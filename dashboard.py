#!/usr/bin/env python3
"""
A tiny Flask dashboard to run scans and visualize results.
- GET / -> show latest results (from latest_scan.json)
- POST /scan -> trigger a new scan (async) against a configured URL

Usage:
  set START_URL (env var) or edit the DEFAULT_START_URL below
  python dashboard.py
"""
import os, json, threading, asyncio, csv, time, re
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, jsonify

# Import scanner from app.py
from app import AsyncSQLiScanner

DEFAULT_START_URL = os.environ.get("START_URL", "http://localhost:8000")

app = Flask(__name__)

# Global scan status and a dedicated asyncio loop in a worker thread
scan_in_progress = False
_worker_loop = None
_worker_thread = None

def _ensure_worker_loop():
  global _worker_loop, _worker_thread
  if _worker_loop and _worker_thread and _worker_thread.is_alive():
    return _worker_loop
  _worker_loop = asyncio.new_event_loop()
  def _runner(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()
  _worker_thread = threading.Thread(target=_runner, args=(_worker_loop,), daemon=True)
  _worker_thread.start()
  return _worker_loop

def _guess_dbms_and_fix(technique: str, evidence: str):
  ev = evidence or ""
  tech = (technique or "").lower()
  # DBMS guess heuristics
  if re.search(r"SQLSTATE\[", ev, re.I):
    dbms = "Unknown (PDO / SQLSTATE)"
  elif re.search(r"near \".*\": syntax error|no such column|unrecognized token|unterminated (?:quoted )?string", ev, re.I):
    dbms = "SQLite"
  elif re.search(r"You have an error in your SQL syntax|mysql_", ev, re.I):
    dbms = "MySQL"
  elif "boolean" in tech:
    dbms = "Generic SQL injection"
  else:
    dbms = "Unknown"
  # Fix guidance
  if "error" in tech:
    fix = (
      "Use prepared statements/parameterized queries. Do not concatenate input. "
      "Validate inputs. Disable detailed DB errors in production; log server-side."
    )
  elif "boolean" in tech:
    fix = (
      "Use parameterized queries and strict input validation (whitelists). "
      "Apply least-privilege DB accounts and normalize responses for invalid conditions."
    )
  elif "union" in tech:
    fix = (
      "Use bound parameters; cast/validate inputs to expected types. Restrict selectable columns."
    )
  else:
    fix = "Use parameterized queries and input validation; avoid string concatenation."
  return dbms, fix

def _enrich_result(r: dict):
  tech = r.get("technique", "")
  ev = r.get("evidence", "")
  dbms, fix = _guess_dbms_and_fix(tech, ev)
  out = dict(r)
  out["dbms"] = dbms
  out["solution"] = fix
  out["suggestion"] = fix  # backward-compat with template/JS if needed
  return out

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SQLi Scanner Dashboard</title>
  <style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1220;color:#d6e1ff;margin:0}
  header{padding:16px 24px;border-bottom:1px solid #1c2545;background:#0d1430}
  h1{margin:0;font-size:20px}
  .container{max-width:1100px;margin:24px auto;padding:0 16px}
  .card{background:#0e1a40;border:1px solid #203063;border-radius:10px;padding:16px;margin-bottom:16px}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px 10px;border-bottom:1px solid #203063;text-align:left}
  .btn{background:#4c6fff;border:0;color:white;padding:8px 12px;border-radius:8px;text-decoration:none;cursor:pointer}
  .btn[disabled]{opacity:.5;cursor:not-allowed}
  input[type=text]{background:#0b1736;border:1px solid #203063;color:#d6e1ff;border-radius:8px;padding:8px 10px;width:360px}
  code{color:#f6d365}
  /* Severity colors (enabled when .colors-on is present on body) */
  .colors-on tr.sev-critical{background:rgba(255,77,77,0.15)}
  .colors-on tr.sev-high{background:rgba(255,165,0,0.12)}
  .colors-on tr.sev-medium{background:rgba(255,255,0,0.08)}
  .codebox{background:#0b1736;border:1px dashed #324b96;border-radius:8px;padding:8px;white-space:pre-wrap;color:#b8c7ff;margin-top:6px}
  .toast{position:fixed;right:16px;bottom:16px;background:#203063;color:#fff;padding:10px 14px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.3);opacity:0;transform:translateY(8px);transition:all .25s}
  .toast.show{opacity:1;transform:translateY(0)}
  .toast.success{background:#1f6f43}
  .toast.warn{background:#8a6d3b}
  .toast.error{background:#8b2f2f}
  .loading{display:flex;align-items:center;gap:8px;margin-top:6px}
  .spinner{width:14px;height:14px;border:2px solid #4c6fff33;border-top-color:#4c6fff;border-radius:50%;animation:spin 1s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <header><h1>SQLi Scanner Dashboard</h1></header>
  <div class="container">
    <div class="card" id="statusCard">
      <h3>Scan Status</h3>
      <p id="statusText">{{ 'Running' if scan_in_progress else 'Idle' }}</p>
      <div id="loadingIndicator" class="loading" {% if not scan_in_progress %}style="display:none"{% endif %}>
        <div class="spinner" aria-hidden="true"></div>
        <div>Scanning… crawling and testing URLs. This may take a few minutes.</div>
      </div>
    </div>
    <div class="card">
      <form id="scanForm" method="post" action="/scan">
        <label>Start URL</label>
        <input type="text" name="start_url" value="{{ start_url }}">
        <button class="btn" id="scanBtn" type="submit" {% if scan_in_progress %}style="display:none"{% endif %}>Run Scan</button>
      </form>
      <p>Tip: Start the PHP app first. Default is <code>{{ start_url }}</code>.</p>
      <div style="margin-top:8px; display:flex; gap:16px; align-items:center">
        <label><input type="checkbox" id="colorToggle"> Show severity colors</label>
        <label><input type="checkbox" id="codeToggle"> Show secure query snippet</label>
        <label><input type="checkbox" id="sseToggle"> Use live updates (SSE)</label>
      </div>
      <div class="card" style="margin-top:12px">
        <h4 style="margin:0 0 8px 0">Scan controls</h4>
        <div style="display:grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap:8px; align-items:end">
          <label>Max Depth<br><input type="number" id="ctlDepth" min="0" value="2"></label>
          <label>Concurrency<br><input type="number" id="ctlConc" min="1" value="10"></label>
          <label>Delay (s)<br><input type="number" id="ctlDelay" step="0.1" min="0" value="0.2"></label>
          <label>Boolean Rounds<br><input type="number" id="ctlBoolRounds" min="1" value="3"></label>
          <label><input type="checkbox" id="ctlRobots" checked> Respect robots.txt</label>
          <label><input type="checkbox" id="ctlQuiet"> Quiet</label>
          <label><input type="checkbox" id="ctlTimeBased"> Time-based SQLi</label>
          <label>Time Threshold (s)<br><input type="number" id="ctlTimeThreshold" step="0.5" min="1" value="2"></label>
          <label><input type="checkbox" id="ctlParamFuzz"> Param Fuzzing</label>
          <label>Crawler UA<br><input type="text" id="ctlUA" placeholder="e.g., MyScanner/1.0"></label>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Latest Results</h3>
      <p><span id="count">{{ count }}</span> findings | updated <span id="updated">{{ updated }}</span></p>
      <p>
        <a class="btn" href="/api/results?format=json">Download JSON</a>
        <a class="btn" href="/api/results?format=csv">Download CSV</a>
      </p>
      <table>
    <thead><tr><th>Technique</th><th>Risk</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th><th>DBMS Guess</th><th>Suggested Fix</th></tr></thead>
        <tbody id="resultsBody">
        {% for r in results %}
          <tr class="sev-{{ (r.risk or 'Medium')|lower }}">
            <td>{{ r.technique }}</td>
            <td>{{ r.risk or 'Medium' }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.url }}</td>
            <td>{{ r.param }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.payload }}</td>
      <td style="max-width:320px; overflow-wrap:anywhere">{{ r.evidence }}</td>
      <td>{{ r.dbms }}</td>
      <td style="max-width:360px; overflow-wrap:anywhere">{{ r.solution }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  <div id="toast" class="toast" role="status" aria-live="polite" aria-atomic="true" style="display:none"></div>
  <script>
    function showToast(msg, type='warn'){
      const t = document.getElementById('toast');
      if(!t) return;
      t.textContent = msg;
      t.className = `toast ${type}`;
      t.style.display = 'block';
      // force reflow to apply transition
      void t.offsetWidth;
      t.classList.add('show');
      clearTimeout(window.__toastTimer);
      window.__toastTimer = setTimeout(()=>{
        t.classList.remove('show');
        setTimeout(()=>{ t.style.display='none'; }, 250);
      }, 3000);
    }
    async function refreshResults(){
      try{
        const r = await fetch('/api/results');
        const j = await r.json();
        document.getElementById('count').textContent = j.count;
        document.getElementById('updated').textContent = j.updated ? new Date(j.updated).toLocaleString() : 'never';
        const tbody = document.getElementById('resultsBody');
        tbody.innerHTML = '';
        const colorsOn = document.getElementById('colorToggle')?.checked;
        const codeOn = document.getElementById('codeToggle')?.checked;
        document.body.classList.toggle('colors-on', !!colorsOn);
        const suggestionFor = (row) => {
          const p = row.param || 'parameter';
          const base = `Use prepared statements/parameterized queries (bind variables) for '${p}'. Validate and whitelist expected types/lengths.`;
          if ((row.technique||'').toLowerCase().includes('error')){
            return base + ' Do not expose database error details; return generic messages and log server-side.';
          }
          if ((row.technique||'').toLowerCase().includes('boolean')){
            return base + ' Normalize error responses so invalid conditions do not change page structure; add consistent responses.';
          }
          if ((row.technique||'').toLowerCase().includes('union')){
            return base + ' Restrict SELECT columns and cast inputs to expected types (e.g., integers).';
          }
          return base;
        };
        (j.results||[]).forEach(r => {
          const tr = document.createElement('tr');
          const dbms = r.dbms || (r.evidence && /SQLSTATE\[/i.test(r.evidence) ? 'Unknown (PDO / SQLSTATE)' : ((r.technique||'').toLowerCase().includes('boolean') ? 'Generic SQL injection' : 'Unknown'));
          const fix = r.solution || suggestionFor(r);
          const risk = (r.risk||'Medium');
          tr.className = `sev-${risk.toLowerCase()}`;
          tr.innerHTML = `<td>${r.technique||''}</td>
            <td>${risk}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">${r.url||''}</td>
            <td>${r.param||''}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">${r.payload||''}</td>
            <td style=\"max-width:320px; overflow-wrap:anywhere\">${r.evidence||''}</td>
            <td>${dbms}</td>
            <td style=\"max-width:360px; overflow-wrap:anywhere\">${fix}</td>`;
          if (codeOn){
            const code = document.createElement('div');
            code.className='codebox';
            code.textContent = (r.fix_snippet || 'Use parameterized queries.');
            const td = document.createElement('td');
            td.colSpan = 8;
            td.appendChild(code);
            const tr2 = document.createElement('tr');
            tr2.className = `sev-${risk.toLowerCase()}`;
            tr2.appendChild(td);
            tbody.appendChild(tr);
            tbody.appendChild(tr2);
            return;
          }
          tbody.appendChild(tr);
        });
      }catch(e){/* ignore */}
    }
    async function refreshStatus(){
      try{
        const r = await fetch('/api/status');
        const j = await r.json();
        const el = document.getElementById('statusText');
  const running = !!j.running;
  el.textContent = running ? 'Running' : 'Idle';
  const li = document.getElementById('loadingIndicator');
  if (li) li.style.display = running ? 'flex' : 'none';
  const btn = document.getElementById('scanBtn');
  if (btn) btn.style.display = running ? 'none' : 'inline-block';
      }catch(e){}
    }
  setInterval(()=>{refreshResults(); refreshStatus();}, 5000);
  document.getElementById('colorToggle')?.addEventListener('change', refreshResults);
  document.getElementById('codeToggle')?.addEventListener('change', refreshResults);
    // Intercept form submit to call /api/scan and show toast if 429
    document.getElementById('scanForm')?.addEventListener('submit', async (e)=>{
      e.preventDefault();
      try{
        const fd = new FormData(e.target);
        const start_url = fd.get('start_url') || '';
        const ctrl = {
          start_url,
          max_depth: parseInt(document.getElementById('ctlDepth')?.value || '2', 10),
          concurrency: parseInt(document.getElementById('ctlConc')?.value || '10', 10),
          delay: parseFloat(document.getElementById('ctlDelay')?.value || '0.2'),
          boolean_rounds: parseInt(document.getElementById('ctlBoolRounds')?.value || '3', 10),
          respect_robots: !!document.getElementById('ctlRobots')?.checked,
          quiet: !!document.getElementById('ctlQuiet')?.checked,
          time_based: !!document.getElementById('ctlTimeBased')?.checked,
          time_threshold: parseFloat(document.getElementById('ctlTimeThreshold')?.value || '2'),
          param_fuzz: !!document.getElementById('ctlParamFuzz')?.checked,
          crawler_ua: (document.getElementById('ctlUA')?.value || '').trim() || null,
        };
        // Immediately clear previous results in the UI
        try{
          document.getElementById('resultsBody').innerHTML = '';
          document.getElementById('count').textContent = '0';
          document.getElementById('updated').textContent = 'scanning…';
          const statusEl = document.getElementById('statusText');
          if (statusEl) statusEl.textContent = 'Running';
          const li = document.getElementById('loadingIndicator');
          if (li) li.style.display = 'flex';
          const btn = document.getElementById('scanBtn');
          if (btn) btn.style.display = 'none';
        }catch(_){ }
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(ctrl)
        });
        if (resp.status === 429){
          const j = await resp.json().catch(()=>({reason:'Scan already running'}));
          showToast(j.reason || 'Scan already running', 'warn');
          return;
        }
        if (resp.ok){
          showToast('Scan started', 'success');
          refreshStatus();
          return;
        }
        showToast('Failed to start scan', 'error');
      }catch(err){
        showToast('Failed to start scan', 'error');
      }
    });

    // Optional SSE live updates
    let es;
    function configureSSE(){
      try{ es && es.close(); }catch(_){ }
      es = undefined;
      const useSSE = document.getElementById('sseToggle')?.checked;
      if(useSSE){
        es = new EventSource('/events');
        es.onmessage = (_ev)=>{ refreshResults(); refreshStatus(); };
        es.onerror = (_e)=>{ /* silent; fallback remains interval */ };
      }
    }
    document.getElementById('sseToggle')?.addEventListener('change', configureSSE);
    configureSSE();
  </script>
</body>
</html>
"""


def load_latest():
    try:
        with open("latest_scan.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        mtime = datetime.fromtimestamp(os.path.getmtime("latest_scan.json"))
        return data, mtime
    except Exception:
        return [], None


def run_scan(start_url: str, options: dict | None = None):
  """Schedule the scan coroutine onto a persistent event loop thread."""
  global scan_in_progress
  loop = _ensure_worker_loop()
  async def _run():
    global scan_in_progress
    try:
      scan_in_progress = True
      opts = options or {}
      scanner = AsyncSQLiScanner(
        start_url=start_url,
        max_depth=int(opts.get('max_depth', 2)),
        concurrency=int(opts.get('concurrency', 10)),
        delay=float(opts.get('delay', 0.2)),
        respect_robots=bool(opts.get('respect_robots', True)),
        boolean_rounds=int(opts.get('boolean_rounds', 3)),
        verbose=not bool(opts.get('quiet', False)),
        quiet=bool(opts.get('quiet', False)),
  time_based=bool(opts.get('time_based', False)),
  time_threshold=float(opts.get('time_threshold', 2.0)),
  param_fuzz=bool(opts.get('param_fuzz', False)),
  robots_user_agent=(opts.get('crawler_ua') or None),
      )
      await scanner.run()
      scanner.export_results()
    finally:
      scan_in_progress = False
  # Create a task in the worker loop without blocking
  def _create_task():
    asyncio.ensure_future(_run(), loop=loop)
  loop.call_soon_threadsafe(_create_task)
@app.after_request
def add_cors(resp):
  resp.headers['Access-Control-Allow-Origin'] = '*'
  resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
  return resp



@app.route("/", methods=["GET"])
def index():
  results, mtime = load_latest()
  # If a scan is in progress, do not show previous results on the landing page
  show_results = (not scan_in_progress)
  if not show_results:
    results = []
    mtime = None
  updated = mtime.strftime("%Y-%m-%d %H:%M:%S") if mtime else "never"
  class R:  # simple object view for Jinja
    def __init__(self, d):
      enriched = _enrich_result(d)
      self.__dict__.update(enriched)
  return render_template_string(
    TEMPLATE,
    start_url=DEFAULT_START_URL,
    results=[R(r) for r in results],
    count=len(results),
    updated=updated,
    scan_in_progress=scan_in_progress,
  )


@app.route("/scan", methods=["POST"])
def scan():
  # Basic HTML form fallback (JS intercepts to /api/scan normally)
  global scan_in_progress
  if scan_in_progress:
    # Simply redirect back if already running
    return redirect(url_for("index"))
  start_url = request.form.get("start_url") or DEFAULT_START_URL
  run_scan(start_url)
  return redirect(url_for("index"))


@app.route("/api/results", methods=["GET"])
def api_results():
  global scan_in_progress
  # While a scan is running, suppress previous results so the UI only shows fresh results when ready
  if scan_in_progress:
    fmt = request.args.get('format')
    if fmt == 'csv':
      from io import StringIO
      si = StringIO()
      writer = csv.DictWriter(si, fieldnames=["url","risk","param","technique","payload","evidence","dbms","solution"])
      writer.writeheader()
      resp = app.response_class(si.getvalue(), mimetype='text/csv')
      resp.headers['Content-Disposition'] = 'attachment; filename="latest_scan.csv"'
      return resp
    return jsonify({"count": 0, "updated": None, "results": []})

  results, mtime = load_latest()
  enriched = [_enrich_result(r) for r in results]
  fmt = request.args.get('format')
  if fmt == 'csv':
    # stream CSV
    from io import StringIO
    si = StringIO()
    # include risk column instead of generic 'type'
    writer = csv.DictWriter(si, fieldnames=["url","risk","param","technique","payload","evidence","dbms","solution"])
    writer.writeheader()
    for r in enriched:
      writer.writerow({k: r.get(k,"") for k in writer.fieldnames})
    resp = app.response_class(si.getvalue(), mimetype='text/csv')
    resp.headers['Content-Disposition'] = 'attachment; filename="latest_scan.csv"'
    return resp
  # default json
  return jsonify({
    "count": len(enriched),
    "updated": mtime.isoformat() if mtime else None,
    "results": enriched,
  })


@app.route("/api/scan", methods=["POST","OPTIONS"])
def api_scan():
  if request.method == 'OPTIONS':
    return ('', 204)
  payload = request.get_json(silent=True) or {}
  start_url = payload.get('start_url') or request.form.get('start_url') or DEFAULT_START_URL
  global scan_in_progress
  if scan_in_progress:
    return jsonify({"started": False, "reason": "Scan already in progress"}), 429
  options = {
    'max_depth': payload.get('max_depth', 2),
    'concurrency': payload.get('concurrency', 10),
    'delay': payload.get('delay', 0.2),
    'boolean_rounds': payload.get('boolean_rounds', 3),
    'respect_robots': payload.get('respect_robots', True),
    'quiet': payload.get('quiet', False),
  'time_based': payload.get('time_based', False),
  'time_threshold': payload.get('time_threshold', 2.0),
  'param_fuzz': payload.get('param_fuzz', False),
  'crawler_ua': payload.get('crawler_ua') or None,
  }
  run_scan(start_url, options)
  return jsonify({"started": True, "start_url": start_url})


@app.route('/events')
def sse_events():
  def generate():
    last_mtime = None
    last_status = None
    while True:
      try:
        # Detect result changes
        try:
          mtime = os.path.getmtime('latest_scan.json')
        except Exception:
          mtime = None
        changed = (mtime != last_mtime) or (last_status != bool(scan_in_progress))
        last_mtime = mtime
        last_status = bool(scan_in_progress)
        # include a recommend reconnect delay for clients
        if changed:
          yield 'event: message\n'
          yield 'data: update\n\n'
        else:
          # heartbeat to keep the connection alive across proxies
          yield ': ping\n\n'
      except GeneratorExit:
        break
      except Exception:
        yield ': ping\n\n'
      time.sleep(5)
  return app.response_class(
    generate(),
    mimetype='text/event-stream',
    headers={
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',  # disable proxy buffering if present
    }
  )


@app.route("/api/status", methods=["GET"]) 
def api_status():
    return jsonify({"running": bool(scan_in_progress)})


if __name__ == "__main__":
  # Disable reloader to avoid spawning multiple worker threads/SSE generators
  app.run(host="127.0.0.1", port=5050, debug=True, use_reloader=False)
