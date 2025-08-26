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
  input[type=text]{background:#0b1736;border:1px solid #203063;color:#d6e1ff;border-radius:8px;padding:8px 10px;width:360px}
  code{color:#f6d365}
  </style>
</head>
<body>
  <header><h1>SQLi Scanner Dashboard</h1></header>
  <div class="container">
    <div class="card" id="statusCard">
      <h3>Scan Status</h3>
      <p id="statusText">{{ 'Running' if scan_in_progress else 'Idle' }}</p>
    </div>
    <div class="card">
      <form method="post" action="/scan">
        <label>Start URL</label>
        <input type="text" name="start_url" value="{{ start_url }}">
        <button class="btn" type="submit">Run Scan</button>
      </form>
      <p>Tip: Start the PHP app first. Default is <code>{{ start_url }}</code>.</p>
    </div>

    <div class="card">
      <h3>Latest Results</h3>
      <p><span id="count">{{ count }}</span> findings | updated <span id="updated">{{ updated }}</span></p>
      <p>
        <a class="btn" href="/api/results?format=json">Download JSON</a>
        <a class="btn" href="/api/results?format=csv">Download CSV</a>
      </p>
      <table>
    <thead><tr><th>Technique</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th><th>DBMS Guess</th><th>Suggested Fix</th></tr></thead>
        <tbody id="resultsBody">
        {% for r in results %}
          <tr>
            <td>{{ r.technique }}</td>
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
  <script>
    async function refreshResults(){
      try{
        const r = await fetch('/api/results');
        const j = await r.json();
        document.getElementById('count').textContent = j.count;
        document.getElementById('updated').textContent = j.updated ? new Date(j.updated).toLocaleString() : 'never';
        const tbody = document.getElementById('resultsBody');
        tbody.innerHTML = '';
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
          tr.innerHTML = `<td>${r.technique||''}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">${r.url||''}</td>
            <td>${r.param||''}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">${r.payload||''}</td>
            <td style=\"max-width:320px; overflow-wrap:anywhere\">${r.evidence||''}</td>
            <td>${dbms}</td>
            <td style=\"max-width:360px; overflow-wrap:anywhere\">${fix}</td>`;
          tbody.appendChild(tr);
        });
      }catch(e){/* ignore */}
    }
    async function refreshStatus(){
      try{
        const r = await fetch('/api/status');
        const j = await r.json();
        const el = document.getElementById('statusText');
        el.textContent = j.running ? 'Running' : 'Idle';
      }catch(e){}
    }
    setInterval(()=>{refreshResults(); refreshStatus();}, 5000);
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


def run_scan(start_url: str):
  """Schedule the scan coroutine onto a persistent event loop thread."""
  global scan_in_progress
  loop = _ensure_worker_loop()
  async def _run():
    global scan_in_progress
    try:
      scan_in_progress = True
      scanner = AsyncSQLiScanner(start_url=start_url, max_depth=2, concurrency=10, delay=0.2)
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
  start_url = request.form.get("start_url") or DEFAULT_START_URL
  run_scan(start_url)
  return redirect(url_for("index"))


@app.route("/api/results", methods=["GET"])
def api_results():
  results, mtime = load_latest()
  enriched = [_enrich_result(r) for r in results]
  fmt = request.args.get('format')
  if fmt == 'csv':
    # stream CSV
    from io import StringIO
    si = StringIO()
    writer = csv.DictWriter(si, fieldnames=["url","type","param","technique","payload","evidence","dbms","solution"])
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
  start_url = request.json.get('start_url') if request.is_json else (request.form.get('start_url') or DEFAULT_START_URL)
  run_scan(start_url)
  return jsonify({"started": True, "start_url": start_url})


@app.route("/api/status", methods=["GET"]) 
def api_status():
    return jsonify({"running": bool(scan_in_progress)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
