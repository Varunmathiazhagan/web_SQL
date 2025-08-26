#!/usr/bin/env python3
"""
A tiny Flask dashboard to run scans and visualize results.
- GET / -> show latest results (from latest_scan.json)
- POST /scan -> trigger a new scan (async) against a configured URL

Usage:
  set START_URL (env var) or edit the DEFAULT_START_URL below
  python dashboard.py
"""
import os, json, threading, asyncio
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, jsonify

# Import scanner from app.py
from app import AsyncSQLiScanner

DEFAULT_START_URL = os.environ.get("START_URL", "http://localhost:8000")

app = Flask(__name__)

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
      <p>{{ count }} findings | updated {{ updated }}</p>
      <table>
        <thead><tr><th>Technique</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th></tr></thead>
        <tbody>
        {% for r in results %}
          <tr>
            <td>{{ r.technique }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.url }}</td>
            <td>{{ r.param }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.payload }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.evidence }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
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
    async def _run():
        scanner = AsyncSQLiScanner(start_url=start_url, max_depth=2, concurrency=10, delay=0.2)
        await scanner.run()
        scanner.export_results()
    asyncio.run(_run())
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
            self.__dict__.update(d)
    return render_template_string(
        TEMPLATE,
        start_url=DEFAULT_START_URL,
        results=[R(r) for r in results],
        count=len(results),
        updated=updated,
    )


@app.route("/scan", methods=["POST"])
def scan():
    start_url = request.form.get("start_url") or DEFAULT_START_URL
    t = threading.Thread(target=run_scan, args=(start_url,), daemon=True)
    t.start()
    return redirect(url_for("index"))


@app.route("/api/results", methods=["GET"])
def api_results():
    results, mtime = load_latest()
    return jsonify({
        "count": len(results),
        "updated": mtime.isoformat() if mtime else None,
        "results": results,
    })


@app.route("/api/scan", methods=["POST","OPTIONS"])
def api_scan():
  if request.method == 'OPTIONS':
    return ('', 204)
  start_url = request.json.get('start_url') if request.is_json else (request.form.get('start_url') or DEFAULT_START_URL)
  t = threading.Thread(target=run_scan, args=(start_url,), daemon=True)
  t.start()
  return jsonify({"started": True, "start_url": start_url})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
