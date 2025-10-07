#!/usr/bin/env python3
import os, io, yaml, json, logging, base64, uuid, pathlib, shutil
from logging import StreamHandler
from pythonjsonlogger import jsonlogger
from flask import Flask, render_template, request, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename

from validator import Validator, human_bytes, make_scan_metadata

# ---------- logging ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_JSON = os.getenv("LOG_JSON", "false").lower() == "true"

logger = logging.getLogger("adzip")
logger.setLevel(LOG_LEVEL)
handler = StreamHandler()
formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s") if LOG_JSON \
    else logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ---------- config ----------
with open("config.yaml", "r") as f:
    CFG = yaml.safe_load(f)

MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", 25))
PORT = int(os.getenv("PORT", 5000))
API_KEY = os.getenv("API_KEY", "")  # optional

# storage
DATA_DIR = pathlib.Path("data")
RUNS_DIR = DATA_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)
HISTORY = DATA_DIR / "history.jsonl"

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024)

validator = Validator(CFG.get("app", {}), logger=logger)

# ---------- JSON error handlers ----------
@app.errorhandler(Exception)
def handle_any_error(e):
    logger.exception("unhandled_error")
    return jsonify({"error": str(e)}), 500

@app.errorhandler(413)
def handle_large_file(_e):
    return jsonify({"error": f"Upload too large. Limit is {MAX_UPLOAD_MB} MB."}), 413

# ---------- helpers ----------
def save_run(run_id, payload):
    (RUNS_DIR / run_id).mkdir(parents=True, exist_ok=True)
    with open(RUNS_DIR / run_id / "report.json", "w") as f:
        json.dump(payload, f, indent=2)
    with open(HISTORY, "a") as f:
        f.write(json.dumps({"id": run_id, "ts": payload["metadata"]["unix_timestamp"],
                            "name": payload["metadata"]["original_name"]}) + "\n")

def load_report(run_id):
    p = RUNS_DIR / run_id / "report.json"
    if not p.exists(): abort(404)
    with open(p) as f:
        return json.load(f)

# ---------- routes ----------
@app.get("/")
def index():
    return render_template(
        "index.html",
        title=CFG["app"].get("title", "Ad ZIP Validator"),
        max_zip=human_bytes(CFG["app"].get("max_zip_bytes", 204800)),
        allow_remote=CFG["app"].get("allow_remote_urls", False),
        have_playwright=validator.have_playwright,
        show_meta=CFG.get("ui", {}).get("show_metadata_panel", True),
    )

@app.get("/runs")
def list_runs():
    items = []
    if HISTORY.exists():
        with open(HISTORY) as f:
            for line in f:
                try: items.append(json.loads(line))
                except: pass
    items.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return jsonify({"runs": items[:200]})

@app.get("/runs/<run_id>")
def get_run(run_id):
    return jsonify(load_report(run_id))

@app.get("/runs/<run_id>/view")
def view_run(run_id):
    rpt = load_report(run_id)
    # simple viewer page that iframes the extracted index.html
    return render_template("viewer.html",
                           title=f"Run {run_id}",
                           iframe_src=rpt["entry_url"],
                           report_id=run_id)

@app.get("/runs/<run_id>/file/<path:path>")
def serve_run_file(run_id, path):
    root = RUNS_DIR / run_id / "unzipped"
    path = pathlib.Path(path)
    if ".." in str(path): abort(400)
    return send_from_directory(root, str(path))

@app.get("/runs/<run_id>/backup.png")
def backup_png(run_id):
    """Return the PNG saved for a given timestamp (created by validator)."""
    t = request.args.get("t")
    if not t: abort(400)
    p = RUNS_DIR / run_id / f"backup_{t.replace('.','_')}.png"
    if not p.exists(): abort(404)
    return send_from_directory(p.parent, p.name, mimetype="image/png")

@app.post("/analyze")
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    f = request.files["file"]
    if not f or f.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(f.filename)
    data = f.read()
    if not data:
        return jsonify({"error": "Empty file"}), 400
    if not filename.lower().endswith(".zip"):
        return jsonify({"error": "Please upload a .zip"}), 400

    run_id = uuid.uuid4().hex[:12]
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info("upload", extra={"event": "upload", "file_name": filename, "size": len(data), "run": run_id})
    report = validator.analyze(io.BytesIO(data), original_name=filename, run_dir=run_dir)

    # enrich metadata
    md = make_scan_metadata(request.user_agent.string, original_name=filename)
    if "metadata" in report:
        report["metadata"].update(md)
    else:
        report["metadata"] = md

    report["run_id"] = run_id
    save_run(run_id, report)

    status_code = 200 if "results" in report else 400
    logger.info("analysis_done", extra={"event": "analysis", "ok": (status_code == 200), "run": run_id})
    return jsonify(report), status_code

# --------- Public API (base64) ----------
@app.post("/api/scanZip")
def api_scan_zip():
    # Auth if API_KEY is set
    if API_KEY:
        if request.headers.get("X-ApiKey") != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    b64 = payload.get("data")
    if not b64:
        return jsonify({"error": "Missing 'data' (base64 ZIP)"}), 400
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return jsonify({"error": "Invalid base64"}), 400

    run_id = uuid.uuid4().hex[:12]
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    report = validator.analyze(io.BytesIO(raw), original_name=f"api_{run_id}.zip", run_dir=run_dir)
    md = make_scan_metadata(request.user_agent.string, original_name=f"api_{run_id}.zip")
    report["metadata"] = {**(report.get("metadata") or {}), **md}
    report["run_id"] = run_id
    save_run(run_id, report)
    return jsonify(report), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
