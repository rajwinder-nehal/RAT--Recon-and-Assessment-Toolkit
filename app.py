import functools
import os
import threading
import uuid

from flask import Flask, jsonify, render_template, request, send_file

from modules import session
from modules import target as target_state
from modules.dns_lookup import get_dns_records
from modules.geolocation import get_geolocation
from modules.nmap import PRESETS, run_nmap, validate_target
from modules.whois_lookup import get_whois_data
from modules.report import generate_report
from modules.subdomain import _check_domain, enumerate_subdomains
from modules.findings import analyze, count_by_severity

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

# Optional allowlist: set RAT_ALLOWED_TARGETS="scanme.nmap.org,example.com"
ALLOWED = {t.strip().lower()
           for t in os.environ.get("RAT_ALLOWED_TARGETS", "").split(",")
           if t.strip()}

# Nmap scans run in the background; the page checks on them by job id
jobs = {}
sub_jobs = {}
jobs_lock = threading.Lock()


class ScanBusy(Exception):
    pass


def api(fn):
    """Turn exceptions into clean JSON errors with the right status code."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return jsonify(fn(*args, **kwargs))
        except ValueError as e:
            return jsonify(error=str(e)), 400
        except KeyError:
            return jsonify(error="Not found"), 404
        except ScanBusy as e:
            return jsonify(error=str(e)), 409
        except Exception as e:
            return jsonify(error=str(e)), 500
    return wrapper


def use_target(raw):
    """Validate the target; a new target clears old results (like the CLI)."""
    t = (raw or "").strip()
    validate_target(t)
    if ALLOWED and t.lower() not in ALLOWED:
        raise ValueError("This target is not on the allowed list.")
    if t != target_state.current_target:
        target_state.current_target = t
        session.clear()
    return t


@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/dns")
@api
def dns_route():
    t = use_target(request.args.get("target"))
    records = get_dns_records(t)
    session.add("dns", {k: v for k, v in records.items() if v})
    return {"target": t, "records": records}


@app.get("/api/whois")
@api
def whois_route():
    t = use_target(request.args.get("target"))
    result = get_whois_data(t)
    session.add("whois", result)
    return {"target": t, "result": result}


@app.get("/api/geo")
@api
def geo_route():
    t = use_target(request.args.get("target"))
    result = get_geolocation(t)
    session.add("geo", result)
    return {"target": t, "result": result}


def scan_worker(job_id, target, flags):
    try:
        result = run_nmap(target, flags)
        session.add("nmap", result)
        update = {"status": "done", "result": result}
    except Exception as e:
        update = {"status": "error", "error": str(e)}
    with jobs_lock:
        jobs[job_id].update(update)


@app.post("/api/nmap")
@api
def nmap_start():
    body = request.get_json(silent=True) or {}
    t = use_target(body.get("target"))
    scan = body.get("scan", "quick")
    if scan not in PRESETS:
        raise ValueError(f"Unknown scan type. Choose one of: {', '.join(PRESETS)}")

    with jobs_lock:
        if any(j["status"] == "running" for j in jobs.values()):
            raise ScanBusy("A scan is already running. Wait for it to finish.")
        job_id = uuid.uuid4().hex[:8]
        jobs[job_id] = {"status": "running", "target": t, "scan": scan}

    threading.Thread(target=scan_worker, args=(job_id, t, PRESETS[scan]),
                     daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/nmap/<job_id>")
@api
def nmap_status(job_id):
    with jobs_lock:
        job = jobs[job_id]  # KeyError becomes a 404
        return dict(job)
def subdomain_worker(job_id, domain, brute):
    try:
        result = enumerate_subdomains(domain, brute=brute)
        # Only keep the result if the target hasn't changed while we were working
        if target_state.current_target == domain:
            session.add("subdomains", result)
        update = {"status": "done", "result": result}
    except Exception as e:
        update = {"status": "error", "error": str(e)}
    with jobs_lock:
        sub_jobs[job_id].update(update)


@app.post("/api/subdomains")
@api
def subdomains_start():
    body = request.get_json(silent=True) or {}
    t = use_target(body.get("target"))
    _check_domain(t)                       # ValueError becomes a 400 error
    brute = body.get("brute") is True      # active brute force only when explicitly requested

    with jobs_lock:
        if any(j["status"] == "running" for j in sub_jobs.values()):
            raise ScanBusy("A subdomain search is already running. Wait for it to finish.")
        job_id = uuid.uuid4().hex[:8]
        sub_jobs[job_id] = {"status": "running", "target": t, "brute": brute}

    threading.Thread(target=subdomain_worker, args=(job_id, t, brute),
                     daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/subdomains/<job_id>")
@api
def subdomains_status(job_id):
    with jobs_lock:
        job = sub_jobs[job_id]   # KeyError becomes a 404
        return dict(job)    

@app.get("/api/report")
def report_route():
    try:
        use_target(request.args.get("target"))
        path = generate_report()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=str(e)), 500

    if not path:
        return jsonify(error="Could not create the report. If the PDF is open, close it and try again."), 500
    return send_file(os.path.abspath(path), mimetype="application/pdf", as_attachment=True)

@app.get("/api/findings")
@api
def findings_route():
    use_target(request.args.get("target"))
    findings = analyze()
    return {"findings": findings, "counts": count_by_severity(findings)}

if __name__ == "__main__":
    # debug stays off: Flask's debug mode exposes a console that can run code.
    # host 127.0.0.1 means only your own computer can reach it.
    app.run(host="127.0.0.1", port=5000, debug=False)

    