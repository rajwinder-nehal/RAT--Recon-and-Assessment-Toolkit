import time

import pytest

import app as webapp
import modules.report as report_module
from modules import session
from modules import target as target_state


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(webapp, "ALLOWED", set())      # ignore any allowlist in your shell
    webapp.jobs.clear()
    webapp.sub_jobs.clear()
    webapp.app.config["TESTING"] = True
    yield webapp.app.test_client()
    webapp.jobs.clear()
    webapp.sub_jobs.clear()


def wait_for(client, url, tries=100):
    """Poll a background job until it stops running."""
    for _ in range(tries):
        data = client.get(url).get_json()
        if data["status"] != "running":
            return data
        time.sleep(0.05)
    raise AssertionError("the background job did not finish")


# ---------- Page and simple lookups ----------

def test_dashboard_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"RAT" in r.data
    assert b'data-module="subdomains"' in r.data


def test_dns_route_returns_records_and_saves_only_the_ones_found(client, monkeypatch):
    monkeypatch.setattr(webapp, "get_dns_records", lambda t: {"A": ["1.1.1.1"], "MX": []})
    r = client.get("/api/dns", query_string={"target": "example.com"})

    assert r.status_code == 200
    assert r.get_json() == {"target": "example.com",
                            "records": {"A": ["1.1.1.1"], "MX": []}}
    assert session.get("dns")["data"] == {"A": ["1.1.1.1"]}


def test_whois_and_geo_routes_save_their_results(client, monkeypatch):
    monkeypatch.setattr(webapp, "get_whois_data", lambda t: {"Domain": t})
    monkeypatch.setattr(webapp, "get_geolocation", lambda t: {"Country": "Testland"})

    assert client.get("/api/whois", query_string={"target": "example.com"}).status_code == 200
    assert client.get("/api/geo", query_string={"target": "example.com"}).status_code == 200
    assert session.get("whois")["data"] == {"Domain": "example.com"}
    assert session.get("geo")["data"] == {"Country": "Testland"}


def test_a_failing_lookup_returns_a_json_error(client, monkeypatch):
    def broken(target):
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(webapp, "get_whois_data", broken)
    r = client.get("/api/whois", query_string={"target": "example.com"})
    assert r.status_code == 500
    assert r.get_json()["error"] == "lookup failed"


@pytest.mark.parametrize("target", ["192.168.1.0/24", "10.0.0.1-5", "bad target", "-oN"])
def test_unsafe_targets_are_rejected_with_400(client, target):
    r = client.get("/api/dns", query_string={"target": target})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_missing_target_is_rejected(client):
    assert client.get("/api/dns").status_code == 400


def test_allowlist_blocks_targets_that_are_not_listed(client, monkeypatch):
    monkeypatch.setattr(webapp, "ALLOWED", {"example.com"})
    monkeypatch.setattr(webapp, "get_dns_records", lambda t: {"A": ["1.1.1.1"]})

    blocked = client.get("/api/dns", query_string={"target": "google.com"})
    assert blocked.status_code == 400
    assert "allowed list" in blocked.get_json()["error"]

    allowed = client.get("/api/dns", query_string={"target": "example.com"})
    assert allowed.status_code == 200


def test_changing_the_target_clears_old_results_but_the_same_target_keeps_them(client, monkeypatch):
    monkeypatch.setattr(webapp, "get_dns_records", lambda t: {"A": ["1.1.1.1"]})
    monkeypatch.setattr(webapp, "get_whois_data", lambda t: {"Domain": t})

    client.get("/api/whois", query_string={"target": "one.com"})
    client.get("/api/dns", query_string={"target": "one.com"})
    assert session.get("whois") is not None            # same target: kept
    assert session.get("dns") is not None

    client.get("/api/dns", query_string={"target": "two.com"})
    assert session.get("whois") is None                 # new target: cleared
    assert session.get("dns") is not None


# ---------- Findings ----------

def test_findings_route_reports_counts(client, monkeypatch):
    monkeypatch.setattr(target_state, "current_target", "example.com")
    session.add("nmap", {"Host State": "up", "Ports": [
        {"Port": "23/tcp", "State": "open", "Service": "telnet", "Version": ""}]})

    r = client.get("/api/findings", query_string={"target": "example.com"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["counts"] == {"High": 1, "Medium": 0, "Low": 0, "Info": 0}
    assert data["findings"][0]["Title"] == "Telnet exposed (port 23)"


def test_findings_route_with_nothing_run_is_empty(client):
    data = client.get("/api/findings", query_string={"target": "example.com"}).get_json()
    assert data["findings"] == []
    assert data["counts"] == {"High": 0, "Medium": 0, "Low": 0, "Info": 0}


# ---------- Nmap background job ----------

def test_nmap_job_runs_in_the_background_and_saves_its_result(client, monkeypatch):
    fake_result = {"Command": "nmap -F scanme.nmap.org", "Host State": "up",
                   "Ports": [], "Output": "ok"}
    monkeypatch.setattr(webapp, "run_nmap", lambda t, flags: fake_result)

    r = client.post("/api/nmap", json={"target": "scanme.nmap.org", "scan": "quick"})
    assert r.status_code == 200
    data = wait_for(client, f"/api/nmap/{r.get_json()['job_id']}")

    assert data["status"] == "done"
    assert data["result"] == fake_result
    assert session.get("nmap")["data"] == fake_result


def test_nmap_job_reports_errors(client, monkeypatch):
    def broken(target, flags):
        raise RuntimeError("boom")

    monkeypatch.setattr(webapp, "run_nmap", broken)
    r = client.post("/api/nmap", json={"target": "scanme.nmap.org", "scan": "quick"})
    data = wait_for(client, f"/api/nmap/{r.get_json()['job_id']}")
    assert data["status"] == "error"
    assert data["error"] == "boom"


def test_nmap_only_accepts_preset_scans_never_custom_flags(client, monkeypatch):
    used = []
    monkeypatch.setattr(webapp, "run_nmap", lambda t, flags: used.append(flags) or {"Ports": []})

    bad = client.post("/api/nmap", json={"target": "scanme.nmap.org", "scan": "evil"})
    assert bad.status_code == 400

    r = client.post("/api/nmap", json={"target": "scanme.nmap.org", "scan": "quick",
                                       "flags": ["--script=vuln"]})
    wait_for(client, f"/api/nmap/{r.get_json()['job_id']}")
    assert used == [["-F"]]                              # the extra flags were ignored


def test_only_one_nmap_scan_runs_at_a_time(client):
    webapp.jobs["old"] = {"status": "running"}
    r = client.post("/api/nmap", json={"target": "scanme.nmap.org", "scan": "quick"})
    assert r.status_code == 409
    assert "already running" in r.get_json()["error"]


def test_nmap_rejects_bad_targets_and_unknown_jobs(client):
    bad = client.post("/api/nmap", json={"target": "10.0.0.1-5", "scan": "quick"})
    assert bad.status_code == 400
    assert client.get("/api/nmap/doesnotexist").status_code == 404


# ---------- Subdomain background job ----------

def test_subdomain_search_rejects_ip_addresses(client):
    r = client.post("/api/subdomains", json={"target": "8.8.8.8"})
    assert r.status_code == 400
    assert "domain name" in r.get_json()["error"]


def test_subdomain_job_saves_its_result(client, monkeypatch):
    fake_result = {"Domain": "example.com", "Brute Force": False, "Wildcard DNS": False,
                   "Notes": [], "Subdomains": []}
    monkeypatch.setattr(webapp, "enumerate_subdomains", lambda domain, brute=False: fake_result)

    r = client.post("/api/subdomains", json={"target": "example.com"})
    assert r.status_code == 200
    data = wait_for(client, f"/api/subdomains/{r.get_json()['job_id']}")

    assert data["status"] == "done"
    assert data["result"] == fake_result
    assert session.get("subdomains")["data"] == fake_result


def test_brute_force_is_off_unless_explicitly_set_to_true(client, monkeypatch):
    seen = []

    def fake(domain, brute=False):
        seen.append(brute)
        return {"Domain": domain, "Subdomains": []}

    monkeypatch.setattr(webapp, "enumerate_subdomains", fake)

    for body in ({"target": "example.com"},
                 {"target": "example.com", "brute": "yes"},
                 {"target": "example.com", "brute": True}):
        r = client.post("/api/subdomains", json=body)
        wait_for(client, f"/api/subdomains/{r.get_json()['job_id']}")

    assert seen == [False, False, True]


def test_only_one_subdomain_search_runs_at_a_time(client):
    webapp.sub_jobs["old"] = {"status": "running"}
    r = client.post("/api/subdomains", json={"target": "example.com"})
    assert r.status_code == 409


# ---------- Report download ----------

def test_report_route_returns_a_pdf_download(client, monkeypatch, tmp_path):
    monkeypatch.setattr(report_module, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(target_state, "current_target", "example.com")
    session.add("dns", {"A": ["1.2.3.4"]})

    r = client.get("/api/report", query_string={"target": "example.com"})
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert "attachment" in r.headers["Content-Disposition"]
    assert r.data.startswith(b"%PDF")
    r.close()


def test_report_route_rejects_bad_targets(client):
    r = client.get("/api/report", query_string={"target": "10.0.0.1-5"})
    assert r.status_code == 400