import os

from modules import report, session
from modules import target as target_state


def fill_session():
    session.add("whois", {"Domain": "EXAMPLE.COM", "Registrar": "Test Registrar",
                          "Created": "1995-08-14", "Expires": "2030-08-13",
                          "Name Servers": "a.iana-servers.net, b.iana-servers.net"})
    session.add("dns", {"A": ["93.184.216.34"], "MX": ["0 ."], "TXT": ['"v=spf1 -all"']})
    session.add("geo", {"IP": "93.184.216.34", "Country": "United States",
                        "City": "Norwell", "ISP": "Edgecast"})
    session.add("nmap", {
        "Command": "nmap -F example.com", "Host State": "up",
        "Address": "93.184.216.34", "Hostname": "example.com", "OS": "N/A",
        "Ports": [{"Port": "80/tcp", "State": "open", "Service": "http", "Version": ""}],
        "Output": "Host: example.com (93.184.216.34) is up\n\nPORT   STATE  SERVICE\n80/tcp open   http",
    })
    session.add("subdomains", {
        "Domain": "example.com", "Brute Force": True, "Wildcard DNS": False,
        "Notes": ["Rate limit <hit> & retry"],          # characters that need escaping
        "Subdomains": [
            {"Subdomain": "www.example.com", "IPs": ["93.184.216.34"], "Resolves": True, "Source": "crt.sh"},
            {"Subdomain": "old.example.com", "IPs": [], "Resolves": False, "Source": "crt.sh"},
        ],
    })


def build(monkeypatch, tmp_path, target="example.com"):
    """Generate a report into a temporary folder instead of the real reports folder."""
    monkeypatch.setattr(report, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(target_state, "current_target", target)
    return report.generate_report()


def test_report_needs_a_target(monkeypatch, tmp_path):
    monkeypatch.setattr(report, "BASE_DIR", str(tmp_path))
    assert report.generate_report() is None
    assert not (tmp_path / "reports").exists()


def test_report_with_every_module_is_a_valid_pdf(monkeypatch, tmp_path):
    fill_session()
    path = build(monkeypatch, tmp_path)

    assert path == os.path.join(str(tmp_path), "reports", "RAT_Report_example.com.pdf")
    assert os.path.exists(path)
    with open(path, "rb") as f:
        assert f.read(5) == b"%PDF-"
    assert os.path.getsize(path) > 1500


def test_report_works_when_no_module_was_run(monkeypatch, tmp_path):
    path = build(monkeypatch, tmp_path)
    assert path is not None
    with open(path, "rb") as f:
        assert f.read(5) == b"%PDF-"


def test_generating_twice_overwrites_the_same_file(monkeypatch, tmp_path):
    first = build(monkeypatch, tmp_path)
    second = build(monkeypatch, tmp_path)
    assert first == second
    assert len(os.listdir(tmp_path / "reports")) == 1


def test_unsafe_characters_are_removed_from_the_filename(monkeypatch, tmp_path):
    path = build(monkeypatch, tmp_path, target="2001:db8::1")
    assert path is not None
    assert ":" not in os.path.basename(path)
    assert os.path.exists(path)


def test_summary_text_shows_not_run_completed_and_the_subdomain_count():
    assert report.summary_text("dns") == "Not run"
    session.add("dns", {"A": ["1.2.3.4"]})
    assert report.summary_text("dns") == "Completed"
    session.add("subdomains", {"Subdomains": [{}, {}]})
    assert report.summary_text("subdomains") == "Completed (2 found)"