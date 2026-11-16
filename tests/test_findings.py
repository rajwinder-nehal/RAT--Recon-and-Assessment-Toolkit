from datetime import datetime, timedelta

import pytest

from modules import session
from modules.findings import SEVERITIES, analyze, count_by_severity


# ---------- Helpers to load fake scan results ----------

def port(number, state="open", proto="tcp", version=""):
    return {"Port": f"{number}/{proto}", "State": state, "Service": "svc", "Version": version}


def scan(*ports, host="up"):
    session.add("nmap", {"Host State": host, "Ports": list(ports)})


def dns(**records):
    session.add("dns", records)


def expires_in(days):
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def sub(name, resolves=True):
    return {"Subdomain": name, "IPs": ["1.2.3.4"] if resolves else [],
            "Resolves": resolves, "Source": "crt.sh"}


def subs(*items, wildcard=False):
    session.add("subdomains", {"Domain": "example.com", "Wildcard DNS": wildcard,
                               "Subdomains": list(items)})


def titles():
    return [f["Title"] for f in analyze()]


def severities():
    return [f["Severity"] for f in analyze()]


# ---------- Nmap rules ----------

def test_no_results_means_no_findings():
    assert analyze() == []


def test_open_telnet_is_high():
    scan(port(23))
    findings = analyze()
    assert findings[0]["Severity"] == "High"
    assert "Telnet" in findings[0]["Title"]


@pytest.mark.parametrize("number", [23, 445, 1433, 1521, 3306, 3389, 5432,
                                    5900, 6379, 9200, 11211, 27017])
def test_database_and_remote_access_ports_are_high(number):
    scan(port(number))
    assert severities() == ["High"]


@pytest.mark.parametrize("number", [21, 135, 139, 5985])
def test_legacy_and_windows_service_ports_are_medium(number):
    scan(port(number))
    assert severities() == ["Medium"]


def test_clear_text_mail_port_is_low():
    scan(port(110))
    assert severities() == ["Low"]


def test_closed_and_filtered_ports_are_ignored():
    scan(port(23, state="closed"), port(3389, state="filtered"))
    assert analyze() == []


def test_udp_ports_are_ignored():
    scan(port(23, proto="udp"))
    assert analyze() == []


def test_a_down_host_produces_no_port_findings():
    scan(port(23), host="down")
    assert analyze() == []


def test_http_without_https_is_low():
    scan(port(80))
    assert titles() == ["HTTP without HTTPS"]
    assert severities() == ["Low"]


def test_http_with_https_is_fine():
    scan(port(80), port(443))
    assert analyze() == []


def test_ten_open_ports_is_flagged_but_nine_is_not():
    scan(*[port(n) for n in range(2000, 2010)])
    assert titles() == ["Large number of open ports"]
    session.clear()
    scan(*[port(n) for n in range(2000, 2009)])
    assert analyze() == []


def test_service_versions_are_reported_as_info():
    scan(port(8080, version="Apache 2.4.49"))
    findings = analyze()
    assert findings[0]["Severity"] == "Info"
    assert "Apache 2.4.49" in findings[0]["Detail"]


# ---------- Email security rules (DNS) ----------

def test_domain_without_mx_gets_no_email_findings():
    dns(A=["1.2.3.4"])
    assert analyze() == []


def test_mail_domain_without_spf_and_dmarc_gets_two_medium_findings():
    dns(MX=["10 mail.example.com."])
    assert set(titles()) == {"No SPF record", "No DMARC record"}
    assert set(severities()) == {"Medium"}


@pytest.mark.parametrize("spf, severity, expected_title", [
    ('"v=spf1 +all"', "High", "SPF allows any sender"),
    ('"v=spf1 ?all"', "Low", "SPF has a neutral policy"),
    ('"v=spf1 include:_spf.google.com ~all"', "Info", "SPF uses soft fail"),
])
def test_spf_policies_are_rated(spf, severity, expected_title):
    dns(MX=["10 mail.example.com."], TXT=[spf], DMARC=['"v=DMARC1; p=reject"'])
    findings = analyze()
    assert len(findings) == 1
    assert findings[0]["Severity"] == severity
    assert expected_title in findings[0]["Title"]


def test_well_configured_mail_domain_has_no_findings():
    dns(MX=["10 mail.example.com."],
        TXT=['"v=spf1 include:_spf.example.com -all"'],
        DMARC=['"v=DMARC1; p=reject; rua=mailto:reports@example.com"'])
    assert analyze() == []


def test_dmarc_monitoring_only_is_low():
    dns(MX=["10 mail.example.com."], TXT=['"v=spf1 -all"'],
        DMARC=['"v=DMARC1; p=none; rua=mailto:reports@example.com"'])
    findings = analyze()
    assert len(findings) == 1
    assert findings[0]["Severity"] == "Low"
    assert "p=none" in findings[0]["Title"]


def test_dmarc_quarantine_is_accepted():
    dns(MX=["10 mail.example.com."], TXT=['"v=spf1 -all"'],
        DMARC=['"v=DMARC1; p=quarantine"'])
    assert analyze() == []


# ---------- Domain expiry rules (WHOIS) ----------

def test_expired_domain_is_high():
    session.add("whois", {"Expires": "2020-01-01 00:00:00"})
    assert severities() == ["High"]


def test_domain_expiring_in_ten_days_is_medium():
    session.add("whois", {"Expires": expires_in(10)})
    assert severities() == ["Medium"]


def test_domain_expiring_in_sixty_days_is_low():
    session.add("whois", {"Expires": expires_in(60)})
    assert severities() == ["Low"]


def test_domain_expiring_in_a_year_is_fine():
    session.add("whois", {"Expires": expires_in(400)})
    assert analyze() == []


def test_unreadable_expiry_date_is_ignored():
    session.add("whois", {"Expires": "N/A"})
    assert analyze() == []


# ---------- Subdomain rules ----------

def test_no_subdomains_means_no_findings():
    subs()
    assert analyze() == []


def test_found_subdomains_are_reported_as_info():
    subs(sub("www.example.com"))
    assert titles() == ["Subdomains discovered"]
    assert severities() == ["Info"]


def test_resolving_dev_subdomain_is_flagged_as_sensitive():
    subs(sub("dev.example.com"))
    sensitive = [f for f in analyze() if f["Severity"] == "Low"]
    assert len(sensitive) == 1
    assert "dev.example.com" in sensitive[0]["Detail"]


def test_hyphenated_names_are_checked_word_by_word():
    subs(sub("dev-api.example.com"))
    assert "Low" in severities()


def test_similar_looking_words_are_not_false_positives():
    subs(sub("developer.example.com"))
    assert titles() == ["Subdomains discovered"]


def test_non_resolving_subdomain_is_not_called_sensitive():
    subs(sub("dev.example.com", resolves=False))
    assert "Low" not in severities()
    assert any("no DNS record" in t for t in titles())


def test_wildcard_dns_is_noted():
    subs(sub("www.example.com"), wildcard=True)
    assert "Wildcard DNS is enabled" in titles()


# ---------- Whole-engine behavior ----------

def load_sample():
    scan(port(23), port(3306, version="MySQL 5.5.62"), port(80))
    dns(MX=["10 mail.example.com."], TXT=['"v=spf1 +all"'])
    session.add("whois", {"Expires": "2020-01-01 00:00:00"})
    subs(sub("dev.example.com"), sub("old.example.com", resolves=False))


def test_sample_data_gives_the_expected_counts():
    load_sample()
    assert count_by_severity(analyze()) == {"High": 4, "Medium": 1, "Low": 2, "Info": 3}


def test_findings_are_sorted_most_severe_first():
    load_sample()
    order = [SEVERITIES.index(f["Severity"]) for f in analyze()]
    assert order == sorted(order)


def test_every_finding_has_all_fields_filled_in():
    load_sample()
    for f in analyze():
        for field in ("Severity", "Title", "Detail", "Recommendation", "Source"):
            assert f[field], f"{field} is empty in {f['Title']}"


def test_counts_include_every_severity_even_when_zero():
    assert count_by_severity([]) == {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    