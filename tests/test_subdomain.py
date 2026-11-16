import pytest

from modules import subdomain


class FakeResponse:
    """Stands in for a requests response, so no real network call is made."""
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else []

    def json(self):
        return self._payload


def patch_sources(monkeypatch, crt=None, spotter=None, resolves=None, wildcard=None):
    """Replace every network-facing helper with a fake."""
    crt = crt or (set(), "")
    spotter = spotter or (set(), "")
    resolves = resolves or {}
    monkeypatch.setattr(subdomain, "_crt_sh", lambda d: crt)
    monkeypatch.setattr(subdomain, "_certspotter", lambda d: spotter)
    monkeypatch.setattr(subdomain, "_resolve", lambda name: resolves.get(name, []))
    monkeypatch.setattr(subdomain, "_wildcard_ips", lambda d: set(wildcard or ()))


# ---------- Input checks ----------

def test_check_domain_accepts_a_domain():
    subdomain._check_domain("example.com")        # must not raise


@pytest.mark.parametrize("value", [
    "8.8.8.8", "2001:db8::1", "localhost", "bad target", "192.168.1.0/24",
])
def test_check_domain_rejects_ips_and_bad_input(value):
    with pytest.raises(ValueError):
        subdomain._check_domain(value)


def test_ip_address_error_mentions_domain_name():
    with pytest.raises(ValueError, match="domain name"):
        subdomain.enumerate_subdomains("8.8.8.8")


# ---------- Combining the sources ----------

def test_passive_search_lists_names_from_certificate_logs(monkeypatch):
    patch_sources(monkeypatch,
                  crt=({"www.example.com", "dev.example.com"}, ""),
                  resolves={"www.example.com": ["1.1.1.1"]})
    result = subdomain.enumerate_subdomains("example.com", brute=False)

    names = [s["Subdomain"] for s in result["Subdomains"]]
    assert names == ["dev.example.com", "www.example.com"]       # sorted
    by_name = {s["Subdomain"]: s for s in result["Subdomains"]}
    assert by_name["www.example.com"]["Resolves"] is True
    assert by_name["www.example.com"]["IPs"] == ["1.1.1.1"]
    assert by_name["www.example.com"]["Source"] == "crt.sh"
    assert by_name["dev.example.com"]["Resolves"] is False
    assert result["Notes"] == []
    assert result["Brute Force"] is False


def test_domain_is_cleaned_before_searching(monkeypatch):
    patch_sources(monkeypatch)
    result = subdomain.enumerate_subdomains("  Example.COM ", brute=False)
    assert result["Domain"] == "example.com"


def test_falls_back_to_cert_spotter_when_crt_sh_fails(monkeypatch):
    patch_sources(monkeypatch,
                  crt=(set(), "crt.sh lookup failed (HTTP 502) after 3 tries."),
                  spotter=({"api.example.com"}, ""),
                  resolves={"api.example.com": ["3.3.3.3"]})
    result = subdomain.enumerate_subdomains("example.com", brute=False)

    assert [s["Subdomain"] for s in result["Subdomains"]] == ["api.example.com"]
    assert result["Subdomains"][0]["Source"] == "certspotter"
    assert any("Cert Spotter" in n for n in result["Notes"])


def test_reports_both_failures_when_no_source_works(monkeypatch):
    patch_sources(monkeypatch,
                  crt=(set(), "crt.sh lookup failed (HTTP 502) after 3 tries."),
                  spotter=(set(), "Cert Spotter lookup failed (HTTP 429)."))
    result = subdomain.enumerate_subdomains("example.com", brute=False)

    assert result["Subdomains"] == []
    assert len(result["Notes"]) == 1
    assert "502" in result["Notes"][0]
    assert "429" in result["Notes"][0]


def test_brute_force_keeps_only_names_that_resolve(monkeypatch):
    patch_sources(monkeypatch, resolves={"mail.example.com": ["2.2.2.2"]})
    result = subdomain.enumerate_subdomains("example.com", brute=True,
                                            wordlist=["mail", "ftp"])
    assert [s["Subdomain"] for s in result["Subdomains"]] == ["mail.example.com"]
    assert result["Subdomains"][0]["Source"] == "bruteforce"
    assert result["Brute Force"] is True


def test_name_found_by_both_methods_lists_both_sources(monkeypatch):
    patch_sources(monkeypatch,
                  crt=({"mail.example.com"}, ""),
                  resolves={"mail.example.com": ["2.2.2.2"]})
    result = subdomain.enumerate_subdomains("example.com", brute=True, wordlist=["mail"])
    assert len(result["Subdomains"]) == 1
    assert result["Subdomains"][0]["Source"] == "bruteforce, crt.sh"


def test_wildcard_dns_hides_fake_brute_force_hits(monkeypatch):
    patch_sources(monkeypatch, wildcard={"9.9.9.9"})
    # every guess resolves to the wildcard address, except one real host
    monkeypatch.setattr(
        subdomain, "_resolve",
        lambda n: ["5.5.5.5"] if n == "real.example.com" else ["9.9.9.9"])

    result = subdomain.enumerate_subdomains("example.com", brute=True,
                                            wordlist=["real", "fake", "other"])
    assert [s["Subdomain"] for s in result["Subdomains"]] == ["real.example.com"]
    assert result["Wildcard DNS"] is True
    assert any("Wildcard" in n for n in result["Notes"])


def test_huge_result_sets_are_capped(monkeypatch):
    many = {f"h{i}.example.com" for i in range(600)}
    patch_sources(monkeypatch, crt=(many, ""))
    result = subdomain.enumerate_subdomains("example.com", brute=False)

    assert len(result["Subdomains"]) == 500
    assert any("500" in n for n in result["Notes"])


# ---------- crt.sh lookup ----------

def test_crt_sh_cleans_and_filters_names(monkeypatch):
    rows = [{"name_value": "*.example.com\nwww.example.com\nevil.other.com\nMAIL.example.com"}]
    monkeypatch.setattr(subdomain.requests, "get", lambda *a, **k: FakeResponse(200, rows))

    names, note = subdomain._crt_sh("example.com")
    assert names == {"www.example.com", "mail.example.com"}
    assert note == ""


def test_crt_sh_retries_three_times_then_reports_the_status(monkeypatch):
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return FakeResponse(502)

    monkeypatch.setattr(subdomain.requests, "get", fake_get)
    monkeypatch.setattr(subdomain.time, "sleep", lambda seconds: None)

    names, note = subdomain._crt_sh("example.com")
    assert names == set()
    assert len(calls) == 3
    assert "502" in note
    assert "3 tries" in note


def test_crt_sh_succeeds_after_a_temporary_failure(monkeypatch):
    responses = [FakeResponse(502),
                 FakeResponse(200, [{"name_value": "www.example.com"}])]
    monkeypatch.setattr(subdomain.requests, "get", lambda *a, **k: responses.pop(0))
    monkeypatch.setattr(subdomain.time, "sleep", lambda seconds: None)

    names, note = subdomain._crt_sh("example.com")
    assert names == {"www.example.com"}
    assert note == ""


def test_crt_sh_reports_connection_errors(monkeypatch):
    def fake_get(*args, **kwargs):
        raise ConnectionError("network down")

    monkeypatch.setattr(subdomain.requests, "get", fake_get)
    monkeypatch.setattr(subdomain.time, "sleep", lambda seconds: None)

    names, note = subdomain._crt_sh("example.com")
    assert names == set()
    assert "ConnectionError" in note


# ---------- Cert Spotter lookup ----------

def test_cert_spotter_reads_pages_until_one_is_empty(monkeypatch):
    pages = [[{"id": "1", "dns_names": ["a.example.com", "*.example.com", "x.other.com"]}], []]
    seen = []

    def fake_get(url, params=None, **kwargs):
        seen.append(dict(params))
        return FakeResponse(200, pages.pop(0))

    monkeypatch.setattr(subdomain.requests, "get", fake_get)
    monkeypatch.setattr(subdomain.time, "sleep", lambda seconds: None)

    names, note = subdomain._certspotter("example.com")
    assert names == {"a.example.com"}
    assert note == ""
    assert "after" not in seen[0]
    assert seen[1]["after"] == "1"


def test_cert_spotter_keeps_partial_results_when_rate_limited(monkeypatch):
    responses = [FakeResponse(200, [{"id": "1", "dns_names": ["a.example.com"]}]),
                 FakeResponse(429)]
    monkeypatch.setattr(subdomain.requests, "get", lambda *a, **k: responses.pop(0))
    monkeypatch.setattr(subdomain.time, "sleep", lambda seconds: None)

    names, note = subdomain._certspotter("example.com")
    assert names == {"a.example.com"}
    assert "incomplete" in note


def test_cert_spotter_failure_on_the_first_page_is_reported(monkeypatch):
    monkeypatch.setattr(subdomain.requests, "get", lambda *a, **k: FakeResponse(429))

    names, note = subdomain._certspotter("example.com")
    assert names == set()
    assert "429" in note


def test_cert_spotter_stops_at_the_page_limit(monkeypatch):
    page = [{"id": "1", "dns_names": ["a.example.com"]}]
    monkeypatch.setattr(subdomain.requests, "get", lambda *a, **k: FakeResponse(200, page))
    monkeypatch.setattr(subdomain.time, "sleep", lambda seconds: None)

    names, note = subdomain._certspotter("example.com", max_pages=2)
    assert names == {"a.example.com"}
    assert "2 pages" in note