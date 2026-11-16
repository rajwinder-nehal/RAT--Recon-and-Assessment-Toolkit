from modules import session


def test_get_returns_none_for_unknown_module():
    assert session.get("nmap") is None


def test_add_then_get_returns_data_and_timestamp():
    session.add("dns", {"A": ["1.2.3.4"]})
    entry = session.get("dns")
    assert entry["data"] == {"A": ["1.2.3.4"]}
    assert entry["time"]          # a non-empty timestamp string


def test_adding_again_replaces_the_old_result():
    session.add("dns", {"A": ["1.1.1.1"]})
    session.add("dns", {"A": ["2.2.2.2"]})
    assert session.get("dns")["data"] == {"A": ["2.2.2.2"]}


def test_clear_removes_everything():
    session.add("dns", {})
    session.add("whois", {})
    session.clear()
    assert session.get("dns") is None
    assert session.get("whois") is None