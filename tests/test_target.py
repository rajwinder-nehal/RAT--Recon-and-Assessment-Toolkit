from modules import target as target_state


def type_into_prompt(monkeypatch, text):
    monkeypatch.setattr("builtins.input", lambda prompt="": text)


def test_set_target_accepts_a_domain_and_trims_spaces(monkeypatch):
    type_into_prompt(monkeypatch, "  scanme.nmap.org ")
    target_state.set_target()
    assert target_state.get_target() == "scanme.nmap.org"


def test_set_target_rejects_ranges(monkeypatch):
    type_into_prompt(monkeypatch, "10.0.0.1-5")
    target_state.set_target()
    assert target_state.get_target() is None


def test_set_target_rejects_empty_input(monkeypatch):
    type_into_prompt(monkeypatch, "")
    target_state.set_target()
    assert target_state.get_target() is None