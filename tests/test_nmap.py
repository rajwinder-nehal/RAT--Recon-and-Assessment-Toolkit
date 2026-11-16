import subprocess
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from modules import nmap

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -F scanme.nmap.org">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames>
      <hostname name="scanme.nmap.org" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="25">
        <state state="filtered"/>
        <service name="smtp"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 3.2 - 4.9" accuracy="96"/>
    </os>
  </host>
</nmaprun>"""


# ---------- Target validation ----------

@pytest.mark.parametrize("target", [
    "scanme.nmap.org", "example.com", "my-host.example.com", "localhost",
    "192.168.1.10", "8.8.8.8", "2001:db8::1",
])
def test_accepts_single_hosts(target):
    nmap.validate_target(target)          # must not raise


@pytest.mark.parametrize("target", [
    "", None, "-oN", "a b", "192.168.1.0/24", "example.com;ls", "$(whoami)",
    "x" * 254,
    pytest.param("10.0.0.1-5", id="hyphen-range"),
    pytest.param("192.168.1.1-254", id="last-octet-range"),
    pytest.param("999.1.1.1", id="not-a-real-ip"),
    pytest.param("example.com\n", id="trailing-newline"),
])
def test_rejects_unsafe_or_ranged_targets(target):
    with pytest.raises(ValueError):
        nmap.validate_target(target)


# ---------- Flag validation ----------

@pytest.mark.parametrize("flags", [
    [], ["-F"], ["-sV"], ["-A"], ["-O"], ["-T4"], ["-p-"],
    ["-p", "80,443"], ["-p", "1-1000"],
])
def test_accepts_safe_flags(flags):
    nmap.validate_flags(flags)            # must not raise


@pytest.mark.parametrize("flags", [
    ["-oN", "out.txt"], ["-oX", "-"], ["-iL", "hosts.txt"],
    ["--script=vuln"], ["--script", "default"], ["--resume", "log"],
    ["--datadir=/tmp"], ["--send-eth"],
    ["-sV", "192.168.1.5"], ["scanme.nmap.org"], ["-p", "80;ls"],
])
def test_rejects_dangerous_flags_and_extra_targets(flags):
    with pytest.raises(ValueError):
        nmap.validate_flags(flags)


def test_presets_are_complete_and_valid():
    assert set(nmap.PRESETS) == {"quick", "service", "os", "full", "aggressive"}
    for flags in nmap.PRESETS.values():
        nmap.validate_flags(flags)


# ---------- XML parsing ----------

def test_parse_reads_host_details():
    r = nmap.parse_nmap_xml(SAMPLE_XML, "nmap -F scanme.nmap.org")
    assert r["Host State"] == "up"
    assert r["Address"] == "45.33.32.156"
    assert r["Hostname"] == "scanme.nmap.org"
    assert r["OS"] == "Linux 3.2 - 4.9 (96% match)"
    assert r["Command"] == "nmap -F scanme.nmap.org"


def test_parse_reads_every_port_with_service_and_version():
    r = nmap.parse_nmap_xml(SAMPLE_XML, "nmap -F scanme.nmap.org")
    assert len(r["Ports"]) == 3
    assert r["Ports"][0] == {"Port": "22/tcp", "State": "open",
                             "Service": "ssh", "Version": "OpenSSH 6.6.1p1 Ubuntu"}
    assert r["Ports"][1]["Version"] == ""          # no version reported
    assert r["Ports"][2]["State"] == "filtered"


def test_parse_builds_text_output_for_the_report():
    r = nmap.parse_nmap_xml(SAMPLE_XML, "nmap -F scanme.nmap.org", "Warning: slow")
    assert "22/tcp" in r["Output"]
    assert "OpenSSH 6.6.1p1" in r["Output"]
    assert "Notes: Warning: slow" in r["Output"]


def test_parse_host_down_has_no_ports():
    xml = '<nmaprun><host><status state="down"/><address addr="1.2.3.4"/></host></nmaprun>'
    r = nmap.parse_nmap_xml(xml, "nmap x")
    assert r["Host State"] == "down"
    assert r["Ports"] == []
    assert "No ports found." in r["Output"]


def test_parse_with_no_host_element_defaults_to_down():
    r = nmap.parse_nmap_xml("<nmaprun></nmaprun>", "nmap x")
    assert r["Host State"] == "down"
    assert r["Address"] == "N/A"
    assert r["Ports"] == []


def test_parse_rejects_garbage_input():
    with pytest.raises(ET.ParseError):
        nmap.parse_nmap_xml("this is not xml", "nmap x")


# ---------- run_nmap (nmap itself is faked, so no real scans) ----------

def fake_nmap(monkeypatch, stdout=SAMPLE_XML, stderr=""):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)

    monkeypatch.setattr(nmap.shutil, "which", lambda name: "nmap")
    monkeypatch.setattr(nmap.subprocess, "run", fake_run)
    return calls


def test_run_nmap_builds_the_expected_command(monkeypatch):
    calls = fake_nmap(monkeypatch)
    r = nmap.run_nmap("scanme.nmap.org", ["-F"])
    assert calls == [["nmap", "-F", "-oX", "-", "scanme.nmap.org"]]
    assert r["Command"] == "nmap -F scanme.nmap.org"
    assert len(r["Ports"]) == 3


def test_run_nmap_rejects_bad_target_without_running(monkeypatch):
    calls = fake_nmap(monkeypatch)
    with pytest.raises(ValueError):
        nmap.run_nmap("192.168.1.0/24", ["-F"])
    assert calls == []


def test_run_nmap_rejects_blocked_flags_without_running(monkeypatch):
    calls = fake_nmap(monkeypatch)
    with pytest.raises(ValueError):
        nmap.run_nmap("scanme.nmap.org", ["--script=vuln"])
    assert calls == []


def test_run_nmap_reports_missing_nmap(monkeypatch):
    monkeypatch.setattr(nmap.shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError, match="not installed"):
        nmap.run_nmap("scanme.nmap.org", ["-F"])


def test_run_nmap_raises_the_error_text_when_there_is_no_output(monkeypatch):
    fake_nmap(monkeypatch, stdout="", stderr="boom")
    with pytest.raises(RuntimeError, match="boom"):
        nmap.run_nmap("scanme.nmap.org", ["-F"])


def test_run_nmap_turns_a_timeout_into_a_clear_error(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=5)

    monkeypatch.setattr(nmap.shutil, "which", lambda name: "nmap")
    monkeypatch.setattr(nmap.subprocess, "run", fake_run)
    with pytest.raises(TimeoutError):
        nmap.run_nmap("scanme.nmap.org", ["-F"], timeout=5)