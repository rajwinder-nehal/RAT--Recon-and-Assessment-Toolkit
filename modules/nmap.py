import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import ipaddress

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from modules.target import get_target
from modules import session

console = Console()

# Scan types used by the menu (and later by the web app)
PRESETS = {
    "quick": ["-F"],
    "service": ["-sV"],
    "os": ["-O"],
    "full": ["-p-"],
    "aggressive": ["-A"],
}

# Flags that could write files, read files or run scripts are not allowed
BLOCKED_FLAGS = ("-o", "-iL", "--script", "--datadir", "--resume",
                 "--stylesheet", "--excludefile", "--append-output",
                 "--interactive", "--send-")

TARGET_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-:]*[A-Za-z0-9])?$")
VALUE_RE = re.compile(r"^[0-9][0-9,\-]*$")  # values like 80,443 or 1-1000


def validate_target(target):
    """Allow a single host or IP only (no ranges, no spaces, no leading dash)."""
    if not target or len(target) > 253 or not TARGET_RE.fullmatch(target):
        raise ValueError("Invalid target. Use a single domain or IP, such as scanme.nmap.org")

    # Names made only of digits, dots and hyphens must be real IP addresses.
    # Otherwise nmap would read something like 10.0.0.1-5 as a range of hosts.
    if re.fullmatch(r"[0-9.\-]+", target):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ValueError("Invalid IP address. Ranges are not allowed.") from None


def validate_flags(flags):
    """Reject dangerous flags and anything that looks like an extra target."""
    for f in flags:
        if f.startswith(BLOCKED_FLAGS):
            raise ValueError(f"Flag not allowed: {f}")
        if not f.startswith("-") and not VALUE_RE.match(f):
            raise ValueError(f"Unexpected value: {f}")


def parse_nmap_xml(xml_text, command, warnings=""):
    """Turn nmap's XML output into a simple dictionary."""
    root = ET.fromstring(xml_text)

    result = {
        "Command": command,
        "Host State": "down",
        "Address": "N/A",
        "Hostname": "N/A",
        "OS": "N/A",
        "Ports": [],
    }

    host = root.find("host")
    if host is not None:
        status = host.find("status")
        if status is not None:
            result["Host State"] = status.get("state", "unknown")

        addr = host.find("address")
        if addr is not None:
            result["Address"] = addr.get("addr", "N/A")

        hostname = host.find("./hostnames/hostname")
        if hostname is not None:
            result["Hostname"] = hostname.get("name", "N/A")

        osmatch = host.find("./os/osmatch")
        if osmatch is not None:
            result["OS"] = f"{osmatch.get('name')} ({osmatch.get('accuracy')}% match)"

        for port in host.findall("./ports/port"):
            state = port.find("state")
            svc = port.find("service")
            version = ""
            if svc is not None:
                version = " ".join(filter(None, [svc.get("product"),
                                                 svc.get("version"),
                                                 svc.get("extrainfo")]))
            result["Ports"].append({
                "Port": f"{port.get('portid')}/{port.get('protocol')}",
                "State": state.get("state", "") if state is not None else "",
                "Service": svc.get("name", "") if svc is not None else "",
                "Version": version,
            })

    result["Output"] = format_text(result, warnings)
    return result


def format_text(result, warnings=""):
    """Plain-text summary used by the PDF report."""
    lines = [f"Host: {result['Hostname']} ({result['Address']}) is {result['Host State']}"]
    if result["OS"] != "N/A":
        lines.append(f"OS guess: {result['OS']}")
    lines.append("")
    if result["Ports"]:
        lines.append(f"{'PORT':<12}{'STATE':<10}{'SERVICE':<14}VERSION")
        for p in result["Ports"]:
            lines.append(f"{p['Port']:<12}{p['State']:<10}{p['Service']:<14}{p['Version']}")
    else:
        lines.append("No ports found.")
    if warnings:
        lines.append("")
        lines.append(f"Notes: {warnings}")
    return "\n".join(lines)


def run_nmap(target, flags, timeout=900):
    """Run nmap and return the parsed result dict. Prints nothing.
    Raises an exception with a readable message if anything fails."""
    validate_target(target)
    validate_flags(flags)

    if shutil.which("nmap") is None:
        raise FileNotFoundError(
            "nmap is not installed or not on PATH. Install it from nmap.org "
            "and reopen the terminal.")

    shown = " ".join(["nmap", *flags, target])
    command = ["nmap", *flags, "-oX", "-", target]  # "-oX -" = XML on stdout

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Scan took longer than {timeout} seconds and was stopped.")

    if not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or "nmap returned no output.")

    return parse_nmap_xml(proc.stdout, shown, proc.stderr.strip())


def scan_cli(flags):
    """Run a scan from the terminal menu and show the results."""
    target = get_target()

    if target is None:
        console.print("\n[red]No Target Set![/red]")
        return

    console.print("\n[cyan]Running Command:[/cyan]")
    console.print("[green]" + escape(" ".join(["nmap", *flags, target])) + "[/green]\n")

    try:
        with console.status("[yellow]Scanning, please wait...[/yellow]"):
            result = run_nmap(target, flags)
    except Exception as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        return

    console.print(f"Host   : {result['Hostname']} ({result['Address']}) is {result['Host State']}")
    if result["OS"] != "N/A":
        console.print(f"OS     : {escape(result['OS'])}")

    if result["Ports"]:
        table = Table(border_style="cyan")
        for col in ("Port", "State", "Service", "Version"):
            table.add_column(col)
        for p in result["Ports"]:
            table.add_row(p["Port"], p["State"], escape(p["Service"]), escape(p["Version"]))
        console.print(table)
    else:
        console.print("[yellow]No ports found.[/yellow]")

    session.add("nmap", result)


def custom_scan():

    target = get_target()

    if target is None:
        console.print("[red]Set target first![/red]")
        return

    flags = input("\nEnter Nmap Flags : ").split()

    try:
        validate_flags(flags)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    console.print("\n[yellow]Command Preview[/yellow]")
    console.print(escape(" ".join(["nmap", *flags, target])))

    run = input("\nRun Scan? (y/n): ")

    if run.lower() == "y":
        scan_cli(flags)


def nmap_menu():

    while True:

        console.print(
            Panel.fit(
"""
1. Quick Scan

2. Service Detection

3. OS Detection

4. Full TCP Scan

5. Aggressive Scan

6. Custom Scan

7. Back
""",
title="NMAP SCANNER",
border_style="cyan"
            )
        )

        console.print(f"\nCurrent Target : [green]{get_target()}[/green]\n")

        choice = input("Select Option : ")

        if choice == "1":
            scan_cli(PRESETS["quick"])

        elif choice == "2":
            scan_cli(PRESETS["service"])

        elif choice == "3":
            scan_cli(PRESETS["os"])

        elif choice == "4":
            scan_cli(PRESETS["full"])

        elif choice == "5":
            scan_cli(PRESETS["aggressive"])

        elif choice == "6":
            custom_scan()

        elif choice == "7":
            break

        else:
            console.print("[red]Invalid Option[/red]")