import dns.resolver
from rich.console import Console
from rich.panel import Panel
from modules.target import get_target
from modules import session

console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


def _lookup(name, record_type):
    try:
        answers = dns.resolver.resolve(name, record_type, lifetime=5)
        return [a.to_text() for a in answers]
    except Exception:
        return []


def get_dns_records(target):
    """Return DNS records as a dict, e.g. {"A": ["93.184.216.34"], "MX": []}.
    Prints nothing, so both the CLI and the web app can use it."""
    found = {record: _lookup(target, record) for record in RECORD_TYPES}
    found["DMARC"] = _lookup(f"_dmarc.{target}", "TXT")
    return found


def dns_lookup():

    target = get_target()

    if not target:
        console.print("[red]Please set a target first.[/red]")
        return

    console.print(
        Panel.fit(
            f"DNS Lookup: {target}",
            border_style="cyan"
        )
    )

    found = get_dns_records(target)

    for record, values in found.items():
        console.print(f"\n[bold yellow]{record} Records[/bold yellow]")
        if values:
            for v in values:
                console.print(v)
        else:
            console.print("[red]No record found[/red]")

    # Save only the records that exist, so the PDF report stays clean
    session.add("dns", {k: v for k, v in found.items() if v})