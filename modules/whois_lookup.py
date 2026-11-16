import whois
from rich.console import Console
from rich.panel import Panel
from modules.target import get_target
from modules import session

console = Console()


def _clean(value):
    """WHOIS often returns a list (e.g. two dates). Keep the first item as text."""
    if isinstance(value, (list, tuple, set)):
        value = next(iter(value), None)
    return "N/A" if value is None else str(value)


def get_whois_data(target):
    """Return WHOIS info as a dict of text values. Prints nothing.
    Raises an exception if the lookup fails, so the caller can show the error."""
    data = whois.whois(target)

    name_servers = data.name_servers or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]

    return {
        "Domain": _clean(data.domain_name),
        "Registrar": _clean(data.registrar),
        "Created": _clean(data.creation_date),
        "Expires": _clean(data.expiration_date),
        "Name Servers": ", ".join(sorted({str(n).lower() for n in name_servers})) or "N/A",
    }


def whois_lookup():

    target = get_target()

    if target is None:
        console.print("[red]No Target Set![/red]")
        return

    console.print(f"\n[cyan]Running WHOIS on {target}...[/cyan]\n")

    try:
        result = get_whois_data(target)

        console.print(Panel.fit("WHOIS RESULT", style="green"))

        for key, value in result.items():
            console.print(f"{key:<13}: {value}")

        session.add("whois", result)

    except Exception as e:
        console.print(f"[red]{e}[/red]")