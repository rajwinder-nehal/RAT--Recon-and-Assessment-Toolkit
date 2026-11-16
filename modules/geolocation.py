import requests
from rich.console import Console
from rich.panel import Panel
from modules.target import get_target
from modules import session

console = Console()


def get_geolocation(target):
    """Return location info as a dict. Prints nothing.
    Raises an exception if the lookup fails, so the caller can show the error."""
    url = f"http://ip-api.com/json/{target}"
    data = requests.get(url, timeout=10).json()

    if data.get("status") != "success":
        raise ValueError(data.get("message", "Unable to fetch location"))

    return {
        "IP": data.get("query"),
        "Country": data.get("country"),
        "Region": data.get("regionName"),
        "City": data.get("city"),
        "ZIP": data.get("zip"),
        "Latitude": data.get("lat"),
        "Longitude": data.get("lon"),
        "Timezone": data.get("timezone"),
        "ISP": data.get("isp"),
        "Organization": data.get("org"),
    }


def geolocation():

    target = get_target()

    if not target:
        console.print("[red]Please set target first.[/red]")
        return

    console.print(f"\n[cyan]Getting Geolocation of {target}...\n")

    try:
        result = get_geolocation(target)

        console.print(Panel.fit("IP GEOLOCATION", border_style="green"))

        for key, value in result.items():
            console.print(f"{key:<13}: {value}")

        session.add("geo", result)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")