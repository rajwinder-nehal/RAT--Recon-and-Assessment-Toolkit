from rich.console import Console
from rich.panel import Panel

console = Console()

CHOICES = {
    "1": "target",
    "2": "nmap",
    "3": "whois",
    "4": "dns",
    "5": "geo",
    "6": "subdomain",
    "7": "report",
    "8": "exit",
}


def main_menu():

    while True:

        console.print(
            Panel.fit(
                """
[1] Set Target
[2] Nmap Scanner
[3] WHOIS Lookup
[4] DNS Lookup
[5] IP Geolocation
[6] Subdomain Enumeration
[7] Generate Report
[8] Exit
                """,
                title="[bold cyan]RAT MAIN MENU[/bold cyan]",
                border_style="green"
            )
        )

        choice = input("\nRAT > ").strip()

        if choice in CHOICES:
            return CHOICES[choice]

        console.print("[red]Invalid Option[/red]")