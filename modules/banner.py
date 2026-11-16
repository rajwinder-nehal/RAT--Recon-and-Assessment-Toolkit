from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def show_banner():

    banner = r"""

██████╗  █████╗ ████████╗
██╔══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║   ██║
██╔══██╗██╔══██║   ██║
██║  ██║██║  ██║   ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

   Recon Automation Toolkit
    """

    console.print(
        Panel.fit(
            Text(banner, style="bold cyan"),
            title="[bold green]RAT v1.0[/bold green]",
            subtitle="[yellow]For authorized testing only[/yellow]",
            border_style="bright_blue"
        )
    )