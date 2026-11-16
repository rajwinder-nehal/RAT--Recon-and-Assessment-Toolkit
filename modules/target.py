from rich.console import Console

from modules import session

console = Console()

current_target = None


def set_target():

    global current_target

    # Imported here to avoid a circular import (nmap.py imports this module)
    from modules.nmap import validate_target

    target = input("\nEnter Target (IP/Domain): ").strip()

    if target == "":
        console.print("[red]Target cannot be empty.[/red]")
        return

    try:
        validate_target(target)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    current_target = target
    session.clear()

    console.print(f"\n[green]✔ Target Set Successfully : {current_target}[/green]")


def get_target():
    return current_target