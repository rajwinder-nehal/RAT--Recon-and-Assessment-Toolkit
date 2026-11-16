from rich.progress import Progress
import time

def loading():

    tasks = [
        "Loading Modules",
        "Checking Dependencies",
        "Loading Configuration",
        "Initializing Scanner",
        "Preparing Interface"
    ]

    with Progress() as progress:

        task = progress.add_task("[cyan]Starting RAT...", total=len(tasks))

        for item in tasks:
            time.sleep(0.5)
            progress.update(task, advance=1, description=f"[green]✔ {item}")

    print("\n[+] Toolkit Ready!\n")
