import ipaddress
import random
import re
import time
import string
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import requests
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from modules.nmap import validate_target
from modules.target import get_target
from modules import session

console = Console()

MAX_RESULTS = 500
NAME_RE = re.compile(r"^[a-z0-9.\-]+$")

WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email", "admin",
    "portal", "vpn", "vpn2", "dev", "test", "staging", "stage", "uat", "qa",
    "prod", "beta", "demo", "new", "old", "api", "app", "m", "mobile", "blog",
    "shop", "store", "cdn", "static", "assets", "img", "images", "media",
    "files", "download", "docs", "support", "help", "status", "git", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "intranet", "internal", "secure",
    "login", "auth", "sso", "remote", "ns1", "ns2", "mx", "mx1", "mail2",
    "autodiscover", "owa", "exchange", "cpanel", "whm", "db", "mysql", "sql",
    "backup", "monitor", "grafana", "kibana", "proxy", "gateway", "crm", "erp",
    "hr", "dashboard", "panel", "forum", "community", "news", "video", "chat",
    "ws", "web", "host", "server", "cloud", "calendar", "training", "learn",
    "lms", "student", "careers", "events", "partners", "pay", "billing",
    "accounts", "account", "my",
]

_resolver = dns.resolver.Resolver()
_resolver.timeout = 2
_resolver.lifetime = 3


def _check_domain(domain):
    """Subdomain enumeration only makes sense for a domain name."""
    validate_target(domain)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Subdomain enumeration needs a domain name, not an IP address.")
    if "." not in domain:
        raise ValueError("Enter a full domain name, such as example.com")


def _resolve(name):
    """Return the list of IPv4 addresses for a name, or [] if it doesn't resolve."""
    try:
        return sorted(a.to_text() for a in _resolver.resolve(name, "A"))
    except Exception:
        return []


def _resolve_many(names, threads):
    names = list(names)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        return dict(zip(names, pool.map(_resolve, names)))


def _wildcard_ips(domain):
    """If a random, surely-nonexistent name resolves, the domain uses wildcard DNS."""
    label = "".join(random.choices(string.ascii_lowercase, k=14))
    return set(_resolve(f"{label}.{domain}"))

def _crt_sh(domain):
    """Passive lookup in certificate transparency logs. Returns (names, note).
    Retries a few times, because crt.sh is often slow or overloaded."""
    rows = None
    last_error = ""

    for attempt in range(3):
        try:
            res = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"User-Agent": "RAT-recon/1.0"},
                timeout=30,
            )
            if res.status_code == 200:
                rows = res.json()
                break
            last_error = f"HTTP {res.status_code}"
        except Exception as e:
            last_error = type(e).__name__
        if attempt < 2:
            time.sleep(3 * (attempt + 1))   # wait 3s, then 6s

    if rows is None:
            return set(), f"crt.sh lookup failed ({last_error}) after 3 tries."

    suffix = "." + domain
    names = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(suffix) and NAME_RE.match(name):
                names.add(name)
    return names, ""

def _certspotter(domain, max_pages=5):
    """Backup passive source: Cert Spotter's free CT search API.
    Needs no key but is rate limited. Returns (names, note)."""
    suffix = "." + domain
    names = set()
    after = None
    note = ""

    try:
        for page_number in range(max_pages):
            params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
            if after:
                params["after"] = after

            res = requests.get(
                "https://api.certspotter.com/v1/issuances",
                params=params,
                headers={"User-Agent": "RAT-recon/1.0"},
                timeout=30,
            )
            if res.status_code != 200:
                if names:
                    return names, "Cert Spotter stopped early (rate limit), so the list may be incomplete."
                return set(), f"Cert Spotter lookup failed (HTTP {res.status_code})."

            page = res.json()
            if not page:
                break

            for item in page:
                for name in item.get("dns_names", []):
                    name = str(name).strip().lower().lstrip("*.")
                    if name.endswith(suffix) and NAME_RE.match(name):
                        names.add(name)

            after = page[-1].get("id")
            if not after:
                break
            time.sleep(1)   # be polite to the free API
        else:
            note = f"Cert Spotter was limited to {max_pages} pages, so the list may be incomplete."
    except Exception as e:
        if names:
            return names, "Cert Spotter stopped early, so the list may be incomplete."
        return set(), f"Cert Spotter lookup failed ({type(e).__name__})."

    return names, note

def enumerate_subdomains(domain, brute=True, wordlist=None, threads=20):
    """Find subdomains of a domain. Prints nothing and returns a dict.
    Raises ValueError for an invalid domain."""
    domain = domain.strip().lower()
    _check_domain(domain)
    threads = max(1, min(int(threads), 50))
    notes = []

        # 1) Passive: certificate transparency logs (crt.sh first, Cert Spotter as backup)
    ct_source = "crt.sh"
    ct_names, note = _crt_sh(domain)
    if note:
        backup_names, backup_note = _certspotter(domain)
        if backup_names:
            ct_names, ct_source = backup_names, "certspotter"
            notes.append(f"{note} Used Cert Spotter instead.")
            if backup_note:
                notes.append(backup_note)
        else:
            notes.append(f"{note} {backup_note}")
    if len(ct_names) > MAX_RESULTS:
        notes.append(f"The certificate logs returned {len(ct_names)} names; "
                     f"only the first {MAX_RESULTS} are shown.")
        ct_names = set(sorted(ct_names)[:MAX_RESULTS])


    # 2) Active: wordlist brute force
    candidates = set()
    wildcard = set()
    if brute:
        wildcard = _wildcard_ips(domain)
        if wildcard:
            notes.append("Wildcard DNS detected: every name resolves, so brute-force "
                         "results that match the wildcard were ignored.")
        candidates = {f"{w}.{domain}" for w in (wordlist or WORDLIST)}

    # 3) Resolve everything once, then merge the sources
    ips = _resolve_many(ct_names | candidates, threads)

    results = []
    for name in sorted(ct_names | candidates):
        found_by = set()
        if name in ct_names:
            found_by.add(ct_source)
        if name in candidates:
            addresses = set(ips[name])
            if addresses and not (wildcard and addresses <= wildcard):
                found_by.add("bruteforce")
        if not found_by:
            continue
        results.append({
            "Subdomain": name,
            "IPs": ips[name],
            "Resolves": bool(ips[name]),
            "Source": ", ".join(sorted(found_by)),
        })

    return {
        "Domain": domain,
        "Brute Force": brute,
        "Wildcard DNS": bool(wildcard),
        "Notes": notes,
        "Subdomains": results,
    }


def subdomain_enum():
    """Terminal version: asks before running the active brute force."""
    target = get_target()

    if not target:
        console.print("[red]Please set target first.[/red]")
        return

    answer = input(f"\nAlso brute force {len(WORDLIST)} common names? "
                   f"This sends DNS queries for them. (y/n): ")
    brute = answer.strip().lower() == "y"

    try:
        with console.status("[yellow]Enumerating subdomains...[/yellow]"):
            result = enumerate_subdomains(target, brute=brute)
    except Exception as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        return

    for note in result["Notes"]:
        console.print(f"[yellow]{escape(note)}[/yellow]")

    subs = result["Subdomains"]
    if not subs:
        console.print("[yellow]No subdomains found.[/yellow]")
    else:
        table = Table(border_style="cyan")
        for col in ("Subdomain", "IP address", "Source"):
            table.add_column(col)
        for s in subs:
            ip_text = ", ".join(s["IPs"]) if s["Resolves"] else "[dim]no DNS record[/dim]"
            table.add_row(escape(s["Subdomain"]), ip_text, s["Source"])
        console.print(table)
        live = sum(1 for s in subs if s["Resolves"])
        console.print(f"\n[green]{len(subs)} subdomains found, {live} resolving.[/green]")

    session.add("subdomains", result)