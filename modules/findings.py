import re
from datetime import datetime

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from modules import session

console = Console()

SEVERITIES = ["High", "Medium", "Low", "Info"]
ORDER = {name: i for i, name in enumerate(SEVERITIES)}
COLORS = {"High": "red", "Medium": "yellow", "Low": "cyan", "Info": "dim"}

# port -> (severity, title, recommendation)
RISKY_PORTS = {
    21:    ("Medium", "FTP exposed", "FTP sends passwords in clear text. Use SFTP or FTPS, or restrict access."),
    23:    ("High",   "Telnet exposed", "Telnet is unencrypted and often has weak credentials. Disable it and use SSH."),
    110:   ("Low",    "POP3 exposed (clear text)", "Use POP3S or IMAPS so mail logins are encrypted."),
    135:   ("Medium", "Windows RPC exposed", "Block this port at the firewall. It should not be reachable from the internet."),
    139:   ("Medium", "NetBIOS exposed", "Block this port at the firewall. It should not be reachable from the internet."),
    445:   ("High",   "SMB exposed", "SMB has a long history of serious vulnerabilities. Block it at the firewall."),
    1433:  ("High",   "Microsoft SQL Server exposed", "Databases should not face the internet. Restrict access to trusted hosts or a VPN."),
    1521:  ("High",   "Oracle database exposed", "Databases should not face the internet. Restrict access to trusted hosts or a VPN."),
    3306:  ("High",   "MySQL exposed", "Databases should not face the internet. Restrict access to trusted hosts or a VPN."),
    3389:  ("High",   "Remote Desktop (RDP) exposed", "RDP is a common ransomware entry point. Put it behind a VPN and enable network-level authentication."),
    5432:  ("High",   "PostgreSQL exposed", "Databases should not face the internet. Restrict access to trusted hosts or a VPN."),
    5900:  ("High",   "VNC exposed", "VNC is often weakly protected. Put it behind a VPN or tunnel it over SSH."),
    5985:  ("Medium", "Windows Remote Management exposed", "Restrict WinRM to management networks only."),
    6379:  ("High",   "Redis exposed", "Redis often has no authentication by default. Bind it to localhost or require a password and firewall it."),
    9200:  ("High",   "Elasticsearch exposed", "Exposed Elasticsearch has caused many data leaks. Restrict access and enable authentication."),
    11211: ("High",   "Memcached exposed", "Memcached has no authentication. Bind it to localhost or firewall it."),
    27017: ("High",   "MongoDB exposed", "Exposed MongoDB has caused many data leaks. Restrict access and enable authentication."),
}

SENSITIVE_WORDS = {
    "dev", "test", "staging", "stage", "uat", "qa", "beta", "demo", "old",
    "admin", "vpn", "internal", "intranet", "backup", "db", "sql", "mysql",
    "jenkins", "git", "gitlab", "jira", "grafana", "kibana", "monitor",
    "phpmyadmin", "cpanel", "whm",
}


def _f(severity, title, detail, fix, source):
    return {"Severity": severity, "Title": title, "Detail": detail,
            "Recommendation": fix, "Source": source}


# ---------- Checks (each one reads the saved results of a module) ----------

def _check_nmap(d):
    out = []
    if d.get("Host State") == "down":
        return out

    open_ports = [p for p in d.get("Ports", []) if p.get("State") == "open"]
    numbers = set()

    for p in open_ports:
        try:
            number, proto = p["Port"].split("/")
            number = int(number)
        except (KeyError, ValueError):
            continue
        if proto != "tcp":
            continue
        numbers.add(number)
        if number in RISKY_PORTS:
            severity, title, fix = RISKY_PORTS[number]
            service = p.get("Service") or "unknown"
            out.append(_f(severity, f"{title} (port {number})",
                          f"Port {p['Port']} is open (service: {service}).", fix, "Nmap"))

    if 80 in numbers and 443 not in numbers:
        out.append(_f("Low", "HTTP without HTTPS",
                      "Port 80 is open but port 443 is not, so web traffic may be unencrypted.",
                      "Serve the site over HTTPS and redirect HTTP to it.", "Nmap"))

    if len(open_ports) >= 10:
        out.append(_f("Low", "Large number of open ports",
                      f"{len(open_ports)} open ports were found.",
                      "Close services that are not needed and firewall the rest.", "Nmap"))

    versions = [f"{p['Port']} {p['Version']}" for p in open_ports if p.get("Version")]
    if versions:
        shown = "; ".join(versions[:5])
        if len(versions) > 5:
            shown += f" (+{len(versions) - 5} more)"
        out.append(_f("Info", "Service versions are visible", shown,
                      "Check these versions against known vulnerabilities and hide version banners where possible.",
                      "Nmap"))
    return out


def _check_dns(d):
    out = []
    # Email rules only make sense for domains that receive mail
    if not d.get("MX"):
        return out

    txt = [t.replace('"', "") for t in d.get("TXT", [])]
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)

    if spf is None:
        out.append(_f("Medium", "No SPF record",
                      "The domain receives mail (MX records exist) but has no SPF record.",
                      "Publish an SPF record that lists the servers allowed to send email for the domain.", "DNS"))
    else:
        tokens = spf.lower().split()
        policy = next((t for t in tokens if t in ("+all", "all", "-all", "~all", "?all")), None)
        if policy in ("+all", "all"):
            out.append(_f("High", "SPF allows any sender",
                          f"The SPF record ends with '{policy}', so anyone can send mail as this domain.",
                          "End the SPF record with '-all' (or '~all' while testing).", "DNS"))
        elif policy == "?all":
            out.append(_f("Low", "SPF has a neutral policy (?all)",
                          "The SPF record does not tell receivers what to do with unauthorized senders.",
                          "Change '?all' to '~all' or '-all'.", "DNS"))
        elif policy == "~all":
            out.append(_f("Info", "SPF uses soft fail (~all)",
                          "Unauthorized senders are marked suspicious but not rejected.",
                          "Move to '-all' once you are sure all legitimate senders are listed.", "DNS"))

    dmarc = next((t.replace('"', "") for t in d.get("DMARC", []) if "v=dmarc1" in t.lower()), None)
    if dmarc is None:
        out.append(_f("Medium", "No DMARC record",
                      "The domain receives mail but publishes no DMARC policy, which makes spoofing easier.",
                      "Publish a DMARC record at _dmarc.<domain>, starting with p=none and moving to quarantine or reject.",
                      "DNS"))
    else:
        match = re.search(r"\bp\s*=\s*(\w+)", dmarc, re.I)
        if match and match.group(1).lower() == "none":
            out.append(_f("Low", "DMARC policy is monitoring only (p=none)",
                          "Spoofed mail is reported but not blocked.",
                          "Move the policy to p=quarantine or p=reject once reports look clean.", "DNS"))
    return out


def _parse_date(text):
    match = re.search(r"\d{4}-\d{2}-\d{2}", str(text))
    if not match:
        return None
    try:
        return datetime.strptime(match.group(0), "%Y-%m-%d")
    except ValueError:
        return None


def _check_whois(d):
    expires = _parse_date(d.get("Expires"))
    if expires is None:
        return []
    days = (expires - datetime.now()).days
    if days < 0:
        return [_f("High", "Domain registration has expired",
                   f"The domain expired on {expires.date()}.",
                   "Renew the domain immediately. An expired domain can be taken over by someone else.", "WHOIS")]
    if days <= 30:
        return [_f("Medium", "Domain expires soon", f"The domain expires in {days} days ({expires.date()}).",
                   "Renew the domain and enable auto-renewal.", "WHOIS")]
    if days <= 90:
        return [_f("Low", "Domain expires within 90 days", f"The domain expires in {days} days ({expires.date()}).",
                   "Renew the domain and enable auto-renewal.", "WHOIS")]
    return []


def _check_subdomains(d):
    out = []
    subs = d.get("Subdomains", [])
    if not subs:
        return out

    domain = d.get("Domain", "")
    live = [s for s in subs if s.get("Resolves")]
    stale = [s for s in subs if not s.get("Resolves")]

    out.append(_f("Info", "Subdomains discovered", f"{len(subs)} found, {len(live)} resolving.",
                  "Review the list and remove DNS records for services that are no longer used.", "Subdomains"))

    sensitive = []
    for s in live:
        label = s["Subdomain"].removesuffix("." + domain)
        if SENSITIVE_WORDS & set(re.split(r"[^a-z]+", label)):
            sensitive.append(s["Subdomain"])
    if sensitive:
        shown = ", ".join(sensitive[:10])
        if len(sensitive) > 10:
            shown += f" (+{len(sensitive) - 10} more)"
        out.append(_f("Low", "Potentially sensitive subdomains are publicly resolvable", shown,
                      "Make sure development, admin and internal systems are not reachable from the internet, "
                      "or protect them with authentication or a VPN.", "Subdomains"))

    if stale:
        examples = ", ".join(s["Subdomain"] for s in stale[:3])
        out.append(_f("Info", f"{len(stale)} subdomain(s) have no DNS record",
                      f"Seen in certificate logs but not resolving, for example: {examples}.",
                      "These may be old certificates. Confirm the services were decommissioned and no records are left dangling.",
                      "Subdomains"))

    if d.get("Wildcard DNS"):
        out.append(_f("Info", "Wildcard DNS is enabled",
                      "Every possible subdomain resolves, which can hide real hosts and complicate enumeration.",
                      "Use wildcard records only if you need them.", "Subdomains"))
    return out


# ---------- Public functions ----------

def analyze():
    """Read the saved results and return a list of findings, most severe first."""
    checks = [("nmap", _check_nmap), ("dns", _check_dns),
              ("whois", _check_whois), ("subdomains", _check_subdomains)]
    findings = []
    for key, check in checks:
        entry = session.get(key)
        if entry:
            findings.extend(check(entry["data"]))
    findings.sort(key=lambda f: ORDER[f["Severity"]])
    return findings


def count_by_severity(findings):
    counts = {name: 0 for name in SEVERITIES}
    for f in findings:
        counts[f["Severity"]] += 1
    return counts


def findings_cli():
    """Terminal view of the findings."""
    findings = analyze()
    if not findings:
        console.print("[yellow]No findings. Run some modules first (Nmap, DNS, WHOIS, Subdomains).[/yellow]")
        return

    table = Table(border_style="cyan", show_lines=True)
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Details and fix")

    for f in findings:
        color = COLORS[f["Severity"]]
        table.add_row(
            f"[{color}]{f['Severity']}[/{color}]",
            escape(f["Title"]),
            f"{escape(f['Detail'])}\n[dim]Fix: {escape(f['Recommendation'])}[/dim]",
        )
    console.print(table)

    counts = count_by_severity(findings)
    console.print("  ".join(f"[{COLORS[s]}]{s}: {counts[s]}[/{COLORS[s]}]" for s in SEVERITIES))