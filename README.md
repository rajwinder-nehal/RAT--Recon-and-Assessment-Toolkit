# PTAF - Recon Automation Toolkit

![Tests](https://github.com/<your-username>/PTAF/actions/workflows/tests.yml/badge.svg)

A Python toolkit that automates the reconnaissance phase of an authorized security assessment and turns the raw results into severity-rated findings. It runs from the **terminal** or from a **local web dashboard**, and both share the same core modules.

> **For authorized testing and educational use only.** Only scan systems you own or have written permission to test. `scanme.nmap.org` is provided by the Nmap project for practice.

## Screenshots

![Dashboard](docs/dashboard.png)
![PDF report](docs/report.png)
![Terminal](docs/terminal.png)

## Features

- **Nmap orchestration** with XML output parsed into ports, services and versions
- **DNS lookup** (A, AAAA, MX, NS, TXT, DMARC), **WHOIS**, and **IP geolocation**
- **Subdomain enumeration**: certificate transparency logs (crt.sh, with Cert Spotter as an automatic backup) plus an optional threaded brute force, with wildcard DNS detection
- **Findings engine**: rates exposed services (RDP, databases, Telnet), email security gaps (SPF, DMARC), domain expiry and sensitive subdomains as High, Medium, Low or Info, each with a fix recommendation
- **PDF report** with a severity summary, findings table and a section per module
- **Web dashboard** (Flask) with background scans and live status
- **Safety checks**: single hosts only (no ranges), dangerous nmap flags blocked, optional target allowlist, authorization confirmation, brute force off by default
- **159 automated tests** with all network calls faked

## Requirements

- Python 3.10 or newer
- [Nmap](https://nmap.org/download.html) installed and on your PATH

## Setup (Windows)

```
git clone https://github.com/<your-username>/PTAF.git
cd PTAF
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Usage

**Web dashboard**
```
python app.py
```
Open http://127.0.0.1:5000, enter a target, tick the authorization box, run the modules, and download the report.

**Terminal version**
```
python main.py
```

**Restrict which targets are allowed** (optional)
```
$env:PTAF_ALLOWED_TARGETS="scanme.nmap.org,example.com"
python app.py
```

**Run the tests**
```
python -m pytest -q
```

## Project structure

```
app.py              Flask server and API routes
main.py             Terminal menu
templates/          Dashboard page
static/             Dashboard CSS and JavaScript
modules/
  nmap.py             Runs nmap, parses XML, validates targets and flags
  dns_lookup.py       DNS records, including DMARC
  whois_lookup.py     WHOIS data
  geolocation.py      IP geolocation
  subdomain.py        Subdomain enumeration
  findings.py         Rules that turn results into rated findings
  report.py           PDF report generator
  session.py          Stores results for findings and the report
tests/              pytest suite
```

## Design notes

- Each module has a function that **returns data** and a thin wrapper that prints it, so the CLI and the web app reuse the same code.
- Nmap output is parsed from XML (`-oX`) instead of scraping text.
- The web version only offers preset scans, ignores custom flags, and runs one scan at a time in a background thread.
- Target validation rejects ranges (such as `10.0.0.1-5`), invalid IPs and anything that could be read as an nmap option. A test for this caught a bypass in an earlier version.
- If crt.sh is down or overloaded, the tool retries and then falls back to Cert Spotter, and tells the user what happened.
- The server binds to `127.0.0.1` with debug mode off.

## Limitations

- Results are kept in one shared in-memory store, so the web app supports **one user at a time** and is meant to run locally.
- Findings only reflect the modules that were run for the current target.
- OS detection and aggressive scans need administrator rights on Windows.
- Geolocation uses the free ip-api.com service, which is rate limited.

## Roadmap

- TLS certificate analysis
- Per-user sessions for safe hosting
- Scan history and comparison
- Docker image

## Author

<Rajwinder> 