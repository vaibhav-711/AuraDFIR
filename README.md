# Aura DFIR

**An open-source web server log analysis and incident-response platform, built on the Elastic Stack.**


## What is Aura DFIR?

Aura DFIR is a self-hosted investigation workbench for anyone who has ever been handed a 4 GB
`access.log` and asked *"were we hacked?"*. You create a **case**, upload raw Apache / Nginx / IIS
logs (or load-balancer/proxy logs — see below), and Aura DFIR indexes them into Elasticsearch,
runs a layered **detection engine** over them (attack signatures, brute-force detection,
enumeration, data-exfil outliers), enriches every attacker IP with **AbuseIPDB reputation
scores**, and reconstructs a **visual, session-based attack timeline** — recon → exploitation →
post-exploitation → exfiltration — that you can view as a chart or export for your report.

It is built for:

- **DFIR analysts** triaging a web server compromise
- **SOC teams** doing retro-hunts over historic access logs
- **Sysadmins / developers** who want more than `grep` but less than a full SIEM
- **Students & CTF players** learning web attack forensics

Everything runs locally. No log data ever leaves your machine except the IP addresses you
explicitly submit to AbuseIPDB.

### Important: how detection actually works (no AI/ML)

Aura DFIR does **not** use AI, machine learning, or an LLM to decide what's malicious. Every
finding comes from one of three fully transparent, deterministic methods:

1. **Signature matching** — ~25 categories of known-bad patterns (SQL injection, XSS, webshells,
   Log4Shell, etc.) written as plain regular expressions. See `app/analysis/rules.py`.
2. **Behavioural thresholds** — plain counting rules run as Elasticsearch aggregations (e.g. "20+
   failed logins from one IP in 5 minutes = brute force", "single IP served 100× the median
   bytes = possible exfiltration").
3. **Basic statistics** — z-score outlier detection on hourly traffic volume (no fancy math, just
   mean/standard-deviation).

This is a deliberate design choice, not a limitation: every single finding traces back to a
specific, readable rule or number you can point to in a report — nothing is a black-box judgment
call you can't explain or defend. If you want AI-assisted summarisation on top of these findings,
that's on the roadmap (see below) as an optional add-on, not a replacement for the core engine.

## Technical description

| Layer | Technology |
|---|---|
| API + Web UI | Python 3.11+, FastAPI, Jinja2 (server-rendered, zero build step) |
| App database | SQLite via SQLAlchemy (users, sessions, cases, API keys, IP reputation cache) |
| Log storage / search | Elasticsearch 8.x (one index per case, ECS-style field names) |
| Visualisation (optional) | Kibana pointed at the `auradfir-*` indices |
| Auth | Password (PBKDF2-SHA256) + mandatory TOTP 2FA (RFC 6238), DB-backed sessions |
| Threat intel | AbuseIPDB v2 API with multi-key pooling, daily-quota tracking and a local reputation cache |

### Architecture

```
                    ┌────────────────────────────────────────────┐
 raw logs ──parse──▶│  Ingest (combined / vhost / IIS W3C → ECS) │
                    └───────────────┬────────────────────────────┘
                                    ▼ bulk
                    ┌──────────────────────────────┐
                    │  Elasticsearch               │◀── Kibana (optional)
                    │  auradfir-case<N>-logs        │
                    │  auradfir-case<N>-findings    │
                    └───────┬──────────────┬───────┘
                            │              │
              ┌─────────────▼───┐   ┌──────▼──────────────┐
              │ Detection engine│   │ Timeline correlation │
              │ sigs + aggs +   │   │ sessionize, phase    │
              │ statistics      │   │ tagging, export      │
              └─────────────┬───┘   └──────┬──────────────┘
                            ▼              ▼
                    ┌──────────────────────────────┐     ┌────────────┐
                    │  FastAPI web UI              │────▶│ AbuseIPDB  │
                    │  auth+2FA · cases · admin    │     │ key pool   │
                    └──────────────────────────────┘     └────────────┘
```

## Features

1. **User & session management** — admin-managed users, PBKDF2 password hashing, DB-backed
   session tokens with expiry, mandatory TOTP 2FA with offline QR provisioning, admin MFA reset.
2. **Case management** — cases with severity/status/notes; each case owns its own pair of ES
   indices so evidence never cross-contaminates.
3. **Log ingestion (ELK backend)** — upload a file directly in the browser, or via the CLI/exe;
   parsers for Apache/Nginx combined (+vhost) and IIS W3C formats, normalised to ECS field names.
4. **Detection engine** — three layers (see [docs/ANALYSIS_AND_CORRELATION.md](docs/ANALYSIS_AND_CORRELATION.md)):
   **25 signature categories** (SQLi, NoSQL, OS-command & template injection, Shellshock, XSS,
   LFI/traversal, RFI, SSRF, XXE, deserialization, webshells, Log4Shell, Spring4Shell, Struts
   OGNL, CRLF, open redirect, access-bypass, sensitive-file access, CVE/component probes,
   scanner UAs and more), behavioural aggregations (brute force, 404 enumeration, exfil byte
   outliers, dangerous HTTP methods, rare user-agents) and z-score traffic-spike detection — all
   rule-based, no AI/ML. One dialect-safe rule list drives both the ES engine and the Python
   tagger, enforced by `tests/test_rules.py`.
5. **Visual timeline correlation** — groups events into attacker sessions (IP + user-agent,
   30-min gap), tags each event with matched signatures, classifies sessions into attack phases,
   and renders a **swimlane chart** (one lane per attacker IP, bars coloured by phase) plus
   attack-chain and session tables. Also exportable as JSON.
6. **Statistics module** — per-case top-N (user-selectable 10/20/50/100/200) rankings of source
   IPs, user-agents, URLs, domains, referrers, methods and status codes, plus IPs-by-bytes,
   cardinalities and a traffic-over-time chart. Charts are **offline inline SVG / CSS bars** (no
   CDN, works air-gapped and in the exe). Export to **Excel (.xlsx) with native charts**, or JSON.
7. **Parameter (field) analysis** — declare the server type (Apache / Nginx / IIS, plus
   AWS ALB / HAProxy / Squid load balancers & proxies) and Aura DFIR produces a **comparative
   table of expected vs. present parameters** (core / recommended / optional) from pasted text,
   an uploaded file, or a case's indexed events, and flags **discrepancies**: missing timezone,
   inconsistent/unparseable timestamps, private/loopback client IPs (you're logging the
   proxy, not the client), IIS query-string logging disabled, empty core fields, wrong-format
   (low parse-rate) and more. See [docs/PARAMETER_ANALYSIS.md](docs/PARAMETER_ANALYSIS.md).
8. **AbuseIPDB bulk reputation** — check every unique source IP in a case against AbuseIPDB;
   multiple API keys pooled with per-key daily-quota accounting, automatic rotation on 429,
   and a 24 h local cache so you never waste quota re-checking the same IP.
9. **Admin dashboard** — manage users (create / disable / reset MFA) and AbuseIPDB keys
   (add / disable / delete, live usage-vs-quota bars, 30-day usage history).
10. **Single-file executable** — an obfuscated, self-contained `AuraDFIR.exe`: double-click and
    run, no Python or pip install needed. It even manages Elasticsearch for you (see below).

---

## Setup

There are two ways to run Aura DFIR. **If you're not a developer and just want to try it,
use Option A.** Option B is for people comfortable with a terminal who want to run/modify the
Python source directly.

Either way, you need one supporting piece of software: **Elasticsearch**, which is where log
data is stored and searched. You do **not** need Docker, and you do **not** need to install Java
separately (Elasticsearch bundles its own).

### Option A — Just want to try it? (no coding required)

This is the executable (`AuraDFIR.exe`), built from this same source code. It's a normal Windows
program — the same idea as downloading and running any `.exe` you get.

1. **Get the file.** Download `AuraDFIR.exe` from the project's **Releases** page on GitHub (a
   maintainer builds and publishes it there — you don't need to build anything yourself). Put it
   in its own folder, e.g. `C:\AuraDFIR\`.

2. **Create your admin account.** Open that folder, hold Shift, right-click an empty spot, and
   choose **"Open PowerShell window here"** (on newer Windows: "Open in Terminal"). A black/blue
   window opens — this is where you type commands. Type this and press Enter:
   ```
   .\AuraDFIR.exe --create-admin admin
   ```
   It will ask you to type a password twice (nothing will appear as you type — that's normal for
   passwords). It then shows a QR code image file. Open it, and scan it with an authenticator app
   on your phone (Google Authenticator, Microsoft Authenticator, Authy — any of these work). This
   sets up the mandatory two-factor login.

3. **Start the program.** In the same window, type:
   ```
   .\AuraDFIR.exe
   ```
   **The first time you do this**, it will ask a one-time question about Elasticsearch:
   ```
   Pick one:
     * Already installed?  enter the folder that contains bin\elasticsearch.bat
     * Running elsewhere?  enter its URL  (e.g. http://localhost:9200)
     * Neither?            just press Enter to download & set it up
   ```
   If you don't already have Elasticsearch, **just press Enter**. It will download and configure
   it automatically (a one-time download, a few hundred MB — this needs an internet connection
   and may take a few minutes). You will **not** be asked this again on later launches — it's
   remembered and started automatically every time from now on.

4. **Use it.** Your web browser opens automatically to the app. Log in with the username/password
   from step 2, then enter the 6-digit code from your authenticator app. You'll land on the
   Dashboard.

5. **Try it out with the included sample.** Click **Cases → New**, give it any name, and create
   it. Open the case, and in the **"Ingest logs"** box, upload the sample log file that ships in
   this repository at `samples\sample_access.log` (it contains a realistic, safe, simulated
   attack for demonstration). Click **Upload & index**, then click **▶ Run analysis engine**.
   Explore the **Findings**, **📊 Statistics**, **🔧 Parameters**, and **🕓 Timeline** pages.

6. **To stop it**, just close that PowerShell window (this also stops Elasticsearch). To start
   again later, re-open the folder and run `.\AuraDFIR.exe` — no setup questions this time.

That's the entire experience for a non-technical user. Everything below is for people who want
to run or modify the Python source code directly.

### Option B — Run from source (for developers)

You'll need **Python 3.11 or newer** installed first (get it from python.org if you don't have
it; on the installer, tick "Add Python to PATH").

```powershell
# 1. Get the code
git clone https://github.com/<you>/AuraDFIR.git
cd AuraDFIR

# 2. Create an isolated Python environment for this project ("virtual environment")
#    — this keeps Aura DFIR's dependencies separate from anything else on your machine.
python -m venv .venv
.\.venv\Scripts\Activate.ps1
#    (Linux/macOS instead:  source .venv/bin/activate)
#    Your terminal prompt should now start with "(.venv)" — that confirms it worked.

# 3. Install the Python packages Aura DFIR needs
pip install -r requirements.txt

# 4. Copy the example settings file and open .env in a text editor to set SECRET_KEY
#    to any long random string (this protects login sessions — don't skip it).
copy .env.example .env
```

Now start Elasticsearch. Leave this window open — it needs to keep running in the background
while you use the app:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_elasticsearch.ps1
```
The first run downloads Elasticsearch (~600 MB, one time only) and starts it. Wait until you see
it say it has started before continuing. (Alternative: if you already run Elasticsearch
somewhere, skip this and just set `ES_URL` in `.env` to point at it — see
[docs/RUN_WITHOUT_DOCKER.md](docs/RUN_WITHOUT_DOCKER.md).)

Open a **second** terminal window (same folder, same virtual environment — repeat step 2's
`Activate.ps1` line in this new window too), and run:

```powershell
python scripts\create_admin.py --username admin
python -m uvicorn app.main:app --reload
```

The first command creates your login and shows a QR code to scan with an authenticator app; the
second starts the web server. Open **http://127.0.0.1:8000** in your browser, log in, and enter
the 2FA code.

### Typical workflow (both options)

1. **Cases → New** — create a case, note its ID (shown in the URL, e.g. `/cases/1` → ID is `1`).
2. **Upload a log file** in the case's "Ingest logs" box (or via CLI: see below).
3. Click **▶ Run analysis engine** to generate findings.
4. Click **📊 Statistics** and **🕓 Timeline** to explore the results visually.
5. On **Admin → API Keys**, add an AbuseIPDB API key (free at abuseipdb.com) and bulk-check the
   case's attacker IPs for reputation scores.
6. Use **🔧 Parameters** to check whether your log format is missing important fields.

Command-line equivalents for steps 2–3 (useful for scripting or very large files):
```bash
python scripts/ingest_logs.py --case 1 --file /evidence/access.log
python scripts/run_analysis.py --case 1
python scripts/build_timeline.py --case 1 --ip 203.0.113.7 --out timeline.json
```

---

## Project layout

```
app/
  main.py            FastAPI app, dashboard
  config.py          settings from .env
  database.py        SQLAlchemy engine/session
  models.py          User, Case, AbuseIPDBKey, KeyUsage, IPReputation, ...
  es.py              Elasticsearch client factory
  auth/              login, TOTP 2FA, session dependencies
  cases/             case CRUD, notes, findings view, analyze/timeline/ingest endpoints
  ingest/            log parsers + bulk indexer
  analysis/          rules.py (25 signature categories) + engine.py (ES detections)
                     + statistics.py (top-N rankings + charts) + export.py (Excel)
                     + parameters.py (field-presence analysis)
  correlation/       timeline.py (sessionization + phase classification + SVG chart)
  intel/             abuseipdb.py (key pool, cache, bulk checker) + API routes
  admin/             key & user management dashboard
  tools/             parameter-analysis routes
  es_manager.py      runtime Elasticsearch provisioning (used by the exe)
  templates/ static/ server-rendered UI
launcher.py          exe entry point (--create-admin / --ingest / --reset-es / --help)
scripts/             create_admin, ingest_logs, run_analysis, build_timeline,
                     setup_elasticsearch.ps1 (run ES locally, no Docker)
samples/             sample_access.log (a ready-to-ingest attack trace)
build/               build.py (obfuscate + package) → dist/AuraDFIR.exe
auradfir.spec        PyInstaller onefile spec
tests/               test_rules, test_statistics, test_parameters, test_es_manager, test_export_viz
docs/                ANALYSIS_AND_CORRELATION, BUILD_EXE, PARAMETER_ANALYSIS,
                     RUN_WITHOUT_DOCKER
```

## Packaging as a standalone executable

This is only needed if you're a maintainer building a release — regular users should just
download the exe from Releases (Option A above).

```bash
pip install -r requirements.txt -r requirements-build.txt
python build/build.py          # → dist/AuraDFIR.exe (obfuscated, single file)
```

The app code is obfuscated with PyArmor, then PyInstaller bundles CPython and every dependency
into one file. Full details, caveats (antivirus false positives, code-signing) in
[docs/BUILD_EXE.md](docs/BUILD_EXE.md).

## Security notes / hardening TODO before production

- Set a strong `SECRET_KEY` in `.env`; serve behind TLS (reverse proxy).
- CSRF tokens on state-changing forms (not yet implemented).
- Rate-limit `/auth/login`.
- ES security is disabled for local dev (see `scripts/setup_elasticsearch.ps1`); enable auth
  and set `ES_USER`/`ES_PASSWORD` in `.env` for anything real.

## Roadmap (not yet built)

- Error-log and WAF/CDN log parsers; multi-source correlation
- GreyNoise / OTX / CISA KEV enrichment alongside AbuseIPDB
- **Optional AI/LLM-assisted finding summarisation** (local via LM Studio, or a hosted API) —
  a proposed future add-on for turning findings into plain-English report text. Not implemented
  today; the core detection engine above is, and will remain, fully rule-based.
- Report generator (DOCX/PDF) from case + timeline

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. Please run the test suite in `tests/` before submitting parser or rule changes,
and describe new detection rules in the PR body.
