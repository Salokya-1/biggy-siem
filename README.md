# BIGGY — Security Information & Event Management (SIEM / XDR)

> A self-contained, open-source security operations console. Biggy ingests
> events, detects threats with a live IDS rule engine, responds automatically
> (IPS), scans files with its **own** malware engine, enriches with VirusTotal,
> discovers and monitors network assets, runs nmap port scans, and collects
> endpoint telemetry from host agents — all behind an authenticated console.

Biggy is inspired by Wazuh, Splunk, Security Onion and Elastic SIEM, and by
VirusTotal / Google's enterprise tooling — rebuilt as one small, hackable app
you can run on a single machine with no external services required.

<p align="center"><em>Login → live SOC console → drill into any subsystem.</em></p>

---

## Feature map

| Area | What Biggy does |
|------|-----------------|
| **SIEM core** | Normalised event pipeline, real-time WebSocket feed, full-text search, severity/category analytics, 24h timeline |
| **IDS** | Data-driven rule engine (`contains` / `equals` / `regex` / `threshold`) with MITRE ATT&CK tags. Threshold rules catch brute-force & port-scan bursts |
| **IPS (active response)** | Rules can auto-`block` a source IP or `quarantine` a file/host; manual containment from the console |
| **Malware scanner (built in-house)** | The **Biggy Engine** — MD5/SHA1/SHA256 hashing, a signature DB (incl. EICAR), YARA-style content rules, double-extension & entropy heuristics → weighted risk score & verdict |
| **Automated scanning** | Background watcher scans your **Downloads** folder every 5 min; on-demand folder & recursive scans; drag-&-drop file scan |
| **Threat intelligence** | VirusTotal API v3 for file hashes, IPs, domains & URLs (cached), with graceful offline mode |
| **Network infrastructure** | Subnet **device discovery** (ARP + ping sweep), up/down **monitoring**, and **port scanning** via real `nmap` (auto-fallback to a built-in TCP scanner), risky-service flagging |
| **Host agents** | A lightweight agent (`psutil`) enrols and streams CPU/mem/disk, processes, connections + heuristic endpoint detections (suspicious process, Office-spawns-shell, new listening ports) |
| **Auth** | Login page, PBKDF2-hashed passwords, signed session cookies; every sign-in logged to the pipeline |

Everything runs from **stdlib + 5 pip packages**. No Elasticsearch, no Docker required.

---

## Quick start

Biggy is fully cross-platform (Windows, Linux, macOS). Use the launcher for your OS —
it creates the virtualenv, installs deps and starts the server:

```bash
# Windows
run.bat

# Linux / macOS (e.g. Kali)
chmod +x run.sh && ./run.sh
```

…or do it by hand:

```bash
python -m venv .venv
.venv\Scripts\activate           # Windows
source .venv/bin/activate         # Linux / macOS
pip install -r requirements.txt
python run.py
```

Open **http://localhost:8642** and sign in with the first-run credentials:

```
user: admin      password: argus
```

### Running on Linux / Kali (view from another machine)
On Linux, Biggy ingests the OS log via **journald / `/var/log/auth.log`** (the Linux
counterpart to the Windows Event Log — SSH brute-force, sudo, account changes, etc.),
and uses real **`nmap`** (preinstalled on Kali) for port scans.

To reach the console from your host/VM host, bind to all interfaces (the `run.sh`
launcher already does this):

```bash
ARGUS_HOST=0.0.0.0 python run.py
```

Then browse to `http://<linux-ip>:8642` from the other machine. Recommended extras:
```bash
sudo apt update && sudo apt install -y python3-venv git nmap net-tools
```
(Reading system logs and raw pings generally needs root — run with `sudo` if the
Endpoint Log stays empty.)

> Configure everything (secret, admin creds, VirusTotal key, watch folder, port)
> by copying `.env.example` to `.env`. Biggy seeds an admin account, a default
> ruleset, signatures and a little demo telemetry on first launch so the console
> is alive immediately.

### Enable VirusTotal (optional)
Put a free API key in `.env`:
```
VIRUSTOTAL_API_KEY=your_key_here
```
Without it, hash/IP/URL lookups run in offline mode and file scanning uses the
local engine only.

### Real nmap (optional)
If `nmap` is on your PATH, port scans use it (`-T4 -F -Pn --open` by default).
Otherwise Biggy falls back to its own threaded TCP-connect scanner automatically.

---

## Deploy a host agent

On any machine you want to monitor:

```bash
pip install psutil
python agent/argus_agent.py --server http://<argus-host>:8642 --key argus-agent-key
```

It enrols, then heartbeats telemetry + endpoint detections every 30s. Watch it
appear under **Host Agents**. (Change the shared key with `ARGUS_AGENT_KEY`.)

---

## Try it in 60 seconds

1. **Threat Intel →** paste the EICAR hash (linked in the UI) → `malicious`.
2. **Malware Scanner →** drop any file; create an `eicar.com` test file to see a
   full-score detection with reasons.
3. **Network Map →** *Discover* your subnet, then *Port scan* a host.
4. **Event Stream →** *Inject test event* a few times quickly to trip the
   **SSH/RDP Brute Force** threshold rule → an alert fires and the source IP is
   auto-blocked (see **Active Response**).
5. **Detection Rules →** deploy your own rule and watch it match live.

---

## Architecture

```
                        ┌────────────────────────── Web console (SPA) ──────────────────────────┐
                        │  Login · Overview · Events · Alerts · Rules · Scanner · Intel · Net ·  │
                        │  Agents · Response         (vanilla JS + WebSocket live feed)          │
                        └───────────────▲───────────────────────────────────────────────────────┘
                                        │ REST + WS
        ┌───────────────────────────────┴───────────────────────────────┐
        │                         FastAPI  (argus/app.py)                │
        └───┬───────────┬───────────┬───────────┬───────────┬───────────┘
            │           │           │           │           │
      ┌─────▼─────┐ ┌───▼────┐ ┌────▼─────┐ ┌───▼─────┐ ┌───▼──────┐
      │ pipeline  │ │  IDS   │ │ scanners │ │ network │ │  agents  │
      │ (ingest)  │ │ + IPS  │ │ (engine) │ │ nmap/   │ │ registry │
      │           │ │        │ │  watcher │ │ discover│ │          │
      └─────┬─────┘ └───┬────┘ └────┬─────┘ └───┬─────┘ └───┬──────┘
            └───────────┴───────────┴─── SQLite (WAL) ──────┴──────┘
                       events · alerts · rules · scans · devices · agents · blocklist
```

- **`argus/core/`** — event pipeline, detection engine, active response, live bus.
- **`argus/scanners/`** — the self-built file scanner + background folder watcher.
- **`argus/network/`** — nmap wrapper (+ pure-Python fallback) and discovery/monitor.
- **`argus/integrations/`** — VirusTotal v3 connector (cached).
- **`agent/argus_agent.py`** — the standalone host agent.

## REST API (selected)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/login`, `/api/logout` | auth |
| `GET`  | `/api/overview` | dashboard metrics |
| `GET/POST` | `/api/events` | list / ingest events |
| `GET`  | `/api/alerts` · `POST /api/alerts/{id}/status` | triage |
| `GET/POST/PATCH/DELETE` | `/api/rules` | manage detections |
| `POST` | `/api/scan/file` · `/api/scan/folder` | malware scanning |
| `GET`  | `/api/intel/{hash,ip,domain}/…` · `POST /api/intel/url` | VirusTotal |
| `GET`  | `/api/devices` · `POST /api/network/{discover,monitor,scan}` | network |
| `POST` | `/api/agent/enroll` · `/api/agent/heartbeat` | agents (x-agent-key) |
| `GET/POST/DELETE` | `/api/blocklist` | IPS |
| `WS`   | `/ws` | live event/alert stream |

Interactive API docs at **`/api/docs`**.

---

## Security notes
Biggy is a learning / lab project. Before exposing it beyond localhost: change
`ARGUS_SECRET` and `ARGUS_AGENT_KEY`, set a strong admin password, serve behind
TLS, and only scan networks and files you are authorised to. Port scanning and
network discovery should only be run against systems you own or have permission
to test.

## License
MIT — do anything, no warranty.
