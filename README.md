# Whitewolf Security — Network IDS

A live web dashboard for the [Network IDS project](https://github.com/Whitewolf-ui/Network-ids-project),
built on FastAPI + Jinja2 + SQLite. It wraps the original `simple_ids.py`
Scapy detection logic (port-scan detection + sensitive-port monitoring) in a
controllable, authenticated background thread, persists alerts to SQLite, and
serves a public landing page plus a private live dashboard.

## What's included

- **Public landing page** (`/`) — marketing page with company details, features, and a disclaimer
- **Account setup** (`/setup`) — one-time admin account creation, shown automatically until an account exists
- **Login / logout** — session-cookie auth (PBKDF2-HMAC-SHA256 hashed passwords, HTTP-only cookies, 7-day sessions)
- **Live dashboard** (`/dashboard`, protected) — start/stop monitoring, live alert feed, stat cards, alerts-per-minute trend chart, watchlist per sensitive port, top source IPs
- **Account settings** (`/settings`, protected) — profile (email + monitoring interface), password change, logout
- All alerts persisted to `ids_data.db` (SQLite)

## Requirements

- Linux (packet capture via Scapy needs raw sockets → root)
- Python 3.8+

## Setup and run

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x run.sh
./run.sh
```

Then open **http://localhost:8000**. Since no account exists yet, you'll land
on the account-creation form automatically — set a username, email, and
password, and you're straight into the dashboard.

## Testing it

Once you've hit **Start monitoring** on the dashboard, generate traffic in
another terminal:

```bash
nmap localhost -p 20-30
# or
for port in 22 80 443 21 23; do nc -w 1 localhost $port 2>/dev/null; done
```

The pulse strip should spike, alerts should land in the live feed, and the
stat cards update within a couple of seconds.

## Notes on going from beta to something more solid

- Each user has their own monitoring interface set in **Settings**, defaulting
  to `lo` (loopback) to match the original project's local-testing setup. To
  monitor a real network interface, change it there (e.g. `eth0`) — this needs
  the box to actually see that traffic (span/mirror port, or run on the gateway).
- The detection logic is unchanged from `simple_ids.py`: 5+ unique destination
  ports from one IP within the process lifetime triggers a port-scan alert.
  For a longer-running deployment you'll want a sliding time window instead of
  an unbounded per-IP port set.
- This is a single-admin-account model — there's no multi-user signup, by
  design, since `/setup` locks itself once an account exists.
- `ids_data.db` is created next to `run.sh` on first run and holds both alert
  history and the account/session tables.

## Project structure

```
network-ids-webapp/
├── run.sh
├── requirements.txt
├── ids_data.db                # created on first run
└── app/
    ├── main.py                # FastAPI app + routes (landing, auth, dashboard, settings, API)
    ├── auth.py                # PBKDF2 password hashing + session cookie handling
    ├── ids_engine.py          # Scapy-based detection engine (start/stop-able)
    ├── database.py             # SQLite persistence (alerts, users, sessions)
    ├── templates/
    │   ├── landing.html
    │   ├── setup.html
    │   ├── login.html
    │   ├── dashboard.html
    │   └── settings.html
    └── static/
        ├── css/style.css
        └── js/dashboard.js
```
