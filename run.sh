#!/usr/bin/env bash
# Launches the WhiteWolf IDS dashboard.
# Packet capture requires root, so this is normally run with sudo.
set -e
cd "$(dirname "$0")"
source venv/bin/activate
exec sudo -E venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
