#!/bin/bash
set -e

# Try to apply capability at runtime
if command -v setcap &> /dev/null; then
    echo "[INFO] Applying cap_net_raw to Python..."
    setcap cap_net_raw=ep /usr/local/bin/python3.11 2>/dev/null || echo "[WARN] Could not apply capability (running in restricted environment)"
fi

# Start the app
exec "$@"