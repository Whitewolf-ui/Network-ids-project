#!/bin/bash

# Load environment variables from .env
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Use venv Python explicitly
cd /home/whitewolf/Downloads/network-ids-webapp
sudo /home/whitewolf/Downloads/network-ids-webapp/venv/bin/python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000