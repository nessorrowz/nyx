#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
command -v nmap >/dev/null || { echo "nmap not found on PATH — install it first."; exit 1; }
python3 -c "import fastapi" 2>/dev/null || pip install -r requirements.txt
exec uvicorn app.main:app --host 127.0.0.1 --port 8777 --reload
