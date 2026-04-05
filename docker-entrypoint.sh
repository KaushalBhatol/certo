#!/bin/sh
set -e

# Auto-generate SECRET_KEY if not provided, persisted in the data volume
if [ -z "$SECRET_KEY" ]; then
  SECRET_FILE="/app/data/.secret_key"
  if [ -f "$SECRET_FILE" ]; then
    SECRET_KEY=$(cat "$SECRET_FILE")
  else
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    mkdir -p /app/data
    echo "$SECRET_KEY" > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
  fi
  export SECRET_KEY
fi

# Run startup checks: generate self-signed cert, init DB, seed default admin
python -c "from utils.precheck import precheckes; precheckes()"

# Start gunicorn with SSL
exec gunicorn app:app \
  --bind 0.0.0.0:8080 \
  --workers ${GUNICORN_WORKERS:-2} \
  --timeout 120 \
  --certfile data/ssl/certo.crt \
  --keyfile data/ssl/certo.key \
  --access-logfile - \
  --error-logfile -
