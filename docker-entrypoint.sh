#!/bin/sh
set -e

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
