#!/bin/sh
# boris.gb 2026-10-29 23:17 - restore the panel and AmneziaWG from an encrypted portal backup (.awgbak) on this server
# Usage (in /opt/awg-panel, after deploy.sh and with AmneziaWG installed): ./restore.sh <backup.awgbak> [new-public-ip]
# Puts back .env, the panel database, data.key and the AmneziaWG files, applies them and starts the panel.
set -e
cd "$(dirname "$0")"
[ -f "$1" ] || { echo "usage: $0 <backup.awgbak> [new-public-ip]" >&2; exit 2; }
F=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
docker image inspect awg-panel:latest >/dev/null 2>&1 || docker build -q --network host -t awg-panel:latest panel >/dev/null
[ -f .env ] || { touch .env; chmod 600 .env; }
mkdir -p data
docker compose stop panel >/dev/null 2>&1 || true
# в контейнере панели: доступ к amnezia-awg2 (pid host, privileged), к data/ и к .env на запись
docker run --rm -it --network host --pid host --privileged -e PANEL_DATA=/data \
  -v "$PWD/data:/data" -v "$PWD/.env:/srv/host.env" -v "$F:/srv/backup.awgbak:ro" \
  awg-panel:latest python -m app.backup restore /srv/backup.awgbak --env /srv/host.env ${2:+--host "$2"}
docker compose up -d --no-build
H=$(grep '^PANEL_HOST=' .env | cut -d= -f2); P=$(grep '^PANEL_PORT=' .env | cut -d= -f2)
echo "Done. Panel: https://$H:${P:-14443}"
