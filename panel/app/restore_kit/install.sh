#!/bin/bash
# AWG Panel — восстановление сервера из полного бэкапа (Debian/Ubuntu, под root).
#   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in awg-full-….tar.gz.enc | tar xz
#   cd awg-full && ./install.sh            # спрашивает по каждому шагу
#   ./install.sh --yes [--ip <публичный IP>] [--no-docker] [--no-awg] [--no-panel] [--no-firewall]
# Шаги: Docker → AmneziaWG (свежий образ amneziawg-go, конфиг и клиенты из бэкапа) → панель (код, .env, база,
# статистика) → firewall (ufw). Существующее на сервере перед заменой сохраняется рядом с суффиксом .before-restore-<время>.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
YES=0; NEW_IP=""; DO_DOCKER=1; DO_AWG=1; DO_PANEL=1; DO_FW=1
AWG_NAME_OVERRIDE=""; AWG_PORT_OVERRIDE=""; PANEL_DIR="/opt/awg-panel"
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --ip) NEW_IP="$2"; shift ;;
    --no-docker) DO_DOCKER=0 ;;
    --no-awg) DO_AWG=0 ;;
    --no-panel) DO_PANEL=0 ;;
    --no-firewall) DO_FW=0 ;;
    --awg-name) AWG_NAME_OVERRIDE="$2"; shift ;;     # для проверки рядом с работающим сервером
    --awg-port) AWG_PORT_OVERRIDE="$2"; shift ;;
    --panel-dir) PANEL_DIR="$2"; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   ✓ %s\n' "$*"; }
warn() { printf '   ! %s\n' "$*" >&2; }
ask()  {  # ask "вопрос" → 0 = да (по умолчанию да)
  [ "$YES" = 1 ] && return 0
  local a; read -r -p "   $1 [Y/n] " a </dev/tty || true
  case "${a:-y}" in [Yy]*|[Дд]*) return 0 ;; *) return 1 ;; esac
}
meta() { python3 -c "import json,sys; d=json.load(open('$HERE/meta.json')); print($1)" 2>/dev/null || true; }
stamp=$(date +%Y%m%d-%H%M%S)

[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
command -v apt-get >/dev/null || { echo "Debian/Ubuntu (apt) is required." >&2; exit 1; }

say "Checking the backup"
( cd "$HERE" && sha256sum -c --quiet SHA256SUMS ) && ok "checksums match" || { echo "Checksums do not match — the archive is damaged." >&2; exit 1; }
command -v python3 >/dev/null || apt-get install -y -q python3 >/dev/null
OLD_IP=$(meta "d.get('panel_host','')"); PANEL_PORT=$(meta "d.get('panel_port','14443')")
AWG_NAME=${AWG_NAME_OVERRIDE:-$(meta "(d.get('awg') or {}).get('container','amnezia-awg2')")}
AWG_PORT=${AWG_PORT_OVERRIDE:-$(meta "(d.get('awg') or {}).get('port','')")}
AWG_NET=$(meta "(d.get('awg') or {}).get('network','amnezia-dns-net')")
AWG_SUBNET=$(meta "(d.get('awg') or {}).get('subnet','') or '172.29.172.0/24'")
ok "backup from $(meta "d.get('created_text','?')"), panel $(meta "d.get('panel_version','?')"), server $OLD_IP, VPN port ${AWG_PORT:-?}/udp"

# ---- публичный адрес ----
if [ -z "$NEW_IP" ]; then
  DETECTED=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
  if [ -n "$OLD_IP" ] && [ "$DETECTED" = "$OLD_IP" ]; then NEW_IP="$OLD_IP"
  elif [ "$YES" = 1 ]; then NEW_IP="${DETECTED:-$OLD_IP}"
  else
    read -r -p "   Public IP of this server [${DETECTED:-$OLD_IP}]: " NEW_IP </dev/tty || true
    NEW_IP=${NEW_IP:-${DETECTED:-$OLD_IP}}
  fi
fi
[ "$NEW_IP" != "$OLD_IP" ] && warn "new address $NEW_IP (was $OLD_IP): clients need new configs — send them from the client cards"

# ---- Docker ----
if [ "$DO_DOCKER" = 1 ] && ! command -v docker >/dev/null; then
  say "Docker"
  if ask "Docker is not installed. Install docker.io and docker compose from the system repository?"; then
    apt-get update -q >/dev/null
    apt-get install -y -q docker.io >/dev/null
    apt-get install -y -q docker-compose-v2 >/dev/null 2>&1 || apt-get install -y -q docker-compose-plugin >/dev/null 2>&1 \
      || apt-get install -y -q docker-compose >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    ok "$(docker --version)"
  fi
fi
command -v docker >/dev/null || { echo "Docker is required." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || warn "docker compose is missing — the panel step will fail; install the compose plugin"

# ---- AmneziaWG ----
if [ "$DO_AWG" = 1 ] && [ -f "$HERE/amnezia/awg/awg0.conf" ]; then
  say "AmneziaWG (container $AWG_NAME, port $AWG_PORT/udp)"
  if ask "Restore AmneziaWG: build the latest amneziawg-go image and put back the server keys and all clients?"; then
    if docker ps -a --format '{{.Names}}' | grep -qx "$AWG_NAME"; then
      if ask "Container $AWG_NAME already exists. Replace it (its /opt/amnezia/awg is saved first)?"; then
        docker cp "$AWG_NAME:/opt/amnezia/awg" "/root/$AWG_NAME-awg.before-restore-$stamp" 2>/dev/null || true
        docker rm -f "$AWG_NAME" >/dev/null
      else
        DO_AWG=0
      fi
    fi
  else
    DO_AWG=0
  fi
  if [ "$DO_AWG" = 1 ]; then
    BUILD="/opt/amnezia/$AWG_NAME"; mkdir -p "$BUILD"
    if [ -f "$HERE/amnezia/Dockerfile" ]; then cp "$HERE/amnezia/Dockerfile" "$BUILD/Dockerfile"
    else printf 'FROM amneziavpn/amneziawg-go:latest\nRUN apk add --no-cache bash curl dumb-init iptables iproute2\nRUN mkdir -p /opt/amnezia && printf "#!/bin/bash\\ntail -f /dev/null\\n" > /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh\nENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]\n' > "$BUILD/Dockerfile"; fi
    docker build -q --pull --network host -t "$AWG_NAME" "$BUILD" >/dev/null
    ok "image $AWG_NAME built from the latest amneziavpn/amneziawg-go"
    docker network inspect "$AWG_NET" >/dev/null 2>&1 || docker network create --driver bridge --subnet "$AWG_SUBNET" "$AWG_NET" >/dev/null
    docker run -d --name "$AWG_NAME" --restart always --privileged --cap-add NET_ADMIN --cap-add SYS_MODULE \
      --log-driver none -p "$AWG_PORT:$AWG_PORT/udp" -v /lib/modules:/lib/modules \
      --sysctl net.ipv4.conf.all.src_valid_mark=1 --network "$AWG_NET" "$AWG_NAME" >/dev/null
    docker exec "$AWG_NAME" mkdir -p /opt/amnezia/awg
    docker cp "$HERE/amnezia/awg/." "$AWG_NAME:/opt/amnezia/awg/"
    if [ -n "$AWG_PORT_OVERRIDE" ]; then   # проверочный запуск на другом порту
      docker exec "$AWG_NAME" sed -i "s/^ListenPort = .*/ListenPort = $AWG_PORT/" /opt/amnezia/awg/awg0.conf
    fi
    [ -f "$HERE/amnezia/start.sh" ] && docker cp "$HERE/amnezia/start.sh" "$AWG_NAME:/opt/amnezia/start.sh"
    docker exec "$AWG_NAME" sh -c 'chmod 600 /opt/amnezia/awg/* && chmod a+x /opt/amnezia/start.sh'
    docker restart "$AWG_NAME" >/dev/null
    sleep 3
    PEERS=$(docker exec "$AWG_NAME" awg show awg0 peers 2>/dev/null | wc -l || echo 0)
    [ "$PEERS" -gt 0 ] && ok "awg0 is up, clients: $PEERS" || { warn "awg0 did not come up: docker logs $AWG_NAME"; }
  fi
fi

# ---- панель ----
if [ "$DO_PANEL" = 1 ] && [ -d "$HERE/panel" ]; then
  say "Panel ($PANEL_DIR, https://$NEW_IP:$PANEL_PORT)"
  if ask "Restore the panel: code, settings (.env), database with statistics, administrators and client keys?"; then
    if [ -d "$PANEL_DIR" ]; then
      (cd "$PANEL_DIR" && docker compose down >/dev/null 2>&1) || true
      mv "$PANEL_DIR" "$PANEL_DIR.before-restore-$stamp"
      ok "old panel moved to $PANEL_DIR.before-restore-$stamp"
    fi
    mkdir -p "$PANEL_DIR/data"; chmod 700 "$PANEL_DIR/data"
    cp -a "$HERE/panel/." "$PANEL_DIR/"
    install -m 600 "$HERE/panel-data/panel.env" "$PANEL_DIR/.env"
    [ -f "$HERE/panel-data/data.key" ] && install -m 600 "$HERE/panel-data/data.key" "$PANEL_DIR/data/data.key"
    install -m 600 "$HERE/panel-data/panel.db" "$PANEL_DIR/data/panel.db"
    if [ -n "$NEW_IP" ] && [ "$NEW_IP" != "$OLD_IP" ]; then
      sed -i -e "s/^PANEL_HOST=.*/PANEL_HOST=$NEW_IP/" -e "s/^PUBLIC_HOST=.*/PUBLIC_HOST=$NEW_IP/" "$PANEL_DIR/.env"
      ok "PANEL_HOST/PUBLIC_HOST = $NEW_IP"
    fi
    (cd "$PANEL_DIR" && docker build -q --network host -t awg-panel:latest panel >/dev/null && docker compose up -d --no-build >/dev/null)
    sleep 6
    curl -sf http://127.0.0.1:8080/healthz >/dev/null && ok "panel is running" || warn "panel did not answer yet: cd $PANEL_DIR && docker compose logs panel"
  fi
fi

# ---- firewall ----
if [ "$DO_FW" = 1 ] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "Firewall (ufw)"
  if ask "Open ${AWG_PORT:-?}/udp (VPN), $PANEL_PORT/tcp (panel) and 80/tcp (certificate validation)?"; then
    [ -n "$AWG_PORT" ] && ufw allow "$AWG_PORT/udp" comment "AmneziaWG" >/dev/null
    ufw allow "$PANEL_PORT/tcp" comment "awg-panel" >/dev/null
    ufw allow 80/tcp comment "awg-panel certificate validation" >/dev/null
    ok "ports opened"
  fi
elif [ "$DO_FW" = 1 ]; then
  warn "ufw is not active: make sure ${AWG_PORT:-the VPN port}/udp, $PANEL_PORT/tcp and 80/tcp are reachable"
fi

say "Done"
echo "   Panel: https://$NEW_IP:$PANEL_PORT  (sign in with the administrators from the backup)"
[ -n "$AWG_PORT" ] && echo "   VPN:   $NEW_IP:$AWG_PORT/udp"
[ "$NEW_IP" != "$OLD_IP" ] && echo "   The address changed: send new configs to the clients from the client cards (Telegram / e-mail)."
exit 0
