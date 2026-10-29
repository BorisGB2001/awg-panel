# AWG Panel

[Русская версия](README.ru.md)

A web panel for an AmneziaWG server run by the AmneziaVPN app (Docker container `amnezia-awg2`). It shows who is connected, from where and how much traffic they use, which sites clients visit, and lets you block domains and IPs, add and remove clients and issue their configs. It also has alerts, a monthly archive, a self-service portal for clients and Telegram/e-mail notifications.

| | |
|---|---|
| Address | `https://<server-ip>:14443` (port is `PANEL_PORT` in `.env`; Let's Encrypt certificate for the IP, renewed by Caddy, port 80 must be open) |
| Install dir | `/opt/awg-panel` on the AmneziaWG server |
| Containers | `awg-panel` (Python, FastAPI), `awg-panel-caddy` (HTTPS) |
| Data | `/opt/awg-panel/data`: `panel.db` (SQLite), `backups/` (AmneziaWG configs and DB), `geo/` (DB-IP), `data.key` |
| Login | user `admin`, password + TOTP code |

## Screenshots

Demo data: the clients, addresses and traffic are fictional. Click a picture to open it full size. The pictures are made by `tools/screenshots.py`.

<table>
<tr><td width="50%"><a href="docs/screenshots/en/overview.png"><img src="docs/screenshots/en/overview.png" alt="Overview — clients, traffic, top 10"></a><br><b>Overview — clients, traffic, top 10</b></td><td width="50%"><a href="docs/screenshots/en/client.png"><img src="docs/screenshots/en/client.png" alt="Client card — group, quota, portal, activity"></a><br><b>Client card — group, quota, portal, activity</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/en/sites.png"><img src="docs/screenshots/en/sites.png" alt="Sites — what clients visit"></a><br><b>Sites — what clients visit</b></td><td width="50%"><a href="docs/screenshots/en/events.png"><img src="docs/screenshots/en/events.png" alt="Events — connections, IP changes, admin actions"></a><br><b>Events — connections, IP changes, admin actions</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/en/archive.png"><img src="docs/screenshots/en/archive.png" alt="Monthly archive"></a><br><b>Monthly archive</b></td><td width="50%"><a href="docs/screenshots/en/alerts.png"><img src="docs/screenshots/en/alerts.png" alt="Alerts"></a><br><b>Alerts</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/en/blocking.png"><img src="docs/screenshots/en/blocking.png" alt="Blocking — domains, IPs, presets"></a><br><b>Blocking — domains, IPs, presets</b></td><td width="50%"><a href="docs/screenshots/en/groups.png"><img src="docs/screenshots/en/groups.png" alt="Groups — traffic and quotas"></a><br><b>Groups — traffic and quotas</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/en/server.png"><img src="docs/screenshots/en/server.png" alt="Server — AmneziaWG and collectors"></a><br><b>Server — AmneziaWG and collectors</b></td><td width="50%"><a href="docs/screenshots/en/admins.png"><img src="docs/screenshots/en/admins.png" alt="Administrators — roles and groups"></a><br><b>Administrators — roles and groups</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/en/portal.png"><img src="docs/screenshots/en/portal.png" alt="Client portal (personal link)"></a><br><b>Client portal (personal link)</b></td><td width="50%"><a href="docs/screenshots/en/overview-dark.png"><img src="docs/screenshots/en/overview-dark.png" alt="Dark theme"></a><br><b>Dark theme</b></td></tr>
</table>

## Features

- **Dashboard**: online clients, traffic today and this month, top-10 downloaders (today / month), traffic chart, activity heatmap.
- **Sessions**: when each client connected and disconnected, from which IP and country, traffic per session; alerts on a new country, a shared config (many endpoint changes) and traffic spikes.
- **Sites**: domains and IPs each client visits (DNS + TLS SNI) with bytes per site.
- **Blocking**: domains, subdomains, IPs and subnets, per client or for everyone, with presets (YouTube, TikTok, …). DoH/DoT/QUIC bypasses are closed for affected clients.
- **Clients**: add, rename, disable/enable and delete on the live interface without restarting AmneziaWG. A new client gets the highest used IP + 1, as in the AmneziaVPN app. Configs as `.conf`, QR code and `vpn://` key for the AmneziaVPN app.
- **Client portal**: a personal link where a client sees their own traffic, sessions and sites, downloads their config and subscribes to notifications.
- **Notifications**: Telegram bot and e-mail, including a daily PNG report (today's chart and top-10 sites).
- **Monthly archive**: statistics reset on the 1st at 00:00, the previous month is kept in the archive.
- **Administrators**: super administrators and group administrators, each with a password and TOTP; a new administrator gets a temporary password and sets up the authenticator on first sign-in.
- **Groups**: clients are organised in groups; a group administrator sees and manages only the clients of its groups. Per-group traffic today and this month.
- **Quotas**: traffic limits per group or client per day or month, alerts at 80 % and 100 %, optionally disabling clients until the period ends.
- **Themes**: light, dark or as in the system.
- **Languages**: English by default, Russian included, any language can be added as a JSON file.

## How it works

- The panel **does not touch** the `amnezia-awg2` container (no recreate, restart or changes to `start.sh`). It finds the `amneziawg-go awg0` process in `/proc`, runs commands via `nsenter` in its namespaces and reads/writes `awg0.conf` and `clientsTable` via `/proc/<PID>/root`. No docker.sock is needed; that is why the panel container is `privileged`, `pid: host`, `network_mode: host`.
- Clients are added and removed on the live interface (`awg set`), so other sessions are not interrupted. Before every change both files are backed up to `data/backups/`, and on error the change is rolled back. The AmneziaVPN app keeps seeing all clients.
- Collection: `awg show dump` every 30 s (traffic, sessions, endpoints), DNS answers and SNI from `tcpdump` on `awg0`, closed connections from `conntrack`. Geo data comes from DB-IP Lite databases, updated monthly.
- Blocking uses iptables rules in the container namespace (chain `AWGPANEL_BLOCK`); they keep working without the panel and are restored after a container restart.
- Retention: per-minute traffic — 7 days; sites and connections — 30 days, then daily totals (`hosts_day`, one year); hourly traffic, sessions and the monthly archive — forever; events — one year. Nightly DB backup, last 14 kept.

## Requirements

- A Linux server with AmneziaWG installed by the AmneziaVPN app (container `amnezia-awg2`, interface `awg0`).
- Docker with the Compose plugin.
- Open TCP ports 80 (certificate issuance) and `PANEL_PORT` (14443 by default).

## Installation

```bash
# on your workstation, from the repository root
./deploy.sh root@<server>                     # copies files, builds the image, runs tests, starts the panel
ssh root@<server> 'cd /opt/awg-panel && cp -n .env.example .env && chmod 600 .env'
# edit .env: PANEL_HOST, PUBLIC_HOST, SESSION_SECRET, DATA_KEY (commands to generate them are in the file)
ssh root@<server> 'cd /opt/awg-panel && docker compose up -d --no-build'   # panel + caddy
ssh root@<server> 'ufw allow 14443/tcp && ufw allow 80/tcp'                # 80 is for the certificate
```

Set the admin password and TOTP in your own terminal (the output contains the TOTP secret):

```bash
ssh -t root@<server> /opt/awg-panel/init-admin.sh          # password + TOTP
ssh -t root@<server> /opt/awg-panel/init-admin.sh hash     # change the password only
ssh -t root@<server> /opt/awg-panel/init-admin.sh totp     # re-issue TOTP only
```

To skip the host argument, put it into `.deploy-host` (ignored by git): `echo root@<server> > .deploy-host`.

## Updating

```bash
./deploy.sh root@<server>
```

The script builds the image in the host network, runs the tests inside the image and recreates only the `panel` container (Caddy and AmneziaWG are not touched). DB migrations run automatically on start.

## Health and logs

```bash
ssh root@<server> 'curl -s http://127.0.0.1:8080/healthz'          # collector status
ssh root@<server> 'docker logs --tail 100 awg-panel'
ssh root@<server> 'docker logs --tail 50 awg-panel-caddy'
```

The same is shown in the panel on the "Server" page.

## Backup and restore

- AmneziaWG configs before every change: `data/backups/<date>-<operation>/{awg0.conf,clientsTable}` (last 200). Manual restore:
  ```bash
  P=$(pgrep -f '^amneziawg-go awg0'); D=/proc/$P/root/opt/amnezia/awg; B=/opt/awg-panel/data/backups/<dir>
  cp $B/awg0.conf $D/awg0.conf && cp $B/clientsTable $D/clientsTable
  nsenter -t $P -m -n sh -c 'awg-quick strip /opt/amnezia/awg/awg0.conf > /tmp/awg0.strip && awg syncconf awg0 /tmp/awg0.strip'
  ```
- Panel DB: `data/backups/db/panel-*.db` (last 14). Restore: `docker compose stop panel`, copy the file to `data/panel.db`, delete `panel.db-wal`/`-shm`, `docker compose up -d --no-build panel`.
- Secrets: `.env` (password, TOTP, sessions) and `data/data.key` (encrypts client private keys). Without `data.key` the configs of clients created in the panel cannot be restored. Keep copies somewhere safe.

## Uninstall

```bash
cd /opt/awg-panel && docker compose down
P=$(pgrep -f '^amneziawg-go awg0')
nsenter -t $P -m -n sh -c 'iptables -D FORWARD -i awg0 -j AWGPANEL_BLOCK; iptables -F AWGPANEL_BLOCK; iptables -X AWGPANEL_BLOCK'
ufw delete allow 14443/tcp; ufw delete allow 80/tcp
rm -rf /opt/awg-panel        # removes data and backups too — save what you need first
```

`nf_conntrack_acct=1` inside the container is reset on its next restart; it does not affect the VPN.

## Known quirks

- **Password hash without `$`.** docker compose interpolates variables in `.env`, so the hash is stored as `scrypt:N:r:p:salt:hash`.
- **`Referrer-Policy: same-origin`.** With `no-referrer` browsers submit forms with `Origin: null`; the panel accepts that, but keep the header as is.
- **Image build** — `docker build --network host` (on some hosts the bridge build network has no DNS).
- **"Never seen" status** — the client has not connected since monitoring started (AmneziaWG does not keep handshakes across its restarts).
- **Sites** are seen via DNS and SNI; DoH/DoT to non-standard resolvers and Encrypted Client Hello are not visible. Bytes per site come from closed connections.
- **Configs can be issued** only for clients created in the panel: private keys of clients created in the AmneziaVPN app exist only on their devices.

## Languages

English is the default; an EN/RU switcher is in the panel header and in the client portal (the choice is stored in a cookie; in the portal it is also the language of the client's notifications and daily report). The default is `DEFAULT_LANG` in `.env`.

Translations are JSON files `panel/app/locales/<code>.json`: the key is the English phrase, the value is the translation, `_language` is the language name in the switcher. Placeholders like `{name}` must not be translated.

To add a language, copy `en.json` to e.g. `de.json`, translate the values and `_language`, and deploy — the language appears in the switcher automatically. After code changes `cd panel && python -m app.i18n` appends new phrases to `en.json` and reports what is missing in other files; `tests/test_i18n.py` fails on incomplete translations.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r panel/requirements.txt pytest httpx
cd panel && ../.venv/bin/python -m pytest -q
```

Screenshots for this README: `.venv/bin/python tools/screenshots.py` (needs Google Chrome; runs the panel locally on demo data).

Code in `panel/app/`: `awgctl.py` (container access), `awgconf.py` (config files), `manage.py` (clients), `poller.py` (traffic, sessions), `sniffer.py`/`flows.py`/`names.py` (sites), `blocker.py` (blocking), `alerts.py`, `monthly.py`, `maintenance.py`, `clientconf.py` (.conf, QR, vpn://), `charts.py` (SVG), `admins.py`, `groups.py`, `quotas.py`, `portal.py`, `notify.py`, `report.py`, `i18n.py`, `main.py` (web).

Geolocation by [DB-IP](https://db-ip.com) Lite (CC BY 4.0).
