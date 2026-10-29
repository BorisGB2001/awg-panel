# Changelog

## 1.7.0 — 2026-10-30

- Backups page: every administrator sets up their own backup — daily or weekly at a chosen hour, or "now" — sent to
  Telegram, e-mail or both. A super administrator backs up the whole portal (database, `.env`, `data.key`,
  AmneziaWG files) — enough to set up a new server; a group administrator gets the client list and configs of
  their groups. Files are always encrypted with the administrator's backup password (AES-256-GCM, scrypt).
- Restore: on the same server from the Backups page (AmneziaWG files applied live, database with a panel restart,
  previous state kept); on a new server with `restore.sh` (also sets a new public IP). `python -m app.backup decrypt`
  for manual decryption.
- docker-compose: `.env` is mounted read-only into the panel container (it is part of the portal backup).
- Narrower menu items so that the menu fits one line.

## 1.6.2 — 2026-10-30

- Client card: Telegram ID and e-mail fields for the administrator. A new Telegram ID is checked with a test message
  (the bot can write only to someone who pressed "Start" in it once); an e-mail entered by the administrator counts
  as confirmed. The config page has a Telegram ID field too, so the config can be sent right away.

## 1.6.1 — 2026-10-30

- Fix: choosing a group did nothing on the Sites, Events and Archive pages — the script that applies the filter was
  loaded only on the overview. It is now loaded on every page.
- app.js and app.css are requested with the panel version, so browsers do not keep an old copy after an update.

## 1.6.0 — 2026-10-30

- Send the config to the client: to Telegram (if the client connected it) or by a one-time bot link valid for 7 days —
  the client presses "Start" and gets the .conf file, QR code and vpn:// key, and notifications are connected too;
  or by e-mail (.conf and QR attached; needs SMTP in .env).
- Regenerate keys: a new config with the same IP, live without restarting AmneziaWG; the old config stops working.
  Also issues a config for clients created in the AmneziaVPN app.
- After adding a client the config page opens at once with the sending options.
- Group administrators can do all of this for the clients of their groups.

## 1.5.1 — 2026-10-30

- Overview: the client's group is shown under its name in the client list (the list search finds clients by group too).

## 1.5.0 — 2026-10-30

- Telegram alerts for administrators: connect the panel bot on the "My account" page; new alerts (and, optionally,
  sign-ins) come to Telegram. Super administrators get everything, group administrators only alerts about the
  clients of their groups. Quiet hours (only server alerts then). In the bot: /stats — a short summary, /stop.
- Client portal: a clear Telegram block with a "Disconnect" button; the client's quota is shown; clients are
  notified when they reach their quota.
- Groups: traffic-by-group chart and a CSV export; the monthly archive shows totals by group.
- Layout: form controls in one row have the same height (group and quota forms, page headers with filters).

## 1.4.1 — 2026-10-30

- README: screenshots of every menu section (English and Russian), made on demo data by `tools/screenshots.py`.
- Fix: chart axis labels like "953.7 MiB" were cut on the left, the last time label on the right.
- The quota usage bar on the client card no longer stretches across the whole page.

## 1.4.0 — 2026-10-30

- Traffic quotas per group and per client: a limit in GiB per day or calendar month (downloaded + uploaded).
- Alerts at 80 % and 100 %, once per period (again if the limit is raised). Action when exceeded: alert only, or
  disable the clients until the next period; they are enabled again automatically when the period changes or the
  limit is raised. A client enabled by hand is not disabled again in the same period.
- Usage bars on the Groups page and the client card; group quotas are set by super administrators, client quotas
  also by the client's group administrator.

## 1.3.0 — 2026-10-30

- Client groups: Groups page (clients, online, traffic today and this month, administrators per group), create,
  rename and delete groups; move a client to a group on its card; choose the group when adding a client.
- Group administrators: a new role that sees and manages only the clients of its groups — overview, client cards,
  configs, sites, events, alerts, archive, CSV exports and blocking rules. Rules for everyone stay with super
  administrators and are shown to group administrators read-only. Groups are assigned on the Administrators page.
- Group filter on the overview, sites, events and archive pages.
- Clients created in the AmneziaVPN app have no group and are visible to super administrators only.

## 1.2.0 — 2026-10-30

- Administrator accounts in the panel database (Administrators page, super administrators only). The `.env`
  account (`init-admin.sh`) is always a super administrator and stays the recovery login.
- A new administrator gets a temporary password shown once; on first sign-in they scan the authenticator QR code
  and must set their own password. Reset, disable, enable and delete; the last active super administrator is protected.
- Sessions end at once when an account is disabled or reset; a TOTP code is accepted only once, also across restarts.
- "My account" page with password change; the user name in the header links to it.
- The Server page is for super administrators only.

## 1.1.2 — 2026-10-29

- Fix: the theme switch did nothing in the client portal (personal link); the portal also showed the language
  and theme switchers twice.

## 1.1.1 — 2026-10-29

Security update.

- Dependencies with known vulnerabilities upgraded: Starlette 0.48 → 1.10, python-multipart 0.0.20 → 0.0.32,
  cryptography 46.0.2 → 50.0.2 (plus FastAPI 0.162, uvicorn 0.54). Caddy 2.10 → 2.11.7.
- Fix: open redirect via a `back` value like `/\evil.com` after actions on the blocking page.
- CSV exports neutralise spreadsheet formulas in client names; the archive month is validated.
- Panel data directory and database files are now private (700/600).
- Tests: every admin POST action must reject a request without a valid CSRF token.

## 1.1.0 — 2026-10-29

- Theme switch: light / dark / system, in the panel header, on the login page and in the client portal.
- The current page is highlighted in the menu; on phones the menu moves to its own row.
- Server page: compact tiles (18px values, shorter labels, totals on a second line, PID next to "Uptime"),
  AmneziaWG parameters shown as a grid of tiles.
- Version shown in the footer and in `/healthz`.
- Fix: false "connection from a new country" alerts when a client switches between its home address and a
  carrier CGNAT address (100.64.0.0/10) that has no country in the geo database.

## 1.0.0 — 2026-10-29

First public release: sessions and traffic per client, visited sites (DNS + SNI), domain/IP blocking with presets,
live client management with configs (.conf, QR, vpn://), alerts, monthly archive, client portal,
Telegram/e-mail notifications, English and Russian interface.
