# Changelog

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
