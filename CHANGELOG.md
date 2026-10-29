# Changelog

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
