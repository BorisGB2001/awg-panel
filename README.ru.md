# AWG панель

[English version](README.md)

Веб-панель для сервера AmneziaWG (контейнер `amnezia-awg2`, приложение AmneziaVPN): сессии и трафик клиентов, откуда подключаются, на какие сайты ходят, блокировка доменов и IP, добавление/удаление клиентов и выдача конфигов, алерты, помесячный архив, группы клиентов с их администраторами, квоты трафика, личный кабинет клиента, уведомления в Telegram и на почту.

| | |
|---|---|
| Адрес | `https://<IP-сервера>:14443` (порт — `PANEL_PORT` в `.env`; сертификат Let's Encrypt на IP, Caddy продлевает сам; порт 80 должен быть разрешён в firewall, но Caddy слушает его только несколько секунд во время проверки сертификата) |
| Каталог | `/opt/awg-panel` на сервере AmneziaWG |
| Контейнеры | `awg-panel` (Python, FastAPI), `awg-panel-caddy` (HTTPS) |
| Данные | `/opt/awg-panel/data`: `panel.db` (SQLite), `backups/` (конфиги AmneziaWG и БД), `geo/` (DB-IP), `data.key` |
| Вход | логин `admin`, пароль + код TOTP |

## Скриншоты

Данные демонстрационные: клиенты, адреса и трафик вымышлены. Нажмите на картинку, чтобы открыть её целиком. Скриншоты делает `tools/screenshots.py`.

<table>
<tr><td width="50%"><a href="docs/screenshots/ru/overview.png"><img src="docs/screenshots/ru/overview.png" alt="Обзор — клиенты, трафик, топ-10"></a><br><b>Обзор — клиенты, трафик, топ-10</b></td><td width="50%"><a href="docs/screenshots/ru/client.png"><img src="docs/screenshots/ru/client.png" alt="Карточка клиента — группа, квота, кабинет, активность"></a><br><b>Карточка клиента — группа, квота, кабинет, активность</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/ru/config.png"><img src="docs/screenshots/ru/config.png" alt="Конфиг — QR, ключ vpn://, отправка в Telegram или на почту"></a><br><b>Конфиг — QR, ключ vpn://, отправка в Telegram или на почту</b></td><td width="50%"><a href="docs/screenshots/ru/sites.png"><img src="docs/screenshots/ru/sites.png" alt="Сайты — куда ходят клиенты"></a><br><b>Сайты — куда ходят клиенты</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/ru/events.png"><img src="docs/screenshots/ru/events.png" alt="События — подключения, смены IP, действия админов"></a><br><b>События — подключения, смены IP, действия админов</b></td><td width="50%"><a href="docs/screenshots/ru/archive.png"><img src="docs/screenshots/ru/archive.png" alt="Помесячный архив"></a><br><b>Помесячный архив</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/ru/alerts.png"><img src="docs/screenshots/ru/alerts.png" alt="Алерты"></a><br><b>Алерты</b></td><td width="50%"><a href="docs/screenshots/ru/blocking.png"><img src="docs/screenshots/ru/blocking.png" alt="Блокировки — домены, IP, наборы"></a><br><b>Блокировки — домены, IP, наборы</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/ru/groups.png"><img src="docs/screenshots/ru/groups.png" alt="Группы — трафик и квоты"></a><br><b>Группы — трафик и квоты</b></td><td width="50%"><a href="docs/screenshots/ru/backups.png"><img src="docs/screenshots/ru/backups.png" alt="Бэкапы — расписание, Telegram/почта, восстановление"></a><br><b>Бэкапы — расписание, Telegram/почта, восстановление</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/ru/server.png"><img src="docs/screenshots/ru/server.png" alt="Сервер — AmneziaWG и сборщики"></a><br><b>Сервер — AmneziaWG и сборщики</b></td><td width="50%"><a href="docs/screenshots/ru/admins.png"><img src="docs/screenshots/ru/admins.png" alt="Администраторы — роли и группы"></a><br><b>Администраторы — роли и группы</b></td></tr>
<tr><td width="50%"><a href="docs/screenshots/ru/portal.png"><img src="docs/screenshots/ru/portal.png" alt="Кабинет клиента (личная ссылка)"></a><br><b>Кабинет клиента (личная ссылка)</b></td><td width="50%"><a href="docs/screenshots/ru/overview-dark.png"><img src="docs/screenshots/ru/overview-dark.png" alt="Тёмная тема"></a><br><b>Тёмная тема</b></td></tr>
</table>

## Как устроено

- Панель **не трогает** контейнер `amnezia-awg2` (не пересоздаёт, не перезапускает, не меняет `start.sh`). Работает снаружи: находит процесс `amneziawg-go awg0` в `/proc`, команды выполняет через `nsenter` в его namespace, файлы `awg0.conf` и `clientsTable` читает и пишет через `/proc/<PID>/root`. docker.sock не нужен; поэтому контейнер панели — `privileged`, `pid: host`, `network_mode: host`.
- Клиенты добавляются и удаляются на живом интерфейсе (`awg set`), без перезапуска — сессии остальных не рвутся. IP нового клиента — максимальный занятый + 1 (как в приложении AmneziaVPN). Перед каждым изменением — бэкап обоих файлов в `data/backups/`, при ошибке — откат. Приложение AmneziaVPN продолжает видеть всех клиентов.
- Сбор: опрос `awg show dump` раз в 30 с (трафик, сессии, IP), DNS-ответы и SNI из `tcpdump` на `awg0`, закрытые соединения из `conntrack`. Гео — базы DB-IP Lite, обновляются раз в месяц.
- Блокировка — правила iptables в namespace контейнера (цепочка `AWGPANEL_BLOCK`), работают и без панели; после рестарта контейнера панель ставит их заново.
- Хранение: поминутный трафик — 7 дней; сайты и соединения — 30 дней, дальше итоги по дням (`hosts_day`, год); часовой трафик, сессии и помесячный архив — бессрочно; события — год. Бэкап БД — каждую ночь, 14 последних.

## Установка с нуля

```bash
# на своём компьютере, из корня репозитория
./deploy.sh root@<сервер>                     # копирует файлы, собирает образ, гоняет тесты, запускает panel
ssh root@<сервер> 'cd /opt/awg-panel && cp -n .env.example .env && chmod 600 .env'
# в .env задать PANEL_HOST, PUBLIC_HOST, SESSION_SECRET, DATA_KEY (команды для генерации — в самом файле)
ssh root@<сервер> 'cd /opt/awg-panel && docker compose up -d --no-build'   # panel + caddy
ssh root@<сервер> 'ufw allow 14443/tcp && ufw allow 80/tcp'   # 80 — только для проверки сертификата, в остальное время там никто не слушает
```

Пароль администратора и TOTP — в своём терминале (вывод содержит секрет TOTP):

```bash
ssh -t root@<сервер> /opt/awg-panel/init-admin.sh          # пароль + TOTP
ssh -t root@<сервер> /opt/awg-panel/init-admin.sh hash     # только сменить пароль
ssh -t root@<сервер> /opt/awg-panel/init-admin.sh totp     # только перевыпустить TOTP
```

## Обновление

```bash
./deploy.sh root@<сервер>
```

Чтобы не указывать хост каждый раз: `echo root@<сервер> > .deploy-host` (файл не попадает в git).

Скрипт собирает образ в сети хоста, прогоняет тесты внутри образа и пересоздаёт только контейнер `panel` (Caddy и AmneziaWG не трогаются). Миграции БД применяются сами при старте.

## Проверка и логи

```bash
ssh root@<сервер> 'curl -s http://127.0.0.1:8080/healthz'          # состояние сборщиков
ssh root@<сервер> 'docker logs --tail 100 awg-panel'
ssh root@<сервер> 'docker logs --tail 50 awg-panel-caddy'
```

То же в панели — страница «Сервер».

## Бэкап и восстановление

- Конфиги AmneziaWG перед каждым изменением: `data/backups/<дата>-<операция>/{awg0.conf,clientsTable}` (200 последних). Восстановить вручную:
  ```bash
  P=$(pgrep -f '^amneziawg-go awg0'); D=/proc/$P/root/opt/amnezia/awg; B=/opt/awg-panel/data/backups/<каталог>
  cp $B/awg0.conf $D/awg0.conf && cp $B/clientsTable $D/clientsTable
  nsenter -t $P -m -n sh -c 'awg-quick strip /opt/amnezia/awg/awg0.conf > /tmp/awg0.strip && awg syncconf awg0 /tmp/awg0.strip'   # применит конфиг целиком
  ```
- БД панели: `data/backups/db/panel-*.db` (14 последних). Восстановить: `docker compose stop panel`, скопировать файл в `data/panel.db`, удалить `panel.db-wal`/`-shm`, `docker compose up -d --no-build panel`.
- Секреты: `.env` (пароль, TOTP, сессии), `data/data.key` (шифрование приватных ключей клиентов) — без `data.key` конфиги клиентов, созданных в панели, восстановить нельзя. Хранить копии в надёжном месте.

## Доступ по IP

Панель (и страница входа) может открываться только с адресов и подсетей из списка; кабинет клиентов остаётся открытым. Пустой список — ограничения нет. Список меняется на странице **«Администраторы»** (супер-администратор; панель не даст удалить ваш текущий адрес) или на сервере — так можно, даже если из браузера доступа нет:

```bash
ssh root@<сервер> /opt/awg-panel/ip-allow.sh list
ssh root@<сервер> /opt/awg-panel/ip-allow.sh add 203.0.113.7 офис        # адрес или подсеть, IPv4 или IPv6
ssh root@<сервер> /opt/awg-panel/ip-allow.sh remove 203.0.113.7          # или номер из list
ssh root@<сервер> /opt/awg-panel/ip-allow.sh clear                       # снять ограничение
```

## Бэкапы в Telegram или на почту, восстановление

Каждый администратор настраивает свой бэкап на странице **«Бэкапы»**: каждый день или раз в неделю в выбранный час, плюс «Сделать бэкап сейчас»; отправка в Telegram (чат, подключённый в «Моём аккаунте»), на почту или туда и туда.

- **Супер-администратор — весь портал:** база панели, `.env` (пароль и TOTP администратора, ключи, токен бота, почта), `data.key` и файлы AmneziaWG (`awg0.conf`, `clientsTable`, ключи сервера, PSK). Этого хватает, чтобы поднять новый сервер.
- **Администратор группы — свои группы:** `clients.csv` и конфиги `.conf` клиентов.
- Файл (`.awgbak`) **всегда зашифрован** паролем бэкапа администратора (AES-256-GCM, ключ из пароля через scrypt). Сохраните пароль: без него бэкап не открыть. Расшифровать вручную: `docker compose exec panel python -m app.backup decrypt <файл>` (спросит пароль).

**Восстановление на этом же сервере:** «Бэкапы» → «Восстановление из бэкапа» (супер-администратор): файлы AmneziaWG применяются сразу, без перезапуска AmneziaWG, база ставится на место, и панель перезапускается. Прежнее состояние сохраняется в `data/backups/<время>-pre-restore/`.

**Переезд на новый сервер:**

1. Установите AmneziaWG на новый сервер приложением AmneziaVPN (тот же протокол и **тот же порт**, что был, — порт берётся из восстановленного `awg0.conf`).
2. Разверните панель: `./deploy.sh root@<новый-сервер>` (см. «Установка с нуля»; `init-admin.sh` запускать не нужно).
3. Скопируйте бэкап и восстановите: `scp awg-portal-….awgbak root@<новый-сервер>:/opt/awg-panel/`, затем на сервере `cd /opt/awg-panel && ./restore.sh awg-portal-….awgbak [<новый-IP>]`. Скрипт спросит пароль бэкапа, вернёт `.env`, базу, `data.key` и файлы AmneziaWG, применит их и запустит панель.
4. Откройте порты (`ufw allow <порт-VPN>/udp`, `14443/tcp`, `80/tcp`).

Если у сервера остался прежний IP, клиенты продолжают работать со старыми конфигами. При новом IP передайте его в `restore.sh`: панель будет выдавать конфиги с новым адресом — отправьте их клиентам с карточек (Telegram или почта).



```bash
cd /opt/awg-panel && docker compose down
P=$(pgrep -f '^amneziawg-go awg0')
nsenter -t $P -m -n sh -c 'iptables -D FORWARD -i awg0 -j AWGPANEL_BLOCK; iptables -F AWGPANEL_BLOCK; iptables -X AWGPANEL_BLOCK'
ufw delete allow 14443/tcp; ufw delete allow 80/tcp
rm -rf /opt/awg-panel        # вместе с данными и бэкапами — сначала сохранить нужное
```

`nf_conntrack_acct=1` в контейнере сбросится при его следующем перезапуске; на работу VPN не влияет.

## Известные особенности

- **Порт 80** разрешён в firewall, но обычно закрыт: перенаправления HTTP→HTTPS нет, Caddy открывает :80 только пока Let's Encrypt проверяет сертификат на IP (раз в 2–3 дня, на несколько секунд). Проверка через порт 443 (TLS-ALPN) тоже возможна, если 443 свободен: уберите `disable_tlsalpn_challenge` из `Caddyfile`.

- **Хеш пароля без `$`.** docker compose подставляет переменные в `.env`, поэтому хеш хранится как `scrypt:N:r:p:salt:hash`.
- **`Referrer-Policy: same-origin`.** С `no-referrer` браузер отправляет формы с `Origin: null`; панель такое принимает, но держать заголовок так.
- **Сборка образа** — только `docker build --network host` (на некоторых хостах в bridge-сети сборки нет DNS).
- **Статус «не видели»** — клиент не подключался с начала наблюдения (AmneziaWG не хранит handshake до своего перезапуска).
- **Сайты** видны по DNS и SNI; DoH/DoT на нестандартных резолверах и Encrypted Client Hello не видны. Байты по сайтам — по закрытым соединениям.
- **Конфиг выдаётся** только для клиентов, созданных в панели: приватный ключ клиентов из приложения AmneziaVPN есть только на их устройствах.

## Языки интерфейса

Основной язык — английский; переключатель EN/RU в шапке панели и в кабинете клиента (выбор запоминается в cookie, в кабинете — ещё и как язык уведомлений и сводки клиента). Язык по умолчанию — `DEFAULT_LANG` в `.env` (по умолчанию `en`).

Переводы — JSON-файлы `panel/app/locales/<код>.json`: ключ — английская фраза, значение — перевод, `_language` — название языка в переключателе. Фразы вида `{name}` — подстановки, их не переводить.

Добавить язык: скопировать `en.json` в, например, `de.json`, перевести значения и `_language`, выложить (`./deploy.sh`) — язык появится в переключателе сам. После правок кода: `cd panel && python -m app.i18n` дописывает новые фразы в `en.json` и показывает, чего не хватает в остальных файлах; тест `tests/test_i18n.py` не даст выложить неполный перевод.

## Разработка

```bash
python3 -m venv .venv && .venv/bin/pip install -r panel/requirements.txt pytest httpx
cd panel && ../.venv/bin/python -m pytest -q
```

Скриншоты для README: `.venv/bin/python tools/screenshots.py` (нужен Google Chrome; панель запускается локально на демо-данных).

Код: `panel/app/` — `awgctl.py` (доступ к контейнеру), `awgconf.py` (файлы), `manage.py` (клиенты), `poller.py` (трафик, сессии), `sniffer.py`/`flows.py`/`names.py` (сайты), `blocker.py` (блокировка), `alerts.py`, `monthly.py`, `maintenance.py`, `clientconf.py` (.conf, QR, vpn://), `charts.py` (SVG), `admins.py` (администраторы), `groups.py` (группы), `quotas.py` (квоты), `portal.py`, `notify.py`, `report.py`, `i18n.py`, `main.py` (веб).
