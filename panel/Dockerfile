# boris.gb 2026-10-28 21:12 - AmneziaWG panel image: Python + tools that run inside the amnezia-awg2 namespaces
# boris.gb 2026-10-29 07:26 - comments in English (public repository)
FROM python:3.13-alpine

# tcpdump/conntrack/nsenter run in the amnezia-awg2 network namespace
# boris.gb 2026-11-01 00:33 - curl: "what is my IP" requests from the clients' namespace (Server tab, client path to the internet)
RUN apk add --no-cache tcpdump conntrack-tools util-linux-misc iproute2 tzdata font-dejavu curl
# boris.gb 2026-10-29 00:13 - font-dejavu: non-Latin text in the daily client report image (Pillow)

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests

ENV PYTHONUNBUFFERED=1 \
    PANEL_DATA=/data
VOLUME /data

CMD ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8080", \
     "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-server-header"]
