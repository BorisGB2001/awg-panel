"""Доступ к контейнеру amnezia-awg2 снаружи, без docker.sock.

Процесс amneziawg-go ищется по /proc; команды awg выполняются через nsenter в его mount- и net-namespace,
файлы читаются и пишутся через /proc/<PID>/root.
"""
from __future__ import annotations

import fcntl
import os
import subprocess
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .awgconf import AwgConf, parse_clients, render_clients
from .config import Settings


class AwgUnavailable(RuntimeError):
    """Процесс amneziawg-go не найден или интерфейс недоступен."""


@dataclass(frozen=True)
class PeerStat:
    pubkey: str
    endpoint: str | None      # "ip:port" или None
    allowed_ips: str
    latest_handshake: int     # unix, 0 — ни разу
    rx: int                   # байт получено сервером от клиента (клиент отдал)
    tx: int                   # байт отправлено клиенту (клиент скачал)

    @property
    def endpoint_ip(self) -> str | None:
        if not self.endpoint:
            return None
        host = self.endpoint.rsplit(":", 1)[0]
        return host.strip("[]")


def parse_dump(text: str) -> list[PeerStat]:
    """Вывод `awg show <iface> dump`: первая строка — интерфейс, далее по строке на клиента (8 полей через TAB)."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        endpoint = None if f[2] in ("(none)", "") else f[2]
        out.append(PeerStat(f[0], endpoint, "" if f[3] == "(none)" else f[3], int(f[4]), int(f[5]), int(f[6])))
    return out


def find_pid(match: str, proc: Path = Path("/proc")) -> int | None:
    want = match.split()
    for d in proc.iterdir():
        if not d.name.isdigit():
            continue
        try:
            argv = (d / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        except OSError:
            continue
        if [a.decode(errors="replace") for a in argv] == want:
            return int(d.name)
    return None


class AWG:
    def __init__(self, settings: Settings, proc: Path = Path("/proc")):
        self.s = settings
        self.proc = proc
        self._pid: int | None = None
        self._lock = threading.Lock()

    # ---- процесс ----

    def pid(self) -> int:
        """PID amneziawg-go; перепроверяется при каждом вызове (контейнер мог перезапуститься)."""
        pid = self._pid
        if pid is not None:
            try:
                argv = (self.proc / str(pid) / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                if [a.decode(errors="replace") for a in argv] == self.s.awg_process_match.split():
                    return pid
            except OSError:
                pass
        pid = find_pid(self.s.awg_process_match, self.proc)
        if pid is None:
            self._pid = None
            raise AwgUnavailable(f"process “{self.s.awg_process_match}” not found")
        self._pid = pid
        return pid

    def started_at(self) -> float:
        """Время старта процесса amneziawg-go (unix)."""
        pid = self.pid()
        ticks = int((self.proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])
        boot = next(float(line.split()[1]) for line in (self.proc / "stat").read_text().splitlines()
                    if line.startswith("btime "))
        return boot + ticks / os.sysconf("SC_CLK_TCK")

    # ---- команды ----

    def ns_argv(self, args: list[str], mount: bool = False) -> list[str]:
        """argv для запуска команды в namespace контейнера; mount=True — и бинарник берётся из контейнера."""
        return ["nsenter", "-t", str(self.pid()), *(["-m"] if mount else []), "-n", "--", *args]

    def run(self, args: list[str], mount: bool = True, input: str | None = None, timeout: float = 15) -> str:
        try:
            r = subprocess.run(self.ns_argv(args, mount), input=input, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise AwgUnavailable(f"{args[0]}: timeout") from e
        if r.returncode != 0:
            raise AwgUnavailable(f"{' '.join(args[:3])}: {r.stderr.strip()[:300]}")
        return r.stdout

    def dump(self) -> list[PeerStat]:
        return parse_dump(self.run(["awg", "show", self.s.awg_iface, "dump"]))

    def set_peer(self, pubkey: str, ip: str) -> None:
        psk = f"{self.s.awg_dir}/wireguard_psk.key"
        self.run(["awg", "set", self.s.awg_iface, "peer", pubkey, "preshared-key", psk, "allowed-ips", f"{ip}/32"])

    def remove_peer(self, pubkey: str) -> None:
        self.run(["awg", "set", self.s.awg_iface, "peer", pubkey, "remove"])

    # ---- файлы ----

    def path(self, name: str) -> Path:
        return self.proc / str(self.pid()) / "root" / self.s.awg_dir.lstrip("/") / name

    def read_text(self, name: str) -> str:
        return self.path(name).read_text(encoding="utf-8")

    def read_conf(self) -> AwgConf:
        return AwgConf.parse(self.read_text(f"{self.s.awg_iface}.conf"))

    def read_clients(self) -> list[dict]:
        try:
            return parse_clients(self.read_text("clientsTable"))
        except FileNotFoundError:
            return []

    def server_public_key(self) -> str:
        return self.read_text("wireguard_server_public_key.key").strip()

    def psk(self) -> str:
        return self.read_text("wireguard_psk.key").strip()

    def write_conf(self, conf: AwgConf) -> None:
        atomic_write(self.path(f"{self.s.awg_iface}.conf"), conf.render())

    def write_clients(self, clients: list[dict]) -> None:
        atomic_write(self.path("clientsTable"), render_clients(clients))

    @contextmanager
    def locked(self):
        """Одна операция изменения за раз — и между потоками, и между процессами панели."""
        with self._lock:
            self.s.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.s.data_dir / "awg.lock", "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)


def atomic_write(path: Path, text: str) -> None:
    """Временный файл рядом → fsync → rename; права и владелец — как у исходного файла."""
    st = path.stat() if path.exists() else None
    tmp = path.with_name(f".{path.name}.panel-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if st:
            os.chmod(tmp, st.st_mode & 0o7777)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
