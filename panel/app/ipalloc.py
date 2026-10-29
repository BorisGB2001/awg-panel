"""Выдача IP новому клиенту без сбоя нумерации."""
from __future__ import annotations

import ipaddress


class NoFreeIP(RuntimeError):
    pass


def next_ip(subnet: str, used: set[str]) -> str:
    """Следующий после максимального занятого (как приложение AmneziaVPN); если дошли до конца — наименьший свободный.

    used — IP из awg0.conf, clientsTable и отключённых в панели клиентов. Адрес сети (адрес сервера 10.8.1.0)
    и broadcast не выдаются никогда.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    taken = {ipaddress.ip_address(u) for u in used if u and ipaddress.ip_address(u) in net}
    if taken:
        nxt = max(taken) + 1
        if nxt in hosts and nxt not in taken:
            return str(nxt)
    for h in hosts:
        if h not in taken:
            return str(h)
    raise NoFreeIP(f"no free addresses in {net}")
