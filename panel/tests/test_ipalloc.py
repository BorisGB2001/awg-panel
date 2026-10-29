import pytest

from app.ipalloc import NoFreeIP, next_ip

NET = "10.8.1.0/24"


def test_max_plus_one_ignores_gaps():
    used = {f"10.8.1.{i}" for i in (1, 2, 3, 5, 7, 46)}
    assert next_ip(NET, used) == "10.8.1.47"


def test_empty_starts_at_one():
    assert next_ip(NET, set()) == "10.8.1.1"


def test_reserved_disabled_ip_counts():
    assert next_ip(NET, {"10.8.1.1", "10.8.1.50"}) == "10.8.1.51"


def test_wraps_to_lowest_free_at_end():
    used = {f"10.8.1.{i}" for i in range(1, 255) if i != 6}
    assert next_ip(NET, used) == "10.8.1.6"


def test_never_gives_network_or_broadcast():
    used = {f"10.8.1.{i}" for i in range(2, 255)}
    assert next_ip(NET, used) == "10.8.1.1"
    with pytest.raises(NoFreeIP):
        next_ip(NET, used | {"10.8.1.1"})


def test_foreign_and_empty_values_ignored():
    assert next_ip(NET, {"", "192.168.0.9", "10.8.1.4"}) == "10.8.1.5"
