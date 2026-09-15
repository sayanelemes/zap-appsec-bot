import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Запрещенные IPv4 подсети (RFC 1918, Loopback, Link-Local, Cloud Metadata, CGNAT, Broadcast)
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Текущая сеть (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Приватная сеть (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Приватная сеть (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Приватная сеть (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

# Запрещенные IPv6 подсети
BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique Local Addresses (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-Local
    ipaddress.ip_network("ff00::/8"),          # Multicast
]

# Запрещенные имена хостов
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "instance-data",
}


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Проверяет, входит ли IP-адрес в список заблокированных диапазонов."""
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return True
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return True

    return False


async def validate_url_safe(url: str) -> tuple[bool, str, str | None]:
    """
    Асинхронно валидирует URL для предотвращения SSRF:
    1. Проверяет схему (http, https).
    2. Проверяет хостнейм на локальные домены.
    3. Асинхронно резолвит IP-адрес через getaddrinfo.
    4. Проверяет все IP на принадлежность к закрытым/локальным диапазонам.

    Возвращает:
        tuple[is_safe, error_reason, resolved_ip]
    """
    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        return False, f"Некорректный синтаксис URL: {e}", None

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Разрешены только протоколы HTTP и HTTPS.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "Не удалось извлечь имя хоста из URL.", None

    hostname_lower = hostname.lower().strip(".")

    # Проверка спецхостов
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Доступ к внутреннему хосту '{hostname}' запрещен (SSRF-защита).", None

    if hostname_lower.endswith((".local", ".internal", ".localhost", ".lan")):
        return False, f"Доступ к локальным доменным зонам ('{hostname}') запрещен.", None

    # Если в URL напрямую передан IP-адрес
    try:
        direct_ip = ipaddress.ip_address(hostname_lower)
        if is_ip_blocked(direct_ip):
            return False, f"Запрещенный адрес: {direct_ip} (локальная/приватная сеть).", str(direct_ip)
        return True, "", str(direct_ip)
    except ValueError:
        # Это доменное имя, резолвим через DNS
        pass

    loop = asyncio.get_running_loop()
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addr_infos = await loop.getaddrinfo(
            hostname_lower,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        return False, f"Не удалось разрешить DNS для '{hostname}': хост не найден ({e}).", None
    except Exception as e:
        return False, f"Ошибка при проверке DNS для '{hostname}': {e}", None

    if not addr_infos:
        return False, f"Не удалось получить IP-адрес для хоста '{hostname}'.", None

    first_resolved_ip: str | None = None

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        if not first_resolved_ip:
            first_resolved_ip = ip_str
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip_obj):
                logger.warning("SSRF Block: хост %s разрешился в приватный IP %s", hostname, ip_str)
                return False, f"Хост '{hostname}' разрешается в приватный IP-адрес {ip_str} (SSRF-защита).", ip_str
        except ValueError:
            return False, f"Не удалось валидировать IP-адрес: {ip_str}", None

    return True, "", first_resolved_ip
