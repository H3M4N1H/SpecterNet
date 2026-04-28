"""Shared constants and formatting helpers used across the app."""

from __future__ import annotations

import datetime as _dt
import socket

try:
    from scapy.all import get_if_list
except Exception:  # pragma: no cover - fallback when scapy is unavailable
    get_if_list = None


PROTO_COLORS = {
    "ARP": "#f38ba8",
    "TCP": "#89b4fa",
    "UDP": "#a6e3a1",
    "HTTP": "#fab387",
    "HTTPS": "#f5c2e7",
    "DNS": "#cba6f7",
    "FTP": "#f9e2af",
    "ICMP": "#94e2d5",
    "SMTP": "#f38ba8",
    "Telnet": "#f2cdcd",
    "OTHER": "#6c7086",
}


SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def format_bytes(num_bytes: int | float) -> str:
    """Format a byte count into a human-readable string."""
    try:
        value = float(num_bytes)
    except Exception:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024.0
        unit += 1

    if unit == 0:
        return f"{int(value)} {units[unit]}"
    return f"{value:.1f} {units[unit]}"


def format_timestamp(timestamp: float | int | None) -> str:
    """Format a packet timestamp for the packet table."""
    if timestamp is None:
        return ""
    try:
        dt = _dt.datetime.fromtimestamp(float(timestamp))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return str(timestamp)


def get_interfaces() -> list[str]:
    """Return a best-effort list of local capture interfaces."""
    if get_if_list is not None:
        try:
            interfaces = [iface for iface in get_if_list() if iface]
            if interfaces:
                return interfaces
        except Exception:
            pass

    try:
        return [name for _, name in socket.if_nameindex()]
    except Exception:
        return []

