import re
import logging
from utils.logger import get_logger
from utils.helpers import SERVICE_PORTS

logger = get_logger("Analyzer")


def get_protocol(packet):
    """Determine highest-level protocol of packet."""
    try:
        from scapy.layers.inet import TCP, UDP, ICMP, IP
        from scapy.layers.l2 import ARP
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
        from scapy.layers.dns import DNS
        try:
            from scapy.layers.tls.all import TLS
        except ImportError:
            TLS = None

        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            return "HTTP"
        if TLS and packet.haslayer(TLS):
            return "TLS"
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport == 443 or dport == 443:
                return "HTTPS"
            if sport == 21 or dport == 21:
                return "FTP"
            if sport == 22 or dport == 22:
                return "SSH"
            if sport == 23 or dport == 23:
                return "Telnet"
            if sport == 25 or dport == 25:
                return "SMTP"
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
    except Exception as e:
        logger.debug(f"Protocol detection failed: {e}")
    return "OTHER"


def get_summary(packet):
    """Get human-readable packet summary."""
    try:
        from scapy.layers.inet import TCP, UDP, IP
        from scapy.layers.http import HTTPRequest, HTTPResponse
        from scapy.layers.dns import DNS, DNSQR
        try:
            from scapy.layers.tls.handshake import TLSClientHello
        except ImportError:
            TLSClientHello = None

        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            method = req.Method.decode(errors='ignore') if req.Method else "?"
            path = req.Path.decode(errors='ignore') if req.Path else "/"
            host = req.Host.decode(errors='ignore') if hasattr(req, 'Host') and req.Host else ""
            return f"{method} {host}{path}"

        if packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            code = resp.Status_Code.decode(errors='ignore') if resp.Status_Code else "?"
            return f"HTTP {code}"

        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0 and packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
                return f"DNS Query: {qname}"
            return "DNS Response"

        if TLSClientHello and packet.haslayer(TLSClientHello):
            hello = packet[TLSClientHello]
            if hasattr(hello, 'extensions'):
                from scapy.layers.tls.extensions import TLS_Ext_ServerName
                for ext in hello.extensions:
                    if isinstance(ext, TLS_Ext_ServerName):
                        server_names = [sn.servername.decode(errors='ignore') for sn in ext.servernames]
                        return f"TLS SNI: {', '.join(server_names)}"
            return "TLS Client Hello"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # Detect SSH banner
            if (tcp.sport == 22 or tcp.dport == 22) and packet.haslayer(__import__('scapy.packet', fromlist=['Raw']).Raw):
                payload = packet[__import__('scapy.packet', fromlist=['Raw']).Raw].load
                if payload.startswith(b"SSH-"):
                    return f"SSH Banner: {payload.decode(errors='ignore').strip()}"
            
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            return f"TCP {' '.join(flags) or 'DATA'} Seq={tcp.seq}"

        if packet.haslayer(UDP):
            udp = packet[UDP]
            return f"UDP {udp.sport} → {udp.dport}"

    except Exception as e:
        logger.debug(f"Summary generation failed: {e}")
    
    try:
        return packet.summary()[:80]
    except Exception:
        return "[Unknown Packet]"


def get_src_dst(packet):
    """Extract source and destination."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import ARP

        if packet.haslayer(IP):
            ip = packet[IP]
            src = ip.src
            dst = ip.dst
            if packet.haslayer(TCP):
                src += f":{packet[TCP].sport}"
                dst += f":{packet[TCP].dport}"
            elif packet.haslayer(UDP):
                src += f":{packet[UDP].sport}"
                dst += f":{packet[UDP].dport}"
            return src, dst

        if packet.haslayer(ARP):
            return packet[ARP].psrc, packet[ARP].pdst

    except Exception as e:
        logger.debug(f"Source/Dest extraction failed: {e}")
    return "?", "?"


def get_packet_length(packet):
    try:
        return len(packet)
    except Exception:
        return 0


def sniff_credentials(packet):
    """
    Detect plaintext credentials in packet payload.
    Returns list of (protocol, src, credential_string) or empty list.
    """
    creds = []
    try:
        from scapy.layers.inet import TCP, IP
        from scapy.layers.http import HTTPRequest

        src_ip = packet[IP].src if packet.haslayer(__import__('scapy.layers.inet', fromlist=['IP']).IP) else "?"

        # HTTP POST credential sniffing
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            method = req.Method.decode(errors='ignore') if req.Method else ""
            if method == "POST" and packet.haslayer(__import__('scapy.packet', fromlist=['Raw']).Raw):
                payload = packet[__import__('scapy.packet', fromlist=['Raw']).Raw].load.decode('utf-8', errors='ignore')
                # Common login field patterns
                patterns = [
                    r'(user(?:name)?|login|email)[=:]([^&\s]{1,50})',
                    r'(pass(?:word)?|pwd)[=:]([^&\s]{1,50})',
                ]
                found = {}
                for pattern in patterns:
                    matches = re.findall(pattern, payload, re.IGNORECASE)
                    for key, val in matches:
                        found[key.lower()] = val
                if found:
                    cred_str = " | ".join(f"{k}={v}" for k, v in found.items())
                    creds.append(("HTTP", src_ip, cred_str))

        # FTP credential sniffing
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            from scapy.packet import Raw
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload.upper().startswith("USER "):
                    creds.append(("FTP", src_ip, f"USERNAME: {payload[5:]}"))
                elif payload.upper().startswith("PASS "):
                    creds.append(("FTP", src_ip, f"PASSWORD: {payload[5:]}"))

        # Telnet sniffing (basic)
        if packet.haslayer(TCP) and (packet[TCP].dport == 23 or packet[TCP].sport == 23):
            from scapy.packet import Raw
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload and payload.isprintable() and len(payload) > 0:
                    creds.append(("Telnet", src_ip, f"DATA: {payload[:50]}"))

        # SMTP AUTH sniffing
        if packet.haslayer(TCP) and (packet[TCP].dport == 25 or packet[TCP].sport == 25):
            from scapy.packet import Raw
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                if any(x in payload.upper() for x in ["AUTH ", "MAIL FROM:", "RCPT TO:"]):
                    creds.append(("SMTP", src_ip, payload[:80]))

    except Exception as e:
        logger.debug(f"Credential sniffing failed: {e}")

    return creds


def dissect_packet(packet):
    """Full packet dissection for detail view."""
    layers = []
    try:
        pkt = packet
        while pkt:
            layer_name = pkt.__class__.__name__
            fields = {}
            for field in pkt.fields:
                val = pkt.fields[field]
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='replace')
                    except Exception:
                        val = val.hex()
                fields[field] = str(val)
            layers.append((layer_name, fields))
            pkt = pkt.payload if pkt.payload and pkt.payload.__class__.__name__ != "NoPayload" else None
    except Exception as e:
        logger.debug(f"Packet dissection failed: {e}")
    return layers
