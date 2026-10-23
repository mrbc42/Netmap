"""Port lists and well-known service names."""

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 81: "http-alt", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    179: "bgp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    500: "isakmp", 515: "lpd", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 853: "dns-over-tls", 873: "rsync",
    902: "vmware-auth", 993: "imaps", 995: "pop3s", 1080: "socks",
    1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 1900: "upnp", 2049: "nfs", 2082: "cpanel", 2375: "docker",
    2376: "docker-tls", 3000: "http-dev", 3128: "squid", 3306: "mysql",
    3389: "rdp", 3478: "stun", 3689: "daap", 4443: "https-alt", 5000: "upnp/http",
    5001: "https-alt", 5060: "sip", 5222: "xmpp", 5353: "mdns", 5357: "wsdapi",
    5432: "postgresql", 5555: "adb", 5900: "vnc", 5985: "winrm", 6379: "redis",
    6443: "kubernetes", 6668: "tuya", 7000: "airplay", 7547: "tr-069",
    8000: "http-alt", 8006: "proxmox", 8008: "http-alt", 8009: "chromecast",
    8080: "http-proxy", 8081: "http-alt", 8123: "home-assistant",
    8200: "vault", 8291: "winbox", 8443: "https-alt", 8554: "rtsp-alt",
    8728: "mikrotik-api", 8883: "mqtt-tls", 8888: "http-alt", 9000: "http-alt",
    9090: "prometheus", 9100: "jetdirect", 9200: "elasticsearch",
    9443: "https-alt", 10000: "webmin", 11211: "memcached", 27017: "mongodb",
    32400: "plex", 49152: "upnp", 62078: "iphone-sync",
}

# Roughly the ports that matter on a typical LAN, ordered by usefulness.
TOP_PORTS = [
    80, 443, 22, 445, 139, 135, 53, 21, 23, 25, 3389, 8080, 8443, 3306, 5432,
    161, 631, 9100, 515, 554, 8554, 548, 2049, 111, 5000, 5001, 5900, 8000,
    8008, 8009, 8081, 8123, 8888, 9000, 9090, 1883, 8883, 62078, 7000, 32400,
    5353, 1900, 49152, 5357, 3000, 6379, 27017, 9200, 11211, 2375, 6443,
    8006, 10000, 8291, 8728, 7547, 110, 143, 993, 995, 587, 465, 389, 636,
    88, 1433, 1521, 5985, 902, 873, 3128, 1080, 4443, 9443, 5060, 81, 6668,
    3689, 5555, 1194, 1723, 500, 179, 119, 69, 2082, 8200, 853,
]

# Ports used to decide whether a host is alive when ICMP is unavailable.
# A RST (connection refused) is as good as an open port for liveness.
PROBE_PORTS = [80, 443, 22, 445, 139, 53, 3389, 8080, 62078, 5000, 7000, 9100, 554, 8009]

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8888, 9000, 9090, 10000, 32400}
HTTPS_PORTS = {443, 4443, 5001, 8006, 8443, 9443}


def parse_ports(spec: str) -> list[int]:
    """Parse e.g. 'top', 'top200', 'all', '1-1024', or mixes like 'top,2222,8000-8100'."""
    ports: set[int] = set()
    for part in spec.lower().replace(" ", "").split(","):
        if part in ("top", "default"):
            ports.update(TOP_PORTS)
        elif part.startswith("top"):
            extra = [p for p in sorted(SERVICES) if p not in TOP_PORTS] + [p for p in range(1, 1025)]
            ports.update(list(dict.fromkeys(TOP_PORTS + extra))[: int(part[3:])])
        elif part == "all":
            ports.update(range(1, 65536))
        elif "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)
