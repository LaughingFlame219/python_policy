from utils import normalize

# ============================================================
# Built‑in FortiGate services (full protocol definitions)
# ============================================================

BUILTIN_SERVICES = {
    "ALL": {
        "protocol_number": None,
        "tcp": [(1, 65535)],
        "udp": [(1, 65535)],
        "icmp": None,
        "any": True,
    },
    "ALL_TCP": {
        "protocol_number": 6,
        "tcp": [(1, 65535)],
        "udp": [],
        "icmp": None,
        "any": True,
    },
    "ALL_UDP": {
        "protocol_number": 17,
        "tcp": [],
        "udp": [(1, 65535)],
        "icmp": None,
        "any": True,
    },
    "ALL_ICMP": {
        "protocol_number": 1,
        "tcp": [],
        "udp": [],
        "icmp": (None, None),
        "any": False,   # 🔥 ICMP専用なので ANY にしない
    },
    "DNS": {
        "protocol_number": None,
        "tcp": [(53, 53)],
        "udp": [(53, 53)],
        "icmp": None,
        "any": False,
    },
    "NTP": {
        "protocol_number": 17,
        "tcp": [],
        "udp": [(123, 123)],
        "icmp": None,
        "any": False,
    },
    "SMTP": {
        "protocol_number": 6,
        "tcp": [(25, 25)],
        "udp": [],
        "icmp": None,
        "any": False,
    },
    "HTTP": {
        "protocol_number": 6,
        "tcp": [(80, 80)],
        "udp": [],
        "icmp": None,
        "any": False,
    },
    "HTTPS": {
        "protocol_number": 6,
        "tcp": [(443, 443)],
        "udp": [],
        "icmp": None,
        "any": False,
    },
    "SSH": {
        "protocol_number": 6,
        "tcp": [(22, 22)],
        "udp": [],
        "icmp": None,
        "any": False,
    },
}


# ============================================================
# portrange parser (FortiGate 7.x fully supported)
# ============================================================

def parse_portrange(parts):
    ranges = []

    for p in parts:
        # 513:512 → ["513", "512"]
        if ":" in p:
            sub = p.split(":")
            for sp in sub:
                if "-" in sp:
                    s, e = sp.split("-")
                    s, e = int(s), int(e)
                    if s > e:
                        s, e = e, s
                    ranges.append((s, e))
                else:
                    v = int(sp)
                    ranges.append((v, v))
            continue

        # 8080-8090 → (8080, 8090)
        if "-" in p:
            s, e = p.split("-")
            s, e = int(s), int(e)
            if s > e:
                s, e = e, s
            ranges.append((s, e))
            continue

        # 単一ポート
        v = int(p)
        ranges.append((v, v))

    return ranges


# ============================================================
# Custom Service Parser (FortiGate 7.x fully supported)
# ============================================================

def parse_service_custom(lines):
    service_objects = {}
    current_name = None

    protocol_number = None
    tcp_ranges = []
    udp_ranges = []
    icmp_type = None
    icmp_code = None
    any_flag = False

    in_section = False

    for ln in lines:
        ln = ln.strip()

        if "config firewall service custom" in ln:
            in_section = True
            continue

        if in_section and ln.startswith("edit"):
            current_name = normalize(ln.replace("edit", ""))
            protocol_number = None
            tcp_ranges = []
            udp_ranges = []
            icmp_type = None
            icmp_code = None
            any_flag = False
            continue

        # 🔥 名前から ANY を判定（ALL_ICMP は除外）
        if in_section and current_name:
            name = current_name.upper()
            if name in ("ALL", "ALL_TCP", "ALL_UDP") or "ANY" in name:
                any_flag = True

        # protocol-number
        if in_section and ln.startswith("set protocol-number"):
            try:
                protocol_number = int(ln.replace("set protocol-number", "").strip())
            except:
                protocol_number = None
            continue

        # protocol (TCP/UDP/ICMP)
        if in_section and ln.startswith("set protocol "):
            proto = ln.replace("set protocol", "").strip().upper()
            if proto == "TCP":
                protocol_number = 6
            elif proto == "UDP":
                protocol_number = 17
            elif proto == "ICMP":
                protocol_number = 1
            continue

        # TCP portrange
        if in_section and ln.startswith("set tcp-portrange"):
            parts = ln.replace("set tcp-portrange", "").strip().split()
            tcp_ranges = parse_portrange(parts)
            continue

        # UDP portrange
        if in_section and ln.startswith("set udp-portrange"):
            parts = ln.replace("set udp-portrange", "").strip().split()
            udp_ranges = parse_portrange(parts)
            continue

        # ICMP
        if in_section and ln.startswith("set icmptype"):
            icmp_type = ln.replace("set icmptype", "").strip()
            continue

        if in_section and ln.startswith("set icmpcode"):
            icmp_code = ln.replace("set icmpcode", "").strip()
            continue

        # next → finalize
        if in_section and ln == "next":
            if current_name:
                # portrange が 1–65535 の場合は ANY とみなす
                for s, e in tcp_ranges + udp_ranges:
                    if s == 1 and e == 65535:
                        any_flag = True

                service_objects[current_name] = {
                    "protocol_number": protocol_number,
                    "tcp": tcp_ranges.copy(),
                    "udp": udp_ranges.copy(),
                    "icmp": (icmp_type, icmp_code) if icmp_type else None,
                    "any": any_flag,
                }
            current_name = None
            continue

        if in_section and ln == "end":
            in_section = False
            continue

    # 🔥 built‑in services をマージ（ユーザー定義が優先）
    for name, obj in BUILTIN_SERVICES.items():
        if name not in service_objects:
            service_objects[name] = obj

    return service_objects


# ============================================================
# Service Group Parser
# ============================================================

def parse_service_group(lines):
    service_groups = {}
    current_name = None
    members = []

    in_section = False

    for ln in lines:
        ln = ln.strip()

        if "config firewall service group" in ln:
            in_section = True
            continue

        if in_section and ln.startswith("edit"):
            current_name = normalize(ln.replace("edit", ""))
            members = []
            continue

        if in_section and ln.startswith("set member"):
            parts = ln.replace("set member", "").strip().split()
            members = [normalize(p) for p in parts]
            continue

        if in_section and ln == "next":
            if current_name:
                service_groups[current_name] = members.copy()
            current_name = None
            members = []
            continue

        if in_section and ln == "end":
            in_section = False
            continue

    return service_groups


# ============================================================
# Main Entry
# ============================================================

def parse_services(lines):
    service_objects = parse_service_custom(lines)
    service_groups = parse_service_group(lines)
    return service_objects, service_groups
