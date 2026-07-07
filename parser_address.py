from utils import normalize
import ipaddress

# ============================================================
# Address パーサー（VDOM内部対応）
# ============================================================

def parse_address_section(lines):
    address_objects = {}
    current_name = None
    current_type = None
    subnet_ip = None
    subnet_mask = None
    fqdn_value = None
    single_ip = None

    in_section = False

    for ln in lines:
        ln = ln.strip()

        if "config firewall address" in ln:
            in_section = True
            continue

        if in_section and ln.startswith("edit"):
            current_name = normalize(ln.replace("edit", "").strip())
            current_type = None
            subnet_ip = None
            subnet_mask = None
            fqdn_value = None
            single_ip = None
            continue

        if in_section and ln.startswith("set type"):
            current_type = normalize(ln.replace("set type", "").strip())
            continue

        if in_section and ln.startswith("set subnet"):
            parts = ln.replace("set subnet", "").strip().split()
            if len(parts) >= 2:
                subnet_ip = parts[0]
                subnet_mask = parts[1]
            elif len(parts) == 1:
                subnet_ip = parts[0]
            continue

        if in_section and ln.startswith("set ip "):
            single_ip = ln.replace("set ip", "").strip()
            continue

        if in_section and ln.startswith("set fqdn"):
            fqdn_value = normalize(ln.replace("set fqdn", "").strip())
            continue

        if in_section and ln == "next":
            if current_name:
                if current_name.lower() == "all":
                    address_objects[current_name] = {"type": "all"}

                elif current_type == "fqdn":
                    address_objects[current_name] = {
                        "type": "fqdn",
                        "fqdn": fqdn_value
                    }

                elif current_type == "dynamic":
                    address_objects[current_name] = {"type": "dynamic"}

                elif single_ip:
                    try:
                        ip = ipaddress.ip_address(single_ip)
                        address_objects[current_name] = {
                            "type": "subnet",
                            "network": f"{ip}/{ip.max_prefixlen}"
                        }
                    except Exception:
                        address_objects[current_name] = {"type": "unknown"}

                elif subnet_ip:
                    try:
                        # 🔥 FortiGate の "IP MASK" を CIDR に変換
                        if subnet_mask:
                            net = ipaddress.ip_network(f"{subnet_ip}/{subnet_mask}", strict=False)
                        else:
                            net = ipaddress.ip_network(subnet_ip, strict=False)
                        address_objects[current_name] = {
                            "type": "subnet",
                            "network": str(net)
                        }
                    except Exception:
                        address_objects[current_name] = {"type": "unknown"}

                else:
                    address_objects[current_name] = {"type": "unknown"}

            current_name = None
            continue

        if in_section and ln == "end":
            in_section = False
            continue

    return address_objects


# ============================================================
# AddrGrp パーサー（VDOM内部対応）
# ============================================================

def parse_addrgrp_section(lines):
    address_groups = {}
    current_name = None
    members = []

    in_section = False

    for ln in lines:
        ln = ln.strip()

        if "config firewall addrgrp" in ln:
            in_section = True
            continue

        if in_section and ln.startswith("edit"):
            current_name = normalize(ln.replace("edit", "").strip())
            members = []
            continue

        if in_section and ln.startswith("set member"):
            parts = ln.replace("set member", "").strip().split()
            members = [normalize(p) for p in parts]
            continue

        if in_section and ln == "next":
            if current_name:
                address_groups[current_name] = members.copy()
            current_name = None
            members = []
            continue

        if in_section and ln == "end":
            in_section = False
            continue

    return address_groups


# ============================================================
# ヘルパー: address_objects に無い場合はリテラル CIDR/IP として解釈
# ============================================================

def _get_network_from_obj(name, address_objects):
    obj = address_objects.get(name)
    if obj:
        t = obj.get("type")
        if t == "subnet":
            try:
                return "subnet", ipaddress.ip_network(obj["network"], strict=False)
            except Exception:
                return None, None
        if t == "fqdn":
            return "fqdn", obj.get("fqdn")
        if t == "dynamic":
            return "dynamic", name
        if t == "all":
            return "all", None

    try:
        net = ipaddress.ip_network(name, strict=False)
        if net.prefixlen == net.max_prefixlen:
            return "host", ipaddress.ip_address(net.network_address)
        return "subnet", net
    except Exception:
        pass

    try:
        ip = ipaddress.ip_address(name)
        return "host", ip
    except Exception:
        pass

    return None, None


# ============================================================
# アドレス包含判定（下位が上位に完全包含されているか）
# ============================================================

def single_address_inclusion(lower, upper, address_objects, address_groups=None):
    if upper == "all":
        return True
    if lower == "all":
        return False

    typeL, valL = _get_network_from_obj(lower, address_objects)
    typeU, valU = _get_network_from_obj(upper, address_objects)

    if typeL is None or typeU is None:
        return False

    if typeL == "subnet" and typeU == "subnet":
        try:
            return valL.subnet_of(valU)
        except Exception:
            return False

    if typeL == "host" and typeU == "subnet":
        try:
            return valL in valU
        except Exception:
            return False

    if typeL == "host" and typeU == "host":
        return valL == valU

    if typeL == "fqdn" and typeU == "fqdn":
        return valL == valU

    if typeL == "dynamic" and typeU == "dynamic":
        return lower == upper

    if typeU == "all":
        return True
    if typeL == "all":
        return False

    return False


def address_inclusion_list(lower_list, upper_list, address_objects, address_groups):
    def expand(addr):
        if addr in address_groups:
            return address_groups[addr]
        return [addr]

    expanded_lower = []
    for a in lower_list:
        expanded_lower.extend(expand(a))

    expanded_upper = []
    for b in upper_list:
        expanded_upper.extend(expand(b))

    for l in expanded_lower:
        if not any(single_address_inclusion(l, u, address_objects, address_groups) for u in expanded_upper):
            return False

    return True


# ============================================================
# メインエントリ
# ============================================================

def parse_addresses(lines):
    address_objects = parse_address_section(lines)
    address_groups = parse_addrgrp_section(lines)
    return address_objects, address_groups
