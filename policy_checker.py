"""
parser_policy_full.py
FortiGate コンフィグ解析：アドレス/サービスパーサー + ポリシー重複判定（デバッグなし最終版）
"""

import ipaddress
import re

DEBUG = False  # デバッグ無効化

# -------------------------
# ユーティリティ
# -------------------------
def normalize(s):
    if s is None:
        return None
    s = s.strip()
    s = s.replace('\u200b', '')
    s = s.replace('\u200c', '')
    s = s.replace('\u200d', '')
    s = s.replace('\u3000', '')
    s = s.replace('\t', ' ')
    s = s.replace('\r', '')
    s = s.replace('\n', '')
    s = re.sub(r'\s+', ' ', s)
    s = s.strip('"').strip("'")
    return s

def to_int_safe(x):
    try:
        if x is None:
            return None
        if isinstance(x, int):
            return x
        if isinstance(x, str) and x.strip()=="":
            return None
        return int(str(x).strip())
    except:
        return None

def repr_short(x):
    try:
        return repr(x)
    except:
        return str(x)

# -------------------------
# portrange parser
# -------------------------
def parse_portrange(parts):
    ranges = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if ":" in p:
            for sp in p.split(":"):
                sp = sp.strip()
                if "-" in sp:
                    s,e = sp.split("-",1)
                    try:
                        s_i,e_i = int(s),int(e)
                    except:
                        continue
                    if s_i>e_i: s_i,e_i = e_i,s_i
                    ranges.append((s_i,e_i))
                else:
                    try:
                        v = int(sp)
                        ranges.append((v,v))
                    except:
                        continue
            continue
        if "-" in p:
            s,e = p.split("-",1)
            try:
                s_i,e_i = int(s),int(e)
            except:
                continue
            if s_i>e_i: s_i,e_i = e_i,s_i
            ranges.append((s_i,e_i))
            continue
        try:
            v = int(p)
            ranges.append((v,v))
        except:
            continue
    return ranges

# -------------------------
# Service Custom Parser
# -------------------------
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

    for raw_ln in lines:
        ln = raw_ln.rstrip("\r\n")
        ln_norm = normalize(ln)

        if "config firewall service custom" in ln_norm:
            in_section = True
            continue

        if in_section and ln_norm.startswith("edit"):
            current_name = normalize(ln_norm.replace("edit","",1).strip())
            protocol_number = None
            tcp_ranges = []
            udp_ranges = []
            icmp_type = None
            icmp_code = None
            any_flag = False
            continue

        if in_section and "set protocol" in ln_norm:
            proto = ln_norm.split("set protocol", 1)[1].strip().upper()
            proto = normalize(proto)
            protocol_number = {"TCP":6,"UDP":17,"ICMP":1,"ICMP6":58}.get(proto, None)
            continue

        if in_section and ln_norm.startswith("set tcp-portrange"):
            parts = ln_norm.replace("set tcp-portrange","",1).strip().split()
            tcp_ranges = parse_portrange(parts)
            continue

        if in_section and ln_norm.startswith("set udp-portrange"):
            parts = ln_norm.replace("set udp-portrange","",1).strip().split()
            udp_ranges = parse_portrange(parts)
            continue

        if in_section and ln_norm.startswith("set icmptype"):
            icmp_type = ln_norm.replace("set icmptype","",1).strip()
            if icmp_type == "":
                icmp_type = None
            continue

        if in_section and ln_norm.startswith("set icmpcode"):
            icmp_code = ln_norm.replace("set icmpcode","",1).strip()
            if icmp_code == "":
                icmp_code = None
            continue

        if in_section and ln_norm.lower().startswith("next"):
            if current_name and current_name.upper() == "ALL_ICMP":
                protocol_number = 1
                icmp = (None, None)
                tcp_ranges = []
                udp_ranges = []
            elif current_name and current_name.upper() == "ALL_ICMP6":
                protocol_number = 58
                icmp = (None, None)
                tcp_ranges = []
                udp_ranges = []
            else:
                if protocol_number in (1,58):
                    if icmp_type is None:
                        icmp = (None, None)
                    else:
                        icmp = (icmp_type, icmp_code)
                else:
                    icmp = None

            service_objects[current_name] = {
                "protocol_number": protocol_number,
                "tcp": tcp_ranges.copy(),
                "udp": udp_ranges.copy(),
                "icmp": icmp,
                "any": any_flag,
            }
            current_name = None
            continue

        if in_section and ln_norm.lower().startswith("end"):
            in_section = False
            continue

    return service_objects

# -------------------------
# Service Group Parser
# -------------------------
def parse_service_group(lines):
    service_groups = {}
    current_name = None
    members = []
    in_section = False

    for raw_ln in lines:
        ln = raw_ln.rstrip("\r\n")
        ln_norm = normalize(ln)

        if "config firewall service group" in ln_norm:
            in_section = True
            continue

        if in_section and ln_norm.startswith("edit"):
            current_name = normalize(ln_norm.replace("edit","",1).strip())
            members = []
            continue

        if in_section and ln_norm.startswith("set member"):
            parts = ln_norm.replace("set member","",1).strip().split()
            members = [normalize(p) for p in parts]
            continue

        if in_section and ln_norm.lower().startswith("next"):
            if current_name:
                service_groups[current_name] = members.copy()
            current_name = None
            members = []
            continue

        if in_section and ln_norm.lower().startswith("end"):
            in_section = False
            continue

    return service_groups

def parse_services(lines):
    return parse_service_custom(lines), parse_service_group(lines)

# -------------------------
# Policy Parser
# -------------------------
class Policy:
    def __init__(self, edit_id, srcintf, dstintf, srcaddr, dstaddr, service, action):
        self.edit_id = edit_id
        self.srcintf = srcintf
        self.dstintf = dstintf
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr
        self.service = service
        self.action = action

def parse_policies(lines):
    policies = []
    in_section = False
    edit_id = None
    srcintf = []
    dstintf = []
    srcaddr = []
    dstaddr = []
    service = []
    action = None

    for raw_ln in lines:
        s = normalize(raw_ln)
        if s is None:
            continue

        if s.startswith("config firewall policy"):
            in_section = True
            continue

        if in_section and s.startswith("edit "):
            edit_id = normalize(s.replace("edit","",1).strip())
            srcintf = []
            dstintf = []
            srcaddr = []
            dstaddr = []
            service = []
            action = None
            continue

        if in_section and s.startswith("set srcintf"):
            srcintf = [normalize(p) for p in s.replace("set srcintf","",1).strip().split()]
            continue

        if in_section and s.startswith("set dstintf"):
            dstintf = [normalize(p) for p in s.replace("set dstintf","",1).strip().split()]
            continue

        if in_section and s.startswith("set srcaddr"):
            srcaddr = [normalize(p) for p in s.replace("set srcaddr","",1).strip().split()]
            continue

        if in_section and s.startswith("set dstaddr"):
            dstaddr = [normalize(p) for p in s.replace("set dstaddr","",1).strip().split()]
            continue

        if in_section and s.startswith("set service"):
            service = [normalize(p) for p in s.replace("set service","",1).strip().split()]
            continue

        if in_section and s.startswith("set action"):
            action = normalize(s.replace("set action","",1).strip())
            continue

        if in_section and s.lower().startswith("next"):
            policies.append(Policy(edit_id, srcintf, dstintf, srcaddr, dstaddr, service, action))
            continue

        if in_section and s.lower().startswith("end"):
            in_section = False
            continue

    return policies

# -------------------------
# Address Inclusion
# -------------------------
def _addr_to_network(name, address_objects):
    if name is None:
        return None, None
    obj = address_objects.get(name)
    if obj:
        t = obj.get("type")
        if t == "subnet":
            try:
                return "subnet", ipaddress.ip_network(obj["network"], strict=False)
            except:
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
    except:
        pass

    try:
        ip = ipaddress.ip_address(name)
        return "host", ip
    except:
        pass

    return None, None

def single_address_inclusion(lower, upper, address_objects, address_groups):
    if upper == "all":
        return True
    if lower == "all":
        return False

    typeL, valL = _addr_to_network(lower, address_objects)
    typeU, valU = _addr_to_network(upper, address_objects)

    if typeL is None or typeU is None:
        return False

    if typeL == "subnet" and typeU == "subnet":
        try:
            return valL.subnet_of(valU)
        except:
            return False

    if typeL == "host" and typeU == "subnet":
        try:
            return valL in valU
        except:
            return False

    if typeL == "host" and typeU == "host":
        return valL == valU

    if typeL == "fqdn" and typeU == "fqdn":
        return valL == valU

    if typeL == "dynamic" and typeU == "dynamic":
        return lower == upper

    return False

def address_inclusion_list(lower_list, upper_list, address_objects, address_groups):
    def expand(addr):
        return address_groups.get(addr, [addr])

    expanded_lower = []
    for a in lower_list:
        expanded_lower.extend(expand(a))

    expanded_upper = []
    for b in upper_list:
        expanded_upper.extend(expand(b))

    return all(
        any(single_address_inclusion(l, u, address_objects, address_groups) for u in expanded_upper)
        for l in expanded_lower
    )

# -------------------------
# Service Overlap
# -------------------------
def service_overlap(srvA, srvB, service_objects, service_groups):
    def expand(srv):
        return service_groups.get(srv, [srv])

    listA = expand(srvA)
    listB = expand(srvB)

    for a in listA:
        for b in listB:
            if single_service_overlap(a, b, service_objects):
                return True
    return False

def single_service_overlap(a, b, service_objects):
    objA = service_objects.get(a)
    objB = service_objects.get(b)

    if objA is None or objB is None:
        return a == b

    pa = to_int_safe(objA.get("protocol_number"))
    pb = to_int_safe(objB.get("protocol_number"))

    if pa is not None and pb is not None and pa != pb:
        return False

    if objA.get("any") or objB.get("any"):
        return True

    icmpA = objA.get("icmp")
    icmpB = objB.get("icmp")

    if pa in (1,58) and icmpA is None:
        icmpA = (None, None)
    if pb in (1,58) and icmpB is None:
        icmpB = (None, None)

    if icmpA is not None and icmpB is not None:
        return icmpA == icmpB

    return False

# -------------------------
# Policy Overlap（完全包含）
# -------------------------
def check_policy_overlap(policies, address_objects, address_groups, service_objects, service_groups):
    result = {}
    policies_sorted = sorted(policies, key=lambda p: int(p.edit_id))

    for i, pA in enumerate(policies_sorted):
        overlaps = []
        for j in range(i):
            pB = policies_sorted[j]

            if pA.srcintf != pB.srcintf:
                continue
            if pA.dstintf != pB.dstintf:
                continue
            if pA.action != pB.action:
                continue

            if not address_inclusion_list(pA.srcaddr, pB.srcaddr, address_objects, address_groups):
                continue

            if not address_inclusion_list(pA.dstaddr, pB.dstaddr, address_objects, address_groups):
                continue

            svc_ok = False
            for a in pA.service:
                for b in pB.service:
                    if service_overlap(a, b, service_objects, service_groups):
                        svc_ok = True
                        break
                if svc_ok:
                    break

            if not svc_ok:
                continue

            overlaps.append(pB.edit_id)

        result[pA.edit_id] = overlaps

    return result

# -------------------------
# 依存関数
# -------------------------
def port_range_overlap(r1, r2):
    try:
        s1,e1 = r1
        s2,e2 = r2
        return not (e1 < s2 or e2 < s1)
    except:
        return False
