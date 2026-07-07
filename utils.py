import ipaddress
import fnmatch

# ================================
# IP / CIDR 判定
# ================================

def parse_subnet(ip_str, mask_str):
    """FortiGateの subnet を ip_network に変換"""
    try:
        # 例: 10.0.0.0 255.255.255.0 → 10.0.0.0/24
        network = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
        return network
    except Exception:
        return None


def ip_in_network(ip_str, network):
    """単一IPがネットワークに含まれるか判定"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip in network
    except Exception:
        return False


def network_overlap(net1, net2):
    """ネットワーク同士が重複しているか判定"""
    try:
        return net1.overlaps(net2)
    except Exception:
        return False


# ================================
# FQDN 判定
# ================================

def fqdn_match(fqdn_pattern, fqdn_value):
    """
    FQDN のワイルドカード一致判定
    *.google.com → mail.google.com は True
    """
    return fnmatch.fnmatch(fqdn_value, fqdn_pattern)


# ================================
# サービスのポート範囲判定
# ================================

def port_range_overlap(range1, range2):
    """
    ポート範囲の重複判定
    range1 = (start1, end1)
    range2 = (start2, end2)
    """
    s1, e1 = range1
    s2, e2 = range2
    return not (e1 < s2 or e2 < s1)


def any_port():
    """ANYポートを表現"""
    return [(1, 65535)]


# ================================
# 文字列正規化
# ================================

def normalize(s):
    """FortiGateの文字列を正規化"""
    if s is None:
        return ""
    return s.strip().replace('"', '')
