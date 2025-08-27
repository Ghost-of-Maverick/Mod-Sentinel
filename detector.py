# detector.py
import binascii
import yaml
import rules_loader
from collections import defaultdict, deque
import time
import re

# ----------------------------
# Estado e configuração
# ----------------------------

rules = []

# Carrega config (pares IP-MAC e listas de clientes/servidores Modbus)
with open("config.yaml", "r") as f:
    _cfg = yaml.safe_load(f) or {}

ALLOWED_MACS = _cfg.get("allowed_macs", {})
MODBUS_CLIENTS = set(_cfg.get("MODBUS_CLIENT", []))
MODBUS_SERVERS = set(_cfg.get("MODBUS_SERVER", []))

# ---- Configuração de DoS (overrides via config.yaml -> dos_detection) ----
_dos_cfg = (_cfg.get("dos_detection") or {})

# janelas (segundos)
SYN_WINDOW_SEC    = int((_dos_cfg.get("syn") or {}).get("window_sec", 1))
ARP_WINDOW_SEC    = int((_dos_cfg.get("arp") or {}).get("window_sec", 1))
UDP21_WINDOW_SEC  = int((_dos_cfg.get("udp21") or {}).get("window_sec", 1))
ICMP_WINDOW_SEC   = int((_dos_cfg.get("icmp") or {}).get("window_sec", 1))

# limiares (contagem por janela)
LIMIAR_SYN_PER_DST           = int((_dos_cfg.get("syn") or {}).get("per_dst", 400))
LIMIAR_SYN_UNIQUE_SRC_PER_DST= int((_dos_cfg.get("syn") or {}).get("unique_src_per_dst", 120))
LIMIAR_ARP_REPLY_PER_TARGET  = int((_dos_cfg.get("arp") or {}).get("per_target", 200))
LIMIAR_UDP21_PER_DST         = int((_dos_cfg.get("udp21") or {}).get("per_dst", 400))
LIMIAR_ICMP_ECHO_PER_DST     = int((_dos_cfg.get("icmp") or {}).get("per_dst", 400))

# cooldown para não “spammar” alertas repetidos (segundos)
ALERT_COOLDOWN_SEC = int((_dos_cfg.get("cooldown_sec") or 3))

# ----------------------------
# Estado para detecção de DoS (sliding windows)
# ----------------------------

# Contadores por destino (SYN 502 / UDP 21 / ICMP Echo)
_syn_by_dst = defaultdict(deque)       # dst_ip -> deque[timestamps]
_udp21_by_dst = defaultdict(deque)     # dst_ip -> deque[timestamps]
_icmp_by_dst = defaultdict(deque)      # dst_ip -> deque[timestamps]

# SYN: também acompanhar fontes distintas por destino
_syn_src_deque_by_dst = defaultdict(deque)      # dst_ip -> deque[(ts, src_ip)]
_syn_src_count_by_dst = defaultdict(lambda: defaultdict(int))  # dst_ip -> {src_ip: count_active_in_window}

# ARP reply flood por alvo (IP anunciado no ARP reply)
_arp_reply_by_target = defaultdict(deque)  # target_ip/pdst/tpa -> deque[timestamps]

# Cooldown de alertas (categoria -> chave -> último_ts)
_last_alert_ts = {
    "syn":   defaultdict(float),
    "udp21": defaultdict(float),
    "icmp":  defaultdict(float),
    "arp":   defaultdict(float),
}

# ----------------------------
# Funções utilitárias
# ----------------------------

def init_detector(rules_file):
    global rules
    rules = rules_loader.load_rules(rules_file)

def _int_to_be_bytes(val: int, size: int) -> bytes:
    return int(val).to_bytes(size, byteorder="big", signed=False)

def _to_int_or_default(s, default=0):
    try:
        if s is None or s == "":
            return default
        return int(str(s), 0)
    except Exception:
        return default

def _hexstr_to_bytes(hex_str: str) -> bytes:
    if not hex_str:
        return b""
    try:
        return bytes.fromhex(hex_str)
    except Exception:
        return b""

def parse_content(content_str: str) -> bytes:
    """
    Converte 'content:"|00 00|"' em b"\x00\x00" e content textual em bytes().
    """
    if not content_str:
        return b""
    if content_str.startswith("|") and content_str.endswith("|"):
        hex_str = content_str.strip("|").replace(" ", "")
        return binascii.unhexlify(hex_str)
    return content_str.encode()

def build_modbus_tcp_bytes(pkt: dict) -> bytes:
    """
    Reconstrói o *payload Modbus/TCP completo* (MBAP + FC + Data) a partir dos campos
    que o packet_sniffer já populou.
    """
    tx_id  = _to_int_or_default(pkt.get("transaction_id"), 0)
    proto  = _to_int_or_default(pkt.get("protocol_id"), 0)
    unit   = _to_int_or_default(pkt.get("unit_id"), 0)
    fc     = _to_int_or_default(pkt.get("function_code"), 0)

    data_bytes = _hexstr_to_bytes(pkt.get("payload", ""))
    mbap_len = 1 + 1 + len(data_bytes)
    mbap  = _int_to_be_bytes(tx_id, 2) + _int_to_be_bytes(proto, 2) + _int_to_be_bytes(mbap_len, 2) + _int_to_be_bytes(unit, 1)
    fc_b  = _int_to_be_bytes(fc, 1)
    return mbap + fc_b + data_bytes

def ip_in_token_list(ip: str, token: str, clients_set, servers_set) -> bool:
    if not token or not ip:
        return False
    t = token.strip()
    if "MODBUS_CLIENT" in t:
        return ip in clients_set
    if "MODBUS_SERVER" in t:
        return ip in servers_set
    ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t))
    if not ips:
        return t.lower() == "any"
    return ip in ips

def header_matches(rule: dict, pkt: dict, clients_set, servers_set) -> bool:
    try:
        proto = rule.get("proto", "").lower()
        if proto and proto != "tcp":
            return False  # só filtramos TCP/502
        src_tok   = rule.get("src", "")
        src_port  = str(rule.get("src_port", "")).lower()
        direction = rule.get("direction", "->")
        dst_tok   = rule.get("dst", "")
        dst_port  = str(rule.get("dst_port", "")).lower()

        pkt_src_ip   = pkt.get("src_ip", "")
        pkt_dst_ip   = pkt.get("dst_ip", "")
        pkt_src_port = str(pkt.get("src_port", "")).lower()
        pkt_dst_port = str(pkt.get("dst_port", "")).lower()

        def port_ok(rule_p, pkt_p):
            if not rule_p or rule_p == "any":
                return True
            return rule_p == pkt_p

        def ip_token_ok(ip, token):
            neg = token.strip().startswith("!")
            core = token.strip()[1:].strip() if neg else token.strip()
            belongs = ip_in_token_list(ip, core, clients_set, servers_set)
            return (not belongs) if neg else belongs or core.lower() == "any"

        if direction == "->":
            if not port_ok(src_port, pkt_src_port) or not port_ok(dst_port, pkt_dst_port):
                return False
            if not ip_token_ok(pkt_src_ip, src_tok):
                return False
            if not ip_token_ok(pkt_dst_ip, dst_tok):
                return False
            return True
        elif direction == "<>":
            ok1 = (
                port_ok(src_port, pkt_src_port) and
                port_ok(dst_port, pkt_dst_port) and
                ip_token_ok(pkt_src_ip, src_tok) and
                ip_token_ok(pkt_dst_ip, dst_tok)
            )
            ok2 = (
                port_ok(src_port, pkt_dst_port) and
                port_ok(dst_port, pkt_src_port) and
                ip_token_ok(pkt_dst_ip, src_tok) and
                ip_token_ok(pkt_src_ip, dst_tok)
            )
            return ok1 or ok2
        else:
            return False
    except Exception:
        return False

# ----------------------------
# Utilitários de DoS
# ----------------------------

def _now_from_pkt(pkt: dict) -> float:
    ts = pkt.get("timestamp") or pkt.get("ts")
    try:
        if ts is not None:
            return float(ts)
    except Exception:
        pass
    return time.time()

def _within_broadcast(ip: str) -> bool:
    if not ip:
        return False
    return ip.endswith(".255") or ip == "255.255.255.255"

def _prune_deque(dq: deque, cutoff: float):
    while dq and dq[0] < cutoff:
        dq.popleft()

def _prune_pair_deque(dq: deque, counts: dict, cutoff: float):
    while dq and dq[0][0] < cutoff:
        _, s = dq.popleft()
        counts[s] -= 1
        if counts[s] <= 0:
            del counts[s]

def _can_alert(cat: str, key: str, now_ts: float) -> bool:
    last = _last_alert_ts.get(cat, {}).get(key, 0.0)
    if now_ts - last >= ALERT_COOLDOWN_SEC:
        _last_alert_ts[cat][key] = now_ts
        return True
    return False

def _is_tcp(pkt: dict) -> bool:
    p = (pkt.get("l4_proto") or pkt.get("protocol") or pkt.get("ip_proto") or "").lower()
    if isinstance(p, int):
        return p == 6
    return "tcp" in str(p)

def _is_udp(pkt: dict) -> bool:
    p = (pkt.get("l4_proto") or pkt.get("protocol") or pkt.get("ip_proto") or "").lower()
    if isinstance(p, int):
        return p == 17
    return "udp" in str(p)

def _is_icmp(pkt: dict) -> bool:
    p = (pkt.get("l4_proto") or pkt.get("protocol") or pkt.get("ip_proto") or "").lower()
    if isinstance(p, int):
        return p == 1
    return "icmp" in str(p)

def _is_arp_reply(pkt: dict) -> (bool, str):
    """
    Retorna (is_reply, target_ip) para ARP. Usa campos comuns: arp_op, pdst, tpa, arp_target_ip.
    """
    op = pkt.get("arp_op") or pkt.get("arp.operation") or pkt.get("arp_opcode")
    # Normalizar op
    if isinstance(op, str):
        op_l = op.lower()
        if op_l in ("2", "reply", "is-at"):
            is_reply = True
        elif op_l in ("1", "request", "who-has"):
            is_reply = False
        else:
            is_reply = False
    else:
        is_reply = (int(op or 0) == 2)

    target_ip = (
        pkt.get("arp_target_ip") or
        pkt.get("arp.tpa") or
        pkt.get("arp_tpa") or
        pkt.get("pdst") or
        pkt.get("dst_ip")  # fallback
    )
    return is_reply, target_ip

def _is_syn(pkt: dict) -> bool:
    """
    Considera SYN sem ACK.
    Aceita tcp_flags como int (bitmask) ou string ('S', 'SA', 'FPA', '0x12', etc).
    """
    flags = pkt.get("tcp_flags") or pkt.get("flags")
    if flags is None:
        return False
    # Tentar int/hex
    if isinstance(flags, int):
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        return syn and not ack
    if isinstance(flags, str):
        f = flags.strip()
        # hexa: '0x12' etc
        try:
            if f.lower().startswith("0x"):
                val = int(f, 16)
                syn = bool(val & 0x02)
                ack = bool(val & 0x10)
                return syn and not ack
        except Exception:
            pass
        # letras: contém 'S' e não contém 'A'
        f_up = f.upper()
        return ("S" in f_up) and ("A" not in f_up)
    return False

# ----------------------------
# Núcleo de deteção
# ----------------------------

def detect(modbus_data):
    """
    Recebe o dicionário montado em packet_sniffer.py e devolve (status, mensagem).
    status=1 se malicioso, 0 caso contrário.
    """
    if not modbus_data:
        return 0, None

    now_ts = _now_from_pkt(modbus_data)

    # ---------- ARP Spoofing (IP->MAC tabelado) ----------
    src_ip  = modbus_data.get("src_ip")
    src_mac = modbus_data.get("src_mac")
    if src_ip and src_mac:
        expected = ALLOWED_MACS.get(src_ip)
        if expected and expected.lower() != str(src_mac).lower():
            if _can_alert("arp", f"spoof:{src_ip}", now_ts):
                return 1, f"[MITM] ARP Spoofing: IP {src_ip} deveria ser {expected}, recebeu {src_mac}"

    dst_ip   = modbus_data.get("dst_ip") or ""
    dst_port = _to_int_or_default(modbus_data.get("dst_port"), 0)
    src_ip   = src_ip or modbus_data.get("ip.src") or ""

    # ---------- DoS 1: TCP SYN flood na porta 502 ----------
    if _is_tcp(modbus_data) and dst_port == 502 and _is_syn(modbus_data):
        dq = _syn_by_dst[dst_ip]
        dq.append(now_ts)
        _prune_deque(dq, now_ts - SYN_WINDOW_SEC)
        count_syn = len(dq)

        # fontes distintas por destino (para rand-source)
        dq2  = _syn_src_deque_by_dst[dst_ip]
        cnts = _syn_src_count_by_dst[dst_ip]
        dq2.append((now_ts, src_ip))
        _prune_pair_deque(dq2, cnts, now_ts - SYN_WINDOW_SEC)
        cnts[src_ip] = cnts.get(src_ip, 0) + 0  # já incrementado acima; esta linha evita KeyError em alguns paths
        unique_src = len(cnts)

        if (count_syn > LIMIAR_SYN_PER_DST or unique_src > LIMIAR_SYN_UNIQUE_SRC_PER_DST):
            if _can_alert("syn", dst_ip, now_ts):
                return 1, (f"[DoS] Possível SYN flood contra {dst_ip}:502 "
                           f"(janela {SYN_WINDOW_SEC}s: SYN={count_syn}, fontes={unique_src})")

    # ---------- DoS 2: ARP reply flood ----------
    is_arp_reply, arp_target = _is_arp_reply(modbus_data)
    if is_arp_reply and arp_target:
        dq = _arp_reply_by_target[arp_target]
        dq.append(now_ts)
        _prune_deque(dq, now_ts - ARP_WINDOW_SEC)
        if len(dq) > LIMIAR_ARP_REPLY_PER_TARGET:
            if _can_alert("arp", arp_target, now_ts):
                return 1, (f"[DoS] Possível ARP spoof/reply flood direcionado a {arp_target} "
                           f"(janela {ARP_WINDOW_SEC}s: replies={len(dq)})")

    # ---------- DoS 3: UDP flood na porta 21 ----------
    if _is_udp(modbus_data) and dst_port == 21:
        dq = _udp21_by_dst[dst_ip]
        dq.append(now_ts)
        _prune_deque(dq, now_ts - UDP21_WINDOW_SEC)
        if len(dq) > LIMIAR_UDP21_PER_DST:
            if _can_alert("udp21", dst_ip, now_ts):
                return 1, (f"[DoS] Possível UDP flood na {dst_ip}:21 "
                           f"(janela {UDP21_WINDOW_SEC}s: UDP={len(dq)})")

    # ---------- DoS 4: ICMP Echo (Smurf/ICMP flood) ----------
    icmp_type = _to_int_or_default(modbus_data.get("icmp_type"), -1)
    is_echo_req = (_is_icmp(modbus_data) and (icmp_type == 8 or str(modbus_data.get("icmp_type")).lower() in ("8", "echo-request")))
    if is_echo_req:
        dq = _icmp_by_dst[dst_ip]
        dq.append(now_ts)
        _prune_deque(dq, now_ts - ICMP_WINDOW_SEC)
        over_rate = len(dq) > LIMIAR_ICMP_ECHO_PER_DST
        to_broadcast = _within_broadcast(dst_ip) or bool(modbus_data.get("is_broadcast"))
        if over_rate or to_broadcast:
            if _can_alert("icmp", dst_ip, now_ts):
                reason = "broadcast" if to_broadcast else f"taxa alta ({len(dq)}/{ICMP_WINDOW_SEC}s)"
                return 1, f"[DoS] Possível Smurf/ICMP flood para {dst_ip} ({reason})"

    # ---------- Reconstruir o buffer Modbus/TCP completo ----------
    mbtcp_bytes = build_modbus_tcp_bytes(modbus_data)

    # ---------- Avaliação das regras ----------
    for rule in rules:
        opts = rule.get("options", {})
        sid  = opts.get("sid", "N/A")
        msg  = opts.get("msg", "[Regra sem mensagem]")

        # 1) Header (proto/src/src_port/direction/dst/dst_port)
        if not header_matches(rule, modbus_data, MODBUS_CLIENTS, MODBUS_SERVERS):
            continue

        # 2) Flow (from_client/to_client/established)
        flow = opts.get("flow")
        if flow:
            is_c2s = str(modbus_data.get("dst_port")) == "502"
            is_s2c = str(modbus_data.get("src_port")) == "502"
            if ("from_client" in flow and not is_c2s) or \
               ("to_client"   in flow and not is_s2c) or \
               ("established" in flow and not (is_c2s or is_s2c)):
                continue

        # 3) Condições de conteúdo (agora sobre o buffer MBTCP)
        all_match = True

        # dsize
        if "dsize" in opts:
            dsize = opts["dsize"]
            if ">" in dsize:
                try:
                    min_size = int(dsize.strip(">").strip())
                    if len(mbtcp_bytes) <= min_size:
                        all_match = False
                except Exception:
                    all_match = False
            else:
                try:
                    expected_size = int(dsize)
                    if len(mbtcp_bytes) != expected_size:
                        all_match = False
                except Exception:
                    all_match = False

        # contents
        if all_match and "contents" in opts:
            for c in opts["contents"]:
                try:
                    content = parse_content(c.get("content", ""))
                    offset  = int(c.get("offset", 0))
                    depth   = int(c.get("depth", max(0, len(mbtcp_bytes) - offset)))
                    if offset < 0 or offset > len(mbtcp_bytes):
                        all_match = False
                        break
                    window = mbtcp_bytes[offset: offset + depth]
                    if content not in window:
                        all_match = False
                        break
                except Exception:
                    all_match = False
                    break

        # pcre
        if all_match and "pcre" in opts:
            try:
                pcre = opts["pcre"]
                body = pcre.strip()
                if body.startswith("/"):
                    body = body[1:]
                if body.endswith("/iAR"):
                    body = body[:-4]
                elif body.endswith("/"):
                    body = body[:-1]
                pattern = re.compile(body.encode(), re.DOTALL)
                if not pattern.search(mbtcp_bytes):
                    all_match = False
            except Exception:
                all_match = False

        # byte_test
        if all_match and "byte_test" in opts:
            try:
                bt = opts["byte_test"]
                size     = int(bt["size"])
                operator = bt["operator"]
                value    = int(bt["value"], 0)
                offset   = int(bt["offset"])
                data_val = int.from_bytes(mbtcp_bytes[offset:offset + size], "big")
                if   operator == ">=" and not (data_val >= value): all_match = False
                elif operator == "==" and not (data_val == value): all_match = False
                elif operator == "<=" and not (data_val <= value): all_match = False
            except Exception:
                all_match = False

        # byte_jump / isdataat
        if all_match and "byte_jump" in opts:
            try:
                bj = opts["byte_jump"]
                jsize   = int(bj["size"])
                joffset = int(bj["offset"])
                relative = bj.get("relative", False)
                jump_val = int.from_bytes(mbtcp_bytes[joffset:joffset + jsize], "big")
                idx = joffset + jsize + jump_val if relative else jump_val
                if idx < 0 or idx > len(mbtcp_bytes):
                    all_match = False
                _jump_index_cache = idx
            except Exception:
                all_match = False
                _jump_index_cache = None
        else:
            _jump_index_cache = None

        if all_match and "isdataat" in opts:
            try:
                ida = opts["isdataat"]
                index    = int(ida["index"])
                relative = ida.get("relative", False)
                if relative and _jump_index_cache is not None:
                    check_pos = _jump_index_cache + index
                else:
                    check_pos = index
                if check_pos < 0 or check_pos >= len(mbtcp_bytes):
                    all_match = False
            except Exception:
                all_match = False

        if all_match:
            return 1, f"[SID {sid}] {msg}"

    # Nenhuma regra nem gatilho de DoS
    return 0, None
