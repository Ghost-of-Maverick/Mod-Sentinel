import binascii
import yaml
import rules_loader

# ----------------------------
# Estado e configuração
# ----------------------------

rules = []
modbus_state = {}   # Guarda pedidos Modbus por (src_ip, dst_ip, fc)

# Carrega config (pares IP-MAC e listas de clientes/servidores Modbus)
with open("config.yaml", "r") as f:
    _cfg = yaml.safe_load(f) or {}

ALLOWED_MACS = _cfg.get("allowed_macs", {})
MODBUS_CLIENTS = set(_cfg.get("MODBUS_CLIENT", []))
MODBUS_SERVERS = set(_cfg.get("MODBUS_SERVER", []))


def init_detector(rules_file):
    """
    Carrega as regras através do rules_loader (não alterado).
    """
    global rules
    rules = rules_loader.load_rules(rules_file)


# ----------------------------
# Funções utilitárias
# ----------------------------

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
    Converte 'content:"|00 00|"' em b"\\x00\\x00" e content textual em bytes().
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

    - MBAP:
        0-1: Transaction ID     (2 bytes)
        2-3: Protocol ID        (2 bytes)
        4-5: Length             (2 bytes) = 1 (UnitID) + 1 (FC) + len(Data)
        6  : Unit ID            (1 byte)
    - FC: Function Code        (1 byte)
    - Data:                     (resto)

    O teu packet_sniffer coloca em `payload` apenas os data bytes *após* o FC.
    Aqui reconstruímos tudo para que as regras com offset funcionem corretamente.
    """
    # Extrair valores (strings → int)
    tx_id  = _to_int_or_default(pkt.get("transaction_id"), 0)
    proto  = _to_int_or_default(pkt.get("protocol_id"), 0)
    unit   = _to_int_or_default(pkt.get("unit_id"), 0)
    fc     = _to_int_or_default(pkt.get("function_code"), 0)

    data_bytes = _hexstr_to_bytes(pkt.get("payload", ""))
    # Comprimento = UnitID(1) + FC(1) + len(data)
    mbap_len = 1 + 1 + len(data_bytes)

    # Montar MBAP + FC + Data
    mbap  = _int_to_be_bytes(tx_id, 2) + _int_to_be_bytes(proto, 2) + _int_to_be_bytes(mbap_len, 2) + _int_to_be_bytes(unit, 1)
    fc_b  = _int_to_be_bytes(fc, 1)
    return mbap + fc_b + data_bytes


def ip_in_token_list(ip: str, token: str, clients_set, servers_set) -> bool:
    """
    Decide se o IP 'ip' pertence ao conjunto descrito por 'token' (src/dst do header):

    - token pode conter:
        - lista de IPs (separador vírgula ou pipe)
        - "$MODBUS_CLIENT" / "$MODBUS_SERVER" (rules_loader pode não ter substituído em alguns casos)
        - negação '!' (trataremos fora, nesta função devolvemos pertença simples)
    - devolve True se 'ip' está em 'token'; False caso contrário.

    Nota: esta função NÃO trata da negação; quem chama é que decide se inverte o resultado.
    """
    if not token or not ip:
        return False

    t = token.strip()

    # Placeholder explícito
    if "MODBUS_CLIENT" in t:
        return ip in clients_set
    if "MODBUS_SERVER" in t:
        return ip in servers_set

    # Extrair IPs que apareçam no token
    # aceitamos separadores ',', '||' ou espaço
    import re
    ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t))
    if not ips:
        # Caso "any"
        if t.lower() == "any":
            return True
        return False

    return ip in ips


def header_matches(rule: dict, pkt: dict, clients_set, servers_set) -> bool:
    """
    Emula o header da regra (proto/src/src_port/direction/dst/dst_port) para o pacote.

    Suporta:
      - '->' e '<>' (bidirecional)
      - portas 'any' ou numéricas
      - negação de fonte/destino com '!' (e.g., !$MODBUS_CLIENT)
      - 'any' em IPs

    Isto completa o que já fazias com 'flow' nas opções.
    """
    try:
        proto = rule.get("proto", "").lower()
        if proto and proto != "tcp":
            return False  # só estamos a filtrar TCP/502

        src_tok   = rule.get("src", "")
        src_port  = str(rule.get("src_port", "")).lower()
        direction = rule.get("direction", "->")
        dst_tok   = rule.get("dst", "")
        dst_port  = str(rule.get("dst_port", "")).lower()

        pkt_src_ip   = pkt.get("src_ip", "")
        pkt_dst_ip   = pkt.get("dst_ip", "")
        pkt_src_port = str(pkt.get("src_port", "")).lower()
        pkt_dst_port = str(pkt.get("dst_port", "")).lower()

        # Portas
        def port_ok(rule_p, pkt_p):
            if not rule_p or rule_p == "any":
                return True
            return rule_p == pkt_p

        # Negação (só no token, não em porta)
        def ip_token_ok(ip, token):
            neg = token.strip().startswith("!")
            core = token.strip()[1:].strip() if neg else token.strip()
            belongs = ip_in_token_list(ip, core, clients_set, servers_set)
            return (not belongs) if neg else belongs or core.lower() == "any"

        # Verificar conforme direção
        if direction == "->":
            if not port_ok(src_port, pkt_src_port) or not port_ok(dst_port, pkt_dst_port):
                return False
            if not ip_token_ok(pkt_src_ip, src_tok):
                return False
            if not ip_token_ok(pkt_dst_ip, dst_tok):
                return False
            return True

        elif direction == "<>":
            # sentido 1
            ok1 = (
                port_ok(src_port, pkt_src_port) and
                port_ok(dst_port, pkt_dst_port) and
                ip_token_ok(pkt_src_ip, src_tok) and
                ip_token_ok(pkt_dst_ip, dst_tok)
            )
            # sentido 2 (swap)
            ok2 = (
                port_ok(src_port, pkt_dst_port) and
                port_ok(dst_port, pkt_src_port) and
                ip_token_ok(pkt_dst_ip, src_tok) and
                ip_token_ok(pkt_src_ip, dst_tok)
            )
            return ok1 or ok2

        else:
            # outras direções não usadas no teu ruleset
            return False

    except Exception:
        # Em caso de dúvida, não casar header.
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

    # ---------- ARP Spoofing ----------
    src_ip  = modbus_data.get("src_ip")
    src_mac = modbus_data.get("src_mac")
    if src_ip and src_mac:
        expected = ALLOWED_MACS.get(src_ip)
        if expected and expected.lower() != src_mac.lower():
            return 1, f"[MITM] ARP Spoofing: IP {src_ip} deveria ser {expected}, recebeu {src_mac}"

    # ---------- Estado de pedidos/respostas ----------
    dst_ip = modbus_data.get("dst_ip")
    fc     = _to_int_or_default(modbus_data.get("function_code"), 0)

    # Guardar pedido (c2s → dst_port 502)
    if str(modbus_data.get("dst_port")) == "502":
        modbus_state[(src_ip, dst_ip, fc)] = modbus_data

    # Verificar coerência na resposta (s2c → src_port 502)
    elif str(modbus_data.get("src_port")) == "502":
        key = (dst_ip, src_ip, fc)
        if key in modbus_state:
            last_request = modbus_state[key]
            if not is_response_consistent(last_request, modbus_data):
                return 1, "[MITM] Resposta incoerente com o pedido anterior"

    # ---------- Reconstruir o buffer Modbus/TCP completo ----------
    # MUITO IMPORTANTE: as tuas regras usam offsets do MBAP e FC.
    # O packet_sniffer dá 'payload' apenas os data bytes pós-FC.
    # Aqui juntamos MBAP + FC + Data para que offsets/contents/pcre batam certo.
    mbtcp_bytes = build_modbus_tcp_bytes(modbus_data)

    # ---------- Avaliação das regras ----------
    for rule in rules:
        opts = rule.get("options", {})
        sid  = opts.get("sid", "N/A")
        msg  = opts.get("msg", "[Regra sem mensagem]")

        # 1) Header (proto/src/src_port/direction/dst/dst_port)
        if not header_matches(rule, modbus_data, MODBUS_CLIENTS, MODBUS_SERVERS):
            continue

        # 2) Flow (from_client/to_client/established) — mantém a tua lógica
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

        # dsize (tamanho total do buffer que estamos a considerar)
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

        # contents (cada content com offset/depth)
        if all_match and "contents" in opts:
            for c in opts["contents"]:
                try:
                    content = parse_content(c.get("content", ""))
                    offset  = int(c.get("offset", 0))
                    # depth: nº máximo de bytes para comparar a partir de offset
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

        # pcre (regex binário) — agora sobre MBTCP
        if all_match and "pcre" in opts:
            try:
                import re
                pcre = opts["pcre"]
                # remove /.../iAR
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

        # byte_jump / isdataat (semântica simplificada)
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
                # Guardar idx corrente numa var para isdataat relativa
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
                # isdataat:0,relative → verifica se ainda HÁ dados a partir da posição
                if check_pos < 0 or check_pos >= len(mbtcp_bytes):
                    all_match = False
            except Exception:
                all_match = False

        # Resultado da regra
        if all_match:
            return 1, f"[SID {sid}] {msg}"

    # Nenhuma regra bateu
    return 0, None


# ----------------------------
# Coerência pedido ↔ resposta
# ----------------------------

def is_response_consistent(request, response):
    """
    Exemplo de coerência para FC=3 (pode-se expandir se precisares).
    """
    if _to_int_or_default(request.get("function_code")) != _to_int_or_default(response.get("function_code")):
        return False

    req_payload = _hexstr_to_bytes(request.get("payload", ""))
    res_payload = _hexstr_to_bytes(response.get("payload", ""))

    # FC=3 Read Holding Registers:
    # req: [addr_hi, addr_lo, qty_hi, qty_lo] → qty (nº registos)
    # res: [byte_count, data...], byte_count deve ser qty*2
    if _to_int_or_default(response.get("function_code")) == 3:
        if len(req_payload) >= 4 and len(res_payload) >= 1:
            qty = (req_payload[2] << 8) | req_payload[3]
            expected_bytes = qty * 2
            byte_count = res_payload[0]
            if byte_count != expected_bytes:
                return False

    return True
