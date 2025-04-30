# detector.py (novo)
import rules_loader
import binascii

rules = []


def init_detector(rules_file):
    global rules
    rules = rules_loader.load_rules(rules_file)


def detect(modbus_data):
    if not modbus_data or "payload" not in modbus_data:
        return "OK", None

    payload_bytes = bytes.fromhex(modbus_data["payload"])

    for rule in rules:
        opts = rule["options"]
        
        if "content" in opts:
            try:
                content = parse_content(opts["content"])
                offset = int(opts.get("offset", 0))
                depth = int(opts.get("depth", len(payload_bytes) - offset))

                search_window = payload_bytes[offset:offset + depth]

                if content in search_window:
                    msg = opts.get("msg", "[Regra sem mensagem]")
                    sid = opts.get("sid", "N/A")
                    return "Malicious", f"[SID {sid}] {msg}"
            except Exception as e:
                continue

    return "OK", None


def parse_content(content_str):
    # Exemplo: "|08 00 04|" → b'\x08\x00\x04'
    if content_str.startswith("|") and content_str.endswith("|"):
        hex_str = content_str.strip("|").replace(" ", "")
        return binascii.unhexlify(hex_str)
    else:
        return content_str.encode()
