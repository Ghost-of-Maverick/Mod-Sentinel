# rules_loader.py
import re
import yaml


def load_config_variables():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config.get("MODBUS_CLIENT", []), config.get("MODBUS_SERVER", [])


def load_rules(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()

    client_ips, server_ips = load_config_variables()
    rules = []
    current_rule = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("alert"):
            current_rule = line
        else:
            current_rule += " " + line

        if line.endswith(")"):
            parsed = parse_rule(current_rule, client_ips, server_ips)
            if parsed:
                rules.append(parsed)
            current_rule = ""

    return rules


def parse_rule(rule_text, client_ips, server_ips):
    # Exemplo: alert tcp $MODBUS_CLIENT any -> $MODBUS_SERVER 502 (...)
    try:
        header, options_raw = rule_text.split("(", 1)
        options_raw = options_raw.strip(") ")
        options = parse_options(options_raw)

        # Substituição de variáveis
        header = header.replace("$MODBUS_CLIENT", "|MODBUS_CLIENT|")
        header = header.replace("$MODBUS_SERVER", "|MODBUS_SERVER|")

        proto, src, src_port, direction, dst, dst_port = header.split()[1:7]

        return {
            "proto": proto,
            "src": src,
            "src_port": src_port,
            "direction": direction,
            "dst": dst,
            "dst_port": dst_port,
            "options": options,
            "original": rule_text
        }
    except Exception as e:
        print(f"[ERRO] Falha ao analisar regra: {e}\n{rule_text}")
        return None


def parse_options(options_str):
    options = {}
    parts = options_str.split(";")
    for part in parts:
        if not part.strip():
            continue
        if ":" in part:
            key, value = part.strip().split(":", 1)
            options[key.strip()] = value.strip().strip('"')
    return options
