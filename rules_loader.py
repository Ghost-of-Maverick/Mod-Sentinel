import yaml

def load_config_variables():
    """
    Carrega variáveis MODBUS_CLIENT e MODBUS_SERVER do ficheiro config.yaml.
    Retorna listas de IPs/hosts para cliente e servidor.
    """
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config.get("MODBUS_CLIENT", []), config.get("MODBUS_SERVER", [])


def load_rules(file_path):
    """
    Lê o ficheiro de regras e devolve uma lista de dicionários com as regras processadas.
    """
    with open(file_path, "r") as f:
        lines = f.readlines()

    client_ips, server_ips = load_config_variables()
    rules = []
    current_rule = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Junta linhas quebradas até fechar com ')'
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
    """
    Converte uma regra Snort-like para dicionário interno, substituindo variáveis.
    """
    try:
        # Separa header e opções
        header, options_raw = rule_text.split("(", 1)
        options_raw = options_raw.strip(") ")
        options = parse_options(options_raw)

        # Substitui variáveis por listas de IPs
        header = header.replace("$MODBUS_CLIENT", ",".join(client_ips))
        header = header.replace("$MODBUS_SERVER", ",".join(server_ips))

        parts = header.split()
        if len(parts) < 7:
            raise ValueError("Header da regra inválido")

        proto, src, src_port, direction, dst, dst_port = parts[1:7]

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
    """
    Analisa as opções de uma regra Snort-like e devolve dicionário com campos conhecidos.
    """
    options = {}
    contents = []
    parts = [p.strip() for p in options_str.split(";") if p.strip()]
    i = 0

    while i < len(parts):
        part = parts[i]

        if part.startswith("msg:"):
            options["msg"] = part.split(":", 1)[1].strip().strip('"')

        elif part.startswith("content:"):
            content_val = part.split(":", 1)[1].strip().strip('"')
            entry = {"content": content_val}
            if i + 1 < len(parts) and parts[i + 1].startswith("offset:"):
                entry["offset"] = parts[i + 1].split(":", 1)[1].strip()
                i += 1
            if i + 1 < len(parts) and parts[i + 1].startswith("depth:"):
                entry["depth"] = parts[i + 1].split(":", 1)[1].strip()
                i += 1
            contents.append(entry)

        elif part.startswith("byte_test:"):
            vals = [x.strip() for x in part.split(":", 1)[1].split(",")]
            options["byte_test"] = {
                "size": vals[0],
                "operator": vals[1],
                "value": vals[2],
                "offset": vals[3]
            }

        elif part.startswith("byte_jump:"):
            vals = [x.strip() for x in part.split(":", 1)[1].split(",")]
            options["byte_jump"] = {
                "size": vals[0],
                "offset": vals[1],
                "relative": "relative" in vals
            }

        elif part.startswith("isdataat:"):
            vals = [x.strip() for x in part.split(":", 1)[1].split(",")]
            options["isdataat"] = {
                "index": vals[0],
                "relative": "relative" in vals
            }

        elif part.startswith("sid:"):
            options["sid"] = part.split(":", 1)[1].strip()

        elif part.startswith("classtype:"):
            options["classtype"] = part.split(":", 1)[1].strip()

        elif part.startswith("priority:"):
            options["priority"] = part.split(":", 1)[1].strip()

        else:
            # Guarda qualquer outra opção não tratada
            if ":" in part:
                key, value = part.split(":", 1)
                options[key.strip()] = value.strip().strip('"')

        i += 1

    if contents:
        options["contents"] = contents
    return options
