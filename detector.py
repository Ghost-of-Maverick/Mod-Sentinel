import yaml

RULES_FILE = 'rules/default.yaml'

def load_rules():
    with open(RULES_FILE, 'r') as file:
        return yaml.safe_load(file)

def detect(packet_data):
    rules = load_rules()
    for rule in rules['rules']:
        if packet_data['function_code'] == rule['function_code']:
            return ("Malicious", rule['description'])
    return ("OK", None)
