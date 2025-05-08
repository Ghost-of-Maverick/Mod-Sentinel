# app_logger.py
import logging
import os
import yaml
from logging.handlers import RotatingFileHandler

LOG_DIR = 'logs'
APP_LOG_FILE = os.path.join(LOG_DIR, 'app.log')
os.makedirs(LOG_DIR, exist_ok=True)

# Lê nível de log a partir do config.yaml
def get_log_level():
    try:
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)
            level_str = config.get('app_log_level', 'INFO').upper()
            return getattr(logging, level_str, logging.INFO)
    except Exception:
        return logging.INFO

# Logger principal
logger = logging.getLogger("ModSentinelApp")
logger.setLevel(logging.DEBUG)  # Sempre DEBUG aqui para captar tudo internamente

# Formato padrão
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')

# Handler para ficheiro (capta tudo)
file_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=1_000_000, backupCount=3)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

# Handler para consola (capta apenas info relevantes, não verbose/test)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

# Filtro: excluir mensagens que contenham "[VERBOSE]"
class NoVerboseFilter(logging.Filter):
    def filter(self, record):
        return "[VERBOSE]" not in record.getMessage()

console_handler.addFilter(NoVerboseFilter())
logger.addHandler(console_handler)
