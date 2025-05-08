import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = 'logs'
APP_LOG_FILE = os.path.join(LOG_DIR, 'app.log')
os.makedirs(LOG_DIR, exist_ok=True)

# Logger principal
logger = logging.getLogger("ModSentinelApp")
logger.setLevel(logging.DEBUG)  # Capta tudo internamente

# Formato padrão
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')

# Handler para ficheiro (capta tudo)
file_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=1_000_000, backupCount=3)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

# Handler para consola (só INFO+ e sem mensagens verbose)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

# Filtro para não mostrar mensagens [VERBOSE] na consola
class NoVerboseFilter(logging.Filter):
    def filter(self, record):
        return "[VERBOSE]" not in record.getMessage()

console_handler.addFilter(NoVerboseFilter())
logger.addHandler(console_handler)
