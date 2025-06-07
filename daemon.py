import os
import time
import yaml
import threading
from datetime import datetime
from packet_sniffer import start_sniffer_thread
from detector import init_detector, detect
from logger import log_event
from utils import write_pid, remove_pid, check_pid
from app_logger import logger
from queue import Empty, Queue

TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
PCAP_FULL = f"logs/captura_completa_{TIMESTAMP}.pcap"
CSV_FILE = f"logs/trafego_{TIMESTAMP}.csv"

os.makedirs("logs", exist_ok=True)

CONFIG_FILE = 'config.yaml'

def load_config():
    with open(CONFIG_FILE, 'r') as file:
        return yaml.safe_load(file)

def daemon_loop():
    config = load_config()

    rules_file = config.get("rules_file", "rules/modsentinel.rules")
    interface = config.get("interface", "eth0")

    logger.info("ModSentinel iniciado.")
    logger.info(f"Interface configurada: {interface}")

    # Inicializa regras de deteção
    init_detector(rules_file)

    # Inicia sniffer em thread
    start_sniffer_thread(interface)

    try:
        while True:
            time.sleep(1)  # Mantém daemon ativo
    except KeyboardInterrupt:
        logger.info("ModSentinel interrompido pelo utilizador.")
    finally:
        logger.info("ModSentinel terminado.")

def start_daemon():
    if check_pid():
        logger.warning("ModSentinel já está em execução.")
        return
    pid = os.fork()
    if pid == 0:
        write_pid()
        logger.info("PID registado e processo filho iniciado.")
        try:
            daemon_loop()
        finally:
            logger.info("ModSentinel terminou. A remover PID.")
            remove_pid()

def stop_daemon():
    pid = check_pid()
    if pid:
        try:
            os.kill(pid, 15)
            logger.info(f"Processo {pid} terminado.")
        except ProcessLookupError:
            logger.warning("PID inválido. A remover ficheiro.")
        remove_pid()
    else:
        logger.warning("Tentativa de parar ModSentinel, mas nenhum processo ativo.")
