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

def generate_test_packet():
    return {
        "transaction_id": 0,
        "protocol_id": 0,
        "length": 6,
        "unit_id": 1,
        "function_code": 99,
        "payload": "63deadbeef"
    }

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
<<<<<<< HEAD
            time.sleep(1)  # Mantém daemon ativo
    except KeyboardInterrupt:
        logger.info("ModSentinel interrompido pelo utilizador.")
=======
            try:
                if not tshark_packet_queue.empty():
                    parsed_packet = tshark_packet_queue.get()
                    status, rule = detect(parsed_packet)
                    if verbose_mode:
                        logger.info(
                            f"[VERBOSE] Modbus: {parsed_packet['IP']['src']}:{parsed_packet['TCP']['sport']} → "
                            f"{parsed_packet['IP']['dst']}:{parsed_packet['TCP']['dport']} | FC: {parsed_packet['function_code']}"
                        )
                    log_event(parsed_packet, parsed_packet, status, rule)
                    log_to_csv(parsed_packet, parsed_packet, status)

            except Exception as e:
                logger.exception(f"Erro ao processar pacote: {e}")

            if test_mode and (time.time() - last_test_log >= test_interval):
                modbus_data = generate_test_packet()
                status, rule = detect(modbus_data)
                fake_packet = {
                    'IP': {'src': '192.0.2.1', 'dst': '192.0.2.2'},
                    'TCP': {'sport': 12345, 'dport': 502}
                }
                if verbose_mode:
                    logger.info(f"[VERBOSE][TEST MODE] Pacote gerado: FC: {modbus_data['function_code']}")
                log_event(fake_packet, modbus_data, status, rule)
                log_to_csv(fake_packet, modbus_data, status)
                last_test_log = time.time()

            time.sleep(0.1)
>>>>>>> 457c16413991943058053aa60c6b336b5f9d0719
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
