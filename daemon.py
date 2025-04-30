import os
import time
import yaml
import threading
from packet_capture import start_sniffer
from packet_buffer import packet_queue
from parser import parse_modbus_packet
from detector import detect
from logger import log_event
from utils import write_pid, remove_pid, check_pid
from app_logger import logger

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
        "payload": "deadbeef"
    }

def daemon_loop():
    config = load_config()
    interface = config.get('interface', 'eth0')
    verbose_mode = config.get('verbose_mode', False)
    test_mode = config.get('test_mode', False)
    test_interval = config.get('test_interval', 5)

    last_test_log = time.time()

    logger.info("ModGuard iniciado.")
    logger.info(f"Interface configurada: {interface}")
    if test_mode:
        logger.info("Modo de teste ativo.")
    if verbose_mode:
        logger.info("Modo verbose ativo.")

    sniffer_thread = threading.Thread(target=start_sniffer, args=(interface,), daemon=True)
    sniffer_thread.start()
    logger.info("Thread de captura iniciada.")

    while True:
        try:
            if not packet_queue.empty():
                packet = packet_queue.get()
                modbus_data = parse_modbus_packet(packet)
                if modbus_data:
                    status, rule = detect(modbus_data)
                    if verbose_mode:
                        logger.info(f"[VERBOSE] Pacote Modbus: {packet['IP'].src}:{packet['TCP'].sport} → "
                                    f"{packet['IP'].dst}:{packet['TCP'].dport}, FC: {modbus_data['function_code']}")
                    log_event(packet, modbus_data, status, rule)

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
            last_test_log = time.time()

        time.sleep(0.1)

def start_daemon():
    if check_pid():
        logger.warning("ModGuard já está em execução.")
        return
    pid = os.fork()
    if pid == 0:
        write_pid()
        logger.info("PID registado e processo filho iniciado.")
        try:
            daemon_loop()
        finally:
            logger.info("ModGuard terminou. A remover PID.")
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
        logger.warning("Tentativa de parar ModGuard, mas nenhum processo ativo.")
