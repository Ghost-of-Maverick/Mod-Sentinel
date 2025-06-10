import threading
import json
import logging
import os
import subprocess
import time
from datetime import datetime
import json
import pyshark
from csv_logger import log_to_csv, set_csv_file, close_csv_file
from logger import log_event
from detector import detect
from app_logger import logger

# Diretórios e nomes de ficheiro com timestamp
TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
PCAP_FILE = f"logs/captura_{TIMESTAMP}.pcap"
CSV_FILE = f"logs/trafego_{TIMESTAMP}.csv"

os.makedirs("logs", exist_ok=True)

tcpdump_proc = None  # Global para podermos terminar mais tarde

def iniciar_tcpdump(interface):
    global tcpdump_proc
    tcpdump_proc = subprocess.Popen([
        "tcpdump",
        "-i", interface,
        "-w", PCAP_FILE,
        "tcp port 502"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logger.info(
        f"tcpdump iniciado: interface={interface}, ficheiro={PCAP_FILE}")
    tcpdump_proc.wait()


def iniciar_tcpdump_em_thread(interface):
    thread = threading.Thread(
        target=iniciar_tcpdump,
        args=(interface,),
        daemon=True)
    thread.start()
    return thread

def packet_sniffer(interface):
    logger.info("A iniciar captura e análise com pyshark...")

    iniciar_tcpdump_em_thread(interface)

    try:
        # Não cria o ficheiro pcap, apenas captura os pacotes, havia problemas por causa disto...
        capture = pyshark.LiveCapture(interface=interface, display_filter="tcp.port == 502")

        for packet in capture.sniff_continuously():
            try:
                parsed = {
                    'timestamp': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'src_mac': packet.eth.src if hasattr(packet, 'eth') else '',
                    'dst_mac': packet.eth.dst if hasattr(packet, 'eth') else '',
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else '',
                    'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else '',
                    'src_port': packet.tcp.srcport if hasattr(packet, 'tcp') else '',
                    'dst_port': packet.tcp.dstport if hasattr(packet, 'tcp') else '',
                    'function_code': getattr(packet, 'modbus', {}).get('func_code', '?') if hasattr(packet, 'modbus') else '',
                    'flags': packet.tcp.flags if hasattr(packet, 'tcp') else '',
                    'length': packet.length,
                    'transaction_id': getattr(packet, 'modbus', {}).get('transaction_id', '') if hasattr(packet, 'modbus') else '',
                    'payload': getattr(packet, 'data', {}).get('data', '') if hasattr(packet, 'data') else ''
                }

                status, rule = detect(parsed)
                parsed['malicious'] = int(bool(status))  # Garante valor 0 ou 1

                log_to_csv(parsed, parsed, status)
                log_event(parsed, parsed, status, rule)

            except Exception as e:
                logger.warning(f"Erro ao processar pacote: {e}")

    except Exception as e:
        logger.error(f"Erro no sniffer: {e}")
    finally:
        close_csv_file()
        if tcpdump_proc and tcpdump_proc.poll() is None:
            tcpdump_proc.terminate()
            tcpdump_proc.wait()
        logger.info("Captura e gravacao terminadas.")

def start_sniffer_thread(interface):
    set_csv_file(CSV_FILE)
    thread = threading.Thread(target=packet_sniffer, args=(interface,), daemon=True)
    thread.start()
    return thread