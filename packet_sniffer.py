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

def extrair_transaction_id_raw(packet):
    try:
        raw = bytes.fromhex(packet.tcp.payload.replace(':', ''))
        if len(raw) >= 2:
            tx_id = int.from_bytes(raw[0:2], byteorder='big')
            return str(tx_id)
    except Exception as e:
        logger.debug(f"Erro a extrair transaction_id raw: {e}")
    return ''

def extrair_unit_id_raw(packet):
    try:
        raw = bytes.fromhex(packet.tcp.payload.replace(':', ''))
        if len(raw) >= 7:
            unit_id = raw[6]  # Byte 7 no MBAP header (index 6)
            return str(unit_id)
    except Exception as e:
        logger.debug(f"Erro a extrair unit_id raw: {e}")
    return ''

def extrair_data_bytes(packet):
    try:
        raw = bytes.fromhex(packet.tcp.payload.replace(':', ''))
        if len(raw) > 8:
            # Data bytes = tudo após os 7 bytes de cabeçalho MBAP + 1 byte Function Code
            return raw[8:].hex()
    except Exception as e:
        logger.debug(f"Erro a extrair data bytes: {e}")
    return ''

def extrair_protocol_id_raw(packet):
    try:
        raw = bytes.fromhex(packet.tcp.payload.replace(':', ''))
        if len(raw) >= 4:
            protocol_id = int.from_bytes(raw[2:4], byteorder='big')  # Byte 3 e 4
            return str(protocol_id)
    except Exception as e:
        logger.debug(f"Erro a extrair protocol_id raw: {e}")
    return ''

def packet_sniffer(interface):
    logger.info("A iniciar captura e análise com pyshark...")

    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter="tcp port 502", output_file=PCAP_FILE)

        for packet in capture.sniff_continuously():
            try:
                transaction_id = ''
                protocol_id = ''
                unit_id = ''
                function_code = ''
                payload = ''

                if 'modbus' in packet:
                    modbus_layer = packet.modbus
                    transaction_id = getattr(modbus_layer, 'transaction_id', '')
                    function_code = getattr(modbus_layer, 'func_code', '?')
                    unit_id = getattr(modbus_layer, 'unit_id', '')

                if not transaction_id:
                    transaction_id = extrair_transaction_id_raw(packet)
                if not unit_id:
                    unit_id = extrair_unit_id_raw(packet)
                protocol_id = extrair_protocol_id_raw(packet)
                payload = extrair_data_bytes(packet)

                parsed = {
                    'timestamp': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'src_mac': packet.eth.src if hasattr(packet, 'eth') else '',
                    'dst_mac': packet.eth.dst if hasattr(packet, 'eth') else '',
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else '',
                    'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else '',
                    'src_port': packet.tcp.srcport if hasattr(packet, 'tcp') else '',
                    'dst_port': packet.tcp.dstport if hasattr(packet, 'tcp') else '',
                    'function_code': function_code,
                    'unit_id': unit_id,
                    'protocol_id': protocol_id,
                    'flags': packet.tcp.flags if hasattr(packet, 'tcp') else '',
                    'length': packet.length,
                    'transaction_id': transaction_id,
                    'payload': payload
                }

                status, rule = detect(parsed)
                parsed['malicious'] = int(bool(status))

                log_to_csv(parsed, parsed, status)
                log_event(parsed, parsed, status, rule)

            except Exception as e:
                logger.warning(f"Erro ao processar pacote: {e}")

    except Exception as e:
        logger.error(f"Erro no sniffer: {e}")
    finally:
        close_csv_file()
        logger.info("Captura e gravação terminadas.")

def start_sniffer_thread(interface):
    set_csv_file(CSV_FILE)
    thread = threading.Thread(target=packet_sniffer, args=(interface,), daemon=True)
    thread.start()
    return thread