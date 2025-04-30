from scapy.all import sniff
from packet_buffer import packet_queue
from app_logger import logger
from datetime import datetime

def packet_handler(packet):
    packet_queue.put(packet)

def start_sniffer(interface):
    logger.info(f"Sniffer iniciado na interface {interface}")
    sniff(iface=interface, filter="tcp port 502", prn=packet_handler, store=False)

