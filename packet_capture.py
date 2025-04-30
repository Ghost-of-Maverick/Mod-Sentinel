from scapy.all import sniff

def modbus_filter(packet):
    return packet.haslayer('TCP') and packet['TCP'].dport == 502

def capture_packets(interface):
    packets = sniff(iface=interface, filter="tcp port 502", prn=lambda x:x, store=False)
    for packet in packets:
        yield packet
