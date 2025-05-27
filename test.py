from scapy.all import *
import random

def create_modbus_request(transaction_id=1, unit_id=1, function_code=3, start_addr=0, quantity=1):
    # Modbus TCP Header (MBAP)
    protocol_id = 0  # Always 0 for Modbus TCP
    length = 6       # Length of PDU (function_code + start_addr + quantity)
    
    mbap = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    
    # Modbus PDU
    pdu = struct.pack(">BHH", function_code, start_addr, quantity)
    
    return mbap + pdu

def send_modbus_traffic(target_ip, port=502, count=10, interval=1):
    for i in range(count):
        trans_id = random.randint(0, 65535)
        payload = create_modbus_request(transaction_id=trans_id)
        
        pkt = IP(dst=target_ip)/TCP(dport=port, sport=RandShort(), flags="S")/Raw(load=payload)
        print(f"Sending Modbus TCP request to {target_ip}:{port} [Transaction ID: {trans_id}]")
        send(pkt, verbose=0)
        time.sleep(interval)

if __name__ == "__main__":
    target = "192.168.1.100"  # Change this to your Modbus server IP
    send_modbus_traffic(target_ip=target, count=5, interval=0.5)
