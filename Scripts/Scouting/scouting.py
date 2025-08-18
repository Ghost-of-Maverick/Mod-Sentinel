import socket
import time

def send_modbus_packet(ip, port, packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        sock.sendall(packet)
        response = sock.recv(1024)
        return response
    finally:
        sock.close()

def read_holding_registers(ip='172.27.224.250', port=502, start_address=0, quantity=10):
    transaction_id = b'\x00\x01'        # 2 bytes - pode ser incrementado se quiseres
    protocol_id = b'\x00\x00'           # 2 bytes
    length = b'\x00\x06'                # 2 bytes: unit id + function + 4 bytes de payload
    unit_id = b'\x01'                   # 1 byte (normalmente 1)
    function_code = b'\x03'             # Read Holding Registers

    # Start address e quantity em big endian (2 bytes cada)
    start_addr_bytes = start_address.to_bytes(2, byteorder='big')
    quantity_bytes = quantity.to_bytes(2, byteorder='big')

    packet = transaction_id + protocol_id + length + unit_id + function_code + start_addr_bytes + quantity_bytes

    response = send_modbus_packet(ip, port, packet)
    return response

def parse_registers(response):
    # Resposta tem:
    # Transaction ID (2 bytes), Protocol ID (2 bytes), Length (2 bytes), Unit ID (1 byte), Function Code (1 byte), Byte Count (1 byte), Dados...
    if not response or len(response) < 9:
        return None
    byte_count = response[8]
    registers = []
    for i in range(byte_count // 2):
        reg = (response[9 + 2*i] << 8) + response[10 + 2*i]
        registers.append(reg)
    return registers

if __name__ == '__main__':
    ip = '172.27.224.250'
    port = 502
    start_address = 0     # endereço inicial dos registos
    quantity = 10         # número de registos a ler

    print(f'A ler registos com FC 3 do PLC {ip}...')

    while True:
        try:
            response = read_holding_registers(ip, port, start_address, quantity)
            registers = parse_registers(response)
            if registers is None:
                print('Resposta inválida ou sem dados.')
            else:
                print(f'Registos {start_address} a {start_address+quantity-1}: {registers}')
            time.sleep(1)
        except KeyboardInterrupt:
            print('\nInterrompido pelo utilizador. A sair...')
            break
        except Exception as e:
            print(f'Erro: {e}')
            time.sleep(2)