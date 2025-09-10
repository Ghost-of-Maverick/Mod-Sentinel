#!/usr/bin/env python3
import sys
import time
import socket
import logging

# Logging para journal (systemd)
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

try:
    from pymodbus.client import ModbusTcpClient
except Exception:
    try:
        from pymodbus.client.sync import ModbusTcpClient
    except Exception as e:
        logger.exception("Falha ao importar pymodbus. Instala 'pymodbus' para o Python usado por systemd.")
        sys.exit(1)

# Configurações PLC
PLC_IP = "127.0.0.1"
PLC_PORT = 502

# Destino UDP
DEST_IP = "172.27.224.251"
DEST_PORT = 5005

RETRY_SECONDS = 5
READ_INTERVAL = 1
MODBUS_TIMEOUT = 3

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT, timeout=MODBUS_TIMEOUT)

    logger.info("motor_sender arrancado")
    try:
        while True:
            try:
                if not client.connect():
                    logger.warning("Não foi possível conectar ao Modbus %s:%s — tenta novamente em %s s", PLC_IP, PLC_PORT, RETRY_SECONDS)
                    time.sleep(RETRY_SECONDS)
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT, timeout=MODBUS_TIMEOUT)
                    continue

                logger.info("Conectado ao Modbus %s:%s", PLC_IP, PLC_PORT)

                # Loop de leitura enquanto conectado
                while True:
                    try:
                        result = client.read_coils(address=0, count=1)
                        if result is None:
                            logger.warning("Leitura devolveu None — vai tentar reconectar")
                            break

                        # Verifica erro ou extrai bits
                        if hasattr(result, "isError") and result.isError():
                            logger.error("Erro na leitura Modbus: %s", result)
                        else:
                            bits = getattr(result, "bits", None)
                            if bits and len(bits) >= 1:
                                motor_state = int(bits[0])
                                message = str(motor_state).encode("utf-8")
                                try:
                                    sock.sendto(message, (DEST_IP, DEST_PORT))
                                    logger.info("Motor state %s enviado para %s:%s", motor_state, DEST_IP, DEST_PORT)
                                except Exception as e:
                                    logger.exception("Falha ao enviar UDP: %s", e)
                            else:
                                logger.warning("Resposta sem 'bits' válidos: %s", result)

                        time.sleep(READ_INTERVAL)

                    except Exception as e:
                        logger.exception("Exceção no ciclo de leitura — vai reconectar: %s", e)
                        break

                client.close()
                time.sleep(RETRY_SECONDS)
                client = ModbusTcpClient(PLC_IP, port=PLC_PORT, timeout=MODBUS_TIMEOUT)

            except Exception as e:
                logger.exception("Erro inesperado no loop principal — aguarda %s s e tenta novamente: %s", RETRY_SECONDS, e)
                time.sleep(RETRY_SECONDS)

    except KeyboardInterrupt:
        logger.info("Interrompido pelo utilizador")

    finally:
        try:
            client.close()
        except Exception:
            pass
        sock.close()
        logger.info("motor_sender terminado")

if __name__ == "__main__":
    main()
