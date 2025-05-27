import subprocess

def start_tshark_capture(interface, full_path, modbus_path):
    try:
        # Captura completa
        full_proc = subprocess.Popen([
            'tshark', '-i', interface, '-w', full_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Captura apenas Modbus (porta 502)
        modbus_proc = subprocess.Popen([
            'tshark', '-i', interface, '-w', modbus_path, '-f', 'tcp port 502'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return full_proc, modbus_proc
    except FileNotFoundError:
        print("[ERRO] tshark não encontrado. Instala com: apt install tshark")
        return None, None

def stop_tshark_capture(proc1, proc2):
    if proc1:
        proc1.terminate()
    if proc2:
        proc2.terminate()
