import os

PID_FILE = '/tmp/modsentinel.pid'
LOG_FILE = 'logs/modsentinel.log'

def write_pid():
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

def remove_pid():
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)

def check_pid():
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                return pid
            except OSError:
                return None
    return None

def tail_logs(n=10):
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            return ''.join(lines[-n:])
    except FileNotFoundError:
        return "Ficheiro de log não encontrado."

