#!/usr/bin/env python3
import socket
import logging
import math
from datetime import datetime
from time import time
from pymodbus.client import ModbusTcpClient
from nicegui import ui
import matplotlib.pyplot as plt

# ---------------- CONFIG ----------------
PLC1_IP = "172.27.224.250"
PLC1_PORT = 502
TEMP_REGISTER = 6

UDP_LISTEN_IP = "0.0.0.0"
UDP_LISTEN_PORT = 5005

# Referências térmicas
TEMP_MIN = 15.0
TEMP_MAX = 120.0
TEMP_LOW = 30.0        # mínimo do ciclo motor ON
TEMP_HIGH = 41.0       # máximo do ciclo motor ON
TEMP_CRITICO = 70.0    # aquecimento rápido se motor OFF

# Constantes físicas
K_CYCLE = 0.02         # motor ON (ciclo normal)
K_CRITICO = 0.08       # subida rápida ataque
K_RECUP = 0.04         # descida recuperação

READ_INTERVAL = 1.0    # segundos

# ---------------- ESTADO ----------------
temp_atual = 40.0
motor_state = 1          # motor ON por defeito
ultimo_dado_motor = None
start_time = time()

phase = "ciclo"          # ciclo / ataque / recuperacao
alvo = TEMP_LOW          # alvo inicial
historico_temperatura = []

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("PLC2")

# ---------------- MODBUS ----------------
client = ModbusTcpClient(PLC1_IP, port=PLC1_PORT)
if not client.connect():
    logger.error("Não foi possível conectar ao PLC1 %s:%s", PLC1_IP, PLC1_PORT)

# ---------------- UDP ----------------
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_LISTEN_IP, UDP_LISTEN_PORT))
sock.setblocking(False)
logger.info("UDP listener à escuta em %s:%s", UDP_LISTEN_IP, UDP_LISTEN_PORT)

# ---------------- FUNÇÃO PARA SALVAR PNG ----------------
def salvar_grafico_png():
    if not historico_temperatura:
        logger.warning("Não há dados para salvar.")
        return

    tempos, temperaturas = zip(*historico_temperatura)
    plt.figure(figsize=(10, 6))
    plt.plot(tempos, temperaturas, marker='o', linestyle='-', color='orange')
    plt.xlabel("Tempo (s)")
    plt.ylabel("Temperatura (°C)")
    plt.title("Histórico de Temperatura PLC2")
    plt.grid(True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"grafico_temperatura_{timestamp}.png"

    plt.savefig(filename)
    plt.close()
    logger.info(f"Gráfico salvo como {filename}")

# ---------------- MODELO FÍSICO ----------------
def atualizar_temperatura(motor_state_local, temp, dt=1.0):
    global phase, alvo, TEMP_LOW, TEMP_HIGH, TEMP_CRITICO, K_CYCLE, K_CRITICO, K_RECUP

    if motor_state_local == 1:
        if phase in ["ataque", "recuperacao"]:
            # recuperação depois de ataque
            phase = "recuperacao"
            k = K_RECUP
            delta = (alvo - temp) * (1 - math.exp(-k * dt))
            temp += delta
            if abs(temp - alvo) < 0.5:
                phase = "ciclo"
                alvo = TEMP_LOW if temp > (TEMP_LOW + TEMP_HIGH)/2 else TEMP_HIGH
        else:
            # ciclo normal motor ON
            phase = "ciclo"
            k = K_CYCLE
            delta = (alvo - temp) * (1 - math.exp(-k * dt))
            temp += delta
            # inverter alvo quando se aproxima
            if abs(temp - alvo) < 0.3:
                alvo = TEMP_HIGH if alvo == TEMP_LOW else TEMP_LOW

    else:
        # motor OFF inesperado (ataque)
        phase = "ataque"
        k = K_CRITICO
        delta = (TEMP_CRITICO - temp) * (1 - math.exp(-k * dt))
        temp += delta

    temp = max(TEMP_MIN, min(TEMP_MAX, temp))
    return temp

# ---------------- GUI ----------------
@ui.page('/')
def index():
    global temp_atual, motor_state, ultimo_dado_motor, start_time, phase, alvo
    global TEMP_LOW, TEMP_HIGH, TEMP_CRITICO, K_CYCLE, K_CRITICO, K_RECUP, historico_temperatura

    with ui.row().style("height:100vh; width:100vw; display:flex; align-items:center; justify-content:center;"):
        with ui.column().classes("items-center justify-center p-4"):

            ui.label("Simulação PLC2 → PLC1").classes("text-2xl font-bold")

            # Labels principais
            estado_label = ui.label("⚙️ Motor: ---").classes("text-lg")
            temp_label = ui.label("🌡️ Temperatura: ---").classes("text-lg")
            clock_label = ui.label("🕒 ---").classes("text-lg")
            debug_label = ui.label("Último dado motor: ---").classes("text-sm text-gray-500")

            # Gráfico
            chart = ui.echart({
                'xAxis': {'type': 'category', 'data': []},
                'yAxis': {'type': 'value', 'name': '(ºC)'},
                'series': [{'name': 'Temperatura', 'type': 'line', 'data': []}],
            }).classes("w-full h-64")

            # Botões principais
            with ui.row():
                ui.button("Salvar gráfico PNG", on_click=salvar_grafico_png)

                def resetar():
                    nonlocal chart
                    historico_temperatura.clear()
                    chart.options['series'][0]['data'] = []
                    chart.options['xAxis']['data'] = []
                    chart.update()
                    globals().update(temp_atual=40.0, phase="ciclo", alvo=TEMP_LOW, start_time=time(), motor_state=1)
                ui.button("🔄 Resetar Simulação", on_click=resetar, color="red")

            # ---------------- Sliders ----------------
            with ui.expansion("⚙️ Ajustes do Modelo", icon="tune"):

                with ui.row():
                    ui.label("TEMP_LOW (mínimo ciclo)")
                    ui.slider(min=20, max=40, value=TEMP_LOW, step=0.5,
                              on_change=lambda e: globals().update(TEMP_LOW=e.value)) \
                      .props("label-always")

                with ui.row():
                    ui.label("TEMP_HIGH (máximo ciclo)")
                    ui.slider(min=35, max=50, value=TEMP_HIGH, step=0.5,
                              on_change=lambda e: globals().update(TEMP_HIGH=e.value)) \
                      .props("label-always")

                with ui.row():
                    ui.label("TEMP_CRITICO (ataque)")
                    ui.slider(min=60, max=100, value=TEMP_CRITICO, step=1,
                              on_change=lambda e: globals().update(TEMP_CRITICO=e.value)) \
                      .props("label-always")

                with ui.row():
                    ui.label("K_CYCLE (ciclo)")
                    ui.slider(min=0.005, max=0.05, value=K_CYCLE, step=0.001,
                              on_change=lambda e: globals().update(K_CYCLE=e.value)) \
                      .props("label-always")

                with ui.row():
                    ui.label("K_CRITICO (ataque)")
                    ui.slider(min=0.01, max=0.2, value=K_CRITICO, step=0.005,
                              on_change=lambda e: globals().update(K_CRITICO=e.value)) \
                      .props("label-always")

                with ui.row():
                    ui.label("K_RECUP (recuperação)")
                    ui.slider(min=0.01, max=0.1, value=K_RECUP, step=0.002,
                              on_change=lambda e: globals().update(K_RECUP=e.value)) \
                      .props("label-always")

            # ---------------- Ciclo principal ----------------
            def ciclo_simulacao():
                global temp_atual, motor_state, ultimo_dado_motor, phase

                # Receber estado do motor via UDP
                try:
                    data, addr = sock.recvfrom(1024)
                    dado = data.decode("utf-8").strip()
                    motor_state = int(dado)
                    ultimo_dado_motor = dado
                except BlockingIOError:
                    pass
                except Exception as e:
                    logger.error(f"Erro ao processar UDP: {e}")

                # Atualizar temperatura
                temp_atual = atualizar_temperatura(motor_state, temp_atual, dt=READ_INTERVAL)
                temp_enviar = round(temp_atual)

                # Escrever no PLC
                try:
                    client.write_register(address=TEMP_REGISTER, value=temp_enviar, slave=1)
                except Exception as e:
                    logger.error("Falha ao escrever no PLC1: %s", e)

                # Atualizar labels
                temp_label.set_text(f'🌡️ Temperatura: {temp_atual:.2f} ºC | 📤 Enviado: {temp_enviar} ºC')
                estado_label.set_text(f'⚙️ Motor: {"ON" if motor_state else "OFF"} | Phase: {phase}')
                clock_label.set_text(f'🕒 {datetime.now().strftime("%H:%M:%S")}')
                debug_label.set_text(f"Último dado: {ultimo_dado_motor} | Tempo decorrido: {int(time()-start_time)}s")

                # Atualizar gráfico
                tempo_atual_s = int(time() - start_time)
                data_chart = chart.options['series'][0]['data']
                x_data = chart.options['xAxis']['data']

                data_chart.append(round(temp_atual, 1))
                x_data.append(tempo_atual_s)

                if len(data_chart) > 100:
                    data_chart.pop(0)
                    x_data.pop(0)

                chart.options['series'][0]['data'] = data_chart
                chart.options['xAxis']['data'] = x_data
                chart.update()

                # Guardar histórico
                historico_temperatura.append((tempo_atual_s, temp_atual))

            ui.timer(READ_INTERVAL, ciclo_simulacao)

# ---------------- RUN ----------------
if __name__ in {"__main__", "__mp_main__"}:
    logger.info("A arrancar PLC2 simulation (escreve no PLC1 %s:%s)", PLC1_IP, PLC1_PORT)
    ui.run(port=8081, reload=False)
