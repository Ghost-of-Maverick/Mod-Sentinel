#!/usr/bin/env python3
import socket
import logging
import math
import random
from datetime import datetime
import time
from pymodbus.client import ModbusTcpClient
from nicegui import ui, app
import matplotlib.pyplot as plt
import os
import shutil
from typing import Optional, Tuple

# ---------------- CONFIG ----------------
PLC1_IP = "172.27.224.250"
PLC1_PORT = 502
TEMP_REGISTER = 6

UDP_LISTEN_IP = "0.0.0.0"
UDP_LISTEN_PORT = 5005

# Limites de segurança
TEMP_MIN = 15.0
TEMP_MAX = 150.0  # apenas limite gráfico/segurança

# Constantes físicas (default)
K_CYCLE = 0.015     # ciclo natural (motor ON)
K_CRITICO = 0.05    # subida rápida (motor OFF)
K_RECUP = 0.03      # recuperação pós-ataque

READ_INTERVAL = 1.0  # segundos

RUIDO = 0.0  # intensidade do ruído (slider controla isto)

# ---------------- ESTADO ----------------
temp_atual = 40.0
motor_state = 1          # motor ON por defeito
ultimo_dado_motor = None
start_time = time.time()

phase = "ciclo"          # ciclo / ataque / recuperacao
alvo = 30.0              # alvo inicial
historico_temperatura = []

# Globals para conexões que serão inicializadas no main
client = None
modbus_connected = False
sock = None

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("PLC2")

# ---------------- FUNÇÕES DE RECONEXÃO / CREATION ----------------
def get_modbus_client() -> Tuple[Optional[ModbusTcpClient], bool]:
    try:
        c = ModbusTcpClient(PLC1_IP, port=PLC1_PORT)
        ok = c.connect()
        if ok:
            logger.info("Ligação Modbus estabelecida com PLC1 %s:%s", PLC1_IP, PLC1_PORT)
            return c, True
        else:
            logger.error("Não foi possível conectar ao PLC1 %s:%s", PLC1_IP, PLC1_PORT)
            try:
                c.close()
            except Exception:
                pass
            return c, False
    except Exception as e:
        logger.exception("Excepção ao criar Modbus client: %s", e)
        return None, False

def get_udp_socket():
    tries = 0
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((UDP_LISTEN_IP, UDP_LISTEN_PORT))
            s.setblocking(False)
            logger.info("UDP listener à escuta em %s:%s", UDP_LISTEN_IP, UDP_LISTEN_PORT)
            return s
        except OSError as e:
            tries += 1
            logger.error("Erro ao fazer bind UDP (try %d): %s", tries, e)
            try:
                s.close()
            except Exception:
                pass
            time.sleep(1)
            if tries >= 5:
                logger.warning("Continuando com tentativas contínuas para recriar socket UDP...")
                time.sleep(5)

# ---------------- FUNÇÃO PARA SALVAR PNG ----------------
def salvar_grafico_png():
    global historico_temperatura
    if not historico_temperatura:
        logger.warning("Não há dados para salvar.")
        return

    # Prepara dados
    tempos, temperaturas = zip(*historico_temperatura)
    plt.figure(figsize=(10, 6))
    plt.plot(tempos, temperaturas, marker='o', linestyle='-', color='orange')
    plt.xlabel("Tempo (s)")
    plt.ylabel("Temperatura (°C)")
    plt.title("Histórico de Temperatura PLC2")
    plt.grid(True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"grafico_temperatura_{timestamp}.png"

    # Salva de forma segura
    try:
        tmpfile = filename + ".tmp.png"
        plt.savefig(tmpfile)
        plt.close()
        shutil.move(tmpfile, filename)
        logger.info("Gráfico salvo como %s", filename)
    except Exception as e:
        logger.exception("Falha ao salvar gráfico: %s", e)

# ---------------- MODELO FÍSICO ----------------
def atualizar_temperatura(motor_state_local, temp, dt=1.0):
    global phase, alvo, K_CYCLE, K_CRITICO, K_RECUP, RUIDO

    temp_base = temp  # base para cálculos de fase

    if motor_state_local == 1:
        if phase in ["ataque", "recuperacao"]:
            phase = "recuperacao"
            delta = (alvo - temp_base) * (1 - math.exp(-K_RECUP * dt))
            temp_base += delta
            if abs(temp_base - alvo) < 0.5:
                phase = "ciclo"
                alvo = random.uniform(29.5, 31.5) if temp_base > 35 else random.uniform(40.0, 43.0)
        else:
            phase = "ciclo"
            delta = (alvo - temp_base) * (1 - math.exp(-K_CYCLE * dt))
            temp_base += delta
            if abs(temp_base - alvo) < 0.3:
                if alvo < 35:
                    alvo = random.uniform(40.0, 43.0)
                else:
                    alvo = random.uniform(29.5, 31.5)
    else:
        phase = "ataque"
        ganho = 1 + random.uniform(-0.1, 0.1)
        temp_base += K_CRITICO * dt * ganho

    # Adiciona ruído limitado
    if RUIDO > 0:
        temp_ruido = random.uniform(-RUIDO, RUIDO)
        # garante que o ruído não reduz temp abaixo de 29.5
        temp = max(29.5, temp_base + temp_ruido)
    else:
        temp = temp_base

    # Limita ao máximo gráfico/segurança
    temp = min(temp, TEMP_MAX)

    return temp

# ---------------- GUI ----------------
@ui.page('/')
def index():
    global temp_atual, motor_state, ultimo_dado_motor, start_time, phase, alvo
    global K_CYCLE, K_CRITICO, K_RECUP, historico_temperatura

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
                    # reset globals
                    globals().update(temp_atual=40.0, phase="ciclo", alvo=30.0, start_time=time.time(), motor_state=1)
                ui.button("🔄 Resetar Simulação", on_click=resetar, color="red")

            # ---------------- Sliders ----------------
            with ui.expansion("⚙️ Ajustes do Modelo", icon="tune"):

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
                
                with ui.row():
                    ui.label("Ruído")
                    ui.slider(min=0.0, max=2.0, value=RUIDO, step=0.1,
                            on_change=lambda e: globals().update(RUIDO=e.value)) \
                    .props("label-always")

            # ---------------- Ciclo principal ----------------
            def ciclo_simulacao():
                global temp_atual, motor_state, ultimo_dado_motor, phase
                global client, modbus_connected, sock, historico_temperatura

                # Tenta reconectar Modbus se necessário
                if not modbus_connected or client is None:
                    logger.warning("Ligação Modbus não activa, a tentar reconectar...")
                    new_client, ok = get_modbus_client()
                    if new_client:
                        client = new_client
                    modbus_connected = ok

                # Receber estado do motor via UDP
                try:
                    data, addr = sock.recvfrom(1024)
                    dado = data.decode("utf-8").strip()
                    motor_state = int(dado)
                    ultimo_dado_motor = dado
                except BlockingIOError:
                    # nenhum dado recebido — normal
                    pass
                except OSError as e:
                    # erro socket -> recriar
                    logger.error("Erro UDP (OSError): %s — a recriar socket", e)
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = get_udp_socket()
                except Exception as e:
                    logger.exception("Erro ao processar UDP: %s", e)
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = get_udp_socket()

                # Atualizar temperatura
                temp_atual = atualizar_temperatura(motor_state, temp_atual, dt=READ_INTERVAL)
                temp_enviar = round(temp_atual)

                # Escrever no PLC (Modbus)
                if client and modbus_connected:
                    try:
                        # usando write_register; captura falhas e força reconexão
                        client.write_register(address=TEMP_REGISTER, value=temp_enviar, slave=1)
                    except Exception as e:
                        logger.error("Falha ao escrever no PLC1: %s", e)
                        try:
                            client.close()
                        except Exception:
                            pass
                        client = None
                        modbus_connected = False
                else:
                    logger.debug("Ignorando escrita Modbus porque não há ligação ativa")

                # Atualizar labels
                if app.clients:
                    temp_label.set_text(f'🌡️ Temperatura: {temp_atual:.2f} ºC | 📤 Enviado: {temp_enviar} ºC')
                    estado_label.set_text(f'⚙️ Motor: {"ON" if motor_state else "OFF"} | Phase: {phase}')
                    clock_label.set_text(f'🕒 {datetime.now().strftime("%H:%M:%S")}')
                    debug_label.set_text(f"Último dado motor: {ultimo_dado_motor} | Tempo decorrido: {int(time.time()-start_time)}s")

                    # Atualizar gráfico
                    tempo_atual_s = int(time.time() - start_time)
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
                tempo_atual_s = int(time.time() - start_time)
                historico_temperatura.append((tempo_atual_s, temp_atual))

            ui.timer(READ_INTERVAL, ciclo_simulacao)

# ---------------- RUN ----------------
if __name__ in {"__main__", "__mp_main__"}:
    logger.info("A arrancar PLC2 simulation (escreve no PLC1 %s:%s)", PLC1_IP, PLC1_PORT)

    # Inicializa conexões com lógica de recuperação
    client, modbus_connected = get_modbus_client()
    sock = get_udp_socket()

    ui.run(port=8081, reload=False)