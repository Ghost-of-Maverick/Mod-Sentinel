from nicegui import ui
import pymodbus.client as ModbusClient
import pandas as pd

# Carregar e preparar lista de temperaturas
df = pd.read_csv("MetroPT3_interpolado.csv", low_memory=False)  # evita o aviso
temperaturas_interpoladas = df['temperatura_nova'].tolist()
temp_index = 0  # índice global da leitura atual

@ui.page("/")
def index():
    def sync_temp():
        global temp_index

        if temp_index < len(temperaturas_interpoladas):
            temp_lido = temperaturas_interpoladas[temp_index]
            temp_enviar = round(temp_lido)
            temp_index += 1
        else:
            temp_lido = 30.0
            temp_enviar = 30

        # Enviar para o PLC
        client = ModbusClient.ModbusTcpClient('172.27.224.250')
        client.connect()
        client.write_register(address=6, value=temp_enviar, slave=1, no_response_expected=False)
        client.close()

        # Atualizar interface
        knob.set_value(temp_enviar)
        temp_label.set_text(
            f'📊 Index: {temp_index} | '
            f'🌡️ Lido: {temp_lido:.3f} ºC | '
            f'📤 Enviado: {temp_enviar} ºC | '
            f'⏱️ Tempo: {temp_index} s'
        )

    with ui.column().classes('items-center justify-center w-full'):
        ui.label("🧠 Simulação de Temperatura RTU → PLC").classes('text-2xl font-bold text-blue-700')

        with ui.row().classes("items-center justify-center gap-8 mt-4"):
            global knob
            knob = ui.knob(30, show_value=True, step=1, size="128px", min=0, max=99)
            knob.disable()

            global temp_label
            temp_label = ui.label(
                f'📊 Index: 0 | 🌡️ Lido: 30.000 ºC | 📤 Enviado: 30 ºC | ⏱️ Tempo: 0 s'
            ).classes('text-lg text-blue-600')

        with ui.row().classes("mt-6"):
            ui.mermaid('''graph LR; RTU["RTU"] --> PLC["PLC"]''')

    ui.timer(1.0, sync_temp, immediate=True)

ui.run(port=8081)
