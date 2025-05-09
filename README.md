## 🛡️ModSentinel

O **ModSentinel** é uma aplicação Python de deteção de anomalias e ataques ao protocolo Modbus, focado na proteção de infraestruturas industriais. Foi desenvolvido para funcionar de forma passiva em modo sniffer, analisando o tráfego de rede industrial em tempo real uma vez que funciona como um Daemon.

## 📦 Clonagem do Projeto

```bash
git clone https://github.com/Ghost-of-Maverick/ModSentinel.git
cd Mod-Sentinel
```

## ⚙️ Requisitos

Certificar de que tens o Python 3.8+ está instalado. Depois, instalar os requisitos:
```bash
pip install -r requirements.txt
```

## 🚀 Execução

A aplicação pode ser iniciada, parada ou reiniciada através do comando principal:
```bash
python main.py [start|stop|restart|help]
```

Exemplos:
   - `python main.py start` – inicia o ModSentinel
   - `python main.py stop` – para o processo em execução
   - `python main.py restart` – reinicia a aplicação
   - `python main.py help` – mostra os comandos que podem ser utilizados

## ⚠️ Configuração (config.yaml)
```yaml
interface: eth1

# Modos de debug/teste
verbose_mode: true # modo verbose ativo/desativo
test_mode: true    # gera pacotes artificiais periodicamente
test_interval: 5   # intervalo em segundos para pacotes artificiais

MODBUS_CLIENT:
  - 172.27.224.10

MODBUS_SERVER:
  - 172.27.224.250

rules_file: rules/modsentinel.rules
```
 - `interface`: interface de rede onde o sniffer vai escutar
 - `verbose_mode`: mostra _logs_ detalhados em consola
 - `test_mode`: ativa envio de pacotes Modbus de teste
 - `test_interval`: intervalo de envio dos pacotes de teste
 - `rules_file`: caminho para as regras de deteção
 - `MODBUS_CLIENT`: clientes Modbus
 - `MODBUS_SERVER`: servidor Modbus

## 🕵️ Regras de deteção

As regras estão definidas no estilo Snort e suportam:
  - `content`, `offset`, `depth`, `msg`, `sid`, `priority`
  - Variáveis como `$MODBUS_CLIENT`, `$MODBUS_SERVER` - definidas no ficheiro `config.yaml`
  - Regras de teste com payloads artificiais (ex: `|63|`)

Exemplo de regra:

```
alert tcp $MODBUS_CLIENT any -> $MODBUS_SERVER 502 (
    content:"|08 00 04|"; offset:7; depth:3;
    msg:"SCADA_IDS: Modbus TCP - Force Listen Only Mode";
    sid:1111001; priority:1;
)
```

## 📂 Logs

Os eventos são registados em:
  - `logs/app.log` - logs internos do Mod Sentinel
  - `logs/modguard.log` - deteções e pacotes analisados
