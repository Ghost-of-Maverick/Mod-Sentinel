#!/bin/bash

# Verificação de sudo
if [ "$EUID" -ne 0 ]; then
    echo "Este script precisa de ser corrido com sudo."
    echo "Use: sudo $0"
    exit 1
fi

# Criar pasta de logs, se não existir
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# Nome do ficheiro de log com data/hora
LOG_FILE="$LOG_DIR/modbus_reader_$(date +'%Y%m%d_%H%M%S').log"

echo "A iniciar leitura de registos Modbus..."
echo "Logs serão gravados em: $LOG_FILE"
echo "Pressiona CTRL+C para parar."

# Executar script Python com logging
python3 modbus_reader.py 2>&1 | tee -a "$LOG_FILE"
