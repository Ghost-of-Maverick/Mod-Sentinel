#!/usr/bin/env bash
set -euo pipefail

# Verificação de sudo
if [ "$EUID" -ne 0 ]; then
    echo "Este script precisa de ser corrido com sudo."
    echo "Use: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$LOG_DIR/modbus_reader_$(date +'%Y%m%d_%H%M%S').log"

echo "A iniciar leitura de registos Modbus..."
echo "Logs serão gravados em: $LOG_FILE"
echo "Pressiona CTRL+C para parar."

python3 -u "$SCRIPT_DIR/modbus_reader.py" 2>&1 | tee -a "$LOG_FILE"
