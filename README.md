# Mod Sentinel

Mod Sentinel is a daemon that passively monitors Modbus/TCP and ARP traffic. It uses tshark to capture packets, applies detection rules and logs all traffic to CSV and log files.

## Requirements

- Python 3.8+
- `tshark` command line tool

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Running

Start the daemon:

```bash
python main.py start
```

Stop the daemon:

```bash
python main.py stop
```

Captured traffic is stored in the `logs/` directory.
