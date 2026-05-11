# Personal Firewall (Linux)

Lightweight personal firewall prototype that sniffs packets in real time, applies rule-based filtering, and uses iptables for blocking. Includes a terminal flow and an optional CustomTkinter UI.

## Features

- Live packet capture (TCP, UDP, ICMP)
- Rule engine with blacklist support
- iptables-based blocking with cleanup on exit
- Logging to firewall.log
- Optional UI with live log, stats, and blacklist editor

## Requirements

- Ubuntu 24.04 LTS
- Python 3.12+
- iptables
- Root privileges (sniffing + iptables)

## Setup

Create and activate a venv (example):

```
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

Install Tkinter (needed for UI):

```
sudo apt update
sudo apt install python3-tk
```

## Run (CLI)

```
./run.sh
```

Or:

```
sudo /path/to/project/.venv/bin/python /path/to/project/main.py
```

## Run (UI)

```
./run-ui.sh
```

Or:

```
sudo /path/to/project/.venv/bin/python /path/to/project/ui.py
```

## Blacklist

Edit blacklist.txt and add one IP per line. Lines starting with # are ignored.

## Logs

All events are appended to firewall.log with timestamps, action, direction, protocol, and endpoints.

## Notes

- iptables rules persist until removed. The app cleans up rules it adds on exit, but you can flush manually if needed:
  - sudo iptables -F
- Test with safe IPs to avoid blocking critical services.

