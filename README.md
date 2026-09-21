# DPIveil

DPIveil is a lightweight Windows command-line network traffic tool written in Python.

The project is currently in its initial development stage. The first milestone is a stable CLI core with administrator checks, profile loading, logging, graceful shutdown, and WinDivert/PyDivert integration.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Press `Ctrl+C` to stop DPIveil cleanly.

## Project status

The packet-processing strategies are intentionally kept separate from the application lifecycle. This makes it easier to test profiles independently and add new strategies without touching the CLI or logging code.
