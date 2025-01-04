### AS Ping CLI



Ping a ASN with one line command



##### Install

```bash
# Check Python version (Require Python 3.6 or higher)
python3 --version

# Install dependencies
apt install fping python3-pip python3-venv
test ! -e /tmp/venv/python3 && python3 -m venv /tmp/venv/python3
/tmp/venv/python3/bin/python3 -m pip install -U pip
/tmp/venv/python3/bin/python3 -m pip install -U aiohttp ipaddress numpy typer
```



##### Use

```bash
# Show help information
/tmp/venv/python3/bin/python3 as_ping_cli.py --help

# Ping ${asn}
/tmp/venv/python3/bin/python3 as_ping_cli.py -a ${asn} -s 50 -p 20
```

