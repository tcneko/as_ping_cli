### AS Ping CLI



Ping a ASN with one line command



##### Install

```bash
# Check Python version (Require Python 3.6 or higher)
python3 --version

# Install dependencies
apt install fping
python3 -m pip --no-cache-dir install aiohttp ipaddress numpy typer
```



##### Use

```bash
# Show help information
python3 as_ping_cli.py --help

# Ping ${asn}
python3 as_ping_cli.py -a ${asn} -s 50 -p 20
```

