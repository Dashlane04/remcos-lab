#!/usr/bin/env python3
"""Update only the two non-secret WSL collector addresses; never evaluate .env."""
import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path
import re
import tempfile


def private_ipv4(value):
    address = ipaddress.IPv4Address(value)
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if not any(address in ipaddress.IPv4Network(net) for net in networks):
        raise ValueError("Collector addresses must be RFC1918 IPv4 addresses")
    return str(address)


def update_addresses(root, server_ip, bind_ip):
    values = {"LAB_SERVER_IP": private_ipv4(server_ip), "DATA_BIND_IP": private_ipv4(bind_ip)}
    path = Path(root) / "infra/.env"
    if path.is_symlink():
        raise ValueError("Refusing a symlinked settings file")
    original = path.read_bytes()
    # Preserve every unrelated byte, including credentials, quotes and line endings.
    changed = original
    for name, value in values.items():
        pattern = rb"(?m)^" + name.encode() + rb"=[^\r\n]*"
        if len(re.findall(pattern, changed)) != 1:
            raise ValueError("Expected exactly one existing " + name)
        changed = re.sub(pattern, name.encode() + b"=" + value.encode(), changed)
    if changed == original:
        os.chmod(path, 0o600)
        return False
    folder = Path(root) / "data/raw/maintenance-backups"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = folder / ("addresses-" + stamp + ".env")
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(original)
    fd, temporary = tempfile.mkstemp(prefix=".env-addresses-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(changed)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--bind-ip", required=True)
    args = parser.parse_args()
    changed = update_addresses(args.root, args.server_ip, args.bind_ip)
    print("Collector address settings " + ("updated." if changed else "already match."))


if __name__ == "__main__":
    main()
