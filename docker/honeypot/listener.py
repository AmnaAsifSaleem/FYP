#!/usr/bin/env python3
"""
listener.py — Lightweight multi-port ICS honeypot for the CAVE-OT Docker testbed.

Replaces the VMware VM's Conpot containers. Binds every device port the plant
uses (from the PORTS env var) and answers connections with a small canned,
protocol-flavoured blob — which is all the CAVE-OT pipeline actually needs:
a port that's open, that accepts a connection, and that sends *a* response so
packets flow and get captured. Discovery (smart_discover.py) and the Suricata
rules key off the destination PORT, not deep protocol emulation, so faithful
port coverage matters far more than realistic Modbus/S7/DNP3 state machines.

Why not real Conpot: the honeynet/conpot image only listens on Conpot's default
ports (502/102/161/80/47808/623...). The plant uses a custom scheme (10201,
5031, 5032, 20001, 2222, 10203, 10204, ...) that Conpot does not serve without
extensive per-device template config. These listeners serve exactly the 15
device ports, reliably and reproducibly.

Config via env:
  TCP_PORTS  comma-separated TCP ports to listen on
  UDP_PORTS  comma-separated UDP ports to listen on
"""

import os
import socket
import threading

# Canned, vaguely-protocol-shaped replies keyed by port. Anything unknown gets
# a generic ACK blob. The traffic generators just do recv(256) and are happy
# with any bytes back.
CANNED = {
    502:   bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x64]),  # modbus read-holding resp
    5020:  bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x64]),
    5031:  bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x64]),
    5032:  bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x64]),
    10201: bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a]),  # s7 COTP CC
    10203: bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a]),
    10204: bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a]),
    20000: bytes([0x05, 0x64, 0x0a, 0x44, 0x03, 0x00, 0x01, 0x00, 0xe9, 0x21]),  # dnp3 link header
    20001: bytes([0x05, 0x64, 0x0a, 0x44, 0x03, 0x00, 0x01, 0x00, 0xe9, 0x21]),
    80:    b"HTTP/1.1 200 OK\r\nServer: WinCC-OA/3.17\r\nContent-Length: 2\r\n\r\nOK",
    8080:  b"HTTP/1.1 200 OK\r\nServer: WinCC-OA/3.15\r\nContent-Length: 2\r\n\r\nOK",
    443:   b"HTTP/1.1 200 OK\r\nServer: PI-Server/3.4.400\r\nContent-Length: 2\r\n\r\nOK",
    6230:  bytes([0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00]),  # ipmi-ish
    2222:  b"SSH-2.0-Cisco-ASA-9.16.4\r\n",
    47808: bytes([0x81, 0x0a, 0x00, 0x0c, 0x01, 0x00, 0x30, 0x01, 0x75, 0x00, 0x3e, 0x91]),  # bacnet i-am
}
GENERIC = bytes([0x00, 0x00, 0x00, 0x01])


def serve_tcp(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    print(f"[listener] TCP :{port} up", flush=True)
    reply = CANNED.get(port, GENERIC)
    while True:
        try:
            conn, _addr = s.accept()
            threading.Thread(target=_handle_tcp, args=(conn, reply), daemon=True).start()
        except Exception as e:
            print(f"[listener] TCP :{port} accept error: {e}", flush=True)


def _handle_tcp(conn, reply):
    try:
        conn.settimeout(3)
        try:
            conn.recv(1024)
        except Exception:
            pass
        conn.sendall(reply)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve_udp(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    print(f"[listener] UDP :{port} up", flush=True)
    reply = CANNED.get(port, GENERIC)
    while True:
        try:
            _data, addr = s.recvfrom(2048)
            s.sendto(reply, addr)
        except Exception as e:
            print(f"[listener] UDP :{port} error: {e}", flush=True)


def _parse(env_val):
    return [int(p) for p in env_val.replace(" ", "").split(",") if p]


if __name__ == "__main__":
    tcp_ports = _parse(os.environ.get("TCP_PORTS", ""))
    udp_ports = _parse(os.environ.get("UDP_PORTS", ""))
    print(f"[listener] starting — TCP={tcp_ports} UDP={udp_ports}", flush=True)

    for p in tcp_ports:
        threading.Thread(target=serve_tcp, args=(p,), daemon=True).start()
    for p in udp_ports:
        threading.Thread(target=serve_udp, args=(p,), daemon=True).start()

    # Keep the main thread alive
    threading.Event().wait()
