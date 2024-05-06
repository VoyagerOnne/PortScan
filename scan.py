import threading  # для мультипоточности
import socket  # само сканирование
import sys  # для получения аргументов
from datetime import datetime


# new commit 2
OPEN_PORTS = []
def scaner(IP):
    start = datetime.now()
    def scan_port(ip, port):
        global OPEN_PORTS

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            connect = sock.connect((ip, port))
            OPEN_PORTS.append(str(port))
            sock.close()
        except:
            pass

    target = IP
    CLOSED_PORTS = []

    for port in range(1, 1000):
        potoc = threading.Thread(target=scan_port, args=(target, port))
        potoc.start()
    ends = datetime.now()
    o_ports = " ".join(OPEN_PORTS)
    return o_ports
