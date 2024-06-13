import threading  # для мультипоточности
import socket  # само сканирование
from datetime import datetime
import argparse  # для разбора аргументов командной строки
import ipaddress

import time
from ipaddress import IPv4Address, AddressValueError
from pprint import pprint


class WhoisClient:
    def __init__(self, server, port=43):
        self.server = server
        self.port = port

    def query(self, query_string):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server, self.port))
            s.send((query_string + '\r\n').encode())
            response = b''
            while True:
                data = s.recv(4096)
                response += data
                if not data:
                    break
        return response.decode()

class IanaWhoisClient(WhoisClient):
    def __init__(self):
        super().__init__('whois.iana.org')

    def get_whois_server(self, ip):
        response = self.query(ip)
        for line in response.splitlines():
            if line.startswith('whois'):
                return line.split(':')[1].strip()
        return None

class IpWhoisClient(WhoisClient):
    def get_whois_info(self, ip):
        response = self.query(ip)
        whois_info = {}
        num = 0
        for line in response.splitlines():
            if line.strip().startswith('%') or not line.strip():
                continue
            key, value = line.strip().split(': ', 1)
            if key in ['created', 'last-modified']:
                dt = datetime.fromisoformat(value.strip()).strftime("%Y-%m-%d %H:%M:%S")
                whois_info[f"{key}_{num}"] = dt
                num += 1
            else:
                whois_info[key.strip()] = value.strip()
        return whois_info if whois_info else None

class IpValidator:
    @staticmethod
    def validate(ip):
        try:
            IPv4Address(ip)
            return True
        except AddressValueError:
            print('IP-адрес не валидный')
            return False

class WhoisService:
    def __init__(self):
        self.iana_client = IanaWhoisClient()
        self.default_whois_server = 'whois.ripe.net'

    def get_ip_info(self, ip):
        if not IpValidator.validate(ip):
            return

        whois_server = self.iana_client.get_whois_server(ip)
        if not whois_server:
            print('Произошла ошибка! будет использован стандартный регистратор whois.ripe.net')
            whois_server = self.default_whois_server

        time.sleep(1)

        ip_client = IpWhoisClient(whois_server)
        info = ip_client.get_whois_info(ip)
        if info:
            pprint(info)
        else:
            print('Не удалось получить данные об IP-адресе')



class PortScanner:
    def __init__(self):
        self.open_ports = []

    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            sock.connect((ip, port))
            service = self.get_service(ip, port)
            version = self.get_version(sock, port)
            self.open_ports.append((port, service, version))
            sock.close()
        except:
            pass

    def scan(self, ip, port_range=(1, 1000)):
        # Очистка списка открытых портов перед каждым запуском сканирования
        self.open_ports = []

        threads = []

        for port in range(port_range[0], port_range[1] + 1):
            thread = threading.Thread(target=self.scan_port, args=(ip, port))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        open_ports_str = ""
        if len(self.open_ports) > 0:
            open_ports_str = "port\tserv\tversion\n" + "\n".join([f"\n{port}\t{service}\n{version}" for port, service, version in self.open_ports]) + "\n"
        return open_ports_str

    def get_service(self, ip, port):
        try:
            if port == 80 or port == 443:
                return f'{socket.getservbyport(port)}\t{socket.gethostbyaddr(ip)[0]}'
            return socket.getservbyport(port)
        except:
            try:
                return socket.getservbyport(port) + "?"
            except:
                return "unknown"

    def get_version(self, sock, port):
        try:
            if port == 80 or port == 443:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 21:
                sock.sendall(b"USER anonymous\r\n")
            elif port == 22:
                sock.sendall(b"\r\n")
            elif port == 25:
                sock.sendall(b"HELO localhost\r\n")
            else:
                sock.sendall(b"\r\n")

            response = sock.recv(1024).decode().strip()
            return "\n".join(response.split("\n") if response else "")
        except:
            return ""

def parse_ip_range(ip_range_str):
    addrs = []
    net = ipaddress.ip_network(ip_range_str, False).hosts()
    for addr in net:
        addrs.append(str(addr))
    return addrs

if __name__ == "__main__":
    print('VoyagerOnne says hello to you!\n')
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("ip_range", help="IP range to scan (e.g., 10.0.0.0/24)", type=parse_ip_range)
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1000)", default="1-1000")
    
    args = parser.parse_args()
    port_range = tuple(map(int, args.ports.split('-')))
    scanner = PortScanner()
    open_ports = scanner.scan(args.ip_range, port_range)
    
    t_start = datetime.now()
    for ip in args.ip_range:
        print(f"info for {ip}:")
        print(f"{scanner.scan(ip, port_range)}")

    t_end = datetime.now()

    print(f"Scan duration: {t_end - t_start}")

    if len(args.ip_range) == 1:
        f = input("Are you wont get web info about this target? y/n\t")
        if f == 'y' or f == 'Y' or f == '\n' or f == '':
            try:
                whois_service = WhoisService()
                whois_service.get_ip_info(args.ip_range[0])
            except:
                print("\nSorry, this host haven't open 80 or 443 port :( ")
        print('\nVoyagerOnne sends you bye!')
