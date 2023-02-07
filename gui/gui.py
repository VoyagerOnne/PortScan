import kivy
from kivy.app import App 
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout

import threading  # для мультипоточности
import socket  # само сканирование
import sys  # для получения аргументов
from datetime import datetime

from kivy.core.window import Window


Window.title = "Scan"
Window.size = (600, 300)
Window.clearcolor = (0.15, 0.15, 0.15, 0)

class MyApp(App):

    def __init__(self):
        super().__init__()
        self.label = Label(text="GUAP scaner")
        self.port = Label(text="")
        self.input_data = TextInput(hint_text='Введите IP', multiline=False)
        self.btn = Button(text="Сканировать!", on_press=self.on_text)

    def on_text(self, *args):
        data = self.input_data.text
        scan = scaner(data)
        self.port.text = 'Открытые порты: ' + str(scan)
            
    
    def build(self):
        box = BoxLayout(orientation='vertical', spacing=7, padding=[10])
        box.add_widget(self.label)
        box.add_widget(self.input_data)
        box.add_widget(self.btn)
        box.add_widget(self.port)

        return box


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

    SENCES = ("-c" in sys.argv)

    for port in range(1, 1000):
        potoc = threading.Thread(target=scan_port, args=(target, port))
        potoc.start()
    ends = datetime.now()
    o_ports = ", ".join(OPEN_PORTS)
    return o_ports


if __name__ == '__main__':
    MyApp().run()