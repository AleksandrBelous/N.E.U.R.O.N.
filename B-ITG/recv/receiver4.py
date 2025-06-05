# receiver.py
import socket
from scapy.all import *
from scapy.layers.inet import *
import time

port = 12345
# Фиктивный сокет для захвата порта
dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dummy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# dummy_socket.bind(('0.0.0.0', port))  # Укажите ваш порт
dummy_socket.listen(1)  # Переводим в режим прослушивания
dummy_socket.close()


def handle_packet(pkt):
    if TCP in pkt and pkt[TCP].dport == port and pkt[TCP].flags == 'S':
        print("[Scapy] Получен SYN")
        # Формируем SYN-ACK
        ack = pkt[TCP].seq + 1
        syn_ack = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
                sport=pkt[TCP].dport,
                dport=pkt[TCP].sport,
                flags='SA',
                seq=1000,
                ack=ack
                )
        send(syn_ack, verbose=0)
        print("[Scapy] Отправлен SYN-ACK")


# Запускаем сниффер
print("[Scapy] start sniffer")
sniff(filter=f"tcp port {port}", prn=handle_packet, store=0)
