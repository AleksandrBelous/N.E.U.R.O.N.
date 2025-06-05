# from scapy.all import *
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.config import conf
from scapy.supersocket import L3RawSocket
from scapy.sendrecv import sniff
from params import src, dst
from protocols.L4 import _TCP, _Raw, TCP

# Конфигурация
L3SocketRaw = L3RawSocket()
TCP = TCP(src=src, dst=dst)

import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', 12346))
server_socket.listen(5)
print("Сервер запущен на порту 12346")


#
# while True:
#     conn, addr = server_socket.accept()
#     print("Подключение от", addr)
#     conn.close()


def handshake_receiver():
    print("[HANDSHAKE] Клиент ожидает SYN ...")
    # Используем BPF-фильтр для ожидания TCP-пакета с флагом SYN
    bpf_filter_syn = " and ".join([TCP.tcp_filter, f"src host {src.ip}", f"dst host {dst.ip}"])
    syn_packets = L3SocketRaw.sniff(filter=bpf_filter_syn, count=1, timeout=60)
    if not syn_packets:
        print("[HANDSHAKE] SYN не получен. Клиент завершает работу.")
        exit(1)
    SYN = syn_packets[0]
    if not SYN.haslayer(_TCP):
        print("[HANDSHAKE] Получен пакет без TCP. Клиент завершает работу.")
        return None, None
    print("[HANDSHAKE] Клиент получил SYN от отправителя")
    SYN.show2()
    # client_seq = 2000  # Начальное значение sequence клиента
    # ack_num = SYN[_TCP].seq + 1
    #
    # # Формируем и отправляем SYN-ACK
    # SYN_ACK = TCP.SYN_ACK
    # SYN_ACK[_TCP].seq = client_seq
    # SYN_ACK[_TCP].ack = ack_num
    # print("[HANDSHAKE] Клиент сформировал SYN-ACK")
    # SYN_ACK.show2()
    # L3SocketRaw.send(SYN_ACK)
    # ACK = L3SocketRaw.sr1(SYN_ACK, timeout=1)
    # print("[HANDSHAKE] Клиент отправил SYN-ACK")
    print("[HANDSHAKE] Клиент ожидает ACK ...")
    # Ожидаем ACK от отправителя для завершения рукопожатия
    bpf_filter_ack = " and ".join([TCP.tcp_filter, f"src host {src.ip}", f"dst host {dst.ip}", TCP.ACK_filter])
    ack_packets = L3SocketRaw.sniff(filter=bpf_filter_ack, count=1, timeout=60)
    if not ack_packets:
        print("[HANDSHAKE] ACK не получен. Клиент завершает работу.")
        return None, None
    ACK = ack_packets[0]
    ACK = L3SocketRaw.recv()
    print("[HANDSHAKE] Клиент получил ACK")
    ACK.show2()
    print("[HANDSHAKE] Клиент завершает рукопожатие.")
    # client_seq += 1  # инкремент после SYN-ACK (как в стандартном TCP)
    # sender_seq = ACK[_TCP].seq  # sequence отправителя для передачи данных
    return client_seq, sender_seq


if __name__ == "__main__":
    if L3SocketRaw is None:
        exit(1)
    client_seq, sender_seq = handshake_receiver()
    print(f"client_seq: {client_seq}, sender_seq: {sender_seq}")
    # payload = "Response"  # Полезная нагрузка клиента
    #
    #
    # def packet_handler(pkt):
    #     global client_seq
    #     if pkt.haslayer(_TCP) and pkt.haslayer(_Raw):
    #         data = pkt[_Raw].load
    #         print(f"[CLIENT] Получен пакет: seq={pkt[_TCP].seq}, data={data}")
    #         payload_len = len(data)
    #         new_ack = pkt[_TCP].seq + payload_len
    #         PSH_ACK = TCP.PSH_ACK
    #         PSH_ACK[_TCP].seq = client_seq  # client_seq - глобальная или внешняя переменная
    #         PSH_ACK[_TCP].ack = new_ack
    #         PSH_ACK[_Raw].load = f"{payload}: seq={client_seq}, ack={new_ack}"
    #         L3SocketRaw.send(PSH_ACK)
    #         print(f"[CLIENT] Отправлен ответ: seq={client_seq}, ack={new_ack}")
    #         # Обновление client_seq происходит здесь
    #         client_seq += len(payload)
    #
    #
    # try:
    #     sniff(filter=f"tcp and src host {src.ip} and dst host {dst.ip}", prn=packet_handler)
    # except Exception as e:
    #     print("[CLIENT] Ошибка при обмене пакетами:", e)
