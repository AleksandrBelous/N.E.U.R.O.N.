# from scapy.all import *
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.config import conf
from scapy.supersocket import L3RawSocket
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


def handshake_sender():
    initial_seq = 100
    # Шаг 1: отправляем SYN
    SYN = TCP.SYN
    SYN[_TCP].seq = initial_seq
    print(f"[HANDSHAKE] Сервер отправил SYN на {dst.ip}")
    SYN.show2()
    SYN_ACK = L3SocketRaw.sr1(SYN, timeout=30, verbose=False)
    # for port in range(0, 2 ** 16 - 1):
    #     print(port)
    #     SYN[_TCP].port = port
    #     SYN_ACK = L3SocketRaw.sr1(SYN, timeout=30, verbose=False)
    #     if SYN_ACK is not None and SYN_ACK.haslayer(_TCP):
    #         if SYN_ACK[_TCP].flags & 0x12 == 0x12:
    #             print(f"Получен SYN-ACK на порту {port}")
    # L3SocketRaw.send(SYN)
    # SYN_ACK = L3SocketRaw.sniff(count=1)
    if SYN_ACK is None or not SYN_ACK.haslayer(_TCP):
        print("[HANDSHAKE] SYN-ACK не получен. Сервер завершает работу.")
        return None, None
    print("[HANDSHAKE] Сервер получил SYN-ACK")
    SYN_ACK.show2()
    # Шаг 2: отправляем ACK для завершения рукопожатия
    my_seq = SYN_ACK[_TCP].ack
    ack_num = SYN_ACK[_TCP].seq + 1
    ACK = TCP.ACK
    ACK[_TCP].seq = my_seq
    ACK[_TCP].ack = ack_num
    print("[HANDSHAKE] Сервер отправил ACK")
    ACK.show2()
    # L3SocketRaw.send(ACK)
    last_pkt = L3SocketRaw.sr1(ACK)
    # last_pkt = L3SocketRaw.sniff(count=1)
    print("[HANDSHAKE] Сервер завершил рукопожатие.")
    return my_seq, ack_num, last_pkt


if __name__ == "__main__":
    if L3SocketRaw is None:
        exit(1)
    # Устанавливаем соединение
    my_seq, ack_num, last_pkt = handshake_sender()
    print(f"my_seq: {my_seq}, ack_num: {ack_num}")
    print(f"Last PKT:")
    last_pkt.show2()

    # PSH_ACK = TCP.PSH_ACK
    # duration = 1  # 10 минут
    # start_time = time.time()
    #
    # while time.time() - start_time < duration:
    #     # Ожидаем ответ от клиента через сокет
    #     try:
    #         response = L3SocketRaw.recv()
    #         if response and response.haslayer(_TCP):
    #             # Если в ответе есть полезная нагрузка, увеличиваем ack на длину полученных данных
    #             data_len = len(response[_Raw].load) if response.haslayer(_Raw) else 0
    #             # Новое значение ack = sequence клиента + длина его данных
    #             ack_num = response[_TCP].seq + data_len
    #             print(f"[SENDER] Получен ответ: "
    #                   f"seq={response[_TCP].seq}, "
    #                   f"data_len={data_len} "
    #                   f"-> обновленный ack={ack_num}"
    #                   )
    #     except Exception as e:
    #         print("[SENDER] Ошибка при получении пакета:", e)
    #     # Формируем TCP-пакет с флагами PSH+ACK и полезной нагрузкой
    #     PSH_ACK[_TCP].seq = my_seq
    #     PSH_ACK[_TCP].ack = ack_num
    #     payload = f"Hello: seq={my_seq}, ack={ack_num}"  # Полезная нагрузка отправителя
    #     PSH_ACK[_Raw].load = payload
    #     L3SocketRaw.send(PSH_ACK)
    #     print(f"[SENDER] Отправлен пакет: [{payload}]")
    #     my_seq += len(payload)  # обновляем свой sequence с учетом длины полезной нагрузки
