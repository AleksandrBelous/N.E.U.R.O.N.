import asyncio
import socket
import time
import numpy as np
from ScapyTrafficDistributionGenerator import generate_distribution, plot_ecdf, plot_density
from params import dst


# Асинхронная функция для ожидания до target_time (точное управление таймингом)
async def async_sleep_until(target_time):
    # now = time.perf_counter()
    try:
        await asyncio.sleep(target_time - time.perf_counter())
    except asyncio.CancelledError as e:
        print(e)
        return


class AsyncSender:
    """
    Асинхронный отправитель пакетов, который:
        - использует постоянные TCP и UDP сокеты (persistent connections),
        - для каждого секундного интервала отправляет пакеты с равномерным интервалом,
        - принимает число пакетов для этой секунды из distribution.

    Для TCP учитывается, что на каждый отправленный запрос придёт ответ.
    Поэтому если в distribution указано, например, 450 пакетов в секунду,
    то мы выделяем 90% (примерно 405) на TCP – что приведёт к 405 запросам и 405 ответам (810 TCP-пакетов)
    и 10% (45) UDP-пакетов, итого ~855 пакетов/сек.
    """

    def __init__(self):
        self.dst_ip = dst.ip
        self.dst_port = dst.port
        self.tcp_sock = None
        self.udp_sock = None
        self.tcp_count = 0
        self.udp_count = 0

    async def init_tcp_connection(self):
        """
        Открывает новое TCP-соединение (неблокирующий режим) для текущей сессии.
        """
        loop = asyncio.get_event_loop()
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setblocking(False)
        await loop.sock_connect(self.tcp_sock, (self.dst_ip, self.dst_port))
        # print(f"[TCP] Соединение установлено с {self.dst_ip}:{self.dst_port}")

    async def close_tcp_connection(self):
        """
        Закрывает TCP-соединение, завершив текущую сессию.
        """
        if self.tcp_sock:
            self.tcp_sock.close()
            self.tcp_sock = None
            # print("[TCP] Соединение закрыто.")

    async def init_udp_socket(self):
        """
        Инициализирует один UDP-сокет, который будет использоваться для всех сессий.
        """
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setblocking(False)

    async def close_udp_socket(self):
        """
        Закрывает UDP-сокет.
        """
        if self.udp_sock:
            self.udp_sock.close()
            self.udp_sock = None
            print("[UDP] Сокет закрыт.")

    async def send_tcp_burst(self):
        """
        Отправляет burst TCP-пакетов за одну секунду.
        tcp_count – число TCP запросов (на каждый из них сервер ответит, удваивая трафик).
        """
        if self.tcp_count <= 0:
            return
        await self.init_tcp_connection()  # открываем TCP-соединение для текущей сессии
        interval = 1.0 / self.tcp_count
        start_time = time.perf_counter()
        loop = asyncio.get_event_loop()
        for i in range(self.tcp_count):
            msg = f"TCP | {i}".encode()
            try:
                await loop.sock_sendall(self.tcp_sock, msg)
            except Exception as e:
                print(f"Ошибка отправки TCP пакета {i}: {e}")
            await async_sleep_until(start_time + (i + 1) * interval)
        # Если до конца секунды осталось время, ждем его
        await async_sleep_until(start_time + 1.0)
        await self.close_tcp_connection()  # закрываем TCP-соединение по окончании сессии

    async def send_udp_burst(self):
        """
        Отправляет burst UDP-пакетов за одну секунду.
        udp_count – число UDP пакетов.
        """
        if self.udp_count <= 0:
            return
        interval = 1.0 / self.udp_count
        start_time = time.perf_counter()
        loop = asyncio.get_event_loop()
        for i in range(self.udp_count):
            msg = f"UDP | {i}".encode()
            try:
                await loop.sock_sendto(self.udp_sock, msg, (self.dst_ip, self.dst_port))
            except Exception as e:
                print(f"Ошибка отправки UDP пакета {i}: {e}")
            await async_sleep_until(start_time + (i + 1) * interval)
        await async_sleep_until(start_time + 1.0)

    async def send_packets_session(self, session_distribution):
        """
        Для одного "сессионного" блока (например, session_length секунд)
        перебираем для каждой секунды значение из session_distribution (число пакетов, заданное distribution)
        и отправляем соответствующий burst.
        При этом для TCP берем 90% (это число будет отправлено как запросы, а сервер ответит на каждый)
        и для UDP – оставшиеся 10%.
        """
        for second, pkts in enumerate(session_distribution):
            # Вычисляем, сколько TCP и UDP пакетов отправить в этой секунде.
            # Обратите внимание: итоговое TCP-трафик будет в 2 раза больше (запрос+ответ).
            self.tcp_count = int(pkts * 0.8)
            self.udp_count = int(pkts - self.tcp_count)
            # print(f"Секунда {second + 1}: всего {pkts} пакетов, TCP запросов: {tcp_count}, UDP: {udp_count}")
            await asyncio.gather(
                    self.send_tcp_burst(),
                    self.send_udp_burst(),
                    )

    async def send_packets(self, transmission_sessions):
        """
        Перебирает все сессии (список списков, где каждый вложенный список – значения distribution для session_length секунд)
        и отправляет пакеты для каждой сессии.
        """
        total_sessions = len(transmission_sessions)
        for i, session in enumerate(transmission_sessions):
            print(f"Начало сессии {i + 1}/{total_sessions} (длительность {len(session)} секунд)")
            await self.send_packets_session(session)


async def main():
    # Генерируем distribution.
    # В оригинальном коде используется функция generate_distribution('normal', 450, 60*15)
    # Здесь 450 – базовое число пакетов (например, TCP запросов для каждой секунды, которые в сумме дадут ~900 TCP-пакетов с ответами)
    total_seconds = 60 * 15  # например, 15 минут
    distribution = generate_distribution('normal', 500, total_seconds)
    # Разобьем distribution на сессии, например, по 20 секунд каждая:
    session_length = 60
    transmission_sessions = [
            distribution[i:i + session_length] for i in range(0, len(distribution), session_length)
            ]
    print(
            f"Сгенерировано {len(distribution)} секунд, разбито на {len(transmission_sessions)} сессий по {session_length} секунд"
            )

    sender = AsyncSender()
    await sender.init_udp_socket()
    try:
        await sender.send_packets(transmission_sessions)
    finally:
        await sender.close_udp_socket()


if __name__ == '__main__':
    asyncio.run(main())
