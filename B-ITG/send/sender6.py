import socket
import time
import datetime
import threading

import numpy as np
from aiohttp.tcp_helpers import tcp_nodelay, tcp_keepalive
from numpy.lib.function_base import interp
from rich import print
from params import dst
from ScapyTrafficDistributionGenerator import generate_distribution, plot_ecdf, plot_density

color_sender = f"[green][Sender][/green]"
color_tcp = f"[blue][TCP][/blue]"
color_udp = f"[orange3][UDP][/orange3]"
color_error = f"[red]Error[/red]"


def sleep_until(target_time):
    """Точная задержка до указанного времени"""
    now = time.perf_counter()
    if now < target_time:
        time.sleep(target_time - now)


class Sender:
    def __init__(self):
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __del__(self):
        """Деструктор для закрытия сокетов"""
        if self.tcp_sock:
            self.tcp_sock.close()
        self.udp_sock.close()

    def create_tcp_connection(self):
        """Создаем новое TCP соединение"""
        if self.tcp_sock:
            self.tcp_sock.close()
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.connect((dst.ip, dst.port))
        print(f"{color_sender} {color_tcp} Connected to {dst.ip}:{dst.port}")

    def send_tcp_burst(self, tcp_session: np.ndarray, verbose=False):
        """Отправка TCP-пакетов блоками"""
        try:
            self.create_tcp_connection()
            session_length = len(tcp_session)
            total_pkts = tcp_session.sum(axis=0)
            if verbose:
                print(f"{color_sender} {color_tcp} Sending {total_pkts} pkts for {session_length} s")
            for i in range(session_length):
                start_time = time.perf_counter()
                num_pkts_per_sec = tcp_session[i]
                interval = 1.0 / num_pkts_per_sec
                if verbose:
                    print(f"{color_sender} {color_tcp} Will send {num_pkts_per_sec} pkts for {1} s")
                    print(f"{color_sender} {color_tcp} Interval: {interval} s")
                for j in range(num_pkts_per_sec):
                    msg = f"TCP | {i}-{j}"
                    self.tcp_sock.sendall(msg.encode())
                    sleep_until(start_time + (i + 1) * interval)
                sleep_until(start_time + 1.0)
                interval_time = time.perf_counter() - start_time
                if verbose:
                    print(f"{color_sender} {color_tcp} Finished send {num_pkts_per_sec} pkts "
                          f"at {interval_time:.6f} sec, speed = {num_pkts_per_sec / interval_time:.6f} pps)"
                          )
        except (BrokenPipeError, ConnectionResetError, ConnectionRefusedError, Exception) as e:
            print(f"{color_sender} {color_tcp} Connection failed! {color_error}: {e}")
        finally:
            if self.tcp_sock:
                self.tcp_sock.close()
            print(f"{color_sender} {color_tcp} Disconnected")

    def send_udp_burst(self, udp_session, verbose=False):
        """Отправка UDP-пакетов блоками"""
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print(f"{color_sender} {color_udp} Connected to {dst.ip}:{dst.port}")
            session_length = len(udp_session)
            total_pkts = udp_session.sum(axis=0)
            if verbose:
                print(f"{color_sender} {color_udp} Sending {total_pkts} pkts for {session_length} s")
            for i in range(session_length):
                start_time = time.perf_counter()
                num_pkts_per_sec = udp_session[i]
                interval = 1.0 / num_pkts_per_sec
                if verbose:
                    print(f"{color_sender} {color_udp} Will send {num_pkts_per_sec} pkts for {1} s")
                    print(f"{color_sender} {color_udp} Interval: {interval} s")
                for j in range(num_pkts_per_sec):
                    msg = f"UDP | {i}-{j}"
                    self.udp_sock.sendto(msg.encode(), (dst.ip, dst.port))
                    sleep_until(start_time + (i + 1) * interval)
                sleep_until(start_time + 1.0)
                interval_time = time.perf_counter() - start_time
                if verbose:
                    print(f"{color_sender} {color_udp} Finished send {num_pkts_per_sec} pkts "
                          f"at {interval_time:.6f} sec, speed = {num_pkts_per_sec / interval_time:.6f} pps)"
                          )
        except (OSError, BrokenPipeError, ConnectionResetError, ConnectionRefusedError, Exception) as e:
            print(f"{color_sender} {color_udp} Connection failed! {color_error}: {e}")
            return
        finally:
            self.udp_sock.close()
            print(f"{color_sender} {color_udp} Disconnected")

    def send_packets(self, sessions: list[dict]):
        """Отправка пакетов по заданному шаблону"""
        len_ = len(sessions)
        for i, session in enumerate(sessions):
            # print(f"session {i}: {session}")
            print(f"\n{color_sender} Cycle {i + 1}/{len_}")
            # # Фаза TCP
            # if session["tcp_per_second"] > 0:
            #     self.send_tcp_burst(session["tcp_per_second"], session["duration"])
            # # Фаза UDP
            # if session["udp_per_second"] > 0:
            #     self.send_udp_burst(session["udp_per_second"], session["duration"])
            threads = []

            # Запускаем TCP и UDP параллельно
            if session.get("is_tcp", None):
                # print(type(session["tcp_session"]))
                # print(session["tcp_session"])
                # if not isinstance(session["tcp_session"], np.ndarray):
                #     session["tcp_session"] = np.array(session["tcp_session"])
                tcp_thread = threading.Thread(
                        target=self.send_tcp_burst,
                        args=(session["tcp_session"], False,),
                        )
                tcp_thread.start()
                threads.append(tcp_thread)

            if session.get("is_udp", None):
                udp_thread = threading.Thread(
                        target=self.send_udp_burst,
                        args=(session["udp_session"], False)
                        )
                udp_thread.start()
                threads.append(udp_thread)

            # Ждем завершения всех потоков цикла
            for t in threads:
                t.join()


def main():
    sender = Sender()
    try:
        distribution = generate_distribution('normal', 500, 60 * 15)
        # print(distribution)
        # plot_density(distribution, '-')
        transmission_sessions = []
        tcp_session_length_sec = 60
        udp_session_length_sec = 0  # int(tcp_session_length_sec * 0.2)
        for i in range(0, len(distribution), tcp_session_length_sec + udp_session_length_sec):
            tcp_session = distribution[i:i + tcp_session_length_sec]
            j = i + tcp_session_length_sec
            udp_session = distribution[j:j + udp_session_length_sec]
            # print(tcp_session)
            # print(f"i={i} pkt per sec: {len(tcp_session)}")
            # print(udp_session)
            transmission_sessions.append({
                    "is_tcp"     : True,
                    "tcp_session": tcp_session,  # TCP сессия
                    "is_udp"     : False,
                    # "udp_session": udp_session,
                    }
                    )
        # cycles = 10
        # for cycle in range(cycles):
        #     transmission_sessions.append({
        #             "tcp_per_second": 1000,  # TCP пакетов в секунду
        #             "udp_per_second": 0,  # UDP пакетов в секунду
        #             "duration"      : 10,  # Длительность каждой фазы
        #             }
        #             )
        #     transmission_sessions.append({
        #             "tcp_per_second": 500,  # TCP пакетов в секунду
        #             "udp_per_second": 0,  # UDP пакетов в секунду
        #             "duration"      : 10,  # Длительность каждой фазы
        #             }
        #             )
        #
        start_time = time.time()
        print(f"{color_sender} Start sending at {datetime.datetime.now()}")
        print(f"{color_sender} Will total spend {len(distribution)} seconds")
        sender.send_packets(transmission_sessions)
        stop_time = time.time()
        print(f"{color_sender} Stopped sending at {datetime.datetime.now()}")
        print(f"{color_sender} Sending duration: {stop_time - start_time}")
    except (ConnectionRefusedError, Exception) as e:
        print(f"{color_sender} Connection refused. {color_error}: {e}")
    finally:
        sender.tcp_sock.close()
        sender.udp_sock.close()


if __name__ == "__main__":
    main()
