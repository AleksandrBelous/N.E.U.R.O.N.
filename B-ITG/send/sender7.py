import socket
import time
import datetime
import threading

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from aiohttp.tcp_helpers import tcp_nodelay, tcp_keepalive
from numpy.core.defchararray import title
from numpy.lib.function_base import interp
from rich import print
from scapy.sendrecv import sniff, wrpcap
from collections import defaultdict
from scapy.utils import PcapReader
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

    def create_tcp_connection(self, verbose=False):
        """Создаем новое TCP соединение"""
        if self.tcp_sock:
            self.tcp_sock.close()
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.connect((dst.ip, dst.port))
        if verbose:
            print(f"{color_sender} {color_tcp} Connected to {dst.ip}:{dst.port}")

    def send_tcp_burst(self, tcp_pkts_per_sec: np.ndarray, verbose=False):
        """Отправка TCP-пакетов блоками"""
        try:
            self.create_tcp_connection()
            # tcp_pkts_per_sec_length = len(tcp_pkts_per_sec)
            interval = 1.0 / tcp_pkts_per_sec
            if verbose:
                print(f"{color_sender} {color_tcp} Sending {tcp_pkts_per_sec} pkts for {1} s")
                print(f"{color_sender} {color_tcp} Interval: {interval} s")
            start_time = time.perf_counter()
            for i in range(tcp_pkts_per_sec):
                msg = f"TCP | {i}"
                self.tcp_sock.sendall(msg.encode())
                sleep_until(start_time + (i + 1) * interval)
            if self.tcp_sock:
                self.tcp_sock.close()
                if verbose:
                    print(f"{color_sender} {color_tcp} Disconnected")
            sleep_until(start_time + 1.0)
            interval_time = time.perf_counter() - start_time
            if verbose:
                print(f"{color_sender} {color_tcp} Finished send {tcp_pkts_per_sec} pkts "
                      f"at {interval_time:.6f} sec, speed = {tcp_pkts_per_sec / interval_time:.6f} pps)"
                      )
        except (BrokenPipeError, ConnectionResetError, ConnectionRefusedError, Exception) as e:
            print(f"{color_sender} {color_tcp} Connection failed! {color_error}: {e}")
        finally:
            if self.tcp_sock:
                self.tcp_sock.close()
                if verbose:
                    print(f"{color_sender} {color_tcp} Disconnected")

    def send_udp_burst(self, udp_pkts_per_sec, verbose=False):
        """Отправка UDP-пакетов блоками"""
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            interval = 1.0 / udp_pkts_per_sec
            if verbose:
                print(f"{color_sender} {color_udp} Connected to {dst.ip}:{dst.port}")
                print(f"{color_sender} {color_udp} Sending {udp_pkts_per_sec} pkts for {1} s")
                print(f"{color_sender} {color_udp} Interval: {interval} s")
            start_time = time.perf_counter()
            for i in range(udp_pkts_per_sec):
                msg = f"UDP | {i}"
                self.udp_sock.sendto(msg.encode(), (dst.ip, dst.port))
                sleep_until(start_time + (i + 1) * interval)
            self.udp_sock.close()
            if verbose:
                print(f"{color_sender} {color_udp} Disconnected")
            sleep_until(start_time + 1.0)
            interval_time = time.perf_counter() - start_time
            if verbose:
                print(f"{color_sender} {color_udp} Finished send {udp_pkts_per_sec} pkts "
                      f"at {interval_time:.6f} sec, speed = {udp_pkts_per_sec / interval_time:.6f} pps)"
                      )
        except (OSError, BrokenPipeError, ConnectionResetError, ConnectionRefusedError, Exception) as e:
            print(f"{color_sender} {color_udp} Connection failed! {color_error}: {e}")
            return
        finally:
            self.udp_sock.close()
            if verbose:
                print(f"{color_sender} {color_udp} Disconnected")

    def send_packets(self, sessions: list):
        """Отправка пакетов по заданному шаблону"""
        len_ = len(sessions)
        for i, list_of_pkts_chunks in enumerate(sessions):
            # print(f"\nlist_of_pkts_chunks {i}: {list_of_pkts_chunks}")
            print(f"{color_sender} Cycle {i + 1}/{len_}")
            for pkts_per_sec in list_of_pkts_chunks:
                tcp_pkts_per_sec = int(pkts_per_sec * 0.9)
                udp_pkts_per_sec = int(pkts_per_sec - tcp_pkts_per_sec)

                # Открываем потоки для каждой секунды, во время которой отправим и TCP и UDP вместе
                threads = []

                if tcp_pkts_per_sec:
                    tcp_thread = threading.Thread(
                            target=self.send_tcp_burst,
                            args=(tcp_pkts_per_sec, False,),
                            )
                    tcp_thread.start()
                    threads.append(tcp_thread)

                if udp_pkts_per_sec:
                    udp_thread = threading.Thread(
                            target=self.send_udp_burst,
                            args=(udp_pkts_per_sec, False,)
                            )
                    udp_thread.start()
                    threads.append(udp_thread)

                # Ждем завершения всех потоков цикла
                for t in threads:
                    t.join()


def calculate_packets_per_second(pcap_file):
    counts = defaultdict(int)
    # with PcapReader(pcap_file) as pcap:
    for pkt in pcap_file:
        second = int(pkt.time)
        counts[second] += 1

    # Определяем диапазон секунд для корректного формирования списка
    if counts:
        start = min(counts.keys())
        end = max(counts.keys())
        return [counts.get(sec, 0) for sec in range(start, end + 1)]
    else:
        return []


def plot_packet_distribution(packet_counts, title):
    plt.figure(figsize=(8, 6))
    sns.histplot(packet_counts, bins=100, kde=True, color="skyblue", edgecolor="black")
    plt.title(f"mean ≈ {np.mean(packet_counts):.2f}")
    plt.xlabel("Пакетов/сек")
    plt.ylabel("Число таких секунд")
    plt.tight_layout()
    # Сохраняем график перед отображением
    plt.savefig(
            title,
            dpi=300,  # Высокое разрешение
            bbox_inches='tight',  # Обрезка пустых полей
            facecolor='white',  # Фон
            format='png',
            )
    # plt.show()
    plt.close()


def main():
    for distro in ["gamma"]: #, "cauchy", "gamma"]:
        for seed in [42]:
            sender = Sender()
            try:
                median = 500
                timeout = int(60 * 60 * 1.5)
                distribution = generate_distribution(distro, median, timeout, seed)
                # print(distribution)
                # plot_density(distribution, '-')
                transmission_sessions = []
                session_length_sec = 60
                for i in range(0, len(distribution), session_length_sec):
                    list_of_pkts_chunks = distribution[i:i + session_length_sec]
                    transmission_sessions.append(list_of_pkts_chunks)
                start_time = time.perf_counter()
                print(f"{color_sender} Start sending at {datetime.datetime.now()}")
                print(f"{color_sender} Will total spend {len(distribution)} seconds")
                packets = []
                # Запускаем сниффер в отдельном потоке
                sniffer_thread = threading.Thread(
                        target=sniff,
                        kwargs={
                                # "filter" : "tcp port 12345 or udp port 12345",
                                "prn"    : lambda pkt: packets.append(pkt),  # Сохраняем каждый пакет
                                "timeout": timeout + 20,
                                "store"  : False
                                }
                        )
                sniffer_thread.start()
                sender.send_packets(transmission_sessions)
                stop_time = time.perf_counter()
                print(f"{color_sender} Stopped sending at {datetime.datetime.now()}")
                print(f"{color_sender} Sending duration: {stop_time - start_time} sec")
                # Ждем завершения работы сниффера
                sniffer_thread.join()
                title = f"{distro}-median-{median}-timeout-{timeout}-seed-{seed}-tcp-udp-sender7-anomal"
                pcap_file = title + ".pcap"
                wrpcap(pcap_file, packets)
                print(f"Сохранено {len(packets)} пакетов")
                pkts_counts = calculate_packets_per_second(packets)
                plot_file = title + ".png"
                plot_packet_distribution(pkts_counts, plot_file)
            except (ConnectionRefusedError, Exception) as e:
                print(f"{color_sender} Connection refused. {color_error}: {e}")
            finally:
                sender.tcp_sock.close()
                sender.udp_sock.close()
                del packets
            time.sleep(60)
            print("Stop ...")


if __name__ == "__main__":
    main()
