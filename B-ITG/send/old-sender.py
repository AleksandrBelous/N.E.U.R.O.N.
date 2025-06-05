# old-sender.py
import time
import numpy as np
from scapy.all import send
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP, sr1
from scapy.layers.dns import DNS, DNSQR
from random import randint


def generate_packet(protocol, params):
    """Генерирует пакеты для протоколов, не требующих TCP-соединения."""
    if protocol == "udp":
        dst_ip = params.get("dst_ip", "192.168.1.1")
        dst_port = params.get("dst_port", 12345)
        return Ether() / IP(dst=dst_ip) / UDP(dport=dst_port) / b"UDP Data"
    elif protocol == "icmp":
        dst_ip = params.get("dst_ip", "192.168.1.1")
        return IP(dst=dst_ip) / ICMP()
    elif protocol == "arp":
        dst_ip = params.get("dst_ip", "192.168.1.1")
        src_ip = params.get("src_ip", "192.168.1.100")
        return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=src_ip, pdst=dst_ip)
    elif protocol == "dns":
        dst_ip = params.get("dst_ip", "8.8.8.8")
        return IP(dst=dst_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    else:
        raise ValueError("Unsupported protocol for generate_packet.")


def tcp_handshake(dst_ip, dst_port):
    """
    Реализует трёхстороннее TCP-рукопожатие:
      1. Отправка SYN.
      2. Ожидание SYN-ACK.
      3. Отправка ACK.
    Возвращает объект IP, исходящий порт и начальный номер последовательности.
    """
    ip = IP(dst=dst_ip)
    sport = randint(1024, 65535)
    syn = TCP(sport=sport, dport=dst_port, flags="S", seq=1000)
    print(f"[HANDSHAKE] Отправка SYN на {dst_ip}:{dst_port}")
    synack = sr1(ip / syn, timeout=2, verbose=False)
    if synack is None or not synack.haslayer(TCP):
        print("[HANDSHAKE] SYN-ACK не получен. Завершение.")
        return None, None, None
    print("[HANDSHAKE] Получен SYN-ACK")
    ack = TCP(sport=sport, dport=dst_port, flags="A", seq=synack.ack, ack=synack.seq + 1)
    send(ip / ack, verbose=False)
    print("[HANDSHAKE] Отправлен ACK. Рукопожатие завершено.")
    return ip, sport, synack.ack


def send_tcp_data(ip, sport, dport, init_seq, payload, count):
    """
    Отправляет несколько TCP-пакетов с полезной нагрузкой в рамках установленного соединения.
    После каждого пакета номер последовательности увеличивается на длину payload.
    Возвращает обновлённый номер последовательности.
    """
    seq = init_seq
    for i in range(count):
        pkt = ip / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=0) / payload
        send(pkt, verbose=False)
        print(f"[DATA] Отправлен TCP пакет #{i + 1} с seq={seq}")
        seq += len(payload)
    return seq


def send_packets(distribution: np.ndarray, protocols, protocol_params, tcp_payloads):
    """
    Отправляет пакеты согласно распределению.
    Для TCP-протоколов (telnet, http, https) сначала устанавливается соединение,
    затем отправляются данные с заданной полезной нагрузкой.
    Для остальных протоколов пакеты отправляются напрямую.
    """
    tcp_protocols = { "telnet", "http", "https" }
    tcp_connections = { }  # Хранит данные установленных TCP-соединений по протоколам
    total_seconds = len(distribution)
    for sec in range(total_seconds):
        start_time = time.time()
        total_packets = distribution[sec]
        num_protocols = len(protocols)
        packets_per_proto = total_packets // num_protocols
        remainder = total_packets % num_protocols

        for proto in protocols:
            count = packets_per_proto + (1 if remainder > 0 else 0)
            remainder = max(0, remainder - 1)
            params = protocol_params.get(proto, { })
            if proto in tcp_protocols:
                dst_ip = params.get("dst_ip", "192.168.43.2")
                dst_port = params.get("dst_port", 80 if proto == "http" else (443 if proto == "https" else 23))
                if proto not in tcp_connections:
                    ip_obj, sport, init_seq = tcp_handshake(dst_ip, dst_port)
                    if ip_obj is None:
                        print(f"[{proto.upper()}] Не удалось установить TCP-соединение. Пропуск отправки.")
                        continue
                    tcp_connections[proto] = { "ip": ip_obj, "sport": sport, "seq": init_seq, "dst_port": dst_port }
                conn = tcp_connections[proto]
                payload = tcp_payloads.get(proto, b"")
                new_seq = send_tcp_data(conn["ip"], conn["sport"], conn["dst_port"], conn["seq"], payload, count)
                conn["seq"] = new_seq
            else:
                for _ in range(count):
                    pkt = generate_packet(proto, params)
                    send(pkt, verbose=False)
                    print(f"[{proto.upper()}] Отправлен пакет")
        elapsed = time.time() - start_time
        if elapsed < 1:
            time.sleep(1 - elapsed)


def sender_mode():
    """
    Режим отправителя.
    Генерирует распределение (10 секунд) и отправляет пакеты по заданному распределению.
    """
    distribution = np.random.poisson(lam=100, size=10)
    protocols = ["udp", "icmp", "arp", "dns", "telnet", "http", "https"]
    protocol_params = {
            "udp"   : { "dst_ip": "192.168.43.2", "dst_port": 58220 },
            "icmp"  : { "dst_ip": "192.168.43.2" },
            "arp"   : { "dst_ip": "192.168.43.2", "src_ip": "192.168.43.2" },
            "dns"   : { "dst_ip": "8.8.8.8" },
            "telnet": { "dst_ip": "192.168.43.2", "dst_port": 58220 },
            "http"  : { "dst_ip": "192.168.43.2", "dst_port": 58220 },
            "https" : { "dst_ip": "192.168.43.2", "dst_port": 58220 }
            }
    tcp_payloads = {
            "telnet": b"TELNET DATA",
            "http"  : b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "https" : b"\x16\x03\x01\x00\x2e"  # Пример фрагмента TLS ClientHello
            }
    send_packets(distribution, protocols, protocol_params, tcp_payloads)


if __name__ == "__main__":
    print("Режим отправителя запущен.")
    sender_mode()
