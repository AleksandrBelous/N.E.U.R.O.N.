from scapy.all import send
from scapy.layers.inet import IP, TCP, sr1
from params import src, dst


def is_TCP_handshake():
    SYN = IP(dst=dst.ip) / TCP(sport=src.port, dport=dst.port, flags="S", seq=1000)
    SYN_ASK = sr1(SYN, timeout=2, verbose=False)
    if SYN_ASK is None or not SYN_ASK.haslayer(TCP):
        print("[HANDSHAKE] SYN-ACK не получен. Завершение.")
    print("[HANDSHAKE] Получен SYN-ACK")
    SYN_ASK.show2()
    ASK = IP(dst=dst.ip) / TCP(sport=src.port, dport=dst.port, flags="A", seq=SYN_ASK.ack, ack=SYN_ASK.seq + 1)
    send(ASK, verbose=False)
    print("[HANDSHAKE] Отправлен ACK. Рукопожатие завершено.")
    return SYN_ASK.ack


if __name__ == "__main__":
    print("Режим отправителя запущен.")
    is_TCP_handshake()
    # dst_mac = getmacbyip(dst_ip)
    # pkt = IP(dst=dst_ip) / TCP(dport=dst_port) / b"My TCP Data e"
    # send(SYN, count=1, verbose=True)
