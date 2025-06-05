# receiver.py
from scapy.sendrecv import sniff


def packet_callback(pkt):
    print(pkt.show())


def receiver_mode():
    """
    Режим приёмника.
    Запускается пассивный захват пакетов с заданным фильтром.
    """
    print("Режим приёмника запущен...")
    src_ip = '172.16.63.1'
    dst_ip = '172.16.63.152'
    proto = 'tcp'
    sniff(filter=f"src {src_ip} and dst {dst_ip} and {proto}", prn=packet_callback)
    # sniff(filter=f"host {dst_ip} and {proto}", prn=packet_callback)


if __name__ == "__main__":
    receiver_mode()
