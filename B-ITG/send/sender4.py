from scapy.all import *
from scapy.layers.inet import *
import time

target_ip = "127.0.0.1"
target_port = 12345

# 1. SYN
syn = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags='S', seq=100)
print("[Sender] Отправка SYN...")
syn_ack = sr1(syn, timeout=20, verbose=0)

if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 'SA':
    print("[Sender] Получен SYN-ACK")
    # 2. ACK
    ack_pkt = IP(dst=target_ip) / TCP(
            sport=syn_ack[TCP].dport,
            dport=target_port,
            flags='A',
            seq=syn_ack[TCP].ack,
            ack=syn_ack[TCP].seq + 1
            )
    send(ack_pkt, verbose=0)
    print("[Sender] Отправлен ACK. Соединение установлено!")

    # 3. Передача данных
    start_time = time.time()
    data_seq = syn_ack[TCP].ack
    while time.time() - start_time < 10:
        data_pkt = IP(dst=target_ip) / TCP(
                sport=syn_ack[TCP].dport,
                dport=target_port,
                flags='PA',
                seq=data_seq,
                ack=syn_ack[TCP].seq + 1
                ) / Raw(load="Hello from sender!")
        send(data_pkt, verbose=0)
        data_seq += len(data_pkt[Raw].load)
        time.sleep(1)

    # 4. Завершение (FIN)
    fin = IP(dst=target_ip) / TCP(
            sport=syn_ack[TCP].dport,
            dport=target_port,
            flags='FA',
            seq=data_seq,
            ack=syn_ack[TCP].seq + 1
            )
    fin_ack = sr1(fin, timeout=2, verbose=0)
    print("[Sender] Соединение закрыто")
else:
    print("[Sender] Ошибка рукопожатия")
