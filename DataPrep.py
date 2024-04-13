#!/bin/python3
import os
from statistics import stdev

from scapy.all import sniff, rdpcap, wrpcap


class DataPrep:

    def __init__(self):
        self.packets_list = list()
        self.filter = "ip and tcp"
        self.num_packets_to_sniff = 10
        self.last_time = None
        self.count = 0
        self.row_data = list()
        self.pcap_to_read = ''
        # self.num_packets_to_create = 50000
        self.is_norm_sample = ''

    def set_default(self):
        self.packets_list = list()
        self.last_time = None
        self.row_data = list()
        self.pcap_to_read = ''

    def sniffing_packets(self, packet):
        self.packets_list.append(packet)

    def analyze_10_packets(self, packets):
        total_length = 0
        max_pkt_len = 0
        fwd_pkts_len = []
        fwd_ia_times = []
        fwd_header_len = 0

        for packet in packets:
            try:
                total_length += len(packet)
                max_pkt_len = max(max_pkt_len, len(packet))
                fwd_pkts_len.append(packet.len)
                if self.last_time is not None:
                    # print(f"a={self.last_time} b={packet.time} d=b-a={packet.time - self.last_time}")
                    fwd_ia_times.append(packet.time - self.last_time)
                self.last_time = packet.time
                fwd_header_len += packet.ihl * 4 + packet.dataofs * 4
            except Exception as e:
                print(e)
                print(f"can't analyze packet:")
                packet.show()
        try:
            avg_pkt_size = float(round(total_length / len(packets), 3))
            flow_bytes_per_s = float(round(total_length / (packets[-1].time - packets[0].time), 3))
            fwd_pkt_mean_len = float(round(sum(fwd_pkts_len) / len(fwd_pkts_len), 3))
            fwd_iat_min = float(round(min(fwd_ia_times) * 1000, 5))
            tot_len_fwd_pkts = sum(fwd_pkts_len)
            fwd_iat_std = float(round(stdev(fwd_ia_times), 5))
            flow_iat_mean = float(round(sum(fwd_ia_times) / len(fwd_ia_times), 5))
            fwd_pkt_max_len = max(fwd_pkts_len)

            # Вывод результатов
            # print(len(fwd_ia_times), fwd_ia_times)
            # print("Average Packet Size:", avg_pkt_size)
            # print("Flow Bytes/s:", flow_bytes_per_s)
            # print("Max Packet Length:", max_pkt_len)
            # print("Fwd Packet Length Mean:", fwd_pkt_mean_len)
            # print("Fwd IAT Min:", fwd_iat_min)
            # print("Total Length of Fwd Packets:", tot_len_fwd_pkts)
            # print("Fwd IAT Std:", fwd_iat_std)
            # print("Flow IAT Mean:", flow_iat_mean)
            # print("Fwd Packet Length Max:", fwd_pkt_max_len)
            # print("Fwd Header Length:", fwd_header_len)
            return (
                    avg_pkt_size,
                    flow_bytes_per_s,
                    max_pkt_len,
                    fwd_pkt_mean_len,
                    fwd_iat_min,
                    tot_len_fwd_pkts,
                    fwd_iat_std,
                    flow_iat_mean,
                    fwd_pkt_max_len,
                    fwd_header_len
                    )
        except Exception as e:
            print(e)

    def analyze_pcap(self, pkts):
        n = len(pkts) + 1
        i, j = 0, 10
        while i + 10 < n:
            # print()
            self.row_data.append(self.analyze_10_packets(pkts[i:j]))
            i, j = j, j + 10
            # print()
        # print(*self.row_data, sep='\n')

    def start_sniffing(self):
        sniff(prn=self.sniffing_packets, filter=self.filter, count=self.num_packets_to_sniff)

    def read_pcap(self):
        self.packets_list = rdpcap(self.pcap_to_read)

    def create_pcap(self, num_packets_to_create):
        sniff(prn=self.sniffing_packets, filter=self.filter, count=num_packets_to_create)
        wrpcap(f'my{num_packets_to_create}.pcap', self.packets_list)

    def create_csv(self):
        file_name, file_extension = os.path.splitext(self.pcap_to_read)
        print(file_name, file_extension)
        new_folder = os.path.join(os.getcwd(), 'csvs')
        os.makedirs(new_folder, exist_ok=True)
        with open(os.path.join(new_folder, os.path.split(file_name)[-1] + '.csv'), 'w') as f:
            f.write(
                    'Average Packet Size,Flow Bytes/s,Fwd Packet Length Mean,Max Packet Length,Fwd IAT Min,Total Length of Fwd Packets,Flow IAT Mean,Fwd IAT Std,Fwd Packet Length Max,Fwd Header Length,Label\n'
                    )
            for tpl in self.row_data:
                f.write(','.join([str(e) for e in tpl] + [self.is_norm_sample]))

    def set_samples(self, target_folder: str, y_correct: int):
        self.is_norm_sample = str(y_correct) + '\n'
        attacks_pcaps_folder = os.path.join(os.getcwd(), target_folder)
        print('att >>', attacks_pcaps_folder)
        for file in os.listdir(attacks_pcaps_folder):
            print('file is ', file)
            self.pcap_to_read = os.path.join(attacks_pcaps_folder, file)
            self.read_pcap()
            self.analyze_pcap(sn.packets_list)
            self.create_csv()
            self.set_default()


if __name__ == '__main__':
    sn = DataPrep()
    # sn.start_sniffing()
    # sn.analyze_packets(sn.packets_list)
    # sn.set_default()
    sn.set_samples('my_pcaps', 0)
    # sn.create_pcap(50000)
