#!/bin/python3
import os
from statistics import stdev

from scapy.all import sniff, rdpcap, wrpcap


class DataPrep:

    def __init__(self):
        self.pkts_list = list()
        self.filter = "ip and tcp"
        self.num_pkts_to_sniff = 10
        self.last_time = None
        self.count = 0
        self.row_data = list()
        self.pcap_to_read = ''
        self.is_norm_sample = ''
        self.X = None
        self.detected = None

    def set_default(self):
        """
        set attributes to default values
        :return: None
        """
        self.pkts_list = list()
        self.last_time = None
        self.row_data = list()
        self.pcap_to_read = ''

    def sniffing_packets(self, pkt):
        """
        help function for packets sniffing
        :param pkt: yet sniffed packet
        :return: None, put sniffed packets at 'pkts_list' attribute
        """
        self.pkts_list.append(pkt)

    def analyze_10_packets(self, pkts):
        """
        analyze 10 packets to get target network characteristics
        :param pkts: 10 target packets, TCP/IP only !!!
        :return:
        - "Average Packet Size", the average length of the TCP/IP packet data field (hereinafter referred to as the packet length)
        - "Flow Bytes/s", the data flow rate
        - "Max Packet Length", the maximum packet length
        - "Fwd Packet Length Mean", the average length of packets transmitted in the forward direction
        - "Fwd IAT Min", the minimum value of the inter-packet interval (IAT, inter-arrival time) in the forward direction
        - "Total Length of Fwd Packets", the total length of packets transmitted in the forward direction
        - "Fwd IAT Std", the standard deviation of the value of the inter-packet interval in the forward direction of the packets
        - "Flow IAT Mean", the average value of the batch interval
        - "Fwd Packet Length Max", the maximum length of a packet transmitted in the forward direction
        - "Fwd Header Length", the total length of the headers of packets transmitted in the forward direction
        """
        total_length = 0
        max_pkt_len = 0
        fwd_pkts_len = []
        fwd_ia_times = []
        fwd_header_len = 0

        for packet in pkts:
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
            avg_pkt_size = float(round(total_length / len(pkts), 3))
            flow_bytes_per_s = float(round(total_length / (pkts[-1].time - pkts[0].time), 3))
            fwd_pkt_mean_len = float(round(sum(fwd_pkts_len) / len(fwd_pkts_len), 3))
            fwd_iat_min = float(round(min(fwd_ia_times) * 1000, 5))
            tot_len_fwd_pkts = sum(fwd_pkts_len)
            fwd_iat_std = float(round(stdev(fwd_ia_times), 5))
            flow_iat_mean = float(round(sum(fwd_ia_times) / len(fwd_ia_times), 5))
            fwd_pkt_max_len = max(fwd_pkts_len)
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
        """
        group and analyze packets by 10
        :param pkts: target list with packets
        :return: None, put unlabeled data samples at 'row_data' attribute
        """
        n = len(pkts) + 1
        i, j = 0, 10
        while i + 10 < n:
            self.row_data.append(self.analyze_10_packets(pkts[i:j]))
            i, j = j, j + 10

    def start_sniffing(self):
        """
        start sniffing with given params
        :return: None, put sniffed packets at 'pkts_list' attribute
        """
        sniff(prn=self.sniffing_packets, filter=self.filter, count=self.num_pkts_to_sniff)

    def store_X(self):
        with open('Xy.txt', 'w') as f:
            f.write(','.join([str(e) for e in self.X] + ['0']))

    def train_mode(self, is_v=False):
        self.start_sniffing()
        if is_v: print(f'sniffed {self.num_pkts_to_sniff} packets')
        self.X = self.analyze_10_packets(self.pkts_list)
        self.store_X()
        if is_v: print('stored as dataset')

    def store_detected(self):
        with open('detected.txt', 'w') as f:
            f.write(','.join([str(e) for e in self.detected]))
    def detecting_mode(self, is_v=False):
        self.start_sniffing()
        if is_v: print(f'sniffed {self.num_pkts_to_sniff} packets')
        self.detected = self.analyze_10_packets(self.pkts_list)
        self.store_detected()
        if is_v: print('stored')

    def read_pcap(self):
        """
        put the .pcap file at 'pkts_list' attribute
        :return: None, put the .pcap file at 'pkts_list' attribute
        """
        self.pkts_list = rdpcap(self.pcap_to_read)

    def create_pcap_from_net(self, num_packets_to_create):
        """
        start sniffing the network and store packets at local .pcap file
        :param num_packets_to_create: number of packets to sniff
        :return: None, create 'my{num_packets_to_create}.pcap' file at local folder
        """
        sniff(prn=self.sniffing_packets, filter=self.filter, count=num_packets_to_create)
        wrpcap(f'my{num_packets_to_create}.pcap', self.pkts_list)

    def create_csv(self):
        """
        create local 'csvs/' folder with .csv datasets based on 'pcap_to_read' attribute
        :return: None, create local 'csvs/' folder
        """
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
        """
        read the prepared .pcap file and convert it to datasets
        :param target_folder: folder with .pcap[s] file[s]
        :param y_correct: 0 for normal traffic, 1 for malicious
        :return: create 'csvs' folder with .csv datasets
        """
        self.is_norm_sample = str(y_correct) + '\n'
        attacks_pcaps_folder = os.path.join(os.getcwd(), target_folder)
        for file in os.listdir(attacks_pcaps_folder):
            self.pcap_to_read = os.path.join(attacks_pcaps_folder, file)
            self.read_pcap()
            self.analyze_pcap(self.pkts_list)
            self.create_csv()
            self.set_default()


if __name__ == '__main__':
    dp = DataPrep()
    dp.set_samples('my_pcaps', 0)
