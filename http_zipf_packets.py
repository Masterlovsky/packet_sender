from email.base64mime import header_length
from httplib2 import Http
import numpy as np
import getopt
import sys
from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

# zipf distribution: https://en.wikipedia.org/wiki/Zipf%27s_law. We let C = 1.0


def generate_zipf_packets(dstip, num_flows, total_packets, packet_size, power) -> list:
    summation = 0
    res = 0
    zipf_dist = []
    packets = []
    # * fill zipf dist
    for i in range(1, num_flows+1):
        summation += 1.0/i**power

    init_num_packets = total_packets/summation
    for i in range(1, num_flows + 1):
        res = init_num_packets * (1.0/i**power)
        zipf_dist.append(int(res))

    print("[generate zipf flows] # packet number in the first flow = {}".format(
        zipf_dist[0]))

    # * fill packets
    if ":" not in dstip:
        ip_layer = IP(dst=dstip)
    else:
        ip_layer = IPv6(dst=dstip)
    header_len = len(Ether()/ip_layer/TCP())

    for i in range(num_flows):
        tcp_sport = random.randint(10000, 65535)
        shake_hands(dstip, tcp_sport)
        uri = uri_list[i]
        http_msg = "GET {} HTTP/1.1 \r\nUser-Agent: curl/7.29.0\r\n".format(uri)
        for j in range(zipf_dist[i]):
            flow_packet = Ether()/ip_layer/TCP(dport=80, sport=tcp_sport)/http_msg
            packets.append(flow_packet)

    np.random.shuffle(packets)
    # flow_packet = Ether()/ip_layer/TCP(dport=80, sport=tcp_sport, flags='F')/Raw(RandString(size=packet_size - header_len))
    # packets.append(flow_packet)
    return packets
    # wrpcap("tcp_zipf_test.pcap", packets, append = False)

# TCP shake hands 3 times


def shake_hands(dst_ip, src_port, dst_port=80):
    if ":" not in dst_ip:
        ip_layer = IP(dst=dst_ip)
    else:
        ip_layer = IPv6(dst=dst_ip)
    try:
        spk1 = ip_layer/TCP(dport=dst_port, sport=src_port, flags="S")
        res1 = sr1(spk1)
        ack1 = res1[TCP].ack
        ack2 = res1[TCP].seq + 1
        spk2 = ip_layer/TCP(dport=dst_port, sport=src_port,
                            seq=ack1, ack=ack2, falgs="A")
        send(spk2)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "i:f:p:s:e:m:")
        if len(opts) != 5:
            print("Usage: -i <dst ip> -f <number of flows> -p <number of packets> -s <size of packet in bytes> -e <exponent greater than 1>")
            sys.exit(1)
        for opt, arg in opts:
            if opt == '-i':
                i = arg
            if opt == '-f':
                f = int(arg)
            if opt == '-p':
                p = int(arg)
            if opt == '-s':
                s = int(arg)
            if opt == '-e':
                e = float(arg)
        print("Main: Number of flows = %d Number of packets = %d Size of packets = %d Zipf exponent = %f" % (f, p, s, e))
        uri_list = ["/{}.txt".format(i) for i in range(1, f + 1)] # generate uri list
        packets = generate_zipf_packets(i, f, p, s, e)
        send(packets, inter=0.1)

    except getopt.GetoptError:
        print("Usage: -i <ip> -f <number of flows> -p <number of packets> -s <size of packet in bytes> -e <exponent greater than 1> -m <maximum number of flows to be marked with a fin packet>")

    # da1 = IP(dst=dst_ip)/TCP(dport=dst_port, sport=src_port,
    #                          seq=ack1, ack=ack2, flags=24)/data
    # res2 = sr1(da1)
