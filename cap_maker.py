import struct
import random
from typing import List

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp
from secrets import token_bytes

src_mac = "00:00:00:9f:f8:3b"
dst_mac = "00:00:00:87:7e:0e"
src_ip = "88.44.85.145"
dst_ip = "212.110.118.170"
ports = list(range(4000, 4020))


def write_cap(file_path: str, packets: List[bytes]):
    PCAP_HEADER = bytes.fromhex("D4C3B2A10200040000000000000000000000040001000000")
    with open(file_path, "wb") as f:
        f.write(PCAP_HEADER)
        for packet in packets:
            f.write(struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet)


def create_tcp_packet(src_port, dst_port):
    packet = ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac, type=ethernet.ETH_TYPE_IP) + \
             ip.IP(p=ip.IP_PROTO_TCP, src_s=src_ip, dst_s=dst_ip) + \
             tcp.TCP(sport=src_port, dport=dst_port)
    packet[tcp.TCP].body_bytes = token_bytes(random.randint(500, 1000))
    return packet.bin()


def create_udp_packet(src_port, dst_port):
    packet = ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac, type=ethernet.ETH_TYPE_IP) + \
             ip.IP(p=ip.IP_PROTO_TCP, src_s=src_ip, dst_s=dst_ip) + \
             udp.UDP(sport=src_port, dport=dst_port)
    packet[udp.UDP].body_bytes = token_bytes(random.randint(500, 1000))
    return packet.bin()


def create_tcp_conversation():
    src_port = random.choice(ports)
    dst_port = random.choice(ports)
    conversation = []
    for p in range(500):
        conversation.append(create_tcp_packet(src_port, dst_port))
        conversation.append(create_tcp_packet(dst_port, src_port))
    return conversation


def create_udp_conversation():
    src_port = random.choice(ports)
    dst_port = random.choice(ports)
    conversation = []
    for p in range(500):
        conversation.append(create_udp_packet(src_port, dst_port))
        conversation.append(create_udp_packet(dst_port, src_port))
    return conversation


if __name__ == '__main__':
    packets = []
    for _ in range(105):
        packets.extend(create_tcp_conversation())
        packets.extend(create_udp_conversation())
    random.shuffle(packets)
    write_cap('benchmark.cap', packets)
    tcp_bpf = ' or '.join([f"tcp port {port}" for port in ports])
    udp_bpf = ' or '.join([f"udp port {port}" for port in ports])

    tcp_dfiter = ' or '.join([f"tcp.port == {port}" for port in ports])
    udp_dfilter = ' or '.join([f"udp.port == {port}" for port in ports])
    print("BPF:", tcp_bpf, ' or ', udp_bpf)
    print("Dfilter:", tcp_dfiter, ' or ', udp_dfilter)
