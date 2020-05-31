import struct
import random
from typing import List, Union, Type, Iterator
import os

from pypacker.pypacker import Packet
from pypacker.layer12 import ethernet, radiotap, ieee80211, llc
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp

ETHERNET_PCAP_HEADER = bytes.fromhex("D4C3B2A10200040000000000000000000000040001000000")
RADIOTAP_PCAP_HEADER = bytes.fromhex("D4C3B2A10200040000000000000000000000040017000000")

SRC_MAC = "00:00:00:9f:f8:3b"
DST_MAC = "00:00:00:87:7e:0e"
SRC_IP = "88.44.85.145"
DST_IP = "212.110.118.170"
PORTS = list(range(4000, 4020))

# Split evenly between each size
PACKETS_PER_CONVERSATION = 1000

# Split evenly between TCP and UDP
CONVERSATIONS = 420


def write_cap(file_path: str, packets: List[bytes], pcap_header: bytes):
    with open(file_path, "wb") as f:
        f.write(pcap_header)
        for packet in packets:
            packet_length = len(packet)
            f.write(struct.pack("<IIII", 0, 0, packet_length, packet_length) + packet)


def create_packet(
    packet_layer12: Packet,
    protocol: Union[Type[tcp.TCP], Type[udp.UDP]],
    src_port: int,
    dst_port: int,
) -> bytes:
    protocol_number = ip.IP_PROTO_TCP if protocol == tcp.TCP else ip.IP_PROTO_UDP
    packet = (
        packet_layer12
        + ip.IP(p=protocol_number, src_s=SRC_IP, dst_s=DST_IP)
        + protocol(sport=src_port, dport=dst_port)
    )
    packet[protocol].body_bytes = os.urandom(random.randint(500, 1000))
    return packet.bin()


def create_conversation(
    packet_layer12: Packet, protocol: Union[Type[tcp.TCP], Type[udp.UDP]]
) -> Iterator[bytes]:
    src_port = random.choice(PORTS)
    dst_port = random.choice(PORTS)
    for p in range(PACKETS_PER_CONVERSATION // 2):
        yield create_packet(packet_layer12, protocol, src_port, dst_port)
        yield create_packet(packet_layer12, protocol, dst_port, src_port)


def generate_cap_file(
    packet_base: Packet, conversation_count: int, cap_header: bytes, cap_name: str
):
    packets: List[bytes] = []
    for _ in range(conversation_count // 2):
        packets.extend(create_conversation(packet_base, tcp.TCP))
        packets.extend(create_conversation(packet_base, udp.UDP))

    random.shuffle(packets)
    write_cap(cap_name, packets, cap_header)


if __name__ == "__main__":
    packets: List[bytes] = []

    ethernet_base = ethernet.Ethernet(src_s=SRC_MAC, dst_s=DST_MAC)
    generate_cap_file(
        ethernet_base, CONVERSATIONS, ETHERNET_PCAP_HEADER, "ethernet_benchmark.cap"
    )

    radiotap_base = (
        radiotap.Radiotap()
        + ieee80211.IEEE80211(framectl=0x8801)
        + ieee80211.IEEE80211.Dataframe(sec_param=None)
        + llc.LLC(
            dsap=170, ssap=170, ctrl=3, snap=int.to_bytes(llc.LLC_TYPE_IP, 5, "big")
        )
    )
    generate_cap_file(
        radiotap_base, CONVERSATIONS, RADIOTAP_PCAP_HEADER, "radiotap_benchmark.cap"
    )

    min_port = min(PORTS)
    max_port = max(PORTS)
    bpf = f"tcp portrange {min_port}-{max_port} or udp portrange {min_port}-{max_port}"
    display_filter = (
        f"(({max_port} >= tcp.srcport >= {min_port})"
        f" or "
        f"({max_port} >= tcp.dstport >= {min_port}))"
        f" or "
        f"(({max_port} >= udp.srcport >= {min_port})"
        f" or "
        f"({max_port} >= udp.dstport >= {min_port}))"
    )
    print("BPF:", bpf)
    print("Display filter:", display_filter)
    print("Ethernet cap encapsulation type value: 1")
    print("Radiotap cap encapsulation type value: 23")
