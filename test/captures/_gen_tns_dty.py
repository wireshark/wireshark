#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_dty.pcap — a TTI_DTY (Set Datatypes) request.

The TTI_DTY body is the one an Oracle client sends when it negotiates
us7ascii, wrapped in the 10-byte TNS DATA framing, and emitted as a single TCP segment to port
1521 inside an IPv4 datagram (LINKTYPE_RAW, no Ethernet header).

This gives the dissector a deterministic, license-clean fixture for the
SQLNET_SET_DATATYPES decoder without needing a live Oracle capture.
"""
import os
import struct

TTI_DTY_BODY = bytes.fromhex(
    "02670367030126060100006a0101060101010101010029900307030001004f013704"
    "000000000c0000060001010702000000000000010101000202010003030100040401"
    "0005050100060601000707010008080100090901000a0a01000b0b01000c0c01000d"
    "0d01000e0e01000f0f01001010010011110100121201001313010014140100151501"
    "00161601001717010018180100191901001a1a01001b1b01001c1c01001d1d01001e"
    "1e01001f1f0100202001002121010022220100232301002424010025250100262601"
    "002727010028280100292901002a2a01002b2b01002c2c01002d2d01002e2e01002f"
    "2f010030300100313101003232010033330100343401003535010036360100373701"
    "0038380100393901003a3a01003b3b01003c3c01003d3d01003e3e01003f3f010040"
    "40010041410100424201004343010044440100454501004646010047470100484801"
    "00494901004a4a01004b4b01004c4c01004d4d01004e4e01004f4f01005050010051"
    "51010052520100535301005454010055550100565601005757010058580100595901"
    "005a5a01005b5b01005c5c01005d5d01005e5e01005f5f0100606001006161010062"
    "620100636301006464010065650100666601006767010068680100696901006a6a01"
    "006b6b01006c6c01006d6d01006e6e01006f6f010070700100717101007272010073"
    "7301007474010075750100767601007777010078780100797901007a7a01007b7b01"
    "007c7c01007d7d01007e7e01007f7f01008080010081810100828201008383010084"
    "84010085850100868601008787010088880100898901008a8a01008b8b01008c8c01"
    "008d8d01008e8e01008f8f0100909001009191010092920100939301009494010095"
    "950100969601009797010098980100999901009a9a01009b9b01009c9c01009d9d01"
    "009e9e01009f9f0100a0a00100a1a10100a2a20100a3a30100a4a40100a5a50100a6"
    "a60100a7a70100a8a80100a9a90100aaaa0100abab0100acac0100adad0100aeae01"
    "00afaf0100b0b00100b1b10100b2b20100b3b30100b4b40100b5b50100b6b60100b7"
    "b70100b8b80100b9b90100baba0100bbbb0100bcbc0100bdbd0100bebe0100bfbf01"
    "00c0c00100c1c10100c2c20100c3c30100c4c40100c5c50100c6c60100c7c70100c8"
    "c80100c9c90100caca0100cbcb0100cccc0100cdcd0100cece0100cfcf0100d0d001"
    "00d1d10100d2d20100d3d30100d4d40100d5d50100d6d60100d7d70100d8d80100d9"
    "d90100dada0100dbdb0100dcdc0100dddd0100dede0100dfdf0100e0e00100e1e101"
    "00e2e20100e3e30100e4e40100e5e50100e6e60100e7e70100e8e80100e9e90100ea"
    "ea0100ebeb0100ecec0100eded0100eeee0100efef0100f0f00100f1f10100f2f201"
    "00f3f30100f4f40100f5f5010002020a0003020a0004020a000501010006020a0007"
    "020a00090101000c0c0a000d000e000f170100100011001200130014001500160027"
    "7801003a0044020a00450046004a0006005b020a005e0101005f1701006060010061"
    "600100680b010069006c6d01006e6f0100746601007600770079007a007b00880092"
    "920100930098020a0099020a009a020a009b0101009c0c0a00ac020a00d100030000"
)

# TNS DATA framing (Type=TNS_DATA=6).
tns_packet = struct.pack(">HhBBhh", len(TTI_DTY_BODY) + 10, 0, 6, 0, 0, 0) + TTI_DTY_BODY


def ipv4_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, tcp_hdr_plus_data: bytes) -> int:
    pseudo = src + dst + b"\x00\x06" + struct.pack(">H", len(tcp_hdr_plus_data))
    buf = pseudo + tcp_hdr_plus_data
    if len(buf) % 2:
        buf += b"\x00"
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


src_ip = bytes([127, 0, 0, 1])
dst_ip = bytes([127, 0, 0, 1])
src_port = 54321
dst_port = 1521

# TCP header: src_port, dst_port, seq, ack, dataofs/flags, win, csum, urg.
tcp_no_csum = struct.pack(
    ">HHIIBBHHH",
    src_port, dst_port,
    1,            # seq
    0,            # ack
    0x50,         # data offset = 5 (20 bytes), no reserved bits
    0x18,         # flags: PSH|ACK
    65535,        # window
    0,            # checksum (computed below)
    0,            # urgent
)
csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns_packet)
tcp_hdr = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
tcp_segment = tcp_hdr + tns_packet

ip_total_len = 20 + len(tcp_segment)
ip_no_csum = struct.pack(
    ">BBHHHBBH",
    0x45,         # version+ihl
    0,            # tos
    ip_total_len,
    1,            # id
    0x4000,       # flags=DF, frag=0
    64,           # ttl
    6,            # proto = TCP
    0,            # checksum
) + src_ip + dst_ip
ip_csum = ipv4_checksum(ip_no_csum)
ip_hdr = ip_no_csum[:10] + struct.pack(">H", ip_csum) + ip_no_csum[12:]
ip_packet = ip_hdr + tcp_segment

# pcap global header — LINKTYPE_RAW = 101 (IPv4-only payload).
pcap_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
pkt_hdr = struct.pack("<IIII", 0, 0, len(ip_packet), len(ip_packet))

out = os.path.join(os.path.dirname(__file__), "tns_dty.pcap")
with open(out, "wb") as f:
    f.write(pcap_hdr + pkt_hdr + ip_packet)
print(f"wrote {out} ({os.path.getsize(out)} bytes)")
