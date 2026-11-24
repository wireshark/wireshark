#!/usr/bin/env python3
# Generates test/captures/capwap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CAPWAP dissector
(packet-capwap.c).

CAPWAP control runs on UDP port 5246 and CAPWAP data on UDP port 5247.
Each packet starts with a one octet preamble (version and type; type 1
means a DTLS record follows), then the CAPWAP header (HLEN, RID, WBID,
the T F L W M K flags, fragment ID and offset, optional radio MAC and
wireless specific information). Control packets carry a control header
and message elements (RFC 5415, the IEEE 802.11 binding of RFC 5416 and
Cisco and Fortinet vendor specific elements); data packets carry an
802.3 or 802.11 frame or a keep-alive. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcapwap.py <output directory>

Writes:
  capwap-coverage.pcap            every message type, every message
                                  element the dissector decodes, every
                                  Fortinet and Cisco vendor element,
                                  header options, DTLS, keep-alive, data
                                  payloads and reassembly of control and
                                  data messages
  capwap-coverage-malformed.pcap  wrong element lengths, truncated
                                  elements, header length 0, bad keep-alive
                                  and header lengths
"""

import os
import struct
import sys

WTP = '192.0.2.10'
AC = '192.0.2.1'
CTRL = 5246
DATA = 5247
WTP_CPORT = 32768
WTP_DPORT = 32769

VENDOR_FORTINET = 12356
VENDOR_CISCO_WIFI = 4232704


def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4_udp(payload, sport, dport, src, dst, ident=1):
    s, d = ip4(src), ip4(dst)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = s + d + struct.pack('!BBH', 0, 17, len(udp))
    c = ip_csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('!H', c) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0, s, d)
    return ip[:10] + struct.pack('!H', ip_csum(ip)) + ip[12:] + udp


def eth(payload, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + b'\x08\x00' + payload


_ident = [0]


def udp_frame(payload, sport, dport, src, dst):
    _ident[0] += 1
    return eth(ipv4_udp(payload, sport, dport, src, dst, _ident[0]))


def to_ac(p, port=CTRL):
    return udp_frame(p, WTP_CPORT if port == CTRL else WTP_DPORT, port, WTP, AC)


def to_wtp(p, port=CTRL):
    return udp_frame(p, port, WTP_CPORT if port == CTRL else WTP_DPORT, AC, WTP)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# Header flags (the low 9 bits of the first header word)
F_T = 0x100
F_F = 0x080
F_L = 0x040
F_W = 0x020
F_M = 0x010
F_K = 0x008


def capwap(flags=0, rid=0, wbid=1, mac=None, wireless=None, frag_id=0,
           frag_off=0, hlen=None):
    """Preamble and CAPWAP header. The header length is computed like the
    dissector does (optional parts padded to 4 octets from the start of
    the packet) unless given."""
    opt = b''
    pos = 8
    if mac is not None:
        opt += bytes([len(mac)]) + mac
        pos += 1 + len(mac)
        pad = (-pos) % 4
        opt += bytes(pad)
        pos += pad
    if wireless is not None:
        opt += wireless
        pos += len(wireless)
        pad = (-pos) % 4
        opt += bytes(pad)
        pos += pad
    if mac is not None:
        flags |= F_M
    if wireless is not None:
        flags |= F_W
    if hlen is None:
        hlen = pos // 4
    w = (hlen << 19) | (rid << 14) | (wbid << 9) | flags
    return (b'\x00' + struct.pack('!I', w)[1:] + struct.pack('!HH', frag_id, frag_off << 3)
            + opt)


def control(elements, msgtype=1, seq=0, flags=0):
    body = b''.join(elements)
    return struct.pack('!IBHB', msgtype, seq, len(body) + 3, flags) + body


def elem(t, v):
    return struct.pack('!HH', t, len(v)) + v


def vsp(vendor, eid, data):
    return elem(37, struct.pack('!IH', vendor, eid) + data)


def forti(eid, data):
    return vsp(VENDOR_FORTINET, eid, data)


def cisco(eid, data):
    return vsp(VENDOR_CISCO_WIFI, eid, data)


def sub8(vendor, t, v):
    """AC Information / WTP Descriptor sub-element: vendor, type, length."""
    return struct.pack('!IHH', vendor, t, len(v)) + v


def sub4(t, v):
    """WTP Board Data sub-element: type, length."""
    return struct.pack('!HH', t, len(v)) + v


MAC1 = bytes.fromhex('020000000a01')
MAC2 = bytes.fromhex('020000000a02')
BSSID = bytes.fromhex('020000000b01')
EUI64 = bytes.fromhex('0200000000000c01')


def inner_udp(data=b'capwap-test', seq=1):
    return ipv4_udp(data, 40000 + seq, 9, '10.0.0.1', '10.0.0.2', seq)


def inner_eth(data=b'capwap-test', seq=1):
    return eth(inner_udp(data, seq), MAC1, MAC2)


def inner_wlan_bsfc(seq=1):
    """802.11 data frame (To DS), no FCS, frame control octets swapped."""
    return (bytes([0x01, 0x08]) + struct.pack('<H', 0) + BSSID + MAC1 + MAC2
            + struct.pack('<H', seq << 4) + bytes.fromhex('aaaa03000000') + b'\x08\x00'
            + inner_udp(b'capwap-wlan', seq))


def dtls_alert():
    # DTLS 1.2 plaintext Alert (epoch 0): warning, close_notify
    return struct.pack('!BHH6sH', 21, 0xfefd, 0, b'\0\0\0\0\0\1', 2) + b'\x01\x00'


# ---------------------------------------------------------------------------
# Message elements

def ac_descriptor():
    v = struct.pack('!HHHHBBBB', 3, 1000, 2, 64, 0x06, 1, 0, 0x06)
    v += sub8(9, 4, b'AC-HW-1.0')
    v += sub8(9, 5, b'8.10.130.0')
    v += sub8(14179, 6, b'\x01\x02')     # unknown AC information type
    return elem(1, v)


def wtp_board_data():
    v = struct.pack('!I', 14179)
    v += sub4(0, b'AIR-CAP3702I')
    v += sub4(1, b'FTX1234ABCD')
    v += sub4(2, b'\x00\x01')
    v += sub4(3, b'A0')
    v += sub4(4, MAC1)
    v += sub4(9, b'\xde\xad')            # unknown board data type
    return elem(38, v)


def wtp_descriptor():
    v = struct.pack('!BBB', 2, 2, 2)
    v += struct.pack('!BH', 1, 0x000c) + struct.pack('!BH', 1, 0x0003)
    v += sub8(14179, 0, b'HW-1')
    v += sub8(14179, 1, b'SW-8.10')
    v += sub8(14179, 2, b'BOOT-1')
    v += sub8(14179, 3, b'OTHER-2')
    v += sub8(14179, 9, b'XY')           # unknown descriptor type
    return elem(39, v)


def wtp_descriptor_draft8():
    """Decodes in both modes: draft 8 has 2 octets of encryption
    capabilities and one sub-element; RFC 5415 reads the first of those
    octets as 10 encryption capabilities that reach past the end of the
    sub-element loop, so no sub-element is read."""
    v = struct.pack('!BB', 2, 1) + bytes([0x0a, 0x08]) + sub8(9, 0, b'C' * 24)
    assert len(v) == 36
    return elem(39, v)


def radio_info(rid=1, types=0x0f):
    return elem(1048, struct.pack('!B3sB', rid, b'\0\0\0', types))


def ieee_ie():
    v = struct.pack('!BBB', 1, 1, 0xc0)
    # no SSID: the 802.11 SSID decoder skips every SSID after the first
    # until a management frame resets its beacon padding state
    v += bytes([1, 4, 0x82, 0x84, 0x8b, 0x96])
    v += bytes([3, 1, 6])
    return elem(1029, v)


def add_wlan(key=b'0123456789abc', ssid=b'capwap-ssid'):
    v = struct.pack('!BBHBBH', 1, 2, 0xffff, 1, 2, len(key)) + key
    v += bytes(6) + struct.pack('!BBBBB', 1, 1, 0, 1, 0) + ssid
    return elem(1024, v)


def update_wlan(key=b'KEY0'):
    return elem(1044, struct.pack('!BBHBBH', 1, 2, 0x5555, 1, 3, len(key)) + key)


def wtp_qos():
    v = struct.pack('!BB', 1, 0x1f)
    for q in range(4):
        v += struct.pack('!BHHBBB', 10 + q, 3 + q, 7 + q, 2, q, 46 - q)
    return elem(1045, v)


def station():
    return elem(1036, struct.pack('!BHB6sHB', 1, 5, 0, MAC1, 0x0421, 2) + bytes([0x82, 0x84, 0x0b]))


def session_key():
    return elem(1038, MAC1 + struct.pack('!H', 0xc000) + bytes(range(6)) + bytes(range(6, 12))
                + bytes(range(16)))


FORTINET = [
    (16, struct.pack('!BH', 1, 30) + (600).to_bytes(3, 'big') + struct.pack('!HH', 30, 15)),
    (24, b'\x01\x01'),
    (32, b'\x01'),
    (33, b'\x01\x02\x0c' + MAC1 + MAC2),
    (33, b'\x00\x01\x00'),                         # no MAC address
    (34, b'FP221C3X12345678\x01'),
    (36, b'\x01\x06' + MAC1 + BSSID + b'\x02'),
    (49, b'\x01\x0f\x01\x02'),
    (50, struct.pack('!H', 6) + b'FGT60E' + struct.pack('!IIIII', 1, 2, 300, 60, 0)),
    (51, b'\x01\x02'),
    (52, b'\x01\x01'),
    (53, b'\x01\x01'),
    (54, b'\x01\x03'),
    (55, b'\x01\x00'),
    (56, b'\x01' + bytes.fromhex('0a0b0c0d0e0f')),
    (81, struct.pack('!I', 1)),
    (82, b'adminpass'),
    (83, b'ABC'),
    (84, b'\x01' + struct.pack('!H', 841) + b'US '),
    (99, b'\x01' + struct.pack('!H', 1)),
    (103, b'\x01\x01'),
    (104, b'\x01\x01'),
    (106, b'\x01\x01' + struct.pack('!H', 30)),
    (108, b'\x01\x01' + b'scan-ssid'),
    (112, b'\x01\x01\x1e'),
    (128, b'\x01\x02\x01\x00'),
    (145, b'\x01\x02\x01'),
    (147, b'\x01' + struct.pack('!H', 0x0164)),
    (148, b'\x01' + struct.pack('!H', 0x0003)),
    (149, b'\x01\x02' + struct.pack('!I', 6000)),
    (150, b'\x01\x02' + ip4('10.1.0.1') + ip4('255.255.255.0')),
    (151, b'\x01\x02'),
    (161, struct.pack('!H', 100)),
    (167, b'\x01\x02' + b'psk-secret'),
    (176, b'\x01'),
    (177, struct.pack('!H', 1)),
    (192, b'\x01\x02\x03\x04'),
    (193, b'\x01' + struct.pack('!H', 20)),
    (209, b'\x01' + struct.pack('!I', 1)),
    (146, b'\x01\x02\xaa\xbb'),                    # VAP elements (not decoded)
    (152, b'\x01\x02\xcc'),
    (153, b'\x01\x02'),
    (163, b'\x01\x02\x00\x00\x00'),
    (65, b'\x01\xaa'),                             # radio elements (not decoded)
    (170, b'\x01'),
    (171, b'\x02\x01\x02'),
    (250, b'\x01\x02\x03'),                        # unknown
]

CISCO = [
    (2, b'\x01' + ip4('192.0.2.1')),
    (5, b'AP-CAPWAP-01'),
    (6, b'\x01' + b'\x01\x02\x03\x04' + b'\x08\x0a\x82\x00' + struct.pack('!HHHH', 3, 6000, 5, 6000)),
    (54, b'\x02\x01'),
    (83, ip4('192.0.2.10') + ip4('255.255.255.0') + ip4('192.0.2.254') + b'\x01' + bytes(4)),
    (108, struct.pack('!II', 3600, 7200)),
    (123, b'default-group'),
    (125, struct.pack('!H', 1)),
    (151, struct.pack('!I', 1700000000) + b'\x01'),
    (207, b'\x01\x00\x02\x03'),
    (208, b'\x00'),
    (44, b'\x30\x82\x00\x00'),                     # not decoded
]

UNDECODED = [7, 9, 13, 14, 15, 17, 19, 21, 22, 34, 42, 43, 46, 47, 1035, 1039, 1043, 1047,
             60, 2000]


def main_frames():
    frames = []
    # 1-2 Discovery Request / Response
    frames.append(to_ac(capwap() + control([
        elem(20, b'\x01'), wtp_board_data(), wtp_descriptor(), elem(41, b'\x0e'),
        elem(44, b'\x02'), radio_info(0, 0x01), radio_info(1, 0x0e), elem(52, b'\xff' * 12),
        vsp(9, 1, b'\x01\x02\x03')], 1, 0)))
    frames.append(to_wtp(capwap() + control([
        ac_descriptor(), elem(4, b'capwap-ac'), elem(10, ip4(AC) + struct.pack('!H', 2)),
        elem(11, bytes.fromhex('20010db8000000000000000000000001') + struct.pack('!H', 3)),
        radio_info(1, 0x0f)], 2, 0)))
    # 3-4 Join Request / Response
    frames.append(to_ac(capwap() + control([
        elem(28, b'Building 1'), wtp_board_data(), wtp_descriptor(), elem(45, b'wtp-01'),
        elem(35, bytes(range(16))), elem(41, b'\x04'), elem(44, b'\x01'), radio_info(),
        elem(53, b'\x01'), elem(30, ip4(WTP)), elem(50, bytes.fromhex('20010db8000000000000000000000010')),
        elem(51, b'\x02'), elem(29, struct.pack('!H', 1500)),
        elem(48, struct.pack('!HHHHHHHB', 7, 1, 2, 1, 0, 1, 2, 3))], 3, 1)))
    frames.append(to_wtp(capwap() + control([
        elem(33, struct.pack('!I', 0)), ac_descriptor(), elem(4, b'capwap-ac'),
        elem(2, ip4('192.0.2.1') + ip4('192.0.2.2')),
        elem(2, ip4('192.0.2.3') + b'\x00\x01'),             # not a multiple of 4
        elem(3, bytes.fromhex('20010db8000000000000000000000001') * 2),
        elem(3, bytes(20)),                                  # not a multiple of 16
        elem(30, ip4(AC)), elem(1060, b'\x02\x00\x01'), elem(1061, b'\x01')], 4, 1)))
    # 5-6 Configuration Status Request / Response
    frames.append(to_ac(capwap() + control([
        elem(4, b'capwap-ac'), elem(5, b'\x01primary-ac'), elem(5, b'\x02backup-ac'),
        elem(31, b'\x01\x01'), elem(36, struct.pack('!H', 120)),
        elem(48, struct.pack('!HHHHHHHB', 1, 0, 0, 0, 0, 0, 0, 0)),
        elem(49, ip4(WTP) + ip4('255.255.255.0') + ip4('192.0.2.254') + b'\x01'),
        elem(1025, b'\x01\x01\x02\x03\x01\x02\x01'),
        elem(1028, b'\x01\x00\x06\x01' + struct.pack('!I', 100)),
        elem(1030, struct.pack('!BBHBBHII', 1, 0, 2347, 7, 4, 2346, 512, 512)),
        elem(1032, struct.pack('!BBHHH', 1, 0, 1, 11, 20)),
        elem(1033, struct.pack('!BBBBI', 2, 0, 36, 0x0f, 100)),
        elem(1040, b'\x01\x82\x84\x8b\x96'),
        elem(1041, struct.pack('!BBH', 1, 0, 17)),
        elem(1042, struct.pack('!BBHHH', 1, 3, 20, 17, 14)),
        elem(1046, struct.pack('!BBBB6sH4s', 1, 1, 4, 1, BSSID, 100, b'US \0')),
        radio_info(2, 0x08), elem(40, b'\x01')], 5, 2)))
    frames.append(to_wtp(capwap() + control([
        elem(12, b'\x05\x1e'), elem(16, b'\x01' + struct.pack('!H', 120)),
        elem(23, struct.pack('!I', 300)), elem(40, b'\x02'), elem(2, ip4('192.0.2.1')),
        wtp_qos(), elem(1034, b'\x01\x02\x04\x0b\x16')], 6, 2)))
    # 7-8 Configuration Update Request / Response
    frames.append(to_wtp(capwap() + control([
        elem(6, struct.pack('!I', 3908988000)), elem(31, b'\xff\x02'),
        elem(25, struct.pack('!I', 14179) + b'image-8.10.bin')], 7, 3)))
    frames.append(to_ac(capwap() + control([elem(33, struct.pack('!I', 2))], 8, 3)))
    # 9-10 WTP Event Request / Response
    frames.append(to_ac(capwap() + control([
        elem(32, b'\x01\x02\x00'), elem(1031, b'\x01\x02' + MAC2),
        elem(18, b'\x01\x06' + MAC1)], 9, 4)))
    frames.append(to_wtp(capwap() + control([], 10, 4)))
    # 11-12 Change State Event Request / Response
    frames.append(to_ac(capwap() + control([
        elem(32, b'\x01\x01\x00'), elem(32, b'\x02\x02\x03'),
        elem(33, struct.pack('!I', 0))], 11, 5)))
    frames.append(to_wtp(capwap() + control([], 12, 5)))
    # 13-14 Echo Request / Response
    frames.append(to_ac(capwap() + control([], 13, 6)))
    frames.append(to_wtp(capwap() + control([], 14, 6)))
    # 15-18 Image Data Request / Response
    frames.append(to_ac(capwap() + control([
        elem(25, struct.pack('!I', 14179) + b'image-8.10.bin'), elem(27, b'')], 15, 7)))
    frames.append(to_wtp(capwap() + control([
        elem(33, struct.pack('!I', 0)), elem(26, struct.pack('!I', 4096) + bytes(range(16)))], 16, 7)))
    frames.append(to_wtp(capwap() + control([elem(24, b'\x01' + bytes(range(32)))], 15, 8)))
    frames.append(to_wtp(capwap() + control([elem(24, b'\x02' + b'EOF')], 15, 9)))
    # 19 Image Data Request with an error indication (Data Type 5, no data)
    frames.append(to_ac(capwap() + control([elem(24, b'\x05')], 15, 10)))
    # 20-21 Reset Request / Response
    frames.append(to_wtp(capwap() + control([
        elem(25, struct.pack('!I', 14179) + b'image-8.10.bin')], 17, 11)))
    frames.append(to_ac(capwap() + control([elem(33, struct.pack('!I', 0))], 18, 11)))
    # 22-23 Primary Discovery Request / Response
    frames.append(to_ac(capwap() + control([elem(20, b'\x00'), wtp_board_data(), wtp_descriptor(),
                                           elem(41, b'\x02'), elem(44, b'\x00'), radio_info()], 19, 12)))
    frames.append(to_wtp(capwap() + control([ac_descriptor(), elem(4, b'capwap-ac'), radio_info()], 20, 12)))
    # 24-25 Data Transfer Request / Response: elements not decoded
    frames.append(to_ac(capwap() + control([elem(t, bytes([t & 0xff, 1, 2])) for t in UNDECODED], 21, 13)))
    frames.append(to_wtp(capwap() + control([elem(33, struct.pack('!I', 0))], 22, 13)))
    # 26-27 Clear Configuration Request / Response
    frames.append(to_wtp(capwap() + control([], 23, 14)))
    frames.append(to_ac(capwap() + control([elem(33, struct.pack('!I', 0))], 24, 14)))
    # 28-29 Station Configuration Request / Response
    frames.append(to_wtp(capwap() + control([
        elem(8, b'\x01\x06' + MAC1),                       # no VLAN name
        elem(8, b'\x01\x06' + MAC2 + b'guest-vlan'),
        elem(8, b'\x01\x08' + EUI64 + b'vlan8'),
        elem(8, b'\x01\x04' + MAC1[:4] + b'v4'),          # neither EUI-48 nor EUI-64
        elem(18, b'\x01\x06' + MAC1), elem(18, b'\x01\x08' + EUI64),
        elem(18, b'\x01\x04' + MAC1[:4] + b'\0\0'),
        station(), elem(1037, MAC1 + struct.pack('!H', 0x0005)), session_key()], 25, 15)))
    frames.append(to_ac(capwap() + control([elem(33, struct.pack('!I', 0))], 26, 15)))
    # 30-31 IEEE 802.11 WLAN Configuration Request / Response
    frames.append(to_wtp(capwap() + control([
        add_wlan(), add_wlan(b'', b'open-ssid'), update_wlan(), update_wlan(b''),
        elem(1027, b'\x01\x03'), ieee_ie()], 3398913, 16)))
    frames.append(to_ac(capwap() + control([
        elem(33, struct.pack('!I', 0)), elem(1026, b'\x01\x02' + BSSID)], 3398914, 16)))
    # 32 an unknown message type, enterprise specific
    frames.append(to_ac(capwap() + control([elem(4, b'x')], 0x00377399, 17)))
    # 33-34 Fortinet vendor specific elements (Configuration Update Request)
    half = len(FORTINET) // 2
    frames.append(to_wtp(capwap() + control([forti(e, d) for e, d in FORTINET[:half]], 7, 18)))
    frames.append(to_wtp(capwap() + control([forti(e, d) for e, d in FORTINET[half:]], 7, 19)))
    # 35 Cisco vendor specific elements
    frames.append(to_wtp(capwap() + control([cisco(e, d) for e, d in CISCO], 4, 20)))
    # 36 the reproducer of the Supported MAC Profiles fix (the review
    #    capwap_small.py frame 1): AC Descriptor, WTP Board Data and WTP
    #    Descriptor whose last sub-element ends the element, and a
    #    Supported MAC Profiles element with 3 profiles 0, 1, 2
    acinfo = lambda t, v: struct.pack('!IHH', 9, t, len(v)) + v
    acdesc = elem(1, struct.pack('!HHHHBBBB', 1, 10, 2, 20, 0, 0, 0, 0) +
                  acinfo(4, b'HW') + acinfo(5, b'SW'))
    board = elem(38, struct.pack('!I', 9) + struct.pack('!HH', 0, 3) + b'MOD' +
                 struct.pack('!HH', 1, 3) + b'SER')
    wtpdesc = elem(39, struct.pack('!BBB', 1, 1, 1) + struct.pack('!BH', 1, 0) +
                   acinfo(0, b'HW') + acinfo(1, b'SW') + acinfo(2, b'BT'))
    macprof = elem(1060, bytes([3, 0, 1, 2]))
    frames.append(udp_frame(capwap() + control([acdesc, board, wtpdesc, macprof]),
                            CTRL, CTRL, '192.0.2.1', '192.0.2.2'))

    # Header options on the control channel
    # 37 radio MAC address (EUI-48) and wireless specific information
    #    (AC to WTP: IEEE 802.11 destination WLANs)
    frames.append(to_wtp(capwap(mac=MAC1, wireless=b'\x04' + struct.pack('!HH', 0x0005, 0)) +
                         control([], 13, 21)))
    # 38 radio MAC address (EUI-64)
    frames.append(to_ac(capwap(mac=EUI64) + control([], 13, 22)))
    # 39 radio MAC address of 4 octets, wireless information with WBID 3
    frames.append(to_ac(capwap(wbid=3, mac=MAC1[:4], wireless=b'\x02\x01\x02') + control([], 13, 23)))
    # 40 wireless information that decodes the same with the draft 8 Cisco
    #    preference (that one reads a WBID octet first and assumes a length
    #    of 4), and a WTP Descriptor that decodes in both modes
    frames.append(to_ac(capwap(wireless=b'\x04\x01\x10\x20\x30') +
                        control([wtp_descriptor_draft8()], 1, 24)))

    # 41-43 a fragmented Configuration Update Request (Image Data), fragment ID 7
    msg = control([elem(24, b'\x01' + bytes(i & 0xff for i in range(200))),
                   elem(4, b'fragmented-ac')], 7, 25)
    parts = [msg[0:96], msg[96:192], msg[192:]]
    off = 0
    for i, p in enumerate(parts):
        fl = F_F | (F_L if i == len(parts) - 1 else 0)
        frames.append(to_wtp(capwap(flags=fl, frag_id=7, frag_off=off // 8) + p))
        off += len(p)
    # 44 a fragment without payload (ignored)
    frames.append(to_wtp(capwap(flags=F_F, frag_id=8)))

    # Data channel
    # 45 IEEE 802.3 frame
    frames.append(to_ac(capwap(wbid=1) + inner_eth(b'capwap-8023', 1), DATA))
    # 46 IEEE 802.11 frame (frame control swapped), with the WTP to AC
    #    frame info (RSSI, SNR, data rate)
    frames.append(to_ac(capwap(F_T, rid=1, wbid=1, wireless=b'\x04' + struct.pack('!bBH', -60, 30, 540))
                        + inner_wlan_bsfc(2), DATA))
    # 47 IEEE 802.11 frame to the WTP with destination WLANs and radio MAC
    frames.append(to_wtp(capwap(F_T, rid=1, wbid=1, mac=BSSID, wireless=b'\x04' + struct.pack('!HH', 3, 0))
                         + inner_wlan_bsfc(3), DATA))
    # 48 native frame with WBID 0 (Cisco) and 49 with WBID 2 (not decoded)
    frames.append(to_ac(capwap(F_T, wbid=0) + b'\x01\x02\x03\x04wbid0', DATA))
    frames.append(to_ac(capwap(F_T, wbid=2) + b'\x05\x06\x07\x08wbid2', DATA))
    # 50-51 keep-alive in both directions (Session ID)
    ka = elem(35, bytes(range(16)))
    frames.append(to_ac(capwap(F_K) + struct.pack('!H', 2 + len(ka)) + ka, DATA))
    frames.append(to_wtp(capwap(F_K) + struct.pack('!H', 2 + len(ka)) + ka, DATA))
    # 52-53 a fragmented 802.3 frame, fragment ID 9
    fr = inner_eth(b'D' * 100, 4)
    frames.append(to_ac(capwap(F_F, frag_id=9, frag_off=0) + fr[:64], DATA))
    frames.append(to_ac(capwap(F_F | F_L, frag_id=9, frag_off=8) + fr[64:], DATA))
    # 54 a data fragment without payload (ignored)
    frames.append(to_ac(capwap(F_F, frag_id=10), DATA))
    # 55-56 DTLS on the control and data channel
    frames.append(to_ac(b'\x01\x00\x00\x00' + dtls_alert()))
    frames.append(to_ac(b'\x01\x00\x00\x00' + dtls_alert(), DATA))
    return frames


def malformed_frames():
    frames = []
    # 1 header length 0 (the review capwap_small.py frame 2); the
    #   dissector continues after the header it decoded
    frames.append(udp_frame(capwap(hlen=0) + control([elem(1060, bytes([3, 0, 1, 2]))]),
                            CTRL, CTRL, '192.0.2.1', '192.0.2.2'))
    # 2 every length check of the element decoder: one element too short or
    #   too long for each type (each gets an error expert info)
    bad = [(1, 4), (2, 2), (3, 8), (4, 0), (5, 1), (6, 3), (8, 4), (10, 4), (11, 4), (12, 1),
           (16, 2), (18, 4), (20, 2), (23, 2), (24, 0), (25, 3), (26, 4), (27, 2), (28, 0),
           (29, 1), (30, 2), (31, 1), (32, 2), (33, 2), (35, 4), (36, 1), (37, 6), (38, 4),
           (39, 8), (40, 2), (41, 2), (44, 2), (45, 0), (48, 4), (49, 4), (50, 4), (51, 2),
           (52, 0), (53, 2), (1024, 8), (1025, 2), (1026, 2), (1027, 1), (1028, 2), (1029, 2),
           (1030, 2), (1031, 2), (1032, 2), (1033, 2), (1034, 2), (1036, 4), (1037, 2),
           (1038, 4), (1040, 2), (1041, 2), (1042, 2), (1044, 4), (1046, 2), (1048, 2),
           (1060, 1), (1061, 2)]
    frames.append(to_ac(capwap() + control([elem(t, bytes(n)) for t, n in bad], 1)))
    # 3 Image Data error indication that carries data
    frames.append(to_ac(capwap() + control([elem(24, b'\x05data')], 15)))
    # 4 Fortinet MAC lists with a length that is not a multiple of 6
    frames.append(to_wtp(capwap() + control([forti(33, b'\x01\x02\x05' + MAC1[:5]),
                                             forti(36, b'\x01\x04' + MAC1)], 7)))
    # 5 Add Station with a MAC length past the end of the element (the
    #   VLAN name length went negative before the fix on the branch; the
    #   MAC address is now read from the next element and no VLAN name is
    #   added), a Fortinet WTP Allow with only the allow octet (empty
    #   serial number), then a MAC length past the end of the packet
    frames.append(to_wtp(capwap() + control([elem(8, b'\x01\x0a' + bytes(6)),
                                             elem(4, b'next-element'),
                                             forti(34, b'\x01'),
                                             elem(8, b'\x01\xff' + bytes(6))], 25)))
    # 6 header length that does not match the optional parts
    frames.append(to_ac(capwap(hlen=5) + control([], 13)))
    # 7 keep-alive with a wrong length
    frames.append(to_ac(capwap(F_K) + struct.pack('!H', 99) + elem(35, bytes(16)), DATA))
    # 8 element length past the end of the packet
    frames.append(to_ac(capwap() + control([elem(4, b'name')])[:-2] + b'\x00\x40ab'))
    # 9 truncated header
    frames.append(to_ac(b'\x00\x10\x02'))
    # 10 Fortinet Spectrum Analysis / VAP PSK / VAP element with 1 octet
    #    of data (the length goes negative) -- one per frame
    for eid in (108, 167, 146, 65):
        frames.append(to_wtp(capwap() + control([forti(eid, b'\x01')], 7)))
    # 14 WTP QoS shorter than its fixed size
    frames.append(to_wtp(capwap() + control([elem(1045, b'\x01\x00')], 6)))
    # 15 fragmented control message with the reassembly giving a short
    #    control header
    frames.append(to_wtp(capwap(F_F | F_L, frag_id=20) + b'\x00\x00\x00'))
    # 16 keep-alive with a truncated element
    frames.append(to_ac(capwap(F_K) + struct.pack('!H', 8) + b'\x00\x23\x00\x10ab', DATA))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'capwap-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'capwap-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
