#!/usr/bin/env python3
# Generates test/captures/lon_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LON coverage captures. Usage: mklon.py <outdir>

LON PDUs are carried in CN/IP (EIA-852) data packets over UDP ports
1628 (normal) and 1629 (urgent), both registered by default. Every frame
of the main capture is Ethernet/IPv4/UDP/CN-IP/LON.
"""
import os
import struct
import sys

def pcap(path, pkts, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_eth(payload, sport, dport, ip_id=1):
    src = bytes([192, 0, 2, 1]); dst = bytes([192, 0, 2, 2])
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ip_id, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp

def cnip(lon, ptype=1, pcode=0, seq=0, exth=b''):
    """CN/IP header (20 octets + extension) followed by the LON PDU"""
    n = len(exth) // 4
    length = 20 + len(exth) + len(lon)
    return struct.pack('>HBBBBHIII', length, 1, ptype, n, pcode, 0x0100, 0x11223344,
                       seq, 1000 + seq) + exth + lon

def npdu(pdu_fmt, addr_fmt, dom_len, version=0):
    return bytes([(version << 6) | (pdu_fmt << 4) | (addr_fmt << 2) | dom_len])

# address parts: 0 broadcast, 1 multicast, 2a unicast, 2b multicast, 3 uid
ADDR = {
    '0': (0, bytes([0x01, 0x02, 0x03])),
    '1': (1, bytes([0x01, 0x02, 0x04])),
    '2a': (2, bytes([0x01, 0x82, 0x05, 0x06])),
    '2b': (2, bytes([0x01, 0x02, 0x05, 0x06, 0x07, 0x08])),
    '3': (3, bytes([0x01, 0x02, 0x03, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6])),
}
DOM = {0: b'', 1: b'\x11', 2: b'\x11\x22\x33', 3: bytes(range(0x11, 0x17))}

def lon(ppdu, pdu_fmt, addr, dom_len, body, version=0):
    af, ab = ADDR[addr]
    return bytes([ppdu]) + npdu(pdu_fmt, af, dom_len, version) + ab + DOM[dom_len] + body

def tpdu(auth, ttype, trans):
    return bytes([(auth << 7) | (ttype << 4) | trans])

NV = bytes([0xc1, 0x23])        # network variable, direction and selector
NV2 = bytes([0x85, 0xff])
APP = bytes([0x15])             # application message
NM = bytes([0x65])              # NM_UPDATE_KEY
ND = bytes([0x51])              # ND_QUERY_STATUS
FF = bytes([0x43])              # foreign frame

def main(out):
    L = []     # LON PDUs
    # Every address format with every domain length: an APDU with a
    # network variable (PDU format 3)
    for a in ADDR:
        for d in range(4):
            L.append(lon(0x00 + len(L) % 64, 3, a, d, NV + b'\x01\x02'))
    # PPDU bits: priority, alternate path, delta backlog
    L.append(lon(0xc0, 3, '3', 0, NV))
    L.append(lon(0x80 | 0x3f, 3, '0', 1, APP + b'\xaa'))
    L.append(lon(0x40 | 0x05, 3, '1', 2, ND))
    # APDU destination types: network variable (both bytes), application,
    # network management (with and without the 0x7f service request),
    # network diagnostic, foreign frame; with and without a data tail
    L.append(lon(0x01, 3, '2a', 0, NV2))
    L.append(lon(0x01, 3, '2a', 0, APP))
    L.append(lon(0x01, 3, '2a', 0, bytes([0x3f]) + b'\x01\x02\x03'))
    for code in (0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
                 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x60, 0x7e):
        L.append(lon(0x01, 3, '2a', 0, bytes([code]) + b'\x00\x01'))
    # NM_MANUAL_SERVICE_REQUEST: unique node id and node name follow
    L.append(lon(0x01, 3, '3', 0, bytes([0x7f]) + bytes(range(0xb0, 0xb6)) + b'NODENAME' + b'\xee'))
    for code in (0x51, 0x52, 0x53, 0x54, 0x55, 0x5f):
        L.append(lon(0x01, 3, '2a', 0, bytes([code])))
    L.append(lon(0x01, 3, '2a', 0, bytes([0x40])))
    L.append(lon(0x01, 3, '2a', 0, bytes([0x4f, 0x99])))
    # TPDU types: ACKD, UnACKD_RPT (with an APDU), ACK, REMINDER and
    # REM/MSG (with an M_List and an APDU), and unknown types
    L.append(lon(0x02, 0, '2a', 0, tpdu(0, 0, 3) + NV + b'\x07'))
    L.append(lon(0x02, 0, '2a', 1, tpdu(1, 0, 4) + APP))
    L.append(lon(0x02, 0, '1', 0, tpdu(0, 1, 5) + NM))
    L.append(lon(0x02, 0, '0', 0, tpdu(1, 2, 6)))
    for mlen in (1, 2, 4):
        L.append(lon(0x02, 0, '2a', 0, tpdu(0, 4, 7) + bytes([mlen]) + bytes(range(1, mlen + 1))))
    # REMINDER with an M_List of 8 and 0 bytes: reproducers of "LON:
    # Register M_List as bytes" (the field was an FT_UINT8 added with the
    # length, which failed for any length but 1)
    L.append(lon(0x02, 0, '2b', 0, tpdu(0, 4, 8) + bytes([8]) + bytes(range(1, 9))))
    L.append(lon(0x02, 0, '2b', 0, tpdu(0, 4, 9) + bytes([0]) + b'\x01'))
    L.append(lon(0x02, 0, '3', 3, tpdu(0, 5, 10) + bytes([3]) + b'\xa1\xa2\xa3' + NV))
    L.append(lon(0x02, 0, '3', 3, tpdu(1, 5, 10) + bytes([0]) + APP + b'\x01'))
    L.append(lon(0x02, 0, '0', 0, tpdu(0, 5, 11) + bytes([6]) + bytes(range(6)) + ND))
    for ttype in (3, 6, 7):
        L.append(lon(0x02, 0, '0', 0, tpdu(0, ttype, 1) + b'\x00'))
    # SPDU types: REQUEST, RESPONSE, REMINDER, REM/MSG, unknown
    L.append(lon(0x03, 1, '2a', 0, tpdu(1, 0, 1) + NV + b'\x01'))
    L.append(lon(0x03, 1, '2a', 0, tpdu(0, 2, 2) + APP))
    L.append(lon(0x03, 1, '2a', 0, tpdu(0, 4, 3) + bytes([5]) + bytes(range(5))))
    L.append(lon(0x03, 1, '2a', 0, tpdu(0, 4, 4) + bytes([0]) + b'\x01'))
    L.append(lon(0x03, 1, '1', 0, tpdu(1, 5, 5) + bytes([2]) + b'\x01\x02' + NM))
    L.append(lon(0x03, 1, '1', 0, tpdu(1, 5, 6) + bytes([0]) + ND))
    L.append(lon(0x03, 1, '1', 0, tpdu(0, 1, 7) + b'\x00'))
    L.append(lon(0x03, 1, '1', 0, tpdu(0, 3, 7) + b'\x00'))
    # AuthPDU: challenge and reply (9 octets are skipped), unknown types
    # (the type is bits 5-4, AuthPDU format bits 7-6 and 3-2 per the
    # dissector's masks)
    L.append(lon(0x04, 2, '2a', 0, bytes([0x00]) + bytes(range(9))))
    L.append(lon(0x04, 2, '2a', 0, bytes([0x20 | 0x05]) + bytes(range(9))))
    L.append(lon(0x04, 2, '3', 1, bytes([0x10]) + bytes(range(9))))
    L.append(lon(0x04, 2, '3', 1, bytes([0x30 | 0x0c]) + bytes(range(9))))
    # protocol version bits
    L.append(lon(0x01, 3, '0', 0, NV, version=1))
    L.append(lon(0x01, 3, '0', 0, NV, version=3))
    pkts = []
    for i, l in enumerate(L):
        # alternate between the normal and the urgent port
        port = 1628 if i % 3 else 1629
        pkts.append(udp_eth(cnip(l, seq=i), 1628, port, ip_id=i + 1))
    # CN/IP frames that are not data packets or carry another protocol code:
    # LON is not called and CN/IP shows the data
    pkts.append(udp_eth(cnip(L[0], ptype=0x63), 1628, 1628, ip_id=200))
    pkts.append(udp_eth(cnip(L[0], pcode=5), 1628, 1628, ip_id=201))
    # CN/IP extension header: skipped
    pkts.append(udp_eth(cnip(L[1], exth=b'\xaa\xbb\xcc\xdd\x11\x22\x33\x44'), 1628, 1628, ip_id=202))
    pcap(os.path.join(out, 'lon-coverage.pcap'), pkts)
    # malformed: truncated PDUs (exceptions)
    bad = []
    def b(l):
        bad.append(udp_eth(cnip(l, seq=900 + len(bad)), 1628, 1628, ip_id=300 + len(bad)))
    b(b'\x00')                                               # only the PPDU
    b(lon(0, 3, '3', 0, b'')[:6])                            # address cut off
    b(lon(0, 3, '0', 3, b'')[:6])                            # domain cut off
    b(lon(0, 0, '0', 0, b''))                                # TPDU missing
    b(lon(0, 0, '0', 0, tpdu(0, 4, 1)))                      # M_List length missing
    b(lon(0, 0, '0', 0, tpdu(0, 4, 1) + bytes([9]) + b'\x01\x02'))   # M_List cut off
    b(lon(0, 0, '0', 0, tpdu(0, 5, 1) + bytes([2]) + b'\x01\x02'))   # no APDU after the M_List
    b(lon(0, 3, '0', 0, b''))                                # APDU missing
    b(lon(0, 3, '0', 0, bytes([0xc1])))                      # NV selector cut off
    b(lon(0, 3, '0', 0, bytes([0x7f]) + b'\x01\x02'))        # service request cut off
    b(lon(0, 1, '0', 0, tpdu(0, 4, 1) + bytes([4]) + b'\x01'))      # SPDU M_List cut off
    b(lon(0, 2, '0', 0, bytes([0x00]) + b'\x01\x02'))        # AuthPDU cut off
    b(lon(0, 2, '0', 0, b''))                                # AuthPDU missing
    pcap(os.path.join(out, 'lon-coverage-malformed.pcap'), bad)
    print(len(pkts), len(bad))

main(sys.argv[1])
