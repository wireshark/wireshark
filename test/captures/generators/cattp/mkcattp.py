#!/usr/bin/env python3
# Generates test/captures/cattp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ETSI Card Application
Toolkit Transport Protocol dissector (packet-cattp.c, ETSI TS 102 127).

CAT-TP runs over UDP. Its dissector is a heuristic that is disabled by
default ("cattp_udp") and can be selected with Decode As on any UDP
port. The captures use UDP port 4116 on the card side; dissect them with
"-d udp.port==4116,cattp" (or "--enable-heuristic cattp_udp"). Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcattp.py <output directory>

Writes:
  cattp-coverage.pcap             SYN with an ICCID (10 and 9 octets) and
                                  other identifications, SYN/ACK, ACK with
                                  and without data, NUL, SEG, EAK with one
                                  and three numbers, RST with every reason
                                  code and an unknown one, a PDU without a
                                  known type, a version 1 PDU, and the
                                  short EAK header reproducer (valid
                                  checksum)
  cattp-coverage-malformed.pcapng the reproducer as published (Exported
                                  PDU, bad checksum), a bad checksum, a
                                  SYN cut in the identification, a RST
                                  without reason code, and datagrams the
                                  heuristic rejects
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
UPORT = 4116
CPORT = 49152


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip_frame(src, dst, proto, l4, ident):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + l4


def udp_frame(sport, dport, payload, src, dst, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    return ip_frame(src, dst, 17, udp, ident)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)




def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def write_pcapng(path, frames):
    """frames: (interface, data); interface 0 is Ethernet, 1 Exported PDU."""
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(pcapng_block(1, struct.pack('<HHI', 1, 0, 262144)))
        f.write(pcapng_block(1, struct.pack('<HHI', 252, 0, 262144)))
        for i, (ifc, p) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


def exported_pdu(payload, name=b'cattp'):
    padded = name + b'\0' * (4 - len(name) % 4)
    return struct.pack('>HH', 12, len(padded)) + padded + struct.pack('>HH', 0, 0) + payload


# CAT-TP -----------------------------------------------------------------

SYN, ACK, EAK, RST, NUL, SEG = 0x80, 0x40, 0x20, 0x10, 0x08, 0x04


def cattp(flags, sport, dport, seq, ack, extra=b'', data=b'', wsize=8, version=0,
          rfu=b'\0\0', hlen=None, plen=None, cksum=True):
    """The 18 octet base header, the variable header part and the data.
    The checksum covers header and data (no pseudo header)."""
    if hlen is None:
        hlen = 18 + len(extra)
    if plen is None:
        plen = len(data)
    hdr = struct.pack('>B2sBHHHHHH', flags | version, rfu, hlen, sport, dport, plen, seq, ack,
                      wsize)
    pdu = hdr + b'\0\0' + extra + data
    if cksum:
        c = csum(pdu[:hlen + plen])
        pdu = pdu[:16] + struct.pack('>H', c) + pdu[18:]
    return pdu


def syn_extra(maxpdu, maxsdu, ident):
    return struct.pack('>HHB', maxpdu, maxsdu, len(ident)) + ident


def eaks(*nums):
    return b''.join(struct.pack('>H', n) for n in nums)


ICCID10 = bytes.fromhex('98942000001234567890')   # ICCID 8949020000214365870_9
ICCID9 = bytes.fromhex('989420000012345678')


def main_frames():
    F = []

    def me(p):      # terminal (card side, port 4116) to the OTA server
        F.append(udp_frame(UPORT, CPORT, p, IP_C, IP_S, ident=len(F) + 1))

    def srv(p):
        F.append(udp_frame(CPORT, UPORT, p, IP_S, IP_C, ident=len(F) + 1))

    # Session 1 (CAT-TP ports 1 on the card, 1025 on the server)
    # 1: SYN with a 10 octet ICCID as identification
    me(cattp(SYN, 1, 1025, 100, 0, syn_extra(1024, 4096, ICCID10)))
    # 2: SYN/ACK without identification
    srv(cattp(SYN | ACK, 1025, 1, 500, 100, syn_extra(512, 2048, b'')))
    # 3: ACK
    me(cattp(ACK, 1, 1025, 101, 500))
    # 4: ACK with data (handed to the data dissector)
    srv(cattp(ACK, 1025, 1, 501, 101, data=b'\x02\x70\x00\x00\x10OTA command 1'))
    # 5: ACK with the SEG flag and data, then the last segment
    srv(cattp(ACK | SEG, 1025, 1, 502, 101, data=b'first segment of an SDU'))
    srv(cattp(ACK, 1025, 1, 503, 101, data=b'last segment'))
    # 7: NUL ACK (keep alive)
    me(cattp(ACK | NUL, 1, 1025, 102, 503))
    # 8: EAK with three out of sequence numbers
    me(cattp(ACK | EAK, 1, 1025, 102, 501, eaks(503, 505, 506)))
    # 9: EAK with one number and data (odd data length)
    me(cattp(ACK | EAK, 1, 1025, 102, 506, eaks(508), data=b'response'))
    # 10: RST, normal ending
    me(cattp(RST, 1, 1025, 103, 0, b'\x00'))
    # Session 2: SYNs with other identifications
    # 11: SYN with a 9 octet ICCID
    me(cattp(SYN, 2, 1026, 200, 0, syn_extra(1024, 1024, ICCID9)))
    # 12: SYN with a 9 octet identification that is not an ICCID
    me(cattp(SYN, 3, 1026, 300, 0, syn_extra(1024, 1024, b'terminal1')))
    # 13: SYN with a 12 octet identification starting with 0x98 (too
    # long for an ICCID)
    me(cattp(SYN, 4, 1026, 400, 0, syn_extra(1024, 1024, bytes.fromhex('98') + b'longerident')))
    # 14: SYN with an 8 octet identification starting with 0x98 (too short)
    me(cattp(SYN, 5, 1026, 500, 0, syn_extra(1024, 1024, bytes.fromhex('9894200000123456'))))
    # 15-22: RST (with ACK set in some) for reason codes 1-7 and an unknown 8
    for rc in range(1, 9):
        flags = RST | (ACK if rc % 2 else 0)
        srv(cattp(flags, 1026, 2, 600 + rc, 200, bytes([rc])))
    # 23: a PDU with none of SYN, ACK, RST ("[Unknown PDU]"; the heuristic
    # does not accept it, Decode As does)
    me(cattp(NUL, 6, 1027, 700, 0))
    # 24: a version 1 ACK (the heuristic rejects versions other than 0)
    me(cattp(ACK, 6, 1027, 701, 0, version=1))
    # 25: the reproducer of "CAT-TP: Do not wrap the EAK count of a short
    # header" (cattp_eak_hlen.py): an EAK PDU with header
    # length 4, shorter than the 18 octet base header, and two octets after
    # the base header. The checksum covers only the first 4 octets, so the
    # RFU octets are set to make it valid (0x60fb + 0x9f04 = 0xffff). With
    # the fix it shows 0 EAKs instead of 249 and an exception.
    hdr = struct.pack('>B2sBHHHHHHH', 0x60, b'\xfb\x9f', 4, 1, 2, 0, 1, 1, 10, 0)
    srv(hdr + struct.pack('>HH', 7, 8))
    return F


def malformed_frames():
    F = []

    def E(p):
        F.append((0, p))

    def X(p):
        F.append((1, exported_pdu(p)))

    def me(p):
        E(udp_frame(UPORT, CPORT, p, IP_C, IP_S, ident=len(F) + 1))

    # 1: the reproducer as published: Exported PDU, header length 4,
    # checksum 0 (bad checksum error); with the fix 0 EAKs
    hdr = struct.pack('>BBBBHHHHHHH', 0x60, 0, 0, 4, 1, 2, 0, 1, 1, 10, 0)
    X(hdr + struct.pack('>HH', 7, 8))
    # 2: an ACK with a bad checksum
    p = cattp(ACK, 1, 1025, 101, 500)
    me(p[:16] + b'\x12\x34' + p[18:])
    # 3: a SYN whose identification length runs past the end
    p = cattp(SYN, 1, 1025, 100, 0, syn_extra(1024, 4096, ICCID10))
    E(udp_frame(UPORT, CPORT, p[:-4], IP_C, IP_S, ident=3))
    X(p[:-4])
    # 5: a RST without its reason code (Exported PDU)
    X(cattp(RST, 1, 1025, 103, 0, hlen=19))
    # 6: a 10 octet datagram (shorter than the base header)
    me(b'\x40\x00\x00\x12\x00\x01\x04\x01\x00\x00')
    # 7: a header and data length that do not add up to the datagram
    me(cattp(ACK, 1, 1025, 101, 500, data=b'abcd', plen=8))
    # 8: an EAK whose header length claims more EAKs than present
    X(cattp(ACK | EAK, 1, 1025, 102, 501, eaks(503), hlen=30))
    # 9: data length past the end (checksum over more than the PDU)
    X(cattp(ACK, 1, 1025, 101, 500, data=b'abcd', plen=100, cksum=False))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cattp-coverage.pcap'), main_frames())
    write_pcapng(os.path.join(out, 'cattp-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
