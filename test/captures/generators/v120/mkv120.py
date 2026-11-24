# Generates test/captures/v120_coverage.eyesdn.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import struct
import sys

def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (encap, uton, channel, payload)."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (encap, uton, channel, payload) in enumerate(records):
            hdr = struct.pack('>I', 1000 * i)[1:] + struct.pack('>Q', 1700000000 + i)[3:]
            hdr += bytes([channel, (encap << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


def exppdu(name, payload):
    """Exported PDU frame (linktype 252) naming a dissector."""
    b = name.encode()
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('>HH', 12, len(b)) + b + struct.pack('>HH', 0, 0) + payload


def inet_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ether(payload, etype=0x0800, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('>H', etype) + payload


def ip4(proto, src, dst, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    hdr = hdr[:10] + struct.pack('>H', inet_csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b'', win=8192):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def sctp(sport, dport, vtag, chunks):
    body = b''.join(chunks)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + body)
    return hdr[:8] + struct.pack('<I', c) + body


def sctp_data(tsn, sid, ssn, ppid, data, flags=3):
    ln = 16 + len(data)
    ch = struct.pack('>BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppid) + data
    return ch + b'\0' * ((4 - ln % 4) % 4)


def sctp_init(tag, chunk_type=1):
    return struct.pack('>BBHIIHHI', chunk_type, 0, 20, tag, 65535, 4, 4, 1000)


#!/usr/bin/env python3
"""Generate the synthetic captures for the V.120 dissector (packet-v120.c).

V.120 (asynchronous data over ISDN) is reached the way a real trace reaches
it: an EyeSDN file (wiretap/eyesdn.c) whose B-channel records go to the ISDN
dissector, which makes a conversation per channel and assigns the V.120
dissector to it when the first frame is the V.120 SABME (08 01 7f).  Every
record is built from scratch with struct; no captured traffic is used.

Usage: mkv120.py <output directory>

Writes:
  v120-coverage.eyesdn            valid V.120 frames in both directions
  v120-coverage-malformed.eyesdn  frames cut short inside the V.120 header
"""

ENC = 1  # EYESDN_ENCAP_ISDN is 0; the direction octet holds protocol << 1


def addr(lli, cr, ea0=0, ea1=1):
    # byte 0: LLI high 6 bits, C/R, EA0; byte 1: LLI low 7 bits, EA1
    return bytes([((lli >> 7) << 2) | (cr << 1) | ea0, ((lli & 0x7f) << 1) | ea1])


def iframe(ns, nr, p=0):
    return bytes([ns << 1, (nr << 1) | p])


def sframe(kind, nr, pf=0):
    return bytes([(kind << 2) | 1, (nr << 1) | pf])


def rec(sent, payload, channel=1):
    # For bearer channels the reader flips the direction bit: uton = !bit.
    return (0, 0 if sent else 1, channel, payload)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    SABME = b'\x08\x01\x7f'
    r = []
    # 1: SABME from the user: the circuit is V.120 from here on
    r.append(rec(True, SABME))
    # 2: UA response from the network (C/R = 1 for the user side seen as DCE)
    r.append(rec(False, addr(0, 1) + b'\x73'))
    # 3-6: more unnumbered frames: XID, DISC, DM, FRMR, UI
    r.append(rec(True, addr(0, 0) + b'\xbf\x01\x02'))
    r.append(rec(True, addr(5, 0) + b'\x53'))
    r.append(rec(False, addr(5, 1) + b'\x1f'))
    r.append(rec(False, addr(0x1fff, 1) + b'\x87\x00\x01\x02'))
    # 7: UI with a one octet header (ext = 1) and data
    r.append(rec(True, addr(1, 0) + b'\x03' + b'\x83' + b'hello'))
    # 8: UI with a two octet header: ext 0, E/DR/SR/RR bits set, segmentation
    r.append(rec(True, addr(1, 0) + b'\x03' + b'\x7f\xf3' + b'world'))
    # 9: I frame, N(S)=0 N(R)=0, one octet header with break and error control
    r.append(rec(True, addr(1, 0) + iframe(0, 0) + b'\xc7' + b'ATZ\r'))
    # 10: I frame with a two octet header, data from the network
    r.append(rec(False, addr(1, 0) + iframe(1, 1, 1) + b'\x0a\x80' + b'OK\r\n'))
    # 11: I frame from the network, a response
    r.append(rec(False, addr(1, 1) + iframe(2, 1) + b'\x81' + b'x'))
    # 12-15: supervisory frames RR, RNR, REJ, SREJ, both directions
    r.append(rec(True, addr(1, 0) + sframe(0, 3)))
    r.append(rec(False, addr(1, 1) + sframe(1, 4, 1)))
    r.append(rec(True, addr(1, 0) + sframe(2, 5, 1)))
    r.append(rec(False, addr(1, 1) + sframe(3, 6)))
    # 16: I frame without data after the control field (no header)
    r.append(rec(True, addr(1, 0) + iframe(3, 2)))
    # 17: invalid frame: byte0 bit 0 set and byte1 bit 0 clear
    r.append(rec(True, b'\x09\x02\x00\x00'))
    # 18: the same with unknown direction handling: D channel is LAPD, so use
    # another B channel that starts with SABME, to get a second circuit
    r.append(rec(True, SABME, channel=2))
    r.append(rec(False, addr(0, 1) + b'\x63', channel=2))
    # 20: header fix reproducer: UI with the header 0x83 after the 1 octet control
    r.append(rec(True, b'\x08\x01\x03\x83\x41\x42'))
    # 21: a 1500 octet payload with a one octet header
    r.append(rec(True, addr(1, 0) + iframe(4, 2) + b'\x80' + bytes(range(256)) * 5))
    eyesdn(os.path.join(out, 'v120-coverage.eyesdn'), r)

    m = []
    m.append(rec(True, SABME))
    # only the address octets: byte1 is read, no control field
    m.append(rec(True, b'\x08\x01'))
    # address, then the I frame control cut after one octet
    m.append(rec(True, b'\x08\x01\x02'))
    # a lone octet
    m.append(rec(True, b'\x08'))
    # two octet header cut after one octet (ext clear)
    m.append(rec(True, b'\x08\x01\x03\x00'))
    eyesdn(os.path.join(out, 'v120-coverage-malformed.eyesdn'), m)


main()
