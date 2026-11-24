#!/usr/bin/env python3
# Generates test/captures/rtcdc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RTCDC (WebRTC data channel establishment protocol)
# coverage captures. Usage: mkrtcdc.py <outdir>
# RTCDC is registered on SCTP payload protocol identifier 50 by default.
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (~crc) & 0xffffffff

class Cap:
    def __init__(self):
        self.pkts = []
        self.tsn = 1000
    def sctp(self, payload, ppi=50, sid=0, ssn=0, flags=0x03, src=(192, 0, 2, 1),
             dst=(192, 0, 2, 2), sport=5000, dport=5001, vtag=0x11223344):
        ln = 16 + len(payload)
        chunk = struct.pack('!BBHIHHI', 0, flags, ln, self.tsn, sid, ssn, ppi) + payload
        chunk += b'\0' * ((-ln) % 4)
        self.tsn += 1
        self.raw(src, dst, sport, dport, vtag, chunk)
    def raw(self, src, dst, sport, dport, vtag, chunks):
        sc = struct.pack('!HHII', sport, dport, vtag, 0) + chunks
        sc = sc[:8] + struct.pack('<I', crc32c(sc)) + sc[12:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(sc), len(self.pkts) + 1, 0,
                         64, 132, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pkts.append(b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + sc)
    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
                f.write(p)

def old_open(ctype, flags, rel, prio, label):
    return struct.pack('!BBHHH', 0x00, ctype, flags, rel, prio) + label
def old_resp(err, flags, sid, extra=b''):
    return struct.pack('!BBHH', 0x01, err, flags, sid) + extra
def new_open(ctype, prio, rel, label, proto, llen=None, plen=None):
    return struct.pack('!BBHIHH', 0x03, ctype, prio, rel,
                       len(label) if llen is None else llen,
                       len(proto) if plen is None else plen) + label + proto

def main(outd):
    c = Cap()
    # Older draft: DATA_CHANNEL_OPEN_REQUEST (0), RESPONSE (1), ACK (2)
    for i, (ct, fl, rel, pr, lab) in enumerate([
            (0, 0x0000, 0, 256, b'chat'),
            (1, 0x0001, 3, 0, b'unreliable-rexmit'),
            (2, 0x0001, 500, 512, b'timed'),
            (0, 0xfffe, 0, 1, b'a'),
            (0x7f, 0xffff, 65535, 65535, b'\xc3\xa5\xc3\xa4\xc3\xb6 label with utf8')]):
        c.sctp(old_open(ct, fl, rel, pr, lab), sid=2 * i, ssn=0)
    c.sctp(old_resp(0, 0, 4), sid=4)
    c.sctp(old_resp(1, 0xffff, 65535), sid=5)
    c.sctp(b'\x02', sid=4, ssn=1)
    # New style (RFC 8832): DATA_CHANNEL_OPEN (3): every channel type
    for i, (ct, prio, rel, lab, proto) in enumerate([
            (0x00, 0, 0, b'reliable', b''),
            (0x01, 100, 5, b'rexmit', b'json'),
            (0x02, 200, 1000, b'timed', b'bin'),
            (0x80, 300, 0, b'unordered', b'proto-x'),
            (0x81, 400, 3, b'rexmit-unordered', b''),
            (0x82, 500, 2000, b'timed-unordered', b'p'),
            (0x00, 0, 0, b'', b''),
            (0x00, 65535, 0xffffffff, b'x' * 200, b'y' * 100),
            (0x03, 1, 1, b'unknown type', b'p'),            # unknown channel type
            (0x83, 1, 1, b'unknown unordered', b''),        # unknown channel type
            (0x00, 1, 7, b'reliable with reliability', b''), # non-zero reliability
            (0x80, 1, 7, b'', b'protocol only')]):
        c.sctp(new_open(ct, prio, rel, lab, proto), sid=10 + i, ssn=0)
    # Unknown message types (reserved) with and without trailing data
    for t in (0x04, 0x7f, 0xff):
        c.sctp(bytes([t]) + b'\0' * 5, sid=30)
    # ACK as a complete message with a fragmentless chunk, in the other direction
    c.sctp(b'\x02', sid=10, ssn=1, src=(192, 0, 2, 2), dst=(192, 0, 2, 1), sport=5001, dport=5000,
           vtag=0x55667788)
    c.sctp(old_resp(0, 0, 10), sid=11, ssn=1, src=(192, 0, 2, 2), dst=(192, 0, 2, 1), sport=5001,
           dport=5000, vtag=0x55667788)
    c.write(os.path.join(outd, 'rtcdc-coverage.pcap'))

    m = Cap()
    # ACK and response that are longer than allowed
    m.sctp(b'\x02extra')
    m.sctp(old_resp(0, 0, 1, b'more'))
    # inconsistent label and protocol lengths
    m.sctp(new_open(0, 0, 0, b'label', b'proto', llen=3))
    m.sctp(new_open(0, 0, 0, b'label', b'proto', plen=9))
    m.sctp(new_open(0, 0, 0, b'label', b'proto', llen=0xffff, plen=0xffff))
    m.sctp(new_open(0, 0, 0, b'label', b'', llen=100))
    # truncated messages
    m.sctp(b'\x03\x00\x00')
    m.sctp(b'\x03' + b'\0' * 9)
    m.sctp(b'\x00\x00\x00')
    m.sctp(b'\x01\x00\x00')
    m.sctp(old_open(0, 0, 0, 1, b''))   # empty label: the label item has no octets
    m.sctp(b'\x00')
    m.sctp(b'\x01')
    m.write(os.path.join(outd, 'rtcdc-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
