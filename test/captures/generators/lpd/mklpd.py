#!/usr/bin/env python3
# Generates test/captures/lpd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic LPD (RFC 1179, TCP port 515) coverage captures.
# Usage: mklpd.py <outdir>.  Writes lpd-coverage.pcap and
# lpd-coverage-malformed.pcap.  Synthetic documentation addresses only.
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
CLI, SRV = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MACC, MACS = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Stream:
    def __init__(self, sport=40000, dport=515):
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.ipid = 1

    def seg(self, to_server, payload, flags=0x18):
        if to_server:
            src, dst, sp, dp, seq, ack = CLI, SRV, self.sport, self.dport, self.cseq, self.sseq
            m = MACS + MACC
        else:
            src, dst, sp, dp, seq, ack = SRV, CLI, self.dport, self.sport, self.sseq, self.cseq
            m = MACC + MACS
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        n = len(payload) + (1 if flags & 3 else 0)
        if to_server:
            self.cseq += n
        else:
            self.sseq += n
        return m + b'\x08\x00' + ip + tcp

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

fr = []
s = Stream()
C = lambda p: fr.append(s.seg(True, p))              # request from the client
S = lambda p: fr.append(s.seg(False, p))             # response from the server
C(b'\x02lp0\n')                                      # receive a printer job, queue "lp0"
S(b'\x00')                                           # response: success
C(b'\x02\n')                                         # empty queue name (the fixed find_printer_string())
S(b'\x01')                                           # response: queue not accepting jobs
C(b'\x01queue-a\x00')                                # start print, NUL terminated
S(b'\x02')                                           # response: queue full
C(b'\x03lp0 -s -l\n')                                # short queue status
S(b'\x03')                                           # response: bad job format
C(b'\x04lp0 user\n')                                 # long queue status
C(b'\x05lp0 agent 12 13\n')                          # remove jobs
C(b'\x06lp0 lpc stop\n')                             # LPRng lpc
C(b'\x07lp0 block\n')                                # LPRng block format
C(b'\x08secure\n')                                   # LPRng secure command
C(b'\x09lp0 verbose\n')                              # LPRng verbose status
C(b'\x00lp0\n')                                      # code 0 (continuation) with a string
C(b'\x02lp0 missing terminator')                     # no terminator: shown as data
C(b'\x02')                                           # one octet is a response, whatever the code
C(b'\x02nul-first\x00and a later newline\n')         # NUL before the newline
S(b'\x7f')                                           # one octet that is not a response code
C(b'\x41plain data of a print job\n')                # code above 9: unknown / continuation
C(b'\x0a')                                           # one octet from the client is a "response"
C(bytes([0xd5]) * 40)                                # data octets
pcap(os.path.join(OUT, 'lpd-coverage.pcap'), fr)

bad = []
s2 = Stream(sport=40001)
# frames the dissector cannot reject: zero length payloads are not passed to it,
# so these are only odd shapes of valid requests
bad.append(s2.seg(True, b'\x02' + b'A' * 1200 + b'\n'))   # very long queue name
bad.append(s2.seg(True, b'\x09' + b'\x00' * 20))         # NUL padded
bad.append(s2.seg(True, b'\x02' + bytes(range(1, 128)) + b'\n'))   # non-printable queue name
bad.append(s2.seg(True, b'\x02\x00'))                    # empty NUL terminated name
pcap(os.path.join(OUT, 'lpd-coverage-malformed.pcap'), bad)
print(len(fr), len(bad))
