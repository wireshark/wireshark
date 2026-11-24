#!/usr/bin/env python3
# Generates test/captures/msn-messenger_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the MSN Messenger (MSNMS) coverage captures. Usage: mkmsn_messenger.py <outdir>"""
import struct
import sys
import os

def pcap(frames):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack('<IIII', 1700000000 + i, 0, len(f), len(f)) + f
    return out

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Conn:
    def __init__(self, n, sport, dport=1863):
        self.c = bytes([10, 0, 0, 1]); self.s = bytes([10, 0, 0, 100 + n])
        self.sp, self.dp = sport, dport
        self.cseq = 1000; self.sseq = 5000; self.ipid = 1
    def seg(self, fromc, payload, flags=0x18):
        if fromc:
            src, dst, sp, dp, seq, ack = self.c, self.s, self.sp, self.dp, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = self.s, self.c, self.dp, self.sp, self.sseq, self.cseq
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 8192, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(tcp) + len(payload), self.ipid, 0, 64, 6, 0) + src + dst
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        n = len(payload) + (1 if flags & 3 else 0)
        if fromc: self.cseq += n
        else: self.sseq += n
        eth = bytes.fromhex('020000000002020000000001') if not fromc else bytes.fromhex('020000000001020000000002')
        return eth + b'\x08\x00' + ip + tcp + payload
    def handshake(self):
        a = self.seg(True, b'', 0x02)
        b = self.seg(False, b'', 0x12)
        c = self.seg(True, b'', 0x10)
        return [a, b, c]

def main(out):
    frames = []
    # 1: native MSNP session on tcp/1863
    c = Conn(1, 50001)
    frames += c.handshake()
    msgs = [
        (True,  b'VER 1 MSNP8 MSNP7 CVR0\r\n'),
        (False, b'VER 1 MSNP8\r\n'),
        (True,  b'CVR 2 0x0409 win 4.10 i386 MSNMSGR 5.0.0544 MSMSGS user@example.com\r\n'),
        (False, b'CVR 2 5.0.0544 5.0.0544 5.0.0544 http://example.com/dl http://example.com\r\n'),
        (True,  b'USR 3 TWN I user@example.com\r\n'),
        (False, b'XFR 3 NS 10.0.0.2:1863 0\r\n'),
        # Bare LF and bare CR terminators
        (True,  b'PNG\n'),
        (False, b'QNG\r'),
        # No terminator
        (True,  b'CHL 0 123456789'),
        # Several lines in one segment, including blank lines
        (False, b'MSG 5 N 80\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nHello, world!\r\n'),
        # Only a line terminator (empty first line)
        (True,  b'\r\n'),
        # Non-printable and high bytes in the first line (format_text)
        (False, b'NOT \x01\x02\x7f\xc3\xa9 \xff\xfe\r\n\x00\x1b[0m\r\n'),
        # A very long line
        (True,  b'ADD 9 FL user@example.com ' + b'N' * 1500 + b'\r\n'),
        # Mixed terminators across lines
        (False, b'LST A\nB\rC\r\nD'),
        (True,  b'OUT\r\n'),
    ]
    for fromc, p in msgs:
        frames.append(c.seg(fromc, p))
    frames.append(c.seg(True, b'', 0x11))
    frames.append(c.seg(False, b'', 0x11))
    frames.append(c.seg(True, b'', 0x10))
    # 2: MSN Messenger over HTTP (media_type application/x-msn-messenger)
    h = Conn(2, 50002, 80)
    frames += h.handshake()
    body = b'MSG 1 U 40\r\nMIME-Version: 1.0\r\n\r\nping\r\n'
    req = (b'POST /gateway/gateway.dll?Action=open&Server=NS&IP=messenger.hotmail.com HTTP/1.1\r\n'
           b'Host: gateway.messenger.hotmail.com\r\nContent-Type: application/x-msn-messenger\r\n'
           b'Content-Length: %d\r\n\r\n' % len(body)) + body
    frames.append(h.seg(True, req))
    body2 = b'VER 1 MSNP8\r\nCVR 2 1.0\r\n'
    resp = (b'HTTP/1.1 200 OK\r\nContent-Type: application/x-msn-messenger\r\n'
            b'Content-Length: %d\r\n\r\n' % len(body2)) + body2
    frames.append(h.seg(False, resp))
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, 'msn-messenger-coverage.pcap'), 'wb').write(pcap(frames))
    # malformed capture: truncated/odd TCP payloads (reported length > captured)
    mf = Conn(3, 50003)
    fr = []
    fr += mf.handshake()
    f = mf.seg(True, b'USR 1 TWN I user@example.com\r\n')
    fr.append(f)
    # frame truncated in capture (snaplen) in the middle of the line
    fr.append(mf.seg(False, b'XFR 1 NS 10.0.0.2:1863 0\r\nsecond line'))
    data = pcap(fr)
    # cut last frame's captured length
    last = fr[-1]
    out2 = pcap(fr[:-1]) + struct.pack('<IIII', 1700000099, 0, len(last) - 10, len(last)) + last[:-10]
    open(os.path.join(out, 'msn-messenger-coverage-malformed.pcap'), 'wb').write(out2)

main(sys.argv[1])
