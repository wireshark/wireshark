#!/usr/bin/env python3
# Generates test/captures/fix_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FIX dissector (packet-fix.c).
Usage: mkfix.py <output directory>
FIX over TCP is found by the "fix_tcp" heuristic dissector (no port).
Writes fix-coverage.pcap and fix-coverage-malformed.pcap."""
# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()

import os
import sys

CTRLA = b'\x01'

def fixmsg(fields, ver=b'FIX.4.2', badsum=False, body_len=None, trailer=True):
    """fields: list of (tag, value) after BeginString/BodyLength."""
    body = b''.join(b'%s=%s\x01' % (t.encode(), v if isinstance(v, bytes) else str(v).encode())
                    for t, v in fields)
    bl = len(body) if body_len is None else body_len
    m = b'8=' + ver + b'\x01' + (b'9=%s\x01' % (str(bl).encode() if isinstance(bl, int) else bl)) + body
    s = sum(m) % 256
    if badsum:
        s = (s + 7) % 256
    return m + (b'10=%03d\x01' % s if trailer else b'')

def hdr(mt, seq, extra=()):
    return [('35', mt), ('49', 'BUYSIDE'), ('56', 'SELLSIDE'), ('34', seq),
            ('52', '20261104-06:30:00.000')] + list(extra)

def main(out):
    fr = []
    CIP, SIP = '10.0.0.1', '10.0.0.2'
    # A: a session on port 9878 (no port registered; found by the heuristic):
    # one message per segment, mostly table-driven fields
    f = Flow(50001, 9878, fr); f.open()
    msgs = [
        fixmsg(hdr('A', 1, [('98', 0), ('108', 30), ('141', 'Y')])),
        fixmsg(hdr('0', 2)),
        fixmsg(hdr('1', 3, [('112', 'TEST1')])),
        fixmsg(hdr('D', 4, [('11', 'ORD1'), ('21', 1), ('55', 'IBM'), ('54', 1), ('38', 100),
                            ('40', 2), ('44', '123.45'), ('59', 0), ('60', '20261104-06:30:01'),
                            ('1', 'ACC1'), ('15', 'USD'), ('18', '1'), ('47', 'A'), ('65', 'x'),
                            ('22', '4'), ('167', 'CS')])),
        fixmsg(hdr('8', 5, [('37', 'O1'), ('17', 'E1'), ('20', 0), ('150', 'F'), ('39', 2),
                            ('40', 2), ('54', 2), ('32', 100), ('31', '123.45'), ('151', 0),
                            ('14', 100), ('6', '123.45'), ('29', '1')])),
        fixmsg(hdr('2', 6, [('7', 1), ('16', 0)])),
        fixmsg(hdr('3', 7, [('45', 4), ('58', 'Missing tag'), ('371', 55), ('373', 1)])),
        fixmsg(hdr('4', 8, [('36', 20), ('123', 'Y')])),
        fixmsg(hdr('9', 9, [('102', 1), ('434', 1), ('39', 4)])),
        fixmsg(hdr('j', 10, [('45', 4), ('380', 0)])),
        fixmsg(hdr('Z', 11, [('9999', 'private field'), ('5000', 'x')])),   # unknown tags, unknown message type
        fixmsg(hdr('5', 12)),
    ]
    for i, m in enumerate(msgs):
        if i % 2 == 0:
            f.c2s(m)
        else:
            f.s2c(m)
        f.ack_s() if i % 2 == 0 else f.ack_c()
    f.close()

    # B: one message split into three TCP segments; the minimum PDU length
    # (24 octets) is not even reached by the first one
    f = Flow(50002, 9878, fr); f.open()
    m = fixmsg(hdr('D', 1, [('11', 'SPLIT'), ('55', 'MSFT'), ('54', 2), ('38', 5), ('40', 1)]))
    f.c2s(m[:12]); f.ack_s()
    f.c2s(m[12:60]); f.ack_s()
    f.c2s(m[60:]); f.ack_s()
    # C: two messages in one segment, then a message split at the boundary
    m1 = fixmsg(hdr('0', 2)); m2 = fixmsg(hdr('0', 3)); m3 = fixmsg(hdr('1', 4, [('112', 'AGAIN')]))
    f.c2s(m1 + m2 + m3[:30]); f.ack_s()
    f.c2s(m3[30:]); f.ack_s()
    # D: a trailing message whose BodyLength is not at the expected spot
    # (10= missing there): the dissector resynchronises on the next 8=FIX
    bad = fixmsg(hdr('0', 5), body_len=10)
    f.c2s(bad + fixmsg(hdr('0', 6))); f.ack_s()
    # BodyLength that is not a number, then a valid message
    f.c2s(fixmsg(hdr('0', 7), body_len=b'abc') + fixmsg(hdr('0', 8))); f.ack_s()
    # F: no 10= checksum at all at the end of the data (assumes 7 octets)
    m9 = fixmsg(hdr('0', 9), trailer=False)
    f.c2s(m9 + b'10=%d\x01' % (sum(m9) % 256)); f.ack_s()
    # Missing value, missing tag and fields without '='
    f.c2s(fixmsg(hdr('0', 10, [('55', b''), ('', b'novalue'), ('58', 'ok')]))); f.ack_s()
    # E: bytes with the high bit set before the next message: the stream
    # needs to be resynchronised at the right offset
    junk = b'\xc3\xa9\xff\xfe\x80\x81 garbage text with bytes \xe2\x82\xac\xf0\x9f\x98\x80\x01'
    f.c2s(junk + fixmsg(hdr('0', 12))); f.ack_s()
    f.c2s(junk + junk + fixmsg(hdr('0', 13))); f.ack_s()
    # a continuation segment (does not start with 8=FIX)
    f.c2s(b'tail of something earlier\x01'); f.ack_s()
    # message of a different FIX version
    f.c2s(fixmsg(hdr('0', 14), ver=b'FIXT.1.1')); f.ack_s()
    f.close()

    # G: reproducer for the negative BodyLength: after the bad message,
    # valid messages must still be dissected
    f = Flow(50003, 9878, fr); f.open()
    neg = b'8=FIX.4.2\x019=-23\x0135=0\x01'
    neg += b'10=%03d\x01' % (sum(neg) % 256)
    good = fixmsg([('35', '0'), ('49', 'SENDER'), ('56', 'TARGET')])
    f.c2s(neg); f.ack_s()
    f.c2s(good); f.ack_s()
    f.c2s(good); f.ack_s()
    f.close()

    # I: non-FIX data on another port is left to the heuristic (not FIX)
    f = Flow(50006, 9999, fr); f.open()
    f.c2s(b'GET / HTTP/1.0\r\n\r\n'); f.ack_s()
    f.close()

    # J: resynchronisation and unusual framing on an established FIX stream
    f = Flow(50005, 9878, fr); f.open()
    f.c2s(fixmsg(hdr('0', 1))); f.ack_s()
    # the next header "8=FI" is cut at the end of the segment (fewer than
    # five octets after the SOH): the 4 octets wait for the next segment
    nxt = fixmsg(hdr('1', 2, [('112', 'CUT')]))
    f.c2s(b'y' * 30 + b'\x01' + nxt[:4]); f.ack_s()
    f.c2s(nxt[4:]); f.ack_s()
    # \x018 that does not start a message, then the real next message
    f.c2s(b'z' * 10 + b'\x018=notfix and some more\x01' + fixmsg(hdr('0', 3))); f.ack_s()
    # the final SOH of the checksum arrives in the next segment
    m = fixmsg(hdr('0', 4))
    f.c2s(m[:-1]); f.ack_s()
    f.c2s(m[-1:] + fixmsg(hdr('0', 5))); f.ack_s()
    f.close()

    # H: a message longer than one segment, with a 'BodyLength' that
    # exceeds the data seen so far (desegment) and ends in a FIN
    f = Flow(50004, 9878, fr); f.open()
    big = fixmsg(hdr('D', 1, [('58', 'x' * 300)]))
    f.c2s(big[:200]); f.ack_s()
    f.c2s(big[200:]); f.ack_s()
    f.close()
    pcap(os.path.join(out, 'fix-coverage.pcap'), fr)

    mal = []
    f = Flow(51001, 9878, mal); f.open()
    f.c2s(fixmsg(hdr('0', 1), badsum=True)); f.ack_s()                       # bad checksum
    f.c2s(fixmsg(hdr('0', 2, [('abc', 'x'), ('55', 'IBM')]))); f.ack_s()   # non numeric tag
    f.c2s(fixmsg(hdr('A', 3, [('98', 'zzz')]))); f.ack_s()                   # invalid integer string
    f.c2s(fixmsg(hdr('0', 4, [('98', 'zzz'), ('102', '9x')]))); f.ack_s()
    f.c2s(fixmsg(hdr('0', 5, [('10', 'zzz')]))); f.ack_s()                   # 10= in the middle with a bad value
    f.c2s(b'\xc3\xa9\xff garbage \x01' + fixmsg(hdr('0', 6))); f.ack_s()   # junk shorter than the minimum PDU
    f.c2s(b'8=FIX.4.2\x01'); f.ack_s()                                       # nothing else
    f.c2s(b'8=FIX.4.2\x019=0\x01'); f.ack_s()                               # no MsgType
    f.c2s(b'8=FIX.4.2\x019=0\x0135=\x0110=000\x01'); f.ack_s()              # empty MsgType
    f.c2s(b'8=FIX.4.2\x0110=000\x01'); f.ack_s()                            # BodyLength missing
    f.c2s(b'8=FIX.4.2'); f.ack_s()                                           # no SOH at all
    f.c2s(b'8=FIX.4.2 and some more text without a control A in it'); f.ack_s()
    f.c2s(b'\x018=FIX\x01\x018=FI'); f.ack_s()                              # resync at the end
    f.c2s(b'x' * 30 + b'\x018=FIX.4.2\x019=5\x0135=0\x01'); f.ack_s()
    f.c2s(b'8=FIX.4.2\x01' + b'x' * 30); f.ack_s()                           # no BodyLength field (no second SOH)
    # a field without '=' where BodyLength is expected (the PDU length
    # returned by fix_header_len() is 10 octets short)
    f.c2s(b'8=FIX.4.2\x01novaluehere' + b'q' * 30 + b'\x01' + fixmsg(hdr('0', 7))); f.ack_s()
    f.close()
    pcap(os.path.join(out, 'fix-coverage-malformed.pcap'), mal)

if __name__ == '__main__':
    main(sys.argv[1])
