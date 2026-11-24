#!/usr/bin/env python3
# Generates test/captures/sipfrag_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the sipfrag coverage captures: mksipfrag.py <outdir>
# Everything is built with struct; nothing comes from a real network.
import sys
import struct

# ---- packet builders (all addresses are documentation addresses) ----
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_A = b'\x02\0\0\0\0\x01'
MAC_B = b'\x02\0\0\0\0\x02'

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64,
                    proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def eth(src_mac, dst_mac, payload, etype=0x0800):
    return dst_mac + src_mac + struct.pack('>H', etype) + payload

def udp(src, dst, sport, dport, payload, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(MAC_A if src[3] & 1 else MAC_B, MAC_B if src[3] & 1 else MAC_A,
               ip4(src, dst, 17, u, ident))

class Tcp:
    '''One TCP connection; seq numbers tracked per direction.'''
    def __init__(self, a, b, pa, pb):
        self.a, self.b, self.pa, self.pb = a, b, pa, pb
        self.sa, self.sb = 1000, 5000
        self.ident = 100
    def seg(self, fwd, payload=b'', flags=0x18):
        if fwd:
            s, d, sp, dp, seq, ack = self.a, self.b, self.pa, self.pb, self.sa, self.sb
        else:
            s, d, sp, dp, seq, ack = self.b, self.a, self.pb, self.pa, self.sb, self.sa
        if flags & 0x10 == 0:
            ack = 0
        opts = b''
        if flags & 2:
            opts = struct.pack('>BBH', 2, 4, 1460)
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4,
                        flags, 65535, 0, 0) + opts
        t += payload
        ph = bytes(s) + bytes(d) + struct.pack('>BBH', 0, 6, len(t))
        c = csum(ph + t)
        t = t[:16] + struct.pack('>H', c) + t[18:]
        adv = len(payload) + (1 if flags & 3 else 0)
        if fwd:
            self.sa += adv
        else:
            self.sb += adv
        self.ident += 1
        return eth(MAC_A if fwd else MAC_B, MAC_B if fwd else MAC_A,
                   ip4(s, d, 6, t, self.ident))
    def handshake(self):
        return [self.seg(True, b'', 0x02), self.seg(False, b'', 0x12),
                self.seg(True, b'', 0x10)]
    def close(self):
        return [self.seg(True, b'', 0x11), self.seg(False, b'', 0x11),
                self.seg(True, b'', 0x10)]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

class Cap:
    """pcapng writer; packets are (linktype, data). Linktype 1 = Ethernet,
    252 = Exported PDU."""
    def __init__(self):
        self.pkts = []
        self.t = 1700000000
    def add(self, p, linktype=1):
        self.pkts.append((linktype, p))
        return len(self.pkts)
    @staticmethod
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    def write(self, path):
        out = self.blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        lts = []
        for lt, _ in self.pkts:
            if lt not in lts:
                lts.append(lt)
        for lt in lts:
            out += self.blk(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (lt, p) in enumerate(self.pkts):
            ts = (self.t + i) * 1000000 + i * 1000
            out += self.blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32,
                                           ts & 0xffffffff, len(p), len(p)) + p)
        with open(path, 'wb') as f:
            f.write(out)

A = [192, 0, 2, 1]
B = [192, 0, 2, 2]

def notify(body, cid=1, cseq=1, ctype=b'message/sipfrag;version=2.0', extra=b'', first=None, nl=b'\r\n'):
    first = first or b'NOTIFY sip:a@192.0.2.1 SIP/2.0'
    h = (first + nl +
         b'Via: SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bKfrag%d' % cid + nl +
         b'From: <sip:b@192.0.2.2>;tag=2' + nl +
         b'To: <sip:a@192.0.2.1>;tag=1' + nl +
         b'Call-ID: frag%d@192.0.2.2' % cid + nl +
         b'CSeq: %d NOTIFY' % cseq + nl +
         b'Event: refer' + nl +
         b'Subscription-State: active;expires=60' + nl + extra)
    if ctype:
        h += b'Content-Type: ' + ctype + nl
    h += b'Content-Length: %d' % len(body) + nl + nl
    return h + body

def build(outdir):
    cap = Cap()
    # 1: one line (Info shows "(SIP/2.0 200 OK)")
    cap.add(udp(B, A, 5060, 5060, notify(b'SIP/2.0 200 OK\r\n')))
    # 2: several lines, a header line, an empty line and a last line
    #    without a line end
    cap.add(udp(B, A, 5060, 5060, notify(
        b'SIP/2.0 100 Trying\r\nContact: <sip:b@192.0.2.2>\r\n'
        b'Content-Length: 0\r\n\r\nlast line', cid=2, cseq=2)))
    # 3: LF only line ends
    cap.add(udp(B, A, 5060, 5060, notify(
        b'SIP/2.0 180 Ringing\nCall-ID: x\nCSeq: 1 INVITE\n', cid=3, cseq=3, nl=b'\n')))
    # 4: quoted string that spans a line break stays one line
    cap.add(udp(B, A, 5060, 5060, notify(
        b'SIP/2.0 486 Busy Here\r\nSubject: "two\r\n lines"\r\nTo: <sip:a@192.0.2.1>\r\n',
        cid=4, cseq=4)))
    # 5: TCP, the sipfrag part of a NOTIFY (one segment, Content-Length)
    t = Tcp(B, A, 40000, 5060)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, notify(b'SIP/2.0 603 Decline\r\nWarning: 399 x "y"\r\n', cid=5, cseq=5)))
    cap.add(t.seg(False, b'', 0x10))
    for p in t.close():
        cap.add(p)
    # 6: 200 OK response to a NOTIFY that carries a sipfrag body
    cap.add(udp(A, B, 5060, 5060, notify(
        b'SIP/2.0 202 Accepted\r\n', cid=6, cseq=6, first=b'SIP/2.0 200 OK')))
    # 7: Exported PDU naming sipfrag, several lines
    cap.add(exp_pdu('sipfrag', b'INVITE sip:c@192.0.2.3 SIP/2.0\r\nVia: SIP/2.0/UDP x\r\n\r\n'), 252)
    # 8: Exported PDU naming sipfrag, one line
    cap.add(exp_pdu('sipfrag', b'SIP/2.0 200 OK'), 252)
    # 9: SIP-in-SIP: message/sip body whose own body is a sipfrag
    inner = notify(b'SIP/2.0 200 OK\r\n', cid=9, cseq=9)
    cap.add(udp(B, A, 5060, 5060, notify(inner, cid=7, cseq=7, ctype=b'message/sip')))
    cap.write(outdir + '/sipfrag-coverage.pcapng')

    cap = Cap()
    # an empty Exported PDU payload gives zero lines: "()"
    cap.add(exp_pdu('sipfrag', b''), 252)
    # CR only line ends, NULs, an unterminated quote, a long line
    cap.add(exp_pdu('sipfrag', b'SIP/2.0 200 OK\rVia: x\rTo: y\r'), 252)
    cap.add(exp_pdu('sipfrag', b'SIP/2.0 200\0OK\r\n\0\0\r\nSubject: "open\r\nmore\r\n'), 252)
    cap.add(exp_pdu('sipfrag', b'X' * 3000 + b'\r\n' + b'Y' * 10), 252)
    cap.add(exp_pdu('sipfrag', b'\r\n\r\n\r\n'), 252)
    cap.write(outdir + '/sipfrag-coverage-malformed.pcapng')

if __name__ == '__main__':
    build(sys.argv[1])
