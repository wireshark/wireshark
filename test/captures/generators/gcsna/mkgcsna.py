# Generates test/captures/gcsna_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
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
import sys
import os

SRC, DST = '192.0.2.1', '192.0.2.2'
MACD = bytes.fromhex('020000000002'); MACS = bytes.fromhex('020000000001')

class Bits:
    """Big-endian bit packer."""
    def __init__(self): self.v = 0; self.n = 0
    def add(self, val, width):
        self.v = (self.v << width) | (val & ((1 << width) - 1)); self.n += width; return self
    def pad(self):
        if self.n % 8: self.add(0, 8 - self.n % 8)
        return self
    def bytes(self):
        self.pad(); return self.v.to_bytes(self.n // 8, 'big')

def a21(mtype, ies, corr=1):
    return bytes([mtype, 0x04, 0x04]) + struct.pack('>I', corr) + ies

def gcsna_ie(pdu):
    return bytes([0xC0]) + struct.pack('>H', len(pdu)) + pdu

def frame(payload, sport=23272, dport=23272):
    return eth(MACD, MACS, 0x0800, ip4(SRC, DST, 17, udp(sport, dport, payload)))

def tlac(msgtype, body, rev=6, channel=0, records=()):
    """cdma2k TLAC header as the dissector reads it: channel(1) 1xProtocolRevision(8),
    2 unused bits, message type (6), record count (4)."""
    b = Bits().add(channel, 1).add(rev, 8).add(0, 2)
    if channel == 0:
        b.add(msgtype, 6)
    else:
        raise ValueError
    b.add(len(records), 4)
    for rtype, data in records:
        b.add(rtype, 4).add(len(data), 8)
        for d in data: b.add(d, 8)
    b.pad()
    return b.bytes() + struct.pack('>H', len(body)) + body

def circuit(option, alts=None, iws=None, ack=0, stop=0, seq=0, nt=0, tl=b''):
    b = Bits().add(option >> 3, 5).add(option & 7, 3)
    if alts is None:
        b.add(0, 1)
    else:
        b.add(1, 1).add(len(alts), 8)
        for a in alts: b.add(a, 8)
    if iws is None:
        b.add(0, 1)
    else:
        b.add(1, 1).add(iws, 16)
    b.add(ack, 1).add(stop, 1).add(seq, 6).add(nt, 2).add(0, 4)
    return b'\x01' + b.bytes() + tl

def l2ack(seq):
    return b'\x02' + bytes([(seq & 0x3f) << 2])

def reject(seq, cause, extra_bits):
    b = Bits().add(seq, 6).add(cause, 8)
    for v, w in extra_bits: b.add(v, w)
    return b'\x03' + b.bytes()

def build(outdir):
    fr = []
    # --- 1xCircuitService (always with a TLAC PDU: without it the encapsulated
    # item at the end of the message is an exception, see the malformed capture)
    t1 = tlac(0x02, bytes([0x10, 0x00]))
    for opt in (0x00, 0x01, 0x02, 0x08):          # Release 8, Release 9, C.S0097-A, SRVCC
        fr.append(frame(a21(0x01, gcsna_ie(circuit(opt, tl=t1)))))
    fr.append(frame(a21(0x01, gcsna_ie(circuit(0x01, alts=[0x00, 0x02], ack=1, seq=5, tl=t1)))))
    fr.append(frame(a21(0x01, gcsna_ie(circuit(0x02, alts=[], iws=0x1234, stop=1, seq=63, tl=t1)))))
    fr.append(frame(a21(0x01, gcsna_ie(circuit(0x08, alts=[1, 2, 3, 8], iws=0xFFFF, ack=1, stop=1, seq=17, nt=3, tl=t1)))))
    fr.append(frame(a21(0x01, gcsna_ie(circuit(0x00, ack=1, seq=1, nt=1, tl=t1)))))
    fr.append(frame(a21(0x01, gcsna_ie(circuit(0x01, alts=[0], iws=7, seq=2, nt=2, tl=t1)))))
    # TLAC with header records (type 2: skipped by length)
    t2 = tlac(0x02, bytes([0x10, 0x00]), records=[(2, b'\xaa\xbb')])
    fr.append(frame(a21(0x01, gcsna_ie(circuit(0x00, seq=3, tl=t2)))))
    # --- L2 Ack
    fr.append(frame(a21(0x02, gcsna_ie(l2ack(0)))))
    fr.append(frame(a21(0x02, gcsna_ie(l2ack(63)), corr=2)))
    # --- Service Reject for every cause
    fr.append(frame(a21(0x03, gcsna_ie(reject(1, 0, [(0, 8)])))))                             # no classes
    fr.append(frame(a21(0x03, gcsna_ie(reject(2, 0, [(2, 8), (0, 5), (1, 3), (1, 5), (0, 3)])))))
    fr.append(frame(a21(0x03, gcsna_ie(reject(3, 1, [(7, 8)])))))                             # Invalid 1xProtocolRevision
    fr.append(frame(a21(0x03, gcsna_ie(reject(4, 2, [(1, 8), (0, 5), (2, 3), (6, 8)])))))     # both
    fr.append(frame(a21(0x03, gcsna_ie(reject(5, 3, [(0x55, 8)])))))                          # Invalid Message Id
    fr.append(frame(a21(0x03, gcsna_ie(reject(8, 5, [(3, 8), (0x10, 8), (0x20, 8), (0x30, 8)])))))  # record types
    fr.append(frame(a21(0x03, gcsna_ie(reject(9, 5, [(0, 8)])))))
    # --- several messages in one GCSNA PDU
    fr.append(frame(a21(0x02, gcsna_ie(l2ack(1) + l2ack(2) + reject(3, 3, [(9, 8)]) + l2ack(4)))))
    fr.append(frame(a21(0x03, gcsna_ie(reject(1, 1, [(1, 8)]) + circuit(0x00, tl=t1)))))
    # the reproducer of the reject loop: a Service Reject after 8200 bytes of L2 acks
    P = 8200
    fr.append(frame(a21(0x03, gcsna_ie(b'\x02' * P + bytes([0x03, 0x00, 0x04, 0x00])))))
    # Exported PDU entry: Service Reject cause 3 and an L2 ack
    pdus = [(1, exp_pdu('gcsna', reject(11, 3, [(0x21, 8)]) + l2ack(9)))]
    # a message with an IE before and after the GCSNA PDU
    fr.append(frame(a21(0x01, bytes([0x0A, 0x02, 0x00, 0x21]) + gcsna_ie(l2ack(7)))))
    # other UDP port (not A21): nothing
    ngcs = len(fr)
    frames = [(0, f) for f in fr] + pdus
    pcapng(os.path.join(outdir, 'gcsna-coverage.pcapng'), [1, 252], frames)

    m = []
    m.append(frame(a21(0x03, gcsna_ie(reject(6, 4, [])))))              # cause 4: the bit offset is used as byte offset (bug)
    m.append(frame(a21(0x03, gcsna_ie(reject(7, 4, [(0xAB, 8), (0xCD, 8)])))))
    m.append(frame(a21(0x03, gcsna_ie(reject(10, 9, [(0xEE, 8)])))))   # unknown cause: same
    for opt in (0x00, 0x01):                                            # no TLAC (the reproducer of the reserved bits was this 4 byte message)
        m.append(frame(a21(0x01, gcsna_ie(circuit(opt)))))
    m.append(frame(a21(0x01, gcsna_ie(circuit(0x01, alts=[1, 2], iws=3)))))
    m.append(frame(a21(0x03, gcsna_ie(b'\x07'))))                       # unknown message id: error
    m.append(frame(a21(0x02, gcsna_ie(l2ack(1) + b'\x09\x00'))))        # valid then unknown: error
    m.append(frame(a21(0x03, gcsna_ie(b'\x03'))))                       # reject cut short
    m.append(frame(a21(0x03, gcsna_ie(b'\x03\x00\x00'))))               # cause 0 without the count
    m.append(frame(a21(0x03, gcsna_ie(b'\x03\x00\x00\x05\x00'))))       # five classes, one present
    m.append(frame(a21(0x03, gcsna_ie(b'\x03\x00\x14\x05\x01'))))       # cause 5 (shifted) cut short
    m.append(frame(a21(0x01, gcsna_ie(b'\x01'))))                       # circuit service without option
    m.append(frame(a21(0x01, gcsna_ie(b'\x01\x00\x80'))))               # alternates announced, none present
    m.append(frame(a21(0x01, gcsna_ie(circuit(0x00, tl=b'\x00\x01\x02')))))  # garbage TLAC: cdma2k error
    m.append(frame(a21(0x02, gcsna_ie(b'\x02'))))                       # L2 ack without sequence
    m.append(frame(a21(0x01, gcsna_ie(circuit(0x00, tl=tlac(0x3f, b'\x00'))))))   # unknown cdma2k message
    pcapng(os.path.join(outdir, 'gcsna-coverage-malformed.pcapng'), [1, 252],
           [(0, f) for f in m] + [(1, exp_pdu('gcsna', bytes([0x01, 0x00, 0x00, 0x00]))), (1, exp_pdu('gcsna', b''))])

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
