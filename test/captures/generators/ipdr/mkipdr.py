#!/usr/bin/env python3
# Generates test/captures/ipdr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IPDR/SP coverage captures (synthetic traffic only).
Usage: mkipdr.py <outdir> [-v]"""
# ---- helpers (synthetic traffic only; documentation addresses) ----
import struct
import sys
import os

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def _ip4(a):
    return bytes(int(x) for x in a.split('.'))

_ETH = bytes.fromhex('020000000002') + bytes.fromhex('020000000001')

def eth_ip(src, dst, proto, seg, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), ident, 0x4000, 64, proto, 0, _ip4(src), _ip4(dst))
    h = h[:10] + struct.pack('!H', _csum(h)) + h[12:]
    return _ETH + b'\x08\x00' + h + seg

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opt = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
    pseudo = _ip4(src) + _ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('!H', _csum(pseudo + hdr + payload)) + hdr[18:]
    return eth_ip(src, dst, 6, hdr + payload)

def udp(src, dst, sport, dport, payload):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(src, dst, 17, seg)

class Tcp:
    """One TCP connection; send() appends a data frame from the client
    ('c') or the server ('s') and tracks the sequence numbers."""
    def __init__(self, frames, c, s, cport, sport, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self.f.append(tcp(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.f.append(tcp(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.f.append(tcp(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def send(self, who, data):
        if who == 'c':
            self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data))
            self.cseq += len(data)
        else:
            self.f.append(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data))
            self.sseq += len(data)
    def fin(self):
        self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, b'', 0x11))

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(path, linktypes, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def exp_tlv(tag, val):
    return struct.pack('!HH', tag, len(val)) + val

def exported_pdu(name, payload):
    return exp_tlv(12, name.encode()) + struct.pack('!HH', 0, 0) + payload

CL, SV = '192.0.2.10', '192.0.2.20'      # exporter, collector
LABELS = []

def mark(frames, text):
    LABELS.append((len(frames) + 1, text))

def msg(mid, sid, body=b'', flags=0, ver=2, length=None):
    """An IPDR/SP message: version, id, session, flags, total length."""
    n = 8 + len(body) if length is None else length
    return struct.pack('!BBBBI', ver, mid, sid, flags, n) + body

def u(fmt, *a):
    return struct.pack('!' + fmt, *a)

def vendor(s=b'ACME'):
    return u('I', len(s)) + s          # FT_UINT_STRING with a 4 octet length prefix

def lp(b):
    return u('I', len(b)) + b

def samis(host=b'cmts1.example.com', ipv6=bytes(range(16)), ifname=b'Cable1/0/0',
          cm6=None, ll=None, chans=(1, 2, 3), cls=b'BestEffort', direction=1,
          chset_len=None, host_len=None):
    r = b''
    r += lp(host) if host_len is None else u('I', host_len) + host
    r += u('I', 123456)                       # uptime
    r += bytes([192, 0, 2, 1])                # CMTS IPv4
    r += lp(ipv6)
    r += lp(ifname)
    r += u('I', 7) + b'\x00\x00'              # MD interface index and 2 octets
    r += bytes.fromhex('02aabbccdd01')        # CM MAC
    r += bytes([192, 0, 2, 50])               # CM IPv4
    r += lp(bytes(range(16, 32)) if cm6 is None else cm6)
    r += lp(bytes(range(32, 48)) if ll is None else ll)
    r += u('III', 2, 8, 1700000000)           # QoS, registration status, last registration
    r += u('I', 1) + u('Q', 1700000000123)    # record type, creation time (ms)
    ch = bytes(chans)
    r += u('I', len(ch) if chset_len is None else chset_len) + ch
    r += u('I', 1234) + b'\x01' + u('II', 4321, 99)   # app id, multicast, service id, gate id
    r += lp(cls)
    r += u('I', direction) + u('QQ', 123456789, 4567) + u('IIII', 1, 2, 3000, 4000)
    return u('I', len(r) + 4) + r

def data_msg(sid, rec, seq=1, tmpl=1, cfg=1):
    return msg(0x20, sid, u('HHB', tmpl, cfg, 0) + u('Q', seq) + rec)

def main():
    out = sys.argv[1]
    frames = []
    t = Tcp(frames, CL, SV, 50000, 4737)
    mark(frames, 'connection setup and session control')
    t.send('c', msg(0x05, 0, u('I', 0xC0000201) + u('H', 4737) + u('II', 0x3, 5000) + vendor()))
    t.send('s', msg(0x06, 0, u('II', 0x3, 5000) + vendor(b'COLL')))
    t.send('c', msg(0x14, 0, u('H', 11)))
    t.send('s', msg(0x15, 0, u('H', 11)))
    t.send('c', msg(0x16, 1, u('H', 12)))
    t.send('s', msg(0x17, 1, u('HH', 12, 3)))
    t.send('c', msg(0x1D, 1))
    t.send('s', msg(0x1E, 1))
    t.send('c', msg(0x10, 1, u('HB', 3, 0)))
    t.send('s', msg(0x13, 1))
    t.send('c', msg(0x1A, 1, u('H', 3)))
    t.send('s', msg(0x1B, 1, u('HB', 3, 1)))
    t.send('c', msg(0x08, 1, u('I', 1700000000) + u('Q', 1000) + u('Q', 0) + b'\x01' + u('II', 60, 100) + bytes(range(16))))
    t.send('c', msg(0x01, 1))
    mark(frames, 'data and acknowledgements')
    t.send('c', data_msg(1, samis(), seq=1))
    t.send('s', msg(0x21, 1, u('H', 1) + u('Q', 1)))
    t.send('c', data_msg(2, b'\x01\x02\x03\x04', seq=2))                # no SAMIS session: raw record
    t.send('c', data_msg(1, samis(ipv6=b'', cm6=b'', ll=b'fe80::1', chans=()), seq=3))    # no IPv6, empty set (warning)
    t.send('c', data_msg(1, samis(ipv6=bytes(4), cm6=b'2001:db8::2', ll=b'', chans=(5,), direction=2), seq=4))  # IPv6 length 4 (the fix: not shown)
    t.send('c', data_msg(1, samis(host=b'', ifname=b'', cls=b'', chans=tuple(range(255))), seq=5))
    t.send('c', data_msg(1, samis(chans=tuple(range(256)) , chset_len=256), seq=6))   # 256 channels: too big (warning)
    t.send('c', data_msg(1, samis(chans=(1,)), seq=7) + data_msg(1, samis(chans=(2,)), seq=8))   # two PDUs in one segment
    big = data_msg(1, samis(chans=(9,)), seq=9)
    t.send('c', big[:30])                                              # a PDU over three segments
    t.send('c', big[30:100])
    t.send('c', big[100:])
    t.send('c', msg(0x40, 1))
    t.send('c', msg(0x30, 1, u('HHB', 2, 3, 0) + u('Q', 77) + b'request data'))
    t.send('s', msg(0x31, 1, u('HHB', 2, 3, 0) + u('Q', 77) + b'response data'))
    t.send('c', msg(0x23, 1, u('I', 1700000100) + u('H', 5) + b'something went wrong'))
    t.send('s', msg(0x40, 1))
    mark(frames, 'flow and session stop, unknown message id')
    t.send('c', msg(0x03, 1, u('H', 0) + b'flow stopped'))
    t.send('c', msg(0x09, 1, u('H', 1) + b'session stopped'))
    t.send('c', msg(0x07, 0))
    t.send('c', msg(0x7f, 0))                                          # unknown message id
    t.fin()
    mark(frames, 'other versions are not IPDR')
    t = Tcp(frames, CL, SV, 50001, 4737)
    t.send('c', msg(0x40, 0, ver=3))
    write_pcap(os.path.join(out, 'ipdr-coverage.pcap'), frames)
    n_main = len(frames)

    # ---- malformed capture: lengths that run past the data ----
    frames = []
    t = Tcp(frames, CL, SV, 51000, 4737)
    mark(frames, 'MALFORMED capture: SAMIS records with lengths past the end')
    def bad(rec_fn, seq):
        t.send('c', data_msg(1, rec_fn(), seq=seq))
    bad(lambda: samis(host_len=0xFFFFFFFF), 1)
    # build records with one length field replaced
    def patch(rec, idx_fn):
        return idx_fn(rec)
    good = samis()
    # offsets of the length fields in the record: 4 + 4 + len(host) + 4 + 4 -> ipv6 len, etc.
    def set_at(rec, off, val=0xFFFFFFFF):
        return rec[:off] + u('I', val) + rec[off + 4:]
    host = 17
    off_ipv6 = 4 + 4 + host + 4 + 4
    off_if = off_ipv6 + 4 + 16
    off_cm6 = off_if + 4 + 10 + 4 + 2 + 6 + 4
    off_ll = off_cm6 + 4 + 16
    off_ch = off_ll + 4 + 16 + 12 + 4 + 8
    off_cls = off_ch + 4 + 3 + 4 + 1 + 8
    for i, off in enumerate((off_ipv6, off_if, off_cm6, off_ll, off_ch, off_cls)):
        t.send('c', data_msg(1, set_at(good, off), seq=10 + i))
    t.send('c', data_msg(1, set_at(good, off_ch, 0x7FFFFFF0), seq=20))      # len + 4 wrapped before the fix
    t.send('c', data_msg(1, set_at(good, off_ch, 0xFFFFFFFC), seq=21))
    t.send('c', data_msg(1, good[:40], seq=22))                              # record cut short (exception)
    t.send('c', msg(0x20, 1, u('HHB', 1, 1, 0)))                             # DATA cut short
    t.send('c', msg(0x05, 0, u('I', 1)))                                     # CONNECT cut short
    write_pcap(os.path.join(out, 'ipdr-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv:
        for n, s in LABELS:
            print(n, s)
        print('main frames', n_main, 'malformed frames', len(frames))
        print('offsets', off_ipv6, off_if, off_cm6, off_ll, off_ch, off_cls)

main()
