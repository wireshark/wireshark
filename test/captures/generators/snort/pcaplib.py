# Helper module for the snort capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helper library for the c16 coverage generators (copied into each coverage directory as pcaplib.py)
# pcap/pcapng writers, Ethernet/IPv4/UDP/TCP builders, Exported PDU tags. Synthetic addresses only.
import struct
CLI = (192, 0, 2, 1)
SRV = (192, 0, 2, 2)

def ip4(proto, payload, src=CLI, dst=SRV, ident=1):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                       bytes(src), bytes(dst)) + payload

def eth(etype, payload, smac=1, dmac=2):
    return bytes([2, 0, 0, 0, 0, dmac]) + bytes([2, 0, 0, 0, 0, smac]) + struct.pack('!H', etype) + payload

def udp(sport, dport, payload, src=CLI, dst=SRV):
    return eth(0x0800, ip4(17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload, src, dst))

def tcp(sport, dport, payload=b'', seq=1, ack=1, flags=0x18, src=CLI, dst=SRV, opts=b''):
    hl = (20 + len(opts)) // 4
    return eth(0x0800, ip4(6, struct.pack('!HHIIBBHHH', sport, dport, seq, ack, hl << 4, flags, 65535, 0, 0)
                           + opts + payload, src, dst))

def tag(t, v):
    return struct.pack('!HH', t, len(v)) + v

def exp_pdu(name, payload, extra=b''):
    return tag(12, name.encode()) + extra + tag(0, b'') + payload

def write_pcap(fn, frames, dlt=1, snap=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, dlt))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def _blk(t, body):
    body += b'\x00' * ((4 - len(body) % 4) % 4)
    return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)

def _opt(code, val):
    return struct.pack('<HH', code, len(val)) + val + b'\x00' * ((4 - len(val) % 4) % 4)

def write_pcapng(fn, frames, dlts=(1,)):
    """frames: list of bytes, (bytes, comment) or (bytes, comment, ifid)."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for d in dlts:
        out += _blk(1, struct.pack('<HHI', d, 0, 262144))
    for i, fr in enumerate(frames):
        comment, ifid = None, 0
        if isinstance(fr, tuple):
            data = fr[0]
            comment = fr[1]
            if len(fr) > 2:
                ifid = fr[2]
        else:
            data = fr
        b = struct.pack('<IIIII', ifid, 0, 1000000 + i, len(data), len(data)) + data
        b += b'\x00' * ((4 - len(data) % 4) % 4)
        if comment is not None:
            b += _opt(1, comment.encode())
        b += struct.pack('<HH', 0, 0)
        out += _blk(6, b)
    open(fn, 'wb').write(out)

class TcpFlow:
    """Bidirectional TCP flow with tracked sequence numbers."""
    def __init__(self, cport, sport, caddr=CLI, saddr=SRV):
        self.cport, self.sport, self.caddr, self.saddr = cport, sport, caddr, saddr
        self.cseq, self.sseq = 1000, 5000
    def handshake(self):
        mss = struct.pack('!BBH', 2, 4, 9000) + b'\x04\x02\x01\x01'   # SACK permitted; MSS option so that large segments are not flagged
        a = tcp(self.cport, self.sport, b'', self.cseq, 0, 0x02, self.caddr, self.saddr, mss)
        b = tcp(self.sport, self.cport, b'', self.sseq, self.cseq + 1, 0x12, self.saddr, self.caddr, mss)
        self.cseq += 1; self.sseq += 1
        c = tcp(self.cport, self.sport, b'', self.cseq, self.sseq, 0x10, self.caddr, self.saddr)
        return [a, b, c]
    def c2s(self, data, flags=0x18):
        fr = tcp(self.cport, self.sport, data, self.cseq, self.sseq, flags, self.caddr, self.saddr)
        self.cseq += len(data); return fr
    def s2c(self, data, flags=0x18):
        fr = tcp(self.sport, self.cport, data, self.sseq, self.cseq, flags, self.saddr, self.caddr)
        self.sseq += len(data); return fr
    def fin(self):
        a = tcp(self.cport, self.sport, b'', self.cseq, self.sseq, 0x11, self.caddr, self.saddr); self.cseq += 1
        b = tcp(self.sport, self.cport, b'', self.sseq, self.cseq, 0x11, self.saddr, self.caddr); self.sseq += 1
        c = tcp(self.cport, self.sport, b'', self.cseq, self.sseq, 0x10, self.caddr, self.saddr)
        return [a, b, c]
