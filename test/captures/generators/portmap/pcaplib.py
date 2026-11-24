# Helper module for the portmap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared pcap helpers (synthetic addresses only).
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def eth(payload, ethertype=0x0800, dst='020000000002', src='020000000001'):
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack('!H', ethertype) + payload

def udp(sport, dport, data, **kw):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    return eth(ipv4(17, u, **kw))

def exported_pdu(dissector, data):
    name = dissector.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0)
    return tags + data

def write_pcap(path, frames, linktype=1, step_us=0):
    """frames: list of bytes or (bytes, usec_offset)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        t = 0
        for fr in frames:
            if isinstance(fr, tuple):
                fr, t = fr
            else:
                t += 1000000 if not step_us else step_us
            f.write(struct.pack('<IIII', 1700000000 + t // 1000000, t % 1000000, len(fr), len(fr)))
            f.write(fr)

class Tcp:
    """TCP stream builder with a handshake, one direction per call."""
    def __init__(self, cport, sport, csrc='192.0.2.1', ssrc='192.0.2.2'):
        self.cport, self.sport, self.csrc, self.ssrc = cport, sport, csrc, ssrc
        self.cseq, self.sseq = 1000, 5000
    @staticmethod
    def _seg(sp, dp, seq, ack, flags, data, src, dst):
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0) + data
        return eth(ipv4(6, t, src=src, dst=dst))
    def handshake(self):
        f = [self._seg(self.cport, self.sport, self.cseq, 0, 0x02, b'', self.csrc, self.ssrc)]
        self.cseq += 1
        f.append(self._seg(self.sport, self.cport, self.sseq, self.cseq, 0x12, b'', self.ssrc, self.csrc))
        self.sseq += 1
        f.append(self._seg(self.cport, self.sport, self.cseq, self.sseq, 0x10, b'', self.csrc, self.ssrc))
        return f
    def c2s(self, data):
        f = self._seg(self.cport, self.sport, self.cseq, self.sseq, 0x18, data, self.csrc, self.ssrc)
        self.cseq += len(data)
        return f
    def s2c(self, data):
        f = self._seg(self.sport, self.cport, self.sseq, self.cseq, 0x18, data, self.ssrc, self.csrc)
        self.sseq += len(data)
        return f
