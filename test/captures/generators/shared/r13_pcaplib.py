# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal pcap writer helpers for review group r13 (synthetic addresses only)
import struct

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(payload, ethertype, src=b'\x02\0\0\0\0\x01', dst=b'\x02\0\0\0\0\x02'):
    return dst + src + struct.pack('!H', ethertype) + payload

def ipv4(payload, proto, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload

def tcp(payload, sport, dport, seq, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5<<4, flags, 65535, 0, 0) + payload

class TcpStream:
    """Two-direction TCP stream; seq numbers tracked per direction."""
    def __init__(self, cport=40000, sport=1883):
        self.cport, self.sport = cport, sport
        self.seq = {0: 1000, 1: 5000}
    def handshake(self):
        """SYN, SYN/ACK, ACK frames; the data then starts at seq 1000/5000."""
        def syn(sport, dport, seq, ack, fl, src, dst, m1, m2):
            opts = struct.pack('!BBH', 2, 4, 1460) + b'\x01\x03\x03\x07' + b'\x04\x02\x01\x01'
            h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 8 << 4, fl, 65535, 0, 0) + opts
            return eth(ipv4(h, 6, src, dst), 0x0800, m1, m2)
        c, s_ = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
        out = [syn(self.cport, self.sport, 999, 0, 0x02, '192.0.2.1', '192.0.2.2', c, s_),
               syn(self.sport, self.cport, 4999, 1000, 0x12, '192.0.2.2', '192.0.2.1', s_, c)]
        p = tcp(b'', self.cport, self.sport, 1000, 5000, 0x10)
        out.append(eth(ipv4(p, 6), 0x0800))
        return out
    def pkt(self, data, from_server=False):
        d = 1 if from_server else 0
        if d:
            p = tcp(data, self.sport, self.cport, self.seq[1], self.seq[0])
            f = eth(ipv4(p, 6, '192.0.2.2', '192.0.2.1'), 0x0800, b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01')
        else:
            p = tcp(data, self.cport, self.sport, self.seq[0], self.seq[1])
            f = eth(ipv4(p, 6), 0x0800)
        self.seq[d] += len(data)
        return f

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def exported_pdu(proto_name, payload):
    """Exported PDU (linktype 252) with EXP_PDU_TAG_DISSECTOR_NAME."""
    n = proto_name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('!HH', 12, len(n) + pad) + n + b'\0'*pad
    tags += struct.pack('!HH', 0, 0)
    return tags + payload
