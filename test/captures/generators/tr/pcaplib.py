# Helper module for the tr capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic pcap helpers: Ethernet/IPv4/UDP/TCP frames and a pcap writer.
import struct

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), ident, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def eth(payload, etype=0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'):
    mac = lambda m: bytes(int(x, 16) for x in m.split(':'))
    return mac(dst) + mac(src) + struct.pack('!H', etype) + payload

def udp(sport, dport, payload, **kw):
    return eth(ipv4(17, struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload, **kw))

def tcp(sport, dport, seq, payload, ack=1, flags=0x18, **kw):
    return eth(ipv4(6, struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload, **kw))

class Flow:
    """One TCP connection; seg() returns frames with running sequence numbers."""
    def __init__(self, cport, sport, c='192.0.2.1', s='192.0.2.2', isn=1000, isn_s=5000):
        self.cport, self.sport, self.c, self.s = cport, sport, c, s
        self.seq = {True: isn, False: isn_s}
    def seg(self, data, client=True, flags=0x18):
        k = client
        if client:
            f = tcp(self.cport, self.sport, self.seq[True], data, ack=self.seq[False], flags=flags, src=self.c, dst=self.s)
        else:
            f = tcp(self.sport, self.cport, self.seq[False], data, ack=self.seq[True], flags=flags, src=self.s, dst=self.c)
        self.seq[k] += len(data)
        return f

def write(fn, frames, linktype=1):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length): a truncated record
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), orig))
            f.write(fr)

def exported_pdu(dissector, payload, tags=b''):
    """Exported PDU (linktype 252) frame naming a registered dissector (tag 12)."""
    name = dissector.encode()
    pad = (-len(name)) % 4
    t = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + tags
    return t + struct.pack('!HH', 0, 0) + payload

def exp_tag(tag, value):
    pad = (-len(value)) % 4
    return struct.pack('!HH', tag, len(value) + pad) + value + b'\0' * pad

def write_ng(fn, linktypes, frames):
    """pcapng: one IDB per entry of linktypes; frames = [(interface index, bytes)]."""
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, d) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    open(fn, 'wb').write(out)

def tr_frame(payload, fc=0x00, dst='c0:00:00:00:00:01', src='00:00:00:00:00:02', ac=0x10, rif=b''):
    """IEEE 802.5 token ring frame (pcap linktype 6): AC, FC, DA, SA (routing bit set when a RIF follows), payload."""
    mac = lambda m: bytearray(int(x, 16) for x in m.split(':'))
    s = mac(src)
    if rif:
        s[0] |= 0x80
    return bytes([ac, fc]) + bytes(mac(dst)) + bytes(s) + rif + payload
