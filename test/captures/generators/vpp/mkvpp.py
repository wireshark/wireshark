# Generates test/captures/vpp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (copied into each generator) ----
import struct
import os
import sys
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def pcap_write(fname, pkts, linktype=1, t0=1700000000):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            olen = None
            if isinstance(p, tuple):
                if len(p) == 3:
                    p, ts, olen = p
                else:
                    p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), olen or len(p)))
            f.write(p)

def eth(payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x0800):
    f = dst + src + struct.pack('!H', et) + payload
    return f + b'\0' * max(0, 60 - len(f))

def ip4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ttl=64, ident=1, flags_frag=0, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags_frag, ttl, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1', dst=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2', hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def tcp(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2), win=65535):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    return t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def gz(path, gzpath):
    with open(path, 'rb') as f:
        d = f.read()
    with open(gzpath, 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))

# ---- VPP dispatch trace (pcap link type 280, DLT_VPP_DISPATCH) ----
def vpp(pkt, node='ethernet-input', meta='', opaque='', opaque2='', trace=None, hint=0, major=1, minor=0,
        bufidx=0x00010203, count=None):
    n = 4 if trace is None else 5
    s = (struct.pack('!BBBBI', major, minor, n if count is None else count, hint, bufidx) +
         node.encode() + b'\0' + meta.encode() + b'\0' + opaque.encode() + b'\0' + opaque2.encode() + b'\0')
    if trace is not None:
        s += trace.encode() + b'\0'
    return s + pkt

def tcp_hdr(sport=1234, dport=80, flags=0x18, payload=b'hello'):
    return struct.pack('!HHIIBBHHH', sport, dport, 1000, 2000, 5 << 4, flags, 4096, 0, 0) + payload

def udp_hdr(sport=5000, dport=9999, payload=b'vpp test payload'):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

S4, D4 = (192, 0, 2, 1), (192, 0, 2, 2)
S6 = bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1'
D6 = bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2'

def udp4(sport, payload=b'vpp test payload'):
    return ip4(17, udp(sport, 9999, payload))

def udp6(sport, payload=b'vpp test payload'):
    u = struct.pack('!HHHH', sport, 9999, 8 + len(payload), 0) + payload
    c = csum(S6 + D6 + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u)
    return ip6(17, u[:6] + struct.pack('!H', c) + u[8:])

def tcp4(sport, seq=1000, payload=b'hello'):
    return ip4(6, tcp(sport, 80, seq, 2000, 0x18, payload))

def ethernet(payload, et=0x0800):
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01' + struct.pack('!H', et) + payload

def ip4p(proto, payload):
    return ip4(proto, payload)

def build(outdir):
    pk = []
    ip_udp = udp4(5000)
    ip_tcp = tcp4(1234)
    ip6_udp = udp6(5001)
    # hint 0 (none): the first byte decides (0x45 IPv4, 0x60 IPv6, else Ethernet)
    pk.append(vpp(ip_udp, 'ip4-input', 'sw_if_index 1\nfib 0', 'opaque 1', 'opaque2 1', hint=0))
    pk.append(vpp(ip6_udp, 'ip6-input', 'sw_if_index 2', '', '', hint=0))
    pk.append(vpp(ethernet(ip_udp), 'ethernet-input', 'sw_if_index 3', 'o', 'o2', hint=0))
    # every hint
    pk.append(vpp(ethernet(tcp4(1235, 5000)), 'af-packet-input', 'm', 'o', 'o', hint=1))
    pk.append(vpp(ip_tcp, 'ip4-lookup', 'm', 'o', 'o', hint=2))
    pk.append(vpp(ip6(6, tcp_hdr(1236, 80, 0x10, b'')), 'ip6-lookup', 'm', 'o', 'o', hint=3))
    pk.append(vpp(tcp_hdr(1240, 80, 0x18, b'tcp only'), 'tcp4-input', 'm', 'o', 'o', hint=4))
    pk.append(vpp(udp_hdr(5100), 'udp4-input', 'm', 'o', 'o', hint=5))
    # a trace string (five strings) with several lines, CRLF and empty lines
    pk.append(vpp(ethernet(udp4(6009)), 'ethernet-input', 'line1\nline2\r\nline3', 'op1\nop2', 'op2-1\nop2-2',
                  trace='ethernet-input: sw_if_index 1\n  IP4: 02:00:00:00:00:01 -> 02:00:00:00:00:02\n\nend', hint=1))
    pk.append(vpp(udp4(6001), 'trace-only', '', '', '', trace='x', hint=2))
    # empty strings everywhere
    pk.append(vpp(udp4(6002), '', '', '', '', hint=2))
    # minor version mismatch: a warning, the rest is dissected
    pk.append(vpp(udp4(6003), 'ip4-input', 'm', 'o', 'o', hint=2, minor=3))
    # protocol hint out of range: a warning, hint 0 is used (0x45 selects IPv4)
    pk.append(vpp(udp4(6004), 'ip4-input', 'm', 'o', 'o', hint=9))
    pk.append(vpp(ethernet(udp4(6010)), 'ip4-input', 'm', 'o', 'o', hint=200))
    # a long metadata string over several lines
    pk.append(vpp(udp4(6005), 'node-with-a-long-name-' + 'n' * 100, '\n'.join('key%d: value%d' % (i, i) for i in range(30)),
                  'o', 'o', hint=2))
    pcap_write(os.path.join(outdir, 'vpp-coverage.pcap'), [(p, 1700000000 + i) for i, p in enumerate(pk)], linktype=280)

    mal = []
    # major version mismatch: the dissection stops after the version
    mal.append(vpp(udp4(6006), major=2))
    mal.append(vpp(udp4(6007), major=0))
    # minor and hint both bad
    mal.append(vpp(udp4(6008), minor=1, hint=77))
    # truncated header and strings without terminators
    mal.append(b'\x01\x00\x04')
    mal.append(b'\x01\x00\x04\x00\x00\x00\x00\x01node')
    mal.append(b'\x01\x00\x04\x02\x00\x00\x00\x01node\0meta')
    mal.append(b'\x01\x00\x05\x02\x00\x00\x00\x01node\0m\0o\0o2\0trace')
    # strings only: no packet follows
    mal.append(b'\x01\x00\x04\x00\x00\x00\x00\x01node\0m\0o\0o2\0')
    pcap_write(os.path.join(outdir, 'vpp-coverage-malformed.pcap'), [(p, 1700000000 + i) for i, p in enumerate(mal)], linktype=280)
    gz(os.path.join(outdir, 'vpp-coverage.pcap'), os.path.join(outdir, 'vpp_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
