# Generates test/captures/vsip_coverage.pcap.gz
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

# ---- VSIP (Verint Systems Internet Protocol) as Exported PDU "vsip" ----
G1 = bytes(range(16))
G2 = bytes(range(0xa0, 0xb0))
G3 = bytes([0x11] * 16)

def vsip(vtype, body, version=0x0100, transac=1, size=None):
    hl = 7 if version == 0x0100 else 9
    total = hl + len(body)
    sz = total if size is None else size
    hdr = struct.pack('!HBH', version, vtype, transac)
    hdr += struct.pack('!H', sz & 0xffff) if version == 0x0100 else struct.pack('!I', sz)
    if version not in (0x0100, 0x0101):
        hdr += struct.pack('!H', sz & 0xffff)
    return hdr + body

def val(t, v=None):
    # value of a given value type (1 char, 2 short, 3 int, 4 string, 5 uint, 6 guid, 7 float, 8 binary)
    if t == 1: return b'\x41'
    if t == 2: return struct.pack('!h', -2)
    if t == 3: return struct.pack('!i', -70000)
    if t == 4:
        s = v if v is not None else b'text value'
        return struct.pack('!H', len(s)) + s
    if t == 5: return struct.pack('!I', 4000000000)
    if t == 6: return G2
    if t == 7: return struct.pack('!f', 1.5)
    if t == 8:
        s = v if v is not None else b'\x00\x01\x02binary'
        return struct.pack('!I', len(s)) + s
    return b''

def cfg_item(cid, t, v=None):
    return struct.pack('!HB', cid, t) + val(t, v)

def arg_item(t, v=None):
    return bytes([t]) + val(t, v)

def build(outdir):
    pk = []
    def add(frame):
        pk.append(exp_pdu('vsip', frame))
    for ver in (0x0100, 0x0101):
        add(vsip(1, struct.pack('!IHB', 0xc0000201, 2300, 1), ver, 1))                       # Ping request
        add(vsip(1, struct.pack('!IHB', 0xe0000064, 2301, 204), ver, 2))                     # multicast reply, RTP over TCP volatile
        add(vsip(2, struct.pack('!IHB', 0xc0000202, 2300, 0xff) + G1 + struct.pack('!HHB', 8193, 17, 1) +
                 struct.pack('!H', 7) + b'camera1', ver, 3))                                 # Ping response
        add(vsip(2, struct.pack('!IHB', 0xc0000203, 2300, 0x00) + G3 + struct.pack('!HHB', 8200, 3, 0) +
                 struct.pack('!H', 0), ver, 4))                                              # empty subtype
        add(vsip(19, G1 + b'\x03' + G2, ver, 5))                                             # content type switch
        add(vsip(20, G1 + b'\x01', ver, 6))
        add(vsip(3, b'\x00', ver, 7))                                                        # get capabilities
        caps = b''.join(bytes([et]) + G1 + struct.pack('!HH', 8193 + et % 8, 0x0100 + et)
                        for et in (0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 17, 18, 20, 22, 99))
        add(vsip(4, struct.pack('!H', 16) + caps, ver, 8))
        add(vsip(4, struct.pack('!H', 0), ver, 9))
        add(vsip(5, G1 + struct.pack('!IHHB', 0xc0000210, 5000, 5002, 7), ver, 10))          # start device
        add(vsip(21, G1 + struct.pack('!IHHB', 0xe0000211, 5004, 5006, 11) + G2, ver, 11))   # start device ex
        add(vsip(6, G1, ver, 12))
        add(vsip(22, G1 + G2, ver, 13))
        items = b''.join(cfg_item(cid, t) for cid, t in
                         ((1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (13, 6), (257, 7), (4097, 8), (20482, 4), (99999 & 0xffff, 9)))
        add(vsip(7, G1 + struct.pack('!H', 10) + items, ver, 14))
        add(vsip(7, G1 + struct.pack('!H', 2) + cfg_item(4, 4, b'') + cfg_item(5, 8, b''), ver, 15))
        add(vsip(8, G1 + struct.pack('!H', 4) + b''.join(struct.pack('!H', c) for c in (1, 257, 4097, 20481)), ver, 16))
        add(vsip(8, G1 + struct.pack('!H', 0), ver, 17))
        add(vsip(9, G1 + struct.pack('!H', 10) + items, ver, 18))
        add(vsip(10, G1 + b'\x01' + struct.pack('!II', 1, 2), ver, 19))                      # send command
        add(vsip(10, G1 + b'\x40' + struct.pack('!II', 0xffffffff, 0), ver, 20))
        args = b''.join(arg_item(t) for t in (1, 2, 3, 4, 5, 6, 7, 8, 9))
        add(vsip(24, G1 + b'\x09' + struct.pack('!II', 3, 4) + struct.pack('!H', 9) + args, ver, 21))   # send command ex
        add(vsip(24, G1 + b'\x21' + struct.pack('!II', 3, 4) + struct.pack('!H', 0), ver, 22))
        add(vsip(11, G1 + struct.pack('!HI', 5, 77), ver, 23))                               # event notify
        add(vsip(12, struct.pack('!IHB', 0xc0000220, 6000, 12), ver, 24))                    # event subscribe
        add(vsip(23, struct.pack('!IHB', 0xc0000221, 6002, 140) + G2, ver, 25))              # event subscribe ex
        add(vsip(13, b'\x07' + struct.pack('!I', 0x80000005), ver, 26))                      # error response
        add(vsip(48, b'\x07' + struct.pack('!I', 0x80000006) + struct.pack('!H', 9) + args, ver, 27))   # error va response
        add(vsip(48, b'\x0a' + struct.pack('!I', 1) + struct.pack('!H', 0), ver, 28))
        add(vsip(77, b'\x00' * 4, ver, 29))                                                  # unknown type
    # a message type from the list without a body decoder (Content type values etc. appear in the fields above)
    pcap_write(os.path.join(outdir, 'vsip-coverage.pcap'), pk, linktype=252)

    mal = []
    def madd(frame):
        mal.append(exp_pdu('vsip', frame))
    # unsupported version: not VSIP
    madd(struct.pack('!HBH', 0x0200, 1, 1) + b'\0' * 12)
    # the reproducer of "VSIP: Check the length of binary values": length 0xFFFFFFFF
    madd(vsip(7, G1 + struct.pack('!H', 2) + struct.pack('!HBI', 0x1000, 8, 0xFFFFFFFF) + b'BINDATA!' +
              struct.pack('!HBI', 0x1000, 8, 0xFFFFFFFF) + b'BINDATA!', 0x0100, 1))
    # the same through the other messages that carry values
    madd(vsip(9, G1 + struct.pack('!H', 1) + struct.pack('!HBI', 1, 8, 0x80000000) + b'xx', 0x0101, 2))
    madd(vsip(24, G1 + b'\x01' + struct.pack('!II', 1, 2) + struct.pack('!H', 1) + bytes([8]) + struct.pack('!I', 0xfffffff0) + b'x', 0x0100, 3))
    madd(vsip(48, b'\x07' + struct.pack('!I', 1) + struct.pack('!H', 1) + bytes([8]) + struct.pack('!I', 0x7fffffff) + b'x', 0x0100, 4))
    # binary value with a length just larger than the data left
    madd(vsip(7, G1 + struct.pack('!H', 1) + struct.pack('!HBI', 1, 8, 5) + b'1234', 0x0100, 5))
    # string value longer than the data
    madd(vsip(7, G1 + struct.pack('!H', 1) + struct.pack('!HBH', 1, 4, 100) + b'short', 0x0100, 6))
    # counts that run past the end of the data
    madd(vsip(4, struct.pack('!H', 50) + G1, 0x0100, 7))
    madd(vsip(8, G1 + struct.pack('!H', 5000) + b'\0\1', 0x0100, 8))
    madd(vsip(24, G1 + b'\x01' + struct.pack('!II', 1, 2) + struct.pack('!H', 3), 0x0100, 9))
    madd(vsip(48, b'\x07' + struct.pack('!I', 1) + struct.pack('!H', 4), 0x0101, 10))
    madd(vsip(9, G1 + struct.pack('!H', 3) + cfg_item(1, 3), 0x0101, 11))
    # every fixed size message cut short
    for t, n in ((1, 3), (2, 20), (19, 30), (20, 10), (3, 0), (5, 20), (21, 30), (6, 8), (22, 20), (10, 10), (11, 12),
                 (12, 3), (23, 10), (13, 2), (7, 5), (7, 17)):
        madd(vsip(t, b'\x01' * n, 0x0100, 20, size=7 + n))
    # a message with only the version
    madd(b'\x01\x00')
    madd(b'\x01\x01\x07\x00\x01')
    pcap_write(os.path.join(outdir, 'vsip-coverage-malformed.pcap'), mal, linktype=252)
    gz(os.path.join(outdir, 'vsip-coverage.pcap'), os.path.join(outdir, 'vsip_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
