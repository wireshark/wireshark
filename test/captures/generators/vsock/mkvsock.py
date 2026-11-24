# Generates test/captures/vsock_coverage.pcap.gz
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

# ---- vSocket (AF_VSOCK monitor, pcap link type 271 DLT_VSOCK) ----
def vsock(src_cid, dst_cid, sport, dport, op, t, tlen=None, transport=b'', payload=b'', reserved=0):
    if tlen is None:
        tlen = len(transport)
    return (struct.pack('<QQIIHHHH', src_cid, dst_cid, sport, dport, op, t, tlen, reserved) +
            transport + payload)

def virtio(src_cid, dst_cid, sport, dport, length, vtype, vop, flags=0, buf_alloc=262144, fwd_cnt=0):
    return struct.pack('<QQIIIHHIII', src_cid, dst_cid, sport, dport, length, vtype, vop, flags,
                       buf_alloc, fwd_cnt)

HOST = 2
BIG = 1000000000000000000         # 10**18: 19 digits
MAXC = 0xFFFFFFFFFFFFFFFF         # 20 digits

def vio_frame(op, vop, payload=b'', vtype=1, src=3, dst=HOST, sport=1234, dport=5000, flags=0, fwd=0):
    tr = virtio(src, dst, sport, dport, len(payload), vtype, vop, flags, 262144, fwd)
    return vsock(src, dst, sport, dport, op, 2, transport=tr, payload=payload)

def build(outdir):
    pk = []
    # connection setup, data and teardown with the virtio transport
    pk.append(vio_frame(1, 1))                                  # Connect, Request
    pk.append(vio_frame(3, 2, src=HOST, dst=3, sport=5000, dport=1234))   # Control, Response
    pk.append(vio_frame(4, 5, b'GET / HTTP/1.0\r\n\r\n', fwd=0))          # Payload, RW
    pk.append(vio_frame(4, 5, bytes(range(200)), src=HOST, dst=3, sport=5000, dport=1234, fwd=18))
    pk.append(vio_frame(3, 6, flags=0))                                    # Credit update
    pk.append(vio_frame(3, 7))                                             # Credit response
    pk.append(vio_frame(3, 4, flags=3))                                    # Shutdown
    pk.append(vio_frame(3, 3))                                             # Rst
    pk.append(vio_frame(2, 0))                                             # Disconnect, Invalid
    pk.append(vio_frame(3, 99, vtype=7))                                   # unknown virtio op and type
    # every operation and transport value
    for op in (0, 1, 2, 3, 4, 17):
        pk.append(vsock(5, HOST, 1000 + op, 2000, op, 1, payload=b'P' * op))        # no transport info
    pk.append(vsock(5, HOST, 1, 2, 1, 0))                                           # unknown transport
    pk.append(vsock(5, HOST, 1, 2, 4, 9, tlen=0, payload=b'unknown transport 9'))   # transport value not listed
    # large context IDs: the address strings must not be cut short
    pk.append(vio_frame(4, 5, b'big', src=BIG, dst=BIG + 1))
    pk.append(vio_frame(4, 5, b'max', src=MAXC, dst=MAXC - 1))
    pk.append(vsock(MAXC, BIG, 1, 2, 4, 1, payload=b'no transport, big CIDs'))
    pk.append(vsock(0, 1, 0, 0xffffffff, 0, 0))
    # transport length that does not fit: the payload offset used to wrap in 16 bits
    pk.append(vsock(7, HOST, 1, 2, 4, 1, tlen=0xFFFF, payload=b'PAYLOAD-' * 2))              # reproducer
    pk.append(vsock(7, HOST, 1, 2, 4, 1, tlen=65504, payload=b'PAYLOAD-' * 2))               # 32 + 65504 = 65536
    pk.append(vsock(7, HOST, 1, 2, 4, 1, tlen=65508, payload=b'PAYLOAD-' * 2))               # 32 + 65508 wraps to 4
    pk.append(vsock(7, HOST, 1, 2, 4, 1, tlen=8, payload=b'PAYLOAD-' * 2))                   # transport bytes skipped
    pk.append(vsock(7, HOST, 1, 2, 4, 1, tlen=8, payload=b'ABCDEFGH'))                       # nothing after them
    # virtio with a transport length larger than the header (extra bytes are payload-like data)
    tr = virtio(3, HOST, 1, 2, 4, 1, 5) + b'\xee' * 6
    pk.append(vsock(3, HOST, 1, 2, 4, 2, tlen=len(tr), transport=tr, payload=b'DATA'))
    pcap_write(os.path.join(outdir, 'vsock-coverage.pcap'), pk, linktype=271)

    mal = []
    # shorter than the 32 byte header: not dissected
    mal.append(vsock(1, 2, 3, 4, 4, 1)[:31])
    mal.append(b'')
    # virtio transport cut short
    full = vio_frame(4, 5, b'x')
    mal.append(full[:40])
    mal.append(full[:70])
    mal.append(full[:75])
    pcap_write(os.path.join(outdir, 'vsock-coverage-malformed.pcap'), mal, linktype=271)
    gz(os.path.join(outdir, 'vsock-coverage.pcap'), os.path.join(outdir, 'vsock_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
