#!/usr/bin/env python3
# Generates test/captures/qnet6_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the QNET6 coverage captures. Usage: mkqnet6.py <outdir>
Ethernet type 0x8204 (QNX6 QNET LWL4) and IPv4 protocol 106, little and big
endian LWL4 versions; layers KIF, NR, LR and SEQ; QOS packets."""
import struct
import sys
import os

# ---- CRC-32/MPEG-2 (poly 0x04c11db7, MSB first, no final xor) ----
_T = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = ((_c << 1) ^ 0x04c11db7) & 0xffffffff if _c & 0x80000000 else (_c << 1) & 0xffffffff
    _T.append(_c)

def crc_mpeg2(data, crc=0):
    for b in data:
        crc = ((crc << 8) & 0xffffffff) ^ _T[((crc >> 24) ^ b) & 0xff]
    return crc

def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

ETH = bytes([2,0,0,0,0,2, 2,0,0,0,0,1])

def eth_frame(l4):
    return ETH + b'\x82\x04' + l4          # the two octets of padding are the start of the LWL4 header

def ip_frame(l4, n):
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), n + 1, 0, 64, 106, 0,
                      bytes([192,0,2,1]), bytes([192,0,2,2]))
    iph = iph[:10] + struct.pack('!H', ip_csum(iph)) + iph[12:]
    return ETH + b'\x08\x00' + iph + l4

def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

FIRST, LAST, CRCF = 1, 2, 4

def l4(payload=b'', typ=8, flags=3, layer=0, e='<', crc='good', plen=None, src_nd=1, dst_nd=2,
       sconn=0x11, dconn=0x22, seq=7, qtype=0, qidx=0, offset=0, ver=None):
    """LWL4 header (38 octets from the padding) plus payload."""
    if ver is None: ver = 0x2a if e == '<' else 0xaa
    if plen is None: plen = len(payload)
    qos = struct.pack(e + 'HHIIIHH', src_nd, dst_nd, sconn, dconn, seq, qtype, qidx)
    hdr = struct.pack('BBBB', ver, typ, flags, layer) + qos + struct.pack(e + 'II', offset, plen)
    if crc == 'zero':
        c = 0
    else:
        c = crc_mpeg2(hdr + b'\0\0\0\0' + payload[:min(len(payload), plen)])
        if crc == 'bad': c ^= 0x55aa55aa
    return b'\0\0' + hdr + struct.pack(e + 'I', c) + payload

# ---- KIF building blocks ----
def kif(msgtype, size=0, e='<'):
    return struct.pack(e + 'HH', msgtype, size)

def cred(e='<', ngroups=0, groups=None, nd=1, pid=100, sid=101, flags=3):
    d = struct.pack(e + 'IIII', nd, pid, sid, flags) + struct.pack(e + 'IIIIIII', 1000, 1001, 1002, 2000, 2001, 2002, ngroups)
    for g in (groups if groups is not None else range(ngroups)):
        d += struct.pack(e + 'I', 3000 + g)
    return d

def vinfo(e='<', coid=0x80000001):
    return struct.pack(e + 'II', 0x50, 0x60) + struct.pack(e + 'IIIIIIII', 5, coid, 10, 64, 0xabcd, 3, 64, 0)

def msgsend(msg, e='<', cr=False, coid=0x80000001, nbytes=None, mt=5):
    t = mt | (0x100 if cr else 0) | (0x8080 if e == '>' else 0)
    d = kif(t, 0, e) + vinfo(e, coid)
    d += struct.pack(e + 'I', len(msg) if nbytes is None else nbytes) + msg
    if cr: d += cred(e)
    return d

def connect_msgsend(msg, e='<', cr=False, mt=1, icr=False):
    t = mt | (0x100 if cr else 0) | (0x8080 if e == '>' else 0)
    d = kif(t, 0x30, e) + struct.pack(e + 'IIIII', 5, 0x1111, 0x2222, 0x3333, 0x4444)
    if cr: d += cred(e)
    d += kif(5 | (0x100 if icr else 0) | (0x8080 if e == '>' else 0), 0, e) + vinfo(e) + struct.pack(e + 'I', len(msg)) + msg
    if icr: d += cred(e)
    return d

def pulse(e='<', cr=False):
    t = 12 | (0x100 if cr else 0) | (0x8080 if e == '>' else 0)
    d = kif(t, 0, e) + vinfo(e)
    d += struct.pack(e + 'HH', 1, 2) + bytes([7, 0, 0, 0]) + struct.pack(e + 'III', 99, 0x1234, 10)
    if cr: d += cred(e)
    return d

# ---- IO messages ----
def io(typ, body=b'', e='<', extra=b'', nxt=None, cl=None):
    """type + combine_len + body; combine_len counts type, itself and body, plus extra data"""
    n = 4 + len(body) + len(extra) if cl is None else cl
    if nxt is not None: n |= 0x8000
    return struct.pack(e + 'HH', typ, n) + body + extra + (nxt or b'')

def msginfo(e='<', chid=0x40000001, coid=0x80000000):
    return (struct.pack(e + 'IIIII', 1, 2, 300, 301, chid) + struct.pack(e + 'III', 5, coid, 64) +
            struct.pack(e + 'III', 64, 0, 0) + struct.pack(e + 'HHI', 10, 1, 0))

def io_connect(sub, path=b'/dev/null\0', extra_type=0, extra=b'', e='<', nxt=None, eflag=7, pathlen=None,
               extralen=None, nopad=False):
    h = struct.pack(e + 'HIHHII', sub, 0x8000, 128, 2, 0x1234, 0x5678)
    h += struct.pack(e + 'II', 0x20042, 0o100644) + struct.pack(e + 'HHHH', 1, 2, 0, len(path) if pathlen is None else pathlen)
    h += bytes([eflag, extra_type]) + struct.pack(e + 'H', len(extra) if extralen is None else extralen)
    d = struct.pack(e + 'H', 0x100) + h + path
    if extra:
        pad = (len(path) + 40) & 7
        if pad and not nopad: d += bytes(8 - pad)
        d += extra
    return d

def build_all():
    G, B = [], []                    # (kind, ...) entries
    def g(fr, how='eth'): G.append((how, fr))
    def bad(fr, how='eth'): B.append((how, fr))
    # ---------------- LWL4 headers, types, layers, flags ----------------
    g(l4(typ=9, flags=3, layer=0))                              # Ack, header only
    g(l4(b'', typ=10, layer=0))                                  # Nack
    g(l4(b'\1\2\3\4', typ=10, layer=3))                           # Nack with data
    g(l4(typ=9, layer=3, payload=b'\0\0\0\0'))                   # Ack with data, sequence layer
    g(l4(b'\1\2\3\4', typ=8, layer=3))                           # Qos sequence hole filler
    g(l4(b'\1\2\3\4', typ=8, layer=9))                           # unknown layer
    g(l4(b'\1\2\3\4', typ=0xc, layer=0))                         # unknown type
    g(l4(b'\1\2\3\4', typ=0xb, layer=3))                         # LRES type with the sequence layer
    g(l4(b'\1\2\3\4', typ=0, layer=3))                           # type 0: qos switch not taken
    g(l4(b'\0\1', typ=8, layer=0))                               # KIF payload too short
    g(l4(b'\0', typ=8, layer=1, plen=0))                         # NR: plen 0
    g(l4(b'\0' * 20, typ=8, layer=2, plen=20))                   # LR: plen below 56
    # fragments
    g(l4(kif(14) + b'\0\0\0\0', flags=1, crc='zero'))            # first fragment only
    g(l4(b'\0\0\0\0\1\1', flags=0, crc='zero'))                  # middle fragment
    g(l4(b'\0\0\0\0\1\1', flags=2, crc='zero'))                  # last fragment
    g(l4(kif(14) + b'\0\0\0\0', flags=3 | CRCF, crc='good'))     # crc bit set
    g(l4(kif(14) + b'\0\0\0\0', flags=3, crc='bad'))             # incorrect crc
    g(l4(kif(14) + b'\0\0\0\0', flags=1 | CRCF, crc='zero'))     # crc bit but not first and last: no crc check
    g(l4(kif(14) + b'\0\0\0\0', flags=3, crc='good', plen=2))    # plen shorter than the data (crc over plen octets)
    g(l4(kif(14, e='>') + b'\0\0\0\0', e='>'))                   # big endian LWL4 version
    g(l4(kif(14, e='>') + b'\0\0\0\0', e='>', crc='bad'))
    # ---------------- QoS ----------------
    strs = b'srcnode\0example\0dstnode\0domain\0pad'
    g(l4(struct.pack('<HHHH', 0, 8, 16, 24) + strs, typ=1, layer=0))
    g(l4(struct.pack('>HHHH', 0, 8, 16, 24) + strs, typ=1, e='>'))
    g(l4(struct.pack('<HHHH', 0, 8, 16, 100) + strs, typ=1))     # offset beyond the strings: nothing generated
    g(l4(struct.pack('<HHHH', 0, 8, 16, 24) + b'a\0b\0c\0d\0e\0', typ=1, qtype=1, qidx=3))
    for t in (2, 3, 4, 5, 6, 7):
        g(l4(b'\0\0\0\0', typ=t, qtype=t % 4, qidx=t))
    # ---------------- NR ----------------
    for e in '<>':
        g(l4(bytes([0]), layer=1, e=e))                                              # ping request
        g(l4(bytes([1]), layer=1, e=e))                                              # ping reply
        g(l4(bytes([2, 6]) + struct.pack(e + 'H', 0x1234) + b'node-a', layer=1, e=e)) # remote request
        g(l4(bytes([2, 40]) + struct.pack(e + 'H', 0x1235) + b'node-b', layer=1, e=e))# name length past the end
        g(l4(bytes([3, 0]) + struct.pack(e + 'HI', 0x1234, 7), layer=1, e=e))        # remote reply
        g(l4(bytes([4, 0]) + struct.pack(e + 'HI', 0x1234, 2), layer=1, e=e))        # remote error
    g(l4(bytes([9, 0, 0, 0]), layer=1))                                              # unknown NR type
    # ---------------- LR ----------------
    def lr(typ, src, dst, e='<', mac=True, offs=None, ver=1):
        names = [src[0], src[1], b'\x08\x01' + bytes([2, 0, 0, 0, 0, 1]) if mac else b'\x08\x02ifname\0\0',
                 dst[0], dst[1], b'\x08\x01' + bytes([2, 0, 0, 0, 0, 2]) if mac else b'\x08\x02ifname\0\0']
        data, pairs = b'', b''
        for i, nm in enumerate(names):
            off = len(data)
            pairs += struct.pack(e + 'II', off if offs is None or offs[i] is None else offs[i], len(nm))
            data += nm + bytes((-len(nm)) % 8)
        total = 56 + len(data)
        return bytes([ver, 0, typ, 0]) + struct.pack(e + 'I', total) + pairs + data
    for e in '<>':
        g(l4(lr(1, (b'alice', b'example.net'), (b'bob', b'example.org'), e), layer=2, typ=0xb, e=e))
        g(l4(lr(2, (b'alice', b'example.net'), (b'bob', b'example.org'), e), layer=2, typ=0xb, e=e))
    g(l4(lr(3, (b'a', b'b'), (b'c', b'd')), layer=2, typ=0xb))                       # unknown LR type
    g(l4(lr(1, (b'a', b'b'), (b'c', b'd'), mac=False), layer=2, typ=0xb))            # address family 2: no address
    g(l4(lr(2, (b'a', b'b'), (b'c', b'd'), offs=[None, 5000, None, None, None, None]), layer=2, typ=0xb))  # offsets out of range
    g(l4(lr(1, (b'alice', b'example.net'), (b'bob', b'example.org')), layer=2, typ=0xb), 'ip')
    # ---------------- KIF: connect and friends ----------------
    for e in '<>':
        big = 0x8080 if e == '>' else 0
        g(l4(kif(0 | big, 0, e) + struct.pack(e + 'IIIII', 5, 0x1111, 0x40000003, 0x3333, 0x4444), e=e))
        g(l4(kif(0 | 0x100 | big, 0, e) + struct.pack(e + 'IIIII', 5, 0x1111, 5, 0x3333, 0x4444) + cred(e, 0), e=e))
        g(l4(kif(0 | 0x100 | big, 0, e) + struct.pack(e + 'IIIII', 5, 0x1111, 5, 0x3333, 0x4444) + cred(e, 3), e=e))
        g(l4(kif(2 | big, 0, e) + struct.pack(e + 'IIIII', 5, 1, 2, 3, 4), e=e))                 # connect success
        g(l4(kif(2 | 0x100 | big, 0, e) + struct.pack(e + 'IIIII', 5, 1, 2, 3, 4) + cred(e, 1), e=e))
        g(l4(kif(3 | big, 0, e) + struct.pack(e + 'III', 5, 1, 13), e=e))                       # connect fail
        g(l4(kif(15 | big, 0, e) + struct.pack(e + 'I', 0x77), e=e))                             # connect death
        g(l4(kif(4 | big, 0, e) + struct.pack(e + 'III', 1, 2, 3), e=e))                         # unblock
        g(l4(kif(6 | big, 0, e) + struct.pack(e + 'IIII', 1, 2, 0, 512), e=e))                   # msgread
        for t in (8, 9, 10, 7, 16):
            g(l4(kif(t | big, 0, e) + struct.pack(e + 'IIII', 0, 2, 16, 8) + b'datadata', e=e))   # write/reply/error/xfer/error
        g(l4(kif(11 | big, 0, e) + struct.pack(e + 'I', 9) + struct.pack(e + 'IIII', 1, 2, 3, 4), e=e))  # event
        g(l4(kif(13 | big, 0, e) + struct.pack(e + 'IIIIII', 1, 2, 3, 15, 0, 0), e=e))           # signal
        g(l4(kif(13 | 0x100 | big, 0, e) + struct.pack(e + 'IIIIII', 1, 2, 3, 15, 0, 0) + cred(e, 2), e=e))
        g(l4(kif(14 | big, 0, e) + struct.pack(e + 'I', 0x55), e=e))                             # disconnect
        g(l4(pulse(e, False), e=e))
        g(l4(pulse(e, True), e=e))
    g(l4(kif(17, 0) + b'\0' * 8))                                                             # connect pulse (no decoder)
    g(l4(kif(100, 0) + b'\0' * 8))                                                            # unknown KIF type
    # ---------------- MsgSend with every IO message ----------------
    for e in '<>':
        def S(msg, **kw): g(l4(msgsend(msg, e=e, **kw), e=e))
        S(io(0x116, e=e))                                                                     # close
        S(io(0x104, struct.pack(e + 'I', 0), e=e))                                            # stat
        S(io(0x119, struct.pack(e + 'I', 7), e=e))                                            # sync (flags)
        S(io(0x111, e=e))                                                                     # shutdown
        S(io(0x106, struct.pack(e + 'III', 0x0802, 4, 0), e=e, extra=b'devdata!'))            # devctl (dcmd with a name)
        S(io(0x106, struct.pack(e + 'III', 0x0201, 4, 0), e=e))
        S(io(0x106, struct.pack(e + 'III', 0x7fff, 4, 0), e=e))                               # unknown dcmd
        S(io(0x101, struct.pack(e + 'III', 4096, 0, 0), e=e))                                 # read, no xtype
        S(io(0x101, struct.pack(e + 'III', 4096, 0x105, 0) + struct.pack(e + 'Q', 0x1000), e=e))   # read, XTYPE_OFFSET
        S(io(0x101, struct.pack(e + 'III', 4096, 0x101, 0) + struct.pack(e + 'III', 1, 2, 3), e=e, extra=b'xx'))  # READCOND
        S(io(0x102, struct.pack(e + 'III', 4, 0, 0), e=e, extra=b'', nxt=None) + b'DATA')     # write, data
        S(io(0x102, struct.pack(e + 'III', 4, 0x105, 0) + struct.pack(e + 'Q', 0x2000), e=e, extra=b'ex') + b'wdata')
        S(io(0x102, struct.pack(e + 'III', 4, 0x101, 0) + struct.pack(e + 'III', 1, 2, 3), e=e))
        S(io(0x108, struct.pack(e + 'HH', 5, 0), e=e))                                        # pathconf
        S(io(0x109, struct.pack(e + 'HHQ', 1, 0, 0x123456789), e=e))                          # lseek
        S(io(0x10a, struct.pack(e + 'I', 0o104755), e=e))                                      # chmod
        S(io(0x10b, struct.pack(e + 'II', 100, 200), e=e))                                     # chown
        S(io(0x10c, struct.pack(e + 'III', 1, 1700000000, 1700000100), e=e))                   # utime
        S(io(0x10e, struct.pack(e + 'III', 3, 12, 0), e=e, extra=b'/some/path\0\0'))           # fdinfo
        S(io(0x10f, struct.pack(e + 'II', 1, 100), e=e))                                       # lock
        S(io(0x110, struct.pack(e + 'HHQQ', 1, 0, 0, 4096), e=e))                              # space
        S(io(0x113, struct.pack(e + 'HH', 5, 6), e=e, extra=b'iomsg'))                         # io_msg
        S(io(0x115, msginfo(e) + struct.pack(e + 'II', 0, 0x99), e=e))                         # dup
        S(io(0x10d, struct.pack(e + 'IHH', 0x20042, 1, 2) + msginfo(e) + struct.pack(e + 'II', 0, 5), e=e))  # openfd
        S(io(0x112, struct.pack(e + 'I', 7) + struct.pack(e + 'Q', 0x4000) + msginfo(e) + bytes(24), e=e))  # mmap
        S(io(0x103, b'\0\0\0\0', e=e))                                                         # reserved type: unknown
        # notify: 0 and 2 fds
        for nfds in (0, 2):
            body = struct.pack(e + 'II', nfds, 3) + struct.pack(e + 'IIII', 1, 2, 3, 4) + struct.pack(e + 'Q', 0x55) + \
                struct.pack(e + 'IIIII', 0, 0, nfds, 3, 1) + struct.pack(e + 'Q', 2500000000 if nfds else 500)
            body = struct.pack(e + 'II', 1, 0x30000000) + struct.pack(e + 'IIII', 1, 2, 3, 4) + struct.pack(e + 'Q', 0x55) + \
                struct.pack(e + 'IIIII', 0, 0, nfds, 3, 1) + struct.pack(e + 'Q', (2500000000 if nfds else 500))
            for i in range(nfds):
                body += struct.pack(e + 'IHH', 5 + i, 7 if i else 1, 4 if i else 0)
            S(io(0x105, body, e=e))
        # timeout zero
        body = struct.pack(e + 'II', 2, 0) + struct.pack(e + 'IIII', 1, 2, 3, 4) + struct.pack(e + 'Q', 1) + \
            struct.pack(e + 'IIIII', 0, 0, 0, 3, 1) + struct.pack(e + 'Q', 0)
        S(io(0x105, body, e=e))
        # connect messages
        S(io_connect(2, e=e))                                                                  # open, no extra
        S(io_connect(2, path=b'/net/node1/dev/x\0', e=e, extra_type=1, extra=b'\0\0\0\7', ))   # link, 4 octet ocb
        S(io_connect(7, e=e, extra_type=1, extra=b'\0\0\0\7\1\2'))                             # link with extra_len 6 (fixed: MIN(6, 4))
        S(io_connect(2, e=e, extra_type=1, extra=b'\1\2'))                                     # link, extra_len 2
        S(io_connect(3, e=e, extra_type=2, extra=b'/target/path\0'))                           # symlink path
        S(io_connect(4, e=e, extra_type=9, extra=b'/new/name\0'))                              # rename path
        S(io_connect(9, e=e, extra_type=10, extra=b'mountdata'))                               # mount
        S(io_connect(9, e=e, extra_type=11, extra=b'mountocb'))                                # mount ocb
        S(io_connect(5, e=e, extra_type=0, extra=b'\1\2\3\4\5\6\7\x08\x09'))                   # none: data
        S(io_connect(5, e=e, extra_type=7, extra=b'\1\2\3\4\5\6'))                             # other type: data
        S(io_connect(2, path=b'', e=e))                                                        # empty path
        S(io_connect(2, path=b'/x\0', e=e, pathlen=200))                                       # path length past the end
        S(io_connect(7, path=b'/x\0', e=e, extra_type=1, extra=b'\0\0\0\7', extralen=500))     # extra length past the end
        # combined: connect with the combined message
        S(io_connect(0, e=e, extra_type=0, extra=io(0x101, struct.pack(e + 'III', 8, 0, 0), e=e)))   # COMBINE with read
        S(io_connect(1, e=e, extra_type=0, extra=io(0x116, e=e)))                                    # COMBINE_CLOSE with close
        S(io_connect(0, e=e, extra_type=0, extra=b'\1\2'))                                           # extra too short to combine
        # combined chains
        S(io(0x101, struct.pack(e + 'III', 8, 0, 0), e=e, nxt=io(0x116, e=e)))
        S(io(0x106, struct.pack(e + 'III', 0x0802, 4, 0), e=e, nxt=io(0x104, struct.pack(e + 'I', 0), e=e, nxt=io(0x116, e=e))))
        parts = [(0x102, struct.pack(e + 'III', 8, 0, 0)), (0x109, struct.pack(e + 'HHQ', 0, 0, 0)),
                 (0x108, struct.pack(e + 'HH', 1, 0)), (0x10a, struct.pack(e + 'I', 0o644)),
                 (0x10e, struct.pack(e + 'III', 0, 0, 0)), (0x10f, struct.pack(e + 'II', 0, 0)),
                 (0x110, struct.pack(e + 'HHQQ', 0, 0, 0, 0)), (0x10b, struct.pack(e + 'II', 1, 2)),
                 (0x10c, struct.pack(e + 'III', 0, 1, 2)), (0x119, struct.pack(e + 'I', 1)), (0x111, b''),
                 (0x10d, struct.pack(e + 'IHH', 0, 0, 0) + msginfo(e) + bytes(8)),
                 (0x112, struct.pack(e + 'I', 1) + bytes(8) + msginfo(e) + bytes(24)),
                 (0x113, struct.pack(e + 'HH', 1, 1)), (0x115, msginfo(e) + bytes(8)),
                 (0x105, struct.pack(e + 'II', 0, 0) + struct.pack(e + 'IIII', 0, 0, 0, 0) + bytes(8) + bytes(20) + bytes(8))]
        chain = None
        for t_, b_ in reversed(parts):                  # 16 messages: the nesting limit
            chain = io(t_, b_, e=e, nxt=chain)
        S(chain)
        S(io(0x116, e=e, cl=4 + 50, extra=b'abc'))                                              # extra length past the end
        S(io_connect(2, path=b'ab\0', e=e, extra_type=0, extra=b'xy', extralen=2, nopad=True)) # padding longer than the rest
        S(io(0x105, struct.pack(e + 'II', 0, 0) + struct.pack(e + 'IIII', 0, 0, 0, 0) + bytes(8) + bytes(20) + bytes(8), e=e,
             nxt=io(0x116, e=e)))                                                              # notify combined with close
        S(io(0x116, e=e, extra=b'cl'))                                                          # close with extra data
        S(io(0x116, e=e), cr=True)                                                              # msgsend with credentials
        S(io(0x116, e=e), coid=0x40000005)                                                      # side channel connection id
        S(io(0x116, e=e), coid=0x40000000)                                                      # the system manager's
    # connect msgsend
    for e in '<>':
        g(l4(connect_msgsend(io(0x116, e=e), e=e), e=e))
        g(l4(connect_msgsend(io(0x104, struct.pack(e + 'I', 0), e=e), e=e, cr=True), e=e))
        g(l4(connect_msgsend(io(0x116, e=e), e=e, cr=True, icr=True), e=e))
    # ---------------- reproducers ----------------
    # F1 (recursion): chains of combined _IO_CLOSE messages, 15, 16 and 20 levels, in both endians
    for e in '<>':
        for n in (15, 16, 20):
            chain = struct.pack(e + 'HH', 0x116, 0x8004) * (n - 1) + struct.pack(e + 'HH', 0x116, 0x0004)
            g(l4(msgsend(chain, e=e), e=e))
    # small fix: link ocb length is MIN(extra_len, 4); extra_len of 5..8 used to raise an exception
    g(l4(msgsend(io_connect(2, path=b'/net/x\0', extra_type=1, extra=b'\0\0\0\7\1\2\3\4'), e='<'), e='<'))
    g(l4(msgsend(io_connect(2, path=b'/net/x\0', extra_type=1, extra=b'\0\0\7', e='>'), e='>'), e='>'))
    # IPv4 protocol 106 carrying KIF
    g(l4(kif(14) + b'\0\0\0\0'), 'ip')
    g(l4(msgsend(io(0x116)), crc='good'), 'ip')
    # ---------------- malformed capture ----------------
    m = io(0x116)
    bad(l4(kif(0) + b'\0' * 8))                                                                # connect too short
    bad(l4(kif(0x100) + struct.pack('<IIIII', 5, 1, 5, 3, 4) + cred(ngroups=0)[:20]))        # truncated credentials
    bad(l4(kif(0x100) + struct.pack('<IIIII', 5, 1, 5, 3, 4) + cred(ngroups=12)))            # ngroups > 8
    bad(l4(kif(0x100) + struct.pack('<IIIII', 5, 1, 5, 3, 4) + cred(ngroups=5, groups=[1])))  # groups cut short
    bad(l4(kif(1 | 0x100) + struct.pack('<IIIII', 5, 1, 2, 3, 4) + cred(ngroups=12)))        # connect msgsend: bad credentials
    bad(l4(kif(2 | 0x100) + struct.pack('<IIIII', 5, 1, 2, 3, 4) + cred(ngroups=12)))        # connect success: bad credentials
    bad(l4(msgsend(m, cr=False)[:0] + kif(5 | 0x100) + vinfo() + struct.pack('<I', 4) + m + cred(ngroups=12)))  # msgsend: bad credentials
    bad(l4(kif(11)))                                                                           # event without client handle
    bad(l4(kif(1) + b'\0' * 12))                                                               # connect msgsend short
    bad(l4(kif(1) + struct.pack('<IIIII', 5, 1, 2, 3, 4)))                                     # nothing after the connect
    bad(l4(kif(1) + struct.pack('<IIIII', 5, 1, 2, 3, 4) + kif(5) + b'\0' * 12))               # msgsend part too short
    bad(l4(kif(2) + b'\0' * 8))
    bad(l4(kif(3) + b'\0' * 4))
    bad(l4(kif(15)))
    bad(l4(kif(14)))
    bad(l4(kif(4) + b'\0' * 4))
    bad(l4(kif(5) + b'\0' * 20))
    bad(l4(kif(12) + vinfo() + b'\0' * 8))                                                     # pulse short
    bad(l4(kif(6) + b'\0' * 8))
    bad(l4(kif(8) + b'\0' * 8))
    bad(l4(kif(11) + b'\0' * 8))
    bad(l4(kif(11) + b'\0' * 4))
    bad(l4(kif(13) + b'\0' * 12))
    bad(l4(kif(13 | 0x100) + struct.pack('<IIIIII', 1, 2, 3, 4, 5, 6) + cred()[:10]))
    bad(l4(msgsend(m, nbytes=1000)))
    bad(l4(msgsend(b'\x16\x01')))                                                              # close without combine_len
    bad(l4(msgsend(b'\x00\x01\x00')))                                                          # connect without subtype
    bad(l4(msgsend(struct.pack('<HH', 0x100, 2) + b'\0' * 10)))                                # connect: header short
    bad(l4(msgsend(io(0x105, b'\0' * 20))))                                                    # notify short
    bad(l4(msgsend(io(0x105, struct.pack('<II', 1, 0) + struct.pack('<IIII', 1, 2, 3, 4) + struct.pack('<Q', 1) +
                      struct.pack('<IIIII', 0, 0, 100, 3, 1) + struct.pack('<Q', 0)))))        # nfds past the end
    for t, n in ((0x101, 4), (0x102, 4), (0x104, 2), (0x106, 8), (0x108, 2), (0x109, 6), (0x10a, 2), (0x10b, 4),
                 (0x10c, 6), (0x10d, 20), (0x10e, 4), (0x10f, 4), (0x110, 10), (0x112, 20), (0x113, 2),
                 (0x115, 20), (0x119, 2)):
        bad(l4(msgsend(struct.pack('<HH', t, 4) + b'\0' * n)))                                 # every IO message cut short
    bad(l4(msgsend(io(0x10e, struct.pack('<III', 0, 0, 0))[:8])))                              # fdinfo: left below 14
    bad(l4(msgsend(struct.pack('<HH', 0x101, 0x8010) + struct.pack('<III', 1, 0, 0))))         # combine flag, nothing follows
    bad(l4(msgsend(struct.pack('<HH', 0x101, 0x8010) + struct.pack('<III', 1, 5, 0))))
    bad(l4(msgsend(struct.pack('<HH', 0x101, 0x8010) + struct.pack('<III', 1, 5, 0) + b'\x16')))
    bad(l4(struct.pack('<HHHH', 0, 8, 16, 24) + b'abc', typ=1))
    bad(l4(struct.pack('<HHHH', 0, 8, 16, 24) + b'a\0b\0c\0d\0e', typ=1))                 # name without a terminator to the end                                # tcs init: no terminator
    bad(l4(struct.pack('<HHHH', 0, 1, 2, 3), typ=1))                                           # tcs init: no strings
    bad(l4(b'\0\0\0', typ=1))                                                                  # tcs init: short
    bad(l4(bytes([2]), layer=1))                                                               # remote request cut short
    bad(l4(bytes([3]), layer=1))
    bad(l4(bytes([4, 0, 1]), layer=1))
    bad(l4(bytes([2, 3]) + b'\1', layer=1))
    bad(l4(b'\1\0\1\0\x40\0\0\0' + bytes(40), layer=2, plen=56))                               # LR cut short
    # LR: an address pair at the very end (the family octet is past the end)
    z = bytes([1, 0, 1, 0]) + struct.pack('<I', 56 + 8) + struct.pack('<IIIIIIIIIIII', 0, 4, 0, 4, 8, 8, 0, 4, 0, 4, 8, 8) + b'name'
    bad(l4(z, layer=2))
    bad(l4(kif(14)[:3], plen=3))                                                               # KIF header cut short
    bad(l4(msgsend(io(0x116)), crc='good')[:60])                                               # frame cut inside the vinfo
    return G, B

def main(out):
    os.makedirs(out, exist_ok=True)
    G, B = build_all()
    def frames(lst):
        r = []
        for k, (how, fr) in enumerate(lst):
            r.append(eth_frame(fr) if how == 'eth' else ip_frame(fr, k))
        return r
    write_pcap(os.path.join(out, 'qnet6-coverage.pcap'), frames(G))
    write_pcap(os.path.join(out, 'qnet6-coverage-malformed.pcap'), frames(B))
    print(len(G), len(B))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
