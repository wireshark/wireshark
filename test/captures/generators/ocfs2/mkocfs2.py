#!/usr/bin/env python3
# Generates test/captures/ocfs2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OCFS2 (o2net / o2dlm) coverage captures.  Usage: mkocfs2.py <outdir>
Writes ocfs2-coverage.pcap (valid traffic on TCP 7777; the dissector has no
default port, tshark needs -d tcp.port==7777,ocfs2) and
ocfs2-coverage-malformed.pcap (paths only malformed input reaches).
Everything is synthetic."""
import struct
import sys
import os

def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_ip(proto, payload, src, dst):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 1, 0, 64, proto, 0, s, d)
    ip = ip[:10] + struct.pack('!H', ip_csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + payload

class Cap:
    def __init__(self): self.pkts = []
    def add(self, p): self.pkts.append(p)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)

C, S = '192.0.2.1', '192.0.2.2'

class Tcp:
    def __init__(self, cap, cport, sport):
        self.cap, self.cp, self.sp = cap, cport, sport
        self.cseq, self.sseq = 1000, 5000
    def seg(self, fromclient, data, flags=0x18):
        if fromclient:
            sp, dp, seq, ack, a, b = self.cp, self.sp, self.cseq, self.sseq, C, S
        else:
            sp, dp, seq, ack, a, b = self.sp, self.cp, self.sseq, self.cseq, S, C
        if flags == 0x02: ack = 0
        h = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        self.cap.add(eth_ip(6, h + data, a, b))
        n = len(data) + (1 if flags & 3 else 0)
        if fromclient: self.cseq += n
        else: self.sseq += n
    def handshake(self):
        self.seg(True, b'', 0x02); self.seg(False, b'', 0x12); self.seg(True, b'', 0x10)
    def c(self, d): self.seg(True, d)
    def s(self, d): self.seg(False, d)

u8 = lambda v: struct.pack('!B', v)
u16 = lambda v: struct.pack('!H', v)
u32 = lambda v: struct.pack('!I', v)
u64 = lambda v: struct.pack('!Q', v)

MAGIC, STATUS, KEEPREQ, KEEPRESP = 0xfa55, 0xfa56, 0xfa57, 0xfa58
DLM_KEY = 0x666c6172
M = dict(master_request=500, unused1=501, assert_master=502, create_lock=503,
         convert_lock=504, proxy_ast=505, unlock_lock=506, deref_lockres=507,
         migrate_request=508, mig_lockres=509, query_join=510, assert_joined=511,
         cancel_join=512, exit_domain=513, master_requery=514, lock_request=515,
         reco_data_done=516, begin_reco=517, finalize_reco=518, query_region=519,
         query_nodeinfo=520)

def msg(mtype, payload=b'', magic=MAGIC, num=1, key=DLM_KEY, status=0, sys_status=0, pad=0, dlen=None):
    return (u16(magic) + u16(len(payload) if dlen is None else dlen) + u16(mtype) + u16(pad) +
            u32(sys_status) + u32(status) + u32(key) + u32(num) + payload)

def name(s, n=None):                          # fixed 64 octet lock name buffer
    return s.ljust(n or 64, b'\0')
def lockname(kind, ino=0x1234, gen=0x5678):
    # "M00000000000000000000XXXXXXXX" style name; 'N' (dentry) locks carry the
    # inode in octets 18-25 (read as a 64 bit big endian number)
    if kind == b'N':
        return b'N' + b'0' * 17 + u64(ino) + b'\0' * 6
    return kind + b'%016x%08x' % (ino, gen) + b'\0' * 6
cookie = lambda node, seq: u64((node << 56) | seq)

FLAGS_PUT_LVB, FLAGS_GET_LVB = 0x20000000, 0x40000000
ALLFLAGS = 0x1fffffff | 0x20000000 | 0x40000000 | 0x80000000
lvb = lambda b=0x30: bytes((b + i) & 0xff for i in range(64))

def master(node, nm, flags):
    return u8(node) + u8(len(nm)) + u16(0) + u32(flags) + nm
def create(ck, flags, node, rtype, nm):
    return ck + u32(flags) + u8(0) + u8(node) + u8(rtype) + u8(len(nm)) + name(nm)
def migrate_lockres(master_, nm, locks, flags, total):
    if not locks:
        return u8(master_) + u8(len(nm)) + u8(0)
    b = u8(master_) + u8(len(nm)) + u8(len(locks)) + u8(flags) + u32(total) + cookie(3, 99) + name(nm, 32)
    b += lvb()[:24] + lvb(0x50)[:24] + lvb(0x70)[:16]
    for ck, lst, fl, ty, cv, hb, nd in locks:
        b += ck + u8(0) + u8(lst) + u8(fl) + u8(ty) + u8(cv) + u8(hb) + u8(nd)
    return b

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    cap = Cap()
    t = Tcp(cap, 49701, 7777)
    t.handshake()
    nm = lockname(b'M'); nmN = lockname(b'N'); nmW = lockname(b'W')
    seq = [0]
    def n(): seq[0] += 1; return seq[0]
    # keep-alives and a response (status magic): the payload of those goes to the data dissector
    t.c(msg(0, magic=KEEPREQ, num=n()))
    t.s(msg(0, magic=KEEPRESP, num=n()))
    t.c(msg(M['master_request'], master(1, nm, 0), num=n(), pad=0x0a0b))
    t.s(msg(0, b'\x00\x00\x00\x00', magic=STATUS, num=n(), status=0))
    t.c(msg(M['master_request'], master(1, nmN, 0), num=n()))              # dentry lock name
    t.c(msg(M['assert_master'], master(2, nm, 0x1), num=n()))
    t.c(msg(M['assert_master'], master(2, nmW, 0x6), num=n()))
    t.c(msg(M['create_lock'], create(cookie(1, 7), 0x0200000, 1, 5, nm), num=n()))
    t.c(msg(M['create_lock'], create(cookie(2, 8), ALLFLAGS & ~FLAGS_PUT_LVB, 2, 3, nmN), num=n()))
    t.c(msg(M['convert_lock'], create(cookie(1, 9), 0x0, 1, 3, nm), num=n()))
    t.c(msg(M['convert_lock'], create(cookie(1, 10), FLAGS_PUT_LVB, 1, 5, nm) + lvb(), num=n()))
    t.c(msg(M['proxy_ast'], cookie(1, 11) + u32(0) + u8(1) + u8(0) + u8(3) + u8(len(nm)) + name(nm), num=n()))
    t.c(msg(M['proxy_ast'], cookie(1, 12) + u32(FLAGS_GET_LVB) + u8(1) + u8(1) + u8(5) + u8(len(nm)) + name(nm) + lvb(), num=n()))
    t.c(msg(M['proxy_ast'], cookie(1, 13) + u32(0) + u8(1) + u8(2) + u8(5) + u8(len(nmN)) + name(nmN), num=n()))
    t.c(msg(M['unlock_lock'], cookie(1, 14) + u32(0) + u16(0) + u8(1) + u8(len(nm)) + name(nm), num=n()))
    t.c(msg(M['unlock_lock'], cookie(1, 15) + u32(FLAGS_PUT_LVB) + u16(0) + u8(1) + u8(len(nm)) + name(nm) + lvb(), num=n()))
    t.c(msg(M['deref_lockres'], u32(0) + u16(0) + u8(1) + u8(len(nm)) + nm, num=n()))
    t.c(msg(M['migrate_request'], u8(1) + u8(2) + u8(len(nm)) + u8(0) + u32(0) + nm, num=n()))
    # migrate lockres: no locks, and two locks
    t.c(msg(M['mig_lockres'], migrate_lockres(1, nm, [], 0, 0), num=n()))
    locks = [(cookie(1, 20), 0, 1, 3, 3, 5, 1), (cookie(2, 21), 1, 2, 5, 5, 0, 2)]
    t.c(msg(M['mig_lockres'], migrate_lockres(1, nm, locks, 0x7, 2), num=n()))
    t.c(msg(M['mig_lockres'], migrate_lockres(1, nm, locks[:1], 0x1, 1), num=n()))
    # query join: current and old (100 octet) layouts
    dom = name(b'mydomain', 64)
    t.c(msg(M['query_join'], u8(1) + u16(0) + u8(8) + u16(0x0101) + u16(0x0100) + dom + bytes([0x05] + [0xff] * 3 + [0] * 28), num=n()))
    t.c(msg(M['query_join'], u8(2) + u16(0) + u8(8) + dom + bytes([0x01] + [0] * 31), num=n()))
    t.c(msg(M['assert_joined'], u8(1) + u16(0) + u8(8) + dom, num=n()))
    t.c(msg(M['cancel_join'], u8(1) + u16(0) + u8(8) + dom, num=n()))
    t.c(msg(M['exit_domain'], u8(1), num=n()))
    t.c(msg(M['master_requery'], u16(0) + u8(1) + u8(len(nm)) + u32(0) + nm, num=n()))
    t.c(msg(M['lock_request'], u8(1) + u8(3) + u16(0) + u32(0), num=n()))
    t.c(msg(M['begin_reco'], u8(1) + u8(3) + u16(0) + u32(0), num=n()))
    t.c(msg(M['reco_data_done'], u8(1) + u8(3) + u16(0) + u32(0) + lvb(), num=n()))
    t.c(msg(M['finalize_reco'], u8(1) + u8(3) + u8(1) + u8(0) + u32(0), num=n()))
    # query region (two regions) and node info (two nodes)
    t.c(msg(M['query_region'], u8(1) + u8(2) + u8(8) + u8(0) + dom + name(b'region-a', 32) + name(b'region-b', 32), num=n()))
    t.c(msg(M['query_nodeinfo'], u8(1) + u8(2) + u8(8) + dom +
            u8(1) + u8(0) + u16(7777) + bytes([192, 0, 2, 1]) + u8(2) + u8(0) + u16(7777) + bytes([192, 0, 2, 2]), num=n()))
    # unknown / unused message types and an unknown payload
    t.c(msg(M['unused1'], b'\x01\x02\x03\x04', num=n()))
    t.c(msg(499, b'abcd', num=n()))
    t.c(msg(1000, b'', num=n()))
    # several PDUs in one segment, and a PDU split over two segments
    t.c(msg(M['exit_domain'], u8(3), num=n()) + msg(M['exit_domain'], u8(4), num=n()) +
        msg(0, magic=KEEPREQ, num=n()))
    big = msg(M['query_region'], u8(1) + u8(3) + u8(8) + u8(0) + dom + b''.join(name(b'r%d' % i, 32) for i in range(3)), num=n())
    t.c(big[:40]); t.c(big[40:])
    # responses from the server
    t.s(msg(0, b'\x00\x00\x00\x00', magic=STATUS, num=n(), status=0xfffffffb))
    t.s(msg(M['master_request'], master(2, nm, 0), num=n(), sys_status=5, status=2))
    cap.write(os.path.join(outdir, 'ocfs2-coverage.pcap'))

    # ------------------------------------------------ malformed
    m = Cap()
    t = Tcp(m, 49702, 7777)
    t.handshake()
    # wrong magic (dissect_ocfs2 returns 0)
    t.c(b'\x12\x34' + msg(500, b'')[2:])
    t.c(b'\xfa')                                  # one octet: no magic yet
    # truncated PDU header (needs 24 octets) and truncated bodies
    t.c(msg(M['create_lock'], create(cookie(1, 7), 0, 1, 5, nm))[:60])
    t.c(msg(M['master_request'], b'\x01'))
    t.c(msg(M['master_request'], master(1, nmN[:20], 0)))               # 'N' name shorter than 26
    t.c(msg(M['query_join'], u8(1) + u16(0) + u8(8) + u16(0x0101) + u16(0x0100) + dom))   # node map cut
    t.c(msg(M['mig_lockres'], migrate_lockres(1, nm, [(cookie(1, 20), 0, 1, 3, 3, 5, 1)] * 3, 0x7, 2)[:130]))
    t.c(msg(M['query_region'], u8(1) + u8(200) + u8(8) + u8(0) + dom + name(b'r', 32)))   # 200 regions announced
    t.c(msg(M['query_nodeinfo'], u8(1) + u8(200) + u8(8) + dom + b'\x01\x00\x1e\x61\xc0\x00\x02\x01'))
    t.c(msg(M['mig_lockres'], u8(1) + u8(8) + u8(255) + b'\x00' * 20))
    # length field larger than the data (the PDU never completes) and smaller than the header fields
    t.c(msg(M['exit_domain'], u8(1), dlen=1000))
    m.write(os.path.join(outdir, 'ocfs2-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
