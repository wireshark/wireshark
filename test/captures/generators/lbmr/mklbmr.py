#!/usr/bin/env python3
# Generates test/captures/lbmr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LBMR (LBM topic resolution) coverage captures.
Usage: mklbmr.py <outdir>

lbmr-coverage.pcap            main capture (default preferences)
lbmr-coverage-malformed.pcap  malformed messages, the reproducers, and frames that
                              only the tag table or changed preferences reach
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from common import pcap, udp, ip4, eth

CTX = bytes(range(0x11, 0x19))              # 8 byte context instance / source id
OTID = bytes(range(0x40, 0x60))             # 32 byte originating transport id


def ipb(a):
    return socket.inet_aton(a)


def frame(payload, src='10.0.0.1', dst='224.9.10.11', sport=12965, dport=12965):
    mc = int(dst.split('.')[0]) >= 224
    dmac = bytes.fromhex('01005e090a0b') if mc else bytes.fromhex('020000000002')
    return eth(dmac, bytes.fromhex('020000000001'), 0x0800, ip4(src, dst, 17, udp(sport, dport, payload)))


def frame6(payload, src='2001:db8::1', dst='2001:db8::2', sport=12965, dport=12965):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0x1234) + payload
    ip = struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + socket.inet_pton(socket.AF_INET6, src) + \
        socket.inet_pton(socket.AF_INET6, dst)
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x86dd, ip + u)


def uc(payload, src='10.0.0.1', dst='10.0.0.2', sport=14402, dport=15380):
    """Unicast topic resolution (the default ports)."""
    return frame(payload, src, dst, sport, dport)


def hdr(typ, tqrs, tirs, ver=0, opts=False):
    return struct.pack('>BBH', (ver << 4) | typ | (8 if opts else 0), tqrs, tirs)


def tqr(name):
    return name.encode() + b'\0'


def wctqr(ptype, pat):
    return bytes([ptype]) + pat.encode() + b'\0'


def tir(name, transport, idx, tdata, opts=b'', ttl=16, tlen=None):
    if tlen is None:
        tlen = len(tdata)
    t = transport | (0x80 if opts else 0)
    return name.encode() + b'\0' + struct.pack('>BBHI', t, tlen, ttl, idx) + opts + tdata


# ---- TIR options ----
def opt_block(opts, total=None):
    body = b''.join(opts)
    if total is None:
        total = 4 + len(body)
    return struct.pack('>BBH', 0, 4, total) + body


def o2(typ, body, flags=0x8000, length=None):
    """option with a 16 bit flags field"""
    return struct.pack('>BBH', typ, length if length is not None else 4 + len(body), flags) + body


def o1(typ, body, flags=0x80, idx=0, length=None):
    """option with 8 bit flags and one more byte"""
    return struct.pack('>BBBB', typ, length if length is not None else 4 + len(body), flags, idx) + body


ALL_TOPT = [
    o2(0x01, struct.pack('>HHIIIIII', 5000, 5001, 0x0a000001, 0x0a000002, 0x11111111, 7, 0x100, 0x1)
       , flags=0xf800),                                              # UME, all flags
    o1(0x02, struct.pack('>HHII', 5002, 3, 0x0a000003, 0x22222222), flags=0x80, idx=2),   # UME store
    o1(0x03, struct.pack('>HH', 4, 0), flags=0x80, idx=1),           # UME store group
    o2(0x04, struct.pack('>HHIIII', 5003, 0, 0x0a000004, 9, 0x200, 0x2), flags=0xc000),  # latejoin
    o2(0x05, struct.pack('>I', 77), flags=0x8000),                   # UMQ rcridx
    o2(0x06, b'queue/name\0', flags=0xfc00),                         # UMQ qinfo
    o1(0x07, struct.pack('>I', 1234), flags=0x80, idx=3),            # cost (hop count 3)
    o2(0x08, OTID, flags=0x8000),                                    # originating transport id
    o1(0x09, CTX, flags=0x80, idx=0),                                # ctxinst
    o1(0x0a, CTX, flags=0x80, idx=1),                                # ctxinsts
    o2(0x0b, struct.pack('>I8sIIHH', 55, bytes(range(1, 9)), 66, 0x0a000005, 5004, 0), flags=0x8000),  # ULB
    o1(0x0c, CTX, flags=0x80, idx=2),                                # ctxinstq
    o2(0x0d, struct.pack('>I', 99), flags=0x8000),                   # domain id
    o2(0x0e, struct.pack('>HHII', 5005, 0, 0x0a000006, 0xf), flags=0x8000),     # extended functionality
    o2(0x7f, b'\xde\xad\xbe\xef', flags=0),                          # unknown option
]


# ---- TIR transports ----
def t_tcp(ip, port):
    return ipb(ip) + struct.pack('>H', port)


def t_tcp_sid(ip, port, sid):
    return ipb(ip) + struct.pack('>IH', sid, port)


def t_lbtrm(src, mc, sid, dport, uport):
    return ipb(src) + ipb(mc) + struct.pack('>IHH', sid, dport, uport)


def t_ipc(host, sid, xport):
    return struct.pack('>IIH', host, sid, xport)


def t_rdma(ip, sid, port):
    return ipb(ip) + struct.pack('>IH', sid, port)


TCP, LBTRU, TCP6, SMX, LBTRM, RDMA, IPC = 0x00, 0x01, 0x02, 0x04, 0x10, 0x20, 0x40


def build_main():
    fr = []
    A = fr.append

    # ---- keepalives, alive messages and plain queries ----
    A(frame(hdr(0, 0, 0)))                                     # unicast resolver keepalive (multicast)
    A(uc(hdr(0, 0, 0), sport=14403))
    A(uc(hdr(2, 0, 0), sport=14404))                           # receiver alive
    A(uc(hdr(3, 0, 0), src='10.0.0.2', dst='10.0.0.1', sport=15380, dport=14402))   # source alive
    A(uc(hdr(2, 1, 0) + tqr('rcv/alive/topic'), sport=14405))  # alive type with a TQR: not a keepalive
    A(uc(hdr(0, 0, 0), sport=14406))
    A(frame(hdr(0, 1, 0) + tqr('topic/one')))
    A(frame(hdr(0, 3, 0) + tqr('topic/two') + tqr('topic/three') + tqr('topic/four'), src='10.0.0.3'))
    # wildcard queries: pattern types
    A(frame(hdr(1, 1, 0) + wctqr(1, 'topic/.*')))
    A(frame(hdr(1, 2, 0) + wctqr(2, 'orders\\..*') + wctqr(0, 'x*'), src='10.0.0.3'))

    # ---- advertisements, all transports ----
    A(frame(hdr(0, 0, 1) + tir('topic/tcp', TCP, 100, t_tcp('10.0.0.1', 4000))))
    A(frame(hdr(0, 0, 1) + tir('topic/tcpsid', TCP, 101, t_tcp_sid('10.0.0.1', 4001, 0xaabbccdd))))
    A(frame(hdr(0, 0, 1) + tir('topic/lbtrm', LBTRM, 102, t_lbtrm('10.0.0.1', '224.10.10.10', 0x11223344, 14400, 14390))))
    A(frame(hdr(0, 0, 1) + tir('topic/lbtru', LBTRU, 103, t_tcp('10.0.0.1', 4002))))
    A(frame(hdr(0, 0, 1) + tir('topic/lbtrusid', LBTRU, 104, t_tcp_sid('10.0.0.1', 4003, 0x01020304))))
    A(frame(hdr(0, 0, 1) + tir('topic/ipc', IPC, 105, t_ipc(0x7f000001, 0x55, 9))))
    A(frame(hdr(0, 0, 1) + tir('topic/rdma', RDMA, 106, t_rdma('10.0.0.1', 0x1234abcd, 5000))))
    A(frame(hdr(0, 0, 1) + tir('topic/smx', SMX, 107, t_ipc(0x7f000001, 0x66, 10))))
    A(frame(hdr(0, 0, 1) + tir('topic/tcp6', TCP6, 108, b'\x20\x01' + bytes(14) + struct.pack('>H', 4004))))
    A(frame(hdr(0, 0, 1) + tir('topic/weird', 0x33, 109, b'\x01\x02\x03\x04')))
    # several advertisements in one packet, with a query, from a second source
    A(frame(hdr(0, 1, 3) + tqr('topic/mixed') +
            tir('topic/a', TCP, 110, t_tcp('10.0.0.4', 4005)) +
            tir('topic/b', LBTRM, 111, t_lbtrm('10.0.0.4', '224.10.10.11', 0x55667788, 14401, 14391)) +
            tir('topic/c', LBTRU, 112, t_tcp_sid('10.0.0.4', 4006, 7)), src='10.0.0.4'))
    # advertisement again (same transport, found by the transport tables)
    A(frame(hdr(0, 0, 2) + tir('topic/tcp', TCP, 100, t_tcp('10.0.0.1', 4000)) +
            tir('topic/lbtrm', LBTRM, 102, t_lbtrm('10.0.0.1', '224.10.10.10', 0x11223344, 14400, 14390))))
    A(frame(hdr(0, 0, 2) + tir('topic/ipc', IPC, 105, t_ipc(0x7f000001, 0x55, 9)) +
            tir('topic/rdma', RDMA, 106, t_rdma('10.0.0.1', 0x1234abcd, 5000))))
    A(frame(hdr(0, 0, 1) + tir('topic/smx', SMX, 107, t_ipc(0x7f000001, 0x66, 10))))
    # unicast advertisement
    A(uc(hdr(0, 0, 1) + tir('topic/uc', TCP, 120, t_tcp('10.0.0.1', 4010)), sport=14404))

    # ---- advertisements with every topic option, one packet each and all in one ----
    for i, o in enumerate(ALL_TOPT):
        A(frame(hdr(0, 0, 1) + tir('topic/opt%d' % i, TCP, 200 + i, t_tcp('10.0.0.5', 4100 + i), opts=opt_block([o]))))
    A(frame(hdr(0, 0, 1) + tir('topic/allopts', TCP, 300, t_tcp('10.0.0.5', 4200), opts=opt_block(ALL_TOPT)),
            src='10.0.0.5'))
    # options and an LBT-RM transport, and options with a bigger TTL
    A(frame(hdr(0, 0, 2) +
            tir('topic/o1', LBTRM, 301, t_lbtrm('10.0.0.5', '224.10.10.12', 0x1, 14402, 14392), opts=opt_block(ALL_TOPT[:3]), ttl=0) +
            tir('topic/o2', RDMA, 302, t_rdma('10.0.0.5', 0x2, 5001), opts=opt_block(ALL_TOPT[3:6]), ttl=65535),
            src='10.0.0.5'))

    # ---- topic management ----
    def tmr(typ, flags, name):
        n = name.encode() + b'\0'
        return struct.pack('>HBB', 4 + len(n), typ, flags) + n
    recs = [tmr(1, 0x00, 'topic/use/query'), tmr(1, 0x80, 'topic/use/response'),
            tmr(0, 0x00, 'topic/leave'), tmr(1, 0x40, 'pcre/.*'), tmr(1, 0x20, 'regex/.*'),
            tmr(9, 0x00, 'topic/unknown')]
    body = b''.join(recs)
    A(frame(hdr(4, 0, 0) + struct.pack('>HH', 4 + len(body), len(recs)) + body))

    # ---- queue resolution (type 6) ----
    def qir(q, t, qid, ver, prev, groups, queues, opts=b''):
        gb = len(groups) | (0x8000 if opts else 0)
        s = q.encode() + b'\0' + t.encode() + b'\0' + struct.pack('>IIIHH', qid, ver, prev, gb, len(queues))
        s += opts
        s += b''.join(struct.pack('>HH', i, sz) for i, sz in groups)
        s += b''.join(struct.pack('>IHHHH', ipx, port, idx, g, 0x8000 if i == 0 else 0)
                      for i, (ipx, port, idx, g) in enumerate(queues))
        return s
    A(frame(hdr(6, 2, 0) + tqr('queue/one') + tqr('queue/two')))
    A(frame(hdr(6, 0, 1) + qir('queue/one', 'topic/q', 5, 2, 1, [(0, 2), (1, 3)],
                               [(0x0a000001, 6000, 0, 0), (0x0a000002, 6001, 1, 1)])))
    A(frame(hdr(6, 1, 2) + tqr('queue/three') +
            qir('queue/two', 'topic/q2', 6, 1, 0, [], [(0x0a000003, 6002, 0, 0)]) +
            qir('queue/three', 'topic/q3', 7, 3, 2, [(0, 1)], [], opts=opt_block(ALL_TOPT[:2]))))

    # ---- extended messages ----
    # proxy source election: without and with options
    pser = lambda dep, flags, topic, extra=b'': struct.pack('>BBHHHIIIIHH', 0x07, 1, dep, 28 + len(topic) + 1, flags,
                                                           0x0a000001, 0x0a000002, 5, 6, 4000, 4001) + topic.encode() + b'\0' + extra
    A(frame(pser(0, 0, 'topic/pser')))
    ctxi = lambda t: bytes([10, t]) + CTX
    optlen = lambda n: struct.pack('>HH', 0, 4 + n)
    A(frame(pser(1, 0x8000, 'topic/pser2', optlen(20) + ctxi(0) + ctxi(1))))
    A(frame(pser(0, 0x8000, 'topic/pser3', optlen(10) + ctxi(1))))
    A(frame(pser(0, 0x8000, 'topic/pser4', optlen(2) + b'\x02\x55')))      # unknown PSER option, length 2

    # queue management: every packet type, with and without the queue name
    def qm(ptype, flags, dep16, extra=b'', qname=b''):
        return struct.pack('>BBBB20sIIIHHHH', 0x07, 2, flags, ptype, bytes(range(20)), 9, 3, 0x0a000007, 6100, 1, 0, dep16) + extra + qname
    inst = lambda i: struct.pack('>IHHHH', 0x0a000010 + i, 6200 + i, i, 0, [0, 0x8000, 0x4000, 0x2000][i % 4])
    A(frame(qm(1, 0xf0, 3, struct.pack('>I', 1234) + inst(0) + inst(1) + inst(2), b'queue/il\0')))   # IL, flags I N L K
    A(frame(qm(1, 0x80, 0, struct.pack('>I', 1))))
    A(frame(qm(2, 0x80, 0)))                          # JR
    A(frame(qm(3, 0xc0, 4, qname=b'queue/jrej\0')))     # JREJ with queue name
    A(frame(qm(4, 0x00, 0)))                          # IKA
    A(frame(qm(5, 0x40, 0, struct.pack('>I', 4), b'queue/ec\0')))       # EC
    A(frame(qm(6, 0x00, 7, struct.pack('>II', 100, 200))))              # EV
    A(frame(qm(7, 0x40, 0, qname=b'q\0')))              # CNIL, queue name of 2 bytes
    A(frame(qm(7, 0x40, 0, qname=b'')))                 # CNIL, N flag but no name
    A(frame(qm(8, 0x00, 0, struct.pack('>I', 300))))    # QRO
    A(frame(qm(0x77, 0x00, 5)))                         # unknown packet type

    # context information
    def ctxinfo(flags, name=b'', hop=1):
        ln = 20 + len(name)
        return struct.pack('>BBBBHHI8s', 0x07, 3, ln, hop, flags, 12345, 0x0a000008, CTX) + name
    A(frame(ctxinfo(0xfc00 | 0x0000)))
    A(frame(ctxinfo(0x0001, b'context-name\0')))
    A(frame(ctxinfo(0x8000, hop=9)))

    # topic resolution request: each flag
    for fl in (0x7f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x00):
        A(frame(struct.pack('>BBH', 0x07, 4, fl)))

    # gateway messages
    def tnwg(typ, body, ver=1):
        return struct.pack('>BBHHH', (ver << 4) | 7, 5, 8 + len(body), typ, 0) + body
    def rec(flags, pattype, domain, sym):
        s = sym.encode() + b'\0'
        return struct.pack('>HBBI', 8 + len(s), flags, pattype, domain) + s
    recs = rec(0x00, 0, 1, 'topic/.*') + rec(0xe0, 1, 2, 'pattern') + rec(0x80, 2, 3, 'x') + rec(0x40, 0, 4, 'cancel') + rec(0x20, 0, 5, 'refresh')
    A(frame(tnwg(0, struct.pack('>HH', 4 + len(recs), 5) + recs)))
    A(frame(tnwg(0, struct.pack('>HH', 4, 0))))
    A(frame(tnwg(0, struct.pack('>HH', 12, 1) + struct.pack('>HBBI', 4, 0, 0, 0))))   # record shorter than its header

    def topt(typ, body, flags=0x8000):
        return struct.pack('>BBH', typ, 4 + len(body), flags) + body
    ctxinst_o = topt(0, CTX)
    addr_o = topt(1, struct.pack('>HHI', 4000, 0, 0x0a000001))
    dom_o = topt(2, struct.pack('>I', 77))
    name_o = topt(3, b'gw-name\0')
    unk_o = topt(0x55, b'\xaa\xbb')
    for fl in (0xf0000000, 0x00000000, 0x80000000, 0x40000000, 0x20000000, 0x10000000):
        opts = ctxinst_o + addr_o + dom_o + name_o + unk_o
        info = struct.pack('>HBBII', 12 + len(opts), 2, 0, fl, 0x1234) + opts
        A(frame(tnwg(1, info)))
    info = struct.pack('>HBBII', 12, 0, 0, 0, 0)                    # no options
    A(frame(tnwg(1, info)))
    # the TNWG option loop after "LBMR: Fix TNWG option loop and swapped LBTRDMA
    # arguments": three options, each at the right offset
    opts = ctxinst_o + dom_o + addr_o
    A(frame(tnwg(1, struct.pack('>HBBII', 12 + len(opts), 1, 0, 0x80000000, 0) + opts)))
    opts = name_o + ctxinst_o + ctxinst_o + dom_o
    A(frame(tnwg(2, struct.pack('>H', 2 + len(opts)) + opts)))      # TRREQ with options
    A(frame(tnwg(2, struct.pack('>H', 2))))                         # TRREQ without
    A(frame(tnwg(9, b'\0\0\0\0')))                                  # unknown gateway type

    # remote domain route
    A(frame(struct.pack('>BBHIHHI', 0x17, 6, 3, 0x0a000009, 5555, 2, 12) + struct.pack('>III', 1, 2, 3)))
    A(frame(struct.pack('>BBHIHHI', 0x17, 6, 0, 0x0a000009, 5555, 3, 0)))

    # remote context information
    def rctx_rec(flags, opts):
        return struct.pack('>HH', 4 + len(opts), flags) + opts
    ra = struct.pack('>BBHIIHH', 1, 16, 0, 5, 0x0a00000a, 7777, 0)
    ri = struct.pack('>BBH', 2, 12, 0) + CTX
    ro = struct.pack('>BBHI', 3, 8, 0, 9)
    rn = struct.pack('>BBH', 4, 4 + 5, 0) + b'rctx\0'
    ru = struct.pack('>BBH', 0x77, 6, 0) + b'\x01\x02'
    recs = rctx_rec(0x8000, ra + ri + ro + rn) + rctx_rec(0, ra) + rctx_rec(0, ru)
    A(frame(struct.pack('>BBHHH', 0x17, 7, 8 + len(recs), 3, 0) + recs))
    A(frame(struct.pack('>BBHHH', 0x17, 7, 8, 0, 0)))

    # unknown extended type, unknown normal type
    A(frame(struct.pack('>BBH', 0x07, 0x42, 0) + b'\0\0'))
    A(frame(struct.pack('>BBH', 0x05, 0, 0)))

    # ---- LBMR packet options after the main part ----
    def popt(typ, body, flags=0x8000):
        return struct.pack('>BBH', typ, 4 + len(body), flags) + body
    po = [popt(0x81, CTX, 0xe000),                                  # source id
          struct.pack('>BBBB', 0x82, 4, 0x80, 2),                   # source type: store
          popt(0x83, struct.pack('>I', 0x06020100), 0x8003),        # version
          popt(0x84, struct.pack('>I', 12), 0x8001),                # local domain
          popt(0x90, b'\x01\x02\x03\x04', 0)]                       # unknown option
    body = b''.join(po)
    lenopt = struct.pack('>BBH', 0x80, 4, len(body) + 4)
    A(frame(hdr(0, 1, 0, opts=True) + tqr('topic/opts') + body + lenopt))
    A(frame(hdr(0, 0, 1, opts=True) + tir('topic/opts2', TCP, 400, t_tcp('10.0.0.6', 4300)) + body + lenopt))
    # options without a length option, a single one
    A(frame(hdr(0, 0, 0, opts=True) + po[2]))
    # length option with a total length that does not trim anything
    A(frame(hdr(0, 0, 0, opts=True) + po[3] + struct.pack('>BBH', 0x80, 4, 2000)))
    # extended message with options and the length option
    ext = struct.pack('>BBH', 0x0f, 4, 0x20)
    A(frame(ext + po[0] + struct.pack('>BBH', 0x80, 4, len(po[0]) + 4)))
    A(frame(pser(0, 0x8000, 'topic/pser5', optlen(2) + b'\x00\x55')))      # unknown PSER option, length 0
    return fr


def build_malformed():
    fr = []
    A = fr.append
    # --- the reproducer of "LBMR: Fix TNWG option loop and swapped LBTRDMA arguments":
    # a TNWG context information with an option of length 0 (hung the dissector)
    opt = struct.pack('>BBH', 0x00, 0, 0) + b'\x11' * 8
    ctxinfo = struct.pack('>HBBII', 12 + len(opt), 0, 0, 0, 0) + opt
    A(uc(struct.pack('>BBHHH', 0x07, 0x05, 8 + len(ctxinfo), 0x0001, 0) + ctxinfo, sport=14402))
    # the same with the other option types and a length of 1, 2, 3
    for t in (0, 1, 2, 3, 0x55):
        for ln in (0, 3):
            opt = struct.pack('>BBH', t, ln, 0) + b'\x11' * 8
            ci = struct.pack('>HBBII', 12 + len(opt), 0, 0, 0, 0) + opt
            A(uc(struct.pack('>BBHHH', 0x07, 0x05, 8 + len(ci), 0x0001, 0) + ci, sport=14402))
    # BUG (not fixed, see README): a TNWG interest with 2000 records whose length is 0
    # never advances: dissect_lbmr_tnwg_interest() -> dissect_lbmr_tnwg_interest_rec()
    # returns rec_len (0) and the loop runs rec_count (up to 65535) times at one offset
    A(uc(struct.pack('>BBHHH', 0x17, 0x05, 8 + 4 + 8, 0x0000, 0) + struct.pack('>HH', 12, 2000) +
         struct.pack('>HBBI', 0, 0, 0, 0)))
    # a TRREQ with a zero-length option
    opt = struct.pack('>BBH', 2, 0, 0) + b'\0' * 4
    A(uc(struct.pack('>BBHHH', 0x07, 0x05, 8 + 2 + len(opt), 0x0002, 0) + struct.pack('>H', 2 + len(opt)) + opt))

    # topic management block without records (the record list item starts past the end)
    A(frame(hdr(4, 0, 0) + struct.pack('>HH', 4, 0)))
    # --- zero-length topic option
    A(frame(hdr(0, 0, 1) + tir('topic/zero', TCP, 1, t_tcp('10.0.0.1', 4000), opts=opt_block([struct.pack('>BBH', 5, 0, 0)], total=8))))
    A(frame(hdr(0, 0, 1) + tir('topic/zero2', TCP, 1, t_tcp('10.0.0.1', 4000),
                              opts=opt_block([struct.pack('>BBH', 5, 0, 0) + b'\0' * 8], total=12))))
    # --- wrong transport lengths
    A(frame(hdr(0, 0, 1) + tir('t/tcp', TCP, 1, b'\x01\x02\x03\x04\x05\x06\x07')))
    A(frame(hdr(0, 0, 1) + tir('t/lbtrm', LBTRM, 1, t_lbtrm('10.0.0.1', '224.1.1.1', 1, 2, 3) + b'\0\0', tlen=18)))
    A(frame(hdr(0, 0, 1) + tir('t/lbtru', LBTRU, 1, b'\x01\x02\x03\x04\x05\x06\x07\x08')))
    A(frame(hdr(0, 0, 1) + tir('t/ipc', IPC, 1, b'\0' * 12)))
    A(frame(hdr(0, 0, 1) + tir('t/rdma', RDMA, 1, b'\0' * 8)))
    A(frame(hdr(0, 0, 1) + tir('t/smx', SMX, 1, t_ipc(1, 2, 3) + b'\0\0', tlen=12)))
    # --- topic option that runs past the end, truncated records
    A(frame(hdr(0, 5, 0) + tqr('only-one')))
    A(frame(hdr(0, 0, 3) + tir('t/a', TCP, 1, t_tcp('10.0.0.1', 4000))))
    A(frame(hdr(6, 0, 1) + b'queue\0topic\0' + b'\0' * 8))
    A(frame(hdr(4, 0, 0) + struct.pack('>HH', 4, 3) + struct.pack('>HBB', 4, 1, 0)))
    # truncated extended messages
    for ext in (1, 2, 3, 4, 5, 6, 7):
        A(frame(struct.pack('>BBH', 0x07, ext, 0)))
    A(frame(struct.pack('>BB', 0x07, 5)))
    A(frame(struct.pack('>B', 0x00)))
    # --- frames that only changed preferences or the tag table reach
    # 224.9.20.20:13000 (tag B / preferences), unicast 10.0.0.77 with ports 14410-14412 and 15390
    A(frame(hdr(0, 1, 0) + tqr('tag/multicast'), dst='224.9.20.20', sport=13000, dport=13000))
    A(frame(hdr(0, 1, 0) + tqr('tag/multicast2'), dst='224.9.20.21', sport=13001, dport=13001))
    A(frame(hdr(0, 1, 0) + tqr('tag/wrongport'), dst='224.9.20.20', sport=13000, dport=13001))
    A(frame(hdr(0, 1, 0) + tqr('tag/unicast'), src='10.0.0.77', dst='10.0.0.88', sport=14410, dport=15390))
    A(frame(hdr(0, 1, 0) + tqr('tag/unicast-rev'), src='10.0.0.88', dst='10.0.0.77', sport=15390, dport=14411))
    A(frame(hdr(0, 1, 0) + tqr('tag/unicast-other'), src='10.0.0.5', dst='10.0.0.6', sport=14410, dport=15390))
    A(frame(hdr(0, 1, 0) + tqr('tag/unicast-noport'), src='10.0.0.77', dst='10.0.0.88', sport=14410, dport=15391))
    A(frame(hdr(0, 1, 0) + tqr('default/unicast-other-addr'), src='10.0.0.5', dst='10.0.0.6', sport=14403, dport=15380))
    A(frame(hdr(0, 1, 0) + tqr('default/unicast-bad-ports'), src='10.0.0.5', dst='10.0.0.6', sport=14407, dport=15380))
    A(frame(hdr(0, 1, 0) + tqr('default/multicast-wrong-group'), dst='224.9.10.12'))
    A(frame(hdr(0, 1, 0) + tqr('default/multicast-wrong-port'), dst='224.9.10.11', sport=12965, dport=12966))
    A(frame(hdr(0, 1, 0) + tqr('tag/outgoing-wrong-port'), dst='224.9.20.21', sport=13001, dport=13002))
    # UDP over IPv6: never claimed by the heuristic; with Decode As and the tag table
    # the tag matching sees IPv6 addresses
    A(frame6(hdr(0, 1, 0) + tqr('ipv6/topic')))
    return fr


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'lbmr-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'lbmr-coverage-malformed.pcap'), build_malformed())
