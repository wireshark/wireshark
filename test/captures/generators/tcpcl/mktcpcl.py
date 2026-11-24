#!/usr/bin/env python3
# Generates test/captures/tcpcl_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the TCPCL dissector (packet-tcpcl.c,
DTN TCP Convergence Layer versions 3 and 4, RFC 9174).

Usage: mktcpcl.py <output directory>

Writes:
  tcpcl-coverage.pcapng            TCPCLv4 and TCPCLv3 sessions on TCP port 4556
                                   and on another port through the "dtn!"
                                   heuristic: contact headers, SESS_INIT with
                                   and without extensions, segmented transfers
                                   (with the Transfer Length extension) and acks,
                                   refusals, keepalives, STARTTLS, shutdowns,
                                   sessions without a contact header, a transfer
                                   of more segments than the per-transfer limit
  tcpcl-coverage-malformed.pcapng  duplicate and missing messages, reserved
                                   flags, extension items, truncated messages,
                                   mismatching acks

Every packet is built with struct; addresses are from 192.0.2.0/24. The
bundles in the transfers are small made-up BPv6 bundles; TLS is only the
plain ClientHello that follows a STARTTLS negotiation (nothing is
encrypted or decrypted).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import LT_ETH, pcapng, TcpConn

PORT = 4556


def sdnv(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))


def bundle6(payload=b'hello bundle', src='//a', dst='//b'):
    d = b'dtn\0none\0' + src.encode() + b'\0' + dst.encode() + b'\0'
    fields = (sdnv(0) + sdnv(9) + sdnv(0) + sdnv(9 + len(src) + 1) + sdnv(0) + sdnv(4) + sdnv(0) + sdnv(4)
              + sdnv(1000) + sdnv(1) + sdnv(3600) + sdnv(len(d)) + d)
    prim = bytes([6]) + sdnv(0) + sdnv(len(fields)) + fields
    return prim + bytes([1]) + sdnv(0x08) + sdnv(len(payload)) + payload


# ---------------------------------------------------------------- v4 messages
def v4_chdr(cantls=False):
    return b'dtn!' + bytes([4, 0x01 if cantls else 0])


def v4_sess_init(keepalive=30, seg_mru=1 << 20, xfer_mru=1 << 24, node=b'ipn:1.0', exts=b''):
    return (bytes([7]) + struct.pack('>HQQH', keepalive, seg_mru, xfer_mru, len(node)) + node
            + struct.pack('>I', len(exts)) + exts)


def ext(flags, typ, data):
    return struct.pack('>BHH', flags, typ, len(data)) + data


def v4_seg(xid, flags, data, exts=None, datalen=None):
    m = bytes([1, flags]) + struct.pack('>Q', xid)
    if flags & 2:
        e = exts or b''
        m += struct.pack('>I', len(e)) + e
    return m + struct.pack('>Q', len(data) if datalen is None else datalen) + data


def v4_ack(xid, flags, n):
    return bytes([2, flags]) + struct.pack('>QQ', xid, n)


def v4_refuse(xid, reason=1):
    return bytes([3, reason]) + struct.pack('>Q', xid)


def v4_term(reply=False, reason=0):
    return bytes([5, 1 if reply else 0, reason])


KEEPALIVE4 = bytes([4])


def v4_reject(reason=3, head=0x7f):
    return bytes([6, reason, head])


# ---------------------------------------------------------------- v3 messages
def v3_chdr(flags=0x03, keepalive=60, eid=b'dtn://node-a'):
    return b'dtn!' + bytes([3, flags]) + struct.pack('>H', keepalive) + sdnv(len(eid)) + eid


def v3_data(flags, data):
    return bytes([0x10 | flags]) + sdnv(len(data)) + data


def v3_ack(n):
    return bytes([0x20]) + sdnv(n)


def v3_refuse(reason):
    return bytes([0x30, reason << 4])


KEEPALIVE3 = bytes([0x40])


def v3_shutdown(reason=None, delay=None):
    f = 0x50 | (0x02 if reason is not None else 0) | (0x01 if delay is not None else 0)
    m = bytes([f])
    if reason is not None:
        m += bytes([reason])
    if delay is not None:
        m += struct.pack('>H', delay)
    return m


class Cap:
    def __init__(self):
        self.frames = []
        self.n = 0

    def conn(self, sport, dport=PORT, c='192.0.2.1', s='192.0.2.2', handshake=True):
        t = TcpConn(sport, dport, c, s, isn_c=1000 + sport, isn_s=5000 + sport)
        if handshake:
            t.handshake()
        return t

    def done(self, *conns):
        for t in conns:
            self.frames += t.frames


def tls_clienthello():
    ch = (b'\x03\x03' + bytes(range(32)) + b'\x00' + struct.pack('>H', 2) + b'\x13\x01' + b'\x01\x00'
          + struct.pack('>H', 0))
    hs = b'\x01' + struct.pack('>I', len(ch))[1:] + ch
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs


def main(out):
    cap = Cap()
    # ============================================================ v4 session
    a = cap.conn(40000)
    a.send(v4_chdr())
    a.send(v4_chdr(), client=False)
    a.send(v4_sess_init(keepalive=30, node=b'ipn:1.0'))
    a.send(v4_sess_init(keepalive=45, seg_mru=1500, xfer_mru=1 << 30, node=b'dtn://node-b/'), client=False)
    a.send(KEEPALIVE4)
    a.send(KEEPALIVE4, client=False)
    b1 = bundle6(b'P' * 100)
    # transfer 1: three segments, the first with the Transfer Length extension, acks cumulative
    tl = ext(0, 1, struct.pack('>Q', len(b1)))
    s1, s2, s3 = b1[:40], b1[40:80], b1[80:]
    a.send(v4_seg(1, 0x02, s1, exts=tl))
    a.send(v4_ack(1, 0x02, len(s1)), client=False)
    a.send(v4_seg(1, 0x00, s2))
    a.send(v4_ack(1, 0x00, len(s1) + len(s2)), client=False)
    a.send(v4_seg(1, 0x01, s3))
    a.send(v4_ack(1, 0x01, len(b1)), client=False)
    # transfer 2: a single segment, an unknown non-critical item and no extension list
    b2 = bundle6(b'second transfer')
    a.send(v4_seg(2, 0x03, b2))
    a.send(v4_ack(2, 0x03, len(b2)), client=False)
    # two messages in one TCP segment, a segment split over two TCP segments, xfer 3 refused
    b3 = bundle6(b'Q' * 60)
    a.send(v4_seg(3, 0x02, b3[:30], exts=b'') + v4_seg(3, 0x00, b3[30:50]))
    m = v4_seg(3, 0x01, b3[50:])
    a.send(m[:9])
    a.send(m[9:])
    a.send(v4_refuse(3, reason=2), client=False)
    a.send(v4_refuse(3, reason=0), client=False)
    # a transfer from the passive side, acks from the active side
    b4 = bundle6(b'reverse direction', src='//b', dst='//a')
    a.send(v4_seg(1, 0x03, b4, exts=ext(0, 1, struct.pack('>Q', len(b4)))), client=False)
    a.send(v4_ack(1, 0x03, len(b4)))
    # message reject, session termination (reply flag on the second)
    a.send(v4_reject(1, 0x01), client=False)
    a.send(v4_reject(2, 0x05))
    a.send(v4_reject(3, 0x07))
    a.send(v4_term(False, 1))
    a.send(v4_term(True, 0), client=False)
    cap.done(a)
    # ============================================================ v4 with STARTTLS
    t = cap.conn(40001)
    t.send(v4_chdr(cantls=True))
    t.send(v4_chdr(cantls=True), client=False)
    t.send(tls_clienthello())
    cap.done(t)
    # a contact header that turns TLS off on one side
    t2 = cap.conn(40002)
    t2.send(v4_chdr(cantls=True))
    t2.send(v4_chdr(cantls=False), client=False)
    t2.send(v4_sess_init())
    t2.send(v4_sess_init(), client=False)
    cap.done(t2)
    # ============================================================ v3 session
    v = cap.conn(40010)
    v.send(v3_chdr(0x03, 60, b'dtn://node-a'))
    v.send(v3_chdr(0x00, 30, b'dtn://node-b.example/'), client=False)
    bb = bundle6(b'v3 payload ' * 6)
    v.send(v3_data(0x02, bb[:30]))
    v.send(v3_ack(30), client=False)
    v.send(v3_data(0x00, bb[30:60]))
    v.send(v3_ack(60), client=False)
    v.send(v3_data(0x01, bb[60:]))
    v.send(v3_ack(len(bb)), client=False)
    bc = bundle6(b'single v3 segment')
    v.send(v3_data(0x03, bc))
    v.send(v3_ack(len(bc)), client=False)
    v.send(KEEPALIVE3)
    v.send(KEEPALIVE3, client=False)
    # a transfer from the passive side
    v.send(v3_data(0x03, bundle6(b'from passive', src='//b', dst='//a')), client=False)
    v.send(v3_ack(len(bundle6(b'from passive'))))
    # shutdown: no options, reason, delay, both
    v.send(v3_shutdown())
    v.send(v3_shutdown(reason=1), client=False)
    v.send(v3_shutdown(delay=300))
    v.send(v3_shutdown(reason=2, delay=0x1234), client=False)
    cap.done(v)
    # ============================================================ heuristic on another port
    h4 = cap.conn(40020, 50020)
    h4.send(v4_chdr())
    h4.send(v4_chdr(), client=False)
    h4.send(v4_sess_init())
    h4.send(v4_sess_init(), client=False)
    h4.send(v4_seg(7, 0x03, bundle6(b'heuristic')))
    h4.send(v4_ack(7, 0x03, len(bundle6(b'heuristic'))), client=False)
    h3 = cap.conn(40021, 50021)
    h3.send(v3_chdr())
    h3.send(v3_chdr(), client=False)
    h3.send(v3_data(0x03, bundle6(b'h3')))
    h3.send(v3_ack(len(bundle6(b'h3'))), client=False)
    cap.done(h4, h3)
    # ============================================================ no contact header (capture started late)
    n4 = cap.conn(40030)
    n4.send(v4_seg(5, 0x03, bundle6(b'mid-session v4')))
    n4.send(v4_ack(5, 0x03, len(bundle6(b'mid-session v4'))), client=False)
    n4.send(KEEPALIVE4)
    n3 = cap.conn(40031)
    n3.send(v3_data(0x03, bundle6(b'mid-session v3')))
    n3.send(v3_ack(len(bundle6(b'mid-session v3'))), client=False)
    n3.send(KEEPALIVE3)
    cap.done(n4, n3)
    # TCP on another port that is not TCPCL (the heuristic looks at the payload and gives up)
    x = cap.conn(40033, 50030)
    x.send(b'abc')
    x.send(b'not the magic string')
    x.send(b'dtn!')
    cap.done(x)
    # ============================================================ the transfer-segment limit
    # 5100 one-octet segments of one transfer; the dissector tracks 5000 per transfer
    L = cap.conn(40040)
    L.send(v4_chdr())
    L.send(v4_chdr(), client=False)
    L.send(v4_sess_init(xfer_mru=1 << 40))
    L.send(v4_sess_init(xfer_mru=1 << 40), client=False)
    buf, ackbuf = b'', b''
    for i in range(5100):
        fl = 0x02 if i == 0 else (0x01 if i == 5099 else 0)
        buf += v4_seg(9, fl, b'x')
        ackbuf += v4_ack(9, fl, i + 1)
        if (i + 1) % 1700 == 0:
            L.send(buf)
            buf = b''
            L.send(ackbuf, client=False)
            ackbuf = b''
    cap.done(L)
    pcapng(os.path.join(out, 'tcpcl-coverage.pcapng'), [(0, f) for f in cap.frames], (LT_ETH,))
    print('main capture: %d frames' % len(cap.frames))

    # ============================================================ malformed
    mc = Cap()
    # session extension items (the table has no handlers), critical flag, extension data
    s = mc.conn(41000)
    s.send(v4_chdr())
    s.send(v4_chdr(), client=False)
    s.send(v4_sess_init(exts=ext(0, 1, struct.pack('>Q', 1234)) + ext(1, 0x4001, b'abc') + ext(0, 2, b'')))
    s.send(v4_sess_init(exts=b''), client=False)
    s.send(v4_sess_init())                       # duplicate SESS_INIT
    # transfer: segments that start twice, end twice, miss the start, exceed the MRU
    s.send(v4_seg(1, 0x00, b'no start'))
    s.send(v4_seg(1, 0x02, b'second start'))
    s.send(v4_seg(1, 0x01, b'end'))
    s.send(v4_seg(1, 0x01, b'second end'))
    s.send(v4_ack(1, 0x00, 5), client=False)     # flags do not match
    s.send(v4_ack(1, 0x03, 999), client=False)   # no segment with that length
    s.send(v4_ack(77, 0x03, 5), client=False)    # unknown transfer
    s.send(v4_refuse(77), client=False)          # refusal without transfer
    s.send(v4_seg(2, 0x02, b'ext crit', exts=ext(1, 1, struct.pack('>Q', 10)) + ext(0, 1, struct.pack('>Q', 3))))
    s.send(v4_seg(2, 0x01, b'0123456789abcdef'))
    s.send(v4_seg(3, 0x03, b'big', exts=ext(0, 1, struct.pack('>Q', 1 << 62))))
    s.send(v4_seg(4, 0x03, b'x' * 50, datalen=50)[:20])        # message cut short (TCP desegmentation)
    s.send(bytes([0x7f, 0, 0]))                                # unknown message type
    s.send(v4_term(False, 3))
    s.send(v4_term(False, 3))                                  # duplicate SESS_TERM, no reply flag
    s.send(v4_term(False, 3), client=False)                    # reply expected
    s.send(KEEPALIVE4)
    mc.done(s)
    # SESS_INIT whose lengths run past the segment, session before contact header
    s2 = mc.conn(41001)
    s2.send(v4_chdr())
    s2.send(v4_chdr(), client=False)
    s2.send(bytes([7]) + struct.pack('>HQQH', 30, 1, 1, 200) + b'ipn:1')           # node id too long
    s2.send(v4_sess_init()[:12])
    s2.send(bytes([1, 0x02]) + struct.pack('>Q', 5))                               # segment header cut
    s2.send(bytes([1, 0x03]) + struct.pack('>Q', 5) + struct.pack('>Q', 1 << 40) + b'abc')   # data length huge
    mc.done(s2)
    # contact header problems
    s3 = mc.conn(41002)
    s3.send(v4_chdr())
    s3.send(b'dtn!' + bytes([3, 0, 0, 30, 1, 0x61]), client=False)      # version mismatch
    s3.send(v4_chdr())                                              # duplicate contact header
    s3.send(b'dtn!' + bytes([9, 0]), client=False)
    s3.send(b'dtn!')
    mc.done(s3)
    # v3 problems: data flags, invalid message type, lengths
    s4 = mc.conn(41003)
    s4.send(v3_chdr())
    s4.send(v3_chdr(), client=False)
    s4.send(v3_data(0x00, b'no start'))
    s4.send(v3_data(0x02, b'start again'))
    s4.send(v3_data(0x02, b'start again'))
    s4.send(v3_data(0x01, b'end'))
    s4.send(v3_data(0x01, b'end again'))
    s4.send(bytes([0x1c]) + sdnv(2) + b'ab')                           # reserved data flag bits
    s4.send(v3_ack(10), client=False)
    s4.send(v3_ack(11), client=False)
    # REFUSE-BUNDLE is one octet long, but the dissector reads a second one (see the README)
    for reason in (0, 1, 2, 3, 9):
        s4.send(v3_data(0x03, bundle6(b'refused %d' % reason)))
        s4.send(v3_refuse(reason), client=False)
    s4.send(bytes([0x60]) + sdnv(5))                                  # LENGTH message
    s4.send(bytes([0x70]))                                            # unknown type
    s4.send(bytes([0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]) + b'abc')  # SDNV beyond 64 bits
    mc.done(s4)
    # a contact header for version 5 and for version 2 (invalid version)
    hv = mc.conn(41006, 50022)
    hv.send(b'dtn!' + bytes([5, 0]))
    hv.send(b'dtn!' + bytes([2, 0, 0, 0, 0]), client=False)
    mc.done(hv)
    # first segment looks like a TLS record (chdr_missing_tls): the segment is then shown as a
    # contact header with an invalid magic string (see the README)
    nt = mc.conn(41007)
    nt.send(b'\x17\x03\x03\x00\x20' + bytes(range(32)))
    nt.send(b'\x17\x03\x03\x00\x20' + bytes(range(32)), client=False)
    mc.done(nt)
    # chdr missing with v3/v4 only preferences and a message that fits none
    s5 = mc.conn(41004)
    s5.send(bytes([0x7e, 1, 2, 3, 4, 5, 6, 7]))
    s5.send(bytes([0x7e, 1, 2, 3, 4, 5, 6, 7]), client=False)
    mc.done(s5)
    # the original reproducer of the session extension table (type 1 as a session extension)
    s6 = mc.conn(41005)
    s6.send(v4_chdr())
    s6.send(v4_chdr(), client=False)
    s6.send(v4_sess_init(exts=ext(0, 1, struct.pack('>Q', 1234))))
    s6.send(v4_sess_init(), client=False)
    for i in range(3):
        fl = (2 if i == 0 else 0) | (1 if i == 2 else 0)
        s6.send(v4_seg(9, fl, b'zz', exts=b''))
        s6.send(v4_ack(9, fl, 2 * (i + 1)), client=False)
    mc.done(s6)
    # acks whose flags differ from the segment, unknown transfer extension, lengths that overflow
    s7 = mc.conn(41008)
    s7.send(v4_chdr())
    s7.send(v4_chdr(), client=False)
    s7.send(v4_seg(20, 0x03, b'12345'))                                   # before the SESS_INIT of this direction
    s7.send(v4_sess_init())
    s7.send(v4_sess_init(), client=False)
    s7.send(v4_seg(21, 0x03, b'12345'))
    s7.send(v4_ack(21, 0x01, 5), client=False)                              # flags differ from the segment
    s7.send(v4_seg(22, 0x02, b'unknown ext', exts=ext(0, 0x4002, b'zz') + ext(1, 0x4003, b'')))
    s7.send(v4_seg(22, 0x01, b'end'))
    s7.send(bytes([7]) + struct.pack('>HQQH', 30, 1, 1, 4) + b'ipn:' + struct.pack('>I', 0xffffffff))
    s7.send(bytes([1, 0x03]) + struct.pack('>Q', 23) + struct.pack('>Q', 0x7fffffff) + b'abc')
    mc.done(s7)
    s8 = mc.conn(41009)
    s8.send(v3_chdr())
    s8.send(v3_chdr(), client=False)
    s8.send(bytes([0x10, 0x80]))                                          # data segment, length SDNV cut
    s8.send(bytes([0x20, 0x80]), client=False)                            # ack, length SDNV cut
    s8.send(bytes([0x60, 0x80]))
    mc.done(s8)
    # first segments that are neither TCPCL messages nor look like TLS
    for k, junk in enumerate((b'\x7e\x01\x02', b'\x17\x04\x03\x00\x20' + bytes(range(32)),
                              b'\x17\x03\x03\x00\x00' + bytes(range(32)),
                              b'\x16\x03\x01\xff\xff' + bytes(range(32)))):
        j = mc.conn(41010 + k)
        j.send(junk)
        j.send(junk, client=False)
        mc.done(j)
    pcapng(os.path.join(out, 'tcpcl-coverage-malformed.pcapng'), [(0, f) for f in mc.frames], (LT_ETH,))
    print('malformed capture: %d frames' % len(mc.frames))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
