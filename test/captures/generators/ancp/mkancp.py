#!/usr/bin/env python3
# ANCP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ANCP (packet-ancp.c): an access node (192.0.2.1) and a network access
server (192.0.2.2) exchange Access Node Control Protocol messages on TCP
port 6068.

Usage: mkancp.py [<output directory>]

Writes:
  ancp-coverage.pcap            every message type, adjacency code and
                                capability, DSL line attribute sub-TLV,
                                extension TLV, result and code, TCP
                                reassembly, and the reproducers of the
                                TLV skipping fixes
  ancp-coverage-malformed.pcap  paths that end in an exception

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import (TCP_ACK, TCP_SYN, TcpFlow, eth, ipv4, tcp,  # noqa: E402
                    write_pcap)

PORT = 6068
ETHERTYPE = 0x880C
AN_MAC = bytes.fromhex('020000000a01')
NAS_MAC = bytes.fromhex('020000000a02')


def ancp(mtype, body, common=None, ver=0x32, length=None):
    """One ANCP (GSMP) message. common = (result, code, partition id,
    transaction id, i flag, submessage number, length2) for the messages
    that have the common header (all but Adjacency)."""
    rest = bytes([ver, mtype])
    if common is not None:
        res, code, pid, tid, iflag, sub, len2 = common
        rest += struct.pack('>HB', (res << 12) | code, pid) + tid.to_bytes(3, 'big')
        rest += struct.pack('>HH', (iflag << 15) | sub, len2)
    rest += body
    return struct.pack('>HH', ETHERTYPE, len(rest) if length is None else length) + rest


def tlv(ttype, value, tlen=None):
    pad = b'\0' * (-len(value) % 4)
    return struct.pack('>HH', ttype, len(value) if tlen is None else tlen) + value + pad


def stlv(stype, value, slen=None):
    return struct.pack('>HH', stype, len(value) if slen is None else slen) + value + \
        b'\0' * (-len(value) % 4)


def u32(v):
    return struct.pack('>I', v)


def dsl_attrs(items):
    """The DSL-Line-Attributes TLV (type 4) with the given sub-TLVs; every
    sub-TLV is padded to 8 bytes by the 32-bit value, except where stlv()
    produces another size."""
    return tlv(4, b''.join(items))


def adj(code, caps, timer=250, flag=0, sname=AN_MAC, rname=NAS_MAC, sport=1, rport=2,
        pinfo=0x11, sinst=1, pid=0, rinst=2, ncaps=None):
    cb = b''.join(struct.pack('>HH', t, len(v)) + v + b'\0' * (-len(v) % 4)
                  for t, v in caps)
    body = bytes([timer, (flag << 7) | code]) + sname + rname
    body += struct.pack('>II', sport, rport)
    body += bytes([pinfo]) + sinst.to_bytes(3, 'big') + bytes([pid]) + rinst.to_bytes(3, 'big')
    body += bytes([0, len(caps) if ncaps is None else ncaps]) + struct.pack('>H', len(cb)) + cb
    return ancp(10, body)


def common(res=0, code=0, pid=0, tid=1, iflag=0, sub=0, len2=0):
    return (res, code, pid, tid, iflag, sub, len2)


def port_up_dn(mtype, tech, tlvs, cm, ntlv=None, blklen=None):
    blk = b''.join(tlvs)
    body = b'\0' * 20 + bytes([0x00, mtype, tech, 0])
    body += struct.pack('>HH', len(tlvs) if ntlv is None else ntlv,
                        len(blk) if blklen is None else blklen) + blk
    return ancp(mtype, body, cm)


def port_mgmt(function, xfunction, tlvs=(), cm=None, ntlv=None):
    blk = b''.join(tlvs)
    body = b'\0' * 14 + bytes([function, xfunction]) + b'\0' * 4
    body += bytes([0, 32, 0, 0])
    body += struct.pack('>HH', len(tlvs) if ntlv is None else ntlv, len(blk)) + blk
    return ancp(32, body, cm or common(res=2, tid=7))


SYN_OPTIONS = bytes.fromhex('020405b404020101')  # MSS 1460, SACK permitted, NOPs


def handshake(flow):
    """The three-way handshake with the options of a real stack (a SYN
    without options is flagged as a scanner)."""
    frames = []
    for d, flags in ((0, TCP_SYN), (1, TCP_SYN | TCP_ACK), (0, TCP_ACK)):
        sp, dp = (flow.sport, flow.dport) if d == 0 else (flow.dport, flow.sport)
        s, t = (flow.src, flow.dst) if d == 0 else (flow.dst, flow.src)
        sm, dm = (flow.smac, flow.dmac) if d == 0 else (flow.dmac, flow.smac)
        seg = tcp(b'', sp, dp, flow.seq[d], flow.seq[1 - d] if flags & TCP_ACK else 0, flags,
                  options=SYN_OPTIONS if flags & TCP_SYN else b'', src=s, dst=t)
        flow.seq[d] += 1 if flags & TCP_SYN else 0
        flow.ident += 1
        frames.append(eth(ipv4(seg, 6, s, t, ident=flow.ident - 1), 0x0800, dst=dm, src=sm))
    return frames


def build():
    ok = []        # frames of the main capture
    bad = []       # frames of the malformed capture

    an = TcpFlow(40002, PORT, isn_c=1000, isn_s=5000, smac=AN_MAC, dmac=NAS_MAC,
                 checksum=True)
    ok += handshake(an)

    # Adjacency handshake: Syn, SynAck, Ack, Rstack, with the capabilities
    caps_all = [(1, b''), (2, b''), (3, b''), (4, b'')]
    ok.append(an.send(adj(1, caps_all)))
    ok.append(an.recv(adj(2, caps_all, sname=NAS_MAC, rname=AN_MAC, timer=100, pinfo=0x21)))
    ok.append(an.send(adj(3, caps_all[:2], flag=1)))
    ok.append(an.recv(adj(4, [(4, b'\x00\x00\x00\x07')], flag=1)))
    ok.append(an.send(adj(9, [(0x55, b'abcdef')])))       # unknown code and capability
    ok.append(an.send(adj(3, [])))                        # no capabilities

    # Port-Up for a DSL line: every DSL attribute, in several TLVs
    rate_subs = [stlv(0x81 + i, u32(1000 * (i + 1))) for i in range(10)]   # 0x81..0x8a
    delay_subs = [stlv(0x8b + i, u32(5 + i)) for i in range(4)]            # 0x8b..0x8e
    type_subs = [stlv(0x91, u32(t)) for t in (1, 2, 3, 4, 5, 6, 9)]
    state_subs = [stlv(0x8f, u32(t)) for t in (1, 2, 3, 7)]
    encap = stlv(0x90, b'\x03\x01\x02', 3)
    odd = stlv(0x77, u32(0xfffffffe))
    tl_circ = tlv(1, b'dslam1 atm 1/1/01/01:8.35')
    tl_rem = tlv(2, b'subscriber-0815')
    tl_prof = tlv(5, b'profile-gold')
    tl_att1 = dsl_attrs(rate_subs)
    tl_att2 = dsl_attrs(delay_subs + type_subs[:2])
    tl_att3 = dsl_attrs(type_subs[2:] + state_subs)
    tl_att4 = dsl_attrs([encap, odd])
    ok.append(an.send(port_up_dn(80, 5, [tl_circ, tl_rem, tl_att1, tl_att2],
                                 common(res=3, code=0x503, pid=1, tid=0x010203, iflag=1, sub=5, len2=0))))
    ok.append(an.send(port_up_dn(80, 5, [tl_att3, tl_att4, tl_prof, tlv(0x1000, b'target')],
                                 common(res=0, code=0, tid=2))))
    # Port-Down for a DSL line
    ok.append(an.send(port_up_dn(81, 5, [tl_circ, dsl_attrs([stlv(0x8f, u32(2))])],
                                 common(res=4, code=0x504, tid=3))))
    # Port-Up for a PON line and for a technology type that has no TLV decoding
    ok.append(an.send(port_up_dn(80, 1, [tl_circ, tl_rem], common(res=1, code=0x13, tid=4))))
    ok.append(an.send(port_up_dn(80, 0xff, [tl_circ], common(res=2, code=0x500, tid=5))))
    ok.append(an.send(port_up_dn(80, 0, [], common(res=3, code=0x505, tid=6), ntlv=0)))

    # Port-Management: loopback request with function 8 and 9
    ok.append(an.recv(port_mgmt(9, 0x11)))
    ok.append(an.recv(port_mgmt(8, 0, cm=common(res=2, code=0x506, tid=8))))
    ok.append(an.recv(port_mgmt(0, 3, cm=common(res=3, code=0x507, tid=9))))
    # Provisioning and Generic Response with TLVs: OAM test parameters, opaque
    # data, response string
    ping = tlv(7, bytes([5, 3, 0, 0]))
    opaque = tlv(8, u32(0x11223344) + u32(0x55667788))
    resp = tlv(9, b'Loopback test passed in 12 ms')
    for mt, code in ((93, 0x509), (91, 0x508)):
        body = ping + opaque + resp + tlv(1, b'circuit')
        cm = common(res=3, code=code, tid=10 + mt, len2=len(body))
        ok.append(an.recv(ancp(mt, body, cm)))
    # Message types that have no body decoding
    for mt, code in ((85, 0x000), (200, 0x000), (144, 0x051), (145, 0x053), (146, 0x054), (147, 0x055),
                     (148, 0x064), (149, 0x065), (150, 0x066)):
        ok.append(an.send(ancp(mt, b'', common(res=3, code=code, tid=mt))))
    for code in (0x002, 0x006, 0x067, 0x068, 0x069, 0x501, 0x502, 0x508, 0x7ff):
        ok.append(an.send(ancp(85, b'', common(res=0, code=code, tid=code))))

    # TCP: a message split over three segments, two messages in one segment,
    # and a message and the start of the next
    m1 = port_up_dn(80, 5, [tl_circ, tl_att1, tl_rem], common(res=3, code=0x503, tid=0x20))
    ok.append(an.send(m1[:3]))
    ok.append(an.send(m1[3:30]))
    ok.append(an.send(m1[30:]))
    m2 = adj(1, caps_all)
    m3 = port_up_dn(81, 5, [tl_circ], common(res=4, code=0x504, tid=0x21))
    ok.append(an.send(m2 + m3))
    m4 = port_up_dn(80, 1, [tl_rem], common(res=3, code=0x500, tid=0x22))
    ok.append(an.send(m4 + m2[:7]))
    ok.append(an.send(m2[7:]))

    # Reproducers of the TLV skipping fixes (report r9)
    t1 = struct.pack('>HH', 4, 4) + b'\x00\x01\x00\x04'     # DSL attributes with length 4
    t2 = struct.pack('>HH', 1, 4) + b'abcd'
    ok.append(an.send(port_up_dn(80, 5, [t1, t2], common(res=3, tid=0x30))))
    caps = struct.pack('>HH', 1, 4) + b'\x00\x04\x00\x00' + struct.pack('>HH', 2, 0)
    adjb = (bytes([100, 0x01]) + AN_MAC + NAS_MAC + struct.pack('>II', 1, 2) + bytes([0x11])
            + b'\x00\x00\x01' + bytes([1]) + b'\x00\x00\x02' + bytes([0, 2])
            + struct.pack('>H', len(caps)) + caps)
    ok.append(an.send(ancp(10, adjb)))
    t3 = struct.pack('>HH', 4, 8) + struct.pack('>HH', 0x81, 0) + b'\x00\x00\x03\xe8'
    ok.append(an.send(port_up_dn(80, 5, [t3], common(res=3, tid=0x31))))
    # DSL attributes with a sub-TLV of 8 bytes and of 5 bytes (padded)
    t4 = tlv(4, stlv(0x90, b'\x01\x02\x03\x04\x05\x06\x07\x08') + stlv(0x8f, u32(1)))
    ok.append(an.send(port_up_dn(80, 5, [t4, t2], common(res=3, tid=0x32))))
    # TLV lengths that are not a multiple of 4, in the generic path and the
    # OAM TLVs, followed by another TLV
    ok.append(an.send(port_up_dn(80, 5, [tlv(1, b'abcde'), tlv(0x99, b'xy'), tlv(7, bytes([2, 9, 0, 0])),
                                         tlv(8, u32(1) + u32(2)), t2],
                                 common(res=3, tid=0x33))))
    ok += an.close()

    # ---- malformed paths
    bn = TcpFlow(40003, PORT, isn_c=2000, isn_s=6000, smac=AN_MAC, dmac=NAS_MAC, checksum=True,
                 ip_ident=300)
    bad += handshake(bn)
    # more TLVs announced than present
    bad.append(bn.send(port_up_dn(80, 5, [tl_circ], common(res=3, tid=1), ntlv=5)))
    # a sub-TLV that is longer than the TLV
    bad.append(bn.send(port_up_dn(80, 5, [tlv(4, struct.pack('>HH', 0x81, 400) + b'\0' * 4)],
                                  common(res=3, tid=2))))
    # DSL attributes with a short sub-TLV at the end
    bad.append(bn.send(port_up_dn(80, 5, [tlv(4, struct.pack('>HH', 0x81, 4), tlen=8)],
                                  common(res=3, tid=3))))
    # TLV whose length runs past the end of the message
    bad.append(bn.send(port_up_dn(80, 5, [struct.pack('>HH', 1, 200) + b'abcd'],
                                  common(res=3, tid=4))))
    # OAM TLVs truncated
    bad.append(bn.send(port_up_dn(80, 5, [struct.pack('>HH', 8, 8) + b'\0\0'],
                                  common(res=3, tid=5))))
    bad.append(bn.send(port_up_dn(80, 5, [struct.pack('>HH', 7, 4)], common(res=3, tid=6))))
    # generic response and provisioning with an unterminated TLV list
    bad.append(bn.send(ancp(91, struct.pack('>HH', 1, 400) + b'ab', common(res=3, tid=7))))
    bad.append(bn.send(ancp(93, b'\0\0', common(res=3, tid=8), length=40)))
    # adjacency announcing more capabilities than present, and a short one
    bad.append(bn.send(adj(1, caps_all, ncaps=9)))
    bad.append(bn.send(ancp(10, bytes(10))))
    # a message cut short in the common header; an empty-ish port management
    bad.append(bn.send(ancp(80, b'', common(res=3, tid=9))))
    bad.append(bn.send(ancp(32, b'\0' * 10, common(res=3, tid=10))))
    # a payload that does not start with the GSMP ethertype
    bad.append(bn.send(b'\x88\x0d\x00\x04\x32\x50\x00\x00'))
    bad.append(bn.send(b'\x12\x34\x00\x04\x32\x50\x00\x00'))
    return ok, bad


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(outdir, exist_ok=True)
    ok, bad = build()
    ts = lambda i: (1700000000 + i // 10, (i % 10) * 100000)  # noqa: E731
    write_pcap(os.path.join(outdir, 'ancp-coverage.pcap'), ok, ts=ts)
    write_pcap(os.path.join(outdir, 'ancp-coverage-malformed.pcap'), bad, ts=ts)
    print(len(ok), len(bad))


if __name__ == '__main__':
    main()
