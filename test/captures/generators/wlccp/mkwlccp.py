#!/usr/bin/env python3
# Generates test/captures/wlccp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the WLCCP dissector
(packet-wlccp.c, Cisco Wireless LAN Context Control Protocol).

WLCCP is reached by UDP port 2887, by ethertype 0x872d and by the LLC
Cisco wireless OUI (00:40:96) with PID 0x0000. Version 0xC1 messages
have a SAP (context management, security, RRM, QoS, network management,
MIP), a message type and, for most, a list of TLVs (group + type in the
flags word, container TLVs nest). Everything is dissected only with a
protocol tree (tshark -V). Every packet is built here with struct; no
captured traffic is used.

Usage: mkwlccp.py <output directory>

Writes:
  wlccp-coverage.pcap            every SAP/message type handled, every TLV
                                 type handled, containers up to the depth
                                 limit (32), the two bug reproducers
  wlccp-coverage-malformed.pcap  truncated messages and TLVs, TLV nesting
                                 past the limit (expert info), bad lengths
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlccp_common import udp_frame, eth_frame, write_pcap

M = lambda n: bytes([2, 0, 0, 0, 0, n])
H = struct.pack

# ---------------------------------------------------------------- TLVs
def tlv(group, typ, payload=b'', container=False, enc=False, req=False, flags=None, length=None):
    w = (0x8000 if container else 0) | (0x4000 if enc else 0) | (group << 8) | (0x80 if req else 0) | typ
    if flags is not None:
        w = flags
    ln = 4 + len(payload) if length is None else length
    return H('>HH', w, ln) + payload

def ccm_null(n=3): return tlv(0, 0, b'\x00' * n)
def ccm_ip(ip=(192, 0, 2, 9), **kw): return tlv(0, 9, bytes(ip), **kw)
def sec_init(): return tlv(1, 1, b'\x00\x03\x00\x00')
def sec_ctx_req(): return tlv(1, 2, H('>I', 0x11) + H('>H', 4) + M(1) + H('>H', 1) + M(2) + b'\x00\x01' + bytes(range(32)))
def sec_auth(): return tlv(1, 6, H('>H', 4) + M(1) + H('>H', 1) + M(2) + H('>I', 7) + b'\x00\x02' + bytes(range(32, 64)))
def sec_mic(n=16): return tlv(1, 8, H('>Q', 0x1122334455667788) + H('>H', n) + bytes(range(0xa0, 0xa0 + n)))
def sec_ctx_rep(): return tlv(1, 0x0a, H('>I', 0x12) + H('>H', 4) + M(1) + H('>H', 1) + M(2) + bytes(range(32)) + H('>I', 3600))
def rrm(typ, payload, **kw): return tlv(2, typ, payload, **kw)
def rrm_common6(): return bytes([5, 1, 6, 0]) + H('>H', 100)
def rrm_tlvs():
    t = []
    t.append(rrm(2, H('>HH', 9, 300)))
    t.append(rrm(3, bytes([1]) + M(5) + M(6)))
    t.append(rrm(4, b''))
    t.append(rrm(0x12, bytes([1, 2, 6, 1]) + H('>H', 50)))
    t.append(rrm(0x14, bytes([1, 2, 6, 2]) + H('>H', 50) + M(7) + M(8)))
    fr = b''.join(bytes([3 + i, 200 + i]) + M(9) + M(10 + i) for i in range(2))
    t.append(rrm(0x15, bytes([1, 2, 6, 0]) + H('>H', 50) + fr + b'\x00' * 4))
    t.append(rrm(0x15, bytes([1, 2, 6, 0]) + H('>H', 50) + b'\x00' * 4))   # no elements
    t.append(rrm(0x16, rrm_common6()))
    t.append(rrm(0x17, rrm_common6() + b'\x42'))
    t.append(rrm(0x18, rrm_common6()))
    t.append(rrm(0x19, rrm_common6() + bytes(range(8)) + b'\x00' * 4))
    t.append(rrm(0x1c, rrm_common6()))
    t.append(rrm(0x1e, bytes([3, 6, 4]) + M(11) + H('>H', 100) + H('>H', 0xffff) + bytes([0, 6, 0x53, 0x53, 0x49, 0x44, 0x31, 0x32]) + b'\x00' * 4))
    t.append(rrm(0x1e, bytes([3, 6, 4]) + M(11) + H('>H', 100) + H('>H', 0x0000) + b'\x00' * 4))
    t.append(rrm(0x1f, bytes([1, 2, 0xc8, 3]) + H('>I', 1234) + H('>Q', 0x0102030405060708)))
    t.append(rrm(0x20, bytes([192, 0, 2, 1]) + M(12) + M(13) + bytes([192, 0, 2, 2]) + M(14) + M(15)))
    t.append(rrm(0x21, H('>H', 77) + bytes([192, 0, 2, 3]) + M(16) + b'\x00' + bytes([192, 0, 2, 4]) + M(17) + b'\x01'))
    t.append(rrm(0x22, b'\x00'))
    t.append(rrm(0x58, H('>H', 3)))
    t.append(rrm(0x5b, bytes([192, 0, 2, 5]) + M(18) + H('>H', 1)))
    t.append(rrm(0x5c, H('>H', 2)))
    t.append(rrm(0x50, b'\x01\x02\x03'))     # unknown RRM type
    return t
def nm(typ, payload, **kw): return tlv(4, typ, payload, **kw)
def nm_tlvs():
    t = []
    base = M(20) + H('>H', 5) + M(21)
    t.append(nm(0x20, base + bytes([60, 0]) + bytes([192, 0, 2, 20]) + bytes([1, 2, 0]) + b'user1' + b'\x00' * 4))
    t.append(nm(0x20, base + bytes([60, 0]) + bytes([192, 0, 2, 20]) + bytes([1, 2, 0]) + b'\x00' * 4))
    t.append(nm(0x21, M(22) + H('>H', 5) + M(23) + bytes([3, 0])))
    t.append(nm(0x22, M(24) + H('>H', 5) + M(25) + bytes([60, 1, 2]) + b'\x00' * 3))
    t.append(nm(0x24, M(26) + H('>H', 5) + M(27) + b'\x00\x00' + bytes([192, 0, 2, 26])))
    t.append(nm(0x26, base + bytes([60, 0]) + bytes([192, 0, 2, 27]) + bytes([1, 2, 0]) + b'refresh' + b'\x00' * 4))
    t.append(nm(0x27, b'\x00' * 6 + H('>H', 5) + H('>I', 99)))
    t.append(nm(0x40, b'\x01\x02'))            # unknown NM type
    return t

# ---------------------------------------------------------------- messages
def msg(sap, mtype, body, length=None, version=0xC1, ntype=0x0002):
    ln = 6 + len(body) if length is None else length
    return bytes([version, sap]) + H('>HH', ntype, ln) + bytes([mtype]) + body

def cm_flags(retry=0, resp=0, tlv_=0, inb=0, outb=0, hop=0, root=0, relay=0, mic=0):
    return (retry << 15) | (resp << 14) | (tlv_ << 13) | (inb << 12) | (outb << 11) | (hop << 10) | (root << 9) | (relay << 8) | (mic << 7)

def cm_head(flags, hops=1, mid=0x1234, relay=False):
    h = bytes([hops]) + H('>HH', mid, flags) + H('>H', 0x0001) + M(1) + H('>H', 0x0002) + M(2)
    if relay or flags & 0x100:
        h += H('>H', 0x0004) + M(3)
    return h

def ccm(mtype, flags=0, extra=b'', tlvs=b'', sub=0, **kw):
    return msg(0, (sub << 6) | mtype, cm_head(flags) + extra + tlvs, **kw)

def scm_adv(sflags, prio, bprio):
    return (M(30) + H('>H', sflags) + bytes([5, 3, prio, bprio]) + M(31) + H('>H', 0x55) +
            H('>I', 100000) + H('>H', 1500) + bytes([2, 30]))

def aaa(msgtype, rest=b'', auth=1, key=2, status=0):
    return H('>H', 0x0040) + M(40) + bytes([msgtype, auth, key, status]) + rest

def rrm_msg(mtype, flags, tlvs=b'', sub=0):
    body = bytes([flags]) + H('>H', 0x2222) + H('>H', 0x0001) + M(1) + H('>H', 0x0002) + M(2)
    return msg(2, (sub << 6) | mtype, body + tlvs)

def nm_msg(mtype, flags, extra=b'', tlvs=b'', sub=0):
    body = bytes([1]) + H('>HH', 0x3333, flags) + H('>H', 0x0001) + M(1) + H('>H', 0x0002) + M(2)
    return msg(4, (sub << 6) | mtype, body + extra + tlvs)

def v0(typ, hostname=b'AP-1', ip=(192, 0, 2, 40), length=72):
    b = bytes([0, length]) + H('>H', typ) + M(1) + M(2) + b'\x00' * 22
    b += bytes(ip) + b'\x00\x00' + hostname.ljust(28, b'\x00')
    return b

def nested(n):
    """n nested container TLVs (depths 0..n-1) around one IPv4Address TLV."""
    inner = ccm_ip()
    for _ in range(n):
        inner = tlv(0, 9, b'\xc0\x00\x02\x09' + inner, container=True)
    return inner

def siblings(n):
    return tlv(0, 9, b'\xc0\x00\x02\x09' + tlv(7, 0, b'') * n, container=True)

def frames():
    ok, bad = [], []
    U = lambda p, sp=2887, dp=2887: udp_frame(p, sp, dp)
    # --- context management
    ok.append(U(ccm(1, cm_flags(root=1, outb=1), scm_adv(0x000f, 0x85, 0x81))))                       # 1 SCM advertise (all SCM flag bits, preferred/disable bits)
    ok.append(U(ccm(1, cm_flags(inb=1, hop=1), scm_adv(0x0000, 0x05, 0x01), sub=1)))                  # 2 reply, no flags
    ok.append(U(ccm(2, cm_flags(retry=1, resp=1))))                                                   # 3 CCM advertise
    for t in (3, 4, 5, 6, 7, 8, 9, 0x0a):                                                              # 4-11
        ok.append(U(ccm(t, cm_flags(relay=1, resp=1) if t % 2 else cm_flags(), sub=t & 3)))
    ok.append(U(ccm(3, cm_flags(tlv_=1, relay=1), tlvs=ccm_null() + ccm_ip())))                       # 12 TLV flag, relay node
    ok.append(U(ccm(0x0b, cm_flags(tlv_=1, mic=1), aaa(2, bytes([0, 0, 1, 0]) + H('>H', 5) + b'\x01\x02\x03\x04\x05', status=0),
                    tlvs=sec_mic())))                                                                 # 13 cmAAA EAPOL-EAP + MIC
    ok.append(U(ccm(0x0b, cm_flags(), aaa(2, bytes([0, 0, 2, 1]), auth=2, key=3), sub=1)))             # 14 EAPOL, type != 0
    ok.append(U(ccm(0x0b, cm_flags(), aaa(3, b'accounting text'), sub=2)))                             # 15 Cisco proprietary
    ok.append(U(ccm(0x0b, cm_flags(), aaa(1), sub=3)))                                                 # 16 other AAA message
    ok.append(U(ccm(0x0c, cm_flags(mic=1), H('>H', 0x0040) + M(41) + b'\x00\x00', tlvs=sec_mic(8))))   # 17 cmPathInit, MIC only (no TLV flag)
    ok.append(U(ccm(0x0f, cm_flags(), bytes([2, 0]))))                                                # 18 cmWIDS
    ok.append(U(ccm(0x30, cm_flags())))                                                               # 19 unknown CCM type
    # --- security SAP
    ok.append(U(msg(1, 1, b'\x00' * 12)))                                                             # 20
    ok.append(U(msg(1, 7, b'\x00' * 12)))                                                             # 21
    # --- RRM
    ok.append(U(rrm_msg(1, 0x03, b''.join(rrm_tlvs()[:8]))))                                          # 22 rmReq, MIC+request/reply flags
    ok.append(U(rrm_msg(2, 0x00, b''.join(rrm_tlvs()[8:16]), sub=1)))                                 # 23
    ok.append(U(rrm_msg(3, 0x01, b''.join(rrm_tlvs()[16:]) + sec_mic(), sub=2)))                      # 24
    ok.append(U(rrm_msg(9, 0x00, ccm_null())))                                                     # 25 unknown RRM type
    # --- QoS, MIP
    ok.append(U(msg(3, 1, b'\x00' * 16)))                                                             # 26
    ok.append(U(msg(3, 2, b'\x00' * 16)))                                                             # 27
    ok.append(U(msg(5, 1, b'\x00' * 16)))                                                             # 28
    ok.append(U(msg(5, 2, b'\x00' * 16)))                                                             # 29
    ok.append(U(msg(7, 1, b'\x00' * 16)))                                                             # 30 unknown SAP
    # --- network management
    tl = nm_tlvs()
    ok.append(U(nm_msg(0x01, 0x0000)))                                                                # 31 nmAck
    ok.append(U(nm_msg(0x10, 0x8000, b'\x07\x00\x00\x00')))                                           # 32 nmConfigRequest, retry
    ok.append(U(nm_msg(0x11, 0x4000, b'\x07\x00\x00\x00', sub=1)))                                    # 33 ack required
    ok.append(U(nm_msg(0x20, 0x2000, H('>Q', 0x0102030405060708) + b'\x01\x00\x00\x00' + H('>H', 1) + M(50), tlvs=tl[0] + tl[1])))   # 34 AP registration + TLVs
    ok.append(U(nm_msg(0x21, 0x2080, H('>Q', 99) + bytes([3, 1, 0, 0]), tlvs=tl[2] + sec_mic())))     # 35 SCM state change, TLV + MIC
    ok.append(U(nm_msg(0x22, 0x0080, bytes([1, 2, 3, 0]), tlvs=sec_mic())))                           # 36 SCM keep active, MIC only
    ok.append(U(nm_msg(0x30, 0x2000, H('>Q', 100), tlvs=tl[3] + tl[4] + tl[5])))                      # 37 client event report
    ok.append(U(nm_msg(0x31, 0x2000, H('>I', 0x01020304), tlvs=tl[6] + tl[7])))                       # 38 refresh request
    ok.append(U(nm_msg(0x44, 0x0000)))                                                                # 39 unknown NM type
    # --- TLV varieties through the CCM group message
    allsec = sec_init() + sec_ctx_req() + sec_auth() + sec_ctx_rep() + sec_mic(0)
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=allsec)))                                               # 40 all security TLVs
    odd = (tlv(0, 5, b'\x01\x02', enc=True) + tlv(0, 6, b'', req=True) + tlv(3, 1, b'\x01\x02\x03') + tlv(5, 1, b'\x01') +
           tlv(4, 0x7f, b'') + tlv(1, 0x20, b'abc') + tlv(8, 1, b'\x01\x02') + tlv(15, 3, b'') +
           tlv(0, 0, b'', flags=0x3000))
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=odd)))                                                  # 41 unknown groups/types, flag bits
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 9, b'\xc0\x00\x02\x09', container=True) + ccm_ip())))   # 42 empty container
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 1, ccm_ip() + ccm_null(), container=True))))     # 43 container, unknown fixed part
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=nested(31))))                                           # 44 31 nested + innermost = 32 levels (depth 0..31)
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=siblings(150))))                                        # 45 reproducer: 150 sibling TLVs (assert at 101)
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=nested(30) + nested(5))))                               # 46 two chains
    # --- other transports
    ok.append(eth_frame(ccm(1, cm_flags(root=1), scm_adv(0x0003, 0x80, 0x40)), 0x872d))               # 47 ethertype
    lp = ccm(3, cm_flags(tlv_=1), tlvs=ccm_ip())
    llc = b'\xaa\xaa\x03\x00\x40\x96\x00\x00' + lp
    ok.append(eth_frame(struct.pack('>H', len(llc)) + llc, 0)[:12] + struct.pack('>H', len(llc)) + llc)   # 48 LLC OUI 00:40:96 PID 0
    ok.append(eth_frame(v0(0x4081), 0x872d))                                                          # 49 version 0, type 0x4081 (hostname)
    ok.append(eth_frame(v0(0x1234, length=40)[:40], 0x872d))                                          # 50 version 0, other type
    ok.append(U(v0(0x4081, b'Switch-with-long-name-0123456')))                                        # 51 version 0 over UDP, 28 byte name
    ok.append(U(ccm(3, cm_flags(tlv_=1), tlvs=ccm_ip()), 40000, 2887))                                # 52 different source port
    ok.append(U(bytes([0x41, 0, 0, 0]) + b'\x00' * 8))                                                # 53 version 0x41: not decoded further

    # ------------------------------------------------------------ malformed
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=nested(32))))                       # 1 33 levels: expert info
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=nested(33))))                       # 2 34 levels
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=nested(300))))                      # 3 deep recursion reproducer, far past the limit
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=nested(40) + ccm_ip())))            # 4 too deep then a sibling TLV
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 9, b'\x01\x02', length=6))))   # 5 IPv4 TLV cut short
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 0, b'\x00' * 4, length=400)))) # 6 length past the end
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 0, b'', length=2))))        # 7 length below the header (length-4 wraps)
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 0, b'', length=3))))        # 8
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 0, b'', length=4))))        # 9 length 4, empty
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 0, b'\x00\x00', length=0x20))))  # 10
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(1, 8, H('>QH', 1, 400) + b'\x00' * 4))))  # 11 MIC length past the end
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(1, 2, b'\x00' * 10))))         # 12 security TLV cut short
    bad.append(U(ccm(0x0b, cm_flags(), aaa(2, bytes([0, 0, 1, 0]) + H('>H', 600) + b'\x00' * 3))))  # 13 EAP length past the end
    bad.append(U(ccm(1, cm_flags(), scm_adv(0, 1, 1)[:20])))                       # 14 SCM advertise truncated
    bad.append(U(ccm(3, cm_flags(relay=1))[:20]))                                  # 15 relay node truncated
    bad.append(U(bytes([0xC1])))                                                    # 16 header cut off after the version
    bad.append(U(bytes([0xC1, 0, 0, 2, 0, 12])))                                    # 17 no message type
    bad.append(U(rrm_msg(1, 0x01, rrm(0x15, b'\x00' * 4))))                         # 18 frameReport TLV too short
    bad.append(U(rrm_msg(1, 0x01, rrm(0x19, b'\x00' * 6))))                         # 19 rpiHistReport length wraps
    bad.append(U(rrm_msg(1, 0x01, rrm(0x1e, b'\x00' * 10))))                        # 20 commonBeaconReport short
    bad.append(U(rrm_msg(1, 0x01, rrm(0x14, bytes([1, 2, 6, 200]) + H('>H', 50)))))  # 21 frameRequest count 200, no BSSIDs
    bad.append(U(nm_msg(0x20, 0x2000, tlvs=nm(0x20, b'\x00' * 10))))                # 22 client event TLV short
    bad.append(U(nm_msg(0x20, 0x2000, tlvs=nm(0x26, b'\x00' * 6))))                 # 23
    bad.append(U(nm_msg(0x20, 0x2000)[:30]))                                        # 24 NM message truncated
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=b'\x00\x00\x00')))                   # 25 3 bytes: below a TLV header, ignored
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=b'\x80\x09\x00\x04')))               # 26 container with no body
    bad.append(U(ccm(3, cm_flags(tlv_=1), tlvs=tlv(0, 9, b'\xc0\x00\x02\x09' + tlv(0, 0, b'', length=2), container=True))))  # 27 container, child length below header
    bad.append(U(v0(0x4081)[:30]))                                                  # 28 version 0, truncated
    return ok, bad

def main(out):
    ok, bad = frames()
    write_pcap(os.path.join(out, 'wlccp-coverage.pcap'), ok)
    write_pcap(os.path.join(out, 'wlccp-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
