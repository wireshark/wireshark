#!/usr/bin/env python3
# Generates test/captures/idrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic IDRP (ISO 10747) coverage captures. IDRP PDUs are
carried in CLNP data PDUs (NLPID 0x81) over 802.3/LLC, with the NSAP
selector 0 of the destination.  Usage: mkidrp.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from c9lib import pcap, MAC1, MAC2

def clnp(payload, dst_nsel=0, dst=b'\x49\x00\x01\xaa\xbb', src=b'\x49\x00\x02\xcc\xdd'):
    d = dst + bytes([dst_nsel]); s = src + b'\x00'
    body = bytes([len(d)]) + d + bytes([len(s)]) + s
    hl = 9 + len(body)
    tot = hl + len(payload)
    return (bytes([0x81, hl, 1, 30, 0x1c]) + struct.pack('>HH', tot, 0) + body + payload)

def llc(p):
    return MAC2 + MAC1 + struct.pack('>H', 3 + len(p)) + b'\xfe\xfe\x03' + p

frames = []
def send(idrp_pdu, nsel=0):
    frames.append(llc(clnp(idrp_pdu, nsel)))

def pdu(ptype, body=b'', seq=1, ack=0, co=10, ca=10, li=None, nlpid=0x85):
    n = 30 + len(body) if li is None else li
    return (bytes([nlpid]) + struct.pack('>HBIIBB', n, ptype, seq, ack, co, ca)
            + bytes(range(16)) + body)

def lp(b):                       # one octet length prefix
    return bytes([len(b)]) + b

# ---------- OPEN ----------
RDI = b'\x47\x00\x01\x02\x03'
def open_body(rib=b'', nrib=0, confed=(), auth=0, authdata=b'', ver=1, hold=90, maxpdu=1500):
    return (struct.pack('>BHH', ver, hold, maxpdu) + lp(RDI) + bytes([nrib]) + rib
            + bytes([len(confed)]) + b''.join(lp(c) for c in confed)
            + bytes([auth]) + authdata)

send(pdu(1, open_body()))                                          # no RIB-Atts
send(pdu(1, open_body(confed=(b'\x47\x00\x09', b'\x47\x00\x0a'), auth=1, authdata=b'\x00' * 8)))
send(pdu(1, open_body(auth=2, authdata=b'secret-placeholder')))
# RIB-Atts: each simple attribute type, locally defined QOS, security
simple = [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 15, 16]
rib = bytes([len(simple)]) + bytes(simple)                         # one RIB-Att with 13 distinguishing attributes
qos = bytes([11]) + lp(b'\x47\x00\x01') + lp(b'\x01\x02') + lp(b'')
sec = bytes([14]) + b'\x00\x08' + lp(b'\x01\x02\x03') + lp(b'')
rib2 = bytes([2]) + qos + sec
rib3 = bytes([1, 8])                                               # unknown (transit delay: default case)
send(pdu(1, open_body(rib=rib + rib2 + rib3, nrib=3)))

# ---------- UPDATE ----------
def attr(flag, atype, value):
    return bytes([flag, atype]) + struct.pack('>H', len(value)) + value

def nlri(entries=((24, b'\x47\x00\x01'),), proto=b'\x81'):
    a = b''.join(bytes([bits]) + data for bits, data in entries)
    return b'\x01' + lp(proto) + struct.pack('>H', len(a)) + a

def update(attrs=(), withdrawn=(), nl=None):
    a = b''.join(attrs)
    return (struct.pack('>H', len(withdrawn)) + b''.join(struct.pack('>I', w) for w in withdrawn)
            + struct.pack('>H', len(a)) + a + (nlri() if nl is None else nl))

def seg(stype, rdis):
    body = b''.join(lp(r) for r in rdis)
    return bytes([stype]) + struct.pack('>H', len(body)) + body

def nexthop(server, hops):
    out = bytes([server])
    for ptype, proto, net, snpas in hops:
        out += bytes([ptype]) + lp(proto) + lp(net) + bytes([len(snpas)])
        for semis, data in snpas:
            out += bytes([semis]) + data
    return out

send(pdu(2, update()))                                             # keepalive-like UPDATE: no attributes
send(pdu(2, update(withdrawn=(1, 2, 0x01020304), attrs=())))
send(pdu(2, update(attrs=[attr(0x40, 1, b'\x00\x00\x00\x07\x05')])))    # route separator
send(pdu(2, update(attrs=[attr(0xc0, 2, b'')])))                        # ext info (fix: boolean)
send(pdu(2, update(attrs=[attr(0x40, 3, seg(1, [b'\x47\x00\x01', b'\x47\x00\x02']) + seg(2, [b'\x47\x00\x03']) + seg(3, [b'\x47\x00\x04']) + seg(4, [b'\x47\x00\x05']))])))
nh = nexthop(1, [(1, b'\x81', b'\x47\x00\x01\x00\x01', [(12, b'\x02\x00\x00\x00\x00\x01'), (13, b'\x02\x00\x00\x00\x00\x02\x03')]),
                 (1, b'\x81', b'\x47\x00\x02', [])])
send(pdu(2, update(attrs=[attr(0x40, 4, nh)])))                        # next hop with SNPAs
send(pdu(2, update(attrs=[attr(0x40, 4, nexthop(0, [(1, b'\x81', b'\x47\x00\x01\x00\x01', [])]))])))   # fix: server flag + one hop
send(pdu(2, update(attrs=[attr(0x40, 4, b'\x00')])))                    # server flag only, no hops
send(pdu(2, update(attrs=[attr(0xe0, 5, bytes([2]) + lp(b'\x47\x00\x01') + lp(b'\x47\x00\x02')),
                          attr(0x80, 6, bytes([1]) + lp(b'\x47\x00\x03')),
                          attr(0x80, 5, bytes([0])), attr(0x80, 6, bytes([0]))])))
send(pdu(2, update(attrs=[attr(0x80, 7, b'\x05'), attr(0x80, 8, b'\x00\x0a'), attr(0x80, 9, b'\x00\x00\x00\x03'),
                          attr(0x80, 10, b'\x00\x20'), attr(0x80, 12, b'\x01'), attr(0x80, 13, b'\x04'),
                          attr(0x80, 15, b'\x09'), attr(0x80, 16, b'\x02')])))
send(pdu(2, update(attrs=[attr(0x80, 11, lp(b'\x47\x00\x01') + lp(b'\x01\x02') + lp(b'\x07\x08\x09')),
                          attr(0x80, 14, lp(b'\x01\x02\x03') + lp(b'\xaa\xbb'))])))
# several NLRIs, several address infos, zero length address
send(pdu(2, update(attrs=[attr(0x40, 7, b'\x01')], nl=nlri([(24, b'\x47\x00\x01'), (16, b'\x47\x00'), (0, b''), (40, b'\x47\x00\x01\x02\x03')]))))
send(pdu(2, update(nl=nlri([], proto=b''))))                       # no address info

# ---------- ERROR ----------
send(pdu(3, b'\x01\x01'))                                          # every error code and a subcode
for code, subs in ((1, range(1, 8)), (2, (1, 11, 12)), (3, (0, 1)), (4, (1, 2)), (5, (1, 2))):
    for s in subs:
        send(pdu(3, bytes([code, s]) + (b'diag' if s == 1 else b'')))
send(pdu(3, bytes([9, 0x55]) + b'unknown error code'))
send(pdu(3, bytes([1, 99])))

# ---------- KEEPALIVE, CEASE, RIB REFRESH, unknown ----------
send(pdu(4))
send(pdu(5))
send(pdu(0x20, b'\x00\x01'))                                       # unknown PDU type
# RIB refresh: opcodes, empty attribute set (warning), with RIB-Atts
send(pdu(6, b'\x01\x00'))
qos_r = bytes([11]) + lp(b'\x47\x00\x01') + lp(b'\x01\x02') + lp(b'')
sec_r = bytes([14]) + b'\x00\x08' + lp(b'\x01\x02') + lp(b'\xaa')
send(pdu(6, b'\x02' + bytes([2]) + bytes([2]) + qos_r + sec_r + bytes([3, 1, 4, 16])))
send(pdu(6, b'\x00' + bytes([1]) + bytes([13]) + bytes([1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 15, 16])))
send(pdu(6, b'\x03' + bytes([1, 1, 8])))                           # unknown RIB-Att (default)
# an IDRP PDU not to NSEL 0 is left to the next dissector; another NLPID too
send(pdu(1, open_body()), nsel=1)
send(pdu(1, open_body(), nlpid=0x82))
# 32 bit sequence numbers and credits at the limits
send(pdu(4, seq=0xffffffff, ack=0xffffffff, co=255, ca=0))
# PDU with trailing octets in the CLNP payload after a KEEPALIVE
send(pdu(4, li=30) + b'trailing')
pcap(os.path.join(sys.argv[1], 'idrp-coverage.pcap'), frames)

# ---------- malformed ----------
frames = []
# unknown path attribute type is not skipped: its value is parsed as attributes (the review reproducer)
send(pdu(2, update(attrs=[attr(0x80, 0x63, b'\x80\x07\x00\x01')])))
send(pdu(2, update(attrs=[attr(0x80, 0x63, b'\xff\xff\xff\xff\xff')])))
# lengths past the data
send(pdu(1, open_body())[:35])
send(pdu(1, open_body())[:32])
send(pdu(1, open_body())[:-3])
send(pdu(2, update(attrs=[attr(0x40, 4, nh)]))[:45])
send(pdu(2, update())[:31])
send(pdu(2, update(attrs=[attr(0x40, 3, seg(1, [b'\x47\x00\x01']))]))[:50])
send(pdu(2, struct.pack('>H', 500) + b'\x00' * 4))                 # unfeasible routes past the end
send(pdu(2, struct.pack('>HH', 0, 500) + attr(0x40, 7, b'\x01')))  # path attributes length past the end
send(pdu(2, update(attrs=[attr(0x40, 3, b'\x01\xff\xff')])))      # path segment length past the end
send(pdu(2, update(attrs=[attr(0x40, 4, b'\x00\x01\xff')])))      # next hop proto length past the end
send(pdu(2, update(attrs=[attr(0x40, 5, b'\x05\xff')])))          # dist list rdi length past the end
send(pdu(2, update(attrs=[attr(0x40, 11, b'\xff')])))
send(pdu(2, update(attrs=[attr(0x40, 14, b'\xff')])))
send(pdu(2, update(nl=b'\x01\xff')))
send(pdu(2, update(nl=b'\x01\x01\x81\x00\x10\x40')))
send(pdu(1, open_body(rib=bytes([1, 11, 0xff]), nrib=1)))        # OPEN QOS with lengths past the end
send(pdu(1, open_body(rib=bytes([1, 14, 0, 0, 0xff]), nrib=1)))
send(pdu(1, open_body(rib=b'', nrib=5)))                          # RIB-Att count with no data
send(pdu(1, open_body(confed=(b'x',) * 3)[:-6]))
send(pdu(3, b''))
send(pdu(3, b'\x01'))
send(pdu(6, b''))
send(pdu(6, b'\x01\x02\x01'))
send(pdu(6, b'\x01\x01\x01\x0b\xff'))
send(pdu(6, b'\x01\x01\x01\x0e\x00\x00\xff'))
send(pdu(2, b''))
send(pdu(2, update(), li=3)[:8])
pcap(os.path.join(sys.argv[1], 'idrp-coverage-malformed.pcap'), frames)
