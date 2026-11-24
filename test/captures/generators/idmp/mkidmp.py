#!/usr/bin/env python3
# Generates test/captures/idmp_coverage.pcap.gz, idmp_twopass.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic IDMP (X.519 Internet Directly Mapped Protocol)
coverage captures: TCP port 1102 (default).  The bind/request/result
operations are DAP (protocol OID 2.5.33.0).  Usage: mkidmp.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from c9lib import pcap, Flow

def tlv(tag, content=b''):
    n = len(content)
    if n < 128:
        ln = bytes([n])
    elif n < 256:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + struct.pack('>H', n)
    return bytes([tag]) + ln + content

def integer(v):
    return tlv(0x02, bytes([v]) if v < 128 else struct.pack('>H', v))
def enum(v): return tlv(0x0a, bytes([v]))
DAP = tlv(0x06, bytes([0x55, 0x21, 0x00]))                # OID 2.5.33.0
OTHER = tlv(0x06, bytes([0x55, 0x09, 0x01]))              # an unregistered protocol OID
def gname(s): return tlv(0xa0, tlv(0x82, s))              # [0] GeneralName: dNSName
def gname1(s): return tlv(0xa1, tlv(0x82, s))

def seg(data, final=1, version=1, length=None):
    return struct.pack('>BBI', version, final, len(data) if length is None else length) + data

SET0 = tlv(0x31)                                          # SET {}
BINDERR = tlv(0x31, tlv(0xa1, enum(2)))                    # DirectoryBindError: securityError
read_arg = tlv(0x31, tlv(0xa0, tlv(0x30)))                # ReadArgument: object = empty rdnSequence
read_res = tlv(0x31, tlv(0xa0, tlv(0x30, tlv(0x30))))     # ReadResult: entry with empty name

PDUS = {
 'bind':        tlv(0xa0, tlv(0x30, DAP + gname(b'client.example') + gname1(b'server.example') + tlv(0xa2, SET0))),
 'bind_plain':  tlv(0xa0, tlv(0x30, DAP + tlv(0xa2, SET0))),
 'bindResult':  tlv(0xa1, tlv(0x30, DAP + gname(b'server.example') + tlv(0xa1, SET0))),
 'bindResult2': tlv(0xa1, tlv(0x30, DAP + tlv(0xa1, SET0))),
 'bindError0':  tlv(0xa2, tlv(0x30, DAP + gname(b'server.example') + enum(0) + tlv(0xa1, BINDERR))),
 'bindError1':  tlv(0xa2, tlv(0x30, DAP + enum(1) + tlv(0xa1, BINDERR))),
 'request':     tlv(0xa3, tlv(0x30, integer(1) + integer(1) + read_arg)),
 'request2':    tlv(0xa3, tlv(0x30, integer(2) + tlv(0x06, bytes([0x55, 0x01, 0x02])) + read_arg)),    # global opcode
 'result':      tlv(0xa4, tlv(0x30, integer(1) + integer(1) + read_res)),
 'error':       tlv(0xa5, tlv(0x30, integer(1) + integer(7) + SET0)),
 'unbind':      tlv(0xa7, tlv(0x05)),
 'startTLS':    tlv(0xa9, tlv(0x05)),
}
for i in range(14):
    PDUS['reject%d' % i] = tlv(0xa6, tlv(0x30, integer(3) + enum(i)))
for i in range(7):
    PDUS['abort%d' % i] = tlv(0xa8, enum(i))
for i in range(4):
    PDUS['tls%d' % i] = tlv(0xaa, enum(i))

frames = []
conn_n = [0]
def conn(fn):
    f = Flow(41102 + conn_n[0], 1102, frames, cip='10.1.0.1', sip='10.1.0.2')
    conn_n[0] += 1
    f.open(); fn(f); f.close()

def main(f):
    f.s2c(seg(PDUS['unbind']))
    f.c2s(seg(PDUS['bind']))                       # bind with DAP argument; saves the protocol id
    f.s2c(seg(PDUS['bindResult']))
    f.c2s(seg(PDUS['request']))
    f.s2c(seg(PDUS['result']))
    f.c2s(seg(PDUS['request2']))
    f.s2c(seg(PDUS['error']))
    f.c2s(seg(PDUS['bind_plain']))
    f.s2c(seg(PDUS['bindResult2']))
    f.s2c(seg(PDUS['bindError0']))
    f.s2c(seg(PDUS['bindError1']))
    f.c2s(seg(tlv(0xa0, tlv(0x30, OTHER + tlv(0xa2, SET0)))))     # bind with an unregistered protocol
    f.c2s(seg(PDUS['request']))
    for i in range(14):
        f.s2c(seg(PDUS['reject%d' % i]))
    for i in range(7):
        f.s2c(seg(PDUS['abort%d' % i]))
    f.c2s(seg(PDUS['startTLS']))
    for i in range(4):
        f.s2c(seg(PDUS['tls%d' % i]))
    f.c2s(seg(PDUS['unbind']))
    # several IDMP PDUs in one TCP segment
    f.c2s(seg(PDUS['bind']) + seg(PDUS['request']) + seg(PDUS['unbind']))
    # a PDU over two TCP segments
    m = seg(PDUS['request'])
    f.c2s(m[:9]); f.c2s(m[9:])
    # a segment header split after three octets
    m = seg(PDUS['result'])
    f.s2c(m[:3]); f.s2c(m[3:])
    # IDMP segmentation: a bind in two IDMP segments, in separate TCP segments
    b = PDUS['bind']
    f.c2s(seg(b[:10], final=0))
    f.c2s(seg(b[10:], final=1))
    # three segments, the first two in one TCP segment
    r = PDUS['request']
    f.c2s(seg(r[:5], final=0) + seg(r[5:9], final=0))
    f.c2s(seg(r[9:], final=1))
    # a segment of length 0 and a final segment with no data of its own
    f.c2s(seg(r[:6], final=0))
    f.c2s(seg(b'', final=0))
    f.c2s(seg(r[6:], final=1))
conn(main)
pcap(os.path.join(sys.argv[1], 'idmp-coverage.pcap'), frames)

# ---------- the review reproducer, a capture of its own ----------
# On the first pass A completes in frame B and B in frame C; the reassembly key is
# only (frame, id), so on the second pass the final segment in frame B finds B's
# head: process_reassembled_data() gives NULL. The output of the two passes differs.
frames = []
def twopass(f):
    pdu = bytes([0xa0, 0x06, 0x06, 0x03, 0x55, 0x09, 0x01, 0x05, 0x00])
    f.c2s(seg(pdu[:4], final=0))
    f.c2s(seg(pdu[4:], final=1) + seg(pdu[:4], final=0))
    f.c2s(seg(pdu[4:], final=1))
conn(twopass)
pcap(os.path.join(sys.argv[1], 'idmp-twopass.pcap'), frames)
import gzip
with open(os.path.join(sys.argv[1], 'idmp-twopass.pcap'), 'rb') as fi, gzip.GzipFile(os.path.join(sys.argv[1], 'idmp_twopass.pcap.gz'), 'wb', 9, mtime=0) as fo:
    fo.write(fi.read())

frames = []; conn_n[0] = 100
def bad(f):
    f.c2s(seg(PDUS['request']))                          # a request before any bind: protocol unknown (differs in -2)
    f.c2s(seg(b'\xa0\xff\xff\xff'))                    # BER length past the data
    f.c2s(seg(b'\xa0\x05\x30\x03'))
    f.c2s(seg(b'\xab\x00'))                            # unknown CHOICE tag
    f.c2s(seg(tlv(0xa0, tlv(0x30, DAP + tlv(0xa2, tlv(0x31, b'\xff\xff'))))))   # garbage in the DAP argument
    f.c2s(seg(tlv(0xa3, tlv(0x30, integer(1) + integer(1) + b'\xff\x7f'))))
    f.c2s(seg(tlv(0xa6, tlv(0x30, integer(3) + enum(99)))))
    f.c2s(seg(tlv(0xa8, enum(99))))
    f.c2s(seg(tlv(0xa4, tlv(0x30, integer(1)))))
    f.c2s(seg(b''))
    f.c2s(seg(b'\xa7', version=9))                     # unknown version octet
    f.c2s(seg(b'\xa7\x02\x05\x00', length=1000)[:12])  # length larger than the data
    f.c2s(struct.pack('>BB', 1, 1))                    # header cut short
conn(bad)
pcap(os.path.join(sys.argv[1], 'idmp-coverage-malformed.pcap'), frames)
