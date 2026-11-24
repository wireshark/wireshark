#!/usr/bin/env python3
# Generates test/captures/mrp_msrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MRP-MSRP coverage captures.  Usage: mkmrp-msrp.py <outdir> [-v]
MSRP is carried directly in Ethernet frames (ethertype 0x22ea, destination
01:80:c2:00:00:0e).  Nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from r13_pcaplib import eth, write_pcap

frames = []; marks = []
def mark(n): marks.append((n, len(frames) + 1))
def F(payload):
    frames.append(eth(payload, 0x22ea, b'\x02\0\0\0\0\x01', b'\x01\x80\xc2\x00\x00\x0e'))

TALKER_ADV, TALKER_FAILED, LISTENER, DOMAIN = 1, 2, 3, 4

def packed3(events):
    out = b''
    for i in range(0, len(events), 3):
        a, b, c = (list(events[i:i + 3]) + [0, 0])[:3]
        out += bytes([36 * a + 6 * b + c])
    return out

def packed4(events):
    out = b''
    for i in range(0, len(events), 4):
        a, b, c, d = (list(events[i:i + 4]) + [0, 0, 0])[:4]
        out += bytes([(a << 6) | (b << 4) | (c << 2) | d])
    return out

def vector(first, events, leave_all=0, fours=None, n=None):
    n = len(events) if n is None else n
    v = struct.pack('!H', (leave_all << 13) | n) + first + packed3(events)
    if fours is not None: v += packed4(fours)
    return v

def message(atype, alen, vectors, list_len=None):
    body = b''.join(vectors) + b'\0\0'
    return bytes([atype, alen]) + struct.pack('!H', len(body) if list_len is None else list_len) + body

def pdu(*messages, version=0):
    return bytes([version]) + b''.join(messages) + b'\0\0'

def sid(n): return bytes([0x00, 0x1b, 0x21, 0x00, 0x00, 0x01, 0x00, n])
def talker(n, prio=3, rank=1, latency=1000):
    return (sid(n) + bytes([0x91, 0xe0, 0x01, 0x00, 0x00, n]) + struct.pack('!H', 0x0002)   # DA, VLAN 2
            + struct.pack('!HH', 224, 8) + bytes([(prio << 5) | (rank << 4)]) + struct.pack('!I', latency))
def failed(n, code):
    return talker(n) + bytes([0x00, 0x1b, 0x21, 0xff, 0xfe, 0x00, 0x00, 0x01]) + bytes([code])

def build_main():
    mark('Domain')
    F(pdu(message(DOMAIN, 4, [vector(bytes([6, 3]) + struct.pack('!H', 2), [1])])))                  # SR class A, priority 3, VID 2
    F(pdu(message(DOMAIN, 4, [vector(bytes([5, 2]) + struct.pack('!H', 2), [1, 2, 3, 4])])))          # SR class B
    F(pdu(message(DOMAIN, 4, [vector(bytes([4, 2]) + struct.pack('!H', 3), [0, 5], leave_all=1)])))
    F(pdu(message(DOMAIN, 4, [vector(bytes([c, 0]) + struct.pack('!H', 1), [1]) for c in (3, 2, 1, 0, 7)])))   # other classes, several vectors
    mark('Talker Advertise')
    F(pdu(message(TALKER_ADV, 25, [vector(talker(1), [1, 2, 3])])))
    F(pdu(message(TALKER_ADV, 25, [vector(talker(2, prio=2, rank=0, latency=0xffffffff), [0, 1, 2, 3, 4, 5, 1], leave_all=1)])))
    F(pdu(message(TALKER_ADV, 25, [vector(talker(3, 1, 0), [1]), vector(talker(4, 7, 1), [2, 2])])))
    mark('Talker Failed (every failure code)')
    F(pdu(message(TALKER_FAILED, 34, [vector(failed(1, 1), [1])])))
    F(pdu(message(TALKER_FAILED, 34, [vector(failed(2, c), [1, 2]) for c in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11)])))
    F(pdu(message(TALKER_FAILED, 34, [vector(failed(3, c), [0]) for c in (12, 13, 14, 15, 16, 17, 18, 19, 20)], )))
    mark('Listener (three- and four-packed events)')
    F(pdu(message(LISTENER, 8, [vector(sid(1), [1, 2, 3], fours=[0, 1, 2])])))
    F(pdu(message(LISTENER, 8, [vector(sid(2), [0, 1, 2, 3, 4, 5, 1], fours=[0, 1, 2, 3, 3, 2, 1], leave_all=1)])))
    F(pdu(message(LISTENER, 8, [vector(sid(3), [1], fours=[3]), vector(sid(4), [4, 4, 4, 4], fours=[1, 1, 1, 1])])))
    mark('several messages in one PDU')
    F(pdu(message(DOMAIN, 4, [vector(bytes([6, 3]) + struct.pack('!H', 2), [1])]),
          message(TALKER_ADV, 25, [vector(talker(5), [1, 2]), vector(talker(6), [3])]),
          message(LISTENER, 8, [vector(sid(5), [1, 2, 3, 4], fours=[2, 2, 2, 2])]),
          message(TALKER_FAILED, 34, [vector(failed(7, 5), [1])])))
    F(pdu(message(DOMAIN, 4, [vector(bytes([5, 2]) + struct.pack('!H', 2), [1])]),
          message(LISTENER, 8, [vector(sid(9), [2], fours=[1])]), version=1))
    mark('no messages')
    F(pdu())

def build_malformed():
    global frames, marks
    frames = []; marks = []
    mark('unknown attribute type (warning, no events decoded)')
    F(pdu(message(0x09, 8, [vector(sid(1), [1, 2])])))
    F(pdu(message(0x00 + 5, 4, [vector(b'\0\0\0\0', [1])])))
    mark('truncated and missing end marks')
    F(b'\x00')
    F(b'\x00\x01\x08\x00')
    F(b'\x00\x03\x08\x00\x0b\x00\x03' + sid(1))                                  # vector with its events missing
    F(b'\x00' + message(LISTENER, 8, [vector(sid(1), [1, 2, 3], fours=[0, 1, 2])])[:-2])   # list end mark missing
    F(b'\x00' + message(LISTENER, 8, [vector(sid(1), [1, 2, 3], fours=[0, 1, 2])]))        # no message end mark
    F(b'\x00' + bytes([LISTENER, 8]) + struct.pack('!H', 0x0fff) + vector(sid(1), [1], fours=[1]))   # list length larger than the data
    F(b'\x00' + bytes([LISTENER, 8, 0, 0]) + b'\0\0\0\0')                         # list length 0 followed by end marks
    F(b'\x00' + bytes([TALKER_ADV, 25]) + struct.pack('!H', 40) + struct.pack('!H', 0x1fff) + talker(1) + b'\x01')   # 8191 values announced
    F(b'\x00' + bytes([TALKER_FAILED, 34]) + struct.pack('!H', 40) + vector(failed(1, 3), [1])[:30])   # talker failed cut in the failure info
    F(b'\x00' + bytes([DOMAIN, 4]) + struct.pack('!H', 9) + vector(b'\x06\x03\x00', [1]))   # domain first value cut
    F(b'\x00' + bytes([TALKER_ADV, 12]) + struct.pack('!H', 40) + vector(talker(1)[:12], [1, 2, 3]) + b'\0\0\0\0')   # talker with attribute length 12
    F(b'\x00' + bytes([LISTENER, 255]) + struct.pack('!H', 40) + vector(sid(1), [1], fours=[1]) + b'\0\0\0\0')       # attribute length larger than the data
    F(b'\x00' + message(DOMAIN, 4, [vector(bytes([6, 3]) + struct.pack('!H', 2), [1])])[:-2] + b'\0')           # one octet end mark

if __name__ == '__main__':
    out = sys.argv[1]
    build_main()
    write_pcap(os.path.join(out, 'mrp-msrp-coverage.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'frames'); print(marks)
    frames = []; marks = []
    build_malformed()
    write_pcap(os.path.join(out, 'mrp-msrp-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'malformed frames'); print(marks)
