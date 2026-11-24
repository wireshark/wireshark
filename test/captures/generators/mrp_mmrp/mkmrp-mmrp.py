#!/usr/bin/env python3
# Generates test/captures/mrp_mmrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MRP-MMRP coverage captures.  Usage: mkmrp-mmrp.py <outdir> [-v]
MMRP is carried directly in Ethernet frames (ethertype 0x88f6, destination
01:80:c2:00:00:20).  Nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from r13_pcaplib import eth, write_pcap

frames = []; marks = []
def mark(n): marks.append((n, len(frames) + 1))
def F(payload):
    frames.append(eth(payload, 0x88f6, b'\x02\0\0\0\0\x01', b'\x01\x80\xc2\x00\x00\x20'))

def packed3(events):
    """ThreePackedEvents: three events per octet, value = 36a + 6b + c."""
    out = b''
    for i in range(0, len(events), 3):
        a, b, c = (list(events[i:i + 3]) + [0, 0])[:3]
        out += bytes([36 * a + 6 * b + c])
    return out

def vector(first, events, leave_all=0, n=None):
    n = len(events) if n is None else n
    return struct.pack('!H', (leave_all << 13) | n) + first + packed3(events)

def message(atype, alen, vectors):
    return bytes([atype, alen]) + b''.join(vectors) + b'\0\0'

def mac(a): return bytes([0x01, 0x00, 0x5e, 0x00, 0x00, a])

def pdu(*messages, version=0):
    return bytes([version]) + b''.join(messages) + b'\0\0'

MAC, SVC = 2, 1

def build_main():
    mark('MAC attribute')
    F(pdu(message(MAC, 6, [vector(mac(1), [1, 2, 3])])))                      # one vector, three events
    F(pdu(message(MAC, 6, [vector(mac(2), [0])])))                            # one event
    F(pdu(message(MAC, 6, [vector(mac(3), [1, 4])])))                         # two events
    F(pdu(message(MAC, 6, [vector(mac(4), [0, 1, 2, 3, 4, 5, 1])])))          # all six events, 7 values
    F(pdu(message(MAC, 6, [vector(mac(5), [2, 2, 2], leave_all=1)])))         # Leave All
    F(pdu(message(MAC, 6, [vector(mac(6), [], leave_all=1)])))                # Leave All, no values
    mark('several vector attributes in one message')
    F(pdu(message(MAC, 6, [vector(mac(7), [1, 1]), vector(mac(9), [5, 4, 3, 2]), vector(mac(11), [0, 0, 0])])))
    mark('Service Requirement attribute')
    F(pdu(message(SVC, 1, [vector(b'\x00', [1])])))                           # Forward All Groups
    F(pdu(message(SVC, 1, [vector(b'\x01', [1, 2, 3, 4]), vector(b'\x02', [0])])))
    mark('several messages in one PDU')
    F(pdu(message(SVC, 1, [vector(b'\x00', [1])]),
          message(MAC, 6, [vector(mac(20), [1, 2, 3]), vector(mac(21), [4])]),
          message(MAC, 6, [vector(mac(30), [0, 0, 1, 1, 2, 2], leave_all=1)])))
    F(pdu(message(MAC, 6, [vector(mac(40), [3])]), message(SVC, 1, [vector(b'\x01', [5, 5])]), version=1))
    mark('no messages')
    F(pdu())

def build_malformed():
    global frames, marks
    frames = []; marks = []
    mark('unknown attribute type (no first value or events decoded)')
    F(pdu(message(0x07, 4, [vector(b'\0\0\0\0', [1, 2])])))
    mark('truncated and missing end marks')
    F(b'\x00')                                                                  # protocol version only
    F(b'\x00\x02\x06')                                                          # message cut after the length
    F(b'\x00\x02\x06\x00\x03' + mac(1))                                         # vector with its events missing
    F(b'\x00' + message(MAC, 6, [vector(mac(1), [1, 2, 3])]))                   # no message end mark
    F(b'\x00' + bytes([MAC, 6]) + vector(mac(1), [1, 2, 3]))                    # no end marks at all
    F(b'\x00' + bytes([MAC, 6]) + struct.pack('!H', 0x1fff) + mac(1) + b'\x01') # 8191 values announced
    F(b'\x00' + bytes([MAC, 255]) + vector(mac(1), [1]) + b'\0\0\0\0')          # attribute length larger than the data
    F(b'\x00' + bytes([MAC, 0]) + vector(b'', [1, 2]) + b'\0\0\0\0')            # attribute length 0
    F(b'\x00' + bytes([MAC, 3]) + vector(b'\x01\x02\x03', [1, 2, 3]) + b'\0\0\0\0')   # MAC with a 3 octet attribute length
    F(b'\x00' + bytes([MAC, 6]) + vector(mac(1), [1, 2, 3]) + b'\0')            # one octet end mark
    F(b'\x00' + bytes([SVC, 1]) + struct.pack('!H', 5) + b'\x00\x01')           # Service Requirement events cut

if __name__ == '__main__':
    out = sys.argv[1]
    build_main()
    write_pcap(os.path.join(out, 'mrp-mmrp-coverage.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'frames'); print(marks)
    frames = []; marks = []
    build_malformed()
    write_pcap(os.path.join(out, 'mrp-mmrp-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'malformed frames'); print(marks)
