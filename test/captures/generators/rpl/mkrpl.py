#!/usr/bin/env python3
# Generates test/captures/rpl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the RPL coverage captures: mkrpl.py <outdir>
# Every packet is built with struct; nothing comes from a real network.
# RPL (Remote Program Load) is carried in 802.3 frames with LLC DSAP 0xFC.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pk import Cap

def vec(vtype, body=b''):
    '''RPL vector: 16 bit length (including this header), 16 bit type.'''
    return struct.pack('>HH', 4 + len(body), vtype) + body

def llc(payload, extra=0, src=1, dst=2, dsap=0xfc):
    '''802.3 + LLC UI frame; extra adds octets to the 802.3 length that the
    payload does not fill (they are padding that RPL sees as trailing data).'''
    data = bytes([dsap, 0xfc, 0x03]) + payload
    return (b'\x02\x00\x00\x00\x00' + bytes([dst]) + b'\x02\x00\x00\x00\x00' + bytes([src])
            + struct.pack('>H', len(data)) + data)

LMAC = bytes.fromhex('020000000010')
SMAC = bytes.fromhex('020000000020')

def corr(v=0x01020304): return vec(0x4003, struct.pack('>I', v))
def lmac(): return vec(0x4006, LMAC)
def lsap(s=0xf8): return vec(0x4007, bytes([s]))
def fsize(n=1500): return vec(0x4009, struct.pack('>H', n))
def cclass(c=0x0001): return vec(0x400a, struct.pack('>H', c))
def resp(c=0): return vec(0x400b, bytes([c]))
def setmac(): return vec(0x400c, SMAC)
def seqhdr(n): return vec(0x4011, struct.pack('>I', n))
def fdata(d): return vec(0x4018, d)
def linfo():
    return vec(0xc005, bytes(range(8)) + struct.pack('>HHH', 0x0021, 640, 0x0102)
               + bytes.fromhex('0a0b0c0d0e0f') + struct.pack('>H', 0x1234) + b'ADAPTER001')
def lhdr(): return vec(0xc014, struct.pack('>IIB', 0x1000, 0x2000, 0x81))

def nest(levels, leaf):
    '''A chain of containers (type 4) levels deep, the innermost holding leaf.'''
    v = leaf
    for _ in range(levels):
        v = vec(0x0004, v)
    return v

def main(out):
    cap = Cap()
    # FIND command: search vector (correlator, loader SAP), connect info
    cap.add(llc(vec(1, vec(4, corr() + lsap()) + vec(8, fsize() + cclass() + linfo()))))
    # FOUND frame: search vector with loader address and correlator
    cap.add(llc(vec(2, vec(4, corr(0xa1a2a3a4) + lmac()))))
    # FOUND frame carrying the response correlator and a set address vector
    cap.add(llc(vec(2, vec(4, corr(9) + resp(3) + setmac()), )))
    # Send File Request: correlator, sequence header and the loader header
    cap.add(llc(vec(0x10, corr(7) + seqhdr(1) + lhdr())))
    # File Data Response: sequence header and 100 octets of data
    cap.add(llc(vec(0x20, corr(7) + seqhdr(2) + fdata(bytes(i & 0xff for i in range(100))))))
    # Connect Info Vector as a top level message, and a Search Vector
    cap.add(llc(vec(8, fsize(512) + cclass(0x8000) + resp(1))))
    cap.add(llc(vec(4, corr(1) + lmac() + lsap(0x00))))
    # Every leaf type as the top level type of the message
    cap.add(llc(corr(0x11223344)))
    cap.add(llc(lmac()))
    cap.add(llc(lsap(0xe0)))
    cap.add(llc(fsize(4096)))
    cap.add(llc(cclass(0x4000)))
    cap.add(llc(resp(255)))
    cap.add(llc(setmac()))
    cap.add(llc(seqhdr(0xffffffff)))
    cap.add(llc(fdata(b'file data')))
    cap.add(llc(fdata(b'')))
    cap.add(llc(linfo()))
    cap.add(llc(lhdr()))
    # Leaf types with data behind the fixed part (shown as Data)
    cap.add(llc(vec(0x4003, struct.pack('>I', 5) + b'extra')))
    cap.add(llc(vec(0x4007, b'\xf8\x01\x02')))
    # Unknown type at the top level, and an unknown vector inside a container
    cap.add(llc(vec(0x1234, b'unknown payload')))
    cap.add(llc(vec(1, vec(4, corr() + vec(0x7777, b'\x01\x02\x03\x04') + lsap()) + vec(0x6666))))
    # RPL data after the RPL message (802.3 length longer than the RPL length)
    p = vec(2, vec(4, corr(3)))
    cap.add(llc(p + b'trailing octets'))
    # Nesting up to the limit of 8 containers
    cap.add(llc(nest(7, corr(1))))
    # Vector with length 0 (loop ends), and with length 4 only (empty)
    cap.add(llc(struct.pack('>HH', 12, 1) + struct.pack('>HH', 0, 4) + b'\0\0\0\0'))
    cap.add(llc(vec(1, vec(4))))
    # Frame 27 on: nesting deeper than 8 (the reproducer of "RPL: Bound the
    # container recursion"): "rpl.nesting_too_deep" expert info (an error)
    cap.add(llc(nest(10, corr(1))))
    cap.add(llc(nest(300, corr(1))))
    cap.write(os.path.join(out, 'rpl-coverage.pcap'))

    # Malformed
    cap = Cap()
    # Length field larger than the frame, vector length past the message
    cap.add(llc(struct.pack('>HH', 200, 1) + vec(4, corr())))
    cap.add(llc(struct.pack('>HH', 40, 1) + struct.pack('>HH', 500, 4) + corr()))
    cap.add(llc(struct.pack('>HH', 8, 0x4003) + b'\0\0'))               # leaf too short
    cap.add(llc(struct.pack('>HH', 6, 0xc005) + b'\0\0'))
    cap.add(llc(struct.pack('>HH', 6, 0x4006) + b'\0\0'))
    cap.add(llc(struct.pack('>HH', 4, 0x4018) + b''))                    # data of length 0
    cap.add(llc(struct.pack('>HH', 2, 0x4018)))                           # len - 4 underflow
    cap.add(llc(struct.pack('>HH', 5, 1) + b'\x00'))                    # vector header cut short
    cap.add(llc(b'\x00\x08'))                                             # only a length
    cap.add(llc(vec(1, vec(4, corr())))[:-3], 0)
    cap.write(os.path.join(out, 'rpl-coverage-malformed.pcap'))

main(sys.argv[1])
