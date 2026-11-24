#!/usr/bin/env python3
# Generates test/captures/smrse_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SMRSE coverage captures.  Usage: mksmrse.py <outdir>
All packets are synthetic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from berlib import boolean, gz, integer, octets, seq, TcpStream, tlv, write_pcap

def semi(digits):
    """semi-octet (swapped nibble) encoding of a digit string"""
    if len(digits) % 2: digits += 'F'
    return bytes(int(digits[i+1], 16) << 4 | int(digits[i], 16) for i in range(0, len(digits), 2))

def addr(atype, plan, digits=None, raw=None, tag=0x30):
    v = raw if raw is not None else semi(digits)
    return seq(integer(atype), integer(plan), octets(v), tag=tag)

def pdu(tag, body=b'', length=None, reserved=0x7e):
    if length is None: length = len(body) + 4
    return struct.pack('>BHB', reserved, length, tag) + body

def bind(pw=b'secret'):
    return seq(addr(1, 1, '46701234567'), tlv(0x13, pw))

def mt(mr=1, prio=False, mms=True, orig=None, dest=None, ud=b'hello', vmsc=None, tc=None):
    b = boolean(prio) + boolean(mms) + integer(mr)
    b += orig or addr(1, 1, '46701111111')
    b += dest or addr(2, 8, '0701234567')
    b += octets(ud)
    if vmsc is not None: b += addr(1, 1, vmsc, tag=0xa1)
    if tc is not None: b += integer(tc, tag=0x82)
    return seq(b)

def mo(mr=2, orig=None, ud=b'world', vmsc=None, imsi=None):
    b = integer(mr) + (orig or addr(1, 1, '46709999999')) + octets(ud)
    if vmsc is not None: b += addr(1, 1, vmsc, tag=0xa1)
    if imsi is not None: b += octets(imsi, tag=0x82)
    return seq(b)

def rperr(reason=22, mw=True, mr=3, alert=None, diag=None):
    b = integer(reason) + boolean(mw) + integer(mr)
    if alert is not None: b += addr(1, 1, alert, tag=0xa1)
    if diag is not None: b += octets(diag, tag=0x82)
    return seq(b)

def main(out):
    cs = TcpStream(33001, 4321)
    f = cs.handshake()
    def c(p): f.append(cs.c2s(p))
    def s(p): f.append(cs.s2c(p))
    c(pdu(1)); s(pdu(2))
    c(pdu(3, bind()))
    s(pdu(4, seq()))
    c(pdu(3, seq(addr(2, 8, '01234567890123456789'), tlv(0x13, b'x'))))   # address of 10 octets
    for r in (0, 1, 2, 3, 4, 5):
        s(pdu(5, seq(integer(r))))
    c(pdu(7, mt()))
    c(pdu(7, mt(5, True, False, addr(3, 9, '123'), addr(4, 4, '1'), b'x' * 164, '46700000000', 65535)))
    c(pdu(7, mt(6, False, True, addr(0, 0, '4670'), addr(1, 3, '4670'), b'\x00', None, 0)))
    c(pdu(7, mt(7, False, False, addr(1, 4, '467012345678901234'), addr(1, 1, '1'), b'y', '4670123', None)))
    c(pdu(8, mo()))
    c(pdu(8, mo(8, addr(1, 9, '46700000001'), b'z' * 20, '46701234', semi('240010123456789'))))
    c(pdu(8, mo(9, None, b'q', None, b'\x21\x43\x65\x87\x09')))
    s(pdu(9, seq(integer(2))))
    for r in (1, 9, 11, 13, 15, 19, 20, 21, 22, 29, 30, 36, 44, 60, 61, 70, 101, 103, 104):
        s(pdu(10, rperr(r, r % 2 == 0, r)))
    s(pdu(10, rperr(29, False, 9, '46701234567', b'\x01\x02\x03')))
    s(pdu(11, seq(addr(1, 1, '46701111111'), integer(77))))
    c(pdu(6, seq()))
    s(pdu(1))
    # two PDUs in one segment (only the first is dissected, no reassembly)
    c(pdu(2) + pdu(1))
    # PDU with a length field that is not the PDU length
    c(pdu(2, length=0xffff))
    write_pcap(os.path.join(out, 'smrse-coverage.pcap'), f)
    gz(os.path.join(out, 'smrse-coverage.pcap'), os.path.join(out, 'smrse_coverage.pcap.gz'))

    # malformed
    ms = TcpStream(33002, 4321)
    m = ms.handshake()
    def mc(p): m.append(ms.c2s(p))
    mc(pdu(1, reserved=0x7f))            # reserved byte is not 126: not SMRSE
    mc(pdu(12))                          # unknown tag: not SMRSE
    mc(pdu(0))
    mc(bytes([0x7e, 0, 4]))              # too short for the tag
    mc(pdu(3, b''))                      # Bind without a body
    mc(pdu(3, seq(addr(1, 1, raw=b'\x21' * 14), tlv(0x13, b'p'))))   # 14 octet address (capped at 10)
    mc(pdu(3, seq(addr(1, 1, raw=b''), tlv(0x13, b'p'))))            # empty address
    mc(pdu(3, tlv(0x30, b'\x30\x80')))   # indefinite length nested
    mc(pdu(7, seq(boolean(True), boolean(True), integer(1)) ))       # MT truncated
    mc(pdu(7, mt()[:20]))                # truncated inside the originating address
    mc(pdu(8, mo(2, None, b'a', None, b'')))     # empty IMSI
    mc(pdu(8, mo(2, None, b'a', None, b'\xff' * 9)))
    mc(pdu(10, seq(integer(1))))
    mc(pdu(9, seq(octets(b'x'))))        # message reference of the wrong type
    mc(pdu(5, seq(integer(1 << 40))))    # integer too long for 32 bits
    mc(pdu(4, b'\x04\x00'))              # wrong type
    write_pcap(os.path.join(out, 'smrse-coverage-malformed.pcap'), m)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
