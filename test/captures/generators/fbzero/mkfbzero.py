#!/usr/bin/env python3
# Generates test/captures/fbzero_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Facebook Zero Protocol dissector
(packet-fbzero.c).

FB Zero is found by the TCP heuristic dissector "fb_zero" (enabled by
default): the first segment of a connection carries a public flags
octet, the version "QTV", a flags octet, a little endian length and the
message tag CHLO or SNOM. The heuristic then sets the conversation
dissector, so later segments of the connection are shown as encrypted
payload. Every packet is built with struct; nothing comes from a real
network, and no handshake key material is made up (the payloads are
zero octets).

Usage: mkfbzero.py <output directory>
  fbzero-coverage.pcap            handshakes with every tag, conversations
  fbzero-coverage-malformed.pcap  bad tag offsets, truncated messages
"""
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ipsum(h):
    s = sum(struct.unpack('>10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Conn:
    """One TCP connection; segment() builds frames with running sequence
    numbers."""
    def __init__(self, cport, sport=4444, cip='10.0.0.1', sip='10.0.0.2'):
        self.cport, self.sport = cport, sport
        self.cip = bytes(int(x) for x in cip.split('.'))
        self.sip = bytes(int(x) for x in sip.split('.'))
        self.seq = {True: 1000, False: 5000}

    def segment(self, from_client, payload, flags=0x18):
        sip, dip = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        ln = 20 + len(tcp) + len(payload)
        ip = struct.pack('>BBHHHBBH', 0x45, 0, ln, 1, 0x4000, 64, 6, 0) + sip + dip
        ip = ip[:10] + struct.pack('>H', ipsum(ip)) + ip[12:]
        self.seq[from_client] += len(payload)
        dst, src = (MAC_B, MAC_A) if from_client else (MAC_A, MAC_B)
        return dst + src + b'\x08\x00' + ip + tcp + payload


def tag(name, val):
    return name + val


def message(mtag, tags, flag=0, length=None, number=None, tag_end=None):
    """A handshake message body (from the flags octet): flag, length,
    message tag, number of tags, padding, tag/end offset pairs, values.
    tags is a list of (tag, value). Returns bytes starting at the 'unknown'
    flag octet."""
    pairs = b''
    vals = b''
    for i, (t, v) in enumerate(tags):
        vals += v
        end = len(vals) if tag_end is None or i not in tag_end else tag_end[i]
        pairs += t + struct.pack('<I', end)
    n = len(tags) if number is None else number
    body = mtag + struct.pack('<HH', n, 0) + pairs + vals
    if length is None:
        length = len(body)
    return bytes([flag]) + struct.pack('<I', length) + body


def hdr(puflags=0x01, version=b'QTV'):
    return bytes([puflags]) + version


def sni(name=b'www.example.org'):
    return (b'SNI\0', name)


VERS = (b'VERS', b'Q001')
AEAD = (b'AEAD', b'AESGS20PCC12XXXX'[:12] + b'')   # AESG S20P CC12
KEXS = (b'KEXS', b'C255P256')
SCID = (b'SCID', bytes(range(16)))
TIME = (b'TIME', struct.pack('<I', 1700000000))
ALPN = (b'ALPN', b'h2\0\0')
PUBS = (b'PUBS', struct.pack('<H', 32) + b'\x01\x02\x03' * 3)
NONC = (b'NONC', bytes(range(32)))
SNO = (b'SNO\0', b'\xaa' * 8)


def nopad(t, v):
    return (t, v)


chlo_full = [sni(), VERS, AEAD, KEXS, PUBS, NONC, ALPN, SCID, TIME, SNO]

main = []
c = Conn(40001)
# 1: CHLO with every known tag, puflags 0x01 (version present; fixed bug)
main.append(c.segment(True, hdr() + message(b'CHLO', chlo_full)))
# 2: SNOM server reply on the same conversation, flags 0x01, one message
main.append(c.segment(False, hdr() + message(b'SNOM', [VERS, SNO, SCID])))
# 3: SHLO is not a handshake tag here: payload on the conversation
main.append(c.segment(False, hdr() + message(b'SHLO', [VERS])))
# 4-5: encrypted payload (conversation dissector): with and without the
# version flag
main.append(c.segment(True, hdr(0x01) + bytes(range(40))))
main.append(c.segment(True, bytes([0x00]) + bytes(range(40))))
# 6: puflags bits other than the version bit, version flag clear
main.append(c.segment(True, bytes([0xfe]) + bytes(20)))
# 7: version flag but another version
main.append(c.segment(True, hdr(0x01, b'Q99') + bytes(30)))
# 8: too short for the dissector (2 octets): not handled
main.append(c.segment(True, b'\x01Q'))

# new connection: other puflags with the version bit, other bits set
c = Conn(40002)
main.append(c.segment(True, hdr(0x03) + message(b'CHLO', [sni(b'a.b'), VERS], flag=5)))
# two messages in one segment, the first with no tags (total tag length 0;
# the second used to be lost)
c = Conn(40003)
main.append(c.segment(True, hdr() + message(b'CHLO', []) +
                      message(b'CHLO', [sni(b'second.example')])))
# every tag empty (total tag length 0) followed by a second message
c = Conn(40004)
main.append(c.segment(True, hdr() + message(b'CHLO', [(b'SNI\0', b''), (b'SNO\0', b''),
                      (b'SCID', b'')]) + message(b'SNOM', [VERS])))
# unknown tags (note), unknown tag with data
c = Conn(40005)
main.append(c.segment(True, hdr() + message(b'CHLO', [(b'XYZW', b'\1\2\3'), (b'ABCD', b''),
                      sni()])))
# wrong tag lengths: warnings
c = Conn(40006)
main.append(c.segment(True, hdr() + message(b'CHLO', [
    (b'VERS', b'Q00'), (b'TIME', b'\1\2\3'), (b'ALPN', b'h2'),
    (b'NONC', b'\0' * 31), (b'PUBS', b'\1'),
    (b'AEAD', b'AESGX'), (b'KEXS', b'C25'), (b'PUBS', b'\1\0\2\3\4\5'),
    (b'AEAD', b'')])))
# AEAD and KEXS with unknown algorithms, PUBS with only the length
c = Conn(40007)
main.append(c.segment(True, hdr() + message(b'CHLO', [
    (b'AEAD', b'ABCDEFGH'), (b'KEXS', b'WXYZ'), (b'PUBS', b'\x03\0')])))
# no version flag handshake (flag octet 0, tag at offset 6)
c = Conn(40008)
main.append(c.segment(True, hdr() + message(b'CHLO', [sni()])))   # heuristic start
main.append(c.segment(True, bytes([0x00]) + message(b'CHLO', [sni(b'x.y')])))
main.append(c.segment(True, bytes([0x00]) + message(b'SNOM', [VERS])))
# a segment with flag octet 0 and no known message tag: payload
main.append(c.segment(True, bytes([0x00]) + b'\x00' + struct.pack('<I', 6) + b'ABCDEF'))
# a CHLO followed by a message with an unknown tag
c = Conn(40009)
main.append(c.segment(True, hdr() + message(b'CHLO', [VERS]) +
                      b'\x00' + struct.pack('<I', 6) + b'ABCDEF'))
# message tag only in the heuristic range but length > frame: not claimed
c = Conn(40010)
main.append(c.segment(True, hdr() + message(b'CHLO', [VERS], length=5000)))
# other port
c = Conn(40011, sport=7777)
main.append(c.segment(True, hdr() + message(b'CHLO', [sni(b'port7777')])))
# a segment that is not FB Zero at all
c = Conn(40012)
main.append(c.segment(True, b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'))
main.append(c.segment(True, b'short'))

malformed = []
c = Conn(41001)
# end offsets that go backwards
malformed.append(c.segment(True, hdr() + message(b'CHLO', [sni(), VERS, SNO],
                                                  tag_end={1: 2})))
# end offset past the end of the packet
c = Conn(41002)
malformed.append(c.segment(True, hdr() + message(b'CHLO', [sni(), VERS],
                                                  tag_end={1: 5000})))
# huge end offset (negative length when signed)
c = Conn(41003)
malformed.append(c.segment(True, hdr() + message(b'CHLO', [sni(), VERS],
                                                  tag_end={1: 0xfffffff0})))
c = Conn(41004)
malformed.append(c.segment(True, hdr() + message(b'CHLO', [sni()], tag_end={0: 0xffffffff})))
# tag number larger than the pairs present
c = Conn(41005)
malformed.append(c.segment(True, hdr() + message(b'CHLO', [sni()], number=60000)))
# message cut after the tag
c = Conn(41006)
malformed.append(c.segment(True, hdr() + message(b'CHLO', [], number=5)))
# a second message whose header is cut short
c = Conn(41007)
malformed.append(c.segment(True, hdr() + message(b'CHLO', [VERS]) + b'\x00\x05\0'))
# SNOM cut in the middle of the tag table
c = Conn(41008)
malformed.append(c.segment(True, hdr() + message(b'SNOM', [VERS, SNO, SCID], number=9)))

if __name__ == '__main__':
    out = sys.argv[1]
    pcap(os.path.join(out, 'fbzero-coverage.pcap'), main)
    pcap(os.path.join(out, 'fbzero-coverage-malformed.pcap'), malformed)
