#!/usr/bin/env python3
# Generates test/captures/nb_rtpmux_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

# ---- Nb RTP multiplexing (3GPP TS 29.414) in Exported PDUs ----
# The dissector has no port of its own (the UDP port preference is empty),
# so the frames are Exported PDU records (link type 252) that name the
# "nb_rtpmux" dissector.
def epdu(payload):
    name = b'nb_rtpmux'
    name += b'\0' * (-len(name) % 4)         # the tag length includes the padding
    tag = struct.pack('!HH', 12, len(name)) + name
    return tag + struct.pack('!HH', 0, 0) + payload

def rtp(seq, ts, pt=0, ssrc=0x11223344, payload=b'\x55' * 20, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def mux(dst, src, data, rbit=0):
    '''Format without header compression (T = 0).'''
    return struct.pack('!HBH', dst // 2, len(data), (rbit << 15) | (src // 2)) + data

def cmux(dst, src, sn, ts, data=b'', rbit=0, length=None):
    '''Format with RTP header compression (T = 1): length covers SN, TS and data.'''
    n = len(data) + 3 if length is None else length
    return struct.pack('!HBHBH', 0x8000 | (dst // 2), n, (rbit << 15) | (src // 2), sn, ts) + data

main = []
bad = []
# one RTP packet per mux packet, R bit clear and set
main.append(epdu(mux(5004, 5006, rtp(1, 160))))
main.append(epdu(mux(5004, 5006, rtp(2, 320), rbit=1)))
# several multiplexed RTP packets, different payload types and sizes
main.append(epdu(mux(5004, 5006, rtp(3, 480)) + mux(6000, 6002, rtp(9, 960, 8, payload=b'\xd5' * 40))))
main.append(epdu(mux(5004, 5006, rtp(4, 640)) + mux(6000, 6002, rtp(10, 1120, 8))
                 + mux(7000, 7002, rtp(100, 1000, 96, 0x55667788, b'\x01\x02\x03'), 1)))
# a zero length entry carries no RTP payload; the largest port values
main.append(epdu(mux(5004, 5006, b'') + mux(65534, 65534, rtp(5, 800), 1)))
main.append(epdu(mux(0, 0, rtp(6, 960))))
# header compression: the smallest data (length 4), with data, R bit, several in one packet
main.append(epdu(cmux(5004, 5006, 7, 1280, b'\x01')))
main.append(epdu(cmux(5004, 5006, 8, 1440, b'\xaa' * 16)))
main.append(epdu(cmux(5004, 5006, 9, 1600, b'\xbb' * 33, rbit=1)))
main.append(epdu(cmux(5004, 5006, 10, 1760, b'\xcc' * 4) + cmux(6000, 6002, 11, 1920, b'\xdd' * 8)))
# the two kinds in one packet, compressed first and last
main.append(epdu(cmux(5004, 5006, 12, 2080, b'\xee') + mux(6000, 6002, rtp(13, 2240))))
main.append(epdu(mux(6000, 6002, rtp(14, 2400)) + cmux(5004, 5006, 13, 2560, b'\x02')))
# a zero length uncompressed entry followed by one with RTP
main.append(epdu(mux(5004, 5006, b'') + mux(5004, 5006, rtp(15, 2720))))

# reproducer of "NB_RTPMUX: Check the length of compressed packets, fix the R bit":
# R bit set on an uncompressed entry (it used to be shown with length 1)
# is main frame 2; a compressed entry with length 1 or 2 is malformed:
bad.append(epdu(cmux(5004, 5006, 1, 1, b'', length=1) + b'\0' * 4))
bad.append(epdu(cmux(5004, 5006, 1, 1, b'', length=2) + b'\0' * 4))
# length 3: a valid compressed header without data, reported as "Length too short" (see README)
bad.append(epdu(cmux(5004, 5006, 7, 1280)))
bad.append(epdu(mux(6000, 6002, rtp(14, 2400)) + cmux(5004, 5006, 13, 2560, b'')))
# entry that claims more data than the packet holds
bad.append(epdu(struct.pack('!HBH', 2502, 200, 2503) + rtp(1, 1)))
bad.append(epdu(cmux(5004, 5006, 1, 1, b'', length=100)))
# too short for the dissector (needs 6 bytes)
bad.append(epdu(b'\x00\x01\x02\x03\x04'))
# trailing bytes that are too few for another entry are ignored
bad.append(epdu(mux(5004, 5006, rtp(1, 1)) + b'\x00\x01\x02\x03\x04'))
# RTP payload that is not RTP at all
bad.append(epdu(mux(5004, 5006, b'\x01\x02\x03\x04')))

def pcap(name, pdus):
    write_pcap(name, pdus, linktype=252)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'nb_rtpmux-coverage.pcap'), main)
    gz(os.path.join(out, 'nb_rtpmux-coverage.pcap'))
    os.rename(os.path.join(out, 'nb_rtpmux-coverage.pcap.gz'), os.path.join(out, 'nb_rtpmux_coverage.pcap.gz'))
    pcap(os.path.join(out, 'nb_rtpmux-coverage-malformed.pcap'), bad)
