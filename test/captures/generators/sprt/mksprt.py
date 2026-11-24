#!/usr/bin/env python3
# Generates test/captures/sprt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the SPRT coverage captures.  Usage: mksprt.py <outdir> [-v]
import struct
import sys
import os
from pcaplib import udp_pkt, write_pcap

def sprt(tc, seq, payload=b'', noa=0, base=0, acks=(), ssid=0, ext=0, pt=96, res=0):
    h = struct.pack('!BBHH', (ext << 7) | ssid, (res << 7) | pt, (tc << 14) | seq, (noa << 14) | base)
    for tcn, sqn in acks:
        h += struct.pack('!H', (tcn << 14) | sqn)
    return h + payload

def msg(mid, body=b'', rbit=0):
    return bytes([(rbit << 7) | mid]) + body

A = [192, 0, 2, 10]      # media address announced in the SDP
C = [192, 0, 2, 11]
pk = []
marks = []
def add(p, sport, dport, src=C, dst=A):
    pk.append(udp_pkt(sport, dport, p, src, dst))
def mark(name):
    marks.append((len(pk) + 1, name))

# ---- 1: SIP INVITE with SDP announcing udpsprt on 192.0.2.10:30100
mark('SIP/SDP')
sdp = ('v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n'
       'm=audio 30101 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n'
       'm=image 30100 udpsprt 120\r\na=sprtmap:120 v150mr/1\r\n').encode()
sip = ('INVITE sip:bob@192.0.2.10 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.11:5060;branch=z9hG4bK1\r\n'
       'Max-Forwards: 70\r\nFrom: <sip:alice@192.0.2.11>;tag=1\r\nTo: <sip:bob@192.0.2.10>\r\n'
       'Call-ID: sprt-1@192.0.2.11\r\nCSeq: 1 INVITE\r\nContact: <sip:alice@192.0.2.11>\r\n'
       'Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n' % len(sdp)).encode() + sdp
add(sip, 5060, 5060)

# ---- conversation set up by SDP, port 30100: any SSID / payload type
S = 30100
mark('SDP conversation: header variants')
add(sprt(0, 0), 40000, S)                                   # no payload, TC 0
add(sprt(1, 5, msg(0)), 40000, S)                           # NULL message
add(sprt(2, 7, msg(6, b'\x23\x04'), ssid=3, pt=50), 40000, S)  # other SSID, low payload type
add(sprt(3, 0, msg(7)), 40000, S)
add(sprt(1, 8, msg(1, b'\xff\xff'), noa=1, base=3, acks=[(1, 4)]), 40001, S)
add(sprt(2, 9, msg(1, b'\x00\x00'), noa=2, base=100, acks=[(1, 4), (2, 5)]), 40001, S)
add(sprt(1, 0x3fff, msg(1, b'\x12\x34'), noa=3, base=0x3fff, acks=[(0, 0), (1, 1), (3, 0x3fff)]), 40001, S)
add(sprt(0, 0, noa=1, base=0, acks=[(3, 9)]), 40001, S)     # ack only, "No Payload"

mark('INIT, XID_XCHG, JM_INFO, START_JM')
for v in (0x0000, 0xffff, 0x8421, 0x5aa5):
    add(sprt(1, 10, msg(1, struct.pack('!H', v))), 40000, S)
for ecp, x1, x2 in ((0, 0, 0), (1, 0xff, 0xff), (2, 0x20, 0x01), (7, 0x55, 0x80)):
    body = struct.pack('!BBBHBBBHHBBHH', ecp, x1, x2, 0x0400 + ecp, 250, 3, 2, 0x0400, 0x0800, 255, 254, 0x1000, 0x2000)
    add(sprt(1, 11, msg(2, body)), 40000, S)
cats = {
    'call': 0x8001, 'call2': 0x8F7F, 'mod': 0xAFFF, 'mod0': 0xA000, 'proto': 0x5123, 'pstn': 0xB7FF,
    'pcm': 0xEAAA, 'ext': 0x0345, 'unk': 0x3FFF, 'unk2': 0xC001, 'unk3': 0x1100, 'unk4': 0x2222,
}
for k in ('call', 'mod', 'proto', 'pstn', 'pcm', 'ext', 'unk', 'call2', 'mod0'):
    add(sprt(1, 12, msg(3, struct.pack('!H', cats[k]))), 40000, S)
# several categories in one message
add(sprt(2, 13, msg(3, b''.join(struct.pack('!H', cats[k]) for k in
        ('call', 'mod', 'proto', 'pstn', 'pcm', 'ext', 'unk', 'unk2', 'unk3', 'unk4')))), 40000, S)
add(sprt(1, 14, msg(4)), 40000, S)

mark('CONNECT (conversation 40000 -> 30100: DLCI enabled)')
def connect(selmod, cdir, selcompr, errcorr, tdsr, rdsr, adt, extra=b''):
    return msg(5, struct.pack('!BBHHH', (selmod << 2) | cdir, (selcompr << 4) | errcorr, tdsr, rdsr, adt) + extra)
dict_bits = struct.pack('!HHBB', 2048, 1024, 32, 16)
hist_bits = struct.pack('!HH', 8192, 4096)
add(sprt(1, 15, connect(4, 3, 2, 1, 33600, 28800, 0x8000 | 0x4000 | 0x1000, dict_bits + hist_bits)), 40000, S)
add(sprt(1, 16, connect(0, 0, 0, 0, 300, 300, 0x0000)), 40000, S)
add(sprt(1, 17, connect(17, 2, 1, 2, 1200, 75, 0xffff, dict_bits)), 40000, S)
add(sprt(1, 18, connect(3, 1, 3, 3, 56000, 31200, 0x8001)), 40000, S)
add(sprt(2, 19, connect(1, 0, 2, 0, 49333, 33600, 0x0f0f, dict_bits + hist_bits)), 40000, S)
add(sprt(1, 20, connect(40, 0, 4, 5, 1, 1, 0, dict_bits + hist_bits)), 40000, S)  # reserved values

mark('BREAK .. PROF_XCHG')
for v in ((0, 1, 5), (1, 2, 9), (2, 3, 255), (7, 0, 0)):
    add(sprt(1, 21, msg(6, bytes([(v[0] << 4) | v[1], v[2]]))), 40000, S)
add(sprt(1, 22, msg(7)), 40001, S)
add(sprt(1, 23, msg(8, bytes([1, 2]))), 40000, S)
add(sprt(1, 23, msg(8, bytes([2, 7]))), 40000, S)
add(sprt(1, 24, msg(8, bytes([3, 1, (4 << 2) | 2 | 1]) + struct.pack('!HH', 33600, 28800))), 40000, S)
add(sprt(1, 25, msg(8, bytes([3, 0, (6 << 2)]) + struct.pack('!HH', 4800, 2400) + b'\x01\x02')), 40000, S)
add(sprt(1, 26, msg(8, bytes([4, 3]))), 40000, S)
add(sprt(1, 26, msg(8, bytes([9, 3]))), 40000, S)
add(sprt(1, 27, msg(9, bytes([2, 0x7f, 0x11]))), 40000, S)
add(sprt(1, 27, msg(9, bytes([0, 0, 0]))), 40000, S)
add(sprt(1, 27, msg(9, bytes([255, 255, 255]))), 40000, S)
for v in (0x01, 0xff, 0x8a):
    # 18 octets: v lr1.. built by hand
    body = bytes([v, v ^ 0xff, 7]) + struct.pack('!HBBBHHBBHH', 0x0401, 200, 3, 2, 0x0400, 0x0800, 255, 254, 0x1000, 0x2000)
    add(sprt(1, 28, msg(10, body)), 40000, S)

mark('data messages')
add(sprt(1, 30, msg(16, bytes([0x80 | 0x15]) + b'raw octets')), 40000, S)   # N field present
add(sprt(1, 31, msg(16, bytes([0x07]) + b'no N')), 40000, S)
add(sprt(2, 32, msg(16, bytes([0x00]))), 40000, S)
add(sprt(1, 33, msg(17, bytes([0x15]) + b'bits')), 40000, S)               # 00: L
add(sprt(1, 34, msg(17, bytes([0x40 | 0x1d]) + b'\xaa\x55')), 40000, S)    # 01: L, P
add(sprt(1, 35, msg(17, bytes([0x80 | 0x2a, 0x7e]) + b'\x01\x02\x03')), 40000, S)  # 10: L, P, N
add(sprt(1, 36, msg(17, bytes([0xc0 | 0x2a, 0x01]) + b'\x04')), 40000, S)  # 11
for mid, name in ((21, 'frame'),):
    for fr in (0, 1, 2, 3):
        add(sprt(1, 37 + fr, msg(mid, bytes([(0x15 << 2) | fr]) + b'HDLC frame')), 40000, S)
for mid in (19, 20):
    for b0 in (0x00, 0x13, 0x2e, 0x7f, 0x5a):
        add(sprt(1, 41, msg(mid, bytes([b0]) + b'chars')), 40000, S)
add(sprt(1, 42, msg(22, struct.pack('!H', 0x1234) + b'octets with cs')), 40000, S)
for b0 in (0x00, 0x13, 0x7f):
    add(sprt(1, 43, msg(23, bytes([b0]) + struct.pack('!H', 0x0102) + b'char stat cs')), 40000, S)
    add(sprt(1, 44, msg(24, bytes([b0]) + struct.pack('!H', 0x0304) + b'char dyn cs')), 40000, S)
for mid in (11, 15, 25, 99, 100, 127, 40):
    add(sprt(1, 45, msg(mid, b'\x01\x02\x03\x04')), 40000, S)
add(sprt(1, 46, msg(16, bytes([0x01]) + b'x', rbit=1)), 40000, S)         # reserved bit set in the message id octet

mark('I_OCTET with DLCI (the CONNECT of frame 29 enabled it)')
add(sprt(1, 50, msg(18, bytes([0x2d]) + b'one octet DLCI (ea=1)')), 40000, S)
add(sprt(1, 51, msg(18, bytes([0xfa, 0x15]) + b'two octet DLCI (ea=0)')), 40000, S)
add(sprt(1, 52, msg(18, bytes([0x00, 0x00]) + b'x')), 40000, S)
# a second CONNECT in the same conversation does not change the DLCI setting
add(sprt(1, 53, connect(4, 0, 0, 0, 14400, 14400, 0x0000)), 40000, S)
add(sprt(1, 54, msg(18, bytes([0x01]) + b'still with DLCI')), 40000, S)

# ---- a second conversation, from another source: DLCI absent
mark('heuristic conversation from 192.0.2.30: DLCI absent')
add(sprt(1, 1, connect(4, 0, 0, 0, 9600, 9600, 0x0000)), 40010, 30300, src=[192, 0, 2, 30], dst=[192, 0, 2, 21])
add(sprt(1, 2, msg(18, b'no dlci data')), 40010, 30300, src=[192, 0, 2, 30], dst=[192, 0, 2, 21])
add(sprt(1, 3, msg(18, b'')), 40010, 30300, src=[192, 0, 2, 30], dst=[192, 0, 2, 21])

# ---- a third one: I_OCTET without any CONNECT, DLCI presence unknown
mark('heuristic conversation from 192.0.2.31: no CONNECT, DLCI unknown')
add(sprt(1, 1, msg(18, b'unknown dlci')), 40020, 30300, src=[192, 0, 2, 31], dst=[192, 0, 2, 21])
add(sprt(1, 2, msg(18, b'unknown dlci again')), 40020, 30300, src=[192, 0, 2, 31], dst=[192, 0, 2, 21])

# ---- heuristic: UDP port 30300 is not announced anywhere
H = 30300
mark('heuristic (SSID 0, PT 96-127)')
add(sprt(0, 0, msg(1, b'\x00\x10')), 41000, H, src=[192, 0, 2, 20], dst=[192, 0, 2, 21])
add(sprt(1, 77, msg(16, bytes([0x00]) + b'heur')), 41000, H, src=[192, 0, 2, 20], dst=[192, 0, 2, 21])
add(sprt(2, 78, connect(4, 0, 0, 0, 14400, 14400, 0x8000), noa=1, base=5, acks=[(1, 3)], pt=127), 41000, H, src=[192, 0, 2, 20], dst=[192, 0, 2, 21])
add(sprt(1, 79, msg(18, bytes([0x01]) + b'dlci'), pt=127), 41000, H, src=[192, 0, 2, 20], dst=[192, 0, 2, 21])
add(sprt(3, 0, msg(6, b'\x00\x01'), pt=100), 41000, H, src=[192, 0, 2, 20], dst=[192, 0, 2, 21])
# the three reproducers of the fix: masks of the heuristic
mark('fix: reserved bit 0x80, payload type with bit 0x10, TC 0 with a sequence number above 0x3f')
add(sprt(1, 80, msg(16, bytes([0x00]) + b'pt 112'), pt=0x70), 41001, H, src=[192, 0, 2, 22], dst=[192, 0, 2, 21])       # now SPRT
add(sprt(1, 81, msg(16, bytes([0x00]) + b'res bit'), pt=0x60, res=1), 41001, H, src=[192, 0, 2, 25], dst=[192, 0, 2, 21])  # not SPRT
add(sprt(0, 0x0100, msg(16, bytes([0x00]) + b'tc0 seq'), pt=0x60), 41001, H, src=[192, 0, 2, 26], dst=[192, 0, 2, 21])    # not SPRT
add(sprt(3, 0x0100, msg(16, bytes([0x00]) + b'tc3 seq'), pt=0x60), 41001, H, src=[192, 0, 2, 27], dst=[192, 0, 2, 21])    # not SPRT
# heuristic rejections
mark('heuristic rejections: short, SSID != 0, PT < 96, TC 0 with a sequence number')
add(b'\x00\x60\x00\x00\x00', 41002, H, src=[192, 0, 2, 23], dst=[192, 0, 2, 21])
add(sprt(1, 1, msg(16, b'\x00'), ssid=1), 41002, H, src=[192, 0, 2, 23], dst=[192, 0, 2, 21])
add(sprt(1, 1, msg(16, b'\x00'), pt=95), 41002, H, src=[192, 0, 2, 23], dst=[192, 0, 2, 21])
add(sprt(0, 5, msg(16, b'\x00')), 41002, H, src=[192, 0, 2, 23], dst=[192, 0, 2, 21])
# RTP version 2 through the SPRT heuristic: handed to RTP
mark('version 2 header: handed to RTP')
rtp = struct.pack('!BBHII', 0x80, 96, 0x4001, 160, 0x11223344) + b'\x00' * 8
add(rtp, 41003, H, src=[192, 0, 2, 24], dst=[192, 0, 2, 21])

mal = []
def addm(p, sport, dport, src=C, dst=A):
    mal.append(udp_pkt(sport, dport, p, src, dst))
# malformed / warnings: TC 0 with a sequence number, truncated payloads, bad lengths in the conversation
addm(sip, 5060, 5060)
addm(sprt(0, 33, msg(0)), 42000, S)                          # expert: sequence number 0 for TC 0
addm(sprt(1, 1, msg(1, b'\x00')), 42000, S)                  # INIT cut short
addm(sprt(1, 1, msg(2, b'\x00\x01')), 42000, S)              # XID_XCHG cut short
addm(sprt(1, 1, msg(3, b'\x80')), 42000, S)                  # JM_INFO with one octet
addm(sprt(1, 1, msg(5, b'\x00\x00\x00')), 42000, S)          # CONNECT cut short
addm(sprt(1, 1, msg(5, struct.pack('!BBHHH', 0, 0x20, 1, 1, 0) )), 42000, S)  # V.42bis, no dictionary fields
addm(sprt(1, 1, msg(6)), 42000, S)
addm(sprt(1, 1, msg(8, bytes([3, 0, 0]))), 42000, S)
addm(sprt(1, 1, msg(9, b'\x00')), 42000, S)
addm(sprt(1, 1, msg(10, b'\x00' * 5)), 42000, S)
addm(sprt(1, 1, msg(16)), 42000, S)                          # RAW_OCTET without the L octet
addm(sprt(1, 1, msg(17)), 42000, S)
addm(sprt(1, 1, msg(17, b'\xc0')), 42000, S)
addm(sprt(1, 1, msg(19)), 42000, S)
addm(sprt(1, 1, msg(21)), 42000, S)
addm(sprt(1, 1, msg(22, b'\x01')), 42000, S)
addm(sprt(1, 1, msg(23, b'\x01\x02')), 42000, S)
addm(sprt(1, 1, msg(24)), 42000, S)
addm(sprt(1, 1, msg(5, struct.pack('!BBHHH', 0, 0, 1, 1, 0x8000))), 42001, S)
addm(sprt(1, 1, msg(18, b'\x00')), 42001, S)                 # DLCI two octets, only one present
addm(sprt(1, 1, msg(18, b'')), 42001, S)
addm(sprt(1, 1, msg(18, b'\x00')[:0] + b''), 42002, S)
addm(b'\x00\x60\x40', 42003, S)                              # shorter than the header
addm(sprt(2, 1, noa=3, acks=[(0, 0)]), 42004, S)             # ack fields cut short
addm(sprt(1, 1, noa=3, acks=[(0, 0), (0, 0), (0, 0)]), 42004, S)
addm(rtp[:4], 42005, S)

if len(sys.argv) < 2:
    sys.exit('usage: mksprt.py <outdir> [-v]')
out = sys.argv[1]
write_pcap(os.path.join(out, 'sprt-coverage.pcap'), pk)
write_pcap(os.path.join(out, 'sprt-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for n, name in marks:
        print(n, name)
    print('main', len(pk), 'malformed', len(mal))
