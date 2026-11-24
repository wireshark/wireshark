#!/usr/bin/env python3
# Generates test/captures/mip6_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Mobile IPv6 / Proxy MIPv6 captures.  Usage: mkmip6.py <outdir>
Writes mip6-coverage.pcap (valid frames) and mip6-coverage-malformed.pcap."""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(payload, et):
    return bytes([2,0,0,0,0,2, 2,0,0,0,0,1]) + struct.pack('!H', et) + payload

def ipv6(payload, nxt, src=1, dst=2, hlim=64):
    s = bytes.fromhex('20010db8000000000000000000000000'[:-2] + '%02x' % src)
    d = bytes.fromhex('20010db8000000000000000000000000'[:-2] + '%02x' % dst)
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + s + d + payload

def ipv4(payload, proto):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    bytes([192,0,2,1]), bytes([192,0,2,2]))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---- Mobility Header ----------------------------------------------------
def opt(t, data=b''):
    return bytes([t, len(data)]) + data

def pad_to8(n_so_far):
    """Padding option bytes that bring n_so_far to a multiple of 8."""
    k = (-n_so_far) % 8
    if k == 0: return b''
    if k == 1: return b'\x00'
    return opt(1, b'\0' * (k - 2))

def mh(mtype, body, opts=b'', pproto=59, pad=True, hlen=None):
    raw = body + opts
    total = 6 + len(raw)
    if pad: raw += pad_to8(total)
    total = 6 + len(raw)
    h = (total // 8 - 1) if hlen is None else hlen
    return struct.pack('!BBBBH', pproto, h, mtype, 0, 0) + raw

def v6(m, nxt=135, **kw): return eth(ipv6(m, nxt, **kw), 0x86dd)
IP6 = bytes.fromhex('20010db8000000000000000000000099')
IP4 = bytes([198,51,100,7])
frames = []; bad = []
def F(m, **kw): frames.append(v6(m, **kw))

# ---- messages -----------------------------------------------------------
F(mh(0, b'\0\0'))                                         # BRR, no options
F(mh(0, b'\0\0', opt(2, struct.pack('!H', 30))))          # BRR + BRA
F(mh(1, b'\0\0' + bytes(range(8))))                       # HoTI
F(mh(2, b'\0\0' + bytes(range(8, 16))))                   # CoTI
F(mh(3, struct.pack('!H', 7) + bytes(range(8)) + bytes(range(16, 24))))   # HoT
F(mh(4, struct.pack('!H', 9) + bytes(range(8)) + bytes(range(32, 40))))   # CoT
def bu(flags, seq=1, life=100, opts=b''):
    return mh(5, struct.pack('!HHH', seq, flags, life), opts)
F(bu(0xf800))                                             # A H L K M
F(bu(0x0400, 2))                                          # R -> NEMO in column
F(bu(0x0000, 3))                                          # plain after NEMO
F(bu(0x0380, 4))                                          # P F T
F(bu(0x0040, 5))                                          # B
F(bu(0x8000, 6, opts=opt(3, IP6)))                        # alt CoA
def ba(status, flags, seq=1, life=100, opts=b''):
    return mh(6, struct.pack('!BBHH', status, flags, seq, life), opts)
F(ba(0, 0xf0))                                            # K R P T B
F(ba(0, 0x40, 2))                                         # R -> NEMO
F(ba(135, 0x00, 3))                                       # plain after NEMO
F(ba(1, 0x80, 4, opts=opt(2, b'\0\x10')))
F(mh(7, b'\x02\0' + IP6))                                 # BE
F(mh(7, b'\x01\0' + IP6))
F(mh(8, struct.pack('!HBBH', 1, 0xf0, 0, 50)))            # FBU A H L K
F(mh(8, struct.pack('!HBBH', 2, 0x00, 0, 60), opt(7, b'\x01' + bytes(6))))  # FBU + LLA
F(mh(9, struct.pack('!BBHH', 0, 0x80, 1, 50)))            # FBACK K
F(mh(9, struct.pack('!BBHH', 0, 0x00, 2, 50), opt(7, b'\x02' + bytes(range(1, 7)))))
# FBACK that carries an AH (payload proto 51), AH has no next header
ah = struct.pack('!BBHII', 59, 4, 0, 0x100, 1) + bytes(12)
F(mh(9, struct.pack('!BBHH', 0, 0, 3, 50), pproto=51) + ah)
# nested AH: FBACK / AH(next 135) / FBACK / AH(next 59): two levels
inner = mh(9, struct.pack('!BBHH', 0, 0, 4, 50), pproto=51) + struct.pack('!BBHII', 59, 4, 0, 0x100, 2) + bytes(12)
F(mh(9, struct.pack('!BBHH', 0, 0, 3, 50), pproto=51) + struct.pack('!BBHII', 135, 4, 0, 0x100, 1) + bytes(12) + inner)
F(mh(10, b'\0\0'))                                        # FNA
# FNA carrying an IPv6 packet (payload proto 41): ICMPv6 echo reply
def v6addr(n): return bytes.fromhex('20010db80000000000000000000000%02x' % n)
icmp0 = struct.pack('!BBHHH', 129, 0, 0, 1, 1)
pseudo = v6addr(3) + v6addr(4) + struct.pack('!IHBB', len(icmp0), 0, 0, 58)
icmp = struct.pack('!BBHHH', 129, 0, csum(pseudo + icmp0), 1, 1)
inner6 = ipv6(icmp, 58, src=3, dst=4)
F(mh(10, b'\0\0', pproto=41) + inner6)
F(mh(11, b'\0\0' + b'\xde\xad\xbe\xef\x00\x11'))          # EMH with data
F(mh(11, b''))                                            # EMH without data
F(mh(12, b'\x02\0' + IP6 + IP6[:-1] + b'\x01'))           # HAS 2 addresses
F(mh(12, b'\x01\0' + IP6, opt(2, b'\0\x08')))             # HAS 1 + option
F(mh(12, b'\x00\0'))                                      # HAS 0
F(mh(13, struct.pack('!BBI', 0, 0x80, 1)))                # HB U
F(mh(13, struct.pack('!BBI', 0, 0x40, 2)))                # HB R
F(mh(14, struct.pack('!HBB', 1, 0xc0, 3)))                # HI S U
F(mh(15, struct.pack('!HBB', 1, 0, 3)))                   # HAck
F(mh(16, struct.pack('!BBHH', 1, 2, 77, 0xe000)))         # BRI
F(mh(16, struct.pack('!BBHH', 1, 4, 78, 0x1000)))
F(mh(16, struct.pack('!BBHH', 2, 0, 79, 0xe000)))         # BRA
F(mh(16, struct.pack('!BBHH', 2, 128, 80, 0x1000)))
F(mh(16, struct.pack('!BBHH', 3, 0, 81, 0)))              # unknown BR type
F(mh(17, struct.pack('!HHH', 5, 0, 100)))                 # LRI
F(mh(18, struct.pack('!HBBH', 5, 0x80, 0, 100)))          # LRA
F(mh(18, struct.pack('!HBBH', 6, 0x00, 129, 0)))
F(mh(19, b'\x01\x02\x03\x04'))                            # unknown type 19
F(mh(200, b''))                                           # unknown, 8 byte header

# ---- options (carried in Binding Updates) ---------------------------------
def O(*opts_, flags=0x8000):
    frames.append(v6(bu(flags, 9, 100, b''.join(opts_))))
def OA(*opts_):                                           # in a BA
    frames.append(v6(ba(0, 0, 9, 100, b''.join(opts_))))

O(b'\0', opt(1, b''), opt(1, b'\0\0\0'), opt(1, b'\0' * 5))   # Pad1, PadN
O(opt(2, b'\0\x40'), opt(3, IP6), opt(4, struct.pack('!HH', 1, 2)))
O(opt(5, bytes(range(12))), opt(5, b''))                  # authorization data
O(opt(6, b'\0\x40' + IP6), opt(22, b'\0\x40' + IP6))      # MNP, HNP
O(opt(7, b'\x01' + bytes(6)), opt(7, b'\x02'))            # LLA
O(opt(8, b'\x01' + b'mn@example.org'), opt(8, b'\x03' + b'\x12\x34\x56\x78\x90'),
  opt(8, b'\x01' + b'x'))
O(opt(9, b'\x01' + struct.pack('!I', 0x1234) + bytes(range(12))))
O(opt(10, struct.pack('!Q', 0x0123456789abcdef)))
O(opt(11), opt(12, bytes(range(20))), opt(13, bytes(range(32))), opt(14, bytes(range(8))))
O(opt(15), opt(16, bytes(range(8))))
O(opt(17, b'\x00\x80' + b'mn.example.org'))               # DNS update, R
O(opt(18, b'experimental'))
O(opt(19, struct.pack('!I', 4491) + b'\x07' + b'vendor data'),        # VSM other vendor
  opt(19, struct.pack('!I', 4491) + b'\x08'))                          # no data
O(opt(20, b'\x07example\x03com'), opt(20, b'internet.example'))        # SSM APN and UTF-8
O(opt(21, struct.pack('!I', 0x1234) + bytes(range(12))))
O(opt(23, b'\0\x01'), opt(23, b'\0\x02'), opt(23, b'\0\x03'))          # Handoff indicator
O(opt(24, b'\0\x03'), opt(24, b'\0\x05'), opt(24, b'\0\x06'), opt(24, b'\0\x07'))
O(opt(25, b'\0\0' + bytes([2,0,0,0,0,5])), opt(25, b'\0\0'))           # MN LLI
O(opt(26, IP6))
O(opt(27, struct.pack('!Q', (1700000000 + 2208988800) << 16 | 0x8000)))   # timestamp
O(opt(28, struct.pack('!I', 7)))                                       # restart counter
O(opt(29, bytes([24, 0x80]) + IP4), opt(29, bytes([32, 0x00]) + IP4))  # IPv4 HoA
O(opt(30, bytes([0, 32]) + IP4), opt(30, bytes([128, 24]) + IP4))      # IPv4 address ack
O(opt(31, struct.pack('!HI', 0x8000, 0)), opt(31, struct.pack('!HI', 0, 0xffffffff)),
  opt(31, struct.pack('!HI', 0, 60)))                                  # NAT detection
O(opt(32, b'\0\0' + IP4))                                              # IPv4 CoA
O(opt(33, b'\0\0'), opt(33, b'\0\0' + struct.pack('!I', 0x1001)))      # GRE key
O(opt(34, bytes([0, 64]) + IP6))                                       # MH IPv6 addr/prefix
O(opt(35, struct.pack('!HBB', 1, 0, 0x80)),                            # BID, no address
  opt(35, struct.pack('!HBB', 2, 0, 0) + IP4),
  opt(35, struct.pack('!HBB', 3, 0, 0) + IP6))
O(opt(36, bytes([24, 0]) + IP4), opt(36, bytes([32, 0]) + bytes(4)))   # IPv4 HoA request
O(opt(37, bytes([0, 24]) + IP4), opt(37, bytes([1, 32]) + IP4), opt(37, bytes([2, 0]) + IP4))
O(opt(38, b'\0\0' + IP4), opt(39, b'\0\0'))                            # default router, DHCP
O(opt(40, b'\0\0' + bytes([19, 5]) + struct.pack('!I', 10415) + b'\x01'
        + bytes([19, 5]) + struct.pack('!I', 4491) + b'\x01'
        + bytes([1, 2, 0xaa, 0xbb]) + bytes([2, 0])))                  # context request
O(opt(41, bytes([1, 0]) + IP6), opt(41, bytes([2, 0]) + IP4), opt(41, bytes([3, 0]) + IP4))
O(opt(42, bytes(8)), opt(43, bytes(4)), opt(44, bytes(4)), opt(45, bytes(4)), opt(99, bytes(3)))  # unknown
O(opt(46, b'\0\0'))
O(opt(47, struct.pack('!H', 0x8000) + IP6), opt(47, struct.pack('!H', 0x4000) + IP4),
  opt(47, struct.pack('!H', 0xc000) + IP6 + IP4), opt(47, struct.pack('!H', 0) + b'\0\0\0\0'))
O(opt(48, struct.pack('!HIII', 1, 10, 100, 1000) + b'\0\0\0\0'))      # load info
O(opt(49, IP4))
O(opt(50, b'\0\0' + struct.pack('!I', 1)), opt(50, b'\0\0' + struct.pack('!I', 77)))
O(opt(51, b'\0\0' + IP6))
# access network identifier: network id (UTF-8, binary), geo, operator id
O(opt(52, bytes([1, 12, 0x80, 4]) + b'wlan' + bytes([3]) + b'ap1'
        + bytes([1, 10, 0x00, 3]) + b'abc' + bytes([2]) + b'ap'
        + bytes([2, 6]) + b'\x00\x10\x00\xff\xf0\x00'
        + bytes([3, 6, 1]) + struct.pack('!I', 4491) + b'\0'
        + bytes([3, 6, 2]) + b'ab.cd'
        + bytes([2, 6]) + bytes(6)
        + bytes([9, 2]) + b'zz'))
O(opt(55, bytes([0x80, 24]) + IP4), opt(55, bytes([0, 64]) + IP6))     # DMNP
# 3GPP vendor specific options
def v3(sub, data, m=0):
    return opt(19, struct.pack('!I', 10415) + bytes([sub, m]) + data)
pco = bytes([0x80, 0x00, 0x0d, 0x04, 8, 8, 8, 8, 0x00, 0x03, 0x00,
             0x80, 0x21, 0x0a, 0x01, 0x01, 0x00, 0x0a, 0x81, 0x06, 8, 8, 4, 4,
             0x00, 0x01, 0x10] + list(IP6))
O(v3(1, pco), v3(2, b'\x81'), v3(3, IP4), v3(3, IP6), v3(3, bytes(8)), v3(4, b'\x01'))
O(v3(5, bytes([0x01]) + IP4 + b'\x00\x05'),                            # FQ-CSID
  v3(6, b'\x02\x01'), v3(7, struct.pack('!I', 0x01020304)), v3(8, b'\x01'))
O(v3(9, b'apn'), v3(10, b'\x08\x00'), v3(11, bytes.fromhex('3a1b2c3d4e5f6071')),
  v3(12, bytes.fromhex('94712345678f')), v3(13, bytes.fromhex('130062')))
O(v3(14, b'\x02'), v3(15, b'\x01'), v3(16, bytes.fromhex('13245678f9')),
  v3(17, b'\x05'), v3(18, b'\x21'), v3(19, b'\x01'))
O(v3(20, b'\x80\x00\x0d\x00'), v3(30, b'\x01'), v3(99, b'\x01\x02'),
  v3(1, b'\x01\x02', m=1))                                             # fragment
OA(opt(2, b'\0\x40'), opt(8, b'\x01abc'))                              # options in a BA
# options in other messages
frames.append(v6(mh(1, b'\0\0' + bytes(8), opt(2, b'\0\x10'))))
frames.append(v6(mh(13, struct.pack('!BBI', 0, 0, 3), opt(28, struct.pack('!I', 1)))))
frames.append(v6(mh(17, struct.pack('!HHH', 7, 0, 100), opt(41, bytes([1, 0]) + IP6))))
frames.append(v6(mh(18, struct.pack('!HBBH', 7, 0, 0, 100), opt(41, bytes([1, 0]) + IP6))))
frames.append(v6(mh(12, b'\x01\0' + IP6, opt(2, b'\0\x08'))))

# ---- other carriers -------------------------------------------------------
frames.append(eth(ipv4(bu(0x8000, 20, 100, opt(3, IP6)), 135), 0x0800))   # MH over IPv4
frames.append(eth(ipv4(mh(6, struct.pack('!BBHH', 0, 0, 20, 100)), 62), 0x0800))   # old proto 62
frames.append(eth(ipv4(udp(mh(5, struct.pack('!HHH', 21, 0x0200, 100), opt(22, b'\0\x40' + IP6) + opt(23, b'\0\x01') + opt(24, b'\0\x05') + opt(27, bytes(8))), 40000, 5436), 17), 0x0800))
frames.append(eth(ipv4(udp(mh(6, struct.pack('!BBHH', 0, 0x20, 21, 100), opt(22, b'\0\x40' + IP6)), 5436, 40000), 17), 0x0800))
# mobility header as a hop-by-hop... no; destination options chain: IPv6 / dst opts / MH
dst_opts = struct.pack('!BB', 135, 0) + opt(1, b'\0' * 4)
F(dst_opts + bu(0x8000, 22), nxt=60)

# ---- malformed ------------------------------------------------------------
def B(m, **kw): bad.append(v6(m, **kw))
bad.extend(frames[:0])
# option length errors
B(bu(0, 1, 1, opt(2, b'\0\x40\x00')))                   # BRA too long
B(bu(0, 1, 1, opt(3, IP6[:8]) + opt(4, b'\0\0')))
B(bu(0, 1, 1, opt(19, b'\0\0')))                        # VSM too short
B(bu(0, 1, 1, opt(9, b'\x01\0\0')))                     # auth too short
B(bu(0, 1, 1, opt(52, b'\x01')))                        # ANI too short
B(bu(0, 1, 1, opt(55, bytes([0, 8, 1, 2, 3]))))          # DMNP odd length
B(bu(0, 1, 1, opt(40, b'\0\0\0\0')))
B(bu(0, 1, 1, opt(41, b'\0\0')))                        # LMAA too short
B(bu(0, 1, 1, opt(47, b'\0\0')))                        # redirect short
B(bu(0, 1, 1, opt(8, b'')))                             # MNID empty
B(bu(0, 1, 1, opt(35, b'\0\0')))
B(bu(0, 1, 1, opt(33, b'\0\0\0')))
B(bu(0, 1, 1, opt(38, b'\0\0\0')))
B(bu(0, 1, 1, opt(6, b'\0')))                           # MNP, wrong length
B(bu(0, 1, 1, opt(50, b'\0\0\0\0')))
B(bu(0, 1, 1, opt(24, b'\0\0\0')))
# options running past the end, length byte missing

raw = struct.pack('!BBBBHHHH', 59, 1, 5, 0, 0, 1, 0, 100) + b'\x01\x20\0\0'
bad.append(v6(raw))                                     # option past end
raw = struct.pack('!BBBBHHHH', 59, 1, 5, 0, 0, 1, 0, 100) + b'\0\0\0\x03'
bad.append(v6(raw))                                     # length byte past end
bad.append(v6(struct.pack('!BBBBHHHH', 59, 1, 5, 0, 0, 1, 0, 100) + b'\0\0\0\x0e'))
# header length smaller than the message body
bad.append(v6(struct.pack('!BBBBHBB', 59, 0, 3, 0, 0, 0, 7) + bytes(20)))
bad.append(v6(struct.pack('!BBBBHHHH', 59, 0, 5, 0, 0, 1, 0, 100)))     # BU with hlen 0
bad.append(v6(struct.pack('!BBBBH', 59, 0, 12, 0, 0) + b'\x09\0'))      # HAS claims 9 addresses
# truncated messages
bad.append(v6(struct.pack('!BBBBHHH', 59, 1, 5, 0, 0, 1, 0)))
bad.append(v6(struct.pack('!BBBB', 59, 1, 5, 0)))
bad.append(v6(struct.pack('!BBBBH', 59, 1, 9, 0, 0) + b'\0'))
bad.append(v6(struct.pack('!BBBBH', 59, 2, 7, 0, 0) + bytes(5)))
bad.append(v6(struct.pack('!BBBBH', 59, 0, 17, 0, 0) + b'\0\1'))
bad.append(v6(struct.pack('!BBBBH', 59, 0, 16, 0, 0) + b'\1'))
bad.append(v6(struct.pack('!BBBBH', 59, 3, 77, 0, 0) + b'\0\0'))        # unknown, truncated
bad.append(v6(struct.pack('!BBBBH', 59, 1, 3, 0, 0) + bytes(10)))       # HoT truncated
# FNA with truncated inner IPv6
bad.append(v6(mh(10, b'\0\0', pproto=41) + b'\x60\0\0'))
# AH nesting: FBACK / AH(135) / FBACK / AH ... (assertion before the fix)
mhx = struct.pack('!BBBBH', 51, 1, 9, 0, 0) + struct.pack('!BBHH', 0, 0, 1, 1) + bytes([1, 2, 0, 0])
ahx = struct.pack('!BBHII', 135, 1, 0, 0x100, 1)
bad.append(v6((mhx + ahx) * 40))
bad.append(v6((struct.pack('!BBHII', 51, 1, 0, 0x100, 1)) * 40, nxt=51))   # AH only
bad.append(v6((mhx + ahx) * 2000))                                      # ~56 KB, deep
# UDP/IPv4 variants
bad.append(eth(ipv4(udp(struct.pack('!BBBB', 59, 1, 5, 0) + b'\0\0', 1, 5436), 17), 0x0800))
bad.append(eth(ipv4(bu(0, 1, 1, opt(2, b'\0\0\0')), 135), 0x0800))

out = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, 'mip6-coverage.pcap'), frames)
write_pcap(os.path.join(out, 'mip6-coverage-malformed.pcap'), [b for b in bad if b])
print(len(frames), len([b for b in bad if b]))
