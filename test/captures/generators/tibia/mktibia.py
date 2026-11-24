#!/usr/bin/env python3
# Generates test/captures/tibia_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Tibia coverage captures.  Usage: mktibia.py <outdir> [-v]
# No keys, no encryption: the legacy protocol (7.60) is plain text, the
# newer login and game traffic is left as opaque filler where the dissector
# would need a key.
import struct
import sys
import os
import zlib
from pcaplib import TcpFlow, write_pcap

def s(x):
    if isinstance(x, str):
        x = x.encode('latin-1')
    return struct.pack('<H', len(x)) + x

def pkt_raw(body):
    """length + body (no checksum, no padding)"""
    return struct.pack('<H', len(body)) + body

def pkt_plain(body):
    """length + body. The dissector reads a 4 octet checksum and needs one more octet, so a short command
    is followed by ping/pong (0x1e) commands."""
    if len(body) < 5:
        body += b'\x1e' * (5 - len(body))
    return pkt_raw(body)

def pkt_adler(body):
    data = struct.pack('<I', zlib.adler32(body)) + body
    return struct.pack('<H', len(data)) + data

def coords(x, y, z):
    return struct.pack('<HHB', x, y, z)

pk = []
marks = []
def mark(name):
    marks.append((len(pk) + 1, name))

C1 = [192, 0, 2, 11]
S1 = [192, 0, 2, 10]

class Flow(TcpFlow):
    def __init__(self, cport, sport):
        TcpFlow.__init__(self, cport, sport, C1, S1)
    def cl(self, data):
        pk.append(self.c2s(data))
    def sv(self, data):
        pk.append(self.s2c(data))

# ===== legacy 7.60 login server, plain text
mark('7.60 login server on port 7171')
f = Flow(50001, 7171)
files = struct.pack('>III', 0x4a4b4c01, 0x4a4b4c02, 0x4a4b4c03)
f.cl(pkt_plain(bytes([0x01]) + struct.pack('<HH', 2, 760) + files + struct.pack('<I', 123456) + s('secret')))
motd = bytes([0x14]) + s('1\nWelcome to the test server')
chars = bytes([0x64, 2]) + s('Alice') + s('World1') + bytes(S1) + struct.pack('>H', 7172) \
      + s('Bob') + s('World2') + bytes([192, 0, 2, 12]) + struct.pack('>H', 7173) + struct.pack('<H', 30)
f.sv(pkt_plain(motd + chars))
f.cl(pkt_plain(bytes([0x01]) + struct.pack('<HH', 2, 760) + files + struct.pack('<I', 654321) + s('')))
f.sv(pkt_plain(bytes([0x0a]) + s('Account number or password is not correct.')))
f.cl(pkt_plain(bytes([0x01]) + struct.pack('<HH', 2, 760) + files + struct.pack('<I', 7) + s('x' * 20)))
f.sv(pkt_plain(bytes([0x0b]) + s('Too many connections.')))
f.sv(pkt_plain(bytes([0x64, 0]) + struct.pack('<H', 0)))                   # empty character list
f.sv(pkt_plain(bytes([0x28]) + s('session') + b'tail'))                      # unknown command: data
f.sv(pkt_plain(bytes([0x14]) + s('motd') + bytes([0x64, 1]) + s('Carol') + s('W') + bytes(S1) + struct.pack('>H', 7172) + struct.pack('<H', 0xffff)))  # MOTD and charlist in one packet

# ===== legacy 7.60 game server, plain text
mark('7.60 game server on port 7172: login, server and client commands')
g = Flow(50002, 7172)
g.cl(pkt_plain(bytes([0x0a]) + struct.pack('<HH', 2, 760) + b'\x00' + struct.pack('<I', 123456) + s('Alice') + s('secret')))
g.sv(pkt_plain(bytes([0x0a]) + struct.pack('<IH', 0x40000001, 0x32) + b'\x00'))    # map init: data
g.sv(pkt_plain(bytes([0x0b]) + b'\x01' * 32))
g.sv(pkt_plain(bytes([0x64]) + coords(32000, 32100, 7)))
g.sv(pkt_plain(bytes([0x69]) + coords(32001, 32100, 7) + b'\x00\x01tile'))
g.sv(pkt_plain(bytes([0x6a]) + coords(32001, 32101, 7) + b'\x99\x01'))
g.sv(pkt_plain(bytes([0x6b]) + coords(32002, 32101, 7) + b'\x02' + b'\x98\x01'))
g.sv(pkt_plain(bytes([0x6c]) + coords(32002, 32102, 7) + b'\x03'))
g.sv(pkt_plain(bytes([0x6d]) + coords(32002, 32102, 7) + b'\x01' + coords(32003, 32102, 7)))
g.sv(pkt_plain(bytes([0x6e, 0x01]) + struct.pack('<HH', 0x0640, 20) + b'\x01\x02\x03'))
g.sv(pkt_plain(bytes([0x6f, 0x01])))
g.sv(pkt_plain(bytes([0x70, 0x02]) + b'\x01\x02\x03'))
g.sv(pkt_plain(bytes([0x71, 0x02, 0x03])))
g.sv(pkt_plain(bytes([0x72, 0x02, 0x03])))
g.sv(pkt_plain(bytes([0x78, 0x05])))
g.sv(pkt_plain(bytes([0x79, 0x05, 0xaa, 0xbb])))
g.sv(pkt_plain(bytes([0x7d]) + s('Trader') + b'\x02\x01\x02'))
g.sv(pkt_plain(bytes([0x7e]) + s('Trader') + b'\x02\x01\x02'))
g.sv(pkt_plain(bytes([0x7f])))
g.sv(pkt_plain(bytes([0x82, 0xfa, 0xd7])))
g.sv(pkt_plain(bytes([0x83]) + coords(32000, 32100, 7) + b'\x0b'))
g.sv(pkt_plain(bytes([0x84]) + coords(32000, 32100, 7) + b'\xb4' + s('-12')))
g.sv(pkt_plain(bytes([0x85]) + coords(32000, 32100, 7) + struct.pack('<I', 0x01020304) + coords(32003, 32103, 7)))
g.sv(pkt_plain(bytes([0x86]) + struct.pack('<I', 0x40000001) + b'\xd2'))
g.sv(pkt_plain(bytes([0x8c, 0x11, 0x64])))
g.sv(pkt_plain(bytes([0x8d, 0x12, 0x01, 0x02])))
g.sv(pkt_plain(bytes([0x8e, 0x13, 0x01, 0x02, 0x03, 0x04, 0x05])))
g.sv(pkt_plain(bytes([0x96]) + struct.pack('<I', 0x1234) + bytes([0x01, 0x20]) + s('A note')))
g.sv(pkt_plain(bytes([0xa2]) + struct.pack('<I', 0x0000_0207)))
g.sv(pkt_plain(bytes([0xa3])))
g.sv(pkt_plain(bytes([0xac]) + struct.pack('<H', 4) + s('Trade') + b'\0\0\0\0'))
g.sv(pkt_plain(bytes([0xad]) + s('Bob')))
g.sv(pkt_plain(bytes([0xb4, 0x16]) + s('You see a wall.')))
g.sv(pkt_plain(bytes([0xb5, 0x02])))
g.sv(pkt_plain(bytes([0xd2]) + struct.pack('<I', 77) + s('Friend') + b'\x01'))
g.sv(pkt_plain(bytes([0xd3]) + struct.pack('<I', 77)))
g.sv(pkt_plain(bytes([0xd4]) + struct.pack('<I', 77)))
g.sv(pkt_plain(bytes([0x1e])))
g.sv(pkt_plain(bytes([0x14]) + s('You are dead.')))
g.sv(pkt_plain(bytes([0x15]) + s('Information')))
g.sv(pkt_plain(bytes([0x16]) + s('Too many players online.')))
for cmd in (0x65, 0x66, 0x67, 0x68, 0xaa, 0xab, 0xa0, 0xa1, 0x8f, 0xbe, 0xbf, 0xc8, 0x7a, 0xff):
    g.sv(pkt_plain(bytes([cmd]) + b'\x01\x02\x03\x04\x05\x06'))
# several commands in one packet
g.sv(pkt_plain(bytes([0x82, 0xfa, 0xd7]) + bytes([0x6f, 0x01]) + bytes([0xb5, 0x03]) + bytes([0x1e])))
g.sv(pkt_plain(bytes([0x1f]) + b'\x01\x02\x03\x04\x05'))                    # nonce
mark('7.60 game server: client commands')
g.cl(pkt_plain(bytes([0x96, 0x01]) + s('hello there')))
g.cl(pkt_plain(bytes([0x96, 0x07]) + struct.pack('<H', 4) + s('channel talk')))
g.cl(pkt_plain(bytes([0x1e])))
g.cl(pkt_plain(bytes([0x65])))
g.cl(pkt_plain(bytes([0x78]) + coords(32000, 32100, 7) + b'\x01\x02\x03'))
g.cl(pkt_plain(bytes([0x14])))
g.cl(pkt_plain(bytes([0x1e, 0x96, 0x01]) + s('two commands') + bytes([0x1e])))

mark('7.60 game login of a second character, longer names')
g2 = Flow(50003, 7172)
g2.cl(pkt_plain(bytes([0x0a]) + struct.pack('<HH', 2, 760) + b'\x01' + struct.pack('<I', 5) + s('Bob the builder') + s('hunter2 hunter2')))
g2.sv(pkt_plain(bytes([0x14]) + s('Wrong password')))

# ===== modern clients without keys
mark('protocol 10.00 and 11.00: login requests (RSA block left undecoded), nonce, opaque game data')
def getcharlist(version, plen, adler=True, cmd=0x01, extra=b''):
    body = bytes([cmd]) + struct.pack('<HH', 2, version)
    if version >= 980:
        body += struct.pack('<I', version * 10)          # client version
    if cmd == 0x01:
        body += struct.pack('>III', 0x4a4b4c01, 0x4a4b4c02, 0x4a4b4c03)
    elif version >= 1071:
        body += struct.pack('<H', 1234)                  # content revision
    if version >= 980:
        body += b'\x00'                                  # game preview state
    total = plen - 2 - (4 if adler else 0)
    body += b'\x00' * (total - len(body))                # RSA block and trailer: filler, not encrypted data
    return pkt_adler(body) if adler else pkt_raw(body)

def pkt_adler_ver(version, plen, cmd=0x01):
    return getcharlist(version, plen, True, cmd)

h = Flow(50010, 7171)
h.cl(pkt_adler_ver(1000, 151))         # charlist request, version 10.00: 2 + 4 + 17 + 128
# the server answer of a newer protocol is encrypted: opaque bytes after the length and a valid checksum
op = bytes([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]) * 4
h.sv(pkt_adler(op))
h.cl(pkt_adler_ver(1100, 373))
h.sv(pkt_adler(op[:16]))
h2 = Flow(50011, 7172)
h2.cl(pkt_adler_ver(1000, 2 + 4 + 5 + 4 + 1 + 128, cmd=0x0a))    # character login, version 10.00
h2.sv(pkt_adler(struct.pack('<H', 6) + bytes([0x1f]) + b'\x11\x22\x33\x44\x55'))   # nonce, unencrypted
h2.sv(pkt_adler(op))                                             # game data of a newer protocol: undecoded XTEA data
h2.cl(pkt_adler(op[:24]))
h3 = Flow(50012, 7172)
h3.cl(pkt_adler_ver(1100, 2 + 4 + 5 + 4 + 2 + 1 + 128, cmd=0x0a))     # version 11.00 with a content revision
h3.sv(pkt_adler(op[:8]))
h3.cl(pkt_adler(op[:20]))                                             # not a multiple of 8
h3.sv(pkt_adler(struct.pack('<H', 6) + bytes([0x1f]) + b'\x01\x02\x03\x04\x05'))

# ===== login server charlists with a world list (protocol >= 10.10)
# The real reply is encrypted. Here the reply is built so that its length and first command look like the
# unencrypted nonce packet; the dissector then reads the login commands from the payload that follows. With
# protocol 11.11 the four octets after the length are skipped (compression), as in a real packet.
mark('protocol 11.11 charlists with world lists (plain text through the nonce check)')
def world_reply(worlds, chars, motd=None):
    payload = b''
    if motd:
        payload += bytes([0x14]) + s(motd)
    payload += bytes([0x64, len(worlds)])
    for wid, name, ip, port, preview in worlds:
        payload += bytes([wid]) + s(name) + s(ip) + struct.pack('<HB', port, preview)
    payload += bytes([len(chars)])
    for cid, name in chars:
        payload += bytes([cid]) + s(name)
    return payload

def nonce_like(payload):
    plen = 8 + len(payload)
    return struct.pack('<HHBB', plen - 2, plen - 4, 0x1F, 0) + struct.pack('<H', len(payload)) + payload

w = Flow(50020, 7171)
w.cl(getcharlist(1111, 373, adler=False))
w.sv(nonce_like(world_reply([(0, 'Antica', '10.1.2.3', 7172, 0), (1, 'Belobra', '192.0.2.77', 7173, 1)],
                          [(0, 'Knight'), (1, 'Druid'), (2, 'Mage')], motd='1\nWelcome')))
w.sv(nonce_like(world_reply([(2, 'Short', '1.2', 7174, 0), (3, 'Big', '999.1.1.1', 7175, 0), (4, 'Dots', '1.2.3', 7176, 0),
                           (5, 'Text', 'abc', 7177, 0)], [])))
w.sv(nonce_like(bytes([0x64, 0, 0])))                                      # no world, no character
w.sv(nonce_like(bytes([0x0a]) + s('Login failed.')))
w.sv(nonce_like(bytes([0x28]) + s('acc\npass')))
w.sv(nonce_like(bytes([0x14]) + s('only a message of the day')))
mark('fix: world list entry with an empty address (heap over-read of the address string)')
w3 = Flow(50021, 7171)
w3.cl(getcharlist(1111, 373, adler=False))
w3.sv(nonce_like(world_reply([(0, 'W', '', 7172, 0)], [])))
w3.sv(nonce_like(world_reply([(0, 'W', '1.2', 7172, 0), (1, 'X', '', 7173, 0)], [])))

# ===== split and merged packets
mark('7.60 packets split over TCP segments and several packets in one segment')
sp = Flow(50030, 7172)
sp.cl(pkt_plain(bytes([0x0a]) + struct.pack('<HH', 2, 760) + b'\x00' + struct.pack('<I', 99) + s('Dave') + s('pass1234')))
big = pkt_plain(bytes([0x14]) + s('A longer text that is split over two TCP segments'))
pk.append(sp.s2c(big[:10]))
pk.append(sp.s2c(big[10:]))
two = pkt_plain(bytes([0xb4, 0x16]) + s('first')) + pkt_plain(bytes([0xb4, 0x17]) + s('second'))
pk.append(sp.s2c(two))
pk.append(sp.s2c(two[:5]))
pk.append(sp.s2c(two[5:] + pkt_plain(bytes([0x1e]))))
# a packet whose length field does not match: not Tibia

# ===== UDP-less: a non-Tibia frame on the port
nt = Flow(50031, 7171)
pk.append(nt.c2s(b'GET / HTTP/1.0\r\n\r\n'))

mal = []
class MFlow(TcpFlow):
    def __init__(self, cport, sport):
        TcpFlow.__init__(self, cport, sport, C1, S1)
    def cl(self, data):
        mal.append(self.c2s(data))
    def sv(self, data):
        mal.append(self.s2c(data))

# a server-first conversation in the main capture too: the first packet seen comes from the server port
# (the client port is below 0xC000), which the conversation setup tells apart
mark('first packet of the conversation comes from the server')
sf = Flow(50050, 7172)
sf.sv(pkt_plain(bytes([0xb4, 0x16]) + s('server speaks first')))
sf.cl(pkt_plain(bytes([0x96, 0x01]) + s('client answers')))

# --- malformed: login server, complete PDUs with bad contents
a = MFlow(50040, 7171)
a.cl(pkt_raw(bytes([0x01]) + struct.pack('<HH', 2, 760) + files + struct.pack('<I', 1) + s('pw')))
a.sv(pkt_raw(bytes([0x14]) + struct.pack('<H', 500) + b'short'))               # string longer than the packet
a.sv(pkt_raw(bytes([0x64, 5]) + s('Only one') + s('W') + bytes(S1)))          # character list cut short
a.sv(pkt_raw(bytes([0x64]) + b'\x00\x00\x00\x00'))
a.sv(pkt_raw(bytes([0x0a]) + b'\x00\x00\x00\x00'))
a.sv(pkt_raw(bytes([0x1e, 0x1e, 0x1e])))                                       # shorter than the checksum field
# --- length field larger than the data (the rest never comes)
b = MFlow(50043, 7171)
b.cl(pkt_raw(bytes([0x01]) + struct.pack('<HH', 2, 760) + files + struct.pack('<I', 1) + s('pw')))
b.sv(struct.pack('<H', 300) + bytes([0x14]) + s('cut'))
# --- game server, plain 7.60 commands cut short
mg = MFlow(50041, 7172)
mg.cl(pkt_raw(bytes([0x0a]) + struct.pack('<HH', 2, 760) + b'\x00' + struct.pack('<I', 1) + s('Eve') + s('longpassword')))
for cmd, tail in ((0x64, b'\x01\x01\x01\x01'), (0x69, b'\x01\x02'), (0x6e, b'\x01\x01'), (0x7d, b'\xff\xff'), (0x86, b'\x01\x01'),
                  (0x96, b'\x01\x01\x01\x01'), (0xa2, b'\x01\x01\x01'), (0xac, b'\x01\x02\x03'), (0xb4, b'\x01\x01\x01\x01'),
                  (0xd2, b'\x01\x02\x03\x04'), (0x1f, b'\x01\x01\x01'), (0x84, b'\x01\x01\x01\x01'), (0x6d, b'\x01\x01\x01\x01')):
    mg.sv(pkt_raw(bytes([cmd]) + tail))
mg.cl(pkt_raw(bytes([0x96]) + b'\x00\x00\x00\x00'))
mg.cl(pkt_raw(bytes([0x96, 0x07, 0x01, 0x00, 0x00])))
mg.cl(pkt_raw(bytes([0x96, 0x01]) + struct.pack('<H', 99) + b'x'))
mg.sv(pkt_raw(bytes([0x1e, 0x1f]) + b'abc'))
# --- modern login server replies
mm = MFlow(50042, 7171)
mm.cl(getcharlist(1111, 373, adler=False))
x = nonce_like(bytes([0x14]) + s('m'))
mm.sv(x[:6] + struct.pack('<H', 999) + x[8:])                                    # XTEA payload length larger than the packet
mm.sv(nonce_like(bytes([0x64, 3, 0]) + s('A')))                                  # world list cut short
mm.sv(nonce_like(bytes([0x64])))
mm.sv(nonce_like(bytes([0x64, 1, 0]) + s('W') + s('1.2.3.4')))
mm.sv(nonce_like(world_reply([(0, 'W', '1.2.3.4', 7172, 0)], [(0, 'Knight')])[:-3]))   # character name cut short
mm.sv(nonce_like(bytes([0x0a, 0xff, 0xff, 0xff])))                              # error string with a bad length
# --- a server-first modern conversation whose first PDU is shorter than the header
mn = MFlow(50044, 7172)
mn.sv(pkt_raw(bytes([0x1f, 0, 0, 0])))
mn.sv(pkt_adler(struct.pack('<H', 6) + bytes([0x1f]) + b'\x01\x02'))

if len(sys.argv) < 2:
    sys.exit('usage: mktibia.py <outdir> [-v]')
out = sys.argv[1]
write_pcap(os.path.join(out, 'tibia-coverage.pcap'), pk)
write_pcap(os.path.join(out, 'tibia-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for n, name in marks:
        print(n, name)
    print('main', len(pk), 'malformed', len(mal))
