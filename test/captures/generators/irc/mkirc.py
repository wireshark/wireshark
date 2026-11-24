#!/usr/bin/env python3
# Generates test/captures/irc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IRC coverage captures (synthetic traffic only).
Usage: mkirc.py <outdir> [-v]"""
# ---- helpers (synthetic traffic only; documentation addresses) ----
import struct
import sys
import os

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def _ip4(a):
    return bytes(int(x) for x in a.split('.'))

_ETH = bytes.fromhex('020000000002') + bytes.fromhex('020000000001')

def eth_ip(src, dst, proto, seg, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), ident, 0x4000, 64, proto, 0, _ip4(src), _ip4(dst))
    h = h[:10] + struct.pack('!H', _csum(h)) + h[12:]
    return _ETH + b'\x08\x00' + h + seg

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opt = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
    pseudo = _ip4(src) + _ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('!H', _csum(pseudo + hdr + payload)) + hdr[18:]
    return eth_ip(src, dst, 6, hdr + payload)

def udp(src, dst, sport, dport, payload):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(src, dst, 17, seg)

class Tcp:
    """One TCP connection; send() appends a data frame from the client
    ('c') or the server ('s') and tracks the sequence numbers."""
    def __init__(self, frames, c, s, cport, sport, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self.f.append(tcp(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.f.append(tcp(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.f.append(tcp(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def send(self, who, data):
        if who == 'c':
            self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data))
            self.cseq += len(data)
        else:
            self.f.append(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data))
            self.sseq += len(data)
    def fin(self):
        self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, b'', 0x11))

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(path, linktypes, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def exp_tlv(tag, val):
    return struct.pack('!HH', tag, len(val)) + val

def exported_pdu(name, payload):
    return exp_tlv(12, name.encode()) + struct.pack('!HH', 0, 0) + payload

CL, SV = '192.0.2.10', '192.0.2.20'
LABELS = []
A = b'\x01'

def mark(frames, text):
    LABELS.append((len(frames) + 1, text))

def lines(*ls):
    return b''.join(l + b'\r\n' for l in ls)

def main():
    out = sys.argv[1]
    frames = []
    # ---- session 1: TCP 6667 ----
    t = Tcp(frames, CL, SV, 42001, 6667)
    mark(frames, 'client requests (TCP 6667)')
    t.send('c', b'NICK alice\r\nPRIVMSG #chan :' + A + b'ACTION waves' + A + b'\r\nUSER a')   # the reproducer
    t.send('c', lines(b'NICK alice', b'USER alice 0 * :Alice A'))
    t.send('c', lines(b'JOIN #chan', b'JOIN #a,#b key1,key2', b'PART #chan :bye'))
    t.send('c', lines(b'PRIVMSG #chan :hello world', b'PRIVMSG bob :a : colon in the trailer'))
    t.send('c', lines(b'PRIVMSG bob :' + A + b'VERSION' + A))                 # CTCP without parameters
    t.send('c', lines(b'PRIVMSG #chan :' + A + b'ACTION waves' + A + b' and more'))
    t.send('c', lines(b':alice!a@host NOTICE bob :' + A + b'PING 123456' + A))   # prefix, NOTICE, CTCP
    t.send('c', lines(b'QUIT', b'QUIT :', b'QUIT  ', b'AWAY'))                   # no parameters
    t.send('c', lines(b'MODE #chan +o bob', b'MODE   #chan   +o   bob  ', b'WHO #chan %cuhsnfdar,1'))
    t.send('c', lines(b'PING :irc.example.com', b'PONG irc.example.com', b'TOPIC #chan :a topic'))
    t.send('c', lines(b'', b'', b'NICK bob'))                                    # empty lines
    t.send('c', lines(b'JOIN :' + A + b'X' + A, b'MODE #chan ' + A + b'X' + A))  # tag data outside PRIVMSG/NOTICE
    t.send('c', lines(b'PRIVMSG #chan ' + A + b'ACTION' + A + b' tail',
                      b'PRIVMSG #chan ' + A + b'ACTION' + A + b' :trailer',
                      b'NOTICE #chan x ' + A + b'PING 1' + A))                   # tags in the parameters
    t.send('c', lines(b'PRIVMSG a' + A + b'X' + A + b'b c', b'PRIVMSG a b' + A + b'X' + A))
    t.send('c', lines(b'123 numeric', b'456', b':p 789 x'))                       # numeric commands in a request
    t.send('c', lines(b'PASS placeholder'))                                        # constant placeholder, no real password
    # ---- server responses ----
    mark(frames, 'server responses (TCP 6667)')
    t.send('s', lines(b':irc.example.com 001 alice :Welcome to the network alice',
                      b':irc.example.com 002 alice :Your host is irc.example.com',
                      b':irc.example.com 353 alice = #chan :alice bob @carol',
                      b':irc.example.com 366 alice #chan :End of /NAMES list.'))
    t.send('s', lines(b'PING :irc.example.com', b'PONG', b'NOTICE AUTH :*** Looking up your hostname'))
    t.send('s', lines(b':bob!b@host PRIVMSG #chan :' + A + b'ACTION dances' + A,
                      b':bob!b@host PRIVMSG alice :' + A + b'VERSION' + A,
                      b':bob!b@host NOTICE alice :' + A + b'PING 1' + A + b' x'))
    t.send('s', lines(b':irc.example.com 999', b':irc.example.com 372 alice', b':irc.example.com PONG   ', b'432'))
    t.send('s', lines(b':irc.example.com 005 alice CHANTYPES=# PREFIX=(ov)@+ :are supported'))
    t.send('s', lines(b':irc.example.com NOTICE alice ' + A + b'X' + A + b' y',
                      b':irc.example.com NOTICE alice y ' + A + b'X' + A,
                      b':irc.example.com NOTICE alice ' + A + b'X' + A + b' :trailer',
                      b':irc.example.com 100 alice y' + A + b'X' + A + b' z'))
    t.send('s', lines(b':irc.example.com JOIN :' + A + b'X' + A))                 # tag outside NOTICE/PRIVMSG
    t.send('s', lines(b':irc.example.com MODE alice  +i  ', b'   :x PRIVMSG a :b', b'  PING   :x'))
    t.send('s', b'\r\n')                                                           # empty frame content
    t.send('s', b':irc.example.com 001 alice :a line with no end')                # no line end in the segment
    t.send('c', b'QUIT :done\r\n')
    t.fin()
    # ---- session 2: the second default port, 57000 ----
    t = Tcp(frames, CL, SV, 42002, 57000)
    mark(frames, 'TCP 57000')
    t.send('c', lines(b'NICK carol', b'USER carol 0 * :Carol'))
    t.send('s', lines(b':irc.example.com 001 carol :Welcome'))
    write_pcap(os.path.join(out, 'irc-coverage.pcap'), frames)
    n_main = len(frames)

    # ---- malformed capture ----
    frames = []
    t = Tcp(frames, CL, SV, 43001, 6667)
    mark(frames, 'MALFORMED capture: requests')
    t.send('c', lines(b':prefixonly', b':prefix ', b'   ', b':p    ', b'PRIVMSG #chan :' + A + b'ACTION waves'))
    t.send('c', lines(b'PRIVMSG #chan ' + A + b'ACTION', b'PRIVMSG #chan :' + A))
    t.send('c', lines(b'PRIVMSG #chan x ' + A + b'ACTION waves'))
    mark(frames, 'MALFORMED: responses')
    t.send('s', lines(b':prefixonly', b':prefix ', b'   ', b':p    ', b':s NOTICE a :' + A + b'ACTION waves'))
    t.send('s', lines(b':s NOTICE a ' + A + b'ACTION', b':s NOTICE a :' + A, b'NOTICE a x ' + A + b'ACTION waves'))
    t.send('s', lines(b'NOTICE ' + A + b'X', b'NOTICE x' + A + b'X' + A))
    write_pcap(os.path.join(out, 'irc-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv:
        for n, s in LABELS:
            print(n, s)
        print('main frames', n_main, 'malformed frames', len(frames))

main()
