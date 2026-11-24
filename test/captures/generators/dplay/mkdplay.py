#!/usr/bin/env python3
# Generates test/captures/dplay_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DirectPlay dissector
(packet-dplay.c, DirectPlay 6-9 session protocol).

DirectPlay is found by the heuristics "dplay_udp" and "dplay_tcp", which
are disabled by default: dissect with --enable-heuristic dplay_udp
--enable-heuristic dplay_tcp. A message starts with a 28 octet header
(size and token, a sockaddr_in, "play", command, dialect) followed by
the command's data: session descriptions, packed and super packed
players, security descriptions and NUL-terminated UTF-16LE strings
(decoded by display_unicode_string() in packet-smb-common.c). A message
without "play" whose token is 0xfab, 0xbab or 0xcab is a player to
player message. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkdplay.py <output directory>

Writes:
  dplay-coverage.pcap            every command the dissector decodes, all
                                 dialects, packed and super packed players
                                 with every length type, type 0x15 packets
                                 holding other messages, player to player
                                 messages, over UDP and TCP
  dplay-coverage-malformed.pcap  reproducer lengths beyond the data,
                                 messages cut short
"""

import os
import socket
import struct
import sys
import uuid

HOST = '192.0.2.1'
PEER = '192.0.2.2'
INST = uuid.UUID('11111111-2222-3333-4444-555555555555')
GAME = uuid.UUID('66666666-7777-8888-9999-aaaaaaaaaaaa')
MSG = uuid.UUID('0f0e0d0c-0b0a-0908-0706-050403020100')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def mac(ip):
    return bytes([2, 0, 0, 0, 0, int(ip.split('.')[-1])])


def ip4(src, dst, proto, payload):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + h + payload


def udp(payload, rev=False, sport=47624, dport=2350):
    src, dst = (PEER, HOST) if rev else (HOST, PEER)
    if rev:
        sport, dport = dport, sport
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 17, len(u))
    return ip4(src, dst, 17, u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:])


class Tcp:
    def __init__(self, cport, sport, frames):
        self.cport, self.sport, self.frames = cport, sport, frames
        self.seq = {True: 1000, False: 5000}
        self.seg(True, 0x02, b'')
        self.seq[True] += 1
        self.seg(False, 0x12, b'')
        self.seq[False] += 1
        self.seg(True, 0x10, b'')

    def seg(self, c2s, flags, payload):
        src, dst = (HOST, PEER) if c2s else (PEER, HOST)
        sp, dp = (self.cport, self.sport) if c2s else (self.sport, self.cport)
        ack = self.seq[not c2s] if flags & 0x10 else 0
        opts = b'\x02\x04\x05\xb4\x01\x01\x04\x02' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sp, dp, self.seq[c2s], ack,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.frames.append(ip4(src, dst, 6, t))
        self.seq[c2s] += len(payload)

    def send(self, c2s, payload):
        self.seg(c2s, 0x18, payload)


def header(cmd, body, dialect=0x000e, token=0xfab, port=2300, ip='192.0.2.1'):
    size = 28 + len(body)
    return (struct.pack('<I', (token << 20) | size) + struct.pack('<H', 2) +
            struct.pack('>H', port) + socket.inet_aton(ip) + bytes(8) + b'play' +
            struct.pack('<HH', cmd, dialect) + body)


def u16z(s):
    return s.encode('utf-16-le') + b'\0\0'


def sess_desc(flags=0, maxp=8, curp=1):
    return (struct.pack('<II', 80, flags) + INST.bytes + GAME.bytes +
            struct.pack('<II', maxp, curp) + bytes(8) + bytes(8) + struct.pack('<IIII', 1, 2, 3, 4))


def dpid(n):
    return struct.pack('<I', n)


def packed_player(short=None, long=None, sp=b'', pd=b'', ids=(), parent=None,
                  flags=0x0f, pid=0x101, size=None):
    """Packed player; the size covers the fixed part, names, data and
    player IDs. The dissector shows a parent ID when the size, counted
    from the start of the structure, leaves room for it (before the fix
    only when the absolute offset in the packet minus 4 was below the
    size, so frame 11 uses a size larger than the structure)."""
    names = (u16z(short) if short else b'') + (u16z(long) if long else b'')
    var = names + sp + pd + b''.join(dpid(i) for i in ids)
    if size is None:
        size = 48 + len(var) + (4 if parent is not None else 0)
    pp = struct.pack('<II', size, flags) + dpid(pid)
    pp += struct.pack('<IIIII', len(u16z(short)) if short else 0,
                      len(u16z(long)) if long else 0, len(sp), len(pd), len(ids))
    pp += dpid(0x100) + struct.pack('<II', 48, 0x0e) + bytes(4) + var
    if parent is not None:
        pp += dpid(parent)
    return pp


def spp_value(t, v):
    return {1: struct.pack('<B', v), 2: struct.pack('<H', v), 3: struct.pack('<I', v)}[t]


def super_packed(flags=0, short=None, long=None, pd=None, pdt=0, sp=None, spt=0,
                 ids=None, idt=0, parent=None, shortcuts=None, sct=0, pid=0x201):
    mask = ((1 if short else 0) | (2 if long else 0) | (spt << 2) | (pdt << 4) |
            (idt << 6) | (0x100 if parent is not None else 0) | (sct << 9))
    b = struct.pack('<II', 16, flags) + dpid(pid) + struct.pack('<I', mask)
    b += struct.pack('<I', 0x0e) if flags & 1 else dpid(0x100)
    if short:
        b += u16z(short)
    if long:
        b += u16z(long)
    if pdt:
        b += spp_value(pdt, len(pd)) + pd
    if spt:
        b += spp_value(spt, len(sp)) + sp
    if idt:
        b += spp_value(idt, len(ids)) + b''.join(dpid(i) for i in ids)
    if parent is not None:
        b += dpid(parent)
    if sct:
        b += spp_value(sct, len(shortcuts)) + b''.join(dpid(i) for i in shortcuts)
    return b


def security_desc():
    return struct.pack('<II', 24, 0x01) + bytes(4) + bytes(4) + struct.pack('<II', 1, 0x6610)


def type07(sspi=None, capi=None):
    b = dpid(0x102) + security_desc()
    b += struct.pack('<III', 1 if sspi else 0, 1 if capi else 0, 0)
    if sspi:
        b += u16z(sspi)
    if capi:
        b += u16z(capi)
    return b


def player_msg(pp=None, password=None):
    b = dpid(0) + dpid(0x101) + dpid(0x301) + struct.pack('<II', 28 if pp else 0, 1 if password else 0)
    if pp:
        b += pp
    if password is not None:
        b += u16z(password)
    return b


def type13(pp=None, password=None, tick=0x12345678):
    b = dpid(0) + dpid(0x101) + dpid(0x301) + struct.pack('<II', 28 if pp else 0, 1 if password else 0)
    if pp:
        b += pp
    if password is not None:
        b += u16z(password)
    return b + struct.pack('<I', tick)


def type1a(name=None, password=None, flags=0):
    b = dpid(0) + struct.pack('<II', 1 if name else 0, 1 if password else 0) + sess_desc(flags)
    if name:
        b += u16z(name)
    if password:
        b += u16z(password)
    return b


def type15(inner_cmd, inner_body, idx=0, total=1):
    inner = b'play' + struct.pack('<HH', inner_cmd, 0x000e) + inner_body
    return MSG.bytes + struct.pack('<IIIIII', idx, len(inner), 0, total, len(inner), 0) + inner


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f = []
    # 1-2: enum sessions with a password, and without
    f.append(udp(header(0x02, GAME.bytes + struct.pack('<II', 1, 0x41) + u16z('secret'))))
    f.append(udp(header(0x02, GAME.bytes + struct.pack('<II', 0, 0x02), dialect=0x0009)))
    # 3: enum sessions reply with every session flag and a game name
    f.append(udp(header(0x01, sess_desc(0xffffffff, 16, 3) + struct.pack('<I', 1) +
                        u16z('Coverage Game')), rev=True))
    # 4: enum sessions reply without a game name
    f.append(udp(header(0x01, sess_desc(0x0004) + struct.pack('<I', 0), dialect=0x000a), rev=True))
    # 5: reproducer dplay_misc.pcap frame 2: game name followed by other data
    f.append(udp(header(0x01, sess_desc() + struct.pack('<I', 1) + u16z('Game') + b'TRAILING'),
                 rev=True))
    # 6: enum players (no data), dialect 6.1a
    f.append(udp(header(0x04, b'', dialect=0x000b)))
    # 7: request player ID
    f.append(udp(header(0x05, struct.pack('<I', 0x0000001f), dialect=0x000c)))
    # 8: request player reply with SSPI and CAPI provider names
    f.append(udp(header(0x07, type07('NTLM', 'Microsoft Base Cryptographic Provider')), rev=True))
    # 9: request player reply without provider names
    f.append(udp(header(0x07, type07(), dialect=0x000d), rev=True))
    # 10: create player with a packed player: names, SP data, player
    # data and two player IDs; then a password
    pp = packed_player('Alice', 'Alice Liddell', b'\x01\x02\x03\x04', b'\xaa\xbb', (0x401, 0x402))
    f.append(udp(header(0x08, player_msg(pp, 'pw'))))
    # 11: create group, packed player without names or data, with a parent
    # ID (size 0x200)
    f.append(udp(header(0x09, player_msg(packed_player(flags=0, pid=0x601, parent=0x501,
                                                       size=0x200)))))
    # 12-17: delete player, delete group, add player to group, delete
    # player from group, 0x2e and 0x38, without packed player or password
    for cmd in (0x0b, 0x0c, 0x0d, 0x0e, 0x2e, 0x38):
        f.append(udp(header(cmd, player_msg())))
    # 18: player data changed
    f.append(udp(header(0x0f, dpid(0) + dpid(0x101) + struct.pack('<II', 4, 44) + b'DATA')))
    # 19: player data changed with no data
    f.append(udp(header(0x0f, dpid(0) + dpid(0x101) + struct.pack('<II', 0, 44))))
    # 20: reproducer dplay_misc.pcap frame 1: add forward request with a
    # password and the tick count after it
    f.append(udp(header(0x13, struct.pack('<III', 1, 2, 3) + struct.pack('<II', 0, 1) +
                        u16z('pw') + struct.pack('<I', 0x12345678))))
    # 21: add forward request with a packed player, no password
    f.append(udp(header(0x13, type13(packed_player('Bob', None, b'', b'\x01'), None, 0x0badf00d))))
    # 22-27: type 0x15 packets holding 0x05, 0x07, 0x08, 0x13, 0x1a and 0x16
    f.append(udp(header(0x15, type15(0x05, struct.pack('<I', 0x09)))))
    f.append(udp(header(0x15, type15(0x07, type07('Kerberos', None), 0, 2)), rev=True))
    f.append(udp(header(0x15, type15(0x08, player_msg(packed_player('Carol'), 'x'), 1, 2))))
    f.append(udp(header(0x15, type15(0x13, type13(None, 'pass', 7)))))
    f.append(udp(header(0x15, type15(0x1a, type1a('Inner', None)))))
    f.append(udp(header(0x15, type15(0x16, dpid(0x101) + struct.pack('<I', 5)))))
    # 28-29: ping and pong
    f.append(udp(header(0x16, dpid(0x101) + struct.pack('<I', 1000))))
    f.append(udp(header(0x17, dpid(0x102) + struct.pack('<I', 1000)), rev=True))
    # 30: session desc changed with session name and password
    f.append(udp(header(0x1a, type1a('Renamed Session', 'newpass', 0x00000040)), rev=True))
    # 31: session desc changed without them
    f.append(udp(header(0x1a, type1a()), rev=True))
    # 32: super enum players reply: a system player with names and 1 octet
    # lengths, a player with 2 octet lengths and a parent, a group with
    # 4 octet lengths and shortcuts, a shortcut; and a password
    players = [
        super_packed(0x0f, 'Sys', 'System Player', b'\x01', 1, b'\x02\x03', 1, [0x401], 1),
        super_packed(0x02, 'Dave', None, b'\x04\x05', 2, b'\x06', 2, [0x402, 0x403], 2, parent=0x501),
    ]
    groups = [super_packed(0x04, None, 'Group One', b'\x07' * 3, 3, b'\x08', 3, [0x404], 3,
                           shortcuts=[0x601, 0x602], sct=1, pid=0x301)]
    shortcuts = [super_packed(0x00, None, None, shortcuts=[0x603], sct=2, pid=0x302),
                 super_packed(0x00, None, None, shortcuts=[0x604], sct=3, pid=0x303)]
    body = struct.pack('<IIIIIII', len(players), len(groups), 0x80, len(shortcuts), 0x28, 0x78, 1)
    body += sess_desc(0x0100, 8, 2) + u16z('Super Game') + u16z('sp')
    body += b''.join(players + groups + shortcuts)
    f.append(udp(header(0x29, body), rev=True))
    # 33: super enum players reply without password or players
    body = struct.pack('<IIIIIII', 0, 0, 0, 0, 0x28, 0x78, 0) + sess_desc() + u16z('Empty')
    f.append(udp(header(0x29, body), rev=True))
    # 34: 0x2f
    f.append(udp(header(0x2f, dpid(0x777))))
    # 35: a command without data decoding (0x24), unknown dialect
    f.append(udp(header(0x24, b'\x00\x01\x02\x03', dialect=0x0042)))
    # 36: player to player messages: remote (0xfab), forwarded (0xcab)
    # and 0xbab tokens
    for tok in (0xfab, 0xcab, 0xbab):
        p2p = struct.pack('<I', (tok << 20) | 32) + struct.pack('<H', 2) + struct.pack('>H', 2300) + \
            bytes(12) + b'\x00\x02\x03\x04\x05\x06\x07\x08'
        f.append(udp(p2p, sport=2350, dport=2350))
    # TCP: enum sessions and reply on port 47624 (dplay_tcp)
    c = Tcp(1030, 47624, f)
    c.send(True, header(0x02, GAME.bytes + struct.pack('<II', 0, 0x01)))
    c.send(False, header(0x01, sess_desc(0x10) + struct.pack('<I', 1) + u16z('TCP Game')))
    c.send(True, header(0x05, struct.pack('<I', 0x08)))
    pcap(os.path.join(out, 'dplay-coverage.pcap'), f)

    m = []
    # reproducer dplay_misc.pcap frames 3-5: super packed player data and
    # SP data lengths 0xffffffff, type 0x0f data size 0xffffffff, packed
    # player SP and player data sizes 0xffffffff
    spp = struct.pack('<IIII', 0x20, 1, 0x1234, (3 << 2) | (3 << 4)) + struct.pack('<I', 0xe) + \
        struct.pack('<I', 0xffffffff) + struct.pack('<I', 0xffffffff)
    body = struct.pack('<IIIIIII', 0xffffffff, 0, 0, 0, 0, 0, 0) + sess_desc() + u16z('G') + spp * 50
    m.append(udp(header(0x29, body)))
    m.append(udp(header(0x0f, struct.pack('<IIII', 1, 2, 0xffffffff, 0) + b'DATA')))
    pp = struct.pack('<IIIIIIII', 48, 0, 7, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff) + bytes(16)
    m.append(udp(header(0x08, struct.pack('<IIIII', 1, 2, 3, 1, 0) + pp + bytes(40))))
    # packed player with player data size beyond the data
    pp = packed_player(None, None, b'', b'\x01\x02')
    pp = pp[:24] + struct.pack('<I', 100) + pp[28:]
    m.append(udp(header(0x08, player_msg(pp))))
    # super packed player with a 2 octet SP data length beyond the data
    m.append(udp(header(0x29, struct.pack('<IIIIIII', 1, 0, 0, 0, 0, 0, 0) + sess_desc() +
                        u16z('G') + struct.pack('<IIII', 16, 0, 1, 2 << 2) + dpid(0) + b'\xff\x00')))
    # header cut short (25 octets with "play" at 20)
    m.append(udp(header(0x02, b'')[:25]))
    # session description cut short
    m.append(udp(header(0x01, sess_desc()[:30])))
    # request player reply with a provider name without its NUL
    m.append(udp(header(0x07, type07('NTLM')[:-2])))
    # player to player message with nothing after the sockaddr_in
    m.append(udp(struct.pack('<I', (0xfab << 20) | 32) + struct.pack('<H', 2) + bytes(19)))
    # not DirectPlay: a datagram shorter than 25 octets, and one with
    # another token
    m.append(udp(b'\x01' * 10))
    m.append(udp(struct.pack('<I', (0x123 << 20) | 32) + bytes(28)))
    pcap(os.path.join(out, 'dplay-coverage-malformed.pcap'), m)


if __name__ == '__main__':
    main()
