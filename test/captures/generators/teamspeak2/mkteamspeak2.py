#!/usr/bin/env python3
# Generates test/captures/teamspeak2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the TeamSpeak 2 coverage captures. Usage: mkteamspeak2.py <outdir> [-v]
Writes teamspeak2-coverage.pcap (main) and teamspeak2-coverage-malformed.pcap.
UDP port 8767 is registered by default. The CRC32 of every packet is
computed with zlib.crc32 (the checksum field zeroed). Names and passwords
are made up; the session keys are arbitrary numbers, there is no
encryption in the protocol. Everything is synthetic (192.0.2.0/24)."""
import os
import struct
import sys
import zlib
from pcaplib import CLI, SRV, udp, write_pcap

C_STD, C_ACK, C_CVOICE, C_SVOICE, C_CONN = 0xbef0, 0xbef1, 0xbef2, 0xbef3, 0xbef4
KEY = 0x11223344
CID = 7

def crc_at(data, off):
    z = bytearray(data)
    z[off:off + 4] = b'\x00\x00\x00\x00'
    return struct.pack('<I', zlib.crc32(bytes(z)) & 0xffffffff)

def conn(typ, seq, payload=b'', key=KEY, cid=CID, badcrc=False):
    d = struct.pack('<HHIII', C_CONN, typ, key, cid, seq) + b'\x00\x00\x00\x00' + payload
    c = crc_at(d, 16)
    if badcrc:
        c = bytes(b ^ 0xff for b in c)
    return d[:16] + c + d[20:]

def std(typ, seq, payload=b'', fragcount=0, resend=0, key=KEY, cid=CID, badcrc=False):
    d = struct.pack('<HHIIIHH', C_STD, typ, key, cid, seq, resend, fragcount) + b'\x00\x00\x00\x00' + payload
    c = crc_at(d, 20)
    if badcrc:
        c = bytes(b ^ 0xff for b in c)
    return d[:20] + c + d[24:]

def ack(seq, key=KEY, cid=CID):
    return struct.pack('<HHIII', C_ACK, 0, key, cid, seq)

def voice(klass, codec, seq, data, key=KEY, cid=CID):
    return struct.pack('<HHIII', klass, codec, key, cid, seq) + data

def s(txt, n=30):
    """A fixed size Pascal string (length octet, text, zero padding): FT_UINT_STRING fields."""
    b = txt.encode()
    return bytes([len(b)]) + b + b'\x00' * (n - 1 - len(b))

def channellist(chans):
    out = struct.pack('<I', len(chans))
    for (cid, flags, codec, parent, order, maxu, name, topic, desc) in chans:
        out += struct.pack('<IBBHIHH', cid, flags, 0, codec, parent, order, maxu)
        out += name.encode() + b'\x00' + topic.encode() + b'\x00' + desc.encode() + b'\x00'
    return out

def playerlist(players, extra=b''):
    out = struct.pack('<I', len(players))
    for (pid, chan, flags, nick) in players:
        out += struct.pack('<IIIH', pid, chan, 0, flags) + s(nick)
    return out + extra

def u(sport, dport, payload, up=True):
    if up:
        return udp(sport, dport, payload)
    return udp(sport, dport, payload, src=SRV, dst=CLI)

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    CP, SP = 40500, 8767
    c2s = lambda p: u(CP, SP, p, True)
    s2c = lambda p: u(SP, CP, p, False)
    # connection class
    add('ping', c2s(conn(1, 1, b'\x00\x00\x00\x00')))
    add('pingreply', s2c(conn(2, 1, struct.pack('<I', 1))))
    add('loginrequest', c2s(conn(3, 2, s('TeamSpeak') + s('Linux') + b'\x00' * 10 + s('alice') + s('secret') + s('Alice the nick'))))
    add('loginreply', s2c(conn(4, 2, s('Example TS2 Server') + s('Linux') + b'\x00' * 9 + b'\x00\x00\x00' + b'\x00' * 80
                               + struct.pack('<I', 0x55667788) + b'\x00' * 4 + s('Welcome to the example server', 40))))
    # reliable (standard class), client to server: sequence numbers 1000.. (first one sets the baseline)
    add('c-loginpart2', c2s(std(5, 1000, b'\x01\x02' + s('Default Channel') + s('Sub Channel') + s('chanpass') + b'\x00\x00\x00\x00')))
    add('s-ack', s2c(ack(1000)))
    chans = [(1, 0x00, 0, 0, 1, 32, 'Lobby', 'Welcome', 'The main lobby'),
             (2, 0x01 | 0x04, 1, 0, 2, 8, 'Moderated', 'Topic two', 'Unregistered, password protected'),
             (3, 0x02 | 0x08 | 0x10, 2, 2, 3, 0, 'Sub', '', ''),
             (4, 0x1f, 5, 1, 4, 16, 'All flags', 'T', 'D')]
    cl = channellist(chans)
    # server to client: sequence 5000..; the channel list over three fragments
    add('s-chanlist-1', s2c(std(6, 5000, cl[:40], fragcount=2)))
    add('c-ack-1', c2s(ack(5000)))
    add('s-chanlist-2', s2c(std(6, 5001, cl[40:80], fragcount=1)))
    add('s-chanlist-3', s2c(std(6, 5002, cl[80:], fragcount=0)))
    pl = playerlist([(1, 1, 0x0000, 'alice'), (2, 2, 0x0001 | 0x0002, 'bob'), (3, 1, 0x0004 | 0x0008 | 0x0010, 'carol')], b'\x00' * 20)
    add('s-playerlist', s2c(std(7, 5003, pl)))
    add('s-loginend', s2c(std(8, 5004, b'\x00\x01\x02\x03')))
    add('s-newplayer', s2c(std(0x64, 5005, struct.pack('<II', 4, 1) + b'\x00' * 6 + s('dave', 10))))
    add('s-knownupdate', s2c(std(0x68, 5006, struct.pack('<IH', 4, 0x001f))))
    add('s-channelchange', s2c(std(0x67, 5007, struct.pack('<IIIH', 4, 1, 2, 0))))
    add('s-playerleft', s2c(std(0x65, 5008, struct.pack('<I', 3) + b'\x00' * 8 + b'trailing')))
    add('s-playerkicked', s2c(std(0x66, 5009, struct.pack('<I', 2) + b'\x00' * 8)))
    add('s-text', s2c(std(0x82, 5010, b'\x01\x00\x00\x00hello everyone\x00')))
    nxt = [5011]
    for name, t in (('chan-playerlist', 0x6c), ('chan-list-update', 0x6e), ('chan-deleted', 0x73), ('chan-name', 0x6f),
                    ('chan-topic', 0x70), ('chan-password', 0x71), ('create-channel', 0xc9), ('bounce', 0xfc0f),
                    ('unknown-type', 0x7777)):
        add('s-' + name, s2c(std(t, nxt[0], b'\x00' * 8)))
        nxt[0] += 1
    # client to server
    add('c-switchchannel', c2s(std(0x12f, 1001, struct.pack('<I', 2) + s('chanpass', 10))))
    add('c-changestatus', c2s(std(0x130, 1002, struct.pack('<H', 0x0005))))
    add('c-disconnect', c2s(std(0x12c, 1003, b'\x00\x00\x00\x00')))
    add('c-fragmented-text', c2s(std(0x82, 1004, b'\x00' * 20, fragcount=1)))
    add('c-fragmented-text-2', c2s(std(0x82, 1005, b'\x01' * 20, fragcount=0)))
    # out of order / retransmission (sequence number that is not last + 1): ignored
    add('c-ooo-dup', c2s(std(0x130, 1002, struct.pack('<H', 0x0005))))
    add('c-ooo-jump', c2s(std(0x130, 1100, struct.pack('<H', 0x0005))))
    add('c-resend', c2s(std(0x130, 1006, struct.pack('<H', 0x0001), resend=3)))
    # voice: client and server, every codec
    for i, codec in enumerate((0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700, 0x0800, 0x0900, 0x0a00, 0x0b00, 0x0c00, 0x0d00)):
        add('c-voice-%d' % i, c2s(voice(C_CVOICE, codec, 10 + i, bytes(range(20)))))
    for i, codec in enumerate((0x0000, 0x0500, 0x0c00)):
        add('s-voice-%d' % i, s2c(voice(C_SVOICE, codec, 20 + i, bytes(range(24)), cid=3)))
    add('s-ack-2', s2c(ack(1001)))
    add('unknown-class', c2s(struct.pack('<HHIII', 0xbeef, 1, KEY, CID, 1) + b'\x00' * 8))
    # ---- second conversation: server speaks first, a fragmented first packet; login without ping ----
    CP2 = 40501
    c2s2 = lambda p: u(CP2, SP, p, True)
    s2c2 = lambda p: u(SP, CP2, p, False)
    add('c2-first-fragmented', s2c2(std(6, 900, cl[:30], fragcount=1, key=0x99)))
    add('c2-fragment-last', s2c2(std(6, 901, cl[30:], fragcount=0, key=0x99)))
    add('c2-nonfrag', s2c2(std(8, 902, b'\x00\x00', key=0x99)))
    add('c2-client', c2s2(std(0x130, 50, struct.pack('<H', 3), key=0x99)))
    add('c2-client2', c2s2(std(0x130, 51, struct.pack('<H', 0), key=0x99)))
    add('c2-loginrequest', c2s2(conn(3, 52, s('TeamSpeak') + s('Win32') + b'\x00' * 10 + s('') + s('') + s('anon'), key=0x99)))
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    CP, SP = 40600, 8767
    c2s = lambda p: u(CP, SP, p, True)
    s2c = lambda p: u(SP, CP, p, False)
    # a CRC field that is the last field: the expected checksum is shown as 0 (observation)
    add('ping-no-payload', c2s(conn(1, 1)))
    add('disconnect-no-payload', c2s(std(0x12c, 1003, b'')))
    add('loginreply-bad-crc', s2c(conn(4, 3, s('Server') + b'\x00' * 150 + b'Hi\x00', badcrc=True)))
    add('std-bad-crc', c2s(std(0x130, 1006, struct.pack('<H', 0x0005), badcrc=True)))
    add('short-4', c2s(b'\xf4\xbe\x01\x00'))
    add('short-header', c2s(struct.pack('<HHI', C_CONN, 1, 5)))
    add('conn-no-crc', c2s(struct.pack('<HHIII', C_CONN, 1, 5, 1, 1) + b'\x00\x00'))
    add('loginrequest-short', c2s(conn(3, 2, b'TeamSpeak\x00' + b'\x00' * 40)))
    add('loginreply-short', s2c(conn(4, 2, b'Server\x00' + b'\x00' * 40)))
    add('pingreply-short', s2c(struct.pack('<HHIII', C_CONN, 2, 5, 1, 1) + b'\x00' * 4))
    add('ack-short', s2c(struct.pack('<HHII', C_ACK, 0, 5, 1)))
    add('std-short', c2s(struct.pack('<HHIIIH', C_STD, 5, 5, 1, 100, 0)))
    add('std-first', c2s(std(0x130, 2000, struct.pack('<H', 1))))
    add('playerlist-lies', s2c(std(7, 3000, struct.pack('<I', 5000) + b'\x01' * 30)))
    add('playerlist-short', s2c(std(7, 3001, struct.pack('<I', 2) + b'\x01' * 10)))
    add('chanlist-lies', s2c(std(6, 3002, struct.pack('<I', 9) + struct.pack('<IBBHIHH', 1, 0, 0, 0, 0, 1, 1) + b'name-without-terminator')))
    add('chanlist-short', s2c(std(6, 3003, struct.pack('<I', 1) + b'\x01\x00')))
    add('loginpart2-short', c2s(std(5, 2001, b'\x01\x02abc')))
    add('newplayer-short', s2c(std(0x64, 3004, b'\x01\x00')))
    add('knownupdate-short', s2c(std(0x68, 3005, b'\x01\x00')))
    add('channelchange-short', s2c(std(0x67, 3006, b'\x01\x00')))
    add('playerleft-short', s2c(std(0x65, 3007, b'\x01\x00')))
    add('switchchannel-short', c2s(std(0x12f, 2002, b'\x01')))
    add('changestatus-short', c2s(std(0x130, 2003, b'')))
    add('frag-count-huge', s2c(std(6, 3008, b'x' * 10, fragcount=0xffff)))
    add('frag-next', s2c(std(6, 3009, b'y' * 10, fragcount=3)))
    add('frag-skip', s2c(std(6, 3010, b'z' * 10, fragcount=0)))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcap(os.path.join(out, 'teamspeak2-coverage.pcap'), F)
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 'teamspeak2-coverage-malformed.pcap'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
