#!/usr/bin/env python3
# Generates test/captures/wow_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic WoW (login protocol, TCP 3724) captures.
# Usage: mkwow.py <outdir>
import struct
import sys
import os

PORT = 3724

class Pcap:
    def __init__(self):
        self.frames = []
        self.t = 1000000
    def add(self, data):
        self.t += 1
        self.frames.append((self.t, data))
    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, d in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(d), len(d)) + d)

def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Conn:
    '''One TCP connection with a client and a server.'''
    CMAC = bytes.fromhex('020000000001')
    SMAC = bytes.fromhex('020000000002')
    def __init__(self, pcap, cport, cip='192.0.2.10', sip='192.0.2.20'):
        self.p = pcap
        self.cport = cport
        self.ip = {'c': bytes(map(int, cip.split('.'))), 's': bytes(map(int, sip.split('.')))}
        self.seq = {'c': 1000, 's': 5000}
        self.ipid = 1
        self.seg('c', b'', 0x02)
        self.seq['c'] += 1
        self.seg('s', b'', 0x12)
        self.seq['s'] += 1
        self.seg('c', b'', 0x10)
    def seg(self, d, payload, flags=0x18, seq=None):
        o = 's' if d == 'c' else 'c'
        sp, dp = (self.cport, PORT) if d == 'c' else (PORT, self.cport)
        if seq is None:
            seq = self.seq[d]
        ack = 0 if flags == 0x02 else self.seq[o]
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = self.ip[d] + self.ip[o] + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0) + self.ip[d] + self.ip[o]
        self.ipid += 1
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + tcp
        macs = (self.CMAC, self.SMAC) if d == 'c' else (self.SMAC, self.CMAC)
        self.p.add(macs[1] + macs[0] + b'\x08\x00' + ip)
        return seq
    def send(self, d, payload, split=()):
        '''Send payload, optionally split at the given offsets.'''
        cuts = [0] + list(split) + [len(payload)]
        for a, b in zip(cuts, cuts[1:]):
            self.seg(d, payload[a:b])
            self.seq[d] += b - a
    def resend(self, d, payload, seq):
        self.seg(d, payload, seq=seq)
    def close(self):
        self.seg('c', b'', 0x11)
        self.seq['c'] += 1
        self.seg('s', b'', 0x11)

def client_challenge(cmd, acct=b'ACCOUNT', pv=3, build=12340, size=None):
    body = b'WoW\0' + bytes([3, 3, 5]) + struct.pack('<H', build)
    body += b'68x\0' + b'niW\0' + b'SUne' + struct.pack('<i', 60) + bytes([192, 0, 2, 10])
    body += bytes([len(acct)]) + acct
    if size is None:
        size = len(body)
    return bytes([cmd, pv]) + struct.pack('<H', size) + body

def srv_challenge(result=0, gen=b'\x07', prime=None):
    if result:
        return bytes([0, 0, result])
    prime = prime or bytes(range(1, 33))
    return (bytes([0, 0, 0]) + bytes(range(32)) + bytes([len(gen)]) + gen +
            bytes([len(prime)]) + prime + bytes(range(100, 132)) + bytes(range(200, 216)))

def logon_proof_c(nkeys=1):
    m = bytes(range(32)) + bytes(range(20)) + bytes(range(20, 40)) + bytes([nkeys])
    for i in range(nkeys):
        m += struct.pack('<HI', i, 0x1000 + i) + b'KEY' + bytes([i]) + bytes(range(20))
    return bytes([1]) + m

def logon_proof_s(result=0):
    if result:
        return bytes([1, result, 0, 0])
    return bytes([1, 0]) + bytes(range(20)) + struct.pack('<I', 0x1234)

def reconnect_proof_c():
    return bytes([3]) + bytes(range(16)) + bytes(range(20)) + bytes(range(20, 40)) + bytes([0])

def realm(rtype, flag, name, addr, pop, chars, cat, rid, term=True):
    t = b'\0' if term else b''
    return (struct.pack('<IB', rtype, flag) + name + t + addr + t +
            struct.pack('<fBBB', pop, chars, cat, rid))

def realm_list_s(realms, footer=b'\x10\x00'):
    body = struct.pack('<I', 0) + bytes([len(realms)]) + b''.join(realms) + footer
    return bytes([0x10]) + struct.pack('<H', len(body)) + body

def realm_list_s_raw(body):
    return bytes([0x10]) + struct.pack('<H', len(body)) + body

def survey(sid=1, err=0, data=b'ZZZZ'):
    return bytes([4]) + struct.pack('<IBH', sid, err, len(data)) + data

def xfer_init(name=b'Patch.mpq', size=123456):
    return bytes([0x30, len(name)]) + name + struct.pack('<Q', size) + bytes(range(16))

def xfer_data(data):
    return bytes([0x31]) + struct.pack('<H', len(data)) + data

def main(out):
    P = Pcap()
    # 1: successful login, realm list in one segment
    c = Conn(P, 40001)
    c.send('c', client_challenge(0))
    c.send('s', srv_challenge())
    c.send('c', logon_proof_c(2))
    c.send('s', logon_proof_s())
    c.send('c', bytes([0x10]) + b'\0\0\0\0')
    c.send('s', realm_list_s([
        realm(0, 0, b'Azeroth', b'192.0.2.30:8085', 1.5, 2, 1, 1),
        realm(1, 0x40, b'Warfront', b'192.0.2.31:8085', 0.5, 0, 2, 2),
        realm(6, 0, b'Roleplay', b'192.0.2.32:8085', 2.0, 3, 3, 3),
        realm(8, 0x20, b'RPPvP', b'192.0.2.33:8085', 0.0, 1, 5, 4),
        realm(3, 0, b'Odd', b'x', 1.0, 0, 0, 5)]))
    c.close()
    # 2: failed logon results (server challenge failure, proof failure)
    for i, res in enumerate((4, 5, 9, 0x0e, 0xff)):
        c = Conn(P, 40010 + i)
        c.send('c', client_challenge(0, acct=b'BAD%d' % i))
        c.send('s', srv_challenge(res))
        c.send('c', logon_proof_c(0))
        c.send('s', logon_proof_s(res))
        c.close()
    # 3: logon challenge split in several segments (desegmentation)
    c = Conn(P, 40020)
    ch = client_challenge(0, acct=b'SPLITACCOUNTNAME')
    c.send('c', ch, split=(2, 3, 20, 40))
    c.send('s', srv_challenge())
    # two client PDUs in one segment, challenge then proof
    c.send('c', logon_proof_c(1) + bytes([0x10, 0, 0, 0, 0]))
    # realm list in three segments, with a retransmission of the middle one
    rl = realm_list_s([realm(0, 0, b'N%d' % i, b'1.2.3.%d:8085' % i, 1.0, i, 1, i) for i in range(6)])
    seq0 = c.seq['s']
    c.send('s', rl, split=(5, 40))
    c.resend('s', rl[5:40], seq0 + 5)
    # two server PDUs in one segment: realm list then another
    c.send('s', realm_list_s([realm(0, 0, b'X', b'Y', 1.0, 1, 1, 1)]) + realm_list_s([]))
    c.close()
    # 4: reconnect challenge and proof
    c = Conn(P, 40030)
    c.send('c', client_challenge(2, acct=b'RECONNECT'))
    c.send('s', bytes([2, 0]) + bytes(range(16)) + bytes(range(16, 32)))
    c.send('c', reconnect_proof_c())
    c.send('s', bytes([3, 0, 0]))
    c.close()
    # 4b: reconnect challenge refused (result != 0)
    c = Conn(P, 40031)
    c.send('c', client_challenge(2, acct=b'RECONNECT2'))
    c.send('s', bytes([2, 3]))
    c.close()
    # 5: survey result, transfer commands, unknown command
    c = Conn(P, 40040)
    c.send('s', survey(7, 0, b'compressed-survey-data'))
    c.send('c', survey(8, 1, b''))
    c.send('s', xfer_init())
    c.send('c', bytes([0x32]))
    c.send('c', bytes([0x33]) + struct.pack('<Q', 65536))
    c.send('s', xfer_data(bytes(range(100))))
    c.send('c', bytes([0x34]))
    c.send('s', bytes([0x7f, 1, 2, 3]))
    c.send('c', bytes([0x7e]))
    c.close()
    # 6: realm list with no realms and a long realm name just under 255
    c = Conn(P, 40050)
    c.send('c', bytes([0x10]) + b'\0\0\0\0')
    c.send('s', realm_list_s([]))
    c.send('c', bytes([0x10]) + b'\0\0\0\0')
    c.send('s', realm_list_s([realm(0, 0, b'L' * 253, b'addr', 1.0, 1, 1, 1)]))
    c.send('c', bytes([0x10]) + b'\0\0\0\0')
    c.send('s', realm_list_s([realm(0, 0, b'L' * 254, b'addr', 1.0, 1, 1, 1)]))
    c.close()
    P.write(os.path.join(out, 'wow-coverage.pcap'))

    # Malformed and boundary cases
    M = Pcap()
    # reproducers of "WoW: Always advance over C strings": names with no NUL
    c = Conn(M, 41000)
    c.send('c', bytes([0x10]) + b'\0\0\0\0')
    c.send('s', realm_list_s_raw(struct.pack('<I', 0) + bytes([3]) + struct.pack('<IB', 0, 0) + b'A' * 300))
    c.close()
    c = Conn(M, 41001)
    c.send('s', realm_list_s_raw(struct.pack('<I', 0) + bytes([2]) + struct.pack('<IB', 0, 0) + b'A' * 60))
    c.send('s', realm_list_s_raw(struct.pack('<I', 0) + bytes([200]) + struct.pack('<IB', 0, 0) + b'BC\0' + b'D' * 40))
    # unterminated name longer than 255, exactly 255 and shorter than the tvb
    c.send('s', realm_list_s_raw(struct.pack('<I', 0) + bytes([1]) + struct.pack('<IB', 0, 0) + b'E' * 255))
    c.send('s', realm_list_s_raw(struct.pack('<I', 0) + bytes([1]) + struct.pack('<IB', 0, 0) + b'F' * 254 + b'\0' + b'G\0'))
    c.send('s', realm_list_s_raw(struct.pack('<I', 0) + bytes([1]) + struct.pack('<IB', 0, 0) + b'F' * 255 + b'\0' + b'G\0'))
    c.close()
    # truncated server challenge, truncated client challenge, short PDUs
    c = Conn(M, 41002)
    c.send('s', bytes([0, 0, 0]) + bytes(10))
    c.send('c', client_challenge(0)[:20])
    c.send('c', client_challenge(0, size=0x40))
    c.send('c', client_challenge(0, size=2000))
    c.send('s', bytes([1, 0, 1, 2]))
    c.send('c', logon_proof_c(5)[:80])
    c.send('c', bytes([0x10]) + b'\0\0')
    c.send('s', xfer_data(b'x' * 10)[:6])
    c.send('s', bytes([0x30, 200]) + b'abc')
    c.send('s', survey(1, 0, b'abcdef')[:12])
    c.send('s', bytes([4, 1, 0, 0, 0, 0, 0xff, 0xff]) + b'tiny')
    c.send('s', bytes([2]))
    c.send('c', bytes([3, 1, 2]))
    c.send('s', realm_list_s_raw(b'\0\0'))
    c.send('s', bytes([0x10]) + struct.pack('<H', 0xffff) + b'short')
    c.close()
    M.write(os.path.join(out, 'wow-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1])
