#!/usr/bin/env python3
# Generates test/captures/raknet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic RakNet coverage captures (nothing from a real network).

Usage: mkraknet.py <outdir>
Writes raknet-coverage.pcap, raknet-coverage-malformed.pcap and frames.txt.
"Encrypted" RakNet fields (keys, proofs, challenges) are placeholder bytes.
"""
import struct
import sys
import os
import zlib

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipb(a): return bytes(map(int, a.split('.')))

def udp_frame(src, dst, sport, dport, payload, smac=1, dmac=2):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, ipb(src), ipb(dst))
    h = h[:10] + struct.pack('!H', ip_csum(h)) + h[12:]
    return bytes([2, 0, 0, 0, 0, dmac]) + bytes([2, 0, 0, 0, 0, smac]) + b'\x08\x00' + h + udp

class Cap:
    def __init__(self):
        self.frames, self.notes = [], []
    def add(self, fr, note=''):
        self.frames.append(fr); self.notes.append(note)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)

MAGIC = bytes([0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78])
CG = bytes([0xc1] * 8)      # client guid
SG = bytes([0x5e] * 8)      # server guid
CIP, SIP = '10.1.0.1', '10.1.0.2'
PH64 = bytes(range(64)); PH128 = bytes(range(128)); PH32 = bytes(range(32)); PH160 = bytes(range(160))

def sa4(ip, port):  return b'\x04' + bytes(~x & 0xff for x in ipb(ip)) + struct.pack('>H', port)
def sa6(port=19132): return b'\x06' + bytes(range(1, 17)) + struct.pack('>H', port)
SABAD = b'\x09'
def ts(n=1234): return struct.pack('>Q', n)

# offline messages
def unconnected_ping(op=1): return bytes([op]) + ts() + MAGIC + CG
def unconnected_pong(s=b'MCPE;server;1;1.0;0;10;123;x;Survival;1'): return b'\x1c' + ts() + SG + MAGIC + struct.pack('>H', len(s)) + s
def ocr1(pad=20): return b'\x05' + MAGIC + b'\x0a' + b'\x00' * pad
def ocrep1(enc=False): return b'\x06' + MAGIC + SG + (b'\x01' + struct.pack('>I', 0xdeadbeef) + PH64 if enc else b'\x00') + struct.pack('>H', 1400)
def ocr2(srv=None, enc=False, chal=False):
    b = b'\x07' + MAGIC
    if enc:
        b += struct.pack('>I', 0xdeadbeef) + (b'\x01' + PH64 if chal else b'\x00')
    return b + (srv or sa4(SIP, 30001)) + struct.pack('>H', 1400) + CG
def ocrep2(enc=False, addr=None):
    return b'\x08' + MAGIC + SG + (addr or sa4(CIP, 50001)) + struct.pack('>H', 1400) + (b'\x01' + PH128 if enc else b'\x00')
def conn_failed(op): return bytes([op]) + MAGIC + SG
def incompat(): return b'\x19' + b'\x05' + MAGIC + SG

# connected (system) messages
def conn_req(enc=0, client_key=0, pw=b'pass'):
    b = b'\x09' + CG + ts()
    if enc:
        b += b'\x01' + PH32 + (b'\x01' + PH160 if client_key else b'\x00')
    else:
        b += b'\x00'
    return b + pw
def ping(): return b'\x00' + ts()
def pong(): return b'\x03' + ts() + ts(5678)
def conn_accepted(v6=False):
    b = b'\x10' + sa4(CIP, 50001) + struct.pack('>H', 0)
    for i in range(10):
        b += sa6() if (v6 and i % 3 == 0) else sa4('127.0.0.1', 19132)
    return b + ts() + ts()
def new_incoming(v6=False):
    b = b'\x13' + (sa6() if v6 else sa4(SIP, 30001))
    for i in range(10):
        b += sa6() if (v6 and i % 3 == 0) else sa4('127.0.0.1', 19132)
    return b + ts() + ts()

def rk_msg(payload, rel=0, msgno=0, ordidx=0, channel=0, split=None, seqidx=0, bits=None):
    flags = (rel << 5) | (0x10 if split else 0)
    nbits = len(payload) * 8 if bits is None else bits
    b = bytes([flags]) + struct.pack('>H', nbits)
    if rel in (2, 3, 4):
        b += msgno.to_bytes(3, 'little')
    if rel in (1, 4):
        b += seqidx.to_bytes(3, 'little')
    if rel in (1, 3, 4):
        b += ordidx.to_bytes(3, 'little') + bytes([channel])
    if split:
        b += struct.pack('>IHI', *split)
    return b + payload

def frameset(pktno, *msgs, flags=0x84):
    return bytes([flags]) + pktno.to_bytes(3, 'little') + b''.join(msgs)

def ack(ranges, flags=0xc0, bas=None):
    b = bytes([flags])
    if flags & 0x20 and flags & 0x40 and bas is not None:
        b += struct.pack('>I', bas)
    b += struct.pack('>H', len(ranges))
    for r in ranges:
        if r[0] == r[1]:
            b += b'\x01' + r[0].to_bytes(3, 'little')
        else:
            b += b'\x00' + r[0].to_bytes(3, 'little') + r[1].to_bytes(3, 'little')
    return b

def nak(ranges): return ack(ranges, flags=0xa0)

def s16(b): return struct.pack('>H', len(b)) + b
def s32le(b): return struct.pack('<I', len(b)) + b
def mcpe_login():
    data = s32le(b'{"chain":["header.payload.sig"]}') + s32le(b'client.data.jwt')
    z = zlib.compress(data)
    return b'\xfe\x01' + struct.pack('>II', 100, len(z)) + z
def mcpe_handshake(): return b'\xfe\x03' + s16(b'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE') + s16(b'tokentokentoken')

class Sess:
    def __init__(self, cap, cport, sport):
        self.cap, self.cport, self.sport = cap, cport, sport
    def c(self, payload, note=''):
        self.cap.add(udp_frame(CIP, SIP, self.cport, self.sport, payload), note)
    def s(self, payload, note=''):
        self.cap.add(udp_frame(SIP, CIP, self.sport, self.cport, payload, 2, 1), note)

def build_main():
    cap = Cap()
    # ---- Session A: heuristic via Unconnected Ping, no encryption, all offline messages
    A = Sess(cap, 50001, 30001)
    A.c(unconnected_ping(1), 'A: Unconnected Ping (heuristic match)')
    A.s(unconnected_pong(), 'A: Unconnected Pong')
    A.c(unconnected_ping(2), 'A: Unconnected Ping Open Connections')
    A.c(ocr1(), 'A: Open Connection Request 1')
    A.s(ocrep1(False), 'A: Open Connection Reply 1, no encryption')
    A.c(ocr2(), 'A: Open Connection Request 2, IPv4 server address')
    A.s(ocrep2(False), 'A: Open Connection Reply 2, no encryption')
    pn = 0
    def fs(*m, **kw):
        nonlocal pn
        pn += 1
        return frameset(pn - 1, *m, **kw)
    A.c(fs(rk_msg(conn_req(0), rel=2, msgno=0)), 'A: Connection Request, no encryption, password')
    A.c(fs(rk_msg(conn_req(1, 1), rel=2, msgno=1)), 'A: Connection Request with proof and client key')
    A.c(fs(rk_msg(conn_req(1, 0, b'x'), rel=2, msgno=2)), 'A: Connection Request with proof, no client key')
    A.s(fs(rk_msg(conn_accepted(False), rel=3, msgno=0, ordidx=0)), 'A: Connection Request Accepted (IPv4 addresses)')
    A.s(fs(rk_msg(conn_accepted(True), rel=3, msgno=1, ordidx=1)), 'A: Connection Request Accepted (IPv4/IPv6 addresses)')
    A.c(fs(rk_msg(new_incoming(False), rel=3, msgno=3, ordidx=0)), 'A: New Incoming Connection')
    A.c(fs(rk_msg(new_incoming(True), rel=3, msgno=4, ordidx=1)), 'A: New Incoming Connection (IPv6)')
    A.c(fs(rk_msg(ping(), rel=0), flags=0x80), 'A: Connected Ping, unreliable, packet flags 0x80')
    A.s(fs(rk_msg(pong(), rel=1, seqidx=1, ordidx=2), flags=0x8c), 'A: Connected Pong, unreliable sequenced, flags 0x8c')
    A.c(fs(rk_msg(ping(), rel=4, msgno=5, seqidx=2, ordidx=3, channel=2), flags=0x88), 'A: Connected Ping, reliable sequenced')
    A.c(fs(rk_msg(ping(), rel=2, msgno=6), rk_msg(pong(), rel=0), rk_msg(ping(), rel=3, msgno=7, ordidx=4)),
        'A: three messages in one datagram')
    # fragmented unknown message, reassembled
    big = b'\x86' + bytes(range(256)) * 2
    parts = [big[:200], big[200:400], big[400:]]
    for i, p in enumerate(parts):
        A.c(fs(rk_msg(p, rel=3, msgno=8 + i, ordidx=5, split=(3, 7, i))),
            'A: split message fragment %d/3 (unknown message id 0x86)' % (i + 1))
    # split message in two datagrams out of order and a split ping
    sp = ping()
    A.c(fs(rk_msg(sp[5:], rel=2, msgno=12, split=(2, 8, 1))), 'A: fragment 2/2 first (out of order)')
    A.c(fs(rk_msg(sp[:5], rel=2, msgno=13, split=(2, 8, 0))), 'A: fragment 1/2 completes a Connected Ping')
    # payload length in bits not a multiple of eight, unknown id, a single message
    A.c(fs(rk_msg(b'\x87\x01\x02', rel=0, bits=20)), 'A: unknown message id 0x87, 20 bits')
    # ACK / NAK
    A.s(ack([(0, 3), (5, 5), (7, 9)]), 'A: ACK with ranges and singles')
    A.s(ack([(1, 1)], flags=0xe0, bas=0x01020304), 'A: ACK with B and AS')
    A.s(nak([(4, 4), (10, 12)]), 'A: NAK')
    A.s(ack([]), 'A: ACK without records')
    A.c(b'\x40\x01\x02', 'A: invalid datagram (valid bit clear)')
    # ---- Session B: heuristic via OCR1; only the second reply turns encryption on
    B = Sess(cap, 50002, 30002)
    B.c(ocr1(60), 'B: Open Connection Request 1 (heuristic match)')
    B.s(ocrep1(False), 'B: Open Connection Reply 1 without encryption')
    B.c(ocr2(sa4(SIP, 30002), False), 'B: Open Connection Request 2')
    B.s(ocrep2(True, sa6()), 'B: Open Connection Reply 2 with encryption, IPv6 client address')
    B.c(frameset(0, rk_msg(ping(), rel=0)), 'B: connected datagram after encryption was agreed')
    B.s(ack([(0, 0)]), 'B: ACK after encryption was agreed')
    B.c(frameset(1, rk_msg(b'\x01\x02\x03\x04\x05', rel=3, msgno=0, ordidx=0)), 'B: encrypted datagram')
    # ---- Session C: reproducer of the state bug (connected datagram before the reply with encryption)
    C = Sess(cap, 50003, 30003)
    C.c(b'\x05' + MAGIC + b'\x0a' + b'\x00' * 20, 'C: [fix] Open Connection Request 1')
    C.c(b'\x84\x01\x00\x00' + b'\x00' + struct.pack('>H', 72) + b'\x00' + struct.pack('>Q', 1234),
        'C: [fix] connected datagram (Connected Ping) before the reply that turns encryption on')
    C.s(b'\x08' + MAGIC + b'\x00' * 8 + sa4(CIP, 50003) + struct.pack('>H', 1400) + b'\x01' + b'\x00' * 128,
        'C: [fix] Open Connection Reply 2 with encryption')
    C.c(b'\x84\x02\x00\x00' + b'\x00' + struct.pack('>H', 72) + b'\x00' + struct.pack('>Q', 1234),
        'C: [fix] connected datagram after the reply (encrypted)')
    # ---- Session D: heuristic via Unconnected Pong, failures
    D = Sess(cap, 50004, 30004)
    D.s(unconnected_pong(b''), 'D: Unconnected Pong with empty string (heuristic match)')
    for op, n in ((0x0d, 'Out Of Band Internal'), (0x11, 'Connection Attempt Failed'), (0x12, 'Already Connected'),
                  (0x14, 'No Free Incoming Connections'), (0x17, 'Connection Banned'), (0x1a, 'IP Recently Connected')):
        D.s(conn_failed(op), 'D: %s' % n)
    D.s(incompat(), 'D: Incompatible Protocol Version')
    D.c(ocr2(SABAD), 'D: Open Connection Request 2 with an invalid IP version')
    D.s(ocrep2(False, SABAD), 'D: Open Connection Reply 2 with an invalid IP version')
    D.s(frameset(0, rk_msg(b'\x10' + SABAD + b'\x00\x00' + SABAD * 10 + ts() + ts(), rel=0)), 'D: Connection Request Accepted with invalid address versions')
    D.c(unconnected_ping(1)[:1] + ts() + MAGIC + CG, 'D: Unconnected Ping')
    D.c(bytes([0x7f]) + b'\x00' * 8, 'D: unknown offline id without the valid bit')
    # ---- Session E: UDP port 19132 (MCPE registers it), sub-dissector paths
    E = Sess(cap, 50005, 19132)
    E.c(unconnected_ping(1), 'E: Unconnected Ping on port 19132')
    E.s(unconnected_pong(), 'E: Unconnected Pong')
    E.c(ocr1(), 'E: Open Connection Request 1')
    E.s(ocrep1(False), 'E: Open Connection Reply 1')
    E.c(ocr2(sa4(SIP, 19132)), 'E: Open Connection Request 2')
    E.s(ocrep2(False, sa4(CIP, 50005)), 'E: Open Connection Reply 2')
    E.c(frameset(0, rk_msg(mcpe_login(), rel=3, msgno=0, ordidx=0)), 'E: one game message (sub-protocol gets its own layer)')
    E.s(frameset(0, rk_msg(mcpe_handshake(), rel=3, msgno=0, ordidx=0), rk_msg(ping(), rel=0)),
        'E: game message and ping in one datagram')
    E.c(frameset(1, rk_msg(b'\x99\x01\x02', rel=2, msgno=1)), 'E: unknown message the sub-dissector rejects')
    E.c(frameset(2, rk_msg(mcpe_login(), rel=3, msgno=2, ordidx=1, split=(2, 3, 0), bits=8 * 20)[:0] + rk_msg(mcpe_login()[:20], rel=3, msgno=2, ordidx=1, split=(2, 3, 0)),
                  ), 'E: first fragment of a game message')
    E.c(frameset(3, rk_msg(mcpe_login()[20:], rel=3, msgno=3, ordidx=1, split=(2, 3, 1))), 'E: last fragment, reassembled game message')
    # ---- Not RakNet: UDP datagrams the heuristic rejects
    cap.add(udp_frame(CIP, SIP, 50030, 30030, bytes(range(60))), 'F: UDP datagram that is not RakNet')
    cap.add(udp_frame(CIP, SIP, 50031, 30031, b'\x84\x00\x00\x00' + b'\x00' * 4), 'F: datagram that looks like a connected message but starts no session')
    return cap

def build_malformed():
    cap = Cap()
    port = [50100]
    def one(payload, note, to_server=True, sport=19132):
        """Every case is a session of its own on port 19132 (no heuristic, no state)."""
        port[0] += 1
        S_ = Sess(cap, port[0], sport)
        (S_.c if to_server else S_.s)(payload, note)
    one(unconnected_ping(1)[:20], 'M: truncated Unconnected Ping')
    one(ocr1()[:10], 'M: truncated Open Connection Request 1')
    one(ocrep1(True)[:30], 'M: truncated Open Connection Reply 1', False)
    one(ocrep2(True)[:40], 'M: truncated Open Connection Reply 2', False)
    one(unconnected_pong(b'abc')[:-2], 'M: Unconnected Pong string longer than the packet', False)
    one(unconnected_pong(b'abc')[:33], 'M: Unconnected Pong cut before the string length', False)
    one(b'\x84\x00', 'M: connected datagram too short')
    one(b'\x84\x00\x00\x00', 'M: connected datagram without a message')
    one(b'\x84\x00\x00\x00\x60\x00', 'M: message header cut')
    one(frameset(1, rk_msg(ping(), rel=0)[:8]), 'M: message payload shorter than its length')
    one(frameset(2, rk_msg(b'\x00' * 3, rel=0, bits=800)), 'M: message length beyond the datagram')
    one(frameset(3, rk_msg(b'\x09' + CG, rel=0)), 'M: Connection Request cut')
    one(frameset(3, rk_msg(conn_req(1, 0, b''), rel=2)), 'M: Connection Request without a password')
    one(frameset(4, rk_msg(b'\x10' + sa4(CIP, 1), rel=0)), 'M: Connection Request Accepted cut')
    one(frameset(5, rk_msg(b'\x13' + sa4(CIP, 1) + b'\x04\x01', rel=0)), 'M: New Incoming Connection cut')
    one(frameset(6, rk_msg(b'\x00' + ts(), rel=0, split=(0, 9, 0))), 'M: split count zero')
    one(frameset(7, rk_msg(b'\x0a' * 4, rel=0, split=(2, 10, 5))), 'M: split index beyond the count')
    one(b'\xc0\x00\x05\x01\x01', 'M: ACK with more records than data')
    one(b'\xa0', 'M: NAK without a record count')
    one(ack([(1, 2)], flags=0xe0)[:3], 'M: ACK cut inside B and AS')
    one(b'\xc0', 'M: ACK without a record count')
    cap.add(udp_frame(CIP, SIP, 50300, 30300, b'\x01\x02\x03'), 'M: short UDP datagram tested by the heuristic')
    # Encryption negotiated the normal way (Reply 1 with encryption, Request 2, Reply 2 with
    # encryption): Request 2 and the frames after it decode differently with -2 (bug, see README)
    B = Sess(cap, 50201, 19132)
    B.c(ocr1(60), 'B: Open Connection Request 1')
    B.s(ocrep1(True), 'B: Open Connection Reply 1 with encryption (cookie, public key)')
    B.c(ocr2(sa4(SIP, 19132), True, True), 'B: Open Connection Request 2 with cookie and challenge')
    B.s(ocrep2(True, sa6()), 'B: Open Connection Reply 2 with encryption')
    B.c(frameset(0, rk_msg(ping(), rel=0)), 'B: encrypted datagram')
    B.s(ack([(0, 0)]), 'B: encrypted ACK')
    B2 = Sess(cap, 50202, 19132)
    B2.c(ocr1(), 'B2: Open Connection Request 1')
    B2.s(ocrep1(True), 'B2: Open Connection Reply 1 with encryption')
    B2.c(ocr2(sa4(SIP, 19132), True, False), 'B2: Open Connection Request 2 with cookie, no challenge')
    B2.s(ocrep2(True, sa4(CIP, 50202)), 'B2: Open Connection Reply 2 with encryption')
    # Open Connection Replies seen more than once in a session: the state keeps only the last
    # one, so the frames in between decode differently with -2 (bug, see README)
    R = Sess(cap, 50200, 19132)
    R.c(ocr1(), 'R: Open Connection Request 1')
    R.s(ocrep1(True), 'R: Open Connection Reply 1 with encryption')
    R.c(ocr2(sa4(SIP, 19132), True, True), 'R: Open Connection Request 2 with cookie and challenge')
    R.s(ocrep2(False, sa4(CIP, 50200)), 'R: Open Connection Reply 2 without encryption')
    R.c(frameset(0, rk_msg(ping(), rel=0)), 'R: Connected Ping')
    R.c(ocr1(), 'R: reconnect, Open Connection Request 1')
    R.s(ocrep1(False), 'R: Open Connection Reply 1 without encryption')
    R.c(ocr2(sa4(SIP, 19132), False), 'R: Open Connection Request 2 without encryption')
    R.s(ocrep2(True, sa4(CIP, 50200)), 'R: Open Connection Reply 2 with encryption')
    R.c(frameset(1, rk_msg(ping(), rel=0)), 'R: encrypted datagram')
    return cap

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main(); m.write(os.path.join(out, 'raknet-coverage.pcap'))
    x = build_malformed(); x.write(os.path.join(out, 'raknet-coverage-malformed.pcap'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for name, c in (('main', m), ('malformed', x)):
            f.write('# %s: %d frames\n' % (name, len(c.frames)))
            for i, n in enumerate(c.notes, 1):
                f.write('%d\t%s\n' % (i, n))
