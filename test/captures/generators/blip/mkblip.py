#!/usr/bin/env python3
# Generates test/captures/blip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BLIP dissector (packet-blip.c).

BLIP (Couchbase Lite <-> Sync Gateway replication) runs over WebSocket
with the subprotocol "BLIP_3+CBMobile_2", "_3" or "_4", negotiated by an
HTTP/1.1 Upgrade on TCP. Every packet is built from scratch with struct
and zlib; no captured traffic is used.

Usage: mkblip.py <output directory>

Writes:
  blip-coverage.pcap            three Ethernet/IPv4/TCP connections, each an
                                HTTP Upgrade followed by WebSocket frames
                                carrying BLIP: MSG/RPY/ERR/ACKMSG/ACKRPY,
                                every flag, properties, multi-frame messages,
                                compressed frames on the per-direction
                                deflate streams, and the clean frames of the
                                blip_mix.py reproducer
  blip-coverage-malformed.pcap  Exported PDU frames straight to "blip": the
                                whole blip_mix.py reproducer, decompression
                                errors, the buffer overflow and truncated
                                frames
"""

import os
import struct
import sys
import zlib

# --------------------------------------------------------------------------
# Link, IPv4 and TCP


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident,
                      0x4000, 64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, dst, sport, dport, seq, ack, flags, data):
    # SYNs carry an MSS option (a SYN without options is flagged as a scanner)
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack,
                      (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6,
                         len(hdr) + len(data))
    c = csum(pseudo + hdr + data)
    return hdr[:16] + struct.pack('>H', c) + hdr[18:] + data


MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')

FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10


class Conn:
    """One TCP connection; keeps the sequence numbers of both sides."""

    def __init__(self, out, cip, sip, cport, sport):
        self.out = out
        self.cip, self.sip, self.cport, self.sport = cip, sip, cport, sport
        self.cseq, self.sseq = 1000, 50000
        self.ident = 1
        self.seg(True, SYN, b'')
        self.cseq += 1
        self.seg(False, SYN | ACK, b'')
        self.sseq += 1
        self.seg(True, ACK, b'')

    def seg(self, from_client, flags, data):
        if from_client:
            t = tcp(self.cip, self.sip, self.cport, self.sport, self.cseq,
                    self.sseq if flags & ACK else 0, flags, data)
            ip = ipv4(self.cip, self.sip, 6, t, self.ident)
            frame = MAC_S + MAC_C + b'\x08\x00' + ip
        else:
            t = tcp(self.sip, self.cip, self.sport, self.cport, self.sseq,
                    self.cseq, flags, data)
            ip = ipv4(self.sip, self.cip, 6, t, self.ident)
            frame = MAC_C + MAC_S + b'\x08\x00' + ip
        self.ident += 1
        self.out.append(frame)

    def send(self, from_client, data):
        self.seg(from_client, PSH | ACK, data)
        if from_client:
            self.cseq += len(data)
        else:
            self.sseq += len(data)

    def close(self):
        self.seg(True, FIN | ACK, b'')
        self.cseq += 1
        self.seg(False, FIN | ACK, b'')
        self.sseq += 1
        self.seg(True, ACK, b'')

    def upgrade(self, offered, chosen):
        req = ('GET /db/_blipsync HTTP/1.1\r\n'
               'Host: sg.example.com:%d\r\n'
               'Upgrade: websocket\r\n'
               'Connection: Upgrade\r\n'
               'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
               'Sec-WebSocket-Version: 13\r\n'
               'Sec-WebSocket-Protocol: %s\r\n'
               '\r\n' % (self.sport, offered)).encode()
        rsp = ('HTTP/1.1 101 Switching Protocols\r\n'
               'Upgrade: websocket\r\n'
               'Connection: Upgrade\r\n'
               'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n'
               'Sec-WebSocket-Protocol: %s\r\n'
               '\r\n' % chosen).encode()
        self.send(True, req)
        self.send(False, rsp)


# --------------------------------------------------------------------------
# WebSocket

MASK = bytes.fromhex('37fa213d')


def ws(payload, from_client, opcode=0x2, fin=True):
    b0 = (0x80 if fin else 0) | opcode
    n = len(payload)
    m = 0x80 if from_client else 0
    if n < 126:
        hdr = struct.pack('>BB', b0, m | n)
    elif n < 65536:
        hdr = struct.pack('>BBH', b0, m | 126, n)
    else:
        hdr = struct.pack('>BBQ', b0, m | 127, n)
    if from_client:
        payload = bytes(c ^ MASK[i % 4] for i, c in enumerate(payload))
        hdr += MASK
    return hdr + payload


# --------------------------------------------------------------------------
# BLIP

MSG, RPY, ERR, ACKMSG, ACKRPY = 0, 1, 2, 4, 5
COMPRESSED, URGENT, NOREPLY, MORECOMING = 0x08, 0x10, 0x20, 0x40


def varint(v):
    o = b''
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            o += bytes([b | 0x80])
        else:
            return o + bytes([b])


def props(*kv):
    return b''.join(s.encode() + b'\0' for s in kv)


def checksum(data):
    return struct.pack('>I', zlib.crc32(data))


def blip(num, flags, body, prop=None):
    """An uncompressed BLIP frame; prop=None for a continuation frame."""
    data = (varint(len(prop)) + prop if prop is not None else b'') + body
    return varint(num) + varint(flags) + data + checksum(data)


def blip_ack(num, flags, nbytes):
    return varint(num) + varint(flags) + varint(nbytes)


class Deflater:
    """One direction's deflate stream (the BLIP stream keeps its context)."""

    def __init__(self):
        self.co = zlib.compressobj(6, zlib.DEFLATED, -15)

    def blip(self, num, flags, body, prop=None):
        data = (varint(len(prop)) + prop if prop is not None else b'') + body
        c = self.co.compress(data) + self.co.flush(zlib.Z_SYNC_FLUSH)
        assert c.endswith(b'\x00\x00\xff\xff')
        return varint(num) + varint(flags) + c[:-4] + checksum(data)


# The blip_mix.py reproducer from the review, built the same way.
def blip_mix():
    co = zlib.compressobj(9, zlib.DEFLATED, -15)

    def comp(data):
        c = co.compress(data) + co.flush(zlib.Z_SYNC_FLUSH)
        assert c.endswith(b'\x00\x00\xff\xff')
        return c[:-4]
    p = []
    pr = b'Profile\0subChanges\0continuous\0true\0'
    p.append(varint(1) + varint(0x08) + comp(varint(len(pr)) + pr + b'{"a":1}') + b'\0\0\0\0')
    p.append(varint(2) + varint(0x08) + b'\0\0\0\0')
    p.append(varint(3) + varint(0x08) + b'\x01')
    p.append(varint(4) + varint(0x08))
    p.append(varint(5) + varint(0x08) + b'\xff\xff\xff\xff\xff\xff')
    p.append(varint(6) + varint(0x00) + varint(0xffffffff) + b'abcd1234')
    p.append(varint(7) + varint(0x00) + varint(0x100000005) + b'ab\0cd1234')
    p.append(varint(8) + varint(0x00) + varint(0x7fffffff) + b'ab')
    p.append(varint(9) + varint(0x04) + varint(1000))
    p.append(varint(10) + varint(0x00) + b'\xff' * 12)
    p.append(varint(11) + varint(0x08) + comp(varint(3) + b'a\0b' + b'body') + b'\0\0\0\0')
    p.append(b'\x80')
    return p


# --------------------------------------------------------------------------
# pcap


def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                data, wire = fr
            else:
                data, wire = fr, len(fr)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), wire) + data)


def main_capture():
    out = []
    CIP, SIP = (192, 0, 2, 10), (198, 51, 100, 20)

    # Connection 1: BLIP_3+CBMobile_2, uncompressed -------------------------
    c = Conn(out, CIP, SIP, 50001, 4984)
    c.upgrade('BLIP_3+CBMobile_3, BLIP_3+CBMobile_2', 'BLIP_3+CBMobile_2')
    # MSG #1 with properties and no body
    c.send(True, ws(blip(1, MSG, b'', props('Profile', 'getCheckpoint', 'client', 'cp-1')), True))
    # RPY #1 with properties and a JSON body
    c.send(False, ws(blip(1, RPY, b'{"time":"2026-01-01","seq":42}', props('rev', '0-1')), False))
    # MSG #2 urgent
    c.send(True, ws(blip(2, MSG | URGENT, b'{"since":0}', props('Profile', 'subChanges', 'continuous', 'true')), True))
    # MSG #3 noreply
    c.send(True, ws(blip(3, MSG | NOREPLY, b'[[1,"doc1","1-a"]]', props('Profile', 'changes')), True))
    # ERR #2
    c.send(False, ws(blip(2, ERR, b'missing', props('Error-Domain', 'HTTP', 'Error-Code', '404')), False))
    # MSG #4 urgent|noreply, properties with an embedded empty value
    c.send(True, ws(blip(4, MSG | URGENT | NOREPLY, b'{}', props('Profile', 'norev', 'error', '')), True))
    # MSG #5 in two frames: MoreComing, then the continuation (no properties)
    c.send(True, ws(blip(5, MSG | MORECOMING, b'{"docs":[1,2,', props('Profile', 'proposeChanges')), True))
    c.send(True, ws(blip(5, MSG, b'3,4]}'), True))
    # ACKMSG #5 from the server, RPY #5 in two frames, ACKRPY #5 from the client
    c.send(False, ws(blip_ack(5, ACKMSG, 500), False))
    c.send(False, ws(blip(5, RPY | URGENT | MORECOMING, b'[0,0,', props('maxHistory', '20')), False))
    c.send(False, ws(blip(5, RPY | URGENT, b'0,0]'), False))
    c.send(True, ws(blip_ack(5, ACKRPY, 70000), True))
    # MSG #300 (two-octet message number), empty properties
    c.send(True, ws(blip(300, MSG, b'plain body', b''), True))
    # MSG #6: empty properties and only two octets left (less than a checksum)
    c.send(True, ws(varint(6) + varint(MSG) + varint(0) + b'ok', True))
    # Unknown message types 3, 6 and 7 ("???")
    c.send(True, ws(blip(7, 3, b'x', props('a', 'b')), True))
    c.send(True, ws(blip(8, 6 | NOREPLY | MORECOMING, b'y', props('c', 'd')), True))
    c.send(True, ws(blip(9, 7 | URGENT | NOREPLY | MORECOMING, b'z', props('e', 'f')), True))
    # Two BLIP frames in one TCP segment
    c.send(True, ws(blip(10, MSG, b'first', props('Profile', 'getAttachment')), True) +
           ws(blip(11, MSG | NOREPLY, b'second', props('Profile', 'setCheckpoint')), True))
    # A large RPY spread over three TCP segments (TCP reassembly)
    big = ws(blip(10, RPY, b'{"data":"' + b'A' * 3000 + b'"}', props('Content-Type', 'application/json')), False)
    c.send(False, big[:1000])
    c.send(False, big[1000:2000])
    c.send(False, big[2000:])
    # A BLIP frame in a fragmented WebSocket message (WebSocket reassembly)
    frag = blip(12, MSG, b'fragmented websocket message', props('Profile', 'rev'))
    c.send(True, ws(frag[:10], True, opcode=0x2, fin=False))
    c.send(True, ws(frag[10:], True, opcode=0x0, fin=True))
    # One-octet properties without a terminating NUL
    c.send(True, ws(blip(13, MSG, b'body', b'p'), True))
    c.close()

    # Connection 2: BLIP_3+CBMobile_3, compressed ---------------------------
    c = Conn(out, CIP, SIP, 50002, 4984)
    c.upgrade('BLIP_3+CBMobile_3', 'BLIP_3+CBMobile_3')
    cd, sd = Deflater(), Deflater()
    c.send(True, ws(cd.blip(1, MSG | COMPRESSED, b'{"client":"cbl-1","since":"0"}',
                            props('Profile', 'getCheckpoint', 'client', 'cbl-1')), True))
    c.send(False, ws(sd.blip(1, RPY | COMPRESSED, b'{"client":"cbl-1","since":"42"}',
                             props('rev', '0-2')), False))
    # Same stream again: the second message refers back into the first
    c.send(True, ws(cd.blip(2, MSG | COMPRESSED | URGENT, b'{"client":"cbl-1","since":"42"}',
                            props('Profile', 'setCheckpoint', 'client', 'cbl-1', 'rev', '0-2')), True))
    c.send(False, ws(blip(2, RPY, b'', props('rev', '0-3')), False))
    # Compressed message in two frames
    c.send(True, ws(cd.blip(3, MSG | COMPRESSED | MORECOMING, b'[["doc1","1-a"],',
                            props('Profile', 'changes')), True))
    c.send(True, ws(cd.blip(3, MSG | COMPRESSED, b'["doc2","1-b"]]'), True))
    c.send(False, ws(blip_ack(3, ACKMSG, 64), False))
    # Compressed, empty properties and empty body
    c.send(True, ws(cd.blip(4, MSG | COMPRESSED | NOREPLY, b'', b''), True))
    # Compressed with every flag; a body larger than 1 Kb once decompressed
    c.send(False, ws(sd.blip(3, RPY | COMPRESSED | URGENT | NOREPLY | MORECOMING,
                             b'{"rows":[' + b'{"id":"doc","rev":"1-a"},' * 120 + b'{}]}',
                             props('Content-Type', 'application/json')), False))
    c.send(False, ws(sd.blip(3, RPY | COMPRESSED | URGENT, b' '), False))
    c.send(True, ws(blip_ack(3, ACKRPY, 3200), True))
    c.close()

    # Connection 3: BLIP_3+CBMobile_4, the clean frames of blip_mix ---------
    c = Conn(out, CIP, SIP, 50003, 4984)
    c.upgrade('BLIP_3+CBMobile_4', 'BLIP_3+CBMobile_4')
    mix = blip_mix()
    for i in (0, 8, 10):
        c.send(True, ws(mix[i], True))
    c.close()

    # Connection 4: two compressed BLIP frames in one TCP segment; each
    # keeps its own inflated data on the second pass ------------------------
    c = Conn(out, CIP, SIP, 50004, 4984)
    c.upgrade('BLIP_3+CBMobile_3', 'BLIP_3+CBMobile_3')
    d = Deflater()
    c.send(True, ws(d.blip(1, MSG | COMPRESSED, b'first body', props('Profile', 'a')), True) +
           ws(d.blip(2, MSG | COMPRESSED, b'second body', props('Profile', 'b')), True))
    c.close()
    return out


EXP_IP = [(192, 0, 2, 30), (198, 51, 100, 40)]


def exp_pdu(payload, sport=0, dport=0):
    n = b'blip'
    tags = struct.pack('>HH', 12, len(n)) + n
    if sport:
        tags += struct.pack('>HH4s', 20, 4, bytes(EXP_IP[0]))
        tags += struct.pack('>HH4s', 21, 4, bytes(EXP_IP[1]))
        tags += struct.pack('>HHI', 24, 4, 2)
        tags += struct.pack('>HHI', 25, 4, sport)
        tags += struct.pack('>HHI', 26, 4, dport)
    return tags + struct.pack('>HH', 0, 0) + payload


def malformed_capture():
    out = []
    # 1-12: the blip_mix.py reproducer, unchanged (no addresses or ports)
    for p in blip_mix():
        out.append(exp_pdu(p))
    # 13: decompressed body larger than the default 64 Kb buffer
    d = Deflater()
    out.append(exp_pdu(d.blip(1, MSG | COMPRESSED, b'B' * 70000, b''), 40001, 4984))
    # 14: deflate garbage after an overflow (reported as buffer too small)
    out.append(exp_pdu(varint(1) + varint(COMPRESSED) + b'\xfe\xff\xff\xff\xff\xff' + b'\0' * 4, 40002, 4984))
    # 15: compressed frame cut short by the snapshot length
    d = Deflater()
    f = d.blip(1, MSG | COMPRESSED, b'truncated body', props('Profile', 'x'))
    out.append((exp_pdu(f, 40003, 4984)[:-6], len(exp_pdu(f, 40003, 4984))))
    # 16: three octets: no room for the checksum
    out.append(exp_pdu(varint(1) + varint(MSG) + varint(0), 40004, 4984))
    # 17: ACK without its byte count
    out.append(exp_pdu(varint(2) + varint(ACKMSG), 40004, 4984))
    # 18: empty
    out.append(exp_pdu(b'', 40004, 4984))
    # 19: uncompressed frame cut short by the snapshot length inside the properties
    f = blip(3, MSG, b'body', props('Profile', 'truncated'))
    out.append((exp_pdu(f, 40004, 4984)[:-12], len(exp_pdu(f, 40004, 4984))))
    # 20: compressed frame of exactly four octets after the header
    out.append(exp_pdu(varint(4) + varint(COMPRESSED) + b'\0\0\0\0', 40005, 4984))
    # 21: a stored block header whose NLEN comes from the 00 00 ff ff that
    # is appended: the flush fails with Z_DATA_ERROR (-3)
    out.append(exp_pdu(varint(5) + varint(COMPRESSED) + b'\x00\x00\x00' + b'\0' * 4, 40006, 4984))
    # 22: a final deflate block: the first inflate ends the stream (1)
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    out.append(exp_pdu(varint(6) + varint(COMPRESSED) + co.compress(b'\x00end') + co.flush() + b'\0' * 4, 40007, 4984))
    return out


def main():
    od = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(od, 'blip-coverage.pcap'), 1, main_capture())
    write_pcap(os.path.join(od, 'blip-coverage-malformed.pcap'), 252, malformed_capture())


if __name__ == '__main__':
    main()
