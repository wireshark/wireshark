# Generates test/captures/v5ua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import struct
import sys

def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (encap, uton, channel, payload)."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (encap, uton, channel, payload) in enumerate(records):
            hdr = struct.pack('>I', 1000 * i)[1:] + struct.pack('>Q', 1700000000 + i)[3:]
            hdr += bytes([channel, (encap << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


def exppdu(name, payload):
    """Exported PDU frame (linktype 252) naming a dissector."""
    b = name.encode()
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('>HH', 12, len(b)) + b + struct.pack('>HH', 0, 0) + payload


def inet_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ether(payload, etype=0x0800, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('>H', etype) + payload


def ip4(proto, src, dst, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    hdr = hdr[:10] + struct.pack('>H', inet_csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b'', win=8192, opts=b''):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def sctp(sport, dport, vtag, chunks):
    body = b''.join(chunks)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + body)
    return hdr[:8] + struct.pack('<I', c) + body


def sctp_data(tsn, sid, ssn, ppid, data, flags=3):
    ln = 16 + len(data)
    ch = struct.pack('>BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppid) + data
    return ch + b'\0' * ((4 - ln % 4) % 4)


def sctp_init(tag, chunk_type=1):
    return struct.pack('>BBHIIHHI', chunk_type, 0, 20, tag, 65535, 4, 4, 1000)




def pcapng(path, linktypes, frames):
    """frames: (interface id, data). Writes SHB, one IDB per link type, EPBs."""
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifid, data) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
#!/usr/bin/env python3
"""Generate the synthetic captures for the V5UA dissector (packet-v5ua.c).

V5UA (V5.2-User Adaptation Layer) runs over SCTP: port 5675 (RFC) and 10001
(the Nortel draft), or payload protocol identifier 6.  The dissector tells
the RFC format from the draft format by the first parameter: an integer
interface identifier (tag 1) followed by a DLCI (tag 0x81) is the RFC, a
tag 2 or a DLCI without that tag is the draft, whose parameters have no
length and are taken from the common header.  Packets are built from
scratch with struct; addresses are from 192.0.2.0/24.

Usage: mkv5ua.py <output directory>

Writes:
  v5ua-coverage.pcap            RFC messages of every class and type, draft
                                messages on port 10001, V5.2 and Q.931
                                protocol data
  v5ua-coverage-malformed.pcap  parameters cut short, draft lengths wrong
"""

A, B = '192.0.2.40', '192.0.2.41'


def P(tag, value=b''):
    """RFC parameter: tag, length (with header), value, padded to 4."""
    ln = 4 + len(value)
    return struct.pack('>HH', tag, ln) + value + b'\0' * ((4 - ln % 4) % 4)


def msg(cls, typ, body, length=None):
    return struct.pack('>BBBBI', 1, 0, cls, typ, 8 + len(body) if length is None else length) + body


def iid(link=7, chan=3):
    return P(0x01, struct.pack('>I', (link << 5) | chan))


def text_iid(s=b'0'):
    return P(0x03, s)


def dlci(sapi=0, tei=0, efa=8176):
    return P(0x81, bytes([sapi << 2, (tei << 1) | 1]) + struct.pack('>H', efa))


def pdata(b):
    return P(0x0e, b)


def v52msg(n=5):
    # a PSTN Signal for PSTN address 5 with a recognition time IE (8 octets)
    return bytes([0x48, 0x0b, 0x05, 0x02, 0x10, 0x02, 0x84, 0x05])


Q931 = bytes([0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa2])      # SETUP


# draft parameters: no tag/length for anything after the V5UA header
def draft_hdr(link=7, chan=3, sapi=0, tei=0, efa=8176, ids=1):
    # tag 1, length L = 4 + 4 * ids, the identifiers, 4 octets that the dissector
    # skips, then DLCI (sapi, tei) and EFA at offset 4 + L: the header is L + 8 octets
    idb = b''.join(struct.pack('>I', ((link + i) << 5) | chan) for i in range(ids))
    return struct.pack('>HH', 1, 4 + len(idb)) + idb + b'\0' * 4 + bytes([sapi << 2, (tei << 1) | 1]) + struct.pack('>H', efa)


def dmsg(cls, typ, body):
    # the draft common header length does not count the header itself
    return struct.pack('>BBBBI', 1, 0, cls, typ, len(body)) + body


def layer3(m):
    return bytes([0x48, 0x00]) + struct.pack('>H', 4 + len(m)) + m


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = []
    tsn = [1]

    def add(v, port=5675, ppid=6, src=A, dst=B, sp=10000):
        pkt = sctp(sp if src == A else port, port if src == A else sp, 0x22222222,
                   [sctp_data(tsn[0], 0, tsn[0], ppid, v)])
        frames.append(ether(ip4(132, src, dst, pkt, tsn[0])))
        tsn[0] += 1

    # --- reproducer frames of the fix: no DLCI (frame 1), then one with DLCI (frame 2)
    add(msg(14, 1, P(0x11, struct.pack('>I', 0x1234))))
    add(msg(14, 1, iid() + dlci(efa=5)))
    # --- ASP state maintenance (class 3)
    add(msg(3, 1, P(0x11, struct.pack('>I', 77))))                   # ASP up with ASP id
    add(msg(3, 1, P(0x04, b'info string')))                          # ASP up with an info string
    add(msg(3, 1, P(0x04, b'')))                                     # empty info string
    add(msg(3, 2, P(0x0a, struct.pack('>I', 1))))                    # ASP down with a reason
    add(msg(3, 2, P(0x0a, struct.pack('>I', 9))))                    # unknown reason
    add(msg(3, 3, P(0x04, b'beat') + P(0x09, b'\x01\x02\x03\x04\x05')))  # heartbeat + data
    add(msg(3, 4, P(0x04, b'ack')))
    add(msg(3, 5, P(0x04, b'ack')))
    add(msg(3, 6, P(0x04, b'x') + P(0x09, b'xyz')))
    add(msg(3, 0, P(0x04, b'reserved')))
    # --- ASP traffic maintenance (class 4)
    add(msg(4, 1, P(0x0b, struct.pack('>I', 1)) + P(0x08, struct.pack('>II', 1, 100) + struct.pack('>II', 200, 300))))
    add(msg(4, 1, P(0x0b, struct.pack('>I', 2)) + iid()))
    add(msg(4, 2, P(0x0b, struct.pack('>I', 3)) + text_iid(b'if-42')))
    add(msg(4, 3, P(0x0b, struct.pack('>I', 1)) + P(0x08, struct.pack('>II', 5, 5))))
    add(msg(4, 4, P(0x04, b'ia')))
    add(msg(4, 0, P(0x04, b'r')))
    # --- management (class 0): error, notify, TEI status
    for code in range(0, 14):
        add(msg(0, 0, P(0x0c, struct.pack('>I', code)) + P(0x07, b'\x01\x02\x03\x04\x05\x06')))
    add(msg(0, 0, P(0x0c, struct.pack('>I', 7)) + iid() + dlci()))
    add(msg(0, 0, P(0x0c, struct.pack('>I', 8)) + iid() + dlci(efa=100)))        # class 0 with an ISDN EFA
    add(msg(0, 1, P(0x0d, struct.pack('>HH', 1, 1)) + P(0x11, struct.pack('>I', 5))))
    for st, sid in ((1, 2), (1, 3), (1, 4), (2, 1), (2, 2), (3, 9)):
        add(msg(0, 1, P(0x0d, struct.pack('>HH', st, sid))))
    add(msg(0, 2, text_iid(b'tei-1')))
    add(msg(0, 3, text_iid(b'tei-2') + P(0x10, struct.pack('>I', 0))))
    add(msg(0, 4, text_iid(b'tei-3') + P(0x10, struct.pack('>I', 1))))
    add(msg(0, 4, text_iid(b'tei-4') + P(0x10, struct.pack('>I', 5))))
    add(msg(0, 5, text_iid(b'q5')))
    add(msg(0, 8, text_iid(b'q8')))
    # --- V5 boundary primitives (class 14), V5.2 and Q.931 protocol data
    for t in (1, 2, 3, 4):
        add(msg(14, t, iid(t, t) + dlci(0, t, 8176) + pdata(v52msg())))
    add(msg(14, 1, iid() + dlci(0, 1, 8177) + pdata(Q931)))
    add(msg(14, 2, iid() + dlci(1, 2, 8178) + pdata(Q931)))
    add(msg(14, 1, iid() + dlci(0, 0, 100) + pdata(Q931)))              # ISDN EFA
    add(msg(14, 1, iid() + dlci(0, 0, 8179) + pdata(v52msg())))
    add(msg(14, 1, iid() + dlci(0, 0, 8180) + pdata(v52msg())))
    add(msg(14, 1, iid() + dlci(0, 0, 8181) + pdata(v52msg())))         # unknown EFA
    add(msg(14, 2, iid() + dlci(0, 0, 8191) + pdata(v52msg())))         # reserved EFA
    add(msg(14, 1, iid() + dlci(0, 0, 8175) + pdata(v52msg())))
    # several interface identifiers in one parameter
    add(msg(14, 5, P(0x01, struct.pack('>II', (1 << 5) | 1, (2 << 5) | 2)) + dlci(0, 5, 8176)))
    add(msg(14, 5, iid(9, 9) + dlci(0, 5, 8176)))
    add(msg(14, 6, iid() + dlci()))
    add(msg(14, 7, iid() + dlci()))
    for t, reason in ((8, 0), (9, 1), (10, 2), (10, 3), (10, 7)):
        add(msg(14, t, iid() + dlci() + P(0x0f, struct.pack('>I', reason))))
    add(msg(14, 11, text_iid(b'ls')))
    add(msg(14, 12, text_iid(b'ls')))
    for st in (0, 1, 2):
        add(msg(14, 13, text_iid(b'ls') + P(0x82, struct.pack('>I', st))))
    for t, bid, val in ((14, 0, 7), (15, 1, 7), (16, 0, 0), (17, 1, 1), (17, 5, 9)):
        add(msg(14, t, text_iid(b'sa') + P(0x83, struct.pack('>HH', bid, val))))
    add(msg(14, 18, text_iid(b'er') + P(0x84, struct.pack('>I', 1))))
    add(msg(14, 18, text_iid(b'er') + P(0x84, struct.pack('>I', 2))))
    add(msg(14, 0, text_iid(b'rsv')))
    # an unknown parameter and a reserved tag, 3 octet value with padding
    add(msg(14, 1, text_iid(b'u') + P(0x55, b'\x01\x02\x03') + P(0x12, b'\xaa\xbb\xcc\xdd')))
    add(msg(14, 1, text_iid(b'u') + P(0x55, b'')))
    # a message from the other direction, on payload protocol identifier 6 on another port
    add(msg(14, 2, text_iid(b'p') + pdata(v52msg())), port=9999, ppid=6)
    # unknown message class
    add(msg(77, 1, P(0x04, b'unknown class')))
    add(msg(14, 99, P(0x04, b'unknown type')))

    # --- draft messages on port 10001
    D = 10001
    # tag 2: ASP adaptation layer identifier (ASP up/down/active/inactive), SCN protocol id (tag 3 text)
    add(dmsg(3, 1, struct.pack('>HH', 2, 4) + b'V5UA'), port=D)
    add(dmsg(4, 1, struct.pack('>HH', 2, 4) + b'V5UA'), port=D)
    add(dmsg(3, 2, struct.pack('>HH', 2, 8) + b'V5UAV5UA'), port=D)
    # an ASP message with a second parameter: the SCN protocol identifier (draft tag 3)
    add(dmsg(3, 1, struct.pack('>HH', 2, 4) + b'V5UA' + struct.pack('>HH', 3, 4) + b'SCN1'), port=D)
    # class 0 error, class 1 TEI status: V5UA header + error code (+ info string)
    add(dmsg(0, 0, draft_hdr() + struct.pack('>I', 3)), port=D)
    add(dmsg(0, 0, draft_hdr() + struct.pack('>I', 5) + b'text'), port=D)
    add(dmsg(1, 1, draft_hdr()), port=D)
    add(dmsg(1, 2, draft_hdr() + struct.pack('>I', 0)), port=D)
    add(dmsg(1, 3, draft_hdr() + struct.pack('>I', 1)), port=D)
    add(dmsg(1, 5, draft_hdr(efa=8180)), port=D)
    # class 9: data request/indication with layer 3 data
    for t in (1, 2, 3, 4):
        add(dmsg(9, t, draft_hdr(efa=8176 + t % 3) + layer3(v52msg())), port=D)
    add(dmsg(9, 1, draft_hdr(efa=100) + layer3(v52msg())), port=D)
    add(dmsg(9, 1, draft_hdr(efa=8177) + b'\x00\x00\x00\x00'), port=D)        # no 0x48: no layer 3
    add(dmsg(9, 5, draft_hdr(efa=8178)), port=D)
    add(dmsg(9, 8, draft_hdr(efa=8179) + struct.pack('>I', 1)), port=D)
    add(dmsg(9, 10, draft_hdr(efa=8180) + struct.pack('>I', 3)), port=D)
    add(dmsg(9, 6, draft_hdr(efa=8191, ids=2)), port=D)
    # draft classes with tags and no length (types above 10)
    add(dmsg(9, 13, draft_hdr() + P(0x82, struct.pack('>I', 0))), port=D)
    add(dmsg(9, 14, draft_hdr() + P(0x83, struct.pack('>HH', 1, 7))), port=D)
    add(dmsg(9, 18, draft_hdr() + P(0x84, struct.pack('>I', 1))), port=D)
    # draft over SCTP port 5675 with the DLCI one-bit clear (incorrect DLCI): still draft
    bad = struct.pack('>HH', 1, 8) + struct.pack('>I', (7 << 5) | 3) + b'\0' * 4 + bytes([0x00, 0x00]) + struct.pack('>H', 8176)
    add(dmsg(9, 5, bad), port=D)
    # a draft ASP message whose header has the V5UA header form of tag 1 only after a tag 2
    # draft: IID parameter at tag 1 with a different DLCI byte (the draft DLCI detection)
    # the last frame of the capture: the first parameter has a tag that the version detection
    # does not know, so it skips two octets at a time until it meets a known tag (RFC)
    add(msg(14, 1, P(0x55, b'\x00\x00\x00\x00') + text_iid(b'u') + pdata(v52msg())))
    pcap(os.path.join(out, 'v5ua-coverage.pcap'), 1, frames)

    # --- malformed
    frames = []
    tsn[0] = 1
    add(msg(14, 1, text_iid(b'u')[:6]))
    add(msg(14, 1, P(0x01, struct.pack('>I', 1))[:6]))
    add(msg(14, 1, P(0x0e, v52msg())[:6]))
    add(msg(14, 1, P(0x0e, v52msg())[:3]))
    add(msg(14, 1, iid() + dlci()[:6]))
    add(msg(14, 1, iid() + dlci() + P(0x0e, b'\x48\x00\x00')))
    add(msg(14, 1, iid() + dlci() + struct.pack('>HH', 0x0e, 3)))
    add(msg(14, 1, iid() + dlci() + struct.pack('>HH', 0x0e, 0x400) + v52msg()))
    add(msg(14, 1, iid() + dlci() + struct.pack('>HH', 0x0e, 2) + b'\x48\x01\x05\x00'))
    add(msg(14, 13, text_iid(b'l') + struct.pack('>HH', 0x82, 6) + b'\0\0'))
    add(msg(0, 0, struct.pack('>HH', 0x0c, 6) + b'\0\0'))
    add(msg(0, 1, struct.pack('>HH', 0x0d, 6) + b'\0\0'))
    add(msg(3, 3, struct.pack('>HH', 0x09, 2) + b'\0\0'))
    add(msg(4, 1, struct.pack('>HH', 0x08, 12) + b'\0\0\0\0\0\0\0\0'))
    add(msg(0, 0, struct.pack('>HH', 0x07, 3) + b'\0\0\0\0'))
    add(msg(14, 1, struct.pack('>HH', 0x03, 2) + b'\0\0'))
    add(msg(14, 1, struct.pack('>HH', 0x03, 4)))
    add(msg(3, 1, struct.pack('>HH', 0x04, 8) + b'ab'))
    # a message shorter than the common header
    add(b'\x01\x00\x0e\x01\x00\x00\x00\x08'[:6])
    add(b'\x01\x00')
    # draft with wrong lengths: header length for the draft shorter / longer than the data
    for ml in (0, 4, 8, 12, 0x100, 0xfffffff8, 0xffffffff):
        add(struct.pack('>BBBBI', 1, 0, 9, 1, ml) + draft_hdr() + layer3(v52msg()), port=D)
        add(struct.pack('>BBBBI', 1, 0, 0, 0, ml) + draft_hdr() + struct.pack('>I', 3) + b'text', port=D)
        add(struct.pack('>BBBBI', 1, 0, 1, 1, ml) + draft_hdr() + struct.pack('>I', 0), port=D)
        add(struct.pack('>BBBBI', 1, 0, 3, 1, ml) + struct.pack('>HH', 2, 4) + b'V5UA', port=D)
    add(dmsg(9, 1, draft_hdr()[:10]), port=D)
    add(dmsg(9, 8, draft_hdr()), port=D)
    add(dmsg(1, 1, draft_hdr()[:12]), port=D)
    pcap(os.path.join(out, 'v5ua-coverage-malformed.pcap'), 1, frames)


main()
