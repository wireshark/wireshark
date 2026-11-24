#!/usr/bin/env python3
# Generates test/captures/mcpe_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the MCPE dissector
(packet-mcpe.c, Minecraft Pocket Edition over RakNet). MCPE is reached by
default over RakNet on UDP port 19132: RakNet frame set datagrams carrying
0xFE "Wrapper" messages: Login, Server to Client Handshake and Batch (zlib
compressed record lists). No keys: the "encrypted" traffic after the
handshake is not produced (a Batch is shown as encrypted only by the state;
the malformed capture has frames after the handshake).

Usage: mkmcpe.py <output directory> [-v]
Writes mcpe-coverage.pcapng (main) and mcpe-coverage-malformed.pcapng.
"""
import zlib
import struct
import sys

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames, extra_lt=()):
    """frames: list of (interface, bytes). Interface 0 is Ethernet, 1 is
    Exported PDU, 2.. the link types in extra_lt. 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (LT_ETH, LT_EXPPDU) + tuple(extra_lt):
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    return bytes([2, 0]) + ip4(addr)


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)
def u64(v): return struct.pack('<Q', v)
def b16(v): return struct.pack('>H', v)
def b32(v): return struct.pack('>I', v)
# ---- end of prelude ----

# ------------------------------------------------------------ MCPE over RakNet

CLI, SRV = '192.0.2.41', '192.0.2.42'


def rk_msg(payload, rel=3, msgno=0, ordidx=0, channel=0, split=None, seqidx=0, bits=None):
    """RakNet encapsulated message. rel: 0 unreliable, 1 unreliable sequenced,
    2 reliable, 3 reliable ordered, 4 reliable sequenced. split =
    (count, id, index)."""
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


def s16(b): return struct.pack('>H', len(b)) + b
def s32le(b): return struct.pack('<I', len(b)) + b


def login(protocol=100, chain=b'{"chain":["header.payload.sig"]}', jwt=b'client.data.jwt', comp=None):
    data = s32le(chain) + s32le(jwt)
    z = zlib.compress(data) if comp is None else comp
    return b'\x01' + struct.pack('>II', protocol, len(z)) + z


def handshake(key=b'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE', tok=b'tokentokentoken'):
    return b'\x03' + s16(key) + s16(tok)


def batch(records, comp=None):
    body = b''.join(struct.pack('>I', len(r)) + r for r in records)
    z = zlib.compress(body) if comp is None else comp
    return b'\x06' + struct.pack('>I', len(z)) + z


def nested(depth, leaf=None):
    if leaf is None:
        leaf = login()
    rec = leaf
    for _ in range(depth):
        rec = batch([rec])
    return rec


def wrap(pkt): return b'\xfe' + pkt


def main_frames():
    f = []
    pn = [0]

    def send(cport, msgs, src=CLI, sport=None, dport=19132, dst=SRV, upload=True):
        pn[0] += 1
        fs = frameset(pn[0], *msgs)
        if upload:
            f.append(udp(fs, src, cport, dst, 19132))
        else:
            f.append(udp(fs, dst, 19132, src, cport))

    mno = [0]

    def m(payload, **kw):
        mno[0] += 1
        return rk_msg(wrap(payload), msgno=mno[0], ordidx=mno[0], **kw)

    # Login: protocol version and the chain/client data strings
    send(40500, [m(login())])
    send(40500, [m(login(protocol=0xffffffff, chain=b'', jwt=b''))])
    # Batches: single and several records (unknown packet IDs, a login), nested batches
    send(40500, [m(batch([login()]))])
    send(40500, [m(batch([login(), login(protocol=7), login(chain=b'', jwt=b'x')]))])
    send(40500, [m(batch([nested(1)]))])
    send(40500, [m(nested(3))])
    send(40500, [m(nested(15))])
    send(40500, [m(batch([nested(2), login(), nested(1)]))])
    # server -> client batches
    send(40500, [m(batch([login(), login()]))], upload=False)
    # several messages in one frame set, other reliabilities
    send(40500, [rk_msg(wrap(batch([login()])), rel=0), rk_msg(wrap(login()), rel=1, ordidx=1, seqidx=1),
                 rk_msg(wrap(batch([login()])), rel=2, msgno=77), rk_msg(wrap(login()), rel=4, msgno=78, ordidx=2, seqidx=2)])
    # a large Login split over three RakNet fragments, reassembled
    big = wrap(login(chain=b'{"chain":["' + b'A' * 700 + b'"]}', jwt=b'B' * 500))
    # compress with a random-ish payload so that the zlib stream is large
    parts = [big[:400], big[400:800], big[800:]]
    for i, p in enumerate(parts):
        send(40500, [rk_msg(p, rel=3, msgno=200 + i, ordidx=50, split=(3, 9, i))])
    # Server to Client Handshake: public key and token (the last message of this
    # conversation: the dissector treats everything after it as encrypted)
    send(40501, [m(handshake())], upload=False)
    return f


def malformed_frames():
    f = []
    pn = [100]
    mno = [100]

    def send(cport, payload_msgs, upload=True):
        pn[0] += 1
        fs = frameset(pn[0], *payload_msgs)
        if upload:
            f.append(udp(fs, CLI, cport, SRV, 19132))
        else:
            f.append(udp(fs, SRV, 19132, CLI, cport))

    def m(payload, **kw):
        mno[0] += 1
        return rk_msg(wrap(payload), msgno=mno[0], ordidx=mno[0], **kw)

    # failed decompression (login and batch), nesting deeper than 16, unknown
    # packet ID inside a batch with trailing bytes, an empty batch, a record
    # longer than the batch
    send(40600, [m(login(comp=b'not zlib data'))])
    send(40600, [m(batch([b'\x7f'], comp=b'not zlib either'))])
    send(40600, [m(nested(16))])
    send(40600, [m(nested(40))])
    send(40600, [m(batch([]))])
    send(40600, [m(b'\x06' + struct.pack('>I', 0))])
    send(40600, [m(b'\x06' + struct.pack('>I', 500) + b'xyz')])
    z = zlib.compress(struct.pack('>I', 1000) + b'\x7f')
    send(40600, [m(b'\x06' + struct.pack('>I', len(z)) + z)])
    z = zlib.compress(struct.pack('>I', 0))
    send(40600, [m(b'\x06' + struct.pack('>I', len(z)) + z)])
    z = zlib.compress(b'\x00\x00')
    send(40600, [m(b'\x06' + struct.pack('>I', len(z)) + z)])
    # login with data strings longer than the data
    z = zlib.compress(struct.pack('<I', 5000) + b'abc')
    send(40600, [m(b'\x01' + struct.pack('>II', 1, len(z)) + z)])
    z = zlib.compress(s32le(b'chain') + struct.pack('<I', 9000))
    send(40600, [m(b'\x01' + struct.pack('>II', 1, len(z)) + z)])
    send(40600, [m(b'\x01\x00\x00')])
    send(40600, [m(b'\x01' + struct.pack('>II', 1, 9999))])
    # handshake with strings longer than the message, a message after the
    # handshake in the same conversation (encrypted), an unknown packet id
    send(40601, [m(b'\x03' + struct.pack('>H', 900) + b'key')], upload=False)
    send(40602, [m(handshake())], upload=False)
    send(40602, [m(batch([b'\x7f']))], upload=False)
    send(40602, [m(login())])
    send(40602, [m(b'\x20abc')])
    # unknown packet IDs (not claimed by the heuristic), a one-octet message
    send(40603, [m(b'\x7fabc')])
    send(40603, [rk_msg(b'\xfe', rel=3, msgno=999, ordidx=999)])
    send(40603, [rk_msg(b'\xfe\x7f\x00', rel=3, msgno=998, ordidx=998)])
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    pcapng(out + '/mcpe-coverage.pcapng', mf)
    xf = malformed_frames()
    pcapng(out + '/mcpe-coverage-malformed.pcapng', xf)
    if '-v' in sys.argv:
        print('main', len(mf), 'malformed', len(xf))


main()
