#!/usr/bin/env python3
# Generates test/captures/websocket_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the WebSocket coverage captures. Usage: mkwebsocket.py <outdir>
Everything is synthetic: TCP/IPv4 sessions between 192.0.2.x addresses."""
import struct
import sys
import os
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


PKTS = []


class Tcp:
    """One TCP connection; all connections share one packet list."""
    n = 0

    def __init__(self, sport=80, cport=None, handshake=True):
        Tcp.n += 1
        self.cport = cport or 40000 + Tcp.n
        self.sport = sport
        self.cip = bytes([192, 0, 2, 1])
        self.sip = bytes([192, 0, 2, 2])
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self._seg(True, b'', 0x02)
            self.cseq += 1
            self._seg(False, b'', 0x12)
            self.sseq += 1
            self._seg(True, b'', 0x10)

    def _seg(self, from_client, payload, flags=0x18):
        if from_client:
            src, dst, sp, dp, seq, ack = self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq
            smac, dmac = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
        else:
            src, dst, sp, dp, seq, ack = self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq
            smac, dmac = b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01'
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags != 0x02 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        PKTS.append(dmac + smac + b'\x08\x00' + ip + tcp)

    def send(self, from_client, payload, maxseg=1400):
        for i in range(0, max(len(payload), 1), maxseg):
            chunk = payload[i:i + maxseg]
            self._seg(from_client, chunk)
            if from_client:
                self.cseq += len(chunk)
            else:
                self.sseq += len(chunk)

    def c(self, payload, **kw):
        self.send(True, payload, **kw)

    def s(self, payload, **kw):
        self.send(False, payload, **kw)


MASK = b'\x37\xfa\x21\x3d'


def frame(op, payload=b'', fin=True, mask=False, rsv=0, force_len=None):
    """WebSocket frame. force_len: 16 or 64 forces the extended length form."""
    b0 = (0x80 if fin else 0) | (rsv << 4) | op
    n = len(payload)
    m = 0x80 if mask else 0
    if force_len == 64 or n > 65535:
        hdr = struct.pack('!BBQ', b0, m | 127, n)
    elif force_len == 16 or n > 125:
        hdr = struct.pack('!BBH', b0, m | 126, n)
    else:
        hdr = struct.pack('!BB', b0, m | n)
    if mask:
        hdr += MASK
        payload = bytes(c ^ MASK[i % 4] for i, c in enumerate(payload))
    return hdr + payload


def upgrade(t, ext=None, proto=None, version=13, upg='websocket', resp_ext=None, resp_proto=None):
    h = (b'GET /chat HTTP/1.1\r\nHost: example.invalid\r\nUpgrade: %s\r\n'
         b'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
         b'Sec-WebSocket-Version: %d\r\n' % (upg.encode(), version))
    if proto:
        h += b'Sec-WebSocket-Protocol: ' + proto.encode() + b'\r\n'
    if ext:
        h += b'Sec-WebSocket-Extensions: ' + ext.encode() + b'\r\n'
    t.c(h + b'\r\n')
    r = (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: %s\r\nConnection: Upgrade\r\n'
         b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGOzhZzOo=\r\n' % upg.encode())
    if resp_proto or proto:
        r += b'Sec-WebSocket-Protocol: ' + (resp_proto or proto).encode() + b'\r\n'
    if resp_ext or ext:
        r += b'Sec-WebSocket-Extensions: ' + (resp_ext or ext).encode() + b'\r\n'
    t.s(r + b'\r\n')


class Deflater:
    """permessage-deflate sender (compression is done with python zlib; the
    Z_SYNC_FLUSH tail is stripped as RFC 7692 requires)."""
    def __init__(self, wbits=15, takeover=True):
        self.wbits, self.takeover = wbits, takeover
        self.c = zlib.compressobj(9, zlib.DEFLATED, -wbits)

    def pack(self, data):
        if not self.takeover:
            self.c = zlib.compressobj(9, zlib.DEFLATED, -self.wbits)
        out = self.c.compress(data) + self.c.flush(zlib.Z_SYNC_FLUSH)
        assert out.endswith(b'\x00\x00\xff\xff')
        return out[:-4]


# ---------------------------------------------------------------- 1 plain
t = Tcp()
upgrade(t)
t.s(frame(1, b'hello from the server\n'))
t.c(frame(1, b'hello from the client\n', mask=True))
t.c(frame(2, bytes(range(40)), mask=True))
t.s(frame(2, bytes(range(200)), force_len=16))             # 16 bit length, binary
t.s(frame(9, b'ping data'))
t.c(frame(10, b'ping data', mask=True))
t.s(frame(10))                                            # pong, no payload
t.s(frame(1, b'x' * 300 + b'\n', force_len=16))
t.s(frame(1, b'sixty-four bit length form\n', force_len=64))
t.c(frame(1, b'masked 16 bit length ' * 20 + b'\n', mask=True))
# several frames in one segment
t.s(frame(1, b'one\n') + frame(1, b'two\n') + frame(2, b'\x01\x02\x03'))
# a frame split over two TCP segments (header and payload separately)
fr = frame(1, b'split across two segments\n')
t.s(fr[:3])
t.s(fr[3:])
# a frame whose extended length is cut in the middle (needs more data)
fr = frame(2, bytes(300), force_len=16)
t.s(fr[:3])
t.s(fr[3:])
fr = frame(2, bytes(20), force_len=64)
t.s(fr[:6])
t.s(fr[6:])
# 70000 octet binary frame over many segments
t.s(frame(2, bytes((i * 7) & 0xff for i in range(70000))))
# fragmented text: first, ping in the middle, continuation, last
t.s(frame(1, b'frag', fin=False))
t.s(frame(9, b'mid'))
t.s(frame(0, b'ment', fin=False))
t.s(frame(0, b'ed text\n', fin=True))
# fragmented masked binary from the client
t.c(frame(2, b'AAAA', fin=False, mask=True))
t.c(frame(0, b'BBBB', fin=False, mask=True))
t.c(frame(0, b'CCCC', fin=True, mask=True))
# reproducer for the continuation-fragment early return (pinfo->fragmented
# was left set and "single" was not dissected)
t.s(frame(1, b'ab', fin=False) + frame(0, b'cd', fin=False) + frame(1, b'single\n'))
t.s(frame(0, b'ef\n'))
# close frames
t.c(frame(8, struct.pack('!H', 1000) + b'bye', mask=True))
t.s(frame(8, struct.pack('!H', 1001)))
t.s(frame(8, b'\x03'))                                    # one octet body
t.s(frame(8))
# reserved opcodes
t.s(frame(3, b'reserved data frame'))
t.s(frame(11, b'reserved control frame'))

# 64 bit length that does not fit in 32 bits (reproducer of the truncation
# to 32 bits: it used to be decoded as 5 octets), alone on its connection
t = Tcp()
upgrade(t)
t.s(frame(1, b'before\n'))
t.s(struct.pack('!BBQ', 0x82, 127, 0x100000005) + b'12345' + frame(1, b'after\n'))

# ---------------------------------------------------------------- 2 subprotocols
t = Tcp()
upgrade(t, proto='sip')
t.c(frame(1, b'OPTIONS sip:bob@example.invalid SIP/2.0\r\nVia: SIP/2.0/WS 192.0.2.1;branch=z9hG4bK1\r\n'
             b'Max-Forwards: 70\r\nTo: <sip:bob@example.invalid>\r\nFrom: <sip:alice@example.invalid>;tag=1\r\n'
             b'Call-ID: ws-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n', mask=True))
t.s(frame(1, b'SIP/2.0 200 OK\r\nVia: SIP/2.0/WS 192.0.2.1;branch=z9hG4bK1\r\nTo: <sip:bob@example.invalid>;tag=2\r\n'
             b'From: <sip:alice@example.invalid>;tag=1\r\nCall-ID: ws-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'))
t = Tcp()
upgrade(t, proto='coap')
# CoAP over WebSockets: GET with token 0x11 and Uri-Path "x" (RFC 8323)
t.c(frame(2, bytes([0x01, 0x01, 0x11, 0xb1, ord('x')]), mask=True))
t.s(frame(2, bytes([0x01, 0x45, 0x11, 0xff]) + b'ok'))
t = Tcp()
upgrade(t, proto='chat')                                   # no dissector for it
t.s(frame(1, b'{"json": [1, 2, 3], "text": "line"}\n'))
t.c(frame(1, b'{"reply": true}', mask=True))
t = Tcp()
upgrade(t, upg='WebSocket')                                # other spelling of the token
t.s(frame(1, b'upgrade token spelled WebSocket\n'))

# ---------------------------------------------------------------- 3 permessage-deflate
t = Tcp()
upgrade(t, ext='permessage-deflate')
ds, dc = Deflater(), Deflater()
m1 = b'compressed text message, compressed text message, compressed text message\n'
t.s(frame(1, ds.pack(m1), rsv=4))
t.s(frame(1, ds.pack(m1 + b'again\n'), rsv=4))            # back reference to m1 (context takeover)
t.c(frame(1, dc.pack(b'client message one\n'), rsv=4, mask=True))
t.c(frame(2, dc.pack(bytes(range(256)) * 4), rsv=4, mask=True))
t.s(frame(2, ds.pack(b''), rsv=4))                        # empty message
t.s(frame(1, b'not compressed (RSV1 clear)\n'))
t.s(frame(9, b'ping'))                                    # control frame between messages
# fragmented compressed message
big = b'fragmented compressed message with some repetition ' * 10 + b'\n'
z = ds.pack(big)
h = len(z) // 3
t.s(frame(1, z[:h], fin=False, rsv=4))
t.s(frame(0, z[h:2 * h], fin=False))
t.s(frame(0, z[2 * h:]))
# the decompressed size limit: just under, exactly at and just past 10 MiB
LIM = 10 * 1024 * 1024
t.s(frame(2, ds.pack(b'u' * (LIM - 1)), rsv=4))
t.s(frame(2, ds.pack(b'e' * LIM), rsv=4))
t.s(frame(2, ds.pack(b'o' * (LIM + 1)), rsv=4))
t.s(frame(1, ds.pack(b'ooo after the truncated message, window still in sync\n'), rsv=4))
# 20000 random octets repeated: a 20 KB compressed message whose 2x size is
# not a divisor of 10 MiB, so the last inflate chunk crosses the limit
import random
blk = random.Random(7).randbytes(20000)
t.s(frame(2, ds.pack(blk * 540), rsv=4))
# decompression failure (the stream is unusable afterwards, so it is last)
t.s(frame(1, b'\xff\xff\xff\xff\xff', rsv=4))

# no context takeover, window bits
for ext in ('permessage-deflate; server_no_context_takeover; client_no_context_takeover; '
            'server_max_window_bits=9; client_max_window_bits=10',
            'permessage-deflate; server_max_window_bits=7; client_max_window_bits=20',
            'permessage-deflate; server_max_window_bits=abc; client_max_window_bits',
            'x-webkit-deflate-frame'):
    t = Tcp()
    upgrade(t, ext=ext)
    nt = 'no_context_takeover' in ext
    ds = Deflater(9 if 'bits=9' in ext else 15, takeover=not nt)
    dc = Deflater(10 if 'bits=10' in ext else 15, takeover=not nt)
    t.s(frame(1, ds.pack(b'server message 1 for ' + ext.encode() + b'\n'), rsv=4))
    t.s(frame(1, ds.pack(b'server message 2 for ' + ext.encode() + b'\n'), rsv=4))
    t.c(frame(1, dc.pack(b'client message for ' + ext.encode() + b'\n'), rsv=4, mask=True))

# server selects the extension in its response only
t = Tcp()
upgrade(t, ext=None, resp_ext='permessage-deflate')
ds = Deflater()
t.s(frame(1, ds.pack(b'extension named in the response only\n'), rsv=4))

# ---------------------------------------------------------------- 4 HTTP/2 (cleartext, prior knowledge)


def h2frame(typ, flags, stream, payload=b''):
    return struct.pack('!I', len(payload))[1:] + bytes([typ, flags]) + struct.pack('!I', stream) + payload


def hp(name, value):
    """HPACK literal header field without indexing, new name, no Huffman."""
    return b'\x00' + bytes([len(name)]) + name + bytes([len(value)]) + value


t = Tcp(sport=9000)
t.c(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4, 0, 0))
t.s(h2frame(4, 0, 0))
t.c(h2frame(4, 1, 0))
hdr = (hp(b':method', b'CONNECT') + hp(b':protocol', b'websocket') + hp(b':scheme', b'http') +
       hp(b':path', b'/chat') + hp(b':authority', b'example.invalid') +
       hp(b'sec-websocket-version', b'13') + hp(b'sec-websocket-protocol', b'chat') +
       hp(b'sec-websocket-extensions', b'permessage-deflate'))
t.c(h2frame(1, 4, 1, hdr))
t.s(h2frame(1, 4, 1, hp(b':status', b'200') + hp(b'sec-websocket-protocol', b'chat') +
                hp(b'sec-websocket-extensions', b'permessage-deflate')))
ds, dc = Deflater(), Deflater()
t.s(h2frame(0, 0, 1, frame(1, ds.pack(b'websocket over HTTP/2, compressed\n'), rsv=4)))
t.c(h2frame(0, 0, 1, frame(1, dc.pack(b'client over HTTP/2\n'), rsv=4, mask=True)))
t.s(h2frame(0, 0, 1, frame(1, b'plain frame over HTTP/2\n')))
t.s(h2frame(0, 1, 1, frame(8, struct.pack('!H', 1000))))

# ---------------------------------------------------------------- 5 no HTTP upgrade (heuristic / Decode As)
t = Tcp(sport=8001, cport=50001)
t.c(frame(1, b'heuristic websocket, client\n', mask=True))
t.s(frame(1, b'heuristic websocket, server\n'))
t.s(frame(2, bytes(range(30))))
t = Tcp(sport=8002, cport=50002)
t.c(frame(1, b'decode as websocket_tcp, client\n', mask=True))
t.s(frame(1, b'decode as websocket_tcp, server\n'))
t = Tcp(sport=8004, cport=50004)
t.s(frame(1, b'heuristic websocket, the server speaks first\n'))
t.c(frame(1, b'reply\n', mask=True))
t = Tcp(sport=8005, cport=50005)
t.c(b'\x81')                                              # too short for the heuristic
t.c(b'\x00' + frame(1, b'x')[1:])
# RDP fast-path over WebSocket (the "ws" heuristic table)
t = Tcp(sport=8006, cport=50006)
t.s(frame(2, b'\x00\x03\x00\x00'[:0] + bytes([0x00, 0x06, 0x00, 0x00, 0x00, 0x00])))
# the heuristic must refuse these (RSV bit, bad opcode, plain HTTP letters)
t = Tcp(sport=8003, cport=50003)
t.c(frame(1, b'rsv bit set\n', rsv=1, mask=True))
t.c(frame(5, b'bad opcode', mask=True))
t.c(b'GET / HTTP/1.1\r\n\r\n')
t.c(b'\x81')

def write(fname, pkts):
    with open(os.path.join(OUT, fname), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


write('websocket-coverage.pcap', PKTS)
print('main', len(PKTS), 'packets')

# ---------------------------------------------------------------- malformed capture
PKTS.clear()
Tcp.n = 100
t = Tcp()
upgrade(t, ext='permessage-deflate')
ds = Deflater()
t.s(frame(1, ds.pack(b'ok\n'), rsv=4))
# truncated frames: payload shorter than announced at the end of the stream
t.s(frame(1, b'0123456789')[:6])
t = Tcp()
upgrade(t)
# 64 bit length near 2^64 and near 2^32: clamped, the PDU never completes
t.s(struct.pack('!BBQ', 0x82, 127, 0xfffffffffffffff0) + b'data')
t = Tcp()
upgrade(t)
t.s(struct.pack('!BBQ', 0x82, 127, 0xfffffff8) + b'data' * 4)
t = Tcp()
upgrade(t)
t.s(b'\x81')                                              # one octet only
t.s(b'\x81\x7e')                                          # 16 bit length cut
t = Tcp()
upgrade(t)
t.c(struct.pack('!BB', 0x81, 0x80 | 5) + MASK + b'abc')   # masked, payload cut short
# a masked payload longer than max_unmasked_len (-o websocket.max_unmasked_len:100):
# the payload item is longer than the unmasked data, so the dissection stops
# with a bounds error before the "not fully unmasked" expert info is added
t = Tcp()
upgrade(t)
t.c(frame(1, (b'masked payload that is longer than the preference allows\n' * 30), mask=True))
write('websocket-coverage-malformed.pcap', PKTS)
print('malformed', len(PKTS), 'packets')
