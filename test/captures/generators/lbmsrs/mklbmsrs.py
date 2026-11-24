#!/usr/bin/env python3
# Generates test/captures/lbmsrs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the LBMSRS (Ultra Messaging Stateful Resolution Service over RSocket)
# coverage captures.  Usage: mklbmsrs.py <outdir> [-v]
# Every packet is built with struct; the addresses are from 192.0.2.0/24 and
# 127.0.0.1 (the dissector's default heuristic address).
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


class Pcap:
    def __init__(self):
        self.frames = []
        self.ts = 1700000000

    def add(self, fr):
        self.frames.append(fr)
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', self.ts + i // 1000, (i % 1000) * 1000, len(fr), len(fr)))
                f.write(fr)


class Tcp:
    '''One TCP connection; send() appends a data segment from the client
    (dir 0) or the server (dir 1).'''

    def __init__(self, pc, cip, cport, sip, sport):
        self.pc = pc
        self.a = [(cip, cport), (sip, sport)]
        self.seq = [1000, 5000]
        self.ipid = 1

    def seg(self, d, flags, payload=b''):
        (si, sp), (di, dp) = self.a[d], self.a[1 - d]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d] if flags & 0x10 else 0,
                          0x50, flags, 65535, 0, 0) + payload
        ph = ip4(si) + ip4(di) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0, ip4(si), ip4(di))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.ipid += 1
        eth = bytes([2, 0, 0, 0, 0, 2 - d]) + bytes([2, 0, 0, 0, 0, 1 + d]) + b'\x08\x00'
        return self.pc.add(eth + ip + tcp)

    def handshake(self):
        self.seg(0, 0x02); self.seq[0] += 1
        self.seg(1, 0x12); self.seq[1] += 1
        self.seg(0, 0x10)

    def send(self, d, payload):
        n = self.seg(d, 0x18, payload)
        self.seq[d] += len(payload)
        return n


# ---- RSocket framing -------------------------------------------------------
F_SETUP, F_LEASE, F_KEEPALIVE, F_REQ_RESPONSE, F_REQ_FNF, F_REQ_STREAM, F_REQ_CHANNEL, \
    F_REQ_N, F_CANCEL, F_PAYLOAD, F_ERROR, F_METADATA_PUSH, F_RESUME, F_RESUME_OK = range(1, 15)
F_EXT = 0x3f


def rs(stream, ftype, flags, body, mdata=None, bad_len=None):
    '''RSocket frame: 3 octet length, stream id, 6 bit type + ignore +
    metadata + 8 flag bits, frame specific fixed part, optional metadata
    (3 octet length + data), payload.'''
    f = flags
    if mdata is not None:
        f |= 0x100
    b = struct.pack('!IH', stream, (ftype << 10) | f)
    if body[:0] == b'' and mdata is not None:
        pass
    fixed, payload = body if isinstance(body, tuple) else (b'', body)
    b += fixed
    if mdata is not None:
        b += struct.pack('!I', len(mdata))[1:] + mdata
    b += payload
    n = len(b) if bad_len is None else bad_len
    return struct.pack('!I', n)[1:] + b


# ---- SRS messages ----------------------------------------------------------
def s8(s):
    s = s.encode() if isinstance(s, str) else s
    return struct.pack('!B', len(s)) + s


OTID = bytes(range(0x10, 0x30))
CTX = bytes([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 7])
CTX2 = bytes([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 9])


def reg_req(app=0, mode=0x07, port=14371, dom=1, ver=2):
    return struct.pack('!H', 1) + struct.pack('!B4sHIIBBI', app, ip4('192.0.2.7'), port, 0x11223344, 0x55667788, ver, mode, dom)


def reg_resp(cid=0x0102030405060708, dom=1, ver=2):
    return struct.pack('!HQIB', 2, cid, dom, ver)


def stream_req():
    return struct.pack('!HB', 3, 0)


def sir(topic='topic1', source='source1', cost=5, ttl=3, otid=OTID):
    t = topic.encode() + b'\0'
    s = source.encode() + b'\0'
    return (struct.pack('!H', 4) + otid + s8(t) + s8(s) +
            struct.pack('!IIIIHIBBIIQ', 0x1234, 77, 0x03, 0xc0000207, 14400, 5, 1, 2, 11, 12, 0x1122334455667788) +
            CTX + struct.pack('!BIIHi', 0, 0x0a000000 + 5, 0x1, ttl, cost))


def ser(topic='topic1', source='source1'):
    return sir(topic, source, cost=-1)


def sdr(topic='topic1'):
    return struct.pack('!H', 5) + OTID + s8(topic.encode() + b'\0')


def tail(ctx=CTX, ty=0, ver=0x0a000000 + 5, vf=1):
    return ctx + struct.pack('!BIII', ty, ver, vf, 0)


def rcv(mid, topic):
    return struct.pack('!H', mid) + s8(topic.encode() + b'\0') + struct.pack('!I', 1) + tail()


def sli(topic='topic1', source='source1'):
    return struct.pack('!H', 12) + OTID + s8(topic + '\0') + s8(source + '\0') + tail()


def route(mid, doms, port=14380, idx=2):
    return (struct.pack('!H', mid) + struct.pack('!H', len(doms)) + b''.join(struct.pack('!I', d) for d in doms) +
            struct.pack('!IH', 0xc0000208, port) + CTX + struct.pack('!BIIHH', 0, 0x0a000005, 1, idx, 0))


def dmi(dom=3):
    return struct.pack('!HI', 15, dom) + tail()


def cnq(name='ctxname'):
    return struct.pack('!H', 16) + s8(name + '\0') + struct.pack('!I', 4) + tail()


def cni(mid=17, name='ctxname'):
    return (struct.pack('!H', mid) + s8(name + '\0') + struct.pack('!IIH', 4, 0xc0000209, 14390) +
            CTX2 + CTX + struct.pack('!BIII', 1, 0x0a000005, 1, 0))


ALL_BATCH = {
    'SIR': sir(), 'SER': ser(), 'SDR': sdr(), 'RIR': rcv(6, 'rtopic'), 'RDR': rcv(7, 'rtopic'),
    'RER': rcv(8, 'rtopic'), 'WIR': rcv(9, 'wild.*'), 'WDR': rcv(10, 'wild.*'), 'WER': rcv(11, 'wild.*'),
    'SLI': sli(), 'RTI': route(13, [1, 2, 3]), 'RTE': route(14, [4]), 'DMI': dmi(), 'CNQ': cnq(),
    'CNI': cni(), 'CNE': cni(18),
}


def build_main(pc, notes):
    def mark(label):
        notes.append((len(pc.frames) + 1, label))

    c = Tcp(pc, '127.0.0.1', 41500, '192.0.2.2', 50000)
    mark('connection 1 handshake')
    c.handshake()
    mark('registration request first (the SMPP heuristic claims a connection that starts with SETUP, see README), then SETUP, REQUEST_*/PAYLOAD with registration messages')
    lead = rs(1, F_REQ_FNF, 0, (b'', stream_req()))
    c.send(0, lead)
    # SETUP: lease flag, mime types, registration request as payload
    setup = struct.pack('!HHII', 1, 0, 1000, 5000) + s8('application/x.srs') + s8('application/x.srs')
    c.send(0, rs(0, F_SETUP, 0x0040, (setup, reg_req())))
    # SETUP with resume token and a stream request
    tok = b'TOKEN123'
    setup2 = struct.pack('!HHII', 1, 0, 1000, 5000) + struct.pack('!H', len(tok)) + tok + s8('mime') + s8('data')
    c.send(0, rs(0, F_SETUP, 0x0080, (setup2, stream_req())))
    # SETUP with a different mime type and no payload
    c.send(0, rs(0, F_SETUP, 0, (struct.pack('!HHII', 1, 0, 1000, 5000) + s8('') + s8(''), b'')))
    c.send(1, rs(0, F_KEEPALIVE, 0x0080, (struct.pack('!Q', 0x1000), b'')))
    c.send(1, rs(0, F_KEEPALIVE, 0x0000, (struct.pack('!Q', 0), b'')))
    c.send(0, rs(1, F_REQ_RESPONSE, 0x0000, (struct.pack('!B', 0)[:0], reg_req(1, 0x01, 14372))))
    c.send(0, rs(1, F_REQ_RESPONSE, 0x0080, (b'', reg_req(2, 0x02))))
    c.send(0, rs(3, F_REQ_FNF, 0x0000, (b'', reg_req(2, 0x04, 0, 0, 3))))
    c.send(1, rs(1, F_PAYLOAD, 0x0060, reg_resp()))
    c.send(1, rs(1, F_PAYLOAD, 0x0020, reg_resp(0xfffffffffffffff0, 9, 3)))
    c.send(1, rs(3, F_PAYLOAD, 0x00a0, reg_resp(1, 2, 1)))
    c.send(0, rs(5, F_REQ_STREAM, 0x0000, (struct.pack('!I', 100), stream_req())))
    c.send(0, rs(5, F_REQ_STREAM, 0x0080, (struct.pack('!I', 0x7fffffff), stream_req())))
    c.send(0, rs(7, F_REQ_CHANNEL, 0x00c0, (struct.pack('!I', 5), stream_req())))
    c.send(0, rs(7, F_REQ_CHANNEL, 0x0000, (struct.pack('!I', 5), reg_req())))
    mark('REQUEST_N, CANCEL, ERROR, METADATA_PUSH, RESUME, RESUME_OK, EXT, ignore flag')
    c.send(0, lead + rs(5, F_REQ_N, 0, (struct.pack('!I', 10), b'')))
    c.send(0, rs(5, F_REQ_N, 0, (struct.pack('!I', 10), stream_req())))
    c.send(0, rs(5, F_CANCEL, 0, (b'', sir())))
    c.send(0, lead + rs(5, F_CANCEL, 0, b''))
    c.send(1, rs(5, F_ERROR, 0, (struct.pack('!I', 0x201), sdr())))
    for code in (0, 1, 2, 3, 4, 0x101, 0x102, 0x202, 0x203, 0x204, 0xffffffff, 0x999):
        c.send(1, rs(9, F_ERROR, 0, (struct.pack('!I', code), sdr())))
    c.send(0, rs(0, F_METADATA_PUSH, 0, b'\x00\x01\x02'))
    c.send(0, rs(0, F_METADATA_PUSH, 0, b''))
    c.send(0, rs(0, F_RESUME, 0, b'\x00\x01\x00\x00\x00\x08TOKEN123' + b'\0' * 16))
    c.send(0, rs(0, F_RESUME_OK, 0, struct.pack('!Q', 99)))
    c.send(0, rs(0, F_EXT, 0x0200, b'\0' * 8))
    c.send(0, rs(5, F_REQ_FNF, 0x0200, (b'', reg_req()), mdata=b'ignored'))
    mark('metadata present: REQUEST_FNF, PAYLOAD, REQUEST_STREAM with metadata')
    c.send(0, rs(11, F_REQ_FNF, 0, (b'', sdr()), mdata=b'text/plain'))
    c.send(1, rs(11, F_PAYLOAD, 0x20, rcv(6, 'm.topic'), mdata=b''))
    c.send(0, rs(13, F_REQ_STREAM, 0, (struct.pack('!I', 2), reg_req()), mdata=b'\x00\x01meta'))
    mark('every SRS message as a single batch element, one per frame (batch counters in the info column)')
    sid = 21
    for name in ('SIR', 'SER', 'SDR', 'RIR', 'RDR', 'RER', 'WIR', 'WDR', 'WER', 'SLI', 'RTI', 'RTE',
                 'DMI', 'CNQ', 'CNI', 'CNE'):
        c.send(1, rs(sid, F_PAYLOAD, 0x20, ALL_BATCH[name])); sid += 2
    mark('batches of mixed messages (several per frame)')
    allm = b''.join(ALL_BATCH[k] for k in ('SIR', 'SER', 'SDR', 'RIR', 'RDR', 'RER', 'WIR', 'WDR', 'WER',
                                           'SLI', 'RTI', 'RTE', 'DMI', 'CNQ', 'CNI', 'CNE'))
    c.send(1, rs(41, F_PAYLOAD, 0x20, allm))
    c.send(0, rs(43, F_REQ_FNF, 0, (b'', sir('a') + sir('b') + ser('c') + sdr('a') + rcv(6, 'x') * 3)))
    c.send(1, rs(45, F_PAYLOAD, 0x20, route(13, []) + route(14, []) + dmi(1) + dmi(2) + cnq('a') + cni(17, 'b') + cni(18, 'c')))
    c.send(1, rs(47, F_PAYLOAD, 0x20, sir(topic='') + sdr(topic='')))
    c.send(1, rs(49, F_PAYLOAD, 0x20, sir() + b'\x00\x63junk'))        # unknown id after a message
    c.send(1, rs(51, F_PAYLOAD, 0x20, sir() + b'\x00'))                # one stray octet
    c.send(1, rs(53, F_PAYLOAD, 0x20, rcv(7, 'a') + rcv(8, 'b') + b'\x00\x01' + b'\0' * 3))
    mark('Registration request/response with unexpected length (only the message id is dissected)')
    c.send(0, rs(55, F_REQ_FNF, 0, (b'', reg_req() + b'\0\0')))
    c.send(1, rs(55, F_PAYLOAD, 0x20, reg_resp() + b'\0'))
    c.send(0, rs(55, F_REQ_FNF, 0, (b'', stream_req() + b'\0')))
    mark('two RSocket frames in one TCP segment (the second is LEASE and an unknown frame type)')
    c.send(0, rs(57, F_REQ_FNF, 0, (b'', sdr())) + rs(0, F_LEASE, 0, struct.pack('!II', 1000, 10)) +
           rs(0, 0x30, 0, b'\x01\x02') + rs(0, 0, 0, b'\0'))
    c.send(0, rs(59, F_REQ_FNF, 0, (b'', sdr())) + rs(0, F_KEEPALIVE, 0x80, (struct.pack('!Q', 5), b'')))
    mark('RSocket frame split over two and three TCP segments (desegmentation)')
    f = rs(61, F_PAYLOAD, 0x20, ALL_BATCH['SIR'] + ALL_BATCH['SDR'] + ALL_BATCH['CNI'])
    c.send(1, f[:20]); c.send(1, f[20:90]); c.send(1, f[90:])
    f = rs(63, F_REQ_FNF, 0, (b'', sir('long.' + 'x' * 100, 'src' + 'y' * 100)))
    c.send(0, f[:30]); c.send(0, f[30:])
    mark('PDU boundary in the middle of a segment')
    f1 = rs(65, F_REQ_FNF, 0, (b'', sdr('one')))
    f2 = rs(67, F_REQ_FNF, 0, (b'', sdr('two')))
    c.send(0, f1 + f2[:15]); c.send(0, f2[15:])
    # --- second connection, server side on 127.0.0.1: the other direction
    c2 = Tcp(pc, '192.0.2.9', 41000, '127.0.0.1', 50001)
    mark('connection 2 (server is 127.0.0.1): heuristic matches the destination address')
    c2.handshake()
    c2.send(0, rs(1, F_REQ_FNF, 0, (b'', reg_req())))
    c2.send(1, rs(1, F_PAYLOAD, 0x20, reg_resp()))
    c2.send(0, rs(3, F_REQ_STREAM, 0, (struct.pack('!I', 1), stream_req())))
    c2.send(1, rs(3, F_PAYLOAD, 0x20, sir() + rcv(6, 'a') + cni()))
    # --- third connection, no loopback address at all: needs the prefs (runcov.sh)
    c3 = Tcp(pc, '192.0.2.20', 42000, '192.0.2.21', 50002)
    mark('connection 3 (192.0.2.20 / 192.0.2.21, port 50002): only with the tag table or the address preference')
    c3.handshake()
    c3.send(0, rs(1, F_REQ_FNF, 0, (b'', reg_req())))
    c3.send(1, rs(1, F_PAYLOAD, 0x20, reg_resp()))
    c3.send(0, rs(3, F_REQ_STREAM, 0, (struct.pack('!I', 1), stream_req())))
    c3.send(1, rs(3, F_PAYLOAD, 0x20, sir() + sli()))
    mark('end of main capture')


def build_malformed(pc, notes):
    def mark(label):
        notes.append((len(pc.frames) + 1, label))

    c = Tcp(pc, '127.0.0.1', 41600, '192.0.2.2', 50100)
    c.handshake()
    lead = rs(1, F_REQ_FNF, 0, (b'', sdr()))      # a valid frame so that the heuristic matches
    mark('SRS messages cut at every field boundary (frame length matches the data)')
    sid = 3
    for name, m in ALL_BATCH.items():
        cuts = set(range(2, len(m)))
        for cut in sorted(cuts):
            # keep it small: cut at every boundary found by trying each offset
            pass
    # cut points: every offset for messages shorter than 80 octets, the boundaries for SIR
    for name, m in ALL_BATCH.items():
        step = 1
        for cut in range(0, len(m), step):
            if len(m) > 80 and cut > 8 and cut % 3 and cut not in (34, 35, 36, 36 + 7, 36 + 8):
                continue
            body = m[:cut]
            if not body:
                continue
            c.send(0, lead + rs(sid, F_PAYLOAD, 0x20, body))
            sid += 2
    mark('RTI/RTE with a domain count larger than the data (exception at the end of the frame)')
    for mid in (13, 14):
        c.send(0, lead + rs(sid, F_PAYLOAD, 0x20, struct.pack('!HH', mid, 0xffff) + b'\0' * 16)); sid += 2
        c.send(0, lead + rs(sid, F_PAYLOAD, 0x20, struct.pack('!HH', mid, 3) + b'\0' * 8)); sid += 2
        c.send(0, lead + rs(sid, F_PAYLOAD, 0x20, struct.pack('!HH', mid, 1) + b'\0' * 20)); sid += 2
    mark('Unknown SRS message id in the payload (expert info)')
    c.send(0, lead + rs(sid, F_PAYLOAD, 0x20, struct.pack('!HI', 0x4242, 1))); sid += 2
    c.send(0, lead + rs(sid, F_SETUP, 0, (struct.pack('!HHII', 1, 0, 1, 1) + s8('a') + s8('b'), struct.pack('!HI', 99, 0)))); sid += 2
    c.send(0, lead + rs(sid, F_KEEPALIVE, 0, (struct.pack('!Q', 1), struct.pack('!H', 0)))); sid += 2
    c.send(0, lead + rs(sid, F_PAYLOAD, 0x20, b'\x01')); sid += 2
    mark('RSocket frames cut short: every frame type, the fixed part and the metadata')
    for ft, fixed_len in ((F_SETUP, 14), (F_KEEPALIVE, 10), (F_REQ_RESPONSE, 2), (F_REQ_FNF, 2), (F_REQ_STREAM, 6),
                          (F_REQ_CHANNEL, 6), (F_REQ_N, 6), (F_CANCEL, 2), (F_PAYLOAD, 2), (F_ERROR, 6)):
        full = bytes(range(1, 40))
        for cut in sorted({0, 1, fixed_len - 3, fixed_len - 2, fixed_len - 1, fixed_len}):
            if cut < 0 or cut > len(full):
                continue
            flags = 0x80 if ft == F_SETUP else 0
            raw = struct.pack('!IH', sid, (ft << 10) | flags) + full[:cut]
            c.send(0, lead + struct.pack('!I', len(raw))[1:] + raw); sid += 2
    # SETUP with resume flag cut inside the token and the mime fields
    base = struct.pack('!HHII', 1, 0, 1, 1)
    for tail_ in (b'', b'\x00', b'\x00\x05AB', b'\x00\x02AB', b'\x00\x02AB\x05mi', b'\x00\x02AB\x02mi',
                  b'\x00\x02AB\x02mi\x05da', b'\x00\x02AB\x02mi\x02da'):
        raw = struct.pack('!IH', sid, (F_SETUP << 10) | 0x80) + base + tail_
        c.send(0, lead + struct.pack('!I', len(raw))[1:] + raw); sid += 2
    for tail_ in (b'', b'\x05mi', b'\x02mi', b'\x02mi\x05da', b'\x02mi\x02da'):
        raw = struct.pack('!IH', sid, (F_SETUP << 10)) + base + tail_
        c.send(0, lead + struct.pack('!I', len(raw))[1:] + raw); sid += 2
    # metadata cut short
    for ft, fixed in ((F_REQ_FNF, b'\0\0'),):
        for md in (b'\x00', b'\x00\x00\x10abc', b'\x00\x00\x03abc'):
            raw = struct.pack('!IH', sid, (ft << 10) | 0x100) + fixed + md
            c.send(0, lead + struct.pack('!I', len(raw))[1:] + raw); sid += 2
    mark('Frame length field disagreeing with the data')
    c.send(0, lead + rs(sid, F_REQ_FNF, 0, (b'', sdr()), bad_len=3)); sid += 2
    c.send(0, lead + rs(sid, F_REQ_FNF, 0, (b'', sdr()), bad_len=0)); sid += 2
    c.send(0, lead + rs(sid, F_REQ_FNF, 0, (b'', sdr()), bad_len=1)); sid += 2
    c.send(0, lead + b'\x00\x00')
    c.send(0, lead + b'\x00\x00\x02\x00\x00')
    mark('Frame length larger than the data at the end of the capture (reassembly never completes)')
    c.send(0, rs(sid, F_REQ_FNF, 0, (b'', sdr()), bad_len=5000))
    # ---- heuristic rejects (not dissected as LBMSRS)
    mark('Heuristic rejects: unknown frame type, stream id not 0 for SETUP, unknown message id, short')
    d = Tcp(pc, '127.0.0.1', 41700, '192.0.2.2', 50200)
    d.handshake()
    d.send(0, rs(0, 0x30, 0, b'\0' * 8))
    d.send(0, rs(0, 0, 0, b'\0' * 8))
    d.send(0, rs(0, F_LEASE, 0, struct.pack('!II', 1, 1) + b'\0\0\0'))
    d.send(0, rs(4, F_SETUP, 0, b'\0' * 14))
    d.send(0, rs(4, F_KEEPALIVE, 0, b'\0' * 10))
    d.send(0, rs(4, F_REQ_FNF, 0, (b'', struct.pack('!HI', 0x7777, 0))))
    d.send(0, rs(4, F_REQ_FNF, 0, (b'', struct.pack('!HI', 17, 0)), mdata=b'abc'))
    d.send(0, rs(4, F_REQ_FNF, 0, (b'', b'\0\1')))
    d.send(0, rs(4, F_REQ_FNF, 0, (b'', b'')))
    d.send(0, b'\x00\x00\x05\x00\x00')
    d.send(0, b'\x00\x00\x05\x00\x00\x00\x04\x14')
    d.send(0, b'\x00\x00')
    d.send(0, rs(4, F_REQ_FNF, 0x100, (b'', b''), mdata=b'abcdef'))
    d.send(0, rs(4, F_REQ_FNF, 0, (b'\0\0', b''), mdata=None)[:7] + b'\x04\x00\x00')
    # frame with metadata flag but no room for the metadata length
    raw = struct.pack('!IH', 4, (F_REQ_FNF << 10) | 0x100) + b'\x00'
    d.send(0, struct.pack('!I', len(raw))[1:] + raw)
    raw = struct.pack('!IH', 4, (F_REQ_FNF << 10) | 0x100) + b'\x00\x00\x00\x00\x03'
    d.send(0, struct.pack('!I', len(raw))[1:] + raw)
    mark('Ignore flag without metadata (taken as metadata, bug), PDU header split from the rest (heuristic needs the message id in the first segment)')
    d2 = Tcp(pc, '127.0.0.1', 41800, '192.0.2.2', 50300)
    d2.handshake()
    d2.send(0, rs(5, F_REQ_FNF, 0, (b'', sdr())))
    d2.send(0, rs(5, F_REQ_FNF, 0x0200, (b'', sdr('ignorable'))))
    d2.send(0, rs(5, F_PAYLOAD, 0x0200, (b'', sir())))
    f = rs(63, F_REQ_FNF, 0, (b'', sir('long.' + 'x' * 100, 'src' + 'y' * 100)))
    d2.send(0, f[:9]); d2.send(0, f[9:])
    mark('end of malformed capture')


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    for name, fn in (('lbmsrs-coverage.pcap', build_main), ('lbmsrs-coverage-malformed.pcap', build_malformed)):
        pc = Pcap(); notes = []
        fn(pc, notes)
        pc.write(os.path.join(OUT, name))
        if VERBOSE:
            print(name, len(pc.frames), 'frames')
            for n, l in notes:
                print('  %4d  %s' % (n, l))
