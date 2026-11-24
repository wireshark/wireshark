#!/usr/bin/env python3
# Generates test/captures/nats_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NATS (TCP port 4222) coverage captures.

    mknats.py <outdir>

writes nats-coverage.pcap (every client and server operation, headers,
request/response matching, reassembly over several segments, several
operations per segment; decodes cleanly) and nats-coverage-malformed.pcap
(the edge cases of the review of this dissector and lines that stop short).
Nothing is captured from a real network.
"""
import json
import os
import struct
import sys

CL = bytes([10, 0, 0, 2])
SV = bytes([10, 0, 0, 1])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


class Flow:
    """one TCP connection to port 4222; tracks sequence numbers"""
    count = 0

    def __init__(self, cport):
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.frames = []
        Flow.count += 1

    def _seg(self, to_server, payload, flags):
        if to_server:
            src, dst, sp, dp, seq, ack = CL, SV, self.cport, 4222, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            src, dst, sp, dp, seq, ack = SV, CL, 4222, self.cport, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        opts = bytes.fromhex('020405b4010303070402') if flags & 2 else b''
        opts += b'\x01' * (-len(opts) % 4)
        th = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        pseudo = src + dst + struct.pack('!BBH', 0, 6, len(th) + len(payload))
        c = csum(pseudo + th + payload)
        th = th[:16] + struct.pack('!H', c) + th[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(th) + len(payload), len(self.frames) + Flow.count * 100, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        a, b = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
        eth = (a + b if to_server else b + a) + b'\x08\x00'
        self.frames.append(eth + ip + th + payload)

    def handshake(self):
        self._seg(True, b'', 0x02)
        self._seg(False, b'', 0x12)
        self._seg(True, b'', 0x10)

    def c(self, payload):
        self._seg(True, payload, 0x18)

    def s(self, payload):
        self._seg(False, payload, 0x18)


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)


INFO = {"server_id": "NDEMO", "version": "2.10.4", "proto": 1, "host": "10.0.0.1", "port": 4222,
        "headers": True, "max_payload": 1048576, "client_id": 7}
CONNECT = {"verbose": False, "pedantic": False, "tls_required": False, "name": "demo", "lang": "go",
           "version": "1.31.0", "protocol": 1, "echo": True, "headers": True}


def j(o):
    return json.dumps(o, separators=(',', ':')).encode()


def hdrs(*lines, version=b'NATS/1.0', eol=b'\r\n'):
    return version + eol + b''.join(l + eol for l in lines) + eol


def hpub(subj, h, body, reply=None, op=b'HPUB', sid=None):
    toks = [op, subj]
    if sid is not None:
        toks.append(sid)
    if reply:
        toks.append(reply)
    toks += [str(len(h)).encode(), str(len(h) + len(body)).encode()]
    return b' '.join(toks) + b'\r\n' + h + body + b'\r\n'


def pub(subj, body, reply=None, op=b'PUB', sid=None):
    toks = [op, subj]
    if sid is not None:
        toks.append(sid)
    if reply:
        toks.append(reply)
    toks.append(str(len(body)).encode())
    return b' '.join(toks) + b'\r\n' + body + b'\r\n'


def main_frames():
    flows = []
    # --- 1. a session: INFO, CONNECT, PING/PONG, SUB, UNSUB, PUB, MSG, +OK, -ERR
    f = Flow(41000)
    f.handshake()
    f.s(b'INFO ' + j(INFO) + b'\r\n')
    f.c(b'CONNECT ' + j(CONNECT) + b'\r\n' + b'PING\r\n')
    f.s(b'PONG\r\n')
    f.c(b'SUB demo.> 1\r\n')
    f.c(b'SUB demo.workers workers 2\r\n')
    f.c(b'sub lower.case 3\r\n')
    f.s(b'+OK\r\n')
    f.c(b'UNSUB 1\r\n')
    f.c(b'UNSUB 2 10\r\n')
    f.c(pub(b'demo.hello', b'Hello NATS'))
    f.c(pub(b'demo.empty', b''))
    f.s(pub(b'demo.hello', b'Hello NATS', op=b'MSG', sid=b'1'))
    f.s(pub(b'demo.empty', b'', op=b'MSG', sid=b'1'))
    f.c(b'PING\r\n')
    f.s(b'PONG\r\n')
    f.s(b'-ERR \'Unknown Protocol Operation\'\r\n')
    f.s(b'-ERR \'Authorization Violation\'\r\n')
    f.c(b'PONG\r\n')
    f.c(b'PING\r\n')
    # --- 2. request / response matching through the reply subject
    f.c(pub(b'svc.echo', b'ping?', reply=b'_INBOX.abc123'))
    f.s(pub(b'svc.echo', b'ping?', op=b'MSG', sid=b'2', reply=b'_INBOX.abc123'))
    f.c(pub(b'_INBOX.abc123', b'pong!'))                            # the response, seen from the responder
    f.s(pub(b'_INBOX.abc123', b'pong!', op=b'MSG', sid=b'3'))      # and delivered to the requester
    f.c(pub(b'svc.second', b'again', reply=b'_INBOX.def456'))
    f.s(pub(b'_INBOX.def456', b'', op=b'MSG', sid=b'3'))           # response without a body
    f.c(pub(b'svc.third', b'x', reply=b'_INBOX.ghi789'))
    f.s(pub(b'svc.third', b'x', op=b'MSG', sid=b'4', reply=b'_INBOX.ghi789'))
    f.s(pub(b'_INBOX.ghi789', b'late', op=b'MSG', sid=b'5', reply=b'_INBOX.reply2'))   # response that is a request itself
    f.c(pub(b'_INBOX.reply2', b'final'))
    flows.append(f)
    # --- 3. headers
    f = Flow(41001)
    f.handshake()
    f.c(hpub(b'hdr.one', hdrs(b'Nats-Msg-Id: 1', b'Content-Type: text/plain'), b'with headers'))
    f.c(hpub(b'hdr.two', hdrs(b'A: 1', b'A: 2', b'A: 3', b'B:no-space', b'C:   spaced'), b'dup', reply=b'_INBOX.h1'))
    f.s(hpub(b'hdr.one', hdrs(b'Nats-Msg-Id: 1'), b'delivered', op=b'HMSG', sid=b'9'))
    f.s(hpub(b'_INBOX.h1', hdrs(b'Status: 200'), b'ok', op=b'HMSG', sid=b'9', reply=b'_INBOX.h2'))
    f.c(hpub(b'hdr.nobody', hdrs(b'Only: header'), b''))
    f.c(hpub(b'hdr.status', hdrs(version=b'NATS/1.0 503'), b'x'))       # status line, no headers
    f.c(hpub(b'hdr.odd', hdrs(b'noColonHere', b': emptyname', b'Empty:'), b'odd'))
    f.c(hpub(b'hdr.ver', hdrs(b'V: 1', version=b'NATS/2.7'), b'v2.7'))
    f.c(hpub(b'hdr.ver2', hdrs(b'V: 1', version=b'NATS/300.1'), b'bad major'))
    f.c(hpub(b'hdr.ver3', hdrs(b'V: 1', version=b'NATS/1.x'), b'bad minor'))
    f.c(hpub(b'hdr.ver4', hdrs(b'V: 1', version=b'NATS'), b'no slash'))
    f.c(hpub(b'hdr.ver5', hdrs(b'V: 1', version=b'NATS/1'), b'no dot'))
    f.c(hpub(b'hdr.lf', hdrs(b'L: 1', b'M: 2', eol=b'\n') , b'lf only'))   # header block with LF only
    f.c(b'hpub lower.case 20 22\r\nNATS/1.0\r\nK: v\r\n\r\nhi\r\n')
    flows.append(f)
    # --- 4. reassembly and several operations per segment
    f = Flow(41002)
    f.handshake()
    body = bytes(range(65, 91)) * 8
    msg = pub(b'big.one', body)
    f.c(msg[:60])
    f.c(msg[60:130])
    f.c(msg[130:])
    f.c(b'PUB split.cmd 3\r\nabc\r\nPING\r\nSUB a.b 5\r\nPUB two.in.one 2\r\nhi\r\nPUB cut.in.body 10\r\n01234')
    f.c(b'56789\r\nPING\r\n')
    f.c(b'PU')
    f.c(b'B cut.in.cmd 4\r\nabcd\r\n')
    f.s(b'MSG a.b 5 3\r\nabc\r\nMSG a.b 5 3\r\ndef\r\nPONG\r\n')
    hm = hpub(b'big.hdr', hdrs(b'Part: 1', b'Part: 2'), body, reply=b'_INBOX.big')
    f.c(hm[:40])
    f.c(hm[40:200])
    f.c(hm[200:])
    f.c(b'PING\r\nHPUB tail 10 12\r\nNATS/1.0\r\n\r\nhi\r\n')
    f.c(b'PUB x 1\r\n9\r\nPING')
    f.c(b'\r\n')
    flows.append(f)
    # --- 5. unknown operations, blank lines and lines that do not parse
    f = Flow(41003)
    f.handshake()
    f.c(b'FOO bar\r\n')
    f.c(b'\r\n')
    f.c(b'SUB onlysubject\r\n')
    f.c(b'UNSUB\r\n')
    f.c(b'UNSUB 1 notanumber\r\n')
    f.c(b'PUB onlysubject\r\n')
    f.c(b'MSG a b 5\r\nhello\r\n')       # MSG without a count in the right place
    f.c(b'PUB bad notanumber\r\nabc\r\n')
    f.c(b'HPUB subj 10 5\r\nabcdefghij\r\n')    # more header bytes than total bytes
    f.c(b'PING\r\n')
    flows.append(f)
    # --- 6. the reproducers of "NATS: Fix length overflows and headers map lifetime"
    for i, m in enumerate((b'INFO\r\n', b'CONNECT\r\n', b'-ERR\r\n', b'INFO {"a":1}\n', b'INFO \r\n', b'-ERR  \r\n',
                           b'PUB foo 4294967295\r\nabc\r\n',
                           b'HPUB foo 4294967294 4294967294\r\nNATS/1.0\r\nX:\r\n\r\n',
                           b'HPUB foo 12 14\r\nNATS/1.0\n\na:\nhi\r\n',
                           b'HMSG foo 1 reply 22 24\r\nNATS/1.0\r\na:b\r\n:\r\n\r\nhi\r\n')):
        f = Flow(42000 + i)
        f.c(m)
        f.c(b'PING\r\n') if i < 6 or i == 8 or i == 9 else None
        flows.append(f)
    out = []
    for f in flows:
        out += f.frames
    return out


def malformed_frames():
    out = []
    f = Flow(43000)
    f.handshake()
    f.c(b'HPUB foo 1 1\r\nN\r\n')
    f.c(b'HPUB foo 2 2\r\n\r\n\r\n')
    f.c(b'HPUB foo 3 3\r\nN/.\r\n')
    f.c(b'MSG foo 1 reply 0\r\n\r\n')
    f.c(b'UNSUB 1 99999999999999999999999\r\n')
    f.c(b'PUB foo bar 5\r\nhello\r\nMSG bar 9 5\r\nworld\r\n')
    f.c(b'HPUB foo 0 0\r\n\r\n')
    f.c(b'HPUB foo 4 4\r\nNATS\r\n')
    out += f.frames
    # truncations of a header message
    base = hpub(b'trunc.me', hdrs(b'A: 1', b'B: 2'), b'bodybody', reply=b'_INBOX.t')
    for n in range(3, len(base), 3):
        g = Flow(44000 + n)
        g.c(base[:n])
        out += g.frames
    return out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    write_pcap(os.path.join(out, 'nats-coverage.pcap'), m)
    x = malformed_frames()
    write_pcap(os.path.join(out, 'nats-coverage-malformed.pcap'), x)
    print(len(m), 'frames,', len(x), 'malformed-capture frames')


if __name__ == '__main__':
    main()
