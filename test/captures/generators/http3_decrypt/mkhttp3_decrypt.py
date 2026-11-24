#!/usr/bin/env python3
# Generates the http3_decrypt captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator for http3_decrypt_coverage.pcapng: real HTTP/3 over QUIC from aioquic,
exchanged in memory and written as IPv4/UDP over 127.0.0.1.
Usage: mkhttp3_decrypt.py <outdir> [-v]   (run with the aioquic venv python)
Writes http3-decrypt.pcapng, http3-decrypt-malformed.pcapng and
http3-repro-decoder-break.pcapng, with the TLS key log in a Decryption Secrets
Block. The keys are random, so every run differs."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))



from qsim import Pair, Sim
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import *
from aioquic.quic.events import *

out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
sim = Sim(os.path.join(out, 'http3-decrypt.keys'))
port = [4446]
def addrs():
    port[0] += 1
    return ('127.0.0.1', 50000 + port[0]), ('127.0.0.1', port[0])

H3 = ['h3']
v = encode_uint_var

def frame(ft, payload=b''):
    return v(ft) + v(len(payload)) + payload

class H3Pair(Pair):
    def __init__(self, sim, wt=False, ccfg_kw=None, scfg_kw=None, h3cls=H3Connection, alpn=H3, **kw):
        c, s = addrs()
        super().__init__(sim, sim.ccfg(alpn, **(ccfg_kw or {})), sim.scfg(alpn, **(scfg_kw or {})), c, s,
                         autostart=False, **kw)
        self.wt = wt
        self.h3cls = h3cls
        self.ch = h3cls(self.client, enable_webtransport=wt)
        self.sh = None
        self.cev, self.sev = [], []
        self.on_server_created = self._mk_server_h3
        self.on_event = self._ev
        self.start()

    def _mk_server_h3(self, server):
        self.sh = self.h3cls(server, enable_webtransport=self.wt)

    def _ev(self, isc, ev):
        h = self.ch if isc else self.sh
        if h is None:
            return
        (self.cev if isc else self.sev).extend(h.handle_event(ev))

    def take(self, which, cls):
        lst = self.cev if which == 'c' else self.sev
        got = [e for e in lst if isinstance(e, cls)]
        for e in got:
            lst.remove(e)
        return got

    def request(self, headers, body=None, end=True, trailers=None):
        sid = self.client.get_next_available_stream_id()
        self.ch.send_headers(sid, headers, end_stream=(body is None and trailers is None and end))
        if body is not None:
            self.ch.send_data(sid, body, end_stream=(trailers is None and end))
        if trailers is not None:
            self.ch.send_headers(sid, trailers, end_stream=True)
        return sid

def req_headers(path, method=b'GET', extra=()):
    return [(b':method', method), (b':scheme', b'https'), (b':authority', b'localhost'),
            (b':path', path), (b'user-agent', b'aioquic-test'), (b'accept', b'*/*'), *extra]

def resp_headers(status=b'200', extra=()):
    return [(b':status', status), (b'server', b'aioquic-test'), (b'content-type', b'text/plain'), *extra]

def h3_basic():
    sim.mark('GET and POST with trailers, QPACK dynamic table (encoder and decoder streams), several requests, parallel streams')
    p = H3Pair(sim)
    p.pump(timers=True)
    s1 = p.request(req_headers(b'/index.html', extra=[(b'cookie', b'session=abcdef0123456789'), (b'x-custom', b'value-one')]))
    p.pump()
    for e in p.take('s', HeadersReceived):
        p.sh.send_headers(e.stream_id, resp_headers(extra=[(b'set-cookie', b'a=b; Path=/'), (b'x-custom', b'value-one')]))
        p.sh.send_data(e.stream_id, b'<html>hello world</html>', end_stream=False)
        p.sh.send_headers(e.stream_id, [(b'x-trailer', b'done')], end_stream=True)
    p.pump()
    # same headers again: dynamic table references
    streams = []
    for i in range(4):
        streams.append(p.request(req_headers(b'/item/%d' % i, extra=[(b'cookie', b'session=abcdef0123456789'), (b'x-custom', b'value-one')])))
    p.pump()
    for e in p.take('s', HeadersReceived):
        p.sh.send_headers(e.stream_id, resp_headers(extra=[(b'x-custom', b'value-one')]))
    p.pump()
    for st in reversed(streams):
        p.sh.send_data(st, b'item body %d' % st, end_stream=True)
    p.pump()
    # POST with a body in several DATA frames and trailers
    sid = p.request(req_headers(b'/upload', b'POST', [(b'content-type', b'application/x-www-form-urlencoded'), (b'content-length', b'51')]), end=False)
    for i in range(3):
        p.ch.send_data(sid, b'field%d=value%d&' % (i, i) + b'x' * 3, end_stream=False)
        p.pump()
    p.ch.send_headers(sid, [(b'x-checksum', b'0123')], end_stream=True)
    p.pump()
    for e in p.take('s', HeadersReceived):
        pass
    p.sh.send_headers(sid, resp_headers(b'201'), end_stream=False)
    p.sh.send_data(sid, b'created', end_stream=True)
    p.pump()
    p.client.close(error_code=0x100)
    p.pump()
    return p

import zlib
import json
from capgen import pcap_with_secrets

def answer_all(p, status=b'200', body=None, extra=(), end=True):
    """Respond to every pending request on the server."""
    for e in p.take('s', HeadersReceived):
        p.sh.send_headers(e.stream_id, resp_headers(status, extra))
        if body is not None:
            p.sh.send_data(e.stream_id, body, end_stream=end)

def h3_content():
    sim.mark('response bodies: gzip, JSON, text, a large body over many packets (reassembly), a large POST')
    p = H3Pair(sim)
    p.pump(timers=True)
    gz = zlib.compressobj(wbits=31)
    gzbody = gz.compress(b'compressed response body ' * 20) + gz.flush()
    sid_gz = p.request(req_headers(b'/gzip', extra=[(b'accept-encoding', b'gzip, deflate')]))
    sid_js = p.request(req_headers(b'/data.json', extra=[(b'accept', b'application/json')]))
    sid_big = p.request(req_headers(b'/big.bin'))
    p.pump()
    p.take('s', HeadersReceived)
    p.sh.send_headers(sid_gz, resp_headers(extra=[(b'content-encoding', b'gzip'), (b'content-length', str(len(gzbody)).encode())]))
    p.sh.send_data(sid_gz, gzbody, end_stream=True)
    js = json.dumps({'name': 'aioquic', 'values': [1, 2, 3], 'nested': {'ok': True}}).encode()
    p.sh.send_headers(sid_js, [(b':status', b'200'), (b'content-type', b'application/json'), (b'content-length', str(len(js)).encode())])
    p.sh.send_data(sid_js, js, end_stream=True)
    big = bytes(range(256)) * 20
    p.sh.send_headers(sid_big, [(b':status', b'200'), (b'content-type', b'application/octet-stream'), (b'content-length', str(len(big)).encode())])
    for i in range(0, len(big), 1500):
        p.sh.send_data(sid_big, big[i:i + 1500], end_stream=(i + 1500 >= len(big)))
        p.pump()
    p.pump()
    up = bytes(reversed(range(256))) * 8
    sid = p.request(req_headers(b'/post', b'POST', [(b'content-type', b'application/octet-stream'), (b'content-length', str(len(up)).encode())]), body=up)
    p.pump()
    p.take('s', HeadersReceived)
    p.sh.send_headers(sid, resp_headers(b'204'), end_stream=True)
    p.pump()
    p.client.close(error_code=0x100)
    p.pump()
    return p

def h3_push_ctrl():
    sim.mark('server push, PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID, GOAWAY, PRIORITY_UPDATE, reserved frame and stream types')
    p = H3Pair(sim)
    p.pump(timers=True)
    sid = p.request(req_headers(b'/with-push'))
    p.pump()
    p.take('s', HeadersReceived)
    push_sid = p.sh.send_push_promise(sid, req_headers(b'/pushed.css'))
    p.sh.send_headers(sid, resp_headers(extra=[(b'link', b'</pushed.css>; rel=preload')]))
    p.sh.send_data(sid, b'main response', end_stream=True)
    p.sh.send_headers(push_sid, [(b':status', b'200'), (b'content-type', b'text/css')])
    p.sh.send_data(push_sid, b'body { color: red }', end_stream=True)
    p.pump()
    ctl = p.ch._local_control_stream_id
    q = p.client
    q.send_stream_data(ctl, frame(0xd, v(16)))                        # MAX_PUSH_ID
    q.send_stream_data(ctl, frame(0x21, b'grease'))                    # reserved frame type
    q.send_stream_data(ctl, frame(0x1f * 7 + 0x21, b''))               # reserved, longer type
    q.send_stream_data(ctl, frame(0xf0700, v(sid) + b'u=2, i'))        # PRIORITY_UPDATE (request)
    q.send_stream_data(ctl, frame(0xf0701, v(1) + b'u=5'))             # PRIORITY_UPDATE (push)
    p.pump()
    sctl = p.sh._local_control_stream_id
    p.server.send_stream_data(sctl, frame(0x3, v(1)))                  # CANCEL_PUSH
    p.server.send_stream_data(sctl, frame(0x21, b'x' * 20))
    p.pump()
    # unknown unidirectional stream types: reserved and unassigned
    q.send_stream_data(q.get_next_available_stream_id(is_unidirectional=True), v(0x21) + b'unknown stream payload', end_stream=True)
    q.send_stream_data(q.get_next_available_stream_id(is_unidirectional=True), v(0x1f * 3 + 0x21) + b'grease stream')
    q.send_stream_data(q.get_next_available_stream_id(is_unidirectional=True), v(0x77) + b'unassigned type')
    p.pump()
    # request stream with a reserved frame type before the HEADERS
    rsid = q.get_next_available_stream_id()
    hdrs = p.ch._encode_headers(rsid, req_headers(b'/grease-frame'))
    q.send_stream_data(rsid, frame(0x21, b'reserved frame') + frame(1, hdrs) + frame(0x40, b'unknown frame'), end_stream=True)
    p.pump()
    p.server.send_stream_data(sctl, frame(0x7, v(rsid + 4)))           # GOAWAY
    p.pump()
    q.send_stream_data(ctl, frame(0x7, v(2)))                          # GOAWAY from the client (push ID)
    p.pump()
    p.client.close(error_code=0x100)
    p.pump()
    return p

def h3_reset():
    sim.mark('streams reset in the middle of a response and of a request, STOP_SENDING, interim response')
    p = H3Pair(sim)
    p.pump(timers=True)
    sid1 = p.request(req_headers(b'/reset-response'))
    sid2 = p.request(req_headers(b'/stop-sending'))
    sid3 = p.request(req_headers(b'/post-reset', b'POST'), body=b'partial request body', end=False)
    p.pump()
    p.take('s', HeadersReceived)
    p.sh.send_headers(sid1, [(b':status', b'103'), (b'link', b'</style.css>; rel=preload')])
    p.sh.send_headers(sid1, resp_headers(extra=[(b'content-length', b'100000')]))
    p.sh.send_data(sid1, b'first part of a response that never finishes', end_stream=False)
    p.pump()
    p.server.reset_stream(sid1, 0x10c)         # H3_REQUEST_CANCELLED
    p.client.stop_stream(sid2, 0x10c)
    p.client.reset_stream(sid3, 0x10c)
    p.pump()
    # a server-initiated bidirectional stream: HTTP/3 does not use them (the client closes the connection)
    p.server.send_stream_data(p.server.get_next_available_stream_id(), b'\x01\x00 server initiated bidirectional stream data')
    p.pump()
    p.client.close(error_code=0x100)
    p.pump()
    return p

class H3Settings(H3Connection):
    TABLE = 0
    EXTRA = {}
    def _get_local_settings(self):
        st = super()._get_local_settings()
        st[Setting.QPACK_MAX_TABLE_CAPACITY] = self.TABLE
        st.update(self.EXTRA)
        return st

class H3Static(H3Settings):
    TABLE = 0
    EXTRA = {0x6: 16384, 0x4242: 7, 0xffd277: 1}

class H3Tiny(H3Settings):
    TABLE = 256

def h3_qpack_variants():
    sim.mark('QPACK without a dynamic table (capacity 0) and with a tiny one (evictions, duplicates), MAX_FIELD_SECTION_SIZE, unknown settings')
    for cls in (H3Static, H3Tiny):
        p = H3Pair(sim, h3cls=cls)
        p.pump(timers=True)
        rounds = 6 if cls is H3Static else 14
        for i in range(rounds):
            p.request(req_headers(b'/q/%d' % i, extra=[(b'x-repeated', b'same value every time'), (b'x-seq', b'value-%d-' % (i % 5) + b'z' * (30 * (i % 5))),
                                                       (b'authorization', b'Bearer ' + b'tok%d' % i * 4), (b'cookie', b'k=%d' % i)]))
            p.pump()
        p.pump()
        for e in p.take('s', HeadersReceived):
            p.sh.send_headers(e.stream_id, resp_headers(extra=[(b'x-repeated', b'same value every time'), (b'x-long', b'L' * 300)]), end_stream=True)
        p.pump()
        p.client.close(error_code=0x100)
        p.pump()
    return p

def h3_webtransport():
    sim.mark('extended CONNECT (WebTransport), H3 datagrams, WebTransport streams')
    mdf = dict(max_datagram_frame_size=1200)
    p = H3Pair(sim, wt=True, ccfg_kw=mdf, scfg_kw=mdf)
    p.pump(timers=True)
    sid = p.request([(b':method', b'CONNECT'), (b':scheme', b'https'), (b':authority', b'localhost'),
                     (b':path', b'/wt'), (b':protocol', b'webtransport'), (b'origin', b'https://localhost')], end=False)
    p.pump()
    p.take('s', HeadersReceived)
    p.sh.send_headers(sid, [(b':status', b'200'), (b'sec-webtransport-http3-draft', b'draft02')])
    p.pump()
    p.ch.send_datagram(sid, b'h3 datagram from the client')
    p.sh.send_datagram(sid, b'h3 datagram from the server')
    p.pump()
    ws = p.ch.create_webtransport_stream(sid)
    p.client.send_stream_data(ws, b'webtransport bidirectional stream data', end_stream=True)
    wu = p.ch.create_webtransport_stream(sid, is_unidirectional=True)
    p.client.send_stream_data(wu, b'webtransport unidirectional', end_stream=True)
    su = p.sh.create_webtransport_stream(sid, is_unidirectional=True)
    p.server.send_stream_data(su, b'server unidirectional', end_stream=True)
    p.pump()
    p.client.close(error_code=0x100)
    p.pump()
    return p

def ws_frame(payload, masked, opcode=1):
    n = len(payload)
    assert n < 126
    if not masked:
        return bytes([0x80 | opcode, n]) + payload
    key = bytes([0x37, 0xfa, 0x21, 0x3d])
    return bytes([0x80 | opcode, 0x80 | n]) + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))

def h3_connect():
    sim.mark('CONNECT tunnel and extended CONNECT with :protocol websocket (WebSocket frames in DATA)')
    p = H3Pair(sim)
    p.pump(timers=True)
    s1 = p.request([(b':method', b'CONNECT'), (b':authority', b'tunnel.example.net:443')], end=False)
    p.pump()
    p.take('s', HeadersReceived)
    p.sh.send_headers(s1, [(b':status', b'200')])
    p.ch.send_data(s1, b'tunneled client bytes', end_stream=False)
    p.pump()
    p.sh.send_data(s1, b'tunneled server bytes', end_stream=False)
    p.pump()
    s2 = p.request([(b':method', b'CONNECT'), (b':scheme', b'https'), (b':authority', b'localhost'), (b':path', b'/chat'),
                    (b':protocol', b'websocket'), (b'sec-websocket-version', b'13'), (b'origin', b'https://localhost')], end=False)
    p.pump()
    p.take('s', HeadersReceived)
    p.sh.send_headers(s2, [(b':status', b'200'), (b'sec-websocket-protocol', b'chat')])
    p.pump()
    p.ch.send_data(s2, ws_frame(b'hello websocket', True), end_stream=False)
    p.pump()
    p.sh.send_data(s2, ws_frame(b'reply from the server', False), end_stream=False)
    p.pump()
    p.ch.send_data(s2, ws_frame(b'\x03\xe8bye', True, 8), end_stream=True)
    p.sh.send_data(s2, ws_frame(b'\x03\xe8', False, 8), end_stream=True)
    p.pump()
    p.client.close(error_code=0x100)
    p.pump()
    return p

SCENARIOS = [h3_basic, h3_content, h3_push_ctrl, h3_reset, h3_qpack_variants, h3_webtransport, h3_connect]
for f in SCENARIOS:
    try:
        f()
    except Exception as e:
        import traceback; traceback.print_exc()
        print('SCENARIO FAILED', f.__name__, e)

main_marks = sim.marks
sim.write_pcap(os.path.join(out, 'http3-decrypt.pcap'))
sim.keylog.close()

# The pcapng file with the key log in a Decryption Secrets Block.
pcap_with_secrets(os.path.join(out, 'http3-decrypt.pcap'), os.path.join(out, 'http3-decrypt.keys'),
                  os.path.join(out, 'http3-decrypt.pcapng'))
os.unlink(os.path.join(out, 'http3-decrypt.pcap'))
os.unlink(os.path.join(out, 'http3-decrypt.keys'))
main_count = len(sim.frames)

# ---- second capture (coverage only, not committed): malformed QPACK instructions and frames,
# written to streams with aioquic's API (packets protected by aioquic)
sim = Sim(os.path.join(out, 'http3-decrypt-malformed.keys'))

def inject(label, who, stream, data, end=False):
    sim.mark(label)
    p = H3Pair(sim)
    p.pump(timers=True)
    if who == 'enc':      # the server's QPACK encoder stream
        p.server.send_stream_data(p.sh._local_encoder_stream_id, data)
    elif who == 'dec':    # the client's QPACK decoder stream
        p.client.send_stream_data(p.ch._local_decoder_stream_id, data)
    elif who == 'cenc':   # the client's QPACK encoder stream
        p.client.send_stream_data(p.ch._local_encoder_stream_id, data)
    elif who == 'sdec':   # the server's QPACK decoder stream
        p.server.send_stream_data(p.sh._local_decoder_stream_id, data)
    elif who == 'creq':   # a client request stream
        p.client.send_stream_data(p.client.get_next_available_stream_id(), data, end_stream=end)
    elif who == 'sctl':
        p.server.send_stream_data(p.sh._local_control_stream_id, data)
    elif who == 'cctl':
        p.client.send_stream_data(p.ch._local_control_stream_id, data)
    p.pump()
    return p

big = b'\xff' * 11 + b'\x01'
def malformed():
    for who in ('enc', 'cenc'):
        inject('QPACK encoder stream: insert with name reference, invalid Huffman value', who, 0, b'\xc1\x83\xff\xff\xff')
        inject('QPACK encoder stream: insert with literal name, invalid Huffman name and value', who, 0, b'\x63\xff\xff\xff\x83\xff\xff\xff')
        inject('QPACK encoder stream: set capacity with an oversized integer', who, 0, b'\x3f' + big)
        inject('QPACK encoder stream: duplicate with an oversized integer', who, 0, b'\x1f' + big)
        inject('QPACK encoder stream: name reference with an oversized integer', who, 0, b'\xff' + big + b'\x01a')
        inject('QPACK encoder stream: literal name with an oversized length', who, 0, b'\x5f' + big)
        inject('QPACK encoder stream: truncated insert', who, 0, b'\x45abc')
        inject('QPACK encoder stream: huge value length', who, 0, b'\xc1\x7f' + big)
    for who in ('dec', 'sdec'):
        inject('QPACK decoder stream: section acknowledgement with an oversized integer', who, 0, b'\xff' + big)
        inject('QPACK decoder stream: stream cancellation with an oversized integer', who, 0, b'\x7f' + big)
        inject('QPACK decoder stream: insert count increment with an oversized integer', who, 0, b'\x3f' + big)
        inject('QPACK decoder stream: valid instructions', who, 0, b'\x81\x42\x05')
    inject('request stream: HEADERS with garbage QPACK data', 'creq', 0, frame(1, bytes(range(40, 80))))
    inject('request stream: HEADERS that needs a dynamic table entry that does not exist', 'creq', 0, frame(1, b'\x05\x00\x80'))
    inject('request stream: HEADERS with an invalid Huffman value', 'creq', 0, frame(1, b'\x00\x00\xd1\x23\xff\xff\xff\x00'))
    inject('request stream: truncated frame', 'creq', 0, v(1) + v(300) + b'abc')
    inject('request stream: huge frame length', 'creq', 0, v(1) + b'\xff' * 8)
    inject('control stream: oversized SETTINGS', 'cctl', 0, frame(0x4, b'\x01' + b'\xff' * 9))
    inject('control stream: truncated SETTINGS', 'cctl', 0, frame(0x4, b'\x01\x40'))
    inject('control stream: second SETTINGS', 'cctl', 0, frame(0x4, b''))
    inject('control stream: GOAWAY with a bad length', 'sctl', 0, frame(0x7, b'\x40'))
    inject('control stream: PRIORITY_UPDATE too short', 'cctl', 0, frame(0xf0700, b''))
    inject('control stream: data frame on the control stream', 'cctl', 0, frame(0x0, b'data'))
malformed()
sim.write_pcap(os.path.join(out, 'http3-decrypt-malformed.pcap'))
sim.keylog.close()

# The pcapng file with the key log in a Decryption Secrets Block.
pcap_with_secrets(os.path.join(out, 'http3-decrypt-malformed.pcap'), os.path.join(out, 'http3-decrypt-malformed.keys'),
                  os.path.join(out, 'http3-decrypt-malformed.pcapng'))
os.unlink(os.path.join(out, 'http3-decrypt-malformed.pcap'))
os.unlink(os.path.join(out, 'http3-decrypt-malformed.keys'))
n_malformed = len(sim.frames)

# ---- reproducer: a QPACK decoder stream instruction whose prefixed integer cannot be decoded
# (packet-http3.c leaves a TRY block with `break`, see README); one connection
sim = Sim(os.path.join(out, 'http3-repro-decoder-break.keys'))
inject('QPACK decoder stream: stream cancellation with an oversized integer', 'dec', 0, b'\x7f' + big)
sim.write_pcap(os.path.join(out, 'http3-repro-decoder-break.pcap'))
sim.keylog.close()

# The pcapng file with the key log in a Decryption Secrets Block.
pcap_with_secrets(os.path.join(out, 'http3-repro-decoder-break.pcap'), os.path.join(out, 'http3-repro-decoder-break.keys'),
                  os.path.join(out, 'http3-repro-decoder-break.pcapng'))
os.unlink(os.path.join(out, 'http3-repro-decoder-break.pcap'))
os.unlink(os.path.join(out, 'http3-repro-decoder-break.keys'))
if '-v' in sys.argv:
    for n, t in main_marks:
        print(n, t)
print(main_count, 'frames in the main capture,', n_malformed, 'in the malformed one,', len(sim.frames), 'in the reproducer')
