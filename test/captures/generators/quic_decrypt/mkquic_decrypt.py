#!/usr/bin/env python3
# Generates test/captures/quic_decrypt_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator for quic_decrypt_coverage.pcapng: real QUIC traffic from aioquic,
exchanged in memory and written as IPv4/UDP over 127.0.0.1.
Usage: mkquic_decrypt.py <outdir> [-v]   (run with the aioquic venv python)
Writes quic-decrypt.pcapng (and the -malformed one), with the TLS key log in a
Decryption Secrets Block. The keys are random, so every run differs."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))



import struct
from qsim import Buffer, encode_quic_version_negotiation, Pair, pull_quic_header, Sim, XConn
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import *
from aioquic.tls import CipherSuite
from aioquic.quic.packet import QuicProtocolVersion
from capgen import pcap_with_secrets

ALPN = ['quic-test']
out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
sim = Sim(os.path.join(out, 'quic-decrypt.keys'))
port = [4436]
def addrs(n=None):
    port[0] += 1
    return ('127.0.0.1', 50000 + port[0]), ('127.0.0.1', port[0])

def handshake(p, **kw):
    p.pump(timers=True)
    assert p.client._handshake_complete if hasattr(p.client, '_handshake_complete') else True
    return p

def sc1():
    '''Core connection: transport parameters, streams, FIN, PING, DATAGRAM, resets, key updates, close.'''
    sim.mark('core: v1, AES-128, transport parameters, streams, ping, datagram, resets, key updates, app close')
    c, s = addrs()
    p = Pair(sim, sim.ccfg(ALPN, idle_timeout=30.0, max_data=200000, max_stream_data=50000,
                           max_datagram_frame_size=1200, cipher_suites=[CipherSuite.AES_128_GCM_SHA256]),
             sim.scfg(ALPN, idle_timeout=40.0, max_data=300000, max_stream_data=60000,
                      max_datagram_frame_size=1000, cipher_suites=[CipherSuite.AES_128_GCM_SHA256]), c, s)
    p.pump(timers=True)
    cl, sv = p.client, p.server
    sid = cl.get_next_available_stream_id()
    cl.send_stream_data(sid, b'hello ' * 20)
    p.pump()
    cl.send_stream_data(sid, b'world ' * 20, end_stream=True)
    sv.send_stream_data(sid, b'reply one', end_stream=False)
    p.pump()
    sv.send_stream_data(sid, b' and two', end_stream=True)
    uni = sv.get_next_available_stream_id(is_unidirectional=True)
    sv.send_stream_data(uni, b'server push-like uni stream', end_stream=True)
    cl.send_ping(1); sv.send_ping(2)
    cl.send_datagram_frame(b'datagram from client')
    sv.send_datagram_frame(b'datagram from server')
    p.pump()
    # key update twice
    cl.request_key_update()
    cl.send_stream_data(cl.get_next_available_stream_id(), b'after key update 1', end_stream=True)
    p.pump()
    sv.request_key_update()
    sv.send_stream_data(uni + 4, b'after key update 2', end_stream=True)
    p.pump()
    cl.request_key_update()
    cl.send_ping(3)
    p.pump()
    # reset and stop
    s2 = cl.get_next_available_stream_id()
    cl.send_stream_data(s2, b'to be reset ' * 10)
    p.pump()
    cl.reset_stream(s2, 0x1234)
    s3 = cl.get_next_available_stream_id()
    cl.send_stream_data(s3, b'stop sending me ' * 5)
    p.pump()
    sv.stop_stream(s3, 0x77)
    p.pump()
    cl.change_connection_id()
    cl.send_ping(4)
    p.pump()
    sv.change_connection_id()
    sv.send_ping(5)
    p.pump()
    cl.close(error_code=0x101, reason_phrase='application bye')
    p.pump()
    return p


def varint(v):
    b = Buffer(capacity=8)
    b.push_uint_var(v)
    return b.data

def tp(pid, value):
    return varint(pid) + varint(len(value)) + value

def extra_params(conn, raw):
    """Append raw transport parameters (the TLS extension content, before aioquic protects it)."""
    orig = conn._serialize_transport_parameters
    conn._serialize_transport_parameters = lambda: orig() + raw

def cert_chain(scfg, n):
    scfg.certificate_chain = [sim.cert] * n

def sc2():
    sim.mark('ChaCha20, CRYPTO split over packets (large ClientHello and certificate chain), out of order handshake')
    c, s = addrs()
    cc = sim.ccfg(ALPN, cipher_suites=[CipherSuite.CHACHA20_POLY1305_SHA256], quantum_readiness_test=True)
    sc = sim.scfg(ALPN, cipher_suites=[CipherSuite.CHACHA20_POLY1305_SHA256])
    cert_chain(sc, 6)
    p = Pair(sim, cc, sc, c, s)
    def pol(d, n, data):
        if d == 's' and n in (2, 3, 4):
            return 'hold'
        return 'ok'
    p.policy = pol
    p.pump(timers=False)
    p.release(list(reversed(range(len(p.held)))))
    p.policy = None
    p.pump(timers=True)
    sid = p.client.get_next_available_stream_id()
    p.client.send_stream_data(sid, b'chacha stream data', end_stream=True)
    p.pump(timers=True)
    p.client.close()
    p.pump()
    return p

def mqtt_connect(client_id):
    vh = b'\x00\x04MQTT\x04\x02\x00\x3c' + struct.pack('!H', len(client_id)) + client_id.encode()
    return b'\x10' + bytes([len(vh)]) + vh

def mqtt_publish(topic, payload):
    body = struct.pack('!H', len(topic)) + topic.encode() + payload
    n = len(body)
    rl = b''
    while True:
        d = n % 128
        n //= 128
        rl += bytes([d | (0x80 if n else 0)])
        if not n:
            break
    return b'\x30' + rl + body

def sc3():
    sim.mark('MQTT on AES-256: messages split over STREAM frames; out of order, duplicated, overlapping and retransmitted data, ACK ranges, large stream')
    c, s = addrs()
    A = ['mqtt']
    p = Pair(sim, sim.ccfg(A, cipher_suites=[CipherSuite.AES_256_GCM_SHA384]),
             sim.scfg(A, cipher_suites=[CipherSuite.AES_256_GCM_SHA384]), c, s, cls=XConn)
    p.pump(timers=True)
    cl, sv = p.client, p.server
    # out of order: one message in six pieces, held, delivered in another order
    sid = cl.get_next_available_stream_id()
    q = mqtt_connect('ooo-client') + mqtt_publish('t/ooo', b'first message, out of order pieces')
    cuts = [0, 9, 18, 27, 36, 45, len(q)]
    p.policy = lambda d, n, data: 'hold' if d == 'c' else 'ok'
    for i in range(6):
        cl.send_stream_data(sid, q[cuts[i]:cuts[i + 1]], end_stream=False)
        p.pump()
    p.release([3, 1, 0, 4, 5, 2])
    p.policy = None
    p.pump(timers=True)
    # in order but split: reassembled by the MQTT dissector
    q = mqtt_publish('t/split', b'second message in order, split into small pieces')
    for i in range(0, len(q), 12):
        cl.send_stream_data(sid, q[i:i + 12])
        p.pump()
    # drops: gaps in ACKs and retransmissions
    q = mqtt_publish('t/drop', b'third message with dropped datagrams' * 2)
    p.policy = lambda d, n, data: 'drop' if (d == 'c' and n % 2 == 0) else 'ok'
    for i in range(0, len(q), 10):
        cl.send_stream_data(sid, q[i:i + 10])
        p.pump()
    p.policy = None
    p.pump(timers=True)
    # duplicates
    p.policy = lambda d, n, data: 'dup'
    cl.send_stream_data(sid, mqtt_publish('t/dup', b'duplicated datagram'))
    p.pump()
    p.policy = None
    # PDUs that start and end inside STREAM frames: several PDUs in one frame, PDUs split over frames
    msgs = [mqtt_publish('t/m%d' % i, b'm%d-' % i * (4 + 5 * i)) for i in range(5)]
    blob = b''.join(msgs)
    n = 0
    for size in (29, 31, 47, 23, 61, 1000):
        if n >= len(blob):
            break
        cl.send_stream_data(sid, blob[n:n + size])
        n += size
        p.pump()
    # overlap: data delivered but its ACK lost, the next data dropped; after the timeout both
    # go out again in one frame that overlaps what was already received
    pm = mqtt_publish('t/overlap', b'overlapping retransmission test' * 2)
    p.policy = lambda d, n, data: 'drop' if d == 's' else 'ok'
    cl.send_stream_data(sid, pm[:13])
    p.pump()
    p.policy = lambda d, n, data: 'drop'
    cl.send_stream_data(sid, pm[13:])
    p.pump()
    p.policy = None
    p.pump(timers=True, quiet_rounds=8)
    # STREAM frames that overlap data already received (injected with aioquic's packet builder)
    nsid = cl.get_next_available_stream_id()
    m = mqtt_publish('t/overlap2', b'overlapping STREAM frames, partly new data')
    cl.send_stream_data(nsid, m[:20])
    p.pump()
    cl.extra = [(0x0e, varint(nsid) + varint(10) + varint(30) + m[10:40])]
    p.pump()
    cl.extra = [(0x0f, varint(nsid) + varint(30) + varint(len(m) - 30) + m[30:])]
    p.pump()
    # one large message from the server over many packets
    sv.send_stream_data(sid, mqtt_publish('t/big', bytes(range(256)) * 12), end_stream=False)
    p.pump(timers=True)
    cl.send_stream_data(sid, b'', end_stream=True)
    p.pump(timers=True)
    cl.close(error_code=0)
    p.pump()
    return p

def sc15():
    sim.mark('lost handshake datagrams and ACKs: CRYPTO retransmitted and overlapping')
    c, s = addrs()
    sc = sim.scfg(ALPN)
    cert_chain(sc, 5)
    p = Pair(sim, sim.ccfg(ALPN), sc, c, s)
    p.policy = lambda d, n, data: 'drop' if ((d == 's' and n == 2) or (d == 'c' and 2 <= n <= 3)) else 'ok'
    p.pump(timers=True, quiet_rounds=10)
    p.policy = None
    p.pump(timers=True, quiet_rounds=10)
    p.client.close()
    p.pump()
    return p

def sc4():
    sim.mark('QUIC version 2, ALPN h3-32 (alias of h3), key update')
    c, s = addrs()
    A = ['h3-32']
    cc = sim.ccfg(A, supported_versions=[QuicProtocolVersion.VERSION_2])
    sc = sim.scfg(A, supported_versions=[QuicProtocolVersion.VERSION_2])
    p = Pair(sim, cc, sc, c, s)
    p.pump(timers=True)
    p.client.send_stream_data(p.client.get_next_available_stream_id(is_unidirectional=True), b'\x00\x04\x00')
    sid = p.client.get_next_available_stream_id()
    p.client.send_stream_data(sid, b'\x01\x00', end_stream=True)
    p.client.send_ping(9)
    p.pump(timers=True)
    p.client.request_key_update()
    p.client.send_ping(10)
    p.pump(timers=True)
    p.client.close()
    p.pump()
    return p

def sc5():
    sim.mark('compatible version negotiation: v1 Initial, v2 handshake')
    c, s = addrs()
    cc = sim.ccfg(ALPN, supported_versions=[QuicProtocolVersion.VERSION_2, QuicProtocolVersion.VERSION_1],
                  original_version=QuicProtocolVersion.VERSION_1)
    sc = sim.scfg(ALPN)
    p = Pair(sim, cc, sc, c, s)
    p.pump(timers=True)
    sid = p.client.get_next_available_stream_id()
    p.client.send_stream_data(sid, b'compatible vn', end_stream=True)
    p.pump(timers=True)
    p.client.close()
    p.pump()
    return p

def sc6():
    sim.mark('Retry (v1) and the client Initial that answers it')
    c, s = addrs()
    # aioquic restarts TLS (a new ClientHello random) after a Retry, so the secrets in the key log
    # belong to the second ClientHello that Wireshark does not use: the handshake after the Retry
    # is not decryptable and the flow stops with the client's second Initial.
    p = Pair(sim, sim.ccfg(ALPN), sim.scfg(ALPN), c, s, retry=True)
    p.pump(rounds=1)
    for data, addr in p.client.datagrams_to_send(now=sim.t):     # the Initial that carries the token
        sim.record(p.caddr, p.saddr, data)
    return p

def sc6b():
    sim.mark('Retry (v2) and the client Initial that answers it')
    c, s = addrs()
    v2 = [QuicProtocolVersion.VERSION_2]
    p = Pair(sim, sim.ccfg(ALPN, supported_versions=v2), sim.scfg(ALPN, supported_versions=v2), c, s, retry=True)
    p.pump(rounds=1)
    for data, addr in p.client.datagrams_to_send(now=sim.t):
        sim.record(p.caddr, p.saddr, data)
    return p

def sc7():
    sim.mark('Version negotiation, then v1')
    c, s = addrs()
    cc = sim.ccfg(ALPN, supported_versions=[0x1a2a3a4a, QuicProtocolVersion.VERSION_1])
    sc = sim.scfg(ALPN)
    p = Pair(sim, cc, sc, c, s)
    # server side answers VN for the unknown first version
    data = p.client.datagrams_to_send(now=sim.t)[0][0]
    hdr = pull_quic_header(Buffer(data=data), host_cid_length=8)
    sim.record(p.caddr, p.saddr, data)
    vn = encode_quic_version_negotiation(source_cid=hdr.destination_cid, destination_cid=hdr.source_cid,
                                         supported_versions=[QuicProtocolVersion.VERSION_1, QuicProtocolVersion.VERSION_2, 0x0a0a0a0a])
    sim.record(p.saddr, p.caddr, vn)
    p.client.receive_datagram(vn, p.saddr, now=sim.t)
    p.pump(timers=True)
    p.client.close()
    p.pump()
    return p

TICKETS = []
def dns_query(name, ident=0, qtype=1):
    q = b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', qtype, 1)

def dns_response(query):
    return query[:2] + b'\x81\x80' + query[4:6] + b'\x00\x01\x00\x00\x00\x00' + query[12:] + \
        b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01'

def doq(msg):
    return struct.pack('!H', len(msg)) + msg

def sc8():
    sim.mark('connection with session ticket, then resumption with 0-RTT early data (ALPN doq-i03)')
    ALPN = ['doq-i03']
    c, s = addrs()
    store = {}
    def handler(t):
        TICKETS.append(t); store[t.ticket] = t
    def fetcher(ticket):
        return store.get(ticket)
    p = Pair(sim, sim.ccfg(ALPN), sim.scfg(ALPN), c, s, ticket_handler=handler,
             ticket_fetcher=fetcher, ctor_kw=dict(session_ticket_handler=handler))
    p.pump(timers=True)
    p.client.close()
    p.pump()
    c, s = addrs()
    cc = sim.ccfg(ALPN)
    cc.session_ticket = TICKETS[-1]
    p = Pair(sim, cc, sim.scfg(ALPN), c, s, ticket_handler=handler, ticket_fetcher=fetcher,
             ctor_kw=dict(session_ticket_handler=handler))
    sid = p.client.get_next_available_stream_id()
    p.client.send_stream_data(sid, doq(dns_query('early.example.net', 7)), end_stream=True)
    p.pump(timers=True)
    p.server.send_stream_data(sid, doq(dns_response(dns_query('early.example.net', 7))), end_stream=True)
    sid2 = p.client.get_next_available_stream_id()
    p.client.send_stream_data(sid2, doq(dns_query('later.example.net', 8)), end_stream=True)
    p.pump(timers=True)
    p.server.send_stream_data(sid2, doq(dns_response(dns_query('later.example.net', 8))), end_stream=True)
    p.pump(timers=True)
    p.client.close()
    p.pump()
    return p

def sc9():
    sim.mark('connection migration: client moves to a new port, PATH_CHALLENGE/PATH_RESPONSE, NEW_CONNECTION_ID')
    c, s = addrs()
    p = Pair(sim, sim.ccfg(ALPN), sim.scfg(ALPN), c, s)
    p.pump(timers=True)
    cl = p.client
    sid = cl.get_next_available_stream_id()
    cl.send_stream_data(sid, b'before migration')
    p.pump(timers=True)
    cl.change_connection_id()
    p.pump(timers=True)
    p.caddr = ('127.0.0.1', c[1] + 1000)
    cl.send_stream_data(sid, b' after migration', end_stream=True)
    p.pump(timers=True)
    cl.send_ping(7)
    p.pump(timers=True)
    cl.close()
    p.pump()
    return p

def sc10():
    sim.mark('flow control: blocked frames, MAX_DATA, MAX_STREAM_DATA, many streams, MAX_STREAMS')
    c, s = addrs()
    p = Pair(sim, sim.ccfg(ALPN), sim.scfg(ALPN, max_data=4000, max_stream_data=2500), c, s)
    p.pump(timers=True)
    cl, sv = p.client, p.server
    sid = cl.get_next_available_stream_id()
    cl.send_stream_data(sid, bytes(range(200)) * 30, end_stream=True)
    p.pump(timers=True)
    # drain at the server so that MAX_DATA / MAX_STREAM_DATA are raised
    for _ in range(4):
        p.pump(timers=True)
    # more streams than the limit
    for i in range(135):
        cl.send_stream_data(cl.get_next_available_stream_id(), b'x', end_stream=True)
    p.pump(timers=True)
    for _ in range(3):
        p.pump(timers=True)
    cl.close()
    p.pump()
    return p

def sc11():
    sim.mark('ALPN roq-09 with a DATAGRAM, transport CONNECTION_CLOSE with a TLS alert error code, frame type and reason')
    c, s = addrs()
    A = ['roq-09']
    p = Pair(sim, sim.ccfg(A, max_datagram_frame_size=1200), sim.scfg(A, max_datagram_frame_size=1200), c, s)
    p.pump(timers=True)
    p.client.send_datagram_frame(b'\x00' + b'rtp-over-quic datagram')
    p.pump(timers=True)
    p.server.close(error_code=0x128, frame_type=0x06, reason_phrase='TLS alert handshake_failure')
    p.pump()
    return p

def sc12():
    sim.mark('frames aioquic never sends (NEW_TOKEN, MAX_STREAMS, blocked frames, ACK_ECN, ACK_FREQUENCY, observed address, multipath, unknown), each in its own packet')
    c, s = addrs()
    mdf = dict(max_datagram_frame_size=1200)
    p = Pair(sim, sim.ccfg(ALPN, **mdf), sim.scfg(ALPN, **mdf), c, s, cls=XConn)
    p.pump(timers=True)
    cl, sv = p.client, p.server
    v = varint
    cid = bytes(range(1, 9))
    sid = cl.get_next_available_stream_id()
    cl.send_stream_data(sid, b'x')
    p.pump()
    ok = [
        (0x07, v(16) + bytes(range(16))),                          # NEW_TOKEN (server to client)
        (0x12, v(200)), (0x13, v(300)),                            # MAX_STREAMS bidi, uni
        (0x14, v(5000)), (0x15, v(sid) + v(70000)),                # DATA_BLOCKED, STREAM_DATA_BLOCKED
        (0x16, v(129)), (0x17, v(130)),                            # STREAMS_BLOCKED
        (0x03, v(1) + v(5) + v(0) + v(0) + v(2) + v(1) + v(0)),    # ACK_ECN
    ]
    ok += [
        (0x30, b'DATAGRAM frame that runs to the end of the packet'),
        (0x08, v(1) + b'no length, no offset'), (0x09, v(5) + b'fin, no length'),      # STREAM without a length
        (0x0c, v(9) + v(0) + b'offset, no length'), (0x0d, v(13) + v(0) + b'offset and fin'),
    ]
    for ft, pl in ok:
        sv.extra = [(ft, pl)]
        p.pump()
    # one packet with frames the aioquic peer rejects (it closes the connection at the first)
    bad = [
        (0x1f, b''), (0xac, b''),                                  # IMMEDIATE_ACK (final, draft 05)
        (0xaf, v(1) + v(2) + v(25000) + v(3)),                     # ACK_FREQUENCY
        (0x2f5, v(123456)),                                        # TIME_STAMP
        (0x9f81a6, v(1) + bytes([127, 0, 0, 1]) + struct.pack('!H', 4440)),            # OBSERVED_ADDRESS v4
        (0x9f81a7, v(2) + bytes(15) + b'\x01' + struct.pack('!H', 4441)),              # v6
        (0x15228c00, v(1) + v(0) + v(0) + v(0) + v(0)),            # PATH_ACK
        (0x15228c01, v(1) + v(0) + v(0) + v(1) + v(0) + v(0) + v(1) + v(2) + v(1) + v(0)),       # PATH_ACK_ECN with a range
        (0x15228c05, v(1) + v(7)),                                 # PATH_ABANDON
        (0x15228c06, v(1) + v(2) + v(1)),                          # PATH_STATUS
        (0x15228c07, v(1) + v(3)), (0x15228c08, v(1) + v(4)),      # BACKUP/AVAILABLE
        (0x15228c09, v(1) + v(5) + v(0) + bytes([8]) + cid + bytes(16)),                # PATH_NEW_CONNECTION_ID
        (0x15228c0a, v(1) + v(5)),                                 # PATH_RETIRE_CONNECTION_ID
        (0x15228c0b, v(4)), (0x15228c0c, v(3)), (0x15228c0d, v(5)), (0x15228c0e, v(1) + v(9)),
        (0x3fff, b''),                                             # unknown frame type
    ]
    sv.extra = bad
    p.pump()
    cl.close()
    p.pump()
    return p

def sc13b():
    sim.mark('extra transport parameters (grease_quic_bit, loss bits, multipath, preferred address, min_ack_delay, time stamps, disable_active_migration), stateless reset')
    c, s = addrs()
    p = Pair(sim, sim.ccfg(ALPN), sim.scfg(ALPN), c, s, autostart=False)
    cl = p.client
    extra_params(cl, tp(0x2ab2, b'') + tp(0x1057, b'\x00') + tp(0x0f739bbc1b666d06, b'') + tp(0x0c, b'')
                 + tp(0xff04de1b, varint(1000)) + tp(0x7158, varint(3)) + tp(0x1000, bytes([4, 1])) + tp(0x3e, varint(3)))
    pa = (bytes([127, 0, 0, 2]) + struct.pack('!H', 4999) + bytes(16) + struct.pack('!H', 0) + bytes([8]) + bytes(range(50, 58)) + bytes(range(16)))
    # constructed after the server exists: patch the class-level hook through ctor
    orig = XConn._serialize_transport_parameters
    p.scfg  # config only
    p.cls = XConn
    class S(XConn):
        def _serialize_transport_parameters(self):
            return QuicConnection._serialize_transport_parameters(self) + tp(0x2ab2, b'') + tp(0x1057, b'\x01') \
                + tp(0x0f739bbc1b666d06, b'') + tp(0x0d, pa) + tp(0x3e, varint(5)) + tp(0x0f739bbc1b666d07, varint(2))
    p.cls = S
    p.start()
    p.pump(timers=True)
    sv = p.server
    cl.send_stream_data(cl.get_next_available_stream_id(), b'with loss bits', end_stream=True)
    p.pump(timers=True)
    # a stateless reset: unpredictable bits ending in the token the server announced
    token = sv._host_cids[0].stateless_reset_token
    sim.record(p.saddr, p.caddr, b'\x45' + bytes(range(100, 140)) + token)
    return p

SCENARIOS = [sc1, sc2, sc3, sc4, sc5, sc6, sc6b, sc7, sc8, sc9, sc10, sc11, sc12, sc13b, sc15]
for f in SCENARIOS:
    try:
        f()
    except Exception as e:
        import traceback; traceback.print_exc()
        print('SCENARIO FAILED', f.__name__, e)

sim.write_pcap(os.path.join(out, 'quic-decrypt.pcap'))
sim.keylog.close()

# The pcapng file with the key log in a Decryption Secrets Block.
pcap_with_secrets(os.path.join(out, 'quic-decrypt.pcap'), os.path.join(out, 'quic-decrypt.keys'),
                  os.path.join(out, 'quic-decrypt.pcapng'))
os.unlink(os.path.join(out, 'quic-decrypt.pcap'))
os.unlink(os.path.join(out, 'quic-decrypt.keys'))
main_marks = sim.marks
main_count = len(sim.frames)

# ---- second capture (coverage only, not committed): malformed frame contents, in packets built by aioquic
sim = Sim(os.path.join(out, 'quic-decrypt-malformed.keys'))

def bad_frame_conn(label, ft, payload, direction='s', alpn=ALPN):
    sim.mark(label)
    c, s = addrs()
    p = Pair(sim, sim.ccfg(alpn), sim.scfg(alpn), c, s, cls=XConn)
    p.pump(timers=True)
    (p.server if direction == 's' else p.client).extra = [(ft, payload)]
    p.pump()
    return p

def close_conn(label, who, **kw):
    sim.mark(label)
    c, s = addrs()
    p = Pair(sim, sim.ccfg(ALPN), sim.scfg(ALPN), c, s)
    p.pump(timers=True)
    getattr(p, who).close(**kw)
    p.pump()

v = varint
def malformed():
    bad_frame_conn('CRYPTO length past the end', 0x06, v(0) + v(100) + b'abc')
    bad_frame_conn('NEW_TOKEN length past the end', 0x07, v(50) + b'ab')
    bad_frame_conn('STREAM length past the end', 0x0a, v(3) + v(100) + b'ab')
    bad_frame_conn('STREAM offset + length beyond 32 bits', 0x0e, v(3) + v(0xfffffffe) + v(5) + b'abcde')
    bad_frame_conn('NEW_CONNECTION_ID with CID length 0', 0x18, v(9) + v(0) + bytes([0]) + bytes(16))
    bad_frame_conn('NEW_CONNECTION_ID with CID length 21', 0x18, v(9) + v(0) + bytes([21]) + bytes(21) + bytes(16))
    bad_frame_conn('CONNECTION_CLOSE reason past the end', 0x1c, v(0) + v(0) + v(50) + b'abc')
    bad_frame_conn('DATAGRAM with length past the end', 0x31, v(100) + b'ab')
    bad_frame_conn('DATAGRAM without a length and a stream frame without length', 0x30, b'datagram runs to the end')
    bad_frame_conn('STREAM_DATA_BLOCKED', 0x15, v(3) + v(77))
    bad_frame_conn('client sends NEW_TOKEN (protocol violation)', 0x07, v(4) + b'abcd', direction='c')
    close_conn('transport close with a private error code', 'server', error_code=0x4abc, frame_type=0x00, reason_phrase='private')
    close_conn('transport close, client, no reason', 'client', error_code=0x0a, frame_type=0x01, reason_phrase='')
    close_conn('application close with a long reason', 'client', error_code=0x1234, reason_phrase='x' * 120)
malformed()
sim.write_pcap(os.path.join(out, 'quic-decrypt-malformed.pcap'))
sim.keylog.close()

# The pcapng file with the key log in a Decryption Secrets Block.
pcap_with_secrets(os.path.join(out, 'quic-decrypt-malformed.pcap'), os.path.join(out, 'quic-decrypt-malformed.keys'),
                  os.path.join(out, 'quic-decrypt-malformed.pcapng'))
os.unlink(os.path.join(out, 'quic-decrypt-malformed.pcap'))
os.unlink(os.path.join(out, 'quic-decrypt-malformed.keys'))
if '-v' in sys.argv:
    for n, t in main_marks:
        print(n, t)
print(main_count, 'frames in the main capture,', len(sim.frames), 'in the malformed one')
