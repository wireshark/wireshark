#!/usr/bin/env python3
# Generates test/captures/tls_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the TLS dissector
(packet-tls.c): the record layer, handshake fragment reassembly in both
directions, TCP desegmentation of records, SSLv2 records, alerts,
heartbeats, the heuristics for TLS on other ports, STARTTLS, Exported
PDU frames (tls13-handshake, tls-echconfig) and the reproducers of the
fixes on the branch.

Nothing is encrypted and no keys are computed: records after a
ChangeCipherSpec and application data are random octets, so the
dissector shows them as opaque (decryption code is not exercised).

Usage: mktls.py <output directory> [-v]

Writes:
  tls-coverage.pcapng           clean captures (Ethernet and Exported PDU)
  tls-coverage-malformed.pcap   truncated records, bad SSLv2 messages,
                                records that are not allowed in TLS 1.3
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib

from tlslib import (
    cert, client_hello, exported_pdu, ext, exts, filler, Flow, HRR_RANDOM, hs, ocsp_response,
    record, server_hello, u16s, v16, v24, v8, write_pcap, write_pcapng,
)

VERBOSE = '-v' in sys.argv
marks = []


def mark(frames, label):
    marks.append((len(frames), label))


def sslv2_record(body, pad=None, escape=False):
    """Two-byte header (no padding) or three-byte header (with padding)."""
    if pad is None:
        return struct.pack('!H', 0x8000 | len(body)) + body
    b0 = (0x40 if escape else 0) | (len(body) >> 8)
    return bytes([b0, len(body) & 0xff, pad]) + body


def sslv2_client_hello(version=0x0300, specs=(0x010080, 0x020080, 0x030080, 0x040080, 0x050080,
                                                0x060040, 0x0700c0, 0x000004, 0x000005, 0x00000a),
                       sid=b'', challenge=16):
    body = (b'\x01' + struct.pack('!H', version) + struct.pack('!HHH', len(specs) * 3, len(sid), challenge) +
            b''.join(s.to_bytes(3, 'big') for s in specs) + sid + filler(challenge))
    return body


def sslv2_server_hello(cert=None, specs=(0x010080, 0x050080), conn_id=16, version=0x0002, hit=0):
    cert = cert if cert is not None else cert_der()
    body = (b'\x04' + bytes([hit, 1]) + struct.pack('!H', version) + struct.pack('!HHH', len(cert), len(specs) * 3, conn_id) +
            cert + b''.join(s.to_bytes(3, 'big') for s in specs) + filler(conn_id))
    return body


def cert_der():
    return cert('sslv2.example.com')


def sslv2_master_key(spec=0x010080, clear=0, enc=64, arg=0):
    return (b'\x02' + spec.to_bytes(3, 'big') + struct.pack('!HHH', clear, enc, arg) +
            filler(clear) + filler(enc) + filler(arg))


def alert(level, desc):
    return bytes([level, desc])


def build_main():
    F = []                                  # (linktype, frame)
    eth_frames = []

    def add(frames):
        F.extend((1, f) for f in frames)

    # ---- A: a TLS 1.2 session over TCP with SYN, FIN, segmentation of records
    mark(F, 'TLS 1.2 session with handshake, FIN; records split over TCP segments')
    fl = Flow(50001, syn=True)
    ch = record(22, client_hello(extensions=exts(ext(0, v16(b'\x00' + v16(b'tls.example'))), ext(16, v16(v8(b'h2') + v8(b'http/1.1'))),
                                                 ext(35), ext(23), ext(65281, v8(b'')))), 0x0301)
    fl.c(ch)
    sh = server_hello(suite=0xc02f, sid=filler(32), extensions=exts(ext(16, v16(v8(b'h2'))), ext(65281, v8(b'')), ext(23)))
    certm = hs(11, v24(v24(cert('tls.example', sct=True)) + v24(cert('Test CA'))))
    ske = hs(12, bytes([3]) + struct.pack('!H', 29) + v8(filler(32)) + struct.pack('!H', 0x0804) + v16(filler(256)))
    # server flight: record header split from its body, then a handshake spanning the next segments
    data = record(22, sh) + record(22, certm + ske + hs(14, b''))
    fl.raw(data[:3], True)                      # record header incomplete
    fl.raw(data[3:50], True)                    # header complete, body incomplete
    fl.raw(data[50:50 + 300], True)             # still incomplete
    fl.raw(data[350:], True)                    # the rest
    fl.c(record(22, hs(16, v8(filler(32)))), record(20, b'\x01'), record(22, filler(40)))
    fl.s(record(22, hs(4, struct.pack('!I', 7200) + v16(filler(64)))), record(20, b'\x01'), record(22, filler(40)))
    fl.c(record(23, filler(120)), record(23, filler(300)))
    fl.s(record(23, filler(1400)))
    fl.c(record(21, filler(26)))                # encrypted alert (not 2 octets)
    fl.s(record(21, alert(1, 0)))               # close_notify, plain
    fl.fin(False)
    fl.fin(True)
    add(fl.frames)

    # ---- B: handshake messages over several records, both directions, mixed with other messages
    mark(F, 'Handshake messages split over several records in both directions (reassembly)')
    fl = Flow(50002, syn=False)
    cert_big = hs(11, v24(v24(cert('big.example.com', san=['a%d.example.com' % i for i in range(30)])) + v24(cert('Test CA'))))
    ckx_big = hs(16, v16(filler(300)))
    fl.c(record(22, client_hello()))
    # server Certificate split over three records; the last also holds the ServerKeyExchange and ServerHelloDone
    sh = server_hello(suite=0xc02f, sid=filler(32))
    p1, p2, p3 = cert_big[:100], cert_big[100:400], cert_big[400:]
    fl.s(record(22, sh + p1))
    fl.c(record(22, ckx_big[:50]))              # client direction at the same time
    fl.s(record(22, p2))
    fl.c(record(22, ckx_big[50:200]))
    fl.s(record(22, p3 + hs(12, bytes([3]) + struct.pack('!H', 29) + v8(filler(32)) + struct.pack('!H', 0x0804) + v16(filler(64))) + hs(14, b'')))
    fl.c(record(22, ckx_big[200:]), record(20, b'\x01'), record(22, filler(40)))
    # the handshake message header split over records (fewer than four octets)
    msg = hs(4, struct.pack('!I', 600) + v16(filler(100)))
    fl.s(record(22, msg[:2]))
    fl.s(record(22, msg[2:3]))
    fl.s(record(22, msg[3:50]))
    fl.s(record(22, msg[50:]))
    # a message ending exactly at the end of a record, then a new one starting
    fl.s(record(22, hs(0, b'') + msg[:30]))
    fl.s(record(22, msg[30:]))
    add(fl.frames)

    # ---- C: record layer oddities
    mark(F, 'Unknown content types, zero length records, big records, TLS versions')
    fl = Flow(50003, syn=False)
    fl.c(record(22, client_hello(version=0x0301, extensions=None), 0x0301))
    fl.s(record(22, server_hello(version=0x0301, suite=0x0035, extensions=None) + hs(11, v24(v24(cert('old.example.com')))) + hs(14, b''), 0x0301))
    fl.c(record(99, filler(10), 0x0301))                      # unknown content type with TLS 1.0
    fl.c(record(23, filler(2000), 0x0301))
    fl.c(record(23, filler(17000), 0x0301))                   # longer than 2^14, TLSCiphertext limit not exceeded
    fl.c(b'\x17\x03\x01')                                     # header cut in the middle at the end of the stream
    add(fl.frames)
    fl = Flow(50004, syn=False)
    fl.c(record(99, filler(10), 0x0303))                      # unknown content type in an unknown-version conversation
    fl.c(record(22, client_hello(version=0x0302, extensions=None), 0x0302))
    fl.s(record(22, server_hello(version=0x0302, suite=0x002f, extensions=None) + hs(14, b''), 0x0302))
    fl.c(record(99, filler(10), 0x0302))
    add(fl.frames)
    # SSL 3.0 session
    fl = Flow(50005, syn=False)
    fl.c(record(22, client_hello(version=0x0300, extensions=None, suites=(0x0005, 0x000a)), 0x0300))
    fl.s(record(22, server_hello(version=0x0300, suite=0x0005, extensions=None) + hs(14, b''), 0x0300))
    fl.c(record(22, hs(16, filler(128)), 0x0300), record(20, b'\x01', 0x0300), record(22, filler(56), 0x0300))
    fl.s(record(20, b'\x01', 0x0300), record(22, filler(56), 0x0300))
    fl.c(record(23, filler(100), 0x0300))
    fl.s(record(21, alert(2, 40), 0x0300))
    add(fl.frames)
    # TLS 1.1 session, NPN encrypted extension (type 67)
    fl = Flow(50006, syn=False)
    fl.c(record(22, client_hello(version=0x0302, extensions=exts(ext(13172))), 0x0302))
    fl.s(record(22, server_hello(version=0x0302, suite=0xc014, extensions=exts(ext(13172, v8(b'http/1.1') + v8(b'spdy/3')))) + hs(14, b''), 0x0302))
    fl.c(record(22, hs(16, v8(filler(65)))), record(20, b'\x01'), record(22, hs(67, v8(b'http/1.1') + v8(bytes(24)) )))
    add(fl.frames)
    # ChangeCipherSpec with version fields, TLS 1.2 abbreviated handshake with a Session ID
    fl = Flow(50007, syn=False)
    sid = filler(32)
    fl.c(record(22, client_hello(sid=sid)))
    fl.s(record(22, server_hello(sid=sid)), record(20, b'\x01'), record(22, filler(40)))
    fl.c(record(20, b'\x01'), record(22, filler(40)))
    fl.c(record(23, filler(50)))
    add(fl.frames)

    # SSL 3.0: an unknown content type (shown as continuation data), a record followed by a partial header
    fl = Flow(50008, syn=False)
    fl.c(record(22, client_hello(version=0x0300, extensions=None), 0x0300))
    fl.s(record(22, server_hello(version=0x0300, suite=0x002f, extensions=None) + hs(14, b''), 0x0300))
    fl.c(record(99, filler(10), 0x0300))
    fl.c(record(23, filler(10), 0x0300) + b'\x17\x03\x00')
    fl.c(b'\x00\x10' + filler(16))
    fl.c(record(25, filler(30), 0x0300), record(26, filler(30), 0x0300))
    add(fl.frames)

    # ---- C2: handshake message types
    mark(F, 'Handshake message types: HelloRequest, HelloVerifyRequest, Retry Request, CertificateVerify, Finished, certificate messages, KeyUpdate')
    fl = Flow(50009, syn=False)
    fl.c(record(22, client_hello(extensions=exts(ext(42), ext(41, v16(v16(filler(16)) + struct.pack('!I', 1) + b'') + v16(v8(filler(32)))), ext(43, v8(u16s(0x0304)))))))
    fl.s(record(22, server_hello(extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(41, b'\x00\x00')))))
    fl.s(record(22, hs(0, b'') + hs(3, b'\x03\x03\x00') + hs(5, b'') + hs(13, v8(b'\x01') + v16(u16s(0x0401)) + v16(b'')) +
                 hs(15, struct.pack('!H', 0x0804) + v16(filler(64))) + hs(20, filler(12)) + hs(99, b'') ))
    fl.s(record(22, hs(21, b'\x01' + v16(v16(b'http://example.com/c.der') + b'\x01' + filler(20)))))
    fl.s(record(22, hs(22, b'\x01' + v24(ocsp_response(0)))))
    fl.s(record(22, hs(23, b'\x00\x00\x00') + hs(254, filler(32)) + hs(67, v8(b'http/1.1') + v8(bytes(24)))))
    fl.s(record(22, hs(24, b'\x01') + hs(99, b'\x00\x01')))
    fl.s(record(22, hs(99, b'\x00')))                                # unknown first message
    cbody = b'\x00' + v24(v24(cert('z.example.com')) + exts())
    fl.s(record(22, hs(25, struct.pack('!H', 1) + len(cbody).to_bytes(3, 'big') + v24(zlib.compress(cbody)))))
    add(fl.frames)
    fl = Flow(50013, syn=False)
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x0304))), ext(51, v16(struct.pack('!H', 29) + v16(filler(32))))))))
    fl.s(record(22, server_hello(suite=0x1301, random32=HRR_RANDOM, extensions=exts(ext(43, struct.pack('!H', 0x0304)),
                                                                           ext(51, struct.pack('!H', 23))))))
    fl.s(record(22, hs(6, struct.pack('!HH', 0x7f17, 0x1301) + exts(ext(43, struct.pack('!H', 0x7f17))))))
    add(fl.frames)

    # ---- D: alerts
    mark(F, 'Alerts of every level and description')
    fl = Flow(50010, syn=False)
    fl.c(record(22, client_hello()))
    fl.s(record(22, server_hello() + hs(14, b'')))
    for lvl, desc in [(1, 0), (1, 90), (2, 10), (2, 20), (2, 21), (2, 22), (2, 30), (2, 40), (2, 42), (2, 43), (2, 44), (2, 45),
                      (2, 46), (2, 47), (2, 48), (2, 49), (2, 50), (2, 51), (2, 60), (2, 70), (2, 71), (2, 80), (2, 86), (2, 90),
                      (1, 100), (2, 109), (2, 110), (2, 111), (2, 112), (2, 113), (2, 114), (2, 115), (2, 116), (2, 120), (2, 121),
                      (2, 255), (3, 0), (0, 200)]:
        fl.s(record(21, alert(lvl, desc)))
    fl.c(record(21, alert(1, 0)))               # client close_notify
    fl.c(record(21, alert(1, 0) + alert(2, 40)))  # two alerts in one record (only the first is shown)
    add(fl.frames)

    # ---- E: heartbeats (plain text)
    mark(F, 'Heartbeat messages')
    fl = Flow(50011, syn=False)
    fl.c(record(22, client_hello(extensions=exts(ext(15, b'\x01')))))
    fl.s(record(22, server_hello(extensions=exts(ext(15, b'\x01'))) + hs(14, b'')))
    fl.c(record(24, b'\x01' + struct.pack('!H', 10) + filler(10) + filler(16)))       # request, valid
    fl.s(record(24, b'\x02' + struct.pack('!H', 10) + filler(10) + filler(16)))       # response
    fl.s(record(24, b'\x03' + struct.pack('!H', 5) + filler(5) + filler(16)))         # unknown type
    fl.c(record(24, b'\x01\x00\x01' + filler(1) + filler(16)))
    fl.s(record(24, b'\x01' + struct.pack('!H', 3) + filler(400)))                    # long, "encrypted" heartbeat
    add(fl.frames)

    # ---- F: TLS 1.3 records
    mark(F, 'TLS 1.3: opaque records, middlebox compatibility CCS, alerts')
    fl = Flow(50012, syn=False)
    fl.c(record(22, client_hello(sid=filler(32), extensions=exts(ext(43, v8(u16s(0x0304, 0x0303))), ext(51, v16(struct.pack('!H', 29) + v16(filler(32)))))), 0x0301))
    fl.s(record(22, server_hello(sid=filler(32), suite=0x1301, extensions=exts(ext(43, struct.pack('!H', 0x0304)),
                                                                             ext(51, struct.pack('!H', 29) + v16(filler(32)))))),
         record(20, b'\x01'))
    fl.c(record(20, b'\x01'))
    fl.s(record(23, filler(100)), record(23, filler(1200)))
    fl.c(record(23, filler(80)))
    fl.s(record(21, alert(1, 0)))
    add(fl.frames)

    # ---- G: SSLv2
    mark(F, 'SSLv2 and the SSLv2 compatible ClientHello')
    fl = Flow(50020, syn=False)                # SSLv2 hello with a SSLv3 version, then a TLS ServerHello
    fl.c(sslv2_record(sslv2_client_hello(0x0301)))
    fl.s(record(22, server_hello(version=0x0301, suite=0x0035, extensions=None) + hs(11, v24(v24(cert('v2.example.com')))) + hs(14, b''), 0x0301))
    fl.c(record(22, hs(16, v16(filler(128))), 0x0301), record(20, b'\x01', 0x0301), record(22, filler(40), 0x0301))
    fl.s(record(20, b'\x01', 0x0301), record(22, filler(40), 0x0301))
    add(fl.frames)
    fl = Flow(50021, syn=False)                # pure SSLv2: hello, server hello, master key, finished
    fl.c(sslv2_record(sslv2_client_hello(0x0002, sid=filler(16), challenge=16)))
    fl.s(sslv2_record(sslv2_server_hello()))
    fl.c(sslv2_record(sslv2_master_key(clear=0, enc=64, arg=0)))
    fl.c(sslv2_record(sslv2_master_key(spec=0x020080, clear=5, enc=64, arg=8)))
    fl.c(sslv2_record(sslv2_client_hello(0x0002, challenge=16), pad=0))      # hello with a three-byte header and escape
    fl.c(sslv2_record(sslv2_server_hello(), pad=2, escape=True))
    fl.c(sslv2_record(b'\x03' + filler(32), pad=0))                          # client-finished, three-byte header
    fl.s(sslv2_record(b'\x05' + filler(16), pad=0, escape=True))             # server-verify, escape bit
    fl.s(sslv2_record(b'\x06' + filler(32), pad=4))                          # server-finished
    fl.s(sslv2_record(b'\x00\x00\x01'))                                      # error
    fl.s(sslv2_record(b'\x07' + filler(10)))                                 # request certificate
    fl.c(sslv2_record(b'\x08' + filler(10)))                                 # client certificate
    fl.c(sslv2_record(b'\x42' + filler(10)))                                 # unknown message type -> encrypted data
    fl.c(sslv2_record(b'\x01\x12\x34' + filler(20)))                         # client hello with an invalid version
    fl.s(sslv2_record(b'\x04\x00\x01\x12\x34' + filler(20)))                 # server hello with an invalid version
    fl.c(sslv2_record(b'\x02' + struct.pack('!HHH', 1000, 1000, 1000) + filler(20)))    # master key whose lengths exceed the record
    fl.c(sslv2_record(sslv2_client_hello(0x0002, specs=(0x010080,), sid=filler(16), challenge=64)))
    fl.c(sslv2_record(sslv2_client_hello(0x0002, specs=(0x010080,), sid=b'', challenge=0)))
    fl.s(sslv2_record(sslv2_server_hello(cert=b'', specs=(), conn_id=0)))
    add(fl.frames)
    # SSLv2 records over several segments
    fl = Flow(50022, syn=False)
    r = sslv2_record(sslv2_client_hello(0x0002, challenge=16))
    fl.raw(r[:1])
    fl.raw(r[1:20])
    fl.raw(r[20:] + sslv2_record(sslv2_master_key()))
    r3 = sslv2_record(b'\x03' + filler(32), pad=0)
    fl.raw(r3[:2], False)
    fl.raw(r3[2:], False)
    add(fl.frames)

    # ---- H: heuristics for TLS on other ports
    mark(F, 'TLS found by the heuristic on other TCP ports (SSLv3/TLS and SSLv2 ClientHello)')
    for port, rec in [(8443, record(22, client_hello(), 0x0301)), (8444, sslv2_record(sslv2_client_hello(0x0002, challenge=32), None)),
                      (8445, record(23, filler(60), 0x0303)),
                      (8446, record(22, client_hello(), 0x0301)[:4]),        # too short for the heuristic
                      (8447, record(99, filler(60), 0x0303)), (8448, record(22, b'', 0x0303)), (8449, record(22, filler(20), 0x0100))]:
        fl = Flow(52000 + port - 8443, port, syn=False)
        fl.c(rec)
        fl.s(record(22, server_hello() + hs(14, b''))) if port == 8443 else None
        add(fl.frames)
    # SSLv2 hello with the wrong header byte, wrong cipher spec length, session ID length, challenge length
    for i, body in enumerate([sslv2_client_hello(0x0002, challenge=32)]):
        pass
    for i, (port, rec) in enumerate([
            (8450, bytes([0x80, 0x3e]) + sslv2_client_hello(0x0002, challenge=32)[:0] + b'\x02' + b'\x00\x02' + struct.pack('!HHH', 3, 0, 32) + bytes(3) + filler(32) + filler(20)),
            (8451, bytes([0x80, 0x3e]) + b'\x01' + b'\x00\x02' + struct.pack('!HHH', 4, 0, 32) + bytes(4) + filler(32) + filler(20)),
            (8452, bytes([0x80, 0x3e]) + b'\x01' + b'\x00\x02' + struct.pack('!HHH', 3, 8, 32) + bytes(3) + filler(32) + filler(20)),
            (8453, bytes([0x80, 0x3e]) + b'\x01' + b'\x00\x02' + struct.pack('!HHH', 3, 0, 16) + bytes(3) + filler(32) + filler(20)),
            (8454, bytes([0x80, 0x3e]) + b'\x01' + b'\x00\x02' + struct.pack('!HHH', 0, 0, 32) + filler(32) + filler(23)),
            (8455, bytes([0x80, 0x3e]) + b'\x01' + b'\x00\x02' + struct.pack('!HHH', 3, 16, 32) + bytes(3) + filler(16) + filler(32) + filler(4)),
            (8456, b'\x80\x20' + b'\x01\x00\x02' + filler(29)),
    ]):
        fl = Flow(52100 + i, port, syn=False)
        fl.c(rec)
        add(fl.frames)

    # ---- I: STARTTLS (FTP AUTH TLS, SMTP STARTTLS): the TLS dissector takes over after the acknowledgement
    mark(F, 'STARTTLS: FTP AUTH TLS and SMTP STARTTLS')
    fl = Flow(53001, 21, syn=True)
    fl.s(b'220 FTP server ready\r\n')
    fl.c(b'AUTH TLS\r\n')
    fl.s(b'234 Proceed with negotiation\r\n')
    fl.c(record(22, client_hello(extensions=exts(ext(0, v16(b'\x00' + v16(b'ftp.example')))))))
    fl.s(record(22, server_hello() + hs(14, b'')))
    fl.c(record(22, hs(16, v8(filler(32)))), record(20, b'\x01'), record(22, filler(40)))
    add(fl.frames)
    fl = Flow(53002, 25, syn=False)
    fl.s(b'220 mail.example.com ESMTP\r\n')
    fl.c(b'EHLO client.example.com\r\n')
    fl.s(b'250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n')
    fl.c(b'STARTTLS\r\n')
    fl.s(b'220 2.0.0 Ready to start TLS\r\n')
    fl.c(record(22, client_hello()))
    fl.s(record(22, server_hello() + hs(14, b'')))
    fl.c(record(23, filler(60)))
    add(fl.frames)

    # ---- J: Exported PDU: tls13-handshake and tls-echconfig
    mark(F, 'Exported PDU: tls13-handshake, tls-echconfig')
    ee = hs(8, exts(ext(16, v16(v8(b'h3')))))
    sh13 = server_hello(suite=0x1301, extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(51, struct.pack('!H', 29) + v16(filler(32)))))
    F.append((252, exported_pdu('tls13-handshake', client_hello(sid=b'', extensions=exts(ext(43, v8(u16s(0x0304))), ext(51, v16(struct.pack('!H', 29) + v16(filler(32)))))))))
    F.append((252, exported_pdu('tls13-handshake', sh13 + ee)))
    F.append((252, exported_pdu('tls13-handshake', hs(11, b'\x00' + v24(v24(cert('quic.example.com')) + exts()))[:100])))
    ech1 = struct.pack('!HH', 0xfe0d, 0) + b''
    cfg = (struct.pack('!H', 0xfe0d))
    from_utils = None
    def ech_config(cfg_id=7, kem=0x20, suites=((1, 1), (1, 3)), name='public.example.com', version=0xfe0d, exts_=b''):
        key = v16(filler(32))
        cs = v16(b''.join(struct.pack('!HH', k, a) for k, a in suites))
        contents = bytes([cfg_id]) + struct.pack('!H', kem) + key + cs + bytes([64]) + v8(name.encode()) + v16(exts_)
        return struct.pack('!HH', version, len(contents)) + contents
    F.append((252, exported_pdu('tls-echconfig', v16(ech_config() + ech_config(cfg_id=9, name='b.example.com')))))

    # ---- K: reproducers of the fixes
    mark(F, 'Reproducers: handshake fragment direction, CCS state with -2')
    fl = Flow(54001, syn=False)
    fl.s(record(22, client_hello() + hs(11, b'\x01' * 10, 256)))
    fl.c(record(22, b'\x02' * 20))
    add(fl.frames)
    fl = Flow(54002, syn=False)
    ccs = record(20, b'\x01')
    fl.c(ccs)
    fl.c(record(22, hs(11, b'\x01' * 20, 256)))
    fl.c(record(22, client_hello()))
    fl.c(ccs)
    add(fl.frames)

    # ---- L: data that is not TLS on port 443 (printable first octets are rejected by the dissector)
    mark(F, 'Plain text on port 443')
    fl = Flow(54003, syn=False)
    fl.c(b'GET / HTTP/1.1\r\nHost: tls.example\r\n\r\n')
    fl.s(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
    add(fl.frames)
    return F


def build_malformed():
    F = []
    mark(F, 'Truncated records, SSLv2 errors, records that are not allowed in TLS 1.3')

    def add(frames):
        F.extend(frames)

    fl = Flow(55001, syn=False)
    fl.c(record(22, client_hello(sid=filler(32), extensions=exts(ext(43, v8(u16s(0x0304))), ext(51, v16(struct.pack('!H', 29) + v16(filler(32))))))))
    fl.s(record(22, server_hello(suite=0x1301, extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(51, struct.pack('!H', 29) + v16(filler(32)))))))
    fl.s(record(24, b'\x01\x00\x01' + filler(20)))       # heartbeat in TLS 1.3
    fl.c(record(20, b'\x01'))
    fl.s(record(22, hs(1, b'\x03\x03')))                  # a handshake message too short
    add(fl.frames)
    # TLS 1.3 draft CCS not allowed
    fl = Flow(55002, syn=False)
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x7f15)))))))
    fl.s(record(22, server_hello(extensions=exts(ext(43, struct.pack('!H', 0x7f15)), ext(51, struct.pack('!H', 29) + v16(filler(32)))))))
    fl.s(record(20, b'\x01'))
    add(fl.frames)
    # SSLv2 client hello with a session id that is too long
    fl = Flow(55003, syn=False)
    body = sslv2_client_hello(0x0002, sid=filler(40), challenge=16)
    fl.c(sslv2_record(body))
    fl.c(sslv2_record(sslv2_client_hello(0x0002, specs=(0x010080,), sid=b'', challenge=16)[:8]))
    add(fl.frames)
    # zero length records (an exception is thrown when no data follows), records over the size limit
    fl = Flow(55005, syn=False)
    fl.c(record(22, client_hello(), 0x0301))
    fl.s(record(22, server_hello(version=0x0301, suite=0x0035, extensions=None) + hs(14, b''), 0x0301))
    fl.c(record(22, b'', 0x0301))
    fl.c(record(21, b'', 0x0301))
    fl.c(record(20, b'', 0x0301))
    fl.c(record(23, b'', 0x0301))
    fl.c(record(22, b'', 0x0301) + record(23, filler(20), 0x0301))
    fl.s(record(23, filler(16384 + 2049), 0x0301))
    fl.c(record(24, b'\x01' + struct.pack('!H', 4000) + filler(40), 0x0301))
    fl.c(record(24, b'\x02\x00\x00', 0x0301))
    fl.c(b'\x17\x03\x01')
    add(fl.frames)
    fl = Flow(55006, syn=False)
    fl.s(sslv2_record(sslv2_server_hello(hit=1)[:20]))
    fl.s(sslv2_record(sslv2_client_hello(0x0002, specs=(0x010080,), sid=b'', challenge=16)[:8]) + sslv2_record(b'\x01\x00\x02' + filler(5)))
    add(fl.frames)
    # tls-echconfig with an unknown ECHConfig version is only reachable through Exported PDU (see the main capture)
    # truncated handshake records at the end of the capture, truncated by the snapshot length
    fl = Flow(55004, syn=False)
    fl.c(record(22, client_hello()))
    fr = fl.s(record(22, server_hello() + hs(11, v24(v24(cert('trunc.example.com')))) + hs(14, b'')))
    F2 = list(fl.frames)
    F2[-1] = (fl.frames[-1][:150], len(fl.frames[-1]))
    add(F2)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    global marks
    main_frames = build_main()
    write_pcapng(os.path.join(out, 'tls-coverage.pcapng'), main_frames)
    marks.append((len(main_frames), 'end'))
    shown = list(marks)
    marks = []
    mal = build_malformed()
    write_pcap(os.path.join(out, 'tls-coverage-malformed.pcap'), mal)
    if VERBOSE:
        print('main frames:', len(main_frames), 'malformed frames:', len(mal))
        for i, lbl in shown:
            print(i + 1, lbl)


if __name__ == '__main__':
    main()
