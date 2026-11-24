#!/usr/bin/env python3
# Generates test/captures/p4rpc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the P4RPC coverage captures: mkp4rpc.py <outdir>.
P4RPC (Perforce) on TCP port 1666 is found by the TCP heuristic (the TLS
port is preferred by default), after which the conversation keeps the
dissector. Exported PDU frames name "p4rpc" and "p4rpc.tls" (the TLS
handler, which sees plaintext after decryption; no TLS is built here).
Includes the reproducer of "P4RPC: Put the time-string and NUL experts at
the right offset" (message_params_as_tree off, in the malformed capture
and in the tests)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcapng, TCP, exported_pdu, gz

def param(name, val):
    if isinstance(name, str): name = name.encode()
    if isinstance(val, str): val = val.encode()
    return name + b'\0' + struct.pack('<I', len(val)) + val + b'\0'

def cksum(l):
    return (l & 0xff) ^ ((l >> 8) & 0xff) ^ ((l >> 16) & 0xff) ^ ((l >> 24) & 0xff)

def msg(*params, length=None, ck=None):
    body = b''.join(params)
    l = len(body) if length is None else length
    return bytes([cksum(l) if ck is None else ck]) + struct.pack('<I', l) + body

def haverec(client, depot, rev, ftype, date, wide):
    d = struct.pack('<Q', date) if wide else struct.pack('<I', date)
    return client.encode() + b'\0' + depot.encode() + b'\0' + struct.pack('<II', rev, ftype) + d

def stream1(c):
    """First stream: heuristic detection, then conversation dissector."""
    f = c.handshake()
    f.append(c.c2s(msg(param('func', 'protocol'), param('xfiles', 'client'), param('server2', '40'))))
    f.append(c.s2c(msg(param('func', 'flush1'), param('handle', 'h1'), param('confirm', 'yes'))))
    f.append(c.c2s(msg(param('func', 'user-sync'), param('syncTime', '1700000000'), param('depotTime', '1699999999'),
                       param('headModTime', '0'), param('headTime', '1500000000'), param('maxLockTime', '1700000100'),
                       param('maxPauseTime', '1'), param('theirTime', '1700000200'), param('otherTime', '1700000300'))))
    f.append(c.s2c(msg(param('func', 'client-FstatInfo'), param('action', 'edit'),
                       param('haveRec', haverec('//client/a.c', '//depot/a.c', 3, 0x10001, 1700000000, False)),
                       param('haveRec', haverec('//client/b.c', '//depot/b.c', 4, 0x10002, 1700000001, True)),
                       param('haveRec', haverec('//client/c.c', '//depot/c.c', 5, 0x10003, 0, False)))))
    f.append(c.c2s(msg(param('', 'anonymous parameter'), param('func', 'dm-Ping'), param('empty', ''))))
    # a very long value (truncated in the var=val text) and one cut in the middle of a multi-byte character
    f.append(c.s2c(msg(param('func', 'long'), param('data', 'x' * 300),
                       param('utf8', 'a' * 124 + '€€€'))))
    # split over three TCP segments: reassembly
    m = msg(param('func', 'split'), param('data', 'y' * 3000), param('handle', 'h2'))
    f.append(c.c2s(m[:3]))
    f.append(c.c2s(m[3:1500]))
    f.append(c.c2s(m[1500:]))
    # two messages in one segment
    f.append(c.s2c(msg(param('func', 'first')) + msg(param('func', 'second'), param('handle', 'h3'))))
    # Perforce time of 2040 (8-digit tests of the time formatting) and a huge time
    f.append(c.c2s(msg(param('func', 'times'), param('depotTime', '2300000000'), param('headTime', '99999999999'))))
    f.append(c.c2s(msg(param('func', 'release'))))
    return f

def stream2(c):
    """Second stream on another port, found by the heuristic too."""
    f = c.handshake()
    f.append(c.c2s(msg(param('func', 'dm-Login'), param('user', 'alice'))))
    f.append(c.s2c(msg(param('func', 'client-Message'), param('code', '0'), param('severity', '1'))))
    # reproducer of the time-string expert offset: the value is the last parameter
    f.append(c.c2s(msg(param('func', 'nonnum'), param('fooTime', '12345abcdefghij'))))
    return f

def main(out):
    fr = []
    fr += stream1(TCP('192.0.2.1', 40300, '192.0.2.2', 1666))
    fr += stream2(TCP('192.0.2.1', 40301, '192.0.2.3', 3000))
    # data the heuristic must reject: too short, bad checksum, length too small or too large
    c = TCP('192.0.2.1', 40302, '192.0.2.4', 4000)
    fr += c.handshake()
    fr.append(c.c2s(b'\x01\x02\x03'))
    fr.append(c.c2s(msg(param('func', 'nope'), ck=0x77)))
    fr.append(c.c2s(msg(param('func', 'nope'), length=4)))
    fr.append(c.c2s(msg(param('func', 'nope'), length=0x20000000)))
    fr.append(exported_pdu('p4rpc', msg(param('func', 'exported'), param('syncTime', '1700000000'))))
    fr.append(exported_pdu('p4rpc.tls', msg(param('func', 'tls'), param('handle', 'tls1'), param('action', 'sync'))))
    pcapng(os.path.join(out, 'p4rpc-coverage.pcapng'), fr)
    gz(os.path.join(out, 'p4rpc-coverage.pcapng'))
    # malformed capture: every bad message in a stream of its own, after a good one
    bad = []
    port = [40310]
    def one(payload):
        port[0] += 1
        c = TCP('192.0.2.1', port[0], '192.0.2.2', 1666)
        bad.extend(c.handshake())
        bad.append(c.c2s(msg(param('func', 'start'))))             # opens the conversation
        bad.append(c.c2s(payload))
    one(msg(param('func', 'badck'), ck=0x55))                                    # checksum mismatch
    one(msg(param('func', 'a'), param('v', 'b'), length=3))                      # length below the minimum
    one(msg(param('func', 'a'), length=200))                                     # length beyond the data
    one(msg(param('func', 'badnul'))[:-1] + b'X')                                # NUL terminator is 'X'
    body = param('func', 'vlen') + b'v\0' + struct.pack('<I', 5000) + b'abc\0'
    one(msg(length=len(body)) + body)                                            # value length beyond the message
    one(msg(param('func', 'nonnum'), param('fooTime', '12345abcdefghij')))        # non-numeric time (reproducer)
    one(msg(param('func', 'nonnum2'), param('fooTime', 'abc'), param('x', 'y')))
    one(msg(param('func', 'hr'), param('haveRec', b'a\0b\0' + bytes(12))))        # short haveRec
    one(b'\x01\x02')                                                            # fewer than 5 octets
    one(msg(param('func', 'x'), param('data', 'abc'), length=0x20000000))          # length above the maximum
    # a stream whose first message is incomplete: not recognised
    c2 = TCP('192.0.2.1', 40330, '192.0.2.2', 1666)
    bad += c2.handshake()
    m = msg(param('func', 'late'), param('data', 'z' * 100))
    bad.append(c2.c2s(m[:20]))
    bad.append(c2.c2s(m[20:]))
    bad.append(exported_pdu('p4rpc', b'\x01\x02\x03'))
    bad.append(exported_pdu('p4rpc', msg(param('func', 'trunc'))[:9]))
    bad.append(exported_pdu('p4rpc.tls', msg(param('func', 'badtls'), param('d', 'abc'), length=300)))
    pcapng(os.path.join(out, 'p4rpc-coverage-malformed.pcapng'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
