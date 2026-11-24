#!/usr/bin/env python3
# Generates test/captures/tacacs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the TACACS / TACACS+ coverage captures. Usage: mktacacs.py <outdir> [-v]
Writes tacacs-coverage.pcap (main) and tacacs-coverage-malformed.pcap.
TACACS (XTACACS) is UDP 49, TACACS+ is TCP 49; both are registered by
default. TACACS+ bodies are sent with the "unencrypted" flag so that they
decode without a key (a few frames keep the flag clear and carry
arbitrary, non-secret bytes: the dissector shows them as an encrypted body
because no key is set). No obfuscation is computed here.
Everything is synthetic (192.0.2.0/24)."""
import os
import struct
import sys
from pcaplib import CLI, SRV, TcpFlow, udp, write_pcap

def legacy(version, typ, nonce, user=b'', pw=b'', resp=0, reason=0):
    """TACACS (version 0) and XTACACS (version 0x80: 26 octet header)."""
    if version == 0:
        if typ == 2:
            return struct.pack('!BBHBB', version, typ, nonce, resp, reason)
        return struct.pack('!BBHBB', version, typ, nonce, len(user), len(pw)) + user + pw
    hdr = struct.pack('!BBHBBBBIIHHIH', version, typ, nonce, len(user), len(pw), resp, reason,
                      0x11223344, 0xc0000207, 513, 7, 0x01020304, 0x55)
    return hdr + (b'' if typ == 2 else user + pw)

def plus(typ, seq, body, flags=0x01, session=0x11223344, ver=0xc0, length=None):
    return struct.pack('!BBBBII', ver, typ, seq, flags, session, len(body) if length is None else length) + body

def authen_start(action=1, priv=1, atype=1, svc=1, user=b'', port=b'', rem=b'', data=b''):
    return struct.pack('!BBBBBBBB', action, priv, atype, svc, len(user), len(port), len(rem), len(data)) + user + port + rem + data

def authen_reply(status, flags=0, msg=b'', data=b''):
    return struct.pack('!BBHH', status, flags, len(msg), len(data)) + msg + data

def authen_cont(user=b'', data=b'', flags=0):
    return struct.pack('!HHB', len(user), len(data), flags) + user + data

def author_req(method=6, priv=1, atype=1, svc=1, user=b'', port=b'', rem=b'', args=()):
    return (struct.pack('!BBBBBBBB', method, priv, atype, svc, len(user), len(port), len(rem), len(args))
            + bytes(len(a) for a in args) + user + port + rem + b''.join(args))

def author_rep(status, msg=b'', data=b'', args=()):
    return (struct.pack('!BBHH', status, len(args), len(msg), len(data)) + bytes(len(a) for a in args)
            + msg + data + b''.join(args))

def acct_req(flags=2, method=6, priv=1, atype=1, svc=1, user=b'', port=b'', rem=b'', args=()):
    return (struct.pack('!BBBBBBBBB', flags, method, priv, atype, svc, len(user), len(port), len(rem), len(args))
            + bytes(len(a) for a in args) + user + port + rem + b''.join(args))

def acct_rep(status, msg=b'', data=b''):
    return struct.pack('!HHB', len(msg), len(data), status) + msg + data

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    def addl(name, frs):
        R[name] = len(F) + 1; F.extend(frs)
    # ---- TACACS (UDP 49): every type; version 0 ----
    for t, name in enumerate(['login', 'response', 'change', 'follow', 'connect', 'superuser', 'logout', 'reload',
                              'slip-on', 'slip-off', 'slip-addr'], 1):
        if t == 2:
            for resp, reason in ((1, 0), (2, 1), (2, 3), (1, 7)):
                add('tacacs-response-%d-%d' % (resp, reason), udp(40000, 49, legacy(0, 2, 0x1000 + t, resp=resp, reason=reason)))
        else:
            add('tacacs-' + name, udp(40000, 49, legacy(0, t, 0x1000 + t, b'alice', b'secretpw')))
    add('tacacs-empty-user', udp(40000, 49, legacy(0, 1, 0x1100, b'', b'')))
    # XTACACS: version 0x80, 1: login and response
    add('xtacacs-login', udp(40001, 49, legacy(0x80, 1, 0x2001, b'bob', b'pw123')))
    add('xtacacs-response', udp(49, 40001, legacy(0x80, 2, 0x2001, resp=1, reason=0), src=SRV, dst=CLI))
    add('xtacacs-logout', udp(40001, 49, legacy(0x01, 7, 0x2002, b'bob', b'')))
    add('xtacacs-unknown-type', udp(40001, 49, legacy(0x80, 0x42, 0x2003, b'bob', b'x')))
    # ---- TACACS+ (TCP 49) ----
    f = TcpFlow(41000, 49)
    addl('tp1-handshake', f.handshake())
    # authentication START for every authentication type, and the other actions
    add('authen-ascii', f.c2s(plus(1, 1, authen_start(1, 15, 1, 1, b'alice', b'tty0', b'192.0.2.9', b'ascii data'))))
    add('authen-reply-getuser', f.s2c(plus(1, 2, authen_reply(4, 0, b'Username:'))))
    add('authen-cont-user', f.c2s(plus(1, 3, authen_cont(b'alice', b'', 0))))
    add('authen-reply-getpass', f.s2c(plus(1, 4, authen_reply(5, 1, b'Password:', b'srv data'))))
    add('authen-cont-pass', f.c2s(plus(1, 5, authen_cont(b'', b'password-bytes', 0))))
    add('authen-reply-pass', f.s2c(plus(1, 6, authen_reply(1, 0, b'Welcome'))))
    add('authen-cont-abort', f.c2s(plus(1, 7, authen_cont(b'', b'', 1))))
    add('authen-reply-fail', f.s2c(plus(1, 8, authen_reply(2, 0, b'Denied', b'x'))))
    f = TcpFlow(41001, 49)
    addl('tp2-handshake', f.handshake())
    add('authen-pap', f.c2s(plus(1, 1, authen_start(1, 1, 2, 3, b'bob', b'tty1', b'192.0.2.10', b'papsecret'))))
    add('authen-reply-getdata', f.s2c(plus(1, 2, authen_reply(3, 0, b'Data?'))))
    add('authen-reply-restart', f.s2c(plus(1, 4, authen_reply(6))))
    add('authen-reply-error', f.s2c(plus(1, 6, authen_reply(7, 0, b'', b'err'))))
    add('authen-reply-follow', f.s2c(plus(1, 8, authen_reply(0x21, 0, b'', b'192.0.2.77'))))
    f = TcpFlow(41002, 49)
    addl('tp3-handshake', f.handshake())
    chap = bytes([7]) + b'challenge-bytes' + bytes(range(16))
    add('authen-chap', f.c2s(plus(1, 1, authen_start(1, 1, 3, 3, b'carol', b'async1', b'', chap))))
    mschap = bytes([9]) + b'mschap-challenge' + bytes(range(49))
    add('authen-mschap', f.c2s(plus(1, 1, authen_start(1, 1, 5, 3, b'dave', b'async2', b'', mschap))))
    arap = b'NASCHAL1' + b'REMCHAL2' + b'REMRESP3'
    add('authen-arap', f.c2s(plus(1, 1, authen_start(1, 1, 4, 4, b'erin', b'async3', b'', arap))))
    add('authen-unknown-type', f.c2s(plus(1, 1, authen_start(1, 1, 9, 2, b'frank', b'', b'', b'unknown authen type data'))))
    add('authen-chpass', f.c2s(plus(1, 1, authen_start(2, 1, 1, 1, b'gina', b'tty2', b'192.0.2.11'))))
    add('authen-sendauth', f.c2s(plus(1, 1, authen_start(4, 1, 1, 0, b'hank', b'', b''))))
    add('authen-sendpass', f.c2s(plus(1, 1, authen_start(3, 1, 1, 8, b'ivan', b'tty4', b''))))
    add('authen-login-nodata', f.c2s(plus(1, 1, authen_start(1, 0, 2, 9, b'', b'', b''))))
    # ---- authorization ----
    f = TcpFlow(41003, 49)
    addl('tp4-handshake', f.handshake())
    add('author-req', f.c2s(plus(2, 1, author_req(6, 15, 1, 1, b'alice', b'tty0', b'192.0.2.9',
                                                   (b'service=shell', b'cmd*', b'priv-lvl=15')))))
    add('author-rep-add', f.s2c(plus(2, 2, author_rep(1, b'ok', b'srvdata', (b'service=shell', b'priv-lvl=15')))))
    add('author-req-noargs', f.c2s(plus(2, 1, author_req(5, 1, 2, 3, b'bob', b'', b''))))
    add('author-rep-repl', f.s2c(plus(2, 4, author_rep(2))))
    add('author-rep-fail', f.s2c(plus(2, 6, author_rep(0x10, b'denied', b''))))
    add('author-rep-error', f.s2c(plus(2, 8, author_rep(0x11))))
    add('author-rep-follow', f.s2c(plus(2, 10, author_rep(0x21, b'', b'192.0.2.78'))))
    # ---- accounting ----
    for fl, name in ((2, 'start'), (4, 'stop'), (8, 'watchdog'), (1, 'more'), (0x0f, 'all')):
        add('acct-req-' + name, f.c2s(plus(3, 1, acct_req(fl, 6, 1, 1, 1, b'alice', b'tty0', b'192.0.2.9',
                                                          (b'task_id=%d' % fl, b'start_time=1604400000', b'service=shell')))))
    add('acct-req-noargs', f.c2s(plus(3, 1, acct_req(2, 4, 1, 2, 3, b'', b'', b''))))
    add('acct-rep-ok', f.s2c(plus(3, 2, acct_rep(1, b'accounted', b'srv'))))
    add('acct-rep-error', f.s2c(plus(3, 4, acct_rep(2))))
    add('acct-rep-follow', f.s2c(plus(3, 6, acct_rep(0x21, b'', b'192.0.2.79'))))
    # ---- framing: two messages in one segment, one over two segments, header split ----
    two = plus(1, 1, authen_start(1, 1, 1, 1, b'x', b'', b'')) + plus(1, 3, authen_cont(b'', b'', 0))
    add('two-in-one', f.c2s(two))
    m = plus(2, 1, author_req(6, 1, 1, 1, b'longuser', b'tty9', b'192.0.2.9', (b'service=shell', b'cmd=show', b'cmd-arg=run')))
    add('split-1', f.c2s(m[:20]))
    add('split-2', f.c2s(m[20:]))
    m = plus(2, 1, author_req(6, 1, 1, 1, b'u', b'', b'', ()))
    add('hdr-split-1', f.c2s(m[:5]))
    add('hdr-split-2', f.c2s(m[5:]))
    # ---- encrypted payloads (no key set): the body stays opaque; arbitrary bytes, not real ciphertext ----
    opaque = bytes((i * 7 + 3) & 0xff for i in range(40))
    add('encrypted-req', f.c2s(plus(1, 1, opaque, flags=0x00, session=0x01020304)))
    add('encrypted-rep', f.s2c(plus(1, 2, opaque[:24], flags=0x04, session=0x01020304)))
    add('single-connect-flag', f.c2s(plus(3, 1, opaque[:16], flags=0x04)))
    # unknown type, minor version 1, unknown major version
    add('unknown-type', f.c2s(plus(7, 1, b'bogus body for an unknown type', flags=1)))
    add('minor-version-1', f.c2s(plus(1, 1, authen_start(1, 1, 1, 1, b'minor1'), ver=0xc1)))
    add('unknown-major', f.c2s(plus(1, 1, authen_start(1, 1, 1, 1, b'major'), ver=0xd2)))
    addl('tp4-fin', f.fin())
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    # TACACS lengths past the end
    add('tacacs-userlen-long', udp(40000, 49, struct.pack('!BBHBB', 0, 1, 1, 200, 200) + b'short'))
    add('tacacs-truncated', udp(40000, 49, b'\x00\x01'))
    add('xtacacs-truncated', udp(40000, 49, struct.pack('!BBHBB', 0x80, 1, 1, 5, 5) + b'\x00' * 10))
    f = TcpFlow(41100, 49)
    F += f.handshake()
    add('length-zero', f.c2s(plus(1, 1, b'', length=0)))
    add('length-negative', f.c2s(plus(1, 1, b'', length=0xffffff00)))
    f = TcpFlow(41101, 49)
    F += f.handshake()
    add('body-truncated', f.c2s(plus(1, 1, authen_start(1, 1, 1, 1, b'alice')[:6])))
    add('author-argc-lies', f.c2s(plus(2, 1, struct.pack('!BBBBBBBB', 6, 1, 1, 1, 2, 0, 0, 9) + b'ab')))
    add('chap-short', f.c2s(plus(1, 1, authen_start(1, 1, 3, 1, b'u', b'', b'', b'abc'))))
    add('mschap-short', f.c2s(plus(1, 1, authen_start(1, 1, 5, 1, b'u', b'', b'', b'abc'))))
    add('arap-short', f.c2s(plus(1, 1, authen_start(1, 1, 4, 1, b'u', b'', b'', b'abc'))))
    add('reply-lens-lie', f.s2c(plus(1, 2, struct.pack('!BBHH', 1, 0, 300, 300) + b'x')))
    add('cont-lens-lie', f.c2s(plus(1, 3, struct.pack('!HHB', 300, 300, 0) + b'x')))
    add('acct-rep-lens-lie', f.s2c(plus(3, 2, struct.pack('!HHB', 300, 300, 1) + b'x')))
    add('acct-req-lens-lie', f.c2s(plus(3, 1, struct.pack('!BBBBBBBBB', 2, 6, 1, 1, 1, 50, 50, 50, 5) + b'x')))
    add('author-rep-lens-lie', f.s2c(plus(2, 2, struct.pack('!BBHH', 1, 5, 300, 300) + b'x')))
    add('type-less-body', f.c2s(plus(3, 2, b'')))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcap(os.path.join(out, 'tacacs-coverage.pcap'), F)
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 'tacacs-coverage-malformed.pcap'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
