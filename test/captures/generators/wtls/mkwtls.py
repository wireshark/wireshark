#!/usr/bin/env python3
# Generates test/captures/wtls_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic WTLS captures (UDP 9202, 9203 and 2949).
Usage: mkwtls.py <outdir>.  Everything is built with struct; the
encrypted records hold opaque made-up bytes."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import w12pcap

def rec(ctype, body, length=True, seq=None, cipher=False):
    b = ctype & 0x0f
    if length: b |= 0x80
    if seq is not None: b |= 0x40
    if cipher: b |= 0x20
    out = bytes([b])
    if seq is not None: out += struct.pack('>H', seq)
    if length: out += struct.pack('>H', len(body))
    return out + body
def hs(htype, body):
    return bytes([htype]) + struct.pack('>H', len(body)) + body

RND = bytes(range(12))
def sess(n):
    return bytes([n]) + bytes((0x10 + i) & 0xff for i in range(n))
def key_entry(suite, pidx, idtype, ident=b'', pset=None):
    e = bytes([suite, pidx])
    if pidx == 0xff:
        e += struct.pack('>H', len(pset)) + pset
    e += bytes([idtype]) + ident
    return e
def textid(s, charset=4):
    return struct.pack('>HB', charset, len(s)) + s
def keys(entries):
    d = b''.join(entries)
    return struct.pack('>H', len(d)) + d

def client_hello(session, ckeys, tkeys, ciphers, comp=(0,), seqmode=1, refresh=3, ver=1, gmt=0x5f000000):
    cs = b''.join(bytes(c) for c in ciphers)
    return hs(1, bytes([ver]) + struct.pack('>I', gmt) + RND + session
              + keys(ckeys) + keys(tkeys)
              + bytes([len(cs)]) + cs + bytes([len(comp)]) + bytes(comp)
              + bytes([seqmode, refresh]))
def server_hello(session, cipher=(1, 3), comp=0, seqmode=2, refresh=5, ckey=1, ver=1, gmt=0x5f000010):
    return hs(2, bytes([ver]) + struct.pack('>I', gmt) + RND + session
              + bytes([ckey]) + bytes(cipher) + bytes([comp, seqmode, refresh]))

def wtls_cert(sigtype=2, issuer=('text', b'ca.example'), subject=('text', b'host.example'),
              pubkey=2, pidx=1, pset=None, exp=b'\x01\x00\x01', mod=bytes(range(16)),
              sig=bytes(8)):
    def ident(i):
        kind, s = i
        t = {'null': 0, 'text': 1, 'bin': 2, 'sha': 254, 'x509': 255}[kind]
        return bytes([t]) + (textid(s) if kind == 'text' else b'')
    d = bytes([1, 1, sigtype]) + ident(issuer)
    d += struct.pack('>II', 0x5e000000, 0x70000000)
    d += ident(subject)
    d += bytes([pubkey, pidx])
    if pidx == 0xff:
        d += struct.pack('>H', len(pset)) + pset
    if pubkey == 2:
        d += struct.pack('>H', len(exp)) + exp + struct.pack('>H', len(mod)) + mod
    d += struct.pack('>H', len(sig)) + sig
    return d
def certs(*items):
    d = b''.join(items)
    return hs(11, struct.pack('>H', len(d)) + d)
def x509(b): return bytes([2]) + struct.pack('>H', len(b)) + b
def x968(b): return bytes([3]) + struct.pack('>H', len(b)) + b
def urlc(b): return bytes([4]) + bytes([len(b)]) + b

def main_frames():
    f = []
    def u(p, port=9202): f.append(w12pcap.udp(p, sport=port, dport=port))
    ck_text = key_entry(8, 1, 1, textid(b'client'))
    ck_bin = key_entry(10, 2, 2, bytes([4]) + b'\x01\x02\x03\x04')
    ck_sha = key_entry(12, 3, 254, bytes(range(20)))
    ck_x509 = key_entry(14, 4, 255, bytes([3]) + b'CN=')
    ck_null = key_entry(0, 0, 0)
    ck_pset = key_entry(18, 0xff, 1, textid(b'cl'), pset=b'secp160r1')
    ciphers = [(1, 3), (5, 7), (3, 99), (99, 2), (99, 98)]
    ch_all = client_hello(sess(0), [ck_text, ck_bin, ck_sha, ck_x509, ck_null, ck_pset],
                          [ck_text, ck_pset, ck_bin, ck_sha, ck_x509], ciphers, comp=(0, 1))
    # Client Hello variants, on all three ports
    u(rec(3, ch_all))
    u(rec(3, client_hello(sess(4), [ck_text], [ck_null], [(0, 0)])), 9203)
    u(rec(3, client_hello(sess(8), [ck_pset], [], [(2, 5)], seqmode=0, refresh=0)), 2949)
    u(rec(3, client_hello(sess(10), [ck_pset], [ck_pset], [(4, 6)], seqmode=2)))   # long session id
    u(rec(3, client_hello(sess(16), [], [], [(9, 4)])), 9203)
    u(rec(3, client_hello(sess(9), [ck_sha], [ck_x509], [(6, 1), (7, 2), (8, 0)])))
    # Server Hello variants
    u(rec(3, server_hello(sess(0))))
    u(rec(3, server_hello(sess(8), cipher=(0, 0), seqmode=0, refresh=0)), 9203)
    u(rec(3, server_hello(sess(12), cipher=(9, 7))))
    u(rec(3, server_hello(sess(3), cipher=(42, 42)), length=False), 2949)
    # Certificates
    u(rec(3, certs(wtls_cert())))
    u(rec(3, certs(wtls_cert(sigtype=1, issuer=('null', b''), subject=('null', b''),
                             pubkey=3, pidx=2))), 9203)
    u(rec(3, certs(wtls_cert(sigtype=0, issuer=('text', b'issuer'), subject=('text', b'subject'),
                             pubkey=2, pidx=0xff, pset=b'rsa-params'))))
    u(rec(3, certs(wtls_cert(pubkey=4, pidx=3), wtls_cert(pubkey=3, pidx=4))))
    u(rec(3, certs(x509(b'\x30\x03\x02\x01\x01'), x968(b'\x01\x02'), urlc(b'http://ca.example/c'))))
    u(rec(3, certs(wtls_cert(), x509(bytes(12)), urlc(b'x'), wtls_cert(subject=('text', b'second')))), 9203)
    # Issuer and subject identifier types the dissector does not decode
    for kind in ('bin', 'sha', 'x509'):
        u(rec(3, certs(wtls_cert(issuer=(kind, b''), subject=(kind, b'')))))
    # Other handshake types (no decoding of the body)
    for t in (0, 12, 13, 14, 15, 16, 20):
        u(rec(3, hs(t, bytes(range(t % 7)))))
    # Alerts: all levels, a few descriptions, with sequence numbers
    for lvl, desc, seq in ((1, 0, None), (2, 10, 5), (3, 40, 6), (1, 90, 7), (3, 100, 8), (2, 255, None)):
        u(rec(2, bytes([lvl, desc]), seq=seq))
    # Records without a length field, change cipher, application data
    u(rec(1, b'\x01', length=False))
    u(rec(1, b'\x01', seq=9))
    u(rec(4, bytes(range(30)), seq=10))
    u(rec(7, b'xyz'))
    # Ciphered records (opaque made-up bytes: nothing is decrypted)
    u(rec(3, bytes(range(40, 70)), cipher=True, seq=11))
    u(rec(4, bytes(range(80, 120)), cipher=True, length=False), 9203)
    # Several records in one datagram
    u(rec(1, b'\x01', seq=12) + rec(3, hs(14, b''), seq=13) + rec(2, bytes([1, 0])) + rec(4, b'tail', length=False))
    u(rec(3, server_hello(sess(5))) + rec(3, certs(wtls_cert())) + rec(3, hs(14, b'')), 9203)
    return f

def malformed_frames():
    f = []
    def u(p, port=9202): f.append(w12pcap.udp(p, sport=port, dport=port))
    ch = client_hello(sess(4), [key_entry(8, 1, 1, textid(b'client'))], [], [(1, 3)])
    u(rec(3, ch[:20]))                       # truncated client hello
    u(rec(3, ch[:30]))
    u(rec(3, ch[:-3]))
    u(rec(3, server_hello(sess(8))[:25]))
    u(rec(3, server_hello(sess(40))[:30]))   # session id longer than the data
    u(rec(3, certs(wtls_cert())[:30]))
    u(rec(3, certs(wtls_cert())[:-5]))
    u(rec(3, certs(x509(bytes(12)))[:8]))
    u(rec(2, b'\x01'))                       # alert without description
    u(rec(3, b'\x01'))                       # handshake without length
    u(rec(3, b''))
    u(b'\x83\x00')                           # record header cut
    u(b'\x83\x00\x10\x03')                   # record longer than the datagram
    u(b'\x43\x00')                           # sequence number cut
    # a client key entry that claims more than present
    bad = key_entry(8, 0xff, 1, textid(b'c'), pset=b'p' * 5)
    u(rec(3, client_hello(sess(0), [bad[:6]], [], [(1, 3)])))
    # certificate with big declared length
    u(rec(3, hs(11, struct.pack('>H', 500) + bytes([1, 1, 2]))))
    u(rec(3, hs(11, struct.pack('>H', 20) + bytes([4, 200]) + b'u')))
    u(rec(3, hs(11, struct.pack('>H', 20) + bytes([2, 0xff, 0xff]) + b'u')))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    w12pcap.write(os.path.join(out, 'wtls-coverage.pcap'), mf)
    w12pcap.write(os.path.join(out, 'wtls-coverage-malformed.pcap'), malformed_frames())
    print(len(mf), 'main frames,', len(malformed_frames()), 'malformed frames')
