#!/usr/bin/env python3
# Generates test/captures/wireguard_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the WireGuard dissector
(packet-wireguard.c).

The capture holds WireGuard messages that are built from random bytes:
the encrypted fields are NOT real ciphertext, nothing here encrypts or
decrypts anything. Only the MAC1 field is computed (blake2s over the
message with the receiver's PUBLIC key, as in the WireGuard spec), so
that the dissector's MAC1 key probe recognises the receiver. The keys
are the test keys of test/suite_decryption.py, embedded as a pcapng
Decryption Secrets Block:
  Spriv_r (LOCAL_STATIC_PRIVATE_KEY) and Spub_i (REMOTE_STATIC_PUBLIC_KEY).
Decryption itself is therefore never successful and the decryption code
is not covered (see README).

Usage: mkwireguard.py <output directory> [-v]
Writes wireguard-coverage.pcapng (main), wireguard-coverage-malformed.pcapng
and keys.txt / keys-bad.txt (key log files for runcov.sh).
"""
import base64
import hashlib
import os
import struct
import sys
from pcaplib import pcapng, udp_frame, udp6_frame

SPRIV_R = 'cFIxTUyBs1Qil414hBwEgvasEax8CKJ5IS5ZougplWs='
SPUB_R = base64.b64decode('YDCttCs9e1J52/g9vEnwJJa+2x6RqaayAYMpSVQfGEY=')
SPUB_I_B64 = 'Igge9KzRytKNwrgkzDE/8hrLu6Ly0OqVdvOPWhA5KR4='
SPUB_I = base64.b64decode(SPUB_I_B64)

def mac1(msg, pub):
    key = hashlib.blake2s(b'mac1----' + pub).digest()
    return hashlib.blake2s(msg, digest_size=16, key=key).digest()

def rnd(n, seed):
    """Deterministic filler bytes (not key material)."""
    return bytes((seed * 31 + i * 7 + (i >> 3)) & 0xff for i in range(n))

def initiation(sender, pub, seed, mac2=bytes(16), reserved=b'\0\0\0', good_mac=True):
    m = struct.pack('<B3sI', 1, reserved, sender) + rnd(32, seed) + rnd(48, seed + 1) + rnd(28, seed + 2)
    m1 = mac1(struct.pack('<B3sI', 1, b'\0\0\0', sender) + m[8:], pub) if good_mac else rnd(16, seed + 9)
    return m + m1 + mac2

def response(sender, receiver, pub, seed, mac2=bytes(16), good_mac=True):
    m = struct.pack('<B3sII', 2, b'\0\0\0', sender, receiver) + rnd(32, seed) + rnd(16, seed + 1)
    m1 = mac1(m, pub) if good_mac else rnd(16, seed + 9)
    return m + m1 + mac2

def cookie(receiver, seed, reserved=b'\0\0\0'):
    return struct.pack('<B3sI', 3, reserved, receiver) + rnd(24, seed) + rnd(32, seed + 1)

def data(receiver, counter, n, seed, reserved=b'\0\0\0'):
    """Transport data with n octets after the 16 octet header; n >= 16 (tag)."""
    return struct.pack('<B3sIQ', 4, reserved, receiver, counter) + rnd(n, seed)

I, R = '10.0.0.1', '10.0.0.2'
frames, labels = [], []
def add(label, payload, sport=51820, dport=51820, src=I, dst=R, v6=False):
    f = udp6_frame(payload, sport, dport, src, dst) if v6 else udp_frame(payload, sport, dport, src, dst)
    frames.append(f); labels.append((len(frames), label))

# Session 1 (the reproducer of "WireGuard: Do not process a response without a
# decrypted initiator"): initiation to Spub_r, whose encrypted static is not
# decryptable, then a response linked to it.
add('initiation to Spub_r (known private key): static does not decrypt', initiation(0xA1, SPUB_R, 1))
add('response to it (reproducer; MAC1 for Spub_i)', response(0xB1, 0xA1, SPUB_I, 2), src=R, dst=I)
add('keepalive I->R (receiver 0xB1)', data(0xB1, 0, 16, 3))
add('data R->I (receiver 0xA1)', data(0xA1, 0, 116, 4), src=R, dst=I)
add('data I->R with non-zero reserved bytes (conversation dissector)', data(0xB1, 1, 48, 5, reserved=b'\x01\x02\x03'))
add('data I->R, counter 2^40', data(0xB1, 1 << 40, 100, 6))
add('data to an unknown receiver', data(0x999, 7, 40, 7))
# Session 2: initiation for Spub_i (public only), from another port, with MAC2
add('initiation for Spub_i (public key only, no handshake state), MAC2 set', initiation(0xA2, SPUB_I, 8, mac2=rnd(16, 77)), sport=51821)
add('cookie reply for it (session found via the initiator port)', cookie(0xA2, 9), dport=51821, src=R, dst=I)
add('cookie reply to nobody', cookie(0x4242, 10), src=R, dst=I)
add('initiation with a MAC1 no key matches', initiation(0xA3, SPUB_R, 11, good_mac=False), sport=51822)
add('response to it, sent to another port (not linked)', response(0xB3, 0xA3, SPUB_I, 12), dport=40000, src=R, dst=I)
add('response with a MAC1 no key matches', response(0xB4, 0xA3, SPUB_I, 13, good_mac=False), dport=51822, src=R, dst=I)
# Session 3: initiation without handshake state, response linked to it
add('initiation for Spub_i, sender 0xA4', initiation(0xA4, SPUB_I, 14), sport=51823)
add('response linked to a session without handshake state', response(0xB5, 0xA4, SPUB_I, 15), dport=51823, src=R, dst=I)
add('a second response for the same initiation (not linked again)', response(0xB6, 0xA4, SPUB_I, 16), dport=51823, src=R, dst=I)
add('data R->I on session 3', data(0xA4, 3, 64, 17), dport=51823, src=R, dst=I)
add('data I->R on session 3', data(0xB5, 0, 32, 18), sport=51823)
# The same sender ID used by a second initiation from a different address
add('initiation reusing sender 0xA1 from 10.0.0.9', initiation(0xA1, SPUB_R, 19), src='10.0.0.9')
add('response for sender 0xA1 sent to 10.0.0.9', response(0xB7, 0xA1, SPUB_I, 20), src=R, dst='10.0.0.9')
add('data for receiver 0xA1 from I side of the first session', data(0xA1, 9, 20, 21), src=R, dst=I)
add('data for receiver 0xB1 sent to an address of neither peer', data(0xB1, 4, 40, 31), dst='10.0.0.77')
# Heuristic only (no handshake seen on the ports)
add('cookie reply on a new port pair (heuristic)', cookie(0x5151, 32), sport=40003, dport=40003)
add('data on a new port pair (heuristic)', data(0x5151, 1, 64, 33), sport=40003, dport=40003)
add('3 octet UDP payload (heuristic needs 4)', b'\x04\0\0', sport=40004, dport=40004)
# Messages that are not WireGuard
add('data with non-zero reserved bytes on a new port (heuristic rejects)', data(0xB1, 1, 48, 22, reserved=b'\x01\x02\x03'), sport=40001, dport=40001)
add('cookie reply with non-zero reserved bytes on a new port', cookie(1, 23, reserved=b'\x00\x00\x01'), sport=40002, dport=40002)
add('type 5 message on the WireGuard conversation', b'\x05\0\0\0' + rnd(40, 24))
add('31 octet data message on the WireGuard conversation', b'\x04\0\0\0' + rnd(27, 25))
add('initiation with a length of 147 on the WireGuard conversation', initiation(0xA5, SPUB_R, 26)[:147])
# IPv6
V1, V2 = '2001:db8::1', '2001:db8::2'
add('IPv6: initiation to Spub_r', initiation(0xC1, SPUB_R, 27), src=V1, dst=V2, v6=True, sport=52000, dport=52000)
add('IPv6: response', response(0xD1, 0xC1, SPUB_I, 28), src=V2, dst=V1, v6=True, sport=52000, dport=52000)
add('IPv6: data I->R', data(0xD1, 0, 80, 29), src=V1, dst=V2, v6=True, sport=52000, dport=52000)
add('IPv6: data R->I', data(0xC1, 0, 16, 30), src=V2, dst=V1, v6=True, sport=52000, dport=52000)
nmain = len(frames)

secrets = ('LOCAL_STATIC_PRIVATE_KEY = %s\nREMOTE_STATIC_PUBLIC_KEY=%s\n' % (SPRIV_R, SPUB_I_B64)).encode()
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
pcapng(os.path.join(out, 'wireguard-coverage.pcapng'), frames, dsb=(0x57474b4c, secrets))

# Malformed capture: only things that raise exceptions. WireGuard checks
# every length before it decodes, so the frames here are truncated by the
# capture (caplen < reported length).
mal = []
def trunc(payload, keep, sport=51820, dport=51820):
    f = udp_frame(payload, sport, dport)
    # drop the tail but keep the length fields: truncate frame bytes only
    mal.append((f, keep))
for payload, keep in ((initiation(1, SPUB_R, 40), 60), (response(2, 1, SPUB_I, 41), 50),
                      (cookie(3, 42), 40), (data(4, 5, 50, 43), 20), (data(4, 5, 50, 44), 10)):
    trunc(payload, 42 + keep)
def pcapng_trunc(path, items, dsb):
    frames_ = []
    # write each frame with caplen < len
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    o = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    o += blk(1, struct.pack('<HHI', 1, 0, 0))
    o += blk(0x0A, struct.pack('<II', dsb[0], len(dsb[1])) + dsb[1])
    for i, (f, cap) in enumerate(items):
        ts = 1700000000_000000 + i * 10000
        o += blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, cap, len(f)) + f[:cap])
    open(path, 'wb').write(o)
pcapng_trunc(os.path.join(out, 'wireguard-coverage-malformed.pcapng'), mal, (0x57474b4c, secrets))

# Key log files for runcov.sh (the test keys of test/suite_decryption.py)
open(os.path.join(out, 'keys.txt'), 'w').write(
    '  REMOTE_STATIC_PUBLIC_KEY = %s\r\n'
    '  LOCAL_STATIC_PRIVATE_KEY = %s\n'
    '# a comment\n'
    '\n'
    'LOCAL_EPHEMERAL_PRIVATE_KEY=sLGLJSOQfyz7JNJ5ZDzFf3Uz1rkiCMMjbWerNYcPFFU=\n'
    'PRESHARED_KEY = //////////////////////////////////////////8=\n'
    'PRESHARED_KEY = iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg=\n'
    'LOCAL_EPHEMERAL_PRIVATE_KEY = 8G1N3LnEqYC7+NW/b6mqceVUIGBMAZSm+IpwG1U0j0w=\n'
    'UNKNOWN_KEY_TYPE = %s\n'
    'LOCAL_STATIC_PRIVATE_KEY = not-base64!\n'
    'LOCAL_STATIC_PRIVATE_KEY =\n'
    '= %s\n'
    'THIS_KEY_TYPE_NAME_IS_MUCH_TOO_LONG_TO_FIT = %s\n'
    'NOEQUALSSIGN\n'
    'LOCAL_STATIC_PRIVATE_KEY = %s\n'
    'LOCAL_STATIC_PRIVATE_KEY = %s\n'
    'LOCAL_STATIC_PRIVATE_KEY = %s%s\n'
    'LOCAL_STATIC_PRIVATE_KEY = %s' % (SPUB_I_B64, SPRIV_R, SPRIV_R, SPRIV_R, SPRIV_R, 'A' * 44, '!' * 44, SPRIV_R, 'A' * 60, SPRIV_R))
open(os.path.join(out, 'keys-bad.txt'), 'w').write('LOCAL_STATIC_PRIVATE_KEY = x\n')

if '-v' in sys.argv:
    for n, l in labels: print(n, l)
    print('main', nmain, 'malformed', len(mal))
