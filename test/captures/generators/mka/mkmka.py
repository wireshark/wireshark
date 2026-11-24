#!/usr/bin/env python3
# Generates test/captures/mka_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic EAPOL-MKA captures (no keys, placeholder bytes only).
Usage: mkmka.py <outdir>.  Writes mka-coverage.pcap (valid frames) and
mka-coverage-malformed.pcap."""
import struct
import sys
import os

def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)

def pset(t, b1, body, flags=0, raw_len=None):
    """Parameter set: type, byte 1, 4 bit flags + 12 bit body length, body, padding."""
    n = len(body) if raw_len is None else raw_len
    return pad4(struct.pack('!BBH', t, b1, (flags << 12) | n) + body)

def sci(n, port=1): return bytes([2, 0, 0, 0, 0, n]) + struct.pack('!H', port)
def mi(n): return bytes([n]) * 12

def basic(actor, mn, ver=3, prio=0x10, ks=False, desired=True, cap=2, ckn=b'\xaa' * 16,
          algo=0x0080C201, port=1):
    flags = (0x8 if ks else 0) | (0x4 if desired else 0) | cap
    body = sci(actor, port) + mi(actor) + struct.pack('!II', mn, algo) + ckn
    return pad4(struct.pack('!BBH', ver, prio, (flags << 12) | len(body)) + body)

def peers(items): return b''.join(mi(n) + struct.pack('!I', mn) for n, mn in items)

def lpl(items, ssci=0): return pset(1, ssci, peers(items))
def ppl(items): return pset(2, 0, peers(items))

def sak_use(latest_an=0, ltx=1, lrx=1, old_an=0, otx=0, orx=0, ptx=0, prx=0, dp=0,
            lmi=1, lkn=1, lpn=1, omi=0, okn=0, opn=0):
    f1 = latest_an << 6 | ltx << 5 | lrx << 4 | old_an << 2 | otx << 1 | orx
    body = mi(lmi) + struct.pack('!II', lkn, lpn) + mi(omi) + struct.pack('!II', okn, opn)
    return pad4(struct.pack('!BBH', 3, f1, 0) [:2] + struct.pack('!H', (ptx << 15 | prx << 14 | dp << 13) | len(body)) + body)

def sak_use_plain(**kw):
    f1 = 0
    return struct.pack('!BBH', 3, f1, 0)

def dsak(an, kn, wrapped, suite=None, conf=0):
    body = struct.pack('!I', kn)
    if suite is not None: body += struct.pack('!Q', suite)
    return pset(4, an << 6 | conf << 4, body + wrapped)

def xpn(latest, old, susp=0): return pset(8, susp, struct.pack('!II', latest, old))

def tlv(t, data): return struct.pack('!H', (t << 9) | len(data)) + data
def eapol(mkpdu, ver=3, da='0180c2000003', src=1):
    e = struct.pack('!BBH', ver, 5, len(mkpdu)) + mkpdu
    return bytes.fromhex(da) + bytes([2, 0, 0, 0, 0, src]) + b'\x88\x8e' + e

ICV = b'\x5a' * 16
GCM128 = 0x0080C20001000001; GCM256 = 0x0080C20001000002
XPN128 = 0x0080C20001000003; XPN256 = 0x0080C20001000004
W128 = b'\xc3' * 24; W256 = b'\xc4' * 40

frames = []; bad = []
def F(mk, **kw): frames.append(eapol(mk, **kw))
def B(mk, **kw): bad.append(eapol(mk, **kw))

# ---- an exchange of a key server (1) and two peers (2, 3), MKA version 3 ---------
F(basic(2, 1, ks=False) + ppl([(1, 1)]) + ICV, src=2)                       # peer 2 sees nobody yet
F(basic(3, 1) + ICV, src=3)
F(basic(1, 1, ks=True, prio=0x00) + lpl([(2, 1), (3, 1)]) + ICV, src=1)    # key server: both live
F(basic(2, 2) + lpl([(1, 1)]) + ppl([(3, 1)]) + ICV, src=2)
F(basic(3, 2) + lpl([(1, 1), (2, 2)]) + ICV, src=3)
# the key server distributes a SAK (AES-128, wrapped key is a placeholder) and announces use
F(basic(1, 2, ks=True, prio=0x00) + dsak(0, 1, W128) + sak_use(lmi=1, lkn=1, lpn=1) + lpl([(2, 2), (3, 2)], ssci=0) + ICV, src=1)
F(basic(2, 3) + sak_use(lmi=1, lkn=1, lpn=1, omi=0, okn=0) + lpl([(1, 2), (3, 2)]) + ICV, src=2)
F(basic(3, 3) + sak_use(lmi=1, lkn=1, lpn=1, old_an=0, orx=1, omi=1, okn=1, opn=1) + lpl([(1, 3), (2, 3)]) + ICV, src=3)
# XPN cipher suites: Distributed SAK with the cipher suite, SAK use, XPN set, Live Peer List with the key server SSCI
F(basic(1, 3, ks=True, prio=0x00) + lpl([(2, 3), (3, 3)], ssci=1) + dsak(1, 2, W128, XPN128) + sak_use(latest_an=1, lmi=1, lkn=2, lpn=7, old_an=0, orx=1, omi=1, okn=1, opn=3) + xpn(0x11, 0x22) + ICV, src=1)
F(basic(2, 4) + lpl([(1, 3), (3, 3)], ssci=0) + sak_use(latest_an=1, lmi=1, lkn=2, lpn=9, old_an=0, orx=1, omi=1, okn=1, opn=4) + xpn(0x11, 0x22) + ICV, src=2)
F(basic(3, 4) + lpl([(1, 3), (2, 4)]) + sak_use(latest_an=1, lmi=1, lkn=2, lpn=9) + xpn(0x33, 0x44, susp=5) + ICV, src=3)
F(basic(1, 4, ks=True, prio=0x00) + dsak(2, 3, W256, XPN256) + sak_use(latest_an=2, lmi=1, lkn=3, lpn=1) + xpn(1, 0) + lpl([(2, 4), (3, 4)], ssci=1) + ICV, src=1)
F(basic(1, 5, ks=True) + dsak(3, 4, W256, GCM256) + sak_use(latest_an=3, ltx=0, lrx=0) + lpl([(2, 5), (3, 5), (4, 1)], ssci=2) + ICV, src=1)
# only the old key is received: the XPN set updates the lowest PN of the old key
F(basic(3, 5) + sak_use(ltx=0, lrx=0, old_an=1, orx=1, otx=1, omi=1, okn=1, opn=5) + xpn(1, 2) + ICV, src=3)
# SAK use without a SAK (MACsec not supported / not desired), plaintext distributed SAK
F(basic(2, 5, desired=False, cap=0) + pset(3, 0, b'') + lpl([(1, 5)]) + ICV, src=2)
F(basic(2, 6, ver=2) + pset(4, 0, b'') + sak_use(lrx=0, ltx=0) + ICV, src=2)
# versions 1 and 2, CKN lengths, algorithm agility, key server priority
F(basic(4, 1, ver=1, ckn=b'k' * 1) + ICV, src=4)
F(basic(4, 2, ver=2, ckn=b'k' * 32) + lpl([(1, 1)]) + ICV, src=4)
F(basic(4, 3, ver=2, ckn=b'') + ICV, src=4)                                  # no CKN
F(basic(4, 4, ver=2, ckn=b'k' * 40) + ICV, src=4)                            # CKN longer than 32
F(basic(4, 5, ver=3, algo=0x0080C202, ks=True, cap=3) + ICV, src=4)
# ---- parameter sets ----------------------------------------------------------------------
F(basic(5, 1) + ppl([(6, 1), (7, 2), (8, 3)]) + ICV, src=5)
F(basic(5, 2) + pset(6, 0, b'example.org') + ICV, src=5)                     # key management domain
F(basic(5, 3) + pset(5, 0, bytes(range(24)) + b'\xaa' * 16) + ICV, src=5)  # distributed CAK (placeholder)
F(basic(5, 4) + pset(5, 0, bytes(range(24)) + b'') + ICV, src=5)             # CKN absent in the CAK set
# announcements
ciph = lambda s, c=3: struct.pack('!H', c) + struct.pack('!Q', s)
F(basic(5, 5) + pset(7, 0, tlv(112, ciph(GCM128) + ciph(GCM256, 2) + ciph(XPN128, 1) + ciph(XPN256, 0) + ciph(0x1234567890, 3))
                       + tlv(113, b'kmd.example')) + ICV, src=5)
F(basic(5, 6) + pset(7, 0, tlv(1, b'\x01\x02\x03') + tlv(2, b'') + tlv(112, ciph(GCM128)[:6])) + ICV, src=5)
F(basic(5, 7) + pset(7, 0, b'') + ICV, src=5)
F(basic(5, 8) + pset(7, 0, tlv(113, b'a')) + ICV, src=5)
# unknown parameter sets and a Basic Parameter Set only
F(basic(5, 9) + pset(100, 7, b'unknown-data') + pset(200, 0, b'') + ICV, src=5)
F(basic(5, 10) + ICV, src=5)
# ICV indicators
F(basic(6, 1) + struct.pack('!BBH', 255, 0, 16) + b'\x5a' * 16, src=6)
F(basic(6, 2) + struct.pack('!BBH', 255, 0, 32) + b'\x5b' * 32, src=6)
# other destination, other EAPOL version
F(basic(6, 5) + ICV, src=6, ver=2, da='0180c2000003')
F(basic(6, 6) + ICV, src=6, ver=1, da='ffffffffffff')
# the same member sending again (the MI to SCI map already has it) and a new MI for an old SCI
F(basic(2, 7) + lpl([(1, 5), (3, 5)]) + ICV, src=2)
F(basic(2, 8, port=2) + lpl([(1, 5)]) + ICV, src=2)

# ---- malformed ------------------------------------------------------------------------------
# unexpected versions
B(basic(2, 1, ver=0) + ICV, src=2)
B(basic(2, 2, ver=4) + ICV, src=2)
B(basic(2, 3, ver=255) + lpl([(1, 1)]) + ICV, src=2)
# undecoded lengths
B(basic(2, 4) + pset(1, 0, bytes(20)) + ICV, src=2)
B(basic(2, 5) + pset(2, 0, bytes(17)) + ICV, src=2)
B(basic(2, 6) + pset(3, 0, bytes(8)) + ICV, src=2)
B(basic(2, 7) + pset(3, 0, bytes(52)) + ICV, src=2)
B(basic(2, 8) + pset(4, 0, bytes(30)) + ICV, src=2)
B(basic(2, 9) + pset(4, 0, struct.pack('!IQ', 1, 0x1111) + bytes(40)) + ICV, src=2)   # unknown cipher suite
B(basic(2, 10) + pset(7, 0, tlv(111, b'info') + tlv(114, b'nid-data') + tlv(5, b'x')) + ICV, src=2)
B(basic(2, 11) + pset(7, 0, tlv(112, ciph(GCM128)) + struct.pack('!H', (112 << 9) | 400) + b'zz') + ICV, src=2)   # TLV past the end
# the basic set shorter than 28, wrapping the CKN length
B(struct.pack('!BBH', 3, 0, 4) + bytes(60), src=2)
B(struct.pack('!BBH', 3, 0, 0) + bytes(60), src=2)
B(struct.pack('!BBH', 3, 0, 4095) + bytes(60), src=2)
# a parameter set longer than the frame
B(basic(2, 12) + struct.pack('!BBH', 1, 0, 3000) + bytes(24) + ICV, src=2)
B(basic(2, 13) + struct.pack('!BBH', 7, 0, 4000) + bytes(40) + ICV, src=2)
B(basic(2, 14) + struct.pack('!BBH', 6, 0, 2000) + bytes(40) + ICV, src=2)
B(basic(2, 15) + struct.pack('!BBH', 5, 0, 10) + bytes(40) + ICV, src=2)              # CAK set, body below 24
B(basic(2, 16) + struct.pack('!BBH', 255, 0, 4095) + b'\x01' * 64, src=2)
B(basic(2, 17) + struct.pack('!BBH', 255, 0, 3) + b'\x01' * 4, src=2)
# truncated mid-set
B(basic(2, 18)[:20], src=2)
B(basic(2, 19) + lpl([(1, 1)])[:10], src=2)
B(basic(2, 20) + sak_use()[:12], src=2)
B(basic(2, 21) + xpn(1, 2)[:6] + ICV[:0], src=2)
B(basic(2, 22) + dsak(0, 1, W128)[:20], src=2)
B(basic(2, 23) + pset(8, 0, b'\0\0\0\1'), src=2)                                       # XPN set with a short body
B(basic(5, 11), src=5)                                                      # no ICV at all
B(basic(6, 3) + struct.pack('!BBH', 255, 0, 0), src=6)                       # ICV indicator of length 0
B(basic(6, 4) + lpl([(1, 1)]) + struct.pack('!BBH', 255, 0, 0), src=6)
B(b'', src=2)
B(b'\x03', src=2)
# ---- many Live Peer Lists and an XPN set: stress the SSCI mapping
B(basic(1, 9, ks=True) + b''.join(lpl([(2, 1), (3, 1)], ssci=k) for k in (0, 1, 2, 255)) + ICV, src=1)
B(basic(1, 10, ks=True) + lpl([(n, 1) for n in range(2, 60)], ssci=200) + ICV, src=1)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(out, exist_ok=True)
def write_pcap(fn, fr):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(fr):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p))); f.write(p)
write_pcap(os.path.join(out, 'mka-coverage.pcap'), frames)
write_pcap(os.path.join(out, 'mka-coverage-malformed.pcap'), bad)
print(len(frames), len(bad))
