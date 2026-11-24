#!/usr/bin/env python3
# Generates test/captures/zbee_security_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-zbee-security.c (ZigBee security).

usage: mkzbee_security.py <outdir> [-v]    (-v prints the frame ranges)

Writes zbee-security-coverage.pcapng and zbee-security-coverage-malformed.pcapng.

This script contains no cryptography.  Secured frames carry filler octets
in place of the encrypted payload and the MIC, so every attempt to
decrypt fails (no valid MIC).  The only keys are made-up constants that
travel in plaintext APS Transport-Key commands, which is how the
dissector learns keys from a capture; they fill the key ring.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from zbeelib import (
    aps_cmd, aps_data, att_find_info, att_mtu, att_notify, CH_TUNNEL, EUI_A, EUI_B, EUI_C, filler,
    hci_conn_complete, ieee, LT_BLUETOOTH_H4_PHDR, LT_IEEE802_15_4_NOFCS, nwk, Pcapng, sec_hdr,
    tlv, transport_key, wpan_data,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
BT, WP = LT_BLUETOOTH_H4_PHDR, LT_IEEE802_15_4_NOFCS
PAN, PAN2 = 0x1a62, 0x2b73
ZC, ZR, ED = 0x0000, 0x0001, 0x0002           # short addresses
E_ZC, E_ZR, E_ED = EUI_A, EUI_B, EUI_C


def key_n(i):
    """A made-up 16 octet constant."""
    return struct.pack('<I', i) + bytes([0x40 + (i % 16)]) * 12


def run():
    p = Pcapng()
    marks = {}
    seq = [0]

    def f(name, payload, src=ZR, dst=ZC, pan=PAN, olen=None):
        """One 802.15.4 data frame carrying `payload` (a NWK frame)."""
        seq[0] += 1
        marks.setdefault(name, []).append(len(p) + 1)
        p.add(WP, wpan_data(payload, seq=seq[0], pan=pan, dst=dst, src=src),
              None if olen is None else olen + 9)

    n = [0]

    def ns():
        n[0] += 1
        return n[0]

    def secnwk(kid, src=ZR, ext=None, payload=filler(12), mic=filler(4), dst=ZC, cmd=False, **kw):
        """NWK frame secured at the NWK layer: header, filler payload, MIC."""
        return nwk(payload + mic, cmd=cmd, src=src, dst=dst, seq=ns(), ext_src=False,
                   sec=sec_hdr(key_id=kid, counter=ns(), src64=ext, **kw))

    def secaps(kid, ext=None, payload=filler(10), mic=filler(4), cmd=False, src=ED, **kw):
        """NWK frame (clear, with extended source) carrying a secured APS frame."""
        aux = sec_hdr(key_id=kid, counter=ns(), src64=ext, **kw)
        if cmd:
            aps = bytes([0x21, ns() & 0xff]) + aux + payload + mic
        else:
            aps = aps_data(b'', 0x0006, security=True, counter=ns()) + aux + payload + mic
        return nwk(aps, src=src, seq=ns(), ext_src={ZR: E_ZR, ED: E_ED, ZC: E_ZC}.get(src, E_ED))

    # ------------------------------------------------------------ NWK security
    # a secured frame from a node never seen: no extended source known
    f('nwk-unknown', secnwk(1, src=0x0077))
    # NWK key with the extended nonce: learns ZR's address, shows the header
    f('nwk-ext', secnwk(1, ext=E_ZR, keyseq=0))
    f('nwk-ext', secnwk(1, ext=E_ZR, keyseq=2, verified=True))
    # NWK key without it: the address is the one learned
    f('nwk-noext', secnwk(1, keyseq=1))
    f('nwk-noext', secnwk(1, keyseq=1, cmd=True))
    # frames with no payload (just the MIC), and one with 120 octets of payload
    f('nwk-empty', secnwk(1, ext=E_ZR, payload=b''))
    f('nwk-long', secnwk(1, ext=E_ZR, payload=filler(120, 0x5a)))
    # link, transport and load key identifiers at the NWK layer
    for kid in (0, 2, 3):
        f('nwk-keyid%d' % kid, secnwk(kid, ext=E_ZR))
    f('nwk-keyid0', secnwk(0))                        # link key, no extended nonce
    # another node of the same PAN, and a node of another PAN
    f('nwk-ed', secnwk(1, src=ED, ext=E_ED))
    f('nwk-pan2', secnwk(1, src=0x0005, ext=E_ED), src=0x0005, pan=PAN2)
    f('nwk-pan2', secnwk(1, src=0x0005), src=0x0005, pan=PAN2)
    # cut short by the capture: not enough octets for the MIC
    # (captured length shorter than the reported one)
    full = secnwk(1, ext=E_ZR, payload=filler(20))
    marks.setdefault('sliced', []).append(len(p) + 1)
    seq[0] += 1
    p.add(WP, wpan_data(full[:-14], seq=seq[0], dst=ZC, src=ZR), 9 + len(full))
    marks['sliced'].append(len(p) + 1)
    seq[0] += 1
    p.add(WP, wpan_data(full[:-19], seq=seq[0], dst=ZC, src=ZR), 9 + len(full))

    # ------------------------------------------------------------ APS security
    # APS data and command frames secured with the link key: the extended
    # source comes from the NWK layer
    f('aps-link', secaps(0), src=ED)
    f('aps-link', secaps(0, ext=E_ED), src=ED)
    f('aps-link', secaps(0, cmd=True), src=ED)
    f('aps-transport', secaps(2, ext=E_ED), src=ED)
    f('aps-transport', secaps(2, cmd=True), src=ED)
    f('aps-load', secaps(3, ext=E_ED), src=ED)
    f('aps-load', secaps(3, cmd=True), src=ED)
    f('aps-nwkkey', secaps(1, ext=E_ED), src=ED)       # NWK key id inside an APS frame
    f('aps-empty', secaps(0, payload=b''), src=ED)
    # an APS frame secured with no extended nonce from a node the NWK layer has no address for
    f('aps-unknown', nwk(aps_data(b'', 0x0006, security=True, counter=ns()) + sec_hdr(0, ns()) + filler(10) + filler(4),
                         src=0x0088, seq=ns(), ext_src=False), src=0x0088)

    # -------------------------------------------------------- Transport-Key
    # plaintext Transport-Key commands fill the key ring of PAN 0x1a62:
    # three keys, then the second one again
    def tk(i, dst64=E_ED, counter=None):
        return nwk(transport_key(key_n(i), keytype=1, dst64=dst64, src64=E_ZC, counter=counter or ns()),
                   src=ZC, dst=ED, seq=ns(), ext_src=E_ZC)
    for i in (1, 2, 3, 2):
        f('transport-key', tk(i), src=ZC, dst=ED)
    f('transport-key', nwk(transport_key(key_n(4), keytype=5, dst64=E_ED, src64=E_ZC, counter=ns()),
                           src=ZC, dst=ED, seq=ns(), ext_src=E_ZC), src=ZC, dst=ED)

    # ---------------------------------------------- secured frames, with keys
    # every key of the ring is tried (and fails: the MIC is filler)
    f('keys-nwk', secnwk(1, ext=E_ZR, keyseq=0))
    f('keys-nwk', secnwk(1, keyseq=0))
    f('keys-nwk', secnwk(1, ext=E_ZR, payload=filler(120, 0x5a)))
    f('keys-nwk', secnwk(1, ext=E_ZR, payload=b''))
    f('keys-aps', secaps(0), src=ED)
    f('keys-aps', secaps(2, ext=E_ED), src=ED)         # transport key: hashed key
    f('keys-aps', secaps(3, cmd=True), src=ED)         # load key: hashed key
    f('keys-aps', secaps(0, payload=filler(100, 0x33)), src=ED)

    # ------------------------------------------------------ APS Relay messages
    # ZC unsecured, so that its short address 0x0000 maps to its EUI64
    f('relay-zc', nwk(aps_cmd(0x09, b'\x01', counter=ns()), src=ZC, dst=ZR, seq=ns(), ext_src=E_ZC), src=ZC, dst=ZR)

    def relay(cmd, joiner=E_ED, inner=None, src=ZC, dst=ZR, ext=None):
        inner = inner if inner is not None else \
            bytes([0x21, 0x06]) + sec_hdr(key_id=0, counter=ns()) + filler(4, 0xaa) + filler(4, 0xbb)
        return nwk(aps_cmd(cmd, tlv(0, ieee(joiner) + inner), counter=ns()), src=src, dst=dst,
                   seq=ns(), ext_src=E_ZC if ext is None else ext)
    # downstream: the inner frame's source is ZC's EUI64, from the address table
    f('relay-down', relay(0x11), src=ZC, dst=ZR)
    # upstream: the joiner's EUI64 from the relay message
    f('relay-up', relay(0x12, src=ZR, dst=ZC, ext=E_ZR), src=ZR, dst=ZC)
    # downstream in a PAN where short address 0 is unknown
    f('relay-down', relay(0x11, src=0x0006, dst=ZR, ext=E_ED), src=0x0006, dst=ZR, pan=PAN2)
    # relayed frame with the extended nonce, and with a transport key id
    f('relay-down', relay(0x11, inner=bytes([0x21, 0x07]) + sec_hdr(key_id=0, counter=ns(), src64=E_ED)
                          + filler(8)), src=ZC, dst=ZR)
    f('relay-up', relay(0x12, inner=bytes([0x21, 0x08]) + sec_hdr(key_id=2, counter=ns())
                        + filler(8), src=ZR, dst=ZC, ext=E_ZR), src=ZR, dst=ZC)

    # --------------------------------------------- clear payload, secured header
    # A real NWK command (Link Status) with a MIC after it: encrypted at the
    # default level, but readable when the security level preference is one of
    # the integrity-only levels (runcov.sh does that)
    ls = bytes([0x08, 0x61]) + struct.pack('<HB', ZC, 0x11)
    f('clear-cmd', nwk(ls + filler(16, 0x11), cmd=True, src=ZR, dst=ZC, seq=ns(), ext_src=False,
                       sec=sec_hdr(key_id=1, counter=ns(), src64=E_ZR)))
    f('clear-cmd', nwk(aps_data(b'\x00\x01\x02\x03', 0x0006) + filler(16, 0x22), src=ZR, dst=ZC, seq=ns(),
                       ext_src=False, sec=sec_hdr(key_id=1, counter=ns())))
    f('clear-cmd', secaps(0, payload=bytes([0x06]) + filler(3, 0x44), cmd=True, mic=filler(16, 0x55)), src=ED)

    # --------------------------------- Key ring cap (64 keys per PAN), reproducer
    # of the quadratic key ring: 70 distinct plaintext Transport-Key commands.
    # The 65th and later keys do not fit (expert info), a repeated key is
    # recognised anywhere in the ring.
    for i in range(10, 80):
        f('keyring-cap', tk(i), src=ZC, dst=ED)
    f('keyring-cap', tk(12), src=ZC, dst=ED)          # a key already in the ring
    f('keyring-cap', tk(79), src=ZC, dst=ED)          # a key that did not fit
    for _ in range(3):
        f('keyring-after', secnwk(1, ext=E_ZR), src=ZR)
    f('keyring-after', secaps(2, ext=E_ED), src=ED)

    # ------------------------------------------------- ZigBee Direct over BT
    # no IEEE 802.15.4 layer: ieee_hints is NULL.  The Relay downstream
    # frame is the reproducer of "uninitialized pan of the address lookup".
    p.add(BT, hci_conn_complete())
    p.add(BT, att_mtu(517, 0))
    p.add(BT, att_mtu(517, 1))
    p.add(BT, att_find_info([(0x0040, CH_TUNNEL)]))

    def bt(name, nwkframe, flags=0):
        marks.setdefault(name, []).append(len(p) + 1)
        v = bytes([flags, len(nwkframe)]) + nwkframe
        p.add(BT, att_notify(0x0040, tlv(0, v)))

    inner = bytes([0x21, 0x06, 0x00]) + struct.pack('<I', 1) + b'\xaa' * 4 + b'\xbb' * 4
    relay_v = ieee(0x0200000000000002) + inner
    bt('bt-relay-down', nwk(aps_cmd(0x11, tlv(0, relay_v), counter=5), src=0x1234, dst=0x0000, seq=1,
                            ext_src=0x0200000000000001))
    bt('bt-relay-up', nwk(aps_cmd(0x12, tlv(0, relay_v), counter=6), src=0x1234, dst=0x0000, seq=2,
                          ext_src=0x0200000000000001))
    # NWK security over BT: the extended nonce, and no nonce (unknown source)
    bt('bt-nwk', nwk(filler(16), src=0x1234, dst=0, seq=3, ext_src=False, sec=sec_hdr(1, 7, src64=0x0200000000000001)), 1)
    bt('bt-nwk', nwk(filler(16), src=0x1234, dst=0, seq=4, ext_src=False, sec=sec_hdr(1, 8)), 1)
    bt('bt-nwk', nwk(filler(16), src=0x1234, dst=0, seq=4, ext_src=False, sec=sec_hdr(0, 8, src64=0x0200000000000001)), 1)
    # a few keys over BT (PAN 0), then a secured frame that tries them
    for i in (1, 2):
        bt('bt-keys', nwk(transport_key(key_n(100 + i), dst64=0x0200000000000002, src64=0x0200000000000001,
                                        counter=10 + i), src=0x0000, dst=0x1234, seq=10 + i,
                          ext_src=0x0200000000000001))
    bt('bt-keys', nwk(aps_data(b'', 0x0006, security=True, counter=20) + sec_hdr(0, 9) + filler(12),
                      src=0x1234, dst=0x0000, seq=20, ext_src=0x0200000000000002))
    bt('bt-keys', nwk(aps_cmd(0x12, tlv(0, ieee(0x0200000000000002) + bytes([0x21, 0x06]) + sec_hdr(0, 10)
                                         + filler(8)), counter=7), src=0x1234, dst=0, seq=21,
                      ext_src=0x0200000000000001))
    p.write(os.path.join(OUT, 'zbee-security-coverage.pcapng'))

    # ------------------------------------------------------------- malformed
    mal = Pcapng()
    mm = {}

    def m(name, data, olen=None, lt=WP):
        mm.setdefault(name, []).append(len(mal) + 1)
        mal.add(lt, data, olen)
    # security header cut off: the control field only, counter cut, extended source cut
    sh = sec_hdr(key_id=1, counter=1, src64=E_ZR)
    for cut in (1, 3, 8):
        m('sec-cut', wpan_data(nwk(b'', src=ZR, dst=ZC, seq=1, ext_src=False, sec=sh[:cut])))
    m('sec-cut', wpan_data(nwk(b'', src=ZR, dst=ZC, seq=2, ext_src=False, sec=sh[:-1])))
    # NWK key id: key sequence number missing
    m('sec-cut', wpan_data(nwk(b'', src=ZR, dst=ZC, seq=3, ext_src=False, sec=sec_hdr(1, 1, src64=E_ZR)[:13])))
    # APS frame whose security header is cut
    m('sec-cut', wpan_data(nwk(aps_data(b'', 0x0006, security=True) + b'\x28\x01\x00', src=ED, dst=ZC, seq=4)))
    # security header at the very end of the payload (no payload, no MIC)
    m('sec-nopayload', wpan_data(nwk(b'', src=ZR, dst=ZC, seq=5, ext_src=False, sec=sec_hdr(1, 1, src64=E_ZR))))
    m('sec-nopayload', wpan_data(nwk(b'', src=ZR, dst=ZC, seq=6, ext_src=False, sec=sec_hdr(0, 1, src64=E_ZR))))
    # BT: security header cut inside a tunnelled NWK frame
    mal.add(BT, hci_conn_complete())
    mal.add(BT, att_mtu(517, 0))
    mal.add(BT, att_mtu(517, 1))
    mal.add(BT, att_find_info([(0x0040, CH_TUNNEL)]))
    v = nwk(b'', src=0x1234, dst=0, seq=3, ext_src=False, sec=sh[:6])
    mm.setdefault('bt-cut', []).append(len(mal) + 1)
    mal.add(BT, att_notify(0x0040, tlv(0, bytes([1, len(v)]) + v)))
    mal.write(os.path.join(OUT, 'zbee-security-coverage-malformed.pcapng'))
    if VERBOSE:
        print('main: %d frames' % len(p))
        for k, v in marks.items():
            print('  %-16s %s' % (k, v))
        print('malformed: %d frames' % len(mal))
        for k, v in mm.items():
            print('  %-16s %s' % (k, v))


run()
