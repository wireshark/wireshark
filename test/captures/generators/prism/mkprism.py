#!/usr/bin/env python3
# Generates test/captures/prism_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Prism (DLT_PRISM_HEADER, 119) captures. Usage: mkprism.py <outdir> [-v]
# Writes prism-coverage.pcap and prism-coverage-malformed.pcap with struct only.
import struct
import sys
import os

DLT_PRISM = 119

def pcap(name, linktype, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

A1 = bytes.fromhex('020000000001')
A2 = bytes.fromhex('020000000002')
A3 = bytes.fromhex('020000000003')
def null_data(seq=1):
    return bytes([0x48, 0x01, 0, 0]) + A1 + A2 + A3 + struct.pack('<H', seq << 4)
def ack():
    return bytes.fromhex('d4000000') + A1

# DID codes: type 1 (message code 0x44) and type 2 (message code 0x41)
T1 = dict(host=0x00010044, mac=0x00020044, chan=0x00030044, rssi=0x00040044,
          sq=0x00050044, signal=0x00060044, noise=0x00070044, rate=0x00080044,
          istx=0x00090044, frmlen=0x000A0044, a1=0x000B0044, a2=0x000C0044,
          b=0x000D0044)
T2 = dict(host=0x00001041, mac=0x00002041, chan=0x00003041, rssi=0x00004041,
          sq=0x00005041, signal=0x00006041, noise=0x00007041, rate=0x00008041,
          istx=0x00009041, frmlen=0x0000A041, a1=0x0000B044, a2=0x0000C044,
          b=0x0000D044)
STD = ['host', 'mac', 'chan', 'rssi', 'sq', 'signal', 'noise', 'rate', 'istx', 'frmlen']

def prism(vals, t=1, bo='<', dev=b'wlan0', status=None, extra=(), body=None,
          msgcode=None, msglen=144, sigle=True):
    '''vals: dict name -> value for the DIDs to present (in the order of the
    dict); the rest of the 10 slots are filled with "not supplied"
    unknown DIDs. status: dict name -> status. extra: raw (did, status,
    len, val) tuples added after vals.'''
    codes = T1 if t == 1 else T2
    if msgcode is None:
        msgcode = 0x44 if t == 1 else 0x41
    status = status or {}
    h = struct.pack(bo + 'II', msgcode, msglen) + dev.ljust(16, b'\0')
    n = 0
    for k, v in vals.items():
        # sig values are little-endian regardless of the header byte order
        h += struct.pack(bo + 'IHH', codes[k], status.get(k, 0), 4)
        # SIG A1/A2 are read little-endian whatever the header byte order
        if sigle and k in ('a1', 'a2'):
            h += struct.pack('<I', v)
        else:
            h += struct.pack(bo + 'I', v)
        n += 1
    for did, st, ln, val in extra:
        h += struct.pack(bo + 'IHHI', did, st, ln, val)
        n += 1
    while n < 10:
        h += struct.pack(bo + 'IHHI', 0x00ee0044, 1, 4, 0)
        n += 1
    assert len(h) == 144, len(h)
    return h + (null_data() if body is None else body)

def std(chan=6, rate=2, rssi=-40, **kw):
    d = dict(host=1234, mac=0x11223344, chan=chan, rssi=rssi & 0xffffffff, sq=3,
             signal=0xffffffd0, noise=0xffffffa6, rate=rate, istx=0, frmlen=28)
    d.update(kw)
    return d

def sig(a1, a2, b=0x5a5a, **kw):
    d = dict(a1=a1, a2=a2, b=b)
    d.update(kw)
    return d

def build(outdir, verbose=False):
    fr = []
    notes = []
    def add(label, f):
        fr.append(f)
        notes.append(label)
    # All standard DIDs, type 1 and type 2, little and big endian
    add('type1 LE std ch6 1M', prism(std(6, 2)))
    add('type1 LE std ch1 11M (odd rate 5.5)', prism(std(1, 11)))
    add('type1 LE ch11 22 (PBCC)', prism(std(11, 44)))
    add('type1 LE OFDM ch6 -> 11g', prism(std(6, 108)))
    add('type1 LE OFDM ch36 -> 11a', prism(std(36, 108)))
    add('type2 LE std', prism(std(6, 2), t=2))
    add('type2 LE OFDM ch149', prism(std(149, 96), t=2))
    add('type1 BE std', prism(std(6, 22), bo='>'))
    add('type2 BE std', prism(std(11, 12), t=2, bo='>'))
    # OFDM rate without a channel: PHY stays unknown
    d = std(6, 108); del d['chan']
    add('type1 OFDM no channel', prism(d))
    # Rate not DSSS and not OFDM
    add('type1 rate 7 (neither)', prism(std(6, 7)))
    # status 1 (not supplied) for DIDs the dissector would otherwise read
    add('type1 status 1 channel/rate',
        prism(std(6, 2), status=dict(chan=1, rate=1, rssi=1, mac=1)))
    # Unknown DID with status 0 (default case) and unknown msg length
    add('unknown DID', prism(dict(host=1, mac=2), extra=[(0x00ee0044, 0, 4, 0x1234)]))
    # --- Qualcomm SIG A1/A2/B: OFDM (preamble 0)
    # OFDM: (mcs nibble, signal type bit 12, bw bits 13-14)
    for mcsn, dyn, bwb in ((0, 1, 0), (1, 1, 1), (2, 0, 2), (3, 1, 3), (4, 0, 0),
                           (8, 0, 0), (9, 1, 1), (10, 0, 0), (11, 0, 2),
                           (12, 1, 0), (15, 0, 3)):
        a1 = 0 | (mcsn << 4) | (dyn << 12) | (bwb << 13)
        add('sig OFDM mcsn %d dyn %d bw %d' % (mcsn, dyn, bwb),
            prism(sig(a1 | 0x0, 0x1), t=1))
    # OFDM rate (from the SIG) on channel 6 (11g) and with an additional
    # DSSS rate DID after it (11b)
    add('sig OFDM + chan 6', prism(dict(chan=6, **sig(0x10, 0x1))))
    add('sig OFDM + chan 36', prism(dict(chan=36, **sig(0x10, 0x1))))
    add('sig OFDM + chan 6 + DSSS rate', prism(dict(chan=6, a1=0x10, a2=1, b=1, rate=2)))
    add('sig OFDM + DSSS rate no chan', prism(dict(a1=0x10, a2=1, b=1, rate=2)))
    add('sig OFDM + OFDM rate no chan', prism(dict(a1=0x10, a2=1, b=1, rate=108)))
    # DSSS (preamble 1): mcs nibble 8-11 with the short preamble bit 4
    for mcsn in (8, 9, 10, 11, 12, 13, 14, 15, 0):
        add('sig DSSS mcsn %d' % mcsn, prism(sig(1 | (mcsn << 4), 1)))
    # HT (preamble 2): sig_a_1 = (a1 >> 4) & 0xffff: mcs bits 0-6, bw bit 7;
    # sig_a_2 = a2 & 0xfff: stbc bits 4-5, ldpc 6, sgi 7, ness 8-9
    for mcs, bw40, sgi, ldpc, stbc, ness in (
            (0, 0, 0, 0, 0, 0), (7, 1, 1, 1, 1, 1), (15, 0, 1, 0, 0, 2),
            (31, 1, 0, 1, 2, 3), (23, 0, 0, 0, 0, 0), (8, 1, 1, 0, 0, 0),
            (32, 0, 0, 0, 0, 0), (100, 1, 0, 0, 0, 0), (127, 0, 1, 0, 0, 0)):
        a1 = 2 | (((mcs & 0x7f) | (bw40 << 7)) << 4)
        a2 = (stbc << 4) | (ldpc << 6) | (sgi << 7) | (ness << 8) | 0x1
        add('sig HT mcs %d bw40 %d sgi %d' % (mcs, bw40, sgi), prism(sig(a1, a2)))
    # VHT (preamble 3): sig_a_1 = (a1>>4)&0xffffff: bw bits 0-1, stbc 3,
    # group id 4-9, nsts 10-12 (SU), partial AID 13-21 (SU), or nsts for 4
    # users (MU) from bit 10; sig_a_2: sgi bit 0, ldpc bit 2, mcs bits 4-7,
    # txbf bit 8
    def vht(bw, stbc, gid, nsts, mcs, sgi, ldpc, txbf, paid=0x123, mu=None):
        a1s = bw | (stbc << 3) | (gid << 4)
        if mu is None:
            a1s |= (nsts << 10) | (paid << 13)
        else:
            a1s |= (mu[0] << 10) | (mu[1] << 13) | (mu[2] << 16) | (mu[3] << 19)
        # bit 12 only keeps A2 non-zero: SIG B is ignored while A1 or A2 is 0
        a2 = sgi | (ldpc << 2) | (mcs << 4) | (txbf << 8) | 0x1000
        return sig(3 | (a1s << 4), a2)
    for bw in range(4):
        for sgi in (0, 1):
            add('sig VHT SU bw %d sgi %d' % (20 << bw, sgi),
                prism(vht(bw, 0, 0, 1, 7, sgi, 1, 0)))
    add('sig VHT SU nss 2 mcs 9 gid 63 txbf', prism(vht(2, 0, 63, 1, 9, 0, 0, 1)))
    add('sig VHT SU stbc nsts 7', prism(vht(1, 1, 0, 7, 3, 1, 0, 0)))
    add('sig VHT SU nss 5 (over limit)', prism(vht(0, 0, 0, 4, 3, 0, 0, 0)))
    add('sig VHT SU mcs 15 (over limit)', prism(vht(0, 0, 0, 1, 15, 0, 0, 0)))
    add('sig VHT SU nss 4 bw 160 mcs 8', prism(vht(3, 0, 0, 3, 8, 1, 0, 0)))
    add('sig VHT SU nss 3 mcs 6 bw 80', prism(vht(2, 0, 63, 2, 6, 0, 0, 0)))
    add('sig VHT MU', prism(vht(2, 1, 5, 0, 4, 1, 1, 0, mu=(1, 2, 0, 3))))
    add('sig VHT MU gid 62 bw 20', prism(vht(0, 0, 62, 0, 0, 0, 0, 0, mu=(7, 7, 7, 7))))
    # Unknown preamble types 4-15 (reproducer of "Prism: Fix radio metadata,
    # unknown preamble and capture offset": the string was NULL)
    add('sig preamble 4 (reproducer)', prism(sig(0x4, 0x1)))
    add('sig preamble 15', prism(sig(0xf | 0x10, 0x1)))
    # SIG B without SIG A (nothing is shown) and A1 without A2
    add('sig B alone', prism(dict(b=0x77)))
    add('sig A1 + B (no A2)', prism(dict(a1=0x13, b=0x77)))
    add('sig A2 + B (no A1)', prism(dict(a2=0x13, b=0x77)))
    add('sig A1 A2 only', prism(dict(a1=0x13, a2=0x13)))
    # type 2 and big endian variants of the SIG DIDs
    add('type2 sig HT', prism(sig(2 | (7 << 4), 0x1), t=2))
    add('type2 BE sig VHT', prism(vht(2, 0, 0, 1, 5, 1, 0, 0), t=2, bo='>'))
    add('type1 BE sig OFDM', prism(sig(0x30, 0x1), bo='>'))
    add('type1 BE sig HT, A1/A2 big-endian (read little-endian)', prism(sig(2 | (7 << 4), 0x1), bo='>', sigle=False))
    # The notree reproducer: Channel/Rate DIDs (radio metadata and
    # columns even when no tree is built)
    add('reproducer: channel 6, rate 11 Mb/s without a tree',
        prism(dict(host=1, mac=2, chan=6, rssi=50, sq=0, signal=50, noise=10,
                   rate=22, istx=0, frmlen=10), body=ack()))
    # AVS header behind the Prism link-layer type (the wlancap dissector)
    def avs(ver):
        n = 80 if ver == 2 else 64
        h = struct.pack('>IIQQIIIIIIiII', 0x80211000 + ver, n, 1, 2, 4, 6, 20, 1, 0, 2,
                        -40, 0xffffffa6, 2)
        h += struct.pack('>I', 1)
        if ver == 2:
            h += struct.pack('>II', 5, 0) + A2 + b'\0\0'
        return h
    add('AVS v1 behind prism link type', avs(1) + null_data())
    add('AVS v2 behind prism link type', avs(2) + null_data())
    # No Prism header: just 802.11
    add('no header: null data', null_data(9))
    add('no header: ack', ack())
    add('prism, ack body', prism(std(6, 2), body=ack()))
    add('prism, null from DS body', prism(std(6, 2), body=bytes([0x48, 0x02, 0, 0]) + A1 + A2 + A3 + b'\0\0'))
    pcap(os.path.join(outdir, 'prism-coverage.pcap'), DLT_PRISM, fr)

    mal = []
    mal.append(prism(std(6, 2))[:100])             # truncated header
    mal.append(prism(std(6, 2), body=b''))          # header only
    mal.append(prism(std(6, 2), body=b'\x48\x01\x00'))  # truncated 802.11
    mal.append(struct.pack('>I', 0x80211001))       # AVS cookie only
    mal.append(avs(2)[:30])                         # truncated AVS
    mal.append(b'\x44')                             # too short for a message code
    mal.append(prism(std(6, 2), bo='>', body=b'\x48'))
    pcap(os.path.join(outdir, 'prism-coverage-malformed.pcap'), DLT_PRISM, mal)
    if verbose:
        for i, n in enumerate(notes, 1):
            print(i, n)
        print('main frames:', len(fr), 'malformed frames:', len(mal))

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    build(out, '-v' in sys.argv)
