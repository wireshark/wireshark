#!/usr/bin/env python3
# Generates test/captures/awdl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic AWDL coverage captures (packet-awdl.c).

Usage: mkawdl.py <outdir>

Writes awdl-coverage.pcap (clean) and awdl-coverage-malformed.pcap.
Link type 105 (IEEE 802.11, no FCS). Every packet is built with struct;
nothing comes from a real network.
"""
import os
import random
import struct
import sys

STA1 = bytes.fromhex('020000000001')
STA2 = bytes.fromhex('020000000002')
STA3 = bytes.fromhex('020000000003')
BCAST = b'\xff' * 6


def pcap(fn, frames, linktype=105):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def action(tlvs, subtype=0, version=0x10, phy=100, target=50, seq=0):
    """802.11 vendor specific action frame, OUI 00:17:f2, AWDL type 8."""
    hdr = (bytes([0xd0, 0, 0, 0]) + BCAST + STA2 + STA2 +
           struct.pack('<H', seq << 4))
    awdl = (bytes([0x7f, 0x00, 0x17, 0xf2, 8, version, subtype, 0]) +
            struct.pack('<II', phy, target))
    return hdr + awdl + tlvs


def data(body, seq=0):
    """802.11 data frame, LLC/SNAP OUI 00:17:f2 PID 0x0800."""
    hdr = (bytes([0x08, 0, 0, 0]) + STA1 + STA2 + STA3 +
           struct.pack('<H', seq << 4))
    return hdr + bytes.fromhex('aaaa030017f20800') + body


def tlv(t, v):
    return struct.pack('<BH', t, len(v)) + v


def stlv(t, v):
    """Short TLV (one octet length) used in data frames."""
    return struct.pack('<BB', t, len(v)) + v


# ---------------------------------------------------------------- TLVs

def chanseq(enc, chans, dup=0, step=3, fill=0xffff):
    body = struct.pack('<BBBBH', len(chans) - 1, enc, dup, step, fill)
    for c in chans:
        if isinstance(c, tuple):
            body += bytes(c)
        else:
            body += bytes([c])
    return body


def sync_params(cs, txchan=6, master=STA2):
    b = struct.pack('<BHBBHHHHHHBBBB', txchan, 1234, 44, 0, 16, 110,
                    0x1800, 3, 3, 2, 3, 3, 3, 16)
    b += master + bytes([4, 0]) + struct.pack('<HH', 1000, 0)
    assert len(b) == 33
    return tlv(4, b + cs)


def election(flags=0, priv=False):
    b = struct.pack('<BHBB', flags, 7, 1, 0) + STA2 + struct.pack('<II', 600, 500)
    if priv:
        b += b'\x00\x00' + STA3 + struct.pack('<IIH', 650, 99, 12)
    return tlv(5, b)


def election_v2():
    b = STA2 + STA3 + struct.pack('<IIIIIII', 42, 1, 600, 500, 0, 0, 41)
    return tlv(24, b)


def service_params(bitmask, values, sui=5):
    b = b'\x00\x00\x00' + struct.pack('<HI', sui, bitmask) + bytes(values)
    return tlv(6, b)


def ht_caps(mcs, unknown=0, cap=0x11ce, ampdu=0x17):
    return tlv(7, struct.pack('<HHB', unknown, cap, ampdu) + bytes(mcs) + b'\x00\x00')


def version(v=0x3e, devclass=1, pad=b''):
    return tlv(21, bytes([v, devclass]) + pad)


def sync_tree(addrs, pad=b''):
    return tlv(20, b''.join(addrs) + pad)


def label(s):
    return bytes([len(s)]) + s


def comp(v):
    return struct.pack('>H', 0xc000 | v)


def arpa(name, flags=3):
    return tlv(16, bytes([flags]) + name)


def svc_resp(name, rtype, rdata, data_len=None, unknown=0):
    if data_len is None:
        data_len = len(rdata)
    return tlv(2, struct.pack('<H', len(name) + 1) + name + bytes([rtype]) +
               struct.pack('<HH', data_len, unknown) + rdata)


def srv(prio, weight, port, target):
    return struct.pack('>HHH', prio, weight, port) + target


def datapath(flags, country=b'US\x00', socmap=0x0007, bssid=STA3, infra_ch=36,
             infra_addr=STA1, awdl_addr=STA2, umi=1, umiopts=b'\x01\x02\x03',
             extflags=0, logtrigger=1, rlfc=2, active=(100, 200, 300)):
    b = struct.pack('<H', flags)
    if flags & 0x0100:
        b += country
    if flags & 0x0200:
        b += struct.pack('<H', socmap)
    if flags & 0x0001:
        b += bssid + struct.pack('<H', infra_ch)
    if flags & 0x0002:
        b += infra_addr
    if flags & 0x0004:
        b += awdl_addr
    if flags & 0x0010:
        b += struct.pack('<H', umi)
    if flags & 0x1000:
        b += struct.pack('<H', len(umiopts)) + umiopts
    if flags & 0x8000:
        b += struct.pack('<H', extflags)
        if extflags & 1:
            b += struct.pack('<H', logtrigger)
        if extflags & 4:
            b += struct.pack('<I', rlfc)
        if extflags & 0x40:
            b += struct.pack('<III', *active)
    return tlv(12, b)


def container(elem_id, body):
    return tlv(17, bytes([elem_id, len(body)]) + body)


VHT_CAP = struct.pack('<I', 0x0f8259b2) + struct.pack('<HHHH', 0xfffa, 0, 0xfffa, 0)

# ---------------------------------------------------------------- payloads


def csum(b):
    if len(b) % 2:
        b += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4_exp():
    # IPv4, protocol 253 (RFC 3692 experimentation), a few octets of data
    icmp = b'awdl data'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 1, 0, 64, 253, 0,
                     bytes([169, 254, 1, 1]), bytes([169, 254, 1, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + icmp


def ipv6_nonext():
    src = bytes.fromhex('fe800000000000000000000000000001')
    dst = bytes.fromhex('fe800000000000000000000000000002')
    return struct.pack('!IHBB', 0x60000000, 0, 59, 64) + src + dst


def awdl_data_short(seq, etype, payload):
    return data(b'\x04\x08' + struct.pack('<H', seq) + b'\x00\x00' +
                struct.pack('>H', etype) + payload)


def awdl_data_long(seq, tags, etype, payload, hdr1=b'\x00\x00', hdr2=b''):
    return data(b'\x04\x08' + struct.pack('<H', seq) +
                b'\x03' + bytes([len(hdr1)]) + hdr1 + tags +
                b'\x03' + bytes([len(hdr2)]) + hdr2 +
                struct.pack('>H', etype) + payload)


# ---------------------------------------------------------------- frames

def clean_frames():
    fr = []
    # 1: PSF, sync params with channel number encoding (16 channels),
    # election v1, version, sync tree
    cs16 = chanseq(0, [6] * 4 + [44] * 4 + [149] * 4 + [6] * 4)
    fr.append(action(sync_params(cs16) + election() + version() +
                     sync_tree([STA2, STA3]), subtype=0))
    # 2: MIF, sync params with legacy encoding, private election v1,
    # election v2, service params, HT caps, data path state, ARPA, version
    leg = chanseq(1, [(0x51, 6), (0x51, 6), (0x1d, 44), (0x1e, 149)])
    fr.append(action(sync_params(leg) + election(flags=1, priv=True) +
                     election_v2() + service_params(0, []) +
                     ht_caps([0xff]) + datapath(0x0004) +
                     arpa(label(b'Alice-iPhone') + comp(0x0c)) + version(0x3e, 2),
                     subtype=3))
    # 3: channel sequence TLV, operating class encoding
    fr.append(action(tlv(18, chanseq(3, [(6, 0x51), (44, 0x80), (149, 0x80)])), subtype=3))
    # 4: channel sequence, unknown encoding 2 (no channel list), then padding
    fr.append(action(tlv(18, chanseq(2, [0, 0]) + b'\x00\x00'), subtype=3))
    # 5: service response TXT (three strings), SRV, PTR
    txt = label(b'txtvers=1') + label(b'model=MacBookPro') + label(b'')
    fr.append(action(
        svc_resp(label(b'Alice') + comp(0x07), 16, txt) +
        svc_resp(label(b'Alice') + comp(0x07), 33,
                 srv(0, 0, 8770, label(b'alice-mbp') + comp(0x0c))) +
        svc_resp(comp(0x07), 12, label(b'Alice') + comp(0x07)),
        subtype=3))
    # 6: every compression value, unknown compression, NULL compression,
    # and an unknown record type
    allc = b''.join(comp(i) for i in range(0, 15)) + comp(0x3f)
    fr.append(action(
        svc_resp(allc, 12, comp(0)) +
        svc_resp(label(b'x') + comp(0x0b), 1, b'\x7f\x00\x00\x01') +
        svc_resp(comp(0x01), 16, b''),
        subtype=3))
    # 7: service params with a bitmask and values (several bits each)
    fr.append(action(service_params(0x80000005, [0x81, 0xff, 0x10]) +
                     service_params(0x00000002, [0x01]), subtype=3))
    # 8: HT capabilities, 1 to 4 streams
    fr.append(action(ht_caps([0xff]) + ht_caps([0xff, 0xff]) +
                     ht_caps([0xff, 0xff, 0xff]) +
                     ht_caps([0xff, 0xff, 0xff, 0xff], cap=0xffff, ampdu=0xff),
                     subtype=3))
    # 9: the reproducer from awdl_ht_streams0.py: HT capabilities whose
    # first Rx MCS octet is zero, followed by a Version TLV
    fr.append(action(tlv(7, b'\x00\x00' + b'\x2c\x01' + b'\x17' + b'\x00\xff\x00\x00' + b'\x00\x00') +
                     tlv(21, b'\x3e\x01')))
    # 10: data path state, every flag and extended flag
    fr.append(action(datapath(0xffff, extflags=0xffff), subtype=3))
    # 11: data path state, single social channel number, ext flags without
    # optional fields, every other optional field off
    fr.append(action(datapath(0x8200, socmap=44, extflags=0x0002) +
                     datapath(0x0000) +
                     datapath(0x1013, umiopts=b''), subtype=3))
    # 12: IEEE 802.11 container (VHT capabilities), ARPA with NULL
    # compression only (empty name) and with a plain label
    fr.append(action(container(191, VHT_CAP) + arpa(comp(0), flags=0) +
                     arpa(label(b'host') + label(b'local')), subtype=3))
    # 13: sync tree with a trailing partial address (padding), empty sync
    # tree, version with padding, every devclass
    fr.append(action(sync_tree([STA1, STA2, STA3], pad=b'\x00\x00') +
                     sync_tree([]) + version(0x10, 4, pad=b'\x00\x00') +
                     version(0x3e, 8) + version(0x21, 3), subtype=3))
    # 14: undecoded TLVs (note expert info) and an unknown TLV number,
    # an empty one
    fr.append(action(b''.join(tlv(t, b'\x01\x02') for t in
                             (0, 1, 3, 8, 9, 10, 11, 13, 14, 15, 19, 22, 23, 25, 200)) +
                     tlv(11, b''), subtype=3))
    # 15: unknown subtype and version, Tx delay that wraps
    fr.append(action(version(), subtype=7, version=0x21, phy=10, target=20))
    # 16: sync params with 1 channel
    fr.append(action(sync_params(chanseq(0, [149])), subtype=0))
    # 17-24: AWDL data frames
    fr.append(awdl_data_short(1, 0x0800, ipv4_exp()))
    fr.append(awdl_data_short(2, 0x86dd, ipv6_nonext()))
    fr.append(awdl_data_short(3, 0x88b5, b'unknown ethertype payload'))
    fr.append(awdl_data_long(4, b'', 0x86dd, ipv6_nonext()))
    fr.append(awdl_data_long(5, stlv(21, b'\x3e\x01') +
                             stlv(20, STA2) + stlv(1, b'xy'), 0x0800, ipv4_exp(),
                             hdr1=b'\x01\x02\x03\x04', hdr2=b'\x05\x06'))
    fr.append(awdl_data_long(6, stlv(12, struct.pack('<H', 0x0004) + STA2) , 0x88b5, b''))
    fr.append(awdl_data_short(7, 0x86dd, ipv6_nonext()))
    fr.append(awdl_data_long(8, stlv(7, struct.pack('<HHB', 0, 0x11ce, 0x17) + b'\xff\xff\x00\x00'),
                             0x86dd, ipv6_nonext(), hdr1=b''))
    return fr


def malformed_frames():
    fr = []
    # TLV length longer than the frame
    fr.append(action(struct.pack('<BH', 21, 50) + b'\x3e\x01'))
    # TXT data length too short for the strings
    fr.append(action(svc_resp(comp(1), 16, label(b'abcdef') + label(b'gh'), data_len=3)))
    # name length 0 (len - 1 wraps)
    fr.append(action(tlv(2, b'\x00\x00\x05\x00\x00\x00\x00')))
    # truncated TLVs of every decoded type
    for t in (2, 4, 5, 6, 7, 12, 16, 17, 18, 20, 21, 24):
        fr.append(action(tlv(t, b'\x01')))
        fr.append(action(tlv(t, b'')))
    # data path state with a umi options length past the end
    fr.append(action(tlv(12, struct.pack('<HH', 0x1000, 40) + b'ab')))
    # service params: bitmask with more bits than values
    fr.append(action(tlv(6, b'\x00\x00\x00\x05\x00\xff\xff\xff\xff' + b'\x01')))
    # election v1 private flag without the private part
    fr.append(action(tlv(5, struct.pack('<BHBB', 1, 7, 1, 0) + STA2 + struct.pack('<II', 600, 500))))
    # channel sequence with more channels than data
    fr.append(action(tlv(18, struct.pack('<BBBBH', 15, 0, 0, 3, 0) + b'\x06')))
    fr.append(action(tlv(18, struct.pack('<BBBBH', 15, 1, 0, 3, 0) + b'\x51\x06')))
    fr.append(action(tlv(18, struct.pack('<BBBBH', 15, 3, 0, 3, 0) + b'\x06\x51')))
    # sync params too short for the channel sequence
    fr.append(action(tlv(4, b'\x01\x00')))
    # 802.11 container element too long
    fr.append(action(tlv(17, b'\xbf\x0c' + bytes(4))))
    fr.append(action(tlv(17, b'\xdd\x05' + bytes(5))))
    # no TLVs at all: the tagged parameters item throws (observation 1)
    fr.append(action(b'', subtype=7))
    # AWDL fixed part truncated
    fr.append(action(b'')[:-6])
    # data frames: truncated header, long header without terminator,
    # truncated short TLV
    fr.append(data(b'\x04\x08\x01'))
    fr.append(data(b'\x04\x08\x01\x00\x03\x00' + stlv(21, b'\x3e\x01')))
    fr.append(data(b'\x04\x08\x01\x00\x03\x00\x15\x09\x3e'))
    fr.append(data(b'\x04\x08\x01\x00\x03\x20abc'))
    # random mutations of clean frames
    rnd = random.Random(1)
    seeds = clean_frames()
    for _ in range(400):
        f = bytearray(rnd.choice(seeds))
        start = 36 if f[0] == 0xd0 else 32
        for _ in range(rnd.randint(1, 4)):
            if len(f) <= start + 1:
                break
            p = rnd.randrange(start, len(f))
            r = rnd.random()
            if r < 0.6:
                f[p] = rnd.randrange(256)
            elif r < 0.8:
                del f[p:p + rnd.randint(1, 4)]
            else:
                f[p:p] = bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 8)))
        fr.append(bytes(f))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'awdl-coverage.pcap'), clean_frames())
    pcap(os.path.join(out, 'awdl-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
