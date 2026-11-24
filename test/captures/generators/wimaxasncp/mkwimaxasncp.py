#!/usr/bin/env python3
# Generates test/captures/wimaxasncp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the WiMAX ASN CP (UDP 2231) coverage captures.

Usage: mkwimaxasncp.py <outdir> [-v]

Writes wimaxasncp-coverage.pcap (valid and merely unusual packets) and
wimaxasncp-coverage-malformed.pcap (error paths).  Everything is built
with struct; the TLV table is read from the dictionary in the tree
(resources/protocols/wimaxasncp/dictionary.xml), the message tables from
the dissector source.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
import xml.etree.ElementTree as ET

TREE = os.environ.get("WSTREE", os.path.join(SRCDIR))
DICT = TREE + "/resources/protocols/wimaxasncp/dictionary.xml"
SRC = TREE + "/plugins/epan/wimaxasncp/packet-wimaxasncp.c"


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(payload, sport, dport=2231, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def tlv(t, v):
    return struct.pack('!HH', t, len(v)) + v


def asncp(tlvs=b'', ft=1, msg=1, op=1, flags=0, tid=0x0001, lenfix=None, ver=1,
          msid=b'\x02\x00\x00\x00\x00\x09', res1=0, res2=0):
    body = msid + struct.pack('!IHH', res1, tid, res2) + tlvs
    total = 6 + len(body) if lenfix is None else lenfix
    return struct.pack('!BBBBH', ver, flags, ft, (op << 5) | (msg & 0x1f), total) + body


# ---- dictionary --------------------------------------------------------
def load_dict():
    root = ET.parse(DICT).getroot()
    out = []
    for t in root.findall('tlv'):
        ty = t.get('type')
        ty = int(ty, 16) if ty.lower().startswith('0x') else int(ty)
        enums = []
        for e in t.findall('enum'):
            c = e.get('code')
            if c.lower().startswith('0x'):
                enums.append(int(c, 16))
            elif c.isdigit():
                enums.append(int(c))
            else:
                m = re.match(r'WIMAXASNCP_BIT(\d+)\((\d+)\)$', c)
                if m:
                    enums.append(1 << (int(m.group(1)) - 1 - int(m.group(2))))
        out.append((ty, t.get('decoder'), enums, t.get('name'), int(t.get('since') or 0)))
    return out


def load_dict_eff():
    """One definition per type: the one the default NWG version (1.2.1) uses."""
    best = {}
    for e in load_dict():
        if e[0] not in best or e[4] > best[e[0]][4]:
            best[e[0]] = e
    return [e[:4] for e in best.values()]


def load_msgs():
    """(function type, message type) pairs of the dissector's tables."""
    src = open(SRC).read()
    fts = {'QOS': 1, 'HO_CONTROL': 2, 'DATA_PATH_CONTROL': 3, 'CONTEXT_TRANSFER': 4,
           'R3_MOBILITY': 5, 'PAGING': 6, 'RRM': 7, 'AUTHENTICATION': 8,
           'MS_STATE': 9, 'IM_OPERATIONS': 10, 'ACCOUNTING': 11}
    m = re.search(r'wimaxasncp_func_to_msg_vals_map\[\] =\s*\{(.*?)\};', src, re.S)
    pairs = []
    for ft, arr in re.findall(r'WIMAXASNCP_FT_(\w+),\s*(\w+)\s*\}', m.group(1)):
        a = re.search(arr + r'\[\] =\s*\{(.*?)\};', src, re.S)
        for code in re.findall(r'\{\s*(\d+),\s*"', a.group(1)):
            pairs.append((fts[ft], int(code)))
    return sorted(set(pairs))


def rb(n, seed):
    return bytes((seed * 31 + i * 7 + 3) & 0xff for i in range(n))


LONG_DONE = []


def values(dec, enums, seed):
    """Valid values for a decoder, then wrong-length ones."""
    ok, bad = [], []
    if dec in ('WIMAXASNCP_TLV_ENUM8', 'WIMAXASNCP_TLV_ENUM16', 'WIMAXASNCP_TLV_ENUM32'):
        n = {'8': 1, '16': 2, '32': 4}[dec.split('ENUM')[1]]
        cs = (enums[:1] + enums[-1:] if enums else []) + [(1 << (8 * n)) - 2]
        ok = [c.to_bytes(n, 'big') for c in cs]
        bad = [b'', rb(n + 1, seed)] + ([rb(30, seed)] if seed >= 1000 and not LONG_DONE else [])
        if seed >= 1000:
            LONG_DONE.append(1)   # more than 24 octets: "..."
    elif dec.startswith('WIMAXASNCP_TLV_BITFLAGS'):
        n = int(dec[len('WIMAXASNCP_TLV_BITFLAGS'):]) // 8
        ok = [b'\xff' * n, bytes(n), (enums[0] if enums else 1).to_bytes(n, 'big')]
        bad = [rb(n + 1, seed)]
    elif dec == 'WIMAXASNCP_TLV_ETHER':
        ok = [b'\x00\x11\x22\x33\x44\x55']; bad = [rb(5, seed)]
    elif dec == 'WIMAXASNCP_TLV_ASCII_STRING':
        ok = [b'name-%d' % seed, b'']
    elif dec == 'WIMAXASNCP_TLV_FLAG0':
        ok = [b'']; bad = [b'\x01']
    elif dec == 'WIMAXASNCP_TLV_ID':
        ok = [rb(4, seed), rb(6, seed), rb(16, seed)]; bad = [rb(5, seed), b'']
    elif dec in ('WIMAXASNCP_TLV_BYTES', 'WIMAXASNCP_TLV_TBD', 'WIMAXASNCP_TLV_UNKNOWN'):
        ok = [b'', rb(5, seed), rb(24, seed), rb(30, seed)]
    elif dec in ('WIMAXASNCP_TLV_HEX8', 'WIMAXASNCP_TLV_DEC8'):
        ok = [rb(1, seed)]; bad = [rb(2, seed)]
    elif dec in ('WIMAXASNCP_TLV_HEX16', 'WIMAXASNCP_TLV_DEC16'):
        ok = [rb(2, seed)]; bad = [rb(3, seed)]
    elif dec in ('WIMAXASNCP_TLV_HEX32', 'WIMAXASNCP_TLV_DEC32'):
        ok = [rb(4, seed)]; bad = [rb(5, seed)]
    elif dec == 'WIMAXASNCP_TLV_IP_ADDRESS':
        ok = [bytes([10, 0, 0, seed & 255]), rb(16, seed)]; bad = [rb(5, seed)]
    elif dec == 'WIMAXASNCP_TLV_IPV4_ADDRESS':
        ok = [bytes([10, 1, 0, seed & 255])]; bad = [rb(5, seed)]
    elif dec == 'WIMAXASNCP_TLV_PROTOCOL_LIST':
        ok = [struct.pack('!H', 6), struct.pack('!5H', 1, 6, 17, 47, 255),
              struct.pack('!10H', *range(1, 11)), b'']
        bad = [rb(3, seed)]
    elif dec == 'WIMAXASNCP_TLV_PORT_RANGE_LIST':
        ok = [struct.pack('!HH', 80, 90), struct.pack('!8H', 1, 2, 3, 4, 5, 6, 7, 8),
              struct.pack('!HHHH', 1000, 2000, 3000, 4000), b'']
        bad = [rb(6, seed)]
    elif dec == 'WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST':
        ok = [rb(8, seed), rb(24, seed), rb(32, seed), rb(64, seed), b'']
        bad = [rb(12, seed)]
    elif dec == 'WIMAXASNCP_TLV_EAP':
        ok = [struct.pack('!BBHB', 1, 1, 5, 1),                      # request identity
              struct.pack('!BBHB', 2, 2, 5 + 4, 1) + b'user',      # response identity
              struct.pack('!BBH', 3, 3, 4), struct.pack('!BBH', 4, 4, 4),
              struct.pack('!BBH', 9, 5, 4)]                        # unknown code
    elif dec == 'WIMAXASNCP_TLV_VENDOR_SPECIFIC':
        ok = [b'\x00\x00\x09', b'\x00\x00\x09' + rb(6, seed), b'\x00\x00\x00\x01\x02']
        bad = [b'\x00\x01']
    return ok, bad


def build():
    d = load_dict_eff()
    pairs = load_msgs()
    frames = []
    ranges = []
    port = [30000]

    def add(label, pkts):
        start = len(frames) + 1
        for p in pkts:
            port[0] += 1
            frames.append(frame(p, port[0]))
        ranges.append((label, start, len(frames)))

    # 1. one header only frame per known (function type, message type)
    pk = []
    for i, (ft, msg) in enumerate(pairs):
        pk.append(asncp(ft=ft, msg=msg, op=(i % 4) + 1, flags=(i * 5) & 0xff,
                        tid=0x8000 | i if i % 3 == 0 else i, res1=i))
    add('header only: every known function/message type', pk)

    # 2. unknown function type, message types, op ids (the reproducer)
    add('unknown function type 18 message 1 and 2 (fix reproducer), unknown message types, version 2 (not ASN CP)',
        [asncp(ft=18, msg=1), asncp(ft=18, msg=2), asncp(ft=1, msg=0), asncp(ft=1, msg=31, op=0),
         asncp(ft=0, msg=0, op=7), asncp(ft=11, msg=3), asncp(ft=10, msg=20),
         asncp(ft=1, msg=1, ver=2)])

    # 3. every TLV type of the dictionary, simple ones, many per frame
    simple = []   # (type, value) usable inside compounds
    batches = []
    seen = set()
    for seed, (ty, dec, enums, name) in enumerate(d):
        if dec == 'WIMAXASNCP_TLV_COMPOUND':
            continue
        ok, bad = values(dec, enums, seed)
        if ty not in seen and ok:
            simple.append((ty, ok[1] if len(ok) > 1 and dec != 'WIMAXASNCP_TLV_EAP' else ok[0]))
        seen.add(ty)
        batches.append([tlv(ty, v) for v in ok])
    # unknown types, a type used by the dictionary with 'since'
    batches.append([tlv(0, b''), tlv(0xfffe, b'\x01\x02'), tlv(1234, rb(30, 1)), tlv(999, b'')])
    pk = []
    cur = b''
    ft = 1
    for b in batches:
        t = b''.join(b)
        if len(cur) + len(t) > 1100:
            pk.append(cur)
            cur = b''
        cur += t
    pk.append(cur)
    add('every simple TLV type with valid values', [asncp(c, ft=1 + i % 11, msg=1 + i % 3, op=1 + i % 4)
                                                    for i, c in enumerate(pk)])

    # 4. wrong lengths (hex dump fallback)
    pk = []
    cur = b''
    for seed, (ty, dec, enums, name) in enumerate(d):
        if dec == 'WIMAXASNCP_TLV_COMPOUND':
            continue
        ok, bad = values(dec, enums, seed + 1000)
        for v in bad:
            t = tlv(ty, v)
            if len(cur) + len(t) > 1100:
                pk.append(cur)
                cur = b''
            cur += t
    pk.append(cur)
    add('TLVs with a length the decoder does not accept (shown as bytes)',
        [asncp(c, ft=2, msg=1) for c in pk])

    # 5. compounds
    comps = [(ty, name) for ty, dec, enums, name in d if dec == 'WIMAXASNCP_TLV_COMPOUND']
    pk = []
    cur = b''
    for i, (ty, name) in enumerate(comps):
        kids = b''.join(tlv(t, v) for t, v in simple[(i * 3) % len(simple):(i * 3) % len(simple) + 3])
        t = tlv(ty, kids)
        if len(cur) + len(t) > 1100:
            pk.append(cur)
            cur = b''
        cur += t
    pk.append(cur)
    c0 = comps[0][0]
    c1 = comps[1][0]
    nested = tlv(c0, tlv(c1, tlv(c0, tlv(simple[0][0], simple[0][1]) + tlv(c1, tlv(simple[1][0], simple[1][1])))))
    pk.append(nested + tlv(c0, b'') + tlv(c1, tlv(1234, b'\x01')))
    deep = tlv(simple[2][0], simple[2][1])
    for i in range(12):
        deep = tlv(comps[i % len(comps)][0], deep)
    pk.append(deep)
    add('every compound TLV type with three children, nested and empty compounds, 12 levels',
        [asncp(c, ft=3, msg=2) for c in pk])

    # 6. EAP with different codes inside a compound, DHCP-ish; header variants
    eap_ty = [ty for ty, dec, e, n in d if dec == 'WIMAXASNCP_TLV_EAP'][0]
    vs_ty = [ty for ty, dec, e, n in d if dec == 'WIMAXASNCP_TLV_VENDOR_SPECIFIC'][0]
    add('EAP payload and vendor specific TLVs, a second EAP message',
        [asncp(tlv(eap_ty, struct.pack('!BBHB', 1, 7, 9, 13) + b'\x20\x00\x00\x00'), ft=8, msg=1),
         asncp(tlv(eap_ty, struct.pack('!BBHB', 2, 8, 5, 3)), ft=8, msg=2),
         asncp(tlv(vs_ty, b'\x00\x00\x0b' + rb(10, 1)), ft=8, msg=3)])

    # 7. header variants: D bit, flags, reserved, trailing data, longer total
    add('transaction ID with the D bit, flag combinations, reserved fields, length larger than the datagram header, extra octets',
        [asncp(tid=0x8123, flags=0x01), asncp(tid=0x0123, flags=0x02), asncp(tid=0xffff, flags=0xff),
         asncp(res1=0xdeadbeef, res2=0xbeef), asncp(tlv(1, b'\x01') + tlv(2, b'\x00'), lenfix=None)])

    # reproducer: type 229 (ASCII string since the dictionary fix)
    add('Service Class Name (type 229) after the dictionary decoder fix',
        [asncp(tlv(229, b'gold-class'), ft=1, msg=1)])

    # keep a copy of the "since" reps
    return frames, ranges


def build_malformed():
    d = load_dict_eff()
    comps = [ty for ty, dec, e, n in d if dec == 'WIMAXASNCP_TLV_COMPOUND']
    fr = []
    port = [31000]

    def add(p, **kw):
        port[0] += 1
        fr.append(frame(p, port[0]))

    add(asncp(lenfix=19))                   # length less than header size, > 6
    add(asncp(lenfix=7))
    add(asncp(lenfix=4))                    # length at most 6
    add(asncp(tlv(1, b'\x01') + b'\x00\x02\x00'))      # TLV header cut short
    add(asncp(struct.pack('!HH', 1, 40) + b'\x01'))     # TLV longer than data
    add(asncp(struct.pack('!HH', comps[0], 40) + b''))   # compound, no data
    add(asncp(struct.pack('!HH', comps[0], 40) + b'\x00\x01\x00\x01\x00'))  # compound longer
    add(asncp(b'', lenfix=40))                           # length beyond data
    add(b'\x01\x00\x01')                                  # truncated header
    add(b'\x01')
    deep = tlv(1, b'\x01')
    for i in range(260):
        deep = tlv(comps[0], deep)
    add(asncp(deep, ft=1, msg=1))                         # nesting past the tree limit
    # types whose definition differs between the NWG versions (the
    # "since" attribute): wrong for the default version, right for others
    since = sorted({e[0] for e in load_dict() if e[4]})
    for i in range(0, len(since), 20):
        add(asncp(b''.join(tlv(t, rb(4, t)) for t in since[i:i + 20]), ft=1 + i % 4, msg=1))
    return fr


if __name__ == '__main__':
    out = sys.argv[1]
    frames, ranges = build()
    write_pcap(os.path.join(out, 'wimaxasncp-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'wimaxasncp-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        for l, a, b in ranges:
            print('%d-%d: %s' % (a, b, l))
        print('total', len(frames))
