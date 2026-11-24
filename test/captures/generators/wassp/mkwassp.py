#!/usr/bin/env python3
# Generates test/captures/wassp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the WASSP dissector (packet-wassp.c,
Wireless Access Station Session Protocol between Extreme/Enterasys/
Motorola wireless controllers and access points).

WASSP runs over UDP 13910 (and 13907 for the access point discovery); the
UDP heuristic is disabled by default. A message is a header (version 3,
type, sequence number and flags, session id, length) followed by TLVs;
data messages (type 15) carry a mobile unit (MU) header and an Ethernet
frame or TLVs. TLV types are listed in one main table; block TLVs hold
sub-TLVs that are decoded with one of 85 sub-tables (nesting up to 16
levels). Messages can be fragmented (use-fragmentation flag) and are
reassembled per conversation.

The TLV ids, their kinds and the table nesting come from wassp_data.py,
which extract_wassp.py wrote from the tables in packet-wassp.c (they are
protocol constants, not captured data). Every packet is built with struct;
nothing comes from a real network. Addresses are from 192.0.2.0/24.

Usage: mkwassp.py <output directory>

Writes:
  wassp-coverage.pcapng            main capture (UDP and Exported PDU)
  wassp-coverage-malformed.pcapng  paths only malformed input reaches
"""
import os
import struct
import sys

import wassp_data as D

P = struct.pack
TABNO = {n: i for i, (n, v) in enumerate(D.TABS)}
MAINNO = {e: i for i, (e, k, h) in enumerate(D.MAIN)}

LT_ETH, LT_EXPPDU = 1, 252

# ----------------------------------------------------------------- pcapng


def pcapng(path, frames):
    """frames: (interface, bytes); interface 0 Ethernet, 1 Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return P('<II', btype, ln) + body + P('<I', ln)
    out = block(0x0A0D0D0A, P('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, P('<HHI', LT_ETH, 0, 262144))
    out += block(1, P('<HHI', LT_EXPPDU, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, P('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                          len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IDENT = [1]


def eth_udp(payload, sport=13910, dport=13910, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = P('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    IDENT[0] += 1
    ip = P('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), IDENT[0] & 0xffff, 0, 64, 17, 0,
           bytes(src), bytes(dst))
    ip = ip[:10] + P('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


def exppdu(proto, payload):
    name = proto.encode()
    name += b'\0' * ((4 - len(name) % 4) % 4)
    return P('>HH', 12, len(name)) + name + P('>HH', 0, 0) + payload


# --------------------------------------------------------------- messages

# flags in the low 6 bits of the sequence/flags field
F_MORE, F_DATA, F_NOTFIRST, F_USEFRAG = 0x01, 0x02, 0x04, 0x08


def hdr(mtype, payload, seq=1, flags=0, session=0x1234, length=None, version=3):
    return P('>BBHHH', version, mtype, (seq << 6) | flags, session,
             8 + len(payload) if length is None else length) + payload


def tlv(t, value):
    return P('>HH', t, 4 + len(value)) + value


def value_for(kind):
    return {'STRING': b'ap-test\0', 'INT': P('>I', 2), 'UINT': P('>I', 3),
            'BOOL': P('>I', 1), 'OCTETS': bytes(range(8)),
            'MACADD': bytes([2, 0, 0, 0, 0, 7]), 'INDEX': P('>I', 4),
            'IP_ADDR': bytes([192, 0, 2, 9]), 'UNKNOWN': bytes(range(8))}[kind]


# special decoders: (table enum name or None for the main table, EID) ->
# value of the right size
FILTER_ANY = bytes((i * 7) & 0xff for i in range(720))
SPECIAL = {
    'EID_FILTER_RULES': FILTER_ANY, 'EID_V_FILTER_RULES': FILTER_ANY,
    'EID_V_SITE_FILTER_RULES': FILTER_ANY,
    'EID_MU_MAC_LIST': bytes(range(12)),
    'EID_ON_DEMAND_ARRAY': bytes(range(12)), 'EID_DYN_ON_DEMAND_ARRAY': bytes(range(18)),
    'EID_COS': bytes([1, 2, 3, 4, 5, 6, 7, 8]),
    'EID_V_COS': bytes([1, 2, 3, 4, 5, 6, 7, 8]),
    'EID_RATE_LIMIT_RESOURCE_TBL': P('>HHHH', 100, 200, 300, 400),
    'EID_V_RATE_LIMIT_RESOURCE_TBL': P('>HHHH', 100, 200, 300, 400),
    'EID_CHANNEL_LIST': P('>HHHH', 2412, 2437, 2462, 5180),
    'EID_DNS_IP_ADDR': bytes([192, 0, 2, 1, 192, 0, 2, 2]),
    'EID_MU_APPL_STATS_BLOCK': P('>I', 2) + bytes([2, 0, 0, 0, 0, 1]) + P('>HHII', 1, 2, 300, 400)
                               + bytes([2, 0, 0, 0, 0, 2]) + P('>HHII', 3, 4, 500, 600),
    'EID_SCAN_RSS_RSSI': P('>HH', 200, 100), 'EID_PARAMS': P('>BBH', 1, 2, 2412),
    'EID_STATUS': P('>I', 1),
}


# The dissector prints topology modes when a sub-TLV of the site table has
# type EID_SITE_TOPOLOGY_BLOCK (80 as an enumerator, though the table row of
# that name is row 76): row 80 then holds the key and mode
SITE_ROW80 = [None]


def build_table(n, depth, maxdepth, only=None):
    """All rows of sub-table n as sub-TLVs. Block rows hold the nested table
    (one level less) until maxdepth."""
    var = D.TABS[n][1]
    out = b''
    for i, (eid, kind, nested) in enumerate(D.TABVARS[var]):
        if only is not None and i not in only:
            continue
        if kind == 'BLOCK_TLV':
            if depth + 1 < maxdepth:
                out += tlv(i, build_table(nested, depth + 1, maxdepth))
            else:
                out += tlv(i, b'')
        elif D.TABS[n][0] == 'TAB_CONFIG_SITE' and i == 80 and SITE_ROW80[0] is not None:
            out += tlv(i, P('>HH', 1, SITE_ROW80[0]))
        elif D.TABS[n][0] == 'TAB_FILTER_CONFIG_STRUCT_BLOCK' and i in (2, 5):
            # this table is the main table, but the dissector compares the
            # type with the (other) filter rule ids 2 and 5 and then needs 20 octets
            out += tlv(i, bytes(range(20)))
        elif eid in SPECIAL:
            out += tlv(i, SPECIAL[eid])
        else:
            out += tlv(i, value_for(kind))
    return out


def _paths():
    paths = {}
    for mi, (e, k, h) in enumerate(D.MAIN):
        if h.startswith('sub:'):
            paths.setdefault(TABNO[h[4:]], [mi])
    changed = True
    while changed:
        changed = False
        for n, p in list(paths.items()):
            for i, (eid, kind, nested) in enumerate(D.TABVARS[D.TABS[n][1]]):
                if kind == 'BLOCK_TLV' and nested not in paths:
                    paths[nested] = p + [i]
                    changed = True
    return paths


PATHS = _paths()


def table_msg_body(n, maxdepth=1):
    """The TLVs that lead to sub-table n (nested block TLVs) holding all
    its rows."""
    while True:
        try:
            inner = build_table(n, 0, maxdepth)
            for t in reversed(PATHS[n]):
                inner = tlv(t, inner)
            return inner
        except struct.error:
            if maxdepth <= 1:
                raise
            maxdepth -= 1


def table_tlv(t, n, maxdepth):
    """TLV t holding sub-table n, with fewer nested levels if it gets too big."""
    while True:
        try:
            body = build_table(n, 0, maxdepth)
            if len(body) < 30000 or maxdepth <= 1:
                return tlv(t, body)
        except struct.error:
            if maxdepth <= 1:
                raise
        maxdepth -= 1


def main_tlv(i, maxdepth=2):
    eid, kind, handler = D.MAIN[i]
    if handler.startswith('sub:'):
        return table_tlv(i, TABNO[handler[4:]], maxdepth)
    if eid in SPECIAL:
        return tlv(i, SPECIAL[eid])
    if handler == 'hf_wassp_macaddr' or handler == 'hf_wassp_mu_mac':
        return tlv(i, bytes([2, 0, 0, 0, 0, 5]))
    if handler == 'hf_wassp_tlv_value_ip':
        return tlv(i, bytes([192, 0, 2, 7]))
    if handler == 'hf_wassp_tlv_value_string':
        return tlv(i, b'wassp-%d\0' % i)
    if handler == 'hf_wassp_tlv_value_octext':
        return tlv(i, bytes(range(i % 7 + 1, i % 7 + 9)))
    return tlv(i, P('>I', i))


# RU message types that carry TLVs (the goto tlv_dissect list)
TLV_TYPES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23,
             24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
             44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 56, 57, 58, 59, 60, 61, 62, 63, 64,
             65, 66, 67, 68, 101, 102, 103, 104]
OTHER_TYPES = [0, 43, 54, 69, 70, 71, 105, 200]

MAC = bytes([2, 0, 0, 0, 0, 0x33])
# the filter rule decoders read four octets past the value
PAD = tlv(2, b'padpadpad')


def mu_hdr(mtype, action=0x0105, assoc_status=None):
    h = P('>BBH', mtype, 5, action) + MAC + P('>HH', 0x1111, 0x2222)
    if assoc_status is not None:
        h += bytes([assoc_status])
    return h


def small_eth_frame():
    ip = P('!BBHHHBBH4s4s', 0x45, 0, 20 + 8 + 4, 1, 0, 64, 17, 0,
           bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + P('!H', csum(ip)) + ip[12:]
    return (bytes.fromhex('020000000009020000000008') + b'\x08\x00' + ip
            + P('!HHHH', 5000, 5001, 12, 0) + b'abcd')


def deep(n, leaf_value=b'', eid=59):
    """Main TLV 59 holding n nested block TLVs 59 (each holds the next) and
    a leaf: the deepest dissect_wassp_sub_tlv() call has depth n."""
    inner = tlv(MAINNO['EID_RU_SW_VERSION'], b'deep\0\0\0\0') if not leaf_value else leaf_value
    for _ in range(n):
        inner = tlv(eid, inner)
    return inner


def build_main():
    frames = []
    marks = []

    def add(payload, sport=13910, dport=13910, ifc=0):
        frames.append((ifc, eth_udp(payload, sport, dport)))

    def mark(name):
        marks.append((name, len(frames) + 1))

    # ---- discovery on 13907
    mark('discover')
    for op, tail in ((1, MAC), (2, P('>H', 3)), (0, P('>H', 0)), (1, MAC)):
        body = P('>BBHHHH', 3, 1, 0x4321, 0, 0, op) + tail
        body += tlv(MAINNO['EID_RU_SW_VERSION'], b'1.0\0') + tlv(MAINNO['EID_RU_SERIAL_NUMBER'], b'SN1\0')
        add(body, 13907, 13907)
    # ---- messages with a few TLVs, every type that carries TLVs
    mark('simple')
    sw = MAINNO['EID_RU_SW_VERSION']
    st = MAINNO['EID_STATUS']
    for t in TLV_TYPES:
        body = tlv(st, P('>I', 1)) + tlv(sw, b'3.1\0') + tlv(MAINNO['EID_RADIO_ID'], P('>I', 1))
        add(hdr(t, body, seq=t))
    # status of the software version command (an action)
    add(hdr(7, tlv(st, P('>I', 5)) + tlv(MAINNO['EID_IMAGE_PATH'], b'/img\0\0\0\0')))
    # types that carry no TLVs, the empty message, short TLV bodies
    mark('other')
    for t in OTHER_TYPES:
        add(hdr(t, bytes(range(16))))
    add(hdr(14, b'\x30\x05\x02\x01\x00\x04\x00'))
    add(hdr(8, b''))
    add(hdr(8, tlv(st, b'')))
    add(hdr(8, tlv(sw, b'')))
    # ---- the big TLV messages: every main TLV type, in chunks
    mark('main-tlvs')
    chunk = b''
    for i in range(1, len(D.MAIN)):
        t = main_tlv(i, 1)
        if len(chunk) + len(t) > 40000:
            add(hdr(9, chunk))
            chunk = b''
        chunk += t
    add(hdr(9, chunk))
    # an unknown main TLV type, a main TLV of length 4, status in a ack
    add(hdr(9, tlv(500, b'unknown!') + tlv(1000, b'')))
    add(hdr(9, b''.join(tlv(i, b'') for i in (2, 5, 17, 59, 69))))
    # ---- block TLVs by themselves, nesting up to the limit
    mark('nesting')
    # deep(n): n nested TLVs 59; the deepest dissect_wassp_sub_tlv() call has
    # depth n - 1 and 16 is the first depth that is refused, so deep(16) is
    # the last that is accepted
    for n in (1, 2, 8, 15, 16):
        add(hdr(11, deep(n)))
    # every sub-table that a packet can reach, with all its rows, once in
    # a configuration request and (the radio tables) in an acknowledge
    for n in sorted(PATHS):
        add(hdr(8, table_msg_body(n, 1) + PAD))
    for n in (TABNO['CONFIG_GLOBAL_BLOCK'], TABNO['VNS_CONFIG_BLOCK']):
        add(hdr(10, table_msg_body(n, 1) + PAD))
    # topology modes of the site table (every case of the custom label)
    for mode in (0xc005, 0xc000, 0x4007, 0x4000, 0x8009, 0x8000, 0x0003, 0x0000):
        SITE_ROW80[0] = mode
        add(hdr(8, table_msg_body(TABNO['TAB_CONFIG_SITE'], 1) + PAD))
    SITE_ROW80[0] = None
    # a nested RSS data block (compared by id in the RSS data array table)
    add(hdr(8, table_msg_body(TABNO['TAB_RSS_DATA_ARRAY'], 1) + PAD))
    # a filter rule sub-TLV shorter than 20 octets ends the sub-TLV list; the
    # main TLV list then continues with the same octets (a string TLV)
    add(hdr(8, tlv(MAINNO['EID_FILTER_CONFIG_STRUCT'], tlv(2, b'shortval')) + PAD))
    # the acknowledge variant of the radio configuration block: sub-TLVs
    # of the main table (reached through the global configuration)
    gl = TABNO['CONFIG_GLOBAL_BLOCK']
    rcb = [i for i, r in enumerate(D.TABVARS[D.TABS[gl][1]]) if r[0] == 'EID_RADIO_CONFIG_BLOCK'][0]
    add(hdr(10, tlv(MAINNO['EID_TLV_CONFIG'], tlv(rcb, build_table(TABNO['TAB_RU_ACK_RADIO_CONFIG'], 0, 1))) + PAD))
    # filter rule tables with short rules (the rule is not decoded), 16, 20
    # and 36 octets per rule
    fr = MAINNO['EID_FILTER_RULES']
    for n in (0, 8, 16, 20, 36, 40, 144, 720):
        add(hdr(9, tlv(fr, bytes((j * 5) & 0xff for j in range(n))) + PAD))
    # sub-TLVs of length 4 (no value) and with unknown types in a sub table
    add(hdr(9, tlv(MAINNO['EID_EVENT_BLOCK'], tlv(0, b'') + tlv(1, b'') + tlv(2, b''))))
    # ---- data messages (type 15)
    mark('mu')
    eth = small_eth_frame()
    for mt in (3, 11, 16):
        add(hdr(15, mu_hdr(mt) + eth))
    for mt in (6, 7):
        add(hdr(15, mu_hdr(mt) + b'\0\0\0\0'))
    tl = tlv(MAINNO['EID_MU_MAC'], MAC) + tlv(MAINNO['EID_RADIO_ID'], P('>I', 1))
    for mt in (1, 9, 10, 14, 15, 4, 5):
        add(hdr(15, mu_hdr(mt) + tl))
    for ast in (1, 2, 3):
        add(hdr(15, mu_hdr(2, assoc_status=ast) + tl))
    for mt in (0, 8, 13, 17, 18, 40):
        add(hdr(15, mu_hdr(mt) + bytes(range(10))))
    # netflow: the header fields are read at fixed offsets from the start
    # of the message; the "length" field is the sequence/flags word
    rec = bytes(46)
    for length in (10 + 46 * 2, 64, 20, 0):
        body = mu_hdr(12) + P('>HHHI', 9, length, 0, 1234)
        add(P('>BBHHH', 3, 15, length, 1, 0) + body + rec * 2)
    # ---- the location based service tag report: IPv4/UDP header and a
    # 64 octet tag header, and one without the tag magic
    mark('lbs')
    lbs = (P('>HHBBH', 0x7c83, 1, 2, 3, 40) + MAC + P('>HH', 1, 2) + bytes([2, 0, 0, 0, 0, 0x44])
           + bytes([1, 6]) + P('>IH', 7, 8) + bytes([0x50, 0, 0xa0]) + b'\0\0\0' + bytes([2, 3])
           + bytes([2, 0, 0, 0, 0, 0x55]) + P('>HHH', 0x8000, 9, 0) + bytes([2, 0, 0, 0, 0, 0x66])
           + bytes([2, 0, 0, 0, 0, 0x77]))
    assert len(lbs) == 64, len(lbs)
    udp = P('!HHHH', 5000, 5001, 8 + len(lbs), 0)
    ip = P('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(lbs), 1, 0, 64, 17, 0,
           bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + P('!H', csum(ip)) + ip[12:]
    add(hdr(55, ip + udp + lbs))
    lbs2 = P('>H', 0x1234) + lbs[2:]
    add(hdr(55, ip + udp + lbs2))
    # ---- fragmentation: a message in three fragments, a message in one
    # fragment, two interleaved types
    mark('fragments')
    body = b''.join(main_tlv(i, 1) for i in (2, 3, 17, 59, 65, 69, 87))
    third = len(body) // 3
    pieces = [body[:third], body[third:2 * third], body[2 * third:]]
    add(hdr(9, pieces[0], seq=20, flags=F_USEFRAG | F_MORE))
    add(hdr(9, pieces[1], seq=21, flags=F_USEFRAG | F_MORE | F_NOTFIRST))
    add(hdr(9, pieces[2], seq=22, flags=F_USEFRAG | F_NOTFIRST))
    add(hdr(8, tlv(sw, b'frag\0\0\0\0'), seq=23, flags=F_USEFRAG))
    # a status TLV in a reassembled message of type 7 and a data message
    # fragment
    add(hdr(7, tlv(st, P('>I', 6)), seq=28, flags=F_USEFRAG))
    # ---- Exported PDU: the reproducer of the conversation assert (a
    # fragmented message without addresses or ports), a complete message
    mark('exppdu')
    frames.append((1, exppdu('wassp', hdr(8, b'\x00\x01\x00\x08\x00\x00\x00\x00', seq=0, flags=F_USEFRAG | F_MORE))))
    frames.append((1, exppdu('wassp', hdr(8, tlv(sw, b'xpdu\0\0\0\0'), seq=1, flags=F_USEFRAG))))
    frames.append((1, exppdu('wassp', hdr(9, tlv(sw, b'xpdu\0\0\0\0')))))
    frames.append((1, exppdu('wassp', hdr(15, mu_hdr(3) + eth))))
    # ---- the same port range in the other direction
    add(hdr(9, tlv(sw, b'back\0\0\0\0')), 13910, 40000)
    # ports that only the (disabled by default) heuristic dissector knows
    add(hdr(9, tlv(sw, b'heur\0\0\0\0')), 40000, 40001)
    # a nested RSS data block that holds a TLV (the last frame)
    add(hdr(8, tlv(MAINNO['EID_RSS_DATA_ARRAY'], tlv(MAINNO['EID_RSS_DATA_BLOCK'], tlv(2, b'rss-data'))) + PAD))
    return frames, marks


def build_malformed():
    frames = []

    def add(payload, sport=13910, dport=13910, ifc=0):
        frames.append((ifc, eth_udp(payload, sport, dport)))

    sw = MAINNO['EID_RU_SW_VERSION']
    FP0 = tlv(sw, b'abcdefgh') * 6
    FP1 = tlv(sw, b'abcdefgh') * 6
    # nesting past the limit: 17 nested blocks is the first error
    for n in (17, 18, 20, 100):
        add(hdr(11, deep(n)))
    # the reproducer of the recursion (a 64 kB datagram of nested blocks)
    inner = b''
    body = b''
    for _ in range(16000):
        body += P('>HH', 59, 0)      # placeholder, lengths fixed below
    # nested blocks, each a 4 octet header whose length covers the rest
    total = 4 * 16000
    blocks = b''.join(P('>HH', 59, total - 4 * k) for k in range(16000))
    add(hdr(11, blocks[:65000]))
    # broken TLVs: length beyond the message, length under 4, in the main
    # TLV list and in sub-TLV lists, an unknown sub type with bad lengths
    add(hdr(9, P('>HH', sw, 200) + b'abcd'))
    add(hdr(9, P('>HH', sw, 2) + b'abcdefgh'))
    add(hdr(9, P('>HH', 0, 8) + b'abcd'))
    add(hdr(9, tlv(59, P('>HH', 1, 200) + b'abcd')))
    add(hdr(9, tlv(59, P('>HH', 1, 2) + b'abcdefgh')))
    add(hdr(9, tlv(59, P('>HH', 60000, 8) + b'abcdabcd' + P('>HH', 60000, 0) + b'abcd')))
    add(hdr(9, tlv(59, P('>HH', 60000, 2) + b'abcdabcd')))
    add(hdr(9, tlv(59, P('>HH', 1, 4))))
    # a main TLV with a value that is too short for its field
    add(hdr(9, tlv(0, b'') + PAD))
    add(hdr(9, tlv(0, b'abcd')))
    for i in range(len(D.MAIN)):
        eid, kind, handler = D.MAIN[i]
        if handler in ('hf_wassp_tlv_value_ip', 'hf_wassp_macaddr', 'hf_wassp_mu_mac',
                       'hf_wassp_tlv_value_int') or eid in SPECIAL:
            add(hdr(9, tlv(i, b'\x01\x02')))
    # sub-table fields too short
    for tn in ('TAB_CONFIG_SITE', 'VNS_CONFIG_BLOCK', 'TAB_SCAN_PROFILE_BLOCK',
               'TAB_SURVEILLANCE_DATA_BLOCK', 'TAB_DETECTED_ROGUE_BLOCK',
               'CONFIG_GLOBAL_BLOCK', 'TAB_CONFIG_FILTER', 'TAB_FILTER_CONFIG_STRUCT_BLOCK'):
        n = TABNO[tn]
        var = D.TABS[n][1]
        for i, (eid, kind, nested) in enumerate(D.TABVARS[var]):
            if eid in SPECIAL or kind in ('IP_ADDR', 'MACADD'):
                main = MAINNO['EID_TLV_CONFIG'] if tn in ('CONFIG_GLOBAL_BLOCK',) else None
        # the block through the main table that uses this sub table
        for mi, (e, k, h) in enumerate(D.MAIN):
            if h == 'sub:' + tn:
                for i, (eid, kind, nested) in enumerate(D.TABVARS[var]):
                    if eid in SPECIAL or kind in ('IP_ADDR', 'MACADD', 'INT', 'UINT'):
                        add(hdr(9, tlv(mi, tlv(i, b'\x01\x02'))))
                        add(hdr(9, tlv(mi, tlv(i, b''))))
    # data messages: short MU header, netflow with a truncated record
    add(hdr(15, b'\x03'))
    add(hdr(15, mu_hdr(3)[:10]))
    add(hdr(15, mu_hdr(12) + b'\0' * 12, ))
    add(P('>BBHHH', 3, 15, 102, 1, 0) + mu_hdr(12) + P('>HHHI', 9, 102, 0, 1) + bytes(40))
    add(hdr(55, b'\0' * 20))
    add(hdr(14, b''))
    # the header: too short, a discovery header cut short, wrong version
    add(b'\x03\x08\x00\x00\x12\x34')
    add(P('>BBHHHH', 3, 1, 1, 0, 0, 1) + b'\x02\x00')
    add(hdr(9, tlv(sw, b'x\0\0\0'), version=2))
    add(hdr(9, tlv(sw, b'x\0\0\0'), version=2), 40000, 40001)
    add(b'\x03\x09\x00', 40000, 40001)
    # fragments that do not add up: a middle fragment first, a last
    # fragment without a first, a fragment after the message completed
    add(hdr(9, b'\0\0\0\0', seq=40, flags=F_USEFRAG | F_NOTFIRST | F_MORE))
    add(hdr(9, b'\0\0\0\0', seq=41, flags=F_USEFRAG | F_NOTFIRST))
    add(hdr(9, b'\0\0\0\0', seq=42, flags=F_USEFRAG))
    add(hdr(9, b'\0\0\0\0', seq=44, flags=F_USEFRAG | F_MORE))
    add(hdr(9, b'\0\0\0\0', seq=44, flags=F_USEFRAG | F_MORE))
    # interleaved fragments of two types, cut in the middle of a TLV
    add(hdr(8, FP0[:40], seq=24, flags=F_USEFRAG | F_MORE | F_DATA))
    add(hdr(9, FP0[:60], seq=25, flags=F_USEFRAG | F_MORE))
    add(hdr(8, FP1[:40], seq=26, flags=F_USEFRAG | F_NOTFIRST | F_DATA))
    add(hdr(9, FP1[:60], seq=27, flags=F_USEFRAG | F_NOTFIRST))
    # fragment reassembled into TLVs cut in the middle
    add(hdr(9, tlv(sw, b'abcdefgh')[:6], seq=50, flags=F_USEFRAG | F_MORE))
    add(hdr(9, b'', seq=51, flags=F_USEFRAG | F_NOTFIRST))
    # Exported PDU without a conversation
    frames.append((1, exppdu('wassp', hdr(8, b'\0' * 8, flags=F_USEFRAG | F_MORE))))
    frames.append((1, exppdu('wassp', b'\x03')))
    return frames


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    frames, marks = build_main()
    pcapng(os.path.join(outdir, 'wassp-coverage.pcapng'), frames)
    print('main frames', len(frames), marks)
    frames = build_malformed()
    pcapng(os.path.join(outdir, 'wassp-coverage-malformed.pcapng'), frames)
    print('malformed frames', len(frames))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
