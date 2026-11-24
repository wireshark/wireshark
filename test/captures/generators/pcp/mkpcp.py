#!/usr/bin/env python3
# Generates test/captures/pcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the PCP (Performance Co-Pilot) coverage captures.
# Usage: mkpcp.py <outdir>
# Writes pcp-coverage.pcap (clean) and pcp-coverage-malformed.pcap.
# Everything is synthetic: Ethernet/IPv4/TCP to port 44321.
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self):
        self.pkts = []

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


class Flow:
    def __init__(self, cap, cport, sport=44321, cip=(192, 0, 2, 1), sip=(192, 0, 2, 2)):
        self.cap = cap
        self.c = [bytes(cip), cport, 1000]
        self.s = [bytes(sip), sport, 5000]

    def send(self, from_client, payload):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        tcp = struct.pack('>HHIIBBHHH', a[1], b[1], a[2], b[2], 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, a[0], b[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        ph = a[0] + b[0] + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp)) + tcp[18:]
        eth = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
        if not from_client:
            eth = bytes.fromhex('020000000001020000000002') + b'\x08\x00'
        self.cap.pkts.append(eth + ip + tcp)
        a[2] += len(payload)

    def c2s(self, p): self.send(True, p)
    def s2c(self, p): self.send(False, p)


def u32(*v): return struct.pack('>%dI' % len(v), *v)
def i32(*v): return struct.pack('>%di' % len(v), *v)


def pdu(ptype, body, pid=4242, length=None):
    return struct.pack('>III', 12 + len(body) if length is None else length, ptype, pid) + body


def pad4(b): return b + b'\0' * ((-len(b)) % 4)


CREDS, START, RESULT, PROFILE, FETCH = 0x700c, 0x7000, 0x7001, 0x7002, 0x7003
DESC_REQ, DESC, INST_REQ, INST, TEXT_REQ, TEXT = 0x7004, 0x7005, 0x7006, 0x7007, 0x7008, 0x7009
PMNS_IDS, PMNS_NAMES, PMNS_CHILD, PMNS_TRAV = 0x700d, 0x700e, 0x700f, 0x7010
USER_AUTH, LABEL_REQ, LABEL = 0x7011, 0x7012, 0x7013


def pmid(dom, cl, item, flag=0):
    return (flag << 31) | (dom << 22) | (cl << 10) | item


P_LOAD = pmid(60, 2, 0)
P_NUSERS = pmid(60, 2, 4)
P_STR = pmid(60, 12, 3)
P_UNKNOWN = pmid(100, 1, 1, 1)

ALL_FEATURES = 0x03ff
LABELS = 0x0200


def start_body(features, version=2, licensed=1, zero=0):
    return u32(0) + bytes([(zero << 7) | version, licensed]) + struct.pack('>H', features)


def names_pdu(names, status=None):
    # PMNS_NAMES: nstrbytes, numstatus, numnames, then name_t or name_status_t
    body = b''
    for n in names:
        nb = n.encode()
        if status is not None:
            body += i32(status)
        body += u32(len(nb)) + pad4(nb)
    return u32(len(body), 1 if status is not None else 0, len(names)) + body


def labelset(inst, labels, json):
    """labels: list of (name_off, name_len, flags, value_off, value_len, raw16)
    Returns a function of base offset (json start) -> bytes of set header + labels."""
    return (inst, labels, json)


def label_body(ident, ltype, sets, base_hdr=12):
    """LABEL PDU body.  sets: list of (inst, nlabels_or_error, labels, json) where
    labels is a list of 8-byte pmLabel structs.  The JSON strings are appended after
    all headers; the json offset of each set is relative to the start of the PDU."""
    fixed = 12 + 16
    for s in sets:
        fixed += 16 + 8 * len(s[2])
    js_off = fixed
    hdrs = b''
    jsons = b''
    for inst, nl, labels, js in sets:
        hdrs += struct.pack('>iiII', inst, nl, js_off + len(jsons), len(js))
        hdrs += b''.join(labels)
        jsons += js
    return u32(ident, ltype, 0, len(sets)) + hdrs + jsons


def pmlabel(noff, nlen, flags, voff, vlen_raw, endian='>'):
    return struct.pack('>HBBH', noff, nlen, flags, voff) + struct.pack(endian + 'H', vlen_raw)


def build_main(cap):
    # ---- Flow A: a complete session ----
    f = Flow(cap, 51000)
    f.c2s(pdu(CREDS, u32(2) + bytes([1, 2]) + struct.pack('>H', 0x0201)
              + bytes([2, 3]) + struct.pack('>H', 0)))                       # CREDS (CVERSION, CAUTH)
    f.s2c(pdu(START, start_body(ALL_FEATURES)))                              # START, all features
    f.c2s(pdu(PMNS_TRAV, u32(1, 6) + b'kernel\0\0'))                         # PMNS_TRAVERSE padded
    f.c2s(pdu(PMNS_TRAV, u32(1, 8) + b'kernel.a'))                           # no padding
    f.s2c(pdu(PMNS_CHILD, u32(1, 8) + b'all\0load'))                         # PMNS_CHILD
    # name resolution: names, an error that clears the candidates, names again, ids
    f.c2s(pdu(PMNS_NAMES, names_pdu(['kernel.all.nope'])))
    f.s2c(pdu(START, i32(-12357)))                                            # ERROR PM_ERR_NAME
    f.c2s(pdu(PMNS_NAMES, names_pdu(['kernel.all.load', 'kernel.all.nusers', 'mem.str'])))
    f.s2c(pdu(PMNS_IDS, u32(0, 3, P_LOAD, P_NUSERS, P_STR)))                  # maps the names
    f.c2s(pdu(PMNS_NAMES, names_pdu(['a.b', 'a.c'])))                         # candidates ...
    f.s2c(pdu(PMNS_IDS, u32(0, 3, 1, 2, 3)))                                  # ... count differs: not mapped
    f.s2c(pdu(PMNS_NAMES, names_pdu(['kernel.all.load', 'x'], status=0)))    # name_status_t, server side
    f.c2s(pdu(START, i32(-12345)))                                            # other errors
    f.s2c(pdu(START, i32(-12346)))
    f.s2c(pdu(START, i32(-99999)))                                            # unknown error code
    f.c2s(pdu(START, i32(-12357)))
    # profile: two profiles (the dissector shows 32 bytes per profile)
    f.c2s(pdu(PROFILE, u32(7, 1, 2, 0) + u32(0x3c000001, 1, 1, 0) + u32(0x3c000002, 0, 0, 0)
              + u32(0, 0, 0, 0)))
    f.c2s(pdu(PROFILE, u32(7, 0, 0, 0)))                                      # no profile
    # fetch with two known pmids, one unknown, and a split over two segments
    fetch = pdu(FETCH, u32(7) + u32(1700000000, 123456) + u32(3, P_LOAD, P_NUSERS, P_UNKNOWN))
    f.c2s(fetch[:20])
    f.c2s(fetch[20:])
    # result: all value types
    # layout: header 12, when 8, numpmid 4 = 24; entries follow, value blocks are
    # addressed in 32-bit words from the start of the PDU
    entries = []
    blocks = []
    def blk(t, v):
        return struct.pack('>I', (t << 24) | (4 + len(v))) + v
    base = 24
    ents = [
        (P_LOAD, 1, 0, [(1, 0xdeadbeef)]),                       # insitu
        (P_NUSERS, 0, None, []),                                  # no values
    ]
    plan = [
        (pmid(60, 3, 1), 1, [blk(0, struct.pack('>i', -5))]),       # 32
        (pmid(60, 3, 2), 1, [blk(1, struct.pack('>I', 5))]),        # u32
        (pmid(60, 3, 3), 1, [blk(2, struct.pack('>q', -(1 << 40)))]),
        (pmid(60, 3, 4), 1, [blk(3, struct.pack('>Q', 1 << 40))]),
        (pmid(60, 3, 5), 1, [blk(4, struct.pack('>f', 1.5))]),
        (pmid(60, 3, 6), 1, [blk(5, struct.pack('>d', 2.25))]),
        (pmid(60, 3, 7), 1, [blk(6, pad4(b'hello'))]),               # string
        (pmid(60, 3, 8), 1, [blk(7, b'\x01\x02\x03\x04')]),          # aggregate
        (pmid(60, 3, 9), 1, [blk(8, b'\x05\x06\x07\x08')]),          # aggregate static
        (pmid(60, 3, 10), 1, [blk(9, b'\0\0\0\0')]),                 # event: unimplemented
        (pmid(60, 3, 11), 1, [blk(255, b'\0\0\0\0')]),               # unknown type
        (pmid(60, 3, 12), 1, [blk(20, b'\0\0\0\0')]),                # unimplemented type
        (pmid(60, 3, 13), 2, [blk(0, struct.pack('>i', 1)), blk(0, struct.pack('>i', 2))]),  # 2 instances
    ]
    # entry sizes: pmid,numval,[valfmt, (inst,val)*n]
    size = 8 + 12 + 0       # P_LOAD (insitu, 1 value): 8 + 4 + 8
    size = 8 + 4 + 8
    size += 8               # P_NUSERS no values
    for p, n, bl in plan:
        size += 8 + 4 + 8 * n
    blocks_off = base + size
    body = b''
    cur = blocks_off
    ent_bytes = u32(P_LOAD, 1, 0, 1, 0xdeadbeef) + u32(P_NUSERS, 0)
    blocks_bytes = b''
    for p, n, bl in plan:
        ent = u32(p, n, 1)
        for k, b in enumerate(bl):
            ent += u32(k + 1, cur // 4)
            blocks_bytes += b
            cur += len(b)
        ent_bytes += ent
    res = u32(1700000001, 5) + u32(2 + len(plan)) + ent_bytes + blocks_bytes
    f.s2c(pdu(RESULT, res))
    # result with SPTR value format and no values
    ent = u32(P_LOAD, 1, 2, 1, (24 + 8 + 4 + 8 + 4) // 4 + 0)
    b = blk(0, struct.pack('>i', 99))
    ent_len = 8 + 4 + 8
    f.s2c(pdu(RESULT, u32(1700000002, 6) + u32(1) + u32(P_LOAD, 1, 2, 1, (24 + ent_len) // 4) + b))
    f.s2c(pdu(RESULT, u32(1700000003, 7) + u32(0)))                           # no pmid
    # desc
    f.c2s(pdu(DESC_REQ, u32(P_LOAD)))
    units = bytes([0x10, 0x03 << 4 | 0x0, 0x00, 0x00])  # dims/scales packed (arbitrary)
    f.s2c(pdu(DESC, u32(P_LOAD, 5, 0x3c000001, 3) + bytes([0x1f, 0x13, 0x30, 0x00])))
    f.s2c(pdu(DESC, u32(P_NUSERS, 1, 0xffffffff, 1) + bytes([0x01, 0x10, 0x00, 0x00])))
    f.s2c(pdu(DESC, u32(P_STR, 6, 0xffffffff, 4) + bytes([0, 0, 0, 0])))
    # instance request/response
    f.c2s(pdu(INST_REQ, u32(0x3c000001) + u32(1700000004, 0) + i32(-1) + u32(5) + b'cpu0\0\0\0\0'))
    f.c2s(pdu(INST_REQ, u32(0x3c000001) + u32(1700000004, 0) + i32(3) + u32(0)))
    f.s2c(pdu(INST, u32(0x3c000001, 3) + u32(0, 4) + b'cpu0' + u32(1, 5) + pad4(b'cpu1\0')
              + u32(2, 0)))
    f.s2c(pdu(INST, u32(0x3c000001, 0)))
    # text
    f.c2s(pdu(TEXT_REQ, u32(P_LOAD, 5)))              # pmid, one line
    f.c2s(pdu(TEXT_REQ, u32(0x3c000001, 10)))         # indom, help
    f.c2s(pdu(TEXT_REQ, u32(P_LOAD, 1)))              # neither flag
    f.s2c(pdu(TEXT, u32(P_LOAD, 12) + b'load average'))
    # user auth, label request
    f.c2s(pdu(USER_AUTH, b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    f.c2s(pdu(LABEL_REQ, u32(P_LOAD, 1)))
    js = b'{"hostname":"h1","domainname":"d"}'
    labels = [pmlabel(2, 8, 1, 13, 2, '>'), pmlabel(18, 10, 2, 31, 1, '>')]
    f.s2c(pdu(LABEL, label_body(P_LOAD, 1, [(0, 2, labels, js), (-1, -12372, [], b'')])))
    # two PDUs in one segment
    f.c2s(pdu(LABEL_REQ, u32(5, 2)) + pdu(LABEL_REQ, u32(6, 4)))
    # unimplemented types
    f.c2s(pdu(0x700a, u32(1)))                                                # CONTROL_REQ
    f.s2c(pdu(0x7099, u32(1, 2)))

    # ---- Flow B: LABEL PDUs before any START that announced LABELS (reproducer of
    # the fix: tshark -2 must give the same result) ----
    g = Flow(cap, 51001)
    js = b'{"a":"b"}'
    # value length 0x0100 read big-endian does not fit; little-endian gives 1
    g.s2c(pdu(LABEL, label_body(0, 1, [(0, 1, [pmlabel(2, 1, 0, 6, 0x0100)], js)])))
    # plausible big-endian value length: the generic branch
    g.s2c(pdu(LABEL, label_body(0, 1, [(0, 1, [pmlabel(2, 1, 0, 6, 1)], js)])))
    g.s2c(pdu(START, start_body(LABELS)))                                     # announces LABELS
    g.s2c(pdu(LABEL, label_body(0, 1, [(0, 1, [pmlabel(2, 1, 0, 6, 1)], js)])))  # now good labels
    g.s2c(pdu(START, start_body(0x0003, 3, 0, 1)))                            # later START, no LABELS

    # ---- Flow C: TLS upgrade via SECURE_ACK ----
    h = Flow(cap, 51002)
    h.c2s(pdu(START, start_body(0x0001)))
    h.s2c(pdu(START, u32(0)))                                                 # status 0, no features: upgrade
    # ---- Flow D: SECURE_ACK with an error status ----
    k = Flow(cap, 51003)
    k.s2c(pdu(START, u32(5)))
    return


def build_malformed(cap):
    # frame groups that only malformed or odd input reaches
    f = Flow(cap, 52000)
    # FETCH naming 100 pmids but carrying one
    f.c2s(pdu(FETCH, u32(1) + u32(1, 2) + u32(100, P_LOAD)))
    # RESULT: value block offset outside the PDU
    f.s2c(pdu(RESULT, u32(1, 2) + u32(1) + u32(P_LOAD, 1, 1, 1, 0x1000)))
    # RESULT: value block header shorter than 4 (length - 4 underflows)
    f.s2c(pdu(RESULT, u32(1, 2) + u32(1) + u32(P_LOAD, 1, 1, 1, 8) + struct.pack('>I', 0x00000002)))
    # PMNS_NAMES whose name_len exceeds the PDU
    f.c2s(pdu(PMNS_NAMES, u32(100, 0, 1) + u32(1000) + b'abcd'))
    # PMNS_CHILD with a name_len beyond the PDU
    f.s2c(pdu(PMNS_CHILD, u32(1, 1000) + b'abcd'))
    # TEXT with buflen past the end
    f.s2c(pdu(TEXT, u32(P_LOAD, 1000) + b'abc'))
    # INSTANCE with a name length past the end
    f.s2c(pdu(INST, u32(1, 1) + u32(0, 5000) + b'ab'))
    # LABEL pointing its JSON outside the PDU
    f.s2c(pdu(LABEL, u32(0, 1, 0, 1) + struct.pack('>iiII', 0, 1, 5000, 4)
              + pmlabel(0, 4, 0, 0, 4)))
    # LABEL whose label count is larger than what is present
    f.s2c(pdu(LABEL, u32(0, 1, 0, 1) + struct.pack('>iiII', 0, 50, 100, 4)))
    # PDU too short for its type (START with 2 bytes after the header)
    f.c2s(pdu(PROFILE, u32(1, 2, 1000000, 0)))
    f.c2s(pdu(CREDS, u32(1000)))
    f.c2s(pdu(PMNS_IDS, u32(0, 1000)))
    f.c2s(pdu(INST_REQ, u32(1) + u32(1, 2) + u32(3, 100)))
    # pmid names learned only later (not stable between passes; see README)
    g = Flow(cap, 52001)
    g.c2s(pdu(FETCH, u32(0, 0, 0, 1, 0x0c001001)))
    name = b'kernel.all.load'
    g.c2s(pdu(PMNS_NAMES, u32(len(name), 0, 1, len(name)) + pad4(name)))
    g.s2c(pdu(PMNS_IDS, u32(0, 1, 0x0c001001)))
    g.c2s(pdu(FETCH, u32(0, 0, 0, 1, 0x0c001001)))


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    c = Cap(); build_main(c); c.write(os.path.join(out, 'pcp-coverage.pcap'))
    m = Cap(); build_malformed(m); m.write(os.path.join(out, 'pcp-coverage-malformed.pcap'))
    print(len(c.pkts), len(m.pkts))
