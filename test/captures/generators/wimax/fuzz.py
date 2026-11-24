#!/usr/bin/env python3
# Helper module for the wimax capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Field-guided corpus builder (runs tshark; run it on the VM).

For each target (a management message, a map, a MAC header ...) mutate
the corpus entries and keep the mutants that decode without malformed /
warning / error expert info and show a field, label or expert message not
yet seen for that target. The result is stored in corpus/<target>.json.
This is only used to produce the data table that mkwimax.py embeds.

usage: fuzz.py <target[,target...]> <rounds> [mutants_per_round]"""
import os
import sys
import json
import subprocess
import tempfile
import random
import re
from wxlib import (
    BitWriter, BS, crc32, crc8, eth, gmh, m2m_tlvs, mgmt, MS, struct, T_FCH, T_PDU, T_PHY, tlv,
    write_pcap,
)

HERE = os.path.dirname(os.path.abspath(__file__))
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
CORPUS = HERE + '/corpus'
os.makedirs(CORPUS, exist_ok=True)
TMP = os.path.join(HERE)

FCH = eth(BS, m2m_tlvs([tlv(T_FCH, b'\x00\x00\x00')]))


def w_mgmt(t, src=MS, cid=1):
    return lambda b: eth(src, m2m_tlvs([tlv(T_PDU, gmh(cid, mgmt(t, b)))]))


def w_mgmt_dl(t):
    return w_mgmt(t, BS, 0xffff)


def w_hdr(b0min, b0mask):
    def f(b):
        b = (b + b'\0' * 5)[:5]
        h = bytes([(b[0] & b0mask) | b0min]) + b[1:]
        return eth(MS, m2m_tlvs([tlv(T_PDU, h + bytes([crc8(h)]))]))
    return f


def w_gmh(b):
    b = (b + b'\0' * 4)
    b0, b1, cid = b[0] & 0x3F, b[1], (b[2] << 8) | b[3]
    ec = (b[1] >> 7) & 1
    ci = 1
    esf = (b[1] >> 6) & 1
    body = b[4:]
    return eth(MS if (b[1] & 1) else BS, m2m_tlvs([tlv(T_PDU, gmh(cid & 0x3ff, body, ci=ci, esf=esf, subtypes=b0, ec=0))]))


def w_dlmapc(b):
    """Compressed DL-MAP: 0b110 + 2 flag bits + 11 bit length, body, CRC32."""
    b = (b + bytes(12))[:max(len(b), 11)]
    total = 2 + len(b) - 1 + 4
    first = 0xC0 | (b[0] & 0x18) | ((total >> 8) & 7)
    pdu = bytes([first, total & 0xff]) + b[1:]
    pdu += struct.pack('>I', crc32(pdu))
    return eth(BS, m2m_tlvs([tlv(T_PDU, pdu)]))


def w_harq(b):
    """HARQ-MAP: 0b111, UL-MAP appended, reserved, 9 bit length, 6 bit IE count, IEs, CRC32."""
    b = (b + bytes(4))
    ul = b[0] & 1
    cnt = b[1] & 0x3F
    ie = b[2:]
    total = 3 + len(ie) - 1 + 4
    w = 0xE00000 | (ul << 20) | ((total & 0x1FF) << 10) | (cnt << 4) | (ie[0] & 0x0F)
    pdu = struct.pack('>I', w)[1:] + ie[1:]
    pdu += struct.pack('>I', crc32(pdu))
    return eth(BS, m2m_tlvs([tlv(T_PDU, pdu)]))


def w_m2m(t):
    return lambda b: eth(MS, m2m_tlvs([tlv(t, b)]))


PFX = {'ucd': 5, 'dcd': 2, 'rngreq': 1, 'rngrsp': 1, 'regrsp': 1, 'pkmreq': 2, 'pkmrsp': 2, 'dsareq': 2,
       'dsarsp': 3, 'dsaack': 3, 'dscreq': 2, 'dscrsp': 3, 'dscack': 3, 'dsdreq': 6, 'dsdrsp': 7,
       'ucd_dl': 5, 'dcd_dl': 2}
TLVTARGETS = set(['ucd', 'dcd', 'rngreq', 'rngrsp', 'regreq', 'regrsp', 'pkmreq', 'pkmrsp', 'dsareq', 'dsarsp',
                  'dsaack', 'dscreq', 'dscrsp', 'dscack', 'dsdreq', 'dsdrsp', 'rescmd', 'sbcreq', 'sbcrsp',
                  'repreq', 'reprsp', 'dregreq', 'dregcmd', 'pmcreq', 'pmcrsp', 'ucd_dl', 'dcd_dl'])
TARGETS = {}   # name -> (wrapper, seeds, (minlen, maxlen))
for t, nm in [(0, 'ucd'), (1, 'dcd'), (4, 'rngreq'), (5, 'rngrsp'), (6, 'regreq'), (7, 'regrsp'),
              (9, 'pkmreq'), (10, 'pkmrsp'), (11, 'dsareq'), (12, 'dsarsp'), (13, 'dsaack'),
              (14, 'dscreq'), (15, 'dscrsp'), (16, 'dscack'), (17, 'dsdreq'), (18, 'dsdrsp'),
              (25, 'rescmd'), (26, 'sbcreq'), (27, 'sbcrsp'), (28, 'clkcmp'), (29, 'dregcmd'),
              (30, 'dsxrvd'), (33, 'arqfb'), (34, 'arqdiscard'), (35, 'arqreset'), (36, 'repreq'),
              (37, 'reprsp'), (38, 'fpc'), (44, 'aasfbreq'), (45, 'aasfbrsp'), (46, 'aasselect'),
              (47, 'aasbeamreq'), (48, 'aasbeamrsp'), (49, 'dregreq'), (63, 'pmcreq'), (64, 'pmcrsp'),
              (65, 'prcltctrl')]:
    TARGETS[nm] = (w_mgmt(t), [b''], (0, 60))
TARGETS['dlmap'] = (w_mgmt_dl(2), [b''], (0, 200))
TARGETS['ulmap'] = (w_mgmt_dl(3), [b''], (0, 160))
TARGETS['dcd_dl'] = (w_mgmt_dl(1), [b''], (0, 80))
TARGETS['ucd_dl'] = (w_mgmt_dl(0), [b''], (0, 80))
TARGETS['type1'] = (w_hdr(0x80, 0x3F), [b''], (5, 5))
TARGETS['type2'] = (w_hdr(0xC0, 0x3F), [b''], (5, 5))
TARGETS['gmh'] = (w_gmh, [b''], (4, 40))
TARGETS['dlmapc'] = (w_dlmapc, [b''], (2, 150))
TARGETS['harqmap'] = (w_harq, [b''], (3, 150))
TARGETS['harqmap2'] = TARGETS['harqmap']
TARGETS['phy'] = (w_m2m(T_PHY), [b''], (7, 20))


def norm(k):
    if k.startswith('Value (hex)') or 'hex' in k.lower():
        return None
    k = re.sub(r'\s*\(0x[0-9a-fA-F.]+\)', '', k)
    return re.sub(r'\d+', '#', k)[:100]


WARNOK = [False]


def evaluate(frames):
    d = tempfile.mkdtemp(dir=TMP)
    f = d + '/f.pcap'
    write_pcap(f, [FCH] + frames)
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=HERE + '/cfg')
    r = subprocess.run(['timeout', '-s', 'KILL', '900', TSHARK, '-r', f, '-T', 'json'],
                       capture_output=True, env=env)
    os.system('rm -rf ' + d)
    try:
        pk = json.loads(r.stdout or b'[]')
    except Exception:
        return None
    res = []
    for p in pk[1:]:
        keys = set(); bad = [False]
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.startswith('_ws.malformed'):
                        bad[0] = True
                    if k == '_ws.expert.severity':
                        vs = v if isinstance(v, list) else [v]
                        if any(x == 'error' or (x == 'warn' and not WARNOK[0]) for x in vs):
                            bad[0] = True
                    if k == '_ws.expert.message':
                        for m in (v if isinstance(v, list) else [v]):
                            keys.add('E:' + re.sub(r'\d+', '#', str(m))[:60])
                    n = norm(k)
                    if n and not k.startswith('_ws'):
                        keys.add(n)
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(p['_source']['layers'])
        res.append((bad[0], keys))
    if len(res) != len(frames):
        return None
    return res


INTERESTING = [0, 1, 2, 3, 4, 7, 8, 0x0f, 0x10, 0x20, 0x40, 0x7f, 0x80, 0x81, 0xc0, 0xe0, 0xf0, 0xfe, 0xff]


def tlv_bounds(b, start):
    pos = [start]
    i = start
    while i + 2 <= len(b):
        n = b[i + 1]
        hdr = 2
        if n & 0x80:
            k = n & 0x7f
            if k > 4:
                break
            if i + 2 + k > len(b):
                break
            n = int.from_bytes(b[i + 2:i + 2 + k], 'big'); hdr = 2 + k
        i += hdr + n
        if i > len(b):
            break
        pos.append(i)
    return pos


def parse_tree(b, depth=0):
    """Parse a byte string as a chain of TLVs: list of [type, lenbytes, children-or-bytes]; None if not a clean chain."""
    out = []; i = 0
    if not b:
        return None
    while i < len(b):
        if i + 2 > len(b):
            return None
        t = b[i]; n = b[i + 1]; lb = 0
        if n & 0x80:
            lb = n & 0x7f
            if lb > 4 or i + 2 + lb > len(b):
                return None
            n = int.from_bytes(b[i + 2:i + 2 + lb], 'big')
        st = i + 2 + lb
        if st + n > len(b):
            return None
        v = bytes(b[st:st + n])
        kids = parse_tree(v, depth + 1) if (depth < 5 and n >= 2) else None
        out.append([t, lb, kids if kids is not None else v])
        i = st + n
    return out


def ser_tree(tr):
    out = b''
    for t, lb, v in tr:
        vb = ser_tree(v) if isinstance(v, list) else bytes(v)
        out += tlv(t, vb, lb if lb in (1, 2, 3, 4) and len(vb) < (1 << (8 * lb)) else 0)
    return out


def all_lists(tr, acc=None):
    acc = [] if acc is None else acc
    acc.append(tr)
    for n in tr:
        if isinstance(n[2], list):
            all_lists(n[2], acc)
    return acc


LEARNED = {}   # target -> set of types seen


def tree_mutate(rng, b, pfx, hi, learned):
    head, tail = bytes(b[:pfx]), bytes(b[pfx:])
    tr = parse_tree(tail) if tail else []
    if tr is None:
        return None
    lists = all_lists(tr) if tr else [tr]
    lst = rng.choice(lists)
    op = rng.randrange(6)
    n = rng.choice([1, 1, 2, 2, 3, 4, 6, 8])
    body = bytes(rng.choice(INTERESTING + [rng.randrange(256)]) for _ in range(n))
    t = rng.choice(list(learned)) if learned and rng.random() < 0.7 else rng.randrange(256)
    if op == 0:
        lst.insert(rng.randrange(len(lst) + 1), [t, 0, body])
    elif op == 1 and lst:
        node = rng.choice(lst)       # turn a leaf into a compound holding a new child
        if isinstance(node[2], list):
            node[2].insert(rng.randrange(len(node[2]) + 1), [t, 0, body])
        else:
            node[2] = [[t, 0, body]]
    elif op == 2 and len(lst) > 1:
        del lst[rng.randrange(len(lst))]
    elif op == 3 and lst:
        node = rng.choice(lst)
        if not isinstance(node[2], list):
            node[2] = body
        else:
            node[0] = t
    elif op == 4 and lst:
        i = rng.randrange(len(lst)); lst[i] = [t, 0, [lst[i]]]
    else:
        lst.insert(rng.randrange(len(lst) + 1), [t, rng.choice([0, 1, 2]), [[rng.choice(list(learned)) if learned else 1, 0, body], [t, 0, body]]])
    out = head + ser_tree(tr)
    return out[:hi]


def mutate(rng, b, corp, lo, hi, pfx=0, istlv=False):
    b = bytearray(b)
    if istlv and len(b) >= pfx and rng.random() < 0.6:
        r = tree_mutate(rng, bytes(b), pfx, hi, LEARNED.get('cur'))
        if r is not None:
            return r
    if istlv and len(b) >= pfx and rng.random() < 0.5:
        pos = tlv_bounds(b, pfx)
        op = rng.randrange(4)
        n = rng.choice([1, 1, 2, 2, 3, 4, 6, 8])
        t = rng.choice([rng.randrange(256), rng.randrange(1, 40), rng.randrange(140, 220)])
        body = bytes(rng.choice(INTERESTING + [rng.randrange(256)]) for _ in range(n))
        if op == 0:
            i = rng.choice(pos); b[i:i] = tlv(t, body)
        elif op == 1 and len(pos) > 1:
            # wrap a run of top-level TLVs in a compound TLV
            a = rng.randrange(len(pos) - 1); c = rng.randrange(a + 1, len(pos))
            seg = bytes(b[pos[a]:pos[c]])
            b[pos[a]:pos[c]] = tlv(t, seg)
        elif op == 2 and len(pos) > 1:
            # insert a sub-TLV inside a random TLV (grow it)
            a = rng.randrange(len(pos) - 1)
            seg = bytes(b[pos[a]:pos[a + 1]])
            if len(seg) >= 2 and not seg[1] & 0x80:
                inner = seg[2:] + tlv(rng.randrange(1, 60), body)
                if len(inner) < 0x80:
                    b[pos[a]:pos[a + 1]] = bytes([seg[0], len(inner)]) + inner
        else:
            i = rng.choice(pos); b[i:i] = tlv(t, body) + tlv(rng.randrange(1, 40), body)
        if len(b) > hi:
            b = b[:hi]
        return bytes(b)

    for _ in range(rng.choice([1, 1, 1, 2, 3, 5])):
        op = rng.randrange(9)
        if op == 0 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 1 and b:
            b[rng.randrange(len(b))] = rng.choice(INTERESTING)
        elif op == 2 and b:
            i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
        elif op == 3:
            b.insert(rng.randrange(len(b) + 1), rng.choice(INTERESTING + [rng.randrange(256)]))
        elif op == 4 and len(b) > 1:
            del b[rng.randrange(len(b))]
        elif op == 5:
            # insert a TLV
            n = rng.choice([1, 1, 2, 2, 3, 4, 6, 8])
            t = tlv(rng.choice([rng.randrange(256), rng.randrange(1, 40), rng.randrange(140, 220)]),
                    bytes(rng.choice(INTERESTING + [rng.randrange(256)]) for _ in range(n)))
            i = rng.randrange(len(b) + 1)
            b[i:i] = t
        elif op == 6 and corp:
            o = rng.choice(corp)
            if o and b:
                i = rng.randrange(len(o)); j = rng.randrange(i, min(len(o), i + 12) + 1)
                k = rng.randrange(len(b) + 1)
                b[k:k] = o[i:j]
        elif op == 7 and b:
            i = rng.randrange(len(b)); j = rng.randrange(i, min(len(b), i + 8) + 1)
            b[j:j] = b[i:j]
        elif op == 8 and len(b) > 2:
            b = b[:rng.randrange(1, len(b))]
    if len(b) > hi:
        b = b[:hi]
    if len(b) < lo:
        b += bytes(rng.randrange(256) for _ in range(lo - len(b)))
    return bytes(b)


def ie_seeds(rng, name):
    out = []
    R = lambda n: bytes(rng.choice(INTERESTING + [rng.randrange(256)]) for _ in range(n))
    PAD = bytes(48)

    def harq_ie(mode, rui, sublen, nsub=1, rcid=0):
        w = BitWriter()
        w.put(14, 4); w.put(7, 4)
        per = 4 + (8 if rui else 32) + 4 + 8 + sublen * 4
        total_bits = per * nsub
        ln = (total_bits + 18 + 7) // 8
        w.put(ln, 8); w.put(rcid, 2); w.put(0, 2)
        for _ in range(nsub):
            w.put(rng.randrange(8), 3); w.put(rui, 1)
            if rui:
                w.put(rng.randrange(256), 8)
            else:
                w.put(rng.randrange(256), 8); w.put(rng.randrange(128), 7); w.put(rng.randrange(128), 7)
                w.put(rng.randrange(128), 7); w.put(0, 3)
            w.put(mode, 4); w.put(sublen, 8)
            for _ in range(sublen):
                w.put(rng.randrange(16), 4)
        w.pad(8)
        return w.bytes()

    if name in ('dlmap', 'dlmapc'):
        hdr = (b'\x00\x00\x00\x01\x01\x02\x00\x00\x00\x00\x01\x04' if name == 'dlmap'
               else None)
        def mk(ies):
            if name == 'dlmap':
                return hdr + ies + PAD
            return bytes([0]) + bytes(8) + bytes([1]) + ies + PAD
        for d in range(14):
            out.append(mk(bytes([(d << 4) | rng.randrange(16)]) + R(8)))
        for e in range(16):
            for L in (2, 6, 14, 30):
                out.append(mk(bytes([0xE0 | e, L]) + R(L)))
                out.append(mk(bytes([0xF0 | e, (L // 2) << 4 | rng.randrange(16)]) + R(L)))
        for mode in range(8):
            for rui in (0, 1):
                for sublen in (8, 20, 40):
                    for rcid in (0, 1, 2):
                        out.append(mk(harq_ie(mode, rui, sublen, 1, rcid)))
                    out.append(mk(harq_ie(mode, rui, sublen, 2)))
    elif name == 'ulmap':
        hdr = b'\x00\x01\x00\x00\x00\x10\x04'
        for u in range(16):
            for e in range(16):
                for L in (2, 8, 20):
                    out.append(hdr + b'\x00\x01' + bytes([(u << 4) | e, L]) + R(L) + PAD)
    elif name == 'harqmap2':
        # extension IE (type 14, subtype, length) followed by other IEs, with and without UL IEs appended
        for ul in (0, 1):
            for sub in range(16):
                for L in (1, 2, 3, 4):
                    for t in (0, 1, 2, 3, 5, 6, 7):
                        ext = bytes([0x0E, (sub << 4) | L]) + R(L // 2 + 1)
                        out.append(bytes([ul, 2]) + ext + bytes([(t << 4) | rng.randrange(16)]) + R(10) + PAD[:12])
    elif name == 'harqmap':
        for ul in (0, 1):
            for t in range(16):
                for e in range(16):
                    out.append(bytes([ul, 1, t, (e << 4) | rng.randrange(16)]) + R(10) + PAD[:12])
    return out


def padvars(items, name):
    n = ALIGN.get(name)
    if not n:
        return items
    out = []
    for b in items:
        for p in range(n):
            out.append(b + bytes(p))
    return out


IDLE = int(os.environ.get("IDLE", "4"))
ALIGN = {'dlmap': 10, 'ulmap': 10, 'dlmapc': 10, 'harqmap': 6, 'harqmap2': 6}


def fuzz_target(name, rounds, per):
    base = name[:-2] if name.endswith('_w') else name
    WARNOK[0] = base != name
    wrap, seeds, (lo, hi) = TARGETS[base]
    pfx = PFX.get(base, 0); istlv = base in TLVTARGETS
    path = CORPUS + '/' + name + '.json'
    corp = {}   # hex -> keys
    if os.path.exists(path):
        corp = {h: set(k) for h, k in json.load(open(path))}
    rng = random.Random(1234 + len(corp))
    seen = set()
    for k in corp.values():
        seen |= k
    if not corp:
        extra = []
        if istlv:
            for t in range(256):
                for n in (1, 2, 3, 4, 6, 8):
                    extra.append(bytes(pfx) + tlv(t, bytes(((i + 1) * 0x11) & 0xff for i in range(n))))
        extra += ie_seeds(rng, base)
        init = [s for s in seeds] + extra + [bytes(rng.randrange(256) for _ in range(n)) for n in range(lo, min(hi, 24) + 1) for _ in range(3)]
        init = padvars(init, base)
        res = evaluate([wrap(s) for s in init]) or []
        for s, (bad, k) in zip(init, res):
            if not bad and (k - seen):
                corp[s.hex()] = k; seen |= k
    idle = 0
    def relearn():
        ls = set()
        for h in corp:
            tr = parse_tree(bytes.fromhex(h)[pfx:])
            if tr:
                for l in all_lists(tr):
                    for nd in l:
                        ls.add(nd[0])
        LEARNED['cur'] = ls or set(range(1, 60))
    relearn()
    for r in range(rounds):
        relearn()
        if idle >= IDLE:
            break
        items = [bytes.fromhex(h) for h in corp] or [b'']
        batch = []
        for _ in range(per):
            batch.append(mutate(rng, rng.choice(items), items, lo, hi, pfx, istlv))
        if base in ALIGN:
            batch = batch[:max(1, per // ALIGN[base])]
        batch = padvars(batch, base)
        res = evaluate([wrap(s) for s in batch])
        if res is None:
            print(name, 'round', r, 'evaluate failed'); continue
        added = 0
        for s, (bad, k) in zip(batch, res):
            if not bad and (k - seen):
                corp[s.hex()] = k; seen |= k; added += 1
        idle = 0 if added else idle + 1
        print(name, 'round', r, 'corpus', len(corp), 'keys', len(seen), 'added', added, flush=True)
        json.dump([[h, sorted(k)] for h, k in corp.items()], open(path, 'w'))


if __name__ == '__main__':
    for nm in sys.argv[1].split(','):
        fuzz_target(nm, int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 3000)
