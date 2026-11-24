#!/usr/bin/env python3
# Generates test/captures/woww_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic WoWW (World of Warcraft world protocol) captures.
# Usage: mkwoww.py <outdir>
# Exported PDU frames (dissector name "woww", TCP port tags). Only the first
# header per direction of a conversation is unencrypted, so every frame
# uses its own conversation (own client port) and carries one message whose
# body is generated from the parser in packet-woww.c by wowwgen.py.
import struct
import sys
import os
import zlib
import wowwgen
from woww_common_exppdu import exppdu, write_pcap, server_msg, client_msg

CAP = 14   # most variants per opcode and direction
BIGCAP = {'SMSG_UPDATE_OBJECT': 90, 'SMSG_COMPRESSED_UPDATE_OBJECT': 90, 'CMSG_CAST_SPELL': 40, 'CMSG_USE_ITEM': 40, 'CMSG_PET_CAST_SPELL': 40, 'SMSG_SPELL_GO': 40, 'SMSG_SPELL_START': 40, 'SMSG_SPELLLOGEXECUTE': 90, 'SMSG_SEND_MAIL_RESULT': 60}

def cases(body):
    import re
    parts = re.split(r'\n        case ([A-Z][A-Z_0-9]*):\n', body)
    # parts[0] is the prefix, then name, text pairs
    out = []
    for name, text in zip(parts[1::2], parts[2::2]):
        out.append((name, text))
    return out

def cand_info(consts, toks):
    '''{var: (candidates, is_flag)} for the variables of one case.'''
    # In the order of first use: a set's order depends on the hash seed.
    vs = dict.fromkeys(t for t in toks if t[0].islower() and not t.startswith(('hf_', 'ett', 'ptvcursor', 'add_', 'tvb_')) and t not in ('compressed_tvb', 'old_ptv', 'compression_end', 'ptv', 'pinfo', 'tree', 'offset_packet_end', 'uint32_t', 'unsigned', 'uint8_t', 'ptvcursor_t'))
    info = {}
    for v in vs:
        c = wowwgen.case_candidates(toks, consts, v)
        info[v] = (c, wowwgen.case_candidates.is_flag)
    return info

def radix(info):
    '''E: the cycle length of the non-flag variables.'''
    e = 1
    for v, (c, fl) in info.items():
        if not fl:
            e = max(e, len(c))
    return e

def onehots(consts, text):
    '''Single flag values of flag variables used in an else-if chain.'''
    import re
    toks = wowwgen.tokenize(text)
    info = cand_info(consts, toks)
    out = []
    s = ' '.join(toks)
    for v in sorted(set(re.findall(r'else if \( ([a-z_0-9]+) &', s))):
        c, fl = info[v]
        if fl:
            for x in c[1:-1]:
                out.append((v, x))
    return out[:24]

def build(consts, name, text, direction, k, short_inner=False, onehot=None):
    toks = wowwgen.tokenize(text)
    P = wowwgen.Parser(toks)
    stmts = []
    while P.peek() not in (None, "}"):
        stmts.append(P.stmt())
    info = cand_info(consts, toks)
    E = E_of(toks, info)
    order = []
    for t in toks:
        if t in info and t not in order and not info[t][1] and len(info[t][0]) > 1:
            order.append(t)
    first, second = (order + [None, None])[:2]
    def choose(var, w):
        if var == '__guid_mask':
            c = [0x05, 0x00, 0xff, 0x81]
        elif var == '__splines':
            c = [2, 1, 0]
        elif var == '__masks':
            c = [1, 2, 0]
        elif var == 'len':
            c = [6, 0]
        else:
            c, fl = info.get(var, ([0], False))
            if fl and onehot is not None:
                return (onehot[1] if var == onehot[0] else c[0]) & ((1 << (8 * w)) - 1)
            if fl:
                ph = k // E
                i = ph % len(c) if len(c) <= 20 else (len(c) - 1 if ph % 7 == 6 else 0)
                return c[i] & ((1 << (8 * w)) - 1)
        if var == first:
            v = c[k % len(c)]
        elif var == second and len(info[first][0]) * len(c) <= 60:
            v = c[(k // len(info[first][0])) % len(c)]
        else:
            v = c[k % len(c)]
        return v & ((1 << (8 * w)) - 1) if w else v
    g = wowwgen.Gen(consts, direction, choose)
    g.short_inner = short_inner
    try:
        for s in stmts:
            g.run(s)
    except wowwgen.Break:
        pass
    assert len(g.stack) == 1, name
    return bytes(g.out)

def E_of(toks, info):
    E = radix(info)
    if 'add_packed_guid' in toks: E = max(E, 3)
    if 'add_update_mask' in toks: E = max(E, 3)
    if 'add_monster_move_spline' in toks: E = max(E, 3)
    if 'len' in info and 'offset_packet_end' in toks: E = max(E, 2)
    order = []
    for t in toks:
        if t in info and t not in order and not info[t][1] and len(info[t][0]) > 1:
            order.append(t)
    if len(order) >= 2 and len(info[order[0]][0]) * len(info[order[1]][0]) <= 60:
        E = max(E, len(info[order[0]][0]) * len(info[order[1]][0]))
    return E

def nvariants(consts, name, text):
    toks = wowwgen.tokenize(text)
    info = cand_info(consts, toks)
    E = E_of(toks, info)
    fls = [len(c) for c, f in info.values() if f]
    small = max([l for l in fls if l <= 20] or [1])
    if any(l > 20 for l in fls):
        small = max(small, 2)
    # flag variables: all flags set, then each single flag (the else-if chains)
    n = E * small
    return min(n, BIGCAP.get(name, max(CAP, min(E, 48))))

import random

def write_pcap_trunc(name, frames):
    '''frames: (data, original length) pairs.'''
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 0x7fffffff, 252))
        for i, (fr, orig) in enumerate(frames):
            f.write(struct.pack('<IIII', i + 1, 0, len(fr), orig))
            f.write(fr)

def extra_main(frames, add, consts):
    '''Frames that are not generated from the parser: unknown opcodes,
    a PDU with two messages and the reproducers that decode cleanly.'''
    # unknown opcodes in the first (plain) header
    add('server', 0x7ffe, b'unknown server message')
    add('client', 0x7fffe, b'unknown client message')
    # two messages in one PDU: the second header is encrypted and the
    # session key is not known, so only the first message is decoded
    port[0] += 1
    frames.append(exppdu(struct.pack('>H', 6) + struct.pack('<H', consts['SMSG_PONG']) + struct.pack('<I', 7) + bytes([1, 2, 3, 4, 5, 6, 7, 8]), 3724, port[0]))
    port[0] += 1
    frames.append(exppdu(struct.pack('>H', 8) + struct.pack('<I', consts['CMSG_PING']) + struct.pack('<I', 7) + bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), port[0], 3724))
    # SMSG_SEND_MAIL_RESULT, mail result two with an equip error
    add('server', consts['SMSG_SEND_MAIL_RESULT'], struct.pack('<IIII', 9, 0, 1, 5))
    # packed GUID data sources: reproducers of "WoWW: Fix CPU blow-ups on
    # unterminated strings and packed GUIDs" at a size that decodes quickly
    for n in (1000, 3000):
        body = struct.pack('<IB', 1, 0) + bytes([4]) + struct.pack('<I', n) + bytes(n)
        add('server', consts['SMSG_UPDATE_OBJECT'], body)
        raw = body
        add('server', consts['SMSG_COMPRESSED_UPDATE_OBJECT'], struct.pack('<I', len(raw)) + zlib.compress(raw, 9))
    # the same string loops, with terminated strings
    add('server', consts['SMSG_EXPECTED_SPAM_RECORDS'], struct.pack('<I', 100) + b'spam\0' * 100)
    # AddonInfo with 2000 terminated addon names (zlib)
    raw = b''.join(b'Addon%d\0' % i + bytes([1]) + struct.pack('<II', i, i) for i in range(2000))
    add('client', consts['CMSG_AUTH_SESSION'], struct.pack('<II', 5875, 1) + b'ACCOUNT\0' + struct.pack('<I', 42) + bytes(range(20)) + struct.pack('<I', len(raw)) + zlib.compress(raw, 9))

def malformed(out, consts):
    fr = []
    port = [43000]
    def add(direction, opcode, body, size=None, orig=None):
        port[0] += 1
        if direction == 'server':
            p = server_msg(opcode, body)
            if size is not None: p = struct.pack('>H', size) + p[2:]
            fr.append((exppdu(p, 3724, port[0]), orig))
        else:
            p = client_msg(opcode, body)
            if size is not None: p = struct.pack('>H', size) + p[2:]
            fr.append((exppdu(p, port[0], 3724), orig))
    def fix(i):
        d, o = fr[i]
        fr[i] = (d, len(d) if o is None else o)
    # string loops with no terminator (infinite loops before the fix)
    add('server', consts['SMSG_EXPECTED_SPAM_RECORDS'], struct.pack('<I', 0xffffffff) + b'A' * 32800)
    add('server', consts['SMSG_EXPECTED_SPAM_RECORDS'], struct.pack('<I', 100) + b'A' * 32800)
    add('server', consts['SMSG_EXPECTED_SPAM_RECORDS'], struct.pack('<I', 3) + b'ab\0cd\0ef')
    # AddonInfo with no NUL in 1 MB of 'A' (12 s before the fix)
    raw = b'A' * 1000000
    add('client', consts['CMSG_AUTH_SESSION'], struct.pack('<II', 5875, 1) + b'ACCOUNT\0' + struct.pack('<I', 42) + bytes(range(20)) + struct.pack('<I', len(raw)) + zlib.compress(raw, 9))
    # one data source per packed GUID: 65 KB frame and 3M GUIDs after zlib
    n = 65535 + 2 - 4 - 10
    add('server', consts['SMSG_UPDATE_OBJECT'], struct.pack('<IB', 1, 0) + bytes([4]) + struct.pack('<I', n) + bytes(n))
    raw = struct.pack('<IB', 1, 0) + bytes([4]) + struct.pack('<I', 3000000) + bytes(3000000)
    add('server', consts['SMSG_COMPRESSED_UPDATE_OBJECT'], struct.pack('<I', len(raw)) + zlib.compress(raw, 9))
    # size smaller than the header, size 0xffff in a 64 KB PDU
    p = struct.pack('>H', 0) + struct.pack('<I', consts['CMSG_WARDEN_DATA']) + b'\x11' * 16
    fr.append((exppdu(p, 41000, 3724), None))
    p = struct.pack('>H', 0xffff) + struct.pack('<I', consts['CMSG_WARDEN_DATA']) + b'\x22' * (0xffff + 2 - 6)
    fr.append((exppdu(p, 41001, 3724), None))
    # size larger than the frame
    add('server', consts['SMSG_PONG'], struct.pack('<I', 7), size=100)
    add('client', consts['CMSG_PING'], struct.pack('<II', 7, 8), size=900)
    # reported length below the minimum, captured length 0 and 1
    fr.append((exppdu(b'\x00\x02\x01', 41002, 3724), None))
    hdr = exppdu(b'', 41003, 3724)
    fr.append((hdr, len(hdr) + 8))
    fr.append((hdr + b'\x00', len(hdr) + 8))
    # compressed data that is not a zlib stream
    for name in ('CMSG_AUTH_SESSION', 'CMSG_UPDATE_ACCOUNT_DATA', 'CMSG_GMTICKET_CREATE'):
        pass
    add('client', consts['CMSG_UPDATE_ACCOUNT_DATA'], struct.pack('<II', 1, 100) + b'not zlib data')
    add('client', consts['CMSG_AUTH_SESSION'], struct.pack('<II', 5875, 1) + b'ACCOUNT\0' + struct.pack('<I', 42) + bytes(range(20)) + struct.pack('<I', 100) + b'not zlib data')
    add('server', consts['SMSG_COMPRESSED_UPDATE_OBJECT'], struct.pack('<I', 100) + b'not zlib data')
    add('server', consts['SMSG_COMPRESSED_MOVES'], struct.pack('<I', 100) + b'not zlib data')
    # compressed data shorter than the outer end offset (len is computed from
    # the outer tvb in the zlib paths, so these are Malformed Packets)
    for name in ('CMSG_UPDATE_ACCOUNT_DATA', 'CMSG_GMTICKET_CREATE'):
        for k in range(4):
            text = dict(cases(wowwgen.load()[1]))[name]
            b = build(consts, name, text, 'client', k, short_inner=True)
            add('client', consts[name], b)
    # truncated messages: the first N generated messages cut short
    consts_, body = wowwgen.load()
    rnd = random.Random(1)
    for name, text in cases(body)[::9]:
        d = 'client' if name.startswith('CMSG_') else 'server'
        if d == 'server' and consts[name] > 0xffff: continue
        b = build(consts, name, text, d, 0)
        if len(b) < 4: continue
        cut = len(b) - rnd.randint(1, min(len(b) - 1, 12))
        port[0] += 1
        p = server_msg(consts[name], b) if d == 'server' else client_msg(consts[name], b)
        e = exppdu(p, 3724, port[0]) if d == 'server' else exppdu(p, port[0], 3724)
        fr.append((e[:len(e) - (len(b) - cut)], len(e)))
    for i in range(len(fr)):
        fix(i)
    write_pcap_trunc(os.path.join(out, 'woww-coverage-malformed.pcap'), fr)

def keydeduce(out):
    '''One conversation whose later headers are opaque bytes. The dissector
    deduces the session key from client headers (known plaintext), so more
    than 20 client messages make later headers "decryptable". The header
    bytes here are arbitrary; no cipher is implemented. Not part of the
    main capture: the first pass and -2 decode these frames differently.'''
    rnd = random.Random(7)
    fr = []
    def srv(sp, dp, data): fr.append(exppdu(data, sp, dp))
    # conversation A: client side. Plain first message, then opaque headers
    cp = 45000
    fr.append(exppdu(client_msg(0x1DC, struct.pack('<II', 1, 2)), cp, 3724))
    for i in range(28):
        hdr = bytes(rnd.randrange(256) for _ in range(6))
        fr.append(exppdu(hdr + bytes(24), cp, 3724))
    # server side of the same conversation: plain first message, then
    # frames whose headers are opaque bytes; large frames make the
    # decrypted size field fit often, so several messages follow in a PDU
    fr.append(exppdu(server_msg(0x1DD, struct.pack('<I', 7)), 3724, cp))
    for i in range(20):
        hdr = bytes(rnd.randrange(256) for _ in range(4))
        fr.append(exppdu(hdr + bytes(rnd.randrange(256) for _ in range(30000)), 3724, cp))
    # conversation B: server frames first (headers kept until the key is
    # deduced from the client frames that follow)
    cp = 45001
    fr.append(exppdu(server_msg(0x1DD, struct.pack('<I', 7)), 3724, cp))
    for i in range(3):
        hdr = bytes(rnd.randrange(256) for _ in range(4))
        fr.append(exppdu(hdr + bytes(20), 3724, cp))
    fr.append(exppdu(client_msg(0x1DC, struct.pack('<II', 1, 2)), cp, 3724))
    for i in range(30):
        hdr = bytes(rnd.randrange(256) for _ in range(6))
        fr.append(exppdu(hdr + bytes(24), cp, 3724))
    write_pcap(os.path.join(out, 'woww-coverage-keydeduce.pcap'), fr)

port = [40000]

def main(out):
    consts, body = wowwgen.load()
    frames = []
    def add(direction, opcode, b):
        port[0] += 1
        if direction == 'server':
            payload = server_msg(opcode, b)
            frames.append(exppdu(payload, 3724, port[0]))
        else:
            payload = client_msg(opcode, b)
            frames.append(exppdu(payload, port[0], 3724))
    index = []
    for name, text in cases(body):
        op = consts[name]
        dirs = ['client'] if name.startswith('CMSG_') else ['server'] if name.startswith('SMSG_') else ['client', 'server']
        n = nvariants(consts, name, text)
        for d in dirs:
            if d == 'server' and op > 0xffff:
                continue
            for k in range(n):
                b = build(consts, name, text, d, k)
                index.append((len(frames) + 1, name, d, k))
                add(d, op, b)
            seen = set()
            toks_ = wowwgen.tokenize(text)
            E = E_of(toks_, cand_info(consts, toks_))
            for j, oh in enumerate(onehots(consts, text)):
                for kk in range(E):
                    b = build(consts, name, text, d, kk, onehot=oh)
                    if b in seen:
                        continue
                    seen.add(b)
                    index.append((len(frames) + 1, name, d, 100 + j))
                    add(d, op, b)
    extra_main(frames, add, consts)
    write_pcap(os.path.join(out, 'woww-coverage.pcap'), frames)
    malformed(out, consts)
    keydeduce(out)
    with open(os.path.join(out, 'woww-index.txt'), 'w') as f:
        for i in index:
            f.write('%d %s %s %d\n' % i)
    print(len(frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1])
