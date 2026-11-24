# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Structured random generator for BSSMAP / DTAP messages (group g4).

Parses the message function tables and their ELEM_* sequences from the
dissector sources and writes Exported PDU captures with random element
contents.  Usage: python3 g4_fuzz.py <seed> <count-per-msg>
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import random
import re
import sys

from g4_common import write_exp_pdu_pcap

SRC = os.path.join(SRCDIR, 'epan/dissectors', '')


def strip_comments(s):
    s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
    return re.sub(r'//[^\n]*', '', s)


def enum_values(hdr, last):
    i = hdr.index(last + ' ')
    j = hdr.rindex('typedef enum', 0, i)
    body = strip_comments(hdr[j:i + len(last)])
    body = body[body.index('{') + 1:]
    vals = {}
    n = 0
    for item in body.split(','):
        item = item.strip()
        if not item:
            continue
        if '=' in item:
            k, v = item.split('=')
            n = int(v.strip(), 0)
            item = k.strip()
        vals[item] = n
        n += 1
    return vals


def functions(src):
    """name -> list of (macro, iei-token)"""
    out = {}
    for m in re.finditer(r'\n(?:static )?void\s*\n?(\w+)\s*\(tvbuff_t \*tvb[^)]*unsigned len\)\s*\{', src):
        name = m.group(1)
        end = src.find('\n}\n', m.end())
        body = strip_comments(src[m.end():end])
        elems = []
        for e in re.finditer(r'(ELEM_[A-Z_]+)\(([^,]+),', body):
            elems.append((e.group(1), e.group(2).strip()))
        out[name] = elems
    return out


def fcn_array(src, name):
    m = re.search(name + r'\[\]\)\(.*?\)\s*=\s*\{(.*?)\n\};', src, re.S)
    return [x.strip() for x in strip_comments(m.group(1)).split(',') if x.strip()]


def vs_values(src, name):
    m = re.search(r'value_string ' + name + r'\[\]\s*=\s*\{(.*?)\n\};', src, re.S)
    return [int(x, 0) for x in re.findall(r'\{\s*(0x[0-9a-fA-F]+|\d+)\s*,', strip_comments(m.group(1)))]


def rnd_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def rnd_len():
    r = random.random()
    if r < 0.15:
        return 0
    if r < 0.7:
        return random.randint(1, 8)
    if r < 0.95:
        return random.randint(9, 40)
    return random.randint(41, 255)


def build(elems, resolve):
    out = b''
    for macro, tok in elems:
        opt = macro.startswith('ELEM_OPT')
        if opt and random.random() < 0.5:
            continue
        kind = macro.split('_', 2)[2]
        iei = resolve(tok)
        if 'T' in kind.split('_')[0] and kind != 'V' and iei is None:
            iei = random.getrandbits(8)
        if kind == 'V':
            out += rnd_bytes(random.randint(1, 8))
        elif kind in ('LV',):
            n = rnd_len()
            out += bytes([n]) + rnd_bytes(n)
        elif kind in ('LV_E',):
            n = rnd_len()
            out += bytes([n >> 8, n & 0xff]) + rnd_bytes(n)
        elif kind == 'TLV':
            n = rnd_len()
            out += bytes([iei & 0xff, n]) + rnd_bytes(n)
        elif kind == 'TLV_E':
            n = rnd_len()
            out += bytes([iei & 0xff, n >> 8, n & 0xff]) + rnd_bytes(n)
        elif kind == 'TV':
            out += bytes([iei & 0xff]) + rnd_bytes(random.randint(1, 17))
        elif kind == 'TV_SHORT':
            out += bytes([(iei & 0xf0) | random.getrandbits(4)])
        elif kind == 'T':
            out += bytes([iei & 0xff])
    if random.random() < 0.3:
        out += rnd_bytes(random.randint(1, 10))
    return out


def resolver(enum):
    def r(tok):
        if tok in enum:
            return enum[tok]
        try:
            return int(tok, 0)
        except ValueError:
            return None
    return r


def main():
    seed = int(sys.argv[1])
    count = int(sys.argv[2])
    random.seed(seed)
    hdr = open(SRC + 'packet-gsm_a_common.h').read()
    be = enum_values(hdr, 'BE_NONE')

    # BSSMAP
    src = open(SRC + 'packet-gsm_a_bssmap.c').read()
    fns = functions(src)
    names = fcn_array(src, 'bssmap_msg_fcn')
    vals = vs_values(src, 'gsm_a_bssmap_msg_strings')
    pk = []
    for v, n in zip(vals, names):
        if n == 'NULL' or n not in fns:
            continue
        for _ in range(count):
            pk.append(bytes([v]) + build(fns[n], resolver(be)))
    write_exp_pdu_pcap('g4_fuzz_bssmap_%d.pcap' % seed, 'gsm_a_bssmap', pk)

    # DTAP (CC, MM, SMS, SS, TP, GCC, BCC)
    src = open(SRC + 'packet-gsm_a_dtap.c').read()
    fns = functions(src)
    pk = []
    for pd, strs, arr in [(0, 'gsm_a_dtap_msg_gcc_strings', 'dtap_msg_gcc'),
                          (1, 'gsm_a_dtap_msg_bcc_strings', 'dtap_msg_bcc'),
                          (3, 'gsm_a_dtap_msg_cc_strings', 'dtap_msg_cc_fcn'),
                          (5, 'gsm_a_dtap_msg_mm_strings', 'dtap_msg_mm_fcn'),
                          (9, 'gsm_a_dtap_msg_sms_strings', 'dtap_msg_sms_fcn'),
                          (11, 'gsm_a_dtap_msg_ss_strings', 'dtap_msg_ss_fcn'),
                          (15, 'gsm_a_dtap_msg_tp_strings', 'dtap_msg_tp_fcn')]:
        names = fcn_array(src, arr)
        vals = vs_values(src, strs)
        for v, n in zip(vals, names):
            if n == 'NULL' or n not in fns:
                continue
            for _ in range(count):
                ti = random.choice([0x00, 0x10, 0x70, 0x80]) if pd in (0, 1, 3, 9, 11) else 0
                body = build(fns[n], resolver({}))
                if (ti >> 4) & 0x7 == 0x7:
                    pk.append(bytes([ti | pd, random.getrandbits(7), v]) + body)
                else:
                    pk.append(bytes([ti | pd, v]) + body)
    write_exp_pdu_pcap('g4_fuzz_dtap_%d.pcap' % seed, 'gsm_a_dtap', pk)

    # BSSLAP
    src = open(SRC + 'packet-gsm_bsslap.c').read()
    defs = {k: int(v, 0) for k, v in re.findall(r'#define (BSSLAP_PARAM_\w+)\s+(0x[0-9A-Fa-f]+)', src)}
    msgs = {k: int(v) for k, v in re.findall(r'#define (BSSLAP_[A-Z0-9_]+)\s+(\d+)\n', src)}
    fns = {}
    for m in re.finditer(r'\nstatic void\s*\n(dissect_gsm_bsslap_\w+)\s*\([^)]*int offset\)\s*\{', src):
        end = src.find('\n}\n', m.end())
        body = strip_comments(src[m.end():end])
        fns[m.group(1)] = [(e.group(1), e.group(2).strip()) for e in re.finditer(r'(ELEM_[A-Z_]+)\(([^,]+),', body)]
    pk = []
    for case, fn in re.findall(r'case (BSSLAP_[A-Z0-9_]+):\s*\n\s*(?:/\*.*?\*/\s*)?(?:(dissect_gsm_bsslap_\w+)|break)', src):
        for _ in range(count):
            body = build(fns[fn], resolver(defs)) if fn else rnd_bytes(random.randint(0, 6))
            pk.append(bytes([msgs[case]]) + body)
    write_exp_pdu_pcap('g4_fuzz_bsslap_%d.pcap' % seed, 'gsm_bsslap', pk)


if __name__ == '__main__':
    main()
