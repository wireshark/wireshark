#!/usr/bin/env python3
# Helper module for the nfapi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Search helper for mknfapi.py: finds, per TLV tag, bodies that decode with
# the exact TLV length (no malformed, no error expert info).
# Usage: scan.py gen <dir> <maxlen> <variants> | scan.py pick <dir> <badfile>
import struct
import sys
import random
import json
TAGS = list(range(0x0000, 0x0134)) + list(range(0x1000, 0x100E)) + \
       list(range(0x2000, 0x205C)) + list(range(0x3000, 0x301B))

import re
NULLTAGS = set(int(m, 16) for m in re.findall(r"\{ (0x[0-9A-F]{4}), NULL, NULL \}",
    open(os.path.join(SRCDIR, "epan/dissectors/packet-nfapi.c")).read()))

def exp(name=b"nfapi"):
    n = name + b"\0" * ((4 - len(name) % 4) % 4)
    return struct.pack(">HH", 12, len(n)) + n + struct.pack(">HH", 0, 0)

def p5(msgid, payload):
    return struct.pack(">HHHH", 0, msgid, 8 + len(payload), 0) + payload

def body(tag, ln, v):
    if v == 0:
        return bytes(ln)
    r = random.Random(tag * 100003 + ln * 31 + v)
    dens = [0.05, 0.15, 0.4, 0.8][v % 4]
    mx = [3, 8, 40, 255][(v // 4) % 4]
    return bytes((r.randint(1, mx) if r.random() < dens else 0) for _ in range(ln))

def pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(frames):
            f.write(struct.pack("<IIII", i, 0, len(p), len(p)) + p)

if sys.argv[1] == "gen":
    out, maxlen, nv = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    frames, idx = [], []
    for tag in TAGS:
        for ln in range(1, maxlen + 1):
            for v in range(nv):
                b = body(tag, ln, v)
                frames.append(exp() + p5(0x0100, struct.pack(">HH", tag, ln) + b))
                idx.append((tag, ln, v))
    pcap(out + "/scan.pcap", frames)
    json.dump(idx, open(out + "/scan.json", "w"))
    print(len(frames))

if sys.argv[1] == "pick":
    # pick <dir> <maxperTag>: greedy selection of good bodies by new (field, value) pairs
    import subprocess, collections
    import xml.etree.ElementTree as ET
    d, cap = sys.argv[2], int(sys.argv[3])
    idx = json.load(open(d + "/scan.json"))
    bad = set(int(x) for x in open(d + "/scan.bad").read().split())
    cand = []
    for i, (t, l, v) in enumerate(idx):
        if i + 1 in bad or t in NULLTAGS:
            continue
        if t in (0x300a, 0x300d, 0x3010, 0x3012, 0x3013, 0x3017) and l > 12:
            continue
        cand.append((t, l, v))
    random.Random(7).shuffle(cand)
    frames = [exp() + p5(0x0100, struct.pack(">HH", t, l) + body(t, l, v)) for t, l, v in cand]
    pcap(d + "/cand.pcap", frames)
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=d + "/cfg")
    p = subprocess.Popen([os.environ.get("TSHARK", "tshark"), "-r", d + "/cand.pcap", "-T", "pdml", "-J", "nfapi"],
                         stdout=subprocess.PIPE, env=env)
    seen = collections.defaultdict(set)
    picks = collections.defaultdict(list)
    n = 0
    for ev, el in ET.iterparse(p.stdout):
        if el.tag != "packet":
            continue
        t, l, v = cand[n]; n += 1
        sig = set()
        for f in el.iter("field"):
            nm = f.get("name")
            if nm and nm.startswith("nfapi."):
                sig.add((nm, f.get("show")))
        new = sig - seen[t]
        if new and len(picks[t]) < cap:
            seen[t] |= sig
            picks[t].append(body(t, l, v).hex())
        el.clear()
    json.dump(picks, open(d + "/picks.json", "w"))
    print(n, "candidates", sum(len(x) for x in picks.values()), "picked", len(picks), "tags")
