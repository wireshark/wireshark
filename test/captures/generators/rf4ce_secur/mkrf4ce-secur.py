#!/usr/bin/env python3
# Generates test/captures/rf4ce_secur_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the RF4CE security helper coverage captures (packet-rf4ce-secur.c:
key seed handling, the address table, the NWK key and vendor secret storage,
the GDP key exchange state and CCM* decryption of secured NWK frames).

Usage: mkrf4ce-secur.py [-v] [outdir]   (writes rf4ce-secur-coverage.pcap and
rf4ce-secur-coverage-malformed.pcap, IEEE 802.15.4 without FCS (link type 230),
built with struct only).

packet-rf4ce-secur.c has no dissector of its own: RF4CE NWK (a heuristic
dissector on the 802.15.4 payload) and the RF4CE profile dissector call it.
No cryptography is written here and no valid MIC is made: the key seeds,
the random numbers and the tags of the key exchange are made-up bytes and
secured frames carry made-up payloads, so the AES-CCM* decryption and the
key derivation of a matching key exchange tag stay unreached. Nothing comes
from a real network.
"""
# ---- IEEE 802.15.4 / RF4CE helpers (link type 230, no FCS) ----
import struct
import sys
import os

class Cap:
    def __init__(self, linktype=230, snaplen=262144):
        self.lt = linktype; self.snap = snaplen; self.frames = []; self.t = 1700000000.0; self.seq = 0
    def add(self, data, dt=0.01, orig=None):
        """orig: the length on the wire when the capture is cut off (snaplen)"""
        self.t += dt
        self.frames.append((self.t, bytes(data), len(data) if orig is None else orig))
        return len(self.frames)
    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, self.snap, self.lt))
            for t, p, o in self.frames:
                s = int(t); us = int((t - s) * 1e6)
                f.write(struct.pack("<IIII", s, us, len(p), o) + p)
    def nseq(self):
        self.seq = (self.seq + 1) & 0xff
        return self.seq

PAN = 0x1234
# EUI-64 addresses as they are on the air (little endian)
CTRL = bytes.fromhex("0200000000000011")      # controller
TGT = bytes.fromhex("0200000000000022")       # target
OTHER = bytes.fromhex("0200000000000033")
S_CTRL, S_TGT, S_OTHER = 0x0001, 0x0002, 0x0003

def mac_ll(seq, dst, src, nwk, pan=PAN):
    """Data frame, PAN ID compression, long destination and source address."""
    return struct.pack("<HBH", 0xcc41, seq, pan) + dst + src + nwk

def mac_ss(seq, dst, src, nwk, pan=PAN):
    """Data frame, PAN ID compression, short destination and source address."""
    return struct.pack("<HBHHH", 0x8841, seq, pan, dst, src) + nwk

def mac_bcast(seq, src, nwk, pan=PAN):
    """Data frame to the broadcast short address and PAN, long source address (no compression)."""
    return struct.pack("<HBHHH", 0xc801, seq, 0xffff, 0xffff, pan) + src + nwk

def mac_ls(seq, dst, src16, nwk, pan=PAN):
    """Long destination, short source address."""
    return struct.pack("<HBH", 0x8c41, seq, pan) + dst + struct.pack("<H", src16) + nwk

def mac_sl(seq, dst16, src, nwk, pan=PAN):
    """Short destination, long source address."""
    return struct.pack("<HBHH", 0xc841, seq, pan, dst16) + src + nwk

FT_RESERVED, FT_DATA, FT_CMD, FT_VENDOR = 0, 1, 2, 3

def nwk(ftype, counter, payload=b"", sec=0, ver=0, ch=0, resv=1, profile=None, vendor=None):
    fcf = ftype | (sec << 2) | (ver << 3) | (resv << 5) | (ch << 6)
    b = bytes([fcf]) + struct.pack("<I", counter)
    if profile is not None:
        b += bytes([profile])
    if vendor is not None:
        b += struct.pack("<H", vendor)
    return b + payload

def cmd(counter, cmd_id, payload=b"", **kw):
    return nwk(FT_CMD, counter, bytes([cmd_id]) + payload, **kw)

def data(counter, profile, payload=b"", **kw):
    return nwk(FT_DATA, counter, payload, profile=profile, **kw)

def vendor_data(counter, profile, vendor, payload=b"", **kw):
    return nwk(FT_VENDOR, counter, payload, profile=profile, vendor=vendor, **kw)

# ---- NWK command payloads ----
def node_caps(ntype=1, ac=1, sec=1, norm=0, resv=0):
    return bytes([ntype | (ac << 1) | (sec << 2) | (norm << 3) | (resv << 4)])

def vendor_info(vid=0xfff1, s=b"VENDOR"):
    return struct.pack("<H", vid) + s.ljust(7, b"\0")[:7]

def app_caps(usr=False, devs=(), profs=(), r1=0, r2=0):
    b = (1 if usr else 0) | (len(devs) << 1) | (r1 << 3) | (len(profs) << 4) | (r2 << 7)
    return bytes([b])

def disc_req(devs=(1,), profs=(0, 3), usr=None, req_dev=0xff, **kw):
    p = node_caps(**kw) + vendor_info() + app_caps(usr is not None, devs, profs)
    if usr is not None: p += usr.ljust(15, b"\0")[:15]
    return p + bytes(devs) + bytes(profs) + bytes([req_dev])

def class_desc(num=0, dup=0, resv=0):
    return bytes([num | (dup << 4) | (resv << 6)])

def disc_rsp(status=0, devs=(2,), profs=(0, 3), usr=None, lqi=0x80, **kw):
    p = bytes([status]) + node_caps(**kw) + vendor_info() + app_caps(usr is not None, devs, profs)
    if usr is not None:
        p += usr
    return p + bytes(devs) + bytes(profs) + bytes([lqi])

def usr_str_rsp(s=b"remote", classes=((0, 0), (1, 1), (15, 2)), lqi=0x40, resv=0):
    """15 octets of Extra Status Information of a Discovery Response."""
    return s.ljust(8, b"\0")[:8] + b"\0" + struct.pack("<H", resv) + b"".join(class_desc(n, d) for n, d in classes) + bytes([lqi])

def pair_req(addr=0xfffe, devs=(1,), profs=(0, 3), kex=2, usr=None, **kw):
    p = struct.pack("<H", addr) + node_caps(**kw) + vendor_info() + app_caps(usr is not None, devs, profs)
    if usr is not None: p += usr.ljust(15, b"\0")[:15]
    return p + bytes(devs) + bytes(profs) + bytes([kex])

def pair_rsp(status=0, alloc=0x0001, addr=0x0002, devs=(2,), profs=(0, 3), **kw):
    return (bytes([status]) + struct.pack("<HH", alloc, addr) + node_caps(**kw) + vendor_info() +
            app_caps(False, devs, profs) + bytes(devs) + bytes(profs))

def key_seed(seq, fill=0):
    return bytes([seq]) + bytes(((i * 7 + fill + seq) & 0xff) for i in range(80))

def ping(opt=0, pl=b"\x01\x02\x03\x04"):
    return bytes([opt]) + pl

# ---- profile (GDP / ZRC) frames ----
def pfcf(cmd_id, cmd_frame=1, resv=0, pending=0):
    return bytes([(cmd_id & 0xf) | (resv << 4) | (cmd_frame << 6) | (pending << 7)])

def attr_get(items, arr_ids=()):
    """Get/Pull Attributes request body: (id[, entry id]) per item."""
    return b"".join(bytes([i]) + (struct.pack("<H", e) if e is not None else b"") for i, e in items)

def attr_rsp(items):
    """(id, entry or None, status, value or None) -> attribute response body"""
    b = b""
    for i, e, st, v in items:
        b += bytes([i]) + (struct.pack("<H", e) if e is not None else b"") + bytes([st])
        if st == 0 and v is not None:
            b += bytes([len(v)]) + v
    return b

def attr_push(items):
    """(id, entry or None, value) -> Push/Set Attributes body"""
    b = b""
    for i, e, v in items:
        b += bytes([i]) + (struct.pack("<H", e) if e is not None else b"") + bytes([len(v)]) + v
    return b


# ---- main ----
def eui(i, base=0x30):
    return bytes([0x02, 0, 0, 0, 0, base + (i >> 8), i & 0xff, 0x80 | (i & 0x7f)])

def mac_none_src(seq, dst16, nwk_frame, pan=PAN):
    """Data frame with a short destination address and no source address."""
    return struct.pack("<HBHH", 0x0801, seq, pan, dst16) + nwk_frame

def build(outdir, verbose=False):
    c = Cap(230)
    marks = []
    def mark(n): marks.append((len(c.frames) + 1, n))
    S = c.nseq
    n = [0]
    def fc():
        n[0] += 1; return n[0]
    def ll(dst, src, p): c.add(mac_ll(S(), dst, src, p))
    def ss(dst, src, p): c.add(mac_ss(S(), dst, src, p))
    kx = lambda sub, body=b"": pfcf(0x0b) + bytes([sub]) + body
    rand_a = bytes(range(0x10, 0x18)); rand_b = bytes(range(0x20, 0x28)); tag = bytes([0xde, 0xad, 0xbe, 0xef])
    fl = struct.pack("<H", 0x0001)

    mark("pairing of a controller and a target: pair request (3 key seeds expected), pair response (the short addresses are learned), key seeds 0, 1, 1 (retransmit), 2, 2 (retransmit of the last)")
    ll(TGT, CTRL, cmd(fc(), 3, pair_req(kex=2)))
    ll(CTRL, TGT, cmd(fc(), 4, pair_rsp(alloc=S_CTRL, addr=S_TGT)))
    for sq in (0, 1, 1, 2, 2):
        ll(CTRL, TGT, cmd(fc(), 6, key_seed(sq, 1)))
    mark("the same pair response again (the address is already in the table), a pair response for another pair")
    ll(CTRL, TGT, cmd(fc(), 4, pair_rsp(alloc=S_CTRL, addr=S_TGT)))
    ll(OTHER, TGT, cmd(fc(), 4, pair_rsp(alloc=S_OTHER, addr=S_TGT)))
    mark("key seed variants: one seed; a seed that skips one (the latest is taken); a seed sequence past the count")
    ll(TGT, CTRL, cmd(fc(), 3, pair_req(kex=0)))
    ll(CTRL, TGT, cmd(fc(), 6, key_seed(0, 2)))
    ll(TGT, CTRL, cmd(fc(), 3, pair_req(kex=2)))
    ll(CTRL, TGT, cmd(fc(), 6, key_seed(0, 3)))
    ll(CTRL, TGT, cmd(fc(), 6, key_seed(2, 3)))
    ll(TGT, CTRL, cmd(fc(), 3, pair_req(kex=4)))
    for sq in (0, 1, 0, 1, 2, 3, 3, 2, 4, 5):
        ll(CTRL, TGT, cmd(fc(), 6, key_seed(sq, 4)))
    mark("a key seed with the same data as an earlier one: the key is already stored")
    ll(TGT, CTRL, cmd(fc(), 3, pair_req(kex=0)))
    ll(CTRL, TGT, cmd(fc(), 6, key_seed(0, 2)))
    mark("GDP key exchange (made-up random numbers and tags: no key matches): challenge, challenge response, response, confirm")
    ss(S_TGT, S_CTRL, data(fc(), 0, kx(0, fl + rand_a)))
    ss(S_CTRL, S_TGT, data(fc(), 0, kx(1, fl + rand_b + tag)))
    ss(S_TGT, S_CTRL, data(fc(), 0, kx(2, tag)))
    ss(S_CTRL, S_TGT, data(fc(), 0, kx(3)))
    mark("key exchange with EUI-64 addresses; a repeated challenge; a response without challenge; unknown addresses; a source without address")
    ll(TGT, CTRL, data(fc(), 0, kx(0, fl + rand_a)))
    ll(TGT, CTRL, data(fc(), 0, kx(0, fl + rand_b)))
    ll(CTRL, TGT, data(fc(), 0, kx(1, fl + rand_b + tag)))
    ll(CTRL, TGT, data(fc(), 0, kx(1, fl + rand_b + tag)))
    ll(TGT, bytes.fromhex("0200000000009999"), data(fc(), 0, kx(0, fl + rand_a)))
    ll(bytes.fromhex("0200000000009999"), TGT, data(fc(), 0, kx(1, fl + rand_b + tag)))
    ss(0x0aaa, 0x0bbb, data(fc(), 0, kx(0, fl + rand_a)))
    ss(0x0aaa, 0x0bbb, data(fc(), 0, kx(1, fl + rand_b + tag)))
    c.add(mac_none_src(S(), S_TGT, data(fc(), 0, kx(0, fl + rand_a))))
    c.add(mac_none_src(S(), S_TGT, data(fc(), 0, kx(1, fl + rand_b + tag))))
    ll(TGT, CTRL, data(fc(), 0, kx(0, fl + rand_a)))
    ss(S_CTRL, S_TGT, data(fc(), 0, kx(1, fl + rand_b + tag)))
    mark("secured frames (made-up payload and MIC: decryption is tried with every stored key and fails): command, data, long and short addresses, unknown addresses, too short for the MIC")
    ss(S_TGT, S_CTRL, cmd(fc(), 7, bytes(range(32)), sec=1))
    ss(S_TGT, S_CTRL, data(fc(), 3, bytes(range(24)), sec=1))
    ll(TGT, CTRL, cmd(fc(), 7, bytes(range(32)), sec=1))
    ll(CTRL, TGT, data(fc(), 0, bytes(range(60)), sec=1))
    ss(0x0aaa, 0x0bbb, data(fc(), 3, bytes(range(24)), sec=1))
    c.add(mac_none_src(S(), S_TGT, data(fc(), 3, bytes(range(24)), sec=1)))
    ss(S_TGT, S_CTRL, cmd(fc(), 7, bytes(3), sec=1))
    ss(S_TGT, S_CTRL, data(fc(), 3, bytes(2), sec=1))
    ss(S_TGT, S_CTRL, cmd(fc(), 7, bytes(142), sec=1))                  # 148 octets
    ss(S_TGT, S_CTRL, cmd(fc(), 7, bytes(143), sec=1))                  # 149 octets: declined by the heuristic
    mark("fill the tables: 70 more pairings with different keys (the NWK key storage holds 64 keys, the address table 128 addresses)")
    for i in range(70):
        a, b = eui(i, 0x40), eui(i, 0x50)
        ll(b, a, cmd(fc(), 3, pair_req(kex=0)))
        ll(a, b, cmd(fc(), 4, pair_rsp(alloc=0x2000 + 2 * i, addr=0x2001 + 2 * i)))
        ll(a, b, cmd(fc(), 6, key_seed(0, 10 + i)))
    mark("secured frames and key exchange with the tables full")
    ss(0x2000 + 2 * 69, 0x2001 + 2 * 69, cmd(fc(), 7, bytes(range(32)), sec=1))
    ss(0x2001 + 2 * 69, 0x2000 + 2 * 69, data(fc(), 3, bytes(range(24)), sec=1))
    ss(0x2001, 0x2000, data(fc(), 0, kx(0, fl + rand_a)))
    ss(0x2000, 0x2001, data(fc(), 0, kx(1, fl + rand_b + tag)))
    ss(S_TGT, S_CTRL, data(fc(), 0, kx(0, fl + rand_a)))
    ss(S_CTRL, S_TGT, data(fc(), 0, kx(1, fl + rand_b + tag)))
    c.write(os.path.join(outdir, "rf4ce-secur-coverage.pcap"))
    total = len(c.frames)
    # malformed: key exchange frames and seeds cut short
    m = Cap(230)
    def msend(p, dst=S_TGT, src=S_CTRL): m.add(mac_ss(m.nseq(), dst, src, p))
    msend(data(1, 0, kx(0))); msend(data(1, 0, kx(0, fl))); msend(data(1, 0, kx(0, fl + rand_a[:4])))
    msend(data(1, 0, kx(1, fl + rand_b[:3]))); msend(data(1, 0, kx(1, fl + rand_b + tag[:2]))); msend(data(1, 0, kx(2, tag[:1])))
    msend(cmd(1, 6, key_seed(0)[:30])); msend(cmd(1, 6, b""))
    m.write(os.path.join(outdir, "rf4ce-secur-coverage-malformed.pcap"))
    if verbose:
        for i, (f, nme) in enumerate(marks):
            e = marks[i + 1][0] - 1 if i + 1 < len(marks) else total
            print("%4d-%-4d %s" % (f, e, nme))
        print("main %d frames, malformed %d frames" % (total, len(m.frames)))

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-v" else ".", "-v" in sys.argv)
