#!/usr/bin/env python3
# Generates test/captures/rf4ce_profile_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the RF4CE profile coverage captures (packet-rf4ce-profile.c:
GDP, ZRC 1.0 and ZRC 2.0 over RF4CE NWK data frames).

Usage: mkrf4ce-profile.py [-v] [outdir]   (writes rf4ce-profile-coverage.pcap and
rf4ce-profile-coverage-malformed.pcap, IEEE 802.15.4 without FCS (link type 230),
built with struct only).

The profile dissector has no port of its own: RF4CE NWK (a heuristic dissector
on the 802.15.4 payload, enabled by default) hands it the payload of data
frames with the profile ids 0 (GDP), 1 (ZRC 1.0) and 3 (ZRC 2.0). The Key
Exchange frames carry made-up random numbers and tags, so no key is found.
Nothing comes from a real network.
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


# ---- profile payloads ----
def ident_cap(f=0x0e): return bytes([f])
def poll_constraints(recs):
    b = bytes([len(recs)])
    for mid, cap, mink, maxk, mint, maxt in recs:
        b += bytes([mid]) + struct.pack("<HBBII", cap, mink, maxk, mint, maxt)
    return b
def poll_config(mid=1, trig=0x0021, keys=3, interval=1000, timeout=5):
    return bytes([mid]) + struct.pack("<HBIB", trig, keys, interval, timeout)
def action_data(ctl, bank, code, vendor=None, payload=b"", with_ctl=True):
    b = bytes([ctl]) if with_ctl else b""
    b += bytes([len(payload), bank, code])
    if vendor is not None: b += struct.pack("<H", vendor)
    return b + payload
def action_mappings(flags, rf=None, ir=None):
    """rf = (rf_conf, tx_opts, [action data], ir = (conf, vendor id or None, code)"""
    b = bytes([flags])
    if rf is not None:
        conf, opts, ad = rf
        b += bytes([conf, opts, len(ad)]) + ad
    if ir is not None:
        conf, vid, code = ir
        b += bytes([conf]) + (struct.pack("<H", vid) if vid is not None else b"") + bytes([len(code)]) + code
    return b

def build(outdir, verbose=False):
    c = Cap(230)
    marks = []
    def mark(n): marks.append((len(c.frames) + 1, n))
    S = c.nseq
    n = [0]
    def fc():
        n[0] += 1; return n[0]
    def send(profile, payload, src=S_CTRL, dst=S_TGT):
        c.add(mac_ss(S(), dst, src, data(fc(), profile, payload)))
    gdp = lambda payload: send(0, payload)
    z20 = lambda payload: send(3, payload)
    z10 = lambda payload: send(1, payload)
    def pairing():
        c.add(mac_ll(S(), TGT, CTRL, cmd(fc(), 3, pair_req(kex=0))))
        c.add(mac_ll(S(), CTRL, TGT, cmd(fc(), 4, pair_rsp(alloc=S_CTRL, addr=S_TGT))))
        c.add(mac_ll(S(), CTRL, TGT, cmd(fc(), 6, key_seed(0, 4))))

    mark("pairing (EUI-64 addresses) so that the short addresses of the following frames resolve")
    pairing()
    mark("GDP command frames: Generic Response, Configuration Complete, Heartbeat (every trigger), unknown command ids")
    for st in (0, 1, 2, 3, 0x55): gdp(pfcf(0) + bytes([st]))
    for st in (0, 3, 0x40): gdp(pfcf(1) + bytes([st]))
    for tr in (0, 1, 2, 3, 4, 5, 6, 0x77): gdp(pfcf(2, pending=tr & 1) + bytes([tr]))
    for cid in (0x0c, 0x0d, 0x0e, 0x0f): gdp(pfcf(cid) + b"\x01\x02")
    gdp(pfcf(0, resv=3) + b"\x00")
    mark("GDP Get Attributes (scalar and arrayed attributes) and Get Attributes Response")
    gdp(pfcf(3) + attr_get([(0x80, None), (0x81, None), (0x8b, None), (0x90, 0x0102), (0xc0, 0x0001), (0xe0, None)]))
    gdp(pfcf(4) + attr_rsp([(0x80, None, 0, b"\x02"), (0x81, None, 0, b"\x01\x02"), (0x8b, None, 0, ident_cap())]))
    gdp(pfcf(4) + attr_rsp([(0x84, None, 0, poll_constraints([(1, 0x7f, 1, 255, 1000, 2000), (2, 0x0001, 0, 9, 0, 0xffffffff)]))]))
    gdp(pfcf(4) + attr_rsp([(0x85, None, 0, poll_config()), (0x82, None, 0, b"\x03"), (0x83, None, 0, b"\x01\x02\x03")]))
    gdp(pfcf(4) + attr_rsp([(0x8b, None, 1, None), (0x86, None, 2, None), (0x87, None, 3, None), (0x90, 0x0005, 1, None)]))
    gdp(pfcf(4) + attr_rsp([(0x90, 0x0005, 0, b"abc"), (0xc1, 0x0006, 0, b"\xaa\xbb"), (0x88, None, 0, b"")]))
    gdp(pfcf(4) + attr_rsp([(0x8a, None, 0, bytes([0xff] * 0xfe))]) [:0] + attr_rsp([(0x8a, None, 0, b"\x01")]))
    gdp(pfcf(4) + bytes([0x8a, 0x00, 0xff]))                                   # attribute length 255 is not followed
    mark("GDP Push, Set, Pull Attributes and Pull Attributes Response")
    gdp(pfcf(5) + attr_push([(0x8b, None, ident_cap(0x07)), (0x84, None, poll_constraints([(1, 3, 1, 2, 3, 4)])), (0x90, 1, b"xyz")]))
    gdp(pfcf(6) + attr_push([(0x85, None, poll_config(2, 0x0042, 9, 77, 3)), (0x89, None, b"\x01\x00")]))
    gdp(pfcf(7) + attr_get([(0x84, None), (0x8a, None), (0xc2, 7)]))
    gdp(pfcf(8) + attr_rsp([(0x85, None, 0, poll_config(3)), (0x8a, None, 1, None), (0xc2, 7, 0, b"\x01\x02")]))
    mark("GDP Check Validation (request, response, other sub type), Client Notification (every sub type)")
    gdp(pfcf(9) + bytes([0x00, 0x01]))
    for st in (0, 1, 2, 3, 0x55): gdp(pfcf(9) + bytes([0x01, st]))
    gdp(pfcf(9) + bytes([0x05, 0x01, 0x02]))
    for fl in (0x00, 0x0f, 0xf1): gdp(pfcf(10) + bytes([0x00, fl]) + struct.pack("<H", 600 + fl))
    for st in (0x01, 0x40, 0x41, 0x42, 0x77): gdp(pfcf(10) + bytes([st]) + b"\x05\x06")
    mark("GDP non-command frame (cmd frame bit clear): decoded as ZRC 2.0 actions")
    gdp(pfcf(6, 0) + action_data(0x01, 0x02, 0x03))
    gdp(pfcf(3, 0) + b"\x01\x02\x03")
    mark("Key Exchange: challenge, challenge response (the tag does not match: no key is found), response, confirm, repeated challenge, response without challenge, unknown addresses, other sub type")
    rand_a = bytes(range(0x10, 0x18)); rand_b = bytes(range(0x20, 0x28)); tag = bytes([0xde, 0xad, 0xbe, 0xef])
    gdp(pfcf(0x0b) + bytes([0x00]) + struct.pack("<H", 0x0001) + rand_a)
    gdp(pfcf(0x0b) + bytes([0x00]) + struct.pack("<H", 0x0101) + rand_a)         # procedure already started
    send(0, pfcf(0x0b) + bytes([0x01]) + struct.pack("<H", 0x0001) + rand_b + tag, src=S_TGT, dst=S_CTRL)
    send(0, pfcf(0x0b) + bytes([0x02]) + tag, src=S_CTRL, dst=S_TGT)
    gdp(pfcf(0x0b) + bytes([0x03]))
    send(0, pfcf(0x0b) + bytes([0x01]) + struct.pack("<H", 0x0003) + rand_b + tag, src=S_TGT, dst=S_CTRL)   # no procedure
    c.add(mac_ss(S(), 0x0009, 0x0008, data(fc(), 0, pfcf(0x0b) + bytes([0x00]) + struct.pack("<H", 0x0005) + rand_a)))   # unknown source
    c.add(mac_ss(S(), 0x0001, 0x0008, data(fc(), 0, pfcf(0x0b) + bytes([0x01]) + struct.pack("<H", 0x0005) + rand_b + tag)))
    gdp(pfcf(0x0b) + bytes([0x00]) + struct.pack("<H", 0x0006) + rand_a)         # a new procedure
    send(0, pfcf(0x0b) + bytes([0x01]) + struct.pack("<H", 0x0006) + rand_b + tag, src=S_TGT, dst=S_CTRL)
    gdp(pfcf(0x0b) + bytes([0x09, 0x01]))
    mark("ZRC 2.0 command frames: attributes (version, IRDB vendor support, mappable actions, action mappings, arrayed attributes)")
    z20(pfcf(3) + attr_get([(0xa0, None), (0xa6, None), (0xc2, 0), (0xc3, 5), (0xc0, 1), (0xc5, 2), (0xd0, 3), (0xe0, None)]))
    z20(pfcf(4) + attr_rsp([(0xa0, None, 0, b"\x02\x00"), (0xa1, None, 0, b"\x01"), (0xa6, None, 0, struct.pack("<HHH", 1, 7, 0xfff1))]))
    z20(pfcf(4) + attr_rsp([(0xc2, 0, 0, bytes([2, 1, 0x10, 2, 1, 0x11, 3, 2, 0x20]))]))
    z20(pfcf(4) + attr_rsp([(0xc2, 2, 3, None), (0xc3, 2, 1, None)]))
    z20(pfcf(4) + attr_rsp([(0xc3, 1, 0, action_mappings(0x00))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 2, 0, action_mappings(0x01, rf=(0x1f, 0x7f, action_data(0, 3, 4, with_ctl=False))))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 3, 0, action_mappings(0x01, rf=(0x00, 0x00, b"")))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 4, 0, action_mappings(0x02, ir=(0x00, None, b"\x01\x02\x03")))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 5, 0, action_mappings(0x02, ir=(0x01, 0xfff1, b"\x09")))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 6, 0, action_mappings(0x03, rf=(0x05, 0x0a, action_data(1, 9, 9, with_ctl=False)), ir=(0x01, 0x0007, b"")))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 7, 0, action_mappings(0x13, rf=(0x05, 0x0a, action_data(1, 9, 9, with_ctl=False)), ir=(0x00, None, b"\x01")))]))
    z20(pfcf(4) + attr_rsp([(0xc3, 8, 0, bytes([0x07 | 0x20 | 0x40 | 0x80]))]))     # use default (and permanent): descriptors skipped
    z20(pfcf(5) + attr_push([(0xa2, None, b"\x10\x00"), (0xc2, 0, bytes([2, 1, 0x10])), (0xc3, 1, action_mappings(0x01, rf=(0x01, 0x01, action_data(0, 1, 2, with_ctl=False))))]))
    z20(pfcf(6) + attr_push([(0xa3, None, b"\x20\x00"), (0xc4, 1, b"\x01\x02")]))
    z20(pfcf(7) + attr_get([(0xa4, None), (0xc3, 1)]))
    z20(pfcf(8) + attr_rsp([(0xa4, None, 0, b"\xff\x01"), (0xc3, 1, 1, None)]))
    z20(pfcf(0x0a) + bytes([0x40]))
    mark("ZRC 2.0 Actions frames: every action type, modifier bits, payloads, vendor specific actions, several records, empty list")
    z20(pfcf(6, 0) + action_data(0x01, 0x00, 0x41))
    z20(pfcf(6, 0) + action_data(0x02, 0x00, 0x42))
    z20(pfcf(6, 0) + action_data(0x03, 0x01, 0x43, payload=b"\x01\x02"))
    z20(pfcf(6, 0) + action_data(0x00, 0x00, 0x00))
    z20(pfcf(6, 0) + action_data(0xf1, 0x01, 0x10) + action_data(0x4e, 0x02, 0x11))
    z20(pfcf(6, 0) + action_data(0x01, 0xfe, 0x01, vendor=0x1234))
    z20(pfcf(6, 0) + action_data(0x01, 0x02, 0x03) + action_data(0x02, 0x04, 0x05, payload=b"\x07\x08\x09"))
    z20(pfcf(6, 0))
    z20(pfcf(6, 1, pending=1) + attr_push([(0xa0, None, b"\x01")]))
    for cid in (0, 1, 2, 3, 4, 5, 7, 8, 0x0f):
        z20(pfcf(cid, 0) + b"\x01\x02")
    mark("ZRC 1.0: user control pressed / repeated / released, command discovery request and response, unknown commands, cmd frame bit set")
    z10(bytes([0x01, 0x41, 0x01, 0x02]))
    z10(bytes([0x01, 0x42]))
    z10(bytes([0x02, 0x41, 0xff]))
    z10(bytes([0x03, 0x41]))
    z10(bytes([0x04, 0x00]))
    z10(bytes([0x05, 0xff, 0x01, 0x02, 0x03]))
    z10(bytes([0x05]))
    for cid in (0x00, 0x06, 0x07, 0x0f, 0xb6):
        z10(bytes([cid, 0x01]))
    z10(pfcf(0, 1) + b"\x00")                      # bit 6 set: handled as a command frame
    z10(bytes([0x43, 0x01, 0x02]))                # bit 6 set, command 3
    c.write(os.path.join(outdir, "rf4ce-profile-coverage.pcap"))
    total = len(c.frames)
    # malformed: truncated attributes, actions with vendor id and payload, cut commands
    m = Cap(230)
    def msend(profile, payload, src=S_CTRL, dst=S_TGT):
        m.add(mac_ss(m.nseq(), dst, src, data(1, profile, payload)))
    msend(0, pfcf(0)); msend(0, pfcf(1)); msend(0, pfcf(2)); msend(0, pfcf(9)); msend(0, pfcf(9) + b"\x00"); msend(0, pfcf(9) + b"\x01")
    msend(0, pfcf(10)); msend(0, pfcf(10) + b"\x00"); msend(0, pfcf(10) + b"\x00\x01"); msend(0, pfcf(10) + b"\x00\x01\x02")
    msend(0, pfcf(0x0b)); msend(0, pfcf(0x0b) + b"\x00"); msend(0, pfcf(0x0b) + b"\x00\x01\x00\x01")
    msend(0, pfcf(0x0b) + b"\x01\x00\x00" + bytes(8)); msend(0, pfcf(0x0b) + b"\x01\x00\x00" + bytes(8) + b"\x01"); msend(0, pfcf(0x0b) + b"\x02\x01")
    msend(0, pfcf(3) + b"\x90"); msend(0, pfcf(3) + b"\x90\x01"); msend(0, pfcf(4) + b"\x8b"); msend(0, pfcf(4) + b"\x8b\x00"); msend(0, pfcf(4) + b"\x8b\x00\x01")
    msend(0, pfcf(4) + b"\x8b\x00\x03\x00"); msend(0, pfcf(4) + b"\x84\x00\x05\x03\x01\x02")
    msend(0, pfcf(4) + b"\x84\x00\x0a\x02" + bytes(10)); msend(0, pfcf(4) + b"\x85\x00\x04\x01\x02\x03\x04")
    msend(0, pfcf(5) + b"\x85\x0a\x01\x02"); msend(0, pfcf(5) + b"\x85\x10" + bytes(8))
    msend(3, pfcf(4) + b"\xc3\x00\x00\x03\x01")
    msend(3, pfcf(4) + b"\xc3\x00\x00\x04\x01\x00\x00\x00"); msend(3, pfcf(4) + b"\xc3\x00\x00\x05\x01\x01\x01\x01\x03")
    msend(3, pfcf(4) + b"\xc3\x00\x00\x05\x02\x01\xaa\xbb\x01")
    msend(3, pfcf(4) + b"\xc3\x00\x00\x02\x02\x01"); msend(3, pfcf(4) + b"\xc3\x00\x00\x03\x02\x01\x01")
    msend(3, pfcf(4) + b"\xc2\x00\x00\x00\x06\x01\x02\x03\x04\x05"); msend(3, pfcf(4) + b"\xa6\x00\x03\x01\x02\x03")
    msend(3, pfcf(6, 0) + action_data(0x01, 0x02, 0x03, payload=b"\x07", vendor=0x1234))     # vendor id and payload: a stray octet starts a second record
    msend(3, pfcf(6, 0) + b"\x01"); msend(3, pfcf(6, 0) + b"\x01\x05\x01\x02\x03"); msend(3, pfcf(6, 0) + b"\x01\x00\x01")
    msend(3, pfcf(4) + attr_rsp([(0xc2, 1, 0, bytes([2, 1, 0x10, 9]))]))      # mappable actions of 4 octets: a stray octet is read as the next attribute
    msend(3, pfcf(6, 1) + b"\x00")                                           # Set Attributes with garbage
    msend(1, bytes([0x46, 0x01])); msend(1, bytes([0x01])); msend(1, bytes([0x04]))
    m.write(os.path.join(outdir, "rf4ce-profile-coverage-malformed.pcap"))
    if verbose:
        for i, (f, nme) in enumerate(marks):
            e = marks[i + 1][0] - 1 if i + 1 < len(marks) else total
            print("%4d-%-4d %s" % (f, e, nme))
        print("main %d frames, malformed %d frames" % (total, len(m.frames)))

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-v" else ".", "-v" in sys.argv)
