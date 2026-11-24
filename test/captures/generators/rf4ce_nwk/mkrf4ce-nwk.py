#!/usr/bin/env python3
# Generates test/captures/rf4ce_nwk_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the RF4CE NWK coverage captures (packet-rf4ce-nwk.c).

Usage: mkrf4ce-nwk.py [-v] [outdir]   (writes rf4ce-nwk-coverage.pcap and
rf4ce-nwk-coverage-malformed.pcap, IEEE 802.15.4 without FCS (link type 230),
built with struct only).

RF4CE NWK is reached by default through a heuristic dissector on the
IEEE 802.15.4 payload ("wpan" heuristics, enabled by default), so no Decode As
is needed. There is no cryptography here: secured frames carry made-up
payloads and MICs (decryption fails), key seeds are made-up bytes. Nothing
comes from a real network.
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
def build(outdir, verbose=False):
    c = Cap(230)
    marks = []
    def mark(n): marks.append((len(c.frames) + 1, n))
    S = c.nseq
    def bc(p): c.add(mac_bcast(S(), CTRL, p))                  # broadcast from the controller
    def ct(p): c.add(mac_ll(S(), TGT, CTRL, p))                # controller -> target (EUI-64)
    def tc(p): c.add(mac_ll(S(), CTRL, TGT, p))                # target -> controller (EUI-64)
    def cts(p): c.add(mac_ss(S(), S_TGT, S_CTRL, p))           # controller -> target (short)
    n = [0]
    def fc():
        n[0] += 1; return n[0]

    mark("Discovery Request: node capabilities, vendor info, application capabilities (device and profile lists, user string), requested device type")
    bc(cmd(fc(), 1, disc_req()))
    bc(cmd(fc(), 1, disc_req(devs=(), profs=(), ntype=0, ac=0, sec=0, norm=1, resv=0xa, req_dev=0x00)))
    bc(cmd(fc(), 1, disc_req(devs=(1, 2, 3), profs=(0, 1, 2, 3, 0xc0, 0xfe, 0xff), usr=b"user string", req_dev=0x0f)))
    bc(cmd(fc(), 1, disc_req(devs=(4, 5), profs=(2,), req_dev=0x09)))
    ver = disc_req()
    bc(cmd(fc(), 1, ver[:1] + struct.pack("<H", 7) + b"TI\0\0\0\0\0" + ver[10:]))      # vendor id 7 (Texas Instruments)
    mark("Discovery Response: status values, extra status information (user string with class descriptors), LQI")
    tc(cmd(fc(), 2, disc_rsp()))
    for st in (0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xe8, 0xf4, 0xf9, 0x55):
        tc(cmd(fc(), 2, disc_rsp(status=st, devs=(1,), profs=())))
    tc(cmd(fc(), 2, disc_rsp(usr=usr_str_rsp(), devs=(2, 9), profs=(0,), lqi=0xff, ntype=0, ac=0)))
    tc(cmd(fc(), 2, disc_rsp(usr=usr_str_rsp(classes=((4, 3), (0x0e, 0), (2, 1)), resv=0x1234))))
    mark("Pair Request / Response (long addresses): key exchange counts, status values; the pair response teaches the short addresses")
    ct(cmd(fc(), 3, pair_req(kex=2)))
    tc(cmd(fc(), 4, pair_rsp()))
    ct(cmd(fc(), 3, pair_req(addr=0x1111, devs=(1, 2), profs=(0,), kex=0, usr=b"pair user str")))
    tc(cmd(fc(), 4, pair_rsp(status=0xb5, alloc=0x1111, addr=0x2222, devs=(), profs=())))
    ct(cmd(fc(), 3, pair_req(kex=1, ntype=0, ac=0, sec=0)))
    tc(cmd(fc(), 4, pair_rsp(status=0xb0, devs=(1, 2, 3), profs=(0, 1, 2, 3, 4, 5, 6))))
    tc(cmd(fc(), 4, pair_rsp(status=0xb1)))
    mark("Key Seed: sequence 0, 1, 2 (the pair request announced 3 seeds), a retransmitted seed, the last one retransmitted")
    ct(cmd(fc(), 3, pair_req(kex=2)))
    for sq in (0, 1, 1, 2, 2):
        tc(cmd(fc(), 6, key_seed(sq)))
    mark("Key Seed: a single seed, seeds out of order and past the expected count")
    ct(cmd(fc(), 3, pair_req(kex=0)))
    tc(cmd(fc(), 6, key_seed(0, 5)))
    tc(cmd(fc(), 6, key_seed(0, 9)))
    ct(cmd(fc(), 3, pair_req(kex=3)))
    for sq in (0, 2, 1, 3, 3, 4):
        tc(cmd(fc(), 6, key_seed(sq, 3)))
    mark("Unpair Request, Ping Request and Response")
    ct(cmd(fc(), 5))
    cts(cmd(fc(), 7, ping()))
    cts(cmd(fc(), 8, ping(opt=0xff, pl=b"\xde\xad\xbe\xef")))
    mark("Data frames: GDP, ZRC 1.0, ZID, ZRC 2.0, vendor profiles, wildcard; channel designators, protocol versions")
    cts(data(fc(), 0, pfcf(0, 1) + b"\x00"))                 # GDP Generic Response
    cts(data(fc(), 1, bytes([0x01, 0x20])))                  # ZRC 1.0 User Control Pressed
    cts(data(fc(), 2, b"ZID payload"))                       # ZID: not dissected
    cts(data(fc(), 3, pfcf(0, 1) + b"\x01"))                 # ZRC 2.0 Generic Response
    cts(data(fc(), 0xc0, b"0123456789"))                     # vendor specific profile
    cts(data(fc(), 0xff, b"wildcard"))
    for ch in range(4):
        cts(data(fc(), 0xc1, b"channel %d" % ch, ch=ch))
    for v in range(4):
        cts(data(fc(), 0xc2, b"version %d" % v, ver=v))
    mark("Vendor specific frames: every vendor id the heuristic accepts")
    for vid in (1, 2, 3, 4, 5, 6, 7, 0xfff1, 0xfff2, 0xfff3):
        cts(vendor_data(fc(), 0xc3, vid, b"vendor %04x" % vid))
    cts(vendor_data(fc(), 0, 0xfff1, pfcf(0, 1) + b"\x02"))
    mark("fixed: payload of a data frame of a profile without a dissector shown in full (frame 'Unparsed Payload' read at the header offset)")
    c.add(mac_ss(S(), 0x0001, 0x0002, data(1, 0xc0, b"0123456789"), pan=0x1234))
    mark("fixed: pair request and key seed with SHORT 802.15.4 addresses (the key pair context needs EUI-64 addresses)")
    cts(cmd(fc(), 3, pair_req(kex=0)))
    cts(cmd(fc(), 6, key_seed(0, 1)))
    c.add(mac_ls(S(), TGT, S_CTRL, cmd(fc(), 3, pair_req(kex=0))))
    c.add(mac_sl(S(), S_TGT, CTRL, cmd(fc(), 3, pair_req(kex=0))))
    c.add(mac_ls(S(), TGT, S_CTRL, cmd(fc(), 4, pair_rsp())))
    c.add(mac_sl(S(), S_TGT, CTRL, cmd(fc(), 4, pair_rsp())))
    mark("security bit set (payload and MIC are not valid; with the key pair of the last key seed stored, decryption is tried and fails)")
    cts(cmd(fc(), 7, bytes(range(32)), sec=1))                          # command ID is encrypted
    cts(data(fc(), 3, bytes(range(24)), sec=1))
    ct(cmd(fc(), 7, bytes(range(32)), sec=1))
    tc(data(fc(), 0, bytes(range(40)), sec=1))
    cts(cmd(fc(), 7, bytes(3), sec=1))                                   # too short for the MIC
    cts(data(fc(), 3, bytes(6), sec=1))
    c.add(mac_ss(S(), 0x0007, 0x0008, data(fc(), 3, bytes(range(24)), sec=1)))   # unknown short addresses
    mark("frames the heuristic declines (dissected as plain IEEE 802.15.4 data): bad reserved bit, frame type 0, profile 0x10, unknown vendor id, unknown command id, too short, too long")
    cts(nwk(FT_DATA, 1, b"reserved bit clear, long enough payload", resv=0, profile=0))
    cts(nwk(FT_RESERVED, 1, b"reserved type"))
    cts(data(fc(), 0x10, b"profile in the reserved range"))
    cts(vendor_data(fc(), 0xc0, 0x1234, b"unknown vendor"))
    cts(cmd(fc(), 9, b"unknown command"))
    cts(bytes([0x21, 1, 0, 0]))
    cts(data(fc(), 0xc0, bytes(143)))                                    # 149 octets
    cts(data(fc(), 0xc0, bytes(142)))                                    # 148 octets (the longest accepted)
    cts(cmd(fc(), 0, b""))                                               # command frame of 6 octets: command id 0 is declined
    c.add(mac_ss(S(), S_TGT, S_CTRL, bytes([0x22, 1, 0, 0, 0])))        # 5 octets: command frame without command id
    c.write(os.path.join(outdir, "rf4ce-nwk-coverage.pcap"))
    total = len(c.frames)
    # malformed: truncated commands and fields
    m = Cap(230)
    def msend(p): m.add(mac_ss(m.nseq(), S_TGT, S_CTRL, p))
    full = {
        1: disc_req(devs=(1, 2), profs=(0, 3), usr=b"user", req_dev=1),
        2: disc_rsp(usr=usr_str_rsp(), devs=(1, 2), profs=(0, 3)),
        3: pair_req(devs=(1,), profs=(0,), usr=b"u"),
        4: pair_rsp(),
        6: key_seed(0),
        7: ping(),
    }
    for cid, body in full.items():
        for cut in sorted({0, 1, 2, 3, 5, 9, 10, 12, 16, 20, 26, 30, 40, 70}):
            if cut < len(body):
                msend(cmd(1, cid, body[:cut]))
    msend(data(1, 0, b""))                                               # no profile payload at all
    msend(nwk(FT_VENDOR, 1, b"", profile=0xc0)[:6])                      # vendor frame without vendor id
    # captured lengths shorter than the reported length (snaplen): the heuristic declines or the frame is cut
    def trunc(p, keep):
        f = mac_ss(m.nseq(), S_TGT, S_CTRL, p)
        m.add(f[:9 + keep], orig=len(f))
    trunc(data(1, 0xc0, bytes(20)), 4)                                   # fewer than 5 octets captured
    trunc(data(1, 0xc0, bytes(20)), 5)                                   # no profile id captured
    trunc(vendor_data(1, 0xc0, 0xfff1, bytes(20)), 7)                    # vendor id cut
    trunc(cmd(1, 7, ping()), 5)                                          # no command id captured
    trunc(cmd(1, 7, ping()), 9)                                          # command cut
    trunc(cmd(1, 3, pair_req()), 12)                                     # pair request cut
    m.write(os.path.join(outdir, "rf4ce-nwk-coverage-malformed.pcap"))
    if verbose:
        for i, (f, nme) in enumerate(marks):
            e = marks[i + 1][0] - 1 if i + 1 < len(marks) else total
            print("%4d-%-4d %s" % (f, e, nme))
        print("main %d frames, malformed %d frames" % (total, len(m.frames)))

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-v" else ".", "-v" in sys.argv)
