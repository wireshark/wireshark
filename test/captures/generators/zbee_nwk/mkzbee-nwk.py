# Generates test/captures/zbee_nwk_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (generated captures are synthetic; nothing from a network) ----
import struct
import sys
import os

LINKTYPE_IEEE802_15_4_NOFCS = 230


def write_pcap(path, frames, linktype=LINKTYPE_IEEE802_15_4_NOFCS):
    """frames: list of bytes; written with one frame per second."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def wpan_short(payload, seq=1, pan=0x1234, dst=0x0001, src=0x0002):
    """802.15.4 data frame, PAN ID compression, short dst and src."""
    fcf = 0x0001 | 0x0040 | (2 << 10) | (2 << 14)
    return struct.pack("<HBHHH", fcf, seq & 0xff, pan, dst, src) + payload


def wpan_beacon(payload, seq=1, pan=0x1234, src=0x0000, spec=0xCFFF):
    """802.15.4 beacon: short source, superframe spec, no GTS, no pending."""
    fcf = 0x0000 | (2 << 14)
    return struct.pack("<HBHHHBB", fcf, seq & 0xff, pan, src, spec, 0, 0) + payload


def wpan_interpan(payload, seq=1, dpan=0xffff, dst=0xffff, spanid=0x1234, src64=0x00124b0001020304):
    """802.15.4 frame with short destination and extended source (interpan)."""
    fcf = 0x0001 | (2 << 10) | (3 << 14)
    return struct.pack("<HBHHHQ", fcf, seq & 0xff, dpan, dst, spanid, src64) + payload


def wpan_gp(payload, seq=1, pan=0xffff, dst=0xffff, src=0x0000):
    """802.15.4 data frame to the broadcast address with no source (GP, short dst)."""
    fcf = 0x0001 | (2 << 10)          # no PAN compression, short dst, no src
    return struct.pack("<HBHH", fcf, seq & 0xff, pan, dst) + payload


def nwk_fcf(ftype=0, ver=2, disc=1, mcast=0, sec=0, route=0, ext_dst=0, ext_src=0, edi=0):
    return (ftype | (ver << 2) | (disc << 6) | (mcast << 8) | (sec << 9) |
            (route << 10) | (ext_dst << 11) | (ext_src << 12) | (edi << 13))


def nwk(payload=b"", ftype=0, ver=2, disc=1, dst=0x0001, src=0x0002, radius=30, seq=1,
        sec=0, mcast=None, route=None, dst64=None, src64=None, edi=0):
    """NWK frame. mcast: control byte; route: (index, [relays]); dst64/src64: ints."""
    f = nwk_fcf(ftype, ver, disc, mcast is not None, sec, route is not None,
                dst64 is not None, src64 is not None, edi)
    h = struct.pack("<HHHBB", f, dst, src, radius, seq & 0xff)
    if dst64 is not None:
        h += struct.pack("<Q", dst64)
    if src64 is not None:
        h += struct.pack("<Q", src64)
    if mcast is not None:
        h += bytes([mcast])
    if route is not None:
        idx, relays = route
        h += bytes([len(relays), idx]) + b"".join(struct.pack("<H", r) for r in relays)
    return h + payload


def aps_data(payload=b"", cluster=0x0006, profile=0x0104, dst_ep=1, src_ep=1, counter=1,
             delivery=0, group=None, ack_req=0, sec=0, ack_fmt=0, ext=None, ver=2, indirect=0):
    """APS data frame. ext: (fragmentation, block, [ack]) or None."""
    fcf = 0x00 | (delivery << 2) | ((ack_fmt if ver >= 2 else indirect) << 4) | (sec << 5) | (ack_req << 6) | ((1 << 7) if ext else 0)
    h = bytes([fcf])
    if delivery in (0, 2) or (delivery == 1 and ver <= 1 and not indirect):
        h += bytes([dst_ep])
    if delivery == 3:
        h += struct.pack("<H", group)
    h += struct.pack("<H", cluster) if ver >= 2 else bytes([cluster & 0xff])
    h += struct.pack("<H", profile)
    if not (delivery == 1 and indirect):
        h += bytes([src_ep])
    if ver >= 2:
        h += bytes([counter])
    if ext:
        h += bytes([ext[0]]) + bytes([ext[1]]) if ext[0] else bytes([ext[0]])
    return h + payload


def aps_cmd(cmd, body=b"", counter=1, sec=0, ack_req=0, ext=None):
    fcf = 0x01 | (sec << 5) | (ack_req << 6)
    return bytes([fcf, counter, cmd]) + body


def zcl_frame(cmd, payload=b"", seq=1, ftype=0, mfr=None, to_client=0, disable_rsp=0):
    fcf = ftype | ((1 if mfr is not None else 0) << 2) | (to_client << 3) | (disable_rsp << 4)
    h = bytes([fcf])
    if mfr is not None:
        h += struct.pack("<H", mfr)
    return h + bytes([seq, cmd]) + payload


def gp_frame(payload, sec_level=0, src_id=0x11223344, frame_counter=None, mic=b"", ftype=0,
             app_id=0, endpoint=0x01, direction=0, ext=True, key=0, rx_after_tx=0, auto_comm=0, ver=3):
    """ZigBee Green Power NWK frame."""
    fcf = ftype | (ver << 2) | (0x40 if auto_comm else 0) | (0x80 if ext else 0)
    h = bytes([fcf])
    if ext:
        h += bytes([app_id | (sec_level << 3) | (key << 5) | (rx_after_tx << 6) | (direction << 7)])
    if app_id == 0 and (ftype == 0 or ftype == 1):
        h += struct.pack("<I", src_id)
    if app_id == 2:
        h += bytes([endpoint])
    if ext and sec_level in (2, 3) and app_id in (0, 1, 2):
        h += struct.pack("<I", frame_counter or 0)
    return h + payload + mic



# ---------------------------------------------------------------------------
# zbee-nwk coverage: NWK data/command/interpan frames, beacons, ZigBee IEs
# ---------------------------------------------------------------------------
frames = []
labels = []


def add(label, frame):
    frames.append(frame)
    labels.append(label)


mframes = []
mlabels = []


def madd(label, frame):
    mframes.append(frame)
    mlabels.append(label)


def sect(name):
    labels.append(("SECTION", name, len(frames) + 1))


EUI_A = 0x00124b0001020304
EUI_B = 0x00124b000a0b0c0d
EUI_C = 0x00124b00deadbeef
ZCL_ONOFF = aps_data(zcl_frame(0x01, seq=1, ftype=1), cluster=0x0006, profile=0x0104)

# --- 1. Data frames: frame control variants (ZigBee 2007 / PRO) ---------------
sect("data")
add("plain data, ZigBee PRO, discovery enabled", wpan_short(nwk(ZCL_ONOFF, disc=1)))
add("data, discovery suppressed", wpan_short(nwk(ZCL_ONOFF, disc=0, seq=2), seq=2))
add("data, discovery forced", wpan_short(nwk(ZCL_ONOFF, disc=3, seq=3), seq=3))
add("data with extended source (learns 0x0005 -> EUI_A)",
    wpan_short(nwk(ZCL_ONOFF, src=0x0005, seq=4, src64=EUI_A), seq=4, src=0x0005))
add("data with extended destination and source",
    wpan_short(nwk(ZCL_ONOFF, src=0x0006, dst=0x0007, seq=5, dst64=EUI_B, src64=EUI_C), seq=5, src=0x0006, dst=0x0007))
add("data from 0x0005 without extended source (inferred from frame 4)",
    wpan_short(nwk(ZCL_ONOFF, src=0x0005, seq=6), seq=6, src=0x0005))
add("data from unknown 0x0099 without extended source",
    wpan_short(nwk(ZCL_ONOFF, src=0x0099, seq=7), seq=7, src=0x0099))
add("data from 0x00aa without extended source (runcov.sh gives it a static address mapping)",
    wpan_short(nwk(ZCL_ONOFF, src=0x00aa, seq=7), seq=7, src=0x00aa))
add("data, end device initiator flag",
    wpan_short(nwk(ZCL_ONOFF, seq=8, edi=1), seq=8))
add("data to broadcast 0xfffd", wpan_short(nwk(ZCL_ONOFF, dst=0xfffd, seq=9), seq=9, dst=0xfffd))
add("data to broadcast 0xfffc", wpan_short(nwk(ZCL_ONOFF, dst=0xfffc, seq=10), seq=10, dst=0xfffc))
add("data to broadcast 0xffff", wpan_short(nwk(ZCL_ONOFF, dst=0xffff, seq=11), seq=11, dst=0xffff))
add("data from a broadcast source 0xfffd with extended source (not mapped)",
    wpan_short(nwk(ZCL_ONOFF, src=0xfffd, seq=12, src64=EUI_B), seq=12, src=0xfffd))
add("multicast data, mode 1, radius 3, max radius 5",
    wpan_short(nwk(aps_data(zcl_frame(0x01, ftype=1), delivery=3, group=0x1234), seq=13, mcast=0x01 | (3 << 2) | (5 << 5)), seq=13))
add("multicast data, mode 0",
    wpan_short(nwk(aps_data(zcl_frame(0x01, ftype=1), delivery=3, group=0x1234), seq=14, mcast=0x00), seq=14))
add("data with source route, 3 relays",
    wpan_short(nwk(ZCL_ONOFF, seq=15, route=(1, [0x3333, 0x4444, 0x5555])), seq=15))
add("data with source route, no relays",
    wpan_short(nwk(ZCL_ONOFF, seq=16, route=(0, [])), seq=16))
add("data with multicast, source route and extended addresses (all optional fields)",
    wpan_short(nwk(aps_data(zcl_frame(0x01, ftype=1), delivery=3, group=0x4321), seq=17, mcast=0x41, route=(0, [0x6666]),
                   dst64=EUI_B, src64=EUI_A, edi=1), seq=17))
add("ZigBee 2004 (version 1) data, APF with a message transaction (no profile handler)",
    wpan_short(nwk(aps_data(bytes([0x21, 0x01, 0x02, 0xaa, 0xbb]), ver=1, cluster=0x06, profile=0x1234), ver=1, seq=18), seq=18))
add("ZigBee 2004 data, delivery mode indirect with indirect address mode",
    wpan_short(nwk(aps_data(bytes([0x21, 0x01, 0x02, 0xaa, 0xbb]), ver=1, delivery=1, indirect=1, cluster=0x06, profile=0x1234), ver=1, seq=19), seq=19))
add("ZigBee 2004 data, delivery mode indirect (destination endpoint)",
    wpan_short(nwk(aps_data(bytes([0x11, 0x01]), ver=1, delivery=1, indirect=0, cluster=0x06, profile=0x1234), ver=1, seq=20), seq=20))

# --- 2. NWK commands -----------------------------------------------------------
sect("commands")


def cmd(label, body, ver=2, seq=None, **kw):
    n = len(frames) + 1
    add(label, wpan_short(nwk(body, ftype=1, ver=ver, seq=seq or (n & 0xff), **kw), seq=n & 0xff))


cmd("route request, no options", bytes([0x01, 0x00, 0x11]) + struct.pack("<H", 0x2222) + bytes([0x05]))
cmd("route request, multicast+many-to-one (recording)+dest ext",
    bytes([0x01, 0x40 | 0x20 | 0x08, 0x12]) + struct.pack("<HB", 0x2222, 7) + struct.pack("<Q", EUI_B))
cmd("route request, many-to-one without recording", bytes([0x01, 0x10, 0x13]) + struct.pack("<HB", 0xfffc, 1))
cmd("route request, ZigBee 2004 repair option", bytes([0x01, 0x80, 0x14]) + struct.pack("<HB", 0x2222, 2), ver=1)
cmd("route reply, no options", bytes([0x02, 0x00, 0x11]) + struct.pack("<HHB", 0x1111, 0x2222, 3))
cmd("route reply, originator+responder extended, multicast",
    bytes([0x02, 0x40 | 0x20 | 0x10, 0x11]) + struct.pack("<HHB", 0x1111, 0x2222, 3) + struct.pack("<QQ", EUI_A, EUI_B))
cmd("route reply, ZigBee 2004 repair", bytes([0x02, 0x80, 0x11]) + struct.pack("<HHB", 0x1111, 0x2222, 3), ver=1)
for code in (0x00, 0x01, 0x02, 0x0b, 0x13, 0x25):
    if code == 0x13:
        cmd("network status unknown command (0x13) for command 0x77", bytes([0x03, code]) + struct.pack("<H", 0x4444) + bytes([0x77]))
        cmd("network status unknown command (0x13) for command 0x01", bytes([0x03, code]) + struct.pack("<H", 0x4444) + bytes([0x01]))
    else:
        cmd("network status 0x%02x" % code, bytes([0x03, code]) + struct.pack("<H", 0x4444))
for opt in (0x00, 0x20, 0x40, 0x80, 0xe0):
    cmd("leave options 0x%02x" % opt, bytes([0x04, opt]))
cmd("route record, 3 relays", bytes([0x05, 3]) + struct.pack("<HHH", 0x1010, 0x2020, 0x3030))
cmd("route record, no relays", bytes([0x05, 0]))
cmd("rejoin request, capabilities 0x8e", bytes([0x06, 0x8e]))
cmd("rejoin request, capabilities 0x00", bytes([0x06, 0x00]))
cmd("rejoin response, success", bytes([0x07]) + struct.pack("<H", 0x7777) + bytes([0x00]))
cmd("rejoin response, PAN at capacity", bytes([0x07]) + struct.pack("<H", 0xffff) + bytes([0x01]))
cmd("rejoin response, unknown status", bytes([0x07]) + struct.pack("<H", 0xffff) + bytes([0x77]))
cmd("link status, first+last, 3 links", bytes([0x08, 0x40 | 0x20 | 3]) +
    struct.pack("<HBHBHB", 0x0001, 0x31, 0x0002, 0x72, 0x0003, 0x07))
cmd("link status, no links", bytes([0x08, 0x00]))
cmd("network report, PAN identifier conflict, 2 PANs", bytes([0x09, 0x00 | 2]) + struct.pack("<Q", EUI_A) + struct.pack("<HH", 0x1111, 0x2222))
cmd("network report, PAN identifier conflict, none", bytes([0x09, 0x00]) + struct.pack("<Q", EUI_A))
cmd("network report, ZBOSS key trace (plain made-up key; the dissector learns it)",
    bytes([0x09, 6 << 5]) + struct.pack("<Q", EUI_A) + bytes(range(0xa0, 0xb0)))
cmd("network report, unknown report type 3", bytes([0x09, 3 << 5]) + struct.pack("<Q", EUI_A))
cmd("network update, PAN identifier update, 2 PANs", bytes([0x0a, 0x00 | 2]) + struct.pack("<Q", EUI_A) + bytes([5]) + struct.pack("<HH", 0x1111, 0x2222))
cmd("network update, unknown type", bytes([0x0a, 2 << 5]) + struct.pack("<Q", EUI_A) + bytes([5]))
cmd("end device timeout request", bytes([0x0b, 0x03, 0x00]))
for st, info in ((0x00, 0x07), (0x01, 0x00), (0x02, 0x03), (0x7f, 0x01)):
    cmd("end device timeout response, status %d" % st, bytes([0x0c, st, info]))
cmd("link power delta, notification, 2 entries (fixed: structure offsets)",
    bytes([0x0d, 0x00, 0x02]) + struct.pack("<Hb", 0x1111, -3) + struct.pack("<Hb", 0x2222, 4))
cmd("link power delta, request, 0 entries", bytes([0x0d, 0x01, 0x00]))
cmd("link power delta, response, 1 entry", bytes([0x0d, 0x02, 0x01]) + struct.pack("<Hb", 0x3333, 0))
cmd("link power delta, reserved type, 1 entry", bytes([0x0d, 0x03, 0x01]) + struct.pack("<Hb", 0x3333, -128))
cmd("commissioning request, association type 0", bytes([0x0e, 0x00, 0x8e]))
cmd("commissioning request, association type 1", bytes([0x0e, 0x01, 0x00]))
cmd("commissioning response, success", bytes([0x0f]) + struct.pack("<H", 0x7778) + bytes([0x00]))
cmd("commissioning response, failure", bytes([0x0f]) + struct.pack("<H", 0xffff) + bytes([0x02]))
cmd("unknown command 0x40 with one trailing octet", bytes([0x40, 0x99]))
cmd("command with trailing TLV (PAN ID conflict report)", bytes([0x04, 0x20]) + bytes([66, 1]) + struct.pack("<H", 0x4242))
cmd("command with trailing TLV (manufacturer specific)", bytes([0x06, 0x8e]) + bytes([64, 2]) + struct.pack("<H", 0x115b) + bytes([0xaa, 0xbb]))
cmd("command with trailing byte after a complete command", bytes([0x04, 0x20, 0x00]))
cmd("route request with source route (info column)", bytes([0x01, 0x08, 0x20]) + struct.pack("<HB", 0xfffc, 0), seq=0x42,
    route=(0, [0x7001]))

# --- 3. Interpan and other frame types --------------------------------------------
sect("interpan")
def ZLL_SCAN(seq):
    return zcl_frame(0x00, struct.pack("<IBB", 0x01020304, 0x05, 0x06), seq=seq, ftype=1)


IP_NWK = struct.pack("<H", nwk_fcf(3, 2, 0))
add("interpan NWK, APS interpan unicast, ZLL profile",
    wpan_interpan(IP_NWK + bytes([0x03]) + struct.pack("<HH", 0x1000, 0xc05e) + ZLL_SCAN(2)))
add("interpan NWK, APS interpan broadcast", wpan_interpan(IP_NWK +
                  bytes([0x03 | (2 << 2)]) + struct.pack("<HH", 0x1000, 0xc05e) + ZLL_SCAN(3)))
add("interpan NWK, APS interpan group", wpan_interpan(IP_NWK +
                  bytes([0x03 | (3 << 2)]) + struct.pack("<H", 0x4321) + struct.pack("<HH", 0x1000, 0xc05e) + ZLL_SCAN(4)))
madd("interpan frame with only the NWK header (missing payload)", wpan_interpan(IP_NWK))
madd("data frame with only the NWK header (missing payload)", wpan_short(nwk(b"", seq=60), seq=60))
madd("command frame with only the NWK header (missing payload)", wpan_short(nwk(b"", ftype=1, seq=61), seq=61))

# --- 4. Security header handling (no valid key: only the failure paths) ----------
sect("security")
SEC_FILLER_PAYLOAD = bytes(range(0x30, 0x30 + 12))
sec_hdr_nwk = bytes([0x28]) + struct.pack("<I", 0x00000102) + struct.pack("<Q", EUI_A) + bytes([0x00])
add("secured NWK data (level 5, network key), filler payload and MIC, no key",
    wpan_short(nwk(sec_hdr_nwk + SEC_FILLER_PAYLOAD + b"\xee" * 4, sec=1, seq=70), seq=70))
add("secured NWK command (level 5), filler payload, no key",
    wpan_short(nwk(sec_hdr_nwk + SEC_FILLER_PAYLOAD + b"\xee" * 4, ftype=1, sec=1, seq=71), seq=71))
madd("secured NWK frame with only the NWK header (missing payload)", wpan_short(nwk(b"", sec=1, seq=72), seq=72))

# --- 5. Beacons ---------------------------------------------------------------
sect("beacons")
EPID = 0x1122334455667788
add("beacon, ZigBee PRO (version 2), EPID, TX offset, update ID",
    wpan_beacon(bytes([0x00]) + struct.pack("<H", 0x0002 | (2 << 4) | 0x0400 | (3 << 11) | 0x8000) +
                struct.pack("<Q", EPID) + b"\xff\xff\xff" + bytes([7]), seq=80))
add("beacon, ZigBee PRO, EPID and TX offset, no update ID",
    wpan_beacon(bytes([0x00]) + struct.pack("<H", 0x0002 | (2 << 4)) + struct.pack("<Q", EPID) + b"\xff\xff\xff", seq=81))
add("beacon, ZigBee PRO, EPID only", wpan_beacon(bytes([0x00]) + struct.pack("<H", 0x0002 | (2 << 4)) +
                struct.pack("<Q", EPID), seq=82))
add("beacon, ZigBee 2004 (version 1) with TX offset", wpan_beacon(bytes([0x00]) + struct.pack("<H", 0x0001 | (1 << 4)) +
                b"\xff\xff\xff", seq=83))
add("beacon, ZigBee 2004 without TX offset", wpan_beacon(bytes([0x00]) + struct.pack("<H", 0x0000 | (1 << 4)), seq=84))
add("beacon, unknown stack profile 5 with TLV (manufacturer specific)",
    wpan_beacon(bytes([0x00]) + struct.pack("<H", 0x0005 | (2 << 4)) + struct.pack("<Q", EPID) + b"\xff\xff\xff" + bytes([1]) +
                bytes([64, 1]) + struct.pack("<H", 0x115b) + bytes([0x01]), seq=85))
add("beacon whose payload starts with another protocol ID (not ZigBee)", wpan_beacon(bytes([0x07, 1, 2, 3]), seq=86))
add("ZigBee IP beacon, flags 0x87, TLV", wpan_beacon(bytes([0x02, 0x87]) + b"ZigBeeIP-net-01\x00" + bytes([64, 1, 0x5b, 0x11]), seq=87))
add("ZigBee IP beacon, no flags, trailing byte", wpan_beacon(bytes([0x02, 0x00]) + b"abcdefghijklmnop" + bytes([0x00]), seq=88))

# --- 6. ZigBee IEs in 802.15.4-2015 payload IEs ------------------------------------
sect("information elements")


def wpan_2015_ie(ies, payload=b"", seq=1):
    """802.15.4-2015 data frame: header IE termination 1 + vendor payload IE + payload IE termination."""
    fcf = 0x0001 | 0x0040 | (2 << 10) | (2 << 14) | 0x0200 | (2 << 12)
    h = struct.pack("<HBHHH", fcf, seq & 0xff, 0x1234, 0x0001, 0x0002)
    h += struct.pack("<H", 0x7e << 7)                       # header termination 1
    body = b"\x1b\x19\x4a" + ies                            # ZigBee OUI 4A:19:1B (little endian)
    h += struct.pack("<H", 0x8000 | (2 << 11) | len(body)) + body
    h += struct.pack("<H", 0x8000 | (0xf << 11))            # payload IE termination
    return h + payload


def zie(ie_id, body):
    return struct.pack("<H", (ie_id << 6) | len(body)) + body


rejoin = zie(0, struct.pack("<QH", EPID, 0x1357))
txp = zie(1, bytes([0xf6]))
bcn = zie(2, bytes([0x00]) + struct.pack("<H", 0x0002 | (2 << 4)) + struct.pack("<Q", EPID) + b"\xff\xff\xff" + bytes([4]) +
          struct.pack("<H", 0xcfff) + struct.pack(">H", 0x0abc))
add("802.15.4-2015 data with ZigBee Rejoin IE and NWK payload", wpan_2015_ie(rejoin, nwk(ZCL_ONOFF), seq=90))
add("802.15.4-2015 data with ZigBee TX Power IE", wpan_2015_ie(txp, nwk(ZCL_ONOFF, seq=2), seq=91))
add("802.15.4-2015 data with ZigBee Beacon Payload IE", wpan_2015_ie(bcn, nwk(ZCL_ONOFF, seq=3), seq=92))
add("802.15.4-2015 data with Rejoin, TX Power and unknown IE (id 5, 3 octets)",
    wpan_2015_ie(rejoin + txp + zie(5, b"\x01\x02\x03"), nwk(ZCL_ONOFF, seq=4), seq=93))

# --- 7. Frames the heuristics reject ------------------------------------------------
sect("rejected by the heuristics")
add("protocol version 3 frame (Green Power): the NWK dissector passes it to the GP dissector",
    wpan_gp(gp_frame(bytes([0x22]), ext=False), seq=100))
add("data frame whose NWK version is 5 (rejected, shown as data)", wpan_short(struct.pack("<H", nwk_fcf(0, 5, 0)) + b"\x00" * 8, seq=101))
add("one octet payload (rejected, shown as data)", wpan_short(b"\x09", seq=102))
add("reserved NWK frame type 2 (rejected by the heuristic; runcov.sh reaches the invalid-type branch with Decode As)",
    wpan_short(struct.pack("<H", nwk_fcf(2, 2, 1)) + struct.pack("<HHBB", 0x0001, 0x0002, 30, 1) + b"\x01\x02", seq=104))
add("empty payload", wpan_short(b"", seq=103))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "."
    write_pcap(os.path.join(outdir, "zbee-nwk-coverage.pcap"), frames)
    write_pcap(os.path.join(outdir, "zbee-nwk-coverage-malformed.pcap"), mframes)
    if "-v" in sys.argv:
        n = 0
        for l in labels:
            if isinstance(l, tuple):
                print("== %s (from frame %d)" % (l[1], l[2]))
            else:
                n += 1
                print("%4d %s" % (n, l))
        for i, l in enumerate(mlabels):
            print("malformed %3d %s" % (i + 1, l))
    print("zbee-nwk-coverage.pcap:", len(frames), "frames;", "malformed:", len(mframes))


main()
