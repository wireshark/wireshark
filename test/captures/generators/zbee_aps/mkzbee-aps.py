# Generates test/captures/zbee_aps_coverage.pcap.gz
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
# zbee-aps coverage: APS data, acknowledgement and command frames inside NWK
# ---------------------------------------------------------------------------
frames = []
labels = []
mframes = []
mlabels = []


def add(label, frame):
    frames.append(frame)
    labels.append(label)


def madd(label, frame):
    mframes.append(frame)
    mlabels.append(label)


def sect(name):
    labels.append(("SECTION", name, len(frames) + 1))


def keybytes(n):
    """Made-up 16 octet 'keys' (a counter pattern, not derived from anything)."""
    return struct.pack("<IIII", n, n ^ 0x5a5a5a5a, n * 3 + 1, 0x600df00d)


def aps(ftype=0, delivery=0, bit4=0, sec=0, ackreq=0, ext=None, dst=None, group=None, cluster=None,
        profile=None, src=None, counter=None, payload=b"", ver=2):
    """APS frame builder. ext: bytes of the extended header (None: no extended header).
    dst/group/cluster/profile/src/counter: omitted when None."""
    fcf = ftype | (delivery << 2) | (bit4 << 4) | (sec << 5) | (ackreq << 6) | (0x80 if ext is not None else 0)
    h = bytes([fcf])
    if dst is not None:
        h += bytes([dst])
    if group is not None:
        h += struct.pack("<H", group)
    if cluster is not None:
        h += struct.pack("<H", cluster) if ver >= 2 else bytes([cluster])
    if profile is not None:
        h += struct.pack("<H", profile)
    if src is not None:
        h += bytes([src])
    if counter is not None:
        h += bytes([counter])
    if ext is not None:
        h += ext
    return h + payload


def adata(payload=b"", cluster=0x0006, profile=0x0104, dst=1, src=1, counter=1, **kw):
    return aps(0, dst=dst, cluster=cluster, profile=profile, src=src, counter=counter, payload=payload, **kw)


def acmd(cmd, body=b"", counter=1, **kw):
    return aps(1, counter=counter, payload=bytes([cmd]) + body, **kw)


def N(label, apsframe, src=0x0002, dst=0x0001, ver=2, **kw):
    n = len(frames) + 1
    add(label, wpan_short(nwk(apsframe, src=src, dst=dst, ver=ver, seq=n & 0xff, **kw), seq=n & 0xff, src=src, dst=dst))


def M(label, apsframe, src=0x0002, dst=0x0001, ver=2, **kw):
    n = len(mframes) + 1
    madd(label, wpan_short(nwk(apsframe, src=src, dst=dst, ver=ver, seq=n & 0xff, **kw), seq=n & 0xff, src=src, dst=dst))


ON = zcl_frame(0x01, ftype=1, seq=1)
EUI_A = 0x00124b0001020304
EUI_B = 0x00124b000a0b0c0d
EUI_C = 0x00124b00deadbeef
SECHDR = bytes([0x08]) + struct.pack("<I", 0x42) + bytes([0x00]) + bytes(range(0x50, 0x5c)) + b"\xee" * 4   # filler, no valid MIC

# --- 1. Data frames -----------------------------------------------------------------------
sect("data frames")
N("data, unicast, HA profile, On command", adata(ON))
N("data, unicast, acknowledgement requested", adata(ON, ackreq=1, counter=2))
N("data, broadcast delivery mode", adata(ON, counter=3, delivery=2), dst=0xfffd)
N("data, group delivery (ZigBee 2007: group address, no destination endpoint)",
  aps(0, delivery=3, group=0x1234, cluster=0x0006, profile=0x0104, src=1, counter=4, payload=ON))
N("data, ZDP cluster (Simple Descriptor Request)", adata(struct.pack("<BHB", 7, 0x0001, 1), cluster=0x0004, profile=0x0000, dst=0, src=0, counter=5))
N("data, ZDP, unknown cluster 0x7777", adata(b"\x01", cluster=0x7777, profile=0x0000, dst=0, src=0, counter=6))
N("data, unknown profile 0x1234 (ZCL attempted)", adata(ON, profile=0x1234, counter=7))
N("data, Smart Energy profile", adata(zcl_frame(0x00, struct.pack("<H", 0x0000), seq=2), cluster=0x0702, profile=0x0109, counter=8))
N("data, Green Power profile 0xa1e0", adata(ON, cluster=0x0021, profile=0xa1e0, counter=9, dst=242, src=242))
N("data, manufacturer specific profile 0xc216", adata(ON, profile=0xc216, counter=10))
N("data, without payload", adata(b"", counter=11))
N("data, with the acknowledgement format bit set (ignored for data frames)",
  aps(0, bit4=1, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=12, payload=ON))
N("data with an extended header, no fragmentation", aps(0, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=13, ext=bytes([0x00]), payload=ON))
N("data, security flag, filler payload (APS aux header: network key, no valid key)",
  aps(0, sec=1, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=14, payload=SECHDR))
N("data, security flag, data key, extended nonce", aps(0, sec=1, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=15,
  payload=bytes([0x20]) + struct.pack("<I", 0x43) + struct.pack("<Q", EUI_A) + bytes(range(0x50, 0x5c)) + b"\xee" * 4))

# --- 1b. Inter-PAN (stub APS) frames: ZigBee NWK frame type 3 on an extended source address -------------
sect("inter-PAN")
IP_NWK = struct.pack("<H", nwk_fcf(3, 2, 0))
SCAN = zcl_frame(0x00, struct.pack("<IBB", 0x01020304, 0x05, 0x06), seq=2, ftype=1)
for i, (label, d, g) in enumerate((("unicast", 0, None), ("broadcast", 2, None), ("group", 3, 0x4321))):
    add("inter-PAN APS data, %s delivery, ZLL profile (ZCL Touchlink scan request)" % label,
        wpan_interpan(IP_NWK + aps(3, delivery=d, group=g, cluster=0x1000, profile=0xc05e, payload=SCAN), seq=100 + i))
add("inter-PAN APS data with an extended header (no fragmentation)",
    wpan_interpan(IP_NWK + aps(3, cluster=0x1000, profile=0xc05e, ext=bytes([0x00]), payload=SCAN), seq=103))

# --- 2. Test profile 2 ---------------------------------------------------------------------
sect("test profile 2")
T2 = 0x7f01
N("T2, Buffer Test Request", adata(bytes([40]), cluster=0x001c, profile=T2, counter=20))
N("T2, Buffer Test Response, 3 octets", adata(bytes([3, 0x00, 0xaa, 0xbb, 0xcc]), cluster=0x0054, profile=T2, counter=21))
N("T2, Buffer Test Response, status 1 (too few octets sent)", adata(bytes([2, 0x01, 0xaa, 0xbb]), cluster=0x0054, profile=T2, counter=22))
for cid in (0x0001, 0x0002, 0x0003, 0x0004, 0x001d, 0x0055, 0x1000, 0x1001, 0xa0a8, 0xe000, 0xe001, 0xf000, 0xf001, 0xf00a, 0xf00e, 0x7777):
    N("T2 cluster 0x%04x" % cid, adata(bytes([1, 2]), cluster=cid, profile=T2, counter=23))

# --- 3. Acknowledgements -------------------------------------------------------------------
sect("acknowledgements")
N("ack of a data frame (ZigBee 2007, data-ack format with endpoints)", aps(2, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=1), src=0x0001, dst=0x0002)
N("ack of a command (ZigBee 2007, command-ack format: counter only)", aps(2, bit4=1, counter=2), src=0x0001, dst=0x0002)
N("ack, broadcast delivery mode flag", aps(2, delivery=2, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=3), src=0x0001, dst=0x0002)
N("ack with extended header and a fragment block acknowledgement (blocks 1,2,4)",
  aps(2, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=4, ext=bytes([0x01, 0x03, 0x0b])), src=0x0001, dst=0x0002)
N("ack with extended header, middle fragment, block ack 0xff",
  aps(2, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=5, ext=bytes([0x02, 0x01, 0xff])), src=0x0001, dst=0x0002)
N("ack with extended header and no fragmentation", aps(2, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=6, ext=bytes([0x00])), src=0x0001, dst=0x0002)

# --- 4. Fragmentation and reassembly --------------------------------------------------------
sect("fragmentation")
BIG = zcl_frame(0x01, b"".join(struct.pack("<HBB", 0x0000 + i, 0x00, 0x20) + bytes([i]) for i in range(12)), seq=9, ftype=0, to_client=1)
parts = [BIG[0:14], BIG[14:28], BIG[28:]]


def frag(label, counter, kind, block, payload, src=0x0040):
    N(label, aps(0, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=counter, ext=bytes([kind, block]), payload=payload), src=src)


frag("fragment 1 of 3 (first, block number = 3), cluster 0x0006", 30, 1, 3, parts[0])
frag("fragment 2 of 3 (middle, block 1)", 30, 2, 1, parts[1])
frag("fragment 3 of 3 (middle, block 2): reassembled and dissected as ZCL", 30, 2, 2, parts[2])
frag("fragmented message 2: block 2 arrives first", 31, 2, 2, parts[2])
frag("fragmented message 2: block 1", 31, 2, 1, parts[1])
frag("fragmented message 2: the first block completes it", 31, 1, 3, parts[0])
frag("fragmented message 3: the first block alone (never completed)", 32, 1, 2, parts[0])
frag("fragmented message 4 (two blocks), first", 33, 1, 2, BIG[:20])
frag("fragmented message 4, block 1", 33, 2, 1, BIG[20:])
CMDBIG = bytes([0x05, 0x01]) + keybytes(77) + bytes([0x02]) + struct.pack("<QQ", EUI_B, EUI_A)
N("fragmented command, first block", aps(1, counter=34, ext=bytes([0x01, 2]), payload=CMDBIG[:10]), src=0x0041)
N("fragmented command, last block: reassembled Transport Key command", aps(1, counter=34, ext=bytes([0x02, 1]), payload=CMDBIG[10:]), src=0x0041)
N("fragment without payload (extended header only)", aps(0, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=35, ext=bytes([0x02, 1])), src=0x0040)

# --- 5. APS counter wrap (extended counters, only matter for fragmentation) --------------------------
sect("counter wrap")
for c in (0x10, 0xf0, 0x20, 0x21, 0xd8, 0x30):
    N("data from 0x0050 with APS counter 0x%02x" % c, adata(ON, counter=c), src=0x0050)
frag("fragment 1 with counter 0xfe from 0x0050 (the counter wraps while fragmenting)", 0xfe, 1, 2, BIG[:20], src=0x0050)
frag("fragment 2 with counter 0xfe from 0x0050", 0xfe, 2, 1, BIG[20:], src=0x0050)

# --- 6. Commands ------------------------------------------------------------------------------------
sect("commands")
CH = bytes(range(0x60, 0x70))
N("SKKE-1 (filler challenge)", acmd(0x01, struct.pack("<QQ", EUI_A, EUI_B) + CH, counter=40))
N("SKKE-2", acmd(0x02, struct.pack("<QQ", EUI_B, EUI_A) + CH, counter=41))
N("SKKE-3 (filler MAC)", acmd(0x03, struct.pack("<QQ", EUI_A, EUI_B) + CH, counter=42))
N("SKKE-4", acmd(0x04, struct.pack("<QQ", EUI_B, EUI_A) + CH, counter=43))
N("Transport Key, trust center master key", acmd(0x05, bytes([0x00]) + keybytes(1) + struct.pack("<QQ", EUI_B, EUI_A), counter=44))
N("Transport Key, standard network key", acmd(0x05, bytes([0x01]) + keybytes(2) + bytes([0x05]) + struct.pack("<QQ", EUI_B, EUI_A), counter=45))
N("Transport Key, application master key", acmd(0x05, bytes([0x02]) + keybytes(3) + struct.pack("<Q", EUI_C) + bytes([0x01]), counter=46))
N("Transport Key, application link key", acmd(0x05, bytes([0x03]) + keybytes(4) + struct.pack("<Q", EUI_C) + bytes([0x00]), counter=47))
N("Transport Key, trust center link key", acmd(0x05, bytes([0x04]) + keybytes(5) + struct.pack("<QQ", EUI_B, EUI_A), counter=48))
N("Transport Key, high security network key", acmd(0x05, bytes([0x05]) + keybytes(6) + bytes([0x07]) + struct.pack("<QQ", EUI_B, EUI_A), counter=49))
N("Transport Key, ephemeral global auth (no key follows)", acmd(0x05, bytes([0xb0]), counter=50))
N("Transport Key, ephemeral unique auth (no key follows)", acmd(0x05, bytes([0xb1]), counter=51))
N("Transport Key, basic auth key", acmd(0x05, bytes([0xb2]) + keybytes(7) + bytes([0x01]) + struct.pack("<QQ", EUI_B, EUI_A), counter=52))
N("Transport Key, admin auth key type (no further fields)", acmd(0x05, bytes([0xb3]) + keybytes(8), counter=53))
N("Transport Key, unknown key type 0x55", acmd(0x05, bytes([0x55]) + keybytes(9), counter=54))
N("Transport Key with a trailing TLV (link key features and capabilities)", acmd(0x05, bytes([0x04]) + keybytes(5) + struct.pack("<QQ", EUI_B, EUI_A) + bytes([0x00, 0x00, 0x01]), counter=55))
N("Update Device, ZigBee 2007 (with short address), status 0", acmd(0x06, struct.pack("<QHB", EUI_A, 0x1234, 0x00), counter=56))
N("Update Device, status 1 (unsecured join)", acmd(0x06, struct.pack("<QHB", EUI_A, 0x1234, 0x01), counter=57))
N("Update Device, status 2 (leave)", acmd(0x06, struct.pack("<QHB", EUI_A, 0x1234, 0x02), counter=58))
N("Update Device, ZigBee 2004 (no short address)", acmd(0x06, struct.pack("<QB", EUI_A, 0x03), counter=59, ver=1), ver=1)
N("Remove Device", acmd(0x07, struct.pack("<Q", EUI_C), counter=60))
N("Request Key, network key", acmd(0x08, bytes([0x01]), counter=61))
N("Request Key, application master key with partner", acmd(0x08, bytes([0x02]) + struct.pack("<Q", EUI_C), counter=62))
N("Request Key, trust center link key type", acmd(0x08, bytes([0x04]), counter=63))
N("Switch Key", acmd(0x09, bytes([0x07]), counter=64))
N("Entity Authentication initiator challenge, network key", acmd(0x0a, bytes([0x00, 0x03]) + struct.pack("<QQ", EUI_A, EUI_B) + CH, counter=65))
N("Entity Authentication initiator challenge, link key", acmd(0x0a, bytes([0x01]) + struct.pack("<QQ", EUI_A, EUI_B) + CH, counter=66))
N("Entity Authentication responder challenge", acmd(0x0b, bytes([0x01]) + struct.pack("<QQ", EUI_B, EUI_A) + CH, counter=67))
N("Entity Authentication initiator MAC and data", acmd(0x0c, CH + bytes([0x01]) + bytes([1, 2, 3, 4]), counter=68))
N("Entity Authentication responder MAC and data", acmd(0x0d, CH + bytes([0x00]) + bytes([5, 6, 7, 8]), counter=69))
N("Verify Key", acmd(0x0f, bytes([0x04]) + struct.pack("<Q", EUI_A) + CH, counter=70))
N("Confirm Key, success", acmd(0x10, bytes([0x00, 0x04]) + struct.pack("<Q", EUI_A), counter=71))
N("Confirm Key, status 0xa3", acmd(0x10, bytes([0xa3, 0x04]) + struct.pack("<Q", EUI_A), counter=72))
RELAY_INNER = adata(ON, counter=3)
N("Relay Message Downstream (TLV with the joiner and a relayed APS data frame)",
  acmd(0x11, bytes([0x00, 8 + len(RELAY_INNER) - 1]) + struct.pack("<Q", EUI_C) + RELAY_INNER, counter=73))
RELAY_CMD = acmd(0x09, bytes([0x04]), counter=4)
N("Relay Message Upstream (relayed APS command)",
  acmd(0x12, bytes([0x00, 8 + len(RELAY_CMD) - 1]) + struct.pack("<Q", EUI_C) + RELAY_CMD, counter=74))
N("unknown command 0x40 with a trailing byte", acmd(0x40, bytes([0x99]), counter=75))
N("command with trailing byte after a complete Switch Key", acmd(0x09, bytes([0x07, 0x99]), counter=76))
N("command, security flag, filler payload (no key)", aps(1, sec=1, counter=77, payload=SECHDR))
N("command with acknowledgement requested", aps(1, ackreq=1, counter=78, payload=bytes([0x09, 0x08])))

# --- 7. Tunnel command: normal nesting and the nesting limit -------------------------------------------
sect("tunnel command nesting")
SW = acmd(0x09, bytes([0x09]), counter=9)


def tun(inner, counter=1):
    return acmd(0x0e, struct.pack("<Q", EUI_B) + inner, counter=counter)


def nest(n, inner=SW):
    for _ in range(n):
        inner = tun(inner)
    return inner


N("tunnel, 1 level (tunnelled Switch Key)", nest(1))
N("tunnel, 2 levels", nest(2))
N("tunnel, 3 levels", nest(3))
N("tunnel carrying a Transport Key command", tun(acmd(0x05, bytes([0x01]) + keybytes(10) + bytes([0x02]) + struct.pack("<QQ", EUI_B, EUI_A), counter=83)))
N("tunnel, 4 levels (the Switch Key is still dissected)", nest(4))
N("tunnel, 5 levels: the fifth Tunnel command shows the expert info instead of its content", nest(5))
N("tunnel, 8 levels (reproducer of the unbounded recursion, 520 levels in the original)", nest(8))
N("data frame after the deep tunnels (the depth counter was restored)", adata(ON, counter=90))

# --- 8. ZigBee 2004 (NWK version 1) and the application framework ---------------------------------------
sect("ZigBee 2004")
APF_KVP = 0x10
APF_MSG = 0x20


def apf(kind, trans):
    return bytes([kind | len(trans)]) + b"".join(trans)


def N04(label, payload, delivery=0, indirect=0, dst=1, src=1, cluster=0x06, profile=0x0104):
    n = len(frames) + 1
    a = aps(0, delivery=delivery, bit4=indirect, dst=dst if not (delivery == 1 and indirect) else None,
            cluster=cluster, profile=profile, src=src if not (delivery == 1 and indirect) else None,
            payload=payload, ver=1)
    add(label, wpan_short(nwk(a, ver=1, seq=n & 0xff), seq=n & 0xff))


N04("2004 data, APF with one message transaction (profile HA)", apf(APF_MSG, [bytes([1, 2, 0x01, 0x22])]))
N04("2004 data, APF with two message transactions", apf(APF_MSG, [bytes([1, 1, 0x01]), bytes([1, 1, 0x00])]))
N04("2004 data, APF, unknown profile (no application dissector)", apf(APF_MSG, [bytes([1, 1, 0x01])]), profile=0x1234)
N04("2004 data, indirect delivery, destination endpoint (indirect mode 0)", apf(APF_MSG, [bytes([1, 1, 0x01])]), delivery=1, indirect=0)
N04("2004 data, indirect delivery, source endpoint only (indirect mode 1)", apf(APF_MSG, [bytes([1, 1, 0x01])]), delivery=1, indirect=1)
N04("2004 data, broadcast delivery", apf(APF_MSG, [bytes([1, 1, 0x01])]), delivery=2)


def kvp(cmd_, typ):
    """One KVP transaction of the length zbee_apf_transaction_len() computes."""
    head = bytes([1, (typ << 4) | cmd_, 0x01, 0x00])           # seq, cmd/type, attribute (2)
    if cmd_ in (0x9, 0xa):                                       # set/event response: + error code
        return head + b"\x00"
    if cmd_ == 0x8:                                              # get response: + error code, then data
        head += b"\x00"
    if cmd_ not in (0x1, 0x2, 0x5, 0x6, 0x8):
        return head
    n = {0xc: 4, 0xd: 4, 0x3: 2, 0x4: 2, 0xb: 2, 0x1: 1, 0x2: 1}.get(typ)
    if typ in (0xe, 0xf):
        return head + bytes([2, 0xaa, 0xbb])
    return head + b"\x00" * (n or 0)


for cmd_ in (0x1, 0x2, 0x4, 0x5, 0x6, 0x8, 0x9, 0xa, 0x3):
    N04("2004 APF KVP transactions, command 0x%x, all data types" % cmd_,
        apf(APF_KVP, [kvp(cmd_, t) for t in (0x0, 0x1, 0x2, 0x3, 0x4, 0xb, 0xc, 0xd, 0xe, 0xf, 0x7)][:15]))
N04("2004 APF, cluster with 1 octet and unknown profile 0x7f01 (T2 is not special in 2004)", apf(APF_MSG, [bytes([1, 1, 0x01])]), profile=0x7f01)

# --- malformed capture ---------------------------------------------------------------------------------
M("data, indirect delivery in ZigBee 2007 (invalid delivery mode)", aps(0, delivery=1, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=1, payload=ON))
M("data, group delivery in ZigBee 2004 (invalid delivery mode)", aps(0, delivery=3, dst=1, cluster=0x06, profile=0x0104, src=1, payload=ON, ver=1), ver=1)
M("command frame with no payload (missing payload)", aps(1, counter=2))
M("command frame whose payload is only the security header and the frame ends there", aps(1, sec=1, counter=3, payload=b""))
M("data frame truncated after the destination endpoint", bytes([0x00, 0x01]))
M("data frame truncated in the cluster", bytes([0x00, 0x01, 0x06]))
M("command truncated (SKKE-1 with half a challenge)", acmd(0x01, struct.pack("<QQ", EUI_A, EUI_B) + bytes(8), counter=4))
M("Transport Key with a truncated key", acmd(0x05, bytes([0x01]) + keybytes(11)[:9], counter=5))
M("Update Device truncated", acmd(0x06, struct.pack("<Q", EUI_A) + bytes([0x12]), counter=6))
M("Tunnel command without the destination address", acmd(0x0e, bytes([1, 2, 3]), counter=7))
M("Tunnel command whose inner frame is empty", acmd(0x0e, struct.pack("<Q", EUI_B), counter=8))
M("Tunnel, 8 levels around a truncated frame", nest(8, bytes([0x01])))
M("T2 Buffer Test Response with a payload length that is not there", adata(bytes([200, 0x00, 0xaa]), cluster=0x0054, profile=0x7f01, counter=9))
M("T2 Buffer Test Request without payload", adata(b"", cluster=0x001c, profile=0x7f01, counter=10))
M("fragment, first block with block number 0 (the total length wraps)", aps(0, dst=1, cluster=0x0006, profile=0x0104, src=1, counter=0x77, ext=bytes([0x01, 0]), payload=bytes(6)), src=0x0060)
madd("2004 APF whose transaction length runs past the frame", wpan_short(nwk(aps(0, dst=1, cluster=0x06, profile=0x0104, src=1, payload=bytes([0x21, 1, 200, 0x11]), ver=1), ver=1, seq=40), seq=40))
madd("2004 APF KVP transaction cut short", wpan_short(nwk(aps(0, dst=1, cluster=0x06, profile=0x0104, src=1, payload=bytes([0x11, 1, 0xee]), ver=1), ver=1, seq=41), seq=41))
# Transport Key frames with more distinct plain keys than the NWK key ring keeps per PAN (64)
for n in range(2000, 2072):
    M("Transport Key with a plain made-up key #%d" % (n - 1999), acmd(0x05, bytes([0x01]) + keybytes(n) + bytes([0x02]) + struct.pack("<QQ", EUI_B, EUI_A), counter=n & 0xff))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "."
    write_pcap(os.path.join(outdir, "zbee-aps-coverage.pcap"), frames)
    write_pcap(os.path.join(outdir, "zbee-aps-coverage-malformed.pcap"), mframes)
    if "-v" in sys.argv:
        n = 0
        for l in labels:
            if isinstance(l, tuple):
                print("== %s (from frame %d)" % (l[1], l[2]))
            else:
                n += 1
                print("%4d %s" % (n, l))
        for i, l in enumerate(mlabels[:20]):
            print("malformed %3d %s" % (i + 1, l))
    print("zbee-aps-coverage.pcap:", len(frames), "frames; malformed:", len(mframes))


main()
