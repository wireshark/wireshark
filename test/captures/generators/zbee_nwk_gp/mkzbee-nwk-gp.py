# Generates test/captures/zbee_nwk_gp_coverage.pcap.gz
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
# zbee-nwk-gp coverage: ZigBee Green Power frames over IEEE 802.15.4
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


def wpan_gp_ext(payload, seq=1, pan=0xffff, dst64=0x00124b0001020304):
    """802.15.4 data frame with an extended destination and no source."""
    fcf = 0x0001 | (3 << 10)
    return struct.pack("<HBHQ", fcf, seq & 0xff, pan, dst64) + payload


def gpf(payload, ftype=0, ext=True, app=0, sec=0, key=0, rxaftertx=0, direction=0,
        src_id=0x11223344, endpoint=1, counter=0x00000100, mic=None, auto=0, srcid=None, ver=3):
    """ZigBee Green Power NWK frame: header, payload, MIC (filler: no frame here is
    really protected; the MIC and the encrypted payloads are made-up bytes)."""
    fcf = ftype | (ver << 2) | (0x40 if auto else 0) | (0x80 if ext else 0)
    h = bytes([fcf])
    if ext:
        h += bytes([app | (sec << 3) | (key << 5) | (rxaftertx << 6) | (direction << 7)])
    if srcid is None:
        srcid = (app == 0) and ((not ext) or ftype == 0 or (ftype == 1 and payload[:1] != b"\xf3")) \
            and not (ftype == 1 and not ext)
    if srcid:
        h += struct.pack("<I", src_id)
    if ext and app == 2:
        h += bytes([endpoint])
    mic_size = 0
    if ext and app in (0, 1, 2):
        if sec == 1 and app != 1:
            mic_size = 2
        elif sec in (2, 3):
            mic_size = 4
            h += struct.pack("<I", counter)
    if mic is None:
        mic = b"\xa5" * mic_size
    return h + payload + mic


def gp(label, payload, **kw):
    add(label, wpan_gp(gpf(payload, **kw), seq=len(frames) & 0xff))


def keybytes(n):
    """Made-up 16 octet 'keys' (a counter pattern, not derived from anything)."""
    return struct.pack("<IIII", n, n ^ 0x5a5a5a5a, n * 3 + 1, 0x600df00d)


def comm(dev, opts, ext=None, key=None, mic=None, counter=None, appinfo=b""):
    b = bytes([0xE0, dev, opts])
    if ext is not None:
        b += bytes([ext])
        if key is not None:
            b += key
            if mic is not None:
                b += mic
        if counter is not None:
            b += struct.pack("<I", counter)
    return b + appinfo


def comm_reply(opts, pan=None, key=None, mic=None, counter=None):
    b = bytes([0xF0, opts])
    if pan is not None:
        b += struct.pack("<H", pan)
    if key is not None:
        b += key
    if mic is not None:
        b += mic
    if counter is not None:
        b += struct.pack("<I", counter)
    return b


# --- 1. Header variants -------------------------------------------------------------
sect("headers")
gp("data, no extended header (GPD Src ID, Toggle)", bytes([0x22]), ext=False)
gp("data, extended header, security level 0, application ID 0 (On)", bytes([0x21]))
gp("data, auto commissioning flag", bytes([0x20]), auto=1, ext=False)
gp("data from ZGPP direction, rx after tx", bytes([0x21]), direction=1, rxaftertx=1)
gp("data, application ID 0, Src ID 0 (unspecified)", bytes([0x21]), src_id=0)
gp("data, application ID 0, Src ID 0xffffffff (all)", bytes([0x21]), src_id=0xffffffff)
gp("data, application ID 2 (ZGP) with endpoint", bytes([0x21]), app=2, endpoint=5)
gp("data, application ID 1 (LPED), no source ID", bytes([0x21]), app=1)
gp("data, application ID 3 (reserved)", bytes([0x21]), app=3, srcid=False)
gp("data, security level 1 (2 octet MIC), key flag", bytes([0x21]), sec=1, key=1)
gp("data, security level 2 (frame counter, 4 octet MIC), plain payload", bytes([0x22]), sec=2, counter=0x11)
gp("data, security level 2, application ID 2", bytes([0x22]), sec=2, app=2, endpoint=0xf1)
gp("data, security level 1, application ID 1 (no MIC for LPED)", bytes([0x21]), sec=1, app=1)
gp("maintenance frame, application ID 0 (Src ID present)", bytes([0xE1]), ftype=1)
gp("maintenance frame, no extended header", bytes([0xE1]), ftype=1, ext=False, srcid=False)
gp("maintenance frame, channel configuration (no Src ID)", bytes([0xF3, 0x05]), ftype=1)
gp("maintenance frame, application ID 2", bytes([0xE2]), ftype=1, app=2)
add("data to an extended destination address", wpan_gp_ext(gpf(bytes([0x21])), seq=len(frames) & 0xff))
add("data to an extended destination, maintenance channel configuration",
    wpan_gp_ext(gpf(bytes([0xF3, 0x0b]), ftype=1), seq=len(frames) & 0xff))
add("GP frame to a unicast short destination (rejected by the heuristic)",
    wpan_short(gpf(bytes([0x21])), seq=len(frames) & 0xff, dst=0x0001, src=0x0002))

# --- 2. Encrypted frames without a usable key ---------------------------------------
sect("encrypted payloads (no key can decrypt them: made-up bytes)")
ENC = bytes(range(0x40, 0x4a))
gp("encrypted, application ID 0, from ZGPD (empty key ring)", ENC, sec=3)
gp("encrypted, application ID 0, from ZGPP", ENC, sec=3, direction=1)
gp("encrypted, application ID 2 from ZGPD", ENC, sec=3, app=2)
gp("encrypted, application ID 2 from ZGPP", ENC, sec=3, app=2, direction=1)
gp("encrypted, application ID 1", ENC, sec=3, app=1)

# --- 3. Commands without a payload and with simple ones -----------------------------
sect("simple commands")
for cid, name in ((0x00, "Identify"), (0x10, "Recall Scene 0"), (0x17, "Recall Scene 7"), (0x18, "Store Scene 0"),
                  (0x1f, "Store Scene 7"), (0x20, "Off"), (0x23, "Release"), (0x34, "Level Control/Stop"),
                  (0x40, "Move Hue Stop"), (0x45, "Move Saturation Stop"), (0x50, "Lock Door"), (0x51, "Unlock Door"),
                  (0x60, "Press 1 of 1"), (0x65, "Release 2 of 2"), (0x66, "Short press 1 of 1"), (0x68, "Short press 2 of 2"),
                  (0xAF, "Any sensor command"), (0xE1, "Decommissioning"), (0xE2, "Success")):
    gp("command 0x%02x %s" % (cid, name), bytes([cid]))
gp("unknown command 0x77", bytes([0x77, 1, 2, 3]))
gp("command with trailing bytes (Toggle + 2 octets)", bytes([0x22, 0xaa, 0xbb]))
for cid in (0x30, 0x31, 0x35, 0x36, 0x41, 0x42, 0x46, 0x47):
    gp("move command 0x%02x with rate" % cid, bytes([cid, 0x21]))
gp("move up without rate", bytes([0x30]))
for cid in (0x32, 0x33, 0x37, 0x38, 0x43, 0x44, 0x48, 0x49):
    gp("step command 0x%02x with step size and transition time" % cid, bytes([cid, 0x08]) + struct.pack("<H", 0x0014))
gp("step up without transition time", bytes([0x32, 0x08]))
gp("move color", bytes([0x4A]) + struct.pack("<hh", 100, -100))
gp("step color with transition time", bytes([0x4B]) + struct.pack("<hhH", 10, -10, 5))
gp("step color without transition time", bytes([0x4B]) + struct.pack("<hh", 10, -10))
gp("channel request, toggling behaviour", bytes([0xE3, 0x35]))
gp("compact attribute report with data points", bytes([0xA8, 0x03, 0x01, 0x02, 0x03]))
gp("compact attribute report without data points", bytes([0xA8, 0x03]))

# --- 4. Attribute commands ----------------------------------------------------------
sect("attribute commands")
gp("attribute reporting, temperature measured value (int16)", bytes([0xA0]) + struct.pack("<HHBh", 0x0402, 0x0000, 0x29, 2150))
gp("attribute reporting, two records (on/off bool, uint8 sensor)",
   bytes([0xA0]) + struct.pack("<H", 0x0006) + struct.pack("<HBB", 0x0000, 0x10, 1) + struct.pack("<HBB", 0x4000, 0x20, 7))
gp("manufacturer specific attribute reporting", bytes([0xA1]) + struct.pack("<HHHBH", 0x115b, 0xfc00, 0x0001, 0x21, 0x1234))
gp("multi-cluster reporting, 2 clusters", bytes([0xA2]) + struct.pack("<HHBh", 0x0402, 0x0000, 0x29, 2100) +
   struct.pack("<HHBB", 0x0006, 0x0000, 0x10, 1))
gp("manufacturer specific multi-cluster reporting", bytes([0xA3]) + struct.pack("<H", 0x115b) +
   struct.pack("<HHBH", 0xfc00, 0x0001, 0x21, 0x5678))
gp("request attributes, one cluster, 2 attributes", bytes([0xA4, 0x00]) + struct.pack("<HBHH", 0x0006, 4, 0x0000, 0x4000))
gp("request attributes, manufacturer specific, 2 clusters",
   bytes([0xA4, 0x03]) + struct.pack("<HHBH", 0x115b, 0x0006, 2, 0x0000) + struct.pack("<HBH", 0x0402, 2, 0x0000))
gp("read attributes (0xF2), record list of 2 identifiers, 2 clusters",
   bytes([0xF2, 0x01]) + struct.pack("<HBHH", 0x0006, 4, 0x0001, 0x0002) + struct.pack("<HBH", 0x0402, 2, 0x0000))
gp("read attributes (0xF2), empty record list", bytes([0xF2, 0x01]) + struct.pack("<HB", 0x0006, 0))
gp("read attributes response, success and failure records",
   bytes([0xA5, 0x00]) + struct.pack("<HB", 0x0006, 9) + struct.pack("<HBBB", 0x0000, 0x00, 0x10, 1) +
   struct.pack("<HBB", 0x4000, 0x86, 0x00))
gp("read attributes response, manufacturer specific", bytes([0xA5, 0x02]) + struct.pack("<H", 0x115b) +
   struct.pack("<HB", 0x0006, 5) + struct.pack("<HBBB", 0xfc01, 0x00, 0x20, 9))
gp("write attributes, one record (on/off bool)", bytes([0xF1, 0x00]) + struct.pack("<HB", 0x0006, 4) + struct.pack("<HBB", 0x0000, 0x10, 1))
gp("write attributes, manufacturer specific, 2 records",
   bytes([0xF1, 0x02]) + struct.pack("<HHB", 0x115b, 0x0006, 8) + struct.pack("<HBB", 0x0000, 0x10, 1) +
   struct.pack("<HBB", 0x4000, 0x20, 4))
gp("ZCL tunneling, no manufacturer code", bytes([0xA6, 0x01]) + struct.pack("<HBB", 0x0006, 0x02, 2) + bytes([0xde, 0xad]))
gp("ZCL tunneling, manufacturer specific, to client", bytes([0xA6, 0x0c | 0x01]) + struct.pack("<HHBB", 0x115b, 0x0402, 0x00, 0) )

# --- 5. Commissioning ---------------------------------------------------------------
sect("commissioning")
K1, K2, K3, K4 = keybytes(1), keybytes(2), keybytes(3), keybytes(4)
gp("commissioning, device 0x02 (on/off switch), no options", comm(0x02, 0x00), direction=0)
gp("commissioning, all simple option bits (MAC seq, rx on, PAN request, key request, fixed location)",
   comm(0x04, 0x01 | 0x02 | 0x10 | 0x20 | 0x40))
gp("commissioning, extended options with security level capability and key type, no key, outgoing counter",
   comm(0x10, 0x80, ext=0x01 | (4 << 2) | 0x80, counter=0x00001234))
gp("commissioning, extended options, plain GPD key present (learned into the GP key ring)",
   comm(0x30, 0x80, ext=0x02 | (7 << 2) | 0x20, key=K1))
gp("commissioning, the same plain key again (not added twice)", comm(0x30, 0x80, ext=0x20, key=K1))
gp("commissioning, second plain key with outgoing counter", comm(0x12, 0x80, ext=0x20 | 0x80, key=K2, counter=0x00002000))
gp("commissioning, encrypted GPD key (filler bytes and MIC, no key can decrypt it)",
   comm(0x33, 0x80, ext=0x20 | 0x40, key=bytes(range(0x70, 0x80)), mic=b"\xc3\xc3\xc3\xc3"))
gp("commissioning, encrypted key with outgoing counter", comm(0x33, 0x80, ext=0x20 | 0x40 | 0x80,
   key=bytes(range(0x80, 0x90)), mic=b"\xc4\xc4\xc4\xc4", counter=7))
gp("commissioning, application info: manufacturer ID, GreenPeak model ID",
   comm(0xfe, 0x04, appinfo=bytes([0x01 | 0x02]) + struct.pack("<HH", 0x10d0, 0x0001)))
gp("commissioning, application info: other manufacturer model ID",
   comm(0xfe, 0x04, appinfo=bytes([0x01 | 0x02]) + struct.pack("<HH", 0x115b, 0x0042)))
gp("commissioning, application info: model ID without manufacturer ID",
   comm(0xfe, 0x04, appinfo=bytes([0x02]) + struct.pack("<H", 0x0042)))
gp("commissioning, application info: GPD command list (3 commands)",
   comm(0x07, 0x04, appinfo=bytes([0x04, 3, 0x20, 0x21, 0x22])))
gp("commissioning, application info: empty GPD command list", comm(0x07, 0x04, appinfo=bytes([0x04, 0])))
gp("commissioning, application info: cluster reports (2 server, 1 client)",
   comm(0x07, 0x04, appinfo=bytes([0x08, 0x02 | (1 << 4)]) + struct.pack("<HHH", 0x0006, 0x0402, 0x0008)))
gp("commissioning, application info: cluster reports (none)", comm(0x07, 0x04, appinfo=bytes([0x08, 0x00])))
gp("commissioning, application info: switch info length 1", comm(0x07, 0x04, appinfo=bytes([0x10, 1, 0x02 | (1 << 4)])))
gp("commissioning, application info: switch info length 2", comm(0x07, 0x04, appinfo=bytes([0x10, 2, 0x01, 0x03])))
gp("commissioning, application info: switch info length 4 (extra octets skipped)",
   comm(0x07, 0x04, appinfo=bytes([0x10, 4, 0x01, 0x03, 0xaa, 0xbb])))
gp("commissioning, application info: switch info length 0", comm(0x07, 0x04, appinfo=bytes([0x10, 0])))
gp("commissioning, application info: all flags (ADCF, reserved bits)",
   comm(0x07, 0x04, appinfo=bytes([0x20 | 0xc0 | 0x04 | 0x01]) + struct.pack("<H", 0x115b) + bytes([1, 0x20])))
gp("commissioning, all device IDs of interest (temperature sensor)", comm(0x30, 0x00))
gp("commissioning, manufacturer specific device ID 0xfe", comm(0xfe, 0x00))
gp("commissioning, unknown device ID 0x77", comm(0x77, 0x00))
gp("commissioning with trailing data", comm(0x02, 0x00) + bytes([0x01, 0x02]))

# --- 6. Commissioning reply ---------------------------------------------------------
sect("commissioning reply")
gp("commissioning reply, no options", comm_reply(0x00), direction=1)
gp("commissioning reply, PAN ID present", comm_reply(0x01, pan=0x1234), direction=1)
gp("commissioning reply, plain security key present (learned)", comm_reply(0x02 | (3 << 3) | (4 << 5), key=K3), direction=1)
gp("commissioning reply, the same plain key again", comm_reply(0x02, key=K3), direction=1)
gp("commissioning reply, PAN ID and a second plain key", comm_reply(0x03 | (2 << 3), pan=0x4321, key=K4), direction=1)
gp("commissioning reply, encrypted key, security level 2, frame counter (filler: cannot decrypt)",
   comm_reply(0x06 | (2 << 3), key=bytes(range(0x90, 0xa0)), mic=b"\xd5" * 4, counter=0x55), direction=1)
gp("commissioning reply, encrypted key, security level 3, frame counter",
   comm_reply(0x06 | (3 << 3), key=bytes(range(0xa0, 0xb0)), mic=b"\xd6" * 4, counter=0x56), direction=1)
gp("commissioning reply, encrypted key, security level 1: no frame counter",
   comm_reply(0x06 | (1 << 3), key=bytes(range(0xb0, 0xc0)), mic=b"\xd7" * 4), direction=1)
gp("commissioning reply, encrypted key, security level 2 without a frame counter (warning)",
   comm_reply(0x06 | (2 << 3), key=bytes(range(0xc0, 0xd0)), mic=b"\xd8" * 4), direction=1)

# --- 7. Application description -----------------------------------------------------
sect("application description")
gp("application description, total 1 report, 1 report with 1 data point and 1 attribute (value, reported)",
   bytes([0xE4, 1, 1, 0x01, 0x00, 7, 0x00]) + struct.pack("<H", 0x0402) + struct.pack("<HBB", 0x0000, 0x29, 0x32) +
   bytes([0x05]) + struct.pack("<h", 2150))
gp("application description, timeout, server flag, manufacturer ID, 2 attributes, one without value",
   bytes([0xE4, 2, 1, 0x02, 0x01]) + struct.pack("<H", 600) + bytes([15]) + bytes([0x01 | 0x08 | 0x10]) +
   struct.pack("<HH", 0x0006, 0x115b) + struct.pack("<HBB", 0x0000, 0x10, 0x20) + bytes([0x01]) +
   struct.pack("<HBB", 0x4000, 0x10, 0x00) + bytes([0xff]))
gp("application description, 2 reports", bytes([0xE4, 2, 2]) +
   bytes([0x01, 0x00, 6, 0x00]) + struct.pack("<H", 0x0006) + struct.pack("<HBB", 0x0000, 0x10, 0x00) + bytes([0xaa]) +
   bytes([0x02, 0x00, 6, 0x00]) + struct.pack("<H", 0x0008) + struct.pack("<HBB", 0x0000, 0x20, 0x00) + bytes([0xbb]))

# --- 8. Payload lengths (fixes) ---------------------------------------------------
sect("payload lengths")
gp("payload of exactly 256 octets (compact attribute report; payload_len was uint8_t)",
   bytes([0xA8, 0x07]) + b"\x55" * 254)
gp("payload of 300 octets", bytes([0xA8, 0x08]) + b"\x66" * 298)
gp("payload of 255 octets", bytes([0xA8, 0x09]) + b"\x77" * 253)

# --- 9. Key ring with a few keys, then encrypted frames that try every key ---------------
sect("key ring with a few keys (the encrypted frames below try them all; none can decrypt)")
gp("encrypted, application ID 0, from ZGPD, with 4 keys in the ring", ENC, sec=3)
gp("encrypted, application ID 2 from ZGPP, with 4 keys in the ring", ENC, sec=3, app=2, direction=1)

# ---------------------------------------------------------------------------------------
# malformed capture: error paths, stress of the key ring cap, reproducers
# ---------------------------------------------------------------------------------------


def mg(label, payload, **kw):
    madd(label, wpan_gp(gpf(payload, **kw), seq=len(mframes) & 0xff))


madd("data frame with no payload (no Src ID payload): GP header only", wpan_gp(bytes([0x0c]) + struct.pack("<I", 0x11223344), seq=1))
madd("data frame, security level 2, header only", wpan_gp(gpf(b"", sec=2), seq=2))
mg("read attributes, record list length 255 (loop counter wrapped; reproducer)", bytes([0xF2, 0x00]) + struct.pack("<HB", 0x0000, 0xff))
mg("read attributes (0xF2), odd record list length 3: one identifier is read, the 2 octets left start a cluster record (reproducer of the fix)",
   bytes([0xF2, 0x00]) + struct.pack("<HBHH", 0x0000, 3, 0x0001, 0x0002))
mg("read attributes (0xF2), record list length 3 with one octet left", bytes([0xF2, 0x00]) + struct.pack("<HBHB", 0x0006, 3, 0x0001, 0xaa))
mg("read attributes, truncated record", bytes([0xF2, 0x00, 0x06]))
mg("commissioning truncated in the extended options", bytes([0xE0, 0x02, 0x80]))
mg("commissioning, key present but truncated", bytes([0xE0, 0x02, 0x80, 0x20]) + b"\x11" * 5)
mg("commissioning reply truncated PAN ID", bytes([0xF0, 0x01, 0x12]))
mg("application description truncated", bytes([0xE4, 1, 1, 0x01, 0x00, 20, 0x00, 0x02, 0x04]))
mg("write attributes, truncated value", bytes([0xF1, 0x00]) + struct.pack("<HB", 0x0006, 4) + struct.pack("<HB", 0x0000, 0x10))
mg("attribute reporting truncated", bytes([0xA0, 0x06]))
mg("multi cluster reporting truncated", bytes([0xA2, 0x06, 0x00, 0x00]))
mg("move color truncated", bytes([0x4A, 0x01]))
mg("ZCL tunneling truncated", bytes([0xA6, 0x04, 0x01]))
madd("GP frame with a 0 octet maintenance payload", wpan_gp(bytes([0x0d, 0x80, 0x00]), seq=3))
# key ring cap: 258 plain commissioning keys (256 are kept, the rest raise zbee_nwk_gp.keyring_full)
for n in range(1000, 1000 + 258):
    mg("commissioning with a plain GPD key #%d" % (n - 999), comm(0x30, 0x80, ext=0x20, key=keybytes(n)), src_id=0x20000000 + n)
mg("encrypted frame after the ring is full", ENC, sec=3)
mg("encrypted frame after the ring is full (application ID 2)", ENC, sec=3, app=2, direction=1)
for n in range(100):
    mg("encrypted frame #%d that tries all 256 keys (bounded cost)" % n, ENC, sec=3, app=(0, 2)[n & 1], direction=n & 1,
       counter=n)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "."
    write_pcap(os.path.join(outdir, "zbee-nwk-gp-coverage.pcap"), frames)
    write_pcap(os.path.join(outdir, "zbee-nwk-gp-coverage-malformed.pcap"), mframes)
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
    print("zbee-nwk-gp-coverage.pcap:", len(frames), "frames; malformed:", len(mframes))


main()
