#!/usr/bin/env python3
# Generates test/captures/btmesh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic Bluetooth Mesh coverage captures for packet-btmesh.c.
# Usage: mkbtmesh.py <outdir>
#
# Every frame is an Exported PDU (link type 252) for the dissector
# "btmesh.msg" holding one Mesh Network PDU, encrypted and obfuscated with
# the Mesh Profile sample keys (NetKey 7dd7..., AppKey 6396..., IV Index
# 0x12345678), a second network key, a device key and a Label UUID.  The
# matching "Mesh Keys", "Device Keys" and "Label UUIDs" tables are in cfg/
# (and given with -o uat:... in the tests).
import os
import struct
import sys
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

NETKEY = bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")
APPKEY = bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
IVINDEX = bytes.fromhex("12345678")
NETKEY2 = bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
APPKEY2 = bytes.fromhex("3216d1509884b533248541792b877f98")
IVINDEX2 = bytes.fromhex("00000001")
DEVKEY = bytes.fromhex("9d6dd0e96eb25dc19a40ed9914f8f03f")
DEVKEY_ADDR = 0x1201
LABEL_UUID = bytes.fromhex("0073e7e4d8b9440faf8415df4c56c0e1")

PROVISIONER = 0x0001
NODE = 0x1201
GROUP = 0xc001


def cmac(k, m):
    c = CMAC(algorithms.AES(k))
    c.update(m)
    return c.finalize()


def s1(m):
    return cmac(b"\0" * 16, m)


def k2(n, p=b"\0"):
    t = cmac(s1(b"smk2"), n)
    t1 = cmac(t, p + b"\x01")
    t2 = cmac(t, t1 + p + b"\x02")
    t3 = cmac(t, t2 + p + b"\x03")
    return t1[15] & 0x7f, t2, t3


def k4(a):
    return cmac(cmac(s1(b"smk4"), a), b"id6\x01")[15] & 0x3f


def virtual_address(label):
    h = cmac(s1(b"vtad"), label)
    return 0x8000 | ((h[14] & 0x3f) << 8) | h[15]


class Net:
    def __init__(self, netkey, appkey, ivindex):
        self.nid, self.enckey, self.privkey = k2(netkey)
        self.appkey = appkey
        self.aid = k4(appkey)
        self.ivindex = ivindex


NET1 = Net(NETKEY, APPKEY, IVINDEX)
NET2 = Net(NETKEY2, APPKEY2, IVINDEX2)
VADDR = virtual_address(LABEL_UUID)


def ccm(key, nonce, data, mic, aad=b""):
    return AESCCM(key, tag_length=mic).encrypt(nonce, data, aad or None)


def network_pdu(transport, seq, src, dst, ctl=0, ttl=5, net=NET1, badmic=False):
    hdr = bytes([(ctl << 7) | ttl]) + seq.to_bytes(3, "big") + src.to_bytes(2, "big")
    mic = 8 if ctl else 4
    nonce = b"\x00" + hdr + b"\0\0" + net.ivindex
    enc = ccm(net.enckey, nonce, dst.to_bytes(2, "big") + transport, mic)
    if badmic:
        enc = enc[:-1] + bytes([enc[-1] ^ 0xff])
    e = Cipher(algorithms.AES(net.privkey), modes.ECB()).encryptor()
    pecb = e.update(b"\0" * 5 + net.ivindex + enc[:7]) + e.finalize()
    obf = bytes(a ^ b for a, b in zip(hdr, pecb))
    return bytes([((net.ivindex[3] & 1) << 7) | net.nid]) + obf + enc


def access_encrypt(payload, seq_auth, src, dst, szmic, key, devkey, label, net):
    nonce = bytes([2 if devkey else 1, 0x80 if szmic else 0]) + \
        seq_auth.to_bytes(3, "big") + src.to_bytes(2, "big") + \
        dst.to_bytes(2, "big") + net.ivindex
    return ccm(key, nonce, payload, 8 if szmic else 4, label)


class Mesh:
    """Allocates sequence numbers and collects frames."""

    def __init__(self):
        self.seq = 0x000100
        self.frames = []
        self.notes = []

    def mark(self, text):
        self.notes.append((len(self.frames) + 1, text))

    def take(self, n=1):
        s = self.seq
        self.seq += n
        return s

    def add(self, pdu):
        self.frames.append(pdu)

    def access(self, payload, src=PROVISIONER, dst=NODE, devkey=False,
               label=None, net=NET1, szmic=0, seg=None, order=None,
               seq=None, ttl=5):
        """An access message, segmented when it does not fit in one
        unsegmented Lower Transport PDU (11 octets of payload)."""
        if seg is None:
            seg = len(payload) > 11 or szmic
        key = DEVKEY if devkey else net.appkey
        akf_aid = 0 if devkey else (0x40 | net.aid)
        if seq is None:
            seq = self.take(1 if not seg else (len(payload) + (8 if szmic else 4) + 11) // 12)
        up = access_encrypt(payload, seq, src, dst, szmic, key, devkey, label or b"", net)
        if not seg:
            self.add(network_pdu(bytes([akf_aid]) + up, seq, src, dst, ttl=ttl, net=net))
            return
        segs = [up[i:i + 12] for i in range(0, len(up), 12)]
        segn = len(segs) - 1
        order = order if order is not None else list(range(len(segs)))
        for k, sego in enumerate(order):
            hdr = (szmic << 23) | ((seq & 0x1fff) << 10) | (sego << 5) | segn
            tp = bytes([0x80 | akf_aid]) + hdr.to_bytes(3, "big") + segs[sego]
            self.add(network_pdu(tp, seq + k, src, dst, ttl=ttl, net=net))

    def control(self, opcode, params, src=0x0005, dst=PROVISIONER, seg=False, order=None):
        if not seg:
            self.add(network_pdu(bytes([opcode]) + params, self.take(), src, dst, ctl=1))
            return
        segs = [params[i:i + 8] for i in range(0, len(params), 8)] or [b""]
        segn = len(segs) - 1
        seq = self.take(len(segs))
        order = order if order is not None else list(range(len(segs)))
        for k, sego in enumerate(order):
            hdr = ((seq & 0x1fff) << 10) | (sego << 5) | segn
            tp = bytes([0x80 | opcode]) + hdr.to_bytes(3, "big") + segs[sego]
            self.add(network_pdu(tp, seq + k, src, dst, ctl=1))


def opbytes(op):
    return op.to_bytes(1 if op < 0x80 else 2, "big")


def le16(v):
    return struct.pack("<H", v & 0xffff)


def le24(v):
    return struct.pack("<I", v & 0xffffff)[:3]


def mpid_a(pid, length):
    """Marshalled Property ID, format A (length 1..16 octets)."""
    return (((pid & 0x7ff) << 5) | ((length - 1) << 1)).to_bytes(2, "little")


def mpid_b(pid, length):
    """Marshalled Property ID, format B (length 1..127, 0 coded as 0x7f)."""
    code = 0x7f if length == 0 else length - 1
    return bytes([(code << 1) | 1]) + le16(pid)


# Properties with a decoded characteristic (property id, value length, values)
PROPS = [
    (0x0071, 1, [0x14, 0x7f]),                  # Temperature 8
    (0x000d, 3, [1234, 0xffffff]),              # Energy
    (0x0029, 1, [50, 0xff, 0xc9]),              # Percentage 8
    (0x002b, 3, [12345, 0xffffff]),             # Illuminance
    (0x002e, 2, [0x8000]),                      # Perceived Lightness
    (0x0032, 4, [0x3f800000]),                  # Coefficient (float)
    (0x0036, 3, [1500, 0xffffff]),              # Time Millisecond 24
    (0x004c, 2, [7, 0xffff]),                   # Count 16
    (0x0075, 2, [2150, 0x8000, 0x9000]),        # Temperature
    (0x004d, 1, [0, 1, 2]),                     # Boolean
    (0x0057, 2, [250, 0xffff]),                 # Electric Current
    (0x0068, 2, [30, 0xffff]),                  # Time Second 16
    (0x0001, 3, [0x7f0a32, 0x10f5ff]),          # Temperature 8 In A Period Of Day
    (0x0060, 5, [0x00012c0a32]),                # Energy In A Period Of Day
    (0x0061, 5, [0x3210001234]),                # Rel. Runtime In A Generic Level Range
    (0x0062, 7, [0x3200010000ffff]),            # Rel. Exposure Time In An Illuminance Range
    (0x0064, 5, [0x320a000500]),                # Rel. Runtime In A Device Operating Temp. Range
    (0x0065, 5, [0x3200640032]),                # Rel. Runtime In An Input Current Range
    (0x000c, 3, [0x123456]),                    # Device Date Of Manufacture (no field)
    (0x000e, 8, [0x3132333435363738]),          # Fixed String 8 (no field)
]


def val(v, n):
    return (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")


def build_main(m):
    # ---- Network and lower transport ------------------------------------
    m.mark("Transport control messages, unsegmented: Friend Poll .. Heartbeat, opcode 0x0b, 0x7f")
    m.control(0x01, b"\x01")                                    # Friend Poll
    m.control(0x02, b"\x03" + IVINDEX + b"\x01")                # Friend Update
    m.control(0x03, b"\x4b\x0a\x00\x10\x00\x00\x00\x02\x05", src=0x0010, dst=0xffff)   # Friend Request
    m.control(0x04, b"\xff\x10\x08\xc4\x00\x01")                # Friend Offer
    m.control(0x05, b"\x00\x10\x00\x05")                        # Friend Clear
    m.control(0x06, b"\x00\x10\x00\x05")                        # Friend Clear Confirm
    m.control(0x07, b"\x01" + struct.pack(">HH", 0xc001, 0xc002))   # Subscription List Add
    m.control(0x08, b"\x02" + struct.pack(">H", 0xc001))        # Subscription List Remove
    m.control(0x09, b"\x02")                                    # Subscription List Confirm
    m.control(0x0a, b"\x05\x00\x0f", src=NODE, dst=GROUP)       # Heartbeat
    m.control(0x0b, b"\x01\x02\x03")                            # unknown opcode
    m.control(0x7f, b"\x00")
    m.mark("Segment Acknowledgment (OBO 0 and 1)")
    m.control(0x00, struct.pack(">HI", (0x0123 << 2), 0x00000007), src=NODE, dst=PROVISIONER)
    m.control(0x00, struct.pack(">HI", 0x8000 | (0x0456 << 2), 0x00000003), src=0x0010, dst=PROVISIONER)
    m.mark("Segmented control: one segment; Friend Request in order; 3 segments last first; Heartbeat reversed; SeqZero wrap")
    m.control(0x01, b"\x00", seg=True)
    m.control(0x03, b"\x4b\x0a\x00\x10\x00\x00\x00\x02\x05", src=0x0011, dst=0xffff, seg=True)
    m.control(0x0b, bytes(range(1, 20)), seg=True, order=[2, 0, 1])
    m.control(0x0a, b"\x05\x00\x0f" + b"\x00" * 6, src=NODE, dst=GROUP, seg=True, order=[1, 0])
    m.seq |= 0x1fff                                               # SeqZero 0x1fff, second segment wraps
    m.control(0x03, b"\x4b\x0a\x00\x10\x00\x00\x00\x02\x05", src=0x0012, dst=0xffff, seg=True)

    m.mark("Access messages to group, unicast and virtual addresses, device key (to and from the node), second network key")
    m.access(bytes([0x82, 0x01]), dst=GROUP)                      # Generic OnOff Get
    m.access(bytes([0x82, 0x04, 0x01]), src=NODE, dst=PROVISIONER)  # Generic OnOff Status
    m.access(bytes([0x82, 0x02, 0x01, 0x05]), dst=VADDR, label=LABEL_UUID)  # OnOff Set to the virtual address
    m.access(bytes([0x80, 0x08, 0x00]), devkey=True)                    # Config Composition Data Get, to the node
    m.access(bytes([0x80, 0x0e, 0x07]), src=NODE, devkey=True, dst=PROVISIONER)  # Default TTL Status from the node
    m.access(bytes([0x80, 0x0c]), devkey=True, dst=VADDR, label=LABEL_UUID, src=NODE)  # device key, virtual
    m.access(bytes([0x82, 0x01]), net=NET2, dst=GROUP)
    m.access(bytes([0x82, 0x01]), net=NET2, dst=GROUP, src=0x0002)
    m.access(bytes([0x82, 0x01]), dst=0x0000)                     # unassigned destination
    m.mark("Undecryptable: unknown NID, wrong NetMIC, unknown AID, wrong TransMIC, no device key, too short")
    other = Net(bytes(16), APPKEY, IVINDEX)
    m.add(network_pdu(b"\x40" + bytes(10), m.take(), PROVISIONER, NODE, net=other))
    m.add(network_pdu(bytes([0x40 | NET1.aid]) + bytes(10), m.take(), PROVISIONER, NODE, badmic=True))
    m.add(network_pdu(bytes([0x40 | ((NET1.aid + 1) & 0x3f)]) + bytes(10), m.take(), PROVISIONER, NODE))
    m.add(network_pdu(bytes([0x40 | NET1.aid]) + bytes(10), m.take(), PROVISIONER, NODE))
    m.add(network_pdu(b"\x00" + bytes(10), m.take(), 0x0003, 0x0004))
    m.add(network_pdu(b"\x00" + bytes(10), m.take(), PROVISIONER, VADDR))
    m.add(bytes([NET1.nid]) + bytes(16))                          # too short to deobfuscate

    m.mark("Segmented access: Composition Data Status (3 segments), out of order, SZMIC, SegN 0 with SZMIC, SeqZero wrap")
    comp = bytes([0x02, 0x00]) + bytes.fromhex("5900 0100 0200 0a00 0300") + \
        bytes.fromhex("0000 04 01 0000 0010 0210 0310 5900 3412")
    m.access(comp, src=NODE, dst=PROVISIONER, devkey=True)
    m.access(comp, src=NODE, dst=PROVISIONER, devkey=True, order=[2, 0, 1])
    m.access(comp, src=NODE, dst=PROVISIONER, devkey=True, order=[1, 2, 0])
    m.access(comp, src=NODE, dst=PROVISIONER, devkey=True, szmic=1)
    m.access(bytes([0x82, 0x01]), szmic=1)                        # one segment, 64-bit TransMIC
    m.access(bytes([0x82, 0x01]), seg=True)                       # one segment, 32-bit TransMIC
    m.seq |= 0x1fff                                               # SeqAuth ends in 0x1fff
    m.access(comp, src=NODE, dst=PROVISIONER, devkey=True)        # later segments wrap SeqZero
    m.mark("Vendor opcode, unknown one- and two-octet opcodes with parameters")
    m.access(bytes([0xc1]) + le16(0x0059) + b"\x01\x02\x03")
    m.access(bytes([0x7e, 0x01, 0x02]))
    m.access(bytes([0xbf, 0xff, 0x01]))

    # ---- Model layer: every opcode with valid parameter lengths ---------
    m.mark("Model layer: every SIG model opcode the dissector knows")
    for op, variants in MODEL_TABLE:
        for fill, n in variants:
            m.access(opbytes(op) + bytes([fill]) * n)

    # ---- Value specific branches ----------------------------------------
    m.mark("Hand-made model messages: transmit counts, publication, app lists, health, battery, location")
    # Config Network Transmit Set / Relay Set: count 0, 1, more
    for v in (0x00, 0x09, 0x23):
        m.access(bytes([0x80, 0x25, v]), devkey=True)
        m.access(bytes([0x80, 0x27, 0x01, v]), devkey=True)
    # Config Model Publication Set: periods in all resolutions, retransmit
    for period, retr in ((0x05, 0x00), (0x45, 0x09), (0x85, 0x2b), (0xc5, 0x00)):
        m.access(bytes([0x03]) + le16(NODE) + le16(GROUP) + le16(0x1001) +
                 bytes([5, period, retr]) + le16(0x1000), devkey=True)
    m.access(bytes([0x03]) + le16(NODE) + le16(GROUP) + le16(0x0000) +
             bytes([5, 0x01, 0x00]) + le16(0x0059) + le16(0x0001), devkey=True)
    # Config SIG / Vendor Model App List with 2 and 1 key indexes
    m.access(bytes([0x80, 0x4c, 0x00]) + le16(NODE) + le16(0x1000) + b"\x01\x20\x00\x03\x00", src=NODE, dst=PROVISIONER, devkey=True)
    m.access(bytes([0x80, 0x4e, 0x00]) + le16(NODE) + le16(0x0059) + le16(0x0001) + b"\x01\x20\x00\x03\x00", src=NODE, dst=PROVISIONER, devkey=True)
    # Health Fault Status, Battery Status
    m.access(bytes([0x05, 0x00]) + le16(0x0059) + b"\x01\x02\x03", src=NODE, dst=PROVISIONER)
    for lvl, t in ((0x32, 0x000010), (0xff, 0xffffff), (0x80, 0x001000)):
        m.access(bytes([0x82, 0x24, lvl]) + le24(t) + le24(t) + b"\x55")
    # Generic Location Global / Local Status: not configured and limits
    for lat, lon, alt in ((0x80000000, 0x80000000, 0x7fff), (0x12345678, 0x12345678, 0x7ffe), (0x10, 0x10, 100)):
        m.access(bytes([0x40]) + struct.pack("<IIH", lat, lon, alt))
    for n, e, a, fl in ((0x8000, 0x8000, 0x7fff, 0x00), (100, 200, 0x7ffe, 0xfc), (1, 1, 1, 0xfd),
                        (1, 1, 1, 0xfe), (1, 1, 1, 0xff), (1, 1, 1, 0x20)):
        m.access(bytes([0x82, 0x27]) + struct.pack("<hhhB", n if n < 0x8000 else n - 0x10000, e if e < 0x8000 else e - 0x10000, a, fl) + le16(0x0123))
    # Time Status / Time Set (TAI 0 and leap second eras), Time Zone
    m.mark("Time Status with TAI seconds 0 and in every leap second era (btmesh_tai_leak.py), Time Set, Time Zone Status")
    for tai in (0, 100000000, 200000000, 300000000, 400000000, 500000000, 700000000):
        m.access(bytes([0x5d]) + val(tai, 5) + bytes([0x80, 0x10, 0x01, 0x25, 0x40]), src=NODE, dst=PROVISIONER)
    m.access(bytes([0x5c]) + val(700003600, 5) + bytes([0x00, 0x00, 0x01, 0x25, 0x40]))
    for tz in (0x40, 0x48, 0x20):
        m.access(bytes([0x82, 0x3d, tz, tz]) + val(600000000, 5))
    m.mark("Scheduler Action Set, Sensor Descriptor Status, Sensor Status with every decoded property")
    # Scheduler Action Set: every special year/day/hour/minute/second/action
    for year, mon, day, hour, mi, sec, act in (
            (0x64, 0x001, 0, 24, 0x3c, 0x3c, 0), (0x10, 0xfff, 31, 25, 0x3d, 0x3d, 1),
            (0x7f, 0x800, 5, 30, 0x3e, 0x3e, 2), (5, 0, 1, 1, 0x3f, 0x3f, 0xf),
            (5, 0x041, 1, 1, 10, 20, 5)):
        v = (2 & 0xf) | (year << 4) | (mon << 11) | (day << 23) | (hour << 28) | \
            (mi << 33) | (sec << 39) | (0x55 << 45) | (act << 52)
        m.access(bytes([0x60]) + val(v, 7) + bytes([0x00]) + le16(1))
    # Sensor Descriptor Status: property only, two descriptors
    m.access(bytes([0x51]) + le16(0x004d))
    m.access(bytes([0x51]) + le16(0x004d) + le24(0) + bytes([1, 0, 0]) +
             le16(0x0057) + le24(0x123456) + bytes([2, 10, 100]) +
             le16(0x0068) + le24(0x001001) + bytes([3, 70, 0xff]) +
             le16(0x004c) + le24(0x001001) + bytes([3, 150, 200]))
    # Sensor Status: one value per decoded property, format A and B
    body = b""
    for pid, n, values in PROPS:
        for v in values:
            body += mpid_b(pid, n) + val(v, n)
    half = len(body) // 2
    while body[half] & 1 == 0 or body[half + 1:half + 3] not in [le16(p[0]) for p in PROPS]:
        half += 1
    m.access(bytes([0x52]) + body[:half], src=NODE, dst=PROVISIONER)
    m.access(bytes([0x52]) + body[half:], src=NODE, dst=PROVISIONER)
    m.access(bytes([0x52]) + mpid_a(0x0075, 2) + le16(2150) + mpid_a(0x07ff, 3) + b"\x01\x02\x03" +
             mpid_b(0x07fe, 0) + mpid_b(0x07fd, 2) + b"\x01\x02", src=NODE, dst=PROVISIONER)
    # btmesh_mpid_len.py: two format A MPIDs of unknown properties, 2 and 1 octets
    m.mark("Reproducer btmesh_mpid_len.py: Sensor Status with 1-based MPID lengths")
    m.access(bytes([0x52]) + mpid_a(0x7ff, 2) + b"\x11\x22" + mpid_a(0x7fe, 1) + b"\x33", src=NODE, dst=PROVISIONER)
    m.mark("Generic and sensor property messages")
    # Generic property status / set with decoded, undecoded and unknown properties
    for pid, n, values in PROPS[:12:3] + [(0x07ff, 3, [0x010203])]:
        v = val(values[0], n)
        m.access(bytes([0x46]) + le16(pid) + b"\x01" + v)
        m.access(bytes([0x48]) + le16(pid) + b"\x03" + v)
        m.access(bytes([0x4a]) + le16(pid) + b"\x02" + v)
        m.access(bytes([0x4c]) + le16(pid) + v)
        m.access(bytes([0x4e]) + le16(pid) + b"\x03" + v)
        m.access(bytes([0x5b]) + le16(0x004d) + le16(pid) + b"\x03" + v)
    for acc in (0, 1, 2, 3, 4):
        m.access(bytes([0x48]) + le16(0x004c) + bytes([acc]) + le16(5))
        m.access(bytes([0x44]) + le16(0x004c) + bytes([acc]))
        m.access(bytes([0x4e]) + le16(0x004c) + bytes([acc]) + le16(5))
        m.access(bytes([0x5b]) + le16(0x004d) + le16(0x004c) + bytes([acc]) + le16(5))
    # Sensor Cadence: property trigger with known and guessed lengths,
    # percentage trigger, unknown lengths
    for opc in (0x55, 0x56, 0x57):
        m.access(bytes([opc]) + le16(0x004c) + b"\x02" + le16(1) + le16(2) + b"\x05" + le16(10) + le16(20))
        m.access(bytes([opc]) + le16(0x07ff) + b"\x02" + b"\x01\x02\x03" * 4 + b"\x05")     # guessed 3
        m.access(bytes([opc]) + le16(0x07ff) + b"\x02" + b"\x01\x02\x03\x04")               # cannot guess
        m.access(bytes([opc]) + le16(0x004c) + b"\x83" + le16(100) + le16(200) + b"\x1b" + le16(10) + le16(20))
        m.access(bytes([opc]) + le16(0x07ff) + b"\x81" + le16(100) + le16(200) + b"\x05" + b"\x01\x02\x03" * 2 + b"\x04")
        m.access(bytes([opc]) + le16(0x07ff) + b"\x81" + le16(100) + le16(200) + b"\x05" + b"\x01\x02")
        m.access(bytes([opc]) + le16(0x004c) + b"\x10" + le16(1) + le16(2) + b"\x05" + le16(10) + le16(20))
    # Sensor Column / Series with simple, three value and unknown properties
    # (property, value length, value, length of the column (X) value)
    for pid, n, v, x in ((0x004c, 2, 7, 2), (0x0001, 3, 0x7f0a32, 1), (0x0060, 5, 0x00012c0a32, 1),
                         (0x0062, 7, 0x3200010000ffff, 3), (0x000c, 3, 0x123456, 2), (0x07ff, 3, 0x010203, 3)):
        v = val(v, n)
        m.access(bytes([0x82, 0x32]) + le16(pid) + v[:x])
        m.access(bytes([0x53]) + le16(pid) + v)
        m.access(bytes([0x82, 0x33]) + le16(pid))
        m.access(bytes([0x82, 0x33]) + le16(pid) + v[:x] + v[:x])
        m.access(bytes([0x54]) + le16(pid) + v + v)


def build_malformed(m):
    m.mark("Short upper transport PDUs (btmesh_neg_enclen.py): SegN 0 with 1..3 octets")
    for n in (1, 2, 3):
        seq = m.take()
        hdr = ((seq & 0x1fff) << 10)
        tp = bytes([0xc0 | NET1.aid]) + hdr.to_bytes(3, "big") + b"\xaa" * n
        m.add(network_pdu(tp, seq, 0x0003, NODE))
    m.mark("Unsegmented access with only a TransMIC")
    seq = m.take()
    m.add(network_pdu(bytes([0x40 | NET1.aid]) + b"\x01\x02\x03\x04", seq, 0x0003, NODE))
    m.mark("Too short network PDUs")
    m.add(bytes([NET1.nid]) + bytes(10))
    m.add(bytes([NET1.nid]))
    m.mark("Model messages with trailing or missing octets")
    m.access(bytes([0x82, 0x01, 0x00, 0x01]))
    m.access(bytes([0x82, 0x02]))
    m.access(bytes([0x52]) + mpid_a(0x0075, 4) + b"\x01")
    m.access(bytes([0x02, 0x00]) + bytes(10) + b"\x00\x00\x05\x05")
    m.access(bytes([0x82, 0x32]) + le16(0x0062) + b"\x01")
    m.mark("Lone segments of messages that never complete")
    m.control(0x0a, b"\x05\x00\x0f" + b"\x00" * 6, seg=True, order=[0])
    m.access(bytes(30), order=[1])


def exported_pdu(proto, payload):
    name = proto.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack(">HH", 12, len(name) + pad) + name + b"\0" * pad
    tags += struct.pack(">HH", 0, 0)
    return tags + payload


def write_pcap(fn, frames):
    with open(fn, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            fr = exported_pdu("btmesh.msg", fr)
            f.write(struct.pack("<IIII", 1700000000 + i // 10, (i % 10) * 100000, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    for name, build in (("btmesh-coverage.pcap", build_main),
                        ("btmesh-coverage-malformed.pcap", build_malformed)):
        m = Mesh()
        build(m)
        write_pcap(os.path.join(out, name), m.frames)
        print(name, len(m.frames), "frames")
        for n, text in m.notes:
            print("  %4d %s" % (n, text))


# Parameters for every opcode case of dissect_btmesh_model_layer():
# (opcode, [(fill octet, number of parameter octets), ...]).  Each entry
# is an access message of the opcode followed by that many fill octets.
# The lengths are the ones that decode without an exception or trailing
# octets: the shortest one or three with fill 0x01 and, for models whose
# fields have value dependent labels (light, time, scheduler, ...), the
# shortest one with fills 0x00, 0xff, 0x7f and 0x3d.  They were found by
# dissecting every length from 0 to 40 (see README.md).
MODEL_TABLE = [
    (0x0000, [(1, 19)]),  # CONFIG_APPKEY_ADD
    (0x0001, [(1, 19)]),  # CONFIG_APPKEY_UPDATE
    (0x0002, [(1, 11), (1, 21), (1, 31)]),  # CONFIG_COMPOSITION_DATA_STATUS
    (0x0003, [(1, 11), (1, 13), (0, 11), (255, 11), (127, 11), (61, 11)]),  # CONFIG_MODEL_PUBLICATION_SET
    (0x0004, [(1, 3), (1, 4), (1, 5)]),  # HEALTH_CURRENT_STATUS
    (0x0005, [(1, 3), (1, 4), (1, 5)]),  # HEALTH_FAULT_STATUS
    (0x0006, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # CONFIG_HEARTBEAT_PUBLICATION_STATUS
    (0x8000, [(1, 3)]),  # CONFIG_APPKEY_DELETE
    (0x8001, [(1, 2)]),  # CONFIG_APPKEY_GET
    (0x8002, [(1, 3), (1, 5), (1, 6)]),  # CONFIG_APPKEY_LIST
    (0x8003, [(1, 4)]),  # CONFIG_APPKEY_STATUS
    (0x8004, [(1, 0)]),  # HEALTH_ATTENTION_GET
    (0x8005, [(1, 1)]),  # HEALTH_ATTENTION_SET
    (0x8006, [(1, 1)]),  # HEALTH_ATTENTION_SET_UNACKNOWLEDGED
    (0x8007, [(1, 1)]),  # HEALTH_ATTENTION_STATUS
    (0x8008, [(1, 1)]),  # CONFIG_COMPOSITION_DATA_GET
    (0x8009, [(1, 0)]),  # CONFIG_BEACON_GET
    (0x800a, [(1, 1)]),  # CONFIG_BEACON_SET
    (0x800b, [(1, 1)]),  # CONFIG_BEACON_STATUS
    (0x800c, [(1, 0)]),  # CONFIG_DEFAULT_TTL_GET
    (0x800d, [(1, 1)]),  # CONFIG_DEFAULT_TTL_SET
    (0x800e, [(1, 1)]),  # CONFIG_DEFAULT_TTL_STATUS
    (0x800f, [(1, 0)]),  # CONFIG_FRIEND_GET
    (0x8010, [(1, 1)]),  # CONFIG_FRIEND_SET
    (0x8011, [(1, 1)]),  # CONFIG_FRIEND_STATUS
    (0x8012, [(1, 0)]),  # CONFIG_GATT_PROXY_GET
    (0x8013, [(1, 1)]),  # CONFIG_GATT_PROXY_SET
    (0x8014, [(1, 1)]),  # CONFIG_GATT_PROXY_STATUS
    (0x8015, [(1, 2)]),  # CONFIG_KEY_REFRESH_PHASE_GET
    (0x8016, [(1, 3)]),  # CONFIG_KEY_REFRESH_PHASE_SET
    (0x8017, [(1, 4)]),  # CONFIG_KEY_REFRESH_PHASE_STATUS
    (0x8018, [(1, 4), (1, 6), (0, 4), (255, 4), (127, 4), (61, 4)]),  # CONFIG_MODEL_PUBLICATION_GET
    (0x8019, [(1, 12), (1, 14), (0, 12), (255, 12), (127, 12), (61, 12)]),  # CONFIG_MODEL_PUBLICATION_STATUS
    (0x801a, [(1, 25), (1, 27), (0, 25), (255, 25), (127, 25), (61, 25)]),  # CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET
    (0x801b, [(1, 6), (1, 8)]),  # CONFIG_MODEL_SUBSCRIPTION_ADD
    (0x801c, [(1, 6), (1, 8)]),  # CONFIG_MODEL_SUBSCRIPTION_DELETE
    (0x801d, [(1, 4), (1, 6)]),  # CONFIG_MODEL_SUBSCRIPTION_DELETE_ALL
    (0x801e, [(1, 6), (1, 8)]),  # CONFIG_MODEL_SUBSCRIPTION_OVERWRITE
    (0x801f, [(1, 7), (1, 9)]),  # CONFIG_MODEL_SUBSCRIPTION_STATUS
    (0x8020, [(1, 20), (1, 22)]),  # CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD
    (0x8021, [(1, 20), (1, 22)]),  # CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE
    (0x8022, [(1, 20), (1, 22)]),  # CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE
    (0x8023, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # CONFIG_NETWORK_TRANSMIT_GET
    (0x8024, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # CONFIG_NETWORK_TRANSMIT_SET
    (0x8025, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # CONFIG_NETWORK_TRANSMIT_STATUS
    (0x8026, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # CONFIG_RELAY_GET
    (0x8027, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # CONFIG_RELAY_SET
    (0x8028, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # CONFIG_RELAY_STATUS
    (0x8029, [(1, 4)]),  # CONFIG_SIG_MODEL_SUBSCRIPTION_GET
    (0x802a, [(1, 5), (1, 7), (1, 9)]),  # CONFIG_SIG_MODEL_SUBSCRIPTION_LIST
    (0x802b, [(1, 6)]),  # CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET
    (0x802c, [(1, 7), (1, 9), (1, 11)]),  # CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST
    (0x802d, [(1, 2)]),  # CONFIG_LOW_POWER_NODE_POLLTIMEOUT_GET
    (0x802e, [(1, 5)]),  # CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS
    (0x802f, [(1, 2)]),  # HEALTH_FAULT_CLEAR
    (0x8030, [(1, 2)]),  # HEALTH_FAULT_CLEAR_UNACKNOWLEDGED
    (0x8031, [(1, 2)]),  # HEALTH_FAULT_GET
    (0x8032, [(1, 3)]),  # HEALTH_FAULT_TEST
    (0x8033, [(1, 3)]),  # HEALTH_FAULT_TEST_UNACKNOWLEDGED
    (0x8034, [(1, 0)]),  # HEALTH_PERIOD_GET
    (0x8035, [(1, 1)]),  # HEALTH_PERIOD_SET
    (0x8036, [(1, 1)]),  # HEALTH_PERIOD_SET_UNACKNOWLEDGED
    (0x8037, [(1, 1)]),  # HEALTH_PERIOD_STATUS
    (0x8038, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # CONFIG_HEARTBEAT_PUBLICATION_GET
    (0x8039, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # CONFIG_HEARTBEAT_PUBLICATION_SET
    (0x803a, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # CONFIG_HEARTBEAT_SUBSCRIPTION_GET
    (0x803b, [(1, 5), (0, 5), (255, 5), (127, 5), (61, 5)]),  # CONFIG_HEARTBEAT_SUBSCRIPTION_SET
    (0x803c, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS
    (0x803d, [(1, 6), (1, 8)]),  # CONFIG_MODEL_APP_BIND
    (0x803e, [(1, 7), (1, 9)]),  # CONFIG_MODEL_APP_STATUS
    (0x803f, [(1, 6), (1, 8)]),  # CONFIG_MODEL_APP_UNBIND
    (0x8040, [(1, 18)]),  # CONFIG_NETKEY_ADD
    (0x8041, [(1, 2)]),  # CONFIG_NETKEY_DELETE
    (0x8042, [(1, 0)]),  # CONFIG_NETKEY_GET
    (0x8043, [(1, 0), (1, 2), (1, 3)]),  # CONFIG_NETKEY_LIST
    (0x8044, [(1, 3)]),  # CONFIG_NETKEY_STATUS
    (0x8045, [(1, 18)]),  # CONFIG_NETKEY_UPDATE
    (0x8046, [(1, 2)]),  # CONFIG_NODE_IDENTITY_GET
    (0x8047, [(1, 3)]),  # CONFIG_NODE_IDENTITY_SET
    (0x8048, [(1, 4)]),  # CONFIG_NODE_IDENTITY_STATUS
    (0x8049, [(1, 0)]),  # CONFIG_NODE_RESET
    (0x804a, [(1, 0)]),  # CONFIG_NODE_RESET_STATUS
    (0x804b, [(1, 4)]),  # CONFIG_SIG_MODEL_APP_GET
    (0x804c, [(1, 5), (1, 7), (1, 8)]),  # CONFIG_SIG_MODEL_APP_LIST
    (0x804d, [(1, 4), (1, 5), (1, 6)]),  # CONFIG_VENDOR_MODEL_APP_GET
    (0x804e, [(1, 5), (1, 6), (1, 7)]),  # CONFIG_VENDOR_MODEL_APP_LIST
    (0x0040, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # GENERIC_LOCATION_GLOBAL_STATUS
    (0x0041, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # GENERIC_LOCATION_GLOBAL_SET
    (0x0042, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # GENERIC_LOCATION_GLOBAL_SET_UNACKNOWLEDGED
    (0x8201, [(1, 0)]),  # GENERIC_ONOFF_GET
    (0x8202, [(1, 2), (1, 4)]),  # GENERIC_ONOFF_SET
    (0x8203, [(1, 2), (1, 4)]),  # GENERIC_ONOFF_SET_UNACKNOWLEDGED
    (0x8204, [(1, 1), (1, 3)]),  # GENERIC_ONOFF_STATUS
    (0x8205, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_LEVEL_GET
    (0x8206, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # GENERIC_LEVEL_SET
    (0x8207, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # GENERIC_LEVEL_SET_UNACKNOWLEDGED
    (0x8208, [(1, 2), (1, 5), (0, 2), (255, 2), (127, 2), (61, 2)]),  # GENERIC_LEVEL_STATUS
    (0x8209, [(1, 5), (1, 7)]),  # GENERIC_DELTA_SET
    (0x820a, [(1, 5), (1, 7)]),  # GENERIC_DELTA_SET_UNACKNOWLEDGED
    (0x820b, [(1, 3), (1, 5)]),  # GENERIC_MOVE_SET
    (0x820c, [(1, 3), (1, 5)]),  # GENERIC_MOVE_SET_UNACKNOWLEDGED
    (0x820d, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_DEFAULT_TRANSITION_TIME_GET
    (0x820e, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # GENERIC_DEFAULT_TRANSITION_TIME_SET
    (0x820f, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # GENERIC_DEFAULT_TRANSITION_TIME_SET_UNACKNOWLEDGED
    (0x8210, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # GENERIC_DEFAULT_TRANSITION_TIME_STATUS
    (0x8211, [(1, 0)]),  # GENERIC_ONPOWERUP_GET
    (0x8212, [(1, 1)]),  # GENERIC_ONPOWERUP_STATUS
    (0x8213, [(1, 1)]),  # GENERIC_ONPOWERUP_SET
    (0x8214, [(1, 1)]),  # GENERIC_ONPOWERUP_SET_UNACKNOWLEDGED
    (0x8215, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_POWER_LEVEL_GET
    (0x8216, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # GENERIC_POWER_LEVEL_SET
    (0x8217, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # GENERIC_POWER_LEVEL_SET_UNACKNOWLEDGED
    (0x8218, [(1, 2), (1, 5), (0, 2), (255, 2), (127, 2), (61, 2)]),  # GENERIC_POWER_LEVEL_STATUS
    (0x8219, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_POWER_LAST_GET
    (0x821a, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # GENERIC_POWER_LAST_STATUS
    (0x821b, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_POWER_DEFAULT_GET
    (0x821c, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # GENERIC_POWER_DEFAULT_STATUS
    (0x821d, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_POWER_RANGE_GET
    (0x821e, [(1, 5), (0, 5), (255, 5), (127, 5), (61, 5)]),  # GENERIC_POWER_RANGE_STATUS
    (0x821f, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # GENERIC_POWER_DEFAULT_SET
    (0x8220, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # GENERIC_POWER_DEFAULT_SET_UNACKNOWLEDGED
    (0x8221, [(1, 4), (0, 4), (255, 4), (127, 4), (61, 4)]),  # GENERIC_POWER_RANGE_SET
    (0x8222, [(1, 4), (0, 4), (255, 4), (127, 4), (61, 4)]),  # GENERIC_POWER_RANGE_SET_UNACKNOWLEDGED
    (0x8223, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_BATTERY_GET
    (0x8224, [(1, 8), (0, 8), (255, 8), (127, 8), (61, 8)]),  # GENERIC_BATTERY_STATUS
    (0x8225, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_LOCATION_GLOBAL_GET
    (0x8226, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # GENERIC_LOCATION_LOCAL_GET
    (0x8227, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # GENERIC_LOCATION_LOCAL_STATUS
    (0x8228, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # GENERIC_LOCATION_LOCAL_SET
    (0x8229, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # GENERIC_LOCATION_LOCAL_SET_UNACKNOWLEDGED
    (0x005e, [(1, 3), (1, 6)]),  # SCENE_STATUS
    (0x8241, [(1, 0)]),  # SCENE_GET
    (0x8242, [(1, 3), (1, 5)]),  # SCENE_RECALL
    (0x8243, [(1, 3), (1, 5)]),  # SCENE_RECALL_UNACKNOWLEDGED
    (0x8244, [(1, 0)]),  # SCENE_REGISTER_GET
    (0x8245, [(1, 3), (1, 5), (1, 7)]),  # SCENE_REGISTER_STATUS
    (0x8246, [(1, 2)]),  # SCENE_STORE
    (0x8247, [(1, 2)]),  # SCENE_STORE_UNACKNOWLEDGED
    (0x829e, [(1, 2)]),  # SCENE_DELETE
    (0x829f, [(1, 2)]),  # SCENE_DELETE_UNACKNOWLEDGED
    (0x005c, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # TIME_SET
    (0x005d, [(1, 5), (1, 10), (0, 5), (255, 5), (127, 5), (61, 5)]),  # TIME_STATUS
    (0x005f, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # SCHEDULER_ACTION_STATUS
    (0x0060, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # SCHEDULER_ACTION_SET
    (0x0061, [(1, 10), (0, 10), (255, 10), (127, 10), (61, 10)]),  # SCHEDULER_ACTION_SET_UNACKNOWLEDGED
    (0x8237, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # TIME_GET
    (0x8238, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # TIME_ROLE_GET
    (0x8239, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # TIME_ROLE_SET
    (0x823a, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # TIME_ROLE_STATUS
    (0x823b, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # TIME_ZONE_GET
    (0x823c, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # TIME_ZONE_SET
    (0x823d, [(1, 7), (0, 7), (255, 7), (127, 7), (61, 7)]),  # TIME_ZONE_STATUS
    (0x823e, [(1, 0)]),  # TAI_UTC_DELTA_GET
    (0x823f, [(1, 7)]),  # TAI_UTC_DELTA_SET
    (0x8240, [(1, 9)]),  # TAI_UTC_DELTA_STATUS
    (0x8248, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # SCHEDULER_ACTION_GET
    (0x8249, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # SCHEDULER_GET
    (0x824a, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # SCHEDULER_STATUS
    (0x0062, [(1, 2), (1, 3), (1, 4), (0, 2), (255, 4), (127, 2), (61, 2)]),  # LIGHT_LC_PROPERTY_SET
    (0x0063, [(1, 2), (1, 3), (1, 4), (0, 2), (255, 4), (127, 2), (61, 2)]),  # LIGHT_LC_PROPERTY_SET_UNACKNOWLEDGED
    (0x0064, [(1, 2), (1, 3), (1, 4), (0, 2), (255, 4), (127, 2), (61, 2)]),  # LIGHT_LC_PROPERTY_STATUS
    (0x824b, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LIGHTNESS_GET
    (0x824c, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_LIGHTNESS_SET
    (0x824d, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_LIGHTNESS_SET_UNACKNOWLEDGED
    (0x824e, [(1, 2), (1, 5), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LIGHTNESS_STATUS
    (0x824f, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LIGHTNESS_LINEAR_GET
    (0x8250, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_LIGHTNESS_LINEAR_SET
    (0x8251, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_LIGHTNESS_LINEAR_SET_UNACKNOWLEDGED
    (0x8252, [(1, 2), (1, 5), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LIGHTNESS_LINEAR_STATUS
    (0x8253, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LIGHTNESS_LAST_GET
    (0x8254, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LIGHTNESS_LAST_STATUS
    (0x8255, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LIGHTNESS_DEFAULT_GET
    (0x8256, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LIGHTNESS_DEFAULT_STATUS
    (0x8257, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LIGHTNESS_RANGE_GET
    (0x8258, [(1, 5), (0, 5), (255, 5), (127, 5), (61, 5)]),  # LIGHT_LIGHTNESS_RANGE_STATUS
    (0x8259, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LIGHTNESS_DEFAULT_SET
    (0x825a, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LIGHTNESS_DEFAULT_SET_UNACKNOWLEDGED
    (0x825b, [(1, 4), (0, 4), (255, 4), (127, 4), (61, 4)]),  # LIGHT_LIGHTNESS_RANGE_SET
    (0x825c, [(1, 4), (0, 4), (255, 4), (127, 4), (61, 4)]),  # LIGHT_LIGHTNESS_RANGE_SET_UNACKNOWLEDGED
    (0x825d, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_CTL_GET
    (0x825e, [(1, 7), (1, 9), (0, 7), (255, 7), (127, 7), (61, 7)]),  # LIGHT_CTL_SET
    (0x825f, [(1, 7), (1, 9), (0, 7), (255, 7), (127, 7), (61, 7)]),  # LIGHT_CTL_SET_UNACKNOWLEDGED
    (0x8260, [(1, 4), (1, 9), (0, 4), (255, 4), (127, 4), (61, 4)]),  # LIGHT_CTL_STATUS
    (0x8261, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_CTL_TEMPERATURE_GET
    (0x8262, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_CTL_TEMPERATURE_RANGE_GET
    (0x8263, [(1, 5), (0, 5), (255, 5), (127, 5), (61, 5)]),  # LIGHT_CTL_TEMPERATURE_RANGE_STATUS
    (0x8264, [(1, 5), (1, 7), (0, 5), (255, 5), (127, 5), (61, 5)]),  # LIGHT_CTL_TEMPERATURE_SET
    (0x8265, [(1, 5), (1, 7), (0, 5), (255, 5), (127, 5), (61, 5)]),  # LIGHT_CTL_TEMPERATURE_SET_UNACKNOWLEDGED
    (0x8266, [(1, 4), (1, 9), (0, 4), (255, 4), (127, 4), (61, 4)]),  # LIGHT_CTL_TEMPERATURE_STATUS
    (0x8267, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_CTL_DEFAULT_GET
    (0x8268, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_CTL_DEFAULT_STATUS
    (0x8269, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_CTL_DEFAULT_SET
    (0x826a, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_CTL_DEFAULT_SET_UNACKNOWLEDGED
    (0x826b, [(1, 4), (0, 4), (255, 4), (127, 4), (61, 4)]),  # LIGHT_CTL_TEMPERATURE_RANGE_SET
    (0x826c, [(1, 4), (0, 4), (255, 4), (127, 4), (61, 4)]),  # LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACKNOWLEDGED
    (0x826d, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_HSL_GET
    (0x826e, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_HSL_HUE_GET
    (0x826f, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_HSL_HUE_SET
    (0x8270, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_HSL_HUE_SET_UNACKNOWLEDGED
    (0x8271, [(1, 2), (1, 5), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_HSL_HUE_STATUS
    (0x8272, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_HSL_SATURATION_GET
    (0x8273, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_HSL_SATURATION_SET
    (0x8274, [(1, 3), (1, 5), (0, 3), (255, 3), (127, 3), (61, 3)]),  # LIGHT_HSL_SATURATION_SET_UNACKNOWLEDGED
    (0x8275, [(1, 2), (1, 5), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_HSL_SATURATION_STATUS
    (0x8276, [(1, 7), (1, 9), (0, 7), (255, 7), (127, 7), (61, 7)]),  # LIGHT_HSL_SET
    (0x8277, [(1, 7), (1, 9), (0, 7), (255, 7), (127, 7), (61, 7)]),  # LIGHT_HSL_SET_UNACKNOWLEDGED
    (0x8278, [(1, 6), (1, 7), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_HSL_STATUS
    (0x8279, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_HSL_TARGET_GET
    (0x827a, [(1, 6), (1, 7), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_HSL_TARGET_STATUS
    (0x827b, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_HSL_DEFAULT_GET
    (0x827c, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_HSL_DEFAULT_STATUS
    (0x827d, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_HSL_RANGE_GET
    (0x827e, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # LIGHT_HSL_RANGE_STATUS
    (0x827f, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_HSL_DEFAULT_SET
    (0x8280, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_HSL_DEFAULT_SET_UNACKNOWLEDGED
    (0x8281, [(1, 8), (0, 8), (255, 8), (127, 8), (61, 8)]),  # LIGHT_HSL_RANGE_SET
    (0x8282, [(1, 8), (0, 8), (255, 8), (127, 8), (61, 8)]),  # LIGHT_HSL_RANGE_SET_UNACKNOWLEDGED
    (0x8283, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_XYL_GET
    (0x8284, [(1, 7), (1, 9), (0, 7), (255, 7), (127, 7), (61, 7)]),  # LIGHT_XYL_SET
    (0x8285, [(1, 7), (1, 9), (0, 7), (255, 7), (127, 7), (61, 7)]),  # LIGHT_XYL_SET_UNACKNOWLEDGED
    (0x8286, [(1, 6), (1, 7), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_XYL_STATUS
    (0x8287, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_XYL_TARGET_GET
    (0x8288, [(1, 6), (1, 7), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_XYL_TARGET_STATUS
    (0x8289, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_XYL_DEFAULT_GET
    (0x828a, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_XYL_DEFAULT_STATUS
    (0x828b, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_XYL_RANGE_GET
    (0x828c, [(1, 9), (0, 9), (255, 9), (127, 9), (61, 9)]),  # LIGHT_XYL_RANGE_STATUS
    (0x828d, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_XYL_DEFAULT_SET
    (0x828e, [(1, 6), (0, 6), (255, 6), (127, 6), (61, 6)]),  # LIGHT_XYL_DEFAULT_SET_UNACKNOWLEDGED
    (0x828f, [(1, 8), (0, 8), (255, 8), (127, 8), (61, 8)]),  # LIGHT_XYL_RANGE_SET
    (0x8290, [(1, 8), (0, 8), (255, 8), (127, 8), (61, 8)]),  # LIGHT_XYL_RANGE_SET_UNACKNOWLEDGED
    (0x8291, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LC_MODE_GET
    (0x8292, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_MODE_SET
    (0x8293, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_MODE_SET_UNACKNOWLEDGED
    (0x8294, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_MODE_STATUS
    (0x8295, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LC_OM_GET
    (0x8296, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_OM_SET
    (0x8297, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_OM_SET_UNACKNOWLEDGED
    (0x8298, [(1, 1), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_OM_STATUS
    (0x8299, [(1, 0), (0, 0), (255, 0), (127, 0), (61, 0)]),  # LIGHT_LC_LIGHT_ONOFF_GET
    (0x829a, [(1, 2), (1, 4), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LC_LIGHT_ONOFF_SET
    (0x829b, [(1, 2), (1, 4), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LC_LIGHT_ONOFF_SET_UNACKNOWLEDGED
    (0x829c, [(1, 1), (1, 3), (0, 1), (255, 1), (127, 1), (61, 1)]),  # LIGHT_LC_LIGHT_ONOFF_STATUS
    (0x829d, [(1, 2), (0, 2), (255, 2), (127, 2), (61, 2)]),  # LIGHT_LC_PROPERTY_GET
    (0x822a, [(1, 0)]),  # GENERIC_MANUFACTURER_PROPERTIES_GET
    (0x0043, [(1, 0), (1, 2), (1, 4)]),  # GENERIC_MANUFACTURER_PROPERTIES_STATUS
    (0x822b, [(1, 2)]),  # GENERIC_MANUFACTURER_PROPERTY_GET
    (0x0044, [(1, 3)]),  # GENERIC_MANUFACTURER_PROPERTY_SET
    (0x0045, [(1, 3)]),  # GENERIC_MANUFACTURER_PROPERTY_SET_UNACKNOWLEDGED
    (0x0046, [(1, 2), (1, 3), (1, 4)]),  # GENERIC_MANUFACTURER_PROPERTY_STATUS
    (0x822c, [(1, 0)]),  # GENERIC_ADMIN_PROPERTIES_GET
    (0x0047, [(1, 0), (1, 2), (1, 4)]),  # GENERIC_ADMIN_PROPERTIES_STATUS
    (0x822d, [(1, 2)]),  # GENERIC_ADMIN_PROPERTY_GET
    (0x0048, [(1, 3), (1, 4), (1, 5)]),  # GENERIC_ADMIN_PROPERTY_SET
    (0x0049, [(1, 3), (1, 4), (1, 5)]),  # GENERIC_ADMIN_PROPERTY_SET_UNACKNOWLEDGED
    (0x004a, [(1, 2), (1, 3), (1, 4)]),  # GENERIC_ADMIN_PROPERTY_STATUS
    (0x822e, [(1, 0)]),  # GENERIC_USER_PROPERTIES_GET
    (0x004b, [(1, 0), (1, 2), (1, 4)]),  # GENERIC_USER_PROPERTIES_STATUS
    (0x822f, [(1, 2)]),  # GENERIC_USER_PROPERTY_GET
    (0x004c, [(1, 2), (1, 3), (1, 4)]),  # GENERIC_USER_PROPERTY_SET
    (0x004d, [(1, 2), (1, 3), (1, 4)]),  # GENERIC_USER_PROPERTY_SET_UNACKNOWLEDGED
    (0x004e, [(1, 2), (1, 3), (1, 4)]),  # GENERIC_USER_PROPERTY_STATUS
    (0x004f, [(1, 2)]),  # GENERIC_CLIENT_PROPERTIES_GET
    (0x0050, [(1, 0), (1, 2), (1, 4)]),  # GENERIC_CLIENT_PROPERTIES_STATUS
    (0x8230, [(1, 0), (1, 2)]),  # SENSOR_DESCRIPTOR_GET
    (0x0051, [(1, 0), (1, 2), (1, 8)]),  # SENSOR_DESCRIPTOR_STATUS
    (0x8234, [(1, 2)]),  # SENSOR_CADENCE_GET
    (0x0055, [(1, 3), (1, 4), (1, 5)]),  # SENSOR_CADENCE_SET
    (0x0056, [(1, 3), (1, 4), (1, 5)]),  # SENSOR_CADENCE_SET_UNACKNOWLEDGED
    (0x0057, [(1, 3), (1, 4), (1, 5)]),  # SENSOR_CADENCE_STATUS
    (0x8235, [(1, 2)]),  # SENSOR_SETTINGS_GET
    (0x0058, [(1, 2), (1, 4), (1, 6)]),  # SENSOR_SETTINGS_STATUS
    (0x8236, [(1, 4)]),  # SENSOR_SETTING_GET
    (0x0059, [(1, 4), (1, 5), (1, 6)]),  # SENSOR_SETTING_SET
    (0x005a, [(1, 4), (1, 5), (1, 6)]),  # SENSOR_SETTING_SET_UNACKNOWLEDGED
    (0x005b, [(1, 4), (1, 5), (1, 6)]),  # SENSOR_SETTING_STATUS
    (0x8231, [(1, 0), (1, 2)]),  # SENSOR_GET
    (0x0052, [(1, 0), (1, 4), (1, 8)]),  # SENSOR_STATUS
    (0x8232, [(1, 2), (1, 3), (1, 4)]),  # SENSOR_COLUMN_GET
    (0x0053, [(1, 2), (1, 3), (1, 4)]),  # SENSOR_COLUMN_STATUS
    (0x8233, [(1, 2), (1, 4), (1, 6)]),  # SENSOR_SERIES_GET
    (0x0054, [(1, 2), (1, 3), (1, 4)]),  # SENSOR_SERIES_STATUS
]


if __name__ == "__main__":
    main()
