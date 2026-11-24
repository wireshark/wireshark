#!/usr/bin/env python3
# Generates test/captures/mpeg_dsmcc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG DSM-CC coverage captures. User-to-network session and
download messages go over UDP and TCP port 13819 and in sections with table
IDs 0x3a-0x3e in MPEG-TS packets (UDP, heuristic mp2t_udp). The malformed
capture uses Exported PDUs (mp2t-dsmcc, mp2t-dsmcc-udp).
Usage: mkmpeg_dsmcc.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    exp_pdu, ext_header, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, Tcp, TS,
    udp_frame, write_pcap,
)

# ---- message pieces -------------------------------------------------------

SESS_ID = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]) + struct.pack(">I", 7)


def nsap(n=1):
    return (bytes([0x45]) + bytes([0, 0x58, 0x00, 0, 0, 0, 0, 0x01]) +
            struct.pack(">I", 0xAABB0000 + n) + bytes([1, 2, 3, 4, 5, n]) +
            b"\x00")


def u16(n):
    return struct.pack(">H", n)


def u32(n):
    return struct.pack(">I", n)


def user_data(uu=b"", priv=b""):
    return u16(len(uu)) + uu + u16(len(priv)) + priv


def val(kind, n, v=b"\x01"):
    """dsmccResourceDescriptorValue: kind 1 single, 2 list, 3 range, other
    unknown; n octets per value."""
    one = (v * n)[:n].ljust(n, b"\x00")
    if kind == 1:
        return u16(1) + one
    if kind == 2:
        return u16(2) + u16(3) + one * 3
    if kind == 3:
        return u16(3) + one + bytes(n)
    return u16(kind)


def rsrc(rtype, data, reqid=1, number=0x8001, tag=0x4002, flags=0x20,
         status=0):
    return (u16(reqid) + u16(rtype) + u16(number) + u16(tag) +
            bytes([flags, status]) + u16(len(data)) + u16(0) + data)


def resources(*rs):
    return u16(len(rs)) + b"".join(rs)


def rdata():
    """Data fields of every resource type."""
    d = {}
    d[0x0001] = SESS_ID + u16(2) + u16(10) + u16(11)
    d[0x0002] = val(1, 20) + val(2, 2) + val(3, 2)
    d[0x0003] = (val(1, 2) + val(1, 2) + u16(0x0123) + u16(2) +
                 val(1, 2) + val(1, 1) + b"\x00" + val(1, 2) +
                 val(2, 2) + val(1, 1) + b"\x00" + val(3, 2) + val(1, 2))
    d[0x0004] = val(1, 4) + u16(1)
    d[0x0005] = val(1, 4) + val(2, 4)
    d[0x0006] = val(3, 4) + val(1, 4)
    d[0x0007] = b""      # not dissected: the data fields are not skipped
    d[0x0008] = b""
    d[0x0009] = (bytes([192, 0, 2, 1]) + u16(5000) + bytes([192, 0, 2, 2]) +
                 u16(5001) + u16(17))
    d[0x000A] = val(1, 4) + val(1, 4) + val(1, 4) + val(1, 4)
    d[0x000B] = b"0123456789ab" + b"ba9876543210"
    d[0x000C] = b""
    d[0x000D] = b""
    d[0x000E] = u16(2) + u16(16) + u16(17) + u16(18) + u16(19)
    d[0x000F] = u16(2) + nsap(1) + nsap(2)
    d[0x0010] = u16(5) + u16(32)
    d[0x0011] = bytes(range(6)) + u16(2) + u16(1) + u16(2) + u16(3) + u16(4)
    d[0x0012] = u16(7) + u16(8)
    d[0x0013] = (bytes(range(6)) + u16(2) + u16(1) + u16(2) + u16(1) +
                 u16(3))
    d[0x7FFE] = u16(9)
    d[0x7FFF] = u16(10)
    d[0xFFFF] = b"\x01\x02\x03" + b"\x04\x05\x06"
    d[0xF001] = (bytes([1, 2, 3, 4]) + u32(6900000) +
                 bytes([0, 5, 6, 7]))
    d[0xF003] = u16(2) + nsap(3) + u32(0x1234)
    d[0xF004] = val(1, 2) + u16(1) + u16(2) + nsap(4) + nsap(5)
    d[0xF005] = val(1, 2) + u16(3) + b"abc"
    d[0xF006] = (val(1, 2) + val(1, 4) + val(1, 6) + val(1, 2) +
                 val(1, 4) + val(1, 6))
    d[0xF007] = u16(1) + u32(77)
    d[0x1234] = b""      # unknown resource type
    return d


RD = rdata()
ALL_RSRC = resources(*[rsrc(t, RD[t], reqid=i) for i, t in enumerate(sorted(RD))])
SOME_RSRC = resources(rsrc(0x0009, RD[0x0009]), rsrc(0x0004, RD[0x0004]))
NO_RSRC = resources()


def hdr(mtype, msgid, tx=0x80000001, adapt=b"", reserved=0xFF, length=None,
        prot=0x11, download=False):
    return (bytes([prot, mtype]) + u16(msgid) + u32(tx) +
            bytes([reserved, len(adapt)]) + u16(length or 0) + adapt)


def status_tail(n=3):
    return u16(1) + u16(n) + bytes(range(1, n + 1))


UD = user_data(b"user", b"priv")
NSAPS = nsap

# message id -> body builder (the layouts of dissect_dsmcc_un_session)
def bodies(R=SOME_RSRC):
    S = SESS_ID
    ud = UD
    return {
        0x4010: S + u16(0) + nsap(1) + nsap(2) + ud,
        0x4011: S + u16(0) + nsap(2) + R + ud,
        0x4020: S + u16(1) + ud,
        0x4021: S + u16(0) + ud,
        0x4022: S + u16(2) + ud,
        0x4023: S + u16(0) + ud,
        0x4032: S + R + ud,
        0x4033: S + u16(0) + R + ud,
        0x4042: S + u16(1) + u16(2) + u16(5) + u16(6) + ud,
        0x4043: S + u16(0) + ud,
        0x4060: S + u16(1) + nsap(1) + status_tail(),
        0x4061: u16(0) + status_tail(),
        0x4062: u16(0) + status_tail(),
        0x4063: u16(0) + status_tail(),
        0x4070: nsap(1) + u16(1),
        0x4071: nsap(1) + u16(0),
        0x4072: nsap(1) + u16(2),
        0x4073: nsap(1) + u16(0),
        0x4082: S + u16(3),
        0x4090: S + ud,
        0x40A2: S + u16(0) + nsap(1) + nsap(2) + nsap(3) + R + ud,
        0x40A3: S + u16(0) + ud,
        0x40B0: u16(2) + S + S,
        0x8012: S + u16(0) + nsap(1) + nsap(2) + u16(2) + nsap(3) + nsap(4) + ud,
        0x8013: S + u16(0) + nsap(2) + nsap(3) + R + ud,
        0x8020: S + u16(1) + ud,
        0x8021: S + u16(0) + ud,
        0x8022: S + u16(2) + ud,
        0x8023: S + u16(0) + ud,
        0x8030: S + R + ud,
        0x8031: S + u16(0) + R + ud,
        0x8040: S + u16(1) + u16(2) + u16(5) + u16(6) + ud,
        0x8041: S + u16(0) + ud,
        0x8050: S + u16(0) + nsap(1) + R,
        0x8051: S + u16(0) + R,
        0x8060: u16(1) + nsap(1) + status_tail(),
        0x8061: u16(0) + status_tail(),
        0x8062: u16(0) + status_tail(),
        0x8063: u16(0) + status_tail(),
        0x8070: nsap(1) + u16(1),
        0x8071: nsap(1) + u16(0),
        0x8072: nsap(1) + u16(2),
        0x8073: nsap(1) + u16(0),
        0x8082: S + u16(3),
        0x8092: S + ud,
        0x80A0: S + u16(0) + nsap(1) + nsap(2) + ud,
        0x80A1: S + u16(0) + ud,
        0x80A2: S + u16(0) + nsap(1) + nsap(2) + nsap(3) + R + ud,
        0x80A3: S + u16(0) + R + ud,
        0x80B0: u16(1) + S,
    }


def un_msg(msgid, body, adapt=b"", **kw):
    return hdr(2, msgid, adapt=adapt, **kw) + body


# download messages ---------------------------------------------------------

def compat_desc(n_desc, subs=(), dtype=0x01):
    """compatibilityDescriptor with n_desc descriptors (11 octets plus the
    sub descriptors)."""
    if n_desc == 0:
        return u16(0)
    d = b""
    for _ in range(n_desc):
        sub = b"".join(bytes([0x80 + i, len(s)]) + s
                       for i, s in enumerate(subs))
        d += (bytes([dtype, 9 + len(sub), 0x02]) + b"\x00\x01\x02" +
              u16(0x1111) + u16(0x0102) + bytes([len(subs)]) + sub)
    return u16(2 + len(d)) + u16(n_desc) + d


def dii(compat, modules, priv=b"", msgid=0x1002, download_id=0x00000042,
        adapt=b""):
    mods = u16(len(modules))
    for mid, size, ver, info in modules:
        mods += u16(mid) + u32(size) + bytes([ver, len(info)]) + info
    body = (u32(download_id) + u16(4066) + bytes([8, 3]) + u32(0x00100000) +
            u32(0x00200000) + compat + mods + u16(len(priv)) + priv)
    return hdr(3, msgid, adapt=adapt) + body


def pstr(s):
    return bytes([len(s)]) + s


def ddb(module, version, block, data, adapt=b"", reserved=0xFF):
    return (bytes([0x11, 3]) + u16(0x1003) + u32(0x42) +
            bytes([0xFF, len(adapt)]) + u16(0) + adapt +
            u16(module) + bytes([version, reserved]) + u16(block) + data)


CA_ADAPT = bytes([1, 0xFF]) + u16(0x0B00) + u16(4) + b"\xde\xad\xbe\xef"
UID_ADAPT = bytes([2, 0xFF]) + nsap(9)
UNK_ADAPT = bytes([0x81, 0x01, 0x02])


def dsmcc_section(tid, payload, tx_ext=1, version=1, sect=0, last=0, **kw):
    return section(tid, ext_header(tx_ext, version, 1, sect, last) + payload,
                   **kw)


def build_main():
    frames = []
    # --- UDP port 13819: every session message, then TS ---------------------
    msgs = bodies()
    for i, (mid, body) in enumerate(sorted(msgs.items())):
        frames.append(udp_frame(un_msg(mid, body), sport=40000 + i,
                                dport=13819))
    # --- resources in full: a message with every resource descriptor type,
    # the three kinds of resource values and unknown ones
    frames.append(udp_frame(un_msg(0x4011, bodies(ALL_RSRC)[0x4011]),
                            dport=13819))
    frames.append(udp_frame(un_msg(0x8031, bodies(ALL_RSRC)[0x8031]),
                            dport=13819))
    # MPEG program with an unknown value kind and a client CA without data
    frames.append(udp_frame(un_msg(0x4032, SESS_ID + resources(
        rsrc(0x0003, val(4, 2) + val(1, 2) + u16(0) + u16(0) + val(1, 2)),
        rsrc(0xF005, val(1, 2) + u16(0)),
        rsrc(0xF003, u16(4) + nsap(1) + u32(1)),
        rsrc(0xF003, u16(1) + nsap(1) + u32(1))) + UD), dport=13819))
    # unknown session message ID, other message types
    frames.append(udp_frame(un_msg(0x4FFF, b"\x00" * 8), dport=13819))
    frames.append(udp_frame(hdr(1, 0x2000) + b"\x00" * 8, dport=13819))
    frames.append(udp_frame(hdr(4, 0x2000) + b"\x00" * 8, dport=13819))
    frames.append(udp_frame(hdr(5, 0x2000) + b"\x00" * 8, dport=13819))
    frames.append(udp_frame(hdr(0x7F, 0x2000) + b"\x00" * 8, dport=13819))
    # adaptation headers: conditional access, user ID, unknown type
    for ad in (CA_ADAPT, UID_ADAPT, UNK_ADAPT):
        frames.append(udp_frame(un_msg(0x4082, SESS_ID + u16(3), adapt=ad),
                                dport=13819))
    # --- TCP port 13819 -----------------------------------------------------
    t = Tcp(cport=40100, sport=13819)
    t.handshake()
    t.send(True, un_msg(0x4010, msgs[0x4010]))
    t.send(False, un_msg(0x4011, msgs[0x4011]))
    t.send(True, un_msg(0x4020, msgs[0x4020]))
    t.send(False, un_msg(0x4021, msgs[0x4021]))
    # a segment that does not start with the protocol discriminator 0x11
    t.send(True, un_msg(0x4082, SESS_ID + u16(3), prot=0x22))
    t.close()
    frames += t.frames
    # --- download messages in sections of the download table IDs ------------
    ts = TS()
    mods = [(1, 4096, 1, pstr(b"/app/main.html")), (2, 100, 2, b""),
            (3, 9999, 3, b"\x00\x01")]

    def add(*sects, pid=0x300):
        pk = ts.sections(pid, list(sects))
        frames.append(udp_frame(b"".join(pk), dport=5004))

    add(dsmcc_section(0x3C, dii(compat_desc(0), mods, pstr(b"dvb.test"))))
    add(dsmcc_section(0x3C, dii(compat_desc(2, [b"\x01\x02", b""]), mods[:1],
                                msgid=0x1001, adapt=CA_ADAPT)))
    add(dsmcc_section(0x3C, dii(compat_desc(0), [])))
    add(dsmcc_section(0x3C, ddb(1, 1, 0, bytes(range(200)))))
    add(dsmcc_section(0x3C, ddb(2, 3, 7, b"\x55" * 20, adapt=UID_ADAPT)))
    # download message types that are not dissected
    for mid in (0x1004, 0x1005, 0x1006, 0x1007):
        add(dsmcc_section(0x3C, hdr(3, mid) + b"\x00" * 8))
    # a DII on several TS packets
    add(dsmcc_section(0x3C, dii(compat_desc(3, [b"\x01"]), [
        (n, 1000 + n, n & 0xFF, pstr(b"/m/%d" % n)) for n in range(40)])))
    # session messages in table ID 0x3B and the other table IDs
    add(dsmcc_section(0x3B, un_msg(0x4010, msgs[0x4010]), reserved=7))
    add(dsmcc_section(0x3A, b"\x00" * 12))
    add(dsmcc_section(0x3D, b"\x00" * 12, version=31))
    add(dsmcc_section(0x3B, un_msg(0x8012, msgs[0x8012]), tx_ext=0xFFFF,
                      sect=1, last=2))
    # section without syntax indicator (checksum instead of CRC) and
    # sections with a bad CRC
    add(section(0x3B, ext_header(1, 1) + un_msg(0x4082, SESS_ID + u16(3)) +
                b"\x01\x02\x03\x04", ssi=False, crc=False))
    add(dsmcc_section(0x3B, un_msg(0x4082, SESS_ID + u16(3)), badcrc=True))
    return frames


def build_malformed():
    f = []
    # reachable only with the Exported PDU entry points
    # DII whose offset reaches 1000: an expert info (leftover test)
    d1000 = dii(compat_desc(88), [(1, 10, 1, b"")])
    f.append(("mp2t-dsmcc", dsmcc_section(0x3C, d1000)))
    # invalid values: protocol discriminator, reserved, adaptation reserved
    f.append(("mp2t-dsmcc", dsmcc_section(0x3B, un_msg(
        0x4082, SESS_ID + u16(3), prot=0x12, reserved=0))))
    f.append(("mp2t-dsmcc", dsmcc_section(0x3B, un_msg(
        0x4082, SESS_ID + u16(3), adapt=bytes([1, 0, 0, 0, 0, 0, 0, 0])))))
    f.append(("mp2t-dsmcc", dsmcc_section(0x3B, un_msg(
        0x4082, SESS_ID + u16(3), adapt=bytes([2, 0]) + nsap(1)))))
    f.append(("mp2t-dsmcc", dsmcc_section(0x3C, ddb(1, 1, 0, b"\x00" * 8,
                                                      reserved=0))))
    # headend ID flag out of range
    f.append(("mp2t-dsmcc", dsmcc_section(0x3B, un_msg(0x4032, SESS_ID + resources(
        rsrc(0xF003, u16(0) + nsap(1) + u32(1))) + UD))))
    f.append(("mp2t-dsmcc", dsmcc_section(0x3B, un_msg(0x4032, SESS_ID + resources(
        rsrc(0xF003, u16(5) + nsap(1) + u32(1))) + UD))))
    # truncated messages
    full = un_msg(0x4011, bodies(ALL_RSRC)[0x4011])
    for cut in (5, 11, 12, 20, 40, 60, 90, 150, 300):
        f.append(("mp2t-dsmcc-udp", full[:cut]))
    f.append(("mp2t-dsmcc-udp", un_msg(0x4010, bodies()[0x4010])[:-30]))
    f.append(("mp2t-dsmcc-udp", dii(compat_desc(2, [b"\x01"]), [(1, 2, 3, b"")])[:60]))
    f.append(("mp2t-dsmcc-udp", dii(compat_desc(2, [b"\x01"]), [(1, 2, 3, b"")])[:-4]))
    f.append(("mp2t-dsmcc-udp", ddb(1, 1, 0, b"")[:20]))
    # a message of the wrong protocol discriminator (not dissected by the
    # UDP/TCP entry points)
    f.append(("mp2t-dsmcc-udp", un_msg(0x4082, SESS_ID + u16(3), prot=0x22)))
    # table IDs that no registered dissector claims (private, undefined):
    # only the Exported PDU entry point reaches them
    f.append(("mp2t-dsmcc", dsmcc_section(0x3E, b"\x00" * 12)))
    f.append(("mp2t-dsmcc", dsmcc_section(0x30, b"\x00" * 12)))
    # section lengths: section_length 0, 8, and too long; ssi set and no CRC
    f.append(("mp2t-dsmcc", section(0x3B, b"", crc=False, length=0)))
    f.append(("mp2t-dsmcc", section(0x3B, ext_header(1, 1), crc=False, length=5)))
    f.append(("mp2t-dsmcc", section(0x3B, ext_header(1, 1), crc=False, length=9)))
    f.append(("mp2t-dsmcc", section(0x3B, ext_header(1, 1) + b"\x11\x02", length=300)))
    # DSMCC lengths: huge counts
    f.append(("mp2t-dsmcc-udp", un_msg(0x40B0, u16(60000) + SESS_ID)))
    f.append(("mp2t-dsmcc-udp", un_msg(0x4060, SESS_ID + u16(1) + nsap(1) + u16(1) + u16(60000))))
    f.append(("mp2t-dsmcc-udp", un_msg(0x4011, SESS_ID + u16(0) + nsap(1) + u16(60000))))
    f.append(("mp2t-dsmcc-udp", un_msg(0x4011, SESS_ID + u16(0) + nsap(1) + resources(
        rsrc(0x0003, val(1, 2) + val(1, 2) + u16(0) + u16(60000))))))
    return [exp_pdu(n, p) for n, p in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-dsmcc-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-dsmcc-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
