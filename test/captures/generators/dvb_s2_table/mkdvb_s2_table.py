#!/usr/bin/env python3
# Generates test/captures/dvb_s2_table_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB-S2 table coverage captures: DVB-RCS / DVB-RCS2 forward
link signalling tables (ETSI EN 301 790, EN 301 545-2) in Exported PDUs
(linktype 252) that name the "dvb-s2_table" dissector. Over the air the
tables are GSE PDUs of protocol type 0x0082 in DVB-S2 Base Band frames.
Every packet is built with struct; nothing comes from a real network.

Usage: mkdvb_s2_table.py <outdir>

Writes:
  dvb-s2-table-coverage.pcap            every RCS2 table type and every
                                        descriptor (default decoding)
  dvb-s2-table-coverage-rcs.pcap        the same with the RCS (DVB-RCS1)
                                        section headers, for
                                        -o dvb-s2_table.rcs_protocol:RCS
  dvb-s2-table-coverage-malformed.pcap  tables cut short, the TBTP2
                                        reproducer with many frames
"""
import os
import struct
import sys

LINKTYPE_WIRESHARK_UPPER_PDU = 252

# Section layout, switched by build(rcs)
RCS = False


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
    return crc


def exp_pdu(payload, name="dvb-s2_table"):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return (struct.pack("!HH", 12, len(n) + pad) + n + b"\0" * pad +
            struct.pack("!HH", 0, 0) + payload)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                            LINKTYPE_WIRESHARK_UPPER_PDU))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def table(tid, body, niid=0x0001, version=1, crc=True):
    """RCS2: table_id, interactive network ID, version (GSE table header).
    RCS: table_id, SI section header (syntax, length, network ID, version,
    section numbers), the body and the CRC that the table dissectors show
    for RCS."""
    if not RCS:
        return bytes([tid]) + struct.pack(">HB", niid, 0xC0 | (version << 1) | 1) + body
    length = 5 + len(body) + (4 if crc else 0)
    s = bytes([tid, 0xB0 | (length >> 8), length & 0xFF]) + \
        struct.pack(">HBBB", niid, 0xC0 | (version << 1) | 1, 0, 0) + body
    if crc:
        s += struct.pack(">I", crc32_mpeg2(s))
    return s


def d(tag, body):
    return bytes([tag, len(body)]) + body


def descs(*ds):
    """Descriptor loop count (number - 1) and the descriptors."""
    return bytes([len(ds) - 1]) + b"".join(ds)


# --- descriptors -------------------------------------------------------

def ctrl_assign():
    # threshold, max tries, freq threshold, start superframe, frame,
    # repeat period, timeslot (same 11 octets for RCS and RCS2)
    return d(0xA4, struct.pack(">BBHHBHH", 5, 3, 0x1234, 0x0100, 2, 16, 0x0007))


def correction_msg(flags, *rest):
    return d(0xA1, bytes([flags]) + bytes(rest))


def correction_msg_ext():
    return d(0xB1, struct.pack(">BHBH", 1, 0x0203, 4, 0x0506))


def logon_response(mac24s):
    body = struct.pack(">BBH", 0x40 | 0x10 | 0x03, 0x11, 0x0042)
    body += struct.pack(">I", 0x000100)[1:]
    body += bytes([0x20 | len(mac24s)])
    for prefix, mac, flags in mac24s:
        body += bytes([prefix]) + struct.pack(">I", mac)[1:] + bytes([flags])
    body += struct.pack(">HB", 0x0007, 0xFF)
    return d(0xB9, body)


def lower_layer_service():
    body = bytes([10, 20, 30])
    lls = [
        bytes([(1 << 2) | 0x01 | 0x02, 0x12]) + struct.pack(">HH", 0x0003, 0x0005) + bytes([0x01, 0x02]),
        bytes([(2 << 2) | 0x01, 0x23]) + struct.pack(">HH", 0x0001, 0x0002),
        bytes([(3 << 2) | 0x02, 0x04, 0x08]),
        bytes([(4 << 2)]),
    ]
    body += bytes([len(lls)]) + b"".join(lls)
    rcs = [
        bytes([0x10 | 0x04 | 0x02 | 0x01]) + struct.pack(">HHH", 1000, 100, 500) + bytes([9]),
        bytes([0x20 | 0x04]) + struct.pack(">HHH", 2000, 200, 600),
        bytes([0x30 | 0x02]) + struct.pack(">HH", 3000, 300) + bytes([7]),
        bytes([0x40]) + struct.pack(">HH", 4000, 400),
    ]
    body += bytes([len(rcs)]) + b"".join(rcs)
    raacs = [bytes([0x01, 2, 3, 4, 3]) + b"\xaa\xbb\xcc",
             bytes([0x02, 5, 6, 7, 0])]
    body += bytes([len(raacs)]) + b"".join(raacs)
    return d(0xBB, body)


def network_name(name=b"Synthetic RCS2 Network"):
    return d(0x40, name)


def linkage(ltype, extra=b"", private=b""):
    return d(0x4A, struct.pack(">HHHB", 0x0001, 0x0002, 0x0003, ltype) + extra + private)


def sat_return_link(private=b""):
    return d(0xA9, struct.pack(">BHBBHBB", 1, 0x0102, 3, 0xFF, 0x0130, 0x80, 4) +
             struct.pack(">I", 0x012345)[1:] + private)


def logon_initialize(flags2, mid, tail=True):
    body = struct.pack(">BH", 0x21, 0x0102) + bytes([0xFC]) + bytes([flags2])
    body += mid
    if tail and not flags2 & 0x40:
        body += struct.pack(">I", 0x000100)[1:] + struct.pack(">H", 50) + \
            struct.pack(">I", 0x000200)[1:] + struct.pack(">H", 30)
    return d(0xA2, body)


def forward_interaction_path():
    body = struct.pack(">HHB", 0x0001, 0x0002, 0x01) + struct.pack(">HH", 0x0100, 0x0101)
    body += struct.pack(">HHB", 0x0003, 0x0004, 0x00) + struct.pack(">H", 0x0200)
    return d(0xAD, body)


def return_interaction_path():
    # three network routing labels (loop count 2): PIDs, VPI/VCI, route
    # IDs (route id loop count 2, so three route IDs), and one with no
    # flags set
    body = bytes([0x80 | 2])
    body += bytes([0x81, 1]) + struct.pack(">HH", 0x0300, 0x0301)
    body += bytes([0x01, 1]) + bytes([1]) + struct.pack(">H", 32) + bytes([2]) + struct.pack(">H", 33)
    body += bytes([0x01, 2]) + struct.pack(">HHH", 0x0A01, 0x0A02, 0x0A03)
    body += bytes([0x07])
    body += bytes([0x00]) + bytes([0x00]) + bytes([0x00]) + bytes([0x08])
    body += bytes([0x81, 0]) + struct.pack(">H", 0x0400) + bytes([0x00]) + bytes([0x00]) + bytes([0x09])
    return d(0xAE, body)


def snmp_get_request():
    """SNMPv2c GetRequest for sysDescr.0, encoded by hand."""
    def tlv(t, v):
        return bytes([t, len(v)]) + v
    oid = tlv(0x06, bytes([0x2B, 6, 1, 2, 1, 1, 1, 0]))
    varbind = tlv(0x30, oid + tlv(0x05, b""))
    pdu = tlv(0xA0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") +
              tlv(0x30, varbind))
    return tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, b"public") + pdu)


def network_layer_info():
    return d(0xA0, snmp_get_request())


def correction_control():
    return d(0xAC, struct.pack(">IIBB", 1000, 2000, 3, 4))


def contention_control():
    return d(0xAB, struct.pack(">BIBI", 1, 3000, 5, 4000))


def sat_forward_link(std, scrambling=0, private=b""):
    body = struct.pack(">BHBB", 1, 0x0102, 3, 0x80 | 0x05)
    body += struct.pack(">IH", 0x01177800, 0x0192)
    flags = 0x80 | (0 << 5) | (std << 3) | (scrambling << 2) | 0x01
    body += bytes([flags])
    if std == 3:
        body += struct.pack(">I", 0x275000)[1:]
    else:
        body += struct.pack(">I", 0x275000)[1:]
        if std == 0:
            body += bytes([0x03])
        else:
            body += bytes([0x05])
            if scrambling == 0:
                body += struct.pack(">I", 0x012345)[1:]
    return d(0xA8, body + private)


def mobility_control(cmd):
    return d(0xB0, struct.pack(">HH", cmd, 0x0010))


def lowest_sw_version():
    body = bytes([2])
    body += struct.pack(">I", 0x001122)[1:] + bytes([239, 1, 2, 3]) + struct.pack(">H", 5000) + bytes([3]) + b"1.2"
    body += struct.pack(">I", 0x003344)[1:] + bytes([239, 1, 2, 4]) + struct.pack(">H", 5001) + bytes([0])
    return d(0xC5, body)


# --- tables -------------------------------------------------------------

def sct():
    body = bytes([1])  # two superframes
    for sf in range(2):
        body += bytes([sf, 0x80 | sf]) + bytes.fromhex("000102030405") + \
            struct.pack(">IIH", 26500, 29500000 + sf, 100 + sf)
        n = 2 if sf == 0 else 1
        body += bytes([n - 1])
        for fr in range(n):
            body += bytes([fr]) + struct.pack(">I", 1000 * fr) + struct.pack(">I", 0x000100 + fr)[1:]
    return table(0xA0, body)


def tim(unicast=True, descriptors=()):
    status = 0x02 if unicast else 0x01
    tid = 0xB0 if unicast else 0xFE
    return table(tid, bytes([status]) + descs(*descriptors))


def tim_rcs(broadcast):
    """TIM with the DSM-CC header of RCS: MAC address bytes 6, 5, flags,
    section numbers, MAC address bytes 4-1; all-ones is a broadcast TIM."""
    mac = b"\xff" * 6 if broadcast else bytes.fromhex("020000000001")
    body = bytes([mac[5], mac[4], 0xC1, 0, 0, mac[3], mac[2], mac[1], mac[0]])
    body += bytes([0x01 if broadcast else 0x02])
    if broadcast:
        body += descs(network_name(), sat_forward_link(0))
    else:
        body += descs(correction_msg(0xE0, 3, 0x85, 0x01, 0x02), sat_return_link(),
                      logon_response([(24, 0x000001, 0x41)]))
    length = 2 + len(body) + 4 + 5
    s = bytes([0xB0, 0xB0 | (length >> 8), length & 0xFF]) + body
    s = s + struct.pack(">I", crc32_mpeg2(s))
    return s


def tbtp2(fmt, frames):
    body = struct.pack(">BBBBB", 0x11, 2, 1, 7, fmt) + bytes([len(frames) - 1])
    sizes = {0: 6, 1: 1, 2: 2, 3: 3, 10: 2, 11: 3, 12: 4}
    for fnum, assigns in frames:
        body += bytes([fnum]) + struct.pack(">HH", 0x0010, assigns - 1)
        for a in range(assigns):
            if fmt >= 10:
                body += bytes([0x80 + a]) + (a + 1).to_bytes(sizes[fmt] - 1, "big")
            else:
                body += (a + 1).to_bytes(sizes[fmt], "big")
    return table(0xAD, body)


def tbtp():
    body = bytes([0x11]) + struct.pack(">H", 0x0102) + bytes([1])  # 2 frames
    # frame 0: two BTPs, one with the multiple channel flag
    body += bytes([0]) + struct.pack(">H", 1)
    body += struct.pack(">H", 0x0042) + struct.pack(">H", 0x8000 | 0x2000 | 0x1000 | 0x0005) + bytes([3, 4])
    body += struct.pack(">H", 0x0043) + struct.pack(">H", 0x4000 | 0x0010) + bytes([2])
    # frame 1: one BTP
    body += bytes([1]) + struct.pack(">H", 0)
    body += struct.pack(">H", 0x0044) + struct.pack(">H", 0x6000 | 0x0020) + bytes([1])
    return table(0xA5, body)


def cmt():
    body = bytes([2])
    body += bytes([0x11]) + struct.pack(">H", 0x0042) + bytes([0xE0 | 0x08 | 0x01, 3, 0x85]) + struct.pack(">h", -100)
    body += bytes([0x11]) + struct.pack(">H", 0x0043) + bytes([0x40, 0x12])
    body += bytes([0x12]) + struct.pack(">H", 0x0044) + bytes([0x00])
    return table(0xA4, body)


def tmst():
    # each mode is shown as 3 octets but only 1 is consumed: pad the end
    return table(0xAA, bytes([3, 0x00 | 0x20 | 4, 0x40 | 9, 0xC0 | 0x20 | 17]) +
                 (b"\x00\x00" if not RCS else b""))


def tmst2():
    body = bytes([10, 2])
    body += bytes([0x20 | 4, 5, 0])
    body += bytes([0x40 | 17, 6, 1])
    return table(0xAE, body)


def fct2():
    body = bytes([1])  # two frame types
    for ft in range(2):
        body += bytes([ft]) + struct.pack(">IB", 26500, 1)
        body += struct.pack(">I", 1000)[1:] + struct.pack(">I", 2000)[1:] + struct.pack(">I", 3000)[1:]
        body += struct.pack(">H", 100)
        grids = 2 if ft == 0 else 0
        body += bytes([grids]) + b"".join(struct.pack(">I", 10 * g)[1:] for g in range(grids))
        sections = 2 if ft == 0 else 1
        body += bytes([sections - 1]) + b"".join(
            bytes([0x80 + s, s]) + struct.pack(">H", s + 1) for s in range(sections))
    return table(0xAB, body)


def fct():
    body = bytes([1])
    for fid in range(2):
        body += bytes([fid]) + struct.pack(">IHH", 26500, 64, 0)
        n = 2 if fid == 0 else 1
        body += bytes([n - 1])
        for t in range(n):
            body += struct.pack(">I", 1000 * t)[1:] + struct.pack(">IBB", 500 * t, t, 1)
    return table(0xA1, body)


def spt():
    body = bytes([1])
    for s in range(2):
        body += bytes([s + 1]) + struct.pack(">fff", 42164.0 + s, -1.5, 0.25)
    return table(0xA3, body)


def smt():
    return table(0x80, bytes([0x01]) + struct.pack(">H", 0xB000 | 7) + struct.pack(">H", 0x0123) + bytes([4]) + struct.pack(">I", 0x11223344))


def nit_rmt(tid, ndescs, muxes):
    nd = b"".join(ndescs)
    body = struct.pack(">H", 0xF000 | len(nd)) + nd
    ms = b""
    for fwd, other, tds in muxes:
        td = b"".join(tds)
        ms += struct.pack(">HHH", fwd, other, 0xF000 | len(td)) + td
    body += struct.pack(">H", 0xF000 | len(ms)) + ms
    return table(tid, body)


def mmt2():
    body = struct.pack(">HB", 0x0007, 24) + bytes([1])  # two protocols
    # IPv4 multicast (protocol type 0x08, address size 4): two mapping
    # sections, the first with two exclusions
    body += bytes([0x08, 4]) + bytes([1])
    body += bytes([239, 0, 0, 0]) + bytes([239, 0, 0, 255]) + bytes([1])
    body += bytes([239, 0, 0, 10, 239, 0, 0, 20, 239, 0, 0, 30, 239, 0, 0, 40])
    body += struct.pack(">I", 0x010000)[1:] + bytes([8])
    body += bytes([239, 1, 0, 0]) + bytes([239, 1, 0, 255]) + bytes([0])
    body += bytes([239, 1, 0, 1, 239, 1, 0, 2])
    body += struct.pack(">I", 0x020000)[1:] + bytes([16])
    # IPv6 (address size 16), one section with one exclusion
    a = bytes.fromhex("ff0e0000000000000000000000000001")
    b = bytes.fromhex("ff0e00000000000000000000000000ff")
    body += bytes([0x86, 16]) + bytes([0]) + a + b + bytes([0]) + a + a + \
        struct.pack(">I", 0x030000)[1:] + bytes([4])
    return table(0xB2, body)


def tdt(mjd=61347, h=0x12, m=0x34, s=0x56):
    if RCS:
        return bytes([0x70, 0x70, 0x05]) + struct.pack(">HBBB", mjd, h, m, s)
    return table(0x70, struct.pack(">HBBB", mjd, h, m, s))


def lmbt(tx_type, mod_scheme=1, y=2, w=1, pre=2, post=1, pilot_block=1):
    data = bytes([16, 10, 0x01]) + struct.pack(">I", 0x000200)[1:]
    if tx_type > 127:
        data += struct.pack(">H", 100) + bytes([mod_scheme, 1, 2, 3, 4, 5])
        data += bytes([y, w]) + bytes([0x80 | i for i in range(y)]) + bytes([i for i in range(w)])
        data += bytes([pre, post]) + struct.pack(">H", 20) + bytes([pilot_block, 9])
        data += bytes([0x40 | i for i in range(pre + post + pilot_block)])
    else:
        data += bytes([0x55])
    return bytes([tx_type, 0x03, 0x01, len(data)]) + data


def cpmbt(tx_type, interleaver):
    data = bytes([16, 10]) + struct.pack(">I", 0x00000300)
    if tx_type > 127:
        data += bytes([0x20 | 0x04 | 0x01, 0x05, 0x04 | 0x01])
        data += bytes([12]) + bytes(12 * 2 // 8 + 1)
        data += bytes([2]) + struct.pack(">HB", 0, 4) + struct.pack(">HB", 100, 4)
        if interleaver:
            # seven 2 octet fields that each advance 1 octet
            data += bytes([0x01]) + bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE])
        else:
            data += bytes([0x00]) + b"\x11\x22\x33"
    return bytes([tx_type, 0x04, 0x02, len(data)]) + data


def bct():
    txs = [
        lmbt(0x81, mod_scheme=1),
        lmbt(0x82, mod_scheme=2),
        lmbt(0x83, mod_scheme=3),
        lmbt(0x84, mod_scheme=5),
        lmbt(0x05),
        cpmbt(0x91, True),
        cpmbt(0x92, False),
        cpmbt(0x13, False),
        bytes([0x20, 0x02, 0x03, 4]) + b"\x01\x02\x03\x04",
        bytes([0x21, 0x01, 0x04, 2]) + b"\x05\x06",
        bytes([0x22, 0x01, 0x00, 1]) + b"\x07",
    ]
    return table(0xAC, bytes([len(txs)]) + b"".join(txs))


def fat(*ds):
    return table(0xAF, descs(*ds))


def unhandled(tid, body=b"\x00\x01\x02\x03"):
    return table(tid, body)


def build_main():
    F = []
    # 1: TBTP2 with an unknown assignment format (reproducer of the fix:
    # an expert info and the loop is not walked)
    F.append(table(0xAD, bytes([0x00, 0x00, 0x00, 0x00, 0x04, 0xFF]) +
                   b"".join(bytes([i]) + struct.pack(">HH", 0, 0xFFFF) for i in range(256))))
    # 2: TIM with a Network Layer Info descriptor (SNMP PDU, reproducer
    # of the SNMP protocol id fix)
    F.append(tim(True, [network_layer_info()]))
    # 3: FAT with a Return Interaction Path descriptor (route id loop
    # count 2, reproducer of the mask fix)
    F.append(fat(return_interaction_path()))
    # 4: SCT
    F.append(sct())
    # 5: FCT
    F.append(fct())
    # 6: FCT2 (table ID 0xAB in RCS2)
    F.append(fct2())
    # 7: SPT
    F.append(spt())
    # 8: CMT
    F.append(cmt())
    # 9: TBTP
    F.append(tbtp())
    # 10-16: TBTP2 with every assignment format
    for fmt in (0, 1, 2, 3, 10, 11, 12):
        F.append(tbtp2(fmt, [(0, 2), (1, 1)]))
    # 17: TMST, 18: TMST2
    F.append(tmst())
    F.append(tmst2())
    # 19: BCT with every transmission format
    F.append(bct())
    # 20: unicast TIM with the RCS2 unicast descriptors
    F.append(tim(True, [
        correction_msg(0xE0 | 0x08 | 0x01, 3, 0x85, 0x01, 0x02),
        correction_msg(0x40, 0x12),
        correction_msg(0x00),
        correction_msg_ext(),
        ctrl_assign(),
        logon_response([(24, 0x000001, 0x41), (16, 0x000002, 0x20)]),
        lower_layer_service(),
        sat_return_link(),
        sat_return_link(b"\xde\xad"),
        mobility_control(1),
        mobility_control(0x0100),
    ]))
    # 21: broadcast TIM (0xFE) with the broadcast descriptors and the NCR
    # private data of the satellite forward link descriptor
    F.append(tim(False, [
        sat_forward_link(0, private=bytes.fromhex("0123456789ab")),
        sat_forward_link(1, 0),
        sat_forward_link(2, 1, private=b"\x01\x02"),
        sat_forward_link(3),
        correction_control(),
        contention_control(),
        network_name(),
        lowest_sw_version(),
        d(0xA6, b"\x01\x02"),
    ]))
    # 22: FAT with logon initialize and interaction path descriptors
    F.append(fat(
        logon_initialize(0x00, bytes([1]) + struct.pack(">H", 32)),
        logon_initialize(0x10, bytes([1]) + struct.pack(">H", 32) + b"\x00" +
                         bytes([2]) + struct.pack(">H", 33)),
        logon_initialize(0x40 | 0x20 | 0x00, struct.pack(">H", 0x0300)[1:] + struct.pack(">H", 0x0301)),
        forward_interaction_path(),
        sat_forward_link(0, private=bytes.fromhex("0123456789ab")),
    ))
    # 23: FAT with every linkage descriptor variant
    F.append(fat(
        linkage(0x08, bytes([0x10 | 0x00]) + struct.pack(">HH", 0x0020, 0x0021)),
        linkage(0x08, bytes([0x20 | 0x01]) + struct.pack(">H", 0x0022)),
        linkage(0x08, bytes([0x30 | 0x00]) + struct.pack(">HH", 0x0023, 0x0024)),
        linkage(0x08, bytes([0x00 | 0x01])),
        linkage(0x0D, struct.pack(">HB", 0x1234, 0xC0)),
        linkage(0x81, struct.pack(">HB", 0x0030, 1) + struct.pack(">HHHH", 1, 0xFF00, 2, 0xFF00)),
        linkage(0x82, struct.pack(">HB", 0x0031, 0) + struct.pack(">HH", 3, 0xFFF0), b"\x99"),
        linkage(0x01, b"", b"\x01\x02\x03"),
    ))
    # 24: NIT with network and transport descriptors, 25: RMT
    F.append(nit_rmt(0x40, [network_name(), linkage(0x01)], [
        (0x0001, 0x0002, [sat_forward_link(1, 1)]),
        (0x0003, 0x0002, []),
    ]))
    F.append(nit_rmt(0x41, [linkage(0x81, struct.pack(">HB", 0x0030, 0) + struct.pack(">HH", 1, 0xFF00))], [
        (0x0001, 0x0011, [sat_return_link()]),
    ]))
    # 26: NIT without descriptors or multiplexes
    F.append(nit_rmt(0x40, [], []))
    # 27: MMT2
    F.append(mmt2())
    # 28: TDT
    F.append(tdt())
    # 29: SMT
    F.append(smt())
    # 30-37: tables without a decoder: PAT, CAT, PMT, SDT, TCT, PCR, MMT
    # and an unknown table ID
    for tid in (0x00, 0x01, 0x02, 0x42, 0xA2, 0xA6, 0xC0, 0x99):
        F.append(unhandled(tid))
    return [exp_pdu(f) for f in F]


def build_rcs():
    """RCS (DVB-RCS1) decoding: SI section header and CRC; TIM and TDT
    with their DSM-CC style headers."""
    global RCS
    RCS = True
    F = [
        sct(), fct(), spt(), cmt(), tbtp(), tmst(),
        tim_rcs(False), tim_rcs(True), tdt(),
        nit_rmt(0x40, [network_name()], [(0x0001, 0x0002, [sat_forward_link(0)])]),
        nit_rmt(0x41, [], [(0x0001, 0x0011, [])]),
        fat(ctrl_assign()),
        table(0xAB, b"\x00\x01\x02\x03"),   # TCTE: not decoded for RCS
        smt(),
    ]
    RCS = False
    return [exp_pdu(f) for f in F]


def build_malformed():
    F = []
    # 1: the TBTP2 reproducer with an unknown format, five times
    t = table(0xAD, bytes([0x00, 0x00, 0x00, 0x00, 0x04, 0xFF]) +
              b"".join(bytes([i]) + struct.pack(">HH", 0, 0xFFFF) for i in range(256)))
    F += [t] * 5
    # 6: table ID only
    F.append(b"\xAD")
    # 7: TIM with a descriptor loop count beyond the data
    F.append(table(0xB0, b"\x00\x05" + network_name()))
    # 8: SCT cut in the superframe
    F.append(table(0xA0, b"\x00\x01\x02"))
    # 9: BCT with a tx type count beyond the data
    F.append(table(0xAC, b"\x05" + lmbt(0x81)))
    # 10: NIT with a network descriptors length beyond the data
    F.append(table(0x40, struct.pack(">H", 0xF0FF) + network_name()))
    # 11: TBTP2 with an assignment loop beyond the data
    F.append(table(0xAD, bytes([0, 0, 0, 0, 0, 0, 0]) + struct.pack(">HH", 0, 10) + b"\x01" * 6))
    # 12: Network Layer Info descriptor with a broken SNMP PDU
    F.append(tim(True, [d(0xA0, b"\x30\x10\x02\x01")]))
    # 13: TMST that ends with its last mode: each mode is shown as 3
    # octets but only 1 is consumed, so the last item runs past the end
    F.append(table(0xAA, bytes([2, 0x24, 0x49])))
    return [exp_pdu(f) for f in F]


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-s2-table-coverage.pcap"), build_main())
    write_pcap(os.path.join(out, "dvb-s2-table-coverage-rcs.pcap"), build_rcs())
    write_pcap(os.path.join(out, "dvb-s2-table-coverage-malformed.pcap"), build_malformed())
