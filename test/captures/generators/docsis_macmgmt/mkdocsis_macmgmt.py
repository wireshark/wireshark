#!/usr/bin/env python3
# Generates test/captures/docsis_macmgmt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic DOCSIS MAC management captures (LINKTYPE_DOCSIS = 143)
# that cover epan/dissectors/packet-docsis-macmgmt.c.
#
# Every packet is built with struct; nothing comes from a real network.
# Addresses are locally administered (02:00:00:...). Key material,
# certificates, signatures and OCSP responses are opaque placeholder
# bytes with just enough DER structure for the dissector to walk.
#
# Usage: mkdocsis_macmgmt.py <outdir>
import os
import struct
import sys

CM = bytes.fromhex("020000000002")      # cable modem
CMTS = bytes.fromhex("020000000001")    # CMTS
BCAST = bytes.fromhex("01e02f000001")   # DOCSIS all-CMs multicast


def crc16_x25(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u24(v): return struct.pack(">I", v)[1:]
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)


def tlv(t, v):
    """1-byte type, 1-byte length TLV."""
    assert len(v) < 256, (t, len(v))
    return bytes([t, len(v)]) + v


def tlv2(t, v):
    """1-byte type, 2-byte length TLV."""
    return bytes([t]) + u16(len(v)) + v


def tlvs(*items):
    return b"".join(items)


def mgmt(mtype, payload, version=1, rsvd=0, dsap=0, ssap=0, msg_len=None,
         dst=CM, src=CMTS):
    if msg_len is None:
        msg_len = 6 + len(payload)
    hdr = dst + src + struct.pack(">HBBBBBB", msg_len & 0xFFFF, dsap, ssap,
                                  0x03, version, mtype, rsvd)
    return hdr + payload


def docsis(pdu):
    # FC: MAC-specific (0b11), FC_PARM 00001 (MAC management), EHDR_ON 0
    ln = min(len(pdu), 0xFFFF)
    h = struct.pack(">BBH", 0xC2, 0, ln)
    return h + struct.pack("<H", crc16_x25(h)) + pdu


def write_pcap(path, frames, linktype=143):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144,
                            linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i // 10,
                                (i % 10) * 100000, len(fr), len(fr)))
            f.write(fr)


class Cap:
    def __init__(self):
        self.frames = []
        self.sections = []   # (first frame, label)

    def section(self, label):
        self.sections.append((len(self.frames) + 1, label))

    def add(self, *args, **kw):
        self.frames.append(docsis(mgmt(*args, **kw)))

    def raw(self, frame):
        self.frames.append(frame)


M = Cap()      # main capture: valid messages only
X = Cap()      # malformed capture

# A simple docsis_tlv (Appendix C) encoding: Network Access Control on,
# Upstream Channel ID, Max CPE
APPC = tlv(3, b"\x01") + tlv(2, b"\x01") + tlv(18, b"\x04")

# ---------------------------------------------------------------------------
# SYNC, UCD (types 2, 29, 35, 51)
# ---------------------------------------------------------------------------
M.section("SYNC")
M.add(1, u32(0x12345678), dst=BCAST)


def burst(iuc, *subs):
    return bytes([iuc]) + b"".join(subs)


BURST_ALL = burst(
    5,                              # IUC 5 short data
    tlv(1, b"\x02"), tlv(2, b"\x01"), tlv(3, u16(64)), tlv(4, u16(10)),
    tlv(5, b"\x05"), tlv(6, b"\x20"), tlv(7, u16(0x0152)),
    tlv(8, b"\x00"), tlv(9, b"\x08"), tlv(10, b"\x01"), tlv(11, b"\x01"),
    tlv(12, b"\x02"), tlv(13, u16(100)), tlv(14, b"\x01"),
    tlv(15, b"\x01"), tlv(16, b"\x02"), tlv(17, b"\x01"),
    tlv(18, b"\x01"), tlv(19, u16(8)), tlv(20, u16(16)))
BURST_OFDMA = burst(
    13,                             # IUC 13 data profile
    tlv(21, b"\x75\x02\x83\x01"),   # profile: 2 entries
    tlv(22, b"\x10\x02"),           # IR power control
    tlv(99, b"\x01"))               # unknown burst TLV

UCD_TLVS = tlvs(
    tlv(1, b"\x08"),                # symbol rate
    tlv(2, u32(30000000)),          # frequency
    tlv(3, bytes(range(16))),       # preamble pattern
    tlv(4, BURST_ALL),
    tlv(5, burst(1, tlv(1, b"\x01"))),
    tlv(6, bytes(range(8))),        # extended preamble
    tlv(7, b"\x01"), tlv(8, b"\x20"), tlv(9, b"\x04"), tlv(10, b"\x80"),
    tlv(11, u16(0x1234)), tlv(12, u16(3)), tlv(13, u16(4)),
    tlv(14, bytes(range(9))),
    tlv(15, b"\x01"), tlv(16, b"\x01"), tlv(17, b"\x40"),
    tlv(18, u32(0x0000000F)), tlv(19, u32(0x0001000F)),
    tlv(20, b"\x01"), tlv(21, bytes(range(16))),
    tlv(22, b"\x01"),
    tlv(23, BURST_OFDMA),
    tlv(24, u16(0x3FFF)),
    tlv(25, bytes(range(9))),
    tlv(26, b"\x03"), tlv(27, b"\x02"), tlv(28, b"\x01"),
    tlv(29, u32(5000000)),
    tlv(30, u32(0x00100020) + u32(0x01000110)),
    tlv(31, u32(0x00300040)),
    tlv(32, b"\x10"), tlv(33, b"\x12\x34\x56"), tlv(34, b"\x01"),
    tlv(200, b"\xAA\xBB"))          # unknown UCD TLV

M.section("UCD types 2, 29, 35, 51")
M.add(2, b"\x03\x01\x04\x01" + UCD_TLVS, dst=BCAST)
M.add(2, b"\x00\x02\x04\x01" + tlv(1, b"\x04"), dst=BCAST)  # telephony return
M.add(29, b"\x04\x01\x04\x01" + UCD_TLVS, dst=BCAST)
M.add(35, b"\x05\x01\x04\x01" + UCD_TLVS, dst=BCAST)
M.add(51, b"\x06\x01\x04\x01" + UCD_TLVS, version=5, dst=BCAST)

# ---------------------------------------------------------------------------
# MAP v1 / v5
# ---------------------------------------------------------------------------
M.section("MAP v1, v5 (CAT 0 and probe CAT 1)")
ies = u32((0x1234 << 18) | (1 << 14) | 0) + u32((0x3FFF << 18) | (7 << 14) | 100)
M.add(3, b"\x03\x05\x02\x00" + u32(1000) + u32(900) + b"\x00\x05\x06\x0f" + ies,
      dst=BCAST)
M.add(3, b"\x00\x06\x01\x00" + u32(2000) + u32(1900) + b"\x00\x05\x06\x0f" + ies[:4],
      dst=BCAST)
# v5 CAT 0: numie is 2 bytes at offset 2 (top bits) and CAT in byte 3
M.add(3, b"\x03\x05" + u16(2 << 7) + u32(1000) + u32(900) + b"\x00\x05\x06\x0f"
      + ies, version=5, dst=BCAST)
# v5 probe MAP (CAT 1): one probe IE with PW/ST clear (ECT form), one with
# PW set, one with ST set
probes = u32(0x12340000 | 0x8000) + u32(0x12340000 | 0x00010000) + u32(0x00004000 | 0x0005)
M.add(3, b"\x03\x05" + u16((3 << 7) | 1) + u32(1000) + probes, version=5, dst=BCAST)

# ---------------------------------------------------------------------------
# RNG-REQ, RNG-RSP, REG-REQ/RSP, UCC
# ---------------------------------------------------------------------------
M.section("RNG-REQ v1/v5, RNG-RSP")
M.add(4, u16(0x0123) + b"\x01\x00", dst=CMTS, src=CM)
M.add(4, u16(0x0000) + b"\x01\x00", dst=CMTS, src=CM)
M.add(4, u16(0xC123) + b"\x01\x01", version=5, dsap=0x01, ssap=0x23,
      dst=CMTS, src=CM)                         # 3.1 transmit power
M.add(4, u16(0x4123) + b"\x01\x00", version=5, dst=CMTS, src=CM)
M.add(4, u16(0x0123) + b"\x01\x00", version=1, ssap=0x40,
      dst=CMTS, src=CM)                         # 3.0 transmit power
M.add(4, u16(0x0123) + b"\x01\x00", version=4, dst=CMTS, src=CM)

eq = b"\x08\x01\x18\x00" + u16(0x4000) + u16(0xC000) + u16(0x0100) + u16(0xFF00)
ofdma_eq = u24((100 << 12) | 101) + u16(0x2000) + u16(0xE000) + u16(1) + u16(2)
RNGRSP_TLVS = tlvs(
    tlv(1, u32(0xFFFFFF00)), tlv(2, b"\xFE"), tlv(3, u16(0xFFF0)),
    tlv(4, eq), tlv(5, b"\x03"), tlv(6, u32(555000000)), tlv(7, b"\x02"),
    tlv(9, eq), tlv(13, b"\x04"), tlv(14, b"\x40"),
    tlv2(15, ofdma_eq), tlv2(16, ofdma_eq),
    tlv(17, tlv(1, b"\x20") + tlv(2, b"\x01" + u16(200) + b"\x02" + u16(220))
        + tlv(9, b"\x00")),
    tlv(18, tlv(1, b"\x10")),
    tlv(99, b"\x01\x02"))               # unknown -> "unknown TLV" item
M.add(5, u16(0x0123) + b"\x03" + RNGRSP_TLVS)
M.add(5, u16(0x0124) + b"\x00" + tlv(5, b"\x01"))
# commanded power sub-TLVs with other lengths (silently ignored)
M.add(5, u16(0x0125) + b"\x01" + tlv(17, tlv(1, b"\x20\x00") + tlv(2, b"\x01\x02")))

M.section("REG-REQ, REG-RSP, UCC-REQ/RSP")
M.add(6, u16(0x0123) + APPC, dst=CMTS, src=CM)
M.add(7, u16(0x0123) + b"\x00" + APPC)
M.add(8, b"\x02")
M.add(8, b"\x00")
M.add(9, b"\x02", dst=CMTS, src=CM)

# ---------------------------------------------------------------------------
# BPKM-REQ / BPKM-RSP (types 12/13 and the version 5 types 69/70)
# ---------------------------------------------------------------------------
# Placeholder RSA public key: DER SEQUENCE { INTEGER <128 opaque bytes>,
# INTEGER 65537 }. The "modulus" is a fixed filler pattern, not a key.
RSA_PUB = b"\x30\x81\x89\x02\x81\x81\x00" + b"\x5a" * 128 + b"\x02\x03\x01\x00\x01"
# Two minimal OCSP responses: SEQUENCE { ENUMERATED unauthorized(6) },
# no response bytes, so nothing is signed.
OCSP_TWO = b"\x30\x03\x0a\x01\x06" + b"\x30\x03\x0a\x01\x01"
# CMS SignedData skeleton: version 3, no digest algorithms, id-data content
# type without content, no signer infos.
SIGNED_DATA = (b"\x30\x14\x02\x01\x03\x31\x00\x30\x0b\x06\x09"
               b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\x31\x00")


def der(tag, body):
    n = len(body)
    if n < 128:
        return bytes([tag, n]) + body
    if n < 256:
        return bytes([tag, 0x81, n]) + body
    return bytes([tag, 0x82]) + u16(n) + body


# Certificate skeleton: version 3, serial 1, empty issuer and subject
# names, a fixed validity, the placeholder RSA_PUB as the public key and an
# empty signature. It has the X.509 structure and nothing else.
ALG_SHA256RSA = der(0x30, der(0x06, bytes.fromhex("2a864886f70d01010b")))
ALG_RSA = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")))
TBS = der(0x30, der(0xa0, der(0x02, b"\x02")) + der(0x02, b"\x01")
          + ALG_SHA256RSA + der(0x30, b"")
          + der(0x30, der(0x17, b"000101000000Z") + der(0x17, b"491231235959Z"))
          + der(0x30, b"") + der(0x30, ALG_RSA + der(0x03, b"\x00" + RSA_PUB)))
CERT = der(0x30, TBS + ALG_SHA256RSA + der(0x03, b"\x00"))


def a(t, v):
    return tlv2(t, v)


CM_ID = a(5, a(1, b"SN0001") + a(2, b"\x00\x10\x18") + a(3, CM) + a(4, RSA_PUB))
SEC_CAP = a(19, a(21, u16(0x0101) + u16(0x0201)) + a(22, b"\x01"))
SA_DESCR = a(23, a(12, u16(0x2001)) + a(24, b"\x00") + a(20, u16(0x0101)))
TEK_PARAM = a(13, a(8, b"\x11" * 16) + a(9, u32(43200)) + a(10, b"\x03")
              + a(15, b"\x22" * 16))
BPKM_ATTRS_REQ = tlvs(
    a(6, b"synthetic display string"), a(27, u32(0xC0A80001)),
    CM_ID, SEC_CAP, a(12, u16(0x2001)), a(14, b""),
    a(25, a(26, b"\x01") + a(27, u32(0xE0000001))),
    a(61, u64(0x0102030405060708)),
    a(63, u16(0x0017) + b"\x33" * 32),       # key exchange share: opaque
    a(64, b"\x03\x04"),                      # allowed BPI versions
    a(67, b"\x00"), a(68, b"\x01"),
    a(127, b"\xde\xad"),                     # vendor defined
    a(200, b"\x01\x02"),                     # unknown attribute
    a(11, b"\x44" * 20))                     # HMAC digest: opaque
BPKM_ATTRS_RSP = tlvs(
    a(7, b"\x55" * 128),                     # auth key: opaque
    a(9, u32(604800)), a(10, b"\x05"), SA_DESCR, TEK_PARAM,
    a(16, b"\x07"), a(22, b"\x02"),
    a(28, a(17, CERT)), a(62, SIGNED_DATA),               # download parameters
    a(65, OCSP_TWO),
    a(1, b"SN0002"), a(2, b"\x00\x10\x18"), a(3, CM))
M.section("BPKM-REQ/RSP")
M.add(12, b"\x04\x01" + u16(len(BPKM_ATTRS_REQ)) + BPKM_ATTRS_REQ, dst=CMTS, src=CM)
M.add(13, b"\x05\x01" + u16(len(BPKM_ATTRS_RSP)) + BPKM_ATTRS_RSP)
M.add(13, b"\x09\x02" + u16(4) + a(16, b"\x08"))       # Key Reject
M.add(12, b"\x63\x03" + u16(0))                         # unknown code, no attrs
# CMTS designation attribute, every data type, version 5 BPKM
desig = b"".join(a(66, bytes([t]) + (b"\x66" * 20 if t in (0, 5) else b"Name-%d" % t))
                 for t in range(11))
M.add(69, b"\x10\x04" + u16(len(desig)) + desig, version=5, dst=CMTS, src=CM)
certs = tlvs(*[a(t, CERT) for t in (17, 18, 51, 52, 53, 54)])
M.add(70, b"\x05\x05" + u16(len(certs)) + certs, version=5)

# ---------------------------------------------------------------------------
# REG-ACK, DSx, DCC
# ---------------------------------------------------------------------------
M.section("REG-ACK, DSA/DSC/DSD")
M.add(14, u16(0x0123) + b"\x00" + APPC, dst=CMTS, src=CM)
M.add(14, u16(0x0123) + b"\x00", dst=CMTS, src=CM)            # no TLVs
M.add(15, u16(1) + APPC, dst=CMTS, src=CM)
M.add(16, u16(1) + b"\x00" + APPC)
M.add(17, u16(1) + b"\x00" + APPC, dst=CMTS, src=CM)
M.add(18, u16(2) + APPC, dst=CMTS, src=CM)
M.add(19, u16(2) + b"\x00" + APPC)
M.add(20, u16(2) + b"\x00" + APPC, dst=CMTS, src=CM)
M.add(21, u16(3) + u16(0) + u32(0x1001) + APPC, dst=CMTS, src=CM)
M.add(22, u16(3) + b"\x00\x00")

M.section("DCC-REQ/RSP/ACK")
DCC_REQ = tlvs(
    tlv(1, b"\x02"),
    tlv(2, tlv(1, u32(555000000)) + tlv(2, b"\x01") + tlv(3, b"\x01")
        + tlv(4, b"\x08\x10") + tlv(5, b"\x03") + tlv(6, b"\x01")
        + tlv(7, u32(600000000)) + tlv(99, b"\x00")),
    tlv(3, b"\x02"), tlv(4, b"\x02\x01\x04\x01"),
    tlv(6, u16(0x2001) + u16(0x2002)),
    tlv(7, tlv(1, u32(1) + u32(2)) + tlv(2, u16(3) + u16(4))
        + tlv(5, u32(1000)) + tlv(99, b"")),
    tlv(8, CMTS), tlv(31, b"\x04"), tlv(27, b"\x77" * 20),
    tlv(99, b"\x01"))
M.add(23, u16(5) + DCC_REQ)
M.add(24, u16(5) + b"\x00" + tlv(1, tlv(1, u32(1000)) + tlv(2, u64(123456))
                                    + tlv(99, b"")) + tlv(31, b"\x04")
      + tlv(27, b"\x77" * 20) + tlv(99, b""), dst=CMTS, src=CM)
M.add(25, u16(5) + tlv(31, b"\x04") + tlv(27, b"\x77" * 20) + tlv(99, b""))

M.section("INIT-RNG-REQ, DCD")
M.add(30, u16(0x0123) + b"\x01\x02", dst=CMTS, src=CM)
DCD_TLVS = tlvs(
    tlv(23, tlv(2, u16(7)) + tlv(5, b"\x01")
        + tlv(9, tlv(3, u32(0x0A000001)) + tlv(4, u32(0xFFFFFF00))
              + tlv(5, u32(0xE0000001)) + tlv(6, u32(0xFFFFFFFF))
              + tlv(7, u16(1000)) + tlv(8, u16(2000)) + tlv(9, u16(3000))
              + tlv(10, u16(4000)) + tlv(99, b""))
        + tlv(99, b"")),
    tlv(50, tlv(1, b"\x01") + tlv(2, b"\x02") + tlv(3, b"\x01\x02")
        + tlv(4, tlv(1, u16(1)) + tlv(2, CM) + tlv(3, u16(2)) + tlv(4, u16(3))
              + tlv(99, b""))
        + tlv(5, BCAST) + tlv(6, u16(7)) + tlv(43, b"\x08\x03\x00\x10\x18")
        + tlv(99, b"")),
    tlv(51, tlv(1, u32(555000000)) + tlv(2, u16(2)) + tlv(3, u16(3))
        + tlv(4, u16(4)) + tlv(5, u16(5)) + tlv(43, b"\x08\x03\x00\x10\x18")
        + tlv(99, b"")),
    tlv(99, b"\x00"))
M.add(32, b"\x01\x01\x01" + DCD_TLVS, dst=BCAST)

# ---------------------------------------------------------------------------
# MDD (type 33, versions 4 and 5)
# ---------------------------------------------------------------------------
MDD_TLVS = tlvs(
    tlv(1, tlv(1, b"\x01") + tlv(2, u32(555000000)) + tlv(3, b"\x11")
        + tlv(4, b"\x01") + tlv(5, u16(0x0036)) + tlv(6, b"\x01")
        + tlv(7, b"\x4b") + tlv(8, b"\x02") + tlv(9, b"\x01") + tlv(99, b"")),
    tlv(2, tlv(1, b"\x07") + tlv(2, b"\x01\x02\x03") + tlv(99, b"")),
    tlv(3, u32(555000000) + u32(561000000)),
    tlv(4, tlv(1, b"\x01") + tlv(2, b"\x01") + tlv(3, b"\x01") + tlv(99, b"")),
    tlv(5, tlv(1, b"\x03") + tlv(2, u24(0x012345)) + tlv(99, b"")),
    tlv(6, b"\x01"),
    tlv(7, tlv(1, b"\x01") + tlv(2, u16(0x0094)) + tlv(3, b"\x02")
        + tlv(4, b"\x01\x02") + tlv(5, b"\x01") + tlv(6, b"\x03") + tlv(99, b"")),
    tlv(8, b"\x01\x02\x03"),
    tlv(9, b"\x01"), tlv(10, b"\x01"),
    tlv(11, tlv(1, b"\x03") + tlv(2, u16(50)) + tlv(3, b"\x05") + tlv(99, b"")),
    tlv(12, b"\x01"),
    tlv(13, tlv(1, BCAST) + tlv(2, u24(0x0abcde)) + tlv(99, b"")),
    tlv(15, u16(0x0304)), tlv(16, b"\x01"),
    tlv(17, tlv(3, b"\x04") + tlv(4, b"\x00") + tlv(1, b"\x03") + tlv(2, b"\x01")
        + tlv(5, b"\x03")),
    tlv(18, b"\x01"), tlv(19, b"\x02"),
    tlv(20, u32(0x00000FFF)),
    tlv(21, tlv(1, b"\x03") + tlv(2, b"\x02") + tlv(3, b"\x03")
        + tlv(4, u16(204)) + tlv(5, u16(258)) + tlv(6, u16(1218))),
    tlv(22, tlv(2, b"\x02") + tlv(3, b"\x01")),
    tlv(23, tlv(1, b"\x02") + tlv(2, b"\x01")))
M.section("MDD")
M.add(33, b"\x01\x01\x01\x03" + MDD_TLVS, version=4, dst=BCAST)
# Pre-4.0 version only (no ext spectrum), unknown values that give warnings
M.add(33, b"\x02\x01\x01\x03"
      + tlv(17, tlv(1, b"\x03") + tlv(2, b"\x01"))
      + tlv(21, tlv(4, u16(205)) + tlv(5, u16(109)) + tlv(6, u16(1003))
            + tlv(7, b"\x01") + tlv(4, b"\xcc"))
      + tlv(22, tlv(9, b"\x01"))
      + tlv(23, tlv(9, b"\x01"))
      + tlv(17, tlv(9, b"\x01"))
      + tlv(99, b"\x01"), version=5, dst=BCAST)
M.add(33, b"\x03\x01\x01\x03" + tlv(17, tlv(3, b"\x04")), version=4, dst=BCAST)

# ---------------------------------------------------------------------------
# B-INIT-RNG-REQ, DBC, DPV
# ---------------------------------------------------------------------------
M.section("B-INIT-RNG-REQ v4/v5, DBC-REQ (single and two fragments), DBC-RSP/ACK, DPV")
M.add(34, b"\x03\x05\x01\x02", version=4, dst=CMTS, src=CM)
M.add(34, b"\x03\x05\x01\x02", version=4, ssap=0x30, dst=CMTS, src=CM)
M.add(34, b"\x03\x05\x01\x02", version=5, dsap=0x01, ssap=0x10, dst=CMTS, src=CM)
M.add(36, u16(0x0101) + b"\x01\x01" + APPC)
# Two fragments of transaction 0x0102, sent in order
M.add(36, u16(0x0102) + b"\x02\x01" + APPC[:3])
M.add(36, u16(0x0102) + b"\x02\x02" + APPC[3:])
M.add(37, u16(0x0101) + b"\x00" + APPC, dst=CMTS, src=CM)
M.add(38, u16(0x0101) + APPC)
dpv = u16(9) + b"\x01\x80" + u32(0x1001) + u16(3) + b"\x01\x02" + u32(1000) + u32(2000)
M.add(39, dpv)
M.add(40, dpv, dst=CMTS, src=CM)

# ---------------------------------------------------------------------------
# CM-STATUS, CM-STATUS-ACK, CM-CTRL
# ---------------------------------------------------------------------------
M.section("CM-STATUS (every event type), CM-STATUS-ACK")
EV = tlv(1, tlv(2, b"synthetic event") + tlv(4, b"\x01") + tlv(5, b"\x02")
         + tlv(6, u24(0x012345)) + tlv(7, CM) + tlv(8, b"\x03") + tlv(9, b"\x04")
         + tlv(99, b"\x00"))
for i, ev in enumerate(list(range(1, 12)) + [12] + list(range(16, 28))):
    M.add(41, u16(0x100 + i) + bytes([ev]) + (EV + tlv(99, b"") if ev == 1 else
                                              tlv(1, tlv(4, b"\x01"))),
          dst=CMTS, src=CM)
M.add(48, u16(0x100) + b"\x01")
M.add(48, u16(0x101) + b"\x13")

M.section("CM-CTRL-REQ/RSP")
M.add(42, u16(7) + tlv(1, b"\x01") + tlv(2, u32(300)) + tlv(3, b"\x01")
      + tlv(4, b"\x01")
      + tlv(5, tlv(1, b"\x02") + tlv(2, b"\x00\x0f") + tlv(99, b""))
      + tlv(6, tlv(1, b"\x03") + tlv(2, b"\x00\x0f") + tlv(99, b""))
      + tlv(7, b"\x00\x01") + tlv(99, b"\x00"))
M.add(42, u16(8) + tlv(5, b"\x01") + tlv(6, b"\x01"))
M.add(43, u16(7) + tlv(1, b"\x00") + tlv(2, b"\x00") + tlv(3, b"\x00")
      + tlv(4, b"\x00") + tlv(5, b"\x00") + tlv(6, b"\x00") + tlv(7, b"\x00"),
      dst=CMTS, src=CM)

M.section("REG-REQ-MP, REG-RSP-MP (single and two fragments), EM-REQ/RSP")
M.add(44, u16(0x0123) + b"\x01\x01" + APPC, dst=CMTS, src=CM)
M.add(45, u16(0x0123) + b"\x00\x01\x01" + APPC)
M.add(45, u16(0x0124) + b"\x00\x02\x01" + APPC[:4])
M.add(45, u16(0x0124) + b"\x00\x02\x02" + APPC[4:])
M.add(46, u16(11) + b"\x01\x00", dst=CMTS, src=CM)
M.add(46, u16(12) + b"\x09\x00", dst=CMTS, src=CM)
M.add(47, u16(11) + b"\x00\x00")
M.add(47, u16(12) + b"\x02\x00" + tlv(1, u16(30)) + tlv(9, b"\x01"))
M.add(47, u16(13) + b"\x09\x00")

# ---------------------------------------------------------------------------
# OCD, DPD (version 5)
# ---------------------------------------------------------------------------
OCD_TLVS = tlvs(
    tlv(0, b"\x01"), tlv(1, b"\x02"), tlv(2, b"\x03"), tlv(3, u32(600000000)),
    tlv(4, b"\x10"),
    tlv(5, b"\x00" + u32((100 << 16) | 200)),           # continuous range
    tlv(5, b"\x40" + u32((300 << 16) | 400)),           # skip by 1
    tlv(5, b"\x80" + u16(10) + u16(11) + u16(12)),      # list of 3
    tlv(5, b"\xc0" + u32(0)),                           # unknown type
    tlv(6, b"\x01"), tlv(7, b"\x01"),
    tlv(99, b"\x01\x02"))
M.section("OCD (single and two-part multipart), DPD")
M.add(49, b"\x07\x01" + OCD_TLVS, version=5, dst=BCAST)
M.add(49, b"\x08\x01" + OCD_TLVS[:20], version=5, rsvd=0x10, dst=BCAST)
M.add(49, b"\x08\x01" + OCD_TLVS[20:], version=5, rsvd=0x11, dst=BCAST)
DPD_TLVS = tlvs(
    tlv(5, b"\x08" + u32((100 << 16) | 200)),
    tlv(5, b"\x49" + u32((300 << 16) | 400)),
    tlv(5, b"\x8a" + u16(10) + u16(11)),
    tlv(5, b"\xcf" + u32(0)),
    tlv2(6, u16(0x8010) + b"\x12\x34\x56"),             # odd
    tlv2(6, u16(0x0010) + b"\x12\x34"),                 # even
    tlv(99, b"\x01"))
M.add(50, b"\x07\x01\x01" + DPD_TLVS, version=5, dst=BCAST)
M.add(50, b"\x07\x00\x01", version=5, dst=BCAST)
# Small fixes reproducer (docsis_macmgmt_small_fixes.py frames 7-9): a
# vector, list or index list as the last TLV of the message
M.add(50, bytes([1, 0, 1]) + bytes([6]) + u16(3) + b"\x00\x10\x44", version=5, dst=BCAST)
M.add(50, bytes([1, 0, 1]) + tlv(5, b"\x84\x00\x01\x00\x02\x00"), version=5, dst=BCAST)
M.add(49, bytes([1, 1]) + tlv(5, b"\x80\x00\x01\x00\x02\x00"), version=5, dst=BCAST)

# ---------------------------------------------------------------------------
# OPT-REQ/RSP/ACK, RBA
# ---------------------------------------------------------------------------
M.section("OPT-REQ/RSP/ACK (single and multipart), RBA-SW/HW")
OPTREQ_TLVS = tlvs(
    tlv(1, b"\x7f"),
    tlv(2, tlv(1, b"\x08") + tlv(9, b"\x00")),
    tlv(7, tlv(1, b"\x01") + tlv(2, u16(512)) + tlv(3, u16(0x123))
        + tlv(4, b"\x02") + tlv(5, u32(4000)) + tlv(6, b"\x01")
        + tlv(7, u32(5000)) + tlv(9, b"")),
    tlv(9, b"\x00"))
M.add(54, u16(0) + b"\x07\x01\x01" + OPTREQ_TLVS, version=5)
M.add(54, u16(0) + b"\x07\xff\x02", version=5)
# OPT-REQ small fix: measurement duration 1280 (> 1024) now gets a warning
M.add(54, u16(0) + b"\x07\x02\x01" + tlv(7, tlv(2, u16(1280))), version=5)
M.add(54, u16(0) + b"\x08\x01\x01" + OPTREQ_TLVS[:6], version=5, rsvd=0x10)
M.add(54, u16(0) + b"\x08\x01\x01" + OPTREQ_TLVS[6:], version=5, rsvd=0x11)
OPTRSP_TLVS = tlvs(
    tlv2(1, tlv2(1, b"\x10\x20\x30") + tlv2(2, b"\xf0\x0f") + tlv2(3, u16(5))
         + tlv2(4, b"\x02") + tlv2(5, b"\x30") + tlv2(6, b"\x05")
         + tlv2(9, b"\x00")),
    tlv2(2, tlv2(1, u32(1000)) + tlv2(2, u32(10)) + tlv2(3, u32(1))
         + tlv2(4, b"\x01") + tlv2(9, b"")),
    tlv2(3, tlv2(1, u32(500)) + tlv2(2, u32(2)) + tlv2(3, b"\x00")
         + tlv2(9, b"")),
    tlv2(9, b"\x00"))
M.add(55, u16(0) + b"\x07\x01\x01" + OPTRSP_TLVS, version=5, dst=CMTS, src=CM)
M.add(55, u16(0) + b"\x07\xff\x09", version=5, dst=CMTS, src=CM)
M.add(56, u16(0) + b"\x07\x01", version=5)
M.add(56, u16(0) + b"\x07\x10", version=5)
rba = b"\x01\x02\x03\xc0" + u32(1000) + u32(2000) + b"\x03\x00\x01\x02"
M.add(61, rba, version=5, dst=BCAST)
M.add(62, rba[:12] + b"\x00", version=5, dst=BCAST)

# ---------------------------------------------------------------------------
# CWT, ECT, EXT-RNG-REQ, DPR (version 5, DOCSIS 4.0 FDX)
# ---------------------------------------------------------------------------
M.section("CWT-REQ/RSP, ECT-REQ/RSP, EXT-RNG-REQ, DPR")
CWT_TLVS = tlvs(
    tlv(1, b"\x02"), tlv(2, u16(500)),
    tlv(3, tlv(1, b"\x05") + tlv(2, u16(10) + u16(20)) + tlv(3, b"\x04")
        + tlv(9, b"")),
    tlv(9, b""))
M.add(63, b"\x01\x00\x01" + CWT_TLVS, version=5)
M.add(63, b"\x02\x01\x02" + tlv(2, u16(2000)), version=5)     # out of range
M.add(63, b"\x03\x01\x09", version=5)
M.add(64, b"\x01\x00\x01\x00" + tlv(1, b"\x02"), version=5, dst=CMTS, src=CM)
M.add(64, b"\x02\x01\x09\x09", version=5, dst=CMTS, src=CM)
# Small fixes reproducer frames 3, 4 and 10
M.add(63, bytes([1, 0, 1]) + tlv(3, tlv(2, b"\x00\x05")), version=5)
M.add(64, bytes([1, 0, 1, 2]), version=5, dst=CMTS, src=CM)
M.add(63, bytes([1, 0, 1]) + tlv(3, tlv(2, b"\x00\x05") + tlv(1, b"\x07"))
      + tlv(1, b"\x00") + tlv(1, b"\x00"), version=5)
# CWT multipart (two parts)
M.add(63, b"\x04\x00\x01" + CWT_TLVS[:3], version=5, rsvd=0x10)
M.add(63, b"\x04\x00\x01" + CWT_TLVS[3:], version=5, rsvd=0x11)
M.add(64, b"\x04\x00\x01\x00" + CWT_TLVS[:3], version=5, rsvd=0x10, dst=CMTS, src=CM)
M.add(64, b"\x04\x00\x01\x00" + CWT_TLVS[3:], version=5, rsvd=0x11, dst=CMTS, src=CM)

ECT_CTRL = tlv(87, tlvs(
    tlv(1, b"\x00\x01\x02"), tlv(2, b"\x01"),
    tlv(3, tlv(1, tlv(1, b"\x10") + tlv(2, b"\x05") + tlv(3, b"\x20")
                  + tlv(4, b"\x01") + tlv(9, b""))
        + tlv(2, tlv(1, u16(100)) + tlv(2, b"\x05") + tlv(3, b"\x20")
                 + tlv(4, u32(123456)) + tlv(9, b""))
        + tlv(9, b"")),
    tlv(4, tlv(1, b"\x01\x02") + tlv(2, b"\x03\x04") + tlv(9, b"")),
    tlv(5, b"\x10"), tlv(6, b"\x20"), tlv(9, b"")))
ECT_BAD = tlv(87, tlvs(
    tlv(3, tlv(1, tlv(1, b"\x00") + tlv(2, b"\x00") + tlv(3, b"\x00"))
        + tlv(2, tlv(1, u16(0)) + tlv(2, b"\x1f") + tlv(3, b"\x00"))),
    tlv(6, b"\x00")))
M.add(65, u16(1) + ECT_CTRL + tlv(9, b""), version=5)
M.add(65, u16(2) + ECT_BAD, version=5)
M.add(66, u16(1) + b"\x00" + ECT_CTRL, version=5, dst=CMTS, src=CM)
M.add(66, u16(2) + b"\x09", version=5, dst=CMTS, src=CM)
# Unsolicited ECT-RSP (transaction ID 255), deferral times 0 and 1
M.add(66, u16(255) + b"\x00" + tlv(87, tlv(5, b"\x00") + tlv(5, b"\x01")),
      version=5, dst=CMTS, src=CM)
M.add(65, u16(3) + ECT_CTRL[:10], version=5, rsvd=0x10)
M.add(65, u16(3) + ECT_CTRL[10:], version=5, rsvd=0x11)
M.add(66, u16(3) + b"\x00" + ECT_CTRL[:10], version=5, rsvd=0x10, dst=CMTS, src=CM)
M.add(66, u16(3) + b"\x00" + ECT_CTRL[10:], version=5, rsvd=0x11, dst=CMTS, src=CM)
M.add(67, u16(0x0123) + b"\x01\x02", version=5, dsap=0x01, ssap=0x40,
      dst=CMTS, src=CM)
M.add(68, b"\x80\x01\x02\x00" + u32(1000) + u32(0x00001000), version=5)
M.add(68, b"\x00\x01\x02\x00" + u32(1000) + u32(0x01000000), version=5)

# ---------------------------------------------------------------------------
# Multipart RNG-RSP and BPKM, message types without a dissector
# ---------------------------------------------------------------------------
M.section("RNG-RSP and BPKM-RSP multipart, unknown types and MAP version")
M.add(5, u16(0x0130) + b"\x03" + RNGRSP_TLVS[:30], version=5, rsvd=0x10)
M.add(5, u16(0x0130) + b"\x03" + RNGRSP_TLVS[30:], version=5, rsvd=0x11)
M.add(70, b"\x05\x06" + u16(len(BPKM_ATTRS_RSP)) + BPKM_ATTRS_RSP[:100],
      version=5, rsvd=0x10)
M.add(70, b"\x05\x06" + u16(len(BPKM_ATTRS_RSP)) + BPKM_ATTRS_RSP[100:],
      version=5, rsvd=0x11)
for t in (10, 11, 26, 27, 28, 31, 52, 53, 57, 58, 59, 60, 71, 255):
    M.add(t, b"\x01\x02\x03\x04", version=5 if t > 48 else 1)
M.add(3, b"\x03\x05\x02\x00" + u32(1000), version=2, dst=BCAST)

# Small fixes reproducer frames 1 and 2 (UCD OFDMA IR power control as
# the last sub-TLV, and followed by another sub-TLV)
M.section("UCD IR power control (small fixes reproducer)")
M.add(2, bytes([1, 1, 2, 3]) + tlv(23, bytes([13]) + tlv(22, b"\x10\x20")), dst=BCAST)
M.add(2, bytes([1, 1, 2, 3]) + tlv(23, bytes([13]) + tlv(22, b"\x10\x20")
                                   + tlv(1, b"\x01")), dst=BCAST)

# ---------------------------------------------------------------------------
# Reproducer of the uint16_t TLV offset hang: an OCD sent as a two-part
# multipart message whose reassembled TLV block is 80000 bytes, all TLVs
# well formed (docsis_macmgmt_ocd_multipart_wrap.py). Before the fix the
# offset wrapped at 65536 and the walk never ended.
# ---------------------------------------------------------------------------
M.section("OCD multipart message with 80000 bytes of TLVs (hang reproducer)")
wrap = bytearray()
wrap += bytes([0xFE, 0])
wrap += bytes([0xFE, 254]) + b"\x00" * 254
while len(wrap) < 80000:
    wrap += bytes([0xFE, 255]) + b"\x00" * 255
M.add(49, bytes([7, 1]) + bytes(wrap[:40000]), version=5, rsvd=0x10, dst=BCAST)
M.add(49, bytes([7, 1]) + bytes(wrap[40000:]), version=5, rsvd=0x11, dst=BCAST)
OCD_WRAP_TLVS = 2 + (len(wrap) - 258) // 257

# ===========================================================================
# Malformed capture
# ===========================================================================


def sweep(cap, label, wrap_fn, types, enc=tlv, lengths=(0, 3, 7)):
    """One frame per length: every type in 'types' with that length."""
    cap.section(label)
    for ln in lengths:
        body = b"".join(enc(t, b"\x01" * ln) for t in types)
        cap.raw(docsis(wrap_fn(body)))


X.section("msg_len below 6, fragment sequence 0 (reproducers)")
for mtype in (1, 2, 5, 49):
    for ml in (0, 5):
        X.add(mtype, b"\x00\x01\x02\x03" + bytes(36), version=5 if mtype == 49 else 1,
              msg_len=ml)
for n, s in [(2, 0), (2, 3), (255, 0)]:
    X.add(36, bytes([0, 9, n, s]) + APPC)
    X.add(45, bytes([0, 9, 0, n, s]) + APPC)
# Small fixes frame 6: MDD diplexer sub-TLV with a bad length, then a good one
X.add(33, bytes([1, 1, 1, 3]) + tlv(21, tlv(1, b"\x00\x00\x00") + tlv(2, b"\x05")),
      version=4)

sweep(X, "UCD TLVs, bad lengths", lambda b: mgmt(2, b"\x03\x01\x04\x01" + b),
      range(1, 36))
sweep(X, "UCD burst TLVs, bad lengths",
      lambda b: mgmt(2, b"\x03\x01\x04\x01" + tlv(4, b"\x05" + b)), range(1, 24))
sweep(X, "RNG-RSP TLVs, bad lengths", lambda b: mgmt(5, u16(1) + b"\x01" + b),
      [t for t in range(1, 20) if t not in (15, 16)])
sweep(X, "BPKM attributes, bad lengths",
      lambda b: mgmt(13, b"\x05\x01" + u16(len(b)) + b), list(range(0, 70)) + [127],
      enc=tlv2, lengths=(0, 3))
sweep(X, "DCC-REQ TLVs, bad lengths", lambda b: mgmt(23, u16(1) + b), range(1, 33))
sweep(X, "DCC-REQ DS parameters, bad lengths",
      lambda b: mgmt(23, u16(1) + tlv(2, b)), range(1, 9))
sweep(X, "DCC-REQ SF substitution, bad lengths",
      lambda b: mgmt(23, u16(1) + tlv(7, b)), range(1, 7))
sweep(X, "DCC-RSP TLVs, bad lengths", lambda b: mgmt(24, u16(1) + b"\x00" + b),
      [1, 27, 31])
sweep(X, "DCC-RSP CM jump time, bad lengths",
      lambda b: mgmt(24, u16(1) + b"\x00" + tlv(1, b)), [1, 2])
sweep(X, "DCC-ACK TLVs, bad lengths", lambda b: mgmt(25, u16(1) + b), [27, 31])
sweep(X, "DCD DSG config, bad lengths", lambda b: mgmt(32, b"\x01\x01\x01" + tlv(51, b)),
      range(1, 6))
sweep(X, "DCD classifier, bad lengths", lambda b: mgmt(32, b"\x01\x01\x01" + tlv(23, b)),
      [2, 5])
sweep(X, "DCD classifier IP, bad lengths",
      lambda b: mgmt(32, b"\x01\x01\x01" + tlv(23, tlv(9, b))), range(3, 11))
sweep(X, "DCD DSG rule, bad lengths", lambda b: mgmt(32, b"\x01\x01\x01" + tlv(50, b)),
      [1, 2, 5, 6])
sweep(X, "DCD client ID, bad lengths",
      lambda b: mgmt(32, b"\x01\x01\x01" + tlv(50, tlv(4, b))), range(1, 5))
sweep(X, "MDD DOCSIS version, diplexer, ABP, BPI+, 3.1 events, bad lengths",
      lambda b: mgmt(33, b"\x01\x01\x01\x03" + b, version=4), [17, 20, 21, 22, 23])
sweep(X, "MDD DOCSIS version sub-TLVs, bad lengths",
      lambda b: mgmt(33, b"\x01\x01\x01\x03" + tlv(17, b), version=4), range(1, 6))
sweep(X, "MDD diplexer band edge, bad lengths",
      lambda b: mgmt(33, b"\x01\x01\x01\x03" + tlv(21, b), version=4), range(1, 7))
sweep(X, "MDD ABP and BPI+ sub-TLVs, bad lengths",
      lambda b: mgmt(33, b"\x01\x01\x01\x03" + tlv(22, b) + tlv(23, b[:-6] if len(b) > 6 else b),
                     version=4), [1, 2, 3])
sweep(X, "CM-STATUS event TLVs, bad lengths",
      lambda b: mgmt(41, u16(1) + b"\x01" + tlv(1, b)), range(1, 10))
X.add(41, u16(1) + b"\x01" + tlv(1, tlv(2, b"\x41" * 81)))
sweep(X, "CM-CTRL TLVs, bad lengths", lambda b: mgmt(42, u16(1) + b), range(1, 8))
sweep(X, "CM-CTRL DS/US event, bad lengths",
      lambda b: mgmt(42, u16(1) + tlv(5, b) + tlv(6, b)), [1, 2])
sweep(X, "OCD TLVs, bad lengths", lambda b: mgmt(49, b"\x07\x01" + b, version=5),
      range(0, 8))
sweep(X, "DPD TLVs, bad lengths",
      lambda b: mgmt(50, b"\x07\x01\x01" + b + bytes([6]) + u16(1) + b"\x00", version=5),
      [5])
sweep(X, "OPT-REQ TLVs, bad lengths",
      lambda b: mgmt(54, u16(0) + b"\x07\x01\x01" + b, version=5), [1])
sweep(X, "OPT-REQ RxMER thresholds, bad lengths",
      lambda b: mgmt(54, u16(0) + b"\x07\x01\x01" + tlv(2, b), version=5), [1])
sweep(X, "OPT-REQ trigger definition, bad lengths",
      lambda b: mgmt(54, u16(0) + b"\x07\x01\x01" + tlv(7, b), version=5), range(1, 8))
sweep(X, "OPT-RSP RxMER, bad lengths",
      lambda b: mgmt(55, u16(0) + b"\x07\x01\x01" + tlv2(1, b), version=5),
      range(3, 7), enc=tlv2)
sweep(X, "OPT-RSP data CW, bad lengths",
      lambda b: mgmt(55, u16(0) + b"\x07\x01\x01" + tlv2(2, b), version=5),
      range(1, 5), enc=tlv2)
sweep(X, "OPT-RSP NCP fields, bad lengths",
      lambda b: mgmt(55, u16(0) + b"\x07\x01\x01" + tlv2(3, b), version=5),
      range(1, 4), enc=tlv2)
sweep(X, "CWT TLVs, bad lengths",
      lambda b: mgmt(63, b"\x01\x00\x01" + b, version=5), [1, 2])
sweep(X, "CWT US encodings, bad lengths",
      lambda b: mgmt(63, b"\x01\x00\x01" + tlv(3, b), version=5), [1, 2, 3])
sweep(X, "ECT control, bad lengths",
      lambda b: mgmt(65, u16(1) + tlv(87, b), version=5), [2, 5, 6])
sweep(X, "ECT foreground, bad lengths",
      lambda b: mgmt(65, u16(1) + tlv(87, tlv(3, tlv(1, b))), version=5), range(1, 5))
sweep(X, "ECT background, bad lengths",
      lambda b: mgmt(65, u16(1) + tlv(87, tlv(3, tlv(2, b))), version=5), range(1, 5))

X.section("Sub-TLV lists that do not end at the parent length")
# "pos != end": a trailing single byte inside the parent
X.add(13, b"\x05\x01" + u16(4) + tlv2(13, tlv2(10, b"\x01") + b"\x00"))
X.add(13, b"\x05\x01" + u16(9) + tlv2(10, b"\x01"))          # BPKM length too big
X.add(13, b"\x05\x01" + u16(4) + tlv2(10, b"\x01") + b"\x00\x00")
big = (tlv2(1, b"S" * 256) + tlv2(6, b"D" * 129) + tlv2(5, tlv2(1, b"1"))
       + tlv2(21, b"\x01\x01\x01") + tlv2(200, b"\x00" * 1488))
X.add(13, b"\x05\x01" + u16(len(big)) + big)
X.add(12, b"\x04\x01" + u16(2) + tlv2(10, b"\x01"), dst=CMTS, src=CM)
X.add(33, b"\x01\x01\x01\x03" + tlv(17, tlv(3, b"\x04") + b"\x00")
      + tlv(22, tlv(2, b"\x02") + b"\x00") + tlv(23, tlv(1, b"\x01") + b"\x00"),
      version=4)
X.add(55, u16(0) + b"\x07\x01\x01" + tlv2(1, tlv2(4, b"\x01") + b"\x00")
      + tlv2(2, tlv2(4, b"\x01") + b"\x00") + tlv2(3, tlv2(3, b"\x01") + b"\x00")
      + b"\x00", version=5)
X.add(63, b"\x01\x00\x01" + tlv(3, tlv(2, b"\x00\x01\x02") + b"\x00") + b"\x00", version=5)
X.add(65, u16(1) + tlv(87, tlv(3, tlv(1, tlv(4, b"\x01") + b"\x00")
                               + tlv(2, tlv(4, u32(1)) + b"\x00") + b"\x00")
                       + tlv(4, tlv(1, b"\x01") + b"\x00") + b"\x00") + b"\x00",
      version=5)
# DPD subcarrier assignment vector with length < 2, OCD/DPD list < 5
X.add(50, b"\x07\x01\x01" + bytes([6]) + u16(1) + b"\x00", version=5)
X.add(50, b"\x07\x01\x01" + tlv(5, b"\x08\x00"), version=5)

X.section("Truncated fixed fields (exceptions)")
for t in (1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
          24, 25, 29, 30, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 54, 55, 56, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70):
    X.add(t, b"", version=5 if t >= 49 else 1)
# MAP v1 with more IEs than present; RNG-RSP equalizer coefficients cut short
X.add(3, b"\x03\x05\x09\x00" + u32(1000) + u32(900) + b"\x00\x05\x06\x0f" + u32(0))
X.add(5, u16(1) + b"\x01" + b"\x04\x08" + b"\x08\x01\x18\x00\x00\x01")
X.add(5, u16(1) + b"\x01" + b"\x11\x06" + tlv(2, b"\x01\x00\x10"))
X.add(13, b"\x05\x01" + u16(10) + tlv2(65, b"\x30\x03\x0a\x01"))   # OCSP cut short
X.add(13, b"\x05\x01" + u16(5) + tlv2(65, b"\x05\x00"))            # OCSP: not a SEQUENCE

# ==== MAIN


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "docsis-macmgmt-coverage.pcap"), M.frames)
    # The 64 KiB uint16_t-wrap reproducers (docsis_macmgmt_pos_wrap.py)
    PLEN = 0xFFFF - 6

    def chain(fixed, last_t=0xFE):
        o = bytearray(b"\x00" * fixed)
        o += bytes([0xFE, 0]) + bytes([0xFE, 254]) + b"\x00" * 254
        for i in range(254):
            o += bytes([last_t if i == 253 else 0xFE, 255]) + b"\x00" * 255
        del o[PLEN:]
        o += b"\x00" * (PLEN - len(o))
        return bytes(o)
    X.section("64 KiB messages whose TLV offset used to wrap (reproducers)")
    for mtype, ver, fixed, last_t in ((23, 1, 2, 0xFE), (24, 1, 3, 0xFE),
                                      (25, 1, 2, 0xFE), (32, 1, 3, 0xFE),
                                      (41, 1, 3, 0xFE), (42, 1, 2, 0xFE),
                                      (49, 5, 2, 0x00)):
        X.add(mtype, chain(fixed, last_t), version=ver)
    write_pcap(os.path.join(out, "docsis-macmgmt-coverage-malformed.pcap"), X.frames)
    for name, cap in (("main", M), ("malformed", X)):
        print("%s: %d frames" % (name, len(cap.frames)))
        for first, label in cap.sections:
            print("  %4d %s" % (first, label))


if __name__ == "__main__":
    main()
