#!/usr/bin/env python3
# Generates test/captures/dvbci_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DVB-CI (LINKTYPE_DVB_CI 235) coverage captures.

Usage: mkdvbci.py <outdir>

Writes
  dvbci-coverage.pcapng            main capture: interface 0 is DVB-CI,
                                   interface 1 is Exported PDU (252)
  dvbci-coverage-malformed.pcapng  error paths and the reproducers that
                                   decode with error expert infos

Every packet is built here with struct; nothing comes from a real CAM or
host. No keys, no ciphertext: CI+ items that carry key material (DH
values, signatures, nonces, key hashes) are sent with length 0, and the
SAC messages are all in the clear.
"""
import os
import struct
import sys

LT_DVBCI = 235
LT_EXPORTED_PDU = 252
CAM2HOST = 0xFF
HOST2CAM = 0xFE

# ---------------------------------------------------------------- helpers


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82]) + struct.pack(">H", n)


def pseudo(event, payload):
    return struct.pack(">BBH", 0, event, len(payload)) + payload


def lpdu(tcid, tpdu, more=False):
    return bytes([tcid, 0x80 if more else 0x00]) + tpdu


def tpdu_hdr(tag, tcid, body):
    return bytes([tag]) + ber_len(len(body) + 1) + bytes([tcid]) + body


def t_sb(tcid, sb=0x00):
    return bytes([0x80, 0x02, tcid, sb])


def c_tpdu(tcid, body, tag=0xA0):
    """host -> CAM command TPDU"""
    return tpdu_hdr(tag, tcid, body)


def r_tpdu(tcid, body, tag=0xA0, sb=0x00):
    """CAM -> host response TPDU, header and body (if any) and T_SB"""
    hdr = tpdu_hdr(tag, tcid, body) if body is not None else b""
    return hdr + t_sb(tcid, sb)


def apdu(tag, body=b""):
    return struct.pack(">I", tag)[1:] + ber_len(len(body)) + body


def spdu_sess_nb(ssnb, a):
    return bytes([0x90, 0x02]) + struct.pack(">H", ssnb) + a


TCID = 1


def h2c_spdu(spdu, tcid=TCID):
    return pseudo(HOST2CAM, lpdu(tcid, c_tpdu(tcid, spdu)))


def c2h_spdu(spdu, tcid=TCID, sb=0x00):
    return pseudo(CAM2HOST, lpdu(tcid, r_tpdu(tcid, spdu, sb=sb)))


def bcd(n):
    return int(str(n), 16)


def mjd_utc(mjd, h, m, s):
    return struct.pack(">HBBB", mjd, bcd(h), bcd(m), bcd(s))


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
            crc &= 0xFFFFFFFF
    return crc


def section(table_id, ext_id, body, version=1):
    """MPEG long section with CRC"""
    sec_len = 5 + len(body) + 4
    hdr = struct.pack(">BHHBBB", table_id, 0xB000 | sec_len, ext_id,
                      0xC0 | (version << 1) | 1, 0, 0)
    data = hdr + body
    return data + struct.pack(">I", crc32_mpeg2(data))


# ------------------------------------------------------------- ASN.1/X.509

def tlv(t, v):
    return bytes([t]) + ber_len(len(v)) + v


def oid(s):
    p = [int(x) for x in s.split(".")]
    out = bytes([40 * p[0] + p[1]])
    for n in p[2:]:
        enc = [n & 0x7f]
        n >>= 7
        while n:
            enc.insert(0, 0x80 | (n & 0x7f))
            n >>= 7
        out += bytes(enc)
    return tlv(0x06, out)


def SEQ(*a):
    return tlv(0x30, b"".join(a))


def SET(*a):
    return tlv(0x31, b"".join(a))


def INT(n):
    return tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big"))


SHA256RSA = SEQ(oid("1.2.840.113549.1.1.11"), b"\x05\x00")


def name(cn):
    return SEQ(SET(SEQ(oid("2.5.4.3"), tlv(0x0C, cn.encode()))))


def ciplus_cert(cn):
    """X.509 certificate with the four CI+ extensions. The public key
    and the signature are short runs of zero bytes, not real values."""
    exts = SEQ(
        SEQ(oid("1.3.6.1.5.5.7.1.25"), tlv(0x04, SEQ(INT(1), INT(2)))),
        SEQ(oid("1.3.6.1.5.5.7.1.26"), tlv(0x04, tlv(0x03, b"\x07\x80"))),
        SEQ(oid("1.3.6.1.5.5.7.1.27"), tlv(0x04, INT(0x1234))),
        SEQ(oid("1.3.6.1.5.5.7.1.50"), tlv(0x04, INT(1))),
    )
    tbs = SEQ(tlv(0xA0, INT(2)), INT(0x1001), SHA256RSA,
              name("Synthetic CI Plus Root"),
              SEQ(tlv(0x17, b"260101000000Z"), tlv(0x17, b"360101000000Z")),
              name(cn),
              SEQ(SEQ(oid("1.3.6.1.4.1.32473.1")),
                  tlv(0x03, b"\x00\x00\x00")),
              tlv(0xA3, exts))
    return SEQ(tbs, SHA256RSA, tlv(0x03, b"\x00\x00\x00"))


def mud_url_crl():
    """X.509 CRL with an id-pe-mud-url (1.3.6.1.5.5.7.1.25) extension"""
    ext = SEQ(oid("1.3.6.1.5.5.7.1.25"),
              tlv(0x04, tlv(0x16, b"https://mud.example/x")))
    tbs = SEQ(tlv(0x02, b"\x01"), SHA256RSA, SEQ(), tlv(0x17, b"260101000000Z"),
              tlv(0xA0, SEQ(ext)))
    return SEQ(tbs, SHA256RSA, tlv(0x03, b"\x00"))


def exp_pdu(tags, payload):
    out = b""
    for t, v in tags:
        pad = (4 - len(v) % 4) % 4 if t == 12 else 0
        out += struct.pack("!HH", t, len(v) + pad) + v + b"\0" * pad
    return out + struct.pack("!HH", 0, 0) + payload


def exp_pdu_dissector(name_, payload, evt=None):
    tags = [(12, name_.encode())]
    if evt is not None:
        tags.append((31, bytes([evt])))
    return exp_pdu(tags, payload)


# --------------------------------------------------------- capture writers

def blk(t, body):
    body += b"\0" * ((4 - len(body) % 4) % 4)
    return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)


def write_pcapng(path, frames):
    """frames: list of (interface, data[, captured length])"""
    with open(path, "wb") as f:
        f.write(blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        f.write(blk(1, struct.pack("<HHI", LT_DVBCI, 0, 0)))
        f.write(blk(1, struct.pack("<HHI", LT_EXPORTED_PDU, 0, 0)))
        for i, fr in enumerate(frames):
            ifid, data = fr[0], fr[1]
            cap = fr[2] if len(fr) > 2 else len(data)
            ts = (1767225600 + i) * 1000000
            f.write(blk(6, struct.pack("<IIIII", ifid, ts >> 32, ts & 0xFFFFFFFF,
                                       cap, len(data)) + data[:cap]))


# ------------------------------------------------------------- resources

def res(cls, typ=1, ver=1):
    return (cls << 16) | (typ << 6) | ver


RM, AP, CA, AUT, HC, DT, MMI, AMI, LSC, CC, HLC, CUP, OPP, AFS, SAS = (
    res(0x01), res(0x02, ver=3), res(0x03), res(0x10), res(0x20, ver=2),
    res(0x24), res(0x40), res(0x41), res(0x60, ver=4), res(0x8C, ver=2),
    res(0x8D), res(0x8E), res(0x8F), res(0x91), res(0x96))

# session number per resource
SS = {RM: 1, AP: 2, CA: 3, AUT: 4, HC: 5, DT: 6, MMI: 7, AMI: 8, LSC: 9,
      CC: 10, HLC: 11, CUP: 12, OPP: 13, AFS: 14, SAS: 15}


class Cap:
    def __init__(self):
        self.frames = []
        self.notes = []

    def add(self, data, note="", ifid=0, cap=None):
        self.frames.append((ifid, data) if cap is None else (ifid, data, cap))
        self.notes.append(note)
        return len(self.frames)

    def h2c(self, resid, tag, body=b"", note=""):
        return self.add(h2c_spdu(spdu_sess_nb(SS[resid], apdu(tag, body))), note)

    def c2h(self, resid, tag, body=b"", note="", sb=0x00):
        return self.add(c2h_spdu(spdu_sess_nb(SS[resid], apdu(tag, body)), sb=sb), note)


# --------------------------------------------------------- main capture

def cis():
    t = b""
    # device info for attribute memory, with two extension bytes
    t += bytes([0x1D, 0x04, 0x80 | 0x08 | 0x01, 0x81, 0x02, 0xFF])
    # device info for common memory, no extension
    t += bytes([0x1C, 0x02, 0x08, 0xFF])
    # level 1 version: major/minor, manufacturer, name, 2 additional, end
    v1 = b"\x05\x00" + b"Synthetic\0" + b"CI Module\0" + b"Rev A\0" + b"Extra\0" + b"\xFF"
    t += bytes([0x15, len(v1)]) + v1
    # config: rfsz 1, rmsz 1 (2 bytes), rasz 2, last 0x0f, radr, rmsk,
    # 1 reserved byte, CIF subtuple (ifn size 2) and an unknown subtuple
    cif = bytes([0xC0, 0x0A, 0x41, 0x02]) + b"DVB_CI_V1"[:8]
    unk = bytes([0xC1, 0x02, 0x00, 0x00])
    cfg = bytes([0x40 | (1 << 2) | 1, 0x0F, 0xFE, 0x0F, 0x03, 0x00, 0x00]) + cif + unk
    t += bytes([0x1A, len(cfg)]) + cfg
    # config table entries, with and without interface byte
    t += bytes([0x1B, 0x04, 0xCF, 0x04, 0x19, 0x00])
    t += bytes([0x1B, 0x02, 0x0F, 0x08])
    # manufacturer id, no-link tuple (length 0), unknown tuple with data
    t += bytes([0x20, 0x04]) + struct.pack("<HH", 0x02CA, 0x3412)
    t += bytes([0x14, 0x00])
    t += bytes([0x21, 0x02, 0x04, 0x01])
    t += bytes([0xFF])
    return t


def cc_item(dat_id, data=b""):
    return bytes([dat_id]) + struct.pack(">H", len(data)) + data


# content of the items that the dissector decodes; the others (keys,
# nonces, signatures, licenses) are sent with length 0
ITEM_DATA = {0x1E: b"\x00", 0x28: b"\x00", 0x29: b"\x00", 0x2A: b"\x00",
             0x1A: b"\x00\x64", 0x19: b"\x01\x00", 0x1C: b"\x00", 0x26: b"\x00"}


def cc_payload(items, req=None):
    out = b"\x01" + bytes([len(items)]) + b"".join(items)
    if req is not None:
        out += bytes([len(req)]) + bytes(req)
    return out


def sac_msg(ctr, payload, pad=0, sig_len=16):
    body = payload + b"\0" * pad
    hdr = struct.pack(">IBBH", ctr, 0x10, 0x00, len(body))
    return hdr + body + b"\0" * sig_len


def build_main():
    c = Cap()
    # --- hardware events, CIS, COR
    for ev in range(1, 11):
        c.add(pseudo(0xFB, bytes([ev])), "hardware event %d" % ev)
    c.add(pseudo(0xFB, b"\x00"), "unknown hardware event")
    c.add(pseudo(0xFD, cis()), "CIS read")
    c.add(pseudo(0xFD, b"\x15\x03\x05\x00\x41"), "CIS, manufacturer without terminator")
    c.add(pseudo(0xFD, b"\x15\x05\x05\x00\x41\x00\x42"), "CIS, name without terminator")
    c.add(pseudo(0xFD, b"\x15\x08\x05\x00\x41\x00\x42\x00\x43\x44"), "CIS, additional info without terminator")
    c.add(pseudo(0xFC, b"\x0F\xFE\x0F"), "COR write")
    c.add(pseudo(0xFC, b"\xFF\xFF\x0F"), "COR write, unknown address")
    # --- an LPDU before the buffer size negotiation (see the end)
    c.h2c(RM, 0x9F8011, struct.pack(">IIII", RM, AP, CA, DT), "profile before the buffer negotiation, 22 byte LPDU")
    # --- buffer size negotiation
    c.add(pseudo(CAM2HOST, b"\x04\x00"), "CAM buffer size proposal 1024")
    c.add(pseudo(HOST2CAM, b"\x04\x00"), "negotiated buffer size 1024")
    # --- transport connection setup
    c.add(pseudo(HOST2CAM, lpdu(TCID, c_tpdu(TCID, b"", tag=0x82))), "T_create_t_c")
    c.add(pseudo(CAM2HOST, lpdu(TCID, r_tpdu(TCID, b"", tag=0x83))), "T_c_t_c_reply")
    c.add(pseudo(HOST2CAM, lpdu(TCID, c_tpdu(TCID, b"", tag=0x81))), "T_RCV")
    c.add(pseudo(CAM2HOST, lpdu(TCID, r_tpdu(TCID, None, sb=0x80))), "T_SB only, message available")
    c.add(pseudo(CAM2HOST, lpdu(TCID, r_tpdu(TCID, b"", tag=0x86))), "T_request_t_c")
    c.add(pseudo(HOST2CAM, lpdu(TCID, c_tpdu(TCID, b"", tag=0x87))), "T_new_t_c")
    c.add(pseudo(HOST2CAM, lpdu(2, c_tpdu(2, b"", tag=0x82))), "T_create_t_c tcid 2")
    c.add(pseudo(CAM2HOST, lpdu(2, r_tpdu(2, b"", tag=0x83))), "T_c_t_c_reply tcid 2")
    c.add(pseudo(HOST2CAM, lpdu(2, c_tpdu(2, b"", tag=0x84))), "T_delete_t_c tcid 2")
    c.add(pseudo(CAM2HOST, lpdu(2, r_tpdu(2, b"", tag=0x85))), "T_d_t_c_reply tcid 2")
    c.add(pseudo(CAM2HOST, lpdu(3, r_tpdu(3, b"", tag=0x84))), "T_delete_t_c from CAM")
    c.add(pseudo(HOST2CAM, lpdu(3, c_tpdu(3, b"", tag=0x85))), "T_d_t_c_reply from host")
    c.add(pseudo(HOST2CAM, lpdu(TCID, c_tpdu(TCID, b"", tag=0x88))), "T_t_c_error")
    # --- sessions
    for r in (RM, AP, CA, AUT, HC, DT, MMI, AMI, LSC, CC, HLC, CUP, OPP, AFS):
        c.add(c2h_spdu(bytes([0x91, 0x04]) + struct.pack(">I", r)), "open session request")
        c.add(h2c_spdu(bytes([0x92, 0x07, 0x00]) + struct.pack(">IH", r, SS[r])), "open session response")
    # SAS opened by the host with create session
    c.add(h2c_spdu(bytes([0x93, 0x06]) + struct.pack(">IH", SAS, SS[SAS])), "create session")
    c.add(c2h_spdu(bytes([0x94, 0x07, 0x00]) + struct.pack(">IH", SAS, SS[SAS])), "create session response")
    # a session that is refused
    c.add(c2h_spdu(bytes([0x91, 0x04]) + struct.pack(">I", res(0x70))), "open session request, unknown class")
    c.add(h2c_spdu(bytes([0x92, 0x07, 0xF0]) + struct.pack(">IH", res(0x70), 0)), "open session response, error")

    # --- resource manager
    c.h2c(RM, 0x9F8010, note="profile enquiry")
    c.c2h(RM, 0x9F8011, b"".join(struct.pack(">I", r) for r in (RM, AP, CA, DT, MMI, CC)), "profile")
    c.h2c(RM, 0x9F8012, note="profile change")
    # --- application info
    c.h2c(AP, 0x9F8020, note="app info enquiry")
    menu = b"\x15" + "Synthetisches Modul".encode()
    c.c2h(AP, 0x9F8021, b"\x01" + struct.pack(">HH", 0x1234, 0x5678) + bytes([len(menu)]) + menu, "app info")
    c.c2h(AP, 0x9F8021, b"\x02" + struct.pack(">HH", 0x1234, 0x5678) + b"\x00", "app info, empty menu string")
    c.h2c(AP, 0x9F8022, note="enter menu")
    c.c2h(AP, 0x9F8023, note="request CICAM reset")
    c.h2c(AP, 0x9F8024, b"\x01", "datarate info")
    # --- conditional access
    c.h2c(CA, 0x9F8030, note="CA info enquiry")
    c.c2h(CA, 0x9F8031, b"\x0B\x00\x17\x22", "CA info")
    cadesc = b"\x09\x06\x0B\x00\xE1\x01\xAA\xBB"
    es1 = b"\x1B\xE1\x00" + struct.pack(">H", 0xF000 | 1 + 6) + b"\x01" + b"\x09\x04\x0B\x00\xE1\x02"
    es2 = b"\x03\xE1\x01\xF0\x00"
    es3 = b"\x06\xE1\x02\xF0\x01\x01"
    c.h2c(CA, 0x9F8032, b"\x03\x00\x64\xC3" + struct.pack(">H", 0xF000 | 1 + len(cadesc)) + b"\x01" + cadesc + es1 + es2 + es3,
          "CA PMT, program and ES CA descriptors")
    c.h2c(CA, 0x9F8032, b"\x04\x00\x65\xC1\xF0\x00" + es2, "CA PMT, free service")
    c.c2h(CA, 0x9F8033, b"\x00\x64\xC3\x81" + b"\xE1\x00\x81" + b"\xE1\x01\xF1" + b"\xE1\x02\x00", "CA PMT reply")
    c.c2h(CA, 0x9F8033, b"\x00\x65\xC1\x00" + b"\xE1\x00\x00" + b"\xE1\x01\x71", "CA PMT reply, not possible")
    # --- authentication
    c.c2h(AUT, 0x9F8200, b"\x00\x01" + b"challenge", "auth request")
    c.h2c(AUT, 0x9F8201, b"\x00\x01" + b"response", "auth response")
    c.c2h(AUT, 0x9F8200, b"\x00\x02", "auth request, no bytes")
    # --- host control
    c.c2h(HC, 0x9F8400, struct.pack(">HHHH", 0, 0x0001, 0x0002, 0x0003), "tune")
    c.c2h(HC, 0x9F8400, struct.pack(">HHHH", 0x3001, 0x0001, 0x0002, 0x0003), "tune, network id")
    c.c2h(HC, 0x9F8401, b"\x01\x01\x00\x01\x10", "replace")
    c.c2h(HC, 0x9F8402, b"\x01", "clear replace")
    c.h2c(HC, 0x9F8403, note="ask release")
    sat = bytes([0x43, 0x0B]) + bytes([0x01, 0x17, 0x43, 0x75]) + bytes([0x01, 0x92]) + bytes([0x81]) + bytes([0x02, 0x75, 0x00, 0x03])
    pmt = section(0x02, 0x0064, struct.pack(">HH", 0xE100, 0xF000) + b"\x1B\xE1\x00\xF0\x00" + b"\x03\xE1\x01\xF0\x00")
    c.c2h(HC, 0x9F8404, b"\x01" + struct.pack(">H", 0x0064) + struct.pack(">H", 0xF000 | len(sat)) + sat + pmt,
          "tune broadcast request with PMT")
    c.c2h(HC, 0x9F8404, b"\x00" + struct.pack(">H", 0x0065) + b"\xF0\x00", "tune broadcast request, no PMT")
    c.h2c(HC, 0x9F8405, b"\x00", "tune reply ok")
    c.h2c(HC, 0x9F8405, b"\x03", "tune reply error")
    c.c2h(HC, 0x9F8406, b"\x00", "ask release reply")
    # --- date-time
    c.c2h(DT, 0x9F8440, b"\x00", "date-time enquiry, individual")
    c.c2h(DT, 0x9F8440, b"\x0A", "date-time enquiry, every 10 s")
    c.h2c(DT, 0x9F8441, mjd_utc(61041, 12, 34, 56) + struct.pack(">h", -60), "date-time with offset")
    c.h2c(DT, 0x9F8441, mjd_utc(61041, 12, 35, 0), "date-time without offset")
    # --- MMI
    c.c2h(MMI, 0x9F8801, b"\x01\x01", "display control, set MMI mode")
    c.c2h(MMI, 0x9F8801, b"\x02", "display control, get display tables")
    c.h2c(MMI, 0x9F8802, b"\x01\x01", "display reply, MMI mode ack")
    c.h2c(MMI, 0x9F8802, b"\x02" + b"\x01" + b"\x10\x00\x02" + b"\x15", "display reply, display tables")
    c.h2c(MMI, 0x9F8802, b"\xF0", "display reply, unknown command")
    c.c2h(MMI, 0x9F8807, b"\x01\x04" + b"PIN?", "enquiry")
    c.c2h(MMI, 0x9F8807, b"\x00\xFF" + b"\x05" + b"Name", "enquiry, unknown length")
    c.h2c(MMI, 0x9F8808, b"\x01" + b"1234", "answer")
    c.h2c(MMI, 0x9F8808, b"\x00", "answer, cancel")

    def text(t, tag=0x9F8803):
        return apdu(tag, t)
    menu_body = text(b"Main menu") + text(b"Sub") + text(b"") + text(b"Item 1", 0x9F8804) + text(b"Item 2")
    c.c2h(MMI, 0x9F8809, b"\x02" + menu_body, "menu last")
    c.c2h(MMI, 0x9F880A, b"\xFF" + menu_body, "menu more, unknown choices")
    c.c2h(MMI, 0x9F880C, b"\x02" + menu_body, "list last")
    c.c2h(MMI, 0x9F880D, b"\xFF" + menu_body, "list more, unknown items")
    c.h2c(MMI, 0x9F880B, b"\x02", "menu answer")
    c.h2c(MMI, 0x9F880B, b"\x00", "menu answer, cancelled")
    c.c2h(MMI, 0x9F8800, b"\x00", "close MMI immediate")
    c.h2c(MMI, 0x9F8800, b"\x01\x05", "close MMI delay")
    # --- host language & country
    c.c2h(HLC, 0x9F8100, note="host country enquiry")
    c.h2c(HLC, 0x9F8101, b"DEU", "host country")
    c.c2h(HLC, 0x9F8110, note="host language enquiry")
    c.h2c(HLC, 0x9F8111, b"deu", "host language")
    # --- CAM upgrade
    c.c2h(CUP, 0x9F9D01, b"\x00\x00\x00", "firmware upgrade, unknown time")
    c.c2h(CUP, 0x9F9D01, b"\x01\x00\x78", "firmware upgrade, 120 s")
    c.h2c(CUP, 0x9F9D02, b"\x01", "firmware upgrade reply")
    c.c2h(CUP, 0x9F9D03, b"\x32", "firmware upgrade progress 50%")
    c.c2h(CUP, 0x9F9D03, b"\x65", "firmware upgrade progress 101% (warning)")
    c.c2h(CUP, 0x9F9D04, b"\x01", "firmware upgrade complete")
    # --- content control
    c.c2h(CC, 0x9F9001, note="CC open request")
    c.h2c(CC, 0x9F9002, b"\x01", "CC open confirm")
    cert = ciplus_cert("Synthetic Host")
    c.c2h(CC, 0x9F9003, cc_payload([cc_item(0x08, ciplus_cert("Synthetic CICAM")),
                                    cc_item(0x10, cert)],
                                   [0x0D, 0x11, 0x0F, 0x07]),
          "CC data request, authentication step 1, CI+ certificates")
    c.h2c(CC, 0x9F9004, cc_payload([cc_item(0x0D), cc_item(0x11),
                                    cc_item(0x0F, cert), cc_item(0x07, cert)]),
          "CC data confirm, authentication step 2")
    # requested / sent datatype ids that name each protocol step
    steps = [[0x1E], [0x16], [0x05, 0x1E], [0x05, 0x14], [0x1B], [0x1D],
             [0x23], [0x1A, 0x22, 0x19, 0x21], [0x22, 0x25], [0x28], [0x29],
             [0x2A], [0x1E, 0x20]]
    for ids in steps:
        c.c2h(CC, 0x9F9003, cc_payload([cc_item(0x13)], ids), "CC data request, step %s" % ids)
        c.h2c(CC, 0x9F9004, cc_payload([cc_item(i, ITEM_DATA.get(i, b"")) for i in ids]),
              "CC data confirm, step %s" % ids)
    # the remaining item types
    items = [cc_item(0x19, b"\x01\x30\x00"),               # URI v1, copy never, 90 min
             cc_item(0x19, b"\x01\x30\x01"),               # 6 hours
             cc_item(0x19, b"\x01\x30\x02"),               # 12 hours
             cc_item(0x19, b"\x01\x30\x3F"),               # days
             cc_item(0x19, b"\x02\x31\xFF"),               # URI v2, unlimited
             cc_item(0x19, b"\x02\x04\x00"),               # copy free, RCT
             cc_item(0x19, b"\x02\x10\x00"),               # copy no more
             cc_item(0x1A, b"\x00\x64"),
             cc_item(0x1C, b"\x01"),
             cc_item(0x26, b"\x01"),
             cc_item(0x24, b"\xAA\xBB")]
    c.c2h(CC, 0x9F9003, cc_payload(items, []), "CC data request, URI and other items")
    c.c2h(CC, 0x9F9005, note="CC sync request")
    c.h2c(CC, 0x9F9006, b"\x00", "CC sync confirm")
    # clear SAC messages (payload_enc bit 0)
    sac_req = cc_payload([cc_item(0x05, b"\x01\x02\x03\x04\x05\x06\x07\x08"), cc_item(0x1E, b"\x00")], [0x1E])
    c.c2h(CC, 0x9F9007, sac_msg(1, sac_req, pad=3), "CC SAC data request (clear)")
    c.h2c(CC, 0x9F9008, sac_msg(1, cc_payload([cc_item(0x1E, b"\x00")])), "CC SAC data confirm (clear)")
    c.c2h(CC, 0x9F9009, sac_msg(2, b"", pad=16), "CC SAC sync request")
    c.h2c(CC, 0x9F9010, sac_msg(2, b"\x00", pad=15), "CC SAC sync confirm")
    c.h2c(CC, 0x9F9008, sac_msg(3, b""), "CC SAC data confirm, empty payload")
    c.h2c(CC, 0x9F9011, note="CC PIN capabilities request")
    c.c2h(CC, 0x9F9012, b"\x02" + b"\x00" * 5 + b"\x0C", "CC PIN capabilities reply, PIN never changed")
    c.c2h(CC, 0x9F9012, b"\x01" + mjd_utc(61041, 8, 0, 0) + b"\x00", "CC PIN capabilities reply")
    c.h2c(CC, 0x9F9013, b"1234", "CC PIN command")
    c.c2h(CC, 0x9F9014, b"\x02", "CC PIN reply")
    c.c2h(CC, 0x9F9015, b"\x00\x64\x02\x05" + mjd_utc(61041, 20, 15, 0) + b"\x32" + b"\x00" * 15,
          "CC PIN event")
    c.h2c(CC, 0x9F9016, b"\x05" + b"\x00" * 15, "CC PIN playback")
    c.h2c(CC, 0x9F9017, b"0000", "CC PIN MMI request")
    # --- application MMI
    c.c2h(AMI, 0x9F8000, b"\x0B\x05" + b"synthetic.x" + b"init1", "request start")
    c.h2c(AMI, 0x9F8001, b"\x01", "request start ack")
    c.h2c(AMI, 0x9F8002, b"\x00" + b"index.html", "file request, file")
    c.h2c(AMI, 0x9F8002, b"\x01" + b"\x11\x22", "file request, data")
    c.h2c(AMI, 0x9F8002, b"\x02" + bytes(range(16)) + b"pic.png", "file request, file hash")
    c.h2c(AMI, 0x9F8002, b"\x03", "file request, request types")
    html = b"<html>synthetic</html>"
    c.c2h(AMI, 0x9F8003, b"\x01\x00\x0A" + b"index.html" + struct.pack(">I", len(html)) + html, "file ack with file")
    c.c2h(AMI, 0x9F8003, b"\x00\x00\x07" + b"pic.png" + struct.pack(">I", 0), "file ack, file not found")
    c.c2h(AMI, 0x9F8003, b"\x02\x02\x07" + b"pic.png" + struct.pack(">I", 0), "file ack, hash, cached copy valid")
    c.c2h(AMI, 0x9F8003, b"\x01\x01" + b"\x33\x44", "file ack, data")
    c.c2h(AMI, 0x9F8003, b"\x01\x01", "file ack, empty data")
    c.c2h(AMI, 0x9F8003, b"\x01\x03\x00\x01\x02", "file ack, request types")
    c.h2c(AMI, 0x9F8004, b"\x01", "app abort request")
    c.c2h(AMI, 0x9F8005, b"", "app abort ack")
    c.c2h(AMI, 0x9F8004, b"", "app abort request without code")
    c.h2c(AMI, 0x9F8005, b"\x02", "app abort ack")
    # --- low speed communication
    ipv4 = apdu(0x9F8C01, b"\x03\xCF\x14\x01" + b"\x00" * 12 + bytes([192, 0, 2, 1]) + struct.pack(">HB", 80, 1))
    c.c2h(LSC, 0x9F8C00, b"\x01" + ipv4 + b"\x03\x0A", "comms cmd, connect IPv4 TCP 80")
    c.h2c(LSC, 0x9F8C02, b"\x01\x00", "comms reply, connect ack")
    req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    c.c2h(LSC, 0x9F8C03, b"\x01" + req, "comms send last, HTTP request")
    c.h2c(LSC, 0x9F8C02, b"\x06\x01", "comms reply, send ack")
    rsp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    c.h2c(LSC, 0x9F8C06, b"\x02" + rsp[:20], "comms receive more")
    c.h2c(LSC, 0x9F8C05, b"\x03" + rsp[20:], "comms receive last")
    c.c2h(LSC, 0x9F8C04, b"\x04\x00", "comms send more")
    ipv6 = apdu(0x9F8C01, b"\x03\xCF\x14\x02" + bytes.fromhex("20010db8000000000000000000000001") + struct.pack(">HB", 53, 2))
    c.c2h(LSC, 0x9F8C00, b"\x01" + ipv6 + b"\x00\x00", "comms cmd, connect IPv6 UDP 53, infinite timeout")
    ipx = apdu(0x9F8C01, b"\x03\xCF\x14\x07" + b"\x00" * 16 + struct.pack(">HB", 1234, 3))
    c.c2h(LSC, 0x9F8C00, b"\x01" + ipx + b"\x00\x00", "comms cmd, connect unknown IP version")
    host = apdu(0x9F8C01, b"\x04\xCD\x0F\x01" + struct.pack(">H", 443) + b"example.org")
    c.c2h(LSC, 0x9F8C00, b"\x01" + host + b"\x01\x05", "comms cmd, connect hostname TCP 443")
    host2 = apdu(0x9F8C01, b"\x04\xCD\x0F\x02" + struct.pack(">H", 53) + b"example.org")
    c.c2h(LSC, 0x9F8C00, b"\x01" + host2 + b"\x01\x05", "comms cmd, connect hostname UDP 53")
    tel = apdu(0x9F8C01, b"\x01" + b"\x0F\x05\x0123456")
    c.c2h(LSC, 0x9F8C00, b"\x01" + tel + b"\x01\x05", "comms cmd, connect telephone")
    c.c2h(LSC, 0x9F8C00, b"\x02", "comms cmd, disconnect")
    c.c2h(LSC, 0x9F8C00, b"\x04", "comms cmd, enquire status")
    c.c2h(LSC, 0x9F8C00, b"\x03\xFE\x0A", "comms cmd, set params, 1 byte size")
    c.c2h(LSC, 0x9F8C00, b"\x03\x04\x00\x0A", "comms cmd, set params, 2 byte size")
    c.c2h(LSC, 0x9F8C00, b"\x05\x07", "comms cmd, get next buffer")
    c.c2h(LSC, 0x9F8C00, b"\x09", "comms cmd, unknown id")
    for rep, val in ((2, 0), (3, 0), (3, 0xFE), (4, 1), (5, 0), (9, 0xFF)):
        c.h2c(LSC, 0x9F8C02, bytes([rep, val]), "comms reply %d" % rep)
    c.c2h(LSC, 0x9F8C09, note="comms IP config request")
    a6 = lambda n: bytes.fromhex("20010db8") + b"\x00" * 11 + bytes([n])
    c.h2c(LSC, 0x9F8C0A, b"\x40" + bytes.fromhex("020000000001") + a6(2) + b"\xFF" * 8 + b"\x00" * 8
          + a6(1) + a6(1) + b"\x02" + a6(0x35) + a6(0x36), "comms IP config reply, connected")
    c.h2c(LSC, 0x9F8C0A, b"\x00" + bytes.fromhex("020000000001"), "comms IP config reply, disconnected")
    # --- auxiliary file system
    c.c2h(AFS, 0x9F9400, b"\x0B" + b"synthetic.x", "file system offer")
    c.h2c(AFS, 0x9F9401, b"\x01", "file system ack")
    c.h2c(AFS, 0x9F9402, b"\x00" + b"a.txt", "AFS file request")
    c.c2h(AFS, 0x9F9403, b"\x01\x00\x05" + b"a.txt" + struct.pack(">I", len(html)) + html, "AFS file ack")
    # --- operator profile
    c.h2c(OPP, 0x9F9C00, note="operator status request")
    c.c2h(OPP, 0x9F9C01, b"\x21\x8B\x47" + struct.pack(">H", 61041) + b"\x08", "operator status")
    c.h2c(OPP, 0x9F9C02, note="operator NIT request")
    nitbody = (struct.pack(">H", 0xF000 | 7) + b"\x40\x05Synth" +
               struct.pack(">H", 0xF000))
    nit1 = section(0x40, 0x3001, nitbody)
    nit2 = section(0x41, 0x3002, nitbody)
    c.c2h(OPP, 0x9F9C03, struct.pack(">H", len(nit1) + len(nit2)) + nit1 + nit2,
          "operator NIT, CICAM NIT and a NIT other (warning)")
    c.c2h(OPP, 0x9F9C03, b"\x00\x00", "operator NIT, empty")
    c.h2c(OPP, 0x9F9C04, note="operator info request")
    c.c2h(OPP, 0x9F9C05, b"\x09" + struct.pack(">HI", 0x0001, 0x12345678) + b"\x15" + b"\xF3\xC0" + b"deu" + b"\x05Synth",
          "operator info")
    c.c2h(OPP, 0x9F9C05, b"\x01", "operator info, not valid")
    c.h2c(OPP, 0x9F9C06, b"\x82\x01\x16" + b"\x02\x43\x5A" + b"\x01\x00\x01", "operator search start")
    c.h2c(OPP, 0x9F9C06, b"\x00\x00\x00", "operator search start, empty loops")
    c.c2h(OPP, 0x9F9C07, b"\x21\x8B\x47" + struct.pack(">H", 61041) + b"\x08", "operator search status")
    c.h2c(OPP, 0x9F9C08, note="operator exit")
    c.c2h(OPP, 0x9F9C09, struct.pack(">H", 0xF000 | len(sat)) + sat, "operator tune")
    c.h2c(OPP, 0x9F9C0A, b"\x00\x50\x46" + struct.pack(">H", 0x0000 | len(sat)) + sat, "operator tune status")
    c.h2c(OPP, 0x9F9C0A, b"\xFF\x65\x46" + b"\x00\x00", "operator tune status, all done, strength 101 (warning)")
    c.h2c(OPP, 0x9F9C0B, note="operator entitlement ack")
    c.h2c(OPP, 0x9F9C0C, note="operator search cancel")
    # --- specific application support, OIPF
    oipf_id = struct.pack(">Q", 0x0108113101190000)
    c.h2c(SAS, 0x9F9A00, oipf_id, "SAS connect request")
    c.c2h(SAS, 0x9F9A01, oipf_id + b"\x00", "SAS connect confirm, OIPF")
    oipf = b"\x01\x0B\x00" + struct.pack(">I", 7) + b"\x01" + b"\x02\x00\x03DEU"
    c.c2h(SAS, 0x9F9A07, b"\x01" + struct.pack(">H", len(oipf)) + oipf, "SAS async message, OIPF")
    c.c2h(SAS, 0x9F9A01, oipf_id + b"\x01", "SAS connect confirm, not found")
    c.h2c(SAS, 0x9F9A07, b"\x02\x00\x02\xAB\xCD", "SAS async message, data")
    c.add(c2h_spdu(spdu_sess_nb(0x30, apdu(0x9F9A01, oipf_id + b"\x02"))), "SAS connect confirm without a session")
    c.add(h2c_spdu(spdu_sess_nb(0x30, apdu(0x9F9A07, b"\x03\x00\x01\xEF"))), "SAS async message without a session")
    # --- TPDU and LPDU reassembly
    sp = spdu_sess_nb(SS[AP], apdu(0x9F8021, b"\x01" + struct.pack(">HH", 0x1234, 0x5678) + bytes([len(menu)]) + menu))
    c.add(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA1, TCID, sp[:5]) + t_sb(TCID))), "r_tpdu T_data_more")
    c.add(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA0, TCID, sp[5:]) + t_sb(TCID))), "r_tpdu T_data_last, SPDU reassembled")
    tp = c_tpdu(TCID, spdu_sess_nb(SS[DT], apdu(0x9F8441, mjd_utc(61041, 13, 1, 0) + b"\x00\x3C")))
    c.add(pseudo(HOST2CAM, lpdu(TCID, tp[:8], more=True)), "LPDU more")
    c.add(pseudo(HOST2CAM, lpdu(TCID, tp[8:])), "LPDU last, TPDU reassembled")
    # --- session close
    c.h2c(AUT, 0x9F8201, b"\x00\x01", "auth response before close")
    c.add(c2h_spdu(bytes([0x95, 0x02]) + struct.pack(">H", SS[AUT])), "close session request")
    c.add(h2c_spdu(bytes([0x96, 0x03, 0x00]) + struct.pack(">H", SS[AUT])), "close session response")
    c.add(h2c_spdu(bytes([0x96, 0x03, 0xF0]) + struct.pack(">H", 0x77)), "close session response, error")
    # --- warnings that are not errors
    c.add(pseudo(CAM2HOST, lpdu(TCID, r_tpdu(TCID, None, sb=0x42))), "T_SB with unknown value (warning)")
    c.add(pseudo(HOST2CAM, lpdu(TCID, c_tpdu(TCID, b"", tag=0x81))[:1] + b"\x40" + c_tpdu(TCID, b"", tag=0x81)),
          "unknown more/last value (warning)")
    c.add(pseudo(HOST2CAM, lpdu(TCID, c_tpdu(5, b"", tag=0x81))), "T_RCV with tcid mismatch (warning)")
    c.add(pseudo(CAM2HOST, lpdu(TCID, r_tpdu(TCID, b"", tag=0x86)[:-2] + b"\x05\x00")), "T_request_t_c, status tcid differs")
    c.add(pseudo(CAM2HOST, lpdu(TCID, r_tpdu(TCID, b"", tag=0x83).replace(b"\x83\x01\x01", b"\x83\x01\x04"))),
          "T_c_t_c_reply, tcid differs")
    c.add(c2h_spdu(bytes([0x92, 0x07, 0x00]) + struct.pack(">IH", RM, 0x20)), "open session response from the CAM (warning)")
    c.add(h2c_spdu(bytes([0x91, 0x04]) + struct.pack(">I", RM)), "open session request from the host (warning)")
    c.h2c(CA, 0x9F8031, b"\x0B\x00", "CA info from the host (warning)")
    c.c2h(CA, 0x9F8032, b"\x03\x00\x66\xC1\xF0\x00", "CA PMT from the CAM (warning)")
    c.h2c(HLC, 0x9F8441, mjd_utc(61041, 13, 2, 0), "date-time on the HLC session (warning)")
    c.c2h(AP, 0x9F8407, b"", "tune LCN request, not supported (warning)")
    c.add(pseudo(0xFC, b"\x0F\xFF\x0F"), "COR write, address > 0xFFE (warning)")
    c.add(c2h_spdu(bytes([0x91, 0x04]) + struct.pack(">I", res(0x02))), "open session request AP version 1")
    c.add(h2c_spdu(bytes([0x92, 0x07, 0x00]) + struct.pack(">IH", res(0x02), 0x22)), "open session response AP version 1")
    c.add(h2c_spdu(spdu_sess_nb(0x22, apdu(0x9F8024, b"\x00"))), "datarate info on AP version 1 (warning)")
    # LSC message dissection, decoded with dvb-ci.dissect_lsc_msg
    c.add(c2h_spdu(bytes([0x91, 0x04]) + struct.pack(">I", LSC)), "open session request LSC 2")
    c.add(h2c_spdu(bytes([0x92, 0x07, 0x00]) + struct.pack(">IH", LSC, 0x21)), "open session response LSC 2")
    c.add(c2h_spdu(spdu_sess_nb(0x21, apdu(0x9F8C00, b"\x01" + ipv4 + b"\x03\x0A"))), "comms cmd, connect IPv4 TCP 80")
    c.add(c2h_spdu(spdu_sess_nb(0x21, apdu(0x9F8C03, b"\x01" + req))), "comms send last, HTTP request")
    # --- exported PDUs (interface 1)
    c.add(exp_pdu_dissector("ciplus_sac_msg", sac_msg(5, sac_req, pad=3), CAM2HOST),
          "exported SAC message CAM -> host", ifid=1)
    clear = sac_msg(6, cc_payload([cc_item(0x1E, b"\x00")]))
    clear = clear[:4] + bytes([clear[4] | 1]) + clear[5:]
    c.add(exp_pdu_dissector("ciplus_sac_msg", clear, HOST2CAM),
          "exported SAC message host -> CAM, originally encrypted", ifid=1)
    c.add(exp_pdu_dissector("ciplus_sac_msg", clear, 0xFB), "exported SAC message, not a data transfer", ifid=1)
    # --- reproducers
    # CI+ OID override stuck: a truncated CI+ certificate throws a bounds
    # error (packet size limited during capture, not malformed); the MUD
    # URL extension of the following X.509 CRL must keep its meaning
    trunc_cert = b"\x30\x1e" + b"\x30\x1c" + b"\x02\x14" + bytes(range(1, 21)) + b"\x30\x04\x06\x02\x2a\x03"
    fr = h2c_spdu(spdu_sess_nb(SS[CC], apdu(0x9F9004, b"\x01\x01" + cc_item(0x07, trunc_cert))))
    c.add(fr, "CC data confirm with a truncated certificate", cap=len(fr) - 20)
    c.add(exp_pdu_dissector("x509af", mud_url_crl()), "exported X.509 CRL with MUD URL", ifid=1)
    # CA PMT ES loop: an ES with a non-CA descriptor is an error, so
    # it is in the malformed capture. Buffer size two-pass state: the
    # buffer size is renegotiated to 16 bytes at the end; the 22 byte
    # LPDU before the first negotiation must not get "Payload too large"
    # in the second pass
    c.add(pseudo(CAM2HOST, b"\x00\x10"), "CAM buffer size proposal 16")
    c.add(pseudo(HOST2CAM, b"\x00\x10"), "negotiated buffer size 16")
    c.h2c(RM, 0x9F8010, note="profile enquiry, 12 byte LPDU")
    return c


# --------------------------------------------------------- malformed

def build_malformed():
    c = Cap()
    # reproducers from the review
    es = b"\x02\xE1\x00" + b"\xF0\x02" + b"\x01\x0A"
    c.h2c(CA, 0x9F8032, b"\x03\x00\x01\xC1\xF0\x00" + es, "repro dvbci_ca_pmt_es_loop")
    cd = bytes([0x9F, 0x8C, 0x01, 0x05, 0x04, 0x01, 0x00, 0x06, 0x00, 0x50]) + b"host" + b"\x02\x05"
    c.c2h(LSC, 0x9F8C00, b"\x01" + cd, "repro dvbci_small_fixes 1: hostname too short")
    c.h2c(CA, 0x9F8032, b"\x03\x00\x01\xC1\xF0\x06\x01\x09\x03\x01\x00\x01" + b"\x02\xE1\x00\xF0\x00",
          "repro dvbci_small_fixes 2: CA descriptor length 3")
    c.add(h2c_spdu(spdu_sess_nb(1, apdu(0x9F9004, b"\x01\x01" + b"\x07\x00\x00"))), "repro dvbci_ciplus_stuck 1: empty certificate")
    c.add(exp_pdu_dissector("x509af", mud_url_crl()), "repro dvbci_ciplus_stuck 2", ifid=1)
    # more error paths
    c.c2h(LSC, 0x9F8C00, b"\x01" + apdu(0x9F8C01, b"") + b"\x01\x01\x05", "connection descriptor length 0")
    c.c2h(LSC, 0x9F8C00, b"\x02\x00", "disconnect with parameter")
    c.c2h(LSC, 0x9F8C00, b"\x03\x01", "set params, bad length")
    c.h2c(CA, 0x9F8032, b"\x03\x00\x01\xC1\xF0\x03\x01\x0A\x00", "CA PMT, program level non-CA descriptor")
    c.h2c(CA, 0x9F8032, b"\x03\x00\x01\xC1\xF0\x00" + b"\x02\xE1\x00\xF0\x03\x01\x09\x01", "CA PMT, ES CA descriptor length 1")
    c.c2h(RM, 0x9F8011, b"\x00\x01\x00", "profile, length not a multiple of 4")
    c.c2h(CA, 0x9F8031, b"\x0B", "CA info, odd length")
    c.h2c(DT, 0x9F8441, mjd_utc(61041, 1, 2, 3) + b"\x00", "date-time, length 6")
    c.h2c(DT, 0x9F8441, b"\x00\x00\xAA\xBB\xCC", "date-time, invalid BCD")
    c.h2c(MMI, 0x9F8800, b"\x01", "close MMI delay, length 1")
    c.c2h(MMI, 0x9F8801, b"\x01\x01\x00", "display control set mode, length 3")
    c.h2c(MMI, 0x9F8802, b"\x02" + b"AB", "display reply, invalid character table")
    c.c2h(MMI, 0x9F8809, b"\x01" + apdu(0x9F8803, b"T") * 3 + b"\x00\x00\x00\x00", "menu with an invalid item")
    c.c2h(CC, 0x9F9012, b"\x01" + b"\x00\x01\xAA\xBB\xCC" + b"\x00", "PIN capabilities, invalid time")
    c.c2h(CC, 0x9F9015, b"\x00\x64\x02\x05" + b"\x00\x01\xAA\xBB\xCC" + b"\x32" + b"\x00" * 15, "PIN event, invalid time")
    c.c2h(CC, 0x9F9015, b"\x00\x64\x02\x05" + mjd_utc(61041, 20, 15, 0) + b"\x80" + b"\x00" * 15, "PIN event, centiseconds > 100")
    c.c2h(CC, 0x9F9003, b"\x01\x01" + b"\x07\x00\x04" + b"\x30\x02\x30\x00" + b"\x00", "CC data request, broken certificate")
    c.c2h(OPP, 0x9F9C05, b"\x09" + struct.pack(">HI", 1, 2) + b"Synth", "operator info, invalid character table")
    c.c2h(MMI, 0x9F8801, b"", "display control, too short")
    c.h2c(HLC, 0x9F8101, b"DE", "host country, length 2")
    c.add(h2c_spdu(spdu_sess_nb(SS[HLC], b"\x9F\x81\x01\x05DEU")), "APDU length field larger")
    c.add(h2c_spdu(spdu_sess_nb(SS[HLC], b"\x9F\x81\x01\x02DEU")), "APDU length field smaller")
    c.add(h2c_spdu(spdu_sess_nb(SS[HLC], apdu(0x9F8155, b""))), "unknown APDU tag")
    c.add(h2c_spdu(b"\x97\x00"), "unknown SPDU tag")
    c.add(h2c_spdu(b"\x90\x03\x00\x01\x00"), "SPDU length mismatch")
    c.add(pseudo(HOST2CAM, lpdu(TCID, b"\x99\x01\x01")), "invalid c_tpdu tag")
    c.add(pseudo(CAM2HOST, lpdu(TCID, b"\x99\x01\x01" + t_sb(TCID))), "invalid r_tpdu tag")
    c.add(pseudo(HOST2CAM, lpdu(TCID, b"\xA0\x00")), "TPDU length 0")
    c.add(pseudo(HOST2CAM, lpdu(TCID, b"\xA0\x05\x01")), "c_tpdu length mismatch")
    c.add(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA0, TCID, b""))), "r_tpdu without status")
    c.add(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA0, TCID, b"") + b"\x81\x02\x01\x00")), "status tag not T_SB")
    c.add(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA0, TCID, b"") + b"\x80\x03\x01\x00\x00")), "status length 3")
    c.add(pseudo(CAM2HOST, lpdu(TCID, tpdu_hdr(0xA0, TCID, b"") + b"\x80\x02\x07\x00")), "status tcid mismatch")
    c.add(pseudo(HOST2CAM, b"\x00\x08"), "negotiated buffer size 8")
    c.add(pseudo(HOST2CAM, b"\x00"), "short frame")
    c.add(b"\x00\xFE\x00\x05\x01", "pseudo header length mismatch")
    c.add(b"\x01\xFE\x00\x00", "pseudo header version 1")
    c.add(b"\x00\x42\x00\x00", "unknown event")
    c.add(b"\x00\xFE\x00", "3 byte frame")
    # reproducer dvbci_bufsize_expert_range (last: it leaves 16 negotiated)
    c.add(pseudo(CAM2HOST, b"\x00\x10"), "repro dvbci_bufsize_expert_range 1")
    c.add(pseudo(HOST2CAM, b"\x00\x10"), "repro dvbci_bufsize_expert_range 2")
    c.add(h2c_spdu(spdu_sess_nb(1, apdu(0x9F8011, b"\x00\x01\x00\x41" * 4))), "repro dvbci_bufsize_expert_range 3")
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    m = build_main()
    write_pcapng(os.path.join(out, "dvbci-coverage.pcapng"), m.frames)
    b = build_malformed()
    write_pcapng(os.path.join(out, "dvbci-coverage-malformed.pcapng"), b.frames)
    if "-v" in sys.argv:
        for i, n in enumerate(m.notes, 1):
            print("main %d: %s" % (i, n))
        for i, n in enumerate(b.notes, 1):
            print("malformed %d: %s" % (i, n))


if __name__ == "__main__":
    main()
