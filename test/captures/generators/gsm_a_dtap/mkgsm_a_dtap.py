#!/usr/bin/env python3
# Generates test/captures/gsm_a_dtap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GSM A DTAP coverage captures. Usage: mkgsm_a_dtap.py <outdir>

Every frame is Ethernet/IPv4/SCTP/M3UA/SCCP/BSSAP (DTAP), the A interface
as a real capture has it (SCTP port 2905 and PPID 3 are registered by
default, the SCCP connection is opened with a CR whose called party
address has SSN 254).  The DTAP messages are built from the message
and element tables of packet-gsm_a_dtap.c (TABLE at the end of this file)
with pseudo random element contents; KEEP lists, per message, the seeds
whose frames dissect without malformed packets or error expert infos.
"""
import random
import struct
import sys

# ---------------------------------------------------------------- transport
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctp_data(payload, tsn, ppid=3):
    ch = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, ppid) + payload
    ch += b"\0" * (-len(ch) % 4)
    hdr = struct.pack("!HHII", 2905, 2905, 0x1234, 0)
    return hdr[:8] + struct.pack("<I", crc32c(hdr + ch)) + ch


def ip_eth(proto, l4):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + l4


def m3ua_data(sccp, opc=1, dpc=2):
    prot = struct.pack("!IIBBBB", opc, dpc, 3, 2, 0, 0) + sccp
    p = struct.pack("!HH", 0x0210, 4 + len(prot)) + prot
    p += b"\0" * (-len(p) % 4)
    return struct.pack("!BBBBI", 1, 0, 1, 1, 8 + len(p)) + p


_tsn = [100]


def wrap(sccp):
    _tsn[0] += 1
    return ip_eth(132, sctp_data(m3ua_data(sccp), _tsn[0]))


def sccp_cr(src, ssn=254):
    return bytes([1]) + src + bytes([2, 2, 0]) + bytes([2, 0x42, ssn])


def sccp_cc(dst, src):
    return bytes([2]) + dst + src + bytes([2, 0])


def sccp_dt1(dst, data):
    return bytes([6]) + dst + bytes([0, 1, len(data)]) + data


def bssap_dtap(dtap, dlci=0):
    return bytes([1, dlci, len(dtap)]) + dtap


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1700000000 + i // 1000, (i % 1000) * 1000, len(p), len(p)))
            f.write(p)
    print("wrote %d packets to %s" % (len(pkts), path))


SRC_REF = b"\x00\x00\x01"
DST_REF = b"\x00\x00\x02"


def dtap_frame(dtap):
    return wrap(sccp_dt1(DST_REF, bssap_dtap(dtap)))


def open_conn():
    return [wrap(sccp_cr(SRC_REF)), wrap(sccp_cc(SRC_REF, DST_REF))]


# --------------------------------------------------- table driven messages
def build(rng, elems, k, pd, only_opt=False):
    out = b""
    for macro, iei in elems:
        opt = macro.startswith("ELEM_OPT")
        if only_opt and not opt:
            continue
        if opt and k % 3 != 0 and rng.random() < 0.5:
            continue
        kind = macro.split("_", 2)[2]
        gen = CONTENT.get((pd, iei)) if iei is not None else None
        iei = iei if iei is not None else rng.getrandbits(8)
        n = rng.choice([1, 1, 2, 3, 4, 5, 6, 8, 10, 12, 16])
        val = gen(rng) if gen else rbytes(rng, n)
        if kind == "V":
            out += rbytes(rng, rng.choice([1, 1, 2, 3, 4]))
        elif kind == "LV":
            out += lv(rbytes(rng, n))
        elif kind == "LV_E":
            out += struct.pack("!H", n) + rbytes(rng, n)
        elif kind == "TLV":
            out += bytes([iei & 0xff, len(val)]) + val
        elif kind == "TLV_E":
            out += bytes([iei & 0xff]) + struct.pack("!H", len(val)) + val
        elif kind == "TV":
            out += bytes([iei & 0xff]) + (val[:TV_SIZE[(pd, iei)]].ljust(TV_SIZE[(pd, iei)], b"\x11")
                                          if (pd, iei) in TV_SIZE else rbytes(rng, rng.choice([1, 2, 3])))
        elif kind == "TV_SHORT":
            out += bytes([(iei & 0xf0) | rng.getrandbits(4)])
        elif kind == "VV_SHORT":
            out += rbytes(rng, 1)
        elif kind == "T":
            out += bytes([iei & 0xff])
    return out


def table_msg(pd, v, k, ti=0):
    rng = random.Random("%d-%d-%d" % (pd, v, k))
    sp = special(pd, v, rng)
    if sp is not None:
        body = sp + build(rng, TABLE[(pd, v)], k, pd, only_opt=True)
    else:
        body = build(rng, TABLE[(pd, v)], k, pd)
    if ti == 0x70:
        return bytes([ti | pd, 0x01, v]) + body
    return bytes([ti | pd, v]) + body


def pool(K):
    """All candidate frames: list of (pd, v, k, frame)"""
    out = []
    for (pd, v), el in sorted(TABLE.items()):
        if el is None:
            continue
        for k in range(K):
            ti = [0x00, 0x80, 0x10, 0x70][k % 4] if pd in (0, 1, 3, 9, 11) else 0
            out.append((pd, v, k, dtap_frame(table_msg(pd, v, k, ti))))
    return out


# ------------------------------------------- element content generators
def bcd(digits):
    """TBCD, low nibble first, 0xf filler"""
    d = [int(c, 16) if c not in "*#" else {"*": 10, "#": 11}[c] for c in digits]
    if len(d) % 2:
        d.append(0xf)
    return bytes(d[i] | (d[i + 1] << 4) for i in range(0, len(d), 2))


def rdigits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


LAI = bytes([0x62, 0xf2, 0x10, 0x00, 0x07])


def mid(rng):
    """Mobile identity (without the length)."""
    t = rng.choice([1, 1, 2, 3, 4, 0, 5])
    if t == 4:
        return bytes([0xf4]) + bytes(rng.getrandbits(8) for _ in range(4))
    if t == 0:
        return bytes([0xf0])
    if t == 5:
        return bytes([0xf5]) + bytes(rng.getrandbits(8) for _ in range(rng.choice([4, 5])))
    s = rdigits(rng, rng.choice([14, 15, 15, 16]))
    odd = len(s) % 2
    first = (int(s[0]) << 4) | (odd << 3) | t
    return bytes([first]) + bcd(s[1:])


def lv(b):
    return bytes([len(b)]) + b


def cm2(rng):
    return bytes([rng.choice([0x57, 0x33, 0x23, 0x7f]), rng.getrandbits(8) & 0x7f,
                  rng.getrandbits(8) & 0x7f])


def bearer_cap(rng):
    """Bearer capability value: octet 3 and a chain of extension octets."""
    itc = rng.choice([0, 0, 1, 2, 3, 5, 7])
    o3 = (rng.getrandbits(1) << 6) | (rng.getrandbits(2) << 5) | (rng.getrandbits(1) << 4) \
        | (rng.getrandbits(1) << 3) | itc
    if rng.random() < 0.5:
        o3 &= 0x7f              # extension bit clear: octet 3a follows
    else:
        o3 |= 0x80
    out = [o3]
    n = rng.choice([0, 1, 2, 3, 5, 8, 11])
    for i in range(n):
        out.append(rng.getrandbits(7) | (0x80 if i == n - 1 else 0))
    return bytes(out)


def facility(rng):
    arg = bytes([0x30, 0x0a, 0x04, 0x01, 0x0f, 0x04, 0x05, 0xaa, 0x18, 0x0c, 0x36, 0x02])
    kind = rng.choice([0xa1, 0xa1, 0xa2, 0xa3, 0xa4])
    if kind == 0xa1:
        body = bytes([2, 1, rng.randint(0, 5), 2, 1, rng.choice([0x3b, 0x3c, 0x0b, 0x11])]) + arg
    elif kind == 0xa2:
        body = bytes([2, 1, 1]) + bytes([0x30, 3 + len(arg), 2, 1, 0x3b]) + arg
    elif kind == 0xa3:
        body = bytes([2, 1, 1, 2, 1, rng.choice([1, 11, 34])])
    else:
        body = bytes([2, 1, 1, 0x80, 1, rng.randint(0, 3)])
    return bytes([kind, len(body)]) + body


def calling_bcd(rng):
    ext = rng.random() < 0.5
    ton_npi = (rng.choice([0, 1, 2, 3]) << 4) | rng.choice([0, 1, 3, 9])
    d = bcd(rdigits(rng, rng.choice([5, 8, 11, 12])))
    if ext:
        return bytes([0x80 | ton_npi]) + d
    return bytes([ton_npi, 0x80 | (rng.getrandbits(2) << 5) | rng.getrandbits(2)]) + d


def called_bcd(rng):
    return bytes([0x80 | (rng.choice([0, 1, 2, 4]) << 4) | rng.choice([1, 9, 0])]) + \
        bcd(rdigits(rng, rng.choice([6, 9, 10])) + rng.choice(["", "*", "#", "*#"]))


def sub_addr(rng):
    k = rng.choice([0, 1, 2])
    if k == 0:      # NSAP, IA5 digits
        return bytes([0x80, 0x50]) + bytes(rng.choice([0x12, 0x34, 0x56, 0x78]) for _ in range(rng.randint(1, 5))) \
            + (bytes([0x99]) if rng.random() < 0.3 else b"")
    if k == 1:      # NSAP, other AFI
        return bytes([0x80, 0x39]) + bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 6)))
    return bytes([0xa0 | (rng.getrandbits(1) << 3)]) + bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 6)))


CAUSES = [1, 3, 6, 8, 13, 16, 17, 18, 19, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 34, 38, 41, 42, 43, 44, 47,
          49, 50, 55, 57, 58, 63, 65, 68, 69, 70, 79, 81, 87, 88, 91, 95, 96, 97, 98, 99, 100, 101, 102, 111,
          127, 2, 40, 60, 70, 90, 110, 120]


def cause(rng):
    c = rng.choice(CAUSES)
    out = bytes([0x80 | (rng.getrandbits(2) << 5) | rng.choice([0, 1, 2, 4, 5, 10]), 0x80 | c])
    if rng.random() < 0.5:
        out += bytes([0x80 | rng.getrandbits(7)]) if c in (17, 29, 34, 50, 55, 69, 87) else \
            bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 3)))
    return out


def emerg(rng, zero=False):
    out = b""
    for _ in range(rng.choice([1, 2, 3])):
        d = bcd(rdigits(rng, rng.choice([3, 3, 5])) + (rng.choice(["", "*"]) if rng.random() < 0.15 else ""))
        out += bytes([len(d) + 1, rng.getrandbits(5)]) + d
    if zero:
        out += b"\x00"
    return out


def net_name(rng):
    cs = rng.choice([0, 0, 1, 2])
    spare = rng.choice([0, 0, 1, 3, 5])
    if cs == 1:
        txt = "Neté".encode("utf-16-be")
    else:
        txt = bytes(rng.getrandbits(8) for _ in range(rng.choice([4, 7, 10])))
    return bytes([0x80 | (cs << 4) | (rng.getrandbits(1) << 3) | spare]) + txt


def supp_codecs(rng):
    out = b""
    for sysid in rng.sample([0, 1, 2, 4, 5, 0xfa, 0x20], rng.choice([1, 2, 3])):
        bm = bytes(rng.getrandbits(8) for _ in range(rng.choice([1, 2])))
        out += bytes([sysid, len(bm)]) + bm
    return out


def user_user(rng):
    return bytes([rng.choice([0, 1, 2, 3, 4, 5, 0x10, 0x7f])]) + bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 10)))


def llc(rng):
    out = [0x80 | rng.getrandbits(7)]
    for i in range(rng.choice([1, 2, 4, 7])):
        out.append(rng.getrandbits(7) | (0x80 if i % 3 == 2 else 0))
    return bytes(out)


def timer(rng):
    return bytes([(rng.choice([0, 1, 2, 3, 7]) << 5) | rng.getrandbits(5)])


CONTENT = {   # (pd, iei) -> generator(rng) -> value bytes
    (3, 0x04): bearer_cap, (3, 0x41): bearer_cap,
    (3, 0x08): cause, (11, 0x08): lambda r: bytes([0x80 | r.randint(1, 5)]),
    (3, 0x1c): facility, (3, 0x1b): facility, (3, 0x1d): facility, (11, 0x1c): facility,
    (3, 0x1e): lambda r: bytes([0x80 | r.choice([0, 1, 2, 4, 5]), 0x80 | r.randint(1, 10)]),
    (3, 0x34): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x5c): calling_bcd, (3, 0x4c): calling_bcd, (3, 0x74): calling_bcd,
    (3, 0x5e): called_bcd,
    (3, 0x5d): sub_addr, (3, 0x4d): sub_addr, (3, 0x6d): sub_addr, (3, 0x75): sub_addr,
    (3, 0x7e): user_user, (0, 0x7e): user_user, (1, 0x7e): user_user,
    (3, 0x40): supp_codecs, (3, 0x7c): llc, (3, 0x7d): llc,
    (3, 0x2d): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x2e): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x2f): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x24): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x15): lambda r: bytes(r.getrandbits(8) for _ in range(r.randint(1, 3))),
    (3, 0x19): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x3a): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x7b): lambda r: bytes([r.getrandbits(8)]),
    (3, 0x7f): lambda r: bytes([r.getrandbits(8)]),
    (5, 0x17): mid, (0, 0x17): mid, (1, 0x17): mid,
    (5, 0x34): emerg,
    (5, 0x36): timer,
    (5, 0x35): timer,
    (5, 0x43): net_name, (5, 0x45): net_name,
    (5, 0x48): lambda r: bytes(r.getrandbits(8) for _ in range(r.choice([0, 3]))),
    (5, 0x49): lambda r: bytes([r.getrandbits(2)]),
    (5, 0x4a): lambda r: LAI[:3] + bytes([0x62, 0xf2, 0x20]),
    (5, 0x33): cm2,
    (5, 0x20): lambda r: bytes(r.getrandbits(8) for _ in range(r.choice([16, 16, 10]))),
    (5, 0x21): lambda r: bytes(r.getrandbits(8) for _ in range(r.randint(1, 12))),
    (5, 0x22): lambda r: bytes(r.getrandbits(8) for _ in range(r.choice([14, 14, 9]))),
    (5, 0x19): lambda r: bytes(r.choice([0x62, 0xf2, 0x10]) for _ in range(6)),
    (5, 0x1b): lambda r: LAI + b"\x01",
}
TV_SIZE = {(5, 0x13): 5, (5, 0x46): 1, (5, 0x47): 7, (3, 0x2c): 1, (3, 0x34): 1}


def seqkey(rng, sixbit=False):
    k = rng.choice([0, 1, 5, 7])
    return bytes([k << 4 | rng.choice([0, 1, 2, 3])]) if sixbit else bytes([k])


def rbytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def call_ref(rng):
    return struct.pack("!I", rng.getrandbits(32))


def special(pd, v, rng):
    """Mandatory part of messages whose first octet has no element of its own."""
    if (pd, v) == (5, 0x08):        # location updating request
        t = rng.choice([0, 1, 2])
        return bytes([(rng.choice([0, 3, 7]) << 4) | (rng.getrandbits(1) << 3) | t]) + LAI + \
            bytes([rng.choice([0x57, 0x33])]) + lv(mid(rng))
    if (pd, v) == (5, 0x24):        # CM service request
        return bytes([(rng.choice([0, 3, 7]) << 4) | rng.choice([1, 2, 4, 8, 9, 10, 11, 5, 6])]) + lv(cm2(rng)) + lv(mid(rng))
    if (pd, v) == (5, 0x28):        # CM re-establishment request
        return seqkey(rng) + lv(cm2(rng)) + lv(mid(rng))
    if (pd, v) == (5, 0x18):        # identity request
        return bytes([rng.choice([1, 2, 3, 4, 5, 0, 6])])
    if (pd, v) == (5, 0x1a):        # TMSI reallocation command
        return LAI + lv(mid(rng))
    if (pd, v) == (5, 0x12):        # authentication request
        return seqkey(rng) + rbytes(rng, 16)
    if (pd, v) == (5, 0x1c):        # authentication failure
        return bytes([rng.choice([20, 21, 22, 23])])
    if (pd, v) == (5, 0x14):        # authentication response
        return rbytes(rng, 4)
    if (pd, v) in ((0, 0x31), (1, 0x31)):   # GCC / BCC immediate setup
        return seqkey(rng) + lv(cm2(rng)) + lv(mid(rng)) + call_ref(rng)
    if (pd, v) == (1, 0x3b):        # BCC immediate setup 2
        return seqkey(rng) + lv(cm2(rng)) + rbytes(rng, 1) + call_ref(rng) + rbytes(rng, rng.randint(1, 4))
    if (pd, v) == (15, 0x00):       # close TCH loop command
        return bytes([rng.choice([0x00, 0x02, 0x04, 0x08, 0x10, 0x18, 0x38, 0x01, 0x20])])
    if (pd, v) == (15, 0x40):       # close UE test loop (UMTS)
        mode = rng.choice([0, 0, 1, 2, 3])
        out = bytes([rng.getrandbits(6) << 2 | mode])
        if mode == 0:
            n = rng.choice([3, 6, 12, 15])
            out += bytes([n]) + rbytes(rng, n)
        elif mode == 2:
            out += bytes([rng.getrandbits(5)])
        return out
    if (pd, v) in ((15, 0x80), (15, 0x06)):   # close UE test loop (EPC), open loop command
        mode = rng.randint(0, 7)
        out = bytes([rng.getrandbits(5) << 3 | mode])
        if mode == 0:
            n = rng.choice([3, 6, 9, 27])
            out += bytes([n]) + rbytes(rng, n)
        elif mode == 1:
            out += rbytes(rng, 1)
        elif mode == 2:
            out += rbytes(rng, 3)
        elif mode == 3:
            n = rng.choice([1, 3, 5])
            out += struct.pack("!H", n) + bytes([rng.getrandbits(1)]) + rbytes(rng, n - 1)
        elif mode == 4:
            n = rng.choice([1, 2, 4])
            out += bytes([n, rng.getrandbits(1)]) + rbytes(rng, n - 1)
        elif mode == 5:
            out += rbytes(rng, 2)
        else:
            out += rbytes(rng, 2)
        return out
    if (pd, v) == (15, 0x8b):       # update UE location information
        return rbytes(rng, 8 + 3 + 3)
    return None

# ---- generated from packet-gsm_a_dtap.c by extract.py
TABLE = {
    (0, 0): None,
    (0, 49): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 126)],
    (0, 50): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 126)],
    (0, 51): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (0, 52): [('ELEM_MAND_LV', None)],
    (0, 53): [('ELEM_MAND_V', None)],
    (0, 54): [('ELEM_MAND_LV', None)],
    (0, 56): [('ELEM_MAND_LV', None), ('ELEM_OPT_TV_SHORT', 160), ('ELEM_OPT_TV_SHORT', 176)],
    (0, 57): [('ELEM_OPT_TLV', 23)],
    (0, 58): [('ELEM_MAND_V', None)],
    (1, 0): None,
    (1, 49): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None)],
    (1, 50): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 126)],
    (1, 51): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (1, 52): [('ELEM_MAND_LV', None)],
    (1, 53): [('ELEM_MAND_V', None)],
    (1, 54): [('ELEM_MAND_LV', None)],
    (1, 56): [('ELEM_MAND_LV', None), ('ELEM_OPT_TV_SHORT', 160), ('ELEM_OPT_TV_SHORT', 176)],
    (1, 57): [('ELEM_OPT_TLV', 23)],
    (1, 58): [('ELEM_MAND_V', None)],
    (1, 59): [('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (3, 0): None,
    (3, 1): [('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 30), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 127)],
    (3, 2): [('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 30), ('ELEM_OPT_TV_SHORT', 128), ('ELEM_OPT_TLV', 47)],
    (3, 3): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 126)],
    (3, 4): [('ELEM_MAND_LV', None)],
    (3, 5): [('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 30), ('ELEM_OPT_TV', 52), ('ELEM_OPT_TLV', 92), ('ELEM_OPT_TLV', 93), ('ELEM_OPT_TLV', 94), ('ELEM_OPT_TLV', 109), ('ELEM_OPT_TLV', 116), ('ELEM_OPT_TLV', 117), ('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TV_SHORT', 128), ('ELEM_OPT_TLV', 25), ('ELEM_OPT_TLV', 47), ('ELEM_OPT_TLV', 58), ('ELEM_OPT_TLV', 65), ('ELEM_OPT_TLV', 127), ('ELEM_OPT_T', 161), ('ELEM_OPT_T', 162), ('ELEM_OPT_TLV', 21), ('ELEM_OPT_TLV', 29), ('ELEM_OPT_TLV', 27), ('ELEM_OPT_TLV', 45), ('ELEM_OPT_TLV', 64), ('ELEM_OPT_T', 163)],
    (3, 6): [('ELEM_OPT_TV_SHORT', 208), ('ELEM_MAND_TLV', 4), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 64)],
    (3, 7): [('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 30), ('ELEM_OPT_TLV', 76), ('ELEM_OPT_TLV', 77), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 127), ('ELEM_OPT_TLV', 45)],
    (3, 8): [('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 21), ('ELEM_OPT_TLV', 45), ('ELEM_OPT_TLV', 64)],
    (3, 9): [('ELEM_OPT_TLV', 21)],
    (3, 11): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None)],
    (3, 14): [('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 45), ('ELEM_OPT_TLV', 64), ('ELEM_OPT_TLV', 46)],
    (3, 15): None,
    (3, 16): [('ELEM_MAND_LV', None), ('ELEM_OPT_T', 160)],
    (3, 19): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125)],
    (3, 23): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_T', 163), ('ELEM_OPT_T', 164)],
    (3, 24): None,
    (3, 25): None,
    (3, 26): [('ELEM_MAND_LV', None)],
    (3, 28): None,
    (3, 29): None,
    (3, 30): [('ELEM_MAND_LV', None)],
    (3, 31): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_T', 163)],
    (3, 37): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 30), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 123), ('ELEM_OPT_TLV', 127)],
    (3, 42): [('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 127)],
    (3, 45): [('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 127)],
    (3, 49): None,
    (3, 50): None,
    (3, 52): None,
    (3, 53): [('ELEM_MAND_TV', 44)],
    (3, 54): [('ELEM_MAND_TV', 44)],
    (3, 55): [('ELEM_MAND_LV', None)],
    (3, 57): [('ELEM_OPT_TLV', 8)],
    (3, 58): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 127)],
    (3, 61): [('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 36)],
    (3, 62): [('ELEM_MAND_V', None)],
    (5, 0): None,
    (5, 1): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None)],
    (5, 2): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 23), ('ELEM_OPT_T', 161), ('ELEM_OPT_T', 162), ('ELEM_OPT_TLV', 74), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TV_SHORT', 208)],
    (5, 4): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 54)],
    (5, 8): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TV_SHORT', 224)],
    (5, 17): None,
    (5, 18): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 32)],
    (5, 20): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 33)],
    (5, 24): [],
    (5, 25): [('ELEM_MAND_LV', None), ('ELEM_OPT_TV_SHORT', 224), ('ELEM_OPT_TLV', 27), ('ELEM_OPT_TLV', 25)],
    (5, 26): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None)],
    (5, 27): None,
    (5, 28): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 34)],
    (5, 33): None,
    (5, 34): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 54)],
    (5, 35): None,
    (5, 36): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV_SHORT', 128), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TV_SHORT', 208)],
    (5, 37): [('ELEM_MAND_V', None)],
    (5, 38): None,
    (5, 40): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 19), ('ELEM_OPT_TV_SHORT', 208)],
    (5, 41): [('ELEM_MAND_V', None)],
    (5, 48): None,
    (5, 49): [('ELEM_MAND_V', None)],
    (5, 50): [('ELEM_OPT_TLV', 67), ('ELEM_OPT_TLV', 69), ('ELEM_OPT_TV', 70), ('ELEM_OPT_TV', 71), ('ELEM_OPT_TLV', 72), ('ELEM_OPT_TLV', 73)],
    (9, 0): None,
    (9, 1): [('ELEM_MAND_LV', None)],
    (9, 4): None,
    (9, 16): [('ELEM_MAND_V', None)],
    (11, 0): None,
    (11, 42): [('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 28), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 127)],
    (11, 58): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 127)],
    (11, 59): [('ELEM_MAND_TLV', 28), ('ELEM_OPT_TLV', 127)],
    (15, 0): None,
    (15, 1): None,
    (15, 6): [('ELEM_MAND_V', None)],
    (15, 12): None,
    (15, 13): None,
    (15, 16): None,
    (15, 20): [('ELEM_MAND_V', None)],
    (15, 32): [('ELEM_MAND_V', None)],
    (15, 33): [('ELEM_MAND_V', None)],
    (15, 34): None,
    (15, 35): None,
    (15, 36): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (15, 37): [('ELEM_MAND_V', None)],
    (15, 38): [('ELEM_MAND_V', None)],
    (15, 64): [('ELEM_MAND_V', None)],
    (15, 65): None,
    (15, 66): None,
    (15, 67): None,
    (15, 68): None,
    (15, 69): None,
    (15, 70): None,
    (15, 71): None,
    (15, 72): [('ELEM_MAND_V', None)],
    (15, 73): None,
    (15, 74): [('ELEM_MAND_V', None)],
    (15, 128): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV_E', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (15, 129): None,
    (15, 130): None,
    (15, 131): None,
    (15, 132): [('ELEM_MAND_V', None)],
    (15, 133): None,
    (15, 134): None,
    (15, 135): None,
    (15, 136): [('ELEM_MAND_V', None)],
    (15, 137): None,
    (15, 138): [('ELEM_MAND_V', None)],
    (15, 139): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (15, 140): None,
    (15, 141): None,
    (15, 142): None,
    (15, 143): None,
}

# ---- seeds that dissect cleanly (keep.py)
KEEP = {
    (0, 49): [0, 1, 3, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 20, 21, 23, 25, 29, 35, 36, 39],
    (0, 50): [2, 3, 16, 21, 25, 28, 37],
    (0, 51): [0, 7],
    (0, 52): [0, 2, 3, 4, 8, 11, 29],
    (0, 53): [11],
    (0, 54): [3, 5, 6, 9, 19, 20, 27, 28, 30],
    (0, 56): [2, 3, 6, 9, 10, 19, 35],
    (0, 57): [27, 34],
    (0, 58): [0, 2, 3, 4, 5, 6, 8, 12, 17, 18, 22, 24, 29],
    (1, 49): [15],
    (1, 50): [0, 6, 11, 26, 30, 36],
    (1, 51): [11, 36],
    (1, 52): [2, 7, 11, 20, 23, 32],
    (1, 53): [6],
    (1, 54): [3, 6, 16, 38, 39],
    (1, 56): [3, 5, 15, 20, 22, 23, 34],
    (1, 57): [0, 21],
    (1, 58): [0, 1, 2, 3, 4, 5, 7, 8, 12, 21, 24, 26],
    (1, 59): [2, 3, 5, 6, 8, 12, 13, 15, 16, 18, 19, 21, 23, 24, 25, 27, 28, 30, 31, 32, 36, 39],
    (3, 1): [3, 5, 10, 12, 13, 15, 16, 20, 24, 27, 28, 32, 33, 39],
    (3, 2): [0, 17],
    (3, 3): [0, 6, 10, 11, 12, 13, 14, 15, 18, 22, 23, 26, 27, 30, 33, 36, 37, 39],
    (3, 4): [2],
    (3, 5): [1, 3, 4, 6, 11, 13, 18, 19, 22, 23, 27, 29, 31, 32, 39],
    (3, 6): [3, 6, 8, 13, 15, 17, 21, 22, 24, 26, 30, 33, 35, 39],
    (3, 7): [0, 1, 3, 4, 6, 11, 12, 14, 16, 18, 20, 23, 24, 25, 27, 30, 34, 35, 38, 39],
    (3, 8): [0, 3, 7, 8, 9, 14, 15, 18, 21, 23, 25, 31, 33, 36],
    (3, 9): [15],
    (3, 11): [5, 22],
    (3, 14): [0, 2, 6, 9, 18, 25],
    (3, 16): [0, 2, 3, 4, 6, 8, 9, 10, 11, 12, 13, 15, 16, 18, 19, 20, 21, 22, 23, 24, 28, 30, 31, 32, 33, 36, 37],
    (3, 19): [0, 4, 6, 12, 13, 14, 16, 18, 19, 21, 22, 23, 24, 25, 27, 28, 29, 30, 32, 33, 38, 39],
    (3, 23): [3],
    (3, 26): [1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 14, 15, 19, 23, 28, 30, 31, 33, 34, 35, 36, 38, 39],
    (3, 30): [0, 1, 2, 3, 4, 6, 7, 8, 10, 12, 13, 15, 16, 18, 19, 21, 23, 24, 25, 27, 28, 29, 30, 31, 33, 36, 37, 39],
    (3, 31): [21],
    (3, 37): [0, 4, 5, 7, 9, 10, 12, 18, 19, 21, 22, 24, 26, 27, 28, 29, 33, 34, 36, 37, 39],
    (3, 42): [0, 4, 6, 7, 8, 12, 13, 16, 19, 21, 22, 27, 28, 29, 30, 33, 36, 37, 38, 39],
    (3, 45): [0, 1, 2, 6, 7, 10, 11, 12, 13, 15, 17, 18, 21, 24, 25, 26, 28, 30, 33, 34, 38, 39],
    (3, 53): [0],
    (3, 54): [20],
    (3, 55): [1, 4, 5, 7, 12, 13, 16, 17, 20, 21, 22, 23, 24, 28, 29, 36, 37],
    (3, 57): [3],
    (3, 58): [3],
    (3, 61): [0, 1, 3, 5, 7, 8, 10, 15, 16, 17, 18, 19, 20, 23, 25, 26, 27, 29, 32, 33, 34, 35, 39],
    (3, 62): [0, 11],
    (5, 1): [3, 6, 17, 36],
    (5, 2): [12, 17, 22, 23, 24, 32],
    (5, 4): [0, 3, 7, 13, 19, 24, 34],
    (5, 8): [4, 9, 13, 18, 31, 39],
    (5, 18): [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 28, 29, 32, 33, 34, 35, 36, 37, 38, 39],
    (5, 20): [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 39],
    (5, 24): [0, 2, 3, 4, 6, 7],
    (5, 25): [1, 3, 4, 5, 8, 10, 11, 12, 16, 18, 20, 23, 32, 38],
    (5, 26): [7, 11, 12],
    (5, 28): [0, 2, 5, 6, 8, 9, 12, 18, 21, 22, 23, 24, 26, 32, 34, 38],
    (5, 34): [0, 16, 32],
    (5, 36): [0, 3, 5, 9, 10, 12, 18, 26],
    (5, 37): [2, 5, 6, 8, 12, 16, 19, 27],
    (5, 40): [3, 27, 39],
    (5, 41): [0, 38],
    (5, 49): [0, 1, 2, 4, 12, 27, 39],
    (5, 50): [0, 2, 3, 6, 10, 12, 14, 15, 17, 18, 20, 23, 24, 25, 28, 29, 32, 34, 37],
    (9, 1): [0, 8],
    (9, 16): [2, 3, 31],
    (11, 42): [0, 3, 6, 9, 11, 14, 15, 16, 18, 23, 24, 25, 26, 28, 30, 32, 33, 34, 36, 39],
    (11, 58): [11],
    (11, 59): [11],
    (15, 6): [0, 4],
    (15, 20): [2, 21],
    (15, 32): [4, 5, 15],
    (15, 33): [0, 3, 7],
    (15, 36): [0, 10],
    (15, 37): [2, 3],
    (15, 38): [1],
    (15, 64): [1, 3, 13, 22],
    (15, 72): [0],
    (15, 74): [1],
    (15, 128): [0, 1, 2, 3, 4, 7, 15, 17, 35],
    (15, 132): [0],
    (15, 136): [2],
    (15, 138): [1],
    (15, 139): [0, 1],
}

# hand built DTAP messages
def lu_acc_emerg0():
    # Location updating accept: LAI, Emergency Number List with an entry of length 0
    return bytes([0x05, 0x02]) + LAI + bytes([0x34, 0x04, 0x03, 0x00, 0x11, 0x00])

EXTRA = [
    bytes([0x05, 0x02]) + LAI + bytes([0x34, 0x08, 0x03, 0x01, 0x11, 0x2f, 0x03, 0x02, 0x19, 0xf1]),   # LU accept, emergency numbers 112 and 911
    b"\x03",                                    # too short for DTAP
    bytes([0x02, 0x00, 0x01]),                    # reserved protocol discriminator
    bytes([0x03, 0x3f, 0x01]),                    # unknown CC message
    bytes([0x05, 0x3f, 0x01]),                    # unknown MM message
    bytes([0x09, 0x3f, 0x01]),                    # unknown SMS message
    bytes([0x0b, 0x3f, 0x01]),                    # unknown SS message
    bytes([0x0f, 0xff, 0x01]),                    # unknown TP message
    bytes([0x00, 0x7f, 0x01]),                    # unknown GCC message
    bytes([0x01, 0x7f, 0x01]),                    # unknown BCC message
    bytes([0x06, 0x27, 0x00, 0x00, 0x00, 0x00]),  # RR (delegated)
    bytes([0x08, 0x20, 0x62]),                    # GMM status (delegated)
    bytes([0x0a, 0x55, 0x6f]),                    # SM status (delegated)
    bytes([0x03, 0x01] + [0x1c, 0x00]),           # empty facility in alerting
    bytes([0x0f, 0x00, 0x00]), bytes([0x0f, 0x00, 0x02]), bytes([0x0f, 0x00, 0x04]),   # close TCH loop, sub-channel
    bytes([0x0f, 0x00, 0x08]), bytes([0x0f, 0x00, 0x10]), bytes([0x0f, 0x00, 0x18]),
    bytes([0x0f, 0x00, 0x38]), bytes([0x0f, 0x00, 0x21]),
    bytes([0x01, 0x31, 0x77, 0x03, 0x57, 0x18, 0x90, 0x08, 0x29, 0x26, 0x20, 0x11, 0x32, 0x54, 0x76, 0x98, 0x00, 0x00, 0x00, 0x07]),  # BCC immediate setup, no key
]
MALFORMED = [
    bytes([0x05, 0x12, 0x00]) + bytes(range(16)) + bytes([0x20, 0x0a]) + bytes(range(10)),        # AUTN of 10 octets
    bytes([0x05, 0x1c, 0x14, 0x22, 0x09]) + bytes(range(9)),                                      # AUTS of 9 octets
    bytes([0x03, 0x05, 0x5d, 0x03, 0x80, 0x50, 0x99]),                                            # invalid IA5 character
    bytes([0x03, 0x35, 0x2c, 0x5a]),                                                              # keypad: not a DTMF digit
    bytes([0x05, 0x32, 0x43, 0x03, 0x83, 0x41, 0x42]),                                            # text not a multiple of 7 bits
    bytes([0x05, 0x02]) + LAI + bytes([0x34, 0x04, 0x03, 0x01, 0x1a, 0xff]),                      # emergency number: not a digit
    bytes([0x03, 0x05, 0x5e, 0x04, 0x81, 0x1f, 0x21, 0x43]),                                      # called party: end mark inside
    lu_acc_emerg0(),                              # zero length emergency number entry (fixed here)
    bytes([0x73, 0x01]),                          # TI value 7 and no TIE octet
    bytes([0x05, 0x08, 0x70]),                    # truncated location updating request
    bytes([0x03, 0x05, 0x04, 0x20, 0x80]),        # bearer capability longer than the message
]


# ------------------------------------------------------------------ main
def main_frames():
    fr = open_conn()
    for (pd, v), ks in sorted(KEEP.items()):
        for k in ks:
            ti = [0x00, 0x80, 0x10, 0x70][k % 4] if pd in (0, 1, 3, 9, 11) else 0
            fr.append(dtap_frame(table_msg(pd, v, k, ti)))
    for d in EXTRA:
        fr.append(dtap_frame(d))
    # messages the dissector knows by name but has no function for: elements shown as bytes
    for (pd, v), el in sorted(TABLE.items()):
        if el is None and v:
            fr.append(dtap_frame(bytes([pd, v, 0x5a, 0xa5])))
    # more SCCP connections: the first DTAP message of a connection labels it
    for n, first in enumerate([bytes([0x05, 0x3f, 0x01]), bytes([0x05, 0x04, 0x01, 0x00]),
                               bytes([0x03, 0x3f, 0x01])]):
        s = bytes([0, 0, 0x10 + n])
        d = bytes([0, 0, 0x20 + n])
        fr += [wrap(sccp_cr(s)), wrap(sccp_cc(s, d)), wrap(sccp_dt1(d, bssap_dtap(first)))]
    return fr


def malformed_frames():
    return open_conn() + [dtap_frame(d) for d in MALFORMED]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(out + "/gsm_a_dtap-coverage.pcap", main_frames())
    write_pcap(out + "/gsm_a_dtap-coverage-malformed.pcap", malformed_frames())
