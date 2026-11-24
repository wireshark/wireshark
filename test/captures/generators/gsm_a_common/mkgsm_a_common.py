#!/usr/bin/env python3
# Generates test/captures/gsm_a_common_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GSM A common coverage captures. Usage: mkgsm_a_common.py <outdir>

Every frame is Ethernet/IPv4/SCTP/M3UA/SCCP/BSSAP (DTAP), the A interface
as a real capture has it (SCTP port 2905 and PPID 3 are registered by
default, the SCCP connection is opened with a CR whose called party
address has SSN 254).  The DTAP messages are built from the message
and element tables of packet-gsm_a_common.c (TABLE at the end of this file)
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


def bssmap_frame(m):
    return wrap(sccp_dt1(DST_REF, bytes([0, len(m)]) + m))


def msg_frame(pd, data):
    return bssmap_frame(data) if pd == 100 else dtap_frame(data)


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
    if pd == 100:
        return bytes([v]) + body
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
            ti = [0x00, 0x80, 0x10, 0x70][k % 4] if pd in (0, 1, 3, 9, 10, 11) else 0
            out.append((pd, v, k, msg_frame(pd, table_msg(pd, v, k, ti))))
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

# ---- generated from the message tables of packet-gsm_a_dtap.c, -rr.c, -gm.c and -bssmap.c by extract.py
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
    (6, 0): None,
    (6, 2): [('ELEM_MAND_V', None)],
    (6, 3): [('ELEM_MAND_V', None)],
    (6, 4): None,
    (6, 5): [('ELEM_MAND_V', None)],
    (6, 6): None,
    (6, 7): None,
    (6, 8): None,
    (6, 9): None,
    (6, 10): [('ELEM_MAND_V', None)],
    (6, 11): None,
    (6, 12): None,
    (6, 13): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 115), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 117), ('ELEM_OPT_TLV', 118), ('ELEM_OPT_TV', 98), ('ELEM_OPT_TLV', 119)],
    (6, 14): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV_SHORT', 208)],
    (6, 15): None,
    (6, 16): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 98), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 17), ('ELEM_OPT_TV', 18), ('ELEM_OPT_TV', 109)],
    (6, 17): None,
    (6, 18): [('ELEM_MAND_V', None)],
    (6, 19): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TV_SHORT', 1)],
    (6, 20): [('ELEM_OPT_TLV', 16)],
    (6, 21): [('ELEM_MAND_V', None)],
    (6, 22): [('ELEM_MAND_V', None)],
    (6, 23): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 32)],
    (6, 24): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 25): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TV', 100), ('ELEM_OPT_TLV', 114), ('ELEM_MAND_V', None)],
    (6, 26): [('ELEM_MAND_V', None)],
    (6, 27): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 28): None,
    (6, 29): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 30): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 31): [('ELEM_MAND_V', None)],
    (6, 32): None,
    (6, 33): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 23), ('ELEM_MAND_V', None)],
    (6, 34): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 23), ('ELEM_MAND_V', None)],
    (6, 35): None,
    (6, 36): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 37): None,
    (6, 38): None,
    (6, 39): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV_SHORT', 192)],
    (6, 40): [('ELEM_MAND_V', None)],
    (6, 41): [('ELEM_MAND_V', None)],
    (6, 42): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_LV', None)],
    (6, 43): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TV', 2), ('ELEM_OPT_TLV', 5), ('ELEM_OPT_TV', 98), ('ELEM_OPT_TLV', 16), ('ELEM_OPT_TV', 99), ('ELEM_OPT_TV', 17), ('ELEM_OPT_TV', 19), ('ELEM_OPT_TV', 20), ('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 22), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TV', 24), ('ELEM_OPT_TV', 100), ('ELEM_OPT_TV', 102), ('ELEM_OPT_TV', 105), ('ELEM_OPT_TLV', 114), ('ELEM_OPT_TV', 124), ('ELEM_OPT_TV', 123), ('ELEM_OPT_TV', 125), ('ELEM_OPT_TV', 18), ('ELEM_OPT_TLV', 25), ('ELEM_OPT_TV', 28), ('ELEM_OPT_TV', 29), ('ELEM_OPT_TV', 30), ('ELEM_OPT_TLV', 33), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 1), ('ELEM_OPT_TLV', 3), ('ELEM_OPT_TLV', 118), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TV', 81), ('ELEM_OPT_TV', 109), ('ELEM_OPT_TV', 110)],
    (6, 44): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 119)],
    (6, 45): [('ELEM_MAND_V', None)],
    (6, 46): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 5), ('ELEM_OPT_TV', 98), ('ELEM_OPT_TLV', 16), ('ELEM_OPT_TV', 99), ('ELEM_OPT_TV', 17), ('ELEM_OPT_TV', 19), ('ELEM_OPT_TV', 20), ('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 22), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TV', 24), ('ELEM_OPT_TV', 100), ('ELEM_OPT_TV', 102), ('ELEM_OPT_TLV', 114), ('ELEM_OPT_TV', 124), ('ELEM_OPT_TLV', 25), ('ELEM_OPT_TV', 28), ('ELEM_OPT_TV', 29), ('ELEM_OPT_TV', 30), ('ELEM_OPT_TLV', 33), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 1), ('ELEM_OPT_TLV', 3), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TV', 109), ('ELEM_OPT_TV', 110)],
    (6, 47): [('ELEM_MAND_V', None)],
    (6, 48): [('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 99), ('ELEM_OPT_TV', 17), ('ELEM_OPT_TV', 19), ('ELEM_OPT_TV', 20), ('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 22), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TV', 24)],
    (6, 49): None,
    (6, 50): [('ELEM_OPT_TLV', 23)],
    (6, 51): [('ELEM_MAND_V', None)],
    (6, 52): None,
    (6, 53): [('ELEM_MAND_VV_SHORT', None)],
    (6, 54): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 55): [('ELEM_MAND_V', None)],
    (6, 57): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 124), ('ELEM_MAND_V', None)],
    (6, 58): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 59): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 114), ('ELEM_OPT_TV', 124), ('ELEM_OPT_TV', 109)],
    (6, 60): None,
    (6, 61): None,
    (6, 62): None,
    (6, 63): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 124), ('ELEM_MAND_V', None), ('ELEM_OPT_TV', 109)],
    (6, 64): [('ELEM_MAND_V', None)],
    (6, 65): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 1), ('ELEM_OPT_TLV', 3), ('ELEM_OPT_TV', 109)],
    (6, 66): [('ELEM_MAND_V', None)],
    (6, 70): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TV', 109)],
    (6, 72): [('ELEM_MAND_V', None)],
    (6, 73): [('ELEM_MAND_V', None)],
    (6, 74): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None)],
    (6, 75): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 34), ('ELEM_OPT_TLV', 35), ('ELEM_OPT_TLV', 18), ('ELEM_OPT_TLV', 19), ('ELEM_OPT_TV', 20), ('ELEM_OPT_TLV', 36), ('ELEM_OPT_TV', 109)],
    (6, 76): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 16), ('ELEM_OPT_TV', 17), ('ELEM_OPT_TLV', 18), ('ELEM_OPT_TLV', 19), ('ELEM_OPT_TLV', 21), ('ELEM_OPT_TLV', 22), ('ELEM_OPT_TLV', 23), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 24), ('ELEM_OPT_TLV', 25), ('ELEM_OPT_TLV', 32), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV', 109)],
    (6, 77): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None)],
    (6, 78): [('ELEM_OPT_TV', 16), ('ELEM_OPT_TLV', 17)],
    (6, 96): None,
    (6, 98): None,
    (6, 99): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 100): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 106): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None)],
    (6, 192): [('ELEM_MAND_LV', None)],
    (6, 193): None,
    (6, 194): [('ELEM_MAND_LV', None)],
    (8, 0): None,
    (8, 1): [('ELEM_MAND_LV', None), ('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV', 17), ('ELEM_OPT_TLV', 32), ('ELEM_OPT_TLV', 64), ('ELEM_OPT_TLV', 88), ('ELEM_OPT_TLV', 26), ('ELEM_OPT_TLV', 27), ('ELEM_OPT_TLV', 93), ('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TV_SHORT', 224), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 20), ('ELEM_OPT_TV_SHORT', 240), ('ELEM_OPT_TLV', 16), ('ELEM_OPT_TLV', 106), ('ELEM_OPT_TLV', 57), ('ELEM_OPT_TLV', 110)],
    (8, 2): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TLV', 24), ('ELEM_OPT_TLV', 35), ('ELEM_OPT_TV', 37), ('ELEM_OPT_TLV', 42), ('ELEM_OPT_T', 140), ('ELEM_OPT_TLV', 74), ('ELEM_OPT_TV_SHORT', 176), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TV_SHORT', 160), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TLV', 56), ('ELEM_OPT_TLV', 57), ('ELEM_OPT_TLV', 102), ('ELEM_OPT_TLV', 106), ('ELEM_OPT_TLV', 110), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 49), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV', 101), ('ELEM_OPT_TLV', 99), ('ELEM_OPT_TV_SHORT', 208)],
    (8, 3): [('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 43)],
    (8, 4): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 42), ('ELEM_OPT_TLV', 58)],
    (8, 5): [],
    (8, 6): [('ELEM_MAND_VV_SHORT', None)],
    (8, 8): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TV', 39), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 24), ('ELEM_OPT_TLV', 49), ('ELEM_OPT_TLV', 50), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TLV', 88), ('ELEM_OPT_TLV', 26), ('ELEM_OPT_TLV', 27), ('ELEM_OPT_TLV', 17), ('ELEM_OPT_TLV', 32), ('ELEM_OPT_TLV', 64), ('ELEM_OPT_TLV', 93), ('ELEM_OPT_TV_SHORT', 224), ('ELEM_OPT_TV_SHORT', 208), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 20), ('ELEM_OPT_TV_SHORT', 240), ('ELEM_OPT_TLV', 16), ('ELEM_OPT_TLV', 106), ('ELEM_OPT_TLV', 57), ('ELEM_OPT_TLV', 110)],
    (8, 9): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TLV', 24), ('ELEM_OPT_TLV', 35), ('ELEM_OPT_TLV', 38), ('ELEM_OPT_TV', 23), ('ELEM_OPT_TV', 37), ('ELEM_OPT_TLV', 42), ('ELEM_OPT_T', 140), ('ELEM_OPT_TLV', 74), ('ELEM_OPT_TLV', 50), ('ELEM_OPT_TV_SHORT', 176), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TV_SHORT', 160), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TLV', 56), ('ELEM_OPT_TLV', 57), ('ELEM_OPT_TLV', 102), ('ELEM_OPT_TLV', 106), ('ELEM_OPT_TLV', 110), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 49), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV', 101), ('ELEM_OPT_TLV', 99), ('ELEM_OPT_TV_SHORT', 208)],
    (8, 10): [('ELEM_OPT_TLV', 38), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 43)],
    (8, 11): [('ELEM_MAND_V', None), ('ELEM_MAND_VV_SHORT', None), ('ELEM_OPT_TLV', 42), ('ELEM_OPT_TLV', 58)],
    (8, 12): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 50), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TLV', 54), ('ELEM_OPT_TV_SHORT', 208)],
    (8, 13): [('ELEM_OPT_TLV', 50), ('ELEM_OPT_TLV', 53)],
    (8, 14): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 58)],
    (8, 16): [('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_VV_SHORT', None), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TLV', 101)],
    (8, 17): [],
    (8, 18): [('ELEM_MAND_VV_SHORT', None), ('ELEM_MAND_VV_SHORT', None), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV_SHORT', 128), ('ELEM_OPT_TLV', 40), ('ELEM_OPT_TLV', 49), ('ELEM_OPT_TLV', 66), ('ELEM_OPT_TLV', 67), ('ELEM_OPT_TLV', 51)],
    (8, 19): [('ELEM_MAND_VV_SHORT', None), ('ELEM_OPT_TV', 34), ('ELEM_OPT_TLV', 35), ('ELEM_OPT_TLV', 41), ('ELEM_OPT_TLV', 67)],
    (8, 20): [],
    (8, 21): [('ELEM_MAND_VV_SHORT', None)],
    (8, 22): [('ELEM_MAND_LV', None)],
    (8, 28): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 48)],
    (8, 32): [('ELEM_MAND_V', None)],
    (8, 33): [('ELEM_OPT_TLV', 67), ('ELEM_OPT_TLV', 69), ('ELEM_OPT_TV', 70), ('ELEM_OPT_TV', 71), ('ELEM_OPT_TLV', 72), ('ELEM_OPT_TLV', 73)],
    (9, 0): None,
    (9, 1): [('ELEM_MAND_LV', None)],
    (9, 4): None,
    (9, 16): [('ELEM_MAND_V', None)],
    (10, 0): None,
    (10, 65): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 40), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TV_SHORT', 160), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 66): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 43), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TLV', 57), ('ELEM_OPT_TV_SHORT', 176), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 67): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TLV', 107), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 68): [('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 40), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 69): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 70): [('ELEM_MAND_V', None), ('ELEM_OPT_TV_SHORT', 144), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV_E', 123)],
    (10, 71): [('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TLV_E', 123)],
    (10, 72): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 43), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 54), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 73): [('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 74): [('ELEM_OPT_TV', 50), ('ELEM_OPT_TLV', 48), ('ELEM_OPT_TLV', 49), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 75): [('ELEM_OPT_TLV', 48), ('ELEM_OPT_TV', 50), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 76): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TLV', 107), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 77): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 54), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 78): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 52), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 79): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TLV', 107), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 80): None,
    (10, 81): None,
    (10, 82): None,
    (10, 83): None,
    (10, 84): None,
    (10, 85): [('ELEM_MAND_V', None)],
    (10, 86): [('ELEM_MAND_V', None), ('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TV_SHORT', 192)],
    (10, 87): [('ELEM_MAND_LV', None), ('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 53)],
    (10, 88): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 53), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_TLV', 107)],
    (10, 89): [('ELEM_MAND_V', None), ('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 53)],
    (10, 90): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 53)],
    (10, 91): [('ELEM_MAND_LV', None), ('ELEM_MAND_LV', None), ('ELEM_OPT_TLV', 54), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TV_SHORT', 192), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123), ('ELEM_OPT_TLV', 92)],
    (10, 92): [('ELEM_MAND_V', None), ('ELEM_OPT_TLV', 39), ('ELEM_OPT_TLV', 51), ('ELEM_OPT_TLV_E', 123)],
    (10, 93): [('ELEM_MAND_LV', None)],
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
    (100, 0): None,
    (100, 1): [('ELEM_MAND_TLV', 11), ('ELEM_OPT_TLV', 7), ('ELEM_OPT_TLV', 6), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TV', 20), ('ELEM_OPT_TLV', 18), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_T', 53), ('ELEM_OPT_TV', 57), ('ELEM_OPT_TV', 63), ('ELEM_OPT_TLV', 80), ('ELEM_OPT_TLV', 10), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TV', 127), ('ELEM_OPT_TV', 131), ('ELEM_OPT_TLV', 137), ('ELEM_OPT_TV', 138), ('ELEM_OPT_TV', 139), ('ELEM_OPT_T', 140), ('ELEM_OPT_TV', 241)],
    (100, 2): [('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TLV', 5), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV', 44), ('ELEM_OPT_TV', 45), ('ELEM_OPT_TV', 64), ('ELEM_OPT_TLV', 59), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TV', 141), ('ELEM_OPT_TV', 241)],
    (100, 3): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 45), ('ELEM_OPT_TLV', 46), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 125)],
    (100, 4): [],
    (100, 5): [],
    (100, 6): [],
    (100, 7): [('ELEM_MAND_TLV', 11), ('ELEM_MAND_TV', 51), ('ELEM_MAND_TLV', 5), ('ELEM_MAND_TLV', 55), ('ELEM_OPT_TLV', 6), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TLV', 10), ('ELEM_OPT_TLV', 101), ('ELEM_OPT_TLV', 102), ('ELEM_OPT_TLV', 109), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TV', 127), ('ELEM_OPT_TLV', 125)],
    (100, 8): [('ELEM_MAND_TLV', 4)],
    (100, 9): None,
    (100, 10): None,
    (100, 11): None,
    (100, 12): None,
    (100, 13): None,
    (100, 14): None,
    (100, 15): None,
    (100, 16): [('ELEM_MAND_TLV', 11), ('ELEM_MAND_TLV', 10), ('ELEM_OPT_TV', 29), ('ELEM_OPT_TLV', 18), ('ELEM_MAND_TLV', 5), ('ELEM_OPT_TLV', 6), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TV', 25), ('ELEM_MAND_TLV', 5), ('ELEM_OPT_TV', 20), ('ELEM_OPT_TLV', 4), ('ELEM_OPT_TLV', 19), ('ELEM_OPT_TV', 49), ('ELEM_OPT_TV', 64), ('ELEM_OPT_TLV', 55), ('ELEM_OPT_T', 53), ('ELEM_OPT_TV', 57), ('ELEM_OPT_TV', 44), ('ELEM_OPT_TLV', 58), ('ELEM_OPT_TLV', 61), ('ELEM_OPT_TV', 63), ('ELEM_OPT_TLV', 80), ('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 81), ('ELEM_OPT_TLV', 82), ('ELEM_OPT_TLV', 100), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TV', 127), ('ELEM_OPT_TV', 131), ('ELEM_OPT_TLV', 137), ('ELEM_OPT_TV', 138), ('ELEM_OPT_TV', 139)],
    (100, 17): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_T', 27), ('ELEM_MAND_TLV', 26), ('ELEM_OPT_TLV', 46), ('ELEM_OPT_TV', 49), ('ELEM_OPT_TV', 64), ('ELEM_OPT_TV', 50), ('ELEM_OPT_TLV', 58), ('ELEM_OPT_TLV', 81), ('ELEM_OPT_TLV', 82), ('ELEM_OPT_TLV', 83), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 132)],
    (100, 18): [('ELEM_MAND_TLV', 23), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV', 44), ('ELEM_OPT_TV', 45), ('ELEM_OPT_TV', 64), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TLV', 59), ('ELEM_OPT_TLV', 97), ('ELEM_OPT_TLV', 99), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TV', 141)],
    (100, 19): [('ELEM_MAND_TLV', 23), ('ELEM_OPT_TLV', 5), ('ELEM_OPT_TLV', 97), ('ELEM_OPT_TV', 106)],
    (100, 20): [('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TV', 44), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV', 141)],
    (100, 21): [('ELEM_OPT_TV', 106)],
    (100, 22): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TV', 21), ('ELEM_OPT_TV', 45), ('ELEM_OPT_TLV', 46), ('ELEM_OPT_TLV', 83), ('ELEM_OPT_TLV', 97), ('ELEM_OPT_TLV', 99), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 125)],
    (100, 23): [('ELEM_MAND_TLV', 4), ('ELEM_MAND_TLV', 5), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV', 44), ('ELEM_OPT_TV', 64), ('ELEM_OPT_TLV', 59), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TV', 141)],
    (100, 24): [('ELEM_MAND_TV', 14), ('ELEM_MAND_TLV', 26), ('ELEM_MAND_TLV', 5)],
    (100, 25): [('ELEM_MAND_TV', 14), ('ELEM_MAND_TLV', 5)],
    (100, 26): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TLV', 97), ('ELEM_OPT_TV', 106)],
    (100, 27): [('ELEM_OPT_TV', 106)],
    (100, 28): [('ELEM_MAND_TLV', 11), ('ELEM_MAND_TLV', 5), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TV', 45), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 126), ('ELEM_OPT_TV', 127)],
    (100, 29): [('ELEM_OPT_TLV', 4), ('ELEM_OPT_TV', 45), ('ELEM_OPT_TLV', 46), ('ELEM_OPT_TLV', 125)],
    (100, 30): None,
    (100, 31): [('ELEM_OPT_TV', 106), ('ELEM_MAND_TLV', 5), ('ELEM_OPT_TLV', 23), ('ELEM_OPT_TLV', 41)],
    (100, 32): [('ELEM_OPT_TLV', 7), ('ELEM_MAND_TLV', 4), ('ELEM_OPT_T', 143)],
    (100, 33): None,
    (100, 34): [('ELEM_MAND_TLV', 4)],
    (100, 35): None,
    (100, 36): None,
    (100, 37): [('ELEM_MAND_TV', 24), ('ELEM_MAND_TLV', 4)],
    (100, 38): [('ELEM_MAND_TLV', 4), ('ELEM_MAND_TLV', 31)],
    (100, 39): [('ELEM_OPT_TV', 106), ('ELEM_OPT_T', 107), ('ELEM_MAND_TLV', 108)],
    (100, 40): [('ELEM_MAND_TV', 24)],
    (100, 41): [('ELEM_MAND_TV', 24)],
    (100, 42): [('ELEM_MAND_TLV_E', 73), ('ELEM_OPT_TLV', 79)],
    (100, 43): [('ELEM_MAND_TLV', 68), ('ELEM_OPT_TLV', 5), ('ELEM_OPT_TLV', 19), ('ELEM_OPT_TLV', 72), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TLV', 67), ('ELEM_OPT_TLV', 62), ('ELEM_OPT_TLV', 75), ('ELEM_OPT_TLV_E', 73), ('ELEM_OPT_TLV', 8), ('ELEM_OPT_TLV', 104), ('ELEM_OPT_TLV', 119), ('ELEM_OPT_TLV', 117)],
    (100, 44): [('ELEM_MAND_TLV', 61)],
    (100, 45): [('ELEM_OPT_TLV', 69), ('ELEM_OPT_TLV', 70), ('ELEM_OPT_TLV', 76), ('ELEM_OPT_TLV', 71), ('ELEM_OPT_TLV', 85), ('ELEM_OPT_TLV', 118)],
    (100, 46): [('ELEM_OPT_TLV', 71)],
    (100, 47): [('ELEM_MAND_TLV', 8), ('ELEM_OPT_TLV', 100), ('ELEM_OPT_TV', 148), ('ELEM_OPT_TV', 149)],
    (100, 48): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TV', 129), ('ELEM_OPT_T', 240)],
    (100, 49): [('ELEM_OPT_TV', 129), ('ELEM_OPT_T', 240)],
    (100, 50): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TLV', 5)],
    (100, 51): None,
    (100, 52): [('ELEM_MAND_TV', 1), ('ELEM_MAND_TLV', 4)],
    (100, 53): [('ELEM_MAND_TV', 1)],
    (100, 54): [('ELEM_MAND_TV', 37), ('ELEM_OPT_TLV', 38), ('ELEM_MAND_TV', 39), ('ELEM_OPT_TLV', 40), ('ELEM_OPT_TLV', 41), ('ELEM_OPT_TLV', 42)],
    (100, 55): [('ELEM_MAND_TV', 37), ('ELEM_OPT_TV', 43), ('ELEM_OPT_TLV', 38), ('ELEM_MAND_TV', 39), ('ELEM_OPT_TLV', 40), ('ELEM_OPT_TLV', 42)],
    (100, 56): None,
    (100, 57): None,
    (100, 58): None,
    (100, 59): [('ELEM_OPT_TLV', 113), ('ELEM_OPT_TLV', 114), ('ELEM_OPT_TLV', 115), ('ELEM_OPT_TLV', 116), ('ELEM_OPT_TLV', 112)],
    (100, 60): [('ELEM_OPT_TLV', 109), ('ELEM_MAND_TV', 51)],
    (100, 61): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TLV', 128)],
    (100, 62): [('ELEM_OPT_TLV', 128)],
    (100, 63): None,
    (100, 64): [('ELEM_MAND_TV', 1), ('ELEM_MAND_TLV', 4), ('ELEM_OPT_T', 54)],
    (100, 65): [('ELEM_MAND_TV', 1)],
    (100, 66): [('ELEM_MAND_TV', 1)],
    (100, 67): [('ELEM_MAND_TV', 1)],
    (100, 68): [('ELEM_MAND_TLV', 4), ('ELEM_MAND_TV', 1), ('ELEM_MAND_TLV', 30)],
    (100, 69): [('ELEM_MAND_TV', 1), ('ELEM_MAND_TLV', 30)],
    (100, 70): [('ELEM_MAND_TV', 1), ('ELEM_MAND_TLV', 30)],
    (100, 71): [('ELEM_MAND_TV', 1), ('ELEM_MAND_TLV', 30)],
    (100, 72): [('ELEM_MAND_TV', 1), ('ELEM_OPT_TLV', 30)],
    (100, 73): [('ELEM_MAND_TLV', 5), ('ELEM_OPT_TLV', 108), ('ELEM_MAND_TLV', 23)],
    (100, 74): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TV', 106)],
    (100, 75): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TV', 106), ('ELEM_OPT_TLV', 108)],
    (100, 76): [('ELEM_MAND_TLV', 4)],
    (100, 77): [('ELEM_OPT_TLV', 4), ('ELEM_OPT_TV', 106), ('ELEM_OPT_T', 107), ('ELEM_MAND_TLV', 108)],
    (100, 78): [('ELEM_MAND_TLV', 4)],
    (100, 79): [('ELEM_MAND_TV', 1)],
    (100, 80): [('ELEM_MAND_TV', 12), ('ELEM_MAND_TV', 28), ('ELEM_MAND_TLV', 5), ('ELEM_MAND_TV', 13)],
    (100, 81): [('ELEM_MAND_TV', 28), ('ELEM_MAND_TV', 3), ('ELEM_MAND_TLV', 5), ('ELEM_MAND_TV', 34)],
    (100, 82): [('ELEM_MAND_TLV', 8), ('ELEM_OPT_TLV', 9), ('ELEM_MAND_TLV', 26), ('ELEM_OPT_TV', 36), ('ELEM_OPT_TV', 56), ('ELEM_OPT_TV', 103)],
    (100, 83): [('ELEM_OPT_TLV', 7), ('ELEM_MAND_TLV', 10), ('ELEM_OPT_TV', 35), ('ELEM_OPT_TV', 131)],
    (100, 84): [('ELEM_MAND_TLV', 18), ('ELEM_OPT_TLV', 19), ('ELEM_OPT_TV', 106)],
    (100, 85): [('ELEM_OPT_TLV', 32), ('ELEM_OPT_TV', 44)],
    (100, 86): None,
    (100, 87): [('ELEM_MAND_TLV', 5), ('ELEM_MAND_TLV', 23), ('ELEM_OPT_TV', 33), ('ELEM_OPT_TLV', 60), ('ELEM_OPT_TLV_E', 73), ('ELEM_OPT_TLV', 125), ('ELEM_OPT_T', 133), ('ELEM_OPT_TV', 135), ('ELEM_OPT_TLV', 8), ('ELEM_OPT_TV', 148)],
    (100, 88): [('ELEM_OPT_TV', 106)],
    (100, 89): [('ELEM_MAND_TLV', 4)],
    (100, 90): [('ELEM_MAND_TV', 47), ('ELEM_MAND_TLV', 5), ('ELEM_MAND_TLV', 26), ('ELEM_OPT_TLV', 48), ('ELEM_OPT_TLV', 4)],
    (100, 91): None,
    (100, 92): None,
    (100, 93): None,
    (100, 94): None,
    (100, 95): None,
    (100, 96): [('ELEM_MAND_TLV', 108)],
    (100, 97): [('ELEM_MAND_TLV', 110)],
    (100, 98): [('ELEM_MAND_TLV', 122), ('ELEM_MAND_TLV', 121), ('ELEM_MAND_TLV', 123)],
    (100, 99): [('ELEM_MAND_TLV', 5), ('ELEM_MAND_TLV', 23), ('ELEM_MAND_TLV', 122)],
    (100, 100): None,
    (100, 101): None,
    (100, 102): None,
    (100, 103): None,
    (100, 104): None,
    (100, 105): None,
    (100, 106): None,
    (100, 107): None,
    (100, 108): None,
    (100, 109): None,
    (100, 110): None,
    (100, 111): None,
    (100, 112): [('ELEM_MAND_TLV', 4), ('ELEM_MAND_TLV', 5), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TLV', 125)],
    (100, 113): [('ELEM_MAND_TLV', 4), ('ELEM_OPT_TLV', 125)],
    (100, 114): [('ELEM_OPT_TLV', 126), ('ELEM_OPT_TV', 1), ('ELEM_OPT_TLV', 124), ('ELEM_OPT_TV', 127), ('ELEM_OPT_TV', 25), ('ELEM_OPT_TV', 139)],
    (100, 115): [('ELEM_OPT_TLV', 126)],
    (100, 116): [('ELEM_OPT_TV', 138), ('ELEM_OPT_TV', 139)],
    (100, 117): [('ELEM_OPT_TV', 141)],
    (100, 118): [('ELEM_OPT_TV', 141), ('ELEM_OPT_T', 142)],
    (100, 119): None,
    (100, 120): [('ELEM_MAND_TLV', 23), ('ELEM_MAND_TV', 134), ('ELEM_OPT_TLV', 23), ('ELEM_OPT_TV', 135), ('ELEM_OPT_TLV', 8)],
    (100, 121): [('ELEM_MAND_TV', 136)],
}
BE = {
    'BE_LOC_EST': 69,
    'BE_VEL_EST': 85,
    'BE_CELL_ID': 5,
    'BE_CM_INFO_3': 19,
    'BE_CM_INFO_2': 18,
    'BE_IMSI': 8,
    'BE_L3_INFO': 23,
}

# ---- seeds that dissect cleanly (keep.py)
KEEP = {
    (0, 49): [6, 11, 12, 13, 23],
    (0, 50): [3],
    (0, 51): [7],
    (0, 52): [11],
    (0, 53): [11],
    (0, 54): [3],
    (0, 56): [2, 3, 4],
    (0, 57): [21],
    (0, 58): [3],
    (1, 49): [15],
    (1, 50): [0, 11],
    (1, 51): [11],
    (1, 52): [7],
    (1, 53): [6],
    (1, 54): [3],
    (1, 56): [3, 15],
    (1, 57): [0],
    (1, 58): [3],
    (1, 59): [3, 5, 13],
    (3, 1): [6, 10],
    (3, 2): [0, 17, 23],
    (3, 3): [0, 14, 15, 23],
    (3, 4): [2],
    (3, 5): [1, 3, 4, 6, 13, 18, 22, 23],
    (3, 6): [3, 15, 17, 21, 22],
    (3, 7): [0, 3, 7, 12, 17, 18, 20, 23],
    (3, 8): [3, 7, 9, 15, 21, 23],
    (3, 9): [15],
    (3, 11): [5],
    (3, 14): [6, 16, 18],
    (3, 16): [2, 3, 4, 6, 8, 12, 13, 20, 22, 23],
    (3, 19): [6, 13, 19, 21, 22],
    (3, 23): [3],
    (3, 26): [3, 12, 15],
    (3, 30): [7],
    (3, 31): [21],
    (3, 37): [0, 5, 7, 9, 12, 17, 18, 21, 22],
    (3, 42): [0, 8, 12, 15, 21],
    (3, 45): [0, 1, 6, 11, 12, 13, 15, 18, 21],
    (3, 53): [0],
    (3, 54): [20],
    (3, 55): [17, 22],
    (3, 57): [3],
    (3, 58): [3],
    (3, 61): [0, 2, 3, 11, 23],
    (3, 62): [11],
    (5, 1): [3],
    (5, 2): [17, 22],
    (5, 4): [0, 7, 13],
    (5, 8): [2, 5, 13],
    (5, 18): [0, 2, 3, 4, 9, 10, 14, 15, 17, 18, 19, 21, 23],
    (5, 20): [0, 3, 5, 6, 8, 9, 10, 12, 14, 15, 18, 19, 20, 21, 22, 23],
    (5, 24): [0],
    (5, 25): [3, 12, 18],
    (5, 26): [7],
    (5, 28): [0, 2, 5, 6, 8, 9, 12, 18, 21, 22, 23],
    (5, 34): [0, 16],
    (5, 36): [5, 12, 18],
    (5, 37): [2, 8],
    (5, 40): [3],
    (5, 41): [0],
    (5, 49): [0],
    (5, 50): [0, 2, 3, 6, 18, 23],
    (6, 10): [1],
    (6, 13): [5, 23],
    (6, 14): [0],
    (6, 16): [5, 11],
    (6, 18): [0],
    (6, 19): [0],
    (6, 21): [0],
    (6, 22): [2],
    (6, 23): [0],
    (6, 24): [0],
    (6, 25): [0, 3, 7],
    (6, 31): [0],
    (6, 33): [6, 12, 17, 18, 19],
    (6, 34): [0, 1, 2, 3, 4, 5, 6, 9, 11, 12, 13, 14, 15, 17, 18, 19, 21, 22, 23],
    (6, 39): [6],
    (6, 40): [1],
    (6, 41): [2],
    (6, 42): [0],
    (6, 43): [7, 21, 23],
    (6, 44): [8],
    (6, 45): [5],
    (6, 46): [12],
    (6, 47): [1],
    (6, 48): [1, 5, 6, 11, 13, 14, 16, 19, 20, 23],
    (6, 50): [12],
    (6, 51): [1],
    (6, 53): [0, 5],
    (6, 57): [18],
    (6, 58): [2, 7, 9, 11, 17, 18],
    (6, 59): [6],
    (6, 63): [6, 13, 23],
    (6, 64): [0],
    (6, 65): [0],
    (6, 66): [0],
    (6, 70): [0],
    (6, 72): [0],
    (6, 73): [0],
    (6, 74): [0, 12, 15, 18, 23],
    (6, 75): [0, 2, 7, 9, 11, 15, 16, 19],
    (6, 76): [0, 2, 8, 9, 15, 17, 19, 23],
    (6, 77): [20],
    (6, 78): [23],
    (6, 100): [0],
    (6, 106): [5, 10],
    (6, 192): [0],
    (6, 194): [0],
    (8, 1): [3],
    (8, 2): [10, 15],
    (8, 3): [16],
    (8, 4): [18],
    (8, 6): [0, 6],
    (8, 8): [16],
    (8, 9): [16],
    (8, 10): [4],
    (8, 11): [10, 13],
    (8, 12): [0, 4, 9, 10, 12, 13, 22],
    (8, 13): [0],
    (8, 14): [3],
    (8, 17): [0],
    (8, 18): [2, 6, 15],
    (8, 19): [5, 9, 16, 19],
    (8, 20): [0],
    (8, 21): [0, 2, 11],
    (8, 22): [6],
    (8, 28): [0],
    (8, 32): [0],
    (8, 33): [0, 15],
    (9, 1): [8],
    (9, 16): [3],
    (10, 65): [5, 7],
    (10, 66): [6, 14, 21],
    (10, 67): [0, 3, 13, 15],
    (10, 68): [4, 7, 14, 20],
    (10, 69): [5],
    (10, 70): [12, 19],
    (10, 71): [3, 6, 9, 17, 18, 21],
    (10, 72): [6, 15],
    (10, 73): [11, 16],
    (10, 74): [1, 10],
    (10, 75): [14],
    (10, 76): [5],
    (10, 77): [15],
    (10, 78): [10, 15],
    (10, 79): [4, 10],
    (10, 85): [3],
    (10, 86): [8],
    (10, 87): [23],
    (10, 88): [5],
    (10, 89): [15],
    (10, 90): [15],
    (10, 91): [7, 11, 23],
    (10, 92): [19],
    (10, 93): [3],
    (11, 42): [9, 15, 16],
    (11, 58): [11],
    (11, 59): [11],
    (15, 6): [0],
    (15, 20): [2],
    (15, 32): [5, 15],
    (15, 33): [0, 7],
    (15, 36): [0, 10],
    (15, 37): [3],
    (15, 38): [1],
    (15, 64): [1, 13],
    (15, 72): [0],
    (15, 74): [1],
    (15, 128): [0, 1, 2, 3, 4, 15, 17],
    (15, 132): [0],
    (15, 136): [2],
    (15, 138): [1],
    (15, 139): [0, 1],
    (100, 1): [3, 4, 5, 7, 9, 19],
    (100, 2): [15],
    (100, 3): [9, 14],
    (100, 4): [0],
    (100, 5): [0],
    (100, 6): [0],
    (100, 7): [0, 1, 3, 4, 10, 13, 14, 15, 16, 17, 20],
    (100, 8): [20],
    (100, 16): [0, 1, 5, 6, 8, 9, 10, 12, 14, 16, 18, 21, 22],
    (100, 17): [2, 6, 10, 11, 12, 15, 17, 19, 21],
    (100, 18): [2],
    (100, 19): [13],
    (100, 20): [1],
    (100, 21): [1],
    (100, 22): [13],
    (100, 23): [0, 2, 3, 7, 12, 13, 20, 21],
    (100, 24): [0],
    (100, 25): [18],
    (100, 26): [1],
    (100, 27): [7],
    (100, 28): [2, 5, 6, 7, 8, 11, 15, 16, 17, 21, 22],
    (100, 29): [3, 9],
    (100, 31): [14],
    (100, 32): [1],
    (100, 34): [0],
    (100, 37): [1, 23],
    (100, 38): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 17, 18, 20, 21, 22],
    (100, 39): [19, 23],
    (100, 40): [0],
    (100, 41): [0],
    (100, 42): [0],
    (100, 43): [6, 8, 18, 20],
    (100, 44): [11],
    (100, 45): [0, 1, 2, 3, 6, 7, 8, 12, 15, 17, 18, 19, 20, 22],
    (100, 46): [0],
    (100, 47): [9],
    (100, 48): [0, 10],
    (100, 49): [6],
    (100, 50): [9, 18, 20],
    (100, 52): [13],
    (100, 53): [1],
    (100, 54): [3, 12, 21],
    (100, 55): [0, 3, 14],
    (100, 59): [3, 16, 18, 21],
    (100, 60): [3],
    (100, 61): [3],
    (100, 62): [7],
    (100, 64): [3],
    (100, 65): [0],
    (100, 66): [0],
    (100, 67): [0],
    (100, 68): [10, 21],
    (100, 69): [6],
    (100, 70): [1],
    (100, 71): [2],
    (100, 72): [1],
    (100, 73): [5, 6, 10, 11, 19, 21, 23],
    (100, 74): [1],
    (100, 75): [8],
    (100, 76): [0],
    (100, 77): [4, 13, 14, 15],
    (100, 78): [1],
    (100, 79): [4],
    (100, 80): [7],
    (100, 81): [0],
    (100, 82): [0, 2, 7, 9, 12, 17, 18, 21, 23],
    (100, 83): [0, 1],
    (100, 84): [10, 17, 20],
    (100, 85): [6, 13, 21],
    (100, 87): [3, 11, 15, 22, 23],
    (100, 88): [2],
    (100, 89): [0],
    (100, 90): [19, 22],
    (100, 96): [0],
    (100, 98): [0, 1, 2, 3, 7, 8, 9, 10, 12, 13, 14, 15, 18, 19, 20, 23],
    (100, 99): [4, 20],
    (100, 112): [0, 2, 5, 9, 14],
    (100, 113): [6],
    (100, 114): [0, 7, 15, 16, 22],
    (100, 115): [10],
    (100, 116): [12, 15],
    (100, 117): [0],
    (100, 118): [0, 4],
    (100, 120): [11, 19],
    (100, 121): [1],
}

# ---- contents for the elements of common code reached through BSSMAP and GMM
def geo_desc(rng):
    t = rng.choice([0, 1, 3, 5, 8, 9, 10, 11, 12, 13, 14, 5, 1, 3])
    if t == 5:
        n = rng.choice([3, 4, 6])
        return bytes([(t << 4) | n]) + rbytes(rng, 6 * n)
    return bytes([(t << 4) | rng.getrandbits(4)]) + rbytes(rng, rng.choice([22, 24, 26]))


def velocity(rng):
    t = rng.randint(0, 3)
    return bytes([(t << 4) | rng.getrandbits(4)]) + rbytes(rng, 4 if t in (0,) else 5)


def plmn_list(rng):
    return b"".join(bytes([0x62, 0xf2, 0x10 + i]) if i % 2 == 0 else bytes([0x13, 0x00, 0x62 + i]) for i in range(rng.choice([1, 2, 5])))


CONTENT[(100, BE["BE_LOC_EST"])] = geo_desc
CONTENT[(100, BE["BE_VEL_EST"])] = velocity
CONTENT[(8, 0x4a)] = plmn_list

_r = random.Random("common-extra")
EXTRA = []
# Perform Location Response with every shape of the Location Estimate and every velocity type
for _t in (0, 1, 3, 5, 8, 9, 10, 11, 12, 13, 14):
    if _t == 5:
        _g = bytes([0x53]) + rbytes(_r, 18)
    else:
        _g = bytes([_t << 4]) + rbytes(_r, 26)
    EXTRA.append((100, bytes([0x2d, BE["BE_LOC_EST"], len(_g)]) + _g))
for _t in range(4):
    _v = bytes([_t << 4]) + rbytes(_r, 4 if _t == 0 else 7)
    EXTRA.append((100, bytes([0x2d, BE["BE_VEL_EST"], len(_v)]) + _v))
EXTRA.append((100, bytes([0x2d, BE["BE_LOC_EST"], 1, 0x00])))          # shape without coordinates
# GPRS attach accept and routing area update accept with an equivalent PLMN list
LAI = bytes([0x62, 0xf2, 0x10, 0x00, 0x07]) if 'LAI' not in globals() else LAI
_rai = bytes([0x62, 0xf2, 0x10, 0x00, 0x01, 0x01])
for _msg in (0x02, 0x09):
    EXTRA.append((8,
                  bytes([0x08, _msg, 0x01, 0x21] + ([0x42] if _msg == 0x02 else [])) + _rai + bytes([0x4a, 0x09, 0x62, 0xf2, 0x10, 0x62, 0xf2, 0x11, 0x62, 0xf2, 0x20])))
# RR System Information Type 3 and 6 (cell identity)
EXTRA.append((6, bytes([0x06, 0x1b, 0x12, 0x34]) + LAI + bytes([0x01, 0x02, 0x03, 0x45, 0x10, 0x20, 0x01, 0x02, 0x03, 0x2b, 0x2b, 0x2b, 0x2b])))
EXTRA.append((6, bytes([0x06, 0x1e, 0x12, 0x34]) + LAI + bytes([0x45, 0x10, 0x20, 0x01, 0x02, 0x03, 0x04])))
MALFORMED = [
    (100, bytes([0x2d, BE["BE_LOC_EST"], 5, 0x00, 1, 2, 3, 4])),     # location estimate: coordinates cut short
    (9, bytes([0x09, 0x01, 0x02, 0x00, 0x12])),            # CP-DATA with RP-DATA without elements
    (9, bytes([0x09, 0x01, 0x02, 0x04, 0x12])),            # CP-DATA with RP-ERROR without the cause
]


# ------------------------------------------------------------------ main
def main_frames():
    fr = open_conn()
    for (pd, v), ks in sorted(KEEP.items()):
        for k in ks:
            ti = [0x00, 0x80, 0x10, 0x70][k % 4] if pd in (0, 1, 3, 9, 10, 11) else 0
            fr.append(msg_frame(pd, table_msg(pd, v, k, ti)))
    for pd, d in EXTRA:
        fr.append(msg_frame(pd, d))
    # messages the dissector knows by name but has no function for: elements shown as bytes
    for (pd, v), el in sorted(TABLE.items()):
        if el is None and v and pd != 6:
            fr.append(msg_frame(pd, bytes([v, 0x5a, 0xa5]) if pd == 100 else bytes([pd, v, 0x5a, 0xa5])))
    # more SCCP connections: the first DTAP message of a connection labels it
    for n, first in enumerate([bytes([0x05, 0x3f, 0x01]), bytes([0x05, 0x04, 0x01, 0x00]),
                               bytes([0x03, 0x3f, 0x01])]):
        s = bytes([0, 0, 0x10 + n])
        d = bytes([0, 0, 0x20 + n])
        fr += [wrap(sccp_cr(s)), wrap(sccp_cc(s, d)), wrap(sccp_dt1(d, bssap_dtap(first)))]
    return fr


def malformed_frames():
    fr = open_conn() + [msg_frame(pd, d) for pd, d in MALFORMED]
    # every message that has a mandatory element, with nothing after the message type
    for (pd, v), el in sorted(TABLE.items()):
        if el and any(m.startswith("ELEM_MAND") for m, _ in el):
            fr.append(msg_frame(pd, bytes([v]) if pd == 100 else bytes([pd, v])))
    return fr


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(out + "/gsm_a_common-coverage.pcap", main_frames())
    write_pcap(out + "/gsm_a_common-coverage-malformed.pcap", malformed_frames())
