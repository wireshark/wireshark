#!/usr/bin/env python3
# Generates test/captures/esis_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic ESIS (ISO 9542 ES-IS) coverage captures.
# Usage: mkesis.py <outdir>
# ESIS runs over 802.3 + LLC (DSAP/SSAP 0xFE, OSI network layer) with
# NLPID 0x82, reached by default.
import os
import struct
import sys

def write_pcap(fn, frames, linktype=1):
    with open(fn, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr)

ALL_ES = bytes.fromhex("09002b000004")
ALL_IS = bytes.fromhex("09002b000005")
ES_MAC = bytes.fromhex("020000000001")
IS_MAC = bytes.fromhex("020000000002")

def llc_frame(pdu, src, dst, extra=b""):
    llc = b"\xfe\xfe\x03" + pdu + extra
    fr = dst + src + struct.pack(">H", len(llc)) + llc
    return fr + b"\x00" * max(0, 60 - len(fr))

def fletcher(pdu):
    """Return the PDU with the ISO 8473 checksum at octets 8-9 filled in."""
    b = bytearray(pdu)
    b[7] = b[8] = 0
    c0 = c1 = 0
    for x in b:
        c0 = (c0 + x) % 255
        c1 = (c1 + c0) % 255
    L = len(b); n = 8
    x = ((L - n) * c0 - c1) % 255
    y = ((L - n + 1) * (255 - c0) + c1) % 255
    b[7] = x or 255
    b[8] = y or 255
    c0 = c1 = 0
    for v in b:
        c0 = (c0 + v) % 255
        c1 = (c1 + c0) % 255
    assert c0 == 0 and c1 == 0
    return bytes(b)

def esis(ptype, holdtime, var, checksum=True, version=1, length=None, res=0, cks=None):
    l = 9 + len(var) if length is None else length
    pdu = bytes([0x82, l, version, res, ptype]) + struct.pack(">HH", holdtime, 0) + var
    if cks is not None:
        return pdu[:7] + struct.pack(">H", cks) + pdu[9:]
    return fletcher(pdu[:l]) + pdu[l:] if checksum else pdu

def opt(t, v):
    return bytes([t, len(v)]) + v

NSAP1 = bytes.fromhex("49000100000000000a0000")            # 11 octets, AFI 49
NSAP2 = bytes.fromhex("3900010203040506070809101112131415161700")  # 20 octets
NET_IS = bytes.fromhex("490001020000000002" "00")          # 10 octets, NSEL 0
DA = bytes.fromhex("490001000000000000330000")             # 12 octets

def esh(sas, opts=b"", **kw):
    var = bytes([len(sas)]) + b"".join(bytes([len(s)]) + s for s in sas) + opts
    return esis(0x02, kw.pop("ht", 300), var, **kw)

def ish(net, opts=b"", **kw):
    return esis(0x04, kw.pop("ht", 600), bytes([len(net)]) + net + opts, **kw)

def rd(da, snpa, net, opts=b"", **kw):
    var = bytes([len(da)]) + da + bytes([len(snpa)]) + snpa
    var += bytes([len(net)]) + net
    return esis(0x06, kw.pop("ht", 120), var + opts, **kw)

def main(out):
    f = []
    # 1: ES Hello, one source address, no options, checksum verified
    f.append(llc_frame(esh([NSAP1]), ES_MAC, ALL_IS))
    # 2: ES Hello, three source addresses (11, 20 and 8 octets), options
    #    security (source address specific), QoS, priority, and no checksum
    opts = (opt(0xC5, b"\x40\x01\x02") + opt(0xC3, bytes([0xC0 | 0x15]))
            + opt(0xCD, b"\x05"))
    f.append(llc_frame(esh([NSAP1, NSAP2, bytes.fromhex("4700050102030405")], opts, checksum=False, ht=65535), ES_MAC, ALL_IS))
    # 3: ES Hello without source addresses
    f.append(llc_frame(esh([], ht=0), ES_MAC, ALL_IS))
    # 4: IS Hello, NET, suggested ES configuration timer option, checksum
    f.append(llc_frame(ish(NET_IS, opt(0xC6, struct.pack(">H", 50))), IS_MAC, ALL_ES))
    # 5: IS Hello without options and without checksum, PDU type octet with
    #    the high bits set (only the low 5 bits are the type)
    p = bytearray(ish(NET_IS, checksum=False)); p[4] |= 0xE0
    f.append(llc_frame(bytes(p), IS_MAC, ALL_ES))
    # 6: Redirect to an IS: DA, SNPA (6 octets), NET, address and SNPA
    #    mask options, checksum
    f.append(llc_frame(rd(DA, bytes.fromhex("020000000003"), NET_IS,
                          opt(0xE1, bytes.fromhex("490001")) + opt(0xE2, b"\xff\xff\xff\x00\x00\x00")),
                       IS_MAC, ES_MAC))
    # 7: Redirect to an ES (NETL 0), priority above the maximum, padding
    f.append(llc_frame(rd(DA, bytes.fromhex("020000000004"), b"",
                          opt(0xCD, b"\x0f") + opt(0xCC, b"\x00\x00")),
                       IS_MAC, ES_MAC))
    # 8: Redirect to an ES (NETL 0) without options
    f.append(llc_frame(rd(NSAP1, bytes.fromhex("020000000005"), b"", checksum=False), IS_MAC, ES_MAC))
    # 9: unknown PDU type 8 (warning expert info)
    f.append(llc_frame(esis(0x08, 30, b""), ES_MAC, ALL_IS))
    # 10: version 2 (warning expert info), ES Hello
    f.append(llc_frame(esh([NSAP1], version=2), ES_MAC, ALL_IS))
    # 11: IS Hello with octets after the PDU length (ignored)
    f.append(llc_frame(ish(NET_IS), IS_MAC, ALL_ES, extra=b"\xde\xad\xbe\xef"))
    write_pcap(os.path.join(out, "esis-coverage.pcap"), f)

    m = []
    # 1: the reproducer of "ESIS: Stop when the header length is shorter
    #    than the fixed header": header length 5. Before the fix the
    #    variable part length wrapped to 252 and the options were parsed
    #    from the bytes after the PDU (the QoS option below).
    sa = bytes.fromhex("490001020000000000010000")
    rep = bytes([0x82, 5, 1, 0, 2]) + struct.pack(">HH", 10, 0) + bytes([1, len(sa)]) + sa
    rep += bytes([0xC5, 1, 0x0F, 0xC3, 2, 0, 5])
    m.append(llc_frame(rep, ES_MAC, ALL_IS))
    # 2: bad checksum (error expert info)
    m.append(llc_frame(esh([NSAP1], cks=0x1234), ES_MAC, ALL_IS))
    # 3: header length beyond the data: checksum cannot be computed and
    #    the options run off the end
    p = esh([NSAP1], checksum=False)
    p = p[:1] + bytes([60]) + p[2:7] + b"\x12\x34" + p[9:]
    m.append(llc_frame(p, ES_MAC, ALL_IS))
    # 4: ES Hello whose source address length runs off the end
    p = bytes([0x82, 12, 1, 0, 2, 0, 10, 0, 0, 1, 40, 0x49])
    m.append(llc_frame(p, ES_MAC, ALL_IS))
    # 5: Redirect cut after the destination address
    p = rd(DA, b"\x02\x00\x00\x00\x00\x03", NET_IS, checksum=False)
    m.append(llc_frame(p[:9 + 1 + len(DA)], IS_MAC, ES_MAC))
    # 6: header length 0 and the fixed header only
    m.append(llc_frame(bytes([0x82, 0, 1, 0, 4, 0, 1, 0, 0]), IS_MAC, ALL_ES))
    # 7: global unique security option (handed to the Decode As table)
    m.append(llc_frame(esh([NSAP1], opt(0xC5, b"\xc0\x01\x02\x03")), ES_MAC, ALL_IS))
    write_pcap(os.path.join(out, "esis-coverage-malformed.pcap"), m)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
