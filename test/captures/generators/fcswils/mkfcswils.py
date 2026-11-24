# Generates test/captures/fcswils_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic data only) ----
import struct
import sys
import os
import zlib

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            wl = len(fr)
            if isinstance(fr, tuple):
                fr, wl = fr
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), wl))
            f.write(fr)

def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)

def fchdr(r_ctl, d_id, s_id, ftype, f_ctl, oxid, rxid=0xffff, seq_id=0, seqcnt=0, param=0, df_ctl=0, cs_ctl=0):
    return (bytes([r_ctl]) + d_id + bytes([cs_ctl]) + s_id + bytes([ftype]) +
            struct.pack('>I', f_ctl)[1:] + bytes([seq_id, df_ctl]) +
            struct.pack('>HHHI', seqcnt, oxid, rxid, param))

def fcoe(fc, sof=0x2E, eof=0x42, crc=None, ver=0):
    hdr = bytes([ver << 4]) + bytes(12) + bytes([sof])
    if crc is None:
        crc = zlib.crc32(fc) & 0xffffffff
    return eth(hdr + fc + struct.pack('<I', crc) + bytes([eof, 0, 0, 0]), 0x8906)

A = bytes([0x01, 0x02, 0x03])
B = bytes([0x01, 0x04, 0x05])
FIRST = 0x200000
LAST = 0x100000
SEQLAST = 0x080000
RESP = 0x800000
# ---- end common helpers ----
#!/usr/bin/env python3
# Generator for the FC SW_ILS coverage captures.  Usage: mkfcswils.py <outdir>
# Writes fcswils-coverage.pcap (clean) and fcswils-coverage-malformed.pcap.
# SW_ILS is FC type 0x22 with R_CTL 0x02 (request) / 0x03 (reply), carried
# here over FCoE.  Names, zone data and so on are made up.

ox = [0x4000]

def put(size, *items):
    b = bytearray(size)
    for off, data in items:
        if isinstance(data, int):
            data = bytes([data])
        b[off:off + len(data)] = data
    return bytes(b)

def be16(v): return struct.pack('>H', v)
def be32(v): return struct.pack('>I', v)

def req(payload, oxid=None):
    if oxid is None:
        ox[0] += 1
        oxid = ox[0]
    return oxid, fcoe(fchdr(0x02, B, A, 0x22, FIRST | SEQLAST | 0x010000, oxid) + payload)

def acc(payload, oxid, r_ctl=0x03):
    return fcoe(fchdr(r_ctl, A, B, 0x22, RESP | LAST | SEQLAST, oxid, 0x2000 + (oxid & 0xff)) + payload)

def pair(f, payload_req, payload_acc=None, oxid=None):
    oxid, fr = req(payload_req, oxid)
    f.append(fr)
    if payload_acc is not None:
        f.append(acc(payload_acc, oxid))
    return oxid

WWN1 = bytes.fromhex('1000000000000001')
WWN2 = bytes.fromhex('1000000000000002')

# ---- ELP ----
def elp(opcode=0x10, clsf=0x80, c1=0xF0, c2=0x88, c3=0x88, fcmode=0, interlock=False):
    return put(110, (0, opcode), (8, 2), (9, b'\x00\x01'), (12, be32(10000)), (16, be32(2000)),
               (20, WWN1), (28, WWN2),
               (36, bytes([clsf, 0, 0, 0, 0x20 if interlock else 0, 0])),
               (42, be16(2048)), (44, be16(255)), (46, be16(64)), (48, be16(16)),
               (52, bytes([c1, 0])), (54, be16(1024)),
               (56, bytes([c2, 0])), (58, be16(1024)),
               (60, bytes([c3, 0])), (62, be16(1024)),
               (86, be16(fcmode)), (88, be16(0)), (90, be32(16)),
               (94, be32(1)), (98, be32(2)), (102, be32(3)), (106, be32(4)))

# ---- zoning ----
def zname(n):
    nb = n.encode()
    return bytes([len(nb), 0, 0, 0]) + nb

def mbr(t, ident, flags=0):
    return bytes([t, 0, flags, len(ident)]) + ident

def zone_obj(objtype, name, members, proto=0):
    return bytes([objtype, proto, 0, 0]) + zname(name) + be32(len(members)) + b''.join(members)

ALL_MBRS = [
    mbr(1, bytes.fromhex('2100000000000001')),
    mbr(2, be32(0x01020304), 1),
    mbr(3, bytes([1, 2, 3, 0])),
    mbr(4, zname('alias1')),
    mbr(0xE1, bytes.fromhex('2100000000000002') + bytes(8)),
    mbr(0xE2, be32(0x05060708) + bytes(range(8))),
    mbr(0xE3, bytes([4, 5, 6, 0]) + bytes(range(8))),
]

def zoneset_list(setname, objs):
    """Active zone set: name field (+ numrec + objects) preceded by the 2 byte length."""
    body = zname(setname)
    lst = be32(len(objs)) + b''.join(objs)
    return len(body) + len(lst), body + lst

def zone_payload(opcode, active, full):
    """opcode, rsvd, 2 byte active zone set length, active zone set, 4 byte full zone set length, full zone set"""
    out = bytes([opcode, 0])
    if active is None:
        out += be16(0)
    else:
        n, body = active
        out += be16(n) + body
    if full is None:
        out += be32(0)
    else:
        lst = be32(len(full)) + b''.join(full)
        out += be32(len(lst)) + lst
    return out

def build():
    f = []
    # ELP / ACC with the class valid bits clear and set and the flow control modes
    pair(f, elp(), elp(0x02))
    pair(f, elp(clsf=0x80, interlock=True, fcmode=1), elp(0x02, clsf=0, c1=0, c2=0, c3=0, fcmode=2))
    pair(f, elp(fcmode=0x1234, c2=0x80, c3=0x80), elp(0x02, fcmode=1, c2=0x80, c3=0x80))
    # EFP: domain and multicast records, then a record of another type
    def efp(recs, reclen=16, plen=None):
        pl = 16 + reclen * len(recs) if plen is None else plen
        body = put(16, (0, 0x11), (1, reclen), (2, be16(pl)), (7, 0x20), (8, WWN1))
        for r in recs:
            body += r.ljust(reclen, b'\0')
        return body
    dom = lambda d: put(16, (0, 1), (1, d), (8, WWN2))
    mc = lambda g: put(16, (0, 2), (1, g))
    pair(f, efp([dom(1), mc(7), dom(3), put(16, (0, 9))]), efp([dom(1)])[:0] + put(16, (0, 2)) + put(0))
    pair(f, efp([], plen=8), None)
    pair(f, efp([dom(2)], reclen=0), None)
    # DIA, RDI, RDI accept
    pair(f, put(12, (0, 0x12), (4, WWN1)), put(12, (0, 2), (4, WWN2)))
    pair(f, put(16, (0, 0x13), (2, be16(16)), (4, WWN1), (15, 5)), put(16, (0, 2), (2, be16(16)), (4, WWN2), (15, 6)))
    pair(f, put(12, (0, 0x13), (2, be16(12)), (4, WWN1)), put(12, (0, 2), (2, be16(12)), (4, WWN2)))
    # HLO, LSU (two records with link descriptors), LSA (headers), BF, RCF
    fspf = lambda op, flags=0: put(24, (0, op), (4, 2), (5, 1), (6, 2), (11, 10), (12, bytes(range(8))), (23, flags))
    hlo = put(40, (0, 0x14), (4, 2), (5, 1), (6, 2), (11, 10), (12, bytes(range(8))), (20, be32(0xAA)), (24, be32(20)), (28, be32(80)), (35, 11), (37, b'\x00\x00\x07'))
    pair(f, hlo, put(40, (0, 2)))
    def lsr(dom, links):
        h = put(28, (0, 1), (2, be16(5)), (4, be32(0x1234)), (11, dom), (15, dom), (16, be32(7)), (20, be16(0x1111)), (22, be16(28 + 16 * len(links))), (26, be16(len(links))))
        for i in range(links):
            h += put(16, (1, b'\x00\x00' + bytes([i])), (5, b'\x00\x00' + bytes([i + 1])), (9, b'\x00\x00\x02'), (12, 1), (14, be16(500)), (3, 11 + i))
        return h
    lsr_ = lambda dom, n: lsr(dom, list(range(n)))
    def lsr_(dom, n):
        h = put(28, (0, 1), (2, be16(5)), (4, be32(0x1234)), (11, dom), (15, dom), (16, be32(7)), (20, be16(0x1111)), (22, be16(28 + 16 * n)), (26, be16(n)))
        for i in range(n):
            h += put(16, (1, b'\x00\x00' + bytes([i])), (3, 11 + i), (5, b'\x00\x00' + bytes([i + 1])), (9, b'\x00\x00\x02'), (12, 1), (14, be16(500)))
        return h
    lsu = fspf(0x15, 1) + be32(2) + lsr_(10, 2) + lsr_(11, 0)
    pair(f, lsu, put(28, (0, 2)))
    lsa = fspf(0x16, 2) + be32(2) + lsr_(10, 0)[:24] + lsr_(12, 0)[:24]
    pair(f, lsa, None)
    pair(f, put(24, (0, 0x17)), put(4, (0, 2)))
    pair(f, put(4, (0, 0x18)), put(4, (0, 2)))
    # RSCN: with device entries, without (older devices), accept
    ent = lambda st: put(20, (0, st), (1, b'\x01\x02\x03'), (4, WWN1), (12, WWN2))
    rscn = put(16, (0, 0x1B), (4, 0x41), (5, b'\x01\x02\x03'), (8, be32(0x11)), (12, be32(2))) + ent(1) + ent(2)
    pair(f, rscn, put(4, (0, 2)))
    pair(f, put(16, (0, 0x1B), (4, 0x42), (5, b'\x01\x02\x03'), (8, be32(0x11)), (12, be32(3))), None)
    # DRLIR
    pair(f, put(16, (0, 0x1E)), put(4, (0, 2)))
    # unknown/unhandled opcodes are data: DSCN, LOOPD, and others, and beyond the table
    for op in (0x19, 0x1A, 0x1C, 0x1D, 0x20, 0x21, 0x27, 0x32, 0x33, 0x35, 0x7F):
        pair(f, put(16, (0, op), (4, b'data')), None)
    # SW_RJT for several requests, reason codes and explanations
    oxid = pair(f, elp(), None)
    f.append(acc(put(8, (0, 1), (5, 3), (6, 0x0f), (7, 0xaa)), oxid))
    for code, det in ((1, 0), (2, 0x2b), (4, 0x19), (5, 0x2a), (7, 0x10), (9, 0x4), (0xb, 0x0d), (0xff, 0x3)):
        oxid = pair(f, put(16, (0, 0x13), (2, be16(12)), (4, WWN1)), None)
        f.append(acc(put(8, (0, 1), (5, code), (6, det)), oxid))
    # zoning: merge request with all member types, one nested level of zone sets
    zones = [zone_obj(2, 'zone1', ALL_MBRS), zone_obj(2, 'z2', [ALL_MBRS[0]], 1), zone_obj(3, 'aliasobj', ALL_MBRS[:2])]
    zs = [zone_obj(1, 'zset1', [zone_obj(2, 'zoneA', ALL_MBRS[:3]), zone_obj(2, 'zoneB', [])])]
    mr = zone_payload(0x22, zoneset_list('active', zs), zones)
    pair(f, mr, put(8, (0, 2), (5, 0), (6, 0)))
    pair(f, zone_payload(0x22, None, zones[:1]), put(8, (0, 2), (5, 1), (6, 3)))
    pair(f, zone_payload(0x22, zoneset_list('active2', zones[:1]), None), put(8, (0, 2), (5, 1), (6, 0x0a)))
    # ACA / RCA
    pair(f, put(16, (0, 0x23), (2, be16(12)), (7, 1), (11, 2), (15, 3)), put(8, (0, 2), (5, 0)))
    pair(f, put(4, (0, 0x24)), put(8, (0, 2), (5, 1), (6, 2)))
    # SFC with a zone set and the full set, UFC
    pair(f, zone_payload(0x25, zoneset_list('sfcactive', zs), zones[:2]), put(8, (0, 2), (5, 0)))
    pair(f, zone_payload(0x25, None, None), put(8, (0, 2), (5, 1), (6, 1)))
    pair(f, put(4, (0, 0x26)), put(8, (0, 2), (5, 0)))
    # ESC request with three protocol descriptors and accept
    esc = put(12 + 36, (0, 0x30), (2, be16(48)), (4, b'VENDOR01'))
    for i in range(3):
        esc = esc[:12 + 12 * i] + b'DESCVEN' + bytes([48 + i]) + b'\0\0' + be16(i + 1) + esc[24 + 12 * i:]
    pair(f, esc, put(24, (0, 2), (4, b'VENDOR01'), (12, b'DESCVEN1'), (22, be16(2))))
    # ESS: interconnect element info and capability objects
    def ie(vendor=b'ACME', model=b'MDL-1', rel=b'1.0', extra=(b'x=1', b'y=2')):
        s = vendor + b'\0' + model + b'\0' + rel + b'\0'
        for e in extra:
            s += e + b'\0'
        s = s.ljust(252, b'\0')
        # the vendor specific strings run to 252 octets; pad with NULs forming empty strings
        return bytes([0, 0, 0, 40]) + s
    def capobj(t, st, entries):
        return bytes([t, st, 0, len(entries)]) + b''.join(entries)
    ent8 = lambda b3, v=0: put(8, (3, b3), (4, be32(v)))
    objs = [capobj(0xFC, 2, [ent8(0xF8, 7)]), capobj(0xFD, 0, [ent8(1, 8)]), capobj(0x09, 0, [ent8(1, 8)]), capobj(0xFA, 1, [ent8(0xF0)]),
            capobj(0xFA, 3, [ent8(0xFF)]), capobj(0xF7, 0, [ent8(0)]),
            # vendor-specific object: length field 24 -> 3 vendor entries of 8 octets
            bytes([0xE0, 1, 0, 24]) + b'T10VENDR' + bytes(24)]
    def ess_len(objs):
        return 256 + 4 + sum(len(o) for o in objs)
    ess = put(12, (0, 0x31), (8, be32(ess_len(objs)))) + ie() + be16(len(objs)) + be16(0) + b''.join(objs)
    pair(f, ess, put(12, (0, 2), (8, be32(256 + 4))) + ie() + be16(0) + be16(0))
    # ESS where a vendor object (two vendor entries) is followed by another object
    objs2 = [bytes([0xE0, 1, 0, 24]) + b'T10VENDR' + bytes(24), capobj(0xFC, 2, [ent8(0xF8, 7)])]
    ess2 = put(12, (0, 0x31), (8, be32(ess_len(objs2)))) + ie() + be16(len(objs2)) + be16(0) + b''.join(objs2)
    pair(f, ess2, None)
    # MRRA
    pair(f, put(28, (0, 0x34), (12, b'MRRAVEND'), (20, bytes(range(8)))), put(24, (0, 2), (4, b'MRRAVEND'), (12, be32(1)), (16, be32(4096)), (20, be32(30))))
    # AUTH_ILS goes to FC-SP
    pair(f, bytes([0x40, 0, 0x0c, 1]) + be32(20) + be32(1) + bytes(8), None)
    return f

def main(out):
    pcap(os.path.join(out, 'fcswils-coverage.pcap'), build())

    bad = []
    # the same exchange used by two requests (opcode of the exchange is updated on the first pass only)
    o = pair(bad, put(12, (0, 0x12), (4, WWN1)), put(12, (0, 2), (4, WWN2)))
    pair(bad, put(16, (0, 0x13), (2, be16(12)), (4, WWN1)), put(16, (0, 2), (2, be16(12)), (4, WWN2), (15, 5)), oxid=o)
    # an SW_ILS reply on an exchange that an ELS request created (conversation, but no SW_ILS request)
    bad.append(fcoe(fchdr(0x22, B, A, 0x01, FIRST | SEQLAST, 0x6010) + bytes([0x50, 0, 0, 0]) + bytes(8)))
    bad.append(acc(put(8, (0, 2)), 0x6010))
    # a zone member of unknown type (warning)
    bad.append(req(zone_payload(0x22, None, [zone_obj(2, 'zz', [mbr(9, bytes(4))])]))[1])
    # ACC without the request in the capture, and unknown exchange
    bad.append(acc(put(8, (0, 2)), 0x6001))
    bad.append(fcoe(fchdr(0x03, A, B, 0x22, RESP | LAST | SEQLAST, 0x6002, 0x2000) + put(8, (0, 2))))
    # an ACC to a request that is a reject-only style: SW_RJT without a request
    bad.append(acc(put(8, (0, 1), (5, 3), (6, 1)), 0x6003))
    # nested zone sets (zone set in zone set), ZONESET inside a zone set inside a merge request
    inner = zone_obj(1, 'inner', [zone_obj(1, 'innermost', [])])
    nested = zone_obj(1, 'outer', [inner])
    bad.append(req(zone_payload(0x22, zoneset_list('a', [nested]), None))[1])
    bad.append(req(zone_payload(0x25, None, [zone_obj(1, 'outer', [zone_obj(1, 'in', [])])]))[1])
    # ESS vendor object with a length that is not a multiple of 8
    def ie():
        return bytes([0, 0, 0, 40]) + b'A\0B\0C\0'.ljust(252, b'\0')
    for L in (17, 9, 0, 255):
        vo = bytes([0xE0, 1, 0, L]) + b'T10VENDR' + bytes(40)
        body = put(12, (0, 0x31), (8, be32(256 + 4 + 12 + 40))) + ie() + be16(1) + be16(0) + vo
        bad.append(req(body)[1])
    # truncated payloads for each opcode that reads fixed offsets
    for op, n in ((0x10, 60), (0x11, 20), (0x12, 8), (0x13, 14), (0x14, 30), (0x15, 40), (0x16, 40), (0x1B, 14),
                  (0x22, 10), (0x23, 6), (0x25, 10), (0x30, 14), (0x31, 100), (0x34, 14), (0x01, 6)):
        bad.append(req(put(n, (0, op), (2, be16(200))))[1])
    # counts and lengths larger than the packet
    bad.append(req(fspf_ := put(28, (0, 0x15)) + be32(0x7FFFFFFF))[1])
    bad.append(req(put(28, (0, 0x16)) + be32(0x10000))[1])
    bad.append(req(put(16, (0, 0x1B), (12, be32(0xFFFFFFF0))) + bytes(40))[1])
    bad.append(req(put(16, (0, 0x13), (2, be16(0xFFFF)), (4, WWN1)))[1])
    bad.append(req(put(16, (0, 0x23), (2, be16(0xFFFF))))[1])
    bad.append(req(put(16, (0, 0x30), (2, be16(0xFFFF))))[1])
    bad.append(req(put(32, (0, 0x11), (1, 4), (2, be16(0x400))))[1])
    pcap(os.path.join(out, 'fcswils-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
