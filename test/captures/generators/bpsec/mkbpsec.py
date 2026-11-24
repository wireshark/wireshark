#!/usr/bin/env python3
# Generates test/captures/bpsec_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic BPSec (RFC 9172) coverage captures: BPv7 bundles over
UDP port 4556 carrying Block Integrity (BIB, type 11) and Block
Confidentiality (BCB, type 12) blocks with the RFC 9173 default security
contexts 1 (BIB-HMAC-SHA2) and 2 (BCB-AES-GCM), the COSE context 3, a
private context and an unregistered one.

Everything is built with struct; nothing comes from a real network.

Usage: mkbpsec.py <outdir>
"""
import os
import struct
import sys


# --- CBOR -----------------------------------------------------------------

def head(major, val):
    if val < 24:
        return bytes([(major << 5) | val])
    if val < 0x100:
        return bytes([(major << 5) | 24, val])
    if val < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack('>H', val)
    if val < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack('>I', val)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', val)


def u(v):
    return head(0, v)


def nint(v):
    """CBOR negative integer v (v < 0)."""
    return head(1, -1 - v)


def i(v):
    return u(v) if v >= 0 else nint(v)


def bstr(b):
    return head(2, len(b)) + b


def tstr(s):
    b = s.encode()
    return head(3, len(b)) + b


def arr(*items):
    return head(4, len(items)) + b''.join(items)


def cmap(*pairs):
    return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)


def tag(t, item):
    return head(6, t) + item


NULL = b'\xf6'
TRUE = b'\xf5'
FALSE = b'\xf4'
BREAK = b'\xff'


# --- BPv7 -----------------------------------------------------------------

def eid_ipn(node, svc):
    return arr(u(2), arr(u(node), u(svc)))


def eid_dtn(ssp):
    return arr(u(1), tstr(ssp))


SRC = eid_ipn(1, 1)
SEQ = [0]


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def primary(src=None, dst=None):
    """Primary block with a CRC-16 (RFC 9171 requires a CRC unless a BIB
    covers it) and a unique creation timestamp."""
    SEQ[0] += 1
    src = src or SRC
    dst = dst or eid_ipn(2, 1)
    blk = arr(u(7), u(0), u(1), dst, src, eid_ipn(1, 0),
              arr(u(700000000 + SEQ[0]), u(SEQ[0])), u(3600000), bstr(b'\0\0'))
    return blk[:-2] + struct.pack('>H', crc16_x25(blk))


def canonical(btype, num, data_item):
    """Canonical block whose BTSD is data_item (already CBOR) or raw."""
    return arr(u(btype), u(num), u(0), u(0), bstr(data_item))


def payload(data=b'payload data'):
    return canonical(1, 1, data)


def bundle(*blocks, src=None, dst=None):
    return b'\x9f' + primary(src, dst) + b''.join(blocks) + BREAK


def asb(targets, ctx, secsrc=None, params=None, results=None):
    """Abstract Security Block BTSD.  params: list of (id, value item);
    results: list (per target) of lists of (id, value item)."""
    secsrc = secsrc if secsrc is not None else SRC
    flags = 1 if params is not None else 0
    b = arr(*[u(t) for t in targets]) + i(ctx) + u(flags) + secsrc
    if params is not None:
        b += arr(*[arr(i(pid), val) for pid, val in params])
    if results is None:
        results = [[] for _ in targets]
    b += arr(*[arr(*[arr(i(rid), val) for rid, val in res]) for res in results])
    return b


def bib(num, *a, **k):
    return canonical(11, num, asb(*a, **k))


def bcb(num, *a, **k):
    return canonical(12, num, asb(*a, **k))


# --- network --------------------------------------------------------------

def ipv4_udp(pl, sport=4556, dport=4556, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(pl), 0) + pl
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                      bytes(src), bytes(dst))
    s = sum(struct.unpack('>10H', iph))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    iph = iph[:10] + struct.pack('>H', ~s & 0xffff) + iph[12:]
    eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
    return eth + iph + udp


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for n, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + n, 0, len(fr), len(fr)))
            f.write(fr)


# --- COSE pieces ----------------------------------------------------------

PROT_ES256 = bstr(cmap((u(1), nint(-7))))          # {1: -7}
PROT_A128GCM = bstr(cmap((u(1), u(1))))            # {1: 1}
PROT_HS256 = bstr(cmap((u(1), u(5))))              # {1: 5}
UNPROT_KID = cmap((u(4), bstr(b'kid-1')))          # {4: 'kid-1'}
UNPROT_IV = cmap((u(5), bstr(bytes(range(12)))))   # {5: iv}
EMPTY_MAP = cmap()

COSE_SIGN1 = arr(PROT_ES256, UNPROT_KID, NULL, bstr(b'\x51' * 64))
COSE_SIGN1_PAYLOAD = arr(PROT_ES256, EMPTY_MAP, bstr(b'detached?'), bstr(b'\x52' * 64))
COSE_SIGN = arr(bstr(b''), EMPTY_MAP, NULL,
                arr(arr(PROT_ES256, UNPROT_KID, bstr(b'\x53' * 64)),
                    arr(bstr(b''), cmap((u(4), bstr(b'kid-2'))), bstr(b'\x54' * 64))))
COSE_MAC0 = arr(PROT_HS256, UNPROT_KID, NULL, bstr(b'\x61' * 32))
COSE_MAC = arr(PROT_HS256, EMPTY_MAP, NULL, bstr(b'\x62' * 32),
               arr(arr(bstr(b''), cmap((u(1), nint(-6)), (u(4), bstr(b'kid-3'))), bstr(b''))))
COSE_ENCRYPT0 = arr(PROT_A128GCM, UNPROT_IV, NULL)
COSE_ENCRYPT0_CT = arr(PROT_A128GCM, UNPROT_IV, bstr(b'\x71' * 16))
COSE_ENCRYPT = arr(PROT_A128GCM, UNPROT_IV, NULL,
                   arr(arr(bstr(b''), cmap((u(1), nint(-5)), (u(4), bstr(b'kek'))),
                           bstr(b'\x72' * 24)),
                       # recipient with a nested recipient list (4 items)
                       arr(bstr(b''), cmap((u(1), nint(-3))), bstr(b'\x73' * 24),
                           arr(arr(bstr(b''), cmap((u(1), nint(-6))), bstr(b''))))))


def main_frames():
    F = []
    ad = cmap  # noqa
    # 1: BIB ctx 1 on the payload, every ctx 1 parameter, an HMAC result
    F.append(bundle(
        bib(2, [1], 1, params=[(1, u(5)), (2, bstr(b'\xa1' * 40)), (3, u(7))],
            results=[[(1, bstr(b'\xb1' * 32))]]),
        payload()))
    # 2: BIB ctx 1 on the primary block and a hop count block, without
    #    parameters; BCB ctx 2 on the primary block (marks primary c)
    F.append(bundle(
        canonical(10, 3, arr(u(30), u(1))),
        bib(2, [0, 3], 1, results=[[(1, bstr(b'\xb2' * 48))], [(1, bstr(b'\xb3' * 48))]]),
        bcb(4, [0], 2, results=[[(1, bstr(b'\xc0' * 16))]]),
        payload()))
    # 3: BCB ctx 2 on the payload, every ctx 2 parameter, AES variant 1
    F.append(bundle(
        bcb(2, [1], 2, params=[(1, bstr(bytes(range(12)))), (2, u(1)),
                               (3, bstr(b'\xa2' * 24)), (4, u(0))],
            results=[[(1, bstr(b'\xc1' * 16))]]),
        payload(b'\x99' * 24)))
    # 4: BCB ctx 2 (AES variant 3) on a BIB and the payload, BIB ctx 1
    #    (SHA variant 6) on the payload: the BIB is itself ciphertext
    F.append(bundle(
        bcb(3, [2, 1], 2, params=[(1, bstr(bytes(range(12)))), (2, u(3)), (4, u(7))],
            results=[[(1, bstr(b'\xc2' * 16))], [(1, bstr(b'\xc3' * 16))]]),
        bib(2, [1], 1, params=[(1, u(6))], results=[[(1, bstr(b'\xb4' * 48))]]),
        payload(b'\x98' * 24)))
    # 5: BIB ctx 1 with SHA variant 7, an unknown variant in a second
    #    BIB, and an unknown result ID in ctx 1
    F.append(bundle(
        bib(2, [1], 1, params=[(1, u(7)), (3, u(1))],
            results=[[(1, bstr(b'\xb5' * 64)), (9, tstr('extra'))]]),
        bib(3, [4], 1, params=[(1, u(99)), (9, u(1))],
            results=[[(1, bstr(b'\xb6' * 32))]]),
        canonical(7, 4, u(1000)),
        payload()))
    # 6: BIB ctx 3 (COSE): protected/unprotected header and AAD scope
    #    parameters, COSE_Sign1 and COSE_Mac0 results
    F.append(bundle(
        bib(2, [1], 3, params=[(3, bstr(cmap((u(1), nint(-7))))),
                               (4, bstr(UNPROT_KID)),
                               (5, cmap((i(0), u(1)), (i(1), u(3)), (i(-1), u(2))))],
            results=[[(18, bstr(COSE_SIGN1)), (17, bstr(COSE_MAC0))]]),
        payload()))
    # 7: BIB ctx 3 with COSE_Sign (two signatures) and COSE_Mac
    #    (one recipient) on the payload and the primary block
    F.append(bundle(
        bib(2, [1, 0], 3, params=[(5, cmap((i(1), u(2))))],
            results=[[(98, bstr(COSE_SIGN))], [(97, bstr(COSE_MAC))]]),
        payload()))
    # 8: BCB ctx 3 with COSE_Encrypt0 (detached and attached ciphertext)
    #    and COSE_Encrypt with a nested recipient
    F.append(bundle(
        bcb(2, [1, 3], 3, params=[(3, bstr(EMPTY_MAP)), (4, bstr(EMPTY_MAP)),
                                  (5, cmap())],
            results=[[(16, bstr(COSE_ENCRYPT0)), (96, bstr(COSE_ENCRYPT))],
                     [(16, bstr(COSE_ENCRYPT0_CT))]]),
        canonical(10, 3, arr(u(30), u(2))),
        payload(b'\x97' * 32)))
    # 9: COSE_Sign1 with an attached payload, an unregistered COSE
    #    parameter and result ID (generic CBOR)
    F.append(bundle(
        bib(2, [1], 3, params=[(1, u(42)), (5, cmap((i(1), u(0))))],
            results=[[(18, bstr(COSE_SIGN1_PAYLOAD)), (19, bstr(b'\x00'))]]),
        payload()))
    # 10: private (negative) context ID -5, security source differs from
    #     the bundle source (dtn scheme)
    F.append(bundle(
        bib(2, [1], -5, secsrc=eid_dtn('//secnode/'),
            params=[(1, u(1)), (-2, tstr('x'))],
            results=[[(1, bstr(b'\x01\x02')), (-1, arr(u(1), u(2)))]]),
        payload()))
    # 11: unregistered context 200 on both block types, security source
    #     a different ipn node
    F.append(bundle(
        bcb(3, [1], 200, secsrc=eid_ipn(9, 0), params=[(1, cmap((u(1), u(2))))],
            results=[[(1, bstr(b'\xdd' * 8))]]),
        bib(2, [1], 200, results=[[]]),
        payload(b'\x96' * 8)))
    # 12: a BIB with no targets and no results, and one whose single
    #     target has an empty result list
    F.append(bundle(
        bib(2, [], 1),
        bib(3, [1], 2, results=[[]]),
        payload()))
    # 13: BIB and BCB on a bundle from a dtn source, secsrc dtn equal
    F.append(bundle(
        bib(2, [1], 1, secsrc=eid_dtn('//src/'), params=[(1, u(5))],
            results=[[(1, bstr(b'\xb7' * 32))]]),
        bcb(3, [1], 2, secsrc=eid_dtn('//src/'),
            params=[(1, bstr(b'\x00' * 12)), (2, u(1))],
            results=[[(1, bstr(b'\xc4' * 16))]]),
        payload(b'\x95' * 12),
        src=eid_dtn('//src/'), dst=eid_dtn('//dst/svc')))
    return [ipv4_udp(b) for b in F]


def raw_asb(btype, num, raw):
    return arr(u(btype), u(num), u(0), u(0), bstr(raw))


def malformed_frames():
    F = []
    # 1: context ID zero (warning)
    F.append(bundle(bib(2, [1], 0, results=[[(1, bstr(b'\x00'))]]), payload()))
    # 2: target block number not present (warning)
    F.append(bundle(bib(2, [9], 1, results=[[(1, bstr(b'\x00'))]]), payload()))
    # 3: ctx 1 SHA variant given as an array: partially dissected value
    F.append(bundle(bib(2, [1], 1, params=[(1, arr(u(5)))],
                        results=[[(1, bstr(b'\x00'))]]), payload()))
    # 4: target list is not an array
    F.append(bundle(raw_asb(11, 2, u(1) + u(1) + u(0) + SRC + arr()), payload()))
    # 5: target is not an unsigned integer
    F.append(bundle(raw_asb(11, 2, arr(tstr('a')) + u(1) + u(0) + SRC + arr()), payload()))
    # 6: context ID not an integer, flags not an integer
    F.append(bundle(raw_asb(11, 2, arr() + tstr('c') + tstr('f') + SRC + arr()), payload()))
    # 7: result count differs from target count
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + SRC + arr()), payload()))
    # 8: parameter list not an array, parameter pair of the wrong size
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(1) + SRC + u(3)
                            + arr(arr())), payload()))
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(1) + SRC + arr(arr(u(1)))
                            + arr(arr())), payload()))
    # 10: parameter ID not an integer
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(1) + SRC
                            + arr(arr(tstr('p'), u(5))) + arr(arr())), payload()))
    # 11: parameter value truncated
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(1) + SRC
                            + arr(arr(u(2))) + head(2, 40) + b'\x00'), payload()))
    # 12: result target list not an array, result pair of wrong size
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + SRC + arr(u(1))), payload()))
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + SRC + arr(arr(arr()))), payload()))
    # 14: result ID not an integer, result value truncated
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + SRC
                            + arr(arr(arr(tstr('r'), u(1))))), payload()))
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + SRC
                            + arr(arr(arr(u(1)))) + head(2, 40)), payload()))
    # 16: block truncated after the target list
    F.append(bundle(raw_asb(12, 2, arr(u(1))), payload()))
    # 17: security source not an EID
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + u(7) + arr(arr())), payload()))
    # 18: wrong value types for every default-context parameter and result
    F.append(bundle(
        bib(2, [1], 1, params=[(1, tstr('x')), (2, u(1)), (3, tstr('s'))],
            results=[[(1, u(1))]]),
        bcb(3, [1], 2, params=[(1, u(1)), (2, bstr(b'')), (3, u(1)), (4, bstr(b''))],
            results=[[(1, u(1))]]),
        payload()))
    # 19: COSE: AAD scope not a map, protected header not a bstr,
    #     unprotected header bstr holding a non-map, result not a bstr
    F.append(bundle(
        bib(2, [1], 3, params=[(5, arr()), (3, u(1)), (4, bstr(u(1)))],
            results=[[(18, u(1)), (17, bstr(arr()))]]),
        payload()))
    # 20: COSE AAD scope with non-integer block number and flags
    F.append(bundle(
        bib(2, [1], 3, params=[(5, cmap((tstr('b'), tstr('f'))))],
            results=[[(98, bstr(arr(u(1))))]]),
        payload()))
    # 21: COSE messages of the wrong shape
    F.append(bundle(
        bcb(2, [1], 3, results=[[(96, bstr(arr())), (16, bstr(u(1))),
                                 (97, bstr(arr(bstr(b''), cmap(), NULL, bstr(b''), u(1))))]]),
        payload()))
    # 22: security block with a block number that is not an integer
    F.append(bundle(
        arr(u(11), tstr('n'), u(0), u(0), bstr(asb([1], 1, results=[[(1, bstr(b''))]]))),
        payload()))
    # 23: security block number 0 (no number to record in the target)
    F.append(bundle(bib(0, [1], 1, results=[[(1, bstr(b''))]]), payload()))
    # 24: COSE additional protected header as an empty bstr: the header
    #     map dissector reads past the end of the empty value
    F.append(bundle(bib(2, [1], 3, params=[(3, bstr(b''))],
                        results=[[(17, bstr(COSE_MAC0))]]), payload()))
    # 25: parameter value that cannot be skipped (a bare break code) and
    #     26: result value with a reserved additional-information value
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(1) + SRC
                            + arr(arr(u(1), BREAK)) + arr(arr())), payload()))
    F.append(bundle(raw_asb(11, 2, arr(u(1)) + u(1) + u(0) + SRC
                            + arr(arr(arr(u(1), b'\x1c')))), payload()))
    return [ipv4_udp(b) for b in F]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bpsec-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bpsec-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
