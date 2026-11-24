#!/usr/bin/env python3
# Generates test/captures/atn_cm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic ATN Context Management (CM) captures for
# epan/dissectors/packet-atn-cm.c. Every packet is built here with
# struct and a small unaligned-PER bit writer; nothing comes from a real
# network.
#
# Stack: Ethernet / LLC (FE FE 03) / CLNP (20-octet ATN NSAPs, NSEL 0x21)
# / COTP (CR, CC, DT) / ATN-ULCS (session+presentation+ACSE in CR/CC,
# PER Fully-encoded-data in DT) / ATN-CM (unaligned PER).
#
# Usage: mkatn_cm.py <outdir>
import os
import struct
import sys


class Bits:
    def __init__(self):
        self.b = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.b.append((val >> i) & 1)
        return self

    def octets(self, data):
        for c in data:
            self.put(c, 8)
        return self

    def ia5(self, s):
        for c in s.encode('ascii'):
            self.put(c, 7)
        return self

    def add(self, other):
        self.b += other.b
        return self

    def padded(self):
        return self.b + [0] * (-len(self.b) % 8)

    def bytes_(self):
        b = self.padded()
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


# ---------------------------------------------------------------- ATN-CM PER

def short_tsap(ars=None, locsys=bytes(range(0x30, 0x3a))):
    w = Bits()
    w.put(1 if ars is not None else 0, 1)
    if ars is not None:
        w.octets(ars)                      # OCTET STRING (SIZE(3))
    w.put(len(locsys) - 10, 1)             # SIZE(10..11)
    w.octets(locsys)
    return w


def long_tsap(rdp=b'\x47\x00\x27\x81\x10', ars=None, locsys=bytes(range(0x30, 0x3a))):
    w = Bits()
    w.octets(rdp)                          # OCTET STRING (SIZE(5))
    w.add(short_tsap(ars, locsys))
    return w


def aeq_version(q, v):
    return Bits().put(q, 8).put(v - 1, 8)


def aeq_version_address(q, v, addr_long, addr):
    w = aeq_version(q, v)
    w.put(0 if addr_long else 1, 1)        # APAddress CHOICE
    w.add(addr)
    return w


def seq_of(items):
    w = Bits().put(len(items) - 1, 8)      # SIZE(1..256)
    for it in items:
        w.add(it)
    return w


def date_time(y, mo, d, h, mi):
    return Bits().put(y - 1996, 7).put(mo - 1, 4).put(d - 1, 5).put(h, 5).put(mi, 6)


def logon_request(flight, tsap, ground=None, air_only=None, facility=None,
                  dep=None, dest=None, etd=None):
    w = Bits()
    for opt in (ground, air_only, facility, dep, dest, etd):
        w.put(0 if opt is None else 1, 1)
    w.put(len(flight) - 2, 3).ia5(flight)  # IA5String (SIZE(2..8))
    w.add(tsap)
    if ground is not None:
        w.add(seq_of(ground))
    if air_only is not None:
        w.add(seq_of(air_only))
    if facility is not None:
        w.put(len(facility) - 4, 3).ia5(facility)  # SIZE(4..8)
    if dep is not None:
        w.ia5(dep)                         # SIZE(4)
    if dest is not None:
        w.ia5(dest)
    if etd is not None:
        w.add(etd)
    return w


def logon_response(air=None, ground_only=None):
    w = Bits()
    w.put(0 if air is None else 1, 1).put(0 if ground_only is None else 1, 1)
    if air is not None:
        w.add(seq_of(air))
    if ground_only is not None:
        w.add(seq_of(ground_only))
    return w


def abort_reason(v):
    if v < 10:
        return Bits().put(0, 1).put(v, 4)  # ENUMERATED (10 values, ...)
    # extension value: normally small non-negative whole number
    return Bits().put(1, 1).put(0, 1).put(v - 10, 6)


def air_msg(idx, body):
    """CMAircraftMessage CHOICE (3 root alternatives, extensible)."""
    return Bits().put(0, 1).put(idx, 2).add(body)


def gnd_msg(idx, body):
    """CMGroundMessage CHOICE (6 root alternatives, extensible)."""
    return Bits().put(0, 1).put(idx, 3).add(body)


def ext_choice(idx, content):
    """An extension alternative the dissector does not know: ext bit,
    normally small index, open type with a length octet."""
    return Bits().put(1, 1).put(0, 1).put(idx, 6).put(len(content), 8).octets(content)


TSAP_A = long_tsap()
TSAP_B = long_tsap(rdp=b'\x47\x00\x27\x81\x22', ars=b'\x00\x00\x99',
                   locsys=bytes(range(0x40, 0x4b)))
SHORT = short_tsap(ars=b'\x01\x02\x03', locsys=bytes(range(0x50, 0x5b)))
SHORT_NOARS = short_tsap()

GROUND_APPS = [aeq_version_address(2, 1, True, long_tsap(ars=b'\xab\xcd\xef')),
               aeq_version_address(22, 2, False, SHORT),
               aeq_version_address(3, 255, False, SHORT_NOARS)]
AIR_ONLY = [aeq_version(1, 1), aeq_version(255, 7)]

LOGON_MIN = logon_request('AB', TSAP_A)
LOGON_FULL = logon_request('KLM1234', TSAP_B, ground=GROUND_APPS, air_only=AIR_ONLY,
                           facility='EHAAZXYZ', dep='EHAM', dest='LFPG',
                           etd=date_time(2026, 10, 29, 23, 59))
LOGON_MIXED = logon_request('SAS12345', TSAP_A, ground=GROUND_APPS[:1],
                            facility='ESOS', dest='KJFK',
                            etd=date_time(1996, 1, 1, 0, 0))

RESP_EMPTY = logon_response()
RESP_AIR = logon_response(air=GROUND_APPS)
RESP_GND = logon_response(ground_only=AIR_ONLY)
RESP_BOTH = logon_response(air=GROUND_APPS[1:], ground_only=AIR_ONLY[:1])

CONTACT_REQ = Bits().put(4, 3).ia5('LFFFZQZQ').add(long_tsap(ars=b'\x11\x22\x33'))
CONTACT_REQ2 = Bits().put(0, 3).ia5('EGTT').add(long_tsap())

# Downlink and uplink message sets (name, bits)
DOWN = [('cmLogonRequest (minimal)', air_msg(0, LOGON_MIN)),
        ('cmLogonRequest (all optionals)', air_msg(0, LOGON_FULL)),
        ('cmLogonRequest (some optionals)', air_msg(0, LOGON_MIXED)),
        ('cmContactResponse contactSuccess', air_msg(1, Bits().put(0, 1))),
        ('cmContactResponse contactNotSuccessful', air_msg(1, Bits().put(1, 1)))]
DOWN += [('cmAbortReason %d' % v, air_msg(2, abort_reason(v))) for v in range(11)]
DOWN += [('unknown extension alternative', ext_choice(3, b'\x5a\xa5'))]

UP = [('cmLogonResponse (empty)', gnd_msg(0, RESP_EMPTY)),
      ('cmLogonResponse (air initiated)', gnd_msg(0, RESP_AIR)),
      ('cmLogonResponse (ground only)', gnd_msg(0, RESP_GND)),
      ('cmLogonResponse (both)', gnd_msg(0, RESP_BOTH)),
      ('cmUpdate', gnd_msg(1, RESP_BOTH)),
      ('cmUpdate (empty)', gnd_msg(1, RESP_EMPTY)),
      ('cmContactRequest', gnd_msg(2, CONTACT_REQ)),
      ('cmContactRequest (short facility)', gnd_msg(2, CONTACT_REQ2)),
      ('cmForwardRequest (full)', gnd_msg(3, LOGON_FULL)),
      ('cmForwardRequest (minimal)', gnd_msg(3, LOGON_MIN))]
UP += [('cmAbortReason %d' % v, gnd_msg(4, abort_reason(v))) for v in range(11)]
UP += [('cmForwardResponse %d' % v, gnd_msg(5, Bits().put(v, 2))) for v in range(3)]
UP += [('unknown extension alternative', ext_choice(6, b'\x01'))]


# ---------------------------------------------------------------- ATN-ULCS

def bitstring(w, payload_bits):
    """Unconstrained BIT STRING length determinant plus the bits."""
    n = len(payload_bits)
    if n < 128:
        w.put(n, 8)
    else:
        w.put(2, 2).put(n, 14)
    w.b += payload_bits
    return w


def pdv(ctx, payload):
    """Fully-encoded-data with one PDV-list, arbitrary encoding."""
    w = Bits()
    w.put(0, 1)                    # SIZE (1, ...): root, size 1 -> no length
    w.put(0, 1)                    # transfer-syntax-name absent
    w.put(0, 1).put(ctx - 1, 7)    # presentation-context-identifier (1..127, ...)
    w.put(2, 2)                    # arbitrary
    bitstring(w, payload.padded())
    return w.bytes_()


def oid_bits(w, oid=bytes([0x2b, 0x1b, 0x03, 0x01])):
    w.put(len(oid), 8).octets(oid)


def user_info(w, payload):
    """Association-information with one EXTERNALt, arbitrary encoding."""
    w.put(0, 1)                    # SIZE (1, ...): root, size 1
    w.put(0, 3)                    # no direct/indirect reference, no descriptor
    w.put(2, 2)                    # encoding: arbitrary
    bitstring(w, payload.padded())


def aarq(qual=None, payload=None):
    w = Bits()
    w.put(0, 1).put(0, 3)          # ACSE-apdu: ext 0, aarq
    w.put(0, 1)                    # AARQ ext bit
    bm = [0] * 15
    if qual is not None:
        bm[6] = 1                  # calling-AE-qualifier
    if payload is not None:
        bm[14] = 1                 # user-information
    for x in bm:
        w.put(x, 1)
    oid_bits(w)
    if qual is not None:
        w.put(0, 1).put(0, 1)      # AE-qualifier ext 0, form2
        w.put(1, 8).put(qual, 8)   # unconstrained INTEGER, 1 octet
    if payload is not None:
        user_info(w, payload)
    return w


def aare(payload=None, result=0):
    w = Bits()
    w.put(0, 1).put(1, 3)          # ACSE-apdu: ext 0, aare
    w.put(0, 1)                    # AARE ext bit
    bm = [0] * 11
    if payload is not None:
        bm[10] = 1                 # user-information
    for x in bm:
        w.put(x, 1)
    oid_bits(w)
    w.put(0, 1).put(result, 2)     # result (0..2, ...)
    w.put(0, 1)                    # result-source-diagnostic: acse-service-user
    w.put(0, 1).put(0, 4)          # null (0..14, ...)
    if payload is not None:
        user_info(w, payload)
    return w


def rlrq():
    w = Bits()
    w.put(0, 1).put(2, 3)          # rlrq
    w.put(0, 1).put(1, 1).put(0, 1)  # ext 0, reason present, no user-info
    w.put(0, 1).put(0, 2)          # reason normal (0 | 1 | 30, ...)
    return w


def rlre():
    w = Bits()
    w.put(0, 1).put(3, 3)          # rlre
    w.put(0, 1).put(1, 1).put(0, 1)
    w.put(0, 1).put(0, 2)          # reason normal
    return w


def spdu(first, second, acse):
    return bytes([first, second]) + acse.bytes_()


# ---------------------------------------------------------------- frames

def air_nsap(ars):
    # VER 0xc1 (all mobile ATSC), ARS = 24-bit aircraft address
    return bytes([0x47, 0x00, 0x27, 0xc1, 0x45, 0x55, 0x52, 0x00]) + ars.to_bytes(3, 'big') + \
        bytes([0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x21])


def gnd_nsap(n=1):
    # VER 0x81 (all fixed ATSC); last octet is the NSEL (0x21, transport)
    return bytes([0x47, 0x00, 0x27, 0x81, 0x45, 0x55, 0x52, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00,
                  0x20, 0x00, 0x00, 0x00, 0x02, n, 0x21])


def eth_clnp(src, dst, cotp):
    hdr_len = 9 + 1 + len(dst) + 1 + len(src)
    clnp = bytes([0x81, hdr_len, 1, 0x1e, 0x1c]) + struct.pack('>HH', hdr_len + len(cotp), 0)
    clnp += bytes([len(dst)]) + dst + bytes([len(src)]) + src + cotp
    llc = b'\xfe\xfe\x03' + clnp
    return b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + struct.pack('>H', len(llc)) + llc


def dt(src, dst, dstref, nr, payload):
    return eth_clnp(src, dst, bytes([4, 0xf0]) + struct.pack('>H', dstref) + bytes([0x80 | (nr & 0x7f)]) + payload)


def cr(src, dst, srcref, payload):
    return eth_clnp(src, dst, bytes([6, 0xe0, 0, 0]) + struct.pack('>H', srcref) + b'\x40' + payload)


def cc(src, dst, dstref, srcref, payload):
    return eth_clnp(src, dst, bytes([6, 0xd0]) + struct.pack('>HH', dstref, srcref) + b'\x40' + payload)


class Conn:
    """A COTP connection between one aircraft and one ground system.
    Downlink DTs carry the ground reference, uplink DTs the aircraft one."""

    def __init__(self, ars, gnd, aref, gref):
        self.air, self.gnd, self.aref, self.gref = air_nsap(ars), gnd, aref, gref
        self.nd = self.nu = 0

    def down(self, payload):
        p = dt(self.air, self.gnd, self.gref, self.nd, payload)
        self.nd += 1
        return p

    def up(self, payload):
        p = dt(self.gnd, self.air, self.aref, self.nu, payload)
        self.nu += 1
        return p

    def cr(self, payload):
        return cr(self.air, self.gnd, self.aref, payload)

    def cc(self, payload):
        return cc(self.gnd, self.air, self.aref, self.gref, payload)


def build_main():
    pkts = []
    G = gnd_nsap(1)

    # 1. Logon with AARQ calling-AE-qualifier = 1 (CM) in a DT, CM logon
    # request in the AARQ user-information; AARE with the logon response.
    # Then every downlink and uplink message as user data (context 3).
    # The conversation says CM, so atn-ulcs calls atn-cm directly.
    a = Conn(0x4ca123, G, 0x0101, 0x0201)
    pkts.append(a.down(pdv(1, aarq(qual=1, payload=air_msg(0, LOGON_FULL)))))
    pkts.append(a.up(pdv(1, aare(payload=gnd_msg(0, RESP_BOTH)))))
    for _, m in DOWN:
        pkts.append(a.down(pdv(3, m)))
    for _, m in UP:
        pkts.append(a.up(pdv(3, m)))
    pkts.append(a.down(pdv(1, rlrq())))
    pkts.append(a.up(pdv(1, rlre())))

    # 2. Heuristic path: no AARQ seen on this connection, so atn-ulcs
    # tries its heuristic list for each user data PDU (CPDLC first).
    # Only messages that the CPDLC heuristic rejects are used.
    b = Conn(0x4ca456, G, 0x0102, 0x0202)
    for m in HEUR_DOWN:
        pkts.append(b.down(pdv(3, m)))
    for m in HEUR_UP:
        pkts.append(b.up(pdv(3, m)))

    # 3. AARQ without an AE qualifier, then a CM PDU found by the heuristic
    # (which marks the conversation as CM), then further CM PDUs that go
    # straight to atn-cm.
    c = Conn(0x4ca789, G, 0x0103, 0x0203)
    pkts.append(c.down(pdv(1, aarq())))
    pkts.append(c.down(pdv(3, HEUR_DOWN[0])))
    pkts.append(c.down(pdv(3, air_msg(0, LOGON_MIN))))
    pkts.append(c.down(pdv(3, air_msg(2, abort_reason(0)))))

    # 4. COTP CR with SCN+CP and an AARQ (no AE qualifier) carrying a CM
    # logon request: heuristic, CR branch. CC with SAC+CPA and an AARE
    # carrying the logon response (conversation now CM). Then data.
    d = Conn(0x4cabcd, G, 0x0104, 0x0204)
    pkts.append(d.cr(spdu(0xe8, 0x02, aarq(payload=HEUR_DOWN_LOGON))))
    pkts.append(d.cc(spdu(0xf0, 0x02, aare(payload=gnd_msg(0, RESP_AIR)))))
    pkts.append(d.down(pdv(3, air_msg(1, Bits().put(0, 1)))))
    pkts.append(d.up(pdv(3, gnd_msg(2, CONTACT_REQ))))

    # 5. CR with an AARQ without user data, then a CC whose AARE carries
    # a CM logon response: heuristic, CC branch.
    e = Conn(0x4cbeef, G, 0x0105, 0x0205)
    pkts.append(e.cr(spdu(0xe8, 0x02, aarq())))
    pkts.append(e.cc(spdu(0xf0, 0x02, aare(payload=HEUR_UP_LOGON))))
    pkts.append(e.up(pdv(3, gnd_msg(5, Bits().put(0, 2)))))

    # 6. Two ground systems (no mobile NSAP): AARQ with the CM AE qualifier,
    # then user data, which atn-cm cannot classify as up- or downlink.
    g1, g2 = gnd_nsap(2), gnd_nsap(3)
    pkts.append(dt(g1, g2, 0x0301, 0, pdv(1, aarq(qual=1))))
    pkts.append(dt(g1, g2, 0x0301, 1, pdv(3, air_msg(2, abort_reason(1)))))

    # 7. The same between two ground systems without an AARQ: the CM
    # heuristic cannot tell up- from downlink and declines.
    pkts.append(dt(g1, g2, 0x0302, 0, pdv(3, air_msg(2, abort_reason(1)))))

    # 8. User data of some other application that neither the CPDLC nor
    # the CM heuristic accepts, downlink and uplink (no conversation).
    h = Conn(0x4cc0de, G, 0x0106, 0x0206)
    pkts.append(h.down(pdv(3, OTHER_APP)))
    pkts.append(h.up(pdv(3, OTHER_APP)))
    return pkts


# Two octets that no CM or CPDLC PDU decodes from without an exception
# and that leave nothing in the Info column. For CM this is an extension
# alternative whose open type length runs past the data.
OTHER_APP = Bits().octets(b'\xc0\xff')


def heuristic_candidates():
    """CM messages in a form the CPDLC heuristic does not accept."""
    down = [air_msg(1, Bits().put(1, 1))] + [m for _, m in DOWN]
    up = [m for _, m in UP]
    return down, up


HEUR_DOWN, HEUR_UP = heuristic_candidates()
HEUR_DOWN_LOGON = air_msg(0, LOGON_FULL)
HEUR_UP_LOGON = gnd_msg(0, RESP_BOTH)


def build_malformed():
    pkts = []
    G = gnd_nsap(1)
    a = Conn(0x4cdead, G, 0x0111, 0x0211)
    pkts.append(a.down(pdv(1, aarq(qual=1))))
    pkts.append(a.up(pdv(1, aare())))
    # truncated CM PDUs on a CM conversation (direct call, exceptions)
    trunc = [air_msg(0, LOGON_FULL), gnd_msg(3, LOGON_FULL), gnd_msg(0, RESP_AIR),
             gnd_msg(2, CONTACT_REQ)]
    for i, m in enumerate(trunc):
        bits = Bits()
        bits.b = m.b[:len(m.b) // 2]
        if i % 2 == 0 and i != 2:
            pkts.append(a.down(pdv(3, bits)))
        else:
            pkts.append(a.up(pdv(3, bits)))
    # empty user data
    pkts.append(a.down(pdv(3, Bits())))
    # heuristic on truncated data: no conversation, both heuristics fail
    b = Conn(0x4cdeaf, G, 0x0112, 0x0212)
    for m in trunc:
        bits = Bits()
        bits.b = m.b[:len(m.b) // 3]
        pkts.append(b.down(pdv(3, bits)))
        pkts.append(b.up(pdv(3, bits)))
    # Known unfixed state issue (not malformed): a CM PDU found by the
    # heuristic marks the conversation as CM, then an AARQ with the CPDLC
    # AE qualifier on the same connection sets it to CPDLC. The AE
    # qualifier is written on every pass, so with -2 the CM frame is
    # handed to atn-cpdlc on the second pass.
    c = Conn(0x4cfeed, G, 0x0113, 0x0213)
    pkts.append(c.down(pdv(1, aarq())))
    pkts.append(c.down(pdv(3, air_msg(1, Bits().put(1, 1)))))
    pkts.append(c.down(pdv(1, aarq(qual=2))))
    return pkts


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1793232000 + i, 0, len(p), len(p)) + p)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'atn_cm-coverage.pcap'), build_main())
    write_pcap(os.path.join(out, 'atn_cm-coverage-malformed.pcap'), build_malformed())
