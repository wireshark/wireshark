#!/usr/bin/env python3
# Generates test/captures/atn_ulcs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic ATN Upper Layer Communications Service (ULCS) captures
# for epan/dissectors/packet-atn-ulcs.c (generated from
# epan/dissectors/asn1/atn-ulcs/). Every packet is built here with struct
# and a small unaligned-PER bit writer; nothing comes from a real network.
# The frame building (LLC/CLNP/COTP and the CM PDUs) is taken from
# ../atn_cm-coverage/mkatn_cm.py.
#
# Stack: Ethernet / LLC (FE FE 03) / CLNP (ATN NSAPs, NSEL 0x21) / COTP
# (CR, CC, DT, ED) / ATN-ULCS (short session + presentation + ACSE in the
# SPDU form, or PER Fully-encoded-data) / ATN-CM or ATN-CPDLC. A few
# frames use COTP over TPKT over TCP/IPv4 instead of CLNP.
#
# Writes:
#   atn_ulcs-coverage.pcap            main capture (Ethernet)
#   atn_ulcs-coverage-exported.pcap   PDV-list forms that the COTP
#                                     heuristic never hands to ATN-ULCS,
#                                     passed by name in Exported PDUs
#   atn_ulcs-coverage-malformed.pcap  truncated and broken PDUs
#
# Usage: mkatn_ulcs.py <outdir>
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


def B(data):
    return Bits().octets(data)


# ------------------------------------------------------------ PER helpers

def len_det(w, n):
    if n < 128:
        w.put(n, 8)
    else:
        w.put(2, 2).put(n, 14)
    return w


def per_oid(w, oid):
    return len_det(w, len(oid)).octets(oid)


def per_int(w, v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return len_det(w, n).octets((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))


def per_octstr(w, data):
    return len_det(w, len(data)).octets(data)


def per_bitstr(w, bits):
    len_det(w, len(bits))
    w.b += list(bits)
    return w


def per_open(w, data):
    return len_det(w, len(data)).octets(data)


OID_ACN_CM = bytes([0x2b, 0x1b, 0x03, 0x01])        # 1.3.27.3.1
OID_ACN_CPDLC = bytes([0x2b, 0x1b, 0x03, 0x02])
OID_AP_TITLE = bytes([0x2b, 0x1b, 0x00, 0x00, 0x81, 0x18, 0x01])
OID_MECH = bytes([0x2b, 0x1b, 0x03, 0x00, 0x05])
OID_DIRECT = bytes([0x2b, 0x1b, 0x03, 0x0a])
OID_TSN = bytes([0x2b, 0x1b, 0x03, 0x00, 0x01])


# ------------------------------------------------------------ ATN-CM PDUs
# (from mkatn_cm.py)

def short_tsap(ars=None, locsys=bytes(range(0x30, 0x3a))):
    w = Bits()
    w.put(1 if ars is not None else 0, 1)
    if ars is not None:
        w.octets(ars)
    w.put(len(locsys) - 10, 1)
    w.octets(locsys)
    return w


def long_tsap(rdp=b'\x47\x00\x27\x81\x10', ars=None, locsys=bytes(range(0x30, 0x3a))):
    return Bits().octets(rdp).add(short_tsap(ars, locsys))


def logon_request(flight, tsap):
    w = Bits().put(0, 6)                   # no optionals
    w.put(len(flight) - 2, 3).ia5(flight)
    w.add(tsap)
    return w


def air_msg(idx, body):
    return Bits().put(0, 1).put(idx, 2).add(body)


def gnd_msg(idx, body):
    return Bits().put(0, 1).put(idx, 3).add(body)


def cm_abort(v):
    return Bits().put(0, 1).put(v, 4)


CM_LOGON = air_msg(0, logon_request('KLM1234', long_tsap(ars=b'\x00\x00\x99')))
CM_LOGON_RESP = gnd_msg(0, Bits().put(0, 2))                    # empty
CM_CONTACT_RESP = air_msg(1, Bits().put(1, 1))                  # CPDLC rejects it
CM_FWD_RESP = gnd_msg(5, Bits().put(1, 2))
CM_ABORT_DOWN = air_msg(2, cm_abort(5))
CM_ABORT_UP = gnd_msg(4, cm_abort(3))
# Two octets that neither the CPDLC nor the CM heuristic accepts.
OTHER_APP = B(b'\xc0\xff')

# ------------------------------------------------------------ ATN-CPDLC PDUs
# GroundPDUs/AircraftPDUs and their protected forms, abort alternatives.

CPDLC_GND_ABORT_USER = Bits().put(0, 1).put(0, 3).put(0, 1).put(3, 3)      # abortUser 3
CPDLC_GND_ABORT_PROV = Bits().put(0, 1).put(1, 3).put(0, 1).put(2, 3)      # abortProvider 2
CPDLC_AIR_ABORT_USER = Bits().put(0, 1).put(0, 2).put(0, 1).put(5, 3)      # abortUser 5
CPDLC_AIR_ABORT_PROV = Bits().put(0, 1).put(1, 2).put(0, 1).put(7, 3)      # abortProvider 7


# ------------------------------------------------------------ ULCS / ACSE

def ap_title(w, form2=None):
    """AP-title CHOICE (extensible): form2 = OID, form1 = Name (an RDN
    sequence of exactly one NULL attribute, no bits)."""
    w.put(0, 1)
    if form2 is not None:
        w.put(0, 1)
        per_oid(w, form2)
    else:
        w.put(1, 1)
    return w


def ae_qualifier(w, form2=None):
    w.put(0, 1)
    if form2 is not None:
        w.put(0, 1)
        per_int(w, form2)
    else:
        w.put(1, 1)
    return w


def externalt(w, enc, payload, direct=None, indirect=None, descr=None):
    """EXTERNALt. enc: 0 single-ASN1-type (open type, octets), 1
    octet-aligned (octets), 2 arbitrary (Bits)."""
    w.put(direct is not None, 1).put(indirect is not None, 1).put(descr is not None, 1)
    if direct is not None:
        per_oid(w, direct)
    if indirect is not None:
        per_int(w, indirect)
    if descr is not None:
        per_octstr(w, descr)
    w.put(enc, 2)
    if enc == 0:
        per_open(w, payload)
    elif enc == 1:
        per_octstr(w, payload)
    else:
        per_bitstr(w, payload.padded())
    return w


def assoc_info(w, items):
    """Association-information: SIZE (1, ..., 0 | 2..MAX) OF EXTERNALt.
    items is a list of (enc, payload, kwargs)."""
    if len(items) == 1:
        w.put(0, 1)
    else:
        w.put(1, 1)
        len_det(w, len(items))
    for enc, payload, kw in items:
        externalt(w, enc, payload, **kw)
    return w


def ui_arb(payload, **kw):
    return [(2, payload, kw)]


def auth_value(w, kind, value):
    """Authentication-value CHOICE (no extension marker)."""
    if kind == 'charstring':
        w.put(0, 2)
        per_octstr(w, value)
    elif kind == 'bitstring':
        w.put(1, 2)
        per_bitstr(w, value)
    elif kind == 'external':
        # EXTERNAL (packet-per.c): indirect-reference and octet-aligned
        w.put(2, 2)
        w.put(0, 1).put(1, 1).put(1, 1)
        per_int(w, 7)
        per_octstr(w, b'auth-ext')
        w.put(1, 2)
        per_octstr(w, value)
    elif kind == 'other':
        w.put(3, 2)
        per_oid(w, OID_MECH)
        per_open(w, value)          # other-mechanism-value: PER open type
    elif kind == 'other_raw':
        # as the reproducer wrote it: no length prefix of its own
        w.put(3, 2)
        per_oid(w, OID_ACN_CM)
        w.octets(value)
    return w


AARQ_FIELDS = ['protocol_version', 'called_ap_title', 'called_ae_qualifier',
               'called_ap_inv', 'called_ae_inv', 'calling_ap_title',
               'calling_ae_qualifier', 'calling_ap_inv', 'calling_ae_inv',
               'acse_req', 'mech', 'auth', 'acn_list', 'impl', 'user_info']


def aarq(acn=OID_ACN_CM, **f):
    """AARQ-apdu. Fields (all optional): see AARQ_FIELDS. ap titles and
    AE qualifiers: ('form2', value) or ('form1',); auth: (kind, value);
    user_info: list for assoc_info()."""
    w = Bits()
    w.put(0, 1).put(0, 3)          # ACSE-apdu: ext 0, aarq
    w.put(0, 1)                    # AARQ extension bit
    for name in AARQ_FIELDS:
        w.put(name in f, 1)
    if 'protocol_version' in f:
        per_bitstr(w, [1])
    per_oid(w, acn)
    _common_fields(w, f, ['called_ap_title', 'called_ae_qualifier', 'called_ap_inv',
                          'called_ae_inv', 'calling_ap_title', 'calling_ae_qualifier',
                          'calling_ap_inv', 'calling_ae_inv'])
    if 'acse_req' in f:
        per_bitstr(w, f['acse_req'])
    if 'mech' in f:
        per_oid(w, f['mech'])
    if 'auth' in f:
        auth_value(w, *f['auth'])
    if 'acn_list' in f:
        len_det(w, len(f['acn_list']))
        for o in f['acn_list']:
            per_oid(w, o)
    if 'impl' in f:
        per_octstr(w, f['impl'])
    if 'user_info' in f:
        assoc_info(w, f['user_info'])
    return w


def _common_fields(w, f, names):
    for name in names:
        if name not in f:
            continue
        v = f[name]
        if name.endswith('ap_title'):
            ap_title(w, v[1] if v[0] == 'form2' else None)
        elif name.endswith('ae_qualifier'):
            ae_qualifier(w, v[1] if v[0] == 'form2' else None)
        else:
            per_int(w, v)


AARE_FIELDS = ['protocol_version', 'resp_ap_title', 'resp_ae_qualifier', 'resp_ap_inv',
               'resp_ae_inv', 'acse_req', 'mech', 'auth', 'acn_list', 'impl', 'user_info']


def aare(result=0, diag=('user', 0), acn=OID_ACN_CM, **f):
    w = Bits()
    w.put(0, 1).put(1, 3)          # aare
    w.put(0, 1)
    for name in AARE_FIELDS:
        w.put(name in f, 1)
    if 'protocol_version' in f:
        per_bitstr(w, [1])
    per_oid(w, acn)
    w.put(0, 1).put(result, 2)     # Associate-result (0..2, ...)
    if diag[0] == 'user':
        w.put(0, 1).put(0, 1).put(diag[1], 4)     # (0..14, ...)
    else:
        w.put(1, 1).put(0, 1).put(diag[1], 2)     # (0..2, ...)
    _common_fields(w, f, ['resp_ap_title', 'resp_ae_qualifier', 'resp_ap_inv', 'resp_ae_inv'])
    if 'acse_req' in f:
        per_bitstr(w, f['acse_req'])
    if 'mech' in f:
        per_oid(w, f['mech'])
    if 'auth' in f:
        auth_value(w, *f['auth'])
    if 'acn_list' in f:
        len_det(w, len(f['acn_list']))
        for o in f['acn_list']:
            per_oid(w, o)
    if 'impl' in f:
        per_octstr(w, f['impl'])
    if 'user_info' in f:
        assoc_info(w, f['user_info'])
    return w


def release(rlre, reason=None, user_info=None):
    w = Bits()
    w.put(0, 1).put(3 if rlre else 2, 3)
    w.put(0, 1).put(reason is not None, 1).put(user_info is not None, 1)
    if reason is not None:
        w.put(0, 1).put(reason, 5)        # (0 | 1 | 30, ...) -> 0..30
    if user_info is not None:
        assoc_info(w, user_info)
    return w


def abrt(source=0, diag=None, user_info=None):
    w = Bits()
    w.put(0, 1).put(4, 3)
    w.put(0, 1).put(diag is not None, 1).put(user_info is not None, 1)
    w.put(0, 1).put(source, 1)            # ABRT-source (0..1, ...)
    if diag is not None:
        w.put(0, 1).put(diag - 1, 3)      # ENUMERATED 1..6, ...
    if user_info is not None:
        assoc_info(w, user_info)
    return w


def pdv(ctx, payload):
    """Fully-encoded-data with one PDV-list, arbitrary encoding, as the
    COTP heuristic expects it."""
    w = Bits()
    w.put(0, 1)                    # SIZE (1, ...): root
    w.put(0, 1)                    # no transfer-syntax-name
    w.put(0, 1).put(ctx - 1, 7)
    w.put(2, 2)                    # arbitrary
    per_bitstr(w, payload.padded())
    return w.bytes_()


def pdv_list(w, ctx, enc, payload, tsn=None, ctx_ext=False):
    w.put(tsn is not None, 1)
    if tsn is not None:
        per_oid(w, tsn)
    if ctx_ext:
        w.put(1, 1)
        per_int(w, ctx)            # extension value: unconstrained
    else:
        w.put(0, 1).put(ctx - 1, 7)
    w.put(enc, 2)
    if enc == 0:
        per_open(w, payload)
    elif enc == 1:
        per_octstr(w, payload)
    else:
        per_bitstr(w, payload.padded())
    return w


def fully_encoded(items):
    """items: list of dicts for pdv_list()."""
    w = Bits()
    if len(items) == 1:
        w.put(0, 1)
    else:
        w.put(1, 1)
        len_det(w, len(items))
    for it in items:
        pdv_list(w, **it)
    return w.bytes_()


def spdu(first, second, acse):
    return bytes([first, second]) + acse.bytes_()


SCN, SCNC, SAC, SACC, SRF, SRFC = 0xe8, 0xf8, 0xf0, 0xd8, 0xe0, 0xa0
CP = 0x02


# ------------------------------------------------------------ frames

def air_nsap(ars, ver=0xc1):
    # VER 0xc1 (all mobile ATSC) or 0x41 (all mobile AINSC); ARS = 24-bit
    # aircraft address
    return bytes([0x47, 0x00, 0x27, ver, 0x45, 0x55, 0x52, 0x00]) + ars.to_bytes(3, 'big') + \
        bytes([0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x21])


def gnd_nsap(n=1):
    return bytes([0x47, 0x00, 0x27, 0x81, 0x45, 0x55, 0x52, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00,
                  0x20, 0x00, 0x00, 0x00, 0x02, n, 0x21])


ETH_HDR = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02'


def eth_clnp(src, dst, cotp):
    hdr_len = 9 + 1 + len(dst) + 1 + len(src)
    clnp = bytes([0x81, hdr_len, 1, 0x1e, 0x1c]) + struct.pack('>HH', hdr_len + len(cotp), 0)
    clnp += bytes([len(dst)]) + dst + bytes([len(src)]) + src + cotp
    llc = b'\xfe\xfe\x03' + clnp
    return ETH_HDR + struct.pack('>H', len(llc)) + llc


def dt(src, dst, dstref, nr, payload):
    return eth_clnp(src, dst, bytes([4, 0xf0]) + struct.pack('>H', dstref) + bytes([0x80 | (nr & 0x7f)]) + payload)


def ed(src, dst, dstref, nr, payload):
    return eth_clnp(src, dst, bytes([4, 0x10]) + struct.pack('>H', dstref) + bytes([0x80 | (nr & 0x7f)]) + payload)


def cr(src, dst, srcref, payload):
    return eth_clnp(src, dst, bytes([6, 0xe0, 0, 0]) + struct.pack('>H', srcref) + b'\x40' + payload)


def cc(src, dst, dstref, srcref, payload):
    return eth_clnp(src, dst, bytes([6, 0xd0]) + struct.pack('>HH', dstref, srcref) + b'\x40' + payload)


class Conn:
    """A COTP connection between one aircraft and one ground system.
    Downlink DTs carry the ground reference, uplink DTs the aircraft one."""

    def __init__(self, ars, gnd, aref, gref, ver=0xc1, air=None):
        self.air = air if air is not None else air_nsap(ars, ver)
        self.gnd, self.aref, self.gref = gnd, aref, gref
        self.nd = self.nu = 0

    def down(self, payload):
        p = dt(self.air, self.gnd, self.gref, self.nd, payload)
        self.nd += 1
        return p

    def up(self, payload):
        p = dt(self.gnd, self.air, self.aref, self.nu, payload)
        self.nu += 1
        return p

    def ed_down(self, payload):
        return ed(self.air, self.gnd, self.gref, 0, payload)

    def cr(self, payload):
        return cr(self.air, self.gnd, self.aref, payload)

    def cc(self, payload):
        return cc(self.gnd, self.air, self.aref, self.gref, payload)


# COTP over TPKT over TCP/IPv4 (the addresses are not OSI NSAPs)

def ipv4_tcp(src, dst, sport, dport, seq, ack, payload):
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, 0x18, 8192, 0, 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
                     bytes(src), bytes(dst)) + tcp
    return ETH_HDR + b'\x08\x00' + ip


def tpkt(cotp):
    return struct.pack('>BBH', 3, 0, 4 + len(cotp)) + cotp


class TcpConn:
    def __init__(self):
        self.a, self.b = (10, 0, 0, 1), (10, 0, 0, 2)
        self.sa, self.sb = 1000, 5000

    def send(self, from_a, cotp):
        data = tpkt(cotp)
        if from_a:
            p = ipv4_tcp(self.a, self.b, 40102, 102, self.sa, self.sb, data)
            self.sa += len(data)
        else:
            p = ipv4_tcp(self.b, self.a, 102, 40102, self.sb, self.sa, data)
            self.sb += len(data)
        return p


FULL_AARQ = dict(
    protocol_version=True,
    called_ap_title=('form2', OID_AP_TITLE),
    called_ae_qualifier=('form2', 1),
    called_ap_inv=1234,
    called_ae_inv=-5,
    calling_ap_title=('form1',),
    calling_ae_qualifier=('form2', 1),
    calling_ap_inv=70000,
    calling_ae_inv=0,
    acse_req=[1, 1],
    mech=OID_MECH,
    auth=('charstring', b'secret'),
    acn_list=[OID_ACN_CM, OID_ACN_CPDLC],
    impl=b'ULCS-test-1.0',
    user_info=ui_arb(CM_LOGON, direct=OID_DIRECT, indirect=3, descr=b'CM logon'),
)

FULL_AARE = dict(
    protocol_version=True,
    resp_ap_title=('form1',),
    resp_ae_qualifier=('form1',),
    resp_ap_inv=1,
    resp_ae_inv=2,
    acse_req=[0, 1],
    mech=OID_MECH,
    auth=('bitstring', [1, 0, 1, 1, 0, 0, 1, 0, 1]),
    acn_list=[OID_ACN_CM],
    impl=b'GND',
    user_info=[(2, CM_LOGON_RESP, {}), (1, b'\x01\x02\x03', {'indirect': 1})],
)


def build_main():
    pkts = []
    G = gnd_nsap(1)

    # --- 1-6: connection A, CM. COTP CR with SCN+CP and an AARQ that
    # has every optional field (CR branch: conversation created from
    # src/srcref, calling-AE-qualifier 1 written to it, user-information
    # handed to ATN-CM); CC with SAC+CPA and an AARE with every optional
    # field (CC branch, conversation not found from src: two created);
    # DT user data both ways; RLRQ/RLRE with reasons and user-information.
    a = Conn(0xa1a001, G, 0x0101, 0x0201)
    pkts.append(a.cr(spdu(SCN, CP, aarq(**FULL_AARQ))))
    pkts.append(a.cc(spdu(SAC, CP, aare(**FULL_AARE))))
    pkts.append(a.down(pdv(3, CM_CONTACT_RESP)))
    pkts.append(a.up(pdv(3, CM_FWD_RESP)))
    pkts.append(a.down(pdv(1, release(False, 1, [(0, b'\x05\x00', {'direct': OID_DIRECT})]))))
    pkts.append(a.up(pdv(1, release(True, 1, ui_arb(CM_ABORT_UP)))))

    # --- 7-11: connection B, CPDLC (AE qualifier 2), aircraft NSAP with
    # VER 0x41 (mobile AINSC). SCNC+CP / SACC+CPA, DT data, ABRT.
    b = Conn(0xa1a002, G, 0x0102, 0x0202, ver=0x41)
    pkts.append(b.cr(spdu(SCNC, CP, aarq(acn=OID_ACN_CPDLC, calling_ae_qualifier=('form2', 2),
                                         user_info=ui_arb(CPDLC_AIR_ABORT_USER)))))
    pkts.append(b.cc(spdu(SACC, CP, aare(acn=OID_ACN_CPDLC, user_info=ui_arb(CPDLC_GND_ABORT_USER)))))
    pkts.append(b.down(pdv(3, CPDLC_AIR_ABORT_PROV)))
    pkts.append(b.up(pdv(3, CPDLC_GND_ABORT_PROV)))
    pkts.append(b.down(pdv(1, abrt(0, 3, ui_arb(CPDLC_AIR_ABORT_USER)))))

    # --- 12-17: connection C, protected-mode CPDLC (22). AARQ and AARE in
    # DT (DT branches), authentication "other" (OID plus a PER open type)
    # and "external", responding-AE-qualifier in the AARE (same value),
    # user-information with zero EXTERNALs (extension), DT and ED data,
    # ABRT from the provider without diagnostic.
    c = Conn(0xa1a003, G, 0x0103, 0x0203)
    pkts.append(c.down(pdv(1, aarq(acn=OID_ACN_CPDLC, calling_ae_qualifier=('form2', 22),
                                   acse_req=[1], mech=OID_MECH,
                                   auth=('other', b'\x04\x02AB')))))
    pkts.append(c.up(pdv(1, aare(acn=OID_ACN_CPDLC, resp_ae_qualifier=('form2', 22),
                                 resp_ap_title=('form2', OID_AP_TITLE),
                                 auth=('external', b'\xa5\x5a'), user_info=[]))))
    pkts.append(c.down(pdv(3, CPDLC_AIR_ABORT_PROV)))
    pkts.append(c.up(pdv(3, CPDLC_GND_ABORT_PROV)))
    pkts.append(c.ed_down(pdv(3, CPDLC_AIR_ABORT_USER)))
    pkts.append(c.up(pdv(1, abrt(1))))

    # --- 18-21: connection D, AE qualifier 0 (ADS, not handled): user
    # data goes to the heuristic list. Data of another application
    # (rejected), then a CM PDU that the CM heuristic accepts (it marks
    # the conversation CM), then CM passed directly.
    d = Conn(0xa1a004, G, 0x0104, 0x0204)
    pkts.append(d.down(pdv(1, aarq(calling_ae_qualifier=('form2', 0)))))
    pkts.append(d.down(pdv(3, OTHER_APP)))
    pkts.append(d.down(pdv(3, CM_CONTACT_RESP)))
    pkts.append(d.down(pdv(3, CM_ABORT_DOWN)))

    # --- 22-25: connection E: AE qualifier 3 (ATI) with CM user data in
    # the AARQ (EXTERNALt, unhandled qualifier: heuristic). Connection E2:
    # AARQ with AE qualifier 10 (ARF), then an AARE (DT branch,
    # conversation created from the AARQ data) whose CM user data the
    # heuristic accepts, then CM passed directly.
    e = Conn(0xa1a005, G, 0x0105, 0x0205)
    pkts.append(e.down(pdv(1, aarq(calling_ae_qualifier=('form2', 3), user_info=ui_arb(CM_LOGON)))))
    e2 = Conn(0xa1a006, G, 0x0106, 0x0206)
    pkts.append(e2.down(pdv(1, aarq(calling_ae_qualifier=('form2', 10)))))
    pkts.append(e2.up(pdv(1, aare(user_info=ui_arb(CM_LOGON_RESP)))))
    pkts.append(e2.up(pdv(3, CM_FWD_RESP)))

    # --- 26-28: no conversation. DT user data on references without an
    # AARQ (heuristic: CM accepted, other rejected); an AARQ in a CC
    # (both references set: no conversation, AE qualifier not stored,
    # user-information CC branch finds nothing: heuristic).
    f = Conn(0xa1a007, G, 0x0107, 0x0207)
    pkts.append(f.down(pdv(3, CM_ABORT_DOWN)))
    pkts.append(f.down(pdv(3, OTHER_APP)))
    f2 = Conn(0xa1a008, G, 0x0108, 0x0208)
    pkts.append(f2.cc(spdu(SAC, CP, aarq(calling_ae_qualifier=('form2', 1),
                                         user_info=ui_arb(CM_LOGON_RESP)))))

    # --- 29-31: CR AARQ without qualifier, the same CR again (CR branch,
    # conversation found), user data of an unknown application in the
    # CR's AARQ (qualifier unknown: heuristic), then CC AARE.
    g = Conn(0xa1a009, G, 0x0109, 0x0209)
    pkts.append(g.cr(spdu(SCN, CP, aarq())))
    pkts.append(g.cr(spdu(SCN, CP, aarq(user_info=ui_arb(OTHER_APP)))))
    pkts.append(g.cc(spdu(SAC, CP, aare(user_info=ui_arb(OTHER_APP)))))

    # --- 32-35: DT AARQ (qualifier 1), the same AARQ again (DT branch,
    # conversation found), then a CC AARE: the CC branch finds the
    # conversation from src/srcref (created by the DT AARQ) and adds one
    # for dst/dstref. Then CM data uplink through that conversation.
    h = Conn(0xa1a00a, G, 0x010a, 0x020a)
    pkts.append(h.down(pdv(1, aarq(calling_ae_qualifier=('form2', 1)))))
    pkts.append(h.down(pdv(1, aarq(calling_ae_qualifier=('form2', 1)))))
    pkts.append(h.cc(spdu(SAC, CP, aare(user_info=ui_arb(CM_LOGON_RESP)))))
    pkts.append(h.up(pdv(3, CM_ABORT_UP)))

    # --- 36-43: one aircraft, two AARQs in a row on different references
    # (the second does not overwrite the pending one), AARE on the second
    # connection (conversation created with the first AARQ's data), the
    # same AARE again (conversation found, nothing pending), an AARE on a
    # third connection (nothing pending: conversation without data, user
    # data then goes to the heuristics), and an AARE from an aircraft
    # that never sent an AARQ (not dissected further).
    i1 = Conn(0xa1a00b, G, 0x010b, 0x020b)
    i2 = Conn(0xa1a00b, G, 0x011b, 0x021b)
    i3 = Conn(0xa1a00b, G, 0x012b, 0x022b)
    pkts.append(i1.down(pdv(1, aarq(calling_ae_qualifier=('form2', 1)))))
    pkts.append(i2.down(pdv(1, aarq(calling_ae_qualifier=('form2', 1)))))
    pkts.append(i2.up(pdv(1, aare())))
    pkts.append(i2.up(pdv(1, aare())))
    pkts.append(i2.up(pdv(3, CM_ABORT_UP)))
    pkts.append(i3.up(pdv(1, aare(result=1, diag=('user', 5)))))
    pkts.append(i3.up(pdv(3, CM_FWD_RESP)))
    j = Conn(0xa1a0ff, G, 0x01ff, 0x02ff)
    pkts.append(j.up(pdv(1, aare(user_info=ui_arb(CM_LOGON_RESP)))))

    # --- 44-62: Short Refuse. An AARQ, then CCs with SRF+CPR and SRFC+CPR
    # carrying a rejecting AARE: every parameter combination (B1, B2,
    # parameter indication) and every CPR error code, every acse-service
    # user and provider diagnostic.
    k = Conn(0xa1a00c, G, 0x010c, 0x020c)
    pkts.append(k.cr(spdu(SCN, CP, aarq(calling_ae_qualifier=('form2', 1)))))
    n = 0
    for base in (SRF, SRFC):
        for err in range(8):
            kk = Conn(0xa1a00c, G, 0x0300 + n, 0x0400 + n)
            if n < 15:
                diag = ('user', n)
            else:
                diag = ('provider', n - 15)
            pkts.append(kk.cc(spdu(base | (n % 8), CP | (err << 4),
                                   aare(result=1 + n % 2, diag=diag))))
            n += 1
    for v in (1, 2):
        kk = Conn(0xa1a00c, G, 0x0300 + n, 0x0400 + n)
        pkts.append(kk.cc(spdu(SAC, CP, aare(result=2, diag=('provider', v)))))
        n += 1

    # --- 63-65: two ground systems (no mobile NSAP, aircraft address 0):
    # AARQ, AARE (aircraft address 0 found), data.
    g1, g2 = gnd_nsap(2), gnd_nsap(3)
    pkts.append(dt(g1, g2, 0x0501, 0, pdv(1, aarq(calling_ae_qualifier=('form2', 1)))))
    pkts.append(dt(g2, g1, 0x0601, 0, pdv(1, aare())))
    pkts.append(dt(g2, g1, 0x0601, 1, pdv(3, CM_FWD_RESP)))

    # --- 66-68: CLNP with short (non-ATN, 13-octet) NSAPs: the 24-bit
    # address and the up/downlink tests stop at the length check.
    s1 = bytes([0x49, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x21])
    s2 = bytes([0x49, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x33, 0x21])
    pkts.append(dt(s1, s2, 0x0701, 0, pdv(1, aarq(calling_ae_qualifier=('form2', 3)))))
    pkts.append(dt(s2, s1, 0x0702, 0, pdv(1, aare())))
    pkts.append(dt(s1, s2, 0x0701, 1, pdv(3, CM_ABORT_DOWN)))

    # --- 69-71: COTP class 0 over TPKT over TCP/IPv4 (addresses are not
    # OSI): CR with SCN+CP AARQ, CC with SAC+CPA AARE, DT data (to
    # ATN-CM through the AARQ's AE qualifier).
    t = TcpConn()
    pkts.append(t.send(True, bytes([6, 0xe0, 0, 0, 0x08, 0x01, 0x00]) +
                       spdu(SCN, CP, aarq(calling_ae_qualifier=('form2', 1)))))
    pkts.append(t.send(False, bytes([6, 0xd0, 0x08, 0x01, 0x09, 0x01, 0x00]) +
                       spdu(SAC, CP, aare())))
    pkts.append(t.send(True, bytes([2, 0xf0, 0x80]) + pdv(3, OTHER_APP)))

    # --- 72-76: edge cases of the reference and address tests:
    # an AARQ in a DT with dst-ref 0 (neither reference set: no
    # conversation) with CM user data (heuristic); an AARE in a CR (only
    # src-ref set: no conversation created); an AARQ between a 20-octet
    # aircraft NSAP and a 13-octet NSAP (the length test fails on the
    # destination only) with CM user data (heuristic, which asks for
    # up/downlink, and declines); empty user data in an EXTERNALt and in a PDV-list.
    m = Conn(0xa1a00e, G, 0x010e, 0x020e)
    pkts.append(dt(m.air, G, 0x0000, 0, pdv(1, aarq(calling_ae_qualifier=('form2', 1),
                                                    user_info=ui_arb(CM_ABORT_DOWN)))))
    pkts.append(cr(G, m.air, 0x0b0e, spdu(SAC, CP, aare())))
    pkts.append(dt(m.air, s2, 0x0c0e, 0, pdv(1, aarq(user_info=ui_arb(CM_ABORT_DOWN)))))
    pkts.append(m.down(pdv(1, aarq(calling_ae_qualifier=('form2', 1), user_info=ui_arb(Bits())))))
    pkts.append(m.down(pdv(3, Bits())))

    # --- 77-78: COTP data that is not ATN-ULCS: one octet (too short for the
    # heuristic) and two octets that match neither the SPDU nor the
    # PDV-list patterns.
    pkts.append(dt(m.air, G, 0x0d0e, 0, b'\x42'))
    pkts.append(dt(m.air, G, 0x0d0e, 1, b'\x42\x43\x44'))

    # --- 79-81: the reproducers of the fixes on the branch, clean forms.
    # other-mechanism-value is a PER open type (length prefix): a short
    # one in a DT AARQ, and the "long" reproducer frame as it was (its
    # first octet 0x04 is read as the open type length). Then a DT with
    # SCN+CP and an AARQ: the SPDU path now adds an atn-ulcs item.
    r = Conn(0xa1a00d, G, 0x010d, 0x020d)
    pkts.append(r.up(pdv(1, aarq(auth=('other', b'\x04\x02AB'), impl=b'after-auth'))))
    pkts.append(r.up(pdv(1, aarq(auth=('other_raw', b'\x04\x02AB' + bytes(120))))))
    pkts.append(r.up(spdu(SCN, CP, aarq(calling_ae_qualifier=('form2', 2)))))
    return pkts


# ------------------------------------------------------------ exported PDUs

def exp_pdu(name, payload):
    tag = name.encode()
    return struct.pack('>HH', 12, len(tag)) + tag + struct.pack('>HH', 0, 0) + payload


def build_exported():
    """Fully-encoded-data forms that never pass the COTP heuristic
    (which only accepts one PDV-list, no transfer-syntax-name, context 1
    or 3, arbitrary encoding), passed straight to the atn-ulcs dissector
    by name. No OSI addresses, so there is no ATN conversation."""
    cases = [
        [dict(ctx=1, enc=2, payload=release(False, 0), tsn=OID_TSN)],
        [dict(ctx=1, enc=1, payload=release(True, 30).bytes_())],
        [dict(ctx=3, enc=0, payload=b'\x11\x22')],
        [dict(ctx=2, enc=2, payload=B(b'\x33'))],
        [dict(ctx=127, enc=2, payload=B(b'\x44'))],
        [dict(ctx=200, enc=2, payload=B(b'\x55'), ctx_ext=True)],
        [dict(ctx=1, enc=2, payload=abrt(0, 6)),
         dict(ctx=3, enc=2, payload=OTHER_APP),
         dict(ctx=3, enc=2, payload=CM_CONTACT_RESP, tsn=OID_TSN)],
    ]
    return [exp_pdu('atn-ulcs', fully_encoded(c)) for c in cases]


# ------------------------------------------------------------ malformed

def build_malformed():
    pkts = []
    G = gnd_nsap(1)
    a = Conn(0xa1b001, G, 0x0111, 0x0211)
    full = aarq(**FULL_AARQ)
    # SPDU + PPDU without an ACSE PDU, and truncated AARQs
    pkts.append(a.cr(bytes([SCN, CP])))
    pkts.append(a.cr(spdu(SCN, CP, full)[:12]))
    pkts.append(a.down(pdv(1, Bits())))  # empty ACSE PDU
    trunc = Bits()
    trunc.b = full.b[:len(full.b) // 2]
    pkts.append(a.down(pdv(1, trunc)))
    # other-mechanism-value without a PER length prefix (the original
    # reproducer, frame 1): the open type length runs past the data
    pkts.append(a.up(pdv(1, aarq(auth=('other_raw', b'\x04\x02AB')))))
    # Fully-encoded-data with a bit string length past the data
    pkts.append(a.down(b'\x00\xa0\x7f\x00'))
    # AARE with an AARQ pending, truncated after the bitmap
    tr = Bits()
    tr.b = aare(**FULL_AARE).b[:20]
    pkts.append(a.up(pdv(1, tr)))
    # SRF with nothing after the PPDU
    pkts.append(a.cc(bytes([SRF | 3, CP | 0x70])))
    return pkts


def write_pcap(path, pkts, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1793232000 + i, 0, len(p), len(p)) + p)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'atn_ulcs-coverage.pcap'), build_main())
    write_pcap(os.path.join(out, 'atn_ulcs-coverage-exported.pcap'), build_exported(), 252)
    write_pcap(os.path.join(out, 'atn_ulcs-coverage-malformed.pcap'), build_malformed())
