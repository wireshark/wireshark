#!/usr/bin/env python3
# Generates test/captures/hnbap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HNBAP dissector (packet-hnbap.c,
generated from asn1/hnbap/).

HNBAP (3GPP TS 25.469, Home Node B Application Part, Iuh interface) is
ASN.1 aligned PER carried over SCTP (port 29169, payload protocol
identifier 20). This script has a small aligned PER writer and encodes
the PDUs by hand from the ASN.1 in epan/dissectors/asn1/hnbap/ (the
HNB-Identity, IMSIs, PLMNs etc. are invented values). Every packet is
built with struct; addresses are from 192.0.2.0/24.

Usage: mkhnbap.py <output directory>
Writes hnbap-coverage.pcap and hnbap-coverage-malformed.pcap.
"""
import struct
import sys
import os

# ------------------------------------------------------------- PER ---
class BW:
    def __init__(self):
        self.bits = []
    def b(self, v, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((v >> i) & 1)
        return self
    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)
        return self
    def raw(self, data):
        for c in data:
            self.b(c, 8)
        return self
    def cint(self, v, lo, hi):
        """constrained whole number lo..hi"""
        r = hi - lo + 1
        v -= lo
        assert 0 <= v < r, (v, lo, hi)
        if r == 1:
            return self
        if r <= 255:
            return self.b(v, (r - 1).bit_length())
        if r == 256:
            return self.align().b(v, 8)
        if r <= 65536:
            return self.align().b(v, 16)
        maxn = ((r - 1).bit_length() + 7) // 8
        n = max(1, (v.bit_length() + 7) // 8)
        self.b(n - 1, (maxn - 1).bit_length())
        return self.align().b(v, 8 * n)
    def enum(self, idx, nroot, ext=True, extidx=None):
        if ext:
            if extidx is not None:
                self.b(1, 1).b(0, 1).b(extidx, 6)   # normally small number
                return self
            self.b(0, 1)
        return self.b(idx, (nroot - 1).bit_length())
    def choice(self, idx, n, ext=True):
        if ext:
            self.b(0, 1)
        return self.b(idx, (n - 1).bit_length())
    def octets(self, data, lb, ub=None, ext=False):
        """OCTET STRING (SIZE(lb..ub[,...]))"""
        if ub is None:
            ub = lb
        if ext:
            self.b(0, 1)
        if lb == ub:
            assert len(data) == lb
            if lb == 0:
                return self
            if lb <= 2:
                return self.raw(data)
            return self.align().raw(data)
        self.cint(len(data), lb, ub)
        return self.align().raw(data)
    def bitstr(self, value, nbits, lb=None, ub=None, ext=False):
        """BIT STRING with nbits bits (value an int); fixed size when lb is None"""
        if ext:
            self.b(0, 1)
        if lb is None:
            if nbits > 16:
                self.align()
            return self.b(value, nbits)
        self.cint(nbits, lb, ub)
        if ub > 16:
            self.align()
        return self.b(value, nbits)
    def opentype(self, data):
        self.align()
        assert len(data) < 128
        self.b(len(data), 8)
        return self.raw(data)
    def get(self):
        self.align()
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            v = 0
            for bit in self.bits[i:i + 8]:
                v = (v << 1) | bit
            out.append(v)
        return bytes(out)

def W():
    return BW()

REJECT, IGNORE, NOTIFY = 0, 1, 2

# ---------------------------------------------------------- types ---
PLMN = bytes.fromhex('00f110')           # 001/01
def plmn(w=None, p=PLMN):
    w = w or W(); w.octets(p, 3); return w

def v_plmn():
    return plmn().get()

def v_lac(v=0x0102):
    return W().octets(struct.pack('!H', v), 2).get()

def v_rac(v=5):
    return W().octets(bytes([v]), 1).get()

def v_sac(v=0x0201):
    return W().octets(struct.pack('!H', v), 2).get()

def v_cellid(v=0x0abcdef):
    return W().bitstr(v, 28).get()

def v_csgid(v=0x1234567):
    return W().bitstr(v, 27).get()

def v_psc(v=0x1ff):
    return W().bitstr(v, 9).get()

def v_hnbid(info=b'hnb-001'):
    w = W(); w.b(0, 1); w.b(0, 1)       # ext, iE-Extensions absent
    w.octets(info, 1, 255)
    return w.get()

def v_ctx(v=0xabcdef):
    return W().bitstr(v, 24).get()

def v_rnc(v=1234):
    return W().cint(v, 0, 65535).get()

def v_backoff(v=600):
    return W().cint(v, 0, 3600).get()

def v_mux(v=2048):
    return W().cint(v, 1024, 65535).get()

CAUSE_N = (14, 2, 7, 4)
def v_cause(group=0, idx=0, extidx=None):
    w = W(); w.choice(group, 4); w.enum(idx, CAUSE_N[group], extidx=extidx)
    return w.get()

def v_regcause(kind='normal'):
    w = W()
    if kind == 'emergency':
        w.enum(0, 2)
    elif kind == 'normal':
        w.enum(1, 2)
    else:
        w.enum(0, 2, extidx=0)
    return w.get()

def v_uecap(rel=0, csg=0, ext_ies=False):
    w = W(); w.b(0, 1); w.b(0, 1)
    w.enum(rel, 6); w.enum(csg, 2)
    return w.get()

def v_csgstat(v=0):
    return W().enum(v, 2).get()

def v_accessmode(v=2):
    return W().enum(v, 3).get()

def ipaddr(w, v4=True):
    w.b(0, 1); w.b(0, 1)                # ext, iE-Extensions absent
    w.choice(0 if v4 else 1, 2)
    w.octets(bytes([192, 0, 2, 77]) if v4 else bytes(range(1, 17)), 4 if v4 else 16)
    return w

def v_ip(v4=True):
    return ipaddr(W(), v4).get()

def v_ue_identity(kind):
    w = W(); w.choice(kind, 8)
    lai = lambda w: (w.b(0, 1), plmn(w), w.octets(b'\x01\x02', 2))
    if kind == 0:
        w.octets(bytes.fromhex('0010123456789f'), 3, 8)           # IMSI 7 octets
    elif kind == 1:
        w.bitstr(0xdeadbeef, 32); lai(w)
    elif kind == 2:
        w.bitstr(0xcafef00d, 32); w.b(0, 1); lai(w); w.octets(b'\x07', 1)
    elif kind == 3:
        w.bitstr(0x123456789abcdef & ((1 << 60) - 1), 60)
    elif kind == 4:
        w.bitstr(0x0badc0de, 32)
    elif kind == 5:
        w.octets(bytes.fromhex('1122334455'), 5, 7)
    elif kind == 6:
        w.octets(bytes.fromhex('112233445566'), 5, 7); w.bitstr(0x01020304, 32)
    elif kind == 7:
        w.octets(bytes.fromhex('aabb'), 2, 17)
    return w.get()

def v_critdiag(full=True):
    w = W(); w.b(0, 1)
    if full:
        w.b(1, 1).b(1, 1).b(1, 1).b(1, 1).b(0, 1)       # optional bitmap
        w.cint(3, 0, 255)                               # procedureCode
        w.b(0, 2)                                       # triggeringMessage
        w.b(0, 2)                                       # procedureCriticality
        w.cint(2, 1, 256)                               # two errors
        for crit, ie_id, err in ((REJECT, 5, 0), (IGNORE, 4, 1)):
            w.b(0, 1); w.b(0, 1)                        # item ext, iE-Extensions
            w.b(crit, 2); w.cint(ie_id, 0, 65535); w.enum(err, 2)
    else:
        w.b(0, 5)
    return w.get()

def locinfo_utran(w):
    w.b(0, 1)                                           # MacroCoverageInformation ext
    w.b(0, 1)                                           # iE-Extensions
    w.choice(0, 2)
    w.b(0, 1)                                           # UTRANCellID: iE-Extensions (no ext)
    w.octets(b'\x00\x10', 2); w.octets(b'\x03', 1); plmn(w); w.bitstr(0x0123456, 28)

def locinfo_geran(w):
    w.b(0, 1); w.b(0, 1)
    w.choice(1, 2)
    w.b(0, 1)
    plmn(w); w.octets(b'\x00\x20', 2); w.octets(b'\x00\x30', 2)

def locinfo_geo(w, sign=0, lat=1234567, lon=-123456, dirn=1, alt=100):
    w.b(0, 1); w.b(0, 1)                                # GeographicalLocation: ext, iE-Ext
    w.b(0, 1); w.b(0, 1)                                # GeographicalCoordinates: ext, iE-Ext
    w.b(sign, 1); w.cint(lat, 0, 8388607); w.cint(lon, -8388608, 8388607)
    w.b(0, 1)                                           # AltitudeAndDirection ext
    w.b(dirn, 1); w.cint(alt, 0, 32767)

def v_locinfo(macro=None, geo=False, ext_ip=None):
    w = W(); w.b(0, 1)
    w.b(1 if macro else 0, 1); w.b(1 if geo else 0, 1); w.b(1 if ext_ip is not None else 0, 1)
    if macro == 'utran':
        locinfo_utran(w)
    elif macro == 'geran':
        locinfo_geran(w)
    if geo:
        locinfo_geo(w)
    if ext_ip is not None:
        # ProtocolExtensionContainer {id-HNB-Internet-Information, reject, IP-Address}
        w.cint(1, 1, 65535)
        w.cint(17, 0, 65535); w.b(REJECT, 2); w.opentype(v_ip(ext_ip))
    return w.get()

def transport_info(w, assoc='gtp'):
    w.b(0, 1); w.b(0, 1)                                # ext, iE-Extensions
    w.bitstr(0xc0000201 >> 0, 32, 1, 160, ext=True)     # TransportLayerAddress (32 bits)
    if assoc == 'gtp':
        w.choice(0, 2); w.octets(b'\x00\x00\x12\x34', 4)
    else:
        w.choice(1, 2); w.octets(b'\x01\x02\x03', 1, 4, ext=True)

def v_rablist(n=2):
    w = W(); w.cint(n, 1, 256)
    for i in range(n):
        w.b(0, 1); w.b(0, 1)                            # item ext, iE-Extensions
        w.bitstr(0x20 + i, 8)
        transport_info(w, 'gtp'); transport_info(w, 'binding')
        w.b(i & 1, 1)                                   # CN-DomainIndicator
    return w.get()

def v_updatecause():
    return W().enum(0, 1).get()

def hnb_rnl(w):
    w.b(0, 1)                                           # HNB-RNL-Identity ext (one alternative)
    w.b(0, 1); w.b(0, 1)                                # HNB-Cell-Identifier ext, iE-Ext
    plmn(w); w.bitstr(0x0f0f0f0, 28)

def v_neighreq(n=2):
    w = W(); w.cint(n, 1, 32)
    for i in range(n):
        w.b(0, 1); w.b(0, 1)                            # item ext, iE-Ext
        hnb_rnl(w)
    return w.get()

def v_neighlist(provided=True):
    w = W(); w.cint(2, 1, 32)
    for i in range(2):
        w.b(0, 1); w.b(0, 1)                            # HNBConfigInfo ext, iE-Ext
        hnb_rnl(w)
        if (i == 0) == provided:
            w.choice(0, 2)
            w.b(0, 1); w.b(1, 1); w.b(1, 1); w.b(0, 1)  # ext, psc, csg, iE-Ext
            w.bitstr(0x0aa, 9); w.bitstr(0x7654321, 27)
            w.enum(1, 3)                                # access mode hybrid
            w.cint(2, 1, 3)
            ipaddr(w, True); ipaddr(w, False)
        else:
            w.choice(1, 2)
            w.b(0, 1); w.b(0, 1)                        # ext, iE-Ext
            w.choice(3, 4); w.enum(3, 4)                # Cause misc / unspecified
    return w.get()

# ------------------------------------------------------- messages ---
def ie(ie_id, crit, value):
    w = W(); w.cint(ie_id, 0, 65535); w.b(crit, 2); w.opentype(value)
    return w.get()

def message(ies, exts=()):
    w = W()
    w.b(0, 1)                                           # extension bit
    w.b(1 if exts else 0, 1)                            # protocolExtensions present
    w.cint(len(ies), 0, 65535)
    for x in ies:
        w.align().raw(x)
    if exts:
        w.cint(len(exts), 1, 65535)
        for x in exts:
            w.align().raw(x)
    return w.get()

def pdu(kind, proc, crit, msg):
    w = W()
    w.b(0, 1); w.b(kind, 2)                             # ext bit, 0 initiating, 1 successful, 2 unsuccessful
    w.cint(proc, 0, 255); w.b(crit, 2); w.opentype(msg)
    return w.get()

ID = dict(Cause=1, CritDiag=2, HNBIdentity=3, Context=4, UEIdentity=5, LAC=6, RAC=7, Loc=8, PLMN=9,
          SAC=10, CellId=11, RegCause=12, UECap=13, RNC=14, CSG=15, Backoff=16, InternetInfo=17,
          AccessMode=18, Mux=19, ServiceArea=20, CSGStatus=21, RABList=22, ConfigInfo=23, AccessResult=25,
          UpdateCause=26, NeighList=27, NeighReq=28, IurhAddr=29, PSC=30, CellIdentifier=31)

def hnb_register_request(loc, cause_ext=True, csg=True, exts=True):
    ies = [ie(ID['HNBIdentity'], REJECT, v_hnbid()), ie(ID['Loc'], REJECT, loc),
           ie(ID['PLMN'], REJECT, v_plmn()), ie(ID['CellId'], REJECT, v_cellid()),
           ie(ID['LAC'], REJECT, v_lac()), ie(ID['RAC'], REJECT, v_rac()), ie(ID['SAC'], REJECT, v_sac())]
    if csg:
        ies.append(ie(ID['CSG'], REJECT, v_csgid()))
    x = []
    if exts:
        x = [ie(ID['ServiceArea'], IGNORE, v_sac(0x0303)), ie(ID['AccessMode'], REJECT, v_accessmode(1)),
             ie(ID['PSC'], IGNORE, v_psc()), ie(ID['IurhAddr'], IGNORE, v_ip(True))]
    return pdu(0, 1, REJECT, message(ies, x))

def frames_pdus():
    P = []
    # HNB registration, location information in every form
    P.append(hnb_register_request(v_locinfo('utran', True, True)))
    P.append(hnb_register_request(v_locinfo('geran', False, False), csg=False, exts=False))
    P.append(hnb_register_request(v_locinfo(None, True, None)))
    P.append(hnb_register_request(v_locinfo(None, False, None), exts=False))
    P.append(hnb_register_request(v_locinfo('utran', False, False)))
    P.append(pdu(1, 1, REJECT, message([ie(ID['RNC'], REJECT, v_rnc())],
                [ie(ID['Mux'], IGNORE, v_mux()), ie(ID['IurhAddr'], IGNORE, v_ip(False))])))
    P.append(pdu(1, 1, REJECT, message([ie(ID['RNC'], REJECT, v_rnc(0))])))
    # rejects: every Cause choice, the ext values, CriticalityDiagnostics, Backoff
    for grp, idx, extidx in ((0, 0, None), (0, 13, None), (0, 0, 0), (1, 1, None), (2, 6, None), (3, 3, None)):
        P.append(pdu(2, 1, REJECT, message([ie(ID['Cause'], IGNORE, v_cause(grp, idx, extidx)),
                                            ie(ID['CritDiag'], IGNORE, v_critdiag(grp == 0 and idx == 0 and extidx is None)),
                                            ie(ID['Backoff'], REJECT, v_backoff(3600))])))
    P.append(pdu(2, 1, REJECT, message([ie(ID['Cause'], IGNORE, v_cause(1, 0))])))
    # HNB de-register
    P.append(pdu(0, 2, IGNORE, message([ie(ID['Cause'], IGNORE, v_cause(0, 11)), ie(ID['Backoff'], REJECT, v_backoff())])))
    # UE register request with every UE identity
    for kind in range(8):
        P.append(pdu(0, 3, REJECT, message([
            ie(ID['UEIdentity'], REJECT, v_ue_identity(kind)),
            ie(ID['RegCause'], IGNORE, v_regcause(('normal', 'emergency', 'relocation')[kind % 3])),
            ie(ID['UECap'], REJECT, v_uecap(kind % 6, kind & 1))])))
    P.append(pdu(1, 3, REJECT, message([ie(ID['UEIdentity'], REJECT, v_ue_identity(0)), ie(ID['Context'], REJECT, v_ctx())],
                                       [ie(ID['CSGStatus'], REJECT, v_csgstat(1))])))
    P.append(pdu(1, 3, REJECT, message([ie(ID['UEIdentity'], REJECT, v_ue_identity(1)), ie(ID['Context'], REJECT, v_ctx(1))])))
    P.append(pdu(2, 3, REJECT, message([ie(ID['UEIdentity'], REJECT, v_ue_identity(2)), ie(ID['Cause'], IGNORE, v_cause(0, 6)),
                                        ie(ID['CritDiag'], IGNORE, v_critdiag(True))])))
    P.append(pdu(0, 4, IGNORE, message([ie(ID['Context'], REJECT, v_ctx()), ie(ID['Cause'], IGNORE, v_cause(0, 7))])))
    P.append(pdu(0, 7, IGNORE, message([ie(ID['Context'], REJECT, v_ctx()), ie(ID['CSGStatus'], REJECT, v_csgstat(0))])))
    # TNL update
    P.append(pdu(0, 9, REJECT, message([ie(ID['Context'], REJECT, v_ctx()), ie(ID['RABList'], REJECT, v_rablist(2)),
                                        ie(ID['UpdateCause'], REJECT, v_updatecause())])))
    P.append(pdu(1, 9, REJECT, message([ie(ID['Context'], REJECT, v_ctx())])))
    P.append(pdu(2, 9, REJECT, message([ie(ID['Context'], REJECT, v_ctx()), ie(ID['Cause'], IGNORE, v_cause(1, 0)),
                                        ie(ID['CritDiag'], IGNORE, v_critdiag(False))])))
    # config transfer
    P.append(pdu(0, 10, REJECT, message([ie(ID['NeighReq'], REJECT, v_neighreq(2))])))
    P.append(pdu(1, 10, REJECT, message([ie(ID['NeighList'], REJECT, v_neighlist(True))])))
    P.append(pdu(1, 10, REJECT, message([ie(ID['NeighList'], REJECT, v_neighlist(False))])))
    # relocation complete, error indication
    P.append(pdu(0, 11, IGNORE, message([ie(ID['Context'], IGNORE, v_ctx())])))
    P.append(pdu(0, 5, IGNORE, message([ie(ID['Cause'], IGNORE, v_cause(2, 0)), ie(ID['CritDiag'], IGNORE, v_critdiag(True))])))
    # private message: PrivateIE-Container with a local id
    w = W(); w.b(0, 1); w.cint(1, 1, 65535)
    pw = W(); pw.b(0, 1); pw.cint(7, 0, 65535); pw.b(IGNORE, 2); pw.opentype(b'\x01\x02\x03')
    w.align().raw(pw.get())
    P.append(pdu(0, 6, IGNORE, w.get()))
    # private message with a global (OBJECT IDENTIFIER) id
    w = W(); w.b(0, 1); w.cint(1, 1, 65535)
    pw = W(); pw.b(1, 1); pw.align().b(3, 8).raw(bytes([0x2b, 0x06, 0x01])); pw.b(IGNORE, 2); pw.opentype(b'\xaa\xbb')
    w.align().raw(pw.get())
    P.append(pdu(0, 6, IGNORE, w.get()))
    # IEs with ids that have no registered dissector (HNBConfigInfo, AccessResult, HNB-Cell-Identifier, unknown)
    P.append(pdu(0, 1, REJECT, message([ie(ID['ConfigInfo'], REJECT, b'\x01\x02'), ie(ID['AccessResult'], IGNORE, b'\x00'),
                                        ie(ID['CellIdentifier'], NOTIFY, b'\xff'), ie(100, NOTIFY, b'\x00')],
                                       [ie(200, IGNORE, b'\x05')])))
    # unknown procedure code (initiating and outcomes)
    P.append(pdu(0, 99, REJECT, message([ie(ID['Cause'], IGNORE, v_cause())])))
    P.append(pdu(1, 99, REJECT, message([ie(ID['Cause'], IGNORE, v_cause())])))
    P.append(pdu(2, 99, REJECT, message([ie(ID['Cause'], IGNORE, v_cause())])))
    # outcomes for procedures that have none: successful/unsuccessful ErrorIndication
    P.append(pdu(1, 5, IGNORE, message([ie(ID['Cause'], IGNORE, v_cause())])))
    P.append(pdu(2, 4, IGNORE, message([ie(ID['Cause'], IGNORE, v_cause())])))
    # notify criticality
    P.append(pdu(0, 2, NOTIFY, message([ie(ID['Cause'], NOTIFY, v_cause(3, 0))])))
    return P

def malformed_pdus():
    P = []
    ok = hnb_register_request(v_locinfo('utran', True, True))
    P.append(ok[:-1])                                   # truncated
    P.append(ok[:3])
    P.append(b'\x80\x01')                               # PDU extension bit set
    P.append(b'\x60\x01\x00')                           # choice index 3 (not a choice)
    P.append(b'')
    # open type length past the end
    P.append(bytes([0x00, 0x01, 0x00, 0x7f, 0x00]))
    # IE container with a count past the data
    w = W(); w.b(0, 1); w.b(0, 1); w.cint(5, 0, 65535)
    P.append(pdu(0, 1, REJECT, w.get()))
    # IE whose value is cut short
    P.append(pdu(0, 1, REJECT, message([ie(ID['HNBIdentity'], REJECT, b'\x00\x05ab')])))
    # an IE with an unknown criticality (3)
    w = W(); w.cint(ID['Cause'], 0, 65535); w.b(3, 2); w.opentype(v_cause())
    P.append(pdu(0, 2, REJECT, message([w.get()])))
    # Cause with the choice extension bit set
    P.append(pdu(0, 2, REJECT, message([ie(ID['Cause'], IGNORE, b'\x80\x00')])))
    # UE identity: IMSI length past the end, extension alternative
    P.append(pdu(0, 3, REJECT, message([ie(ID['UEIdentity'], REJECT, b'\x07\x00\x01')])))
    P.append(pdu(0, 3, REJECT, message([ie(ID['UEIdentity'], REJECT, b'\x80\x00')])))
    # RAB list with a count past the data and one of 256
    P.append(pdu(0, 9, REJECT, message([ie(ID['RABList'], REJECT, b'\xff\x00')])))
    # extension enum values, ext bit in many types
    P.append(pdu(0, 3, REJECT, message([ie(ID['RegCause'], IGNORE, b'\xff\xff'), ie(ID['UECap'], REJECT, b'\xff\xff\xff')])))
    # trailing garbage after a good message
    P.append(ok + b'\x00\x01\x02')
    return P

# ------------------------------------------------------------ SCTP ---
CRC_TABLE = None
def crc32c(data):
    global CRC_TABLE
    if CRC_TABLE is None:
        CRC_TABLE = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            CRC_TABLE.append(c)
    crc = 0xffffffff
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xff] ^ (crc >> 8)
    return crc ^ 0xffffffff

def sctp_frame(payload, tsn, sport=40000, dport=29169, ppid=20, vtag=0x1234, to_hnbgw=True):
    chunk_len = 16 + len(payload)
    chunk = struct.pack('>BBHIHHI', 0, 3, chunk_len, tsn, 0, tsn & 0xffff, ppid) + payload
    chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
    hdr = struct.pack('>HHI', sport, dport, vtag)
    crc = crc32c(hdr + b'\0\0\0\0' + chunk)
    sctp = hdr + struct.pack('<I', crc) + chunk
    src, dst = ([192, 0, 2, 1], [192, 0, 2, 2]) if to_hnbgw else ([192, 0, 2, 2], [192, 0, 2, 1])
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(sctp), 1, 0, 64, 132, 0, bytes(src), bytes(dst))
    s = sum(struct.unpack('>10H', ip[:20]))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:] + sctp
    return bytes.fromhex('020000000002' '020000000001' '0800') + ip

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def main_frames():
    F = []
    for i, p in enumerate(frames_pdus()):
        if i % 7 == 6:     # some on another port: reached through the payload protocol identifier
            F.append(sctp_frame(p, i + 1, sport=41000, dport=41001))
        else:
            F.append(sctp_frame(p, i + 1))
    return F

def malformed_frames():
    return [sctp_frame(p, i + 1) for i, p in enumerate(malformed_pdus()) if p]

if __name__ == '__main__':
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    pcap(os.path.join(d, 'hnbap-coverage.pcap'), main_frames())
    pcap(os.path.join(d, 'hnbap-coverage-malformed.pcap'), malformed_frames())
