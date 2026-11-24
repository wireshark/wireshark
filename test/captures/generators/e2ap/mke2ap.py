#!/usr/bin/env python3
# Generates test/captures/e2ap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic E2AP coverage captures.

Usage: mke2ap.py <outdir> [<asn1 dir>]

The E2AP messages and the E2SM-KPM, E2SM-RC and E2SM-NI service model
contents they carry are encoded with aper.py from the ASN.1 modules in
the Wireshark tree (epan/dissectors/asn1/e2ap), with every optional
component and every IE of each IE set present and one CHOICE
alternative per message, cycling through the alternatives. E2SM-CCC
contents are JSON text. Nothing comes from a real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct

import aper
from e2ap_perlib import BW, ie, container, pdu  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASN = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1/e2ap')
FILES = ['E2AP-CommonDataTypes.asn', 'E2AP-Constants.asn', 'E2AP-Containers.asn',
         'E2AP-IEs.asn', 'E2AP-PDU-Contents.asn', 'E2AP-PDU-Descriptions.asn',
         'e2sm-v3.01.asn', 'e2sm-rc-v1.03.asn', 'e2sm-kpm-v3.00.asn', 'e2sm-ni-v1.00.asn']
RC3FILES = ['e2sm-v3.05.asn', 'e2sm-rc-v3.05.asn']
LLCFILES = ['e2sm-v7.00.asn', 'llc-v1.0.asn']
NVARIANTS = 3
PDUMOD = 'E2AP-PDU-Descriptions'

# ---- RAN functions ----

E2SM = {
    'KPM': ('E2SM-KPM-IEs', {
        'def': 'E2SM-KPM-RANfunction-Description',
        'ev': 'E2SM-KPM-EventTriggerDefinition',
        'act': 'E2SM-KPM-ActionDefinition',
        'ihdr': 'E2SM-KPM-IndicationHeader',
        'imsg': 'E2SM-KPM-IndicationMessage'}),
    # RC v1.03 (packet-e2ap.c), used with the rc_manual_version_choice
    # preference set to version-1
    'RC1': ('E2SM-RC-IEs', {
        'def': 'E2SM-RC-RANFunctionDefinition',
        'ev': 'E2SM-RC-EventTrigger',
        'act': 'E2SM-RC-ActionDefinition',
        'ihdr': 'E2SM-RC-IndicationHeader',
        'imsg': 'E2SM-RC-IndicationMessage',
        'cpid': 'E2SM-RC-CallProcessID',
        'chdr': 'E2SM-RC-ControlHeader',
        'cmsg': 'E2SM-RC-ControlMessage',
        'cout': 'E2SM-RC-ControlOutcome'}),
    # RC v3.05 (packet-rc-v3.c), the default
    'RC3': ('E2SM-RC-IEs', {
        'def': 'E2SM-RC-RANFunctionDefinition',
        'ev': 'E2SM-RC-EventTrigger',
        'act': 'E2SM-RC-ActionDefinition',
        'ihdr': 'E2SM-RC-IndicationHeader',
        'imsg': 'E2SM-RC-IndicationMessage',
        'cpid': 'E2SM-RC-CallProcessID',
        'chdr': 'E2SM-RC-ControlHeader',
        'cmsg': 'E2SM-RC-ControlMessage',
        'cout': 'E2SM-RC-ControlOutcome',
        'qhdr': 'E2SM-RC-QueryHeader',
        'qdef': 'E2SM-RC-QueryDefinition',
        'qout': 'E2SM-RC-QueryOutcome'}),
    # LLC v1.0 (packet-llc-v1.c)
    'LLC': ('E2SM-LLC-IEs', {
        'def': 'E2SM-LLC-RANFunctionDefinition',
        'ev': 'E2SM-LLC-EventTrigger',
        'act': 'E2SM-LLC-ActionDefinition',
        'ihdr': 'E2SM-LLC-IndicationHeader',
        'imsg': 'E2SM-LLC-IndicationMessage',
        'chdr': 'E2SM-LLC-ControlHeader',
        'cmsg': 'E2SM-LLC-ControlMessage',
        'cout': 'E2SM-LLC-ControlOutcome'}),
    'NI': ('E2SM-NI-IEs', {
        'def': 'E2SM-NI-RANfunction-Description',
        'ev': 'E2SM-NI-EventTriggerDefinition',
        'act': 'E2SM-NI-ActionDefinition',
        'ihdr': 'E2SM-NI-IndicationHeader',
        'imsg': 'E2SM-NI-IndicationMessage',
        'cpid': 'E2SM-NI-CallProcessID',
        'chdr': 'E2SM-NI-ControlHeader',
        'cmsg': 'E2SM-NI-ControlMessage',
        'cout': 'E2SM-NI-ControlOutcome'}),
}


def rf(id_, kind, oid, short=None, desc_oid=None):
    names = {'KPM': 'ORAN-E2SM-KPM', 'RC': 'ORAN-E2SM-RC', 'NI': 'ORAN-E2SM-NI',
             'LLC': 'ORAN-E2SM-LLC'}
    return {'id': id_, 'kind': kind, 'oid': oid,
            'short': short or names.get(kind, kind),
            'e2smoid': desc_oid or oid}


KPM3 = '1.3.6.1.4.1.53148.1.3.2.2'
KPM4 = '1.3.6.1.4.1.53148.1.4.2.2'
RC1 = '1.3.6.1.4.1.53148.1.1.2.3'
NI1 = '1.3.6.1.4.1.53148.1.1.2.1'
CCC2 = '1.3.6.1.4.1.53148.1.2.2.4'
LLC1 = '1.3.6.1.4.1.53148.1.1.2.5'

F_KPM = rf(1, 'KPM', KPM3)
F_RC = rf(2, 'RC', RC1)
F_NI = rf(3, 'NI', NI1)
F_CCC = rf(4, 'CCC', CCC2)
F_KPM4 = rf(5, 'KPM', KPM4)                        # signalled v4, dissector v3
F_UNK = rf(6, 'UNK', '1.3.6.1.4.1.53148.1.1.2.99', short='ORAN-E2SM-XYZ')
F_UNMAPPED = rf(7, 'KPM', KPM3)                    # never announced
# a KPM definition whose short name only starts with ORAN-E2SM-KPM
F_KPMX = rf(8, 'KPM', KPM3, short='ORAN-E2SM-KPMX')
F_LLC = rf(9, 'LLC', LLC1)
FUNCS = [F_KPM, F_RC, F_NI, F_CCC, F_KPM4, F_UNK, F_KPMX, F_LLC]
TRAFFIC = [F_KPM, F_RC, F_NI, F_CCC, F_LLC]
# variants of the service model messages of each kind of RAN function
NV_SM = {'KPM': 22, 'RC': 6, 'NI': 6, 'CCC': 2, 'LLC': 4}

SLOT = {
    'RANfunctionDefinition': 'def',
    'RICeventTriggerDefinition': 'ev',
    'RICactionDefinition': 'act',
    'RICindicationHeader': 'ihdr',
    'RICindicationMessage': 'imsg',
    'RICcallProcessID': 'cpid',
    'RICcontrolHeader': 'chdr',
    'RICcontrolMessage': 'cmsg',
    'RICcontrolOutcome': 'cout',
    'RICqueryHeader': 'qhdr',
    'RICqueryDefinition': 'qdef',
    'RICqueryOutcome': 'qout',
}


def ccc_json(slot, f):
    if slot == 'def':
        return ('{"ranFunctionName": {"ranFunctionShortName": "ORAN-E2SM-CCC", '
                '"ranFunctionE2SMOid": "%s", "ranFunctionDescription": "synthetic", '
                '"ranFunctionInstance": 1}}' % f['oid']).encode()
    return ('{"%s": {"format": 1, "value": [1, 2, 3]}}' % slot).encode()


SPECS = {}


def e2sm_bytes(sp, slot, ctx):
    f = ctx.vals['rf']
    if f['kind'] == 'CCC':
        return ccc_json(slot, f)
    kind = f['kind']
    if kind == 'RC':
        # the RAN function definition is always decoded by the highest
        # version, the rest by the version the preference names
        kind = 'RC3' if slot == 'def' else 'RC%d' % ctx.vals.get('rcver', 3)
    if kind in E2SM and slot in E2SM[kind][1]:
        mod, types = E2SM[kind]
        sub = aper.Ctx(k=ctx.k, full=ctx.full, vals=ctx.vals)
        spec = {'RC3': 'rc3', 'LLC': 'llc'}.get(kind, 'main')
        return SPECS[spec].encode(types[slot], mod, sub)
    if slot == 'def':
        # a RAN function the dissector does not know: a RANfunction-Name
        # with the unknown short name
        sub = aper.Ctx(k=ctx.k, vals=ctx.vals)
        return sp.encode('RANfunction-Name', 'E2SM-COMMON-IEs', sub)
    return bytes([0x10 + ctx.k, 0x20, 0x30, 0x40])


def make_slot_override(slot):
    def ov(sp, w, t, mod, ctx):
        sp.enc_octets(w, t, e2sm_bytes(sp, slot, ctx), None, mod)
    return ov


def ov_ranfunction_name(sp, w, t, mod, ctx):
    f = ctx.vals['rf']
    w.b(0, 1)               # extension bit
    w.b(1, 1)               # ranFunction-Instance present
    s = {'size': ('1', '150', True)}
    sp.enc_str(w, dict(s, kind='PrintableString'), f['short'])
    sp.enc_str(w, {'kind': 'PrintableString', 'size': ('1', '1000', True)}, f['e2smoid'])
    sp.enc_str(w, dict(s, kind='PrintableString'), 'Synthetic %s' % f['kind'])
    sp.enc_int(w, f['id'], None, None)


def ov_ranfunction_oid(sp, w, t, mod, ctx):
    sp.enc_str(w, t, ctx.vals['rf']['oid'], None, mod)


def ov_ranfunction_id(sp, w, t, mod, ctx):
    sp.enc_int(w, ctx.vals['rf']['id'], 0, 4095)


def ov_gnb_id(sp, w, t, mod, ctx):
    # GNB-ID-Choice: gnb-ID BIT STRING (SIZE(22..32)), fixed per association
    w.b(0, 1)
    g = ctx.vals.get('gnb', 1)
    sp.enc_bits(w, {'size': ('22', '32', False)}, 32, g.to_bytes(4, 'big'))


def ov_plmn(sp, w, t, mod, ctx):
    sp.enc_octets(w, t, [b'\x00\xf1\x10', b'\x62\x02\x21'][ctx.k % 2], None, mod)


IFACES = ['NG', 'Xn', 'E1', 'F1', 'W1', 'S1', 'X2']
# (procedure code) of a setup procedure of each interface protocol
IFACE_PROC = {'NG': 21, 'Xn': 17, 'E1': 0, 'F1': 1, 'S1': 17, 'X2': 6}
_counters = {}


def counter(name):
    n = _counters.get(name, 0)
    _counters[name] = n + 1
    return n


def ov_component_id(sp, w, t, mod, ctx):
    i = counter('iface') % len(IFACES)
    w.b(0, 1)
    sp.enc_int(w, i, 0, len(IFACES) - 1)
    name, at = t['alts'][i]
    sp.enc(w, at, None, mod, ctx)
    if IFACES[i] != 'W1':
        # there is no W1AP dissector; the W1 parts go to the dissector
        # of the previous component of the same message, if any
        ctx.vals['iface'] = IFACES[i]


def ap_pdu(kind, proc):
    """An *AP PDU with an empty protocolIEs container."""
    return bytes([kind << 5, proc, 0x00, 0x03, 0x00, 0x00, 0x00])


def ov_component_cfg(sp, w, t, mod, ctx):
    iface = ctx.vals.get('iface')
    if iface:
        req, rsp = ap_pdu(0, IFACE_PROC[iface]), ap_pdu(1, IFACE_PROC[iface])
    else:
        req, rsp = b'\x01\x02', b'\x03\x04'
    w.b(0, 1)
    sp.enc_octets(w, {'size': None}, req)
    sp.enc_octets(w, {'size': None}, rsp)


TNL = [
    (bytes([192, 0, 2, 20]), 32, 36421),
    (bytes.fromhex('20010db8000000000000000000000020'), 128, 36422),
    (bytes([192, 0, 2, 21]) + bytes.fromhex('20010db8000000000000000000000021'), 160, 36423),
    (bytes([192, 0, 2, 22, 0x50]), 36, 36424),     # tnlPort not octet-aligned
    (bytes([192, 0, 2, 23]), 32, None),
]


def ov_tnl(sp, w, t, mod, ctx):
    addr, nbits, port = TNL[counter('tnl') % len(TNL)]
    w.b(0, 1)
    w.b(1 if port is not None else 0, 1)
    sp.enc_bits(w, {'size': ('1', '160', True)}, nbits, addr)
    if port is not None:
        sp.enc_bits(w, {'size': ('16', '16', False)}, 16, port.to_bytes(2, 'big'))


def ov_rflist(sp, w, t, mod, ctx):
    # RANfunctions-List: one item per RAN function in vals['funcs']
    funcs = ctx.vals.get('funcs') or [ctx.vals['rf']]
    lb, ub, ext = sp.size(t, None, mod)
    sp.enc_len(w, len(funcs), lb, ub, ext)
    saved = ctx.vals['rf']
    for f in funcs:
        ctx.vals['rf'] = f
        sp.enc(w, t['elem'], None, mod, ctx)
    ctx.vals['rf'] = saved


OVERRIDES = {
    'RANfunctions-List': ov_rflist,
    'RANfunction-Name': ov_ranfunction_name,
    'RANfunctionOID': ov_ranfunction_oid,
    'RANfunctionID': ov_ranfunction_id,
    'GNB-ID-Choice': ov_gnb_id,
    'PLMN-Identity': ov_plmn,
    'E2nodeComponentID': ov_component_id,
    'E2nodeComponentConfiguration': ov_component_cfg,
    'TNLinformation': ov_tnl,
}
for _t, _s in SLOT.items():
    OVERRIDES[_t] = make_slot_override(_s)


# ---- packet framing ----

def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:] + payload


NODE = [192, 0, 2, 1]   # E2 node
RIC = [192, 0, 2, 2]    # near-RT RIC


class Assoc:
    """An SCTP association between an E2 node port and the RIC port."""

    def __init__(self, node_port, ric_port=37464, ppid=70):
        self.ports = (node_port, ric_port)
        self.ppid = ppid
        self.tsn = {False: 100, True: 9000}
        self.ssn = {False: 0, True: 0}

    def frame(self, payload, rev):
        tsn = self.tsn[rev]
        self.tsn[rev] += 1
        ssn = self.ssn[rev]
        self.ssn[rev] = (ssn + 1) & 0xffff
        chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, ssn, self.ppid) + payload
        chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
        sport, dport = self.ports[::-1] if rev else self.ports
        sctp = struct.pack('>HHII', sport, dport, 0x0a0b0c0d, 0) + chunk
        src, dst = (RIC, NODE) if rev else (NODE, RIC)
        a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        if rev:
            a, b = b, a
        return b + a + b'\x08\x00' + ipv4(src, dst, 132, sctp)


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# ---- the reproducers of the bugs fixed in "E2AP: Fix NULL tvb on TNL
# address and RAN function dissector choice" (from e2ap_tnladdr_null.py,
# e2ap_ranfunc_wrong_dissector.py and e2ap_empty_ranfundef.py) ----

def repro_frames(assoc):
    out = []
    # E2connectionUpdate whose tnlAddress uses the extension bit with
    # length 0: a NULL value tvb (DISSECTOR_ASSERT before the fix)
    item = BW()
    item.b(0, 1)
    item.b(0, 1)
    item.b(0, 1)            # tnlPort absent
    item.b(1, 1)            # tnlAddress outside the extension root
    item.lendet(0)
    item.b(0, 1)
    item.b(0, 2)            # ric-service
    lst = BW()
    lst.b(0, 5)
    lst.octets(ie(43, 1, item.get()))
    out.append(assoc.frame(pdu(0, 11, 0, container([ie(44, 0, lst.get())])), False))

    # E2setupRequest with RAN function 2 = ORAN-E2SM-RC, then a
    # RICindication for it: decoded as KPM (malformed) before the fix,
    # and differently with -2
    oid = RC1
    rcdef = BW()
    rcdef.b(0, 1)
    rcdef.b(0, 5)
    rcdef.b(0, 1)
    rcdef.b(0, 1)
    rcdef.pstr("ORAN-E2SM-RC", 1, 150)
    rcdef.pstr(oid, 1, 1000)
    rcdef.pstr("RAN Control", 1, 150)
    rcdef = rcdef.get()
    item = BW()
    item.b(0, 1)
    item.u16a(2)
    item.lendet(len(rcdef))
    item.octets(rcdef)
    item.u16a(1)
    item.pstr(oid, 1, 1000)
    lst = BW()
    lst.u8a(0)
    lst.octets(ie(8, 1, item.get()))
    out.append(assoc.frame(pdu(0, 1, 0, container([ie(10, 0, lst.get())])), False))
    hdr = bytes(6)
    ind_hdr = BW().lendet(len(hdr)).octets(hdr).get()
    ind = container([ie(5, 0, BW().u16a(2).get()), ie(25, 0, ind_hdr)])
    out.append(assoc.frame(pdu(0, 5, 0, ind), False))

    # E2setupRequest whose RAN function has an empty definition
    item = BW()
    item.b(0, 1)
    item.u16a(1)
    item.lendet(0)
    item.u16a(1)
    item.pstr(KPM3, 1, 1000)
    lst = BW()
    lst.u8a(0)
    lst.octets(ie(8, 1, item.get()))
    out.append(assoc.frame(pdu(0, 1, 0, container([ie(10, 0, lst.get())])), False))
    return out


# ---- message helpers ----

class Gen:
    def __init__(self):
        self.sp = aper.Spec([os.path.join(ASN, f) for f in FILES], OVERRIDES)
        SPECS['main'] = self.sp
        SPECS['rc3'] = aper.Spec([os.path.join(ASN, '..', 'rc-v3', f) for f in RC3FILES],
                                 OVERRIDES)
        SPECS['llc'] = aper.Spec([os.path.join(ASN, '..', 'llc-v1', f) for f in LLCFILES],
                                 OVERRIDES)
        self.procs = {o['&procedureCode']: (o, om)
                      for o, om in self.sp.procedures('E2AP-ELEMENTARY-PROCEDURES', PDUMOD)}

    def msg(self, proc, kind, f, k=0, gnb=1, full=True, **vals):
        vals.update(rf=f, gnb=gnb)
        return self.sp.pdu('E2AP-PDU', PDUMOD, kind, self.procs[proc],
                           aper.Ctx(k=k, full=full, vals=vals))

    def setup(self, funcs, gnb):
        """E2setupRequest announcing the RAN functions funcs."""
        return self.msg('id-E2setup', 0, funcs[0], gnb=gnb, funcs=funcs)


def sm_traffic(g, a, funcs, nv, **vals):
    """Subscription, indication and control messages for the RAN
    functions funcs, with nv variants of each."""
    out = []
    for f in funcs:
        for k in range(nv or NV_SM[f['kind']]):
            out.append(a.frame(g.msg('id-RICsubscription', 0, f, k=k, **vals), True))
            out.append(a.frame(g.msg('id-RICsubscription', 1, f, k=k, **vals), False))
            out.append(a.frame(g.msg('id-RICindication', 0, f, k=k, **vals), False))
            if f['kind'] in ('RC', 'NI', 'CCC', 'LLC'):
                out.append(a.frame(g.msg('id-RICcontrol', 0, f, k=k, **vals), True))
                out.append(a.frame(g.msg('id-RICcontrol', 1, f, k=k, **vals), False))
                out.append(a.frame(g.msg('id-RICcontrol', 2, f, k=k, **vals), False))
            if f['kind'] in ('RC', 'CCC'):
                out.append(a.frame(g.msg('id-RICquery', 0, f, k=k, **vals), True))
                out.append(a.frame(g.msg('id-RICquery', 1, f, k=k, **vals), False))
                out.append(a.frame(g.msg('id-RICquery', 2, f, k=k, **vals), False))
    return out


def subscriptions(g, a, f, nv, **vals):
    """More RICsubscriptionRequests, to reach the rarer CHOICE
    alternatives of the event trigger and action definitions."""
    return [a.frame(g.msg('id-RICsubscription', 0, f, k=k, **vals), True) for k in range(nv)]


def main():
    g = Gen()
    frames = []

    # Association A: an E2 node with gNB 1 announcing six RAN functions,
    # then every E2AP message, carrying the service model contents of the
    # function it names.
    a = Assoc(36422)
    frames.append(a.frame(g.setup(FUNCS, 1), False))
    frames.append(a.frame(g.msg('id-E2setup', 1, F_KPM), True))
    frames.extend(sm_traffic(g, a, TRAFFIC, None))
    frames.extend(subscriptions(g, a, F_KPM, 10))
    frames.extend(sm_traffic(g, a, [F_KPM4, F_UNK, F_UNMAPPED], 1))
    for proc, (o, om) in g.procs.items():
        for kind, fld in enumerate(['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome']):
            if fld not in o:
                continue
            for k in range(NVARIANTS):
                f = TRAFFIC[k % len(TRAFFIC)]
                frames.append(a.frame(g.msg(proc, kind, f, k=k), kind != 0))
            frames.append(a.frame(g.msg(proc, kind, F_KPM, full=False), kind != 0))

    # Association B: the same gNB on a new association; the RAN functions
    # it announced on A are found through its gNB ID.
    b = Assoc(36423)
    frames.append(b.frame(g.msg('id-E2nodeConfigurationUpdate', 0, F_KPM), False))
    frames.append(b.frame(g.msg('id-RICindication', 0, F_RC), False))

    # Associations D-H: five more gNBs, one more than the gNB table holds.
    for i in range(5):
        d = Assoc(36425 + i)
        frames.append(d.frame(g.setup([F_KPM], 4 + i), False))

    # Association R: the reproducers.
    frames.extend(repro_frames(Assoc(36421)))
    write_pcap(os.path.join(OUT, 'e2ap-coverage.pcap'), frames)

    # Malformed capture: truncated and corrupted copies of the main
    # capture's messages, on association A after its setup.
    mal = [frames[0]]
    payloads = []
    for fr in frames[1:-4]:
        payloads.append(fr[14 + 20 + 12 + 16:])
    for i, p in enumerate(payloads[::9]):
        mal.append(a.frame(p[:max(1, len(p) // 2)], False))
    for i, p in enumerate(payloads[4::13]):
        x = bytearray(p)
        x[len(x) // 2] ^= 0xa5
        mal.append(a.frame(bytes(x), True))
    # Nine RAN functions, one more than the table holds: the expert info
    # is only added in the first pass, so it is not in the main capture.
    c = Assoc(36450)
    many = [rf(10 + i, ['KPM', 'RC', 'NI'][i % 3], [KPM3, RC1, NI1][i % 3]) for i in range(9)]
    mal.append(c.frame(g.setup(many, 3), False))
    # RC v1.03 contents for the rc_manual_version_choice=version-1 runs
    r = Assoc(36451)
    f_rc = rf(30, 'RC', RC1)
    mal.append(r.frame(g.setup([f_rc], 10), False))
    mal.extend(sm_traffic(g, r, [f_rc], 24, rcver=1))
    mal.extend(subscriptions(g, r, f_rc, 40, rcver=1))
    for proc in ('id-RICquery', 'id-RICsubscriptionModification', 'id-RICsubscriptionModificationRequired'):
        if proc in g.procs:
            for kind, fld in enumerate(['&InitiatingMessage', '&SuccessfulOutcome',
                                        '&UnsuccessfulOutcome']):
                if fld in g.procs[proc][0]:
                    mal.append(r.frame(g.msg(proc, kind, f_rc, rcver=1), kind != 0))
    # RICsubscriptionDeleteRequired is registered as a successful outcome
    # (e2ap.cnf), so an initiating message is not decoded; this one is a
    # successful outcome to reach the code.
    o, om = g.procs['id-RICsubscriptionDeleteRequired']
    o2 = dict(o)
    o2['&SuccessfulOutcome'] = o['&InitiatingMessage']
    mal.append(r.frame(g.sp.pdu('E2AP-PDU', PDUMOD, 1, (o2, om),
                                aper.Ctx(vals={'rf': f_rc, 'gnb': 10})), True))
    write_pcap(os.path.join(OUT, 'e2ap-coverage-malformed.pcap'), mal)

    print(len(frames), len(mal))


if __name__ == '__main__':
    main()
