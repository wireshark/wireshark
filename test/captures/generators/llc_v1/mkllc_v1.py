#!/usr/bin/env python3
# Generates test/captures/llc_v1_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic E2SM-LLC v1 (packet-llc-v1.c) coverage captures.

Usage: mkllc_v1.py <outdir> [<asn1 dir of e2ap> [<asn1 dir of llc-v1>]]

E2SM-LLC (O-RAN low layer control, ORAN-E2SM-LLC) is reached through E2AP
(SCTP port 37464, PPID 70): an E2setupRequest announces a RAN function
named ORAN-E2SM-LLC with the LLC OID 1.3.6.1.4.1.53148.1.1.2.5, and the
subscription requests, indications and control requests for it carry the
LLC event trigger and action definitions, indication headers and messages,
and the control headers, messages and outcomes. The E2AP messages and the
LLC contents are encoded with aper.py (copied from the E2AP coverage
directory) from the ASN.1 modules in the Wireshark tree (asn1/e2ap and
asn1/llc-v1), with every optional component present and one alternative of
each CHOICE selected by a variant number. Nothing comes from a real network.
"""
import os
import sys














SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASN = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1/e2ap')
KASN = sys.argv[3] if len(sys.argv) > 3 else os.path.join(SRCDIR, 'epan/dissectors/asn1/llc-v1')
FILES = ['E2AP-CommonDataTypes.asn', 'E2AP-Constants.asn', 'E2AP-Containers.asn',
         'E2AP-IEs.asn', 'E2AP-PDU-Contents.asn', 'E2AP-PDU-Descriptions.asn',
         'e2sm-v3.01.asn']
KFILES = ['e2sm-v7.00.asn', 'llc-v1.0.asn']
PDUMOD = 'E2AP-PDU-Descriptions'

LLC = '1.3.6.1.4.1.53148.1.1.2.5'

KPM_TYPES = {
    'def': 'E2SM-LLC-RANFunctionDefinition',
    'ev': 'E2SM-LLC-EventTrigger',
    'act': 'E2SM-LLC-ActionDefinition',
    'ihdr': 'E2SM-LLC-IndicationHeader',
    'imsg': 'E2SM-LLC-IndicationMessage',
    'chdr': 'E2SM-LLC-ControlHeader',
    'cmsg': 'E2SM-LLC-ControlMessage',
    'cout': 'E2SM-LLC-ControlOutcome'}

SLOT = {
    'RANfunctionDefinition': 'def',
    'RICeventTriggerDefinition': 'ev',
    'RICactionDefinition': 'act',
    'RICindicationHeader': 'ihdr',
    'RICindicationMessage': 'imsg',
    'RICcontrolHeader': 'chdr',
    'RICcontrolMessage': 'cmsg',
    'RICcontrolOutcome': 'cout',
}
SPECS = {}


def rf(id_, oid=LLC, short='ORAN-E2SM-LLC', desc_oid=None):
    return {'id': id_, 'oid': oid, 'short': short, 'e2smoid': desc_oid or oid}


F_LLC = rf(1)


def e2sm_bytes(sp, slot, ctx):
    sub = aper.Ctx(k=ctx.k, full=ctx.full, vals=ctx.vals)
    if slot in KPM_TYPES:
        return SPECS['llc'].encode(KPM_TYPES[slot], 'E2SM-LLC-IEs', sub)
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
    sp.enc_str(w, dict(s, kind='PrintableString'), 'Synthetic LLC v1')
    sp.enc_int(w, f['id'], None, None)


def ov_ranfunction_oid(sp, w, t, mod, ctx):
    sp.enc_str(w, t, ctx.vals['rf']['oid'], None, mod)


def ov_ranfunction_id(sp, w, t, mod, ctx):
    sp.enc_int(w, ctx.vals['rf']['id'], 0, 4095)


def ov_gnb_id(sp, w, t, mod, ctx):
    w.b(0, 1)
    g = ctx.vals.get('gnb', 1)
    sp.enc_bits(w, {'size': ('22', '32', False)}, 32, g.to_bytes(4, 'big'))


def ov_plmn(sp, w, t, mod, ctx):
    sp.enc_octets(w, t, [b'\x00\xf1\x10', b'\x62\x02\x21'][ctx.k % 2], None, mod)


def ov_rflist(sp, w, t, mod, ctx):
    funcs = ctx.vals.get('funcs') or [ctx.vals['rf']]
    lb, ub, ext = sp.size(t, None, mod)
    sp.enc_len(w, len(funcs), lb, ub, ext)
    saved = ctx.vals['rf']
    for f in funcs:
        ctx.vals['rf'] = f
        sp.enc(w, t['elem'], None, mod, ctx)
    ctx.vals['rf'] = saved


_counters = {}


def counter(name):
    n = _counters.get(name, 0)
    _counters[name] = n + 1
    return n


TNL = [
    (bytes([192, 0, 2, 20]), 32, 36421),
    (bytes.fromhex('20010db8000000000000000000000020'), 128, 36422),
    (bytes([192, 0, 2, 22, 0x50]), 36, 36424),
    (bytes([192, 0, 2, 23]), 32, None),
]


def ov_tnl(sp, w, t, mod, ctx):
    addr, nbits, port = TNL[counter('tnl') % len(TNL)]
    w.b(0, 1)
    w.b(1 if port is not None else 0, 1)
    sp.enc_bits(w, {'size': ('1', '160', True)}, nbits, addr)
    if port is not None:
        sp.enc_bits(w, {'size': ('16', '16', False)}, 16, port.to_bytes(2, 'big'))


IFACES = ['NG', 'Xn', 'E1', 'F1', 'W1', 'S1', 'X2']
IFACE_PROC = {'NG': 21, 'Xn': 17, 'E1': 0, 'F1': 1, 'S1': 17, 'X2': 6}


def ov_component_id(sp, w, t, mod, ctx):
    i = counter('iface') % len(IFACES)
    w.b(0, 1)
    sp.enc_int(w, i, 0, len(IFACES) - 1)
    name, at = t['alts'][i]
    sp.enc(w, at, None, mod, ctx)
    if IFACES[i] != 'W1':
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


OVERRIDES = {
    'RANfunctions-List': ov_rflist,
    'RANfunction-Name': ov_ranfunction_name,
    'RANfunctionOID': ov_ranfunction_oid,
    'RANfunctionID': ov_ranfunction_id,
    'GNB-ID-Choice': ov_gnb_id,
    'PLMN-Identity': ov_plmn,
    'TNLinformation': ov_tnl,
    'E2nodeComponentID': ov_component_id,
    'E2nodeComponentConfiguration': ov_component_cfg,
}
for _t, _s in SLOT.items():
    OVERRIDES[_t] = make_slot_override(_s)


# ---- packet framing (SCTP, PPID 70) ----

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


class Gen:
    def __init__(self):
        self.sp = aper.Spec([os.path.join(ASN, f) for f in FILES], OVERRIDES)
        SPECS['main'] = self.sp
        SPECS['llc'] = aper.Spec([os.path.join(KASN, f) for f in KFILES], OVERRIDES)
        self.procs = {o['&procedureCode']: (o, om)
                      for o, om in self.sp.procedures('E2AP-ELEMENTARY-PROCEDURES', PDUMOD)}

    def msg(self, proc, kind, f, k=0, gnb=1, full=True, **vals):
        vals.update(rf=f, gnb=gnb)
        return self.sp.pdu('E2AP-PDU', PDUMOD, kind, self.procs[proc],
                           aper.Ctx(k=k, full=full, vals=vals))

    def setup(self, funcs, gnb, k=0, full=True):
        """E2setupRequest announcing the RAN functions funcs."""
        return self.msg('id-E2setup', 0, funcs[0], gnb=gnb, funcs=funcs, k=k, full=full)


def main():
    g = Gen()
    NK = int(os.environ.get('LLC_VARIANTS', '24'))
    a = Assoc(36422)
    frames = []
    # Association A: gNB 1 announces LLC as RAN function 1 (the RAN function
    # definition is an E2SM-LLC-RANFunctionDefinition); more gNBs announce it
    # with different variants of the description.
    frames.append(a.frame(g.setup([F_LLC], 1), False))
    frames.append(a.frame(g.msg('id-E2setup', 1, F_LLC), True))
    for k in range(NK):
        frames.append(a.frame(g.msg('id-RICsubscription', 0, F_LLC, k=k), True))
        frames.append(a.frame(g.msg('id-RICsubscription', 1, F_LLC, k=k), False))
        frames.append(a.frame(g.msg('id-RICindication', 0, F_LLC, k=k), False))
        frames.append(a.frame(g.msg('id-RICcontrol', 0, F_LLC, k=k), True))
        frames.append(a.frame(g.msg('id-RICcontrol', 1, F_LLC, k=k), False))
        if k % 3 == 0:
            frames.append(a.frame(g.msg('id-RICcontrol', 2, F_LLC, k=k), False))
    # the same with the optional components left out
    for k in range(4):
        frames.append(a.frame(g.msg('id-RICsubscription', 0, F_LLC, k=k, full=False), True))
        frames.append(a.frame(g.msg('id-RICindication', 0, F_LLC, k=k, full=False), False))
        frames.append(a.frame(g.msg('id-RICcontrol', 0, F_LLC, k=k, full=False), True))
        frames.append(a.frame(g.msg('id-RICcontrol', 1, F_LLC, k=k, full=False), False))
    # more E2setupRequests: every variant of the RAN function definition
    for i in range(NK):
        b = Assoc(36430 + i)
        frames.append(b.frame(g.setup([rf(1 + i % 5)], 20 + i, k=i), False))
    frames.append(a.frame(g.setup([F_LLC], 1, k=3, full=False), False))
    write_pcap(os.path.join(OUT, 'llc-v1-coverage.pcap'), frames)

    # Malformed capture: truncated and corrupted copies of the main capture's messages.
    mal = [frames[0]]
    payloads = [fr[14 + 20 + 12 + 16:] for fr in frames[1:]]
    for i, p in enumerate(payloads[::5]):
        mal.append(a.frame(p[:max(1, len(p) // 2)], False))
    for i, p in enumerate(payloads[2::7]):
        x = bytearray(p)
        x[len(x) // 2] ^= 0xa5
        mal.append(a.frame(bytes(x), True))
    for i, p in enumerate(payloads[1::11]):
        x = bytearray(p)
        x[-3] ^= 0xff
        x[len(x) * 3 // 4] ^= 0x5a
        mal.append(a.frame(bytes(x), False))
    write_pcap(os.path.join(OUT, 'llc-v1-coverage-malformed.pcap'), mal)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()
