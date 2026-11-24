#!/usr/bin/env python3
# Generates test/captures/gsm_map_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GSM MAP captures.  Usage: mkgsm_map.py <outdir> [asn1 dir]

MAP rides in TCAP over SCCP over MTP3 (link-layer type 141, DLT_MTP3), so
no Decode As is needed: SCCP routes on the subsystem number (6-9, 145, 148-150
are the MAP SSNs), TCAP carries the dialogue (the application context
version selects the old argument types) and the components.

The component arguments are BER values built from the ASN.1 of the
dissector itself (asn1gen.py parses epan/dissectors/asn1/gsm_map/*.asn;
the operation and error codes and argument types come from the dispatch
switches in packet-gsm_map-template.c, so every message type the
dissector knows is covered).  The values are made up and rotate with a
variant number; nothing is random.  Everything is built with struct."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
from pcaplib import pcap, pcapng
from asn1gen import load_all, Gen, tlv_raw

TREE = os.path.join(SRCDIR, 'epan/dissectors/asn1/gsm_map')
FILES = '''MAP-ExtensionDataTypes.asn MAP-CommonDataTypes.asn MAP-SS-DataTypes.asn MAP-ER-DataTypes.asn
MAP-SM-DataTypes.asn MAP-OM-DataTypes.asn MAP-MS-DataTypes.asn MAP-CH-DataTypes.asn
MAP-LCS-DataTypes.asn MAP-GR-DataTypes.asn MAP-SS-Code.asn MAP-BS-Code.asn MAP-TS-Code.asn GSMMAP.asn SS-DataTypes.asn Ericsson.asn Nokia.asn'''.split()
PREFIX = [('gsm_map_ms_', 'MAP-MS-DataTypes'), ('gsm_map_ch_', 'MAP-CH-DataTypes'),
          ('gsm_map_sm_', 'MAP-SM-DataTypes'), ('gsm_map_ss_', 'MAP-SS-DataTypes'),
          ('gsm_map_er_', 'MAP-ER-DataTypes'), ('gsm_map_lcs_', 'MAP-LCS-DataTypes'),
          ('gsm_map_gr_', 'MAP-GR-DataTypes'), ('gsm_map_om_', 'MAP-OM-DataTypes'),
          ('gsm_map_ericsson_', 'Ericsson'), ('gsm_old_', 'DummyMAP'),
          ('gsm_ss_', 'SS-DataTypes'), ('gsm_map_', 'MAP-CommonDataTypes')]
COMMON_SEARCH = ['MAP-CommonDataTypes', 'MAP-SS-Code', 'MAP-BS-Code', 'MAP-TS-Code', 'MAP-ExtensionDataTypes']

def tbcd(digits):
    if len(digits) % 2: digits += 'f'
    return bytes((int(digits[i + 1], 16) << 4) | int(digits[i], 16) for i in range(0, len(digits), 2))

# ---- semantic overrides for OCTET STRING types (n = the size picked) -------
def o_imsi(g, n, p): return tbcd('262019876543210')[:max(n, 3)] if n <= 8 else tbcd('262019876543210')
def o_addr(g, n, p): return (b'\x91' + tbcd('4917012345678')[:max(n - 1, 1)])[:max(n, 1)]
def o_lmsi(g, n, p): return b'\x01\x02\x03\x04'
def o_tmsi(g, n, p): return b'\x11\x22\x33\x44'[:max(n, 1)]
def o_imei(g, n, p): return tbcd('353409301234567')[:8] if n == 8 else None
def o_gsn(g, n, p):
    return b'\x04\x0a\x00\x00\x01' if n < 9 else b'\x14' + bytes(range(1, 17))
def o_tpdu(g, n, p): return bytes.fromhex('0405a12143f0000062110102020240' '04c8329bfd06')
def o_ussd(g, n, p): return bytes.fromhex('e8329bfd06')
def o_tele(g, n, p): return bytes([[0x11, 0x12, 0x21, 0x22][g.pick(p, 4)]])
def o_bearer(g, n, p): return bytes([[0x10, 0x11, 0x20, 0x21][g.pick(p, 4)]])
BSSMAP_RESET = bytes.fromhex('00' '04' '30040120')
DTAP_MM = bytes.fromhex('0506' '31' '62')[:0] + bytes.fromhex('05' '31' '62')[:0]
RANAP_REL = bytes.fromhex('00' '01' '00' '0a' '00000100' '04' '40' '03' '0201' '80')
def ext_signal_info(g, t, p):
    pid = [2, 3, 2, 3][g.pick(p, 4)]
    sig = {1: bytes.fromhex('04' '03' 'a0' '90' 'a3'),
           2: BSSMAP_RESET,
           3: BSSMAP_RESET,
           4: bytes.fromhex('04' '03' '80' '90' 'a3')}[pid]
    body = tl(0x0a, bytes([pid])) + tl(0x04, sig)
    return (0, True, 16, body, False)
def access_signal_info(g, t, p):
    pid = [1, 2][g.pick(p, 2)]
    sig = BSSMAP_RESET if pid == 1 else RANAP_REL
    body = tl(0x0a, bytes([pid])) + tl(0x04, sig)
    return (0, True, 16, body, False)
LAI = bytes.fromhex('62f210' '0001')
def fixed(b):
    return lambda g, n, p: b
def o_gcid(g, n, p): return (LAI + bytes.fromhex('0002'))[:max(5, min(n, 7))]
OVR2 = {'OCT:RAIdentity': fixed(LAI + b'\x05'), 'OCT:LAIFixedLength': fixed(LAI),
        'OCT:GlobalCellId': o_gcid, 'OCT:CellGlobalIdOrServiceAreaIdFixedLength': fixed(LAI + b'\x00\x02'),
        'OCT:E-UTRAN-CGI': fixed(bytes.fromhex('62f210' '00000001')), 'OCT:TA-Id': fixed(LAI),
        'OCT:LocationNumber': fixed(bytes.fromhex('83' '10' '9471' '10')),
        'OCT:Ext-GeographicalInformation': fixed(bytes.fromhex('10' '123456' '234567' '0a')),
        'OCT:GeographicalInformation': fixed(bytes.fromhex('10' '123456' '234567' '0a')),
        'OCT:GeodeticInformation': fixed(bytes.fromhex('08' '80' '10' '123456' '234567' '0a')),
        'OCT:APN': fixed(b'\x07example\x03com'),
        'OCT:SM-RP-SMEA': fixed(bytes.fromhex('0a' '91' '9471012345')),
        'OCT:PDP-Type': fixed(bytes.fromhex('f121')),
        'OCT:USSD-DataCodingScheme': fixed(b'\x0f')}
OVR = {'OCT:IMSI': o_imsi, 'OCT:ISDN-AddressString': o_addr, 'OCT:AddressString': o_addr,
       'OCT:ISDN-SubaddressString': None, 'OCT:LMSI': o_lmsi, 'OCT:TMSI': o_tmsi,
       'OCT:IMEI': o_imei, 'OCT:GSN-Address': o_gsn, 'OCT:SignalInfo': o_tpdu,
       'OCT:USSD-String': o_ussd, 'OCT:Ext-TeleserviceCode': o_tele, 'OCT:TeleserviceCode': o_tele,
       'OCT:Ext-BearerServiceCode': o_bearer, 'OCT:BearerServiceCode': o_bearer,
       'ExternalSignalInfo': ext_signal_info, 'Bss-APDU': ext_signal_info, 'AccessNetworkSignalInfo': access_signal_info, 'OCT:Ext-ISDN-AddressString': o_addr}
OVR.update(OVR2)
OVR = {k: v for k, v in OVR.items() if v}

# ---- switch tables from the dissector's template ---------------------------
def read_switches(path):
    src = open(path).read()
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'static unsigned (dissect_(?:invokeData|returnResultData|returnErrorData))\(', src)]
    out = {}
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else src.index('static int dissect_gsm_mapext_PlmnContainer')
        body = src[pos:end]
        cases = []
        for m in re.finditer(r'case\s+(\d+)\s*:([^\n]*)\n(.*?)(?=\n\s*case\s+\d+\s*:|\n\s*default\s*:|\Z)', body, re.S):
            code = int(m.group(1))
            fns = re.findall(r'dissect_(gsm_[A-Za-z0-9_]+)', m.group(3))
            fns = [f for f in fns if f != 'gsm_map_ericsson_EnhancedCheckIMEI_Arg' or True]
            cases.append((code, m.group(2).strip(), fns))
        out[name] = cases
    return out

def nokia_table(tree):
    txt = open(os.path.join(tree, 'Nokia.asn')).read()
    out = []
    for mm in re.finditer(r'\{\s*&ExtensionType;\s*([A-Za-z0-9-]+),\s*&extensionId;\s*\{([\d ]+)\}', txt):
        out.append((mm.group(1), '.'.join(mm.group(2).split())))
    return out

class Ctx:
    def __init__(self, tree):
        self.tree = tree
        self.mods = load_all(tree, FILES)
        self.gen = Gen(self.mods, OVR)
        self.nokia = [(t, o) for t, o in nokia_table(tree) if t in self.mods['NokiaMAP-Extensions'].types]
        self.gen.overrides['ExtensionContainer'] = self.ext_container
        self.gen.overrides['SLR-ArgExtensionContainer'] = self.ext_container
        self.norm = {}
        for mn, m in self.mods.items():
            self.norm[mn] = {n.replace('-', '_'): n for n in m.types}
    def ext_container(self, g, t, path):
        types = self.nokia
        tn, oid = types[g.ext_n % len(types)]
        g.ext_n += 1
        nm = self.mods['NokiaMAP-Extensions']
        saved = g.ext_enabled
        g.ext_enabled = False
        try:
            parts = g.enc({'k': 'ref', 'name': tn, 'tag': None}, nm, 'ext/' + tn)
            val = tlv_raw(*parts[:4])
        except (KeyError, RecursionError):
            val = tl(0x30, b'')
        g.ext_enabled = saved
        pe = tl(0x30, tl(0x06, oid_bytes(oid)) + val)
        return (0, True, 16, tlv_raw(2, True, 0, pe), False)

    def lookup(self, fn):
        for pre, modname in PREFIX:
            if fn.startswith(pre):
                tail = fn[len(pre):]
                m = self.mods.get(modname)
                if m is None: return None
                n = self.norm[modname].get(tail)
                if n: return m, n
                if modname == 'MAP-CommonDataTypes':
                    for mn2 in self.mods:
                        n = self.norm[mn2].get(tail)
                        if n: return self.mods[mn2], n
                return None
        return None

# ---- BER / TCAP / SCCP / MTP3 -----------------------------------------------
def tlv(tag, content):
    return tlv_raw(tag >> 6, bool(tag & 0x20), tag & 0x1f, content)
def tl(first, content):
    return tlv_raw(first >> 6, bool(first & 0x20), first & 0x1f, content)

def comp_invoke(iid, op, param=None, linked=None):
    c = tl(0x02, bytes([iid]))
    if linked is not None: c += tl(0x80, bytes([linked]))
    c += tl(0x02, bytes([op]))
    return tl(0xa1, c + (param or b''))
def comp_result(iid, op, param=None, last=True):
    c = tl(0x02, bytes([iid]))
    if op is not None:
        c += tl(0x30, tl(0x02, bytes([op])) + (param or b''))
    return tl(0xa2 if last else 0xa7, c)
def comp_error(iid, code, param=None):
    return tl(0xa3, tl(0x02, bytes([iid])) + tl(0x02, bytes([code])) + (param or b''))
def comp_reject(iid, kind, prob):
    idpart = tl(0x02, bytes([iid])) if iid is not None else tl(0x05, b'')
    return tl(0xa4, idpart + tl(0x80 + kind, bytes([prob])))

def oid_bytes(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for n in a[2:]:
        parts = [n & 0x7f]; n >>= 7
        while n: parts.append(0x80 | (n & 0x7f)); n >>= 7
        out += bytes(reversed(parts))
    return out

DIAL_OID = bytes.fromhex('00118605010101')   # dialogue-as-id 0.0.17.773.1.1.1
def dialogue(kind, ac_num, ver, result=0):
    ac = tl(0xa1, tl(0x06, oid_bytes('0.4.0.0.1.0.%d.%d' % (ac_num, ver))))
    if kind == 'aarq':
        pdu = tl(0x60, ac)
    else:
        pdu = tl(0x61, ac + tl(0xa2, tl(0x02, bytes([result]))) +
                 tl(0xa3, tl(0xa1, tl(0x02, b'\x00'))))
    return tl(0x6b, tl(0x28, tl(0x06, DIAL_OID) + tl(0xa0, pdu)))

def tcap(kind, otid=None, dtid=None, dial=b'', comps=()):
    body = b''
    if otid is not None: body += tl(0x48, struct.pack('>I', otid))
    if dtid is not None: body += tl(0x49, struct.pack('>I', dtid))
    body += dial
    if comps: body += tl(0x6c, b''.join(comps))
    return tl({'begin': 0x62, 'end': 0x64, 'continue': 0x65, 'uni': 0x61}[kind], body)

def sccp_udt(ssn_called, ssn_calling, data, cls=0x01):
    called = bytes([0x42, ssn_called]); calling = bytes([0x42, ssn_calling])
    called_f = bytes([len(called)]) + called
    calling_f = bytes([len(calling)]) + calling
    p1 = 3
    p2 = 2 + len(called_f)
    p3 = 1 + len(called_f) + len(calling_f)
    return bytes([0x09, cls, p1, p2, p3]) + called_f + calling_f + bytes([len(data)]) + data

def mtp3(sccp, dpc=2, opc=1, sls=0):
    label = (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28)
    return bytes([0x83]) + struct.pack('<I', label) + sccp

MAXDATA = 250


SSNS = [6, 7, 8, 9, 145, 148, 149, 150]
# how many argument/result variants per opcode (the big structures are spread over many frames)
VAR = {7: 30, 2: 8, 56: 6, 83: 8, 86: 8, 70: 8, 71: 8, 62: 6, 65: 6, 45: 6, 68: 6, 69: 6, 22: 6, 23: 6, 47: 4, 50: 4, 4: 4,
       24: 4, 44: 4, 46: 4, 67: 4, 85: 6, 8: 4, 10: 4, 114: 4, 115: 4, 116: 4, 117: 4}
def nvar(code, ver):
    return VAR.get(code, 3) if ver == 3 else 2
# frames that decode with a warning or a bounds exception (kept for the malformed capture)
EXCL = set('''
inv:22:SendRoutingInfoArg:v3:2
inv:22:SendRoutingInfoArgV2:v2:0
inv:22:SendRoutingInfoArgV2:v2:1
inv:34:ForwardAccessSignalling-Arg:v3:0
inv:34:ForwardAccessSignalling-Arg:v3:1
inv:34:ForwardAccessSignalling-Arg:v3:2
inv:37:ResetArg:v2:0
inv:37:ResetArg:v2:1
inv:46:MO-ForwardSM-Arg:v2:0
inv:46:MO-ForwardSM-Arg:v2:1
inv:65:AnyTimeModificationArg:v3:5
inv:68:PrepareHO-Arg:v3:0
inv:68:PrepareHO-Arg:v3:1
inv:68:PrepareHO-Arg:v3:2
inv:68:PrepareHO-Arg:v3:3
inv:68:PrepareHO-Arg:v3:4
inv:68:PrepareHO-ArgOld:v2:1
inv:69:PrepareSubsequentHO-Arg:v3:0
inv:7:InsertSubscriberDataArg:v3:17
inv:7:InsertSubscriberDataArg:v3:18
inv:7:InsertSubscriberDataArg:v3:8
inv:84:SendGroupCallInfoArg:v3:0
inv:84:SendGroupCallInfoArg:v3:1
res:22:IMSI:v3:0
res:22:IMSI:v3:1
res:22:IMSI:v3:2
res:22:IMSI:v3:3
res:22:IMSI:v3:4
res:22:IMSI:v3:5
res:22:SendRoutingInfoResV2:v2:0
res:22:SendRoutingInfoResV2:v2:1
res:50:ActivateTraceModeRes:v3:2
res:71:AnyTimeInterrogationRes:v3:1
res:73:SetReportingStateRes:v3:2
res:7:InsertSubscriberDataRes:v3:14
'''.split())

def encode_type(cx, mod, tname, variant, popt, budget):
    g = cx.gen
    g.variant, g.popt, g.seed = variant, popt, variant * 7919
    t = {'k': 'ref', 'name': tname, 'tag': None}
    parts = g.enc(t, mod, tname)
    return tlv_raw(*parts[:4])

POPTS = (1.0, 0.7, 0.5, 0.35, 0.2, 0.12)
def best_encoding(cx, mod, tname, variant, budget):
    start = POPTS[variant % len(POPTS)] if variant < 6 else POPTS[2 + variant % 4]
    cx.gen.ext_enabled = variant % 3 == 2
    for popt in [p for p in (1.0, 0.7, 0.5, 0.35, 0.2, 0.12, 0.05, 0.0) if p <= start]:
        try:
            b = encode_type(cx, mod, tname, variant, popt, budget)
        except (KeyError, RecursionError):
            continue
        if len(b) <= budget:
            return b
    return None

def version_of(fn):
    if 'V1' in fn: return 1
    if 'V2' in fn or 'Old' in fn or fn.startswith('gsm_old_'): return 2
    return 3

def exp_pdu(name, payload):
    n = name.encode(); pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

def ses_pres_reproducer():
    """MAP reached as a BER OID dissector through SES/PRES/ACSE (fix: "GSM MAP: Do not
    treat BER OID callback data as tcap_private_t"): Exported PDU "ses", a PRES CP-type whose
    presentation context is bound to the MAP application context OID, then PDV data."""
    def ses_len(n): return bytes([n]) if n < 255 else b'\xff' + struct.pack('>H', n)
    imsi = tl(0x04, tbcd('262019876543210'))
    invoke = tl(0xa1, tl(0x02, b'\x01') + tl(0x02, b'\x38') + imsi)
    map_oid = bytes([0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03])
    ctx_item = tl(0x30, tl(0x02, b'\x01') + tl(0x06, map_oid) + tl(0x30, tl(0x06, bytes([0x51, 0x01]))))
    pdv = tl(0x30, tl(0x02, b'\x01') + tl(0xa0, invoke))
    user_data = tl(0x61, pdv)
    cp = tl(0x31, tl(0xa0, tl(0x80, b'\x01')) + tl(0xa2, tl(0xa4, ctx_item) + user_data))
    p = b'\xc1' + ses_len(len(cp)) + cp
    ses_cn = b'\x0d' + ses_len(len(p)) + p
    ses_dt = b'\x01\x00\x01\x00' + user_data
    return [exp_pdu('ses', ses_cn), exp_pdu('ses', ses_dt)]

def build(outdir, tree=TREE):
    cx = Ctx(tree)
    sw = read_switches(os.path.join(tree, 'packet-gsm_map-template.c'))
    main, mal, keys = [], [], []
    skipped = []
    state = {'tid': 0x1000, 'n': 0}
    begins = {}

    def emit(key, data, ssn=None):
        ssn = ssn or SSNS[state['n'] % len(SSNS)]
        state['n'] += 1
        fr = mtp3(sccp_udt(ssn, 6 if ssn != 6 else 7, data))
        (mal if key in EXCL else main).append(fr)
        keys.append((key, key in EXCL))

    # invoke arguments
    for code, comment, fns in sw['dissect_invokeData']:
        seen = set()
        for fn in fns:
            r = cx.lookup(fn)
            if not r or fn in seen:
                if not r: skipped.append(('inv', code, fn))
                continue
            seen.add(fn)
            mod, tname = r
            ver = version_of(fn)
            vers = [ver] if ver < 3 else [3, 2] if code in (22, 44, 46, 2, 7, 3, 67, 37, 56, 45, 47, 66, 58) else [3]
            for ver in vers:
                for variant in range(nvar(code, ver)):
                    b = best_encoding(cx, mod, tname, variant, 215)
                    if b is None:
                        skipped.append(('inv-size', code, fn)); continue
                    key = 'inv:%d:%s:v%d:%d' % (code, tname, ver, variant)
                    tid = state['tid']; state['tid'] += 1
                    iid = 1 + (tid & 0x3f)
                    d = tcap('begin', otid=tid, dial=dialogue('aarq', 1 + code % 40, ver),
                             comps=[comp_invoke(iid, code, b)])
                    if len(d) > MAXDATA:
                        d = tcap('begin', otid=tid, comps=[comp_invoke(iid, code, b)])
                    emit(key, d)
                    begins.setdefault(code, []).append((tid, iid, ver))
    # results
    for code, comment, fns in sw['dissect_returnResultData']:
        seen = set()
        for fn in fns:
            r = cx.lookup(fn)
            if not r or fn in seen:
                if not r: skipped.append(('res', code, fn))
                continue
            seen.add(fn)
            mod, tname = r
            ver = version_of(fn)
            for variant in range(nvar(code, ver)):
                b = best_encoding(cx, mod, tname, variant, 215)
                if b is None:
                    skipped.append(('res-size', code, fn)); continue
                bl = begins.get(code) or [(0x900 + code, 1, 3)]
                tid, iid, bver = bl[min(variant, len(bl) - 1)] if ver == 3 else bl[-1]
                key = 'res:%d:%s:v%d:%d' % (code, tname, ver, variant)
                d = tcap('end', dtid=tid, dial=dialogue('aare', 1 + code % 40, ver),
                         comps=[comp_result(iid, code, b)])
                if len(d) > MAXDATA:
                    d = tcap('end', dtid=tid, comps=[comp_result(iid, code, b)])
                emit(key, d)
    # results without a parameter, not-last results
    for code in sorted(begins)[:6]:
        tid, iid, ver = begins[code][0]
        emit('res0:%d' % code, tcap('end', dtid=tid, comps=[comp_result(iid, None)]))
    # errors
    allb = [x for v in begins.values() for x in v]
    ecount = 0
    for code, comment, fns in sw['dissect_returnErrorData']:
        seen = set()
        for fn in fns:
            r = cx.lookup(fn)
            if not r or fn in seen:
                if not r: skipped.append(('err', code, fn))
                continue
            seen.add(fn)
            mod, tname = r
            for variant in range(2):
                b = best_encoding(cx, mod, tname, variant, 215)
                if b is None:
                    skipped.append(('err-size', code, fn)); continue
                tid, iid, ver = allb[ecount % len(allb)]
                ecount += 1
                key = 'err:%d:%s:%d' % (code, tname, variant)
                emit(key, tcap('end', dtid=tid, comps=[comp_error(iid, code, b)]))
    # errors without parameter, for codes without a decoder, rejects
    for code in list(range(0, 3)) + [3, 7, 10, 11, 12, 13, 14, 20, 21, 22, 23, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 71, 72, 99, 200]:
        tid, iid, ver = allb[ecount % len(allb)]
        ecount += 1
        emit('err0:%d' % code, tcap('end', dtid=tid, comps=[comp_error(iid, code)]))
    for kind, probs in ((0, (0, 1, 2)), (1, (0, 1, 2, 3, 4)), (2, (0, 1, 2)), (3, (0, 1, 2, 3))):
        for prob in probs:
            tid, iid, ver = allb[ecount % len(allb)]
            ecount += 1
            emit('rej:%d:%d' % (kind, prob), tcap('end', dtid=tid, comps=[comp_reject(iid, kind, prob)]))
    emit('rej:null', tcap('end', dtid=allb[0][0], comps=[comp_reject(None, 0, 0)]))
    rep = ses_pres_reproducer()
    pcapng(os.path.join(outdir, 'gsm_map-coverage.pcapng'), [141, 252],
           [(0, f) for f in main] + [(1, f) for f in rep])
    pcap(os.path.join(outdir, 'gsm_map-coverage-malformed.pcap'), mal, linktype=141)
    with open(os.path.join(outdir, 'keys.txt'), 'w') as f:
        for k, x in keys: f.write('%s %d\n' % (k, x))
    with open(os.path.join(outdir, 'skipped.txt'), 'w') as f:
        for s_ in skipped: f.write('%s\n' % (s_,))
    print('main frames', len(main), 'excluded', len(mal), 'skipped', len(skipped))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.', sys.argv[2] if len(sys.argv) > 2 else TREE)
