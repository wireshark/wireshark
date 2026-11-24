#!/usr/bin/env python3
# Generates test/captures/inap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the INAP coverage captures. Usage: mkinap.py <outdir>

Writes inap-coverage.pcap (valid INAP in TCAP/SCCP/M3UA/SCTP, SSN 106 and
241, the default path) and inap-coverage-malformed.pcap (paths that only
malformed input reaches).  The component arguments are encoded from the
type tree that is read out of packet-inap.c (berschema.py); the TCAP, SCCP
and M3UA framing and the Remote Operations components are built here
with struct.  All values are made up."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
from berschema import Schema, tlv

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('INAP_C', os.path.join(SRCDIR, 'epan/dissectors/packet-inap.c'))

sc = Schema(SRC, 'inap', seed=725)
text = sc.src

def table(kind):
    """case opcode_x: ... dissect_XArg_PDU -> type name, per switch"""
    m = re.search(r'static unsigned dissect_%s\([^;]*?\) \{\n.*?\n\}\n' % kind, text, re.S)
    out = []
    for c in re.finditer(r'case (\w+):.*?\n\s*offset= dissect_(\w+)_PDU', m.group(0), re.S):
        out.append((c.group(1), 'dissect_inap_' + c.group(2)))
    return out

consts = {n: int(v) for n, v in re.findall(r'#define ((?:opcode|errcode)_\w+)\s+(\d+)', text)}
INVOKES = [(consts[c], c, f) for c, f in table('invokeData')]
RESULTS = [(consts[c], c, f) for c, f in table('returnResultData')]
ERRORS = [(consts[c], c, f) for c, f in table('returnErrorData')]

# ---- hooks for the handwritten (ANY) parts of the tree
# the template leaves these four types undissected ("FIX ME" bodies): they
# do not advance the offset, so leave them out
for h in ('T_triggerPar', 'T_uIScriptSpecificInfo', 'T_uIScriptResult',
          'T_uIScriptSpecificInfo_01', 'T_uIScriptSpecificInfo_02'):
    sc.hooks['dissect_inap_' + h] = lambda s, ov: b''

def embedded_pdv(s, ov):
    cls, tag = ov if ov else (0, 11)
    # EXTERNAL: indirect reference and an arbitrary (bit string) encoding
    return tlv(cls, tag, True, tlv(0, 2, False, b'\x05') + tlv(2, 2, False, b'\x00\xaa\x55'))
sc.hooks['dissect_inap_EMBEDDED_PDV'] = embedded_pdv

def ext_value(s, ov):
    return tlv(2, 1, False, b'\x04\x02\xaa\xbb')
sc.hooks['dissect_inap_T_value'] = ext_value
# only local codes; the global OID form is built by hand below
sc.hooks['dissect_inap_Code'] = lambda s, ov: integer(s.rng.randrange(0, 200))

# octet strings that are parsed by the ISUP / Q.931 helpers
def pick(*alts):
    return lambda s: s.rng.choice(alts)
sc.fixed = {
    'dissect_inap_CalledPartyNumber': pick(bytes([0x83, 0x10, 0x21, 0x43, 0x65]), bytes([0x03, 0x10, 0x21, 0x43])),
    'dissect_inap_CallingPartyNumber': pick(bytes([0x83, 0x13, 0x21, 0x43, 0x65]), bytes([0x03, 0x14, 0x21])),
    'dissect_inap_OriginalCalledPartyID': pick(bytes([0x83, 0x10, 0x21, 0x43]), bytes([0x03, 0x10, 0x21])),
    'dissect_inap_RedirectingPartyID': pick(bytes([0x83, 0x10, 0x21, 0x43]), bytes([0x03, 0x10, 0x21])),
    'dissect_inap_RedirectionInformation': pick(bytes([0x00, 0x01]), bytes([0x45, 0x23])),
    'dissect_inap_HighLayerCompatibility': pick(bytes([0x91, 0x81]), bytes([0x91, 0x01, 0x81])),
    'dissect_inap_Cause': pick(bytes([0x80, 0x90]), bytes([0x81, 0x82, 0x83])),
    'dissect_inap_Digits': pick(bytes([0x01, 0x83, 0x10, 0x21, 0x43, 0x65]), bytes([0x02, 0x03, 0x14, 0x21]),
                                bytes([0x01, 0x03, 0x10, 0x21, 0x43])),
    'dissect_inap_T_bearerCap': pick(bytes([0x80, 0x90, 0xa3]), bytes([0x88, 0x90])),
}

# ---- components
def integer(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return tlv(0, 2, False, v.to_bytes(n, 'big', signed=True))

def code_local(v):
    return integer(v)

def code_global(oid=b'\x2a\x03\x04'):
    return tlv(0, 6, False, oid)

def invoke(iid, op, arg, linked=None, glob=False):
    b = integer(iid) if iid is not None else tlv(0, 5, False, b'')
    if linked is not None:
        b += tlv(2, 0, False, integer(linked))
    b += code_global() if glob else code_local(op)
    return tlv(2, 1, True, b + (arg or b''))

def retres(iid, op, res):
    b = integer(iid)
    if op is not None:
        b += tlv(0, 16, True, code_local(op) + (res or b''))
    return tlv(2, 2, True, b)

def reterr(iid, ec, par, glob=False):
    b = integer(iid) + (code_global() if glob else code_local(ec)) + (par or b'')
    return tlv(2, 3, True, b)

def reject(iid, prob_cls_tag, val):
    return tlv(2, 4, True, (integer(iid) if iid is not None else tlv(0, 5, False, b'')) +
               tlv(2, prob_cls_tag, False, bytes([val])))

# ---- TCAP / SCCP / M3UA / SCTP framing
def ipcsum(h):
    s = sum((h[i] << 8) + h[i + 1] for i in range(0, len(h), 2))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

AC_INAP = bytes([0x04, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00])    # 0.4.0.1.1.1.0.0
DLG_AS = bytes([0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01])       # 0.0.17.773.1.1.1

def dialogue(kind='aarq', ac=AC_INAP):
    if kind == 'aarq':
        pdu = tlv(1, 0, True, tlv(2, 1, True, tlv(0, 6, False, ac)))
    else:
        pdu = tlv(1, 1, True, tlv(2, 1, True, tlv(0, 6, False, ac)) +
                  tlv(2, 2, True, tlv(0, 2, False, b'\x00')) +
                  tlv(2, 3, True, tlv(2, 1, True, tlv(0, 2, False, b'\x00'))))
    return tlv(1, 11, True, tlv(0, 8, True, tlv(0, 6, False, DLG_AS) + tlv(2, 0, True, pdu)))

def tcap(kind, comps, otid=1, dtid=1, dlg=b''):
    cp = tlv(1, 12, True, b''.join(comps)) if comps else b''
    if kind == 'begin':
        return tlv(1, 2, True, tlv(1, 8, False, struct.pack('>I', otid)) + dlg + cp)
    if kind == 'continue':
        return tlv(1, 5, True, tlv(1, 8, False, struct.pack('>I', otid)) +
                   tlv(1, 9, False, struct.pack('>I', dtid)) + dlg + cp)
    if kind == 'end':
        return tlv(1, 4, True, tlv(1, 9, False, struct.pack('>I', dtid)) + dlg + cp)
    if kind == 'abort':
        return tlv(1, 7, True, tlv(1, 9, False, struct.pack('>I', dtid)) + tlv(1, 10, False, b'\x01'))
    if kind == 'uni':
        return tlv(1, 1, True, cp)

def sccp(tcap_msg, ssn):
    called = bytes([0x43, 0x02, 0x00, ssn])
    calling = bytes([0x43, 0x01, 0x00, ssn])
    if len(tcap_msg) > 240:
        # long unitdata: 16 bit little endian pointers and data length
        lc, lg = len(called), len(calling)
        # (the dissector counts a 16 bit pointer from its second octet)
        p1 = 11 - 3 - 1
        p2 = (11 + 1 + lc) - 5 - 1
        p3 = (11 + 1 + lc + 1 + lg) - 7 - 1
        return bytes([0x13, 0x00, 0x0f]) + struct.pack('<HHHH', p1, p2, p3, 0) + bytes([lc]) + called + \
            bytes([lg]) + calling + struct.pack('<H', len(tcap_msg)) + tcap_msg
    p1 = 3
    p2 = (5 + 1 + len(called)) - 3
    p3 = (5 + 1 + len(called) + 1 + len(calling)) - 4
    return bytes([0x09, 0x00, p1, p2, p3]) + bytes([len(called)]) + called + \
        bytes([len(calling)]) + calling + bytes([len(tcap_msg)]) + tcap_msg

def frame(tcap_msg, ssn=106, tsn=1):
    pd = struct.pack('>IIBBBB', 1, 2, 3, 2, 0, 0) + sccp(tcap_msg, ssn)
    plen = 4 + len(pd)
    param = struct.pack('>HH', 0x0210, plen) + pd + b'\0' * ((4 - plen % 4) % 4)
    m3ua = struct.pack('>BBBBI', 1, 0, 1, 1, 8 + len(param)) + param
    clen = 16 + len(m3ua)
    chunk = struct.pack('>BBHIHHI', 0, 3, clen, tsn, 0, tsn, 3) + m3ua + b'\0' * ((4 - clen % 4) % 4)
    sctp = struct.pack('>HHII', 2905, 2905, 1, 0) + chunk
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(sctp), tsn & 0xffff, 0, 64, 132, 0,
                      bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    iph = iph[:10] + struct.pack('>H', ipcsum(iph)) + iph[12:]
    return bytes.fromhex('020000000002' '020000000001' '0800') + iph + sctp

def pcap(frames):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack('<IIII', 1000 + i, 0, len(f), len(f)) + f
    return out

# ---- the main capture
class Cap:
    def __init__(self):
        self.frames = []
        self.n = 0
        self.tid = 0x1000
        self.marks = []
    def mark(self, name):
        self.marks.append((name, self.n))
    def add(self, kind, comps, ssn=106, dlg=b'', otid=None, dtid=None):
        self.n += 1
        if kind == 'begin':
            self.tid += 1
        o = otid if otid is not None else self.tid
        d = dtid if dtid is not None else self.tid
        self.frames.append(frame(tcap(kind, comps, o, d, dlg), ssn, self.n))

BAD = set()          # (set from the check run: arguments that are not clean)

def fit(fn):
    for _ in range(30):
        a = sc.enc(fn)
        if len(a) < 400:
            return a
    return a

def build_main():
    c = Cap()
    # reproducers of "INAP: Fix a dissector bug assertion on the BCSM
    # correlation ID": bcsmEventCorrelationID in EventReportBCSM and
    # RequestReportBCSMEvent (frames 1 and 2)
    corr = bytes([0x00, 0x11, 0x22])
    a24 = tlv(0, 16, True, tlv(2, 0, False, b'\x02') + tlv(2, 1, False, corr))
    c.add('begin', [invoke(1, 24, a24)])
    bc = tlv(0, 16, True, tlv(2, 0, False, b'\x02') + tlv(2, 1, False, b'\x00'))
    a23 = tlv(0, 16, True, tlv(2, 0, True, bc) + tlv(2, 1, False, corr))
    c.add('begin', [invoke(2, 23, a23)])
    # with a dialogue portion naming the INAP application context
    c.add('begin', [invoke(3, 24, a24)], dlg=dialogue('aarq'), otid=0x3001)
    c.add('continue', [invoke(4, 24, a24)], dlg=dialogue('aare'), otid=0x2000, dtid=0x3001)
    c.add('end', [invoke(5, 24, a24)], dtid=0x2000)
    c.mark('dialogue')
    # every argument type, in a Begin, a Continue and an End of one
    # transaction (SSN 241 for the odd operation codes)
    for op, name, fn in INVOKES:
        ssn = 241 if op & 1 else 106
        T, R = 0x10000 + op * 16, 0x20000 + op * 16
        c.add('begin', [invoke(10 + op, op, fit(fn))], ssn=ssn, otid=T)
        c.add('continue', [invoke(11 + op, op, fit(fn))], ssn=ssn, otid=R, dtid=T)
        c.add('end', [invoke(12 + op, op, fit(fn))], ssn=ssn, dtid=R)
    c.mark('arguments')
    # more encodings for the types that reach a CHOICE with many
    # alternatives (EventSpecificInformationBCSM has 31): one per
    # alternative, as TCAP Unidirectional messages
    for op, name, fn in INVOKES:
        for k in range(min(sc.reach_max(fn), 34) - 3):
            c.add('uni', [invoke(100 + k, op, fit(fn))], ssn=106)
    c.mark('choice sweep')
    # every result type and every error parameter
    for rnd in range(2):
        for op, name, fn in RESULTS:
            c.add('end', [retres(20 + op, op, fit(fn))], dtid=0x30000 + op)
        for op, name, fn in ERRORS:
            if fn.endswith('ReferralParameter'):
                continue      # needs a DSP AccessPointInformation: malformed capture
            c.add('end', [reterr(30 + op, op, fit(fn))], dtid=0x40000 + op)
    c.mark('results and errors')
    return c

def build_special(c):
    c.mark('digits')
    # several components in one message, linked invokes, absent invoke id
    a = [invoke(40, 0, b'')]
    c.add('begin', [invoke(40, 0, None), invoke(41, 10, None, linked=40), invoke(None, 64, None)])
    c.add('uni', [invoke(1, 17, None)])
    # return results without a result, with the opcode and an empty result
    c.add('end', [retres(1, None, None), retres(2, 24, None)])
    # errors without parameters
    for ec in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21):
        c.add('end', [reterr(50 + ec, ec, None)])
    # global opcode / error code
    c.add('begin', [invoke(60, 0, None, glob=True)])
    c.add('end', [reterr(61, 0, None, glob=True)])
    # rejects: general, invoke, return result, return error problems
    for tag, vals in ((0, (0, 1, 2)), (1, (0, 1, 2, 3, 4, 5)), (2, (0, 1, 2)), (3, (0, 1, 2, 3, 4))):
        for v in vals:
            c.add('end', [reject(70 + tag, tag, v)])
    c.add('end', [reject(None, 0, 1)])
    # TCAP abort
    c.add('abort', [])

def ext_fields(c):
    """ExtensionField with a local and a global type, with and without
    criticality; the value is dissected as data"""
    def ef(code, crit, val):
        return tlv(0, 16, True, code + (tlv(0, 10, False, bytes([crit])) if crit is not None else b'') +
                   tlv(2, 1, False, val))
    exts = tlv(2, 5, True, ef(integer(1), None, b'\x01\x02') + ef(integer(2), 1, b'') +
               ef(code_global(), 2, b'\x05\x00') + ef(code_global(b'\x2a\x03\x07'), None, b'\x04\x01\x99') +
               ef(integer(3), 0, b'\x30\x00'))
    # initialDP/continueWithArgument carry Extensions as [5]/[x]
    c.add('begin', [invoke(91, 24, tlv(0, 16, True, tlv(2, 0, False, b'\x02') + exts))])
    c.add('begin', [invoke(92, 88, tlv(0, 16, True, exts))])   # continueWithArgument

def digits(c):
    c.mark('extension fields')
    """Digits users: every hf that dissect_inap_Digits() branches on is
    reached by the argument encodings above; add explicit numbers for the
    ISUP and Q.931 helpers (CalledPartyNumber, CallingPartyNumber,
    BearerCapability, RedirectionInformation, Original/RedirectingPartyID,
    HighLayerCompatibility, Cause)"""
    def seq(*e):
        return tlv(0, 16, True, b''.join(e))
    called = bytes([0x83, 0x10, 0x21, 0x43, 0x65])
    calling = bytes([0x83, 0x13, 0x21, 0x43, 0x65, 0x87])
    bearer = bytes([0x80, 0x90, 0xa3])
    cause = bytes([0x80, 0x90])
    hlc = bytes([0x91, 0x81])
    redir = bytes([0x00, 0x01])
    # InitialDPArg: serviceKey [0]? build from the schema, then overwrite
    # fields by hand where the schema generator would use random bytes
    idp = seq(tlv(2, 0, False, b'\x05'),
              tlv(2, 2, False, called),
              tlv(2, 3, False, calling),
              tlv(2, 5, False, b'\x0a'),
              tlv(2, 6, False, bytes([0x80, 0x90, 0xa3])),
              tlv(2, 7, False, b'\x04'),
              tlv(2, 8, False, bytes([0x81, 0xf1])))
    c.add('begin', [invoke(100, 0, idp)])

def build_malformed():
    import random
    r = random.Random(774)
    c = Cap()
    # unknown opcodes and error codes (expert infos)
    c.add('begin', [invoke(80, 250, tlv(0, 16, True, b''))])
    c.add('end', [retres(81, 250, tlv(0, 16, True, b''))])
    c.add('end', [reterr(82, 250, tlv(0, 16, True, b''))])
    c.add('begin', [invoke(83, 250, None)])
    # ReferralParameter needs a DSP AccessPointInformation
    for op, name, fn in ERRORS:
        if fn.endswith('ReferralParameter'):
            c.add('end', [reterr(84, op, sc.enc(fn))], dtid=0x50000)
    # the "FIX ME" types do not advance the offset
    sc.hooks.pop('dissect_inap_T_uIScriptSpecificInfo')
    for op, name, fn in INVOKES:
        if 'Script' in fn or 'TriggerData' in fn:
            for _ in range(2):
                c.add('begin', [invoke(85, op, sc.enc(fn))], otid=0x50001)
    # mutations of the valid arguments: wrong tags, truncated and
    # lengthened contents, bit flips, in the TCAP component
    for rnd in range(3):
        for op, name, fn in INVOKES:
            arg = bytearray(fit(fn))
            m = rnd
            if m == 0 and len(arg) > 3:
                arg = arg[:r.randrange(2, len(arg))]          # truncated (length too long)
            elif m == 1:
                arg[r.randrange(len(arg))] ^= 1 << r.randrange(8)
            else:
                for _ in range(3):
                    arg[r.randrange(len(arg))] = r.randrange(256)
            inv = bytearray(invoke(90, op, bytes(arg)))
            c.add('begin', [bytes(inv)], otid=0x60000 + op)
    # a component that is cut short and one with trailing bytes
    c.add('begin', [invoke(91, 0, None)[:-1]], otid=0x61000)
    c.add('begin', [invoke(92, 0, None) + b'\x01\x02'], otid=0x61001)
    # results and errors, mutated
    for op, name, fn in RESULTS + ERRORS:
        for _ in range(2):
            arg = bytearray(fit(fn))
            arg[r.randrange(len(arg))] = r.randrange(256)
            c.add('end', [retres(93, op, bytes(arg)) if (op, name, fn) in RESULTS else reterr(93, op, bytes(arg))],
                  dtid=0x62000 + op)
    return c

def main(out):
    c = build_main()
    ext_fields(c)
    digits(c)
    build_special(c)
    frames = [f for i, f in enumerate(c.frames, 1) if i not in BAD]
    open(os.path.join(out, 'inap-coverage.pcap'), 'wb').write(pcap(frames))
    print('main capture: %d frames' % len(frames), c.marks)
    m = build_malformed()
    open(os.path.join(out, 'inap-coverage-malformed.pcap'), 'wb').write(pcap(m.frames))
    print('malformed capture: %d frames' % len(m.frames))
    return c

if __name__ == '__main__':
    main(sys.argv[1])
