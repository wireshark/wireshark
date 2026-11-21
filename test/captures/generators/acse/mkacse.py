#!/usr/bin/env python3
# Generates test/captures/acse_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the ACSE dissector (packet-acse.c, ISO 8650 ACSE and
the connectionless ISO 10035 CL-ACSE): mkacse.py <outdir>.  The APDUs are BER
built by hand (x500lib.py has the BER, TCP and OSI helpers).  They travel in
session SPDUs over COTP and TPKT on TCP 102, all registered by default.
CL-ACSE goes through the connectionless session and CL-PRES in an Exported
PDU "ses", and an ACSE APDU as TCAP component parameter in Exported PDU
"tcap".  Everything is synthetic."""
import os, struct, sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
from x500lib import *

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
MMS = '1.0.9506.2.1'
MMS_AC = '1.0.9506.2.3'
FTAM = '1.0.8571.2.1'
BER = '2.1.1'
MECH = '1.3.9999.7.1'
CONCLUDE = b'\x8b\x00'            # MMS conclude-RequestPDU, a valid PDU


def X(n, *items):
    return tlv(0xa0 | n, *items)


def P(n, *items):
    """IMPLICIT primitive context tag [n]."""
    return tlv(0x80 | n, *items)


def bits_(unused, data, n):
    return tlv(0x80 | n, bytes([unused]), data)


# ---- names, titles, qualifiers
RDN_CN = rdn((AT_CN, PSTR('acse-test')))
RDN_O = rdn((AT_O, UTF8('Example')))
NAME = SEQ(RDN_O, RDN_CN)
AP_F1 = NAME                       # AP-title form1 = Name (rdnSequence)
AP_F2 = OID('1.3.9999.1.2')        # form2
AP_F3 = PSTR('ap-title-3')         # form3
AE_Q1 = RDN_CN                     # ASO-qualifier form1
AE_Q2 = INT(42)
AE_Q3 = PSTR('qual')
AE_QO = OCTS(b'\x01\x02\x03')


def ASOI_TAG(tag, *entries):
    return tlv(tag, *entries)


def asoi_entry(q=None, ident=None):
    items = []
    if q is not None:
        items.append(X(0, q))
    if ident is not None:
        items.append(X(1, INT(ident)))
    return SEQ(*items)


# ---- EXTERNAL forms (UNIVERSAL 8)
def ext_direct(oid, value):
    return tlv(0x28, OID(oid), X(0, value))


def ext_indirect(ctx, value, descr=None):
    # packet-ber rejects ObjectDescriptor (UNIVERSAL 7) as an OCTET STRING
    # type, so the descriptor is used only in the malformed capture
    items = [INT(ctx)]
    if descr:
        items.append(tlv(0x07, descr.encode()))
    items.append(X(0, value))
    return tlv(0x28, *items)


def ext_octets(oid, value):
    return tlv(0x28, OID(oid), tlv(0x81, value))


def ext_arbitrary(oid, nbits_unused, value):
    return tlv(0x28, OID(oid), tlv(0x82, bytes([nbits_unused]), value))


def ext_both(oid, ctx, value, descr=False):
    return tlv(0x28, OID(oid), INT(ctx), *([tlv(0x07, b'descr')] if descr else []), X(0, value))


def ui(*exts):
    return X(30, *exts)


UI_MMS = ui(ext_direct(MMS, CONCLUDE))
UI_ALL = ui(ext_direct(MMS, CONCLUDE), ext_indirect(3, CONCLUDE),
            ext_octets(MMS, CONCLUDE), ext_arbitrary(MMS, 0, b'\x55'),
            ext_both(MMS, 3, CONCLUDE))
UI_IND = ui(ext_indirect(3, CONCLUDE))


# ---- authentication values
AUTH_CHAR = P(0, b'secret')
AUTH_BITS = bits_(0, b'\xa5\xa5', 1)
AUTH_EXT = tlv(0xa2, OID(MMS), X(0, CONCLUDE))
AUTH_OTHER = tlv(0xa3, OID(MMS), CONCLUDE)
AUTH_OTHER_UNK = tlv(0xa3, OID(MECH), b'\x05\x00')


# ---- context lists
def ctx_def(pci, abstract, *transfer):
    return SEQ(INT(pci), OID(abstract), SEQ(*[OID(t) for t in transfer]))


PCDL_LIST = X(14, X(0, SEQ(ctx_def(1, '2.2.1.0.1', BER), ctx_def(3, MMS, BER, '1.2.3.4'))))
PCDL_DEF = X(14, X(1, SEQ(SEQ(P(0, oid_enc(MMS)), P(1, oid_enc(BER))),
                          SEQ(P(1, oid_enc(BER))))))
ACTX_LIST = X(13, *[OID(o) for o in (MMS_AC, '1.0.8571.1.1')])


def aarq_full(*, ver=True, ctxname=MMS_AC, called_ap=AP_F1, called_aeq=AE_Q1, called_api=7, called_aei=8,
              calling_ap=AP_F2, calling_aeq=AE_Q2, calling_api=9, calling_aei=10, req=True, mech=True,
              auth=AUTH_CHAR, ctxlist=True, impl=True, pcdl=None, cdtag=True, cgtag=True, user=UI_MMS):
    items = []
    if ver:
        items.append(bits_(7, b'\x80', 0))
    items.append(X(1, OID(ctxname)))
    for n, val in ((2, called_ap), (3, called_aeq)):
        if val is not None:
            items.append(X(n, val))
    for n, val in ((4, called_api), (5, called_aei)):
        if val is not None:
            items.append(X(n, INT(val)))
    for n, val in ((6, calling_ap), (7, calling_aeq)):
        if val is not None:
            items.append(X(n, val))
    for n, val in ((8, calling_api), (9, calling_aei)):
        if val is not None:
            items.append(X(n, INT(val)))
    if req:
        items.append(bits_(4, b'\xf0', 10))
    if mech:
        items.append(P(11, oid_enc(MECH)))
    if auth:
        items.append(X(12, auth))
    if ctxlist:
        items.append(ACTX_LIST[:0] + X(13, *[OID(o) for o in (MMS_AC, '1.0.8571.1.1')]))
    if impl:
        items.append(P(29, b'impl-1.0'))
    if pcdl:
        items.append(pcdl)
    if cdtag:
        items.append(ASOI_TAG(0xaf, asoi_entry(AE_Q2, 5), asoi_entry(None, 6), asoi_entry(AE_Q3), SEQ()))
    if cgtag:
        items.append(ASOI_TAG(0xb0, asoi_entry(AE_QO, 3)))
    if user:
        items.append(user)
    return tlv(0x60, *items)


def aare_full(*, result=0, diag=(1, 0), ver=True, ctxname=MMS_AC, ap=AP_F3, aeq=AE_QO, api=3, aei=4,
              req=True, mech=True, auth=AUTH_BITS, ctxlist=True, impl=True, results=True, cdtag=True,
              cgtag=True, user=UI_MMS):
    items = []
    if ver:
        items.append(bits_(7, b'\x80', 0))
    items.append(X(1, OID(ctxname)))
    items.append(X(2, INT(result)))
    items.append(X(3, X(diag[0], INT(diag[1]))))
    for n, val in ((4, ap), (5, aeq)):
        if val is not None:
            items.append(X(n, val))
    for n, val in ((6, api), (7, aei)):
        if val is not None:
            items.append(X(n, INT(val)))
    if req:
        items.append(bits_(4, b'\xf0', 8))
    if mech:
        items.append(P(9, oid_enc(MECH)))
    if auth:
        items.append(X(10, auth))
    if ctxlist:
        items.append(X(11, *[OID(o) for o in (MMS_AC,)]))
    if impl:
        items.append(P(29, b'impl-2.0'))
    if results:
        items.append(X(12, SEQ(P(0, b'\x00'), P(1, oid_enc(BER)), P(2, b'\x00')),
                       SEQ(P(0, b'\x01'), P(2, b'\x02')),
                       SEQ(P(0, b'\x02'), P(2, b'\x03')),
                       SEQ(P(0, b'\x00'))))
    if cdtag:
        items.append(ASOI_TAG(0xad, asoi_entry(AE_Q2, 5)))
    if cgtag:
        items.append(ASOI_TAG(0xae, asoi_entry(AE_Q1, 6)))
    if user:
        items.append(user)
    return tlv(0x61, *items)


def rl(tag, *, reason=0, q=None, asoi=None, user=None):
    items = []
    if reason is not None:
        items.append(P(0, ber_int(reason)))
    if q is not None:
        items.append(X(13, q))
    if asoi is not None:
        items.append(P(14, ber_int(asoi)))
    if user:
        items.append(user)
    return tlv(tag, *items)


def rlrq(**kw):
    return rl(0x62, **kw)


def rlre(**kw):
    return rl(0x63, **kw)


def abrt(*, source=0, diag=None, q=None, asoi=None, user=None):
    items = [P(0, ber_int(source))]
    if diag is not None:
        items.append(P(1, ber_int(diag)))
    if q is not None:
        items.append(X(13, q))
    if asoi is not None:
        items.append(P(14, ber_int(asoi)))
    if user:
        items.append(user)
    return tlv(0x64, *items)


def udata_ui(*exts):
    return X(30, SEQ(*exts))


def udata_simple(b):
    return X(30, OCTS(b))


def udata_fully(*pdvs):
    return X(30, X(0, *pdvs))


def pdvlist(ctx, kind, value, ts=None):
    items = [OID(ts)] if ts else []
    items.append(INT(ctx))
    if kind == 'single':
        items.append(X(0, value))
    elif kind == 'octet':
        items.append(tlv(0x81, value))
    else:
        items.append(tlv(0x82, b'\x00', value))
    return SEQ(*items)


def adt(*, q=None, asoi=None, data=None):
    items = []
    if q is not None:
        items.append(X(0, q))
    if asoi is not None:
        items.append(P(1, ber_int(asoi)))
    items.append(data)
    return tlv(0x65, *items)


def acrq(*, q=None, asoi=None, ctxname=MMS_AC, ctxlist=True, pcdl=None, user=None):
    items = []
    if q is not None:
        items.append(X(0, q))
    if asoi is not None:
        items.append(P(1, ber_int(asoi)))
    if ctxname:
        items.append(P(3, oid_enc(ctxname)))
    if ctxlist:
        items.append(X(4, OID(MMS_AC), OID('1.0.8571.1.1')))
    if pcdl:
        items.append(X(5, X(0, SEQ(ctx_def(1, '2.2.1.0.1', BER)))))
    if user:
        items.append(user)
    return tlv(0x66, *items)


def acrp(*, q=None, asoi=None, ctxname=MMS_AC, results=True, user=None):
    items = []
    if q is not None:
        items.append(X(0, q))
    if asoi is not None:
        items.append(P(1, ber_int(asoi)))
    if ctxname:
        items.append(P(3, oid_enc(ctxname)))
    if results:
        items.append(X(4, SEQ(P(0, b'\x00'), P(1, oid_enc(BER)), P(2, b'\x00')), SEQ(P(0, b'\x01'))))
    if user:
        items.append(user)
    return tlv(0x67, *items)


def ses_rf(pres):
    return spdu(12, ses_param_userdata(pres))


def ses_ab(pres):
    return spdu(25, ses_param_userdata(pres))


def ses_aa(pres):
    return spdu(26, ses_param_userdata(pres))


def cpr_(user_data):
    return SEQ(OCTS(b'\x00\x02', 0x83), INT(2, 0x87), INT(3, 0x8a), user_data)


def pdata(ctx, apdu):
    return fully_encoded(pdv(ctx, apdu))


def main():
    frames = []
    bad = []
    cl = []
    cnt = [41000]

    class A:
        """An association on TCP 102 with contexts 1 ACSE, 3 MMS, 5 FTAM."""
        def __init__(self, target=None):
            cnt[0] += 1
            self.target = frames if target is None else target
            self.c = Conn(self.target, cnt[0], 102)
            self.c.handshake()
            self.c.send(True, tpkt(cotp_cr()))
            self.c.send(False, tpkt(cotp_cc()))

        def osi(self, from_client, s):
            self.c.send(from_client, tpkt(cotp_dt(s)))

        def cn(self, apdu, ctxs=((1, OID_ACSE), (3, MMS), (5, FTAM))):
            self.osi(True, ses_cn(pres_cp(list(ctxs), pdata(1, apdu))))

        def ac(self, apdu, n=3):
            self.osi(False, ses_ac(pres_cpa(n, pdata(1, apdu))))

        def data(self, from_client, ctx, apdu):
            self.osi(from_client, ses_dt(pdata(ctx, apdu)))

        def close(self):
            self.c.close()

    # ---- association 1: full AARQ/AARE (form1/form2/form3 titles), user
    # information in every EXTERNAL form, then data transfer, release
    a = A()
    a.cn(aarq_full(user=UI_ALL))
    a.ac(aare_full(user=UI_ALL))
    a.data(True, 3, CONCLUDE)                       # not ACSE: MMS
    a.data(True, 1, rlrq())                         # ACSE APDU in P-DATA
    a.data(False, 1, rlre())
    a.data(True, 1, adt(q=AE_Q1, asoi=5, data=udata_ui(ext_direct(MMS, CONCLUDE), ext_indirect(3, CONCLUDE))))
    a.data(False, 1, adt(q=AE_Q2, asoi=6, data=udata_simple(b'simply encoded')))
    for kind, ts in (('single', None), ('octet', BER), ('arbitrary', None)):
        a.data(True, 1, adt(q=AE_Q3, data=udata_fully(pdvlist(3, kind, CONCLUDE if kind != 'arbitrary' else b'\x77', ts=ts))))
    a.data(False, 1, adt(q=AE_QO, data=udata_fully(pdvlist(1, 'single', rlrq()))))
    a.data(True, 1, adt(data=udata_ui()))
    a.data(True, 1, acrq(q=AE_Q1, asoi=7, user=UI_MMS))
    a.data(False, 1, acrp(q=AE_Q2, asoi=7, user=UI_MMS))
    a.data(True, 1, acrq(ctxname=None, ctxlist=False))
    a.data(False, 1, acrp(ctxname=None, results=False))
    a.data(True, 1, acrq(pcdl=1, user=UI_IND))
    # P-DATA with a different context in the same TSDU
    a.osi(True, ses_fn(pdata(1, rlrq(reason=1, q=AE_Q1, asoi=9, user=UI_MMS))))
    a.osi(False, ses_dn(pdata(1, rlre(reason=1, q=AE_QO, asoi=9, user=UI_MMS))))
    # P-TYPED-DATA with an ACSE APDU in the ACSE context
    a.osi(True, b'\x01\x00' + spdu(33, b'') + pdata(1, rlrq()))
    a.osi(False, b'\x01\x00' + spdu(33, b'') + pdata(1, adt(data=udata_simple(b'typed'))))
    a.close()

    # ---- the indirect-reference state: the same output in one pass and -2
    # (frame 2 is an ACSE APDU; frame 3 carries an indirect reference)
    a = A()
    a.cn(aarq_full(user=None, mech=False, auth=None, ctxlist=False, pcdl=None, cdtag=False, cgtag=False))
    a.data(True, 1, rlrq())
    a.cn(aarq_full(user=UI_IND, mech=False, auth=None, ctxlist=False, cdtag=False, cgtag=False))
    a.close()

    # ---- associations 2..: one authentication value each, other titles
    for auth, ap, aeq, cap, caeq, pcdl, user in (
            (AUTH_BITS, AP_F2, AE_Q2, AP_F3, AE_Q3, PCDL_LIST, UI_MMS),
            (AUTH_EXT, AP_F3, AE_QO, AP_F1, AE_Q1, PCDL_DEF, UI_ALL),
            (AUTH_OTHER, AP_F1, AE_Q3, AP_F2, AE_QO, None, UI_IND),
            (AUTH_OTHER_UNK, AP_F2, AE_Q1, AP_F3, AE_Q2, PCDL_LIST, None)):
        a = A()
        a.cn(aarq_full(auth=auth, called_ap=ap, called_aeq=aeq, calling_ap=cap, calling_aeq=caeq,
                       pcdl=pcdl, user=user))
        a.ac(aare_full(auth=auth, ap=cap, aeq=caeq, user=user))
        a.close()

    # minimal AARQ / AARE, no optional field
    a = A()
    a.cn(aarq_full(ver=False, called_ap=None, called_aeq=None, called_api=None, called_aei=None,
                   calling_ap=None, calling_aeq=None, calling_api=None, calling_aei=None, req=False,
                   mech=False, auth=None, ctxlist=False, impl=False, cdtag=False, cgtag=False, user=None))
    a.ac(aare_full(ver=False, aeq=None, ap=None, api=None, aei=None, req=False, mech=False, auth=None,
                   ctxlist=False, impl=False, results=False, cdtag=False, cgtag=False, user=None,
                   diag=(2, 2)))
    a.close()

    # ---- refused: AARE in the refuse SPDU, diagnostics of service user / provider
    for res, diag, user in ((1, (1, 2), UI_MMS), (2, (2, 1), None), (1, (1, 14), None)):
        a = A()
        a.cn(aarq_full(user=None))
        a.osi(False, ses_rf(cpr_(pdata(1, aare_full(result=res, diag=diag, user=user)))))
        a.close()

    # ---- abort: ABRT with every field, with the reasons
    for ses_t, ab in ((ses_ab, abrt(source=0, diag=1, q=AE_Q1, asoi=3, user=UI_MMS)),
                      (ses_ab, abrt(source=1, diag=2)),
                      (ses_ab, abrt(source=0, diag=3, q=AE_Q2, asoi=4)),
                      (ses_ab, abrt(source=1, diag=4)),
                      (ses_ab, abrt(source=0, diag=5)),
                      (ses_ab, abrt(source=0, diag=6, user=UI_IND)),
                      (ses_ab, abrt(source=1))):
        a = A()
        a.cn(aarq_full(user=None))
        a.ac(aare_full(user=None))
        a.osi(True, ses_t(tlv(0xa0, tlv(0xa0, SEQ(INT(1), OID(BER))), pdata(1, ab))))
        a.close()

    # ---- release request/response reasons
    for rq, rs in ((0, 0), (1, 1), (30, 30)):
        a = A()
        a.cn(aarq_full(user=None))
        a.ac(aare_full(user=None))
        a.osi(True, ses_fn(pdata(1, rlrq(reason=rq))))
        a.osi(False, ses_dn(pdata(1, rlre(reason=rs))))
        a.close()
    a = A()
    a.cn(aarq_full(user=None))
    a.ac(aare_full(user=None))
    a.osi(True, ses_fn(pdata(1, rlrq(reason=None))))
    a.osi(False, ses_dn(pdata(1, rlre(reason=None))))
    a.close()

    # ---- ACSE context carrying typed data / resynchronize SPDUs: the
    # session type is not one ACSE dissects
    a = A()
    a.cn(aarq_full(user=None))
    a.ac(aare_full(user=None))
    a.close()

    # ---- connectionless ACSE (Exported PDU "ses": CL-session, CL-PRES, CL-ACSE)
    def clses(pres):
        n = b'ses'
        pad = (4 - len(n) % 4) % 4
        cl.append((252, struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0)
                   + spdu(64, b'') + pres))

    def ud(apdu):
        return SEQ(tlv(0xa4, ctx_item(1, OID_ACSE), ctx_item(3, MMS)), fully_encoded(pdv(1, apdu)))
    clses(ud(aarq(MMS_AC)))
    clses(ud(aarq_full(user=UI_ALL)))
    clses(ud(aarq_full(user=None, auth=AUTH_OTHER, pcdl=PCDL_LIST)))
    clses(ud(aare_full(user=UI_MMS)))

    # ---- TCAP: dialogue application context 2.2.1.0.1; the component
    # parameter is handed to the ber.oid handle for ACSE
    def tcap(apdu, n=1):
        aarq_d = tlv(0x60, tlv(0x80, b'\x07\x80') + tlv(0xa1, OID(OID_ACSE)))
        dlg = tlv(0x6b, tlv(0x28, OID('0.0.17.773.1.1.1') + tlv(0xa0, aarq_d)))
        inv = tlv(0xa1, INT(1) + INT(0) + apdu)
        return tlv(0x62, tlv(0x48, b'\x01\x02\x03\x04') + dlg + tlv(0x6c, inv))
    # TCAP hands the components ([APPLICATION 12]) to the ACSE handle, which
    # is not an ACSE APDU: these frames are malformed (the capture file
    # malformed only; the tests build the first frame themselves)
    for apdu in (rlrq(), aarq_full(user=UI_MMS), tlv(0x30, b'\x04\x01\x00')):
        malformed_cl.append((252, struct.pack('!HH', 12, 4) + b'tcap' + struct.pack('!HH', 0, 0) + tcap(apdu)))

    # ---- the malformed capture
    # ACSE APDU that is not valid, deep EXTERNAL nesting, short data, wrong tags
    a = A(bad)
    a.cn(aarq_full(user=None))
    a.ac(aare_full(user=None))
    inner = rlrq(reason=0)
    for _ in range(40):
        inner = rlrq(user=ui(ext_direct(OID_ACSE, inner)))
    a.data(True, 1, inner)
    for junk in (b'\x02\x01\x07', b'\x60', b'\x60\x80', b'\x62\x03\x80', b'\x60\x03\x01\x01\x01',
                 b'\x65\x03\xbe\x01\x00', b'\x30\x00', b'\x62\x00\x62\x00', b'\xa0\x03\x02\x01\x01',
                 b'\x60\x0a\xa1\x08\x06\x06\x2a\x86\x48\x86\xf7\x0d'):
        a.data(True, 1, junk)
        a.osi(True, ses_cn(pres_cp([(1, OID_ACSE)], pdata(1, junk))))
        a.osi(True, ses_ab(pdata(1, junk)))
        a.osi(True, ses_fn(pdata(1, junk)))
        a.osi(True, ses_dn(pdata(1, junk)))
    # ACSE for a session type it does not dissect: abort accept
    a.osi(True, ses_aa(tlv(0xa0, tlv(0xa0, SEQ(INT(1), OID(BER))), pdata(1, abrt()))))
    # data-value-descriptor (ObjectDescriptor): packet-ber rejects tag 7
    a.data(True, 1, aarq_full(user=ui(ext_both(MMS, 3, CONCLUDE, descr=True), ext_indirect(3, CONCLUDE, 'descr'))))
    a.data(True, 1, aarq_full(user=ui(tlv(0x28, INT(77), X(0, CONCLUDE)))))
    a.data(True, 1, aarq_full(user=ui(tlv(0x28, OID('1.3.9999.99'), X(0, CONCLUDE)))))
    a.data(True, 1, aarq_full(user=ui(tlv(0x28, OID(MMS), X(0, b'\x01')))))
    a.close()
    for junk in (b'\x62', b'\x02\x01\x07', b'\x62\x03\x80'):
        n = b'ses'
        pad = (4 - len(n) % 4) % 4
        bad.append(b'')
        bad.pop()
        # connectionless with a broken APDU
        pc = SEQ(tlv(0xa4, ctx_item(1, OID_ACSE)), fully_encoded(pdv(1, junk)))
        cl_bad = (252, struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0)
                  + spdu(64, b'') + pc)
        malformed_cl.append(cl_bad)

    write_pcapng(os.path.join(OUT, 'acse-coverage.pcapng'), [(1, f) for f in frames] + cl)
    write_pcapng(os.path.join(OUT, 'acse-coverage-malformed.pcapng'),
                 [(1, f) for f in bad] + malformed_cl)


malformed_cl = []


def write_pcapng(fname, frames):
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for i, (lt, data) in enumerate(frames):
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += blk(1, struct.pack('<HHI', lt, 0, 65535))
        out += blk(6, struct.pack('<IIIII', ifs[lt], 0, 1000000 + i * 1000, len(data), len(data)) + data)
    open(fname, 'wb').write(out)


if __name__ == '__main__':
    main()
