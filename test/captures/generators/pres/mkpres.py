#!/usr/bin/env python3
# Generates test/captures/pres_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the presentation dissector (packet-pres.c, ISO
8823 and the connectionless ISO 9576): mkpres.py <outdir>.  The PPDUs are
BER built by hand (x500lib.py has the BER, TCP and OSI helpers); they
travel in session SPDUs over COTP and TPKT on TCP 102, all registered by
default.  CL-PRES goes through the connectionless session in an Exported
PDU.  Everything is synthetic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from x500lib import (
    aare, aarq, BITS, Conn, cotp_cc, cotp_cr, cotp_dt, INT, OCTS, OID, SEQ, ses_dt,
    ses_param_userdata, SET, spdu, tlv, tpkt,
)

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ACSE = '2.2.1.0.1'
FTAM = '1.0.8571.2.1'
BER = '2.1.1'
UNKNOWN = '1.3.9999.1'
AARQ = aarq('1.0.8571.1.1')
FT1 = tlv(0xa2, b'')
FT2 = tlv(0xa3, b'')
FT3 = tlv(0xa4, b'')


def bits(unused, data, tag=0x03):
    return BITS(unused, data, tag)


def ctx(i, abstract, *transfer):
    return SEQ(INT(i), OID(abstract), SEQ(*[OID(t) for t in transfer]))


def ctxlist(tag, *items):
    return tlv(tag, *items)


def result(res, ts=None, reason=None):
    return SEQ(INT(res, 0x80), *( [OID(ts, 0x81)] if ts else []), *( [INT(reason, 0x82)] if reason is not None else []))


# User-data
def simply(data):
    return OCTS(data, 0x40)


def pdvl(c, kind, value, ts=None):
    body = [OID(ts)] if ts else []
    body.append(INT(c))
    if kind == 'single':
        body.append(tlv(0xa0, value))
    elif kind == 'octet':
        body.append(OCTS(value, 0x81))
    else:
        body.append(bits(0, value, 0x82))
    return SEQ(*body)


def fully(*pdvs):
    return tlv(0x61, *pdvs)


def mode(v=1):
    return tlv(0xa0, INT(v, 0x80))


def normal(tag, *items):
    return tlv(tag, *items)


VERSION = bits(7, b'\x80', 0x80)


def cp(*, calling=b'\x00\x01', called=b'\x00\x02', contexts=None, default=True, reqs=True, ureq=True,
       opts=True, nominated=True, ext=True, user=None, version=True):
    items = []
    if version:
        items.append(VERSION)
    if calling is not None:
        items.append(OCTS(calling, 0x81))
    if called is not None:
        items.append(OCTS(called, 0x82))
    if contexts is not None:
        items.append(ctxlist(0xa4, *contexts))
    if default:
        items.append(tlv(0xa6, OID(ACSE, 0x80), OID(BER, 0x81)))
    if reqs:
        items.append(bits(6, b'\xc0', 0x88))
    if ureq:
        items.append(bits(3, b'\x4f\xe0', 0x89))
    if opts:
        items.append(tlv(0xab, bits(6, b'\xc0')))
    if nominated:
        items.append(tlv(0xac, INT(1)))
    if ext:
        items.append(tlv(0xae, SEQ()))
    if user:
        items.append(user)
    return SET(mode(), normal(0xa2, *items))


def cpa(*, responding=b'\x00\x02', results=None, reqs=True, ureq=True, opts=True, nominated=True,
        user=None, version=True):
    items = []
    if version:
        items.append(VERSION)
    if responding is not None:
        items.append(OCTS(responding, 0x83))
    if results is not None:
        items.append(tlv(0xa5, *results))
    if reqs:
        items.append(bits(6, b'\xc0', 0x88))
    if ureq:
        items.append(bits(3, b'\x4f\xe0', 0x89))
    if opts:
        items.append(tlv(0xab, bits(6, b'\xc0')))
    if nominated:
        items.append(tlv(0xac + 1, INT(1)))
    if user:
        items.append(user)
    return SET(mode(), normal(0xa2, *items))


def cpr(*, responding=b'\x00\x02', results=None, default_result=True, reason=True, user=None, version=True):
    items = []
    if version:
        items.append(VERSION)
    if responding is not None:
        items.append(OCTS(responding, 0x83))
    if results is not None:
        items.append(tlv(0xa5, *results))
    if default_result:
        items.append(INT(2, 0x87))
    if reason:
        items.append(INT(3, 0x8a))
    if user:
        items.append(user)
    return SEQ(*items)


def aru(*, ids=(1, 3), user=None):
    items = []
    if ids is not None:
        items.append(tlv(0xa0, *[SEQ(INT(i), OID(BER)) for i in ids]))
    if user:
        items.append(user)
    return tlv(0xa0, *items)


def arp(reason=1, event=2):
    items = []
    if reason is not None:
        items.append(INT(reason, 0x80))
    if event is not None:
        items.append(INT(event, 0x81))
    return SEQ(*items)


def ses(si, pres, extra=b''):
    return spdu(si, extra + ses_param_userdata(pres))


def ses_td(pres):
    return b'\x01\x00' + spdu(33, b'') + pres


def ses_rs(pres):
    return spdu(53, b'\x1a\x01\x01\x1b\x01\x00\x2a\x03001' + ses_param_userdata(pres))


def ses_ra(pres):
    return spdu(34, b'\x1a\x01\x01\x1b\x01\x00\x2a\x03001' + ses_param_userdata(pres))


def main():
    frames = []
    bad = []

    def new_assoc(port, target=frames):
        c = Conn(target, port, 102)
        c.handshake()
        c.send(True, tpkt(cotp_cr()))
        c.send(False, tpkt(cotp_cc()))
        return c

    def tp(c, from_client, session_pdu, eot=True):
        c.send(from_client, tpkt(cotp_dt(session_pdu, eot)))

    # ---- association 1: everything on the normal mode
    c = new_assoc(40001)
    ctxs = [ctx(1, ACSE, BER), ctx(3, FTAM, BER, '1.2.3.4.5'), ctx(5, UNKNOWN, BER), ctx(7, ACSE, BER)]
    tp(c, True, ses(13, cp(contexts=ctxs, user=fully(pdvl(1, 'single', AARQ)))))
    res = [result(0, BER), result(0, BER), result(1, None, 1), result(2, BER, 2)]
    tp(c, False, ses(14, cpa(results=res, user=fully(pdvl(1, 'single', aare('1.0.8571.1.1'))))))
    # data transfer: every PDV-list kind
    data = [
        fully(pdvl(3, 'single', FT1)),
        fully(pdvl(3, 'single', FT2), pdvl(3, 'octet', FT3)),
        fully(pdvl(3, 'octet', FT1)),
        fully(pdvl(3, 'arbitrary', b'\x01\x02\x03')),
        fully(pdvl(5, 'single', INT(5)), pdvl(5, 'octet', b'abc'), pdvl(5, 'arbitrary', b'\x80')),
        fully(pdvl(7, 'single', INT(7), ts=BER)),
        fully(pdvl(9, 'single', INT(9))),
        fully(pdvl(3, 'single', FT1, ts=BER)),
        simply(b'simply encoded data'),
        simply(b''),
    ]
    for i, d in enumerate(data):
        tp(c, i % 2 == 0, ses_dt(d))
    # a data PPDU split into two PPDUs of one TSDU
    tp(c, True, ses_dt(fully(pdvl(3, 'single', FT1)) + fully(pdvl(3, 'single', FT2))))
    # typed data: AC, ACA, ttd
    tp(c, True, ses_td(tlv(0xa0, tlv(0xa0, ctx(11, '1.3.9999.3', BER), ctx(13, ACSE, BER)),
                           tlv(0xa1, INT(5), INT(7)), fully(pdvl(3, 'single', FT1)))))
    tp(c, False, ses_td(tlv(0xa1, tlv(0xa0, result(0, BER), result(0, BER)), tlv(0xa1, INT(0), INT(1)),
                            fully(pdvl(3, 'single', FT2)))))
    tp(c, True, ses_td(tlv(0xa0, tlv(0xa0, ctx(15, ACSE, BER)))))
    tp(c, False, ses_td(tlv(0xa1)))
    tp(c, True, ses_td(fully(pdvl(3, 'single', FT1))))
    tp(c, False, ses_td(simply(b'typed')))
    # resynchronize
    tp(c, True, ses_rs(SEQ(tlv(0xa0, SEQ(INT(1), OID(BER)), SEQ(INT(3), OID(BER))), fully(pdvl(3, 'single', FT1)))))
    tp(c, False, ses_ra(SEQ(tlv(0xa0, SEQ(INT(1), OID(BER))), simply(b'rsa'))))
    tp(c, True, ses_rs(SEQ()))
    tp(c, False, ses_ra(SEQ()))
    # release and abort
    tp(c, True, ses(9, fully(pdvl(3, 'single', FT1))))
    tp(c, False, ses(10, fully(pdvl(3, 'single', FT2))))
    c.close()

    # ---- association 2: the minimum, x410 mode
    c = new_assoc(40002, bad)
    tp(c, True, ses(13, SET(mode(), tlv(0xa1, INT(0, 0x80), INT(3, 0x81), INT(1, 0x82), tlv(0xa3, tlv(0xa0, INT(5)))))))
    tp(c, False, ses(14, SET(mode(), tlv(0xa1, INT(0, 0x80), INT(3, 0x81), tlv(0xa2, tlv(0xa0, INT(5)))))))
    c.close()
    c = new_assoc(40002)
    tp(c, True, ses(13, cp(calling=None, called=None, default=False, reqs=False, ureq=False, opts=False,
                           nominated=False, ext=False, version=False)))
    tp(c, False, ses(14, cpa(responding=None, reqs=False, ureq=False, opts=False, nominated=False, version=False)))
    tp(c, True, ses_dt(simply(b'x')))
    tp(c, False, ses_dt(fully(pdvl(3, 'single', FT1))))
    c.close()

    # ---- association 3: refused, CPR variants
    for port, pres in ((40003, cpr(results=[result(1, None, 1)], user=fully(pdvl(1, 'single', aare('1.0.8571.1.1', result=1))))),
                       (40004, cpr(responding=None, default_result=False, reason=False, version=False)),
                       (40005, SET(INT(1, 0x80))),
                       (40006, cpr(results=[result(2, BER, 2)], user=simply(b'refused')))):
        c = new_assoc(port)
        tp(c, True, ses(13, cp(contexts=[ctx(1, ACSE, BER)])))
        tp(c, False, ses(12, pres))
        c.close()

    # ---- association 4: aborts
    for port, ses_type, pres in ((40007, 25, aru()), (40008, 25, aru(ids=None, user=simply(b'abort'))),
                                 (40009, 25, aru(ids=(1,), user=fully(pdvl(3, 'single', FT1)))),
                                 (40010, 26, aru(ids=None)), (40011, 25, arp()),
                                 (40012, 25, arp(None, None)), (40013, 26, arp(2, 1)),
                                 (40014, 25, SET(INT(0, 0x80), INT(4, 0x81)))):
        c = new_assoc(port)
        tp(c, True, ses(13, cp(contexts=[ctx(1, ACSE, BER)])))
        tp(c, False, ses(14, cpa(results=[result(0, BER)])))
        tp(c, True, ses(ses_type, pres))
        c.close()

    # ---- association 5: no CP in the capture; the contexts come from the
    # users table (-o uat:pres_context_list:...) with no definition
    c = new_assoc(40020)
    tp(c, True, ses_dt(fully(pdvl(2, 'single', AARQ))))
    tp(c, False, ses_dt(fully(pdvl(2, 'octet', aare('1.0.8571.1.1')))))
    c.close()

    # ---- connectionless presentation (Exported PDU "ses")
    cl = []
    def clses(pres, extra=b''):
        data = spdu(64, extra) + pres
        n = b'ses'
        pad = (4 - len(n) % 4) % 4
        cl.append((252, struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + data))
    for p in (SEQ(simply(b'unitdata')),
              SEQ(VERSION, OCTS(b'\x00\x01', 0x81), OCTS(b'\x00\x02', 0x82),
                  tlv(0xa4, ctx(1, FTAM, BER)), fully(pdvl(1, 'single', FT1))),
              SEQ(fully(pdvl(1, 'octet', FT3)))):
        clses(p)

    # ---- the malformed capture
    # a data PPDU before the PPDU that defines its context: decodes only
    # in the second pass because the table is filled on every pass
    c = new_assoc(40030, bad)
    tp(c, True, ses(13, cp(contexts=[ctx(1, ACSE, BER)])))
    tp(c, False, ses(14, cpa(results=[result(0, BER)])))
    tp(c, True, ses_dt(fully(pdvl(9, 'single', AARQ))))
    tp(c, True, ses_td(tlv(0xa0, tlv(0xa0, ctx(9, ACSE, BER)))))
    c.close()
    for i, junk in enumerate((b'\x30\x80', b'\xa0\x03\x01', SET(mode()) + b'\x00', b'\x31\x05\x01',
                              SEQ(tlv(0xa0, INT(1))) , b'', b'\x61\x03\x30\x01', b'\x61\x84\xff\xff\xff\xff')):
        c = new_assoc(40040 + i, bad)
        tp(c, True, ses(13, junk))
        tp(c, False, ses(14, junk))
        tp(c, True, ses_dt(junk))
        tp(c, False, ses_td(junk))
        tp(c, True, ses(25, junk))
        tp(c, False, ses(12, junk))
        c.close()
    # session with no PPDU
    c = new_assoc(40050, bad)
    tp(c, True, b'\x0d\x00')
    tp(c, True, ses_dt(b'\x01\x02'))
    c.close()

    # one pcapng with Ethernet and Exported PDU
    write_pcapng(os.path.join(OUT, 'pres-coverage.pcapng'), [(1, f) for f in frames] + cl)
    write_pcapng(os.path.join(OUT, 'pres-coverage-malformed.pcapng'), [(1, f) for f in bad])


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
