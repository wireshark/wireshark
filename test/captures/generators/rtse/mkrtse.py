#!/usr/bin/env python3
# Generates test/captures/rtse_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RTSE dissector
(packet-rtse.c, X.228 Reliable Transfer Service Element; generated from
epan/dissectors/asn1/rtse).

RTSE has no port of its own. It is reached through the OSI upper layers
(TPKT/COTP on TCP 102, session, presentation, ACSE) whenever the
presentation context carries one of the abstract syntaxes that P1 and DISP
register for RTSE (2.6.0.2.12 id-as-mta-rtse, ...), and directly from the
presentation dissector in X.410 mode:

  - RTORQ and RTOAC in the ACSE AARQ/AARE user information, with the open
    form (user data decoded by the P1 bind dissector, in all three ways
    T_open picks the dissector: from the abstract syntax of the
    presentation context, applicationProtocol 12 and applicationProtocol 1
    of an earlier RTORQ) and the recover form (SessionConnectionIdentifier
    with t61String and octetString references);
  - RTORJ in a rejecting AARE and in a presentation CPR (X.410 mode);
  - data transfer segments (DT SPDUs) reassembled at the major
    synchronisation point (MAP), including a transfer whose EXTERNAL has a
    direct reference and one with several segments;
  - RTTP, RTTR and RTAB as RTSE APDUs of typed data, expedited data and
    abort SPDUs;
  - an Exported PDU naming "rtse", which has no session data and is left
    alone.

Usage: mkrtse.py <output directory>
Writes rtse-coverage.pcapng and rtse-coverage-malformed.pcapng.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x400lib import (  # noqa: E402,
    aare, aarq, Assoc, BITS, cotp_cc, cotp_cr, cotp_dt, CTX_ACSE, external, fully_encoded, INT,
    OCTS, OID, OID_ACSE, Pcapng, pdv, pres_cp, pres_cpa, ros_invoke, SEQ, ses_ac, ses_cn,
    ses_param_userdata, SET, spdu, tlv, tpkt, user_info, UTCT,
)
from mkp1 import (AC_MTA_TRANSFER, AS_MTA_RTSE, CTX, mta_bind_arg, mta_bind_result,  # noqa: E402
                  message_apdu, report_apdu, ipm_content_ipm)

AS_MTSE = '2.6.0.2.7'           # id-as-mtse, registered for RTSE by P1 (no ROS)
BIND_ERR = INT(2)               # authentication-error


def t61(s, tag=0x14):
    return tlv(tag, s)


class R(Assoc):
    """An association on the OSI upper layers whose first abstract syntax is
    used by RTSE."""

    def ses_td(self, from_client, apdu, ctx=None):
        """RTSE APDU in a Typed Data SPDU (the Give Tokens before it is the
        way the session dissector finds a TD)."""
        self.c.send(from_client, tpkt(cotp_dt(
            b'\x01\x00' + spdu(33, b'') + fully_encoded(pdv(self.ctx if ctx is None else ctx, apdu)))))

    def ses_ex(self, from_client, apdu, ctx=None):
        self.c.send(from_client, tpkt(cotp_dt(
            b"\x01\x00" + spdu(5, b"") + fully_encoded(pdv(self.ctx if ctx is None else ctx, apdu)))))

    def segment(self, from_client, data):
        self.pdata(from_client, OCTS(data))

    def map(self, from_client, serial=b'1'):
        self.osi(from_client, spdu(41, bytes([42, 1]) + serial))

    def transfer(self, from_client, apdu, nseg=2, ctx=None, direct=None, serial=b'1'):
        """An RTSE transfer: an EXTERNAL holding the ROS invoke of the APDU
        in nseg data transfer segments, then a major synchronisation point."""
        inner = apdu if direct == AS_MTSE else ros_invoke(1, 1, apdu)
        if direct is not None:
            ext = tlv(0x28, OID(direct), tlv(0xa0, inner))
        else:
            ext = external(self.ctx if ctx is None else ctx, inner)
        n = max(1, len(ext) // nseg + 1)
        for i in range(0, len(ext), n):
            self.segment(from_client, ext[i:i + n])
        self.map(from_client, serial)


def rtorq_body(open_data=None, recover=None, checkpoint=None, window=None, dialogue=None, proto=None):
    """The content of an RTORQapdu SET with all its optional fields."""
    body = b''
    if checkpoint is not None:
        body += INT(checkpoint, 0x80)
    if window is not None:
        body += INT(window, 0x81)
    if dialogue is not None:
        body += INT(dialogue, 0x82)
    if recover is not None:
        body += tlv(0xa3, recover)
    else:
        body += tlv(0xa3, tlv(0xa0, open_data))
    if proto is not None:
        body += INT(proto, 0x84)
    return body


def rtorq_ex(*a, **kw):
    return tlv(0xb0, rtorq_body(*a, **kw))


def rtoac_body(open_data=None, recover=None, checkpoint=None, window=None):
    body = b''
    if checkpoint is not None:
        body += INT(checkpoint, 0x80)
    if window is not None:
        body += INT(window, 0x81)
    if recover is not None:
        body += tlv(0xa2, recover)
    else:
        body += tlv(0xa2, tlv(0xa0, open_data))
    return body


def rtoac_ex(*a, **kw):
    return tlv(0xb1, rtoac_body(*a, **kw))


def conn_id(ref, common=b'261101120000Z', additional=None, octets=False):
    """SessionConnectionIdentifier as the recover alternative [1]."""
    r = OCTS(ref) if octets else t61(ref)
    body = r + UTCT(common.decode())
    if additional is not None:
        body += tlv(0x80, additional)
    return tlv(0xa1, body)


def rtorj_body(reason=None, user=None):
    body = b''
    if reason is not None:
        body += INT(reason, 0x80)
    if user is not None:
        body += tlv(0xa1, user)
    return body


def rtorj(reason=None, user=None):
    return tlv(0xb2, rtorj_body(reason, user))


def rttp(priority=1):
    return INT(priority)


def rtab_body(reason=None, reflected=None, user=None):
    body = b''
    if reason is not None:
        body += INT(reason, 0x80)
    if reflected is not None:
        body += BITS(0, reflected, 0x81)
    if user is not None:
        body += tlv(0xa2, user)
    return body


def rtab(*a, **kw):
    return tlv(0xb6, rtab_body(*a, **kw))


def x410(mode, body):
    """CP/CPA PPDU of X.410 mode: mode selector and the RTSE APDU as [1]."""
    return SET(tlv(0xa0, INT(0, 0x80)), tlv(0xa1, body))


def bind_arg():
    return tlv(0xb0, mta_bind_arg(True))


def bind_res():
    return tlv(0xb1, mta_bind_result(True))


def frames():
    ipm = ipm_content_ipm()
    msg = message_apdu(ipm, 22, nrecip=1)
    F = []
    port = [46000]

    def new(app_ctx=AC_MTA_TRANSFER, syn=((CTX, AS_MTA_RTSE),)):
        port[0] += 1
        return R(F, port[0], app_ctx, list(syn))

    # ---- 1: the open form with every optional field; the user data is
    # decoded by the dissector of the presentation context's abstract
    # syntax (T_open default branch); applicationProtocol 12 follows
    r = new()
    r.open(user_info(CTX, rtorq_ex(bind_arg(), checkpoint=3, window=5, dialogue=1, proto=12)),
           user_info(CTX, rtoac_ex(mta_bind_result(True), checkpoint=3, window=5)))
    r.transfer(True, msg, nseg=3)
    r.transfer(False, report_apdu(ctype=22, content=ipm), nseg=1)
    # a second map with nothing to reassemble
    r.map(True, b'2')
    # the same through a direct reference to the abstract syntax (the OID
    # table of RTSE) in place of the presentation context
    r.transfer(True, msg, direct=AS_MTA_RTSE, serial=b'3')
    # an EXTERNAL with a direct reference to an OID no dissector registered
    # for RTSE: a warning, and the content as unknown BER (the fix of "RTSE:
    # Pass offset 0 to dissect_unknown_ber for an unknown OID")
    r.segment(True, tlv(0x28, OID('1.3.6.1.4.1.32473.9'), tlv(0xa0, SEQ(*[INT(i) for i in range(1, 21)]))))
    r.map(True, b'4')
    # RTTP and RTTR APDUs of typed and expedited data
    r.ses_td(True, rttp(1))
    r.ses_ex(False, rttp(0))
    r.ses_td(False, OCTS(external(CTX, ros_invoke(2, 1, msg))))
    r.ses_ex(True, OCTS(external(CTX, ros_invoke(3, 1, msg))))
    r.close()

    # ---- 2: the recover form; applicationProtocol 12 of the first
    # association selects the P1 dissector for the open data below
    r = new()
    r.open(user_info(CTX, rtorq_ex(recover=conn_id(b'ref-1', additional=b'more'))),
           user_info(CTX, rtoac_ex(recover=conn_id(b'ref-2', additional=None, octets=True), checkpoint=0)))
    r.close()
    r = new()
    r.open(user_info(CTX, rtorq_ex(recover=conn_id(b'\x01\x02\x03', octets=True), window=1)),
           user_info(CTX, rtoac_ex(recover=conn_id(b'r', additional=b'x'))))
    r.close()

    # ---- 3: applicationProtocol 12 and 1 of an earlier RTORQ pick the
    # dissector of T_open (and of the refuse data) by name; a later RTORQ
    # with applicationProtocol 0 resets it
    r = new()
    r.open(user_info(CTX, rtorq_ex(mta_bind_arg(True), proto=12)),
           user_info(CTX, rtoac_ex(mta_bind_result(True))))
    r.close()
    r = new()
    r.open(user_info(CTX, rtorq_ex(mta_bind_arg(True), proto=1)),
           user_info(CTX, rtoac_ex(mta_bind_result(True))))
    r.close()
    # RTORJ in a rejecting AARE: refuse reasons and user data (the bind
    # error); applicationProtocol 1 of the RTORQ before it
    for i, (reason, user) in enumerate(((0, BIND_ERR), (1, None), (2, BIND_ERR),
                                        (3, None), (None, BIND_ERR), (4, None), (1, tlv(0xb2, BIND_ERR)))):
        r = new()
        r.c.handshake()
        r.c.send(True, tpkt(cotp_cr()))
        r.c.send(False, tpkt(cotp_cc()))
        ctxs = [(CTX_ACSE, OID_ACSE), (CTX, AS_MTA_RTSE)]
        proto = (1, 12, 1, None, 12, None, 2)[i]
        r.osi(True, ses_cn(pres_cp(ctxs, fully_encoded(pdv(CTX_ACSE, aarq(
            AC_MTA_TRANSFER, user_info(CTX, rtorq_ex(mta_bind_arg(True), proto=proto))))))))
        rj = user_info(CTX, rtorj(reason, user))
        r.osi(False, ses_ac(pres_cpa(len(ctxs), fully_encoded(pdv(CTX_ACSE, aare(
            AC_MTA_TRANSFER, rj, result=1))))))
        r.c.close()
    # leave applicationProtocol 0 behind (the static value of the dissector)
    r = new()
    r.open(user_info(CTX, rtorq_ex(bind_arg(), proto=0)),
           user_info(CTX, rtoac_ex(bind_res())))

    # ---- 4: the id-as-mtse abstract syntax (P1 without ROS), by direct
    # reference in the EXTERNAL
    r.transfer(True, msg, direct=AS_MTSE, nseg=2, serial=b'4')
    r.close()

    # ---- 5: RTAB in typed data, expedited data and a session abort
    r = new()
    r.open(user_info(CTX, rtorq_ex(bind_arg())),
           user_info(CTX, rtoac_ex(bind_res())))
    r.ses_td(True, rtab(0, b'\x01'))
    r.ses_ex(False, rtab(1, b'\x80\x01'))
    r.ses_td(True, rtab(2))
    r.ses_ex(False, rtab(3, b'\x04'))
    r.ses_td(True, rtab(4, b'\x08'))
    r.ses_ex(False, rtab(5))
    r.ses_td(False, rtab(6))
    r.ses_ex(True, rtab(99))
    r.ses_td(True, rtab())
    r.close()

    # ---- 6: X.410 mode, where the presentation dissector calls the RTSE
    # dissectors of RTORQ (CP), RTOAC (CPA), RTORJ (CPR) and RTAB (ARU)
    # itself, and the open data has no presentation context
    for i in range(3):
        r = new()
        r.c.handshake()
        r.c.send(True, tpkt(cotp_cr()))
        r.c.send(False, tpkt(cotp_cc()))
        r.osi(True, spdu(13, ses_param_userdata(x410(1, rtorq_body(mta_bind_arg(True), checkpoint=1, window=2,
                                                                    dialogue=i % 2, proto=i)))))
        if i == 0:
            r.osi(False, spdu(14, ses_param_userdata(x410(1, rtoac_body(mta_bind_result(True), window=3)))))
            r.osi(True, spdu(25, ses_param_userdata(SET(rtab_body(7, b'\x02', None)))))
        elif i == 1:
            r.osi(False, spdu(12, ses_param_userdata(SET(rtorj_body(2, BIND_ERR)))))
        else:
            r.osi(False, spdu(12, ses_param_userdata(SET(rtorj_body(1, BIND_ERR)))))
            r.osi(True, spdu(25, ses_param_userdata(SET(rtab_body(None, None, None)))))
        r.c.close()
    # applicationProtocol 0 again (the dissector keeps it between packets)
    r = new()
    r.c.handshake()
    r.c.send(True, tpkt(cotp_cr()))
    r.c.send(False, tpkt(cotp_cc()))
    r.osi(True, spdu(13, ses_param_userdata(x410(1, rtorq_body(mta_bind_arg(True), proto=0)))))
    r.c.close()
    return F, new


def exported(p, name):
    p.exp(name, tlv(0xb0, INT(0, 0x80)))


def main_pcapng():
    p = Pcapng()
    F, _ = frames()
    p.eth(F)
    # no session data from ACSE: RTSE leaves it alone
    exported(p, 'rtse')
    return p


def malformed_pcapng():
    p = Pcapng()
    ipm = ipm_content_ipm()
    msg = message_apdu(ipm, 22, nrecip=1)
    F = []
    port = [47000]

    def new():
        port[0] += 1
        return R(F, port[0], AC_MTA_TRANSFER, [(CTX, AS_MTA_RTSE)])

    r = new()
    r.open(user_info(CTX, rtorq_ex(bind_arg())),
           user_info(CTX, rtoac_ex(bind_res())))
    # an EXTERNAL whose indirect reference names no presentation context
    r.transfer(True, msg, ctx=9, serial=b'1')
    # unregistered direct reference with a second unknown OID
    ext = tlv(0x28, OID('1.3.6.1.4.1.32473.10'), tlv(0xa0, SEQ(INT(1), SEQ(INT(2)))))
    r.segment(True, ext)
    r.map(True, b'2')
    # a data transfer SPDU whose user data is no OCTET STRING
    r.pdata(True, SEQ(INT(1)))
    r.map(True, b'3')
    # an RTSE APDU that is none of the six, in typed and expedited data
    r.ses_td(True, tlv(0xb9, INT(1)))
    # userdataAB is not implemented: its content is an unknown field
    r.ses_td(True, rtab(4, None, tlv(0x04, b'')))
    r.ses_ex(False, b'\x30\x00')
    # truncated RTSE APDUs
    r.ses_td(True, tlv(0xb0, INT(0, 0x80))[:3])
    r.ses_ex(True, tlv(0xb6, INT(0, 0x80), INT(0, 0x81))[:4])
    # a transfer whose reassembled data is not an EXTERNAL
    r.segment(True, b'\x01\x02\x03')
    r.map(True, b'4')
    r.close()
    # the RTORQ of an earlier association is inherited: bind with garbage
    r = new()
    r.open(user_info(CTX, rtorq_ex(b'\x00\x01')),
           user_info(CTX, rtoac_ex(b'\x30\x80')))
    r.close()
    p.eth(F)
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_pcapng().write(os.path.join(out, 'rtse-coverage.pcapng'))
    malformed_pcapng().write(os.path.join(out, 'rtse-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
