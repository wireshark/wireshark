#!/usr/bin/env python3
# ANSI IS-637 coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ANSI IS-637 (TIA/EIA-637, 3GPP2 C.S0015) SMS.

All frames are Exported PDUs (linktype 252) so that the different ways the
IS-637 dissectors are reached can share one file:

  - "ip": IPv4/UDP/SIP MESSAGE with an application/vnd.3gpp2.sms body
    (3GPP2 X.S0048 SMS over IMS), carrying the transport layer
  - "ansi_tcap": ANSI-41 MAP SMSDeliveryPointToPoint with
    SMS_TeleserviceIdentifier and SMS_BearerData, carrying the
    teleservice layer (ansi_map.tele_id table)
  - "ansi_a_bsmap" / "ansi_a_dtap": IOS ADDS Page / ADDS Deliver with an
    SMS ADDS User Part, carrying the transport layer (ansi_a.sms table)
  - "ansi_637_trans" / "ansi_637_tele" by name and the "ansi_637.tele_id"
    table with a value (tags 14 and 32), for the reproducers of the bugs
    fixed in "ANSI IS-637: Do not assert on User Data longer than its text"

Usage: mkansi_637.py [<output directory>]

Writes ansi_637-coverage.pcap and ansi_637-coverage-malformed.pcap. Every
packet is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, ipv4, udp, write_pcap  # noqa: E402

# ---------------------------------------------------------------------------
# Exported PDU


def exp_tag(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(payload, name=None, table=None, value=None):
    hdr = b''
    if name is not None:
        hdr += exp_tag(12, name.encode())
    if table is not None:
        hdr += exp_tag(14, table.encode())
        hdr += exp_tag(32, struct.pack('>I', value))
    return hdr + exp_tag(0, b'') + payload


# ---------------------------------------------------------------------------
# IPv4 / UDP / SIP

def ipv4_udp(src, dst, sport, dport, payload, ident=0):
    return ipv4(udp(payload, sport, dport), 17, src=bytes(src), dst=bytes(dst),
                ident=ident & 0xffff, flags_frag=0x4000)


UE = (192, 0, 2, 10)        # mobile station's IMS client
SMSC = (192, 0, 2, 20)      # IP-SM-GW / message center
sip_seq = [0]


def sip_message(trans_pdu, mo=True):
    """SIP MESSAGE carrying one IS-637 transport layer message."""
    sip_seq[0] += 1
    n = sip_seq[0]
    ms, mc = 'sip:+15551230001@ims.example.net', 'sip:smsc@ims.example.net'
    src, dst = (UE, SMSC) if mo else (SMSC, UE)
    frm, to = (ms, mc) if mo else (mc, ms)
    hdr = ('MESSAGE %s SIP/2.0\r\n'
           'Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK637-%04d\r\n'
           'Max-Forwards: 70\r\n'
           'From: <%s>;tag=637-%04d\r\n'
           'To: <%s>\r\n'
           'Call-ID: is637-%04d@ims.example.net\r\n'
           'CSeq: %d MESSAGE\r\n'
           'Content-Type: application/vnd.3gpp2.sms\r\n'
           'Content-Length: %d\r\n\r\n') % (
        to, '.'.join(map(str, src)), n, frm, n, to, n, n, len(trans_pdu))
    return exp_pdu(ipv4_udp(src, dst, 5060, 5060, hdr.encode() + trans_pdu, n), name='ip')


# ---------------------------------------------------------------------------
# ANSI TCAP / ANSI-41 MAP (BER)


def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def ber_tag(cls, cons, num):
    first = (cls << 6) | (0x20 if cons else 0)
    if num < 31:
        return bytes([first | num])
    out = [num & 0x7f]
    num >>= 7
    while num:
        out.append(0x80 | (num & 0x7f))
        num >>= 7
    return bytes([first | 0x1f]) + bytes(reversed(out))


CTX, PRI = 2, 3


def ber(cls, cons, num, content):
    return ber_tag(cls, cons, num) + blen(len(content)) + content


def tcap_invoke(inv_id, opcode, params):
    body = ber(PRI, 0, 15, bytes([inv_id]))
    body += ber(PRI, 0, 17, struct.pack('>H', 0x0900 | opcode))
    body += ber(PRI, 1, 18, params)
    return ber(PRI, 1, 9, body)


def tcap_package(ptype, tid, comps):
    body = ber(PRI, 0, 7, tid) + ber(PRI, 1, 8, b''.join(comps))
    return ber(PRI, 1, ptype, body)


map_tid = [0x63700000]


def ansi_map_smdpp(tele_id, bearer):
    """SMSDeliveryPointToPoint (op 53) Invoke in a Query With Permission."""
    map_tid[0] += 1
    params = ber(CTX, 0, 116, struct.pack('>H', tele_id)) + ber(CTX, 0, 105, bearer)
    pkg = tcap_package(2, struct.pack('>I', map_tid[0]), [tcap_invoke(1, 53, params)])
    return exp_pdu(pkg, name='ansi_tcap')


# ---------------------------------------------------------------------------
# IOS A interface (ADDS)


def ansi_a_adds_page(trans_pdu):
    # Mobile Identity: IMSI 310150123456789 (odd), ADDS User Part burst type SMS
    mid = bytes([0x0d, 0x08, 0x3e, 0x01, 0x51, 0x10, 0x32, 0x54, 0x76, 0x98])
    aup = bytes([0x3d, len(trans_pdu) + 1, 0x03]) + trans_pdu
    return exp_pdu(bytes([0x65]) + mid + aup, name='ansi_a_bsmap')


def ansi_a_adds_deliver(trans_pdu):
    # DTAP: protocol discriminator 3,
    # reserved octet, message type 0x53, ADDS User Part (LV)
    aup = bytes([len(trans_pdu) + 1, 0x03]) + trans_pdu
    return exp_pdu(bytes([0x03, 0x00, 0x53]) + aup, name='ansi_a_dtap')


# ---------------------------------------------------------------------------
# Bit packing


class Bits:
    def __init__(self):
        self.b = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.b.append((val >> i) & 1)
        return self

    def putbytes(self, data):
        for c in data:
            self.put(c, 8)
        return self

    def __len__(self):
        return len(self.b)

    def bytes(self):
        b = self.b + [0] * ((-len(self.b)) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def gsm_pack(septets, fill=0):
    """GSM 03.38 packing (LSB first), optionally after 'fill' fill bits."""
    out = []
    acc = 0
    nbits = fill
    for s in septets:
        acc |= (s & 0x7f) << nbits
        nbits += 7
        while nbits >= 8:
            out.append(acc & 0xff)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xff)
    return bytes(out)


GSM_BASIC = ('@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?'
             '¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà')


def gsm_septets(text):
    return [GSM_BASIC.index(c) for c in text]


def sub(pid, data):
    assert len(data) < 256
    return bytes([pid, len(data)]) + data


# ---------------------------------------------------------------------------
# Transport layer parameters

DTMF = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
        '0': 10, '*': 11, '#': 12, '?': 0}


def t_tele_id(v):
    return sub(0x00, struct.pack('>H', v))


def t_srvc_cat(v):
    return sub(0x01, struct.pack('>H', v))


def addr_dtmf(digits, number_mode=0):
    b = Bits().put(0, 1).put(number_mode, 1).put(len(digits), 8)
    for d in digits:
        b.put(DTMF[d], 4)
    return b.bytes()


def addr_ascii(text, ton=1, plan=1):
    b = Bits().put(1, 1).put(0, 1).put(ton, 3).put(plan, 4).put(len(text), 8)
    b.putbytes(text.encode('latin-1'))
    b.put(0, 7)
    return b.bytes()


def addr_data(data, ton):
    b = Bits().put(1, 1).put(1, 1).put(ton, 3).put(len(data), 8).putbytes(data).put(0, 3)
    return b.bytes()


def subaddr(data, stype=0, odd=0):
    return Bits().put(stype, 3).put(odd, 1).put(len(data), 8).putbytes(data).put(0, 4).bytes()


def t_orig_addr(a):
    return sub(0x02, a)


def t_orig_subaddr(a):
    return sub(0x03, a)


def t_dest_addr(a):
    return sub(0x04, a)


def t_dest_subaddr(a):
    return sub(0x05, a)


def t_bearer_reply(seq):
    return sub(0x06, bytes([seq << 2]))


def t_cause(seq, eclass, code=None):
    return sub(0x07, bytes([(seq << 2) | eclass]) + (b'' if code is None else bytes([code])))


def t_bearer(tele):
    return sub(0x08, tele)


def trans_p2p(*params):
    return b'\x00' + b''.join(params)


def trans_bcast(*params):
    return b'\x01' + b''.join(params)


def trans_ack(*params):
    return b'\x02' + b''.join(params)


# ---------------------------------------------------------------------------
# Teleservice layer subparameters

ENC_OCTET, ENC_EPM, ENC_ASCII7, ENC_IA5, ENC_UCS2, ENC_SJIS, ENC_KOREAN, \
    ENC_HEBREW, ENC_LATIN, ENC_GSM7, ENC_GSMDCS = range(11)
ENC_KSC5601 = 0x10
BITLEN = {ENC_OCTET: 8, ENC_SJIS: 8, ENC_KOREAN: 8, ENC_HEBREW: 8, ENC_LATIN: 8,
          ENC_KSC5601: 8, ENC_UCS2: 16, ENC_GSM7: 7}


def bitlen(enc):
    return BITLEN.get(enc, 7)


def put_chars(b, enc, chars):
    """Append characters MSB first. 'chars' are code values or a str."""
    n = bitlen(enc)
    for c in chars:
        b.put(ord(c) if isinstance(c, str) else c, n)


def encode_text(enc, text):
    if enc == ENC_UCS2:
        return [ord(c) for c in text]
    if enc == ENC_HEBREW:
        return list(text.encode('iso-8859-8'))
    if enc == ENC_LATIN:
        return list(text.encode('latin-1'))
    if enc == ENC_KSC5601 or enc == ENC_KOREAN:
        return list(text.encode('euc-kr'))
    if enc == ENC_SJIS:
        return list(text.encode('shift_jis'))
    if isinstance(text, bytes):
        return list(text)
    return [ord(c) for c in text]


def s_msg_id(mtype, mid, hdr=0):
    return sub(0x00, struct.pack('>I', (mtype << 20) | (mid << 4) | (hdr << 3))[1:])


def s_user_data(enc, text, msg_type=None):
    """User Data without a header, text MSB first (GSM 7-bit packed LSB first)."""
    b = Bits().put(enc, 5)
    if enc == ENC_EPM:
        b.put(msg_type, 8)
    if enc == ENC_GSM7:
        sept = gsm_septets(text)
        b.put(len(sept), 8).putbytes(gsm_pack(sept))
    else:
        chars = encode_text(enc, text)
        b.put(len(chars), 8)
        put_chars(b, enc, chars)
    return sub(0x01, b.bytes())


def udh_concat(ref, total, seq):
    return bytes([0x00, 0x03, ref, total, seq])


def s_user_data_udh(enc, ies, text):
    """User Data with a User Data Header (Header Indicator set in Message Identifier)."""
    udhl = len(ies)
    udh = bytes([udhl]) + ies
    b = Bits().put(enc, 5)
    n = bitlen(enc)
    if n == 7:
        fill = 6 - (udhl % 7)
        if enc == ENC_GSM7:
            sept = gsm_septets(text)
            hdr_sept = ((udhl + 1) * 8 + fill) // 7
            b.put(hdr_sept + len(sept), 8)
            # UDH, then the septets packed after 'fill' fill bits (as in GSM)
            b.putbytes(udh + gsm_pack(sept, fill))
        else:
            chars = encode_text(enc, text)
            hdr_sept = ((udhl + 1) * 8 + fill) // 7
            b.put(hdr_sept + len(chars), 8).putbytes(udh).put(0, fill)
            put_chars(b, enc, chars)
    else:
        chars = encode_text(enc, text)
        units = (udhl + 1) * 8 // n
        assert units * n == (udhl + 1) * 8
        b.put(units + len(chars), 8).putbytes(udh)
        put_chars(b, enc, chars)
    return sub(0x01, b.bytes())


def s_rsp_code(v):
    return sub(0x02, bytes([v]))


def bcd(v):
    return ((v // 10) << 4) | (v % 10)


def ts(y, mo, d, h, mi, s):
    return bytes([bcd(y % 100), bcd(mo), bcd(d), bcd(h), bcd(mi), bcd(s)])


def s_mc_ts(*t):
    return sub(0x03, ts(*t))


def s_valid_abs(*t):
    return sub(0x04, ts(*t))


def s_valid_rel(v):
    return sub(0x05, bytes([v]))


def s_defer_abs(*t):
    return sub(0x06, ts(*t))


def s_defer_rel(v):
    return sub(0x07, bytes([v]))


def s_priority(v):
    return sub(0x08, bytes([v << 6]))


def s_privacy(v):
    return sub(0x09, bytes([v << 6]))


def s_reply_opt(user_ack, dak, read_ack, report):
    return sub(0x0a, bytes([(user_ack << 7) | (dak << 6) | (read_ack << 5) | (report << 4)]))


def s_num_msgs(n):
    return sub(0x0b, bytes([bcd(n)]))


def s_alert(v):
    return sub(0x0c, bytes([v << 6]))


def s_lang(v):
    return sub(0x0d, bytes([v]))


def s_cb_ascii(text, ton=1, plan=1):
    return sub(0x0e, bytes([0x80 | (ton << 4) | plan, len(text)]) + text.encode())


def s_cb_dtmf(digits):
    b = Bits().put(0, 1).put(len(digits), 8)
    for d in digits:
        b.put(DTMF[d], 4)
    return sub(0x0e, b.bytes())


def s_disp_mode(v):
    return sub(0x0f, bytes([v << 6]))


def mult_enc_records(records):
    """records: list of (encoding, text or code list); returns the Bits."""
    b = Bits()
    for enc, text in records:
        chars = text if isinstance(text, list) else encode_text(enc, text)
        b.put(enc, 5).put(len(chars), 8)
        if enc == ENC_GSM7:
            b.putbytes(gsm_pack(chars))
        else:
            put_chars(b, enc, chars)
    return b


def s_deposit_idx(v):
    return sub(0x11, struct.pack('>H', v))


def s_scpd(enc, records):
    """records: (op, category, language, max_msgs, alert, text)"""
    b = Bits().put(enc, 5)
    for op, cat, lang, maxm, alert, text in records:
        chars = text if isinstance(text, list) else encode_text(enc, text)
        b.put(op, 4).put(cat, 16).put(lang, 8).put(maxm, 8).put(alert, 4).put(len(chars), 8)
        if enc == ENC_GSM7:
            b.putbytes(gsm_pack(chars))
        else:
            put_chars(b, enc, chars)
    return sub(0x12, b.bytes())


def s_scpr(records):
    return sub(0x13, b''.join(struct.pack('>HB', c, r << 4) for c, r in records))


def s_msg_status(eclass, code):
    return sub(0x14, bytes([(eclass << 6) | code]))


def s_tp_fail(v):
    return sub(0x15, bytes([v]))


def cmas_user_data(cmas_octets):
    """TIA-1149 CMAS message in User Data: encoding 0, NUM_FIELDS, octets, 3 bits."""
    b = Bits().put(0, 5).put(len(cmas_octets), 8).putbytes(cmas_octets).put(0, 3)
    return sub(0x01, b.bytes())


def cmas_type0(enc, text):
    b = Bits().put(enc, 5)
    chars = text if isinstance(text, list) else encode_text(enc, text)
    if enc == ENC_GSM7:
        b.putbytes(gsm_pack(chars))
    else:
        put_chars(b, enc, chars)
    data = b.bytes()
    return bytes([0x00, len(data)]) + data


def cmas_type1(cat, resp, sev, urg, cert):
    return bytes([0x01, 4, cat, resp, (sev << 4) | urg, cert << 4])


def cmas_type2(ident, handling, y, mo, d, h, mi, s, lang):
    return bytes([0x02, 10]) + struct.pack('>HBBBBBBBB', ident, handling, y, mo, d, h, mi, s, lang)


# ---------------------------------------------------------------------------
# Cases dissected by name (each in an Exported PDU naming the dissector).

MSGID_SUBMIT0 = sub(0x00, b'\x20\x00\x00')


def repro_user_data(enc, nf, chars, bitlen_, total):
    b = Bits().put(enc, 5).put(nf, 8)
    for c in chars:
        b.put(c, bitlen_)
    return sub(0x01, b.bytes().ljust(total, b'\x00'))


def repro_p2p(tele, tele_id=4098):
    return b'\x00' + t_tele_id(tele_id) + t_bearer(tele)


def repro_bcast(tele):
    return b'\x01' + t_srvc_cat(1) + t_bearer(tele)


def reproducers():
    T, TE = 'ansi_637_trans', 'ansi_637_tele'
    clean, malformed = [], []
    # 1: GSM 7-bit, 1 character in 12 octets: 76 reserved bits (assertion)
    clean.append((T, repro_p2p(MSGID_SUBMIT0 + repro_user_data(9, 1, [0x41], 7, 12))))
    # 2: Latin, 1 character in 12 octets: 75 reserved bits (dissector bug)
    clean.append((T, repro_p2p(MSGID_SUBMIT0 + repro_user_data(8, 1, [0x41], 8, 12))))
    # 3: Latin, 20 characters in a 3 octet User Data followed by 8 Language
    #    Indicators, which used to be read as text
    b = Bits().put(8, 5).put(20, 8).put(ord('Q'), 8)
    clean.append((T, repro_p2p(MSGID_SUBMIT0 + sub(0x01, b.bytes()) + s_lang(1) * 8)))
    # 4: Multiple Encoding User Data, 7-bit ASCII "AB" then Latin "XYZ", whose
    #    text starts on an octet boundary and used to be read one octet late
    b = Bits().put(2, 5).put(2, 8).put(ord('A'), 7).put(ord('B'), 7)
    b.put(8, 5).put(3, 8).putbytes(b'XYZ')
    clean.append((T, repro_p2p(MSGID_SUBMIT0 + sub(0x10, b.bytes()) + s_lang(1))))
    # 5: Service Category Program Data, 7-bit ASCII
    b = Bits().put(2, 5).put(1, 4).put(1, 16).put(1, 8).put(5, 8).put(1, 4).put(2, 8)
    b.put(ord('A'), 7).put(ord('B'), 7)
    clean.append((T, repro_p2p(MSGID_SUBMIT0 + sub(0x12, b.bytes()))))
    # 6: Broadcast CMAS with type 0 records of length 0
    b = Bits().put(0, 5).put(8, 8).putbytes(bytes(8))
    clean.append((T, repro_bcast(MSGID_SUBMIT0 + sub(0x01, b.bytes()))))
    # 7: 262 octet teleservice message (the length was truncated to 6); it
    #    ends in a lone subparameter ID, so it throws at the end
    tele7 = sub(0x02, b'\x01') * 2 + sub(0x0d, b'\x05') * 85 + b'\x00'
    malformed.append((TE, tele7[:262]))
    # 8: 256 octet teleservice message (the length was truncated to 0)
    malformed.append((TE, (sub(0x02, b'\x01') * 86)[:256]))
    # Stale Broadcast teleservice ID: Latin "ABC" by name, a Broadcast
    # transport message, then the same teleservice message again, which
    # used to be decoded as CMAS
    ud = sub(0x01, bytes([0x40, 0x18, 0x41, 0x42, 0x43]))
    stale = [(TE, ud), (T, b'\x01' + t_srvc_cat(1)), (TE, ud)]
    return ([exp_pdu(p, name=n) for n, p in clean],
            [exp_pdu(p, name=n) for n, p in malformed],
            [exp_pdu(p, name=n) for n, p in stale])


# ---------------------------------------------------------------------------
# Main capture

MS_NUM = '5551230001'
MC_NUM = '5551230002'


def g_sip_basic():
    """SMS over IMS: MO Submit, MT Deliver, acknowledgements."""
    f = []
    # MO Submit with most optional subparameters
    tele = (s_msg_id(2, 1) + s_user_data(ENC_ASCII7, 'Hello from IS-637') +
            s_valid_rel(167) + s_defer_rel(170) + s_priority(2) + s_privacy(1) +
            s_reply_opt(1, 1, 1, 1) + s_alert(3) + s_lang(1) +
            s_cb_ascii('+15551230001', 1, 1) + s_disp_mode(1))
    f.append(sip_message(trans_p2p(t_tele_id(4098), t_dest_addr(addr_dtmf(MC_NUM)),
                                   t_bearer_reply(1), t_bearer(tele))))
    # MT Deliver: 8-bit ASCII originating address, NSAP subaddress (odd)
    tele = (s_msg_id(1, 2) + s_user_data(ENC_LATIN, 'Café crème à 8 h') +
            s_mc_ts(2026, 10, 27, 9, 30, 15) + s_valid_abs(1999, 12, 31, 23, 59, 59) +
            s_defer_abs(2026, 1, 1, 0, 0, 0) + s_num_msgs(3) + s_deposit_idx(0x1234) +
            s_priority(0) + s_privacy(0) + s_reply_opt(0, 0, 0, 0) + s_alert(0) +
            s_disp_mode(0) + s_lang(2) + s_cb_dtmf('5551230002'))
    f.append(sip_message(trans_p2p(t_tele_id(4098), t_orig_addr(addr_ascii('+15551230002', 1, 1)),
                                   t_orig_subaddr(subaddr(b'\x50\x12\x34', 0, 1)),
                                   t_bearer_reply(2), t_bearer(tele)), mo=False))
    # Acknowledge, no error: the error class ends the Cause Codes
    f.append(sip_message(trans_ack(t_dest_addr(addr_dtmf(MC_NUM)), t_cause(1, 0))))
    # Acknowledge, temporary error but no cause code
    f.append(sip_message(trans_ack(t_dest_addr(addr_dtmf(MC_NUM)), t_cause(2, 2)), mo=False))
    # Acknowledge, permanent error: Destination busy
    f.append(sip_message(trans_ack(t_dest_addr(addr_dtmf(MS_NUM)), t_cause(2, 3, 33)), mo=False))
    # Deliver with data network addresses and a user-specified subaddress
    tele = s_msg_id(1, 3) + s_user_data(ENC_ASCII7, 'Mail from the gateway')
    f.append(sip_message(trans_p2p(
        t_tele_id(4098), t_orig_addr(addr_data(b'alice@example.net', 2)),
        t_dest_addr(addr_data(bytes([192, 0, 2, 10]), 1)),
        t_dest_subaddr(subaddr(b'\x01\x02', 1, 0)), t_bearer(tele)), mo=False))
    # Deliver: unknown and reserved data network types, reserved subaddress type,
    # DTMF address with *, # and unassigned digits (odd count)
    tele = s_msg_id(1, 4) + s_user_data(ENC_ASCII7, 'Hi')
    f.append(sip_message(trans_p2p(
        t_tele_id(4098), t_orig_addr(addr_data(b'\x0a\x0b', 0)),
        t_dest_addr(addr_data(b'\x0c', 5)), t_orig_subaddr(subaddr(b'\x99', 3, 1)),
        t_dest_addr(addr_dtmf('*12#0?')), t_dest_addr(addr_dtmf('1234567')),
        t_orig_addr(addr_ascii('911', 2, 0)), t_bearer(tele)), mo=False))
    return f


CAUSE_CODES = (list(range(0, 7)) + list(range(32, 40)) + list(range(64, 68)) +
               list(range(96, 109)) + [7, 31, 40, 47, 48, 63, 68, 95, 109, 223, 224, 255])


def g_sip_causes():
    """Every cause code (and one from each reserved range), several per message."""
    f = []
    for i in range(0, len(CAUSE_CODES), 8):
        params = [t_cause((i // 8) + j, 3 if j % 2 else 2, c)
                  for j, c in enumerate(CAUSE_CODES[i:i + 8])]
        f.append(sip_message(trans_ack(t_dest_addr(addr_dtmf(MS_NUM)), *params), mo=False))
    return f


TELE_ID_SWEEP = (0, 1, 4102, 4103, 32513, 32514, 32515, 32520, 32584, 100, 4105,
                 5000, 32530, 50000, 40000)


def g_sip_teleservices():
    """Each registered teleservice with typical bearer data, then the
    unregistered teleservice IDs (bearer data not dissected)."""
    f = []
    # AMPS Extended Protocol Enhanced Services: IS-91 extended protocol message
    tele = s_msg_id(1, 10) + s_user_data(ENC_EPM, 'CALL 5551234', msg_type=0x82)
    f.append(sip_message(trans_p2p(t_tele_id(4096), t_bearer(tele)), mo=False))
    # Paging (CPT-95): call-back number only
    tele = s_msg_id(1, 11) + s_priority(3) + s_cb_dtmf('5551239')
    f.append(sip_message(trans_p2p(t_tele_id(4097), t_bearer(tele)), mo=False))
    # Voice Mail Notification
    tele = (s_msg_id(1, 12) + s_num_msgs(12) + s_priority(1) + s_cb_dtmf('*86') +
            s_user_data(ENC_IA5, 'New voicemail'))
    f.append(sip_message(trans_p2p(t_tele_id(4099), t_bearer(tele)), mo=False))
    # WAP: octet, unspecified (a WDP datagram)
    tele = s_msg_id(1, 13) + s_user_data(ENC_OCTET, bytes([0x00, 0x0b, 0x23, 0xf0, 0x01, 0x06, 0x01, 0xae]))
    f.append(sip_message(trans_p2p(t_tele_id(4100), t_bearer(tele)), mo=False))
    # WEMT: Latin with a concatenation header, fragment 1 of 2
    tele = s_msg_id(1, 14, hdr=1) + s_user_data_udh(ENC_LATIN, udh_concat(0x42, 2, 1), 'Enhanced part one')
    f.append(sip_message(trans_p2p(t_tele_id(4101), t_bearer(tele)), mo=False))
    # Teleservice IDs that are not registered, with bearer data that is not
    # dissected
    tele = s_msg_id(1, 15) + s_user_data(ENC_ASCII7, 'not decoded')
    for tid in TELE_ID_SWEEP:
        f.append(sip_message(trans_p2p(t_tele_id(tid), t_dest_addr(addr_dtmf(MS_NUM)),
                                       t_bearer(tele)), mo=False))
    # A message without Teleservice Identifier: the bearer data is not dissected
    f.append(sip_message(trans_p2p(t_dest_addr(addr_dtmf(MS_NUM)), t_bearer(tele)), mo=False))
    return f


def g_map_encodings():
    """ANSI-41 SMSDeliveryPointToPoint, one User Data encoding each."""
    f = []
    texts = [
        (ENC_OCTET, b'\x01\x02\x03\xfe'),
        (ENC_ASCII7, 'Hello'),                    # no reserved bits
        (ENC_ASCII7, 'Seven bit ASCII text'),
        (ENC_IA5, 'IA5 text @ 10:30'),
        (ENC_UCS2, 'Unicode Ω ☺'),
        (ENC_SJIS, 'こんにちは'),
        (ENC_KOREAN, '안녕하세요'),
        (ENC_HEBREW, 'שלום'),
        (ENC_LATIN, 'Größe 10 €'.replace('€', 'E')),
        (ENC_GSM7, 'GSM default alphabet'),       # 20 septets: 7 reserved bits
        (ENC_GSM7, 'GSM 7bit'),                   # 8 septets: 3 reserved bits
        (ENC_GSMDCS, 'GSM DCS'),
        (ENC_KSC5601, '한국어'),
        (0x11, 'reserved'),
    ]
    for i, (enc, text) in enumerate(texts):
        tele = s_msg_id(1, 0x100 + i) + s_user_data(enc, text) + s_mc_ts(2026, 10, 27, 10, i, 0)
        f.append(ansi_map_smdpp(4098, tele))
    return f


def g_map_udh():
    """User Data Headers: 7-bit ASCII with every fill bit case, GSM 7-bit,
    UCS2 and 8-bit."""
    f = []
    src_ind = bytes([0x07, 0x01, 0x01])
    port16 = bytes([0x05, 0x04, 0x0b, 0x84, 0x23, 0xf0])
    sim_sec = bytes([0x70, 0x00])
    concat16 = bytes([0x08, 0x04, 0x12, 0x34, 0x02, 0x01])
    port8 = bytes([0x04, 0x02, 0xf5, 0xf5])
    cases = [
        (ENC_ASCII7, udh_concat(0x10, 3, 1), 'first part'),    # UDHL 5: 1 fill bit
        (ENC_ASCII7, src_ind, 'source'),                      # UDHL 3: 3 fill bits
        (ENC_ASCII7, concat16, 'second part'),                # UDHL 6: no fill bits
        (ENC_ASCII7, port16 + src_ind, 'ported'),             # UDHL 9: 4 fill bits
        (ENC_ASCII7, sim_sec, 'secured'),                     # UDHL 2: 4 fill bits
        (ENC_ASCII7, port8, 'port 245'),                      # UDHL 4: 2 fill bits
        (ENC_GSM7, udh_concat(0x11, 2, 2), 'GSM part two'),
        (ENC_GSM7, concat16, 'GSM'),
        (ENC_UCS2, udh_concat(0x12, 2, 1), 'Unicode Ω part'),
        (ENC_LATIN, port8, 'Latin with port'),
        (ENC_OCTET, port16, '\x01\x02'),
    ]
    for i, (enc, ies, text) in enumerate(cases):
        tele = s_msg_id(1, 0x200 + i, hdr=1) + s_user_data_udh(enc, ies, text)
        f.append(ansi_map_smdpp(4101 if enc != ENC_ASCII7 else 4098, tele))
    return f


def g_map_misc():
    """Remaining subparameters and values, over ANSI-41 MAP."""
    f = []
    # Every message type (and an unassigned one), with the user response
    # code, message status (every class and code) and TP-Failure cause
    statuses = ([(0, c) for c in (0, 1, 2, 3, 4)] + [(1, 0)] +
                [(2, c) for c in (4, 5, 31, 6)] +
                [(3, c) for c in (4, 5, 6, 7, 8, 9, 10, 13, 31, 11)])
    for mtype in range(0, 10):
        tele = s_msg_id(mtype, 0x300 + mtype)
        if mtype in (4, 6, 8):
            for ec, code in statuses[(mtype // 2 - 2) * 7:(mtype // 2 - 2) * 7 + 7]:
                tele += s_msg_status(ec, code)
            tele += s_tp_fail(0xc0 + mtype)
        if mtype == 5:
            tele += s_rsp_code(7)
        if mtype == 3:
            tele += s_msg_id(3, 0x2ff)
        f.append(ansi_map_smdpp(4098, tele))
    # Relative validity and deferred delivery times: every range
    rel = [0, 143, 144, 167, 168, 196, 197, 244, 245, 246, 247, 248, 249, 255]
    tele = s_msg_id(1, 0x320) + b''.join(s_valid_rel(v) for v in rel[:7]) + \
        b''.join(s_defer_rel(v) for v in rel[7:])
    f.append(ansi_map_smdpp(4098, tele))
    # Timestamps with an invalid month, priorities, privacy, alert and display
    # modes, languages, call-back numbers with an even digit count and none
    tele = (s_msg_id(1, 0x321) + sub(0x03, bytes([0x95, 0x13, 0x01, 0x00, 0x00, 0x00])) +
            sub(0x04, bytes([0x26, 0x00, 0x31, 0x23, 0x59, 0x59])) +
            b''.join(s_priority(v) for v in (1, 3)) + b''.join(s_privacy(v) for v in (2, 3)) +
            b''.join(s_alert(v) for v in (1, 2)) + b''.join(s_disp_mode(v) for v in (2, 3)) +
            b''.join(s_lang(v) for v in (0, 3, 4, 5, 6, 7, 200)) +
            s_cb_dtmf('12') + s_cb_dtmf('') + s_cb_ascii('', 2, 2) + s_cb_ascii('411', 0, 0))
    f.append(ansi_map_smdpp(4098, tele))
    # Enhanced VMN and Enhanced VMN Ack have no dissector; empty ones
    tele = s_msg_id(1, 0x322) + sub(0x16, b'') + sub(0x17, b'') + s_num_msgs(99)
    f.append(ansi_map_smdpp(4099, tele))
    return f


def g_map_multienc():
    """Multiple Encoding User Data."""
    f = []
    sets = [
        # 7-bit ASCII "AB" puts the Latin text on an octet boundary
        [(ENC_ASCII7, 'AB'), (ENC_LATIN, 'XYZ')],
        [(ENC_ASCII7, 'Hi'), (ENC_UCS2, 'Ω'), (ENC_IA5, 'ia5'), (ENC_HEBREW, 'אב')],
        [(ENC_OCTET, b'\x00\xff'), (ENC_KSC5601, '한'), (ENC_SJIS, 'カ')],
        # GSM 7-bit last: 8 septets packed, then 3 reserved bits
        [(ENC_LATIN, 'Hej'), (ENC_GSM7, gsm_septets('GSM text'))],
        # GSM 7-bit last with 1 septet: 4 reserved bits
        [(ENC_LATIN, 'Hej'), (ENC_GSM7, gsm_septets('G'))],
        # GSM 7-bit last after 3 ASCII characters: 1 reserved bit
        [(ENC_ASCII7, 'abc'), (ENC_GSM7, gsm_septets('GSM text'))],
        # empty record
        [(ENC_ASCII7, ''), (ENC_LATIN, 'X')],
    ]
    for i, recs in enumerate(sets):
        b = mult_enc_records(recs)
        tele = s_msg_id(1, 0x400 + i) + sub(0x10, b.bytes())
        f.append(ansi_map_smdpp(4098, tele))
    return f


def g_map_scpt():
    """Service Category Programming (carried as CMT-95 so it is dissected),
    and Service Category Program Results."""
    f = []
    # 7-bit ASCII: a 5 character name puts the second name on an octet boundary
    tele = s_msg_id(1, 0x500) + s_scpd(ENC_ASCII7, [
        (1, 0x0006, 1, 10, 4, 'Alert'),
        (1, 0x0007, 1, 5, 8, 'Weather'),
        (0, 0x0020, 2, 0, 0, ''),
    ])
    f.append(ansi_map_smdpp(4098, tele))
    # One 5 character name: the subparameter ends on an octet boundary
    tele = s_msg_id(1, 0x508) + s_scpd(ENC_ASCII7, [(1, 0x0006, 1, 10, 4, 'Fires')])
    f.append(ansi_map_smdpp(4098, tele))
    tele = s_msg_id(1, 0x501) + s_scpd(ENC_LATIN, [
        (2, 0x0000, 0, 0, 11, 'Tout'),
        (1, 0x0010, 2, 3, 1, 'Météo'),
    ])
    f.append(ansi_map_smdpp(4098, tele))
    tele = s_msg_id(1, 0x502) + s_scpd(ENC_UCS2, [(1, 0x0003, 1, 1, 2, 'Ω News')])
    f.append(ansi_map_smdpp(4098, tele))
    # GSM 7-bit: 8 septets (3 reserved bits), then 1 septet (4 reserved bits)
    tele = s_msg_id(1, 0x503) + s_scpd(ENC_GSM7, [(1, 0x0004, 1, 2, 3, gsm_septets('Sports 1'))])
    f.append(ansi_map_smdpp(4098, tele))
    tele = s_msg_id(1, 0x504) + s_scpd(ENC_GSM7, [(1, 0x0005, 1, 2, 5, gsm_septets('S'))])
    f.append(ansi_map_smdpp(4098, tele))
    tele = s_msg_id(1, 0x505) + s_scpd(ENC_SJIS, [(1, 0x0008, 3, 2, 6, 'ニュース')])
    f.append(ansi_map_smdpp(4098, tele))
    tele = s_msg_id(1, 0x506) + s_scpd(ENC_IA5, [(1, 0x0009, 1, 2, 7, 'Lottery'),
                                                 (1, 0x000a, 1, 2, 9, 'Stocks'),
                                                 (1, 0x000b, 1, 2, 10, 'Traffic')])
    f.append(ansi_map_smdpp(4098, tele))
    # Results: every result code
    tele = s_msg_id(5, 0x507) + s_scpr([(0x0006 + i, i) for i in range(16)])
    f.append(ansi_map_smdpp(4098, tele))
    return f


def g_cmas():
    """Broadcast SMS: CMAS (TIA-1149) over SIP and ANSI-41 MAP."""
    f = []
    t1 = cmas_type1(2, 0, 0, 0, 0)
    t2 = cmas_type2(4370, 0, 26, 10, 27, 12, 0, 0, 1)

    def bcast(cat, cmas, extra=b''):
        tele = s_msg_id(1, 0x600 + len(f)) + cmas_user_data(bytes([0]) + cmas) + extra + s_priority(3)
        return sip_message(trans_bcast(t_srvc_cat(cat), t_bearer(tele)), mo=False)

    f.append(bcast(4096, cmas_type0(ENC_ASCII7, 'Presidential Alert: test') + t1 + t2))
    f.append(bcast(4097, cmas_type0(ENC_LATIN, 'Évacuez la zone') + cmas_type1(1, 1, 1, 1, 1) + t2))
    f.append(bcast(4098, cmas_type0(ENC_UCS2, 'Ω Severe') + cmas_type1(3, 2, 2, 2, 2)))
    f.append(bcast(4099, cmas_type0(ENC_IA5, 'AMBER Alert') + cmas_type1(4, 3, 0, 1, 0)))
    f.append(bcast(4100, cmas_type0(ENC_HEBREW, 'בדיקה') + cmas_type1(5, 4, 1, 0, 1)))
    f.append(bcast(4097, cmas_type0(ENC_OCTET, b'\x10\x20') + cmas_type1(6, 5, 0, 0, 0)))
    f.append(bcast(4097, cmas_type0(ENC_KSC5601, '경보') + cmas_type1(7, 6, 0, 0, 0)))
    f.append(bcast(4097, cmas_type0(ENC_GSM7, gsm_septets('Flash flood now!')) + cmas_type1(8, 7, 0, 0, 0)))
    f.append(bcast(4097, cmas_type0(ENC_SJIS, '地震') + cmas_type1(9, 8, 0, 0, 0)))
    # 7-bit text whose last septet is zero, so it is taken as reserved bits
    # (5 octets: 5 encoding bits and 5 septets), and one with no reserved bits
    f.append(bcast(4097, cmas_type0(ENC_ASCII7, 'Torn\x00') + cmas_type1(10, 0, 0, 0, 0)))
    f.append(bcast(4097, cmas_type0(ENC_ASCII7, 'CBRNE') + cmas_type1(11, 0, 0, 0, 0)))
    f.append(bcast(4097, cmas_type0(ENC_ASCII7, 'Other') + cmas_type1(12, 9, 3, 3, 3) +
                   cmas_type2(1, 0xff, 95, 13, 31, 23, 59, 59, 7)))
    # Empty alert text (type 0 record with only the encoding)
    f.append(bcast(4097, bytes([0x00, 0x01, ENC_LATIN << 3]) + t1))
    # Type 0 not first, expiry in the last century
    f.append(bcast(4098, t1 + cmas_type0(ENC_ASCII7, 'Shelter') + cmas_type2(2, 1, 99, 1, 1, 0, 0, 0, 2)))
    # Non-CMAS broadcast: the User Data of every Broadcast message is taken
    # as CMAS, so a 7-bit ASCII one is an unknown encoding
    tele = s_msg_id(1, 0x6ff) + s_user_data(ENC_ASCII7, 'Local weather: sunny') + s_lang(1)
    f.append(sip_message(trans_bcast(t_srvc_cat(6), t_bearer(tele)), mo=False))
    # A service category just past the CMAS range
    f.append(sip_message(trans_bcast(t_srvc_cat(4101), t_bearer(tele)), mo=False))
    # User Data as the last subparameter, so the 3 reserved bits after the
    # CMAS message are in the last octet of the message: no type 0 record
    # (this used to throw), type 0 after a type 1 record (this used to
    # throw) and type 0 first (marked the wrong octet)
    for i, cmas in enumerate((t1 + t2, t1 + cmas_type0(ENC_ASCII7, 'Last record'),
                              cmas_type0(ENC_LATIN, 'First record') + t1)):
        ud_last = s_msg_id(1, 0x680 + i) + cmas_user_data(bytes([0]) + cmas)
        f.append(sip_message(trans_bcast(t_srvc_cat(4097), t_bearer(ud_last)), mo=False))
    return f


def g_ansi_a():
    """IOS A interface: ADDS Page and ADDS Deliver with SMS."""
    tele = s_msg_id(1, 0x700) + s_user_data(ENC_ASCII7, 'Via the A interface') + s_lang(1)
    return [ansi_a_adds_page(trans_p2p(t_tele_id(4098), t_orig_addr(addr_dtmf(MC_NUM)), t_bearer(tele))),
            ansi_a_adds_deliver(trans_p2p(t_tele_id(4098), t_orig_addr(addr_dtmf(MC_NUM)),
                                          t_bearer(s_msg_id(1, 0x701) + s_user_data(ENC_LATIN, 'DTAP')))),
            ansi_a_adds_deliver(trans_ack(t_dest_addr(addr_dtmf(MC_NUM)), t_cause(5, 0)))]


def g_long():
    """Messages over 255 octets (their lengths used to be truncated to 8 bits)."""
    f = []
    text = ('A long message that needs more than two hundred and fifty five octets '
            'of transport layer data, which is fine for SMS over IMS where the '
            'SIP body carries the whole transport message without the limit of '
            'the air interface. The end.')[:200]
    tele = s_msg_id(2, 0x800) + s_user_data(ENC_LATIN, text) + s_lang(1) + s_priority(1)
    f.append(sip_message(trans_p2p(t_tele_id(4098), t_dest_addr(addr_ascii('+15551230002')),
                                   t_dest_subaddr(subaddr(b'\x50\x01\x02\x03', 0, 0)),
                                   t_orig_addr(addr_data(b'long.sender@example.net', 2)),
                                   t_bearer(tele), t_bearer_reply(33))))
    # Teleservice layer of 520 octets over ANSI-41 MAP
    tele = (s_msg_id(1, 0x801) + s_user_data(ENC_LATIN, (text * 2)[:250]) +
            s_user_data(ENC_ASCII7, (text * 2)[:250]) + s_mc_ts(2026, 10, 27, 11, 0, 0) +
            s_disp_mode(2))
    f.append(ansi_map_smdpp(4098, tele))
    return f


def g_stale():
    """A Broadcast transport message followed by an ANSI-41 MAP teleservice
    message: the teleservice message is not CMAS."""
    cmas = bytes([0]) + cmas_type0(ENC_ASCII7, 'Test alert') + cmas_type1(2, 4, 1, 1, 1)
    tele = s_msg_id(1, 0x900) + cmas_user_data(cmas)
    return [sip_message(trans_bcast(t_srvc_cat(4100), t_bearer(tele)), mo=False),
            ansi_map_smdpp(4098, s_msg_id(1, 0x901) + s_user_data(ENC_LATIN, 'Not an alert'))]


def g_lengths():
    """Subparameters with the wrong length, unknown parameters, empty fields:
    note and warning expert infos only."""
    f = []
    # Fixed length teleservice subparameters one octet too long
    tele = s_msg_id(1, 0xa00)
    for pid, n in ((0x00, 3), (0x02, 1), (0x03, 6), (0x04, 6), (0x05, 1), (0x06, 6),
                   (0x07, 1), (0x08, 1), (0x09, 1), (0x0a, 1), (0x0b, 1), (0x0c, 1),
                   (0x0d, 1), (0x0f, 1), (0x11, 2), (0x14, 1), (0x15, 1)):
        tele += sub(pid, bytes(n + 1))
    f.append(ansi_map_smdpp(4098, tele))
    # Short subparameters; variable length fields that run past the subparameter
    tele = (s_msg_id(1, 0xa01) + sub(0x01, b'\x10') + sub(0x0e, b'\x80') +
            sub(0x0e, b'\x81\x05\x31\x32') + sub(0x0e, bytes([0x05, 0x00])) +
            sub(0x10, b'\x10') + sub(0x12, b'\x10') +
            sub(0x13, b'\x00\x06\x00\x00'))
    f.append(ansi_map_smdpp(4098, tele))
    # User Data: text longer than the subparameter, and the subparameter longer
    # than the text; the same for Multiple Encoding User Data and Service
    # Category Program Data
    b = Bits().put(ENC_LATIN, 5).put(10, 8).putbytes(b'short')
    ud_short = sub(0x01, b.bytes())
    b = Bits().put(ENC_ASCII7, 5).put(2, 8).put(ord('O'), 7).put(ord('K'), 7)
    ud_long = sub(0x01, b.bytes() + bytes(3))
    b = Bits().put(ENC_LATIN, 5).put(2, 8).putbytes(b'OK').put(ENC_LATIN, 5).put(9, 8).putbytes(b'XY')
    me_short = sub(0x10, b.bytes())
    b = Bits().put(ENC_LATIN, 5).put(1, 4).put(1, 16).put(1, 8).put(1, 8).put(1, 4).put(9, 8).putbytes(b'XY')
    scpd_short = sub(0x12, b.bytes())
    f.append(ansi_map_smdpp(4098, s_msg_id(1, 0xa02) + ud_short + ud_long + me_short + scpd_short))
    # Enhanced VMN subparameters with content (no dissector), then an
    # unknown subparameter which ends the message
    tele = s_msg_id(1, 0xa03) + sub(0x16, b'\x01\x02') + sub(0x17, b'\x03') + sub(0x30, b'\x00') + s_lang(1)
    f.append(ansi_map_smdpp(4099, tele))
    # Transport layer: wrong lengths, short addresses, empty addresses,
    # an empty parameter and an unknown parameter
    f.append(sip_message(trans_p2p(
        sub(0x00, b'\x10\x02\x00'), sub(0x01, b'\x01'), sub(0x02, b'\x00'),
        sub(0x02, b'\xc8\x40'), sub(0x04, b'\xc0\x00'), sub(0x02, Bits().put(1, 1).put(0, 1).put(1, 3).put(1, 4).put(5, 8).put(0x41, 8).bytes()),
        sub(0x04, b'\x88\x00\x00'), sub(0x02, b'\x05\x00'), sub(0x04, b'\x00\x00'),
        sub(0x03, b'\x00'), sub(0x03, b'\x00\xa0'), sub(0x05, b'\x00\x00'),
        sub(0x06, b''), sub(0x08, b''), t_tele_id(4098), sub(0x09, b'\x00\x00'),
        t_bearer_reply(1))))
    # Unknown transport layer message type
    f.append(sip_message(b'\x05' + t_dest_addr(addr_dtmf(MS_NUM)) + t_cause(1, 0)))
    # CMAS: unknown encoding, too short, an unknown record type, data left
    # after the last record, and type 0 records of length 0 between valid ones

    def bcast(ud):
        return sip_message(trans_bcast(t_srvc_cat(4097), t_bearer(s_msg_id(1, 0xa10) + ud + s_lang(1))), mo=False)
    f.append(bcast(sub(0x01, b'\x10\x00\x00')))
    f.append(bcast(sub(0x01, b'\x00')))
    f.append(bcast(cmas_user_data(bytes([0]) + cmas_type0(ENC_ASCII7, 'Alert') +
                                  bytes([0x07, 2, 0xaa, 0xbb]) + cmas_type1(2, 0, 0, 0, 0) + b'\x00\x00')))
    f.append(bcast(cmas_user_data(bytes([0]) + cmas_type0(ENC_ASCII7, 'Alert') + bytes([0x00, 0x00]) +
                                  cmas_type1(2, 0, 0, 0, 0))))
    return f


def malformed_frames():
    """Paths that end in an exception."""
    f = []
    # Truncated subparameters (length past the end of the message)
    f.append(ansi_map_smdpp(4098, s_msg_id(1, 0xb01) + b'\x01\x10\x10\x00'))
    f.append(ansi_map_smdpp(4098, s_msg_id(1, 0xb02) + b'\x00'))
    f.append(sip_message(b'\x00' + t_tele_id(4098) + b'\x08\x20\x00\x03'))
    f.append(sip_message(b'\x00' + t_tele_id(4098) + b'\x02'))
    # Cause Codes claiming a cause code past the end of the message
    f.append(sip_message(b'\x02\x07\x05\x07'))
    # Bearer Reply Option with length 1 at the end, truncated
    f.append(sip_message(b'\x00\x06\x01'))
    # User Data Header whose length runs past the User Data
    b = Bits().put(ENC_LATIN, 5).put(4, 8).putbytes(b'\x20\x00\x03\x01')
    f.append(ansi_map_smdpp(4098, s_msg_id(1, 0xb03, hdr=1) + sub(0x01, b.bytes())))
    # CMAS type 0 record longer than the CMAS message
    f.append(sip_message(trans_bcast(t_srvc_cat(4097), t_bearer(
        s_msg_id(1, 0xb04) + cmas_user_data(bytes([0, 0x00, 0x20, 0x10, 0x41, 0x42]))))))
    # CMAS type 1 / type 2 records cut short
    f.append(sip_message(trans_bcast(t_srvc_cat(4097), t_bearer(
        s_msg_id(1, 0xb05) + cmas_user_data(bytes([0, 0x02, 0x0a, 0x00, 0x01]))))))
    # An empty transport layer message (SIP does not hand an empty body over)
    f.append(exp_pdu(b'', name='ansi_637_trans'))
    return f


def frame_ts(i):
    return 1767225600 + i, 0


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean_repro, bad_repro, stale = reproducers()
    groups = [
        ('SIP MESSAGE: Submit, Deliver, Acknowledge, addresses', g_sip_basic()),
        ('SIP MESSAGE: Acknowledge with every cause code', g_sip_causes()),
        ('SIP MESSAGE: teleservice IDs', g_sip_teleservices()),
        ('ANSI-41 MAP: User Data encodings', g_map_encodings()),
        ('ANSI-41 MAP: User Data Headers', g_map_udh()),
        ('ANSI-41 MAP: message types and other subparameters', g_map_misc()),
        ('ANSI-41 MAP: Multiple Encoding User Data', g_map_multienc()),
        ('ANSI-41 MAP: Service Category Programming', g_map_scpt()),
        ('SIP MESSAGE: Broadcast, CMAS', g_cmas()),
        ('IOS A interface: ADDS Page / ADDS Deliver', g_ansi_a()),
        ('Messages over 255 octets', g_long()),
        ('Broadcast followed by a teleservice message', g_stale()),
        ('Reproducers (by name)', clean_repro),
        ('Stale Broadcast reproducer (by name)', stale),
        ('Wrong lengths, unknown parameters (notes and warnings)', g_lengths()),
    ]
    frames = []
    for title, g in groups:
        print('%4d-%-4d %s' % (len(frames) + 1, len(frames) + len(g), title))
        frames += g
    write_pcap(os.path.join(out, 'ansi_637-coverage.pcap'), frames,
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU, ts=frame_ts)
    bad = bad_repro + malformed_frames()
    print('malformed: %d frames' % len(bad))
    write_pcap(os.path.join(out, 'ansi_637-coverage-malformed.pcap'), bad,
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU, ts=frame_ts)


if __name__ == '__main__':
    main()
