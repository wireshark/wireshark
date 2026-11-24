# Helper module for the dap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for mkdap.py: BER encoding, Ethernet/IPv4/TCP with
sequence tracking, and the OSI upper layers (TPKT, COTP, session,
presentation, ACSE). Everything is built with struct."""

import struct


# ---------------------------------------------------------------- BER

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, *vals):
    val = b''.join(vals)
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + ber_len(len(val)) + val


def ber_int(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def oid_enc(s):
    p = [int(x) for x in s.split('.')]
    out = bytearray()
    for a in [p[0] * 40 + p[1]] + p[2:]:
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(enc)
    return bytes(out)


def INT(v, tag=0x02):
    return tlv(tag, ber_int(v))


def ENUM(v, tag=0x0a):
    return tlv(tag, ber_int(v))


def OID(s, tag=0x06):
    return tlv(tag, oid_enc(s))


def NULL(tag=0x05):
    return tlv(tag, b'')


def BOOL(v, tag=0x01):
    return tlv(tag, b'\xff' if v else b'\x00')


def OCTS(b, tag=0x04):
    return tlv(tag, b)


def PSTR(s, tag=0x13):          # PrintableString
    return tlv(tag, s.encode())


def UTF8(s, tag=0x0c):
    return tlv(tag, s.encode())


def UTCT(s='261101120000Z', tag=0x17):
    return tlv(tag, s.encode())


def GENT(s='20261101120000Z', tag=0x18):
    return tlv(tag, s.encode())


def BITS(unused, data, tag=0x03):
    return tlv(tag, bytes([unused]) + data)


def SEQ(*items, tag=0x30):
    return tlv(tag, *items)


def SET(*items, tag=0x31):
    return tlv(tag, *items)


def X(n, *items):
    """Explicit context tag [n], constructed."""
    assert n < 31
    return tlv(0xa0 | n, *items)


def EXTERNAL(oid, value, tag=0x28):
    """EXTERNAL with direct-reference and single-ASN1-type [0]."""
    return tlv(tag, OID(oid), tlv(0xa0, value))


# ------------------------------------------------- Ethernet / IPv4 / TCP

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


class Conn:
    """A TCP connection between a client and a server, with sequence
    numbers kept for both directions."""

    def __init__(self, cap, cport, sport, cip=(192, 0, 2, 1), sip=(192, 0, 2, 2)):
        self.cap = cap
        self.c = (bytes(cip), cport, bytes.fromhex('020000000001'))
        self.s = (bytes(sip), sport, bytes.fromhex('020000000002'))
        self.seq = {True: 1000, False: 5000}

    def _pkt(self, from_client, flags, payload):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''     # MSS on SYN
        tcp = struct.pack('!HHIIBBHHH', a[1], b[1], seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = a[0] + b[0] + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, a[0], b[0])
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.seq[from_client] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.cap.append(b[2] + a[2] + b'\x08\x00' + ip + tcp)

    def handshake(self):
        self._pkt(True, 0x02, b'')
        self._pkt(False, 0x12, b'')
        self._pkt(True, 0x10, b'')

    def send(self, from_client, payload):
        self._pkt(from_client, 0x18, payload)

    def close(self):
        self._pkt(True, 0x11, b'')
        self._pkt(False, 0x11, b'')
        self._pkt(True, 0x10, b'')


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


# ------------------------------------------------- OSI upper layers

OID_ACSE = '2.2.1.0.1'
OID_BER = '2.1.1'
CTX_ACSE = 1


def tpkt(payload):
    return struct.pack('>BBH', 3, 0, len(payload) + 4) + payload


def cotp_cr():
    # CR: dst-ref 0, src-ref 1, class 0, TPDU size 2048 (0x0b)
    body = b'\xe0\x00\x00\x00\x01\x00' + b'\xc0\x01\x0b'
    return bytes([len(body)]) + body


def cotp_cc():
    body = b'\xd0\x00\x01\x00\x02\x00' + b'\xc0\x01\x0b'
    return bytes([len(body)]) + body


def cotp_dt(data, eot=True):
    return b'\x02\xf0' + bytes([0x80 if eot else 0x00]) + data


def ses_param_userdata(data):
    if len(data) < 255:
        return bytes([193, len(data)]) + data
    return bytes([194, 0xff]) + struct.pack('>H', len(data)) + data


def spdu(si, params):
    if len(params) < 255:
        return bytes([si, len(params)]) + params
    return bytes([si, 0xff]) + struct.pack('>H', len(params)) + params


def ctx_item(ctx, oid):
    return SEQ(INT(ctx), OID(oid), SEQ(OID(OID_BER)))


def pdv(ctx, value):
    return SEQ(INT(ctx), tlv(0xa0, value))


def fully_encoded(*pdvs):
    return tlv(0x61, *pdvs)


def pres_cp(contexts, user_data):
    items = b''.join(ctx_item(c, o) for c, o in contexts)
    nmp = (OCTS(b'\x00\x01', 0x81) + OCTS(b'\x00\x02', 0x82)
           + tlv(0xa4, items) + user_data)
    return SET(tlv(0xa0, INT(1, 0x80)), tlv(0xa2, nmp))


def pres_cpa(n, user_data):
    res = SEQ(INT(0, 0x80), OID(OID_BER, 0x81))
    nmp = OCTS(b'\x00\x02', 0x83) + tlv(0xa5, res * n) + user_data
    return SET(tlv(0xa0, INT(1, 0x80)), tlv(0xa2, nmp))


def ses_cn(pres):
    return spdu(13, ses_param_userdata(pres))


def ses_ac(pres):
    return spdu(14, ses_param_userdata(pres))


def ses_fn(pres):
    return spdu(9, ses_param_userdata(pres))


def ses_dn(pres):
    return spdu(10, ses_param_userdata(pres))


def ses_dt(pres):
    # Give Tokens (empty) + Data Transfer (empty params) + user information
    return b'\x01\x00\x01\x00' + pres


def aarq(app_ctx, user=b''):
    return tlv(0x60, BITS(7, b'\x80', 0x80), tlv(0xa1, OID(app_ctx)), user)


def aare(app_ctx, user=b'', result=0):
    return tlv(0x61, BITS(7, b'\x80', 0x80), tlv(0xa1, OID(app_ctx)),
               tlv(0xa2, INT(result)), tlv(0xa3, tlv(0xa1, INT(0))), user)


def rlrq():
    return tlv(0x62, INT(0, 0x80))


def rlre():
    return tlv(0x63, INT(0, 0x80))


# ------------------------------------------------------------ ROS (IMPLICIT)

def ros_invoke(iid, opcode, arg=None, linked=None):
    body = INT(iid)
    if linked is not None:
        body += INT(linked, 0x80)
    body += INT(opcode)
    if arg is not None:
        body += arg
    return tlv(0xa1, body)


def ros_result(iid, opcode=None, result=None):
    body = INT(iid)
    if opcode is not None:
        body += SEQ(INT(opcode), result if result is not None else b'')
    return tlv(0xa2, body)


def ros_error(iid, code, param=None):
    return tlv(0xa3, INT(iid), INT(code), param if param is not None else b'')


def ros_reject(iid, ptag, problem):
    return tlv(0xa4, INT(iid), INT(problem, 0x80 | ptag))
