# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for the X.500 coverage generators (DISP, DOP, DSP):
BER encoding, Ethernet/IPv4/TCP with sequence tracking, the OSI upper
layers (TPKT, COTP, session, presentation, ACSE), ROS, RTSE, IDMP and
X.501/X.511 types. Everything is built with struct. Mostly copied from
dap-coverage (osilib.py and mkdap.py)."""

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


OID_DAP_AS = '2.5.9.1'       # id-as-directory-access
OID_DAP_AC = '2.5.3.1'       # id-ac-directory-access
OID_DAP_IP = '2.5.33.0'      # IDMP dap-ip
CTX_DAP = 3

AT_OC = '2.5.4.0'            # objectClass (OBJECT IDENTIFIER)
AT_CN = '2.5.4.3'            # commonName (DirectoryString)
AT_SN = '2.5.4.4'            # surname
AT_C = '2.5.4.6'             # countryName (PrintableString)
AT_O = '2.5.4.10'            # organizationName
AT_OU = '2.5.4.11'           # organizationalUnitName
AT_TEL = '2.5.4.20'          # telephoneNumber
AT_GN = '2.5.4.42'           # givenName
AT_MEMBER = '2.5.4.31'       # member (DistinguishedName)
OC_PERSON = '2.5.6.6'
MR_CASEIGNORE = '2.5.13.2'
MR_NUMERIC = '2.5.13.8'
ALG_SHA256RSA = '1.2.840.113549.1.1.11'
ALG_ECPUB = '1.2.840.10045.2.1'
CURVE_P256 = '1.2.840.10045.3.1.7'


# ------------------------------------------------------- X.501 types

def rdn(*pairs):
    return SET(*[SEQ(OID(t), v) for t, v in pairs])


def dn(*rdns):
    """RDNSequence (also Name and DistinguishedName)."""
    return SEQ(*rdns)


R_C = rdn((AT_C, PSTR('AU')))
R_O = rdn((AT_O, UTF8('Example Org')))
R_OU = rdn((AT_OU, UTF8('People')))
R_CN = rdn((AT_CN, PSTR('Alice Smith')))
R_CN2 = rdn((AT_CN, PSTR('Bob Jones')))
# a multi-valued RDN
R_MULTI = rdn((AT_CN, PSTR('Carol')), (AT_SN, UTF8('Brown')))

DN_ORG = dn(R_C, R_O)
DN_ALICE = dn(R_C, R_O, R_OU, R_CN)
DN_BOB = dn(R_C, R_O, R_OU, R_CN2)
DN_ADMIN = dn(R_C, R_O, rdn((AT_CN, PSTR('admin'))))
DN_DSA = dn(R_C, R_O, rdn((AT_CN, PSTR('dsa-1'))))
DN_ROOT = dn()


def context(ctype=AT_CN, vals=(PSTR('en'),), fallback=None):
    """Context: no context syntax is registered, so the context type is
    an attribute type whose syntax is known."""
    body = OID(ctype) + SET(*vals)
    if fallback is not None:
        body += BOOL(fallback)
    return SEQ(body)


def ctx_assertion(ctype=AT_CN, vals=(PSTR('en'),)):
    return SEQ(OID(ctype), SET(*vals))


def attribute(t, *vals, with_ctx=False):
    body = OID(t) + SET(*vals)
    if with_ctx:
        body += SET(SEQ(vals[0], SET(context(fallback=True))))
    return SEQ(body)


def ava(t, v, asserted=None):
    body = OID(t) + v
    if asserted == 'all':
        body += X(0, NULL())
    elif asserted == 'selected':
        body += X(1, SET(ctx_assertion()))
    return SEQ(body)


def ata(t, with_ctx=True):
    """AttributeTypeAssertion."""
    body = OID(t)
    if with_ctx:
        body += SEQ(ctx_assertion())
    return SEQ(body)


def alg(oid=ALG_SHA256RSA, params=None):
    return SEQ(OID(oid), NULL() if params is None else params)


def certificate(serial=1):
    tbs = SEQ(X(0, INT(2)), INT(serial), alg(), DN_ORG,
              SEQ(UTCT('260101000000Z'), UTCT('361231235959Z')), DN_ALICE,
              SEQ(alg(ALG_ECPUB, OID(CURVE_P256)), BITS(0, b'\x04' + bytes(range(64)))))
    return SEQ(tbs, alg(), BITS(0, bytes(range(32))))


def cert_path():
    return SEQ(certificate())


def code_local(v):
    return INT(v)


def code_global(oid):
    return OID(oid)


def security_parameters(variant=0):
    """SecurityParameters; variant 0 has every field with a UTCTime and
    a local code, variant 1 a GeneralizedTime and a global code."""
    if variant == 0:
        return SET(X(0, cert_path()), X(1, DN_ALICE), X(2, UTCT()),
                   X(3, BITS(0, b'\x11\x22\x33\x44')), X(4, INT(1)),
                   X(5, BITS(0, b'\x55\x66')), X(6, code_local(1)),
                   X(8, INT(3)), X(9, code_local(2)))
    return SET(X(1, DN_BOB), X(2, GENT()), X(4, INT(2)),
               X(6, code_global('2.5.33.0')), X(8, INT(0)),
               X(9, code_global('2.5.33.0')))


def operation_progress(phase=2, nxt=1):
    body = X(0, ENUM(phase))
    if nxt is not None:
        body += X(1, INT(nxt))
    return SET(body)


def service_controls():
    return SET(X(0, BITS(2, b'\xff\xfc')),          # every option bit
               X(1, INT(2)), X(2, INT(30)), X(3, INT(100)), X(4, INT(1)),
               X(5, INT(4096)),
               X(6, SEQ(DN_DSA, SEQ(INT(7), INT(1)))),
               X(7, OID('2.5.9.1')), X(8, INT(3)))


def context_selection(selected=True, preference=True):
    if not selected:
        return NULL()
    if preference:
        ca = SEQ(ctx_assertion(), ctx_assertion(AT_CN, (PSTR('de'),)))
    else:
        ca = SET(ctx_assertion())
    return SET(SEQ(OID(AT_CN), ca))


def common_args(full=False, alt=False):
    if not full:
        return b''
    return (X(30, service_controls()) + X(29, security_parameters(1 if alt else 0))
            + X(28, DN_ADMIN) + X(27, operation_progress())
            + X(26, INT(1)) + X(25, BITS(5, b'\xe0')) + X(24, ENUM(2))
            + X(23, BOOL(False)) + X(22, SET(dn(R_C, R_O, R_OU)))
            + X(21, BOOL(True))
            + X(20, context_selection(True, alt))
            + X(19, ENUM(3 if alt else 2)))


def common_results(full=False, alt=False):
    if not full:
        return b''
    return (X(30, security_parameters(1 if alt else 0)) + X(29, DN_DSA)
            + X(28, BOOL(True))
            + X(27, SEQ(attribute(AT_CN, PSTR('notice')))))


def eis(variant=0):
    """EntryInformationSelection."""
    if variant == 0:
        return SET(X(1, SET(OID(AT_CN), OID(AT_SN))), X(2, INT(0)),
                   X(4, SET(OID(AT_OC))), context_selection(True, False),
                   BOOL(True),
                   SEQ(ENUM(3), SEQ(OID(OC_PERSON))))
    if variant == 1:
        return SET(X(0, NULL()), X(2, INT(1)), X(3, NULL()),
                   context_selection(False), BOOL(False), SEQ(ENUM(2)))
    return SET()


def entry_information(name=DN_ALICE, full=True):
    if not full:
        return SEQ(name)
    info = SET(OID(AT_TEL),
               attribute(AT_CN, PSTR('Alice Smith')),
               attribute(AT_OC, OID(OC_PERSON)))
    return SEQ(name, BOOL(False), info, X(3, BOOL(True)), X(4, BOOL(True)),
               X(5, BOOL(True)))


def presentation_address():
    return SEQ(X(0, OCTS(b'\x00\x01')), X(1, OCTS(b'\x00\x01')),
               X(2, OCTS(b'\x00\x01')), X(3, SET(OCTS(b'\x54\x00\x72\x87\x22\x03\xc0\x00\x02\x02'))))


def access_point_information():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(3, ENUM(1)),
               X(5, BOOL(True)))


def access_point():
    return SET(X(0, DN_DSA), X(1, presentation_address()))


def continuation_reference():
    return SET(X(0, DN_ALICE), X(1, INT(0)), X(2, operation_progress(3, None)),
               X(3, INT(2)), X(4, ENUM(2)), X(5, SET(access_point_information())),
               X(6, BOOL(True)), X(7, SET(dn(R_C))), X(8, BOOL(True)),
               X(9, BOOL(True)))


# ------------------------------------------------------- filters

def f_item(fi):
    return X(0, fi)


def f_and(*f):
    return X(1, SET(*f))


def f_or(*f):
    return X(2, SET(*f))


def f_not(f):
    return X(3, f)


def fi_equality(asserted='all'):
    return X(0, ava(AT_CN, PSTR('Alice'), asserted))


def fi_substrings(*strings):
    return X(1, SEQ(OID(AT_CN), SEQ(*strings)))


def fi_ge():
    return X(2, ava(AT_SN, UTF8('A')))


def fi_le():
    return X(3, ava(AT_SN, UTF8('M')))


def fi_present(t=AT_TEL):
    return X(4, OID(t))


def fi_approx():
    return X(5, ava(AT_GN, UTF8('Alys'), 'selected'))


def fi_extensible(match_value=False):
    # matchValue [3] is mandatory, but its body is not implemented
    body = X(1, SET(OID(MR_CASEIGNORE))) + X(2, OID(AT_CN)) + X(3, PSTR('alice'))
    body += X(4, BOOL(True))
    return X(6, SEQ(body))


def fi_context_present():
    return X(7, ata(AT_CN))


# the substrings item: the initial [0] value is shown as "not yet
# implemented"; any [1] and final [2] are skipped
SUBSTR_CLEAN = fi_substrings(X(0, PSTR('Al')), attribute(AT_CN, PSTR('control')))

FILTER_BIG = f_and(
    f_item(fi_equality('all')),
    f_or(f_item(SUBSTR_CLEAN), f_item(fi_ge()), f_item(fi_le())),
    f_not(f_item(fi_present())),
    f_item(fi_approx()),
    f_item(fi_extensible()),
    f_item(fi_context_present()))


def paged_new():
    return SEQ(INT(25), SEQ(SEQ(OID(AT_SN), OID(MR_CASEIGNORE)), SEQ(OID(AT_CN))),
               X(1, BOOL(True)), X(2, BOOL(True)))


def paged_ref(ref):
    return OCTS(ref)


def poq(entry_count=7):
    return SET(X(0, INT(1)), X(1, SET(continuation_reference())),
               X(2, BOOL(True)), X(3, SET(OID('2.5.9.2'))),
               X(4, OCTS(b'page-2')), X(5, f_item(fi_present(AT_CN))),
               X(6, SEQ(attribute(AT_CN, PSTR('partial')))),
               X(entry_count, INT(42)), X(10, BOOL(True)))


def relaxation():
    return SEQ(X(0, SEQ()), X(3, INT(2)), X(4, INT(1)))


def join_argument():
    return SEQ(X(0, DN_ORG), X(1, UTF8('local-1')), X(2, ENUM(1)),
               X(3, f_item(fi_present(AT_CN))),
               X(4, SEQ(SEQ(OID(AT_CN), OID(AT_SN), SEQ(OID(AT_CN))))),
               X(5, eis(1)))


def signed(data, tag=None):
    body = data + alg() + BITS(0, b'\x5a' * 16)
    return X(0, SEQ(body)) if tag == 0 else SEQ(body)


# ------------------------------------------------------- bind

def bind_arg(creds=None, versions=True):
    body = b''
    if creds is not None:
        body += X(0, creds)
    if versions:
        body += X(1, BITS(6, b'\xc0'))
    return SET(body)


def simple_creds(name=DN_ALICE, validity=True, password='plain'):
    body = b''
    if name is not None:
        body += X(0, name)
    if validity:
        body += X(1, SET(X(0, UTCT()), X(1, GENT('20261101130000Z')),
                         X(2, BITS(0, b'\x01\x02\x03\x04')), X(3, BITS(0, b'\x05\x06\x07\x08'))))
    if password == 'plain':
        body += X(2, OCTS(b'secret'))
    elif password == 'protected':
        body += X(2, SEQ(OCTS(b'\x9f' * 20), alg('1.3.14.3.2.26'), BITS(0, b'\x77' * 8)))
    elif password == 'gt':
        pass
    return X(0, SEQ(body))


def token():
    td = SEQ(X(0, alg()), X(1, DN_ALICE), X(2, UTCT()),
             X(3, BITS(0, b'\x01' * 8)), X(4, BITS(0, b'\x02' * 8)),
             X(5, SEQ(alg())), X(6, BITS(0, b'\x03' * 8)),
             X(7, SEQ(alg('2.16.840.1.101.3.4.1.42', OCTS(bytes(16))))), X(8, BITS(0, b'\x04' * 8)))
    return SEQ(td, alg(), BITS(0, b'\x99' * 16))


def strong_creds():
    return X(1, SET(X(0, cert_path()), X(1, token()), X(2, DN_ALICE)))


def external_creds():
    # EXTERNAL with direct-reference and octet-aligned encoding
    return X(2, SEQ(OID('1.3.6.1.4.1.32473.1'), OCTS(b'token', 0x81), tag=0x28))


def sasl_creds(full=True):
    body = X(0, UTF8('PLAIN'))
    if full:
        body += X(1, OCTS(b'\x00alice\x00secret')) + X(2, BOOL(False))
    return X(4, SEQ(body))


def bind_error_data(kind='service', problem=1, secp=False):
    body = X(0, BITS(6, b'\xc0'))
    body += X(1, INT(problem)) if kind == 'service' else X(2, INT(problem))
    if secp:
        body += X(30, security_parameters(1))
    return SET(body)


# ------------------------------------------------------- associations

def user_info(ctx, value):
    """ACSE user-information: one EXTERNAL with an indirect reference
    (the presentation context) and single-ASN1-type."""
    return tlv(0xbe, tlv(0x28, INT(ctx), tlv(0xa0, value)))


def external(ctx, value):
    return tlv(0x28, INT(ctx), tlv(0xa0, value))


class Assoc:
    """An association over the OSI upper layers on TCP port 102 with the
    given application context and abstract syntaxes [(ctx, oid), ...];
    the first abstract syntax is the default for the ROS helpers."""

    def __init__(self, frames, cport, app_ctx, syntaxes):
        self.c = Conn(frames, cport, 102)
        self.app_ctx = app_ctx
        self.syntaxes = syntaxes
        self.ctx = syntaxes[0][0]
        self.iid = 0

    def osi(self, from_client, s):
        self.c.send(from_client, tpkt(cotp_dt(s)))

    def pdata(self, from_client, data, ctx=None):
        self.osi(from_client, ses_dt(fully_encoded(pdv(self.ctx if ctx is None else ctx, data))))

    def open(self, aarq_user=b'', aare_user=b''):
        self.c.handshake()
        self.c.send(True, tpkt(cotp_cr()))
        self.c.send(False, tpkt(cotp_cc()))
        ctxs = [(CTX_ACSE, OID_ACSE)] + list(self.syntaxes)
        self.osi(True, ses_cn(pres_cp(ctxs, fully_encoded(pdv(CTX_ACSE, aarq(self.app_ctx, aarq_user))))))
        self.osi(False, ses_ac(pres_cpa(len(ctxs), fully_encoded(pdv(CTX_ACSE, aare(self.app_ctx, aare_user))))))

    def close(self):
        self.osi(True, ses_fn(fully_encoded(pdv(CTX_ACSE, rlrq()))))
        self.osi(False, ses_dn(fully_encoded(pdv(CTX_ACSE, rlre()))))
        self.c.close()

    def bind(self, arg):
        self.pdata(True, tlv(0xb0, arg))

    def bind_result(self, res):
        self.pdata(False, tlv(0xb1, res))

    def bind_error(self, err):
        self.pdata(False, tlv(0xb2, err))

    def unbind(self):
        self.pdata(True, tlv(0xb3, b''))

    def op(self, opcode, arg, result=None, error=None, from_client=True):
        """An invoke and its result or error (code, parameter)."""
        self.iid += 1
        self.pdata(from_client, ros_invoke(self.iid, opcode, arg))
        if result is not None:
            self.pdata(not from_client, ros_result(self.iid, opcode, result))
        if error is not None:
            self.pdata(not from_client, ros_error(self.iid, error[0], error[1]))

    def reject(self, ptag, problem):
        self.pdata(False, ros_reject(self.iid, ptag, problem))


# RTSE (X.228), for the reliable shadow application contexts

def rtorq(user):
    """RTORQapdu [16] with connectionDataRQ [3] open [0] user data."""
    return tlv(0xb0, INT(0, 0x80), INT(3, 0x81), INT(1, 0x82), tlv(0xa3, tlv(0xa0, user)))


def rtoac(user):
    return tlv(0xb1, INT(0, 0x80), INT(3, 0x81), tlv(0xa2, tlv(0xa0, user)))


def rttr(ctx, value):
    """RTTRapdu: an OCTET STRING holding an EXTERNAL."""
    return OCTS(external(ctx, value))


class Idmp:
    """A connection over IDMP (TCP port 1102) for the protocol OID."""

    def __init__(self, frames, cport, proto_oid):
        self.c = Conn(frames, cport, 1102)
        self.proto = proto_oid

    def send(self, from_client, pdu, final=True):
        self.c.send(from_client, struct.pack('!BBI', 2, 1 if final else 0, len(pdu)) + pdu)

    def bind(self, arg):
        self.send(True, X(0, SEQ(OID(self.proto), X(2, arg))))

    def bind_result(self, res):
        self.send(False, X(1, SEQ(OID(self.proto), X(1, res))))

    def request(self, iid, opcode, arg):
        self.send(True, X(3, SEQ(INT(iid), INT(opcode), arg)))

    def result(self, iid, opcode, res):
        self.send(False, X(4, SEQ(INT(iid), INT(opcode), res)))

    def error(self, iid, code, param):
        self.send(False, X(5, SEQ(INT(iid), INT(code), param)))
