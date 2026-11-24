#!/usr/bin/env python3
# Generates test/captures/credssp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CredSSP dissector
(packet-credssp.c, generated from epan/dissectors/asn1/credssp).

CredSSP normally runs inside TLS. Every frame here is an Exported PDU
record (link type 252) that hands a TSRequest either to the "credssp"
dissector by name (with IPv4 address and TCP port tags, so the NTLMSSP
and GSS-API conversations work), or to a heuristic dissector:
"credssp_tls" (CredSSP's own heuristic), "rdp_tls" (RDP, which tries
the "rdp" heuristic list, where CredSSP registers "credssp_tpkt"), or
to the "tpkt" dissector, whose heuristic list leads to RDP and CredSSP
the same way.

The NTLMSSP exchanges are anonymous (empty NT response, one octet LM
response) with key exchange and extended session security, so Wireshark
derives the sealing keys without any credentials and decrypts
pubKeyAuth and authInfo (TSCredentials) with no preferences set. The
sealing is done here with RC4 / HMAC-MD5 as in MS-NLMP.

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcredssp.py <output directory>

Writes:
  credssp_creds_not_octets.pcap    reproducer of an unfixed bug
  credssp-coverage.pcap            clean capture
  credssp-coverage-malformed.pcap  paths only malformed input reaches
"""

import hashlib
import hmac
import os
import struct
import sys

# ---------------------------------------------------------------- BER


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, val=b''):
    return bytes([tag]) + ber_len(len(val)) + val


def ber_int(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def INT(v):
    return tlv(0x02, ber_int(v))


def OCTS(b):
    return tlv(0x04, b)


def SEQ(*items):
    return tlv(0x30, b''.join(items))


def ctx(n, val):
    return tlv(0xa0 | n, val)


def gstr(s):
    return tlv(0x1b, s.encode())


def u16(s):
    return s.encode('utf-16-le')


# ----------------------------------------------------------- CredSSP

def ts_request(version, nego=None, auth=None, pubkey=None, err=None,
               nonce=None, raw_ver=None):
    items = [ctx(0, raw_ver if raw_ver is not None else INT(version))]
    if nego is not None:
        items.append(ctx(1, SEQ(*[SEQ(ctx(0, OCTS(t))) for t in nego])))
    if auth is not None:
        items.append(ctx(2, OCTS(auth)))
    if pubkey is not None:
        items.append(ctx(3, OCTS(pubkey)))
    if err is not None:
        items.append(ctx(4, INT(err)))
    if nonce is not None:
        items.append(ctx(5, OCTS(nonce)))
    return SEQ(*items)


def ts_credentials(cred_type, creds):
    return SEQ(ctx(0, INT(cred_type)), ctx(1, OCTS(creds)))


def ts_password(domain, user, password):
    return SEQ(ctx(0, OCTS(u16(domain))), ctx(1, OCTS(u16(user))),
               ctx(2, OCTS(u16(password))))


def ts_csp(key_spec, card=None, reader=None, container=None, csp=None):
    items = [ctx(0, INT(key_spec))]
    for n, v in ((1, card), (2, reader), (3, container), (4, csp)):
        if v is not None:
            items.append(ctx(n, OCTS(u16(v))))
    return SEQ(*items)


def ts_smartcard(pin, csp, user_hint=None, domain_hint=None):
    items = [ctx(0, OCTS(u16(pin))), ctx(1, csp)]
    if user_hint is not None:
        items.append(ctx(2, OCTS(u16(user_hint))))
    if domain_hint is not None:
        items.append(ctx(3, OCTS(u16(domain_hint))))
    return SEQ(*items)


def rg_package(name, buf):
    return SEQ(ctx(0, OCTS(u16(name))), ctx(1, OCTS(buf)))


def ts_remoteguard(logon, supplemental=None):
    items = [ctx(0, logon)]
    if supplemental is not None:
        items.append(ctx(1, SEQ(*supplemental)))
    return SEQ(*items)


def krb_ticket():
    """A Kerberos Ticket (APPLICATION 1) that cannot be decrypted."""
    sname = SEQ(ctx(0, INT(2)), ctx(1, SEQ(gstr('TERMSRV'), gstr('rdp.example.test'))))
    enc = SEQ(ctx(0, INT(18)), ctx(1, INT(3)), ctx(2, OCTS(bytes(range(32)))))
    return tlv(0x61, SEQ(ctx(0, INT(5)), ctx(1, gstr('EXAMPLE.TEST')), ctx(2, sname),
                         ctx(3, enc)))


def kerb_ticket_logon(with_ticket=True):
    t = krb_ticket() if with_ticket else b''
    # MessageType 0x22 (KerbTicketLogon), flags 1 (allow expired),
    # ServiceTicketLength, TicketGrantingTicketLength 0, two pointers
    return struct.pack('<IIII', 0x22, 1, len(t), 0) + bytes(16) + t


def ntlm_supplemental(encrypted=b''):
    # Version, Flags (2 = NT OWF present), CredentialKey (20 octets),
    # CredentialKeyType, EncryptedCredsSize, EncryptedCreds
    return (struct.pack('<II', 0, 2) + bytes(range(0x40, 0x54))
            + struct.pack('<II', 2, len(encrypted)) + encrypted)


# ----------------------------------------------------------- NTLMSSP

NTLM_FLAGS = (0x00000001 | 0x00000004 | 0x00000010 | 0x00000020 | 0x00000200
              | 0x00008000 | 0x00080000 | 0x00800000 | 0x02000000
              | 0x20000000 | 0x40000000 | 0x80000000)
VERSION = struct.pack('<BBHBBBB', 10, 0, 19041, 0, 0, 0, 15)


def ntlm_negotiate():
    return (b'NTLMSSP\0' + struct.pack('<II', 1, NTLM_FLAGS)
            + struct.pack('<HHI', 0, 0, 40) * 2 + VERSION)


def av(t, v):
    return struct.pack('<HH', t, len(v)) + v


def ntlm_challenge(server_challenge):
    target = u16('EXAMPLE')
    info = (av(2, u16('EXAMPLE')) + av(1, u16('RDPHOST')) + av(4, u16('example.test'))
            + av(3, u16('rdphost.example.test')) + av(7, struct.pack('<Q', 133000000000000000))
            + av(0, b''))
    off = 56
    return (b'NTLMSSP\0' + struct.pack('<I', 2)
            + struct.pack('<HHI', len(target), len(target), off)
            + struct.pack('<I', NTLM_FLAGS) + server_challenge + bytes(8)
            + struct.pack('<HHI', len(info), len(info), off + len(target))
            + VERSION + target + info)


def rc4(key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    state = [s, 0, 0]

    def crypt(data):
        s, i, j = state
        out = bytearray()
        for c in data:
            i = (i + 1) & 0xff
            j = (j + s[i]) & 0xff
            s[i], s[j] = s[j], s[i]
            out.append(c ^ s[(s[i] + s[j]) & 0xff])
        state[1], state[2] = i, j
        return bytes(out)
    return crypt


def ntlm_authenticate(exported_key):
    """Anonymous AUTHENTICATE: KeyExchangeKey is all zero, so the
    encrypted random session key is RC4(zeros, exported key)."""
    enc_key = rc4(bytes(16))(exported_key)
    lm = b'\0'
    ws = u16('CLIENT')
    off = 88
    fields = b''
    payload = b''
    for blob in (lm, b'', b'', b'', ws, enc_key):
        fields += struct.pack('<HHI', len(blob), len(blob), off + len(payload))
        payload += blob
    return (b'NTLMSSP\0' + struct.pack('<I', 3) + fields
            + struct.pack('<I', NTLM_FLAGS | 0x800) + VERSION + bytes(16) + payload)


class Sealer:
    C2S_SEAL = b'session key to client-to-server sealing key magic constant\0'
    S2C_SEAL = b'session key to server-to-client sealing key magic constant\0'
    C2S_SIGN = b'session key to client-to-server signing key magic constant\0'
    S2C_SIGN = b'session key to server-to-client signing key magic constant\0'

    def __init__(self, key, client):
        seal = self.C2S_SEAL if client else self.S2C_SEAL
        sign = self.C2S_SIGN if client else self.S2C_SIGN
        self.rc4 = rc4(hashlib.md5(key + seal).digest())
        self.sign = hashlib.md5(key + sign).digest()
        self.seq = 0

    def seal(self, msg):
        seq = struct.pack('<I', self.seq)
        self.seq += 1
        enc = self.rc4(msg)
        mac = hmac.new(self.sign, seq + msg, 'md5').digest()[:8]
        return struct.pack('<I', 1) + self.rc4(mac) + seq + enc


# ------------------------------------------------------ Exported PDU

def etlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(payload, name='credssp', tag=12, addr=None):
    n = name.encode()
    hdr = etlv(tag, n)
    if addr is not None:
        src, sport, dst, dport = addr
        hdr += (etlv(20, bytes(src)) + etlv(21, bytes(dst))
                + etlv(24, struct.pack('>I', 2))
                + etlv(25, struct.pack('>I', sport)) + etlv(26, struct.pack('>I', dport)))
    return hdr + struct.pack('>HH', 0, 0) + payload


def write_pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1761955200 + i, 0, len(p), len(p)))
            f.write(p)


CLIENT = (192, 0, 2, 10)
SERVER = (198, 51, 100, 20)


class Conv:
    """One CredSSP exchange between CLIENT:port and SERVER:3389."""

    def __init__(self, port, version, n):
        self.c2s = (CLIENT, port, SERVER, 3389)
        self.s2c = (SERVER, 3389, CLIENT, port)
        self.version = version
        self.key = bytes((n * 16 + i) & 0xff for i in range(16))
        self.challenge = bytes([0x11 * ((n % 15) + 1)] * 4) + bytes(range(4))
        self.nonce = hashlib.sha256(b'nonce %d' % n).digest()
        self.client = Sealer(self.key, True)
        self.server = Sealer(self.key, False)
        self.spki = SEQ(SEQ(tlv(0x06, bytes.fromhex('2a864886f70d010101')), tlv(0x05)),
                        tlv(0x03, b'\0' + SEQ(INT(0xc0ffee << 64 | n), INT(65537))))

    def handshake(self, nonce=True):
        v = self.version
        out = [exp_pdu(ts_request(v, nego=[ntlm_negotiate()]), addr=self.c2s),
               exp_pdu(ts_request(v, nego=[ntlm_challenge(self.challenge)]), addr=self.s2c)]
        if v >= 5:
            h = hashlib.sha256(b'CredSSP Client-To-Server Binding Hash\0' + self.nonce
                               + self.spki).digest()
        else:
            h = self.spki
        out.append(exp_pdu(ts_request(v, nego=[ntlm_authenticate(self.key)],
                                      pubkey=self.client.seal(h),
                                      nonce=self.nonce if nonce else None), addr=self.c2s))
        if v >= 5:
            h = hashlib.sha256(b'CredSSP Server-To-Client Binding Hash\0' + self.nonce
                               + self.spki).digest()
        else:
            h = bytes([self.spki[0] + 1]) + self.spki[1:]
        out.append(exp_pdu(ts_request(v, pubkey=self.server.seal(h)), addr=self.s2c))
        return out

    def creds(self, tscred):
        return exp_pdu(ts_request(self.version, auth=self.client.seal(tscred)), addr=self.c2s)

    def server_msg(self, **kw):
        return exp_pdu(ts_request(self.version, **kw), addr=self.s2c)

    def client_msg(self, **kw):
        return exp_pdu(ts_request(self.version, **kw), addr=self.c2s)


def main_capture():
    p = []
    # 1-5: version 6, password credentials
    c = Conv(49700, 6, 1)
    p += c.handshake()
    p.append(c.creds(ts_credentials(1, ts_password('EXAMPLE', 'alice', 'Secr3t!'))))
    # 6-11: version 6, smart card credentials with every optional field,
    # then a second TSCredentials in the same conversation with none
    c = Conv(49701, 6, 2)
    p += c.handshake()
    p.append(c.creds(ts_credentials(2, ts_smartcard(
        '123456', ts_csp(1, 'Example Card', 'Example Reader 0', 'container-1',
                         'Microsoft Base Smart Card Crypto Provider'),
        'bob@example.test', 'EXAMPLE'))))
    p.append(c.creds(ts_credentials(2, ts_smartcard('0000', ts_csp(2)))))
    # 12-18: version 6, Remote Credential Guard: Kerberos logon with a
    # ticket and NTLM, Kerberos and unknown supplemental packages; then an
    # NTLM logon; then a logon with only an unknown package (the fix: its
    # buffer is not decoded with the NTLM package of the previous frame)
    c = Conv(49702, 6, 3)
    p += c.handshake()
    p.append(c.creds(ts_credentials(6, ts_remoteguard(
        rg_package('Kerberos', kerb_ticket_logon()),
        [rg_package('NTLM', ntlm_supplemental(bytes(range(24)))),
         rg_package('Kerberos', kerb_ticket_logon(False)),
         rg_package('CloudAP', b'\x01\x02\x03\x04')]))))
    p.append(c.creds(ts_credentials(6, ts_remoteguard(
        rg_package('NTLM', ntlm_supplemental())))))
    p.append(c.creds(ts_credentials(6, ts_remoteguard(
        rg_package('Negotiate', bytes(range(0x30, 0x58)))))))
    # 19-23: version 4: no client nonce; errorCode from the server;
    # credentials of an unknown type
    c = Conv(49703, 4, 4)
    p += c.handshake(nonce=False)
    p.append(c.creds(ts_credentials(4, b'\x30\x03\x02\x01\x07')))
    # 24: version 4 error (STATUS_LOGON_FAILURE)
    p.append(c.server_msg(err=-0x3fffff93))
    # 25-28: version 2: negoTokens only (no MIC/nonce); a TSRequest with
    # two negoTokens
    c = Conv(49704, 2, 5)
    p += c.handshake(nonce=False)
    # 29: version 2 with two tokens in negoTokens (both NEGOTIATE)
    p.append(c.client_msg(nego=[ntlm_negotiate(), ntlm_negotiate()]))
    # 30: version 6 errorCode with nonce from the server (SEC_E_LOGON_DENIED)
    c = Conv(49705, 6, 6)
    p.append(c.server_msg(err=-0x7ff6fefa, nonce=c.nonce))
    # 31: a TSRequest without addresses (no conversation): the NTLMSSP
    # payload is not decrypted
    p.append(exp_pdu(ts_request(6, auth=bytes([1, 0, 0, 0]) + bytes(range(40)))))
    # 32-34: the heuristics. credssp_tls, rdp_tls (rdp list), tpkt (tpkt
    # list, RDP, rdp list)
    req = ts_request(6, nego=[ntlm_negotiate()])
    p.append(exp_pdu(req, name='credssp_tls', tag=13))
    p.append(exp_pdu(ts_request(3, nego=[ntlm_negotiate()]), name='rdp_tls', tag=13))
    p.append(exp_pdu(ts_request(98, nego=[ntlm_negotiate()]), name='tpkt'))
    # 35-40: payloads the CredSSP heuristic rejects (each shows as data)
    for bad in (b'\x30\x05\xa0\x03\x02\x01',                 # 7 octets: too short
                b'\x31\x0a\xa0\x03\x02\x01\x06' + bytes(5),  # SET, not SEQUENCE
                b'\x30\x0a\xa1\x03\x02\x01\x06' + bytes(5),  # [1], not [0]
                b'\x30\x0a\xa0\x03\x04\x01\x06' + bytes(5),  # OCTET STRING version
                b'\x30\x0a\xa0\x03\x02\x01\x01' + bytes(5),  # version 1
                b'\x30\x0b\xa0\x04\x02\x02\x00\x06' + bytes(5)):  # 2 octet version
        p.append(exp_pdu(bad, name='credssp_tls', tag=13))
    return p


def malformed_capture():
    p = []
    # 1-2: the reproducers (credssp_null_authinfo.py):
    # authInfo / pubKeyAuth hold an INTEGER instead of an OCTET STRING
    inner = tlv(0x02, b'\x00')
    p.append(exp_pdu(SEQ(ctx(0, INT(6)), ctx(2, inner))))
    p.append(exp_pdu(SEQ(ctx(0, INT(6)), ctx(3, inner))))
    # 3: negoToken that is not an OCTET STRING
    p.append(exp_pdu(SEQ(ctx(0, INT(6)), ctx(1, SEQ(SEQ(ctx(0, INT(1))))))))
    # 4-5: errorCode with version 2 and clientNonce with version 4
    p.append(exp_pdu(ts_request(2, err=5)))
    p.append(exp_pdu(ts_request(4, nonce=bytes(32))))
    # 6: truncated TSRequest
    p.append(exp_pdu(ts_request(6, nego=[ntlm_negotiate()])[:20]))
    # 7-13: a conversation whose sealed TSCredentials are malformed:
    # credentials not an OCTET STRING (frame 11, the unfixed bug in
    # dissect_credssp_T_credentials()), a Remote Guard package name not an
    # OCTET STRING, a credBuffer not an OCTET STRING
    c = Conv(49800, 6, 7)
    p += c.handshake()
    p.append(c.creds(SEQ(ctx(0, INT(1)), ctx(1, INT(5)))))
    p.append(c.creds(ts_credentials(6, SEQ(ctx(0, SEQ(ctx(0, INT(1)), ctx(1, OCTS(b'x'))))))))
    p.append(c.creds(ts_credentials(6, SEQ(ctx(0, SEQ(ctx(0, OCTS(u16('NTLM'))),
                                                      ctx(1, INT(1))))))))
    # 14: version 3 TSRequest from the TLS heuristic whose rest is garbage
    p.append(exp_pdu(b'\x30\x0a\xa0\x03\x02\x01\x03' + b'\xff' * 5, name='credssp_tls', tag=13))
    return p


def creds_not_octets():
    """Reproducer of the bug in dissect_credssp_T_credentials(): a
    decrypted TSCredentials whose credentials [1] is an INTEGER, so NULL
    is passed on as the tvb of TSPasswordCreds."""
    c = Conv(49900, 6, 8)
    return c.handshake() + [c.creds(SEQ(ctx(0, INT(1)), ctx(1, INT(5))))]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'credssp_creds_not_octets.pcap'), creds_not_octets())
    write_pcap(os.path.join(out, 'credssp-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'credssp-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()
