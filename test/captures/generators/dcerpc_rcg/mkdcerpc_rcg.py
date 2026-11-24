#!/usr/bin/env python3
# Generates test/captures/dcerpc_rcg_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the RCG dissector (packet-dcerpc-rcg.c,
# [MS-RDPEAR] Remote Credential Guard calls) and its only caller, the
# RDPEAR virtual channel dissector (packet-rdp_ear.c).
#
# RDPEAR runs inside an RDP dynamic virtual channel, which is inside TLS
# or CredSSP, so the frames are Exported PDUs (link type 252) naming the
# "rdp_ear" dissector.  Frame 1 is an Exported PDU naming "tpkt" with an
# X.224 Connection Request carrying an RDP Negotiation Request; it makes
# the RDP dissector record 192.0.2.2:3389 as the server, so the RDPEAR
# frames sent to it are decoded as call outputs (KerbCredIsoRemoteOutput,
# NtlmCredIsoRemoteOutput) and the ones from it as call inputs.
#
# Every packet is built with struct; nothing comes from a real network.
#
# Usage: mkdcerpc_rcg.py <outdir>
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))







import struct

from ndrenc import (U8, U16, I16, U32, I32, I64, Raw, Ptr, Struct, CArr,
                    CVStr, Union, ndr)
from repro import reproducer_dir

C = bytes([192, 0, 2, 1])      # RDP client (holds the credentials)
S = bytes([192, 0, 2, 2])      # RDP server
CPORT, SPORT = 50000, 3389


def tlv(t, v):
    pad = (4 - len(v) % 4) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def exp_pdu(name, payload, src=None, dst=None, sport=None, dport=None):
    t = tlv(12, name.encode())
    if src:
        t += tlv(20, src) + tlv(21, dst)
    if sport is not None:
        t += tlv(24, struct.pack('>I', 2))          # EXP_PDU_PT_TCP
        t += tlv(25, struct.pack('>I', sport)) + tlv(26, struct.pack('>I', dport))
    return t + struct.pack('>HH', 0, 0) + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def read_pcap(path):
    """Frames of a pcap written by the reproducer scripts."""
    d = open(path, 'rb').read()
    off, out = 24, []
    while off < len(d):
        n = struct.unpack_from('<I', d, off + 8)[0]
        out.append(d[off + 16:off + 16 + n])
        off += 16 + n
    return out


def ber(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + struct.pack('>H', n)
    return bytes([tag]) + ln + content


def ber_int(v):
    b = v.to_bytes(4, 'big', signed=True)
    while len(b) > 1 and ((b[0] == 0 and b[1] < 0x80) or (b[0] == 0xff and b[1] >= 0x80)):
        b = b[1:]
    return ber(0x02, b)


# ---------------------------------------------------------------------------
# RDP connection request (sets the server address of the conversation)

def x224_cr():
    negreq = struct.pack('<BBHI', 1, 0x02, 8, 0x0b)   # redirected auth, TLS|CredSSP|EarlyUA
    cr = b'Cookie: mstshash=rcg\r\n' + negreq
    x224 = bytes([len(cr) + 6, 0xe0, 0, 0, 0, 0, 0]) + cr
    return struct.pack('>BBH', 3, 0, len(x224) + 4) + x224


# ---------------------------------------------------------------------------
# RDPEAR framing

NDR_HDR_KERB = (bytes([1, 0x10, 8, 0]) + b'\xcc' * 4 +
                struct.pack('<II', 0, 0) + struct.pack('<II', 0x00020000, 0))
NDR_HDR_NTLM = (bytes([1, 0x10, 8, 0]) + b'\xcc' * 4 +
                struct.pack('<II', 0, 0) + struct.pack('<I', 0x00020000))
RESERVED = b'\0' * 16


def wrap_token(inner, sealed=False, ec=12, seq=1):
    flags = 0x02 if sealed else 0x00
    if not sealed:
        # Unsealed CFX wrap token, RRC 0: plaintext, then EC octets of checksum
        return (b'\x05\x04' + bytes([flags, 0xff]) +
                struct.pack('>HHQ', ec, 0, seq) + inner + bytes(range(0xa0, 0xa0 + ec)))
    # Sealed: 44 + EC octets of checksum, then ciphertext (not decrypted)
    return (b'\x05\x04' + bytes([flags | 0x04, 0xff]) +
            struct.pack('>HHQ', 0, 0, seq) + b'\x5a' * 44 + inner)


def rdpear(package, buf, to_server, version=None, sealed=False, seq=1,
           tspkg=0x1122334455667788):
    seqbody = b''
    if version is not None:
        seqbody += ber(0xa0, ber_int(version))
    seqbody += ber(0xa1, ber(0x04, package.encode('utf-16-le')))
    seqbody += ber(0xa2, ber(0x04, buf))
    tok = wrap_token(ber(0x30, seqbody), sealed=sealed, seq=seq)
    hdr = struct.pack('<IIIIQ', 0x4eacc3c8, len(tok), 1, 0, tspkg)
    if to_server:
        return exp_pdu('rdp_ear', hdr + tok, C, S, CPORT, SPORT)
    return exp_pdu('rdp_ear', hdr + tok, S, C, SPORT, CPORT)


# ---------------------------------------------------------------------------
# RCG types

def octet(b):                       # KERB_RPC_OCTET_STRING
    return Struct(U32(len(b)), Ptr(CArr(b)))


def enckey(etype, key):             # KERB_RPC_ENCRYPTION_KEY
    return Struct(U32(0), U32(etype), octet(key))


def asn1data(pdu, b):               # KERB_ASN1_DATA
    return Struct(U32(pdu), U32(len(b)), Ptr(CArr(b)))


def checksum_data(pdu, b):          # KERB_ASN1_DATA_CHECKSUM
    return Struct(U32(pdu), U32(len(b)), Ptr(CArr(b)))


def ustr(text, extra=1):            # RPC_UNICODE_STRING
    n = len(text)
    return Struct(U16(2 * n), U16(2 * (n + extra)),
                  Ptr(CVStr(text, maxc=n + extra)))


def iname(nametype, names):         # KERB_RPC_INTERNAL_NAME
    return Struct(I16(nametype), U16(len(names)),
                  Ptr(CArr([ustr(x) for x in names])))


def largeint(v):
    return Struct(I64(v))


def blob(b):                        # KERB_RPC_CRYPTO_API_BLOB
    return Struct(U32(len(b)), Ptr(CArr(b)))


def secrets(seed):                  # MSV1_0_REMOTE_ENCRYPTED_SECRETS
    r6 = bytes((seed + i) & 0xff for i in range(12))
    return Struct(U32(1), U32(0), U32(1),
                  Raw(bytes([seed] * 20)), Raw(bytes([seed + 1] * 20)),
                  U32(len(r6)), Ptr(CArr(r6)))


AES256 = 18
KEY = bytes(range(0x40, 0x60))
SUBKEY = bytes(range(0x60, 0x80))
ARMOR = bytes(range(0x80, 0xa0))
TICKET = ber(0x61, ber(0x30, ber(0xa0, ber_int(5)) + ber(0xa1, ber(0x1b, b'EXAMPLE.TEST'))))
AUTHDATA = ber(0x30, ber(0x30, ber(0xa0, ber_int(1)) + ber(0xa1, ber(0x04, b'\x30\x00'))))
ENCPART = ber(0x30, ber(0xa0, ber_int(AES256)) + ber(0xa2, ber(0x04, bytes(range(48)))))
# Kerberos Checksum: hmac-sha1-96-aes256 and a GSS-API authenticator checksum
CKSUM_HMAC = ber(0x30, ber(0xa0, ber_int(16)) + ber(0xa1, ber(0x04, bytes(range(12)))))
CKSUM_GSS = ber(0x30, ber(0xa0, ber_int(0x8003)) +
                ber(0xa1, ber(0x04, struct.pack('<I', 16) + b'\x11' * 16 +
                              struct.pack('<I', 0x3e))))


def kin(callid, arm):
    """KerbCredIsoRemoteInput."""
    return Struct(U16(callid), Union(callid, arm))


def kout(callid, arm, status=0):
    """KerbCredIsoRemoteOutput."""
    return Struct(U16(callid), U32(status), Union(callid, arm))


def kerb_calls():
    """(input, output) pairs for every Kerberos call."""
    calls = []
    # 0x100 NegotiateVersion
    calls.append((kin(0x100, Struct(U32(1))), kout(0x100, Struct(U32(1)))))
    # 0x101 BuildAsReqAuthenticator, with and without the optional ArmorKey
    calls.append((kin(0x101, Struct(Ptr(enckey(AES256, KEY)),
                                    Ptr(enckey(AES256, ARMOR)),
                                    Ptr(largeint(-300 * 10000000)))),
                  kout(0x101, Struct(I32(2), octet(ENCPART)))))
    calls.append((kin(0x101, Struct(Ptr(enckey(AES256, KEY)), Ptr(None),
                                    Ptr(largeint(0)))),
                  kout(0x101, Struct(I32(2), octet(b'')), status=0xc000000d)))
    # 0x102 VerifyServiceTicket, with and without TimeSkew
    calls.append((kin(0x102, Struct(Ptr(asn1data(1, TICKET)),
                                    Ptr(enckey(AES256, KEY)),
                                    Ptr(largeint(1234567)))),
                  kout(0x102, Struct(asn1data(3, TICKET), I32(0)))))
    calls.append((kin(0x102, Struct(Ptr(asn1data(1, TICKET)),
                                    Ptr(enckey(17, KEY[:16])), Ptr(None))),
                  kout(0x102, Struct(asn1data(3, b''), I32(31)))))
    # 0x103 CreateApReqAuthenticator, all optional pointers set / all NULL
    calls.append((kin(0x103, Struct(Ptr(enckey(AES256, KEY)), U32(7),
                                    Ptr(iname(1, ['alice'])),
                                    Ptr(ustr('EXAMPLE.TEST')),
                                    Ptr(largeint(0x0102030405060708)),
                                    Ptr(enckey(AES256, SUBKEY)),
                                    Ptr(asn1data(2, AUTHDATA)),
                                    Ptr(checksum_data(0, CKSUM_GSS)),
                                    U32(11))),
                  kout(0x103, Struct(largeint(0x01d9000000000000),
                                     asn1data(4, ENCPART), I32(0)))))
    calls.append((kin(0x103, Struct(Ptr(enckey(AES256, KEY)), U32(8),
                                    Ptr(iname(2, ['host', 'server.example.test'])),
                                    Ptr(ustr('', extra=0)),
                                    Ptr(largeint(0)),
                                    Ptr(None), Ptr(None), Ptr(None), U32(11))),
                  kout(0x103, Struct(largeint(0), asn1data(4, b''), I32(37)),
                       status=0xc000018b)))
    # 0x104 DecryptApReply
    calls.append((kin(0x104, Struct(Ptr(asn1data(5, ENCPART)),
                                    Ptr(enckey(AES256, SUBKEY)))),
                  kout(0x104, Struct(asn1data(6, AUTHDATA)))))
    # 0x105 UnpackKdcReplyBody, with and without StrengthenKey
    calls.append((kin(0x105, Struct(Ptr(asn1data(7, ENCPART)),
                                    Ptr(enckey(AES256, KEY)),
                                    Ptr(enckey(AES256, ARMOR)),
                                    U32(25), U32(3))),
                  kout(0x105, Struct(I32(0), asn1data(25, AUTHDATA)))))
    calls.append((kin(0x105, Struct(Ptr(asn1data(7, ENCPART)),
                                    Ptr(enckey(AES256, KEY)), Ptr(None),
                                    U32(26), U32(8))),
                  kout(0x105, Struct(I32(41), asn1data(26, b'')))))
    # 0x106 ComputeTgsChecksum
    calls.append((kin(0x106, Struct(Ptr(asn1data(8, AUTHDATA)),
                                    Ptr(enckey(AES256, KEY)), U32(16))),
                  kout(0x106, Struct(checksum_data(0, CKSUM_HMAC)))))
    # 0x107 BuildEncryptedAuthData
    calls.append((kin(0x107, Struct(U32(5), Ptr(enckey(AES256, SUBKEY)),
                                    Ptr(asn1data(9, AUTHDATA)))),
                  kout(0x107, Struct(asn1data(10, ENCPART)))))
    # 0x108 PackApReply
    calls.append((kin(0x108, Struct(Ptr(asn1data(11, TICKET)),
                                    Ptr(asn1data(12, AUTHDATA)),
                                    Ptr(enckey(AES256, SUBKEY)))),
                  kout(0x108, Struct(U32(len(ENCPART)), Ptr(CArr(ENCPART))))))
    # 0x109 HashS4UPreauth
    calls.append((kin(0x109, Struct(Ptr(asn1data(13, AUTHDATA)),
                                    Ptr(enckey(AES256, KEY)), I32(-138))),
                  kout(0x109, Struct(Ptr(U32(16)),
                                     Ptr(Ptr(CArr(bytes(range(16)))))))))
    # 0x10a SignS4UPreauthData
    calls.append((kin(0x10a, Struct(Ptr(enckey(AES256, KEY)), U32(1),
                                    Ptr(asn1data(14, AUTHDATA)),
                                    Ptr(I32(16)))),
                  kout(0x10a, Struct(Ptr(I32(16)), Ptr(U32(12)),
                                     Ptr(Ptr(CArr(bytes(range(12, 24)))))))))
    # 0x10b VerifyChecksum
    calls.append((kin(0x10b, Struct(Ptr(enckey(AES256, KEY)), U32(16),
                                    U32(12), Ptr(CArr(bytes(range(12)))),
                                    U32(9), Ptr(CArr(b'checkdata')))),
                  kout(0x10b, Struct(U32(1)))))
    # 0x113 DecryptPacCredentials
    cred = lambda name, data: Struct(ustr(name), U32(len(data)), Ptr(CArr(data)))
    credarr = Struct(U32(2), CArr([cred('NTLM', bytes(range(40))),
                                   cred('Kerberos', bytes(range(24)))]))
    calls.append((kin(0x113, Struct(Ptr(enckey(AES256, KEY)), U32(0),
                                    U32(AES256), U32(32),
                                    Ptr(CArr(bytes(range(32)))))),
                  kout(0x113, Struct(Ptr(credarr)))))
    # 0x114 CreateECDHKeyAgreement
    calls.append((kin(0x114, Struct(U32(256))),
                  kout(0x114, Struct(Ptr(I64(0x1000)), Ptr(I32(0)), Ptr(U32(65)),
                                     Ptr(Ptr(CArr(b'\x04' + bytes(range(64))))))))
                 )
    # 0x115 CreateDHKeyAgreement
    calls.append((kin(0x115, Struct(U8(0))),
                  kout(0x115, Struct(Ptr(blob(b'\xff' * 32)), Ptr(blob(b'\x02')),
                                     Ptr(blob(b'\x7f' * 20)), Ptr(I64(0x2000)),
                                     Ptr(I32(0)), Ptr(U32(32)),
                                     Ptr(Ptr(CArr(bytes(range(32, 64)))))))))
    # 0x116 DestroyKeyAgreement
    calls.append((kin(0x116, Struct(I64(0x1000))), kout(0x116, Struct(U8(0)))))
    # 0x117 KeyAgreementGenerateNonce
    calls.append((kin(0x117, Struct(I64(0x2000))),
                  kout(0x117, Struct(Ptr(U32(32)),
                                     Ptr(Ptr(CArr(bytes(range(64, 96)))))))))
    # 0x118 FinalizeKeyAgreement
    calls.append((kin(0x118, Struct(Ptr(I64(0x2000)), Ptr(U32(AES256)),
                                    U32(32), Ptr(CArr(bytes(range(96, 128)))),
                                    U32(16), Ptr(CArr(b'X509PublicKey...')))),
                  kout(0x118, Struct(Ptr(enckey(AES256, KEY))))))
    return calls


def nin(callid, arm):
    return Struct(U16(callid), Union(callid, arm))


def nout(callid, arm, status=0):
    return Struct(U16(callid), U32(status), Union(callid, arm))


def ntlm_calls():
    calls = []
    calls.append((nin(0x200, Struct(U32(0))), nout(0x200, Struct(U32(0)))))
    calls.append((nin(0x201, Struct(Ptr(secrets(0x10)), Ptr(ustr('alice')),
                                    Ptr(ustr('EXAMPLE')), Ptr(ustr('SERVER')),
                                    Raw(b'\x01\x23\x45\x67\x89\xab\xcd\xef'))),
                  nout(0x201, Struct(U16(24), Ptr(CArr(bytes(range(24)))),
                                     Struct(Raw(b'\x31' * 16), Raw(b'\x32' * 8)),
                                     Raw(b'\x33' * 16), Raw(b'\x34' * 8)))))
    calls.append((nin(0x202, Struct(Ptr(Struct(Raw(b'\x55' * 8))),
                                    Ptr(secrets(0x20)))),
                  nout(0x202, Struct(Raw(b'\x66' * 24)))))
    calls.append((nin(0x203, Struct(Ptr(Struct(Raw(b'\x77' * 24))),
                                    Ptr(secrets(0x30)))),
                  nout(0x203, Struct(Raw(b'\x88' * 16)))))
    calls.append((nin(0x204, Struct(Ptr(secrets(0x40)), Ptr(secrets(0x50)))),
                  nout(0x204, Struct(U32(1), U32(0), U32(1)))))
    return calls


def kbuf(node):
    return ndr(node, RESERVED + NDR_HDR_KERB)


def nbuf(node):
    return ndr(node, RESERVED + NDR_HDR_NTLM)


REPRO = reproducer_dir(os.path.dirname(os.path.abspath(__file__)),
                       ['rcg_rdpear_leak.py', 'rcg_unknown_package.py', 'rcg_gsschecksum.py'])


def main_frames():
    fr = [exp_pdu('tpkt', x224_cr(), C, S, CPORT, SPORT)]
    seq = 1
    first = True
    for inp, out in kerb_calls():
        # The first call carries the optional Version field
        fr.append(rdpear('Kerberos', kbuf(inp), False, seq=seq,
                         version=0 if first else None))
        fr.append(rdpear('Kerberos', kbuf(out), True, seq=seq))
        first = False
        seq += 1
    for inp, out in ntlm_calls():
        fr.append(rdpear('NTLM', nbuf(inp), False, seq=seq))
        fr.append(rdpear('NTLM', nbuf(out), True, seq=seq))
        seq += 1
    # Call IDs that no union arm handles
    fr.append(rdpear('Kerberos', kbuf(kin(0x1ff, None)), False, seq=seq))
    fr.append(rdpear('Kerberos', kbuf(kout(0x1ff, None, status=0xc0000002)), True, seq=seq))
    fr.append(rdpear('NTLM', nbuf(nin(0x2ff, None)), False, seq=seq + 1))
    fr.append(rdpear('NTLM', nbuf(nout(0x2ff, None, status=0xc0000002)), True, seq=seq + 1))
    # A package other than Kerberos and NTLM is not dissected
    fr.append(rdpear('Negotiate', nbuf(nin(0x200, Struct(U32(0)))), False, seq=seq + 2))
    # A sealed wrap token cannot be decrypted without keys
    fr.append(rdpear('Kerberos', kbuf(kin(0x100, Struct(U32(1)))), False,
                     sealed=True, seq=seq + 3))
    # Reproducers of the fixes on the branch (frames copied verbatim)
    fr += read_pcap(os.path.join(REPRO, 'rcg_rdpear_leak.pcap'))[:2]
    fr += read_pcap(os.path.join(REPRO, 'rcg_unknown_package.pcap'))
    # GssChecksum whose Length says 4 but whose BER Checksum is 36 octets
    # (decodes cleanly; the trailing KeyUsage is taken from the wrong place)
    fr += read_pcap(os.path.join(REPRO, 'rcg_gsschecksum.pcap'))
    return fr


def malformed_frames():
    fr = [exp_pdu('tpkt', x224_cr(), C, S, CPORT, SPORT)]
    # Truncated NDR in every call input and output
    for inp, out in kerb_calls():
        b = kbuf(inp)
        fr.append(rdpear('Kerberos', b[:len(b) - 3], False))
        b = kbuf(out)
        fr.append(rdpear('Kerberos', b[:len(b) - 3], True))
    for inp, out in ntlm_calls():
        b = nbuf(inp)
        fr.append(rdpear('NTLM', b[:len(b) - 3], False))
        b = nbuf(out)
        fr.append(rdpear('NTLM', b[:len(b) - 3], True))
    # GssChecksum and ComputeTgsChecksum output with a broken BER Checksum
    bad = ber(0x30, ber(0xa0, ber_int(16)) + b'\xa1\x20\x04')
    fr.append(rdpear('Kerberos', kbuf(kout(0x106, Struct(checksum_data(0, bad)))), True))
    # RDPEAR header only, and a length beyond the frame
    fr.append(exp_pdu('rdp_ear', struct.pack('<IIIIQ', 0x4eacc3c8, 0, 0, 0, 0), S, C, SPORT, CPORT))
    fr.append(exp_pdu('rdp_ear', struct.pack('<IIIIQ', 0x4eacc3c8, 100, 0, 0, 0) + b'\x05\x04', S, C, SPORT, CPORT))
    # Package buffer shorter than the reserved and NDR headers
    fr.append(rdpear('Kerberos', b'\0' * 20, False))
    fr.append(rdpear('NTLM', b'\0' * 20, True))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dcerpc-rcg-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dcerpc-rcg-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
