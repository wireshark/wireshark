#!/usr/bin/env python3
# Generates test/captures/negoex_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NEGOEX coverage captures.  Usage: mknegoex.py <outdir>
Writes negoex-coverage.pcap (main) and negoex-coverage-malformed.pcap.
NEGOEX messages travel in SPNEGO tokens of HTTP "Negotiate" authentication
(TCP port 80); a few frames use Exported PDUs that name the registered
dissectors "negoex" and "gssapi".  Everything is synthetic (192.0.2.0/24).
No keys or cryptography: the checksum and exchange bytes are placeholders."""
import struct
import sys
import os
import base64
from netlib import Conn, write_pcapng

def p32(x): return struct.pack('<I', x)
def p16(x): return struct.pack('<H', x)
def p64(x): return struct.pack('<Q', x)

GUID_A = bytes.fromhex('5c33530deaf90d4db2ec4ae3786ec308')   # placeholder authentication scheme ids
GUID_B = bytes.fromhex('6e50fa0ebb24324d8e1e0a1c1bd5f9b3')
GUID_C = bytes.fromhex('0123456789abcdeffedcba9876543210')
CONV = bytes.fromhex('00112233445566778899aabbccddeeff')
RANDOM = bytes(range(32))

def hdr(mtype, seq, msglen, hdrlen=40, sig=b'NEGOEXTS', conv=CONV):
    return sig + p32(mtype) + p32(seq) + p32(hdrlen) + p32(msglen) + conv

def nego(mtype, seq, schemes=(GUID_A, GUID_B), exts=((b'ext-one-data',),), pad_ext=False):
    """INITIATOR_NEGO / ACCEPTOR_NEGO.  The dissector reads the first extension
    entry at the end of the fixed part, so the extension vector goes first."""
    fixed = 40 + 32 + 8 + 8 + 8
    ext_off = fixed
    as_off = ext_off + 8 * len(exts)
    data_off = as_off + 16 * len(schemes)
    ext_bytes = b''
    ext_hdr = b''
    for e in exts:
        ext_hdr += p32(data_off + len(ext_bytes)) + p16(len(e[0])) + p16(0)
        ext_bytes += e[0]
    total = data_off + len(ext_bytes)
    body = (RANDOM + p64(0) + p32(as_off) + p16(len(schemes)) + p16(0)
            + p32(ext_off) + p16(len(exts)) + p16(0) + ext_hdr + b''.join(schemes) + ext_bytes)
    return hdr(mtype, seq, total) + body

def exchange(mtype, seq, scheme=GUID_A, data=b'exchange placeholder bytes'):
    off = 40 + 16 + 8
    return hdr(mtype, seq, off + len(data)) + scheme + p32(off) + p16(len(data)) + p16(0) + data

def verify(seq, scheme=GUID_A, cksum=b'\xaa' * 12, ctype=0x0f, cscheme=1):
    off = 40 + 16 + 20
    return (hdr(6, seq, off + len(cksum)) + scheme + p32(20) + p32(cscheme) + p32(ctype)
            + p32(off) + p16(len(cksum)) + p16(0) + cksum)

def alert(seq, scheme=GUID_A, err=0xc0000001, rest=b'\0' * 8):
    return hdr(7, seq, 40 + 16 + 4 + len(rest)) + scheme + p32(err) + rest

# --- DER / SPNEGO ---------------------------------------------------------------
def dlen(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b
def tlv(tag, body): return bytes([tag]) + dlen(len(body)) + body
OID_SPNEGO = bytes.fromhex('06062b0601050502')
OID_NEGOEX = bytes.fromhex('060a2b06010401823702021e')
OID_NTLM = bytes.fromhex('060a2b06010401823702020a')
OID_KRB5 = bytes.fromhex('06092a864886f712010202')
def neg_init(mechs, token):
    mt = tlv(0xa0, tlv(0x30, b''.join(mechs)))
    inner = mt + (tlv(0xa2, tlv(0x04, token)) if token is not None else b'')
    return tlv(0x60, OID_SPNEGO + tlv(0xa0, tlv(0x30, inner)))
def neg_resp(token, state=1, mech=OID_NEGOEX):
    inner = tlv(0xa0, tlv(0x0a, bytes([state]))) + (tlv(0xa1, mech) if mech else b'')
    if token is not None:
        inner += tlv(0xa2, tlv(0x04, token))
    return tlv(0xa1, tlv(0x30, inner))
def gss_initial(oid, inner):
    return tlv(0x60, oid + inner)

def http_req(tok, path='/private', host='nego.example.test'):
    return ('GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Negotiate %s\r\n\r\n'
            % (path, host, base64.b64encode(tok).decode())).encode()
def http_resp(tok, code='401 Unauthorized', extra=''):
    h = 'HTTP/1.1 %s\r\n' % code
    if tok is not None:
        h += 'WWW-Authenticate: Negotiate %s\r\n' % base64.b64encode(tok).decode()
    return (h + extra + 'Content-Length: 0\r\n\r\n').encode()

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

def build_main():
    f = []
    C, S = '192.0.2.10', '192.0.2.80'
    # --- one SPNEGO/NEGOEX handshake per HTTP connection ----------------------------------
    c = Conn(f, C, S, 50001, 80)
    c.c2s(http_req(neg_init([OID_NEGOEX, OID_NTLM, OID_KRB5], nego(0, 0))))
    c.s2c(http_resp(neg_resp(nego(1, 1, schemes=(GUID_B, GUID_A, GUID_C)))))
    c.c2s(http_req(neg_resp(exchange(2, 2) + exchange(2, 3, GUID_B, b'second meta data'), mech=None)))
    c.s2c(http_resp(neg_resp(exchange(3, 4) + exchange(3, 5, GUID_B, b'acceptor meta'), mech=None)))
    c.c2s(http_req(neg_resp(exchange(4, 6, GUID_A, b'challenge placeholder'), mech=None)))
    c.s2c(http_resp(neg_resp(exchange(5, 7, GUID_A, b'ap request placeholder'), mech=None)))
    c.c2s(http_req(neg_resp(verify(8) + alert(9), mech=None)))
    c.s2c(http_resp(neg_resp(verify(10, cksum=b'\xbb' * 20, ctype=0x10, cscheme=2) + alert(11, err=0, rest=b'\0'),
                             state=0, mech=None), code='200 OK'))
    c.fin()
    # NEGOEX as first mechanism only, no extensions, one authentication scheme
    c = Conn(f, C, S, 50002, 80)
    c.c2s(http_req(neg_init([OID_NEGOEX], nego(0, 0, schemes=(GUID_C,), exts=()))))
    c.s2c(http_resp(neg_resp(nego(1, 1, schemes=(GUID_C,), exts=()), state=1)))
    c.fin()
    # Several extensions
    c = Conn(f, C, S, 50003, 80)
    c.c2s(http_req(neg_init([OID_NEGOEX, OID_KRB5], nego(0, 0, exts=((b'ext1',), (b'extension-two',), (b'e3',))))))
    c.s2c(http_resp(neg_resp(None, state=2, mech=OID_NEGOEX), code='200 OK'))
    c.fin()
    # --- the NEGOEX dissector and the GSS-API dissector by Exported PDU -------------------------
    e = []
    e.append(exp_pdu('negoex', nego(0, 0)))
    e.append(exp_pdu('negoex', exchange(2, 1) + verify(2) + alert(3)))
    e.append(exp_pdu('gssapi', gss_initial(OID_NEGOEX, nego(1, 0))))
    e.append(exp_pdu('negoex', alert(0, rest=b'\0')))
    # An unknown message type stops the dissection of the remaining messages
    e.append(exp_pdu('negoex', hdr(8, 0, 48) + b'\0' * 8 + alert(1)))
    # The ALERT message of the reproducer, with a valid length (cbMessageLength 0 loops without a tree)
    e.append(exp_pdu('negoex', alert(0)))
    return f, e

def build_malformed():
    e = []
    # cbMessageLength smaller than the header: expert info "Message length is smaller than the header"
    for ml in (0, 1, 39):
        e.append(exp_pdu('negoex', hdr(7, 0, ml) + bytes(16) + p32(0xc0000001) + bytes(8)))
    e.append(exp_pdu('gssapi', gss_initial(OID_NEGOEX, hdr(7, 0, 0) + bytes(28))))
    e.append(exp_pdu('negoex', hdr(0, 0, 0) + bytes(28) + alert(1)))
    # truncated messages of every type
    for m in (nego(0, 0), nego(1, 0), exchange(2, 0), exchange(5, 0), verify(0), alert(0)):
        for cut in (45, 60, 80, 100):
            if cut < len(m):
                e.append(exp_pdu('negoex', m[:cut]))
    # message_len beyond the data, vector offsets beyond the message
    m = bytearray(exchange(2, 0)); m[16:20] = p32(1000)
    e.append(exp_pdu('negoex', bytes(m)))
    m = bytearray(exchange(2, 0)); m[56:60] = p32(5000); e.append(exp_pdu('negoex', bytes(m)))
    m = bytearray(nego(0, 0)); m[80:84] = p32(4000); m[84:86] = p16(9); e.append(exp_pdu('negoex', bytes(m)))
    m = bytearray(nego(0, 0)); m[88:92] = p32(2000); m[92:94] = p16(5); e.append(exp_pdu('negoex', bytes(m)))
    m = bytearray(verify(0)); m[76:80] = p32(9000); e.append(exp_pdu('negoex', bytes(m)))
    # a wrong signature is not checked; a header with too few bytes for the message type
    e.append(exp_pdu('negoex', b'NOTNEGOEX' + bytes(40)))
    e.append(exp_pdu('negoex', b'NEGOEXTS'))
    return e

if __name__ == '__main__':
    out = sys.argv[1]
    f, e = build_main()
    # HTTP frames are Ethernet (interface 0), the Exported PDU frames interface 1; the
    # Exported PDUs are placed between the HTTP connections, in order.
    frames = [(0, p) for p in f] + [(1, p) for p in e]
    write_pcapng(os.path.join(out, 'negoex-coverage.pcapng'), frames)
    m = build_malformed()
    write_pcapng(os.path.join(out, 'negoex-coverage-malformed.pcapng'), [(1, p) for p in m])
    print(len(frames), len(m))
