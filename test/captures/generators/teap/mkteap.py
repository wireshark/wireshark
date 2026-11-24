#!/usr/bin/env python3
# Generates test/captures/teap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the TEAP coverage captures. Usage: mkteap.py <outdir> [-v]
Writes teap-coverage.pcapng (main), teap-coverage-malformed.pcapng;
teap_coverage.pcapng.gz is made by the caller with gzip -9n.
Everything is synthetic: EAP-TEAP outer TLVs in EAPOL frames (no TLS
tunnel, no keys) and Exported PDUs naming "teap"."""
import os
import struct
import sys
from pcaplib import eth, exp_pdu, write_pcapng

def tlv(t, v, m=False, r=False):
    return struct.pack('!HH', t | (0x8000 if m else 0) | (0x4000 if r else 0), len(v)) + v

def pattr(t, v):
    return struct.pack('!HH', t, len(v)) + v

_ID = [0]

def eap_teap(tlvs, code=1, ident=None, flags=0x11):
    """EAPOL-EAP packet of type TEAP whose payload is only outer TLVs.
    The identifier is unique per frame (EAP flags repeated code+id as retransmissions)."""
    _ID[0] += 1
    ident = _ID[0] & 255
    body = bytes([flags]) + struct.pack('!I', len(tlvs)) + tlvs
    eap = struct.pack('!BBHB', code, ident, 5 + len(body), 55) + body
    return eth(0x888e, struct.pack('!BBH', 2, 0, len(eap)) + eap)

def eap_pkt(code, ident, typ, data=b''):
    if code in (3, 4):
        return struct.pack('!BBH', code, ident, 4)
    return struct.pack('!BBHB', code, ident, 5 + len(data), typ) + data

def crypto(flags, subtype, ver=1, rcv=1, nonce=0x41):
    return (b'\x00' + bytes([ver, rcv, (flags << 4) | subtype]) + bytes([nonce]) * 32
            + b'\xe1' * 20 + b'\xf2' * 20)

def pac_info(depth):
    inner = pattr(3, struct.pack('!I', 86400))
    for _ in range(depth):
        inner = pattr(9, inner)
    return inner

def nested_nak(depth):
    t = tlv(3, b'\x00\x01')
    for _ in range(depth):
        t = tlv(4, struct.pack('!IH', 0, 3) + t)
    return t

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    # Start with the Authority-ID, then single TLVs
    add('start', eap_teap(tlv(1, b'authority.example.invalid', m=True), flags=0x31))
    add('identity', eap_teap(tlv(2, b'\x00\x01', m=True), 1, 2))
    add('identity-machine', eap_teap(tlv(2, b'\x00\x02'), 2, 2))
    add('result-ok', eap_teap(tlv(3, b'\x00\x01', m=True), 1, 3))
    add('result-fail', eap_teap(tlv(3, b'\x00\x02', m=True), 2, 3))
    add('result-unknown', eap_teap(tlv(3, b'\x00\x07'), 1, 4))
    # NAK without and with an embedded TLV
    add('nak', eap_teap(tlv(4, struct.pack('!IH', 0x137, 9)), 1, 5))
    add('nak-nested', eap_teap(tlv(4, struct.pack('!IH', 0, 3) + tlv(3, b'\x00\x02')), 1, 5))
    # Error codes: known, unknown
    for c in (1, 1001, 2002, 4242):
        add('error%d' % c, eap_teap(tlv(5, struct.pack('!I', c), m=True), 1, 6))
    add('channel-binding', eap_teap(tlv(6, b'\x01\x02\x03\x04'), 1, 7))
    add('vendor', eap_teap(tlv(7, struct.pack('!I', 311) + b'\xde\xad\xbe\xef', m=True), 1, 8))
    add('request-action', eap_teap(tlv(8, b'\x01\x01'), 1, 9))
    add('request-action-neg', eap_teap(tlv(8, b'\x02\x02'), 1, 9))
    add('request-action-nested', eap_teap(tlv(8, b'\x01\x01' + tlv(2, b'\x00\x01') + tlv(5, struct.pack('!I', 1005))), 1, 9))
    # EAP-Payload: an EAP Identity response, followed by more TLVs and alone
    ident_resp = eap_pkt(2, 7, 1, b'user@example.invalid')
    add('eap-payload', eap_teap(tlv(9, ident_resp, m=True), 1, 10))
    add('eap-payload-more', eap_teap(tlv(9, eap_pkt(2, 9, 1, b'user2') + tlv(2, b'\x00\x01') + tlv(3, b'\x00\x01')), 1, 10))
    add('eap-payload-request', eap_teap(tlv(9, eap_pkt(1, 8, 1, b'who?')), 1, 10))
    add('eap-payload-success', eap_teap(tlv(9, eap_pkt(3, 8, 0)), 1, 10))
    add('intermediate-result', eap_teap(tlv(10, b'\x00\x01'), 1, 11))
    add('intermediate-result-nested', eap_teap(
        tlv(10, b'\x00\x02' + tlv(5, struct.pack('!I', 1003)) + tlv(12, crypto(1, 0))), 1, 11))
    # PAC TLV with every attribute
    pac = (pattr(1, bytes(range(32))) + pattr(2, b'opaque-ticket') + pattr(3, struct.pack('!I', 3600))
           + pattr(4, b'a-id.example') + pattr(5, b'i-id.example') + pattr(6, b'\x00\x00')
           + pattr(7, b'a-id-info text') + pattr(8, b'\x00\x01') + pattr(10, b'\x00\x01')
           + pattr(9, pattr(4, b'inner a-id') + pattr(5, b'inner i-id') + pattr(10, b'\x00\x01'))
           + pattr(99, b'unknown attribute'))
    add('pac', eap_teap(tlv(11, pac, m=True), 1, 12))
    add('pac-info-15-levels', eap_teap(tlv(11, pac_info(14)), 1, 12))
    # Crypto-Binding with each flag value and subtype
    for fl in (0, 1, 2, 3):
        for st in (0, 1):
            add('crypto-%d-%d' % (fl, st), eap_teap(tlv(12, crypto(fl, st), m=True), 1, 13))
    # Basic password auth
    add('pwd-req', eap_teap(tlv(13, b'Enter your password'), 1, 14))
    add('pwd-req-empty', eap_teap(tlv(13, b''), 1, 14))
    add('pwd-resp', eap_teap(tlv(14, bytes([4]) + b'user' + bytes([6]) + b'secret'), 2, 14))
    add('pwd-resp-empty', eap_teap(tlv(14, b'\x00\x00'), 2, 14))
    add('pkcs7', eap_teap(tlv(15, b'\x30\x03\x02\x01\x00'), 1, 15))
    add('pkcs10', eap_teap(tlv(16, b'\x30\x03\x02\x01\x00'), 2, 15))
    add('trusted-root', eap_teap(tlv(17, b'\x30\x03\x02\x01\x00'), 1, 15))
    add('unassigned', eap_teap(tlv(0, b'\x00'), 1, 16))
    add('unknown-type', eap_teap(tlv(99, b'xyz', m=True, r=True), 1, 16))
    # Several TLVs in one packet
    add('multi', eap_teap(tlv(1, b'aid') + tlv(2, b'\x00\x01') + tlv(3, b'\x00\x01', m=True)
                          + tlv(12, crypto(3, 1)) + tlv(13, b'prompt'), 1, 17))
    # Exported PDU naming teap (second interface)
    add('exppdu-result', ('X', exp_pdu('teap', tlv(3, b'\x00\x01', m=True) + tlv(5, struct.pack('!I', 1))), 1))
    add('exppdu-pac', ('X', exp_pdu('teap', tlv(11, pattr(3, struct.pack('!I', 5))
                                                 + pattr(9, pattr(4, b'x')))), 1))
    # Fix reproducer, bounded: 600 nested PAC-Info levels, stays below the
    # old dissection-depth assertion but is beyond the new limit -> see malformed.
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    # The reproducer of "TEAP: ..." fix: PAC-Info nested 600 deep (EAPOL and Exported PDU)
    deep = tlv(11, pac_info(600))
    add('pacinfo-600-eapol', eap_teap(deep))
    add('pacinfo-600-exppdu', ('X', exp_pdu('teap', deep), 1))
    add('pacinfo-17', eap_teap(tlv(11, pac_info(17))))
    add('pacinfo-16', eap_teap(tlv(11, pac_info(15))))
    add('nak-nested-20', eap_teap(nested_nak(20)))
    add('nak-nested-600', eap_teap(nested_nak(600)))
    # request-action / intermediate-result / eap-payload nested the same way
    t = tlv(3, b'\x00\x01')
    for _ in range(40):
        t = tlv(8, b'\x01\x01' + t)
    add('request-action-40', eap_teap(t))
    t = tlv(3, b'\x00\x01')
    for _ in range(40):
        t = tlv(10, b'\x00\x01' + t)
    add('intermediate-40', eap_teap(t))
    # EAP-Payload holding an EAP-TEAP packet with outer TLVs, again and again
    inner = tlv(3, b'\x00\x01')
    for i in range(40):
        eapbody = bytes([0x11]) + struct.pack('!I', len(inner)) + inner
        e = struct.pack('!BBHB', 2, i & 255, 5 + len(eapbody), 55) + eapbody
        inner = tlv(9, e)
    add('eap-payload-40', eap_teap(inner))
    # Truncated TLVs: length past the end, header cut short
    add('truncated-tlv', eap_teap(struct.pack('!HH', 1, 100) + b'abc'))
    add('truncated-header', eap_teap(b'\x00\x03\x00'))
    add('truncated-crypto', eap_teap(tlv(12, b'\x00\x01\x01\x31' + b'A' * 10)))
    add('truncated-pwd', eap_teap(tlv(14, bytes([200]) + b'user')))
    add('truncated-pac-attr', eap_teap(tlv(11, struct.pack('!HH', 1, 500) + b'k' * 4)))
    add('truncated-eap-payload', eap_teap(tlv(9, b'\x02\x01\x00')))
    add('truncated-nak', eap_teap(tlv(4, b'\x00\x00\x00')))
    add('exppdu-trunc', ('X', exp_pdu('teap', b'\x00\x0b\x00\x10\x00\x03'), 1))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcapng(os.path.join(out, "teap-coverage.pcapng"),
                 [(f[1], None, 1) if isinstance(f, tuple) else (f, None, 0) for f in F], dlts=(1, 252))
    G, RM = malformed_frames()
    write_pcapng(os.path.join(out, 'teap-coverage-malformed.pcapng'),
                 [(f[1], None, 1) if isinstance(f, tuple) else (f, None, 0) for f in G], dlts=(1, 252))
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
