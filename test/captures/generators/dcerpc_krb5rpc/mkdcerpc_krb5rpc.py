#!/usr/bin/env python3
# Generates test/captures/dcerpc_krb5rpc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the KRB5RPC DCE/RPC
dissector (packet-dcerpc-krb5rpc.c, DCE/RPC Kerberos V,
rsec_krb5rpc_sendto_kdc, which hands a Kerberos PDU to the Kerberos
dissector).

Connectionless DCE/RPC over UDP (as DCE security uses it) in both byte
orders, and connection-oriented DCE/RPC over TCP with a bind (little and
big endian). The DCE/RPC heuristics find the PDUs, so no Decode As is
needed. The Kerberos PDUs (AS-REQ, AS-REP, TGS-REQ, KRB-ERROR; no TGS-REP,
whose undecryptable enc-part gets a "missing keytype" warning)
are DER-encoded here; the ciphertexts are random-looking filler, nothing
is a real key or ticket. Every packet is built from scratch with struct
(dcelib.py); no captured traffic is used.

The first two frames are the reproducer krb5rpc_offset.pcap (generated
by krb5rpc_offset.py) for "KRB5RPC: Add the Kerberos length to the
offset": a request and response that a KRB-ERROR fills exactly.

Usage: mkdcerpc_krb5rpc.py <output directory>

Writes:
  dcerpc_krb5rpc-coverage.pcap            the calls
  dcerpc_krb5rpc-coverage-malformed.pcap  stubs cut short, a bad blob
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
HERE = os.path.dirname(os.path.abspath(__file__))
from dcelib import CL, CO, NDR, TCP, pcap  # noqa: E402
from repro import reproducer

UUID_KRB5RPC = '8f73de50-768c-11ca-bffc-08001e039431'
VER_KRB5RPC = (1, 0)
REALM = b'EXAMPLE.TEST'


# ---------------------------------------------------------------- DER
def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + ln + body


def ctx(n, body):
    return der(0xa0 + n, body)


def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big', signed=True)
    return der(0x02, b)


def seq(*items):
    return der(0x30, b''.join(items))


def gstr(s):
    return der(0x1b, s)


def ktime(s):
    return der(0x18, s)


def principal(ntype, *names):
    return seq(ctx(0, integer(ntype)), ctx(1, seq(*[gstr(n) for n in names])))


def encdata(etype, cipher, kvno=None):
    items = [ctx(0, integer(etype))]
    if kvno is not None:
        items.append(ctx(1, integer(kvno)))
    items.append(ctx(2, der(0x04, cipher)))
    return seq(*items)


def filler(n, seed):
    return bytes((seed * 31 + i * 17) & 0xff for i in range(n))


def ticket():
    return der(0x61, seq(ctx(0, integer(5)), ctx(1, gstr(REALM)),
                         ctx(2, principal(2, b'krbtgt', REALM)),
                         ctx(3, encdata(18, filler(64, 1), 2))))


def req_body(sname, opts=b'\x00\x40\x81\x00\x10'):
    return seq(ctx(0, der(0x03, opts)),
               ctx(1, principal(1, b'alice')),
               ctx(2, gstr(REALM)),
               ctx(3, sname),
               ctx(5, ktime(b'20370913024805Z')),
               ctx(6, ktime(b'20370913024805Z')),
               ctx(7, integer(0x1234567)),
               ctx(8, seq(integer(18), integer(17), integer(23))))


def as_req():
    # PA-PAC-REQUEST (128) { include-pac TRUE }
    pa = seq(seq(ctx(1, integer(128)), ctx(2, der(0x04, seq(ctx(0, der(0x01, b'\xff')))))))
    return der(0x6a, seq(ctx(1, integer(5)), ctx(2, integer(10)), ctx(3, pa),
                         ctx(4, req_body(principal(2, b'krbtgt', REALM)))))


def as_rep():
    return der(0x6b, seq(ctx(0, integer(5)), ctx(1, integer(11)),
                         ctx(3, gstr(REALM)), ctx(4, principal(1, b'alice')),
                         ctx(5, ticket()), ctx(6, encdata(18, filler(48, 2), 1))))


def tgs_req():
    ap_req = der(0x6e, seq(ctx(0, integer(5)), ctx(1, integer(14)),
                           ctx(2, der(0x03, b'\x00\x00\x00\x00\x00')),
                           ctx(3, ticket()), ctx(4, encdata(18, filler(40, 3)))))
    pa = seq(seq(ctx(1, integer(1)), ctx(2, der(0x04, ap_req))))
    return der(0x6c, seq(ctx(1, integer(5)), ctx(2, integer(12)), ctx(3, pa),
                         ctx(4, req_body(principal(2, b'host', b'server.example.test')))))


def krb_error(code, text=None):
    items = [ctx(0, integer(5)), ctx(1, integer(30)),
             ctx(4, ktime(b'20261101000000Z')), ctx(5, integer(0)),
             ctx(6, integer(code)), ctx(9, gstr(REALM)),
             ctx(10, principal(2, b'krbtgt', REALM))]
    if text is not None:
        items.append(ctx(11, der(0x1b, text)))
    return der(0x7e, seq(*items))


# ---------------------------------------------------------------- KRB5RPC
def sendto_kdc(rpc, le, req, resp, out_buf_len=4096):
    """request: len, then the message (shown as keysize and spare1 by the
    dissector); response: resp_len, max, offset, actual count, out_buf"""
    q = NDR(le)
    q.u32(len(req))
    q.u32(len(req))
    q.raw(req)
    r = None
    if resp is not None:
        r = NDR(le)
        r.u32(len(resp))
        r.u32(out_buf_len)
        r.u32(0)
        r.u32(len(resp))
        r.raw(resp)
        r = r.bytes()
    rpc.call(0, q.bytes(), r)


def krb5rpc_calls(rpc, le):
    sendto_kdc(rpc, le, as_req(), krb_error(25))      # KDC_ERR_PREAUTH_REQUIRED
    sendto_kdc(rpc, le, as_req(), as_rep())
    sendto_kdc(rpc, le, tgs_req(), krb_error(60, b'generic error'))  # KRB_ERR_GENERIC
    sendto_kdc(rpc, le, tgs_req(), krb_error(7))      # KDC_ERR_S_PRINCIPAL_UNKNOWN


def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    off, frames = 24, []
    while off < len(data):
        n = struct.unpack('<I', data[off + 8:off + 12])[0]
        frames.append(data[off + 16:off + 16 + n])
        off += 16 + n
    return frames


def main_frames():
    F = read_pcap(reproducer(os.path.join(HERE, 'krb5rpc_offset.py'), 'krb5rpc_offset.pcap'))
    for cport, le in ((40001, True), (40002, False)):
        rpc = CL(F, UUID_KRB5RPC, VER_KRB5RPC[0], le, cport=cport, sport=135)
        krb5rpc_calls(rpc, le)
    for cport, le in ((50001, True), (50002, False)):
        t = TCP(F, cport)
        rpc = CO(t, UUID_KRB5RPC, VER_KRB5RPC, le)
        rpc.bind()
        krb5rpc_calls(rpc, le)
        if le:
            # an opnum the interface does not have
            rpc.call(1, b'\0' * 8, b'\0' * 4)
        t.fin()
    return F


def malformed_frames():
    F = []
    rpc = CL(F, UUID_KRB5RPC, VER_KRB5RPC[0], cport=40101, sport=135)
    rpc.call(0, b'\x10\0\0\0', b'\x10\0\0\0\0\x10\0\0')       # cut in the header fields
    blob = as_req()
    sendto_kdc(rpc, True, blob[:40], krb_error(25)[:30])      # Kerberos PDUs cut short
    sendto_kdc(rpc, True, b'\x30\x03\x02\x01\x05', b'\xff' * 12)  # not a Kerberos PDU
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_krb5rpc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_krb5rpc-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
