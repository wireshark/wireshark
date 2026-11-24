#!/usr/bin/env python3
# Generates test/captures/rpki_rtr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the RPKI-RTR coverage captures: mkrpki_rtr.py <outdir>
# Every packet is built with struct; nothing comes from a real network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pk import Cap, ip4, Tcp

def pdu(ver, typ, field, body=b'', length=None):
    '''RTR PDU: version, type, 16 bit field (session id/error/zero), length.'''
    if length is None:
        length = 8 + len(body)
    return struct.pack('!BBHI', ver, typ, field, length) + body

def serial_notify(ver, sid, serial):
    return pdu(ver, 0, sid, struct.pack('!I', serial))

def serial_query(ver, sid, serial):
    return pdu(ver, 1, sid, struct.pack('!I', serial))

def reset_query(ver):
    return pdu(ver, 2, 0)

def cache_response(ver, sid):
    return pdu(ver, 3, sid)

def ipv4_prefix(ver, flags, plen, maxlen, addr, asn):
    return pdu(ver, 4, 0, struct.pack('!BBBB4sI', flags, plen, maxlen, 0, ip4(addr), asn))

def ipv6_prefix(ver, flags, plen, maxlen, addr16, asn):
    return pdu(ver, 6, 0, struct.pack('!BBBB16sI', flags, plen, maxlen, 0, addr16, asn))

def end_of_data(ver, sid, serial, refresh=3600, retry=600, expire=7200):
    b = struct.pack('!I', serial)
    if ver >= 1:
        b += struct.pack('!III', refresh, retry, expire)
    return pdu(ver, 7, sid, b)

def cache_reset(ver):
    return pdu(ver, 8, 0)

# A made-up EC public key (placeholder bytes, not a real key)
def spki(seed):
    oid_ec = b'\x06\x07\x2a\x86\x48\xce\x3d\x02\x01'
    oid_p256 = b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07'
    alg = b'\x30' + bytes([len(oid_ec) + len(oid_p256)]) + oid_ec + oid_p256
    pt = b'\x00\x04' + bytes((seed + i) & 0xff for i in range(64))
    bs = b'\x03' + bytes([len(pt)]) + pt
    inner = alg + bs
    return b'\x30' + bytes([len(inner)]) + inner

def router_key(ver, flags, ski, asn, info):
    body = ski + struct.pack('!I', asn) + info
    return struct.pack('!BBBBI', ver, 9, flags, 0, 8 + len(body)) + body

def error_report(ver, code, bad_pdu, text):
    body = struct.pack('!I', len(bad_pdu)) + bad_pdu + struct.pack('!I', len(text)) + text
    return pdu(ver, 10, code, body)

def aspa(ver, flags, customer, providers):
    body = struct.pack('!I', customer) + b''.join(struct.pack('!I', p) for p in providers)
    return struct.pack('!BBBBI', ver, 11, flags, 0, 8 + len(body)) + body

def main(out):
    cap = Cap()
    # Version 0 session (RFC 6810) on TCP 323, one PDU per segment
    t = Tcp(cap, 40001, 323)
    t.handshake()
    t.s(serial_notify(0, 0x1234, 10))
    t.c(serial_query(0, 0x1234, 9))
    t.c(reset_query(0))
    t.s(cache_response(0, 0x1234))
    t.s(ipv4_prefix(0, 1, 24, 24, '198.51.100.0', 64496))
    t.s(ipv4_prefix(0, 0, 16, 24, '203.0.113.0', 64497))
    t.s(ipv6_prefix(0, 1, 32, 48, bytes.fromhex('20010db8000000000000000000000000'), 64498))
    t.s(ipv6_prefix(0, 0, 48, 64, bytes.fromhex('20010db8000100000000000000000000'), 4200000000))
    t.s(end_of_data(0, 0x1234, 10))
    t.s(cache_reset(0))
    t.c(error_report(0, 2, b'', b''))
    t.c(error_report(0, 4, reset_query(1), b'Unsupported Protocol Version'))
    t.c(error_report(0, 0, serial_query(0, 1, 2), b'Corrupt data'))
    t.fin()

    # Version 1 session (RFC 8210): intervals, router keys
    t = Tcp(cap, 40002, 323)
    t.handshake()
    t.c(reset_query(1))
    t.s(cache_response(1, 77))
    t.s(ipv4_prefix(1, 1, 8, 24, '10.0.0.0', 65000))
    t.s(router_key(1, 1, bytes(range(20)), 65001, spki(1)))
    t.s(router_key(1, 0, bytes(range(20, 40)), 65002, spki(9)))
    t.s(end_of_data(1, 77, 11, 1800, 300, 3600))
    t.c(serial_query(1, 77, 11))
    t.s(serial_notify(1, 77, 12))
    t.c(error_report(1, 8, b'\x01\x02\x00\x00\x00\x00\x00\x08', b'bad'))
    t.s(cache_reset(1))
    t.fin()

    # Version 2 (draft-ietf-sidrops-8210bis): ASPA
    t = Tcp(cap, 40003, 323)
    t.handshake()
    t.c(reset_query(2))
    t.s(cache_response(2, 5))
    t.s(aspa(2, 1, 64500, [64501, 64502, 64503]))
    t.s(aspa(2, 0, 64504, []))
    t.s(aspa(2, 1, 64505, [4200000001]))
    t.s(router_key(2, 1, bytes(range(40, 60)), 65003, spki(33)))
    t.s(end_of_data(2, 5, 1, 900, 120, 1800))
    t.fin()

    # Unknown PDU types (header only; and with a longer length) skipped
    t = Tcp(cap, 40005, 323)
    t.handshake()
    t.c(pdu(1, 5, 0))
    t.c(pdu(1, 12, 0))
    t.c(pdu(1, 200, 7, b'\0' * 8))

    # Several PDUs in one segment, and PDUs split across segments
    t = Tcp(cap, 40006, 323)
    t.handshake()
    t.s(cache_response(1, 9) + ipv4_prefix(1, 1, 24, 24, '192.0.2.0', 64511)
        + ipv6_prefix(1, 1, 64, 64, bytes.fromhex('20010db8ffff00000000000000000000'), 64512)
        + end_of_data(1, 9, 3))
    p = ipv6_prefix(1, 1, 56, 56, bytes.fromhex('20010db8aaaa00000000000000000000'), 64513)
    t.s(p[:3])         # the header is split
    t.s(p[3:20])
    t.s(p[20:])
    p = error_report(1, 1, cache_reset(1), b'a longer error text for the split case')
    t.s(p[:30])
    t.s(p[30:] + serial_notify(1, 9, 4))

    # Retransmission of a segment (TCP hands it over again)
    t = Tcp(cap, 40007, 323)
    t.handshake()
    t.s(end_of_data(1, 3, 4))
    t.sseq -= len(end_of_data(1, 3, 4))
    t.s(end_of_data(1, 3, 4))
    t.s(cache_reset(1))

    cap.write(os.path.join(out, 'rpki-rtr-coverage.pcap'))

    # Malformed
    cap = Cap()
    # Wrong version for Router Key (0) and ASPA (0 and 1): warnings only
    t = Tcp(cap, 41000, 323)
    t.handshake()
    t.s(router_key(0, 1, bytes(20), 65004, spki(1)))
    t.s(aspa(0, 1, 1, [2]))
    t.s(aspa(1, 1, 1, [2]))

    port = [41001]
    def one(data, trunc=None):
        t = Tcp(cap, port[0], 323)
        port[0] += 1
        t.handshake()
        t.s(data, trunc=trunc)
    # ASPA length below 12: provider count wraps, the items throw
    one(struct.pack('!BBBBI', 2, 11, 1, 0, 8) + struct.pack('!I', 1))
    one(struct.pack('!BBBBI', 2, 11, 1, 0, 12) + struct.pack('!I', 1))
    one(struct.pack('!BBBBI', 2, 11, 1, 0, 17) + struct.pack('!I', 1) + bytes(5))
    # Error report whose encapsulated PDU and text lengths run past the PDU
    one(pdu(1, 10, 0, struct.pack('!I', 1000) + b'\0' * 4))
    one(pdu(1, 10, 0, struct.pack('!I', 0) + struct.pack('!I', 0xffffffff) + b'abcd'))
    one(pdu(1, 10, 3, b'\0\0'))
    # Router Key PDU too short for its fields, and with a bad key
    one(struct.pack('!BBBBI', 1, 9, 1, 0, 12) + bytes(4))
    one(router_key(1, 1, bytes(20), 65004, b'\x30\x05\x01\x02'))
    one(router_key(1, 1, bytes(20), 65004, b'\xff'))
    # Serial notify with a short length, prefix PDUs that are too short
    one(pdu(1, 0, 1, b'', length=8))
    one(pdu(1, 4, 0, b'\x01\x18', length=10))
    one(pdu(1, 6, 0, b'\x01\x18\x18\x00' + bytes(6), length=18))
    one(pdu(1, 7, 0, b'\0\0\0\1', length=12))
    one(pdu(1, 7, 0, b'\0\0\0\1\0\0', length=14))
    # Length smaller than the header, huge length (waits for more data)
    one(struct.pack('!BBHI', 1, 2, 0, 4))
    one(struct.pack('!BBHI', 1, 12, 0, 0xfffffff0))
    one(struct.pack('!BBHI', 1, 12, 0, 0x7fffffff))
    # Unknown type whose length is smaller than the header
    one(struct.pack('!BBHI', 1, 99, 0, 2))
    # Short segment (header incomplete) and a truncated capture
    one(b'\x01\x02')
    one(end_of_data(1, 1, 1), trunc=6)
    cap.write(os.path.join(out, 'rpki-rtr-coverage-malformed.pcap'))

main(sys.argv[1])
