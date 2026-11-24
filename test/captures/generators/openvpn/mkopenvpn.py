#!/usr/bin/env python3
# Generates test/captures/openvpn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OpenVPN coverage captures: mkopenvpn.py <outdir>.
UDP and TCP port 1194 are registered by default. Nothing here is real
cryptography: the HMAC, data channel and wrapped client key octets are
made-up patterns (the dissector never checks them). tls-auth is found by
the dissector's own detection (a non-zero octet in the place of the array
length and few zero octets in the first four of the "HMAC")."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcap, udp, TCP, gz

CLI, SRV = '192.0.2.1', '192.0.2.2'
SID_C = 0x1122334455667788
SID_S = 0x99aabbccddeeff01

def pattern(n, seed=0x5a):
    return bytes(((seed + 7 * i) ^ (i >> 3)) & 0xff or 1 for i in range(n))

def hmac(n=20):
    return pattern(n, 0x31)

def op(opcode, key=0):
    return bytes([(opcode << 3) | key])

def control(opcode, sid, acks=(), rsid=None, mpid=None, payload=b'', auth=None, key=0, pid=1):
    """P_CONTROL / P_ACK / reset packets. auth: None, 'auth' (tls-auth with a
    20 octet HMAC) or ('auth', n) for an n octet HMAC."""
    b = op(opcode, key) + struct.pack('>Q', sid)
    if auth:
        n = 20 if auth == 'auth' else auth[1]
        b += hmac(n) + struct.pack('>II', pid, 1700000000 + pid)
    b += bytes([len(acks)]) + b''.join(struct.pack('>I', a) for a in acks)
    if acks:
        b += struct.pack('>Q', rsid)
    if opcode != 5 and mpid is not None:
        b += struct.pack('>I', mpid)
    return b + payload

def crypt(opcode, sid, wkc_len=None, data=b'', pid=1, trailing=b''):
    """tls-crypt packets: pid, time, a 32 octet made-up HMAC, then data."""
    b = op(opcode) + struct.pack('>Q', sid) + struct.pack('>II', pid, 1700000000 + pid) + hmac(32)
    return b + data + trailing

def wkc(n):
    """A made-up wrapped client key of n octets with its length in the last two."""
    return pattern(n - 2, 0x77) + struct.pack('>H', n)

def tls_clienthello():
    hello = struct.pack('>H', 0x0303) + pattern(32, 0x11) + b'\x00' + struct.pack('>H', 4) + b'\x13\x01\x13\x02' + b'\x01\x00' \
        + struct.pack('>H', 0)
    hs = b'\x01' + struct.pack('>I', len(hello))[1:] + hello
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs

def u(frames, data, to_server=True, sport=40500):
    if to_server:
        frames.append(udp(data, CLI, sport, SRV, 1194))
    else:
        frames.append(udp(data, SRV, 1194, CLI, sport))

def udp_session(fr):
    ch = tls_clienthello()
    u(fr, control(7, SID_C, mpid=0))                                                 # hard reset client v2
    u(fr, control(8, SID_S, acks=[0], rsid=SID_C, mpid=0), False)                    # hard reset server v2 with an ack
    u(fr, control(5, SID_C, acks=[0], rsid=SID_S))                                   # P_ACK
    u(fr, control(4, SID_C, mpid=1, payload=ch[:30]))                                # TLS ClientHello, first fragment
    u(fr, control(5, SID_S, acks=[1, 2], rsid=SID_C), False)                         # two acks
    u(fr, control(4, SID_C, mpid=2, payload=ch[30:]))                                # second fragment: reassembled
    u(fr, control(4, SID_S, acks=[2], rsid=SID_C, mpid=1, payload=b'\x16\x03\x03\x00\x04\x0e\x00\x00\x00'), False)   # ServerHelloDone
    u(fr, control(3, SID_C, mpid=3))                                                 # soft reset
    u(fr, control(1, SID_C, mpid=0, key=1))                                          # hard reset client v1
    u(fr, control(2, SID_S, mpid=0, key=1), False)                                   # hard reset server v1
    u(fr, op(6) + pattern(40))                                                       # P_DATA_V1
    u(fr, op(9) + b'\x00\x00\x07' + pattern(40, 0x20), False)                        # P_DATA_V2 with peer ID 7
    u(fr, op(9, 2) + b'\x00\x01\x00' + pattern(16, 0x21))                            # P_DATA_V2 key 2

def tlsauth_session(fr):
    ch = tls_clienthello()
    sp = 40501
    u(fr, control(7, SID_C + 1, mpid=0, auth='auth', pid=1), sport=sp)                        # tls-auth detected by content
    u(fr, control(8, SID_S + 1, acks=[0], rsid=SID_C + 1, mpid=0, auth='auth', pid=1), False, sp)
    u(fr, control(5, SID_C + 1, acks=[0], rsid=SID_S + 1, auth='auth', pid=2), sport=sp)
    u(fr, control(4, SID_C + 1, mpid=1, payload=ch, auth='auth', pid=3), sport=sp)
    u(fr, control(4, SID_C + 1, mpid=2, payload=b'\x17\x03\x03\x00\x08' + pattern(8), auth='auth', pid=4), sport=sp)

def tlscrypt_session(fr):
    sp = 40502
    u(fr, crypt(10, SID_C + 2, data=wkc(120), pid=1), sport=sp)                # P_CONTROL_HARD_RESET_CLIENT_V3 with the wrapped client key
    u(fr, crypt(10, SID_C + 2, data=wkc(2), pid=2), sport=sp)                  # smallest wrapped key
    u(fr, crypt(11, SID_C + 2, data=wkc(64), pid=3), sport=sp)                 # P_CONTROL_WKC_V1
    u(fr, crypt(10, SID_C + 2, pid=4), sport=sp)                               # nothing after the HMAC

def tcp_session(fr):
    c = TCP(CLI, 40600, SRV, 1194)
    fr += c.handshake()
    def framed(b):
        return struct.pack('>H', len(b)) + b
    ch = tls_clienthello()
    p1 = framed(control(7, SID_C + 3, mpid=0))
    fr.append(c.c2s(p1))
    fr.append(c.s2c(framed(control(8, SID_S + 3, acks=[0], rsid=SID_C + 3, mpid=0))))
    fr.append(c.c2s(framed(control(5, SID_C + 3, acks=[0], rsid=SID_S + 3))))
    m1 = framed(control(4, SID_C + 3, mpid=1, payload=ch[:50]))
    m2 = framed(control(4, SID_C + 3, mpid=2, payload=ch[50:]))
    fr.append(c.c2s(m1))
    fr.append(c.c2s(m2[:9]))                                   # a PDU split across TCP segments
    fr.append(c.c2s(m2[9:]))
    fr.append(c.s2c(framed(control(4, SID_S + 3, acks=[1, 2], rsid=SID_C + 3, mpid=1, payload=b'\x16\x03\x03\x00\x04\x0e\x00\x00\x00'))
                    + framed(op(6) + pattern(30))))            # two PDUs in one segment
    fr.append(c.c2s(framed(op(9) + b'\x00\x00\x02' + pattern(30))))

def malformed():
    fr = []
    sp = 40510
    # tls-crypt: wrapped key length of 0/1 and above the data, extra data before the key, one octet after the HMAC
    u(fr, crypt(10, SID_C + 4, data=pattern(20)), sport=sp)                                  # length read from the last two octets: illegal
    u(fr, crypt(10, SID_C + 4, data=b'\x00\x01'), sport=sp)                                  # length 1
    u(fr, crypt(10, SID_C + 4, data=b'\x07'), sport=sp)                                      # one octet only
    u(fr, crypt(11, SID_C + 4, data=pattern(30) + wkc(20)), sport=sp)                        # extra data before the key
    u(fr, control(5, SID_C + 5, acks=[0], rsid=SID_S, payload=b'\xaa\xbb\xcc'), sport=sp)    # P_ACK with extra data
    u(fr, control(5, SID_C + 5, acks=[1, 2, 3], rsid=SID_S)[:20], sport=sp)                  # truncated array
    u(fr, op(7) + b'\x01\x02\x03', sport=sp)                                                 # truncated session ID
    u(fr, op(9) + b'\x00', sport=sp)                                                         # truncated peer ID
    u(fr, op(14) + pattern(12, 0x40), sport=sp)                                              # unknown opcode 14
    u(fr, b'\x20', sport=sp)                                                                  # opcode only
    u(fr, control(7, SID_C + 6, auth='auth')[:34], sport=sp)                                  # truncated HMAC
    return fr

def main(out):
    fr = []
    udp_session(fr)
    tlsauth_session(fr)
    tlscrypt_session(fr)
    tcp_session(fr)
    pcap(os.path.join(out, 'openvpn-coverage.pcap'), fr)
    gz(os.path.join(out, 'openvpn-coverage.pcap'))
    pcap(os.path.join(out, 'openvpn-coverage-malformed.pcap'), malformed())

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
