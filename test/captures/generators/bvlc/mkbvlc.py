#!/usr/bin/env python3
# Generates test/captures/bvlc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BVLC and BSCVLC dissectors
(packet-bvlc.c, protocols "bvlc" and "bscvlc").

Every packet is built from scratch with struct; no captured traffic is used.
BVLC for BACnet/IP (Annex J, type 0x81) and BACnet/IPv6 (Annex U, type
0x82) is carried on UDP port 47808; BACnet/SC (BSCVLC) is carried in
WebSocket binary frames on two TCP connections upgraded from HTTP with the
subprotocols hub.bsc.bacnet.org and dc.bsc.bacnet.org. The whole capture
is Ethernet (linktype 1).

Usage: mkbvlc.py <output directory>

Writes:
  bvlc-coverage.pcap            every BVLC/IPv4, BVLC/IPv6 and BSCVLC
                                function, every header option, Secure-BVLL
                                (the fix on the branch) for IPv4 and IPv6
  bvlc-coverage-malformed.pcap  truncated messages, encrypted Secure-BVLL,
                                and the reproducer of
                                bvlc_secure_bvll_recursion.py
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
IP_BC = bytes([192, 0, 2, 255])
IP6_A = bytes.fromhex('20010db8000000000000000000000001')
IP6_B = bytes.fromhex('20010db8000000000000000000000002')
IP6_MC = bytes.fromhex('ff0200000000000000000000000bac0c')
PORT = 47808


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def eth(etype, payload, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(proto, l4, src, dst, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident & 0xffff, 0,
                      64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + l4


def udp4(payload, sport=PORT, dport=PORT, src=IP_A, dst=IP_B):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('>BBH', 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    return eth(0x0800, ipv4(17, udp, src, dst))


def udp6(payload, sport=PORT, dport=PORT, src=IP6_A, dst=IP6_B):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('>IxxxB', len(udp), 17)
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    ip = struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst
    return eth(0x86dd, ip + udp)


def tcp4(sport, dport, seq, ack, flags, payload, src, dst):
    opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''  # MSS, SACK permitted
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = src + dst + struct.pack('>BBH', 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('>H', csum(pseudo + hdr + payload)) + hdr[18:]
    return eth(0x0800, ipv4(6, hdr + payload, src, dst))


def write_pcap(path, frames):
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
    t = 1700000000
    for i, f in enumerate(frames):
        out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000,
                               len(f), len(f)) + f)
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


# BACnet payloads ----------------------------------------------------------

# NPDU version 1, control 0 (APDU, no DNET/SNET), Unconfirmed Who-Is
NPDU_WHOIS = bytes([0x01, 0x00, 0x10, 0x08])
# NPDU, Unconfirmed I-Am device 1234, max APDU 1476, segmentation none, vendor 7
NPDU_IAM = bytes([0x01, 0x00, 0x10, 0x00, 0xc4, 0x02, 0x00, 0x04, 0xd2,
                  0x22, 0x05, 0xc4, 0x91, 0x03, 0x21, 0x07])
# NPDU, network message Who-Is-Router-To-Network
NPDU_WHOISROUTER = bytes([0x01, 0x80, 0x00])


def bvlc4(func, body, length=None):
    if length is None:
        length = 4 + len(body)
    return bytes([0x81, func]) + struct.pack('>H', length) + body


def bvlc6(func, body, length=None):
    if length is None:
        length = 4 + len(body)
    return bytes([0x82, func]) + struct.pack('>H', length) + body


def wrapper(control=0x00, auth=None, dadr=b'', sadr=b''):
    """BACnet security wrapper, unencrypted: control, key revision, key id,
    source device, message id, timestamp, destination device, DNET, DLEN,
    DADR, SNET, SLEN, SADR and (control 0x10) authentication data."""
    w = bytes([control, 0x01]) + struct.pack('>H', 0x0101) + \
        (1234).to_bytes(3, 'big') + struct.pack('>II', 0x01020304, 1700000000) + \
        (5678).to_bytes(3, 'big') + struct.pack('>H', 0xffff) + bytes([len(dadr)]) + dadr + \
        struct.pack('>H', 0xffff) + bytes([len(sadr)]) + sadr
    if auth is not None:
        mech, data = auth
        w += bytes([mech]) + struct.pack('>H', 42) + bytes([3])
        if mech:
            w += struct.pack('>H', len(data)) + data
    return w


SIG = bytes(range(0xa0, 0xb0))   # 16 octet signature


def secure4(inner, control=0x00, auth=None, dadr=b'', sadr=b''):
    return bvlc4(0x0c, wrapper(control, auth, dadr, sadr) + inner + SIG)


def secure6(inner, control=0x00, auth=None):
    return bvlc6(0x0b, wrapper(control, auth) + inner + SIG)


V_A = (0x0a0b0c).to_bytes(3, 'big')   # virtual addresses (Annex U)
V_B = (0x0d0e0f).to_bytes(3, 'big')
B6 = IP6_A + struct.pack('>H', PORT)  # B/IPv6 address


def ipv4_frames():
    f = []
    # BVLC-Result with every result code, and an unknown one
    for r in (0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70):
        f.append(udp4(bvlc4(0x00, struct.pack('>H', r)), src=IP_B, dst=IP_A))
    bdt = [(IP_A, PORT, b'\xff\xff\xff\xff'), (bytes([198, 51, 100, 7]), 47809,
                                                b'\xff\xff\xff\x00')]
    bdt = b''.join(ip + struct.pack('>H', p) + m for ip, p, m in bdt)
    # Write-Broadcast-Distribution-Table with two entries
    f.append(udp4(bvlc4(0x01, bdt)))
    # Read-Broadcast-Distribution-Table
    f.append(udp4(bvlc4(0x02, b'')))
    # Read-Broadcast-Distribution-Table-Ack: two entries, empty table
    f.append(udp4(bvlc4(0x03, bdt), src=IP_B, dst=IP_A))
    f.append(udp4(bvlc4(0x03, b''), src=IP_B, dst=IP_A))
    # Forwarded-NPDU from 198.51.100.7:47809 (I-Am)
    f.append(udp4(bvlc4(0x04, bytes([198, 51, 100, 7]) + struct.pack('>H', 47809) + NPDU_IAM),
                  src=IP_B, dst=IP_BC))
    # Register-Foreign-Device, TTL 300 s
    f.append(udp4(bvlc4(0x05, struct.pack('>H', 300))))
    # Read-Foreign-Device-Table and its Ack with two entries
    f.append(udp4(bvlc4(0x06, b'')))
    fdt = IP_A + struct.pack('>HHH', PORT, 300, 330) + \
        bytes([203, 0, 113, 9]) + struct.pack('>HHH', 47810, 60, 12)
    f.append(udp4(bvlc4(0x07, fdt), src=IP_B, dst=IP_A))
    # Delete-Foreign-Device-Table-Entry
    f.append(udp4(bvlc4(0x08, bytes([203, 0, 113, 9]) + struct.pack('>H', 47810))))
    # Distribute-Broadcast-To-Network, Original-Unicast, Original-Broadcast
    f.append(udp4(bvlc4(0x09, NPDU_WHOIS)))
    f.append(udp4(bvlc4(0x0a, NPDU_IAM)))
    f.append(udp4(bvlc4(0x0b, NPDU_WHOISROUTER), dst=IP_BC))
    # Secure-BVLL (unencrypted wrapper) carrying an Original-Unicast-NPDU:
    # the fix on the branch dissects the inner BVLL after the wrapper
    f.append(udp4(secure4(bvlc4(0x0a, NPDU_WHOIS))))
    # Secure-BVLL with DADR/SADR and authentication data (mechanism 1)
    f.append(udp4(secure4(bvlc4(0x0b, NPDU_IAM), control=0x13,
                          auth=(1, b'\x11\x22\x33\x44'), dadr=b'\x05', sadr=b'\x06\x07')))
    # Secure-BVLL with authentication mechanism 0 (no data) carrying a BVLC-Result
    f.append(udp4(secure4(bvlc4(0x00, b'\x00\x00'), control=0x10, auth=(0, b''))))
    # Secure-BVLL inside a Secure-BVLL: the inner one is not decoded
    f.append(udp4(secure4(bvlc4(0x0c, b'\x00' * 8))))
    # Unknown function 0x0d with payload (data)
    f.append(udp4(bvlc4(0x0d, b'\xde\xad\xbe\xef')))
    # BVLC length shorter than the UDP payload ("invalid length")
    f.append(udp4(bvlc4(0x0a, NPDU_WHOIS) + b'\x00\x00', ))
    # Rejected: length 2 (shorter than the header), unknown BVLC type 0x83
    f.append(udp4(bvlc4(0x00, b'\x00\x00', length=2)))
    f.append(udp4(bytes([0x83, 0x0a, 0x00, 0x08]) + NPDU_WHOIS))
    return f


def ipv6_frames():
    f = []
    # BVLC-Result with every result code and an unknown one
    for r in (0x00, 0x30, 0x60, 0x90, 0xa0, 0xc0, 0xff):
        f.append(udp6(bvlc6(0x00, V_B + struct.pack('>H', r)), src=IP6_B, dst=IP6_A))
    # Original-Unicast-NPDU, Original-Broadcast-NPDU
    f.append(udp6(bvlc6(0x01, V_A + V_B + NPDU_IAM)))
    f.append(udp6(bvlc6(0x02, V_A + NPDU_WHOIS), dst=IP6_MC))
    # Address-Resolution, Forwarded-Address-Resolution, Address-Resolution-ACK
    f.append(udp6(bvlc6(0x03, V_A + V_B), dst=IP6_MC))
    f.append(udp6(bvlc6(0x04, V_A + V_B + B6), dst=IP6_MC))
    f.append(udp6(bvlc6(0x05, V_B + V_A), src=IP6_B, dst=IP6_A))
    # Virtual-Address-Resolution and its ACK
    f.append(udp6(bvlc6(0x06, V_A)))
    f.append(udp6(bvlc6(0x07, V_B + V_A), src=IP6_B, dst=IP6_A))
    # Forwarded-NPDU
    f.append(udp6(bvlc6(0x08, V_A + B6 + NPDU_WHOIS), src=IP6_B, dst=IP6_MC))
    # Register-Foreign-Device, Delete-Foreign-Device-Table-Entry
    f.append(udp6(bvlc6(0x09, V_A + struct.pack('>H', 600))))
    f.append(udp6(bvlc6(0x0a, V_A + B6)))
    # Secure-BVLL carrying an Original-Unicast-NPDU (the fix on the branch)
    f.append(udp6(secure6(bvlc6(0x01, V_A + V_B + NPDU_WHOIS))))
    # Secure-BVLL with authentication data carrying a Register-Foreign-Device
    f.append(udp6(secure6(bvlc6(0x09, V_A + struct.pack('>H', 60)), control=0x10,
                          auth=(2, b'\x01\x02'))))
    # Secure-BVLL inside a Secure-BVLL
    f.append(udp6(secure6(bvlc6(0x0b, b'\x00' * 8))))
    # Distribute-Broadcast-To-Network
    f.append(udp6(bvlc6(0x0c, V_A + NPDU_WHOISROUTER)))
    # Unknown function 0x0d (no fixed header length) with data
    f.append(udp6(bvlc6(0x0d, b'\x01\x02\x03')))
    # BVLC length shorter than the UDP payload
    f.append(udp6(bvlc6(0x01, V_A + V_B + NPDU_WHOIS) + b'\x00'))
    # Rejected: length 4 for Forwarded-NPDU (needs 28)
    f.append(udp6(bvlc6(0x08, b'\x00' * 6, length=4)))
    return f


# BACnet/SC over WebSocket -------------------------------------------------

def opt(otype, data=None, more=False, must=False):
    b = otype & 0x1f
    if more:
        b |= 0x80
    if must:
        b |= 0x40
    if data is None:
        return bytes([b])
    return bytes([b | 0x20]) + struct.pack('>H', len(data)) + data


def bsc(func, msgid, body=b'', orig=None, dest=None, dopts=None, opts=None, ctrl_extra=0):
    ctrl = ctrl_extra
    hdr = b''
    if orig is not None:
        ctrl |= 0x08
        hdr += orig
    if dest is not None:
        ctrl |= 0x04
        hdr += dest
    if dopts is not None:
        ctrl |= 0x02
        hdr += dopts
    if opts is not None:
        ctrl |= 0x01
        hdr += opts
    return bytes([func, ctrl]) + struct.pack('>H', msgid) + hdr + body


VMAC_HUB = bytes.fromhex('0a0000000001')
VMAC_N1 = bytes.fromhex('0a0000000002')
VMAC_N2 = bytes.fromhex('0a0000000003')
UUID1 = bytes(range(0x10, 0x20))
UUID2 = bytes(range(0x20, 0x30))

# Hint option data: an authorization scope with standard bits (context 1,
# bit string) and an extended scope (opening tag 0, character string, closing)
HINT = bytes([0x1a, 0x04, 0xa0]) + bytes([0x0e, 0x75, 0x04, 0x00, 0x61, 0x62, 0x63, 0x0f])
# Token option data: issuer (context 0, unsigned 5), key-id (context 8, 2)
TOKEN = bytes([0x09, 0x05, 0x89, 0x02])


def bsc_messages_hub():
    """Node 1 <-> hub, subprotocol hub.bsc.bacnet.org. (from_client, payload)"""
    m = []
    # Connect-Request with a destination hello option (identity relay)
    m.append((True, bsc(0x06, 1, VMAC_N1 + UUID1 + struct.pack('>HH', 1600, 1497),
                        dopts=opt(0x02, b'\x01', must=True))))
    m.append((False, bsc(0x07, 1, VMAC_HUB + UUID2 + struct.pack('>HH', 1600, 1497))))
    # Advertisement-Solicitation and Advertisement (hub states 0, 1, 2, 3)
    m.append((True, bsc(0x05, 2, dest=VMAC_HUB)))
    for st, acc in ((0, 0), (1, 1), (2, 0), (3, 2)):
        m.append((False, bsc(0x04, 2 + st, bytes([st, acc]) + struct.pack('>HH', 1600, 1497),
                             orig=VMAC_HUB)))
    # Encapsulated-NPDU: originating and destination VMAC, destination
    # options (hello, proprietary with data, reserved type 6 without data)
    # and data options (secure path, identity, hint, token, proprietary)
    dopts = opt(0x02, b'\x00', more=True) + opt(0x1f, b'\x00\x07\x01\xaa', more=True, must=True) + \
        opt(0x06)
    dopts_end = opt(0x01, more=True) + opt(0x03, (1234).to_bytes(3, 'big'), more=True) + \
        opt(0x04, HINT, more=True) + opt(0x05, TOKEN, more=True, must=True) + \
        opt(0x1f, b'\x00\x07\x02', more=True) + opt(0x09, b'\x01')
    m.append((True, bsc(0x01, 10, NPDU_IAM, orig=VMAC_N1, dest=VMAC_N2,
                        dopts=dopts, opts=dopts_end)))
    # Encapsulated-NPDU from node 2, secure path data option
    m.append((False, bsc(0x01, 11, NPDU_WHOIS, orig=VMAC_N2, opts=opt(0x01))))
    # Destination option list with every option type in the destination
    # list (secure path, identity, hint, token without/with data)
    dopts = opt(0x01, more=True) + opt(0x03, (99).to_bytes(3, 'big'), more=True) + \
        opt(0x04, HINT, more=True) + opt(0x05, TOKEN, more=True) + opt(0x1e, b'\x55')
    m.append((True, bsc(0x01, 12, NPDU_WHOISROUTER, dest=VMAC_N2, dopts=dopts)))
    # Data option with hello (not a data option, still decoded)
    m.append((True, bsc(0x01, 13, NPDU_WHOIS, opts=opt(0x02, b'\x01'))))
    # Reserved control bits set
    m.append((True, bsc(0x01, 14, NPDU_WHOIS, ctrl_extra=0xf0)))
    # Address-Resolution and Address-Resolution-ACK with WebSocket URIs
    m.append((True, bsc(0x02, 20, dest=VMAC_N2)))
    m.append((False, bsc(0x03, 20, b'wss://192.0.2.3:4443/ wss://[2001:db8::3]/',
                         orig=VMAC_N2, dest=VMAC_N1)))
    # BVLC-Result: ACK, and NAK with error class, code and details
    m.append((False, bsc(0x00, 21, bytes([0x02, 0x00]))))
    m.append((False, bsc(0x00, 22, bytes([0x02, 0x01, 0x00]) + struct.pack('>HH', 7, 0x88) +
                         b'address resolution failed')))
    m.append((False, bsc(0x00, 23, bytes([0x0c, 0x01, 0x00]) + struct.pack('>HH', 0x40, 0x7fff))))
    # Heartbeat-Request/ACK; the request's data option list says more
    # options follow but is ended by a zero octet (shown as data), the
    # ACK's option list by the end of the message
    m.append((True, bsc(0x0a, 30, b'\x00', opts=opt(0x01, more=True))))
    m.append((False, bsc(0x0b, 30, dopts=opt(0x1f, more=True))))
    # Proprietary-Message, vendor 7
    m.append((True, bsc(0x0c, 31, struct.pack('>H', 7) + b'\x01' + b'vendor data')))
    # Unknown function 0x0d with payload
    m.append((True, bsc(0x0d, 32, b'\x01\x02\x03')))
    # Too short (3 octets): not BSCVLC
    m.append((True, b'\x0a\x00\x00'))
    # Disconnect-Request/ACK
    m.append((True, bsc(0x08, 40)))
    m.append((False, bsc(0x09, 40)))
    return m


def bsc_messages_dc():
    """Node 1 <-> node 2 direct connection, subprotocol dc.bsc.bacnet.org."""
    return [
        (True, bsc(0x06, 1, VMAC_N1 + UUID1 + struct.pack('>HH', 9000, 8000))),
        (False, bsc(0x07, 1, VMAC_N2 + UUID2 + struct.pack('>HH', 9000, 8000))),
        (True, bsc(0x01, 2, NPDU_WHOIS)),
        (True, bsc(0x08, 3)),
        (False, bsc(0x09, 3)),
    ]


def ws_frame(payload, masked, key=b'\x12\x34\x56\x78', opcode=0x2):
    b0 = 0x80 | opcode
    n = len(payload)
    if n < 126:
        hdr = bytes([b0, (0x80 if masked else 0) | n])
    else:
        hdr = bytes([b0, (0x80 if masked else 0) | 126]) + struct.pack('>H', n)
    if masked:
        payload = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
        hdr += key
    return hdr + payload


def websocket_conn(cport, subproto, messages, client=bytes([192, 0, 2, 10]),
                   server=bytes([192, 0, 2, 20])):
    f = []
    cseq, sseq = 1000, 5000
    f.append(tcp4(cport, 80, cseq, 0, 0x02, b'', client, server))
    f.append(tcp4(80, cport, sseq, cseq + 1, 0x12, b'', server, client))
    cseq += 1
    sseq += 1
    f.append(tcp4(cport, 80, cseq, sseq, 0x10, b'', client, server))

    def c2s(p):
        nonlocal cseq
        f.append(tcp4(cport, 80, cseq, sseq, 0x18, p, client, server))
        cseq += len(p)

    def s2c(p):
        nonlocal sseq
        f.append(tcp4(80, cport, sseq, cseq, 0x18, p, server, client))
        sseq += len(p)

    c2s(('GET /bacnet HTTP/1.1\r\nHost: 192.0.2.20\r\nUpgrade: websocket\r\n'
         'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
         'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n' % subproto).encode())
    s2c(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
         'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n'
         'Sec-WebSocket-Protocol: %s\r\n\r\n' % subproto).encode())
    for from_client, p in messages:
        if from_client:
            c2s(ws_frame(p, True))
        else:
            s2c(ws_frame(p, False))
    return f


# Malformed ----------------------------------------------------------------

def malformed_frames():
    f = []
    # IPv4: 3 octets (no length), BDT shorter than its length, FDT entry cut,
    # Register-Foreign-Device without TTL, Forwarded-NPDU without address
    f.append(udp4(b'\x81\x0a\x00'))
    f.append(udp4(bvlc4(0x01, b'\x00' * 6, length=14)))
    f.append(udp4(bvlc4(0x07, b'\x00' * 5, length=14)))
    f.append(udp4(bvlc4(0x05, b'')))
    f.append(udp4(bvlc4(0x08, b'\x00\x00')))
    f.append(udp4(bvlc4(0x04, b'\x00\x00', length=10)))
    # Secure-BVLL: wrapper cut short, encrypted wrapper, wrapper without
    # room for the signature
    f.append(udp4(bvlc4(0x0c, wrapper()[:10])))
    f.append(udp4(bvlc4(0x0c, bytes([0x40]) + wrapper()[1:15] + b'\xee' * 8 + SIG)))
    f.append(udp4(bvlc4(0x0c, wrapper() + b'\x00' * 4)))
    # IPv6: header cut, Forwarded-Address-Resolution cut, encrypted Secure-BVLL
    f.append(udp6(b'\x82\x01'))
    f.append(udp6(bvlc6(0x04, V_A + V_B + IP6_A[:4], length=28)))
    f.append(udp6(bvlc6(0x0b, bytes([0x40]) + wrapper()[1:15] + b'\xee' * 8 + SIG)))
    f.append(udp6(bvlc6(0x0b, wrapper()[:12])))
    # Inner BVLL of a Secure-BVLL with a length past its end
    f.append(udp4(secure4(bvlc4(0x0a, NPDU_WHOIS, length=40))))
    f.append(udp6(secure6(bvlc6(0x01, V_A + V_B + NPDU_WHOIS, length=40))))
    # The reproducer of bvlc_secure_bvll_recursion.py: a
    # 9000 octet Secure-BVLL (IPv4 and IPv6) of zeros after the wrapper
    w = bytes([0x00, 0x01]) + b'\0\x01' + b'\0\0\x01' + b'\0\0\0\x01' + \
        b'\0\0\0\x01' + b'\0\0\x02' + b'\xff\xff' + b'\x00' + b'\xff\xff' + b'\x00'
    v4 = bytes([0x81, 0x0c]) + struct.pack('!H', 4) + w
    v4 += b'\0' * (9000 - len(v4))
    v6 = bytes([0x82, 0x0b]) + struct.pack('!H', 4) + w
    v6 += b'\0' * (9000 - len(v6))
    rep4 = udp4(v4)
    rep6 = udp6(v6)
    # The original uses fixed MAC/IP fields; only the BVLC payload matters
    f.append(rep4)
    f.append(rep6)
    # BSCVLC: option with a data length past the end, Connect-Request cut,
    # BVLC-Result NAK cut, Advertisement cut
    bad = []
    bad.append((True, bsc(0x01, 1, b'', dopts=b'\x22\x00\x40\x01')))
    bad.append((True, bsc(0x01, 2, b'', opts=b'\x24\x00\x10\x1a')))
    bad.append((True, bsc(0x06, 3, VMAC_N1)))
    bad.append((False, bsc(0x00, 4, b'\x02\x01\x00\x00')))
    bad.append((False, bsc(0x04, 5, b'\x01')))
    bad.append((True, bsc(0x0c, 6, b'\x00')))
    bad.append((True, bsc(0x01, 7, b'', orig=VMAC_N1[:3])))
    f += websocket_conn(50001, 'hub.bsc.bacnet.org', bad)
    return f


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = ipv4_frames() + ipv6_frames()
    frames += websocket_conn(49152, 'hub.bsc.bacnet.org', bsc_messages_hub())
    frames += websocket_conn(49153, 'dc.bsc.bacnet.org', bsc_messages_dc(),
                             server=bytes([192, 0, 2, 30]))
    write_pcap(os.path.join(outdir, 'bvlc-coverage.pcap'), frames)
    write_pcap(os.path.join(outdir, 'bvlc-coverage-malformed.pcap'), malformed_frames())
    print(len(frames), 'frames')


if __name__ == '__main__':
    main()
