#!/usr/bin/env python3
# Generates test/captures/dof_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DOF dissector
(packet-dof.c, Distributed Object Framework).

DOF runs over UDP 3567 and 5567, TCP 3567 and, as the DOF tunnel, over
TCP 8567. A DOF PDU is a DNP (network) header, a DPP (presentation)
header and an application PDU: DSP (app 0), OAP (app 1), TEP (128),
TRP (129), SGMP (130) or the DPP common commands (app 0x7FFF). Every
packet is built from scratch with struct; nothing comes from a real
network. Addresses are from the documentation ranges and 10/8.

Frames 1-303 need no keys. The TRP responses there carry "tickets"
(Security.5) that are 64 constant 0x00 octets used as placeholders.
Frames 304 on cover the security code: a TEP session key exchange, the
CCM security mode (AES-CCM ciphertext and HMAC-SHA256 confirmations
computed with the Python 'cryptography' library from made-up test keys),
the key and identity secret tables, TRP identity matching and SGMP. The
dissector decrypts them only with its tables filled in:
  -o 'uat:custom_dof_seckey_list:"<session key>"'
  -o 'uat:custom_dof_identsecret_list:"<domain>","<identity>","<secret>"'
(mkdof.py -k prints the values).

Usage: mkdof.py <output directory> [-v]   (-v prints the frame ranges)
       mkdof.py -k                        prints the UAT values

Writes:
  dof-coverage.pcapng            main capture (Ethernet and Exported PDU)
  dof-coverage-malformed.pcapng  paths only malformed input reaches
"""

import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# ---------------------------------------------------------------- pcapng

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is Ethernet,
    interface 1 Exported PDU. Timestamps advance 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_EXPPDU, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


# ------------------------------------------------------------ IP/UDP/TCP

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    a = ip4(addr)
    if a[0] == 224:
        return bytes([0x01, 0x00, 0x5e, a[1] & 0x7f, a[2], a[3]])
    return bytes([2, 0]) + a


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'           # MSS
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


# --------------------------------------------------------- DOF encodings

def c2(v, n=None):
    """Compressed 16 bit (Type.1)."""
    if n is None:
        n = 1 if v < 0x80 else 2
    return bytes([v]) if n == 1 else struct.pack('!H', 0x8000 | v)


def c3(v, n=None):
    """Compressed 24 bit (Type.2)."""
    if n is None:
        n = 1 if v < 0x80 else 2 if v < 0x4000 else 3
    if n == 1:
        return bytes([v])
    if n == 2:
        return struct.pack('!H', 0x8000 | v)
    return struct.pack('!I', 0xC00000 | v)[1:]


def c4(v, n=None):
    """Compressed 32 bit (Type.3)."""
    if n is None:
        n = 1 if v < 0x80 else 2 if v < 0x4000 else 4
    if n == 1:
        return bytes([v])
    if n == 2:
        return struct.pack('!H', 0x8000 | v)
    return struct.pack('!I', 0xC0000000 | v)


def oid(cls, data=b'', attrs=(), cls_len=None):
    """Object ID (Type.4): class, header (attribute bit, length), data,
    then attributes (Type.5) as (id, value) pairs."""
    hdr = len(data) | (0x80 if attrs else 0)
    out = c4(cls, cls_len) + bytes([hdr]) + data
    for i, (aid, val) in enumerate(attrs):
        more = 0x80 if i + 1 < len(attrs) else 0
        out += bytes([aid | more, len(val)]) + val
    return out


def iid(code, data):
    """Interface ID: registry octet (low two bits: length code), data."""
    return bytes([code]) + data


def dnp(body, flags=0x0c, src=1, dst=2, lensize=None, version=1):
    """DNPv1. flags None: default flags (one header octet). Otherwise the
    flags octet, a length field of 'lensize' octets (default: 1 if any
    length bits in flags) and the source/destination addresses."""
    if flags is None:
        return bytes([version]) + body
    ports = b''
    if flags & 0x04:
        ports += c3(src)
    if flags & 0x08:
        ports += c3(dst)
    size = flags & 0x03
    length = len(ports) + len(body)
    lf = length.to_bytes(size, 'big') if size else b''
    return bytes([0x80 | version, flags]) + lf + ports + body


def dpp(app, flags=None, seq=None, retry=None, delay=0, opid=b'', sec=b''):
    """DPPv2 header and the application PDU. flags None: default flags
    (command, no operation ID), one delay octet."""
    if flags is None:
        return b'\x02' + bytes([delay]) + app
    out = bytes([0x82, flags]) + opid
    if not flags & 0x10:
        if flags & 0x04:
            out += bytes([seq])
        if flags & 0x02:
            out += bytes([retry])
        out += bytes([delay])
    if flags & 0x80:
        out += sec
    return out + app


RSP = 0x10          # DPP flags: response
APP_DPP = b'\xff\xff'


def dof(app, dflags=None, **kw):
    """DNP (ports 1 -> 2) + DPP + app."""
    return dnp(dpp(app, dflags, **kw))


def dof_rsp(app, **kw):
    """Server response: DNP ports 2 -> 1, DPP response flag."""
    return dnp(dpp(app, RSP, **kw), src=2, dst=1)


# Object IDs used throughout
OID_A = oid(1, b'\x0a\x0b\x0c\x0d')                          # non printable
OID_P = oid(3, b'abcd')                                       # printable
OID_ESC = oid(0x22, b'a(b)[c]{d}\\e|f')                       # escaped chars
OID_ATTR = oid(1, b'\x01\x02', [(2, oid(3, b'xyz')), (1, b'\x99'), (5, b'zz')])
OID_NEST = oid(0x90, b'node', [(0, oid(4, b'in', [(2, oid(5, b'deep'))]))], cls_len=2)
OID_BIG = oid(0x123456, b'\xfe', [(3, b'\x00\x05')])            # 4 octet class, attribute not an OID
OID_HUGE = oid(0x3A000000, b'h')                                # class >= 0x01000000
OID_BCAST = oid(0)                                              # broadcast, no data
OID_BCAST_BAD = oid(0, b'x')                                    # broadcast with data: "Illegal OID"
OID_EMPTY_ATTR = oid(7, b'', [(9, b'')])                        # no data, empty attribute
OID_MID = oid(0x0234, b'm', [(3, b'\xc0\x01'), (3, b'\x01\x81\x41'), (3, b'\x01\x01\x41\x99')])
                                    # 2 octet class >= 0x100; attribute values that are not OIDs:
                                    # class cut short, attribute missing, trailing octet

IID1 = iid(0x01, b'\x22')
IID2 = iid(0x02, b'\x12\x34')
IID4 = iid(0x07, b'\x01\x02\x03\x04')
IID16 = iid(0x00, bytes(range(16)))


# ----------------------------------------------------------- main capture

def udp_c(payload, cli='192.0.2.1', cport=40000, srv='192.0.2.2', sport=3567):
    return udp(payload, cli, cport, srv, sport)


def udp_s(payload, cli='192.0.2.1', cport=40000, srv='192.0.2.2', sport=3567):
    return udp(payload, srv, sport, cli, cport)


def basics():
    """DNP and DPP headers, DPP common commands, security header."""
    f = []
    cli, srv = '192.0.2.1', '192.0.2.2'
    # DNPv0 query, query with padding, query responses
    f.append(udp_c(b'\x00'))
    f.append(udp_c(b'\x00\x00\x00\x00'))
    f.append(udp_s(b'\x00\x01\x02\x00\x00'))
    f.append(udp_s(b'\x00\x01'))
    f.append(udp_c(b'\x80'))                       # DNPv0 with the flag bit
    # Unknown DNP version
    f.append(udp_c(b'\x05\x02\x00'))
    # DPPv0 query (DNP default flags), query responses
    f.append(udp_c(b'\x01\x00'))
    f.append(udp_s(b'\x01\x00\x02\x01'))
    f.append(udp_s(b'\x01\x80\x02\x00\x07'))
    # Unknown DPP version
    f.append(udp_c(b'\x01\x05\x00'))
    # DNPv1 length sizes and address encodings
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03'), flags=0x00)))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03'), flags=0x01, src=0x90)))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03'), flags=0x0e, src=0x90, dst=0x5000)))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03'), flags=0x0f, src=0x123456, dst=3)))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03'), flags=0x0b, dst=0x4001)))
    # DPP flags: sequence, retry, long delay, default flags included
    f.append(udp_c(dof(APP_DPP + b'\x03', 0x06, seq=5, retry=2, delay=200)))
    f.append(udp_c(dof(APP_DPP + b'\x03', 0x00, delay=10)))
    f.append(udp_c(dof(APP_DPP + b'\x05', 0x04, seq=6, delay=128)))
    # DPP common commands
    sid = OID_A
    f.append(udp_c(dof(APP_DPP + b'\x00' + sid)))                 # node down
    f.append(udp_c(dof(APP_DPP + b'\x01' + sid + c4(5))))        # source lost
    f.append(udp_c(dof(APP_DPP + b'\x08' + sid + c4(0x1234))))   # source found
    f.append(udp_c(dof(APP_DPP + b'\x02' + sid + c4(0x50000))))  # rename
    f.append(udp_c(dof(APP_DPP + b'\x03')))                      # ping
    f.append(udp_c(dof(APP_DPP + b'\x05')))                      # heartbeat
    f.append(udp_c(dof(APP_DPP + b'\x06')))                      # query
    f.append(udp_c(dof(APP_DPP + b'\x04' + sid)))                # cancel all
    f.append(udp_c(dof(APP_DPP + b'\x07')))                      # unknown
    f.append(udp_s(dof_rsp(APP_DPP + b'\x06' + OID_P)))          # query response
    f.append(udp_s(dof_rsp(APP_DPP + b'\x03')))                  # ping response
    # Unknown application, two octet application ID
    f.append(udp_c(dof(c2(0x50) + b'\x01\x02')))
    f.append(udp_c(dof(c2(0x1234) + b'\x01')))
    # Security header without the security mode header: SSID (1, 2 and 4
    # octets), AS, remote domain with a remote security scope, partition
    scope = c2(4) + c4(1) + c4(0x3FFFFFFF) + c4(0x3FFFFFFE) + c4(0x3FFFFFFD)
    f.append(udp_c(dof(APP_DPP + b'\x03', 0x80, delay=0, sec=b'\x01' + c4(5))))
    f.append(udp_c(dof(APP_DPP + b'\x03', 0x80, delay=0, sec=b'\x03' + c4(0x1234))))
    f.append(udp_c(dof(APP_DPP + b'\x03', 0x80, delay=0,
                       sec=b'\x0d' + c4(0x123456) + c4(0x77) + scope + c2(1) + c4(0x5000))))
    f.append(udp_s(dof_rsp(APP_DPP + b'\x03', sec=b'\x04' + c2(0))))
    f.append(udp_s(dof_rsp(APP_DPP + b'\x03', sec=b'\x00')))
    # UDP multicast (not 2 node) on 5567, and a reply from the server port
    f.append(udp(dnp(dpp(APP_DPP + b'\x05'), flags=None), '192.0.2.5', 40005, '224.0.1.200', 5567))
    f.append(udp(dnp(dpp(APP_DPP + b'\x05')), '192.0.2.6', 5567, '192.0.2.5', 40005))
    return f


def sid_learning():
    """About 120 packets: SIDs learned from Source Lost, shown on later
    packets, the receiver SID, SID IDs merged when two senders turn out to
    have the same SID, explicit operation IDs, operation tracking and a
    SID too long to be learned."""
    f = []
    srv = '10.1.255.1'
    n = 30
    sids = [oid(1, b'node%02d' % i) for i in range(n)]

    def cli(i):
        return '10.1.0.%d' % (i + 1)
    # Every client announces its SID (Source Lost names the SID too)
    for i in range(n):
        f.append(udp(dnp(dpp(APP_DPP + b'\x01' + sids[i] + c4(i)), flags=None),
                     cli(i), 40000, srv, 3567))
    # Later packets show the learned SID
    for i in range(n):
        f.append(udp(dnp(dpp(APP_DPP + b'\x03'), flags=None), cli(i), 40000, srv, 3567))
    # The server answers: its SID is learned from the query response, the
    # client SID shows as the RID
    for i in range(10):
        f.append(udp(dnp(dpp(APP_DPP + b'\x06' + oid(2, b'server'), RSP), flags=None),
                     srv, 3567, cli(i), 40000))
    # New senders 10.1.1.x get provisional SID IDs (ping, an implied
    # sender operation, a packet to them), then name the SID of an
    # existing client: the provisional SID ID is merged into the old one
    for k in range(5):
        c = '10.1.1.%d' % (k + 1)
        f.append(udp(dnp(dpp(APP_DPP + b'\x03'), flags=None), c, 40000, srv, 3567))
        f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x20, opid=c4(100 + k), delay=0), flags=None),
                     c, 40000, srv, 3567))
        f.append(udp(dnp(dpp(APP_DPP + b'\x03', RSP), flags=None), srv, 3567, c, 40000))
        f.append(udp(dnp(dpp(APP_DPP + b'\x08' + sids[k] + c4(7)), flags=None),
                     c, 40000, srv, 3567))
        f.append(udp(dnp(dpp(APP_DPP + b'\x03'), flags=None), c, 40000, srv, 3567))
    # Explicit operation IDs: an unknown SID, the same SID again, the
    # sender's own SID and the receiver's SID (notes: could be implied)
    c0 = cli(0)
    other = oid(9, b'other')
    f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x60, opid=other + c4(1), delay=0), flags=None),
                 c0, 40000, srv, 3567))
    f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x60, opid=other + c4(2), delay=0), flags=None),
                 c0, 40000, srv, 3567))
    f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x60, opid=sids[0] + c4(3), delay=0), flags=None),
                 c0, 40000, srv, 3567))
    f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x60, opid=oid(2, b'server') + c4(4), delay=0), flags=None),
                 c0, 40000, srv, 3567))
    # Operation tracking: a command and its retries (implied sender), two
    # responses (implied receiver), a second operation
    c1 = cli(1)
    for r in range(3):
        f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x22, opid=c4(77), retry=r, delay=1), flags=None),
                     c1, 40000, srv, 3567))
    for r in range(2):
        f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x40 | RSP, opid=c4(77)), flags=None),
                     srv, 3567, c1, 40000))
    f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x20, opid=c4(78), delay=0), flags=None),
                 c1, 40000, srv, 3567))
    f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x40 | RSP, opid=c4(78)), flags=None),
                 srv, 3567, c1, 40000))
    for r in range(3):
        f.append(udp(dnp(dpp(APP_DPP + b'\x03', 0x20, opid=c4(77), delay=0), flags=None),
                     c1, 40000, srv, 3567))
    # A SID of 310 octets is not learned: the packet after it shows no SID
    long_sid = oid(1, b'long', [(1, b'L' * 200), (1, b'M' * 100)])
    c = '10.1.2.1'
    f.append(udp(dnp(dpp(APP_DPP + b'\x01' + long_sid + c4(1)), flags=None), c, 40000, srv, 3567))
    f.append(udp(dnp(dpp(APP_DPP + b'\x03'), flags=None), c, 40000, srv, 3567))
    return f


def oid_variants():
    """Object ID encodings, carried as the SID of Node Down commands from
    their own sender (DNP source address 9)."""
    f = []
    for o in (OID_P, OID_ESC, OID_ATTR, OID_NEST, OID_BIG, OID_HUGE, OID_BCAST,
              OID_BCAST_BAD, OID_EMPTY_ATTR, OID_MID):
        f.append(udp_c(dnp(dpp(APP_DPP + b'\x00' + o), src=9)))
    return f


def dsp():
    """DOF Session Protocol (app 0)."""
    f = []
    opts = (bytes([0, 0x00, 0x80, 2]) + b'\x01\x02' +       # TEP family option
            bytes([1, 0x00, 0x01, 1]) + b'\x01' +           # OAP family option
            bytes([3, 0x00, 0x81, 1]) + b'\x00' +           # TRP family option
            bytes([255, 0x12, 0x34, 0]) +                   # general, no value
            bytes([9, 0x00, 0x05, 1]) + b'\xee')            # unknown code
    f.append(udp_c(dof(b'\x00')))                            # nop
    f.append(udp_c(dof(b'\x00\x00')))                        # query
    f.append(udp_s(dof_rsp(b'\x00\x00')))                    # query response
    f.append(udp_c(dof(b'\x00\x01' + opts)))                 # config request
    f.append(udp_s(dof_rsp(b'\x00\x02')))                    # ACK
    f.append(udp_s(dof_rsp(b'\x00\x03' + bytes([1, 0, 1, 0]))))   # NAK
    f.append(udp_s(dof_rsp(b'\x00\x04')))                    # REJ
    f.append(udp_c(dof(b'\x00\x05')))                        # terminate
    f.append(udp_s(dof_rsp(b'\x00\x05')))
    f.append(udp_c(dof(b'\x00\x06')))                        # open
    f.append(udp_s(dof_rsp(b'\x00\x06' + c2(0) + c2(1) + c2(128) + c2(0x7fff))))
    f.append(udp_s(dof_rsp(b'\x00\x07' + c2(1) + c2(0x81))))  # open secure response
    f.append(udp_c(dof(b'\x00\x20')))                        # unknown opcode
    f.append(udp_c(dof(b'\x00\x01')))                        # config request, no options
    return f


def oap():
    """Object Access Protocol (app 1), every opcode."""
    f = []
    A = b'\x01'
    binding = IID1 + OID_A
    cmdctl = (b'\x7f' + c2(0x1234) + b'\x02' + OID_P + OID_ATTR + c2(9))
    vals = b'\xde\xad\xbe\xef'
    # nop
    f.append(udp_c(dof(A)))
    # Provide: alias sizes 1, 2 and 4; interface IDs of 1, 2, 4, 16 octets
    f.append(udp_c(dof(A + bytes([0x40 | 16]) + b'\x07' + IID1 + OID_A)))
    f.append(udp_c(dof(A + bytes([0x80 | 16]) + b'\x01\x02' + IID2 + OID_P)))
    f.append(udp_c(dof(A + bytes([0xC0 | 16]) + b'\x01\x02\x03\x04' + IID4 + OID_ATTR)))
    f.append(udp_c(dof(A + bytes([0x40 | 16]) + b'\x08' + IID16 + OID_NEST)))
    # Get: alias (resolved to frame of the Provide), binding, command control
    f.append(udp_c(dof(A + bytes([0x40 | 10]) + c2(3) + b'\x07')))
    f.append(udp_c(dof(A + bytes([0x0a]) + c2(0x85) + binding)))
    f.append(udp_c(dof(A + bytes([0x60 | 10]) + cmdctl + c2(4) + b'\x08')))
    f.append(udp_c(dof(A + bytes([0x40 | 10]) + c2(3) + b'\x55')))     # alias not defined
    # Invoke, Set with value lists
    f.append(udp_c(dof(A + bytes([0x80 | 12]) + c2(5) + b'\x01\x02' + vals)))
    f.append(udp_c(dof(A + bytes([0x0c]) + c2(5) + binding + vals)))
    f.append(udp_c(dof(A + bytes([0xC0 | 20]) + c2(6) + b'\x01\x02\x03\x04' + vals)))
    f.append(udp_c(dof(A + bytes([0x20 | 20]) + b'\x00' + c2(6) + binding + vals)))
    # Activate, Connect, Full Connect, Watch: alias or binding
    for op in (28, 4, 3, 30):
        f.append(udp_c(dof(A + bytes([0x40 | op]) + b'\x07')))
        f.append(udp_c(dof(A + bytes([0x20 | op]) + b'\x02' + IID2 + OID_P)))
    # Register, Subscribe
    f.append(udp_c(dof(A + bytes([0x40 | 25]) + c2(7) + b'\x07')))
    f.append(udp_c(dof(A + bytes([0xC0 | 25]) + c2(7) + b'\x01\x02\x03\x04')))
    f.append(udp_c(dof(A + bytes([0xC0 | 30]) + b'\x01\x02\x03\x04')))
    f.append(udp_c(dof(A + bytes([25]) + c2(0x100) + binding)))
    f.append(udp_c(dof(A + bytes([0xC0 | 24]) + c2(8) + b'\x01\x02\x03\x04' + c2(0x200))))
    f.append(udp_c(dof(A + bytes([24]) + c2(8) + binding + c2(1))))
    # Change, Signal: item, alias or binding, sequence, values
    f.append(udp_c(dof(A + bytes([0x40 | 2]) + c2(9) + b'\x07' + b'\x00\x01' + vals)))
    f.append(udp_c(dof(A + bytes([2]) + c2(9) + binding + b'\x00\x02' + vals)))
    f.append(udp_c(dof(A + bytes([0x80 | 22]) + c2(10) + b'\x01\x02' + b'\x00\x03' + vals)))
    f.append(udp_c(dof(A + bytes([22]) + c2(10) + binding + b'\x00\x04' + vals)))
    # Open: alias or binding, then interface and object
    f.append(udp_c(dof(A + bytes([0x40 | 14]) + b'\x07' + IID2 + OID_ESC)))
    f.append(udp_c(dof(A + bytes([14]) + binding + IID4 + OID_P)))
    # Advertise with and without command control (the fixed offset)
    f.append(udp_c(dof(A + bytes([0x20 | 5]) + b'\x00' + IID1 + OID_P)))
    f.append(udp_c(dof(A + bytes([0x20 | 5]) + b'\x41' + c2(3) + c2(0x99) + IID2 + OID_A)))
    f.append(udp_c(dof(A + bytes([5]) + binding)))
    # A Get from the other node (sender 2) with alias 6: same hash as
    # alias 7 of sender 1, not the same alias
    f.append(udp_s(dnp(dpp(A + bytes([0x40 | 10]) + c2(3) + b'\x06'), src=2, dst=1)))
    # Define, illegal commands (Exception, unknown opcode)
    f.append(udp_c(dof(A + bytes([6]))))
    f.append(udp_c(dof(A + bytes([9]))))
    f.append(udp_c(dof(A + bytes([31]))))
    # Responses
    f.append(udp_s(dof_rsp(A + bytes([0x20 | 10]) + OID_P + vals)))     # Get, provider
    f.append(udp_s(dof_rsp(A + bytes([10]) + vals)))
    f.append(udp_s(dof_rsp(A + bytes([0x20 | 12]) + OID_A + vals)))     # Invoke, provider
    f.append(udp_s(dof_rsp(A + bytes([12]) + vals)))
    f.append(udp_s(dof_rsp(A + bytes([0x20 | 25]) + OID_A + b'\x00\x05')))  # Register
    f.append(udp_s(dof_rsp(A + bytes([25]) + b'\x00\x06')))
    f.append(udp_s(dof_rsp(A + bytes([20]))))                            # Set
    f.append(udp_s(dof_rsp(A + bytes([0x20 | 24]) + OID_P)))             # Subscribe
    f.append(udp_s(dof_rsp(A + bytes([0xE0 | 9]) + c2(0x123) + vals)))   # Exception
    f.append(udp_s(dof_rsp(A + bytes([9]) + c2(2) + vals)))
    f.append(udp_s(dof_rsp(A + bytes([6]))))                             # Define
    f.append(udp_s(dof_rsp(A + bytes([14]))))                            # Open
    f.append(udp_s(dof_rsp(A + bytes([28]))))                            # Activate (illegal)
    return f


def oap_fix_repros():
    """The OAP reproducers of the fix: Advertise with command control, and
    an alias used one frame before the Provide that defines it."""
    f = []
    cli, srv = '192.0.2.50', '192.0.2.51'
    oap_adv = b'\x01' + bytes([0x20 | 5]) + b'\x00' + b'\x01\x22' + b'\x01\x03\x01\x02\x03'
    f.append(udp(dnp(b'\x02\x00' + oap_adv), cli, 40000, srv, 3567))
    get = b'\x01' + bytes([0x40 | 10]) + b'\x03' + b'\x07'
    provide = b'\x01' + bytes([0x40 | 16]) + b'\x07' + b'\x01\x22' + b'\x01\x03\x01\x02\x03'
    f.append(udp(dnp(b'\x02\x00' + get), cli, 40001, srv, 3567))
    f.append(udp(dnp(b'\x02\x00' + provide), cli, 40001, srv, 3567))
    f.append(udp(dnp(b'\x02\x00' + get), cli, 40001, srv, 3567))
    return f


def sec4(flag, ident, nonce, perms):
    """Security.4 key request: flag octet, Security.3.1 (credential type,
    stage 0, Security.8 node identifier), nonce, Security.2 permissions."""
    return bytes([flag]) + c2(1) + b'\x00' + ident + nonce + perms


PERMS = (c2(3) + c2(2) +                        # count 3; type 2 (no length)
         c2(5) + c2(3) + b'\xaa\xbb\xcc' +      # type 5 with 3 octets
         c2(0x81) + c2(0))                      # type 129, length 0
SEC4 = sec4(0x03 | 0xC0, oid(8, b'alice'), b'\x11\x22\x33\x44', PERMS)
SEC13 = bytes([2, 0x60, 0x02, 2]) + b'\x01\x02'          # mode data 0x6002, 2 octets
SEC61 = b'\x05' + SEC13 + SEC4
SEC62 = sec4(0x00, oid(8, b'bob', [(1, b'\x01')]), b'\x55', c2(0))
SEC10 = c2(2) + c4(0x3FFFFFFD) + c4(0x88)
SEC12A = bytes([0x00 | 3])                               # M 0: no identifiers
SEC12B = bytes([0x40 | 2]) + c4(0x3FFFFFFF) + c4(0x3FFFFFFE)
SEC12C = bytes([0xC0 | 1]) + c4(0x3FFFFFFD)
SEC11 = c2(3) + SEC12A + SEC12B + SEC12C
SEC63 = b'\x09' + SEC10 + SEC11 + c2(0)
TICKET = bytes(64)          # Security.5 placeholder: 64 zero octets, not a key


def security():
    """TEP and TRP PDUs that carry the plain Security structures. No keys
    are configured, so nothing is derived or decrypted."""
    f = []
    TEP = c2(128)
    TRP = c2(129)
    dom = oid(7, b'domain')
    # TEP: nop, Rekey (domain + Security.6.1), End Session, Session Ending,
    # Reject with and without data, Request outside a secure session
    f.append(udp_c(dof(TEP)))
    f.append(udp_c(dof(TEP + b'\x11' + dom + SEC61)))
    f.append(udp_c(dof(TEP + b'\x05')))
    f.append(udp_c(dof(TEP + b'\x06')))
    f.append(udp_s(dof_rsp(TEP + b'\x00' + b'\x07' + b'reason')))
    f.append(udp_s(dof_rsp(TEP + b'\x00' + b'\x02')))
    f.append(udp_c(dof(TEP + b'\x01' + SEC61)))
    # TRP commands
    f.append(udp_c(dof(TRP)))
    f.append(udp_c(dof(TRP + b'\x01' + dom + SEC4 + oid(8, b'group'))))          # KEK
    f.append(udp_c(dof(TRP + b'\x02' + dom + SEC4)))                             # random
    f.append(udp_c(dof(TRP + b'\x03' + dom + SEC62 + SEC61)))                    # session
    f.append(udp_c(dof(TRP + b'\x04' + dom + b'\x0a' + SEC4 + oid(8, b'node'))))  # scopes
    f.append(udp_c(dof(TRP + b'\x06' + dom + c2(1) + b'\x00' + c2(3) + b'pub')))  # resolve
    f.append(udp_c(dof(TRP + b'\x07')))                                          # local domain
    f.append(udp_c(dof(TRP + b'\x09' + dom + c2(1) + b'\x00' + oid(8, b'carol') + b'cred')))
    # TRP responses
    f.append(udp_s(dof_rsp(TRP + b'\x00' + b'\x03')))                            # reject
    f.append(udp_s(dof_rsp(TRP + b'\x01' + TICKET + b'\x01\x02\x03' + b'\x00\x01' +
                           oid(6, b'sidg') + SEC10 + SEC13 + c4(0x22) + PERMS + SEC11 + SEC11)))
    f.append(udp_s(dof_rsp(TRP + b'\x02' + TICKET)))
    f.append(udp_s(dof_rsp(TRP + b'\x03' + TICKET + TICKET + SEC63)))
    f.append(udp_s(dof_rsp(TRP + b'\x04' + TICKET + b'\x0a' + SEC10 + SEC11)))
    f.append(udp_s(dof_rsp(TRP + b'\x06' + c2(1) + b'\x01' + c2(0))))
    f.append(udp_s(dof_rsp(TRP + b'\x09' + b'ok')))
    f.append(udp_s(dof_rsp(TRP + b'\x08')))
    # SGMP: only the empty PDU (key distribution is not covered)
    f.append(udp_c(dof(c2(130))))
    return f


def tcp_session():
    """DOF over TCP 3567: negotiation, PDUs with lengths, several PDUs in
    one segment, PDUs and headers split over segments."""
    f = []
    t = TCP('192.0.2.10', 41000, '192.0.2.20', 3567)
    f += t.handshake()
    f.append(t.c2s(b'\x00\x00'))                 # DNPv0 query
    f.append(t.s2c(b'\x00\x01'))                 # DNPv0 response: version 1
    f.append(t.c2s(b'\x01\x02'))                 # DNPv1/DPPv2 negotiation
    f.append(t.s2c(b'\x01\x02'))
    p1 = dnp(dpp(b'\x00\x06'), flags=0x01)       # DSP open
    f.append(t.c2s(p1))
    p2 = dnp(dpp(b'\x00\x06' + c2(1), RSP), flags=0x01)
    p3 = dnp(dpp(APP_DPP + b'\x03', RSP), flags=0x02)
    f.append(t.s2c(p2 + p3))                     # two PDUs in one segment
    big = dnp(dpp(b'\x01' + bytes([0x0c]) + c2(5) + IID1 + OID_A + bytes(300)), flags=0x02)
    f.append(t.c2s(big[:100]))                   # one PDU over two segments,
    f.append(t.c2s(big[100:] + dnp(dpp(APP_DPP + b'\x03'), flags=0x01)))   # another after it
    f.append(t.c2s(b'\x01\x02'))                 # PDU without flags after negotiation
    p4 = dnp(dpp(APP_DPP + b'\x05'), flags=0x01)
    f.append(t.c2s(p4[:1]))                      # header split after one octet
    f.append(t.c2s(p4[1:]))
    p5 = dnp(dpp(APP_DPP + b'\x03'), flags=0x03)
    f.append(t.c2s(p5[:3]))                      # 3 octet length cut short
    f.append(t.c2s(p5[3:]))
    p6 = dnp(dpp(b'\x00\x05'), flags=0x0d, src=0x1234)
    f.append(t.c2s(p6))
    f.append(t.seg(p6, True, seq=t.cseq - len(p6)))     # retransmission
    f.append(t.s2c(dnp(dpp(b'\x00\x05', RSP), flags=0x0d, src=0x1234)))
    # Not DOF: an unknown version during negotiation, an unknown version
    # with flags after it
    u = TCP('192.0.2.11', 41001, '192.0.2.20', 3567)
    f += u.handshake()
    f.append(u.c2s(b'\x07\x00'))
    w = TCP('192.0.2.12', 41002, '192.0.2.20', 3567)
    f += w.handshake()
    f.append(w.c2s(b'\x87\x01\x00'))
    return f


def tunnel(pdu_op, dof_bytes):
    return b'\x01' + struct.pack('!H', 2 + len(dof_bytes)) + bytes([pdu_op, 0]) + dof_bytes


def tunnel_session():
    """DOF tunnel over TCP 8567."""
    f = []
    t = TCP('192.0.2.30', 42000, '192.0.2.40', 8567)
    f += t.handshake()
    f.append(t.c2s(tunnel(3, b'\x05\x02')))      # unknown DNP version, negotiating
    f.append(t.s2c(tunnel(3, b'\x01\x02')))      # DNPv1/DPPv2 negotiation
    f.append(t.c2s(tunnel(1, b'')))              # other tunnel opcode
    t1 = tunnel(3, dnp(dpp(b'\x00\x06'), flags=0x00))
    t2 = tunnel(3, dnp(dpp(APP_DPP + b'\x03'), flags=0x01))
    f.append(t.c2s(t1 + t2))                     # two tunnel PDUs in one segment
    t3 = tunnel(3, dnp(dpp(b'\x01' + bytes([0x40 | 16]) + b'\x09' + IID1 + OID_P), flags=0x0d, src=5))
    f.append(t.c2s(t3[:2]))                      # fewer than 3 octets
    f.append(t.c2s(t3[2:10]))                    # less than the length
    f.append(t.c2s(t3[10:]))
    f.append(t.s2c(tunnel(3, dnp(dpp(b'\x00\x06' + c2(1), RSP), flags=0x00))))
    return f


def startoffset_repros():
    """The two hangs fixed on the branch: a PDU that starts 64 KiB or more
    into a frame, over TCP 3567 and over the tunnel (TCP 8567)."""
    f = []
    FIRST = 65482
    t = TCP('192.0.2.1', 40001, '192.0.2.2', 3567)
    f += t.handshake()
    pdu1 = bytes([0x81, 0x02]) + struct.pack('!H', FIRST - 4) + b'\x00' * (FIRST - 4)
    f.append(t.c2s(pdu1 + bytes([0x81, 0x01, 0x01, 0x00])))
    u = TCP('192.0.2.1', 40002, '192.0.2.2', 8567)
    f += u.handshake()
    p1 = b'\x01' + struct.pack('!H', FIRST - 3) + b'\x00' * (FIRST - 3)
    p2 = b'\x01' + struct.pack('!H', 2) + b'\x00\x00'
    f.append(u.c2s(p1 + p2))
    return f


def exppdu():
    """Exported PDUs naming the registered DOF dissectors: dof.tunnel
    (fixed: no packet reference, was an assertion), dof.oid, dof.app."""
    f = []
    f.append(exported_pdu('dof.tunnel', b'\x01\x00\x04\x03\x00\x01\x00'))
    f.append(exported_pdu('dof.oid', OID_NEST))
    f.append(exported_pdu('dof.app', b'\x05\x01'))
    return f


# ------------------------------------------------- security (frames 304-)
# TEP session key exchange, the CCM security mode, the key and identity
# secret tables, TRP identity matching and SGMP. The ciphertext and the
# HMAC-SHA256 confirmations are computed with the 'cryptography' library;
# the keys are made-up test values. Run with the tables filled in (see
# -k), otherwise these frames are not decrypted.

TEP = c2(128)
TRP = c2(129)
SGMP = c2(130)

# Made-up keys (test values only)
SESSION_KEY = bytes(range(0x00, 0x20))          # in the session key table
IDENT_KEY = bytes(range(0x40, 0x60))            # learned from the ticket
IDENT_SECRET = bytes(range(0x80, 0xa0))         # identity secret table
UNKNOWN_KEY = bytes(range(0xc0, 0xe0))          # in no table

DOMAIN = oid(7, b'domain')
ALICE = oid(8, b'alice')
BOB = oid(8, b'bob')
CAROL = oid(8, b'carol')


def key_req(ident, nonce, perms=PERMS):
    """Security.4: flag (nonce length - 1), Security.3.1 (credential
    type 1, stage 0, Security.8 identity), nonce, Security.2."""
    return bytes([len(nonce) - 1]) + c2(1) + b'\x00' + ident + nonce + perms


def sec13_ccm(encrypt=True, tag=8):
    """Security.13 / DSP option for CCM (0x6001): strength count 1,
    strength 0, flags (E bit, tag length (t-2)/2)."""
    data = bytes([1, 0, (0x80 if encrypt else 0) | ((tag - 2) // 2)])
    return bytes([2, 0x60, 0x01, len(data)]) + data


def sec61(mode, ident, nonce):
    """Security.6.1: desired duration, security mode, Security.4."""
    return b'\x05' + mode + key_req(ident, nonce)


def tep_s(ssid, state=b'\x01\x02\x03\x04'):
    """TEP.2.2.1 responder initialization: SSID, Security.9 initial state."""
    return c4(ssid) + c2(len(state)) + state


def confirmation(key, i_nonce, r_nonce, s, r_ident):
    """HMAC-SHA256 over zero padded nonces, S and the responder identity
    (validate_session_key())."""
    msg = (bytes(16 - len(i_nonce)) + i_nonce + bytes(16 - len(r_nonce)) + r_nonce +
           s + r_ident)
    return hmac.new(key, msg, hashlib.sha256).digest()


def ticket_for(secret, key, mac=bytes(range(0x10, 0x30))):
    """Security.5 ticket that the identity secret turns into 'key':
    key = ticket[32:64] XOR AES-ECB(secret, ticket[0:32])."""
    enc = Cipher(algorithms.AES(secret), modes.ECB()).encryptor()
    pad = enc.update(mac) + enc.finalize()
    return mac + bytes(a ^ b for a, b in zip(key, pad))


def nonce(nid, dn, slot=0):
    return nid.to_bytes(4, 'big') + slot.to_bytes(2, 'big') + b'\x00' + dn.to_bytes(4, 'big')


def ccm_dpp(key, ssid, nid, dn, plain, tag=8, rsp=False, pn=None, tnid=None, nnid=None,
            encrypt=True, corrupt=False, dflags=0x00, **dkw):
    """A DPPv2 PDU with the security header (E and S flags, SSID) and a
    CCM header, the rest encrypted with AES-CCM; the associated data is
    the DPP PDU up to the end of the CCM header."""
    flags = 0x00
    ext = b''
    if pn is not None:
        flags |= 0x01
        ext += c4(pn)
        dn = pn
    if tnid is not None:
        flags |= 0x08
        ext += c4(tnid)
    if nnid is not None:
        flags |= 0x02
        ext += c4(nnid)
    sec = bytes([0x81]) + c4(ssid) + bytes([flags]) + ext
    hdr = dpp(b'', 0x80 | dflags | (RSP if rsp else 0), sec=sec, **dkw)
    if encrypt:
        body = AESCCM(key, tag_length=tag).encrypt(nonce(nid, dn), plain, hdr)
    else:
        body = plain + AESCCM(key, tag_length=tag).encrypt(nonce(nid, dn), b'', hdr + plain)
    if corrupt:
        body = body[:-1] + bytes([body[-1] ^ 0x01])
    return hdr + body


def key_exchange(i_ident, i_nonce, r_ident, r_nonce, ssid, key, ticket, mode, opid):
    """TEP Request (Rekey) and Accept PDUs (application payloads only)."""
    req = TEP + b'\x11' + DOMAIN + sec61(mode, i_ident, i_nonce)
    s = tep_s(ssid)
    conf = confirmation(key, i_nonce, r_nonce, s, r_ident)
    acc = TEP + b'\x01' + ticket + conf + s + key_req(r_ident, r_nonce, c2(0)) + SEC63
    return req, acc, conf


# Plain application PDUs carried inside the encrypted packets
PING = APP_DPP + b'\x03'
OAP_GET = b'\x01' + bytes([0x0a]) + c2(0x85) + IID1 + OID_A      # OAP Get, binding
HEARTBEAT = APP_DPP + b'\x05'


def udp_session():
    """Two-node UDP session keyed through the session key table."""
    f = []
    cli, srv = ('192.0.2.50', 40100), ('192.0.2.51', 3567)

    def c(p):
        return udp(dnp(p), cli[0], cli[1], srv[0], srv[1])

    def s(p):
        return udp(dnp(p, src=2, dst=1), srv[0], srv[1], cli[0], cli[1])

    i_nonce, r_nonce = b'\x11\x22\x33\x44', b'\x55\x66\x77\x88\x99\xaa'
    req, acc, conf = key_exchange(ALICE, i_nonce, BOB, r_nonce, 5, SESSION_KEY,
                                  bytes(range(0x20, 0x60)), sec13_ccm(), 1)
    f.append(c(dpp(req, 0x20, opid=c4(1), delay=0)))                 # TEP Request (Rekey)
    f.append(s(dpp(acc, 0x40 | RSP, opid=c4(1))))                    # TEP Accept: key learned
    f.append(s(ccm_dpp(SESSION_KEY, 5, 1, 1, PING, rsp=True)))        # responder, DN 1
    f.append(c(dpp(TEP + b'\x21' + conf, 0x20, opid=c4(1), delay=0)))  # TEP Confirm
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 1, OAP_GET)))               # initiator, DN 1
    f.append(s(ccm_dpp(SESSION_KEY, 5, 1, 7, PING, rsp=True, pn=7)))  # explicit packet number
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 2, PING, corrupt=True)))    # MAC check fails
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 3, HEARTBEAT, tnid=3, nnid=4)))  # target/next node IDs
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 4, b"", tag=8)[:-3]))        # 5 octets: shorter than the MAC
    # Long associated data (operation ID, sequence, 4 octet packet number
    # and node IDs): the CBC-MAC runs over more than one block
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 0, TEP + b'\x11' + sec61(sec13_ccm(), ALICE, b'\x61\x62'),
                       dflags=0x24, opid=c4(30), seq=9, pn=0x10000, tnid=0x20000, nnid=0x30000)))
    # Encrypted TEP Request (Rekey without a domain, plain Request with a
    # new operation): the domain comes from the secure session
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 5, TEP + b'\x01' + sec61(sec13_ccm(), ALICE, b'\x63'),
                       dflags=0x20, opid=c4(31))))
    # More than 255 counter blocks (the counter carries into the next octet)
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 6, PING + bytes(4200))))
    # The CCM application (app 24577)
    f.append(c(ccm_dpp(SESSION_KEY, 5, 0, 7, c2(24577) + b'\x00')))
    f.append(c(dpp(TEP + b'\x05')))                                   # End Session
    # A TEP Accept without an operation ID, and one that answers a
    # command that is not a TEP request
    f.append(s(dpp(acc, RSP)))
    f.append(c(dpp(PING, 0x20, opid=c4(40), delay=0)))
    f.append(s(dpp(acc, 0x40 | RSP, opid=c4(40))))
    return f


def identity_session():
    """Two-node UDP session whose key comes from the initiator ticket and
    the identity secret table; the mode authenticates without encryption."""
    f = []
    cli, srv = ('192.0.2.52', 40200), ('192.0.2.53', 3567)

    def c(p):
        return udp(dnp(p), cli[0], cli[1], srv[0], srv[1])

    def s(p):
        return udp(dnp(p, src=2, dst=1), srv[0], srv[1], cli[0], cli[1])

    i_nonce, r_nonce = b'\x01\x02\x03\x04\x05\x06\x07\x08', b'\x09\x0a'
    req, acc, conf = key_exchange(CAROL, i_nonce, BOB, r_nonce, 6, IDENT_KEY,
                                  ticket_for(IDENT_SECRET, IDENT_KEY), sec13_ccm(False, 4), 2)
    f.append(c(dpp(req, 0x20, opid=c4(2), delay=0)))
    f.append(s(dpp(acc, 0x40 | RSP, opid=c4(2))))
    f.append(s(ccm_dpp(IDENT_KEY, 6, 1, 1, PING, tag=4, rsp=True, encrypt=False)))
    f.append(c(dpp(TEP + b'\x21' + conf, 0x20, opid=c4(2), delay=0)))
    f.append(c(ccm_dpp(IDENT_KEY, 6, 0, 1, PING, tag=4, encrypt=False)))
    f.append(c(ccm_dpp(IDENT_KEY, 6, 0, 2, b'', tag=4, encrypt=False)[:-2]))   # shorter than the MAC
    return f


def unknown_key_session():
    """A key exchange whose key is in no table: the session exists but
    its packets cannot be decrypted."""
    f = []
    cli, srv = ('192.0.2.54', 40300), ('192.0.2.55', 3567)

    def c(p):
        return udp(dnp(p), cli[0], cli[1], srv[0], srv[1])

    def s(p):
        return udp(dnp(p, src=2, dst=1), srv[0], srv[1], cli[0], cli[1])

    req, acc, conf = key_exchange(ALICE, b'\x31\x32', BOB, b'\x33\x34', 7, UNKNOWN_KEY,
                                  bytes(64), sec13_ccm(), 3)
    f.append(c(dpp(req, 0x20, opid=c4(3), delay=0)))
    f.append(s(dpp(acc, 0x40 | RSP, opid=c4(3))))
    f.append(s(ccm_dpp(UNKNOWN_KEY, 7, 1, 1, PING, rsp=True)))
    return f


def ccm_tcp_session():
    """The same exchange over TCP (streaming): the key applies to the
    responder after the Accept and to the initiator after the Confirm."""
    f = []
    t = TCP('192.0.2.60', 41200, '192.0.2.61', 3567)
    f += t.handshake()
    f.append(t.c2s(b'\x01\x02'))                 # DNPv1/DPPv2 negotiation
    f.append(t.s2c(b'\x01\x02'))
    i_nonce, r_nonce = b'\x41\x42\x43\x44', b'\x45\x46\x47\x48'
    req, acc, conf = key_exchange(ALICE, i_nonce, BOB, r_nonce, 9, SESSION_KEY,
                                  bytes(range(0x60, 0xa0)), sec13_ccm(tag=16), 4)

    def p(x):
        return dnp(x, flags=0x01)
    f.append(t.c2s(p(dpp(req, 0x20, opid=c4(4), delay=0))))
    f.append(t.s2c(p(dpp(acc, 0x40 | RSP, opid=c4(4)))))
    f.append(t.c2s(p(ccm_dpp(SESSION_KEY, 9, 0, 1, PING, tag=16))))         # before the Confirm
    f.append(t.s2c(p(ccm_dpp(SESSION_KEY, 9, 1, 1, PING, tag=16, rsp=True))))
    f.append(t.c2s(p(dpp(TEP + b'\x21' + conf, 0x20, opid=c4(4), delay=0))))
    f.append(t.c2s(p(ccm_dpp(SESSION_KEY, 9, 0, 1, OAP_GET, tag=16))))
    f.append(t.s2c(p(ccm_dpp(SESSION_KEY, 9, 1, 2, PING, tag=16, rsp=True, pn=2))))
    return f


def trp_identity():
    """TRP commands whose initiator identity is in the identity secret
    table (the dissector remembers the secret for the response)."""
    f = []
    cli, srv = ('192.0.2.56', 40400), ('192.0.2.57', 3567)

    def c(p):
        return udp(dnp(p), cli[0], cli[1], srv[0], srv[1])
    f.append(c(dpp(TRP + b'\x01' + DOMAIN + key_req(CAROL, b'\x01') + oid(8, b'group'), 0x20,
                   opid=c4(10), delay=0)))
    f.append(c(dpp(TRP + b'\x02' + DOMAIN + key_req(CAROL, b'\x02'), 0x20, opid=c4(11), delay=0)))
    f.append(c(dpp(TRP + b'\x04' + DOMAIN + b'\x0a' + key_req(CAROL, b'\x03') + oid(8, b'node'),
                   0x20, opid=c4(12), delay=0)))
    f.append(c(dpp(TRP + b'\x03' + DOMAIN + key_req(CAROL, b'\x05', c2(0)) +
                   sec61(sec13_ccm(), ALICE, b'\x06'), 0x20, opid=c4(14), delay=0)))   # session
    f.append(c(dpp(TRP + b'\x01' + oid(7, b'other') + key_req(CAROL, b'\x04') + oid(8, b'g'),
                   0x20, opid=c4(13), delay=0)))                    # other domain: no match
    return f


def sgmp():
    """SGMP commands and the group request response (structures only)."""
    f = []
    cli, srv = ('192.0.2.58', 40500), ('192.0.2.59', 3567)

    def c(p):
        return udp(dnp(p), cli[0], cli[1], srv[0], srv[1])

    def s(p):
        return udp(dnp(p, src=2, dst=1), srv[0], srv[1], cli[0], cli[1])
    state = c2(3) + b'\x0a\x0b\x0c'
    f.append(c(dpp(SGMP + b'\x00' + c2(1) + b'\x02' + b'\x01\x02\x03\x04')))      # Heartbeat
    f.append(c(dpp(SGMP + b'\x01' + b'\x00\x10' + b'\x00\x02')))                  # Epoch Changed
    f.append(c(dpp(SGMP + b'\x02' + b'\x03' + state + bytes(range(32)))))         # Rekey
    f.append(c(dpp(SGMP + b'\x05' + b'\x03' + state + b'\x00\x03' + bytes(32))))  # Rekey Epoch
    f.append(c(dpp(SGMP + b'\x07' + state + bytes(32))))                          # Rekey Merge
    f.append(c(dpp(SGMP + b'\x03' + DOMAIN + b'\x00\x02' + key_req(oid(8, b'group'), b'\x07') +
                   SEC10, 0x20, opid=c4(20), delay=0)))                          # Request Group
    f.append(s(dpp(SGMP + b'\x03' + state + c2(1) + b'\x01' + bytes(64), 0x40 | RSP,
                   opid=c4(20))))                                                # its response
    return f


SECTIONS = (basics, sid_learning, oid_variants, dsp, oap, oap_fix_repros, security,
            tcp_session, tunnel_session, startoffset_repros, exppdu,
            udp_session, identity_session, unknown_key_session, ccm_tcp_session,
            trp_identity, sgmp)


def main_frames(verbose=False):
    frames = []
    for sec in SECTIONS:
        part = sec()
        if verbose:
            print('%4d-%4d %s' % (len(frames) + 1, len(frames) + len(part), sec.__name__))
        frames += part
    return frames


# -------------------------------------------------------------- malformed

def malformed_frames():
    f = []
    # DNP length shorter than the address fields (fixed: expert info)
    f.append(udp_c(bytes([0x81, 0x05, 0x00, 0x01]) + b'\x02\x00' + b'\xff\xff\x03'))
    f.append(udp_c(bytes([0x81, 0x09, 0x00, 0x01]) + b'\x02\x00'))
    # Reserved DNP and DPP flag bits, default DPP flags
    f.append(udp_c(bytes([0x81, 0x10]) + dpp(APP_DPP + b'\x03')))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03', 0x19, seq=1, delay=0))))
    f.append(udp_s(dnp(dpp(APP_DPP + b'\x03', 0x11), src=2, dst=1)))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x03', 0x08, delay=0))))
    # Over-long compressed values (format warnings)
    f.append(udp_c(dnp(dpp(c2(0x7fff, 2)[:0] + b'\x80\x01' + b'\x00'), src=1)))
    f.append(udp_c(dnp(dpp(APP_DPP + b'\x01' + oid(1, b'x', cls_len=4) + c4(1, 2)), flags=0x0c,
                       src=1, dst=2)))
    f.append(udp_c(bytes([0x81, 0x0c]) + c3(1, 2) + c3(2, 3) + dpp(APP_DPP + b'\x03')))
    # OID header bit 6, attribute running past the end
    f.append(udp_c(dof(APP_DPP + b'\x00' + b'\x01\x42ab')))
    f.append(udp_c(dof(APP_DPP + b'\x00' + b'\x01\x81a\x02\x10')))
    # Security header with the security mode flag but no secure session,
    # twice (the second has the error from the first)
    f.append(udp_c(dof(APP_DPP + b'\x03', 0x80, delay=0, sec=b'\x81' + c4(9))))
    f.append(udp_c(dof(b'', 0x80, delay=0, sec=b'\x80')))
    # OAP Provide without an alias; value lists that are empty
    f.append(udp_s(dof_rsp(b'\x01' + bytes([12]))))
    f.append(udp_s(dof_rsp(b'\x01' + bytes([9]) + c2(2))))
    f.append(udp_c(dof(b'\x01' + bytes([16]) + IID1 + OID_A)))
    # Security structures: invalid stage, reserved Security.4 bits,
    # Security.13 data out of range
    f.append(udp_c(dof(c2(129) + b'\x02' + oid(7, b'd') +
                       sec4(0x30, oid(8, b'x'), b'\x00', c2(0)).replace(b'\x01\x00', b'\x01\x05', 1))))
    f.append(udp_c(dof(c2(128) + b'\x11' + oid(7, b'd') + b'\x05' + bytes([2, 0x10, 0x00, 0]) +
                       sec4(0, oid(8, b'x'), b'\x00', c2(0)))))
    # Truncated PDUs
    f.append(udp_c(b'\x81'))
    f.append(udp_c(dof(APP_DPP + b'\x01')))
    f.append(udp_c(dof(b'\x01' + bytes([0x40 | 10]))))
    f.append(udp_c(dof(c2(129) + b'\x03' + oid(7, b'd'))))
    f.append(udp_c(dof(b'\x00\x01' + bytes([1, 0, 1, 9]))))
    # TCP: a two octet PDU with no DPP octet; tunnel PDU without DOF
    t = TCP('192.0.2.10', 41100, '192.0.2.20', 3567)
    f += t.handshake()
    f.append(t.c2s(b'\x00\x00'))
    f.append(t.c2s(b'\x81\x00'))
    u = TCP('192.0.2.30', 42100, '192.0.2.40', 8567)
    f += u.handshake()
    f.append(u.c2s(b'\x01\x00\x02\x03\x00'))
    # Streaming negotiation never completed (timeout on the second pass)
    w = TCP('192.0.2.13', 41003, '192.0.2.20', 3567)
    f += w.handshake()
    f.append(w.c2s(b'\x01\x02'))
    # Exported PDU dof.tunnel with a PDU that is not opcode 3
    f.append(exported_pdu('dof.tunnel', b'\x01\x00\x02\x01\x00'))
    return f


def uat_values():
    return {
        'seckey': SESSION_KEY.hex(),
        'identsecret': (DOMAIN.hex(), CAROL.hex(), IDENT_SECRET.hex()),
    }


def main():
    if '-k' in sys.argv:
        v = uat_values()
        print('uat:custom_dof_seckey_list:"%s"' % v['seckey'])
        print('uat:custom_dof_identsecret_list:"%s","%s","%s"' % v['identsecret'])
        return
    out = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.'
    pcapng(os.path.join(out, 'dof-coverage.pcapng'), main_frames('-v' in sys.argv))
    pcapng(os.path.join(out, 'dof-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
