#!/usr/bin/env python3
# Generates test/captures/c1222_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ANSI C12.22 dissector
(packet-c1222.c, generated from epan/dissectors/asn1/c1222/).

Every packet is built from scratch with struct; no captured traffic is
used. A head-end (192.0.2.1) talks C12.22 to a meter (192.0.2.2) on UDP
and TCP port 1153 (both registered by default). Messages with security
mode "cleartext with authentication" and "ciphertext with
authentication" are protected with the EAX' mode of C12.22 using the keys
in cfg/c1222_decryption_table (key 0x02 and key 0x00), so that the
dissector can authenticate and decrypt them; the AES-128 and EAX' code
below follows wsutil/eax.c.

Usage: mkc1222.py <output directory>

Writes:
  c1222-coverage.pcap            every ACSE header element, AP titles
                                 absolute and relative, every
                                 authentication value encoding, every
                                 EPSEM service, ED class, the three
                                 security modes (authenticated, decrypted,
                                 an unknown key), TCP reassembly
  c1222-coverage-malformed.pcap  truncated services, bad checksum, failed
                                 authentication, EPSEM length errors, and
                                 the reviewer's sweep
                                 c1222_sweep.py and
                                 c1222_tcp_pdu_len.py
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))









import struct
from repro import reproducer_dir

HEADEND = bytes([192, 0, 2, 1])
METER = bytes([192, 0, 2, 2])
PORT = 1153
KEYS = {0x02: bytes.fromhex('00112233445566778899aabbccddeeff'),
        0x00: bytes.fromhex('ffeeddccbbaa99887766554433221100')}
BASEOID = '2.16.124.113620.1.22'


# AES-128 and EAX' ----------------------------------------------------------

SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        SBOX[p] = (x ^ 0x63) & 0xff
        if p == 1:
            break
    SBOX[0] = 0x63


_init_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1


def _expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def aes_encrypt_block(key, block):
    rk = _expand(key)
    s = [a ^ b for a, b in zip(block, rk[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]   # ShiftRows
        if r != 10:                                            # MixColumns
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


assert aes_encrypt_block(bytes(range(16)), bytes.fromhex('00112233445566778899aabbccddeeff')) \
    == bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')   # FIPS-197 C.1


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _dbl(b):
    out = bytearray(16)
    carry = 0
    for i in range(16):
        out[i] = ((b[i] << 1) | carry) & 0xff
        carry = 1 if b[i] & 0x80 else 0
    if carry:
        out[0] ^= 0x87
    return bytes(out)


def _cmac(key, iv, data, D, Q):
    """The CMAC of eax.c: CBC from iv over the data padded to 16 octets,
    the last block XORed with D (complete) or Q (padded)."""
    n = len(data)
    size = (n + 15) // 16 * 16
    work = bytearray(data)
    if size != n:
        work += b'\x80' + b'\0' * (size - n - 1)
        work[size - 16:] = _xor(work[size - 16:], Q)
    else:
        work[size - 16:] = _xor(work[size - 16:], D)
    ws = iv
    for i in range(0, size, 16):
        ws = aes_encrypt_block(key, _xor(ws, work[i:i + 16]))
    return ws


def _ctr(key, ws, data):
    ctr = bytearray(ws)
    ctr[12] &= 0x7f
    ctr[14] &= 0x7f
    c = int.from_bytes(ctr, 'big')
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _xor(data[i:i + 16], aes_encrypt_block(key, c.to_bytes(16, 'big')))
        c = (c + 1) % (1 << 128)
    return bytes(out)


def _dq(key):
    D = _dbl(aes_encrypt_block(key, bytes(16)))
    return D, _dbl(D)


def eax_cleartext_auth(key, canon, clear):
    D, Q = _dq(key)
    return _cmac(key, D, canon + clear, D, Q)[12:16]


def eax_encrypt(key, canon, clear):
    D, Q = _dq(key)
    wsn = _cmac(key, D, canon, D, Q)
    if not clear:
        return b'', wsn[12:16]
    cipher = _ctr(key, wsn, clear)
    return cipher, _xor(_cmac(key, Q, cipher, D, Q), wsn)[12:16]


# BER -----------------------------------------------------------------------

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + ber_len(len(body)) + body


def oid_body(s):
    a = [int(x) for x in s.split('.')]
    vals = [a[0] * 40 + a[1]] + a[2:]
    out = b''
    for v in vals:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return out


def reloid_body(s):
    out = b''
    for v in [int(x) for x in s.split('.')]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return out


def integer(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big'))


def abs_title(s):
    return tlv(0x06, oid_body(s))


def rel_title(s):
    return tlv(0x80, reloid_body(s))


# C12.22 message ------------------------------------------------------------

class Auth(bytes):
    """An authentication value; raw holds the key-id and iv element
    contents that go at the end of the canonified header."""
    raw = b''


def auth_c1222(keyid=None, iv=None, indirect=None):
    """Calling-authentication-value [12] with the C12.22 single-ASN.1
    encoding: [2] { [indirect], [0] { [1] { [0] key-id, [1] iv } } }"""
    inner = b''
    raw = b''
    if keyid is not None:
        inner += tlv(0x80, bytes([keyid]))
        raw += bytes([keyid])
    if iv is not None:
        inner += tlv(0x81, iv)
        raw += iv
    body = (integer(indirect) if indirect is not None else b'') + tlv(0xa0, tlv(0xa1, inner))
    a = Auth(tlv(0xa2, body))
    a.raw = raw
    return a


def auth_c1221(choice, data):
    """C12.21 encoding: [2] { [0] { [0] { [choice] data } } }"""
    return tlv(0xa2, tlv(0xa0, tlv(0xa0, tlv(0x80 | choice, data))))


def auth_octets(data):
    return tlv(0xa2, tlv(0x81, data))


class Msg:
    """A C12.22 message. Header elements are given as inner encodings (the
    content of the context tag); epsem is the cleartext EPSEM without the
    flags octet."""
    def __init__(self, called=rel_title('7.1'), calling=rel_title('7.2'), calling_id=1,
                 aso=None, called_id=None, ae_qual=None, mech=None, auth=None):
        self.called, self.calling, self.calling_id = called, calling, calling_id
        self.aso, self.called_id, self.ae_qual, self.mech, self.auth = \
            aso, called_id, ae_qual, mech, auth

    def header(self):
        h = b''
        if self.aso is not None:
            h += tlv(0xa1, self.aso)
        if self.called is not None:
            h += tlv(0xa2, self.called)
        if self.called_id is not None:
            h += tlv(0xa4, integer(self.called_id))
        if self.calling is not None:
            h += tlv(0xa6, self.calling)
        if self.ae_qual is not None:
            h += tlv(0xa7, integer(self.ae_qual))
        if self.calling_id is not None:
            h += tlv(0xa8, integer(self.calling_id))
        if self.mech is not None:
            h += tlv(0x8b, self.mech)
        if self.auth is not None:
            h += tlv(0xac, self.auth)
        return h

    def canon(self, user_info_len, flags):
        """The canonified header of decrypt_packet()/canonify_unencrypted_header()."""
        def title(t):
            if t[0] == 0x80:   # relative: made absolute with the base OID
                full = oid_body(BASEOID) + t[2:]
                return bytes([0x06, len(full)]) + full
            return t
        c = b''
        if self.aso is not None:
            c += tlv(0xa1, self.aso)
        if self.called is not None:
            c += tlv(0xa2, title(self.called))
        if self.called_id is not None:
            c += tlv(0xa4, integer(self.called_id))
        if self.ae_qual is not None:
            c += tlv(0xa7, integer(self.ae_qual))
        c += tlv(0xa8, integer(self.calling_id))
        if self.mech is not None:
            c += tlv(0x8b, self.mech)
        if self.auth is not None:
            c += tlv(0xac, self.auth)
        # User-information: [30] and EXTERNAL and octet string headers and
        # the flags octet (assumes short form lengths)
        c += bytes([0xbe]) + ber_len(user_info_len) + user_info_hdr
        if self.calling is not None:
            c += tlv(0xa6, title(self.calling))
        # key-id and iv element contents
        c += getattr(self.auth, 'raw', b'')
        return c

    def build(self, flags, epsem, mode=0, keyid=0, key=None, bad_mac=False):
        """mode 0 cleartext, 1 cleartext with authentication, 2 ciphertext
        with authentication."""
        global user_info_hdr
        flags = (flags & ~0x0c) | (mode << 2)
        if mode == 0:
            body = bytes([flags]) + epsem
            return tlv(0x60, self.header() + tlv(0xbe, tlv(0x28, tlv(0x81, body))))
        # The canonified user information is the start of the EXTERNAL:
        # 3 + 2 * (size of the BER length of the whole EXTERNAL) octets,
        # which with short lengths is the two headers and the flags octet
        # and with long ones also takes the first octet of the EPSEM
        # (cleartext in mode 1; in mode 2 only short lengths work here)
        ext = tlv(0x28, tlv(0x81, bytes([flags]) + epsem + bytes(4)))
        size = len(ber_len(len(ext)))
        user_info_hdr = ext[:3 + 2 * size]
        assert mode == 1 or size == 1
        canon = self.canon(len(ext), flags)
        key = key or KEYS.get(keyid, bytes(16))
        if mode == 1:
            mac = eax_cleartext_auth(key, canon, epsem)
            data = epsem
        else:
            data, mac = eax_encrypt(key, canon, epsem)
        if bad_mac:
            mac = bytes(b ^ 0xff for b in mac)
        body = bytes([flags]) + data + mac
        return tlv(0x60, self.header() + tlv(0xbe, tlv(0x28, tlv(0x81, body))))


user_info_hdr = b''


def svc(*cmd):
    """One EPSEM service: BER length and the request or response octets."""
    b = bytes(cmd[0]) if isinstance(cmd[0], (bytes, bytearray)) else bytes(cmd)
    return ber_len(len(b)) + b


def cksum(data):
    return (-sum(data)) & 0xff


# Link layers ---------------------------------------------------------------

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def eth(payload, to_meter):
    a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    return (b + a if to_meter else a + b) + b'\x08\x00' + payload


def ipv4(proto, l4, src, dst):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, src, dst)
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + l4


def udp(payload, to_meter=True, cport=50000):
    src, dst = (HEADEND, METER) if to_meter else (METER, HEADEND)
    sport, dport = (cport, PORT) if to_meter else (PORT, cport)
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(src + dst + struct.pack('>BBH', 0, 17, len(u)) + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return eth(ipv4(17, u, src, dst), to_meter)


class Tcp:
    def __init__(self, frames, cport):
        self.f, self.cport = frames, cport
        self.cseq, self.sseq = 1000, 7000
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01'
        self.seg(True, 0x02, b'', opts)
        self.sseq_ack = 0
        self.seg(False, 0x12, b'', opts)
        self.seg(True, 0x10, b'')

    def seg(self, to_meter, flags, payload, opts=b''):
        src, dst = (HEADEND, METER) if to_meter else (METER, HEADEND)
        sport, dport = (self.cport, PORT) if to_meter else (PORT, self.cport)
        seq, ack = (self.cseq, self.sseq) if to_meter else (self.sseq, self.cseq)
        if flags == 0x02:
            ack = 0
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        c = csum(src + dst + struct.pack('>BBH', 0, 6, len(hdr) + len(payload)) + hdr + payload)
        hdr = hdr[:16] + struct.pack('>H', c) + hdr[18:]
        self.f.append(eth(ipv4(6, hdr + payload, src, dst), to_meter))
        n = len(payload) + (1 if flags & 0x03 else 0)
        if to_meter:
            self.cseq += n
        else:
            self.sseq += n

    def send(self, to_meter, payload):
        self.seg(to_meter, 0x18, payload)


def write_pcap(path, frames):
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
    t = 1700000000
    for i, f in enumerate(frames):
        out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


# Main capture --------------------------------------------------------------

def main_frames():
    f = []
    req = Msg()
    rsp = Msg(called=rel_title('7.2'), calling=rel_title('7.1'))

    def ex(request, response, mreq=req, mrsp=rsp, flags=0x80, **kw):
        f.append(udp(mreq.build(flags, request, **kw)))
        if response is not None:
            f.append(udp(mrsp.build(flags, response, **kw), to_meter=False))

    tbl = bytes(range(1, 11))
    # Identify; response OK with identification data
    ex(svc(0x20), svc(b'\x00\x00\x01\x00\x00'))
    # Negotiate with 0, 1 and 11 baud rates; response
    ex(svc(0x60, 0x02, 0x00, 0x04), svc(b'\x00\x02\x00\x04\x06'))
    ex(svc(0x61, 0x01, 0x00, 0x02, 0x06), None)
    ex(svc(b'\x6b\x00\x80\x01' + bytes(range(1, 12))), None)
    # Logon (user id 2, user "OPERATOR  "), Security with and without user id
    ex(svc(b'\x50\x00\x02OPERATOR  '), svc(0x00))
    ex(svc(b'\x51' + b'secret password 0123' + b'\x00\x02'), svc(0x00))
    ex(svc(b'\x51' + b'another password 456'), svc(0x03))
    # Authenticate (4 octets), response with 0 octets
    ex(svc(b'\x53\x04\xde\xad\xbe\xef'), svc(b'\x00\x00'))
    # Full Read of ST-1, MT-0, Pending ST-3, Pending MT, UDT, Pending UDT,
    # and an unknown table flag; responses with table data and checksum
    ex(svc(0x30, 0x00, 0x01), svc(b'\x00' + struct.pack('>H', len(tbl)) + tbl + bytes([cksum(tbl)])))
    for t in (0x0800, 0x1003, 0x1801, 0x2005, 0x3002, 0x4001):
        ex(svc(b'\x30' + struct.pack('>H', t)), None)
    # Default Read, Partial Read Offset
    ex(svc(0x3e), svc(b'\x00\x00\x02\xaa\xbb\x9b'))
    ex(svc(b'\x3f\x00\x17\x00\x01\x00\x00\x08'), svc(0x04))
    # Full Write of table 0x0801 with a checksum; Full Write of table 7
    # (procedure 10, sequence 5, two parameter octets), little endian
    ex(svc(b'\x40\x08\x01' + struct.pack('>H', 5) + tbl[:5] + bytes([cksum(tbl[:5])])), svc(0x00))
    proc = struct.pack('<H', 0x000a) + b'\x05' + b'\x12\x34'
    ex(svc(b'\x40\x00\x07' + struct.pack('>H', len(proc)) + proc + bytes([cksum(proc)])), svc(0x00))
    # Manufacturer procedure 2058 (MF, response "post on exception")
    proc = struct.pack('<H', 0x180a) + b'\x06'
    ex(svc(b'\x40\x00\x07' + struct.pack('>H', len(proc)) + proc + bytes([cksum(proc)])), None)
    # Default Write (not decoded), Partial Write Offset
    ex(svc(b'\x4e\x01\x02\x03'), svc(0x05))
    ex(svc(b'\x4f\x00\x17\x00\x00\x04' + struct.pack('>H', 3) + b'\x01\x02\x03' + bytes([cksum(b'\x01\x02\x03')])),
       svc(0x00))
    # Wait 30 s, Timing Setup
    ex(svc(0x70, 30), svc(0x00))
    ex(svc(0x71, 60, 5, 10, 3), svc(b'\x00\x3c\x05\x0a\x03'))
    # Logoff, Terminate, Disconnect (with an unexpected data octet)
    ex(svc(0x52), svc(0x00))
    ex(svc(0x21), svc(0x00))
    ex(svc(0x22, 0x01), None)
    # Every error response code and an unknown code 0x13; an unknown
    # command 0x7f
    for e in range(0x01, 0x14):
        f.append(udp(rsp.build(0x80, svc(e)), to_meter=False))
    ex(svc(0x7f, 0x01, 0x02), None)
    # Two services in one EPSEM (Logon and Full Read); flags with the
    # recovery and proxy bits, response control "on exception" and "never"
    ex(svc(b'\x50\x00\x02OPERATOR  ') + svc(0x30, 0x00, 0x05), None, flags=0xe1)
    ex(svc(0x30, 0x00, 0x05), None, flags=0x82)
    # ED class included
    ex(b'EDCL' + svc(0x30, 0x00, 0x01), b'EDCL' + svc(0x00), flags=0x90)
    # A service with a long form (2 octet) length: Full Read response of 300 octets
    big = bytes(i & 0xff for i in range(300))
    f.append(udp(rsp.build(0x80, svc(b'\x00' + struct.pack('>H', 300) + big + bytes([cksum(big)]))),
                 to_meter=False))
    # Header variants: absolute AP titles, ASO context, called AP invocation
    # id, calling AE qualifier, mechanism name
    full = Msg(aso=abs_title(BASEOID), called=abs_title(BASEOID + '.7.1'), called_id=77,
               calling=abs_title(BASEOID + '.7.2'), ae_qual=1, calling_id=300,
               mech=oid_body('2.16.124.113620.1.22.2.0'))
    ex(svc(0x20), None, mreq=full)
    # No calling AP title
    ex(svc(0x20), None, mreq=Msg(calling=None))
    # Authentication value encodings: C12.21 identification, request,
    # response (empty), octet aligned, C12.22 with indirect 0
    for a in (auth_c1221(0, b'\x00\x01\x02'), auth_c1221(1, b'\x11\x22\x33\x44'),
              auth_c1221(2, b''), auth_octets(b'\x01\x02\x03\x04\x05'),
              auth_c1222(keyid=2, iv=b'\x00\x00\x00\x01', indirect=0)):
        ex(svc(0x20), None, mreq=Msg(auth=a))

    # Security: cleartext with authentication, key 2 with an IV; the
    # response the same
    a = auth_c1222(keyid=2, iv=b'\x0a\x0b\x0c\x0d')
    ex(svc(0x30, 0x00, 0x01), svc(b'\x00' + struct.pack('>H', 5) + tbl[:5] + bytes([cksum(tbl[:5])])),
       mreq=Msg(auth=a), mrsp=Msg(called=rel_title('7.2'), calling=rel_title('7.1'), auth=a),
       mode=1, keyid=2)
    # Ciphertext with authentication, key 2: Logon and Full Write of a
    # procedure, decrypted; response decrypted
    a = auth_c1222(keyid=2, iv=b'\x0a\x0b\x0c\x0e')
    proc = struct.pack('<H', 0x0006) + b'\x07'
    ex(svc(b'\x50\x00\x02OPERATOR  ') +
       svc(b'\x40\x00\x07' + struct.pack('>H', len(proc)) + proc + bytes([cksum(proc)])),
       svc(0x00) + svc(0x00),
       mreq=Msg(auth=a), mrsp=Msg(called=rel_title('7.2'), calling=rel_title('7.1'), auth=a),
       mode=2, keyid=2)
    # Ciphertext with authentication, no authentication value (key 0),
    # every optional header element in the canonified header
    full2 = Msg(aso=abs_title(BASEOID), called=abs_title(BASEOID + '.7.1'), called_id=77,
                calling=abs_title(BASEOID + '.7.2'), ae_qual=1, calling_id=301,
                mech=oid_body('2.16.124.113620.1.22.2.0'))
    ex(svc(0x30, 0x00, 0x03), None, mreq=full2, mode=2, keyid=0)
    # Cleartext with authentication of a 200 octet Full Read response:
    # long form lengths in the canonified header
    big = bytes(i & 0xff for i in range(300))
    ex(svc(0x30, 0x00, 0x16), svc(b'\x00' + struct.pack('>H', 200) + big[:200] + bytes([cksum(big[:200])])),
       mode=1, keyid=0)
    # Ciphertext with authentication with ED class and an empty EPSEM
    # (only the MAC), key 0
    ex(b'EDCL' + svc(0x20), None, flags=0x90, mode=2, keyid=0)
    ex(b'', None, mode=2, keyid=0)
    # Cleartext with authentication without services (only the MAC)
    ex(b'', None, mode=1, keyid=0)
    # Ciphertext with authentication with an unknown key (0x07): not
    # decrypted (warning)
    a = auth_c1222(keyid=7, iv=b'\x00\x00\x00\x07')
    ex(svc(0x30, 0x00, 0x01), None, mreq=Msg(auth=a), mode=2, keyid=7, key=bytes(range(16)))

    # TCP: a request and response, a message in two segments, two
    # messages in one segment
    t = Tcp(f, 50001)
    t.send(True, req.build(0x80, svc(0x20)))
    t.send(False, rsp.build(0x80, svc(b'\x00\x00\x01\x00\x00')))
    m = req.build(0x80, svc(0x30, 0x00, 0x01))
    t.send(True, m[:5])
    t.send(True, m[5:])
    r = rsp.build(0x80, svc(b'\x00' + struct.pack('>H', len(tbl)) + tbl + bytes([cksum(tbl)])))
    t.send(False, r + rsp.build(0x80, svc(0x00)))
    # A message with a long form length (header and user information over
    # 127 octets) split in three segments
    m = req.build(0x80, svc(b'\x40\x08\x01' + struct.pack('>H', 150) + big[:150] +
                            bytes([cksum(big[:150])])))
    t.send(True, m[:1])
    t.send(True, m[1:100])
    t.send(True, m[100:])
    t.send(False, rsp.build(0x80, svc(0x00)))
    return f


# Malformed capture ---------------------------------------------------------

def malformed_frames():
    f = []
    req = Msg()

    def m(epsem, flags=0x80, **kw):
        f.append(udp(req.build(flags, epsem, **kw)))

    # Truncated services (error "command truncated"): Logon, Security,
    # Authenticate without length and with data one octet past the service
    # (fixed on the branch), Full Read, Partial Read, Full Write header,
    # Full Write data, Full Write of table 7 with table size 0 and 1 (fixed
    # on the branch), Partial Write header and data, Wait, Negotiate, Timing
    # Setup
    for s in (b'\x50\x00\x02OPER', b'\x51short', b'\x53', b'\x53\x02\xaa',
              b'\x30\x00', b'\x3f\x00\x01\x00', b'\x40\x00\x01\x00',
              b'\x40\x00\x01\x00\x09\x01\x02', b'\x40\x00\x07\x00\x00\xcc',
              b'\x40\x00\x07\x00\x01\xaa\xcc', b'\x4f\x00\x01\x00\x00\x00\x00',
              b'\x4f\x00\x01\x00\x00\x00\x00\x09\x01', b'\x70', b'\x62\x00',
              b'\x71\x01\x02'):
        m(svc(s))
    # Bad checksum in Full Write and Partial Write
    m(svc(b'\x40\x00\x01\x00\x02\x01\x02\x00'))
    m(svc(b'\x4f\x00\x01\x00\x00\x00\x00\x02\x01\x02\x00'))
    # Zero length service (fixed on the branch), service longer than the
    # EPSEM, BER length error (5 octet length), ED class missing
    m(b'\x00\x20')
    m(b'\x05\x20')
    m(b'\x85\x01\x00\x00\x00\x00\x30')
    m(b'ED', flags=0x90)
    # Cleartext with authentication: bad MAC (failed authentication), no
    # key in the table for key 5, MAC missing (fewer than 4 octets left
    # after the services), EPSEM of just the flags octet
    m(svc(0x20), mode=1, keyid=0, bad_mac=True)
    a = auth_c1222(keyid=5, iv=b'\x00\x00\x00\x05')
    f.append(udp(Msg(auth=a).build(0x80, svc(0x20), mode=1, keyid=5, key=bytes(16))))
    f.append(udp(tlv(0x60, req.header() + tlv(0xbe, tlv(0x28, tlv(0x81, b'\x84' + svc(b'\x20\x01\x02\x03\x04')))))))
    f.append(udp(tlv(0x60, req.header() + tlv(0xbe, tlv(0x28, tlv(0x81, b'\x84'))))))
    f.append(udp(tlv(0x60, req.header() + tlv(0xbe, tlv(0x28, tlv(0x81, b'\x88'))))))
    # Ciphertext with authentication with a bad MAC, and without a called
    # AP title (required for the canonified header)
    m(svc(0x20), mode=2, keyid=0, bad_mac=True)
    f.append(udp(Msg(called=None).build(0x80, svc(0x20), mode=2, keyid=0)))
    # Canonified header larger than its buffer (300 octets): a 280 octet
    # mechanism name
    f.append(udp(Msg(mech=b'\x2a' + b'\x01' * 279).build(0x80, svc(0x20), mode=1, keyid=0)))
    # Canonified header with the [30] tag of the user information at
    # offset 299 and 300 of the 300 octet buffer (277 and 278 octet
    # mechanism names)
    for n in (277, 278):
        f.append(udp(Msg(mech=b'\x2a' + b'\x01' * (n - 1)).build(0x80, svc(0x20), mode=1, keyid=0)))
    # EXTERNAL of 126 octets: the user information is 128 octets, so its
    # canonified copy needs a two octet length the copy was not made for
    f.append(udp(req.build(0x80, svc(b'\x4e' + bytes(117)), mode=1, keyid=0)))
    # Service length with four octets of which the last ends it (0x83
    # 0x80 0x80 0x01): accepted by ber_len_ok(), then longer than the EPSEM
    m(b'\x83\x80\x80\x01\x20')
    # User-information not EXTERNAL, EXTERNAL without an octet string
    f.append(udp(tlv(0x60, req.header() + tlv(0xbe, tlv(0x04, b'\x80\x20')))))
    f.append(udp(tlv(0x60, req.header() + tlv(0xbe, tlv(0x28, tlv(0x82, b'\x80\x20'))))))
    # Truncated message and header
    f.append(udp(req.build(0x80, svc(0x30, 0x00, 0x01))[:12]))
    f.append(udp(b'\x60'))
    # The reviewer's sweep (c1222_sweep.py) and TCP PDU
    # lengths near 2^32 (c1222_tcp_pdu_len.py)
    here = os.path.dirname(os.path.abspath(__file__))
    batch = reproducer_dir(here, ['c1222_sweep.py', 'c1222_tcp_pdu_len.py'])
    for name in ('c1222_sweep.pcap', 'c1222_tcp_pdu_len.pcap'):
        with open(os.path.join(batch, name), 'rb') as fh:
            data = fh.read()
        off = 24
        while off < len(data):
            n = struct.unpack('<I', data[off + 8:off + 12])[0]
            f.append(data[off + 16:off + 16 + n])
            off += 16 + n
    return f


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = main_frames()
    write_pcap(os.path.join(outdir, 'c1222-coverage.pcap'), frames)
    write_pcap(os.path.join(outdir, 'c1222-coverage-malformed.pcap'), malformed_frames())
    print(len(frames), 'frames')


if __name__ == '__main__':
    main()
