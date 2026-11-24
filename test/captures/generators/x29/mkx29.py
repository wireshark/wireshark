#!/usr/bin/env python3
# Generates test/captures/x29_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: a minimal pcap writer and Ethernet/IPv4/TCP/UDP builders.
# Everything is synthetic: addresses are 10.0.0.x / 02:00:00:00:00:0x.
import os
import struct
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Pcap:
    def __init__(self, linktype=1):
        self.linktype = linktype
        self.pkts = []
        self.t = 0
    def add(self, data):
        self.t += 1
        self.pkts.append((self.t, bytes(data)))
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.linktype))
            for t, p in self.pkts:
                f.write(struct.pack('<IIII', 1700000000 + t, 0, len(p), len(p)))
                f.write(p)
        return len(self.pkts)

def ip4(a):
    return bytes(map(int, a.split('.')))

MAC1 = b'\x02\0\0\0\0\x01'
MAC2 = b'\x02\0\0\0\0\x02'

def ip_packet(proto, src, dst, payload, ident=1):
    tot = 20 + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload

def udp_frame(sip, dip, sport, dport, payload, smac=MAC1, dmac=MAC2):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return dmac + smac + b'\x08\x00' + ip_packet(17, sip, dip, udp)

class Tcp:
    """One TCP connection; frames are appended to a Pcap."""
    def __init__(self, pcap, cport, sport, cip='10.0.0.1', sip='10.0.0.2'):
        self.p = pcap
        self.c = (cip, cport, MAC1)
        self.s = (sip, sport, MAC2)
        self.seq = [1000, 5000]
    def _pkt(self, d, payload, flags=0x18, advance=None):
        src, dst = (self.c, self.s) if d == 0 else (self.s, self.c)
        seq = self.seq[d]
        ack = 0 if flags == 0x02 else self.seq[1 - d]
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''      # MSS on a SYN
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ph = ip4(src[0]) + ip4(dst[0]) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.seq[d] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.p.add(dst[2] + src[2] + b'\x08\x00' + ip_packet(6, src[0], dst[0], tcp + payload))
    def handshake(self):
        self._pkt(0, b'', 0x02)
        self._pkt(1, b'', 0x12)
        self._pkt(0, b'', 0x10)
    def c2s(self, payload):
        self._pkt(0, payload)
    def s2c(self, payload):
        self._pkt(1, payload)
    def fin(self):
        self._pkt(0, b'', 0x11)
        self._pkt(1, b'', 0x11)
        self._pkt(0, b'', 0x10)

def llc_frame(dsap, ssap, ctrl, payload=b'', smac=MAC1, dmac=MAC2):
    body = bytes([dsap, ssap]) + ctrl + payload
    return dmac + smac + struct.pack('!H', len(body)) + body

def outdir():
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(d, exist_ok=True)
    return d

# ---- pcapng ----
def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def _opt(code, val):
    return struct.pack('<HH', code, len(val)) + val + b'\0' * ((-len(val)) % 4)

class PcapNG:
    """Several interfaces; add(iface, data, flags=None) with optional epb_flags."""
    def __init__(self, linktypes=(1,)):
        self.linktypes = list(linktypes)
        self.pkts = []
        self.t = 0
    def add(self, data, iface=0, flags=None):
        self.t += 1
        self.pkts.append((iface, self.t, bytes(data), flags))
    def write(self, fn):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
        for iface, t, d, flags in self.pkts:
            ts = 1700000000 * 1000000 + t * 1000
            body = struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d
            body += b'\0' * ((-len(d)) % 4)
            if flags is not None:
                body += _opt(2, struct.pack('<I', flags)) + struct.pack('<HH', 0, 0)
            out += _blk(6, body)
        with open(fn, 'wb') as f:
            f.write(out)
        return len(self.pkts)

def exported_pdu(name, payload):
    """Exported PDU (linktype 252) record naming a dissector."""
    nm = name.encode()
    pad = (-len(nm)) % 4
    tag = struct.pack('!HH', 12, len(nm) + pad) + nm + b'\0' * pad
    return tag + struct.pack('!HH', 0, 0) + payload

def gsmtap(sub_type, payload, uplink=False, gtype=0x13):
    """GSMTAP v2 header (16 octets) for E1/T1 line traces."""
    arfcn = 0x4000 if uplink else 0
    return struct.pack('!BBBBHBBIBBBB', 2, 4, gtype, 0, arfcn, 0, 0, 0, sub_type, 0, 0, 0) + payload

# ---- X.25 packet builders (shared by the X.25, X.29 and XOT generators) ----
def x25hdr(lcn, typ, gfi=1):
    return bytes([(gfi << 4) | (lcn >> 8), lcn & 0xff, typ])

GFI_MOD8 = 0x1
GFI_MOD128 = 0x2
GFI_Q = 0x8
GFI_A = 0x8       # address format bit in call setup packets (TOA/NPI)
GFI_D = 0x4

def bcd(digits):
    d = [int(c, 16) for c in digits]
    if len(d) % 2:
        d.append(0)
    return bytes((d[i] << 4) | d[i + 1] for i in range(0, len(d), 2))

def addr_ntoa(called, calling):
    """Address block with 4 bit lengths (calling in the high nibble) and BCD digits."""
    return bytes([(len(calling) << 4) | len(called)]) + bcd(called + calling)

def addr_toa(called, calling):
    """Address block with 8 bit lengths (called, calling) and BCD digits."""
    return bytes([len(called), len(calling)]) + bcd(called + calling)

def fac(*items):
    b = b''.join(items)
    return bytes([len(b)]) + b

def fA(code, p):
    return bytes([code, p])

def fB(code, a, b):
    return bytes([code, a, b])

def fC(code, a, b, c):
    return bytes([code, a, b, c])

def fD(code, data):
    return bytes([code, len(data)]) + data

def call_request(lcn, called='12345', calling='6789012', facilities=b'\x00', user=b'', gfi=GFI_MOD8,
                 toa=False):
    if toa:
        a = addr_toa(called, calling)
        gfi |= GFI_A
    else:
        a = addr_ntoa(called, calling)
    return x25hdr(lcn, 0x0B, gfi) + a + facilities + user

def call_accepted(lcn, called='', calling='', facilities=None, gfi=GFI_MOD8, toa=False):
    if facilities is None:
        return x25hdr(lcn, 0x0F, gfi)
    a = addr_toa(called, calling) if toa else addr_ntoa(called, calling)
    return x25hdr(lcn, 0x0F, gfi | (GFI_A if toa else 0)) + a + facilities

def clear_request(lcn, cause=0, diag=0, gfi=GFI_MOD8):
    return x25hdr(lcn, 0x13, gfi) + bytes([cause, diag])

def clear_confirm(lcn, extra=b'', gfi=GFI_MOD8):
    return x25hdr(lcn, 0x17, gfi) + extra

def interrupt(lcn, data=b'\x01'):
    return x25hdr(lcn, 0x23) + data

def interrupt_conf(lcn):
    return x25hdr(lcn, 0x27)

def reset_request(lcn, cause=0, diag=0):
    return x25hdr(lcn, 0x1B) + bytes([cause, diag])

def reset_conf(lcn):
    return x25hdr(lcn, 0x1F)

def restart_request(cause=0, diag=0):
    return x25hdr(0, 0xFB) + bytes([cause, diag])

def restart_conf():
    return x25hdr(0, 0xFF)

def diagnostic(diag=0x10, extra=b''):
    return x25hdr(0, 0xF1) + bytes([diag]) + extra

def registration_request(dte, dce, reg=b'\x01\x02\x03'):
    return x25hdr(0, 0xF3) + addr_ntoa(dce, dte) + bytes([len(reg)]) + reg

def registration_conf(cause, diag, dte, dce, reg=b'\x01\x02'):
    return x25hdr(0, 0xF7) + bytes([cause, diag]) + addr_ntoa(dce, dte) + bytes([len(reg)]) + reg

def data8(lcn, ps, pr, payload, m=0, q=0, d=0):
    gfi = GFI_MOD8 | (GFI_Q if q else 0) | (GFI_D if d else 0)
    return x25hdr(lcn, (pr << 5) | (m << 4) | (ps << 1), gfi) + payload

def data128(lcn, ps, pr, payload, m=0, q=0, d=0):
    gfi = GFI_MOD128 | (GFI_Q if q else 0) | (GFI_D if d else 0)
    return bytes([(gfi << 4) | (lcn >> 8), lcn & 0xff, ps << 1, (pr << 1) | m]) + payload

def rr8(lcn, pr, kind=0x01):
    return x25hdr(lcn, (pr << 5) | kind)

def rr128(lcn, pr, kind=0x01):
    return bytes([(GFI_MOD128 << 4) | (lcn >> 8), lcn & 0xff, kind, pr << 1])

def xot(x25pkt, version=0):
    return struct.pack('!HH', version, len(x25pkt)) + x25pkt

def udp_ip_datagram(payload=b'hello'):
    udp = struct.pack('!HHHH', 1024, 9, 8 + len(payload), 0) + payload
    return ip_packet(17, '10.1.1.1', '10.1.1.2', udp)

def clnp_dt(data=b''):
    """A minimal CLNP DT PDU with 3 octet addresses (no checksum, no options)."""
    hdr = bytes([0x81, 0, 0x01, 0x0A, 0x1C]) + b'\0\0' + b'\0\0' + bytes([3]) + b'\x49\x00\x01' + bytes([3]) + b'\x49\x00\x02'
    hdr = bytes([0x81, len(hdr), 0x01, 0x0A, 0x1C]) + struct.pack('!H', len(hdr) + len(data)) + b'\0\0' + hdr[9:]
    return hdr + data

# ---- X.25 scenarios (shared by the X.25, X.29 and XOT generators) ----
def pad_digits(n):
    return ''.join(str(i % 10) for i in range(n))

def facility_calls(send):
    """Call requests that carry every facility class; send(pkt, from_dte)."""
    lcn = 20
    def call(f, **kw):
        nonlocal lcn
        send(call_request(lcn, facilities=f, **kw), True)
        lcn += 1
    # class A
    call(fac(fA(0x00, 0x00), fA(0x00, 0x0F), fA(0x00, 0xFF), fA(0x01, 0x01), fA(0x01, 0xC1),
             fA(0x01, 0x82)))
    call(fac(fA(0x02, 0xAA), fA(0x03, 0x12), fA(0x04, 0x01), fA(0x08, 0x01), fA(0x09, 0x05),
             fA(0x0A, 0x66), fA(0x0B, 0x01), fA(0x05, 0x07)))
    # class B
    call(fac(fB(0x41, 0x12, 0x34), fB(0x42, 0x0A, 0x0B), fB(0x43, 0x02, 0x07), fB(0x44, 0x11, 0x22),
             fB(0x47, 0x00, 0x05), fB(0x48, 0x00, 0x06), fB(0x49, 0x01, 0xF4), fB(0x45, 0xAA, 0xBB)))
    # class C
    call(fac(fC(0x80, 1, 2, 3), fC(0xA5, 4, 5, 6)))
    # class D: call duration, segment count, call transfer (both reasons), RPOA extension
    call(fac(fD(0xC1, bytes([1, 2, 3, 4, 0, 0x12, 0x34, 0x56])),
             fD(0xC2, bytes(range(1, 9))),
             fD(0xC3, bytes([0x07, 4]) + bcd('1234')),
             fD(0xC3, bytes([0xC1, 3]) + bcd('567')),
             fD(0xC4, bytes([0x31, 0x32, 0x33, 0x34]))))
    # class D: monetary unit, NUI, called/calling address extension, end-to-end transit delay
    call(fac(fD(0xC5, b'USD'), fD(0xC6, b'user1'),
             fD(0xC9, bytes([5]) + bcd('98765')),
             fD(0xCB, bytes([4]) + bcd('4321')),
             fD(0xCA, bytes([0x00, 0x64, 0x00, 0xC8, 0x01, 0x2C]))))
    # class D: call deflection (both reasons), priority with 1..6 values, unknown D
    call(fac(fD(0xD1, bytes([0xC1, 4]) + bcd('1111')),
             fD(0xD1, bytes([0x05, 2]) + bcd('22')),
             fD(0xD2, bytes([1, 2, 3, 255, 5, 6])),
             fD(0xD3, b'unknown')))
    # class D: short end-to-end transit delay and priority forms (no bytes, one value, ... )
    for n in (0, 1, 2, 3, 4, 5):
        call(fac(fD(0xCA, bytes(range(1, n + 1)))))
    for n in (0, 1, 2, 3, 4, 5):
        call(fac(fD(0xD2, bytes(range(1, n + 1)))))
    # other CALL_DURATION and SEGMENT_COUNT multiples
    call(fac(fD(0xC1, bytes(8)), fD(0xC2, bytes(16)), fD(0xC4, bytes(2)), fD(0xC4, bytes(6))))
    # an empty facility list and a TOA/NPI (A bit) call with facilities
    call(b'\x00')
    call(fac(fA(0x01, 0x01), fB(0x42, 0x0A, 0x0A)), toa=True)
    call(fac(fD(0xC5, b'EUR')), called='3', calling='4', toa=True)
    # short and odd addresses, no calling address, no called address, no addresses
    call(fac(fA(0x01, 0x00)), called='1', calling='')
    call(fac(fA(0x01, 0x00)), called='', calling='9')
    call(fac(fA(0x01, 0x00)), called='123456789012345', calling='543210987654321')
    call(fac(fA(0x01, 0x00)), called='', calling='')
    # call request with hex digits in the address
    call(fac(fA(0x01, 0x00)), called='ABCDEF', calling='0F')
    return lcn

def bogus_facility_calls(send, lcn=60):
    """Call requests whose facilities do not fit their length (expert info, no malformed packet)."""
    def call(f, **kw):
        nonlocal lcn
        send(call_request(lcn, facilities=f, user=kw.pop('user', b'\x45' + b'\0' * 19)), True)
        lcn += 1
    # facilities length 1 with a class A facility (the reproducer of the length underflow)
    call(bytes([1, 0x01, 0x01]))
    # class B facility in a length of 2, class C in a length of 3, class D longer than the list
    call(bytes([2, 0x42, 0x0A, 0x0A]))
    call(bytes([3, 0x80, 1, 2, 3]))
    call(bytes([4, 0xC5, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
    # class D facilities with a length that does not fit their format
    call(fac(fD(0xC1, b'\x01\x02\x03')))        # call duration, not a multiple of 4
    call(fac(fD(0xC2, b'\x01\x02\x03\x04')))    # segment count, not a multiple of 8
    call(fac(fD(0xC3, b'\x07')))                # call transfer, too short
    call(fac(fD(0xC4, b'\x01\x02\x03')))        # RPOA extension, odd
    call(fac(fD(0xCB, b'')))                    # calling address extension, empty
    call(fac(fD(0xC9, b'')))                    # called address extension, empty
    call(fac(fD(0xD1, b'\x01')))                # call deflection, too short
    # the same bogus length after a good facility
    call(bytes([3, 0x01, 0x01, 0x42, 0x0A]))
    return lcn

def user_data_calls(send, base=100):
    """Call requests with the various forms of call user data (X.263 / X.264)."""
    lcn = base
    def call(user, **kw):
        nonlocal lcn
        send(call_request(lcn, user=user, **kw), True)
        lcn += 1
        return lcn - 1
    out = {}
    out['ip'] = call(b'\xCC')
    out['ipv6'] = call(b'\x8E')
    out['x29'] = call(b'\x01\x00\x00\x00')
    out['x29data'] = call(b'\x01\x00\x00\x00' + b'login: ')
    out['clnp'] = call(clnp_dt(b''))
    out['esis'] = call(b'\x82\x00\x00')
    out['isis'] = call(b'\x83\x00\x00')
    out['idrp'] = call(b'\x85\x00\x00')
    out['sndcf'] = call(b'\xC1\x00\x00')
    out['other'] = call(b'\xEE\x01\x02\x03')          # unregistered SPI, skipped
    out['two'] = call(b'\x02\x55\x66')                # SPI below 3
    out['cotp'] = call(bytes([5, 0x01, 0x01, 0x00, 0x00, 0x00]))              # UN TPDU, COTP
    out['cltp'] = call(bytes([5, 0x01, 0x02, 0x00, 0x00, 0x00]))              # UN TPDU, CLTP
    out['x274a'] = call(bytes([5, 0x01, 0x03, 0x00, 0x00, 0x00]))             # ISO 10736 + COTP
    out['x274b'] = call(bytes([5, 0x01, 0x04, 0x00, 0x00, 0x00]))             # ISO 10736 + CLTP
    out['not_un'] = call(bytes([5, 0x02, 0x01, 0x00, 0x00, 0x00]))            # second octet not 1
    out['short'] = call(bytes([5]))                                           # cannot see the second octet
    out['big'] = call(bytes([0x21]) + b'\0' * 4)                              # > 32: an SPI
    out['nodata'] = call(b'')
    return out, lcn

def data_scenarios(send, ids):
    """Data transfer, flow control and the other packet types on the VCs of user_data_calls."""
    ip = ids['ip']
    send(call_accepted(ip), False)
    send(data8(ip, 0, 0, udp_ip_datagram(b'first')), True)
    send(rr8(ip, 1), False)
    send(data8(ip, 0, 1, udp_ip_datagram(b'reply')), False)
    send(data8(ip, 1, 1, udp_ip_datagram(b'second'), d=1), True)
    send(rr8(ip, 2, 0x05), False)             # RNR
    send(rr8(ip, 2, 0x09), False)             # REJ
    send(interrupt(ip, b''), True)
    send(interrupt_conf(ip), False)
    send(reset_request(ip, 0x05, 0x00), False)
    send(reset_conf(ip), True)
    send(clear_request(ip, 0x00, 0x00), True)
    send(clear_confirm(ip), False)
    v6 = ids['ipv6']
    send(call_accepted(v6), False)
    send(data8(v6, 0, 0, bytes([0x60, 0, 0, 0, 0, 0, 59, 64]) + bytes(32)), True)
    send(clear_request(v6, 0x09, 0x11), False)
    send(clear_confirm(v6), True)
    cl = ids['clnp']
    send(call_accepted(cl, called='1', calling='2', facilities=b'\x00'), False)
    send(data8(cl, 0, 0, clnp_dt(b'hi')), True)
    send(clear_request(cl, 0x01, 0x20), True)
    cot = ids['cotp']
    send(call_accepted(cot), False)
    send(data8(cot, 0, 0, bytes([2, 0xF0, 0x80]) + b'cotp data'), True)
    send(data128(cot, 1, 0, bytes([2, 0xF0, 0x80]) + b'x'), True)
    send(clear_request(cot, 0x0D, 0x00), False)
    clt = ids['cltp']
    send(data8(clt, 0, 0, bytes([2, 0x40, 0x00])), True)
    send(clear_request(clt, 0x13, 0x00), True)

def flow_and_misc(send, vc=300):
    """Flow control, resets, restarts, registration and diagnostics with both modulos."""
    for kind in (0x01, 0x05, 0x09):
        send(rr8(vc, 3, kind), True)
        send(rr128(vc, 100, kind), False)
    send(data8(vc, 7, 6, b'mod8 data'), True)
    send(data8(vc, 2, 3, b'q bit', q=1), False)
    send(data8(vc, 3, 3, b'd bit', d=1), True)
    send(data128(vc, 100, 99, b'mod128 data'), True)
    send(data128(vc, 127, 0, b'mod128 q', q=1, d=1), False)
    send(data8(vc, 0, 0, b''), True)                 # a data packet without data
    send(interrupt(vc, b'\x55'), True)
    send(interrupt_conf(vc), False)
    send(reset_request(vc, 0x01, 0x2B), False)
    send(reset_request(vc, 0x80, 0x00), True)
    send(reset_request(vc, 0x7E, 0x00), True)        # unknown cause
    send(reset_conf(vc), True)
    for cause in (0x00, 0x01, 0x03, 0x05, 0x09, 0x0B, 0x0D, 0x11, 0x13, 0x15, 0x19, 0x21, 0x29, 0x39,
                  0x85, 0x7E):
        send(clear_request(vc + 1, cause, 0x00), cause & 1 == 1)
    for diag in (0, 1, 16, 38, 70, 122, 250, 0xFF):
        send(clear_request(vc + 2, 0x00, diag), True)
    send(clear_confirm(vc + 1), False)
    # clear confirmation in the extended format: addresses and facilities
    send(clear_confirm(vc + 1, addr_ntoa('123', '456') + fac(fA(0x01, 0x01))), False)
    send(clear_confirm(vc + 1, addr_toa('123', '456') + fac(fA(0x01, 0x01)), gfi=GFI_MOD8 | GFI_A), False)
    for cause in (0x00, 0x01, 0x03, 0x07, 0x7F, 0x80, 0x55):
        send(restart_request(cause, 0x00), True)
        send(restart_request(cause, 0x07), False)
    send(restart_conf(), False)
    for cause in (0x00, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0F, 0x11, 0x1D, 0x85, 0x40):
        send(reset_request(vc + 3, cause, 0x00), False)
    send(registration_request('1234567', '89'), True)
    send(registration_request('1', '', b'\x04abcd'), True)
    send(registration_conf(0x7F, 0x00, '5551234', '12'), False)
    send(registration_conf(0x05, 0x10, '', ''), False)
    send(diagnostic(0x10), False)
    send(diagnostic(0x01, b'\x01\x02'), False)
    # call accepted with addresses and facilities, and the short forms
    send(call_accepted(vc + 4, called='1234', calling='5678', facilities=fac(fB(0x43, 2, 2))), False)
    send(call_accepted(vc + 4, called='1234', calling='5678', facilities=fac(fB(0x43, 2, 2)), toa=True), False)
    send(call_accepted(vc + 4, called='', calling='', facilities=b'\x00'), False)

def reassembly(send, vc=400):
    """M-bit sequences: both modulos, both directions, interleaved, and a sequence that never ends."""
    send(call_request(vc, user=b'\x01\x00\x00\x00'), True)           # X.29 on this VC
    send(call_accepted(vc), False)
    send(data8(vc, 0, 0, b'line one ', m=1), True)
    send(data8(vc, 0, 1, b'reply part ', m=1), False)
    send(data8(vc, 1, 1, b'line two ', m=1), True)
    send(data8(vc, 1, 2, b'reply end\r\n'), False)
    send(data8(vc, 2, 2, b'line three\r\nsecond line\r\n'), True)
    # mod 128 sequence on another VC
    v2 = vc + 1
    send(data128(v2, 0, 0, b'AAAA' * 3, m=1), True)
    send(data128(v2, 1, 0, b'BBBB' * 3, m=1), True)
    send(data128(v2, 2, 0, b'CCCC' * 3, m=1), True)
    send(data128(v2, 3, 0, b'DDDD'), True)
    # a single packet with the M bit clear needs no reassembly
    send(data128(v2, 4, 0, b'single'), True)
    # a sequence that is never finished (M bit on the last packet)
    v3 = vc + 2
    send(data8(v3, 0, 0, b'unfinished ', m=1), True)
    send(data8(v3, 1, 0, b'sequence ', m=1), True)

def no_call_data(send, vc=500):
    """Data on VCs whose call was not captured: what the preferences "check data", QLLC and
    COTP-without-data change; by default the payload is shown as data."""
    send(data8(vc, 0, 0, bytes([2, 0xF0, 0x80]) + b'cotp'), True)                       # looks like COTP
    send(data8(vc + 1, 0, 0, udp_ip_datagram(b'ip guess')), True)                       # looks like IP
    send(data8(vc + 2, 0, 0, clnp_dt(b'clnp guess')), True)                             # looks like CLNP
    send(data8(vc + 3, 0, 0, b'\x01\x02\x03\x04\x05'), True)                            # nothing
    send(data8(vc + 4, 0, 0, b'qllc sna data', q=1), True)                              # QLLC (pref)
    send(data8(vc + 4, 1, 0, b'\x2d\x01\x02\x03'), False)
    # a call request without user data, then COTP data (pref: assume COTP for such calls)
    send(call_request(vc + 5, user=b''), True)
    send(call_accepted(vc + 5), False)
    send(data8(vc + 5, 0, 0, bytes([2, 0xF0, 0x80]) + b'cotp after nodata'), True)
    send(data8(vc + 5, 1, 1, bytes([2, 0xF0, 0x80]) + b'cotp reply'), False)


# ---- X.29 (PAD messages and terminal data) over X.25 over XOT (TCP 1998), plus Exported PDU ----
def build(outdir):
    n = PcapNG([1, 252])
    p = Pcap()
    class Sink(Pcap):
        pass
    # reuse the Tcp helper on a small adapter that appends to the pcapng
    class Adapter:
        def add(self, data):
            n.add(data, iface=0)
    t = Tcp(Adapter(), 42001, 1998)
    t.handshake()
    def send(pkt, from_dte=True):
        (t.c2s if from_dte else t.s2c)(xot(pkt))
    def pad(lcn, msg, ps, pr=0, from_dte=True):
        send(data8(lcn, ps, pr, msg, q=1), from_dte)
    # a call to the PAD: protocol identifier 01 00 00 00 starts X.29, the rest is data (a banner)
    vc = 1
    send(call_request(vc, user=b'\x01\x00\x00\x00' + b'PAD ready\r\n'))
    send(call_accepted(vc), False)
    ps = [0, 0]
    def padm(msg, from_dte=True):
        d = 0 if from_dte else 1
        pad(vc, msg, ps[d], ps[1 - d], from_dte)
        ps[d] = (ps[d] + 1) % 8
    # PAD messages with parameter/value pairs
    padm(bytes([0x02, 1, 1, 2, 0, 3, 126, 4, 0]))              # Set
    padm(bytes([0x04, 1, 0, 2, 0]), True)                      # Read
    padm(bytes([0x06, 5, 1, 6, 1]), True)                      # Set and read
    padm(bytes([0x00, 1, 1, 2, 0, 3, 126, 4, 0, 5, 1, 6, 1, 7, 8]), False)   # Parameter indication
    padm(bytes([0x00]), False)                                 # Parameter indication, no parameters
    padm(bytes([0x02]), True)                                  # Set without parameters
    padm(bytes([0x01]), False)                                 # Invitation to clear
    # indication of break: none, change of PAD aspect, break, another type reference
    padm(bytes([0x03]), True)
    padm(bytes([0x03, 0x01, 0x05]), True)
    padm(bytes([0x03, 0x08, 0x00]), True)
    padm(bytes([0x03, 0x55, 0x77]), True)
    padm(bytes([0x07, 0x12, 0x34, 0x56]), True)                # Reselection
    padm(bytes([0x08, 0x12, 0x34, 0x56, 0x78]), True)          # Reselection with TOA/NPI
    padm(bytes([0x05, 0x00]), False)                           # Error: less than eight bits
    padm(bytes([0x05, 0x02, 0x0E]), False)                     # Error: unrecognized message code, with the code
    padm(bytes([0x05, 0x04, 0x02]), False)
    padm(bytes([0x05, 0x0C, 0x07]), False)
    padm(bytes([0x0E, 0xAA, 0xBB]), True)                      # unknown message code
    # terminal data without the Q bit: lines with CR LF, CR, LF, no end of line, empty
    def text(t_, from_dte=True):
        d = 0 if from_dte else 1
        send(data8(vc, ps[d], ps[1 - d], t_), from_dte)
        ps[d] = (ps[d] + 1) % 8
    text(b'login: root\r\n', True)
    text(b'password: \r', False)
    text(b'line one\nline two\r\nline three\rline four', True)
    text(b'no line end', False)
    text(b'\r\n\r\n', True)
    text(b'', True)
    text(bytes(range(0x20, 0x7f)) + b'\x80\xff\r\n', False)
    # data in M-bit fragments is reassembled before X.29 sees it
    send(data8(vc, ps[0], ps[1], b'long line part 1, ', m=1), True)
    ps[0] = (ps[0] + 1) % 8
    send(data8(vc, ps[0], ps[1], b'part 2\r\nsecond line\r\n'), True)
    ps[0] = (ps[0] + 1) % 8
    # mod 128 call with PAD messages and data
    vc2 = 2
    send(call_request(vc2, user=b'\x01\x00\x00\x00', gfi=GFI_MOD128 | GFI_D))
    send(call_accepted(vc2, gfi=GFI_MOD128), False)
    send(data128(vc2, 0, 0, bytes([0x02, 1, 1]), q=1), True)
    send(data128(vc2, 0, 1, bytes([0x00, 1, 1]), q=1), False)
    send(data128(vc2, 1, 1, b'hello from mod 128\r\n'), True)
    send(data128(vc2, 1, 2, b'', q=1), False)
    # a second X.29 call with the SPI only (the PAD does not send any more data)
    send(call_request(3, user=b'\x01\x00\x00\x00'))
    send(clear_request(3, 0x00, 0x00))
    send(clear_request(vc, 0x00, 0x00))
    send(clear_confirm(vc), False)
    t.fin()
    # Exported PDU entries that name "x29": the dissector needs the Q bit from X.25 and gives up
    for body in (b'\x02\x01\x01', b'plain text\r\n', b''):
        n.add(exported_pdu('x29', body), iface=1)
    c = n.write(os.path.join(outdir, 'x29-coverage.pcapng'))
    print('x29-coverage.pcapng', c)

    # malformed: PAD messages cut in the middle of a parameter pair, an error message without type
    m = Pcap()
    mt = Tcp(m, 42002, 1998)
    mt.handshake()
    def msend(pkt, from_dte=True):
        (mt.c2s if from_dte else mt.s2c)(xot(pkt))
    msend(call_request(1, user=b'\x01\x00\x00\x00'))
    msend(data8(1, 0, 0, bytes([0x02, 1, 1, 2]), q=1))        # odd number of parameter octets
    msend(data8(1, 1, 0, bytes([0x04, 7]), q=1))
    msend(data8(1, 2, 0, bytes([0x05]), q=1))                 # error without type
    msend(data8(1, 3, 0, bytes([0x05, 0x02]), q=1))           # error without code
    msend(data8(1, 4, 0, bytes([0x03, 0x01]), q=1))           # break, aspect without value
    msend(data8(1, 5, 0, bytes([0x03, 0x08]), q=1))
    msend(data8(1, 6, 0, bytes([0x03, 0x55]), q=1))
    msend(data8(1, 7, 0, b'', q=1))                           # PAD message without a code
    msend(data8(1, 0, 0, bytes([0xFF]), q=1))                 # unknown code, no data
    msend(data8(1, 1, 0, bytes([0x07]), q=1))                 # reselection without data
    msend(data8(1, 2, 0, bytes([0x08]), q=1))                 # reselection with TOA/NPI without data
    mt.fin()
    c = m.write(os.path.join(outdir, 'x29-coverage-malformed.pcap'))
    print('x29-coverage-malformed.pcap', c)

if __name__ == '__main__':
    build(outdir())
