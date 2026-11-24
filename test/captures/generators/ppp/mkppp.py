#!/usr/bin/env python3
# Generates test/captures/ppp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the PPP coverage captures. Usage: mkppp.py <outdir> [-v].

Synthetic data only: documentation addresses (192.0.2.0/24, 2001:db8::/32),
made-up names. The PAP/CHAP fields hold placeholder octets, no key, hash or
ciphertext is computed. The main capture is a pcapng file with four
interfaces: PPP (DLT 9), PPP with direction (DLT 204), Linux cooked
(DLT 113) and Ethernet (DLT 1)."""
import struct
import sys
import zlib

DLT_EN10MB, DLT_PPP, DLT_SLL, DLT_PPP_WITH_DIR, DLT_USB_LINUX = 1, 9, 113, 204, 189

# PPP protocol numbers
IP, MP, MUX, VSNP, BCP_BPDU = 0x21, 0x3d, 0x59, 0x5b, 0x31
IPV6, RTP_FH, RTP_CNTCP, RTP_CUDP8 = 0x57, 0x61, 0x65, 0x67
RTP_CS, RTP_CUDP16, COMP = 0x2065, 0x2067, 0xfd
CDPCP, MPLSCP, IPCP, OSINLCP, BCP_NCP, IPV6CP = 0x8207, 0x8281, 0x8021, 0x8023, 0x8031, 0x8057
MUXCP, VSNCP, CCP = 0x8059, 0x805b, 0x80fd
LCP, PAP, CBCP, BACP, BAP, CHAP = 0xc021, 0xc023, 0xc029, 0xc02b, 0xc02d, 0xc223


class Cap:
    def __init__(self):
        self.frames = []      # (interface index, bytes, original length)
        self.marks = []

    def note(self, label):
        self.marks.append((len(self.frames) + 1, label))

    def add(self, data, ifc=0, orig=None):
        self.frames.append((ifc, data, orig))


def ppp(proto, data, pfc=False, acfc=False):
    """A PPP frame in HDLC-like framing (as DLT_PPP delivers it)."""
    p = struct.pack('!H', proto)
    if pfc and proto < 0x100:
        p = p[1:]
    return (b'' if acfc else b'\xff\x03') + p + data


def cp(code, ident, data=b''):
    return struct.pack('!BBH', code, ident, 4 + len(data)) + data


def opt(t, data=b''):
    return bytes([t, 2 + len(data)]) + data


def ip4(a):
    return bytes(map(int, a.split('.')))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(payload, proto=17, src='192.0.2.1', dst='192.0.2.2', ihl=5, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, 4 * ihl + len(payload), ident, 0, 64, proto,
                    0, ip4(src), ip4(dst)) + b'\x01' * (4 * (ihl - 5))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def udp(data, sport=5004, dport=5004):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data


UDP_PKT = ipv4(udp(b'synthetic payload'))


def ipv6_pkt():
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    payload = udp(b'v6 payload')
    ck = csum(src + dst + struct.pack('!IBBBB', len(payload), 0, 0, 0, 17) + payload) or 0xffff
    payload = payload[:6] + struct.pack('!H', ck) + payload[8:]
    return struct.pack('!IHBB', 0x60000000, len(payload), 17, 64) + src + dst + payload


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload


ETH_IP = eth(b'\x02\x00\x00\x00\x00\x02', b'\x02\x00\x00\x00\x00\x01', 0x0800, UDP_PKT)


# --------------------------------------------------------------------------
# option tables: (type, [valid data variants])
# --------------------------------------------------------------------------
def lcp_options():
    o = []
    o.append(opt(0, b'\x00\x00\x0c\x01'))                   # vendor, Cisco OUI, no data
    o.append(opt(0, b'\x00\x00\x0c\x01abcd'))
    o.append(opt(1, struct.pack('!H', 1500)))
    o.append(opt(2, struct.pack('!I', 0)))
    o.append(opt(2, struct.pack('!I', 0xffffffff)))
    o.append(opt(2, struct.pack('!I', 0x000a0000)))
    o.append(opt(2, struct.pack('!I', 0x80000001)))
    o.append(opt(3, struct.pack('!H', 0xc023)))                       # PAP
    o.append(opt(3, struct.pack('!H', 0xc223) + b'\x05'))             # CHAP, MD5
    o.append(opt(3, struct.pack('!H', 0xc223) + b'\x80' + b'\x01\x02'))
    o.append(opt(3, struct.pack('!H', 0xc227)))                       # EAP
    o.append(opt(3, struct.pack('!H', 0xc027) + b'\x01\x02\x03'))     # other protocol with data
    o.append(opt(4, struct.pack('!H', 0xc025)))                       # LQR, no data
    o.append(opt(4, struct.pack('!H', 0xc025) + struct.pack('!I', 100)))
    o.append(opt(5, struct.pack('!I', 0x01020304)))
    o.append(opt(6, struct.pack('!I', 1000)))
    o.append(opt(6, struct.pack('!I', 0)))
    o.append(opt(7))
    o.append(opt(8))
    o.append(opt(9, b'\x07'))
    o.append(opt(10, b'\x04'))
    o.append(opt(10, b'\x00'))
    o.append(opt(11, b'\x07'))
    o.append(opt(11, b'\x07\x01\x02\x03'))
    o.append(opt(11, b'\x00'))
    o.append(opt(11, b'\xc8'))
    for op in range(0, 8):
        o.append(opt(13, bytes([op]) + (b'555-0100' if op else b'')))
    o.append(opt(15))
    o.append(opt(16))
    o.append(opt(17, struct.pack('!H', 1600)))
    o.append(opt(18))
    o.append(opt(19, b'\x00'))
    o.append(opt(19, b'\x00\x01'))
    o.append(opt(19, b'\x01' + b'L' * 25))
    o.append(opt(19, b'\x02' + ip4('192.0.2.77')))
    o.append(opt(19, b'\x02\x01\x02'))
    o.append(opt(19, b'\x03' + b'\x02\x00\x00\x00\x00\x07'))
    o.append(opt(19, b'\x03\x01\x02\x03'))
    o.append(opt(19, b'\x04' + struct.pack('!II', 1, 2)))
    o.append(opt(19, b'\x04' + struct.pack('!IIIIII', 1, 2, 3, 4, 5, 6)))
    o.append(opt(19, b'\x04\x01\x02\x03'))
    o.append(opt(19, b'\x05' + b'5551234'))
    o.append(opt(19, b'\x05' + b'1' * 20))
    o.append(opt(19, b'\x09\x01\x02'))
    o.append(opt(21, b'\x01'))
    o.append(opt(21, b'\x02'))
    o.append(opt(21, b'\x07'))
    o.append(opt(22, b'\x00\x00'))
    o.append(opt(23, struct.pack('!H', 0x1234)))
    o.append(opt(24, b'\x01'))
    o.append(opt(24, b'\x01\x02\x03\x04'))
    o.append(opt(25, b'\x04'))
    o.append(opt(26, b'\x01\x02\xaa\xbb\x02\x01\xcc'))
    o.append(opt(26))
    o.append(opt(26, b'\x01\x09\xaa'))
    o.append(opt(27, b'\x02\x04'))
    o.append(opt(27, b'\x06\x08'))
    o.append(opt(28, struct.pack('!I', 4) + b'en-US'))
    o.append(opt(28, struct.pack('!I', 106) + b'sv'))
    o.append(opt(29))
    o.append(opt(99, b'\x01\x02\x03'))
    return o


def ipcp_options():
    o = []
    o.append(opt(1, ip4('192.0.2.1') + ip4('192.0.2.2')))
    o.append(opt(2, struct.pack('!H', 0x002d) + b'\x0f\x01'))
    o.append(opt(2, struct.pack('!H', 0x0037) + b'\x07\x00'))
    o.append(opt(2, struct.pack('!H', 0x0003) + struct.pack('!HHH', 15, 1500, 60)))
    o.append(opt(2, struct.pack('!H', 0x0003) + struct.pack('!HHH', 15, 1500, 60) +
                 opt(1, struct.pack('!HHH', 0, 1, 2))))
    o.append(opt(2, struct.pack('!H', 0x0003) + struct.pack('!HHH', 15, 1500, 60) +
                 opt(1, struct.pack('!H', 0)) + opt(1)))
    o.append(opt(2, struct.pack('!H', 0x0061) + struct.pack('!HHHHH', 15, 15, 0, 0, 168)))
    o.append(opt(2, struct.pack('!H', 0x0061) + struct.pack('!HHHHH', 15, 15, 256, 5, 168) +
                 opt(1) + opt(2) + opt(3, b'\x01') + opt(9, b'\x01\x02')))
    o.append(opt(2, struct.pack('!H', 0x1234) + b'\x01\x02\x03'))
    o.append(opt(2, struct.pack('!H', 0x1234)))
    o.append(opt(3, ip4('192.0.2.1')))
    o.append(opt(4, ip4('192.0.2.50')))
    o.append(opt(129, ip4('192.0.2.53')))
    o.append(opt(130, ip4('192.0.2.137')))
    o.append(opt(131, ip4('192.0.2.54')))
    o.append(opt(132, ip4('192.0.2.138')))
    o.append(opt(200, b'\x01'))
    return o


def ipv6cp_options():
    return [opt(1, bytes(range(1, 9))),
            opt(2, struct.pack('!H', 0x002d) + b'\x0f\x01'),
            opt(2, struct.pack('!H', 0x0061) + struct.pack('!HHHHH', 15, 15, 0, 0, 168)),
            opt(9, b'\x01')]


def bcp_ncp_options():
    return [opt(1, struct.pack('!H', 0x1235)), opt(2, struct.pack('!H', 0x5671)),
            opt(3, b'\x01'), opt(3, b'\x0c'), opt(4, b'\x01'), opt(4, b'\x00'), opt(5, b'\x01'),
            opt(6, b'\x02\x00\x00\x00\x00\x07'),
            opt(6, b'\x03\x00\x00\x00\x00\x07'),           # L and M bits of the first octet pair
            opt(6, b'\x00\x01\x00\x00\x00\x07'),
            opt(6, b'\x01\x01\x00\x00\x00\x07'),
            opt(7, b'\x01'), opt(7, b'\x00\x01\x02\x03\x04\x07'), opt(7, b''),
            opt(8, b'\x01'), opt(9, b'\x01'), opt(10, b'\x01'), opt(77, b'\x01')]


def osinlcp_options():
    return [opt(1, b'\x04'), opt(1, b'\x00'), opt(9, b'\x01')]


def ccp_options():
    o = []
    o.append(opt(0, b'\x00\x00\x0c\x01'))
    o.append(opt(0, b'\x00\x00\x0c\x01abc'))
    for t in (1, 2, 3, 16):
        o.append(opt(t))
        o.append(opt(t, b'\x01\x02'))
    o.append(opt(17, struct.pack('!HB', 1, 3)))
    o.append(opt(17, struct.pack('!HB', 1, 3) + b'\x01'))
    o.append(opt(17, struct.pack('!HB', 1, 3) + b'\x01\x02\x03'))
    for bits in (0x01000001, 0x000000e0, 0x00000010, 0x01000040, 0x00000000):
        o.append(opt(18, struct.pack('!I', bits)))
    o.append(opt(19, b'\x08'))
    o.append(opt(19, b'\x08\x01\x02'))
    o.append(opt(20))
    o.append(opt(20, b'\x01\x02\x03'))
    o.append(opt(21, b'\x2f'))
    o.append(opt(21, b'\x20'))
    o.append(opt(23, struct.pack('!HBB', 1, 3, 1)))
    o.append(opt(24, b'\x81\x07'))
    o.append(opt(25, b'\x01'))
    o.append(opt(26, b'\x78\x00'))
    o.append(opt(26, b'\x7a\x01'))
    o.append(opt(27, struct.pack('!H', 0)))
    o.append(opt(27, struct.pack('!H', 1) + struct.pack('!H', 4000)))
    o.append(opt(27, struct.pack('!H', 3) + struct.pack('!HH', 4000, 8000)))
    o.append(opt(200, b'\x01'))
    return o


def vsncp_options():
    o = []
    o.append(opt(1, b'\x05'))
    o.append(opt(2, b'\x03isp\x07example\x03net'))
    o.append(opt(2))
    o.append(opt(3, b'\x01'))
    o.append(opt(3, b'\x03'))
    o.append(opt(4, b'\x01' + ip4('192.0.2.9')))
    o.append(opt(4, b'\x02' + bytes(range(8))))
    o.append(opt(4, b'\x03' + bytes(range(8)) + ip4('192.0.2.10')))
    o.append(opt(4, b'\x09'))
    o.append(opt(5, b'\x80' + struct.pack('!HB', 0x8021, 4) + ip4('192.0.2.1') +
                 struct.pack('!HB', 0xc023, 0) + struct.pack('!HB', 0x000a, 0)))
    o.append(opt(5))
    o.append(opt(6, b'\x02'))
    o.append(opt(7, b'\x01'))
    o.append(opt(8, ip4('192.0.2.254')))
    o.append(opt(9, b'\x00'))
    o.append(opt(10, b'\x00\x01\x02\x03'))
    o.append(opt(11, bytes(range(10, 18))))
    o.append(opt(66, b'\x01'))
    return o


def bap_options():
    return {
        1: [opt(1, struct.pack('!HB', 128, 1))],
        2: [opt(2, opt(1, b'\x05') + opt(2, b'5550100') + opt(3, b'12') + opt(9, b'zz'))],
        3: [opt(3)],
        4: [opt(4, b'Reason text'), opt(4)],
        5: [opt(5, struct.pack('!H', 0x0102))],
        6: [opt(6, b'\x00\x01')],
    }


def group(options, per=3):
    return [options[i:i + per] for i in range(0, len(options), per)]


# --------------------------------------------------------------------------
def build():
    c = Cap()
    ident = [0]

    def nid():
        ident[0] = (ident[0] + 1) & 0xff
        return ident[0]

    def send(proto, data, **kw):
        c.add(ppp(proto, data, **kw))

    def cps(proto, code, data=b'', **kw):
        send(proto, cp(code, nid(), data), **kw)

    CODES = (1, 2, 3, 4)

    c.note('LCP configuration options (Request/Ack/Nak/Reject, three options each)')
    for n, g in enumerate(group(lcp_options(), 3)):
        cps(LCP, CODES[n % 4], b''.join(g))
    c.note('LCP other codes: Terminate, Code-Reject, Echo, Discard, Identification, Time-Remaining, Reset, vendor, unknown')
    cps(LCP, 5)
    cps(LCP, 5, b'user request')
    cps(LCP, 6, b'bye')
    cps(LCP, 7, cp(200, 1, b'x'))
    cps(LCP, 7)
    cps(LCP, 9, struct.pack('!I', 0x11223344))
    cps(LCP, 9, struct.pack('!I', 0x11223344) + b'pad pad')
    cps(LCP, 10, struct.pack('!I', 0x55667788))
    cps(LCP, 10, struct.pack('!I', 0x55667788) + b'echo')
    cps(LCP, 11, struct.pack('!I', 0x11223344))
    cps(LCP, 11, struct.pack('!I', 0x11223344) + b'discard me')
    cps(LCP, 12, struct.pack('!I', 0x11223344) + b'synthetic-ident')
    cps(LCP, 12, struct.pack('!I', 0x11223344))
    cps(LCP, 13, struct.pack('!II', 0x11223344, 300))
    cps(LCP, 13, struct.pack('!II', 0x11223344, 0xffffffff) + b'forever')
    cps(LCP, 14)
    cps(LCP, 15, b'\x01\x02')
    cps(LCP, 0, struct.pack('!I', 0x01020304) + b'\x00\x00\x0c' + b'\x07' + b'vendor data')
    cps(LCP, 0, struct.pack('!I', 0x01020304) + b'\x12\x34\x56' + b'\x01')
    cps(LCP, 200, b'\x01\x02')
    cps(LCP, 200)
    c.note('LCP in frames without address/control and with a compressed protocol field')
    send(LCP, cp(9, nid(), struct.pack('!I', 1)), acfc=True)
    send(LCP, cp(9, nid(), struct.pack('!I', 1)), acfc=True, pfc=True)
    c.note('Protocol-Reject: unknown protocol, IPCP, nested Protocol-Reject up to past the nesting limit')
    cps(LCP, 8, struct.pack('!H', 0x1234) + b'rejected')
    cps(LCP, 8, struct.pack('!H', 0x0021) + UDP_PKT)
    cps(LCP, 8, struct.pack('!H', IPCP) + cp(1, 1, opt(3, ip4('192.0.2.1'))))
    cps(LCP, 8, struct.pack('!H', 0x0021))
    inner = cp(9, 1, b'\0\0\0\0')
    for _ in range(10):
        inner = cp(8, 1, struct.pack('!H', LCP) + inner)
    send(LCP, inner)
    c.note('option parsing: length byte past the end, length 1, length past the end of the options, unknown option')
    send(LCP, cp(1, nid(), b'\x01'))
    send(LCP, cp(1, nid(), b'\x01\x01'))
    send(LCP, cp(1, nid(), b'\x01\x08\x05\xdc'))
    send(LCP, cp(1, nid(), opt(200, b'\x01\x02') + opt(201)))
    c.note('quality-protocol reproducer, wrong option lengths (invalid length warnings)')
    send(LCP, cp(1, nid(), opt(4, struct.pack('!H', 0xc025) + struct.pack('!I', 16))))
    send(LCP, cp(1, nid(), opt(1, b'\x05\xdc\x00')))
    send(LCP, cp(1, nid(), opt(5, b'\x01\x02')))
    send(LCP, cp(1, nid(), opt(7, b'\x01')))
    send(LCP, cp(1, nid(), opt(19) + opt(3) + opt(0) + opt(28, b'\x01')))

    c.note('IPCP')
    for n, g in enumerate(group(ipcp_options(), 3)):
        cps(IPCP, CODES[n % 4], b''.join(g))
    cps(IPCP, 5, b'bye')
    cps(IPCP, 6)
    cps(IPCP, 7, cp(1, 1))
    cps(IPCP, 0, struct.pack('!I', 5) + b'\x00\x00\x0c' + b'\x01')
    cps(IPCP, 99, b'xyz')
    cps(IPCP, 99)
    send(IPCP, cp(1, nid(), opt(2, struct.pack('!H', 0x0061) + struct.pack('!HHHHH', 15, 15, 0, 0, 168) + opt(3))))
    c.note('IPv6CP, OSI-NLCP')
    for n, g in enumerate(group(ipv6cp_options(), 2)):
        cps(IPV6CP, CODES[n % 4], b''.join(g))
    for n, g in enumerate(group(osinlcp_options(), 2)):
        cps(OSINLCP, CODES[n % 4], b''.join(g))
    cps(OSINLCP, 1, opt(1))
    c.note('BCP NCP options, BCP data with every MAC type, Bridge control')
    for n, g in enumerate(group(bcp_ncp_options(), 3)):
        cps(BCP_NCP, CODES[n % 4], b''.join(g))
    zero = zlib.crc32(ETH_IP) & 0xffffffff
    fcs = struct.pack('<I', zero)
    send(BCP_BPDU, bytes([0x00, 1]) + ETH_IP)
    send(BCP_BPDU, bytes([0x80, 1]) + ETH_IP + fcs)
    send(BCP_BPDU, bytes([0x23, 1]) + ETH_IP + b'\x00\x00\x00')
    send(BCP_BPDU, bytes([0x10, 1]) + b'\x42\x42\x03')
    for mt in (2, 3, 4, 11, 12):
        send(BCP_BPDU, bytes([0x00, mt, 0x00]) + b'\x01\x02\x03\x04\x05\x06')
    send(BCP_BPDU, bytes([0x00, 9]) + b'\xde\xad\xbe\xef')
    send(BCP_BPDU, bytes([0x0f, 1]) + b'\x01')          # more pad octets than data

    c.note('CCP options and Reset-Request/Ack')
    for n, g in enumerate(group(ccp_options(), 3)):
        cps(CCP, CODES[n % 4], b''.join(g))
    cps(CCP, 14)
    cps(CCP, 15, b'\x01\x02')
    cps(CCP, 5, b'bye')
    send(COMP, b'\x01\x02\x03\x04compressed data')
    c.note('Callback Control Protocol and BACP')
    cbcp_user = opt(2, b'\x05' + b'\x01' + b'5550100\x00' + b'\x02' + b'room-12\x00')
    cps(CBCP, 1, opt(1, b'\x00') + opt(1))
    cps(CBCP, 1, cbcp_user)
    cps(CBCP, 2, opt(3, b'\x00' + b'\x01' + b'5550101\x00'))
    cps(CBCP, 2, opt(4, b'\x00' + b'\x01' + b'5550102\x00' + b'\x01' + b'5550103\x00'))
    cps(CBCP, 3, opt(2, b'\x00'))
    cps(CBCP, 3)
    cps(BACP, 1, opt(1, struct.pack('!I', 0x01020304)))
    cps(BACP, 2, opt(1, struct.pack('!I', 0x01020304)))
    cps(BACP, 3, opt(2, b'\x01\x02'))
    cps(BACP, 1, opt(1, b'\x01'))
    c.note('BAP: every type, response codes, options and phone-delta sub-options')
    bo = bap_options()
    allbap = [o for l in bo.values() for o in l]
    for t in (1, 3, 5, 7):
        send(BAP, struct.pack('!BBH', t, nid(), 4 + sum(len(o) for o in allbap[:6])) + b''.join(allbap[:6]))
    for t, rc in ((2, 0x00), (4, 0x01), (6, 0x02), (8, 0x03), (2, 0x04)):
        body = bytes([rc]) + b''.join(allbap[6:])
        send(BAP, struct.pack('!BBH', t, nid(), 4 + len(body)) + body)
    send(BAP, struct.pack('!BBH', 1, nid(), 4))
    send(BAP, struct.pack('!BBH', 9, nid(), 4 + 4) + b'\x01\x02\x03\x04')
    for l in bo.values():
        for o in l:
            send(BAP, struct.pack('!BBH', 7, nid(), 4 + len(o)) + o)
    c.note('PAP and CHAP (placeholder fields), unknown codes, short and odd lengths')
    send(PAP, bytes([1, 1]) + struct.pack('!H', 4 + 1 + 4 + 1 + 6) + b'\x04' + b'user' + b'\x06' + b'pw-xyz')
    send(PAP, bytes([2, 1]) + struct.pack('!H', 4 + 1 + 7) + b'\x07' + b'Welcome')
    send(PAP, bytes([3, 1]) + struct.pack('!H', 4 + 1 + 6) + b'\x06' + b'Denied')
    send(PAP, bytes([9, 1]) + struct.pack('!H', 6) + b'\x01\x02')
    send(CHAP, bytes([1, 7]) + struct.pack('!H', 4 + 1 + 16 + 6) + b'\x10' + bytes(range(16)) + b'server')
    send(CHAP, bytes([2, 7]) + struct.pack('!H', 4 + 1 + 16 + 30) + b'\x10' + bytes(range(16, 32)) + b'a-very-long-peer-name-of-30-ch')
    send(CHAP, bytes([2, 7]) + struct.pack('!H', 4 + 1) + b'\x00')
    send(CHAP, bytes([1, 7]) + struct.pack('!H', 4 + 1 + 3) + b'\x03' + b'\x01\x02\x03')
    send(CHAP, bytes([3, 7]) + struct.pack('!H', 4 + 7) + b'Welcome')
    send(CHAP, bytes([4, 7]) + struct.pack('!H', 4 + 6) + b'Denied')
    send(CHAP, bytes([4, 7]) + struct.pack('!H', 4))
    send(CHAP, bytes([9, 7]) + struct.pack('!H', 6) + b'\x01\x02')
    send(CHAP, bytes([9, 7]) + struct.pack('!H', 4))
    send(CHAP, bytes([1, 7]) + struct.pack('!H', 3))               # length < 4
    send(CHAP, bytes([1, 7]) + struct.pack('!H', 4 + 1 + 8) + b'\x28' + b'\x01' * 8)    # value size > length
    send(CHAP, bytes([1, 7]) + struct.pack('!H', 5) + b'\x00')

    c.note('PPPMuxCP (default PID 0x0021), then PPPMux sub-frames')
    cps(MUXCP, 1, opt(1, struct.pack('!H', 0x0021)))
    cps(MUXCP, 2, opt(1, struct.pack('!H', 0x0021)))
    cps(MUXCP, 5)
    cps(MUXCP, 1, opt(1, b'\x00'))
    pkt = UDP_PKT

    def sub(flags_len, pid, data, lxt=False, pff=True):
        n = len(data) + len(pid)
        if lxt:
            hdr = struct.pack('!H', 0x4000 | (0x8000 if pff else 0) | n)
        else:
            hdr = bytes([(0x80 if pff else 0) | n])
        return hdr + pid + data
    send(MUX, sub(0, b'\x21', pkt, pff=True))
    send(MUX, sub(0, b'\x00\x21', pkt, lxt=True))
    send(MUX, sub(0, b'', pkt, pff=False))
    send(MUX, sub(0, b'\x21', pkt) + sub(0, b'', pkt, pff=False) + sub(0, b'\x00\x57', ipv6_pkt(), lxt=True) +
         sub(0, b'', ipv6_pkt(), lxt=True, pff=False))
    send(MUX, sub(0, b'\x00\x3b', b'unknown protocol data'))
    # the reproducers of "PPP: Bound nesting of PPP payloads and fix small decoding errors"
    send(MUX, sub(0, b'', pkt, pff=False))                  # without PID: the default PID from MuxCP
    send(MUX, sub(0, b'\x00\x57', ipv6_pkt()))
    inner = b'\x00\x01\x02'
    for _ in range(10):
        inner = struct.pack('!H', 0xc000 | (len(inner) + 2)) + b'\x00\x59' + inner
    send(MUX, inner)
    # two sub-frames: a PID, then none (PID carried over inside the packet)
    send(MUX, sub(0, b'\x21', pkt) + sub(0, b'', pkt, pff=False) + sub(0, b'', pkt, pff=False))

    c.note('MPLSCP and CDPCP (no option table), VSNCP and VSNP (3GPP2)')
    cps(MPLSCP, 1, opt(7, b'\x01') + opt(9))
    cps(MPLSCP, 5, b'x')
    cps(CDPCP, 1, opt(1, b'\x01\x02'))
    cps(CDPCP, 2)
    # VSNCP: every packet uses the 3GPP2 OUI, so that VSNP decodes the same in a second pass
    voui = b'\xcf\x00\x02'
    vo = vsncp_options()
    for n, g in enumerate(group(vo, 3)):
        send(VSNCP, struct.pack('!BBH', CODES[n % 4], nid(), 7 + sum(len(x) for x in g)) + voui + b''.join(g))
    send(VSNCP, struct.pack('!BBH', 5, nid(), 7) + voui)
    send(VSNCP, struct.pack('!BBH', 6, nid(), 7) + voui)
    send(VSNCP, struct.pack('!BBH', 77, nid(), 9) + voui + b'\x01\x02')
    send(VSNP, b'\x05' + UDP_PKT)

    c.note('Multilink: one B+E fragment, three fragments, class bits, an unreassembled fragment, nested single fragments')
    body = struct.pack('!H', IP) + UDP_PKT
    send(MP, bytes([0xc0]) + (1).to_bytes(3, 'big') + body)
    for k, (flag, part) in enumerate(((0x80, body[:12]), (0x00, body[12:25]), (0x40, body[25:]))):
        send(MP, bytes([flag]) + (10 + k).to_bytes(3, 'big') + part)
    for k, (flag, part) in enumerate(((0x80 | (2 << 2), body[:20]), (0x40 | (2 << 2), body[20:]))):
        send(MP, bytes([flag]) + (20 + k).to_bytes(3, 'big') + part)
    send(MP, bytes([0x80]) + (30).to_bytes(3, 'big') + body[:15])
    send(MP, bytes([0x80]) + (31).to_bytes(3, 'big') + b'\x01' * 4)
    send(MP, bytes([0xc0]) + (32).to_bytes(3, 'big'))
    send(MP, bytes([0xc0 | 0x03]) + (33).to_bytes(3, 'big') + struct.pack('!H', 0x1234) + b'abc')
    inner = struct.pack('!H', IP) + UDP_PKT
    for k in range(10):
        inner = struct.pack('!H', MP) + bytes([0xc0]) + (100 + k).to_bytes(3, 'big') + inner
    send(MP, inner[2:])

    c.note('Compressed RTP over PPP: full header, compressed UDP, context state, compressed non-TCP')
    rtp = udp(bytes([0x80, 0, 0, 1]) + b'\x00' * 8)

    def fh(flags, cid=None, seq=0, ihl=5, v=4, proto=17, cidlen16=False):
        p = bytearray(ipv4(rtp, proto=proto, ihl=ihl))
        p[0] = (v << 4) | ihl
        p[2] = flags
        l = 4 * ihl
        if cidlen16:
            p[3] = seq
            p[l + 4:l + 6] = struct.pack('!H', cid or 0x0102)
        else:
            p[3] = cid or 7
            p[l + 5] = seq
        return bytes(p)
    send(RTP_FH, fh(0xc0 | 5, seq=9, cidlen16=True))
    send(RTP_FH, fh(0x80 | 5, seq=0, cidlen16=True))
    send(RTP_FH, fh(0x80 | 5, seq=3, cidlen16=True))
    send(RTP_FH, fh(0x40 | 5, seq=9))
    send(RTP_FH, fh(0x00 | 5, seq=0))
    send(RTP_FH, fh(0x00 | 5, seq=4))
    send(RTP_FH, fh(0x40 | 5, seq=9, ihl=6))
    send(RTP_FH, fh(0x40 | 5, seq=9, v=6))
    send(RTP_FH, fh(0x40 | 5, seq=9, proto=6))
    send(RTP_CUDP16, b'\x01\x02\x03' + b'rtp data')
    send(RTP_CUDP8, b'\x07\x03' + b'rtp data')
    send(RTP_CS, bytes([1, 2]) + bytes([5, 0x41, 3]) + bytes([6, 0x02, 4]))
    send(RTP_CS, bytes([2, 2]) + bytes([0, 5, 0x41, 3]) + bytes([0, 6, 0x02, 4]))
    send(RTP_CNTCP, bytes([0x07, 0x40 | 3, 9]) + struct.pack('!H', 0x1234) + b'data')
    send(RTP_CNTCP, bytes([0x07, 0x00 | 3]) + struct.pack('!H', 0x1234) + b'data')
    send(RTP_CNTCP, bytes([0x07, 0xc0 | 3, 0x01, 9]) + struct.pack('!H', 0x1234) + b'data')
    send(RTP_CNTCP, bytes([0x07, 0x80 | 3, 0x01]) + struct.pack('!H', 0x1234) + b'data')

    c.note('PPP framing: IPv4, IPv6, compressed protocol field, no address/control, Cisco HDLC, unknown protocols')
    send(IP, UDP_PKT)
    send(IP, UDP_PKT, pfc=True)
    send(IP, UDP_PKT, acfc=True)
    send(IP, UDP_PKT, acfc=True, pfc=True)
    send(IPV6, ipv6_pkt())
    send(0x1234, b'\x01\x02\x03')
    send(0x00fb, b'\x01\x02')
    send(0x0053, b'\x01\x02')
    c.add(b'\x0f\x00\x08\x00' + UDP_PKT)
    c.add(b'\x8f\x00\x08\x00' + UDP_PKT)
    c.note('PPP with direction (DLT 204) and Linux cooked capture')
    for d in (0, 1):
        c.add(bytes([d]) + ppp(LCP, cp(9, nid(), struct.pack('!I', d))), ifc=1)
        c.add(bytes([d]) + ppp(IP, UDP_PKT), ifc=1)
    c.add(bytes([1]) + ppp(IPCP, cp(1, 3, opt(3, ip4('192.0.2.1')))), ifc=1)
    # a frame cut by the snap length (captured 14 octets of 61)
    full = ppp(IP, UDP_PKT)
    c.add(full[:14], ifc=0, orig=len(full))
    c.add(full[:-1], ifc=0, orig=len(full))
    c.add(full[:-3], ifc=0, orig=len(full))
    sll = lambda payload, pt=0: struct.pack('!HHH8sH', pt, 512, 0, b'', 0x0007) + payload
    c.add(sll(ppp(LCP, cp(9, nid(), struct.pack('!I', 5)))), ifc=2)
    c.add(sll(ppp(IP, UDP_PKT), pt=4), ifc=2)

    c.note('PPP over GRE: enhanced GRE (PPTP) and the raw HDLC byte stream protocols')
    ethhdr = lambda payload: eth(b'\x02\x00\x00\x00\x00\x02', b'\x02\x00\x00\x00\x00\x01', 0x0800, payload)

    def gre_v1(ppp_frame, call=0x2222, seq=None):
        flags = 0x2001 | (0x1000 if seq is not None else 0)
        h = struct.pack('!HHHH', flags, 0x880b, len(ppp_frame), call)
        if seq is not None:
            h += struct.pack('!I', seq)
        return ethhdr(ipv4(h + ppp_frame, proto=47))

    def gre_raw(proto, data):
        return ethhdr(ipv4(struct.pack('!HH', 0, proto) + data, proto=47))
    c.add(gre_v1(ppp(LCP, cp(9, nid(), struct.pack('!I', 9)))), ifc=3)
    c.add(gre_v1(ppp(IP, UDP_PKT), seq=1), ifc=3)
    c.add(gre_v1(ppp(IPCP, cp(1, 1, opt(3, ip4('192.0.2.1'))), acfc=True)), ifc=3)
    esc = lambda b: b.replace(b'\x7d', b'\x7d\x5d').replace(b'\x7e', b'\x7d\x5e')
    f1 = b'\x7e' + b'\xff\x7d\x23' + b'\xc0\x21' + esc(cp(9, 1, b'\0\0\0\x05')) + b'\x7e'
    f2 = b'\x7e' + b'\xff\x7d\x23' + b'\x00\x21' + esc(UDP_PKT) + b'\x7e'
    c.add(gre_raw(0x8881, f1), ifc=3)
    c.add(gre_raw(0x8881, f1 + f2), ifc=3)
    c.add(gre_raw(0x8881, f1 + b'\x7e' + f2[1:]), ifc=3)
    c.add(gre_raw(0x8881, b'\xc0\x21\x09\x01\x00\x08\x00\x00\x00\x05\x7e' + f2), ifc=3)
    c.add(gre_raw(0x8881, f1 + b'\x7e\xff\x7d\x23\xc0\x21\x09'), ifc=3)
    c.add(gre_raw(0x8881, b'\x7e'), ifc=3)
    c.add(gre_raw(0x8881, b'\x7e\x7d'), ifc=3)
    c.add(gre_raw(0x8881, b'\x7e\x7e'), ifc=3)
    c.note('PPP in USB bulk transfers (the heuristic is off by default: shown as USB bulk data; runcov.sh enables it)')

    def usb(data):
        h = struct.pack('<QBBBBHBBqiiII8s', 1, 0x43, 3, 0x81, 4, 1, 0x2d, 0, 0, 0, 0, len(data), len(data), b'')
        return h + data
    lcpf = cp(9, 1, b'\0\0\0\x05')
    c.add(usb(b'\x7e\xff\x03\xc0\x21' + lcpf + b'\x7e'), ifc=4)
    c.add(usb(b'\x7e\xff\x7d\x23\xc0\x21' + esc(lcpf) + b'\x7e'), ifc=4)
    c.add(usb(b'\xff\x03\xc0\x21' + lcpf), ifc=4)
    c.add(usb(b'\xff\x7d\x23\xc0\x21' + esc(lcpf)), ifc=4)
    c.add(usb(b'\x7e\x00\x21' + UDP_PKT + b'\x7e'), ifc=4)
    c.add(usb(b'\x01\x02\x03\x04\x05'), ifc=4)
    return c


def build_malformed():
    """Frames the dissector reports as malformed or with errors."""
    c = Cap()

    def send(proto, data, **kw):
        c.add(ppp(proto, data, **kw))
    # every option cut or extended by one octet (with a consistent length byte)
    for proto, opts in ((LCP, lcp_options()), (IPCP, ipcp_options()), (IPV6CP, ipv6cp_options()),
                        (BCP_NCP, bcp_ncp_options()), (CCP, ccp_options()), (VSNCP, vsncp_options())):
        for o in opts:
            for delta in (-1, 1, -3):
                d = o[2:]
                d = d[:delta] if delta < 0 else d + b'\xaa' * delta
                if len(d) + 2 > 255 or (delta < 0 and len(o) - 2 < -delta):
                    continue
                oo = bytes([o[0], 2 + len(d)]) + d
                if proto == VSNCP:
                    send(proto, struct.pack('!BBH', 1, 1, 7 + len(oo)) + b'\xcf\x00\x02' + oo)
                else:
                    send(proto, cp(1, 1, oo))
    # options that are cut off in the middle of the packet
    for proto, o in ((IPCP, ipcp_options()[1]), (IPCP, ipcp_options()[3]), (IPCP, ipcp_options()[6]),
                     (LCP, lcp_options()[7])):
        send(proto, cp(1, 1, o)[:-2])
    send(LCP, cp(1, 1, opt(2, b'\x00')))
    # CBCP addresses without a terminating NUL, short CBCP options
    send(CBCP, cp(1, 1, opt(2, b'\x05\x01abc')))
    send(CBCP, cp(1, 1, opt(2, b'\x05')))
    send(CBCP, cp(1, 1, opt(3, b'\x05\x01abc')))
    send(CBCP, cp(1, 1, opt(4, b'\x05')))
    send(CBCP, cp(1, 1, opt(3, b'\x05\x01')))
    send(CBCP, cp(1, 1, opt(3, b'\x00\x00')))
    send(CBCP, cp(1, 1, opt(1)))
    # BAP phone delta sub-option errors
    for sub in (b'\x01\x01', b'\x01\x20', b'\x01\x04\x01', b'\x01\x04\x01\x02', b'\x02\x02', b'\x03\x02', b'\x09\x02'):
        send(BAP, struct.pack('!BBH', 7, 1, 4 + 2 + len(sub)) + opt(2, sub))
    send(BAP, struct.pack('!BBH', 7, 1, 4 + 3) + b'\x02\x03\x00')
    # control protocol packets cut in the header
    for proto in (LCP, IPCP, CCP, BCP_NCP, MUXCP, CBCP, BACP, MPLSCP, IPV6CP, OSINLCP, CDPCP):
        send(proto, b'\x01\x01')
        send(proto, cp(1, 1, opt(3, b'\x01'))[:5])
    send(VSNCP, b'\x01\x01\x00\x0b\xcf\x00')
    send(LCP, cp(9, 1)[:5])
    send(LCP, cp(13, 1, b'\0\0\0\1\0\0'))
    send(LCP, cp(0, 1, b'\0\0\0\1\0\0'))
    send(LCP, cp(8, 1, b'\x00'))
    # PAP/CHAP cut
    send(PAP, bytes([1, 1, 0, 20, 10]) + b'ab')
    send(PAP, bytes([2, 1, 0, 10, 10]) + b'ab')
    send(PAP, b'\x01\x01\x00')
    send(CHAP, bytes([1, 7, 0, 30, 0x10]) + b'\x01' * 5)
    send(CHAP, bytes([1, 7, 0]))
    send(CHAP, bytes([1, 7]) + struct.pack('!H', 4 + 1 + 40) + b'\x28' + b'\x01' * 4)
    # MP, MUX, CRTP and BCP cut
    send(MP, b'\xc0\x00')
    send(MUX, b'\x45')
    send(MUX, b'\x85\x21' + b'\x00' * 2)
    send(MUX, b'\x40')
    send(MUX, b'\x40\x10\x21\x00')
    send(RTP_FH, b'\x45\x00\xc0\x01')
    send(RTP_FH, bytes([0x45, 0, 0x40, 0, 0, 0, 0, 0, 0, 17]) + b'\x00' * 8)
    send(RTP_CUDP16, b'\x01')
    send(RTP_CUDP8, b'\x01')
    send(RTP_CS, b'\x01')
    send(RTP_CS, bytes([1, 3, 1]))
    send(RTP_CNTCP, b'\x07')
    send(BCP_BPDU, b'\x00')
    send(BCP_BPDU, b'\x00\x02')
    send(BCP_BPDU, bytes([0x80, 1]) + b'\x01\x02')
    send(VSNP, b'')
    send(VSNP, b'\x06' + b'\x45')
    send(IP, b'\x45\x00')
    c.add(b'\xff')
    c.add(b'\xff\x03\x00')
    # VSNP after a VSNCP with another OUI (state: the second pass differs)
    send(VSNP, b'\x05' + UDP_PKT)
    send(VSNCP, struct.pack('!BBH', 1, 1, 7) + b'\xcf\x00\x02')
    send(VSNCP, struct.pack('!BBH', 1, 1, 7) + b'\x00\x25\x6d')
    send(VSNP, b'\x05' + UDP_PKT)
    send(VSNCP, struct.pack('!BBH', 1, 1, 7) + b'\x12\x34\x56')
    send(VSNP, b'\x05' + UDP_PKT)
    # Multilink with sequence numbers past each other, a class and a fragment of 1 octet
    send(MP, bytes([0x80, 0xff, 0xff, 0xff]) + b'\x00\x21\x45')
    send(MP, bytes([0x40, 0xff, 0xff, 0xff]) + b'\x01')
    # raw HDLC byte stream with a lone escape at the end
    ethhdr = lambda payload: eth(b'\x02\x00\x00\x00\x00\x02', b'\x02\x00\x00\x00\x00\x01', 0x0800, payload)
    for data in (b'\xff\x7d\x23\xc0\x21\x09\x01\x00\x08', b'\x7d', b'\x7e\xff\x7d', b'\x7e\xff\x7d\x23\xc0\x21\x7d\x7e', b'\x7d\x7d\x7d\x7e',
                 b'\x7e\x7e\x7e\x7d\x23\x7e', b'\xff\x03\x7e'):
        c.add(ethhdr(ipv4(struct.pack('!HH', 0, 0x8881) + data, proto=47)), ifc=3)
    return c


def write_pcapng(name, cap, ifcs):
    def block(btype, body):
        pad = (-len(body)) % 4
        n = 12 + len(body) + pad
        return struct.pack('<II', btype, n) + body + b'\0' * pad + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for dlt in ifcs:
        out += block(1, struct.pack('<HHI', dlt, 0, 65535))
    for n, (ifc, data, orig) in enumerate(cap.frames):
        out += block(6, struct.pack('<IIIII', ifc, 0, n * 1000, len(data), orig or len(data)) + data)
    with open(name, 'wb') as fh:
        fh.write(out)


IFCS = (DLT_PPP, DLT_PPP_WITH_DIR, DLT_SLL, DLT_EN10MB, DLT_USB_LINUX)

if __name__ == '__main__':
    out = sys.argv[1]
    c = build()
    write_pcapng(out + '/ppp-coverage.pcapng', c, IFCS)
    write_pcapng(out + '/ppp-coverage-malformed.pcapng', build_malformed(), IFCS)
    if '-v' in sys.argv:
        for n, l in c.marks:
            print(n, l)
        print(len(c.frames), 'frames')
