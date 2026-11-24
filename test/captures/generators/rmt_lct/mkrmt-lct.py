#!/usr/bin/env python3
# Generates test/captures/rmt_lct_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(a): return bytes(int(x) for x in a.split('.'))

def ip_pkt(proto, l4, src, dst, ident=1, ttl=64):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, ttl, proto, 0, ip4(src), ip4(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + l4

ETH = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01'
def eth_wrap(ippkt, etype=0x0800, rev=False):
    mac = ETH[6:] + ETH[:6] if rev else ETH
    return mac + struct.pack('>H', etype) + ippkt

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_wrap(ip_pkt(17, udp, src, dst))

class Tcp:
    '''A TCP connection that tracks sequence numbers.'''
    def __init__(self, a, ap, b, bp):
        self.a, self.ap, self.b, self.bp = a, ap, b, bp
        self.seq = {0: 1000, 1: 5000}
    def seg(self, payload, d=0, flags=0x18, advance=True):
        if d == 0: s, sp, t, tp = self.a, self.ap, self.b, self.bp
        else: s, sp, t, tp = self.b, self.bp, self.a, self.ap
        seq, ack = self.seq[d], self.seq[1 - d]
        tcp = struct.pack('>HHIIBBHHH', sp, tp, seq, ack, 0x50, flags, 8192, 0, 0) + payload
        if advance:
            self.seq[d] += len(payload) + (1 if flags & 3 else 0)
        return eth_wrap(ip_pkt(6, tcp, s, t))
    def handshake(self):
        return [self.seg(b'', 0, 0x02), self.seg(b'', 1, 0x12), self.seg(b'', 0, 0x10)]

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---- pcapng ----
def _blk(btype, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', btype, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(name, ifaces, frames):
    '''ifaces: list of linktypes; frames: list of (iface index, data).'''
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in ifaces:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, d) in enumerate(frames):
        ts = 1000 * 1000000 + i * 100000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    with open(name, 'wb') as f:
        f.write(out)

def exp_pdu(dissector, payload):
    '''Exported PDU (linktype 252) carrying the named dissector.'''
    n = dissector.encode()
    tag = struct.pack('>HH', 12, (len(n) + 3) // 4 * 4) + n + b'\0' * ((-len(n)) % 4)
    return tag + struct.pack('>HH', 0, 0) + payload

# ---- ALC / LCT / FEC builders ----
import zlib

def lct_hdr(C=0, psi=0, S=0, O=0, H=0, T=0, R=0, A=0, B=0, cp=0, cci=None, tsi=0, toi=0,
            sct=None, ert=None, exts=b'', ver=1, hlen=None):
    b16 = (ver << 12) | (C << 10) | (psi << 8) | (S << 7) | (O << 5) | (H << 4) | (T << 3) | (R << 2) | (A << 1) | B
    cci_size = 4 * (C + 1)
    tsi_size = S * 4 + H * 2
    toi_size = O * 4 + H * 2
    if cci is None: cci = bytes(range(1, cci_size + 1))
    body = cci[:cci_size].ljust(cci_size, b'\0')
    body += (tsi % (1 << (8 * tsi_size))).to_bytes(tsi_size, 'big') if tsi_size else b''
    body += (toi % (1 << (8 * toi_size))).to_bytes(toi_size, 'big') if toi_size else b''
    if T: body += struct.pack('>I', 1000 if sct is None else sct)
    if R: body += struct.pack('>I', 2500 if ert is None else ert)
    body += exts
    total = 4 + len(body)
    if hlen is None: hlen = total // 4
    return struct.pack('>HBB', b16, hlen, cp) + body

def ext_var(het, data):
    '''Variable-length header extension (HET <= 127): HET, HEL (words), data; padded to words.'''
    n = 2 + len(data)
    n += (-n) % 4
    return bytes([het, n // 4]) + data.ljust(n - 2, b'\0')

def ext_fixed(het, b3):
    '''Fixed-length (4 octet) extension (HET >= 128): HET + 3 octets.'''
    return bytes([het]) + b3

def ext_fti(transfer_len, rest, tl_bytes=6):
    '''EXT_FTI (HET 64): HEL, 48 bit transfer length, then 'rest' (padded to words)'''
    data = transfer_len.to_bytes(tl_bytes, 'big') + rest
    return ext_var(64, data)

def fec_hdr(cp, sbn=3, esi=0x1234, sbl=77, inst=0):
    if cp in (0, 1, 130): return struct.pack('>HH', sbn & 0xffff, esi & 0xffff)
    if cp in (2, 128, 132): return struct.pack('>II', sbn, esi)
    if cp in (3, 4): return struct.pack('>I', ((sbn & 0xfff) << 20) | (esi & 0xfffff))
    if cp == 6: return struct.pack('>B', sbn & 0xff) + (esi & 0xffffff).to_bytes(3, 'big')
    if cp == 129: return struct.pack('>IHH', sbn, sbl, esi & 0xffff)
    return b''

SLT_ADDR = ('192.0.2.50', '239.255.10.1')

def slt_xml(services):
    s = '<?xml version="1.0" encoding="UTF-8"?><SLT bsid="1">'
    for (sid, major, minor, proto, src, dst, port) in services:
        attrs = 'serviceId="%d"' % sid
        if major is not None: attrs += ' majorChannelNo="%d"' % major
        if minor is not None: attrs += ' minorChannelNo="%d"' % minor
        sls = 'slsProtocol="%d" slsDestinationIpAddress="%s" slsDestinationUdpPort="%d"' % (proto, dst, port)
        if src: sls += ' slsSourceIpAddress="%s"' % src
        s += '<Service %s><BroadcastSvcSignaling %s/></Service>' % (attrs, sls)
    return (s + '</SLT>').encode()

def lls_slt(services):
    return b'\x01\x00\x00\x01' + zlib.compress(slt_xml(services))

def eth_udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    return udp_frame(payload, sport, dport, src, dst)

def alp_ip(payload, sport, dport, src, dst):
    '''ALP packet (type IPv4, single packet without additional header) around IPv4/UDP.'''
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = ip_pkt(17, udp, src, dst)
    n = len(ip)
    return struct.pack('>BB', (0 << 5) | (n >> 8), n & 0xff) + ip

SERVICES = [
    (1001, 5, 1, 1, None, '239.255.10.1', 4001),         # channel 5.1, ALC/LCT (ROUTE/DASH)
    (1002, None, None, 1, None, '239.255.10.2', 4002),   # no channel numbers
    (1003, 7, 2, 1, '192.0.2.50', '239.255.10.3', 4003), # with a source address
    (1004, 8, 1, 2, None, '239.255.10.4', 4004),         # slsProtocol 2: not ALC
    (1005, 9, 1, 1, None, '239.255.10.5', 4005),
]
LLS_ADDR = ('192.0.2.1', '224.0.23.60', 4937)
SRC = '192.0.2.50'

def f_lls(ifc=0):
    return (ifc, eth_udp(lls_slt(SERVICES), 4937, 4937, LLS_ADDR[0], LLS_ADDR[1]))

def f_alc(payload, svc=0, eth=True, src=SRC):
    s = SERVICES[svc]
    if eth:
        return (0, eth_udp(payload, 5000, s[6], src, s[5]))
    return (1, alp_ip(payload, 5000, s[6], src, s[5]))

XML = b'<?xml version="1.0"?><a/>'

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    f = [f_lls()]                                                       # 1 SLT
    payload = fec_hdr(0) + b'payload-bytes'
    def eth_frame(hdr, svc=0, pl=payload):
        f.append(f_alc(hdr + pl, svc=svc))
    # 2-5: congestion control information of 4, 8, 12 and 16 octets
    for C in range(4):
        eth_frame(lct_hdr(C=C, S=1, O=1, tsi=0x1001, toi=C + 1, cp=0))
    # 6-15: TSI/TOI sizes: (S, O, H) -> TSI size S*4+H*2, TOI size O*4+H*2
    for (S, O, H) in ((0, 0, 0), (0, 0, 1), (1, 0, 0), (0, 1, 0), (1, 1, 0), (1, 1, 1), (1, 2, 0),
                      (1, 2, 1), (1, 3, 0), (1, 3, 1)):
        eth_frame(lct_hdr(S=S, O=O, H=H, tsi=0x112233445566, toi=0x0102030405060708090a0b0c0d0e, cp=0), svc=1)
    # 16-19: sender current time, expected residual time, both, close flags
    eth_frame(lct_hdr(S=1, O=1, tsi=1, toi=1, T=1, sct=1500), svc=2)
    eth_frame(lct_hdr(S=1, O=1, tsi=1, toi=1, R=1, ert=250), svc=2)
    eth_frame(lct_hdr(S=1, O=1, tsi=1, toi=1, T=1, R=1, sct=0xffffffff, ert=0), svc=2)
    eth_frame(lct_hdr(S=1, O=1, tsi=1, toi=1, A=1, B=1), svc=2)
    # 20-31: header extensions, each alone
    exts = [
        ext_var(0, b'\xff\xff'),                                       # EXT_NOP
        ext_var(1, b'\x00' * 6),                                       # EXT_AUTH
        ext_var(2, b'\x00' * 6),                                       # EXT_TIME (no decoding)
        ext_var(3, struct.pack('>HBBHH', 7, 0x80, 12, 0x8000, 4096)),  # EXT_CC rate
        ext_fti(1000000, struct.pack('>HHI', 0, 1024, 64)),            # EXT_FTI (codepoint 0)
        ext_var(65, b'\x00' * 6),                                      # DVB-IPTV CDS poll request
        ext_var(66, b'\x00' * 6),                                      # EXT_ROUTE_PRESENTATION_TIME
        ext_var(67, bytes([0, 0, 0, 1, 0, 0])),                        # EXT_TOL 48 bit
        ext_fixed(128, b'\x12\x34\x56'),                               # EXT_RATE
        ext_fixed(192, b'\x10\x00\x09'),                               # EXT_FDT
        ext_fixed(193, b'\x00\x00\x02'),                               # EXT_CENC
        ext_fixed(194, b'\x01\x00\x00'),                               # EXT_TOL 24 bit
        ext_fixed(200, b'\xaa\xbb\xcc'),                               # unknown fixed length extension
        ext_var(70, b'\x01\x02\x03\x04\x05\x06'),                      # unknown variable length extension
    ]
    for e in exts:
        eth_frame(lct_hdr(S=1, O=1, tsi=1, toi=5, cp=0, exts=e), svc=0)
    # 34: all extensions in one header
    eth_frame(lct_hdr(S=1, O=1, tsi=1, toi=5, cp=0, exts=b''.join(exts), T=1, R=1), svc=1)
    # FDT with the FLUTE extension: the payload goes to the XML dissector
    f.append(f_alc(lct_hdr(S=1, O=1, tsi=0, toi=0, cp=0, exts=ext_fixed(192, b'\x10\x00\x01')) + fec_hdr(0) + XML, svc=2))
    # 36-: ATSC3 mode through the ALP interface
    f.append(f_alc(lct_hdr(psi=2, S=1, O=1, tsi=3, toi=0x20, cp=1) + struct.pack('>I', 0) + XML, eth=False, svc=0))  # the is_sp reproducer
    f.append(f_alc(lct_hdr(psi=0, S=1, O=1, tsi=3, toi=0x21, cp=128) + fec_hdr(128) + b'repair', eth=False, svc=0))
    f.append(f_alc(lct_hdr(psi=3, S=1, O=1, tsi=3, toi=0x22, cp=9) + struct.pack('>I', 77) + b'abc', eth=False, svc=1))
    # an EXT_FTI in a source packet: decoded with encoding id 0 although the codepoint is 8
    f.append(f_alc(lct_hdr(psi=2, S=1, O=1, tsi=3, toi=0x23, cp=8,
                           exts=ext_fti(5000, struct.pack('>HHI', 0, 512, 16))) + struct.pack('>I', 3) + b'src', eth=False, svc=2))
    # the same in a repair packet: the codepoint 0 gives the same layout
    f.append(f_alc(lct_hdr(psi=0, S=1, O=1, tsi=3, toi=0x23, cp=0,
                           exts=ext_fti(5000, struct.pack('>HHI', 0, 512, 16))) + fec_hdr(0) + b'rep', eth=False, svc=2))
    # Exported PDU "rmt-lct" without data from the caller (no data exchange structure): the
    # extensions are decoded with codepoint 0, FDT/CENC are not decoded as FLUTE
    ex = ext_fti(1234, struct.pack('>HHI', 0, 512, 16)) + ext_fixed(192, b'\x10\x00\x02') + ext_fixed(193, b'\x00\x00\x01')
    f.append((2, exp_pdu('rmt-lct', lct_hdr(S=1, O=1, tsi=1, toi=1, cp=0, exts=ex) + b'tail')))
    f.append((2, exp_pdu('rmt-lct', lct_hdr(psi=2, S=1, O=1, tsi=1, toi=1, cp=0) + b'tail')))
    write_pcapng(os.path.join(out, 'rmt-lct-coverage.pcapng'), [1, 289, 252], f)
    mal = [f_lls()]
    # header length 0 (no room for the fixed header), 1 word, and past the end
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, hlen=0) + b'\0' * 12))
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, hlen=1) + b'\0' * 12))
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, hlen=100) + b'\0' * 12))
    # extension with a zero length (the extension loop stops), and one that runs past the end
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, exts=bytes([70, 0, 0, 0])) + payload))
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, exts=bytes([70, 9, 0, 0])) + payload))
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, exts=ext_var(3, b'\0' * 2)) + payload))   # CC rate too short
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, exts=ext_var(64, b'\0' * 2)) + payload))  # FTI too short
    # fields cut short
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1)[:10]))
    mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, T=1)[:20]))
    mal.append(f_alc(b'\x10'))
    write_pcapng(os.path.join(out, 'rmt-lct-coverage-malformed.pcapng'), [1, 289, 252], mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
