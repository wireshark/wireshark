#!/usr/bin/env python3
# Generates test/captures/rmt_fec_coverage.pcapng.gz
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

def fti_rest(cp, inst=0x1234):
    if cp in (0, 2, 128, 130): return struct.pack('>HHI', inst, 1024, 4096)
    if cp == 1: return struct.pack('>HHHBB', inst, 1024, 12, 3, 4)
    if cp == 6: return struct.pack('>HBHBB', 1024, 2, 3, 4, 0)
    if cp == 129: return struct.pack('>HHHH', inst, 1024, 255, 300)
    if cp == 132: return struct.pack('>HHII', inst, 1024, 255, 300)
    return struct.pack('>HHI', inst, 1, 2)

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    f = [f_lls()]                                                       # 1 SLT
    CPS = (0, 1, 2, 3, 4, 5, 6, 128, 129, 130, 131, 132)
    # 2-13: ALC packets with every FEC encoding id (the LCT codepoint): FEC payload ID header
    # followed by data (no EXT_FTI)
    for cp in CPS:
        f.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=cp + 1, cp=cp) + fec_hdr(cp, sbn=0x100 + cp, esi=0xabc0 + cp) + b'symbol-data', svc=cp % 3))
    # 14-25: EXT_FTI for every encoding id, in a packet of that codepoint. FEC encoding ids
    # below 128 other than 0 get a warning ("should be zero"); ids >= 128 store and show the
    # FEC instance id (0x1234, more than 8 bits)
    for cp in CPS:
        tl = 0x0123456789 if cp == 6 else 0x0123456789ab
        if cp == 6:
            e = ext_fti(tl << 8, fti_rest(cp))
        else:
            e = ext_fti(tl, fti_rest(cp))
        f.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=0x40 + cp, cp=cp, exts=e) + fec_hdr(cp) + b'symbol-data', svc=cp % 3))
    # ATSC3: the codepoint is not an encoding id: EXT_FTI is decoded as encoding 0, and the FEC header
    # of a repair packet is selected by the codepoint
    e = ext_fti(0x0123456789ab, fti_rest(0))
    f.append(f_alc(lct_hdr(psi=2, S=1, O=1, tsi=2, toi=1, cp=130, exts=e) + struct.pack('>I', 3) + b'src', eth=False))
    f.append(f_alc(lct_hdr(psi=0, S=1, O=1, tsi=2, toi=2, cp=130, exts=ext_fti(0x0123456789ab, fti_rest(130))) + fec_hdr(130) + b'repair', eth=False))
    f.append(f_alc(lct_hdr(psi=0, S=1, O=1, tsi=2, toi=3, cp=6, exts=ext_fti(0x0123456789 << 8, fti_rest(6))) + fec_hdr(6) + b'repair', eth=False))
    # Exported PDU "rmt-fec" without data from the caller: encoding id 0
    f.append((2, exp_pdu('rmt-fec', struct.pack('>HH', 7, 0x55) + b'tail')))
    write_pcapng(os.path.join(out, 'rmt-fec-coverage.pcapng'), [1, 289, 252], f)
    mal = [f_lls()]
    for cp, n in ((0, 3), (2, 7), (3, 3), (6, 3), (129, 7), (130, 3)):
        mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, cp=cp) + b'\0' * n))
    for cp in (0, 6, 128, 129, 132):
        mal.append(f_alc(lct_hdr(S=1, O=1, tsi=1, toi=1, cp=cp, exts=ext_var(64, b'\0' * 8)) + fec_hdr(cp) + b'x'))
    mal.append((2, exp_pdu('rmt-fec', b'\x00\x01')))
    write_pcapng(os.path.join(out, 'rmt-fec-coverage-malformed.pcapng'), [1, 289, 252], mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
