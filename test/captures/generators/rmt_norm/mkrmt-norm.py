#!/usr/bin/env python3
# Generates test/captures/rmt_norm_coverage.pcapng.gz
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

def grrt(inst=0x0102, grtt=10, bg=0x35):
    return struct.pack('>HBB', inst, grtt, bg)

def norm(typ, hdr, payload=b'', seq=1, src=0x0a000001, ver=1):
    '''Common header (hlen counts the whole header: common + type specific + FEC + extensions).'''
    hdr += b'\0' * ((-len(hdr)) % 4)       # the header length is in words
    n = 8 + len(hdr)
    return struct.pack('>BBHI', (ver << 4) | typ, n // 4, seq, src) + hdr + payload

def feccode(fid, oid, reserved=False):
    return bytes([fid]) + (b'\0' if reserved else b'') + struct.pack('>H', oid)

def n_info(fid=0, flags=0x14, exts=b'', payload=b'info-data', seq=1):
    return norm(2 - 1, grrt() + bytes([flags]) + feccode(fid, 7) + exts, payload, seq=seq)   # type 1

def n_data(fid, flags, fec=b'', exts=b'', payload=b'object-data', seq=2, stream=None, oid=9):
    hdr = grrt(grtt=200) + bytes([flags]) + feccode(fid, oid) + fec + exts
    if stream is not None:
        payload = struct.pack('>HHI', 0, len(payload), stream) + payload
    return norm(2, hdr, payload, seq=seq)

def n_cmd(flavor, body=b'', seq=3, payload=b''):
    return norm(3, grrt() + bytes([flavor]) + body, payload, seq=seq)

def nackdata(form, flags, fid, oid, fec=b'', extra=b''):
    body = feccode(fid, oid, reserved=True) + fec + extra
    return struct.pack('>BBH', form, flags, len(body)) + body

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    f = []
    def add(p): f.append((0, exp_pdu('norm', p)))
    fti0 = ext_fti(5000, struct.pack('>HHI', 0, 512, 16))
    # 1-3 INFO: no extension, with EXT_FTI, with unknown encoding
    add(n_info())
    add(n_info(fid=129, exts=ext_fti(5000, struct.pack('>HHHH', 0x1234, 512, 16, 32))))
    add(n_info(fid=5, flags=0x00, exts=ext_var(0, b'\0' * 2), payload=b''))
    # 4-9 DATA: flags of every kind, FEC headers of several encodings, stream data, extensions
    add(n_data(0, 0x01, fec_hdr(0), payload=b'repair'))
    add(n_data(129, 0x02 | 0x04, fec_hdr(129), exts=ext_fti(100, struct.pack('>HHHH', 0x4321, 512, 16, 32))))
    add(n_data(2, 0x08 | 0x10, fec_hdr(2), exts=ext_fixed(128, b'\x12\x34\x56') + ext_fixed(193, b'\0\0\1')))
    add(n_data(0, 0x20 | 0x40, fec_hdr(0), stream=1000, payload=b'stream-bytes'))
    add(n_data(6, 0x00, fec_hdr(6), exts=ext_fti(0x0123456789 << 8, struct.pack('>HBHB', 1024, 2, 3, 4) + b'\0'), payload=b''))
    add(n_data(5, 0x00, b'', payload=b''))
    # 10-: CMD flavors
    add(n_cmd(1, feccode(0, 3) + fec_hdr(0)))                                   # FLUSH
    add(n_cmd(1, feccode(5, 3), payload=b'flush-tail'))                         # FLUSH, extra payload
    add(n_cmd(2, b'\0\0\0', payload=b'eot-tail'))                               # EOT
    add(n_cmd(3, feccode(0, 3) + fec_hdr(0), payload=struct.pack('>HHH', 1, 2, 3) + b'\0\0'))   # SQUELCH, list of object ids
    add(n_cmd(3, feccode(5, 3) + struct.pack('>HH', 4, 5)))                     # SQUELCH, encoding without header
    add(n_cmd(1, feccode(0, 3) + fec_hdr(0) + fti0))                                      # FLUSH with an extension
    # CC: reserved, sequence, send time, followed by one and two CC nodes
    cc_hdr = struct.pack('>BHII', 0, 77, 1000, 500)
    node = lambda nid, fl, rtt, rate: struct.pack('>IBBH', nid, fl, rtt, rate)
    add(n_cmd(4, cc_hdr + node(1, 0x1f, 40, 0x1234) + node(2, 0x00, 250, 0x2345)))
    add(n_cmd(4, cc_hdr + ext_fixed(128, b'\x12\x34\x56') + node(3, 0x05, 10, 0x3456)))
    add(n_cmd(4, cc_hdr))                                                       # CC without nodes
    # REPAIR_ADV: flags, reserved, an extension (EXT_FTI), then NACK data items (reproducer of
    # "RMT-NORM: Keep the FEC encoding ID per packet": the extension is decoded before the NACK
    # data and so with the same encoding id in one pass and in two)
    ra = struct.pack('>BH', 0x80, 0) + ext_fti(1000, struct.pack('>HHHH', 7, 512, 32, 40))
    add(n_cmd(5, ra, payload=nackdata(1, 0x01, 129, 0x55, fec=fec_hdr(129))))
    add(n_cmd(5, struct.pack('>BH', 0, 0), payload=nackdata(2, 0x02, 0, 9, fec=fec_hdr(0)) +
              nackdata(3, 0x0c, 129, 10, fec=fec_hdr(129)) + nackdata(1, 0x04, 0, 11)))
    add(n_cmd(5, struct.pack('>BH', 0, 0)))                                     # no NACK data
    add(n_cmd(6, struct.pack('>BBB', 0, 1, 5) + b'\0'))                         # ACK_REQ
    add(n_cmd(7, b'\0\0\0', payload=b'application data'))                       # APPLICATION
    add(n_cmd(99, b'\0\0\0', payload=b'unknown'))                               # unknown flavor
    # ACK: ack source, instance, type, id, grtt, then padding/extensions
    ack = lambda t, ex=b'': struct.pack('>IHBBII', 0x0a000002, 0x0102, t, 9, 1, 2000) + ex
    add(norm(5, ack(1)))
    add(norm(5, ack(2, ext_fixed(128, b'\x00\x10\x00')), payload=b'ack payload'))
    add(norm(5, ack(77)))                                                       # unknown ack type
    # NACK
    nk = lambda ex=b'': struct.pack('>IHHII', 0x0a000001, 0x0102, 0, 3, 4000) + ex
    add(norm(4, nk(ext_fti(5, struct.pack('>HHI', 0, 1, 2))), payload=nackdata(1, 1, 0, 5, fec=fec_hdr(0)) + nackdata(1, 2, 129, 6, fec=fec_hdr(129))))
    add(norm(4, nk()))
    add(norm(4, nk(), payload=nackdata(2, 8, 0, 5)))
    # REPORT (type 6): payload
    add(norm(6, b'\0' * 8, payload=b'report-data'))
    # version 2: declined with a warning
    add(norm(2, b'\0' * 8, ver=2))
    # type 7 and 0: unknown, payload
    add(norm(7, b'\0' * 8, payload=b'x'))
    # the heuristic (disabled by default; "udp" "norm_udp"): the same packets in UDP
    f.append((1, eth_udp(n_data(0, 0x00, fec_hdr(0)), 6003, 6003, '192.0.2.1', '224.1.2.3')))
    f.append((1, eth_udp(n_cmd(1, feccode(0, 3) + fec_hdr(0)), 6003, 6003, '192.0.2.1', '224.1.2.3')))
    f.append((1, eth_udp(b'\x13\x02\0', 6003, 6003)))                           # shorter than 12
    f.append((1, eth_udp(b'\x23' + b'\x02' + b'\0' * 14, 6003, 6003)))          # version 2
    f.append((1, eth_udp(b'\x17' + b'\x02' + b'\0' * 14, 6003, 6003)))          # type 7
    f.append((1, eth_udp(b'\x13' + b'\x15' + b'\0' * 14, 6003, 6003)))          # header length 21
    write_pcapng(os.path.join(out, 'rmt-norm-coverage.pcapng'), [252, 1], f)
    mal = []
    def madd(p): mal.append((0, exp_pdu('norm', p)))
    madd(b'\x13')                                                   # INFO cut
    madd(norm(1, grrt()[:3])); madd(norm(2, grrt() + b'\x00' + b'\x00'))
    madd(norm(3, grrt() + b'\x03'))                                 # SQUELCH, nothing else
    madd(norm(3, grrt() + b'\x04' + b'\0\0'))                       # CC cut
    madd(norm(3, grrt() + bytes([5]) + b'\0'))                      # REPAIR_ADV cut
    madd(norm(3, grrt() + bytes([5]) + b'\0\0\0' + b'\x01\x00\x00\x40' + b'\0' * 4))   # NACK length past the end
    madd(norm(3, grrt()[:2]))
    madd(norm(5, b'\0' * 6)); madd(norm(4, b'\0' * 10))
    madd(norm(3, grrt() + bytes([6]) + b'\0'))                      # ACK_REQ cut
    madd(norm(2, grrt() + b'\0' + feccode(129, 1) + b'\0' * 2))     # FEC header cut
    write_pcapng(os.path.join(out, 'rmt-norm-coverage-malformed.pcapng'), [252, 1], mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
