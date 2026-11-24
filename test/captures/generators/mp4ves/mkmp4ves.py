#!/usr/bin/env python3
# Generates test/captures/mp4ves_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds the MP4V-ES coverage captures. Usage: mkmp4ves.py <outdir> [-v]
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split('.'))

ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'

def ethip(proto, payload, src, dst, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + payload

def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ethip(17, u, src, dst)

def tcp(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0) + payload
    pseudo = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    c = csum(pseudo + t)
    t = t[:16] + struct.pack('>H', c) + t[18:]
    return ethip(6, t, src, dst)

def exp_pdu(name, payload, extra=b''):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + extra + struct.pack('>HH', 0, 0) + payload

def rtp(pt, seq, ts, payload, ssrc=0x11223344, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts & 0xffffffff, ssrc) + payload

class Cap:
    """pcapng writer with interface 0 = Ethernet, 1 = Exported PDU (252)."""
    def __init__(self):
        self.frames = []
    def eth(self, data, note=None):
        self.frames.append((1, data)); return len(self.frames)
    def epdu(self, name, payload, extra=b''):
        self.frames.append((252, exp_pdu(name, payload, extra))); return len(self.frames)
    def write(self, fname):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 0))
        out += blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (lt, d) in enumerate(self.frames):
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, 0, 1000 + i, len(d), len(d)) + d)
        open(fname, 'wb').write(out)

def pcap(fname, linktype, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)) + p)

class Bits:
    def __init__(self):
        self.v = 0
        self.n = 0
    def add(self, val, n):
        self.v = (self.v << n) | (val & ((1 << n) - 1))
        self.n += n
        return self
    def align(self, bit=1):
        while self.n % 8:
            self.add(bit, 1)
        return self
    def raw(self, b):
        for x in b:
            self.add(x, 8)
        return self
    def bytes(self):
        pad = (-self.n) % 8
        return ((self.v << pad)).to_bytes((self.n + pad) // 8, 'big')

SC = b'\x00\x00\x01'

def vol(b, rand=0, vot=1, layer_id=0, aspect=1, par=(1, 1), ctrl=0, vbv=0, shape=0, ext=0, tail=8):
    """VideoObjectLayer after the start code, as dissect_mp4ves_VideoObjectLayer reads it."""
    b.add(rand, 1).add(vot, 8).add(layer_id, 1)
    if layer_id:
        b.add(2, 4).add(3, 3)
    b.add(aspect, 4)
    if aspect == 0xf:
        b.add(par[0], 8).add(par[1], 8)
    b.add(ctrl, 1)
    if ctrl:
        b.add(1, 2).add(0, 1).add(vbv, 1)
        if vbv:
            for n in (15, 1, 15, 1, 15, 1, 3, 11, 1, 15, 1):
                b.add(1 if n == 1 else 0x155, n)
    b.add(shape, 2)
    if shape == 3:
        b.add(ext, 4)
    b.add(1, 1).add(30000, 16).add(1, 1).add(0, 1)
    b.align(0)
    b.raw(bytes(tail))
    return b

def vos(profile=1, vo_id=1, vo_type=1, sig=0, cdesc=0, user=(), vo_start=0x00, with_vol=True,
        zero_bit=0, vol_kw=None, endcode=False, vo_raw=None, after_vo=None):
    b = Bits().raw(SC + b'\xb0').add(profile, 8).raw(SC + b'\xb5')
    b.add(vo_id, 1)
    if vo_id:
        b.add(1, 4).add(1, 3)
    b.add(vo_type, 4)
    if vo_type in (1, 2):
        b.add(sig, 1)
        if sig:
            b.add(5, 3).add(1, 1).add(cdesc, 1)
            if cdesc:
                b.add(1, 8).add(1, 8).add(1, 8)
    b.add(zero_bit, 1)
    b.align(1)
    for u in user:
        b.raw(SC + b'\xb2').raw(u)
    if vo_type == 1 and vo_raw is not None:
        b.raw(vo_raw)
    elif vo_type == 1 and with_vol:
        b.raw(SC + bytes([vo_start]))
        if after_vo is not None:
            b.raw(after_vo)
        elif vo_start <= 0x20:
            b.raw(SC + b'\x20')
            vol(b, **(vol_kw or {}))
    elif vo_type != 1:
        b.raw(SC + b'\xb6')
    return b.bytes()

def sdp_invite(callid, port, cfg=None, profile=None, extra=''):
    fmtp = ''
    if cfg is not None or profile is not None:
        fmtp = 'a=fmtp:96 '
        parts = []
        if profile is not None:
            parts.append('profile-level-id=%d' % profile)
        if cfg is not None:
            parts.append('config=' + cfg.hex().upper())
        fmtp += '; '.join(parts) + '\r\n'
    sdp = ('v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=mp4ves\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n'
           'm=video %d RTP/AVP 96\r\na=rtpmap:96 MP4V-ES/90000\r\n' % port) + fmtp + extra
    sip = ('INVITE sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK%s\r\n'
           'From: <sip:alice@192.0.2.1>;tag=1\r\nTo: <sip:bob@192.0.2.2>\r\nCall-ID: %s@192.0.2.1\r\n'
           'CSeq: 1 INVITE\r\nContact: <sip:alice@192.0.2.1>\r\nContent-Type: application/sdp\r\n'
           'Content-Length: %d\r\n\r\n' % (callid, callid, len(sdp))) + sdp
    return sip.encode()

def main(out, verbose):
    cap = Cap()
    notes = []
    seq = [1]
    def note(label):
        notes.append((label, len(cap.frames) + 1))
    def invite(callid, port, **kw):
        cap.eth(udp(sdp_invite(callid, port, **kw), 5060, 5060))
    def rtpkt(port, payload, marker=0, pt=96):
        cap.eth(udp(rtp(pt, seq[0], 3000 * seq[0], payload, marker=marker), port, port))
        seq[0] += 1

    # 1. SDP config variants, one INVITE each (the config is dissected inside SDP)
    note('SDP configs')
    cfgs = [
        vos(profile=1),
        vos(profile=8, vo_id=0),
        vos(profile=0x93, sig=1, cdesc=0),
        vos(profile=0xf3, sig=1, cdesc=1, vol_kw=dict(aspect=0xf, par=(12, 11))),
        vos(profile=0x34, user=(b'x264 test data', b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a')),
        vos(profile=0x91, vol_kw=dict(layer_id=1, aspect=3, rand=1, vot=0x11)),
        vos(profile=0x61, vol_kw=dict(ctrl=1, vbv=0)),
        vos(profile=0xb1, vol_kw=dict(ctrl=1, vbv=1)),
        vos(profile=0xe5, vol_kw=dict(shape=3, ext=5)),
        vos(profile=0xfe, vol_kw=dict(shape=1, aspect=6)),
        vos(profile=2, vo_type=2, sig=1),                 # still texture object: no VOL
        vos(profile=2, vo_type=3, vo_id=0),               # mesh
        vos(profile=2, vo_type=4),                        # FBA
        vos(profile=2, vo_type=5),                        # 3D mesh
        vos(profile=2, vo_type=0),
        vos(profile=3, vo_start=0x1f, vol_kw=dict(aspect=0)),
        vos(profile=3, user=(b'\xaa',), vol_kw=dict(aspect=2, ctrl=1, vbv=1, shape=3)),
    ]
    for i, c in enumerate(cfgs):
        invite('cfg%d' % i, 6000 + 2 * i, cfg=c, profile=(c[4] if len(c) > 4 else 1))
    cfg_range = (notes[-1][1], len(cap.frames))
    # profile-level-id without a config, config without a profile
    invite('plid', 6100, profile=3)
    invite('cfgonly', 6102, cfg=vos(profile=0x22))

    # 2. RTP payloads, PT 96 from the first INVITE (port 6000)
    note('RTP payloads')
    P = 6000
    rtpkt(P, vos(profile=1) + b'\x00\x00\x01\xb6\x10\x20')     # VS header (config) in the payload
    rtpkt(P, vos(profile=0xf1, sig=1, cdesc=1, user=(b'abc',)))
    rtpkt(P, SC + b'\xb6' + bytes([0x00]) + b'\x11\x22' * 10, marker=1)     # VOP, coding type I
    rtpkt(P, SC + b'\xb6' + bytes([0x40]) + b'\x11\x22' * 10)               # P
    rtpkt(P, SC + b'\xb6' + bytes([0x80]) + b'\x11\x22' * 10)               # B
    rtpkt(P, SC + b'\xb6' + bytes([0xc0]) + b'\x11\x22' * 10)               # S
    rtpkt(P, SC + b'\xb3' + b'\x00' * 8)                                    # GOV
    for code in (0x00, 0x1f, 0x20, 0x2f, 0x30, 0xaf, 0xb1, 0xb2, 0xb4, 0xb5, 0xb7, 0xba, 0xbb,
                 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc6, 0xcf, 0xd0, 0xff):
        rtpkt(P, SC + bytes([code]) + b'\x55' * 6)
    rtpkt(P, b'\x12\x34\x56\x78' * 20)                       # VOP fragment: no start code
    rtpkt(P, b'\x00\x00\x02\xb6' + bytes(8))                 # prefix not 000001
    rtpkt(P, b'\x00\x00\x01')                                # three octets: too short
    rtpkt(P, b'\x01')
    # second RTP stream in the session of port 6002 (profile-level-id announced in SDP)
    rtpkt(6002, SC + b'\xb6' + bytes([0x40]) + b'\x01' * 6)

    # 3. Exported PDU entries
    note('Exported PDU')
    cap.epdu('mp4ves_config', cfgs[0])
    cap.epdu('mp4ves_config', cfgs[3])
    cap.epdu('mp4ves_config', cfgs[4])
    cap.epdu('mp4ves', SC + b'\xb6\x40' + bytes(6))
    cap.epdu('mp4ves', SC + b'\xb0\x01' + SC[:2] + b'\x01\xb5\x91' + bytes(8))
    # reproducer of the user data length fix: 10 octets of user data at the end of the config
    cap.epdu('mp4ves_config', bytes.fromhex('000001b0 01 000001b5'.replace(' ', '')) + bytes([0x09]) +
             bytes.fromhex('000001b2') + b'0123456789' + bytes.fromhex('00000100') +
             SC + b'\x20' + vol(Bits()).bytes())
    # configs that are cut short or invalid but decode without an exception
    note('Exported PDU, invalid configs')
    cap.epdu('mp4ves_config', SC + b'\xb0\x01' + SC + b'\xb2')      # user data start code in the VS header
    cap.epdu('mp4ves_config', SC + b'\xb3\x01' + SC + b'\xb5')      # not a VS start code
    cap.epdu('mp4ves_config', b'\x12\x34\x56\x78\x9a')            # no start code prefix
    cap.epdu('mp4ves_config', SC + b'\xb0\x01\x12\x34\x56\x78')   # no start code prefix after the profile
    cap.epdu('mp4ves_config', vos(profile=1, vo_start=0x30))         # video object start code above 0x20
    cap.epdu('mp4ves_config', vos(profile=1, zero_bit=1))            # next_start_code with a one bit
    cap.epdu('mp4ves_config', vos(profile=1, user=(b'abcd',))[:-5])
    cap.epdu('mp4ves_config', SC + b'\xb0\x01' + SC + b'\xb5\x20' + SC + b'\x00')  # nothing after the VO code
    cap.epdu('mp4ves_config', vos(profile=1, vo_raw=b'\x12\x34\x56\x78\x9a\xbc'))   # no video object start code
    cap.epdu('mp4ves_config', vos(profile=1, after_vo=b'\x12\x34\x56\x78\x9a\xbc'))  # no VOL start code
    cap.epdu('mp4ves_config', vos(profile=1, after_vo=SC + b'\x30' + bytes(6)))          # not a VOL start code
    note('end')
    cap.write(os.path.join(out, 'mp4ves-coverage.pcapng'))

    # Malformed
    m = Cap()
    labels = []
    m.eth(udp(sdp_invite('mal', 6000, cfg=vos(profile=1)), 5060, 5060))
    def mp(payload):
        m.eth(udp(rtp(96, len(m.frames), 1, payload), 6000, 6000))
    mp(SC + b'\xb6')                                           # VOP without the coding type octet
    mp(SC + b'\xb0')                                           # VS: no profile
    mp(SC + b'\xb0\x01' + SC)                                  # VS: start code cut short
    mp(SC + b'\xb0\x01' + SC + b'\xb5')                        # VO: no data
    mp(SC + b'\xb0\x01' + SC + b'\xb5\x80')
    mp(SC + b'\xb0\x01' + SC + b'\xb5\xa0' )
    for n in range(1, 8):                                      # truncated at every length
        mp(vos(profile=1)[:12 + n])
    m.epdu('mp4ves_config', vos(profile=1, with_vol=False))   # config_too_short expert
    m.epdu('mp4ves_config', SC + b'\xb0\x01' + SC + b'\xb2')   # user data start code in VS: return -1
    m.epdu('mp4ves_config', SC + b'\xb3\x01' + SC + b'\xb5')   # not a VS start code
    m.epdu('mp4ves_config', b'\x12\x34\x56\x78\x9a')           # no start code prefix
    m.epdu('mp4ves_config', SC + b'\xb0\x01\x12\x34\x56\x78')  # no prefix after the profile
    m.epdu('mp4ves_config', vos(profile=1, vo_start=0x30))    # video object start code > 0x20
    m.epdu('mp4ves_config', SC + b'\xb0\x01' + SC + b'\xb5\x20' + SC + b'\x00')   # no data after vo start
    m.epdu('mp4ves_config', vos(profile=1, zero_bit=1))        # nonzero zero_bit
    m.epdu('mp4ves_config', vos(profile=1, user=(b'abcd',))[:-5])   # config truncated in the user data
    m.epdu('mp4ves_config', vos(profile=1, vol_kw=dict(tail=0))[:-1])   # VOL cut short
    m.epdu('mp4ves_config', b'')
    m.epdu('mp4ves_config', SC)
    m.epdu('mp4ves_config', vos(profile=2, user=(b'zzz',))[:20])
    # user data without the terminating start code: runs past the end
    m.epdu('mp4ves_config', SC + b'\xb0\x01' + SC + b'\xb5\x20' + SC[:0] + b'\x80' + SC + b'\xb2' + b'\x55' * 6)
    m.write(os.path.join(out, 'mp4ves-coverage-malformed.pcapng'))
    if verbose:
        print(notes, 'cfg frames', cfg_range, 'total', len(cap.frames))
        for i, (lt, d) in enumerate(m.frames):
            print('mal', i + 1, lt, d[:40].hex() if lt == 252 else '')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
