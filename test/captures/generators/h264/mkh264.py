#!/usr/bin/env python3
# Generates test/captures/h264_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.264 coverage captures. Usage: mkh264.py <outdir> [-v]
H.264 is reached the way a real call reaches it: SIP INVITEs whose SDP
maps RTP payload types to "H264/90000" (UDP 5004, 5008, 5010) and
"H264-SVC/90000" (UDP 5006) with profile-level-id and
sprop-parameter-sets, then RTP packets with those payload types (single
NAL units, STAP-A/B, MTAP16/24, FU-A, PACSI, NAL header extension). The
Annex B byte stream format is reached through Exported PDU frames naming
the "h264_bytestream" dissector. The captures are pcapng with an Ethernet
and an Exported PDU interface. Everything is built with struct and a bit
writer; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import base64
import tempfile
from _lib import PcapNg, A, B, sip, sdp, rtp, Bits, escape
import asnper

# ---------------------------------------------------------------- NAL builders
def nal(ref, typ, rbsp, esc=True):
    return bytes([(ref << 5) | typ]) + (escape(rbsp) if esc else rbsp)

def hrd(cnt=1, sched=((100, 200, 0), (300, 400, 1))):
    b = Bits().ue(cnt - 1).u(4, 3).u(4, 5)
    for br, cs, cbr in sched[:cnt]:
        b.ue(br).ue(cs).u(1, cbr)
    return b.u(5, 23).u(5, 23).u(5, 23).u(5, 24)

def vui(ar=None, overscan=None, vst=None, chroma_loc=None, timing=None, nal_hrd=None, vcl_hrd=None,
        low_delay=0, pic_struct=0, bsr=False):
    b = Bits()
    if ar is None: b.u(1, 0)
    else:
        b.u(1, 1).u(8, ar)
        if ar == 255: b.u(16, 4).u(16, 3)
    if overscan is None: b.u(1, 0)
    else: b.u(1, 1).u(1, overscan)
    if vst is None: b.u(1, 0)
    else:
        fmt, full, col = vst
        b.u(1, 1).u(3, fmt).u(1, full)
        if col is None: b.u(1, 0)
        else: b.u(1, 1).u(8, col[0]).u(8, col[1]).u(8, col[2])
    if chroma_loc is None: b.u(1, 0)
    else: b.u(1, 1).ue(chroma_loc[0]).ue(chroma_loc[1])
    if timing is None: b.u(1, 0)
    else: b.u(1, 1).u(32, timing[0]).u(32, timing[1]).u(1, timing[2])
    for h in (nal_hrd, vcl_hrd):
        if h is None: b.u(1, 0)
        else: b.u(1, 1); b.b += h.b
    if nal_hrd is not None or vcl_hrd is not None: b.u(1, low_delay)
    b.u(1, pic_struct)
    if not bsr: b.u(1, 0)
    else: b.u(1, 1).u(1, 1).ue(0).ue(2).ue(16).ue(16).ue(2).ue(4)
    return b

def scaling_list(b, kind, size):
    """Write the delta_scale values of one scaling list; kind: 'default', 'flat', 'ramp', 'stop'."""
    last = nxt = 8
    for j in range(size):
        if nxt != 0:
            if kind == 'default': d = -8 if j == 0 else 0
            elif kind == 'flat': d = 0
            elif kind == 'stop': d = (-last) if j == 3 else 1   # nextScale becomes 0 at j == 3
            else: d = 1 if j < 40 else -1
            b.se(d)
            nxt = (last + d + 256) % 256
        last = last if nxt == 0 else nxt

def sps(profile=66, cs=0x00, level=30, sid=0, chroma=1, rct=0, bdl=0, bdc=0, bypass=0, scaling=None,
        l2fn=0, poc=0, l2poc=4, poc1=(1, -2, 3, (1, -1, 2)), nref=1, gaps=0, wmb=39, hmu=29,
        fmo=1, mbaff=0, d8=1, crop=None, v=None, ref=3):
    hdr = bytes([profile, cs, level])
    b = Bits().ue(sid)
    if profile in (100, 110, 122, 144, 44, 83, 86, 118, 128, 138):
        b.ue(chroma)
        if chroma == 3: b.u(1, rct)
        b.ue(bdl).ue(bdc).u(1, bypass)
        if scaling is None: b.u(1, 0)
        else:
            b.u(1, 1)
            for i in range(8):
                k = scaling[i]
                if k is None: b.u(1, 0)
                else:
                    b.u(1, 1); scaling_list(b, k, 16 if i < 6 else 64)
    b.ue(l2fn).ue(poc)
    if poc == 0: b.ue(l2poc)
    elif poc == 1:
        b.u(1, poc1[0]).se(poc1[1]).se(poc1[2]).ue(len(poc1[3]))
        for o in poc1[3]: b.se(o)
    b.ue(nref).u(1, gaps).ue(wmb).ue(hmu).u(1, fmo)
    if not fmo: b.u(1, mbaff)
    b.u(1, d8)
    if crop is None: b.u(1, 0)
    else:
        b.u(1, 1)
        for c in crop: b.ue(c)
    if v is None: b.u(1, 0)
    else: b.u(1, 1); b.b += v.b
    b.trailing()
    return nal(ref, 7, hdr + b.bytes())

def pps(pid=0, sid=0, entropy=1, poc_pres=0, nsg=0, sgmap=0, l0=0, l1=0, wp=0, wb=0, qp=0, qs=0, cqo=-2,
        dbf=1, cip=0, rpc=0, ext=None, raw_tail=b'', ref=3):
    b = Bits().ue(pid).ue(sid).u(1, entropy).u(1, poc_pres).ue(nsg)
    if nsg > 0:
        b.ue(sgmap)
        return nal(ref, 8, b.pad().bytes() + raw_tail)
    b.ue(l0).ue(l1).u(1, wp).u(2, wb).se(qp).se(qs).se(cqo).u(1, dbf).u(1, cip).u(1, rpc)
    if ext is not None:
        t8, pscm, sec = ext
        b.u(1, t8).u(1, pscm)
        if pscm: return nal(ref, 8, b.pad().bytes() + raw_tail)
        b.se(sec)
    b.trailing()
    return nal(ref, 8, b.bytes())

def slice_(typ, first_mb=0, stype=7, ppsid=0, data=b'\x88\x84\x01\x10\x20\x30', ref=2):
    b = Bits().ue(first_mb).ue(stype).ue(ppsid)
    return nal(ref, typ, b.pad().bytes() + data)

def part_bc(typ, slice_id=3, data=b'\x44\x55\x66', ref=2):
    return nal(ref, typ, Bits().ue(slice_id).pad().bytes() + data)

def aud(ppt=3):
    return nal(0, 9, Bits().u(3, ppt).trailing().bytes())

def sei_msg(ptype, payload):
    h = b''
    t = ptype
    while t >= 255: h += b'\xff'; t -= 255
    h += bytes([t])
    s = len(payload)
    while s >= 255: h += b'\xff'; s -= 255
    h += bytes([s])
    return h + payload

def sei(*msgs, trailing=True):
    return bytes([0x06]) + b''.join(msgs) + (b'\x80' if trailing else b'')

MS_LAYOUT = bytes.fromhex('139FB1A9446A4DEC8CBF65B1E12D2CFD')
MS_CROP = bytes.fromhex('BB7FC1A06986405290F0092921753' + '9CF')
MS_BITSTREAM = bytes.fromhex('05FBC6B95A8040E5A22AAB4020267E26')

def ms_layer(w=640, h=480, dw=640, dh=480, br=500000, fr=4, lt=1, prid=2, cb=1):
    return struct.pack('>HHHHIBB', w, h, dw, dh, br, (fr << 5) | lt, (prid << 2) | cb)

def stap(typ, units, don=None):
    b = bytes([typ]) + (struct.pack('>H', don) if don is not None else b'')
    for u in units: b += struct.pack('>H', len(u)) + u
    return b

def mtap(typ, units, don=7):
    b = bytes([typ]) + struct.pack('>H', don)
    for i, u in enumerate(units):
        b += struct.pack('>HB', len(u), i + 1)
        b += struct.pack('>H', 100 * (i + 1)) if typ == 26 else b'\x00' + struct.pack('>H', 100 * (i + 1))
        b += u
    return b

def svc_ext(svc=1, i=1, prid=5, n=1, did=3, qid=2, tid=4, u=1, d=0, o=1, rr=2):
    return bytes([(svc << 7) | (i << 6) | prid, (n << 7) | (did << 4) | qid, (tid << 5) | (u << 4) | (d << 3) | (o << 2) | rr])

def pacsi(flags, nals, tl0=9, idr=0x1234, donc=77):
    b = bytes([30]) + svc_ext() + bytes([flags])
    if flags & 0x40: b += bytes([tl0]) + struct.pack('>H', idr)
    if flags & 0x20: b += struct.pack('>H', donc)
    for n in nals: b += struct.pack('>H', len(n)) + n
    return b

def ni_mtap(units, j=0, k=0, l=0, subtype=2):
    b = bytes([(subtype << 3) | (j << 2) | (k << 1) | l])
    for i, u in enumerate(units):
        b += struct.pack('>HH', len(u), 50 * (i + 1))
        if j: b += struct.pack('>H', 300 + i)
        b += u
    return bytes([31]) + b

def fu_a(typ, s, e, payload, ref=2, indicator=28):
    return bytes([(ref << 5) | indicator, (s << 7) | (e << 6) | typ]) + payload

# ---------------------------------------------------------------- the captures
def build_sps_set():
    full_vui = vui(ar=255, overscan=1, vst=(5, 1, (1, 2, 3)), chroma_loc=(0, 2), timing=(1001, 60000, 1),
                   nal_hrd=hrd(2), vcl_hrd=hrd(1, ((7, 8, 1),)), low_delay=1, pic_struct=1, bsr=True)
    S = {}
    S['base'] = sps()
    S['base1b'] = sps(profile=66, cs=0x10, level=11)
    S['base_crop'] = sps(profile=77, cs=0x40, level=31, sid=2, nref=4, gaps=1, wmb=1000, hmu=67,
                         fmo=0, mbaff=1, d8=0, crop=(0, 0, 0, 8))
    S['poc1'] = sps(profile=88, poc=1, poc1=(0, 5, -6, (2, -3, 100000)))
    S['poc2'] = sps(profile=66, poc=2, l2fn=7, nref=2)
    S['high'] = sps(profile=100, level=40, chroma=1, bdl=0, bdc=0,
                    scaling=['default', 'flat', None, 'ramp', 'stop', None, 'flat', 'ramp'],
                    crop=(1, 2, 3, 4), v=full_vui)
    S['high_noscale'] = sps(profile=100, level=41, v=vui(ar=1, vst=(2, 0, None)))
    S['high10'] = sps(profile=110, level=42, bdl=2, bdc=2, bypass=0, v=vui(ar=3, overscan=0, timing=(1, 50, 0)))
    S['high422'] = sps(profile=122, level=50, chroma=2, bdl=2, bdc=2, bypass=1, v=vui(nal_hrd=hrd(1)))
    S['high444'] = sps(profile=144, level=51, chroma=3, rct=1, bdl=6, bdc=6, bypass=1, v=vui(vcl_hrd=hrd(2), pic_struct=1))
    S['svc'] = sps(profile=83, level=30, v=vui(chroma_loc=(1, 1), bsr=True))
    S['mvc'] = sps(profile=118, level=40)
    S['stereo'] = sps(profile=128, level=40)
    S['p138'] = sps(profile=138, level=40)
    S['p44'] = sps(profile=44, level=40)
    S['p86'] = sps(profile=86, level=40)
    S['esc'] = sps(profile=66, wmb=0, hmu=0, crop=None)
    return S

H241_OID = [0, 0, 8, 241, 0, 0, 1]

def h245_frames(S, P, workdir):
    """H.245 TerminalCapabilitySet messages with H.241 H.264 generic video capabilities, tunnelled
    in the h245Control of an H.225.0 Facility (Q.931 in TPKT on TCP port 1720)."""
    types = asnper.load(['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn',
                         'h245/MULTIMEDIA-SYSTEM-CONTROL.asn'], workdir)
    sc = asnper.Schema(types)
    mscm, uu_t = types['MultimediaSystemControlMessage'], types['H323-UserInformation']
    def gp(i, kind, v):
        return {'parameterIdentifier': ('standard', i), 'parameterValue': (kind, v)}
    def tcs(coll, noncoll, n=1, direction='receiveVideoCapability'):
        cap = (direction, ('genericVideoCapability', {
            'capabilityIdentifier': ('standard', H241_OID), 'maxBitRate': 4000,
            'collapsing': coll, 'nonCollapsing': noncoll}))
        return ('request', ('terminalCapabilitySet', {'sequenceNumber': n, 'protocolIdentifier': [0, 0, 8, 245, 0, 11],
                'capabilityTable': [{'capabilityTableEntryNumber': 1, 'capability': cap}]}))
    out = []
    SC4 = b'\x00\x00\x00\x01'
    sets = [
        # Profile (all bits), Level (every named level), ProfileIOP, AdditionalModesSupported
        (tcs([gp(41, 'booleanArray', 0xfe), gp(42, 'unsignedMin', 64), gp(46, 'booleanArray', 0xe0),
              gp(11, 'booleanArray', 0x80), gp(12, 'booleanArray', 0x40)], [gp(43, 'octetString', S['high'])]), 'receive'),
        # CustomMax*, MaxStaticMBPS, max NAL sizes, sample aspect ratios, AcceptRedundantSlices, NalAlignedMode
        (tcs([gp(i, 'unsignedMin', 100 + i) for i in (3, 4, 5, 6, 7, 8, 9)] + [gp(10, 'booleanArray', 0x7f),
              gp(44, 'logical', None), gp(45, 'logical', None), gp(41, 'booleanArray', 0x01), gp(42, 'unsignedMin', 12345)],
             [gp(43, 'octetString', SC4 + S['base'] + SC4 + P['basic'])], n=2, direction='transmitVideoCapability'), 'transmit'),
        # decoder configuration with the start code, an SPS followed by a PPS in one octet string, and a 3 octet start code
        (tcs([gp(42, 'unsignedMin', 15)], [gp(43, 'octetString', b'\x00\x00\x01' + S['poc2'] + P['big'])], n=3), 'receive'),
    ]
    for lvl in (15, 19, 22, 29, 36, 43, 50, 57, 64, 71, 78, 85, 92, 99, 106, 113):
        sets.append((tcs([gp(42, 'unsignedMin', lvl)], [], n=10 + lvl), 'receive'))
    for m, _ in sets:
        h245 = sc.encode(mscm, m).bytes()
        uu = sc.encode(uu_t, {'h323-uu-pdu': {'h323-message-body': ('empty', None), 'h245Tunnelling': True,
                                              'h245Control': [h245]}}).bytes()
        q931 = bytes([0x08, 0x02, 0x00, 0x01, 0x62]) + bytes([0x7E]) + struct.pack('!H', len(uu) + 1) + bytes([0x05]) + uu
        out.append(struct.pack('!BBH', 3, 0, 4 + len(q931)) + q931)
    return out

def malformed(out, S, P, sprop):
    m = PcapNg()
    SC4 = b'\x00\x00\x00\x01'
    m.udp(A, B, 5060, 5060, sip(sdp(5004, 96, 'H264/90000',
          'profile-level-id=640028;packetization-mode=1;sprop-parameter-sets=' + sprop(S['base'], P['basic'])),
          call='c23h264m'))
    m.udp(A, B, 5060, 5060, sip(sdp(5020, 96, 'H264/90000',
          'profile-level-id=640028;packetization-mode=1;sprop-parameter-sets=' + sprop(S['high'][:12], P['ext'][:3])),
          call='c23h264n'))
    m.udp(A, B, 5060, 5060, sip(sdp(5022, 96, 'H264/90000',
          'profile-level-id=640028;packetization-mode=1;sprop-parameter-sets=' + sprop(S['base'], P['ext'][:3])),
          call='c23h264o'))
    def rt(payload): m.udp(A, B, 5004, 5004, rtp(payload, 96))
    pad = bytes(24)
    # Exp-Golomb codes of more than 32 bits, exactly 32 bits, in ue(v) and se(v) places
    def pps_bits(first=None, qp=None):
        b = Bits()
        if first is not None: first(b)
        else: b.ue(0)
        b.ue(0).u(1, 1).u(1, 0).ue(0).ue(0).ue(0).u(1, 0).u(2, 0)
        if qp is not None: qp(b)
        else: b.se(0)
        b.se(0).se(0).u(1, 1).u(1, 0).u(1, 0)
        return bytes([0x68]) + b.pad().bytes() + pad
    z = lambda n, tail: (lambda b: b.u(n, 0).u(1, 1).u(tail[0], tail[1]))
    rt(pps_bits(z(40, (40, 0x123456789a))))                 # ue, 40 leading zero bits, even value
    rt(pps_bits(qp=z(40, (40, 0x123456789b))))              # se, odd value
    rt(pps_bits(qp=z(40, (40, 0x123456789a))))              # se, even value
    rt(pps_bits(z(32, (32, 0))))                            # ue, 32 bits, value 0: UINT32_MAX, no overflow
    rt(pps_bits(z(32, (32, 5))))                            # ue, 32 bits, value != 0: overflow
    rt(pps_bits(qp=z(32, (32, 1))))                         # se, 32 bits, value 1: no overflow (odd)
    rt(pps_bits(qp=z(32, (32, 2))))                         # se, 32 bits, value != 1: overflow, even
    rt(pps_bits(qp=z(32, (32, 3))))                         # se, 32 bits, odd, overflow
    # delta_scale out of range in a scaling list
    b = Bits().ue(0).ue(1).ue(0).ue(0).u(1, 0).u(1, 1)
    for i in range(8):
        b.u(1, 1)
        for j in range(16 if i < 6 else 64):
            b.se(-130 if j == 0 else 1)
    b.ue(0).ue(0).ue(4).ue(1).u(1, 0).ue(10).ue(10).u(1, 1).u(1, 1).u(1, 0).u(1, 0).trailing()
    rt(bytes([0x67, 100, 0, 40]) + b.bytes())
    # bad NAL lengths in every aggregation form
    sl = slice_(1)
    rt(stap(24, [sl]) + b'\x00\x00')                                   # size 0
    rt(bytes([24]) + struct.pack('>H', 200) + sl)                      # size too large
    rt(bytes([25, 0, 5]) + struct.pack('>H', 0) + sl)                  # STAP-B size 0
    rt(bytes([26, 0, 5]) + struct.pack('>HBH', 99, 1, 2) + sl)         # MTAP16 too large
    rt(bytes([27, 0, 5]) + struct.pack('>HB', 0, 1) + b'\x00\x00\x01' + sl)   # MTAP24 size 0
    rt(bytes([31, 0x10]) + struct.pack('>HH', 77, 1) + sl)             # NI-MTAP too large
    rt(bytes([31, 0x14]) + struct.pack('>HHH', 0, 1, 2) + sl)          # NI-MTAP with DON, size 0
    sx = sei(sei_msg(6, b'\x01\x02'))
    rt(pacsi(0x00, []) + struct.pack('>H', 0) + sx)                    # PACSI nal size 0
    rt(pacsi(0x00, []) + struct.pack('>H', 100) + sx)                  # PACSI nal size too large
    # truncated forms (exceptions)
    rt(bytes([24])); rt(bytes([24, 0])); rt(bytes([25, 0])); rt(bytes([26, 0, 1, 0, 3])); rt(bytes([27, 0, 1, 0, 3, 1, 0]))
    rt(bytes([28])); rt(bytes([28, 0x85])); rt(bytes([30, 0x80, 0x00])); rt(bytes([30]) + svc_ext())
    rt(bytes([30]) + svc_ext() + bytes([0x40, 1])); rt(bytes([30]) + svc_ext() + bytes([0x20, 1]))
    rt(bytes([31])); rt(bytes([31, 0x10, 0, 3])); rt(bytes([31, 0x14, 0, 3, 0, 1, 0]))
    rt(bytes([0x6e])); rt(bytes([0x6e, 0x80])); rt(bytes([0x6e, 0x00, 0x00]))
    rt(bytes([0x06])); rt(bytes([0x06, 0xff])); rt(bytes([0x06, 5, 0xff]))
    rt(bytes([0x06, 5, 20]) + MS_LAYOUT[:9]); rt(bytes([0x06, 5, 40]) + MS_LAYOUT + bytes(8))
    rt(bytes([0x06, 5, 40]) + MS_LAYOUT + bytes(8) + bytes([1, 16]) + ms_layer()[:9])
    rt(bytes([0x06, 5, 40]) + MS_CROP + bytes([9, 1, 1, 2]))
    rt(bytes([0x06, 5, 18]) + MS_BITSTREAM + bytes([4]))
    rt(bytes([0x06, 5, 40]) + bytes(10))
    rt(bytes([0x06, 0, 200, 1, 2]))
    rt(bytes([0x01])); rt(bytes([0x05, 0x00])); rt(bytes([0x03])); rt(bytes([0x04, 0x00]))
    rt(bytes([0x09])); rt(bytes([0x09, 0x00]))
    for k in range(6, 40, 3):                               # SPS cut at several places
        rt(S['high'][:k])
    for k in (3, 5, 8, 12, 18):
        rt(P['ext_noscale_pos'][:k])
    for k in (3, 5):
        rt(P['slicegrp'][:k])
    rt(fu_a(7, 1, 0, S['high'][1:20]))
    # byte streams the dissector rejects or cuts
    m.add_epdu('h264_bytestream', b'\x12\x34\x56\x78\x9a')           # not a byte stream
    m.add_epdu('h264_bytestream', b'\x00\x00\x01')                     # shorter than 4
    m.add_epdu('h264_bytestream', b'\x00\x00\x00\x00\x12\x34\x56\x78')   # zeros, then not a start code
    m.add_epdu('h264_bytestream', SC4 + S['high'][:15])                  # SPS cut
    m.add_epdu('h264_bytestream', SC4 + bytes([0x67]))                   # SPS header only
    m.add_epdu('h264_bytestream', SC4 + sei(sei_msg(5, bytes(range(16)) + b'xx'))[:8])
    m.add_epdu('h264_bytestream', SC4 + pps_bits(z(40, (40, 0x123456789a)))[:30])
    m.write(os.path.join(out, 'h264-coverage-malformed.pcapng'))

def main(out, verbose=False, workdir=None):
    p = PcapNg(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    S = build_sps_set()
    P = {
        'basic': pps(),
        'ext': pps(pid=1, ext=(1, 0, -3)),
        'ext_noscale_pos': pps(pid=2, entropy=0, poc_pres=1, l0=2, l1=1, wp=1, wb=2, qp=-4, qs=3, cqo=5,
                               dbf=0, cip=1, rpc=1, ext=(0, 0, 4)),
        'scaling': pps(pid=3, ext=(1, 1, 0), raw_tail=b'\xff\xee'),
        'slicegrp': pps(pid=4, nsg=2, sgmap=6, raw_tail=b'\x01\x02\x03'),
        'big': pps(pid=40, sid=31, qp=-26, qs=25, cqo=12),
    }
    sprop = lambda *n: ','.join(base64.b64encode(x).decode() for x in n)

    # ---------- SIP / SDP (Ethernet interface) ----------
    mark('SIP INVITE: H264 type 96 on UDP 5004, profile-level-id 640028, packetization-mode 1, sprop-parameter-sets (SPS,PPS)')
    p.udp(A, B, 5060, 5060, sip(sdp(5004, 96, 'H264/90000',
          'profile-level-id=640028;packetization-mode=1;sprop-parameter-sets=' + sprop(S['high'], P['ext'])),
          call='c23h264a'))
    mark('SIP INVITE: type 97 on UDP 5006 (H264-SVC), level 1b profile, SPS, 4 octet start code and PPS in one sprop blob')
    p.udp(A, B, 5060, 5060, sip(sdp(5006, 97, 'H264-SVC/90000',
          'profile-level-id=42100b;packetization-mode=0;sprop-parameter-sets=' + sprop(S['base1b'] + b'\x00\x00\x00\x01' + P['basic'])),
          call='c23h264b'))
    mark('SIP INVITE: type 98 on UDP 5008, sprop with Annex B start codes (4 and 3 octets)')
    p.udp(A, B, 5060, 5060, sip(sdp(5008, 98, 'H264/90000',
          'profile-level-id=4d001f;packetization-mode=2;sprop-parameter-sets=' +
          sprop(b'\x00\x00\x00\x01' + S['poc2'], b'\x00\x00\x01' + P['big'])), call='c23h264c'))
    mark('SIP INVITE: sprop with a SEI and a slice (types 6 and 5 outside parameter sets)')
    p.udp(A, B, 5060, 5060, sip(sdp(5010, 96, 'H264/90000',
          'packetization-mode=1;sprop-parameter-sets=' + sprop(sei(sei_msg(6, b'\x01\x02')), slice_(5))),
          call='c23h264d'))

    def rt(payload, port=5004, pt=96, mk=0):
        p.udp(A, B, port, port, rtp(payload, pt, mk))

    # ---------- RTP single NAL units ----------
    mark('RTP single NAL: SPS variants (baseline, level 1b, crop+mbaff, POC types 1 and 2, High with scaling lists and full VUI/HRD, High 10/4:2:2/4:4:4, SVC/MVC/Stereo/138/44/86 profiles)')
    for k in ('base', 'base1b', 'base_crop', 'poc1', 'poc2', 'high', 'high_noscale', 'high10', 'high422',
              'high444', 'svc', 'mvc', 'stereo', 'p138', 'p44', 'p86', 'esc'):
        rt(S[k])
    mark('RTP single NAL: PPS variants (basic, transform 8x8, positive values, scaling matrix, slice groups, large ids)')
    for k in ('basic', 'ext', 'ext_noscale_pos', 'scaling', 'slicegrp', 'big'):
        rt(P[k])
    mark('RTP single NAL: slices (types 1, 5, 19), data partitions B and C, access unit delimiter')
    rt(slice_(1, 0, 0, 0)); rt(slice_(1, 5, 1, 1)); rt(slice_(5, 0, 7, 0), mk=1)
    rt(slice_(19, 1, 2, 2)); rt(part_bc(3)); rt(part_bc(4)); rt(slice_(1, 300, 9, 31, ref=0))
    rt(aud(0))      # type 9 is not decoded by the RTP dissector
    mark('RTP single NAL: SEI with buffering period, recovery point, DRPM repetition, other payload types, long type and size')
    rt(sei(sei_msg(0, b'\x01\x02\x03\x04')))
    rt(sei(sei_msg(6, b'\x00\x80\x00')))
    rt(sei(sei_msg(7, b'\x05')))
    rt(sei(sei_msg(1, b'\x11\x22')))
    rt(sei(sei_msg(300, b'\x33' * 300)))
    mark('RTP single NAL: SEI user data unregistered (MS layout with 1 and 2 layers, wrong length; MS cropping; MS bitstream; ISO 16-octet and longer)')
    rt(sei(sei_msg(5, MS_LAYOUT + bytes([0x81, 0, 0, 0, 0, 0, 0, 0x03, 1, 16]) + ms_layer())))
    rt(sei(sei_msg(5, MS_LAYOUT + bytes([0xff] * 8) + bytes([1, 32]) + ms_layer() + ms_layer(w=320, h=240, fr=2, lt=0, prid=7, cb=0))))
    rt(sei(sei_msg(5, MS_LAYOUT + bytes(8) + bytes([1, 99]) + ms_layer())))     # wrong LD size
    rt(sei(sei_msg(5, MS_LAYOUT + bytes(8) + bytes([0]))))                      # p flag 0
    rt(sei(sei_msg(5, MS_CROP + bytes([2, 1]) + bytes([9]) + struct.pack('>HHHH', 1, 2, 3, 4) + bytes([8]) + struct.pack('>HHHH', 5, 6, 7, 8))))
    rt(sei(sei_msg(5, MS_BITSTREAM + bytes([4, 6]))))
    rt(sei(sei_msg(5, bytes(range(16)))))                                       # exactly 16: no payload
    rt(sei(sei_msg(5, bytes(range(16)) + b'secinfo-0123456789')))             # ISO payload (fixed length)
    mark('RTP single NAL: prefix NAL (SVC extension flag set and clear), reserved/unspecified/ignored types')
    rt(bytes([0x6e]) + svc_ext())
    rt(bytes([0x6e]) + b'\x00\x00\x00\xff')
    rt(bytes([0x0a, 0x80])); rt(bytes([0x2c, 1]))
    rt(bytes([0x60 | 20, 1, 2, 3]))
    mark('RTP STAP-A / STAP-B')
    rt(stap(24, [S['base'], P['basic']]))
    rt(stap(24, [S['high'], P['ext'], slice_(5), sei(sei_msg(6, b'\x01\x02'))]))
    rt(stap(25, [P['basic'], slice_(1)], don=500))
    rt(stap(24, [stap(24, [stap(24, [S['base'], P['basic']]), slice_(1)]), sei(sei_msg(6, b'\x01\x02'))]))   # nested aggregation
    mark('RTP MTAP16 / MTAP24')
    rt(mtap(26, [slice_(1), slice_(1, 3)]))
    rt(mtap(27, [slice_(5), P['basic'], S['base']], don=65535))
    mark('RTP PACSI (with TL0PICIDX/IDRPICID, with DONC, with both, with none; embedded SEI)')
    sx = sei(sei_msg(6, b'\x01\x02'))
    rt(pacsi(0x40, [sx])); rt(pacsi(0x20, [sx, sx])); rt(pacsi(0x60, [sx])); rt(pacsi(0x9f, [])); rt(pacsi(0xe0, []))
    mark('RTP FU-A: start of an IDR slice, middle, end; start of an SPS and of a SEI; start fragment with E bit')
    rt(fu_a(5, 1, 0, Bits().ue(0).ue(7).ue(0).pad().bytes() + b'\x88\x99'))
    rt(fu_a(5, 0, 0, b'\x01\x02\x03'))
    rt(fu_a(5, 0, 1, b'\x04\x05'), mk=1)
    rt(fu_a(7, 1, 0, S['base'][1:]))
    rt(fu_a(6, 1, 0, sei(sei_msg(6, b'\x01\x02'))[1:]))
    rt(fu_a(1, 1, 1, Bits().ue(0).ue(0).ue(0).pad().bytes() + b'\x55'))
    mark('RTP NAL header extension (type 31): empty, reserved subtype, NI-MTAP with and without DON')
    rt(ni_mtap([], subtype=1, j=1, k=1, l=1)); rt(ni_mtap([slice_(1)], subtype=0))
    rt(ni_mtap([slice_(1), P['basic']], j=0)); rt(ni_mtap([slice_(5), sx], j=1, k=1, l=1))
    mark('RTP on the other payload types: H264-SVC type 97 and type 98')
    rt(S['base'], port=5006, pt=97); rt(slice_(5), port=5006, pt=97)
    rt(S['high'], port=5008, pt=98); rt(slice_(1), port=5008, pt=98)

    # ---------- H.245 generic video capabilities (Ethernet interface) ----------
    mark('H.245 TerminalCapabilitySet tunnelled in H.225.0 Facility (TCP 1720): H.241 H.264 capabilities (profile, level, ProfileIOP, additional modes, custom parameters, decoder configuration NAL units)')
    for pkt in h245_frames(S, P, workdir):
        p.tcp(A, B, 40001, 1720, pkt)

    # ---------- Annex B byte stream (Exported PDU interface) ----------
    SC4, SC3 = b'\x00\x00\x00\x01', b'\x00\x00\x01'
    HDR = Bits().ue(0).ue(7).ue(0).pad().bytes()
    mark('Exported PDU h264_bytestream: SPS, PPS, SEI, AUD, IDR slice; 3 and 4 octet start codes; leading zeros')
    p.add_epdu('h264_bytestream', SC4 + S['high'] + SC3 + P['ext'] + SC3 + sei(sei_msg(6, b'\x01\x02')) +
               SC4 + aud(2) + SC3 + slice_(5))
    p.add_epdu('h264_bytestream', b'\x00\x00\x00\x00\x00\x00\x01' + S['base_crop'] + SC4 + P['ext_noscale_pos'])
    mark('Exported PDU h264_bytestream: NAL unit types 0 to 19, 28, 31 (one per frame)')
    nals = [bytes([0x00, 0x11]), slice_(1), slice_(2), part_bc(3), part_bc(4), slice_(5), sei(sei_msg(6, b'\x01\x02')),
            S['base'], P['basic'], aud(5), bytes([0x4a, 0x00, 0x01]), bytes([0x4b, 0x11]),
            bytes([0x0c, 0xff, 0xff]), bytes([0x0d, 0x11, 0x22]), bytes([0x6e, 0x01]), bytes([0x0f, 0x01]),
            bytes([0x10, 1]), bytes([0x11, 1]), bytes([0x12, 1]), slice_(19), bytes([0x7c, 0x85, 0x88]), bytes([0x1f, 0x01, 0x02])]
    for n in nals:
        p.add_epdu('h264_bytestream', SC4 + n)
    mark('Exported PDU h264_bytestream: escaped payload (emulation prevention), several SPS/PPS in one packet')
    p.add_epdu('h264_bytestream', SC3 + nal(2, 5, HDR + b'\x88\x00\x00\x00\x01\x00\x00\x02\x00\x00\x03\x00\x00\x7f') + SC3 +
               nal(2, 1, HDR + b'\x88\x00\x00\x03\x00\x7f'))
    p.add_epdu('h264_bytestream', SC4 + S['poc1'] + SC4 + S['poc2'] + SC3 + S['p138'] + SC3 + P['big'])
    p.write(os.path.join(out, 'h264-coverage.pcapng'))
    n = len(p.frames)
    malformed(out, S, P, sprop)
    if verbose:
        print('main capture: %d frames' % n)
        for k, d in marks: print('  %d: %s' % (k, d))

if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if a != '-v']
    main(args[0], '-v' in sys.argv, args[1] if len(args) > 1 else tempfile.mkdtemp())
