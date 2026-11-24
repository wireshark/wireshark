#!/usr/bin/env python3
# Generates test/captures/h265_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the H.265 coverage captures.  Usage: mkh265.py <outdir> [-v]

h265-coverage.pcapng            main capture (Ethernet + Exported PDU)
h265-coverage-malformed.pcapng  paths that only malformed input reaches
"""
import base64
import os
import struct
import sys

from h265lib import (
    aud, Bits, epdu, escape, nal, nal_hdr, pcapng, pps, ptl, sei, slice_hdr, sps, udp_frame, vps,
    vps_auto,
)

VERBOSE = '-v' in sys.argv

# profile compatibility flag words (flag j is bit 31-j)
def compat(*js):
    v = 0
    for j in js:
        v |= 1 << (31 - j)
    return v


# ------------------------------------------------------------------ SDP/SIP

def sip(method, sdp, cseq, status=None):
    if status:
        start = 'SIP/2.0 200 OK\r\n'
    else:
        start = '%s sip:b@192.0.2.2 SIP/2.0\r\n' % method
    h = (start +
         'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK%d\r\n'
         'From: <sip:a@192.0.2.1>;tag=1\r\nTo: <sip:b@192.0.2.2>;tag=2\r\n'
         'Call-ID: 265@192.0.2.1\r\nCSeq: %d INVITE\r\nContact: <sip:a@192.0.2.1>\r\n'
         'Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n' % (cseq, cseq, len(sdp)))
    return (h + sdp).encode()


def sdp_h265(addr, port, fmtp, extra=''):
    return ('v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
            'm=video %d RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n%s'
            'a=fmtp:96 %s\r\n' % (addr, addr, port, extra, fmtp))


def b64(nal_bytes):
    return base64.b64encode(nal_bytes).decode()


def sprop(**kw):
    return '; '.join('sprop-%s=%s' % (k, b64(v)) for k, v in kw.items())


# ---------------------------------------------------------------- the NALs

BASIC_VPS = nal(32, vps_auto(), 0, 1)
BASIC_SPS = nal(33, sps())
BASIC_PPS = nal(34, pps())

A_SRC, A_DST = '192.0.2.1', '192.0.2.2'


class Rtp:
    seq = 100
    ts = 90000

    @classmethod
    def pkt(cls, payload, src, dst, sport, dport, pt=96, marker=0, ssrc=0x1234):
        cls.seq += 1
        cls.ts += 3000
        h = struct.pack('!BBHII', 0x80, (marker << 7) | pt, cls.seq, cls.ts, ssrc)
        return udp_frame(src, dst, sport, dport, h + payload)


def rtp_a(payload, **kw):          # towards the offer address 192.0.2.1:40000
    return Rtp.pkt(payload, A_DST, A_SRC, 40010, 40000, **kw)


def rtp_b(payload, **kw):          # towards the answer address 192.0.2.2:40002
    return Rtp.pkt(payload, A_SRC, A_DST, 40001, 40002, ssrc=0x4321, **kw)


def fu(t, s, e, payload, layer=0, tid=1):
    return nal_hdr(49, layer, tid) + bytes([(s << 7) | (e << 6) | t]) + payload


def ap(*nals):
    out = nal_hdr(48)
    for n in nals:
        out += struct.pack('!H', len(n)) + n
    return out


# ----------------------------------------------------------- PTL variants

PTL_MAIN = {}
PTL_RExt = dict(idc=4, compat=compat(4), tier=1, level=120, c9=(1, 1, 1, 0, 1, 0, 1, 0, 1))
PTL_14BIT = dict(idc=5, compat=compat(5, 4), level=153)
PTL_SCC9 = dict(idc=9, compat=compat(9), space=1, level=150)
PTL_STILL = dict(idc=2, compat=compat(2, 1), level=90)
PTL_OTHER = dict(idc=3, compat=compat(3), level=60)
PTL_COMPAT = dict(idc=1, compat=compat(1, 6), level=93)      # category A through a compatibility flag only
PTL_ZERO = dict(idc=0, compat=0, level=30)                   # reserved zero bit
PTL_SUBS = dict(idc=1, subs=[(1, 0, 4, compat(4), 0), (1, 0, 5, compat(5), 0), (0, 0, 0, 0, 0)])
PTL_SUBS2 = dict(idc=4, compat=compat(4), subs=[(1, 0, 2, compat(2), 0), (1, 0, 3, compat(3), 0),
                                               (1, 0, 0, 0, 0), (0, 0, 0, 0, 0)])


def vps_variants():
    yield 'VPS: basic', nal(32, vps_auto(), 0, 1)
    yield 'VPS: 3 sub-layers, no ordering info, PTL with sub-layers', nal(32, vps_auto(max_sub=2, order_present=0, ptl_kw=PTL_SUBS))
    yield 'VPS: 4 sub-layers, ordering info, RExt PTL with sub-layers', nal(32, vps_auto(max_sub=3, ptl_kw=PTL_SUBS2, max_layers_minus1=1, base_internal=0, base_avail=0))
    yield 'VPS: layer sets, timing with POC proportional, 3 HRD', nal(32, vps_auto(
        max_layer_id=3, num_layer_sets_minus1=3, max_sub=1, order_present=0,
        ptl_kw=PTL_14BIT,
        timing=dict(units=1001, scale=60000, poc=4, hrds=[
            dict(idx=0, common=1),
            dict(common=1, nal=1, vcl=0, sub_pic=1, cpb=(1, 0), general=(0, 1), cvs=(1, 0)),
            dict(common=1, nal=1, vcl=0, sub_pic=0, cpb=(2, 0), general=(1, 0), cvs=(1, 0)),
            dict(common=0, cpb=(1,), general=(0,), cvs=(0,)),
        ])))
    yield 'VPS: timing, 1 HRD (hrd_layer_set_idx reproducer)', nal(32, vps_auto(timing=dict(units=1001, scale=60000, hrds=[dict(idx=0, common=1)])))
    yield 'VPS: timing, 2 HRD with NAL HRD only', nal(32, vps_auto(
        timing=dict(units=1, scale=25, hrds=[dict(idx=0, common=1), dict(idx=300, common=1, nal=1, cpb=(1,), general=(1,))])))
    yield 'VPS: timing, 2 HRD with VCL HRD only, no sub-pic', nal(32, vps_auto(
        timing=dict(units=1, scale=25, hrds=[dict(idx=0, common=1), dict(idx=2, common=1, vcl=1, cpb=(0,), general=(0,), cvs=(0,))])))
    yield 'VPS: extension data flags', nal(32, vps_auto(ext_bits=[1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1]))
    yield 'VPS: still-picture PTL, reserved-zero PTL', nal(32, vps_auto(ptl_kw=PTL_STILL))
    yield 'VPS: profile idc 3 PTL', nal(32, vps_auto(ptl_kw=PTL_OTHER, vps_id=5))
    yield 'VPS: profile idc 9 PTL, tier', nal(32, vps_auto(ptl_kw=PTL_SCC9))
    yield 'VPS: compat-flag PTL', nal(32, vps_auto(ptl_kw=PTL_COMPAT))
    yield 'VPS: profile idc 0 PTL', nal(32, vps_auto(ptl_kw=PTL_ZERO))


def sps_variants():
    yield 'SPS: basic', nal(33, sps())
    yield 'SPS: 3 sub-layers, no ordering info, sub-layer PTL', nal(33, sps(max_sub=2, order_present=0, ptl_kw=PTL_SUBS))
    yield 'SPS: 4 sub-layers, ordering info', nal(33, sps(max_sub=3, ptl_kw=PTL_SUBS2))
    yield 'SPS: monochrome 10 bit, conformance window, PCM, scaling lists enabled (default)', nal(33, sps(
        chroma=0, bd_l=2, bd_c=2, conf_win=(1, 2, 3, 4), scaling=False, pcm=(7, 7, 0, 2, 1), amp=0, sao=0,
        tmvp=0, strong=0, ptl_kw=PTL_RExt, log2_poc=8))
    yield 'SPS: 4:4:4 separate planes, scaling list data, 3 RPS (inter), 2 long-term refs', nal(33, sps(
        chroma=3, sep_plane=1, scaling=0, ptl_kw=PTL_14BIT, log2_poc=4,
        rps=[('abs', [(0, 1), (1, 0), (2, 1)], [(0, 1)]),
             ('inter', 1, 0, [(1, 0)] * 5),
             ('inter', 0, 2, [(0, 1), (0, 0), (1, 0), (0, 1), (1, 1)])],
        lt=[(0x0a, 1), (0x05, 0)]))
    yield 'SPS: scaling list data, other pattern, long-term refs of width 16', nal(33, sps(
        scaling=1, log2_poc=12, lt=[(0x1234, 1)], rps=[('abs', [], [])]))
    yield 'SPS: chroma 4:2:2, VUI with extended SAR, overscan, signal type, colour, chroma loc, display window, timing + POC, HRD', nal(33, sps(
        chroma=2, vui_opts=dict(aspect=255, overscan=1, signal=(5, 1, 1), chroma_loc=(1, 2), disp_win=(1, 2, 3, 4),
                                timing=dict(poc=7, hrd=dict(nal_=0, vcl=0, cpb=(0,), general=(0,)))), ptl_kw=PTL_STILL))
    yield 'SPS: VUI with HRD parameters having NAL and VCL HRD (the dissector drops the length)', nal(33, sps(
        max_sub=1, vui_opts=dict(aspect=1, overscan=0, signal=(1, 0, 0), timing=dict(hrd=dict(nal_=1, vcl=1, sub_pic=1, cpb=(1,), general=(0,))))))
    yield 'SPS: VUI with bitstream restriction and timing without HRD', nal(33, sps(
        vui_opts=dict(timing=dict(), restriction=(0, 2, 1, 15, 15)), ptl_kw=PTL_SCC9))
    yield 'SPS: VUI with bitstream restriction only', nal(33, sps(vui_opts=dict(restriction=(1, 1, 1, 14, 14))))
    yield 'SPS: range extension, extension data flags', nal(33, sps(
        ext=dict(range=(1, 0, 1, 0, 1, 0, 1, 0, 1), bits4=5), ext_tail=[1, 0, 1, 1, 0, 1, 0], ptl_kw=PTL_RExt))
    yield 'SPS: multilayer and 3D extensions (not decoded)', nal(33, sps(ext=dict(ml=1, d3=1)))
    yield 'SPS: SCC extension with palette initializers (4:2:0, 8 bit)', nal(33, sps(
        ext=dict(scc=dict(cpr=1, palette=dict(max=31, delta=3, inits=[1, 2, 3]), mvres=2, ibf=1)), ptl_kw=PTL_SCC9))
    yield 'SPS: SCC extension with palette initializers (monochrome, 12 bit luma, reproducer sps_palette_width)', nal(33, sps(
        chroma=0, bd_l=4, bd_c=0,
        ext=dict(scc=dict(cpr=0, palette=dict(max=15, delta=0, inits=[100, 200]), mvres=1, ibf=0))))
    yield 'SPS: SCC extension, palette mode without initializers', nal(33, sps(
        ext=dict(scc=dict(cpr=1, palette=dict(max=15, delta=0)))))
    yield 'SPS: SCC extension without palette mode', nal(33, sps(ext=dict(scc=dict(cpr=1, mvres=3))))
    yield 'SPS: all extensions', nal(33, sps(
        ext=dict(range=(0, 1, 0, 1, 0, 1, 0, 1, 0), ml=1, d3=1, scc=dict(cpr=0), bits4=1), ext_tail=[1, 1]))
    yield 'SPS: 4:4:4 with conformance window, 16 bit luma PCM', nal(33, sps(
        chroma=3, bd_l=8, bd_c=8, conf_win=(0, 1 << 20, 3 << 18, 0), pcm=(15, 15, 2, 1, 0), vps_id=9, sps_id=7))


def pps_variants():
    yield 'PPS: basic', nal(34, pps())
    yield 'PPS: tiles (uniform), deblocking control, cu_qp_delta', nal(34, pps(
        pps_id=1, tiles=dict(cols=4, rows=3, uniform=1, lf=0), deblock=(1, 0, 3, -2), cuqpd=2,
        cabac=1, sign=1, outflag=1, l0=1, l1=2, init_qp=-5, constrained=1, cb=-3, cr=4,
        slice_chroma=1, wp=1, wbp=1, tqb=1, entropy=1, lf_slices=0))
    yield 'PPS: tiles (explicit widths and heights), deblocking disabled, scaling list data, lists modification', nal(34, pps(
        pps_id=2, tiles=dict(cols=3, rows=3, uniform=0, widths=[5, 6], heights=[3, 4]), deblock=(0, 1, 0, 0),
        scaling=0, lists_mod=1, merge=3, sh_ext=1, init_qp=12))
    yield 'PPS: 1x1 tiles flag with uniform spacing and scaling list data (pattern 1)', nal(34, pps(
        pps_id=3, tiles=dict(cols=1, rows=1, uniform=1), scaling=1, tskip=1))
    yield 'PPS: range extension (transform skip, chroma QP offset list)', nal(34, pps(
        pps_id=4, tskip=1, ext=dict(range=dict(ts=2, ccp=1, qp=[(1, -1), (2, -2)])), extra_tail=b'\xff' * 14))
    yield 'PPS: range extension without transform skip', nal(34, pps(
        pps_id=5, cabac=1, ext=dict(range=dict(ccp=1, qp=[(1, -1), (-2, 2)])), extra_tail=b'\xff' * 14))
    yield 'PPS: multilayer and 3D extensions (not decoded)', nal(34, pps(pps_id=6, ext=dict(ml=1, d3=1)))
    yield 'PPS: SCC extension with ACT and palette initializers (4:4:4)', nal(34, pps(
        pps_id=7, ext=dict(scc=dict(cpr=1, act=(-5, 2, 3), inits=[10, 20, 30, 40], luma8=0, chroma8=2))))
    yield 'PPS: SCC extension with monochrome palette initializers', nal(34, pps(
        pps_id=8, ext=dict(scc=dict(cpr=0, inits=[7, 8], mono=1, luma8=1))))
    yield 'PPS: SCC extension with zero palette initializers (reproducer pps_palette_se is one)', nal(34, pps(
        pps_id=9, ext=dict(scc=dict(cpr=0, inits=[]))))
    yield 'PPS: SCC extension, no palette initializers', nal(34, pps(pps_id=10, ext=dict(scc=dict(cpr=1))))
    yield 'PPS: extension data flags', nal(34, pps(
        pps_id=11, ext=dict(bits4=3), ext_tail=[1, 0, 0, 1, 1, 0, 1, 1, 1]))
    yield 'PPS: all extensions', nal(34, pps(
        pps_id=12, ext=dict(ml=1, d3=1, scc=dict(cpr=1, act=(0, 0, 0), inits=[1]), bits4=1), ext_tail=[1]))


# ------------------------------------------------------------- main capture

def main_frames():
    F = []                     # (ifc, bytes, description)

    def eth(data, desc):
        F.append((0, data, desc))

    def ex(name, payload, desc):
        F.append((1, epdu(name, payload), desc))

    # --- SIP / SDP with sprop parameters
    sdp1 = sdp_h265(A_SRC, 40000, sprop(vps=BASIC_VPS, sps=BASIC_SPS, pps=BASIC_PPS) + '; sprop-max-don-diff=0; sprop-depack-buf-nalus=0')
    eth(udp_frame(A_SRC, A_DST, 5060, 5060, sip('INVITE', sdp1, 1)), 'INVITE with sprop-vps, -sps and -pps')
    sps2 = nal(33, sps(max_sub=1, chroma=3, ptl_kw=PTL_14BIT, vui_opts=dict(aspect=255, restriction=(0, 1, 1, 15, 15))))
    pps2 = nal(34, pps(pps_id=1, tiles=dict(cols=2, rows=2, uniform=1), deblock=(1, 0, 1, 1)))
    vps2 = nal(32, vps_auto(max_sub=1, max_layer_id=1, num_layer_sets_minus1=1,
                       timing=dict(units=1, scale=60, hrds=[dict(idx=0, common=1), dict(common=1, nal=1, cpb=(1,))])))
    sdp2 = sdp_h265(A_DST, 40002, sprop(vps=vps2, sps=sps2, pps=pps2))
    eth(udp_frame(A_DST, A_SRC, 5060, 5060, sip('INVITE', sdp2, 1, status=200)), '200 OK with sprop-vps, -sps and -pps (other values)')
    # a SEI NAL where a PPS is expected: unspecified media format specific parameter
    sdp3 = sdp_h265(A_SRC, 40004, sprop(pps=nal(39, Bits().u(8, 0x80))) + '; sprop-sps=' + b64(nal(32, vps_auto())))
    eth(udp_frame(A_SRC, A_DST, 5060, 5060, sip('INVITE', sdp3, 2)), 'INVITE with a SEI NAL in sprop-pps and a VPS in sprop-sps')

    # --- RTP: in-band parameter sets, AUD, SEI, slices
    ra = rtp_a
    eth(ra(nal(35, aud(1))), 'RTP AUD')
    eth(ra(BASIC_VPS), 'RTP VPS')
    eth(ra(BASIC_SPS), 'RTP SPS')
    eth(ra(BASIC_PPS), 'RTP PPS')
    eth(ra(nal_hdr(39) + escape(sei([(5, bytes(range(20))), (1, b'\x11\x22\x33')]))), 'RTP prefix SEI, two messages')
    eth(ra(nal_hdr(39) + escape(sei([(300, b'\xab' * 270), (255, b'')]))), 'RTP prefix SEI, payload type 300 and size 270')
    eth(ra(nal_hdr(40, 0, 2) + escape(sei([(3, b'\x01\x02')]))), 'RTP suffix SEI')
    eth(ra(slice_hdr(19, first=1), marker=1), 'RTP IDR_W_RADL, first slice segment')
    eth(ra(slice_hdr(20, first=0, dep=0, addr=0x33)), 'RTP IDR_N_LP, not first, independent segment')
    eth(ra(slice_hdr(1, first=0, dep=1, addr=0x80)), 'RTP TRAIL_R, dependent slice segment')
    eth(ra(slice_hdr(1, first=1, stype=1), marker=1), 'RTP TRAIL_R, P slice')
    eth(ra(nal_hdr(36) + b'\x00'), 'RTP end of sequence')
    eth(ra(nal_hdr(37) + b'\x00'), 'RTP end of bitstream')
    eth(ra(nal_hdr(38) + b'\xff' * 8 + b'\x80'), 'RTP filler data')

    # --- fragmentation units
    big = slice_hdr(19, first=1)
    eth(ra(fu(19, 1, 0, escape(bytes([0x80 | 0x40]))[:0] + b'\xde\xad\xbe\xef')), 'RTP FU start (IDR) with payload that is not a slice header')
    eth(ra(fu(19, 0, 0, b'\x01\x02\x03\x04' * 8)), 'RTP FU middle')
    eth(ra(fu(19, 0, 1, b'\x05\x06\x07\x08' * 4), marker=1), 'RTP FU end')
    fs = Bits().u(1, 1).ue(0).u(1, 0).ue(2).trailing().bytes()
    eth(ra(fu(1, 1, 0, fs + b'\x11\x22')), 'RTP FU start (TRAIL_R) holding a slice segment header')
    eth(ra(fu(0, 0, 1, b'\x33\x44')), 'RTP FU end (TRAIL_N)')
    eth(ra(fu(33, 1, 1, escape(sps().bytes()))), 'RTP FU start+end carrying a whole SPS without NAL header')
    eth(ra(fu(34, 1, 1, escape(pps(pps_id=3).bytes()))), 'RTP FU start+end carrying a whole PPS')
    eth(ra(fu(32, 1, 1, escape(vps().bytes()))), 'RTP FU start+end carrying a whole VPS')
    eth(ra(fu(39, 1, 1, escape(sei([(5, b'\x00' * 17)])))), 'RTP FU start+end carrying a SEI message')

    # --- aggregation, PACI and other types
    eth(ra(fu(49, 1, 0, b'\x01\x02\x03')), 'RTP FU start whose type is FU')
    eth(ra(fu(50, 1, 0, b'\x01\x02\x03')), 'RTP FU start whose type is PACI')
    eth(ra(ap(BASIC_VPS, BASIC_SPS, BASIC_PPS)), 'RTP aggregation packet (not decoded)')
    eth(ra(nal_hdr(50) + b'\x00\x01\x02\x03'), 'RTP PACI packet (not decoded)')
    for t in (22, 24, 31, 41, 47, 51, 63):
        eth(ra(nal_hdr(t) + b'\x01\x02\x03'), 'RTP NAL unit type %d' % t)
    for t in (10, 11, 12, 13, 14, 15):
        eth(ra(nal_hdr(t) + b'\x01'), 'RTP reserved VCL NAL type %d' % t)
    eth(ra(nal_hdr(1, 5, 4) + Bits().u(1, 1).ue(0).u(2, 3).ue(1).trailing().bytes()), 'RTP TRAIL_R with layer id 5 and TID 4')
    eth(ra(slice_hdr(0, first=1, stype=0)), 'RTP TRAIL_N')
    eth(ra(nal_hdr(1, 63, 7, f=1) + b'\xe0\x80\x00'), 'RTP NAL with F bit, layer 63, TID 7')

    # --- the other direction (conversation from the 200 OK), all slice types
    for t in list(range(2, 10)) + list(range(16, 22)):
        if t == 19 or t == 20:
            continue
        eth(rtp_b(slice_hdr(t, first=(t % 2), dep=(t % 3 == 0), addr=t, stype=t % 3)), 'RTP slice NAL type %d' % t)
    eth(rtp_b(slice_hdr(22, first=1)), 'RTP RSV_IRAP_VCL22')
    eth(rtp_b(slice_hdr(23, first=0, dep=0, addr=1)), 'RTP RSV_IRAP_VCL23')
    eth(rtp_b(nal_hdr(35) + Bits().u(3, 2).trailing().bytes()), 'RTP AUD pic_type 2')
    eth(rtp_b(nal_hdr(35) + Bits().u(3, 7).trailing().bytes()), 'RTP AUD pic_type 7')

    # --- Exported PDU h265: parameter set variants
    for desc, n in vps_variants():
        ex('h265', n, desc)
    for desc, n in sps_variants():
        ex('h265', n, desc)
    for desc, n in pps_variants():
        ex('h265', n, desc)

    # --- reproducers of the fixes
    # (hrd_layer_set_idx and sps_palette_width are above; the palette SE one:)
    ex('h265', nal(34, pps(pps_id=0, ext=dict(scc=dict(cpr=0, inits=[200])))), 'PPS: one palette initializer (reproducer pps_palette_se)')

    # --- Exported PDU h265_bytestream
    sc3 = b'\x00\x00\x01'
    sc4 = b'\x00\x00\x00\x01'
    stream = sc4 + BASIC_VPS + sc4 + BASIC_SPS + sc4 + BASIC_PPS + sc3 + nal(35, aud(1)) + sc3 + slice_hdr(19)
    ex('h265_bytestream', stream, 'Annex B stream: VPS SPS PPS AUD IDR (3 and 4 byte start codes)')
    ex('h265_bytestream', b'\x00\x00\x00\x00\x00\x01' + slice_hdr(1, first=1) + sc3 + slice_hdr(1, first=0, dep=1, addr=3) + b'\x00\x00\x00\x01' + nal_hdr(36) + b'\x00',
       'Annex B stream with leading zero bytes, ending in EOS')
    ex('h265_bytestream', sc3 + nal_hdr(40) + escape(sei([(4, b'\x01' * 6)])),
       'Annex B stream: single suffix SEI')
    return F


# -------------------------------------------------------- malformed capture

def malformed_frames():
    F = []

    def eth(data, desc):
        F.append((0, data, desc))

    def ex(name, payload, desc):
        F.append((1, epdu(name, payload), desc))

    # the first frame of the capture sets the slice parameters
    sdp = sdp_h265(A_SRC, 40000, sprop(vps=BASIC_VPS, sps=BASIC_SPS, pps=BASIC_PPS))
    eth(udp_frame(A_SRC, A_DST, 5060, 5060, sip('INVITE', sdp, 1)), 'INVITE with sprop parameter sets')

    # reproducers that now stop with an expert info
    ex('h265', nal(33, sps(chroma=1, bd_l=24, bd_c=24,
                            ext=dict(scc=dict(cpr=0, palette=dict(max=31, delta=0, inits=None))))), 'SPS bit depth 32 with SCC extension (reproducer sps_palette_loop, value too large)')
    b = Bits()
    b.u(4, 0).u(3, 0).u(1, 1)
    ptl(b)
    b.ue(0).ue(1).ue(1280).ue(720).u(1, 0).ue(24).ue(24).ue(4).u(1, 1).ue(0).ue(0).ue(0)
    b.ue(0).ue(3).ue(0).ue(3).ue(2).ue(2).u(1, 0).u(1, 1).u(1, 1).u(1, 0).ue(0).u(1, 0).u(1, 1).u(1, 1).u(1, 0)
    b.u(1, 1).u(1, 0).u(1, 0).u(1, 0).u(1, 1).u(4, 0)
    b.u(1, 0).u(1, 1).ue(31).ue(0).u(1, 1)
    b.zeros(40).u(1, 1).u(40, 0x5555555555)
    b.pad()
    ex('h265', nal_hdr(33) + escape(b.bytes() + bytes([0x55]) * 16), 'SPS with palette initializer count of 2^40 (reproducer sps_palette_loop)')
    ex('h265', nal(33, sps(chroma=1, ext=dict(scc=dict(cpr=0, palette=dict(max=31, delta=0, inits=[1] * 129))))),
       'SPS with 129 palette predictor initializers')
    # lt_ref_pic_poc_lsb_sps width reproducer: log2_max_pic_order_cnt_lsb_minus4 = 70
    b = Bits()
    b.u(4, 0).u(3, 0).u(1, 1)
    ptl(b)
    b.ue(0).ue(1).ue(1280).ue(720).u(1, 0).ue(0).ue(0).ue(70)
    b.pad()
    ex('h265', nal_hdr(33) + escape(b.bytes() + bytes([0x55]) * 32), 'SPS with log2_max_pic_order_cnt_lsb_minus4 = 70 (reproducer lt_ref_poc_width)')
    # 65 short-term reference picture sets
    b = Bits()
    b.u(4, 0).u(3, 0).u(1, 1)
    ptl(b)
    b.ue(0).ue(1).ue(1280).ue(720).u(1, 0).ue(0).ue(0).ue(4).u(1, 1).ue(0).ue(0).ue(0)
    b.ue(0).ue(3).ue(0).ue(3).ue(2).ue(2).u(1, 0).u(1, 1).u(1, 1).u(1, 0).ue(65)
    b.pad()
    ex('h265', nal_hdr(33) + escape(b.bytes() + bytes([0x55]) * 16), 'SPS with 65 short-term reference picture sets')
    # PPS reproducers
    ex('h265', nal(34, pps(ext=dict(scc=dict(cpr=0, inits=[1] * 129)))), 'PPS with 129 palette predictor initializers')
    b = pps(pps_id=0, ext=dict(scc=dict(cpr=0, inits=[1, 2], luma8=9, chroma8=0)))
    ex('h265', nal(34, b), 'PPS with luma bit depth entry 17')
    b = pps(pps_id=0, ext=dict(scc=dict(cpr=0, inits=[1, 2], luma8=0, chroma8=12)))
    ex('h265', nal(34, b), 'PPS with chroma bit depth entry 20')

    # Exp-Golomb code that overflows 32 bits
    b = Bits()
    b.u(4, 0).u(3, 0).u(1, 1)
    ptl(b)
    b.zeros(40).u(1, 1).u(40, 0x123456789a)      # sps id with 40 leading zeros
    b.pad()
    ex('h265', nal_hdr(33) + escape(b.bytes() + b'\x55' * 8), 'SPS with an unsigned Exp-Golomb code of 40 leading zero bits')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0).ue(0).ue(0)
    b.zeros(33).u(1, 1).u(33, 0x1ffffffff)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS init_qp_minus26 signed Exp-Golomb with 33 leading zero bits')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0).ue(0).ue(0)
    b.zeros(34).u(1, 1).u(34, 0)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS init_qp_minus26 signed Exp-Golomb with 34 leading zero bits (even)')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0).ue(0).ue(0)
    b.zeros(32).u(1, 1).u(32, 1)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS init_qp_minus26 signed Exp-Golomb with 32 leading zero bits (odd)')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0).ue(0).ue(0)
    b.zeros(32).u(1, 1).u(32, 0)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS init_qp_minus26 signed Exp-Golomb with 32 leading zero bits (even)')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0)
    b.zeros(32).u(1, 1).u(32, 0)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS num_ref_idx_l0 unsigned Exp-Golomb with 32 leading zero bits')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0)
    b.zeros(32).u(1, 1).u(32, 7)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS num_ref_idx_l0 unsigned Exp-Golomb, 32 leading zeros, not zero')
    b = Bits()
    b.ue(0).ue(0).u(1, 1).u(1, 0).u(3, 2).u(1, 0).u(1, 0)
    b.zeros(34).u(1, 1).u(34, 7)
    b.pad()
    ex('h265', nal_hdr(34) + escape(b.bytes() + b'\x55' * 8), 'PPS num_ref_idx_l0 unsigned Exp-Golomb with 34 leading zero bits')

    # truncated and short packets
    ex('h265', nal_hdr(33) + escape(sps().bytes())[:20], 'truncated SPS')
    ex('h265', nal_hdr(32) + escape(vps().bytes())[:10], 'truncated VPS')
    ex('h265', nal_hdr(34) + escape(pps().bytes())[:3], 'truncated PPS')
    ex('h265', nal_hdr(19), 'IDR slice with no header')
    ex('h265', nal_hdr(39) + b'\x05\xff', 'SEI whose payload size runs off the end')
    ex('h265', nal_hdr(39) + b'\xff\xff', 'SEI with only 0xff bytes')
    ex('h265', nal_hdr(35), 'AUD with no payload')
    ex('h265', b'\x40', 'one byte NAL')
    ex('h265', nal_hdr(49) + b'\x80', 'FU start with no payload')
    ex('h265', nal_hdr(49), 'FU with no FU header')
    ex('h265', nal_hdr(32), 'VPS with no payload')
    ex('h265', nal_hdr(36), 'end of sequence with no payload')
    ex('h265', nal_hdr(37), 'end of bitstream with no payload')
    ex('h265_bytestream', b'\x00\x00\x01' + nal_hdr(36), 'Annex B: end of sequence with no payload')

    # truncated sprop in SDP
    s = nal(33, sps())[:12]
    sdp = sdp_h265(A_SRC, 40006, 'sprop-sps=' + b64(s))
    eth(udp_frame(A_SRC, A_DST, 5060, 5060, sip('INVITE', sdp, 3)), 'INVITE with a truncated sprop-sps')
    s = nal_hdr(32) + b'\x01'
    sdp = sdp_h265(A_SRC, 40008, 'sprop-vps=' + b64(s) + '; sprop-pps=' + b64(nal(34, pps())[:4]))
    eth(udp_frame(A_SRC, A_DST, 5060, 5060, sip('INVITE', sdp, 4)), 'INVITE with a truncated sprop-vps and sprop-pps')

    # Annex B streams that are not
    ex('h265_bytestream', b'\x12\x34\x56\x78\x9a', 'Annex B: no start code')
    ex('h265_bytestream', b'\x00\x00', 'Annex B: too short')
    ex('h265_bytestream', b'\x00\x00\x01' + nal_hdr(33) + escape(sps().bytes())[:9] + b'\x00\x00\x01' + nal_hdr(35),
       'Annex B: truncated SPS followed by an AUD')
    ex('h265_bytestream', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'Annex B: only zero bytes')
    ex('h265_bytestream', b'\x00\x00\x01', 'Annex B: only a start code')
    ex('h265_bytestream', b'\x00\x00\x01\x00\x00\x01\x4e\x01\x00\x00\x01', 'Annex B: empty NAL units')

    # RTP with an invalid dynamic payload
    eth(Rtp.pkt(b'\x00', A_DST, A_SRC, 40010, 40000), 'RTP with a one byte payload')
    eth(Rtp.pkt(b'', A_DST, A_SRC, 40010, 40000), 'RTP with no payload')

    # variants with different statics (not for the main capture: -2 differs)
    ex('h265', nal(33, sps(W=64, H=64, min_cb=1, diff_cb=1)), 'SPS 64x64 with small CTB')
    ex('h265', nal(34, pps(dep=0, extra=0)), 'PPS without dependent slices and without extra header bits')
    ex('h265', slice_hdr(1, first=0, dep=0, addr=0, nbits=0, extra=0, dep_enabled=0), 'slice with nBits = 0, no extra bits')
    ex('h265', nal(33, sps(W=0, H=0, min_cb=0, diff_cb=0)), 'SPS with picture size 0')
    ex('h265', slice_hdr(1, first=0, dep=0, addr=0, nbits=0, extra=0, dep_enabled=0), 'slice with a zero size picture')
    return [x for x in F if x is not None]


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, fn in (('h265-coverage.pcapng', main_frames), ('h265-coverage-malformed.pcapng', malformed_frames)):
        fr = fn()
        pcapng(os.path.join(out, name), [(i, d) for i, d, _ in fr])
        if VERBOSE:
            print(name, len(fr), 'frames')
            for n, (_, _, desc) in enumerate(fr, 1):
                print('%3d  %s' % (n, desc))


main()
