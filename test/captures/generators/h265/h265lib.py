# Helper module for the h265 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Bit writer, H.265 syntax encoders and capture helpers for mkh265.py.
# Everything is built with struct; nothing comes from a real network.
import struct


class Bits:
    def __init__(self):
        self.b = []

    def u(self, n, v=0):
        for i in range(n - 1, -1, -1):
            self.b.append((v >> i) & 1)
        return self

    def f(self, v):
        return self.u(1, 1 if v else 0)

    def ue(self, v):
        v += 1
        n = v.bit_length()
        self.u(n - 1, 0)
        self.u(n, v)
        return self

    def se(self, v):
        return self.ue(2 * v - 1 if v > 0 else -2 * v)

    def zeros(self, n):
        return self.u(n, 0)

    def pad(self):
        while len(self.b) % 8:
            self.b.append(0)
        return self

    def trailing(self):
        self.b.append(1)
        return self.pad()

    def bytes(self):
        self.pad()
        out = bytearray()
        for i in range(0, len(self.b), 8):
            v = 0
            for bit in self.b[i:i + 8]:
                v = (v << 1) | bit
            out.append(v)
        return bytes(out)


def escape(rbsp):
    """Insert emulation prevention bytes (the dissector removes 00 00 03)."""
    out = bytearray()
    zeros = 0
    for c in rbsp:
        if zeros >= 2 and c <= 3:
            out.append(3)
            zeros = 0
        out.append(c)
        zeros = zeros + 1 if c == 0 else 0
    return bytes(out)


def nal_hdr(t, layer=0, tid=1, f=0):
    return bytes([(f << 7) | (t << 1) | (layer >> 5), ((layer & 0x1f) << 3) | tid])


def nal(t, b, layer=0, tid=1):
    """NAL unit from a Bits object (rbsp already with trailing bits)."""
    return nal_hdr(t, layer, tid) + escape(b.bytes())


# ------------------------------------------------------------------ PTL

def cbit(compat, j):
    return (compat >> (31 - j)) & 1


def profile_block(b, idc, compat, tier=0, space=0, flags4=(1, 0, 0, 1), c9=None, sub=False):
    """The 88 bits profile part of profile_tier_level(), laid out the way
    the dissector reads them (general or sub-layer)."""
    c9 = c9 if c9 is not None else (0, 1, 0, 0, 1, 0, 0, 0, 0)
    b.u(2, space).u(1, tier).u(5, idc).u(32, compat)
    for x in flags4:
        b.u(1, x)
    cmp_ = lambda *ks: idc in ks or any(cbit(compat, k) for k in ks)
    if cmp_(4, 5, 6, 7, 8, 9, 10):
        for x in c9:
            b.u(1, x)
        if sub:
            b.zeros(34)
        elif cmp_(5, 9, 10):
            b.u(1, 1).zeros(33)       # max_14bit_constraint_flag, reserved
        else:
            b.zeros(34)
    elif cmp_(2):
        b.zeros(7).u(1, 1).zeros(35)
    else:
        b.zeros(43)
    if cmp_(1, 2, 3, 4, 5, 9) and (idc in (1, 2, 3, 4, 5, 9) or True):
        b.u(1, 1)                     # inbld_flag
    else:
        b.u(1, 0)                     # reserved_zero_bit


def ptl(b, max_sub=0, idc=1, compat=None, tier=0, space=0, level=93, flags4=(1, 0, 0, 1),
        c9=None, subs=()):
    """profile_tier_level(1, max_sub). subs: list of (profile_present,
    level_present, idc, compat, level) for each of max_sub sub-layers."""
    if compat is None:
        compat = 1 << (31 - idc)
    profile_block(b, idc, compat, tier, space, flags4, c9)
    b.u(8, level)
    subs = list(subs) + [(0, 0, 0, 0, 0)] * (max_sub - len(subs))
    for s in subs[:max_sub]:
        b.u(1, s[0]).u(1, s[1])
    if max_sub > 0:
        for _ in range(max_sub, 8):
            b.u(2, 0)
    for s in subs[:max_sub]:
        if s[0]:
            profile_block(b, s[2], s[3], 0, 0, (1, 0, 0, 1), None, sub=True)
        if s[1]:
            b.u(8, s[4])
    return b


# --------------------------------------------------------- common parts

def scaling_list_data(b, pattern=0):
    for size in range(4):
        step = 3 if size == 3 else 1
        for m in range(0, 6, step):
            mode = (size + m + pattern) % 2
            b.u(1, mode)
            if not mode:
                b.ue(0 if size < 3 else 0)          # scaling_list_pred_matrix_id_delta
            else:
                if size > 1:
                    b.se(3 if m % 2 else -2)       # scaling_list_dc_coef_minus8
                for i in range(min(64, 1 << (4 + (size << 1)))):
                    b.se(((i * 7) % 5) - 2)


def st_rps(b, idx, spec, num_delta):
    """spec: ('abs', [(delta_minus1, used)...], [(delta_minus1, used)...]) or
    ('inter', sign, abs_delta_rps_minus1, [(used, use_delta)...])"""
    if idx != 0:
        b.f(spec[0] == 'inter')
    if spec[0] == 'inter':
        b.u(1, spec[1]).ue(spec[2])
        ref = idx - 1
        assert len(spec[3]) == num_delta[ref] + 1
        for used, use_delta in spec[3]:
            b.u(1, used)
            if not used:
                b.u(1, use_delta)
        num_delta[idx] = num_delta[ref]
    else:
        b.ue(len(spec[1])).ue(len(spec[2]))
        num_delta[idx] = len(spec[1]) + len(spec[2])
        for d, u in spec[1]:
            b.ue(d).u(1, u)
        for d, u in spec[2]:
            b.ue(d).u(1, u)


def hrd(b, common, max_sub, nal_=0, vcl=0, sub_pic=0, cpb=(0,), general=(0,), cvs=(1,)):
    """hrd_parameters(); per sub-layer variants chosen with cpb/general/cvs
    tuples (cycled).  The dissector reads low_delay_hrd_flag after
    fixed_pic_rate_general_flag = 1 (the standard has none there), so for
    general = 1 the stream carries it as the dissector expects."""
    if common:
        b.u(1, nal_).u(1, vcl)
        if nal_ or vcl:
            b.u(1, sub_pic)
            if sub_pic:
                b.u(8, 23).u(5, 7).u(1, 1).u(5, 9)
            b.u(4, 2).u(4, 3)
            if sub_pic:
                b.u(4, 5)
            b.u(5, 23).u(5, 23).u(5, 23)
    for i in range(max_sub + 1):
        g = general[i % len(general)]
        c = cvs[i % len(cvs)]
        n = cpb[i % len(cpb)]
        b.u(1, g)
        if not g:
            b.u(1, c)
        if c and not g:
            b.ue(3)                       # elemental_duration_in_tc_minus1
            low = 0
        else:
            low = i % 2
            b.u(1, low)
        if not low:
            b.ue(n)                       # cpb_cnt_minus1
        else:
            n = 0
        for present in (nal_, vcl):
            if present:
                for _ in range(n + 1):
                    b.ue(1000).ue(2000)
                    if sub_pic:
                        b.ue(300).ue(400)
                    b.u(1, 1)


# ------------------------------------------------------------------ VPS

def vps(vps_id=0, max_sub=0, order_present=1, max_layer_id=0, num_layer_sets_minus1=0,
        timing=None, ext_bits=None, ptl_kw=None, base_internal=1, base_avail=1, max_layers_minus1=0):
    """timing: None or dict(units, scale, poc=None|ue value, hrds=[dict])"""
    b = Bits()
    b.u(4, vps_id).u(1, base_internal).u(1, base_avail).u(6, max_layers_minus1)
    b.u(3, max_sub).u(1, 1).u(16, 0xffff)
    ptl(b, max_sub, **(ptl_kw or {}))
    b.u(1, order_present)
    for i in range(0 if order_present else max_sub, max_sub + 1):
        b.ue(4 + i).ue(2 + i).ue(i)
    b.u(6, max_layer_id).ue(num_layer_sets_minus1)
    for i in range(1, num_layer_sets_minus1 + 1):
        for j in range(max_layer_id + 1):
            b.u(1, (i + j) & 1)
    if timing:
        b.u(1, 1).u(32, timing['units']).u(32, timing['scale'])
        if timing.get('poc') is not None:
            b.u(1, 1).ue(timing['poc'])
        else:
            b.u(1, 0)
        hrds = timing.get('hrds', [])
        b.ue(len(hrds))
        for i, h in enumerate(hrds):
            idx = h.get('idx', i + 1)
            if i > 0:
                # the dissector restarts the HRD parameters at the byte
                # containing cprms_present_flag: choose hrd_layer_set_idx so
                # that this flag is the last bit of a byte
                idx = next((c for c in range(idx, idx + 64)
                            if (len(b.b) + (2 * (c + 1).bit_length() - 1) + 1) % 8 == 0), None)
                if idx is None:
                    raise ValueError('hrd %d: cannot align, bit length %d' % (i, len(b.b)))
            b.ue(idx)
            if i > 0:
                b.u(1, h['common'])
                hrd(b, h['common'], max_sub, h.get('nal', 0), h.get('vcl', 0), h.get('sub_pic', 0),
                    h.get('cpb', (0,)), h.get('general', (0,)), h.get('cvs', (1,)))
    else:
        b.u(1, 0)
    if ext_bits is None:
        b.u(1, 0)
    else:
        b.u(1, 1)
        for x in ext_bits:
            b.u(1, x)
    b.trailing()
    return b


# ------------------------------------------------------------------ SPS

def vui(b, o, max_sub):
    o = dict(o)
    ar = o.get('aspect')
    b.f(ar is not None)
    if ar is not None:
        b.u(8, ar)
        if ar == 255:
            b.u(16, 4).u(16, 3)
    ov = o.get('overscan')
    b.f(ov is not None)
    if ov is not None:
        b.u(1, ov)
    sig = o.get('signal')
    b.f(sig is not None)
    if sig is not None:
        b.u(3, sig[0]).u(1, sig[1]).f(sig[2])
        if sig[2]:
            b.u(8, 1).u(8, 1).u(8, 1)
    cl = o.get('chroma_loc')
    b.f(cl is not None)
    if cl is not None:
        b.ue(cl[0]).ue(cl[1])
    b.u(1, 0).u(1, 0).u(1, 0)         # neutral chroma, field_seq, frame_field_info
    dw = o.get('disp_win')
    b.f(dw is not None)
    if dw is not None:
        for x in dw:
            b.ue(x)
    tm = o.get('timing')
    b.f(tm is not None)
    if tm is not None:
        b.u(32, 1001).u(32, 60000)
        if tm.get('poc') is not None:
            b.u(1, 1).ue(tm['poc'])
        else:
            b.u(1, 0)
        h = tm.get('hrd')
        b.f(h is not None)
        if h is not None:
            hrd(b, 1, max_sub, **h)
            # the dissector ignores the length of the HRD parameters
            # (bug: return value dropped), so the following bits are read
            # from the start of the HRD structure
            return
    br = o.get('restriction')
    b.f(br is not None)
    if br is not None:
        b.u(1, 1).u(1, 0).u(1, 1)
        for x in br:
            b.ue(x)


def sps(sps_id=0, max_sub=0, ptl_kw=None, chroma=1, sep_plane=0, W=1280, H=720, conf_win=None,
        bd_l=0, bd_c=0, log2_poc=4, order_present=1, min_cb=0, diff_cb=3, min_tb=0, diff_tb=3,
        depth_inter=2, depth_intra=2, scaling=None, amp=1, sao=1, pcm=None, rps=(), lt=None,
        tmvp=1, strong=1, vui_opts=None, ext=None, vps_id=0, ext_tail=None):
    """ext: None or dict with range (tuple of 9 bits), ml (bool), d3 (bool),
    scc (dict), bits4 (int, with ext_tail = bits for sps_extension_data_flag)."""
    b = Bits()
    b.u(4, vps_id).u(3, max_sub).u(1, 1)
    ptl(b, max_sub, **(ptl_kw or {}))
    b.ue(sps_id).ue(chroma)
    if chroma == 3:
        b.u(1, sep_plane)
    b.ue(W).ue(H)
    b.f(conf_win)
    if conf_win:
        for x in conf_win:
            b.ue(x)
    b.ue(bd_l).ue(bd_c).ue(log2_poc)
    b.u(1, order_present)
    for i in range(0 if order_present else max_sub, max_sub + 1):
        b.ue(4 + i).ue(2 + i).ue(i)
    b.ue(min_cb).ue(diff_cb).ue(min_tb).ue(diff_tb).ue(depth_inter).ue(depth_intra)
    b.f(scaling is not None)
    if scaling is not None:
        b.f(scaling is not False)
        if scaling is not False:
            scaling_list_data(b, scaling)
    b.u(1, amp).u(1, sao)
    b.f(pcm)
    if pcm:
        b.u(4, pcm[0]).u(4, pcm[1]).ue(pcm[2]).ue(pcm[3]).u(1, pcm[4])
    b.ue(len(rps))
    nd = [0] * 65
    for i, s in enumerate(rps):
        st_rps(b, i, s, nd)
    b.f(lt is not None)
    if lt is not None:
        b.ue(len(lt))
        for lsb, used in lt:
            b.u(log2_poc + 4, lsb).u(1, used)
    b.u(1, tmvp).u(1, strong)
    b.f(vui_opts is not None)
    if vui_opts is not None:
        vui(b, vui_opts, max_sub)
    if ext is None:
        b.u(1, 0)
    else:
        b.u(1, 1)
        rng = ext.get('range')
        scc = ext.get('scc')
        b.f(rng).f(ext.get('ml')).f(ext.get('d3')).f(scc).u(4, ext.get('bits4', 0))
        if rng:
            for x in rng:
                b.u(1, x)
        if scc:
            b.u(1, scc.get('cpr', 0))
            pal = scc.get('palette')
            b.f(pal)
            if pal:
                b.ue(pal['max']).ue(pal['delta'])
                inits = pal.get('inits')
                b.f(inits is not None)
                if inits is not None:
                    b.ue(len(inits) - 1)
                    ncomp = 1 if chroma == 0 else 3
                    for c in range(ncomp):
                        for v in inits:
                            b.u(8 + (bd_l if c == 0 else bd_c), v)
            b.u(2, scc.get('mvres', 0)).u(1, scc.get('ibf', 0))
        if ext.get('bits4'):
            for x in (ext_tail or ()):
                b.u(1, x)
        # multilayer and 3D extension: the dissector does not decode them
        # (and does not skip them), so their bytes go last
        if ext.get('ml'):
            b.u(8, 0xA5)
        if ext.get('d3'):
            b.u(8, 0x5A)
    b.trailing()
    return b


# ------------------------------------------------------------------ PPS

def pps(pps_id=0, sps_id=0, dep=1, outflag=0, extra=2, sign=0, cabac=0, l0=0, l1=0, init_qp=0,
        constrained=0, tskip=0, cuqpd=None, cb=0, cr=0, slice_chroma=0, wp=0, wbp=0, tqb=0,
        tiles=None, entropy=0, lf_slices=1, deblock=None, scaling=None, lists_mod=0, merge=0,
        sh_ext=0, ext=None, ext_tail=None, extra_tail=b''):
    """tiles: None or dict(cols, rows, uniform, widths, heights, lf).
    deblock: None or (override, disabled, beta, tc). ext: dict(range, scc,
    ml, d3, bits4)."""
    b = Bits()
    b.ue(pps_id).ue(sps_id).u(1, dep).u(1, outflag).u(3, extra).u(1, sign).u(1, cabac)
    b.ue(l0).ue(l1).se(init_qp).u(1, constrained).u(1, tskip)
    b.f(cuqpd is not None)
    if cuqpd is not None:
        b.ue(cuqpd)
    b.se(cb).se(cr).u(1, slice_chroma).u(1, wp).u(1, wbp).u(1, tqb)
    b.f(tiles)
    b.u(1, entropy)
    if tiles:
        b.ue(tiles['cols'] - 1).ue(tiles['rows'] - 1).u(1, tiles['uniform'])
        if not tiles['uniform']:
            for w in tiles['widths']:
                b.ue(w)
            for h in tiles['heights']:
                b.ue(h)
        b.u(1, tiles.get('lf', 1))
    b.u(1, lf_slices)
    b.f(deblock)
    if deblock:
        b.u(1, deblock[0]).u(1, deblock[1])
        if not deblock[1]:
            b.se(deblock[2]).se(deblock[3])
    b.f(scaling is not None)
    if scaling is not None:
        scaling_list_data(b, scaling)
    b.u(1, lists_mod).ue(merge).u(1, sh_ext)
    if ext is None:
        b.u(1, 0)
    else:
        b.u(1, 1)
        rng = ext.get('range')
        scc = ext.get('scc')
        # The dissector reads pps_extension_4bits as ONE bit (packet-h265.c:1560),
        # so this encoder writes one bit: the extension that follows is then
        # decoded from the right position.
        b.f(rng).f(ext.get('ml')).f(ext.get('d3')).f(scc).u(1, 1 if ext.get('bits4') else 0)
        if rng:
            if tskip:
                b.ue(rng.get('ts', 1))
            b.u(1, rng.get('ccp', 1))
            q = rng.get('qp')
            b.f(q)
            if q:
                b.ue(1).ue(len(q) - 1)
                for x, y in q:
                    b.se(x).se(y)
            b.ue(1).ue(2)
        if scc:
            b.u(1, scc.get('cpr', 0))
            act = scc.get('act')
            b.f(act)
            if act:
                b.u(1, 1).se(act[0]).se(act[1]).se(act[2])
            inits = scc.get('inits')
            b.f(inits is not None)
            if inits is not None:
                b.ue(len(inits))
                if len(inits):
                    mono = scc.get('mono', 0)
                    b.u(1, mono).ue(scc.get('luma8', 0))
                    if not mono:
                        b.ue(scc.get('chroma8', 0))
                    for c in range(1 if mono else 3):
                        for v in inits:
                            b.u(8 + (scc.get('luma8', 0) if c == 0 else scc.get('chroma8', 0)), v)
        if ext.get('bits4'):
            for x in (ext_tail or ()):
                b.u(1, x)
        if ext.get('ml'):
            b.u(8, 0xA5)
        if ext.get('d3'):
            b.u(8, 0x5A)
    b.trailing()
    for x in extra_tail:
        b.u(8, x)
    return b


# --------------------------------------------------------- other NAL units

def slice_hdr(t, first=1, pps_id=0, dep=0, addr=0, nbits=8, extra=2, stype=2, no_out=0, dep_enabled=1,
              tail=b'\x5a\xa5'):
    b = Bits()
    b.u(1, first)
    if 16 <= t <= 23:
        b.u(1, no_out)
    b.ue(pps_id)
    if not first:
        if dep_enabled:
            b.u(1, dep)
        if nbits:
            b.u(nbits, addr)
    if not dep:
        for _ in range(extra):
            b.u(1, 1)
        b.ue(stype)
    b.pad()
    return nal_hdr(t) + escape(b.bytes() + tail)


def aud(pic_type=1):
    b = Bits()
    b.u(3, pic_type).trailing()
    return b


def sei(msgs):
    """msgs: list of (payloadType, payload bytes)."""
    out = bytearray()
    for t, p in msgs:
        x = t
        while x >= 255:
            out.append(255)
            x -= 255
        out.append(x)
        x = len(p)
        while x >= 255:
            out.append(255)
            x -= 255
        out.append(x)
        out += p
    out.append(0x80)
    return bytes(out)


# ---------------------------------------------------------- capture files

def csum(h):
    if len(h) % 2:
        h += b'\0'
    s = sum(struct.unpack('!%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def udp_frame(src, dst, sport, dport, payload, ident=[0]):
    ident[0] += 1
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ident[0], 0, 64, 17, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes([2, 0]) + ip4(dst) + bytes([2, 0]) + ip4(src) + b'\x08\x00' + ip + udp


def tag(t, v):
    pad = (4 - len(v) % 4) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def epdu(name, payload):
    return tag(12, name.encode()) + struct.pack('>HH', 0, 0) + payload


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is Ethernet,
    interface 1 Exported PDU."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 262144))
    out += block(1, struct.pack('<HHI', 252, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def vps_auto(**kw):
    """vps(), changing the number of layer sets until the HRD parameters
    can be byte aligned (see vps())."""
    kw.setdefault('num_layer_sets_minus1', 0)
    for extra in range(0, 4):
        k = dict(kw)
        k['num_layer_sets_minus1'] += extra
        try:
            return vps(**k)
        except ValueError:
            pass
    raise ValueError('vps_auto failed')
