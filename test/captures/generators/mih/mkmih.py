#!/usr/bin/env python3
# Generates test/captures/mih_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MIH (IEEE 802.21) coverage captures. Usage: mkmih.py <outdir> [-v]
Everything is synthetic; addresses are from 192.0.2.0/24 and 02:00:00:00:00:xx."""
import struct
import sys
import os

# ---- capture helpers -------------------------------------------------
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(payload, ethertype=0x0800, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', ethertype) + payload

def ipv4(payload, proto=17, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def tcp(payload, sport, dport, seq, ack, flags):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload

def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---- MIH building blocks --------------------------------------------
def tlv(t, v):
    n = len(v)
    if n <= 128:
        return bytes([t, n]) + v
    # more than 128 octets: 0x80+k, then k octets holding n-128
    return bytes([t, 0x81, n - 128]) + v

def tlv_ext(t, v, k):
    """TLV with a length of 128+len(v)-128 spread over k octets (k = 1..8); the
    value is padded with zeros to 128+value."""
    n = len(v)
    assert n >= 128
    return bytes([t, 0x80 + k]) + (n - 128).to_bytes(k, 'big') + v

def mih(service, opcode, aid, tlvs, flags=0x2, ver=1, frag=0, more=0, tid=0x123):
    payload = b''.join(tlvs)
    b0 = (ver << 4) | flags | more
    mid = (service << 12) | (opcode << 10) | aid
    return struct.pack('>BBHHH', b0, frag << 1, mid, tid, len(payload)) + payload

PAD = tlv(100, bytes(48))      # so that the lists never read past the frame

def la_mac(mac=b'\x02\x00\x00\x00\x00\x07', ttype=6):
    return bytes([0]) + struct.pack('>H', ttype) + bytes([6]) + mac
def la_3g(): return bytes([1]) + b'\x13\x00\x14' + struct.pack('>I', 0x01020304)
def la_2g(): return bytes([2]) + b'\x13\x00\x14' + struct.pack('>HH', 0x0101, 0x0202)
def la_str(c, s=b'+15551234'): return bytes([c, len(s)]) + s
def la_other(): return bytes([6])
def link_id(lt=19, la=None): return bytes([lt]) + (la or la_mac())
def lst(items): return bytes([len(items)]) + b''.join(items)
def qos_val(c=1, v=0x0102): return struct.pack('>BH', c, v)
def qos_list(n=2):
    ql = lst([qos_val(1, 10), qos_val(2, 20)][:n])
    return bytes([n]) + ql * 5
def ip4(): return b'\x00\x01\x0a\x04\x00\x01\x00'
def ip6(): return b'\x00\x02\x20\x10' + bytes(14) + b'\x01'
def ipother(): return b'\x00\x09\x00\x02\xaa\xbb'
def netstr(s): return bytes([len(s)]) + s
def sig(per=False, v=0xd8): return bytes([1 if per else 0, v])

def net_type(lt=19, subtype=True, ext=b'ext1', has_type=True):
    b = (bytes([0, lt]) if has_type else bytes([1]))
    if subtype:
        b += bytes([0]) + struct.pack('>II', 0xe0000000, 0)
    else:
        b += bytes([1])
    if ext is not None:
        b += bytes([0, len(ext)]) + ext
    else:
        b += bytes([1])
    return b

def param_type(t, v): return bytes([t, v])
def link_param(t=0, v=1, val=0x0155, qos=None):
    b = param_type(t, v)
    if qos is None:
        return b + bytes([0]) + struct.pack('>H', val)
    sub, data = qos
    return b + bytes([1, sub]) + data
def link_param_rpt(thr=False, **kw):
    b = link_param(**kw)
    return b + (b'\x01\x00\x20\x01' if thr else b'\x00')
def link_det_info(flag_la=True):
    b = link_id(19, la_mac())
    b += (b'\x01' + la_3g()) if flag_la else b'\x00'
    b += netstr(b'netA') + netstr(b'auxA') + sig(True, 77)
    b += struct.pack('>HI', 0x0102, 54000000) + b'\x05' + struct.pack('>I', 0xff000000)
    return b
def link_det_info2():
    b = link_id(19, la_mac()) + b'\x00' + netstr(b'netB') + netstr(b'auxB') + sig(False, 0xc8)
    b += struct.pack('>HI', 0x0102, 100) + b'\x01' + struct.pack('>I', 0x01000000)
    return b
def link_scan(per):
    return la_mac() + netstr(b'ssid') + sig(per, 0x30)
def link_action_req(la=True, atype=2):
    b = link_id(19, la_mac())
    b += (b'\x01' + la_3g()) if la else b'\x00'
    return b + bytes([atype, 0x80 | 0x40 | 0x20]) + struct.pack('>H', 500)
def link_action_rsp(scan=True, res=0):
    b = link_id(19, la_mac()) + bytes([res])
    if scan:
        return b + b'\x01' + lst([link_scan(False), link_scan(True)])
    return b + b'\x00'
def link_poa(): return link_id(19, la_mac()) + lst([la_mac(), la_2g(), la_str(3), la_str(4), la_str(5), la_other()])
def rq_result(opts):
    f = [b'\x00'] * 4
    for i, o in opts.items(): f[i] = o
    return link_poa() + qos_list(1) + f[0] + f[1] + f[2] + f[3] + b'\x00'
def tgt_net(kind):
    if kind == 'id_aux': return b'\x00' + netstr(b'netC') + b'\x00' + b'\x00' + netstr(b'auxC')
    if kind == 'id': return b'\x00' + netstr(b'netD') + b'\x00' + b'\x01\x00'
    if kind == 'la': return b'\x01' + la_mac()
def tsp(k):
    if k == 1: return b'\x01\x05'
    if k == 2: return b'\x02' + netstr(b'carrier')
    return b'\x03'
def rdf(mime):
    return (b'\x01' + netstr(b'text/xml') if mime else b'\x00') + netstr(b'<rdf/>')
def evt_cfg_info():
    d1 = b'\x01' + netstr(b'cfgnet') + b'\x01\x00\x28' + b'\x01\x00\x00\x03\xe8'   # id, signal dBm, data rate
    d2 = b'\x00' + b'\x01\x01\x50' + b'\x01\x00\x00\x03\xe8'
    d3 = b'\x00' + b'\x00' + b'\x00'
    c1 = param_type(0, 1) + b'\x00' + b'\x01\x00\x20\x01'                       # no interval
    c2 = param_type(0, 2) + b'\x01\x2c\x00' + b'\x02\x00\x20\x00'               # interval 300
    return lst([lst([d1, d2, d3]) + lst([c1, c2])])

def mihf_nai(vals):
    return b''.join(b'\\' + bytes([b]) for b in vals)
def mihf(t, s): return tlv(t, netstr(s))
SRC = lambda s=b'mihf1@example.org': mihf(1, s)
DST = lambda s=b'mihf2@example.org': mihf(2, s)

frames = []        # (frame bytes, label)
ranges = []
def add(label, fr):
    frames.append(fr)
def L2(m, src=1): return eth(m, 0x8917, src, 3 - src)
def UDP(m, sp=4551, dp=4551): return eth(ipv4(udp(m, sp, dp)))
def mark(name): ranges.append((name, len(frames) + 1))

def build():
    # ---- 1: header variants ----------------------------------------------
    mark('header variants')
    for svc in (1, 2, 3, 4):
        for op in range(4):
            aids = {1: (1, 2, 3, 4, 5, 9), 2: (1, 2, 3, 5, 6, 7, 8, 9), 3: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13), 4: (1, 2, 3)}[svc]
            aid = aids[op % len(aids)] if svc != 3 else aids[(op * 3) % len(aids)]
            add('hdr', L2(mih(svc, op, aid, [SRC(), DST(), PAD])))
    # every action id once (the remaining ones)
    for svc, aids in {1: (1, 2, 3, 4, 5, 9), 2: (1, 2, 3, 5, 6, 7, 8, 9), 3: tuple(range(1, 14)), 4: (1, 2, 3)}.items():
        for aid in aids:
            add('aid', L2(mih(svc, 1, aid, [SRC(), PAD])))
    # unknown service ids, no action id decoded
    add('svc0', L2(mih(0, 0, 0, [SRC(), PAD])))
    add('svc5', L2(mih(5, 1, 1, [SRC(), PAD])))
    # flags: ack request, ack response, UIR, version 0 and 2, empty payload
    for fl in (0x8, 0x4, 0x2, 0xe, 0x0):
        add('flags', L2(mih(1, 1, 1, [SRC(), PAD], flags=fl)))
    add('ver0', L2(mih(1, 1, 1, [SRC(), PAD], ver=0)))
    add('ver2', L2(mih(1, 1, 1, [SRC(), PAD], ver=2)))
    add('empty', L2(mih(1, 0, 1, [])))
    # fragmented messages: more fragments, a fragment number, both; TLVs not dissected
    add('more', L2(mih(1, 1, 1, [SRC(), PAD], more=1)))
    add('fragno', L2(mih(1, 1, 1, [SRC(), PAD], frag=3)))
    add('both', L2(mih(1, 1, 1, [SRC(), PAD], frag=2, more=1)))
    # a TLV longer than the payload length is a fragmented TLV
    m = mih(1, 1, 1, [SRC()])
    add('fragtlv', L2(m[:6] + struct.pack('>H', 10) + m[8:] + b'\x00' * 12))
    # TLV length encodings
    mark('TLV length encodings')
    add('len128', L2(mih(1, 1, 1, [tlv(100, bytes(128)), PAD])))
    for k in range(1, 9):
        add('lenext%d' % k, L2(mih(1, 1, 1, [tlv_ext(100, bytes(130 + k), k), PAD])))
    add('len300', L2(mih(1, 1, 1, [tlv(100, bytes(300)), PAD])))

    # ---- transports -----------------------------------------------------
    mark('transports')
    m = mih(1, 1, 1, [SRC(), DST(), PAD])
    add('udp', UDP(m))
    add('udp2', UDP(m, 40000, 4551))
    add('udp3', UDP(m, 4551, 40000))
    sip, dip = '192.0.2.1', '192.0.2.2'
    iss, irs = 1000, 5000
    tc = lambda p, fl, s, a, sp=40001, dp=4551, sa=sip, da=dip: eth(ipv4(tcp(p, sp, dp, s, a, fl), 6, sa, da))
    add('syn', tc(b'', 0x02, iss, 0))
    add('synack', eth(ipv4(tcp(b'', 4551, 40001, irs, iss + 1, 0x12), 6, dip, sip), 0x0800, 2, 1))
    add('ack', tc(b'', 0x10, iss + 1, irs + 1))
    add('tcpdata', tc(m, 0x18, iss + 1, irs + 1))
    add('tcpdata2', eth(ipv4(tcp(m, 4551, 40001, irs + 1, iss + 1 + len(m), 0x18), 6, dip, sip), 0x0800, 2, 1))

    # ---- TLVs -----------------------------------------------------------
    mark('MIHF IDs')
    nai_mac = netstr(mihf_nai([2, 0, 0, 0, 0, 0x11]))
    nai_v4 = netstr(mihf_nai([10, 0, 0, 1]))
    nai_v6 = netstr(mihf_nai([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
    nai_odd = netstr(mihf_nai([1, 2, 3, 4, 5]))
    for t in (1, 2, 52):
        add('mihf', L2(mih(1, 1, 1, [tlv(t, nai_mac), tlv(t, nai_v4), tlv(t, nai_v6), tlv(t, nai_odd), tlv(t, netstr(b'plain')), PAD])))
    # reproducer of the composite tvb leak: ID starting with a backslash whose
    # length would run past the end of the TLV is skipped (no malformed packet)
    add('leakfix', L2(mih(1, 1, 1, [SRC(), tlv(1, netstr(b'\\\x02\\\x00')), PAD])))
    # the original reproducer frames (5 good + a truncated one are in the malformed capture)
    add('mihf-good', L2(mih(1, 1, 1, [tlv(1, nai_mac)]), 1))

    mark('simple TLVs')
    simple = [tlv(3, b'\x00'), tlv(3, b'\x02'), tlv(4, b'\x13'), tlv(5, struct.pack('>I', 0xff000000)),
              tlv(6, struct.pack('>I', 0x7c000000)), tlv(7, struct.pack('>II', 0xffffffff, 0xffffffff)),
              tlv(8, b'\xc0\x00\x00\x00'), tlv(11, b'\x01'), tlv(12, struct.pack('>I', 3600)),
              tlv(17, b'\x01'), tlv(18, b'\x7f\x00\x00\x00'), tlv(19, b'\xfe\x00\x00\x00'), tlv(20, b'\x04'),
              tlv(21, struct.pack('>H', 1000)), tlv(22, b'\x03'), tlv(24, b'\x03'),
              tlv(34, b'\x01'), tlv(40, b'\x01'), tlv(41, b'\x01'), tlv(42, b'\x01'), tlv(45, b'\x01'),
              tlv(53, b'\x01'), tlv(61, b'\x01'), tlv(47, struct.pack('>H', 1500))]
    for i in range(0, len(simple), 6):
        add('simple', L2(mih(3, 1, 1, simple[i:i + 6] + [PAD])))
    for v in (0, 1, 2, 3, 4, 5):
        add('dnreason', L2(mih(2, 3, 3, [tlv(20, bytes([v])), tlv(22, bytes([v])), PAD])))
    for v in range(0, 28):
        add('linktype', L2(mih(2, 3, 2, [tlv(4, bytes([v])), PAD])))
    add('flags0', L2(mih(1, 1, 1, [tlv(11, b'\x00'), tlv(17, b'\x00'), tlv(34, b'\x00'), tlv(42, b'\x00'), tlv(3, b'\x01'), tlv(3, b'\x03'), tlv(3, b'\x04'), PAD])))
    add('bin', L2(mih(4, 1, 1, [tlv(43, b'binary\x00data'), tlv(48, b'resp\x00bin'), tlv(100, b'vendor'), PAD])))
    add('reserved', L2(mih(4, 1, 1, [tlv(64, b'resv'), tlv(65, b'resv'), tlv(99, b'resv'), tlv(101, b'exp'), tlv(150, b'exp'), tlv(254, b'exp'), tlv(255, b'unk'), tlv(0, b'unk'), PAD])))
    add('bits', L2(mih(1, 1, 1, [tlv(5, struct.pack('>I', 0x00000000)), tlv(6, struct.pack('>I', 0)), tlv(7, struct.pack('>II', 0, 0)), tlv(8, b'\x00\x00\x00\x00'), tlv(18, bytes(4)), tlv(19, bytes(4)), tlv(24, b'\x00'), PAD])))

    mark('link identifiers and addresses')
    las = [la_mac(), la_mac(ttype=1), la_3g(), la_2g(), la_str(3), la_str(4), la_str(5), la_other()]
    for t in (13, 14, 59):
        add('linkid', L2(mih(2, 3, 2, [tlv(t, link_id(19, la_mac())), PAD])))
    for i, la in enumerate(las):
        add('linkid%d' % i, L2(mih(2, 3, 2, [tlv(13, link_id(19, la)), tlv(15, la), tlv(16, la), tlv(60, la), PAD])))
    e = b'e'
    add('linkaddrlist', L2(mih(1, 1, 1, [tlv(9, lst([net_type(19, True, b'ext1') + la_mac(), net_type(15, True, e) + la_3g(), net_type(18, True, e) + la_2g(),
                                                    net_type(23, True, e) + la_str(3), net_type(24, True, e) + la_str(4), net_type(27, True, e) + la_str(5),
                                                    net_type(6, True, e) + la_other(), net_type(0, False, e, has_type=False) + la_mac(), net_type(19, False, None) + la_mac()])), PAD])))
    add('mbb', L2(mih(1, 1, 1, [tlv(10, lst([net_type(19, False, e) + net_type(15, False, e) + b'\x00', net_type(19, False, e) + net_type(19, True, None) + b'\x01'])), PAD])))
    add('nettype', L2(mih(4, 1, 1, [tlv(62, net_type(19, True, b'ext')), PAD])))
    add('linkidlist', L2(mih(3, 1, 1, [tlv(25, lst([link_id(19, la_mac()), link_id(23, la_3g())])), PAD])))
    add('poalist', L2(mih(3, 1, 1, [tlv(31, lst([link_poa(), link_poa()])), PAD])))
    add('ipaddr', L2(mih(3, 1, 1, [tlv(35, ip4()), tlv(36, ip6()), tlv(37, ipother()), PAD])))

    mark('parameters and thresholds')
    for t in range(0, 12):
        add('ptype', L2(mih(3, 1, 1, [tlv(23, lst([link_param_rpt(False, t=t, v=1 + (t % 3), val=0x1234), link_param_rpt(True, t=t, v=2, val=7)])), PAD])))
    qv = lst([qos_val(1, 2), qos_val(2, 3)])
    qos_cases = [(0, b'\x03' + b'\x00'), (1, qv), (2, qv), (3, qv), (4, qv), (5, qv)]
    for q in qos_cases:
        add('qosparam', L2(mih(3, 1, 1, [tlv(23, lst([link_param_rpt(False, t=1, v=1, qos=q), link_param_rpt(True, t=1, v=2, qos=q)])), PAD])))
    add('cfgreq', L2(mih(3, 1, 2, [tlv(29, lst([param_type(0, 1) + b'\x00' + b'\x01\x00\x20\x01', param_type(5, 2) + b'\x01\x2c\x00' + b'\x02\x00\x20\x00'])), PAD])))
    add('cfgrsp', L2(mih(3, 2, 2, [tlv(30, lst([param_type(0, 1) + struct.pack('>HBB', 30, 1, 0), param_type(5, 3) + struct.pack('>HBB', 31, 0, 1)])), PAD])))
    add('statusreq0', L2(mih(3, 1, 1, [tlv(27, b'\x00\x00\x01' + lst([param_type(0, 1), param_type(2, 2)]) + b'\x00\x00\x04'), PAD])))
    add('statusreq1', L2(mih(3, 1, 1, [tlv(27, b'\x01\x00\x00\x24' + lst([param_type(4, 3)]) + b'\x01\x00\x02'), PAD])))
    s1 = link_id(19, la_mac()) + lst([b'\x00\x03', b'\x01\x00\x24']) + lst([link_param(0, 1, 5), link_param(1, 1, qos=(1, qv))]) + lst([b'\x00\x04', b'\x01\x02'])
    add('statusrsp', L2(mih(3, 2, 1, [tlv(28, lst([s1, s1])), PAD])))
    add('devstates', L2(mih(3, 2, 1, [tlv(26, lst([b'\x01\x64', b'\x00' + netstr(b'devinfo')])), PAD])))
    add('evtcfg', L2(mih(1, 1, 4, [tlv(54, evt_cfg_info()), PAD])))

    mark('handover and resources')
    add('linkdet', L2(mih(2, 3, 1, [tlv(58, lst([link_det_info(True), link_det_info2()])), PAD])))
    add('actions', L2(mih(3, 1, 3, [tlv(38, lst([link_action_req(True), link_action_req(False, 3)])), PAD])))
    add('actionrsp', L2(mih(3, 2, 3, [tlv(39, lst([link_action_rsp(True), link_action_rsp(False, 1)])), PAD])))
    ipm = {0: b'\x01\x7f', 1: b'\x01\x7f', 2: b'\x01\x7f'}
    add('prefA', L2(mih(3, 2, 5, [tlv(32, lst([rq_result({0: b'\x01\x20', 1: b'\x01\x03', 2: b'\x01\x01', 3: b'\x01\x01'})])), PAD])))
    add('prefB', L2(mih(3, 2, 5, [tlv(32, lst([rq_result({0: b'\x02\x01\x80', 1: b'\x02' + ip4(), 2: b'\x02' + ip6(), 3: b'\x02' + ip4()})])), PAD])))
    add('hoquery', L2(mih(3, 1, 4, [tlv(33, qos_list(2)), PAD])))
    for kind in ('id_aux', 'id', 'la'):
        add('tgt_' + kind, L2(mih(3, 1, 7, [tlv(55, tgt_net(kind)), PAD])))
    add('tgtlist', L2(mih(3, 1, 7, [tlv(56, lst([tgt_net('la')])), PAD])))
    for k in (1, 2, 3):
        add('asgn%d' % k, L2(mih(3, 1, 9, [tlv(57, qos_list(1) + tsp(k)), tlv(63, qos_list(1) + tsp(k) + b'\x02'), PAD])))

    mark('information service')
    add('rdf', L2(mih(4, 1, 1, [tlv(44, lst([rdf(True), rdf(False)])), tlv(49, lst([rdf(True)])), tlv(51, lst([rdf(False)])), PAD])))
    add('schm', L2(mih(4, 1, 1, [tlv(46, b'\x01\x01a'), tlv(50, b'\x01\x01b'), tlv(46, b'\x00'), tlv(50, b'\x00'), PAD])))

build()

def build_malformed():
    out = []
    nai = mihf_nai([2, 0, 0, 0, 0, 0x11])
    tl = tlv(1, netstr(nai))
    # the composite tvb reproducer: a padding TLV first, then a NAI-encoded ID cut after the first backslash
    f = L2(mih(1, 1, 1, [tl]))
    out.append(f)
    pad = tlv(0xFF, bytes(20))
    for i in range(5):
        f = L2(mih(1, 1, 1, [pad, tl]))[:14 + 8 + 22 + 2 + 2]
        out.append(f)
    out.append(L2(mih(1, 1, 1, [SRC(), PAD]))[:14 + 5])                  # cut inside the header
    out.append(L2(mih(1, 1, 1, [SRC(), PAD]))[:14 + 10])                 # cut in a TLV header
    out.append(L2(mih(3, 1, 1, [tlv(25, b'\xc8' + bytes(4))])))           # list of 200 link ids runs off the frame
    out.append(L2(mih(3, 1, 1, [tlv(35, b'\x00\x01\x0a\x00\x00')])))      # IPv4 address with length 0
    out.append(L2(mih(3, 1, 1, [tlv(35, b'\x00\x02\x0a\x05\x00\x00')])))   # IPv6 address with length 5
    out.append(L2(mih(3, 1, 1, [tlv(13, link_id(19, la_str(3, b'abc'))[:-6])])))  # link address string past the end
    out.append(L2(mih(1, 1, 1, [bytes([100, 0x84, 0, 0, 0, 5]) + bytes(133)])[:-60]))  # length extension, value cut
    out.append(L2(mih(1, 1, 1, [bytes([100, 0x88]) + bytes(8)])))        # 64 bit length, huge value -> fragmented TLV
    out.append(L2(mih(1, 1, 1, [bytes([100, 0x88]) + b'\x00\x00\x00\x01' + bytes(4) + bytes(10)])))   # 4 GiB length
    out.append(L2(mih(1, 1, 1, [tlv(5, b'\xff')])))                      # bitmask cut short
    out.append(L2(mih(3, 1, 1, [tlv(46, b'\xff\x01a')])))                # RDF schema loop that never ends
    out.append(L2(mih(3, 1, 1, [tlv(23, lst([link_param_rpt(False, t=1, v=1, qos=(1, b'\xff'))]))])))
    return out

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'mih-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'mih-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        for n, s in ranges: print(n, s)
        print(len(frames), 'frames')
