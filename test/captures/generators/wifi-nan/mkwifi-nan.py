#!/usr/bin/env python3
# Generates test/captures/wifi-nan_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Wi-Fi NAN coverage captures: usage mkwifi-nan.py <outdir> [-v]
# NAN attributes travel in the WFA vendor IE (subtype 19) of beacons, in
# Service Discovery frames (public action, WFA subtype 19) and in NAN action
# frames (public action, WFA subtype 24). Keys, nonces, tags and cipher
# material are opaque made-up bytes.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlanlib import A1, A2, BCAST, beacon, MS, NANB, Pcap, public_action_vendor, WFA, wfa_ie

NAN_A = bytes.fromhex('02cc00000001')
NAN_B = bytes.fromhex('02cc00000002')
CLUSTER = bytes.fromhex('506f9a010a0b')

def pat(n, b=0x10):
    return bytes((b + i) & 0xff for i in range(n))

def A(i, data):
    return bytes([i]) + struct.pack('<H', len(data)) + data

def ie(*attrs): return wfa_ie(0x13, b''.join(attrs))
def nan_beacon(*attrs, bi=100, sync=False):
    return beacon(ie(*attrs), interval=512 if sync else bi, capab=0x0420, a1=BCAST, a2=NAN_A, a3=CLUSTER)
def sdf(*attrs, a2=NAN_A, a1=NANB):
    return public_action_vendor(0x13, b''.join(attrs), a1=a1, a2=a2, a3=CLUSTER)
def act(sub, *attrs, a2=NAN_A, a1=NAN_B):
    return public_action_vendor(0x18, bytes([sub]) + b''.join(attrs), a1=a1, a2=a2, a3=CLUSTER)

# ---- attributes ----
def master(pref=1, rnd=2): return A(0x00, bytes([pref, rnd]))
def cluster(rank=0x0102030405060708, hop=2, tx=0x11223344): return A(0x01, struct.pack('>QB', rank, hop) + struct.pack('<I', tx))
def svc_ids(n=1, t=0x02): return A(t, b''.join(pat(6, 0x20 + i) for i in range(n)))
SID = bytes.fromhex('6f2fa8b4d0e1')
def sda(typ=0, inst=1, req=2, bindmap=None, mf=None, srf=None, info=None, flags=0):
    # service control: type (bits 0-1), matching filter 0x04, SRF 0x08, service info 0x10, binding bitmap 0x40
    ctrl = typ | flags | (0x04 if mf is not None else 0) | (0x08 if srf is not None else 0) | \
        (0x10 if info is not None else 0) | (0x40 if bindmap is not None else 0)
    d = SID + bytes([inst, req, ctrl])
    if bindmap is not None: d += struct.pack('<H', bindmap)
    if mf is not None:
        d += bytes([sum(len(x) + 1 for x in mf)]) + b''.join(bytes([len(x)]) + x for x in mf)
    if srf is not None: d += bytes([len(srf)]) + srf      # srf = control octet + address set
    if info is not None: d += bytes([len(info)]) + info
    return A(0x03, d)
def sdea(inst=1, ctrl=0, rl=None, sui=None, svcinfo=None):
    d = bytes([inst]) + struct.pack('<H', ctrl)
    if rl is not None: d += struct.pack('<HH', *rl)
    if sui is not None: d += bytes([sui])
    if svcinfo is not None:
        oui, ptype, spec = svcinfo
        d += struct.pack('<H', 4 + len(spec)) + oui + bytes([ptype]) + spec
    return A(0x0e, d)
def conncap(v=0x3f): return A(0x04, struct.pack('<H', v))
def mapctl(mapid=1, dur=0, rep=0): return bytes([mapid | (dur << 4) | (rep << 6)])
def wlan_infra(bm=b'\x01\x02', role=1): return A(0x05, BCAST + A1 + mapctl() + bm + bytes([role]))
def p2p_op(bm=b'\x01\x02', role=0x07): return A(0x06, bytes([role]) + A1 + mapctl() + bm)
def ibss(bm=b'\x01\x02'): return A(0x07, BCAST + A1 + mapctl() + bm)
def mesh(ctl=0x00, bm=b'\x01\x02\x03\x04', meshid=b'mesh-net'): return A(0x08, A1 + bytes([ctl]) + bm + meshid)
def further_sd(bm=b'\x01\x02\x03'): return A(0x09, mapctl() + bm)
def further_av(i=1, ctl=0x20, oc=81, ch=6, bm=b'\x01\x02'): return A(0x0a, bytes([i, ctl, oc, ch]) + bm)
def country(c=b'XX'): return A(0x0b, c)
def ranging(bm=b'\x01\x02', proto=0): return A(0x0c, A1 + mapctl() + bytes([proto]) + bm)
def cluster_disc(): return A(0x0d, CLUSTER + struct.pack('<QQ', 12345, 0x0102030405060708))
def devcap(v=0): return A(0x0f, bytes([0x11, 0x5a, 0x01, 0x3b, 0xff, 0x33, 0x22, 0x44 + v, 0x1f]))
def ndp(ts, ctrl, token=1, reason=0, pubid=None, rndi=None, info=None):
    d = bytes([token, ts, reason]) + A2 + bytes([7, ctrl])
    if pubid is not None: d += bytes([pubid])
    if rndi is not None: d += rndi
    if info is not None: d += info
    return A(0x10, d)
def ndpe(ts, ctrl, tlvs=b'', token=1, reason=0, pubid=None, rndi=None):
    d = bytes([token, ts, reason]) + A2 + bytes([7, ctrl])
    if pubid is not None: d += bytes([pubid])
    if rndi is not None: d += rndi
    return A(0x29, d + tlvs)
def ndpe_tlv(t, data): return bytes([t]) + struct.pack('<H', len(data)) + data
def tb(ctl=0x0021, bm=b'\xff\x0f'): return struct.pack('<H', ctl) + bytes([len(bm)]) + bm
def avail(seq=1, ctl=0x0301, *entries): return A(0x12, bytes([seq]) + struct.pack('<H', ctl) + b''.join(entries))
def avhdr(etype, noncontig, n): return etype | (noncontig << 1) | (n << 4)     # LSB-first bit fields
def av_entry(typ, tbm=None, hdr=0x01, ents=b'', ctl=0):
    d = struct.pack('<H', typ | ctl | (0x1000 if tbm else 0)) + (tb(*tbm) if tbm else b'') + bytes([hdr]) + ents
    return struct.pack('<H', len(d)) + d
def ndc(entries=None): return A(0x13, A1 + b'\x01' + b''.join(entries if entries is not None else [bytes([1]) + tb()]))
def ndl(ts, ctrl, token=1, reason=0, peer=None, idle=None, sched=None):
    d = bytes([token, ts, reason, ctrl])
    if peer is not None: d += bytes([peer])
    if idle is not None: d += struct.pack('<H', idle)
    if sched: d += b''.join(bytes([m]) + tb(*t) for m, t in sched)
    return A(0x14, d)
def ndlqos(): return A(0x15, bytes([3]) + struct.pack('<H', 512))
def unaligned(ulwctl=None, tail=b''):
    d = struct.pack('<H', 0x0102) + struct.pack('<III', 1000, 200, 5000) + bytes([3, 0x12])
    if ulwctl is not None: d += bytes([ulwctl]) + tail
    return A(0x17, d)
def ranging_info(v=0x08, mov=0x1234): return A(0x1a, bytes([v]) + (struct.pack('<H', mov) if v & 0x08 else b''))
def ranging_setup(ts, ctrl, token=1, reason=0, ftm=None, sched=None):
    d = bytes([token, ts, reason, ctrl])
    if ftm is not None: d += ftm
    if sched: d += b''.join(bytes([m]) + tb(*t) for m, t in sched)
    return A(0x1b, d)
def ftm_report(): return A(0x1c, pat(20))
def container(mapid, *elements): return A(0x1d, bytes([mapid]) + b''.join(bytes([i, len(d)]) + d for i, d in elements))
def NNC(b=3): return bytes([b]) + b'\x00' + bytes([0x24, 0x12]) + struct.pack('<HH', 100, 0x400)
def ext_wlan(): return A(0x1e, BCAST + A1 + bytes([1]) + NNC()[:3] + struct.pack('<HH', 40, 100))
def ext_p2p(): return A(0x1f, bytes([4]) + A1 + bytes([81, 6, 0]) + struct.pack('<HH', 50, 100))
def ext_ibss(): return A(0x20, BCAST + A1 + bytes([115, 36, 0]) + struct.pack('<HH', 5, 6))
def ext_mesh(mid=b'mesh'): return A(0x21, A1 + bytes([81, 1, 0]) + struct.pack('<HH', 7, 8) + mid)
def cipher(caps=0x0f, *suites): return A(0x22, bytes([caps]) + b''.join(bytes([c, p]) for c, p in suites))
def sec_ctx(*ctxs): return A(0x23, b''.join(struct.pack('<H', len(d)) + bytes([t, p]) + d for t, p, d in ctxs))
def shared_key(pid=3, d=pat(24)): return A(0x24, bytes([pid]) + d)
def pub_avail(*entries): return A(0x27, b''.join(bytes([m]) + tb(*t) for m, t in entries))
def devcap_ext(v=0x01ff): return A(0x2a, struct.pack('<H', v))
def ident_res(ver=0, d=None): return A(0x2b, bytes([ver]) + (d if d is not None else pat(16, 0x70)))
def pairing(ts, token=1, reason=0, extra=b'', methods=0x0ff3): return A(0x2c, bytes([token, ts, reason]) + extra + struct.pack('<H', methods))
def vendor_attr(payload): return A(0xDD, payload)
def nest(levels, inner=b'', kind='vendor'):
    """levels vendor specific attributes, each in the next one (WFA NAN IE)."""
    for _ in range(levels):
        inner = vendor_attr(WFA + b'\x13' + inner)
    return inner

main = Pcap(); mal = Pcap(); ranges = []
def mark(p, name, n0):
    ranges.append((name, n0 + 1, len(p.frames)))
RNDI = bytes.fromhex('02cc000000a1')
TB = (0x0021, b'\xff\x0f')

# ---- beacons ----
n0 = len(main.frames)
main.add(nan_beacon(master(), cluster(), svc_ids(1)))
main.add(nan_beacon(master(255, 255), cluster(0xffffffffffffffff, 255, 0xffffffff), sync=True))
main.add(nan_beacon(master(), cluster(), country(b'XX'), cluster_disc(), svc_ids(3), svc_ids(2, 0x28)))
main.add(nan_beacon(devcap(), conncap(0xff), further_sd(), further_av()))
main.add(nan_beacon(wlan_infra(), p2p_op(), ibss(b'\x55')))
main.add(nan_beacon(mesh(0x00), mesh(0x02, b'\x01\x02', b'm'), mesh(0x04, b'\x01', b'mm'), mesh(0x06, b'', b'mmm')))
main.add(nan_beacon(ranging(), ranging_info(0x00), ranging_info(0x08), devcap_ext(0), devcap_ext(0xffff)))
main.add(nan_beacon(ident_res(0), ident_res(1, b'\x01\x02\x03'), ident_res(0xff, b'')))
main.add(nan_beacon(ext_wlan(), ext_p2p(), ext_ibss(), ext_mesh(), ext_mesh(b'')))
mark(main, 'NAN beacons (discovery and sync) with the synchronization and mode attributes', n0)

n0 = len(main.frames)
# vendor specific attributes: other vendor IEs inside, and nesting up to the limit of 8
main.add(nan_beacon(master(), vendor_attr(MS + b'\x04' + b'\x10\x4a\x00\x01\x10')))        # WPS IE
main.add(nan_beacon(master(), vendor_attr(MS + b'\x02\x00\x01\x00')))   # WMM
main.add(nan_beacon(vendor_attr(bytes.fromhex('aabbcc') + b'\x01data')))                    # unknown OUI
main.add(nan_beacon(vendor_attr(WFA + b'\x09' + b'\x02\x02\x00\x25\x00')))                   # P2P attribute list
main.add(nan_beacon(vendor_attr(WFA + b'\x1a' + b'\x00\x01\x02')))                            # DPP IE
main.add(nan_beacon(nest(1, master())))
main.add(nan_beacon(nest(7, master())))
main.add(nan_beacon(nest(8, master())))                                                       # exactly at the limit
# k back-to-back attributes (the reproducer of the 2^k blow-up: 22 took 13 s, 35 more than a day)
main.add(nan_beacon(*[vendor_attr(WFA + b'\x13')] * 22))
main.add(nan_beacon(*[vendor_attr(WFA + b'\x13')] * 35))
main.add(sdf(nest(8, master())))
mark(main, 'vendor specific attributes: other vendor IEs, nesting of 1, 7 and 8 levels, 22 and 35 siblings', n0)

# ---- service discovery frames ----
n0 = len(main.frames)
main.add(sdf(svc_ids(2), sda(0, mf=[b'\x01\x02', b'abc'], info=b'service info')))
main.add(sdf(sda(1, bindmap=0x1234, srf=b'\x01' + pat(8)), sdea(1, 0x0000)))
main.add(sdf(sda(2, info=b'follow'), sdea(2, 0x0301, (100, 200), 7)))
main.add(sdf(sda(0)))
main.add(sdf(sda(1, bindmap=7, mf=[b'x'], srf=b'\x00' + A1 + A2, info=pat(10), flags=0x20), sdea(3, 0x03ff, (1, 2), 9, (WFA, 2, b'spec'))))
main.add(sdf(sdea(1, 0x0100, (1, 2)), sdea(1, 0x0200, None, 5), sdea(4, 0x0000, None, None, (WFA, 0, b'\x01\x02\x03')), sdea(5, 0x0055)))
main.add(sdf(sda(0, info=b''), sda(0, mf=[]), sda(0, srf=b'\x00')))
main.add(sdf(conncap(), country(), ranging_info(), ftm_report(), svc_ids(1, 0x28)))
main.add(sdf(container(1, (0, b'nan-ssid'), (3, b'\x06'), (127, pat(8)), (45, pat(26)), (250, b'\x01\x02'),
                       (221, WFA + b'\x13' + master()), (221, bytes.fromhex('0050f2') + b'\x04' + b'\x10\x4a\x00\x01\x10'))))
main.add(sdf(container(0x13, (221, WFA + b'\x13' + nest(1, master()))), container(2)))
main.add(sdf(container(1, (221, WFA + b'\x13' + container(1, (221, WFA + b'\x13' + master())))) ))
mark(main, 'NAN Service Discovery frames: SDA, SDEA with every optional field, element containers', n0)

# ---- NAN action frames ----
n0 = len(main.frames)
band = av_entry(1, TB, avhdr(0, 0, 2), b'\x02\x04')                    # committed, time bitmap, two band entries (2.4 and 5 GHz)
chan = av_entry(2, None, avhdr(1, 0, 2), bytes([81]) + struct.pack('<H', 0x0041) + b'\x01' + bytes([115]) + struct.pack('<H', 0x000f) + b'\x03')
nonc = av_entry(3, TB, avhdr(1, 1, 1), bytes([124]) + struct.pack('<H', 0x000f) + b'\x01' + struct.pack('<H', 0x0003), ctl=0x0078)
six = av_entry(4, None, avhdr(1, 0, 3), bytes([131]) + struct.pack('<H', 0x0301) + b'\x01' + bytes([133]) + struct.pack('<H', 0x0207) + b'\x02' + bytes([136]) + struct.pack('<H', 0x0101) + b'\x01')
res = av_entry(6, None, avhdr(1, 0, 4), bytes([85]) + struct.pack('<H', 0x0003) + b'\x01' + bytes([0]) + struct.pack('<H', 0x0003) + b'\x01' + bytes([20]) + struct.pack('<H', 0x0003) + b'\x01' + bytes([130]) + struct.pack('<H', 0x0005) + b'\x01')
nochan = av_entry(7, None, avhdr(0, 0, 0))
main.add(act(5, ndp(0x00, 0x00), ndl(0x00, 0x00), devcap(), avail(1, 0x0301, band)))
main.add(act(5, ndp(0x00, 0x08, pubid=5), ndl(0x00, 0x03, peer=9, sched=[(1, TB)]), ndc(), avail(2, 0x0301, chan, nonc)))
main.add(act(6, ndp(0x01, 0x00, rndi=RNDI), ndlqos(), cipher(0x0f, (1, 3), (2, 4)), sec_ctx((1, 3, pat(8)), (2, 4, b'')), avail(3, 0x0303, six)))
main.add(act(6, ndp(0x01, 0x28, rndi=RNDI, info=b'ndp specific'), ndl(0x11, 0x10, idle=500), avail(4, 0x0300, res, nochan)))
main.add(act(7, ndp(0x02, 0x20, info=b'confirm'), shared_key()))
main.add(act(8, ndp(0x03, 0x00), shared_key(1, b'\x01')))
main.add(act(9, ndp(0x04, 0x00), unaligned()))
main.add(act(5, ndpe(0x00, 0x00, ndpe_tlv(0, pat(8)) + ndpe_tlv(1, WFA + b'xyz') + ndpe_tlv(5, pat(4)))))
main.add(act(5, ndpe(0x00, 0x08, ndpe_tlv(0, pat(8)), pubid=2)))
main.add(act(6, ndpe(0x01, 0x00, ndpe_tlv(1, WFA + b''), rndi=RNDI)))
main.add(act(1, ranging_setup(0x00, 0x00), ranging_info()))
main.add(act(2, ranging_setup(0x10, 0x02, ftm=b'\x11\x22\x33'), ftm_report()))
main.add(act(3, ranging_setup(0x20, 0x04, sched=[(1, TB), (2, (0x0021, b'\x0f'))])))
main.add(act(4, ranging_setup(0x00, 0x06, ftm=b'\x01\x02\x03', sched=[(1, (0x0021, b'\xff'))]), ftm_report()))
main.add(act(10, ndl(0x00, 0x13, peer=3, idle=7, sched=[(1, TB), (3, (0x0021, b'\x01'))]), ndlqos(), unaligned(0x00, b'\x05'),
             unaligned(0x01, bytes([81]) + struct.pack('<H', 0x0041) + b'\x01'),
             unaligned(0x02, bytes([115]) + struct.pack('<H', 0x0003) + b'\x01\x03\x00')))
main.add(act(11, ndl(0x10, 0x00), ndc([bytes([1]) + tb(*TB), bytes([2]) + tb(0x0029, b'\x01')]), unaligned(0x03)))
main.add(act(12, pub_avail((1, TB), (2, (0x0041, b'\x01'))), ident_res()))
main.add(act(13, pairing(0x10), pairing(0x01), pairing(0x02), pairing(0x00), devcap_ext(0x0003)))
main.add(act(13, pairing(0x12, reason=3), pairing(0x22, extra=struct.pack('<H', 100) + bytes([3]) + b'abc'),
             pairing(0x21, extra=b'\x04abcd'), pairing(0x11, extra=b'\x00')))
main.add(act(0, ndp(0x00, 0x00)))
main.add(act(99, ndp(0x00, 0x00)))
mark(main, 'NAN action frames: data path, schedule, ranging, availability, security, pairing', n0)

# ---- malformed ----
n0 = len(mal.frames)
# nesting past the limit (9, 10 and 12 levels), in a beacon, a discovery frame and a container
mal.add(nan_beacon(nest(9, master())))
mal.add(nan_beacon(nest(10, master())))
mal.add(sdf(nest(12, master())))
mal.add(sdf(nest(5, container(1, (221, WFA + b'\x13' + nest(4, master()))))))
mal.add(sdf(container(1, (221, WFA + b'\x13' + container(1, (221, WFA + b'\x13' + nest(7, master())))))))
# unknown attribute IDs (reserved ones too), truncated headers and lengths past the frame
for i in (0x11, 0x16, 0x18, 0x19, 0x25, 0x26, 0x2d, 0x80, 0xfe):
    mal.add(nan_beacon(A(i, b'\x01\x02')))
mal.add(nan_beacon(b'\x00\x02'))
mal.add(nan_beacon(master(), b'\x01'))
mal.add(nan_beacon(b'\x01\xff\x00\x00'))
# fixed-size attributes with a wrong length
for i in (0x00, 0x01, 0x04, 0x0d, 0x0f, 0x15, 0x1e, 0x1f, 0x20):
    mal.add(nan_beacon(A(i, b'\x00')))
    mal.add(nan_beacon(A(i, bytes(40))))
# minimum lengths
for i in (0x02, 0x28, 0x03, 0x0e, 0x05, 0x06, 0x07, 0x08, 0x0c, 0x10, 0x29, 0x12, 0x13, 0x14, 0x17, 0x1b, 0x21, 0x22, 0x23,
          0x27, 0x2a, 0x2b, 0x2c, 0xdd):
    mal.add(nan_beacon(A(i, b'\x01')))
mal.add(nan_beacon(A(0x02, bytes(7))))
mal.add(nan_beacon(A(0x2b, b'')))
mal.add(nan_beacon(A(0x2b, b''), master()))
# availability with an unknown / invalid operating class and channel
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([131]) + struct.pack('<H', 0x0201) + b'\x01'))))   # channel 1 start, 2 channels ok
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([131]) + struct.pack('<H', 0x0302) + b'\x01'))))   # channel 2 not in class 131
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([131]) + struct.pack('<H', 0x0001) + b'\x01'))))   # zero channels
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([131]) + struct.pack('<H', 0xff01) + b'\x01'))))   # 255 channels
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([131]) + struct.pack('<H', 0x4001) + b'\x01'))))   # 64 channels
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([131]) + struct.pack('<H', 0x4101) + b'\x01'))))   # 65 channels
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([0]) + struct.pack('<H', 0x0003) + b'\x01'))))      # op class 0
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 1), bytes([136]) + struct.pack('<H', 0x0003) + b'\x01'))))    # op class without a channel set
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(1, 0, 5), bytes([81]) + struct.pack('<H', 0x0003) + b'\x01'))))     # entry count past the attribute
mal.add(act(10, avail(1, 0x0301, av_entry(1, None, avhdr(0, 0, 9), b'\x01'))))
mal.add(act(10, avail(1, 0x0301, b'\xff\x00\x01\x00\x00')))                      # entry length past the attribute
mal.add(act(10, avail(1, 0x0301, av_entry(1, (0x0021, b''), avhdr(0, 0, 0)))))
mal.add(act(10, avail(1, 0x0301, struct.pack('<HH', 3, 0x1001) + b'\xff\xff')))   # time bitmap length past the attribute
# lists whose entries run past the attribute
mal.add(nan_beacon(A(0x03, SID + b'\x01\x02' + bytes([0x04]) + b'\x30\x30\x01')))                 # matching filter length past the end
mal.add(nan_beacon(A(0x03, SID + b'\x01\x02' + bytes([0x08]) + b'\x30\x00')))
mal.add(nan_beacon(A(0x03, SID + b'\x01\x02' + bytes([0x10]) + b'\x30\x01')))
mal.add(nan_beacon(A(0x03, SID + b'\x01\x02' + bytes([0x40]) + b'\x01')))
mal.add(nan_beacon(A(0x0e, b'\x01\x00\x01')))
mal.add(nan_beacon(A(0x0e, b'\x01\x00\x01\x05\x00')))
mal.add(nan_beacon(A(0x29, bytes(11) + b'\x00\x30\x00\x01')))                                     # NDPE TLV past the end
mal.add(nan_beacon(A(0x29, bytes(11) + b'\x01\x02\x00\x01\x02')))
mal.add(nan_beacon(A(0x13, bytes(7) + b'\x01\x00\x00\x30\x01')))
mal.add(nan_beacon(A(0x14, bytes([1, 0x10, 0, 0x02]) + b'\x01\x21\x00\x30\x01')))
mal.add(nan_beacon(A(0x14, bytes([1, 0x10, 0, 0x01]))))
mal.add(nan_beacon(A(0x17, bytes(16) + b'\x01')))
mal.add(nan_beacon(A(0x17, bytes(16) + b'\x02\x01')))
mal.add(nan_beacon(A(0x1b, bytes([1, 0, 0, 0x02]) + b'\x01')))
mal.add(nan_beacon(A(0x1b, bytes([1, 0, 0, 0x04]) + b'\x01\x21\x00\x30\x01')))
mal.add(nan_beacon(A(0x1d, bytes([1]) + b'\x00\x30\x01')))
mal.add(nan_beacon(A(0x22, b'\x0f\x01')))
mal.add(nan_beacon(A(0x23, b'\x30\x00\x01\x02\x01')))
mal.add(nan_beacon(A(0x27, b'\x01\x21\x00\x30\x01')))
mal.add(nan_beacon(A(0x2b, b'\x00\x01')))
mal.add(nan_beacon(A(0x2c, bytes([1, 0x22, 0]) + b'\x01')))
mal.add(nan_beacon(A(0x0a, b'\x01\x20\x51')))
mal.add(nan_beacon(A(0x0b, b'X')))
mal.add(nan_beacon(A(0x24, b'')))
mal.add(act(5, ndp(0x01, 0x28, rndi=RNDI[:3])))
mal.add(sdf(A(0x03, SID[:4])))
mal.add(act(5))
mal.add(act(5, b'\x10\x02'))
mark(mal, 'malformed', n0)

out = sys.argv[1]
main.write(os.path.join(out, 'wifi-nan-coverage.pcap'))
mal.write(os.path.join(out, 'wifi-nan-coverage-malformed.pcap'))
if '-v' in sys.argv:
    for r in ranges: print(*r)
