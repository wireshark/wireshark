#!/usr/bin/env python3
# Generates test/captures/mle_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MLE coverage captures.  Usage: mkmle.py <outdir> [-v]
Everything is built with struct; no keys, no real crypto (the MIC and
payload bytes of the secured frames are placeholders).
Writes mle-coverage.pcap (IEEE 802.15.4 without FCS, linktype 230) and
mle-coverage-malformed.pcap."""
import struct
import sys
import os

def pcap(name, pkts, linktype=230):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            wire = len(p)
            if isinstance(p, tuple):
                p, wire = p
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), wire))
            f.write(p)

SRC64 = 0x0200000000000001
DST64 = 0x0200000000000002

def wpan(payload, seq, dst='short', src='ext'):
    """Data frame, PAN ID compression. dst/src: 'short' or 'ext'."""
    am = {'short': 2, 'ext': 3}
    fcf = 0x0001 | 0x0040 | (am[dst] << 10) | (am[src] << 14)
    if dst == 'short':
        hdr = struct.pack('<HBHH', fcf, seq, 0xface, 0xffff)
    else:
        hdr = struct.pack('<HBHQ', fcf, seq, 0xface, DST64)
    hdr += struct.pack('<Q', SRC64) if src == 'ext' else struct.pack('<H', 0x0400)
    return hdr + payload

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff or 0xffff

SRC6 = bytes.fromhex('fe800000000000000000000000000001')
DST6 = bytes.fromhex('ff020000000000000000000000000001')

def udp(payload, src=SRC6, dst=DST6):
    ln = 8 + len(payload)
    h = struct.pack('>HHHH', 19788, 19788, ln, 0)
    ck = csum(src + dst + struct.pack('>IBBBB', ln, 0, 0, 0, 17) + h + payload)
    return struct.pack('>HHHH', 19788, 19788, ln, ck) + payload

def ipv6(nh, payload, src=SRC6, dst=DST6):
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 255) + src + dst + payload

def ipv4(payload):
    tot = 20 + len(payload)
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, tot, 1, 0, 64, 17, 0,
                    bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    s = sum(struct.unpack('>10H', h)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    return h[:10] + struct.pack('>H', (~s) & 0xffff) + h[12:] + payload

def tlv(t, v=b''):
    return bytes([t, len(v)]) + v

def mle_nosec(cmd, tlvs=b''):
    """Security suite 255: no security header."""
    return bytes([0xff, cmd]) + tlvs

def mle_level0(cmd, tlvs=b'', keymode=1):
    """Security suite 0 with an auxiliary header of security level 0."""
    aux = bytes([keymode << 3]) + struct.pack('<I', 7)
    if keymode == 1:
        aux += bytes([1])
    elif keymode == 2:
        aux += struct.pack('<I', 5) + bytes([2])
    elif keymode == 3:
        aux += struct.pack('<Q', 0x0102030405060708) + bytes([3])
    return bytes([0x00]) + aux + bytes([cmd]) + tlvs

def frame(m, seq, dst='short', src='ext', src6=SRC6, dst6=DST6):
    return wpan(b'\x41' + ipv6(17, udp(m, src6, dst6), src6, dst6), seq, dst, src)

# ---------------- TLV builders ----------------
def t_src(a):            return tlv(0, a)
def t_mode(b):           return tlv(1, bytes([b]))
def t_timeout(n):        return tlv(2, struct.pack('>I', n))
def t_chal(b):           return tlv(3, b)
def t_resp(b):           return tlv(4, b)
def t_llfc(n):           return tlv(5, struct.pack('>I', n))
def t_lqi(entries, asz):  # asz = address bytes (1..16)
    v = bytes([0x80 | (asz - 1)])
    for i, (fl, idr) in enumerate(entries):
        v += bytes([fl, idr]) + bytes(range(0x10 + i, 0x10 + i + asz))
    return tlv(6, v)
def t_netparm(pid, delay, val): return tlv(7, bytes([pid]) + struct.pack('>I', delay) + val)
def t_mlefc(n):          return tlv(8, struct.pack('>I', n))
def t_route64(seq, ids, costs):
    mask = 0
    for i in ids:
        mask |= 1 << (63 - i)
    return tlv(9, bytes([seq]) + struct.pack('>Q', mask) + bytes(costs))
def t_addr16(a):         return tlv(10, struct.pack('>H', a))
def t_leader(pid, w, v, sv, rid): return tlv(11, struct.pack('>IBBBB', pid, w, v, sv, rid))
def t_nwdata(b):         return tlv(12, b)
def t_tlvreq(ts):        return tlv(13, bytes(ts))
def t_scan(b):           return tlv(14, bytes([b]))
def t_conn7():           return tlv(15, bytes([0x40, 3, 2, 1, 5, 9, 12]))
def t_conn10():          return tlv(15, bytes([0xc0, 3, 2, 1, 5, 9, 12]) + struct.pack('>HB', 1280, 4))
def t_margin(b):         return tlv(16, bytes([b]))
def t_status(b):         return tlv(17, bytes([b]))
def t_version(n):        return tlv(18, struct.pack('>H', n))
def t_addrreg(entries):  return tlv(19, b''.join(entries))
def ar_comp(cid, iid):   return bytes([0x80 | cid]) + iid
def ar_full(ip):         return bytes([0x00]) + ip
def t_channel(page, ch): return tlv(20, struct.pack('>BH', page, ch))
def t_panid(p):          return tlv(21, struct.pack('>H', p))
def t_atstamp(sec, ticks): return tlv(22, struct.pack('>Q', (sec << 16) | (ticks << 1) | 1))
def t_ptstamp(sec, ticks): return tlv(23, struct.pack('>Q', (sec << 16) | (ticks << 1)))
def t_active(b):         return tlv(24, b)
def t_pending(b):        return tlv(25, b)
def t_discovery(b):      return tlv(26, b)
def t_superv(n):         return tlv(27, struct.pack('>H', n))
def t_cslch(page, ch):   return tlv(80, struct.pack('>BH', page, ch))
def t_csltmo(n):         return tlv(85, struct.pack('>I', n))
def t_cslacc(a, u):      return tlv(86, bytes([a, u]))
def sub(t, v):           return bytes([t, len(v)]) + v
def t_lmquery(subs):     return tlv(87, subs)
def t_lmmgmt(subs):      return tlv(88, subs)
def t_lmreport(subs):    return tlv(89, subs)
def t_probe(v):          return tlv(90, v)

# MeshCoP TLVs for the Thread MeshCoP dissector
def mc(t, v): return bytes([t, len(v)]) + v
MC_DATASET = (mc(0, struct.pack('>BH', 0, 15)) + mc(1, struct.pack('>H', 0x1234)) +
              mc(3, b'thread-test') + mc(5, bytes(range(16))) + mc(7, bytes.fromhex('fd00000000000000')))
# Thread network data TLVs: type<<1 | stable
def nd(t, stable, v): return bytes([(t << 1) | stable, len(v)]) + v
ND_DATA = (nd(1, 1, bytes([0x00, 64]) + bytes.fromhex('fd000db800000000') +
              nd(3, 1, bytes([0x21, 64])) + nd(2, 1, struct.pack('>HH', 0x0400, 0x3100)))
           + nd(0, 0, struct.pack('>HB', 0x0400, 0x01)))

def sec(level, payload, keymode=1, keyidx=1):
    aux = bytes([level | (keymode << 3)]) + struct.pack('<I', 1) + bytes([keyidx])
    return bytes([0x00]) + aux + payload

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    pk = []
    marks = []
    seq = [0]
    def add(p, label=None):
        pk.append(p)
        if label:
            marks.append((len(pk), label))
    def fr(m, dst='short', src='ext', label=None, **kw):
        seq[0] += 1
        add(frame(m, seq[0], dst, src, **kw), label)

    fr(mle_nosec(0, t_src(b'\x04\x00') + t_mode(0x0b) + t_timeout(240) + t_chal(bytes(range(8)))
                 + t_version(2) + t_tlvreq([0, 1, 5, 6])), label='Link Request, Source Address 2 octets (src map update)')
    fr(mle_nosec(1, t_src(bytes(range(8))) + t_resp(bytes(range(8))) + t_llfc(1000)
                 + t_mlefc(2000) + t_lqi([(0xe0, 3), (0x00, 0x15)], 2) + t_margin(20)),
       label='Link Accept, Source Address 8 octets, Response, frame counters, Link Quality 2 neighbors')
    fr(mle_nosec(2, t_src(b'\x08\x00') + t_chal(b'') + t_resp(b'') + t_leader(0x01020304, 64, 5, 7, 9)),
       src='short', label='Link Accept and Request from a short source, empty Challenge/Response, Leader Data')
    fr(mle_nosec(3, t_status(1)), label='Link Reject, Status Error')
    fr(mle_nosec(4, t_src(b'\x04\x00') + t_leader(1, 2, 3, 4, 5) +
                 t_route64(7, [0, 2, 3, 4, 8, 9, 13, 15], [0x21, 0x32, 0x43, 0x14, 0x25, 0x36, 0x47, 0x18])),
       label='Advertisement with Route64 (8 entries)')
    fr(mle_nosec(5, t_status(2)), label='Update, Status Duplicate Address')
    fr(mle_nosec(6, t_tlvreq([])), label='Update Request, empty TLV Request')
    fr(mle_nosec(7, t_tlvreq([13, 12])), label='Data Request')
    fr(mle_nosec(8, t_src(b'\x04\x00') + t_leader(9, 9, 9, 9, 9) + t_nwdata(ND_DATA)
                 + t_atstamp(1700000000, 100) + t_ptstamp(1700000001, 200)),
       label='Data Response, Network Data, timestamps')
    fr(mle_nosec(8, t_nwdata(b'')), label='Data Response, empty Network Data')
    fr(mle_nosec(9, t_mode(0x0f) + t_chal(bytes(8)) + t_scan(0xc0) + t_version(3)),
       label='Parent Request, Scan Mask')
    fr(mle_nosec(10, t_src(b'\x04\x00') + t_leader(1, 2, 3, 4, 5) + t_llfc(10) + t_mlefc(11)
                 + t_resp(bytes(8)) + t_chal(bytes(8)) + t_lqi([(0xa0, 9)], 1) + t_conn7()
                 + t_margin(12) + t_version(2)), label='Parent Response, Connectivity (7)')
    fr(mle_nosec(10, t_conn10() + t_scan(0x00)), label='Parent Response, Connectivity (10)')
    fr(mle_nosec(11, t_resp(bytes(8)) + t_llfc(1) + t_mlefc(2) + t_timeout(60) + t_version(2) +
                 t_addrreg([ar_comp(1, bytes(8)), ar_full(SRC6), ar_comp(0, bytes(range(8)))]) +
                 t_tlvreq([10, 9, 11, 12]) + t_mode(0x0a)), label='Child ID Request, Address Registration')
    fr(mle_nosec(12, t_src(b'\x04\x00') + t_addr16(0x0401) + t_leader(1, 2, 3, 4, 5) + t_nwdata(ND_DATA) +
                 t_route64(1, [1], [0x11]) + t_active(MC_DATASET) + t_pending(MC_DATASET)
                 + t_atstamp(5, 6) + t_ptstamp(7, 8) + t_addrreg([ar_comp(2, bytes(8))])),
       dst='ext', label='Child ID Response to an extended destination, Address16 (dst map update), datasets')
    fr(mle_nosec(12, t_addr16(0x0402)), label='Child ID Response, Address16 to a short destination')
    fr(mle_nosec(13, t_mode(0x0b) + t_timeout(30) + t_leader(1, 2, 3, 4, 5) + t_addr16(0x1000) + t_superv(129)),
       label='Child Update Request, Supervision Interval')
    fr(mle_nosec(14, t_mode(0x0b) + t_timeout(30) + t_src(b'\x04\x00') + t_llfc(3) + t_mlefc(4)
                 + t_superv(30) + t_status(1) + t_addrreg([ar_full(DST6)]) + t_tlvreq([0])),
       label='Child Update Response')
    fr(mle_nosec(15, t_channel(0, 15) + t_panid(0xface) + t_atstamp(99, 3)), label='Announce, Channel, PAN ID')
    fr(mle_nosec(16, t_discovery(mc(128, b'\x10\x00'))), label='Discovery Request, Thread Discovery')
    fr(mle_nosec(17, t_discovery(mc(129, b'\x10\x00')) + t_netparm(0, 100, struct.pack('>H', 11))),
       label='Discovery Response, Network Parameter channel')
    fr(mle_nosec(5, t_netparm(1, 5, struct.pack('>H', 0xface)) + t_netparm(2, 6, bytes([1])) +
                 t_netparm(3, 7, b'beacon!!') + t_netparm(9, 8, b'xy') + t_netparm(3, 1, b'') +
                 t_netparm(9, 2, b'')),
       label='Update, Network Parameter PAN ID, Permit Join, Beacon Payload, unknown (with data, empty)')
    fr(mle_nosec(18, t_lmmgmt(sub(3, bytes([1, 1, 0x29])) + sub(3, bytes([2, 0])) +
                              sub(7, bytes([1])) + sub(7, bytes([2, 0x29])) + sub(7, bytes([0])))),
       label='Link Metrics Management Request: forward probing (flags, no flags), enhanced ACK config')
    fr(mle_nosec(19, t_lmmgmt(sub(5, bytes([0])) + sub(5, bytes([2])) + sub(5, bytes([254])))),
       label='Link Metrics Management Response, status sub TLV')
    fr(mle_nosec(20, t_probe(bytes([1]))), label='Link Probe')
    fr(mle_nosec(20, t_probe(bytes([1, 0xaa, 0xbb, 0xcc]))), label='Link Probe with a longer value')
    fr(mle_nosec(5, t_lmquery(sub(1, bytes([5])) + sub(2, bytes([0x29, 0x2a]))) +
                 t_lmreport(sub(0, bytes([0x29, 0x55])) + sub(0, bytes([0x71, 1, 2, 3, 4])))),
       label='Link Metrics Query (ID and options), Link Metrics Report (1 and 4 octet values)')
    fr(mle_nosec(5, t_cslch(0, 11) + t_csltmo(100) + t_cslacc(50, 20)), label='CSL Channel, Timeout and Accuracy')
    fr(mle_nosec(21, tlv(28, b'\x01\x02') + tlv(29, b'') + tlv(30, b'\x03') + tlv(31, b'\x04\x05\x06')
                 + tlv(200, b'unknown')), label='CIM Discovery Request, CIM TLVs and unknown TLV')
    fr(mle_nosec(22), label='CIM Discovery Response')
    fr(mle_nosec(23), label='CIM Announce')
    fr(mle_nosec(99, tlv(77, b'')), label='Unknown command, unknown empty TLV')
    fr(mle_nosec(5), label='Update without TLVs')
    for km in (0, 1, 2, 3):
        fr(mle_level0(5, t_status(1) + t_version(2), km),
           label='Security suite 0, auxiliary header level 0, key identifier mode %d' % km)
    fr(mle_nosec(7, t_tlvreq([1, 2])), dst='ext', src='short', label='short source, extended destination')
    fr(mle_nosec(1, t_resp(bytes(8))),
       src6=bytes.fromhex('fe800000000000000200000000000009'),
       dst6=bytes.fromhex('fe800000000000000200000000000001'), label='unicast Link Accept')

    # Reproducers of "MLE: Fix MIC check buffer over-read and assertions".
    # They need an IEEE 802.15.4 key to reach the MIC check; without one
    # the frames decode with a "no key" warning.
    body = bytes([0x00])
    while len(body) < 600:
        n = min(200, 600 - len(body) - 2)
        body += bytes([0x7f, n]) + b'\x41' * n
    fr(sec(1, body + b'\xde\xad\xbe\xef'), label='REPRODUCER 1: MIC-32 only, 600 octet payload (stack over-read with a key)')
    seq[0] += 1
    add(wpan(b'\x41' + ipv6(4, ipv4(udp(sec(1, bytes([0, 0x11, 0]) + b'\xde\xad\xbe\xef')))), seq[0]),
        'REPRODUCER 2: MLE over IPv4-in-IPv6 with MIC (assertion with a key)')

    pcap(os.path.join(out, 'mle-coverage.pcap'), pk)
    if verbose:
        for n, l in marks:
            print(n, l)
        print(len(pk), 'frames')

    # ---------------- malformed capture --------------------------------
    pk = []; marks = []; seq[0] = 100
    def bad(m, label, **kw):
        fr(m, label=label, **kw)
    bad(mle_nosec(5, t_src(b'\x01\x02\x03')), 'Source Address length 3')
    bad(mle_nosec(5, tlv(1, b'\x01\x02')), 'Mode length 2')
    bad(mle_nosec(5, tlv(2, b'\x01\x02')), 'Timeout length 2')
    bad(mle_nosec(5, tlv(5, b'\x01\x02')), 'LL frame counter length 2')
    bad(mle_nosec(5, tlv(8, b'\x01\x02')), 'MLE frame counter length 2')
    bad(mle_nosec(5, tlv(6, bytes([0x81, 1, 2, 3, 4, 5, 6]))), 'Link Quality length mismatch (size 2, 6 octets)')
    bad(mle_nosec(5, tlv(6, bytes([0x81])) + t_status(1)), 'Link Quality with only the flags octet')
    bad(mle_nosec(5, tlv(6, bytes([0x80])) + t_status(1)), 'Link Quality, size 1, length 1')
    bad(mle_nosec(5, tlv(9, bytes([1]) + struct.pack('>Q', 0xc000000000000000) + bytes([1])) + t_status(1) * 4),
        'Route64 count mismatch')
    bad(mle_nosec(5, tlv(10, b'\x01')), 'Address16 length 1')
    bad(mle_nosec(5, tlv(11, b'\x01\x02')), 'Leader Data length 2')
    bad(mle_nosec(5, tlv(14, b'\x01\x02')), 'Scan Mask length 2')
    bad(mle_nosec(5, tlv(15, b'\x01\x02')), 'Connectivity length 2')
    bad(mle_nosec(5, tlv(16, b'\x01\x02')), 'Link Margin length 2')
    bad(mle_nosec(5, tlv(17, b'\x01\x02')), 'Status length 2')
    bad(mle_nosec(5, tlv(18, b'\x01')), 'Version length 1')
    bad(mle_nosec(5, tlv(19, bytes([0x00, 1, 2, 3]))), 'Address Registration not whole entries')
    bad(mle_nosec(5, tlv(20, b'\x01\x02')), 'Channel length 2')
    bad(mle_nosec(5, tlv(21, b'\x01')), 'PAN ID length 1')
    bad(mle_nosec(5, tlv(22, b'\x01\x02')), 'Active Timestamp length 2')
    bad(mle_nosec(5, tlv(23, b'\x01\x02')), 'Pending Timestamp length 2')
    bad(mle_nosec(5, tlv(27, b'\x01')), 'Supervision Interval length 1')
    bad(mle_nosec(5, tlv(80, b'\x01')), 'CSL Channel length 1')
    bad(mle_nosec(5, tlv(85, b'\x01')), 'CSL Timeout length 1')
    bad(mle_nosec(5, tlv(86, b'\x01\x02\x03') + t_status(1)), 'CSL Accuracy length 3 (fix: advance)')
    bad(mle_nosec(5, tlv(90, b'') + t_status(1)), 'Link Probe length 0 (fix)')
    bad(mle_nosec(5, tlv(88, sub(3, bytes([1, 1, 0x29, 0x11, 0x22])) + sub(5, b'\x00')) + t_status(1)),
        'Link Metrics sub TLV loop (fix: stops at the end of its TLV)')
    bad(mle_nosec(5, tlv(7, bytes([3, 0, 0, 0, 1])) + t_status(1)), 'Network Parameter Beacon Payload, length 5')
    bad(mle_nosec(5, tlv(7, bytes([9, 0, 0, 0, 1])) + t_status(1)), 'Network Parameter unknown id, length 5')
    bad(mle_nosec(5, tlv(7, bytes([3, 0, 0])) + t_status(1)), 'Network Parameter Beacon Payload, length 3 (fix: negative length)')
    bad(mle_nosec(5, tlv(7, bytes([9, 0, 0])) + t_status(1)), 'Network Parameter unknown id, length 3 (fix)')
    bad(bytes([0xff, 5, 1]), 'TLV header cut after the type')
    bad(bytes([0xff, 5, 2, 4, 0, 0]), 'Timeout value cut short')
    bad(bytes([0xff, 5, 13, 5, 1]), 'TLV Request cut short')
    bad(bytes([0xff, 5, 7, 5, 0]), 'Network Parameter cut short')
    bad(bytes([0xff, 5, 9, 9, 1, 0xff]), 'Route64 cut short')
    bad(bytes([0xff, 5, 19, 3, 0x00, 1, 2]), 'Address Registration cut short')
    bad(bytes([0xff, 5, 6, 0]), 'Link Quality cut short')
    bad(bytes([0xff]), 'Security suite only')
    bad(bytes([0x00, 0x00]), 'Security suite 0, truncated auxiliary header')
    bad(sec(5, bytes([5]) + t_status(1) + b'\xde\xad\xbe\xef'), 'ENC-MIC-32 (no key / MIC check fails, placeholder bytes)')
    bad(sec(1, bytes([5]) + t_status(1) + b'\xde\xad\xbe\xef'), 'MIC-32 only, placeholder MIC')
    bad(sec(7, bytes([5]) + t_status(1) + b'\x11' * 16), 'ENC-MIC-128, placeholder')
    bad(sec(4, bytes([5]) + t_status(1)), 'ENC, no MIC')
    bad(sec(5, b'\x01'), 'ENC-MIC-32 payload shorter than the MIC (too small)')
    bad(sec(2, bytes([5]) + t_status(1) + b'\x22' * 8), 'MIC-64 only')
    bad(sec(5, bytes([5]) + t_status(1) + b'\xde\xad\xbe\xef', 1, 2),
        'ENC-MIC-32 with key index 2 (no matching key)')
    bad(sec(5, bytes([5]) + t_status(1) + b'\xde\xad\xbe\xef'), 'ENC-MIC-32 from a short source address (no extended source for the key)', src='short')
    seq[0] += 1
    f = frame(sec(5, bytes([5]) + t_status(1) * 3 + b'\xde\xad\xbe\xef'), seq[0])
    add((f[:-8], len(f)), 'ENC-MIC-32 truncated in the capture (MIC and part of the payload missing)')
    seq[0] += 1
    f = frame(sec(4, bytes([5]) + t_status(1) * 3), seq[0])
    add((f[:-4], len(f)), 'ENC truncated in the capture')
    pcap(os.path.join(out, 'mle-coverage-malformed.pcap'), pk)
    if verbose:
        for n, l in marks:
            print('M', n, l)
        print(len(pk), 'malformed frames')

main()
