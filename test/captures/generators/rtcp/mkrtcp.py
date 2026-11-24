#!/usr/bin/env python3
# Generates test/captures/rtcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RTCP coverage captures.
# Usage: mkrtcp.py <outdir> [-v]
#   rtcp-coverage.pcap            main capture (no malformed packets)
#   rtcp-coverage-malformed.pcap  malformed / error paths
# RTCP is reached by the default-enabled UDP heuristic ("RTCP over UDP"),
# so no Decode As is used; the SIP/SDP frames set up an RTCP conversation.
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)

class Cap:
    def __init__(self):
        self.pkts = []
        self.t = 1000.0
    def udp(self, payload, sport=50001, dport=50003, src=A, dst=B, dt=0.1, ts=None):
        u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), len(self.pkts) + 1, 0, 64, 17, 0,
                         bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
        if ts is None:
            self.t += dt
            ts = self.t
        else:
            self.t = ts
        self.pkts.append((ts, eth + ip + u))
        return len(self.pkts)
    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for ts, p in self.pkts:
                f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(p), len(p)))
                f.write(p)

# ------------------------------------------------------------ building blocks
def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)

def rtcp(pt, low5, body, p=0, v=2):
    body = pad4(body)
    return struct.pack('!BBH', (v << 6) | (p << 5) | low5, pt, (4 + len(body)) // 4 - 1) + body

S1 = 0x11223344
S2 = 0x55667788
S3 = 0xA1B2C3D4

def u32(*a):
    return b''.join(struct.pack('!I', x) for x in a)

def report_block(src, frac=10, lost=5, hi=1000, cycles=0, jit=77, lsr=0, dlsr=0):
    return (struct.pack('!IB', src, frac) + struct.pack('!I', lost)[1:] +
            struct.pack('!HHIII', cycles, hi, jit, lsr, dlsr))

def sr(ssrc, blocks=(), ntp=(0xE1000000, 0x80000000), rtpts=160000, pc=100, oc=16000, ext=b'', p=0):
    return rtcp(200, len(blocks), u32(ssrc, ntp[0], ntp[1], rtpts, pc, oc) + b''.join(blocks) + ext, p)

def rr(ssrc, blocks=(), ext=b'', p=0):
    return rtcp(201, len(blocks), u32(ssrc) + b''.join(blocks) + ext, p)

def sdes_chunk(ssrc, items, term=True):
    b = struct.pack('!I', ssrc)
    for t, v in items:
        if t == 8:   # PRIV: prefix string, value
            pre, val = v
            v = bytes([len(pre)]) + pre + val
        b += bytes([t, len(v)]) + v
    if term:
        b += b'\0'
    return pad4(b)

def sdes(chunks, p=0):
    return rtcp(202, len(chunks), b''.join(chunks), p)

def bye(ssrcs, reason=None, p=0):
    b = u32(*ssrcs)
    if reason is not None:
        b += bytes([len(reason)]) + reason
    return rtcp(203, len(ssrcs), b, p)

def app(sub, name, data, ssrc=S1, p=0):
    return rtcp(204, sub, struct.pack('!I', ssrc) + name + data, p)

def pse(t, body, length=None):
    # profile specific extension: type, length in bytes (incl. 4 octet header)
    if length is None:
        length = 4 + len(body)
    return struct.pack('!HH', t, length) + body

def rtpfb(fmt, body, ssrc=S1, media=S2, p=0):
    return rtcp(205, fmt, u32(ssrc, media) + body, p)

def psfb(fmt, body, ssrc=S1, media=S2, p=0):
    return rtcp(206, fmt, u32(ssrc, media) + body, p)

def xr(blocks, ssrc=S1, p=0):
    return rtcp(207, 0, u32(ssrc) + b''.join(blocks), p)

def xr_block(bt, spec, content):
    content = pad4(content)
    return struct.pack('!BBH', bt, spec, len(content) // 4) + content

def utf(s):
    return s.encode()

# MCPT / MCPC field: id, length (1 byte below 192, 2 bytes from 192), value, padding
def fld(i, val):
    hdr = bytes([i]) + (bytes([len(val)]) if i < 192 else struct.pack('!H', len(val)))
    return pad4(hdr + val)

def mcc_mnc():
    return bytes([0x13, 0x00, 0x62])   # MCC 310 MNC 260

def loc(t):
    if t == 0: return b'\0'
    if t == 1: return bytes([1]) + mcc_mnc() + struct.pack('!I', 0x0123456a)
    if t == 2: return bytes([2]) + mcc_mnc() + struct.pack('!H', 0x1234)
    if t == 3: return bytes([3]) + mcc_mnc()
    if t == 4: return bytes([4]) + struct.pack('!H', 4321)
    if t == 5: return bytes([5, 77])
    if t == 6: return bytes([6]) + b'\x12\x34\x56\x65\x43\x21'
    return bytes([t, 0, 0])

def build_main():
    c = Cap()
    m = Cap()
    P = {}   # name -> frame number
    MP = {}
    def add(name, payload, **kw):
        P[name] = c.udp(payload, **kw)
    def addm(name, payload, **kw):
        MP[name] = m.udp(payload, **kw)
    cn = lambda s: (1, utf(s))

    # ---- SDP/SIP setup of an RTCP conversation on 192.0.2.3:4001 (SIP over UDP 5060)
    sdp = (b'v=0\r\no=- 1 1 IN IP4 192.0.2.3\r\ns=-\r\nc=IN IP4 192.0.2.3\r\nt=0 0\r\n'
           b'm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n')
    sip = (b'INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.3:5060;branch=z9hG4bK1\r\n'
           b'From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c1@192.0.2.3\r\n'
           b'CSeq: 1 INVITE\r\nContact: <sip:alice@192.0.2.3>\r\nContent-Type: application/sdp\r\n'
           b'Content-Length: %d\r\n\r\n' % len(sdp)) + sdp
    add('sdp', sip, sport=5060, dport=5060, src=(192, 0, 2, 3), dst=(192, 0, 2, 4))

    # ---- SR / RR / SDES
    add('sr0', sr(S1) + sdes([sdes_chunk(S1, [cn('alice@example.com')])]))
    add('sr2', sr(S1, [report_block(S2), report_block(S3, frac=255, lost=0xffffff, cycles=3, hi=65535)])
        + sdes([sdes_chunk(S1, [cn('a@b'), (2, b'Alice A'), (3, b'a@example.com')])]))
    add('rr1', rr(S2, [report_block(S1, lsr=0x80000000, dlsr=65536)]) + sdes([sdes_chunk(S2, [cn('bob')])]))
    add('rr0', rr(S2))
    add('sdes_all', rr(S2) + sdes([
        sdes_chunk(S1, [cn('user@host'), (2, b'Name'), (3, b'e@x.org'), (4, b'+1 555 0100'),
                        (5, b'Sydney'), (6, b'wsTool 1.0'), (7, b'a note'),
                        (8, (b'prefix', b'private data')), (9, b'h323 addr'), (10, b'\x01\x02\x03')]),
        sdes_chunk(S2, [(8, (b'', b'v')), (8, (b'abc', b'')), (1, b''), (11, b'unknown type')]),
        sdes_chunk(S3, [])]))
    # SDES chunk whose items run to the end without a terminator ("not terminated" warning)
    add('sdes_noterm', rr(S2) + sdes([sdes_chunk(S1, [cn('abcdef')], term=False)]))
    # PRIV with a prefix longer than the item, and with a prefix that fills the item
    add('sdes_priv', rr(S2) + sdes([struct.pack('!I', S1) + bytes([8, 3, 9, 1, 2]) + bytes([8, 4, 3]) + b'abc' + bytes([1, 3]) + b'xyz' + b'\0\0']))
    # RR/SR padding on the last packet; padding bit on a non-final packet (ignored by default)
    pad = b'\0' * 7 + b'\x08'
    add('pad_last', rr(S2) + rtcp(202, 1, sdes_chunk(S1, [cn('p')]) + pad, p=1))
    add('pad_nonfinal', rtcp(201, 0, u32(S2) + b'\0\0\0\x04', p=1) + sdes([sdes_chunk(S1, [cn('q')])]))
    addm('pad_zero', rtcp(201, 0, u32(S2) + b'\0\0\0\0', p=1))

    # ---- Profile specific extensions of MS-RTP
    exts = [
        pse(1, u32(S2, 123456) + b'\x50\0\0\0', 16),                       # estimated bandwidth + confidence
        pse(1, u32(0xffffffff, 77), 12),                                     # SSRC = ANY, no confidence
        pse(4, struct.pack('!HH', 0, 0x1234), 8),                            # packet loss notification
        pse(5, b'\0\0\0\0' + struct.pack('!HHIH', 640, 480, 500000, 30) + b'\0\0', 20),
        pse(6, b'\0\0\0\0', 8),                                              # padding
        pse(7, u32(0, 250000), 12),
        pse(8, u32(0, 260000), 12),
        pse(9, u32(S3, 5, 6, 7, 100) + b'\0\0\x02\x03', 28),
        pse(10, u32(0, 270000), 12),
        pse(11, u32(0xfffffffe) + bytes([0x81, 3]) + struct.pack('!H', 1400), 12),
        pse(12, u32(S3, 1000000, 2000000) + b'\x01\0\0\0', 20),
        pse(13, u32(0xe1000000, 0x40000000, 0, 0x02000000), 20),
        pse(14, b'\x01\0\0\0' + u32(300000), 12),
        pse(99, b'\xde\xad\xbe\xef', 8),                                     # unknown type (data dissector)
    ]
    for i, e in enumerate(exts):
        add('pse%d' % i, rr(S2, ext=e))
    add('pse_sr', sr(S1, ext=exts[0] + exts[2]))
    add('pse_rr_blocks', rr(S2, [report_block(S1)], ext=exts[3] + exts[5] + exts[1]))
    add('pse_short', rr(S2, ext=b'\xff\xff\x00\x02'))   # unknown type, length below 4
    add('pse_len_lt4', rr(S2, ext=pse(6, b'\0\0\0\0', 2)))     # MS extension with length below 4
    add('pse_len_big', rr(S2, ext=pse(4, struct.pack('!HH', 0, 0x1234), 100)))   # extension longer than the packet (consumed clamped)
    addm('pse_len_big_padding', rr(S2, ext=pse(6, b'\0\0\0\0', 100)))
    add('pse_noconsume', rr(S2, ext=pse(2, b'\0\0\0\0\0\0\0\0')))  # unregistered type: shown as unknown

    # ---- BYE
    add('bye1', bye([S1], b'going away'))
    add('bye2', bye([S1, S2]))
    add('bye3', bye([S1], b'abcd'))     # reason padded with three zero octets
    add('bye0', rtcp(203, 0, b''))
    addm('bye_nopad', rtcp(203, 1, u32(S1) + b'\x04abcd' + b'\0\xff\0'))  # padding not zero (warning)

    # ---- APP: PoC1 (TBCP)
    poc = {
        0: b'',
        1: b'\x65\x02\x00\x1e\x64\x02\x00\x05',
        2: u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!' + b'\x64\x02\xff\xff',
        18: u32(S2) + b'\x01\x0asip:a@b.cd',
        3: b'\x01\x05retry\0',
        4: b'\x01\x02\x80\x00',
        5: b'',
        6: b'\x00\x02\x00\x1e',
        7: b'\x78\x01\0\0',
        8: b'',
        9: b'\x01\x00\x05\0',
        11: b'',
        15: b'\xa8\x00\x01\x80' + b'\x01\x03abc' + b'\x03\x03def' + b'\x05\x03ghi' + b'\0',
    }
    for st, d in poc.items():
        add('poc%d' % st, app(st, b'PoC1', d))
    # variants for the other branches of the PoC1 decoder
    add('poc0_prio_ts', app(0, b'PoC1', b'\x66\x02\x00\x02\x67\x08' + u32(0xe1000000, 0) + b'\0\0'))
    add('poc0_prio', app(0, b'PoC1', b'\x66\x02\x00\x01'))
    add('poc0_ts', app(0, b'PoC1', b'\x67\x08' + u32(0xe1000000, 0x10000000) + b'\0\0'))
    add('poc0_code_other', app(0, b'PoC1', b'\x01\x02\x03\x04'))
    add('poc1_stt0', app(1, b'PoC1', b'\x65\x02\x00\x00\x64\x02\x00\x00'))
    add('poc1_inf', app(1, b'PoC1', b'\x65\x02\xff\xff\x64\x02\xff\xff'))
    addm('poc0_ts_len', app(0, b'PoC1', b'\x67\x04\0\0\0\0'))
    add('poc1_short', app(1, b'PoC1', b'\x65\x02\x00\x1e'))
    addm('poc1_bad_code', app(1, b'PoC1', b'\x01\x02\x00\x1e'))
    addm('poc1_bad_len', app(1, b'PoC1', b'\x65\x03\x00\x1e'))
    addm('poc1_part_other', app(1, b'PoC1', b'\x65\x02\x00\x1e\x63\x02\x00\x01'))
    addm('poc1_part_len', app(1, b'PoC1', b'\x65\x02\x00\x1e\x64\x03\x00\x01'))
    add('poc2_other_partic', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!' + b'\x64\x02\x00\x07'))
    add('poc2_name_exact', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!'))
    add('poc2_noname_part', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x64\x02\x00\x00'))
    addm('poc2_nocname', app(2, b'PoC1', u32(S2) + b'\x02\x0aabcdefghij' + b'\0'))
    addm('poc2_name_only', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!\0\0'))
    addm('poc2_part_bad', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!' + b'\x63\x02\x00\x00'))
    addm('poc2_part_len', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!' + b'\x64\x04\x00\x00\x00\x00\0\0'))
    add('poc2_part_inf', app(2, b'PoC1', u32(S2) + b'\x01\x0asip:a@b.cd' + b'\x02\x06Alice!' + b'\x64\x02\xff\xff'))
    add('poc3_nophrase', app(3, b'PoC1', b'\x02\x00\0\0'))
    for rc in (1, 2, 3, 4, 9):
        add('poc6_%d' % rc, app(6, b'PoC1', struct.pack('!HH', rc, 30)))
    add('poc7_other', app(7, b'PoC1', b'\x08\0\0\0'))
    add('poc9_q0', app(9, b'PoC1', b'\x02\x00\x00\0'))
    add('poc9_qmax', app(9, b'PoC1', b'\x03\xff\xff\0'))
    addm('poc5_data', app(5, b'PoC1', b'\0\0\0\0'))
    addm('poc8_data', app(8, b'PoC1', b'\0\0\0\0'))
    addm('poc11_data', app(11, b'PoC1', b'\0\0\0\0'))
    addm('poc12_unknown', app(12, b'PoC1', b'\0\0\0\0'))
    add('poc12_empty', app(12, b'PoC1', b''))
    add('poc15_none', app(15, b'PoC1', b'\x00\x00\x01\x00'))
    add('poc_lowercase', app(5, b'poc1', b''))

    # ---- APP: MCPT (3GPP TS 24.380)
    mcpt = {
        'req': (0, fld(0, b'\x00\x05') + fld(6, utf('sip:user@example.com')) + fld(13, b'\x80\x00')
                + fld(12, b'\x01\x00') + fld(1, b'\x00\x3c') + fld(10, b'\x00\x01')),
        'grant': (1, fld(1, b'\x00\x3c') + fld(14, struct.pack('!IH', S1, 0)) + fld(5, b'\x00\x01')
                  + fld(8, b'\x00\x07') + fld(15, bytes([2, 3]) + b'abc' + bytes([4]) + b'abcd')),
        'deny': (3, fld(2, b'\x00\x01') + fld(2, b'\x00\x02' + utf('no way')) + fld(4, utf('alice'))),
        'deny_cause': (3, fld(2, b'\x00\x07')),
        'revoke': (6, fld(2, b'\x00\x03') + fld(2, b'\x00\x03' + utf('revoked'))),
        'rel': (4, fld(7, b'\x00\x04') + fld(3, b'\x02\x05') + fld(9, utf('bob')) + fld(106, utf('carol'))),
        'other': (5, fld(2, b'\x00\x09') + fld(17, utf('fa1')) + fld(18, bytes([2, 3]) + b'fa1' + bytes([3]) + b'fa2')),
        'track': (11, fld(11, bytes([0x02, 3]) + b'mcx\0' + u32(1, 2)) + fld(11, bytes([0x01, 4]) + b'mcxx' + b'')
                  + fld(11, bytes([0x00, 0]) + u32(0xdeadbeef))),
        'ssrcs': (7, fld(16, bytes([2, 0]) + u32(S1, S2)) + fld(16, bytes([0, 0]))),
        'loc': (8, fld(19, loc(0)) + fld(19, loc(1)) + fld(19, loc(2)) + fld(19, loc(3))
                + fld(19, loc(4)) + fld(19, loc(5)) + fld(19, loc(6)) + fld(19, b'\x07')),
        'locs': (9, fld(20, bytes([3]) + loc(6) + loc(3) + loc(4))),
        'unknown_fld': (0, fld(60, b'\x01\x02\x03') + fld(200, b'\x04\x05')),
        'empty_fld': (0, b'\x00\x00\x00\x00'),
        'nofields': (2, b''),
        'floor_all': (0, fld(13, b'\xff\x80')),
    }
    for k, (st, d) in mcpt.items():
        add('mcpt_' + k, app(st, b'MCPT', d))
    addm('mcpt_nonzero_pad', app(0, b'MCPT', bytes([6, 1]) + b'a\x01'))
    addm('mcpt_extra', app(0, b'MCPT', fld(0, b'\0\5') + b'\0\0\0\0' + fld(1, b'\0\5')))
    addm('mcpt_track_nonzero_pad', app(11, b'MCPT', bytes([11, 8, 1, 1]) + b'ab\x01\x01' + u32(1)))
    add('mcpt_sub12', app(12, b'MCPT', fld(0, b'\0\1')))
    add('mcpt_sub_hi', app(31, b'MCPT', fld(0, b'\0\1')))
    for st in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15):
        add('mcpt_st%d' % st, app(st, b'MCPT', fld(1, b'\0\x0a')))

    # ---- APP: MCPC
    mcpc = [
        (0, fld(0, b'\x01\x02') + fld(1, b'\x01' + utf('sessionid')) + fld(2, utf('warning text'))
         + fld(3, utf('sip:group@x.org')) + fld(4, b'\x00\x01') + fld(5, utf('sip:inviter@x.org'))
         + fld(6, b'\x00\x02') + fld(7, b'\x00\x03') + fld(8, utf('sip:invitee@x.org'))),
        (1, fld(192, bytes(range(10))) + fld(9, b'\1\2\3') + fld(250, b'\x09\x09')),
        (2, b''),
        (3, b'\x00\x00\x00\x00'),
    ]
    for i, (st, d) in enumerate(mcpc):
        add('mcpc%d' % i, app(st, b'MCPC', d))

    # ---- APP: MCCP
    ipv6 = bytes(range(0x20, 0x30))
    grp = bytes([3, 12]) + utf('sip:g@x.org')[:11].ljust(12, b'x') + b'\0\0'     # field 3, 12 octets + 2 padding
    tmgi6 = bytes([1, 6]) + b'\x01\x02\x03' + mcc_mnc()
    tmgi3 = bytes([1, 3]) + b'\x01\x02\x03' + b'\0\0\0'
    z4 = b'\0\0\0\0'      # the dissector counts every field twice: two bytes per field of slack
    mccp = [
        (0, bytes([0, 14]) + bytes([0x11, 0]) + u32(5000, 5002) + bytes([239, 1, 2, 3]) + grp + z4),
        (1, bytes([0, 10]) + bytes([0x10, 0]) + u32(5004) + bytes([239, 1, 2, 4]) + grp + z4),
        (2, bytes([0, 26]) + bytes([0x21, 0x10]) + u32(5006, 5008) + ipv6 + grp + z4),
        (3, bytes([0, 22]) + bytes([0x20, 0x10]) + u32(5010) + ipv6 + grp + z4),
        (4, tmgi6 + grp + z4),
        (5, grp + grp + z4),
        (6, bytes([77, 4]) + b'\1\2\3\4' + b'\0\0' + grp + z4),
        (7, tmgi3 + grp + z4),
    ]
    for i, (st, d) in enumerate(mccp):
        add('mccp%d' % i, app(st, b'MCCP', d))
    # MCCP with a single field: packet_len wraps in the dissector (malformed)
    addm('mccp_single', app(0, b'MCCP', bytes([0, 10]) + bytes([0x10, 0]) + u32(5004) + bytes([239, 1, 2, 4])))
    addm('mccp_tmgi3', app(0, b'MCCP', bytes([1, 3]) + b'\x01\x02\x03'))

    addm('mcpc_nonzero_pad', app(0, b'MCPC', bytes([2, 1]) + b'a\x01'))
    addm('mcpc_extra', app(0, b'MCPC', fld(4, b'\0\1') + b'\0\0\0\0' + fld(4, b'\0\1')))
    addm('mccp_empty', struct.pack('!BBH', 0x80, 204, 1) + u32(S1) + b'MCCP' + bytes([3, 4]) + b'abcd\0\0')
    addm('mccp_extra', app(0, b'MCCP', bytes([3, 5]) + b'abcde' + b'\0\0\0\0\0' + bytes([3, 5]) + b'abcde' + b'\0'))
    addm('app_nonascii', app(1, b'\x01\x02\x03\x04', b'\1\2\3\4'))
    addm('app_nonascii_str', app(1, b'\xff\xfe\xfd\xfc', b'abcd'))
    # ---- APP: 3GPP (RTP multiplexing), generic names
    add('mux', app(1, b'3GPP', b'\xa0\x00\x13\x88'))
    add('mux_long', app(2, b'3GPP', b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    add('mux_none', app(3, b'3GPP', b''))
    add('app_str', app(1, b'TEST', b'hello wor' + b'ld!!'[:3] + b'\0'))
    add('app_bin', app(2, b'TEST', b'\x01\x02\x03\x04'))
    add('app_empty', app(4, b'TEST', b''))

    # ---- Legacy H.261 packet types and others, after a receiver report
    add('fir', rr(S2) + rtcp(192, 0, u32(S1))[:0] + struct.pack('!BBH', 0x80, 192, 1) + u32(S1))
    add('nack_legacy', rr(S2) + struct.pack('!BBH', 0x80, 193, 2) + u32(S1) + struct.pack('!HH', 12, 0x5))
    add('avb', rr(S2) + rtcp(208, 3, u32(S1) + b'abcd' + struct.pack('!H', 1) + bytes(10) + struct.pack('!Q', 1) + u32(7, 8)))
    add('rsi', rr(S2) + rtcp(209, 0, u32(S1, S2, 0xe1000000, 1) + b'\0' * 8))
    add('token', rr(S2) + rtcp(210, 2, u32(S1) + b'\0' * 8))
    add('rsi_min', rr(S2) + rtcp(209, 0, u32(S1, S2, 0xe1000000, 1)))

    # ---- RTPFB: generic NACK, TMMBR/TMMBN, CCFB, transport-cc, others
    add('nack', rtpfb(1, struct.pack('!HH', 100, 0x8001) + struct.pack('!HH', 200, 0)))
    add('nack_blp', rtpfb(1, struct.pack('!HH', 65530, 0xffff)))
    add('tmmbr0', rtpfb(3, b'', media=0))
    add('tmmbn0', rtpfb(4, b'', media=0))
    addm('tmmbr', rtpfb(3, struct.pack('!IBBBB', S3, 0x0a << 2, 0x61, 0xa8, 0x28) + b'\0\0\0\0', media=0))
    addm('tmmbn', rtpfb(4, struct.pack('!IBBBB', S3, 0x0b << 2, 0x61, 0xa8, 0x28) + b'\0\0\0\0', media=0))
    add('rtpfb_fmt2', rtpfb(2, b'\1\2\3\4'))
    addm('rtpfb_fmt31', rtpfb(31, b'\1\2\3\4'))
    add('rtpfb_fmt5', rtpfb(5, b'\1\2\3\4' * 3))
    # CCFB (fmt 11)
    mb = lambda r, e, a: struct.pack('!H', (r << 15) | (e << 13) | a)
    ccfb = struct.pack('!IHH', S2, 100, 3) + mb(1, 0, 100) + mb(1, 2, 2000) + mb(0, 0, 0) + b'\0\0'
    ccfb += struct.pack('!IHH', S3, 7, 2) + mb(1, 3, 8191) + mb(1, 1, 1)
    ccfb += struct.pack('!I', 0x10203040)
    add('ccfb', rtcp(205, 11, u32(S1) + ccfb))
    add('ccfb_0', rtcp(205, 11, u32(S1) + struct.pack('!IHH', S2, 1, 0) + struct.pack('!I', 1)))
    addm('ccfb_many', rtcp(205, 11, u32(S1) + struct.pack('!IHH', S2, 1, 20000) + b'\0' * 16))
    # transport-cc (fmt 15)
    def tcc(base, count, ref, fb, chunks, deltas):
        return struct.pack('!HH', base, count) + ref.to_bytes(3, 'big') + bytes([fb]) + \
            b''.join(struct.pack('!H', x) for x in chunks) + deltas
    add('tcc_run', rtpfb(15, tcc(1000, 5, 0x123456, 1, [0x2003, 0x4002],
                                 b'\x10\x20\x30' + struct.pack('!hh', 400, -400) + b'\0')))
    add('tcc_vec1', rtpfb(15, tcc(65530, 7, 1, 2, [0x9555], bytes(range(1, 8)) + b'\0')))
    add('tcc_vec2', rtpfb(15, tcc(5, 7, 2, 3, [0xd8d0], b'\x05' + struct.pack('!h', -1000) + b'\x06\0')))
    add('tcc_nr', rtpfb(15, tcc(7, 10, 3, 4, [0x0003, 0x2002, 0x4001, 0x0004],
                                b'\x01\x02' + struct.pack('!h', 5000) + b'\0\0')))
    add('tcc_two', rtpfb(15, tcc(1, 2, 4, 5, [0x2002], b'\x01\x02\0\0') + tcc(10, 1, 5, 6, [0x4001], struct.pack('!h', 300) + b'\0\0')))
    add('tcc_vec_nr', rtpfb(15, tcc(1, 14, 4, 5, [0x8000 | 0x0000], b'')))
    add('tcc_empty', rtpfb(15, tcc(1, 0, 1, 1, [], b'')))
    add('tcc_vec2_pad', rtpfb(15, tcc(1, 3, 4, 5, [0xc000 | 0x0140, ], b'\x01' + struct.pack('!h', 300) + b'\x02')))

    addm('tcc_zero_run', rtpfb(15, tcc(1, 3, 1, 1, [0x2000], b'\0\0\0\0')))
    addm('tcc_run_too_long', rtpfb(15, tcc(1, 3, 1, 1, [0x2004], b'\0\0\0\0')))
    addm('tcc_vec1_many', rtpfb(15, tcc(1, 3, 1, 1, [0x9fff], b'\0\0\0\0')))
    addm('tcc_vec2_many', rtpfb(15, tcc(1, 3, 1, 1, [0xd555], b'\0\0\0\0')))
    addm('tcc_vec2_many_ld', rtpfb(15, tcc(1, 2, 1, 1, [0xdaaa], b'\0\0\0\0')))
    # ---- PSFB
    add('pli', psfb(1, b''))
    add('pli_ms', psfb(1, struct.pack('!HH', 5, 0) + bytes(range(8))))
    add('sli', psfb(2, struct.pack('!I', (5 << 19) | (3 << 6) | 7)) )
    add('sli2', psfb(2, struct.pack('!II', 0x00100001, 0x00200002)))
    add('rpsi', psfb(3, b'\x00\x62\x01\x02\x03\x04\x05\x06'))
    add('fir_psfb', psfb(4, struct.pack('!I', S3) + b'\x05\0\0\0', media=0))
    add('fir2', psfb(4, struct.pack('!I', S3) + b'\x05\0\0\0' + struct.pack('!I', S1) + b'\x06\0\0\0', media=0))
    add('tstr', psfb(5, struct.pack('!I', S3) + b'\x05\0\0\0'))
    add('psfb_fmt9', psfb(9, b'\1\2\3\4'))
    remb = lambda ex, man, ssrcs: b'REMB' + bytes([len(ssrcs)]) + struct.pack('!I', (ex << 18) | man)[1:] + u32(*ssrcs)
    add('remb', psfb(15, remb(10, 5000, [S2, S3]), media=0))
    add('remb0', psfb(15, remb(0, 1, []), media=0))
    add('remb2', psfb(15, remb(3, 200, [S3]) + remb(4, 300, [S1, S2]), media=0))
    # MS application layer feedback: video source request, dominant speaker, unknown
    vsre = (bytes([121, 1, 0x30, 0x7f]) + struct.pack('!HHII', 640, 480, 100000, 0) + struct.pack('!I', 50000)
            + b''.join(struct.pack('!H', i) for i in range(10)) + struct.pack('!I', 0x00000075)
            + struct.pack('!HH', 1, 2) + b''.join(struct.pack('!H', i) for i in range(8)) + struct.pack('!I', 307200))
    assert len(vsre) == 0x44
    vsr_body = u32(S3) + struct.pack('!HHBBBB', 7, 0, 1, 1, 1, 0x44) + b'\0\0\0\0' + vsre
    add('ms_vsr', psfb(15, struct.pack('!HH', 1, 4 + len(vsr_body)) + vsr_body, media=0xffffffff))
    vsr2 = u32(S3) + struct.pack('!HHBBBB', 8, 0, 1, 0, 2, 0x44) + b'\0\0\0\0' + vsre + vsre
    add('ms_vsr2', psfb(15, struct.pack('!HH', 1, 4 + len(vsr2)) + vsr2, media=0xfffffffe))
    ds = u32(S1, S2, S3)
    add('ms_dsh', psfb(15, struct.pack('!HH', 3, 4 + len(ds)) + ds, media=0))
    add('ms_unknown', psfb(15, struct.pack('!HH', 9, 8) + b'\1\2\3\4', media=0))

    # ---- XR
    xrs = {
        'ref': [xr_block(4, 0, u32(0xe1000000, 0x20000000))],
        'dlrr': [xr_block(5, 0, u32(S1, 0x1111, 0x2222) + u32(S2, 3, 4))],
        'stats': [xr_block(6, 0xf0, u32(S1) + struct.pack('!HH', 10, 20) + u32(1, 2, 3, 4, 5, 6) + bytes([60, 64, 62, 1]))],
        'voip': [xr_block(7, 0, u32(S1) + bytes([1, 2, 3, 4]) + struct.pack('!HHHH', 5, 6, 7, 8)
                          + bytes([0x7f, 0x7f, 0x7f, 20, 0x7f, 0x7f, 0x7f, 0x7f]) + bytes([0xc0 | 0x20 | 0x10, 0])
                          + struct.pack('!HHH', 40, 80, 120))],
        'voip2': [xr_block(7, 0, u32(S1) + bytes([1, 2, 3, 4]) + struct.pack('!HHHH', 5, 6, 7, 8)
                           + bytes([0xd8, 0xd0, 0x10, 20, 80, 70, 41, 42]) + bytes([0x40, 0])
                           + struct.pack('!HHH', 40, 80, 120))],
        'xnq': [xr_block(8, 0, struct.pack('!HHHH', 1, 2, 3, 4) + u32(5) + struct.pack('!HH', 6, 7)
                         + u32(0x00000008, 0x00000009, 0x0000000a, 0x0000000b))],
        'xnq_spare': [xr_block(8, 0, struct.pack('!HHHH', 1, 2, 3, 4) + u32(5) + struct.pack('!HH', 6, 7)
                         + u32(0x01000008, 0x02000009, 0x0300000a, 0x0400000b))],
        'idms': [xr_block(12, 0x20, bytes([96, 0, 0, 0]) + u32(0xAABBCCDD, 0x55667788, 0xE0000000, 0xFFFFFFFF, 0x01020304, 0x00010002)),
                 xr_block(4, 0, u32(0xe1000000, 0))],
        'loss': [xr_block(1, 0x03, u32(S1) + struct.pack('!HH', 100, 200) + struct.pack('!HHHH', 0x0005, 0x4003, 0x8abc, 0))],
        'dup': [xr_block(2, 0x01, u32(S1) + struct.pack('!HH', 100, 200) + struct.pack('!HH', 0xc001, 0))],
        'discard': [xr_block(25, 0x82, u32(S1) + struct.pack('!HH', 100, 200) + struct.pack('!HH', 0x2001, 0))],
        'rxtimes': [xr_block(3, 0x02, u32(S1) + struct.pack('!HH', 101, 104) + u32(1000, 2000, 3000))],
        'unknown': [xr_block(99, 0, b'\1\2\3\4' * 3)],
        'known_unparsed': [xr_block(9, 0, u32(S1, 2, 3)), xr_block(10, 0, u32(S1, 2, 3)), xr_block(11, 0, u32(S1, 2, 3))],
        'multi': [xr_block(4, 0, u32(0xe1000000, 0)), xr_block(5, 0, u32(S1, 1, 2)), xr_block(99, 0, b'')],
    }
    for k, bl in xrs.items():
        add('xr_' + k, xr(bl))
    add('xr_dlrr_extra', xr([xr_block(5, 0, u32(S1, 1, 2, 3))]))
    add('xr_nosrc', rtcp(207, 0, b''))
    addm('xr_bad_ref', xr([xr_block(4, 0, u32(0xe1000000, 0, 1))]))
    addm('xr_bad_stats', xr([xr_block(6, 0, u32(S1) + b'\0' * 28)]))
    addm('xr_bad_voip', xr([xr_block(7, 0, u32(S1) + b'\0' * 24)]))
    addm('xr_bad_xnq', xr([xr_block(8, 0, b'\0' * 28)]))
    addm('xr_bad_idms', xr([xr_block(12, 0, b'\0' * 24)]))
    addm('xr_block_long', rtcp(207, 0, u32(S1) + struct.pack('!BBH', 99, 0, 50) + b'\0' * 8))
    addm('xr_one_octet', rtcp(207, 0, u32(S1) + b'\x63\0\0\0'[:0] + b'\x01'))
    addm('xr_no_block_hdr', rtcp(207, 0, u32(S1) + b'\x63\0\0\0')[:0] + struct.pack('!BBH', 0x80, 207, 1) + u32(S1))   # packet length 4: missing sender SSRC is a warning

    # ---- Round trip (needs the preference rtcp.show_roundtrip_calculation, runcov.sh / tests)
    # SR from A:50001 to B:50003 at t0, matching RR from B:50003 to A:50001 later.
    def lsr_of(ntp):
        return ((ntp[0] & 0xffff) << 16) | (ntp[1] >> 16)
    ntp1 = (0xe1000000, 0x12340000)
    t0 = 2000.0
    add('rt_sr1', sr(S1, ntp=ntp1) , ts=t0, sport=50001, dport=50003)
    add('rt_rr_late', rr(S2, [report_block(S1, lsr=lsr_of(ntp1), dlsr=int(0.2 * 65536))]),
        ts=t0 + 0.5, sport=50003, dport=50001, src=B, dst=A)
    ntp2 = (0xe1000001, 0x23450000)
    add('rt_sr2', sr(S1, ntp=ntp2), ts=t0 + 1.0, sport=50001, dport=50003)
    add('rt_rr_neg', rr(S2, [report_block(S1, lsr=lsr_of(ntp2), dlsr=int(1.0 * 65536))]),
        ts=t0 + 1.2, sport=50003, dport=50001, src=B, dst=A)
    ntp3 = (0xe1000002, 0x34560000)
    add('rt_sr3', sr(S1, ntp=ntp3), ts=t0 + 2.0, sport=50001, dport=50003)
    add('rt_rr_small', rr(S2, [report_block(S1, lsr=lsr_of(ntp3), dlsr=int(0.095 * 65536))]),
        ts=t0 + 2.1, sport=50003, dport=50001, src=B, dst=A)
    ntp4 = (0xe1000003, 0x45670000)
    add('rt_sr4', sr(S1, ntp=ntp4), ts=t0 + 3.0, sport=50001, dport=50003)
    add('rt_rr_nodlsr', rr(S2, [report_block(S1, lsr=lsr_of(ntp4), dlsr=0)]),
        ts=t0 + 3.3, sport=50003, dport=50001, src=B, dst=A)
    add('rt_rr_nomatch', rr(S2, [report_block(S1, lsr=0xdeadbeef, dlsr=65536)]),
        ts=t0 + 3.4, sport=50003, dport=50001, src=B, dst=A)
    # RR in a stream that never saw an SR
    add('rt_rr_nosr', rr(S2, [report_block(S1, lsr=1, dlsr=2)]), ts=t0 + 4.0,
        sport=50007, dport=50009, src=B, dst=A)
    # RTCP in the conversation set up by the SDP (192.0.2.3 -> port 4001)
    add('setup_rr', rr(S2, [report_block(S1)]), sport=4001, dport=4001, src=(192, 0, 2, 3), dst=(192, 0, 2, 4), ts=t0 + 5.0)
    add('setup_sr', sr(S1) + sdes([sdes_chunk(S1, [cn('setup')])]), sport=4001, dport=4001,
        src=(192, 0, 2, 4), dst=(192, 0, 2, 3), ts=t0 + 5.1)
    # Reproducer of "RTCP: Bound transport-cc allocations ...": 6540 FCIs of 10 octets,
    # each with a zero run length chunk and the packet status count 0xffff (about 1.3 GB of
    # pool memory per packet before the fix). The last frame of the main capture.
    fci = struct.pack('!HH', 0, 0xffff) + b'\0\0\0\x01' + struct.pack('!H', 0)
    add('tcc_alloc', rtpfb(15, fci * 6540))
    return c, P, m, MP

def build_malformed(c, P):
    def add(name, payload, **kw):
        P[name] = c.udp(payload, **kw)
    # Padding count larger than the packet / zero length RTCP packets
    add('pad_big', rr(S2, p=0)[:0] + struct.pack('!BBH', 0xa0, 201, 1) + b'\x11\x22\x33\xc8' + b'\0' * 196)
    add('len0_rr', struct.pack('!BBH', 0x80, 201, 0) + b'\0' * 28)
    add('len0_app', struct.pack('!BBH', 0x80, 204, 0) + b'\0' * 28)
    add('truncated', rr(S2, [report_block(S1)])[:20] + b'')
    add('short3', b'\x80\xc9\x00')
    add('version1', b'\x40\xc9\x00\x01' + b'\0' * 4)
    add('pt_not_allowed', b'\x80\xc3\x00\x01' + b'\0' * 4)
    add('len_not_x4', b'\x80\xc9\x00\x01' + b'\0' * 5)
    add('hdr_longer', b'\x80\xc9\x00\x09' + b'\0' * 4)
    add('version1_port', b'\x40\xc9\x00\x01' + b'\0' * 4, sport=51111, dport=51113)
    add('pt_smpte', rr(S2) + struct.pack('!BBH', 0x80, 194, 1) + u32(S1))
    add('pt_ij', rr(S2) + struct.pack('!BBH', 0x80, 195, 1) + u32(S1))
    # packet length shorter than the content (RR claims count 3, has 0)
    add('rr_count3', struct.pack('!BBH', 0x83, 201, 1) + u32(S2))
    return c, P

def main(outd, verbose=False):
    c, P, m, MP = build_main()
    c.write(os.path.join(outd, 'rtcp-coverage.pcap'))
    build_malformed(m, MP)
    m.write(os.path.join(outd, 'rtcp-coverage-malformed.pcap'))
    if verbose:
        for k, v in sorted(P.items(), key=lambda kv: kv[1]):
            print(v, k)

main(sys.argv[1] if len(sys.argv) > 1 else '.', '-v' in sys.argv)
