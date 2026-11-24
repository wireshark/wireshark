# Generates test/captures/fcfzs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import zlib

def write_pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)

def fchdr(r_ctl, d_id, s_id, ftype, f_ctl, oxid, rxid=0xffff, seq_id=0,
          seqcnt=0, param=0, df_ctl=0, cs_ctl=0):
    return (bytes([r_ctl]) + d_id + bytes([cs_ctl]) + s_id + bytes([ftype]) +
            struct.pack('>I', f_ctl)[1:] + bytes([seq_id, df_ctl]) +
            struct.pack('>HHHI', seqcnt, oxid, rxid, param))

def fcoe(fc, sof=0x2E, eof=0x42):
    hdr = bytes(13) + bytes([sof])
    crc = struct.pack('<I', zlib.crc32(fc) & 0xffffffff)
    return eth(hdr + fc + crc + bytes([eof, 0, 0, 0]), 0x8906)

A = bytes([0x01, 0x02, 0x03])
B = bytes([0x01, 0x04, 0x05])
FIRST = 0x200000
LAST = 0x100000
SEQLAST = 0x080000
RESP = 0x800000
XFER = 0x010000

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp4(payload, sport, dport, seq=1000, ack=1, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    sip = bytes(int(x) for x in src.split('.'))
    dip = bytes(int(x) for x in dst.split('.'))
    th = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ph = sip + dip + struct.pack('>BBH', 0, 6, len(th) + len(payload))
    cs = ip_csum(ph + th + payload)
    th = th[:16] + struct.pack('>H', cs) + th[18:]
    tot = 20 + len(th) + len(payload)
    ih = struct.pack('>BBHHHBBH4s4s', 0x45, 0, tot, 1, 0, 64, 6, 0, sip, dip)
    ih = ih[:10] + struct.pack('>H', ip_csum(ih)) + ih[12:]
    return eth(ih + th + payload, 0x0800)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
frames = []
ox = [0x3000]

def ct(opcode, body=b'', gssub=0x03, gstype=0xFA, rev=1, in_id=b'\x00\x00\x00', maxres=0,
       reason=0, expl=0, vendor=0):
    # CT preamble: revision, IN_ID(3), GS_Type, GS_Subtype, Options, Reserved,
    # command/response code(2), max/residual size(2), reserved, reason, explanation, vendor
    body += bytes(-len(body) % 4)        # FC payloads are a multiple of four octets
    return bytes([rev]) + in_id + bytes([gstype, gssub, 0, 0]) + struct.pack('>HH', opcode, maxres) + \
           bytes([0, reason, expl, vendor]) + body

def req_frame(payload, oxid):
    return fcoe(fchdr(0x02, B, A, 0x20, FIRST | SEQLAST | XFER, oxid) + payload)

def acc_frame(payload, oxid):
    return fcoe(fchdr(0x03, A, B, 0x20, RESP | LAST | SEQLAST, oxid, 0x2000) + payload)

def pair(opcode, req=b'', acc=b'', fr=None, **kw):
    fr = frames if fr is None else fr
    ox[0] += 1
    fr.append(req_frame(ct(opcode, req, **kw), ox[0]))
    fr.append(acc_frame(ct(0x8002, acc, **kw), ox[0]))

def w(n): return bytes([0x10, 0, 0, 0xaa, 0, 0, 0, n])
def padname(s):                  # length octet, 3 reserved, name, padding to 4
    b = s.encode()
    return bytes([len(b), 0, 0, 0]) + b + bytes(-len(b) % 4)
def shortname(s):                # length octet + name + (len % 4) fill, as read by GZSN/GZD
    b = s.encode()
    return bytes([len(b)]) + b + bytes(len(b) % 4)
def member(t, ident=None):
    if ident is None:
        ident = w(t)
    return bytes([t, 0, 0, 0]) + ident
def zoneset(name, zones):
    o = padname(name) + struct.pack('>I', len(zones))
    for zn, mbrs in zones:
        o += padname(zn) + struct.pack('>I', len(mbrs)) + b''.join(mbrs)
    return o + bytes(8)          # the LUN members read past their 12 octet record

mbrs_all = [member(1), member(4), member(2, bytes([0, 0x12, 0x34]) + bytes(5)),
            member(3, bytes([0x01, 0x02, 0x03]) + bytes(5)),
            member(0xE1, w(7)), member(0xE2, w(8)), member(0xE3, w(9))]
zs1 = zoneset('ZSET_ONE', [('zone_a', mbrs_all), ('zb', [member(1)]), ('zone_empty', [])])
zs2 = zoneset('ZS', [])

# GZC: capability flags (hard zones, soft zones, zone set database) and vendor flags
for flags in (0xe0, 0x80, 0x40, 0x20, 0x00):
    pair(0x100, b'', bytes([flags, 0, 0, 0]) + struct.pack('>I', 0x00010000 * (flags >> 5)))
# GEST: enforcement state (soft, hard)
for st in (0xc0, 0x80, 0x40, 0x00):
    pair(0x111, b'', bytes([st, 0, 0, 0]) + struct.pack('>I', 0xcafe0000 | st))
# GZSN: zone set list
pair(0x112, b'', struct.pack('>I', 2) + padname('ZSET') + struct.pack('>I', 3) + padname('abc') + struct.pack('>I', 0))
pair(0x112, b'', struct.pack('>I', 0))
# GZD: zone list of a zone set
pair(0x113, shortname('ZSET'), struct.pack('>I', 2) + padname('zone') + struct.pack('>I', 7) + padname('zb') + struct.pack('>I', 1))
pair(0x113, shortname('ZSET'), struct.pack('>I', 0))
# GZM: member list of a zone
pair(0x114, shortname('zone_a'), struct.pack('>I', 4) + b''.join([member(1), member(4), member(2, bytes([0, 1, 2]) + bytes(5)), member(3, bytes([1, 2, 3]) + bytes(5))]))
pair(0x114, shortname('zb'), struct.pack('>I', 0))
# GAZS: the active zone set; GZS: a zone set by name
pair(0x115, b'', zs1)
pair(0x115, b'', zs2)
pair(0x116, padname('ZSET_ONE'), zs1)
pair(0x116, padname('ZS'), zs2)
# ADZS, AZSD: add and activate a zone set definition
pair(0x200, zs1, b'')
pair(0x201, zs2, b'')
# AZS: activate a zone set by name; DZS: deactivate
pair(0x202, padname('ZSET_ONE'), b'')
pair(0x203, b'', b'')
# AZM / RZM: zone name (length octet, 3 reserved, padded name) followed by members
def zmreq(namelen, mbrs):
    return padname('z' * namelen) + b''.join(mbrs)
for op in (0x204, 0x300):
    pair(op, zmreq(4, [member(1), member(4), member(2, bytes([0, 5, 6]) + bytes(5)), member(3, bytes([7, 8, 9]) + bytes(5))]), b'')
pair(0x204, zmreq(8, [member(1)]), b'')
pair(0x300, zmreq(8, []), b'')
# AZD / RZD: zone set name, then zone name, both as length octet, 3 reserved, padded name
zd = padname('ZSET') + padname('abc')
pair(0x205, zd, b'')
pair(0x301, zd, b'')
# RZS: remove zone set
pair(0x302, padname('ZSET_ONE'), b'')
# Opcodes without a decoder
pair(0x7777, bytes(range(12)), bytes(range(12, 28)))
# Reused exchange: GZC then GEST on the same exchange id
ox[0] += 1
frames.append(req_frame(ct(0x100), ox[0])); frames.append(acc_frame(ct(0x8002, bytes([0xe0, 0, 0, 0, 0, 0, 0, 1])), ox[0]))
frames.append(req_frame(ct(0x111), ox[0])); frames.append(acc_frame(ct(0x8002, bytes([0xc0, 0, 0, 0, 0, 0, 0, 2])), ox[0]))
# Rejects for every reason code explanation
for reason, expl in ((1, 0), (1, 0), (2, 0x01), (3, 0x10), (3, 0x11), (3, 0x12), (3, 0x13), (3, 0x14),
                     (3, 0x15), (3, 0x16), (3, 0x17), (3, 0x18), (3, 0x19), (3, 0x1a), (4, 0x7f), (9, 0xff)):
    ox[0] += 1
    frames.append(req_frame(ct(0x116, padname('ZS')), ox[0]))
    frames.append(acc_frame(ct(0x8001, reason=reason, expl=expl, vendor=expl), ox[0]))
# Reject with no request in the capture, and a reserved opcode
ox[0] += 1
frames.append(acc_frame(ct(0x8001, reason=1, expl=0x7), ox[0]))
ox[0] += 1
frames.append(req_frame(ct(0x8003, bytes(8)), ox[0]))
write_pcap(out + '/fcfzs-coverage.pcap', frames)

# Malformed capture: accepts with no record, unknown member types, counts larger than the data
mal = []
ox[0] = 0x5000
ox[0] += 1
mal.append(acc_frame(ct(0x8002, bytes(8)), ox[0]))
ox[0] += 1
mal.append(req_frame(ct(0x100, gssub=0x02), ox[0])); mal.append(acc_frame(ct(0x8002, bytes(8)), ox[0]))
pair(0x114, shortname('z'), struct.pack('>I', 2) + member(0x55) + member(0), fr=mal)         # GZM unknown type
pair(0x115, b'', zoneset('ZS', [('z', [member(0x77), member(0)])]), fr=mal)                   # zoneset unknown type
pair(0x204, zmreq(4, [member(0x66), member(9)]), b'', fr=mal)                                 # AZM unknown type
pair(0x112, b'', struct.pack('>I', 50) + shortname('ZSET'), fr=mal)
pair(0x113, shortname('ZSET'), struct.pack('>I', 50) + shortname('zone'), fr=mal)
pair(0x114, shortname('z'), struct.pack('>I', 50) + member(1), fr=mal)
pair(0x115, b'', padname('ZS') + struct.pack('>I', 50), fr=mal)
pair(0x115, b'', padname('ZS') + struct.pack('>I', 1) + padname('z') + struct.pack('>I', 50), fr=mal)
pair(0x115, b'', bytes([200, 0, 0, 0]) + b'ab', fr=mal)                                       # name longer than the data
pair(0x116, bytes([200, 0, 0, 0]) + b'ab', b'', fr=mal)
pair(0x202, bytes([200, 0, 0, 0]) + b'ab', b'', fr=mal)
pair(0x205, bytes([200, 0, 0, 0]) + b'ab', b'', fr=mal)
pair(0x204, bytes([200]) + b'ab', b'', fr=mal)
pair(0x204, b'', b'', fr=mal)                                                                  # no name at all
pair(0x100, b'', b'', fr=mal)                                                                  # GZC accept, no body
pair(0x111, b'', bytes([0xc0, 0, 0]), fr=mal)
pair(0x113, b'', b'', fr=mal)
ox[0] += 1
mal.append(acc_frame(ct(0x8001)[:14], ox[0]))
write_pcap(out + '/fcfzs-coverage-malformed.pcap', mal)
