# Generates test/captures/fcfcs_coverage.pcap.gz
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
ox = [0x1000]

def ct(opcode, body=b'', gssub=0x01, gstype=0xFA, rev=1, in_id=b'\x00\x00\x00', maxres=0,
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

def pair(opcode, req=b'', acc=b'', maxres=0, **kw):
    ox[0] += 1
    frames.append(req_frame(ct(opcode, req, maxres=maxres, **kw), ox[0]))
    frames.append(acc_frame(ct(0x8002, acc, **kw), ox[0]))

def w(n): return bytes([0x10, 0, 0, 0xaa, 0, 0, 0, n])
def ustr(s, size=256):           # 1 octet length + string, padded to `size`
    b = s.encode() if isinstance(s, str) else s
    return (bytes([len(b)]) + b).ljust(size, b'\0')
def plat(s): return ustr(s, 0)    # unpadded: length octet + name

# GIEL: two interconnect elements (types switch, hub, bridge, unknown)
pair(0x101, b'', struct.pack('>I', 4) + b''.join(w(i) + bytes([0, 0, 0, t]) for i, t in enumerate([1, 2, 3, 9])))
pair(0x101, b'', struct.pack('>I', 0))                 # empty list
pair(0x111, w(1), bytes([0, 0, 0, 1]))                 # GIET
pair(0x111, w(2), bytes([0, 0, 0, 3]))
pair(0x112, w(1), bytes([0, 0x21, 0, 0]))               # GDID
pair(0x113, w(1), bytes([0, 0xfc, 0x01, 0x0a]))         # GMID
pair(0x114, w(1), w(0x77))                             # GFN
pair(0x115, w(1), ustr('switch-1', 0))                  # GIELN
pair(0x116, w(1), struct.pack('>I', 2) + ustr('http://192.0.2.5/') + ustr('snmp://192.0.2.5'))  # GMAL
pair(0x116, w(1), struct.pack('>I', 0))
# GIEIL: vendor, model, release + vendor specific strings
vend = b'ACME\0' + b'M-1000\0' + b'1.2.3\0' + b'extra info\0' + b'more\0'
pair(0x117, w(1), bytes([0, 0, 0, len(vend)]) + vend)
vend = b'ACME\0' + b'M-1000\0' + b'1.2.3\0'
pair(0x117, w(1), bytes([0, 0, 0, len(vend)]) + vend)  # no vendor specific string
# GPL: ports with module and tx types
ent = lambda n, m, t, p: w(n) + bytes([0, m, t, p])
pair(0x118, w(1), struct.pack('>I', 3) + ent(1, 1, 1, 1) + ent(2, 2, 2, 0x81) + ent(3, 3, 3, 0x84))
pair(0x118, w(1), struct.pack('>I', 0))
pair(0x121, w(5), bytes([0, 0, 0, 0x81]))               # GPT
pair(0x122, w(5), bytes([0, 0, 0, 7]))                  # GPPN
pair(0x124, w(5), struct.pack('>I', 2) + w(9) + bytes([0, 0, 1, 0x01]) + w(10) + bytes([0, 0, 0, 0x7f]))  # GAPNL
pair(0x126, w(5), bytes([0, 0, 0, 0x81, 0, 0, 0, 2]))   # GPS
# platform requests: name length + name
pair(0x191, plat('plat-1'), struct.pack('>I', 2) + w(1) + w(2))     # GPLNL
pair(0x191, plat('plat-2'), struct.pack('>I', 0))
pair(0x192, plat('plat-1'), bytes([0, 0, 0, 5]))                      # GPLT
pair(0x193, plat('plat-1'), struct.pack('>I', 2) + ustr('mgmt://a') + ustr('mgmt://b'))  # GPLML
pair(0x1A1, w(1), plat('plat-1'))                                    # GNPL
pair(0x1A2, b'', struct.pack('>I', 2) + ustr('plat-1') + ustr('platform-two'))   # GPNL
pair(0x215, w(1) + ustr('logical-name', 0), b'')                     # RIELN
# RPL: platform name, type, mgmt addresses and node names
rpl = ustr('plat-1') + struct.pack('>II', 3, 2) + ustr('mgmt://a') + ustr('mgmt://b') + struct.pack('>I', 2) + w(1) + w(2)
pair(0x280, rpl, b'')
rpl = ustr('plat-2') + struct.pack('>II', 4, 0) + struct.pack('>I', 0)
pair(0x280, rpl, b'')
pair(0x291, ustr('plat-1') + w(3), b'')                              # RPLN
pair(0x292, ustr('plat-1') + struct.pack('>I', 5), b'')              # RPLT
pair(0x293, ustr('plat-1') + ustr('mgmt://c', 0), b'')               # RPLM
pair(0x380, plat('plat-1'), b'')                                     # DPL
pair(0x391, w(3), b'')                                               # DPLN
pair(0x393, plat('plat-1'), b'')                                     # DPLML
# GCAP: subtypes FCS, UNS and another one
pair(0xe020, b'', struct.pack('>I', 3) + bytes([1, 0xab, 0xcd, 0xef]) + struct.pack('>I', 0x3) +
     bytes([2, 0, 0, 1]) + struct.pack('>I', 0x1) + bytes([9, 0, 0, 0]) + struct.pack('>I', 0xffffffff))
pair(0xe020, b'', struct.pack('>I', 0))
# opcodes without a decoder: the payload is shown as data
for op in (0x100, 0x128, 0x1B1, 0x7777):
    pair(op, bytes(range(12)), bytes(range(12, 28)))
# the same exchange used for a second request: the stored opcode is replaced
ox[0] += 1
frames.append(req_frame(ct(0x121, w(5)), ox[0])); frames.append(acc_frame(ct(0x8002, bytes([0, 0, 0, 1])), ox[0]))
frames.append(req_frame(ct(0x126, w(5)), ox[0])); frames.append(acc_frame(ct(0x8002, bytes([0, 0, 0, 2, 0, 0, 0, 1])), ox[0]))
# reject for a known request (the failed opcode is shown), for each reason code
for reason, expl, vend in ((1, 0, 0), (2, 0x01, 0), (3, 0x02, 0x44), (4, 0x03, 0), (5, 0x04, 0), (7, 0x7f, 1), (9, 0x10, 0xff)):
    ox[0] += 1
    frames.append(req_frame(ct(0x101), ox[0]))
    frames.append(acc_frame(ct(0x8001, reason=reason, expl=expl, vendor=vend), ox[0]))
# reject without a request in the capture
ox[0] += 1
frames.append(acc_frame(ct(0x8001, reason=1, expl=0x7), ox[0]))
# a request with an opcode in the reserved range above MSG_ACC
ox[0] += 1
frames.append(req_frame(ct(0x8003, bytes(8)), ox[0]))
# CT for another management server (UNS), not decoded by FCS but handled by FC_CT
ox[0] += 1
frames.append(req_frame(ct(0x101, gssub=0x02), ox[0]))
write_pcap(out + '/fcfcs-coverage.pcap', frames)

# Malformed capture: accepts without a record of the request, truncated bodies
mal = []
ox[0] = 0x2000
def orphan_acc(opcode_acc=0x8002):
    ox[0] += 1
    mal.append(acc_frame(ct(opcode_acc, bytes(8)), ox[0]))
orphan_acc()
# an accept whose exchange has a conversation but no stored request
ox[0] += 1
mal.append(req_frame(ct(0x8003, bytes(4)), ox[0]))   # reserved opcode: conversation created
mal.append(acc_frame(ct(0x8002, bytes(8)), ox[0]))   # (reserved opcode was stored, decodes as data)
# an accept for an exchange whose conversation another CT server created
ox[0] += 1
mal.append(req_frame(ct(0x101, gssub=0x02), ox[0]))
mal.append(acc_frame(ct(0x8002, bytes(8)), ox[0]))
# lists with counts larger than the data
def bad(opcode, req, acc):
    ox[0] += 1
    mal.append(req_frame(ct(opcode, req), ox[0])); mal.append(acc_frame(ct(0x8002, acc), ox[0]))
bad(0x101, b'', struct.pack('>I', 1000) + bytes(24))            # GIEL
bad(0x116, w(1), struct.pack('>I', 3) + ustr('x'))              # GMAL
bad(0x117, w(1), bytes([0, 0, 0, 200]) + b'ACME\0M\0R\0v\0')     # GIEIL, list length too big
bad(0x117, w(1), bytes([0, 0, 0, 4]) + b'ACME')                  # GIEIL, no NUL
bad(0x118, w(1), struct.pack('>I', 5) + bytes(12))              # GPL
bad(0x124, w(1), struct.pack('>I', 5) + bytes(12))              # GAPNL
bad(0x191, plat('p'), struct.pack('>I', 9) + w(1))              # GPLNL
bad(0x193, plat('p'), struct.pack('>I', 9) + ustr('m'))         # GPLML
bad(0x1A2, b'', struct.pack('>I', 9) + ustr('p'))               # GPNL
bad(0x192, bytes([200]) + b'abc', bytes([0, 0, 0, 1]))         # platform name longer than data
bad(0x280, ustr('p', 20), b'')                                   # RPL, short
bad(0x280, ustr('p') + struct.pack('>II', 1, 9), b'')            # RPL, address count too big
bad(0x291, ustr('p'), b'')                                       # RPLN, short
bad(0xe020, b'', struct.pack('>I', 100) + bytes(8))             # GCAP
bad(0x101, b'', b'')                                              # GIEL, no body
bad(0x111, b'', b'')                                              # GIET request without name
# reject with a truncated CT header
ox[0] += 1
mal.append(acc_frame(ct(0x8001)[:14], ox[0]))
write_pcap(out + '/fcfcs-coverage-malformed.pcap', mal)
