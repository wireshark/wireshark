# Generates test/captures/fcgi_coverage.pcap.gz
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

class Flow:
    '''One TCP connection (client 192.0.2.1:cport -> server 192.0.2.2:sport).'''
    def __init__(self, cport, sport, frames):
        self.cport, self.sport, self.frames = cport, sport, frames
        self.cseq, self.sseq = 1000, 5000
        # No handshake: the capture starts in the middle of the connection
    def c(self, data):
        self.frames.append(tcp4(data, self.cport, self.sport, seq=self.cseq, ack=self.sseq))
        self.cseq += len(data)
    def s(self, data):
        self.frames.append(tcp4(data, self.sport, self.cport, seq=self.sseq, ack=self.cseq,
                                src='192.0.2.2', dst='192.0.2.1'))
        self.sseq += len(data)

def rec(rtype, rid, content=b'', pad=0, ver=1):
    return struct.pack('>BBHHBB', ver, rtype, rid, len(content), pad, 0) + content + bytes(pad)

def nv(name, value, long_name=False, long_value=False):
    n = name.encode(); v = value.encode()
    o = struct.pack('>I', len(n) | 0x80000000) if (long_name or len(n) > 127) else bytes([len(n)])
    o += struct.pack('>I', len(v) | 0x80000000) if (long_value or len(v) > 127) else bytes([len(v)])
    return o + n + v

def begin(role, flags): return struct.pack('>HB5x', role, flags)
def end(app, proto): return struct.pack('>IB3x', app, proto)

f = Flow(50000, 9000, frames)
# FCGI_GET_VALUES (names only, empty values) and its result
f.c(rec(9, 0, nv('FCGI_MAX_CONNS', '') + nv('FCGI_MAX_REQS', '') + nv('FCGI_MPXS_CONNS', '')))
f.s(rec(10, 0, nv('FCGI_MAX_CONNS', '10') + nv('FCGI_MAX_REQS', '50') + nv('FCGI_MPXS_CONNS', '0')))
# request 1: responder, keep connection; params with long (4 octet) lengths
f.c(rec(1, 1, begin(1, 1)))
f.c(rec(4, 1, nv('REQUEST_METHOD', 'POST') + nv('SCRIPT_NAME', '/index.php') +
        nv('HTTP_COOKIE', 'a=' + 'b' * 198, long_name=False) +
        nv('QUERY_STRING', 'x=1', long_name=True, long_value=True)))
f.c(rec(4, 1))                                   # empty PARAMS ends the stream
f.c(rec(5, 1, b'name=value&other=thing', pad=2))  # STDIN with padding
f.c(rec(5, 1))                                   # empty STDIN
f.s(rec(6, 1, b'Content-Type: text/html\r\n\r\n<html>hello</html>', pad=3))
f.s(rec(7, 1, b'PHP Notice: something', pad=3))
f.s(rec(6, 1))
f.s(rec(3, 1, end(0, 0)))
# request 2: abort and every protocol status of END_REQUEST, other roles
f.c(rec(1, 2, begin(2, 0)))                       # authorizer, no keep conn
f.c(rec(2, 2))                                    # ABORT_REQUEST
f.c(rec(2, 2, b'\0' * 4, pad=4))                  # ABORT_REQUEST with content
f.s(rec(3, 2, end(1, 1)))                         # FCGI_CANT_MPX_CONN
f.s(rec(3, 2, end(0xffffffff, 2)))                # FCGI_OVERLOADED
f.s(rec(3, 2, end(0x01020304, 3)))                # FCGI_UNKNOWN_ROLE
f.s(rec(3, 2, end(7, 0x77)))                      # unknown status
f.c(rec(1, 3, begin(3, 0)))                       # filter
f.c(rec(8, 3, b'file data to filter'))            # FCGI_DATA
f.c(rec(1, 4, begin(9, 0x81)))                    # unknown role, other flag bit
# several records in one segment (BEGIN, PARAMS, STDIN)
f.c(rec(1, 5, begin(1, 0)) + rec(4, 5, nv('A', 'B')) + rec(4, 5) + rec(5, 5, b'zz', pad=6))
# one record split in two segments (inside the header, then inside the content)
r = rec(4, 5, nv('SPLIT_NAME', 'split value that spans segments'), pad=1)
f.c(r[:5]); f.c(r[5:20]); f.c(r[20:])
# two records, the second one split
r = rec(5, 5, b'first') + rec(5, 5, b'second record is split')
f.c(r[:20]); f.c(r[20:])
# a record split over segments from the server side
r = rec(6, 5, b'x' * 300, pad=4)
f.s(r[:100]); f.s(r[100:])
# unknown types: FCGI_UNKNOWN_TYPE, type 0, 99, other version
f.s(rec(11, 0, bytes([42]) + bytes(7)))
f.c(rec(0, 0, b'\xde\xad'))
f.c(rec(99, 5, b'unknown'))
f.s(rec(6, 5, b'v2', ver=2))
f.s(rec(3, 5, end(0, 0)))
write_pcap(out + '/fcgi-coverage.pcap', frames)

# Malformed: name length beyond the record, short records, truncated
mf = []
g = Flow(50001, 9000, mf)
g.c(rec(4, 1, bytes([200]) + bytes([1]) + b'abc'))          # 4-octet name length cut off
g.c(rec(4, 1, bytes([0x80, 0xff, 0xff, 0xff, 5]) + b'abc'))  # huge name length
g.c(rec(4, 1, bytes([3, 0x80, 0x7f, 0xff, 0xff]) + b'abc' + b'v' * 4))  # huge value length
g.c(rec(9, 0, bytes([4, 3]) + b'name'))                      # value cut off
g.c(rec(1, 1, b'\x00\x01'))                                  # BEGIN_REQUEST, short content
g.c(rec(3, 1, b'\x00\x00'))                                  # END_REQUEST, short content
g.c(rec(5, 1, b'abc')[:10])                                  # STDIN cut by the capture
write_pcap(out + '/fcgi-coverage-malformed.pcap', mf)
