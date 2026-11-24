# Generates test/captures/fcip_coverage.pcap.gz
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

class Flow:
    '''One TCP connection without handshake: client 192.0.2.1:cport ->
    server 192.0.2.2:sport; every c() is one segment.'''
    def __init__(self, cport, sport, frames):
        self.cport, self.sport, self.frames = cport, sport, frames
        self.cseq, self.sseq = 1000, 5000
    def c(self, data):
        self.frames.append(tcp4(data, self.cport, self.sport, seq=self.cseq, ack=self.sseq))
        self.cseq += len(data)
    def s(self, data):
        self.frames.append(tcp4(data, self.sport, self.cport, seq=self.sseq, ack=self.cseq,
                                src='192.0.2.2', dst='192.0.2.1'))
        self.sseq += len(data)

def eofword(eof): return bytes([eof, eof, (~eof) & 0xff, (~eof) & 0xff])
def sofword(sof): return bytes([sof, sof, (~sof) & 0xff, (~sof) & 0xff])

def encap(body, pflags=0, words=None, flags=0, tsec=0, tusec=0, crc=0, proto_c=None):
    '''28 octet encapsulation header + body (the body includes the EOF word).'''
    if words is None:
        words = (28 + len(body)) // 4
    wfield = (flags << 8 & 0xfc00) | (words & 0x3ff)
    wc = ((~(flags << 8)) & 0xfc00) | ((~words) & 0x3ff)
    hdr = bytes([1, 1, 0xfe, 0xfe, 1, 1, 0xfe, 0xfe, pflags, 0, (~pflags) & 0xff, 0xff]) + \
          struct.pack('>HHIII', wfield, wc, tsec, tusec, crc)
    return hdr + body

def fcip_frame(fc, sof=0x2E, eof=0x42, **kw):
    body = sofword(sof) + fc + struct.pack('<I', zlib.crc32(fc) & 0xffffffff) + eofword(eof)
    return encap(body, **kw)

def special(wwn_s, wwn_d, flags=0x40, code=0x0002, katov=7000, ch=False):
    body = bytes(4) + wwn_s + bytes([0x11] * 8) + bytes([0x22] * 8) + bytes([flags, 0]) + \
           struct.pack('>H', code) + bytes(2) + wwn_d + struct.pack('>I', katov)
    body += bytes(48 - len(body)) + eofword(0x41)
    return encap(body, pflags=0x81 if ch else 0x01)

def xfer_rdy(ro, oxid):
    return fchdr(0x05, A, B, 0x08, RESP | LAST | SEQLAST, oxid) + struct.pack('>II', ro, 0x1000)
def abts(oxid):
    return fchdr(0x81, A, B, 0x00, FIRST | LAST | SEQLAST, oxid, param=1)
def ack1(oxid):
    return fchdr(0xC0, B, A, 0x00, LAST | SEQLAST, oxid, 0x2000, param=0x80000000)
def els_logo(oxid):
    return fchdr(0x22, B, A, 0x01, FIRST | SEQLAST | XFER, oxid) + bytes([0x05, 0, 0, 0, 0, 0x01, 0x02, 0x03]) + bytes([0x20, 0, 0, 0, 0x21, 0, 0, 0x01])

frames = []
f = Flow(50010, 3225, frames)

# 1. One frame per segment: every SOF with every EOF
sofs = [0x28, 0x29, 0x2D, 0x2E, 0x31, 0x35, 0x36, 0x39]
eofs = [0x41, 0x42, 0x44, 0x46, 0x49, 0x4E, 0x4F, 0x50]
for i, (sof, eof) in enumerate(zip(sofs, eofs)):
    f.c(fcip_frame(xfer_rdy(0x1000 + i, 0x100 + i), sof, eof,
                   tsec=1700000000 + i, tusec=500 * i, crc=0 if i % 2 else 0xdeadbeef))
# the same SOFs/EOFs in the other order, so each EOF follows another SOF
for i, (sof, eof) in enumerate(zip(sofs, eofs[::-1])):
    f.s(fcip_frame(xfer_rdy(0x2000 + i, 0x200 + i), sof, eof))
# Different FC frame types, flags field and a frame with no payload
f.c(fcip_frame(abts(0x300)))
f.s(fcip_frame(ack1(0x300)))
f.c(fcip_frame(els_logo(0x301), flags=0x3f))
# Special frames (FLOGI-like connection establishment), plain and with the changed flag
f.c(special(bytes([0x20, 0, 0, 0xde, 0xad, 0xbe, 0xef, 1]), bytes([0x20, 0, 0, 0xca, 0xfe, 0xba, 0xbe, 2])))
f.s(special(bytes([0x20, 0, 0, 0xca, 0xfe, 0xba, 0xbe, 2]), bytes([0x20, 0, 0, 0xde, 0xad, 0xbe, 0xef, 1]),
            flags=0xc0, code=0x0102, katov=0, ch=True))
# Changed flag on an ordinary frame
f.c(fcip_frame(xfer_rdy(0x3000, 0x302), pflags=0x80))

# 2. Several frames in one segment (the fix: every frame was shown like the first one)
f.c(fcip_frame(xfer_rdy(0x11111111, 0x10), 0x2E, 0x41) + fcip_frame(xfer_rdy(0x22222222, 0x20), 0x2D, 0x42))
f.c(b''.join(fcip_frame(xfer_rdy(0x33333330 + i, 0x30 + i), 0x2E, 0x42 if i % 2 else 0x41) for i in range(5)))
f.s(fcip_frame(abts(0x401)) + special(bytes(8), bytes(8)) + fcip_frame(ack1(0x401), 0x36, 0x50))
# a single frame preceded by 4 octets of garbage (the header is not at offset 0)
f.c(b'\xde\xad\xbe\xef' + fcip_frame(xfer_rdy(0x44444444, 0x40)))

# 3. Bad headers in front of a good frame: the search skips them byte by byte
good = lambda ro: fcip_frame(xfer_rdy(ro, 0x600))
bad_len_short = encap(sofword(0x2E) + xfer_rdy(1, 1) + bytes(4) + eofword(0x42), words=14)
bad_len_long = encap(sofword(0x2E) + xfer_rdy(1, 1) + bytes(4) + eofword(0x42), words=600)
bad_compl = bytearray(fcip_frame(xfer_rdy(2, 2))); bad_compl[14:16] = b'\x00\x01'
bad_eof = fcip_frame(xfer_rdy(3, 3), eof=0x43)             # not a legal EOF
bad_eof_c = bytearray(fcip_frame(xfer_rdy(4, 4))); bad_eof_c[-2] = 0x00   # EOF complement wrong
bad_eof_rep = bytearray(fcip_frame(xfer_rdy(5, 5))); bad_eof_rep[-3] = 0x77  # EOF replica wrong
bad_eof_rep2 = bytearray(fcip_frame(xfer_rdy(5, 5))); bad_eof_rep2[-4 + 1] = 0x00
bad_d = bytearray(fcip_frame(xfer_rdy(6, 6))); bad_d[9] = 1
bad_d2 = bytearray(fcip_frame(xfer_rdy(7, 7))); bad_d2[11] = 0
bad_next = fcip_frame(xfer_rdy(8, 8)) + bytes(range(64, 64 + 40))   # next header does not match
for n, bad in enumerate([bad_len_short, bad_len_long, bytes(bad_compl), bad_eof, bytes(bad_eof_c),
                         bytes(bad_eof_rep), bytes(bad_eof_rep2), bytes(bad_d), bytes(bad_d2)]):
    f.c(bad + good(0x6000 + n))
# bad next header: first frame fails the next-header check, second one is accepted
f.c(bad_next + good(0x6100))

# 4. Reassembly
fr = fcip_frame(xfer_rdy(0x7001, 0x701))
f.c(fr[:40]); f.c(fr[40:])                  # header complete, body split
fr = fcip_frame(els_logo(0x702))
f.s(fr[:40]); f.s(fr[40:55]); f.s(fr[55:70]); f.s(fr[70:])   # four segments
two = fcip_frame(xfer_rdy(0x7002, 0x703)) + fcip_frame(xfer_rdy(0x7003, 0x704), 0x2D, 0x41)
f.c(two[:50]); f.c(two[50:])               # second frame split, first complete
sp = special(bytes(8), bytes([1] * 8))
f.c(sp[:40]); f.c(sp[40:])                  # special frame reassembled
big = fcip_frame(xfer_rdy(0x7004, 0x705)) + fcip_frame(xfer_rdy(0x7005, 0x706))
f.c(big[:70]); f.c(big[70:110]); f.c(big[110:])   # frame boundary inside later segments
write_pcap(out + '/fcip-coverage.pcap', frames)

# Other captures/paths: no handshake; Decode As on port 4000, frames cut by the
# capture, a frame whose length is larger than the data without desegmentation
mal = []
g = Flow(50011, 4000, mal)
g.c(fcip_frame(xfer_rdy(0x9000, 0x900)))
g.c(fcip_frame(xfer_rdy(0x9001, 0x901)) + fcip_frame(xfer_rdy(0x9002, 0x902)))
fr = fcip_frame(xfer_rdy(0x9003, 0x903)); g.c(fr[:50]); g.c(fr[50:])
g.c(special(bytes(8), bytes(8)))
# on the FCIP port, but no frame can be found
nport = [50020]
def newflow():
    nport[0] += 1
    return Flow(nport[0], 3225, mal)
newflow().c(b'\x99' * 100)
newflow().c(b'\x01\x01\xfe\xfe\x01\x01\xfe\xfe' + bytes(40))
newflow().c(b'\x01\x01\xfe\xfe\x01\x01')            # fewer than 28 octets
# a valid frame followed by 40 octets that are not FCIP is rejected (next header check)
newflow().c(fcip_frame(xfer_rdy(0x55555555, 0x50)) + b'\x99' * 40)
# reassembly is only requested when more than 28 octets of the frame are present
x = newflow(); fr = fcip_frame(xfer_rdy(0x7000, 0x700)); x.c(fr[:10]); x.c(fr[10:])
x = newflow(); fr = fcip_frame(xfer_rdy(0x7100, 0x710)); x.c(fr[:28]); x.c(fr[28:])
x = newflow(); big = fcip_frame(xfer_rdy(0x7004, 0x705)) + fcip_frame(xfer_rdy(0x7005, 0x706))
x.c(big[:90]); x.c(big[90:])
# a frame cut by the capture (caplen < len), twice with the last EOF missing
cap = fcip_frame(xfer_rdy(0x9100, 0x910))
raw = tcp4(cap, 50013, 3225)
with open(out + '/fcip-coverage-malformed.pcap', 'wb') as fo:
    fo.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    allf = [(x, len(x)) for x in mal] + [(raw[:-10], len(raw)), (raw[:-30], len(raw)),
            (raw[:14 + 20 + 20 + 40], len(raw))]
    for i, (x, l) in enumerate(allf):
        fo.write(struct.pack('<IIII', 1700000000 + i, 0, len(x), l)); fo.write(x)
