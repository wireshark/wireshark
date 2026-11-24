# Generates test/captures/fcels_coverage.pcap.gz
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
mal = []
ox = [0x4000]

FFFFFE = bytes([0xff, 0xff, 0xfe])
ZERO3 = bytes(3)
X = bytes([0x01, 0x00, 0x01])      # initiator port
Y = bytes([0x01, 0x00, 0x02])      # target port

def w(n): return bytes([0x20, 0, 0, 0xde, 0xad, 0, 0, n])
def p4(b): return b + bytes(-len(b) % 4)

def els_req(payload, d=Y, s=X, oxid=None, fr=None):
    return fcoe(fchdr(0x22, d, s, 0x01, FIRST | SEQLAST | XFER, oxid) + p4(payload))

def els_rsp(payload, d=X, s=Y, oxid=None, rctl=0x23):
    return fcoe(fchdr(rctl, d, s, 0x01, RESP | LAST | SEQLAST, oxid, 0x2000) + p4(payload))

def pair(req, acc, d=Y, s=X, to=None, fr=None, new_ox=True):
    '''A request from s to d and its accept (or reject) from d to s.'''
    fr = frames if fr is None else fr
    if new_ox:
        ox[0] += 1
    fr.append(els_req(req, d, s, ox[0]))
    if acc is not None:
        fr.append(els_rsp(acc, s, d, ox[0]))

ACC = bytes([0x02, 0, 0, 0])

# ---- login: common service parameters, 4 classes, vendor version, service availability
def logi(op, cmn_flags=0x8800, cls_flags=(0x8000, 0xc000, 0x8000, 0x0000), svcvld=False, long_form=False):
    flags = cmn_flags | (1 if svcvld else 0)
    b = bytes([op, 0, 0, 0])
    b += bytes([0x20, 0x20])                       # FC-PH versions (high/low)
    b += struct.pack('>H', 16)                     # B2B credit
    b += struct.pack('>H', flags)                  # common features
    b += struct.pack('>H', 0x0800)                 # receive data field size (also BB_SC_N)
    b += struct.pack('>HH', 0x00ff, 0x0000)        # concurrent sequences, relative offset
    b += struct.pack('>I', 10000)                  # E_D_TOV
    b += w(1) + w(2)                               # N_Port name, node name
    for i, cf in enumerate(cls_flags):
        c = struct.pack('>H', cf)
        if cf & 0x8000:
            c += struct.pack('>HHHHHH', 0x8003 + i, 0x3a1f, 0x0800, 0x00ff, 0x00ff, 0x0007) + bytes(2)
        else:
            c += bytes(14)
        b += c.ljust(16, b'\0')
    b += bytes(range(16))                          # vendor version level
    if long_form:
        b = b.ljust(132, b'\0') + w(9)
        b = b.ljust(256, b'\0')
    return b

for op, name, sflags in ((0x03, 'PLOGI', 0xffff), (0x04, 'FLOGI', 0xffff), (0x50, 'PDISC', 0x7f7e), (0x51, 'FDISC', 0xfffe)):
    d = FFFFFE if op in (0x04, 0x51) else Y
    s = ZERO3 if op == 0x04 else X
    pair(logi(op, sflags & 0xfffe), logi(0x02, 0x3800), d=d, s=s)
# the accept to FLOGI is from the fabric to the address it assigned
pair(logi(0x03, 0x0000, (0, 0, 0, 0)), logi(0x02, 0xfffe, (0xffff,) * 4))       # all flags, all classes
pair(logi(0x03, 0x0001, svcvld=True, long_form=True), logi(0x02, 0x0001, svcvld=True, long_form=True))  # 256 octets, service availability
pair(logi(0x04, 0x0001, svcvld=True, long_form=True), logi(0x02, 0xfffe, (0xffff,) * 4), d=FFFFFE, s=ZERO3)
pair(logi(0x04, 0x8800), logi(0x02, 0x8800), d=FFFFFE, s=bytes([0, 0, 0x05]))    # FLOGI from a loop port (ALPA 5)
pair(logi(0x50, 0xfffe, (0xffff,) * 4), logi(0x02, 0xfffe, (0xffff,) * 4))
pair(logi(0x51, 0xfffe, (0xffff,) * 4), logi(0x02, 0, (0, 0, 0, 0)), d=FFFFFE)

# ---- LOGO, ABTX, RSI, RRQ, REC
pair(bytes([0x05, 0, 0, 0, 0]) + Y + w(2), ACC)
pair(bytes([0x06, 0, 0, 0, 0x80]) + Y + struct.pack('>HH', 0x1111, 0x2222), ACC)
pair(bytes([0x0A, 0, 0, 0, 0x80]) + Y + struct.pack('>HH', 0x3333, 0x4444), ACC)
pair(bytes([0x12, 0, 0, 0, 0]) + Y + struct.pack('>HH', 0x5555, 0x6666), ACC)
pair(bytes([0x13, 0, 0, 0, 0]) + Y + struct.pack('>HH', 0x7777, 0x8888),
     bytes([0x02, 0, 0, 0]) + struct.pack('>HH', 0x7777, 0x8888) + bytes([0]) + X + bytes([0]) + Y +
     struct.pack('>I', 0x08000000) + struct.pack('>I', 0xa0020000) + bytes(4))
# commands without a decoder: RTV, RLS, ECHO, TEST, SRR, LINIT, LKA
for op in (0x0E, 0x0F, 0x10, 0x11, 0x14, 0x70, 0x80):
    pair(bytes([op, 0, 0, 0]) + bytes(range(16)), bytes([0x02, 0, 0, 0]) + bytes(range(16, 36)))

# ---- PRLI / PRLO / TPRLO with SCSI and other pages
def page(typ, flags, orig=0x11112222, resp=0x33334444, tail=bytes(4), ext=0):
    return bytes([typ, ext, flags, 0]) + struct.pack('>II', orig, resp) + tail
def prl(op, pages, resp=False):
    body = b''.join(pages)
    return bytes([op, 0x10]) + struct.pack('>H', len(body) + 4) + body
scsi_tail = struct.pack('>I', 0x0000003f)
pair(prl(0x20, [page(8, 0x80, tail=scsi_tail), page(0x05, 0x60), page(8, 0x20, tail=struct.pack('>I', 0x00000012))]),
     prl(0x02, [page(8, 0x21, tail=scsi_tail), page(0x05, 0x01, tail=struct.pack('>I', 0xffffffff)), page(0x05, 0x02), page(8, 0x01, tail=struct.pack('>I', 0x00000002))]))
pair(prl(0x21, [page(8, 0xa0, tail=scsi_tail), page(0x05, 0xe0)]), prl(0x02, [page(8, 0x21, tail=scsi_tail), page(0x05, 0x01)]))
pair(prl(0x24, [page(8, 0xf0, tail=bytes([0, 1, 2, 3])), page(0x05, 0x70, tail=bytes([0, 1, 2, 3]))]),
     prl(0x02, [page(8, 0x21, tail=bytes([0, 1, 2, 3]))]))
pair(prl(0x20, []), prl(0x02, []))

# ---- ADISC, FARP, FAN
pair(bytes([0x52, 0, 0, 0, 0]) + Y + w(1) + w(2) + bytes(1) + Y, bytes([0x02, 0, 0, 0, 0]) + Y + w(2) + w(3) + bytes(1) + X)
def farp(op):
    return bytes([op, 0, 0, 0, 0x03]) + Y + bytes([0x01]) + X + w(1) + w(2) + w(3) + w(4) + \
        bytes(range(16)) + bytes(range(16, 32))
pair(farp(0x54), farp(0x55))
pair(bytes([0x60, 0, 0, 0, 0]) + FFFFFE + w(5) + w(6), None)

# ---- RPS (request by node name / port number / neither; accept with and without the L_Port extension)
pair(bytes([0x56, 0, 0, 0x02]) + w(1), struct.pack('>I', 0x02000000) + bytes(1) + struct.pack('>H', 0x0003) +
     b''.join(struct.pack('>I', 100 + i) for i in range(6)) + bytes(34))
pair(bytes([0x56, 0, 0, 0x01, 0, 0, 0, 0x2a]) + bytes(4), struct.pack('>I', 0x02000001) + bytes(1) + struct.pack('>H', 0x0005) +
     b''.join(struct.pack('>I', 200 + i) for i in range(6)) + bytes(2) + struct.pack('>H', 0x0001) + bytes(2) + bytes([0x12]) +
     b''.join(struct.pack('>I', 300 + i) for i in range(6)) + bytes(4))
pair(bytes([0x56, 0, 0, 0x00]) + bytes(8), struct.pack('>I', 0x02000000) + bytes(1) + struct.pack('>H', 0x0001) + bytes(40))

# ---- RPL: request and an accept with three port blocks
pair(bytes([0x57, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0x01]) + bytes(4),
     bytes([0x02, 0, 0, 0x34, 0, 0, 0, 3, 0, 0, 0, 0]) +
     b''.join(struct.pack('>I', i) + bytes([0]) + bytes([1, 0, i]) + w(i) for i in range(1, 4)) + bytes(12))
pair(bytes([0x57, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0]) + bytes(4),
     bytes([0x02, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0]) + bytes(12))

# ---- RSCN: pages with every address format and event qualifier
pages = b''.join(bytes([(q << 6) | f, 1, 2, 3]) for q, f in ((0, 0), (0, 1), (0, 2), (1, 0), (2, 2), (3, 1)))
pair(bytes([0x61, 4]) + struct.pack('>H', 4 + len(pages)) + pages, ACC)
pair(bytes([0x61, 4]) + struct.pack('>H', 4) + bytes(0), ACC)
# SCR with each registration function
for fn in (1, 2, 3, 0xff):
    pair(bytes([0x62, 0, 0, 0, 0, 0, 0, fn]), ACC)
# RNFT: request and accept with a list of FC-4 types
pair(bytes([0x63, 0, 0, 0x20, 0, 0, 0, 0x01]),
     bytes([0x02, 0, 0, 0x10, 0, 3, 0, 1]) + bytes([8, 0, 0, 1, 5, 0, 0, 2, 0x20, 0, 0, 3]))
# LSTS accept
pair(bytes([0x72, 0, 0, 0]), bytes([0x02, 0, 0, 0, 0, 1, 1, 2]) + bytes(range(16)) + bytes(range(16, 32)) + bytes(range(128)) )
# RNID: request (format DF and 0x00), accept with the DF format and a general one
pair(bytes([0x78, 0, 0, 0, 0xdf, 0, 0, 0]),
     bytes([0x02, 0, 0, 0, 0xdf, 0x10, 0, 0x20]) + w(1) + w(2) + bytes(range(16)) + struct.pack('>III', 3, 0x11, 0x22) +
     bytes([4, 4]) + struct.pack('>H', 80) + bytes(range(100, 116)) + struct.pack('>H', 0x1234) + bytes(2))
pair(bytes([0x78, 0, 0, 0, 0x00, 0, 0, 0]),
     bytes([0x02, 0, 0, 0, 0x00, 0x00, 0, 0x00]) + bytes(12))
pair(bytes([0x78, 0, 0, 0, 0x01, 0, 0, 0]),
     bytes([0x02, 0, 0, 0, 0x01, 0x10, 0, 0x00]) + w(1) + w(2))
# RLIR (no decoding)
pair(bytes([0x79, 0, 0, 0]) + bytes(16), ACC)
# LIRR (the reproducer: registration function 0x01 and format 0x08 sit in the second and third octet of the payload)
pair(bytes([0x7A, 0, 0, 0, 0x01, 0x08, 0, 0]), bytes([0x02, 0, 0, 0, 0, 0, 0, 0]))
pair(bytes([0x7A, 0, 0, 0, 0x02, 0x00, 0, 0]), bytes([0x02, 0, 0, 0, 0, 0, 0, 0]))
pair(bytes([0x7A, 0, 0, 0, 0xfe, 0x04, 0, 0]), bytes([0x02, 0, 0, 0, 0, 0, 0, 0]))
# SRL, RPSC
pair(bytes([0x7B, 0, 0, 0, 0x01]) + FFFFFE, ACC)
pair(bytes([0x7B, 0, 0, 0, 0x00]) + FFFFFE, ACC)
pair(bytes([0x7D, 0, 0, 0]), bytes([0x02, 0, 0, 2, 0x70, 0x00, 0x20, 0x00, 0xb0, 0x00, 0x40, 0x00]))
pair(bytes([0x7D, 0, 0, 0]), bytes([0x02, 0, 0, 0]))

# ---- iFCP CBIND / UNBIND (the length tells request from response)
# the dissector expects the 4 octet FC CRC in the length: request 28+4, response 36+4; UNBIND 20+4, 24+4
cb_core = bytes([0xE0, 0, 0, 0]) + struct.pack('>HBB', 60, 1, 2) + struct.pack('>I', 0xaabbccdd) + w(1) + w(2)
cb_req = cb_core + bytes(4)
cb_rsp = cb_core + bytes(2) + struct.pack('>H', 3) + bytes(2) + struct.pack('>H', 0x7766) + bytes(4)
ub_core = bytes([0xE4, 0, 0, 0]) + struct.pack('>I', 0x11223344) + bytes(2) + struct.pack('>H', 0x7766) + bytes(8)
ub_req = ub_core + bytes(4)
ub_rsp = ub_core + bytes(2) + struct.pack('>H', 1) + bytes(4)
pair(cb_req, cb_rsp, fr=None)
pair(ub_req, ub_rsp)

# ---- LS_RJT for requests of several kinds, with every reason and detail
rjt = lambda code, det, vnd=0: bytes([0x01, 0, 0, 0, 0, code, det, vnd])
dets = [0x00, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0E, 0x0F, 0x11, 0x13, 0x15, 0x17, 0x19, 0x1E, 0x1F, 0x21, 0x23,
        0x25, 0x27, 0x29, 0x2A, 0x2C, 0x2D, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x40, 0x41, 0x42, 0x44, 0x48, 0x62, 0x7e]
codes = [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0E, 0x20, 0xFF, 0x02]
for i, det in enumerate(dets):
    code = codes[i % len(codes)]
    req = (logi(0x03), prl(0x20, [page(8, 0x80, tail=scsi_tail)]),
           bytes([0x52, 0, 0, 0, 0]) + Y + w(1) + w(2) + bytes(1) + Y, bytes([0x05, 0, 0, 0, 0]) + Y + w(2))[i % 4]
    pair(req, rjt(code, det, i))
# the exchange reused for a second request
ox[0] += 1
frames.append(els_req(bytes([0x05, 0, 0, 0, 0]) + Y + w(2), oxid=ox[0]))
frames.append(els_rsp(ACC, X, Y, ox[0]))
frames.append(els_req(bytes([0x7B, 0, 0, 0, 0x01]) + FFFFFE, oxid=ox[0]))
frames.append(els_rsp(rjt(0x03, 0x01), X, Y, ox[0]))
# LS_RJT with no request in the capture
ox[0] += 1
frames.append(els_rsp(rjt(0x01, 0x00), X, Y, ox[0]))
write_pcap(out + '/fcels-coverage.pcap', frames)

# ---------------------------------------------------------------------------
# Malformed capture: accepts with no record, truncated payloads, counts larger than the data
ox[0] = 0x6000
def mp(req, acc, d=Y, s=X):
    pair(req, acc, d=d, s=s, fr=mal)

# an ACC with no request in the capture, and an ACC for an exchange another protocol opened
ox[0] += 1
mal.append(els_rsp(bytes([0x02, 0, 0, 0]) + bytes(8), X, Y, ox[0]))
ox[0] += 1
mal.append(fcoe(fchdr(0x02, Y, X, 0x20, FIRST | SEQLAST | XFER, ox[0]) + bytes([1, 0, 0, 0, 0xFA, 1, 0, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 0])))   # FC-CT request makes a conversation
mal.append(els_rsp(bytes([0x02, 0, 0, 0]) + bytes(8), X, Y, ox[0]))
# truncated requests and accepts for every decoded opcode: only the opcode is present
for op in (0x03, 0x04, 0x05, 0x06, 0x0A, 0x12, 0x13, 0x20, 0x21, 0x24, 0x50, 0x51, 0x52, 0x54, 0x55, 0x56, 0x57, 0x60,
           0x61, 0x62, 0x63, 0x72, 0x78, 0x7A, 0x7B, 0x7D, 0xE0, 0xE4, 0x01):
    mp(bytes([op, 0, 0, 0]), bytes([0x02, 0, 0, 0]))
# the same with request bodies that are complete, so only the accept is cut
for op, body in ((0x13, bytes(8)), (0x52, bytes(24)), (0x54, bytes(72)), (0x56, bytes(4)), (0x57, bytes(8)),
                 (0x78, bytes(4)), (0x72, bytes(4)), (0x60, bytes(20)), (0x7D, bytes(0))):
    mp(bytes([op, 0, 0, 0]) + body, bytes([0x02, 0, 0, 0, 0, 0]))
# lists longer than the data
mp(bytes([0x57, 0, 0, 0]) + bytes(8), bytes([0x02, 0, 0, 0x20, 0, 0xff, 0xff, 0xff]) + bytes(4) + bytes(32))          # RPL
mp(bytes([0x61, 4, 0xff, 0xff]) + bytes(8), ACC)                                                                         # RSCN
mp(bytes([0x63, 0, 0, 0]) + bytes(4), bytes([0x02, 0, 0, 0x10, 0, 0xff, 0, 0]) + bytes(8))                               # RNFT
mp(bytes([0x20, 0x10, 0xff, 0xff]) + page(8, 0x80, tail=scsi_tail), prl(0x02, []))                                      # PRLI
mp(bytes([0x7D, 0, 0, 0]), bytes([0x02, 0, 0xff, 0xff]) + bytes(8))                                                      # RPSC
mp(bytes([0x56, 0, 0, 0x01]) + bytes(8), struct.pack('>I', 0x02000001) + bytes(20))                                     # RPS, L_Port extension cut
# FLOGI accepts and LS_RJT shorter than their format
mp(logi(0x04), bytes([0x02, 0, 0, 0]) + bytes(20), d=FFFFFE, s=ZERO3)
mp(logi(0x03, 0x0001, svcvld=True), logi(0x02, 0x0001, svcvld=True))                                                     # service availability beyond 116 octets
mp(bytes([0x05, 0, 0, 0, 0]) + Y + w(2), bytes([0x01, 0, 0, 0, 0]))                                                      # LS_RJT cut
# CBIND / UNBIND with a length the dissector does not know
mp(bytes([0xE0, 0, 0, 0]) + bytes(8), ACC)
write_pcap(out + '/fcels-coverage-malformed.pcap', mal)
