#!/usr/bin/env python3
# Generates test/captures/rsvd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds rsvd-coverage.pcap and rsvd-coverage-malformed.pcap: RSVD (MS-RSVD)
# tunnel operations carried in SMB2 IOCTL (FSCTL_SVHDX_SYNC_TUNNEL_REQUEST
# 0x00090304 and the async variant 0x00090364) on TCP 445.
# Usage: mkrsvd.py <outdir> [-v]
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERB = '-v' in sys.argv

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def smb2(cmd, flags, msgid, body, status=0):
    hdr = b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ16s', 64, 1, status, cmd, 1, flags, 0,
                                   msgid, 0xfeff, 1, 0x1122334455667788, b'\0' * 16)
    return hdr + body

def ioctl_rsp(ctl, out):
    return struct.pack('<HHI16sIIIIII', 49, 0, ctl, b'\x11' * 16, 112, 0, 112, len(out), 0, 0) + out

def ioctl_req(ctl, inp):
    return struct.pack('<HHI16sIIIIIIII', 57, 0, ctl, b'\x11' * 16, 120, len(inp), 0,
                       0, 0, 65536, 1, 0) + inp

def rhdr(op, reqid, status=0):
    return struct.pack('<IIQ', op, status, reqid)

class Stream:
    def __init__(self):
        self.seqs = {}
        self.pkts = []
        self.msgid = 1
    def tcp(self, src, dst, sport, dport, payload, flags=0x18):
        key = (sport, dport)
        seq = self.seqs.get(key, 1000 if sport == 445 else 5000)
        self.seqs[key] = seq + len(payload)
        ack = self.seqs.get((dport, sport), 1000 if dport == 445 else 5000)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
        pseudo = struct.pack('!4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        tot = 20 + len(tcp) + len(payload)
        iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot & 0xffff, 1, 0, 64, 6, 0, src, dst)
        iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
        return iph + tcp + payload

CLI = bytes([192, 0, 2, 10]); SRV = bytes([192, 0, 2, 20])
S = Stream()
marks = []

def add(from_client, smb, label=None):
    nb = struct.pack('!I', len(smb)) + smb
    if from_client:
        p = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + S.tcp(CLI, SRV, 49152, 445, nb)
    else:
        p = b'\x02\0\0\0\0\x01\x02\0\0\0\0\x02\x08\x00' + S.tcp(SRV, CLI, 445, 49152, nb)
    S.pkts.append(p)
    if label:
        marks.append((len(S.pkts), label))

def req(data, ctl=0x00090304, label=None):
    S.msgid += 1
    add(True, smb2(0x0b, 0, S.msgid, ioctl_req(ctl, data)), label)

def rsp(data, ctl=0x00090304, label=None):
    add(False, smb2(0x0b, 1, S.msgid, ioctl_rsp(ctl, data)), label)

def pair(rq, rs, ctl=0x00090304, label=None):
    req(rq, ctl, label)
    rsp(rs, ctl)

OP_INFO, OP_SCSI, OP_CHK, OP_SRB, OP_DISK, OP_VAL = (0x02001001 + i for i in range(6))
OP_META, OP_PROG, OP_VHDSET, OP_DELSNAP, OP_SAFE = 0x02002101, 0x02002002, 0x02002005, 0x02002006, 0x0200200D
GUID = bytes(range(16))
GUID2 = bytes(range(16, 32))

# ---- 1-4: simple operations (sync tunnel) ----
rid = [100]
def nid():
    rid[0] += 1
    return rid[0]

# GET_INITIAL_INFO: request has no body, response has the file info
r = nid()
pair(rhdr(OP_INFO, r), rhdr(OP_INFO, r) + struct.pack('<IIIIQ', 2, 512, 4096, 0, 0x40000000), label='GET_INITIAL_INFO')
# CHECK_CONNECTION_STATUS
r = nid()
pair(rhdr(OP_CHK, r), rhdr(OP_CHK, r))
# async variant of the same operation
r = nid()
pair(rhdr(OP_CHK, r), rhdr(OP_CHK, r), ctl=0x00090364)

# GET_DISK_INFO
r = nid()
dreq = struct.pack('<QI16sBBHQ16s', 0, 512, GUID, 1, 0, 0, 0x2000000, GUID2)
dres = struct.pack('<III16sBBHQ16s', 2, 3, 512, GUID, 1, 1, 0, 0x2000000, GUID2)
pair(rhdr(OP_DISK, r) + dreq, rhdr(OP_DISK, r) + dres, label='GET_DISK_INFO')
r = nid()
dres = struct.pack('<III16sBBHQ16s', 3, 4, 4096, GUID2, 0, 0, 0, 0x4000000, GUID)
pair(rhdr(OP_DISK, r) + dreq, rhdr(OP_DISK, r) + dres)
# VALIDATE_DISK
r = nid()
pair(rhdr(OP_VAL, r) + b'\0' * 56, rhdr(OP_VAL, r) + b'\x01', label='VALIDATE_DISK')

# SRB_STATUS: request (28 byte body), response (the fixed SrbStatus bug)
r = nid()
srb_rq = bytes([1]) + b'\0' * 27
srb_rs = bytes([1, 0x81, 0x02, 4]) + b'\x70\0\x05\0'
pair(rhdr(OP_SRB, r) + srb_rq, rhdr(OP_SRB, r) + srb_rs, label='SRB_STATUS (reproducer, response)')
r = nid()
pair(rhdr(OP_SRB, r) + srb_rq, rhdr(OP_SRB, r) + bytes([2, 0x00, 0x00, 0]))

# ---- SCSI ----
def scsi_req(cdb, data_in, dlen, data=b'', srb=0x0, length=36, cdblen=None):
    cdblen = len(cdb) if cdblen is None else cdblen
    padded = cdb + b'\0' * (16 - len(cdb)) if len(cdb) < 16 else cdb
    return (struct.pack('<HHBBBBII', length, 0, cdblen, 20, data_in, 0, srb, dlen)
            + cdb + (b'\0' * (16 - len(cdb)) if len(cdb) < 16 else b'') + b'\0' * 4 + data)

def scsi_rsp(status, data_in, data=b'', sense=b'', auto=0, srb=1, length=36, cdblen=10, dlen=None, sfield=None):
    dlen = len(data) if dlen is None else dlen
    return (struct.pack('<HBBBBBBII', length, (auto << 7) | srb, status, cdblen, len(sense) if sfield is None else sfield,
                        data_in, 0, 0, dlen) + sense + data)

# TEST UNIT READY (6 byte CDB, no data)
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(bytes(6), 2, 0), rhdr(OP_SCSI, r) + scsi_rsp(0, 2, sense=b'\0' * 20), label='SCSI TEST UNIT READY')
# INQUIRY: data in
r = nid()
inq = bytes([0x12, 0, 0, 0, 36, 0])
inqdata = bytes([0, 0, 5, 2, 31, 0, 0, 0]) + b'MSFT    ' + b'Virtual Disk    ' + b'1.0 '
pair(rhdr(OP_SCSI, r) + scsi_req(inq, 1, 36, data=bytes(36)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=inqdata, sense=b'\0' * 20), label='SCSI INQUIRY')
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(inq, 0, 36, data=bytes(36)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=inqdata, sense=b'\0' * 20))
# READ CAPACITY(10)
r = nid()
rc = bytes([0x25]) + b'\0' * 9
pair(rhdr(OP_SCSI, r) + scsi_req(rc, 1, 8, data=bytes(8)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=struct.pack('>II', 0xfffff, 512), sense=b'\0' * 20))
# READ(10) 4 blocks, 2048 bytes
r = nid()
rd = bytes([0x28, 0, 0, 0, 0, 8, 0, 0, 4, 0])
pair(rhdr(OP_SCSI, r) + scsi_req(rd, 1, 2048, data=bytes(2048)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=bytes((i * 7) & 0xff for i in range(2048)), sense=b'\0' * 20), label='SCSI READ(10)')
# WRITE(10) 1024 bytes OUT (data in request), response without data
r = nid()
wr = bytes([0x2a, 0, 0, 0, 0, 16, 0, 0, 2, 0])
pair(rhdr(OP_SCSI, r) + scsi_req(wr, 0, 1024, data=b'\xa5' * 1024), rhdr(OP_SCSI, r) + scsi_rsp(0, 0, sense=b'\0' * 20), label='SCSI WRITE(10)')
# CHECK CONDITION with auto generated sense, sense data with 18 bytes
r = nid()
sense = bytes([0x70, 0, 5, 0, 0, 0, 0, 10]) + b'\0' * 10
pair(rhdr(OP_SCSI, r) + scsi_req(rd, 1, 512, data=bytes(512)), rhdr(OP_SCSI, r) + scsi_rsp(2, 2, sense=sense + b'\0' * 2, auto=1, srb=0x7e))
# 16 byte CDB (READ(16)), response with Length != 36 and a short sense
r = nid()
rd16 = bytes([0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 1, 0, 0])
pair(rhdr(OP_SCSI, r) + scsi_req(rd16, 1, 512, data=bytes(512)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=b'\x11' * 512, sense=b'\0' * 4, length=40), label='SCSI READ(16)')
# response with length 36 and a sense length < 20 (forced to 20)
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(bytes([0x00]) + bytes(5), 2, 0), rhdr(OP_SCSI, r) + scsi_rsp(0, 2, sense=b'\0' * 20, length=36))
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(bytes([0x1b, 0, 0, 0, 1, 0]), 2, 0), rhdr(OP_SCSI, r) + scsi_rsp(0, 2, sense=b'\0' * 20, sfield=5, length=36))
# a response in a conversation without a request first (new task), unknown request id
r = nid()
rsp(rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=b'\x22' * 16, sense=b'\0' * 20))
# SCSI request with data_in == 1 (data not passed to SCSI) and a 0x7f srb status
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(rd, 1, 16, data=b'\x33' * 16), rhdr(OP_SCSI, r) + scsi_rsp(0, 2, srb=0x7f, sense=b'\0' * 20))
# response with more data octets than DataTransferLength says (extra octets are not SCSI data)
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(rd, 1, 16, data=bytes(16)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=b'\x44' * 32, dlen=16, sense=b'\0' * 20), label='SCSI response with extra octets')
# async tunnel SCSI
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(inq, 1, 36, data=bytes(36)), rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=inqdata, sense=b'\0' * 20), ctl=0x00090364)

# The fixed 16-bit length bug: a WRITE(10) with 40000 bytes of data
r = nid()
cdb = bytes([0x2a, 0, 0, 0, 0, 0, 0, 0, 0x4e, 0]) + b'\0' * 6
req(rhdr(OP_SCSI, r) + struct.pack('<HHBBBBII', 36, 0, 10, 20, 0, 0, 0, 40000) + cdb + b'\0' * 4 + b'\x5a' * 40000,
    label='SCSI WRITE(10) with 40000 octets (reproducer, request)')
rsp(rhdr(OP_SCSI, r) + scsi_rsp(0, 0, sense=b'\0' * 20))
r = nid()
pair(rhdr(OP_SCSI, r) + scsi_req(rd, 1, 40000, data=bytes(40000)),
     rhdr(OP_SCSI, r) + scsi_rsp(0, 1, data=b'\x6b' * 40000, sense=b'\0' * 20), label='SCSI READ(10) response with 40000 octets')

# ---- RSVD v2 ----
# META_OPERATION_START: Resize, Create snapshot, Optimize, ExtractVHD, ConvertToVHDSet, ApplySnapshot, unknown
def meta(optype, body):
    return rhdr(OP_META, nid()) + GUID + struct.pack('<II', optype, 0) + body
req(meta(0, struct.pack('<QBBBB', 0x80000000, 1, 0, 1, 0)), label='META_OPERATION_START Resize')
rsp(rhdr(OP_META, rid[0]))
req(meta(1, struct.pack('<II6I', 1, 1, 1, 2, 3, 4, 5, 6) + GUID2 + struct.pack('<I', 0)), label='META_OPERATION_START CreateSnapshot')
rsp(rhdr(OP_META, rid[0]))
req(meta(2, b''), label='META_OPERATION_START Optimize'); rsp(rhdr(OP_META, rid[0]))
req(meta(3, b'\0' * 8), label='META_OPERATION_START ExtractVHD'); rsp(rhdr(OP_META, rid[0]))
name = 'snap.vhds'.encode('utf-16-le')
req(meta(4, struct.pack('<I', len(name)) + name), label='META_OPERATION_START ConvertToVHDSet'); rsp(rhdr(OP_META, rid[0]))
req(meta(4, struct.pack('<I', 0)), label='ConvertToVHDSet with an empty name'); rsp(rhdr(OP_META, rid[0]))
req(meta(5, struct.pack('<I', 4) + GUID2), label='META_OPERATION_START ApplySnapshot'); rsp(rhdr(OP_META, rid[0]))
req(meta(9, b'\0' * 8), label='META_OPERATION_START unknown type'); rsp(rhdr(OP_META, rid[0]))
# META_OPERATION_QUERY_PROGRESS: successful and failed response
r = nid()
pair(rhdr(OP_PROG, r) + GUID, rhdr(OP_PROG, r) + struct.pack('<QQ', 50, 100), label='QUERY_PROGRESS')
r = nid()
pair(rhdr(OP_PROG, r) + GUID, rhdr(OP_PROG, r, 0xc0000001) + GUID, label='QUERY_PROGRESS failed')
# VHDSET_QUERY_INFORMATION
r = nid()
q = struct.pack('<II', 2, 1) + GUID
pair(rhdr(OP_VHDSET, r) + q, rhdr(OP_VHDSET, r) + struct.pack('<I', 2) + b'\0' * 12, label='VHDSET_QUERY_INFORMATION snapshot list')
r = nid()
ent = struct.pack('<IIQII', 5, 0, 132000000000000000, 3, 1) + GUID + GUID2 + GUID
pair(rhdr(OP_VHDSET, r) + struct.pack('<II', 5, 3) + GUID, rhdr(OP_VHDSET, r) + ent, label='VHDSET_QUERY_INFORMATION snapshot entry')
r = nid()
pair(rhdr(OP_VHDSET, r) + struct.pack('<II', 8, 4) + GUID, rhdr(OP_VHDSET, r) + struct.pack('<I', 8) + b'\0' * 4, label='VHDSET_QUERY_INFORMATION other type')
# DELETE_SNAPSHOT
r = nid()
pair(rhdr(OP_DELSNAP, r) + GUID + struct.pack('<II', 1, 3), rhdr(OP_DELSNAP, r), label='DELETE_SNAPSHOT')
# QUERY_SAFE_SIZE
r = nid()
pair(rhdr(OP_SAFE, r) + b'\0' * 16, rhdr(OP_SAFE, r) + struct.pack('<Q', 0x20000000), label='QUERY_SAFE_SIZE')
# operations without a dissector: known and unknown codes
for op in (0x02002008, 0x02002009, 0x0200200A, 0x0200200C, 0x02009999):
    r = nid()
    pair(rhdr(op, r) + b'\0' * 8, rhdr(op, r) + b'\0' * 8)

def pcap(name, pkts):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

main_n = len(S.pkts)
pcap('rsvd-coverage.pcap', S.pkts)
if VERB:
    for n, l in marks:
        print(n, l)
    print('main frames', main_n)

# ---- malformed capture ----
S.pkts = []; marks = []; S.seqs = {}
def bad(rqdata, label=None, resp=False):
    (rsp if resp else req)(rqdata, label=label)
# header cut short
bad(b'\x01\x10\x00\x02\x00\x00', 'header cut short')
bad(rhdr(OP_SCSI, 900)[:12], 'header without request id')
# truncated bodies of each operation, requests and responses
for op in (OP_INFO, OP_SCSI, OP_SRB, OP_DISK, OP_VAL, OP_META, OP_PROG, OP_VHDSET, OP_DELSNAP, OP_SAFE):
    for resp in (False, True):
        bad(rhdr(op, 901) + b'\x01\x02\x03', 'truncated 0x%08x %s' % (op, 'response' if resp else 'request'), resp)
bad(rhdr(OP_SCSI, 910) + scsi_req(rd, 1, 512), 'READ request without the data buffer (dissector expects it)')
# SCSI request: CDB length 255 past the end, data transfer length past the end
bad(rhdr(OP_SCSI, 902) + struct.pack('<HHBBBBII', 36, 0, 255, 20, 0, 0, 0, 0) + bytes(20), 'CDB length past the end')
bad(rhdr(OP_SCSI, 903) + struct.pack('<HHBBBBII', 36, 0, 10, 20, 0, 0, 0, 5000) + bytes(10) + bytes(6) + bytes(4) + bytes(100), 'data transfer length past the end')
bad(rhdr(OP_SCSI, 904) + scsi_rsp(0, 1, data=b'\1' * 8, dlen=9000, sense=b'\0' * 20), 'response data length past the end', True)
bad(rhdr(OP_SCSI, 905) + scsi_rsp(0, 1, sense=b'\0' * 3, length=40, cdblen=10)[:-1] + b'', 'response sense past the end', True)
bad(rhdr(OP_SRB, 906) + bytes([1, 0x81, 0x02, 200]) + b'\0' * 4, 'SRB sense length past the end', True)
# ConvertToVHDSet name length past the end
bad(meta(4, struct.pack('<I', 5000) + b'a\0b\0'), 'ConvertToVHDSet name length past the end')
bad(meta(1, b'\0' * 10), 'CreateSnapshot cut short')
bad(meta(0, b'\0' * 3), 'Resize cut short')
bad(meta(5, b'\0' * 6), 'ApplySnapshot cut short')
bad(rhdr(OP_VHDSET, 907) + b'\x05\0\0', 'VHDSET response cut short', True)
pcap('rsvd-coverage-malformed.pcap', S.pkts)
if VERB:
    for n, l in marks:
        print('malformed', n, l)
