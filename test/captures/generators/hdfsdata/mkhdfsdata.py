#!/usr/bin/env python3
# Generates test/captures/hdfsdata_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HDFSDATA coverage captures.  Usage: mkhdfsdata.py <outdir>

HDFS datanode data transfer protocol (block read and write) over TCP.
HDFSDATA has no default port: it is only available through Decode As of
tcp.port (here 50010).  The dissector classifies a segment by its length
and by a few octets, so the frames are built to the sizes it expects.
Everything is built with struct; the client name, the access tokens and
the data are made-up placeholders, nothing comes from a real network."""
import struct
import sys
import os

CL = bytes([192, 0, 2, 1])
DN = bytes([192, 0, 2, 3])
MAC_C = bytes.fromhex('020000000001')
MAC_D = bytes.fromhex('020000000003')
CPORT, DPORT = 40000, 50010

READ_OP, WRITE_OP = 81, 80
CLIENT = b'DFSClient_placeholder'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def add(self, fr):
        self.frames.append((self.t, fr))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


class Flow:
    def __init__(self, cap, cport=CPORT, dport=DPORT):
        self.cap = cap
        self.cport, self.dport = cport, dport
        self.seq = {True: 1000, False: 5000}
        self.ipid = 1

    def seg(self, to_dn, payload, flags=0x18):
        src, dst = (CL, DN) if to_dn else (DN, CL)
        ms, md = (MAC_C, MAC_D) if to_dn else (MAC_D, MAC_C)
        sp, dp = (self.cport, self.dport) if to_dn else (self.dport, self.cport)
        seq, ack = self.seq[to_dn], self.seq[not to_dn]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.cap.add(md + ms + b'\x08\x00' + ip + tcp + payload)
        self.seq[to_dn] += len(payload) + (1 if flags & 3 else 0)

    def handshake(self):
        self.seg(True, b'', 0x02)
        self.seg(False, b'', 0x12)
        self.seg(True, b'', 0x10)


def tokens(tid=b'', pw=b'', kind=b'', svc=b''):
    return b''.join(bytes([len(x)]) + x for x in (tid, pw, kind, svc))


def header(op, blockid=0x1000000000000001, ts=1700000000):
    return struct.pack('>HBQQ', 17, op, blockid, ts)


def read_request(vint=None, client=CLIENT, tok=None):
    vint = bytes([len(client)]) if vint is None else vint
    return (header(READ_OP) + struct.pack('>QQ', 0, 1 << 20) + vint + client +
            (tokens() if tok is None else tok))


def write_request(nodes=2, client=CLIENT, tok=None, vint=None):
    vint = bytes([len(client)]) if vint is None else vint
    return (header(WRITE_OP) + struct.pack('>IB', 3, 0) + vint + client +
            struct.pack('>BI', 0, nodes) + b''.join(struct.pack('>I', 0x100 + i) for i in range(nodes)) +
            (tokens(b'tok-id', b'tok-pw', b'tok-kind', b'tok-svc') if tok is None else tok) +
            struct.pack('>BI', 1, 512))


def read_frag1(ctype=1, chunk=512, off=0, status=0):
    return struct.pack('>HBIQ', status, ctype, chunk, off)


def read_frag2(data, datalen=None, seq=0, last=1, crc=b'\xaa\xbb\xcc\xdd', inoff=0, length=None):
    """The 29 octet second fragment followed by the data; the first field
    is the packet length the dissector adds 40 to."""
    datalen = len(data) if datalen is None else datalen
    length = len(data) + 4 if length is None else length
    return struct.pack('>IQQBI', length, inoff, seq, last, datalen) + crc + data


def write_packet(data, seq=0, last=0, off=0, chunklen=None, crc64=0x1122334455667788):
    """Write data packet: the first four octets are the length of
    everything after the first 21 octets."""
    chunklen = len(data) if chunklen is None else chunklen
    body = struct.pack('>Q', off) + struct.pack('>QB', seq, last)
    pre = struct.pack('>I', len(data) + 12) + body
    return pre + struct.pack('>IQ', chunklen, crc64) + data


def main(out):
    c = Cap()
    f = Flow(c)
    f.handshake()                                                    # 1-3
    # --- block read
    f.seg(True, read_request())                                      # 4 read request
    f.seg(False, struct.pack('>H', 6))                               # 5 status 6 (success)
    f.seg(False, read_frag1())                                       # 6 first fragment, 15 octets
    f.seg(False, read_frag2(b'D' * 256))                             # 7 second fragment and data
    f.seg(True, struct.pack('>I', 0))                                # 8 4 octets: finish request
    f.seg(False, b'\0' * 8)                                          # 9 end packet (8 zero octets)
    f.seg(False, b'\x00')                                            # 10 pipeline status
    f.seg(False, struct.pack('>H', 0))                               # 11 status 0
    # read response without checksum (chunk size 0), second fragment and data in separate segments
    f.seg(False, read_frag1(ctype=0, chunk=0))                       # 12
    f.seg(False, read_frag2(b'', datalen=100, length=104)[:29])      # 13 header only, 100 octets of data follow
    f.seg(False, b'E' * 100)                                         # 14
    # --- block write
    g = Flow(c, 40001)
    g.handshake()                                                    # 15-17
    g.seg(True, write_request())                                     # 18 write request
    g.seg(False, struct.pack('>H', 6))                               # 19 status
    g.seg(True, write_packet(b'F' * 64))                             # 20 data packet
    g.seg(True, write_packet(b'G' * 32, seq=1, last=1, off=64))      # 21 last data packet
    g.seg(False, b'\x00')                                            # 22 pipeline status
    g.seg(True, write_request(nodes=0, tok=tokens()))                # 23 no further nodes, empty tokens
    g.seg(False, b'\x01\x02\x03\x04\x05\x06\x07\x08')                # 24 8 octets, not the end packet
    g.seg(False, struct.pack('>I', 0xffffffff))                      # 25 4 octets
    g.seg(True, b'', 0x11)                                           # 26 FIN
    c.write(os.path.join(out, 'hdfsdata-coverage.pcap'))

    m = Cap()
    h = Flow(m, 40002)
    h.seg(True, read_request(vint=bytes([0x8f, 21])))                # vint of two octets (see README)
    h.seg(True, read_request(vint=bytes([0x8e, 0, 21])))             # vint of three octets
    h.seg(True, read_request(vint=bytes([0x85, 1, 2, 3, 4])))        # negative size
    h.seg(True, write_request(vint=bytes([0x8f, 21])))
    h.seg(True, read_request()[:50])                                 # cut in the client id
    h.seg(True, read_request(tok=tokens())[:-2])                     # cut in the tokens
    h.seg(True, write_request(nodes=200)[:100])                      # many nodes announced
    h.seg(True, write_request()[:-3])                                # cut before the chunk size
    h.seg(False, read_frag1(ctype=0, chunk=512))                     # first fragment
    h.seg(False, read_frag2(b'H' * 40, crc=b''))                     # checksum type 0, chunk size 512: crc length 0
    h.seg(False, read_frag1(ctype=1, chunk=512))
    h.seg(False, read_frag2(b'H' * 256, seq=1, last=0))              # crc length from the odd fields: too long
    h.seg(False, write_packet(b'I' * 3))                             # shorter than the fixed header
    h.seg(False, struct.pack('>I', 20) + b'\0' * 20)                 # length field matches nothing
    h.seg(False, b'\1\2\3\4\5\6\7\x08\x09\x0a')                      # 10 octets: no length to read
    h.seg(False, read_frag1() + b'\0\0\0\x10')                       # 19 octets: length field too short
    m.write(os.path.join(out, 'hdfsdata-coverage-malformed.pcap'))


main(sys.argv[1])
