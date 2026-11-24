#!/usr/bin/env python3
# Generates test/captures/ncp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())


# ---- NCP (packet-ncp.c): packet types, burst mode, TCP framing, taps ----
# FUNCS holds the request and reply data of 37 NCP functions and subfunctions
# (one or two of each group that the NCP statistics tables count, made-up
# field values; the data was produced from the function table of the
# generator tools/dissector_generators/generate-ncp2222.py, see the ncp2222
# capture).
FUNCS = [
    (0x0001, 1, '', ''),
    (0x0002, 1, '', ''),
    (0x0003, 1, '0103000303616263', ''),
    (0x0004, 1, '0200', ''),
    (0x0005, 1, '0003616263', ''),
    (0x1100, 1, '056162636465', ''),
    (0x1101, 1, '06', ''),
    (0x1500, 1, '010206616263646566', '0103'),
    (0x1501, 1, '', '0461626364'),
    (0x1600, 1, '02010761626364656667', ''),
    (0x1601, 1, '01', '06616263646566'),
    (0x1700, 1, '05616263646506616263646566', ''),
    (0x1701, 1, '0361626306616263646566056162636465', ''),
    (0x2000, 0, '000461626364', '0000000002'),
    (0x2001, 0, '00000003', '0002'),
    (0x2200, 0, '', ''),
    (0x2201, 0, '', ''),
    (0x2303, 1, '01000000000461626364', ''),
    (0x2304, 1, '0100000001056162636465', '00000002'),
    (0x2400, 1, '02000000', '000000000101020461626364'),
    (0x2401, 1, '', '0300'),
    (0x5601, 0, '000503000000', ''),
    (0x5602, 0, '02000000000000000000000000000000000002000000010007006162636465666766', '040000000100000003000000'),
    (0x5702, 0, '05000103000000070103616263', '000300000000000000'),
    (0x5704, 0, '07000100000200000004010202000000060105616263646503616263', ''),
    (0x5902, 0, '030101000000000503000001020001040061626364', '010100000001000000'),
    (0x5905, 0, '02000000010000000200000001020601010102000105006162636465', '000000000100010000000000'),
    (0x5a00, 1, '000000000000000600000002010000000100000002000000000000000000000002000000', '030000000000000002000000000000000600000301000000'),
    (0x5a0a, 1, '020000000300000004', '03000000'),
    (0x6f00, 0, '0003616263', '0100000000'),
    (0x6f01, 0, '00000000', '0101'),
    (0x7201, 1, '', '010000000300000003000000000000000000000202000000'),
    (0x7205, 1, '01000000', '0300000066696c65206e616d652066696c65206e616d652066696c65206e616d652066696c65206e616d652066696c65206e616d030000000000'),
    (0x7b07, 1, '', '0200000001000002030000000000000002000000000000000200000003000000'),
    (0x7b08, 1, '03000000', '000000000002000503000000000000000200000000000000050000040000000301000006000000036e006e006e00'),
    (0x8301, 1, '00000000010202020000000201020001000002016e00', '05000000'),
    (0x8302, 1, '02000200020202000201010200010201010000016e00', '06000000'),
]

IPX_NCP_SOCKET = 0x0451
CONN, TASK = 5, 1

def nhdr(typ, seq, conn=CONN, task=TASK):
    return struct.pack('!HBBBB', typ, seq, conn & 0xff, task, conn >> 8)

def nreq(seq, func, sub, has_len, data, conn=CONN, task=TASK):
    h = nhdr(0x2222, seq, conn, task) + bytes([func])
    if sub is not None:
        h += (struct.pack('!H', len(data) + 1) if has_len else b'') + bytes([sub])
    return h + data

def nrep(seq, data=b'', code=0, status=0, conn=CONN, task=TASK):
    return nhdr(0x3333, seq, conn, task) + bytes([code, status]) + data

def burst(flags, stream, src, dst, pseq, delay, bseq, aseq, blen, off, dlen, nmiss, payload=b''):
    return (struct.pack('!HBB', 0x7777, flags, stream) + struct.pack('!IIIIHHIIHH', src, dst, pseq, delay,
            bseq, aseq, blen, off, dlen, nmiss) + payload)

frames = []
def u(payload, sport=1024, dport=524, to_server=True):
    if to_server:
        frames.append(udp(A, B, sport, dport, payload))
    else:
        frames.append(udp(B, A, dport, sport, payload, 1, 2))

# --- connection management over UDP: create connection, LIP echo, destroy connection
u(nhdr(0x1111, 0, 0xff, 0) + bytes([0, 0]))
u(nrep(0, b'', 0, 0, CONN, 0), to_server=False)
LIP = b'LIP Echo Data   '
u(struct.pack('!H', 0x1111) + bytes([0, 0]) + LIP + b'echo payload')
u(struct.pack('!H', 0x1111) + bytes([1, 0]) + LIP)
u(b'Lip Echo Data' + bytes(range(20)))                  # packet type is the start of the magic
u(nhdr(0x5555, 9) + bytes([0, 0]))
u(nrep(9), to_server=False)

# --- service requests and replies for functions of every statistics group
seq = 10
for code, has_len, rq, rp in FUNCS:
    func, sub = (code >> 8, code & 0xff) if code > 0xff else (code, None)
    seq += 1
    u(nreq(seq, func, sub, has_len, bytes.fromhex(rq)))
    u(nrep(seq, bytes.fromhex(rp)), to_server=False)
# NCP function without a definition, and an error completion code
seq += 1
u(nreq(seq, 0xfe, None, 0, b'\x00' * 4))
u(nrep(seq, b'', 0x00, 0x00), to_server=False)
seq += 1
u(nreq(seq, 0x01, None, 0, b''))
u(nrep(seq, b'', 0x00, 0x40), to_server=False)

# --- NDS: ping and fragmented requests with the verbs that have a statistics row
def nds_req(seq, verb, body, handle=0xffffffff, conn=CONN):
    data = struct.pack('<IIIHHII', handle, 0, 0, 0, 0, verb, 0x10000) + body
    data = data[:4] + struct.pack('<II', len(data) + 2 - 4 - 8, len(data) + 2 - 4 - 8) + data[12:]
    return nhdr(0x2222, seq, conn) + bytes([0x68, 2]) + data

def nds_rep(seq, body, code=0, handle=0xffffffff, conn=CONN):
    return nrep(seq, struct.pack('<III', len(body) + 8, handle, code & 0xffffffff) + body, 0, 0, conn)

seq += 1
u(nhdr(0x2222, seq) + bytes([0x68, 1]) + struct.pack('<II', 1, 1))
u(nrep(seq, bytes([8, 0, 0, 0]) + struct.pack('<IIHH', 0, 0, 0xffff, 0xffff)), to_server=False)
for verb in (1, 2, 3, 5, 6, 0x0e, 0x17, 200):
    seq += 1
    u(nds_req(seq, verb, struct.pack('<I', 1) + bytes(120)))
    u(nds_rep(seq, struct.pack('<I', 1) + bytes(120)), to_server=False)
seq += 1

seq += 1
u(nhdr(0x2222, seq) + bytes([0x68, 5]))                # Monitor NDS Connection: another NDS subfunction
u(nrep(seq), to_server=False)

# --- SecretStore (0x5c) and NMAS (0x5e) fragments: the sub verb is the row of the statistics
# table. The reproducers of "NCP: Do not use a packet value as an SRT row index" are the
# sub verbs 0x80000000, 0xfffffffe, 0x7ffffff0 and 0x01000000, which are no known verbs.
def sub_frag(seq, func, subverb):
    d = bytes([func, 0x02]) + b'\xff\xff\xff\xff' + struct.pack('<II', 64, 32) + b'\0' * 12
    d += struct.pack('<I', subverb) + b'\0' * 16
    return nhdr(0x2222, seq) + d
for func, verbs in ((0x5c, (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80000000, 0xfffffffe, 0x7ffffff0, 0x01000000)),
                    (0x5e, (0, 1, 2, 4, 6, 0x80000000, 0xfffffffe))):
    for sv in verbs:
        seq += 1
        u(sub_frag(seq, func, sv))
        u(nrep(seq, b'\0' * 32), to_server=False)

# --- watchdog, broadcast, positive acknowledgement, unknown type
u(nhdr(0x3e3e, 1) + bytes([0, 0x80, 3, ord('?')]) + b'more')
u(nhdr(0x3e3e, 2) + bytes([0, 0x80, 3, ord('Y')]), to_server=False)
u(nhdr(0x3e3e, 3, 7) + bytes([0, 0x80, 3, ord('?')]), to_server=False)
u(nhdr(0xbbbb, 1) + bytes([0, 0, 0, 0x24]) + struct.pack('!I', 0x01020304))     # oplock break
u(nhdr(0xbbbb, 2) + bytes([0, 0, 0, 0x00]) + struct.pack('!I', 0x05060708) + b'\0' * 4)
u(nhdr(0x1234, 13) + b'unknown packet type payload')

# --- packet burst: read and write requests, data, system packets, flags
def bu(*a, **k):
    u(burst(*a, **k))
cmd = lambda c, h, off, ln: struct.pack('<I', c) + struct.pack('>I', h) + bytes(8) + struct.pack('>II', off, ln)
bu(0x00, 2, 0x11, 0x22, 1, 100, 0, 0, 24, 0, 24, 0, cmd(1, 0xabcd, 4096, 8192))        # burst read
bu(0x00, 2, 0x11, 0x22, 2, 100, 1, 1, 24 + 64, 0, 24 + 64, 0, cmd(2, 0xabcd, 0, 64) + b'W' * 64)   # burst write
bu(0x00, 2, 0x11, 0x22, 3, 100, 2, 2, 24, 0, 24, 0, cmd(7, 0xabcd, 0, 16))             # unknown command
bu(0x10, 2, 0x22, 0x11, 4, 0, 3, 1, 100, 0, 100, 0, b'D' * 100)                          # data, end of burst
bu(0x00, 2, 0x22, 0x11, 5, 0, 3, 1, 100, 10, 50, 0, b'E' * 50)                           # data with an offset
bu(0x5c, 2, 0x22, 0x11, 6, 0, 3, 1, 100, 10, 0, 0)                                       # ABT BSY EOB LST
bu(0x04, 2, 0x22, 0x11, 7, 0, 3, 1, 0, 10, 0, 0)
bu(0x08, 2, 0x22, 0x11, 8, 0, 3, 1, 0, 10, 0, 0)
bu(0x40, 2, 0x22, 0x11, 9, 0, 3, 1, 0, 10, 0, 0)
bu(0x80, 2, 0x11, 0x22, 10, 0, 4, 4, 0, 0, 0, 0)                                          # system packet, no fragments missing
bu(0x80, 2, 0x11, 0x22, 11, 0, 4, 4, 0, 0, 0, 2, struct.pack('>IH', 0x1000, 0x200) + struct.pack('>IH', 0x2000, 0x300))
for n in (3, 7, 15, 19, 23):                                                              # headers cut short inside the command
    bu(0x00, 2, 0x11, 0x22, 20 + n, 100, 0, 0, n, 0, n, 0, bytes(n))

# --- NCP over TCP port 524 (the signature "DmdT" for requests, "tNcP" for replies)
def tcp_req(ncp, ver=1, bufsize=1024, extra=b'', flag=0):
    return struct.pack('>IIII', 0x446d6454, 16 + len(extra) + len(ncp) | flag, ver, bufsize) + extra + ncp
def tcp_rep(ncp, extra=b'', flag=0):
    return struct.pack('>II', 0x744e6350, 8 + len(extra) + len(ncp) | flag) + extra + ncp
st = Stream(frames, 40524, 524)
st.c(tcp_req(nreq(1, 0x01, None, 0, b'')))
st.s(tcp_rep(nrep(1)))
func, sub = FUNCS[11][0] >> 8, FUNCS[11][0] & 0xff
st.c(tcp_req(nreq(2, func, sub, FUNCS[11][1], bytes.fromhex(FUNCS[11][2]))))
st.s(tcp_rep(nrep(2, bytes.fromhex(FUNCS[11][3]))))
# the "packet signature" variant: eight bytes before the NCP header
st.c(tcp_req(nreq(3, 0x01, None, 0, b''), extra=bytes(8), flag=0x80000000))
st.s(tcp_rep(nrep(3), extra=bytes(8), flag=0x80000000))
# two requests of different connections in one segment (reproducer of the shared header report)
st.c(tcp_req(nreq(4, 0x01, None, 0, b'', 5)) + tcp_req(nreq(5, 0x01, None, 0, b'', 7)))
st.s(tcp_rep(nrep(4, b'', 0, 0, 5)) + tcp_rep(nrep(5, b'', 0, 0, 7)))
# a request split over two segments
r = tcp_req(nreq(6, 0x01, None, 0, b''))
st.c(r[:10]); st.c(r[10:])
st.s(tcp_rep(nrep(6)))
# a burst packet and a watchdog over TCP
st.c(tcp_req(burst(0x10, 2, 1, 2, 1, 0, 3, 1, 8, 0, 8, 0, b'burst!!!')))
st.c(tcp_req(nhdr(0x3e3e, 7) + bytes([0, 0x80, 3, ord('?')])))
# something that is not NCP over TCP: no signature, 1 byte of padding first
st.c(b'\x00' + tcp_req(nreq(7, 0x01, None, 0, b'')))
st.c(b'xxxx' + bytes(16))

# --- IPX: socket 0x451 and packet type 0x11 reach NCP too
def ipx(ptype, dsock, ssock, payload, dnode=1, snode=2):
    n = 30 + len(payload)
    h = struct.pack('!HHBB', 0xffff, n, 0, ptype)
    h += struct.pack('!I', 0x1000) + bytes([0, 0, 0, 0, 0, dnode]) + struct.pack('!H', dsock)
    h += struct.pack('!I', 0x2000) + bytes([0, 0, 0, 0, 0, snode]) + struct.pack('!H', ssock)
    return eth(h + payload, snode, dnode, 0x8137)
frames.append(ipx(0x11, IPX_NCP_SOCKET, 0x4000, nreq(1, 0x01, None, 0, b'')))
frames.append(ipx(0x11, 0x4000, IPX_NCP_SOCKET, nrep(1), 2, 1))
frames.append(ipx(0x11, IPX_NCP_SOCKET, 0x4000, nhdr(0x1111, 0, 0xff, 0) + bytes([0, 0])))
frames.append(ipx(0x11, IPX_NCP_SOCKET, 0x4000, burst(0x00, 2, 1, 2, 1, 0, 0, 0, 24, 0, 24, 0, cmd(1, 7, 0, 4096))))

main = frames
frames = []
# --- malformed: headers cut short, a burst that promises more data than it holds, NDS cut short
u(b'\x22\x22')
u(b'Lip Echo Data')                                      # the payload of a LIP echo reaches past the packet
# error completion codes are expert infos of error severity
seq = 200
u(nreq(seq, 0xfe, None, 0, b'\x00' * 4)); u(nrep(seq, b'', 0xff, 0x04), to_server=False)
seq += 1
u(nds_req(seq, 1, struct.pack('<I', 0) + bytes(120))); u(nds_rep(seq, bytes(8), 0xfffffda7), to_server=False)
u(nhdr(0x9999, 11) + bytes([0, 0]), to_server=False)
u(nhdr(0x9999, 12) + bytes([0, 0]) + b'\0' * 4, to_server=False)
u(sub_frag(210, 0x5e, 10))
u(nhdr(0x7777, 1)[:5])
u(burst(0x00, 2, 1, 2, 1, 0, 0, 0, 24, 0, 24, 0, cmd(1, 7, 0, 4096))[:50])
u(burst(0x80, 2, 1, 2, 1, 0, 4, 4, 0, 0, 0, 5, bytes(6)))
u(nhdr(0x3e3e, 1) + bytes([0, 0x80]))
u(nhdr(0x1111, 0, 0xff, 0))
u(nds_req(1, 1, struct.pack('<I', 1))[:40])
u(nhdr(0x2222, 3) + bytes([0x68, 2, 0xff, 0xff, 0xff, 0xff]))
st = Stream(frames, 40525, 524)
st.c(struct.pack('>II', 0x446d6454, 100) + bytes(8))
st.c(struct.pack('>II', 0x446d6454, 0x80000000 | 12) + bytes(4) + bytes(4))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ncp-coverage.pcap'), main)
    gz(os.path.join(out, 'ncp-coverage.pcap'))
    os.rename(os.path.join(out, 'ncp-coverage.pcap.gz'), os.path.join(out, 'ncp_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'ncp-coverage-malformed.pcap'), frames)
