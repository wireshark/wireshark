#!/usr/bin/env python3
# Generates test/captures/nbd_coverage.pcap.gz
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

# ---- NBD message builders ----
HND_INIT = b'NBDMAGIC'
HND_OPT = b'IHAVEOPT'
HND_REPLY = 0x0003e889045565a9
HND_OLD = 0x0000420281861253
REQ, RESP, SREP = 0x25609513, 0x67446698, 0x668e33ef

def opt(o, data=b''):
    return HND_OPT + struct.pack('!II', o, len(data)) + data

def orep(o, r, data=b''):
    return struct.pack('!QIII', HND_REPLY, o, r, len(data)) + data

def req(typ, handle, off=0, length=0, flags=0, data=b''):
    return struct.pack('!IHHQQI', REQ, flags, typ, handle, off, length) + data

def resp(handle, err=0, data=b''):
    return struct.pack('!IIQ', RESP, err, handle) + data

def srep(handle, typ, body=b'', flags=0):
    return struct.pack('!IHHQI', SREP, flags, typ, handle, len(body)) + body

def lstr(s, n=4):
    return struct.pack('!I' if n == 4 else '!H', len(s)) + s

def go(name, infos):
    return lstr(name) + struct.pack('!H', len(infos)) + b''.join(struct.pack('!H', i) for i in infos)

def meta(name, queries):
    return lstr(name) + struct.pack('!I', len(queries)) + b''.join(lstr(q) for q in queries)

def tflags(v):
    return struct.pack('!QH', 1 << 30, v)

def transmission(st, base):
    '''Simple replies for every command type, flags, matching by handle.'''
    h = base
    st.c(req(0, h, 0, 512)); st.s(resp(h, 0, bytes(range(256)) * 2)); h += 1
    st.c(req(1, h, 4096, 64, 0x0001, b'W' * 64)); st.s(resp(h)); h += 1
    st.c(req(3, h, 0, 0, 0x0001)); st.s(resp(h)); h += 1
    st.c(req(4, h, 8192, 4096, 0x0004)); st.s(resp(h)); h += 1
    st.c(req(5, h, 0, 1024)); st.s(resp(h)); h += 1
    st.c(req(6, h, 0, 65536, 0x0002 | 0x0010)); st.s(resp(h)); h += 1
    st.c(req(7, h, 0, 65536, 0x0008 | 0x0020)); st.s(resp(h)); h += 1
    st.c(req(8, h, 1 << 21, 0)); st.s(resp(h)); h += 1
    # error replies: ENOSPC, EPERM, ESHUTDOWN, and an unlisted errno
    for e in (28, 1, 108, 77):
        st.c(req(1, h, 0, 16, 0, b'E' * 16)); st.s(resp(h, e)); h += 1
    # handle reuse
    st.c(req(0, base, 0, 16)); st.s(resp(base, 0, b'R' * 16))
    # response whose request was never seen
    st.s(resp(0x7777))
    # two requests in one segment, replies in one segment
    st.f.append(tcp(A, B, st.cp, st.sp, st.cs, st.ss,
                    req(3, h) + req(1, h + 1, 0, 8, 0, b'S' * 8), 0x18))
    st.cs += 28 + 28 + 8
    st.s(resp(h) + resp(h + 1)); h += 2
    # a write request split in two segments, a read reply split in two
    wr = req(1, h, 0, 300, 0, b'Z' * 300)
    st.c(wr[:100]); st.c(wr[100:]); st.s(resp(h)); h += 1
    st.c(req(0, h, 0, 400))
    rr = resp(h, 0, b'Q' * 400)
    st.s(rr[:50]); st.s(rr[50:]); h += 1
    # structured replies
    st.c(req(0, h, 0, 1024))
    st.s(srep(h, 1, struct.pack('!Q', 0) + b'D' * 512))
    st.s(srep(h, 2, struct.pack('!QI', 512, 512), 0))
    st.s(srep(h, 0, b'', 1)); h += 1
    st.c(req(0, h, 0, 1024))
    st.s(srep(h, 32769, struct.pack('!IH', 5, 5) + b'oops!', 1)); h += 1
    st.c(req(0, h, 0, 1024))
    st.s(srep(h, 32770, struct.pack('!IH', 5, 3) + b'bad' + struct.pack('!Q', 256), 1)); h += 1
    st.c(req(7, h, 0, 65536, 0x0008))
    st.s(srep(h, 5, struct.pack('!I', 1) + struct.pack('!II', 4096, 0) + struct.pack('!II', 8192, 1), 1)); h += 1
    # extended block status reply type and trailing bytes after a hole
    st.c(req(7, h, 0, 65536, 0))
    st.s(srep(h, 6, b'\x00' * 16, 1)); h += 1
    st.c(req(0, h, 0, 64))
    st.s(srep(h, 2, struct.pack('!QI', 0, 64) + b'xx', 1)); h += 1
    st.c(req(2, h))
    return h

frames = []
marks = []
def mark(name):
    marks.append((name, len(frames) + 1))

# 1. Newstyle, NO_ZEROES, option haggling, EXPORT_NAME
mark('newstyle-no-zeroes')
st = Stream(frames, 50001, 10809)
st.s(HND_INIT); st.s(HND_OPT); st.s(struct.pack('!H', 3))
st.c(struct.pack('!I', 3))
st.c(opt(3)); st.s(orep(3, 2, lstr(b'disk0')) + orep(3, 2, lstr(b'disk1')) + orep(3, 1))
st.c(opt(7, go(b'disk0', [0, 1, 2, 3])))
st.s(orep(7, 3, struct.pack('!HQH', 0, 1 << 30, 0x1fff)))
st.s(orep(7, 3, struct.pack('!H', 1) + b'disk0'))
st.s(orep(7, 3, struct.pack('!H', 2) + b'First disk'))
st.s(orep(7, 3, struct.pack('!HIII', 3, 512, 4096, 33554432)))
st.s(orep(7, 3, struct.pack('!H', 9) + b'abcd'))
st.s(orep(7, 1))
st.c(opt(6, go(b'disk1', [])))
st.s(orep(6, 0x80000001, b'no such option'))
st.c(opt(9, meta(b'disk0', [b'base:allocation'])))       # reproducer: 32-bit query length
st.s(orep(9, 4, struct.pack('!I', 1) + b'base:allocation') + orep(9, 1))
st.c(opt(10, meta(b'disk0', [b'base:allocation', b'qemu:dirty-bitmap:b0'])))
st.s(orep(10, 4, struct.pack('!I', 1) + b'base:allocation')
     + orep(10, 4, struct.pack('!I', 2) + b'qemu:dirty-bitmap:b0') + orep(10, 1))
st.c(opt(9, meta(b'disk0', [])))
st.s(orep(9, 1))
st.c(opt(8)); st.s(orep(8, 1))
st.c(opt(11, b'\x00\x01')); st.s(orep(11, 0x80000007))
st.c(opt(4)); st.s(orep(4, 0x80000003, b'peek'))
st.c(opt(99, b'unknown')); st.s(orep(99, 0x80000001))
st.c(opt(3)); st.s(orep(3, 0x80000002))
st.c(opt(3)); st.s(orep(3, 0x80000004))
st.c(opt(3)); st.s(orep(3, 0x80000005))
st.c(opt(3)); st.s(orep(3, 0x80000006))
st.c(opt(3)); st.s(orep(3, 0x80000008))
st.c(opt(3)); st.s(orep(3, 0x80000009))
st.c(opt(3)); st.s(orep(3, 0x8000000a))
st.c(opt(3)); st.s(orep(3, 1, b'unexpected'))
st.c(opt(3)); st.s(orep(3, 0x80000063, b'what'))          # unknown error code with a message
st.c(opt(1, b'disk0'))
st.s(tflags(0x1fff))
transmission(st, 1)
st.c(opt(2))

# 2. Newstyle without NO_ZEROES, EXPORT_NAME, split server reply
mark('newstyle-zeroes')
st = Stream(frames, 50002, 10809)
st.s(HND_INIT + HND_OPT + struct.pack('!H', 1))
st.c(struct.pack('!I', 1))
st.c(opt(1, b'disk1'))
rep = tflags(0x0003) + bytes(124)
st.s(rep[:60]); st.s(rep[60:])
st.c(req(0, 1, 0, 100)); st.s(resp(1, 0, b'a' * 100))
st.c(req(2, 2))

# 3. STARTTLS: the server ack switches the conversation to TLS
mark('starttls')
st = Stream(frames, 50003, 10809)
st.s(HND_INIT); st.s(HND_OPT); st.s(struct.pack('!H', 1))
st.c(struct.pack('!I', 1))
st.c(opt(5)); st.s(orep(5, 1))

# 4. Oldstyle handshake
mark('oldstyle')
st = Stream(frames, 50004, 10809)
st.s(HND_INIT)
st.s(struct.pack('!QQHH', HND_OLD, 1 << 30, 0, 0x0003) + bytes(124))
transmission(st, 0x100)

# 5. Transmission seen from the middle: reply first, then a request
mark('port-reply-first')
st = Stream(frames, 50005, 10809)
st.s(resp(5, 0))
st.c(req(0, 6, 0, 32)); st.s(resp(6, 0, b'M' * 32))
st = Stream(frames, 50006, 10809)
st.s(srep(5, 0, b'', 1))
st.c(req(3, 7)); st.s(resp(7))
mark('port-end')

# 6. Heuristic: NBD on a port that is not registered
H = {}
def hs(port):
    return Stream(frames, port, 40000 + port % 100 + 100)
mark('heur-request')
st = Stream(frames, 50101, 41001)
st.c(req(0, 1, 0, 16)); st.s(resp(1, 0, b'h' * 16)); st.c(req(2, 2))
mark('heur-response')
st = Stream(frames, 50102, 41002)
st.s(resp(3, 0)); st.c(req(3, 4)); st.s(resp(4))
mark('heur-structured-reply')   # reproducer of "NBD: Fix structured reply heuristic"
st = Stream(frames, 50103, 41003)
st.s(srep(0x1122334455667788, 2, struct.pack('!QI', 0, 0), 1))
mark('heur-handshake-init')
st = Stream(frames, 50104, 41004)
st.s(HND_INIT)
mark('heur-handshake-opt')
st = Stream(frames, 50105, 41005)
st.c(opt(3))
mark('heur-handshake-reply')
st = Stream(frames, 50106, 41006)
st.s(orep(3, 1))
mark('heur-handshake-old')
st = Stream(frames, 50107, 41007)
st.s(struct.pack('!QQHH', HND_OLD, 1 << 30, 0, 3) + bytes(124))
mark('heur-end')

main = frames
frames = []
# Not NBD: looks a little like it but must be left alone (malformed capture)
mark('not-nbd')
for i, pl in enumerate([b'abc', req(0, 1)[:20], req(0, 1, 0, 0)[:6] + struct.pack('!H', 99) + req(0, 1)[8:],
                        struct.pack('!II', RESP, 0), struct.pack('!IHHQ', SREP, 0, 0, 1) [:12],
                        bytes(range(1, 13)), b'123456']):
    st = Stream(frames, 50200 + i, 41100 + i)
    st.c(pl)

# --- malformed NBD on the registered port: lengths that reach past the PDU
st = Stream(frames, 50300, 10809)
st.s(HND_INIT); st.s(HND_OPT); st.s(struct.pack('!H', 3))
st.c(struct.pack('!I', 3))
st.c(opt(7, struct.pack('!I', 200) + b'short'))                      # export name longer than the option
st.c(opt(9, lstr(b'disk0') + struct.pack('!I', 5) + lstr(b'q')))     # five queries, one present
st.c(opt(6, lstr(b'd') + struct.pack('!H', 9) + b'\0\0'))            # nine information requests, one present
st.s(orep(7, 3, struct.pack('!H', 0) + b'\x01'))                     # truncated export information
st.s(orep(3, 2, struct.pack('!I', 99) + b'x'))                       # name longer than the reply
st.s(orep(9, 4, b'\x00'))
st.s(orep(7, 3, b''))
st.c(req(1, 1, 0, 100, 0, b'short'))                                 # write request with less data than its length
st.s(srep(2, 32769, struct.pack('!IH', 5, 99) + b'x', 1))            # error message longer than the chunk
st.s(srep(3, 32770, struct.pack('!IH', 5, 3) + b'bad', 1))           # offset missing
st.s(srep(4, 5, b'\x00\x00\x00', 1))                                 # block status cut short
st.s(srep(5, 1, b'\x00', 1))                                         # offset data cut short
st.s(srep(6, 2, b'\x00' * 6, 1))

def finish(outdir):
    pass

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'nbd-coverage.pcap'), main)
    gz(os.path.join(out, 'nbd-coverage.pcap'))
    os.rename(os.path.join(out, 'nbd-coverage.pcap.gz'), os.path.join(out, 'nbd_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'nbd-coverage-malformed.pcap'), frames + [])
    for n, f in marks:
        print(n, f)
