#!/usr/bin/env python3
# Generates test/captures/nisplus_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the NIS+ coverage captures: mknisplus.py <outdir>
import struct
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else '.'

def u32(v): return struct.pack('>I', v & 0xffffffff)
def xstr(s):
    b = s.encode() if isinstance(s, str) else s
    return u32(len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)
xdata = xstr
def arr(items): return u32(len(items)) + b''.join(items)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

CLI, SRV = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
def frame_udp(payload, to_server, sport=1022, dport=32770, cli=CLI, srv=SRV):
    src, dst = (cli, srv) if to_server else (srv, cli)
    sp, dp = (sport, dport) if to_server else (dport, sport)
    udp = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    macs = (b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01') if to_server else (b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02')
    return macs + b'\x08\x00' + ip + udp

def rpc_call(xid, prog, vers, proc, body):
    return u32(xid) + u32(0) + u32(2) + u32(prog) + u32(vers) + u32(proc) + u32(0) * 4 + body
def rpc_reply(xid, body):
    return u32(xid) + u32(1) + u32(0) + u32(0) * 3 + body

NIS, CB = 100300, 100302
frames = []
xid = [0x1000]
def call(proc, args, reply=None, prog=NIS, vers=3, sport=1022):
    xid[0] += 1
    frames.append(frame_udp(rpc_call(xid[0], prog, vers, proc, args), True, sport=sport))
    if reply is not None:
        frames.append(frame_udp(rpc_reply(xid[0], reply), False, sport=sport))

# ---- NIS+ structures -------------------------------------------------------
def rights(v=0x00ff0f0f): return u32(v)
def oid(c=1700000000, m=1700000100): return u32(c) + u32(m)
def obj_hdr(typ, name='foo.org.example.', owner='root.org.example.', group='admin.org.example.', domain='org.example.', acc=0x0f0f0f0f, ttl=43200):
    return oid() + xstr(name) + xstr(owner) + xstr(group) + xstr(domain) + rights(acc) + u32(ttl) + u32(typ)
def endpoint(uaddr='192.0.2.9.8.1', fam='inet', proto='udp'): return xstr(uaddr) + xstr(fam) + xstr(proto)
def dirserver(name='nis1.example.', n=2):
    return xstr(name) + arr([endpoint(), endpoint('192.0.2.9.8.2', 'inet', 'tcp')][:n]) + u32(1) + xdata(b'\x01\x02\x03\x04\x05')
def dirobj():
    return xstr('org.example.') + u32(1) + arr([dirserver(), dirserver('nis2.example.', 1)]) + u32(3600) + \
        arr([rights(0x11111111) + u32(4), rights(0x22222222) + u32(2)])
def groupobj(): return u32(1) + arr([xstr('user1.org.example.'), xstr('user2.org.example.')])
def tableobj():
    col = lambda n, m: xstr(n) + u32(m) + rights(0x0f0f0f0f)
    return xstr('passwd_tbl') + u32(2) + u32(ord(':')) + arr([col('name', 0x41), col('passwd', 0x7f)]) + xstr('/etc')
def entryobj(): return xstr('passwd_tbl') + arr([u32(0x1f) + xstr('user1'), u32(0) + xstr('*')])
def linkobj(): return u32(4) + arr([xstr('attr1') + xdata(b'abc'), xstr('attr2') + xdata(b'')]) + xstr('target.org.example.')
OBJS = {
    2: obj_hdr(2) + dirobj(), 3: obj_hdr(3) + groupobj(), 4: obj_hdr(4) + tableobj(), 5: obj_hdr(5) + entryobj(),
    6: obj_hdr(6) + linkobj(), 7: obj_hdr(7) + xdata(b'private data!'), 1: obj_hdr(1), 0: obj_hdr(0), 99: obj_hdr(99),
}
ALL = list(OBJS.values())

def attr(): return xstr('name') + xdata(b'user1')
def result(err=0, objs=ALL[:3]):
    return u32(err) + arr(objs) + xdata(b'cookie') + u32(10) + u32(20) + u32(30) + u32(40)
def ib_request(): return xstr('[name=user1],passwd_tbl.org.example.') + arr([attr(), attr()]) + u32(3) + arr([OBJS[5]]) + \
        arr([dirserver('cb.example.')]) + u32(8192) + xdata(b'\x00\x01\x02')
def logentry(t=4): return u32(1700000200) + u32(t) + xstr('admin.org.example.') + xstr('org.example.') + arr([attr()]) + OBJS[5]
def logresult(): return u32(0) + xdata(b'cookie') + arr([logentry(i) for i in (0, 1, 3, 8)])
def taglist(): return arr([u32(1) + xstr('1.2.3'), u32(2) + xstr('10'), u32(99) + xstr('x')])

def main_frames():
    call(0, b'', b'')                                                       # NULL
    for proc, name in ((1, 'LOOKUP'), (2, 'ADD'), (3, 'MODIFY'), (4, 'REMOVE')):
        call(proc, xstr('foo.org.example.') + arr(ALL), result())
    call(1, xstr('missing.org.example.') + arr([]), result(2, []))
    for proc in (5, 6, 7, 8, 9, 10):                                       # IB*
        call(proc, ib_request(), result(0, [OBJS[5], OBJS[7]]))
    call(12, xstr('org.example.') + xstr('root.example.'),                  # FINDDIRECTORY
         u32(0) + xstr('org.example.') + xdata(b'\x11' * 10) + xdata(b'\x22' * 6))
    call(14, taglist(), taglist())                                         # STATUS
    call(21, arr([u32(1) + xstr('x')]), arr([]))                           # SERVSTATE (empty reply)
    call(15, xstr('org.example.') + u32(1700000300) + arr([dirserver()]), logresult())   # DUMPLOG
    call(16, xstr('org.example.') + u32(1700000300) + arr([]), logresult())               # DUMP
    call(17, xdata(b'\xde\xad\xbe\xef'), u32(1))                            # CALLBACK
    call(18, xstr('org.example.'), u32(1700000400))                         # CPTIME: the reply is only a time
    call(19, xstr('org.example.'), u32(0) + u32(11) + u32(22))              # CHECKPOINT
    call(20, xstr('org.example.') + u32(1700000500), b'')                   # PING
    for proc in (22, 23, 24):                                               # MKDIR, RMDIR, UPDKEYS
        call(proc, xstr('sub.org.example.'), u32(0))
    call(1, xstr('dup.org.example.') + arr([OBJS[0], OBJS[1]]), result(0, [OBJS[1]]))
    # --- callback program (calls only; the server of the callback is the client of the lookup)
    call(0, b'', b'', prog=CB, vers=1, sport=1023)
    call(1, arr(ALL), u32(1), prog=CB, vers=1, sport=1023)                  # RECEIVE
    call(2, b'', b'', prog=CB, vers=1, sport=1023)                          # FINISH
    call(3, u32(5), b'', prog=CB, vers=1, sport=1023)                       # ERROR

def malformed_frames():
    # reproducer: callback RECEIVE with 0xffffffff entries and no data (was a minute of CPU)
    call(1, u32(0xffffffff) + u32(0) * 4, None, prog=CB, vers=1, sport=1024)
    call(1, u32(3), None, prog=CB, vers=1, sport=1024)
    call(1, xstr('foo.')[:6], None)
    call(1, xstr('foo.org.example.') + arr(ALL)[:50], None)
    call(18, xstr('org.example.'), b'\x00\x00')                            # short time reply
    call(5, ib_request()[:40], None)
    call(15, xstr('org.example.') + u32(1) + u32(5), None)                  # dump servers: five but no data
    call(1, xstr('foo.org.example.') + arr([OBJS[2][:120]]), None)         # truncated object
    call(1, xstr('foo.org.example.') + arr([obj_hdr(2) + xstr('d.') + u32(1) + u32(0x7fffffff)]), None)   # huge array count

def write_pcap(name, frs):
    with open(os.path.join(out, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

if __name__ == '__main__':
    main_frames()
    write_pcap('nisplus-coverage.pcap', frames)
    n = len(frames)
    frames.clear()
    malformed_frames()
    write_pcap('nisplus-coverage-malformed.pcap', frames)
    print(n, 'main frames,', len(frames), 'malformed frames')
