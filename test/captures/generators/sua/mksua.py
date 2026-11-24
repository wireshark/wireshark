#!/usr/bin/env python3
# Generates test/captures/sua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-sua.c (SUA, RFC 3868 and the draft version 8).
# Usage: mksua.py <outdir>
# SUA over SCTP: port 14001 and payload protocol identifier 4 are
# registered by default; the draft 8 parameters need -o sua.version:... .
import os
import struct
import sys
from pcaplib import Pcap, eth, ip4, sctp_data

DLT_EN10MB = 1
SUA_PPI, SUA_PORT = 4, 14001

def u16(x): return struct.pack('!H', x)
def u32(x): return struct.pack('!I', x)

def param(tag, value=b''):
    n = 4 + len(value)
    return struct.pack('!HH', tag, n) + value + b'\0' * ((-n) % 4)

# message classes
MGMT, SSNM, ASPSM, ASPTM, CL, CO, RKM = 0, 2, 3, 4, 7, 8, 9

def msg(cls, typ, *params):
    body = b''.join(params)
    return struct.pack('!BBBBI', 1, 0, cls, typ, 8 + len(body)) + body

# ---- RFC 3868 tags ------------------------------------------------------------
class T:
    INFO, ROUTING_CONTEXT, DIAG, HEARTBEAT, TRAFFIC_MODE, ERROR_CODE, STATUS = 4, 6, 7, 9, 0x0b, 0x0c, 0x0d
    ASP_ID, AFFECTED_PC, CORRELATION = 0x11, 0x12, 0x13
    REG_RESULT, DEREG_RESULT, REG_STATUS, DEREG_STATUS, LOCAL_RK = 0x14, 0x15, 0x16, 0x17, 0x18
    HOP, SRC, DST, SRN, DRN, CAUSE, SEQ, RSEQ, ASP_CAP, CREDIT, DATA, USER_CAUSE, NETAPP, RK = (
        0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109, 0x10a, 0x10b, 0x10c, 0x10d, 0x10e)
    DRN_LABEL, TID_LABEL, ADDR_RANGE, SMI, IMPORTANCE, PRIORITY, PROTO_CLASS, SEQ_CONTROL, SEGMENTATION, CONGESTION = (
        0x10f, 0x110, 0x111, 0x112, 0x113, 0x114, 0x115, 0x116, 0x117, 0x118)
    GT, PC, SSN, IPV4, HOST, IPV6 = 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8006

def gt(digits='12345678', gti=4, tt=0, np=1, nai=4):
    bcd = bytearray()
    d = [int(c) for c in digits]
    for i in range(0, len(d), 2):
        lo = d[i]
        hi = d[i + 1] if i + 1 < len(d) else 0
        bcd.append((hi << 4) | lo)
    return param(T.GT, b'\0\0\0' + bytes([gti, len(d), tt, np, nai]) + bytes(bcd))

def pc(v): return param(T.PC, u32(v))
def ssn(v): return param(T.SSN, b'\0\0\0' + bytes([v]))
def ipv4(a='192.0.2.55'): return param(T.IPV4, bytes(int(x) for x in a.split('.')))
def ipv6(): return param(T.IPV6, bytes(range(1, 17)))
def host(h='sg.example.net'): return param(T.HOST, h.encode())

def addr(tag, ri, *subs, bits=None):
    ind = {0: 0, 1: 4, 2: 3, 3: 0, 4: 1}.get(ri, 0) if bits is None else bits
    return param(tag, u16(ri) + u16(ind) + b''.join(subs))

def src(ri, *subs, **kw): return addr(T.SRC, ri, *subs, **kw)
def dst(ri, *subs, **kw): return addr(T.DST, ri, *subs, **kw)

def info(s='hello'): return param(T.INFO, s.encode())
def rc(*ctx): return param(T.ROUTING_CONTEXT, b''.join(u32(c) for c in ctx))
def hb(b=b'BEAT'): return param(T.HEARTBEAT, b)
def diag(b=b'\x01\x02\x03'): return param(T.DIAG, b)
def tmt(v): return param(T.TRAFFIC_MODE, u32(v))
def err(v): return param(T.ERROR_CODE, u32(v))
def status(t, i): return param(T.STATUS, u16(t) + u16(i))
def aspid(v=7): return param(T.ASP_ID, u32(v))
def affected(*pcs): return param(T.AFFECTED_PC, b''.join(bytes([m]) + v.to_bytes(3, 'big') for m, v in pcs))
def corr(v=0x1234): return param(T.CORRELATION, u32(v))
def netapp(v=1): return param(T.NETAPP, u32(v))
def hop(v=5): return param(T.HOP, b'\0\0\0' + bytes([v]))
def srn(v): return param(T.SRN, u32(v))
def drn(v): return param(T.DRN, u32(v))
def cause(t, v): return param(T.CAUSE, b'\0\0' + bytes([t, v]))
def seq(rcv, snd, more=0): return param(T.SEQ, b'\0\0' + bytes([(rcv << 1) | more, snd << 1]))
def rseq(n): return param(T.RSEQ, b'\0\0\0' + bytes([n << 1]))
def aspcap(classes=0x0f, iw=2): return param(T.ASP_CAP, b'\0\0' + bytes([classes, iw]))
def credit(v=8): return param(T.CREDIT, u32(v))
def data(b): return param(T.DATA, b)
def usercause(c, u): return param(T.USER_CAUSE, u16(c) + u16(u))
def smi(v=1): return param(T.SMI, b'\0\0\0' + bytes([v]))
def importance(v=3): return param(T.IMPORTANCE, b'\0\0\0' + bytes([v]))
def prio(v=2): return param(T.PRIORITY, b'\0\0\0' + bytes([v]))
def pclass(cls=1, roe=0): return param(T.PROTO_CLASS, b'\0\0\0' + bytes([(roe << 7) | cls]))
def seqctl(v=0x01020304): return param(T.SEQ_CONTROL, u32(v))
def segm(first=1, remaining=2, ref=0x112233): return param(T.SEGMENTATION, bytes([(first << 7) | remaining]) + ref.to_bytes(3, 'big'))
def congestion(v=2): return param(T.CONGESTION, u32(v))
def lrk(v=1): return param(T.LOCAL_RK, u32(v))
def regstat(v=0): return param(T.REG_STATUS, u32(v))
def deregstat(v=0): return param(T.DEREG_STATUS, u32(v))
def drnlabel(s=0, e=7, v=0x55): return param(T.DRN_LABEL, bytes([s, e]) + u16(v))
def tidlabel(s=0, e=7, v=0x55): return param(T.TID_LABEL, bytes([s, e]) + u16(v))
def rk(*subs): return param(T.RK, b''.join(subs))
def regres(*subs): return param(T.REG_RESULT, b''.join(subs))
def deregres(*subs): return param(T.DEREG_RESULT, b''.join(subs))
def addrange(*subs): return param(T.ADDR_RANGE, b''.join(subs))

SCMG_SSA = bytes([0x01, 0x08, 0x00, 0x01, 0x00])         # SCCP management: SSA
def build(out):
    p = Pcap(DLT_EN10MB)
    tsn = [1]
    def send(sua, from_asp=True, sport=None, sid=0):
        sp, dp = (31000, SUA_PORT) if from_asp else (SUA_PORT, 31000)
        a, b = ('192.0.2.1', '192.0.2.2') if from_asp else ('192.0.2.2', '192.0.2.1')
        mac = (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01') if from_asp else (b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02')
        pkt = sctp_data(sua, sp, dp, 0x11223344, tsn[0], SUA_PPI, sid=sid, ssn=tsn[0] & 0xffff)
        p.add(eth(ip4(132, pkt, a, b, ident=tsn[0]), 0x0800, *mac))
        tsn[0] += 1

    # --- management ---------------------------------------------------------------
    send(msg(MGMT, 0, err(0x01), netapp(), rc(1, 2), diag()))
    send(msg(MGMT, 0, err(0x19)), from_asp=False)
    send(msg(MGMT, 1, status(1, 3), aspid(), rc(10), info('state change')), from_asp=False)
    send(msg(MGMT, 1, status(2, 2), info('other')), from_asp=False)
    send(msg(MGMT, 1, status(7, 9)), from_asp=False)
    # --- SS7 network management ---------------------------------------------------------
    send(msg(SSNM, 1, netapp(3), rc(1), affected((0, 0x010203), (8, 0x040506)), ssn(8), usercause(1, 3), info('DUNA')), from_asp=False)
    send(msg(SSNM, 2, affected((0, 0x010203)), info()), from_asp=False)
    send(msg(SSNM, 3, rc(1), affected((0, 0x010203)), usercause(0, 3), ssn(8), smi()))
    send(msg(SSNM, 4, affected((0, 0x010203)), congestion(2)), from_asp=False)
    send(msg(SSNM, 5, affected((0, 0x010203)), usercause(2, 4)), from_asp=False)
    send(msg(SSNM, 6, affected((16, 0x010203)), smi(2), ssn(6)), from_asp=False)
    # --- ASP state and traffic maintenance ---------------------------------------------------
    send(msg(ASPSM, 1, aspid(9), info('ASP up'), aspcap()))
    send(msg(ASPSM, 4, info(), aspid(9)), from_asp=False)
    send(msg(ASPSM, 3, hb(b'0123456789')))
    send(msg(ASPSM, 6, hb(b'0123456789')), from_asp=False)
    send(msg(ASPSM, 2, info('bye')))
    send(msg(ASPSM, 5, b''), from_asp=False)
    send(msg(ASPTM, 1, tmt(1), rc(1, 2, 3), info('active')))
    send(msg(ASPTM, 3, tmt(2), rc(1)), from_asp=False)
    send(msg(ASPTM, 1, tmt(3)))
    send(msg(ASPTM, 2, rc(1)))
    send(msg(ASPTM, 4, rc(1)), from_asp=False)
    # --- connectionless ------------------------------------------------------------------------
    for ri, srcs, dsts in (
        (2, (pc(0x0101), ssn(8)), (pc(0x0202), ssn(6))),                  # route on SSN + PC
        (1, (gt('491721234567'), ssn(8)), (gt('4915112345', gti=4, np=7, nai=3), ssn(6))),   # route on GT
        (4, (ipv4('192.0.2.10'), ssn(8)), (ipv4('192.0.2.11'), ssn(9))),    # SSN + IP
        (3, (host('hlr.example.net'),), (host('msc.example.org'),)),         # hostname
        (4, (ipv6(), ssn(8)), (ipv6(), ssn(8))),
        (1, (gt('12345'), pc(0x0105), ssn(1)), (gt('678'), pc(0x0106), ssn(1))),
    ):
        send(msg(CL, 1, pclass(1, 1), seqctl(), src(ri, *srcs), dst(ri, *dsts), hop(), importance(), prio(), corr(), data(b'\x01\x02\x03\x04\x05')))
    send(msg(CL, 1, pclass(0), src(2, pc(0x0101), ssn(1)), dst(2, pc(0x0202), ssn(1)), segm(), data(SCMG_SSA)))
    send(msg(CL, 1, pclass(1), src(2, pc(0x0101), ssn(0xf0)), dst(2, pc(0x0202), ssn(0xf0)), segm(0, 0), data(b'\xaa' * 7)))
    send(msg(CL, 2, cause(1, 0), src(2, pc(0x0202), ssn(6)), dst(2, pc(0x0101), ssn(8)), data(b'\x01\x02\x03\x04\x05')), from_asp=False)
    # --- connection oriented: a connection, data, a release; a refusal ---------------------------
    send(msg(CO, 1, srn(0x1111), pclass(2), credit(), dst(2, pc(0x0202), ssn(0xf0)), src(2, pc(0x0101), ssn(0xf1)), hop(), importance(), prio(), data(b'CR')))
    send(msg(CO, 2, drn(0x1111), srn(0x2222), pclass(2), credit(), dst(2, ssn(0xf1)), data(b'CC')), from_asp=False)
    send(msg(CO, 8, drn(0x2222), seq(3, 4, 1), dst(2, ssn(0xf0)), src(2, ssn(0xf1)), data(b'\x01data one')))
    send(msg(CO, 9, drn(0x1111), rseq(5), credit(4), dst(2, ssn(0xf1)), src(2, ssn(0xf0))), from_asp=False)
    send(msg(CO, 11, drn(0x2222), srn(0x1111)))
    send(msg(CO, 10, drn(0x2222), srn(0x1111), cause(5, 1)), from_asp=False)
    send(msg(CO, 7, drn(0x2222), srn(0x1111), cause(4, 0)))
    send(msg(CO, 6, drn(0x1111), srn(0x2222), cause(4, 1)), from_asp=False)
    send(msg(CO, 4, drn(0x2222), srn(0x1111), cause(3, 0), data(b'bye')))
    send(msg(CO, 5, drn(0x1111), srn(0x2222)), from_asp=False)
    # a COAK for a connection whose CORE was not captured
    send(msg(CO, 2, drn(0x7777), srn(0x8888), pclass(2)), from_asp=False)
    send(msg(CO, 1, srn(0x3333), pclass(3), dst(1, gt('4912345')), src(1, gt('4967890'))))
    send(msg(CO, 3, drn(0x3333), cause(2, 1), dst(2, ssn(0xf1))), from_asp=False)
    for t, v in ((1, 0), (1, 3), (2, 2), (3, 1), (4, 1), (5, 2), (9, 9)):    # every cause type and value
        send(msg(CO, 3, drn(0x3333), cause(t, v)), from_asp=False)
    # --- routing key management -------------------------------------------------------------------
    send(msg(RKM, 1, rk(lrk(1), rc(5), tmt(2), netapp(), drnlabel(), tidlabel(),
                       dst(2, pc(0x0202), ssn(6)), addrange(src(2, pc(0x0101), ssn(8)), dst(1, gt('1234'))))))
    send(msg(RKM, 2, regres(lrk(1), regstat(0), rc(5)), regres(lrk(2), regstat(5))), from_asp=False)
    send(msg(RKM, 3, rc(5, 6)))
    send(msg(RKM, 4, deregres(rc(5), deregstat(0)), deregres(rc(6), deregstat(4))), from_asp=False)
    # --- parameter oddities ----------------------------------------------------------------------------
    send(msg(MGMT, 1, param(0x7777, b'\x01\x02\x03'), param(0x0001, b''), info('')), from_asp=False)   # unknown tags
    send(msg(MGMT, 1, info('padding'), param(T.DIAG, b'\x01'), param(T.HEARTBEAT, b'\x01\x02\x03\x04\x05')), from_asp=False)
    # the sua_ri state: a GT or PC outside an address uses no stale routing indicator
    send(msg(CL, 1, gt('1111'), pc(0x0303), ssn(7), data(b'ri')))
    # --- the reproducers of "SUA: Bound parameter nesting and reject short parameters":
    #     600 nested Routing Key and Source Address parameters (warning expert info,
    #     no assertion)
    def nest_rk(n):
        x = param(T.RK, b'')
        for _ in range(n - 1):
            x = param(T.RK, x)
        return x
    def nest_sa(n):
        x = struct.pack('!HHHH', T.SRC, 8, 2, 0)
        for _ in range(n - 1):
            x = struct.pack('!HHHH', T.SRC, 8 + len(x), 2, 0) + x
        return x
    send(msg(RKM, 1, nest_rk(5)))
    send(msg(CL, 1, nest_sa(5)))
    send(msg(RKM, 1, nest_rk(600)))
    send(msg(CL, 1, nest_sa(600)))
    p.write(os.path.join(out, 'sua-coverage.pcap'))

    # --- the malformed capture ------------------------------------------------------------------------------
    m = Pcap(DLT_EN10MB)
    t2 = [1000]
    def msend(sua):
        pkt = sctp_data(sua, 31000, SUA_PORT, 0x55667788, t2[0], SUA_PPI)
        m.add(eth(ip4(132, pkt, ident=t2[0]), 0x0800))
        t2[0] += 1
    msend(msg(CL, 1, nest_rk(9)))                              # nesting limit: 8 levels of parameters
    msend(msg(CL, 1, nest_sa(9)))
    msend(msg(MGMT, 1, struct.pack('!HH', T.INFO, 1)))         # parameter length below the header
    msend(msg(MGMT, 1, info('x'), struct.pack('!HH', T.DIAG, 3)))
    msend(msg(MGMT, 1, struct.pack('!HH', T.DATA, 0) + b'\0\0\0\0'))
    msend(msg(CL, 1, struct.pack('!HHI', T.DATA, 2, 0)))
    msend(msg(CL, 1, src(2, struct.pack('!HH', T.HOST, 2))))
    msend(msg(MGMT, 1, struct.pack('!HHI', T.STATUS, 20, 0)))   # parameter longer than the message
    msend(b'\x01\x00\x07')                                      # shorter than the common header
    msend(struct.pack('!BBBBI', 1, 0, 7, 1, 8) + struct.pack('!HH', T.SRC, 12) + b'\0\0')   # truncated address
    msend(msg(MGMT, 1, struct.pack('!HHHH', T.SSN, 6, 0, 0)))  # SSN parameter without the SSN octet
    msend(msg(MGMT, 1, struct.pack('!HHHH', T.GT, 8, 0, 0)))   # global title cut off
    msend(msg(MGMT, 1, struct.pack('!HHI', T.SEQ, 8, 0)))
    m.write(os.path.join(out, 'sua-coverage-malformed.pcap'))

    # --- draft version 8 (sua.version) -----------------------------------------------------------------------
    v = Pcap(DLT_EN10MB)
    t3 = [2000]
    V8 = dict(DATA=3, INFO=4, RC=6, DIAG=7, HB=9, TM=0x0b, ERR=0x0c, STATUS=0x0d, CONG=0x0f, ASPID=0x11, AFF=0x12,
              HOP=0x101, SRC=0x102, DST=0x103, SRN=0x104, DRN=0x105, CAUSE=0x106, SEQ=0x107, RSEQ=0x108, CAP=0x109,
              CREDIT=0x10a, UCAUSE=0x10c, NETAPP=0x10d, RK=0x10e, REGRES=0x10f, DEREGRES=0x110, RANGE=0x111,
              CORR=0x112, IMPORT=0x113, PRIO=0x114, PCLASS=0x115, SEQCTL=0x116, SEGM=0x117, SMI=0x118, TID=0x119,
              DRNL=0x11a, GT=0x8001, PC=0x8002, SSN=0x8003, IPV4=0x8004, HOST=0x8005, IPV6=0x8006)
    def vsend(sua):
        pkt = sctp_data(sua, 31000, SUA_PORT, 0x99aabbcc, t3[0], SUA_PPI)
        v.add(eth(ip4(132, pkt, ident=t3[0]), 0x0800))
        t3[0] += 1
    def vp(name, val=b''): return param(V8[name], val)
    def vaddr(name, ri, *subs): return vp(name, u16(ri) + u16(7 if ri == 1 else 3) + b''.join(subs))
    def vgt(d='12345'): return vp('GT', b'\0\0\0' + bytes([4, len(d), 0, 1, 4]) + bytes(int(d[i]) | ((int(d[i + 1]) if i + 1 < len(d) else 0) << 4) for i in range(0, len(d), 2)))
    vsend(msg(MGMT, 0, vp('ERR', u32(0x02)), vp('NETAPP', u32(1)), vp('RC', u32(1)), vp('DIAG', b'abc')))
    vsend(msg(MGMT, 0, vp('ERR', u32(0x18))))
    vsend(msg(MGMT, 1, vp('STATUS', u16(1) + u16(3)), vp('ASPID', u32(2)), vp('INFO', b'v8')))
    vsend(msg(SSNM, 1, vp('AFF', bytes([0, 1, 2, 3])), vp('UCAUSE', u16(1) + u16(2)), vp('CONG', u32(2)), vp('SMI', b'\0\0\0\x01')))
    vsend(msg(ASPSM, 3, vp('HB', b'beat')))
    vsend(msg(ASPTM, 1, vp('TM', u32(1)), vp('RC', u32(1) + u32(2))))
    vsend(msg(CL, 1, vp('PCLASS', b'\0\0\0\x81'), vp('SEQCTL', u32(1)), vaddr('SRC', 2, vp('PC', u32(0x101)), vp('SSN', b'\0\0\0\x08')),
              vaddr('DST', 1, vgt(), vp('SSN', b'\0\0\0\x06')), vp('HOP', b'\0\0\0\x05'), vp('IMPORT', b'\0\0\0\x03'), vp('PRIO', b'\0\0\0\x02'),
              vp('CORR', u32(7)), vp('SEGM', bytes([0x82, 0, 0, 1])), vp('DATA', b'v8 data')))
    vsend(msg(CL, 1, vaddr('SRC', 4, vp('IPV4', bytes([192, 0, 2, 1])), vp('SSN', b'\0\0\0\x08')), vaddr('DST', 3, vp('HOST', b'host.example')),
              vp('DATA', b'data')))
    vsend(msg(CL, 1, vaddr('SRC', 4, vp('IPV6', bytes(range(16))), vp('SSN', b'\0\0\0\x08')), vaddr('DST', 2, vp('PC', u32(0x202)), vp('SSN', b'\0\0\0\x08')),
              vp('DATA', b'data')))
    vsend(msg(CO, 1, vp('SRN', u32(1)), vp('CREDIT', u32(4)), vaddr('DST', 2, vp('PC', u32(2)), vp('SSN', b'\0\0\0\x06'))))
    vsend(msg(CO, 8, vp('DRN', u32(1)), vp('SEQ', b'\0\0\x04\x06'), vp('DATA', b'x')))
    vsend(msg(CO, 9, vp('DRN', u32(1)), vp('RSEQ', b'\0\0\0\x06'), vp('CREDIT', u32(4))))
    vsend(msg(CO, 3, vp('DRN', u32(1)), vp('CAUSE', b'\0\0\x02\x01')))
    vsend(msg(RKM, 1, vp('RK', vp('TID', bytes([0, 7, 0, 5]) ) + vp('DRNL', bytes([0, 7, 0, 5])) + vp('RANGE', vaddr('SRC', 2, vp('PC', u32(1)))))))
    vsend(msg(RKM, 2, vp('REGRES', vp('RC', u32(1)))))
    vsend(msg(RKM, 4, vp('DEREGRES', vp('RC', u32(1)))))
    vsend(msg(MGMT, 1, param(0x7777, b'\1\2\3')))
    v.write(os.path.join(out, 'sua-coverage-v08.pcap'))

build(sys.argv[1] if len(sys.argv) > 1 else '.')
