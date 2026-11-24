#!/usr/bin/env python3
# Generates test/captures/smb_pipe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic coverage captures for packet-smb-pipe.c (SMB
# Transaction on \PIPE\...: named pipe functions, DCE/RPC over named pipes
# and the LANMAN remote administration protocol "RAP").
# Usage: mksmb-pipe.py <outdir>   (writes smb-pipe-coverage.pcap and
# smb-pipe-coverage-malformed.pcap).  Everything is built with struct; the
# addresses are documentation addresses, nothing comes from a network.
# No keys, passwords or ciphertext are produced: password fields are zero.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from smblib import Cap, Conn, trans_req, trans_resp, U16, U32, U8

CONV = 0x1000       # the "converter" word of a LANMAN response: pointers are offset + CONV
LANMAN = r'\PIPE\LANMAN'

# LANMAN API numbers used here
API = dict(NetShareEnum=0, NetShareGetInfo=1, NetServerGetInfo=13, NetUserGetInfo=56,
           NetUserGetGroups=59, NetWkstaGetInfo=63, NetRemoteTOD=91, NetServerEnum2=104,
           NetUserAdd=54, NetUserEnum=53, NetWkstaUserLogon=132, NetWkstaUserLogoff=133,
           NetServerEnum3=215, SamOEM=214, NetGroupEnum=47, NetGetDCName=119, NetUserEnum2=131,
           NetFileEnum2=112, WPrintQEnum=69, NetStatisticsGet2=122, NetConfigGet2=117)


def z(s):
    return s.encode() + b'\0'


def fixed(s, n):
    return s.encode().ljust(n, b'\0')[:n]


def lm_req(c, cmd, pdesc, ddesc, vals=b'', aux=None, data=b'', setup=b'', name=LANMAN, **kw):
    """A LANMAN request: function code, parameter and data descriptors, the
    parameters and optionally the auxiliary data descriptor."""
    params = U16(cmd) + z(pdesc) + z(ddesc) + vals + (z(aux) if aux is not None else b'')
    return trans_req(c, 0x25, setup, params, data, name=name, **kw)


def lm_resp(c, params=b'', data=b'', status=0, conv=CONV, setup=b'', **kw):
    return trans_resp(c, 0x25, setup, U16(status, conv) + params, data, **kw)


class Tail:
    """Strings referenced by pointers from fixed size structures that
    precede them in the data buffer."""

    def __init__(self, base):
        self.base = base
        self.buf = b''

    def ptr(self, s):
        if s is None:
            return U32(0)
        off = self.base + len(self.buf)
        self.buf += z(s)
        return U32(off + CONV)

    def bptr(self, b):
        off = self.base + len(self.buf)
        self.buf += b
        return U32(off + CONV)


def build(n, size, mk):
    """n structures of size octets; mk(i, tail) returns one of them."""
    t = Tail(n * size)
    body = b''.join(mk(i, t) for i in range(n))
    assert len(body) == n * size, (len(body), n * size)
    return body + t.buf


def rr(c, req, rsp, **kw):
    c.nextmid()
    c.send(True, req)
    c.send(False, rsp)


# ---------------------------------------------------------------------------
def lanman(c):
    """One request/response pair for every command the dissector knows, at each
    information level it knows."""
    # NetShareEnum: level 1, 3 shares
    def share(i, t):
        return fixed(['IPC$', 'Share', 'Print'][i], 13) + b'\0' + U16([3, 0, 1][i]) + t.ptr(['Remote IPC', 'a share', None][i])
    rr(c, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 8192)),
       lm_resp(c, U16(3, 3), build(3, 20, share)))
    # level 0 : no list of items for this level (shown as unknown entries)
    rr(c, lm_req(c, 0, 'WrLeh', 'B13', U16(0, 8192)), lm_resp(c, U16(2, 2), fixed('IPC$', 13) + fixed('C$', 13)))
    # no entries at all
    rr(c, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 8192)), lm_resp(c, U16(0, 0), b''))
    # non-zero status: error response with parameters only
    rr(c, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 8192)), lm_resp(c, U16(0, 0), b'', status=2123))
    # NetShareEnum with an auxiliary data descriptor and 'N' in the data descriptor
    def share_aux(i, t):
        return fixed('Share%d' % i, 13) + b'\0' + U16(0) + t.ptr('c') + U16(1)
    # fixed size 22; auxiliary structures follow the entries' strings: layout is entry, aux, entry, aux
    ent = b''
    t = Tail(2 * (20 + 2 + 13))
    for i in range(2):
        ent += fixed('Share%d' % i, 13) + b'\0' + U16(0) + t.ptr('c%d' % i) + U16(1) + fixed('aux%d' % i, 13)
    rr(c, lm_req(c, 0, 'WrLeh', 'B13BWzN', U16(1, 8192), aux='B13'),
       lm_resp(c, U16(2, 2), ent + t.buf))
    # NetShareGetInfo, levels 0, 1, 2 (and 3, which has no table)
    rr(c, lm_req(c, 1, 'zWrLh', 'B13', z('Share') + U16(0, 512)),
       lm_resp(c, U16(13), fixed('Share', 13)))
    t = Tail(20)
    rr(c, lm_req(c, 1, 'zWrLh', 'B13BWz', z('Share') + U16(1, 512)),
       lm_resp(c, U16(30), fixed('Share', 13) + b'\0' + U16(0) + t.ptr('comment') + t.buf))
    t = Tail(40)
    body = fixed('Share', 13) + b'\0' + U16(0) + t.ptr('the comment') + U16(0x1f) + U16(0xffff) + U16(2) + t.ptr('C:\\share') + bytes(9) + b'\0' + t.buf
    rr(c, lm_req(c, 1, 'zWrLh', 'B13BWzWWWzB9B', z('Share') + U16(2, 512)), lm_resp(c, U16(60), body))
    t = Tail(40)
    body = fixed('Share', 13) + b'\0' + U16(0) + t.ptr('c') + U16(0x1f) + U16(7) + U16(2) + t.ptr('C:\\share') + bytes(9) + b'\0' + t.buf
    rr(c, lm_req(c, 1, 'zWrLh', 'B13BWzWWWzB9B', z('Share') + U16(2, 512)), lm_resp(c, U16(60), body))
    rr(c, lm_req(c, 1, 'zWrLh', 'B13', z('Share') + U16(3, 512)), lm_resp(c, U16(13), fixed('Share', 13)))

    # NetServerGetInfo, level 0 and 1
    rr(c, lm_req(c, 13, 'WrLh', 'B16', U16(0, 512)), lm_resp(c, U16(16), fixed('SERVER1', 16)))
    t = Tail(26)
    rr(c, lm_req(c, 13, 'WrLh', 'B16BBDz', U16(1, 512)),
       lm_resp(c, U16(40), fixed('SERVER1', 16) + U8(6, 1) + U32(0x00009003) + t.ptr('Server comment') + t.buf))

    # NetServerEnum2 and 3: levels 0 and 1, several server types
    def srv(i, t):
        return fixed('HOST%d' % i, 16) + U8(5, i) + U32([0x1, 0x8003, 0xffffffff][i]) + t.ptr(['', 'second', None][i])
    rr(c, lm_req(c, 104, 'WrLehDz', 'B16BBDz', U16(1, 4096) + U32(0xffffffff) + z('WORKGROUP')),
       lm_resp(c, U16(3, 3), build(3, 26, srv)))
    rr(c, lm_req(c, 104, 'WrLehDz', 'B16', U16(0, 4096) + U32(0x80000000) + z('')),
       lm_resp(c, U16(2, 2), fixed('A', 16) + fixed('B', 16)))
    rr(c, lm_req(c, 215, 'WrLehDzz', 'B16BBDz', U16(1, 4096) + U32(0x2) + z('WORKGROUP') + z('HOST1')),
       lm_resp(c, U16(3, 5), build(3, 26, srv)))

    # NetUserGetInfo level 11
    t = Tail(86)
    body = (fixed('alice', 21) + b'\0' + t.ptr('comment') + t.ptr('user comment') + t.ptr('Alice A') + U16(1) + U32(0) +
            U32(3600) + t.ptr('\\\\srv\\home') + t.ptr('') + U32(1700000000) + U32(0) + U16(0) + U16(0xffff) +
            t.ptr('SRV') + U16(1) + t.ptr('*') + U32(0xffffffff) + U16(168) + t.bptr(b'\xff' * 21) + U16(437))
    assert len(body) == 86, len(body)
    body += t.buf
    rr(c, lm_req(c, 56, 'zWrLh', 'B21BzzzWDDzzDDWWzWzDWb21W', z('alice') + U16(11, 1024)), lm_resp(c, U16(0x90), body))
    # a logon hours pointer of the wrong length and one past the end of the data
    t = Tail(86)
    body = (fixed('bob', 21) + b'\0' + t.ptr('c') + t.ptr('u') + t.ptr('f') + U16(2) + U32(1) +
            U32(0) + t.ptr('h') + t.ptr('p') + U32(0) + U32(0xffffffff) + U16(5) + U16(7) +
            t.ptr('S') + U16(1) + t.ptr('w') + U32(1000) + U16(168) + t.bptr(b'\xaa' * 20) + U16(437))
    rr(c, lm_req(c, 56, 'zWrLh', 'B21BzzzWDDzzDDWWzWzDWb20W', z('bob') + U16(11, 1024)), lm_resp(c, U16(0x90), body + t.buf))
    t = Tail(86)
    body = (fixed('carl', 21) + b'\0' + t.ptr('c') + t.ptr('u') + t.ptr('f') + U16(2) + U32(1) +
            U32(0) + t.ptr('h') + t.ptr('p') + U32(0) + U32(0xffffffff) + U16(5) + U16(7) +
            t.ptr('S') + U16(1) + t.ptr('w') + U32(1000) + U16(168) + U32(0x7000) + U16(437))
    rr(c, lm_req(c, 56, 'zWrLh', 'B21BzzzWDDzzDDWWzWzDWb21W', z('carl') + U16(11, 1024)), lm_resp(c, U16(0x90), body + t.buf))
    # NetUserGetGroups level 0
    rr(c, lm_req(c, 59, 'zWrLeh', 'B21', z('alice') + U16(0, 512)),
       lm_resp(c, U16(2, 2), fixed('Users', 21) + fixed('Admins', 21)))
    # NetRemoteTOD
    rr(c, lm_req(c, 91, 'rLh', 'DDBBBBWWBBWB', U16(0x1c)),
       lm_resp(c, U16(21), U32(1700000000, 123456) + U8(12, 30, 15, 50) + U16(0xff88, 100) + U8(11, 11) + U16(2026) + U8(3)))
    rr(c, lm_req(c, 91, 'rLh', 'DDBBBBWWBBWB', U16(0x1c)),
       lm_resp(c, U16(21), U32(0, 0) + U8(0, 0, 0, 0) + U16(120, 0) + U8(1, 1) + U16(1980) + U8(0)))
    rr(c, lm_req(c, 91, 'rLh', 'DDBBBBWWBBWB', U16(0x1c)),
       lm_resp(c, U16(21), U32(0xffffffff, 0) + U8(0, 0, 0, 0) + U16(0, 100) + U8(1, 1) + U16(1980) + U8(0)))
    # NetWkstaGetInfo level 10
    t = Tail(22)
    rr(c, lm_req(c, 63, 'WrLh', 'zzzBBzz', U16(10, 512)),
       lm_resp(c, U16(80), t.ptr('WKS1') + t.ptr('alice') + t.ptr('DOMAIN') + U8(5, 1) + t.ptr('LOGONDOM') + t.ptr('OTHER') + t.buf))
    # NetWkstaUserLogon: request with a 54 octet argument block (the password is empty) and
    # one of the wrong length (a warning)
    args = fixed('alice', 21) + b'\0' + bytes(15) + b'\0' + fixed('WKS1', 16)
    assert len(args) == 54
    body = (U16(0) + fixed('alice', 21) + b'\0' + U16(1) + U32(0) + U16(0xffff) + U16(3) + U32(0) + U32(1700000000) +
            U32(0) + U32(0xffffffff) + U32(3600) + U32(0) + U32(0xffffffff))
    t = Tail(len(body) + 16)
    body += t.ptr('SRV') + t.ptr('DOM') + t.ptr('logon.cmd') + U32(0) + t.buf
    rr(c, lm_req(c, 132, 'OOWb54WrLh', 'WB21BWDWWDDDDDDDzzzD', U16(1) + args + U16(0x400) + U16(1024)),
       lm_resp(c, U16(len(body)), body))
    rr(c, lm_req(c, 132, 'OOWb30WrLh', 'WB21BWDWWDDDDDDDzzzD', U16(1) + bytes(30) + U16(0x400) + U16(1024)),
       lm_resp(c, U16(0), b''))
    # NetWkstaUserLogoff
    rr(c, lm_req(c, 133, 'b21b1b16WrLh', 'WDW', fixed('alice', 21) + b'\0' + fixed('WKS1', 16) + U16(1, 512)),
       lm_resp(c, U16(8), U16(0) + U32(120) + U16(5)))
    # a request whose parameter descriptor is not the usual one still goes through the
    # item table: strings as 'z', a null pointer as 'O'
    # commands without any table: the default parameter, data and auxiliary handling
    # NetUserAdd: a data buffer in the request ('s'), an unknown level
    rr(c, lm_req(c, 54, 'WsTW', 'B21BzzzWDDz', U16(1) + U16(40) + U16(1), data=fixed('carol', 21) + b'\0' + U32(0) + U32(0) + U32(0) + U16(1) + U32(0) + U32(0) + U32(0)),
       lm_resp(c, b''))
    # a request data buffer with an auxiliary structure descriptor
    rr(c, lm_req(c, 54, 'WsTW', 'B8N', U16(1) + U16(40) + U16(1), aux='B4', data=b'12345678' + U16(2) + b'abcdwxyz'),
       lm_resp(c, b''))
    # a request with data but which has no data buffer flag in the descriptor
    rr(c, lm_req(c, 53, 'WrLeh', 'B21', U16(0, 512), data=b'x' * 8),
       lm_resp(c, U16(1, 1), fixed('u', 21)))
    # all descriptor characters the request and response parameter code knows
    # W D b O z F L s T r e h i g and counts
    rr(c, lm_req(c, 47, 'WrLeh', 'B21', U16(0, 512)), lm_resp(c, U16(1, 1), fixed('Group', 21)))
    rr(c, lm_req(c, 53, 'WDb4OzF3LsTrg2', 'B21', U16(0) + U32(77) + b'abcd' + z('str') + bytes(3) + U16(512) + U16(0)),
       lm_resp(c, U16(1, 1), fixed('u', 21)))
    # response parameters of every type: g with a count, h, i, e; more types than
    # the item table holds
    rr(c, lm_req(c, 112, 'WrLehDz', 'B8', U16(1, 512) + U32(0) + z('x')),
       lm_resp(c, U16(1, 1), fixed('f', 8)))
    rr(c, lm_req(c, 117, 'zrLhgiW', 'B8', z('x') + U16(512) + U16(7) + U32(8) + U16(9)), lm_resp(c, U16(4) + b'xy' + U32(5) + U16(6), fixed('cfg', 8)))
    # entries without data in the response
    rr(c, lm_req(c, 69, 'WrLeh', 'B8', U16(1, 512)), lm_resp(c, U16(2, 2), b''))
    # a response for descriptors with pointers: strings, bytes and null pointers
    t = Tail(20)
    body = t.ptr('first') + t.bptr(b'\x01\x02\x03') + U32(0) + U16(9) + U32(12345) + U16(0) + t.buf
    rr(c, lm_req(c, 122, 'WrLehDz', 'zb3zWDW', U16(1, 512) + U32(0) + z('x')), lm_resp(c, U16(1, 1), body))
    # ... and with an O null pointer, D, B in the data descriptor
    rr(c, lm_req(c, 122, 'WrLeh', 'OWDB3', U16(1, 512)), lm_resp(c, U16(1, 1), U32(0) + U16(1) + U32(2) + b'abc'))
    # an 'O' (null pointer) in the request and in the data descriptor, matched with items that have a field
    rr(c, lm_req(c, 1, 'OWrLh', 'B13', U16(0, 512)), lm_resp(c, U16(13), fixed('Share', 13)))
    rr(c, lm_req(c, 1, 'zWrLh', 'O', z('Share') + U16(0, 512)), lm_resp(c, U16(8), bytes(8)))
    # an unknown character in the data descriptor
    rr(c, lm_req(c, 0, 'WrLeh', 'B13Q', U16(1, 512)), lm_resp(c, U16(1, 1), fixed('Share', 13) + b'q'))
    # no 'r' (receive buffer) in the parameter descriptor but data in the response
    rr(c, lm_req(c, 0, 'WLeh', 'B13BWz', U16(1, 8192)), lm_resp(c, U16(1, 1), fixed('Share', 13) + b'\0' + U16(0) + U32(0)))
    # a LANMAN request without parameters: nothing for the LANMAN dissector, SMB Pipe only
    c.nextmid()
    c.send(True, trans_req(c, 0x25, b'', b'', b'x', name=LANMAN))
    c.send(False, trans_resp(c, 0x25, b'', b'', b'y'))
    # Interim response (no parameters and no data)
    c.nextmid()
    c.send(True, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 8192)))
    c.send(False, trans_resp(c, 0x25, b'', b'', b''))
    c.send(False, lm_resp(c, U16(0, 0), b''))
    # an unknown command number: uses the default tables; response too
    rr(c, lm_req(c, 9999, 'WrLeh', 'B8', U16(1, 512)), lm_resp(c, U16(1, 1), fixed('u', 8)))
    # a request whose descriptors have a number larger than the packet (count clamp)
    rr(c, lm_req(c, 53, 'WrLeh', 'B8', U16(1, 512)), lm_resp(c, U16(1, 1), fixed('u', 8)))


def dcerpc_bind(callid=1, uuid='a1b2c3d4-1111-4222-8333-444455556666', frag=None):
    import uuid as U
    xfer = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    body = U16(4280, 4280) + U32(0) + U8(1, 0, 0, 0) + U16(0, 1) + U.UUID(uuid).bytes_le + U16(1, 0) + xfer + U32(2)
    return U8(5, 0, 11, 3) + U8(0x10, 0, 0, 0) + U16(16 + len(body) if frag is None else frag, 0) + U32(callid) + body


def dcerpc_bind_ack(callid=1):
    xfer = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    port = b'\\PIPE\\test\0'
    body = U16(4280, 4280) + U32(0x1234) + U16(len(port)) + port
    body += b'\0' * ((-len(body)) % 4) + U8(1, 0, 0, 0) + U16(0, 0) + xfer + U32(2)
    return U8(5, 0, 12, 3) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def dcerpc_req(callid, stub, opnum=3, flags=3, ptype=0, ctx=0):
    body = U32(len(stub)) + U16(ctx, opnum) + stub
    return U8(5, 0, ptype, flags) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def dcerpc_resp(callid, stub, flags=3):
    body = U32(len(stub)) + U16(0, 0) + stub
    return U8(5, 0, 2, flags) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def nmpipe(c, func, fid, params=b'', data=b'', rparams=b'', rdata=b'', name=r'\PIPE\test', rsetup=b'', req=True, resp=True):
    """A transaction on a named pipe with its function in the setup words."""
    c.nextmid()
    setup = U16(func, fid) if fid is not None else U16(func, 5)
    if req:
        c.send(True, trans_req(c, 0x25, setup, params, data, name=name))
    if resp:
        c.send(False, trans_resp(c, 0x25, rsetup, rparams, rdata))


def pipes(c):
    fid = 0x4000
    # DCE/RPC over TransactNmPipe: bind, bind_ack, request, response
    nmpipe(c, 0x26, fid, data=dcerpc_bind(1), rdata=dcerpc_bind_ack(1))
    nmpipe(c, 0x26, fid, data=dcerpc_req(2, b'stub-data-1'), rdata=dcerpc_resp(2, b'reply-1'))
    # a request over two transactions: the PDU is longer than the first transaction's data
    big = dcerpc_req(3, bytes(range(64)) * 3, flags=3)
    nmpipe(c, 0x26, fid, data=big[:100], rdata=b'')
    nmpipe(c, 0x26, fid, data=big[100:], rdata=dcerpc_resp(3, b'done'))
    # ... and a response over two transactions (three, the last one in a later frame)
    rbig = dcerpc_resp(4, bytes(range(200)))
    nmpipe(c, 0x26, fid, data=dcerpc_req(4, b'give me more'), rdata=rbig[:80])
    nmpipe(c, 0x26, fid, data=b'\x05\x00\x00', rdata=rbig[80:160])
    nmpipe(c, 0x26, fid, data=b'\x05\x00\x00', rdata=rbig[160:])
    # a second pipe (another FID) with a plain request
    nmpipe(c, 0x26, 0x4001, data=dcerpc_bind(7, '99999999-0000-4000-8000-000000000001'), rdata=dcerpc_bind_ack(7))
    # a PDU that is not DCE/RPC: left to the data dissector
    nmpipe(c, 0x26, fid, data=b'not dce/rpc at all', rdata=b'xx')
    # TransactNmPipe, no data in the request and a response without data
    nmpipe(c, 0x26, fid)
    # CallNamedPipe (function, priority) with DCE/RPC data: no FID, nothing to decode
    nmpipe(c, 0x54, None, data=dcerpc_bind(8), rdata=dcerpc_bind_ack(8))
    # CallNamedPipe on LANMAN: the LANMAN dissector is called for it
    c.nextmid()
    c.send(True, lm_req(c, 91, 'rLh', 'DDBBBBWWBBWB', U16(0x1c), setup=U16(0x54, 0)))
    c.send(False, lm_resp(c, U16(21), U32(1700000000, 1) + U8(1, 2, 3, 4) + U16(0, 0) + U8(1, 1) + U16(2026) + U8(0)))
    # WaitNamedPipe
    nmpipe(c, 0x53, None, name=r'\PIPE\test')
    # PeekNamedPipe: request, response (available, remaining, status = connected)
    nmpipe(c, 0x23, fid, rparams=U16(10, 4, 3), rdata=b'peek data')
    nmpipe(c, 0x23, fid, rparams=U16(10, 4, 2))
    # response without any parameters
    nmpipe(c, 0x23, fid)
    # QNmPHandState: request, response with the state word; one without parameters
    nmpipe(c, 0x21, fid, rparams=U16(0x8105))
    nmpipe(c, 0x21, fid)
    # SetNmPHandState: request with the state word; one without
    nmpipe(c, 0x01, fid, params=U16(0x8100))
    nmpipe(c, 0x01, fid)
    # QNmPipeInfo: level 1 (output and input buffer sizes, instances, name), level 2 (not decoded)
    nmpipe(c, 0x22, fid, params=U16(1), rdata=U16(4096, 4096) + U8(255, 1, 5) + b'\\test')
    nmpipe(c, 0x22, fid, params=U16(2), rdata=bytes(8))
    nmpipe(c, 0x22, fid)
    # RawReadNmPipe: the response data; RawWriteNmPipe: request data, response bytes written
    nmpipe(c, 0x11, fid, rdata=b'raw read data')
    nmpipe(c, 0x11, fid)
    nmpipe(c, 0x31, fid, data=b'raw write data', rparams=U16(14))
    nmpipe(c, 0x31, fid)
    # an unknown function code
    nmpipe(c, 0x99, fid, data=b'??', rdata=b'??')
    # a transaction on the pipe root and a name like \PIPE\\ with no setup words
    c.nextmid()
    c.send(True, trans_req(c, 0x25, b'', b'', dcerpc_bind(9), name=r'\PIPE\\'))
    c.send(False, trans_resp(c, 0x25, b'', b'', dcerpc_bind_ack(9)))
    # the reproducer of "SMB Pipe: Keep the transaction function and FID from the
    # request": the request has no setup words, the response carries some (PeekNamedPipe)
    c.nextmid()
    c.send(True, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 4096)))
    c.send(False, trans_resp(c, 0x25, U16(0x23, 0x4000), U16(0, 0, 3), b''))


def malformed(outdir):
    cap = Cap(os.path.join(outdir, 'smb-pipe-coverage-malformed.pcap'))
    c = Conn(cap, 40003, 445)
    c.tid = 5
    # descriptor characters that do not match the type of the item in the
    # table: "Bad type field" (error)
    for cmd, pdesc, vals in ((1, 'WWrLh', U16(1, 2, 512)),            # W on a string
                             (1, 'DWrLh', U32(1) + U16(1, 512)),      # D on a string
                             (1, 'b4WrLh', b'abcd' + U16(1, 512)),    # b on a string
                             (13, 'zWrLh', z('x') + U16(1, 512)),     # z on a word
                             (13, 'b2rLh', b'ab' + U16(512)),         # b on a word
                             (13, 'DrLh', U32(1) + U16(512))):        # D on a word
        rr(c, lm_req(c, cmd, pdesc, 'B16', vals), lm_resp(c, U16(0), b''))
    # response parameter descriptors that do not match
    rr(c, lm_req(c, 0, 'WrLeg2', 'B13BWz', U16(1, 512)), lm_resp(c, U16(3) + b'ab', b''))
    rr(c, lm_req(c, 0, 'WrLei', 'B13BWz', U16(1, 512)), lm_resp(c, U16(3) + U32(5), b''))
    rr(c, lm_req(c, 91, 'rLh', 'DDBBBBWWBBWB', U16(0x1c)), lm_resp(c, U16(3), b'x' * 21))
    # data descriptor characters that do not match
    t = Tail(0)
    for dd in ('WWz', 'DBz', 'B13BzW', 'B13Bb4', 'B13BWB', 'B13BWD', 'B13BWb3'):
        rr(c, lm_req(c, 0, 'WrLeh', dd, U16(1, 512)),
           lm_resp(c, U16(1, 1), fixed('Share', 13) + b'\0' + U16(0) + U32(0x1000 + 26) + b'comment\0abc'))
    # a count larger than any SMB payload is clamped to 65535 (then runs off the buffer)
    rr(c, lm_req(c, 13, 'WrLh', 'B99999999999', U16(0, 512)), lm_resp(c, U16(16), fixed('S', 16)))
    rr(c, lm_req(c, 13, 'WrLb99999999999h', 'B16', U16(0, 512) + bytes(8)), lm_resp(c, U16(16), fixed('S', 16)))
    # NetServerGetInfo level 1 with a 2 octet count for a one octet field
    rr(c, lm_req(c, 13, 'WrLh', 'B16B2B2Dz', U16(1, 512)), lm_resp(c, U16(40), fixed('S', 16) + bytes(16)))
    # entries that do not advance: a data descriptor with no data items
    rr(c, lm_req(c, 0, 'WrLeh', '', U16(1, 512)), lm_resp(c, U16(3, 3), bytes(40)))
    rr(c, lm_req(c, 0, 'WrLeh', 'O', U16(1, 512)), lm_resp(c, U16(3, 3), bytes(40)))
    # more entries than the data holds, auxiliary structures that make no progress
    rr(c, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 512)), lm_resp(c, U16(65535, 65535), fixed('Share', 13) + bytes(7)))
    rr(c, lm_req(c, 0, 'WrLeh', 'B13N', U16(1, 512), aux=''), lm_resp(c, U16(2, 2), fixed('A', 13) + U16(3) + fixed('B', 13) + U16(3)))
    # the byte count of a request: parameters cut after the function code, an unterminated
    # descriptor
    c.nextmid()
    c.send(True, trans_req(c, 0x25, b'', U16(0), b'', name=LANMAN))
    c.send(False, lm_resp(c, U16(0, 0), b''))
    c.nextmid()
    c.send(True, trans_req(c, 0x25, b'', U16(0) + b'WrLeh', b'', name=LANMAN))
    c.send(False, trans_resp(c, 0x25, b'', U16(0), b''))
    # request parameters shorter than the descriptor says
    c.nextmid()
    c.send(True, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1)))
    c.send(False, lm_resp(c, U16(3, 3), build(1, 20, lambda i, t: fixed('x', 13) + b'\0' + U16(0) + t.ptr('c'))))
    # response parameters cut short
    c.nextmid()
    c.send(True, lm_req(c, 0, 'WrLeh', 'B13BWz', U16(1, 512)))
    c.send(False, trans_resp(c, 0x25, b'', U16(0), b''))
    # NetWkstaUserLogon argument block cut short
    c.nextmid()
    c.send(True, lm_req(c, 132, 'OOWb54WrLh', 'W', U16(1) + b'short'))
    c.send(False, trans_resp(c, 0x25, b'', U16(0, 0), b''))
    # pipe functions with parameters or setup words cut short
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(0x23), b'', b'', name=r'\PIPE\test'))
    c.send(False, trans_resp(c, 0x25, U16(0x23), U16(1), b''))
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(0x22, 0x4000), U16(1), b'', name=r'\PIPE\test'))
    c.send(False, trans_resp(c, 0x25, b'', b'', U16(10, 10) + U8(1, 1, 200) + b'ab'))
    # QNmPipeInfo response cut inside the fixed part
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(0x22, 0x4000), U16(1), b'', name=r'\PIPE\test'))
    c.send(False, trans_resp(c, 0x25, b'', b'', U16(10, 10) + U8(1)))
    cap.close()


def main(outdir):
    cap = Cap(os.path.join(outdir, 'smb-pipe-coverage.pcap'))
    c = Conn(cap, 40001, 445)
    c.tid = 5
    c2 = Conn(cap, 40002, 445)
    c2.tid = 5
    lanman(c)
    pipes(c2)
    cap.close()
    malformed(outdir)


if __name__ == '__main__':
    main(sys.argv[1])
