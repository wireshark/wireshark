#!/usr/bin/env python3
# Generates test/captures/smb_browse_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic coverage captures for packet-smb-browse.c (the
# Browser protocol in SMB mailslots \MAILSLOT\BROWSE and \MAILSLOT\LANMAN,
# and the server type flags shared with RAP and srvsvc).
# Usage: mksmb-browse.py <outdir>   (writes smb-browse-coverage.pcap and
# smb-browse-coverage-malformed.pcap).  Everything is built with struct; the
# addresses are documentation addresses, nothing comes from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import uuid
from smblib import Cap, Conn, hdr_conn, nbds, trans_req, trans_resp, U16, U32, U8

BROWSE = r'\MAILSLOT\BROWSE'
LANMAN = r'\MAILSLOT\LANMAN'
KW = dict(mid=0, pid=0, uid=0, tid=0)

# server type bits (low to high)
ALL_TYPES = 0xffffffff
OSVERS = [(6, 1), (6, 0), (5, 2), (5, 1), (5, 0), (4, 0), (3, 51), (10, 0)]


def name16(n):
    return n.encode().ljust(16, b'\0')


def host_ann(cmd, name, osv=(5, 1), flags=0x00001003, update=1, period=720000, comment='a comment', sig=True, proto=(15, 1)):
    """Host (1), local master (15) and domain/workgroup (12) announcement of \\MAILSLOT\\BROWSE."""
    b = U8(cmd, update) + U32(period) + name16(name) + U8(*osv) + U32(flags)
    if sig:
        b += U8(*proto) + U16(0xaa55)
    else:
        b += U32(0x12345678)       # the "comment pointer" some domain announcements carry
    return b + comment.encode() + b'\0'


def lanman_ann(cmd, name, osv=(5, 1), flags=0x00001003, update=1, period=720, comment='lm comment'):
    """The same announcements to \\MAILSLOT\\LANMAN: update count, flags, OS version, periodicity (s), name, comment."""
    return U8(cmd, update) + U32(flags) + U8(*osv) + U16(period) + name.encode() + b'\0' + comment.encode() + b'\0'


def election(version, desire, major, minor, osflags, uptime, name):
    return U8(8, version) + U8(desire, major, minor, osflags) + U32(uptime) + U32(0) + name.encode() + b'\0'


def dcerpc_bind(callid, uuid_str, ver):
    xfer = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    body = U16(4280, 4280) + U32(0) + U8(1, 0, 0, 0) + U16(0, 1) + uuid.UUID(uuid_str).bytes_le + U16(*ver) + xfer + U32(2)
    return U8(5, 0, 11, 3) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def dcerpc_bind_ack(callid):
    xfer = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    port = b'\\PIPE\\srvsvc\0'
    body = U16(4280, 4280) + U32(0x1234) + U16(len(port)) + port
    body += b'\0' * ((-len(body)) % 4) + U8(1, 0, 0, 0) + U16(0, 0) + xfer + U32(2)
    return U8(5, 0, 12, 3) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def dcerpc_req(callid, stub, opnum):
    return U8(5, 0, 0, 3) + U8(0x10, 0, 0, 0) + U16(24 + len(stub), 0) + U32(callid) + U32(len(stub)) + U16(0, opnum) + stub


def dcerpc_resp(callid, stub):
    return U8(5, 0, 2, 3) + U8(0x10, 0, 0, 0) + U16(24 + len(stub), 0) + U32(callid) + U32(len(stub)) + U16(0, 0) + stub


def ndr_str(s):
    u = (s + '\0').encode('utf-16le')
    return U32(len(s) + 1, 0, len(s) + 1) + u + b'\0' * ((-len(u)) % 4)


def srvsvc_server_info(c, fid):
    """srvsvc NetrServerGetInfo, level 101: the server type flags are decoded with NDR (a caller of
    dissect_smb_server_type_flags with the NDR representation)."""
    uid = 'ab324fc8-1670-01d3-1278-5a47bf6ee188'.replace('ab', '4b', 1)
    def tx(data, rdata):
        c.nextmid()
        c.send(True, trans_req(c, 0x25, U16(0x26, fid), b'', data, name=r'\PIPE\srvsvc'))
        c.send(False, trans_resp(c, 0x25, b'', b'', rdata))
    tx(dcerpc_bind(1, uid, (3, 0)), dcerpc_bind_ack(1))
    tx(dcerpc_req(2, U32(0x20000) + ndr_str(r'\\SERVER') + U32(101), 21),
       dcerpc_resp(2, U32(101) + U32(0x20004) + U32(500, 0x20008, 6, 1, 0x00008003, 0x2000c) + ndr_str('SERVER') + ndr_str('a comment') + U32(0)))
    # the server type of level 102 (also a server type with NDR)
    tx(dcerpc_req(3, U32(0x20000) + ndr_str(r'\\\\SERVER') + U32(102), 21),
       dcerpc_resp(3, U32(102) + U32(0x20004) + U32(500, 0x20008, 6, 1, 0xffffffff, 0x2000c, 10, 0xffffffff, 0, 240, 3000, 0, 0x20010) + ndr_str('SERVER') + ndr_str('a comment') + ndr_str('c:\\\\users') + U32(0)))


def mailslot(cap, h, name, data, ipid, src='HOST1', dst='WORKGROUP', dtype=0x1d, **kw):
    pdu = trans_req(h, 0x25, U16(1, 0, 2), b'', data, name=name, flags=2, **KW)
    nbds(cap, h, pdu, src=src, dst=dst, dtype=dtype, ipid=ipid, **kw)


def main(outdir):
    cap = Cap(os.path.join(outdir, 'smb-browse-coverage.pcap'))
    h = hdr_conn(cap)
    n = [0]

    def mb(name, data, **kw):
        n[0] += 1
        mailslot(cap, h, name, data, ipid=300 + n[0], **kw)

    # Host announcements: every Windows version string, a range of server types
    for i, osv in enumerate(OSVERS):
        mb(BROWSE, host_ann(1, 'HOST%d' % i, osv=osv, flags=0x1003 | (1 << i)))
    # every server type bit alone (names of each bit) and all of them at once
    for bit in range(32):
        mb(BROWSE, host_ann(1, 'BITS', flags=1 << bit, comment='bit %d' % bit))
    mb(BROWSE, host_ann(1, 'ALL', flags=ALL_TYPES))
    mb(BROWSE, host_ann(1, 'NONE', flags=0))
    # periodicity and a name that fills all 16 octets (no terminator), no comment
    mb(BROWSE, host_ann(1, 'ABCDEFGHIJKLMNOP', period=0xffffffff, comment=''))
    mb(BROWSE, host_ann(1, 'ABCDEFGHIJKLMNO', period=1000, comment='x' * 40))
    # local master announcement, domain announcements (with and without the signature)
    mb(BROWSE, host_ann(15, 'MASTER1', flags=0x00040a03))
    mb(BROWSE, host_ann(12, 'WORKGROUP', flags=0x80000000, comment='MASTER1'))
    mb(BROWSE, host_ann(12, 'OTHERDOM', flags=0x80000000, comment='MASTER2', sig=False))
    # request announcement: flags and the computer name
    mb(BROWSE, U8(2, 0) + b'REQUESTER\0')
    mb(BROWSE, U8(2, 0x80) + b'A\0')
    # browser election requests: version, desire bits (backup, standby, master, domain master, WINS, NT), OS bits
    for i, (desire, osf) in enumerate(((0x01, 0x01), (0x02, 0x10), (0x04, 0x20), (0x08, 0), (0x20, 0x31), (0x80, 0xff), (0xaf, 0x30), (0, 0))):
        mb(BROWSE, election(1, desire, 1, 15, osf, 100000 * (i + 1), 'ELECT%d' % i))
    # backup browser list request / response (0 to 3 names), become backup, master announcement
    mb(BROWSE, U8(9, 3) + U32(0x11223344))
    mb(BROWSE, U8(10, 0) + U32(0x11223344))
    mb(BROWSE, U8(10, 1) + U32(0x11223344) + b'BACKUP1\0')
    mb(BROWSE, U8(10, 3) + U32(0x11223344) + b'BACKUP1\0BACKUP2\0BACKUP3\0')
    mb(BROWSE, U8(11) + b'PROMOTE1\0')
    mb(BROWSE, U8(13) + b'MASTER1\0')
    # reset browser state: demote, flush, stop; combinations
    for flags in (0, 1, 2, 4, 7, 0x18):
        mb(BROWSE, U8(14, flags))
    # an unknown command (the data is not decoded)
    mb(BROWSE, U8(0x63, 1, 2, 3, 4))
    mb(BROWSE, U8(0))
    # \MAILSLOT\LANMAN announcements
    for i, osv in enumerate(OSVERS):
        mb(LANMAN, lanman_ann(1, 'LMHOST%d' % i, osv=osv, flags=0x1003 | (1 << i)))
    mb(LANMAN, lanman_ann(15, 'LMMASTER', period=65535))
    mb(LANMAN, lanman_ann(12, 'LMDOMAIN', comment='LMMASTER'))
    mb(LANMAN, lanman_ann(1, 'ALL', flags=ALL_TYPES, comment=''))
    # the other commands in LANMAN are not decoded
    mb(LANMAN, U8(2, 0) + b'REQ\0')
    mb(LANMAN, U8(0x30, 0, 0))
    # BROWSE messages over TCP 445 (request with a response)
    c = Conn(cap, 40011, 445)
    c.tid = 7
    for name, req, rsp in ((BROWSE, U8(9, 2) + U32(5), U8(10, 2) + U32(5) + b'BK1\0BK2\0'),
                           (BROWSE, host_ann(1, 'TCPHOST'), host_ann(15, 'TCPMASTER')),
                           (LANMAN, lanman_ann(1, 'LMTCP'), lanman_ann(1, 'LMTCP2'))):
        c.nextmid()
        c.send(True, trans_req(c, 0x25, U16(1, 0, 1), b'', req, name=name))
        c.send(False, trans_resp(c, 0x25, b'', b'', rsp))
    c3 = Conn(cap, 40031, 445)
    c3.tid = 5
    srvsvc_server_info(c3, 0x5000)
    cap.close()

    malformed(outdir)


def malformed(outdir):
    cap = Cap(os.path.join(outdir, 'smb-browse-coverage-malformed.pcap'))
    h = hdr_conn(cap)
    n = [0]

    def mb(name, data):
        n[0] += 1
        mailslot(cap, h, name, data, ipid=500 + n[0])

    good = host_ann(1, 'HOST', comment='comment')
    # cut inside each field of the announcement
    for cut in (1, 2, 5, 10, 22, 24, 27, 29, 31):
        mb(BROWSE, good[:cut])
    # domain announcement cut inside the signature / mysterious field
    dom = host_ann(12, 'DOM', comment='MASTER')
    for cut in (30, 31, 33, 34):
        mb(BROWSE, dom[:cut])
    # unterminated strings
    mb(BROWSE, good[:-1])
    mb(BROWSE, U8(2, 0) + b'REQUESTER')
    mb(BROWSE, U8(2))
    mb(BROWSE, U8(8, 1) + U8(1, 1, 15, 1) + U32(1) + U32(0) + b'ELECTNOTERM')
    el = election(1, 1, 1, 15, 1, 5, 'E')
    for cut in (1, 2, 4, 6, 10, 14):
        mb(BROWSE, el[:cut])
    # backup list: count larger than the names that follow, token cut
    mb(BROWSE, U8(10, 5) + U32(1) + b'ONE\0TWO\0')
    mb(BROWSE, U8(10, 2) + U16(1))
    mb(BROWSE, U8(9, 2) + b'\0')
    mb(BROWSE, U8(11))
    mb(BROWSE, U8(13))
    mb(BROWSE, U8(14))
    # LANMAN announcement cut inside each field
    lm = lanman_ann(1, 'LM', comment='c')
    for cut in (1, 2, 5, 7, 9, 11, 13):
        mb(LANMAN, lm[:cut])
    mb(LANMAN, lm[:-1])
    mb(LANMAN, lanman_ann(1, 'LM')[:-1].replace(b'LM\0', b'LM'))
    cap.close()


if __name__ == '__main__':
    main(sys.argv[1])
