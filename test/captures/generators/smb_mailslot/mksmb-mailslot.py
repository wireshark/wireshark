#!/usr/bin/env python3
# Generates test/captures/smb_mailslot_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic coverage capture for packet-smb-mailslot.c.
# Usage: mksmb-mailslot.py <outdir>   (writes smb-mailslot-coverage.pcap and
# smb-mailslot-coverage-malformed.pcap).  Everything is built with struct;
# the addresses are documentation addresses, nothing comes from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from smblib import (
    Cap, Conn, hdr_conn, interim, nbds, trans_req, trans_resp, trans_sec, U16, U32, U8,
)

NAMES = ['HOST1', 'WORKGROUP']


def bhost(cmd=1, name='HOST1', comment='a host'):
    """BROWSE host announcement (command 1) / local master / domain."""
    return (U8(cmd, 1) + U32(30000) + name.encode().ljust(16, b'\0') + U8(5, 1) + U32(0x00001003) +
            U8(15, 1) + U16(0xaa55) + comment.encode() + b'\0')


def lanman_host(name='HOST2'):
    return U8(1, 2) + U32(0x00000003) + U8(5, 0) + U16(120) + name.encode() + b'\0' + b'comment\0'


def netlogon_query(name='HOST1', mslot=r'\MAILSLOT\NET\GETDC01'):
    return U8(7, 0) + name.encode() + b'\0' + mslot.encode() + b'\0' + U16(0xffff)


def mailslot_write(c, name, data, opcode=1, prio=0, cls=2, **kw):
    return trans_req(c, 0x25, U16(opcode, prio, cls), b'', data, name=name, flags=2, **kw)


def main(outdir):
    cap = Cap(os.path.join(outdir, 'smb-mailslot-coverage.pcap'))
    h = hdr_conn(cap)
    ipid = [100]

    def dg(pdu, **kw):
        ipid[0] += 1
        nbds(cap, h, pdu, ipid=ipid[0], **kw)

    # --- NetBIOS datagrams (UDP 138) carrying a mailslot write -----------
    # one per mailslot name the dissector knows
    for name, data in ((r'\MAILSLOT\BROWSE', bhost()),
                       (r'\MAILSLOT\BROWSE', bhost(12, 'WORKGROUP')),
                       (r'\MAILSLOT\LANMAN', lanman_host()),
                       (r'\MAILSLOT\NET\NETLOGON', netlogon_query()),
                       (r'\MAILSLOT\TEMP\NETLOGON', netlogon_query()),
                       (r'\MAILSLOT\MSSP', netlogon_query()),
                       (r'\MAILSLOT\NET\GETDC01', b'\x0b\0HOST1\0'),
                       # unknown mailslot: the payload is shown as data
                       (r'\MAILSLOT\OTHER', b'hello mailslot'),
                       (r'\MAILSLOT\BROWSEX\SUFFIX', bhost(2, 'HOST1')),
                       ):
        h.mid = 0
        dg(mailslot_write(h, name, data, mid=0, pid=0, uid=0, tid=0))
    # unknown opcode, priority and class values; reliable class
    dg(mailslot_write(h, r'\MAILSLOT\BROWSE', bhost(), opcode=2, prio=9, cls=1, mid=0, pid=0, uid=0, tid=0))
    dg(mailslot_write(h, r'\MAILSLOT\BROWSE', bhost(), opcode=1, prio=5, cls=7, mid=0, pid=0, uid=0, tid=0))
    # direct unicast datagram and a group datagram message type
    dg(mailslot_write(h, r'\MAILSLOT\BROWSE', bhost(), mid=0, pid=0, uid=0, tid=0), msgtype=0x10, dst='HOST2', dtype=0)
    dg(mailslot_write(h, r'\MAILSLOT\BROWSE', bhost(), mid=0, pid=0, uid=0, tid=0), msgtype=0x12, dst='WORKGROUP', dtype=0x1e)
    # a mailslot write without data
    dg(mailslot_write(h, r'\MAILSLOT\BROWSE', b'', mid=0, pid=0, uid=0, tid=0))

    # --- over TCP 445: transaction with a response -------------------
    c = Conn(cap, 40001, 445)
    c.tid = 7
    # a request that wants a response (flags 0), the response carries data
    for name, req, rsp in ((r'\MAILSLOT\BROWSE', bhost(), bhost(15, 'HOST3')),
                           (r'\MAILSLOT\LANMAN', lanman_host(), lanman_host('HOST4')),
                           (r'\MAILSLOT\NET\NETLOGON', netlogon_query(), U8(6, 0) + b'\\\\SRV\0' + U16(0xffff)),
                           (r'\MAILSLOT\TEMP\NETLOGON', netlogon_query(), U8(6, 0) + b'\\\\SRV\0' + U16(0xffff)),
                           (r'\MAILSLOT\MSSP', netlogon_query(), U8(6, 0) + b'\\\\SRV\0' + U16(0xffff)),
                           (r'\MAILSLOT\OTHER', b'ping', b'pong')):
        c.nextmid()
        c.send(True, trans_req(c, 0x25, U16(1, 0, 1), b'', req, name=name))
        c.send(False, trans_resp(c, 0x25, b'', b'', rsp))
    # a request with no data and its (empty) interim style response
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(1, 0, 1), b'', b'', name=r'\MAILSLOT\BROWSE'))
    c.send(False, trans_resp(c, 0x25, b'', b'', b''))
    # a response without its request: the mailslot dissector declines
    c.send(False, trans_resp(c, 0x25, b'', b'', bhost(), mid=0x7001))
    # a one way mailslot write (no response flag) on a TCP connection
    c.nextmid()
    c.send(True, mailslot_write(c, r'\MAILSLOT\BROWSE', bhost(2, 'HOST5')))
    # multi-part mailslot write: the first part holds a complete message
    # (total data count larger than its data count), the secondary
    # request carries only the padding that makes up the total
    c.nextmid()
    full = bhost(1, 'HOST6', 'x' * 20)
    pad = bytes(10)
    c.send(True, trans_req(c, 0x25, U16(1, 0, 2), b'', full, name=r'\MAILSLOT\BROWSE', tdc=len(full) + len(pad)))
    c.send(False, interim(c, 0x25))
    c.send(True, trans_sec(c, 0x26, 0, len(full) + len(pad), b'', 0, pad, len(full)))
    c.send(False, trans_resp(c, 0x25, b'', b'', b''))
    # multi-part response: the second part has no setup words either
    c.nextmid()
    rsp = bhost(15, 'HOST7', 'y' * 20)
    c.send(True, trans_req(c, 0x25, U16(1, 0, 1), b'', bhost(), name=r'\MAILSLOT\BROWSE'))
    c.send(False, trans_resp(c, 0x25, b'', b'', rsp, tdc=len(rsp) + len(pad)))
    c.send(False, trans_resp(c, 0x25, b'', b'', pad, tdc=len(rsp) + len(pad), dd=len(rsp)))
    cap.close()
    malformed(outdir)


def malformed(outdir):
    cap = Cap(os.path.join(outdir, 'smb-mailslot-coverage-malformed.pcap'))
    h = hdr_conn(cap)
    n = [200]
    kw = dict(mid=0, pid=0, uid=0, tid=0)

    def dg(pdu):
        n[0] += 1
        nbds(cap, h, pdu, ipid=n[0])

    # only one setup word: priority and class run off the setup area
    dg(trans_req(h, 0x25, U16(1), b'', bhost(), name=r'\MAILSLOT\BROWSE', flags=2, **kw))
    # two setup words
    dg(trans_req(h, 0x25, U16(1, 0), b'', bhost(), name=r'\MAILSLOT\BROWSE', flags=2, **kw))
    # a browse message cut after the command
    dg(mailslot_write(h, r'\MAILSLOT\BROWSE', U8(1), **kw))
    # a net logon message cut after the command
    dg(mailslot_write(h, r'\MAILSLOT\NET\NETLOGON', U8(7), **kw))
    # the mailslot name has no terminator in the byte count
    pdu = bytearray(trans_req(h, 0x25, U16(1, 0, 2), b'', b'', name=r'\MAILSLOT\X', flags=2, **kw))
    dg(bytes(pdu[:-1]))
    cap.close()


if __name__ == '__main__':
    main(sys.argv[1])
