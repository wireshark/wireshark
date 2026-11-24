#!/usr/bin/env python3
# Generates test/captures/smb_common_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-smb-common.c: display_ms_string(),
# display_unicode_string() and dissect_ms_compressed_string() are called
# by the SMB NETLOGON dissector (packet-smb-logon.c), which is reached
# through an SMB mailslot write to \MAILSLOT\NET\NETLOGON (over TCP 445 and
# in a NetBIOS datagram on UDP 138).
# Usage: mksmb_common.py <outdir> -> smb_common_coverage.pcap and
# smb_common_coverage-malformed.pcap.  struct only, documentation addresses,
# nothing from a network, no keys or passwords.
import os
import struct
import sys
from mksmb import (  # noqa: Cap, Conn, conn_setup, trans_req, nb_name, eth_frame, csum, ...
    Cap, Conn, conn_setup, csum, eth_frame, IP_C, IP_S, MAC_C, MAC_S, nb_name, trans_req, U16,
    U32, U8,
)

MS = r'\MAILSLOT\NET\NETLOGON'


def uni(s, nul=True):
    return s.encode('utf-16le') + (b'\0\0' if nul else b'')


def dns(*labels):
    return b''.join(bytes([len(l)]) + l.encode() for l in labels) + b'\0'


def logon_msgs():
    """(description, payload) for the NETLOGON opcodes that use the helpers."""
    tok = U16(0xffff)            # LMNT token
    lm = U16(0xffff)             # LM token
    out = []
    # 0x00 LM1.0/LM2.0 logon request: three ASCII strings, count, NT version, LM token
    out.append(('logon request', U8(0, 0) + b'CLIENT1\0' + b'alice\0' + b'\\MAILSLOT\\TEMP\\LOGON\0' + U8(1) + U16(0) + lm))
    # 0x02..0x05: computer, mailslot, NT version, LM token
    for op in (2, 3, 4, 5):
        out.append(('query %d' % op, U8(op, 0) + b'CLIENT1\0' + b'\\MAILSLOT\\TEMP\\Q\0' + U16(0) + lm))
    # 0x01 LM1.0 response: user and script names
    out.append(('lm10 resp', U8(1, 0) + b'alice\0' + b'logon.bat\0' + U16(0x0001) + lm))
    # 0x07 query for PDC, Windows 95 style (only the LM token after the mailslot) and NT style
    out.append(('pdc query w95', U8(7, 0) + b'CLIENT1\0' + b'\\MAILSLOT\\NET\\GETDC1\0' + lm))
    # (the mailslot name ends at an odd offset: NT style aligns to a word)
    out.append(('pdc query nt', U8(7, 0) + b'CLIENT1\0' + b'\\MAILSLOT\\NET\\GETDC1\0' + b'\0' + uni('CLIENT1') + U32(1) + tok + lm))
    out.append(('pdc query nt even', U8(7, 0) + b'CLIENT\0' + b'\\MAILSLOT\\NET\\GETDC\0' + uni('CLIENT') + U32(1) + tok + lm))
    # 0x08, 0x0c: PDC startup / response: unicode names
    for op in (8, 0x0c):
        out.append(('pdc startup %02x' % op, U8(op, 0) + b'PDC1\0' + b'\0' + uni('PDC1') + uni('DOMAIN') + U32(1) + tok + lm))
        out.append(('pdc startup short %02x' % op, U8(op, 0) + b'PDC1\0'))
        out.append(('pdc startup even %02x' % op, U8(op, 0) + b'PDC12\0' + uni('PDC12') + uni('DOM') + U32(1) + tok + lm))
    # 0x13 and 0x15: SAM logon response (three unicode strings)
    for op in (0x13, 0x15):
        out.append(('sam resp %02x' % op, U8(op, 0) + uni('\\\\DC1') + uni('alice') + uni('DOMAIN') + U32(1) + tok + lm))
    # 0x12 SAM logon request
    out.append(('sam logon req', U8(0x12, 0) + U16(0) + uni('CLIENT1') + uni('alice') + b'\\MAILSLOT\\NET\\GETDC2\0' + U32(0) + U32(0) + U32(1) + tok + lm))
    # 0x17 and 0x19: Active Directory responses with compressed (DNS) names
    for op in (0x17, 0x19):
        p = U8(op, 0) + U16(0)                # offset 4 after alignment
        p += U32(0x1d)                        # unknown
        p += bytes(range(16))                 # domain GUID
        forest = len(p)                       # names start here; pointers refer to the tvb start
        p += dns('example', 'com')            # forest
        p += dns('ad')[:-1] + bytes([0xc0, forest])      # domain dns: "ad" + pointer to the forest
        p += dns('dc1', 'ad')[:-1] + bytes([0xc0, forest])   # server dns
        p += dns('EXAMPLE')                   # domain name
        p += dns('DC1')                       # server name
        p += dns('alice')                     # user name
        p += dns('Default-First-Site-Name')   # server site
        p += dns('Site2')                     # client site
        p += U8(0) + U32(0) + bytes([198, 51, 100, 2]) + U32(0) + U32(0) + U32(0xffffffff) + tok + lm
        out.append(('ad resp %02x' % op, p))
    # unknown commands and the commands with plain data
    for op in (0x14, 0x16, 0x18, 0x1a, 0x30):
        out.append(('other %02x' % op, U8(op, 0) + b'data'))
    return out


def mailslot(c, data, **kw):
    return trans_req(c, 0x25, U16(1, 0, 2), b'', data, name=MS, flags=2, **kw)


def sc_main(outdir):
    cap = Cap(os.path.join(outdir, 'smb_common_coverage.pcap'))
    c = Conn(cap, 42001)
    conn_setup(c, r'\\SRV\SHARE')
    for desc, data in logon_msgs():
        c.nextmid()
        c.send(True, mailslot(c, data))
    # NetBIOS datagram (UDP 138), as a broadcast would carry it
    pick = ('logon request', 'pdc query nt', 'pdc startup 08', 'sam resp 13', 'ad resp 17', 'ad resp 19')
    for i, (desc, data) in enumerate([m for m in logon_msgs() if m[0] in pick]):
        ms = mailslot(c, data, mid=0, pid=0, uid=0, tid=0)
        nbds = struct.pack('!BBH', 0x11, 0x02, 0x1234 + i) + IP_C + struct.pack('!HHH', 138, 68 + len(ms), 0) + \
            nb_name('CLIENT1', 0) + nb_name('EXAMPLE', 0x1c) + ms
        udp = struct.pack('!HHHH', 138, 138, 8 + len(nbds), 0) + nbds
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 50 + i, 0x4000, 64, 17, 0, IP_C, IP_S)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth_frame(cap, MAC_S, MAC_C, 0x0800, ip + udp)
    cap.close()


def sc_malformed(outdir):
    cap = Cap(os.path.join(outdir, 'smb_common_coverage-malformed.pcap'))
    c = Conn(cap, 42002)
    conn_setup(c, r'\\SRV\SHARE')
    tok = U16(0xffff)
    bad = [
        U8(0, 0) + b'CLIENT1',                         # string without a terminator
        U8(0, 0) + b'CLIENT1\0' + b'alice',
        U8(0x13, 0) + 'srv'.encode('utf-16le'),        # unicode string without a terminator
        U8(0x13, 0) + uni('srv') + b'x',               # odd length
        U8(7, 0) + b'C\0' + b'\\M\0' + b'\0' + 'ab'.encode('utf-16le'),
        # compressed names: pointer loop, too long, pointer beyond the tvb, label beyond the end
        U8(0x17, 0) + U16(0) + U32(0) + bytes(16) + bytes([0xc0, 24]),
        U8(0x17, 0) + U16(0) + U32(0) + bytes(16) + (bytes([63]) + b'a' * 63) * 6 + b'\0',
        U8(0x17, 0) + U16(0) + U32(0) + bytes(16) + bytes([0xc0, 0xff]) + b'\0' * 30,
        U8(0x17, 0) + U16(0) + U32(0) + bytes(16) + bytes([10]) + b'abc',
        U8(0x19, 0) + U16(0) + U32(0) + bytes(16),
    ]
    for data in bad:
        c.nextmid()
        c.send(True, mailslot(c, data))
    cap.close()


if __name__ == '__main__':
    sc_main(sys.argv[1])
    sc_malformed(sys.argv[1])
