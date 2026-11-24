#!/usr/bin/env python3
# Generates test/captures/smb_logon_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic coverage captures for packet-smb-logon.c (the
# NETLOGON mailslot protocol: \MAILSLOT\NET\NETLOGON, \MAILSLOT\TEMP\NETLOGON,
# \MAILSLOT\MSSP and the response mailslots).
# Usage: mksmb-logon.py <outdir>   (writes smb-logon-coverage.pcap and
# smb-logon-coverage-malformed.pcap).  Everything is built with struct; the
# addresses are documentation addresses, nothing comes from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import uuid
from smblib import Cap, Conn, hdr_conn, nbds, trans_req, trans_resp, U16, U32, U64, U8

NETLOGON = r'\MAILSLOT\NET\NETLOGON'
TEMPLOGON = r'\MAILSLOT\TEMP\NETLOGON'
MSSP = r'\MAILSLOT\MSSP'
KW = dict(mid=0, pid=0, uid=0, tid=0)
LM20 = U16(0xffff)          # LM20 token
LMNT = U16(0xffff)          # NT token


def z(s):
    return s.encode() + b'\0'


def uz(s):
    return s.encode('utf-16le') + b'\0\0'


def align(b, n, base=0):
    return b + b'\0' * ((-(len(b) + base)) % n)


def lm_token(v=0x0001):
    return U16(v)


def sid(auth=5, subs=(21, 1004, 1005, 1006)):
    return bytes([1, len(subs)]) + auth.to_bytes(6, 'big') + b''.join(U32(s) for s in subs)


def cmd(c, *parts):
    return U8(c, 0) + b''.join(parts)


def dnsname(*labels):
    return b''.join(bytes([len(l)]) + l.encode() for l in labels) + b'\0'


def ads_response(c, guid=uuid.UUID('00112233-4455-6677-8899-aabbccddeeff'), ntver=0x00000015):
    """Commands 0x17 / 0x19: unknown32, domain GUID, eight DNS style names, flags, IP address, NT version, tokens."""
    b = cmd(c)                                    # command, skipped byte
    b = align(b, 4)
    b += U32(0x0000f3fd) + guid.bytes_le           # unknown32 (server type flags), domain GUID
    start = len(b)                                # names are decoded from the start of the buffer
    forest = dnsname('example', 'com')
    off_forest = len(b)
    b += forest                                   # forest DNS name
    b += bytes([0xc0, off_forest])               # domain DNS name = pointer to the forest name
    b += bytes([3]) + b'dc1' + bytes([0xc0, off_forest])   # server DNS name: label + pointer
    b += bytes([7]) + b'EXAMPLE' + b'\0'         # domain name
    b += bytes([3]) + b'DC1' + b'\0'             # server name
    b += bytes([5]) + b'alice' + b'\0'           # user name
    b += bytes([7]) + b'Default' + bytes([0xc0, off_forest])  # server site
    b += bytes([0xc0, off_forest])               # client site
    b += U8(0) + U32(0x00000000) + bytes([198, 51, 100, 7]) + U32(0) + U32(0) + U32(ntver) + LMNT + LM20
    return b


def mailslot(cap, h, name, data, ipid, **kw):
    pdu = trans_req(h, 0x25, U16(1, 0, 2), b'', data, name=name, flags=2, **KW)
    nbds(cap, h, pdu, ipid=ipid, **kw)


def messages():
    """(mailslot name, data) for every command and variant."""
    m = []
    ntv = U32(0x00000005)
    # 0x00 logon request, 0x01 LM1.0 response
    m.append((NETLOGON, cmd(0, z('WKS1'), z('alice'), z(r'\MAILSLOT\TEMP\NETLOGON1'), U8(1), U16(0x0001), lm_token(0x0001))))
    m.append((NETLOGON, cmd(0, z('WKS1'), z('alice'), z(r'\MAILSLOT\TEMP\NETLOGON1'), U8(1), U16(0x0001), lm_token(0x0002))))
    m.append((NETLOGON, cmd(1, z('alice'), z('logon.cmd'))))
    # 0x02..0x05 queries and responses; 0x06 LM2.0 response
    for c in (2, 3, 4, 5):
        m.append((NETLOGON, cmd(c, z('WKS1'), z(r'\MAILSLOT\NET\GETDC001'), U16(0x0001), lm_token())))
    m.append((NETLOGON, cmd(6, z(r'\\SRV'), lm_token())))
    m.append((NETLOGON, cmd(6, z(r'\\SRV'), lm_token(0x0002))))
    # 0x07 query for the PDC: NT style (unicode name, NT version, LMNT token, LM token)
    # and Windows 95 style (only the LM token follows the mailslot name)
    nt = cmd(7, z('WKS1'), z(r'\MAILSLOT\NET\GETDC001'))
    nt = align(nt, 2) + uz('WKS1') + ntv + LMNT + lm_token()
    m.append((NETLOGON, nt))
    m.append((NETLOGON, cmd(7, z('WIN95'), z(r'\MAILSLOT\NET\GETDC002'), lm_token())))
    nt = cmd(7, z('WKS2'), z(r'\MAILSLOT\NET\GETDC03'))                 # odd length: realigned
    nt = align(nt, 2) + uz('WKS2') + ntv + U16(0x1234) + lm_token()   # LMNT token not 0xffff
    m.append((NETLOGON, nt))
    # 0x08 PDC startup (long and short), 0x0c response from PDC
    for c in (8, 0x0c):
        long_ = align(cmd(c, z('PDC1')), 2) + uz('PDC1') + uz('DOMAIN') + ntv + LMNT + lm_token()
        m.append((NETLOGON, long_))
        m.append((NETLOGON, cmd(c, z('PDC1'))))
        odd = align(cmd(c, z('PDC')), 2) + uz('PDC') + align(uz('DOMAIN'), 2) + ntv + LMNT + lm_token()
        m.append((NETLOGON, odd))
        m.append((NETLOGON, align(cmd(c, z('PDCNAME')), 2) + uz('PDCNAME') + align(b'', 2) + uz('') + ntv + LMNT + lm_token()))
    # 0x09 failed PDC, 0x0f response during logon pause, 0x10 unknown user
    for c in (9, 0x0f, 0x10):
        m.append((NETLOGON, cmd(c, ntv, lm_token())))
    # 0x0a announce change to UAS/SAM: old format and long format (database changes, SID)
    base = cmd(0x0a, U32(1), U32(1700000000), U32(5), U32(0x1234), z('PDC1'), z('DOMAIN'))
    m.append((NETLOGON, align(base, 2) + lm_token()))
    dbs = U32(3) + b''.join(U32(i) + U64(1000 + i) + U64(0x01d0000000000000) for i in range(3))
    longf = align(base, 2) + uz('PDC1') + uz('DOMAIN') + dbs + U32(len(sid()))
    longf = align(longf, 4) + sid() + ntv + LMNT + lm_token()
    m.append((NETLOGON, longf))
    longf = align(base, 2) + uz('PDC1') + uz('DOMAIN') + U32(0) + U32(0) + ntv + LMNT + lm_token()    # no databases, no SID
    m.append((NETLOGON, longf))
    # 0x0b no user on machine
    m.append((NETLOGON, cmd(0x0b, z('WKS1'))))
    # 0x0d relogon response, 0x0e interrogate response
    m.append((NETLOGON, cmd(0x0d) + U8(4, 0, 1) + ntv + lm_token()))
    m.append((NETLOGON, cmd(0x0e) + U8(4, 0, 1) + ntv + LMNT))
    # 0x11 LM2.1 account updates
    m.append((NETLOGON, cmd(0x11) + U64(0x1122334455667788) + U32(1700000000) + z('PDC1') + z('alice') + U16(2) + ntv + lm_token()))
    # 0x12 SAM logon request: with and without a domain SID, account control bits
    for ctrl in (0x0080, 0x0002 | 0x0100 | 0x1000, 0x0020 | 0x0200 | 0x0800 | 0x0400, 0x8000 | 0x0010 | 0x0040, 0):
        r = cmd(0x12) + U16(1)
        r = r[:2] + U16(1)
        r = align(r, 2) + uz('WKS1') + uz('alice') + z(r'\MAILSLOT\NET\GETDC003')
        r += U32(ctrl) + U32(0) + ntv + LMNT + lm_token()
        m.append((NETLOGON, r))
    r = cmd(0x12) + U16(2) + uz('WKS1') + uz('') + z(r'\MAILSLOT\NET\GETDC003') + U32(0x80)
    r += U32(len(sid()))
    r = align(r, 4) + sid() + ntv + LMNT + lm_token()
    m.append((NETLOGON, r))
    # 0x13 SAM logon response, 0x15 user unknown; 0x14, 0x16 and 0x18 are not decoded
    for c in (0x13, 0x15):
        m.append((NETLOGON, align(cmd(c), 2) + uz(r'\\SRV') + uz('alice') + uz('DOMAIN') + ntv + LMNT + lm_token()))
    for c in (0x14, 0x16, 0x18):
        m.append((NETLOGON, cmd(c, b'undecoded data')))
    # 0x17 and 0x19 (Active Directory responses); unknown commands
    m.append((NETLOGON, ads_response(0x17)))
    m.append((NETLOGON, ads_response(0x19)))
    m.append((NETLOGON, cmd(0x1a, b'unknown command')))
    m.append((NETLOGON, cmd(0xff, b'unknown command')))
    # the same messages to the other mailslots
    m.append((TEMPLOGON, cmd(0x12, U16(1), uz('WKS1'), uz('alice'), z(r'\MAILSLOT\NET\GETDC003'), U32(0x80), U32(0), ntv, LMNT, lm_token())))
    m.append((TEMPLOGON, ads_response(0x19)))
    m.append((MSSP, cmd(7, z('WKS1'), z(r'\MAILSLOT\NET\GETDC001'), lm_token())))
    m.append((MSSP, cmd(0x0b, z('WKS1'))))
    return m


def main(outdir):
    cap = Cap(os.path.join(outdir, 'smb-logon-coverage.pcap'))
    h = hdr_conn(cap)
    for i, (name, data) in enumerate(messages()):
        mailslot(cap, h, name, data, ipid=300 + i, src='WKS1', dst='DOMAIN', dtype=0x1c)
    # over TCP 445: a request with a response
    c = Conn(cap, 40021, 445)
    c.tid = 7
    for name, req, rsp in ((NETLOGON, cmd(7, z('WKS1'), z(r'\MAILSLOT\NET\GETDC001'), lm_token()), ads_response(0x19)),
                           (TEMPLOGON, cmd(0x12, U16(1), uz('WKS1'), uz('alice'), z(r'\MAILSLOT\NET\GETDC003'), U32(0x80), U32(0), U32(5), LMNT, lm_token()),
                            align(cmd(0x13), 2) + uz(r'\\SRV') + uz('alice') + uz('DOMAIN') + U32(5) + LMNT + lm_token())):
        c.nextmid()
        c.send(True, trans_req(c, 0x25, U16(1, 0, 1), b'', req, name=name))
        c.send(False, trans_resp(c, 0x25, b'', b'', rsp))
    cap.close()
    malformed(outdir)


def malformed(outdir):
    cap = Cap(os.path.join(outdir, 'smb-logon-coverage-malformed.pcap'))
    h = hdr_conn(cap)
    n = [0]
    # every message of the main capture cut at several points, and without terminators
    for name, data in messages():
        for cut in (1, 2, 3, len(data) // 2, len(data) - 1):
            if 0 < cut < len(data):
                n[0] += 1
                mailslot(cap, h, name, data[:cut], ipid=600 + n[0])
    # an ADS response whose name pointer leads outside the message and loops
    bad = ads_response(0x19)
    bad = bad[:24] + bytes([0xc0, 0xff]) + bad[26:]
    n[0] += 1
    mailslot(cap, h, NETLOGON, bad, ipid=600 + n[0])
    cap.close()


if __name__ == '__main__':
    main(sys.argv[1])
