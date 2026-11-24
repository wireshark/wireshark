#!/usr/bin/env python3
# Generates test/captures/saphdb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP HANA SQL Command Network Protocol (HDB) coverage captures.
# Usage: mksaphdb.py <outdir>
# TCP ports 30013 and 30015 are registered by default.  Nothing is captured
# from a network.  The authentication parts carry arbitrary bytes: no
# challenge/response or Kerberos token is built, and the TLS variant
# (saphdb_tls) is not covered.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from sapcov_lib import Cap, Flow

CLI, SRV = '192.0.2.1', '192.0.2.2'
n = [52000]


def flow(c, port=30015):
    n[0] += 1
    f = Flow(c, CLI, SRV, n[0], port)
    f.syn()
    return f


def opt(key, typ, val=b''):
    if typ in (29, 30, 33):
        return bytes([key, typ]) + struct.pack('<h', len(val)) + val
    return bytes([key, typ]) + val


def part(kind, argcount, buf=b'', attrs=0, bufsize=None, buflen=None):
    '''16 byte part header and the buffer padded to a multiple of 8.'''
    b = struct.pack('<BBhIii', kind, attrs, argcount, 0, len(buf) if buflen is None else buflen,
                    len(buf) if bufsize is None else bufsize)
    return b + buf + b'\0' * ((-len(buf)) % 8)


def segment(kind, parts, mtype=0, func=0, segno=1, seglen=None, nparts=None, ofs=0):
    '''24 byte segment header (request: message type; reply: function code).'''
    body = b''.join(parts)
    if kind == 1:
        tail = bytes([mtype, 1, 0]) + b'\0' * 8
    elif kind == 2:
        tail = b'\0' + struct.pack('<h', func) + b'\0' * 8
    else:
        tail = b'\0' * 11
    length = 24 + len(body) if seglen is None else seglen
    return struct.pack('<iihhb', length, ofs, len(parts) if nparts is None else nparts, segno, kind) + tail + body


def message(segments, session=0x1122334455667788, count=1, options=0, varpart=None, nsegm=None,
            comp_len=0, reserved=b'\0\0\0\0'):
    body = b''.join(segments)
    return (struct.pack('<QIIIhBB', session, count, len(body) if varpart is None else varpart,
                        0x20000, len(segments) if nsegm is None else nsegm, options, 0) +
            struct.pack('<I', comp_len) + reserved + body)


def auth(fields):
    b = struct.pack('<H', len(fields))
    for f in fields:
        if len(f) < 0xff:
            b += bytes([len(f)]) + f
        else:
            b += b'\xff' + struct.pack('>H', len(f)) + f
    return b


def build_main(out):
    c = Cap()
    f = flow(c)
    # --- initialization -------------------------------------------------------
    f.send(b'\xff\xff\xff\xff\x04\x01\x00\x00\x04\x01\x01\x00\x01\x01')              # 14 bytes
    f.send(b'\x04\x01\x00\x04\x01\x00\x00\x00'[:8], False)                           # 8 bytes
    # --- authentication: the field layouts only (arbitrary bytes) -----------
    f.send(message([segment(1, [part(33, 1, auth([b'SYSTEM', b'METHOD1', b'\x42' * 64]))], mtype=65)]))
    f.send(message([segment(1, [part(33, 1, auth([b'SYSTEM', b'METHOD1', b'\x42' * 300]))], mtype=65)]))
    f.send(message([segment(2, [part(33, 1, auth([b'METHOD1', b'\x24' * 40]))], func=14)]), False)
    # GSS: two fields (GSS, token) and three fields (user, GSS, token); the token is a count of
    # fields, the second field with a single byte is the commtype (here 1: not SPNEGO)
    gss_token = auth([b'GSSAPI', b'\x01', b'\x07' * 12])
    f.send(message([segment(1, [part(33, 1, auth([b'GSS', gss_token]))], mtype=65)]))
    f.send(message([segment(1, [part(33, 1, auth([b'user', b'GSS', gss_token]))], mtype=65)]))
    # GSS token with an extended (0xff) field length
    gss_big = auth([b'GSSAPI', b'\x01', b'\x07' * 300])
    f.send(message([segment(1, [part(33, 1, auth([b'GSS', gss_big]))], mtype=65)]))
    # --- connect options and the other option parts --------------------------
    copts = (opt(1, 3, struct.pack('<i', 100)) + opt(2, 28, b'\1') + opt(3, 29, b'en_US') +
             opt(56, 3, struct.pack('<i', 12)) + opt(44, 29, b'2.00.059') +
             opt(5, 28, b'\0') + opt(45, 29, b''))
    f.send(message([segment(1, [part(42, 7, copts)], mtype=66)]))
    f.send(message([segment(2, [part(42, 3, opt(1, 3, struct.pack('<i', 100)) + opt(2, 28, b'\1') +
                                   opt(12, 3, struct.pack('<i', 4)))], func=14)]), False)
    f.send(message([segment(1, [part(43, 1, opt(1, 28, b'\1'))], mtype=67),
                    segment(1, [part(44, 1, opt(1, 3, struct.pack('<i', 7)))], mtype=71, segno=2)]))
    f.send(message([segment(2, [part(64, 3, opt(0, 28, b'\0') + opt(1, 28, b'\1') + opt(2, 3, struct.pack('<i', 2)))],
                            func=11)]), False)
    f.send(message([segment(1, [part(27, 2, opt(1, 3, struct.pack('<i', 12)) + opt(2, 29, b'module.sql')),
                                part(29, 3, opt(1, 29, b'2.8') + opt(2, 29, b'JDBC') + opt(3, 29, b'app')),
                                part(34, 2, opt(1, 3, b'\1\0\0\0') + opt(2, 29, b'host1')),
                                part(39, 0, b''), part(67, 0, b''), part(68, 0, b'')], mtype=2)]))
    # topology information: multi-line option part, two rows
    row1 = opt(1, 29, b'hana1') + opt(2, 3, struct.pack('<i', 30015)) + opt(4, 7, struct.pack('<d', 0.5)) + opt(6, 28, b'\1')
    row2 = opt(1, 29, b'hana2') + opt(2, 3, struct.pack('<i', 30040))
    f.send(message([segment(2, [part(15, 2, struct.pack('<h', 4) + row1 + struct.pack('<h', 2) + row2 +
                                     struct.pack('<h', 0))], func=14)]), False)
    # --- statements and results ------------------------------------------------
    f.send(message([segment(1, [part(3, 1, b'SELECT * FROM DUMMY'), part(35, 1, b'client-id-1')], mtype=2)]))
    f.send(message([segment(1, [part(3, 1, b'CALL PROC(?)'), part(32, 1, b'\0' * 12)], mtype=13)]))
    f.send(message([segment(2, [part(5, 1, b'\1' * 24), part(48, 1, b'\2' * 24), part(12, 1, b'\0' * 8)],
                            func=5)]), False)
    for msgtype in (0, 3, 4, 5, 6, 7, 16, 17, 18, 25, 68, 69, 70, 72, 73, 74, 75, 77, 78, 79, 80, 81,
                    82, 83, 84, 85, 86, 87, 88, 89, 99):
        f.send(message([segment(1, [], mtype=msgtype)]))
    for func in (0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                 26, 27, 99):
        f.send(message([segment(2, [], func=func)]), False)
    # --- errors ----------------------------------------------------------------------
    for lvl, text in ((0, b'warning text'), (1, b'invalid table name: TAB1'), (2, b'')):
        err = struct.pack('<iii', 259 + lvl, 15, len(text)) + bytes([lvl]) + b'42S02' + text
        f.send(message([segment(5, [part(6, 1, err)])]), False)
    # a part kind without dissection, with and without arguments; unknown segment kind
    f.send(message([segment(3, [part(100, 1, b'\0' * 8)])]), False)
    f.send(message([segment(1, [part(0, 0, b'')], mtype=25)]))
    # --- one message with three segments -----------------------------------------
    f.send(message([segment(1, [part(3, 1, b'SELECT 1 FROM DUMMY')], mtype=2),
                    segment(1, [part(3, 1, b'SELECT 2 FROM DUMMY')], mtype=2, segno=2),
                    segment(1, [part(3, 1, b'SELECT 3 FROM DUMMY')], mtype=2, segno=3)]))
    # a message split over three TCP segments
    f.split(message([segment(1, [part(3, 1, b'SELECT ' + b'A' * 200 + b' FROM DUMMY')], mtype=2)]), 3)
    # --- compressed packet (review reproducer: the compressed buffer item ran past
    #     the end; fixed: its length is the variable part minus the segment header)
    seg = segment(1, [], mtype=2)
    f.send(message([seg + b'\x99' * 40], options=2, comp_len=300))
    f.send(message([seg + b'\x99' * 40], options=2, comp_len=300, nsegm=2))
    # --- server on the second port, a tenant database
    g = flow(c, 30013)
    g.send(message([segment(1, [part(3, 1, b'SELECT 1 FROM DUMMY')], mtype=2)]))
    c.write(os.path.join(out, 'saphdb-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    f = flow(c)
    f.send(message([segment(1, [part(3, 1, b'x')], mtype=2)], nsegm=0))            # no segments
    f.send(message([segment(1, [part(3, 1, b'x')], mtype=2, segno=7)]))            # wrong segment number
    f.send(message([segment(1, [part(3, 1, b'x')], mtype=2, segno=-1)]))
    f.send(message([segment(1, [part(3, 1, b'x')], mtype=2, nparts=-3)]))          # negative part count
    f.send(message([segment(1, [part(3, 1, b'x')], mtype=2, seglen=5)]))           # segment length < 13
    f.send(message([segment(1, [part(3, 1, b'x')], mtype=2, seglen=4000)]))        # beyond the packet
    f.send(message([segment(1, [part(3, 1, b'xyz', buflen=-5)], mtype=2)]))        # negative part length
    f.send(message([segment(1, [part(3, 1, b'xyz', buflen=4000)], mtype=2)]))      # part length beyond data
    f.send(message([segment(1, [part(33, 1, b'\x05')], mtype=65)]))                # auth count truncated
    f.send(message([segment(1, [part(33, 1, struct.pack('<H', 2) + bytes([3]) + b'GSS')], mtype=65)]))   # no 2nd length
    f.send(message([segment(1, [part(33, 1, struct.pack('<H', 1) + b'\xff\x00')], mtype=65)]))           # ext length cut
    f.send(message([segment(1, [part(33, 1, struct.pack('<H', 1) + bytes([200]) + b'short')], mtype=65)]))  # field too long
    # GSS token variants: nested count cut, nested field length cut, nested extended cut
    for tok in (b'\x05', struct.pack('<H', 2) + b'\x03GSS', struct.pack('<H', 1) + b'\xff\x00',
                struct.pack('<H', 1) + bytes([99]) + b'abc', struct.pack('<H', 1) + b'\xff\x00\x10' + b'ab', b''):
        f.send(message([segment(1, [part(33, 1, auth([b'GSS', tok]))], mtype=65)]))
        f.send(message([segment(1, [part(33, 1, auth([b'user', b'GSS', tok]))], mtype=65)]))
    # a commtype that makes SAP HDB hand the third field to the GSS-API dissector (arbitrary bytes:
    # the GSS-API dissector complains about the token)
    gss_token3 = auth([b'GSSAPI', b'\x03', b'\x07' * 12])
    f.send(message([segment(1, [part(33, 1, auth([b'user', b'GSS', gss_token3]))], mtype=65)]))
    # option parts with no option table (the keys are unknown), and every value type
    f.send(message([segment(1, [part(39, 1, opt(1, 3, b'\1\0\0\0')), part(67, 1, opt(1, 3, b'\1\0\0\0')),
                                part(68, 1, opt(1, 3, b'\1\0\0\0'))], mtype=13)]))
    f.send(message([segment(1, [part(42, 8, opt(7, 1, b'\x05') + opt(8, 2, struct.pack('<h', 3200)) +
                                   opt(9, 4, struct.pack('<q', 2 ** 40)) + opt(56, 7, struct.pack('<d', 1.5)) +
                                   opt(99, 30, b'nstr') + opt(6, 33, b'\x01\x02\x03') + opt(45, 29, b'') +
                                   opt(12, 29, b'x'))], mtype=66)]))
    # options: wrong type for the key, unknown type, truncated values
    f.send(message([segment(1, [part(42, 3, opt(1, 29, b'abc') + opt(2, 77) + opt(3, 29, b'x'))], mtype=66)]))
    f.send(message([segment(1, [part(42, 2, opt(3, 29, b'toolongvalue')[:6])], mtype=66)]))
    f.send(message([segment(1, [part(42, 2, bytes([1, 29]) + struct.pack('<h', -4))], mtype=66)]))
    # error part with the text beyond the data
    f.send(message([segment(5, [part(6, 1, struct.pack('<iii', 1, 1, 9999) + b'\1' + b'42S02' + b'ab')])]), False)
    # compressed with a first segment header only; compressed with nothing after it
    f.send(message([segment(1, [], mtype=2)], options=2))
    f.send(message([b''], options=2, nsegm=1))
    # initialization-sized packets that are not initialization messages
    f.send(b'\0' * 10)
    g = flow(c)
    g.send(message([segment(1, [part(3, 1, b'x')], mtype=2)], varpart=0xff)[:40])  # varpartlength too large
    g = flow(c)
    g.send(message([segment(1, [part(3, 1, b'x')], mtype=2)], varpart=10))         # shorter than the data
    c.write(os.path.join(out, 'saphdb-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)
