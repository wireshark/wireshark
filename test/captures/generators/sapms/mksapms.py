#!/usr/bin/env python3
# Generates test/captures/sapms_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP Message Server coverage captures.  Usage: mksapms.py <outdir>
# SAP MS is registered in sapni.port (3600, 3900), so it is reached through
# SAP NI: the client source port is 40000 (a SAP NI port) and the capture has
# no SYN, so TCP tries both ports.  Nothing is captured from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from sapcov_lib import Cap, Flow, ni

CLI, SRV = '192.0.2.1', '192.0.2.2'
EYE = b'**MESSAGE**\0'
IP4 = bytes([192, 0, 2, 7])
IP6 = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [7])


def s(x, n_):
    if isinstance(x, str):
        x = x.encode()
    return x.ljust(n_, b'\0')[:n_]


def ms(flag, iflag, opcode=None, err=0, ver=4, cs=0, body=b'', to='MSG_SERVER', frm='CLIENT_1',
       errno_=0, version=3, msgtypes=0xff, domain=0, port=3200, key=b'\1' * 8):
    h = (EYE + bytes([version, errno_]) + s(to, 40) + bytes([msgtypes, 0, domain, 0]) + key +
         bytes([flag, iflag]) + s(frm, 40) + struct.pack('!H', port))
    assert len(h) == 110
    if opcode is not None:
        h += bytes([opcode, err, ver, cs]) + body
    else:
        h += body
    return h


def client(ver, name='SRV1', host='host1', svc='sapdp00', types=0x81, servno=3200, status=1, nitrc=2,
           sys_service=0x10):
    b = s(name, 20 if ver == 1 else 40)
    b += s(host, 20 if ver == 1 else 32 if ver == 2 else 64)
    b += s(svc, 20) + bytes([types])
    if ver >= 3:
        b += IP6
    b += IP4 + struct.pack('!H', servno)
    if ver >= 2:
        b += bytes([status, nitrc])
    if ver == 4:
        b += struct.pack('!I', sys_service)
    # the dissector steps over a fixed client length for each version
    return b.ljust({1: 67, 2: 115, 3: 150, 4: 160}[ver], b'\0')


def adm(msgtype, records, version=1, recsize=104):
    return (s('ADM_EYE', 12) + bytes([version, msgtype]) + s(str(recsize), 11) +
                             s(str(len(records)), 11) + b''.join(records))


def admrec(op, ser=1, ex=1, err=0, value=b''):
    return bytes([op, ser, ex, err]) + value.ljust(100, b'\0')[:100]


def rzl(strg_type, name='PARAM1', integer=True):
    v = bytes([strg_type, 0, 0, 0]) + s(name, 20)
    v += b''.join(struct.pack('!I', i + 1) for i in range(10)) if integer else s('text', 40)
    return v + b'\0' * 36


def logon(typ=1, port=3200, name=b'logon1', prot=b'DIAG', host=b'h.example', misc=b'misc',
          v6=IP6, end=b'\0\0\0\1', v6len=16, resp=False, tail=b''):
    b = struct.pack('!HH', typ, port) + IP4 + struct.pack('!H', len(name)) + name
    b += struct.pack('!H', len(prot)) + prot + struct.pack('!H', len(host)) + host
    b += struct.pack('!H', len(misc)) + misc
    if resp:
        return b + b'\1\2\3\4\5\6\7' + tail
    return b + struct.pack('!H', v6len) + v6 + end


def prop(pid, value=b''):
    return s('CLIENT_1', 40) + struct.pack('!I', pid) + value


def build_main(out):
    c = Cap()
    f = Flow(c, CLI, SRV, 40000, 3600)
    send = lambda m, to_srv=True: f.send(ni(m), to_srv)
    # --- logins (MS_LOGIN_2 with diag port) and name/type messages --------
    send(ms(0, 0, body=b'\0' * 4, port=3201))                      # request, iflag 0: diag port
    send(ms(0, 8, body=b'\0\0\0\0', port=0))                          # login 2
    send(ms(2, 1, 0x00, body=b'\x07'))                             # MS_DP_ADM
    for op in (0x01, 0x21, 0x40, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x12, 0x13, 0x1d, 0x51):
        send(ms(2, 2, op, body=b'\0'))                             # opcodes without a body
    for op in (0x02, 0x03, 0x04):
        for v in (1, 2, 3, 4, 9):
            send(ms(2, 7, op, ver=v, body=client(v if v < 9 else 4)))
    send(ms(3, 1, 0x05, ver=4, body=client(4, 'A') + client(4, 'B', sys_service=7)), False)
    send(ms(3, 1, 0x4d, ver=3, body=client(3)), False)
    send(ms(3, 1, 0x4f, ver=2, body=client(2) + client(2)), False)
    send(ms(3, 1, 0x05, ver=1, body=client(1)), False)
    send(ms(2, 1, 0x05, ver=4, body=b''))                          # request: no clients
    send(ms(2, 1, 0x06, ver=1, body=IP4))
    send(ms(2, 1, 0x06, ver=2, body=IP4 + IP6))
    # --- security keys, hardware id -----------------------------------------
    send(ms(2, 1, 0x07, body=s('KEYNAME', 40) + b'K' * 256))
    send(ms(2, 1, 0x08, body=s('KEYNAME', 40)))
    send(ms(3, 1, 0x08, body=b'K' * 256), False)
    send(ms(3, 1, 0x09, body=b'K' * 256), False)
    send(ms(2, 1, 0x09, ver=1, body=IP4 + struct.pack('!H', 3200)))
    send(ms(2, 1, 0x09, ver=2, body=IP6 + struct.pack('!H', 3200)))
    send(ms(3, 1, 0x0a, body=s('HARDWARE-ID-0001', 100)), False)
    send(ms(2, 1, 0x0a, body=b'\xde\xad\xbe\xef'))
    send(ms(2, 1, 0x0a, body=b''))
    # --- statistics, open requests, codepage, dump, file reload -----------
    send(ms(3, 1, 0x11, body=b'\0' * 4), False)
    send(ms(3, 1, 0x11, body=b'\0' * 712), False)
    send(ms(3, 1, 0x11, err=3, body=b'\0' * 4), False)             # error: nothing decoded
    send(ms(2, 1, 0x11, body=b'\0' * 4))                           # request
    send(ms(3, 1, 0x14, body=b'\1' * 176), False)
    send(ms(2, 1, 0x14, body=b'\1' * 8))
    send(ms(3, 1, 0x1c, body=struct.pack('!I', 1100)), False)
    send(ms(2, 1, 0x1c, body=b'\0'))
    send(ms(2, 1, 0x1e, body=bytes([1, 0, 0, 0]) + struct.pack('!HH', 1, 4) + s('DUMPNAME', 40)))
    send(ms(2, 1, 0x1e, body=bytes([1, 0, 0, 0]) + struct.pack('!HH', 1, 4)))
    send(ms(3, 1, 0x1e, body=b'dump text line\n' * 3), False)
    send(ms(3, 1, 0x1e, body=b'\0'), False)
    send(ms(1, 1, 0x1e, body=b'\0'))
    send(ms(2, 1, 0x1f, body=bytes([1, 0, 0, 0])))
    # --- text, counters --------------------------------------------------
    txt = b'some text value'
    send(ms(2, 1, 0x22, body=s('TXT1', 40) + struct.pack('!I', len(txt)) + txt))
    send(ms(3, 1, 0x23, body=s('TXT1', 40) + struct.pack('!I', len(txt)) + txt), False)
    cnt = s('COUNTER-UUID-1', 40) + struct.pack('!II', 5, 2)
    for op in (0x24, 0x25, 0x26, 0x27, 0x28, 0x29):
        send(ms(2, 1, op, body=cnt))
    send(ms(2, 1, 0x24, body=b'short'))
    send(ms(3, 1, 0x2a, body=cnt * 3), False)
    # --- logon -------------------------------------------------------------
    for op in (0x2b, 0x2c, 0x2d):
        send(ms(2, 1, op, body=logon()))
    send(ms(3, 1, 0x2c, body=logon(resp=True, tail=b'tail!')), False)
    send(ms(3, 1, 0x2c, body=logon(resp=True)), False)
    # --- server disconnect, shutdown with and without a reason -------------
    for op in (0x2e, 0x2f, 0x30, 0x4a):
        send(ms(2, 1, op, ver=4, body=client(4) + struct.pack('!H', 6) + b'reason'))
    send(ms(2, 1, 0x2f, ver=4, body=client(4) + struct.pack('!H', 0)))
    send(ms(2, 1, 0x2f, ver=4, body=client(4)))
    send(ms(2, 1, 0x30, ver=4, body=client(4) + struct.pack('!H', 99) + b'short'))
    # --- NI trace, properties, ip to name, ACL, SID, counters, gateway ---------
    send(ms(2, 1, 0x3f, body=s('CLIENT_1', 40) + bytes([0, 1, 0, 3, 0, 0])))
    send(ms(3, 1, 0x3f, body=s('CLIENT_1', 40) + bytes([0, 2, 0, 5, 0, 0])), False)
    send(ms(3, 1, 0x3f, body=b''), False)
    send(ms(3, 1, 0x3f, err=2, body=b'\0'), False)
    send(ms(2, 1, 0x43, body=prop(0x02, struct.pack('!H', 1) + b'\0' * 12 + struct.pack('!H', 8) + b'vhost.ex')))
    send(ms(2, 1, 0x43, body=prop(0x02, struct.pack('!H', 1) + b'\0' * 12 + struct.pack('!H', 0))))
    send(ms(2, 1, 0x43, body=prop(0x03, IP4 + IP6)))
    send(ms(2, 1, 0x44, body=prop(0x04, struct.pack('!I', 6) + s('rdisp/', 100) + b'\0\0' +
                                  struct.pack('!H', 5) + b'value')))
    send(ms(2, 1, 0x44, body=prop(0x04, struct.pack('!I', 0) + b'\0' * 100 + b'\0\0' + struct.pack('!H', 0))))
    send(ms(2, 1, 0x45, body=prop(0x05, struct.pack('!H', 3200) + b'\1')))
    send(ms(2, 1, 0x45, body=prop(0x07, s('7.53', 10) + struct.pack('!III', 100, 5, 1))))
    send(ms(2, 1, 0x45, body=prop(0x01, b'text')))
    send(ms(2, 1, 0x45, body=prop(0x01)))                         # no value
    send(ms(2, 1, 0x46, ver=1, body=IP4 + struct.pack('!HI', 3200, 8) + b'hostname'))
    send(ms(2, 1, 0x46, ver=2, body=IP6 + struct.pack('!HI', 3200, 8) + b'hostname'))
    send(ms(2, 1, 0x46, ver=3, body=struct.pack('!HI', 3200, 0)))
    send(ms(2, 1, 0x47, ver=2, body=IP6))
    send(ms(2, 1, 0x47, ver=1, body=b'\0'))
    send(ms(3, 1, 0x47, body=struct.pack('!H', 0) + b'acl-one\0acl-two\0'), False)
    send(ms(3, 1, 0x47, body=struct.pack('!H', 0) + b'acl-one\0'), False)
    send(ms(3, 1, 0x4e, body=s('SID', 8)), False)
    send(ms(3, 1, 0x4e, err=1, body=b'\0'), False)
    send(ms(3, 1, 0x50, body=struct.pack('!II', 1, 2) + b'\x01\0\0\0' + b'R' * 96), False)
    send(ms(3, 1, 0x50, err=1, body=b'\0'), False)
    send(ms(2, 1, 0x52, body=bytes([1]) + struct.pack('!I', 3200) + bytes([2]) + struct.pack('!I', 3300) +
            bytes([3]) + struct.pack('!Q', 4242) + bytes([4]) + IP6 + bytes([0])))
    send(ms(3, 1, 0x53, body=bytes([1]) + struct.pack('!I', 3200) + bytes([9]) + b'unknown-tag'), False)
    send(ms(3, 1, 0x53, err=1, body=b'\0'), False)
    send(ms(2, 1, 0x54, body=b'K' * 0x1030))
    send(ms(3, 1, 0x54, body=b''), False)
    send(ms(3, 1, 0x54, body=b'x'), False)
    # --- unknown opcode ----------------------------------------------------
    send(ms(2, 1, 0x7f, body=b'\0\0'))
    # --- ADM opcodes -------------------------------------------------------
    send(ms(2, 5, body=adm(1, [admrec(0x01, value=b'rdisp/name=x'), admrec(0x2e, value=b'param=1'),
                               admrec(0x15, value=rzl(11)), admrec(0x15, value=rzl(10, integer=False)),
                               admrec(0x15, value=rzl(31)), admrec(0x00, value=b'general')])))
    send(ms(3, 5, body=adm(2, [admrec(0x02), admrec(0x66), admrec(0x7e)])), False)
    send(ms(3, 5, body=adm(2, [])), False)
    c.write(os.path.join(out, 'sapms-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    f = Flow(c, CLI, SRV, 40000, 3900)
    send = lambda m, to_srv=True: f.send(ni(m), to_srv)
    send(EYE)                                                      # eyecatcher only
    send(EYE + b'\3')                                              # one byte of header
    send(ms(2, 1, 0x01)[:100])                                     # shorter than 110 bytes
    send(ms(2, 1, body=b'')[:110])                                 # nothing after the header
    send(ms(2, 1, body=b'abc'))                                    # opcode header cut short
    send(ms(2, 5, body=b'short'))                                  # ADM header cut short
    send(ms(2, 5, body=adm(1, [admrec(0x01)])[:60]))               # ADM record cut short
    send(ms(2, 1, 0x02, ver=4, body=client(4)[:100]))              # client shorter than its length
    send(ms(3, 1, 0x05, ver=4, body=client(4) + client(4)[:50]), False)
    send(ms(2, 1, 0x07, body=b'short'))
    send(ms(2, 1, 0x08, body=b'short'))
    send(ms(3, 1, 0x08, body=b'short'), False)
    send(ms(3, 1, 0x09, body=b'short'), False)
    send(ms(2, 1, 0x09, ver=1, body=b'abc'))
    send(ms(2, 1, 0x09, ver=2, body=b'abc'))
    send(ms(3, 1, 0x0a, body=b'abc'), False)
    send(ms(2, 1, 0x0a, body=b'abc'))
    send(ms(3, 1, 0x11, body=b'\0' * 7), False)
    send(ms(3, 1, 0x14, body=b'\1' * 100), False)
    send(ms(2, 1, 0x22, body=b'short'))
    send(ms(2, 1, 0x22, body=s('TXT1', 40) + struct.pack('!I', 3) + b'some text value'))   # length mismatch
    send(ms(0, 8, body=b'', port=0))                               # header only: returns 0
    for op in (0x2b, 0x2c, 0x2d):
        full = logon()
        for cut in (5, 12, 14, 16, 20, 22, 26, 30, 34, 36):
            send(ms(2, 1, op, body=full[:cut]))
    # logon fields with lengths larger than the data, one for each field
    send(ms(2, 1, 0x2b, body=struct.pack('!HH', 1, 1) + IP4 + struct.pack('!H', 50) + b'ab'))
    send(ms(2, 1, 0x2b, body=struct.pack('!HH', 1, 1) + IP4 + struct.pack('!H', 1) + b'a' + struct.pack('!H', 50) + b'ab'))
    send(ms(2, 1, 0x2b, body=struct.pack('!HH', 1, 1) + IP4 + struct.pack('!H', 1) + b'a' + struct.pack('!H', 1) + b'p' +
            struct.pack('!H', 50) + b'ab'))
    send(ms(2, 1, 0x2b, body=struct.pack('!HH', 1, 1) + IP4 + struct.pack('!H', 1) + b'a' + struct.pack('!H', 1) + b'p' +
            struct.pack('!H', 1) + b'h' + struct.pack('!H', 50) + b'ab'))
    send(ms(2, 1, 0x2b, body=logon(v6len=4, v6=b'abcd')))
    send(ms(2, 1, 0x2b, body=logon(end=b'')))
    full = logon(resp=True)
    for cut in (5, 12, 14, 16, 20, 24, 28, 32, 36, 38, 42, 44, 50):
        send(ms(3, 1, 0x2c, body=full[:cut]), False)
    send(ms(3, 1, 0x2c, body=struct.pack('!HH', 1, 1) + IP4 + struct.pack('!H', 50) + b'ab'), False)
    send(ms(2, 1, 0x2e, ver=4, body=client(4)[:80]))
    send(ms(2, 1, 0x3f, body=b'short'))
    send(ms(3, 1, 0x3f, body=b'short'), False)
    send(ms(2, 1, 0x46, ver=1, body=b'ab'))
    send(ms(2, 1, 0x46, ver=2, body=b'ab'))
    send(ms(2, 1, 0x46, ver=1, body=IP4 + b'ab'))
    send(ms(2, 1, 0x46, ver=1, body=IP4 + struct.pack('!HI', 3200, 99) + b'abc'))
    send(ms(2, 1, 0x47, ver=2, body=b'ab'))
    send(ms(3, 1, 0x47, body=b'a'), False)
    send(ms(3, 1, 0x47, body=struct.pack('!H', 0) + b'unterminated'), False)       # no NUL
    send(ms(3, 1, 0x47, body=struct.pack('!H', 0) + b'one\0unterminated'), False)  # second without NUL
    send(ms(3, 1, 0x4e, body=b'abc'), False)
    send(ms(3, 1, 0x50, body=b'abc'), False)
    send(ms(3, 1, 0x50, body=struct.pack('!II', 1, 9) + b'\0' * 8 + b'r' * 48), False)  # count > data
    send(ms(3, 1, 0x50, body=struct.pack('!II', 1, 40) + b'\0' * 8), False)             # count > 15
    send(ms(2, 1, 0x52, body=bytes([1, 0, 0])))
    send(ms(2, 1, 0x52, body=bytes([3, 0, 0])))
    send(ms(2, 1, 0x52, body=bytes([4, 0, 0])))
    send(ms(2, 1, 0x52, body=bytes([2])))
    send(ms(3, 1, 0x53, body=b'\0'), False)
    send(ms(2, 1, 0x54, body=b'x'))
    c.write(os.path.join(out, 'sapms-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)
