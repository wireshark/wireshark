# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
def u(*v):
    return b''.join(struct.pack('>I', x & 0xffffffff) for x in v)
def xstr(s):
    b = s.encode() if isinstance(s, str) else s
    return u(len(b)) + b + b'\0' * (-len(b) % 4)
def call(xid, prog, vers, proc, args=b'', cred=u(0, 0), verf=u(0, 0)):
    return u(xid, 0, 2, prog, vers, proc) + cred + verf + args
def reply(xid, res=b'', verf=u(0, 0), accept=0):
    return u(xid, 1, 0) + verf + u(accept) + res
def denied(xid, why=1, *extra):
    return u(xid, 1, 1, why, *extra)
def flavor(fl, body):
    return u(fl, len(body)) + body + b'\0' * (-len(body) % 4)
def rec(data, last=True):
    return u((0x80000000 if last else 0) | len(data)) + data
