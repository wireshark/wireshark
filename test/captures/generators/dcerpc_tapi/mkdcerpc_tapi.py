#!/usr/bin/env python3
# Generates test/captures/dcerpc_tapi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkdcerpc_tapi.py <outdir>: write dcerpc_tapi-coverage.pcap and
dcerpc_tapi-coverage-malformed.pcap, synthetic captures for the TAPI
dissector (packet-dcerpc-tapi.c, Microsoft Telephony API service,
hand-written).

Connection-oriented DCE/RPC over TCP with a bind to TAPI
2f5f6520-ca46-1067-b319-00dd010662da v1.0 and the three opnums the
dissector knows (ClientAttach, ClientRequest, ClientDetach), in NDR
little endian, NDR big endian and NDR64.  Only the TCP/DCE-RPC framing
helpers of ndrgen.py are used; the stubs are written here with struct.
Nothing comes from a real network.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
from ndrgen import TCP, RPC, write_pcap  # noqa: E402

UUID = '2f5f6520-ca46-1067-b319-00dd010662da'
VER = (1, 0)
STATUS_SUCCESS, STATUS_ACCESS_DENIED = 0, 0xc0000022
STATUS_INVALID_PARAMETER = 0xc000000d


class Stub:
    def __init__(self, le, ndr64):
        self.e = '<' if le else '>'
        self.ndr64 = ndr64
        self.b = bytearray()

    def align(self, n):
        while len(self.b) % n:
            self.b.append(0)

    def u32(self, v):
        self.align(4)
        self.b += struct.pack(self.e + 'I', v & 0xffffffff)

    def u3264(self, v):
        if self.ndr64:
            self.align(8)
            self.b += struct.pack(self.e + 'Q', v)
        else:
            self.u32(v)

    def raw(self, data):
        self.b += data

    def handle(self, attr, uuid16):
        # context handle: 4 octets of attributes and a 16 octet UUID
        self.u32(attr)
        self.raw(uuid16)

    def wstring(self, s):
        # [string] [ref] wchar_t *: conformant varying, NUL terminated
        u = s + '\0'
        self.u3264(len(u))
        self.u3264(0)
        self.u3264(len(u))
        for c in u:
            self.b += struct.pack(self.e + 'H', ord(c))

    def array(self, data, maxc=None, actual=None):
        # [size_is] char element_7[*]: conformant varying array of octets
        self.u3264(len(data) if maxc is None else maxc)
        self.u3264(0)
        self.u3264(len(data) if actual is None else actual)
        self.raw(data)

    def bytes(self):
        return bytes(self.b)


H1 = bytes.fromhex('7461706900000000000000000000aa01')
H2 = bytes.fromhex('7461706900000000000000000000aa02')


def attach_rq(le, ndr64, n, a, b):
    s = Stub(le, ndr64)
    s.u32(n)
    s.wstring(a)
    s.wstring(b)
    return s.bytes()


def attach_rs(le, ndr64, h, v, rc):
    s = Stub(le, ndr64)
    s.handle(0, h)
    s.u32(v)
    s.u32(rc)
    return s.bytes()


def request_rq(le, ndr64, h, data, maxc=None, actual=None, n=None):
    s = Stub(le, ndr64)
    s.handle(0, h)
    s.array(data, maxc, actual)
    s.u32(len(data) if n is None else n)
    return s.bytes()


def rc(le, ndr64, v):
    s = Stub(le, ndr64)
    s.u32(v)
    return s.bytes()


def session(F, port, le, ndr64, extra=False):
    t = TCP(F, port)
    r = RPC(t, UUID, VER, le=le, ndr64=ndr64)
    r.bind()
    r.call(0, attach_rq(le, ndr64, 0x00010001, 'CLIENT01', 'user01'),
           attach_rs(le, ndr64, H1, 0x00000003, STATUS_SUCCESS))
    r.call(1, request_rq(le, ndr64, H1, b'ABCDEFGH'), rc(le, ndr64, STATUS_SUCCESS))
    r.call(1, request_rq(le, ndr64, H1, bytes(range(0x20, 0x20 + 27))),
           rc(le, ndr64, STATUS_INVALID_PARAMETER))
    if extra:
        # an empty array
        r.call(1, request_rq(le, ndr64, H1, b''), rc(le, ndr64, STATUS_SUCCESS))
        # actual count smaller than the max count
        r.call(1, request_rq(le, ndr64, H1, b'0123', maxc=64, n=64),
               rc(le, ndr64, STATUS_SUCCESS))
        # a second attach that is refused
        r.call(0, attach_rq(le, ndr64, 0, '', 'x'),
               attach_rs(le, ndr64, b'\0' * 16, 0, STATUS_ACCESS_DENIED))
        # a 6000 octet array in two DCE/RPC fragments over several TCP
        # segments
        r.call(1, request_rq(le, ndr64, H2, bytes((i * 13) & 0xff for i in range(6000))),
               rc(le, ndr64, STATUS_SUCCESS))
        # an opnum the dissector does not know
        r.call(3, b'\0' * 8, b'\0' * 4)
    r.call(2, b'', b'')
    t.fin()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []
    session(F, 50001, True, False, extra=True)
    session(F, 50002, False, False, extra=True)
    session(F, 50003, True, True)
    write_pcap(os.path.join(out, 'dcerpc_tapi-coverage.pcap'), F)

    # Malformed: the reproducer of "TAPI: Do not let an array count move
    # the offset back" (tapi_count_wrap.py: actual counts 0xffffffff and
    # 0x80000010), an array longer than the data, and cut stubs.
    F = []
    le, n64 = True, False
    t = TCP(F, 50101)
    r = RPC(t, UUID, VER)
    r.bind()
    r.call(1, request_rq(le, n64, H1, b'ABCDEFGH'), rc(le, n64, 0))
    r.call(1, request_rq(le, n64, H1, b'ABCDEFGH', actual=0xffffffff, n=8), rc(le, n64, 0))
    r.call(1, request_rq(le, n64, H1, b'ABCDEFGH', actual=0x80000010, n=8), rc(le, n64, 0))
    r.call(1, request_rq(le, n64, H1, b'ABCDEFGH', actual=0x100, n=8), rc(le, n64, 0))
    rq = attach_rq(le, n64, 1, 'CLIENT01', 'user01')
    r.call(0, rq[:len(rq) // 2], attach_rs(le, n64, H1, 3, 0)[:10])
    r.call(1, request_rq(le, n64, H1, b'ABCDEFGH')[:20], b'\0\0')
    t.fin()
    write_pcap(os.path.join(out, 'dcerpc_tapi-coverage-malformed.pcap'), F)


if __name__ == '__main__':
    main()
