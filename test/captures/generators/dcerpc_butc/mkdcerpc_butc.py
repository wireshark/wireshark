#!/usr/bin/env python3
# Generates test/captures/dcerpc_butc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic coverage captures for the DCE/DFS backup tape
coordinator (BUTC, packet-dcerpc-butc.c) dissector.

Connectionless DCE/RPC (ncadg_ip_udp) over UDP port 135, which carries the
interface UUID in every packet, so no Decode As is needed. Every packet is
built with struct; nothing comes from a real network.

Usage: mkdcerpc_butc.py <outdir>
Writes dcerpc-butc-coverage.pcap and dcerpc-butc-coverage-malformed.pcap.
"""
import os
import struct
import sys
import uuid

BUTC = ('1d193c08-000b-11ca-ba1d-02608c2ea96e', 4)

# ---------------------------------------------------------------- framing


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


C = (192, 0, 2, 70)
S = (192, 0, 2, 80)


def udp(src, dst, sport, dport, payload, from_client):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    mc, ms = bytes.fromhex('020000000070'), bytes.fromhex('020000000080')
    eth = (ms + mc) if from_client else (mc + ms)
    return eth + b'\x08\x00' + ip + u


def cl(ptype, opnum, seq, act, stub, big):
    """Connectionless DCE/RPC header (80 octets) and stub."""
    drep = b'\x00\x00\x00' if big else b'\x10\x00\x00'
    e = '>' if big else '<'
    u = uuid.UUID(BUTC[0])
    a = uuid.UUID(act)
    ifu = u.bytes if big else u.bytes_le
    actb = a.bytes if big else a.bytes_le
    hdr = struct.pack('BBBB', 4, ptype, 0x28 if ptype == 0 else 0x0a, 0)
    hdr += drep + b'\x00' + b'\x00' * 16 + ifu + actb
    hdr += struct.pack(e + 'IIIHHHHH', 1, BUTC[1], seq, opnum, 0xffff,
                       0xffff, len(stub), 0)
    hdr += b'\x00\x00'
    assert len(hdr) == 80
    return hdr + stub


class Frames(list):
    trunc = False       # cut every stub in half (malformed capture)

    def pair(self, opnum, req, resp=None, big=False):
        if self.trunc:
            req = req[:len(req) // 2]
            resp = resp[:len(resp) // 2] if resp is not None else None
        seq = len(self)
        act = '7c9d0000-0000-4000-8000-%012x' % seq
        port = 41000 + seq % 1000
        self.append(udp(C, S, port, 135, cl(0, opnum, seq, act, req, big), True))
        if resp is not None:
            self.append(udp(S, C, 135, port, cl(2, opnum, seq, act, resp, big),
                            False))


# ---------------------------------------------------------------- NDR


class W:
    """NDR writer; alignment is relative to the start of the stub."""

    def __init__(self, big=False):
        self.b = bytearray()
        self.e = '>' if big else '<'

    def align(self, n):
        self.b += b'\0' * (-len(self.b) % n)
        return self

    def u8(self, v):
        self.b += struct.pack('B', v)
        return self

    def u16(self, v):
        self.align(2)
        self.b += struct.pack(self.e + 'H', v)
        return self

    def u32(self, *vs):
        for v in vs:
            self.align(4)
            self.b += struct.pack(self.e + 'I', v & 0xffffffff)
        return self

    def udlong(self, v):
        # idl2wrs udlong: dissect_ndr_duint32, aligned to 4
        self.align(4)
        self.b += struct.pack(self.e + 'Q', v)
        return self

    def raw(self, b):
        self.b += b
        return self

    def vs(self, s):
        """butcNameString_t: varying string (offset, actual count), NUL
        terminated, 1 octet per character."""
        b = s.encode() + b'\0' if s is not None else b''
        self.u32(0, len(b))
        return self.raw(b)

    # --- butc structures

    def netaddr(self, typ, data):
        self.u16(typ)
        for x in data:
            self.u8(x)
        return self

    def dumpdesc(self, vid, name, part):
        self.align(4)
        self.udlong(vid).vs(name).u32(part, 1690000000, 1690000100)
        self.netaddr(2, bytes([0, 135, 192, 0, 2, 81]) + bytes(8))
        return self.u32(1, 2, 3, 4)

    def restoredesc(self, frag, tape, flags, old, new):
        self.align(4)
        self.u32(frag).vs(tape).u32(7)
        self.udlong(0x100000000 + frag).udlong(0x200000000 + frag)
        self.u32(3, flags)
        self.netaddr(2, bytes([0, 135, 192, 0, 2, 82]) + bytes(8))
        self.u32(0xd0d0, 0, 0, 0)
        return self.vs(old).vs(new)

    def tapelabel(self, name, size=1 << 30):
        self.align(4)
        self.u32(size, 0, 0, 0, 0, 0, len(name))
        return self.vs(name)

    def tapeset(self):
        self.align(4)
        self.u32(5).vs('tapesrv.example.com').vs('daily.%d')
        return self.u32(10, 1, 0, 1700086400, 1, 0, 0, 0, 0)

    def dumpinterface(self):
        self.align(4)
        self.vs('/full/daily').vs('user.vols').vs('user.vols.daily')
        self.tapeset()
        return self.u32(0, 1, 0, 0, 0, 0)

    def tcinfo(self):
        return self.align(4).u32(4, 0, 0, 0, 0)

    def statusinfo(self, level):
        self.u32(level)
        if level in (3, 4):         # TCOP_DUMP, TCOP_RESTORE: SwitchVol
            self.align(4).u32(1024 * level).vs('user.vol%d' % level)
            self.u32(level - 3, 0)
        elif level in (1, 2):       # TCOP_READLABEL, TCOP_LABELTAPE: label
            self.align(4).tapelabel('tape.%d' % level).u32(0)
        elif level in (0, 5, 6, 7, 8, 9):
            self.u32(0x50 + level)
        # any other level has no arm
        return self

    def tcistatus(self, level, name='task'):
        self.align(4)
        self.vs(name).u32(1 << (level % 5), 1700000000 + level)
        self.statusinfo(level)
        return self.u32(100 + level, 0, 0, 0)

    def status(self, v):
        return self.u32(v)


ST_ERR = 0xc0000022     # NTSTATUS access denied


def build(f, big=False, st_alt=False):
    """One request/response pair of every opnum."""
    def w():
        return W(big)
    st = ST_ERR if st_alt else 0

    # 0 PerformDump: dump interface, then an array of 3 dump descriptors
    # behind embedded pointers, one of them NULL.
    rq = w().dumpinterface()
    # The conformance (max count) of the array comes first: the dissector
    # reads it in the conformant run, then the length and the pointers.
    rq.u32(3).u32(2).u32(0x20000, 0, 0x20004)
    rq.dumpdesc(0x1000001, 'user.alice', 1).dumpdesc(0x1000002, '', 2)
    f.pair(0, bytes(rq.b), bytes(w().u32(77).status(st).b), big)

    # 1 PerformRestore: dump set name and 3 restore descriptors with
    # flags 1, 2 and 3 (one pointer NULL).
    rq = w().u32(0x20000).vs('user.vols.daily')
    rq.u32(4).u32(3).u32(0x20004, 0x20008, 0, 0x2000c)
    rq.restoredesc(1, 'tape.1', 1, 'user.a', '.restored')
    rq.restoredesc(2, 'tape.2', 2, 'user.b', '')
    rq.restoredesc(3, 'tape.3', 3, 'user.c', '.r')
    f.pair(1, bytes(rq.b), bytes(w().u32(78).status(st).b), big)

    # 2 AbortDump
    f.pair(2, bytes(w().u32(77).b), bytes(w().status(st).b), big)
    # 3 LabelTape
    f.pair(3, bytes(w().tapelabel('tape.new').b),
           bytes(w().u32(201).status(st).b), big)
    # 4 ReadLabel
    f.pair(4, b'', bytes(w().u32(202).status(st).b), big)
    # 5 ScanDumps
    f.pair(5, bytes(w().u32(1).b), bytes(w().u32(203).status(st).b), big)
    # 6 TCInfo
    f.pair(6, b'', bytes(w().tcinfo().status(st).b), big)
    # 7 SaveDb, 8 RestoreDb
    f.pair(7, b'', bytes(w().u32(204).status(st).b), big)
    f.pair(8, b'', bytes(w().u32(205).status(st).b), big)
    # 9 EndStatus
    f.pair(9, bytes(w().u32(204).b), bytes(w().status(st).b), big)
    # 10 GetStatus
    f.pair(10, bytes(w().u32(203).b),
           bytes(w().tcistatus(3, 'dump').status(st).b), big)
    # 11 RequestAbort
    f.pair(11, bytes(w().u32(203).b), bytes(w().status(st).b), big)
    # 12 ScanStatus
    f.pair(12, bytes(w().u32(203, 1).b),
           bytes(w().u32(204).tcistatus(4, 'restore').u32(2).status(st).b),
           big)
    # 13 GetServerInterfaces
    f.pair(13, b'', bytes(w().status(st).b), big)


def main_capture():
    f = Frames()
    build(f)                    # frames 1-28, little endian, status 0
    build(f, big=True, st_alt=True)     # frames 29-56, big endian
    # Every arm of tc_statusInfoSwitch and a level without an arm, in
    # GetStatus (levels 0-9) and ScanStatus (level 42) responses.
    for level in range(10):
        f.pair(10, bytes(W().u32(300 + level).b),
               bytes(W().tcistatus(level, 'op%d' % level).status(0).b))
    f.pair(12, bytes(W().u32(310, 0).b),
           bytes(W().u32(311).tcistatus(42, '').u32(2).status(0).b))
    # PerformRestore with a NULL dump set name and an empty array, and a
    # restore descriptor with an unknown flag bit.
    rq = W().u32(0).u32(0).u32(0)
    f.pair(1, bytes(rq.b), bytes(W().u32(0).status(0).b))
    rq = W().u32(0).u32(1).u32(1).u32(0x20000)
    rq.restoredesc(4, 'tape.4', 0x5, 'user.d', '')
    f.pair(1, bytes(rq.b))
    # Reproducer from the review (butc_flags_be.py): big endian
    # PerformRestore whose restore flags are 3.
    stub = struct.pack('>I', 0) + struct.pack('>I', 1) + struct.pack('>I', 1)
    stub += struct.pack('>I', 0x00020000)

    def vs(s):
        b = s.encode() + b'\0'
        r = struct.pack('>II', 0, len(b)) + b
        return r + b'\0' * (-len(r) % 4)
    desc = struct.pack('>i', 1) + vs('tape')
    desc += struct.pack('>i', 0)
    desc += b'\0' * (-len(stub + desc) % 8)
    desc += struct.pack('>QQ', 5, 6) + struct.pack('>i', 7) + struct.pack('>I', 3)
    desc += struct.pack('>H', 2) + b'\0' * 14 + struct.pack('>IIII', 9, 0, 0, 0)
    desc += vs('old') + vs('new')
    f.pair(1, stub + desc, big=True)
    return f


def malformed_capture():
    f = Frames()
    # Every request and response cut short.
    f.trunc = True
    build(f)
    f.trunc = False
    # A restore array with a huge count.
    f.pair(1, bytes(W().u32(0).u32(0x40000000).u32(0x40000000).u32(0x20000).b))
    # A string longer than the packet.
    f.pair(3, bytes(W().u32(1, 0, 0, 0, 0, 0, 9).u32(0, 5000).raw(b'abc').b))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dcerpc-butc-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'dcerpc-butc-coverage-malformed.pcap'),
               malformed_capture())


if __name__ == '__main__':
    main()
