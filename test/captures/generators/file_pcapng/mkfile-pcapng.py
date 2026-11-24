#!/usr/bin/env python3
# Generates test/captures/file_pcapng_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic pcapng files for the file-pcapng / file-pcapng-darwin dissectors.

usage: mkfile-pcapng.py <outdir>
Writes file-pcapng-coverage.pcapng (valid, two sections, both byte orders)
and file-pcapng-coverage-malformed.pcapng (bad lengths, bad options, the
reproducers of the fixes). Both are read with
-X read_format:"MIME Files Format".
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


class W:
    """Builder for one byte order."""
    def __init__(self, le):
        self.e = '<' if le else '>'
        self.le = le

    def p(self, fmt, *a):
        return struct.pack(self.e + fmt, *a)

    def blk(self, t, body, total=None, trailer=None):
        body += b'\0' * ((-len(body)) % 4)
        l = 12 + len(body)
        return (self.p('II', t, l if total is None else total) + body +
                self.p('I', l if trailer is None else trailer))

    def opt(self, c, v=b'', length=None):
        if isinstance(v, str):
            v = v.encode()
        return (self.p('HH', c, len(v) if length is None else length) + v +
                b'\0' * ((-len(v)) % 4))

    def end(self):
        return self.opt(0)

    def custom(self, c, pen, data):
        if isinstance(data, str):
            data = data.encode()
        return self.opt(c, self.p('I', pen) + data)

    def shb(self, opts=b'', magic=None, section=-1):
        m = magic if magic is not None else self.p('I', 0x1A2B3C4D)
        return self.blk(0x0A0D0D0A, m + self.p('HHq', 1, 0, section) + opts)

    def idb(self, link=1, snap=0, opts=b''):
        return self.blk(1, self.p('HHI', link, 0, snap) + opts)

    def epb(self, ifid, ts, data, opts=b'', orig=None):
        return self.blk(6, self.p('IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                  len(data), len(data) if orig is None else orig)
                        + data + b'\0' * ((-len(data)) % 4) + opts)

    def pb(self, ifid, drops, ts, data, opts=b''):
        return self.blk(2, self.p('HHIIII', ifid, drops, ts >> 32, ts & 0xffffffff,
                                  len(data), len(data))
                        + data + b'\0' * ((-len(data)) % 4) + opts)

    def spb(self, data, orig=None):
        return self.blk(3, self.p('I', len(data) if orig is None else orig) + data)

    def nrb(self, recs, opts=b''):
        return self.blk(4, recs + opts)

    def rec(self, code, data):
        return self.p('HH', code, len(data)) + data + b'\0' * ((-len(data)) % 4)

    def isb(self, ifid, ts, opts=b''):
        return self.blk(5, self.p('III', ifid, ts >> 32, ts & 0xffffffff) + opts)

    def dsb(self, typ, data, opts=b''):
        return self.blk(0x0A, self.p('II', typ, len(data)) + data +
                        b'\0' * ((-len(data)) % 4) + opts)

    def cb(self, t, pen, data):
        return self.blk(t, self.p('I', pen) + data)

    def dpib(self, pid, opts):
        # Darwin integers are little endian in either byte order
        return self.blk(0x80000001, struct.pack('<I', pid) + opts)


# a small Ethernet / IPv4 / UDP frame (synthetic)
def frame(n):
    pay = b'coverage %d' % n
    udp = struct.pack('>HHHH', 5000 + n, 6000, 8 + len(pay), 0) + pay
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + udp
    return bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip


def le_ifs(w):
    return []


def section(w, nid):
    out = b''
    # Section Header Block with every option
    out += w.shb(
        w.opt(1, 'synthetic coverage section %d' % nid) + w.opt(2, 'synthetic hardware') +
        w.opt(3, 'synthetic os') + w.opt(4, 'mkfile-pcapng.py') +
        w.custom(2988, 32473, 'utf8 copy') + w.custom(2989, 32473, b'\x01\x02\x03') +
        w.custom(19372, 32473, 'utf8 nocopy') + w.custom(19373, 32473, b'\x04\x05') +
        w.opt(0xf00, b'\x01\x02\x03') + w.end())
    # IDB 0: every option; timestamp resolution microseconds, offset 0
    out += w.idb(1, 65535,
        w.opt(1, 'first interface') + w.opt(2, 'eth0') + w.opt(3, 'synthetic interface') +
        w.opt(4, bytes([192, 0, 2, 1, 255, 255, 255, 0])) +
        w.opt(5, bytes.fromhex('20010db8000000000000000000000001') + b'\x40') +
        w.opt(6, bytes([2, 0, 0, 0, 0, 1])) + w.opt(7, bytes([2, 0, 0, 0xff, 0xfe, 0, 0, 1])) +
        w.opt(8, w.p('Q', 1000000000)) + w.opt(9, b'\x06') + w.opt(10, w.p('I', 3600)) +
        w.opt(11, b'\x00' + b'udp port 6000') + w.opt(12, 'synthetic os') +
        w.opt(13, b'\x04') + w.opt(14, w.p('q', 100)) + w.opt(15, 'synthetic nic') +
        w.opt(16, w.p('Q', 100000)) + w.opt(17, w.p('Q', 1000)) +
        w.opt(18, 'Australia/Sydney') + w.custom(2988, 32473, 'idb custom') +
        w.opt(0xf01, b'\xff') + w.end())
    # IDBs for the timestamp resolution table
    for v in [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x8a, 0x83]:
        out += w.idb(1, 0, w.opt(9, bytes([v])) + w.end())
    # filters of type 1 and unknown, other link types, odd-length name
    out += w.idb(113, 0, w.opt(11, b'\x01' + b'\x06\x00\x00\x00\x00\x00\x00\x00') + w.end())
    out += w.idb(147, 0, w.opt(11, b'\x07' + b'\xaa\xbb') + w.opt(2, 'odd') + w.end())
    # resolution that overflows 64 bits (10^-64): no time stamp can be computed
    out += w.idb(1, 0, w.opt(9, b'\x40') + w.end())
    # IDB with an if_tsoffset and no resolution option (default 10^-6)
    out += w.idb(1, 0, w.opt(14, w.p('q', 1000)) + w.end())
    # --- packets
    flags_opt = w.opt(2, w.p('I', 0x01 | 0x4 | (1 << 5) | 0x00010000 | 0x80000000))
    for i in range(4):
        fl = [0x1, 0x2, 0x3, 0x4][i]
        out += w.epb(0, 1700000000 * 1000000 + i, frame(i),
            w.opt(1, 'packet %d' % i) + w.opt(2, w.p('I', fl | (i << 2) | (i << 5) | (i << 9) | (0x8000 << 16) * (i & 1))) +
            w.opt(3, b'\x00' + b'\x01\x02\x03\x04') + w.opt(3, b'\x04' + bytes(range(20))) +
            w.opt(4, w.p('Q', i)) + w.opt(5, w.p('Q', 0x1122334455667788)) +
            w.opt(6, w.p('I', i)) +
            w.opt(7, b'\x00' + b'\x01') +
            w.opt(7, b'\x01' + w.p('Q', 0xabcd)) + w.opt(7, b'\x02' + w.p('Q', 0xdcba)) +
            w.opt(7, b'\x09' + b'\x00\x00') +
            w.opt(8, w.p('II', 1234, 5678)) +
            w.custom(2988, 32473, 'epb custom') + w.opt(0xf02, b'\x01') +
            w.end())
    # Darwin options on EPBs (little endian values in both byte orders)
    out += w.epb(0, 1700000000 * 1000000 + 10, frame(10),
        w.opt(32769, struct.pack('<I', 0)) + w.opt(32770, struct.pack('<I', 300)) +
        w.opt(32771, struct.pack('<I', 1)) + w.opt(32772, struct.pack('<I', 0x3f)) +
        w.opt(32773, struct.pack('<I', 0xdeadbeef)) + w.opt(32774, struct.pack('<I', 7)) + w.end())
    out += w.epb(0, 1700000000 * 1000000 + 11, frame(11),
        w.opt(32770, struct.pack('<I', 999)) + w.end())
    # timestamps with the other interfaces
    for ifid in range(1, 19):
        out += w.epb(ifid, 1700000000 + ifid, frame(20 + ifid), w.end() if ifid % 2 else b'')
    out += w.epb(19 + 1, 7, frame(60))
    # snaplen: SPB on interface 0 (65535) and zero length
    out += w.spb(frame(40))
    # interface with snap length smaller than the original length
    out += w.idb(1, 20, w.end())
    # Packet Block (obsolete) with options
    out += w.pb(0, 3, 1700000000 * 1000000, frame(41),
        w.opt(1, 'obsolete packet block') + w.opt(2, w.p('I', 0x2)) + w.opt(3, b'\x02\xde\xad\xbe\xef') +
        w.opt(0xf03, b'\x01') + w.end())
    out += w.pb(1, 0, 5, frame(42))
    # packet data too short for the link layer (an exception with dissect_next_layer)
    out += w.pb(0, 0, 5, b'\x01\x02\x03\x04\x05')
    out += w.spb(b'\x01\x02\x03\x04\x05')
    out += w.epb(0, 5, b'\x01\x02\x03\x04\x05')
    # Name Resolution Block
    out += w.nrb(
        w.rec(1, bytes([192, 0, 2, 1]) + b'host1.example\0host1\0') +
        w.rec(1, bytes([192, 0, 2, 2]) + b'host2.example\0') +
        w.rec(1, bytes([192, 0, 2, 3]) + b'noterm') +
        w.rec(2, bytes.fromhex('20010db8000000000000000000000001') + b'host6.example\0') +
        w.rec(2, bytes.fromhex('20010db8000000000000000000000002') + b'unterminated') +
        w.rec(3, bytes([2, 0, 0, 0, 0, 1]) + b'mac.example\0') +
        w.rec(4, bytes([2, 0, 0, 0xff, 0xfe, 0, 0, 1]) + b'eui64.example\0') +
        w.rec(0x77, b'\x01\x02\x03') +
        w.p('HH', 0, 0),
        w.opt(1, 'resolved names') + w.opt(2, 'dns.example') + w.opt(3, bytes([192, 0, 2, 53])) +
        w.opt(4, bytes.fromhex('20010db8000000000000000000000053')) + w.opt(0xf04, b'x') + w.end())
    # NRB without an End of Records record, ending exactly at the data end
    out += w.nrb(w.rec(1, bytes([192, 0, 2, 9]) + b'last\0'))
    # Interface Statistics Block with every option
    out += w.isb(0, 1700000100 * 1000000,
        w.opt(1, 'stats') + w.opt(2, w.p('Q', 1700000000 * 1000000)) + w.opt(3, w.p('Q', 1700000100 * 1000000)) +
        w.opt(4, w.p('Q', 100)) + w.opt(5, w.p('Q', 1)) + w.opt(6, w.p('Q', 99)) + w.opt(7, w.p('Q', 2)) +
        w.opt(8, w.p('Q', 97)) + w.opt(0xf05, b'x') + w.end())
    out += w.isb(9, 5)
    # Decryption Secrets Block (placeholder text, not a key log)
    out += w.dsb(0x544c534b, b'# synthetic placeholder, not a key log\n', w.opt(1, 'dsb comment') + w.opt(5, b'xyz') + w.end())
    out += w.dsb(0x4a4f5552, b'')
    # Custom Blocks
    out += w.cb(0x00000BAD, 32473, b'copyable custom data')
    out += w.cb(0x40000BAD, 7, b'x')
    out += w.cb(0x00000BAD, 99999999, b'')
    # Blocks without a dissector of their own
    out += w.blk(7, b'\1' * 16)
    out += w.blk(8, b'\2' * 8)
    out += w.blk(9, b'MESSAGE=synthetic\n\n')
    out += w.blk(0x101, b'\3' * 12)
    out += w.blk(0x102, b'\4' * 12)
    out += w.blk(0x12345, b'\5' * 4)
    out += w.blk(0x80001234, b'\6' * 8)     # local block, no handler
    # Darwin Process Information Blocks (local block 0x80000001)
    out += w.dpib(501, w.opt(1, 'darwin process') + w.opt(2, 'mDNSResponder') +
                  w.opt(4, bytes(range(16))) + w.opt(0xf06, b'zz') + w.end())
    out += w.dpib(1, w.opt(2, 'launchd') + w.opt(4, bytes(range(16, 32))) + w.end())
    out += w.dpib(7, b'')
    return out


def main():
    le, be = W(True), W(False)
    data = section(le, 1) + section(be, 2)
    # a third section: little endian again, minimal, after a big endian one
    data += le.shb(le.end()) + le.idb(1, 0, le.end()) + le.epb(0, 1, frame(99))
    open(os.path.join(OUT, 'file-pcapng-coverage.pcapng'), 'wb').write(data)

    # ----- malformed
    m = b''
    w = le
    m += w.shb(w.end())
    m += w.idb(1, 0, w.end())
    # options: odd lengths for every fixed-size option (invalid option length)
    bad = b''
    for c, ln in [(4, 3), (5, 3), (6, 3), (7, 3), (8, 3), (9, 2), (10, 2), (13, 2), (14, 2), (16, 2), (17, 2)]:
        bad += w.opt(c, b'\1' * ln)
    bad += w.opt(11, b'') + w.opt(0, b'', 0) + w.end()
    m += w.idb(1, 0, bad)
    m += w.idb(1, 0, w.opt(11, b'\x00' + b'x') + w.opt(2, b'abc') + w.opt(1, b'xx', 40) + w.end())
    m += w.idb(1, 0, w.opt(0, b'\0\0\0\0', 4))
    # EPB options with bad lengths, option length past the block
    badepb = b''
    for c, ln in [(2, 2), (4, 3), (5, 3), (6, 3), (8, 3), (7, 0)]:
        badepb += w.opt(c, b'\1' * ln)
    badepb += w.opt(7, b'\x01\x00')       # verdict eBPF TC with a short value
    badepb += w.opt(3, b'\x00')           # hash without data
    badepb += w.end()
    m += w.epb(0, 5, frame(1), badepb)
    m += w.epb(0, 5, frame(1), w.opt(1, b'zz', 200) + w.end())
    # missing interface (EPB, PB, SPB, ISB)
    m += w.epb(9, 5, frame(2))
    m += w.pb(9, 0, 5, frame(2))
    m += w.pb(0, 0, 5, frame(2), w.opt(2, b'\1\2') + w.end())
    m += w.isb(9, 5)
    # NRB with bad record lengths and an End of Records with a length
    m += w.nrb(w.rec(1, b'\1\2') + w.rec(2, b'\1\2\3\4') + w.p('HH', 0, 4) + b'\0\0\0\0')
    # NRB: the fix reproducers (names running past the record, stale label)
    m += w.nrb(w.rec(1, bytes([192, 0, 2, 1]) + b'ab') + w.rec(1, bytes([192, 0, 2, 2]) + b'c\0') +
               w.rec(0x55, b'zz') + w.p('HH', 0, 0))
    m += w.nrb(w.rec(0, b''), w.opt(3, b'\1' * 3) + w.opt(4, b'\1' * 3) + w.end())
    m += w.isb(0, 5, b''.join(w.opt(c, b'\1' * 3) for c in range(2, 9)) + w.end())
    m += w.epb(0, 5, frame(1), w.opt(32773, struct.pack('<I', 5)) + w.end())
    # DSB with a secrets length past the block, CB tiny, block-length checks
    m += w.blk(0x0A, w.p('II', 0x544c534b, 4000) + b'\0' * 8)
    # PB/SPB whose block ends before its fields (ReportedBoundsError)
    m += w.blk(6, b'\0' * 8)
    # block length not multiple of 4 and trailer mismatch
    m += w.blk(1, w.p('HHI', 1, 0, 0), trailer=99)
    # Darwin block with a short option
    m += w.dpib(3, w.opt(4, b'\1' * 5) + w.opt(2, b'') + w.end())
    # the reproducers of the review (odd values)
    m += w.idb(1, 0, w.opt(9, b'\x00') + w.end()) + w.idb(1, 0, w.opt(9, b'\xbf') + w.end())
    m += w.idb(1, 0, w.opt(9, b'\x7f') + w.opt(14, b'\xff' * 8) + w.end())
    for ifid in (0, 1, 2):
        pass
    m += w.epb(len(m) and 11, (1 << 64) - 1, frame(3))
    # Extraneous data after the options
    m += w.blk(5, w.p('III', 0, 0, 0) + w.opt(0, b'', 0) + b'\xaa\xbb\xcc\xdd')
    # block length below the minimum: stops
    tail = w.p('II', 2, 8)
    data = m + tail
    open(os.path.join(OUT, 'file-pcapng-coverage-malformed.pcapng'), 'wb').write(data)

    # more malformed files (one defect each: they stop the dissection)
    def wr(name, d):
        open(os.path.join(OUT, name), 'wb').write(d)
    ok = le.shb(le.end()) + le.idb(1, 0, le.end())
    wr('file-pcapng-malformed-badmagic.pcapng', ok + le.shb(le.end(), magic=b'\xde\xad\xbe\xef') + le.epb(0, 1, frame(1)))
    # an Exported PDU naming "file-pcapng" with a bad byte order magic in
    # the first block (the MIME reader does not accept such a file)
    pdus = [le.shb(le.end(), magic=b'\xde\xad\xbe\xef'), ok + le.epb(0, 1, frame(1))]
    with open(os.path.join(OUT, 'file-pcapng-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, b in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 12) + b'file-pcapng' + b'\0' + struct.pack('>HH', 0, 0) + b
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)
    wr('file-pcapng-malformed-len-odd.pcapng', ok + le.blk(6, b'\0' * 20, total=34))
    wr('file-pcapng-malformed-len-small.pcapng', ok + le.blk(6, b'\0' * 20, total=8))
    wr('file-pcapng-malformed-len-big.pcapng', ok + le.p('II', 6, 4000) + b'\0' * 24)
    wr('file-pcapng-malformed-shb-trunc.pcapng', ok + le.p('II', 0x0A0D0D0A, 28) + le.p('I', 0x1A2B3C4D) + b'\0' * 12)


main()
