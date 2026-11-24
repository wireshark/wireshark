#!/usr/bin/env python3
# Generates test/captures/zip_coverage.zip.gz, zip_coverage_http.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic ZIP coverage files (Python struct and zlib only).
usage: mkzip.py <outdir>
  zip_coverage.zip        main file: local files, central directory, Zip64 records
  zip_coverage_http.pcap  HTTP responses carrying ZIP data (media types, Export Objects,
                          records that end the walk, the reproducers of the fixes)
  zip_coverage_malformed.pcap  malformed/unsupported cases (coverage only)
"""
import os
import struct
import sys
import zlib

out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)

SIG_LFH, SIG_CDH, SIG_EOCD = 0x04034b50, 0x02014b50, 0x06054b50
SIG_Z64EOCD, SIG_Z64LOC, SIG_DD, SIG_DSIG = 0x06064b50, 0x07064b50, 0x08074b50, 0x05054b50
U32 = 0xFFFFFFFF


def dos(y=2026, mo=11, d=14, h=12, mi=30, s=20):
    return struct.pack("<HH", (h << 11) | (mi << 5) | (s // 2), ((y - 1980) << 9) | (mo << 5) | d)


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def extra(eid, data=b""):
    return struct.pack("<HH", eid, len(data)) + data


def lfh(name, method, flags, crc, csize, usize, extras=b"", data=b"", ver=20):
    return (struct.pack("<IHHH", SIG_LFH, ver, flags, method) + dos() +
            struct.pack("<IIIHH", crc, csize, usize, len(name), len(extras)) +
            name + extras + data)


def cdh(name, method, flags, crc, csize, usize, off, extras=b"", comment=b"",
        made=(20, 3), ver=20, disk=0, iattr=0, eattr=0):
    return (struct.pack("<IHHHH", SIG_CDH, made[0] | (made[1] << 8), ver, flags, method) + dos() +
            struct.pack("<IIIHHHHHII", crc, csize, usize, len(name), len(extras), len(comment),
                        disk, iattr, eattr, off) + name + extras + comment)


def eocd(n, size, off, comment=b""):
    return struct.pack("<IHHHHIIH", SIG_EOCD, 0, 0, n, n, size, off, len(comment)) + comment


# Extra fields ---------------------------------------------------------------
def ex_ut(flags, *times):
    return extra(0x5455, bytes([flags]) + b"".join(struct.pack("<I", t) for t in times))


def ex_ntfs(extra_tag=True):
    ft = struct.pack("<QQQ", 133_800_000_000_000_000, 133_800_000_100_000_000, 133_800_000_200_000_000)
    d = struct.pack("<I", 0) + struct.pack("<HH", 1, 24) + ft
    if extra_tag:
        d += struct.pack("<HH", 2, 4) + b"\1\2\3\4"
    return extra(0x000a, d)


def ex_unix2(uid=1000, gid=100):
    return extra(0x7855, struct.pack("<HH", uid, gid))


def ex_unix3(ver=1, uid=b"\xe8\x03\x00\x00", gid=b"\x64\x00\x00\x00"):
    return extra(0x7875, bytes([ver, len(uid)]) + uid + bytes([len(gid)]) + gid)


def ex_upath(name, ver=1, crc=None, of=None):
    of = name if of is None else of
    c = zlib.crc32(of) if crc is None else crc
    return extra(0x7075, bytes([ver]) + struct.pack("<I", c) + name)


def ex_ucom(comment, ver=1, crc=None):
    c = zlib.crc32(comment) if crc is None else crc
    return extra(0x6375, bytes([ver]) + struct.pack("<I", c) + comment)


def ex_zip64(usize=None, csize=None, off=None, disk=None):
    d = b""
    if usize is not None: d += struct.pack("<Q", usize)
    if csize is not None: d += struct.pack("<Q", csize)
    if off is not None: d += struct.pack("<Q", off)
    if disk is not None: d += struct.pack("<I", disk)
    return extra(0x0001, d)


# Main file ---------------------------------------------------------------------
text = b"Hello, synthetic ZIP world. " * 4
text2 = (b"The quick brown fox jumps over the lazy dog.\n" * 20)
u8name = "café.txt".encode("utf-8")
cp437name = b"caf\x82.txt"        # e-acute in CP437

recs = []   # (name, method, flags, crc, csize, usize, local_extra, cd_extra, comment, made, data, eattr)


def add(name, data_raw, method=0, flags=0, lex=b"", cex=b"", comment=b"", made=(20, 3),
        crc=None, comp=None, ver=20, eattr=0, iattr=0):
    comp = comp if comp is not None else (deflate(data_raw) if method == 8 else data_raw)
    crc = zlib.crc32(data_raw) if crc is None else crc
    recs.append(dict(name=name, method=method, flags=flags, crc=crc, csize=len(comp),
                     usize=len(data_raw), lex=lex, cex=cex, comment=comment, made=made,
                     data=comp, ver=ver, eattr=eattr, iattr=iattr))


# 1 stored, Unix Time with all three times, Unix type 3 extra, NTFS, UTF-8 path
add(b"hello.txt", text, 0, 0, lex=ex_ut(7, 1794659420, 1794659421, 1794659422) + ex_unix3() + ex_ntfs() +
    ex_upath(b"hello.txt") + ex_unix2(),
    cex=ex_ut(7, 1794659420) + ex_unix2() + ex_unix3(1, b"\xe8\x03", b"\x64") + ex_ntfs(False) +
    ex_upath(b"hello.txt"), comment=b"first file", made=(30, 3), eattr=0x81a40000, iattr=1)
# 2 deflate, maximum compression bits, UTF-8 name
add(u8name, text2, 8, 0x0802, lex=ex_ut(1, 1794659420), cex=ex_ut(1, 1794659420),
    comment="café comment".encode("utf-8"), made=(63, 3))
# 3 deflate, fast (0x4 bit), CP437 name (no UTF-8 flag) with UTF-8 path extra fields (good, bad crc,
#   version 2) and UTF-8 comment (good, bad crc, version 2) in the central directory
add(cp437name, text2[:200], 8, 0x0004,
    lex=ex_upath(u8name, 1, None, cp437name) + ex_ucom(b"utf-8 comment"),
    cex=ex_upath(u8name, 1, None, cp437name) + ex_upath(u8name, 1, 0x12345678) + ex_upath(u8name, 2) +
        ex_ucom(b"utf-8 comment") + ex_ucom(b"utf-8 comment", 1, 0xdeadbeef) + ex_ucom(b"x", 2),
    comment=b"utf-8 comment", made=(20, 0), eattr=0x20)
# 4 deflate with a wrong CRC (warning)
add(b"badcrc.txt", text, 8, 0x0000, crc=0x0badc0de, made=(20, 10))
# 5 deflate64 flags (bit 1 super fast), no decompression
add(b"deflate64.bin", b"\x00" * 64, 9, 0x0006, comp=b"\x03\x00" + b"\x00" * 10, made=(45, 19))
# 6 LZMA with EOS flag, patched data flag
add(b"lzma.bin", b"abc", 14, 0x0022, comp=b"\x09\x14\x05\x00\x5d\x00\x00\x10\x00\x00",
    cex=extra(0x9999) + extra(0xCAFE, b"unknown extra data"), made=(46, 1))
# 7 other methods without a decompressor: bzip2, zstd, xz, reserved
for nm, m in ((b"bzip2.bin", 12), (b"zstd.bin", 93), (b"xz.bin", 95), (b"ppmd.bin", 98)):
    add(nm, b"payload", m, 0x0000, comp=b"\x00\x01\x02\x03\x04\x05\x06", made=(63, 3))
# 8 strong encryption bit without the encryption bit, central directory encryption bit, language bit
add(b"flags.bin", text, 0, 0x2840, made=(20, 2))
# 9 directory entry and zero-length files
add(b"dir/", b"", 0, 0, eattr=0x41ed0010 & 0xffffffff, made=(20, 3))
add(b"empty.txt", b"", 0, 0, made=(20, 5))
add(b"empty_deflate.txt", b"", 8, 0, comp=b"\x03\x00", made=(20, 6))
# 10 data descriptor: the crc and sizes follow the data (no signature); not supported, so the
#    walk skips to the next record
dd_data = deflate(text)
add(b"streamed.txt", text, 8, 0x0008, crc=0, comp=dd_data, made=(20, 7))
recs[-1]["dd"] = struct.pack("<III", zlib.crc32(text), len(dd_data), len(text))
# 11 Zip64 local record: sizes in the extra field
z64data = text
add(b"zip64.txt", z64data, 0, 0, lex=ex_zip64(len(z64data), len(z64data)),
    cex=ex_zip64(len(z64data), len(z64data), 0x1000, 0), made=(45, 3), ver=45)
recs[-1]["z64"] = True
# 12 Zip64 in the central directory with only an offset and a disk number
add(b"zip64b.txt", b"b" * 10, 0, 0, made=(45, 3), ver=45)
recs[-1]["z64off"] = True
# 13 MS-DOS made-by with several host systems
for i, host in enumerate((4, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 20, 99)):
    add(b"host%d.txt" % host, b"h%d" % host, 0, 0, made=(10 + i, host))

body = b""
cd = b""
for r in recs:
    off = len(body)
    r["off"] = off
    csize, usize = r["csize"], r["usize"]
    lcsize, lusize = csize, usize
    if r.get("z64"):
        lcsize = lusize = U32
    body += lfh(r["name"], r["method"], r["flags"], r["crc"], lcsize, lusize, r["lex"], r["data"], r["ver"])
    if "dd" in r:
        body += r["dd"]
    body += b"\x00" * 3   # padding between records, skipped by the PK search
    ccs, cus, coff, cdisk, cex = csize, usize, off, 0, r["cex"]
    if r.get("z64"):
        ccs = cus = U32
        coff = U32
        cdisk = 0xFFFF
    if r.get("z64off"):
        coff, cdisk = U32, 0xFFFF
        cex = ex_zip64(None, None, off, 0)
    cd += cdh(r["name"], r["method"], r["flags"] & ~0 if "dd" not in r else r["flags"],
              r["crc"] if "dd" not in r else zlib.crc32(text), ccs if "dd" not in r else csize,
              cus, coff, cex, r["comment"], r["made"], r["ver"], cdisk, r["iattr"], r["eattr"])
cd_off = len(body)
# Zip64 end of central directory with an extensible data sector, its locator, and the end record
ext = b"\xaa\xbb\xcc\xdd" * 3
z64eocd_off = cd_off + len(cd)
z64eocd = (struct.pack("<IQHHIIQQQQ", SIG_Z64EOCD, 44 + len(ext), 45 | (3 << 8), 45, 0, 0,
                       len(recs), len(recs), len(cd), cd_off) + ext)
z64loc = struct.pack("<IIQI", SIG_Z64LOC, 0, z64eocd_off, 1)
end = eocd(len(recs), len(cd), cd_off, b"synthetic archive comment")
main = body + cd + z64eocd + z64loc + end
open(os.path.join(out, "zip_coverage.zip"), "wb").write(main)


# HTTP pcap ----------------------------------------------------------------------
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.n = 0

    def http(self, data, ctype, url=b"/f.zip", sport=40000, extra_hdr=b""):
        self.n += 1
        sport += self.n
        ct = (b"Content-Type: " + ctype + b"\r\n") if ctype else b""
        req = b"GET " + url + b" HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
        resp = (b"HTTP/1.1 200 OK\r\n" + ct + extra_hdr + b"Content-Length: " + str(len(data)).encode() +
                b"\r\n\r\n" + data)
        c, s = bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1])
        # request, response in one segment each, plain seq numbers
        self.frames.append(self.pkt(c, s, sport, 80, 1, 1, req))
        self.frames.append(self.pkt(s, c, 80, sport, 1, 1 + len(req), resp))

    @staticmethod
    def pkt(src, dst, sp, dp, seq, ack, payload):
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        mac = lambda x: b"\x02\0\0\0\0" + bytes([x])
        return (mac(2 if src[3] == 1 else 1) + mac(1 if src[3] == 1 else 2) + b"\x08\x00" + ip + tcp)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack("<IIII", 1794659420 + i, 0, len(fr), len(fr)) + fr)


# small valid ZIPs for the HTTP capture
def small(name=b"a.txt", data=b"abc", method=0, flags=0, lex=b"", tail=b""):
    comp = deflate(data) if method == 8 else data
    return lfh(name, method, flags, zlib.crc32(data), len(comp), len(data), lex, comp) + tail


one = small()
p = Pcap()
p.http(main, b"application/zip", b"/archive.zip")                       # Export Objects, media type
p.http(small(b"b.txt", text, 8, 0, tail=eocd(0, 0, 0)), b"application/java-archive", b"/a.jar")
p.http(small(b"c.txt", text), b"application/vnd.example+zip", b"/download.zip")   # media_type.suffix zip
# reproducer of "ZIP: Fix an endless loop and an assertion on malformed files" (UTF-8 comment extra
# in a local file header, no comment_tvb)
ucom_name = b"a.txt"
ucom = lfh(ucom_name, 0, 0, 0, 0, 0, extra(0x6375, struct.pack("<BI", 1, 0)), b"") + eocd(0, 0, 0)
p.http(ucom, b"application/zip", b"/ucom.zip")
# compressed size beyond the data (endless loop reproducer): the second record claims a size
# that returned a negative length. A short a stored record exceeds the remaining data.
rec0 = lfh(b"a", 0, 0, 0, 0, 0)
csize = (1 << 32) - len(rec0) - 30
neg = rec0 + lfh(b"", 99, 0, 0, csize, csize) + b"\0" * 16
p.http(neg, b"application/zip", b"/neg.zip")
p.http(lfh(b"trunc.txt", 0, 0, 0, 100, 100) + b"short", b"application/zip", b"/trunc.zip")
# record types that end the walk: data descriptor with signature, digital signature
p.http(small(b"d.txt", text, 8, 0x0008, tail=b"") [:0] +
       lfh(b"d.txt", 8, 0x0008, 0, 0, 0, b"", deflate(text)) + struct.pack("<IIII", SIG_DD, zlib.crc32(text),
       len(deflate(text)), len(text)) + eocd(1, 0, 0), b"application/zip", b"/dd.zip")
p.http(one + struct.pack("<IH", SIG_DSIG, 8) + b"signature" + eocd(1, 0, 0), b"application/zip", b"/sig.zip")
# a stored file with a unix2 extra field in a local header only
p.http(small(b"u.txt", b"u", 0, 0, ex_unix2(7, 8)), b"application/zip", b"/u.zip")
p.write(os.path.join(out, "zip_coverage_http.pcap"))

# Malformed / unsupported ---------------------------------------------------------
m = Pcap()
# compressed size above 4 GiB in a Zip64 extra field: unsupported
m.http(lfh(b"big.bin", 0, 0, 0, U32, U32, ex_zip64(1 << 33, 1 << 33)) + b"x" * 20, b"application/zip")
# Zip64 end of directory record whose size overflows
m.http(one + struct.pack("<IQ", SIG_Z64EOCD, 0xFFFFFFFFFFFFFFF8) + b"\0" * 60, b"application/zip")
# truncated extra fields, short records
m.http(lfh(b"x", 0, 0, 0, 0, 0, b"\x55\x54\x09\x00\x07\x01\x02"), b"application/zip")
m.http(struct.pack("<I", SIG_CDH) + b"\0" * 10, b"application/zip")
m.http(struct.pack("<I", SIG_EOCD) + b"\0" * 5, b"application/zip")
m.http(one + struct.pack("<I", SIG_Z64LOC) + b"\0" * 6, b"application/zip")
# NTFS extra field with tag size past the end
m.http(lfh(b"n", 0, 0, 0, 0, 0, extra(0x000a, struct.pack("<IHH", 0, 1, 24) + b"\0" * 8)), b"application/zip")
# unix3 with bad version and sizes outside 1..8
m.http(lfh(b"u", 0, 0, 0, 0, 0, extra(0x7875, b"\x02\x04")), b"application/zip")
m.http(lfh(b"u", 0, 0, 0, 0, 0, extra(0x7875, b"\x01\x00")), b"application/zip")
m.http(lfh(b"u", 0, 0, 0, 0, 0, extra(0x7875, b"\x01\x02\x01\x02\x09" + b"\0" * 9)), b"application/zip")
m.http(lfh(b"u", 0, 0, 0, 0, 0, extra(0x7875, b"\x01\x02\x01\x02\x00")), b"application/zip")
# central directory unix2 / local-style ut flags
m.http(cdh(b"c", 0, 0, 0, 0, 0, 0, ex_unix2() + ex_ut(7, 1, 2, 3)) + eocd(1, 0, 0), b"application/zip")
# ZIP data that does not start with a record: leading junk, signature without dissector
m.http(b"junkPK" + one, b"application/zip")
m.http(b"P" * 7 + b"PK\x09\x09", b"application/zip")
m.write(os.path.join(out, "zip_coverage_malformed.pcap"))
print(len(main))
