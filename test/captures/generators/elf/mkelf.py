#!/usr/bin/env python3
# Generates test/captures/elf_coverage.elf.gz, elf_coverage_http.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic ELF coverage files (Python struct only).
usage: mkelf.py <outdir>
  elf_coverage.elf          main file: 64-bit little endian
  elf_coverage_http.pcap    32-bit LE, 32-bit BE, 64-bit BE files and the reproducers of the fixes,
                            each as the body of an HTTP response (the elf_http heuristic)
  elf_coverage_malformed.pcap  malformed/odd files (coverage only)
"""
import os
import struct
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)


def uleb(v):
    r = b""
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            r += bytes([b | 0x80])
        else:
            return r + bytes([b])


def sleb(v):
    r = b""
    while True:
        b = v & 0x7f
        v >>= 7
        if (v == 0 and not b & 0x40) or (v == -1 and b & 0x40):
            return r + bytes([b])
        r += bytes([b | 0x80])


class Elf:
    def __init__(self, cls=64, be=False, etype=3, machine=62, osabi=0, ident_class=None,
                 ident_data=None, ehsize=None, phentsize=None, shentsize=None):
        self.cls, self.be = cls, be
        self.e = ">" if be else "<"
        self.etype, self.machine, self.osabi = etype, machine, osabi
        self.ident_class = cls // 32 if ident_class is None else ident_class
        self.ident_data = (2 if be else 1) if ident_data is None else ident_data
        self.ehsize = (52 if cls == 32 else 64) if ehsize is None else ehsize
        self.phentsize = (32 if cls == 32 else 56) if phentsize is None else phentsize
        self.shentsize = (40 if cls == 32 else 64) if shentsize is None else shentsize
        self.secs = [dict(name="", type=0, flags=0, data=b"", link=0, info=0, align=0, entsize=0, addr=0, size=None, pad=0)]
        self.phdrs = []
        self.shstrndx = None
        self.pad = {}
        self.phoff_override = None
        self.shoff_override = None
        self.shnum_override = None

    @property
    def w(self):
        return 4 if self.cls == 32 else 8

    def add(self, name, typ, data=b"", flags=0, link=0, info=0, align=1, entsize=0, addr=0,
            size=None, pad=0):
        self.secs.append(dict(name=name, type=typ, flags=flags, data=data, link=link, info=info,
                              align=align, entsize=entsize, addr=addr, size=size, pad=pad))
        return len(self.secs) - 1

    def ph(self, typ, flags=0, sec=None, raw=None, vaddr=0, paddr=0, memsz=None, align=0x1000):
        self.phdrs.append(dict(type=typ, flags=flags, sec=sec, raw=raw, vaddr=vaddr, paddr=paddr,
                               memsz=memsz, align=align))

    def pack_sym(self, name, value, size, info, other, shndx):
        e = self.e
        if self.cls == 32:
            return struct.pack(e + "IIIBBH", name, value, size, info, other, shndx)
        return struct.pack(e + "IBBHQQ", name, info, other, shndx, value, size)

    def pack_dyn(self, tag, val):
        return struct.pack(self.e + ("II" if self.cls == 32 else "QQ"), tag, val)

    def build(self, entry=0x401000, flags=0):
        e = self.e
        # section name string table
        names = b"\0"
        offs = {}
        for s in self.secs[1:]:
            offs[s["name"]] = len(names)
            names += s["name"].encode() + b"\0"
        shstr = self.add(".shstrtab", 3, b"", align=1)
        offs[".shstrtab"] = len(names)
        names += b".shstrtab\0"
        self.secs[shstr]["data"] = names
        shstrndx = shstr if self.shstrndx is None else self.shstrndx
        nph = len(self.phdrs)
        pos = self.ehsize
        phoff = pos if nph else 0
        pos += nph * self.phentsize
        layout = []
        for s in self.secs:
            pos += s.get("pad", 0)
            if s["type"] == 0:
                layout.append(0)
                continue
            a = max(s["align"], 1)
            pos = (pos + a - 1) // a * a
            layout.append(pos)
            if s["type"] != 8:
                pos += len(s["data"])
        shoff = pos
        # program headers
        ph = b""
        for p in self.phdrs:
            if p["sec"] is not None:
                off = layout[p["sec"]]
                fsz = len(self.secs[p["sec"]]["data"])
            elif p["raw"] is not None:
                off, fsz = p["raw"]
            else:
                off = fsz = 0
            msz = fsz if p["memsz"] is None else p["memsz"]
            if self.cls == 32:
                ph += struct.pack(e + "IIIIIIII", p["type"], off, p["vaddr"], p["paddr"], fsz, msz,
                                  p["flags"], p["align"])
            else:
                ph += struct.pack(e + "IIQQQQQQ", p["type"], p["flags"], off, p["vaddr"], p["paddr"],
                                  fsz, msz, p["align"])
        ph = ph.ljust(nph * self.phentsize, b"\0")
        # section headers
        sh = b""
        for i, s in enumerate(self.secs):
            size = len(s["data"]) if s.get("size") is None else s["size"]
            nm = offs.get(s["name"], 0)
            if self.cls == 32:
                sh += struct.pack(e + "IIIIIIIIII", nm, s["type"], s["flags"], s["addr"], layout[i], size,
                                  s["link"], s["info"], s["align"], s["entsize"])
            else:
                sh += struct.pack(e + "IIQQQQIIQQ", nm, s["type"], s["flags"], s["addr"], layout[i], size,
                                  s["link"], s["info"], s["align"], s["entsize"])
        sh = sh.ljust(len(self.secs) * self.shentsize, b"\0")
        ident = b"\x7fELF" + bytes([self.ident_class, self.ident_data, 1, self.osabi, 0]) + b"\0" * 7
        pof = phoff if self.phoff_override is None else self.phoff_override
        sof = shoff if self.shoff_override is None else self.shoff_override
        shnum = len(self.secs) if self.shnum_override is None else self.shnum_override
        if self.cls == 32:
            hdr = ident + struct.pack(e + "HHIIIIIHHHHHH", self.etype, self.machine, 1, entry, pof, sof, flags,
                                      self.ehsize, self.phentsize, nph, self.shentsize, shnum, shstrndx)
        else:
            hdr = ident + struct.pack(e + "HHIQQQIHHHHHH", self.etype, self.machine, 1, entry, pof, sof, flags,
                                      self.ehsize, self.phentsize, nph, self.shentsize, shnum, shstrndx)
        body = hdr.ljust(self.ehsize, b"\0") + ph
        for i, s in enumerate(self.secs):
            if s["type"] in (0, 8):
                continue
            body = body.ljust(layout[i], b"\0") + s["data"]
        body = body.ljust(shoff, b"\0") + sh
        return body


# DWARF / eh_frame helpers -----------------------------------------------------------
def cie(e, aug=b"zR", ca=1, da=-8, ra=16, augdata=b"\x1b", instr=b"\x0c\x07\x08\x90\x01\x00\x00", ext=False,
        version=1):
    body = struct.pack(e + "I", 0) + bytes([version]) + aug + b"\0" + uleb(ca) + sleb(da) + uleb(ra)
    if aug.startswith(b"z"):
        body += uleb(len(augdata)) + augdata
    body += instr
    return lenpfx(e, body, ext)


def fde(e, cie_off, here, pc_begin, pc_range, aug=True, augdata=b"", instr=b"\x41\x0e\x10\x86\x02\x00\x00", ext=False):
    # the CIE pointer is the distance from this field back to the CIE
    ptr = here + (12 if ext else 4) - cie_off
    body = struct.pack(e + "III", ptr, pc_begin, pc_range)
    if aug:
        body += uleb(len(augdata)) + augdata
    body += instr
    return lenpfx(e, body, ext)


def lenpfx(e, body, ext):
    if ext:
        return struct.pack(e + "IQ", 0xFFFFFFFF, len(body)) + body
    return struct.pack(e + "I", len(body)) + body


def eh_frame(e, base_pos=0):
    """Two CFI groups: a CIE with 'zR' and two FDEs (one with extended length), a CIE without
    augmentation (and an extended length) with an FDE, then the terminator."""
    d = b""
    c1 = len(d); d += cie(e)
    d += fde(e, c1, len(d), 0x1000, 0x40, True, b"\x00")
    d += fde(e, c1, len(d), 0x1040, 0x20, True, b"\x00\x00\x00\x00", ext=True)
    c2 = len(d); d += cie(e, aug=b"", ca=4, da=-4, ra=65, ext=True, version=3)
    d += fde(e, c2, len(d), 0x2000, 0x10, False)
    c3 = len(d); d += cie(e, aug=b"zPLR", ca=1, da=-8, ra=16, augdata=b"\x03\x00\x00\x00\x00\x1b\x1b")
    d += fde(e, c3, len(d), 0x3000, 0x10, True, b"\x00\x00\x00\x00")
    d += struct.pack(e + "I", 0)
    return d


def eh_hdr(e, w, efp, cnt, tbl, entries=3, version=1):
    """eh_frame_hdr with the given encodings (the DW_EH_PE bytes); values are sized to match."""
    def size(enc, ):
        n = enc & 0x0f
        return {0: w, 2: 2, 3: 4, 4: 8, 0xa: 2, 0xb: 4, 0xc: 8}.get(n, 0)

    def enc_val(enc, v, fmt_signed=False):
        n = enc & 0x0f
        if n == 1:
            return uleb(v)
        if n == 9:
            return sleb(v)
        sz = size(enc)
        if sz == 0:
            sz = w
        return int(v).to_bytes(sz, "big" if e == ">" else "little", signed=False)

    d = bytes([version, efp, cnt, tbl])
    d += enc_val(efp, 0x1234)
    d += enc_val(cnt, entries)
    tsz = size(tbl) if size(tbl) else 0
    for i in range(entries):
        if tbl & 0x0f in (1, 9):      # one octet LEB128 values, so every entry has the length of the first
            d += enc_val(tbl, 4 * (i + 1)) + enc_val(tbl, 0x30 + i)
        else:
            d += enc_val(tbl, 0x100 * (i + 1)) + enc_val(tbl, 0x2000 + 0x10 * i)
    return d


DYN_TAGS = list(range(0, 34)) + [0x6ffffef5, 0x6ffffffe, 0x6fffffff, 0x70000001, 34, 35, 0x7fffffff]


def make(cls, be, machine, etype=3, big_name=False, variants="all", symcount=14):
    """A fairly complete ELF file with sections, segments, symbols, dynamic and eh_frame data."""
    el = Elf(cls, be, etype, machine, osabi=3)
    e, w = el.e, el.w
    sym_ent = 16 if cls == 32 else 24
    dyn_ent = 8 if cls == 32 else 16
    # string tables
    strtab = b"\0"
    nm = {}
    for n in ("main", "_start", "printf", "environ", "data_obj", "tls_var", "file.c", "weak_fn", "common_var",
              "abs_sym", "gnu_ifunc", "os_sym", "proc_sym", "last"):
        nm[n] = len(strtab)
        strtab += n.encode() + b"\0"
    if big_name:
        nm["long_name"] = len(strtab)
        strtab += b"L" * 300 + b"\0"            # over the 256 octet cap of the name label
    dynstr = b"\0libc.so.6\0libm.so.6\0my_soname\0my_rpath\0puts\0exit\0"
    # symbols (shndx values are section indexes defined below; 0xfff1/0xfff2 are special)
    NSEC = 0
    sec_idx = {}
    sec_idx.update(dict(text=7, data=12, bss=13))
    syms = [el.pack_sym(0, 0, 0, 0, 0, 0)]
    kinds = [(1, 0, 0), (1, 1, 1), (1, 2, 2), (1, 3, 3), (1, 4, 4), (0, 5, 5), (2, 6, 6), (1, 10, 7), (1, 13, 8), (0, 1, 9),
             (1, 2, 10), (2, 0, 11), (0, 7, 12), (1, 3, 13)]
    names_list = ["main", "_start", "printf", "environ", "data_obj", "tls_var", "file.c", "weak_fn", "common_var",
                  "abs_sym", "gnu_ifunc", "os_sym", "proc_sym", "last"]
    shndxs = [7, 7, 0, 12, 12, 12, 0xfff1, 7, 0xfff2, 0xfff1, 7, 13, 0, 1000]
    for i in range(symcount):
        k = i % len(names_list)
        bind, typ, _ = kinds[k]
        syms.append(el.pack_sym(nm[names_list[k]], 0x401000 + 0x10 * i, 0x10, (bind << 4) | typ, i % 4, shndxs[k]))
    if big_name:
        syms.append(el.pack_sym(nm["long_name"], 0, 0, 0x11, 0, 7))
    symtab = b"".join(syms)
    dsyms = [el.pack_sym(0, 0, 0, 0, 0, 0), el.pack_sym(dynstr.index(b"puts"), 0, 0, 0x12, 0, 0),
             el.pack_sym(dynstr.index(b"exit"), 0, 0, 0x22, 0, 0)]
    dynsym = b"".join(dsyms)
    dynamic = b"".join(el.pack_dyn(t, 0x1000 + t) for t in DYN_TAGS)
    ehf = eh_frame(e)
    # sections: index 1.. (null is 0)
    el.add(".interp", 1, b"/lib/ld-synthetic.so.1\0", 2, align=1)                              # 1
    el.add(".note.gnu.build-id", 7, struct.pack(e + "III", 4, 8, 3) + b"GNU\0" + bytes(range(8)), 2, align=4)  # 2
    el.add(".gnu.hash", 0x6ffffff6, b"\0" * 16, 2, align=8)                                     # 3 OS specific
    el.add(".dynsym", 11, dynsym, 2, entsize=sym_ent, align=8)                                  # 4
    el.add(".dynstr", 3, dynstr, 2, align=1)                                                    # 5
    el.add(".rela.dyn", 4, b"\x01" * (3 * (12 if cls == 32 else 24)), 2, entsize=(12 if cls == 32 else 24), align=8)  # 6
    el.add(".text", 1, bytes(range(32)) * 2, 6, align=16, addr=0x401000)                        # 7
    # eh_frame_hdr variants, then eh_frame
    hdrs = {
        32: [(0x1b, 0x03, 0x3b)],
        64: [(0x1b, 0x03, 0x3b)],
    }[cls]
    if variants == "all":
        hdrs = [(0x1b, 0x03, 0x3b),     # pcrel sdata4, udata4 count, datarel sdata4 table
                (0x01, 0x01, 0x04),     # uleb, uleb, udata8
                (0x09, 0x09, 0x0c),     # sleb, sleb, sdata8
                (0x02, 0x02, 0x02),     # udata2 throughout
                (0x00, 0x00, 0x00),     # absptr throughout (register size)
                (0x04, 0x04, 0x03),     # udata8 pointer and count, udata4 table
                (0x03, 0xff, 0x0b),     # omitted count encoding (register size), sdata4 table
                (0x0a, 0x0a, 0x0a),     # sdata2 throughout
                (0x03, 0x03, 0x01),     # table of uleb128 values
                (0x03, 0x03, 0x09)]     # table of sleb128 values
    for k, (a, b, c) in enumerate(hdrs):
        el.add(".eh_frame_hdr", 1, eh_hdr(e, w, a, b, c, entries=3 if k else 2), 2, align=4)          # 8..
    el.add(".eh_frame", 1, ehf, 2, align=8)
    el.add(".dynamic", 6, dynamic, 3, entsize=dyn_ent, align=8)
    el.add(".got", 1, b"\0" * 16, 3, align=8)
    el.add(".data", 1, b"data" * 8, 3, align=8)
    el.add(".bss", 8, b"", 3, align=8, size=0x400)
    el.add(".comment", 1, b"GCC: (synthetic) 1.0\0", 0x30, entsize=1)
    el.add(".rodata.cst16", 1, b"\xab" * 48, 0x12, entsize=16, align=16)
    el.add(".symtab", 2, symtab, 0, entsize=sym_ent, align=8, link=0)
    el.add(".strtab", 3, strtab, 0)
    el.add(".sec.proc", 0x70000001, b"proc", 0xf0000000 | 0x0ff00000 | 0x400 | 0x200 | 0x100 | 0x80 | 0x40 | 0x20 | 0x10)
    el.add(".sec.user", 0x80000001, b"user", 0x7)
    el.add(".sec.unknown", 0x33, b"unk", 0x8)
    el.add(".sec.group", 17, b"\0\0\0\0", 0x200, entsize=4)
    # program headers
    secidx = {s["name"]: i for i, s in enumerate(el.secs)}
    el.ph(6, 4, raw=(el.ehsize, 0))                                                            # PHDR (size filled by hand)
    el.phdrs[-1]["raw"] = (el.ehsize, 7 * el.phentsize)
    el.ph(3, 4, sec=secidx[".interp"])                                                          # INTERP
    el.ph(1, 5, sec=secidx[".text"], vaddr=0x401000, paddr=0x401000)                            # LOAD R+X
    el.ph(1, 6, sec=secidx[".data"], vaddr=0x403000, paddr=0x403000, memsz=0x500)               # LOAD R+W
    el.ph(2, 6, sec=secidx[".dynamic"])                                                         # DYNAMIC
    el.ph(4, 4, sec=secidx[".note.gnu.build-id"])                                               # NOTE
    el.ph(7, 4, sec=secidx[".data"], memsz=0x20, align=8)                                       # TLS (overlaps .data)
    el.ph(0x6474e550, 4, sec=secidx[".eh_frame"])                                               # GNU_EH_FRAME (OS specific)
    el.ph(0x6474e551, 6, raw=(0, 0), align=16)                                                  # GNU_STACK, no data
    el.ph(0x70000001, 4, sec=secidx[".sec.proc"])                                               # processor specific
    el.ph(0x1234, 0xf0000000 | 0x0ff00000 | 0x7, sec=secidx[".sec.unknown"])                    # unknown, all flag bits
    el.ph(0, 0, raw=(0, 0))                                                                     # NULL
    # link the symbol tables
    el.secs[secidx[".symtab"]]["link"] = secidx[".strtab"]
    el.secs[secidx[".dynsym"]]["link"] = secidx[".dynstr"]
    sec_idx = secidx
    return el, el.build(entry=0x401000, flags=0x1)


# ------------------------------------------------------------------------------------
main_el, main = make(64, False, 62, etype=3, big_name=True)
open(os.path.join(out, "elf_coverage.elf"), "wb").write(main)

variants = []
el, b32 = make(32, False, 3, etype=2, variants="one")
variants.append(("32le", b32))
el, b32be = make(32, True, 20, etype=3, variants="all")
variants.append(("32be", b32be))
el, b64be = make(64, True, 22, etype=4, variants="all")
variants.append(("64be", b64be))
el, b32le_all = make(32, False, 40, etype=1, variants="all")        # ET_REL, ARM
variants.append(("32le-rel", b32le_all))


# HTTP pcap ----------------------------------------------------------------------
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.n = 0

    def http(self, data, ctype=None, url=b"/f"):
        self.n += 1
        sport = 40000 + self.n
        ct = (b"Content-Type: " + ctype + b"\r\n") if ctype else b""
        req = b"GET " + url + b" HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
        resp = (b"HTTP/1.1 200 OK\r\n" + ct + b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
        c, s = bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1])
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


# Reproducers of "ELF: Fix assertions, an endless loop and quadratic memory use" ---------
def ehdr32(shoff, shnum, shstrndx, phoff=0, phnum=0):
    ident = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\0" * 7
    return ident + struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0, phoff, shoff, 0, 52, 32, phnum, 40, shnum, shstrndx)


def shdr32(name, typ, off, size, entsize=0):
    return struct.pack("<IIIIIIIIII", name, typ, 0, 0, off, size, 0, 0, 1, entsize)


# e_phoff = 2^32 in a 64-bit file (value_guard used to assert)
ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
valueguard = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 1 << 32, 0, 0, 64, 56, 0, 64, 0, 0) + b"\0" * 64
# eh_frame_hdr whose table encoding is "omit" and whose count is huge (endless loop)
strtab = b"\0.shstrtab\0.eh_frame_hdr\0"
eh = bytes([1, 0x03, 0x04, 0xFF]) + struct.pack("<IQ", 0, 1 << 63)
off_str = 52
off_eh = off_str + len(strtab)
off_sh = off_eh + len(eh)
ehloop = (ehdr32(off_sh, 3, 1) + strtab + eh +
          shdr32(0, 0, 0, 0) + shdr32(1, 3, off_str, len(strtab)) + shdr32(11, 1, off_eh, len(eh)))


# K symbols naming one long string (quadratic memory before the fix; now names are cut at 256)
def strdup(L=600, K=40):
    small = b"\0.shstrtab\0.symtab\0.strtab\0"
    big_rel = len(small)
    strarea = small + b"A" * L + b"\0"
    syms = b"".join(struct.pack("<IIIBBH", big_rel, 0, 0, 0x12, 0, 0) for _ in range(K))
    off_sym = 52 + len(strarea)
    off_sh = off_sym + len(syms)
    sh = (shdr32(big_rel, 0, 0, 0) + shdr32(1, 3, 52, len(small)) + shdr32(11, 2, off_sym, len(syms), 16) +
          shdr32(19, 1, 52, 0))
    return ehdr32(off_sh, 4, 1) + strarea + syms + sh


p = Pcap()
# a fully valid file per variant, with every media type the dissector registers and no content type
p.http(b32, b"application/x-executable", b"/a.out")
p.http(b32be, b"application/x-sharedlib", b"/lib.so")
p.http(b64be, b"application/x-coredump", b"/core")
p.http(b32le_all, b"application/x-object", b"/o.o")
p.http(b32, None, b"/noct")                         # elf_http heuristic, no Content-Type
p.http(main, None, b"/main")  # the 64-bit LE main file over HTTP
p.http(strdup(), None, b"/strdup")                  # reproducer: names capped at 256 octets
p.http(ehloop, None, b"/ehloop")                    # reproducer: omitted table encoding, huge count
p.http(valueguard, None, b"/valueguard")            # reproducer: offset beyond INT_MAX (malformed)
p.write(os.path.join(out, "elf_coverage_http.pcap"))

# Malformed / odd files ---------------------------------------------------------------
m = Pcap()


def oddhdr(**kw):
    el, _ = make(32, False, 3, variants="one")
    for k, v in kw.items():
        setattr(el, k, v)
    return el.build()


# header oddities
for kw in ({"ident_class": 3}, {"ident_class": 0}, {"ident_data": 3}, {"ident_data": 0}, {"ehsize": 99},
           {"phentsize": 40}, {"shentsize": 48}):
    el, _ = make(32, False, 3, variants="one")
    for k, v in kw.items():
        setattr(el, k, v)
    try:
        m.http(el.build(), None, b"/odd")
    except Exception as ex:
        print("skip", kw, ex)
# eh_frame problems: CIE too short, segment larger than the CFI records, FDE before any CIE
for body in (struct.pack("<II", 8, 0) + b"\0" * 8,
             eh_frame("<") + b"\0" * 16,
             struct.pack("<I", 0xFFFFFFFF) + struct.pack("<Q", 1 << 20) + b"\0" * 16,
             fde("<", 0, 0, 1, 2) + struct.pack("<I", 0)):
    el = Elf(32, False, 2, 3)
    el.add(".eh_frame", 1, body, 2, align=4)
    m.http(el.build(), None, b"/eh")
# eh_frame_hdr with unusual table sizes, truncated
el = Elf(32, False, 2, 3)
el.add(".eh_frame_hdr", 1, bytes([1, 0x1b, 0x03, 0x3b]) + struct.pack("<II", 0, 1000), 2, align=4)
m.http(el.build(), None, b"/hdr1")
# eh_frame_hdr with a 1-byte count encoding (unsupported length)
el = Elf(32, False, 2, 3)
el.add(".eh_frame_hdr", 1, bytes([1, 0x1b, 0x05, 0x3b]) + struct.pack("<II", 0, 3), 2, align=4)
m.http(el.build(), None, b"/hdr2")
# a dynamic section whose entry size does not match and an entsize of 0
for ent in (0, 12):
    el = Elf(32, False, 2, 3)
    el.add(".dynamic", 6, b"\x01\0\0\0\x02\0\0\0" * 3, 3, entsize=ent)
    m.http(el.build(), None, b"/dyn")
# symbol table whose entry size is not 16, symbols with a name index beyond the table
el = Elf(32, False, 2, 3)
el.add(".strtab", 3, b"\0abc\0", 0)
el.add(".symtab", 2, struct.pack("<IIIBBH", 1, 0, 0, 0, 0, 0) * 2, 0, entsize=20)
m.http(el.build(), None, b"/sym")
# strtab without a final NUL
el = Elf(32, False, 2, 3)
el.add(".strtab", 3, b"abc", 0)
m.http(el.build(), None, b"/str")
# phdr and shdr tables beyond the data; sections beyond the end
el = Elf(64, False, 3, 62)
el.add(".text", 1, b"x" * 8, 6, size=0x10000000)
m.http(el.build(), None, b"/big")
el = Elf(64, False, 3, 62)
el.add(".text", 1, b"x" * 8, 6)
el.phoff_override = 0x7fffffff
m.http(el.build(), None, b"/phoff")
el = Elf(64, True, 3, 62)
el.add(".text", 1, b"x" * 8, 6)
el.shoff_override = 1 << 40
m.http(el.build(), None, b"/shoff")
# 64-bit dynamic tag above INT_MAX
el = Elf(64, False, 3, 62)
el.add(".dynamic", 6, struct.pack("<QQ", 1 << 40, 0), 3, entsize=16)
m.http(el.build(), None, b"/dyntag")
# shnum beyond the data, shstrndx beyond the table
el = Elf(32, False, 2, 3)
el.add(".text", 1, b"x" * 8, 6)
el.shnum_override = 300
m.http(el.build(), None, b"/shnum")
el = Elf(32, False, 2, 3)
el.add(".text", 1, b"x" * 8, 6)
el.shstrndx = 77
m.http(el.build(), None, b"/shstrndx")
# long names that run to the end of the file without a NUL (fewer than 256 octets left)
def endname():
    small = b"\0.shstrtab\0.symtab\0.strtab\0"
    syms = struct.pack("<IIIBBH", 0, 0, 0, 0x12, 0, 0) + struct.pack("<IIIBBH", 60, 0, 0, 0x12, 0, 0)
    sh_off = 52
    sh = shdr32(0, 0, 0, 0) + shdr32(1, 3, 52 + 160, len(small)) + shdr32(11, 2, 52 + 160 + len(small), len(syms), 16) + shdr32(19, 1, 52 + 160, 0)
    area = small + b"B" * 100          # the long name starts at offset 40 of the area, no NUL
    return ehdr32(sh_off, 4, 1) + sh + area[:0] + b"\0" * (160 - len(sh)) + small + syms + b"B" * 100
m.http(endname(), None, b"/endname")
# truncated file after the header
m.http(main[:100], None, b"/trunc")
m.http(b"\x7fELF" + b"\x01\x01\x01", b"application/x-executable", b"/tiny")
m.write(os.path.join(out, "elf_coverage_malformed.pcap"))
print(len(main), [len(v) for _, v in variants])
