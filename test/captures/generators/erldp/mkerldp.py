#!/usr/bin/env python3
# Generates test/captures/erldp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic ErlDP (Erlang distribution protocol) coverage
# captures. Usage: mkerldp.py <outdir>
#
# ErlDP has no port of its own. As on a real network, each node looks
# the peer's distribution port up with EPMD (TCP port 4369) first: the
# EPMD PORT2_RESP makes a conversation on the returned port with the
# ErlDP dissector, so no Decode As is needed.
#
# Nothing here computes a real digest or challenge: those fields are
# fixed filler bytes.
import os
import struct
import sys

def write_pcap(fn, frames, linktype=1):
    with open(fn, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr)

def ip4(a):
    return bytes(int(x) for x in a.split("."))

class Tcp:
    """One TCP connection; frames are appended to a shared list."""
    def __init__(self, frames, cli, cport, srv, sport):
        self.frames = frames
        self.ep = {0: (cli, cport), 1: (srv, sport)}
        self.seq = {0: 1000, 1: 5000}
        self.syn()

    def _frame(self, d, payload, flags):
        (sa, sp), (da, dp) = self.ep[d], self.ep[1 - d]
        ack = 0 if flags == 0x02 else self.seq[1 - d]
        opts = struct.pack(">BBHBBBB", 2, 4, 65495, 4, 2, 1, 1) if flags & 0x02 else b""
        tcp = struct.pack(">HHIIBBHHH", sp, dp, self.seq[d], ack,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
                         ip4(sa), ip4(da))
        mac = lambda a: bytes.fromhex("0200000000") + bytes([ip4(a)[3]])
        self.frames.append(mac(da) + mac(sa) + b"\x08\x00" + ip + tcp)

    def syn(self):
        self.seq[0] -= 1; self.seq[1] -= 1
        self._frame(0, b"", 0x02)               # SYN
        self.seq[0] += 1
        self._frame(1, b"", 0x12)               # SYN/ACK
        self.seq[1] += 1
        self._frame(0, b"", 0x10)               # ACK

    def send(self, d, payload):
        self._frame(d, payload, 0x18)
        self.seq[d] += len(payload)

CLI, SRV = 0, 1

# --- External Term Format encoders -------------------------------------
def a(v): return b"a" + bytes([v])                          # SMALL_INTEGER_EXT
def i32(v): return b"b" + struct.pack(">i", v)               # INTEGER_EXT
def atom(s): return b"d" + struct.pack(">H", len(s)) + s     # ATOM_EXT
def atom_u(s): return b"v" + struct.pack(">H", len(s)) + s   # ATOM_UTF8_EXT
def satom(s): return b"s" + bytes([len(s)]) + s              # SMALL_ATOM_EXT
def satom_u(s): return b"w" + bytes([len(s)]) + s            # SMALL_ATOM_UTF8_EXT
def acr(n): return b"R" + bytes([n])                         # ATOM_CACHE_REF
def tup(*e): return b"h" + bytes([len(e)]) + b"".join(e)     # SMALL_TUPLE_EXT
def ltup(*e): return b"i" + struct.pack(">I", len(e)) + b"".join(e)
NIL = b"j"
def lst(*e, tail=NIL): return b"l" + struct.pack(">I", len(e)) + b"".join(e) + tail
def string(s): return b"k" + struct.pack(">H", len(s)) + s
def binary(b): return b"m" + struct.pack(">I", len(b)) + b
def bitbin(b, bits): return b"M" + struct.pack(">IB", len(b), bits) + b
def smallbig(n, neg=False, nbytes=None):
    raw = n.to_bytes(nbytes or max(1, (n.bit_length() + 7) // 8), "little")
    return b"n" + bytes([len(raw), 1 if neg else 0]) + raw
def largebig(n, neg=False, nbytes=None):
    raw = n.to_bytes(nbytes or max(1, (n.bit_length() + 7) // 8), "little")
    return b"o" + struct.pack(">IB", len(raw), 1 if neg else 0) + raw
def flt(s): return b"c" + s.ljust(31, b"\x00")              # FLOAT_EXT
def nflt(v): return b"F" + struct.pack(">d", v)              # NEW_FLOAT_EXT
def mp(*kv): return b"t" + struct.pack(">I", len(kv)) + b"".join(k + v for k, v in kv)

NODE_A = b"alpha@host1"
NODE_B = b"beta@host2"
def pid(node=NODE_A, n=81, s=0, c=0x5f3e9c1a):              # NEW_PID_EXT
    return b"X" + atom_u(node) + struct.pack(">III", n, s, c)
def oldpid(node=NODE_A, n=40, s=1, c=2):                    # PID_EXT
    return b"g" + atom(node) + struct.pack(">IIB", n, s, c)
def port(node=NODE_A, n=7, c=3): return b"f" + atom(node) + struct.pack(">IB", n, c)
def nport(node=NODE_A, n=8, c=0x11223344): return b"Y" + satom_u(node) + struct.pack(">II", n, c)
def v4port(node=NODE_A, n=0x0102030405060708, c=9): return b"x" + satom_u(node) + struct.pack(">QI", n, c)
def oldref(node=NODE_A): return b"e" + atom(node) + struct.pack(">IB", 0x123, 1)
def newref(node=NODE_A, ids=(1, 2, 3)):
    return b"r" + struct.pack(">H", len(ids)) + atom(node) + b"\x02" + b"".join(struct.pack(">I", x) for x in ids)
def newerref(node=NODE_A, ids=(0x10, 0x20, 0x30)):
    return b"Z" + struct.pack(">H", len(ids)) + atom_u(node) + struct.pack(">I", 0x5f3e9c1a) + b"".join(struct.pack(">I", x) for x in ids)
def export(m, f, ar): return b"q" + atom_u(m) + atom_u(f) + a(ar)
def fun_old(free):
    return b"u" + struct.pack(">I", len(free)) + pid() + atom_u(b"lists") + a(3) + a(77) + b"".join(free)
def newfun(free):
    body = (bytes([2]) + bytes(range(16)) + struct.pack(">I", 5) + struct.pack(">I", len(free))
            + atom_u(b"shell") + a(5) + i32(123456) + pid() + b"".join(free))
    return b"p" + struct.pack(">I", 4 + len(body)) + body
def record(mod, name, fields, flags=0x01):
    return (b"C" + struct.pack(">IB", len(fields), flags) + atom_u(mod) + atom_u(name)
            + b"".join(atom_u(k) for k, _ in fields) + b"".join(v for _, v in fields))
def local(rest): return b"y" + struct.pack(">I", 0xCAFEF00D) + rest

# --- ErlDP messages -----------------------------------------------------
def hs(tag, body): return struct.pack(">H", 1 + len(body)) + tag + body
def msg4(body): return struct.pack(">I", len(body)) + body
def passthrough(ctl, m=None):
    return msg4(b"p\x83" + ctl + (b"\x83" + m if m is not None else b""))

def dist_hdr_refs(refs, long_atoms=False):
    """refs: list of (segment_index, internal_index, atom text or None)."""
    n = len(refs)
    if n == 0:
        return b"\x00"
    nib = []
    for seg, _, txt in refs:
        nib.append((0x08 if txt is not None else 0) | (seg & 7))
    nib.append(0x01 if long_atoms else 0)
    flags = bytearray(n // 2 + 1)
    for k, v in enumerate(nib):
        flags[k // 2] |= v << (4 * (k % 2))
    out = bytes([n]) + bytes(flags)
    for _, idx, txt in refs:
        out += bytes([idx])
        if txt is not None:
            out += (struct.pack(">H", len(txt)) if long_atoms else bytes([len(txt)])) + txt
    return out

def dist(ctl, m=None, refs=(), long_atoms=False):
    return msg4(b"\x83D" + dist_hdr_refs(list(refs), long_atoms) + ctl + (m if m is not None else b""))

FLAGS6 = 0x17F0BFFFFFD   # bits 0-26 but 1, reserved bit 27, bits 32-38, spare bit 40
DIGEST = bytes(range(0x10, 0x20))

def epmd_lookup(frames, cli, srv, cport, name, port):
    t = Tcp(frames, cli, cport, srv, 4369)
    t.send(CLI, struct.pack(">H", 1 + len(name)) + b"z" + name)
    t.send(SRV, b"w\x00" + struct.pack(">HBBHHH", port, 77, 0, 6, 5, len(name)) + name + b"\x00\x00")

def main(out):
    f = []
    A, B, C = "192.0.2.1", "192.0.2.2", "192.0.2.3"

    # ---- Connection 1: OTP 23+ handshake (version 6 'N' messages) ----
    epmd_lookup(f, A, B, 40001, b"beta", 37001)
    t = Tcp(f, A, 40002, B, 37001)
    # send_name, version 6 flags, creation, name
    t.send(CLI, hs(b"N", struct.pack(">QIH", FLAGS6, 0x5f3e9c1a, len(NODE_A)) + NODE_A))
    t.send(SRV, hs(b"s", b"ok"))
    # send_challenge, version 6: flags, challenge, creation, name
    t.send(SRV, hs(b"N", struct.pack(">QIIH", FLAGS6, 0x01020304, 0x0a0b0c0d, len(NODE_B)) + NODE_B))
    t.send(CLI, hs(b"r", struct.pack(">I", 0x11223344) + DIGEST))
    t.send(SRV, hs(b"a", DIGEST[::-1]))
    # keep-alive tick
    t.send(CLI, msg4(b""))
    # pass-through SEND {2, '', Pid} with a message of every simple term
    t.send(CLI, passthrough(tup(a(2), atom(b""), pid(NODE_B, 90)),
                            tup(a(255), i32(-123456), atom(b"latin1"), atom_u("ütf8".encode()),
                                satom(b"small"), satom_u("smål".encode()), string(b"hello"),
                                NIL, lst(a(1), a(2)), lst(a(1), tail=a(2)))))
    # pass-through with only a control message (no message part)
    t.send(SRV, passthrough(tup(a(1), pid(NODE_B, 1), pid(NODE_A, 2))))
    # pass-through whose control message has no VERSION_MAGIC
    t.send(SRV, msg4(b"p\x00\x01\x02"))
    # unknown message type
    t.send(SRV, msg4(b"\x42\x00\x00"))
    # DIST_HEADER without atom cache refs: REG_SEND {6, From, '', ToName}
    # with integers, big numbers, floats, binaries
    t.send(CLI, dist(tup(a(6), pid(), atom_u(b""), atom_u(b"net_kernel")),
                     ltup(smallbig(0x12, nbytes=1), smallbig(0x1234, True, 2), smallbig(0x123456, nbytes=3),
                          smallbig(0x12345678, nbytes=4), smallbig(0x123456789A, True, 5),
                          smallbig(0x123456789ABC, nbytes=6), smallbig(0x123456789ABCDE, nbytes=7),
                          smallbig(0x123456789ABCDEF0, nbytes=8), smallbig(2**100 + 5),
                          largebig(2**70 + 1, True), largebig(2**600 + 3), smallbig(2**520 + 7),
                          flt(b"1.50000000000000000000e+00"), nflt(2.5),
                          binary(b"\x00\x01\x02binary"), binary(b""), bitbin(b"\xf0\x80", 1))))
    # DIST_HEADER with three atom cache refs: new short atoms, an old one
    t.send(CLI, dist(tup(a(2), acr(0), pid()),
                     tup(acr(1), acr(2), port(), nport(), v4port(), oldpid(),
                         oldref(), newref(), newerref()),
                     refs=[(0, 5, b"rex"), (1, 6, b"call"), (2, 7, None)]))
    # DIST_HEADER with long atoms (even number of refs)
    t.send(SRV, dist(tup(a(22), pid(NODE_B), pid(NODE_A)),
                     mp((atom_u(b"key"), a(1)), (binary(b"k2"), lst(a(3)))),
                     refs=[(3, 200, b"a_long_atom_name"), (4, 201, b"x")], long_atoms=True))
    # MONITOR_P, functions, export, records, LOCAL_EXT as the last term
    t.send(CLI, dist(tup(a(19), pid(), atom_u(b"server"), newerref()),
                     tup(export(b"lists", b"map", 2), fun_old([a(1), atom_u(b"free")]),
                         newfun([i32(7)]), fun_old([]),
                         record(b"mod", b"rec", [(b"f1", a(1)), (b"f2", string(b"v"))]),
                         record(b"mod", b"empty", [], flags=0xFE),
                         local(b"\x01\x02opaque"))))
    # LOCAL_EXT with nothing after its hash
    t.send(SRV, dist(tup(a(2), atom_u(b""), pid()), local(b"")))
    # SPAWN_REQUEST, a LARGE_TUPLE_EXT control message
    t.send(CLI, dist(tup(a(29), newref(), pid(), pid(),
                         tup(atom_u(b"erlang"), atom_u(b"apply"), a(2)), lst(atom_u(b"link")))))
    t.send(SRV, dist(ltup(a(31), newref(), pid(), a(0), pid(NODE_B))))
    # ALTACT_SIG_SEND {37, Flags, SenderPid, To} and {37, Flags, Sender, To, Token}
    t.send(CLI, dist(tup(a(37), a(0x1f), pid(), atom_u(b"to")), atom_u(b"msg")))
    t.send(CLI, dist(tup(a(37), a(0x02), pid(), pid(NODE_B), atom_u(b"token")), atom_u(b"msg")))
    # 37 with arity 3, and with flags as INTEGER_EXT (no flags bitmask)
    t.send(CLI, dist(tup(a(37), a(0), pid())))
    t.send(CLI, dist(tup(a(37), i32(1), pid(), atom_u(b"to"))))
    # control op not in the table, and a control message that is an atom
    t.send(CLI, dist(tup(a(99), NIL)))
    t.send(CLI, dist(atom_u(b"not_a_tuple")))
    # a tuple control message that does not start with a small integer,
    # and a SMALL_BIG_EXT of length 0
    t.send(CLI, dist(tup(i32(2), atom_u(b""), pid()), b"n\x00\x00"))
    # an unknown term tag (warning; the rest is shown as undecoded)
    t.send(SRV, dist(tup(a(2), atom_u(b""), pid()), tup(a(1), b"\xee\x01\x02\x03")))
    # unknown tag directly after the DIST_HEADER
    t.send(SRV, dist(b"\xee"))
    # an unknown distribution header tag (only the header is shown)
    t.send(SRV, msg4(b"\x83Q\x00\x00"))
    # the reproducer of "ErlDP: Check binary and bignum lengths ...",
    # frame 4 of erldp_misc.py: DIST_HEADER with 255 atom cache refs
    n = 255
    flags = bytes([0x99] * (n // 2 + 1))
    refs = b""
    for k in range(n):
        refs += bytes([k & 7])
        if (0x99 >> (4 * (k % 2))) & 0x08:
            refs += struct.pack(">H", 3) + b"abc"
    t.send(SRV, msg4(b"\x83D" + bytes([n]) + flags + refs + b"h\x02a\x02a\x05" + b"j"))
    # two messages in one segment
    t.send(CLI, dist(tup(a(1), pid(), pid(NODE_B))) + dist(tup(a(4), pid(), pid(NODE_B))))
    # one message split over two segments
    big = dist(tup(a(2), atom_u(b""), pid(NODE_B)), binary(bytes(range(256)) * 2))
    t.send(CLI, big[:300])
    t.send(CLI, big[300:])
    # a message of more than 64 KiB in 49 segments (the first two octets of
    # its length are not 0, so the handshake check looks at the tag)
    huge = dist(tup(a(2), atom_u(b""), pid(NODE_B)), binary(bytes(70000)))
    for k in range(0, len(huge), 1448):
        t.send(CLI, huge[k:k + 1448])
    # fragmented message: DIST_FRAG_HEADER (fragment 3), two DIST_FRAG_CONT
    whole = (dist_hdr_refs([(0, 9, b"frag")]) + tup(a(6), pid(), atom_u(b""), acr(0))
             + tup(atom_u(b"fragmented"), binary(bytes(range(120)))))
    seqid = 0x0102030405060708
    parts = [whole[:40], whole[40:100], whole[100:]]
    t.send(CLI, msg4(b"\x83E" + struct.pack(">QQ", seqid, 3) + parts[0]))
    t.send(CLI, msg4(b"\x83F" + struct.pack(">QQ", seqid, 2) + parts[1]))
    t.send(CLI, msg4(b"\x83F" + struct.pack(">QQ", seqid, 1) + parts[2]))
    # a message in a single fragment (fragment ID 1)
    one = dist_hdr_refs([]) + tup(a(2), atom_u(b""), pid(NODE_B)) + atom_u(b"single")
    t.send(SRV, msg4(b"\x83E" + struct.pack(">QQ", 77, 1) + one))
    # a fragment header with no data after the fragment ID
    t.send(SRV, msg4(b"\x83E" + struct.pack(">QQ", 78, 1)))

    # ---- Connection 2: older handshake (version 5 'n' messages) ----
    epmd_lookup(f, C, B, 40003, b"beta", 37001)
    t = Tcp(f, C, 40004, B, 37001)
    # send_name, version 5, flags, name
    t.send(CLI, hs(b"n", struct.pack(">HI", 5, 0x0003FFFD) + b"gamma@host3"))
    t.send(SRV, hs(b"s", b"ok_simultaneous"))
    # send_challenge, version 5: flags, challenge, name
    t.send(SRV, hs(b"n", struct.pack(">HII", 5, 0x0007FFFD, 0x8899AABB) + NODE_B))
    # send_complement: high flags, creation
    t.send(CLI, hs(b"c", struct.pack(">II", 0x7F, 0x00C0FFEE)))
    t.send(CLI, hs(b"r", struct.pack(">I", 0x55667788) + DIGEST))
    t.send(SRV, hs(b"a", DIGEST))
    # send_name, version 5, with a short name (no challenge check)
    t.send(CLI, hs(b"n", struct.pack(">HI", 5, 0x4) + b"g@h"))
    t.send(CLI, dist(tup(a(8), pid(), pid(NODE_B), atom_u(b"normal"))))

    # ---- Connection 3: the second reproducer of the same fix (frame 3 of
    # erldp_misc.py): a PDU with tag 0 at the handshake position. Before
    # the fix strchr() matched the terminating NUL and it was taken as a
    # handshake message; now it is the start of a long message that never
    # completes, so only TCP shows it.
    epmd_lookup(f, C, B, 40005, b"beta", 37001)
    t = Tcp(f, C, 40006, B, 37001)
    t.send(CLI, b"\x00\x03\x00AB")

    write_pcap(os.path.join(out, "erldp-coverage.pcap"), f)

    # ---- malformed capture ----
    m = []
    epmd_lookup(m, A, B, 41001, b"beta", 37002)
    t = Tcp(m, A, 41002, B, 37002)
    # frame 1 of erldp_misc.py: 6000 nested tuples (dissection depth limit)
    t.send(CLI, msg4(b"p\x83" + b"h\x01" * 6000 + b"j"))
    # frame 2 of erldp_misc.py (the reproducer of the binary length fix):
    # BINARY_EXT and LARGE_BIG_EXT with length 0xFFFFFFFF in a list
    t.send(CLI, msg4(b"p\x83" + b"l" + struct.pack(">I", 3) + b"m" + struct.pack(">I", 0xFFFFFFFF)
                     + b"o" + struct.pack(">I", 0xFFFFFFFF) + b"\x00" + b"jjjj" + b"j"))
    # BIT_BINARY_EXT with length 0xFFFFFFFF
    t.send(CLI, msg4(b"p\x83" + b"M" + struct.pack(">IB", 0xFFFFFFFF, 3) + b"\x00"))
    # LARGE_BIG_EXT with length 0xFFFFFFFF on its own
    t.send(CLI, msg4(b"p\x83" + b"o" + struct.pack(">I", 0xFFFFFFFF) + b"\x00\x01"))
    # truncated terms: atom, tuple, pid, float, new_fun, record
    for term in (atom(b"abcdef")[:-2], tup(a(1), a(2))[:-1], pid()[:-3], flt(b"1.0")[:10],
                 newfun([])[:20], record(b"m", b"r", [(b"f", a(1))])[:-1]):
        t.send(SRV, msg4(b"p\x83" + term))
    # DIST_HEADER whose atom cache refs run off the end
    t.send(SRV, msg4(b"\x83D\x02\x88\x00\x01\x05ab"))
    # handshake messages cut short ('r' and 'a' without the digest, 'c')
    t.send(CLI, hs(b"r", b"\x00\x00"))
    t.send(SRV, hs(b"a", b"\x01" * 4))
    t.send(CLI, hs(b"c", b"\x00"))
    t.send(CLI, hs(b"N", struct.pack(">Q", 1)))
    # two handshake messages in one segment: the length check of the
    # handshake test fails, so they are taken as the start of a long
    # message that never completes (shown as TCP only); each connection
    # is announced by EPMD, as on a real network
    epmd_lookup(m, A, B, 41005, b"beta", 37002)
    t = Tcp(m, A, 41003, B, 37002)
    t.send(CLI, hs(b"s", b"ok") + hs(b"a", DIGEST))
    epmd_lookup(m, A, B, 41006, b"beta", 37002)
    t = Tcp(m, A, 41004, B, 37002)
    # fragmented message whose reassembled data is truncated
    t.send(CLI, msg4(b"\x83E" + struct.pack(">QQ", 5, 2) + b"\x01\x08\x01"))
    t.send(CLI, msg4(b"\x83F" + struct.pack(">QQ", 5, 1) + b"\x05ab"))
    write_pcap(os.path.join(out, "erldp-coverage-malformed.pcap"), m)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
