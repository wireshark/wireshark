#!/usr/bin/env python3
# Generates test/captures/rsync_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RSYNC daemon captures (TCP port 873). Usage: mkrsync.py <outdir>
import struct
import sys
import os

class Conn:
    def __init__(self, cport, sport=873, cip=(192,0,2,1), sip=(192,0,2,2)):
        self.cport, self.sport = cport, sport
        self.cip, self.sip = bytes(cip), bytes(sip)
        self.cseq, self.sseq = 1000, 5000
        self.frames = []
        self.id = 1

    def _pkt(self, src, dst, sp, dp, seq, ack, flags, data):
        tcp = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), self.id, 0x4000, 64, 6, 0, src, dst)
        self.id += 1
        s = 0
        for i in range(0, 20, 2):
            s += (ip[i] << 8) | ip[i+1]
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        ip = ip[:10] + struct.pack(">H", (~s) & 0xffff) + ip[12:]
        eth = bytes.fromhex("020000000002020000000001") + b"\x08\x00"
        if src == self.cip:
            eth = bytes.fromhex("020000000002020000000001") + b"\x08\x00"
        else:
            eth = bytes.fromhex("020000000001020000000002") + b"\x08\x00"
        return eth + ip + tcp

    def syn(self):
        self.frames.append(self._pkt(self.cip, self.sip, self.cport, self.sport, self.cseq, 0, 0x02, b""))
        self.cseq += 1
        self.frames.append(self._pkt(self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq, 0x12, b""))
        self.sseq += 1
        self.frames.append(self._pkt(self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq, 0x10, b""))

    def c(self, data):
        self.frames.append(self._pkt(self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq, 0x18, data))
        self.cseq += len(data)

    def s(self, data):
        self.frames.append(self._pkt(self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq, 0x18, data))
        self.sseq += len(data)

def write(fname, frames):
    with open(fname, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, d in enumerate(frames):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(d), len(d)))
            f.write(d)

def main(out):
    frames = []
    # 1) Module list session: version exchange, MOTD (twice), query "\n",
    #    module list in two parts, the final part ends with the EXIT line,
    #    then data in both directions.
    c = Conn(40001); c.syn()
    c.s(b"@RSYNCD: 31.0\n")
    c.c(b"@RSYNCD: 31.0\n")
    c.s(b"Welcome to the synthetic rsync server\n")
    c.s(b"Authorised use only\n")
    c.c(b"\n")
    c.s(b"pub\tPublic files\nbackup\tBackups\n")
    c.s(b"home\tHome directories\n@RSYNCD: EXIT\n")
    c.s(b"\x00\x01\x02\x03unexpected data after the list")
    c.c(b"\x00\x01\x02\x03")       # client state is COMMAND here
    frames += c.frames

    # 2) Module access with authentication: query "pub", server answers with
    #    DATA state (no module list), client commands follow.
    c = Conn(40002); c.syn()
    c.s(b"@RSYNCD: 30.0\n")
    c.c(b"@RSYNCD: 30.0")          # no trailing newline
    c.c(b"pub\n")                 # query -> server state DATA
    c.s(b"@RSYNCD: OK\n")          # server data
    c.c(b"--server\n")             # client command
    c.c(b"--sender\n")
    c.c(b"-vlogDtpre.iLsfxC\n")
    c.c(b".\n")
    c.s(bytes(range(32)))          # more server data
    frames += c.frames

    # 3) Module list query followed by authentication request
    c = Conn(40003); c.syn()
    c.s(b"@RSYNCD: 27.0\n")
    c.c(b"@RSYNCD: 27.0\n")
    c.s(b"MOTD line\n")
    c.c(b"\n")
    c.s(b"@RSYNCD: AUTHREQD abcdefghijklmnop\n")
    c.c(b"user 0123456789abcdef\n")   # client command
    c.s(b"@RSYNCD: OK\n")             # server DATA
    frames += c.frames

    # 4) Module list that never ends with EXIT: longer than the EXIT
    #    string but with other text at the end
    c = Conn(40004); c.syn()
    c.s(b"@RSYNCD: 29.0\n")
    c.c(b"@RSYNCD: 29.0\n")
    c.c(b"\n")
    c.s(b"module-one\tFirst module comment text\n")
    c.s(b"short\n")
    c.s(b"a-very-long-module-listing-line-without-the-end\n")
    frames += c.frames

    # 5) Reproducer-like edge cases of the version header: a version without a
    #    minor number, and CRLF
    c = Conn(40005); c.syn()
    c.s(b"@RSYNCD: 31\n")
    c.c(b"@RSYNCD: 31.0\r\n")
    c.c(b"mod\r\n")
    c.s(b"\x00")
    frames += c.frames

    # 6) A server that talks first on a different client port with the
    #    client sending first (no SYN seen): client frame in INIT state
    c = Conn(40006)
    c.c(b"@RSYNCD: 31.0\n")
    c.s(b"@RSYNCD: 31.0\n")
    frames += c.frames

    write(os.path.join(out, "rsync-coverage.pcap"), frames)

    # Malformed: packets too short for the string compare / header
    m = []
    c = Conn(40010); c.syn()
    c.s(b"@RSYNCD: 31.0\n")
    c.c(b"@RSYNCD")                  # shorter than the version header
    c.c(b"\n")
    c.s(b"x\n")                      # shorter than AUTHREQD in MODULE_LIST state
    m += c.frames
    c = Conn(40011); c.syn()
    c.s(b"@RSYNC")                   # server version header, truncated
    m += c.frames
    c = Conn(40012); c.syn()
    c.s(b"@RSYNCD: ")                # magic and space, no version at all
    m += c.frames
    write(os.path.join(out, "rsync-coverage-malformed.pcap"), m)

if __name__ == "__main__":
    os.makedirs(sys.argv[1], exist_ok=True)
    main(sys.argv[1])
