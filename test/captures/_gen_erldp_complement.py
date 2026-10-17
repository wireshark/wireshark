#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/erldp_complement.pcap: a distribution handshake
started with the old name message, so the client completes it with a
complement message.

    Frame 1 - the client's old send_name ('n'): version 5, the low 32 bits
              of its flags
    Frame 2 - the server's status ('s') "ok"
    Frame 3 - the server's challenge ('N'): all its flags, a challenge,
              its creation and name
    Frame 4 - the client's complement ('c'): the high 32 bits of its
              flags (SPAWN, V4_NC, ALIAS, ALTACT_SIG, NATIVE_RECORDS) and
              its creation
    Frame 5 - the client's challenge reply ('r')
    Frame 6 - the server's challenge ack ('a')

Bytes are built by hand from erts/doc/guides/erl_dist_protocol.md.
"""
import struct
import sys

CLIENT = (bytes((10, 0, 0, 1)), 40000)
SERVER = (bytes((10, 0, 0, 2)), 45000)

DFLAG_PUBLISHED = 0x01
DFLAG_EXTENDED_REFERENCES = 0x04
DFLAG_DIST_MONITOR = 0x08
DFLAG_FUN_TAGS = 0x10
DFLAG_DIST_MONITOR_NAME = 0x20
DFLAG_NEW_FUN_TAGS = 0x80
DFLAG_EXTENDED_PIDS_PORTS = 0x100
DFLAG_EXPORT_PTR_TAG = 0x200
DFLAG_BIT_BINARIES = 0x400
DFLAG_NEW_FLOATS = 0x800
DFLAG_UTF8_ATOMS = 0x10000
DFLAG_MAP_TAG = 0x20000
DFLAG_BIG_CREATION = 0x40000
DFLAG_HANDSHAKE_23 = 0x1000000
DFLAG_UNLINK_ID = 0x2000000
DFLAG_MANDATORY_25_DIGEST = 0x4000000
DFLAG_SPAWN = 0x1 << 32
DFLAG_V4_NC = 0x4 << 32
DFLAG_ALIAS = 0x8 << 32
DFLAG_ALTACT_SIG = 0x20 << 32
DFLAG_NATIVE_RECORDS = 0x40 << 32

FLAGS = (DFLAG_PUBLISHED | DFLAG_EXTENDED_REFERENCES | DFLAG_DIST_MONITOR
         | DFLAG_FUN_TAGS | DFLAG_DIST_MONITOR_NAME | DFLAG_NEW_FUN_TAGS
         | DFLAG_EXTENDED_PIDS_PORTS | DFLAG_EXPORT_PTR_TAG
         | DFLAG_BIT_BINARIES | DFLAG_NEW_FLOATS | DFLAG_UTF8_ATOMS
         | DFLAG_MAP_TAG | DFLAG_BIG_CREATION | DFLAG_HANDSHAKE_23
         | DFLAG_UNLINK_ID | DFLAG_MANDATORY_25_DIGEST | DFLAG_SPAWN
         | DFLAG_V4_NC | DFLAG_ALIAS | DFLAG_ALTACT_SIG
         | DFLAG_NATIVE_RECORDS)


def handshake(tag, body):
    """A handshake message: a 2-byte length, the tag and its body."""
    return struct.pack('!H', 1 + len(body)) + tag + body


class Stream:
    """One TCP connection, keeping each direction's sequence number."""

    def __init__(self, client, server):
        self.ends = {False: client, True: server}
        self.seq = {False: 1000, True: 5000}

    def frame(self, from_server, payload):
        (src, sport), (dst, dport) = self.ends[from_server], self.ends[not from_server]
        eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
        # TCP: PSH|ACK, no options, checksum left 0 (not verified on read).
        tcp = struct.pack('!HHIIBBHHH', sport, dport, self.seq[from_server],
                          self.seq[not from_server], 5 << 4, 0x18, 65535, 0, 0)
        self.seq[from_server] += len(payload)
        total = 20 + len(tcp) + len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                         src, dst)
        return eth + ip + tcp + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, rec in enumerate(frames):
            f.write(struct.pack('!IIII', i, 0, len(rec), len(rec)))
            f.write(rec)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'erldp_complement.pcap'
    a_name, b_name = b'a@127.0.0.1', b'b@127.0.0.1'
    a_creation, b_creation = 0x5ca1ab1e, 0x0b0e0d0a
    digest = bytes(range(0x10, 0x20))

    s = Stream(CLIENT, SERVER)
    write_pcap(path, [
        s.frame(False, handshake(b'n', struct.pack('!HI', 5, FLAGS & 0xffffffff) + a_name)),
        s.frame(True, handshake(b's', b'ok')),
        s.frame(True, handshake(b'N', struct.pack('!QIIH', FLAGS, 0x8badf00d, b_creation,
                                                  len(b_name)) + b_name)),
        s.frame(False, handshake(b'c', struct.pack('!II', FLAGS >> 32, a_creation))),
        s.frame(False, handshake(b'r', struct.pack('!I', 0xdeadbeef) + digest)),
        s.frame(True, handshake(b'a', digest[::-1])),
    ])


if __name__ == '__main__':
    main()
