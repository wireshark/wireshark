#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/erldp_old_tags.pcap: terms with the deprecated
tags that older or non-Erlang nodes may still send, a term on the local
format, and one with a tag no decoder knows. Each message follows a
distribution header with no atom cache references.

    Frame 1 - SEND_SENDER {22, FromPid, ToPid}, the node names as
              ATOM_EXT, then the message
              {'h\\xe9llo' (SMALL_ATOM_EXT, Latin-1), Ref (REFERENCE_EXT),
               done}
    Frame 2 - SEND_SENDER, then a LOCAL_EXT term: a hash and local data
    Frame 3 - SEND_SENDER, then {Unknown, done}, Unknown having tag 1

The atom 'done' after the deprecated tags shows that decoding kept in
step. Bytes are built by hand from erts/doc/guides/erl_ext_dist.md.
"""
import struct
import sys

CLIENT = (bytes((10, 0, 0, 1)), 40000)
SERVER = (bytes((10, 0, 0, 2)), 45000)

VERSION_MAGIC = 131
DIST_HEADER = b'D'
DOP_SEND_SENDER = 22


def atom(text):
    """SMALL_ATOM_UTF8_EXT"""
    return b'w' + bytes((len(text),)) + text


def old_atom(text):
    """ATOM_EXT (deprecated), Latin-1"""
    return b'd' + struct.pack('!H', len(text)) + text


def old_small_atom(text):
    """SMALL_ATOM_EXT (deprecated), Latin-1"""
    return b's' + bytes((len(text),)) + text


def small_int(val):
    """SMALL_INTEGER_EXT"""
    return b'a' + bytes((val,))


def pid(node, num, serial, creation):
    """NEW_PID_EXT"""
    return b'X' + node + struct.pack('!III', num, serial, creation)


def old_ref(node, ref_id, creation):
    """REFERENCE_EXT (deprecated)"""
    return b'e' + node + struct.pack('!IB', ref_id, creation)


def local(hash_, data):
    """LOCAL_EXT: a hash, then data only the encoding node understands"""
    return b'y' + struct.pack('!I', hash_) + data


def tuple_(*elems):
    """SMALL_TUPLE_EXT"""
    return b'h' + bytes((len(elems),)) + b''.join(elems)


def dist_msg(ctl, msg=b''):
    """A message after the handshake: a 4-byte length, a distribution
    header with no atom cache references, the control message and the
    message itself."""
    body = bytes((VERSION_MAGIC,)) + DIST_HEADER + b'\x00' + ctl + msg
    return struct.pack('!I', len(body)) + body


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
    path = sys.argv[1] if len(sys.argv) > 1 else 'erldp_old_tags.pcap'
    node_a = old_atom(b'a@127.0.0.1')
    node_b = old_atom(b'b@127.0.0.1')
    ctl = tuple_(small_int(DOP_SEND_SENDER), pid(node_a, 85, 0, 3), pid(node_b, 90, 0, 2))
    done = atom(b'done')

    s = Stream(CLIENT, SERVER)
    write_pcap(path, [
        s.frame(False, dist_msg(ctl, tuple_(old_small_atom(b'h\xe9llo'),
                                            old_ref(node_b, 0x2a, 2), done))),
        s.frame(False, dist_msg(ctl, local(0xc0ffee11, b'\x01\x02\x03\x04'))),
        s.frame(False, dist_msg(ctl, tuple_(b'\x01\x02\x03', done))),
    ])


if __name__ == '__main__':
    main()
