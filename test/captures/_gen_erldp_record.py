#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/erldp_record.pcap: OTP 29 native records sent
between two nodes, each after a distribution header with no atom cache
references.

    Frame 1 - SEND_SENDER {22, FromPid, ToPid}, then the message
              {#users:user{name = <<"joe">>, age = 42}, done}, the
              record exported
    Frame 2 - SEND_SENDER {22, FromPid, ToPid}, then the message
              {#shop:empty{}, done}, a record with no fields, not exported

The atom 'done' after each record shows that decoding kept in step.
Bytes are built by hand from erts/doc/guides/erl_ext_dist.md.
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


def small_int(val):
    """SMALL_INTEGER_EXT"""
    return b'a' + bytes((val,))


def binary(data):
    """BINARY_EXT"""
    return b'm' + struct.pack('!I', len(data)) + data


def pid(node, num, serial, creation):
    """NEW_PID_EXT"""
    return b'X' + atom(node) + struct.pack('!III', num, serial, creation)


def tuple_(*elems):
    """SMALL_TUPLE_EXT"""
    return b'h' + bytes((len(elems),)) + b''.join(elems)


def record(module, name, exported, fields):
    """RECORD_EXT: the field names first, then their values"""
    return (b'C' + struct.pack('!IB', len(fields), 1 if exported else 0)
            + atom(module) + atom(name)
            + b''.join(atom(k) for k, _ in fields)
            + b''.join(v for _, v in fields))


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
    path = sys.argv[1] if len(sys.argv) > 1 else 'erldp_record.pcap'
    a = pid(b'a@127.0.0.1', 85, 0, 0x5ca1ab1e)
    b = pid(b'b@127.0.0.1', 90, 0, 0x0b0e0d0a)
    ctl = tuple_(small_int(DOP_SEND_SENDER), a, b)
    user = record(b'users', b'user', True,
                  [(b'name', binary(b'joe')), (b'age', small_int(42))])
    empty = record(b'shop', b'empty', False, [])

    s = Stream(CLIENT, SERVER)
    write_pcap(path, [
        s.frame(False, dist_msg(ctl, tuple_(user, atom(b'done')))),
        s.frame(False, dist_msg(ctl, tuple_(empty, atom(b'done')))),
    ])


if __name__ == '__main__':
    main()
