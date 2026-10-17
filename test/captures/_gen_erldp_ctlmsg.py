#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/erldp_ctlmsg.pcap: control messages added
in OTP 24 to 28, each after a distribution header with no atom cache
references.

    Frame 1 - ALIAS_SEND {33, FromPid, Alias}, then the message 'hello'
    Frame 2 - ALIAS_SEND_TT {34, FromPid, Alias, Token}, then 'hello'
    Frame 3 - UNLINK_ID {35, Id, FromPid, ToPid}
    Frame 4 - UNLINK_ID_ACK {36, Id, FromPid, ToPid}
    Frame 5 - ALTACT_SIG_SEND {37, PRIO|NAME, SenderPid, logger}, then 'hello'
    Frame 6 - ALTACT_SIG_SEND {37, ALIAS|TOKEN, SenderPid, Alias, Token},
              then 'hello'
    Frame 7 - ALTACT_SIG_SEND {37, EXIT, SenderPid, ToPid}, then the
              reason 'normal'

Bytes are built by hand from erts/doc/guides/erl_dist_protocol.md and
erl_ext_dist.md.
"""
import struct
import sys

CLIENT = (bytes((10, 0, 0, 1)), 40000)
SERVER = (bytes((10, 0, 0, 2)), 45000)

VERSION_MAGIC = 131
DIST_HEADER = b'D'

ALTACT_SIG_FLG_PRIO = 1
ALTACT_SIG_FLG_TOKEN = 2
ALTACT_SIG_FLG_ALIAS = 4
ALTACT_SIG_FLG_NAME = 8
ALTACT_SIG_FLG_EXIT = 16


def atom(text):
    """SMALL_ATOM_UTF8_EXT"""
    return b'w' + bytes((len(text),)) + text


def small_int(val):
    """SMALL_INTEGER_EXT"""
    return b'a' + bytes((val,))


def small_big(val):
    """SMALL_BIG_EXT, positive, little-endian digits"""
    digits = val.to_bytes((val.bit_length() + 7) // 8, 'little')
    return b'n' + bytes((len(digits), 0)) + digits


def pid(node, num, serial, creation):
    """NEW_PID_EXT"""
    return b'X' + atom(node) + struct.pack('!III', num, serial, creation)


def ref(node, creation, ids):
    """NEWER_REFERENCE_EXT"""
    return (b'Z' + struct.pack('!H', len(ids)) + atom(node)
            + struct.pack('!I', creation) + b''.join(struct.pack('!I', i) for i in ids))


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
    path = sys.argv[1] if len(sys.argv) > 1 else 'erldp_ctlmsg.pcap'
    a = pid(b'a@127.0.0.1', 85, 0, 0x5ca1ab1e)
    b = pid(b'b@127.0.0.1', 90, 0, 0x0b0e0d0a)
    alias = ref(b'b@127.0.0.1', 0x0b0e0d0a, (0x1d, 0x2e, 0x3f))
    # A sequential trace token: {Flags, Label, Serial, From, LastCnt}
    token = tuple_(small_int(6), small_int(1), small_int(2), a, small_int(1))
    unlink_id = 0x1122334455667788
    hello = atom(b'hello')

    s = Stream(CLIENT, SERVER)
    write_pcap(path, [
        s.frame(False, dist_msg(tuple_(small_int(33), a, alias), hello)),
        s.frame(False, dist_msg(tuple_(small_int(34), a, alias, token), hello)),
        s.frame(False, dist_msg(tuple_(small_int(35), small_big(unlink_id), a, b))),
        s.frame(True, dist_msg(tuple_(small_int(36), small_big(unlink_id), b, a))),
        s.frame(False, dist_msg(tuple_(small_int(37),
                                       small_int(ALTACT_SIG_FLG_PRIO | ALTACT_SIG_FLG_NAME),
                                       a, atom(b'logger')), hello)),
        s.frame(False, dist_msg(tuple_(small_int(37),
                                       small_int(ALTACT_SIG_FLG_ALIAS | ALTACT_SIG_FLG_TOKEN),
                                       a, alias, token), hello)),
        s.frame(False, dist_msg(tuple_(small_int(37), small_int(ALTACT_SIG_FLG_EXIT), a, b),
                                atom(b'normal'))),
    ])


if __name__ == '__main__':
    main()
