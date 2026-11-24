#!/usr/bin/env python3
# Generates test/captures/elcom_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ELCOM dissector
(packet-elcom.c, ELCOM-90 utility control centre communication).

ELCOM runs over TCP port 5997 (registered by default). Each message has
a 2 octet length (not counting itself) and a type: P-Connect request
and response (initiator and responder lower addresses, user data with
a control field and security information), P-Release request and
response, and P-Data request (test connection request and response
with a group and object names). Messages to port 5997 are requests.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkelcom.py <output directory>

Writes:
  elcom-coverage.pcap            every message type, every address and
                                 user data form, messages that end
                                 after each field, wrong lengths
  elcom-coverage-malformed.pcap  messages whose fields run past the end
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkt import LINKTYPE_ETHERNET, TcpFlow, ip4, write_pcap

PORT = 5997
CLIENT, SERVER = "192.0.2.10", "192.0.2.20"


def lower_address(port, ip, suffix=b"AB", endian=0x0002, first=0x82):
    """A 21 octet lower address: length 17, the IPv4 marker 0x82, the
    endian word, port, address, 8 zero octets, then the 2 octet
    suffix with its length."""
    v = bytes([first]) + struct.pack(">HH", endian, port) + ip4(ip) + b"\0" * 8
    return bytes([17]) + v + bytes([2]) + suffix


def control_field(y=126, mo=11, d=3, h=12, mi=30, s=45, ms=500):
    return struct.pack(">BBBBBBH", y, mo, d, h, mi, s, ms)


def userdata(pduid=0x04, version=0x13, result=0, restmark=0, cf=None,
             extra=b"", two_byte=False, length=None):
    body = bytes([pduid, version, result, restmark])
    body += (control_field() if cf is None else cf) + extra
    if length is None:
        length = len(body)
    if two_byte:
        return bytes([0, length]) + body
    return bytes([length]) + body


def message(mtype, body, length=None):
    if length is None:
        length = 1 + len(body)
    return struct.pack(">HB", length, mtype) + body


def connect(mtype, ini, resp, ud):
    return message(mtype, ini + resp + ud)


def main_frames():
    f = TcpFlow(CLIENT, SERVER, 40000, PORT)
    F = f.handshake()                                           # 1-3
    ini = lower_address(40000, CLIENT, b"AB")
    resp = lower_address(PORT, SERVER, b"BA")
    sec = b"\0\0\0\0" + bytes(range(0x10, 0x20))
    # 4: P-Connect request: big endian addresses, user data with a
    #    control field and security information
    F.append(f.data(True, connect(0x00, ini, resp,
                                  userdata(0x04, 0x13, 0, 0, extra=sec))))
    # 5: P-Connect response: little endian, user data length in 2 octets
    F.append(f.data(False, connect(0x10,
                                   lower_address(PORT, SERVER, b"AC", 0x0200),
                                   lower_address(40000, CLIENT, b"BD", 0x0200),
                                   userdata(0x05, 0x12, 0, 1,
                                            extra=b"\0\0\0\0", two_byte=True))))
    # 6: suffixes: an invalid first letter, an unknown second letter
    F.append(f.data(True, connect(0x00, lower_address(1, CLIENT, b"CE"),
                                  lower_address(2, SERVER, b"AZ"),
                                  userdata(0x04, 0x00))))
    # 7: suffixes E, F, G and a user data control field without the four
    #    octets after it
    F.append(f.data(True, connect(0x00, lower_address(1, CLIENT, b"BF"),
                                  lower_address(2, SERVER, b"AG"),
                                  userdata(0x04, 0x01, 0, 0,
                                           cf=control_field()[:7] + b"\x09"))))
    # 8: the initiator is not an IPv4 address (0x81): both addresses and
    #    the user data are read from the same place
    F.append(f.data(True, connect(0x00, lower_address(1, CLIENT, first=0x81),
                                  lower_address(2, SERVER, b"AD"),
                                  userdata(0x04, 0x02))))
    # 9: user data length 0 in both octets (invalid), the rest is left over
    F.append(f.data(True, connect(0x00, ini, resp, b"\0\0\x04\x13")))
    # 10: user data length above 79 (invalid)
    F.append(f.data(True, connect(0x00, ini, resp, b"\x50\x04\x13\x00")))
    # 11-12: user data that ends after the result and after the restart
    #        marking (a P-Connect message needs at least 4 octets of user
    #        data, so it cannot end earlier)
    full = userdata(0x04, 0x13)
    for n in (4, 5):
        F.append(f.data(True, connect(0x00, ini, resp, full[:n])))
    # 16: user data with the control field and no security information
    F.append(f.data(False, connect(0x10, resp, ini,
                                   userdata(0x05, 0x13, extra=b"\0\0\0\0"))))
    # 17: P-Connect request with a wrong message length
    F.append(f.data(True, message(0x00, ini + resp + userdata(), length=200)))
    # 18-23: P-Connect requests that the dissector does not accept (it
    #        returns after the Info column): too short, wrong initiator
    #        lengths, wrong responder lengths
    F.append(f.data(True, message(0x00, ini + resp[:20])))
    bad = bytearray(ini + resp + userdata())
    for pos, val in ((0, 16), (18, 3), (21, 16), (39, 3)):
        b = bytearray(bad)
        b[pos] = val
        F.append(f.data(True, message(0x00, bytes(b))))
    # 23: a P-Connect response with only the type
    F.append(f.data(False, message(0x10, b"")))
    # 24-25: P-Release request (reason 3) and response (result 0)
    F.append(f.data(True, message(0x20, b"\x03")))
    F.append(f.data(False, message(0x30, b"\x00")))
    # 26: P-Release request with octets left over
    F.append(f.data(True, message(0x20, b"\x01\xaa\xbb")))
    # 27: P-Data request: test connection request, group, two object
    #     names, then octets left over
    oids = b"\x04OBJ1" + b"\x07OBJECT2" + b"\x00"
    grp = struct.pack(">BBBHH", 7, 2, 10, 1, 20)
    F.append(f.data(True, message(0x80, b"\x40" + grp + oids + b"\xde\xad")))
    # 28: P-Data request: test connection response with a result, no
    #     object names and nothing after the terminating 0
    F.append(f.data(False, message(0x80, b"\x41\x00" + grp + b"\x00")))
    # 29: unknown group type
    F.append(f.data(True, message(0x80, b"\x42\x01\x02")))
    # 30-36: P-Data requests that end after each group field
    for n in (1, 2, 3, 4, 6, 8):
        F.append(f.data(True, message(0x80, (b"\x40" + grp)[:n])))
    F.append(f.data(True, message(0x80, b"")))
    # 37: an object name that runs to the end of the message
    F.append(f.data(True, message(0x80, b"\x40" + grp + b"\x09OBJ")))
    # 38: unknown message type
    F.append(f.data(True, message(0x55, b"\x01\x02")))
    # 39: only two octets (not ELCOM, handed to data)
    F.append(f.data(True, b"\x00\x01"))
    return F


def malformed_frames():
    f = TcpFlow(CLIENT, SERVER, 40001, PORT)
    F = f.handshake()
    # 4: P-Data request, test connection response without the result
    F.append(f.data(False, message(0x80, b"\x41")))
    # 5: the same with a wrong message length
    F.append(f.data(False, message(0x80, b"\x41", length=9)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "elcom-coverage.pcap"), main_frames(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "elcom-coverage-malformed.pcap"),
               malformed_frames(), LINKTYPE_ETHERNET)


if __name__ == "__main__":
    main()
