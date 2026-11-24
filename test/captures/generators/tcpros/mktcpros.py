#!/usr/bin/env python3
# Generates test/captures/tcpros_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-tcpros.c.  Usage: mktcpros.py <outdir>
Writes tcpros-coverage.pcapng(.gz), tcpros_coverage.pcapng.gz and
tcpros-coverage-malformed.pcapng.

TCPROS has no port and its TCP heuristic is disabled by default, so the
PDUs of the main capture are Exported PDU frames naming "tcpros" (interface 1).
Interface 0 holds the same kind of data in TCP streams (ROS port 11311), which
need `--enable-heuristic tcpros_tcp` or Decode As and are used for the TCP
reassembly (tcpros.desegment_tcpros_messages)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import gzip
import shutil
import util as u

LT_ETH, LT_EXPPDU = 1, 252


def pcapng(path, frames):
    """frames: list of (interface, bytes)"""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_EXPPDU, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def exported_pdu(payload, name='tcpros'):
    n = name.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return (1, struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload)


# ---------------------------------------------------------------- TCPROS
def conn_header(fields):
    """fields: list of bytes ('name=value' or anything)"""
    body = b''.join(struct.pack('<I', len(f)) + f for f in fields)
    return struct.pack('<I', len(body)) + body


def ros_msg(seq, sec, nsec, frame, payload):
    """4-byte length + seq + stamp + frame id (length + string) + payload"""
    frame = frame.encode() if isinstance(frame, str) else frame
    body = struct.pack('<III', seq, sec, nsec) + struct.pack('<I', len(frame)) + frame + payload
    return struct.pack('<I', len(body)) + body


def ros_clock(sec, nsec):
    return struct.pack('<III', 8, sec, nsec)


PUB = [b'callerid=/talker', b'topic=/chatter', b'type=std_msgs/String',
       b'md5sum=992ce8a1687cec8c8bd883ec73ca41d1', b'message_definition=string data\n',
       b'latching=0', b'tcp_nodelay=1']
SUB = [b'callerid=/listener', b'topic=/chatter', b'type=std_msgs/String',
       b'md5sum=992ce8a1687cec8c8bd883ec73ca41d1', b'tcp_nodelay=1']
SRV = [b'callerid=/client', b'service=/add_two_ints', b'md5sum=6a2e34150c00229791cc89ff309fff21',
       b'persistent=1', b'probe=1']
PAYLOAD = struct.pack('<I', 13) + b'hello, world!'


def main_frames():
    f = []
    # ---- Exported PDU: every kind of PDU TCPROS tells apart
    f.append(exported_pdu(conn_header(PUB)))                    # connection header (length > first field)
    f.append(exported_pdu(conn_header(SUB)))
    f.append(exported_pdu(conn_header(SRV)))
    f.append(exported_pdu(ros_clock(1700000000, 123456789)))    # ROS Clock
    f.append(exported_pdu(ros_clock(0, 0)))
    f.append(exported_pdu(ros_msg(1, 1700000000, 5, 'base_link', PAYLOAD)))    # ROS message with a Header
    f.append(exported_pdu(ros_msg(2, 1700000001, 999999999, '', PAYLOAD)))       # empty frame id
    f.append(exported_pdu(ros_msg(3, 0, 0, 'map', b'')))                          # no payload
    f.append(exported_pdu(ros_msg(4, 5, 6, 'a' * 200, b'\x01' * 300)))
    # several PDUs in one: header, message, clock, message
    f.append(exported_pdu(conn_header(SUB) + ros_msg(5, 1, 2, 'odom', PAYLOAD) + ros_clock(7, 8) +
                          ros_msg(6, 3, 4, 'odom', PAYLOAD)))
    # connection header fields in all forms: empty value, no value, no name, no separator
    f.append(exported_pdu(conn_header([b'callerid=/x', b'empty=', b'=noname', b'a=b=c', b'topic=/t'])))
    f.append(exported_pdu(conn_header([b'a=1'])))
    # Reproducer of "TCPROS: Do not split a connection header field without separator":
    # "abcde" has no "=" (and is entirely alphanumeric, so it passes is_rosconnection_header)
    f.append(exported_pdu(struct.pack('<I', 9) + struct.pack('<I', 5) + b'abcde'))
    # its control with a separator
    f.append(exported_pdu(struct.pack('<I', 11) + struct.pack('<I', 7) + b'abcde=1'))
    # an alphanumeric first field followed by one with a separator
    f.append(exported_pdu(conn_header([b'abcde', b'topic=/chatter'])))
    f.append(exported_pdu(conn_header([b'abc', b'def=1'])))
    # message whose first fields look like a ROS message (is_rosmsg) with a frame id
    f.append(exported_pdu(ros_msg(7, 8, 9, 'x', b'\x00' * 4)))

    # ---- TCP streams (interface 0), port 11311
    o = []
    def flow(cport, items, seg=None):
        c = u.Conn(o, cport, 11311)
        for it in items:
            d, data = it[0], it[1]
            n = it[2] if len(it) > 2 else seg
            if d == 'c':
                c.send(data) if n is None else c.csegs(data, n)
            else:
                c.recv(data) if n is None else c.ssegs(data, n)
        c.fin()
    flow(41000, [('s', ros_clock(99, 1)), ('c', conn_header(SUB)), ('s', conn_header(PUB)),
                 ('s', ros_msg(1, 100, 1, 'base_link', PAYLOAD)),
                 ('s', ros_msg(2, 100, 2, 'base_link', PAYLOAD) + ros_msg(3, 100, 3, 'base_link', PAYLOAD)),
                 ('s', ros_msg(4, 100, 4, 'base_link', PAYLOAD * 5), 30),         # one message in several segments
                 ('s', ros_clock(100, 5)),
                 ('c', conn_header(SRV)),
                 ('s', ros_msg(5, 100, 6, 'odom', PAYLOAD)[:7]),                    # a length split from its message
                 ('s', ros_msg(5, 100, 6, 'odom', PAYLOAD)[7:])])
    flow(41001, [('c', struct.pack('<I', 9) + struct.pack('<I', 5) + b'abcde')])  # the reproducer over TCP
    # a stream that starts with a ROS message (the heuristic takes it as one)
    flow(41003, [('s', ros_msg(1, 2, 3, 'tf', PAYLOAD)), ('c', conn_header(SUB))])
    # TCP payloads the heuristic rejects (too short, not a clock, a header or a message)
    for i, junk in enumerate((b'\x00' * 4, struct.pack('<II', 7, 0x7a7a7a7a), struct.pack('<III', 9, 1, 2),
                              struct.pack('<I', 10) + b'\x01' * 20,
                              struct.pack('<I', 40) + struct.pack('<III', 1, 2, 3) + struct.pack('<I', 100) + b'\x01' * 20,
                              struct.pack('<I', 5) + b'ab-de', b'\xde\xad\xbe\xef' * 6)):
        flow(41010 + i, [('c', junk)])
    return f, o


def malformed_frames():
    f = []
    P = lambda b: f.append(exported_pdu(b))
    # truncated PDUs of every kind (Exported PDU has no reassembly: TCPROS asks for more data)
    full = conn_header(PUB)
    for n in (1, 3, 4, 5, 7, 8, 12, 20, 50, len(full) - 1):
        P(full[:n])
    msg = ros_msg(1, 2, 3, 'frame', PAYLOAD)
    for n in (4, 8, 12, 19, 20, 24, 28, len(msg) - 1):
        P(msg[:n])
    P(ros_clock(1, 2)[:8])
    P(ros_clock(1, 2) + b'\0')
    # a header field longer than the header, a header longer than its data
    P(struct.pack('<I', 12) + struct.pack('<I', 200) + b'a=b' + b'\0' * 5)
    P(struct.pack('<I', 400) + struct.pack('<I', 5) + b'a=bcd')
    P(struct.pack('<I', 8) + struct.pack('<I', 4) + b'a=bc' + b'\x03\x00')           # trailing bytes, not a field
    P(struct.pack('<I', 8) + struct.pack('<I', 4) + b'a=bc' + b'\x00\x00\x00')
    P(struct.pack('<I', 4) + struct.pack('<I', 0))                                    # empty field
    P(struct.pack('<I', 0))
    P(struct.pack('<I', 8) + struct.pack('<I', 0) + struct.pack('<I', 0))
    # a frame id longer than the message, a message shorter than its Header
    P(ros_msg(1, 2, 3, 'x', b'')[:16] + struct.pack('<I', 100) + b'abc')
    P(struct.pack('<I', 12) + struct.pack('<III', 1, 2, 3) + struct.pack('<I', 0))
    P(struct.pack('<I', 16) + struct.pack('<IIII', 1, 2, 3, 0) + b'\0' * 4)
    P(struct.pack('<I', 20) + struct.pack('<III', 1, 2, 3) + struct.pack('<I', 4) + b'abcd' + b'\0' * 4)
    P(struct.pack('<I', 0xffffffff) + b'\0' * 30)
    P(struct.pack('<I', 5) + b'\0' * 30)                                              # small length, large data
    P(struct.pack('<I', 30) + struct.pack('<I', 40) + b'\0' * 30)
    # PDUs that are neither: message header read beyond the data (the final else branch)
    P(struct.pack('<I', 12) + struct.pack('<I', 50) + b'\0' * 12)
    P(struct.pack('<I', 12) + struct.pack('<I', 50) + b'\0' * 16)
    P(struct.pack('<I', 12) + struct.pack('<I', 4) + b'\0' * 16)
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pdus, tcp = main_frames()
    # PDUs first so that the interesting frames come early
    frames = pdus + [(0, fr) for fr in tcp]
    base = os.path.join(out, 'tcpros-coverage.pcapng')
    pcapng(base, frames)
    with open(base, 'rb') as fh:
        d = fh.read()
    with open(base + '.gz', 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))
    shutil.copy(base + '.gz', os.path.join(out, 'tcpros_coverage.pcapng.gz'))
    pcapng(os.path.join(out, 'tcpros-coverage-malformed.pcapng'), malformed_frames())
    print('%d frames, %d malformed-capture frames' % (len(frames), len(malformed_frames())))


if __name__ == '__main__':
    main()
