#!/usr/bin/env python3
# Generates test/captures/sparkplug_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic SparkplugB over MQTT captures. Usage: mksparkplug.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib_s9 import Stream, write_pcap

PORT = 1883


# ---- protobuf helpers (Sparkplug B Payload) ----
def varint(v):
    out = b''
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def pb_varint(f, v):
    return varint(f << 3) + varint(v)


def pb_bytes(f, b):
    return varint(f << 3 | 2) + varint(len(b)) + b


def metric(name, dtype, **kw):
    m = pb_bytes(1, name.encode())
    if 'alias' in kw:
        m += pb_varint(2, kw['alias'])
    m += pb_varint(3, 1700000000000)
    m += pb_varint(4, dtype)
    if 'int' in kw:
        m += pb_varint(10, kw['int'])
    if 'long' in kw:
        m += pb_varint(11, kw['long'])
    if 'float' in kw:
        m += varint(12 << 3 | 5) + struct.pack('<f', kw['float'])
    if 'double' in kw:
        m += varint(13 << 3 | 1) + struct.pack('<d', kw['double'])
    if 'bool' in kw:
        m += pb_varint(14, int(kw['bool']))
    if 'string' in kw:
        m += pb_bytes(15, kw['string'].encode())
    return m


def payload(seq, metrics):
    p = pb_varint(1, 1700000000000)
    for m in metrics:
        p += pb_bytes(2, m)
    return p + pb_varint(3, seq)


# ---- MQTT ----
def remlen(n):
    out = b''
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def mstr(s):
    s = s.encode() if isinstance(s, str) else s
    return struct.pack('!H', len(s)) + s


def connect(clientid, level=4):
    var = mstr('MQTT') + bytes([level, 0x02]) + struct.pack('!H', 60)
    if level == 5:
        var += b'\x00'
    var += mstr(clientid)
    return b'\x10' + remlen(len(var)) + var


def connack(level=4):
    var = b'\x00\x00' + (b'\x00' if level == 5 else b'')
    return b'\x20' + remlen(len(var)) + var


def publish(topic, body=b'', qos=0, pid=1, level=4, retain=0):
    var = mstr(topic)
    if qos:
        var += struct.pack('!H', pid)
    if level == 5:
        var += b'\x00'
    var += body
    return bytes([0x30 | (qos << 1) | retain]) + remlen(len(var)) + var


def main(out):
    s = Stream('192.0.2.10', 41000, '192.0.2.20', PORT)
    s.hs()
    s.send(connect('edge1'))
    s.recv(connack())
    seq = 0
    # Edge node: birth, data, device birth and data with and without a device
    nbirth = payload(0, [metric('bdSeq', 8, long=1, alias=1),
                         metric('Node Control/Rebirth', 11, bool=False),
                         metric('Properties/Hardware', 12, string='synthetic')])
    s.send(publish('spBv1.0/grp1/NBIRTH/node1', nbirth, qos=1, pid=1))
    s.recv(b'\x40\x02\x00\x01')
    s.send(publish('spBv1.0/grp1/NDATA/node1', payload(1, [metric('Temp', 9, float=21.5, alias=2)])))
    s.send(publish('spBv1.0/grp1/DBIRTH/node1/dev1',
                   payload(2, [metric('Speed', 7, int=1200), metric('Torque', 10, double=3.25)])))
    s.send(publish('spBv1.0/grp1/DDATA/node1/dev1', payload(3, [metric('Speed', 7, int=1300)])))
    s.send(publish('spBv1.0/grp1/DDEATH/node1/dev1', payload(4, [])))
    s.send(publish('spBv1.0/grp1/NDEATH/node1', payload(5, [metric('bdSeq', 8, long=1)])))
    # Commands to a node and to a device (published by a host)
    s.send(publish('spBv1.0/grp1/NCMD/node1', payload(6, [metric('Node Control/Rebirth', 11, bool=True)])))
    s.send(publish('spBv1.0/grp1/DCMD/node1/dev1', payload(7, [metric('Speed', 7, int=0)])))
    # more than five elements: the rest of the topic stays in the last one
    s.send(publish('spBv1.0/grp1/DDATA/node1/dev1/extra/more', payload(8, [metric('X', 14, bool=True)])))
    # an empty payload and a retained message
    s.send(publish('spBv1.0/grp1/NDATA/node2', b'', retain=1))
    # not Sparkplug: other topics, a topic starting with the namespace only as a prefix
    s.send(publish('factory/line1/temp', b'21.5'))
    s.send(publish('spBv1.00/grp1/NDATA/node1', b'\x08\x01'))
    s.send(publish('SpBv1.0/grp1/NDATA/node1', b'\x08\x01'))
    # STATE messages of the primary application are plain MQTT (JSON)
    s.send(publish('STATE/host1', b'{"online":true}', retain=1))

    # MQTT v5: a PUBLISH with a property length
    s5 = Stream('192.0.2.11', 41001, '192.0.2.20', PORT)
    s5.hs()
    s5.send(connect('edge5', 5))
    s5.recv(connack(5))
    s5.send(publish('spBv1.0/grp5/NDATA/node5', payload(1, [metric('V5', 7, int=5)]), level=5))
    s5.send(publish('spBv1.0/grp5/DDATA/node5/devA', payload(2, [metric('V5', 7, int=6)]), level=5))
    s5.send(publish('other/v5', b'x', level=5))

    pkts = s.pkts + s5.pkts
    write_pcap(os.path.join(out, 'sparkplug-coverage.pcap'), pkts)

    # Malformed: topics with too few elements (reproducers of the leak fixed
    # by "Sparkplug: Fix leak of the split topic on early returns", each
    # raises an error expert info) and an empty topic.
    m = Stream('192.0.2.30', 41010, '192.0.2.20', PORT)
    m.hs()
    m.send(connect('bad'))
    m.recv(connack())
    for t in ('spBv1.0', 'spBv1.0/grp', 'spBv1.0/grp/NDATA', '', 'spBv1.0/'):
        m.send(publish(t, b'\x08\x01'))
    # a truncated protobuf payload on a good topic
    m.send(publish('spBv1.0/grp1/NDATA/node1', b'\x12\x20\x0a\x03abc'))
    write_pcap(os.path.join(out, 'sparkplug-coverage-malformed.pcap'), m.pkts)


if __name__ == '__main__':
    main(sys.argv[1])
