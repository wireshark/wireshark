#!/usr/bin/env python3
# Generates test/captures/mqtt_sn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MQTT-SN coverage captures.  Usage: mkmqtt-sn.py <outdir> [-v]
MQTT-SN has no default port, so the frames are Exported PDU (linktype 252)
frames that name the "mqttsn" dissector, the way a capture of a gateway
tap would carry them.  Nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from r13_pcaplib import write_pcap, exported_pdu

(ADVERTISE, SEARCHGW, GWINFO, _r3, CONNECT, CONNACK, WILLTOPICREQ, WILLTOPIC, WILLMSGREQ, WILLMSG,
 REGISTER, REGACK, PUBLISH, PUBACK, PUBCOMP, PUBREC, PUBREL, _r11, SUBSCRIBE, SUBACK, UNSUBSCRIBE,
 UNSUBACK, PINGREQ, PINGRESP, DISCONNECT, _r19, WILLTOPICUPD, WILLTOPICRESP, WILLMSGUPD, WILLMSGRESP) = range(0x1e)
ENCAP = 0xFE

def msg(t, body=b'', long=False):
    if long or len(body) + 2 > 255:
        return b'\x01' + struct.pack('!H', len(body) + 4) + bytes([t]) + body
    return bytes([len(body) + 2, t]) + body

def encap(inner, node, ctrl=0):
    # the length covers only the encapsulation header, the message follows it
    return msg(ENCAP, bytes([ctrl]) + node) + inner

frames = []; marks = []
def mark(n): marks.append((n, len(frames) + 1))
def F(b): frames.append(exported_pdu('mqttsn', b))

def u16(v): return struct.pack('!H', v)

def build_main():
    mark('gateway discovery')
    F(msg(ADVERTISE, bytes([7]) + u16(900)))
    F(msg(SEARCHGW, bytes([2])))
    F(msg(GWINFO, bytes([7])))
    F(msg(GWINFO, bytes([7]) + b'gw-addr-1'))
    mark('connect')
    F(msg(CONNECT, bytes([0x0C, 1]) + u16(60) + b'client-01'))     # will + clean session
    F(msg(CONNECT, bytes([0x04, 1]) + u16(30) + b'client-02'))
    F(msg(WILLTOPICREQ))
    F(msg(WILLTOPIC, bytes([0x30]) + b'will/topic'))              # qos -1 type and retain bits set below
    F(msg(WILLTOPIC, bytes([0x30 | 0x10]) + b'will/topic2'))
    F(msg(WILLTOPIC))                                               # empty will topic
    F(msg(WILLMSGREQ))
    F(msg(WILLMSG, b'goodbye'))
    F(msg(CONNACK, bytes([0])))
    F(msg(CONNACK, bytes([1])))
    F(msg(CONNACK, bytes([2])))
    F(msg(CONNACK, bytes([3])))
    mark('register/publish')
    F(msg(REGISTER, u16(0) + u16(1) + b'sensors/temp'))
    F(msg(REGACK, u16(5) + u16(1) + bytes([0])))
    F(msg(REGACK, u16(0) + u16(2) + bytes([2])))
    F(msg(PUBLISH, bytes([0x00]) + u16(5) + u16(0) + b'21.5'))                 # normal topic id, qos 0
    F(msg(PUBLISH, bytes([0x20 | 0x10]) + u16(5) + u16(3) + b'22.0'))          # qos 1, retain
    F(msg(PUBLISH, bytes([0x40 | 0x80 | 0x01]) + u16(1) + u16(4) + b'dup, predefined'))  # qos 2, dup
    F(msg(PUBLISH, bytes([0x60 | 0x02]) + b'ab' + u16(0) + b'qos -1, short name'))  # qos 3 (-1), short topic
    F(msg(PUBLISH, bytes([0x20]) + u16(5) + u16(6) + b'x' * 300))             # 3 octet length
    F(msg(PUBLISH, bytes([0x00]) + u16(5) + u16(7), True))                     # long header, empty data
    F(msg(PUBACK, u16(5) + u16(3) + bytes([0])))
    F(msg(PUBACK, u16(5) + u16(3) + bytes([2])))
    F(msg(PUBREC, u16(4)))
    F(msg(PUBREL, u16(4)))
    F(msg(PUBCOMP, u16(4)))
    mark('subscribe')
    F(msg(SUBSCRIBE, bytes([0x20]) + u16(8) + b'sensors/#'))                  # topic name
    F(msg(SUBSCRIBE, bytes([0x81]) + u16(9) + u16(1)))                        # predefined topic id
    F(msg(SUBSCRIBE, bytes([0x02]) + u16(10) + b'ab'))                        # short name
    F(msg(SUBACK, bytes([0x20]) + u16(7) + u16(8) + bytes([0])))
    F(msg(SUBACK, bytes([0x40]) + u16(0) + u16(9) + bytes([2])))
    F(msg(UNSUBSCRIBE, bytes([0x00]) + u16(11) + b'sensors/#'))
    F(msg(UNSUBSCRIBE, bytes([0x01]) + u16(12) + u16(1)))
    F(msg(UNSUBSCRIBE, bytes([0x02]) + u16(13) + b'ab'))
    F(msg(UNSUBACK, u16(11)))
    mark('keepalive, disconnect, will update')
    F(msg(PINGREQ))
    F(msg(PINGREQ, b'client-01'))
    F(msg(PINGRESP))
    F(msg(DISCONNECT))
    F(msg(DISCONNECT, u16(120)))
    F(msg(WILLTOPICUPD, bytes([0x20]) + b'new/will'))
    F(msg(WILLTOPICUPD))
    F(msg(WILLTOPICRESP, bytes([0])))
    F(msg(WILLMSGUPD, b'new will message'))
    F(msg(WILLMSGRESP, bytes([0])))
    mark('reserved/unknown types')
    F(msg(0x03, b'\x01'))
    F(msg(0x11, b'\x01'))
    F(msg(0x19, b'\x01'))
    F(msg(0x7f, b'\x01\x02'))
    mark('encapsulated')
    inner = msg(PINGREQ)
    F(encap(inner, b'\x01\x02'))
    F(encap(inner, b'\x01\x02\x03\x04\x05\x06\x07\x08', 0x02))                 # 8 octet node id
    F(encap(inner, b'\xaa', 0x03))
    F(encap(msg(PUBLISH, bytes([0x20]) + u16(5) + u16(3) + b'wrapped'), b'\x00\x10'))
    F(encap(encap(encap(inner, b'\x0c'), b'\x0b'), b'\x0a'))                    # three levels
    F(encap(b'', b'\x01\x02'))                                                # no inner message
    deep = inner
    for i in range(15):                                                       # 15 levels: still allowed
        deep = encap(deep, bytes([i]))
    F(deep)
    mark('reproducers')
    # the bug fixed on the branch: an 8 octet Wireless Node ID in FT_UINT16
    # (frame 'encapsulated' + 1 above is the same reproducer)
    F(bytes([3 + 8, 0xFE, 0x01]) + bytes(range(1, 9)) + bytes([2, 0x16]))

def build_malformed():
    global frames, marks
    frames = []; marks = []
    mark('nesting too deep')
    deep = msg(PINGREQ)
    for i in range(20):
        deep = encap(deep, bytes([i & 0xff]))
    F(deep)
    deep = b''
    for i in range(5000):
        deep += bytes([5, 0xFE, 0x01, 0x00, i & 0xff])
    F(deep + bytes([2, 0x16]))                                                # reproducer: 5000 levels
    mark('truncated')
    F(msg(CONNECT, bytes([0x04, 1]))[:5])
    F(msg(PUBLISH, bytes([0x20]) + u16(5))[:5])
    F(msg(REGISTER, u16(1))[:4])
    F(msg(SUBSCRIBE, bytes([0x20]))[:3])
    F(msg(ADVERTISE, bytes([7]))[:3])
    F(b'\x01\x00')
    F(b'\x05')
    F(msg(PUBLISH, bytes([0x20]) + u16(5) + u16(3) + b'abc')[:-1] + b'')      # fine, control
    F(bytes([0xff, PUBLISH, 0x20, 0, 5]))                                      # length longer than the data
    F(bytes([4, SUBACK, 0x20, 0]))

if __name__ == '__main__':
    out = sys.argv[1]
    build_main()
    write_pcap(os.path.join(out, 'mqtt-sn-coverage.pcap'), frames, linktype=252)
    if '-v' in sys.argv: print(len(frames), 'frames'); print(marks)
    frames = []
    build_malformed()
    write_pcap(os.path.join(out, 'mqtt-sn-coverage-malformed.pcap'), frames, linktype=252)
    if '-v' in sys.argv: print(len(frames), 'malformed frames'); print(marks)
