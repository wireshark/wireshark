#!/usr/bin/env python3
# Generates test/captures/mqtt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MQTT coverage captures.  Usage: mkmqtt.py <outdir> [-v]
All addresses are from 192.0.2.0/24; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib
from r13_pcaplib import TcpStream, write_pcap

def vbi(n):
    out = b''
    while True:
        b = n & 0x7f; n >>= 7
        if n: out += bytes([b | 0x80])
        else: return out + bytes([b])

def mstr(s):
    if isinstance(s, str): s = s.encode()
    return struct.pack('!H', len(s)) + s

def pkt(t, flags, body): return bytes([(t << 4) | flags]) + vbi(len(body)) + body
def props(*items):
    b = b''.join(items)
    return vbi(len(b)) + b
def p8(i, v): return bytes([i, v])
def p16(i, v): return bytes([i]) + struct.pack('!H', v)
def p32(i, v): return bytes([i]) + struct.pack('!I', v)
def pstr(i, s): return bytes([i]) + mstr(s)
def pvbi(i, v): return bytes([i]) + vbi(v)
def puser(k, v): return bytes([0x26]) + mstr(k) + mstr(v)

CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, \
  UNSUB, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT, AUTH = range(1, 16)

frames = []
marks = []
def mark(name): marks.append((name, len(frames) + 1))
def new(cport):
    st = TcpStream(cport=cport)
    frames.extend(st.handshake())
    return st
def C(st, data): frames.append(st.pkt(data))
def S(st, data): frames.append(st.pkt(data, True))

def connect(ver, cid, flags, extra_props=b'', will=None, user=None, pw=None, name=None, will_props=b''):
    if name is None: name = b'MQIsdp' if ver == 3 else b'MQTT'
    b = mstr(name) + bytes([ver, flags]) + struct.pack('!H', 60)
    if ver == 5: b += extra_props or props()
    b += mstr(cid)
    if flags & 0x04:
        if ver == 5: b += will_props or props()
        b += mstr(will[0]) + mstr(will[1])
    if flags & 0x80: b += mstr(user)
    if flags & 0x40: b += mstr(pw)
    return pkt(CONNECT, 0, b)

def old_session(ver, cport):
    """v3.1 (ver 3) or v3.1.1 (ver 4)"""
    st = new(cport=cport)
    C(st, connect(ver, 'cli%d' % ver, 0xEE, will=('will/topic', b'bye'), user='alice', pw='secret'))
    S(st, pkt(CONNACK, 0, bytes([1, 0])))
    C(st, pkt(PUBLISH, 0, mstr('sensors/t1') + b'21.5'))
    C(st, pkt(PUBLISH, 0x03, mstr('sensors/t2') + struct.pack('!H', 7) + b'\x00\x01binary'))   # qos1 retain
    C(st, pkt(PUBLISH, 0x0C, mstr('sensors/t3') + struct.pack('!H', 8) + b'dup q2'))           # dup qos2
    S(st, pkt(PUBACK, 0, struct.pack('!H', 7)))
    S(st, pkt(PUBREC, 0, struct.pack('!H', 8)))
    C(st, pkt(PUBREL, 2, struct.pack('!H', 8)))
    S(st, pkt(PUBCOMP, 0, struct.pack('!H', 8)))
    C(st, pkt(SUBSCRIBE, 2, struct.pack('!H', 9) + mstr('a/#') + b'\x00' + mstr('b/+') + b'\x01' + mstr('c/d') + b'\x02'))
    S(st, pkt(SUBACK, 0, struct.pack('!H', 9) + bytes([0, 1, 2, 0x80])))
    C(st, pkt(UNSUB, 2, struct.pack('!H', 10) + mstr('a/#') + mstr('b/+')))
    S(st, pkt(UNSUBACK, 0, struct.pack('!H', 10)))
    C(st, pkt(PINGREQ, 0, b''))
    S(st, pkt(PINGRESP, 0, b''))
    C(st, pkt(DISCONNECT, 0, b''))
    return st

def v5_session(cport):
    st = new(cport=cport)
    cprops = props(p32(0x11, 3600), p16(0x21, 100), p32(0x27, 65535), p16(0x22, 10),
                   p8(0x19, 1), p8(0x17, 1), puser('k1', 'v1'), pstr(0x15, 'SCRAM'), pstr(0x16, b'\x01\x02'))
    wprops = props(p32(0x18, 30), p8(0x01, 1), p32(0x02, 60), pstr(0x03, 'text/plain'),
                   pstr(0x08, 'resp/topic'), pstr(0x09, b'corr'), puser('wk', 'wv'))
    mark('v5 connect')
    C(st, connect(5, 'cli5', 0xEE, cprops, will=('will/t', b'w'), user='bob', pw='pw', will_props=wprops))
    sprops = props(p8(0x24, 1), p8(0x25, 1), p8(0x28, 1), p8(0x29, 1), p8(0x2A, 1), p16(0x13, 30),
                   pstr(0x12, 'assigned-id'), pstr(0x1A, 'resp-info'), pstr(0x1C, 'other.example'),
                   pstr(0x1F, 'ok'), p16(0x22, 5))
    S(st, pkt(CONNACK, 0, bytes([1, 0]) + sprops))
    # publish with every kind of property
    pp = props(p8(0x01, 1), p32(0x02, 20), pstr(0x03, 'text/plain'), pstr(0x08, 'r/t'),
               pstr(0x09, b'c1'), pvbi(0x0B, 300), p16(0x23, 3), puser('x', 'y'))
    C(st, pkt(PUBLISH, 0x02, mstr('v5/topic') + struct.pack('!H', 1) + pp + b'hello'))
    # content type json -> media type dissector
    pj = props(pstr(0x03, 'application/json'))
    C(st, pkt(PUBLISH, 0, mstr('v5/json') + pj + b'{"a": 1}'))
    # sparkplug-looking topic reaches the heuristic list
    C(st, pkt(PUBLISH, 0, mstr('spBv1.0/grp/NDATA/node1') + props() + b'\x08\x01'))
    # topic alias: define, use, rebind, use
    mark('topic alias')
    al = props(p16(0x23, 1))
    C(st, pkt(PUBLISH, 0, mstr('alias/aaa') + al + b'p1'))
    C(st, pkt(PUBLISH, 0, mstr('') + al + b'p2'))
    C(st, pkt(PUBLISH, 0, mstr('alias/bbb') + al + b'p3'))
    C(st, pkt(PUBLISH, 0, mstr('') + al + b'p4'))
    C(st, pkt(PUBLISH, 0, mstr('') + props(p16(0x23, 9)) + b'unknown alias'))   # unknown alias: note
    # unknown property id falls into the default case
    C(st, pkt(PUBLISH, 0, mstr('v5/unk') + props(b'\xee\x01\x02') + b'x'))
    C(st, pkt(PUBLISH, 0, mstr('v5/empty') + props()))                          # empty payload
    for t, flags in ((PUBACK, 0), (PUBREC, 0), (PUBREL, 2), (PUBCOMP, 0)):
        S(st, pkt(t, flags, struct.pack('!H', 21)))                                  # short form (len 2)
        S(st, pkt(t, flags, struct.pack('!H', 21) + b'\x10' if t != PUBREL and t != PUBCOMP else struct.pack('!H', 21) + b'\x92'))  # reason only (len 3)
        S(st, pkt(t, flags, struct.pack('!H', 21) + (b'\x10' if t in (PUBACK, PUBREC) else b'\x92') + props(pstr(0x1F, 'why'), puser('a', 'b'))))
    mark('v5 subscribe')
    C(st, pkt(SUBSCRIBE, 2, struct.pack('!H', 30) + props(pvbi(0x0B, 5), puser('s', 't')) +
              mstr('t/1') + b'\x2e' + mstr('t/2') + b'\x15' + mstr('t/3') + b'\x08'))
    S(st, pkt(SUBACK, 0, struct.pack('!H', 30) + props(pstr(0x1F, 'granted')) + bytes([0, 1, 2, 0x80, 0x8f, 0x97, 0xa1])))
    C(st, pkt(UNSUB, 2, struct.pack('!H', 31) + props(puser('u', 'v')) + mstr('t/1') + mstr('t/2')))
    S(st, pkt(UNSUBACK, 0, struct.pack('!H', 31) + props() + bytes([0, 0x11])))
    C(st, pkt(PINGREQ, 0, b''))
    S(st, pkt(PINGRESP, 0, b''))
    mark('v5 auth/disconnect')
    C(st, pkt(AUTH, 0, b''))
    C(st, pkt(AUTH, 0, b'\x18'))
    C(st, pkt(AUTH, 0, b'\x18' + props(pstr(0x15, 'SCRAM'), pstr(0x16, b'data'))))
    C(st, pkt(DISCONNECT, 0, b'\x04'))
    C(st, pkt(DISCONNECT, 0, b'\x04' + props(pstr(0x1F, 'bye'), pstr(0x1C, 'srv'), p32(0x11, 0))))
    C(st, pkt(DISCONNECT, 0, b''))
    return st

def build_main():
    mark('v3.1 session'); old_session(3, 41000)
    mark('v3.1.1 session'); old_session(4, 41001)
    v5_session(41002)
    # Reassembly: one PDU in three segments, three PDUs in one segment
    mark('tcp reassembly')
    st = new(cport=41003)
    C(st, connect(5, 'seg', 0x02))
    S(st, pkt(CONNACK, 0, bytes([0, 0, 0])))
    big = pkt(PUBLISH, 0, mstr('big/topic') + props() + bytes(range(256)) * 3)
    C(st, big[:1]); C(st, big[1:5]); C(st, big[5:400]); C(st, big[400:])
    C(st, pkt(PINGREQ, 0, b'') + pkt(PINGREQ, 0, b'') + pkt(PUBLISH, 0, mstr('multi/x') + props() + b'm'))
    # PDU with a 3 byte length (>16 KiB) in one segment
    C(st, pkt(PUBLISH, 0, mstr('huge') + props() + b'z' * 20000))
    # payloads for the message decoding table (see runcov.sh)
    C(st, pkt(PUBLISH, 0, mstr('zlib/ok') + props() + zlib.compress(b'{"z": 1}')))
    C(st, pkt(PUBLISH, 0, mstr('zlib/bad') + props() + b'not zlib data'))
    mark('reproducers')
    # reproducer: topic alias state, version changed by a later CONNECT
    st = new(cport=41004)
    C(st, connect(5, 'c1', 0x02))
    C(st, pkt(PUBLISH, 0, mstr('aaa') + props(p16(0x23, 1)) + b'payload1'))
    C(st, pkt(PUBLISH, 0, mstr('') + props(p16(0x23, 1)) + b'payload2'))
    C(st, pkt(PUBLISH, 0, mstr('bbb') + props(p16(0x23, 1)) + b'payload3'))
    C(st, pkt(PUBLISH, 0, mstr('') + props(p16(0x23, 1)) + b'payload4'))
    C(st, connect(4, 'c2', 0x02))
    C(st, pkt(PUBLISH, 0, mstr('v311/t') + b'later'))
    # SUBSCRIBE topics (memory fix) repeated in one conversation
    C(st, pkt(SUBSCRIBE, 2, struct.pack('!H', 1) + mstr('r/#') + b'\x00' + mstr('s/#') + b'\x01'))

def build_malformed():
    global frames, marks
    frames = []
    mark('no CONNECT (unknown version)')
    st = new(cport=42000)
    C(st, pkt(PUBLISH, 0, mstr('no/connect') + b'x'))
    C(st, pkt(PINGREQ, 0, b''))
    mark('v3 empty topics')
    st = new(cport=42001)
    C(st, connect(4, 'm', 0x04, will=('', b'')))
    C(st, pkt(PUBLISH, 0, mstr('') + b'notopic'))
    C(st, pkt(SUBSCRIBE, 2, struct.pack('!H', 1) + mstr('') + b'\x00'))
    C(st, pkt(UNSUB, 2, struct.pack('!H', 1) + mstr('')))
    mark('v5 property length')
    for i, plen in enumerate([b'\xff' * 10, vbi(0xfffffff0), vbi(0x1fffffff0), vbi(5000)]):
        st = new(42010 + i)
        b = mstr(b'MQTT') + b'\x05\x02' + struct.pack('!H', 60) + plen + mstr('c1') + b'A' * 16
        C(st, pkt(CONNECT, 0, b))
    mark('truncated')
    st = new(cport=42020)
    C(st, connect(5, 'trunc', 0x02))
    C(st, pkt(PUBLISH, 0, mstr('t') + props(pstr(0x03, 'x'))[:-1]))
    C(st, pkt(PUBLISH, 0, mstr('toolong')[:4]))
    C(st, pkt(CONNACK, 0, b'\x00'))
    C(st, pkt(SUBSCRIBE, 2, b'\x00\x01' + props() + b'\x00\x05ab'))
    C(st, pkt(SUBACK, 0, b'\x00\x01' + props(b'\x26\x00\x05ab')))
    # a CONNECT that ends inside the string fields
    C(st, pkt(CONNECT, 0, mstr(b'MQTT') + b'\x05\xc2\x00\x3c' + props() + mstr('c') ))
    C(st, pkt(CONNECT, 0, mstr(b'MQTT') + b'\x04\x04\x00\x3c' + mstr('c') + b'\x00\x01'))
    C(st, pkt(0, 0, b'\x00'))       # reserved type 0
    C(st, pkt(0, 0, b'\x00'))
    C(st, bytes([0xff, 0x00]))      # unknown type 15 AUTH
    C(st, bytes([0x10, 0xff, 0xff, 0xff, 0xff]))   # bad varint length

if __name__ == '__main__':
    out = sys.argv[1]
    build_main()
    write_pcap(os.path.join(out, 'mqtt-coverage.pcap'), frames)
    if '-v' in sys.argv:
        print(len(frames), 'frames'); print(marks)
    n = len(frames)
    frames = []; marks = []
    build_malformed()
    write_pcap(os.path.join(out, 'mqtt-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'malformed frames'); print(marks)
