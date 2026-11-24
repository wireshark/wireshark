# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# T.125 MCS PDU builders (BER connect PDUs, ALIGNED PER domain PDUs) and TPKT/COTP framing
import struct
from berlib import boolean, gz, integer, octets, seq, TcpStream, tlv, write_pcap
from perlib import W

# ---- BER connect PDUs ----
def domain_params(chan=34, users=3, tokens=0, prio=1, thr=0, height=1, size=65528, ver=2):
    return seq(*[integer(x) for x in (chan, users, tokens, prio, thr, height, size, ver)])

def connect_initial(userdata, up=True, calling=b'\x01', called=b'\x01', tp=None, mn=None, mx=None):
    tp = tp or domain_params(34, 2, 0, 1, 0, 1, 65535, 2)
    mn = mn or domain_params(1, 1, 1, 1, 0, 1, 1056, 2)
    mx = mx or domain_params(65535, 64535, 65535, 1, 0, 1, 65535, 2)
    body = octets(calling) + octets(called) + boolean(up) + tp + mn + mx + octets(userdata)
    return tlv(b'\x7f\x65', body)

def connect_response(userdata, result=0, cid=0, dp=None):
    dp = dp or domain_params()
    return tlv(b'\x7f\x66', tlv(0x0a, bytes([result])) + integer(cid) + dp + octets(userdata))

def connect_additional(cid=0, prio=0):
    return tlv(b'\x7f\x67', integer(cid) + tlv(0x0a, bytes([prio])))

def connect_result(result=0):
    return tlv(b'\x7f\x68', tlv(0x0a, bytes([result])))

# ---- PER domain PDUs ----
def uid(w, v): w.con_int(v, 1001, 65535)
def chid(w, v): w.con_int(v, 0, 65535)
def tokid(w, v): w.con_int(v, 1, 65535)
def setof(w, items, enc):
    w.length(len(items))
    for i in items: enc(w, i)
def chattr(w, v):
    kind = v[0]
    idx = {'static': 0, 'userId': 1, 'private': 2, 'assigned': 3}[kind]
    w.con_int(idx, 0, 3)
    if kind == 'static': w.con_int(v[1], 1, 1000)
    elif kind == 'userId': w.bit(v[1]); uid(w, v[2])
    elif kind == 'private':
        w.bit(v[1]); w.con_int(v[2], 1001, 65535); uid(w, v[3]); setof(w, v[4], uid)
    else: w.con_int(v[1], 1001, 65535)
def tokattr(w, v):
    kind = v[0]
    idx = {'grabbed': 0, 'inhibited': 1, 'giving': 2, 'ungivable': 3, 'given': 4}[kind]
    w.con_int(idx, 0, 4)
    tokid(w, v[1])
    if kind in ('grabbed', 'ungivable'): uid(w, v[2])
    elif kind == 'inhibited': setof(w, v[2], uid)
    elif kind == 'giving': uid(w, v[2]); uid(w, v[3])
    else: uid(w, v[2])
def result(w, v): w.con_int(v, 0, 15)
def reason(w, v): w.con_int(v, 0, 4)
def diag(w, v): w.con_int(v, 0, 13)
def tstat(w, v): w.con_int(v, 0, 7)
def uintf(w, v): w.uint(v)

def senddata(idx, initiator, channel, prio=1, seg=3, data=b''):
    w = W(); w.con_int(idx, 0, 42)
    uid(w, initiator); chid(w, channel); w.con_int(prio, 0, 3); w.bits(seg, 2)
    w.octstr(data)
    return w.bytes()

def domain_pdu(idx, *a):
    """idx: DomainMCSPDU choice index; a: field values in ASN.1 order"""
    w = W(); w.con_int(idx, 0, 42)
    if idx == 0: uintf(w, a[0])
    elif idx == 1: uintf(w, a[0]); uintf(w, a[1])
    elif idx in (2, 3):
        setof(w, a[0], chattr); setof(w, a[1], chid)
    elif idx == 4: setof(w, a[0], uid); setof(w, a[1], chid)
    elif idx in (5, 6):
        setof(w, a[0], tokattr); setof(w, a[1], tokid)
    elif idx == 7: setof(w, a[0], tokid)
    elif idx == 8: reason(w, a[0])
    elif idx == 9: diag(w, a[0]); w.octstr(a[1])
    elif idx == 10: pass
    elif idx == 11:
        w.bit(a[1] is not None); result(w, a[0])
        if a[1] is not None: uid(w, a[1])
    elif idx in (12, 13): reason(w, a[0]); setof(w, a[1], uid)
    elif idx == 14: uid(w, a[0]); chid(w, a[1])
    elif idx == 15:
        w.bit(a[3] is not None); result(w, a[0]); uid(w, a[1]); chid(w, a[2])
        if a[3] is not None: chid(w, a[3])
    elif idx == 16: setof(w, a[0], chid)
    elif idx == 17: uid(w, a[0])
    elif idx == 18:
        w.bit(a[2] is not None); result(w, a[0]); uid(w, a[1])
        if a[2] is not None: w.con_int(a[2], 1001, 65535)
    elif idx == 19: uid(w, a[0]); w.con_int(a[1], 1001, 65535)
    elif idx == 20: w.con_int(a[0], 1001, 65535)
    elif idx in (21, 22, 23): uid(w, a[0]); w.con_int(a[1], 1001, 65535); setof(w, a[2], uid)
    elif idx == 24: w.con_int(a[0], 1001, 65535); setof(w, a[1], uid)
    elif 25 <= idx <= 28:
        uid(w, a[0]); chid(w, a[1]); w.con_int(a[2], 0, 3); w.bits(a[3], 2); w.octstr(a[4])
    elif idx in (29, 31, 37, 38, 39, 41): uid(w, a[0]); tokid(w, a[1])
    elif idx in (30, 32, 36, 40): result(w, a[0]); uid(w, a[1]); tokid(w, a[2]); tstat(w, a[3])
    elif idx in (33, 34): uid(w, a[0]); tokid(w, a[1]); uid(w, a[2])
    elif idx == 35: result(w, a[0]); uid(w, a[1]); tokid(w, a[2])
    elif idx == 42: uid(w, a[0]); tokid(w, a[1]); tstat(w, a[2])
    else: raise ValueError(idx)
    return w.bytes()

# ---- TPKT / COTP ----
def tpkt(payload): return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload
def cotp_dt(payload, eot=True): return tpkt(b'\x02\xf0' + (b'\x80' if eot else b'\x00') + payload)
def cotp_cr(src=0x1234): return tpkt(b'\x06\xe0\x00\x00' + struct.pack('!H', src) + b'\x00')
def cotp_cc(dst=0x1234, src=0x5678): return tpkt(b'\x06\xd0' + struct.pack('!HH', dst, src) + b'\x00')
