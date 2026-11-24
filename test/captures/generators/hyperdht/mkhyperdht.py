#!/usr/bin/env python3
# Generates test/captures/hyperdht_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Additional synthetic HyperDHT coverage captures. The tests in
test/suite_dissectors/group_hyperdht.py (captures hyperdht.pcap.gz and
hyperdht_tidreuse.pcap.gz) already cover most of the dissector; this adds
what they miss: the wide compact integer forms, the dht-rpc internal
commands, handshake modes and roles, every datagram the heuristic rejects,
and (in the malformed capture) payloads shorter than their fields.
Usage: mkhyperdht.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from c9lib import pcap, udp_frame

frames = []
A_SRV = '10.7.0.2'

def cu(n, wide=None):
    """compact uint; wide forces a wider (legal) encoding"""
    if wide == 'fd' or (wide is None and 0xfd <= n <= 0xffff):
        return b'\xfd' + struct.pack('<H', n)
    if wide == 'fe' or (wide is None and 0x10000 <= n <= 0xffffffff):
        return b'\xfe' + struct.pack('<I', n)
    if wide == 'ff' or (wide is None and n > 0xffffffff):
        return b'\xff' + struct.pack('<Q', n)
    return bytes([n])

def cb(b, wide=None):                 # compact buffer
    return cu(len(b), wide) + b

def addr(ip='198.51.100.7', port=49737):
    return socket.inet_aton(ip) + struct.pack('<H', port)

ID32 = bytes(range(32))
TOK32 = bytes(range(32, 64))
TGT32 = bytes(range(64, 96))
KEY32 = bytes(range(96, 128))
SIG64 = bytes(range(64))

def req(tid, cmd, internal=False, id_=False, token=False, target=False, value=None,
        cwide=None, vwide=None, extra=b''):
    flags = (1 if id_ else 0) | (2 if token else 0) | (4 if internal else 0) | (8 if target else 0) \
        | (0x10 if value is not None else 0)
    p = bytes([0x03, flags]) + struct.pack('<H', tid) + addr()
    if id_: p += ID32
    if token: p += TOK32
    p += cu(cmd, cwide)
    if target: p += TGT32
    if value is not None: p += cb(value, vwide)
    return p + extra

def rsp(tid, id_=False, token=False, closer=None, error=None, value=None,
        closer_wide=None, ewide=None, vwide=None, extra=b''):
    flags = (1 if id_ else 0) | (2 if token else 0) | (4 if closer is not None else 0) \
        | (8 if error is not None else 0) | (0x10 if value is not None else 0)
    p = bytes([0x13, flags]) + struct.pack('<H', tid) + addr()
    if id_: p += ID32
    if token: p += TOK32
    if closer is not None:
        p += cu(len(closer), closer_wide) + b''.join(addr(*c) for c in closer)
    if error is not None: p += cu(error, ewide)
    if value is not None: p += cb(value, vwide)
    return p + extra

def send(p, sp=50000, dp=50001, src='10.7.0.1', dst=A_SRV):
    frames.append(udp_frame(src, dst, sp, dp, p, len(frames) + 1))

def exch(sp, rq, rp=None, dp=50001):
    """a request from 10.7.0.1:sp to :dp and, optionally, its reply"""
    send(rq, sp=sp, dp=dp)
    if rp is not None:
        send(rp, sp=dp, dp=sp, src=A_SRV, dst='10.7.0.1')

# ---------- internal commands ----------
exch(51000, req(1, 0, internal=True), rsp(1))                                  # PING
exch(51000, req(2, 0, internal=True, value=b'x'), rsp(2, value=b'y'))          # PING with a value
exch(51000, req(3, 2, internal=True, target=True, id_=True, token=True), rsp(3, id_=True, token=True, closer=[('10.0.0.2', 40001), ('10.0.0.3', 40002)]))
exch(51000, req(4, 3, internal=True, value=addr('203.0.113.9', 4242)), rsp(4))  # DOWN_HINT
exch(51000, req(5, 4, internal=True, value=struct.pack('<I', 250)), rsp(5))      # DELAYED_PING
exch(51000, req(6, 1, internal=True, value=struct.pack('<H', 51001)), rsp(6))     # PING_NAT
exch(51002, req(7, 1, internal=True, value=struct.pack('<H', 0)), rsp(7))          # PING_NAT with port 0: no mirroring
exch(51003, req(8, 1, internal=True, value=b'\x01'), rsp(8))                       # short PING_NAT value
exch(51003, req(9, 3, internal=True, value=b'\x01\x02\x03'), rsp(9))               # short DOWN_HINT value
exch(51003, req(10, 4, internal=True, value=b'\x01\x02'), rsp(10))                 # short DELAYED_PING value
exch(51003, req(11, 9, internal=True))                                              # unknown internal command (conversation claimed)
exch(51003, req(12, 3, internal=True, value=b''), rsp(12, value=b''))            # empty values
# ---------- wide compact integers ----------
exch(51100, req(20, 4, cwide='fd', target=True, value=b'\x00', vwide='fd'), rsp(20, error=16, ewide='fd'))
exch(51100, req(21, 4, cwide='fe', target=True, value=b'\x00', vwide='fe'), rsp(21, error=17, ewide='fe', closer=[('10.0.0.2', 40001)], closer_wide='fd'))
exch(51100, req(22, 4, cwide='ff', target=True, value=b'\x00', vwide='ff'), rsp(22, error=1, ewide='ff', closer=[], closer_wide='fe', value=b'v', vwide='ff'))
exch(51100, req(23, 3, cwide='fd', target=True), rsp(23, closer=[('10.0.0.5', 40005)], closer_wide='ff', value=b'', vwide='fe'))
exch(51100, req(24, 0, cwide='fe', value=bytes([0, 2]) + cb(b'noise', 'fd'), vwide='fd'))
exch(51100, req(25, 600, value=b'unknown command 600'), rsp(25))               # unknown command, 0xfd form
exch(51100, req(26, 70000, value=b''), rsp(26))                                  # 0xfe form
exch(51100, req(27, 5000000000), rsp(27, error=300))                              # 0xff form, unknown error 0xfd form
# ---------- handshake / holepunch modes and relay roles ----------
def hs(flags, mode, noise=b'noise', tail=b''):
    return bytes([flags, mode]) + cb(noise) + tail
def hp(flags, mode, hid=7, payload=b'payload', tail=b''):
    return bytes([flags, mode]) + cu(hid) + cb(payload) + tail
for mode in (0, 1, 2, 3, 4, 9):
    exch(52000 + mode, req(30 + mode, 0, target=True, value=hs(0x03, mode, tail=addr('192.0.2.1', 1111) + addr('192.0.2.2', 2222))), rsp(30 + mode, value=hs(0, 4)) if mode == 0 else None)
    exch(52100 + mode, req(40 + mode, 1, target=True, value=hp(0x01, mode, tail=addr('192.0.2.3', 3333))), rsp(40 + mode, value=hp(0, 4)) if mode == 0 else None)
exch(52200, req(50, 0, target=True), rsp(50))                                       # no value
exch(52200, req(51, 0, target=True, value=b'\x00'))                                  # value shorter than flags+mode
exch(52200, req(52, 1, value=hp(0, 0)))                                              # no target
exch(52200, req(53, 0, id_=True, token=True, target=True, value=hs(0, 0)))
# ---------- datagrams the heuristic rejects (not HyperDHT, left to UDP) ----------
good = req(60, 2, target=True)
def reject(p, n=[0]):
    n[0] += 1
    send(p, sp=53000 + n[0], dp=53100 + n[0])
reject(good[:9])                                                  # shorter than the header
reject(b'\x04' + good[1:])                                         # bad type
reject(good[:1] + b'\xe0' + good[2:])                              # bad flags
reject(good[:4] + socket.inet_aton('198.51.100.7') + b'\x00\x00' + good[10:])   # port 0
reject(good[:4] + socket.inet_aton('0.1.2.3') + good[8:])          # 0.0.0.0/8
reject(good[:4] + socket.inet_aton('239.1.1.1') + good[8:])        # multicast
reject(bytes([0x03, 0x01]) + good[2:10] + b'\x00' * 8)              # id flag, too short
reject(bytes([0x03, 0x02]) + good[2:10] + b'\x00' * 8)              # token flag, too short
reject(bytes([0x03, 0x00]) + good[2:10])                            # no command
reject(bytes([0x03, 0x00]) + good[2:10] + b'\xfe\x01')              # command truncated
reject(bytes([0x03, 0x00]) + good[2:10] + b'\x63')                  # unknown command
reject(bytes([0x03, 0x04]) + good[2:10] + b'\x63')                  # unknown internal command
reject(bytes([0x03, 0x08]) + good[2:10] + b'\x02' + b'\x00' * 10)  # target missing
reject(bytes([0x13, 0x04]) + good[2:10])                            # closer array missing
reject(bytes([0x13, 0x04]) + good[2:10] + b'\x05' + addr())         # closer array truncated
reject(bytes([0x13, 0x08]) + good[2:10])                            # error missing
reject(bytes([0x13, 0x08]) + good[2:10] + b'\x09')                  # unknown error code
reject(bytes([0x13, 0x10]) + good[2:10])                            # value missing
reject(bytes([0x13, 0x10]) + good[2:10] + b'\x05ab')                # value truncated
reject(good + b'trailing')                                          # trailing bytes
reject(bytes([0x13, 0x10]) + good[2:10] + b'\xff\x01\x00')          # value length cut
# ---------- trailing bytes and truncated value on a claimed conversation ----------
exch(54000, req(70, 2, target=True), rsp(70))
exch(54000, req(71, 2, target=True, extra=b'\xde\xad'), rsp(71, extra=b'\xbe\xef'))
exch(54000, req(72, 9, value=b'abc'), rsp(72, error=9))
# first-contact replies (request not seen), accepted by the heuristic: closer nodes, error, value
send(rsp(80, closer=[('10.0.0.2', 40001), ('10.0.0.3', 40002)]), sp=56001, dp=56002, src=A_SRV, dst='10.7.0.1')
send(rsp(81, closer=[], error=1, value=b'v'), sp=56003, dp=56004, src=A_SRV, dst='10.7.0.1')
# a claimed conversation: datagrams that are not HyperDHT any more are left to the data dissector
send(b'abc', sp=54000, dp=50001)
send(b'\x04' + good[1:], sp=54000, dp=50001)
send(good[:1] + b'\xe0' + good[2:], sp=54000, dp=50001)
pcap(os.path.join(sys.argv[1], 'hyperdht-coverage.pcap'), frames)

# ---------- malformed: inner payloads shorter than their fields ----------
frames = []
sp = [55000]
def shortp(cmd, value, request=True, setup=True):
    sp[0] += 1
    if request:
        exch(sp[0], req(1, cmd, target=True, value=value), rsp(1, value=value))
    else:
        exch(sp[0], req(1, cmd, target=True), rsp(1, value=value))
# handshake and holepunch cuts
for cmd, full in ((0, hs(0x03, 0, tail=addr() + addr())), (1, hp(0x01, 0, tail=addr()))):
    for n in range(0, len(full) + 1, 1):
        shortp(cmd, full[:n])
# announce: every flag with a cut
ann = bytes([0x0f]) + KEY32 + cu(1) + addr() + ID32 + SIG64 + cu(3)
for n in (0, 1, 20, 33, 34, 40, 50, 66, 80, 120, 140, len(ann)):
    shortp(4, ann[:n]); shortp(5, ann[:n])
shortp(4, bytes([0x01]) + KEY32 + b'\xfd\x05')                      # relays count truncated
shortp(4, bytes([0x01]) + KEY32 + cu(9) + addr())                    # more relays than bytes
shortp(4, bytes([0x08]) + b'')                                        # bump missing
# mutable put / get
mp = KEY32 + cu(5) + cb(b'value') + SIG64
for n in (0, 16, 32, 33, 34, 36, 40, 60, len(mp)):
    shortp(6, mp[:n])
shortp(6, KEY32 + cu(5) + b'\xfd\x05')                                # value length 0xfd truncated
shortp(7, b'')
shortp(7, b'\xfd\x01')
for n in (0, 1, 2, 4, 8, 20):                                          # mutable get reply
    sp[0] += 1
    exch(sp[0], req(1, 7, target=True, value=cu(1)), rsp(1, value=(cu(3) + cb(b'abcd') + SIG64)[:n]))
# lookup / find peer replies
peer = KEY32 + cu(2) + addr() + addr('10.1.1.1', 99)
for n in (0, 1, 2, 20, 35, 36, 40, 44, 48, 52):
    sp[0] += 1
    exch(sp[0], req(1, 3, target=True), rsp(1, value=(cu(1) + peer + cu(8))[:n]))
    sp[0] += 1
    exch(sp[0], req(1, 2, target=True), rsp(1, value=peer[:n]))
sp[0] += 1
exch(sp[0], req(1, 3, target=True), rsp(1, value=cu(5) + peer))      # count larger than the records
sp[0] += 1
exch(sp[0], req(1, 3, target=True), rsp(1, value=cu(2) + peer + peer + cu(7)))   # records then bump
# plugin
pl = cb(b'plugin') + cu(1) + cu(2) + bytes([1]) + cb(b'data')
for n in range(0, len(pl) + 1):
    shortp(10, pl[:n])
shortp(10, b'\x0aplug')                                                # name longer than the value
sp[0] += 1
exch(sp[0], req(1, 10, target=True), rsp(1, value=b'abc'))
# immutable
shortp(8, b'')
sp[0] += 1
exch(sp[0], req(1, 9, target=True), rsp(1, value=b''))
# envelope: truncated values and closer arrays on a claimed conversation
sp[0] += 1
exch(sp[0], req(1, 2, target=True), rsp(1, closer=[('10.0.0.2', 1)]))
send(bytes([0x13, 0x10]) + struct.pack('<H', 1) + addr() + b'\x20ab', sp=50001, dp=sp[0], src=A_SRV, dst='10.7.0.1')   # value longer than packet
send(bytes([0x13, 0x04]) + struct.pack('<H', 1) + addr() + b'\x09' + addr(), sp=50001, dp=sp[0], src=A_SRV, dst='10.7.0.1')
send(bytes([0x03, 0x10]) + struct.pack('<H', 1) + addr() + b'\x02' + b'\x7f' + b'ab', sp=sp[0], dp=50001)
# a claimed conversation: a request without its command, a handshake whose value length is missing
exch(57000, req(90, 2, target=True), rsp(90))
send(bytes([0x03, 0x00]) + struct.pack('<H', 91) + addr(), sp=57000, dp=50001)
send(bytes([0x03, 0x10]) + struct.pack('<H', 92) + addr() + b'\x00', sp=57000, dp=50001)
send(bytes([0x03, 0x10]) + struct.pack('<H', 93) + addr() + b'\x01', sp=57000, dp=50001)
pcap(os.path.join(sys.argv[1], 'hyperdht-coverage-malformed.pcap'), frames)
