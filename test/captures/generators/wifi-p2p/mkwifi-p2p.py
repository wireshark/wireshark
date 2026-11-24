#!/usr/bin/env python3
# Generates test/captures/wifi-p2p_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Wi-Fi P2P coverage captures: usage mkwifi-p2p.py <outdir> [-v]
# P2P attributes travel in the WFA vendor IE (subtype 9) of beacons, probe,
# association and P2P public action / action frames; the P2P ANQP service
# discovery in GAS frames (ANQP vendor specific list, WFA subtype 9).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlanlib import (
    A1, A2, A3, adv_proto_anqp, anqp_vendor, assoc_req, assoc_resp, beacon, gas_req, gas_resp,
    Pcap, probe_req, probe_resp, public_action_vendor, tag, vendor_action, wfa_ie,
)

def attr(t, data, length=None):
    return struct.pack('<BH', t, len(data) if length is None else length) + data

def p2pie(*attrs):
    return wfa_ie(9, b''.join(attrs))

CC = b'XX\x04'                 # country string "XX" + environment 0x04 (any)
def capab(dev=0x25, grp=0x00): return attr(2, bytes([dev, grp]))
def devid(a=A1): return attr(3, a)
def intent(v): return attr(4, bytes([v]))
def cfgto(go=100, cl=50): return attr(5, bytes([go, cl]))
def listen(oc=81, ch=6): return attr(6, CC + bytes([oc, ch]))
def oper(oc=115, ch=36): return attr(17, CC + bytes([oc, ch]))
def gbssid(a=A2): return attr(7, a)
def extlisten(p=500, i=1000): return attr(8, struct.pack('<HH', p, i))
def intaddr(a=A3): return attr(9, a)
def manage(v=7): return attr(10, bytes([v]))
def chlist(*ents):
    return attr(11, CC + b''.join(bytes([oc, len(ch)]) + bytes(ch) for oc, ch in ents))
def noa(index=1, params=0x85, *descs):
    return attr(12, bytes([index, params]) + b''.join(struct.pack('<BIII', c, d, i, s) for c, d, i, s in descs))
PRI = struct.pack('>H', 10) + bytes.fromhex('0050f204') + struct.pack('>H', 5)   # computer? category 10 (Display), subcat 5
SEC = struct.pack('>H', 1) + bytes.fromhex('0050f204') + struct.pack('>H', 1)
def devinfo(name=b'p2p-dev', nsec=1, methods=0x0188, ntype=0x1011, nlen=None):
    return attr(13, A1 + struct.pack('>H', methods) + PRI + bytes([nsec]) + SEC * nsec +
                struct.pack('>HH', ntype, len(name) if nlen is None else nlen) + name)
def client(addr, name=b'cl', nsec=0, capab=0x25, methods=0x0108, ntype=0x1011, nlen=None, extra=b''):
    body = addr + A3 + bytes([capab]) + struct.pack('>H', methods) + PRI + bytes([nsec]) + SEC * nsec + \
        struct.pack('>HH', ntype, len(name) if nlen is None else nlen) + name + extra
    return bytes([len(body)]) + body
def ginfo(*clients): return attr(14, b''.join(clients))
def gid(addr=A2, ssid=b'DIRECT-ab-Test'): return attr(15, addr + ssid)
def p2pif(): return attr(16, A1 + bytes([2]) + A2 + A3)
def invflags(v=1): return attr(18, bytes([v]))
def oob(role=2, oc=81, ch=11): return attr(19, CC + bytes([oc, ch]))
def svchash(*h): return attr(21, b''.join(h))
def sessinfo(s=b'session data'): return attr(22, s)
def conncap(v=1): return attr(23, bytes([v]))
def advid(i=0x01020304, a=A3): return attr(24, struct.pack('>I', i) + a)
def advsvc(*svcs):
    return attr(25, b''.join(struct.pack('>IHB', i, m, len(n)) + n for i, m, n in svcs))
def sessid(i=0x0a0b0c0d, a=A1): return attr(26, struct.pack('>I', i) + a)
def featcap(d=b'\x01\x02\x03'): return attr(27, d)
def persist(a=A1, ssid=b'DIRECT-ps-Group'): return attr(28, a + ssid)
def status(v): return attr(0, bytes([v]))
def minor(v): return attr(1, bytes([v]))
def vendor(d=b'\x00\x11\x22\x01\x02'): return attr(221, d)

def pubact(sub, token, tags):
    return public_action_vendor(9, bytes([sub, token]) + tags)
def p2pact(sub, token, tags):
    return vendor_action(9, bytes([sub, token]) + tags)

main = Pcap(); mal = Pcap(); ranges = []
def mark(p, name, n0):
    ranges.append((name, n0 + 1, len(p.frames)))

n0 = len(main.frames)
# --- IEs of beacons, probe and association frames ---
main.add(probe_req(tag(0, b'DIRECT-') + p2pie(capab(), devid(), listen(), extlisten(), devinfo(b'phone', 0))))
main.add(probe_resp(tag(0, b'DIRECT-ab') + p2pie(capab(0xff, 0xff), devinfo(b'tablet', 2))))
main.add(beacon(tag(0, b'DIRECT-ab-Test') + p2pie(capab(0x25, 0x81), gid(), noa(3, 0x85, (255, 1000, 5000, 123456)))))
main.add(assoc_req(p2pie(capab(), devinfo(b'x', 0), cfgto())))
main.add(assoc_resp(p2pie(status(0), extlisten(0, 0))))
# every device and group capability bit
for i in range(8):
    main.add(probe_req(p2pie(capab(1 << i if i < 6 else 0, 1 << i))))
mark(main, 'P2P IE in probe, beacon and association frames, capability bits', n0)

n0 = len(main.frames)
# every attribute (one frame each; some in a second IE of the same frame)
main.add(probe_resp(p2pie(devid(A2), intent(0xff), cfgto(255, 1), listen(), oper())))
main.add(probe_resp(p2pie(gbssid(), extlisten(65535, 65535), intaddr(), manage(0xff))))
main.add(probe_resp(p2pie(chlist((81, [1, 6, 11]), (115, [36, 40, 44, 48]), (124, [])), noa(0, 0))))
main.add(probe_resp(p2pie(noa(255, 0xff, (1, 2, 3, 4), (255, 5, 6, 7), (2, 8, 9, 10)))))
main.add(probe_resp(p2pie(devinfo(b'name', 0), devinfo(b'longer-device-name', 3), devinfo(b'', 0))))
main.add(probe_resp(p2pie(ginfo(client(A1, b'one'), client(A2, b'two', 1), client(A3, b'', 2)))))
main.add(probe_resp(p2pie(gid(), gid(A3, b''), p2pif(), invflags(0), invflags(1))))
main.add(probe_resp(p2pie(oob(0), oob(1), oob(2), oob(3))))
main.add(probe_resp(p2pie(svchash(b'\x01' * 6, b'\x02' * 6, b'\x03' * 6), sessinfo(), conncap(0), conncap(7))))
main.add(probe_resp(p2pie(advid(), advsvc((1, 0x0108, b'org.example.svc'), (2, 0x0001, b'x'), (3, 0, b'')),
                          sessid(), featcap(b''), featcap(), persist(), persist(A2, b'S'))))
main.add(probe_resp(p2pie(vendor(), attr(99, b'\x01\x02'), attr(20, b'\x00'), attr(222, b''))))
for st in range(14):
    main.add(probe_resp(p2pie(status(st), minor(st % 6))))
mark(main, 'Every attribute type, status and minor reason codes, unknown attributes', n0)

n0 = len(main.frames)
# --- P2P public action frames ---
gn = (capab(), intent(0xb4), cfgto(), listen(), extlisten(), intaddr(), chlist((81, [1, 6, 11]), (115, [36])), devinfo(b'phone', 1), oper())
main.add(pubact(0, 1, p2pie(*gn)))
main.add(pubact(1, 1, p2pie(status(0), capab(), intent(3), cfgto(), oper(), intaddr(), chlist((81, [1])), devinfo(), gid())))
main.add(pubact(2, 1, p2pie(status(0), capab(), oper(), chlist((81, [6])), gid())))
main.add(pubact(3, 2, p2pie(cfgto(), invflags(0), oper(), gbssid(), gid(), chlist((81, [6])), devinfo())))
main.add(pubact(4, 2, p2pie(status(0), cfgto(), oper(), gbssid(), chlist((81, [6])))))
main.add(pubact(5, 3, p2pie(devid(), gid())))
main.add(pubact(6, 3, p2pie(status(1))))
main.add(pubact(7, 4, p2pie(capab(), devinfo(), gid())))
main.add(pubact(8, 4, p2pie()))
main.add(pubact(9, 5, b''))                  # unknown public action subtype
mark(main, 'P2P public action frames (every subtype)', n0)

n0 = len(main.frames)
# --- P2P action frames ---
main.add(p2pact(0, 1, p2pie(noa(7, 0x84, (1, 100, 200, 300)))))
main.add(p2pact(1, 2, p2pie(noa(0, 0, (255, 1, 2, 3)))))
main.add(p2pact(2, 2, p2pie(status(0), noa(1, 0))))
main.add(p2pact(3, 3, p2pie()))
main.add(p2pact(9, 3, b''))
mark(main, 'P2P action frames', n0)

n0 = len(main.frames)
# --- P2P ANQP service discovery over GAS ---
def p2p_anqp(tlvs, sui=0x0102):
    return anqp_vendor(9, struct.pack('<H', sui) + tlvs)
def req_tlv(proto, tid, data): return struct.pack('<HBB', 2 + len(data), proto, tid) + data
def resp_tlv(proto, tid, status, data): return struct.pack('<HBBB', 3 + len(data), proto, tid, status) + data
adv = adv_proto_anqp()
main.add(gas_req(adv, p2p_anqp(req_tlv(0, 1, b'') + req_tlv(1, 2, b'\x00\x01\x02\x03\x04') + req_tlv(2, 3, b'x') +
                               req_tlv(3, 4, b'') + req_tlv(4, 5, b'\x01') + req_tlv(9, 6, b'abc'))))
main.add(gas_req(adv, p2p_anqp(b'')))        # no service TLV (only the update indicator)
main.add(gas_resp(adv, p2p_anqp(resp_tlv(1, 1, 0, b'\x05\x00\x01\x02\x03') + resp_tlv(2, 2, 1, b'') +
                                resp_tlv(3, 3, 2, b'abc') + resp_tlv(0, 4, 3, b'z') + resp_tlv(7, 5, 0, b''))))
main.add(gas_resp(adv, p2p_anqp(resp_tlv(4, 7, 0, b'\x00\x00\x06\x00\x00\x00\x32\x00\x32'))))   # WFD: see wifi-display
mark(main, 'P2P ANQP requests and responses (GAS)', n0)

# --- malformed ---
n0 = len(mal.frames)
mal.add(probe_resp(p2pie(b'\x02\x01')))                       # header cut
mal.add(probe_resp(p2pie(attr(28, bytes(5)))))                # persistent group info < 6 (fixed)
mal.add(probe_resp(p2pie(attr(28, b''))))
mal.add(probe_resp(p2pie(attr(2, b'\x01'))))                  # capability short
mal.add(probe_resp(p2pie(attr(3, bytes(4)))))
mal.add(probe_resp(p2pie(attr(7, bytes(5)))))                 # group BSSID wrong length
mal.add(probe_resp(p2pie(attr(7, bytes(7)))))
mal.add(probe_resp(p2pie(attr(12, b'\x01'))))                 # NoA too short
mal.add(probe_resp(p2pie(attr(12, b'\x01\x02\x03'))))
mal.add(probe_resp(p2pie(devinfo(b'n', 0, ntype=0x1012))))    # wrong name type
mal.add(probe_resp(p2pie(devinfo(b'abc', 0, nlen=40))))       # name longer than attribute
mal.add(probe_resp(p2pie(devinfo(b'abcdef', 0, nlen=2))))     # name shorter than length
mal.add(probe_resp(p2pie(attr(13, A1 + bytes(2)))))           # device info cut
mal.add(probe_resp(p2pie(attr(14, bytes(10)))))               # client descriptor too short
mal.add(probe_resp(p2pie(ginfo(bytes([60]) + bytes(30)))))    # descriptor length past the attribute
mal.add(probe_resp(p2pie(ginfo(bytes([10]) + bytes(30)))))    # descriptor length < 24
c = bytearray(client(A1, b'abc', 0)); c[1 + 23] = 9                    # claims 9 secondary types
mal.add(probe_resp(p2pie(ginfo(bytes(c)))))
mal.add(probe_resp(p2pie(ginfo(client(A1, b'a', 9)))))        # secondary device types
mal.add(probe_resp(p2pie(ginfo(client(A1, b'a', ntype=0x1010)))))
mal.add(probe_resp(p2pie(ginfo(client(A1, b'abc', nlen=90)))))
mal.add(probe_resp(p2pie(ginfo(client(A1, b'abcd', nlen=2)))))
mal.add(probe_resp(p2pie(attr(13, A1 + struct.pack('>H', 1) + PRI + bytes([200])))))   # secondary types claim
mal.add(probe_resp(p2pie(attr(25, struct.pack('>IHB', 1, 2, 60) + b'abc'))))       # service name past end
mal.add(probe_resp(p2pie(attr(25, struct.pack('>IHB', 1, 2, 3)))))
mal.add(probe_resp(p2pie(attr(21, bytes(8)))))               # service hash not a multiple of 6
mal.add(probe_resp(p2pie(attr(11, CC + bytes([81, 200, 1])))))      # channel list count too big
mal.add(probe_resp(p2pie(attr(15, A1[:4]))))                 # group ID cut
mal.add(probe_resp(p2pie(attr(9, A1[:3]))))
mal.add(probe_resp(p2pie(attr(4, b''))))                      # empty attributes
mal.add(probe_resp(p2pie(attr(6, CC))))
mal.add(probe_resp(p2pie(attr(5, b'\x01'))))
mal.add(probe_resp(p2pie(attr(8, b'\x01\x02'))))
mal.add(probe_resp(p2pie(attr(24, bytes(6)))))
mal.add(probe_resp(p2pie(attr(26, bytes(6)))))
mal.add(probe_resp(p2pie(attr(0, b''))))
mal.add(probe_resp(p2pie(attr(1, b''))))
mal.add(probe_resp(p2pie(attr(10, b''))))
mal.add(probe_resp(p2pie(attr(18, b''))))
mal.add(probe_resp(p2pie(attr(19, CC))))
mal.add(probe_resp(p2pie(attr(23, b''))))
mal.add(probe_resp(p2pie(attr(17, CC))))
mal.add(probe_resp(p2pie(attr(2, b'\x01\x02', 300))))         # length past the IE
# ANQP
mal.add(gas_resp(adv, p2p_anqp(struct.pack('<HBBB', 2, 1, 1, 0) + b'\x00\x00')))   # response TLV len 2 (fixed)
mal.add(gas_resp(adv, p2p_anqp(struct.pack('<HBBBBB', 3, 1, 1, 0, 0, 0))))
mal.add(gas_req(adv, p2p_anqp(struct.pack('<HBBBB', 1, 1, 1, 0, 0))))               # request TLV len 1
mal.add(gas_req(adv, p2p_anqp(struct.pack('<HBBB', 200, 1, 1, 0))))                 # TLV past the end
mal.add(gas_req(adv, p2p_anqp(req_tlv(1, 1, b'a') + b'\x00')))                       # padding
mal.add(gas_resp(adv, p2p_anqp(resp_tlv(1, 1, 0, b'a') + b'\x00\x00')))
mal.add(gas_resp(adv, p2p_anqp(resp_tlv(4, 1, 0, b'\x00\x00\x03'))))                 # WFD cut
mal.add(pubact(0, 1, p2pie(attr(4, b''))))
mal.add(p2pact(0, 1, b''))
mal.add(pubact(0, 1, b'\xdd\x05\x50\x6f\x9a\x09\x01'))
mark(mal, 'malformed', n0)

out = sys.argv[1]
main.write(os.path.join(out, 'wifi-p2p-coverage.pcap'))
mal.write(os.path.join(out, 'wifi-p2p-coverage-malformed.pcap'))
if '-v' in sys.argv:
    for r in ranges: print(*r)
