#!/usr/bin/env python3
# Generates test/captures/wifi-display_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Wi-Fi Display coverage captures: usage mkwifi-display.py <outdir> [-v]
# Wi-Fi Display subelements travel in the WFA vendor IE (subtype 10) of
# probe/association frames and in P2P ANQP responses (service protocol 4).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlanlib import (
    A1, A2, A3, adv_proto_anqp, anqp_vendor, assoc_req, assoc_resp, gas_resp, Pcap, probe_req,
    probe_resp, tag, wfa_ie,
)

def sub(i, data, length=None):
    return struct.pack('>BH', i, len(data) if length is None else length) + data

def devinfo(dtype=1, bits=0, port=7236, tput=50):
    return sub(0, struct.pack('>HHH', (bits & ~3) | dtype, port, tput))

def bssid(a=A3):
    return sub(1, a)

def coupled(status=0, mac=A1, res=0):
    return sub(6, bytes([(res << 2) | status]) + mac)

def extcap(v):
    return sub(7, struct.pack('>H', v))

def altmac(a=A2):
    return sub(10, a)

def descr(addr, bss, info, tput, cs, cmac, extra=b''):
    d = addr + bss + struct.pack('>HH', info, tput) + bytes([cs]) + cmac + extra
    return bytes([len(d)]) + d

def session(*descrs):
    return sub(9, b''.join(descrs))

def wfd_ie(data):
    return wfa_ie(10, data)

main = Pcap(); mal = Pcap(); ranges = []
def mark(p, name, n0):
    ranges.append((name, n0 + 1, len(p.frames)))

# --- main capture -------------------------------------------------------
n0 = len(main.frames)
# Device Information: every device type and each flag bit alone
for dt in range(4):
    main.add(probe_req(wfd_ie(devinfo(dt, 0))))
for bit in range(2, 16):
    main.add(probe_resp(tag(0, b'DIRECT-xx-WFD') + wfd_ie(devinfo(1, 1 << bit, 7236 + bit, 100 + bit))))
main.add(probe_resp(wfd_ie(devinfo(3, 0xffff, 0xffff, 0xffff))))
mark(main, 'Device Information (types, every flag bit, all ones)', n0)

n0 = len(main.frames)
main.add(assoc_req(wfd_ie(devinfo(0, 0x0030, 7236, 20) + bssid())))
main.add(assoc_resp(wfd_ie(bssid(A1) + coupled(0) + extcap(0x0000))))
for st in range(4):
    main.add(assoc_req(wfd_ie(coupled(st, A3, 0x3f))))
main.add(assoc_req(wfd_ie(extcap(0xffff))))
for i in range(6):
    main.add(assoc_req(wfd_ie(extcap(1 << i))))
main.add(assoc_req(wfd_ie(altmac())))
main.add(probe_req(wfd_ie(devinfo() + bssid() + coupled() + extcap(0x0011) + altmac())))
mark(main, 'Associated BSSID, Coupled Sink, Extended Capability, Alternative MAC', n0)

n0 = len(main.frames)
# Session information: one descriptor, several, extra info, all flag bits
main.add(probe_resp(wfd_ie(session(descr(A1, A2, 0x0001, 30, 0, A3)))))
main.add(probe_resp(wfd_ie(session(descr(A1, A2, 0x1fff, 30, 1, A3),
                                     descr(A2, A3, 0xffff, 300, 2, A1),
                                     descr(A3, A1, 0x0000, 0, 3, A2)))))
main.add(probe_resp(wfd_ie(session(descr(A1, A2, 0x2d85, 66, 1, A3, b'\xde\xad\xbe\xef'),
                                     descr(A3, A2, 0x0102, 7, 0, A1, b'\x01')))))
for bit in range(2, 16):
    main.add(probe_resp(wfd_ie(session(descr(A1, A2, 1 << bit, 1, 0, A3)))))
main.add(probe_resp(wfd_ie(session())))   # empty list
mark(main, 'Session Information (1-3 descriptors, extra info, every flag bit, empty)', n0)

n0 = len(main.frames)
# Subelements the dissector only reports as unknown payload (valid IDs)
for i in (2, 3, 4, 5, 8):
    main.add(probe_req(wfd_ie(devinfo() + sub(i, bytes(range(10))))))
main.add(probe_req(wfd_ie(sub(99, b'\x01\x02'))))
mark(main, 'Subelements without a decoder (2,3,4,5,8 and an unknown ID)', n0)

n0 = len(main.frames)
# Longest IE and subelement list that fits an IE: devinfo*? 250 bytes of subelements
body = devinfo() + altmac() + bssid() + coupled() + extcap(3) + altmac(A1)
main.add(probe_resp(wfd_ie(body)))
# Subelement lengths just under the limits (exactly the minimum)
main.add(probe_req(wfd_ie(sub(0, bytes(6)) + sub(1, bytes(6)) + sub(6, bytes(7)) +
                          sub(7, bytes(2)) + sub(10, bytes(6)))))
mark(main, 'Many subelements, minimum lengths', n0)

n0 = len(main.frames)
# P2P ANQP responses (GAS, Wi-Fi Alliance P2P ANQP) with service protocol 4 = WFD
def p2p_anqp_resp(tlvs, sui=1):
    return anqp_vendor(9, struct.pack('<H', sui) + tlvs)
def svc_tlv(proto, tid, status, data):
    return struct.pack('<HBBB', 3 + len(data), proto, tid, status) + data
adv = adv_proto_anqp()
wfd = devinfo(1, 0x0010, 7236, 50) + altmac()
main.add(gas_resp(adv, p2p_anqp_resp(svc_tlv(4, 1, 0, wfd))))
main.add(gas_resp(adv, p2p_anqp_resp(svc_tlv(4, 2, 0, session(descr(A1, A2, 0x0141, 5, 1, A3, b'\x00\x00'))))))
mark(main, 'Wi-Fi Display in P2P ANQP service responses', n0)

# --- malformed capture --------------------------------------------------
n0 = len(mal.frames)
mal.add(probe_req(wfd_ie(sub(0, bytes(5)))))                       # device info len < 6 (fixed)
mal.add(probe_req(wfd_ie(sub(0, b''))))
mal.add(probe_req(wfd_ie(b'\x00\x00')))                            # header < 3 bytes (fixed)
mal.add(probe_req(wfd_ie(devinfo() + b'\x00')))
mal.add(probe_req(wfd_ie(devinfo() + b'\x07\x00')))
mal.add(probe_req(wfd_ie(sub(1, bytes(5)))))                       # associated BSSID short
mal.add(probe_req(wfd_ie(sub(6, b''))))                            # coupled sink empty
mal.add(probe_req(wfd_ie(sub(6, bytes(4)))))                       # coupled sink MAC cut
mal.add(probe_req(wfd_ie(sub(7, b'\x01'))))                        # ext capab short
mal.add(probe_req(wfd_ie(sub(10, bytes(3)))))                      # alt MAC short
mal.add(probe_req(wfd_ie(sub(0, bytes(6), 40))))                   # length past end
mal.add(probe_req(wfd_ie(sub(9, bytes([22]) + bytes(22)))))        # descriptor < 23
mal.add(probe_req(wfd_ie(sub(9, bytes([40]) + bytes(23)))))        # descriptor past end
mal.add(probe_req(wfd_ie(sub(9, descr(A1, A2, 1, 1, 0, A3) + bytes([30]) + bytes(5)))))
mal.add(probe_req(wfd_ie(sub(9, bytes([0])))))                     # zero length descriptor
mal.add(probe_req(wfd_ie(sub(9, descr(A1, A2, 1, 1, 0, A3)[:-2], ))))  # first descriptor cut
mal.add(gas_resp(adv, p2p_anqp_resp(svc_tlv(4, 3, 0, sub(0, bytes(3)) + b'\x01'))))
mark(mal, 'malformed', n0)

out = sys.argv[1]
main.write(os.path.join(out, 'wifi-display-coverage.pcap'))
mal.write(os.path.join(out, 'wifi-display-coverage-malformed.pcap'))
if '-v' in sys.argv:
    for r in ranges: print(*r)
