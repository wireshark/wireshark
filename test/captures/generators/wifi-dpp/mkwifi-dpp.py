#!/usr/bin/env python3
# Generates test/captures/wifi-dpp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Wi-Fi DPP coverage captures: usage mkwifi-dpp.py <outdir> [-v]
# DPP public action frames (WFA subtype 26), the DPP configuration protocol in
# GAS frames (vendor specific advertisement protocol), a generic DPP IE and
# ANQP element, and DPP over TCP (port 7871). All cryptographic fields
# (keys, nonces, hashes, wrapped data, tags) are opaque made-up bytes.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlanlib import (
    A1, A2, adv_proto_anqp, adv_proto_vs, anqp_vendor, assoc_req, beacon, gas_comeback_resp,
    gas_req, gas_resp, PcapNg, probe_req, public_action_vendor, tag, WFA, wfa_ie,
)

def at(i, data, length=None):
    return struct.pack('<HH', i, len(data) if length is None else length) + data

def pat(n, b=0xa5):
    return bytes((b + i) & 0xff for i in range(n))

def status(v): return at(0x1000, bytes([v]))
def ihash(): return at(0x1001, pat(32, 1))
def rhash(): return at(0x1002, pat(32, 2))
def ikey(): return at(0x1003, pat(64, 3))
def wrapped(n=48): return at(0x1004, pat(n, 4))
def inonce(n=16): return at(0x1005, pat(n, 5))
def icap(v=1): return at(0x1006, bytes([v]))
def rnonce(): return at(0x1007, pat(16, 7))
def rcap(v=2): return at(0x1008, bytes([v, 0]))
def rkey(): return at(0x1009, pat(64, 9))
def itag(): return at(0x100a, pat(32, 10))
def rtag(): return at(0x100b, pat(32, 11))
def cfgobj(): return at(0x100c, b'{"wi-fi_tech":"infra","discovery":{"ssid":"mynet"}}')
def connector(): return at(0x100d, b'eyJ0eXAiOiJkcHBDb24ifQ.e30.c2ln')
def cfgattrs(): return at(0x100e, b'{"name":"x","wi-fi_tech":"infra"}')
def bootkey(): return at(0x100f, pat(90, 12))
def group(v=19): return at(0x1012, struct.pack('<H', v))
def enckey(): return at(0x1013, pat(64, 13))
def enonce(): return at(0x1014, pat(16, 14))
def codeid(): return at(0x1015, b'identifier')
def transid(v=1): return at(0x1016, bytes([v]))
def bootinfo(): return at(0x1017, pat(10, 17))
def channel(oc=81, ch=6): return at(0x1018, bytes([oc, ch]))
def version(v=2): return at(0x1019, bytes([v]))
def envelope(): return at(0x101a, pat(20, 18))
def sendconn(): return at(0x101b, b'')
def connstatus(): return at(0x101c, b'{"result":0}')
def reconf(): return at(0x101d, b'\x00')
def csignhash(): return at(0x101e, pat(32, 19))
def csrattr(): return at(0x101f, pat(12, 20))
def anonce(): return at(0x1020, pat(16, 21))
def eprime(): return at(0x1021, pat(24, 22))
def unknown(): return at(0x1fff, b'\x01\x02\x03')

def pa(sub, attrs, suite=1):
    return public_action_vendor(26, bytes([suite, sub]) + attrs)

main = PcapNg(); mal = PcapNg(); ranges = []
def mark(p, name, n0):
    ranges.append((name, n0 + 1, len(p.frames)))

n0 = len(main.frames)
# --- public action frames, every subtype ---
main.add(pa(0, ihash() + rhash() + ikey() + wrapped() + channel() + version()))
main.add(pa(1, status(0) + rhash() + ihash() + transid() + version() + rkey() + wrapped(80) + rnonce() * 0 + rcap(2) + inonce()))
main.add(pa(2, status(0) + rhash() + wrapped(32)))
main.add(pa(5, transid() + connector() + version()))
main.add(pa(6, transid() + status(0) + connector() + version()))
main.add(pa(7, group() + enckey() + codeid()))
main.add(pa(8, status(0) + group() + enckey() + codeid()))
main.add(pa(9, wrapped(100)))
main.add(pa(10, wrapped(100)))
main.add(pa(11, wrapped(40)))
main.add(pa(12, wrapped(40) + status(0)))
main.add(pa(13, rhash() + ihash() + csignhash()))
main.add(pa(14, csignhash() + anonce() + eprime()))
main.add(pa(15, csignhash() + anonce() + eprime() + wrapped(30)))
main.add(pa(16, status(1) + anonce() + wrapped(30)))
main.add(pa(17, status(0) + wrapped(30)))
main.add(pa(99, unknown(), suite=2))      # unknown subtype, another crypto suite
main.add(pa(3, b''))                      # no attributes
mark(main, 'DPP public action frames (every subtype 0-2, 5-17, unknown, empty)', n0)

n0 = len(main.frames)
# every attribute (also those that only get the generic decoding)
every = [status(0), ihash(), rhash(), ikey(), wrapped(), inonce(), icap(1), rnonce(), rcap(1), rkey(), itag(), rtag(),
         cfgobj(), connector(), cfgattrs(), bootkey(), group(), enckey(), enonce(), codeid(), transid(), bootinfo(),
         channel(), version(1), envelope(), sendconn(), connstatus(), reconf(), csignhash(), csrattr(), anonce(),
         eprime(), unknown()]
for i, a in enumerate(every):
    main.add(pa(i % 17, a + status(i % 14) if i % 2 else a + transid(i)))
main.add(pa(0, b''.join(every)))
for st in range(14):
    main.add(pa(2, status(st)))
mark(main, 'every DPP attribute and every status value', n0)

n0 = len(main.frames)
# --- generic IE and ANQP element ---
main.add(probe_req(wfa_ie(26, b'\x01\x02\x03\x04')))
main.add(beacon(tag(0, b'dpp-net') + wfa_ie(26, pat(20))))
main.add(assoc_req(wfa_ie(26, b'')))
adv = adv_proto_anqp()
main.add(gas_req(adv, anqp_vendor(26, pat(10))))
main.add(gas_resp(adv, anqp_vendor(26, pat(30))))
mark(main, 'generic DPP IE and ANQP element', n0)

n0 = len(main.frames)
# --- DPP configuration protocol in GAS ---
dadv = adv_proto_vs(WFA, 26, 1)
main.add(gas_req(dadv, enonce() + wrapped(40)))
main.add(gas_req(dadv, at(0x1020, pat(16)) + csrattr()))
main.add(gas_resp(dadv, status(0) + wrapped(60)))
main.add(gas_resp(dadv, b''))                                  # empty response
main.add(gas_comeback_resp(dadv, status(0) + wrapped(30), 0, False))      # single fragment
main.add(gas_comeback_resp(dadv, status(0) + enonce() + wrapped(30)[:20], 0, True, token=2))   # fragment 0 of 2
main.add(gas_comeback_resp(dadv, wrapped(30)[20:] + cfgobj(), 1, False, token=2))              # fragment 1
main.add(gas_comeback_resp(adv_proto_vs(WFA, 26, 2), pat(12), 0, False, token=3))              # other DPP subtype
main.add(gas_comeback_resp(adv_proto_vs(WFA, 27, 1), pat(12), 0, False, token=4))              # other WFA subtype
mark(main, 'DPP configuration protocol in GAS initial and comeback responses (with reassembly)', n0)

# --- DPP over TCP ---
def eth_ip_tcp(sp, dp, seq, ack, flags, payload, src='192.0.2.10', dst='192.0.2.20', rev=False):
    opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 2 else b''
    ip_s = bytes(map(int, (dst if rev else src).split('.')))
    ip_d = bytes(map(int, (src if rev else dst).split('.')))
    tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) + ip_s + ip_d
    macs = (A2 + A1) if rev else (A1 + A2)
    return macs + b'\x08\x00' + ip + tcp

class Flow:
    def __init__(self, sport=40000, dport=7871):
        self.cseq = 1000; self.sseq = 5000; self.sp = sport; self.dp = dport
    def syn(self, cap):
        cap.add(eth_ip_tcp(self.sp, self.dp, self.cseq, 0, 0x02, b''))
        cap.add(eth_ip_tcp(self.dp, self.sp, self.sseq, self.cseq + 1, 0x12, b'', rev=True))
        self.cseq += 1; self.sseq += 1
        cap.add(eth_ip_tcp(self.sp, self.dp, self.cseq, self.sseq, 0x10, b''))
    def c(self, cap, data):
        cap.add(eth_ip_tcp(self.sp, self.dp, self.cseq, self.sseq, 0x18, data)); self.cseq += len(data)
    def s(self, cap, data):
        cap.add(eth_ip_tcp(self.dp, self.sp, self.sseq, self.cseq, 0x18, data, rev=True)); self.sseq += len(data)

def pdu(action, body):
    d = bytes([action]) + body
    return struct.pack('>I', len(d)) + d
def pdu_public(sub, attrs):
    return pdu(9, WFA + bytes([26, 1, sub]) + attrs)
def pdu_cfgreq(attrs, token=1):
    return pdu(0x0a, bytes([token]) + b'\x6c\x08\x7f' + b'\xdd\x05' + WFA + b'\x1a\x01' + struct.pack('<H', len(attrs)) + attrs)
def pdu_cfgresp(attrs, token=1, frag=None):
    action = 0x0d if frag is not None else 0x0b
    body = bytes([token]) + struct.pack('<H', 0)
    if frag is not None: body += bytes([frag])
    body += struct.pack('<H', 0) + b'\x6c\x08\x7f' + b'\xdd\x05' + WFA + b'\x1a\x01' + struct.pack('<H', len(attrs)) + attrs
    return pdu(action, body)


n0 = len(main.frames)
# --- DPP over TCP port 7871 ---
def E(cap, frame):
    cap.add(frame, link=1)
def tcp_c(f, cap, data):
    E(cap, eth_ip_tcp(f.sp, f.dp, f.cseq, f.sseq, 0x18, data)); f.cseq += len(data)
def tcp_s(f, cap, data):
    E(cap, eth_ip_tcp(f.dp, f.sp, f.sseq, f.cseq, 0x18, data, rev=True)); f.sseq += len(data)
def tcp_syn(f, cap):
    E(cap, eth_ip_tcp(f.sp, f.dp, f.cseq, 0, 0x02, b''))
    E(cap, eth_ip_tcp(f.dp, f.sp, f.sseq, f.cseq + 1, 0x12, b'', rev=True))
    f.cseq += 1; f.sseq += 1
    E(cap, eth_ip_tcp(f.sp, f.dp, f.cseq, f.sseq, 0x10, b''))

fl = Flow(); tcp_syn(fl, main)
tcp_c(fl, main, pdu_public(0, ihash() + rhash() + ikey() + wrapped()))
tcp_s(fl, main, pdu_public(1, status(0) + rhash() + ihash() + rkey() + wrapped()))
tcp_c(fl, main, pdu_public(2, status(0) + wrapped(32)))
tcp_c(fl, main, pdu_cfgreq(enonce() + wrapped(40)))
tcp_s(fl, main, pdu_cfgresp(status(0) + wrapped(60)))
tcp_c(fl, main, pdu_cfgreq(csrattr(), token=2))
tcp_s(fl, main, pdu_cfgresp(b'', token=2))                       # response without attributes
tcp_s(fl, main, pdu_cfgresp(cfgobj(), token=3, frag=0))          # fragmented response PDU type
tcp_c(fl, main, pdu(0x55, b'\x01\x02'))                          # unknown action
# two PDUs in one segment, a PDU over two segments, a header split
two = pdu_public(5, transid() + connector()) + pdu_public(6, transid() + status(0))
tcp_c(fl, main, two)
big = pdu_public(0, wrapped(200) + ihash())
tcp_c(fl, main, big[:30]); tcp_c(fl, main, big[30:])
tcp_s(fl, main, pdu_public(11, wrapped(20))[:2]); tcp_s(fl, main, pdu_public(11, wrapped(20))[2:])
tcp_c(fl, main, pdu_public(12, wrapped(20) + status(0)))
mark(main, 'DPP over TCP 7871 (Ethernet): public action, configuration request and response PDUs, reassembly', n0)

# --- malformed ---
n0 = len(mal.frames)
mal.add(pa(0, b'\x00\x10\x01'))                  # attribute header cut
mal.add(pa(0, b'\x00\x10\x20\x00\x01\x02'))      # attribute length past the end
mal.add(pa(0, at(0x1000, b'')))                  # status without data
mal.add(pa(0, at(0x1016, b'')))                  # transaction ID without data
mal.add(pa(0, at(0x1012, b'\x01')))              # finite cyclic group, 1 octet
mal.add(pa(0, at(0x1006, b'')))                  # initiator capabilities empty
mal.add(pa(0, at(0x1018, b'\x01')))              # channel, 1 octet
mal.add(pa(0, at(0x1019, b'')))
mal.add(pa(0, at(0x1003, b'')))                  # empty protocol key
mal.add(pa(0, at(0x1003, b'\x01')))              # protocol key of 1 octet
mal.add(pa(0, at(0x1000, b'\x00', 200)))
mal.add(public_action_vendor(26, b'\x01'))       # public action cut after the crypto suite
mal.add(public_action_vendor(26, b''))
mal.add(gas_req(dadv, b'\x14\x10\x05'))
mal.add(gas_resp(dadv, b'\x14\x10\x05\x00\x01'))
mal.add(gas_comeback_resp(dadv, b'\x14\x10\x05\x00\x01', 0, False, token=7))
mal.add(gas_req(dadv, b''))
mal.add(wfa_ie(26, b'')[:3])
# TCP
fl = Flow(40001); tcp_syn(fl, mal)
tcp_c(fl, mal, struct.pack('>I', 3) + b'\x09\x50\x6f')                 # action 9 cut after the OUI start
tcp_c(fl, mal, struct.pack('>I', 6) + b'\x09' + WFA + b'\x1a')           # no crypto suite
tcp_c(fl, mal, struct.pack('>I', 5) + b'\x0a\x01\x6c\x08\x7f')       # configuration request cut
tcp_s(fl, mal, struct.pack('>I', 6) + b'\x0b\x01\x00\x00\x00\x00')  # configuration response cut
tcp_s(fl, mal, struct.pack('>I', 0xffff0000) + b'\x09')                # huge length, never completes
mark(mal, 'malformed', n0)

out = sys.argv[1]
main.write(os.path.join(out, 'wifi-dpp-coverage.pcapng'))
mal.write(os.path.join(out, 'wifi-dpp-coverage-malformed.pcapng'))
if '-v' in sys.argv:
    for r in ranges: print(*r)
