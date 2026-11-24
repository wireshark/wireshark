#!/usr/bin/env python3
# Generates test/captures/netgear_ensemble_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Netgear Ensemble (NGE) captures. Usage: mknetgear-ensemble.py <outdir> [-v]
# NGE registers no port (only Decode As for udp.port, 4554 by convention):
# the main capture is pcapng with two interfaces, Ethernet (UDP 4554, shown
# with -d udp.port==4554,nge) and Exported PDU (linktype 252) naming "nge".
import struct
import sys
import os

def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)

def pcapng(fn, pkts):
    """pkts: list of (ifid, bytes)."""
    def block(t, body):
        n = 12 + len(body)
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))
    out += block(1, struct.pack('<HHI', 252, 0, 65535))
    for i, (ifid, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i
        out += block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(p), len(p)) + pad4(p))
    open(fn, 'wb').write(out)

def ip_udp(payload, sport=4554, dport=4554):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0) + bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 2])
    s = sum(struct.unpack('>10H', ip)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + udp

def exp_pdu(name, payload):
    n = pad4(name.encode())
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

def lv(s):
    return struct.pack('>I', len(s)) + s

def ens(ensname=b'home', fw=b'fw-1', region=b'US', ver=b'1.0.2', ap=b'ap-kitchen',
        uuid=b'\x11' * 16, ip=(192, 0, 2, 7), mac=b'\x02\x00\x00\x00\x00\x07', uptime=3600,
        tail=b'', unk=(1, 2, 0)):
    return (b'\0' * 17 + struct.pack('>I', unk[0]) + uuid + bytes(ip) + b'\x00' * 20 + mac +
            struct.pack('>I', unk[1]) + lv(ensname) + lv(fw) + lv(region) + struct.pack('>I', unk[2]) +
            lv(ver) + b'\x00' * 16 + struct.pack('>I', uptime) + lv(ap) + tail)

def msg(e, seq=1, version=1, length=None, hdr=b'\0\0\0'):
    return struct.pack('>B', version) + hdr + struct.pack('>I', seq) + struct.pack('>I', len(e) if length is None else length) + e

frames = []; marks = []
def add(p, label, ifid=0):
    frames.append((ifid, p)); marks.append((len(frames), label))
def udp(m, label): add(ip_udp(m), label, 0)
def epdu(m, label): add(exp_pdu('nge', m), label, 1)

udp(msg(ens(tail=b'\xde\xad\xbe\xef')), 'Basic message with a 4 octet trailer')
udp(msg(ens(ensname=b'', fw=b'', region=b'', ver=b'', ap=b'', tail=b'\x00'), seq=2), 'All strings empty')
udp(msg(ens(ensname=b'E' * 200, fw=b'F' * 100, region=b'R' * 50, ver=b'V' * 60, ap=b'A' * 80, tail=b'tail' * 20), seq=3), 'Long strings')
udp(msg(ens(ensname='häus'.encode('utf-8'), ap=b'ap\xffbin\x01', tail=b'x'), seq=0xffffffff, version=2, hdr=b'\x01\x02\x03'),
    'Non-ASCII names, version 2, sequence 0xffffffff')
udp(msg(ens(uuid=bytes(range(16)), ip=(255, 255, 255, 255), mac=b'\xff' * 6, uptime=0xffffffff,
            unk=(0xffffffff, 0xffffffff, 0xffffffff), tail=b'\x00' * 3), seq=4), 'Maximum numeric values')
udp(msg(ens(tail=b'a'), seq=5, length=0), 'TLV length 0')
udp(msg(ens(tail=b'a'), seq=6, length=0x100), 'TLV length 256 (more than the data)')
# the reproducers of "NGE: Avoid overflow of the ensemble subtree length", with a trailer
udp(msg(ens(tail=b'tr'), seq=7, length=0x7FFFFFFF), 'TLV length 0x7FFFFFFF (reproducer)')
udp(msg(ens(tail=b'tr'), seq=8, length=0xFFFFFFFE), 'TLV length 0xFFFFFFFE (reproducer)')
udp(msg(ens(tail=b'tr'), seq=9, length=0x7FFFFFFB), 'TLV length INT_MAX - 4')
udp(msg(ens(tail=b'tr'), seq=10, length=0x7FFFFFFC), 'TLV length INT_MAX - 3 (sum above INT_MAX)')
udp(msg(ens(tail=b'tr'), seq=11, length=0xFFFFFFFF), 'TLV length 0xFFFFFFFF')
epdu(msg(ens(tail=b'tr'), seq=12), 'Exported PDU nge, basic')
epdu(msg(ens(tail=b'tr'), seq=13, length=0x7FFFFFFF), 'Exported PDU nge, TLV length 0x7FFFFFFF')
epdu(msg(ens(tail=b'tr'), seq=14, length=0xFFFFFFFE), 'Exported PDU nge, TLV length 0xFFFFFFFE')
udp(msg(ens(tail=b'x'), seq=15), 'Second source port'); frames[-1] = (0, ip_udp(msg(ens(tail=b'x'), seq=15), sport=1234, dport=4554))

pcapng(os.path.join(sys.argv[1], 'netgear-ensemble-coverage.pcapng'), frames)
if '-v' in sys.argv:
    for n, l in marks: print(n, l)
    print(len(frames), 'frames')

mal = []
ok = ens()
mal.append((0, ip_udp(msg(ok))))                                  # no trailing data after the AP name (exception)
mal.append((1, exp_pdu('nge', msg(ok, length=0x7FFFFFFF))))       # same, Exported PDU, reproducer length
mal.append((0, ip_udp(msg(ok)[:8])))                              # only the header
mal.append((0, ip_udp(msg(ok)[:12])))                             # length field, no ensemble
mal.append((0, ip_udp(msg(ok)[:20])))                             # cut in the first unknown block
mal.append((0, ip_udp(msg(ok)[:60])))                             # cut in the MAC
mal.append((0, ip_udp(msg(ok)[:75])))                             # cut in the ensemble name length
mal.append((0, ip_udp(msg(ens(ensname=b'x' * 10) )[:77 + 4])))    # string cut short
mal.append((0, ip_udp(struct.pack('>B3sII', 1, b'\0\0\0', 1, 0) + b'\0' * 17 + struct.pack('>I', 1) + b'\0' * 16 + bytes(4) + bytes(20) + bytes(6) + struct.pack('>I', 2) + struct.pack('>I', 0xffffffff) + b'abc')))  # string length 0xffffffff
b = msg(ens(ap=b'ap'))
mal.append((0, ip_udp(b[:-2])))                                    # AP name cut short
mal.append((0, ip_udp(b'')))                                      # empty payload
mal.append((0, ip_udp(b'\x01')))                                  # one octet
pcapng(os.path.join(sys.argv[1], 'netgear-ensemble-coverage-malformed.pcapng'), mal)
