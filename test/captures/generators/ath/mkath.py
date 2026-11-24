#!/usr/bin/env python3
# Generates test/captures/ath_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ATH (Apache Tribes
Heartbeat) dissector (packet-ath.c).

All packets are built from scratch with struct; no captured traffic is
used. Three Tomcat cluster members (192.0.2.7, 192.0.2.8, 2001:db8::7)
send membership heartbeats from UDP port 45565 to the multicast group
228.0.0.4 port 45564, the port ATH is registered on.

Usage: mkath.py <output directory>

Writes:
  ath-coverage.pcap            Tomcat 6 and Tomcat 7/8 heartbeats: IPv4 and
                               IPv6 hosts, default and named domain, no
                               command, the BABY-ALEX shutdown command and
                               another command, payloads, and a UDP
                               datagram to port 45564 that is not ATH
  ath-coverage-malformed.pcap  invalid host lengths, a command length of
                               -1, an unknown end mark, truncated packets
"""

import struct
import sys

ATH_PORT = 45564
SRC_PORT = 45565
GROUP4 = bytes((228, 0, 0, 4))
GROUP6 = bytes.fromhex('ff0200000000000000000000000000fa')  # link-local multicast group

HOST_A = bytes((192, 0, 2, 7))
HOST_B = bytes((192, 0, 2, 8))
HOST_6 = bytes.fromhex('20010db8000000000000000000000007')


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def udp4(self, src, payload, dport=ATH_PORT, sport=SRC_PORT, dst=GROUP4):
        u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
        pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(u))
        u = u[:6] + struct.pack('>H', checksum(pseudo + u) or 0xffff) + u[8:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), len(self.frames) & 0xffff,
                         0x4000, 3, 17, 0, src, dst)
        ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
        eth = b'\x01\x00\x5e' + dst[1:] + b'\x02\x00\x00\x00\x00' + src[3:4] + b'\x08\x00'
        self.frames.append(eth + ip + u)

    def udp6(self, src, payload, dport=ATH_PORT, sport=SRC_PORT, dst=GROUP6):
        u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
        pseudo = src + dst + struct.pack('>IxxxB', len(u), 17)
        u = u[:6] + struct.pack('>H', checksum(pseudo + u) or 0xffff) + u[8:]
        ip = struct.pack('>IHBB16s16s', 0x60000000, len(u), 17, 3, src, dst)
        eth = b'\x33\x33' + dst[12:] + b'\x02\x00\x00\x00\x00\x16' + b'\x86\xdd'
        self.frames.append(eth + ip + u)

    def heartbeat(self, host, payload):
        if len(host) == 16:
            self.udp6(host, payload)
        else:
            self.udp4(host if len(host) == 4 else HOST_A, payload)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i, 500000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def unique(n):
    return bytes((n * 17 + i * 31) & 0xff for i in range(16))


def member(host, command=b'', domain=b'', payload=b'', alive=123456, port=4000,
           sport=-1, uport=-1, uid=0, clen=None, hlen=None):
    """The part of a member's data after the length field, as in Tomcat's
    MemberImpl.getData(). clen/hlen override the encoded lengths."""
    return (struct.pack('>QIi', alive, port, sport), struct.pack('>i', uport),
            struct.pack('>B', len(host) if hlen is None else hlen) + host +
            struct.pack('>i', len(command) if clen is None else clen) + command +
            struct.pack('>i', len(domain)) + domain + unique(uid) +
            struct.pack('>i', len(payload)) + payload)


def tomcat6(host, **kw):
    a, _, rest = member(host, **kw)
    body = a + rest
    return b'TRIBES-B' + struct.pack('>I', len(body)) + body + b'TRIBES-E'


def tomcat7(host, **kw):
    a, b, rest = member(host, **kw)
    body = a + b + rest
    return b'TRIBES-B\x01\x00' + struct.pack('>I', len(body)) + body + b'TRIBES-E\x01\x00'


SHUTDOWN = b'BABY-ALEX'


def main_capture(cap):
    # Frames 1-9: Tomcat 7/8 heartbeats
    cap.heartbeat(HOST_A, tomcat7(HOST_A, domain=b'cluster-a', uid=1))                    # 1
    cap.heartbeat(HOST_B, tomcat7(HOST_B, uid=2, sport=4443, uport=4002))                # 2 default domain
    # 3: the reproducer of the IPv6 fix: a 16 octet host used to be shown
    # as "invalid IP length" and the rest of the packet was not decoded
    cap.heartbeat(HOST_6, tomcat7(HOST_6, domain=b'dom', uid=3, port=4001))              # 3
    cap.heartbeat(HOST_6, tomcat7(HOST_6, uid=3, port=4001, alive=223456))               # 4 IPv6, default domain
    cap.heartbeat(HOST_A, tomcat7(HOST_A, command=b'PING', domain=b'cluster-a', uid=1))  # 5 command, domain
    cap.heartbeat(HOST_B, tomcat7(HOST_B, command=b'PING', uid=2))                       # 6 command, default domain
    cap.heartbeat(HOST_A, tomcat7(HOST_A, payload=b'jvmRoute=node1;weight=1', domain=b'cluster-a', uid=1))  # 7
    cap.heartbeat(HOST_6, tomcat7(HOST_6, command=SHUTDOWN, domain=b'dom', uid=3))       # 8 leaving domain
    cap.heartbeat(HOST_B, tomcat7(HOST_B, command=SHUTDOWN, uid=2))                      # 9 leaving default domain
    # Frames 10-17: Tomcat 6 heartbeats
    cap.heartbeat(HOST_A, tomcat6(HOST_A, domain=b'cluster-6', uid=11))                  # 10
    cap.heartbeat(HOST_B, tomcat6(HOST_B, uid=12, sport=4443))                           # 11 default domain
    cap.heartbeat(HOST_6, tomcat6(HOST_6, domain=b'dom6', uid=13))                       # 12 IPv6
    cap.heartbeat(HOST_6, tomcat6(HOST_6, uid=13))                                       # 13 IPv6, default
    cap.heartbeat(HOST_A, tomcat6(HOST_A, command=b'PING', domain=b'cluster-6', uid=11,
                                  payload=b'jvmRoute=node6'))                            # 14
    cap.heartbeat(HOST_B, tomcat6(HOST_B, command=b'PING', uid=12))                      # 15
    cap.heartbeat(HOST_A, tomcat6(HOST_A, command=SHUTDOWN, domain=b'cluster-6', uid=11))  # 16
    cap.heartbeat(HOST_6, tomcat6(HOST_6, command=SHUTDOWN, uid=13))                     # 17
    # 18: something else sent to port 45564: not ATH, shown as data
    cap.udp4(HOST_B, b'hello, not a heartbeat')                                         # 18


def malformed_capture(cap):
    # 1-4: the ath_hlen.py reproducer frames 3 and 4 and
    # variants: a host length other than 4 or 16 is an error expert info
    cap.heartbeat(HOST_A, tomcat7(bytes.fromhex('20010db80007'), uid=4))                # 1 hlen 6
    cap.heartbeat(HOST_A, tomcat7(b'', uid=4))                                          # 2 hlen 0
    cap.heartbeat(HOST_A, tomcat6(bytes.fromhex('20010db80007'), uid=4))                # 3 Tomcat 6 hlen 6
    cap.heartbeat(HOST_A, tomcat7(HOST_A, hlen=16, uid=4))                              # 4 hlen 16, 4 octets
    # 5-6: command length -1 (offset moves back one octet)
    cap.heartbeat(HOST_A, tomcat7(HOST_A, clen=-1, uid=5))                              # 5
    cap.heartbeat(HOST_A, tomcat6(HOST_A, clen=-1, uid=5))                              # 6
    # 7-8: TRIBES-B but neither end mark: "not an ATH packet"
    cap.udp4(HOST_A, b'TRIBES-B\x01\x00' + b'\0' * 30 + b'TRIBES-X')                    # 7
    cap.udp4(HOST_A, b'TRIBES-B')                                                       # 8 begin mark only
    # 9-10: truncated: end mark right after the host
    cap.udp4(HOST_A, b'TRIBES-B\x01\x00' + b'\0' * 24 + b'\x04' + HOST_A + b'\x01\x00')  # 9 Tomcat 7
    cap.udp4(HOST_A, b'TRIBES-B' + b'\0' * 20 + b'\x04' + HOST_A + b'-E')               # 10 Tomcat 6
    # 11: a command length past the end of the packet
    cap.heartbeat(HOST_A, tomcat7(HOST_A, clen=1000, uid=6))                            # 11


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    main_capture(cap)
    cap.write(outdir + '/ath-coverage.pcap')
    cap = Pcap()
    malformed_capture(cap)
    cap.write(outdir + '/ath-coverage-malformed.pcap')


if __name__ == '__main__':
    main()
