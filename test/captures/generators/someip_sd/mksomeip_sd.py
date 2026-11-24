#!/usr/bin/env python3
# Generates test/captures/someip_sd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic SOME/IP-SD captures. Usage: mksomeip_sd.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib_s9 import Stream, write_pcap, udp_pkt

SD_PORT = 30490
A = '192.0.2.10'      # the server ECU
B = '192.0.2.11'      # the client ECU
MC = '239.192.255.250'


def someip(service, method, client, session, payload, mtype=0x00, rc=0, iver=1, pver=1, length=None):
    if length is None:
        length = 8 + len(payload)
    return struct.pack('>HHIHHBBBB', service, method, length, client, session,
                       pver, iver, mtype, rc) + payload


# ---- entries ----
def entry_service(etype, service, instance, major, ttl, minor, i1=0, i2=0, n1=0, n2=0):
    return (struct.pack('>BBBB', etype, i1, i2, (n1 << 4) | n2)
            + struct.pack('>HHB', service, instance, major) + struct.pack('>I', ttl)[1:]
            + struct.pack('>I', minor))


def entry_eg(etype, service, instance, major, ttl, eg, counter=0, init=False, i1=0, i2=0, n1=0, n2=0,
             res=0, res2=0):
    return (struct.pack('>BBBB', etype, i1, i2, (n1 << 4) | n2)
            + struct.pack('>HHB', service, instance, major) + struct.pack('>I', ttl)[1:]
            + struct.pack('>BBH', res, (0x80 if init else 0) | (res2 << 4) | counter, eg))


# ---- options ----
def opt_ipv4(otype, ip, proto, port, length=9):
    return (struct.pack('>HBB', length, otype, 0) + bytes(map(int, ip.split('.')))
            + b'\x00' + bytes([proto]) + struct.pack('>H', port))


def opt_ipv6(otype, ip6, proto, port, length=21):
    return (struct.pack('>HBB', length, otype, 0) + ip6 + b'\x00' + bytes([proto])
            + struct.pack('>H', port))


def opt_config(elements, trailer=b'\x00'):
    s = b''.join(bytes([len(e)]) + e for e in elements) + trailer
    return struct.pack('>HBB', 1 + len(s), 0x01, 0) + s


def opt_config_raw(s):
    return struct.pack('>HBB', 1 + len(s), 0x01, 0) + s


def opt_lb(prio, weight):
    return struct.pack('>HBBHH', 5, 0x02, 0, prio, weight)


def opt_unknown(otype, data=b'', reserved=True):
    body = (b'\x00' if reserved else b'') + data
    return struct.pack('>HB', len(body), otype) + body


def sd(entries, options, flags=0xc0, reserved=0, entries_len=None, options_len=None):
    e = b''.join(entries)
    o = b''.join(options)
    return (struct.pack('>B', flags) + struct.pack('>I', reserved)[1:]
            + struct.pack('>I', len(e) if entries_len is None else entries_len) + e
            + struct.pack('>I', len(o) if options_len is None else options_len) + o)


SDMSG = {'service': 0xffff, 'method': 0x8100, 'client': 0, 'mtype': 0x02}
_sess = [0]


def sd_msg(payload, mtype=0x02, length=None):
    _sess[0] += 1
    return someip(0xffff, 0x8100, 0, _sess[0], payload, mtype=mtype, length=length)


def main(out):
    pkts = []
    ip6a = bytes.fromhex('fd00000000000000000000000000000a')
    ip6m = bytes.fromhex('ff1e0000000000000000000000000001')
    ipid = [1]

    def sdp(src, dst, payload, **kw):
        ipid[0] += 1
        pkts.append(udp_pkt(src, dst, SD_PORT, SD_PORT, sd_msg(payload, **kw), ipid[0]))

    # 1. Find Service (multicast), service ANY and a specific one, versions ANY
    sdp(B, MC, sd([entry_service(0x00, 0x1234, 0x0001, 1, 3, 0),
                   entry_service(0x00, 0xffff, 0xffff, 0xff, 0xffffff, 0xffffffff),
                   entry_service(0x00, 0x1234, 0x0001, 1, 3, 7, 0, 0, 0, 0)], [], flags=0xc0))
    # 2. Offer Service with IPv4 UDP and TCP endpoints (registers ports 30501 udp and 30502 tcp),
    #    a config string, a load balancing option and a multicast option
    sdp(A, MC, sd([entry_service(0x01, 0x1234, 0x0001, 1, 0xffffff, 10, 0, 0, 3, 0),
                   entry_service(0x01, 0x4321, 0x0002, 2, 5, 3, 3, 0, 1, 0)],
                  [opt_ipv4(0x04, A, 17, 30501),
                   opt_ipv4(0x04, A, 6, 30502),
                   opt_config([b'abc=def', b'x', b'']),
                   opt_lb(1, 10)]))
    # 3. Offer with options from both reference ranges, IPv4 multicast and IPv4 SD endpoint
    sdp(A, MC, sd([entry_service(0x01, 0x5678, 0x0001, 1, 3, 1, 0, 2, 1, 2)],
                  [opt_ipv4(0x04, A, 17, 30503),
                   opt_ipv4(0x14, MC, 17, 30490),
                   opt_ipv4(0x24, A, 17, 30490)]))
    # 4. Offer with IPv6 endpoints (registers udp 30601, tcp 30602), multicast and SD endpoint
    sdp(A, MC, sd([entry_service(0x01, 0x6000, 0x0001, 1, 3, 1, 0, 0, 2, 0),
                   entry_service(0x01, 0x6001, 0x0001, 1, 3, 1, 2, 0, 3, 0)],
                  [opt_ipv6(0x06, ip6a, 17, 30601),
                   opt_ipv6(0x06, ip6a, 6, 30602),
                   opt_ipv6(0x16, ip6m, 17, 30603),
                   opt_ipv6(0x26, ip6a, 17, 30490)]))
    # 5. Offer from "other service" 0xfffe: ports are not registered
    sdp(A, MC, sd([entry_service(0x01, 0xfffe, 0x0001, 1, 3, 1, 0, 0, 1, 0)],
                  [opt_ipv4(0x04, A, 17, 30999)]))
    # 6. Eventgroup entries: subscribe with initial events request and counter, acks
    sdp(B, A, sd([entry_eg(0x06, 0x1234, 0x0001, 1, 3, 0x0010, counter=2, init=True, i1=0, n1=1),
                  entry_eg(0x06, 0x1234, 0x0001, 1, 3, 0xffff, counter=0, i1=0, n1=0)],
                 [opt_ipv4(0x04, B, 17, 40000)], flags=0x80))
    sdp(A, B, sd([entry_eg(0x07, 0x1234, 0x0001, 1, 3, 0x0010, counter=2, i1=0, n1=1),
                  entry_eg(0x07, 0x1234, 0x0001, 1, 0, 0x0010, counter=2)],       # Nack
                 [opt_ipv4(0x14, MC, 17, 30511)], flags=0x00))
    # 7. Stop offer, stop subscribe
    sdp(A, MC, sd([entry_service(0x01, 0x1234, 0x0001, 1, 0, 10, 0, 0, 0, 0)], []))
    sdp(B, A, sd([entry_eg(0x06, 0x1234, 0x0001, 1, 0, 0x0010, counter=2),
                  entry_eg(0x06, 0x1234, 0xffff, 0xff, 0, 0xffff)], []))
    # 8. Entry types 2, 3, 4 and 5 (reserved by the specification, no name)
    sdp(B, A, sd([entry_service(0x02, 0x1234, 1, 1, 3, 0), entry_service(0x03, 0x1234, 1, 1, 3, 0),
                  entry_eg(0x04, 0x1234, 1, 1, 3, 1), entry_eg(0x05, 0x1234, 1, 1, 0, 1)], []))
    # 9. A subscribe, then a subscribe after a different entry, an offer without ttl, entries
    #    referencing an option index beyond the options
    sdp(A, MC, sd([entry_service(0x01, 0x7001, 1, 1, 3, 1, 5, 0, 1, 0)], [opt_ipv4(0x04, A, 17, 30701)]))
    # 10. The reproducer of the endless loop fixed by "SOMEIP-SD: Fix endless loop in the
    #     configuration option parser": a configuration string of 300 octets (more than 255)
    sdp(A, MC, sd([entry_service(0x01, 0x7002, 1, 1, 3, 1, 0, 0, 1, 0)],
                  [opt_config_raw(b'\x01' * 300)]))
    # 11. A long string made of valid elements (pos beyond 255), and a string with non ASCII octets
    longel = [b'k%03d=' % i + b'v' * 5 for i in range(40)]
    sdp(A, MC, sd([entry_service(0x01, 0x7003, 1, 1, 3, 1, 0, 0, 2, 0)],
                  [opt_config(longel), opt_config([b'caf\xc3\xa9=\xff\xfe', b'second=ok'])]))
    # 12. Config string without a terminating zero and with element length 0 in the middle
    sdp(A, MC, sd([entry_service(0x01, 0x7004, 1, 1, 3, 1, 0, 0, 2, 0)],
                  [opt_config([b'a=b'], trailer=b''), opt_config_raw(b'\x03a=b\x00\x02zz')]))
    # 12b. options only through the second range, and both ranges referencing the same options
    sdp(A, MC, sd([entry_service(0x01, 0x4321, 0x0003, 1, 3, 1, 0, 0, 0, 1),
                   entry_service(0x01, 0x4321, 0x0004, 1, 3, 1, 0, 0, 1, 0)],
                  [opt_ipv4(0x04, A, 17, 30504)]))
    # 13. Unknown option type 0 (Unknown) is shown by name without a warning? type 0 has a name
    #     but goes to the unknown handler: see the malformed capture. Here: SD over TCP

    # SOME/IP traffic on the ports registered from the endpoints, no Decode As needed.
    # UDP 30501 (offered by service 0x1234 over UDP): request, response, notification, error,
    # TP segments, requests with the ack/TP flags
    t = 0
    def data_udp(src, dst, sp, dp, msg):
        ipid[0] += 1
        pkts.append(udp_pkt(src, dst, sp, dp, msg, ipid[0]))

    data_udp(B, A, 40001, 30501, someip(0x1234, 0x0001, 0x0100, 1, b'\x01\x02\x03\x04', mtype=0x00))
    data_udp(A, B, 30501, 40001, someip(0x1234, 0x0001, 0x0100, 1, b'\x05\x06', mtype=0x80))
    data_udp(B, A, 40001, 30501, someip(0x1234, 0x0002, 0x0100, 2, b'', mtype=0x01))
    data_udp(A, B, 30501, 40001, someip(0x1234, 0x8001, 0x0000, 7, b'\xaa' * 8, mtype=0x02))
    data_udp(A, B, 30501, 40001, someip(0x1234, 0x0001, 0x0100, 1, b'\x00', mtype=0x81, rc=0x02))
    # TCP 30502
    s = Stream(B, 40100, A, 30502)
    s.hs()
    s.send(someip(0x1234, 0x0003, 0x0100, 3, b'tcp request'))
    s.recv(someip(0x1234, 0x0003, 0x0100, 3, b'tcp response', mtype=0x80))
    # a message split over two segments, two messages in one segment
    m = someip(0x1234, 0x0004, 0x0100, 4, b'0123456789abcdef', mtype=0x00)
    s.send(m[:10])
    s.send(m[10:])
    s.recv(someip(0x1234, 0x0005, 0x0100, 5, b'x', mtype=0x80) + someip(0x1234, 0x8002, 0, 6, b'y', mtype=0x02))
    pkts += s.pkts
    # UDP 30601 (IPv4 data on a port from an IPv6 option: the port is global)
    data_udp(B, A, 40002, 30601, someip(0x6000, 0x0001, 0x0100, 1, b'\x00\x01'))
    # SD message sent to a unicast address, with the reboot flag clear
    sdp(A, B, sd([entry_service(0x01, 0x1234, 0x0001, 1, 3, 10, 0, 0, 1, 0)],
                 [opt_ipv4(0x04, A, 17, 30501)], flags=0x40))

    write_pcap(os.path.join(out, 'someip_sd-coverage.pcap'), pkts)

    # ---------------- malformed capture ----------------
    pkts = []
    ipid[0] = 1000
    e_ok = entry_service(0x01, 0x1234, 1, 1, 3, 1, 0, 0, 1, 0)
    # option with length 1 (config string length 0), option with length 0
    sdp(A, MC, sd([e_ok], [opt_config_raw(b'')]))
    sdp(A, MC, sd([e_ok], [struct.pack('>HB', 0, 0x01)]))
    # unknown entry type, subscribe after stop subscribe
    sdp(A, MC, sd([entry_service(0x20, 0x1234, 1, 1, 3, 1)], []))
    sdp(A, MC, sd([entry_eg(0x06, 0x1234, 1, 1, 0, 0x10), entry_eg(0x06, 0x1234, 1, 1, 3, 0x10)], []))
    # offer without endpoints
    sdp(A, MC, sd([entry_service(0x01, 0x1234, 1, 1, 3, 1)], []))
    # unknown options: type 0x30 with data, without data, without reserved octet, option type 0
    sdp(A, MC, sd([e_ok], [opt_unknown(0x30, b'\x01\x02\x03'), opt_unknown(0x31),
                           opt_unknown(0x32, reserved=False), opt_unknown(0x00, b'zz')]))
    # IPv4 and IPv6 options of the wrong length, TCP in a multicast option
    sdp(A, MC, sd([e_ok], [opt_ipv4(0x04, A, 17, 30501, length=10) + b'\x00',
                           opt_ipv6(0x06, ip6a, 17, 30601, length=22) + b'\x00']))
    sdp(A, MC, sd([e_ok], [opt_ipv4(0x14, MC, 6, 30511), opt_ipv6(0x16, ip6m, 6, 30512),
                           opt_ipv4(0x04, A, 99, 30513), opt_ipv6(0x06, ip6a, 99, 30514)]))
    # configuration string with an element longer than the string
    sdp(A, MC, sd([e_ok], [opt_config_raw(b'\x20abc')]))
    # entry array not a multiple of 16, empty entry array, entry array truncated
    sdp(A, MC, sd([e_ok, b'\x00' * 5], []))
    sdp(A, MC, sd([], []))
    sdp(A, MC, sd([e_ok], [], entries_len=64))
    # options array longer than the data, option longer than the options array
    sdp(A, MC, sd([e_ok], [opt_ipv4(0x04, A, 17, 30501)], options_len=100))
    sdp(A, MC, sd([e_ok], [opt_ipv4(0x04, A, 17, 30501), b'\x00\x20\x30\x00'], options_len=16 + 4))
    # an options length without any option octets
    sdp(A, MC, sd([e_ok], [], options_len=5))
    # option array shorter than a minimal option
    sdp(A, MC, sd([e_ok], [b'\x00\x01'], options_len=2))
    # truncated message (shorter than flags + entries length), no options length field
    sdp(A, MC, b'\xc0\x00\x00\x00\x00')
    sdp(A, MC, sd([e_ok], [], flags=0x80)[:4 + 4 + 16])
    # too many options (SD_MAX_NUM_OPTIONS is 271)
    sdp(A, MC, sd([e_ok], [opt_unknown(0x30) for _ in range(280)]))
    # an option referencing beyond the array, many ports in one message
    sdp(A, MC, sd([entry_service(0x01, 0x1234, 1, 1, 3, 1, 250, 0, 15, 0)],
                  [opt_ipv4(0x04, A, 17, 31000 + i) for i in range(20)]))
    # SOME/IP header shorter than the SD payload minimum
    ipid[0] += 1
    pkts.append(udp_pkt(A, MC, SD_PORT, SD_PORT, someip(0xffff, 0x8100, 0, 99, b'\x00' * 4), ipid[0]))
    write_pcap(os.path.join(out, 'someip_sd-coverage-malformed.pcap'), pkts)


if __name__ == '__main__':
    main(sys.argv[1])
