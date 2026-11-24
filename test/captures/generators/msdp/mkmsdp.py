#!/usr/bin/env python3
# Generates test/captures/msdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MSDP coverage captures: mkmsdp.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import Conn, ipv4, pcap

def ip4(a): return bytes(int(x) for x in a.split('.'))

def tlv(t, body=b'', length=None):
    return struct.pack('!BH', t, len(body) + 3 if length is None else length) + body

def sa_entry(src='10.1.1.1', grp='224.1.2.3', plen=32, res=0):
    return struct.pack('!I', (res << 8) | plen)[0:3] + bytes([plen]) + ip4(grp) + ip4(src)

def sa_entry(src='10.1.1.1', grp='224.1.2.3', plen=32, res=0):
    return struct.pack('!I', res)[1:] + bytes([plen]) + ip4(grp) + ip4(src)

def sa(t, entries, rp='10.0.0.1', count=None, extra=b''):
    body = bytes([len(entries) if count is None else count]) + ip4(rp) + b''.join(entries) + extra
    return tlv(t, body)

def mc_packet():
    pl = b'multicast data'
    udp = struct.pack('!HHHH', 1234, 5678, 8 + len(pl), 0) + pl
    return ipv4(17, udp, '10.1.1.1', '224.1.2.3')

def notif(err, sub, data=b'', o=False):
    return tlv(5, bytes([err | (0x80 if o else 0), sub]) + data)

def addr(a, res=0): return struct.pack('!I', res)[1:] + ip4(a)

KA = tlv(4)

def build():
    main, mal, notes = [], [], []
    c = Conn(40000, 639)
    def mark(t): notes.append((len(main) + 1, t))
    main += c.syn()
    mark('KeepAlive, SA (0, 1, 3 entries, encapsulated IPv4 packet), SA Response, SA Request, unknown type')
    main.append(c.cs(KA))
    main.append(c.sc(KA))
    main.append(c.cs(sa(1, [])))
    main.append(c.cs(sa(1, [sa_entry()])))
    main.append(c.cs(sa(1, [sa_entry(), sa_entry('10.2.2.2', '224.9.9.9', 24), sa_entry('10.3.3.3', '232.1.1.1', 16, 0x010203)])))
    main.append(c.cs(sa(1, [sa_entry()], extra=mc_packet())))
    main.append(c.sc(sa(3, [sa_entry(), sa_entry('10.2.2.2', '224.9.9.9', 24)])))
    main.append(c.sc(sa(3, [sa_entry()], extra=mc_packet())))
    main.append(c.cs(tlv(2, b'\x00' + ip4('224.1.2.3'))))               # SA Request
    main.append(c.cs(tlv(2, b'\x00' + ip4('224.1.2.3') + b'junk')))     # trailing junk
    main.append(c.cs(tlv(6, b'trace in progress')))
    main.append(c.cs(tlv(7, b'')))
    main.append(c.cs(tlv(200, b'unknown')))
    main.append(c.cs(KA + sa(1, [sa_entry()]) + KA))                    # several TLVs
    main.append(c.cs(sa(1, [sa_entry()], extra=mc_packet()) + KA))     # encapsulated packet, then another TLV
    main.append(c.cs(tlv(4, b'xy')))                                   # KeepAlive with trailing junk
    mark('Notification: every error code and subcode, nested messages')
    # message header error
    for sub in (0, 2, 3, 9):
        main.append(c.sc(notif(1, sub, KA)))
    main.append(c.sc(notif(1, 3, b'', o=True)))
    main.append(c.sc(notif(1, 2, tlv(9, b'abcd'))))
    # SA request error
    main.append(c.sc(notif(2, 1, addr('224.1.2.3'))))
    main.append(c.sc(notif(2, 0, addr('224.1.2.3', 0x010203) + b'zz')))
    main.append(c.sc(notif(2, 7, addr('224.1.2.3'))))
    # SA message / response error
    main.append(c.sc(notif(3, 0)))
    main.append(c.sc(notif(3, 1, bytes([5]))))
    main.append(c.sc(notif(3, 2, addr('10.0.0.1'))))
    main.append(c.sc(notif(3, 3, addr('224.1.1.1'))))
    main.append(c.sc(notif(3, 4, addr('10.9.9.9'))))
    main.append(c.sc(notif(3, 5, bytes([33]))))
    main.append(c.sc(notif(3, 6, sa(1, [sa_entry()]))))
    main.append(c.sc(notif(3, 6)))
    main.append(c.sc(notif(3, 7, sa(1, [sa_entry()]))))
    main.append(c.sc(notif(3, 7)))
    main.append(c.sc(notif(3, 8, addr('239.1.1.1'))))
    main.append(c.sc(notif(3, 9, b'unknown sub code data')))
    main.append(c.sc(notif(3, 9)))
    main.append(c.sc(notif(3, 3, addr('224.1.1.1') + b'extra bytes')))   # trailing junk
    # nested messages followed by another TLV in the same segment
    main.append(c.sc(notif(1, 2, KA) + KA))
    main.append(c.sc(notif(3, 6, KA) + KA))
    main.append(c.sc(notif(3, 7, KA) + KA))
    main.append(c.sc(notif(6, 0, KA) + KA))
    # hold timer, FSM, notification, cease, unknown code
    main.append(c.sc(notif(4, 0)))
    main.append(c.sc(notif(5, 1)))
    main.append(c.sc(notif(5, 0)))
    main.append(c.sc(notif(6, 0, notif(1, 2, KA))))                      # Notification in Notification
    main.append(c.sc(notif(6, 0)))
    main.append(c.sc(notif(7, 0)))
    main.append(c.sc(notif(7, 0, b'trailing')))
    main.append(c.sc(notif(0x11, 0, b'unknown error code')))
    main.append(c.sc(notif(0x11, 0)))
    # notification nested 10 deep
    d = KA
    for _ in range(10):
        d = notif(6, 0, d)
    main.append(c.sc(d))
    # one more connection where the message is in the middle of the stream
    # --- malformed
    cm = Conn(40001, 639, isn_c=2000, isn_s=6000)
    mal += cm.syn()
    for t in (tlv(4, b'', 2), tlv(4, b'', 0)):
        mal.append(cm.cs(t))
    mal.append(cm.cs(tlv(2, b'')))                                # SA Request too short (length < 1)
    mal.append(cm.cs(tlv(2, b'\x00')))                            # < 4 after reserved
    mal.append(cm.cs(tlv(2, b'\x00\x01\x02')))
    mal.append(cm.cs(tlv(1, b'')))                                # SA without count
    mal.append(cm.cs(tlv(1, b'\x01')))                            # SA without RP
    mal.append(cm.cs(tlv(1, b'\x01\x0a\x00')))
    mal.append(cm.cs(tlv(3, b'\x02' + ip4('10.0.0.1') + sa_entry() + b'12345')))  # entries truncated
    mal.append(cm.cs(tlv(5, b'')))                                # Notification without error code
    mal.append(cm.cs(tlv(5, b'\x01')))                            # without subcode
    mal.append(cm.cs(tlv(5, b'\x02\x01' + b'12345')))             # SA request error short
    mal.append(cm.cs(tlv(5, b'\x03\x01')))                        # invalid entry count short
    for sub in (2, 3, 4, 8):
        mal.append(cm.cs(tlv(5, bytes([3, sub]) + b'123')))
    mal.append(cm.cs(tlv(5, b'\x03\x05')))                        # sprefix short
    mal.append(cm.cs(tlv(5, b'\x03\x06' + b'\x01\x00\x03')))      # nested SA with bad length
    mal.append(cm.cs(tlv(4, b'', 3) + tlv(200, b'x', 300)))       # unknown TLV longer than the data
    mal.append(cm.cs(tlv(1, b'\x01' + ip4('10.0.0.1') + b'\x00' * 12, 1000)))   # SA length beyond data
    # the nesting of notifications past the dissection depth limit
    d = KA
    for _ in range(700):
        d = notif(6, 0, d, ) if len(d) < 65000 else d
    mal.append(cm.cs(d))
    return main, mal, notes

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, notes = build()
    pcap(os.path.join(out, 'msdp-coverage.pcap'), main)
    pcap(os.path.join(out, 'msdp-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main', len(main), 'malformed', len(mal))
        for n, t in notes: print(n, t)
