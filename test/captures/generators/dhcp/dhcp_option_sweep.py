#!/usr/bin/env python3
# Helper module for the dhcp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# packet-dhcp.c: edge-case sweep over options with hand-written parsers
# (client id DUIDs, vendor suboptions, PacketCable, DNR, CCC, Avaya, ...).
# Used with valgrind and WIRESHARK_ABORT_ON_DISSECTOR_BUG=1.
import struct
from dhcp_common import bootp, opt, udp_frame, write_pcap

def dhcp(*opts, vc=None, op=1):
    o = opt(53, b'\x01')
    if vc is not None:
        o += opt(60, vc)
    return udp_frame(bootp(o + b''.join(opts) + b'\xff', op=op))

frames = []
# Option 61 type 255, DUID-LLT/EN/LL with lengths that pass the too-small checks
for duid, lens in ((1, range(7, 14)), (2, range(7, 12)), (3, range(7, 10))):
    for L in lens:
        body = b'\xff' + b'\0\0\0\1' + struct.pack('!H', duid)
        body = (body + b'\x00\x01' + b'\x11' * 20)[:L]
        frames.append(dhcp(opt(61, body)))
# PXE: boot servers / boot menu with zero length, boot item short, prompt 0
for so in (8, 9, 10, 71):
    for L in (0, 1, 2):
        frames.append(dhcp(opt(43, bytes([so, L]) + b'\x00' * L + b'\xff'), vc=b'PXEClient'))
# BSDP
for so in (2, 3, 7, 8, 9, 11, 12):
    for L in (0, 1, 5, 6):
        frames.append(dhcp(opt(43, bytes([so, L]) + b'\x01\x02\x03\x04\x01\x41'[:L]), vc=b'AAPLBSDPC'))
# CableLabs option 43
for so in (8, 31, 32, 11, 52, 53, 54):
    for L in (0, 3, 6, 7):
        frames.append(dhcp(opt(43, bytes([so, L]) + b'A' * L), vc=b'docsis3.0'))
# Aruba Instant AP
for s in (b'', b',', b'a,', b'a,b', b'a,b,', b',,,', b'abc'):
    frames.append(dhcp(opt(43, s), vc=b'ArubaInstantAP'))
# Cisco / Aerohive
for so in range(1, 13):
    frames.append(dhcp(opt(43, bytes([so, 9]) + b'\x01' * 9), vc=b'cisco'))
frames.append(dhcp(opt(43, b'\xe2\x03\x01\x02\x03'), vc=b'AEROHIVE'))
# PacketCable MTA caps (option 60)
for body in (b'0', b'05', b'zz', b'0501', b'05010101', b'0517060200380201070', b'0512020003',
             b'0501020112', b'0501020117', b'051705020', b'0517030201'):
    frames.append(dhcp(opt(60, b'pktc1.0:' + body)))
# DOCSIS CM caps (option 60)
for body in (b'0', b'0501', b'05110700', b'051004aabb', b'05020100', b'zz', b'0529040102'):
    frames.append(dhcp(opt(60, b'docsis1.1:' + body)))
# Option 125 CableLabs subopt 5 (modem caps) with odd TLVs, and TR-111
for caps in (b'', b'\x01', b'\x01\x00', b'\x12\x07\x01', b'\x10\x04\x00\x01\x00\x0f', b'\x29\x04\x01\x02\x03\x04', b'\x02\x00'):
    v = bytes([5, len(caps)]) + caps
    frames.append(dhcp(opt(125, struct.pack('!IB', 4491, len(v)) + v)))
for v in (b'\x01\x06zzzzzz', b'\x01\x00', b'\x01\x06001122', b'\x04\x02-1', b'\x01'):
    frames.append(dhcp(opt(125, struct.pack('!IB', 3561, len(v)) + v)))
# Option 125: two subopts, second runs past the enterprise data
v = b'\x01\x02AB\x01\x05ABCDE'
frames.append(dhcp(opt(125, struct.pack('!IB', 3561, 4) + v)))
# Option 124
for v in (b'', b'\x00', b'\x05abc', b'\x02ab\x00'):
    frames.append(dhcp(opt(124, struct.pack('!IB', 4491, len(v)) + v)))
# Option 82 suboption 9 CableLabs
for cl in (b'\x01\x04\x01\x02\x03\x04', b'\x03\x05ABCDE', b'\x01\x02', b'\x07\x00', b'\x04\x03abc'):
    s9 = struct.pack('!IB', 4491, len(cl)) + cl
    frames.append(dhcp(opt(82, bytes([9, len(s9)]) + s9)))
frames.append(dhcp(opt(82, b'\x10\x03abc' + b'\x07\x03\x01\x03x' + b'\x97\x07' + b'\x00' * 7)))
# DNR (162)
for inst in (b'\x00\x03\x00\x01\x00', b'\x00\x04\x00\x01\x00\x00', b'\x00\x08\x00\x01\x00\x04\x01\x02\x03\x04',
             b'\x00\x05\x00\x01\x02\xc0\x00'):
    frames.append(dhcp(opt(162, inst)))
# CCC 122
for v in (b'\x03\x00', b'\x03\x01\x00', b'\x03\x05\x01\x01\x02\x03\x04', b'\x05\x0cabcdefghijkl', b'\x06\x00', b'\x07\x00', b'\x08\x00'):
    frames.append(dhcp(opt(122, v)))
# Avaya 242
for s in (b'L2QVLAN=10,L2Q=1', b'L2QVLAN=xx', b'VLANTEST=9999999999', b'\xff\xfe=,\xc3\xa9=1,TLSSRVR=a'):
    frames.append(dhcp(opt(242, s)))
# 123 coordinate based location, extreme values
for lci in (b'\xff' * 16, b'\x02' + b'\0' * 9 + b'\x1f\xff' + b'\0' * 4, b'\x00' * 10 + b'\x10\x20' + b'\0' * 3 + b'\x01'):
    frames.append(dhcp(opt(123, lci)))
frames.append(dhcp(opt(123, b'\x01\x05abcde\x02\x40abc')))
# misc
frames.append(dhcp(opt(119, b'\xc0\x00')))
frames.append(dhcp(opt(119, b'\x03abc\xc0\x00')))
frames.append(dhcp(opt(120, b'\x00\xc0\x01')))
frames.append(dhcp(opt(146, b'\x00' * 9 + b'\xc0\x09')))
frames.append(dhcp(opt(158, b'\x00\x05\x01\x02\x03\x04\x05')))
frames.append(dhcp(opt(77, b'\x00\x05abcde\x00\x00\x00\x02a\x00\x00\x00')))
frames.append(dhcp(opt(77, b'\x00\x01')))
frames.append(dhcp(opt(90, b'\x01\x01\x00' + b'\0' * 8 + b'x' * 3), op=2))
frames.append(dhcp(opt(81, b'\x04\x00\x00\xc0\x00')))
frames.append(dhcp(opt(83, b'\x80\x01' + b'\0\0' + b'\x80\x02' + b'\0' * 8)))
frames.append(dhcp(opt(99, b'\x00US\x01\x00\x02\x05ab')))
frames.append(dhcp(opt(63, b'\x01\x00\x05\x01\x01\x06\x03abc\x0b\x04\x01\x02\x03\x04')))
write_pcap('dhcp_option_sweep.pcap', frames)
print(len(frames), 'frames')
