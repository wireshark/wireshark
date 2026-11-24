#!/usr/bin/env python3
# Generates test/captures/ymsg_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the YMSG coverage captures with struct only (nothing is captured).
# Usage: mkymsg.py <outdir>
#   ymsg-coverage.pcap            Ethernet/IPv4/TCP, port 5050 and others
#   ymsg-coverage-malformed.pcap  rejected by the heuristic or cut
# YMSG is disabled by default (protocol and heuristic "ymsg_tcp") and has no
# port of its own, so tshark needs
#   --enable-protocol ymsg --enable-heuristic ymsg_tcp -o tcp.try_heuristic_first:TRUE
import struct
import sys
import os

# Values of the enums of packet-ymsg.c that have a name in the value strings
COMMANDS = [
    1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 40, 41, 42, 44, 51, 60, 70,
    71, 72, 73, 74, 75, 76, 77, 79, 80, 81, 84, 85, 86, 87, 88, 131, 132,
    133, 134, 137, 138, 139, 140, 141, 150, 151, 152, 155, 157, 160, 161,
    167, 168, 169, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
    194, 195, 196, 197, 198, 199, 200, 208, 210, 211, 212, 213, 214, 215,
    216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 239, 240, 241, 242, 252, 253,
    254, 300, 450, 451, 452, 453, 454, 460, 461, 463, 464, 500, 746, 748,
    749, 802, 806, 1000, 1001, 1002, 1100, 1101, 1102, 1103, 1104, 1105,
    1106, 1107, 1108,
]
STATUSES = [
    0, 1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 18, 19, 22, 24, 26, 29,
    33, 100, 101, 102, 1000, 1515563605, 1515563606, 4294967293, 4294967295,
]
FIELDS = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
    92, 93, 94, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
    109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
    123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
    137, 138, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 153,
    154, 159, 160, 161, 162, 180, 181, 182, 183, 184, 185, 186, 187, 190,
    191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 203, 204, 205, 206,
    207, 208, 211, 212, 213, 214, 215, 216, 217, 219, 221, 222, 223, 224,
    225, 226, 227, 230, 231, 232, 236, 237, 238, 239, 240, 241, 242, 243,
    244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 257, 258, 259,
    260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273,
    274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 300, 301, 302, 303,
    304, 305, 306, 307, 310, 312, 313, 314, 315, 316, 317, 318, 319, 320,
    321, 322, 323, 324, 325, 1000, 1001, 1002, 1003, 1004, 1005,
]

DELIM = b'\xc0\x80'

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def tcp_frame(sport, dport, seq, payload, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2])):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + t

def item(key, val):
    k = key if isinstance(key, bytes) else str(key).encode()
    v = val if isinstance(val, bytes) else str(val).encode()
    return k + DELIM + v + DELIM

def ymsg(cmd, status, content=b'', sid=0x11223344, version=16, vendor=0, length=None, magic=b'YMSG'):
    ln = len(content) if length is None else length
    return magic + struct.pack('>HHHHI', version, vendor, ln, cmd, status & 0xffffffff) + \
        struct.pack('<I', sid) + content

class Stream:
    def __init__(self, frames, cport, sport=5050):
        self.frames, self.cport, self.sport = frames, cport, sport
        self.seq = {0: 1000, 1: 7000}
    def send(self, payload, from_server=False):
        d = 1 if from_server else 0
        s = self.seq[d]
        self.seq[d] += len(payload)
        if from_server:
            self.frames.append(tcp_frame(self.sport, self.cport, s, payload))
        else:
            self.frames.append(tcp_frame(self.cport, self.sport, s, payload))

def main(out):
    F = []
    st = Stream(F, 41000)
    # one PDU per command (alternating direction), the status cycling
    # through all statuses and one unknown one
    statuses = STATUSES + [0x12345678]
    for i, cmd in enumerate(COMMANDS):
        content = item(0, 'alice') + item(1, 'bob') + item(14, 'hello %d' % cmd)
        st.send(ymsg(cmd, statuses[i % len(statuses)], content, sid=0x1000 + i), from_server=bool(i % 2))
    st.send(ymsg(9999, 7, item(0, 'x')))                        # unknown command
    st.send(ymsg(1, 7, b''), from_server=True)                  # no content
    # every field key, 12 per PDU
    for i in range(0, len(FIELDS), 12):
        content = b''.join(item(k, 'value%d' % k) for k in FIELDS[i:i + 12])
        st.send(ymsg(0x55, 0, content), from_server=bool(i % 2))
    # keys without a name, a non-numeric key, empty and odd values
    st.send(ymsg(0x4f, 0, item(4000, 'no such field') + item(b'abc', 'text key') + item(0, '') +
                 item(14, b'tab\there \x01\xff') + item(-5, 'negative')))
    # fields whose value is itself a field: start and end of record/list
    lst = item(300, 318) + item(301, 319) + item(302, 320) + item(303, 312) + \
        item(300, 99999) + item(302, 'notanumber') + item(303, '') + item(301, '-1') + item(300, 0)
    st.send(ymsg(0x55, 1, lst), from_server=True)
    # content shorter than the declared length, delimiter missing, no value
    st.send(ymsg(0x55, 0, item(0, 'a') + b'1' + DELIM))
    st.send(ymsg(0x55, 0, item(0, 'a') + b'12'))
    st.send(ymsg(0x55, 0, item(0, 'a') + item(7, 'b') + b'xx'))
    # version and vendor
    st.send(ymsg(0x4c, 0, item(0, 'v'), version=0x0010, vendor=0x00ff))
    # two PDUs in one segment, then three
    p1 = ymsg(0x4b, 1, item(0, 'one'))
    p2 = ymsg(0x4b, 2, item(0, 'two') + item(1, 'dos'))
    p3 = ymsg(0x4b, 3, b'')
    st.send(p1 + p2)
    st.send(p3 + p1 + p2, from_server=True)
    # a PDU split in two segments (reassembly), then split inside the header
    big = ymsg(0x55, 0, b''.join(item(k, 'split %d' % k) for k in range(20, 30)))
    st.send(big[:30]); st.send(big[30:])
    st.send(big[:5]); st.send(big[5:12]); st.send(big[12:])
    # a PDU followed by the start of the next one in the same segment
    st.send(p1 + big[:40], from_server=True)
    st.send(big[40:], from_server=True)
    # another port (no 5050): the heuristic accepts any port
    st2 = Stream(F, 41001, sport=5051)
    st2.send(ymsg(0x4b, 0, item(0, 'other port')))
    st2.send(ymsg(0x4b, 1, item(0, 'reply')), from_server=True)
    pcap(os.path.join(out, 'ymsg-coverage.pcap'), F)

    # malformed / rejected
    M = []
    Stream(M, 42010).send(b'YMS')                        # shorter than the magic
    Stream(M, 42011).send(b'YMSG')                       # magic only
    Stream(M, 42012).send(b'XMSG' + b'\0' * 20)          # not YMSG
    Stream(M, 42013).send(b'ymsg' + b'\0' * 20)
    # six octets after the last item: parsed as one more item, runs off the end
    Stream(M, 42014).send(ymsg(0x55, 0, item(0, 'pad') + b'\0' * 6))
    # key and value without delimiter after a good item
    Stream(M, 42015).send(ymsg(0x55, 0, item(0, 'pad') + b'1234567890'))
    s3 = Stream(M, 42001)
    s3.send(ymsg(1, 0, item(0, 'a'))[:12])               # truncated header (needs reassembly)
    s4 = Stream(M, 42002)
    s4.send(ymsg(1, 0, item(0, 'a'), length=300))        # length beyond the data
    s5 = Stream(M, 42003)
    s5.send(ymsg(1, 0, b'', length=0)[:20])              # header only, length 0
    s6 = Stream(M, 42004)
    s6.send(ymsg(1, 0, item(0, 'x'), length=0xffff))     # huge length
    pcap(os.path.join(out, 'ymsg-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
