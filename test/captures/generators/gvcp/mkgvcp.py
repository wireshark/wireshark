#!/usr/bin/env python3
# Generates test/captures/gvcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the GVCP coverage captures.  Usage: mkgvcp.py <outdir>

Writes gvcp-coverage.pcap (decodes cleanly) and
gvcp-coverage-malformed.pcap (paths only malformed input reaches).
Everything is synthetic.  GVCP is UDP port 3956 (registered by default).
"""
import struct
import socket
import sys
import os

CAM = '192.0.2.2'
HOST = '192.0.2.1'
HMAC = bytes([2, 0, 0, 0, 0, 1])
CMAC = bytes([2, 0, 0, 0, 0, 2])
BMAC = b'\xff' * 6


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(sp, dp, payload, src, dst, smac, dmac):
    u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return dmac + smac + b'\x08\x00' + h + u


def to_cam(payload, sp=50000, dp=3956, dst=CAM, dmac=CMAC):
    return udp_frame(sp, dp, payload, HOST, dst, HMAC, dmac)


def from_cam(payload, sp=3956, dp=50000):
    return udp_frame(sp, dp, payload, CAM, HOST, CMAC, HMAC)


def cmd(code, req, payload=b'', flags=0x01):
    return struct.pack('>BBHHH', 0x42, flags, code, len(payload), req) + payload


def ack(code, req, payload=b'', status=0):
    return struct.pack('>HHHH', status, code, len(payload), req) + payload


DISCOVERY, FORCEIP, RESEND, READREG, WRITEREG, READMEM, WRITEMEM = 2, 4, 0x40, 0x80, 0x82, 0x84, 0x86
EVENT, EVENTDATA, ACTION = 0xC0, 0xC2, 0x100


def sc(i, off):
    return 0x0d00 + 0x40 * i + off


# every bootstrap register that dissect_register() knows
BOOT = [0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x24, 0x34, 0x44, 0x48, 0x68, 0x88, 0xA8,
        0xd8, 0xE8, 0x200, 0x400, 0x600, 0x64C, 0x65C, 0x66C, 0x670]
for n in range(1, 4):
    b = 0x680 + 0x80 * (n - 1)
    BOOT += [b, b + 4, b + 8, b + 0xC, b + 0x1C, b + 0x2C, b + 0x3C, b + 0x4C, b + 0x5C, b + 0x6C, b + 0x70]
BOOT += [0x900, 0x904, 0x908, 0x90C, 0x910, 0x92C, 0x930, 0x934, 0x938, 0x93C, 0x940, 0x944, 0x948,
         0x94C, 0x950, 0x954, 0x958, 0x95C, 0x960, 0x964, 0x968, 0x96C, 0x970, 0x974, 0x978, 0x97C,
         0xA00, 0xA04, 0xA14, 0xB00, 0xB10, 0xB14, 0xB18, 0xB1C, 0xB20, 0x9000]
for i in range(4):
    BOOT += [sc(i, o) for o in (0, 4, 8, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C)]
for i in range(10):
    BOOT += [0x9800 + 0x10 * i, 0x9804 + 0x10 * i]

SPECIAL = {
    0x0: 0x00020002, 0x4: 0x80010003 | (2 << 4), 0x10: 0x80000007, 0x14: 0x80000005,
    0x24: 0xC0000205, 0x34: 0xFFFFFF00, 0x44: 0xC0000201, 0x600: 2, 0x670: 1000000000,
    0x904: 2, 0x938: 3000, 0xA00: 0x00000002, 0xA14: 0xC0000201, 0xB10: 0xE0000001,
    0x934: 0xFFFFFFFF, 0x92C: 0xF000000F, 0xB00: 50020,
}
for _i in range(4):
    SPECIAL[0x0d00 + 0x40 * _i] = 50010 + _i
    SPECIAL[0x0d3C + 0x40 * _i] = 0



def regval(a):
    if a in SPECIAL:
        return SPECIAL[a]
    return (a * 2654435761 + 12345) & 0xFFFFFFFF


frames = []
bad = []
req = [0]


def nreq():
    req[0] += 1
    return req[0]


def exch(c_code, c_pay, a_code, a_pay, status=0, flags=0x01, r=None, cmd_target=None):
    r = r if r is not None else nreq()
    frames.append(to_cam(cmd(c_code, r, c_pay, flags)))
    frames.append(from_cam(ack(a_code, r, a_pay, status)))
    return r


def s(txt, n):
    return txt.encode().ljust(n, b'\0')


# ---------------------------------------------------------------- discovery
frames.append(to_cam(cmd(DISCOVERY, nreq(), b'', 0x11), dst='255.255.255.255', dmac=BMAC))
disc = struct.pack('>IIH', 0x00020002, 0x80000003, 0) + CMAC + b'\0\0'          # 0..15 ; mac at 10
disc = disc[:10] + CMAC
disc += struct.pack('>II', 0x80000007, 0x80000005)                       # 16 supp ip, 20 cur ip cfg
disc += b'\0' * 12 + struct.pack('>I', 0xC0000202)                       # 24..39: ip at 36
disc += b'\0' * 12 + struct.pack('>I', 0xFFFFFF00)                       # 40..55: mask at 52
disc += b'\0' * 12 + struct.pack('>I', 0xC0000201)                       # 56..71: gw at 68
disc += s('Synthetic Vision GmbH', 32) + s('SV-CAM-1', 32) + s('1.2.3', 32) + s('extra info', 48)
disc += s('SN-0001', 16) + s('front camera', 16)
assert len(disc) == 248, len(disc)
frames.append(from_cam(ack(3, r := req[0], disc), sp=3956, dp=50000))
# a second discovery on the same request id, not a broadcast
frames.append(to_cam(cmd(DISCOVERY, nreq(), b'', 0x01)))
frames.append(from_cam(ack(3, req[0], disc.replace(b'SN-0001', b'SN-0002'))))

# ------------------------------------------------------------------ force IP
fip = b'\0\0' + CMAC + b'\0' * 12 + struct.pack('>I', 0xC0000210) + b'\0' * 12 + struct.pack('>I', 0xFFFFFF00) \
    + b'\0' * 12 + struct.pack('>I', 0xC0000201)
assert len(fip) == 56
exch(FORCEIP, fip, 5, b'', flags=0x11)

# -------------------------------------------- read register: every register
for a in BOOT:
    exch(READREG, struct.pack('>I', a), 0x81, struct.pack('>I', regval(a)))

# multiple register read/write, in chunks
for k in range(0, len(BOOT), 32):
    chunk = BOOT[k:k + 32]
    exch(READREG, b''.join(struct.pack('>I', a) for a in chunk), 0x81,
         b''.join(struct.pack('>I', regval(a)) for a in chunk))

# read of custom (unknown) registers, single and multiple
exch(READREG, struct.pack('>I', 0x00012345), 0x81, struct.pack('>I', 0xdeadbeef))
exch(READREG, struct.pack('>II', 0x00012345, 0x00012349), 0x81, struct.pack('>II', 1, 2))
# ack shorter/longer than the request; error status without payload
exch(READREG, struct.pack('>II', 0x00012345, 0x00012349), 0x81, struct.pack('>I', 1))
exch(READREG, struct.pack('>III', 0x4, 0x8, 0xC), 0x81, struct.pack('>IIII', 1, 2, 3, 4))
exch(READREG, struct.pack('>I', 0x00012345), 0x81, b'', status=0x8006)
exch(READREG, struct.pack('>I', 0x00012345), 0x81, struct.pack('>I', 0), status=0x8003)
# ack without a matching request, a duplicate ack and a retransmitted request
frames.append(from_cam(ack(0x81, 9000, struct.pack('>I', 7))))
r = exch(READREG, struct.pack('>I', 0x938), 0x81, struct.pack('>I', 3000))
frames.append(from_cam(ack(0x81, r, struct.pack('>I', 3000))))
frames.append(to_cam(cmd(READREG, r, struct.pack('>I', 0x938))))
frames.append(from_cam(ack(0x81, r, struct.pack('>I', 3000))))

# ------------------------------------------- write register
# the values written to the registers; the stream destination port and the
# message channel port make the dissector learn UDP ports
WREG = {sc(0, 0): 50010, 0xB00: 50020}
for a in BOOT:
    if a in WREG or a == sc(0, 0x3C):
        continue
    exch(WRITEREG, struct.pack('>II', a, regval(a)), 0x83, struct.pack('>HH', 0, 1))
exch(WRITEREG, struct.pack('>II', sc(0, 0), 50010), 0x83, struct.pack('>HH', 0, 1))     # learns GVSP port
exch(WRITEREG, struct.pack('>II', sc(2, 0), 50012), 0x83, struct.pack('>HH', 0, 1))
exch(WRITEREG, struct.pack('>II', 0xB00, 50020), 0x83, struct.pack('>HH', 0, 1))        # learns GVCP port
exch(WRITEREG, struct.pack('>II', sc(0, 0x3C), 0x00010000), 0x83, struct.pack('>HH', 0, 1))
exch(WRITEREG, struct.pack('>II', 0x00012345, 99), 0x83, struct.pack('>HH', 0, 1))      # custom
# multiple
mw = [(0x938, 5000), (0x00012345, 1), (0xA00, 1), (sc(0, 8), 100)]
pay = b''.join(struct.pack('>II', a, v) for a, v in mw)
exch(WRITEREG, pay, 0x83, struct.pack('>HH', 0, 4))                   # all written
exch(WRITEREG, pay, 0x83, struct.pack('>HH', 0, 2), status=0x8001)    # only two: failed
exch(WRITEREG, struct.pack('>II', 0x938, 7), 0x83, struct.pack('>HH', 0, 0), status=0x8006)   # single failed
frames.append(from_cam(ack(0x83, 9001, struct.pack('>HH', 0, 1))))

# ------------------------------------------- read memory / write memory
MEM = {0x48: 32, 0x68: 32, 0x88: 32, 0xA8: 48, 0xd8: 16, 0xE8: 16, 0x200: 512, 0x400: 512}
for a, n in MEM.items():
    data = (('value-%x-' % a) * 64).encode()[:n - 1].ljust(n, b'\0')
    exch(READMEM, struct.pack('>IHH', a, 0, n), 0x85, struct.pack('>I', a) + data)
    exch(WRITEMEM, struct.pack('>I', a) + data, 0x87, struct.pack('>HH', 0, n))
# length not matching the register: no value fields
exch(READMEM, struct.pack('>IHH', 0x48, 0, 8), 0x85, struct.pack('>I', 0x48) + b'12345678')
exch(WRITEMEM, struct.pack('>I', 0x48) + b'12345678', 0x87, struct.pack('>HH', 0, 8))
# a bootstrap register that dissect_register_data() does not know
exch(READMEM, struct.pack('>IHH', 0x938, 0, 4), 0x85, struct.pack('>II', 0x938, 3000))
exch(WRITEMEM, struct.pack('>II', 0x938, 3000), 0x87, struct.pack('>HH', 0, 4))
# unknown addresses, status error
exch(READMEM, struct.pack('>IHH', 0x00100000, 0, 16), 0x85, struct.pack('>I', 0x00100000) + bytes(range(16)))
exch(WRITEMEM, struct.pack('>I', 0x00100000) + bytes(range(16)), 0x87, struct.pack('>HH', 0, 16))
exch(READMEM, struct.pack('>IHH', 0x00100000, 0, 16), 0x85, b'', status=0x8003)
exch(WRITEMEM, struct.pack('>I', 0x00100000) + bytes(range(16)), 0x87, struct.pack('>HH', 0, 0), status=0x8004)
frames.append(from_cam(ack(0x87, 9002, struct.pack('>HH', 0, 4))))        # no request
frames.append(from_cam(ack(0x85, 9003, struct.pack('>I', 0x938) + b'abcd')))

# ------------------------------------- stream channel extended bootstrap
# Learned from the READREG_ACK of SCEBA0 (this ack is a frame of its own so
# the base address is known to the later requests); the base is 0x10000 and
# later 0x20000 learned from a READMEM_ACK (the bug fixed on the branch)
EBASE = 0x00010000
exch(READREG, struct.pack('>I', sc(0, 0x3C)), 0x81, struct.pack('>I', EBASE))
for off in (0, 4, 8, 0xC):
    exch(READREG, struct.pack('>I', EBASE + off), 0x81, struct.pack('>I', 0x1000 + off))
    exch(WRITEREG, struct.pack('>II', EBASE + off, 0x2000 + off), 0x83, struct.pack('>HH', 0, 1))
    exch(READMEM, struct.pack('>IHH', EBASE + off, 0, 4), 0x85, struct.pack('>II', EBASE + off, 0x3000 + off))
    exch(WRITEMEM, struct.pack('>II', EBASE + off, 0x4000 + off), 0x87, struct.pack('>HH', 0, 4))
# an address inside the window that has no name
exch(READREG, struct.pack('>I', EBASE + 0x10), 0x81, struct.pack('>I', 5))
exch(READREG, struct.pack('>IIII', EBASE, EBASE + 4, EBASE + 8, EBASE + 0xC), 0x81,
     struct.pack('>IIII', 0x1000, 0x20, 0x1100, 0x40))
# the reproducer of the READMEM_ACK fix: SCEBA of channel 1 learned by a
# READMEM_ACK, then used
exch(READMEM, struct.pack('>IHH', sc(1, 0x3C), 0, 4), 0x85, struct.pack('>II', sc(1, 0x3C), 0x00030000))
exch(READREG, struct.pack('>I', 0x00030004), 0x81, struct.pack('>I', 0x100))
exch(WRITEREG, struct.pack('>II', 0x00030008, 0x1234), 0x83, struct.pack('>HH', 0, 1))
exch(READMEM, struct.pack('>IHH', 0x00030000, 0, 4), 0x85, struct.pack('>II', 0x00030000, 0x5000))
# channel 4 is not a named register, the window is learned by the READREG_ACK
exch(READREG, struct.pack('>I', sc(4, 0x3C)), 0x81, struct.pack('>I', 0x00040000))
exch(READREG, struct.pack('>I', 0x00040000), 0x81, struct.pack('>I', 0x77))
# the extended window register read with a failing ack
exch(READREG, struct.pack('>I', EBASE), 0x81, b'', status=0x8006)

# ---------------------------------------- pending ack, packet resend
r = nreq()
frames.append(to_cam(cmd(WRITEMEM, r, struct.pack('>I', 0x00100000) + bytes(32))))
frames.append(from_cam(ack(0x89, r, struct.pack('>HH', 0, 250))))
frames.append(from_cam(ack(0x87, r, struct.pack('>HH', 0, 32))))
r = nreq()
frames.append(to_cam(cmd(READREG, r, struct.pack('>I', 0x938))))
frames.append(from_cam(ack(0x89, r, struct.pack('>HH', 0, 100))))
frames.append(from_cam(ack(0x81, r, struct.pack('>I', 3000))))

# 16 bit block id: stream channel(2) block id(2) first(4) last(4)
exch(RESEND, struct.pack('>HHII', 0, 0x1234, 5, 9), 0x41, b'', flags=0x01)
exch(RESEND, struct.pack('>HHII', 1, 0x1234, 5, 9), 0x41, struct.pack('>HHII', 1, 0x1234, 5, 9), status=0x0100)
# 64 bit block id, flag 0x10
exch(RESEND, struct.pack('>HHIIQ', 0, 0, 1000, 2000, 0x1_0000_0002), 0x41, b'', flags=0x11)
exch(RESEND, struct.pack('>HHIIQ', 0, 0, 1000, 2000, 7), 0x41, b'', status=0x8012, flags=0x11)

# -------------------------------------------------------- events
def ev16(eid, ch, blk, ts):
    return struct.pack('>HHHHQ', 0, eid, ch, blk, ts)


def ev64(eid, ch, blk, ts):
    return struct.pack('>HHHHQQ', 0, eid, ch, 0, blk, ts)


# events are sent by the device to the message channel port learned from
# the write of MCP (50020) and to the control channel
def ev_cmd(code, pay, flags=0x01, dp=50000):
    r = nreq()
    frames.append(from_cam_cmd(cmd(code, r, pay, flags), dp))
    return r


def from_cam_cmd(payload, dp):
    return udp_frame(3956, dp, payload, CAM, HOST, CMAC, HMAC)


for dp in (50000, 50020):
    for eid in (0x0009, 0x8001, 0x9000, 0x8000, 0x8FFF, 0x0007, 0x0008):
        r = ev_cmd(EVENT, ev16(eid, 0, 77, 123456789 + eid), dp=dp)
        frames.append(to_cam(ack(0xC1, r, b''), sp=50000 if dp == 50000 else 50020, dp=3956))
ev_cmd(EVENT, ev16(0x0009, 0, 1, 1) + ev16(0x8001, 1, 2, 2) + ev16(0x9001, 2, 3, 3))
ev_cmd(EVENT, ev64(0x0009, 0, 1 << 40, 1) + ev64(0x8002, 1, 2, 2), flags=0x11)
ev_cmd(EVENT, ev64(0x9009, 0, 1 << 40, 1), flags=0x11)
# event data: 16 bit block id, data to the end of the packet
ev_cmd(EVENTDATA, ev16(0x0009, 0, 5, 77) + b'event payload!')
ev_cmd(EVENTDATA, ev16(0x8003, 0, 5, 77) + b'error data')
ev_cmd(EVENTDATA, ev16(0xA000, 0, 5, 77) + b'device specific data')


def evd64(eid, ch, blk, ts, data):
    return struct.pack('>H', 24 + len(data)) + ev64(eid, ch, blk, ts)[2:] + data


# extended: the first word is the size of the event with its data; several
# events per packet, one without data
ev_cmd(EVENTDATA, evd64(0x0009, 0, 1, 2, b'abcdefgh') + evd64(0x8004, 1, 3, 4, b'') + evd64(0xB000, 2, 5, 6, b'xyz1234'), flags=0x11)
ev_cmd(EVENTDATA, evd64(0x0009, 0, 1, 2, b'0123456789abcdef'), flags=0x11)
# the host acknowledges events
frames.append(to_cam(ack(0xC1, req[0], b''), sp=50000, dp=3956))
frames.append(to_cam(ack(0xC3, req[0], struct.pack('>HH', 0, 0)), sp=50000, dp=3956))

# ------------------------------------------------ actions
exch(ACTION, struct.pack('>III', 1, 2, 0xffffffff), 0x101, struct.pack('>I', 0), flags=0x01)
exch(ACTION, struct.pack('>IIIQ', 1, 2, 0x1, 0x0000000100000000), 0x101, struct.pack('>I', 0), flags=0x81)
exch(ACTION, struct.pack('>III', 3, 4, 0x2), 0x101, b'', flags=0x00)
exch(0x0999, b'\1\2\3\4', 0x101, b'', flags=0x01)        # unknown command
# statuses of acks
for st in (0x8001, 0x8002, 0x8004, 0x8005, 0x8007, 0x8008, 0x8009, 0x800A, 0x800B, 0x800C, 0x800D,
           0x800E, 0x800F, 0x8010, 0x8011, 0x8013, 0x8014, 0x8015, 0x8016, 0x8017, 0x8FFF, 0x8ABC):
    exch(WRITEREG, struct.pack('>II', 0x938, 1), 0x83, struct.pack('>HH', 0, 0), status=st)

# the reproducer for the stray ']' in the SCEBA0 register name is the SCEBA0
# reads above

# unaligned addresses inside the window have no name
for off in (1, 6):
    exch(READREG, struct.pack('>I', EBASE + off), 0x81, struct.pack('>I', 9))
    exch(WRITEREG, struct.pack('>II', EBASE + off, 9), 0x83, struct.pack('>HH', 0, 1))
    exch(READMEM, struct.pack('>IHH', EBASE + off, 0, 4), 0x85, struct.pack('>II', EBASE + off, 9))
    exch(WRITEMEM, struct.pack('>II', EBASE + off, 9), 0x87, struct.pack('>HH', 0, 4))

# GVCP to the learned message channel port from the host side, then GVSP
# packet to the learned stream port is in the GVSP capture
frames.append(to_cam(cmd(READREG, nreq(), struct.pack('>I', 0xA00)), sp=50021, dp=3956))
frames.append(from_cam(ack(0x81, req[0], struct.pack('>I', 2)), dp=50021))

# ---------------------------------------------------------------------
# malformed
# ---------------------------------------------------------------------
bad_frames = []


def B(payload, **kw):
    bad_frames.append(to_cam(payload, **kw))


def BA(payload, dp=50000):
    bad_frames.append(from_cam(payload, dp=dp))


# short packets
B(b'\x42\x01\x00\x80')                                     # < 8 bytes: not GVCP
B(b'\x42\x01\x00\x80\x00\x04\x00')
# not GVCP at all: first byte not 0x42 and no ack code
B(struct.pack('>HHHH', 0, 0x7777, 0, 1))
# truncated commands
B(cmd(DISCOVERY, 1)[:7])
B(cmd(FORCEIP, 2, b'\0' * 10))
B(cmd(RESEND, 3, b'\0' * 6))
B(cmd(RESEND, 3, b'\0' * 14, 0x11))
B(cmd(READREG, 4, b''))
B(cmd(READREG, 5, b'\0\0'))
B(cmd(READREG, 5, b'\0\0\x09\x38\0\0'))               # not a multiple of 4
B(cmd(WRITEREG, 6, b''))
B(cmd(WRITEREG, 6, b'\0\0\x09\x38'))
B(cmd(WRITEREG, 6, b'\0\0\x09\x38\0\0\0\1\0\0\x0a'))
B(cmd(WRITEREG, 6, struct.pack('>II', 0xB00, 0x00100001)[:6]))
B(cmd(READMEM, 7, b'\0\0\0\x48'))
B(cmd(WRITEMEM, 8, b''))                                 # length < 4 (fixed bug)
B(cmd(WRITEMEM, 8, b'\0\1'))
B(cmd(WRITEMEM, 8, b'\0\0\0\x48'))
B(cmd(WRITEMEM, 8, b'\0\0\0\x68' + b'x' * 10))
B(cmd(EVENT, 9, b'\0\0'))
B(cmd(EVENT, 9, ev16(1, 0, 1, 1)[:10]))
B(cmd(EVENT, 9, ev16(1, 0, 1, 1) + ev16(1, 0, 1, 1)[:9]))
B(cmd(EVENT, 9, ev64(1, 0, 1, 1)[:20], 0x11))
B(cmd(EVENTDATA, 10, ev16(1, 0, 1, 1)[:4]))
B(cmd(EVENTDATA, 10, ev16(1, 0, 1, 1) + b'x'))                          # > 12 bytes remain
B(cmd(EVENTDATA, 10, struct.pack('>H', 100) + ev64(1, 0, 1, 1)[2:] + b'x' * 4, 0x11))       # data_length beyond packet
B(cmd(EVENTDATA, 10, struct.pack('>H', 24) + ev64(1, 0, 1, 1)[2:], 0x11))
B(cmd(ACTION, 11, b'\0' * 8))
B(cmd(ACTION, 11, b'\0' * 14, 0x80))
# truncated acks
BA(ack(3, 20, b'\0' * 100))                                # discovery ack too short for the strings
BA(ack(3, 20, b'\0' * 150))
BA(ack(3, 20, b'\0' * 230))
BA(ack(3, 20, b'\0' * 240))
BA(ack(3, 20, b'\0' * 245))
BA(ack(0x81, 21, b''))
BA(ack(0x81, 21, b'\0\0\0'))
BA(ack(0x83, 22, b''))
BA(ack(0x83, 22, b'\0\0\0'))
BA(ack(0x85, 23, b'\0\0'))                                # length < 4 (fixed bug)
BA(ack(0x85, 23, b''))
BA(ack(0x85, 23, struct.pack('>I', 0x48) + b'abc'))
BA(ack(0x87, 24, b''))
BA(ack(0x87, 24, b'\0\0'))
BA(ack(0x89, 25, b''))
BA(ack(0x89, 25, b'\0\0'))
# claims more payload than is in the packet
BA(struct.pack('>HHHH', 0, 0x81, 400, 26) + b'\0\0\0\1')
B(struct.pack('>BBHHH', 0x42, 1, READREG, 400, 27) + b'\0\0\x09\x38')
# a request for the learned reg: ack for register list with the window and a
# truncated data section
B(cmd(READREG, 30, struct.pack('>I', sc(0, 0x3C))))
BA(ack(0x81, 30, struct.pack('>I', 0x00010000)))
B(cmd(READREG, 31, struct.pack('>II', 0x00010000, 0x00010004)))
BA(ack(0x81, 31, struct.pack('>I', 0x11)))
B(cmd(READREG, 32, struct.pack('>I', 0x00010000)))
BA(ack(0x81, 32, b''))
B(cmd(WRITEREG, 33, struct.pack('>II', 0x00010000, 1)[:7]))
B(cmd(READMEM, 34, struct.pack('>IHH', 0x00010008, 0, 4)))
BA(ack(0x85, 34, struct.pack('>I', 0x00010008) + b'\0\0'))


def pcap(path, fr):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(fr):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(p), len(p)))
            f.write(p)


out = sys.argv[1]
os.makedirs(out, exist_ok=True)
pcap(os.path.join(out, 'gvcp-coverage.pcap'), frames)
pcap(os.path.join(out, 'gvcp-coverage-malformed.pcap'), bad_frames)
print(len(frames), 'main frames,', len(bad_frames), 'malformed frames')
