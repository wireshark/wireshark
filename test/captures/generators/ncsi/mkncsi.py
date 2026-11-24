#!/usr/bin/env python3
# Generates test/captures/ncsi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# NCSI (packet-ncsi.c) synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())
def write_pcapng(name, items):
    '''items: (linktype, frame). One interface per link type.'''
    def block(btype, body):
        body += bytes(-len(body) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifaces = {}
    for lt in sorted(set(l for l, _ in items)):
        ifaces[lt] = len(ifaces)
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, f) in enumerate(items):
        ts = 1700000000 * 1000000 + i * 1000
        out += block(6, struct.pack('<IIIII', ifaces[lt], ts >> 32, ts & 0xffffffff, len(f), len(f)) + f)
    with open(name, 'wb') as fh:
        fh.write(out)

# ---- NC-SI over Ethernet (ethertype 0x88f8) and over MCTP (type 2).
# Header (16 bytes): MC id, revision, reserved, instance id, type, channel,
# reserved, payload length, 8 reserved bytes; then the payload and a 4 byte
# checksum. Responses have the bit 0x80 in the type and start with a
# response code and a reason code.
NCSI_ETH = 0x88f8
ZERO_MAC = bytes.fromhex('ffffffffffff')

def nc(typ, chan, payload=b'', plen=None, iid=1, mc=0, rev=1, tail=True):
    if plen is None:
        plen = len(payload)
    return bytes([mc, rev, 0, iid, typ, chan, 0, plen]) + bytes(8) + payload + (bytes(4) if tail else b'')

def ncframe(ncsi, src=1, dst=None):
    '''Ethernet frame, padded to the minimum size.'''
    dstmac = ZERO_MAC if dst is None else dst
    f = dstmac + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', NCSI_ETH) + ncsi
    return f + bytes(max(0, 60 - len(f))) if PAD[0] else f

PAD = [True]

def resp(code=0, reason=0):
    return struct.pack('>HH', code, reason)

frames = []
def add(ncsi, **k):
    frames.append(ncframe(ncsi, **k))

# --- requests without a payload: the commands of the specification and an
# unknown type
iid = 0
for typ in (0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0x0a, 0x0c, 0x0d, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
            0x1b, 0x1c, 0x23, 0x24, 0x25, 0x51, 0x52, 0x7e):
    iid += 1
    add(nc(typ, 0x00, iid=iid))
    add(nc(typ | 0x80, 0x00, plen=0, iid=iid), src=2)                    # reply without payload (plen 0)

# --- channel byte: package and internal channel
add(nc(0x03, 0x21))
add(nc(0x03, 0xff))

# --- requests with a payload
add(nc(0x01, 0x1f, bytes(3) + bytes([1])))                                # select package: hardware arbitration
add(nc(0x04, 0x01, bytes(3) + bytes([1])))                                # disable channel: allow link down
add(nc(0x08, 0x01, bytes(3) + bytes([0x07]) + struct.pack('>I', 0)))      # AEN enable
add(nc(0x09, 0x01, struct.pack('>II', 0xffffffff, 0x12345678)))           # set link, every bit
add(nc(0x09, 0x01, struct.pack('>II', 0x00000081, 0)))
add(nc(0x0e, 0x01, bytes.fromhex('020000000a0b') + bytes([1, 0x01]) + bytes(0)))   # set MAC, multicast, enable
add(nc(0x0e, 0x01, bytes.fromhex('020000000a0c') + bytes([2, 0x00])))
add(nc(0x10, 0x01, struct.pack('>I', 0x0000000f)))                        # enable broadcast filter, all
add(nc(0x10, 0x01, struct.pack('>I', 0x00000000)))

# --- responses
for code, reason in ((0, 0), (1, 2), (2, 3), (3, 0x0005), (4, 0x0006), (1, 0x0901), (1, 0x800c), (9, 0xfff0)):
    iid += 1
    add(nc(0x81, 0x01, resp(code, reason), iid=iid), src=2)               # select package response
add(nc(0x84, 0x01, resp(), iid=2), src=2)
add(nc(0x88, 0x01, resp(), iid=3), src=2)

# get link status response: every bit set and none
add(nc(0x8a, 0x01, resp() + struct.pack('>II', 0xffffffff, 0xffffffff)), src=2)
add(nc(0x8a, 0x01, resp() + struct.pack('>II', 0x00000000, 0x00000000)), src=2)
add(nc(0x8a, 0x01, resp() + struct.pack('>II', 0x00000025, 0x00000001)), src=2)   # link up, speed and duplex 2

# --- OEM commands. Mellanox (0x8119): get allocated management address,
# set MC affinity, get temperature; Broadcom (0x113d) and an unknown
# manufacturer are not decoded further.
MLX = struct.pack('>I', 0x8119)
BCM = struct.pack('>I', 0x113d)
def oem_req(oem, cmd, param, rest=b''):
    return oem + bytes([0, cmd, param]) + rest
add(nc(0x50, 0x01, oem_req(MLX, 0x00, 0x1b, bytes([0]))))
smc = (bytes.fromhex('0200000a0b0c') + bytes([0x3f]) + bytes([0x11, 0x01, 0xa0, 0x12, 0x02]) + struct.pack('>H', 0x5e)
       + bytes(2) + bytes([192, 0, 2, 7]) + bytes.fromhex('fe800000000000000000000000000007')
       + bytes.fromhex('20010db8000000000000000000000007'))
add(nc(0x50, 0x01, oem_req(MLX, 0x01, 0x07, bytes([0]) + smc)))
smc2 = bytes(6) + bytes([0x00]) + bytes(5) + bytes(2) + bytes(4) + bytes(16) + bytes(16)
add(nc(0x50, 0x01, oem_req(MLX, 0x01, 0x07, bytes([0]) + smc2)))
add(nc(0x50, 0x01, oem_req(MLX, 0x13, 0x02, bytes([0x81]))))             # get temperature, port sensor 1
add(nc(0x50, 0x01, oem_req(MLX, 0x13, 0x02, bytes([0x00]))))
add(nc(0x50, 0x01, oem_req(MLX, 0x05, 0x09, bytes(4))))                  # unknown Mellanox command
add(nc(0x50, 0x01, oem_req(BCM, 0x01, 0x02, bytes(4))))                  # Broadcom
add(nc(0x50, 0x01, oem_req(struct.pack('>I', 0x12345678), 0x01, 0x02, bytes(4))))

def oem_rep(oem, cmd, param, rest=b'', code=0, reason=0):
    return resp(code, reason) + oem + bytes([0, cmd, param]) + rest
add(nc(0xd0, 0x01, oem_rep(MLX, 0x00, 0x1b, bytes([1, 1, 0, 0, 0]) + bytes.fromhex('02000000aabb'))), src=2)
add(nc(0xd0, 0x01, oem_rep(MLX, 0x00, 0x1b, bytes([1, 0, 0, 0, 0]) + bytes(6))), src=2)
add(nc(0xd0, 0x01, oem_rep(MLX, 0x01, 0x07, bytes(2))), src=2)           # set MC affinity reply
add(nc(0xd0, 0x01, oem_rep(MLX, 0x13, 0x02, bytes([0x81, 0x1a, 45, 60, 85]))), src=2)   # temperature, ok
add(nc(0xd0, 0x01, oem_rep(MLX, 0x13, 0x02, bytes([0x01, 0x0f, 10, 20, 30]), code=1, reason=6)), src=2)   # failed: no temperatures
add(nc(0xd0, 0x01, oem_rep(MLX, 0x13, 0x02, bytes([0x01, 0x0f, 10, 20, 30]), code=0, reason=5)), src=2)   # reason only
add(nc(0xd0, 0x01, oem_rep(MLX, 0x77, 0x77, bytes(6))), src=2)           # unknown Mellanox reply
add(nc(0xd0, 0x01, oem_rep(BCM, 0x01, 0x02, bytes(4))), src=2)
add(nc(0xd0, 0x01, oem_rep(struct.pack('>I', 0x00ffee00), 0x01, 0x02, bytes(4))), src=2)

# --- get capabilities response (32 byte payload after the response code) and a short one
cap = (struct.pack('>IIII', 0x1f, 0x0f, 0x07, 0x2000) + struct.pack('>I', 0x1f)
       + bytes([4, 2, 3, 5]) + bytes(2) + bytes([0x07]) + bytes([2]))
add(nc(0x96, 0x01, resp() + cap), src=2)
cap0 = struct.pack('>IIII', 0, 0, 0, 0) + struct.pack('>I', 0) + bytes([0, 0, 0, 0]) + bytes(2) + bytes([0]) + bytes([0])
add(nc(0x96, 0x01, resp() + cap0), src=2)
add(nc(0x96, 0x01, resp(1, 2) + bytes(12)), src=2)                        # failed, short payload: not decoded

# --- get version ID response (payload of 40 bytes or more)
def ver_rep(ver8, name, fwver, did, vid, ssid, svid, iana, code=0, reason=0):
    return (resp(code, reason) + ver8 + name.ljust(12, b'\0')[:12] + fwver
            + struct.pack('>HHHHI', did, vid, ssid, svid, iana))
# NC-SI version 1.1.0 with alpha, firmware name, known and unknown PCI ids
add(nc(0x95, 0x01, ver_rep(bytes([0xf1, 0xf1, 0x00, 0x41, 0, 0, 0, 0x42]), b'ConnectX-4', bytes([0x10, 0x20, 0x30, 0x40]), 0x0039, 0x8086, 0xffff, 0xffff, 0x8119)), src=2)
add(nc(0x95, 0x01, ver_rep(bytes([0xf3, 0xf7, 0x10, 0x00, 0, 0, 0, 0x00]), b'fw 1.2', bytes([0x01, 0x02, 0x03, 0x04]), 0x0044, 0x8086, 0x0347, 0x1025, 0x113d)), src=2)
add(nc(0x95, 0x01, ver_rep(bytes([0x10, 0x01, 0xf7, 0x00, 0, 0, 0, 0x00]), b'unknown', bytes([0xaa, 0xbb, 0xcc, 0xdd]), 0x1234, 0xabcd, 0x5678, 0x9abc, 0)), src=2)
add(nc(0x95, 0x01, ver_rep(bytes([0xf1, 0xf0, 0xff, 0x41, 0, 0, 0, 0x00]), b'x', bytes(4), 0, 0x15b3, 0, 0, 0x15b3)), src=2)
add(nc(0x95, 0x01, ver_rep(bytes([0xf1, 0xf0, 0xff, 0x41, 0, 0, 0, 0x00]), b'x', bytes(4), 0, 0x15b3, 0, 0, 0x15b3) + bytes(4)), src=2)   # plen 44
add(nc(0x95, 0x01, resp(1, 6) + bytes(12)), src=2)                        # failed: payload shorter than 40
# the sanity frames of the review (version bytes that are no BCD, 0xff everywhere)
add(nc(0x95, 0x00, struct.pack('>HH', 0, 0) + bytes([0xf1, 0xf0, 0xff, 0xfe, 0, 0, 0, 0x81]) + b'\xff' * 12 + bytes(16) + bytes(8), plen=52), src=2)
add(nc(0x95, 0x00, struct.pack('>HH', 0, 0) + bytes([0xe9, 0xfa, 0x7c, 0x7f, 0x7f, 0x7f, 0x7f, 0xf0]) + b'\xe0\x80\xfe\xff' * 3 + bytes(16) + bytes(8), plen=52), src=2)

# --- asynchronous event notifications
def aen(typ, rest=b'', chan=0x01, plen=None):
    return nc(0xff, chan, bytes(3) + bytes([typ]) + rest, plen=plen, iid=0)
add(aen(0x00, struct.pack('>II', 0x0000ffff, 0x11)), src=2)               # link status change
add(aen(0x00, struct.pack('>II', 0x00000000, 0x0)), src=2)
add(aen(0x01), src=2)                                                     # configuration required
add(aen(0x02, struct.pack('>I', 1)), src=2)                               # host NC driver status change
add(aen(0x03, bytes([0x15, 0x2a, 0, 0])), src=2)                          # delayed response ready
add(aen(0x04), src=2)                                                     # reserved
add(aen(0x6f), src=2)
add(aen(0x70), src=2)                                                     # transport specific
add(aen(0x7f), src=2)
add(aen(0x80), src=2)                                                     # OEM specific
add(aen(0xfe), src=2)

# --- a destination other than broadcast, an IID of 0, an MC id and revision that differ
add(nc(0x03, 0x01, iid=0, mc=3, rev=2), dst=bytes.fromhex('0200000000aa'))

# --- shorter than the 8 bytes of an NC-SI header: not claimed by NCSI (no padding, so the frame stays short)
PAD[0] = False
add(nc(0x03, 0x00)[:6])
PAD[0] = True

# --- NC-SI over MCTP (message type 2): Linux cooked capture, ARPHRD_MCTP, protocol 0x00fa
def sll(payload):
    return struct.pack('>HHH8sH', 0, 290, 0, b'', 0x00fa) + payload
def mctp(payload, tag=1, to=1, dst=8, src=9):
    return sll(bytes([1, dst, src, 0xc0 | (to << 3) | tag, 0x02]) + payload)
mctp_frames = [
    mctp(nc(0x15, 0x00)),
    mctp(nc(0x95, 0x00, ver_rep(bytes([0xf1, 0xf1, 0x00, 0x41, 0, 0, 0, 0x42]), b'bmc', bytes(4), 0x0039, 0x8086, 0xffff, 0xffff, 0x8119)), to=0),
    mctp(nc(0x50, 0x00, oem_req(MLX, 0x13, 0x02, bytes([0x81])))),
]

main = frames
frames = []
PAD[0] = False
# ---- malformed (the frames are not padded to the Ethernet minimum, so that a cut payload ends the packet)
# payloads cut short
add(nc(0x01, 0x1f, bytes(3) + bytes([1]), tail=False)[:18])                  # select package without its byte
add(nc(0x09, 0x01, struct.pack('>II', 1, 2), tail=False)[:22])
add(nc(0x0e, 0x01, bytes(6), tail=False))                                     # set MAC: plen 6, byte 22 missing
add(nc(0x0e, 0x01, bytes(6), plen=8, tail=False))
add(nc(0x10, 0x01, bytes(2), tail=False))
add(nc(0x81, 0x01, bytes(2), plen=4, tail=False), src=2)                     # response code cut
add(nc(0xff, 0x01, bytes(3) + bytes([0x00]) + bytes(2), plen=8, tail=False), src=2)   # AEN link status cut
add(nc(0xff, 0x01, bytes(3), plen=4, tail=False), src=2)                     # AEN without a type
add(nc(0xff, 0x01, bytes(3) + bytes([0x03]) + bytes(1), plen=6, tail=False), src=2)
add(nc(0x8a, 0x01, resp() + bytes(2), tail=False), src=2)                    # link status cut
# OEM: ID cut, Mellanox payloads cut inside the command and the affinity addresses
add(nc(0x50, 0x01, bytes(2), tail=False))
add(nc(0x50, 0x01, MLX + bytes(2), tail=False))
add(nc(0x50, 0x01, oem_req(MLX, 0x01, 0x07, bytes([0]) + smc)[:30], plen=60, tail=False))
add(nc(0x50, 0x01, oem_req(MLX, 0x01, 0x07, bytes([0]) + smc), plen=2))      # plen smaller than the header of the Mellanox tree
add(nc(0x50, 0x01, oem_req(MLX, 0x13, 0x02, bytes([0x81]), ), plen=255))
add(nc(0xd0, 0x01, MLX, tail=False), src=2)
add(nc(0xd0, 0x01, oem_rep(MLX, 0x00, 0x1b, bytes([1, 1, 0, 0, 0]), ), tail=False), src=2)   # gama reply without the MAC
add(nc(0xd0, 0x01, oem_rep(MLX, 0x13, 0x02, bytes([0x81, 0x1a, 45])), tail=False), src=2)
add(nc(0xd0, 0x01, oem_rep(MLX, 0x13, 0x02, bytes([0x81, 0x1a, 45, 60, 85]))[:16], plen=40, tail=False), src=2)
# version and capabilities responses cut short while the length says complete
add(nc(0x95, 0x01, resp() + bytes(20), plen=40, tail=False), src=2)
add(nc(0x95, 0x01, resp() + bytes(40), plen=60, tail=False), src=2)
add(nc(0x96, 0x01, resp() + bytes(12), plen=32, tail=False), src=2)
add(nc(0x95, 0x01, ver_rep(bytes([0xf1, 0xf0, 0xff, 0x41, 0, 0, 0, 0]), b'x', bytes(4), 0, 0x8086, 0, 0, 0), plen=30), src=2)   # plen below 40: nothing
add(nc(0x03, 0x01, plen=200, tail=False))                                  # a payload length past the packet
add(nc(0x03, 0x01, bytes(4), plen=0xff, tail=False))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    # main capture: pcapng with an Ethernet interface (NC-SI over Ethernet) and a
    # Linux cooked interface (NC-SI over MCTP)
    write_pcapng(os.path.join(out, 'ncsi-coverage.pcapng'), [(1, f) for f in main] + [(113, f) for f in mctp_frames])
    gz(os.path.join(out, 'ncsi-coverage.pcapng'))
    os.rename(os.path.join(out, 'ncsi-coverage.pcapng.gz'), os.path.join(out, 'ncsi_coverage.pcapng.gz'))
    write_pcapng(os.path.join(out, 'ncsi-coverage-malformed.pcapng'), [(1, f) for f in frames])
