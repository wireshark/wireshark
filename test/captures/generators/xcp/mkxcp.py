#!/usr/bin/env python3
# Generates test/captures/xcp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XCP dissector (packet-xcp.c).

XCP (Universal Measurement and Calibration Protocol) has no port of its
own: the dissector is reached through the mapping tables (UATs) that
tie an ECU address and port, or a pair of CAN IDs, to an ECU ID. The
captures are built for the mappings in cfg/ (see below); tshark must
run with WIRESHARK_CONFIG_DIR pointing to a directory holding them:

  cfg/XCP_Mapping_UDP_TCP  IPv4 192.0.2.85 UDP 5555 -> ECU 1
                           IPv4 192.0.2.85 TCP 5556 -> ECU 2
                           ANY  (any address) UDP 6666 -> ECU 3
                           IPv6 2001:db8::85 UDP 5557 -> ECU 4
                           IPv4 192.0.2.86 UDP 5558 -> ECU 7
                           ANY  (any address) TCP 6667 -> ECU 8
  cfg/XCP_Mapping_CAN      CAN IDs 0x101 (M->S) / 0x102 (S->M) -> ECU 5
                           extended IDs 0x98DA00F1 / 0x98DAF100 -> ECU 6
  cfg/XCP_Addresses        names for memory addresses of ECU 1 and 5

A pcapng file with an Ethernet interface and a SocketCAN interface.
Every session runs CONNECT, the status and information commands, seed
and key, memory access, calibration pages, the DAQ configuration, DAQ
start and data packets (DTOs), programming and the two byte commands,
with the matching positive responses; byte order and address
granularity differ per ECU (little endian/1 byte on ECU 1, big
endian/2 bytes on ECU 2, little endian/4 bytes on ECU 3 ...).

Usage: mkxcp.py <outdir>
Writes xcp-coverage.pcapng and xcp-coverage-malformed.pcapng.
"""
import os
import struct
import sys

ECU4 = bytes([192, 0, 2, 85])
MASTER4 = bytes([192, 0, 2, 10])
ECU6 = bytes.fromhex('20010db8000000000000000000000085')
MASTER6 = bytes.fromhex('20010db8000000000000000000000010')
MAC_M = bytes.fromhex('020000000001')
MAC_E = bytes.fromhex('020000000002')

# ------------------------------------------------------------------ pcapng
def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)

def block(btype, body):
    body = pad4(body)
    return struct.pack('<II', btype, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))

def write_pcapng(path, frames):
    """frames: list of (interface, bytes)"""
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 0))        # Ethernet
    out += block(1, struct.pack('<HHI', 227, 0, 0))      # SocketCAN
    for i, (itf, p) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += block(6, struct.pack('<IIIII', itf, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    with open(path, 'wb') as f:
        f.write(out)

# ---------------------------------------------------------------- network
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_ip4(proto, l4, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return MAC_E + MAC_M + b'\x08\x00' + ip + l4

def udp4(src, dst, sport, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip4(17, u, src, dst)

def udp6(src, dst, sport, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!IxxxB', len(u), 17)
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    ip = struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + src + dst
    return MAC_E + MAC_M + b'\x86\xdd' + ip + u

def tcp4(src, dst, sport, dport, seq, ack, flags, payload=b'', opts=b''):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth_ip4(6, t, src, dst)

def can_frame(cid, data, ext=False):
    return struct.pack('>IBBBB', cid | (0x80000000 if ext else 0), len(data), 0, 0, 0) + data.ljust(8, b'\0')

# -------------------------------------------------------------- sessions
class Sess:
    """One ECU: m2s()/s2m() add a frame to the capture. kind: udp4, tcp4, udp6, any, can, canx"""
    def __init__(self, out, kind, be=False, gran=1, mport=40000):
        self.out, self.kind, self.be, self.gran, self.mport = out, kind, be, gran, mport
        self.ctr = 0
        self.seq_m, self.seq_s = 1000, 5000
        if kind == 'tcp4':
            self._tcp(MASTER4, ECU4, mport, 5556, 0, 0, 0x02, b'')
            self._tcp(ECU4, MASTER4, 5556, mport, 0, 1, 0x12)
            self._tcp(MASTER4, ECU4, mport, 5556, 1, 1, 0x10)
            self.seq_m, self.seq_s = 1, 1

    def _tcp(self, s, d, sp, dp, seq, ack, flags, payload=b''):
        self.out.append((0, tcp4(s, d, sp, dp, seq, ack, flags, payload,
                                 opts=b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 2 else b'')))

    def e16(self, v): return struct.pack('>H' if self.be else '<H', v)
    def e32(self, v): return struct.pack('>I' if self.be else '<I', v)

    def pdu(self, payload):
        p = struct.pack('<HH', len(payload), self.ctr) + payload
        self.ctr = (self.ctr + 1) & 0xffff
        return p

    def send(self, payload, to_ecu, raw=False):
        k = self.kind
        if k in ('can', 'canx'):
            cid, ext = ((0x101, False) if to_ecu else (0x102, False)) if k == 'can' else \
                       ((0x18DA00F1, True) if to_ecu else (0x18DAF100, True))
            self.out.append((1, can_frame(cid, payload, ext)))
            return
        p = payload if raw else self.pdu(payload)
        if k == 'udp4':
            f = udp4(MASTER4, ECU4, self.mport, 5555, p) if to_ecu else udp4(ECU4, MASTER4, 5555, self.mport, p)
        elif k == 'any':
            f = udp4(MASTER4, bytes([192, 0, 2, 99]), self.mport, 6666, p) if to_ecu else \
                udp4(bytes([192, 0, 2, 99]), MASTER4, 6666, self.mport, p)
        elif k == 'udp4b':
            b = bytes([192, 0, 2, 86])
            f = udp4(MASTER4, b, self.mport, 5558, p) if to_ecu else udp4(b, MASTER4, 5558, self.mport, p)
        elif k == 'anytcp':
            b = bytes([192, 0, 2, 99])
            if to_ecu:
                f = tcp4(MASTER4, b, self.mport, 6667, self.seq_m, self.seq_s, 0x18, p)
                self.seq_m += len(p)
            else:
                f = tcp4(b, MASTER4, 6667, self.mport, self.seq_s, self.seq_m, 0x18, p)
                self.seq_s += len(p)
        elif k == 'udp6':
            f = udp6(MASTER6, ECU6, self.mport, 5557, p) if to_ecu else udp6(ECU6, MASTER6, 5557, self.mport, p)
        else:
            if to_ecu:
                f = tcp4(MASTER4, ECU4, self.mport, 5556, self.seq_m, self.seq_s, 0x18, p)
                self.seq_m += len(p)
            else:
                f = tcp4(ECU4, MASTER4, 5556, self.mport, self.seq_s, self.seq_m, 0x18, p)
                self.seq_s += len(p)
        self.out.append((0, f))

    def m2s(self, payload, **kw): self.send(bytes(payload), True, **kw)
    def s2m(self, payload, **kw): self.send(bytes(payload), False, **kw)
    def xchg(self, req, res):
        self.m2s(req)
        self.s2m(bytes([0xFF]) + bytes(res))

    def elems(self, n, base=0x10):
        """n data elements for the address granularity"""
        b = b''
        for i in range(n):
            b += (bytes([base + i]) if self.gran == 1 else
                  self.e16(0x1000 + base + i) if self.gran == 2 else self.e32(0x10000000 + base + i))
        return b

    def data_pad(self):
        """padding before the elements: 2 reserved octets for granularity 4 in DOWNLOAD"""
        return b'\0\0' if self.gran == 4 else b''

def connect(S, res=0x1D, maxcto=8, maxdto=0x0100, mode=0):
    gran_bits = {1: 0, 2: 1, 4: 2}[S.gran] << 1
    comm = (1 if S.be else 0) | gran_bits
    S.m2s([0xFF, mode])
    dto = struct.pack('>H' if S.be else '<H', maxdto)
    S.s2m(bytes([0xFF, res, comm, maxcto]) + dto + bytes([1, 1]))

def full_session(S, name_addr=None, daq=True, tail=True):
    be, g = S.be, S.gran
    e16, e32 = S.e16, S.e32
    nbytes = lambda n: n * g
    connect(S)
    S.xchg([0xFD], [0x01, 0x40, 0x07] + list(e16(0x1234)))                   # GET_STATUS
    S.xchg([0xFC], [])                                                      # SYNCH
    S.xchg([0xFB], [0x00, 0x03, 0x00, 4, 2, 8, 0x10])                        # GET_COMM_MODE_INFO
    for idt in (0, 1, 2, 3, 4, 0x80):                                       # GET_ID
        S.m2s([0xFA, idt])
        text = b'ECU-%d' % idt
        S.s2m(bytes([0xFF, 0x01 if idt != 4 else 0x03, 0, 0]) + e32(len(text)) + text)
    S.m2s([0xFA, 5])
    S.s2m(bytes([0xFF, 0x00, 0, 0]) + e32(8))                                # not transferred
    S.m2s([0xFA, 6])
    S.s2m(bytes([0xFF, 0x02, 0, 0]) + e32(4) + b'\xde\xad\xbe\xef')          # compressed/encrypted bytes? mode 2 and not transfer
    S.xchg([0xF9, 0x01] + list(e16(0x5678)), [])                             # SET_REQUEST
    S.xchg([0xF9, 0x7f] + list(e16(0)), [])                                  # SET_REQUEST, every flag
    S.m2s([0xF8, 0x00, 0x01])                                                # GET_SEED first part
    S.s2m(bytes([0xFF, 4, 0xaa, 0xbb, 0xcc, 0xdd]))
    S.m2s([0xF8, 0x01, 0x00])                                                # remaining
    S.s2m(bytes([0xFF, 2, 0x11, 0x22]))
    S.m2s([0xF7, 4, 0x01, 0x02, 0x03, 0x04])                                 # UNLOCK
    S.s2m(bytes([0xFF, 0x1d]))
    # memory access: SET_MTA with and without a known name, upload, short upload
    S.xchg([0xF6, 0, 0, 0] + list(e32(0x1000)), [])
    S.xchg([0xF6, 0, 0, 1] + list(e32(0x2345)), [])
    S.m2s([0xF5, 3])
    S.s2m(bytes([0xFF]) + (b'\0' * (0 if g == 1 else 1 if g == 2 else 3)) + S.elems(3))
    S.m2s([0xF4, 4, 0, 0] + list(e32(0x1000)))
    S.s2m(bytes([0xFF]) + (b'\0' * (0 if g == 1 else 1 if g == 2 else 3)) + S.elems(4))
    S.m2s([0xF4, 2, 0, 1] + list(e32(0x9999)))
    S.s2m(bytes([0xFF]) + (b'\0' * (0 if g == 1 else 1 if g == 2 else 3)) + S.elems(2))
    S.xchg([0xF3, 0, 0, 0] + list(e32(1024)), [0x01, 0, 0] + list(e32(0xcafebabe)))   # BUILD_CHECKSUM
    # TRANSPORT_LAYER_CMD: Ethernet GET_SLAVE_ID (IPv4 and other version) or CAN sub commands
    if S.kind in ('can', 'canx'):
        S.xchg([0xF2, 0xFF], [0, 0, 0])
        S.xchg([0xF2, 0xFE], [0, 0, 0])
    else:
        S.m2s([0xF2, 0xFF] + list(struct.pack('<H', 5555)) + [192, 0, 2, 10] + [0] * 12 + [0])
        S.s2m(bytes([0xFF, 0]))
        S.m2s([0xF2, 0xFF] + list(struct.pack('<H', 5555)) + [0] * 16 + [1])
        S.s2m(bytes([0xFF, 0]))
        S.m2s([0xF2, 0xFD, 1, 2, 3])
        S.s2m(bytes([0xFF, 0]))
    S.m2s([0xF2, 0xFA, 1])
    S.s2m(bytes([0xFF, 0]))
    # DOWNLOAD, SHORT_DOWNLOAD
    S.m2s([0xF0, 2] + list(S.data_pad()) + list(S.elems(2)))
    S.s2m([0xFF])
    S.m2s([0xED, 2, 0, 0] + list(e32(0x1004)) + list(S.elems(2)))
    S.s2m([0xFF])
    S.m2s([0xED, 1, 0, 1] + list(e32(0xabcdef)) + list(S.elems(1)))
    S.s2m([0xFF])
    S.xchg([0xEE, 1] + list(S.elems(1)), [])                                 # DOWNLOAD_MAX: not dissected (not implemented)
    # calibration pages
    S.xchg([0xEB, 0x83, 0, 1], [])
    S.xchg([0xEB, 0x01, 2, 3], [])
    S.xchg([0xEB, 0x02, 2, 3], [])
    S.xchg([0xEA, 1, 0], [0, 0, 1])
    S.xchg([0xE9], [])
    S.xchg([0xE8, 0, 1, 0, 0], [])
    S.xchg([0xE6, 1, 0], [])
    S.xchg([0xE6, 0, 3], [])
    S.xchg([0xE4, 0, 0, 1, 1], [])
    if daq:
        # DAQ lists: free, allocate (3 lists), ODTs, entries, pointer, write, mode, start
        S.xchg([0xD6], [])
        S.xchg([0xD5, 0] + list(e16(3)), [])
        S.xchg([0xD4, 0] + list(e16(0)) + [2], [])
        S.xchg([0xD4, 0] + list(e16(1)) + [1], [])
        S.xchg([0xD4, 0] + list(e16(2)) + [0], [])
        S.xchg([0xD3, 0] + list(e16(0)) + [0, 2], [])
        S.xchg([0xD3, 0] + list(e16(0)) + [1, 1], [])
        S.xchg([0xD3, 0] + list(e16(1)) + [0, 3], [])
        S.xchg([0xD3, 0] + list(e16(5)) + [0, 1], [])                       # unknown DAQ list
        S.xchg([0xE3, 0] + list(e16(0)), [])
        S.xchg([0xE2, 0] + list(e16(0)) + [0, 0], [])                       # SET_DAQ_PTR
        S.xchg([0xE1, 0xff, 2, 0] + list(e32(0x1000)), [])                  # WRITE_DAQ: named address, size 2
        S.xchg([0xE1, 0xff, 1, 0] + list(e32(0x3000)), [])
        S.xchg([0xE2, 0] + list(e16(0)) + [1, 0], [])
        S.xchg([0xE1, 4, 4, 1] + list(e32(0x2345)), [])                     # bit offset, size 4
        S.xchg([0xE2, 0] + list(e16(1)) + [0, 0], [])
        S.xchg([0xE1, 0xff, 2, 0] + list(e32(0x1004)), [])
        S.xchg([0xE1, 0xff, 3, 0] + list(e32(0x1008)), [])                  # odd size
        S.xchg([0xE1, 0xff, 1, 0] + list(e32(0x100c)), [])
        S.xchg([0xE1, 0xff, 1, 0] + list(e32(0x100d)), [])                  # more writes than entries
        S.xchg([0xE0, 0x00] + list(e16(0)) + list(e16(1)) + [1, 5], [])      # SET_DAQ_LIST_MODE: DAQ, no flags
        S.xchg([0xE0, 0x1a] + list(e16(1)) + list(e16(2)) + [2, 6], [])      # timestamp + pid off + dir(STIM)?
        S.xchg([0xE0, 0x3f] + list(e16(2)) + list(e16(3)) + [3, 7], [])
        S.m2s([0xDE, 0x02] + list(e16(0)))                                   # START_STOP_DAQ_LIST: select
        S.s2m([0xFF, 0x00])
        S.m2s([0xDE, 0x01] + list(e16(0)))                                   # start: the first PID is learned
        S.s2m([0xFF, 0x10])
        S.m2s([0xDE, 0x01] + list(e16(1)))
        S.s2m([0xFF, 0x20])
        S.m2s([0xDE, 0x00] + list(e16(2)))                                   # stop
        S.s2m([0xFF, 0x30])
        S.m2s([0xDE, 0x07] + list(e16(2)))                                   # unknown mode
        S.s2m([0xFF, 0x30])
        S.xchg([0xDD, 0x01], [])
        S.xchg([0xDD, 0x02], [])
        S.xchg([0xDD, 0x00], [])
        S.xchg([0xDD, 0x09], [])
        S.m2s([0xDC])
        S.s2m(bytes([0xFF, 0, 0x08, 0x15]) + e32(123456))                    # GET_DAQ_CLOCK (legacy timestamp)
        S.xchg([0xDB], [])
        S.m2s([0xDA])
        S.s2m(bytes([0xFF, 0x7f]) + e16(8) + e16(4) + bytes([2, 0x3f]))
        S.m2s([0xD9])
        S.s2m(bytes([0xFF, 1, 255, 1, 255, 0xdc]) + e16(10))
        S.m2s([0xD8, 0] + list(e16(0)))
        S.s2m(bytes([0xFF, 0x03, 8, 8]) + e16(1))                             # fixed event present
        S.m2s([0xD8, 0] + list(e16(1)))
        S.s2m(bytes([0xFF, 0x01, 8, 8]))
        S.m2s([0xD7, 0] + list(e16(0)))
        S.s2m(bytes([0xFF, 0x1c, 4, 8, 10, 6, 3]))
        # DAQ data packets (DTOs): the PIDs learned at the start commands (0x10.. for list 0, 0x20 for list 1)
        S.s2m(bytes([0x10]) + b'\x12' * (2 * g) + b'\x34' * g)
        S.s2m(bytes([0x11]) + b'\x07' * (4 * g))
        S.s2m(bytes([0x20]) + b'\x01' * (2 * g) + b'\x02' * (3 * g) + b'\x03' * g)
        S.s2m(bytes([0x99]) + b'\x00' * 6)                                    # unknown PID: not an ODT
        S.s2m(bytes([0xFE, 0x11]))                                            # error packet
        S.s2m(bytes([0xFD, 0x01, 0x02]))                                      # event
        S.s2m(bytes([0xFC, 0x01]))                                            # service request
        S.s2m(bytes([0x40, 0x01]))
    # programming
    S.m2s([0xD2])
    S.s2m(bytes([0xFF, 0, 0x03, 8, 2, 1, 4]))
    S.m2s([0xD1, 0, 0, 0] + list(e32(0x1000)))
    S.s2m([0xFF])
    S.m2s([0xD1, 1, 0, 0] + list(e32(0x7)))
    S.s2m([0xFF])
    S.m2s([0xD1, 2, 0, 0] + list(e32(0)))
    S.s2m([0xFF])
    S.m2s([0xD0, 3] + list(S.data_pad()) + list(S.elems(3)))
    S.s2m([0xFF])
    S.xchg([0xCF], [])
    S.xchg([0xCE], [])
    S.xchg([0xCC, 0, 0, 0], [])
    S.xchg([0xCB], [])
    S.xchg([0xC9], [])
    S.xchg([0xC8], [])
    S.xchg([0xC7], [])
    S.xchg([0xC6], [])
    S.xchg([0xF1], [])
    S.xchg([0xDF], [])
    S.xchg([0xE5], [])
    S.xchg([0xE7], [])
    S.xchg([0xEC], [])
    # two byte commands
    S.m2s([0xC0, 0x00])
    S.s2m([0xFF, 0, 1, 3, 1, 1])
    S.m2s([0xC0, 0x01] + list(e16(1)) + [0x01, 0x03] + list(e16(4)))
    S.s2m([0xFF])
    S.m2s([0xC0, 0x01] + list(e16(2)) + [0x00, 0x00] + list(e16(0)))
    S.s2m([0xFF])
    S.m2s([0xC0, 0x02] + list(e16(2)))
    S.s2m([0xFF, 0, 0, 0])
    S.m2s([0xC0, 0xFC, 0x00, 1, 2, 3])                                       # software debugging
    S.s2m([0xFF, 0, 1])
    S.m2s([0xC0, 0xFD] + list(e16(6)))                                       # POD: get status
    S.s2m([0xFF, 0, 1])
    S.m2s([0xC0, 0xFD] + list(e16(4)) + [1, 2])                              # POD: download
    S.s2m([0xFF, 0, 1])
    S.m2s([0xC0, 0xFD] + list(e16(1)) + [1])
    S.s2m([0xFF, 0, 1])
    S.m2s([0xC0, 0x55, 1])                                                   # unknown two byte command
    S.s2m([0xFF, 1])
    S.m2s([0x42, 1, 2])                                                      # unknown command
    S.s2m([0xFF, 1, 2])
    # errors, events and service requests from the slave; a response without request
    S.m2s([0xF4, 1, 0, 0] + list(e32(0x7000)))
    S.s2m([0xFE, 0x22])
    S.s2m([0xFD, 0x05])
    S.m2s([0xFE])
    S.s2m([0xFF])
    S.m2s([0xFF, 0x01])                                                      # CONNECT again (mode: user defined)
    S.s2m(bytes([0xFF, 0x1D, (1 if be else 0) | ({1: 0, 2: 2, 4: 4}[g]), 8]) + (struct.pack('>H' if be else '<H', 0x100)) + bytes([1, 1]))

main, mal = [], []

# ECU 1 (UDP, little endian, 1 octet granularity): the whole command set
S = Sess(main, 'udp4', False, 1, 40001)
full_session(S)
# ECU 2 (TCP, big endian, 2 octet granularity; the byte order is saved per frame, the address
# granularity is stream state, so every CONNECT of an ECU must use the same one to give the same
# output with -2)
T = Sess(main, 'tcp4', True, 2, 40002)
full_session(T)
# ECU 3 (any address, UDP 6666): the reproducer of the byte order: SET_REQUEST before CONNECT,
# then CONNECT (big endian) and a status
A = Sess(main, 'any', True, 4, 40003)
A.m2s([0xF9, 0x00, 0x12, 0x34])
connect(A)
A.xchg([0xF9, 0x00, 0x12, 0x34], [])
A.xchg([0xFD], [0x01, 0x40, 0x07, 0x12, 0x34])
full_session(A)
# ECU 4 (IPv6)
V = Sess(main, 'udp6', False, 1, 40004)
connect(V)
V.xchg([0xFD], [0x01, 0x40, 0x07, 0x34, 0x12])
V.m2s([0xF4, 2, 0, 0, 0, 0x10, 0, 0])
V.s2m(bytes([0xFF, 1, 2]))
# Streams whose first frame comes from the slave: a specific address and an 'any' address
E7 = Sess(main, 'udp4b', False, 1, 40020)
E7.s2m([0xFD, 0x00])
connect(E7)
E7.xchg([0xFD], [0x01, 0x40, 0x07, 0x00, 0x01])
E8 = Sess(main, 'anytcp', False, 1, 40021)
E8.s2m([0xFD, 0x00])
connect(E8)
E8.xchg([0xFD], [0x01, 0x40, 0x07, 0x00, 0x01])
# ECU 3 again from a second address: the stream exists but the direction is unknown (both are shown)
E3 = Sess(main, 'any', True, 4, 40022)
E3.out.append((0, udp4(MASTER4, bytes([192, 0, 2, 98]), 40022, 6666, E3.pdu(bytes([0xFD])))))
# ECU 5 (CAN, standard IDs): 8 octet frames; ECU 6 (extended IDs, big endian)
C = Sess(main, 'can', False, 1)
connect(C, maxcto=8)
C.xchg([0xFD], [0x01, 0x40, 0x07, 0x34, 0x12])
C.m2s([0xF6, 0, 0, 1, 0x00, 0x20, 0, 0])
C.s2m([0xFF])
C.m2s([0xF4, 2, 0, 1, 0x00, 0x20, 0, 0])
C.s2m([0xFF, 1, 2])
C.xchg([0xF2, 0xFF], [0, 0, 0])
C.xchg([0xC0, 0x00], [0, 1, 3, 1, 1][:5])
D = Sess(main, 'canx', True, 1)
connect(D, maxcto=8)
D.xchg([0xFD], [0x01, 0x40, 0x07, 0x12, 0x34])
D.m2s([0xF4, 1, 0, 0, 0, 0, 0x10, 0])
D.s2m([0xFF, 0, 0, 1, 2][:5])
# DAQ_COUNT limit: 256 is tracked, 257 and 65535 are not (warnings); several in one datagram (the reproducer
# of the memory blow-up used 175 per datagram with 65535)
Q = Sess(main, 'udp4', False, 1, 40010)
connect(Q)
Q.xchg([0xD5, 0, 0x00, 0x01], [])
Q.xchg([0xD5, 0, 0x01, 0x01], [])
Q.xchg([0xD5, 0, 0xff, 0xff], [])
pdu = lambda pl, c: struct.pack('<HH', len(pl), c) + pl
Q.send(b''.join(pdu(bytes([0xD5, 0, 0xff, 0xff]), 100 + i) for i in range(4)), True, raw=True)
Q.xchg([0xD6], [])
Q.xchg([0xD5, 0, 0x00, 0x00], [])
Q.xchg([0xD5, 0, 0x02, 0x00], [])
# several PDUs in one datagram; PDU header splits
Q.send(pdu(bytes([0xFD]), 200) + pdu(bytes([0xFC]), 201), True, raw=True)
Q.send(pdu(bytes([0xFF, 0x01, 0x40, 0x07, 0x12, 0x34]), 200) + pdu(bytes([0xFF]), 201), False, raw=True)
# TCP: a PDU in two segments
T2 = Sess(main, 'tcp4', False, 2, 40011)
connect(T2)
raw = T2.pdu(bytes([0xF4, 1, 0, 0, 0, 0x10, 0, 0]))
T2.out.append((0, tcp4(MASTER4, ECU4, 40011, 5556, T2.seq_m, T2.seq_s, 0x18, raw[:3])))
T2.out.append((0, tcp4(MASTER4, ECU4, 40011, 5556, T2.seq_m + 3, T2.seq_s, 0x18, raw[3:])))
T2.seq_m += len(raw)
T2.s2m(bytes([0xFF, 0]) + T2.e16(0x1234))

# ------------------------------------------------------------------ malformed
# Address granularity of 4 octets on ECU 4 (the main capture uses 1 for it)
G4b = Sess(mal, 'udp6', False, 4, 41004)
full_session(G4b, daq=False)
M = Sess(mal, 'udp4', False, 1, 41001)
connect(M)
M.m2s([0xF6, 0, 0, 0, 1, 2])                    # truncated commands
M.m2s([0xF4, 4, 0])
M.m2s([0xF3, 0, 0])
M.m2s([0xF9, 0])
M.m2s([0xF0, 9, 1, 2])                           # DOWNLOAD with fewer elements than counted
M.m2s([0xE1, 0xff, 2])
M.m2s([0xE0, 0, 0, 0])
M.m2s([0xD1, 1, 0, 0, 0, 0])
M.m2s([0xC0])
M.m2s([0xC0, 0x01, 0, 0])
M.m2s([0xF7, 8, 1])
M.m2s([0xF2, 0xFF, 1])
M.m2s([0xF2])
M.s2m([0xFF, 0x1D])                              # short responses
M.m2s([0xFD])
M.s2m([0xFF, 1, 2])
M.m2s([0xFA, 0])
M.s2m([0xFF, 1, 0, 0, 0xff, 0xff, 0xff, 0x7f, 65])
M.m2s([0xFA, 0])
M.s2m([0xFF, 1, 0, 0, 100, 0, 0, 0, 65])
M.m2s([0xF8, 0, 1])
M.s2m([0xFF, 9, 1])
M.m2s([0xF5, 4])
M.s2m([0xFF, 1])
M.m2s([0xDA])
M.s2m([0xFF, 1, 2])
M.m2s([0xD8, 0, 0, 0])
M.s2m([0xFF, 0x03, 1, 1])
M.m2s([0xDC])
M.s2m([0xFF, 0, 0])
M.m2s([0xC0, 0x00])
M.s2m([0xFF, 0, 1])
M.m2s([0xD2])
M.s2m([0xFF, 0, 1])
M.s2m([0xFF])                                    # DTO with no matching PID, and a response without a request
# header problems: PDU length past the datagram, zero length, header only
M.send(struct.pack('<HH', 200, 1) + b'\xff', True, raw=True)
M.send(struct.pack('<HH', 0, 2), True, raw=True)
M.send(b'\x01\x00', True, raw=True)
M.send(struct.pack('<HH', 0xffff, 3) + b'\xf6', False, raw=True)
# CAN frames with no data and an RTR/error frame
MC = Sess(mal, 'can', False, 1)
mal.append((1, struct.pack('>IBBBB', 0x101, 0, 0, 0, 0) + bytes(8)))
mal.append((1, struct.pack('>IBBBB', 0x101 | 0x40000000, 1, 0, 0, 0) + bytes(8)))          # RTR
mal.append((1, struct.pack('>IBBBB', 0x101 | 0x20000000, 1, 0, 0, 0) + bytes(8)))          # error frame
mal.append((1, can_frame(0x103, b'\xFF\x00')))                                              # not mapped
MC.m2s([0xF4, 1, 0, 0, 0, 0, 0, 0])
MC.s2m([0xFF])
MC.m2s([0xC0])
MC.m2s([0xF6, 0, 0])

out = sys.argv[1]
write_pcapng(os.path.join(out, 'xcp-coverage.pcapng'), main)
write_pcapng(os.path.join(out, 'xcp-coverage-malformed.pcapng'), mal)
print(len(main), len(mal))
