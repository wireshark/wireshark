#!/usr/bin/env python3
# Generates test/captures/iwarp_ddp_rdmap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the iWARP DDP/RDMAP dissector
(packet-iwarp-ddp-rdmap.c, RFC 5040/5041 and the atomic extensions).

DDP/RDMAP segments are carried in MPA FPDUs over TCP; the MPA heuristic
dissector (enabled by default) recognises the MPA Request/Reply frames and
hands every FPDU to this dissector.  Every packet is built with struct; no
captured traffic is used.

Usage: mkiwarp-ddp-rdmap.py <output directory>

Writes:
  iwarp-ddp-rdmap-coverage.pcap            every RDMAP opcode (Write, Read
                                           Request/Response, the four Sends,
                                           Terminate, Atomic Request and
                                           Response), fragmented Sends,
                                           reserved bits and unknown opcodes
  iwarp-ddp-rdmap-coverage-malformed.pcap  segments cut short
"""
import os
import struct
import sys


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


MAC_I = bytes.fromhex('020000000001')
MAC_R = bytes.fromhex('020000000002')


def tcp_frame(from_init, sport, dport, seq, ack, payload, flags=0x18):
    src, dst = ((10, 0, 0, 1), (10, 0, 0, 2)) if from_init else ((10, 0, 0, 2), (10, 0, 0, 1))
    ps, pd = (sport, dport) if from_init else (dport, sport)
    tcp = struct.pack('!HHIIBBHHH', ps, pd, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    mac_dst, mac_src = (MAC_R, MAC_I) if from_init else (MAC_I, MAC_R)
    return mac_dst + mac_src + b'\x08\x00' + ip + tcp + payload


# ----------------------------------------------------------------- DDP / RDMAP

def ddp_send(msn, mo, data, last=True, opcode=3, qn=0, inval_stag=0):
    """Untagged DDP segment: control, RDMAP control (version 1 + opcode), 4
    octets (the invalidate STag for the invalidating Sends), QN, MSN, MO."""
    ctl = (0x40 if last else 0) | 0x01
    return (bytes([ctl, 0x40 | opcode]) + struct.pack('>I', inval_stag)
            + struct.pack('>III', qn, msn, mo) + data)


def ddp_write(stag, to, data, last=True):
    """Tagged DDP segment (RDMA Write)."""
    ctl = 0x80 | (0x40 if last else 0) | 0x01
    return bytes([ctl, 0x40]) + struct.pack('>IQ', stag, to) + data


def rdma_read_request(sink_stag, sink_to, size, src_stag, src_to):
    return (bytes([0x41, 0x41]) + struct.pack('>I', 0) + struct.pack('>III', 1, 0, 0)
            + struct.pack('>IQIIQ', sink_stag, sink_to, size, src_stag, src_to))


# ----------------------------------------------------------------------- MPA

REQ_KEY = b'MPA ID Req Frame'
REP_KEY = b'MPA ID Rep Frame'


def mpa_req_rep(key, flags, rev, private=b'', pd_len=None):
    return key + bytes([flags, rev]) + struct.pack('>H', len(private) if pd_len is None else pd_len) + private


def fpdu(ulpdu, p0=0, markers=False, crc=False, bad_crc=False, trailing=b'', ulpdu_len=None):
    """One FPDU placed at stream offset p0 (relative to the first FPDU of
    the sender, which sits on a multiple of 512).  With markers, a 4 octet
    marker is inserted whenever the stream offset is a multiple of 512.
    Returns the segment payload and the number of octets."""
    base = struct.pack('>H', len(ulpdu) if ulpdu_len is None else ulpdu_len) + ulpdu
    base += b'\0' * ((-len(base)) % 4)
    out = bytearray()
    pos = p0
    start = p0
    def marker():
        return struct.pack('>HH', 0, (pos - start) & 0xffff)
    for b in base:
        if markers and pos % 512 == 0:
            out += marker()
            pos += 4
        out.append(b)
        pos += 1
    if markers and pos % 512 == 0:
        out += marker()
        pos += 4
    if crc:
        c = crc32c(bytes(out))
        if bad_crc:
            c ^= 0x1
        out += struct.pack('>I', c)
    else:
        out += b'\0\0\0\0'
    return bytes(out) + trailing


def marker_before_crc(markers_start_ok=True):
    """The ULPDU length for which the marker lands right before the CRC when
    the FPDU starts on a multiple of 512 (the case where pad_offset() is
    shifted by a marker)."""
    for n in range(1, 700):
        base = 2 + n
        base += (-base) % 4
        # markers at stream offsets 0, 512, ...: before the CRC when
        # (start + len(marked body without crc)) % 512 == 0
        pos = 0
        for i in range(base):
            if pos % 512 == 0:
                pos += 4
            pos += 1
        if pos % 512 == 0 and pos > 512:
            return n
    return None


class Conn:
    """A TCP connection of an MPA initiator and responder."""
    def __init__(self, frames, sport, dport, iseq, rseq):
        self.f = frames
        self.sport, self.dport = sport, dport
        self.seq = {True: iseq, False: rseq}
        self.start = {True: None, False: None}

    def send(self, from_init, payload, flags=0x18):
        peer = not from_init
        self.f.append(tcp_frame(from_init, self.sport, self.dport, self.seq[from_init],
                                self.seq[peer], payload, flags))
        self.seq[from_init] += len(payload)

    def p0(self, from_init):
        """Stream offset of the next FPDU of this sender."""
        if self.start[from_init] is None:
            self.start[from_init] = self.seq[from_init]
        return self.seq[from_init] - self.start[from_init]


def aligned_conn(frames, sport, dport, req, rep):
    """Connection whose first FPDUs start on a multiple of 512: the ISNs are
    chosen so that seq + length of the Request/Reply is such a multiple."""
    iseq = (4096 * 4) - len(req)
    rseq = (4096 * 8) - len(rep)
    c = Conn(frames, sport, dport, iseq, rseq)
    return c


def handshake(c, req, rep):
    c.send(True, req)
    c.send(False, rep)




def ddp_raw(tagged, last, opcode, rest, dv=1, ddp_rsvd=0, rdma_rv=1, rdma_rsv=0):
    c0 = (0x80 if tagged else 0) | (0x40 if last else 0) | (ddp_rsvd << 2) | dv
    c1 = (rdma_rv << 6) | (rdma_rsv << 4) | opcode
    return bytes([c0, c1]) + rest


def untagged(opcode, qn, msn, mo, data=b'', last=True, rsvd4=0, **kw):
    return ddp_raw(False, last, opcode, struct.pack('>I', rsvd4)
                   + struct.pack('>III', qn, msn, mo) + data, **kw)


def tagged(opcode, stag, to, data=b'', last=True, **kw):
    return ddp_raw(True, last, opcode, struct.pack('>IQ', stag, to) + data, **kw)


def terminate(layer, etype, errcode, hdrct, ddp_hdr=b'', rdma_hdr=b'', seg_len=0, rsvd=0, **kw):
    """Terminate: untagged DDP queue 2 and the terminate control field
    (layer/etype, error code, header control bits and reserved bits)."""
    body = bytes([(layer << 4) | etype, errcode]) + struct.pack('>H', (hdrct << 13) | rsvd)
    if hdrct & 2:
        body += struct.pack('>H', seg_len) + ddp_hdr
    if hdrct & 1:
        body += rdma_hdr
    return untagged(7, 2, 0, 0, body, **kw)


def atomic_request(op, req_id=1, stag=0x50, to=0x1000, a=0x1111, am=0xffff, b=0x2222, bm=0xff00, **kw):
    body = struct.pack('>IIIQ', op, req_id, stag, to)
    if op == 0:
        body += struct.pack('>QQ', a, am)
    elif op == 2:
        body += struct.pack('>QQ', a, am)
    body += struct.pack('>QQ', b, bm)
    return untagged(0x0a, 3, 0, 0, body, **kw)


def atomic_response(req_id=1, value=0x0102030405060708, **kw):
    return untagged(0x0b, 0, 0, 0, struct.pack('>IQ', req_id, value), **kw)


def main_frames():
    fr = []
    req = mpa_req_rep(REQ_KEY, 0x00, 1)
    rep = mpa_req_rep(REP_KEY, 0x00, 1)
    c = aligned_conn(fr, 47201, 47202, req, rep)
    handshake(c, req, rep)

    def send(seg, from_init=True):
        c.send(from_init, fpdu(seg))

    # --- the four Sends, one segment each
    send(untagged(3, 0, 1, 0, b'send one segment'))
    send(untagged(4, 0, 2, 0, b'send with invalidate', rsvd4=0x1234), False)
    send(untagged(5, 0, 3, 0, b'send with solicited event'))
    send(untagged(6, 0, 4, 0, b'send se and invalidate', rsvd4=0xdead))
    send(untagged(3, 0, 5, 0, b''))                       # empty Send
    send(untagged(3, 1, 6, 0, b'another queue'))
    # --- a fragmented Send (reassembled): 3 segments, then another message
    send(untagged(3, 0, 7, 0, b'frag one ', last=False))
    send(untagged(3, 0, 7, 9, b'frag two ', last=False))
    send(untagged(3, 0, 7, 18, b'frag three', last=True))
    send(untagged(3, 0, 8, 0, b'single again'))
    # fragments in the other direction in between
    send(untagged(4, 0, 9, 0, b'inval part one ', last=False, rsvd4=7), False)
    send(untagged(4, 0, 9, 15, b'inval part two', last=True, rsvd4=7), False)
    # two fragments in one TCP segment
    c.send(True, fpdu(untagged(5, 0, 10, 0, b'se part one ', last=False)) +
           fpdu(untagged(5, 0, 10, 12, b'se part two', last=True)))
    # a Send that spans two TCP segments
    big = fpdu(untagged(3, 0, 11, 0, bytes(range(250))))
    c.send(True, big[:90])
    c.send(True, big[90:])
    # --- RDMA Write and Read Response (tagged)
    send(tagged(0, 0xabcd, 0x10000, b'write payload'))
    send(tagged(0, 0xabcd, 0x10010, b'write part', last=False))
    send(tagged(0, 0xabcd, 0x1001a, b'last part', last=True))
    send(tagged(2, 0x77, 0x20, b'read response data'), False)
    # --- RDMA Read Request
    send(untagged(1, 1, 0, 0, struct.pack('>IQIIQ', 0x10, 0x20, 4096, 0x30, 0x40)))
    send(untagged(1, 1, 0, 0, struct.pack('>IQIIQ', 0x11, 0x21, 8192, 0x31, 0x41) + b'rr payload'))
    # --- Terminate: each layer and error type
    send(terminate(0, 0, 0, 0))                                  # RDMA layer, etype 0
    send(terminate(0, 1, 5, 0))                                  # RDMA, other etype (error code names)
    send(terminate(1, 1, 2, 3, ddp_hdr=bytes(14), rdma_hdr=bytes(28), seg_len=14 + 28 + 2))   # DDP tagged
    send(terminate(1, 2, 3, 3, ddp_hdr=bytes(18), rdma_hdr=bytes(28), seg_len=50))            # DDP untagged
    send(terminate(1, 0, 4, 2, ddp_hdr=bytes(18)))               # DDP, other etype (local catastrophic)
    send(terminate(1, 3, 4, 1, rdma_hdr=bytes(28)))              # DDP, etype 3
    send(terminate(2, 0, 1, 1, rdma_hdr=bytes(28)))              # LLP layer (MPA), etype 0
    send(terminate(2, 1, 2, 0))                                  # LLP, other etype
    send(terminate(3, 0, 1, 0))                                  # unknown layer
    send(terminate(0, 0, 0, 4))                                  # header control bit M
    send(terminate(0, 0, 0, 0, rsvd=0x1fff))
    # --- Atomic Request and Response
    send(atomic_request(0))
    send(atomic_request(2, req_id=2))
    send(atomic_request(1, req_id=3))                            # other atomic opcode: no add/swap data
    send(atomic_response(2), False)
    send(atomic_response(3, 0xffffffffffffffff), False)
    # --- reserved bits, versions and unknown opcodes
    send(untagged(3, 0, 12, 0, b'reserved bits', ddp_rsvd=0xf, rdma_rsv=3))
    send(untagged(3, 0, 13, 0, b'ddp version 2', dv=2))
    send(untagged(3, 0, 14, 0, b'rdma version 0', rdma_rv=0))
    send(untagged(3, 0, 15, 0, b'rdma version 3', rdma_rv=3))
    for op in (8, 9, 12, 13, 14, 15):
        send(untagged(op, 0, 16, 0, b'unknown opcode'))
        send(tagged(op, 0x99, 0x30, b'unknown tagged opcode'))
    # a tagged Send and an untagged Write: no payload shown
    send(tagged(3, 0x1, 0x2, b'tagged send'))
    send(untagged(0, 0, 17, 0, b'untagged write'))
    send(untagged(2, 0, 18, 0, b'untagged read response'))
    # a Send after the Terminate, both directions
    send(untagged(3, 0, 19, 0, b'after'), False)
    return fr


def malformed_frames():
    fr = []
    req = mpa_req_rep(REQ_KEY, 0x00, 1)
    rep = mpa_req_rep(REP_KEY, 0x00, 1)
    c = aligned_conn(fr, 48201, 48202, req, rep)
    handshake(c, req, rep)

    def send(seg):
        c.send(True, fpdu(seg))

    send(b'\x41')                                              # 1 octet: no RDMAP control
    send(b'\x41\x43')                                          # control only
    send(untagged(3, 0, 1, 0)[:10])                            # cut inside the untagged header
    send(tagged(0, 1, 2)[:8])                                  # cut inside the tagged header
    send(untagged(1, 1, 0, 0, b'\0' * 10))                     # Read Request cut short
    send(untagged(7, 2, 0, 0, b'\x00'))                        # Terminate cut short
    send(terminate(0, 0, 0, 3))                                # Terminate: DDP and RDMA headers missing
    send(terminate(1, 1, 2, 3, ddp_hdr=bytes(4)))
    send(atomic_request(0)[:30])                               # Atomic request cut short
    send(atomic_request(2)[:40])
    send(atomic_response()[:22])
    send(untagged(3, 0, 1, 0, b'x', last=False))               # fragment that never completes
    send(untagged(3, 0, 1, 0, b'x', last=False))
    return fr


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'iwarp-ddp-rdmap-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'iwarp-ddp-rdmap-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
