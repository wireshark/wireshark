#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a pcapng test capture for the core NVMe dissector (packet-nvme.c)
driven over NVMe/TCP (packet-nvme-tcp.c).

nvme-tcp-admin.pcapng  (5 frames)
  A single NVMe/TCP connection (host 10.0.0.1:55000 <-> controller
  10.0.0.2:4420) carrying five Admin-queue CapsuleCommand PDUs.  Each command
  exercises one arm of the admin-queue opcode switch in dissect_nvme_cmd()
  (epan/dissectors/packet-nvme.c) -- the switch that MR4 relocates into the
  shared nvme_dissect_admin_sqe_cdws() helper:

    Frame 1  Identify (06h), CNS=01h Identify Controller   -> CNS/CNTID decode
                                                              + CNS COL_INFO append
    Frame 2  Get Log Page (02h), LID=02h SMART             -> LID decode
                                                              + log-page COL_INFO append
    Frame 3  Set Features (09h), FID=02h Power Management  -> FID decode
    Frame 4  Get Features (0Ah), FID=04h Temperature Thr.  -> FID decode
    Frame 5  Format NVM (80h)                              -> default/unhandled
                                                              CDW10-15 raw decode

  No CQE responses are emitted: MR4 only moves the request-side switch, so the
  request decode is the entire regression surface.  The companion test
  (test/suite_dissection_nvme.py) snapshots the decode of these five frames so
  that the switch relocation can be proven output-preserving.

  The commands land on the admin queue (qid 0) without a Fabrics Connect: none
  of the opcodes is an I/O opcode, so nvme-tcp's qid heuristic
  (nvme_is_io_queue_opcode) defaults the queue to admin.

Wire format layers (outer to inner):
  Ethernet II            (14 bytes, DLT_EN10MB = 1)
  IPv4                   (20 bytes)
  TCP                    (20 bytes, dport 4420)
  NVMe/TCP CapsuleCmd    (8-byte common header + 64-byte SQE)
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# pcapng helpers (shared shape with tools/gen-nvme-mi-test-capture.py)
# ---------------------------------------------------------------------------

def _pad4(n):
    return (n + 3) & ~3

def _block(block_type, body):
    padded = body + b'\x00' * (_pad4(len(body)) - len(body))
    total = 12 + len(padded)
    hdr = struct.pack('<II', block_type, total)
    return hdr + padded + struct.pack('<I', total)

def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    return _block(0x0A0D0D0A, body)

def idb(link_type=1, snaplen=65535):
    """Interface Description Block (DLT_EN10MB = 1)."""
    body = struct.pack('<HHI', link_type, 0, snaplen)
    return _block(0x00000001, body)

def epb(packet_bytes, ts_us):
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  =  ts_us & 0xFFFFFFFF
    caplen = len(packet_bytes)
    padded = packet_bytes + b'\x00' * (_pad4(caplen) - caplen)
    body = struct.pack('<IIIII', 0, ts_high, ts_low, caplen, caplen) + padded
    return _block(0x00000006, body)

# ---------------------------------------------------------------------------
# Ethernet / IPv4 / TCP framing
# ---------------------------------------------------------------------------

HOST_MAC = bytes.fromhex('020000000001')
CTRL_MAC = bytes.fromhex('020000000002')
HOST_IP  = bytes(map(int, '10.0.0.1'.split('.')))
CTRL_IP  = bytes(map(int, '10.0.0.2'.split('.')))
HOST_PORT = 55000
CTRL_PORT = 4420   # IANA NVMe/TCP

def _ones_complement_sum(data):
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def ipv4(src, dst, payload, ident):
    total_len = 20 + len(payload)
    hdr = struct.pack('>BBHHHBBH4s4s',
                      0x45, 0x00, total_len, ident, 0x4000, 64, 6, 0, src, dst)
    checksum = _ones_complement_sum(hdr)
    hdr = hdr[:10] + struct.pack('>H', checksum) + hdr[12:]
    return hdr + payload

def tcp(sport, dport, seq, ack, payload):
    # PSH|ACK; checksum left 0 (tshark does not validate TCP checksums by default)
    offset_flags = (5 << 12) | 0x018
    hdr = struct.pack('>HHIIHHHH',
                      sport, dport, seq, ack, offset_flags, 65535, 0, 0)
    return hdr + payload

def eth(dst_mac, src_mac, payload):
    return dst_mac + src_mac + struct.pack('>H', 0x0800) + payload

# ---------------------------------------------------------------------------
# NVMe/TCP CapsuleCommand PDU
# ---------------------------------------------------------------------------
# Common header (8 bytes): type(1) flags(1) hlen(1) pdo(1) plen(4, LE)
# For a command PDU HLEN covers the common header + the 64-byte SQE.

NVME_TCP_CMD = 0x04

def capsule_cmd_pdu(sqe):
    assert len(sqe) == 64
    hlen = 8 + 64
    plen = hlen          # no in-capsule data, no digests
    ch = struct.pack('<BBBBI', NVME_TCP_CMD, 0x00, hlen, 0x00, plen)
    return ch + sqe

# ---------------------------------------------------------------------------
# 64-byte NVMe Submission Queue Entry
# ---------------------------------------------------------------------------

def sqe(opcode, cid, nsid=0, cdw10=0, cdw11=0, cdw12=0, cdw13=0,
        cdw14=0, cdw15=0):
    b = bytearray(64)
    b[0] = opcode & 0xFF
    b[1] = 0x00                                   # PSDT/FUSE
    struct.pack_into('<H', b, 2, cid & 0xFFFF)    # CID
    struct.pack_into('<I', b, 4, nsid & 0xFFFFFFFF)
    struct.pack_into('<I', b, 40, cdw10 & 0xFFFFFFFF)
    struct.pack_into('<I', b, 44, cdw11 & 0xFFFFFFFF)
    struct.pack_into('<I', b, 48, cdw12 & 0xFFFFFFFF)
    struct.pack_into('<I', b, 52, cdw13 & 0xFFFFFFFF)
    struct.pack_into('<I', b, 56, cdw14 & 0xFFFFFFFF)
    struct.pack_into('<I', b, 60, cdw15 & 0xFFFFFFFF)
    return bytes(b)

# Admin opcodes
AQ_GET_LOG_PAGE = 0x02
AQ_IDENTIFY     = 0x06
AQ_SET_FEATURES = 0x09
AQ_GET_FEATURES = 0x0A
AQ_FORMAT_NVM   = 0x80

# Identify CNS=01h (Controller); Get Log LID=02h (SMART);
# Set FID=02h (Power Mgmt); Get FID=04h (Temperature Threshold).
COMMANDS = [
    sqe(AQ_IDENTIFY,     cid=1, cdw10=0x00000001),
    sqe(AQ_GET_LOG_PAGE, cid=2, cdw10=0x00000002),
    sqe(AQ_SET_FEATURES, cid=3, cdw10=0x00000002, cdw11=0x00000001),
    sqe(AQ_GET_FEATURES, cid=4, cdw10=0x00000004),
    sqe(AQ_FORMAT_NVM,   cid=5, cdw10=0x000000AB),
]


def build():
    out = bytearray()
    out += shb()
    out += idb()

    seq = 1
    ack = 1
    ident = 0x1000
    ts = 1_700_000_000_000_000   # fixed base timestamp (us)
    for i, s in enumerate(COMMANDS):
        pdu = capsule_cmd_pdu(s)
        frame = eth(CTRL_MAC, HOST_MAC,
                    ipv4(HOST_IP, CTRL_IP, tcp(HOST_PORT, CTRL_PORT, seq, ack, pdu),
                         ident + i))
        out += epb(frame, ts + i * 1000)
        seq = (seq + len(pdu)) & 0xFFFFFFFF
    return bytes(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, '..', 'test', 'captures', 'nvme-tcp-admin.pcapng')
    out_path = os.path.normpath(out_path)
    data = build()
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f'wrote {out_path} ({len(COMMANDS)} frames, {len(data)} bytes)')


if __name__ == '__main__':
    sys.exit(main())
