#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate pcapng test capture for the MCTP over SMBus/I2C dissector.

One capture is produced:

mctp-smbus.pcapng  (10 frames)

  --- Heuristic detection & transport-field coverage ---

  Frame 1: Valid MCTP-SMBus frame, no PEC
    dest_slave=0x40 (7-bit 0x20), cmd=0x0F, byte_count=8,
    src_slave=0x81 (7-bit 0x40, MCTP indicator=1), MCTP hdr ver=1,
    dst_EID=0x20, src_EID=0x40, inner payload = MCTP Control Get EID request.
    Total = 11 bytes; byte_count+3=11 so no PEC is present.

  Frame 2: Valid MCTP-SMBus frame, with PEC=0xAB
    Identical to Frame 1 + one PEC byte; total length == byte_count+4.

  Frame 3: Invalid — command code 0x0E (not the required 0x0F)
    Rejected by mctp_smbus_heuristic_check().

  Frame 4: Invalid — source address LSB=0 (IPMB marker, not MCTP)
    Rejected by mctp_smbus_heuristic_check().

  Frame 5: Invalid — MCTP header version lower nibble != 1
    Rejected by mctp_smbus_heuristic_check().

  --- NVMe-MI Health Status Poll over fragmented MCTP ---

  Frame 6: MCTP fragment 1 of 2 (SOM only, not EOM), tag=1, seq=0
    Carries only the 4-byte NVMe-MI header (MCTP type=4, ROR=0, type=MI,
    CSI=0).  The MCTP reassembler cannot yet deliver a payload; nvme-mi
    dissector is not invoked for this frame.
    byte_count=9, len=12, no PEC.

  Frame 7: MCTP fragment 2 of 2 (EOM only, not SOM), tag=1, seq=1, with PEC
    Carries the 12-byte NVMe-MI MI command payload (opcode=0x01 NVM
    Subsystem Health Status Poll, CDW0=0, CDW1=0).  MCTP reassembly
    completes here; the full 16-byte NVMe-MI message is decoded.
    byte_count=17, len=21 (byte_count+4), PEC=0xCD.

  Frame 8: NVMe-MI Health Status Poll response (SOM+EOM, single packet)
    Drive (src_EID=0x20, slave=0x41) replies to BMC (dst_EID=0x40,
    slave=0x80).  ROR=1, type=MI, status=0x00 (success).
    byte_count=13, len=16, no PEC.

  --- Malformed frame ---

  Frame 9: Extra bytes beyond byte count indicated length with PEC (malformed)
    byte_count=8, len=14 (byte_count+4=12, so 2 extra bytes then PEC).
    Triggers ei_mctp_smbus_length_mismatch warning; MCTP inner frame is
    still decoded.  Exercises the fixed off-by-one in the extra-bytes
    count reported in the expert info message.

  Frame 10: Snaplen-truncated — reported length >= MCTP_SMBUS_MIN_LENGTH
    but captured length < MCTP_SMBUS_MIN_LENGTH.
    Full I2C data = same as Frame 1 (origlen=11 >= 9), captured data = 2 bytes.
    The heuristic must return false without throwing a BoundsError.
    Regression guard for the tvb_captured_length fix in mctp_smbus_frame_is_valid.
    Not decoded as mctp.smbus; shown as raw I2C data.

Wire format (DSP0237 §6.3) as seen by the i2c.message subdissector:
  tvb[0]           Destination Slave Address  [7:1]=addr, [0]=R/W#=0
  tvb[1]           Command Code               0x0F
  tvb[2]           Byte Count                 src_addr + MCTP hdr + payload
  tvb[3]           Source Slave Address       [7:1]=addr, [0]=MCTP flag=1
  tvb[4]           MCTP Header Version        [3:0]=0x01
  tvb[5]           Destination EID
  tvb[6]           Source EID
  tvb[7]           MCTP Message Flags         SOM/EOM/Seq/TO/Tag
  tvb[8]           IC | MCTP Message Type
  tvb[9+]          MCTP message payload
  tvb[byte_count+3]  PEC (when total len == byte_count + 4)

MCTP flags byte encoding (tvb[7]):
  bit 7 = SOM, bit 6 = EOM, bits[5:4] = seq, bit 3 = TO, bits[2:0] = tag

NVMe-MI header (4 bytes, little-endian uint32):
  byte 0: bits[6:0]=MCTP type (4), bit[7]=IC
  byte 1: bit[7]=ROR, bits[6:3]=type (0=ctrl,1=MI,2=admin), bit[0]=CSI
  bytes 2-3: reserved/MEB

Encapsulation: DLT_LINUX_I2C (209), with a 5-byte pcap pseudo-header
prepended to each packet (from wiretap/pcap-common.c struct i2c_linux_file_hdr):
  byte  0:  bus (bits 6:0) | is_event (bit 7)
  bytes 1-4: flags, big-endian 32-bit
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# pcapng block helpers
# ---------------------------------------------------------------------------

def _pad4(n):
    return (n + 3) & ~3


def _block(block_type, body):
    padded = body + b'\x00' * (_pad4(len(body)) - len(body))
    total  = 12 + len(padded)
    hdr    = struct.pack('<II', block_type, total)
    return hdr + padded + struct.pack('<I', total)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    return _block(0x0A0D0D0A, body)


def idb(link_type, snaplen=65535):
    body = struct.pack('<HHI', link_type, 0, snaplen)
    return _block(0x00000001, body)


def epb(packet_bytes, ts_us):
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  =  ts_us        & 0xFFFFFFFF
    caplen  = len(packet_bytes)
    padded  = packet_bytes + b'\x00' * (_pad4(caplen) - caplen)
    body    = struct.pack('<IIIII', 0, ts_high, ts_low, caplen, caplen) + padded
    return _block(0x00000006, body)


def epb_trunc(packet_bytes, caplen, ts_us):
    """EPB where captured_packet_length < original_packet_length (snaplen truncation)."""
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  =  ts_us        & 0xFFFFFFFF
    origlen = len(packet_bytes)
    cap_bytes = packet_bytes[:caplen]
    padded  = cap_bytes + b'\x00' * (_pad4(caplen) - caplen)
    body    = struct.pack('<IIIII', 0, ts_high, ts_low, caplen, origlen) + padded
    return _block(0x00000006, body)


# ---------------------------------------------------------------------------
# I2C Linux pseudo-header  (DLT 209 / WTAP_ENCAP_I2C_LINUX)
# ---------------------------------------------------------------------------

DLT_LINUX_I2C = 209
I2C_PHDR_LEN  = 5  # bus byte + 4-byte flags


def i2c_phdr(bus=0, is_event=False, flags=0):
    bus_byte = (bus & 0x7F) | (0x80 if is_event else 0x00)
    return bytes([bus_byte]) + struct.pack('>I', flags)


def i2c_packet(i2c_data, bus=0, flags=0, ts_us=0):
    return epb(i2c_phdr(bus=bus, flags=flags) + bytes(i2c_data), ts_us)


def i2c_packet_trunc(i2c_data, caplen_data, bus=0, flags=0, ts_us=0):
    """I2C packet EPB with only caplen_data bytes of I2C data in the capture file."""
    full = i2c_phdr(bus=bus, flags=flags) + bytes(i2c_data)
    return epb_trunc(full, I2C_PHDR_LEN + caplen_data, ts_us)


# ---------------------------------------------------------------------------
# Frame payloads
# ---------------------------------------------------------------------------

# Frames 1-5: MCTP Control Get Endpoint ID request
#   tvb[0] = 0x40  dest slave addr  7-bit addr=0x20, R/W#=0
#   tvb[1] = 0x0F  command code     MCTP-assigned Block Write code
#   tvb[2] = 0x08  byte_count       1(src) + 4(MCTP hdr) + 3(ctrl payload)
#   tvb[3] = 0x81  src slave addr   7-bit addr=0x40, MCTP indicator=1
#   tvb[4] = 0x01  MCTP hdr ver     lower nibble = 1
#   tvb[5] = 0x20  destination EID
#   tvb[6] = 0x40  source EID
#   tvb[7] = 0xC8  MCTP flags: SOM=1, EOM=1, seq=0, TO=1, tag=0
#   tvb[8] = 0x00  IC=0, type=0x00  MCTP Control message type
#   tvb[9] = 0x80  MCTP ctrl hdr    RQ=1, D=0, Instance=0
#   tvb[10]= 0x02  ctrl command     Get Endpoint ID
# byte_count=8, len=11, byte_count+3=11 → no PEC
_VALID = [
    0x40,   # dest slave addr: 7-bit addr 0x20, R/W#=0
    0x0F,   # command code
    0x08,   # byte_count = 8
    0x81,   # src slave addr: 7-bit addr 0x40, MCTP indicator=1
    0x01,   # MCTP header version (lower nibble must be 1)
    0x20,   # destination EID
    0x40,   # source EID
    0xC8,   # MCTP flags: SOM=1, EOM=1, seq=0, TO=1, tag=0
    0x00,   # IC=0, message type=0x00 (MCTP Control)
    0x80,   # MCTP Control header: RQ=1, D=0, Instance=0
    0x02,   # MCTP Control command: Get Endpoint ID
]

_PEC = 0xAB


def _mutate(idx, val):
    data = _VALID[:]
    data[idx] = val
    return data


# ---------------------------------------------------------------------------
# Frames 6-7: NVMe-MI Health Status Poll request, split across two MCTP
# fragments.  BMC (slave 0x40/EID 0x40) → drive (slave 0x20/EID 0x20).
#
# The 16-byte NVMe-MI message is:
#   [0x04, 0x08, 0x00, 0x00]        ← NVMe-MI header  (frag 1)
#   [0x01, 0x00, 0x00, 0x00,        ← opcode + 3 reserved
#    0x00, 0x00, 0x00, 0x00,        ← CDW0
#    0x00, 0x00, 0x00, 0x00]        ← CDW1            (frag 2)
#
# MCTP tag=1, TO=1 (request-side tag owner).
# Frame 6 MCTP flags: SOM=1 EOM=0 seq=0 TO=1 tag=1 → 0x89
# Frame 7 MCTP flags: SOM=0 EOM=1 seq=1 TO=1 tag=1 → 0x59
# ---------------------------------------------------------------------------

# Frame 6 — fragment 1 (SOM only)
# byte_count = 1(src) + 4(MCTP hdr) + 4(NVMe-MI hdr bytes) = 9
# len = 9 + 3 = 12, byte_count+3=12 → no PEC
_NVME_MI_REQ_SOM = [
    0x40,        # dst slave addr: 7-bit 0x20, R/W#=0
    0x0F,        # command code
    0x09,        # byte_count = 9
    0x81,        # src slave addr: 7-bit 0x40, MCTP indicator=1
    0x01,        # MCTP header version
    0x20,        # destination EID (drive)
    0x40,        # source EID (BMC)
    0x89,        # MCTP flags: SOM=1, EOM=0, seq=0, TO=1, tag=1
    0x04,        # NVMe-MI byte 0: MCTP type=4 (NVMe-MI), IC=0
    0x08,        # NVMe-MI byte 1: ROR=0 (request), type=MI (1<<3), CSI=0
    0x00,        # NVMe-MI byte 2: reserved
    0x00,        # NVMe-MI byte 3: reserved
]

# Frame 7 — fragment 2 (EOM only), with PEC=0xCD
# byte_count = 1(src) + 4(MCTP hdr) + 12(MI cmd payload) = 17
# len = 17 + 4 = 21, byte_count+4=21 → PEC present
_NVME_MI_REQ_EOM = [
    0x40,        # dst slave addr: 7-bit 0x20, R/W#=0
    0x0F,        # command code
    0x11,        # byte_count = 17 = 0x11
    0x81,        # src slave addr: 7-bit 0x40, MCTP indicator=1
    0x01,        # MCTP header version
    0x20,        # destination EID (drive)
    0x40,        # source EID (BMC)
    0x59,        # MCTP flags: SOM=0, EOM=1, seq=1, TO=1, tag=1
    0x01,        # NVM Subsystem Health Status Poll opcode
    0x00, 0x00, 0x00,              # reserved
    0x00, 0x00, 0x00, 0x00,        # CDW0
    0x00, 0x00, 0x00, 0x00,        # CDW1
    0xCD,        # PEC
]

# ---------------------------------------------------------------------------
# Frame 8: NVMe-MI Health Status Poll response (SOM+EOM, single packet)
# Drive (slave 0x41/EID 0x20) → BMC (slave 0x80/EID 0x40).
# MCTP flags: SOM=1 EOM=1 seq=0 TO=0 (receiver's side) tag=1 → 0xC1
# byte_count = 1(src) + 4(MCTP hdr) + 8(NVMe-MI hdr + MI resp payload) = 13
# len = 13 + 3 = 16, byte_count+3=16 → no PEC
# ---------------------------------------------------------------------------
_NVME_MI_RESP = [
    0x80,        # dst slave addr: 7-bit 0x40 (BMC), R/W#=0
    0x0F,        # command code
    0x0D,        # byte_count = 13 = 0x0D
    0x41,        # src slave addr: 7-bit 0x20 (drive), MCTP indicator=1
    0x01,        # MCTP header version
    0x40,        # destination EID (BMC)
    0x20,        # source EID (drive)
    0xC1,        # MCTP flags: SOM=1, EOM=1, seq=0, TO=0 (receiver), tag=1
    0x04,        # NVMe-MI byte 0: MCTP type=4 (NVMe-MI), IC=0
    0x88,        # NVMe-MI byte 1: ROR=1 (response), type=MI (1<<3), CSI=0
    0x00,        # NVMe-MI byte 2: reserved
    0x00,        # NVMe-MI byte 3: reserved
    0x00,        # MI response status = 0x00 (success)
    0x00, 0x00, 0x00,              # NMResp (management response, all zero)
]

# ---------------------------------------------------------------------------
#   Frame 9: Extra bytes beyond byte count indicated length with PEC (malformed)
#   byte_count=8, len=14 (byte_count+4=12, so 2 extra bytes then PEC).
#   Triggers ei_mctp_smbus_length_mismatch warning; MCTP inner frame is
#   still decoded.  Exercises the fixed off-by-one in the extra-bytes
#   count reported in the expert info message.
# ---------------------------------------------------------------------------
_EXTRA_TRAILING = _VALID + [0xDE, 0xAD, _PEC]


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root  = os.path.dirname(script_dir)
    out_path   = os.path.join(repo_root, 'test', 'captures', 'mctp-smbus.pcapng')

    if len(sys.argv) > 1:
        out_path = sys.argv[1]

    frames = [
        _VALID,                # F1: valid, no PEC
        _VALID + [_PEC],       # F2: valid, with PEC
        _mutate(1, 0x0E),      # F3: wrong command code (0x0E) → heuristic reject
        _mutate(3, 0x80),      # F4: MCTP flag not set (LSB=0) → heuristic reject
        _mutate(4, 0x02),      # F5: wrong MCTP header version → heuristic reject
        _NVME_MI_REQ_SOM,      # F6: NVMe-MI request, MCTP fragment 1 (SOM)
        _NVME_MI_REQ_EOM,      # F7: NVMe-MI request, MCTP fragment 2 (EOM) + PEC
        _NVME_MI_RESP,         # F8: NVMe-MI Health Status Poll response
        _EXTRA_TRAILING,       # F9: malformed — extra bytes before PEC
    ]

    data = shb() + idb(DLT_LINUX_I2C)
    for i, payload in enumerate(frames):
        data += i2c_packet(payload, ts_us=(i + 1) * 1_000_000)

    # Frame 10: snaplen-truncated — origlen=11 >= MCTP_SMBUS_MIN_LENGTH=9 but
    # caplen=2 < 9.  Regression guard for the tvb_captured_length fix in
    # mctp_smbus_frame_is_valid(): the heuristic must return false without
    # throwing a BoundsError.  Uses the same I2C bytes as Frame 1 so the
    # reported-length check alone would have proceeded to byte reads.
    data += i2c_packet_trunc(_VALID, caplen_data=2, ts_us=10 * 1_000_000)

    with open(out_path, 'wb') as f:
        f.write(data)

    print(f'Wrote {len(frames) + 1} frames to {out_path}')


if __name__ == '__main__':
    main()
