#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate pcapng test capture for the MCTP over SMBus/I2C dissector.

Four captures are produced: mctp-smbus.pcapng, mapped below;
mctp-smbus-ingress.pcapng and i2c-transport-edge.pcapng, mapped in their
sections near the end of this file; and mctp-smbus-reassembly.pcapng, mapped
in build_smbus_reassembly_pcapng().

mctp-smbus.pcapng  (37 frames, five pcapng sections)
  F1-F19   the transport frames mapped below
  F20-F27  the SMBus Info prefix and a throwing body: F1-F8 of the
           mctp-smbus-body-exception section near the end of this file
  F28-F33  the DSP0237 binding-specific MCTP control fields, which are only
           decodable on an SMBus/I2C ingress; see the block comment above
           their frame bodies
  F34-F36  header-only packets and header version 2, in their section near
           the end of this file
  F37      a 7-byte record, below DSP0237 6.3's 8-byte minimum

mctp-smbus-ingress.pcapng F20-F27 (three pcapng sections, built in main())
  Verifies that MCTP message assemblies cannot cross physical I2C buses,
  PCAPNG sections that reuse the same interface ID, or capture interfaces
  that report the same bus number.

mctp-smbus-reassembly.pcapng (22 frames)
  F1-F10 bad-PEC retry sequences; F11-F15 inter-packet timeout behavior;
  F16-F17 reassembly without a captured PEC; F18-F19 the 100 ms boundary;
  F20-F22 254-byte packets whose bus time hides part of the gap.  The
  timeout check estimates bus time at 250 us per byte (DSP0237 Table 8
  PT1a/PT1b): 18.25 ms for a 68-byte MCTP packet, 64.75 ms for 254 bytes.

  --- Heuristic detection & transport-field coverage ---

  Frame 1: Valid MCTP-SMBus frame, no PEC
    dest_slave=0x40 (7-bit 0x20), cmd=0x0F, byte_count=8,
    src_slave=0x81 (7-bit 0x40, MCTP indicator=1), MCTP hdr ver=1,
    dst_EID=0x20, src_EID=0x40, inner payload = MCTP Control Get EID request.
    Total = 11 bytes; byte_count+3=11 so no PEC is present.

  Frame 2: Valid MCTP-SMBus frame, with a correct PEC
    Identical to Frame 1 + one PEC byte; total length == byte_count+4.
    The PEC is the real CRC-8 over bytes 0..byte_count+2, so the dissector
    must report it as Good.

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
    byte_count=17, len=21 (byte_count+4), correct PEC.

  Frame 8: NVMe-MI Health Status Poll response (SOM+EOM, single packet)
    Drive (src_EID=0x20, slave=0x41) replies to BMC (dst_EID=0x40,
    slave=0x80).  ROR=1, type=MI, status=0x00 (success).
    byte_count=13, len=16, no PEC.

  --- Malformed frame ---

  Frame 9: Extra bytes beyond the byte-count-indicated length (malformed)
    byte_count=8, len=14: the correct PEC at byte_count+3=11, then two pad
    bytes (0xDE 0xAD).  DSP0237 §6.3 Figure 1 fixes the PEC immediately
    after the last data byte, so trailing bytes must not shift it to len-1.
    Triggers ei_mctp_smbus_length_mismatch warning; MCTP header fields remain
    visible, but the invalidly framed packet is not passed into assembly.
    Exercises the fixed off-by-one in the extra-bytes count reported in the
    expert info message.

  Frame 10: Snaplen-truncated — reported length >= MCTP_SMBUS_MIN_LENGTH
    but captured length < MCTP_SMBUS_MIN_LENGTH.
    Full I2C data = same as Frame 1 (origlen=11 >= 9), captured data = 2 bytes.
    The heuristic must return false without throwing a BoundsError.
    Regression guard for the tvb_captured_length fix in mctp_smbus_frame_is_valid.
    Not decoded as mctp.smbus; shown as raw I2C data.

  --- Two concurrent MCTP messages sharing a tag but differing in TO ---

  Frames 11-14: drive (EID 0x20) -> BMC (EID 0x40), both messages tag=2.

    Frame 11  message R fragment 1  SOM, seq 0, TO=0, tag 2
    Frame 12  message A fragment 1  SOM, seq 0, TO=1, tag 2
    Frame 13  message R fragment 2  EOM, seq 1, TO=0, tag 2
    Frame 14  message A fragment 2  EOM, seq 1, TO=1, tag 2

    DSP0236 1.3.3 Table 1 defines a message at the MCTP transport level by
    (Source EID, Tag Owner, Msg tag), and states that the Message Tag field
    "is generated and tracked independently for each value of the Tag Owner
    bit" - so R and A are two distinct messages even though both carry tag 2
    over the same EID pair.  This is the ordinary request/response case: a
    responder returns the requester's tag with TO cleared, while anything the
    device originates itself owns its own tag.

    R reassembles to 8 bytes, A to 12 bytes, with disjoint payload bytes, so a
    reassembly key that omits TO merges them and the two lengths swap.

  --- MCTP control command beyond 0x05 ---

  Frame 15: MCTP Control Get Routing Table Entries request (command 0x0A)
    Frame 1's framing with the control command byte changed and the Table 26
    Entry Handle appended.  DSP0236 Table 12 defines control commands through
    0x14; anything above 0x05 used to fall back to the generic "Control"
    string in the Info column.

  --- Corrupted PEC ---

  Frame 16: Frame 2 with the PEC byte inverted
    DSP0237 §6.3 Figure 1: "All MCTP transactions shall include a PEC byte.
    The PEC byte shall be transmitted by the source and checked by the
    destination."  A corrupt bus transaction must be distinguishable from a
    good one, so the PEC status field must read Bad here and Good on
    Frame 2.

  Frames 17/18: Byte Count below five / exceeding the reported payload.
    Five is the source address plus the transport header: DSP0236 Table 1
    puts the message type byte in a message's first packet only.
    Heuristic rejection is intentionally silent; forced Decode As diagnoses
    the count and reported-length failure respectively.

  Frame 19: A structurally valid Block Write marked Read by the I2C capture
  metadata. The raw SMBus address/R/W# octet makes it a Write, so the
  heuristic claims and dispatches it as MCTP.

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

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapng_testgen import DLT_LINUX_I2C, crc32c, epb, i2c_phdr, idb, shb, smbus_pec

# ---------------------------------------------------------------------------
# I2C Linux pseudo-header  (DLT 209 / WTAP_ENCAP_I2C_LINUX)
# ---------------------------------------------------------------------------

I2C_PHDR_LEN  = 5  # bus byte + 4-byte flags


def i2c_packet(i2c_data, bus=0, flags=0, ts_us=0, interface_id=0):
    return epb(i2c_phdr(bus=bus, flags=flags) + bytes(i2c_data), ts_us,
               interface_id)


def i2c_packet_trunc(i2c_data, caplen_data, bus=0, flags=0, ts_us=0):
    """I2C packet EPB with only caplen_data bytes of I2C data in the capture file."""
    full = i2c_phdr(bus=bus, flags=flags) + bytes(i2c_data)
    return epb(full, ts_us, caplen=I2C_PHDR_LEN + caplen_data)


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

# DSP0237 §6.3 Figure 1: the PEC covers the whole transaction, from the
# destination slave address byte through the last data byte at byte_count+2.
_PEC = smbus_pec(_VALID)


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

# Frame 7 — fragment 2 (EOM only), with a correct PEC
# byte_count = 1(src) + 4(MCTP hdr) + 12(MI cmd payload) = 17
# len = 17 + 4 = 21, byte_count+4=21 → PEC present
_NVME_MI_REQ_EOM_BODY = [
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
]
_NVME_MI_REQ_EOM = _NVME_MI_REQ_EOM_BODY + [smbus_pec(_NVME_MI_REQ_EOM_BODY)]

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
#   Frame 9: Extra bytes beyond the byte-count-indicated length (malformed)
#   byte_count=8, len=14: the correct PEC sits at byte_count+3=11 (DSP0237
#   §6.3 Figure 1 fixes it immediately after the last data byte) and two pad
#   bytes follow it.  Placing the PEC at len-1 instead reads 0xAD, which is
#   both the wrong byte and a failing CRC.
#   Triggers ei_mctp_smbus_length_mismatch warning; MCTP header fields remain
#   visible, but the invalidly framed packet is not passed into assembly.
#   Exercises the fixed off-by-one in the extra-bytes count reported in the
#   expert info message.
# ---------------------------------------------------------------------------
_EXTRA_TRAILING = _VALID + [_PEC, 0xDE, 0xAD]

# ---------------------------------------------------------------------------
#   Frame 16: Frame 2 with a corrupted PEC — the CRC-8 must be checked, not
#   merely displayed (DSP0237 §6.3 Figure 1: "checked by the destination").
# ---------------------------------------------------------------------------
_BAD_PEC = _VALID + [_PEC ^ 0xFF]

# ---------------------------------------------------------------------------
# Frames 11-14: two concurrent drive->BMC messages that share message tag 2 but
# differ in the Tag Owner bit, fragmented and interleaved on the wire.
#
#   message R (TO=0)  a response, whose tag was owned by the BMC
#     8 bytes:  04 88 00 00 | 00 a1 a2 a3
#   message A (TO=1)  device-originated, so the drive owns the tag
#     12 bytes: 04 88 00 00 | 00 b1 b2 b3 b4 b5 b6 b7
#
# Transmit order R1, A1, R2, A2.  A reassembly key of (src EID, dst EID, msg
# tag) alone puts all four fragments in one set: R2's EOM then completes
# R1+A1+R2 (12 bytes) and A2 completes alone (8 bytes), i.e. the two messages
# swap lengths and R is handed a copy of A's header in the middle of its body.
#
# byte_count = 1(src) + 4(MCTP hdr) + payload; total len = byte_count + 3 (no PEC).
# ---------------------------------------------------------------------------

def _drive_to_bmc(flags, payload):
    """MCTP-SMBus frame from the drive (slave 0x20, EID 0x20) to the BMC."""
    return [
        0x80,                     # dst slave addr: 7-bit 0x40 (BMC), R/W#=0
        0x0F,                     # command code
        1 + 4 + len(payload),     # byte_count
        0x41,                     # src slave addr: 7-bit 0x20 (drive), MCTP flag=1
        0x01,                     # MCTP header version
        0x40,                     # destination EID (BMC)
        0x20,                     # source EID (drive)
        flags,                    # MCTP flags byte
    ] + list(payload)


def _scope_fragment(flags, payload):
    """MCTP-SMBus fragment with one stable terminus for scope-isolation tests."""
    return _drive_to_bmc(flags, [0x0A] + list(payload) if flags & 0x80 else payload)


# NVMe-MI header: MCTP type 4, IC=0 / ROR=1 (response), type=MI (1<<3), CSI=0
_MI_HDR = [0x04, 0x88, 0x00, 0x00]

# Frame 11 - R fragment 1: SOM=1 EOM=0 seq=0 TO=0 tag=2 -> 0x82
_TAG_R_SOM = _drive_to_bmc(0x82, _MI_HDR)
# Frame 12 - A fragment 1: SOM=1 EOM=0 seq=0 TO=1 tag=2 -> 0x8A
_TAG_A_SOM = _drive_to_bmc(0x8A, _MI_HDR)
# Frame 13 - R fragment 2: SOM=0 EOM=1 seq=1 TO=0 tag=2 -> 0x52
_TAG_R_EOM = _drive_to_bmc(0x52, [0x00, 0xA1, 0xA2, 0xA3])
# Frame 14 - A fragment 2: SOM=0 EOM=1 seq=1 TO=1 tag=2 -> 0x5A
_TAG_A_EOM = _drive_to_bmc(0x5A, [0x00, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7])

# ---------------------------------------------------------------------------
# Frame 15: MCTP Control Get Routing Table Entries request (command 0x0A).
# DSP0236 Table 12 defines command codes through 0x14; Table 26 makes the
# Entry Handle a request field, so it is present and byte_count grows by one.
# ---------------------------------------------------------------------------
_CTRL_GET_ROUTING_TABLE = _mutate(10, 0x0A) + [0x00]  # Entry Handle 0x00
_CTRL_GET_ROUTING_TABLE[2] = 0x09                     # byte_count


# ---------------------------------------------------------------------------
# mctp-smbus.pcapng F28-F33: the DSP0237 binding-specific MCTP control fields.
#
# DSP0236 1.3.3 leaves three fields to the transport binding: Table 15 byte 4
# ("shall be returned as 0x00 unless otherwise specified by the transport
# binding"), Table 22 bytes 3:N and Table 25 byte 4:N (each "defined as part of
# the corresponding physical transport binding specification").  DSP0237 1.2.0
# 6.9 Table 4 defines the first ([7:1] reserved, [0] fairness arbitration
# support) and 6.8 Table 3 the other two (one byte: [7:1] slave address bits,
# [0] 0b), which is also what makes Table 25's record list walkable at all.
#
# Those decodes are therefore conditional on an SMBus/I2C ingress, and no
# checked-in capture reaches them: every SMBus-ingress control frame in
# mctp-smbus.pcapng is a payload-free Get Endpoint ID request or a 0Ah request.
# The SLL-framed mctp-control*.pcapng captures are the negative control.
#
#   F1  Get Endpoint ID response, medium-specific 0x01: fairness arbitration
#       supported, Table 4's reserved run zero.  Correct PEC.
#   F2  Same with 0x03, so Table 4's [7:1] run is non-zero and DSP0236 5.3's
#       zero-on-write rule is violated.  No PEC, so the new decode is shown not
#       to depend on one.
#   F3  Resolve Endpoint ID response with a Table 3 address: 0x62, i.e. slave
#       address 0x31 with the [0] bit 0b.  Correct PEC.
#   F4  Same with 0x63, whose [0] bit is 1b, which Table 3 does not permit.
#   F5  Routing Information Update request, count 2, both records complete:
#       type 11b/size 4/EID 0x51/address 0x62 and type 00b/size 2/EID 0x30/
#       address 0x40.  Correct PEC.
#   F6  Same records with the count claiming 3, so the walk runs out of bytes
#       on the third record and the payload-truncated expert fires while
#       records 1 and 2 still decode.
#
# byte_count = 1(src) + 4(MCTP hdr) + len(control body); total length is
# byte_count + 3 without a PEC and byte_count + 4 with one (DSP0237 6.3
# Figure 1 puts the PEC immediately after the last data byte).
# ---------------------------------------------------------------------------

def _bmc_to_drive(flags, payload):
    """MCTP-SMBus frame from the BMC (slave 0x40, EID 0x40) to the drive."""
    return [
        0x40,                     # dst slave addr: 7-bit 0x20 (drive), R/W#=0
        0x0F,                     # command code
        1 + 4 + len(payload),     # byte_count
        0x81,                     # src slave addr: 7-bit 0x40 (BMC), MCTP flag=1
        0x01,                     # MCTP header version
        0x20,                     # destination EID (drive)
        0x40,                     # source EID (BMC)
        flags,                    # MCTP flags byte
    ] + list(payload)


def _with_pec(frame):
    return frame + [smbus_pec(frame)]


# Response bodies: byte 0 = MCTP type 0x00, byte 1 = instance ID (Rq clear),
# byte 2 = command, byte 3 = completion code.  MCTP flags 0xC0: SOM|EOM, seq 0,
# TO=0 (the BMC owned the tag), tag 0.
_GET_EID_FAIR = _with_pec(_drive_to_bmc(
    0xC0, [0x00, 0x01, 0x02, 0x00, 0x42, 0x12, 0x01]))
_GET_EID_MEDIUM_RSVD = _drive_to_bmc(
    0xC0, [0x00, 0x02, 0x02, 0x00, 0x42, 0x12, 0x03])
_RESOLVE_EID_ADDR = _with_pec(_drive_to_bmc(
    0xC0, [0x00, 0x03, 0x07, 0x00, 0x50, 0x62]))
_RESOLVE_EID_ADDR_LSB = _drive_to_bmc(
    0xC0, [0x00, 0x04, 0x07, 0x00, 0x50, 0x63])

# Request bodies: byte 1 has Rq set (0x80).  MCTP flags 0xC8: SOM|EOM, seq 0,
# TO=1, tag 0, as the BMC-originated frames above use.
_ROUTING_UPDATE_RECORDS = [0x03, 0x04, 0x51, 0x62, 0x00, 0x02, 0x30, 0x40]
_ROUTING_UPDATE = _with_pec(_bmc_to_drive(
    0xC8, [0x00, 0x85, 0x09, 0x02] + _ROUTING_UPDATE_RECORDS))
_ROUTING_UPDATE_SHORT = _bmc_to_drive(
    0xC8, [0x00, 0x86, 0x09, 0x03] + _ROUTING_UPDATE_RECORDS)


# ---------------------------------------------------------------------------
# NVMe-MI helpers for the captures below
# ---------------------------------------------------------------------------

NVME_MI_TYPE_MI      = 0x1


def nvme_mi_header(msg_type, csi, is_response, ic=True, meb=False, ciap=False):
    b0 = 0x04 | (0x80 if ic else 0x00)  # bit 7 = IC (Integrity Check enabled)
    b1 = (msg_type << 3) | (csi & 0x01)
    if is_response:
        b1 |= 0x80
    # Byte 2 bit 0 = MEB, bit 1 = CIAP (bits 16 and 17 of the 32-bit LE header)
    b2 = (0x01 if meb else 0x00) | (0x02 if ciap else 0x00)
    return bytes([b0, b1, b2, 0x00])

def nvme_mi_message(msg_type, csi, is_response, payload, ic=True, meb=False,
                    ciap=False, mic=None):
    """One complete NVMe-MI message: header + payload + MIC when IC = 1.

    The MIC is CRC-32C over the header and payload, serialised
    least-significant octet first.  `mic`, when given, overrides it.
    """
    hdr = nvme_mi_header(msg_type, csi, is_response, ic=ic, meb=meb, ciap=ciap)
    if not ic:
        assert mic is None, "an IC = 0 message carries no MIC to override"
        return hdr + payload
    if mic is None:
        mic = crc32c(hdr + payload)
    return hdr + payload + struct.pack('<I', mic)


def mi_request_payload(opcode, cdw0=0, cdw1=0):
    """MI command request: opcode(1) + rsvd(3) + CDW0(4) + CDW1(4) = 12 bytes."""
    return bytes([opcode, 0, 0, 0]) + struct.pack('<II', cdw0, cdw1)

def mi_response_payload(status, nmresp=0):
    """MI command response: status(1) + nmresp(3) = 4 bytes."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3]

def mi_response_payload_with_data(status, data, nmresp=0):
    """MI command response with trailing data bytes (exercises nvme-mi.mi.data)."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3] + data


# NVME-MI status codes
STATUS_SUCCESS = 0x00


SMBUS_MCTP_CMD_CODE = 0x0F

BRIDGE_BMC_ADDR = 0x10
BRIDGE_DEV_ADDR = 0x3A      # one 2-Wire port; two Management Endpoints behind it
BRIDGE_BMC_EID  = 0x08
BRIDGE_ME_A_EID = 0x1E


def smbus_mctp_frame(dst_addr, src_addr, dst_eid, src_eid, tag, is_request,
                     mctp_msg, pec=None, som=True, eom=True, seq=0):
    """MCTP-over-SMBus block write (DSP0237) carrying an MCTP message.

    byte_count counts the source slave address plus the MCTP data.  With
    `pec=None` the frame carries no PEC (len == byte_count + 3), which
    packet-mctp-smbus.c accepts; pass pec=True to append the correct PEC,
    or an integer 0-255 to append a deliberately wrong one.

    som/eom/seq build a multi-packet assembly: DSP0236 8.2 packetizes one
    MCTP message across packets that share the tag and carry an incrementing
    packet sequence number, with SOM on the first and EOM on the last.
    """
    to = 0x08 if is_request else 0x00          # Tag Owner
    fst = ((0x80 if som else 0x00) | (0x40 if eom else 0x00)
           | ((seq & 0x03) << 4) | to | (tag & 0x07))
    mctp_hdr = bytes([
        0x01,                                   # MCTP header version
        dst_eid,
        src_eid,
        fst,
    ])
    mctp_data = mctp_hdr + mctp_msg
    byte_count = 1 + len(mctp_data)             # src addr + MCTP data
    frame = bytes([
        (dst_addr << 1) & 0xFE,                 # destination slave address, W
        SMBUS_MCTP_CMD_CODE,
        byte_count,
        ((src_addr << 1) & 0xFE) | 0x01,        # source slave address, MCTP bit
    ]) + mctp_data
    if pec is None:
        return frame
    return frame + bytes([smbus_pec(frame) if pec is True else pec & 0xFF])


def _sliced(pkt, caplen):
    """(bytes, reported length) for a frame the capture cut at `caplen`."""
    return (pkt[:caplen], len(pkt))


# ---------------------------------------------------------------------------
# mctp-smbus-ingress.pcapng - bad PEC handling and declared-packet truncation
# ---------------------------------------------------------------------------
#
# The SMBus layer reports the failed PEC in either preference mode.  With the
# default drop_bad_pec preference, the MCTP header remains visible but the
# packet cannot start, terminate, or change a message assembly.
#
#   F1/F2 good-PEC single-packet exchange, tag 1             positive twin
#   F3    bad-PEC first packet of a two-packet request, tag 0
#   F4    good-PEC second packet, EOM (orphan with the default preference)
#   F5    good-PEC response, tag 0
#
# F6-F11 are the capture-truncation family.  DSP0237 §6.3 Table 1 makes the
# Byte Count "the count of bytes that follow the Byte Count field up to, but
# not including, the PEC byte", so a complete declared packet is byte_count+3
# octets and the PEC, when the record has one, is the octet after it.  Three
# lengths therefore matter independently -- what the record declares, what it
# reports, and what the capture kept -- and each of these frames pins one
# combination:
#
#   F6    byte_count 20, reported 23, captured 12: the declared packet is not
#         all there.  The heuristic must decline it, and a forced decode must
#         say why and still not hand it to MCTP.
#   F7/F8 a complete exchange whose records carry no PEC at all
#         (reported == byte_count+3).
#   F9    a record reporting a PEC the snaplen cut, with its declared packet
#         intact: MCTP runs, the check byte is not read.
#   F10   its response, complete, as the control for F9
#   F11   trailing octets reported *and* the capture cut short: both
#         statements are true and both must be made.
#
# Every record in F1-F5 carries a PEC, unlike the MCTP-bridge section of
# nvme-mi-transactions.pcapng, which is deliberately the no-PEC shape.

_SMBUS_MSG_REQ  = nvme_mi_message(NVME_MI_TYPE_MI, 0, False,
                                  mi_request_payload(0x01))
_SMBUS_MSG_RESP = nvme_mi_message(NVME_MI_TYPE_MI, 0, True,
                                  mi_response_payload(STATUS_SUCCESS))
# 15 octets, chosen so that smbus_mctp_frame() reports byte_count 20 and a
# 23-octet record.  IC = 0 keeps it at
# 15 without a MIC.
_SMBUS_MSG_TRUNC = nvme_mi_message(
    NVME_MI_TYPE_MI, 0, True,
    mi_response_payload_with_data(STATUS_SUCCESS, bytes(7)), ic=False)

def _smbus_ingress(mctp_msg, tag, is_request, pec=True, som=True, eom=True,
                   seq=0, bus=0):
    if is_request:
        dst_addr, src_addr = BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR
        dst_eid,  src_eid  = BRIDGE_ME_A_EID, BRIDGE_BMC_EID
    else:
        dst_addr, src_addr = BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR
        dst_eid,  src_eid  = BRIDGE_BMC_EID, BRIDGE_ME_A_EID
    return i2c_phdr(bus=bus) + smbus_mctp_frame(
        dst_addr, src_addr, dst_eid, src_eid, tag, is_request, mctp_msg,
        pec=pec, som=som, eom=eom, seq=seq)

def _smbus_read(frame):
    """The same record, flagged as an I2C Read in the DLT209 pseudo-header.

    i2c_phdr() lays the header out as one bus octet then four big-endian flag
    octets, and bit 0 of those flags is the Read flag (wiretap/pcap-common.c
    pcap_read_i2c_linux_pseudoheader()). Only the flag changes; every raw SMBus
    byte, including its Write R/W# bit and PEC, is the Write twin's.
    """
    return i2c_phdr(bus=0, flags=1) + frame[I2C_PHDR_LEN:]


def _smbus_odd_addr(frame):
    """The same record with bit 0 of the destination address octet set.

    The raw SMBus address octet's low bit is R/W#, so this turns the Block
    Write into a Read and must keep it out of MCTP. The PEC covers the octet,
    so it is recomputed to keep the record structurally perfect apart from
    the bit under test.
    """
    body = bytearray(frame[I2C_PHDR_LEN:])
    body[0] |= 0x01
    body[-1] = smbus_pec(bytes(body[:-1]))
    return frame[:I2C_PHDR_LEN] + bytes(body)


def _smbus_bad_pec(frame):
    """Same record, with the low bit of its PEC byte inverted."""
    return frame[:-1] + bytes([frame[-1] ^ 0x01])

packets_smbus_ingress = [
    _smbus_ingress(_SMBUS_MSG_REQ,  tag=1, is_request=True),
    _smbus_ingress(_SMBUS_MSG_RESP, tag=1, is_request=False),

    # One bit of the correct PEC inverted: the record is structurally perfect
    # and only the check byte is wrong.
    _smbus_bad_pec(_smbus_ingress(_SMBUS_MSG_REQ[:10], tag=0, is_request=True,
                                  som=True, eom=False, seq=0)),
    _smbus_ingress(_SMBUS_MSG_REQ[10:], tag=0, is_request=True,
                   som=False, eom=True, seq=1),
    _smbus_ingress(_SMBUS_MSG_RESP, tag=0, is_request=False),

    # F6  byte_count 20 -> a declared packet of 23 octets, all 23
    # reported, only 12 captured.  The 15-byte MCTP message that produces
    # byte_count 20 is an MI response body with seven bytes of Response Data;
    # nothing ever decodes it, which is the point.
    _sliced(_smbus_ingress(_SMBUS_MSG_TRUNC, tag=2, is_request=False,
                           pec=None),
            I2C_PHDR_LEN + 12),

    # F7/F8  A complete exchange, every octet
    # captured, and no PEC in either record: reported == captured ==
    # byte_count+3.  Absence must be stated as a status and judged as nothing.
    _smbus_ingress(_SMBUS_MSG_REQ,  tag=3, is_request=True,  pec=None),
    _smbus_ingress(_SMBUS_MSG_RESP, tag=3, is_request=False, pec=None),

    # F9/F10  F9 reports a PEC at offset 28 and the capture stops
    # at exactly 28, so the declared packet is whole and only the check byte
    # is missing: MCTP still runs, and nothing reads the absent octet.  F10 is
    # the same exchange's response, complete, so the pair still links.
    _sliced(_smbus_ingress(_SMBUS_MSG_REQ, tag=4, is_request=True),
            I2C_PHDR_LEN + 28),
    _smbus_ingress(_SMBUS_MSG_RESP, tag=4, is_request=False),

    # F11  Two octets past the PEC *and* a capture that stops
    # inside the declared packet.  The trailing-octet statement is about what
    # the record reports and stays true; the truncation statement is about
    # what was kept.  Both are made, neither replaces the other.
    _sliced(_smbus_ingress(_SMBUS_MSG_REQ, tag=5, is_request=True)
            + b'\xAA\xBB',
            I2C_PHDR_LEN + 20),

    # F12/F13: byte-identical raw SMBus frames; only F12's capture header says
    # Read. The binding takes R/W# from the raw destination address octet, so
    # both are Block Writes and must be claimed.
    _smbus_read(_smbus_ingress(_SMBUS_MSG_REQ, tag=6, is_request=True)),
    _smbus_ingress(_SMBUS_MSG_REQ, tag=6, is_request=True),

    # F14: the capture header says Write, but the raw SMBus address octet is a
    # Read. The I2C layer still reports its capture-level direction as Write;
    # the SMBus binding rejects it using the raw R/W# bit.
    _smbus_odd_addr(_smbus_ingress(_SMBUS_MSG_REQ, tag=7, is_request=True)),

    # F15/F16  Seven-bit address 0 in both directions, which are
    # two different reserved things: octet 00h on a Write is the General Call,
    # octet 01h on a Read is the START byte and addresses nothing.  Short
    # records, so no heuristic claims them and the address label is the only
    # thing under test.
    i2c_phdr(bus=0, flags=0) + bytes([0x00, 0x0F, 0x02, 0x21]),
    i2c_phdr(bus=0, flags=1) + bytes([0x01, 0x0F, 0x02, 0x21]),

    # F17-F19  The response side of the PEC question.
    # Single-packet records, so no reassembly is involved and the only state
    # at stake is the NVMe-MI Command Slot.  Tag 1 is reused deliberately:
    # F1/F2 completed their exchange, so F17 opens a fresh transaction on it
    # rather than displacing anything.
    #
    #   F17 good request                      opens the slot
    #   F18 response with a corrupted PEC     the frame under test
    #   F19 the good response
    #
    # Default: F18's PEC failure changes nothing downstream, so F18 takes the
    # link and closes the slot, and F19 arrives to find nothing outstanding.
    _smbus_ingress(_SMBUS_MSG_REQ,  tag=1, is_request=True),
    _smbus_bad_pec(_smbus_ingress(_SMBUS_MSG_RESP, tag=1, is_request=False)),
    _smbus_ingress(_SMBUS_MSG_RESP, tag=1, is_request=False),
]


BASE_TS_SMBUS_INGRESS_US = 1712361600 * 1_000_000

def build_smbus_ingress_pcapng(output_path, scope_sections):
    """F1-F19 as mapped above, then F20-F27: the three ingress-scope
    sections main() builds (see its comments)."""
    data = shb() + idb(link_type=DLT_LINUX_I2C)
    for i, pkt in enumerate(packets_smbus_ingress):
        ts = BASE_TS_SMBUS_INGRESS_US + i * 1_000_000
        if isinstance(pkt, tuple):
            data += epb(pkt[0], ts, origlen=pkt[1])
        else:
            data += epb(pkt, ts)
    data += scope_sections
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_smbus_ingress) + 8} packets to {output_path}")


# ---------------------------------------------------------------------------
# i2c-transport-edge.pcapng - direction and the reserved address 00h
# ---------------------------------------------------------------------------
#
# LINKTYPE_IPMB_KONTRON (DLT 199) puts a two-octet capture header -- data
# length, then port -- in front of an IPMB frame whose first octet is the
# responder address in ordinary I2C form: seven-bit address in bits 7:1, R/W#
# in bit 0.  packet-i2c.c used to read the direction from offset 0, the
# *length* octet, so the reported direction was the parity of the frame length.
#
#   F1  valid IPMB write, 10-byte frame -> length octet 0x0A (even)
#   F2  valid IPMB write, 11-byte frame -> length octet 0x0B (odd)
#
# Both are writes -- every IPMB transaction is -- so both must read Write.
# Under the defect they read Write and Read respectively, which is the whole
# oracle.  Both also show that the IPMB dissector is handed
# the frame at offset 2, so the responder address is its byte 0 and its header
# checksum over bytes 0:2 verifies.
#
#   F3  responder-address octet 00h -> seven-bit address 0, R/W# clear:
#       the General Call address
#   F4  responder-address octet 01h -> seven-bit address 0, R/W# set:
#       the START byte, which addresses no device and is not a General Call
#
# F3 and F4 carry the same valid IPMB body so that the only difference between
# them is the direction bit of the address octet.

DLT_IPMB_KONTRON = 199


def _ipmb_frame(rs_sa, netfn_lun, rq_sa, rq_seq_lun, cmd, data=b''):
    """One IPMB frame with both checksums correct.

    packet-ipmi.c do_dissect_ipmb() verifies a checksum over bytes 0:2
    (responder address, NetFn/LUN, cks1) and a second over byte 3 onward, so
    both have to be right for the frame to decode as IPMB at all -- which is
    what makes the offset-2 handoff observable rather than assumed.
    """
    head = bytes([rs_sa, netfn_lun])
    cks1 = (-sum(head)) & 0xFF
    body = bytes([rq_sa, rq_seq_lun, cmd]) + data
    cks2 = (-sum(body)) & 0xFF
    return head + bytes([cks1]) + body + bytes([cks2])


def _kontron_record(ipmb, port=0):
    """Kontron capture header (length, port) followed by the IPMB frame."""
    return bytes([len(ipmb) & 0xFF, port]) + ipmb


# NetFn 2Eh (OEM/Group, request) takes a vendor-defined data field of any
# length, so the two frames differ only in how many data bytes they carry.
# Three data bytes give a 10-octet frame (length octet 0x0A, even) and four
# give an 11-octet one (0x0B, odd): both length parities.
_FXN_WRITE_EVEN = _ipmb_frame(0x20, 0x2E << 2, 0x10, 0x00, 0x01,
                              bytes([0xA1, 0xA2, 0xA3]))
_FXN_WRITE_ODD  = _ipmb_frame(0x20, 0x2E << 2, 0x10, 0x00, 0x01,
                              bytes([0xB1, 0xB2, 0xB3, 0xB4]))
_FXN_GENERAL_CALL = _ipmb_frame(0x00, 0x2E << 2, 0x10, 0x00, 0x01,
                                bytes([0xC1, 0xC2]))
_FXN_START_BYTE   = _ipmb_frame(0x01, 0x2E << 2, 0x10, 0x00, 0x01,
                                bytes([0xC1, 0xC2]))

# The runt and event records, on a second interface.
#
#   F5  a three-octet DLT199 record: the two-octet capture header and one
#       address octet, and nothing else.  Reading the address octet from it
#       is legal, but the one byte left over is not an IPMB frame -- IPMB's
#       own shortest form is seven octets -- and handing it over anyway made
#       packet-ipmi.c write "IPMB" into the protocol column for a message it
#       then declined to decode.
#   F6  a two-octet DLT199 record: the capture header alone.  This is the
#       one that used to raise a bounds exception, because the address octet
#       at offset 2 was read without asking whether it was there.
#   F7  a DLT209 data record consisting of the five-octet pseudo-header and
#       no payload at all.  Wiretap strips the pseudo-header, so what the
#       dissector receives is an empty TVB, and the hardware address it used
#       to read from offset 0 unconditionally is not there.
#   F8  a DLT209 *event* record: I2C_EVENT_ONLINE_OFF (bit 3, "the I2C
#       controller went offline") with the upper-order error bit for a clock
#       low timeout set.  The LINKTYPE_I2C_LINUX description attaches those
#       upper bits to this event by name; they used to be read only under
#       bit 5.
#   F9  the same upper bits under I2C_EVENT_ATTACHED_OFF (bit 5, "the I2C
#       controller detached from an I2C bus").  This is the frame that used
#       to take F8's reason, and must now report the detach alone.
#   F10 an ordinary DLT209 write record, as the control for F7: an address
#       octet and two data bytes, which must decode exactly as it always did.
#
# F5, F6 and F7 are records that really are too short: their *reported*
# lengths say so, which is a statement about what was on the wire.  The three
# that follow report enough and were cut by the snaplen instead, which is a
# statement about the capture and not a defect in the traffic.  Calling the
# second kind malformed blames the sender for the analyst's snaplen, so each
# genuine runt above has a capture-cut twin here that must be handled by the
# ordinary captured-bounds path and raise no diagnostic of its own.
#
#   F11 DLT199 reporting twelve octets and keeping two: the address octet at
#       offset 2 is reported but not stored, so it cannot be read and the
#       record is not thereby malformed.  F6's twin.
#   F12 DLT199 reporting twelve octets and keeping three: the address octet
#       is there and is read, and the IPMB body after it is reported long
#       enough to be a real seven-octet frame -- so the "too short for IPMB"
#       finding must not fire, and the handoff must not happen either,
#       because the octets IPMB would read were not kept.  F5's twin.
#   F13 DLT209 reporting one data octet after the pseudo-header and keeping
#       none of it.  F7's twin: F7 reports nothing after the pseudo-header,
#       this one reports an address octet that the capture cut.

DLT199_RUNT_ADDR_ONLY = bytes([0x01, 0x00, 0x20])
DLT199_RUNT_HEADER_ONLY = bytes([0x01, 0x00])

# The reported length the two capture-cut DLT199 records claim: the same
# twelve-octet record F1 carries whole, so what they report is a frame that
# would decode as IPMB in full.
DLT199_CUT_REPORTED_LEN = 12

I2C_EVENT_ONLINE_OFF    = 1 << 3
I2C_EVENT_ATTACHED_OFF  = 1 << 5
I2C_EVENT_ERR_CLOCK_TO  = 1 << 20


def _i2c_linux_record(payload, bus=0, flags=0, is_event=False):
    """A LINKTYPE_I2C_LINUX record: the five-octet pseudo-header wiretap
    strips (bus + event flag, then four big-endian flag octets), followed by
    the record body.  For an event record the body is empty and the flags
    carry the event bitmap."""
    return (bytes([(bus & 0x7F) | (0x80 if is_event else 0x00)])
            + struct.pack('>I', flags) + payload)


packets_i2c_transport_edge = [
    # (interface index, record bytes)
    (0, _kontron_record(_FXN_WRITE_EVEN)),
    (0, _kontron_record(_FXN_WRITE_ODD)),
    (0, _kontron_record(_FXN_GENERAL_CALL)),
    (0, _kontron_record(_FXN_START_BYTE)),
    (0, DLT199_RUNT_ADDR_ONLY),
    (0, DLT199_RUNT_HEADER_ONLY),
    (1, _i2c_linux_record(b'')),
    (1, _i2c_linux_record(b'', is_event=True,
                          flags=I2C_EVENT_ONLINE_OFF | I2C_EVENT_ERR_CLOCK_TO)),
    (1, _i2c_linux_record(b'', is_event=True,
                          flags=I2C_EVENT_ATTACHED_OFF | I2C_EVENT_ERR_CLOCK_TO)),
    (1, _i2c_linux_record(bytes([0x20, 0xD1, 0xD2]))),
    # (interface, record bytes, reported length) for the snaplen-cut records
    (0, DLT199_RUNT_HEADER_ONLY, DLT199_CUT_REPORTED_LEN),
    (0, DLT199_RUNT_ADDR_ONLY, DLT199_CUT_REPORTED_LEN),
    # Five octets of pseudo-header kept, six reported: wiretap subtracts the
    # pseudo-header from both, so the dissector sees a record reporting one
    # data octet and holding none.
    (1, _i2c_linux_record(b''), 6),
]

BASE_TS_I2C_TRANSPORT_EDGE_US = 1713052800 * 1_000_000


def build_i2c_transport_edge_pcapng(output_path):
    # Two interfaces: the Kontron IPMB link type the file started with, and
    # the Linux I2C one the runt and event records need.  Every frame names
    # its own by zero-based IDB position, so the four original frames stay on
    # interface 0 and are byte-for-byte what they were.
    data = shb() + idb(link_type=DLT_IPMB_KONTRON) + idb(link_type=DLT_LINUX_I2C)
    for i, entry in enumerate(packets_i2c_transport_edge):
        # A third element is the reported length of a snaplen-cut record;
        # without one the record is whole and emits exactly what it always
        # did.
        iface, pkt = entry[0], entry[1]
        origlen = entry[2] if len(entry) > 2 else None
        data += epb(pkt, BASE_TS_I2C_TRANSPORT_EDGE_US + i * 1_000_000,
                    origlen=origlen, interface_id=iface)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_i2c_transport_edge)} packets to {output_path}")


# ---------------------------------------------------------------------------
# mctp-smbus.pcapng F20-F27 - the SMBus Info prefix and a throwing body
# ---------------------------------------------------------------------------
#
# packet-mctp-smbus.c composes the physical addressing prefix
# "[0xNN->0xNN] " into COL_INFO.  It used to do so after call_dissector()
# returned, so a bounds exception thrown anywhere below -- the ordinary
# condition on a snaplen-sliced capture -- unwound past it and the packet list
# lost the only indication of which two devices were talking, on precisely the
# frames a reader is looking at when something has gone wrong.
#
# No committed capture combined an SMBus ingress with a body that throws, so
# the defect had no runtime witness on the SMBus half at all; this section is
# that witness, and its first two frames are the control that shows the clean
# composition is unchanged.  F1-F8 below are mctp-smbus.pcapng F20-F27.
#
#   F1/F2 complete request and response, good PEC        positive twin
#   F3    the same request cut six bytes into its command dwords; it
#         degrades with a truncation expert rather than throwing
#   F4    the same request cut four bytes: the MIC is gone but the body is
#         whole, so nothing throws and the prefix was never at risk
#   F5/F6 a complete request and a response captured to the end of the
#         NVMe-MI header, so the body's status read throws
#
# F3, F4 and the F5/F6 pair are each on Management Endpoint EIDs of their own
# so that none displaces the F1 exchange's Command Slot; the point of the file
# is a column, and a superseded-request note would be noise in it.

SMBUS_EXC_ME_THROW_EID = 0x30
SMBUS_EXC_ME_NOMIC_EID = 0x31

_SMBUS_EXC_REQ  = nvme_mi_message(NVME_MI_TYPE_MI, 0, False,
                                  mi_request_payload(0x01))
_SMBUS_EXC_RESP = nvme_mi_message(NVME_MI_TYPE_MI, 0, True,
                                  mi_response_payload(STATUS_SUCCESS))

def _smbus_exc(mctp_msg, tag, is_request, me_eid=BRIDGE_ME_A_EID, bus=0):
    if is_request:
        dst_addr, src_addr = BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR
        dst_eid,  src_eid  = me_eid, BRIDGE_BMC_EID
    else:
        dst_addr, src_addr = BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR
        dst_eid,  src_eid  = BRIDGE_BMC_EID, me_eid
    return i2c_phdr(bus=bus) + smbus_mctp_frame(
        dst_addr, src_addr, dst_eid, src_eid, tag, is_request, mctp_msg,
        pec=True)

packets_smbus_body_exception = [
    _smbus_exc(_SMBUS_EXC_REQ,  tag=1, is_request=True),
    _smbus_exc(_SMBUS_EXC_RESP, tag=1, is_request=False),
]

# 5 I2C pseudo-header + 4 SMBus + 4 MCTP + 20 NVMe-MI + 1 PEC = 34 bytes.
_SMBUS_EXC_THROW = _smbus_exc(_SMBUS_EXC_REQ, tag=2, is_request=True,
                              me_eid=SMBUS_EXC_ME_THROW_EID)
_SMBUS_EXC_NOMIC = _smbus_exc(_SMBUS_EXC_REQ, tag=3, is_request=True,
                              me_eid=SMBUS_EXC_ME_NOMIC_EID)
packets_smbus_body_exception += [
    # Cut seven: the PEC and six NVMe-MI bytes, so the body's last CDW1 byte
    # is missing and packet-nvme-mi-mi.c throws reading it.
    (_SMBUS_EXC_THROW[:-7], len(_SMBUS_EXC_THROW)),
    # Cut five: the PEC and the four MIC bytes.  The body is complete.
    (_SMBUS_EXC_NOMIC[:-5], len(_SMBUS_EXC_NOMIC)),
]

# F5/F6  the throwing witness.
#
# A sliced *request* degrades rather than throws -- it checks its captured
# length before reading the fixed command dwords.  A sliced *response* still
# throws: the response path reads its Response Message Status byte at body
# offset 0 after the framing layer has already emitted the SMBus prefix and the
# MIC, so it shows that both survive an exception raised below them.
#
#   F5  a complete request on its own tag, so F6 has a transaction
#   F6  its response, captured to the end of the NVMe-MI header: the body
#       reports four bytes and carries none, so the status read throws
SMBUS_EXC_ME_RESP_EID = 0x32

_SMBUS_EXC_RESP_THROW = _smbus_exc(_SMBUS_EXC_RESP, tag=4, is_request=False,
                                   me_eid=SMBUS_EXC_ME_RESP_EID)
packets_smbus_body_exception += [
    _smbus_exc(_SMBUS_EXC_REQ, tag=4, is_request=True,
               me_eid=SMBUS_EXC_ME_RESP_EID),
    # i2c(5) + SMBus(4) + MCTP(4) + the four-byte NVMe-MI header = 17.
    (_SMBUS_EXC_RESP_THROW[:17], len(_SMBUS_EXC_RESP_THROW)),
]

# F7/F8  the complete-record witness.
#
# The SMBus layer does not claim a record whose declared packet the capture
# cut, which is what F3, F4 and F6 above are.  This pair asks the same question
# of a record with every octet present.
#
# The NVMe-MI bytes are lifted verbatim from the version-context section of
# nvme-mi-transactions.pcapng (its F21/F22, F199/F200 there), the corpus's
# existing fully-captured body-failure vector: a Read
# NVMe-MI Data Structure request for DTYP 00h (NVM Subsystem Information, a
# 32-byte structure) answered with a Success response carrying RDL 2 and two
# bytes of Response Data.  The response's own declared structure is longer
# than the message that frames it, so the MI body cannot finish decoding it --
# a contradiction internal to the body, with nothing missing from the capture.
#
# The wrapper is complete, so the SMBus layer claims it, the prefix is
# composed, the MIC is verified and published, and the body then fails: the
# transport's evidence survives a body that cannot finish.  It fails *gracefully*, through
# nvme-mi.mi.truncated, rather than by throwing: see the audit in the class
# docstring for why no reachable decoder in this stack throws on a complete
# message today.
SMBUS_EXC_ME_RDL_EID = 0x33

_SMBUS_EXC_RDL_REQ = nvme_mi_message(NVME_MI_TYPE_MI, 0, False,
                                     mi_request_payload(0x00, cdw0=0))
_SMBUS_EXC_RDL_RESP = nvme_mi_message(
    NVME_MI_TYPE_MI, 0, True,
    mi_response_payload_with_data(STATUS_SUCCESS, b'\x01\x02', nmresp=2))

packets_smbus_body_exception += [
    _smbus_exc(_SMBUS_EXC_RDL_REQ, tag=5, is_request=True,
               me_eid=SMBUS_EXC_ME_RDL_EID),
    _smbus_exc(_SMBUS_EXC_RDL_RESP, tag=5, is_request=False,
               me_eid=SMBUS_EXC_ME_RDL_EID),
]

BASE_TS_SMBUS_BODY_EXCEPTION_US = 1712966400 * 1_000_000


def smbus_body_exception_section():
    data = shb() + idb(link_type=DLT_LINUX_I2C, name='smbus-body-exception')
    for i, pkt in enumerate(packets_smbus_body_exception):
        ts = BASE_TS_SMBUS_BODY_EXCEPTION_US + i * 1_000_000
        if isinstance(pkt, tuple):
            data += epb(pkt[0], ts, origlen=pkt[1])
        else:
            data += epb(pkt, ts)
    return data


# ---------------------------------------------------------------------------
# mctp-smbus.pcapng F34-F36 - header-only packets and header version 2
# ---------------------------------------------------------------------------
#
# DSP0236 Table 1 carries the message type byte in a message's first packet
# only, so a continuation packet may be the four-byte transport header alone.
# DSP0237 Table 1 marks header versions other than 1 Reserved, which DSP0236
# 8.7 treats as a packet drop condition rather than a malformed SMBus frame.
#   F34  start packet over SMBus, byte count 69, tag 3
#   F35  end packet over SMBus, byte count 5 (header only)
#   F36  header version 2 over SMBus, otherwise a valid single packet

EMPTY_FINAL_HOST_EID = 0x0A
EMPTY_FINAL_DEV_EID = 0x30
EMPTY_FINAL_TYPE = 0x0A          # Reserved in DSP0239: no dissector claims it


def smbus_empty_final_section():
    host, dev, mtype = EMPTY_FINAL_HOST_EID, EMPTY_FINAL_DEV_EID, EMPTY_FINAL_TYPE
    payload = bytes([mtype]) + bytes(range(1, 64))
    frames = [
        smbus_mctp_frame(0x1D, 0x10, dev, host, 3, True, payload,
                         pec=True, som=True, eom=False, seq=0),
        smbus_mctp_frame(0x1D, 0x10, dev, host, 3, True, b'',
                         pec=True, som=False, eom=True, seq=1),
    ]
    bad = bytearray(smbus_mctp_frame(0x1D, 0x10, dev, host, 4, True,
                                     bytes([mtype, 1, 2])))
    bad[4] = 0x02                              # MCTP header version 2
    frames.append(bytes(bad) + bytes([smbus_pec(bytes(bad))]))
    data = shb() + idb(DLT_LINUX_I2C, name='mctp-smbus-empty-final.pcapng')
    for n, frame in enumerate(frames, 1):
        data += epb(i2c_phdr() + frame, 1750000000000000 + n * 1000)
    return data


def build_smbus_reassembly_pcapng(output_path):
    """Cover bad-PEC retries, the SMBus inter-packet timeout, and message tags."""
    data = shb() + idb(DLT_LINUX_I2C, name='mctp-smbus-reassembly')
    start = bytes([0x7D]) + bytes([0xA1]) * 63
    middle = bytes([0xB1]) * 64
    tail = bytes([0xC1]) * 4
    frames = []

    def add(tag, payload, *, som, eom, seq, timestamp_us, pec=True,
            bad_pec=False):
        frame = smbus_mctp_frame(0x20, 0x40, 0x20, 0x40, tag, True, payload,
                                 pec=pec, som=som, eom=eom, seq=seq)
        if bad_pec:
            frame = frame[:-1] + bytes([frame[-1] ^ 0x01])
        frames.append((timestamp_us, i2c_phdr() + frame))

    base = 1_750_000_000_000_000
    add(1, start,  som=True,  eom=False, seq=0, timestamp_us=base)
    add(1, middle, som=False, eom=False, seq=1, timestamp_us=base + 10_000,
        bad_pec=True)
    add(1, middle, som=False, eom=False, seq=1, timestamp_us=base + 20_000)
    add(1, tail,   som=False, eom=True,  seq=2, timestamp_us=base + 30_000)

    add(2, start,  som=True, eom=False, seq=0, timestamp_us=base + 40_000,
        bad_pec=True)
    add(2, start,  som=True, eom=False, seq=0, timestamp_us=base + 50_000)
    add(2, tail,   som=False, eom=True,  seq=1, timestamp_us=base + 60_000)

    add(3, start,  som=True,  eom=False, seq=0, timestamp_us=base + 70_000)
    add(3, middle, som=True,  eom=False, seq=1, timestamp_us=base + 80_000,
        bad_pec=True)
    add(3, tail,   som=False, eom=True,  seq=1, timestamp_us=base + 90_000)

    # The timeout check subtracts the larger packet's worst-case bus time,
    # 250 us per byte (DSP0237 Table 8 PT1a/PT1b), (68 + 5) * 250 us =
    # 18.25 ms here, from the timestamp gap: 119 ms leaves about 100.75 ms of
    # idle, just over MT3a.
    add(4, start,  som=True,  eom=False, seq=0, timestamp_us=base + 100_000)
    add(4, tail,   som=False, eom=True,  seq=1, timestamp_us=base + 219_000)

    add(5, start,  som=True,  eom=False, seq=0, timestamp_us=base + 400_000)
    add(5, start,  som=True,  eom=False, seq=0, timestamp_us=base + 600_000)
    add(5, tail,   som=False, eom=True,  seq=1, timestamp_us=base + 610_000)

    add(6, start,  som=True,  eom=False, seq=0, timestamp_us=base + 700_000,
        pec=None)
    add(6, tail,   som=False, eom=True,  seq=1, timestamp_us=base + 710_000,
        pec=None)

    # 118.25 ms less 18.25 ms of bus time is exactly MT3a, not over it.
    add(7, start,  som=True,  eom=False, seq=0, timestamp_us=base + 800_000)
    add(7, tail,   som=False, eom=True,  seq=1, timestamp_us=base + 918_250)

    # F20-F22: 254-byte packets take (254 + 5) * 250 us = 64.75 ms on the
    # bus, so a 160 ms gap is about 95.25 ms idle (within MT3a) and a 170 ms
    # gap about 105.25 ms (over it).
    big = bytes([0x7D]) + bytes([0xA1]) * 249
    add(0, big,    som=True,  eom=False, seq=0, timestamp_us=base + 1_000_000)
    add(0, big,    som=False, eom=False, seq=1, timestamp_us=base + 1_160_000)
    add(0, tail,   som=False, eom=True,  seq=2, timestamp_us=base + 1_330_000)

    for timestamp_us, frame in frames:
        data += epb(frame, timestamp_us)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f'Wrote {len(frames)} frames to {output_path}')


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

    # Frames 11-15: same-tag/different-TO interleave, then a control command
    # above 0x05.  Appended after the truncated frame so the frame numbers the
    # existing tests assert on do not move.
    tail = [
        _TAG_R_SOM,               # F11: message R fragment 1 (SOM, TO=0, tag 2)
        _TAG_A_SOM,               # F12: message A fragment 1 (SOM, TO=1, tag 2)
        _TAG_R_EOM,               # F13: message R fragment 2 (EOM, TO=0, tag 2)
        _TAG_A_EOM,               # F14: message A fragment 2 (EOM, TO=1, tag 2)
        _CTRL_GET_ROUTING_TABLE,  # F15: MCTP Control command 0x0A
        _BAD_PEC,                 # F16: valid frame, corrupted PEC
        _mutate(2, 4),            # F17: Byte Count below the minimum five
        _mutate(2, 9),            # F18: reports 11 bytes, count requires 12
        _VALID,                    # F19: pseudo-header Read; raw address is Write
    ]
    for i, payload in enumerate(tail):
        flags = 1 if i == len(tail) - 1 else 0
        data += i2c_packet(payload, flags=flags, ts_us=(11 + i) * 1_000_000)

    # The ingress-scope sections, F20-F27 of mctp-smbus-ingress.pcapng.
    # Section 1 models one capture source observing two controller buses. F20
    # starts a message on bus 0; F21 has matching address, EID, tag, and
    # sequence fields on bus 1, but must not finish it. DSP0236 §8.3 Table 2
    # permits physical addresses to repeat between buses, so this is a normal
    # multi-bus capture rather than a malformed exchange. Section 2 reuses
    # interface 0 and bus 0; F22 must still not finish F20. F23/F24 are the
    # in-section positive control.
    scope_data = shb() + idb(DLT_LINUX_I2C)
    scope_data += i2c_packet(_scope_fragment(0x8B, [0xAA]), bus=0,
                             ts_us=1_000_000)
    scope_data += i2c_packet(_scope_fragment(0x5B, [0xBB]), bus=1,
                             ts_us=2_000_000)
    scope_data += shb() + idb(DLT_LINUX_I2C)
    scope_data += i2c_packet(_scope_fragment(0x5B, [0xCC]), bus=0,
                             ts_us=3_000_000)
    scope_data += i2c_packet(_scope_fragment(0x8B, [0xDD]), bus=0,
                             ts_us=4_000_000)
    scope_data += i2c_packet(_scope_fragment(0x5B, [0xEE]), bus=0,
                             ts_us=5_000_000)
    # Section 3: two capture interfaces that both report I2C bus 0 -- two
    # hosts' captures merged into one file.  The bus byte is each host's own
    # adapter index, so it identifies a bus only within its interface.  F25
    # starts a message on interface 0; F26 has matching address, EID, tag and
    # sequence fields on interface 1 and must not finish it; F27 on
    # interface 0 does.  (Interface numbers here are the section's own.)
    scope_data += shb() + idb(DLT_LINUX_I2C) + idb(DLT_LINUX_I2C)
    scope_data += i2c_packet(_scope_fragment(0x8B, [0xA6]), bus=0,
                             ts_us=6_000_000, interface_id=0)
    scope_data += i2c_packet(_scope_fragment(0x5B, [0xB7]), bus=0,
                             ts_us=7_000_000, interface_id=1)
    scope_data += i2c_packet(_scope_fragment(0x5B, [0xC8]), bus=0,
                             ts_us=8_000_000, interface_id=0)

    # The DSP0237 binding-specific control fields; see the block comment above.
    control_frames = [
        _GET_EID_FAIR,           # F28: medium-specific 0x01, fairness supported
        _GET_EID_MEDIUM_RSVD,    # F29: 0x03, Table 4's reserved run non-zero
        _RESOLVE_EID_ADDR,       # F30: Table 3 address 0x62
        _RESOLVE_EID_ADDR_LSB,   # F31: 0x63, Table 3's [0] bit set
        _ROUTING_UPDATE,         # F32: count 2, both records complete
        _ROUTING_UPDATE_SHORT,   # F33: count 3, only two records present
    ]
    control_data = shb() + idb(DLT_LINUX_I2C)
    for i, payload in enumerate(control_frames):
        control_data += i2c_packet(payload, ts_us=(i + 1) * 1_000_000)

    # F20-F37 follow F1-F19 as sections of their own (see the docstring), so
    # nothing they start can be finished by a frame from another section.
    data += smbus_body_exception_section() + control_data + smbus_empty_final_section()
    # F37: a whole 7-byte record, below the 8-byte minimum (DSP0237 6.3,
    # byte count 4).  The heuristic declines it; Decode As reports it
    # malformed, unlike F10, which is only cut short by the snaplen.
    data += shb() + idb(DLT_LINUX_I2C) + i2c_packet(
        [0x40, 0x0F, 0x04, 0x81, 0x01, 0x20, 0x40], ts_us=1_000_000)
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f'Wrote 37 frames to {out_path}')

    captures_dir = os.path.join(repo_root, 'test', 'captures')
    build_smbus_ingress_pcapng(os.path.join(captures_dir, 'mctp-smbus-ingress.pcapng'),
                               scope_data)
    build_i2c_transport_edge_pcapng(os.path.join(captures_dir, 'i2c-transport-edge.pcapng'))
    build_smbus_reassembly_pcapng(
        os.path.join(captures_dir, 'mctp-smbus-reassembly.pcapng'))


if __name__ == '__main__':
    main()
