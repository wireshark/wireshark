#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate pcapng test captures for the NVMe-MI dissector.

Two captures are produced:

nvme-mi-req-resp.pcapng  (7 frames)
  Exercises the core request/response matching and MPR slot-tracking fix:
  1. Basic MI request/response (CSI=0)
  2. Admin command with More Processing Required (MPR) then final response (CSI=0)
  3. Concurrent MI command on the second slot (CSI=1), interleaved with the MPR sequence

nvme-mi-types.pcapng  (72 frames)
  Comprehensive coverage across all NVMe-MI message types and edge cases:
  - Orphan response (response before any request on that slot; simulates capture
    started mid-conversation — the dissector must not crash or mislink)
  - All five MI opcodes (0x00-0x04)
  - Several Admin opcodes (Get Log, Set Features, Get Features, Identify)
  - Admin request flags (DLEN, DOFF)
  - Admin response with CQE payload data
  - Multiple consecutive MPR responses (2 interim) before the final response
  - Control primitives (type=0x0) — Pause, Get State, Abort, Replay with
    per-opcode CPSP/CPSR payloads
  - PCIe command (type=0x4) — type detected; body falls back to the data
    dissector until a PCIe body decoder exists
  - Two unanswered requests (no response before capture end): one on CSI=1, one on CSI=0
  - A second MCTP conversation (different BMC EID=0x09) to verify per-conversation
    slot isolation
  - Different MCTP tag values (tag=0 and tag=1) — each tag creates a separate
    Wireshark conversation (separate nvme_mi_conv_info) so slot tracking is
    independent; tested with an Admin command pending on tag=0 while a Control
    primitive on tag=1 opens and closes without disturbing the tag=0 slot
  - MI request with non-zero CDW0 and CDW1 (exercises nvme-mi.mi.cdw0 / nvme-mi.mi.cdw1)
  - MI response with trailing data bytes (exercises nvme-mi.mi.data on the response path)
  - Admin request with DOFF-only flags (0x02) and a non-zero doff value
  - Admin response shorter than 16 bytes (CQE dword fields absent — exercises the < 16 branch)
  - Non-success Admin status code (0x03 Invalid Command Opcode)
  - Non-success MI status code (0x06 Invalid Command Input Data Size)
  - MI request with MEB bit set (exercises nvme-mi.meb)
  - Control Primitive interleaved with an in-flight Admin command on the SAME
    conversation and slot (CSI=0): per NVMe-MI 2.1 a Control Primitive may be
    issued while a command is outstanding, so it must not displace the pending
    command transaction (separate per-slot CP tracking in the dissector)
  - Malformed-frame fixtures (the dissector must flag these with expert info,
    show leftover bytes as raw data, and keep request/response tracking
    intact — never throw mid-tree or corrupt the slot state):
    * Truncated (2-byte) Control Primitive request followed by its complete
      response: the response keeps its link but must not fabricate an opcode
      or a spurious tag-mismatch warning
    * Truncated (8-byte) Admin request followed by a complete response: the
      opcode is still recorded and propagated to the response
    * IC bit set on a frame too short to hold a MIC (trailing bytes kept as
      payload, MIC verification skipped, expert added)
    * 1-byte MI MPR interim response: the status byte alone must keep the
      command slot open so the final response still links to the request

Wire format layers (outer to inner):
  Linux SLL cooked capture header (16 bytes, DLT=113)
  MCTP transport header            (4 bytes)
  NVMe-MI header                   (4 bytes; byte 0 = MCTP type 0x04)
  NVMe-MI payload                  (variable)
"""

import struct
import sys
import os

# CRC32C (Castagnoli) — required for IC-enabled (MIC-carrying) NVMe-MI frames.
_CRC32C_POLY = 0x82F63B78

def crc32c(data):
    """Return the standard CRC32C checksum of data (seed=0xFFFFFFFF, final XOR=0xFFFFFFFF)."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            mask = -(crc & 1) & 0xFFFFFFFF
            crc = (crc >> 1) ^ (_CRC32C_POLY & mask)
    return crc ^ 0xFFFFFFFF

# ---------------------------------------------------------------------------
# pcapng helpers
# ---------------------------------------------------------------------------

def _pad4(n):
    """Round n up to the next multiple of 4."""
    return (n + 3) & ~3

def _block(block_type, body):
    """Wrap body bytes into a pcapng block (type + length + body + length)."""
    padded = body + b'\x00' * (_pad4(len(body)) - len(body))
    total = 12 + len(padded)   # 4 type + 4 len + body + 4 len
    hdr = struct.pack('<II', block_type, total)
    return hdr + padded + struct.pack('<I', total)

def shb():
    """Section Header Block."""
    body = struct.pack('<IHHq',
                       0x1A2B3C4D,   # byte-order magic
                       1, 0,          # major, minor version
                       -1)            # section length = unknown
    return _block(0x0A0D0D0A, body)

def idb(link_type=113, snaplen=65535):
    """Interface Description Block (DLT_LINUX_SLL = 113)."""
    body = struct.pack('<HHI', link_type, 0, snaplen)
    return _block(0x00000001, body)

def epb(packet_bytes, ts_us):
    """Enhanced Packet Block with microsecond timestamp."""
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  =  ts_us & 0xFFFFFFFF
    caplen = len(packet_bytes)
    origlen = caplen
    padded = packet_bytes + b'\x00' * (_pad4(caplen) - caplen)
    body = struct.pack('<IIIII', 0, ts_high, ts_low, caplen, origlen) + padded
    return _block(0x00000006, body)

# ---------------------------------------------------------------------------
# Linux SLL cooked capture header (16 bytes, DLT_LINUX_SLL = 113)
# ---------------------------------------------------------------------------
# Offset 0-1  : packet type (BE): 0=received, 4=sent
# Offset 2-3  : hardware address type (BE): 0 = unknown
# Offset 4-5  : hardware address length (BE): 1 for MCTP EID
# Offset 6-13 : hardware address, 8 bytes padded
# Offset 14-15: protocol type (BE): 0x00FA = LINUX_SLL_P_MCTP

LINUX_SLL_P_MCTP = 0x00FA

def sll_header(src_eid, outgoing=False):
    pkt_type = 0x0004 if outgoing else 0x0000
    arphrd   = 0x0000
    ha_len   = 1
    ha       = bytes([src_eid]) + b'\x00' * 7
    return struct.pack('>HHH8sH', pkt_type, arphrd, ha_len, ha, LINUX_SLL_P_MCTP)

# ---------------------------------------------------------------------------
# MCTP transport header (4 bytes)
# ---------------------------------------------------------------------------
# Byte 0: ver (lower nibble = 1)
# Byte 1: destination EID
# Byte 2: source EID
# Byte 3: [SOM(7)][EOM(6)][seq(5:4)][TO(3)][tag(2:0)]
#   Single-packet, sequence=0, tag N:
#     request  (tag owner = sender): TO=1 → 0xC8|N
#     response (tag owner = peer)  : TO=0 → 0xC0|N
#   Different tag values create separate Wireshark conversations (separate
#   nvme_mi_conv_info) because the MCTP dissector uses tag bits as port numbers.

HOST_EID  = 0x0A
BMC_EID   = 0x08
BMC_EID2  = 0x09   # second controller for conversation-isolation tests

def mctp_header(is_request, host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0):
    src = host_eid if is_request else bmc_eid
    dst = bmc_eid  if is_request else host_eid
    fst = (0xC8 | (tag & 0x07)) if is_request else (0xC0 | (tag & 0x07))
    return bytes([0x01, dst, src, fst])

# ---------------------------------------------------------------------------
# NVMe-MI header (4 bytes) — this IS the MCTP message payload start
# ---------------------------------------------------------------------------
# Byte 0: MCTP type byte = 0x04 (NVMe-MI, IC=0)
# Byte 1: [ROR(7)][msg_type(6:3)][CSI(0)]
#   Control type = 0x0  → bits 3-6 = 0000 → 0x00
#   MI      type = 0x1  → bits 3-6 = 0001 → 0x08
#   Admin   type = 0x2  → bits 3-6 = 0010 → 0x10
#   PCIe    type = 0x4  → bits 3-6 = 0100 → 0x20
#   ROR: 0 = request, 1 = response
# Bytes 2-3: reserved 0x00

NVME_MI_TYPE_CONTROL = 0x0
NVME_MI_TYPE_MI      = 0x1
NVME_MI_TYPE_ADMIN   = 0x2
NVME_MI_TYPE_PCIE    = 0x4

def nvme_mi_header(msg_type, csi, is_response, ic=False, meb=False):
    b0 = 0x04 | (0x80 if ic else 0x00)  # bit 7 = IC (Integrity Check enabled)
    b1 = (msg_type << 3) | (csi & 0x01)
    if is_response:
        b1 |= 0x80
    b2 = 0x01 if meb else 0x00           # bit 16 in 32-bit LE header = MEB
    return bytes([b0, b1, b2, 0x00])

# ---------------------------------------------------------------------------
# NVMe-MI MI payload
# ---------------------------------------------------------------------------

def mi_request_payload(opcode, cdw0=0, cdw1=0):
    """MI command request: opcode(1) + rsvd(3) + CDW0(4) + CDW1(4) = 12 bytes."""
    return bytes([opcode, 0, 0, 0]) + struct.pack('<II', cdw0, cdw1)

def mi_response_payload(status):
    """MI command response: status(1) + nmresp(3) = 4 bytes."""
    return bytes([status, 0, 0, 0])

def mi_response_payload_with_data(status, data):
    """MI command response with trailing data bytes (exercises nvme-mi.mi.data)."""
    return bytes([status, 0, 0, 0]) + data

# ---------------------------------------------------------------------------
# NVMe-MI Control Primitive payload (NVMe-MI 2.1 §4.2.1, Figures 37/39)
# ---------------------------------------------------------------------------
# Request layout :  CPO(1) + TAG(1) + CPSP(2)
# Response layout:  STATUS(1) + TAG(1) + CPSR(2)
# Both: 4 payload bytes.

CP_OPC_PAUSE     = 0x00
CP_OPC_RESUME    = 0x01
CP_OPC_ABORT     = 0x02
CP_OPC_GET_STATE = 0x03
CP_OPC_REPLAY    = 0x04

def cp_request_payload(opcode, tag=0, cpsp=0):
    return struct.pack('<BBH', opcode, tag, cpsp)

def cp_response_payload(status, tag=0, cpsr=0):
    return struct.pack('<BBH', status, tag, cpsr)

# ---------------------------------------------------------------------------
# NVMe-MI Admin payload
# ---------------------------------------------------------------------------

def admin_request_payload(opcode, ctrl_id=0x0000, cns=0x00, flags=0x01, doff=0, dlen=0x1000):
    """Admin request SQE (64 bytes).

    flags byte:
      bit 0 (0x1) = DLEN: use data length field
      bit 1 (0x2) = DOFF: use data offset field
    """
    payload  = bytes([opcode, flags]) + struct.pack('<H', ctrl_id)
    payload += b'\x00' * 20          # SQE1-SQE5
    payload += struct.pack('<I', doff)  # data offset
    payload += struct.pack('<I', dlen)  # data length
    payload += b'\x00' * 8           # reserved
    payload += struct.pack('<I', cns)   # SQE10 (CNS / identify selector)
    payload += b'\x00' * 20          # SQE11-SQE15
    assert len(payload) == 64, f"Admin request payload must be 64 bytes, got {len(payload)}"
    return payload

def admin_response_payload(status, cqe1=0, cqe2=0, cqe3=0):
    """Admin response CQE: status(1)+rsvd(3)+CQE1(4)+CQE2(4)+CQE3(4) = 16 bytes."""
    return bytes([status, 0, 0, 0]) + struct.pack('<III', cqe1, cqe2, cqe3)

def admin_response_payload_short(status):
    """Admin response with only 4 bytes (status + rsvd) — no CQE dwords."""
    return bytes([status, 0, 0, 0])

# ---------------------------------------------------------------------------
# Full packet assembly
# ---------------------------------------------------------------------------

# NVME-MI status codes
STATUS_SUCCESS = 0x00
STATUS_MPR     = 0x01   # More Processing Required

def make_packet(is_request, msg_type, csi, payload,
                host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0, ic=False, meb=False):
    src_eid  = host_eid if is_request else bmc_eid
    sll      = sll_header(src_eid, outgoing=is_request)
    mctp     = mctp_header(is_request, host_eid=host_eid, bmc_eid=bmc_eid, tag=tag)
    nvme_hdr = nvme_mi_header(msg_type, csi, is_response=not is_request, ic=ic, meb=meb)
    if ic:
        protected = nvme_hdr + payload
        mic_bytes = struct.pack('>I', crc32c(protected))
        return sll + mctp + nvme_hdr + payload + mic_bytes
    return sll + mctp + nvme_hdr + payload

# ---------------------------------------------------------------------------
# Build the 7-frame core capture (nvme-mi-req-resp.pcapng)
# ---------------------------------------------------------------------------
#
# Packet sequence:
#   1  Host->BMC   MI  Request  CSI=0  opcode=0x01 (Health Status Poll)
#   2  BMC ->Host  MI  Response CSI=0  status=0x00 (Success)            -> #1
#   3  Host->BMC   ADM Request  CSI=0  opcode=0x06 (Identify)
#   4  Host->BMC   MI  Request  CSI=1  opcode=0x04 (Configuration Get)  [concurrent]
#   5  BMC ->Host  ADM Response CSI=0  status=0x01 (MPR)                -> interim #3
#   6  BMC ->Host  MI  Response CSI=1  status=0x00 (Success)            -> #4
#   7  BMC ->Host  ADM Response CSI=0  status=0x00 (Success)            -> final #3
#
# Expected behaviour:
#   F1: Response In -> F2
#   F2: Request In  -> F1
#   F3: Response In -> F7
#   F4: Response In -> F6
#   F5: Request In  -> F3, 'More Processing Required' flag set
#   F6: Request In  -> F4
#   F7: Request In  -> F3

packets_req_resp = [
    # Frame 1: MI Request, CSI=0, opcode=0x01 (Health Status Poll)
    make_packet(True,  NVME_MI_TYPE_MI,    0, mi_request_payload(0x01)),
    # Frame 2: MI Response, CSI=0, status=0x00 (Success) — answers Frame 1
    make_packet(False, NVME_MI_TYPE_MI,    0, mi_response_payload(STATUS_SUCCESS)),
    # Frame 3: Admin Request, CSI=0, opcode=0x06 (Identify, CNS=1)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0, admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01)),
    # Frame 4: MI Request, CSI=1, opcode=0x04 (Configuration Get) — concurrent slot
    make_packet(True,  NVME_MI_TYPE_MI,    1, mi_request_payload(0x04)),
    # Frame 5: Admin Response, CSI=0, status=0x01 (MPR) — interim for Frame 3
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_response_payload(STATUS_MPR)),
    # Frame 6: MI Response, CSI=1, status=0x00 (Success) — answers Frame 4
    make_packet(False, NVME_MI_TYPE_MI,    1, mi_response_payload(STATUS_SUCCESS)),
    # Frame 7: Admin Response, CSI=0, status=0x00 (Success) — final answer for Frame 3
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_response_payload(STATUS_SUCCESS, cqe1=0xABCD1234)),
]

# Timestamps: 1-second intervals starting at 2024-01-15 10:00:00 UTC
BASE_TS_REQ_RESP_US = 1705312800 * 1_000_000

def build_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_req_resp):
        ts = BASE_TS_REQ_RESP_US + i * 1_000_000
        data += epb(pkt, ts)

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"Written {len(packets_req_resp)} packets to {output_path}")
    print()
    print("Packet summary:")
    descs = [
        "Frame 1: MI Request  CSI=0 opcode=0x01 (Health Status Poll)",
        "Frame 2: MI Response CSI=0 status=0x00 (Success)  [response to Frame 1]",
        "Frame 3: ADM Request CSI=0 opcode=0x06 (Identify)",
        "Frame 4: MI Request  CSI=1 opcode=0x04 (Config Get) [concurrent slot]",
        "Frame 5: ADM Response CSI=0 status=0x01 (MPR)     [interim for Frame 3]",
        "Frame 6: MI Response CSI=1 status=0x00 (Success)  [response to Frame 4]",
        "Frame 7: ADM Response CSI=0 status=0x00 (Success) [final response to Frame 3]",
    ]
    for d in descs:
        print(f"  {d}")

# ---------------------------------------------------------------------------
# Build the comprehensive capture (nvme-mi-types.pcapng)
# ---------------------------------------------------------------------------
#
# Conversation 1 (Host=0x0A <-> BMC=0x08):
#
#  Edge cases:
#   F1:  ADM Response CSI=0  — ORPHAN: arrives before any request on this slot
#                               (simulates capture started mid-conversation)
#
#  All MI opcodes:
#   F2:  MI Req  CSI=0 opcode=0x00 (Read NVMe-MI Data Structure)
#   F3:  MI Resp CSI=0 status=0x00                           -> F2
#   F4:  MI Req  CSI=0 opcode=0x01 (NVM Subsystem Health Status Poll)
#   F5:  MI Resp CSI=0 status=0x00                           -> F4
#   F6:  MI Req  CSI=0 opcode=0x02 (Controller Health Status Poll)
#   F7:  MI Resp CSI=0 status=0x00                           -> F6
#   F8:  MI Req  CSI=0 opcode=0x03 (Configuration Set)
#   F9:  MI Resp CSI=0 status=0x00                           -> F8
#   F10: MI Req  CSI=0 opcode=0x04 (Configuration Get)
#   F11: MI Resp CSI=0 status=0x00                           -> F10
#
#  Admin opcodes, flags, CQE data, and response payload:
#   F12: ADM Req  CSI=0 opcode=0x02 (Get Log Page) ctrl_id=0x0002
#   F13: ADM Resp CSI=0 status=0x00 cqe1=0xDEAD0002          -> F12
#   F14: ADM Req  CSI=0 opcode=0x09 (Set Features) ctrl_id=0x0001 flags=DLEN
#   F15: ADM Resp CSI=0 status=0x00                           -> F14
#   F16: ADM Req  CSI=0 opcode=0x0a (Get Features) ctrl_id=0x0003 flags=DOFF|DLEN
#   F17: ADM Resp CSI=0 status=0x00 cqe1=0x5 + 16 data bytes -> F16
#
#  Multiple consecutive MPR before final response:
#   F18: MI Req  CSI=0 opcode=0x01 (Health Status Poll)
#   F19: MI Resp CSI=0 status=0x01 (MPR, 1st interim)        -> F18
#   F20: MI Resp CSI=0 status=0x01 (MPR, 2nd interim)        -> F18
#   F21: MI Resp CSI=0 status=0x00 (final)                   -> F18
#
#  Control primitive (type=0x0) — Pause exchange:
#   F22: CTL Req  CSI=0
#   F23: CTL Resp CSI=0                                       -> F22
#
#  PCIe command (type=0x4) — type recognized, no payload decoder yet:
#   F24: PCIe Req  CSI=0
#   F25: PCIe Resp CSI=0                                      -> F24
#
#  Unanswered requests (no response before end of capture):
#   F26: ADM Req  CSI=1 opcode=0x06 (Identify) — different slot, no response
#   F27: MI  Req  CSI=0 opcode=0x04 (Config Get) — no response
#
# Conversation 2 (Host=0x0A <-> BMC=0x09) — independent slot tracking:
#   F28: ADM Req  CSI=0 opcode=0x06 (Identify) ctrl_id=0x0001
#   F29: ADM Resp CSI=0 status=0x00                           -> F28
#
# Conversation isolation under interleaving:
#   Conv1 opens a new Admin request while Conv2 starts AND finishes completely:
#   F30: Conv1 ADM Req  CSI=0 opcode=0x06 ctrl_id=0x0004  [slot open, Conv1 pending]
#   F31: Conv2 ADM Req  CSI=0 opcode=0x06 ctrl_id=0x0002  [Conv2 opens, BMC=0x09]
#   F32: Conv2 ADM Resp CSI=0 status=0x00                  -> F31 [Conv2 closes]
#   F33: Conv1 ADM Resp CSI=0 status=0x00                  -> F30 [Conv1 closes]
#   F32 must NOT close Conv1's slot; F30 must show response_in=33 (not 32).
#
# Expected response_in (with tshark -2):
#   F2->3, F4->5, F6->7, F8->9, F10->11, F12->13, F14->15, F16->17,
#   F18->21, F22->23, F24->25, F26=none, F27=none, F28->29, F30->33, F31->32
#
# MPR flag present on: F19, F20 only.
# Orphan F1: no response_to field.

def _packets_comprehensive():
    p = []

    # F1: Orphan Admin response (no prior request on CSI=0 in this capture)
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS)))

    # F2-F11: All five MI command opcodes (request + success response each)
    for opcode in range(5):  # 0x00..0x04
        p.append(make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(opcode)))
        p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_SUCCESS)))

    # F12-F13: Admin Get Log Page, ctrl_id=0x0002, CQE1 carries a sentinel value
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x02, ctrl_id=0x0002)))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS, cqe1=0xDEAD0002)))

    # F14-F15: Admin Set Features, flags=DLEN only (0x01), ctrl_id=0x0001
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x09, ctrl_id=0x0001, flags=0x01)))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS)))

    # F16-F17: Admin Get Features, flags=DOFF|DLEN (0x03), ctrl_id=0x0003,
    #          response carries a non-zero CQE1 and 16 bytes of inline data
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x0a, ctrl_id=0x0003, flags=0x03)))
    resp_data = admin_response_payload(STATUS_SUCCESS, cqe1=0x00000005) + b'\xAB\xCD\xEF\x01' * 4
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, resp_data))

    # F18-F21: Health Status Poll with two MPR responses, then final success
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_MPR)))   # 1st MPR
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_MPR)))   # 2nd MPR
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_SUCCESS)))  # final

    # F22-F23: Control Primitive — Pause (opcode 0x00) on tag=0, CSI=0.
    # Pause CPSP is reserved (zero); Pause CPSR's low two bits are obsolete
    # "must be 1" for back-compat (NVMe-MI 2.1 §4.2.1.1) — encode 0x0003.
    p.append(make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                         cp_request_payload(CP_OPC_PAUSE, tag=0, cpsp=0x0000)))
    p.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                         cp_response_payload(STATUS_SUCCESS, tag=0, cpsr=0x0003)))

    # F24-F25: PCIe command (type=0x4) — no payload decoder in dissector
    p.append(make_packet(True,  NVME_MI_TYPE_PCIE, 0, b'\x00' * 8))
    p.append(make_packet(False, NVME_MI_TYPE_PCIE, 0, b'\x00' * 4))

    # F26: Admin Identify on CSI=1 — unanswered (no response before capture end)
    p.append(make_packet(True, NVME_MI_TYPE_ADMIN, 1,
                         admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01)))

    # F27: MI Config Get on CSI=0 — unanswered
    p.append(make_packet(True, NVME_MI_TYPE_MI, 0, mi_request_payload(0x04)))

    # F28-F29: Second MCTP conversation (BMC_EID=0x09) — independent slot tracking
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01),
                         bmc_eid=BMC_EID2))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS),
                         bmc_eid=BMC_EID2))

    # F30-F33: Conversation isolation under interleaving.
    # Conv1 opens a slot, then Conv2 (different EID) opens and fully closes
    # while Conv1's slot is still pending.  Conv2's response (F32) must not
    # close Conv1's slot; Conv1's response (F33) must still link back to F30.
    # F27 (previously the last Conv1 frame, MI Req on CSI=0) is superseded on
    # slot 0 when F30 arrives — this is intentional and tested separately.
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0004, cns=0x01)))
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0002, cns=0x01),
                         bmc_eid=BMC_EID2))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS),
                         bmc_eid=BMC_EID2))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS)))

    # F34-F40: MCTP tag isolation.
    #
    # Different MCTP tags produce different port values in the MCTP dissector
    # (srcport = tag_bits, destport = tag_bits ^ 0x08), so each tag has its own
    # Wireshark conversation and its own nvme_mi_conv_info with independent slots.
    #
    # Scenario: Admin command on tag=0 (F34) is pending.  While it waits for its
    # first interim response, a Control primitive on tag=1 (F35/F36) opens and
    # fully closes.  The tag=0 slot must survive undisturbed: it still receives
    # an MPR (F37) and then the final response (F38).  Separately, a plain Admin
    # exchange on tag=1 (F39/F40) confirms that tag=1's own slot tracking works.
    #
    # F34: [tag=0] Admin Req  CSI=0 opcode=0x06 ctrl_id=0x0005 — slot open
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0005, cns=0x01),
                         tag=0))
    # F35: [tag=1] CTL  Req   CSI=0 — Get State (opcode 0x03) with CESF=1
    #             (CPSP bit 0 — request clear of MES error-state bits)
    p.append(make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                         cp_request_payload(CP_OPC_GET_STATE, tag=1, cpsp=0x0001),
                         tag=1))
    # F36: [tag=1] CTL  Resp  CSI=0 -> F35 — MES sentinel: NSSRO=1 + SSTA=01b (Receive)
    p.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                         cp_response_payload(STATUS_SUCCESS, tag=1, cpsr=0x4001),
                         tag=1))
    # F37: [tag=0] Admin MPR  CSI=0 -> F34 — slot still open despite tag=1 activity
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_MPR), tag=0))
    # F38: [tag=0] Admin Resp CSI=0 -> F34 — final; tag=1 traffic was irrelevant
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS, cqe1=0x12345678),
                         tag=0))
    # F39: [tag=1] Admin Req  CSI=0 opcode=0x06 ctrl_id=0x0006 — tag=1 slot
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0006, cns=0x01),
                         tag=1))
    # F40: [tag=1] Admin Resp CSI=0 -> F39
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS, cqe1=0xCAFEBABE),
                         tag=1))

    # F41-F42: IC=1 (Message Integrity Check enabled) — MI Health Status Poll pair.
    # Exercises the mic_enabled code path in the dissector (lines that compute
    # CRC32C and call proto_tree_add_checksum with PROTO_CHECKSUM_VERIFY).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), ic=True))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_SUCCESS), ic=True))

    # F43-F44: MI request with non-zero CDW0 and CDW1 — exercises nvme-mi.mi.cdw0/cdw1
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x12345678, cdw1=0x9ABCDEF0)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_SUCCESS)))

    # F45-F46: MI response with trailing data bytes — exercises nvme-mi.mi.data on response
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x02)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       bytes([0xAA, 0xBB, 0xCC, 0xDD]))))

    # F47-F48: Admin request with DOFF-only flags (0x02) and non-zero doff value —
    #          exercises the DOFF-only flag combination and a non-zero nvme-mi.admin.doff
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01,
                                               flags=0x02, doff=0x2000, dlen=0)))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS)))

    # F49-F50: Admin response with only 4 bytes — exercises the tvb_reported_length < 16
    #          branch where CQE1/CQE2/CQE3 fields are absent
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x02, ctrl_id=0x0008)))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload_short(STATUS_SUCCESS)))

    # F51-F52: Admin command with non-success, non-MPR status (0x03 = Invalid Command Opcode)
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x09, ctrl_id=0x0001)))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(0x03)))

    # F53-F54: MI command with non-success, non-MPR status (0x06 = Invalid Command Input Data Size)
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(0x06)))

    # F55-F56: MI request with MEB bit set — exercises nvme-mi.meb
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x00), meb=True))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0, mi_response_payload(STATUS_SUCCESS)))

    # F57-F58: Control Primitive Abort (opcode 0x02) on tag=2.
    # Response CPSR carries CPAS=10b (Aborted after partial processing).
    p.append(make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                         cp_request_payload(CP_OPC_ABORT, tag=2, cpsp=0x0000),
                         tag=2))
    p.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                         cp_response_payload(STATUS_SUCCESS, tag=2, cpsr=0x0002),
                         tag=2))

    # F59-F60: Control Primitive Replay (opcode 0x04) on tag=3.
    # Request CPSP carries RRO=5; response CPSR carries RR=1 (replaying).
    p.append(make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                         cp_request_payload(CP_OPC_REPLAY, tag=3, cpsp=0x0005),
                         tag=3))
    p.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                         cp_response_payload(STATUS_SUCCESS, tag=3, cpsr=0x0001),
                         tag=3))

    # F61-F64: Control Primitive interleaved with an in-flight Admin command
    # on the SAME conversation (MCTP tag=0) and SAME slot (CSI=0).  This is the
    # normal use of Control Primitives (NVMe-MI 2.1 §4.2.1): they are processed
    # out-of-band while a command occupies the slot.  The CP exchange must pair
    # F62<->F63 without displacing the pending Admin transaction, which still
    # pairs F61<->F64.  The Get State response reports SSTA=10b (Process) —
    # exactly what an endpoint would say while crunching the Admin command.
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x02, ctrl_id=0x0009)))
    p.append(make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                         cp_request_payload(CP_OPC_GET_STATE, tag=5, cpsp=0x0000)))
    p.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                         cp_response_payload(STATUS_SUCCESS, tag=5, cpsr=0x0002)))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS, cqe1=0xFEED0009)))

    # ------------------------------------------------------------------
    # F65-F72: malformed-frame fixtures.  The dissector must flag each with
    # expert info, render leftover bytes as raw data, and keep the slot
    # tracking intact — it must never throw mid-tree.
    # ------------------------------------------------------------------

    # F65-F66: truncated (2-byte) Control Primitive request on MCTP tag=4,
    # followed by a complete response.  The dissector cannot record opcode or
    # CP tag from the truncated request, so the response must keep its
    # request/response link but not fabricate a generated opcode or a
    # spurious tag-mismatch warning.
    p.append(make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                         struct.pack('<BB', CP_OPC_GET_STATE, 9),
                         tag=4))
    p.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                         cp_response_payload(STATUS_SUCCESS, tag=9, cpsr=0x4001),
                         tag=4))

    # F67-F68: truncated (8-byte) Admin request followed by a complete
    # response.  The opcode (first payload byte) is still parseable and must
    # be recorded and propagated to the response.
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x000A, cns=0x01)[:8]))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS, cqe1=0x0BAD0001)))

    # F69: IC bit set, but the frame is too short to contain a 4-byte MIC
    # (only 2 payload bytes, no MIC appended).  The dissector must flag the
    # bogus IC claim, keep the 2 bytes as payload, and skip MIC verification.
    p.append(sll_header(HOST_EID, outgoing=True)
             + mctp_header(True)
             + nvme_mi_header(NVME_MI_TYPE_MI, 0, is_response=False, ic=True)
             + bytes([0x01, 0x00]))

    # F70-F72: 1-byte MI MPR interim response.  The status byte alone (per
    # the spec the framing layer needs only payload byte 0) must keep the
    # command slot open so the final response still links to the request.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 1, mi_request_payload(0x02)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 1, bytes([STATUS_MPR])))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 1, mi_response_payload(STATUS_SUCCESS)))

    assert len(p) == 72, f"Expected 72 frames, got {len(p)}"
    return p

packets_comprehensive = _packets_comprehensive()

# Timestamps: 1-second intervals starting at 2024-02-01 10:00:00 UTC
BASE_TS_TYPES_US = 1706781600 * 1_000_000

def build_comprehensive_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_comprehensive):
        ts = BASE_TS_TYPES_US + i * 1_000_000
        data += epb(pkt, ts)

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"Written {len(packets_comprehensive)} packets to {output_path}")
    print()
    print("Packet summary:")
    descs = [
        "F1:  ADM Resp  CSI=0  ORPHAN (no prior request — simulates mid-capture start)",
        "F2:  MI  Req   CSI=0  opcode=0x00 (Read NVMe-MI Data Structure)",
        "F3:  MI  Resp  CSI=0  status=0x00 -> F2",
        "F4:  MI  Req   CSI=0  opcode=0x01 (NVM Subsystem Health Status Poll)",
        "F5:  MI  Resp  CSI=0  status=0x00 -> F4",
        "F6:  MI  Req   CSI=0  opcode=0x02 (Controller Health Status Poll)",
        "F7:  MI  Resp  CSI=0  status=0x00 -> F6",
        "F8:  MI  Req   CSI=0  opcode=0x03 (Configuration Set)",
        "F9:  MI  Resp  CSI=0  status=0x00 -> F8",
        "F10: MI  Req   CSI=0  opcode=0x04 (Configuration Get)",
        "F11: MI  Resp  CSI=0  status=0x00 -> F10",
        "F12: ADM Req   CSI=0  opcode=0x02 (Get Log Page) ctrl_id=0x0002",
        "F13: ADM Resp  CSI=0  status=0x00 cqe1=0xDEAD0002 -> F12",
        "F14: ADM Req   CSI=0  opcode=0x09 (Set Features) flags=DLEN ctrl_id=0x0001",
        "F15: ADM Resp  CSI=0  status=0x00 -> F14",
        "F16: ADM Req   CSI=0  opcode=0x0a (Get Features) flags=DOFF|DLEN ctrl_id=0x0003",
        "F17: ADM Resp  CSI=0  status=0x00 cqe1=0x5 + 16 data bytes -> F16",
        "F18: MI  Req   CSI=0  opcode=0x01 (Health Status Poll) [will get 2 MPRs]",
        "F19: MI  Resp  CSI=0  status=0x01 (MPR, 1st interim) -> F18",
        "F20: MI  Resp  CSI=0  status=0x01 (MPR, 2nd interim) -> F18",
        "F21: MI  Resp  CSI=0  status=0x00 (final) -> F18",
        "F22: CTL Req   CSI=0  CP=Pause (0x00) tag=0",
        "F23: CTL Resp  CSI=0  CPSR=0x0003 (Pause obsolete bits) -> F22",
        "F24: PCIe Req  CSI=0  (PCIe command, type=0x4)",
        "F25: PCIe Resp CSI=0  -> F24",
        "F26: ADM Req   CSI=1  opcode=0x06 (Identify) — UNANSWERED",
        "F27: MI  Req   CSI=0  opcode=0x04 (Config Get) — UNANSWERED",
        "F28: ADM Req   CSI=0  opcode=0x06 (Identify) [BMC_EID=0x09, Conv2]",
        "F29: ADM Resp  CSI=0  status=0x00 -> F28 [BMC_EID=0x09, Conv2]",
        "F30: ADM Req   CSI=0  opcode=0x06 ctrl_id=0x0004 [Conv1 slot open]",
        "F31: ADM Req   CSI=0  opcode=0x06 ctrl_id=0x0002 [Conv2, BMC=0x09, interleaved]",
        "F32: ADM Resp  CSI=0  status=0x00 -> F31 [Conv2 closes while Conv1 pending]",
        "F33: ADM Resp  CSI=0  status=0x00 -> F30 [Conv1 closes, isolation verified]",
        "F34: ADM Req   CSI=0  opcode=0x06 ctrl_id=0x0005 [tag=0, slot open]",
        "F35: CTL Req   CSI=0  CP=Get State (0x03) CESF=1 [tag=1, separate conversation]",
        "F36: CTL Resp  CSI=0  MES=0x4001 (NSSRO=1, SSTA=Receive) -> F35 [tag=1 closes while tag=0 pending]",
        "F37: ADM MPR   CSI=0  -> F34 [tag=0 slot survived tag=1 activity]",
        "F38: ADM Resp  CSI=0  -> F34 [tag=0 final cqe1=0x12345678]",
        "F39: ADM Req   CSI=0  opcode=0x06 ctrl_id=0x0006 [tag=1 independent slot]",
        "F40: ADM Resp  CSI=0  -> F39 [tag=1 cqe1=0xCAFEBABE]",
        "F41: MI  Req   CSI=0  opcode=0x01 IC=1 [MIC-enabled, exercises CRC32C path]",
        "F42: MI  Resp  CSI=0  status=0x00 IC=1 -> F41 [MIC-enabled response]",
        "F43: MI  Req   CSI=0  opcode=0x00 CDW0=0x12345678 CDW1=0x9ABCDEF0",
        "F44: MI  Resp  CSI=0  status=0x00 -> F43",
        "F45: MI  Req   CSI=0  opcode=0x02",
        "F46: MI  Resp  CSI=0  status=0x00 + 4 data bytes -> F45",
        "F47: ADM Req   CSI=0  opcode=0x06 flags=DOFF-only doff=0x2000 ctrl_id=0x0007",
        "F48: ADM Resp  CSI=0  status=0x00 -> F47",
        "F49: ADM Req   CSI=0  opcode=0x02 ctrl_id=0x0008",
        "F50: ADM Resp  CSI=0  4-byte short (no CQE fields) -> F49",
        "F51: ADM Req   CSI=0  opcode=0x09 ctrl_id=0x0001",
        "F52: ADM Resp  CSI=0  status=0x03 (Invalid Command Opcode) -> F51",
        "F53: MI  Req   CSI=0  opcode=0x01",
        "F54: MI  Resp  CSI=0  status=0x06 (Invalid Command Input Data Size) -> F53",
        "F55: MI  Req   CSI=0  opcode=0x00 MEB=1",
        "F56: MI  Resp  CSI=0  status=0x00 -> F55",
        "F57: CTL Req   CSI=0  CP=Abort (0x02) [tag=2]",
        "F58: CTL Resp  CSI=0  CPSR=0x0002 (CPAS=partial abort) -> F57 [tag=2]",
        "F59: CTL Req   CSI=0  CP=Replay (0x04) CPSP RRO=5 [tag=3]",
        "F60: CTL Resp  CSI=0  CPSR=0x0001 (RR=1) -> F59 [tag=3]",
        "F61: ADM Req   CSI=0  opcode=0x02 (Get Log Page) ctrl_id=0x0009 [slot open]",
        "F62: CTL Req   CSI=0  CP=Get State (0x03) [tag=0, same slot as F61 — out-of-band]",
        "F63: CTL Resp  CSI=0  MES=0x0002 (SSTA=Process) -> F62 [Admin still pending]",
        "F64: ADM Resp  CSI=0  status=0x00 cqe1=0xFEED0009 -> F61 [slot survived the CP]",
        "F65: CTL Req   CSI=0  TRUNCATED (2 bytes) [tag=4 — opcode/tag not recordable]",
        "F66: CTL Resp  CSI=0  status=0x00 tag=9 -> F65 [no fabricated opcode/tag check]",
        "F67: ADM Req   CSI=0  TRUNCATED (8 bytes) opcode=0x06 [opcode still recorded]",
        "F68: ADM Resp  CSI=0  status=0x00 cqe1=0x0BAD0001 -> F67",
        "F69: MI  Req   CSI=0  IC=1 but NO ROOM FOR MIC (2 payload bytes) — UNANSWERED",
        "F70: MI  Req   CSI=1  opcode=0x02",
        "F71: MI  Resp  CSI=1  1-BYTE MPR interim -> F70 [slot must stay open]",
        "F72: MI  Resp  CSI=1  status=0x00 (final) -> F70",
    ]
    for d in descs:
        print(f"  {d}")
    print()
    print("Expected request/response links (with tshark -2):")
    print("  Requests with response_in: F2->3, F4->5, F6->7, F8->9, F10->11,")
    print("                             F12->13, F14->15, F16->17, F18->21,")
    print("                             F22->23, F24->25, F28->29, F30->33, F31->32,")
    print("                             F34->38, F35->36, F39->40, F41->42,")
    print("                             F57->58, F59->60, F61->64, F62->63,")
    print("                             F65->66, F67->68, F70->72")
    print("  Requests without response_in: F26 (unanswered CSI=1), F27 (unanswered CSI=0),")
    print("                                F69 (unanswered, IC-truncated)")
    print("  Responses with response_to:  F3->2, F5->4, F7->6, F9->8, F11->10,")
    print("                               F13->12, F15->14, F17->16,")
    print("                               F19->18 (MPR), F20->18 (MPR), F21->18,")
    print("                               F23->22, F25->24, F29->28, F32->31, F33->30,")
    print("                               F36->35, F37->34 (MPR), F38->34, F40->39, F42->41,")
    print("                               F58->57, F60->59, F63->62, F64->61,")
    print("                               F66->65, F68->67, F71->70 (MPR), F72->70")
    print("  Orphan with no response_to: F1")
    print("  MPR flag set on: F19, F20, F37, F71")


if __name__ == '__main__':
    captures_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'test', 'captures')

    # nvme-mi-req-resp.pcapng — 7-frame MPR/slot regression capture
    out1 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        captures_dir, 'nvme-mi-req-resp.pcapng')
    build_pcapng(out1)
    print()

    # nvme-mi-types.pcapng — comprehensive coverage capture (frame count is
    # asserted in _packets_comprehensive)
    out2 = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        captures_dir, 'nvme-mi-types.pcapng')
    build_comprehensive_pcapng(out2)
