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

nvme-mi-types.pcapng  (103 frames)
  Comprehensive coverage across all NVMe-MI message types and edge cases:
  - Orphan response (response before any request on that slot; simulates capture
    started mid-conversation — the dissector must not crash or mislink)
  - MI opcodes 0x00-0x07 and 0x0C with realistic command dwords and response
    payloads (Port/Subsystem Information, Controller List, command lists,
    NSHDS, CHDS entries, Configuration Set/Get per-CONFIGID fields,
    VPD Read/Write, Reset, Shutdown)
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
    * Sliced MPR interim response (caplen cut right after the NVMe-MI
      header): the status byte is unverifiable, so the framing layer must
      leave the slot open rather than mislink the request to the interim

Wire format layers (outer to inner):
  Linux SLL cooked capture header (16 bytes, DLT=113)
  MCTP transport header            (4 bytes)
  NVMe-MI header                   (4 bytes; byte 0 = MCTP type 0x04)
  NVMe-MI payload                  (variable)
"""

import os
import struct
import sys

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

def epb(packet_bytes, ts_us, origlen=None):
    """Enhanced Packet Block with microsecond timestamp.  Passing an origlen
    larger than len(packet_bytes) produces a sliced frame (snaplen cut)."""
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  =  ts_us & 0xFFFFFFFF
    caplen = len(packet_bytes)
    if origlen is None:
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
NVME_MI_TYPE_AEM      = 0x5   # Asynchronous Event Message (Figure 20)
NVME_MI_TYPE_RESERVED = 0x3   # 3h and 6h-Fh are Reserved (Figure 20)

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

def mi_response_payload(status, nmresp=0):
    """MI command response: status(1) + nmresp(3) = 4 bytes."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3]

def mi_response_payload_with_data(status, data, nmresp=0):
    """MI command response with trailing data bytes (exercises nvme-mi.mi.data)."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3] + data

# ---------------------------------------------------------------------------
# MI command response data structures (NVMe-MI 2.1 §5)
# ---------------------------------------------------------------------------

def port_info_pcie():
    """Port Information data structure (Figure 114) with PCIe-specific data
    (Figure 115), 32 bytes."""
    return (bytes([
        0x01,                       # PRTTYP = PCIe
        0x03,                       # PRTCAP = AEMS | CIAPS
    ]) + struct.pack('<H', 64)      # MMTUS = 64 bytes
       + struct.pack('<I', 0x1000)  # MEBS = 4096 bytes
       + bytes([
        0x01,                       # PCIEMPS = 256 bytes
        0x0F,                       # PCIESLSV = 2.5/5.0/8.0/16.0 GT/s
        0x04,                       # PCIECLS = 16.0 GT/s
        0x08,                       # PCIEMLW = x8
        0x04,                       # PCIENLW = x4
        0x00,                       # PCIEPN = 0
    ]) + b'\x00' * 18)              # reserved to 32 bytes

def port_info_twire():
    """Port Information data structure with 2-Wire-specific data
    (Figure 116), 32 bytes."""
    return (bytes([
        0x02,                       # PRTTYP = 2-Wire
        0x01,                       # PRTCAP = CIAPS
    ]) + struct.pack('<H', 64)      # MMTUS = 64 bytes
       + struct.pack('<I', 0)       # MEBS = 0 (no MEB)
       + bytes([
        0x53,                       # CVPDADDR
        0x02,                       # MVPDFREQ = 400 kHz
        0x1D,                       # CMEADDR
        0x82,                       # TWPRT = I3CSPRT | MSMBFREQ=400 kHz
        0x00,                       # NVMEBM = no basic management
    ]) + b'\x00' * 19)              # reserved to 32 bytes

def subsys_info():
    """NVM Subsystem Information data structure (Figure 112), 32 bytes."""
    return bytes([
        0x01,                       # NUMP = 1 (0's based -> 2 ports)
        0x02,                       # MJR = 2
        0x01,                       # MNR = 1 (NVMe-MI 2.1)
        0x01,                       # NNSC = SRE
    ]) + b'\x00' * 28               # reserved to 32 bytes

def nshds():
    """NVM Subsystem Health Data Structure (Figure 108), 8 bytes."""
    return (bytes([
        0x38,                       # NSS = DF | RNR | P0LA
        0xFF,                       # SW (all-healthy: inverted CW field)
        0x2D,                       # CTEMP = 45 C
        0x05,                       # PDLU = 5 %
    ]) + struct.pack('<H', 0x0211)  # CCS = CTEMP | NSSRO | RDY
       + b'\x00' * 2)               # reserved

def chds(ctlid, csts, ctemp, pdlu, spare, cwarn, chsc):
    """One Controller Health Data Structure (Figure 97), 16 bytes."""
    return struct.pack('<HHHBBBH', ctlid, csts, ctemp, pdlu, spare,
                       cwarn, chsc) + b'\x00' * 5

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

def admin_request_payload(opcode, ctrl_id=0x0000, cns=0x00, flags=0x01, doff=0, dlen=0x1000,
                          cdw11=0, cdw14=0, lpo=0):
    """Admin request SQE (64 bytes).

    flags byte:
      bit 0 (0x1) = DLEN: use data length field
      bit 1 (0x2) = DOFF: use data offset field

    cns is CDW10 (named for the Identify CNS selector, the original use); cdw11
    and cdw14 fill the command dwords that the other opcode decoders read
    (e.g. Firmware Image Download OFST, Sanitize Overwrite Pattern, Lockdown
    UUID Index).  lpo is the Get Log Page Log Page Offset (CDW12/13, NVMe
    Base 2.3 Figure 203/204) -- byte offset into the log page applied by the
    controller *before* DOFST/DLEN slice the NVMe-MI response (NVMe-MI 2.1
    Figure 139/140); combined with a nonzero doff to test that both layers
    are added together by dissect_nvme_get_logpage_resp().
    """
    payload  = bytes([opcode, flags]) + struct.pack('<H', ctrl_id)
    payload += b'\x00' * 20          # SQE1-SQE5
    payload += struct.pack('<I', doff)  # data offset
    payload += struct.pack('<I', dlen)  # data length
    payload += b'\x00' * 8           # reserved
    payload += struct.pack('<I', cns)    # CDW10 (CNS / identify selector)
    payload += struct.pack('<I', cdw11)  # CDW11
    payload += struct.pack('<Q', lpo)    # CDW12-CDW13 (Log Page Offset)
    payload += struct.pack('<I', cdw14)  # CDW14
    payload += b'\x00' * 4           # CDW15
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

def cqe_status_word(sct=0, sc=0, m=0, dnr=0, phase=0, crd=0):
    """Build the 16-bit NVMe completion Status Field (upper half of CQE DW3):
    Phase(0) | SC(8:1) | SCT(11:9) | CRD(13:12) | More(14) | DoNotRetry(15)."""
    return ((phase & 0x1) | ((sc & 0xff) << 1) | ((sct & 0x7) << 9)
            | ((crd & 0x3) << 12) | ((m & 0x1) << 14) | ((dnr & 0x1) << 15))

def admin_cqe3(status_word, cid=0):
    """CQE DW3 = Command Identifier (low 16) + Status Field word (high 16).
    Over NVMe-MI the CID half is meaningless but the status half is decoded."""
    return ((status_word & 0xffff) << 16) | (cid & 0xffff)

def admin_resp_with_data(data, status=STATUS_SUCCESS):
    """Admin success response: 16-byte status+CQE block then inline data."""
    cqe3 = admin_cqe3(cqe_status_word(phase=1))
    return admin_response_payload(status, cqe1=0, cqe3=cqe3) + data

def make_packet(is_request, msg_type, csi, payload,
                host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0, ic=False, meb=False):
    src_eid  = host_eid if is_request else bmc_eid
    sll      = sll_header(src_eid, outgoing=is_request)
    mctp     = mctp_header(is_request, host_eid=host_eid, bmc_eid=bmc_eid, tag=tag)
    nvme_hdr = nvme_mi_header(msg_type, csi, is_response=not is_request, ic=ic, meb=meb)
    if ic:
        protected = nvme_hdr + payload
        # The MIC is little-endian on the wire, like every NVMe-MI field
        # (libnvme: cpu_to_le32 on transmit, le32_to_cpu on verify).
        mic_bytes = struct.pack('<I', crc32c(protected))
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
    # with realistic command dwords and response payloads (MR3 field decode).

    # F2-F3: Read NVMe-MI Data Structure, DTYP=01h (Port Information).
    # Response carries RDL=32 in NMRESP and a PCIe Port Information structure.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x01000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       port_info_pcie(),
                                                       nmresp=32)))

    # F4-F5: NVM Subsystem Health Status Poll with CS=1 (clear status).
    # Response data is the 8-byte NVM Subsystem Health Data Structure.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x01, cdw1=0x80000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       nshds())))

    # F6-F7: Controller Health Status Poll: ALL=1, MAXRENT=1 (0's based -> 2),
    # CCF=1 + CSTS selection.  Response: RENT=2 + two CHDS entries.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x02, cdw0=0x80010000,
                                            cdw1=0x80000001)))
    chds_pair = (chds(1, 0x0001, 0x0136, 3, 100, 0x00, 0x0001)
                 + chds(2, 0x0083, 0x0140, 7, 0x5A, 0x02, 0x1002))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       chds_pair,
                                                       nmresp=0x020000)))

    # F8-F9: Configuration Set, CID=03h (MCTP Transmission Unit Size),
    # PORTID=1, MTUS=128.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x03, cdw0=0x01000003,
                                            cdw1=0x00000080)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F10-F11: Configuration Get, CID=03h, PORTID=1.  Response NMRESP
    # carries the current MTUS (64).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x01000003)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS, nmresp=64)))

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

    # F27: MI Config Get (CID=02h Health Status Change) on CSI=0 — unanswered
    p.append(make_packet(True, NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x00000002)))

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

    # ------------------------------------------------------------------
    # F73-F90: MI command per-opcode decode fixtures (MR3) — one exchange
    # per Read NVMe-MI Data Structure DTYP and Configuration Identifier
    # not already covered by F2-F11.
    # ------------------------------------------------------------------

    # F73-F74: Read DS, DTYP=00h (NVM Subsystem Information)
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x00000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       subsys_info(),
                                                       nmresp=32)))

    # F75-F76: Read DS, DTYP=02h (Controller List): 3 IDs (1, 2, 5)
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x02000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       struct.pack('<HHHH',
                                                                   3, 1, 2, 5),
                                                       nmresp=8)))

    # F77-F78: Read DS, DTYP=04h (Optionally Supported Command List),
    # CTRLID=1, IOCSI=0.  Two entries: MI VPD Read (0x05) and Admin
    # Device Self-test (0x14).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x04000001)))
    osc_list = struct.pack('<H', 2) + bytes([0x08, 0x05, 0x10, 0x14])
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       osc_list, nmresp=6)))

    # F79-F80: Read DS, DTYP=01h (Port Information) for PORTID=1, which is
    # a 2-Wire port (exercises the 2-Wire port-specific decode).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x01010000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       port_info_twire(),
                                                       nmresp=32)))

    # F81-F82: Configuration Get, CID=01h (SMBus/I2C Frequency), PORTID=0.
    # Response NMRESP carries SFREQ=2 (400 kHz).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x00000001)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS, nmresp=0x000002)))

    # F83-F84: Configuration Set, CID=02h (Health Status Change): clear
    # CWARN + CTEMP + RDY (NMD1 = 0x0901).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x03, cdw0=0x00000002,
                                            cdw1=0x00000901)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F85-F86: Configuration Set, CID=01h (SMBus/I2C Frequency): SFREQ=3
    # (1 MHz) on PORTID=0.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x03, cdw0=0x00000301)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F87-F88: Configuration Get with a reserved CID (0x50) — must fire the
    # reserved-configid expert; endpoint rejects with Invalid Parameter.
    # The error response carries a Parameter Error Location pointing at the
    # offending CONFIGID byte: bit 2 of message byte 8 (NMD0 byte 0), i.e.
    # PEL bit=2 (payload byte 1) and byte offset=8 (payload bytes 3:2 LE)
    # -> NMRESP bytes 0x02, 0x08, 0x00 = nmresp 0x000802.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x00000050)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(0x04, nmresp=0x000802)))

    # F89-F90: Read DS, DTYP=03h (Controller Information) for CTRLID=1.
    ctrl_info = (bytes([0x00])                      # PORTID
                 + b'\x00' * 4                      # reserved
                 + bytes([0x01])                    # PRII = PCIERIV
                 + struct.pack('<H', 0x1219)        # PRI: bus 0x12 dev 3 fn 1
                 + struct.pack('<HHHH', 0x144D, 0xA808, 0x144D, 0xA801)
                 + bytes([0x00])                    # PCIESN
                 + b'\x00' * 15)                    # reserved to 32 bytes
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x00, cdw0=0x03000001)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       ctrl_info, nmresp=32)))

    # ------------------------------------------------------------------
    # F91-F100: MI command per-opcode decode fixtures (MR3b) — opcodes
    # 05h-07h and 0Ch (VPD Read/Write, Reset, Shutdown).
    # ------------------------------------------------------------------

    # F91-F92: VPD Read, DOFST=0, DLEN=8.  Response returns 8 VPD bytes
    # (no Response Data Length in the NMRESP for VPD Read).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x05, cdw0=0x0000, cdw1=0x0008)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(
                             STATUS_SUCCESS,
                             bytes([0x4E, 0x56, 0x4D, 0x65,
                                    0x01, 0x02, 0x03, 0x04]))))

    # F93-F94: VPD Write, DOFST=0x10, DLEN=4, with 4 Request Data bytes.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x06, cdw0=0x0010, cdw1=0x0004)
                         + bytes([0xDE, 0xAD, 0xBE, 0xEF])))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F95-F96: Reset, RSTTYP=00h (Reset NVM Subsystem).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x07, cdw0=0x00000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F97-F98: Shutdown, SHDNTYP=01h (Abrupt NVM Subsystem Shutdown).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x0C, cdw0=0x01000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F99-F100: Reset with a reserved RSTTYP=02h — must fire the
    # reserved-value expert.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x07, cdw0=0x02000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F101-F103: sliced MPR interim response.  F102 is an MPR interim whose
    # capture was cut right after the 4-byte NVMe-MI header (caplen 24 of 28),
    # so the status byte exists in the reported length but not in the captured
    # bytes.  The framing layer cannot tell interim from final and must leave
    # the slot open (treating the response like an interim one) so the real
    # final response (F103) still links to the request — closing the slot on
    # the unverifiable status would silently mislink F101 to F102.
    p.append(make_packet(True, NVME_MI_TYPE_MI, 0, mi_request_payload(0x01)))
    full = make_packet(False, NVME_MI_TYPE_MI, 0,
                       mi_response_payload(STATUS_MPR))
    p.append((full[:24], len(full)))   # SLL(16) + MCTP(4) + NVMe-MI header(4)
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F104-F105: Configuration Set of the Asynchronous Event configuration
    # (CONFIGID=04h in NMD0 bits 7:0).  The request carries an AE Enable List
    # (Figures 92/93) as Request Data: two AE Enable entries — Composite
    # Temperature (ID 06h) enabled, SMART Warnings (ID 09h) disabled.
    ae_list = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])  # NUMAEE=2, ver=0, AEETL=11, AEELHL=5
               + bytes([3]) + struct.pack('<H', 0x8006)            # AEE=1, ID=06h
               + bytes([3]) + struct.pack('<H', 0x0009))           # AEE=0, ID=09h
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x03, cdw0=0x00000004) + ae_list))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    assert len(p) == 105, f"Expected 105 frames, got {len(p)}"
    return p

packets_comprehensive = _packets_comprehensive()

# Timestamps: 1-second intervals starting at 2024-02-01 10:00:00 UTC
BASE_TS_TYPES_US = 1706781600 * 1_000_000

def build_comprehensive_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_comprehensive):
        ts = BASE_TS_TYPES_US + i * 1_000_000
        if isinstance(pkt, tuple):       # (sliced bytes, original length)
            data += epb(pkt[0], ts, origlen=pkt[1])
        else:
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
        "F73: MI  Req   CSI=0  Read DS DTYP=00h (NVM Subsystem Information)",
        "F74: MI  Resp  CSI=0  RDL=32 + NVM Subsystem Information -> F73",
        "F75: MI  Req   CSI=0  Read DS DTYP=02h (Controller List)",
        "F76: MI  Resp  CSI=0  RDL=8 + Controller List (1, 2, 5) -> F75",
        "F77: MI  Req   CSI=0  Read DS DTYP=04h (Opt Supported Cmd List) CTRLID=1",
        "F78: MI  Resp  CSI=0  RDL=6 + 2 command entries -> F77",
        "F79: MI  Req   CSI=0  Read DS DTYP=01h (Port Information) PORTID=1",
        "F80: MI  Resp  CSI=0  RDL=32 + 2-Wire Port Information -> F79",
        "F81: MI  Req   CSI=0  Config Get CID=01h (SMBus/I2C Frequency)",
        "F82: MI  Resp  CSI=0  NMRESP SFREQ=400 kHz -> F81",
        "F83: MI  Req   CSI=0  Config Set CID=02h (Health Status Change) clear=0x0901",
        "F84: MI  Resp  CSI=0  status=0x00 -> F83",
        "F85: MI  Req   CSI=0  Config Set CID=01h (SMBus/I2C Frequency) SFREQ=1 MHz",
        "F86: MI  Resp  CSI=0  status=0x00 -> F85",
        "F87: MI  Req   CSI=0  Config Get CID=0x50 (RESERVED — expert expected)",
        "F88: MI  Resp  CSI=0  status=0x04 (Invalid Parameter) PEL bit=2 byte=8 -> F87",
        "F89: MI  Req   CSI=0  Read DS DTYP=03h (Controller Information) CTRLID=1",
        "F90: MI  Resp  CSI=0  RDL=32 + Controller Information -> F89",
        "F91: MI  Req   CSI=0  VPD Read DOFST=0 DLEN=8",
        "F92: MI  Resp  CSI=0  8 VPD data bytes -> F91",
        "F93: MI  Req   CSI=0  VPD Write DOFST=0x10 DLEN=4 + 4 data bytes",
        "F94: MI  Resp  CSI=0  status=0x00 -> F93",
        "F95: MI  Req   CSI=0  Reset RSTTYP=00h (Reset NVM Subsystem)",
        "F96: MI  Resp  CSI=0  status=0x00 -> F95",
        "F97: MI  Req   CSI=0  Shutdown SHDNTYP=01h (Abrupt)",
        "F98: MI  Resp  CSI=0  status=0x00 -> F97",
        "F99: MI  Req   CSI=0  Reset RSTTYP=02h (RESERVED — expert expected)",
        "F100: MI Resp  CSI=0  status=0x00 -> F99",
        "F101: MI Req   CSI=0  opcode=0x01 (Health Status Poll)",
        "F102: MI Resp  CSI=0  SLICED MPR (caplen 24/28, status byte missing) -> F101",
        "F103: MI Resp  CSI=0  status=0x00 (final) -> F101 [slot survived the sliced MPR]",
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
    print("                             F65->66, F67->68, F70->72, F101->103,")
    print("                             F73->74 ... F89->90 (sequential pairs)")
    print("  Requests without response_in: F26 (unanswered CSI=1), F27 (unanswered CSI=0),")
    print("                                F69 (unanswered, IC-truncated)")
    print("  Responses with response_to:  F3->2, F5->4, F7->6, F9->8, F11->10,")
    print("                               F13->12, F15->14, F17->16,")
    print("                               F19->18 (MPR), F20->18 (MPR), F21->18,")
    print("                               F23->22, F25->24, F29->28, F32->31, F33->30,")
    print("                               F36->35, F37->34 (MPR), F38->34, F40->39, F42->41,")
    print("                               F58->57, F60->59, F63->62, F64->61,")
    print("                               F66->65, F68->67, F71->70 (MPR), F72->70,")
    print("                               F102->101 (sliced), F103->101,")
    print("                               F74->73 ... F90->89 (sequential pairs)")
    print("  Orphan with no response_to: F1")
    print("  MPR flag set on: F19, F20, F37, F71 (not F102 — status unverifiable)")
    print("  Superseded-request expert on: F30, F70, F73")


# ---------------------------------------------------------------------------
# nvme-mi-admin-decode.pcapng — Admin SQE CDW10-15 shared-decode coverage (MR4)
# ---------------------------------------------------------------------------
#
# Standalone admin-request capture exercising nvme_dissect_admin_sqe_cdws()
# (shared with packet-nvme.c) under the NVMe-MI Admin dissector, plus the
# prohibited-opcode expert.  Each request rides its own MCTP tag so no two
# share a command slot (keeps every request independent; no superseded-slot
# noise).  Responses are omitted: MR4 decodes only the request side.
#
#   F1   Identify (06h)        CDW10 CNS=01h Identify Controller, CNTID=0
#   F2   Get Log Page (02h)    CDW10 LID=02h SMART
#   F3   Set Features (09h)    CDW10 FID=02h Power Management
#   F4   Get Features (0Ah)    CDW10 FID=04h Temperature Threshold
#   F5   Format NVM (80h)      CDW10=0x351 LBAFL=1 MSET=1 PI=2 PIL=1 SES=1
#   F6   Firmware Commit (10h) CDW10=0x19 FS=1 CA=3 (replace+activate now)
#   F7   FW Img Download (11h) CDW10 NUMD=0xFF, CDW11 OFST=0x100
#   F8   Device Self-test (14h)CDW10 STC=2 (extended)
#   F9   Lockdown (24h)        CDW10=0x950 SCP=0 PRHBT=1 IFC=2 OFI=09h; CDW14 UIDX=1
#   F10  Sanitize (84h)        CDW10=0x20a SANACT=2 AUSE=1 NDAS=1; CDW11 OVRPAT
#   F11  Abort (08h)           Prohibited over MI -> prohibited-opcode expert

packets_admin_decode = [
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01), tag=0),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x02, ctrl_id=0x0002, cns=0x02), tag=1),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x09, ctrl_id=0x0003, cns=0x02), tag=2),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x0a, ctrl_id=0x0004, cns=0x04), tag=3),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x80, ctrl_id=0x0005, cns=0x351), tag=4),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x10, ctrl_id=0x0006, cns=0x19), tag=5),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x11, ctrl_id=0x0007, cns=0xFF, cdw11=0x100), tag=6),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x14, ctrl_id=0x0008, cns=0x02), tag=7),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x24, ctrl_id=0x0009, cns=0x950, cdw14=0x1), tag=8),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x84, ctrl_id=0x000a, cns=0x20a, cdw11=0xDEADBEEF), tag=9),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x08, ctrl_id=0x000b), tag=10),
]

# Timestamps: 1-second intervals starting at 2024-03-01 10:00:00 UTC
BASE_TS_ADMIN_US = 1709287200 * 1_000_000

def build_admin_decode_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_decode):
        data += epb(pkt, BASE_TS_ADMIN_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_decode)} packets to {output_path}")

# ---------------------------------------------------------------------------
# nvme-mi-admin-resp.pcapng — Admin response status + CQE DW0 decode (MR5)
# ---------------------------------------------------------------------------
#
# Paired request/response exchanges exercising the response-side decode shared
# with packet-nvme.c: the opcode-specific CQE Dword 0 (nvme_dissect_admin_cqe_dw0)
# and the NVMe status word SCT/SC/M/DNR (nvme_dissect_cqe_status).  Each request
# opens the CSI=0 command slot and its response closes it before the next pair,
# so every response recovers its request's opcode/FID from body_ctx.  Request
# and response share an MCTP tag (TO bit distinguishes direction).
#
#   F1/F2  Get Features (0Ah) FID=04h Temperature Threshold
#          -> DW0 TMPTH/TMPSEL/THPSEL; status Success
#   F3/F4  Set Features (09h) FID=07h Number of Queues (success)
#          -> DW0 NSQA/NCQA; status Success
#   F5/F6  Set Features (09h) FID=02h Power Management (failed command)
#          -> DW0 Set-Features error code; status SCT=1 SC=0Eh DNR=1
#   F7/F8  Identify (06h) (success) -> generic DW0; status More + DNR bits

packets_admin_resp = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x0a, ctrl_id=0x0001, cns=0x04), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0012014B,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=0),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x09, ctrl_id=0x0002, cns=0x07), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x00070003,
                                       cqe3=admin_cqe3(cqe_status_word())), tag=1),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x09, ctrl_id=0x0003, cns=0x02), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0000000E,
                                       cqe3=admin_cqe3(cqe_status_word(sct=1, sc=0x0e, dnr=1))),
                tag=2),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0004, cns=0x01), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xCAFEBABE,
                                       cqe3=admin_cqe3(cqe_status_word(m=1, dnr=1))), tag=3),
]

BASE_TS_ADMIN_RESP_US = 1709288400 * 1_000_000

def build_admin_resp_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_resp):
        data += epb(pkt, BASE_TS_ADMIN_RESP_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_resp)} packets to {output_path}")

# ---------------------------------------------------------------------------
# Build the cross-NMIMT slot-reuse capture (nvme-mi-typemismatch.pcapng)
# ---------------------------------------------------------------------------
#
# Malformed: a response whose NMIMT differs from the request still occupying
# the per-CSI command slot.  ADMIN and MI commands share that slot (only
# Control Primitives are tracked out-of-band), so the framing layer links the
# response to the slot's outstanding request regardless of type.  The body
# dissector must NOT then read the other type's recorded opcode / body_ctx: it
# checks the request's NMIMT and treats a cross-type response as an orphan.
#
#   F1 Admin Identify request (CSI=0) -> opens the CSI=0 slot as ADMIN
#   F2 MI    success response (CSI=0) -> lands on the ADMIN slot; the MI body
#                                        must flag orphan, not recover opc 06h
#   F3 MI    request          (CSI=1) -> opens the CSI=1 slot as MI
#   F4 Admin success response (CSI=1) -> lands on the MI slot; the Admin body
#                                        must flag orphan, not recover an opcode
packets_typemismatch = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01)),
    make_packet(False, NVME_MI_TYPE_MI,    0, mi_response_payload(STATUS_SUCCESS)),
    make_packet(True,  NVME_MI_TYPE_MI,    1, mi_request_payload(0x00)),
    make_packet(False, NVME_MI_TYPE_ADMIN, 1,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x12345678)),
]

BASE_TS_TYPEMISMATCH_US = 1709290800 * 1_000_000

def build_typemismatch_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_typemismatch):
        data += epb(pkt, BASE_TS_TYPEMISMATCH_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_typemismatch)} packets to {output_path}")

# ---------------------------------------------------------------------------
# Build the Reserved-message-type capture (nvme-mi-reserved-type.pcapng)
# ---------------------------------------------------------------------------
#
# NMIMT 3h and 5h-Fh are Reserved (Figure 12): such a message has no defined
# request or response format, so the framing layer must flag it, decode nothing
# from it, and keep it out of the command-slot lifecycle.  In particular it must
# not open a transaction on the slot -- that would supersede an in-flight
# command and orphan the command's real response.
#
# An Asynchronous Event Message (NMIMT=5h) is a *defined* message type, not a
# Reserved one, so it must not be flagged as Reserved.  But the ROR bit does not
# apply to an AEM and its CSI bit is always cleared to 0, so it is not a request
# either: it must equally stay out of the Command Slot lifecycle, or it would
# open a transaction on Command Slot 0 and supersede the command outstanding
# there.  Both cases are exercised against the same outstanding Admin command:
#
#   F1 Admin Identify request (CSI=0)  -> opens the CSI=0 command slot
#   F2 Reserved type (NMIMT=3h, CSI=0) -> flagged; must NOT touch the slot
#   F3 Asynchronous Event (NMIMT=5h)   -> NOT flagged; must NOT touch the slot
#   F4 Admin success response (CSI=0)  -> must still pair with F1, opcode 06h
packets_reserved_type = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x000B, cns=0x01)),
    make_packet(True,  NVME_MI_TYPE_RESERVED, 0, b'\xAA' * 4),
    make_packet(True,  NVME_MI_TYPE_AEM, 0, b'\x00\x01\x02\x03'),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x5EED0005)),
]

# ---------------------------------------------------------------------------
# Build the MCTP-bridging capture (nvme-mi-mctp-bridge.pcapng)
# ---------------------------------------------------------------------------
#
# This is the only capture framed over real MCTP-over-SMBus (DLT 209, I2C), so
# it is also the only one that exercises the conversation keying's
# physical-address path -- every other fixture is SLL+MCTP, where the transport
# supplies no physical addresses and the EID path is taken.
#
# MCTP bridging puts SEVERAL Management Endpoints behind ONE physical address.
# OCP Datacenter NVMe SSD 2.7 NVMe-MI-29 requires it, so a Management Controller
# can manage more than one endpoint on a 2-Wire port.  The endpoints are then
# distinguished ONLY by EID -- and an MCTP tag is unique only per endpoint pair,
# so the BMC may legitimately have tag 0 outstanding to both at once.
#
# A conversation keyed on the physical address pair + tag alone therefore merges
# the two endpoints: the command outstanding on Command Slot 0 of ME-A is
# superseded by the command to ME-B, and their responses cross-match.  The key
# must also carry the EID pair.
#
#   BMC  SMBus 0x10, EID 0x08
#   ME-A SMBus 0x3A, EID 0x1E   } same physical address, behind an MCTP bridge
#   ME-B SMBus 0x3A, EID 0x1F   }
#
#   F1 BMC -> ME-A  Admin Identify    (06h) tag=0 CSI=0   opens ME-A slot 0
#   F2 BMC -> ME-B  Admin Get Log Page(02h) tag=0 CSI=0   opens ME-B slot 0
#   F3 ME-A -> BMC  Admin response    tag=0              -> must pair with F1
#   F4 ME-B -> BMC  Admin response    tag=0              -> must pair with F2
#
# Plus a pre-EID-assignment exchange on the same bus, to prove the null-EID
# handling still works when physical addresses ARE present (the EIDs are left
# out of the key there, because the host has no EID yet):
#
#   F5 BMC -> dev   MI request  src EID 0, dst EID 0, tag=1
#   F6 dev -> BMC   MI response src EID 0x1E, dst EID 0 (host still null), tag=1

DLT_LINUX_I2C = 209
SMBUS_MCTP_CMD_CODE = 0x0F

BRIDGE_BMC_ADDR = 0x10
BRIDGE_DEV_ADDR = 0x3A      # one 2-Wire port; two Management Endpoints behind it
BRIDGE_BMC_EID  = 0x08
BRIDGE_ME_A_EID = 0x1E
BRIDGE_ME_B_EID = 0x1F

def i2c_phdr(bus=0, flags=0):
    """Linux I2C pseudo-header: bus byte + 4-byte flags (DLT 209)."""
    return bytes([bus & 0x7F]) + struct.pack('>I', flags)

def smbus_mctp_frame(dst_addr, src_addr, dst_eid, src_eid, tag, is_request,
                     mctp_msg):
    """MCTP-over-SMBus block write (DSP0237) carrying an MCTP message.

    byte_count counts the source slave address plus the MCTP data, and the frame
    carries no PEC (len == byte_count + 3), which packet-mctp-smbus.c accepts.
    """
    to = 0x08 if is_request else 0x00          # Tag Owner
    mctp_hdr = bytes([
        0x01,                                   # MCTP header version
        dst_eid,
        src_eid,
        0xC0 | to | (tag & 0x07),               # SOM=1, EOM=1, seq=0, TO, tag
    ])
    mctp_data = mctp_hdr + mctp_msg
    byte_count = 1 + len(mctp_data)             # src addr + MCTP data
    return bytes([
        (dst_addr << 1) & 0xFE,                 # destination slave address, W
        SMBUS_MCTP_CMD_CODE,
        byte_count,
        ((src_addr << 1) & 0xFE) | 0x01,        # source slave address, MCTP bit
    ]) + mctp_data

def bridge_packet(is_request, msg_type, csi, payload, dev_eid, tag):
    """One NVMe-MI message over MCTP-over-SMBus, BMC <-> a bridged endpoint."""
    nvme_mi_msg = nvme_mi_header(msg_type, csi, is_response=not is_request) + payload
    if is_request:
        dst_addr, src_addr = BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR
        dst_eid,  src_eid  = dev_eid, BRIDGE_BMC_EID
    else:
        dst_addr, src_addr = BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR
        dst_eid,  src_eid  = BRIDGE_BMC_EID, dev_eid
    return i2c_phdr() + smbus_mctp_frame(dst_addr, src_addr, dst_eid, src_eid,
                                         tag, is_request, nvme_mi_msg)

def null_eid_packet(is_request, msg_type, csi, payload, tag):
    """Same bus, but before MCTP EID assignment: the host is the null EID 0 in
    both directions; the device answers from its real EID."""
    nvme_mi_msg = nvme_mi_header(msg_type, csi, is_response=not is_request) + payload
    if is_request:
        return i2c_phdr() + smbus_mctp_frame(BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR,
                                             0x00, 0x00, tag, True, nvme_mi_msg)
    return i2c_phdr() + smbus_mctp_frame(BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR,
                                         0x00, BRIDGE_ME_A_EID, tag, False,
                                         nvme_mi_msg)

packets_mctp_bridge = [
    bridge_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                  admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01),
                  BRIDGE_ME_A_EID, tag=0),
    bridge_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                  admin_request_payload(0x02, ctrl_id=0x0002, cns=0x02),
                  BRIDGE_ME_B_EID, tag=0),
    bridge_packet(False, NVME_MI_TYPE_ADMIN, 0,
                  admin_response_payload(STATUS_SUCCESS, cqe1=0xAAAA000A),
                  BRIDGE_ME_A_EID, tag=0),
    bridge_packet(False, NVME_MI_TYPE_ADMIN, 0,
                  admin_response_payload(STATUS_SUCCESS, cqe1=0xBBBB000B),
                  BRIDGE_ME_B_EID, tag=0),
    null_eid_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=1),
    null_eid_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS), tag=1),
]

BASE_TS_MCTP_BRIDGE_US = 1709293200 * 1_000_000

def build_mctp_bridge_pcapng(output_path):
    data = shb() + idb(link_type=DLT_LINUX_I2C)
    for i, pkt in enumerate(packets_mctp_bridge):
        data += epb(pkt, BASE_TS_MCTP_BRIDGE_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_mctp_bridge)} packets to {output_path}")


BASE_TS_RESERVED_TYPE_US = 1709292000 * 1_000_000

def build_reserved_type_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_reserved_type):
        data += epb(pkt, BASE_TS_RESERVED_TYPE_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_reserved_type)} packets to {output_path}")

# ---------------------------------------------------------------------------
# nvme-mi-admin-identify.pcapng — Admin Identify response payload decode (MR6)
# ---------------------------------------------------------------------------
#
# Paired Identify request/response exchanges exercising the inline response-data
# decode shared with packet-nvme.c (dissect_nvme_data_response()).  The response
# carries the 16-byte status + CQE block followed by the Identify data structure
# at offset 16, byte-for-byte the structure the NVMe transports return.  Each
# request opens the CSI=0 command slot and its response closes it before the
# next pair, so every response recovers its request's opcode + CNS + DOFF from
# body_ctx.  Request and response share an MCTP tag (TO bit distinguishes
# direction).
#
#   F1/F2   Identify Controller (CNS 01h)        -> VID/SSVID/SN/MN/CNTLID
#   F3/F4   Identify Namespace (CNS 00h)         -> NSZE/NCAP
#   F5/F6   Active Namespace ID List (CNS 02h)   -> nsid[0..2]
#   F7/F8   NS Identification Descriptor (CNS 03h) -> EUI64 + NGUID descriptors
#   F9/F10  Controller List (CNS 13h)            -> NUMCIDS + controller IDs
#   F11/F12 Identify Controller, DOFF=24 window  -> MN decoded at structure off 24

def identify_ctrl_data(vid=0x144d, ssvid=0x1014, sn="SERIAL01234567890123",
                       mn="WIRESHARK MODEL NUMBER", cntlid=0x0007, total=4096):
    """Partial Identify Controller data structure (NVMe Base 2.3 Fig 328)."""
    buf = bytearray(total)
    struct.pack_into('<H', buf, 0, vid)
    struct.pack_into('<H', buf, 2, ssvid)
    buf[4:24]  = sn.encode('ascii')[:20].ljust(20, b' ')
    buf[24:64] = mn.encode('ascii')[:40].ljust(40, b' ')
    struct.pack_into('<H', buf, 78, cntlid)
    return bytes(buf)

def identify_ns_data(nsze=0x100000, ncap=0x80000, total=4096):
    """Partial Identify Namespace data structure (NVM Command Set Fig)."""
    buf = bytearray(total)
    struct.pack_into('<Q', buf, 0, nsze)
    struct.pack_into('<Q', buf, 8, ncap)
    return bytes(buf)

def identify_nslist_data(nsids, total=4096):
    """Namespace ID list: packed LE uint32 NSIDs, zero-terminated/zero-filled."""
    buf = bytearray(total)
    for i, nsid in enumerate(nsids):
        struct.pack_into('<I', buf, i * 4, nsid)
    return bytes(buf)

def identify_nsdesc_data(descs, total=4096):
    """NS Identification Descriptor list (Fig 331): each desc is
    (nidt, nid_bytes); NIDL = len(nid_bytes); reserved 2 bytes; then NID."""
    buf = bytearray()
    for nidt, nid in descs:
        buf += bytes([nidt, len(nid), 0, 0]) + nid
    buf = buf.ljust(total, b'\x00')
    return bytes(buf[:total])

def identify_ctrl_list_data(cids, total=4096):
    """Controller List (Fig 138): NUMCIDS (LE u16) then that many LE u16 CIDs."""
    buf = bytearray(total)
    struct.pack_into('<H', buf, 0, len(cids))
    for i, cid in enumerate(cids):
        struct.pack_into('<H', buf, 2 + i * 2, cid)
    return bytes(buf)

# DOFF-window MN chunk: structure offset 24 (the Model Number field), 40 bytes.
_ID_MN = "WIRESHARK MODEL NUMBER".encode('ascii')[:40].ljust(40, b' ')

packets_admin_identify = [
    # F1/F2 Identify Controller (CNS 01h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_data()), tag=0),
    # F3/F4 Identify Namespace (CNS 00h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x00), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ns_data()), tag=1),
    # F5/F6 Active Namespace ID List (CNS 02h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x02), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_nslist_data([1, 2, 7])), tag=2),
    # F7/F8 NS Identification Descriptor list (CNS 03h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x03), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_nsdesc_data([
                    (0x1, bytes(range(0x10, 0x18))),                 # EUI64, 8 bytes
                    (0x2, bytes(range(0x20, 0x30))),                 # NGUID, 16 bytes
                ])), tag=3),
    # F9/F10 Controller List (CNS 13h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x13), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_list_data([1, 2, 5])), tag=4),
    # F11/F12 Identify Controller, DOFF=24 window (Model Number)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01,
                                      flags=0x03, doff=24, dlen=40), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ID_MN), tag=5),
    # F13/F14 Identify Namespace truncated by a small DLEN (64 bytes, off 0):
    # the length-guarded decoder must stop after the fields that fit (NSZE/NCAP)
    # WITHOUT overrunning the payload (no Malformed exception).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x00, dlen=64), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ns_data(total=64)), tag=6),
]

BASE_TS_ADMIN_IDENTIFY_US = 1709289600 * 1_000_000

def build_admin_identify_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_identify):
        data += epb(pkt, BASE_TS_ADMIN_IDENTIFY_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_identify)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng — Admin Get Log Page response payload decode (MR7)
# ---------------------------------------------------------------------------
#
# Paired Get Log Page (opcode 02h) request/response exchanges.  The MI admin
# response routes the inline data (offset 16 onward) through the shared
# packet-nvme.c dissect_nvme_data_response(), which dispatches on the LID the
# request SQE carried (CDW10, recovered from body_ctx) to the per-log-page
# decoder.  These three pages are the ones OOB BMC management polls most and
# that fit the smallest MCTP MTU without windowing (LPO = 0, DOFF = 0):
#
#   F1/F2  SMART / Health Information (LID 02h)  -> composite temp, % used, spare
#   F3/F4  Firmware Slot Information (LID 03h)   -> active slot + slot-1 revision
#   F5/F6  Error Information (LID 01h)           -> error count, SQID, command ID
#   F7/F8  Supported Log Pages (LID 00h)         -> per-LID LSUPP/IOS/LIDSP
#
# The request reuses admin_request_payload(): the cns argument is CDW10, whose
# low byte is the Log Page Identifier (dissect_nvme_get_logpage_cmd reads LID
# from offset 40), so cns=LID selects the page.

NVME_AQ_OPC_GET_LOG_PAGE = 0x02

# Firmware revision strings are read by the decoder as little-endian uint64; the
# test recomputes the expected value from these same bytes.
FW_SLOT1_REV = b"FWREV100"

def smart_data(ct=320, asc=100, ast=10, pu=5, poh=12345, total=512):
    """Partial SMART / Health Information log page (NVMe Base 2.3 Fig 207)."""
    buf = bytearray(total)
    buf[0] = 0x00                          # Critical Warning: none
    struct.pack_into('<H', buf, 1, ct)     # Composite Temperature (Kelvin)
    buf[3] = asc                           # Available Spare (%)
    buf[4] = ast                           # Available Spare Threshold (%)
    buf[5] = pu                            # Percentage Used / Life Age Estimate
    struct.pack_into('<Q', buf, 128, poh)  # Power On Hours (low 8 of 16 bytes)
    return bytes(buf)

def fw_slot_data(afi=0x01, rev1=FW_SLOT1_REV, total=512):
    """Partial Firmware Slot Information log page (NVMe Base 2.3 Fig 205).
    AFI bits 2:0 = active slot; bytes 8:15 = Firmware Revision for Slot 1."""
    buf = bytearray(total)
    buf[0] = afi
    buf[8:16] = rev1[:8].ljust(8, b'\x00')
    return bytes(buf)

def error_info_data(errcnt=42, sqid=3, cid=0x00ab, total=128):
    """Error Information log: the decoded first 64-byte entry (NVMe Base 2.3
    Fig 204) plus room for a second (the page is an array of entries; the
    decoder reads the first entry's trailing reserved field past byte 64)."""
    buf = bytearray(total)
    struct.pack_into('<Q', buf, 0, errcnt)  # Error Count
    struct.pack_into('<H', buf, 8, sqid)    # Submission Queue ID
    struct.pack_into('<H', buf, 10, cid)    # Command ID
    return bytes(buf)

def supported_log_pages_data(total=1024):
    """Supported Log Pages (LID 00h): 256 four-byte LID Supported and Effects
    entries (NVMe Base 2.3 Fig 207/208), indexed by Log Page Identifier.  Marks
    a handful of OOB-BMC-common LIDs supported; LID 02h (SMART) also sets IOS,
    and LID 0Dh (Persistent Event) carries a sentinel LID Specific Parameter."""
    buf = bytearray(total)
    def entry(lid, lsupp=1, ios=0, lidsp=0):
        val = (lsupp & 1) | ((ios & 1) << 1) | ((lidsp & 0xffff) << 16)
        struct.pack_into('<I', buf, lid * 4, val)
    entry(0x00)
    entry(0x01)
    entry(0x02, ios=1)              # SMART supports an index offset
    entry(0x03)
    entry(0x0d, lidsp=0x1234)       # Persistent Event Log, sentinel LIDSP
    return bytes(buf)

packets_admin_logpage = [
    # F1/F2 SMART / Health Information (LID 02h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x02), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data()), tag=0),
    # F3/F4 Firmware Slot Information (LID 03h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x03), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(fw_slot_data()), tag=1),
    # F5/F6 Error Information (LID 01h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x01), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(error_info_data()), tag=2),
    # F7/F8 Supported Log Pages (LID 00h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x00), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(supported_log_pages_data()), tag=3),
]

BASE_TS_ADMIN_LOGPAGE_US = 1709376000 * 1_000_000

def build_admin_logpage_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_logpage):
        data += epb(pkt, BASE_TS_ADMIN_LOGPAGE_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_logpage)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-admin-features.pcapng — Admin Get/Set Features payload decode (MR8)
# ---------------------------------------------------------------------------
#
# The MI admin response routes Get Features inline data (offset 16 onward)
# through the shared packet-nvme.c dissect_nvme_data_response(), which
# dispatches on the FID the request SQE carried (CDW10, recovered from
# body_ctx) to the per-FID structure decoder.  The three Mandatory Management
# Endpoint metadata FIDs (7Dh/7Eh/7Fh) all return a Host Metadata data
# structure (NVMe Base 2.3 Figures 461/462), newly decoded by MR8.
#
#   F1/F2  Get Features Controller Metadata (FID 7Eh)  -> 2 descriptors (Fig 463)
#   F3/F4  Get Features Namespace Metadata  (FID 7Fh)  -> 2 descriptors (Fig 464)
#   F5/F6  Set Features Enhanced Ctrl Meta  (FID 7Dh)  -> request EA field (CDW11)
#   F7/F8  Get Features Temperature Threshold (FID 04h) -> already-covered DW0
#
# admin_request_payload()'s cns argument is CDW10, whose low byte is the FID
# (dissect_nvme_get/set_features_cmd reads it from offset 40), so cns=FID.

F_ENH_CTRL_METADATA      = 0x7d
F_CTRL_METADATA          = 0x7e
F_NS_METADATA            = 0x7f
F_TEMP_THRESHOLD         = 0x04
NVME_AQ_OPC_SET_FEATURES = 0x09
NVME_AQ_OPC_GET_FEATURES = 0x0a

def host_metadata_descriptor(et, eval_str, er=0):
    """One Metadata Element Descriptor (NVMe Base 2.3 Figure 462): a 4-byte
    little-endian header (ET bits 4:0, ER bits 11:8, ELEN bits 31:16) followed
    by ELEN bytes of UTF-8 Element Value."""
    eval_bytes = eval_str.encode('utf-8')
    elen = len(eval_bytes)
    dword = (et & 0x1f) | ((er & 0xf) << 8) | ((elen & 0xffff) << 16)
    return struct.pack('<I', dword) + eval_bytes

def host_metadata_data(descriptors, total=4096):
    """Host Metadata data structure (NVMe Base 2.3 Figure 461): NMED count,
    a reserved byte, then the descriptor list, padded to the 4 KiB size."""
    buf = bytearray()
    buf.append(len(descriptors) & 0xff)   # NMED
    buf.append(0)                         # reserved
    for d in descriptors:
        buf += d
    return bytes(buf).ljust(total, b'\x00') if total else bytes(buf)

packets_admin_features = [
    # F1/F2 Get Features Controller Metadata (FID 7Eh): 2 descriptors
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, cns=F_CTRL_METADATA), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(host_metadata_data([
                    host_metadata_descriptor(0x01, "nvme0"),        # OS Controller Name
                    host_metadata_descriptor(0x0a, "Linux 6.1.0"),  # OS Name and Build
                ])), tag=0),
    # F3/F4 Get Features Namespace Metadata (FID 7Fh): exercises Figure 464
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0002, cns=F_NS_METADATA), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(host_metadata_data([
                    host_metadata_descriptor(0x01, "nvme0n1"),  # OS Namespace Name
                    host_metadata_descriptor(0x02, "EFI NS1"),  # Pre-boot Namespace Name
                ])), tag=1),
    # F5/F6 Set Features Enhanced Controller Metadata (FID 7Dh): EA=Add Entry
    # Multiple (10b) in CDW11 bits 14:13.  The request carries the Host Metadata
    # structure in its data buffer (offset 64 onward), now decoded request-side.
    # Response is a plain success.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0003,
                                      cns=F_ENH_CTRL_METADATA, cdw11=(0x2 << 13)) +
                host_metadata_data([
                    host_metadata_descriptor(0x01, "nvme9"),    # OS Controller Name
                    host_metadata_descriptor(0x10, "overtemp"), # Host-Determined Failure Record
                ], total=128), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=2),
    # F7/F8 Get Features Temperature Threshold (FID 04h): an already-covered
    # Optional FID -- its CQE DW0 (TMPTH/TMPSEL/THPSEL) must still reach the
    # shared per-FID decoder over the MI path (no MR8 packet-nvme.c change).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0004, cns=F_TEMP_THRESHOLD), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0012014B,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=3),
]

BASE_TS_ADMIN_FEATURES_US = 1709376000 * 1_000_000

def build_admin_features_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_features):
        data += epb(pkt, BASE_TS_ADMIN_FEATURES_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_features)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage-windowed.pcapng — multi-window Get Log Page
# ---------------------------------------------------------------------------
#
# Every existing Get Log Page fixture (packets_admin_logpage above, and every
# other Admin fixture in this file) requests the full log page in a single
# message: DOFST=0 for the whole structure.  NVMe-MI-25 mandates multi-window
# retrieval for log pages that do not fit one MCTP message, sliced via the
# Admin request's Data Offset (DOFST) — packet-nvme-mi-admin.c hands that
# offset to nvme_dissect_admin_data_resp() as `off`, and each per-LID decoder
# in packet-nvme.c indexes its fields by (struct_offset - off) rather than
# assuming byte 0 of the response is byte 0 of the structure.  That "off !=
# 0" code path — e.g. dissect_nvme_get_logpage_smart_resp()'s
# `cmd_tvb, 32-off, 16` / `cmd_tvb, 48-off, 16` indexing for Data Units
# Read/Written — has never executed with a nonzero offset anywhere in this
# corpus, so mutation fuzzing on the existing captures cannot reach it
# (editcap perturbs bytes already present; it cannot manufacture a second,
# differently-offset request the seed never sent).  A bug of exactly this
# shape ("field indexed by structure offset instead of window offset") was
# already found and fixed once, for Identify, in MR06 — Get Log Page's
# equivalent path has never been put through the same stress test.
#
# Byte offsets below are cross-checked against NVM Express Base Specification
# 2.3 Figure 210 (SMART / Health Information Log Page), not just against the
# dissector's own comments: byte 47:32 = Data Units Read, byte 63:48 = Data
# Units Written.
#
# Two-window retrieval of the SMART / Health Information log page (LID 02h):
#   F1/F2  Window 1: DOFST=0,  DLEN=32 -> struct bytes [0:32)  (Critical
#          Warning through Percentage Used/EGCWS — off==0, same as every
#          existing fixture; a same-capture baseline to compare window 2
#          against)
#   F3/F4  Window 2: DOFST=32, DLEN=32 -> struct bytes [32:64), i.e. Data
#          Units Read (DUR) and Data Units Written (DUW) in full, each given
#          a distinctive non-zero 16-byte pattern (rather than smart_data()'s
#          default all-zero DUR/DUW) so the pytest assertion actually proves
#          the offset arithmetic reconstructs the right bytes at the right
#          position, rather than merely proving it still shows zero.

_WINDOWED_DUR = bytes(range(0x10, 0x20))  # struct offset 32:47 (Fig 210)
_WINDOWED_DUW = bytes(range(0x20, 0x30))  # struct offset 48:63 (Fig 210)
_smart_window2_data = _WINDOWED_DUR + _WINDOWED_DUW  # 32 bytes = struct [32:64)

# F5/F6 below: same DUR/DUW struct range as F3/F4, but reached via LPO=16 +
# DOFST=16 (combined_off=32) instead of DOFST=32 alone -- a different byte
# pattern so a passing assertion can only be explained by the LPO+transport
# combination actually happening in dissect_nvme_get_logpage_resp(), not by
# accidentally matching F3/F4's bytes.
_lpo_dofst_combined_data = bytes(range(0x40, 0x60))  # 32 bytes = struct [32:64)

# F7/F8: Error Info (LID 01h) CSI field, struct offset 32:39 (8 bytes)
_errinf_csi_data = bytes(range(0x50, 0x58))

# F9/F10: FW Slot (LID 03h) Slot-1 firmware revision, struct offset 8:15
_fw_slot_frs0_data = b'WIRESHK1'

# F13/F14: Changed NSList (LID 04h), 2nd entry (struct offset 8:11 = index 2)
_changed_nslist_entry2 = struct.pack('<I', 0x00000042)

# F15/F16: Endurance Group (LID 09h) DUR field, struct offset 32:47 (16 bytes)
_egroup_dur_data = bytes(range(0x60, 0x70))

# F17/F18: Endurance Group (LID 09h) trailing "Reserved2" field (struct 160:512),
# windowed to combined_off=400 with dlen exactly at the outer guard's minimum
# (512-400=112).  For off=400 (>160), the pre-fix poff formula was (off-160)=240,
# which exceeds this len -- the exact "poff > len" underflow the outer guard
# alone does not exclude, since it only requires len >= 512-off (112), not
# len >= poff (240).
_egroup_rsvd2_window = bytes(range(112))

# F19/F20: Pred Lat NVM Set (LID 0Ah) DTWIN Reads Typical, struct offset 32:39
_pred_lat_dtwin_rt_data = bytes(range(0x70, 0x78))

# F21/F22: Reservation Notification (LID 80h) LPT, struct offset 8:8 (1 byte)
_reserv_notif_lpt_data = bytes([0x07])

# F23/F24: Sanitize Status (LID 81h), off=0, dlen=64 -- ordinary (non-windowed)
# response with plenty of data.  Before the fix, the trailing "rsvd" field
# (struct offset 32 onward) NEVER rendered here regardless of off, because
# the bail-out condition was inverted ("if (poff <= len) return;" instead of
# "if (len <= poff) return;") -- it incorrectly bailed out exactly when there
# WAS enough data.  32 bytes of fixed fields (0:32) + 32 distinctive
# trailing bytes.
_sanitize_fixed_fields = bytes(32)  # sprog/sstat/scdw10/eto/etbe/etce/etond/etbend/etcend, all zero is fine
_sanitize_trailing_data = bytes(range(0x80, 0xA0))  # struct offset 32:64
_sanitize_data = _sanitize_fixed_fields + _sanitize_trailing_data

# F27/F28: Feature ID Sup&Eff (LID 12h), entry index 1 (struct offset 4:7)
_feat_sup_and_eff_entry1 = struct.pack('<I', 0x00000001)

# F29/F30: NVMe-MI Cmd Sup&Eff (LID 13h), entry index 1 (struct offset 4:7)
_mi_cmd_sup_and_eff_entry1 = struct.pack('<I', 0x00000001)

# F31/F32: Supported Log Pages (LID 00h), LID index 2 entry (struct offset 8:11)
_supported_lid2_entry = struct.pack('<I', 0x00000001)

# ---------------------------------------------------------------------------
# Additional windows (F33..F48) appended for the NVMe Base 2.3 / NVMe-MI 2.1
# spec-audit fixes.  Each pair targets one confirmed packet-nvme.c defect that
# only manifests once a nonzero window offset (LPO+DOFST) reaches the decoder.
# ---------------------------------------------------------------------------

# F33/F34: Commands Supported and Effects (LID 05h), off=0, full 2048-byte page.
# NVMe Base 2.3: ACS0..255 occupy bytes [0:1024), IOCS0..255 occupy bytes
# [1024:2048), CONTIGUOUS (table rows "1027:1024 IOCS0", "1031:1028 IOCS1").
# The decoder's IOCS base used 1028 instead of 1024: it skipped IOCS0 (so every
# IOCS entry was mislabelled) AND read 4 bytes past the 2048-byte page
# (Malformed even at off=0).  ACS0 (struct 0) and IOCS0 (struct 1024) carry
# distinct sentinel CSEDS uint32s so a passing assertion proves IOCS0 decodes.
_cmd_sup_and_eff_page = bytearray(2048)
struct.pack_into('<I', _cmd_sup_and_eff_page, 0,    0xA5A50001)  # ACS0  (struct 0)
struct.pack_into('<I', _cmd_sup_and_eff_page, 1024, 0x5A5A0002)  # IOCS0 (struct 1024)
_cmd_sup_and_eff_page = bytes(_cmd_sup_and_eff_page)

# F35/F36: SMART (LID 02h) windowed to combined_off=200 -- the exact start of
# the Temperature Sensor 1..8 array (struct 200:216).  For off>=200 the array's
# tvb position is 0, not the struct-absolute 200: the pre-fix code set poff=off
# (so decode_smart_resp_temps early-returned, rendering nothing) and bounds-
# checked the per-sensor read with the wrong dimension (off+pos instead of
# pos-off).  Temperature Sensor 1 (struct 200:202) carries a known value.
_smart_temps_window = bytearray(16)
struct.pack_into('<H', _smart_temps_window, 0, 300)  # Temperature Sensor 1 (K)
_smart_temps_window = bytes(_smart_temps_window)

# F37/F38: Telemetry Host-Initiated (LID 07h), off=0, DLEN=100 (< the 512-byte
# data-block granularity).  poff = 512 - (off & 0x1ff) = 512; the pre-fix
# "len -= poff" underflowed `len` (unsigned) and the block loop then ran off
# the end of the tvb (Malformed).  Header fields render above the new guard.
_telemetry_short = bytes(100)

# F39/F40: Predictable Latency Event Aggregate (LID 0Bh), off=0, DLEN=4 (< the
# 8-byte poff).  The pre-fix guard "if (len < (poff+2) && off) return;" was
# gated on off, so off=0 fell through and "len -= poff" (poff=8) underflowed.
_pred_lat_aggreg_short = bytes(4)

# F41/F42: ANA (LID 0Ch), off=0, DLEN=8 (< the 16-byte header poff).  No guard
# preceded "len -= poff" (poff=16), so off=0 underflowed `len`.  The 8-byte
# Change Count header renders above the new guard.
_ana_short = bytes(8)

# F43/F44: Device Self-test (LID 06h), off=0, DLEN=2 (< the 4-byte header).  The
# if(off<=4) branch did "len -= (4-off)" with no check, underflowing `len`.
_selftest_short = bytes(2)

# F45/F46: Device Self-test (LID 06h) windowed to combined_off=32 -- the exact
# start of Self-test Result index 1 (results begin at struct 4, each is 28
# bytes, so result[1] is at struct 4+28=32).  The loop offset must be tvb-
# relative ((result struct offset) - off); the pre-fix code used struct-
# absolute off=4+tst_idx*8, reading result[1]'s Power-On-Hours from the wrong
# bytes.  POH (result offset +4 => struct 36:44) carries a known value.
_selftest_result1 = bytearray(40)
struct.pack_into('<Q', _selftest_result1, 4, 0xDEADBEEF)  # result[1] POH (struct 36)
_selftest_result1 = bytes(_selftest_result1)

# F47/F48: Firmware Slot (LID 03h) windowed to combined_off=32 (0 < off < 64).
# The trailing reserved field begins at struct offset 64; its tvb position is
# (64 - off) = 32, not the struct-absolute 64 the pre-fix "poff = ... : off"
# used.  A sentinel at struct 64 (tvb offset 32) proves the field reads from
# the correct position.
_fw_slot_rsvd_window = bytearray(96)
_fw_slot_rsvd_window[32:40] = b'FWRSVD01'  # struct offset 64:72
_fw_slot_rsvd_window = bytes(_fw_slot_rsvd_window)

# ---------------------------------------------------------------------------
# F49..F54: dimensional-clamp regressions for Sanitize Status / Endurance
# Group / Predictable Latency NVM Set trailing "reserved" fields.
#
# Each of these decoders' trailing field is anchored at a tvb-relative
# position `poff` and its correct remaining-room cap is (512-off)-poff (an
# off-INDEPENDENT constant, since poff itself already accounts for off).  A
# prior fix mistakenly capped at (512-poff) instead -- off bytes too large --
# which silently spills that many bytes of unrelated trailing data into the
# field instead of truncating it at the log page's real 512-byte end.  These
# fixtures pick DLEN so the rendered length lands strictly between the
# correct cap and the (larger) buggy cap, and place a distinct sentinel at
# the correct cap's last 4 bytes (proving the field renders that far) plus a
# second sentinel just past it (present only if the clamp is missing).
#
# F49/F50 Sanitize Status (LID 81h), DOFST=8, DLEN=508: poff=32-8=24,
# correct cap=(512-8)-24=480, pre-fix buggy cap=512-24=488; len_after_poff=
# 508-24=484 sits strictly between them.
_sanitize_dim_fixed = bytes(24)               # struct 8:32 (eto..etcend), zero
_sanitize_dim_filler = bytes(476)             # struct 32:508
_sanitize_dim_sentinel_a = struct.pack('>I', 0xCAFEBABE)  # struct 508:512 (true end)
_sanitize_dim_sentinel_b = struct.pack('>I', 0xDEADBEEF)  # struct 512:516 (past true end)
_sanitize_dim_data = (_sanitize_dim_fixed + _sanitize_dim_filler
                      + _sanitize_dim_sentinel_a + _sanitize_dim_sentinel_b)
assert len(_sanitize_dim_data) == 508

# F51/F52 Endurance Group (LID 09h), DOFST=200, DLEN=400: off=200 (>160) so
# poff=0 in both the pre-fix and fixed code (only the missing max_len clamp
# differs); correct cap=512-200=312, pre-fix code applied no cap at all.
_egroup_dim_filler = bytes(308)               # struct 200:508
_egroup_dim_sentinel_a = struct.pack('>I', 0xCAFEBABE)    # struct 508:512 (true end)
_egroup_dim_sentinel_b = struct.pack('>I', 0xDEADBEEF)    # struct 512:516 (past true end)
_egroup_dim_trailing_filler = bytes(84)       # pads DLEN out to 400
_egroup_dim_data = (_egroup_dim_filler + _egroup_dim_sentinel_a
                    + _egroup_dim_sentinel_b + _egroup_dim_trailing_filler)
assert len(_egroup_dim_data) == 400

# F53/F54 Predictable Latency NVM Set (LID 0Ah), DOFST=200, DLEN=400: off=200
# (>152) so poff=0 in both versions; correct cap=512-200=312, pre-fix code
# applied no cap at all -- same shape as the Endurance Group case above.
_pred_lat_dim_data = _egroup_dim_data
assert len(_pred_lat_dim_data) == 400

# F55/F56: LPO 64-bit overflow saturation, Command/Feature Lockdown (LID 14h).
# LPO=0x1_0000_0000 (2**32) with DOFST=0: the pre-fix dispatcher computed
# combined_off = (unsigned)(LPO + DOFST), truncating the 64-bit sum to 32
# bits -- wrapping to 0 -- so the decoder's "if (off) return" guard (variable-
# length CFIL list can only be decoded starting at offset 0) incorrectly did
# NOT bail out.  The fix saturates an overflowing 64-bit sum to UINT32_MAX
# instead of truncating it, so the guard correctly rejects this LPO.
#
# lngth (byte 3) is deliberately nonzero (0x02) with 2 real CFIL entries
# following, so the CFIL field actually renders if the guard fails to fire --
# an all-zero lngth would make cfil absent either way and not distinguish
# fixed from buggy behavior.
_cmd_feat_lockdown_overflow_data = bytes([0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB])

# ---------------------------------------------------------------------------
# F57..F68: second-pass windowed-transfer regressions (2026-07-22 code
# review of the whole "combined LPO+transport offset" mechanism), found by
# re-auditing this same offset math after the F1-F56 fixes above landed.
# ---------------------------------------------------------------------------

# F57/F58: LPO 64-bit ADDITION overflow, Command/Feature Lockdown (LID 14h).
# Unlike F55/F56 (LPO=2**32, which only overflows the 32-bit narrowing
# clamp), this LPO is chosen so the 64-bit addition itself
# (LPO + DOFST) wraps past 2**64 before the UINT32_MAX saturation check
# ever runs: LPO=0xFFFFFFFFFFFFFFFC + DOFST=4 == 2**64 == 0 (mod 2**64).
# The pre-fix dispatcher computed combined_off64 = LPO + off with no
# overflow check on the addition, so this wrapped to a small (here, exactly
# 0) combined_off, defeating the "if (off) return" guard exactly like F56's
# bug -- just reached via wraparound instead of narrowing.  The fix checks
# for overflow before adding and saturates to UINT64_MAX (still > UINT32_MAX
# after narrowing), so the guard correctly rejects this LPO.
_cmd_feat_lockdown_addition_overflow_data = bytes([0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB])

# F59/F60: Telemetry Host-Initiated (LID 07h) windowed to combined_off=512 --
# exactly the first data-block boundary (LPO=0, DOFST=512).  The pre-fix
# "poff = 512 - (off & 0x1ff)" treated any exact multiple of 512 the same as
# off==0 (poff=512), so a window that already starts AT the boundary had its
# entire first block skipped ("len -= poff" consumed the whole window before
# the block loop ran).  512 bytes of a distinct byte value prove the block
# renders when the window starts exactly on a block boundary.
_telemetry_block_at_boundary = bytes([0x5A]) * 512

# F61/F62: Predictable Latency Event Aggregate (LID 0Bh), LPO=0, DOFST=5 --
# combined_off=5, inside the 8-byte "NE" header field but not at its start.
# The pre-fix "poff = 8 - (cmd_ctx->cmd_ctx.get_logpage.off & 0x7)" used the
# raw per-command LPO (here 0) instead of the combined offset actually
# threaded to this decoder, computing poff=8 instead of the correct 3 -- so
# the NSET array was read 5 bytes too far into the window.  A sentinel at
# the CORRECT tvb position (3) proves the fix; a different sentinel at the
# pre-fix WRONG position (8) proves the old code would have shown different
# (bogus) bytes instead.
_pred_lat_aggreg_off_data = bytes([0, 0, 0, 0xEF, 0xBE, 0, 0, 0, 0xAD, 0xDE])

# F63/F64: Supported Log Pages (LID 00h), combined_off=2 -- not a multiple of
# the table's 4-byte record size.  Pre-fix, "fidx = off / 4" (integer
# division) silently truncated to a valid-looking index and spliced two
# adjacent on-wire records into one mislabeled entry instead of rejecting
# the misaligned window.  The fix requires the combined offset be a multiple
# of the record size; a non-aligned window now renders nothing.
_supported_misaligned_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

# F65/F66: Changed Namespace List (LID 04h), combined_off=2 -- same
# misalignment shape as F63/F64 but a different code path (a raw
# tvb-position-0 byte-stride loop, not an "off / 4" index) that spliced
# adjacent NSIDs together instead of rejecting the window.
_changed_nslist_misaligned_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

# F67/F68: Firmware Slot (LID 03h), DOFST=0, DLEN=1 -- exactly the AFI
# field's 1 byte and nothing else.  The pre-fix guard "if (!off && len > 1)"
# used a strict ">" instead of ">=", so a transfer of exactly 1 byte (all of
# AFI, none of the following Reserved) silently skipped AFI entirely.
_fw_slot_afi_exact_data = bytes([0x02])

packets_admin_logpage_windowed = [
    # F1/F2 SMART / Health Information (LID 02h), window 1: DOFST=0, DLEN=32
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x02,
                                      doff=0, dlen=32), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data()[0:32]), tag=0),
    # F3/F4 SMART / Health Information (LID 02h), window 2: DOFST=32, DLEN=32
    #       (Data Units Read at struct offset 32, Data Units Written at 48 —
    #       the first-ever off=32 exercise of this decoder in the corpus)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x02,
                                      doff=32, dlen=32), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_smart_window2_data), tag=1),
    # F5/F6 SMART, window reached via LPO=16 + DOFST=16 (combined_off=32):
    # proves dissect_nvme_get_logpage_resp() actually combines the NVMe-level
    # Log Page Offset with the NVMe-MI transport offset, not just one alone.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x02,
                                      doff=16, dlen=32, lpo=16), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lpo_dofst_combined_data), tag=2),
    # F7/F8 Error Information (LID 01h), DOFST=32, DLEN=8 -> CSI field
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x01,
                                      doff=32, dlen=8), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_errinf_csi_data), tag=3),
    # F9/F10 Firmware Slot Information (LID 03h), DOFST=8, DLEN=8 -> Slot 1
    # firmware revision (the first-ever off!=0 exercise of decode_fw_slot_frs())
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x03,
                                      doff=8, dlen=8), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_fw_slot_frs0_data), tag=4),
    # F11/F12 Firmware Slot Information (LID 03h), DOFST=63, DLEN=1: lands
    # exactly on the trailing-reserved-field boundary with far too little
    # data for it -- before the fix, "len -= poff" here underflowed `len`
    # (unsigned) to a huge value instead of safely rendering nothing.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x03,
                                      doff=63, dlen=1), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes([0xAB])), tag=5),
    # F13/F14 Changed Namespace List (LID 04h), DOFST=8, DLEN=4 -> 2nd entry
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x04,
                                      doff=8, dlen=4), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_changed_nslist_entry2), tag=6),
    # F15/F16 Endurance Group (LID 09h), DOFST=48, DLEN=16 -> Data Units Read
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x09,
                                      doff=48, dlen=16), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_egroup_dur_data), tag=7),
    # F17/F18 Endurance Group (LID 09h), DOFST=400, DLEN=112 (=512-400, the
    # outer guard's exact minimum): the trailing field's pre-fix poff
    # ((off<=160)?...:(off-160)=240) exceeds this len, which is NOT excluded
    # by the "(512-off)<=len" guard alone -- before the fix this underflowed.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x09,
                                      doff=400, dlen=112), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_egroup_rsvd2_window), tag=8),
    # F19/F20 Predictable Latency NVM Set (LID 0Ah), DOFST=32, DLEN=8
    # -> DTWIN Reads Typical
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0A,
                                      doff=32, dlen=8), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_pred_lat_dtwin_rt_data), tag=9),
    # F21/F22 Reservation Notification (LID 80h), DOFST=8, DLEN=1 -> LPT
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x80,
                                      doff=8, dlen=1), tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_reserv_notif_lpt_data), tag=10),
    # F23/F24 Sanitize Status (LID 81h), DOFST=0, DLEN=64: proves the
    # inverted-bail-out fix -- see the block comment above _sanitize_data.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x81,
                                      doff=0, dlen=64), tag=11),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sanitize_data), tag=11),
    # F25/F26 Command and Feature Lockdown (LID 14h), LPO=4 (nonzero),
    # DOFST=0 -> combined_off=4: proves LPO alone (not just DOFST) reaches
    # this decoder's "variable-length list can only be decoded starting at
    # offset 0" guard -- it must bail out here even though DOFST itself is 0.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x14,
                                      doff=0, dlen=4, lpo=4), tag=12),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes([0x01, 0x00, 0x00, 0x00])), tag=12),
    # F27/F28 Feature Identifiers Supported and Effects (LID 12h), DOFST=4,
    # DLEN=4 -> FID index 1 entry
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x12,
                                      doff=4, dlen=4), tag=13),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_feat_sup_and_eff_entry1), tag=13),
    # F29/F30 NVMe-MI Command Supported and Effects (LID 13h), DOFST=4,
    # DLEN=4 -> command index 1 entry
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=4, dlen=4), tag=14),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_mi_cmd_sup_and_eff_entry1), tag=14),
    # F31/F32 Supported Log Pages (LID 00h), DOFST=8, DLEN=4 -> LID index 2
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x00,
                                      doff=8, dlen=4), tag=15),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_supported_lid2_entry), tag=15),
    # F33/F34 Commands Supported and Effects (LID 05h), DOFST=0, DLEN=2048:
    # full page -- asserts IOCS0 (struct 1024) decodes and no page overread.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x05,
                                      doff=0, dlen=2048), tag=16),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_sup_and_eff_page), tag=16),
    # F35/F36 SMART (LID 02h), DOFST=200, DLEN=16 -> Temperature Sensor array
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x02,
                                      doff=200, dlen=16), tag=17),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_smart_temps_window), tag=17),
    # F37/F38 Telemetry Host-Initiated (LID 07h), DOFST=0, DLEN=100 (< 512)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x07,
                                      doff=0, dlen=100), tag=18),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_telemetry_short), tag=18),
    # F39/F40 Predictable Latency Event Aggregate (LID 0Bh), DOFST=0, DLEN=4
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0B,
                                      doff=0, dlen=4), tag=19),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_pred_lat_aggreg_short), tag=19),
    # F41/F42 Asymmetric Namespace Access (LID 0Ch), DOFST=0, DLEN=8 (< 16)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0C,
                                      doff=0, dlen=8), tag=20),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ana_short), tag=20),
    # F43/F44 Device Self-test (LID 06h), DOFST=0, DLEN=2 (< 4-byte header)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x06,
                                      doff=0, dlen=2), tag=21),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_selftest_short), tag=21),
    # F45/F46 Device Self-test (LID 06h), DOFST=32, DLEN=40 -> result[1] POH
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x06,
                                      doff=32, dlen=40), tag=22),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_selftest_result1), tag=22),
    # F47/F48 Firmware Slot (LID 03h), DOFST=32, DLEN=96 -> trailing reserved
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x03,
                                      doff=32, dlen=96), tag=23),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_fw_slot_rsvd_window), tag=23),
    # F49/F50 Sanitize Status (LID 81h), DOFST=8, DLEN=508 -> trailing
    # "rsvd" dimensional-clamp regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x81,
                                      doff=8, dlen=508), tag=24),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sanitize_dim_data), tag=24),
    # F51/F52 Endurance Group (LID 09h), DOFST=200, DLEN=400 -> trailing
    # "rsvd2" dimensional-clamp regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x09,
                                      doff=200, dlen=400), tag=25),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_egroup_dim_data), tag=25),
    # F53/F54 Predictable Latency NVM Set (LID 0Ah), DOFST=200, DLEN=400 ->
    # trailing "rsvd3" dimensional-clamp regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0A,
                                      doff=200, dlen=400), tag=26),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_pred_lat_dim_data), tag=26),
    # F55/F56 Command and Feature Lockdown (LID 14h), LPO=2**32, DOFST=0:
    # LPO 64-bit overflow saturation regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x14,
                                      doff=0, dlen=6, lpo=2**32), tag=27),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_feat_lockdown_overflow_data), tag=27),
    # F57/F58 Command and Feature Lockdown (LID 14h), LPO=0xFFFFFFFFFFFFFFFC,
    # DOFST=4: LPO 64-bit ADDITION overflow regression (see block comment
    # above) -- distinct from F55/F56's narrowing-clamp overflow.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x14,
                                      doff=4, dlen=6, lpo=0xFFFFFFFFFFFFFFFC), tag=28),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_feat_lockdown_addition_overflow_data), tag=28),
    # F59/F60 Telemetry Host-Initiated (LID 07h), DOFST=512, DLEN=512:
    # exact-512-boundary regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x07,
                                      doff=512, dlen=512), tag=29),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_telemetry_block_at_boundary), tag=29),
    # F61/F62 Predictable Latency Event Aggregate (LID 0Bh), DOFST=5:
    # transport-offset-ignored regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0B,
                                      doff=5, dlen=10), tag=30),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_pred_lat_aggreg_off_data), tag=30),
    # F63/F64 Supported Log Pages (LID 00h), DOFST=2: 4-byte misalignment
    # regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x00,
                                      doff=2, dlen=6), tag=31),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_supported_misaligned_data), tag=31),
    # F65/F66 Changed Namespace List (LID 04h), DOFST=2: 4-byte misalignment
    # regression, different code shape than F63/F64 (see block comment
    # above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x04,
                                      doff=2, dlen=6), tag=32),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_changed_nslist_misaligned_data), tag=32),
    # F67/F68 Firmware Slot (LID 03h), DOFST=0, DLEN=1: AFI-exact-length
    # off-by-one regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x03,
                                      doff=0, dlen=1), tag=33),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_fw_slot_afi_exact_data), tag=33),
]

BASE_TS_ADMIN_LOGPAGE_WINDOWED_US = 1709377000 * 1_000_000

def build_admin_logpage_windowed_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_logpage_windowed):
        data += epb(pkt, BASE_TS_ADMIN_LOGPAGE_WINDOWED_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_logpage_windowed)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-features-windowed.pcapng — Set/Get Features windowed-transfer fixes
# ---------------------------------------------------------------------------
#
# packets_admin_features above always transfers FID data with DOFST=0 (a
# single, full-size window).  Four of dissect_nvme_set_features_transfer()'s
# FID handlers silently dropped that offset entirely when it was nonzero
# (APST, Timestamp, PLMC, HBS) -- unlike LBA Range Type and Host Metadata,
# which already received it correctly.  Set/Get Features has no NVMe-level
# offset field analogous to Get Log Page's LPO (struct nvme_cmd_ctx's
# set_features union arm is just `{ uint8_t fid; }`), so here the NVMe-MI
# transport offset (DOFST) is the only thing that needs to reach these
# decoders -- confirmed by dissect_nvme_set_features_transfer_lbart(), the
# one FID handler that was already off-aware, using its `off` parameter only
# for entry-index labeling, with no internal combination logic to mirror.
#
#   F1/F2  APST (FID 0Ch), DOFST=8, DLEN=8 -> 2nd Non-Operational Power
#          State Transition entry (struct offset 8:15)
#   F3/F4  Timestamp (FID 0Eh), DOFST=0, DLEN=8: this decoder took neither
#          `off` nor `len` before the fix -- a basic single-field transfer
#          proves both are now threaded through at all
#   F5/F6  PLMC (FID 13h), DOFST=0, DLEN=40 (<56): the trailing "rsvd1"
#          field's length (tvb, 56, len-56) previously underflowed `len`
#          whenever a transfer arrived shorter than 56 bytes -- exactly this
#          case
#   F7/F8  HBS (FID 16h), DOFST=0, DLEN=1: the trailing "rsvd" field
#          (tvb, 1, len-1) previously underflowed for any transfer of only
#          the 1-byte ACRE field with no reserved bytes following

_apst_entry1_data = bytes(range(0x90, 0x98))  # 2nd APST entry, struct [8:16)
_tst_data = bytes(range(0xA0, 0xA8))          # Timestamp structure, 8 bytes
_plmc_short_data = bytes(range(0xB0, 0xD8))   # 40 bytes: EE(2)+rsvd0(30)+dtwinrt(8)
_hbs_short_data = bytes([0x01])               # just ACRE, no trailing rsvd

# F9/F10 PLMC (FID 13h), DOFST=60 (>56, entirely inside the trailing "rsvd1"
# region): before the fallback fix, the guard "off <= 56 && ..." excluded
# this window entirely, so rsvd1 never rendered at all -- not underflow, but
# silently dropped data.  The fix falls back to poff=0, rendering the whole
# window as rsvd1.
_plmc_past_boundary_data = bytes.fromhex('1122334455667788')

# F11/F12 HBS (FID 16h), DOFST=5 (>1, entirely inside the trailing "rsvd"
# region): same fallback gap as PLMC above, for HBS's 1-byte-fixed-field
# boundary.
_hbs_past_boundary_data = bytes.fromhex('aabbcc')

# F13/F14 PLMC (FID 13h), DOFST=480 (>56, so poff=0 as in F9/F10) with an
# OVERSIZED DLEN=50: 2026-07-22 code review regression.  Neither PLMC nor
# HBS clamped the trailing field's rendered length to the structure's real
# 512-byte end the way every sibling decoder in this file does -- so an
# oversized/malformed transfer rendered bytes past the true end as
# "Reserved".  The correct cap here is (512-480)-poff(0)=32 bytes; a
# sentinel at the true 32-byte boundary proves the field stops there, not
# at the full (unclamped) 50 bytes requested.
_plmc_oversized_data = (bytes(28) + struct.pack('>I', 0xCAFEBABE)
                        + bytes([0xEE]) * 18)
assert len(_plmc_oversized_data) == 50

# F15/F16 HBS (FID 16h), DOFST=480 (>1, so poff=0), OVERSIZED DLEN=50 --
# same regression and same 32-byte correct cap as F13/F14 (HBS is also a
# 512-byte structure), different decoder.
_hbs_oversized_data = _plmc_oversized_data

packets_features_windowed = [
    # F1/F2 Auto Power State Transition (FID 0Ch), DOFST=8, DLEN=8
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0C,
                                      doff=8, dlen=8), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_apst_entry1_data), tag=0),
    # F3/F4 Timestamp (FID 0Eh), DOFST=0, DLEN=8
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0E,
                                      doff=0, dlen=8), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_tst_data), tag=1),
    # F5/F6 Predictable Latency Mode Config (FID 13h), DOFST=0, DLEN=40 (<56)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=0, dlen=40), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_plmc_short_data), tag=2),
    # F7/F8 Host Behavior Support (FID 16h), DOFST=0, DLEN=1
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x16,
                                      doff=0, dlen=1), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_hbs_short_data), tag=3),
    # F9/F10 PLMC (FID 13h), DOFST=60 (>56): trailing-field fallback
    # regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=60, dlen=8), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_plmc_past_boundary_data), tag=4),
    # F11/F12 HBS (FID 16h), DOFST=5 (>1): trailing-field fallback
    # regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x16,
                                      doff=5, dlen=3), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_hbs_past_boundary_data), tag=5),
    # F13/F14 PLMC (FID 13h), DOFST=480, DLEN=50 (oversized): trailing-field
    # missing-clamp regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=480, dlen=50), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_plmc_oversized_data), tag=6),
    # F15/F16 HBS (FID 16h), DOFST=480, DLEN=50 (oversized): same missing-
    # clamp regression as F13/F14 (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x16,
                                      doff=480, dlen=50), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_hbs_oversized_data), tag=7),
]

BASE_TS_FEATURES_WINDOWED_US = 1709378000 * 1_000_000

def build_features_windowed_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_features_windowed):
        data += epb(pkt, BASE_TS_FEATURES_WINDOWED_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_features_windowed)} packets to {output_path}")


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
    print()

    # nvme-mi-admin-decode.pcapng — Admin SQE CDW10-15 shared-decode coverage
    out3 = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
        captures_dir, 'nvme-mi-admin-decode.pcapng')
    build_admin_decode_pcapng(out3)
    print()

    # nvme-mi-admin-resp.pcapng — Admin response status + CQE DW0 decode (MR5)
    out4 = sys.argv[4] if len(sys.argv) > 4 else os.path.join(
        captures_dir, 'nvme-mi-admin-resp.pcapng')
    build_admin_resp_pcapng(out4)
    print()

    # nvme-mi-typemismatch.pcapng — cross-NMIMT slot-reuse guard coverage
    out5 = sys.argv[5] if len(sys.argv) > 5 else os.path.join(
        captures_dir, 'nvme-mi-typemismatch.pcapng')
    build_typemismatch_pcapng(out5)
    print()

    # nvme-mi-reserved-type.pcapng — Reserved NMIMT slot-tracking guard
    out5b = sys.argv[9] if len(sys.argv) > 9 else os.path.join(
        captures_dir, 'nvme-mi-reserved-type.pcapng')
    build_reserved_type_pcapng(out5b)
    print()

    # nvme-mi-mctp-bridge.pcapng — MCTP bridging: several Management Endpoints
    # behind one SMBus address (the only MCTP-over-SMBus framed fixture)
    out5c = sys.argv[10] if len(sys.argv) > 10 else os.path.join(
        captures_dir, 'nvme-mi-mctp-bridge.pcapng')
    build_mctp_bridge_pcapng(out5c)
    print()

    # nvme-mi-admin-identify.pcapng — Admin Identify response payload decode (MR6)
    out6 = sys.argv[6] if len(sys.argv) > 6 else os.path.join(
        captures_dir, 'nvme-mi-admin-identify.pcapng')
    build_admin_identify_pcapng(out6)
    print()

    # nvme-mi-admin-logpage.pcapng — Admin Get Log Page response payload (MR7)
    out7 = sys.argv[7] if len(sys.argv) > 7 else os.path.join(
        captures_dir, 'nvme-mi-admin-logpage.pcapng')
    build_admin_logpage_pcapng(out7)
    print()

    # nvme-mi-admin-features.pcapng — Admin Get/Set Features payload decode (MR8)
    out8 = sys.argv[8] if len(sys.argv) > 8 else os.path.join(
        captures_dir, 'nvme-mi-admin-features.pcapng')
    build_admin_features_pcapng(out8)
    print()

    # nvme-mi-admin-logpage-windowed.pcapng — multi-window Get Log Page
    # (DOFST!=0), cross-checked against NVMe Base 2.3 Figure 210
    out9 = sys.argv[11] if len(sys.argv) > 11 else os.path.join(
        captures_dir, 'nvme-mi-admin-logpage-windowed.pcapng')
    build_admin_logpage_windowed_pcapng(out9)
    print()

    # nvme-mi-features-windowed.pcapng — Set/Get Features windowed-transfer
    # fixes (APST, Timestamp, PLMC, HBS off-dropping + PLMC/HBS underflow)
    out10 = sys.argv[12] if len(sys.argv) > 12 else os.path.join(
        captures_dir, 'nvme-mi-features-windowed.pcapng')
    build_features_windowed_pcapng(out10)
