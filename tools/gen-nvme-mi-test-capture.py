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

def nvme_mi_header(msg_type, csi, is_response, ic=False, meb=False, ciap=False):
    b0 = 0x04 | (0x80 if ic else 0x00)  # bit 7 = IC (Integrity Check enabled)
    b1 = (msg_type << 3) | (csi & 0x01)
    if is_response:
        b1 |= 0x80
    # Byte 2 bit 0 = MEB, bit 1 = CIAP (bits 16 and 17 of the 32-bit LE header)
    b2 = (0x01 if meb else 0x00) | (0x02 if ciap else 0x00)
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
                          cdw11=0, cdw14=0, lpo=0, cdw12=None):
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

    cdw12, when given, fills CDW12 (and clears CDW13) instead of lpo -- the
    same dword pair, but Set Features reads CDW12 as a per-FID field rather
    than a Log Page Offset (e.g. Window Select for FID 14h).
    """
    payload  = bytes([opcode, flags]) + struct.pack('<H', ctrl_id)
    payload += b'\x00' * 20          # SQE1-SQE5
    payload += struct.pack('<I', doff)  # data offset
    payload += struct.pack('<I', dlen)  # data length
    payload += b'\x00' * 8           # reserved
    payload += struct.pack('<I', cns)    # CDW10 (CNS / identify selector)
    payload += struct.pack('<I', cdw11)  # CDW11
    if cdw12 is None:
        payload += struct.pack('<Q', lpo)      # CDW12-CDW13 (Log Page Offset)
    else:
        payload += struct.pack('<II', cdw12, 0)  # CDW12, CDW13
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
                host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0, ic=False, meb=False,
                ciap=False):
    src_eid  = host_eid if is_request else bmc_eid
    sll      = sll_header(src_eid, outgoing=is_request)
    mctp     = mctp_header(is_request, host_eid=host_eid, bmc_eid=bmc_eid, tag=tag)
    nvme_hdr = nvme_mi_header(msg_type, csi, is_response=not is_request, ic=ic,
                              meb=meb, ciap=ciap)
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
    # (CONFIGID=04h in NMD0 bits 7:0).  NMD0 also carries the Set-only fields
    # of Figure 91: ENCFA (bit 24), AEM Delay (bits 23:16) and AEM Retry Delay
    # (bits 15:08).  The request carries an AE Enable List (Figures 92/93) as
    # Request Data: two AE Enable entries — Composite Temperature (ID 06h)
    # enabled, SMART Warnings (ID 09h) disabled.
    ae_list = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])  # NUMAEE=2, ver=0, AEETL=11, AEELHL=5
               + bytes([3]) + struct.pack('<H', 0x8006)            # AEE=1, ID=06h
               + bytes([3]) + struct.pack('<H', 0x0009))           # AEE=0, ID=09h
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x03, cdw0=0x01050A04) + ae_list,
                         ciap=True))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F106-F107: Configuration Get of the Asynchronous Event configuration.
    # NMD0 carries only the CONFIGID (the Set-only fields of Figure 91 are
    # reserved here, Figure 80); the Success Response returns AEELVER in the
    # NVMe Management Response and an AE Supported List (Figures 82/83) as
    # Response Data — Composite Temperature (ID 06h) currently enabled,
    # PCIe Link Active (ID 0Bh) supported but disabled.
    aes_list = (bytes([2, 1]) + struct.pack('<H', 11) + bytes([5])  # NUMAES=2, ver=1, AESTL=11, AESLHL=5
                + bytes([3]) + struct.pack('<H', 0x8006)            # AESE=1, ID=06h
                + bytes([3]) + struct.pack('<H', 0x000B))           # AESE=0, ID=0Bh
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x00000004)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       aes_list, nmresp=1)))

    assert len(p) == 107, f"Expected 107 frames, got {len(p)}"
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
        "F104: MI Req   CSI=0  Config Set CID=04h (Async Event) + AE Enable List, CIAP=1",
        "F105: MI Resp  CSI=0  status=0x00 -> F104",
        "F106: MI Req   CSI=0  Config Get CID=04h (Async Event)",
        "F107: MI Resp  CSI=0  status=0x00 + AE Supported List -> F106",
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
#   F12  Directive Send (19h)  Prohibited over MI (Figure 134) -> prohibited-opcode
#                              expert; regression case for the opcodes added to
#                              nvme_mi_admin_opcode_prohibited() alongside F11's
#                              original coverage.
#   F13  Virt Mgmt (1Ch)       Permitted over MI, adjacent to F12 in the opcode
#                              enum -> must NOT raise the prohibited-opcode expert

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
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x19, ctrl_id=0x000c), tag=11),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x1c, ctrl_id=0x000d), tag=12),
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
#   F9/F10 Identify (06h) rejected by Command and Feature Lockdown
#          -> status SCT=0 (Generic) SC=23h Command Prohibited by Command
#          and Feature Lockdown (Base 2.3 Figure 102), DNR=1 -- the status
#          NVMe-MI 2.1 Figure 29's own Access Denied ties to Command and
#          Feature Lockdown; this is the tunneled-Admin-command side of it.

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
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0005, cns=0x01), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0,
                                       cqe3=admin_cqe3(cqe_status_word(sct=0, sc=0x23, dnr=1))),
                tag=4),
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
#   F3/F4   Identify Namespace (CNS 00h)         -> NSZE/NCAP + bytes 103:31
#   F5/F6   Active Namespace ID List (CNS 02h)   -> nsid[0..2]
#   F7/F8   NS Identification Descriptor (CNS 03h) -> EUI64 + NGUID descriptors
#   F9/F10  Controller List (CNS 13h)            -> NUMCIDS + controller IDs
#   F11/F12 Identify Controller, DOFF=24 window  -> MN decoded at structure off 24

def identify_ctrl_data(vid=0x144d, ssvid=0x1014, sn="SERIAL01234567890123",
                       mn="WIRESHARK MODEL NUMBER", cntlid=0x0007, total=4096):
    """Partial Identify Controller data structure (NVMe Base 2.3 Fig 328).

    Every field below carries a distinct non-zero value so that a decoder
    reading at the wrong offset reports a visibly wrong number rather than a
    plausible zero.  The genuinely-Reserved runs are deliberately left as
    zeroes, so a Reserved item that is one byte too long picks up a neighbour's
    non-zero value and the length assertions in suite_dissection_nvme_mi.py
    catch it.
    """
    buf = bytearray(total)
    struct.pack_into('<H', buf, 0, vid)
    struct.pack_into('<H', buf, 2, ssvid)
    buf[4:24]  = sn.encode('ascii')[:20].ljust(20, b' ')
    buf[24:64] = mn.encode('ascii')[:40].ljust(40, b' ')
    struct.pack_into('<H', buf, 78, cntlid)

    # 110:102 -- BPCAP / Reserved / NSSL / Reserved / PLSI  (Fig 328)
    buf[102] = 0x06                     # BPCAP: SFBPWPS=1, RPMBBPWPS=10b
    struct.pack_into('<I', buf, 104, 0x00112233)   # NSSL, microseconds
    buf[110] = 0x03                     # PLSI: PLSFQ=1, PLSEPF=1

    # 143:134 -- CRCAP / CIU / CIRN
    buf[134] = 0x03                     # CRCAP: RGIDC=1, RRSUP=1
    buf[135] = 0x5a                     # CIU
    struct.pack_into('<Q', buf, 136, 0x0123456789abcdef)   # CIRN

    # 395:356 -- DID .. MSMT
    struct.pack_into('<H', buf, 356, 0xbeef)       # DID
    buf[358] = 0x03                     # KPIOC: KPIOSC=1, KPIOS=1
    struct.pack_into('<H', buf, 360, 0x0037)       # MPTFAWR, 100 ms units
    struct.pack_into('<Q', buf, 368, 0x0000000100000000)   # MEGCAP lo (4 GiB)
    buf[384] = 0x05                     # TMPTHHA: TMPTHMH=5
    buf[385] = 0x02                     # MUPA: MUPS=10b (0.01 W)
    struct.pack_into('<H', buf, 386, 0x0271)       # CQT (mandatory), ms
    struct.pack_into('<H', buf, 388, 0x0001)       # CDPA: HS3=1
    struct.pack_into('<H', buf, 390, 0x04d2)       # MUP
    struct.pack_into('<H', buf, 392, 0x0464)       # IPMSR: SRS=4h, SRV=100
    struct.pack_into('<H', buf, 394, 0x162e)       # MSMT

    # 587:544 -- MAXDNA .. MCDQPC
    struct.pack_into('<Q', buf, 544, 0x0000000000015b3f)   # MAXDNA lo (88895)
    struct.pack_into('<I', buf, 560, 0x00000401)   # MAXCNA
    struct.pack_into('<I', buf, 564, 0x00000c80)   # OAQD
    buf[568] = 0x5a                     # RHIRI, days
    buf[569] = 0x1e                     # HIRT, minutes
    struct.pack_into('<H', buf, 570, 0x0101)       # CMMRTD
    struct.pack_into('<H', buf, 572, 0x0202)       # NMMRTD
    buf[574] = 0x0c                     # MINMRTG
    buf[575] = 0x2a                     # MAXMRTG
    buf[576] = 0x07                     # TRATTR: MRTLL=1, TUDCS=1, THMCS=1
    struct.pack_into('<H', buf, 578, 0x0303)       # MCUDMQ
    struct.pack_into('<H', buf, 580, 0x0404)       # MNSUDMQ
    struct.pack_into('<H', buf, 582, 0x0505)       # MCMR
    struct.pack_into('<H', buf, 584, 0x0606)       # NMCMR
    struct.pack_into('<H', buf, 586, 0x0707)       # MCDQPC

    # 1807:1792 -- NVMe over Fabrics section
    struct.pack_into('<I', buf, 1792, 0x00000104)  # IOCCSZ
    struct.pack_into('<I', buf, 1796, 0x00000011)  # IORCSZ
    struct.pack_into('<H', buf, 1800, 0x0002)      # ICDOFF
    buf[1802] = 0x03                    # FCATT: NZNSETIDS=1, DCMS=1
    buf[1803] = 0x10                    # MSDBD
    struct.pack_into('<H', buf, 1804, 0x0001)      # OFCS: DCS=1
    buf[1806] = 0x02                    # DCTYPE: CDC
    buf[1807] = 0x09                    # CCRL

    return bytes(buf)

def identify_ns_data(nsze=0x100000, ncap=0x80000, nlbaf=2, nulbaf=47,
                     total=4096):
    """Partial Identify Namespace data structure (NVM Command Set 1.2 Fig 114).

    Bytes 103:31 used to produce no tree item at all.  Every field below now
    carries a distinct non-zero value so a decoder reading at the wrong offset
    reports a visibly wrong number rather than a plausible zero; the three
    genuinely-Reserved runs (83, 91:88 and 98:96) stay zero-filled, so their
    lengths are pinned separately in suite_dissection_nvme_mi.py.

    The buffer is filled to byte 383 -- the end of the LBA Format region -- and
    then truncated to `total`, so a caller modelling a DLEN-truncated transfer
    (total < 384) still gets the real structure's leading bytes.
    """
    buf = bytearray(max(total, 384))
    struct.pack_into('<Q', buf, 0, nsze)
    struct.pack_into('<Q', buf, 8, ncap)
    buf[25] = nlbaf                                # NLBAF, 0's based

    # 103:31 -- the formerly undecoded gap
    buf[31] = 0x1f                                 # RESCAP
    buf[32] = 0x87                                 # FPI: FPSUPP=1, 7% remaining
    buf[33] = 0x19                                 # DLFEAT: GDS=1, WZDS=1, DRB=1
    struct.pack_into('<H', buf, 34, 257)           # NAWUN
    struct.pack_into('<H', buf, 36, 514)           # NAWUPF
    struct.pack_into('<H', buf, 38, 771)           # NACWU
    struct.pack_into('<H', buf, 40, 1028)          # NABSN
    struct.pack_into('<H', buf, 42, 1285)          # NABO
    struct.pack_into('<H', buf, 44, 1542)          # NABSPF
    struct.pack_into('<H', buf, 46, 1799)          # NOIOB
    struct.pack_into('<Q', buf, 48, 549755813888)  # NVMCAP low 8 of 16 (512 GiB)
    struct.pack_into('<H', buf, 64, 2056)          # NPWG
    struct.pack_into('<H', buf, 66, 2313)          # NPWA
    struct.pack_into('<H', buf, 68, 2570)          # NPDG
    struct.pack_into('<H', buf, 70, 2827)          # NPDA
    struct.pack_into('<H', buf, 72, 3084)          # NOWS
    struct.pack_into('<H', buf, 74, 3341)          # MSSRL
    struct.pack_into('<I', buf, 76, 0x00112233)    # MCL
    buf[80] = 43                                   # MSRC
    buf[81] = 0x03                                 # KPIOS: KPIOSNS=1, KPIOENS=1
    buf[82] = nulbaf                               # NULBAF (Mandatory)
    # 83 Reserved
    struct.pack_into('<I', buf, 84, 0x00445566)    # KPIODAAG
    # 91:88 Reserved
    struct.pack_into('<I', buf, 92, 0x0000abcd)    # ANAGRPID
    # 98:96 Reserved
    buf[99] = 0x01                                 # NSATTR: write protected
    struct.pack_into('<H', buf, 100, 0x1357)       # NVMSETID
    struct.pack_into('<H', buf, 102, 0x2468)       # ENDGID

    # 383:128 LBA Formats: sixty-four 4-byte LBAFn entries (Fig 114), each
    # laid out per Fig 116 -- RP 25:24, LBADS 23:16, MS 15:00.  Entries 15:00
    # used to be the whole decoded region and 383:192 (LBAF63..LBAF16) was
    # rendered as one "Reserved" run, so every index carries a distinct value
    # and the supported count deliberately runs past 15: NLBAF is 0's based,
    # NULBAF is not, and section 5.5 packs the unique-attribute formats
    # directly after the shared-attribute ones, so (2+1)+47 = 50 are supported.
    for i in range(nlbaf + 1 + nulbaf):
        struct.pack_into('<I', buf, 128 + i * 4,
                         ((i & 0x3) << 24)           # RP
                         | ((9 + i % 4) << 16)       # LBADS
                         | i)                        # MS -- unique per index

    return bytes(buf[:total])

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

def _identify_ctrl_latency_data():
    """identify_ctrl_data() with the four BASE_CUSTOM latency/atomicity fields
    filled in (see F15/F16 below).  Patched into a private copy rather than set
    in identify_ctrl_data() itself: that helper's byte offsets are shared by
    every Identify Controller frame in the corpus, so a new frame with its own
    values cannot disturb an existing assertion."""
    buf = bytearray(identify_ctrl_data())
    struct.pack_into('<I', buf, 84, 1500000)   # RTD3R  87:84, microseconds
    struct.pack_into('<I', buf, 88, 2500000)   # RTD3E  91:88, microseconds
    struct.pack_into('<H', buf, 526, 1)        # AWUN  527:526, 0's based
    struct.pack_into('<H', buf, 528, 3)        # AWUPF 529:528, 0's based
    return bytes(buf)

_ID_CTRL_LATENCIES = _identify_ctrl_latency_data()

def identify_cs_ind_ns_data(total=4096):
    """I/O Command Set Independent Identify Namespace, CNS 08h (NVMe Base 2.3
    Figure 335).  Every field carries a distinct, asymmetric, non-zero value so
    a decoder reading at the wrong offset, with the wrong mask, or with the
    wrong endianness renders a visibly wrong number rather than a plausible
    zero.  The Reserved runs stay zero."""
    buf = bytearray(total)
    buf[0]  = 0x38                               # 00    NSFEAT: VWCNP|RMEDIA|UIDREUSE
    buf[1]  = 0x03                               # 01    NMIC: DISNS|SHRNS
    buf[2]  = 0xa5                               # 02    RESCAP: IEKS|WEARS|EAS|PTPLS
    buf[3]  = 0x99                               # 03    FPI: FPIS=1, RFNVM=25
    struct.pack_into('<I', buf, 4, 0x12345678)   # 07:04 ANAGRPID
    buf[8]  = 0x01                               # 08    NSATTR: CWP
    struct.pack_into('<H', buf, 10, 0xabcd)      # 11:10 NVMSETID
    struct.pack_into('<H', buf, 12, 0x1234)      # 13:12 ENDGID
    buf[14] = 0x07                               # 14    NSTAT: IOI=11b, NRDY=1
    buf[15] = 0x03                               # 15    KPIOS: KPIOSNS|KPIOENS
    struct.pack_into('<H', buf, 16, 0x0042)      # 17:16 MAXKT
    struct.pack_into('<I', buf, 20, 0xcafebabe)  # 23:20 RGRPID
    return bytes(buf)

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
    # F15/F16 Identify Controller (CNS 01h) with the four BASE_CUSTOM-formatted
    # latency/atomicity fields non-zero.  identify_ctrl_data() leaves all four
    # at 0, and every other in-tree capture does too, so add_ctrl_rtd3() and
    # add_ctrl_lblocks() only ever ran down their zero/singular branches --
    # their plural branches yielded the literal two-character string "%s",
    # which the format's own %s then consumed ("1500000 microsecond%s",
    # "2 logical block%s").  Distinct values so a formatter reading the wrong
    # field is visible:
    #   RTD3R 87:84 = 1500000, RTD3E 91:88 = 2500000 (Base 2.3 Figure 328,
    #   microseconds), AWUN 527:526 = 1, AWUPF 529:528 = 3 (0's based, so they
    #   render as 2 and 4 logical blocks).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ID_CTRL_LATENCIES), tag=7),
    # F17/F18 Identify I/O Command Set specific Identify Controller data
    # structure (CNS 06h) with CDW11 CSI = 02h (Zoned Namespace Command Set).
    # CNS 06h is Mandatory in NVMe 2.x and is meaningless without CSI, but the
    # CDW11 Reserved run used to cover 31:16 and hide the field entirely
    # (NVMe Base 2.3 Figure 324: Reserved 23:16, CSI 31:24).  The response is a
    # plain success, so this pair pins the command-side decode alone.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x06,
                                      cdw11=0x02000000), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))),
                tag=8),
    # Identify Namespace (CNS 00h) claiming more LBA Formats than exist.
    # NLBAF is 0's based, so nlbaf=63 means 64 shared-attribute formats, and
    # nulbaf=10 adds ten more: 74 in total, where NVM Command Set 1.2 section
    # 5.5 caps the 383:128 region at 64 entries.  The count is impossible on
    # its own terms rather than merely unseen -- no transfer window can make it
    # legitimate -- so it is reported rather than silently clamped, while the
    # 64 formats that do fit still decode.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x00), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ns_data(nlbaf=63, nulbaf=10)),
                tag=9),
    # F21/F22 I/O Command Set Independent Identify Namespace (CNS 08h): the
    # fixed 24-byte header (NVMe Base 2.3 Figure 335) with every field distinct
    # so a wrong offset/mask/endianness is visible.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x08), tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_cs_ind_ns_data()), tag=10),
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

def smart_data(ct=320, asc=100, ast=10, pu=5, poh=12345, total=512, cw=0x00):
    """Partial SMART / Health Information log page (NVMe Base 2.3 Fig 207)."""
    buf = bytearray(total)
    buf[0] = cw                            # 00 Critical Warning (Fig 210)
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

# Error Information Log Entry Reserved field, NVMe Base 2.3 Figure 209 bytes
# 62:42 -- exactly 21 bytes.  A distinctive run so an oversized Reserved item
# (the pre-fix 24 bytes, which ran past LPVER at 63 and two bytes into the next
# entry) fails the equality assertion on length as well as on content.
ERRINF_RSVD1 = bytes(range(0xA0, 0xB5))
assert len(ERRINF_RSVD1) == 21

def error_info_data(errcnt=42, sqid=3, cid=0x00ab, vsia=0x81, trtype=0x03,
                    csi=0x02, opc=0x09, csinfo=0x1122334455667788, ttsi=0x1234,
                    lpver=0x01, total=128, pel=0x0000):
    """Error Information log: the decoded first 64-byte entry (NVMe Base 2.3
    Fig 209) plus a second entry, so an entry-1 field that overruns byte 63 is
    visible.  Every field carries a distinct non-zero value, and the second
    entry is filled with 0xEE, so an off-by-one offset shows up as a wrong
    number rather than a plausible zero.

    Parameters use the spec's abbreviations, which do NOT line up with the
    display filter names: byte 30 CSI (Command Set Indicator) is filter
    .cmdset, and byte 32 CSINFO (Command Specific Information) is filter .csi
    -- the latter was registered upstream in 2021 and cannot be reassigned."""
    buf = bytearray(b'\xee' * total)
    buf[0:64] = bytes(64)
    struct.pack_into('<Q', buf, 0, errcnt)   # 07:00 Error Count
    struct.pack_into('<H', buf, 8, sqid)     # 09:08 Submission Queue ID
    struct.pack_into('<H', buf, 10, cid)     # 11:10 Command ID
    struct.pack_into('<H', buf, 14, pel)     # 15:14 Parameter Error Location
    buf[28] = vsia                           # 28    Vendor Specific Info Available
    buf[29] = trtype                         # 29    Transport Type
    buf[30] = csi                            # 30    Command Set Indicator -> .cmdset
    buf[31] = opc                            # 31    Opcode
    struct.pack_into('<Q', buf, 32, csinfo)  # 39:32 Command Specific Info -> .csi
    struct.pack_into('<H', buf, 40, ttsi)    # 41:40 Transport Type Specific Info
    buf[42:63] = ERRINF_RSVD1                # 62:42 Reserved
    buf[63] = lpver                          # 63    Log Page Version
    return bytes(buf)

# Endurance Group Information Reserved field, NVMe Base 2.3 Figure 222 bytes
# 31:08 -- exactly 24 bytes.  Distinctive for the same reason as ERRINF_RSVD1:
# the pre-fix item was 26 bytes starting at byte 6, swallowing the Domain
# Identifier.
EGROUP_RSVD1 = bytes(range(0xC0, 0xD8))
assert len(EGROUP_RSVD1) == 24

def egroup_data(cw=0x0c, egfeat=0x01, avsp=100, avspt=10, pused=7, did=0x1234,
                tegcap=0x1122334455667788, uegcap=0x99aabbccddeeff11,
                total=512):
    """Endurance Group Information log page (NVMe Base 2.3 Fig 222).

    Critical Warning deliberately clears bit 0 (EGASB) while Endurance Group
    Features sets bit 0 (EGRMEDIA), so reading EGRMEDIA one byte early would
    report '0' instead of '1'.

    TEGCAP (175:160) and UEGCAP (191:176) are 16-byte byte-counts; only the
    low 8 bytes are set.  Their values are distinct byte patterns with no
    repeated or zero bytes, so a swapped or shifted offset renders a visibly
    different hex string rather than another plausible capacity."""
    buf = bytearray(total)
    buf[0] = cw                              # 00    Endurance Group Critical Warning
    buf[1] = egfeat                          # 01    Endurance Group Features
    buf[3] = avsp                            # 03    Available Spare
    buf[4] = avspt                           # 04    Available Spare Threshold
    buf[5] = pused                           # 05    Percentage Used
    struct.pack_into('<H', buf, 6, did)      # 07:06 Domain Identifier
    buf[8:32] = EGROUP_RSVD1                 # 31:08 Reserved
    struct.pack_into('<Q', buf, 160, tegcap) # 175:160 TEGCAP (low 8 of 16)
    struct.pack_into('<Q', buf, 176, uegcap) # 191:176 UEGCAP (low 8 of 16)
    return bytes(buf)

def cmd_feat_lockdown_data(ss, cs=0, cfil=(0x02, 0x04, 0x06)):
    """Command and Feature Lockdown log page (NVMe Base 2.3 Fig 271).

    CFILA byte 0 carries Scope Selected in bits 3:0 and Contents Selected in
    bits 5:4, byte 3 is the list length, and the Command and Feature Identifier
    List follows.  Figure 271 makes the list's contents depend on Scope, so the
    same byte names an Admin opcode under Scope 0h and a Set Features Feature
    Identifier under Scope 2h.

    The default list is chosen so every byte resolves to a *different* name in
    the two tables -- 02h is Get Log Page or Power Management, 04h is Delete CQ
    or Temperature Threshold, 06h is Identify or Volatile Write Cache -- so a
    decoder that ignores Scope, or reads it from the wrong place, cannot
    produce the expected strings by coincidence."""
    return bytes([(cs & 0x3) << 4 | (ss & 0xf), 0x00, 0x00, len(cfil)]) + bytes(cfil)


def pred_lat_data(status=0x01, etype=0xC000, total=512):
    """Predictable Latency Per NVM Set log page (NVMe Base 2.3 Fig 224).

    Figure 224 has no NVM Set Identifier field: the set this page describes is
    named only by the Log Specific Identifier of the request (Fig 223), so this
    fixture exists to pin that the label comes from the request.

    status = 01h -> PLMW 001b (Deterministic Window).  etype = C000h sets both
    DEAT (bit 15) and MVEAT (bit 14), the two highest bits, so an Event Type
    mask that is one bit short drops a set bit rather than silently agreeing.
    The five 8-byte estimates use distinct byte patterns with no repeated or
    zero bytes, so a shifted offset renders a visibly different value."""
    d = bytearray(total)
    d[0] = status
    struct.pack_into('<H', d, 2, etype)
    struct.pack_into('<Q', d,  32, 0x1122334455667788)  # DTWIN Reads Typical
    struct.pack_into('<Q', d,  40, 0x99aabbccddeeff11)  # DTWIN Writes Typical
    struct.pack_into('<Q', d,  48, 0x2233445566778899)  # DTWIN Time Maximum
    struct.pack_into('<Q', d,  56, 0x33445566778899aa)  # NDWIN Time Min High
    struct.pack_into('<Q', d,  64, 0x445566778899aabb)  # NDWIN Time Min Low
    struct.pack_into('<Q', d, 128, 0x5566778899aabbcc)  # DTWIN Reads Estimate
    struct.pack_into('<Q', d, 136, 0x66778899aabbccdd)  # DTWIN Writes Estimate
    struct.pack_into('<Q', d, 144, 0x778899aabbccddee)  # DTWIN Time Estimate
    return bytes(d)


def ana_data(chgc=7, agid=3, nnv=1, grp_chgc=9, anasa=0x31, nsid=0x0000002a):
    """Asymmetric Namespace Access log page (NVMe Base 2.3 Figures 227/228):
    a 16-byte header then one ANA Group Descriptor plus its NSID list.

    ANASA (descriptor byte 16) defaults to 31h -- ANAS = 1h (Optimized) in
    bits 03:00 and a non-zero Reserved nibble in bits 07:04, so the group's
    container item is distinguishable from the ANA state it contains."""
    buf = bytearray(16)
    struct.pack_into('<Q', buf, 0, chgc)     # 07:00 Change Count
    struct.pack_into('<H', buf, 8, 1)        # 09:08 Number of ANA Group Descriptors
    desc = bytearray(32)
    struct.pack_into('<I', desc, 0, agid)    # 03:00 ANA Group ID
    struct.pack_into('<I', desc, 4, nnv)     # 07:04 Number of NSID Values
    struct.pack_into('<Q', desc, 8, grp_chgc)  # 15:08 Change Count
    desc[16] = anasa                         # 16    ANA State Attributes
    return bytes(buf + desc + struct.pack('<I', nsid))

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
    # F9/F10 Endurance Group Information (LID 09h)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x09), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(egroup_data()), tag=4),
    # F11/F12 SMART (LID 02h) again, but exercising two mask boundaries that
    # three upstream packet-nvme.c defects straddled:
    #   request  CDW10 = FF02h -> LID 02h, LSP 7Fh, RAE 1 (NVMe Base 2.3
    #            Figure 201: 14:08 LSP).  Bits 14:13 are set, so an LSP mask
    #            of only 12:08 reports 1Fh and spills the rest into "Reserved",
    #            and RAE must stay 1.
    #   response Critical Warning = E1h -> bit 7 Reserved, bit 6 IPS, bit 5
    #            PMRRO, bit 0 ASCBT (NVMe Base 2.3 Figure 210).  Bits on both
    #            sides of the Reserved boundary, so a Reserved mask of E0h
    #            reports 7 and leaves IPS with no field at all.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0xFF02), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data(cw=0xE1)), tag=5),
    # F13/F14 Error Information (LID 01h) with a non-zero Parameter Error
    # Location: bytes 15:14 = 852Ah -> BYTLOC 2Ah (07:00), BITLOC 5h (10:08),
    # Reserved bit 15 (NVMe Base 2.3 Figure 209).  All three sub-fields carry
    # bits, so a BITLOC mask that reaches down into BYTLOC, or a Reserved mask
    # that does, reports a contaminated number.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x01), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(error_info_data(pel=0x852A)), tag=6),
    # F15/F16 Asymmetric Namespace Access (LID 0Ch): header + one full ANA
    # Group Descriptor.  ANASA = 31h exercises the group's container item,
    # which spans the whole byte and so must carry no mask of its own.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x0c), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(ana_data()), tag=7),
    # F17/F18 SMART (LID 02h) with all three CDW14 sub-fields set at once:
    # CDW14 = 0280_0045h -> UUID Index 45h (06:00), Offset Type 1 (bit 23),
    # CSI 02h (31:24), Reserved 22:07 zero (NVMe Base 2.3 Figure 205).
    # UIDX was masked 0x3f, one bit too narrow, so 45h reported as 05h, and the
    # Reserved run covered 31:07 -- swallowing both OT and CSI.  Bit 6 of UIDX
    # and bits on both sides of Reserved, so any of the three masks being wrong
    # shows up as a different number rather than a missing field.  The response
    # is a plain success, so this pair pins the command-side decode alone.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x02,
                                      cdw14=0x02800045), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))),
                tag=8),
    # F19/F20 Endurance Group Information (LID 09h) for a *nonzero* Endurance
    # Group, and F21/F22 Predictable Latency Per NVM Set (LID 0Ah) for a
    # nonzero NVM Set.  Neither Figure 222 nor Figure 224 contains the
    # identifier the host asked for -- it appears only in the request's Log
    # Specific Identifier (CDW11 31:16, Figures 221/223) -- so without carrying
    # it across, two responses for different groups/sets are byte-identical in
    # the tree.  The F9/F10 pair above already covers LID 09h but with LSI 0,
    # which cannot tell "read the LSI" apart from "print a zero"; these use
    # 0007h and 0003h so the rendered label has to match the request.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x09,
                                      cdw11=0x00070000), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(egroup_data()), tag=9),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x0a,
                                      cdw11=0x00030000), tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(pred_lat_data()), tag=10),
    # F23/F24 and F25/F26 Command and Feature Lockdown (LID 14h): two responses
    # carrying a *byte-identical* Command and Feature Identifier List and
    # differing only in CFILA's Scope Selected field -- 0h (Admin Command Set
    # opcodes) then 2h (Set Features Feature Identifiers).
    #
    # Figure 271 defines the list's contents in terms of Scope, so those same
    # three bytes name six different things across the pair.  Any difference
    # between the two dissections is therefore caused solely by Scope, which is
    # what makes this a test of the lookup and not of the list walk.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x14), tag=11),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(cmd_feat_lockdown_data(ss=0)), tag=11),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x14), tag=12),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(cmd_feat_lockdown_data(ss=2)), tag=12),
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
F_HOST_CNTL_THERM_MGMT   = 0x10
F_LBA_RANGE_TYPE         = 0x03
F_PRED_LAT_MODE_WIND     = 0x14
F_NS_WRITE_CONF          = 0x84
F_IRQ_VECTOR_CONF        = 0x09
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
    # F9/F10 Set Features Host Controlled Thermal Management (FID 10h).
    # CDW11 = 0154_015Eh -> TMT1 = 0154h (340 K) in bits 31:16, TMT2 = 015Eh
    # (350 K) in bits 15:00 (NVMe Base 2.3 Figure 417).  The two halves differ,
    # so a sub-field registered without a bitmask (which renders the whole
    # dword) is distinguishable from either temperature.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0005,
                                      cns=F_HOST_CNTL_THERM_MGMT,
                                      cdw11=0x0154015E), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=4),
    # F11/F12 Get Features HCTM (FID 10h): the same Figure 417 layout is
    # returned in CQE DW0, decoded by a separate hf array with the same defect.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0005,
                                      cns=F_HOST_CNTL_THERM_MGMT), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0154015E,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=5),
    # F13..F22: the five Set/Get Features group members whose display name was
    # a copy of the container's -- "DWORD11", "DWORD12" or "DWORD0" -- so each
    # subtree showed identically-named rows and none of the fields could be
    # identified by label.  Every value below is non-zero and distinct from its
    # neighbours, so a member reading the wrong bits is visible in the value as
    # well as the name.
    #
    # F13..F16 Set/Get Features LBA Range Type (FID 03h): NUM 05:00 of CDW11
    # (Set, NVM Command Set 1.2 Figure 93) and of CQE DWORD0 (Get, Figure 94).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0006,
                                      cns=F_LBA_RANGE_TYPE, cdw11=0x00000005),
                tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=6),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0006,
                                      cns=F_LBA_RANGE_TYPE), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x00000007,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=7),
    # F17..F20 Set/Get Features Namespace Write Protection Config (FID 84h):
    # WPS 02:00 -- NVMe Base 2.3 Figure 470.  02h = Write Protect Until Power
    # Cycle on the Set side, 03h = Permanent Write Protect on the Get side, so
    # the two frames cannot be confused.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0007,
                                      cns=F_NS_WRITE_CONF, cdw11=0x00000002),
                tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=8),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0007,
                                      cns=F_NS_WRITE_CONF), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x00000003,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=9),
    # F21/F22 Set Features Predictable Latency Mode Window (FID 14h): WSEL
    # 02:00 of CDW12 -- NVMe Base 2.3 Figure 425.  01h = Deterministic Window.
    # CDW11 carries the NVM Set Identifier, left 0 so the two dwords differ.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0008,
                                      cns=F_PRED_LAT_MODE_WIND, cdw12=0x00000001),
                tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=10),
    # F23/F24 Set Features Interrupt Vector Configuration (FID 09h): IV 15:00,
    # CD bit 16, Reserved 31:17 of CDW11 (NVMe Base 2.3 Figure 475).  IV=1234h,
    # CD=0, plus a synthetic Reserved bit (20) set -- upstream registered IV
    # with mask 0 (so it rendered the whole dword, picking up the Reserved
    # bit) and CD with a 17-bit mask covering IV as well (so it read "set"
    # whenever IV was nonzero, wrongly true here since IV != 0 but CD is
    # really clear). Both defects are visible as wrong values with this CDW11.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0009,
                                      cns=F_IRQ_VECTOR_CONF, cdw11=0x00101234),
                tag=11),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=11),
    # F25/F26 Get Features IRQV (FID 09h): the same Figure 475 layout is
    # returned in CQE DW0, decoded by a separate hf array with the same defect.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0009,
                                      cns=F_IRQ_VECTOR_CONF), tag=12),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x00101234,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=12),
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
# (struct offset 48 onward) NEVER rendered here regardless of off, because
# the bail-out condition was inverted ("if (poff <= len) return;" instead of
# "if (len <= poff) return;") -- it incorrectly bailed out exactly when there
# WAS enough data.  48 bytes of defined fields (0:48) + 16 distinctive
# trailing bytes.
#
# SSTAT carries Sanitize Operation Status = 010b (Sanitizing) with both the
# Media Verification Canceled and Namespace Data Erased bits set, so the two
# bits NVMe Base 2.3 Figure 302 defines above Global Data Erased are covered.
_sanitize_fixed_fields = (struct.pack('<HH', 0, 0x0602)  # sprog, sstat
                          + bytes(28))                   # scdw10..etcend, zero
_sanitize_state_fields = (struct.pack('<I', 90)          # etpvds
                          + bytes([0x25])                # ssi: FAILS=2, SANS=5
                          + bytes(3)                     # reserved
                          + struct.pack('<I', 4)         # mnsoip
                          + struct.pack('<I', 0x0000002A))  # stnsid
_sanitize_trailing_data = bytes(range(0x90, 0xA0))       # struct offset 48:64
_sanitize_data = (_sanitize_fixed_fields + _sanitize_state_fields
                  + _sanitize_trailing_data)
assert len(_sanitize_data) == 64

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

# ---------------------------------------------------------------------------
# F69..F74: three pre-existing UPSTREAM packet-nvme.c defects (present in
# Wireshark since 2021/2022, not introduced by this project).
# ---------------------------------------------------------------------------

# F69/F70: ANA (LID 0Ch) windowed to LPO=16, DLEN=4 -- a window that starts
# exactly at ANA Group Descriptor 0 and carries only its 4-byte ANA Group ID.
# dissect_nvme_get_logpage_ana_resp_grp()'s entry guard is "len < 4", but the
# fresh-descriptor path then read Number of NSID Values (NVMe Base 2.3
# Figure 228, bytes 07:04) unconditionally, which needs len >= 8: a 4..7-byte
# window threw BoundsError and rendered the frame "[Malformed Packet]"
# instead of decoding the Group ID it did carry.  A distinctive AGID proves
# the guarded path still decodes the field rather than merely not throwing.
_ana_grp_id_only = struct.pack('<I', 0x0000002A)

# F71/F72: Commands Supported and Effects (LID 05h) windowed to LPO=1020,
# DLEN=16 -- straddling the ACS/IOCS boundary (NVMe Base 2.3 Figure 213:
# ACS0..255 at bytes [0:1024), IOCS0..255 at [1024:2048)).  That yields
# exactly one ACS record (ACS255, struct 1020) followed by three IOCS records
# (IOCS0..2, struct 1024/1028/1032), which is the smallest window that covers
# both of dissect_nvme_get_logpage_cmd_sup_and_eff_grp()'s defects at once:
#   - the parenthetical index was a constant ("fidx+1" where "fidx+i" is
#     meant), so every record was labelled (ACS1)/(IOCS1) regardless of index
#     -- here ACS255 was labelled (ACS256) and all three IOCS records (IOCS1);
#   - `grp` was reassigned to each record's own subtree inside the loop, so
#     record N+1 nested inside record N instead of being its sibling.
# (The same lines also spelled "I/0 Command Supported" for "I/O".)
# Each record carries a distinct non-zero CSEDS dword so a wrong offset shows
# up as a wrong number rather than as another zero.
_cmd_sup_and_eff_boundary = (struct.pack('<I', 0x1111FF01)   # ACS255  (struct 1020)
                             + struct.pack('<I', 0x22220001)  # IOCS0   (struct 1024)
                             + struct.pack('<I', 0x33330002)  # IOCS1   (struct 1028)
                             + struct.pack('<I', 0x44440003))  # IOCS2  (struct 1032)
assert len(_cmd_sup_and_eff_boundary) == 16

# F73/F74: LBA Status Information (LID 0Eh), DOFST=0, DLEN=64 -- one LBA
# Status Log Namespace Element carrying TWO LBA Range Descriptors.  Layout
# per NVM Command Set 1.2 Figure 109 (log page header, bytes 15:0),
# Figure 110 (namespace element: NEID 03:00, NLRD 07:04, RATYPE 08,
# Reserved 15:09) and Figure 111 (range descriptor: RSLBA 07:00, RNLB 11:08,
# Reserved 15:12).
#
# dissect_nvme_get_logpage_lba_status_lba_range()'s descriptor loop is
# "while (len >= 8)" but never decremented `len` on the len >= 16 path, so it
# could only exit by walking `poff` off the end of the tvb and throwing --
# emitting one ever-deeper-nested bogus Range Descriptor per iteration on the
# way, and returning a `done` far larger than the element, which then
# underflowed the caller's own unsigned `len`.  ANY element with more than one
# descriptor triggers it, which is what this fixture is: two descriptors is
# the minimum that makes the loop iterate twice.  Both descriptors carry
# distinct non-zero RSLBA/RNLB values.
_lba_status_page = (
    struct.pack('<I', 64)          # LSLPLEN (03:00)
    + struct.pack('<I', 1)         # NLSLNE  (07:04): one namespace element
    + struct.pack('<I', 0x1234)    # ESTULB  (11:08)
    + struct.pack('<H', 0)         # Reserved (13:12)
    + struct.pack('<H', 7)         # LSGC    (15:14)
    # LBA Status Log Namespace Element (Figure 110)
    + struct.pack('<I', 0x0000002A)  # NEID   (03:00)
    + struct.pack('<I', 2)           # NLRD   (07:04): two range descriptors
    + bytes([0x10])                  # RATYPE (08)
    + bytes(7)                       # Reserved (15:09)
    # LBA Range Descriptor 0 (Figure 111)
    + struct.pack('<Q', 0x1111222233334444)  # RSLBA
    + struct.pack('<I', 0x55556666)          # RNLB
    + bytes(4)                               # Reserved
    # LBA Range Descriptor 1
    + struct.pack('<Q', 0x0123456789ABCDEF)  # RSLBA
    + struct.pack('<I', 0x0000BEEF)          # RNLB
    + bytes(4))                              # Reserved
assert len(_lba_status_page) == 64

# F75/F76: ANA (LID 0Ch) fetched at DOFST=16 with LPO=0 -- the transport window
# starts exactly at ANA Group Descriptor 0, so the 16-byte header carrying
# Number of ANA Group Descriptors (NVMe Base 2.3 Figure 227, bytes 09:08) is not
# in this message at all.  dissect_nvme_get_logpage_ana_resp() took its group
# count from cmd_ctx->cmd_ctx.get_logpage.records on that path, but NVMe-MI
# builds a freshly zeroed command context per transaction, so the count was 0
# and "while (len >= 4 && groups)" never ran: every descriptor present went
# unrendered.  NVMe-MI 2.1 Figure 136 caps DLEN at 4,096, so an ANA log page
# larger than that can only be fetched with successive nonzero DOFST -- this is
# the ordinary Management Controller path, not a corner case.
#
# Two descriptors with distinct ANA Group IDs and NSIDs, so the test can tell
# "both rendered" from "the walk stopped after one".
_ana_dofst_descs = (ana_data(agid=0x11, grp_chgc=0x21, nsid=0x00000101)[16:]
                    + ana_data(agid=0x22, grp_chgc=0x22, nsid=0x00000202)[16:])
assert len(_ana_dofst_descs) == 72

# F77/F78: the same 72 bytes at the same logical offset, but expressed with
# LPO=16 and DOFST=0 instead of DOFST=16 and LPO=0.  The controller applies
# LPO before NVMe-MI slices the response, so both requests ask for exactly
# "the log page from byte 16 on" and both responses carry byte-identical
# payloads -- they must decode identically.  They did not:
# dissect_nvme_get_logpage_ana_resp()'s leading "if" has an off<16 branch and
# a tr_off branch and nothing else, so with off>=16 and tr_off==0 neither ran
# and "groups" kept its initializer of 1 -- exactly one descriptor rendered.

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
    # F69/F70 ANA (LID 0Ch), LPO=16, DLEN=4: 4-byte fresh-descriptor window
    # (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0C,
                                      doff=0, dlen=4, lpo=16), tag=34),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ana_grp_id_only), tag=34),
    # F71/F72 Commands Supported and Effects (LID 05h), LPO=1020, DLEN=16:
    # ACS/IOCS boundary window (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x05,
                                      doff=0, dlen=16, lpo=1020), tag=35),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_sup_and_eff_boundary), tag=35),
    # F73/F74 LBA Status Information (LID 0Eh), DOFST=0, DLEN=64: one
    # namespace element with two range descriptors (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0E,
                                      doff=0, dlen=64), tag=36),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lba_status_page), tag=36),
    # F75/F76 ANA (LID 0Ch), DOFST=16, LPO=0: the transport window starts at
    # ANA Group Descriptor 0 (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0C,
                                      doff=16, dlen=len(_ana_dofst_descs)),
                tag=37),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ana_dofst_descs), tag=37),
    # F77/F78 ANA (LID 0Ch), LPO=16, DOFST=0: the same window as F75/F76
    # expressed through the command's Log Page Offset (see block comment
    # above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0C,
                                      doff=0, dlen=len(_ana_dofst_descs),
                                      lpo=16),
                tag=38),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ana_dofst_descs), tag=38),
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

# F11/F12 HBS (FID 16h), DOFST=8 (>6, entirely inside the trailing "rsvd"
# region): same fallback gap as PLMC above, for HBS's 6-byte-fixed-field
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

# F17/F18 HBS (FID 16h), DOFST=0, DLEN=6: the full defined part of the Host
# Behavior Support structure -- ACRE, ETDAS, LBAFEE, HDISNS and the Copy
# Descriptor Formats Enable word (Figure 426).
_hbs_full_data = (bytes([0x01,   # ACRE
                         0x01,   # ETDAS
                         0x01,   # LBAFEE
                         0x00])  # HDISNS
                  + struct.pack('<H', 0x000C))  # CDFE: CDF2E | CDF3E

# F19/F20: LBA Range Type (FID 03h), DOFST=0, DLEN=128 -- TWO 64-byte LBA
# Range Type data structure entries (NVM Command Set 1.2 Figure 95: Type 00,
# Attributes 01, Reserved 15:02, SLBA 23:16, NLB 31:24, GUID 47:32,
# Reserved 63:48).  This is an UPSTREAM packet-nvme.c defect, present since
# 2021: dissect_nvme_set_features_transfer_lbart() anchors every "LBA Range
# Structure N" container item at tvb offset 0 rather than at the entry's own
# offset, so selecting structure 1 highlights structure 0's bytes.  Only the
# container's extent is wrong -- the child fields all use the entry offset --
# so the regression has to be asserted on the item's PDML pos/size, and it
# takes two entries to see it at all.  Each entry's Type/SLBA/NLB are
# distinct and non-zero so a wrong offset shows as a wrong number.
def _lbart_entry(type_, attr, slba, nlb, guid):
    return (bytes([type_, attr]) + bytes(14)
            + struct.pack('<Q', slba) + struct.pack('<Q', nlb)
            + guid + bytes(16))

_lbart_two_entries = (
    _lbart_entry(0x02, 0x03, 0x1000, 0x00FF, bytes(range(0xC0, 0xD0)))
    + _lbart_entry(0x03, 0x01, 0x2000, 0x01FF, bytes(range(0xE0, 0xF0))))
assert len(_lbart_two_entries) == 128

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
    # F11/F12 HBS (FID 16h), DOFST=8 (>6): trailing-field fallback
    # regression (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x16,
                                      doff=8, dlen=3), tag=5),
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
    # F17/F18 HBS (FID 16h), DOFST=0, DLEN=6: the whole defined part of the
    # Host Behavior Support structure (NVMe Base 2.3 Figure 426), so every
    # field above ACRE is covered.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x16,
                                      doff=0, dlen=6), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_hbs_full_data), tag=8),
    # F19/F20 LBA Range Type (FID 03h), DOFST=0, DLEN=128: two 64-byte
    # entries, for the container-item offset defect (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x03,
                                      doff=0, dlen=128), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lbart_two_entries), tag=9),
]

BASE_TS_FEATURES_WINDOWED_US = 1709378000 * 1_000_000

def build_features_windowed_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_features_windowed):
        data += epb(pkt, BASE_TS_FEATURES_WINDOWED_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_features_windowed)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-admin-security.pcapng — Security Send/Receive payload decode
# ---------------------------------------------------------------------------
#
# Paired Security Send (81h) / Security Receive (82h) exchanges exercising the
# security-protocol payload dispatch shared with packet-nvme.c
# (dissect_nvme_security_data): the SECP saved from Command Dword 10 on the
# request pass selects the payload decoder for the Send request data (inline,
# SQE offset 64 onward) and the Receive response data (offset 16 onward).
# SECP 00h response data decodes natively in packet-nvme.c
# (nvme.security.info.*); SECP 01h/02h dispatch through the
# "nvme.security.secp" dissector table to the TCG Storage dissector
# (packet-tcg-storage.c).
#
# Command Dword 10 layout (NVMe Base 2.3 Figures 397/399):
#   SECP  = bits 31:24, SPSP1 = bits 23:16 (SPSP high byte),
#   SPSP0 = bits 15:8  (SPSP low byte).
# admin_request_payload()'s cns argument is CDW10, so cns carries the packed
# selector.  DOFST = 0 on every request (dissect_nvme_security_data only
# decodes transfers that start at the beginning of the protocol structure);
# DLEN = the response data length; CDW11 = TL (Send) / AL (Receive).
#
# Per TCG SIIS, an IF-SEND (Security Send) completion never carries data:
# the host retrieves any result with a follow-up IF-RECV (Security Receive).
# Every Send here therefore completes with a bare 16-byte status+CQE block
# (DLEN = 0) and is paired with a Receive on the same SECP/SPSP.
#
#   F1/F2   Security Receive SECP=00h SPSP=0000h
#           -> supported security protocol list [00h, 01h, 02h]
#   F3/F4   Security Receive SECP=01h SPSP=0001h (Level 0 Discovery ComID)
#           -> discovery header + TPer, Locking, Opal SSC 2.x and Supported
#              Data Removal Mechanism features
#   F5/F6   Security Send    SECP=01h SPSP=1000h (Opal base ComID)
#           -> request data: ComPacket / Packet / Data subpacket carrying
#              the Session Manager StartSession method call
#           -> response: no data
#   F7/F8   Security Receive SECP=01h SPSP=1000h
#           -> response data: ComPacket carrying the SyncSession result
#   F9/F10  Security Send    SECP=02h SPSP=1000h (ComID management)
#           -> request data: PROTOCOL STACK RESET request block
#           -> response: no data
#   F11/F12 Security Receive SECP=02h SPSP=1000h
#           -> response data: ComID-mgmt response block (request echo +
#              Available Data Length 4 + 4-byte success status)
#   F13/F14 Security Send    SECP=02h SPSP=0004h (TPer Reset ComID)
#   F15/F16 Security Receive SECP=02h SPSP=0000h (GET COMID)
#   F17/F18 Security Receive SECP=01h SPSP=0001h (Level 0 Discovery, Ruby SSC)
#           -> request data: ignored by the TPer, not a ComID-mgmt request
#           -> response: no data
#   F19/F20 Security Receive SECP=01h SPSP=1000h
#           -> response data: the same SyncSession result with legal Empty
#              atoms interleaved (Core Spec §3.2.2.3.1.5)
#   F21/F22 Security Receive SECP=01h SPSP=0001h
#           -> response data: Level 0 Discovery carrying the SIIS feature
#              descriptor (0x0005) and a Namespace Geometry Reporting
#              descriptor (0x0405)

NVME_AQ_OPC_SECURITY_SEND = 0x81
NVME_AQ_OPC_SECURITY_RECV = 0x82

def security_cdw10(secp, spsp):
    """Pack Security Send/Receive Command Dword 10 (NSSF unused)."""
    return ((secp & 0xff) << 24) | ((spsp & 0xffff) << 8)

# --- SECP 00h: Supported Security Protocols List (SPC-5 7.7.1, BE) --------

def secp0_supported_list(protocols):
    """6 reserved bytes, 2-byte BE list length, then 1-byte protocol IDs."""
    return b'\x00' * 6 + struct.pack('>H', len(protocols)) + bytes(protocols)

# --- SECP 01h: Level 0 Discovery (Core Spec §3.3.6, BE) --------------------

def tcg_l0_feature(code, version, data, minor=0):
    """Feature descriptor: Code(2) + Version(bits 7:4 of byte 2) + Length(1).

    Byte 2's low nibble is Reserved for every feature except Opal SSC V2
    (0x0203), where it carries the SSC Minor Version Number."""
    return (struct.pack('>HBB', code,
                        ((version & 0x0f) << 4) | (minor & 0x0f), len(data))
            + data)

def tcg_l0_data_removal_feature():
    """0x0404 Supported Data Removal Mechanism, 32-byte body (Opal SSC 2.02
    Table 9): Crypto Erase and Vendor Specific Erase supported, both timed in
    seconds, with the Bit 5 (Vendor Specific) time after four Reserved bytes."""
    body = (bytes([0x00,        # Reserved
                   0x02,        # Interrupted set, Processing clear
                   0x24,        # mechanisms: Crypto Erase (2) | Vendor (5)
                   0x00])       # time formats: all seconds
            + struct.pack('>HHH', 0, 0, 30)  # times for bits 0, 1, 2
            + b'\x00' * 4                    # Reserved (no bit 3/4 mechanism)
            + struct.pack('>H', 600)         # time for bit 5 (Vendor Specific)
            + b'\x00' * 16)                  # reserved to length 32
    return tcg_l0_feature(0x0404, 2, body)

def tcg_level0_discovery_data():
    """48-byte discovery header (Data Structure Revision 1) + four feature
    descriptors: TPer (0x0001, Sync + ComID Mgmt), Locking (0x0002, Supported
    + Enabled), Opal SSC 2.x (0x0203, Base ComID 0x1000, 1 ComID, 4 admins,
    8 users, SSC Minor Version 2 = Opal 2.02), and Supported Data Removal
    Mechanism (0x0404)."""
    feats = (
        tcg_l0_feature(0x0001, 1, bytes([0x41]) + b'\x00' * 11)   # Sync|ComID Mgmt
        + tcg_l0_feature(0x0002, 1, bytes([0x03]) + b'\x00' * 11) # Supported|Enabled
        + tcg_l0_feature(0x0203, 2,
                         struct.pack('>HHBHHBB',
                                     0x1000,  # Base ComID
                                     1,       # Number of ComIDs
                                     0x00,    # flags (no range crossing)
                                     4,       # Locking SP Admin authorities
                                     8,       # Locking SP User authorities
                                     0x00,    # Initial C_PIN_SID indicator
                                     0x00)    # C_PIN_SID on Revert
                         + b'\x00' * 5,       # reserved to length 16
                         minor=2)             # Opal SSC 2.02
        + tcg_l0_data_removal_feature())
    # Length of Parameter Data counts everything after the 4-byte field itself
    hdr = (struct.pack('>II', 44 + len(feats), 1)  # length, revision
           + b'\x00' * 8                           # reserved
           + b'\x00' * 32)                         # vendor specific
    return hdr + feats

def tcg_level0_discovery_ruby_data():
    """48-byte discovery header + a single Ruby SSC (0x0304) feature.

    Ruby SSC v1.00 Table 7 is byte-for-byte the Opal 2.x descriptor: Range
    Crossing Behavior at data byte 4 and the authority counts at data bytes
    5:6 and 7:8.  It is NOT the Opalite/Pyrite "lite" layout, which leaves
    those five bytes Reserved (Pyrite SSC 2.01 Table 6)."""
    feats = tcg_l0_feature(0x0304, 1,
                           struct.pack('>HHBHHBB',
                                       0x2000,  # Base ComID
                                       1,       # Number of ComIDs
                                       0x01,    # Range Crossing Behavior set
                                       4,       # Locking SP Admin authorities
                                       9,       # Locking SP User authorities
                                       0x00,    # Initial C_PIN_SID indicator
                                       0xFF)    # C_PIN_SID on Revert = VU
                           + b'\x00' * 5)       # reserved to length 16
    hdr = (struct.pack('>II', 44 + len(feats), 1)  # length, major 0 / minor 1
           + b'\x00' * 8                           # reserved
           + b'\x00' * 32)                         # vendor specific
    return hdr + feats

def tcg_level0_discovery_siis_data():
    """48-byte discovery header + the SIIS feature descriptor (0x0005) and a
    Namespace Geometry Reporting descriptor (0x0405).

    SIIS v1.20 §3.6 Table 2 makes 0x0005 Mandatory ("An SD that supports this
    standard SHALL return the SIIS feature descriptor") with Length 0x0C: data
    byte 0 is the SIIS Revision Number (Table 3: 0x20 = SIIS v1.20), data byte
    1 carries Identifier Usage Scope in bits 2:1 (Table 4) and Key Change Zone
    Behavior in bit 0, and data bytes 2:11 are Reserved.

    0x0405 is named by SIIS §4.7.7 / §5.7.3 but its descriptor layout is
    defined by a feature-set specification not available here, so its body is
    deliberately opaque -- only the descriptor name may be decoded."""
    feats = (
        tcg_l0_feature(0x0005, 1,
                       bytes([0x20,   # SIIS Revision Number = v1.20
                              0x05])  # Id Usage Scope = 10b, Key Change Zone = 1
                       + b'\x00' * 10)   # Reserved, total Length = 0x0C
        + tcg_l0_feature(0x0405, 1, b'\xA5' * 12))
    hdr = (struct.pack('>II', 44 + len(feats), 1)  # length, major 0 / minor 1
           + b'\x00' * 8                           # reserved
           + b'\x00' * 32)                         # vendor specific
    return hdr + feats

def tcg_level0_discovery_badlen_data():
    """48-byte discovery header + three descriptors, the middle one declaring
    a Length of 13 while carrying the ordinary 12 data bytes.

    Core Spec §3.3.6.3.1.3: "This field SHALL be an integral multiple of 4."
    13 is not, so a reader that trusts it starts the next descriptor one byte
    late and every descriptor after that parses as garbage -- here the third
    descriptor's Feature Code reads 0x0310 instead of 0x0003.  All the bytes a
    reader needs are present, so nothing overruns and no length clamp fires:
    the misalignment is the entire visible symptom, which is why it needs an
    expert info of its own to be attributable."""
    bad = (struct.pack('>HBB', 0x0002, 0x10, 13)   # Locking, version 1, Len 13
           + bytes([0x03]) + b'\x00' * 11)         # 12 data bytes, not 13
    assert len(bad) == 4 + 12, len(bad)
    feats = (
        tcg_l0_feature(0x0001, 1, bytes([0x41]) + b'\x00' * 11)  # good, Len 12
        + bad
        + tcg_l0_feature(0x0003, 1, b'\x11' * 12))  # misparsed as a side effect
    hdr = (struct.pack('>II', 44 + len(feats), 1)
           + b'\x00' * 8
           + b'\x00' * 32)
    return hdr + feats

# --- SECP 02h: GET COMID (Core Spec §3.3.4.3.1 Tables 27/28, BE) ----------
# An IF-RECV on ComID 0000h whose entire payload is the 4-byte Extended ComID
# (ComID in the first two bytes, TPer-assigned extension in the last two),
# zero-padded out to the transfer length.  It is NOT a ComID management
# response, so it carries no Request Code or Available Data Length.
tcg_get_comid_resp = struct.pack('>HH', 0x1000, 0x0001) + b'\x00' * 4

# --- SECP 01h: ComPacket framing + token stream (Core Spec §3.2, BE) ------

TCG_SMUID        = bytes.fromhex('00000000000000FF')  # Session Manager UID
TCG_STARTSESSION = bytes.fromhex('000000000000FF02')
TCG_SYNCSESSION  = bytes.fromhex('000000000000FF03')
TCG_ADMIN_SP     = bytes.fromhex('0000020500000001')

def tcg_bytes_atom(data):
    """Short atom, byte sequence: 0b10 1 0 llll (0xA8 for an 8-byte UID)."""
    assert len(data) <= 15
    return bytes([0xA0 | len(data)]) + data

def tcg_tiny_uint(v):
    """Tiny atom, unsigned: the 6-bit value itself."""
    assert 0 <= v <= 0x3F
    return bytes([v])

def tcg_short_uint(v, width):
    """Short atom, unsigned integer: 0b10 0 0 llll + BE value bytes."""
    return bytes([0x80 | width]) + v.to_bytes(width, 'big')

def _tcg_atom_header_selfcheck(header, want_byte_flag, want_sign_flag, want_data_len,
                               want_hdr_len):
    """Independently re-derive (hdr_len, byte_flag, sign_flag, data_len) from
    `header` using the exact bit formulas in packet-tcg-storage.c's
    dissect_tcg_token_stream() Short/Medium/Long Atom branches, and assert
    they match what the caller intended.

    This exists because the atom classes below (Medium, Long, wide Short
    integer) are hand-derived from the dissector's bit-packing and never
    exercised by the existing StartSession/SyncSession fixture -- there is no
    prior encoder in this file to copy, so a transcription mistake here would
    silently produce a fixture that parses "successfully" without ever
    reaching the branch it claims to test.  Fail at generation time instead
    of only discovering it later via tshark -V.
    """
    b = header[0]
    if b <= 0xBF:
        hdr_len, byte_flag, sign_flag = 1, bool(b & 0x20), bool(b & 0x10)
        data_len = b & 0x0F
    elif b <= 0xDF:
        hdr_len, byte_flag, sign_flag = 2, bool(b & 0x10), bool(b & 0x08)
        data_len = ((b & 0x07) << 8) | header[1]
    else:
        hdr_len, byte_flag, sign_flag = 4, bool(b & 0x02), bool(b & 0x01)
        data_len = (header[1] << 16) | (header[2] << 8) | header[3]
    got = (hdr_len, byte_flag, sign_flag, data_len)
    want = (want_hdr_len, want_byte_flag, want_sign_flag, want_data_len)
    assert got == want, f"TCG atom header self-check failed: got {got}, want {want}"

def tcg_medium_bytes_atom(data):
    """Medium atom, byte sequence: 0b1101_0lll + 1 length byte (11-bit
    length, up to 0x7FF).  Reaches the Medium Atom class (0xC0-0xDF), which
    only exists for byte-sequence data too long for a Short Atom's 4-bit
    length field (>15 bytes) -- never emitted by the existing fixtures."""
    n = len(data)
    header = bytes([0xD0 | ((n >> 8) & 0x07), n & 0xFF])
    _tcg_atom_header_selfcheck(header, True, False, n, 2)
    return header + data

def tcg_short_int(v, width):
    """Short atom, signed integer: 0b1001_llll + BE two's-complement value
    bytes.  Reaches the signed-atom branch, never emitted by the existing
    fixtures (which only use unsigned Short Atoms)."""
    data = v.to_bytes(width, 'big', signed=True)
    header = bytes([0x90 | width])
    _tcg_atom_header_selfcheck(header, False, True, width, 1)
    return header + data

def tcg_short_int_wide(v, width):
    """Short atom, unsigned integer wider than 64 bits (data_len 9-15): the
    dissector's "> 8 bytes" raw-render fallback, distinct from the normal
    <=8-byte integer path exercised by the existing StartSession/SyncSession
    fixtures (which only use Short atoms)."""
    data = v.to_bytes(width, 'big')
    header = bytes([0x80 | width])
    _tcg_atom_header_selfcheck(header, False, False, width, 1)
    return header + data

def tcg_long_int(v, width, signed=False):
    """Long atom, integer: 0b1110_000s + 3 length bytes + BE value bytes.
    Reaches the Long Atom class (0xE0-0xEF), never emitted by the existing
    fixtures (which only use Short atoms)."""
    data = v.to_bytes(width, 'big', signed=signed)
    header = bytes([0xE0 | (0x01 if signed else 0x00)]) + struct.pack('>I', len(data))[1:]
    _tcg_atom_header_selfcheck(header, False, signed, len(data), 4)
    return header + data

# End of Data followed by the method status list [status, 0, 0]
TCG_EOD_STATUS_SUCCESS = bytes([0xF9, 0xF0, 0x00, 0x00, 0x00, 0xF1])

def tcg_subpacket(tokens, kind=0x0000):
    """Subpacket: 6 reserved + Kind(2) + Length(4, token bytes only) +
    tokens + pad to 4-byte alignment (pad excluded from Length)."""
    pad = (-len(tokens)) % 4
    return (b'\x00' * 6 + struct.pack('>HI', kind, len(tokens))
            + tokens + b'\x00' * pad)

def tcg_packet(payload, tsn=0, hsn=0, seq=1):
    """Packet: TSN(4) + HSN(4) + Seq(4) + rsvd(2) + AckType(2) + Ack(4) +
    Length(4, bytes after this 24-byte header)."""
    return struct.pack('>IIIHHII', tsn, hsn, seq, 0, 0, 0,
                       len(payload)) + payload

def tcg_compacket(payload, comid, ext=0):
    """ComPacket: rsvd(4) + ComID(2) + Ext(2) + Outstanding(4) +
    MinTransfer(4) + Length(4, bytes after this 20-byte header)."""
    return struct.pack('>IHHIII', 0, comid, ext, 0, 0,
                       len(payload)) + payload

# StartSession: SMUID.StartSession[HostSessionID=1, SPID=Admin SP, Write=1]
tcg_startsession_tokens = (
    bytes([0xF8])                        # Call
    + tcg_bytes_atom(TCG_SMUID)          # Invoking UID
    + tcg_bytes_atom(TCG_STARTSESSION)   # Method UID
    + bytes([0xF0])                      # Start List
    + tcg_tiny_uint(1)                   # HostSessionID
    + tcg_bytes_atom(TCG_ADMIN_SP)       # SPID
    + tcg_tiny_uint(1)                   # Write = TRUE
    + bytes([0xF1])                      # End List
    + TCG_EOD_STATUS_SUCCESS)

# SyncSession: SMUID.SyncSession[HostSessionID=1, SPSessionID=0x1001]
tcg_syncsession_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNCSESSION)
    + bytes([0xF0])
    + tcg_tiny_uint(1)                   # HostSessionID
    + tcg_short_uint(0x1001, 2)          # SPSessionID
    + bytes([0xF1])
    + TCG_EOD_STATUS_SUCCESS)

# The Empty atom (0xFF).  Core Spec §3.2.2.3.1.5: it "MAY appear at any point
# in the stream encoding where any other atom is able to appear ... and it
# SHALL be ignored", its purpose being value alignment inside a Data
# subpacket, so devices really do emit it.  §3.2.2.4.2 describes the payload
# structure "(discounting empty atoms)".
TCG_TOK_EMPTY = bytes([0xFF])

# The same SyncSession result, with Empty atoms at three spec-permitted spots:
# after Call, between the two UIDs, and between End of Data and the status
# StartList.  Every one of those sits astride a token-adjacency latch in
# dissect_tcg_token_stream(), so an implementation that lets an Empty atom
# consume the latch loses the method annotation and the Method Status while
# still parsing the stream "successfully".
tcg_syncsession_empty_atoms_tokens = (
    bytes([0xF8])                        # Call
    + TCG_TOK_EMPTY
    + tcg_bytes_atom(TCG_SMUID)          # Invoking UID
    + TCG_TOK_EMPTY
    + tcg_bytes_atom(TCG_SYNCSESSION)    # Method UID
    + bytes([0xF0])
    + tcg_tiny_uint(1)                   # HostSessionID
    + tcg_short_uint(0x1001, 2)          # SPSessionID
    + bytes([0xF1])
    + bytes([0xF9])                      # End of Data
    + TCG_TOK_EMPTY
    + bytes([0xF0, 0x00, 0x00, 0x00, 0xF1]))  # status list [SUCCESS, 0, 0]

# A status list whose first element is 0x1234.  Core Spec §3.2.2.4.2 item 5
# makes the Method Status a value in 00h-FFh (Table 166), so this element is
# malformed input.  The tiny atom that follows it is an ordinary list element
# and must NOT be promoted to a Method Status of 0x05 (SP_DISABLED).
tcg_status_out_of_range_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNCSESSION)
    + bytes([0xF0])
    + tcg_tiny_uint(1)
    + bytes([0xF1])
    + bytes([0xF9])                      # End of Data
    + bytes([0xF0])                      # Start List (method status list)
    + tcg_short_uint(0x1234, 2)          # out-of-range status element
    + tcg_tiny_uint(0x05)                # would be fabricated as SP_DISABLED
    + tcg_tiny_uint(0x00)
    + bytes([0xF1]))

tcg_startsession_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_startsession_tokens)), 0x1000)
tcg_syncsession_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_syncsession_tokens)), 0x1000)
tcg_syncsession_empty_atoms_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_syncsession_empty_atoms_tokens)), 0x1000)
tcg_status_out_of_range_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_status_out_of_range_tokens)), 0x1000)

# --- SECP 02h: ComID management (Core Spec §3.3.10, BE) --------------------

# PROTOCOL STACK RESET request: ComID + Ext + Request Code
tcg_stack_reset_req = struct.pack('>HHI', 0x1000, 0, 0x00000002)
# Response: request echo + Reserved(2) + Available Data Length + 4-byte
# success status (Core Spec §3.3.10.3 STACK_RESET response format)
tcg_stack_reset_resp = (struct.pack('>HHIHH', 0x1000, 0, 0x00000002, 0, 4)
                        + b'\x00' * 4)

# TPer Reset (SECP 02h, ComID 0004h): the transfer length must be non-zero and
# the TPer ignores the content (Opal SSC 2.02 Table 14).
tcg_tper_reset_req = b'\x00' * 16

_l0_data = tcg_level0_discovery_data()
_l0_ruby_data = tcg_level0_discovery_ruby_data()
_l0_siis_data = tcg_level0_discovery_siis_data()
_l0_badlen_data = tcg_level0_discovery_badlen_data()
_secp0_list = secp0_supported_list([0x00, 0x01, 0x02])

packets_admin_security = [
    # F1/F2 Security Receive SECP=00h SPSP=0000h: supported protocol list
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x00, 0x0000),
                                      dlen=len(_secp0_list),
                                      cdw11=len(_secp0_list)), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_secp0_list), tag=0),
    # F3/F4 Security Receive SECP=01h SPSP=0001h: Level 0 Discovery
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x0001),
                                      dlen=len(_l0_data),
                                      cdw11=len(_l0_data)), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_l0_data), tag=1),
    # F5/F6 Security Send SECP=01h SPSP=1000h: StartSession (no response data)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=0,
                                      cdw11=len(tcg_startsession_cp))
                + tcg_startsession_cp, tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=2),
    # F7/F8 Security Receive SECP=01h SPSP=1000h: SyncSession result
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=len(tcg_syncsession_cp),
                                      cdw11=len(tcg_syncsession_cp)), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(tcg_syncsession_cp), tag=3),
    # F9/F10 Security Send SECP=02h SPSP=1000h: PROTOCOL STACK RESET request
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x02, 0x1000),
                                      dlen=0,
                                      cdw11=len(tcg_stack_reset_req))
                + tcg_stack_reset_req, tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=4),
    # F11/F12 Security Receive SECP=02h SPSP=1000h: stack-reset result
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x02, 0x1000),
                                      dlen=len(tcg_stack_reset_resp),
                                      cdw11=len(tcg_stack_reset_resp)), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(tcg_stack_reset_resp), tag=5),
    # F13/F14 Security Send SECP=02h SPSP=0004h: TPer Reset.  Non-zero
    # transfer length whose payload the TPer ignores, and no IF-RECV response.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x02, 0x0004),
                                      dlen=0,
                                      cdw11=len(tcg_tper_reset_req))
                + tcg_tper_reset_req, tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=6),
    # F15/F16 Security Receive SECP=02h SPSP=0000h: GET COMID.  The response
    # payload is only the 4-byte Extended ComID, so it must not be decoded
    # with the 12-byte ComID management response header.  Tags are 3 bits
    # (MCTP), so this reuses tag 7 / tag 0 from transactions that already
    # completed above rather than overflowing the field.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x02, 0x0000),
                                      dlen=len(tcg_get_comid_resp),
                                      cdw11=len(tcg_get_comid_resp)), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(tcg_get_comid_resp), tag=7),
    # F17/F18 Security Receive SECP=01h SPSP=0001h: a Level 0 Discovery whose
    # only feature is Ruby SSC (0x0304).  Ruby follows the Opal 2.x descriptor
    # layout, so its authority counts must decode rather than disappearing
    # into the Opalite/Pyrite Reserved block.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x0001),
                                      dlen=len(_l0_ruby_data),
                                      cdw11=len(_l0_ruby_data)), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_l0_ruby_data), tag=0),
    # F19/F20 Security Receive SECP=01h SPSP=1000h: the SyncSession result
    # again, with legal Empty atoms interleaved.  Core Spec §3.2.2.3.1.5 says
    # an Empty atom SHALL be ignored, so this frame must decode exactly like
    # F8 -- same method annotation, same Method Status.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=len(tcg_syncsession_empty_atoms_cp),
                                      cdw11=len(tcg_syncsession_empty_atoms_cp)),
                tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(tcg_syncsession_empty_atoms_cp), tag=1),
    # F21/F22 Security Receive SECP=01h SPSP=0001h: a Level 0 Discovery whose
    # features are the Mandatory SIIS descriptor (0x0005, SIIS v1.20 Table 2)
    # and a Namespace Geometry Reporting descriptor (0x0405, named by SIIS
    # §4.7.7 / §5.7.3 but with no layout in any spec available here).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x0001),
                                      dlen=len(_l0_siis_data),
                                      cdw11=len(_l0_siis_data)), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_l0_siis_data), tag=2),
]

BASE_TS_ADMIN_SECURITY_US = 1709380800 * 1_000_000

def build_admin_security_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_security):
        data += epb(pkt, BASE_TS_ADMIN_SECURITY_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_security)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-admin-eom.pcapng - Physical Interface Receiver Eye Opening
# Measurement log page (LID 19h)
# ---------------------------------------------------------------------------
#
# LID 19h is defined by the NVMe over PCIe Transport Specification (Revision
# 1.3, section 3.9.1.1, Figures 68-73), not by NVMe Base -- Base's Get Log Page
# LID table just says "refer to the applicable NVM Express Transport
# specification".  Reachable out-of-band: libnvme exposes
# nvme_mi_admin_get_log_phy_rx_eom().
#
# Layout: a fixed 64-byte EOM Header (Figure 72) followed by ND EOM Lane
# Descriptors (Figure 73) of DS bytes each.  Both ND and DS live in the header,
# so the descriptor list can only be walked from a full offset-0 view.
#
# The descriptor stride is DS, NOT 32 + NROWS*NCOLS + EDLEN -- Figure 73's
# trailing Padding field absorbs the difference.  The fixture below carries 10
# bytes of PAD per descriptor so that behaviour is pinned down rather than
# accidentally satisfied.
#
#   F1/F2  EOMIP=2 (completed), 2 lane descriptors, Printable Eye + Eye Data
#   F3/F4  EOMIP=0 (no measurement started), header only, ND=0
#   F5/F6  same log page windowed at DOFST=64, so ND/DS are out of view and
#          the descriptor walk must be skipped
#   F7/F8  one internally inconsistent descriptor whose Printable Eye does not
#          fit in DS, so neither PE nor Eye Data may be rendered
#
# Every field carries a distinct value so a shifted offset shows up as a wrong
# number rather than a plausible one.

EOM_NROWS = 4
EOM_NCOLS = 8
EOM_EDLEN = 6
EOM_DS = 80          # 32 + (4*8) + 6 = 70, padded to 80 -> 10 PAD bytes
EOM_ND = 2

NVME_LID_PHY_RX_EOM = 0x19

def eom_lane_desc(lane, eye):
    """One EOM Lane Descriptor (NVMe over PCIe Transport 1.3 Figure 73)."""
    d = struct.pack('<BBBB', 0x00, 0x01, lane, eye)  # rsvd, MSTAT(MSCS=1), LN, EYE
    d += struct.pack('<HHHH', 14, 16, 11, 9)         # TOP, BTM, LFT, RGT
    d += struct.pack('<HH', EOM_NROWS, EOM_NCOLS)    # NROWS, NCOLS
    d += struct.pack('<I', EOM_EDLEN)                # EDLEN is 4 bytes (19:16)
    d += bytes(12)                                   # Reserved 31:20
    assert len(d) == 32, len(d)
    # Printable Eye: ASCII '1' outside the eye, '0' on or inside it.  Row 0 is
    # all '1' and later rows vary by lane, so a wrong offset is visible as text.
    for r in range(EOM_NROWS):
        d += bytes((0x31 if (r == 0 or c < lane) else 0x30)
                   for c in range(EOM_NCOLS))
    d += bytes([0xA0 + lane]) * EOM_EDLEN            # Eye Data (vendor specific)
    d += bytes(EOM_DS - len(d))                      # Padding
    assert len(d) == EOM_DS, len(d)
    return d

def eom_data(eomip=2, nd=EOM_ND, ndesc=None):
    """EOM log page: a 64-byte header (Figure 72) plus lane descriptors.

    nd is what the header's ND field (and RSZ) claim; ndesc is how many
    descriptors actually follow, defaulting to the claimed count.  They differ
    only for the adversarial frame, which claims more descriptors than it
    sends."""
    h = struct.pack('<BB', NVME_LID_PHY_RX_EOM, eomip)  # LID, EOMIP
    h += struct.pack('<H', 64)                 # HSIZE (spec: shall be 64)
    h += struct.pack('<I', 64 + EOM_DS * nd)   # RSZ
    h += struct.pack('<BB', 0x07, 0x03)        # EDGN, LREV (spec: shall be 3h)
    h += struct.pack('<B', 0x03)               # ODP: PEFP and EDFP both set
    h += struct.pack('<BB', 0x04, 0x01)        # LNS = 4 lanes, EPL = 1 (NRZ)
    h += struct.pack('<B', 0x41)               # LSPFC: rsvd=0, LSPFV=41h
    h += struct.pack('<B', 0x05)               # LINFO: MLS = 5
    h += bytes(3)                              # Reserved 17:15
    h += struct.pack('<H', 0xBEEF)             # LSIC 19:18
    h += struct.pack('<I', EOM_DS)             # DS 23:20
    h += struct.pack('<H', nd)                 # ND 25:24
    h += struct.pack('<HH', 16, 11)            # MAXTB, MAXLR
    h += struct.pack('<HHH', 11, 22, 33)       # ETGOOD, ETBETTER, ETBEST
    h += bytes(28)                             # Reserved 63:36
    assert len(h) == 64, len(h)
    if ndesc is None:
        ndesc = nd
    return h + b''.join(eom_lane_desc(lane=i, eye=i) for i in range(ndesc))

_eom_full = eom_data()

# An internally inconsistent lane descriptor: NROWS*NCOLS declares a 64-byte
# Printable Eye at descriptor offset 32, which needs 96 bytes, but DS is only
# 80.  PE therefore cannot be rendered, and because the Eye Data field is
# specified to start at (NROWS*NCOLS+32) its offset is undefined too, so ED
# must be suppressed as well rather than drawn at the PE offset.
EOM_BAD_NROWS = 8
EOM_BAD_NCOLS = 8

def eom_lane_desc_pe_over_ds(lane, eye):
    """A lane descriptor whose Printable Eye overflows DS (Figure 73)."""
    d = struct.pack('<BBBB', 0x00, 0x01, lane, eye)  # rsvd, MSTAT(MSCS=1), LN, EYE
    d += struct.pack('<HHHH', 14, 16, 11, 9)         # TOP, BTM, LFT, RGT
    d += struct.pack('<HH', EOM_BAD_NROWS, EOM_BAD_NCOLS)
    d += struct.pack('<I', EOM_EDLEN)                # EDLEN is 4 bytes (19:16)
    d += bytes(12)                                   # Reserved 31:20
    assert len(d) == 32, len(d)
    # As much of the eye diagram as DS leaves room for, all ASCII '0' (on or
    # inside the eye).  If Eye Data is wrongly drawn at the PE offset it reads
    # back as six ASCII '0' bytes instead of the 0xA-series vendor pattern the
    # consistent descriptors carry.
    d += b'\x30' * (EOM_DS - len(d))
    assert len(d) == EOM_DS, len(d)
    return d

def eom_data_pe_over_ds():
    """EOM log page carrying one internally inconsistent lane descriptor."""
    return eom_data(nd=1)[:64] + eom_lane_desc_pe_over_ds(lane=0, eye=0)

packets_admin_eom = [
    # F1/F2 completed measurement, 2 lane descriptors
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=NVME_LID_PHY_RX_EOM), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_eom_full), tag=0),
    # F3/F4 no measurement started: EOMIP 0h means the log page is just HSIZE
    # bytes (Figure 68) and ND is 0, so no descriptor may be rendered
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=NVME_LID_PHY_RX_EOM), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(eomip=0, nd=0)), tag=1),
    # F5/F6 windowed view starting at the first descriptor (DOFST=64): ND and
    # DS are not in view, so the descriptor list must NOT be walked
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=NVME_LID_PHY_RX_EOM,
                                      flags=0x03, doff=64,
                                      dlen=EOM_DS), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_eom_full[64:64 + EOM_DS]), tag=2),
    # F7/F8 a descriptor whose Printable Eye overflows DS: PE needs
    # 32 + (8*8) = 96 bytes but DS is 80, so PE is unrenderable and the Eye
    # Data offset that follows it is undefined
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=NVME_LID_PHY_RX_EOM), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data_pe_over_ds()), tag=3),
    # F9/F10 a *partial* first window of a complete log page: DOFST=0 but DLEN
    # covers only the 64-byte header plus one of the ND descriptors, while
    # NUMD asks for the whole page.  The descriptor walk therefore runs out of
    # data with descriptors still to come -- which is exactly what a device
    # lying about ND looks like locally, and must NOT be reported, because
    # here the rest is simply in the next window.
    #
    # This is the fixture that distinguishes the two: the walk stopping early
    # is only a contradiction once the window holds everything NUMD asked for,
    # so it is the NUMD comparison rather than the walk that is under test.
    # NUMDL is CDW10 31:16 and NUMD is 0's based in dwords, so a full page of
    # 64 + EOM_DS * EOM_ND bytes is ((64 + EOM_DS * EOM_ND) // 4) - 1.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS * EOM_ND) // 4) - 1) << 16)),
                                      flags=0x03, doff=0,
                                      dlen=64 + EOM_DS), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_eom_full[:64 + EOM_DS]), tag=4),
    # F11/F12 the complement of F9/F10: a *complete* transfer whose header
    # over-declares ND.  The response carries the 64-byte header plus EOM_ND
    # descriptors and NUMD asks for exactly those bytes, so nothing is
    # outstanding -- but ND claims EOM_ND + 1.  Unlike F10 there is no later
    # window the missing descriptor could arrive in, so this is a genuine
    # self-contradiction and is reported.
    #
    # F10 and F12 differ only in NUMD and in the claimed ND; both stop the
    # descriptor walk early.  That is the point: the walk running out of data
    # is identical in the two, so only the NUMD comparison separates the
    # partial window from the lying header.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS * EOM_ND) // 4) - 1) << 16)),
                                      dlen=64 + EOM_DS * EOM_ND), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=EOM_ND + 1, ndesc=EOM_ND)),
                tag=5),
]

BASE_TS_ADMIN_EOM_US = 1709462400 * 1_000_000

def build_admin_eom_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_admin_eom):
        data += epb(pkt, BASE_TS_ADMIN_EOM_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_admin_eom)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-tcg-atom-classes.pcapng — TCG token-stream atom-class coverage
# ---------------------------------------------------------------------------
#
# packets_admin_security above (StartSession/SyncSession) only ever emits
# Short Atoms carrying unsigned values <=8 bytes — every UID is exactly 8
# bytes, every integer is small.  dissect_tcg_token_stream() in
# packet-tcg-storage.c branches on several atom classes that shape never
# reaches: Medium/Long Atoms (0xC0-0xEF, needed once a byte-sequence exceeds
# a Short Atom's 4-bit length field or an integer needs a wider header),
# signed atoms (never emitted), and the "integer atom wider than 64 bits"
# raw-render fallback (data_len 9-15, distinct from the normal <=8-byte
# integer path).  This structural variety is exactly what mutation fuzzing
# on the existing seed cannot manufacture — editcap perturbs bytes already
# present, it does not insert a longer atom class the seed never used.
#
# NOTE — spec-verification limitation: no TCG Storage Architecture Core
# Specification text was available in this repo's spec bundle (checked
# C:\Users\Brandon\code\specs\{okf,md,pdf} — nothing TCG-related exists
# there) to independently verify a *specific real* method name/UID for this
# shape of call.  The Invoking UID reuses the existing, already-reviewed
# TCG_SMUID constant; the Method UID below is a clearly-synthetic
# placeholder (renders as an unrecognized 0x... UID on the wire, same as any
# unknown method in real traffic).  The atom *encoding* itself is verified —
# every helper below re-derives its own header bits with the exact formula
# read out of dissect_tcg_token_stream() (see _tcg_atom_header_selfcheck)
# and this file's generated output is diffed against the running ASan tshark
# build (-V) before being treated as correct — but the higher-level claim
# "this is what a real TCG method call looks like" is unverified pending
# access to the actual spec.  Re-derive against it if/when available.
TCG_SYNTHETIC_METHOD = bytes.fromhex('0000000000EEEEEE')

tcg_atom_classes_tokens = (
    bytes([0xF8])                            # Call
    + tcg_bytes_atom(TCG_SMUID)              # Invoking UID
    + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)   # Method UID (synthetic, see above)
    + bytes([0xF0])                          # Start List (outer parameter list)
    +   bytes([0xF0])                        #   nested Start List (depth 2 —
    +     tcg_tiny_uint(1)                   #   never exercised before: the
    +     tcg_short_int(-5, 2)               #   existing fixtures nest one
    +   bytes([0xF1])                        #   level only)
    +   tcg_medium_bytes_atom(b'\x42' * 20)  #   Medium Atom: 20-byte blob
    +   tcg_long_int(-70000, 4, signed=True) #   Long Atom: signed integer
    +   tcg_short_int_wide(0x0102030405060708090A, 10)  # Short Atom,
                                              #   data_len=10 -> "wider than
                                              #   64 bits" fallback
    + bytes([0xF1])                          # End List
    + TCG_EOD_STATUS_SUCCESS)

tcg_atom_classes_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_atom_classes_tokens)), 0x1000)

packets_tcg_atom_classes = [
    # F1/F2 Security Send SECP=01h SPSP=1000h: synthetic method call
    # exercising Medium/Long atoms, signed atoms, a nested list and the
    # wide-integer fallback (see block comment above)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=0,
                                      cdw11=len(tcg_atom_classes_cp))
                + tcg_atom_classes_cp, tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=0),
]

BASE_TS_TCG_ATOM_CLASSES_US = 1709381800 * 1_000_000

def build_tcg_atom_classes_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_tcg_atom_classes):
        data += epb(pkt, BASE_TS_TCG_ATOM_CLASSES_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_tcg_atom_classes)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-tcg-malformed.pcapng — TCG token-stream error-path coverage
# ---------------------------------------------------------------------------
#
# Deliberately hits three distinct error branches in
# dissect_tcg_token_stream() that a well-formed seed cannot reach on its own.
# Mutation fuzzing *can* eventually stumble into these by corrupting a length
# byte, but a dedicated fixture proves the expert-info code itself fires
# correctly right now, rather than relying on chance to rediscover it later:
#   F1/F2  a reserved control token (0xF4, one of 0xF4-0xF7/0xFD-0xFE) mid-
#          stream -> ei_tcg_tok_reserved, then parsing continues
#   F3/F4  a Short Atom header claiming more data (10 bytes) than remains in
#          the subpacket (3 bytes) -> clamped, ei_tcg_length_overrun, break
#   F5/F6  a Long Atom lead byte with only 1 more byte following (needs a
#          4-byte header) -> ei_tcg_truncated, break
#   F7/F8  a method status list whose first element is 0x1234, wider than the
#          00h-FFh the Method Status occupies (Core Spec §3.2.2.4.2 item 5,
#          Table 166) -> ei_tcg_tok_status_range, and the ordinary list
#          element that follows must not be promoted to a Method Status
#   F9/F10 a Level 0 Discovery feature descriptor whose Length is 13, which
#          Core Spec §3.3.6.3.1.3 forbids ("SHALL be an integral multiple of
#          4") -> ei_tcg_feat_length_align.  The misalignment then cascades
#          into the descriptor that follows, which is the point: the cascade
#          has to be attributable to a named cause.
# Each was hand-traced against dissect_tcg_token_stream()'s actual control
# flow (offset/end bookkeeping, clamp condition, break points) before being
# treated as correct, and independently confirmed via the real ASan tshark
# build below.

tcg_reserved_token_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
    + bytes([0xF0])
    +   tcg_tiny_uint(1)
    +   bytes([0xF4])           # Reserved control token (0xF4-0xF7)
    +   tcg_tiny_uint(2)        # parsing must continue after it
    + bytes([0xF1])
    + TCG_EOD_STATUS_SUCCESS)

tcg_overrun_atom_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
    # Short unsigned-int atom header claims data_len=10, only 3 bytes follow
    + bytes([0x8A]) + bytes([0x01, 0x02, 0x03]))

tcg_truncated_header_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
    # Long Atom lead byte + 1 byte; a Long Atom header needs 4
    + bytes([0xE0, 0x00]))

tcg_reserved_token_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_reserved_token_tokens)), 0x1000)
tcg_overrun_atom_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_overrun_atom_tokens)), 0x1000)
tcg_truncated_header_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_truncated_header_tokens)), 0x1000)

def _tcg_malformed_receive(cp, tag):
    """Security Receive request/response pair carrying `cp` as the response
    payload — the realistic direction for a device-originated malformed or
    buggy TCG response, matching F3/F4/F7/F8/F11/F12 in packets_admin_security
    above."""
    return [
        make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                          ctrl_id=0x0001, flags=0x00,
                                          cns=security_cdw10(0x01, 0x1000),
                                          dlen=len(cp),
                                          cdw11=len(cp)), tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(cp), tag=tag),
    ]

def _tcg_malformed_l0_receive(l0, tag):
    """Security Receive request/response pair carrying `l0` as a Level 0
    Discovery response payload (SECP 01h, ComID 0001h)."""
    return [
        make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                          ctrl_id=0x0001, flags=0x00,
                                          cns=security_cdw10(0x01, 0x0001),
                                          dlen=len(l0),
                                          cdw11=len(l0)), tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(l0), tag=tag),
    ]

packets_tcg_malformed = (
    _tcg_malformed_receive(tcg_reserved_token_cp, tag=0) +      # F1/F2
    _tcg_malformed_receive(tcg_overrun_atom_cp, tag=1) +        # F3/F4
    _tcg_malformed_receive(tcg_truncated_header_cp, tag=2) +    # F5/F6
    _tcg_malformed_receive(tcg_status_out_of_range_cp, tag=3) + # F7/F8
    _tcg_malformed_l0_receive(_l0_badlen_data, tag=4)           # F9/F10
)

BASE_TS_TCG_MALFORMED_US = 1709382800 * 1_000_000

def build_tcg_malformed_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_tcg_malformed):
        data += epb(pkt, BASE_TS_TCG_MALFORMED_US + i * 1_000_000)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_tcg_malformed)} packets to {output_path}")


# ---------------------------------------------------------------------------
# nvme-mi-error-paths.pcapng — response paths whose format depends on
# something other than the opcode: a sliced MIC, a non-Success Control
# Primitive status, and an Admin data window no structured decoder renders.
# ---------------------------------------------------------------------------
#
#   --- Sliced MIC vs. the command-slot lifecycle (MCTP tag 0, CSI 0) ---
#
#   F1  MI  Req   opcode 01h (Health Status Poll), IC=1, complete
#   F2  MI  Req   opcode 04h (Configuration Get),  IC=1, SLICED 6 bytes short,
#                 so the span the MIC covers is not fully captured.
#   F3  MI  Resp  status 00h, IC=1, complete
#
#   The MIC spans the reported message length, so computing it over a sliced
#   frame throws a bounds exception -- and it is thrown before the command
#   slot lifecycle runs, with pinfo->fd->visited already set.  F2 then never
#   takes the slot and F3 links back to F1 instead of F2: a wrong Request In,
#   a wrong Response Time, and no expert info anywhere.  F3 must link to F2,
#   and F2 must raise the superseded-request note against F1.
#
#   --- MIC field itself cut off (MCTP tag 6, CSI 0) ---
#
#   F4  MI  Req   opcode 01h, IC=1, complete
#   F5  MI  Resp  status 00h, IC=1, SLICED by exactly the 4 MIC bytes.  Here
#                 the covered span *is* complete, so this is the second half
#                 of the same defect: adding the checksum item over bytes that
#                 were never captured throws as well.  The MIC must be
#                 reported as not present rather than claimed either way.
#
#   --- Control Primitive error responses (Figures 27/28: the Response Body
#       format depends on the Status field, not just on the opcode) ---
#
#   F6  CP  Req   Abort (02h), TAG=5Ah                       [MCTP tag 1]
#   F7  CP  Resp  status 08h (Unable to Abort).  Figure 30 makes bytes 7:5
#                 Reserved; they are deliberately non-zero here (00 EF BE) so
#                 that decoding them as the Figure 40 Success layout is
#                 visible: byte 5 reads as TAG=00h (a false mismatch against
#                 the request's 5Ah) and bytes 7:6 as CPSR=BEEFh, out of which
#                 the Abort CPSR decode fabricates a CPAS value.
#   F8  CP  Req   Get State (03h), TAG=77h                   [MCTP tag 2]
#   F9  CP  Resp  status 04h (Invalid Parameter).  Figure 32 puts the
#                 Parameter Error Location in bytes 7:5: BITLOC=2, BYTLOC=16.
#                 Decoded as a Success response this is TAG=02h + CPSR=0010h
#                 and the whole diagnostic payload disappears.
#   F10 CP  Req   Get State (03h), TAG=33h                   [MCTP tag 3]
#   F11 CP  Resp  status 00h (Success), TAG=33h, CPSR=4001h -- the control:
#                 a Success response still decodes Tag and CPSR.
#
#   --- Admin Data window that no structured decoder renders (Figure 114
#       allows a 2-Wire MTU of 64 bytes, so a BMC walking the 4096-byte
#       Identify structure sends many such windows) ---
#
#   F12 ADM Req   Identify CNS=1Ch, DOFST=64, DLEN=64        [MCTP tag 4]
#   F13 ADM Resp  status 00h + 64 data bytes.  CNS 1Ch has no case in
#                 dissect_nvme_identify_resp(), so the "Data" subtree stays
#                 empty -- but nvme_dissect_admin_data_resp() still returns
#                 true (Identify *is* in the structured set), which used to
#                 hide the raw bytes item as well.  The payload must remain
#                 visible in the detail tree.
#   F14 ADM Req   Identify CNS=01h, DOFST=0, DLEN=64         [MCTP tag 5]
#   F15 ADM Resp  status 00h + the first 64 bytes of an Identify Controller
#                 structure -- the control: the structured decode does render
#                 fields here, so the raw bytes item stays hidden.

_ERR_MI_REQ_1 = make_packet(True,  NVME_MI_TYPE_MI, 0,
                            mi_request_payload(0x01), tag=0, ic=True)
_ERR_MI_REQ_2 = make_packet(True,  NVME_MI_TYPE_MI, 0,
                            mi_request_payload(0x04), tag=0, ic=True)
_ERR_MI_RESP  = make_packet(False, NVME_MI_TYPE_MI, 0,
                            mi_response_payload(STATUS_SUCCESS), tag=0, ic=True)
_ERR_MI_REQ_3 = make_packet(True,  NVME_MI_TYPE_MI, 0,
                            mi_request_payload(0x01), tag=6, ic=True)
_ERR_MI_RESP_NOMIC = make_packet(False, NVME_MI_TYPE_MI, 0,
                                 mi_response_payload(STATUS_SUCCESS), tag=6,
                                 ic=True)

packets_error_paths = [
    _ERR_MI_REQ_1,
    (_ERR_MI_REQ_2[:-6], len(_ERR_MI_REQ_2)),
    _ERR_MI_RESP,
    _ERR_MI_REQ_3,
    (_ERR_MI_RESP_NOMIC[:-4], len(_ERR_MI_RESP_NOMIC)),

    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_ABORT, tag=0x5A), tag=1),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                bytes([0x08, 0x00, 0xEF, 0xBE]), tag=1),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x77), tag=2),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                bytes([0x04, 0x02]) + struct.pack('<H', 16), tag=2),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x33), tag=3),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                cp_response_payload(STATUS_SUCCESS, tag=0x33, cpsr=0x4001), tag=3),

    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, cns=0x1C, flags=0x03,
                                      doff=64, dlen=64), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes(range(64))), tag=4),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, cns=0x01, flags=0x01,
                                      doff=0, dlen=64), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_data()[:64]), tag=5),
]

BASE_TS_ERROR_PATHS_US = 1709548800 * 1_000_000

def build_error_paths_pcapng(output_path):
    data = shb() + idb()
    for i, pkt in enumerate(packets_error_paths):
        ts = BASE_TS_ERROR_PATHS_US + i * 1_000_000
        if isinstance(pkt, tuple):       # (sliced bytes, original length)
            data += epb(pkt[0], ts, origlen=pkt[1])
        else:
            data += epb(pkt, ts)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_error_paths)} packets to {output_path}")


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

    # nvme-mi-admin-security.pcapng — Security Send/Receive payload decode
    out11 = sys.argv[11] if len(sys.argv) > 11 else os.path.join(
        captures_dir, 'nvme-mi-admin-security.pcapng')
    build_admin_security_pcapng(out11)
    print()

    # nvme-mi-admin-logpage-windowed.pcapng — multi-window Get Log Page
    # (DOFST!=0), cross-checked against NVMe Base 2.3 Figure 210
    out12 = sys.argv[12] if len(sys.argv) > 12 else os.path.join(
        captures_dir, 'nvme-mi-admin-logpage-windowed.pcapng')
    build_admin_logpage_windowed_pcapng(out12)
    print()

    # nvme-mi-features-windowed.pcapng — Set/Get Features windowed-transfer
    # fixes (APST, Timestamp, PLMC, HBS off-dropping + PLMC/HBS underflow)
    out13 = sys.argv[13] if len(sys.argv) > 13 else os.path.join(
        captures_dir, 'nvme-mi-features-windowed.pcapng')
    build_features_windowed_pcapng(out13)
    print()

    # nvme-mi-tcg-atom-classes.pcapng — TCG token-stream atom-class coverage
    # (Medium/Long atoms, signed atoms, nested lists, wide-integer fallback)
    out14 = sys.argv[14] if len(sys.argv) > 14 else os.path.join(
        captures_dir, 'nvme-mi-tcg-atom-classes.pcapng')
    build_tcg_atom_classes_pcapng(out14)
    print()

    # nvme-mi-tcg-malformed.pcapng — TCG token-stream error-path coverage
    # (reserved control token, length-overrun atom, truncated atom header)
    out15 = sys.argv[15] if len(sys.argv) > 15 else os.path.join(
        captures_dir, 'nvme-mi-tcg-malformed.pcapng')
    build_tcg_malformed_pcapng(out15)
    print()

    # nvme-mi-admin-eom.pcapng - Physical Interface Receiver Eye Opening
    # Measurement log page (LID 19h), NVMe over PCIe Transport 1.3 Figs 72/73
    out16 = sys.argv[16] if len(sys.argv) > 16 else os.path.join(
        captures_dir, 'nvme-mi-admin-eom.pcapng')
    build_admin_eom_pcapng(out16)
    print()

    # nvme-mi-error-paths.pcapng - sliced-MIC slot lifecycle, Control
    # Primitive error responses, and an Admin data window nothing decodes
    out17 = sys.argv[17] if len(sys.argv) > 17 else os.path.join(
        captures_dir, 'nvme-mi-error-paths.pcapng')
    build_error_paths_pcapng(out17)
