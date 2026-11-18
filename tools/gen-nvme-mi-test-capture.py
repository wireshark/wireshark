#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate pcapng test captures for the NVMe-MI dissector.

Most captures hold several builders' output, one pcapng section per builder;
the comment above each build_merged() call in main() maps the sections, and
each builder's own frame map numbers its frames from 1.  The first two
builders of nvme-mi-types.pcapng are mapped here:

nvme-mi-types.pcapng F108-F114  (build_pcapng, 7 frames)
  Exercises the core request/response matching and MPR slot-tracking fix:
  1. Basic MI request/response (CSI=0)
  2. Admin command with More Processing Required (MPR) then final response (CSI=0)
  3. Concurrent MI command on the second slot (CSI=1), interleaved with the MPR sequence

nvme-mi-types.pcapng F1-F107  (build_comprehensive_pcapng)
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
  - PCIe command (type=0x4) — a Configuration Read and its Success response
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

import contextlib
import io
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapng_testgen import (
    DLT_LINUX_I2C,
    DLT_LINUX_SLL2,
    crc32c,
    epb,
    i2c_phdr,
    idb,
    shb,
    sll2_header,
    sll_header,
    smbus_pec,
)


def write_pcapng(output_path, packets, base_us, idbs=None, step_us=1_000_000):
    """Write packets step_us apart; a packet is bytes, (bytes, origlen) or (bytes, origlen, interface)."""
    data = shb() + (idb() if idbs is None else idbs)
    for i, packet in enumerate(packets):
        if isinstance(packet, (bytes, bytearray)):
            packet = (packet,)
        packet, origlen, interface = tuple(packet) + (None, 0)[len(packet) - 1:]
        data += epb(packet, base_us + i * step_us, origlen=origlen,
                    interface_id=interface)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets)} packets to {output_path}")

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

def mctp_header(is_request, host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0,
                som=True, eom=True, seq=0):
    src = host_eid if is_request else bmc_eid
    dst = bmc_eid  if is_request else host_eid
    to  = 0x08 if is_request else 0x00
    fst = ((0x80 if som else 0x00) | (0x40 if eom else 0x00)
           | ((seq & 0x03) << 4) | to | (tag & 0x07))
    return bytes([0x01, dst, src, fst])

# ---------------------------------------------------------------------------
# NVMe-MI header (4 bytes) — this IS the MCTP message payload start
# ---------------------------------------------------------------------------
# Byte 0: MCTP type byte = 0x04 (NVMe-MI), bit 7 = IC
# Byte 1: [ROR(7)][msg_type(6:3)][CSI(0)]
#   Control type = 0x0  → bits 3-6 = 0000 → 0x00
#   MI      type = 0x1  → bits 3-6 = 0001 → 0x08
#   Admin   type = 0x2  → bits 3-6 = 0010 → 0x10
#   PCIe    type = 0x4  → bits 3-6 = 0100 → 0x20
#   ROR: 0 = request, 1 = response
# Bytes 2-3: reserved 0x00
#
# ---------------------------------------------------------------------------
# Why IC = 1 is the default for every message this file builds
# ---------------------------------------------------------------------------
# NVMe-MI 2.1 3.1.1: "The IC bit is set to '1' in all NVMe-MI Messages in the
# out-of-band mechanism", and the Figure 20 IC row repeats it as a shall for
# out-of-band Response Messages and Asynchronous Event Messages.  Every frame
# in this corpus is out-of-band by construction -- the NVMe-MI dissector is
# registered on "mctp.type" alone, so nothing reaches it any other way.
#
# IC = 1 is therefore the default, and a real CRC-32C MIC is computed and
# appended for it.  IC = 0 is still reachable, but only by asking for it
# explicitly, and only where a frame is a deliberate negative vector (see
# nvme-mi-types.pcapng F179-F202).

NVME_MI_TYPE_CONTROL = 0x0
NVME_MI_TYPE_MI      = 0x1
NVME_MI_TYPE_ADMIN   = 0x2
NVME_MI_TYPE_PCIE    = 0x4
NVME_MI_TYPE_AEM      = 0x5   # Asynchronous Event Message (Figure 20)
NVME_MI_TYPE_RESERVED = 0x3   # 3h and 6h-Fh are Reserved (Figure 20)

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

    The MIC covers the header and the payload -- everything ahead of it -- and
    the canonical CRC-32C result is serialised least-significant octet first,
    like every other NVMe-MI field (libnvme: cpu_to_le32 on transmit,
    le32_to_cpu on verify).  `struct.pack('<I', crc32c(...))` below is that
    serialisation and must not change: it is what an endpoint puts on the
    wire, and every committed capture's MIC bytes depend on it.

    Which integer the dissector's nvme-mi.mic field *shows* is a separate
    question, and it has been answered both ways.  It now shows the canonical
    CRC value -- the number Figure 21's parameters produce, Appendix B
    publishes and a CRC tool reports -- read little-endian like every other
    NVMe-MI field (3.2.1).  Only the field and filter representation has ever
    moved; these bytes did not.  So for nvme-mi-types.pcapng F41 the wire bytes
    are still d2 d4 77 36 and nvme-mi.mic reads their canonical value,
    0x3677d4d2.

    `mic`, when given, overrides the computed value.  It is still a canonical
    CRC integer, packed the same way, and it exists for the deliberately
    corrupt MIC integrity vectors (nvme-mi-types.pcapng F179-F202) and for
    nothing else.
    """
    hdr = nvme_mi_header(msg_type, csi, is_response, ic=ic, meb=meb, ciap=ciap)
    if not ic:
        assert mic is None, "an IC = 0 message carries no MIC to override"
        return hdr + payload
    if mic is None:
        mic = crc32c(hdr + payload)
    return hdr + payload + struct.pack('<I', mic)

# ---------------------------------------------------------------------------
# NVMe-MI MI payload
# ---------------------------------------------------------------------------

def mi_request_payload(opcode, cdw0=0, cdw1=0):
    """MI command request: opcode(1) + rsvd(3) + CDW0(4) + CDW1(4) = 12 bytes."""
    return bytes([opcode, 0, 0, 0]) + struct.pack('<II', cdw0, cdw1)

def mi_response_payload(status, nmresp=0):
    """MI command response: status(1) + nmresp(3) = 4 bytes."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3]

def pcie_request_payload(opcode, ctlid=0, nmd0=0, nmd1=0, nmd2=0, data=b'',
                         rsvd=0):
    """PCIe command request (NVMe-MI 2.1 Figure 147): OPC, Reserved, CTLID,
    NMD0-NMD2, then optional Request Data."""
    return (bytes([opcode, rsvd]) + struct.pack('<HIII', ctlid, nmd0, nmd1, nmd2)
            + data)

def pcie_response_payload(status, data=b'', rsvd=0):
    """PCIe command response (Figure 150): Status, Reserved(3), RESPD."""
    return bytes([status]) + struct.pack('<I', rsvd)[:3] + data

# A Configuration Read of the Vendor and Device ID dword.
PCIE_CFG_READ_ID = pcie_request_payload(0x00, ctlid=0x0001, nmd0=4, nmd1=0x000)
PCIE_CFG_ID_DATA = bytes.fromhex('86805309')

def mi_response_payload_with_data(status, data, nmresp=0):
    """MI command response with trailing data bytes (exercises nvme-mi.mi.data)."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3] + data

# ---------------------------------------------------------------------------
# AE Occurrence List (NVMe-MI 2.1 Figures 61 and 62)
# ---------------------------------------------------------------------------
#
# One structure with two call sites, which is why it is built here rather than
# inside one capture:
#
#   * the entire body of an Asynchronous Event Message -- Figure 60 gives an
#     AEM only a header, an Asynchronous Event Data field and a MIC, and 4.4.4
#     says "The AE Occurrence List data structure shall start at offset 0h of
#     the Asynchronous Event Data field"; and
#   * the Response Data of a Configuration Set of the Asynchronous Event
#     configuration, i.e. the Response Message to an AEM Ack or an AE Sync
#     (5.2.4).
#
# The AEM Transmission Info byte is the one field that means different things
# on the two paths, so aeo_list() takes AEMGN and AEMRC separately.

AEO_LIST_HDR_LEN  = 7      # AEOLHL "shall be set to 7h" (Figure 61)
AEO_ENTRY_HDR_LEN = 9      # AELHLEN "shall be set to 9h" (Figure 62)

# AE Occurrence Scope values (Figure 62); the scope selects which Figure 64
# layout the 4-byte AE Occurrence Scope ID Info field carries.
AEO_SCOPE_CONTROLLER = 0x1
AEO_SCOPE_SUBSYSTEM  = 0x2
AEO_SCOPE_MGMT_EP    = 0x3
AEO_SCOPE_PORT       = 0x4
AEO_SCOPE_ENDURANCE_GRP = 0x5

def aeo_entry(ae_id, scope, scope_id=0, specific=b'', vendor=b''):
    """One AE Occurrence data structure (Figure 62).

    A 9-byte header -- AELHLEN, AEOSIL, AEOVSIL, then the 6-byte AE Occurrence
    Unique ID (AE Occurrence ID, the scope-selected 4-byte Scope ID Info and
    the Scope Info byte) -- followed by the two optional payloads, whose
    lengths the header declares.
    """
    return (bytes([AEO_ENTRY_HDR_LEN, len(specific), len(vendor), ae_id])
            + struct.pack('<I', scope_id) + bytes([scope & 0x0F])
            + specific + vendor)

def aeo_list(entries, aemgn=0, aemrc=0, overflow=False, aelver=0,
             hdr_len=AEO_LIST_HDR_LEN, numaeo=None, total_len=None):
    """An AE Occurrence List data structure (Figure 61).

    Every field defaults to the conformant value derived from `entries`, so a
    caller names only the deviation it wants.  Byte 6 is AEMTI, built from the
    AEM Generation Number and AEM Retry Count: it "shall be cleared to 0h" in
    the Response Message to an AEM Ack or an AE Sync, and carries the
    generation and retry counts in an AEM.

    An overflow list carries the header and no body (4.4.4), so pass
    entries=[] with overflow=True; AEOLTL is then cleared to 0h as required.
    """
    body = b''.join(entries)
    if numaeo is None:
        numaeo = len(entries)
    if total_len is None:
        total_len = 0 if overflow else hdr_len + len(body)
    aeolli = (0x800000 if overflow else 0) | (total_len & 0x7FFFFF)
    aemti = ((aemgn & 0x1F) << 3) | (aemrc & 0x07)
    return (bytes([numaeo, aelver]) + struct.pack('<I', aeolli)[:3]
            + bytes([hdr_len, aemti]) + body)

# ---------------------------------------------------------------------------
# MI command response data structures (NVMe-MI 2.1 §5)
# ---------------------------------------------------------------------------

def port_info_pcie():
    """Port Information data structure (Figure 117) with PCIe-specific data
    (Figure 118), 32 bytes."""
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

def port_info_twire(prtcap=0x01):
    """Port Information data structure with 2-Wire-specific data
    (Figure 119), 32 bytes.

    Bit 0 of `prtcap` is the bit that MI 2.2 Figure 117 redefines -- CIAPS in
    2.1, "obsolete, shall be set to 1" in 2.2 -- so a version-context fixture
    has to be able to vary it independently of the rest of the structure.
    """
    return (bytes([
        0x02,                       # PRTTYP = 2-Wire
        prtcap,                     # PRTCAP (bit 1 AEMS, bit 0 CIAPS/obsolete)
    ]) + struct.pack('<H', 64)      # MMTUS = 64 bytes
       + struct.pack('<I', 0)       # MEBS = 0 (no MEB)
       + bytes([
        0x53,                       # CVPDADDR
        0x02,                       # MVPDFREQ = 400 kHz
        0x1D,                       # CMEADDR
        0x82,                       # TWPRT = I3CSPRT | MSMBFREQ=400 kHz
        0x00,                       # NVMEBM = no basic management
    ]) + b'\x00' * 19)              # reserved to 32 bytes

def subsys_info(mjr=0x02, mnr=0x01, nnsc=0x01, nump=0x01):
    """NVM Subsystem Information data structure (Figure 115), 32 bytes.

    Bytes 01 and 02 are the only place an NVM Subsystem advertises which
    revision of NVMe-MI it implements (Figure 112 in NVMe-MI 2.1, Figure 115
    in 2.2 -- the offsets did not move), and Figure 113 / Figure 116 map them
    onto published versions: 2h/1h is 2.1 and 2h/2h is 2.2, the row 2.2 added.
    Neither table has a catch-all Reserved row, so a pair that appears in
    neither must not be diagnosed as reserved or invalid -- but neither is it
    proof of a later publication.  Such a tuple has uncertain provenance and
    is carried as the bytes it is.  The defaults are MJR 2 / MNR 1 / NNSC
    bit 0 set.
    """
    return bytes([
        nump,                       # NUMP (0's based -> nump + 1 ports)
        mjr,                        # MJR
        mnr,                        # MNR
        nnsc,                       # NNSC (bit 0: SRE in 2.1, obsolete in 2.2)
    ]) + b'\x00' * 28               # reserved to 32 bytes

def nshds():
    """NVM Subsystem Health Data Structure (Figure 105), 8 bytes."""
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
    controller *before* DOFST/DLEN slice the NVMe-MI response (NVMe-MI 2.2
    Figure 142/143); combined with a nonzero doff to test that both layers
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
STATUS_INTERNAL_ERROR = 0x02

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

# The four Identify Controller bytes a DLEN of 4 selects: VID, SSVID.  A
# Success Response to a Response-Data command owes exactly DLEN bytes
# (NVMe-MI 2.2 Figure 139), so a stub answer to an Identify request carries
# these rather than nothing.
ID4 = struct.pack('<HH', 0x144d, 0x144d)

def make_packet(is_request, msg_type, csi, payload,
                host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0, ic=True, meb=False,
                ciap=False, mic=None):
    src_eid  = host_eid if is_request else bmc_eid
    sll      = sll_header(src_eid, outgoing=is_request)
    mctp     = mctp_header(is_request, host_eid=host_eid, bmc_eid=bmc_eid, tag=tag)
    return sll + mctp + nvme_mi_message(msg_type, csi,
                                        is_response=not is_request,
                                        payload=payload, ic=ic, meb=meb,
                                        ciap=ciap, mic=mic)

def aem_packet(payload, tag=0, ciap=False, ic=True, mic=None, to=True):
    """One Asynchronous Event Message (NMIMT 5h) carrying `payload` as its
    Asynchronous Event Data.

    make_packet() cannot build one, because an AEM is neither a Request nor a
    Response Message: NVMe-MI 2.1 4.4.4 has it travel from the Management
    Endpoint to the Management Controller while *owning* the MCTP tag ("the Msg
    tag shall be selected by the Management Endpoint and the Tag Owner bit
    shall be set to '1' since the AEM originates from the Management Endpoint",
    with the Destination Endpoint ID set to the entity that most recently
    caused an AE Arm) -- device to host, yet TO=1, which no request/response
    direction produces.  In the NVMe-MI header the ROR bit "is not applicable"
    to an AEM and is cleared to '0', as is CSI (Figure 20).

    IC follows the same rule it does everywhere else here: Figure 20's IC row
    names the Asynchronous Event Message explicitly among the out-of-band
    messages in which the bit "shall be set to '1'".

    `to` is the MCTP Tag Owner bit of 4.4.4 (a) quoted above; False builds
    the one AEM the corpus needs that violates it.
    """
    sll  = sll_header(BMC_EID, outgoing=False)
    mctp = bytes([0x01, HOST_EID, BMC_EID,
                  0xC0 | (0x08 if to else 0x00) | (tag & 0x07)])
    return sll + mctp + nvme_mi_message(NVME_MI_TYPE_AEM, 0,
                                        is_response=False, payload=payload,
                                        ic=ic, ciap=ciap, mic=mic)

# ---------------------------------------------------------------------------
# Build the 7-frame core capture (nvme-mi-types.pcapng F108-F114)
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
    # Frame 3: Admin Request, CSI=0, opcode=0x06 (Identify, CNS=1), DLEN=4
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0, admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01, dlen=4)),
    # Frame 4: MI Request, CSI=1, opcode=0x04 (Configuration Get) — concurrent slot
    make_packet(True,  NVME_MI_TYPE_MI,    1, mi_request_payload(0x04)),
    # Frame 5: Admin Response, CSI=0, status=0x01 (MPR) — interim for Frame 3
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_response_payload(STATUS_MPR)),
    # Frame 6: MI Response, CSI=1, status=0x00 (Success) — answers Frame 4
    make_packet(False, NVME_MI_TYPE_MI,    1, mi_response_payload(STATUS_SUCCESS)),
    # Frame 7: Admin Response, CSI=0, status=0x00 (Success) — final answer for Frame 3,
    #          carrying the 4 bytes DLEN selected
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_response_payload(STATUS_SUCCESS, cqe1=0xABCD1234) + ID4),
]

# Timestamps: 1-second intervals starting at 2024-01-15 10:00:00 UTC
BASE_TS_REQ_RESP_US = 1705312800 * 1_000_000

def build_pcapng(output_path):
    write_pcapng(output_path, packets_req_resp, BASE_TS_REQ_RESP_US)
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
    # with realistic command dwords and response payloads.

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

    # F24-F25: PCIe Configuration Read (type=0x4) of the ID dword
    p.append(make_packet(True,  NVME_MI_TYPE_PCIE, 0, PCIE_CFG_READ_ID))
    p.append(make_packet(False, NVME_MI_TYPE_PCIE, 0,
                         pcie_response_payload(STATUS_SUCCESS, PCIE_CFG_ID_DATA)))

    # F26: Admin Identify on CSI=1 — unanswered (no response before capture end)
    p.append(make_packet(True, NVME_MI_TYPE_ADMIN, 1,
                         admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01)))

    # F27: MI Config Get (CID=02h Health Status Change) on CSI=0 — unanswered
    p.append(make_packet(True, NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x00000002)))

    # F28-F29: Second MCTP conversation (BMC_EID=0x09) — independent slot tracking
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01, dlen=4),
                         bmc_eid=BMC_EID2))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS) + ID4,
                         bmc_eid=BMC_EID2))

    # F30-F33: Conversation isolation under interleaving.
    # Conv1 opens a slot, then Conv2 (different EID) opens and fully closes
    # while Conv1's slot is still pending.  Conv2's response (F32) must not
    # close Conv1's slot; Conv1's response (F33) must still link back to F30.
    # F27 (previously the last Conv1 frame, MI Req on CSI=0) is superseded on
    # slot 0 when F30 arrives — this is intentional and tested separately.
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0004, cns=0x01, dlen=4)))
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0002, cns=0x01, dlen=4),
                         bmc_eid=BMC_EID2))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS) + ID4,
                         bmc_eid=BMC_EID2))
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS) + ID4))

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
                         admin_request_payload(0x06, ctrl_id=0x0005, cns=0x01, dlen=4),
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
                         admin_response_payload(STATUS_SUCCESS, cqe1=0x12345678) + ID4,
                         tag=0))
    # F39: [tag=1] Admin Req  CSI=0 opcode=0x06 ctrl_id=0x0006 — tag=1 slot
    p.append(make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                         admin_request_payload(0x06, ctrl_id=0x0006, cns=0x01, dlen=4),
                         tag=1))
    # F40: [tag=1] Admin Resp CSI=0 -> F39
    p.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                         admin_response_payload(STATUS_SUCCESS, cqe1=0xCAFEBABE) + ID4,
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
    # F73-F90: MI command per-opcode decode fixtures — one exchange
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

    # F95-F96: Reset, RSTTYP=00h (Reset NVM Subsystem).  F96 is an *Error*
    # Response, and must stay one.  NVMe-MI 2.1 section 5: "When a Reset
    # command that specifies a Reset NVM Subsystem in the Reset Type field
    # completes successfully... No Success Response is transmitted."  An Error
    # Response is what a Reset that did not complete successfully returns, so
    # F96 is the negative control for the Reset conformance expert: a Reset
    # 00h answered with an error must stay silent.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x07, cdw0=0x00000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_INTERNAL_ERROR)))

    # F97-F98: Shutdown, SHDNTYP=01h (Abrupt NVM Subsystem Shutdown).
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x0C, cdw0=0x01000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F99-F100: Reset with a reserved RSTTYP=02h — must fire the
    # reserved-value expert.  F100 stays a Success Response deliberately:
    # section 5's "no Success Response" promise is made only about a Reset
    # that specifies Reset NVM Subsystem, so a Success answer to a *Reserved*
    # Reset Type is odd but not normatively impossible, and it is the
    # negative control proving the Reset conformance expert keys on RSTTYP
    # rather than on the opcode.
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x07, cdw0=0x02000000)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload(STATUS_SUCCESS)))

    # F101-F103: sliced MPR interim response.  F102 is an MPR interim whose
    # capture was cut right after the 4-byte NVMe-MI header (caplen 24 of 32),
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
    # of Figure 90: ENCFA (bit 24), AEM Delay (bits 23:16) and AEM Retry Delay
    # (bits 15:08).  The request carries an AE Enable List (Figures 91/92) as
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
    # NMD0 carries only the CONFIGID (the Set-only fields of Figure 90 are
    # reserved here, Figure 80); the Success Response returns AEELVER in the
    # NVMe Management Response and an AE Supported List (Figures 82/83) as
    # Response Data — Composite Temperature (ID 06h) currently enabled,
    # PCIe Link Active (ID 0Bh) supported but disabled.
    #
    # AEELVER (the NMRESP byte) is 0h, as Figure 81 requires: "This field
    # shall be cleared to 0h."  The deliberate AEELVER=1 fixture lives in
    # nvme-mi-mi-commands.pcapng F419-F458.
    aes_list = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])  # NUMAES=2, ver=0, AESTL=11, AESLHL=5
                + bytes([3]) + struct.pack('<H', 0x8006)            # AESE=1, ID=06h
                + bytes([3]) + struct.pack('<H', 0x000B))           # AESE=0, ID=0Bh
    p.append(make_packet(True,  NVME_MI_TYPE_MI, 0,
                         mi_request_payload(0x04, cdw0=0x00000004)))
    p.append(make_packet(False, NVME_MI_TYPE_MI, 0,
                         mi_response_payload_with_data(STATUS_SUCCESS,
                                                       aes_list, nmresp=0)))

    assert len(p) == 107, f"Expected 107 frames, got {len(p)}"
    return p

packets_comprehensive = _packets_comprehensive()

# Timestamps: 1-second intervals starting at 2024-02-01 10:00:00 UTC
BASE_TS_TYPES_US = 1706781600 * 1_000_000

def build_comprehensive_pcapng(output_path):
    write_pcapng(output_path, packets_comprehensive, BASE_TS_TYPES_US)
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
        "F102: MI Resp  CSI=0  SLICED MPR (caplen 24/32, status byte missing) -> F101",
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
# nvme-mi-admin-identify.pcapng F29-F41 — Admin SQE CDW10-15 shared-decode coverage
# ---------------------------------------------------------------------------
#
# Standalone admin-request capture exercising nvme_dissect_admin_sqe_cdws()
# (shared with packet-nvme.c) under the NVMe-MI Admin dissector, plus the
# prohibited-opcode expert.  Each request rides its own MCTP tag so no two
# share a command slot (keeps every request independent; no superseded-slot
# noise).  Responses are omitted: only the request side is decoded.
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
#   F12  Directive Send (19h)  Prohibited over MI (Figure 137) -> prohibited-opcode
#                              expert
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
    write_pcapng(output_path, packets_admin_decode, BASE_TS_ADMIN_US)

# ---------------------------------------------------------------------------
# nvme-mi-admin-identify.pcapng F42-F51 — Admin response status + CQE DW0 decode
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
#          -> DW0 TMPTH, bits 31:16 not defined for a completion
#             (Base 2.3 5.2.26.1.3); status Success
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
                # Base 2.3 5.2.26.1.3 returns "the temperature threshold
                # selected by Command Dword 11" and nothing else.  F1's CDW11
                # is 0: Composite Temperature, Over Temperature Threshold.  So
                # the completion is that threshold (014Bh K) with 31:16 clear.
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0000014B,
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
                admin_request_payload(0x06, ctrl_id=0x0004, cns=0x01, dlen=4), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xCAFEBABE,
                                       cqe3=admin_cqe3(cqe_status_word(m=1, dnr=1)))
                + ID4, tag=3),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0005, cns=0x01), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0,
                                       cqe3=admin_cqe3(cqe_status_word(sct=0, sc=0x23, dnr=1))),
                tag=4),
]

BASE_TS_ADMIN_RESP_US = 1709288400 * 1_000_000

def build_admin_resp_pcapng(output_path):
    write_pcapng(output_path, packets_admin_resp, BASE_TS_ADMIN_RESP_US)

# ---------------------------------------------------------------------------
# Build the cross-NMIMT slot-reuse capture (nvme-mi-types.pcapng F119-F124)
# ---------------------------------------------------------------------------
#
# Malformed: a response whose NMIMT differs from the request still occupying
# the per-CSI command slot.  ADMIN and MI commands share that slot (only
# Control Primitives are tracked out-of-band), so the framing layer finds the
# slot's outstanding request regardless of type.  Two things must then follow:
# the body dissector must NOT read the other type's recorded opcode / body_ctx
# (it checks the request's NMIMT and treats a cross-type response as an
# orphan), and the framing layer must not commit the pairing either -- no
# Request In, no Response Time, and above all no closing of a slot whose real
# answer has not arrived yet.
#
#   F1 Admin Identify request (CSI=0) -> opens the CSI=0 slot as ADMIN
#   F2 MI    success response (CSI=0) -> lands on the ADMIN slot; the MI body
#                                        must flag orphan, not recover opc 06h,
#                                        and the frame must take no link
#   F3 MI    request          (CSI=1) -> opens the CSI=1 slot as MI
#   F4 Admin success response (CSI=1) -> lands on the MI slot; the Admin body
#                                        must flag orphan, not recover an opcode
#   F5 Admin success response (CSI=0) -> the real answer to F1; must link
#   F6 MI    success response (CSI=1) -> the real answer to F3; must link
packets_typemismatch = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01, dlen=4)),
    make_packet(False, NVME_MI_TYPE_MI,    0, mi_response_payload(STATUS_SUCCESS)),
    make_packet(True,  NVME_MI_TYPE_MI,    1, mi_request_payload(0x00)),
    make_packet(False, NVME_MI_TYPE_ADMIN, 1,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x12345678)),

    # F5/F6  the answers that really do belong to F1 and F3.  They exist to
    # prove the cross-NMIMT responses above consumed nothing: a response that
    # does not echo its request's NMIMT (Figure 28: the field "contains the
    # value from the same field in the corresponding Request Message") is not
    # the answer, so both command slots must still be occupied when these
    # arrive, and both must link and close normally.
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xA5A5000A) + ID4),
    make_packet(False, NVME_MI_TYPE_MI,    1, mi_response_payload(STATUS_SUCCESS)),
]

BASE_TS_TYPEMISMATCH_US = 1709290800 * 1_000_000

def build_typemismatch_pcapng(output_path):
    write_pcapng(output_path, packets_typemismatch, BASE_TS_TYPEMISMATCH_US)

# ---------------------------------------------------------------------------
# Build the Reserved-message-type capture (nvme-mi-types.pcapng F115-F118)
# ---------------------------------------------------------------------------
#
# NMIMT 3h and 6h-Fh are Reserved (Figure 20): such a request has no defined
# body format, so the framing layer must flag it, decode nothing from it,
# and keep it out of the command-slot lifecycle. In particular it must
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
#
# F3 carries a well-formed one-occurrence AE Occurrence List rather than filler
# bytes.  The AEM body is dissected now, so filler would raise a truncation
# expert here and this fixture is about slot bookkeeping, not about malformed
# bodies -- nvme-mi-mi-commands.pcapng F459-F481 owns the short-AEM case deliberately.
packets_reserved_type = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x000B, cns=0x01, dlen=4)),
    make_packet(True,  NVME_MI_TYPE_RESERVED, 0, b'\xAA' * 4),
    aem_packet(aeo_list([aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM,
                                   specific=bytes([0x4B]))])),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x5EED0005) + ID4),
]

# ---------------------------------------------------------------------------
# Build the MCTP-bridging capture (nvme-mi-transactions.pcapng F247-F258)
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

SMBUS_MCTP_CMD_CODE = 0x0F

BRIDGE_BMC_ADDR = 0x10
BRIDGE_DEV_ADDR = 0x3A      # one 2-Wire port; two Management Endpoints behind it
BRIDGE_BMC_EID  = 0x08
BRIDGE_ME_A_EID = 0x1E
BRIDGE_ME_B_EID = 0x1F

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

def bridge_packet(is_request, msg_type, csi, payload, dev_eid, tag, bus=0,
                  ic=True):
    """One NVMe-MI message over MCTP-over-SMBus, BMC <-> a bridged endpoint."""
    nvme_mi_msg = nvme_mi_message(msg_type, csi, is_response=not is_request,
                                  payload=payload, ic=ic)
    if is_request:
        dst_addr, src_addr = BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR
        dst_eid,  src_eid  = dev_eid, BRIDGE_BMC_EID
    else:
        dst_addr, src_addr = BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR
        dst_eid,  src_eid  = BRIDGE_BMC_EID, dev_eid
    return i2c_phdr(bus=bus) + smbus_mctp_frame(dst_addr, src_addr, dst_eid,
                                                src_eid, tag, is_request,
                                                nvme_mi_msg)

def null_eid_packet(is_request, msg_type, csi, payload, tag, bus=0, ic=True):
    """Same bus, but before MCTP EID assignment: the host is the null EID 0 in
    both directions; the device answers from its real EID."""
    nvme_mi_msg = nvme_mi_message(msg_type, csi, is_response=not is_request,
                                  payload=payload, ic=ic)
    if is_request:
        return i2c_phdr(bus=bus) + smbus_mctp_frame(BRIDGE_DEV_ADDR,
                                                    BRIDGE_BMC_ADDR,
                                                    0x00, 0x00, tag, True,
                                                    nvme_mi_msg)
    return i2c_phdr(bus=bus) + smbus_mctp_frame(BRIDGE_BMC_ADDR,
                                                BRIDGE_DEV_ADDR,
                                                0x00, BRIDGE_ME_A_EID, tag,
                                                False, nvme_mi_msg)

def null_dest_packet(is_request, msg_type, csi, payload, tag, dev_addr,
                     me_eid=None, bus=0):
    """An *assigned* host addressing a peer by physical address alone.

    DSP0236 Table 2's Null Destination EID means "the destination EID value is
    to be ignored and only physical addressing is used", and it is available to
    a host that already has an EID of its own -- which is the case null_eid_packet()
    above does not cover, because there the host is the null EID in both
    directions.  The request therefore carries a real source EID and a null
    destination; the response carries the device's real source EID and the
    host's, so the two frames do not share an EID pair at all.
    """
    nvme_mi_msg = nvme_mi_message(msg_type, csi, is_response=not is_request,
                                  payload=payload, ic=True)
    if is_request:
        return i2c_phdr(bus=bus) + smbus_mctp_frame(dev_addr, BRIDGE_BMC_ADDR,
                                                    0x00, BRIDGE_BMC_EID, tag,
                                                    True, nvme_mi_msg)
    return i2c_phdr(bus=bus) + smbus_mctp_frame(BRIDGE_BMC_ADDR, dev_addr,
                                                BRIDGE_BMC_EID, me_eid, tag,
                                                False, nvme_mi_msg)


packets_mctp_bridge = [
    bridge_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                  admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01, dlen=4),
                  BRIDGE_ME_A_EID, tag=0),
    bridge_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                  admin_request_payload(0x02, ctrl_id=0x0002, cns=0x02),
                  BRIDGE_ME_B_EID, tag=0),
    bridge_packet(False, NVME_MI_TYPE_ADMIN, 0,
                  admin_response_payload(STATUS_SUCCESS, cqe1=0xAAAA000A) + ID4,
                  BRIDGE_ME_A_EID, tag=0),
    bridge_packet(False, NVME_MI_TYPE_ADMIN, 0,
                  admin_response_payload(STATUS_SUCCESS, cqe1=0xBBBB000B),
                  BRIDGE_ME_B_EID, tag=0),
    null_eid_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=1),
    null_eid_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS), tag=1),

    # F7/F8  The host has an EID (08h) and addresses
    # the device by physical address alone, so the request carries the Null
    # Destination EID and the response carries the device's real one: the two
    # frames share no EID pair.  Keyed on the device EID the request would sit
    # in a conversation its own response could never join, so the request is
    # keyed without it and the response falls back to that shape once.
    null_dest_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01),
                     tag=2, dev_addr=BRIDGE_DEV_ADDR),
    null_dest_packet(False, NVME_MI_TYPE_MI, 0,
                     mi_response_payload(STATUS_SUCCESS), tag=2,
                     dev_addr=BRIDGE_DEV_ADDR, me_eid=BRIDGE_ME_A_EID),

    # F9/F10  the same shape on a different physical pair and the same tag.
    # The fallback drops the device EID but never the physical addresses, so
    # this exchange must stay entirely separate from F7/F8.
    null_dest_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x04),
                     tag=2, dev_addr=BRIDGE_DEV_ADDR + 1),
    null_dest_packet(False, NVME_MI_TYPE_MI, 0,
                     mi_response_payload(STATUS_SUCCESS), tag=2,
                     dev_addr=BRIDGE_DEV_ADDR + 1, me_eid=BRIDGE_ME_B_EID),

    # F11/F12  a second null-destination exchange on F7/F8's physical pair.
    #
    # The endpoint identity of a null-destination *request* is the physical
    # pair alone -- its destination EID is the null one, so there is no usable
    # EID pair -- while its *response* carries two real EIDs and therefore a
    # fuller identity.  For F8 to release the Command Slot F7 took, the
    # response has to find the endpoint the request created, which is why
    # nvme_mi_endpoint_for_frame() retries without the EID pair.
    #
    # F11 is the witness that it did: another CSI 0 request to the same
    # endpoint, which finds the slot free and so raises no displacement note.
    # Had F8 filed its occupancy under a second, EID-bearing endpoint, F7's
    # would still be occupied here and F11 would report a supersede that never
    # happened.  A fresh tag, so the proof is about endpoint occupancy and not
    # about tag reuse.
    null_dest_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01),
                     tag=3, dev_addr=BRIDGE_DEV_ADDR),
    null_dest_packet(False, NVME_MI_TYPE_MI, 0,
                     mi_response_payload(STATUS_SUCCESS), tag=3,
                     dev_addr=BRIDGE_DEV_ADDR, me_eid=BRIDGE_ME_A_EID),
]

BASE_TS_MCTP_BRIDGE_US = 1709293200 * 1_000_000

def build_mctp_bridge_pcapng(output_path):
    write_pcapng(output_path, packets_mctp_bridge, BASE_TS_MCTP_BRIDGE_US, idb(link_type=DLT_LINUX_I2C))


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F288-F321 - which request a response to the Null
# Destination EID answers
# ---------------------------------------------------------------------------
#
# A request to the Null Destination EID (DSP0236 Table 2) is keyed without the
# device EID, and its response comes from the device's real EID, so the
# response retries that shape.  Two ways it used not to:
#
#   F288-F296  build_null_dest_sll2_pcapng: Linux MCTP (SLL2), no physical
#              addresses.  The retry ran only with them.
#     F1/F2  8 -> 0 NSHSP (01h), tag 1; 9 -> 8 answers
#     F3/F4  8 -> 9 Configuration Get (04h), tag 2, answered
#     F5/F6  8 -> 0 NSHSP, tag 2: the full key now exists (F3), empty
#     F7     0Ah -> 8 response on tag 3: no request, so an orphan
#     F8/F9  8 -> 0 NSHSP, tag 4, ifindex 1; 9 -> 8 answers on ifindex 2,
#            another bus, so an orphan and F8 stays unanswered
#
#   F297-F304  build_null_dest_slot_pcapng: MCTP over SMBus, BMC 10h EID 08h,
#              ME-A 3Ah EID 1Eh, tag 1, CSI 0.  The retry ran only when the
#              full key had no conversation.
#     F1/F2  null-destination NSHSP, answered
#     F3/F4  Configuration Get to EID 1Eh, answered
#     F5/F6  null-destination NSHSP, answered (F3 made the full key)
#     F7/F8  null-destination NSHSP, answered: F6 freed F5's slot
#
#   F305-F311  the same with F4 dropped: F3 is still outstanding when F5 goes
#              out, and the newer request is the one answered (NVMe-MI 2.1
#              section 4.2).  F1/F2, F3, F4/F5 = F5/F6, F6/F7 = F7/F8 above.
#
#   F312-F314  build_null_dest_stale_pcapng: the other way round, SMBus as
#              F297-F304.  The EID-addressed request is the newer one, so it
#              keeps the response.
#     F1     null-destination NSHSP, tag 1, never answered
#     F2/F3  Configuration Get to EID 1Eh, tag 1, answered
#   F315-F317  the same over SLL2 (host EID 8, device EID 9), linux_mctp=True
#
#   F318-F321  build_null_dest_sll2_version_pcapng: once matched, an SLL2
#              response's body is observed on its own endpoint, so the
#              version it carries qualifies later frames to that device.
#     F1/F2  8 -> 0 Read NVMe-MI Data Structure (00h), NVM Subsystem
#            Information, tag 1; 9 -> 8 answers, MJR 2, MNR 1
#     F3/F4  8 -> 9 NSHSP, tag 2, answered

NULL_DEST_HOST_EID = 0x08
NULL_DEST_DEV_EID  = 0x09
NULL_DEST_SFREQ    = 0x000002       # Configuration Get CID 01h: 400 kHz

def _null_dest_sll2(is_request, payload, tag,
                    dst_eid=NULL_DEST_DEV_EID, src_eid=NULL_DEST_DEV_EID,
                    ifindex=1):
    """One MI message over SLL2.  A
    request goes from the host to `dst_eid` (0 for the Null Destination EID);
    a response comes from `src_eid`."""
    if is_request:
        sll = sll2_header(NULL_DEST_HOST_EID, outgoing=True, ifindex=ifindex)
        mctp = mctp_header(True, host_eid=NULL_DEST_HOST_EID, bmc_eid=dst_eid,
                           tag=tag)
    else:
        sll = sll2_header(src_eid, outgoing=False, ifindex=ifindex)
        mctp = mctp_header(False, host_eid=NULL_DEST_HOST_EID, bmc_eid=src_eid,
                           tag=tag)
    return sll + mctp + nvme_mi_message(NVME_MI_TYPE_MI, 0, not is_request,
                                        payload)

def _nshsp_pair():
    return (mi_request_payload(0x01),
            mi_response_payload_with_data(STATUS_SUCCESS, nshds()))

def _cfg_get_pair():
    return (mi_request_payload(0x04, cdw0=0x01),
            mi_response_payload(STATUS_SUCCESS, nmresp=NULL_DEST_SFREQ))

def _null_dest_smbus(is_request, payload):
    """A null-destination MI message between BMC 10h and ME-A 3Ah, tag 1."""
    return null_dest_packet(is_request, NVME_MI_TYPE_MI, 0, payload, tag=1,
                            dev_addr=BRIDGE_DEV_ADDR, me_eid=BRIDGE_ME_A_EID)

def _to_me_a(is_request, payload):
    """An MI message to or from ME-A's EID, tag 1."""
    return bridge_packet(is_request, NVME_MI_TYPE_MI, 0, payload,
                         BRIDGE_ME_A_EID, tag=1)

def _write_null_dest(output_path, link_type, packets, ts_offset_us):
    write_pcapng(output_path, packets, BASE_TS_MCTP_BRIDGE_US + ts_offset_us,
                 idb(link_type=link_type))

def build_null_dest_sll2_pcapng(output_path):
    nshsp_req, nshsp_rsp = _nshsp_pair()
    cfg_req, cfg_rsp = _cfg_get_pair()
    packets = [
        _null_dest_sll2(True,  nshsp_req, tag=1, dst_eid=0),
        _null_dest_sll2(False, nshsp_rsp, tag=1),
        _null_dest_sll2(True,  cfg_req,   tag=2),
        _null_dest_sll2(False, cfg_rsp,   tag=2),
        _null_dest_sll2(True,  nshsp_req, tag=2, dst_eid=0),
        _null_dest_sll2(False, nshsp_rsp, tag=2),
        _null_dest_sll2(False, nshsp_rsp, tag=3, src_eid=0x0A),
        _null_dest_sll2(True,  nshsp_req, tag=4, dst_eid=0, ifindex=1),
        _null_dest_sll2(False, nshsp_rsp, tag=4, ifindex=2),
    ]
    _write_null_dest(output_path, DLT_LINUX_SLL2, packets, 100_000_000)

def build_null_dest_slot_pcapng(output_path, answer_eid_request=True):
    nshsp_req, nshsp_rsp = _nshsp_pair()
    cfg_req, cfg_rsp = _cfg_get_pair()
    null_dest, to_eid = _null_dest_smbus, _to_me_a
    packets = [null_dest(True, nshsp_req), null_dest(False, nshsp_rsp),
               to_eid(True, cfg_req)]
    if answer_eid_request:
        packets.append(to_eid(False, cfg_rsp))
    packets += [null_dest(True, nshsp_req), null_dest(False, nshsp_rsp),
                null_dest(True, nshsp_req), null_dest(False, nshsp_rsp)]
    _write_null_dest(output_path, DLT_LINUX_I2C, packets, 200_000_000)

def build_null_dest_stale_pcapng(output_path, linux_mctp=False):
    nshsp_req, _ = _nshsp_pair()
    cfg_req, cfg_rsp = _cfg_get_pair()
    if linux_mctp:
        link_type = DLT_LINUX_SLL2
        packets = [_null_dest_sll2(True,  nshsp_req, tag=1, dst_eid=0),
                   _null_dest_sll2(True,  cfg_req,   tag=1),
                   _null_dest_sll2(False, cfg_rsp,   tag=1)]
    else:
        link_type = DLT_LINUX_I2C
        packets = [_null_dest_smbus(True, nshsp_req), _to_me_a(True, cfg_req),
                   _to_me_a(False, cfg_rsp)]
    _write_null_dest(output_path, link_type, packets, 300_000_000)

def build_null_dest_sll2_version_pcapng(output_path):
    nshsp_req, nshsp_rsp = _nshsp_pair()
    body = subsys_info(mjr=2, mnr=1)
    packets = [
        _null_dest_sll2(True,
                        mi_request_payload(0x00, cdw0=VC_NMD0_DTYP_SUBSYS),
                        tag=1, dst_eid=0),
        _null_dest_sll2(False,
                        mi_response_payload_with_data(STATUS_SUCCESS, body,
                                                      nmresp=len(body)),
                        tag=1),
        _null_dest_sll2(True,  nshsp_req, tag=2),
        _null_dest_sll2(False, nshsp_rsp, tag=2),
    ]
    _write_null_dest(output_path, DLT_LINUX_SLL2, packets, 400_000_000)


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F322-F352 - a Replay expected on the physical
# alias of an endpoint
# ---------------------------------------------------------------------------
#
# MCTP over SMBus, BMC 10h EID 08h, the device at 3Ah, CSI 0 throughout.  A
# Null-EID message is keyed on the physical pair alone and an EID-addressed
# one on the physical pair and the EIDs, so one Management Endpoint has two
# endpoint contexts.  A Replay is matched only on its own context, so a
# response from the other one is an orphan (NVMe-MI 2.1 sections 4.2 and
# 4.2.1.3).
#
#   F322-F330  build_replay_alias_pcapng('stale'): the device has no EID yet
#              (it answers from EID 0), then is assigned 1Eh; the Set
#              Endpoint ID exchange itself is not in the section
#     F1/F2  8 -> 0 Read NVMe-MI Data Structure (00h), NVM Subsystem
#            Information, tag 1; answered
#     F3/F4  8 -> 0 Replay, RRO 0, tag 2; Success with RR set
#     F5     the replay on tag 2, with a bad MIC: refused, still expected
#     F6/F7  8 -> 1Eh Configuration Get (04h), tag 2; answered.  F6 made F2
#            unavailable for replay, so F7 answers F6
#     F8/F9  8 -> 1Eh NSHSP (01h), tag 3: F7 freed F6's slot
#   F331-F338  build_replay_alias_pcapng('abort'): F1-F5 as above, then
#     F6/F7  8 -> 1Eh Abort, tag 3; Success, CPAS 00b
#     F8     1Eh -> 8 MI Success response on tag 2: no request, and the
#            Abort discarded the replay, so an orphan
#   F339-F345  build_replay_alias_pcapng('alias')
#     F1/F2  8 -> 1Eh NSHSP, tag 1; answered
#     F3/F4  8 -> 0 Read NVMe-MI Data Structure, tag 2; answered by 1Eh
#     F5/F6  8 -> 0 Replay, RRO 0, tag 3; Success with RR set, from 1Eh
#     F7     1Eh -> 8 the replay of F4 on tag 3, from the other context:
#            an orphan
#   F346-F352  build_replay_alias_pcapng('between'): an EID-addressed command
#              between the original command and the Replay
#     F1/F2  8 -> 0 Read NVMe-MI Data Structure, tag 1; answered from EID 0
#     F3/F4  8 -> 1Eh Configuration Get, tag 2; answered.  F3 made F2
#            unavailable for replay
#     F5/F6  8 -> 0 Replay, RRO 0, tag 3; Success with RR set, from 1Eh
#     F7     1Eh -> 8 MI Success response on tag 3: not the replay of F2, so
#            an orphan

def _replay_alias_packet(is_request, msg_type, payload, tag, eid, mic=None):
    """BMC 10h EID 08h <-> the device at 3Ah, CSI 0.  `eid` is the device's
    side of the MCTP header: 0 for a Null Destination EID request or a device
    with no EID yet, ME-A's 1Eh otherwise."""
    msg = nvme_mi_message(msg_type, 0, not is_request, payload, mic=mic)
    if is_request:
        frame = smbus_mctp_frame(BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR, eid,
                                 BRIDGE_BMC_EID, tag, True, msg)
    else:
        frame = smbus_mctp_frame(BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR,
                                 BRIDGE_BMC_EID, eid, tag, False, msg)
    return i2c_phdr() + frame

def build_replay_alias_pcapng(output_path, variant):
    nshsp_req, nshsp_rsp = _nshsp_pair()
    cfg_req, cfg_rsp = _cfg_get_pair()
    body = subsys_info(mjr=2, mnr=1)
    read_req = mi_request_payload(0x00, cdw0=VC_NMD0_DTYP_SUBSYS)
    read_rsp = mi_response_payload_with_data(STATUS_SUCCESS, body,
                                             nmresp=len(body))
    replay_req = cp_request_payload(CP_OPC_REPLAY, tag=0x31)
    replay_rsp = cp_response_payload(STATUS_SUCCESS, tag=0x31, cpsr=0x0001)
    mi, cp, me_a, p = (NVME_MI_TYPE_MI, NVME_MI_TYPE_CONTROL, BRIDGE_ME_A_EID,
                       _replay_alias_packet)
    if variant == 'alias':
        packets = [p(True, mi, nshsp_req, 1, me_a), p(False, mi, nshsp_rsp, 1, me_a),
                   p(True, mi, read_req, 2, 0), p(False, mi, read_rsp, 2, me_a),
                   p(True, cp, replay_req, 3, 0), p(False, cp, replay_rsp, 3, me_a),
                   p(False, mi, read_rsp, 3, me_a)]
    else:
        bad_mic = crc32c(nvme_mi_header(mi, 0, True) + read_rsp) ^ 0xFFFFFFFF
        packets = [p(True, mi, read_req, 1, 0), p(False, mi, read_rsp, 1, 0),
                   p(True, cp, replay_req, 2, 0), p(False, cp, replay_rsp, 2, 0),
                   p(False, mi, read_rsp, 2, 0, mic=bad_mic)]
        if variant == 'between':
            packets = [p(True, mi, read_req, 1, 0), p(False, mi, read_rsp, 1, 0),
                       p(True, mi, cfg_req, 2, me_a), p(False, mi, cfg_rsp, 2, me_a),
                       p(True, cp, replay_req, 3, 0), p(False, cp, replay_rsp, 3, me_a),
                       p(False, mi, cfg_rsp, 3, me_a)]
        elif variant == 'stale':
            packets += [p(True, mi, cfg_req, 2, me_a), p(False, mi, cfg_rsp, 2, me_a),
                        p(True, mi, nshsp_req, 3, me_a), p(False, mi, nshsp_rsp, 3, me_a)]
        else:
            assert variant == 'abort', variant
            packets += [p(True, cp, cp_request_payload(CP_OPC_ABORT, tag=0x32), 3, me_a),
                        p(False, cp, cp_response_payload(STATUS_SUCCESS, tag=0x32), 3, me_a),
                        p(False, mi, cfg_rsp, 2, me_a)]
    _write_null_dest(output_path, DLT_LINUX_I2C, packets, 500_000_000)


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F353-F412 - a Replay whose original response
# never reached NVMe-MI
# ---------------------------------------------------------------------------
#
# MCTP over SMBus, BMC 10h EID 08h, ME-A at 3Ah EID 1Eh, CSI 0 throughout.  The
# original response to a Read NVMe-MI Data Structure (00h) for a 40-entry
# Controller List is two packets (94 bytes, 64-byte transmission unit), and
# only its first packet is sent: the transmission is paused or cut off in the
# Transmit state, so MCTP never completes the message.  A Replay with RR set
# then retransmits it on the Replay's own Msg tag (NVMe-MI 2.1 section
# 4.2.1.5, the Transmit state), and that copy is the command's response.
#
#   F353-F366  build_replay_lost_original_pcapng('transmit')
#     F1     8 -> 1Eh Read NVMe-MI Data Structure, Controller List, tag 1
#     F2     the first packet of its response (SOM, no EOM), tag 1
#     F3/F4  Pause, tag 2; Success
#     F5/F6  Replay, RRO 0, tag 2; Success with RR set
#     F7/F8  the replayed response on tag 2: F1's response
#     F9/F10 Replay, RRO 0, tag 3; Success with RR set
#     F11/F12 the replayed response again on tag 3: the replay of F8
#     F13/F14 8 -> 1Eh NSHSP (01h), tag 4: F8 freed F1's slot
#   F367-F375  build_replay_lost_original_pcapng('partial'): F1-F4 as above,
#     F5/F6  Replay, RRO 1, tag 2; Success with RR set
#     F7     the replay from packet 1 on tag 2: F1's response, kept raw
#     F8/F9  8 -> 1Eh NSHSP, tag 3
#   F376-F385  build_replay_lost_original_pcapng('alias'): the Replay is
#              expected on the physical alias (the Null Destination EID)
#     F1/F2  8 -> 1Eh NSHSP, tag 1; answered
#     F3     8 -> 0 Read NVMe-MI Data Structure, Controller List, tag 2
#     F4     the first packet of its response from 1Eh, tag 2
#     F5/F6  8 -> 0 Replay, RRO 0, tag 3; Success with RR set, from 1Eh
#     F7/F8  the replayed response from 1Eh on tag 3: F3's response, from
#            the other context, so orphans
#     F9/F10 8 -> 0 NSHSP, tag 4; answered from 1Eh
#   F386-F392  build_replay_lost_original_pcapng('between'): an EID-addressed
#              command between the original command and the Replay
#     F1     8 -> 0 Read NVMe-MI Data Structure, Controller List, tag 1
#     F2     the first packet of its response from 1Eh, tag 1
#     F3/F4  8 -> 1Eh Configuration Get (04h), tag 2; answered.  F3 made F1's
#            response unavailable for replay
#     F5/F6  8 -> 0 Replay, RRO 0, tag 3; Success with RR set, from 1Eh
#     F7     1Eh -> 8 MI Success response on tag 3: not F1's, so an orphan
#   F393-F402  build_replay_lost_original_pcapng('mismatch'): F1/F2 as in
#              'transmit', then
#     F3/F4  Replay, RRO 0, tag 2; Success with RR set
#     F5     an Admin response on tag 2: not an MI response, so not the replay
#     F6     an MI response for CSI 1 on tag 2: not the slot, so not the replay
#     F7/F8  the replayed response on tag 2: F1's response
#     F9/F10 8 -> 1Eh NSHSP, tag 3
#   F403-F412  build_replay_lost_original_pcapng('unanswered'): F1-F6 as in
#              'transmit', and the replayed response is never captured
#     F7/F8  Replay, RRO 0, tag 3; Success with RR set, while F5's
#            expectation is still open
#     F9/F10 8 -> 1Eh NSHSP, tag 4, while F7's expectation is still open:
#            no replay was seen, so nothing freed F1's slot

def _replay_lost_frames(is_request, msg, tag, eid, first_only=False):
    """`msg` between BMC 10h EID 08h and the device at 3Ah, one frame per
    64-byte packet (DSP0236 8.4.2).  `eid` is the device's side of the MCTP
    header (0 for a Null Destination EID request).  `first_only` sends the
    first packet and nothing after it."""
    chunks = [msg[i:i + 64] for i in range(0, len(msg), 64)]
    if first_only:
        chunks = chunks[:1]
    frames = []
    for i, chunk in enumerate(chunks):
        eom = i == len(chunks) - 1 and not first_only
        if is_request:
            frame = smbus_mctp_frame(BRIDGE_DEV_ADDR, BRIDGE_BMC_ADDR, eid,
                                     BRIDGE_BMC_EID, tag, True, chunk,
                                     som=i == 0, eom=eom, seq=i)
        else:
            frame = smbus_mctp_frame(BRIDGE_BMC_ADDR, BRIDGE_DEV_ADDR,
                                     BRIDGE_BMC_EID, eid, tag, False, chunk,
                                     som=i == 0, eom=eom, seq=i)
        frames.append(i2c_phdr() + frame)
    return frames

def build_replay_lost_original_pcapng(output_path, variant):
    mi, cp, admin, me_a = (NVME_MI_TYPE_MI, NVME_MI_TYPE_CONTROL,
                           NVME_MI_TYPE_ADMIN, BRIDGE_ME_A_EID)
    data = mi_struct_ctrl_list(list(range(1, 41)))
    read_req = nvme_mi_message(mi, 0, False, mi_request_payload(
        0x00, cdw0=mi_struct_nmd0(0x02)))
    read_rsp = nvme_mi_message(mi, 0, True, mi_response_payload_with_data(
        STATUS_SUCCESS, data, nmresp=len(data)))
    assert len(read_rsp) == 94, len(read_rsp)
    nshsp_req, nshsp_rsp = (nvme_mi_message(mi, 0, not req, p)
                            for req, p in zip((True, False), _nshsp_pair()))
    cfg_req, cfg_rsp = (nvme_mi_message(mi, 0, not req, p)
                        for req, p in zip((True, False), _cfg_get_pair()))

    def cp_pair(opcode, ctl_tag, tag, eid=me_a, rsp_eid=me_a, rro=0, cpsr=0):
        return (_replay_lost_frames(True, nvme_mi_message(
                    cp, 0, False, cp_request_payload(opcode, tag=ctl_tag, cpsp=rro)),
                    tag, eid)
                + _replay_lost_frames(False, nvme_mi_message(
                    cp, 0, True, cp_response_payload(STATUS_SUCCESS, tag=ctl_tag,
                                                     cpsr=cpsr)),
                    tag, rsp_eid))

    def replay(ctl_tag, tag, eid=me_a, rro=0):
        return cp_pair(CP_OPC_REPLAY, ctl_tag, tag, eid=eid, rro=rro, cpsr=0x0001)

    f = _replay_lost_frames
    lost = f(True, read_req, 1, me_a) + f(False, read_rsp, 1, me_a, first_only=True)
    pause = cp_pair(CP_OPC_PAUSE, 0x41, 2)
    if variant == 'transmit':
        packets = (lost + pause + replay(0x42, 2) + f(False, read_rsp, 2, me_a)
                   + replay(0x43, 3) + f(False, read_rsp, 3, me_a)
                   + f(True, nshsp_req, 4, me_a) + f(False, nshsp_rsp, 4, me_a))
    elif variant == 'partial':
        packets = (lost + pause + replay(0x42, 2, rro=1)
                   + f(False, read_rsp[:4] + read_rsp[64:], 2, me_a)
                   + f(True, nshsp_req, 3, me_a) + f(False, nshsp_rsp, 3, me_a))
    elif variant == 'alias':
        packets = (f(True, nshsp_req, 1, me_a) + f(False, nshsp_rsp, 1, me_a)
                   + f(True, read_req, 2, 0) + f(False, read_rsp, 2, me_a, first_only=True)
                   + replay(0x42, 3, eid=0) + f(False, read_rsp, 3, me_a)
                   + f(True, nshsp_req, 4, 0) + f(False, nshsp_rsp, 4, me_a))
    elif variant == 'between':
        packets = (f(True, read_req, 1, 0) + f(False, read_rsp, 1, me_a, first_only=True)
                   + f(True, cfg_req, 2, me_a) + f(False, cfg_rsp, 2, me_a)
                   + replay(0x42, 3, eid=0) + f(False, cfg_rsp, 3, me_a))
    elif variant == 'unanswered':
        packets = (lost + pause + replay(0x42, 2) + replay(0x43, 3)
                   + f(True, nshsp_req, 4, me_a) + f(False, nshsp_rsp, 4, me_a))
    else:
        assert variant == 'mismatch', variant
        packets = (lost + replay(0x42, 2)
                   + f(False, nvme_mi_message(admin, 0, True,
                                              admin_response_payload(STATUS_SUCCESS)),
                       2, me_a)
                   + f(False, nvme_mi_message(mi, 1, True, _nshsp_pair()[1]), 2, me_a)
                   + f(False, read_rsp, 2, me_a)
                   + f(True, nshsp_req, 3, me_a) + f(False, nshsp_rsp, 3, me_a))
    _write_null_dest(output_path, DLT_LINUX_I2C, packets, 600_000_000)


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F413-F451 - a Replay expected on an endpoint's
# EID-keyed context, then a Null Destination EID message in its slot
# ---------------------------------------------------------------------------
#
# The other way round from F322-F352: MCTP over SMBus, BMC 10h EID 08h, ME-A
# at 3Ah EID 1Eh, CSI 0 throughout.  The Replay is armed on the EID-keyed
# context, and then a Null-EID command or successful Abort, keyed on the SMBus
# pair alone, comes into the same Command Slot.  The two contexts are kept
# apart, so that does not discard the response the Replay would retransmit
# (NVMe-MI 2.1 sections 4.2 and 4.2.1.3).
#
#   F413-F421  build_replay_eid_alias_pcapng('stale')
#     F1/F2  8 -> 1Eh Read NVMe-MI Data Structure (00h), NVM Subsystem
#            Information, tag 1; answered
#     F3/F4  8 -> 1Eh Replay, RRO 0, tag 2; Success with RR set
#     F5     the replay on tag 2, with a bad MIC: refused, still expected
#     F6/F7  8 -> 0 Configuration Get (04h), tag 2; F7, from 1Eh, is the
#            replay of F2
#     F8/F9  8 -> 0 NSHSP (01h), tag 3; answered from 1Eh
#   F422-F429  build_replay_eid_alias_pcapng('abort'): F1-F5 as above, then
#     F6/F7  8 -> 0 Abort, tag 3; Success, CPAS 00b, from 1Eh
#     F8     1Eh -> 8 MI Success response on tag 2: the replay of F2, as
#            the Abort was on the other context
#   F430-F436  build_replay_eid_alias_pcapng('alias'): a Null-EID command
#              before the original command changes nothing
#     F1/F2  8 -> 0 NSHSP, tag 1; answered from 1Eh
#     F3/F4  8 -> 1Eh Read NVMe-MI Data Structure, tag 2; answered
#     F5/F6  8 -> 1Eh Replay, RRO 0, tag 3; Success with RR set
#     F7     1Eh -> 8 the replay of F4 on tag 3
#   F437-F443  build_replay_eid_alias_pcapng('between'): a Null-EID command
#              between the original command and the Replay
#     F1/F2  8 -> 1Eh Read NVMe-MI Data Structure, tag 1; answered
#     F3/F4  8 -> 0 Configuration Get, tag 2; answered from 1Eh
#     F5/F6  8 -> 1Eh Replay, RRO 0, tag 3; Success with RR set
#     F7     1Eh -> 8 MI Success response on tag 3: the replay of F2
#   F444-F451  build_replay_eid_alias_pcapng('lost'): the original response
#              never reached NVMe-MI, as in F353-F412
#     F1     8 -> 1Eh Read NVMe-MI Data Structure, Controller List, tag 1
#     F2     the first packet of its response, tag 1
#     F3/F4  8 -> 1Eh Replay, RRO 0, tag 2; Success with RR set
#     F5/F6  8 -> 0 Configuration Get, tag 2; F6, from 1Eh, is the replay of
#            F1's response
#     F7/F8  8 -> 0 NSHSP, tag 3; answered from 1Eh

def build_replay_eid_alias_pcapng(output_path, variant):
    nshsp_req, nshsp_rsp = _nshsp_pair()
    cfg_req, cfg_rsp = _cfg_get_pair()
    body = subsys_info(mjr=2, mnr=1)
    read_req = mi_request_payload(0x00, cdw0=VC_NMD0_DTYP_SUBSYS)
    read_rsp = mi_response_payload_with_data(STATUS_SUCCESS, body,
                                             nmresp=len(body))
    replay_req = cp_request_payload(CP_OPC_REPLAY, tag=0x31)
    replay_rsp = cp_response_payload(STATUS_SUCCESS, tag=0x31, cpsr=0x0001)
    mi, cp, me_a, p = (NVME_MI_TYPE_MI, NVME_MI_TYPE_CONTROL, BRIDGE_ME_A_EID,
                       _replay_alias_packet)
    if variant == 'alias':
        packets = [p(True, mi, nshsp_req, 1, 0), p(False, mi, nshsp_rsp, 1, me_a),
                   p(True, mi, read_req, 2, me_a), p(False, mi, read_rsp, 2, me_a),
                   p(True, cp, replay_req, 3, me_a), p(False, cp, replay_rsp, 3, me_a),
                   p(False, mi, read_rsp, 3, me_a)]
    elif variant == 'between':
        packets = [p(True, mi, read_req, 1, me_a), p(False, mi, read_rsp, 1, me_a),
                   p(True, mi, cfg_req, 2, 0), p(False, mi, cfg_rsp, 2, me_a),
                   p(True, cp, replay_req, 3, me_a), p(False, cp, replay_rsp, 3, me_a),
                   p(False, mi, cfg_rsp, 3, me_a)]
    elif variant == 'lost':
        data = mi_struct_ctrl_list(list(range(1, 41)))
        lost_req = nvme_mi_message(mi, 0, False, mi_request_payload(
            0x00, cdw0=mi_struct_nmd0(0x02)))
        lost_rsp = nvme_mi_message(mi, 0, True, mi_response_payload_with_data(
            STATUS_SUCCESS, data, nmresp=len(data)))
        packets = (_replay_lost_frames(True, lost_req, 1, me_a)
                   + _replay_lost_frames(False, lost_rsp, 1, me_a, first_only=True)
                   + [p(True, cp, replay_req, 2, me_a), p(False, cp, replay_rsp, 2, me_a),
                      p(True, mi, cfg_req, 2, 0), p(False, mi, cfg_rsp, 2, me_a),
                      p(True, mi, nshsp_req, 3, 0), p(False, mi, nshsp_rsp, 3, me_a)])
    else:
        bad_mic = crc32c(nvme_mi_header(mi, 0, True) + read_rsp) ^ 0xFFFFFFFF
        packets = [p(True, mi, read_req, 1, me_a), p(False, mi, read_rsp, 1, me_a),
                   p(True, cp, replay_req, 2, me_a), p(False, cp, replay_rsp, 2, me_a),
                   p(False, mi, read_rsp, 2, me_a, mic=bad_mic)]
        if variant == 'stale':
            packets += [p(True, mi, cfg_req, 2, 0), p(False, mi, cfg_rsp, 2, me_a),
                        p(True, mi, nshsp_req, 3, 0), p(False, mi, nshsp_rsp, 3, me_a)]
        else:
            assert variant == 'abort', variant
            packets += [p(True, cp, cp_request_payload(CP_OPC_ABORT, tag=0x32), 3, 0),
                        p(False, cp, cp_response_payload(STATUS_SUCCESS, tag=0x32), 3, me_a),
                        p(False, mi, cfg_rsp, 2, me_a)]
    _write_null_dest(output_path, DLT_LINUX_I2C, packets, 700_000_000)


BASE_TS_RESERVED_TYPE_US = 1709292000 * 1_000_000

def build_reserved_type_pcapng(output_path):
    write_pcapng(output_path, packets_reserved_type, BASE_TS_RESERVED_TYPE_US)


def build_nmimt_error_pcapng(output_path):
    """Reserved-NMIMT error responses (MI 2.1 3.1.1, 4.1.2, Figs 28-32)."""
    invalid = b'\xAA' * 4
    pel_nmimt = bytes.fromhex('04 03 01 00')  # byte 1, bit 3
    reply = make_packet(False, NVME_MI_TYPE_RESERVED, 0, pel_nmimt, tag=1)
    generic = make_packet(False, NVME_MI_TYPE_RESERVED, 0,
                          bytes.fromhex('02 00 00 00'), tag=1)
    packets = [
        # F1/F9: an ordinary Admin command around the error exchange.
        (make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                     admin_request_payload(0x06, ctrl_id=0xB, cns=1, flags=0,
                                           dlen=4)), 0),
        (make_packet(True, NVME_MI_TYPE_RESERVED, 0, invalid, tag=1), 0),
        # F3/F4: neither successful nor unknown status defines a body.
        (make_packet(False, NVME_MI_TYPE_RESERVED, 0,
                     bytes.fromhex('00 03 01 00'), tag=1), 0),
        (make_packet(False, NVME_MI_TYPE_RESERVED, 0,
                     bytes.fromhex('09 03 01 00'), tag=1), 0),
        (reply, 1),  # F5: same tag/EIDs, on another interface.
        (reply[:-1] + bytes([reply[-1] ^ 1]), 0),  # F6: MIC failure.
        (reply[:26], 0),  # F7: sliced midway through PEL; no invented fields.
        (reply, 0),  # F8: conformant NMIMT error.
        (make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                     admin_response_payload(STATUS_SUCCESS, cqe1=0x5EED0005) + ID4), 0),
        # F10/F11: NMIMT and CIAP are both invalid; PEL may select CIAP.
        (make_packet(True, NVME_MI_TYPE_RESERVED, 0, invalid,
                     tag=1, ciap=True), 0),
        (make_packet(False, NVME_MI_TYPE_RESERVED, 0,
                     bytes.fromhex('04 01 02 00'), tag=1), 0),
        # F12/F13: an error after a request with a bad MIC.
        (make_packet(True, NVME_MI_TYPE_RESERVED, 0, invalid, tag=2,
                     mic=0), 0),
        (make_packet(False, NVME_MI_TYPE_RESERVED, 0, pel_nmimt, tag=2), 0),
        # F14-F17: a Reserved-NMIMT request and an MI command on one tag.
        (make_packet(True, NVME_MI_TYPE_RESERVED, 1, invalid, tag=3), 0),
        (make_packet(True, NVME_MI_TYPE_MI, 1,
                     mi_request_payload(0x04, cdw0=0x01), tag=3), 0),
        (make_packet(False, NVME_MI_TYPE_RESERVED, 1, pel_nmimt, tag=3), 0),
        (make_packet(False, NVME_MI_TYPE_MI, 1,
                     mi_response_payload(STATUS_SUCCESS), tag=3), 0),
        # F18-F20: generic common format; a missing MIC cannot close it.
        (make_packet(True, NVME_MI_TYPE_RESERVED, 0, invalid, tag=1), 0),
        (generic[:-2], 0),
        (generic, 0),
    ]
    packets = [(packet, len(reply) if i in (6, 18) else None, interface)
               for i, (packet, interface) in enumerate(packets)]
    write_pcapng(output_path, packets, BASE_TS_RESERVED_TYPE_US, idb() + idb())


# ---------------------------------------------------------------------------
# nvme-mi-admin-identify.pcapng — Admin Identify response payload decode
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
                       mn="WIRESHARK MODEL NUMBER", cntlid=0x0007, total=4096,
                       vwci=0):
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
    buf[254] = vwci                     # VWCI: VWCRV bit 7, VWCR 6:0 (Fig 328)

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

    Every field in bytes 103:31 carries a distinct non-zero value so a
    decoder reading at the wrong offset reports a visibly wrong number rather
    than a plausible zero; the three genuinely-Reserved runs (83, 91:88 and 98:96) stay zero-filled, so their
    lengths are pinned separately in suite_dissection_nvme_mi.py.

    The buffer is filled to byte 383 -- the end of the LBA Format region -- and
    then truncated to `total`, so a caller modelling a DLEN-truncated transfer
    (total < 384) still gets the real structure's leading bytes.
    """
    buf = bytearray(max(total, 384))
    struct.pack_into('<Q', buf, 0, nsze)
    struct.pack_into('<Q', buf, 8, ncap)
    buf[25] = nlbaf                                # NLBAF, 0's based

    # 103:31
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
    # laid out per Fig 116 -- RP 25:24, LBADS 23:16, MS 15:00.  Every index
    # carries a distinct value and the supported count deliberately runs past
    # 15, so LBAF63..LBAF16 are decoded too: NLBAF is 0's based,
    # NULBAF is not, and section 5.5 packs the unique-attribute formats
    # directly after the shared-attribute ones, so (2+1)+47 = 50 are supported.
    for i in range(nlbaf + 1 + nulbaf):
        struct.pack_into('<I', buf, 128 + i * 4,
                         ((i & 0x3) << 24)           # RP
                         | ((9 + i % 4) << 16)       # LBADS
                         | i)                        # MS -- unique per index

    return bytes(buf[:total])

def identify_ns_data_wide_lbaf(total=4096):
    """Identify Namespace whose LBA Formats use the full width of MS and LBADS.

    Every other fixture keeps MS <= 7 and LBADS <= 12, which the narrower masks
    MS 7:0 and LBADS 19:16 render exactly as the real ones do -- so only values
    that overflow them can pin NVM Command Set 1.2 Figure 116's actual widths
    (MS 15:00, LBADS 23:16)."""
    buf = bytearray(identify_ns_data(nlbaf=2, nulbaf=0, total=total))
    # LBAF0 is a plain 512-byte format that renders identically under either
    # mask, so it anchors that the entries decode at all; LBAF1 and LBAF2 each
    # overflow one of the two narrow masks by itself.
    for i, (rp, lbads, ms) in enumerate(((0, 9, 0),        # baseline
                                         (0, 12, 4096),    # MS needs 15:08
                                         (3, 16, 8))):     # LBADS needs bit 20
        struct.pack_into('<I', buf, 128 + i * 4,
                         (rp << 24) | (lbads << 16) | ms)
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
    # latency/atomicity fields non-zero (identify_ctrl_data() leaves all four
    # at 0), so the plural branches of add_ctrl_rtd3() and add_ctrl_lblocks()
    # run.  Distinct values so a formatter reading the wrong field is visible:
    #   RTD3R 87:84 = 1500000, RTD3E 91:88 = 2500000 (Base 2.3 Figure 328,
    #   microseconds), AWUN 527:526 = 1, AWUPF 529:528 = 3 (0's based, so they
    #   render as 2 and 4 logical blocks).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ID_CTRL_LATENCIES), tag=7),
    # F17/F18 Identify I/O Command Set specific Identify Controller data
    # structure (CNS 06h) with CDW11 CSI = 02h (Zoned Namespace Command Set).
    # CNS 06h is Mandatory in NVMe 2.x and is meaningless without CSI
    # (NVMe Base 2.3 Figure 324: Reserved 23:16, CSI 31:24).  The response
    # carries the four bytes the request selects (DLEN 4), raw -- CNS 06h has
    # no field decoder -- so this pair pins the command-side decode alone.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x06,
                                      cdw11=0x02000000, dlen=4), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes(4)), tag=8),
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
    # F23/F24 Identify Namespace (CNS 00h) whose LBA Formats exercise the full
    # width of both packed fields: LBAF1 has MS 4096 (over the low byte) and
    # LBAF2 has LBADS 16 (over the low nibble).  Every other fixture stays
    # inside MS <= 7 / LBADS <= 12, where the too-narrow masks render exactly
    # what the correct ones do.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x00), tag=11),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ns_data_wide_lbaf()), tag=11),
    # F25/F26 Identify Controller (CNS 01h) with VWCI = 45h: VWCRV clear and
    # VWCR 45h.  NVMe Base 2.3 Figure 328 byte 254: "If the VPD Write Cycle
    # Remaining Valid bit is cleared to '0', then this field is not valid and
    # shall be cleared to a value of 0h."
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01), tag=12),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_data(vwci=0x45)), tag=12),
    # F27/F28 the control: VWCI = C5h, the same count with VWCRV set.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0007, cns=0x01), tag=13),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_data(vwci=0xC5)), tag=13),
]

BASE_TS_ADMIN_IDENTIFY_US = 1709289600 * 1_000_000

def build_admin_identify_pcapng(output_path):
    write_pcapng(output_path, packets_admin_identify, BASE_TS_ADMIN_IDENTIFY_US)


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng — Admin Get Log Page response payload decode
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

def smart_data(ct=320, asc=100, ast=10, pu=5, poh=12345, total=512, cw=0x00,
               dur=0, duw=0, olec=0, ipm=0):
    """Partial SMART / Health Information log page (NVMe Base 2.3 Fig 210).

    dur/duw are the raw wire values of Data Units Read (bytes 47:32) and Data
    Units Written (bytes 63:48).  Both count 512-byte data units *in thousands*
    and are rounded up, so the byte total each implies is value * 512,000.

    olec is Operational Lifetime Energy Consumed (bytes 239:232, watt-hours)
    and ipm is Interval Power Measurement (bytes 243:240); Reserved starts
    at 244."""
    buf = bytearray(total)
    buf[0] = cw                            # 00 Critical Warning (Fig 210)
    struct.pack_into('<H', buf, 1, ct)     # Composite Temperature (Kelvin)
    buf[3] = asc                           # Available Spare (%)
    buf[4] = ast                           # Available Spare Threshold (%)
    buf[5] = pu                            # Percentage Used / Life Age Estimate
    struct.pack_into('<QQ', buf, 32, dur & ((1 << 64) - 1), dur >> 64)  # 47:32 DUR
    struct.pack_into('<QQ', buf, 48, duw & ((1 << 64) - 1), duw >> 64)  # 63:48 DUW
    struct.pack_into('<Q', buf, 128, poh)  # Power On Hours (low 8 of 16 bytes)
    struct.pack_into('<Q', buf, 232, olec) # 239:232 OLEC (watt-hours)
    struct.pack_into('<I', buf, 240, ipm)  # 243:240 IPM
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
# (one running past LPVER at 63) fails the equality assertion on length as
# well as on content.
ERRINF_RSVD1 = bytes(range(0xA0, 0xB5))
assert len(ERRINF_RSVD1) == 21

def error_info_data(errcnt=42, sqid=3, cid=0x00ab, vsia=0x81, trtype=0x03,
                    csi=0x02, opc=0x09, csinfo=0x1122334455667788, ttsi=0x1234,
                    lpver=0x01, total=128, pel=0x0000, sts=0x0000):
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
    struct.pack_into('<H', buf, 12, sts)     # 13:12 Status Info: Phase Tag is
                                             #       bit 0, Status is bits 15:1
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

# The Error Information log page is a list, not a single entry: NVMe Base 2.3
# section 5.2.12.1.2, "The log page is a set of 64-byte entries; the maximum
# number of entries supported is indicated in the ELPE field in the Identify
# Controller data structure (refer to Figure 328)".  ELPE is a one-byte 0's
# based value at byte 262, so a page holds at most 256 entries.
#
# Every entry below carries a different Error Count, Submission Queue ID,
# Command ID, Opcode and Command Specific Information: identical entries would
# hide a wrong stride and a wrong entry boundary alike, since both would still
# render the same numbers.
#   (Error Count, SQID, CID, Opcode, Command Specific Information)
ERRINF_LIST_ENTRIES = (
    (0xAA01, 0x0101, 0x0011, 0x21, 0x1000000000000001),
    (0xAA02, 0x0202, 0x0022, 0x22, 0x2000000000000002),
    (0xAA03, 0x0303, 0x0033, 0x23, 0x3000000000000003),
    (0xAA04, 0x0404, 0x0044, 0x24, 0x4000000000000004),
)

# The last entry is cut short, so the transfer is not a whole multiple of the
# 64-byte stride.  40 bytes reaches the end of Command Specific Information
# (bytes 39:32) but not Transport Type Specific Information (41:40), so the
# remnant renders ECNT through CSINFO and nothing after it -- a partial entry
# that renders every field, or none, would not pin the boundary.
ERRINF_LIST_TAIL_LEN = 40

def error_info_list_data(entries=ERRINF_LIST_ENTRIES,
                         tail_len=ERRINF_LIST_TAIL_LEN):
    """len(entries) - 1 whole Error Information Log Entries followed by the
    first `tail_len` bytes of the last one.  Pass tail_len=64 for a transfer
    that is a whole number of entries."""
    buf = b''
    for i, (ecnt, sqid, cid, opc, csinfo) in enumerate(entries):
        entry = error_info_data(errcnt=ecnt, sqid=sqid, cid=cid, opc=opc,
                                csinfo=csinfo, total=64)
        buf += entry if i < len(entries) - 1 else entry[:tail_len]
    return buf

_errinf_list_data = error_info_list_data()
assert len(_errinf_list_data) == 3 * 64 + 40

# Endurance Group Information Reserved field, NVMe Base 2.3 Figure 222 bytes
# 31:08 -- exactly 24 bytes.  Distinctive for the same reason as ERRINF_RSVD1:
# an item starting at byte 6 would swallow the Domain Identifier.
EGROUP_RSVD1 = bytes(range(0xC0, 0xD8))
assert len(EGROUP_RSVD1) == 24

def egroup_data(cw=0x0c, egfeat=0x01, avsp=100, avspt=10, pused=7, did=0x1234,
                tegcap=0x1122334455667788, uegcap=0x99aabbccddeeff11,
                dur=0, duw=0, muw=0, total=512):
    """Endurance Group Information log page (NVMe Base 2.3 Fig 222).

    Critical Warning deliberately clears bit 0 (EGASB) while Endurance Group
    Features sets bit 0 (EGRMEDIA), so reading EGRMEDIA one byte early would
    report '0' instead of '1'.

    TEGCAP (175:160) and UEGCAP (191:176) are 16-byte byte-counts; only the
    low 8 bytes are set.  Their values are distinct byte patterns with no
    repeated or zero bytes, so a swapped or shifted offset renders a visibly
    different hex string rather than another plausible capacity.

    DUR (63:48), DUW (79:64) and MUW (95:80) default to 0h, which Figure 222
    defines as "the controller does not report" -- not a measurement of zero.
    All three are reported in billions of *bytes* ("a value of 1 corresponds
    to 1,000,000,000 bytes read"), unlike SMART's same-named fields, which
    count thousands of 512-byte units.  MUW carries that sentence word for
    word, so it must render exactly as its two siblings do."""
    buf = bytearray(total)
    buf[0] = cw                              # 00    Endurance Group Critical Warning
    buf[1] = egfeat                          # 01    Endurance Group Features
    buf[3] = avsp                            # 03    Available Spare
    buf[4] = avspt                           # 04    Available Spare Threshold
    buf[5] = pused                           # 05    Percentage Used
    struct.pack_into('<H', buf, 6, did)      # 07:06 Domain Identifier
    buf[8:32] = EGROUP_RSVD1                 # 31:08 Reserved
    struct.pack_into('<Q', buf, 48, dur)     # 63:48  DUR (low 8 of 16)
    struct.pack_into('<Q', buf, 64, duw)     # 79:64  DUW (low 8 of 16)
    struct.pack_into('<Q', buf, 80, muw)     # 95:80  MUW (low 8 of 16)
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

def selftest_data(nresults=20, tail=36):
    """Device Self-test log page (NVMe Base 2.3 Fig 215): a 4-byte header then
    exactly 20 Self-test Result data structures of 28 bytes each (Fig 216) --
    RDS1 at 31:04 through RDS20 at 563:536, so the page ends at 564 bytes.

    Every result carries its own Power On Hours (A000h + index) and Namespace
    Identifier (100h + index), so a walk whose index never advances, or
    advances by the wrong amount, renders a visibly wrong number instead of a
    plausible one.

    `tail` bytes of EEh follow the page; a walk bounded only by the transfer
    length would mint them into further "results" 28 at a time."""
    buf = bytearray(4 + nresults * 28 + tail)
    buf[0] = 0x00                              # 00 CDSTO: no operation in progress
    buf[1] = 0x00                              # 01 CDSTC
    for i in range(nresults):
        base = 4 + i * 28
        buf[base] = 0x10                       # DSTS: DSTC 1h (Short), DSTR 0h
        buf[base + 1] = i                      # Segment Number
        buf[base + 2] = 0x01                   # VDINFO: NSID Valid
        struct.pack_into('<Q', buf, base + 4, 0xA000 + i)   # 11:04 Power On Hours
        struct.pack_into('<I', buf, base + 12, 0x100 + i)   # 15:12 NSID
    for i in range(4 + nresults * 28, len(buf)):
        buf[i] = 0xEE
    return bytes(buf)

def changed_nslist_data(nsids, total=64):
    """Changed Attached Namespace List (LID 04h): a Namespace List (NVMe Base
    2.3 Fig 139) of four-byte namespace IDs.  Figure 139's list is ordered and
    "Unused entries are zero filled", so everything past `nsids` is fill that
    the walk has to stop at rather than render as further namespace 0 entries.

    A first entry of FFFFFFFFh is the 5.2.12.1.5 overflow sentinel ("If more
    than 1,024 namespaces have changed attributes ... the first entry in the
    log page shall be set to FFFFFFFFh and the remainder of the list shall be
    zero filled"), not the broadcast NSID its value would otherwise read as."""
    buf = bytearray(total)
    for i, nsid in enumerate(nsids):
        struct.pack_into('<I', buf, i * 4, nsid)
    return bytes(buf)

def event_aggreg_data(nument, entries):
    """Predictable Latency Event Aggregate (LID 0Bh, NVMe Base 2.3 section
    5.2.12.1.12 Figure 225) and Endurance Group Event Aggregate (LID 0Fh,
    section 5.2.12.1.15 Figure 257) are one page shape, so one builder covers
    both: an 8-byte Number of Entries (NUMENT) at bytes 07:00 then a list of
    2-byte identifiers from byte 8 on, entry N at bytes (2N+7):(2N+6).

    `entries` deliberately runs longer than `nument`: everything past NUMENT is
    fill the Get Log Page command asked for and the page does not define ("If
    the number of dwords requested ... includes data beyond the end of the
    ... log page, then zeros shall be returned"), and neither walk stopped
    there.  The fill entries are distinct and non-zero so an unbounded walk
    renders visibly different identifiers rather than more plausible zeros."""
    buf = struct.pack('<Q', nument)
    for ident in entries:
        buf += struct.pack('<H', ident)
    return buf


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
    # Bit 6 of UIDX (a 0x3f mask would report 45h as 05h) and bits on both
    # sides of Reserved are set, so any of the three masks being wrong
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
    # F27/F28 SMART (LID 02h) with Offset Type set and LPO=2, answered with a
    # full SMART payload.  F17/F18 pins the command-side OT decode but its
    # response carries no data; here the response does, so this pair is what
    # pins the response side: an index must not reach a decoder as a byte
    # offset.  LID 02h is IOS-capable per the Supported Log Pages fixture.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x02, lpo=2,
                                      cdw14=0x00800000), tag=13),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data()), tag=13),
    # F29/F30 Device Self-test (LID 06h), answered with 600 bytes: the whole
    # 564-byte page (NVMe Base 2.3 Figure 215, RDS1 through RDS20) plus 36
    # trailing bytes that are not part of it: the walk must stop at 20 results
    # and advance its index for each one.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x06,
                                      doff=0, dlen=600), tag=14),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(selftest_data()), tag=14),
    # F31/F32 Changed Attached Namespace List (LID 04h): three real namespace
    # IDs followed by 13 dwords of zero fill.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x04,
                                      doff=0, dlen=64), tag=15),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(
                    changed_nslist_data([0x00000001, 0x0000002a, 0x00002000])),
                tag=15),
    # F33/F34 The same page carrying only the FFFFFFFFh overflow sentinel,
    # which is also the broadcast NSID but does not mean "all namespaces" here.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x04,
                                      doff=0, dlen=64), tag=16),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(changed_nslist_data([0xFFFFFFFF])), tag=16),
    # F35/F36 Predictable Latency Event Aggregate (LID 0Bh): NUMENT declares
    # three entries and the response carries eight, so the five past the count
    # are fill.  Entry 2 is 0h, which section 5.2.12.1.12 says the page "shall
    # not contain" -- inside NUMENT, so it is a real violation and not just
    # more fill.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0B,
                                      doff=0, dlen=24), tag=17),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(
                    event_aggreg_data(3, [0x0005, 0x0000, 0x0009,
                                          0x1111, 0x2222, 0x3333,
                                          0x4444, 0x5555])), tag=17),
    # F37/F38 Endurance Group Event Aggregate (LID 0Fh): the same page shape
    # with NUMENT = 2 and eight entries present.  Section 5.2.12.1.15 states no
    # rule against a 0h entry, so every identifier here is non-zero and this
    # pair covers the walk bound alone.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0F,
                                      doff=0, dlen=24), tag=18),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(
                    event_aggreg_data(2, [0x0007, 0x0003, 0x6666,
                                          0x7777, 0x8888, 0x9999,
                                          0xAAAA, 0xBBBB])), tag=18),
    # F39/F40 Error Information (LID 01h) answered with 232 bytes: three whole
    # 64-byte entries (NVMe Base 2.3 Figure 209) and then 40 bytes of a fourth.
    # Every entry must render, not just entry 0; the odd tail pins what a
    # partial trailing entry renders.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x01,
                                      doff=0, dlen=232), tag=19),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_errinf_list_data), tag=19),
    # F41/F42 Endurance Group Information (LID 09h) with a NON-ZERO DUR and
    # DUW.  Every other Endurance Group frame in the corpus leaves both 0h, so
    # nothing pinned the reported case: Figure 222 makes 0h "the controller
    # does not report" and makes a non-zero value a rounded-up ceiling, and
    # the two must not render alike.  3 and 7 are distinct and small, so they
    # print in full rather than in scientific notation and a DUR/DUW offset
    # swap shows up as a different number.
    #
    # The values are deliberately tiny: Figure 222 counts billions of BYTES
    # here (a value of 1 is 1,000,000,000 bytes), unlike SMART's thousands of
    # 512-byte units, so the wire value is already the magnitude the "(GB)"
    # label names.  A test asserts 3 and 7 render as 3 and 7 -- if anyone ever
    # "fixes" these to be scaled like SMART's, that assertion is what fails.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, cns=0x09), tag=20),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(egroup_data(dur=3, duw=7, muw=5)), tag=20),
]

BASE_TS_ADMIN_LOGPAGE_US = 1709376000 * 1_000_000

def build_admin_logpage_pcapng(output_path):
    write_pcapng(output_path, packets_admin_logpage, BASE_TS_ADMIN_LOGPAGE_US)


# ---------------------------------------------------------------------------
# nvme-mi-admin-features.pcapng — Admin Get/Set Features payload decode
# ---------------------------------------------------------------------------
#
# The MI admin response routes Get Features inline data (offset 16 onward)
# through the shared packet-nvme.c dissect_nvme_data_response(), which
# dispatches on the FID the request SQE carried (CDW10, recovered from
# body_ctx) to the per-FID structure decoder.  The three Mandatory Management
# Endpoint metadata FIDs (7Dh/7Eh/7Fh) all return a Host Metadata data
# structure (NVMe Base 2.3 Figures 461/462).
#
#   F1/F2  Get Features Controller Metadata (FID 7Eh)  -> 2 descriptors (Fig 463)
#   F3/F4  Get Features Namespace Metadata  (FID 7Fh)  -> 2 descriptors (Fig 464)
#   F5/F6  Set Features Enhanced Ctrl Meta  (FID 7Dh)  -> request EA field (CDW11)
#   F7/F8  Get Features Temperature Threshold (FID 04h) -> already-covered DW0
#          (TMPTH only; 31:16 not defined for a completion, 5.2.26.1.3)
#   F29..F32 Set/Get Features Async Event Config (FID 0Bh) -> Figure 409 bits
#   F33..F36 Get/Set Features Timestamp (FID 0Eh) -> Figures 415 and 414
#   F37/F38  Get Features Pred Latency Mode Window (FID 14h) -> Figure 425 DW0
#   F39..F42 Get Features Arbitration (FID 01h) with Select 011b and 000b
#            -> Figure 199 supported capabilities vs the Feature's own layout
#   F43/F44  Get Features Temperature Threshold with a CDW11 selector and a
#            completion whose undefined upper half is non-zero
#
# admin_request_payload()'s cns argument is CDW10, whose low byte is the FID
# (dissect_nvme_get/set_features_cmd reads it from offset 40), so cns=FID.

F_ARBITRATION            = 0x01
F_ENH_CTRL_METADATA      = 0x7d
F_CTRL_METADATA          = 0x7e
F_NS_METADATA            = 0x7f
F_TEMP_THRESHOLD         = 0x04
F_HOST_CNTL_THERM_MGMT   = 0x10
F_LBA_RANGE_TYPE         = 0x03
F_PRED_LAT_MODE_WIND     = 0x14
F_NS_WRITE_CONF          = 0x84
F_IRQ_VECTOR_CONF        = 0x09
F_ASYNC_EVENT_CONF       = 0x0b
F_TIMESTAMP              = 0x0e
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

# The Host Metadata structure the Set Features requests below carry as their
# NVMe Request Data.  Shared by F5 (DOFST=0) and F27 (DOFST=64) so the only
# difference between those two frames is the Data Offset field.
_hmd_set_features_data = host_metadata_data([
    host_metadata_descriptor(0x01, "nvme9"),    # OS Controller Name
    host_metadata_descriptor(0x10, "overtemp"), # Host-Determined Failure Record
], total=128)

# The 8-byte Timestamp data structure shared by F33/F34 (Get) and F35/F36
# (Set), so the direction is the only difference between the two renderings.
# Little-endian: byte 07 = A5h, byte 06 = 53h, bytes 05:00 = 123456789ABCh.
_timestamp_data = struct.pack('<Q', 0xA553123456789ABC)

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
                _hmd_set_features_data, tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=2),
    # F7/F8 Get Features Temperature Threshold (FID 04h): an already-covered
    # Optional FID -- its CQE DW0 must still reach the shared per-FID decoder
    # over the MI path.  Base 2.3 5.2.26.1.3 returns only "the temperature
    # threshold selected by Command Dword 11", and F7's CDW11 is 0 (Composite
    # Temperature, Over Temperature Threshold), so the completion is that
    # threshold with bits 31:16 clear.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0004, cns=F_TEMP_THRESHOLD), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0000014B,
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
    # F13..F22: five Set/Get Features group members, each with its own display
    # name rather than the container's ("DWORD11", "DWORD12" or "DWORD0").
    # Every value below is non-zero and distinct from its
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
    # CD=0, plus a synthetic Reserved bit (20) set, so an IV mask covering the
    # whole dword or a CD mask covering IV shows as a wrong value.
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
    # F27/F28 Set Features Enhanced Controller Metadata (FID 7Dh) again, byte
    # for byte F5's request except that DOFST is 64 instead of 0.
    #
    # doff=64 here is DELIBERATELY non-conformant and must stay that way.
    # NVMe-MI 2.2 Figure 139 defines DOFST as "the starting offset, in bytes,
    # of the portion of data contained in the NVMe Admin Command completion
    # data that shall be returned ... for commands that are defined to
    # transfer NVMe Response Data", and says it "should be cleared to 0h for
    # all other commands (i.e., ... commands that are defined to transfer NVMe
    # Request Data from a Management Controller to a Management Endpoint)".
    # Set Features transfers Request Data, so DOFST must NOT window the
    # request payload: the 128 bytes are a whole Host Metadata structure
    # starting at its NMED byte, and must decode identically to F5's.
    #
    # flags=0x00 (rather than F5's 0x01) keeps the obsolete DOFSTV/DLENV
    # comment off this frame, so the Data Offset note is its only expert and
    # can be asserted by exact equality.
    #
    # Pinned by TestNvmeMiAdminFeatures::test_request_data_ignores_dofst and
    # ::test_request_side_dofst_is_noted.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0003,
                                      cns=F_ENH_CTRL_METADATA, flags=0x00,
                                      doff=64, dlen=len(_hmd_set_features_data),
                                      cdw11=(0x2 << 13)) +
                _hmd_set_features_data, tag=13),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=13),
    # F29..F32 Set/Get Features Asynchronous Event Configuration (FID 0Bh).
    #
    # NVMe Base 2.3 Figure 409 defines every bit of this dword except 26:22,
    # including eleven notification-enable bits at 30:27 and 21:15.  Section
    # 5.2.26.1.5 returns the same figure in Dword 0 of a Get Features
    # completion, so both paths need a frame.
    #
    # Both CDW11 (F29) and CQE DW0 (F31) set all eleven of those bits, so a
    # missing row or a mask that covers 30:15 cannot pass.  The Reserved
    # 26:22 run is deliberately non-zero and different in each frame (10101b in F29, 01010b in F31) so a Reserved
    # mask that is too wide or too narrow shows as a wrong value rather than
    # as a zero that any mask renders identically.  The already-decoded bits
    # 14:08 alternate, and alternate in *opposite* phase between the two
    # frames, so a row reading its neighbour's bit is visible too.
    #
    #   F29 CDW11   = FD7FD55Ah  SHCW=5Ah, 14:08 = 1010101b, 21:15 all set,
    #                            rsvd 26:22 = 10101b, 31:27 all set
    #   F31 CQE DW0 = FABFAAA5h  SHCW=A5h, 14:08 = 0101010b, 21:15 all set,
    #                            rsvd 26:22 = 01010b, 31:27 all set
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x000a,
                                      cns=F_ASYNC_EVENT_CONF,
                                      cdw11=0xFD7FD55A), tag=14),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=14),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x000a,
                                      cns=F_ASYNC_EVENT_CONF), tag=15),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xFABFAAA5,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=15),
    # F33..F36 Get/Set Features Timestamp (FID 0Eh).
    #
    # The two directions do not share a data structure.  NVMe Base 2.3
    # Figure 414 (Set Features) defines bytes 07:06 as Reserved; Figure 415
    # (Get Features) defines byte 06 as the Timestamp Attribute (TSTMPS) --
    # 07:04 Reserved, 03:01 Timestamp Origin (TSTMPO), 00 Synch (SYNC) -- and
    # only byte 07 as Reserved, so the layout depends on the direction.
    #
    # F33/F34 is the Get pair and F35/F36 the Set pair, carrying the *same*
    # eight bytes, so the direction is the only difference between them:
    #
    #   bytes 05:00  TSTMP  = 123456789ABCh -- every byte distinct, so a mask
    #                         shifted by a byte shows a wrong value
    #   byte  06     TSTMPS = 53h -> Reserved 07:04 = 5h, TSTMPO = 001b
    #                         ("initialized with a Set Features command"),
    #                         SYNC = 1b ("may have stopped counting").  The
    #                         07:04 Reserved run is deliberately non-zero so a
    #                         too-wide TSTMPO mask shows as a wrong value
    #                         rather than a zero any mask renders alike.
    #   byte  07     Reserved = A5h -- differs from byte 06, so the Get side's
    #                         one-byte Reserved and the Set side's two-byte
    #                         Reserved (A553h) cannot be confused.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x000b,
                                      cns=F_TIMESTAMP), tag=16),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_timestamp_data), tag=16),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x000b,
                                      cns=F_TIMESTAMP,
                                      dlen=len(_timestamp_data)) +
                _timestamp_data, tag=17),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=17),
    # F37/F38 Get Features Predictable Latency Mode Window (FID 14h).
    #
    # NVMe Base 2.3 section 5.2.26.1.13 says a Get Features for this FID
    # returns Figure 425 -- Command Dword 12, whose only field is Window
    # Select at 02:00 -- in Dword 0 of the completion.  The CQE group carried
    # Figure 424 instead (Command Dword 11, NVM Set Identifier 15:00), which
    # is the *request* dword, so the completion answered "which window is this
    # NVM Set in" with a plausible-looking NVM Set Identifier.
    #
    #   CQE DW0 = A5B6C7D2h  WSEL 02:00 = 010b (Non-Deterministic Window),
    #                        Reserved 31:03 = 14B6D8FAh
    #
    # WSEL is NDWIN here where F21's Set-side CDW12 is DTWIN, so the two
    # cannot be confused, and the Reserved run is non-zero across the whole
    # dword: under the old layout the same bits rendered NVMSETID = C7D2h and
    # Reserved = A5B6h, so both fields move.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x000c,
                                      cns=F_PRED_LAT_MODE_WIND), tag=18),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xA5B6C7D2,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=18),
    # F39..F42 Get Features Arbitration (FID 01h), Select 011b then 000b.
    #
    # NVMe Base 2.3 section 5.2.11.1: "A Select field set to 011b (i.e.,
    # supported capabilities) returns the capabilities supported for this
    # Feature Identifier ... in Dword 0 of the completion queue entry", laid
    # out by Figure 199 -- 31:03 Reserved, 02 Changeable (CHANG), 01 NS
    # Specific (NSSPEC), 00 Saveable (SVBL).  Only when Select is *not* 011b
    # "may [Dword 0] contain feature-dependent information".  The completion
    # decoder switched on the Feature Identifier alone and never on Select, so
    # a capability sweep -- which is the whole point of Select 011b -- came
    # out in each Feature's own value layout.
    #
    # Both pairs carry the same completion Dword 0, 5A493827h, so the Select
    # field in the request is the only difference between them:
    #
    #   F39/F40  SEL=011b: SVBL, NSSPEC and CHANG all set, Reserved 31:03 =
    #                      0B492704h.  The Reserved run is non-zero so a
    #                      too-wide or too-narrow mask shows a wrong value
    #                      rather than a zero any mask renders alike.
    #   F41/F42  SEL=000b: the control.  The same dword must still decode in
    #                      the Arbitration layout -- AB=7, Reserved=04h,
    #                      LPW=38h, MPW=49h, HPW=5Ah -- so "decode Figure 199"
    #                      cannot silently become "stop decoding the Feature".
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x000d,
                                      cns=F_ARBITRATION | (0x3 << 8)), tag=19),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x5A493827,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=19),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x000d,
                                      cns=F_ARBITRATION), tag=20),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x5A493827,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=20),
    # F43/F44 Get Features Temperature Threshold with a selector in CDW11 and a
    # completion whose upper half is non-zero.  Base 2.3 5.2.26.1.3 defines only
    # bits 15:00 of that dword, so 0012h in 31:16 is undefined content rather
    # than a violation: the request asks for Temperature Sensor 2's under
    # temperature threshold (CDW11 THSEL=01b, TMPSEL=2h) and the completion
    # returns it.  The frame exists so the "not defined" item has something to
    # render, and so a fix that dropped the upper half entirely is visible.
    #
    # dlen=0 unlike F7 and the other scalar-FID Gets above: this Feature
    # transfers no NVMe Request or Response Data, so Figure 139 wants Data
    # Length cleared, and the request-side census in this class records the
    # older frames' 4096 as deliberately retained non-conformance.  A new
    # frame should not add to that list -- it is here for the completion
    # dword, and a clean request keeps it saying only that.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0016,
                                      cns=F_TEMP_THRESHOLD, dlen=0,
                                      cdw11=(0x1 << 20) | (0x2 << 16)), tag=21),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x0012014B,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=21),
]

BASE_TS_ADMIN_FEATURES_US = 1709376000 * 1_000_000

def build_admin_features_pcapng(output_path):
    write_pcapng(output_path, packets_admin_features, BASE_TS_ADMIN_FEATURES_US)


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F43-F170 — multi-window Get Log Page
# ---------------------------------------------------------------------------
#
# NVMe-MI-25 mandates multi-window retrieval for log pages that do not fit
# one MCTP message, sliced via the Admin request's Data Offset (DOFST).
# packet-nvme-mi-admin.c hands that offset to nvme_dissect_admin_data_resp()
# as `off`, and each per-LID decoder in packet-nvme.c indexes its fields by
# (struct_offset - off) rather than assuming byte 0 of the response is byte 0
# of the structure.  These fixtures exercise that nonzero-offset path, which
# mutation fuzzing of single-window captures cannot reach.
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
# (512-400=112).  For off=400 (>160) the field starts at tvb offset 0; a poff
# of (off-160)=240 would exceed this len, which the outer guard (len >=
# 512-off) alone does not exclude.
_egroup_rsvd2_window = bytes(range(112))

# F19/F20: Pred Lat NVM Set (LID 0Ah) DTWIN Reads Typical, struct offset 32:39
_pred_lat_dtwin_rt_data = bytes(range(0x70, 0x78))

# F21/F22: Reservation Notification (LID 80h) LPT, struct offset 8:8 (1 byte)
_reserv_notif_lpt_data = bytes([0x07])

# F23/F24: Sanitize Status (LID 81h), off=0, dlen=64 -- ordinary (non-windowed)
# response with plenty of data, so the trailing "rsvd" field (struct offset
# 48 onward) must render.  48 bytes of defined fields (0:48) + 16 distinctive
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
# F33..F48: per-LID decoder offsets and short-transfer guards.
# ---------------------------------------------------------------------------

# F33/F34: Commands Supported and Effects (LID 05h), off=0, full 2048-byte page.
# NVMe Base 2.3: ACS0..255 occupy bytes [0:1024), IOCS0..255 occupy bytes
# [1024:2048), CONTIGUOUS (table rows "1027:1024 IOCS0", "1031:1028 IOCS1").
# ACS0 (struct 0) and IOCS0 (struct 1024) carry distinct sentinel CSEDS
# uint32s so a passing assertion proves IOCS0 decodes at 1024.
_cmd_sup_and_eff_page = bytearray(2048)
struct.pack_into('<I', _cmd_sup_and_eff_page, 0,    0xA5A50001)  # ACS0  (struct 0)
struct.pack_into('<I', _cmd_sup_and_eff_page, 1024, 0x5A5A0002)  # IOCS0 (struct 1024)
_cmd_sup_and_eff_page = bytes(_cmd_sup_and_eff_page)

# F35/F36: SMART (LID 02h) windowed to combined_off=200 -- the exact start of
# the Temperature Sensor 1..8 array (struct 200:216).  For off>=200 the array's
# tvb position is 0, not the struct-absolute 200, and each per-sensor read is
# bounded by pos-off.  Temperature Sensor 1 (struct 200:202) carries a known
# value.
_smart_temps_window = bytearray(16)
struct.pack_into('<H', _smart_temps_window, 0, 300)  # Temperature Sensor 1 (K)
_smart_temps_window = bytes(_smart_temps_window)

# F37/F38: Telemetry Host-Initiated (LID 07h), off=0, DLEN=100 (< the 512-byte
# data-block granularity).  poff = 512 - (off & 0x1ff) = 512 exceeds the
# transfer, so the header fields render and the block loop must not run.
_telemetry_short = bytes(100)

# F39/F40: Predictable Latency Event Aggregate (LID 0Bh), off=0, DLEN=4 (< the
# 8-byte poff): "len -= poff" must not run, even at off=0.
_pred_lat_aggreg_short = bytes(4)

# F41/F42: ANA (LID 0Ch), off=0, DLEN=8 (< the 16-byte header poff).  The
# 8-byte Change Count header renders; "len -= poff" must not underflow.
_ana_short = bytes(8)

# F43/F44: Device Self-test (LID 06h), off=0, DLEN=2 (< the 4-byte header):
# "len -= (4-off)" must not underflow `len`.
_selftest_short = bytes(2)

# F45/F46: Device Self-test (LID 06h) windowed to combined_off=32 -- the exact
# start of Self-test Result index 1 (results begin at struct 4, each is 28
# bytes, so result[1] is at struct 4+28=32).  The loop offset must be tvb-
# relative ((result struct offset) - off), not struct-absolute.  POH (result
# offset +4 => struct 36:44) carries a known value.
_selftest_result1 = bytearray(40)
struct.pack_into('<Q', _selftest_result1, 4, 0xDEADBEEF)  # result[1] POH (struct 36)
_selftest_result1 = bytes(_selftest_result1)

# F47/F48: Firmware Slot (LID 03h) windowed to combined_off=32 (0 < off < 64).
# The trailing reserved field begins at struct offset 64; its tvb position is
# (64 - off) = 32, not the struct-absolute 64.  A sentinel at struct 64 (tvb
# offset 32) proves the field reads from the correct position.
_fw_slot_rsvd_window = bytearray(96)
_fw_slot_rsvd_window[32:40] = b'FWRSVD01'  # struct offset 64:72
_fw_slot_rsvd_window = bytes(_fw_slot_rsvd_window)

# ---------------------------------------------------------------------------
# F49..F54: length clamps for the Sanitize Status / Endurance Group /
# Predictable Latency NVM Set trailing "reserved" fields.
#
# Each of these decoders' trailing field is anchored at a tvb-relative
# position `poff` and its remaining-room cap is (512-off)-poff, so the field
# stops at the log page's real 512-byte end.  These fixtures pick DLEN so the
# data runs past that end, and place a distinct sentinel at the cap's last 4
# bytes (proving the field renders that far) plus a second sentinel just past
# it (present only if the clamp is missing or off bytes too large).
#
# F49/F50 Sanitize Status (LID 81h), DOFST=8, DLEN=508: poff=32-8=24,
# cap=(512-8)-24=480 (512-24=488 would be off bytes too large);
# len_after_poff=508-24=484 sits strictly between them.
_sanitize_dim_fixed = bytes(24)               # struct 8:32 (eto..etcend), zero
_sanitize_dim_filler = bytes(476)             # struct 32:508
_sanitize_dim_sentinel_a = struct.pack('>I', 0xCAFEBABE)  # struct 508:512 (true end)
_sanitize_dim_sentinel_b = struct.pack('>I', 0xDEADBEEF)  # struct 512:516 (past true end)
_sanitize_dim_data = (_sanitize_dim_fixed + _sanitize_dim_filler
                      + _sanitize_dim_sentinel_a + _sanitize_dim_sentinel_b)
assert len(_sanitize_dim_data) == 508

# F51/F52 Endurance Group (LID 09h), DOFST=200, DLEN=400: off=200 (>160) so
# poff=0; cap=512-200=312.
_egroup_dim_filler = bytes(308)               # struct 200:508
_egroup_dim_sentinel_a = struct.pack('>I', 0xCAFEBABE)    # struct 508:512 (true end)
_egroup_dim_sentinel_b = struct.pack('>I', 0xDEADBEEF)    # struct 512:516 (past true end)
_egroup_dim_trailing_filler = bytes(84)       # pads DLEN out to 400
_egroup_dim_data = (_egroup_dim_filler + _egroup_dim_sentinel_a
                    + _egroup_dim_sentinel_b + _egroup_dim_trailing_filler)
assert len(_egroup_dim_data) == 400

# F53/F54 Predictable Latency NVM Set (LID 0Ah), DOFST=200, DLEN=400: off=200
# (>152) so poff=0; cap=512-200=312 -- same shape as the Endurance Group case
# above.
_pred_lat_dim_data = _egroup_dim_data
assert len(_pred_lat_dim_data) == 400

# F55/F56: LPO 64-bit overflow saturation, Command/Feature Lockdown (LID 14h).
# LPO=0x1_0000_0000 (2**32) with DOFST=0: the dispatcher saturates a 64-bit
# combined offset that does not fit 32 bits to UINT32_MAX rather than
# truncating it to 0, so the decoder's "if (off) return" guard (the
# variable-length CFIL list decodes only from offset 0) rejects this LPO.
#
# lngth (byte 3) is deliberately nonzero (0x02) with 2 real CFIL entries
# following, so the CFIL field would render if the guard failed to fire.
_cmd_feat_lockdown_overflow_data = bytes([0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB])

# ---------------------------------------------------------------------------
# F57..F68: more combined LPO+transport offset cases.
# ---------------------------------------------------------------------------

# F57/F58: LPO 64-bit ADDITION overflow, Command/Feature Lockdown (LID 14h).
# Unlike F55/F56 (LPO=2**32, which only overflows the 32-bit narrowing),
# the 64-bit addition itself wraps: LPO=0xFFFFFFFFFFFFFFFC + DOFST=4 == 2**64
# == 0 (mod 2**64).  The dispatcher checks for overflow before adding and
# saturates to UINT64_MAX (still > UINT32_MAX after narrowing), so the
# "if (off) return" guard rejects this LPO.
_cmd_feat_lockdown_addition_overflow_data = bytes([0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB])

# F59/F60: Telemetry Host-Initiated (LID 07h) windowed to combined_off=512 --
# exactly the first data-block boundary (LPO=0, DOFST=512).  A window that
# starts AT a boundary has poff=0, not 512 as "512 - (off & 0x1ff)" gives.
# 512 bytes of a distinct byte value prove the block renders when the window
# starts exactly on a block boundary.
_telemetry_block_at_boundary = bytes([0x5A]) * 512

# F61/F62: Predictable Latency Event Aggregate (LID 0Bh), LPO=0, DOFST=5 --
# combined_off=5, inside the 8-byte "NE" header field but not at its start.
# poff comes from the combined offset threaded to this decoder (poff=3), not
# the raw per-command LPO (which would give 8).  A sentinel at the correct
# tvb position (3) and a different one at position 8 tell the two apart.
_pred_lat_aggreg_off_data = bytes([0, 0, 0, 0xEF, 0xBE, 0, 0, 0, 0xAD, 0xDE])

# F63/F64: Supported Log Pages (LID 00h), combined_off=2 -- not a multiple of
# the table's 4-byte record size.  The window must be rejected (render
# nothing), not truncated by "off / 4" to an index that splices two adjacent
# records into one mislabeled entry.
_supported_misaligned_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

# F65/F66: Changed Namespace List (LID 04h), combined_off=2 -- same
# misalignment shape as F63/F64 but a different code path (a byte-stride loop
# from tvb position 0, which would splice adjacent NSIDs together).
_changed_nslist_misaligned_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

# F67/F68: Firmware Slot (LID 03h), DOFST=0, DLEN=1 -- exactly the AFI
# field's 1 byte (all of AFI, none of the following Reserved), which must
# still render.
_fw_slot_afi_exact_data = bytes([0x02])

# ---------------------------------------------------------------------------
# F69..F74: upstream packet-nvme.c log page decoders.
# ---------------------------------------------------------------------------

# F69/F70: ANA (LID 0Ch) windowed to LPO=16, DLEN=4 -- a window that starts
# exactly at ANA Group Descriptor 0 and carries only its 4-byte ANA Group ID.
# Number of NSID Values (NVMe Base 2.3 Figure 228, bytes 07:04) is absent, so
# the frame must decode the Group ID it carries without a BoundsError.  A
# distinctive AGID proves the field decodes rather than merely not throwing.
_ana_grp_id_only = struct.pack('<I', 0x0000002A)

# F71/F72: Commands Supported and Effects (LID 05h) windowed to LPO=1020,
# DLEN=16 -- straddling the ACS/IOCS boundary (NVMe Base 2.3 Figure 213:
# ACS0..255 at bytes [0:1024), IOCS0..255 at [1024:2048)).  That yields
# exactly one ACS record (ACS255, struct 1020) followed by three IOCS records
# (IOCS0..2, struct 1024/1028/1032): each record must carry its own index
# label (ACS255, IOCS0..2) and be a sibling, not a child, of the one before.
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
# Two descriptors is the minimum that makes the descriptor loop iterate
# twice, so the walk must consume each one and stop at the element's end.
# Both descriptors carry distinct non-zero RSLBA/RNLB values.
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
# in this message at all, and NVMe-MI builds a freshly zeroed command context
# per transaction, so the descriptors present must render without a group
# count.  NVMe-MI 2.2 Figure 139 caps DLEN at 4,096, so an ANA log page
# larger than that can only be fetched with successive nonzero DOFST -- this is
# the ordinary Management Controller path, not a corner case.
#
# Two descriptors with distinct ANA Group IDs and NSIDs, so the test can tell
# "both rendered" from "the walk stopped after one".
_ana_dofst_descs = (ana_data(agid=0x11, grp_chgc=0x21, nsid=0x00000101)[16:]
                    + ana_data(agid=0x22, grp_chgc=0x22, nsid=0x00000202)[16:])
assert len(_ana_dofst_descs) == 72

# F79/F80 and F81/F82: LBA Status Information (LID 0Eh) windowed.
#
# The dispatcher saturates a 64-bit Log Page Offset that will not fit 32 bits
# to UINT32_MAX, and dissect_nvme_get_logpage_lba_status_resp() is handed that
# saturated value.  UINT32_MAX is not a multiple of 16, and a Namespace
# Element is 16 * (NLRD + 1) bytes (NVM CS 1.2 Figure 110), so the window
# cannot be placed: it must raise the misaligned expert and render nothing,
# not realign and invent a Namespace Element from the window's bytes.
#
# F81/F82 is the control: a real 16-byte-aligned
# window (DOFST=16, the start of the first Namespace Element) must still
# decode, so "reject unaligned" cannot degenerate into "reject windowed".
_lba_status_element = (
    struct.pack('<I', 0x0000005B)            # NEID   (03:00)
    + struct.pack('<I', 1)                   # NLRD   (07:04): one descriptor
    + bytes([0x10])                          # RATYPE (08)
    + bytes(7)                               # Reserved (15:09)
    + struct.pack('<Q', 0x00000000DEADBEEF)  # RSLBA
    + struct.pack('<I', 0x00001234)          # RNLB
    + bytes(4))                              # Reserved
assert len(_lba_status_element) == 32

# F77/F78: the same 72 bytes at the same logical offset, but expressed with
# LPO=16 and DOFST=0 instead of DOFST=16 and LPO=0.  The controller applies
# LPO before NVMe-MI slices the response, so both requests ask for exactly
# "the log page from byte 16 on" and both responses carry byte-identical
# payloads -- they must decode identically (both descriptors, not one).

# F83/F84 and F85/F86: Telemetry Host-Initiated (LID 07h) at offsets only
# 64-bit arithmetic can carry.
#
# NVMe Base 2.3 Figure 218 makes Telemetry Host-Initiated Data Area 4 Last
# Block a 32-bit block number, and the Telemetry Host-Initiated Log Page text
# above it ("All Telemetry Data Blocks are 512 bytes in size", block n at
# (n*512)+511:(n*512)) makes the page run to (2**32-1)*512 bytes.  An offset
# past 4 GiB into this page is therefore in spec, not an attack, and two
# separate 32-bit failures live on the way there -- hence two fixtures.
#
# F83/F84 -- LPO=2**32 (LPOU=1, LPOL=0), DOFST=0.  Narrowed to 32 bits, 2**32
# would read as the start of the log page and render the 512-byte header of
# Figure 218 out of data block bytes; the dispatcher saturates instead, so no
# header field may render here.  LPOL is a multiple of 512, as the Telemetry
# Host-Initiated text requires.
#
# F85/F86 -- LPO=0xFFFFFE00 (the start of block 8388607) plus DOFST=256.  The
# combined offset is 0xFFFFFF00, which fits 32 bits exactly: no saturation is
# involved, so this isolates the second wrap, in "next_block = (off + poff) /
# 512", where poff is the 256-byte skip to the next block boundary.  That sum
# is exactly 2**32, so the two blocks here must come out as 8388608 and
# 8388609, not 0 and 1.
#
# Byte 0 is a plausible LID (07h) so a misread renders a Log Identifier that
# looks real; the rest of each window is a per-block filler so a misplaced
# block boundary is visible in the rendered bytes.
_telemetry_lpou_window = (bytes([0x07]) + bytes([0xA5]) * 511
                          + bytes([0x5A]) * 512)
assert len(_telemetry_lpou_window) == 1024

_telemetry_block_boundary_window = (bytes([0x00]) * 256      # tail of block 8388607
                                    + bytes([0xB1]) * 512    # block 8388608
                                    + bytes([0xB2]) * 512)   # block 8388609
assert len(_telemetry_block_boundary_window) == 1280

# ---------------------------------------------------------------------------
# F87..F94: walk bounds that the log page's own header declares.
# ---------------------------------------------------------------------------

# F87/F88: Commands Supported and Effects (LID 05h) at LPO=2040, DLEN=16 -- the
# last two I/O entries of the page followed by two dwords of the Reserved
# region.  NVMe Base 2.3 Figure 213 puts IOCS0..IOCS255 at bytes 2047:1024 and
# makes bytes 4095:2048 Reserved, so the walk must cap the entry *index*, not
# just the count: IOCS256 and IOCS257 are names Figure 213 does not define.
_cmd_sup_and_eff_iocs_tail = (struct.pack('<I', 0x1111FE00)    # IOCS254 (struct 2040)
                              + struct.pack('<I', 0x2222FF00)  # IOCS255 (struct 2044)
                              + struct.pack('<I', 0x33330000)  # Reserved (struct 2048)
                              + struct.pack('<I', 0x44440000))  # Reserved (struct 2052)
assert len(_cmd_sup_and_eff_iocs_tail) == 16

# F89/F90: the same page at LPO=2048, DLEN=8 -- a window that starts in the
# Reserved region, so its first index is already IOCS256 and nothing it holds
# is an entry at all.
_cmd_sup_and_eff_reserved = (struct.pack('<I', 0xAAAA0001)
                             + struct.pack('<I', 0xBBBB0002))
assert len(_cmd_sup_and_eff_reserved) == 8


def _lba_status_ns_element(neid, nlrd, rslba, rnlb, ratype=0x10):
    """One LBA Status Log Namespace Element (NVM CS 1.2 Figure 110): a 16-byte
    header (NEID 03:00, NLRD 07:04, RATYPE 08, Reserved 15:09) followed by NLRD
    16-byte LBA Range Descriptors (Figure 111)."""
    out = (struct.pack('<I', neid) + struct.pack('<I', nlrd)
           + bytes([ratype]) + bytes(7))
    for i in range(nlrd):
        out += struct.pack('<Q', rslba + i) + struct.pack('<I', rnlb + i) + bytes(4)
    return out


# F95/F96: the Commands Supported and Effects entry's own bit layout (NVMe
# Base 2.3 Figure 214), LPO=0, DLEN=8 -- two ACS entries, no windowing,
# covering CSER (bits 15:14) and CSP (bits 31:20).
#
#   ACS0 = 03FA4001h  CSUPP=1, CSER=01b, CSE=010b, USS=1, and all six CSP
#                     scope bits (25:20) set -- CSP reads 03Fh.
#   ACS1 = FC00AAA3h  CSUPP=1, LBCC=1, Reserved(13:5)=155h (a bit pattern that
#                     reads differently under a 15:5 mask), CSER=10b,
#                     and CSP = FC0h: only CSP's own reserved bits 11:6 set.
#                     Figure 267's FSP (LID 12h) defines CDQSCP at its bit 6;
#                     Figure 214 does not, so bit 26 must land in Reserved.
_cmd_sup_and_eff_cser_csp = (struct.pack('<I', 0x03FA4001)   # ACS0 (struct 0)
                             + struct.pack('<I', 0xFC00AAA3))  # ACS1 (struct 4)
assert len(_cmd_sup_and_eff_cser_csp) == 8

# F97/F98: Commands Supported and Effects (LID 05h), combined_off=2 -- the
# same 4-byte misalignment shape as F63/F64 and F65/F66: the window's two
# half-records must not be spliced into one entry labelled ACS0.
_cmd_sup_and_eff_misaligned = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])


def _lba_status_header(lslplen, nlslne, estulb=0x1234, lsgc=7):
    """LBA Status Information log page header (NVM CS 1.2 Figure 109): LSLPLEN
    03:00, NLSLNE 07:04, ESTULB 11:08, Reserved 13:12, LSGC 15:14."""
    return (struct.pack('<I', lslplen) + struct.pack('<I', nlslne)
            + struct.pack('<I', estulb) + struct.pack('<H', 0)
            + struct.pack('<H', lsgc))


# F91..F94: the LBA Status Information walk (LID 0Eh) must stop at the page's
# end, not the transfer's.  Figure 109 declares two bounds and the two pairs
# below separate them: each carries the same 64 bytes of element data,
# and only the header differs, so whichever field is being ignored is the one
# that lets the second element render.
_lba_status_two_elements = (
    _lba_status_ns_element(0x0000005B, 1, 0x00000000DEADBEEF, 0x00001234)
    + _lba_status_ns_element(0x0000005C, 1, 0x00000000FEEDFACE, 0x00005678))
assert len(_lba_status_two_elements) == 64

# F91/F92: NLSLNE is what stops the walk.  LSLPLEN = 80 covers the whole
# transfer, so the page's declared length cannot be what ends it after one.
_lba_status_nlslne_bound = _lba_status_header(80, 1) + _lba_status_two_elements
assert len(_lba_status_nlslne_bound) == 80

# F93/F94: LSLPLEN is what stops the walk.  NLSLNE = 2 would admit both
# elements, so the count cannot be what ends it after one; the page's declared
# length runs out at byte 48, in the middle of the transfer.
_lba_status_lslplen_bound = _lba_status_header(48, 2) + _lba_status_two_elements
assert len(_lba_status_lslplen_bound) == 80

# F99/F100: Error Information (LID 01h) read at DOFST=128, DLEN=136.  NVMe-MI
# 2.2 Figure 139 caps a transfer at 4,096 bytes, so a full 256-entry Error
# Information page can only ever be fetched in windows, and the ordinals the
# tree shows have to come from the window's offset rather than from a position
# within the transfer: these are entries 2, 3 and the first 8 bytes of 4, not
# 0, 1 and 2.  8 bytes is exactly the Error Count (07:00), so the remnant
# renders that field and no other.
_errinf_window_data = error_info_list_data(
    ((0xBB02, 0x0505, 0x0055, 0x31, 0x5000000000000005),
     (0xBB03, 0x0606, 0x0066, 0x32, 0x6000000000000006),
     (0xBB04, 0x0707, 0x0077, 0x33, 0x7000000000000007)),
    tail_len=8)
assert len(_errinf_window_data) == 2 * 64 + 8

# F101..F108: the Event Aggregate pages (Predictable Latency, LID 0Bh, NVMe
# Base 2.3 Figure 225; Endurance Group, LID 0Fh, Figure 257) windowed at an odd
# offset.  Both are one 8-byte NUMENT header followed by 2-byte identifiers
# from byte 8, so once a window starts past the header its first byte has to be
# an entry boundary -- an odd combined offset names no entry at all, so the
# walk must not read 2211h, 4433h and 6655h out of halves of entries.
#
# One decoder serves both LIDs, but only the hf pair differs between them, so
# each is exercised separately.
_event_aggreg_misaligned = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

# F105..F108 are the control: an even offset past the
# header is a legitimate window onto entries 1, 2 and 3, so "reject unaligned"
# must not degenerate into "reject windowed".  A different byte pattern than
# the misaligned pair so a test cannot pass by matching the wrong frame.
_event_aggreg_aligned = bytes([0xAD, 0xDE, 0xEF, 0xBE, 0x0D, 0xF0])

# F109..F112: the scope field of the two Figure 214 siblings, LPO=0, DLEN=12 --
# three entries each, no windowing, covering the scope bits 31:20 and CDQSCP.
#
# The two figures are NOT the same table, which is the whole point of covering
# both.  Figure 267's FSP (LID 12h) defines Controller Data Queue (CDQSCP) at
# its bit 6 and reserves only 11:7; Figure 269's CSP (LID 13h) reserves 11:6
# outright, exactly as Figure 214 does for LID 05h.  Dword bit 26 is therefore
# a named bit on 12h and Reserved on 13h, and each entry below isolates one
# part of that so a mask copied from the wrong figure -- or a CDQSCP given a
# neighbouring bit -- cannot pass:
#
#   FIS0  = 04000001h  FSUPP=1, FSP bit 6 alone: CDQSCP and nothing else.
#   FIS1  = 03F00001h  FSUPP=1, FSP bits 5:0: the six bits 12h shares with
#                      Figures 214 and 269, with CDQSCP clear.
#   FIS2  = F8000001h  FSUPP=1, FSP bits 11:7: 12h's own reserved range.
#   MICS0 = 04000001h  CSUPP=1, the same dword bit 26 -- which 13h has to
#                      report inside CSP's Reserved item, not as a named bit.
#   MICS1 = 03F00001h  CSUPP=1, CSP bits 5:0: all six named bits.
#   MICS2 = FC000001h  CSUPP=1, CSP bits 11:6: 13h's whole reserved range.
_feat_sup_and_eff_fsp = (struct.pack('<I', 0x04000001)     # FIS0 (struct 0)
                         + struct.pack('<I', 0x03F00001)   # FIS1 (struct 4)
                         + struct.pack('<I', 0xF8000001))  # FIS2 (struct 8)
assert len(_feat_sup_and_eff_fsp) == 12

_mi_cmd_sup_and_eff_csp = (struct.pack('<I', 0x04000001)     # MICS0 (struct 0)
                           + struct.pack('<I', 0x03F00001)   # MICS1 (struct 4)
                           + struct.pack('<I', 0xFC000001))  # MICS2 (struct 8)
assert len(_mi_cmd_sup_and_eff_csp) == 12

# F113..F120: the Event Aggregate pages read in more than one window (NVMe
# Base 2.3 5.2.12.1.12 / Figure 225 and 5.2.12.1.15 / Figure 257).  NUMENT at
# bytes 07:00 is the only thing that bounds the identifier list, and a read
# that runs past the list is answered with zeros ("zeros shall be returned for
# data transferred beyond the end of that log page").  A window that starts
# past the header carries no NUMENT, so the walk has only the identifiers
# themselves to go on -- and 0h is not a valid NVM Set or Endurance Group
# Identifier (3.2.2, 3.2.3), so the first 0000h is where the list can end.
# A conformant page read in two windows must not draw the 0Bh "shall not
# contain an entry cleared to 0h" warning on its own fill.
#
# One conformant Predictable Latency Event Aggregate page: NUMENT=1, entry 1
# = NVM Set 5, then the fill that answers a 16-byte read (NUMD 3).
_event_aggreg_one_entry_page = struct.pack('<Q', 1) + struct.pack('<H', 5) + bytes(6)
assert len(_event_aggreg_one_entry_page) == 16
# The same page's bytes [8:16): what its DOFST=8, DLEN=8 window carries.
_event_aggreg_second_window = _event_aggreg_one_entry_page[8:]
# NUMENT=2 with the second entry cleared to 0h -- a real 5.2.12.1.12
# violation inside the list -- then 4 bytes of fill.
_event_aggreg_zero_inside = struct.pack('<Q', 2) + struct.pack('<HH', 5, 0) + bytes(4)
assert len(_event_aggreg_zero_inside) == 16
# The Endurance Group sibling read the same second way: bytes [8:16) of a
# NUMENT=1 page whose entry is Endurance Group 7.  No expert exists for 0Fh;
# what this pins is that its fill stops being rendered as entries too.
_egroup_aggreg_second_window = struct.pack('<H', 7) + bytes(6)

# F121-F126: Command and Feature Lockdown (LID 14h) windows.  NVMe Base 2.3
# Figure 271 is a 512-byte page: CFILA at byte 0, LNGTH at 3, an LNGTH-byte
# list of coded values from byte 4, Reserved to byte 511.  Windows not
# starting at byte 0 must decode, and the Reserved item is sized to the page,
# not the transfer.
#
# One conformant page: Scope Selected 0h (Admin Command Set opcodes),
# Contents Selected 00b (able to be prohibited), LNGTH 8, then eight
# opcodes in the ascending order Figure 271 requires.  It starts with 00h
# (Delete SQ) on purpose: 00h is a legal coded value here, and OCP 2.7
# NVMe-AD-15 puts every supported Admin opcode in this list, so a real
# page's list begins with it -- a window without LNGTH cannot take a 00h as
# the end of the list.
_lockdown_list = bytes([0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x08, 0x09])
_lockdown_page = (bytes([0x00, 0x00, 0x00, len(_lockdown_list)]) + _lockdown_list
                  + bytes(512 - 4 - len(_lockdown_list)))
assert len(_lockdown_page) == 512
# The same page read 8 bytes long: "the controller returns the complete log
# page with undefined results for dwords beyond the end of the log page"
# (Figure 201, NUMDL) -- a pattern the Reserved item has to stop before.
_lockdown_page_plus8 = _lockdown_page + bytes.fromhex('deadbeefdeadbeef')


def _lockdown_pair(doff, dlen, data, tag):
    """A LID 14h request for the window [doff, doff+dlen), NUMD sized to it,
    and the response carrying `data`."""
    numd = (doff + dlen) // 4 - 1
    return [
        make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                          ctrl_id=0x0001, flags=0x00,
                                          cns=0x14 | (numd << 16),
                                          doff=doff, dlen=dlen), tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(data), tag=tag),
    ]


packets_admin_logpage_windowed = [
    # F1/F2 SMART / Health Information (LID 02h), window 1: DOFST=0, DLEN=32
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x02,
                                      doff=0, dlen=32), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data()[0:32]), tag=0),
    # F3/F4 SMART / Health Information (LID 02h), window 2: DOFST=32, DLEN=32
    #       (Data Units Read at struct offset 32, Data Units Written at 48)
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
    # data for it: "len -= poff" must not underflow; nothing renders.
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
    # outer guard's exact minimum) -- see _egroup_rsvd2_window above.
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
    # this decoder as a nonzero combined offset -- LNGTH is not in the
    # window, so the list is not walked and the response says so.
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
    # "rsvd" length clamp (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x81,
                                      doff=8, dlen=508), tag=24),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sanitize_dim_data), tag=24),
    # F51/F52 Endurance Group (LID 09h), DOFST=200, DLEN=400 -> trailing
    # "rsvd2" length clamp (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x09,
                                      doff=200, dlen=400), tag=25),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_egroup_dim_data), tag=25),
    # F53/F54 Predictable Latency NVM Set (LID 0Ah), DOFST=200, DLEN=400 ->
    # trailing "rsvd3" length clamp (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0A,
                                      doff=200, dlen=400), tag=26),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_pred_lat_dim_data), tag=26),
    # F55/F56 Command and Feature Lockdown (LID 14h), LPO=2**32, DOFST=0:
    # LPO 64-bit overflow saturation (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x14,
                                      doff=0, dlen=6, lpo=2**32), tag=27),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_feat_lockdown_overflow_data), tag=27),
    # F57/F58 Command and Feature Lockdown (LID 14h), LPO=0xFFFFFFFFFFFFFFFC,
    # DOFST=4: LPO 64-bit ADDITION overflow (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x14,
                                      doff=4, dlen=6, lpo=0xFFFFFFFFFFFFFFFC), tag=28),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_feat_lockdown_addition_overflow_data), tag=28),
    # F59/F60 Telemetry Host-Initiated (LID 07h), DOFST=512, DLEN=512:
    # window on an exact 512-byte boundary (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x07,
                                      doff=512, dlen=512), tag=29),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_telemetry_block_at_boundary), tag=29),
    # F61/F62 Predictable Latency Event Aggregate (LID 0Bh), DOFST=5:
    # poff from the transport offset (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0B,
                                      doff=5, dlen=10), tag=30),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_pred_lat_aggreg_off_data), tag=30),
    # F63/F64 Supported Log Pages (LID 00h), DOFST=2: 4-byte misalignment
    # (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x00,
                                      doff=2, dlen=6), tag=31),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_supported_misaligned_data), tag=31),
    # F65/F66 Changed Namespace List (LID 04h), DOFST=2: 4-byte misalignment
    # (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x04,
                                      doff=2, dlen=6), tag=32),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_changed_nslist_misaligned_data), tag=32),
    # F67/F68 Firmware Slot (LID 03h), DOFST=0, DLEN=1: exactly AFI (see
    # block comment above).
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
    # F79/F80 LBA Status Information (LID 0Eh), LPO=2**32, DOFST=0: the
    # combined offset saturates to UINT32_MAX, which is not 16-byte aligned
    # (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0E,
                                      doff=0, dlen=len(_lba_status_element),
                                      lpo=2**32), tag=39),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lba_status_element), tag=39),
    # F81/F82 LBA Status Information (LID 0Eh), DOFST=16, LPO=0: a legitimate
    # 16-byte-aligned window at the first Namespace Element (see block comment
    # above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0E,
                                      doff=16, dlen=len(_lba_status_element)),
                tag=40),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lba_status_element), tag=40),
    # F83/F84 Telemetry Host-Initiated (LID 07h), LPO=2**32 (LPOU nonzero),
    # DOFST=0: the 64-bit Log Page Offset must not narrow to 0 (see block
    # comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x07,
                                      doff=0,
                                      dlen=len(_telemetry_lpou_window),
                                      lpo=2**32), tag=41),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_telemetry_lpou_window), tag=41),
    # F85/F86 Telemetry Host-Initiated (LID 07h), LPO=0xFFFFFE00 + DOFST=256:
    # data block numbering across the 32-bit boundary (see block comment
    # above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x07,
                                      doff=256,
                                      dlen=len(_telemetry_block_boundary_window),
                                      lpo=0xFFFFFE00), tag=42),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_telemetry_block_boundary_window), tag=42),
    # F87/F88 Commands Supported and Effects (LID 05h), LPO=2040, DLEN=16:
    # the IOCS index cap (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x05,
                                      doff=0, dlen=16, lpo=2040), tag=43),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_sup_and_eff_iocs_tail), tag=43),
    # F89/F90 Commands Supported and Effects (LID 05h), LPO=2048, DLEN=8: a
    # window wholly inside the Reserved region (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x05,
                                      doff=0, dlen=8, lpo=2048), tag=44),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_sup_and_eff_reserved), tag=44),
    # F91/F92 LBA Status Information (LID 0Eh), DOFST=0, DLEN=80: NLSLNE
    # bounds the Namespace Element walk (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0E,
                                      doff=0, dlen=80), tag=45),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lba_status_nlslne_bound), tag=45),
    # F93/F94 LBA Status Information (LID 0Eh), DOFST=0, DLEN=80: LSLPLEN
    # bounds it instead (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0E,
                                      doff=0, dlen=80), tag=46),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_lba_status_lslplen_bound), tag=46),
    # F95/F96 Commands Supported and Effects (LID 05h), LPO=0, DLEN=8: the
    # CSER and CSP fields of Figure 214 (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x05,
                                      doff=0, dlen=8), tag=47),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_sup_and_eff_cser_csp), tag=47),
    # F97/F98 Commands Supported and Effects (LID 05h), DOFST=2: 4-byte
    # misalignment (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x05,
                                      doff=2, dlen=6), tag=48),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_cmd_sup_and_eff_misaligned), tag=48),
    # F99/F100 Error Information (LID 01h), DOFST=128: entries 2 and 3 of the
    # page plus the Error Count of entry 4 (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x01,
                                      doff=128, dlen=136), tag=49),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_errinf_window_data), tag=49),
    # F101/F102 Predictable Latency Event Aggregate (LID 0Bh), DOFST=9: an odd
    # offset past the NUMENT header names no entry boundary (see block comment
    # above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0B,
                                      doff=9, dlen=6), tag=50),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_misaligned), tag=50),
    # F103/F104 Endurance Group Event Aggregate (LID 0Fh), DOFST=9: the same
    # window on the sibling page (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0F,
                                      doff=9, dlen=6), tag=51),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_misaligned), tag=51),
    # F105/F106 Predictable Latency Event Aggregate (LID 0Bh), DOFST=10: the
    # aligned control (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0B,
                                      doff=10, dlen=6), tag=52),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_aligned), tag=52),
    # F107/F108 Endurance Group Event Aggregate (LID 0Fh), DOFST=10: the
    # aligned control on the sibling page (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x0F,
                                      doff=10, dlen=6), tag=53),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_aligned), tag=53),
    # F109/F110 Feature Identifiers Supported and Effects (LID 12h), LPO=0,
    # DLEN=8: the FSP scope bits of Figure 267, CDQSCP included (see block
    # comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x12,
                                      doff=0, dlen=12), tag=54),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_feat_sup_and_eff_fsp), tag=54),
    # F111/F112 NVMe-MI Commands Supported and Effects (LID 13h), LPO=0,
    # DLEN=8: the CSP scope bits of Figure 269, which has no CDQSCP (see block
    # comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=0, dlen=12), tag=55),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_mi_cmd_sup_and_eff_csp), tag=55),
    # F113/F114 Predictable Latency Event Aggregate (LID 0Bh), DOFST=0,
    # DLEN=16, NUMD=3: NUMENT in the window -- the control.  One entry, then
    # six bytes of fill the NUMENT-bounded walk does not touch.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x0B | (3 << 16), doff=0, dlen=16), tag=56),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_one_entry_page), tag=56),
    # F115/F116 the same page's second window, DOFST=8, DLEN=8: entry 5 then
    # six bytes of fill, and no NUMENT to say so (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x0B | (3 << 16), doff=8, dlen=8), tag=57),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_second_window), tag=57),
    # F117/F118 LID 0Bh, DOFST=0, DLEN=16, NUMD=3: NUMENT=2 with entry 2
    # cleared to 0h -- inside the list, so the 5.2.12.1.12 warning is right.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x0B | (3 << 16), doff=0, dlen=16), tag=58),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_event_aggreg_zero_inside), tag=58),
    # F119/F120 Endurance Group Event Aggregate (LID 0Fh), DOFST=8, DLEN=8,
    # NUMD=3: the sibling page's second window (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x0F | (3 << 16), doff=8, dlen=8), tag=59),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_egroup_aggreg_second_window), tag=59),
    # F121/F122 the whole page, DOFST 0, DLEN 512, NUMD 127: the control --
    # eight named opcodes and 500 bytes of Reserved ending at byte 511,
    # decoded the same before and after.
    *_lockdown_pair(0, 512, _lockdown_page, 60),
    # F123/F124 the page plus eight bytes, DOFST 0, DLEN 520, NUMD 129: the
    # Reserved item stops at byte 511; the undefined tail gets no item.
    *_lockdown_pair(0, 520, _lockdown_page_plus8, 61),
    # F125/F126 an interior window, DOFST 4, DLEN 8, NUMD 2: the first eight
    # list bytes with LNGTH (byte 3) and Scope Selected (byte 0) outside the
    # window -- the list end and the values' names are both unknowable, and
    # the decoder says so rather than guessing or staying silent.
    *_lockdown_pair(4, 8, _lockdown_page[4:12], 62),
    # F127/F128 Firmware Slot Information (LID 03h) at Log Page Offset 10 --
    # bits 1:0 set, which NVMe Base 2.3 Figure 203 forbids for a byte offset
    # ("The offset shall be dword aligned, indicated by bits 1:0 being cleared
    # to 00b").  A controller that does not abort "shall operate as if bits
    # 1:0 are cleared to 00b", i.e. as offset 8, so the 8-byte response is
    # FRS1 (page bytes 15:8) and decodes as such; the request is flagged.
    # DOFST 0, DLEN 8, NUMD 1 keep the NVMe-MI window conformant so the
    # alignment expert is the only one on the request.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x03 | (1 << 16),
                                      doff=0, dlen=8, lpo=10), tag=63),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b'MASKED08'), tag=63),
]

BASE_TS_ADMIN_LOGPAGE_WINDOWED_US = 1709377000 * 1_000_000

def build_admin_logpage_windowed_pcapng(output_path):
    write_pcapng(output_path, packets_admin_logpage_windowed, BASE_TS_ADMIN_LOGPAGE_WINDOWED_US)


# ---------------------------------------------------------------------------
# nvme-mi-admin-features.pcapng F45-F66 — Set/Get Features windowed-transfer fixes
# ---------------------------------------------------------------------------
#
# packets_admin_features above always transfers FID data with DOFST=0 (a
# single, full-size window).  These frames pass a nonzero transport offset
# (DOFST) to the APST, Timestamp, PLMC and HBS FID handlers of
# dissect_nvme_set_features_transfer().  Set/Get Features has no NVMe-level
# offset field analogous to Get Log Page's LPO, so DOFST is the only offset
# these decoders need.
#
#   F1/F2  APST (FID 0Ch), DOFST=8, DLEN=8 -> 2nd Non-Operational Power
#          State Transition entry (struct offset 8:15)
#   F3/F4  Timestamp (FID 0Eh), DOFST=0, DLEN=8: a basic single-field
#          transfer, so `off` and `len` reach the decoder
#   F5/F6  PLMC (FID 13h), DOFST=0, DLEN=40 (<56): the trailing "rsvd1"
#          field's length (tvb, 56, len-56) must not underflow `len`
#   F7/F8  HBS (FID 16h), DOFST=0, DLEN=1: the trailing "rsvd" field
#          (tvb, 1, len-1) must not underflow for a transfer of only the
#          1-byte ACRE field
#   F21/F22 Controller Metadata (FID 7Eh), DOFST=64: the Host Metadata
#          decoder's own later-window branch, which no other capture reaches

_apst_entry1_data = bytes(range(0x90, 0x98))  # 2nd APST entry, struct [8:16)
_tst_data = bytes(range(0xA0, 0xA8))          # Timestamp structure, 8 bytes
_plmc_short_data = bytes(range(0xB0, 0xD8))   # 40 bytes: EE(2)+rsvd0(30)+dtwinrt(8)
_hbs_short_data = bytes([0x01])               # just ACRE, no trailing rsvd

# F9/F10 PLMC (FID 13h), DOFST=60 (>56, entirely inside the trailing "rsvd1"
# region): poff falls back to 0, rendering the whole window as rsvd1.
_plmc_past_boundary_data = bytes.fromhex('1122334455667788')

# F11/F12 HBS (FID 16h), DOFST=8 (>6, entirely inside the trailing "rsvd"
# region): same fallback as PLMC above, for HBS's 6-byte-fixed-field
# boundary.
_hbs_past_boundary_data = bytes.fromhex('aabbcc')

# F13/F14 PLMC (FID 13h), DOFST=480 (>56, so poff=0 as in F9/F10) with an
# OVERSIZED DLEN=50.  The trailing field's rendered length is clamped to the
# structure's real 512-byte end: (512-480)-poff(0)=32 bytes.  A sentinel at
# the 32-byte boundary proves the field stops there, not at the full 50
# bytes requested.
_plmc_oversized_data = (bytes(28) + struct.pack('>I', 0xCAFEBABE)
                        + bytes([0xEE]) * 18)
assert len(_plmc_oversized_data) == 50

# F15/F16 HBS (FID 16h), DOFST=480 (>1, so poff=0), OVERSIZED DLEN=50 --
# same 32-byte cap as F13/F14 (HBS is also a 512-byte structure), different
# decoder.
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
# Reserved 63:48).  Each "LBA Range Structure N" container item must be
# anchored at its entry's own offset, not tvb offset 0; that is asserted on
# the item's PDML pos/size, and it takes two entries to see.  Each entry's
# Type/SLBA/NLB are distinct and non-zero so a wrong offset shows as a wrong
# number.
def _lbart_entry(type_, attr, slba, nlb, guid):
    return (bytes([type_, attr]) + bytes(14)
            + struct.pack('<Q', slba) + struct.pack('<Q', nlb)
            + guid + bytes(16))

_lbart_two_entries = (
    _lbart_entry(0x02, 0x03, 0x1000, 0x00FF, bytes(range(0xC0, 0xD0)))
    + _lbart_entry(0x03, 0x01, 0x2000, 0x01FF, bytes(range(0xE0, 0xF0))))
assert len(_lbart_two_entries) == 128

# F21/F22: Controller Metadata (FID 7Eh), DOFST=64 -- a later window of a
# Host Metadata structure.  The NMED count and the descriptor list's start
# are both at the front of the 4 KiB structure, so a chunk beginning
# mid-list cannot be realigned; dissect_nvme_host_metadata() must render it
# raw and say so with nvme.window_decode_skipped.  Every other Host Metadata
# frame in these captures arrives at offset 0, so this branch has no other
# coverage.  The bytes are a plausible mid-list fragment (UTF-8 Element
# Value text) rather than zeroes, so a misparse produces visible garbage.
_hmd_window_data = b'ubuntu-24.04\x00\x00\x00\x00'

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
    # (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=60, dlen=8), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_plmc_past_boundary_data), tag=4),
    # F11/F12 HBS (FID 16h), DOFST=8 (>6): trailing-field fallback
    # (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x16,
                                      doff=8, dlen=3), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_hbs_past_boundary_data), tag=5),
    # F13/F14 PLMC (FID 13h), DOFST=480, DLEN=50 (oversized): trailing-field
    # clamp (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03, cns=0x13,
                                      doff=480, dlen=50), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_plmc_oversized_data), tag=6),
    # F15/F16 HBS (FID 16h), DOFST=480, DLEN=50 (oversized): same clamp as
    # F13/F14 (see block comment above).
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
    # F21/F22 Controller Metadata (FID 7Eh), DOFST=64: a later window of the
    # Host Metadata structure (see block comment above).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x03,
                                      cns=F_CTRL_METADATA,
                                      doff=64, dlen=len(_hmd_window_data)),
                tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_hmd_window_data), tag=10),
]

BASE_TS_FEATURES_WINDOWED_US = 1709378000 * 1_000_000

def build_features_windowed_pcapng(output_path):
    write_pcapng(output_path, packets_features_windowed, BASE_TS_FEATURES_WINDOWED_US)


# ---------------------------------------------------------------------------
# nvme-mi-features-sel.pcapng — Get Features Select handling and feature units
# ---------------------------------------------------------------------------
#
# Base 2.3 Figures 197/199: Select 011b returns supported capabilities in
# completion Dword 0 and no data structure; 100b-111b are reserved.  The
# remaining pairs cover the 0's-based Arbitration weights and Arbitration
# Burst (Figure 404), LBA Range Type NUM/NLB (NVM CS 1.2 Figures 93-95), the
# Host Identifier completion (Figure 467: data only), the power scale and
# measurement type tables (Figures 452-454, 679, 681) and the Security
# Personality data (Figures 450-451).  Each pair is a request then its
# response; the frame map below lists the response frames.
#
#   F2   Arbitration SEL 0: AB 3 (8 commands), LPW 38h (57), HPW FFh (256)
#   F4   Arbitration SEL 1: AB 7 (no limit)
#   F6   Arbitration SEL 3: capabilities only
#   F7/F8 Arbitration SEL 4 (reserved): expert on request, DW0 raw
#   F9/F10 APST SEL 3, DLEN 16, 16 bytes data: DLEN and data flagged, raw
#   F12  Timestamp SEL 5 with 8 bytes data: raw
#   F14  Host Identifier SEL 0: DW0 raw, 8-byte HOSTID
#   F16  LBA Range Type SEL 2: NUM 0 (1); NLB 0 (1) and all-ones (2^64)
#   F18  Power Limit: PLV 1234h, PLS 01b (0.0001 W)
#   F20  Power Threshold: PTS 10b (0.01 W), PMTS Ch (vendor specific)
#   F21  Set Power Measurement: ACT 1, PMTS 0 (NVM subsystem total power)
#   F24  Get CDP PERID 1: SPS TCGPST|AHATSDPS|VSPF0, SSP TCGPSUP|VSPFF
#   F25  Set CDP PERID 1 CHPS: attributes ASP|TCGP|VSPF1
#   F27  Set Power Limit: PLS 10b (0.01 W) in CDW13
#   F31  Set Power Management: WH 3, PS 5 (Base 2.4 Figure 468)
#   F34  Get Power Management: WH 2, PS 5
#   F35  Set Temperature Threshold: TMPSEL 2h, TMPTH 14Bh (Figure 470)
#   F37  Get Temperature Threshold: TMPSEL 2h
#   F39  Get Read Recovery Level Config: NVMSETID 3 (Figure 484)

BASE_TS_FEATURES_SEL_US = 1709392000 * 1_000_000
F_AUTO_PS_TRANSITION = 0x0c
F_HOST_ID = 0x81
F_CONF_DEV_PERSONALITY = 0x22
F_POWER_LIMIT = 0x23
F_POWER_THRESHOLD = 0x24
F_POWER_MEASUREMENT = 0x25
F_LBA_STATUS_INFO = 0x15


def features_sel_packets():
    ok = admin_cqe3(cqe_status_word(phase=1))
    pkts = []

    def get(fid, sel, dw0, data=b'', cdw11=0, cdw13=0):
        tag = (len(pkts) // 2) & 7
        pkts.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0001,
                                          flags=0x03, cns=fid | (sel << 8),
                                          doff=0, dlen=len(data), cdw11=cdw11,
                                          lpo=cdw13 << 32), tag=tag))
        pkts.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS, cqe1=dw0, cqe3=ok) + data,
                    tag=tag))

    def put(fid, data=b'', cdw11=0, cdw13=0, dw0=0):
        tag = (len(pkts) // 2) & 7
        pkts.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0001,
                                          flags=0x01, cns=fid, dlen=len(data),
                                          cdw11=cdw11, lpo=cdw13 << 32) + data,
                    tag=tag))
        pkts.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS, cqe1=dw0, cqe3=ok), tag=tag))

    get(F_ARBITRATION, 0, 0xff003803)
    get(F_ARBITRATION, 1, 0x00000007)
    get(F_ARBITRATION, 3, 0x00000005)
    get(F_ARBITRATION, 4, 0xff003803)
    get(F_AUTO_PS_TRANSITION, 3, 0x00000001, bytes(range(1, 17)))
    get(F_TIMESTAMP, 5, 0, bytes(range(0x20, 0x28)))
    get(F_HOST_ID, 0, 0xdeadbeef, bytes(range(0x30, 0x38)))
    get(F_LBA_RANGE_TYPE, 2, 0x00000000,
        _lbart_entry(0x01, 0x01, 0x10, 0, bytes(16))
        + _lbart_entry(0x01, 0x01, 0x20, 0xffffffffffffffff, bytes(16)))
    get(F_POWER_LIMIT, 0, 0x00011234)
    get(F_POWER_THRESHOLD, 0, 0x00c20100)
    put(F_POWER_MEASUREMENT, cdw11=0x00000001)
    get(F_CONF_DEV_PERSONALITY, 0, 0x00000001,
        struct.pack('<II', 0x00010006, 0x80000002), cdw13=0x01)
    put(F_CONF_DEV_PERSONALITY, struct.pack('<I', 0x00020003), cdw13=0x201)
    put(F_POWER_LIMIT, cdw13=0x00020100)
    # The controller answers with the closest interval it supports (NVM CS 1.2 Fig 99).
    put(F_LBA_STATUS_INFO, cdw11=0x0032000a, dw0=0x00320014)
    put(F_POWER_MGMT, cdw11=3 << 5 | 5)
    get(F_POWER_MGMT, 0, 2 << 5 | 5)
    put(F_TEMP_THRESHOLD, cdw11=0x2 << 16 | 0x14b)
    get(F_TEMP_THRESHOLD, 0, 0x14b, cdw11=0x2 << 16)
    get(0x12, 0, 0, cdw11=0x0003)
    return pkts


def build_features_sel_pcapng(output_path):
    write_pcapng(output_path, features_sel_packets(), BASE_TS_FEATURES_SEL_US)


# ---------------------------------------------------------------------------
# nvme-mi-logpage-fixed.pcapng: MI-8a fixed-layout log pages (Base 2.3 LIDs
# 15h, 16h, 18h, 1Dh, 25h and 7Fh).
# ---------------------------------------------------------------------------
BASE_TS_LOGPAGE_FIXED_US = 1709564800 * 1_000_000


def logpage_fixed_vectors():
    """(LID, LSP, LPO, data) per case; one request and one response frame each."""
    v = []
    # F1/F2 Boot Partition: ABPID 1, BPSZ 2 (256 KiB), then image bytes.
    bp = bytes([0x15, 0, 0, 0]) + struct.pack('<I', 0x80000002) + bytes(8) + bytes(range(32))
    v.append((0x15, 0, 0, bp))
    # F3/F4 Rotational Media Information, Figure 274.
    rmi = bytearray(512)
    struct.pack_into('<HHH2xIIII', rmi, 0, 1, 2, 7200, 10, 1, 20, 2)
    v.append((0x16, 0, 0, bytes(rmi)))
    # F5/F6 NRS 0001h is prohibited; a 24-byte read stops before the reserved tail.
    rmi2 = bytearray(rmi)
    struct.pack_into('<H', rmi2, 4, 1)
    v.append((0x16, 0, 0, bytes(rmi2[:24])))
    # F7/F8 Management Address List: MAT 1, MAT 2, then MAT FFh ends the list.
    mal = bytearray(4096)
    mal[0] = 1
    mal[4:4 + 22] = b'https://10.0.0.1/mgmt\0'
    mal[512] = 2
    mal[516:516 + 21] = b'snmp://192.0.2.7:161\0'
    mal[1024] = 0xff
    mal[1536] = 1
    v.append((0x18, 0, 0, bytes(mal)))
    # F9/F10 Descriptor 1 alone.
    v.append((0x18, 0, 512, bytes(mal[512:1024])))
    # F11/F12 Device Personalities: NUMP 1 (two), DPLPHL 6, CDPLPS 16.
    dp = struct.pack('<HBBH', 1, 0, 6, 16) + bytes([5, 0, 0, 0x01, 0x01]) + bytes([5, 1, 3, 0x02, 0x00])
    v.append((0x1d, 0, 0, dp))
    # F13/F14 Personality 1 with PPS 4.
    dp_bad = bytearray(dp)
    dp_bad[11] = 4
    v.append((0x1d, 0, 0, bytes(dp_bad)))
    # F15/F16 From LPO 8: Personality 0 cut (raw), Personality 1 whole.
    v.append((0x1d, 0, 8, dp[8:16]))
    # F17/F18 Power Measurement: two histogram descriptors and 4 VS bytes.
    pm = bytearray(64)
    struct.pack_into('<BBHIIHH', pm, 0, 0, 3, 0x0009, 84, 100, 2, 30)
    struct.pack_into('<Q', pm, 16, 0x0003000000123456)
    struct.pack_into('<HHHHI', pm, 24, 8, 250, 16, 4, 0)
    struct.pack_into('<IIQB', pm, 40, (2 << 16) | 1234, (2 << 16) | 2500, 0x0002000000654321, 5)
    pm += struct.pack('<II', 60, 0) + struct.pack('<II', 40, (2 << 16) | 25) + bytes.fromhex('deadbeef')
    v.append((0x25, 0, 0, bytes(pm)))
    # F19/F20 PHDS 4 with NPHD 1; IPWRPE FFh is not reported.
    pm_bad = bytearray(pm[:72])
    struct.pack_into('<H', pm_bad, 12, 1)
    struct.pack_into('<H', pm_bad, 24, 4)
    struct.pack_into('<H', pm_bad, 30, 0)
    pm_bad[56] = 0xff
    v.append((0x25, 0, 0, bytes(pm_bad)))
    # F21/F22 Sanitize Namespace Status List, NLT 1: three NSIDs, a fourth past NUMNSID.
    snsl = struct.pack('<QQ', 7, 3) + struct.pack('<4I', 1, 2, 5, 9)
    v.append((0x7f, 1, 0, snsl))
    # F23/F24 NSID 1 and 2 alone.
    v.append((0x7f, 0, 20, snsl[20:28]))
    # F25/F26 Boot Partition BPINFO alone.
    v.append((0x15, 0, 4, bp[4:8]))
    # F27/F28 Device Personalities with DPLPHL 12: six bytes follow the header
    # before the two Personalities.
    # Two bytes of padding make the 22 bytes a whole number of Dwords.
    v.append((0x1d, 0, 0, struct.pack('<HBBH', 1, 0, 12, 16) + bytes(6) + dp[6:16] + bytes(2)))
    return v


def logpage_fixed_packets():
    pkts = []
    for i, (lid, lsp, lpo, data) in enumerate(logpage_fixed_vectors()):
        numd = (len(data) + 3) // 4 - 1
        tag = i & 7
        pkts.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, admin_request_payload(
            0x02, ctrl_id=0x0001, cns=lid | (lsp << 8) | ((numd & 0xffff) << 16),
            cdw11=numd >> 16, lpo=lpo, flags=0x03, doff=0, dlen=len(data)), tag=tag))
        pkts.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                admin_response_payload(STATUS_SUCCESS) + data, tag=tag))
    return pkts


def build_logpage_fixed_pcapng(output_path):
    write_pcapng(output_path, logpage_fixed_packets(), BASE_TS_LOGPAGE_FIXED_US)


# ---------------------------------------------------------------------------
# nvme-mi-logpage-desc.pcapng F1-F24 — MI-8b: descriptor-list log pages
# ---------------------------------------------------------------------------
# Media Unit Status (10h, Base 2.3 Figures 259-260), Supported Capacity
# Configuration List (11h, Figures 261-265), Dispersed Namespace
# Participating NVM Subsystems (17h, Figure 275) and Reachability Groups /
# Associations (1Ah/1Bh, Figures 279-283) read with OT=0.  Each pair is
# request (odd frame) then response (even frame).  F25/F26 is 11h again, cut
# at a descriptor boundary.
BASE_TS_LOGPAGE_DESC_US = 1709651200 * 1_000_000


def logpage_desc_vectors():
    le16 = lambda v: struct.pack('<H', v)
    le32 = lambda v: struct.pack('<I', v)
    le64 = lambda v: struct.pack('<Q', v)
    le128 = lambda v: v.to_bytes(16, 'little')
    v = []

    # 10h: NMU 2, CCHANS 4, SELC 1.
    mu0 = (le16(0) + le16(1) + le16(1) + le16(1) + le16(3) + bytes([90, 5, 2, 16])
           + bytes(2) + le16(0) + le16(1))
    mu1 = (le16(1) + le16(1) + le16(2) + le16(2) + le16(0xffff) + bytes([100, 255, 1, 32])
           + bytes(18) + le16(3))
    mus = le16(2) + le16(4) + le16(1) + bytes(10) + mu0 + mu1
    # F1/F2 the whole page; the pad after descriptor 1 is outside NMU.
    v.append((0x10, 0, 0, mus + bytes(2)))
    # F3/F4 descriptor 0 with CIO 8.
    v.append((0x10, 0, 0, mus[:29] + bytes([8]) + mus[30:]))
    # F5/F6 a window starting inside descriptor 0.
    v.append((0x10, 0, 20, mus[20:]))
    # F7/F8 the window ends inside descriptor 1 (after NVMSETID).
    v.append((0x10, 0, 0, mus[:44]))

    # 11h: one configuration with one Endurance Group of two Channels.
    mu = lambda muid, info=b'': le16(muid) + bytes(4) + le16(len(info)) + info
    ch0 = le16(0) + le16(1) + mu(0)
    ch1 = le16(0xffff) + le16(2) + mu(1) + mu(2, bytes.fromhex('aabbccdd'))
    eg = (le16(1) + le16(2) + bytes(12) + le128(0x1000_0000_0000)
          + le128(0x10_0000_0000) + le128(1000) + bytes(16)
          + le16(2) + le16(1) + le16(2) + le16(2) + ch0 + ch1)
    cc = le16(1) + le16(0) + le16(1) + bytes(26) + eg
    scc = bytes([1]) + bytes(15) + cc
    # F9/F10 the whole page.
    v.append((0x11, 0, 0, scc))
    # F11/F12 the window ends inside the Endurance Group's reserved bytes.
    v.append((0x11, 0, 0, scc[:120]))
    # F13/F14 a window starting past the first descriptor.
    v.append((0x11, 0, 32, scc[32:]))

    # 17h: NUMPSUB 2; a third, nonzero entry is outside the count.
    nqn = lambda t: t.encode().ljust(256, b'\0')
    dnps = (le64(4) + le64(2) + bytes(240) + nqn('nqn.2014-08.org.nvmexpress:uuid:1111')
            + nqn('nqn.2024-01.com.example:subsys2') + nqn('nqn.stale'))
    # F15/F16 the whole page.
    v.append((0x17, 0, 0, dnps))
    # F17/F18 entry 1 alone.
    v.append((0x17, 0, 512, dnps[512:768]))

    # 1Ah: NRGD 2; group 1 has no NSIDs.
    rg0 = le32(1) + le32(2) + le64(3) + bytes(16) + le32(1) + le32(2)
    rg1 = le32(2) + le32(0) + le64(4) + bytes(16)
    rgl = le64(9) + le16(2) + bytes(6) + rg0 + rg1
    # F19/F20 the whole page, OT=0.
    v.append((0x1a, 0, 0, rgl))
    # F21/F22 a window starting inside descriptor 0.
    v.append((0x1a, 0, 32, rgl[32:]))

    # 1Bh: NRAD 1, RAC 02h, two RGIDs.
    ra0 = le32(7) + le32(2) + le64(1) + bytes([2]) + bytes(15) + le32(1) + le32(2)
    # F23/F24 the whole page, OT=0.
    v.append((0x1b, 0, 0, le64(5) + le16(1) + bytes(6) + ra0))
    # F25/F26 the 11h window ends exactly where Channel 1's second Media Unit
    # would start.
    v.append((0x11, 0, 0, scc[:len(scc) - len(mu(2, bytes.fromhex('aabbccdd')))]))
    return v


def logpage_desc_packets():
    pkts = []
    for i, (lid, lsp, lpo, data) in enumerate(logpage_desc_vectors()):
        numd = (len(data) + 3) // 4 - 1
        tag = i & 7
        pkts.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, admin_request_payload(
            0x02, ctrl_id=0x0001, cns=lid | (lsp << 8) | ((numd & 0xffff) << 16),
            cdw11=numd >> 16, lpo=lpo, flags=0x03, doff=0, dlen=len(data)), tag=tag))
        pkts.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                admin_response_payload(STATUS_SUCCESS) + data, tag=tag))
    return pkts


def build_logpage_desc_pcapng(output_path):
    write_pcapng(output_path, logpage_desc_packets(), BASE_TS_LOGPAGE_DESC_US)


# ---------------------------------------------------------------------------
#
# Identify (06h) exchanges whose DOFST/DLEN windows start inside or past the
# list headers, plus the NVM Command Set specific structures (NVM CS 1.2
# Figures 118-120), the Ports List (Base 2.3 Figures 351-352), descriptor
# NIDL checks (Figure 331) and a reserved CNS.  Each pair is request (odd
# frame) then response (even frame) carrying the window's bytes.

# ---------------------------------------------------------------------------
# nvme-mi-identify-win.pcapng F1-F78 — windowed Identify lists and fields
# ---------------------------------------------------------------------------
BASE_TS_IDENTIFY_WIN_US = 1709478400 * 1_000_000


def identify_win_packets():
    ok = admin_cqe3(cqe_status_word(phase=1))
    pkts = []

    def ident(cns, data, off=0, csi=0, cntid=0, cnssid=0):
        tag = (len(pkts) // 2) & 7
        pkts.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                          flags=0x03, cns=cns | (cntid << 16),
                                          doff=off, dlen=len(data),
                                          cdw11=(csi << 24) | cnssid),
                    tag=tag))
        pkts.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS, cqe3=ok) + data, tag=tag))

    def window(struct_bytes, off, length):
        return bytes(struct_bytes.ljust(4096, b'\0')[off:off + length])

    # F1/F2 CNS 00h, LBAF32..47 with NLBAF/NULBAF outside the window.
    ns = bytearray(4096)
    for i in range(64):
        ns[128 + 4 * i:132 + 4 * i] = struct.pack('<I', (1 << 24) | (12 << 16) | i)
    ident(0x00, window(ns, 256, 64), off=256)
    # F3/F4 CNS 02h at an unaligned offset: two raw lead bytes, then nsid[1..3].
    ident(0x02, window(struct.pack('<4I', 1, 5, 6, 7), 2, 16), off=2)
    # F5/F6 CNS 03h: an EUI64 NIDT with a 16-byte NIDL, then a CSI descriptor.
    ident(0x03, bytes([1, 16, 0, 0]) + bytes(range(16)) + bytes([4, 1, 0, 0, 2])
          + bytes(7))
    # F7/F8 CNS 04h: NUMENT 2, entry 1 cut inside TNVMSC.
    nvmset = bytearray(4096)
    nvmset[0] = 2
    for i, base in enumerate((128, 256)):
        nvmset[base:base + 48] = (struct.pack('<HH4xII', i + 1, 0x10 + i, 100 + i, 8 + i)
                                  + bytes([0x40 + i] * 16) + bytes([0x50 + i] * 16))
    ident(0x04, window(nvmset, 0, 276))
    # F9/F10 CNS 04h: entry 1 alone, NUMENT outside the window.
    ident(0x04, window(nvmset, 256, 48), off=256)
    # F11/F12 CNS 14h from VQFRT.
    pcc = bytearray(4096)
    pcc[32:48] = struct.pack('<IIHHHH', 0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
    pcc[64:80] = struct.pack('<IIHHHH', 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc)
    ident(0x14, window(pcc, 32, 48), off=32)
    # F13/F14 CNS 15h: Secondary Controller Entry 1 alone.
    scl = bytearray(4096)
    scl[0] = 2
    scl[64:78] = struct.pack('<HHB3xHHH', 0x22, 0x01, 0x01, 0x03, 4, 5)
    ident(0x15, window(scl, 64, 32), off=64)
    # F15/F16 CNS 16h: ND 0 (one descriptor) while descriptor 1 is nonzero.
    ngl = bytearray(4096)
    ngl[0:5] = struct.pack('<IB', 1, 0)
    ngl[32:64] = struct.pack('<4Q', 0x1000, 0x2000, 0x3000, 0x4000)
    ident(0x16, window(ngl, 0, 64), csi=0)
    # F17/F18 CNS 17h: entries 1 and 2, entry 3's UUID cleared ends the list.
    uuid = bytearray(4096)
    for i in (1, 2, 3):
        uuid[32 * i] = i
    uuid[48:64] = bytes(range(0x10, 0x20))
    uuid[80:96] = bytes(range(0x20, 0x30))
    ident(0x17, window(uuid, 0, 128))
    # F19/F20 CNS 17h: a window starting inside entry 2, then entry 3.
    uuid[112:128] = bytes(range(0x30, 0x40))
    ident(0x17, window(uuid, 72, 56), off=72)
    # F21/F22 CNS 05h CSI 0 (NVM CS 1.2 Figure 118).
    nvm_ns = bytearray(4096)
    nvm_ns[0:10] = struct.pack('<QBB', 0x00ff, 0x0f, 0x01)
    nvm_ns[12:16] = struct.pack('<I', (1 << 9) | (3 << 7) | 0x10)
    nvm_ns[16:20] = struct.pack('<I', (2 << 7) | 0x20)
    nvm_ns[268:296] = struct.pack('<7I', 0x100, 7, 3, 15, 0x200, 0x300, 0x400)
    ident(0x05, window(nvm_ns, 0, 296), csi=0)
    # F23/F24 CNS 06h CSI 0 (NVM CS 1.2 Figure 120).
    ident(0x06, struct.pack('<4BIQBBHIB3x', 1, 2, 3, 4, 0x1000, 0x2000, 0x03, 5,
                            0x0001, 0x00010200, 0xc1), csi=0)
    # F25/F26 CNS 18h: Domain Attributes Entry 0 without NUMENT.
    dom = bytearray(4096)
    dom[0] = 1
    dom[128:192] = struct.pack('<H14x', 0x4321) + bytes([1] * 16) + bytes([2] * 16) + bytes([3] * 16)
    ident(0x18, window(dom, 128, 64), off=128)
    # F27/F28 CNS 19h: identifiers 1..4 without NEGIDS; a zero slot skipped.
    ident(0x19, struct.pack('<4H', 7, 0, 9, 0x10), off=4)
    # F29/F30 CNS 1Ch: vectors 0 and 1 (Base 2.3 Figure 344).
    ident(0x1c, struct.pack('<2Q', 0x5, 0x1f))
    # F31/F32 CNS 1Eh: one Underlying Fabrics Transport Entry.
    ports = bytearray(16 + 576)
    ports[0:16] = struct.pack('<QQ', 9, 1)
    ports[16:16 + 11] = b'192.168.0.1'
    ports[16 + 256:16 + 260] = bytes([1, 2, 3, 4])
    ports[16 + 512:16 + 517] = struct.pack('<HBBB', 0x0102, 0x03, 0x01, 0x15)
    ident(0x1e, bytes(ports))
    # F33/F34 reserved CNS 0Bh.
    ident(0x0b, bytes(range(16)))
    # F35/F36 CNS 01h PSD0 with APW Workload #1 (Base 2.3 Figures 329, 674).
    psd = bytearray(32)
    psd[22] = 0x01
    ident(0x01, bytes(psd), off=2048)
    # F37/F38 CNS 18h: a window inside entry 0 covering all of TDC.
    ident(0x18, window(dom, 0x90, 0x10), off=0x90)
    # F39/F40 CNS 18h: a window splitting TDC stays partial.
    ident(0x18, window(dom, 0x94, 0x0c), off=0x94)
    # F41/F42 CNS 18h: a nonzero slice of reserved entry 0 bytes 15:4.
    dom[132:144] = b'\xee' * 12
    ident(0x18, window(dom, 0x84, 0x0c), off=0x84)
    # F43/F44 CNS 18h: starts inside entry 0, crosses into entry 1 (DID 2).
    struct.pack_into('<H', dom, 256, 0x0002)
    ident(0x18, window(dom, 0x90, 0x80), off=0x90)
    # F45/F46 CNS 18h: starts inside an all-zero entry 2, NUMENT unknown.
    ident(0x18, window(dom, 0x190, 0x10), off=0x190)
    # F47/F48 CNS 1Dh: one Underlying Namespace entry; CNSSID is its IDX.
    und = bytearray(16 + 320)
    und[0:16] = struct.pack('<QQ', 3, 1)
    und[16:16 + 5] = b'nqn.x'
    struct.pack_into('<IH', und, 16 + 256, 0x11, 0x22)
    struct.pack_into('<H', und, 16 + 318, 0x1234)
    ident(0x1d, bytes(und), cnssid=0x1234)
    # F49-F52 CNS 1Dh: NUMENT 12, then 13 with a 13th NQN cut at 4096 bytes.
    und12 = bytearray(4096)
    for k in range(13):
        p0 = 16 + k * 320
        und12[p0:p0 + 5] = b'nqn.%d' % (k % 10)
        if k < 12:
            struct.pack_into('<H', und12, p0 + 318, k)
    struct.pack_into('<Q', und12, 0, 1)
    struct.pack_into('<Q', und12, 8, 12)
    ident(0x1d, bytes(und12[:3856]))
    struct.pack_into('<Q', und12, 8, 13)
    ident(0x1d, bytes(und12))
    # F53-F58 CNS 16h: the layout belongs to the I/O Command Set (Base 2.4
    # section 5.2.14.2.13), so CSI 01h and vendor CSI 30h stay opaque; CSI 00h
    # at DOFST 32 is the NVM control.
    ident(0x16, window(ngl, 0, 64), csi=0x01)
    ident(0x16, window(ngl, 32, 32), off=32, csi=0x30)
    ident(0x16, window(ngl, 32, 32), off=32, csi=0)
    # F59/F60 CNS 16h CSI 02h: Invalid I/O Command Set (Figure 103).
    tag = (len(pkts) // 2) & 7
    pkts.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x03, cns=0x16, dlen=64,
                                      cdw11=0x02 << 24), tag=tag))
    pkts.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe3=admin_cqe3(
                    cqe_status_word(sct=1, sc=0x2c, dnr=1, phase=1))), tag=tag))
    # F61-F74 reserved enum endpoints beside a defined control (Base 2.4
    # Figures 338/342, NVM CS 1.3 Figures 123/128).
    # F61-F64 CNS 01h SANICAP: NODMMAS 3, then 2.
    for nodmmas in (3, 2):
        ident(0x01, struct.pack('<I', nodmmas << 30), off=328)
    # F65-F70 CNS 00h DPC..NAWUN: PIT/DRB 4/3, 7/7, then 3/2.
    for pit, drb in ((4, 3), (7, 7), (3, 2)):
        ident(0x00, bytes([0, pit, 0, 0, 0, drb, 0, 0]), off=28)
    # F71/F72 CNS 03h: NIDT 0h, 5h and FFh, then a CSI descriptor.
    ident(0x03, b''.join(bytes([t, 4, 0, 0]) + bytes([t] * 4) for t in (0, 5, 0xff))
          + bytes([4, 1, 0, 0, 0]) + bytes(3))
    # F73/F74 CNS 05h CSI 0 ELBAF0..2: Qualified Type with QPIF 3h, Fh, 2h.
    ident(0x05, struct.pack('<3I', *((q << 9) | (3 << 7) for q in (3, 0xf, 2))),
          off=12, csi=0)
    # F75/F76 CNS 04h: 128-bit byte counts (Base 2.4 Figure 345), TNVMSC
    # 1 TiB (below 2^64) and UNVMSC 2^64 + 1234h (above it).
    cap = bytearray(4096)
    cap[0] = 1
    cap[128:176] = (struct.pack('<HH4xII', 1, 1, 0, 0) + (1 << 40).to_bytes(16, 'little')
                    + ((1 << 64) + 0x1234).to_bytes(16, 'little'))
    ident(0x04, window(cap, 0, 256))
    # F77/F78 CNS 18h: TDC 4096, UDC 0 and MEGDC 5 * 2^64 (Figure 351).
    dcap = bytearray(4096)
    dcap[0] = 1
    dcap[128:192] = (struct.pack('<H14x', 1) + (4096).to_bytes(16, 'little') + bytes(16)
                     + (5 << 64).to_bytes(16, 'little'))
    ident(0x18, window(dcap, 0, 256))
    return pkts


def build_identify_win_pcapng(output_path):
    write_pcapng(output_path, identify_win_packets(), BASE_TS_IDENTIFY_WIN_US)


def build_nvme_p2_5_pcapng(output_path):
    packets = []
    endpoint = 0x20

    def command(opcode, cdw10=0, cdw11=0, data=None, doff=0, lpo=0,
                cdw12=None, sct=0, sc=0):
        nonlocal endpoint
        endpoint += 1
        dlen = len(data) if data is not None else 0
        flags = 0x01 | (0x02 if doff else 0)
        request = admin_request_payload(
            opcode, cns=cdw10, cdw11=cdw11, doff=doff, dlen=dlen,
            flags=flags, lpo=lpo, cdw12=cdw12)
        status = cqe_status_word(sct=sct, sc=sc, phase=1)
        response = admin_response_payload(
            STATUS_SUCCESS, cqe3=admin_cqe3(status)) + (data or b'')
        packets.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, request,
                                   bmc_eid=endpoint))
        packets.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, response,
                                   bmc_eid=endpoint))

    ctrl = bytearray(identify_ctrl_data())
    ctrl[76] = 0x0f
    struct.pack_into('<H', ctrl, 266, 0x0157)
    struct.pack_into('<H', ctrl, 268, 0x012c)
    ctrl[1806] = 0x03
    struct.pack_into('<I', ctrl, 2048 + 4, 1234)
    struct.pack_into('<I', ctrl, 2048 + 8, 5678)
    ctrl[2048 + 23] = 100
    ctrl[2048 + 24] = 99
    ctrl[2048 + 25] = 200
    command(OPC_IDENTIFY, cdw10=0x01, data=bytes(ctrl))

    # Both cuts are within the 16-byte FGUID field (Base 2.4 Figure 338).
    command(OPC_IDENTIFY, cdw10=0x01, data=bytes(ctrl[116:124]), doff=116)
    command(OPC_IDENTIFY, cdw10=0x01, data=bytes(ctrl[112:120]), doff=112)

    ns = bytearray(identify_ns_data())
    ns[9] = 0x03
    command(OPC_IDENTIFY, cdw10=0x05, data=bytes(ns))

    err = bytearray(64)
    err[30] = 0x01
    command(OPC_GET_LOG_PAGE, cdw10=0x01 | (15 << 16), data=bytes(err))
    for eto in (0xffffffff, 0):
        sanitize = bytearray(512)
        struct.pack_into('<I', sanitize, 8, eto)
        command(OPC_GET_LOG_PAGE, cdw10=0x81 | (127 << 16),
                data=bytes(sanitize))

    for fid, attri, r4karl in ((0x1c, 0x00, 0x05), (0x1c, 0x00, 0x18)):
        perf = bytearray(8)
        perf[0] = 0x01
        perf[4] = r4karl
        command(OPC_GET_FEATURES, cdw10=fid, cdw11=attri, data=bytes(perf))
    command(OPC_GET_FEATURES, cdw10=0x00)
    command(OPC_GET_FEATURES, cdw10=0x90)
    command(OPC_GET_FEATURES, cdw10=0x15)
    command(OPC_GET_FEATURES, cdw10=0x1c, cdw11=0x01)
    perf_attributes = bytearray(1024)
    perf_attributes[0] = 0x01
    command(OPC_GET_FEATURES, cdw10=0x1c, cdw11=0xc0,
            data=bytes(perf_attributes))
    command(OPC_GET_FEATURES, cdw10=0x03 | (0x03 << 8))
    for act in (0, 1, 2, 0x0b, 0x0c, 0x0f):
        command(OPC_SET_FEATURES, cdw10=0x25, cdw11=act)

    # Format NVM PI=1, MSET=0, PIL=1: I/O Command Set specific (Base 2.4
    # Figure 195); NVM Command Set 1.3 Figure 91 is only the NVM reading.
    command(0x80, cdw10=0x0120)

    # Sanitize Namespace action values and the Fig 455 / Fig 104 status
    # conflict. The 12h status is shown with a note, not an expert info.
    for sanact in (0, 1, 4, 5, 7):
        command(OPC_SANITIZE_NS, cdw10=sanact)
    command(OPC_SANITIZE_NS, cdw10=0, sct=1, sc=0x12)
    command(OPC_SANITIZE_NS, cdw10=0, sct=1, sc=0x3c)
    command(OPC_SANITIZE, cdw10=0, sct=1, sc=0x23)
    command(OPC_GET_LBA_STATUS, cdw12=0)

    # ETPVDS has no 0h sentinel (Base 2.4 Figure 312).
    for etpvds in (0, 0xffffffff):
        sanitize = bytearray(512)
        struct.pack_into('<I', sanitize, 8, 0xffffffff)
        struct.pack_into('<I', sanitize, 32, etpvds)
        command(OPC_GET_LOG_PAGE, cdw10=0x81 | (127 << 16),
                data=bytes(sanitize))

    # LSP MCDA (Base 2.4 Figure 220) with CTHID set, then SCP 1h and
    # CNTTS 3h (Figure 274).
    for mcda in (0, 1, 2, 3, 5, 7):
        command(OPC_GET_LOG_PAGE,
                cdw10=0x07 | ((0x01 | (mcda << 1)) << 8) | (127 << 16))
    command(OPC_GET_LOG_PAGE, cdw10=0x14 | (0x01 << 8) | (127 << 16))
    command(OPC_GET_LOG_PAGE, cdw10=0x14 | (0x30 << 8) | (127 << 16))

    # Reserved CDW10 values with assigned neighbours as controls (Base 2.4
    # Figures 177, 187, 195, 365 and 451).
    command(OPC_FORMAT_NVM, cdw10=7 << 9)
    for ca in (4, 6):
        command(OPC_FW_COMMIT, cdw10=ca << 3)
    for stc in (4, 0xe):
        command(OPC_SELF_TEST, cdw10=stc)
    for cdw10 in (5, 1, 3 << 5, 3 << 16, 0xf << 16):
        command(OPC_LOCKDOWN, cdw10=cdw10)
    for sanact in (0, 6, 2):
        command(OPC_SANITIZE, cdw10=sanact)

    # Sanitize Namespace CDW10 reserved bits 9:5 and 31:11 (Figure 454).
    for cdw10 in (0x24, 0x80000004, 0x41c):
        command(OPC_SANITIZE_NS, cdw10=cdw10)

    write_pcapng(output_path, packets, 1800000000 * 1_000_000)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F1-F24 — Security Send/Receive payload decode
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
# Command Dword 10 layout (NVMe Base 2.3 Figure 394 for Security Receive,
# Figure 398 for Security Send):
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
#           -> discovery header + TPer, Locking, Opal SSC V2 and Supported
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
#   F23/F24 Security Receive SECP=00h SPSP=0002h
#           -> response data: an SP Specific value with no layout in
#              packet-nvme.c, so the raw blob's
#              nvme.window_decode_skipped names SPC-5

NVME_AQ_OPC_SECURITY_SEND = 0x81
NVME_AQ_OPC_SECURITY_RECV = 0x82

def security_cdw10(secp, spsp):
    """Pack Security Send/Receive Command Dword 10 (NSSF unused)."""
    return ((secp & 0xff) << 24) | ((spsp & 0xffff) << 8)

# --- SECP 00h: Supported Security Protocols List (SPC-5, BE) --------------

def secp0_supported_list(protocols):
    """6 reserved bytes, 2-byte BE list length, then 1-byte protocol IDs."""
    return b'\x00' * 6 + struct.pack('>H', len(protocols)) + bytes(protocols)

# --- SECP 01h: Level 0 Discovery (Core Spec §3.3.6, BE) --------------------

def tcg_l0_feature(code, version, data, minor=0):
    """Feature descriptor: Code(2) + Version(bits 7:4 of byte 2) + Length(1).

    Byte 2's low nibble is Reserved except from Version 2 of Opal SSC V2
    (0x0203, SSC Minor Version Number), Additional DataStore Tables (0x0202)
    and Configurable Namespace Locking (0x0403) (Feature Set Minor Version
    Number)."""
    return (struct.pack('>HBB', code,
                        ((version & 0x0f) << 4) | (minor & 0x0f), len(data))
            + data)

def tcg_l0_data_removal_feature():
    """0x0404 Supported Data Removal Mechanism, 32-byte body (Opal SSC 2.30
    Table 8): Crypto Erase and Vendor Specific Erase supported, both timed in
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
    + Enabled), Opal SSC V2 (0x0203, Base ComID 0x1000, 1 ComID, 4 admins,
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

    0x0405 is the Geometry Reporting layout (CNL 1.00 Table 10, Configurable
    Locking 1.30 Table 11: Version 1, Length 0x1C): ALIGN set, seven Reserved
    bytes, LogicalBlockSize 4096, AlignmentGranularity 8, LowestAlignedLBA
    0."""
    feats = (
        tcg_l0_feature(0x0005, 1,
                       bytes([0x20,   # SIIS Revision Number = v1.20
                              0x05])  # Id Usage Scope = 10b, Key Change Zone = 1
                       + b'\x00' * 10)   # Reserved, total Length = 0x0C
        + tcg_l0_feature(0x0405, 1,
                         b'\x01' + bytes(7) + struct.pack('>IQQ', 4096, 8, 0)))
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
# defines the status as a uinteger; Table 166 does not close its allocation.
# The tiny atom that follows it is an ordinary list element
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
    + tcg_short_uint(0x1234, 2)          # legal, unnamed status
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

# SyncSession assigning SPSessionID 0010h: Core 3.3.7.1.1 reserves 0 to 4095
# for special sessions and has the TSM SHALL NOT assign one to a regular
# session.  Otherwise F8 of nvme-mi-security.pcapng, whose 1001h is
# the control.
tcg_reserved_tsn_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNCSESSION)
    + bytes([0xF0])
    + tcg_tiny_uint(1)                   # HostSessionID
    + tcg_short_uint(0x0010, 2)          # SPSessionID = TSN 0010h
    + bytes([0xF1])
    + TCG_EOD_STATUS_SUCCESS)
tcg_reserved_tsn_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_reserved_tsn_tokens)), 0x1000)

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
# SECP 00h SPSP 0002h Security Compliance Information (SPC-5): a 4-byte
# Compliance Descriptors Length then the descriptors, which packet-nvme.c
# leaves raw -- one 12-byte descriptor (type 0001h, length 4).
_secp0_other = struct.pack('>IHHI', 12, 0x0001, 0, 4) + bytes(range(0x10, 0x14))

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
                                      dlen=len(tcg_startsession_cp),
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
                                      dlen=len(tcg_stack_reset_req),
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
                                      dlen=len(tcg_tper_reset_req),
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
    # and a Namespace Geometry Reporting descriptor (0x0405, CNL 1.00 Table
    # 10, the Geometry Reporting layout).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x0001),
                                      dlen=len(_l0_siis_data),
                                      cdw11=len(_l0_siis_data)), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_l0_siis_data), tag=2),
    # F23/F24 Security Receive SECP=00h SPSP=0002h: Security Compliance
    # Information, header only (NVMe Base 2.4 section 5.2.28 defers to SPC-5).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x00, 0x0002),
                                      dlen=len(_secp0_other),
                                      cdw11=len(_secp0_other)), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_secp0_other), tag=3),
]

BASE_TS_ADMIN_SECURITY_US = 1709380800 * 1_000_000

def build_admin_security_pcapng(output_path):
    write_pcapng(output_path, packets_admin_security, BASE_TS_ADMIN_SECURITY_US)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F43-F58 — ComID management response bodies
# ---------------------------------------------------------------------------
#
# SECP 02h / SPSP 1000h Security Receive responses, whose 12-byte header is
# followed by a request-code-specific body (TCG Core Spec v2.01 §3.3.4.7).
# packets_admin_security only ever carries the STACK_RESET success body, so
# every other body layout -- and both of the length edge cases the spec
# distinguishes -- lives here.
#
# Every response carries exactly the Transfer Length the host asked for:
# Core 2.01 3.3.4.7.2 has the TPer pad shorter response data with zeros and
# cut longer data at the Transfer Length, and MI 2.2 Figure 139 has the
# Management Endpoint return DLEN bytes of it.  The two length cases are
# deliberately separate frames because they look alike and mean opposite
# things:
#   - Available Data Length shorter than the layout Tables 33/36 mandate is a
#     TPer contradicting itself -> truncated expert.
#   - a Transfer Length that stops at the header is the §3.3.4.7.2
#     probe-then-refetch flow (the host reads bytes 10-11 first to learn the
#     length, then repeats the command) -> a declared length with no body
#     bytes, and no expert.
#
#   F1/F2   VERIFY COMID VALID (0001h), Available Data Length 0x22, full body
#           -> ComID State + Time of Allocation/Expiry/Since Last Reset
#              (Table 33), each a 10-byte Table 34 date
#   F3/F4   PROTOCOL STACK RESET (0002h), Available Data Length 0
#           -> Table 37 Pending: no Stack Reset Result field at all
#   F5/F6   STACK_RESET, Available Data Length 4, full 4-byte body
#           -> Success result decodes (the control for F7-F10)
#   F7/F8   STACK_RESET, Available Data Length 4, Transfer Length 12: the
#           probe.  The header says 4 bytes are available and the host has
#           not asked for them yet -> no result, NOT malformed (§3.3.4.7.2)
#   F9/F10  STACK_RESET, Available Data Length 2 (contradicts Table 36's 4)
#           -> truncated expert
#   F11/F12 Request Code 0000h "No Response Available" (Table 31)
#           -> named in the Info column, and an all-Reserved body
#   F13/F14 STACK_RESET, Available Data Length 0, but 4 bytes follow the
#           header -> still Table 37 Pending: no result, no truncation, the
#           trailing bytes are pad.  F3/F4 cannot show this because it has no
#           trailing bytes for a length-driven decoder to misread.
#   F15/F16 STACK_RESET, Available Data Length 8 against Table 36's 4, with
#           all 8 bytes present -> the result decodes and the 4 excess bytes
#           are Response Data (inside the declared data, so not pad)

TCG_REQ_NO_RESPONSE        = 0x00000000
TCG_REQ_VERIFY_COMID_VALID = 0x00000001
TCG_REQ_STACK_RESET        = 0x00000002

def comid_mgmt_resp_hdr(req_code, avail_len):
    """ComID(2) + ComID Ext(2) + Request Code(4) + Reserved(2) +
    Available Data Length(2) = the 12-byte response header."""
    return struct.pack('>HHIHH', 0x1000, 0, req_code, 0, avail_len)

def comid_date(year, mon, day, hour, minute, sec, frac):
    """Core Spec Table 34 date: 10 bytes, trailing reserved byte."""
    return struct.pack('>HBBBBBHB', year, mon, day, hour, minute, sec, frac, 0)

# Table 33 body: state Associated (3) then the three dates.  The last is all
# zeroes, the Table 34 encoding for "TPer has no real-time clock".
_comid_verify_body = (struct.pack('>I', 3)
                      + comid_date(2024, 3, 15, 12, 34, 5, 500)
                      + comid_date(2025, 1, 2, 3, 4, 5, 6)
                      + comid_date(0, 0, 0, 0, 0, 0, 0))
assert len(_comid_verify_body) == 0x22

_comid_bodies = [
    comid_mgmt_resp_hdr(TCG_REQ_VERIFY_COMID_VALID, 0x22) + _comid_verify_body,
    comid_mgmt_resp_hdr(TCG_REQ_STACK_RESET, 0),
    comid_mgmt_resp_hdr(TCG_REQ_STACK_RESET, 4) + struct.pack('>I', 0),
    comid_mgmt_resp_hdr(TCG_REQ_STACK_RESET, 4),           # the probe: header only
    comid_mgmt_resp_hdr(TCG_REQ_STACK_RESET, 2) + b'\x00\x00',
    comid_mgmt_resp_hdr(TCG_REQ_NO_RESPONSE, 0),
    # Pending with trailing bytes: the discriminator is the *declared* length,
    # so these 4 bytes are pad, not a result and not a truncation.
    comid_mgmt_resp_hdr(TCG_REQ_STACK_RESET, 0) + b'\xDE\xAD\xBE\xEF',
    # Over-declared: 8 bytes declared and present where Table 36 mandates 4.
    comid_mgmt_resp_hdr(TCG_REQ_STACK_RESET, 8) + struct.pack('>I', 0)
    + b'\xA1\xA2\xA3\xA4',
]

packets_tcg_comid_mgmt = []
for _i, _body in enumerate(_comid_bodies):
    # DLEN must be dword-aligned (NVMe-MI 2.2 Figure 139), so the host asks
    # for the body rounded up, and the TPer pads to that Transfer Length with
    # zeros (Core 2.01 3.3.4.7.2): F2 and F10 carry two pad bytes.
    _alloc = (len(_body) + 3) & ~3
    _body = _body + bytes(_alloc - len(_body))
    packets_tcg_comid_mgmt += [
        make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                          ctrl_id=0x0001, flags=0x00,
                                          cns=security_cdw10(0x02, 0x1000),
                                          dlen=_alloc, cdw11=_alloc), tag=_i),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(_body), tag=_i),
    ]

BASE_TS_TCG_COMID_MGMT_US = 1709383800 * 1_000_000

def build_tcg_comid_mgmt_pcapng(output_path):
    write_pcapng(output_path, packets_tcg_comid_mgmt, BASE_TS_TCG_COMID_MGMT_US)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F35-F40 — windowed Security Send/Receive transfers
# ---------------------------------------------------------------------------
#
# dissect_nvme_security_data() can only hand a payload to a security-protocol
# dissector when the transfer holds the whole structure from its first byte.
# Later Receive windows remain raw with nvme.window_decode_skipped.
# Invalid MI Send lengths/offsets remain raw with a contract diagnostic:
#
#   F1/F2  Security Receive SECP=01h SPSP=0001h, DOFST=32, DLEN=32 of an
#          Allocation Length of 64 -- a later window.  The 32 response bytes
#          are the tail of a Level 0 Discovery, which would otherwise be
#          decoded from its (absent) header.  DOFST is dword-aligned so the
#          transport's own invalid-DOFST expert stays out of the way.
#   F3/F4  Security Send SECP=01h SPSP=1000h, DOFST=0 but only 16 of CDW11's
#          64-byte Transfer Length attached -- an incomplete FIRST window.
#          The original guard tested only "off != 0", so this half went
#          straight to the TCG dissector as if it were a whole ComPacket.
#
# F5/F6 carries a complete ComPacket but violates Send's DOFST=0 contract.
# DOFST does not relocate Request Data; MI Fig 139 still rejects a nonzero
# value for a command not defined to return Response Data.

_sec_window_tail = bytes(range(0x40, 0x60))
_sec_send_partial = bytes(range(0x80, 0x90))

packets_security_windowed = [
    # F1/F2 Security Receive, later window (DOFST=32)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x03,
                                      cns=security_cdw10(0x01, 0x0001),
                                      doff=32, dlen=len(_sec_window_tail),
                                      cdw11=64), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sec_window_tail), tag=0),
    # F3/F4 Security Send, partial first window (DOFST=0, 16 of TL 64).
    #
    # dlen=0 here is DELIBERATELY non-conformant and must stay that way.
    # Security Send is a Request-Data command, so NVMe-MI 2.2 Figure 139
    # makes DLEN=0 an Invalid Parameter condition twice over: DLEN must
    # equal the Request Data length, and it shall not be 0h for a command
    # defined to transfer Request Data.  The frame carries 16 bytes.
    # This is the Security-path coverage for the DLEN-versus-bytes-carried
    # check; the sibling Sends in packets_admin_security and
    # packets_tcg_atom_classes use dlen=len(payload), so this is the only
    # Security frame that trips it.  Asserted by
    # TestNvmeMiSecurityWindowed::test_partial_send_declares_no_request_data.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=0, cdw11=64)
                + _sec_send_partial, tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=1),
    # F5/F6 Security Send, COMPLETE first window carrying a non-zero DOFST.
    #
    # doff=32 here is DELIBERATELY non-conformant and must stay that way.
    # NVMe-MI 2.2 Figure 139 defines DOFST only for "commands that are defined
    # to transfer NVMe Response Data from a Management Endpoint to a
    # Management Controller", and says it "should be cleared to 0h for all
    # other commands (i.e., ... commands that are defined to transfer NVMe
    # Request Data from a Management Controller to a Management Endpoint)".
    # Security Send transfers Request Data, so DOFST describes nothing here
    # and must not be applied as a window: the 88 bytes are a whole
    # SyncSession ComPacket starting at byte 0 and must reach the TCG
    # dissector.  This is the counterpart to F1/F2, where the same offset on a
    # Security *Receive* is a genuine response-side window that must be
    # honoured.  DLEN and CDW11 (Transfer Length) both equal the 88 bytes
    # carried, so neither the DLEN reconciliation nor the partial-window guard
    # has anything to say about this frame.
    #
    # Pinned by TestNvmeMiSecurityWindowed::test_request_data_ignores_dofst
    # and ::test_request_side_dofst_is_noted.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      doff=32, dlen=len(tcg_syncsession_cp),
                                      cdw11=len(tcg_syncsession_cp))
                + tcg_syncsession_cp, tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=2),
]

BASE_TS_SECURITY_WINDOWED_US = 1709384800 * 1_000_000

def build_security_windowed_pcapng(output_path):
    write_pcapng(output_path, packets_security_windowed, BASE_TS_SECURITY_WINDOWED_US)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F25-F34 - Security Receive transfers that fall
# short of the Allocation Length
# ---------------------------------------------------------------------------
#
# A Security Receive whose transfer delivers fewer bytes than Command Dword 11
# (Allocation Length) asked for is still handed to the security-protocol
# dissector, so the prefix that did arrive decodes.  What must not happen is
# the TCG dissector blaming the TPer for it: a declared length that runs past
# the bytes present but ends inside the Allocation Length is not
# over-declaring, it is cut off by the transfer.  Blaming the length field
# there points the analyst at the one field that is not wrong.
#
#   F1/F2  Security Receive SECP=01h SPSP=1000h, AL=88 (the whole SyncSession
#          ComPacket) with only 64 bytes delivered.  Every declared length in
#          the ComPacket / Packet / Subpacket chain is self-consistent and
#          ends at byte 88, so none of them may raise
#          tcg-storage.length_overrun -- each raises
#          tcg-storage.transfer_short on the structure it cut instead.
#   F3/F4  the control that keeps the overrun expert honest: AL=40 and 40
#          bytes delivered, a COMPLETE transfer, carrying a ComPacket that
#          declares 68 bytes of payload.  68 runs past even the 40 the host
#          allocated, so this Length field really is wrong and must still be
#          flagged as an overrun, on the Length field.
#   F5/F6  the same cut applied to a Level 0 Discovery (SPSP 0001h), whose
#          Length of Parameter Data is checked by a different function than
#          the ComPacket's Length and needed the same treatment.  Its MI DLEN
#          (64) selects exactly the bytes delivered, so the Level 0 decoder
#          treats it as a legal prefix rather than a short transfer.
#   F7/F8  the same 88-byte ComPacket cut at 30 bytes instead of 64, so the
#          cut lands inside the 24-byte Packet header rather than on a
#          boundary.  The ten bytes left over are too short to hold the next
#          header, which is a different code path from a declared length that
#          overruns: it rendered them raw and called the frame Malformed, even
#          though the bytes are missing for exactly the reason F2's are.
#   F9/F10 the same cut applied to the Level 0 Discovery: 50 of 136 bytes, so
#          the two bytes after the 48-byte header cannot hold a feature
#          descriptor header.  DLEN 50 selects them, so this too is a selected
#          prefix (though DLEN 50 is not dword aligned MI traffic).

# 64 of the SyncSession ComPacket's 88 bytes: the header and part of the
# Packet it frames.
_sec_short_cp = tcg_syncsession_cp[:64]

# A ComPacket header declaring 68 payload bytes with only 20 attached, sent
# as a complete 40-byte transfer.  Nothing truncated it -- the declaration
# does not fit the transfer the host asked for.
_sec_overrun_cp = (struct.pack('>IHHIII', 0, 0x1000, 0, 0, 0, 68)
                   + tcg_syncsession_cp[20:40])
assert len(_sec_overrun_cp) == 40, len(_sec_overrun_cp)

# 64 of the Level 0 Discovery's 136 bytes: the 48-byte header (whose Length of
# Parameter Data covers all 136) and the first feature descriptor.
_sec_short_l0 = _l0_data[:64]

# The same two structures cut so that the survivors cannot hold the next
# header: 30 bytes leaves 10 of the ComPacket's 24-byte Packet header, and 50
# bytes leaves 2 of a 4-byte feature descriptor header.
_sec_stub_cp = tcg_syncsession_cp[:30]
_sec_stub_l0 = _l0_data[:50]

packets_security_short_xfer = [
    # F1/F2 ComPacket cut by the transfer
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=len(_sec_short_cp),
                                      cdw11=len(tcg_syncsession_cp)), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sec_short_cp), tag=0),
    # F3/F4 ComPacket Length that overruns the whole allocation
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=len(_sec_overrun_cp),
                                      cdw11=len(_sec_overrun_cp)), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sec_overrun_cp), tag=1),
    # F5/F6 Level 0 Discovery cut by the transfer
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x0001),
                                      dlen=len(_sec_short_l0),
                                      cdw11=len(_l0_data)), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sec_short_l0), tag=2),
    # F7/F8 ComPacket cut inside the Packet header
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x1000),
                                      dlen=len(_sec_stub_cp),
                                      cdw11=len(tcg_syncsession_cp)), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sec_stub_cp), tag=3),
    # F9/F10 Level 0 Discovery cut inside a feature descriptor header
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=security_cdw10(0x01, 0x0001),
                                      dlen=len(_sec_stub_l0),
                                      cdw11=len(_l0_data)), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_sec_stub_l0), tag=4),
]

BASE_TS_SECURITY_SHORT_XFER_US = 1709385800 * 1_000_000

def build_security_short_xfer_pcapng(output_path):
    write_pcapng(output_path, packets_security_short_xfer, BASE_TS_SECURITY_SHORT_XFER_US)


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F431-F450 - Physical Interface Receiver Eye Opening
# Measurement log page (LID 19h)
# ---------------------------------------------------------------------------
#
# LID 19h is defined by the NVMe over PCIe Transport Specification (Revision
# 1.4, section 3.9.1.1, Figures 71-76), not by NVMe Base -- Base's Get Log Page
# LID table just says "refer to the applicable NVM Express Transport
# specification".  Reachable out-of-band: libnvme exposes
# nvme_mi_admin_get_log_phy_rx_eom().
#
# Layout: an EOM Header of HSIZE bytes (Figure 75, which requires 64) followed
# by ND EOM Lane Descriptors (Figure 76) of DS bytes each, the first at HSIZE
# (Figure 74).  Both ND and DS live in the header,
# so the descriptor list can only be walked from a full offset-0 view.
#
# The descriptor stride is DS, NOT 32 + NROWS*NCOLS + EDLEN -- Figure 76's
# trailing Padding field absorbs the difference.  PAD is bounded, though: it
# takes the body "to a Dword boundary" and is "not present" once the structure
# is already aligned, so it is at most three bytes.  The fixture below carries 2
# bytes of PAD per descriptor (DS 72 around a 70-byte body), which still makes
# the stride differ from the body length, so a stride derived from the field
# sizes desynchronises and misreads descriptor 1.
#
#   F1/F2  EOMIP=2 (completed), 2 lane descriptors, Printable Eye + Eye Data
#   F3/F4  EOMIP=0 (no measurement started), header only, ND=0
#   F5/F6  same log page windowed at DOFST=64, so ND/DS are out of view and
#          the descriptor walk must be skipped
#   F7/F8  one internally inconsistent descriptor whose Printable Eye does not
#          fit in DS, so neither PE nor Eye Data may be rendered
#   F17/F18  a DS that over-declares by 8 bytes: PAD is still 2 bytes and the
#          remainder is undefined by Figure 76 (deliberate negative vector)
#   F19/F20  a conformant DS whose PAD is not cleared to 0h (deliberate
#          negative vector)
#   F21/F22  HSIZE 72: the descriptor list starts at HSIZE (deliberate
#          negative vector)
#   F23/F24  HSIZE 32, smaller than the header: no walk (deliberate negative
#          vector)
#
# Every field carries a distinct value so a shifted offset shows up as a wrong
# number rather than a plausible one.

EOM_NROWS = 4
EOM_NCOLS = 8
EOM_EDLEN = 6
EOM_DS = 72          # 32 + (4*8) + 6 = 70, to the next Dword boundary -> 2 PAD
EOM_ND = 2

NVME_LID_PHY_RX_EOM = 0x19

def eom_lane_desc(lane, eye, ds=None, pad=None):
    """One EOM Lane Descriptor (NVMe over PCIe Transport 1.4 Figure 76).

    ds and pad default to a conformant descriptor: DS is the 70-byte body taken
    to the next Dword boundary and PAD is that many zero bytes.  They are
    parameterised only for the two deliberate negative vectors (F18's
    over-declared DS, F20's PAD that is not cleared to 0h)."""
    if ds is None:
        ds = EOM_DS
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
    d += bytes(ds - len(d)) if pad is None else pad   # Padding
    assert len(d) == ds, len(d)
    return d

def eom_data(eomip=2, nd=EOM_ND, ndesc=None, odp=0x03, desc_fn=None, ds=None,
             hsize=64):
    """EOM log page: a 64-byte header (Figure 75) plus lane descriptors.

    nd is what the header's ND field (and RSZ) claim; ndesc is how many
    descriptors actually follow, defaulting to the claimed count.  They differ
    only for a prefix of a larger log, which holds fewer descriptors than ND
    counts.  odp/desc_fn let a caller build descriptors that omit the optional
    Printable Eye and Eye Data fields, which ODP is what advertises.  ds is the
    header's Descriptor Size field, defaulting to the conformant EOM_DS.  hsize
    is the Header Size field; above 64 the header is followed by hsize - 64
    bytes of 0xEE before the first descriptor (PCIe Transport 1.4 Figure 74
    starts the list at HSIZE), below 64 the descriptors still follow the
    64-byte header."""
    if ds is None:
        ds = EOM_DS
    h = struct.pack('<BB', NVME_LID_PHY_RX_EOM, eomip)  # LID, EOMIP
    h += struct.pack('<H', hsize)              # HSIZE (spec: shall be 64)
    h += struct.pack('<I', max(hsize, 64) + ds * nd)  # RSZ
    h += struct.pack('<BB', 0x07, 0x03)        # EDGN, LREV (spec: shall be 3h)
    h += struct.pack('<B', odp)                # ODP: PEFP and EDFP both set
    h += struct.pack('<BB', 0x04, 0x01)        # LNS = 4 lanes, EPL = 1 (NRZ)
    h += struct.pack('<B', 0x41)               # LSPFC: rsvd=0, LSPFV=41h
    h += struct.pack('<B', 0x05)               # LINFO: MLS = 5
    h += bytes(3)                              # Reserved 17:15
    h += struct.pack('<H', 0xBEEF)             # LSIC 19:18
    h += struct.pack('<I', ds)                 # DS 23:20
    h += struct.pack('<H', nd)                 # ND 25:24
    h += struct.pack('<HH', 16, 11)            # MAXTB, MAXLR
    h += struct.pack('<HHH', 11, 22, 33)       # ETGOOD, ETBETTER, ETBEST
    h += bytes(28)                             # Reserved 63:36
    assert len(h) == 64, len(h)
    h += b'\xEE' * (hsize - 64)
    if ndesc is None:
        ndesc = nd
    if desc_fn is None:
        desc_fn = eom_lane_desc
    return h + b''.join(desc_fn(lane=i, eye=i) for i in range(ndesc))

_eom_full = eom_data()

# An internally inconsistent lane descriptor: NROWS*NCOLS declares a 64-byte
# Printable Eye at descriptor offset 32, which needs 96 bytes, but DS is only
# 72.  PE therefore cannot be rendered, and because the Eye Data field is
# specified to start at (NROWS*NCOLS+32) its offset is undefined too, so ED
# must be suppressed as well rather than drawn at the PE offset.
EOM_BAD_NROWS = 8
EOM_BAD_NCOLS = 8

def eom_lane_desc_pe_over_ds(lane, eye):
    """A lane descriptor whose Printable Eye overflows DS (Figure 76)."""
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

def eom_lane_desc_no_pe_ed(lane, eye):
    """A lane descriptor that omits both optional fields (Figure 76).

    NROWS, NCOLS and EDLEN are 0h -- what a device reports with ODP's PEFP and
    EDFP clear -- so PE and ED are absent by declaration rather than by
    overflowing DS.  The 32-byte header is then the whole descriptor: it is
    already Dword aligned, so Figure 76's Padding field "is not present" and DS
    is 32 for the page that carries this descriptor."""
    d = struct.pack('<BBBB', 0x00, 0x01, lane, eye)  # rsvd, MSTAT(MSCS=1), LN, EYE
    d += struct.pack('<HHHH', 14, 16, 11, 9)         # TOP, BTM, LFT, RGT
    d += struct.pack('<HH', 0, 0)                    # NROWS, NCOLS: not provided
    d += struct.pack('<I', 0)                        # EDLEN: not provided
    d += bytes(12)                                   # Reserved 31:20
    assert len(d) == 32, len(d)
    return d

EOM_DS_OVER = 80     # over-declares the 70-byte body by 8 bytes past its PAD

def eom_lane_desc_over_ds(lane, eye):
    """A conformant body under a Descriptor Size that over-declares (Figure 76).

    PAD is still the two bytes that take the 70-byte body to a Dword boundary;
    the eight bytes DS leaves after it are defined by no row of Figure 76, so
    they contradict the descriptor's own NROWS/NCOLS/EDLEN.  They are 0xDE
    rather than 0h so a decoder that stretched Padding to DS renders a visibly
    wrong value rather than a longer run of plausible zeroes."""
    return eom_lane_desc(lane, eye, ds=EOM_DS_OVER,
                         pad=b'\x00\x00' + b'\xDE' * 8)

def eom_lane_desc_dirty_pad(lane, eye):
    """A conformant descriptor whose PAD is not cleared to 0h (Figure 76).

    Figure 76: "The controller shall pad with all bytes cleared to 0h to a Dword
    boundary."  The first pad byte is 0h and the second is not, so a check that
    only looks at the first byte of the field still passes it."""
    return eom_lane_desc(lane, eye, pad=b'\x00\xA5')

_eom_pe_over_ds = eom_data_pe_over_ds()

packets_admin_eom = [
    # F1/F2 completed measurement, 2 lane descriptors
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           (((len(_eom_full) // 4) - 1) << 16)),
                                      dlen=len(_eom_full)), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_eom_full), tag=0),
    # F3/F4 no measurement started: EOMIP 0h means the log page is just HSIZE
    # bytes (Figure 71) and ND is 0, so no descriptor may be rendered.  The
    # request asks for the whole 224-byte page a host that has read F1's ND
    # expects (NUMD 55, DLEN 224); the 64-byte answer is an under-delivery
    # (Base 2.3 Figure 201 returns the complete NUMD dwords, undefined past
    # the page's end; MI 2.2 Figure 139 owes DLEN of them) and carries the
    # short-response Note.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS * EOM_ND) // 4) - 1) << 16)),
                                      flags=0x03, doff=0,
                                      dlen=64 + EOM_DS * EOM_ND), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(eomip=0, nd=0)), tag=1),
    # F5/F6 windowed view starting at the first descriptor (DOFST=64): ND and
    # DS are not in view, so the descriptor list must NOT be walked
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           (((len(_eom_full) // 4) - 1) << 16)),
                                      flags=0x03, doff=64,
                                      dlen=EOM_DS), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_eom_full[64:64 + EOM_DS]), tag=2),
    # F7/F8 a descriptor whose Printable Eye overflows DS: PE needs
    # 32 + (8*8) = 96 bytes but DS is 72, so PE is unrenderable and the Eye
    # Data offset that follows it is undefined
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           (((len(_eom_pe_over_ds) // 4) - 1) << 16)),
                                      dlen=len(_eom_pe_over_ds)), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_eom_pe_over_ds), tag=3),
    # F9/F10 a *partial* first MI window of a complete log page: DOFST=0 but
    # DLEN covers only the 64-byte header plus one of the ND descriptors, while
    # NUMD asks for the whole page.  The descriptor walk stops at the window's
    # end; the rest is in the next window, and nothing is reported.
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
    # F11/F12 a fully delivered prefix of a larger log: ND counts EOM_ND + 1
    # descriptors and NUMD asks for the header plus EOM_ND of them.  A host
    # may read any prefix of a log page (Base 2.3 Figures 202/203), so the
    # walk stops at the data's end and nothing is reported, as for F10.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS * EOM_ND) // 4) - 1) << 16)),
                                      dlen=64 + EOM_DS * EOM_ND), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=EOM_ND + 1, ndesc=EOM_ND)),
                tag=5),
    # F13/F14 the complement of F7/F8: a descriptor that legitimately carries
    # neither optional field.  ODP reports PEFP and EDFP clear and
    # NROWS/NCOLS/EDLEN are 0h, so PE and ED are absent by declaration, not by
    # overflowing DS -- which must not be reported as a field overrun.  The
    # 32-byte header is then the whole descriptor and DS is 32: the structure is
    # already Dword aligned, so Figure 76's Padding field is not present.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + 32) // 4) - 1) << 16)),
                                      dlen=64 + 32), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=1, ds=32, odp=0x00,
                                              desc_fn=eom_lane_desc_no_pe_ed)),
                tag=6),
    # F15/F16 CDW10 = 0619h: LID 19h with LSP = 06h, so ACT is 1h (Start
    # Measurement and Read Log Data) and MQUAL is 2h (Best).  Every other
    # request here has LSP zero, where ACT and MQUAL read 0h under any mask
    # confined to LSP -- swapping or shifting the two masks would pass.  Only
    # distinct non-zero values in adjacent 2-bit slices pin the bit positions
    # (PCIe Transport 1.4 Figure 72: ACT is CDW10 11:10, MQUAL is 09:08).
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=((0x06 << 8) | NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS) // 4) - 1) << 16)),
                                      dlen=64 + EOM_DS),
                tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=1)), tag=7),
    # F17/F18 a deliberate negative vector: DS 80 around the same conformant
    # 70-byte body.  PAD is the two bytes that reach the Dword boundary; the
    # eight 0xDE bytes after it are defined by no row of Figure 76 and
    # contradict the descriptor's own NROWS/NCOLS/EDLEN.  NUMD and DLEN are
    # declared exactly, so neither the request nor the answer draws a window
    # diagnostic and this frame's only report is the descriptor-size one.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS_OVER) // 4) - 1) << 16)),
                                      dlen=64 + EOM_DS_OVER), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=1, ds=EOM_DS_OVER,
                                              desc_fn=eom_lane_desc_over_ds)),
                tag=8),
    # F19/F20 the second negative vector: a conformant DS whose PAD carries a
    # byte that is not 0h, which Figure 76 makes a shall violation.  Everything
    # else is F15/F16's shape, so the only difference in the tree is the note.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS) // 4) - 1) << 16)),
                                      dlen=64 + EOM_DS), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=1,
                                              desc_fn=eom_lane_desc_dirty_pad)),
                tag=9),
    # F21/F22 HSIZE 72, not the 64 Figure 75 requires: Figure 74 still puts
    # descriptor 0 at HSIZE, after eight 0xEE bytes, so a walk from a fixed
    # offset 64 reads LN and EYE as EEh.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((72 + EOM_DS) // 4) - 1) << 16)),
                                      dlen=72 + EOM_DS), tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=1, hsize=72)), tag=10),
    # F23/F24 HSIZE 32, smaller than the header's own fields: no descriptor
    # offset can be trusted, so the conformant descriptor at 64 is not walked.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001,
                                      cns=(NVME_LID_PHY_RX_EOM |
                                           ((((64 + EOM_DS) // 4) - 1) << 16)),
                                      dlen=64 + EOM_DS), tag=11),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(eom_data(nd=1, hsize=32)), tag=11),
]

BASE_TS_ADMIN_EOM_US = 1709462400 * 1_000_000

def build_admin_eom_pcapng(output_path):
    write_pcapng(output_path, packets_admin_eom, BASE_TS_ADMIN_EOM_US)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F41-F42 — TCG token-stream atom-class coverage
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
# Specification text was available to independently verify a *specific real*
# method name/UID for this
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
                                      dlen=len(tcg_atom_classes_cp),
                                      cdw11=len(tcg_atom_classes_cp))
                + tcg_atom_classes_cp, tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(b''), tag=0),
]

BASE_TS_TCG_ATOM_CLASSES_US = 1709381800 * 1_000_000

def build_tcg_atom_classes_pcapng(output_path):
    write_pcapng(output_path, packets_tcg_atom_classes, BASE_TS_TCG_ATOM_CLASSES_US)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F59-F70 — TCG token-stream error-path coverage
# ---------------------------------------------------------------------------
#
# Includes historical malformed cases reclassified by Core 3.2.3.1 and the
# open status domain. Incomplete token prefixes use distinct regular sessions
# so a later independent vector is not their continuation.
#   F1/F2  a reserved control token (0xF4, one of 0xF4-0xF7/0xFD-0xFE) mid-
#          stream -> ei_tcg_tok_reserved, then parsing continues
#   F3/F4  a Short Atom header claiming more data (10 bytes) than remains in
#          the subpacket (3 bytes) -> pending token fragment, no expert
#   F5/F6  a Long Atom lead byte with only 1 more byte following (needs a
#          4-byte header) -> pending token fragment, no expert
#   F7/F8  a method status list whose first element is 0x1234 -> unnamed
#          Method Status, no width expert; the ordinary list
#          element that follows must not be promoted to a Method Status
#   F9/F10 a Level 0 Discovery feature descriptor whose Length is 13, which
#          Core Spec §3.3.6.3.1.3 forbids ("SHALL be an integral multiple of
#          4") -> ei_tcg_feat_length_align.  The misalignment then cascades
#          into the descriptor that follows, which is the point: the cascade
#          has to be attributable to a named cause.
#   F11/F12 a successful SyncSession whose SPSessionID is 0010h.  Core Spec
#          §3.3.7.1.1: "the TSM SHALL NOT assign any TSN in the range 0 to
#          4095 to a regular session". The dissector does not diagnose it:
#          the tracker declines to start the session and no expert is added.
# Runtime validation belongs to the coordinated batch gate.

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
    # Incomplete atom: legal streaming prefix, with no captured continuation.
    + bytes([0x8A]) + bytes([0x01, 0x02, 0x03]))

tcg_truncated_header_tokens = (
    bytes([0xF8])
    + tcg_bytes_atom(TCG_SMUID)
    + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
    # Incomplete long header: legal streaming prefix, not a parent contradiction.
    + bytes([0xE0, 0x00]))

tcg_reserved_token_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_reserved_token_tokens)), 0x1000)
tcg_overrun_atom_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_overrun_atom_tokens), tsn=0x2001, hsn=2), 0x1000)
tcg_truncated_header_cp = tcg_compacket(
    tcg_packet(tcg_subpacket(tcg_truncated_header_tokens), tsn=0x2002, hsn=3), 0x1000)

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
    _tcg_malformed_l0_receive(_l0_badlen_data, tag=4) +         # F9/F10
    _tcg_malformed_receive(tcg_reserved_tsn_cp, tag=5)          # F11/F12
)

BASE_TS_TCG_MALFORMED_US = 1709382800 * 1_000_000

def build_tcg_malformed_pcapng(output_path):
    write_pcapng(output_path, packets_tcg_malformed, BASE_TS_TCG_MALFORMED_US)


# ---------------------------------------------------------------------------
# nvme-mi-security.pcapng F71-F98 — SIIS 1.20 Tables 23/24 selector rules:
# SECP 00h is not defined for IF-SEND and SECP 06h is not defined for NVMe,
# with or without data.  Receive 00h, 01h/02h and raw 03h-05h are controls.
# ---------------------------------------------------------------------------

def _security_selector_pair(send, secp, spsp, data, tag):
    request = admin_request_payload(
        NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV,
        ctrl_id=0x0001, flags=0x00, cns=security_cdw10(secp, spsp),
        dlen=len(data), cdw11=len(data))
    return [
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    request + (data if send else b''), tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(b'' if send else data), tag=tag),
    ]

_secp0_cert = struct.pack('>HH', 0, 4) + bytes.fromhex('30820000')

packets_security_selector = [
    pkt for i, args in enumerate((
        (True,  0x00, 0x0000, b'\xa5' * 16),    # F1/F2   Send 00h with data
        (True,  0x00, 0x0000, b''),             # F3/F4   Send 00h, TL 0
        (False, 0x00, 0x0000, _secp0_list + bytes(1)),  # F5/F6 supported list
        (False, 0x00, 0x0001, _secp0_cert),     # F7/F8   certificate
        (False, 0x00, 0x0002, _secp0_other),    # F9/F10  compliance, raw
        (True,  0x06, 0x1000, b'\xa5' * 16),    # F11/F12 Send 06h with data
        (True,  0x06, 0x1000, b''),             # F13/F14 Send 06h, TL 0
        (False, 0x06, 0x1000, b'\xa5' * 16),    # F15/F16 Receive 06h with data
        (False, 0x06, 0x1000, b''),             # F17/F18 Receive 06h, AL 0
        (True,  0x03, 0x1000, b'\xa5' * 16),    # F19/F20 Send 03h, raw
        (False, 0x04, 0x1000, b'\xa5' * 16),    # F21/F22 Receive 04h, raw
        (False, 0x05, 0x1000, b'\xa5' * 16),    # F23/F24 Receive 05h, raw
        (False, 0x01, 0x0001, _l0_data),        # F25/F26 Level 0 Discovery
        (True,  0x02, 0x1000, tcg_stack_reset_req)))  # F27/F28 STACK_RESET
    for pkt in _security_selector_pair(*args, tag=i % 8)
]

BASE_TS_SECURITY_SELECTOR_US = 1709386800 * 1_000_000

def build_security_selector_pcapng(output_path):
    write_pcapng(output_path, packets_security_selector, BASE_TS_SECURITY_SELECTOR_US)


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F259-F287 — response paths whose format depends on
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
#   The MIC spans the reported message length, so it cannot be computed over
#   a sliced frame; the command slot lifecycle must still run.  F3 must link
#   to F2, and F2 must raise the superseded-request note against F1.
#
#   --- MIC field itself cut off (MCTP tag 6, CSI 0) ---
#
#   F4  MI  Req   opcode 01h, IC=1, complete
#   F5  MI  Resp  status 00h, IC=1, SLICED by exactly the 4 MIC bytes.  Here
#                 the covered span *is* complete, but the MIC itself was never
#                 captured, so it must be reported as not present rather than
#                 claimed either way.
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
#   --- Admin Data window that no structured decoder renders (Figure 117
#       allows a 2-Wire MTU of 64 bytes, so a BMC walking the 4096-byte
#       Identify structure sends many such windows) ---
#
#   F12 ADM Req   Identify CNS=1Ch, DOFST=64, DLEN=64        [MCTP tag 4]
#   F13 ADM Resp  status 00h + 64 data bytes.  CNS 1Ch has no case in
#                 dissect_nvme_identify_resp(), so the "Data" subtree stays
#                 empty even though nvme_dissect_admin_data_resp() returns
#                 true (Identify *is* in the structured set).  The payload
#                 must remain visible in the detail tree.
#   F14 ADM Req   Identify CNS=01h, DOFST=0, DLEN=64         [MCTP tag 5]
#   F15 ADM Resp  status 00h + the first 64 bytes of an Identify Controller
#                 structure -- the control: the structured decode does render
#                 fields here, so the raw bytes item stays hidden.
#
#   --- Data Offset against the completion-data size (Figure 139 bounds DOFST
#       and DOFST + DLEN against the command's completion data, not against a
#       constant and not against the width of the field) ---
#
#   F16 ADM Req   Get Log Page LID=02h (SMART), LPO=4, DOFST=FFFFFFFCh,
#                 DLEN=8, NUMD=0.  The completion data is (NUMD + 1) * 4 = 4
#                 bytes, so DOFST is "greater than or equal to the size of
#                 the NVMe Admin Command completion data" and DOFST + DLEN
#                 exceeds it: two Invalid Parameter conditions, both named
#                 against the 4 bytes.  LPO+DOFST wraps to 0 in 32 bits, so
#                 it must not read as the *first* window of the page.
#                                                             [MCTP tag 7]
#   F17 ADM Resp  status 00h + 8 bytes that are the opening bytes of a SMART
#                 page.  Nothing of that page may be rendered: a Critical
#                 Warning item here means the offset aliased back to 0.
#
#   --- Admin Response Body format follows the Status field, not the opcode
#       (Figures 27/28 again -- the Admin counterpart of F6-F11 above) ---
#
#   F18 ADM Req   Identify CNS=01h, DOFST=0, DLEN=64          [MCTP tag 8]
#   F19 ADM Resp  status 04h (Invalid Parameter) carrying 32 payload bytes.
#                 Figure 31/32 gives an Invalid Parameter Error Response
#                 bytes 7:5 as the Parameter Error Location and defines
#                 nothing after them, so the trailing bytes are not a CQE and
#                 not NVMe Response Data.  They are shaped so that decoding
#                 them as the Figure 141 Success layout is visible: bytes 4:7
#                 read as CQE DW0 DEADBEEFh, 12:15 as a CQE DW3 whose status
#                 word is SCT=1 SC=0Eh DNR=1, and the 16 bytes after that as
#                 the head of an Identify Controller structure (VID 144Dh).
#                 The PEL points at message byte 28, the Data Offset field.
#
#   --- Data Length against the bytes the message actually carries (Figure 139
#       gives DLEN two meanings: the length of the NVMe Request Data field for
#       commands that transfer Request Data, and the size of the Response Data
#       window for commands that transfer Response Data) ---
#
#   F20 ADM Req   Set Features FID 7Dh (Enhanced Controller Metadata) with
#                 DLEN=64 but a 128-byte Host Metadata structure in the NVMe
#                 Request Data field.  DLEN is dword-aligned and well under
#                 4,096, so neither magnitude check sees it -- but the Request
#                 Data field is "larger than the size specified in the Data
#                 Length field", the specification's own example of a Request
#                 Message that is not well formed (Invalid Command Input Data
#                 Size).                                      [MCTP tag 1]
#   F21 ADM Resp  status 00h, no data -- ordinary for a Request Data command.
#   F22 ADM Req   Get Log Page LID=C0h (vendor specific, so no structured
#                 decoder adds items of its own), DOFST=0, DLEN=8.  The
#                 request itself is clean: this half must stay silent.
#                                                              [MCTP tag 3]
#   F23 ADM Resp  status 00h + 16 data bytes.  DLEN selected an 8-byte window
#                 of the completion data, so 8 bytes are what "shall be
#                 returned in the NVMe Response Data field"; the other 8 are
#                 data the Management Controller never asked for.
#
#   --- Windows past 2^32 that the completion data does hold (Base 2.3
#       Figure 201: NUMDL/NUMDU are one 32-bit 0's based dword count, so a
#       log page may run to 16 GiB; the DOFST field's width is not a bound) ---
#
#   F24 ADM Req   Get Log Page LID=07h (Telemetry Host-Initiated), NUMD=
#                 FFFFFFFFh, LPO=0, DOFST=FFFFFE00h, DLEN=400h: a window that
#                 straddles 2^32 by one 512-byte data block on each side.
#                 Every Figure 139 condition holds, so no expert.  [MCTP tag 2]
#   F25 ADM Resp  status 00h + the 1,024 bytes DLEN selected: Telemetry data
#                 blocks 8388607 and 8388608 (= 2^32 / 512).
#   F26 ADM Req   Security Send SECP=01h, TL=1000h, DOFST=FFFFF000h, DLEN=1000h
#                 with 4,096 request bytes.  DOFST + DLEN is exactly 2^32.  The
#                 only rule broken is the Security Send contract (DOFST must be
#                 0 on a Request Data command), which the dissector's Security
#                 check owns -- it must not be silenced by a bound that does
#                 not exist.                                    [MCTP tag 4]
#   F27 ADM Resp  status 04h (Invalid Parameter), PEL byte 28 (Data Offset).
#   F28 ADM Req   Security Receive SECP=01h, AL=2000h, DOFST=FFFFF000h,
#                 DLEN=1000h.  DOFST >= AL and DOFST + DLEN > AL: both Security
#                 Receive experts, on their own fields.         [MCTP tag 5]
#   F29 ADM Resp  status 04h (Invalid Parameter), PEL byte 28.

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

# The first eight bytes of a SMART / Health Information page, with values no
# other fixture uses: if the FFFFFFFCh Data Offset ever aliases back to 0 these
# are what surface as Critical Warning / Composite Temperature.
_ERR_SMART_HEAD = smart_data(cw=0x1F, ct=350, asc=42, ast=9, pu=77)[:8]

# Invalid Parameter Error Response (status 04h).  Bytes 3:1 are the Parameter
# Error Location -- BITLOC=0, BYTLOC=28, i.e. the Data Offset field of the
# request -- and the format defines nothing after them.  The 28 bytes that
# follow are shaped like the Success layout so that decoding them as one is
# visible in the tree rather than merely different.
_ERR_ADMIN_INVALID_PARAM = (
    bytes([0x04, 0x00]) + struct.pack('<H', 28)             # status + PEL
    + struct.pack('<I', 0xDEADBEEF)                         # "CQE DW0"
    + struct.pack('<I', 0x0BADF00D)                         # "CQE DW1"
    + struct.pack('<I', admin_cqe3(cqe_status_word(sct=1, sc=0x0E, dnr=1)))
    + identify_ctrl_data()[:16])                            # "Response Data"

# The same Invalid Parameter Error Response with nothing after the Parameter
# Error Location: BITLOC=0, BYTLOC=28, the request's Data Offset field.
_ERR_ADMIN_INVALID_PARAM_DOFST = bytes([0x04, 0x00]) + struct.pack('<H', 28)

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

    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE, ctrl_id=0x0001,
                                      cns=0x02, flags=0x00,
                                      doff=0xFFFFFFFC, dlen=8, lpo=4), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_ERR_SMART_HEAD), tag=7),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0002, cns=0x01,
                                      flags=0x00, doff=0, dlen=64), tag=8),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, _ERR_ADMIN_INVALID_PARAM, tag=8),

    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0003,
                                      cns=F_ENH_CTRL_METADATA, flags=0x00,
                                      doff=0, dlen=64, cdw11=(0x2 << 13)) +
                host_metadata_data([
                    host_metadata_descriptor(0x01, "nvme9"),
                ], total=128), tag=9),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=9),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE, ctrl_id=0x0001,
                                      cns=0xC0, flags=0x00, doff=0, dlen=8),
                tag=11),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes(range(0x40, 0x50))), tag=11),

    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE, ctrl_id=0x0001,
                                      cns=0x07 | (0xFFFF << 16), cdw11=0xFFFF,
                                      flags=0x00, doff=0xFFFFFE00, dlen=0x400),
                tag=10),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes([0x1B]) * 512 + bytes([0xE4]) * 512),
                tag=10),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_SEND, ctrl_id=0x0001,
                                      cns=0x01 << 24, cdw11=0x1000, flags=0x00,
                                      doff=0xFFFFF000, dlen=0x1000) + bytes(4096),
                tag=12),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, _ERR_ADMIN_INVALID_PARAM_DOFST, tag=12),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SECURITY_RECV, ctrl_id=0x0001,
                                      cns=0x01 << 24, cdw11=0x2000, flags=0x00,
                                      doff=0xFFFFF000, dlen=0x1000),
                tag=13),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, _ERR_ADMIN_INVALID_PARAM_DOFST, tag=13),
]

BASE_TS_ERROR_PATHS_US = 1709548800 * 1_000_000

def build_error_paths_pcapng(output_path):
    write_pcapng(output_path, packets_error_paths, BASE_TS_ERROR_PATHS_US)



# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F419-F458 — malformed Asynchronous Event lists
# ---------------------------------------------------------------------------
#
# The AE Enable List (Configuration Set 03h request data, NVMe-MI 2.2 Figures
# 91/92) and the AE Supported List (Configuration Get 04h response data,
# Figures 82/83) share one walker, which has several separate ways of calling
# a list self-contradictory.  Every other capture carries only well-formed
# lists, so each site gets one frame here — and both call sites are used, so a
# guard that exists on only one of them cannot hide.
#
#   F1/F2   Config Set, AE Enable List with AEELHL=3    -> header length < 5h
#   F3/F4   Config Set, AE Enable List NUMAEE=1 with 1  -> entries claimed but
#           byte after a 5-byte header                     no room for them
#   F5/F6   Config Get, AE Supported List AESTL=40 over -> declared total
#           11 bytes of data                               length overruns
#   F7/F8   Config Get, AE Supported List with AESL=1   -> entry length < 3h
#   F9/F10  Config Set, well-formed AE Enable List      -> control: silent
#   F11/F12 Config Get, well-formed AE Supported List   -> control: silent
#
# The two lists carry the *same* fields under opposite normative force, so the
# fixed values of Figure 82/83 ("shall" throughout) are checked on the AE
# Supported List and not on the AE Enable List, whose Figure 91/92 counterparts
# are only a "should" — AEELVER explicitly so: a Management Endpoint "shall
# not generate an error for any value in this field".  Each gets a pair:
# the Supported-list frame that must be flagged, and the Enable-list frame with
# the identical deviation that must stay silent.  Without the second half a
# check written on the shared walker rather than on the strict call site would
# pass just as well.
#
#   F13/F14 Config Set, AE Enable List NUMAEE=0        -> control: silent
#           (0h is the defined AEM Ack encoding)
#   F15/F16 Config Get, AE Supported List NUMAES=0     -> NUMAES shall be >= 1h
#   F17/F18 Config Set, AE Enable List AEELVER=1       -> control: silent
#   F19/F20 Config Get, AE Supported List AESLVER=1    -> AESLVER shall be 0h
#   F21/F22 Config Set, AE Enable List AEELHL=7        -> control: silent
#   F23/F24 Config Get, AE Supported List AESLHL=7     -> AESLHL shall be 5h
#   F25/F26 Config Set, AE Enable List AEEL=4          -> control: silent
#   F27/F28 Config Get, AE Supported List AESL=4       -> AESL shall be 3h
#   F29/F30 Config Set, AE Enable List NUMAEE=3 with   -> entries ran out
#           only 2 entries present                        part-way (an error)
#   F31/F32 Config Get, AE Supported List NUMAES=3     -> entries ran out
#           with only 2 entries present                   part-way (an error)
#
# Each malformed list is malformed in exactly one way -- the other conditions
# are kept satisfied so a test can attribute the expert message -- with one
# deliberate exception:
#
#   F33/F34 Config Set, AE Enable List AEELHL=3 *and*  -> one list check:
#           NUMAEE=1 with 2 bytes after the header        "0 of 1" entries
#
# F33 is the case where a short header leaves no room for the entries it
# declares.  The header clamp is silent on the Enable side, so the single
# after-walk check must still report the missing entry.
#
#   F35/F36 Config Set, AE Enable List AEETL=6         -> AEETL mismatch: a
#           with 8 bytes of list data                     Note, not malformed
#                                                         (Figure 91 "should")
#   F37/F38 Config Get, AE Supported List AESTL=6      -> AESTL shall be the
#           with 8 bytes of list data                     header plus the
#                                                         entries, exactly
#   F39/F40 Config Get, well-formed AE Supported List  -> AEELVER shall be 0h
#           but AEELVER=1h in the NVMe Management Response
#
# F39/F40 is the DELIBERATELY non-conformant frame for Figure 81's AEELVER, and
# has to stay that way: test_management_response_version_is_a_shall pins it.
# Every other Configuration Get response in this capture carries AEELVER 0h,
# so each frame stays malformed in exactly one way.
#
# Each accepted Set gets the AE Occurrence List 5.2.4 requires.  The endpoint
# supports AE 06h and 09h and starts with none enabled; only the Set pairs
# define its state, and the Get pairs are independent Supported List fixtures
# (F8 advertises 0Bh enabled).  The three Sets short of their declared entries
# (F3, F29, F33) are rejected with Figure 29 status 06h and change nothing.

NVME_MI_CFGID_AE_SET_CDW0 = 0x01050A04   # ENCFA/AEMD/AERD + CONFIGID=04h
NVME_MI_CFGID_AE_GET_CDW0 = 0x00000004   # CONFIGID=04h only (Figure 80)

# AEELHL=3, below the defined 5h.  AEETL matches the 8 bytes present and the
# single entry is well-formed, so only the header-length site may fire.
_ae_hdr_len_short = (bytes([1, 0]) + struct.pack('<H', 8) + bytes([3])
                     + bytes([3]) + struct.pack('<H', 0x8006))
# NUMAEE=1 but only 1 byte follows the 5-byte header; an entry needs 3.
_ae_no_room_for_entries = (bytes([1, 0]) + struct.pack('<H', 6) + bytes([5])
                           + bytes([0xFF]))
# AESTL=40 against 11 bytes of list data; header and entries are otherwise fine.
_aes_total_len_overrun = (bytes([2, 0]) + struct.pack('<H', 40) + bytes([5])
                          + bytes([3]) + struct.pack('<H', 0x8006)
                          + bytes([3]) + struct.pack('<H', 0x0009))
# AESL=1, below the defined 3h; the walker clamps to 3 to keep making progress.
_aes_entry_len_short = (bytes([1, 0]) + struct.pack('<H', 8) + bytes([5])
                        + bytes([1]) + struct.pack('<H', 0x800B))
# Controls: the same shapes as the nvme-mi-types.pcapng lists.
_ae_well_formed = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])
                   + bytes([3]) + struct.pack('<H', 0x8006)
                   + bytes([3]) + struct.pack('<H', 0x0009))
_aes_well_formed = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])
                    + bytes([3]) + struct.pack('<H', 0x8006)
                    + bytes([3]) + struct.pack('<H', 0x000B))

# The fixed-value pairs.  Each Enable/Supported pair carries byte-for-byte the
# same deviation, differing only in which of the two lists it travels in.
# NUMAEE=0h is legal and meaningful (it is what makes a Configuration Set an
# AEM Ack); NUMAES=0h means the device claims to support no AE at all, so no
# AEM can ever arrive — the interop bug this capture most wants surfaced.
_ae_num_zero = bytes([0, 0]) + struct.pack('<H', 5) + bytes([5])
_aes_num_zero = bytes([0, 0]) + struct.pack('<H', 5) + bytes([5])
# Version 1h: AEELVER may hold any value, AESLVER shall be cleared to 0h.
_ae_ver_nonzero = (bytes([1, 1]) + struct.pack('<H', 8) + bytes([5])
                   + bytes([3]) + struct.pack('<H', 0x8006))
_aes_ver_nonzero = (bytes([1, 1]) + struct.pack('<H', 8) + bytes([5])
                    + bytes([3]) + struct.pack('<H', 0x8006))
# Header length 7h, i.e. two bytes of padding before the body.  Above the
# defined 5h rather than below it, so no clamp is involved and the walk still
# lands on the entry — what separates "shall be set to 5h" from "at least 5".
_ae_hdr_len_long = (bytes([1, 0]) + struct.pack('<H', 10) + bytes([7])
                    + bytes([0, 0])
                    + bytes([3]) + struct.pack('<H', 0x8006))
_aes_hdr_len_long = (bytes([1, 0]) + struct.pack('<H', 10) + bytes([7])
                     + bytes([0, 0])
                     + bytes([3]) + struct.pack('<H', 0x8006))
# Entry length 4h: one trailing byte inside the entry.  Again above the defined
# 3h, so the walk advances by the declared length and stays consistent.
_ae_entry_len_long = (bytes([1, 0]) + struct.pack('<H', 9) + bytes([5])
                      + bytes([4]) + struct.pack('<H', 0x8006) + bytes([0]))
_aes_entry_len_long = (bytes([1, 0]) + struct.pack('<H', 9) + bytes([5])
                       + bytes([4]) + struct.pack('<H', 0x8006) + bytes([0]))
# Three entries declared, two present.  The total length matches the data that
# is actually there, so only the count is contradicted — the walk renders two
# entries and has to say that it stopped short of the three it was promised.
_ae_entry_shortfall = (bytes([3, 0]) + struct.pack('<H', 11) + bytes([5])
                       + bytes([3]) + struct.pack('<H', 0x8006)
                       + bytes([3]) + struct.pack('<H', 0x0009))
_aes_entry_shortfall = (bytes([3, 0]) + struct.pack('<H', 11) + bytes([5])
                        + bytes([3]) + struct.pack('<H', 0x8006)
                        + bytes([3]) + struct.pack('<H', 0x000B))
# AEELHL=3 and one entry declared with only 2 bytes after the clamped 5-byte
# header: the one list here that trips two checks at once.  AEETL matches the
# data present so the total-length check stays out of it, and no entry can be
# rendered, so the in-loop shortfall check stays out of it too -- leaving
# exactly the two messages whose independence is in question.
_ae_short_header_no_room = (bytes([1, 0]) + struct.pack('<H', 7) + bytes([3])
                            + bytes([0, 0]))
# Total length 6h against a 5-byte header and one 3-byte entry, i.e. 8 bytes.
# Under-declared rather than over-declared, so it fits inside the data present
# and the "declares more than the bytes present" check stays out of it: this is
# the pair that separates "the total length fits" from "the total length is
# exact", which is all Figure 82's sentence and 5.1.4's "shall be minimally
# sized" are asking for.
_ae_total_len_short = (bytes([1, 0]) + struct.pack('<H', 6) + bytes([5])
                       + bytes([3]) + struct.pack('<H', 0x8006))
_aes_total_len_short = (bytes([1, 0]) + struct.pack('<H', 6) + bytes([5])
                        + bytes([3]) + struct.pack('<H', 0x8006))

# F1 enables 06h and nothing disables it, so every AE Sync answers with 06h's
# current state and leaves the endpoint AE Armed; the lone AEM Ack (F13) is
# processed in the Armed State, so its list has no occurrence.
_ae_sync_occurrences = aeo_list([
    aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM, specific=bytes([0x1E]))])  # 30 C
_ae_ack_occurrences = aeo_list([])

def _ae_set_pair(ae_list, response=None):
    """Configuration Set (CONFIGID 04h) carrying an AE Enable List, + response.

    `response` is the AE Occurrence List of a Success response; None answers
    with status 06h, Invalid Command Input Data Size (Figure 29).
    """
    if response is None:
        payload = mi_response_payload(0x06)
    else:
        payload = mi_response_payload_with_data(STATUS_SUCCESS, response)
    return [make_packet(True,  NVME_MI_TYPE_MI, 0,
                        mi_request_payload(0x03, cdw0=NVME_MI_CFGID_AE_SET_CDW0)
                        + ae_list),
            make_packet(False, NVME_MI_TYPE_MI, 0, payload)]

def _ae_get_pair(aes_list, aeelver=0):
    """Configuration Get (CONFIGID 04h) whose response carries an AE Supported List.

    `aeelver` is the NVMe Management Response byte of Figure 81, which the
    Management Endpoint "shall" clear to 0h -- a different field from the
    AEELVER inside an AE Enable List, which Figure 91 states as a "should".
    It defaults to the conformant 0h so that each frame stays malformed in
    exactly one way; F39/F40 is the one pair that names a deviation here.
    """
    return [make_packet(True,  NVME_MI_TYPE_MI, 0,
                        mi_request_payload(0x04, cdw0=NVME_MI_CFGID_AE_GET_CDW0)),
            make_packet(False, NVME_MI_TYPE_MI, 0,
                        mi_response_payload_with_data(STATUS_SUCCESS,
                                                      aes_list,
                                                      nmresp=aeelver))]

packets_ae_list_malformed = (_ae_set_pair(_ae_hdr_len_short, _ae_sync_occurrences)
                             + _ae_set_pair(_ae_no_room_for_entries)
                             + _ae_get_pair(_aes_total_len_overrun)
                             + _ae_get_pair(_aes_entry_len_short)
                             + _ae_set_pair(_ae_well_formed, _ae_sync_occurrences)
                             + _ae_get_pair(_aes_well_formed)
                             + _ae_set_pair(_ae_num_zero, _ae_ack_occurrences)
                             + _ae_get_pair(_aes_num_zero)
                             + _ae_set_pair(_ae_ver_nonzero, _ae_sync_occurrences)
                             + _ae_get_pair(_aes_ver_nonzero)
                             + _ae_set_pair(_ae_hdr_len_long, _ae_sync_occurrences)
                             + _ae_get_pair(_aes_hdr_len_long)
                             + _ae_set_pair(_ae_entry_len_long, _ae_sync_occurrences)
                             + _ae_get_pair(_aes_entry_len_long)
                             + _ae_set_pair(_ae_entry_shortfall)
                             + _ae_get_pair(_aes_entry_shortfall)
                             + _ae_set_pair(_ae_short_header_no_room)
                             + _ae_set_pair(_ae_total_len_short, _ae_sync_occurrences)
                             + _ae_get_pair(_aes_total_len_short)
                             + _ae_get_pair(_aes_well_formed, aeelver=1))

BASE_TS_AE_LIST_MALFORMED_US = 1709385800 * 1_000_000

def build_ae_list_malformed_pcapng(output_path):
    write_pcapng(output_path, packets_ae_list_malformed, BASE_TS_AE_LIST_MALFORMED_US)


# ---------------------------------------------------------------------------
# nvme-mi-types.pcapng F125-F148 - header-bit and slot-bookkeeping rules
# ---------------------------------------------------------------------------
#
# Five rules the framing layer enforces that no other fixture reaches, each
# with the negative control that separates it from the blanket check it would
# be tempting to write instead.  Every rule here is decided by a *combination*
# of header fields (opcode + CSI, NMIMT + ROR, opcode + slot state), so a
# check on any single field passes the positive case and fails the control.
#
# Each MCTP tag is a separate Wireshark conversation (the tag bits become the
# port numbers), so a tag per group keeps the Command Slot and Control
# Primitive bookkeeping of one group out of the next one's way.
#
#   --- CSI in a Control Primitive request (NVMe-MI 2.1 4.2.1.1/4.2.1.2:
#       "The CSI bit in a [Pause|Resume] Control Primitive is not used and
#       should be cleared to 0") ---
#
#   F1  CP  Req  CSI=1 Pause     (00h) TAG=11h  [tag 0]
#   F2  CP  Req  CSI=1 Resume    (01h) TAG=12h  [tag 0]
#   F3  CP  Req  CSI=1 Abort     (02h) TAG=13h  [tag 0]  -> silent: 4.2.1.3
#                defines Abort against "the specified Command Slot" and
#                Figure 37 gives the body no slot field, so CSI is the only
#                thing naming the slot and a set bit is conformant.
#   F4  CP  Req  CSI=1 Get State (03h) TAG=14h  [tag 0]  -> silent (4.2.1.4
#                returns the per-slot SSTA field)
#   F5  CP  Req  CSI=1 Replay    (04h) TAG=15h  [tag 0]  -> silent (4.2.1.5)
#
#   F1-F5 share one MCTP tag and none of them is answered, so they are also
#   five successive displacements of the Control Primitive pairing slot: per
#   4.2.1 a Management Controller "may issue a Control Primitive ... without
#   waiting for a response for previously issued Control Primitives", so not
#   one of them may raise the superseded-request note.
#
#   --- The same bit on the two paths where it is legal ---
#
#   F6  CP  Req  CSI=0 Pause     (00h) TAG=21h  [tag 1]  -> silent (the
#                conformant way to send a Pause)
#   F7  CP  Req  CSI=0 Pause     (00h) TAG=22h  [tag 1]  -> silent; displaces
#                F6's unanswered primitive, which is 4.2.1's blessed sequence
#                and must not raise the superseded-request note either
#   F8  CP  Resp CSI=1 Success   TAG=22h        [tag 1]  -> silent.  The
#                recovered opcode is Pause, so a check placed before the
#                request/response split would fire here -- but a Response
#                Message's CSI "shall indicate the Command Slot associated
#                with the Request Message", the opposite rule.
#
#   --- Control Primitives pair by TAG, not by CSI ---
#
#   F9  CP  Req  CSI=1 Get State (03h) TAG=31h  [tag 2]
#   F10 CP  Resp CSI=0 Success   TAG=31h CPSR=4001h [tag 2] -> must pair with
#                F9 and must not be called an orphan response.  TAG is the
#                only field 4.2.1 obliges the endpoint to echo ("shall copy
#                the value of the Tag field"; Figures 37 and 40); nothing
#                says that of CSI.  Get State is used because CSI=1 is
#                conformant there, so the pairing assertion is not muddied by
#                the note F1/F2 raise.
#
#   --- CIAP and MEB are prohibited outside a Command Message, and 1.8.14
#       makes a Command Message "a Request Message that contains an NVMe
#       Admin Command, PCIe Command, or NVMe-MI Command" -- both halves ---
#
#   F11 CP  Req  Get State, CIAP=1     TAG=41h  [tag 3]  -> ciap_prohibited
#   F12 CP  Req  Get State, MEB=1      TAG=42h  [tag 3]  -> meb_prohibited
#   F13 AEM (NMIMT 5h), CIAP=1                  [tag 3]  -> ciap_prohibited.
#                An AEM owns no Command Slot, so it passes through the
#                bookkeeping untouched and can share the tag.  Its
#                Asynchronous Event Data is a well-formed one-occurrence AE
#                Occurrence List so that the CIAP bit is the only thing this
#                frame reports; a stub body would add a truncation expert of
#                its own.
#   F14 CP  Req  Get State, CIAP=1 MEB=1 TAG=43h [tag 3] -> both fire (one
#                expert field per bit: the Invalid Parameter Error Response
#                the endpoint returns names which bit in its PEL)
#   F15 MI  Req  01h (NVM Subsystem Health Status Poll)  [tag 4]  -> silent
#   F16 MI  Resp Success, MEB=1                          [tag 4]  ->
#                meb_prohibited.  This is the frame a check on NMIMT alone
#                misses: the NMIMT is 1h, one of the three command sets, but
#                a Response Message is not a Request Message and so not a
#                Command Message.  4.2.3 agrees for MEB specifically -- the
#                buffer routing is keyed on the bit "set to '1' in a Command
#                Message", i.e. on the request's copy.
#   F17 MI  Req  01h, CIAP=1 MEB=1                       [tag 5]  -> silent:
#                the control.  A Command Message may set either bit, so a
#                check on ROR alone would fire here.
#   F18 MI  Resp Success                                 [tag 5]  -> silent
#
#   --- A displaced Reset is owed no response (5.8: "No Success Response is
#       transmitted"), so it is not an ambiguous supersede ---
#
#   F19 MI  Req  07h (Reset), NMD0=0 so RSTTYP=00h       [tag 6]  -> never
#                answered, by design
#   F20 MI  Req  01h                                     [tag 6]  -> carries
#                the generated nvme-mi.prev_no_response pointing at F19, and
#                must NOT raise the superseded-request note
#   F21 MI  Resp Success                                 [tag 6]  -> pairs
#                with F20, so the displacement really did hand the slot over
#
#   F22 ADM Req  06h (Identify, CNS=01h), Command Flags 00h [tag 7] -> never
#                answered: the control, an ordinary Command Message.  The
#                obsolete DOFSTV/DLENV flag bits are cleared so the frame
#                raises nothing of its own.
#   F23 MI  Req  01h                                     [tag 7]  -> raises
#                the superseded-request note and carries no
#                nvme-mi.prev_no_response
#   F24 MI  Resp Success                                 [tag 7]  -> pairs
#                with F23

packets_framing_conformance = [
    # F1-F5: CSI=1 across every Control Primitive opcode, on one tag.
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_PAUSE,     tag=0x11), tag=0),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_RESUME,    tag=0x12), tag=0),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_ABORT,     tag=0x13), tag=0),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x14), tag=0),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_REPLAY,    tag=0x15), tag=0),

    # F6-F8: the conformant CSI=0 Pause, a second one displacing it, and a
    # response whose own CSI is set.
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_PAUSE, tag=0x21), tag=1),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_PAUSE, tag=0x22), tag=1),
    make_packet(False, NVME_MI_TYPE_CONTROL, 1,
                cp_response_payload(STATUS_SUCCESS, tag=0x22), tag=1),

    # F9-F10: CSI=1 request answered with CSI=0 -- pairing is by tag.
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x31), tag=2),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                cp_response_payload(STATUS_SUCCESS, tag=0x31, cpsr=0x4001),
                tag=2),

    # F11-F14: CIAP/MEB outside a Command Message.
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x41), tag=3,
                ciap=True),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x42), tag=3,
                meb=True),
    aem_packet(aeo_list([aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM,
                                   specific=bytes([0x4B]))]),
               tag=3, ciap=True),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_GET_STATE, tag=0x43), tag=3,
                ciap=True, meb=True),

    # F15-F16: an ordinary MI exchange whose *response* sets MEB.
    make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=4),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=4, meb=True),

    # F17-F18: the control -- a Command Message may set both bits.
    make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=5,
                ciap=True, meb=True),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=5),

    # F19-F21: a Reset displaced by the next command on the same slot.
    make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x07), tag=6),
    make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=6),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=6),

    # F22-F24: the control -- an ordinary unanswered command, displaced.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01,
                                      flags=0x00, doff=0, dlen=0), tag=7),
    make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=7),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=7),
]

BASE_TS_FRAMING_CONFORMANCE_US = 1709640000 * 1_000_000

def build_framing_conformance_pcapng(output_path):
    write_pcapng(output_path, packets_framing_conformance, BASE_TS_FRAMING_CONFORMANCE_US)

# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F459-F481 - Asynchronous Event Message body decode
# ---------------------------------------------------------------------------
#
# An AEM (NMIMT 5h) is the only NVMe-MI message that is neither a Request nor a
# Response, and its body is an AE Occurrence List data structure (Figure 60,
# and 4.4.4: "The AE Occurrence List data structure shall start at offset 0h of
# the Asynchronous Event Data field").  The same structure travels as the
# Response Data of a Configuration Set of the Asynchronous Event configuration
# -- the Response Message to an AEM Ack or an AE Sync (5.2.4) -- and one field
# is defined *only* against that second path:
#
#   Figure 61, AEM Transmission Info (AEMTI, byte 6, holding the AEM Generation
#   Number and the AEM Retry Count): "For the AE Occurrence List data structure
#   in the Response Message to an AEM Ack or an AE Sync, this field is not
#   applicable and shall be cleared to 0h."
#
#   Figure 61, AEM Retry Count: "For an AEM, this field shall indicate the
#   number of times the AEM has been retried."
#
# So the fixed-value check applies to the Configuration Set response and must
# not apply to the AEM.  The capture pins that polarity from both sides: the
# identical AEMTI byte is carried once on each path, and exactly one of the two
# frames may be flagged.  Getting the sense backwards flips both assertions, so
# neither frame alone would catch it.
#
#   F1  AEM       AEMGN=3, AEMRC=2; two AE Occurrences   [tag 0] -> decoded,
#                 and silent: the retry count is what an AEM is for
#   F2  MI  Req   Configuration Set 03h, CONFIGID 04h,   [tag 1]
#                 AE Enable List with NUMAEE=0, which is what makes this
#                 Configuration Set an AEM Ack (5.2.4)
#   F3  MI  Resp  Success + an AE Occurrence List whose  [tag 1] -> flagged:
#                 AEMTI byte is F1's, 1Ah                          AEMTI shall
#                                                                  be 0h here
#   F4  MI  Req   the same AEM Ack again                 [tag 2]
#   F5  MI  Resp  Success + the same list with AEMTI     [tag 2] -> silent:
#                 cleared to 0h                                    the control
#   F6  AEM       AE Occurrence List Overflow set, so    [tag 0] -> silent
#                 the header travels without a body (4.4.4), with AEOLTL and
#                 NUMAEO cleared to 0h as Figure 61 requires
#   F7  AEM       4-byte Asynchronous Event Data, below  [tag 0] -> truncated
#                 the 7-byte AE Occurrence List Header
#
# The rest of the capture is the fixed values of Figures 61 and 62 that carry
# NO such qualifier, and therefore bind both call sites.  AEMTI is the one
# field whose sentence names a path; taking that as the pattern and making the
# others path-dependent too would silently stop checking every real AEM.
#
#   F8  AEM       AELVER=1                              [tag 0] -> flagged:
#                 "This field shall be cleared to 0h" (Figure 61), stated with
#                 no mention of either call site
#   F9  MI  Req   an AEM Ack                            [tag 3]
#   F10 MI  Resp  the same AELVER=1 list                [tag 3] -> flagged:
#                 the other half of the pair.  F8 and F10 together are what
#                 says AELVER is unqualified, exactly as F1/F3 say AEMTI is not
#   F11 AEM       AEOLTL=16 against a 27-byte list      [tag 0] -> flagged:
#                 under-declared, so it fits in the data present and only an
#                 exact check catches it (Figure 61, and 4.4.4's "shall be
#                 minimally sized")
#   F12 AEM       vendor specific AE C0h with AEOSIL=1  [tag 0] -> flagged:
#                 "If this AE is vendor specific (i.e., the AE Identifier is
#                 in the range C0h to FFh), then this field shall be cleared
#                 to 0h" (Figure 62)
#   F13 AEM       vendor specific AE C1h, AEOSIL=0 and  [tag 0] -> silent:
#                 a 2-byte AE Occurrence Vendor Specific Info -- the control.
#                 F12's check has to key on AEOSIL, not on "a vendor AE with a
#                 payload"; the vendor payload has a field of its own, with a
#                 UUID index naming whose definition to read it by
#
# The last pair is the entry walk running out of body part-way, and the one
# frame that must not be reported twice for it.
#
#   F14 AEM       NUMAEO=3 over F1's two occurrences    [tag 0] -> flagged
#                 once: the walk renders two and stops, and NUMAEO "shall
#                 indicate the number of AE Occurrence data structures ... in
#                 the AE Occurrence List Body" (Figure 61).  The list is
#                 otherwise F1's, so the count is the only deviation, and
#                 AEOLTL still matches what was sent -- the exactness check is
#                 gated on the walk having reached NUMAEO, so it cannot cover
#                 this.
#   F15 AEM       NUMAEO=1 with no list body at all     [tag 0] -> flagged
#                 once, by the "claimed but only N bytes follow the header"
#                 pre-check.  The walk breaks on its first iteration here, so
#                 this is the frame a part-way diagnostic without an i > 0
#                 gate would report a second time on the same field.
#
# The two occurrences in F1/F3/F5 are Figure 63 events with the scope Figure 63
# assigns them and the AE Occurrence Specific Info Figure 65 defines: Composite
# Temperature (06h, NVM Subsystem scope, a 1-byte Composite Temperature Value)
# and Controller Fatal Status (01h, Controller scope, Controller ID 1, a 1-byte
# Controller Fatal Status Value).
#
# The last six frames are the per-occurrence and per-message fixed values of
# Figures 63 and 64 and section 4.4.4, one violation and its control each:
#
#   F16 AEM       PCIe Link Active (0Bh), Port scope,  [tag 0] -> flagged:
#                 AEOPT=0 (NVM Subsystem port 1).  Figure 63, row 0Bh: "The AE
#                 Occurrence Port Type bit for this AE shall be set '1'"
#   F17 AEM       the same with AEOPT=1 (NVMe-MI port 1) [tag 0] -> silent
#   F18 AEM       Composite Temperature (06h) with       [tag 0] -> flagged:
#                 Controller scope, Controller 1.  Figure 63 scopes 06h as NVM
#                 Subsystem and Figure 62 has AESS "shall indicate the scope
#                 of the AE"
#   F19 AEM       F1's body with the MCTP Tag Owner bit  [tag 0] -> flagged:
#                 cleared.  4.4.4 (a): "the Tag Owner bit shall be set to '1'
#                 since the AEM originates from the Management Endpoint"
#   F20 AEM       five occurrences, one per Figure 64    [tag 0] -> flagged
#                 layout that has Reserved bits, each with them set: 00h
#                 Controller 31:16, C2h Management Endpoint 31:8, 0Bh Port
#                 31:17 (AEOPT=1, port 1), C3h Endurance Group 31:16, 06h NVM
#                 Subsystem 31:0.  1.9.6: "shall be cleared to 0h".  Only a
#                 vendor specific AE can carry the Management Endpoint and
#                 Endurance Group scopes, which Figure 63 assigns to no AE
#   F21 AEM       the same five with the Reserved bits   [tag 0] -> silent:
#                 clear -- the control, and the corpus's only Management
#                 Endpoint (2Ah) and Endurance Group (7) scope decode
#
# Finally the other variation of 5.2.4's Configuration Set.  Every Asynchronous
# Event Configuration Set above is an AEM Ack (NUMAEE=0h); this pair is the AE
# Sync, which the Info column has to be able to tell apart from them:
#
#   F22 MI  Req   Configuration Set CID 04h with NUMAEE=2 [tag 4] -> an AE Sync
#   F23 MI  Resp  its AE Occurrence List, AEMTI 0h        [tag 4] -> silent

# CONFIGID 04h alone: the AE Sync-only fields of Figure 90 (ENCFA, AEM Delay,
# AEM Retry Delay) are "not applicable and shall be ignored for an AEM Ack".
NVME_MI_CFGID_AE_ACK_CDW0 = 0x00000004
# AE Enable List with NUMAEE=0 (Figures 91/92): the encoding that makes a
# Configuration Set an AEM Ack rather than an AE Sync.
_aem_ack_enable_list = bytes([0, 0]) + struct.pack('<H', 5) + bytes([5])

_aem_occurrences = [
    aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM, specific=bytes([0x4B])),
    aeo_entry(0x01, AEO_SCOPE_CONTROLLER, scope_id=0x0001,
              specific=bytes([0x01])),
]

def _aem_ack_pair(aeo, tag):
    """An AEM Ack Configuration Set and the Response Message carrying `aeo`."""
    return [make_packet(True,  NVME_MI_TYPE_MI, 0,
                        mi_request_payload(0x03,
                                           cdw0=NVME_MI_CFGID_AE_ACK_CDW0)
                        + _aem_ack_enable_list, tag=tag),
            make_packet(False, NVME_MI_TYPE_MI, 0,
                        mi_response_payload_with_data(STATUS_SUCCESS, aeo),
                        tag=tag)]

# AE Enable List with NUMAEE=2 (Figures 91/92): the encoding that makes the same
# Configuration Set an AE Sync instead.  NUMAEE=2, AEETL=11, AEELHL=5, then two
# AE Enable data structures -- the shape the events-config fixture's inline list
# carries.
_aem_sync_enable_list = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])
                         + bytes([3]) + struct.pack('<H', 0x8006)
                         + bytes([3]) + struct.pack('<H', 0x0009))

def _aem_sync_pair(aeo, tag):
    """An AE Sync Configuration Set and the Response Message carrying `aeo`.

    CDW0 0105_0A04h is the AE-Sync field set of Figure 90 (ENCFA set, AEM Delay
    5 s, AEM Retry Delay 10 x 100 ms, CID 04h) -- the same value the
    events-config and comprehensive fixtures already use, so nothing new is
    exercised on the request dword.  The response carries an AE Occurrence List
    whose AEMTI is 0h, which Figure 61 requires on a Configuration Set response.
    """
    return [make_packet(True,  NVME_MI_TYPE_MI, 0,
                        mi_request_payload(0x03, cdw0=0x01050A04)
                        + _aem_sync_enable_list, tag=tag),
            make_packet(False, NVME_MI_TYPE_MI, 0,
                        mi_response_payload_with_data(STATUS_SUCCESS, aeo),
                        tag=tag)]

# AELVER=1h.  The AE Occurrence List is otherwise exactly F1's, so the version
# byte is the only thing either frame carrying it can be flagged for.
_aem_bad_version = aeo_list(_aem_occurrences, aelver=1)

# AEOLTL=16 against a list that is 7 + 10 + 10 = 27 bytes.
_aem_total_len_short = aeo_list(_aem_occurrences, total_len=16)

# A vendor specific AE (Figure 63 reserves C0h to FFh for them) that declares
# AE Occurrence Specific Info anyway, and the control that declares none.
_aem_vendor_with_specific = aeo_list([
    aeo_entry(0xC0, AEO_SCOPE_SUBSYSTEM, specific=bytes([0x11]))])
_aem_vendor_conformant = aeo_list([
    aeo_entry(0xC1, AEO_SCOPE_SUBSYSTEM, vendor=bytes([0x00, 0xAB]))])

# NUMAEO=3 over the two occurrences F1 carries: the body runs out after the
# second, part-way through the count.  Everything else -- AEOLTL, AEOLHL, both
# occurrences -- is F1's, so only the count is wrong.
_aem_count_over_body = aeo_list(_aem_occurrences, numaeo=3)

# NUMAEO=1 with an empty body, i.e. not even one occurrence header follows the
# list header.  The walk stops on its first iteration, which is the case the
# "claimed but only N bytes follow" pre-check already speaks for.
_aem_count_no_body = aeo_list([], numaeo=1)

_aem_link_active_nvm_port = aeo_list([
    aeo_entry(0x0B, AEO_SCOPE_PORT, scope_id=0x00000001, specific=bytes([0x01]))])
_aem_link_active_mi_port = aeo_list([
    aeo_entry(0x0B, AEO_SCOPE_PORT, scope_id=0x00010001, specific=bytes([0x01]))])
_aem_temperature_controller_scope = aeo_list([
    aeo_entry(0x06, AEO_SCOPE_CONTROLLER, scope_id=0x0001, specific=bytes([0x4B]))])

# Figure 64's Reserved bits, set and clear.  The identifiers are the low
# bits the layout keeps (Controller 1, Management Endpoint 2Ah, NVMe-MI port
# 1, Endurance Group 7); NVM Subsystem scope has no identifier at all.
def _aem_scope_reserved_bits(reserved):
    return aeo_list([
        aeo_entry(0x00, AEO_SCOPE_CONTROLLER,
                  scope_id=(0xFFFF0000 if reserved else 0) | 0x0001,
                  specific=bytes([0x01])),
        aeo_entry(0xC2, AEO_SCOPE_MGMT_EP,
                  scope_id=(0x0000FF00 if reserved else 0) | 0x2A),
        aeo_entry(0x0B, AEO_SCOPE_PORT,
                  scope_id=(0x80000000 if reserved else 0) | 0x00010001,
                  specific=bytes([0x01])),
        aeo_entry(0xC3, AEO_SCOPE_ENDURANCE_GRP,
                  scope_id=(0x00010000 if reserved else 0) | 0x0007),
        aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM,
                  scope_id=0x11223344 if reserved else 0,
                  specific=bytes([0x4B])),
    ])

packets_aem = (
    [aem_packet(aeo_list(_aem_occurrences, aemgn=3, aemrc=2))]
    + _aem_ack_pair(aeo_list(_aem_occurrences, aemgn=3, aemrc=2), tag=1)
    + _aem_ack_pair(aeo_list(_aem_occurrences), tag=2)
    + [aem_packet(aeo_list([], overflow=True, aemgn=4)),
       aem_packet(b'\x00\x01\x02\x03'),
       aem_packet(_aem_bad_version)]
    + _aem_ack_pair(_aem_bad_version, tag=3)
    + [aem_packet(_aem_total_len_short),
       aem_packet(_aem_vendor_with_specific),
       aem_packet(_aem_vendor_conformant),
       aem_packet(_aem_count_over_body),
       aem_packet(_aem_count_no_body),
       aem_packet(_aem_link_active_nvm_port),
       aem_packet(_aem_link_active_mi_port),
       aem_packet(_aem_temperature_controller_scope),
       aem_packet(aeo_list(_aem_occurrences), to=False),
       aem_packet(_aem_scope_reserved_bits(True)),
       aem_packet(_aem_scope_reserved_bits(False))]
    + _aem_sync_pair(aeo_list(_aem_occurrences), tag=4)
)

BASE_TS_AEM_US = 1709726400 * 1_000_000

def build_aem_pcapng(output_path):
    write_pcapng(output_path, packets_aem, BASE_TS_AEM_US)


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F374-F415 - fields whose wire value is not the number
# ---------------------------------------------------------------------------
#
# Four fields in packet-nvme.c that an analyst reads straight off the tree and
# gets wrong, because the wire value carries a scale, a sentinel or a bit split
# that the raw number does not show.  Every one is reachable over NVMe-MI.
#
#   F1  Sanitize (84h), SANACT=011b (Overwrite) with OWPASS=3 -- an ordinary
#       pass count, the control for F2.
#   F2  Sanitize (84h), SANACT=011b (Overwrite) with OWPASS=0.  NVMe Base 2.3
#       Figure 388 (Sanitize - Command Dword 10), bits 07:04: "A value of 0h
#       specifies 16 overwrite passes."  0h is the largest pass count, not the
#       smallest.  (nvme-mi-admin-identify.pcapng F38 also carries OWPASS=0, but
#       with SANACT=010b Block Erase; here Overwrite is actually selected, so
#       the annotation is about a field the controller uses.)
#   F3/F4  SMART / Health Information (LID 02h) with Data Units Read and Data
#       Units Written both large.  NVMe Base 2.3 Figure 210, bytes 47:32 and
#       63:48: each counts 512-byte data units "reported in thousands ... and
#       is rounded up", so the byte total is value * 1000 * 512 = value *
#       512,000, and it is an upper bound.  The values land on exact binary
#       magnitudes so the rendered text is stable:
#           DUR = 2^31 -> 2^31 * 512,000 = 1000.00 TiB exactly
#           DUW = 2^32 -> 2^32 * 512,000 =    1.95 PiB (1.953125, i.e. 2000 TiB)
#   F5/F6  Error Information (LID 01h) with a non-zero Status Info word.  NVMe
#       Base 2.3 Figure 209, bytes 13:12: bit 0 is the Phase Tag and bits 15:1
#       are the Status field (refer to Figure 100).  STS = 0303h: Phase Tag is
#       1 and Status is 181h under the correct split, but 0 and 303h if split
#       at the wrong end of the word, so neither field can pass by accident.
#   F7/F8  Sanitize Status (LID 81h) with SPROG = FFFFh and SSTAT reporting
#       Sanitize Operation Status = 001b (completed successfully).  NVMe Base
#       2.3 Figure 302, bytes 01:00: SPROG "is the numerator of the fraction
#       complete that has 65,536 (10000h) as its denominator" and "shall be set
#       to FFFFh if the Sanitize Operation Status (SOS) field is set to a value
#       other than 010b (i.e., Sanitizing)".  Read as a numerator, FFFFh is
#       99.998% -- all but done -- when it in fact means nothing is running.
#   F9/F10 The same log page with SPROG = 4000h and SOS = 010b (Sanitizing): a
#       genuine numerator, exactly 25% of 65,536, so the percentage path is
#       covered alongside the sentinel.
#   F11/F12 Set Features (09h) FID=08h Interrupt Coalescing with Command Dword
#       11 = 0000C81Fh.  NVMe Base 2.3 Figure 474 (section 5.2.26.2.2) splits that
#       dword 31:16 Reserved / 15:08 Aggregation Time (TIME) / 07:00
#       Aggregation Threshold (THR), so THR is 1Fh and TIME is C8h; masks on
#       the two 16-bit halves would read C81Fh and 0.
#       THR is also "a 0's based value" per the same figure, so 1Fh is 32
#       completion queue entries, not 31.
#   F13/F14 Get Features (0Ah) for the same FID.  Section 5.2.26.2.2: "If a Get
#       Features command is submitted for this Feature, the attributes
#       specified in Figure 474 are returned in Dword 0 of the completion queue
#       entry for that command."  DW0 = 00002A07h, deliberately different from
#       F11's Dword 11, so one group's registration cannot be mistaken for the
#       other's.
#   F15/F16 Identify Controller (CNS 01h) windowed to structure offset 532,
#       4 bytes, with ACWU = 7.  NVM Command Set 1.2 Figure 117 (section
#       4.1.5.2), bytes 533:532: ACWU "is specified in logical blocks and is a
#       0's based value" -- the same sentence AWUN and AWUPF carry -- so 7 is
#       8 logical blocks, not 4 KiB units.
#   F17/F18 The same window with ACWU = 0.  The same row ends "If Compare and
#       Write is not a supported fused command, then this field shall be 0h",
#       which the 0's based rule renders as one logical block; the two meanings
#       are indistinguishable from the field alone, so the item says so.
#
#   F19..F38 Identify Controller (CNS 01h) windows over the group-mask fields of
#       NVMe Base 2.3 Figure 328 whose defined bits sit next to Reserved runs,
#       plus the three bits whose rendered meaning is not the bit.  Each
#       window is the smallest byte range the dissector's offset gating will
#       decode, so the response payload stays a handful of bytes.
#
#       Every fixture uses an alternating bit pattern rather than all-ones:
#       adjacent flags differ, so a mask that is one bit wide too many or is
#       shifted by one cannot pass.  Where the frame is marked "reserved bits
#       set", the Reserved runs deliberately carry a non-zero pattern -- not
#       conformant traffic (section 1.4 has reserved fields cleared), but the
#       only way to observe a Reserved run's *extent* rather than just its
#       presence.  For OAES that is the whole point: its reserved bits are not
#       contiguous (18, 26:22, 30:28) and need three separate runs, so a single
#       run of the right total width would still be wrong.
#
#       F19/F20 offset 256, 8 bytes: OACS (257:256), FRMW (260), LPA (261),
#               covering OACS bits 11 (HMLMS) and 10 (CFLS), FRMW bit 5 (SMUD)
#               and LPA bits 6 (DA4S) and 5 (MLPS); LPA's group parent is
#               FT_UINT8, not "True"/"False".  Reserved bits set.
#       F21/F22 offset 92, 8 bytes: OAES (95:92) and CTRATT (99:96), with
#               CTRATT bit 18 (RHII) set.  Reserved bits set.
#       F23/F24 The same window with every named bit inverted, RHII cleared and
#               every Reserved run cleared -- the control that keeps F22 from
#               passing on a stuck bit, and the second RHII state.
#       F25/F26 offset 318, 1 byte: DSTO bit 1 (HIRS).  Reserved bits set.
#       F27/F28 offset 328, 4 bytes: SANICAP bits 4 (NVERS) and 3 (VERS).
#               Reserved bits set.
#       F29/F30 offset 520, 6 bytes: ONCS (521:520) bits 12:8 and FNA (524)
#               bit 3 (FNVMBS).  FNVMBS is set
#               here, which per Figure 328 means the broadcast NSID is *not*
#               supported, so FNS and SENS are cleared as that row requires.
#       F31/F32 The same window with FNVMBS cleared and FNS, SENS and CRYES set.
#       F33/F34 offset 534, 6 bytes: CDFS (535:534) and SGLS (539:536) bits
#               15:08 (SDT).  SDT is 5Ah -- a value, not eight flags.
#               Reserved bits set.
#       F35/F36 offset 1792, 256 bytes: FCATT (1802) bit 0 (DCMS) set.  Figure
#               328 has set mean the *static* controller model, the opposite of
#               what the bit's name reads as.
#       F37/F38 The same window with DCMS cleared (the dynamic model).
#
#   F39/F40 SMART (LID 02h), the response-side counterpart: NVMe Base 2.3
#       Figure 210 puts OLEC at 239:232 and IPM at 243:240, and only then
#       Reserved at 511:244.  IPM is itself a bit-split dword (IPMV 15:00,
#       IPMS 17:16, PMT 23:20) whose power in Watts is IPMV times the IPMS
#       scale, so the raw dword is not the number either.
#   F41/F42 Sanitize Status (LID 81h) with SPROG = 4000h and SOS = 001b
#       (Sanitized): the numerator F9/F10 carries legitimately, reported while
#       nothing is in progress.  Figure 302 has SPROG "set to FFFFh if the
#       Sanitize Operation Status (SOS) field is set to a value other than
#       010b", so this page contradicts itself and is flagged; F7/F8 and F9/F10
#       are the two conformant shapes and stay silent.

# Sanitize Command Dword 10 (NVMe Base 2.3 Figure 388): SANACT in bits 02:00,
# AUSE bit 03, OWPASS bits 07:04, OIPBP bit 08.
SANITIZE_SANACT_OVERWRITE = 0x3
_sanitize_cdw10_owpass3 = SANITIZE_SANACT_OVERWRITE | (3 << 4)
_sanitize_cdw10_owpass0 = SANITIZE_SANACT_OVERWRITE | (0 << 4) | (1 << 8)

# NVMe Base 2.3 Figure 210 bytes 47:32 / 63:48 -- see the block comment above.
_ENCODING_DUR = 2 ** 31
_ENCODING_DUW = 2 ** 32

# NVMe Base 2.3 Figure 209 bytes 13:12: Phase Tag '1' in bit 0, and a Status of
# 181h (Status Code 81h, Status Code Type 1h) in bits 15:1.
_ENCODING_STS = (1 << 0) | (0x181 << 1)
assert _ENCODING_STS == 0x0303

# NVMe Base 2.3 Figure 210 bytes 239:232 (OLEC) and 243:240 (IPM).  OLEC needs
# all eight bytes distinct and set above bit 31, so a 4-byte-wide or shifted
# read reports a different number.  IPM sets IPMV 15:00 = 1F40h (8,000),
# IPMS 17:16 = 10b (0.01 W, i.e. 80 W), PMT 23:20 = 0h (NVM subsystem total
# power) and both Reserved runs -- 19:18 and 31:24 -- non-zero, so a PMT or
# IPMS mask that is one bit too wide reads a Reserved bit instead of 0h.
_ENCODING_OLEC = 0x1122334455667788
_ENCODING_IPM = (0xA5 << 24) | (0x0 << 20) | (0x1 << 18) | (0x2 << 16) | 0x1F40
assert _ENCODING_IPM == 0xA5061F40

def sanitize_status_data(sprog, sos):
    """Sanitize Status log page (NVMe Base 2.3 Figure 302) header: SPROG at
    bytes 01:00 and SSTAT at 03:02, whose bits 02:00 are the Sanitize Operation
    Status.  64 bytes, so the trailing Reserved field (struct offset 48 onward)
    still renders."""
    return struct.pack('<HH', sprog, sos) + bytes(60)

NVME_AQ_OPC_IDENTIFY = 0x06
NVME_AQ_OPC_SANITIZE = 0x84
LID_SANITIZE_STATUS = 0x81

# NVMe Base 2.3 Figure 474 -- see the block comment above.  THR and TIME are
# different from each other and from the (TIME << 8) | THR the old THR mask
# produced, in both the Set Features request and the Get Features completion.
FID_IRQ_COALESCING = 0x08
_ENCODING_IRQC_CDW11 = (0xC8 << 8) | 0x1F
_ENCODING_IRQC_DW0 = (0x2A << 8) | 0x07
assert _ENCODING_IRQC_CDW11 == 0x0000C81F
assert _ENCODING_IRQC_DW0 == 0x00002A07

# NVM Command Set 1.2 Figure 117 bytes 533:532 (ACWU) and 535:534 (Reserved).
# A 4-byte window at structure offset 532 covers exactly those two fields, so
# the Identify Controller response stays 4 bytes rather than 4096.
ID_CTRL_ACWU_OFF = 532

def identify_ctrl_acwu_window(acwu):
    return struct.pack('<HH', acwu, 0)

# --- NVMe Base 2.3 Figure 328 group-mask windows (F19..F38) -----------------
#
# Values are assembled from bit numbers so each one reads as the figure's own
# bit list, and every assembled value is asserted against the literal it must
# produce.  The patterns alternate rather than being all-ones so that a mask
# one bit too wide, or shifted by one, changes what a neighbouring field reads.

def _bits(*set_bits):
    v = 0
    for b in set_bits:
        v |= 1 << b
    return v

# OACS 257:256 -- SSRS, FWDS, DSTS, NSRS, DBCS, CFLS, HMLMS set; bits 12 and 14
# of the (15:12) Reserved run set.  GLSS (bit 9) is clear: it and the Reserved
# run were registered under "oacs.sec", the bit 0 boolean's abbrev.
_FIG328_OACS  = _bits(0, 2, 4, 6, 8, 10, 11, 12, 14)
# FRMW 260 -- FFSRO=1, NOFS=101b, FAWR=0, SMUD=1, Reserved (7:6) = 10b
_FIG328_FRMW  = _bits(0, 1, 3, 5, 7)
# LPA 261 -- SMARTS, LPEDS, PES, MLPS set; CSES, TS, DA4S clear; Reserved (7)=1
_FIG328_LPA   = _bits(0, 2, 4, 5, 7)
assert (_FIG328_OACS, _FIG328_FRMW, _FIG328_LPA) == (0x5d55, 0xab, 0xb5)

# OAES 95:92 -- NSAN, PLEAN, EGEAN, NNSS, RGCNS, ANSAN, CCRCN, ZDCN, DLPCN set;
# FAN, ANACN, LSIAN, TTHR, LHCN clear; and all three Reserved runs non-zero:
# 7:0 = A5h, bit 10, bit 18, 26:22 = 10101b, 30:28 = 101b.
_FIG328_OAES = _bits(0, 2, 5, 7,
                     8, 10, 12, 14, 15, 17, 18, 19, 20,
                     22, 24, 26, 27, 28, 30, 31)
# CTRATT 99:96 -- MDS, VCM, DEG, ELBAS, MEM, RHII, PLS, PMS set; FCM, DNVMS,
# HMBR, FDPS clear; Reserved (31:22) = 0101010101b.
_FIG328_CTRATT = _bits(1, 3, 5, 7, 9,
                       10, 12, 13, 15, 16, 18, 20, 21,
                       22, 24, 26, 28, 30)
assert (_FIG328_OAES, _FIG328_CTRATT) == (0xdd5ed5a5, 0x5575b6aa)

# The control frame: every named bit inverted, every Reserved run cleared.
_FIG328_OAES_INV   = _bits(9, 11, 13, 16, 21)
_FIG328_CTRATT_INV = _bits(0, 2, 4, 6, 8, 11, 14, 17, 19)
assert (_FIG328_OAES_INV, _FIG328_CTRATT_INV) == (0x00212a00, 0x000a4955)

# DSTO 318 -- SDSO=0, HIRS=1, Reserved (7:2) = 101010b
_FIG328_DSTO = _bits(1, 3, 5, 7)
# SANICAP 331:328 -- CES, OWS, VERS set; BES, NVERS clear; NDI=1,
# NODMMAS=01b; Reserved (28:5) non-zero at its low, middle and top bits.
_FIG328_SANICAP = _bits(0, 2, 3, 5, 10, 28, 29, 30)
assert (_FIG328_DSTO, _FIG328_SANICAP) == (0xaa, 0x7000042d)

# ONCS 521:520 -- NVMCMPS, NVMDSMSV, SSFS, TSS, NVMCPYS, NVMAFC, MAXWZD, NSZS
# set; NVMWUSV, NVMWZSV, RESERVS, NVMVFYS, NVMCSA clear; Reserved (15:13)=101b
_FIG328_ONCS = _bits(0, 2, 4, 6, 8, 10, 11, 12, 13, 15)
# FNA 524 -- FNVMBS set, which Figure 328 has *deny* the broadcast NSID, and
# requires FNS and SENS cleared.  Then the same window with FNVMBS cleared.
_FIG328_FNA_BCAST_DENIED  = _bits(3)
_FIG328_FNA_BCAST_ALLOWED = _bits(0, 1, 2)
assert (_FIG328_ONCS, _FIG328_FNA_BCAST_DENIED,
        _FIG328_FNA_BCAST_ALLOWED) == (0xbd55, 0x08, 0x07)

# CDFS 535:534 -- CDF0S, CDF2S, CDF3S set; CDF1S, CDF4S clear; Reserved (15:5)
# non-zero at its bottom, middle and top.
_FIG328_CDFS = _bits(0, 2, 3, 5, 7, 15)
# SGLS 539:536 -- SGLS=10b, KSDBDS=1, Reserved (7:3)=10101b, SDT=5Ah, SBBDS,
# LLDTS, SAOS, TSDBDS set, MBA and MSDS clear, Reserved (31:22) non-zero.
_FIG328_SGLS = (0x2 | _bits(2) | (0x15 << 3) | (0x5A << 8)
                | _bits(16, 18, 20, 21) | _bits(22, 24, 31))
assert (_FIG328_CDFS, _FIG328_SGLS) == (0x80ad, 0x81755aae)

ID_CTRL_OACS_OFF    = 256
ID_CTRL_OAES_OFF    = 92
ID_CTRL_DSTO_OFF    = 318
ID_CTRL_SANICAP_OFF = 328
ID_CTRL_ONCS_OFF    = 520
ID_CTRL_CDFS_OFF    = 534
ID_CTRL_NVMEOF_OFF  = 1792

def identify_ctrl_oacs_window(oacs, frmw, lpa):
    """Bytes 263:256: OACS, ACL, AERL, FRMW, LPA, ELPE, NPSS."""
    return struct.pack('<HBBBBBB', oacs, 0x03, 0x03, frmw, lpa, 0x3f, 0x1f)

def identify_ctrl_oaes_window(oaes, ctratt):
    """Bytes 99:92: OAES then CTRATT."""
    return struct.pack('<II', oaes, ctratt)

def identify_ctrl_oncs_window(oncs, fna):
    """Bytes 525:520: ONCS, FUSES, FNA, VWC."""
    return struct.pack('<HHBB', oncs, 0, fna, 0)

def identify_ctrl_cdfs_window(cdfs, sgls):
    """Bytes 539:534: CDFS then SGLS."""
    return struct.pack('<HI', cdfs, sgls)

def identify_ctrl_nvmeof_window(fcatt):
    """Bytes 2047:1792, the NVMe over Fabrics section: IOCCSZ, IORCSZ, ICDOFF,
    FCATT, MSDBD, OFCS, DCTYPE, CCRL and a 240-byte Reserved tail.  The whole
    256 bytes are sent: the block was once decodable only whole, and these
    frames keep that exact-fit shape."""
    return (struct.pack('<IIHBBHBB', 0x00000104, 0x00000010, 0,
                        fcatt, 0x10, 0x0001, 0x02, 0x00) + bytes(240))

packets_field_encoding = [
    # F1 Sanitize (84h): Overwrite with an ordinary OWPASS of 3
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SANITIZE, ctrl_id=0x0001,
                                      cns=_sanitize_cdw10_owpass3,
                                      cdw11=0xA5A5A5A5), tag=0),
    # F2 Sanitize (84h): Overwrite with OWPASS=0, i.e. 16 passes
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SANITIZE, ctrl_id=0x0002,
                                      cns=_sanitize_cdw10_owpass0,
                                      cdw11=0x5A5A5A5A), tag=1),
    # F3/F4 SMART (LID 02h) with large Data Units Read / Written
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0003, flags=0x03, cns=0x02,
                                      doff=0, dlen=512), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data(dur=_ENCODING_DUR,
                                                duw=_ENCODING_DUW)), tag=2),
    # F5/F6 Error Information (LID 01h) with a non-zero Status Info word
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0004, flags=0x03, cns=0x01,
                                      doff=0, dlen=128), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(error_info_data(sts=_ENCODING_STS)), tag=3),
    # F7/F8 Sanitize Status (LID 81h), SPROG = FFFFh sentinel, SOS = 001b
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0005, flags=0x03,
                                      cns=LID_SANITIZE_STATUS,
                                      doff=0, dlen=64), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(sanitize_status_data(0xFFFF, 0x1)), tag=4),
    # F9/F10 Sanitize Status (LID 81h), SPROG = 4000h (25%), SOS = 010b
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0006, flags=0x03,
                                      cns=LID_SANITIZE_STATUS,
                                      doff=0, dlen=64), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(sanitize_status_data(0x4000, 0x2)), tag=5),
    # F11/F12 Set Features (09h) FID=08h Interrupt Coalescing, THR=1Fh TIME=C8h.
    # The completion carries no per-FID result for this Feature, so its DW0 is
    # the plain dword; the pair exists to close the command slot.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES, ctrl_id=0x0007,
                                      cns=FID_IRQ_COALESCING,
                                      cdw11=_ENCODING_IRQC_CDW11), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=6),
    # F13/F14 Get Features (0Ah) for the same FID; DW0 mirrors Figure 474
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES, ctrl_id=0x0008,
                                      cns=FID_IRQ_COALESCING), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS,
                                       cqe1=_ENCODING_IRQC_DW0,
                                       cqe3=admin_cqe3(cqe_status_word(phase=1))), tag=7),
    # F15/F16 Identify Controller (CNS 01h) windowed to ACWU, ACWU = 7.  The
    # MCTP message tag is 3 bits wide and all eight are already in use, so
    # these two pairs reuse tags 2 and 3.  Both were answered above, which
    # leaves their command slot empty -- reusing tag 0 or 1 instead would
    # supersede F1/F2, whose Sanitize requests are deliberately unanswered.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0009,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_ACWU_OFF, dlen=4), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_acwu_window(7)), tag=2),
    # F17/F18 The same window with ACWU = 0 -- one logical block, or Compare
    # and Write is not supported at all
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x000A,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_ACWU_OFF, dlen=4), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_acwu_window(0)), tag=3),
    # F19/F20 Identify Controller windowed to bytes 263:256 -- OACS, FRMW, LPA
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x000B,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_OACS_OFF, dlen=8), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_oacs_window(
                    _FIG328_OACS, _FIG328_FRMW, _FIG328_LPA)), tag=4),
    # F21/F22 bytes 99:92 -- OAES and CTRATT, RHII set, Reserved runs non-zero
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x000C,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_OAES_OFF, dlen=8), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_oaes_window(
                    _FIG328_OAES, _FIG328_CTRATT)), tag=5),
    # F23/F24 the same window inverted: every named bit flipped, RHII cleared
    # and every Reserved run cleared
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x000D,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_OAES_OFF, dlen=8), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_oaes_window(
                    _FIG328_OAES_INV, _FIG328_CTRATT_INV)), tag=6),
    # F25/F26 byte 318 -- DSTO, HIRS set
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x000E,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_DSTO_OFF, dlen=1), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(bytes([_FIG328_DSTO])), tag=7),
    # F27/F28 bytes 331:328 -- SANICAP, VERS set and NVERS clear
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x000F,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_SANICAP_OFF, dlen=4), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(struct.pack('<I', _FIG328_SANICAP)), tag=2),
    # F29/F30 bytes 525:520 -- ONCS and FNA, with FNVMBS set (broadcast denied)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0010,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_ONCS_OFF, dlen=6), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_oncs_window(
                    _FIG328_ONCS, _FIG328_FNA_BCAST_DENIED)), tag=3),
    # F31/F32 the same window with FNVMBS cleared (broadcast allowed)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0011,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_ONCS_OFF, dlen=6), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_oncs_window(
                    _FIG328_ONCS, _FIG328_FNA_BCAST_ALLOWED)), tag=4),
    # F33/F34 bytes 539:534 -- CDFS and SGLS, SDT = 5Ah
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0012,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_CDFS_OFF, dlen=6), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_cdfs_window(
                    _FIG328_CDFS, _FIG328_SGLS)), tag=5),
    # F35/F36 bytes 2047:1792 -- FCATT 01h: DCMS set (static controller model),
    # NZNSETIDS clear
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0013,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_NVMEOF_OFF, dlen=256), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_nvmeof_window(0x01)), tag=6),
    # F37/F38 the same window with FCATT 02h: DCMS clear (dynamic model)
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0014,
                                      cns=0x01, flags=0x03,
                                      doff=ID_CTRL_NVMEOF_OFF, dlen=256), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(identify_ctrl_nvmeof_window(0x02)), tag=7),
    # F39/F40 SMART (LID 02h) with OLEC and IPM non-zero (Reserved starts at
    # byte 244); every other SMART fixture leaves them zero.
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0015, flags=0x03, cns=0x02,
                                      doff=0, dlen=512), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(smart_data(olec=_ENCODING_OLEC,
                                                ipm=_ENCODING_IPM)), tag=2),
    # F41/F42 Sanitize Status (LID 81h), SPROG = 4000h with SOS = 001b: a
    # progress numerator while nothing is sanitizing
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0016, flags=0x03,
                                      cns=LID_SANITIZE_STATUS,
                                      doff=0, dlen=64), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(sanitize_status_data(0x4000, 0x1)), tag=4),
]

BASE_TS_FIELD_ENCODING_US = 1709812800 * 1_000_000

def build_field_encoding_pcapng(output_path):
    write_pcapng(output_path, packets_field_encoding, BASE_TS_FIELD_ENCODING_US)


# ===========================================================================
# Sliced context, MIC integrity and the multi-interface shapes
# ===========================================================================
#
#   nvme-mi-sliced-context.pcapng        a snaplen-sliced request
#   nvme-mi-types.pcapng F179-F202       MIC integrity and vendor status
#   nvme-mi-transactions.pcapng F1-F178  Command Slot lifecycle
#   nvme-mi-mi-commands.pcapng F75-F204  invalid Reset and inline MEB
#
# Never put two slot-lifecycle experiments on the same CSI + tag, and put
# every malformed frame *after* a positive twin.

# ---------------------------------------------------------------------------
# nvme-mi-sliced-context.pcapng - a snaplen-sliced request publishes no
# request context
# ---------------------------------------------------------------------------
#
# A request whose *reported* length reaches the fixed-body minimum but whose
# *captured* bytes stop short must not publish a body context, or the
# selectors the response layout depends on would read back as zero.  Zero is a
# valid selector in both cases:
#
#   Identify (Admin 06h) with a zeroed CDW10 is CNS 00h, Identify Namespace
#   Read NVMe-MI Data Structure (MI 00h) with a zeroed NMD0 is DTYP 00h,
#   NVM Subsystem Information
#
# so the response would be decoded against selectors that were never on the
# wire.  Configuration Get is the control: a zeroed CONFIGID
# is CID 00h, which is already labelled Reserved, so that path degrades
# gracefully and must keep doing so.
#
#   F1/F2 full-length Identify exchange                      positive twin
#   F3    Identify request, reports 92 bytes, captures 26
#   F4    its well-formed response, 32 bytes of Response Data
#   F5    Read DS OPC 00h request sliced before the DTYP byte
#   F6    its response, 32 bytes of Response Data
#   F7    Configuration Get OPC 04h request sliced the same way   control
#   F8    its response

_SLICED_ID_CTRL   = identify_ctrl_data()[:64]
_SLICED_RESP_DATA = bytes(range(32))

def _sliced(pkt, caplen):
    """(bytes, reported length) for a frame the capture cut at `caplen`."""
    return (pkt[:caplen], len(pkt))

_SLICED_ADMIN_REQ = make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                                admin_request_payload(0x06, ctrl_id=0x000A,
                                                      cns=0x01, flags=0x01,
                                                      doff=0, dlen=64), tag=6)
_SLICED_MI_RDS_REQ = make_packet(True, NVME_MI_TYPE_MI, 0,
                                 mi_request_payload(0x00, cdw0=0x03000000),
                                 tag=1)
_SLICED_MI_CFG_REQ = make_packet(True, NVME_MI_TYPE_MI, 0,
                                 mi_request_payload(0x04, cdw0=0x00000002),
                                 tag=2)

packets_sliced_context = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x000A, cns=0x01,
                                      flags=0x01, doff=0, dlen=64), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_SLICED_ID_CTRL), tag=5),

    # SLL(16) + MCTP(4) + NVMe-MI header(4) + the opcode and flags bytes.
    _sliced(_SLICED_ADMIN_REQ, 26),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_SLICED_RESP_DATA), tag=6),

    # Cut one byte into the MI command body, i.e. before NMD0 at offset 4.
    _sliced(_SLICED_MI_RDS_REQ, 25),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload_with_data(STATUS_SUCCESS,
                                              _SLICED_RESP_DATA), tag=1),

    _sliced(_SLICED_MI_CFG_REQ, 25),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=2),

    # F9-F12  the zero-captured boundary.
    #
    # Reading the opcode byte is itself a read, and a frame cut at the NVMe-MI
    # header captures none of the body.  Byte 0 must not be read there -- an
    # invented opcode 00h is Delete I/O Submission Queue on the Admin side and
    # Read NVMe-MI Data Structure on the MI side, and the latter's zeroed DTYP
    # is NVM Subsystem Information, so the fabrication the sliced frames above
    # produce two bytes later would reappear at zero.
    #
    # 24 captured bytes is SLL(16) + MCTP(4) + the four-byte NVMe-MI header,
    # so the framing layer has everything and the body has nothing.
    #
    #   F9   Admin request, header only, reports a 64-byte SQE
    #   F10  its response, well formed
    #   F11  MI Read NVMe-MI Data Structure request, header only
    #   F12  its response, well formed
    _sliced(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                        admin_request_payload(0x06, ctrl_id=0x000B, cns=0x01,
                                              flags=0x01, doff=0, dlen=64),
                        tag=3), 24),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_SLICED_RESP_DATA), tag=3),

    _sliced(make_packet(True, NVME_MI_TYPE_MI, 0,
                        mi_request_payload(0x00, cdw0=0x00000000), tag=4), 24),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload_with_data(STATUS_SUCCESS,
                                              _SLICED_RESP_DATA), tag=4),

    # F13/F14  A request that reports the 64-byte Submission Queue Entry
    # *plus* 32 bytes of NVMe Request Data, captured to the last byte of the
    # entry.  One byte short of complete, so it still publishes nothing -- and the truncation message has to measure against the 64-byte
    # entry rather than the 96-byte body, or it describes a Submission Queue
    # Entry of a size no such thing has.
    _sliced(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                        admin_request_payload(0x09, ctrl_id=0x000C, cns=0x00,
                                              flags=0x01, doff=0, dlen=32)
                        + _SLICED_RESP_DATA, tag=7), 24 + 63),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=7),

    # F15-F24  a body shorter than its fixed fields, cut right after its first
    # byte.  The truncation path renders what follows byte 0 as raw data, and
    # the capture ends exactly there.  A raw item that runs to the end of the
    # data needs at least one captured byte, so the frame must degrade to the
    # truncation expert alone, with no raw data and no exception.  25 captured
    # bytes is SLL(16) + MCTP(4) + the NVMe-MI header(4) + byte 0.
    #
    #   F15  MI Configuration Get request, reports a 5-byte body (OPC + 4),
    #        captures OPC only
    #   F16  its response, well formed
    #   F17  MI Configuration Get request, well formed
    #   F18  its response, reports a 3-byte body (STATUS + 2), captures STATUS
    #   F19  Admin request, reports a 5-byte body, captures the opcode only
    #   F20  its response, well formed
    #   F21  Admin request, well formed
    #   F22  its response, reports a 3-byte body, captures STATUS only
    #   F23  F15's request, cut one byte later: the 1 captured byte after
    #        OPC is still rendered raw                                control
    #   F24  its response, well formed
    _sliced(make_packet(True, NVME_MI_TYPE_MI, 0, bytes([0x04, 0, 0, 0, 0]),
                        tag=0), 25),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=0),
    make_packet(True, NVME_MI_TYPE_MI, 0,
                mi_request_payload(0x04, cdw0=0x00000002), tag=1),
    _sliced(make_packet(False, NVME_MI_TYPE_MI, 0,
                        bytes([STATUS_SUCCESS, 0, 0]), tag=1), 25),
    _sliced(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                        bytes([0x06, 0x01, 0x0D, 0x00, 0x00]), tag=2), 25),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=2),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x000D, cns=0x01,
                                      flags=0x01, doff=0, dlen=64), tag=3),
    _sliced(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                        bytes([STATUS_SUCCESS, 0, 0]), tag=3), 25),
    _sliced(make_packet(True, NVME_MI_TYPE_MI, 0, bytes([0x04, 0, 0, 0, 0]),
                        tag=4), 26),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload(STATUS_SUCCESS), tag=4),
]

BASE_TS_SLICED_CONTEXT_US = 1712016000 * 1_000_000

def _build_sliced(output_path, packets, base_ts):
    write_pcapng(output_path, packets, base_ts)

def build_sliced_context_pcapng(output_path):
    _build_sliced(output_path, packets_sliced_context,
                  BASE_TS_SLICED_CONTEXT_US)


# ---------------------------------------------------------------------------
# nvme-mi-types.pcapng F179-F202 - a failed Message Integrity Check does not gate
# Command Slot state
# ---------------------------------------------------------------------------
#
# NVMe-MI 2.1 2 (Physical Layer and Message Transport): "If the Message
# Integrity Check fails, then the Request Message shall be discarded."  The
# dissector computes the MIC and compares it *after* the slot lifecycle has
# already run, so a bad-MIC frame mutates state exactly as a good one does.
# In the response direction that destroys a live transaction outright.
#
#   F1/F2 good MIC both directions, tag 0                    positive twin
#   F3    request with a corrupt MIC, tag 4
#   F4    its good response
#   F5    request with a good MIC, tag 2
#   F6    response with a corrupt MIC, tag 2
#   F7    the good response that follows it, tag 2
#   F8/F9 IC = 0 exchange, tag 5                             negative vector
#   F10   request with a good MIC, tag 6
#   F11   its response, STATUS E0h (Vendor Specific), tag 6
#
# F12-F24 follow F1-F11 so that F1-F11 keep their frame numbers.
#
#   F12   MIC KAT anchor, Appendix B Figure 197 payload      32 x 00h
#   F13   MIC KAT anchor, Appendix B Figure 198 payload      32 x FFh
#   F14   MIC KAT anchor, Appendix B Figure 199 payload      30 incrementing
#   F15   MIC KAT anchor, Appendix B Figure 200 payload      32 decrementing
#   F16   CRC tail residue 1: 29-byte payload, 33-byte span
#   F17   CRC tail residue 3: 31-byte payload, 35-byte span
#   F18   MI request, complete, good MIC                     clean twin
#   F19   the same request with its four MIC bytes cut away
#   F20   the same request cut six bytes, so the body throws
#   F21   MI request whose body is two bytes, with a corrupt MIC
#   F22   Control Primitive Get State request, complete      clean twin
#   F23   its response, complete
#   F24   Control Primitive request, body reports 4, captures 2
#
# F8/F9 are deliberate IC = 0 frames, which the rest of the corpus avoids:
# 3.1.1 requires IC = 1 out of band without exception, so an IC conformance
# check needs somewhere to fire, and the exact expert censuses elsewhere
# require it not to fire there.
#
# F10/F11 promote the twelfth session artefact, `xl-vendor-status.pcapng`.
# Figure 29's third column is headed "Response Message Format Section" and its
# last two rows -- `2Bh to DFh | Reserved | -` and
# `E0h to FFh | Vendor Specific | Vendor Specific` -- decline to assign the
# Generic Error format to either range, so bytes 3:1 of an E0h response are
# not a Reserved field.  The response keeps the artefact's exact bytes:
# STATUS E0h, then AA BB CC, then a two-byte 11 22 tail.
#
# The corrupt MICs differ from the correct ones in one byte, so the frames stay
# well-formed in every other respect and only the checksum verdict changes.

_MIC_REQ_PAYLOAD  = mi_request_payload(0x01)
_MIC_RESP_PAYLOAD = mi_response_payload(STATUS_SUCCESS)
_MIC_REQ_GOOD  = crc32c(nvme_mi_header(NVME_MI_TYPE_MI, 0, False)
                        + _MIC_REQ_PAYLOAD)
_MIC_RESP_GOOD = crc32c(nvme_mi_header(NVME_MI_TYPE_MI, 0, True)
                        + _MIC_RESP_PAYLOAD)
_MIC_REQ_BAD   = (_MIC_REQ_GOOD  & 0x00FFFFFF) | 0xC9000000
_MIC_RESP_BAD  = (_MIC_RESP_GOOD & 0x00FFFFFF) | 0xDD000000

# `xl-vendor-status.pcapng` F2, byte for byte: STATUS E0h, then AA BB CC in
# the three bytes the Generic Error Response would call Reserved, then a
# two-byte tail.  NMRESP is packed little-endian, so 00CCBBAAh serialises as
# AA BB CC.
_MIC_VENDOR_STATUS = 0xE0
_MIC_VENDOR_NMRESP = 0x00CCBBAA
_MIC_VENDOR_TAIL   = bytes([0x11, 0x22])

# ---------------------------------------------------------------------------
# F12-F24: the MIC-ordering fix and the Appendix B known-answer anchors
# ---------------------------------------------------------------------------
#
# NVMe-MI 2.1 Appendix B Figures 197-200 give four artificial messages with
# their exact MIC dwords.  None of them can be carried verbatim as the span an
# NVMe-MI MIC covers: 3.1.1.1 has the CRC run over the contents of the NVMe-MI
# Message, which begins at the MCTPD byte, and Figure 20 fixes that byte's
# Message Type at 4h with IC set -- 84h.  Every one of the four vectors starts
# with something else (00h, FFh, 00h, 1Fh), so a frame whose covered span were
# the vector could never be dispatched to this dissector at all.
#
# What can be imported, and is, is the vectors' *byte content* as Message
# Data, on a message type with no registered body dissector (NMIMT 4h, PCIe
# Command) so the payload is rendered raw and the only thing under test is the
# checksum.  The four vectors themselves are asserted directly against an
# independent CRC-32C implementation in test/suite_dissection_nvme_mi.py,
# which is what breaks the generator/dissector self-consistency loop: the
# expected MIC of each frame below is a literal in the test file, derived from
# the spec algorithm, not from this file.
#
# Figure 199's 30-byte vector is the one the specification singles out --
# "the message is not an even number of dwords and the MIC spans Dwords 7 and
# 8" -- and as Message Data it yields a 34-byte covered span, so the CRC's
# non-multiple-of-four tail is exercised.  F16 and F17 complete the residues
# with 33- and 35-byte spans, since 34 alone leaves two of the three unequal
# residues untested.
#
# Each anchor is an unanswered request on its own Management Endpoint EID.
# One unanswered request per conversation displaces nothing, so none of them
# collects a superseded-request note, and no two of them share a Command Slot.

_MIC_KAT_EID_FIG197 = 0x20
_MIC_KAT_EID_FIG198 = 0x21
_MIC_KAT_EID_FIG199 = 0x22
_MIC_KAT_EID_FIG200 = 0x23
_MIC_KAT_EID_RES1   = 0x24
_MIC_KAT_EID_RES3   = 0x25

# Appendix B Figures 197-200, byte for byte.
_MIC_KAT_FIG197 = bytes(32)                     # 32 bytes of 0's
_MIC_KAT_FIG198 = b'\xFF' * 32                  # 32 bytes of 1's
_MIC_KAT_FIG199 = bytes(range(0x1E))      # 30 incrementing, 00h to 1Dh
_MIC_KAT_FIG200 = bytes(range(0x1F, -1, -1))    # 32 decrementing, 1Fh to 00h

# The remaining two CRC tail residues, cut from the Figure 199 pattern so the
# only thing that differs between F14, F16 and F17 is the length.
_MIC_KAT_RES1 = bytes(range(0x1D))        # 29 bytes -> 33-byte span
_MIC_KAT_RES3 = bytes(range(0x1F))        # 31 bytes -> 35-byte span

# F18-F20: one message in three capture states.  The MIC verdict must be the
# same whether or not the body dissector reaches its end, which is what the
# ordering fix is about, so all three carry the identical NVMe-MI message and
# differ only in where the capture stopped.
_MIC_ORDER_EID_CLEAN  = 0x26
_MIC_ORDER_EID_NOMIC  = 0x27
_MIC_ORDER_EID_THROW  = 0x28
_MIC_ORDER_EID_SHORT  = 0x29
_MIC_CTL_EID_CLEAN    = 0x2A
_MIC_CTL_EID_SLICED   = 0x2B

def _mic_order_req(bmc_eid):
    """The shared MI request: 16 SLL + 4 MCTP + 4 header + 12 body + 4 MIC."""
    return make_packet(True, NVME_MI_TYPE_MI, 0, _MIC_REQ_PAYLOAD,
                       bmc_eid=bmc_eid, tag=1)

# A two-byte MI request body: under the twelve an MI Command Message needs, so
# packet-nvme-mi-mi.c raises its own truncation expert and renders the bytes
# raw -- and the MIC, which covers a fully captured six-byte span, is
# computable and deliberately wrong.  A bad verdict and a body that cannot be
# decoded have to be able to coexist on one frame.
_MIC_SHORT_BODY = bytes([0x01, 0x00])
_MIC_SHORT_GOOD = crc32c(nvme_mi_header(NVME_MI_TYPE_MI, 0, False)
                         + _MIC_SHORT_BODY)
_MIC_SHORT_BAD  = (_MIC_SHORT_GOOD & 0x00FFFFFF) | 0x5A000000

# F22-F24: the Control Primitive arm of the same ordering defect.  A Control
# body is exactly four bytes (Figures 37 and 40), and the dissector guarded
# only its *reported* length, so a body reporting four and carrying two threw
# from the first fixed read and took the framing layer's MIC with it.
_MIC_CTL_REQ  = cp_request_payload(CP_OPC_GET_STATE, tag=0x2C, cpsp=0x0001)
_MIC_CTL_RESP = cp_response_payload(STATUS_SUCCESS, tag=0x2C, cpsr=0x0000)

def _mic_ctl_req(bmc_eid):
    return make_packet(True, NVME_MI_TYPE_CONTROL, 0, _MIC_CTL_REQ,
                       bmc_eid=bmc_eid, tag=1)

packets_mic_integrity = [
    make_packet(True,  NVME_MI_TYPE_MI, 0, _MIC_REQ_PAYLOAD,  tag=0),
    make_packet(False, NVME_MI_TYPE_MI, 0, _MIC_RESP_PAYLOAD, tag=0),

    make_packet(True,  NVME_MI_TYPE_MI, 0, _MIC_REQ_PAYLOAD, tag=4,
                mic=_MIC_REQ_BAD),
    make_packet(False, NVME_MI_TYPE_MI, 0, _MIC_RESP_PAYLOAD, tag=4),

    make_packet(True,  NVME_MI_TYPE_MI, 0, _MIC_REQ_PAYLOAD, tag=2),
    make_packet(False, NVME_MI_TYPE_MI, 0, _MIC_RESP_PAYLOAD, tag=2,
                mic=_MIC_RESP_BAD),
    make_packet(False, NVME_MI_TYPE_MI, 0, _MIC_RESP_PAYLOAD, tag=2),

    make_packet(True,  NVME_MI_TYPE_MI, 0, _MIC_REQ_PAYLOAD,  tag=5, ic=False),
    make_packet(False, NVME_MI_TYPE_MI, 0, _MIC_RESP_PAYLOAD, tag=5, ic=False),

    make_packet(True,  NVME_MI_TYPE_MI, 0, _MIC_REQ_PAYLOAD, tag=6),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload_with_data(_MIC_VENDOR_STATUS,
                                              _MIC_VENDOR_TAIL,
                                              nmresp=_MIC_VENDOR_NMRESP),
                tag=6),

    # F12-F17  the Appendix B payloads and the three CRC tail residues.
    make_packet(True, NVME_MI_TYPE_PCIE, 0, _MIC_KAT_FIG197,
                bmc_eid=_MIC_KAT_EID_FIG197, tag=1),
    make_packet(True, NVME_MI_TYPE_PCIE, 0, _MIC_KAT_FIG198,
                bmc_eid=_MIC_KAT_EID_FIG198, tag=1),
    make_packet(True, NVME_MI_TYPE_PCIE, 0, _MIC_KAT_FIG199,
                bmc_eid=_MIC_KAT_EID_FIG199, tag=1),
    make_packet(True, NVME_MI_TYPE_PCIE, 0, _MIC_KAT_FIG200,
                bmc_eid=_MIC_KAT_EID_FIG200, tag=1),
    make_packet(True, NVME_MI_TYPE_PCIE, 0, _MIC_KAT_RES1,
                bmc_eid=_MIC_KAT_EID_RES1, tag=1),
    make_packet(True, NVME_MI_TYPE_PCIE, 0, _MIC_KAT_RES3,
                bmc_eid=_MIC_KAT_EID_RES3, tag=1),

    # F18-F20  one message, three capture states.  40 bytes on the wire; cut
    # four and the MIC itself is gone while the body is still whole, cut six
    # and the body's last CDW1 byte goes with it so the body throws.
    _mic_order_req(_MIC_ORDER_EID_CLEAN),
    _sliced(_mic_order_req(_MIC_ORDER_EID_NOMIC), 36),
    _sliced(_mic_order_req(_MIC_ORDER_EID_THROW), 34),

    # F21  a bad MIC on a frame whose body is too short to decode.
    make_packet(True, NVME_MI_TYPE_MI, 0, _MIC_SHORT_BODY,
                bmc_eid=_MIC_ORDER_EID_SHORT, tag=1, mic=_MIC_SHORT_BAD),

    # F22-F24  the Control Primitive arm.  32 bytes on the wire; cutting to 26
    # leaves the body reporting four bytes and carrying two.
    _mic_ctl_req(_MIC_CTL_EID_CLEAN),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0, _MIC_CTL_RESP,
                bmc_eid=_MIC_CTL_EID_CLEAN, tag=1),
    _sliced(_mic_ctl_req(_MIC_CTL_EID_SLICED), 26),
]

BASE_TS_MIC_INTEGRITY_US = 1712102400 * 1_000_000

def build_mic_integrity_pcapng(output_path):
    _build_sliced(output_path, packets_mic_integrity,
                  BASE_TS_MIC_INTEGRITY_US)


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F1-F178 - three ways the Command Slot lifecycle
# mis-models the endpoint
# ---------------------------------------------------------------------------
#
# Three independent experiments, each on its own MCTP tag so that none of them
# can perturb another:
#
#   A zero-payload response (Figure 28 makes STATUS mandatory at message byte
#   4) is treated as a *known* status and closes the transaction, orphaning the
#   real response that follows.  tags 5 and 6.
#
#     F1 Admin request                     tag 5
#     F2 response with no payload at all   tag 5
#     F3 the real response                 tag 5
#     F4 Admin request                     tag 6      positive twin
#     F5 status-only 1-byte response       tag 6      closes the slot
#
#   Endpoint Command Slots are partitioned by MCTP tag, so two requests that
#   really do contend for one of the endpoint's two slots (1.8.15: "Each
#   Management Endpoint has exactly two Command Slots") are both live, with no
#   displacement note.  tags 0 and 1, both CSI 0.
#
#     F6 Admin Identify request      tag 0 CSI 0
#     F7 Admin Get Log Page request  tag 1 CSI 0
#     F8 response                    tag 0
#     F9 response                    tag 1
#
#   A Replay Control Primitive's replayed Response Message carries the Msg tag
#   of the *primitive* (4.2.1.5), not of the original command, and the
#   dissector keeps no last-response history, so the replayed message is
#   reported orphaned on fully conformant traffic.  tags 2 and 3, CSI 1.
#
#     F10 MI request                          tag 2 CSI 1
#     F11 MI response                         tag 2 CSI 1
#     F12 Replay primitive request            tag 3 CSI 1
#     F13 Replay Success response, RR set     tag 3 CSI 1
#     F14 the replayed Response Message       tag 3 CSI 1
#
#   A Control Primitive Response Message must echo the Tag of the request it
#   answers (Figure 40 byte 5; 4.2.1 makes it a "shall").  One that does not is
#   not the answer, so it must neither be credited with the link nor close the
#   Control Primitive slot -- the real answer that follows must still find it
#   open.  tag 4, CSI 0.
#
#     F15 Get State request, TAG A1h          tag 4 CSI 0
#     F16 Success response, TAG B2h           tag 4 CSI 0   wrong echo
#     F17 Success response, TAG A1h           tag 4 CSI 0   the real answer

_SLOT_REPLAY_CP_TAG = 0x5A
_SLOT_CTL_TAG_GOOD  = 0xA1
_SLOT_CTL_TAG_WRONG = 0xB2

packets_slot_lifecycle = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01,
                                      flags=0x01, doff=0, dlen=16), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, b'', tag=5),
    # ...and the real answer, carrying the 16 bytes DLEN selected.
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x5107C105)
                + ID4 + b'WIRESHARK-SN', tag=5),

    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0002, cns=0x01,
                                      flags=0x01, doff=0, dlen=16), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0, bytes([STATUS_SUCCESS]), tag=6),

    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0003, cns=0x01,
                                      flags=0x00, doff=0, dlen=0), tag=0),
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x02, ctrl_id=0x0004, cns=0x02,
                                      flags=0x00, doff=0, dlen=0), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xAAAA000A), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0xBBBB000B), tag=1),

    make_packet(True,  NVME_MI_TYPE_MI, 1, mi_request_payload(0x01), tag=2),
    make_packet(False, NVME_MI_TYPE_MI, 1,
                mi_response_payload(STATUS_SUCCESS), tag=2),
    make_packet(True,  NVME_MI_TYPE_CONTROL, 1,
                cp_request_payload(CP_OPC_REPLAY, tag=_SLOT_REPLAY_CP_TAG),
                tag=3),
    # CPSR bit 0 is Response Replayed (RR): the endpoint promises the replayed
    # Response Message that F14 is.
    make_packet(False, NVME_MI_TYPE_CONTROL, 1,
                cp_response_payload(STATUS_SUCCESS, tag=_SLOT_REPLAY_CP_TAG,
                                    cpsr=0x0001), tag=3),
    make_packet(False, NVME_MI_TYPE_MI, 1,
                mi_response_payload(STATUS_SUCCESS), tag=3),

    # F15-F17  the Control Primitive Tag echo, on its own tag 4 so the Replay
    # experiment above cannot perturb it.  Figure 40 byte 5 and section 4.2.1
    # both make the echo a "shall": the Management Endpoint "shall copy the
    # value of the Tag field from the Control Primitive Request Message into
    # the Tag field of the Control Primitive Response Message".
    #
    #   F15 Get State request, TAG A1h  -> opens the Control Primitive slot
    #   F16 Success response, TAG B2h   -> does not echo; must not be credited
    #                                      as the answer and must not close
    #                                      the slot, while still raising the
    #                                      body's tag-mismatch expert
    #   F17 Success response, TAG A1h   -> the real answer; links to F15
    make_packet(True,  NVME_MI_TYPE_CONTROL, 0,
                cp_request_payload(CP_OPC_GET_STATE,
                                   tag=_SLOT_CTL_TAG_GOOD), tag=4),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                cp_response_payload(STATUS_SUCCESS,
                                    tag=_SLOT_CTL_TAG_WRONG), tag=4),
    make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                cp_response_payload(STATUS_SUCCESS,
                                    tag=_SLOT_CTL_TAG_GOOD), tag=4),
]

BASE_TS_SLOT_LIFECYCLE_US = 1712188800 * 1_000_000

# Append only: the first seventeen packet records are fixed.
# Names are a wire-vector index for handoff, not runtime expected results.
M4_SLOT_FRAMES = {}

def _m4_slot(name, request, typ=NVME_MI_TYPE_MI, csi=0, tag=0,
             payload=None, endpoint=BMC_EID, **kwargs):
    if payload is None:
        payload = (mi_request_payload(0x01) if request else
                   mi_response_payload_with_data(STATUS_SUCCESS, nshds()))
    M4_SLOT_FRAMES[name] = len(packets_slot_lifecycle) + 1
    packets_slot_lifecycle.append(make_packet(
        request, typ, csi, payload, tag=tag, bmc_eid=endpoint, **kwargs))

def _m4_cp(name, request, opcode=CP_OPC_GET_STATE, csi=0, tag=2,
           value=0, status=STATUS_SUCCESS, ctl_tag=0xA1, **kwargs):
    payload = (cp_request_payload(opcode, tag=ctl_tag, cpsp=value) if request
               else cp_response_payload(status, tag=ctl_tag, cpsr=value))
    _m4_slot(name, request, NVME_MI_TYPE_CONTROL, csi, tag, payload, **kwargs)

# Pairing survives wrong response CSI, only for slot-specific primitives.
for name, opc, req_csi, rsp_csi in [
        ('abort_wrong_csi', CP_OPC_ABORT, 1, 0),
        ('state_wrong_csi', CP_OPC_GET_STATE, 1, 0),
        ('replay_wrong_csi', CP_OPC_REPLAY, 1, 0),
        ('pause_response_csi', CP_OPC_PAUSE, 0, 1),
        ('resume_response_csi', CP_OPC_RESUME, 0, 1),
        ('pause_request_csi', CP_OPC_PAUSE, 1, 0),
        ('resume_request_csi', CP_OPC_RESUME, 1, 0)]:
    _m4_cp(name + '_req', True, opc, csi=req_csi)
    _m4_cp(name + '_resp', False, opc, csi=rsp_csi,
           value=1 if opc == CP_OPC_REPLAY else 0)

# Abort decision table. Tag 0's late response remains tag-correlated, even after
# a successful Abort. It must never evict tag 1's newer endpoint occupant.
for i, (name, status, cpas) in enumerate([
        ('abort_complete', 0, 0), ('abort_before', 0, 1),
        ('abort_partial', 0, 2), ('abort_unable', 8, 0),
        ('abort_error', 2, 0), ('abort_reserved', 0, 3),
        ('abort_bad_csi', 0, 1), ('abort_bad_tag', 0, 1),
        ('abort_bad_mic', 0, 1), ('abort_bad_request', 0, 1),
        ('abort_other_slot', 0, 1)]):
    ep, csi = 0x30 + i, i % 2
    _m4_slot(name + '_old', True, csi=csi, endpoint=ep)
    selected = csi ^ (name == 'abort_other_slot')
    _m4_cp(name + '_req', True, CP_OPC_ABORT, csi=selected, endpoint=ep,
           mic=0 if name == 'abort_bad_request' else None)
    _m4_cp(name + '_resp', False, CP_OPC_ABORT,
           csi=selected ^ (name == 'abort_bad_csi'), endpoint=ep,
           status=status, value=cpas,
           ctl_tag=0xB2 if name == 'abort_bad_tag' else 0xA1,
           mic=0 if name == 'abort_bad_mic' else None)
    _m4_slot(name + '_new', True, csi=csi, tag=1, endpoint=ep)
    _m4_slot(name + '_late', False, csi=csi, endpoint=ep)
    _m4_slot(name + '_done', False, csi=csi, tag=1, endpoint=ep)

# Only Idle contradicts outstanding. MPR remains Process, other CSI is
# independent, and refused/unverified/wrong-CSI answers cannot authorize notes.
_m4_slot('state_command', True, endpoint=0x50)
for name, state in [('state_idle', 0), ('state_process', 2)]:
    _m4_cp(name + '_req', True, endpoint=0x50)
    _m4_cp(name + '_resp', False, value=state, endpoint=0x50)
_m4_slot('state_mpr', False, endpoint=0x50,
         payload=bytes([1, 0, 10, 0]))
for name, selected, returned, state, status, mic, ctl_tag in [
        ('state_mpr_process', 0, 0, 2, 0, None, 0xA1),
        ('state_other_idle', 1, 1, 0, 0, None, 0xA1),
        ('state_bad_csi', 0, 1, 0, 0, None, 0xA1),
        ('state_error', 0, 0, 0, 2, None, 0xA1),
        ('state_bad_mic', 0, 0, 0, 0, 0, 0xA1),
        ('state_bad_tag', 0, 0, 0, 0, None, 0xB2)]:
    _m4_cp(name + '_req', True, csi=selected, endpoint=0x50)
    _m4_cp(name + '_resp', False, csi=returned, value=state,
           status=status, mic=mic, ctl_tag=ctl_tag, endpoint=0x50)
_m4_cp('state_real_idle', False, endpoint=0x50)
_m4_slot('state_done', False, endpoint=0x50)
_m4_cp('state_empty_req', True, endpoint=0x50)
_m4_cp('state_empty_resp', False, endpoint=0x50)

# MH01: a real two-packet response, so RRO=1 selects an actual suffix.
# The suffix preserves the *original* four-byte header and MIC. Do not call
# nvme_mi_message() to rebuild it: that would compute a different, false MIC.
_M4_REPLAY_MESSAGE = nvme_mi_message(
    NVME_MI_TYPE_MI, 0, is_response=True,
    payload=mi_response_payload_with_data(0, bytes(range(80))))

def _m4_replay_wire(name, tag, endpoint=0x60, partial=False, csi=0, bad=False):
    msg = bytearray(_M4_REPLAY_MESSAGE)
    if csi:
        msg[1] |= 1
        msg[-4:] = struct.pack('<I', crc32c(bytes(msg[:-4])))
    if bad:
        msg[-1] ^= 0x80
    msg = bytes(msg)
    chunks = [msg[:4] + msg[64:]] if partial else [msg[:64], msg[64:]]
    for i, chunk in enumerate(chunks):
        M4_SLOT_FRAMES[name + ('_som' if i == 0 and len(chunks) > 1 else '')] = \
            len(packets_slot_lifecycle) + 1
        flags = (0x80 if i == 0 else 0) | (0x40 if i == len(chunks) - 1 else 0)
        packets_slot_lifecycle.append(
            sll_header(endpoint, outgoing=False)
            + bytes([1, HOST_EID, endpoint, flags | (i << 4) | tag]) + chunk)

_m4_slot('replay_command', True, endpoint=0x60,
         payload=mi_request_payload(0x05, cdw1=80))
_m4_replay_wire('replay_original', 0)
_m4_cp('replay_full_req', True, CP_OPC_REPLAY, tag=3, endpoint=0x60)
_m4_cp('replay_full_ack', False, value=1, tag=3, endpoint=0x60)
_m4_replay_wire('replay_full', 3)
_m4_replay_wire('replay_duplicate', 3)
_m4_cp('replay_zero_req', True, CP_OPC_REPLAY, tag=4, endpoint=0x60)
_m4_cp('replay_zero_ack', False, tag=4, endpoint=0x60)
_m4_replay_wire('replay_zero_unsolicited', 4)
_m4_cp('replay_partial_req', True, CP_OPC_REPLAY, tag=5, value=1, endpoint=0x60)
_m4_cp('replay_partial_ack', False, tag=5, value=1, endpoint=0x60)
_m4_replay_wire('replay_partial', 5, partial=True)

_m4_slot('replay_mpr_command', True, csi=1, tag=1, endpoint=0x60)
_m4_slot('replay_mpr_original', False, csi=1, tag=1, endpoint=0x60,
         payload=bytes([1, 0, 10, 0]))
_m4_cp('replay_mpr_req', True, CP_OPC_REPLAY, csi=1, tag=6, endpoint=0x60)
_m4_cp('replay_mpr_ack', False, csi=1, tag=6, value=1, endpoint=0x60)
_m4_slot('replay_mpr', False, csi=1, tag=6, endpoint=0x60,
         payload=bytes([1, 0, 4, 0]))
_m4_slot('replay_mpr_done', False, csi=1, tag=1, endpoint=0x60)

# Pending expectation: foreign endpoint, wrong CSI and bad MIC do not steal it.
_m4_cp('replay_scoped_req', True, CP_OPC_REPLAY, tag=3, endpoint=0x60)
_m4_cp('replay_scoped_ack', False, tag=3, value=1, endpoint=0x60)
_m4_replay_wire('replay_other_endpoint', 3, endpoint=0x61)
_m4_replay_wire('replay_other_csi', 3, csi=1)
_m4_replay_wire('replay_bad_mic', 3, bad=True)
_m4_replay_wire('replay_scoped', 3)
_m4_cp('replay_abort_req', True, CP_OPC_ABORT, endpoint=0x60)
_m4_cp('replay_abort_ack', False, endpoint=0x60)
_m4_cp('replay_after_abort_req', True, CP_OPC_REPLAY, tag=3, endpoint=0x60)
_m4_cp('replay_after_abort_ack', False, tag=3, value=1, endpoint=0x60)
_m4_replay_wire('replay_after_abort', 3)

# A new Command Message invalidates old replay evidence on that CSI, even
# though its transport transaction has a different tag.
_m4_slot('replay_new_history_req', True, endpoint=0x60,
         payload=mi_request_payload(0x05, cdw1=80))
_m4_replay_wire('replay_new_history', 0)
_m4_cp('replay_cancel_req', True, CP_OPC_REPLAY, tag=3, endpoint=0x60)
_m4_cp('replay_cancel_ack', False, tag=3, value=1, endpoint=0x60)
_m4_slot('replay_replacement', True, tag=4, endpoint=0x60)
_m4_replay_wire('replay_cancelled', 3)
_m4_slot('replay_replacement_done', False, tag=4, endpoint=0x60)

# An older tag's completion must leave the newer occupant intact.
_m4_slot('late_old_req', True, endpoint=0x62)
_m4_slot('late_new_req', True, tag=1, endpoint=0x62)
_m4_slot('late_old_resp', False, endpoint=0x62)
_m4_cp('late_state_req', True, endpoint=0x62)
_m4_cp('late_state_resp', False, endpoint=0x62)
_m4_slot('late_new_resp', False, tag=1, endpoint=0x62)
# Distinct CSI requests do not contend, and completing CSI 0 cannot clear 1.
_m4_slot('distinct_zero_req', True, endpoint=0x62)
_m4_slot('distinct_one_req', True, csi=1, tag=1, endpoint=0x62)
_m4_slot('distinct_zero_resp', False, endpoint=0x62)
_m4_cp('distinct_state_req', True, csi=1, endpoint=0x62)
_m4_cp('distinct_state_resp', False, csi=1, endpoint=0x62)
_m4_slot('distinct_one_resp', False, csi=1, tag=1, endpoint=0x62)

def build_slot_lifecycle_pcapng(output_path):
    _build_sliced(output_path, packets_slot_lifecycle,
                  BASE_TS_SLOT_LIFECYCLE_US)


# ---------------------------------------------------------------------------
# One MCTP packet of a multi-packet message over Linux SLL
# ---------------------------------------------------------------------------

def _sll_mctp_fragment(payload, tag, seq, som, eom, is_request=True):
    src = HOST_EID if is_request else BMC_EID
    return (sll_header(src, outgoing=is_request)
            + mctp_header(is_request, tag=tag, som=som, eom=eom, seq=seq)
            + payload)

# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F75-F204 - Reset validity and MEB routing
# ---------------------------------------------------------------------------
#
# Two findings that both live in the MI command body but are consumed (or not)
# by the framing layer:
#
#   "No Success Response is transmitted" holds only for a Reset that specifies
#   Reset NVM Subsystem, and Figure 125 makes every RSTTYP other than 00h
#   Reserved.  The framing layer keys purely on the opcode, so a Reset carrying
#   a reserved RSTTYP still tells the next request on that slot that its
#   predecessor was owed no response -- asserting the opposite of the truth.
#
#   The MEB bit selects where a command's data lives, and the framing layer
#   consumes and discards it, so the body decoder cannot know whether the
#   payload in front of it is inline or should be absent.  4.2.3 conditions
#   the rule on per-endpoint capability state (the MEB Supported Command List
#   and a non-zero MEBS) that a capture need not contain, and 5.2.4 exempts the
#   AE Enable List outright -- so on a capability-free capture the correct
#   behaviour is silence, and only the positive vector is assertable.
#
#   F1  Reset, RSTTYP 00h                    tag 6   no response follows
#   F2  MI request taking the same slot      tag 6   is owed no response
#   F3  its response                         tag 6
#   F4  Reset, RSTTYP 01h (Reserved)         tag 7
#   F5  MI request taking the same slot      tag 7   is owed one
#   F6  its response                         tag 7
#   F7  Reset, RSTTYP 02h (Reserved)         tag 4
#   F8  MI request taking the same slot      tag 4   is owed one
#   F9  its response                         tag 4
#   F10 Reset, RSTTYP 00h                    tag 3
#   F11 a Success Response to it             tag 3   normatively impossible
#   F12 Admin request, MEB set, data inline  tag 1
#   F13 its response                         tag 1
#   F14 Configuration Set CID 04h, MEB set,
#       AE Enable List inline                tag 2   silent by 5.2.4
#   F15 its response                         tag 2
#   F16 Reset, RSTTYP 00h                    tag 5
#   F17 an Error Response to it              tag 5   legal; the control
#
# Figure 125 reserves every RSTTYP other than 00h, so 01h and 02h are two
# representatives of one rule; both are here because the session artefact this
# reproduces used 01h and the oracle vector names 02h.

_MEB_INLINE_DATA = bytes(range(0x41, 0x49))
_MEB_AE_ENABLE_LIST = (bytes([2, 0]) + struct.pack('<H', 11) + bytes([5])
                       + bytes([3]) + struct.pack('<H', 0x8006)
                       + bytes([3]) + struct.pack('<H', 0x0009))

def _reset_then_command(rsttyp, tag):
    """A Reset carrying `rsttyp`, the command that takes its slot, and the
    command's response."""
    return [
        make_packet(True,  NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0x07, cdw0=rsttyp << 24), tag=tag),
        make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01),
                    tag=tag),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS), tag=tag),
    ]

packets_mi_events_config = (
    _reset_then_command(0x00, tag=6)
    + _reset_then_command(0x01, tag=7)
    + _reset_then_command(0x02, tag=4)
    + [
        make_packet(True,  NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0x07, cdw0=0x00000000), tag=3),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS), tag=3),

        make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x09, ctrl_id=0x0001, cns=0x7D,
                                          flags=0x01, doff=0, dlen=8)
                    + _MEB_INLINE_DATA, tag=1, meb=True),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS), tag=1),

        make_packet(True,  NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0x03, cdw0=0x01050A04)
                    + _MEB_AE_ENABLE_LIST, tag=2, meb=True),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS), tag=2),

        # F16/F17  the error-response control for the conformance expert.
        # Section 5 suppresses the Success Response only for a Reset NVM
        # Subsystem that "completes successfully"; one that did not complete
        # successfully answers with an Error Response, which is ordinary
        # traffic and must stay silent.  Same RSTTYP 00h as F10, so the only
        # difference between the two responses is the status byte.
        make_packet(True,  NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0x07, cdw0=0x00000000), tag=5),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_INTERNAL_ERROR), tag=5),
    ]
)

BASE_TS_MI_EVENTS_CONFIG_US = 1712448000 * 1_000_000

# Capability vectors need a proven physical port, not an EID guessed to be a
# slave address. Append I2C IDBs/records after the original SLL experiment.
M4_MEB_FRAMES = {}
packets_m4_meb = []

def _m4_meb(name, request, payload, *, meb=False, endpoint=BMC_EID, tag=0,
            csi=0, iface=1, mic=None):
    M4_MEB_FRAMES[name] = len(packets_mi_events_config) + len(packets_m4_meb) + 1
    msg = nvme_mi_message(NVME_MI_TYPE_MI, csi, not request, payload,
                          meb=meb, mic=mic)
    pkt = i2c_phdr(bus=iface - 1) + smbus_mctp_frame(
        0x3A if request else 0x10, 0x10 if request else 0x3A,
        endpoint if request else HOST_EID, HOST_EID if request else endpoint,
        tag, request, msg, pec=True)
    packets_m4_meb.append((iface, pkt))

def _m4_meb_port(name, size=4096, port=7, address=0x3A, **kwargs):
    data = bytearray(port_info_twire())
    data[4:8] = struct.pack('<I', size)
    data[10] = address
    _m4_meb(name + '_req', True,
             mi_request_payload(0, cdw0=(1 << 24) | (port << 16)), **kwargs)
    _m4_meb(name + '_resp', False,
             mi_response_payload_with_data(0, bytes(data), nmresp=len(data)), **kwargs)

def _m4_meb_list(name, port=7, commands=(3, 5, 6), poison='', **kwargs):
    data = struct.pack('<H', len(commands)) + b''.join(
        bytes([NVME_MI_TYPE_MI << 3, opc]) for opc in commands)
    if poison == 'count':
        data = b'\x14\x00' + data[2:]
    request = mi_request_payload(0, cdw0=(5 << 24) | (port << 16))
    _m4_meb(name + '_req', True,
             request[:1] if poison == 'request_short' else request,
             mic=0 if poison == 'request_mic' else None,
             **kwargs)
    payload = mi_response_payload_with_data(0, data, nmresp=len(data))
    if poison == 'rdl':
        payload = payload[:1] + struct.pack('<H', len(data) + 1) + payload[3:]
    if poison == 'status':
        payload = mi_response_payload(2)
    _m4_meb(name + '_resp', False, payload,
             mic=0 if poison == 'response_mic' else None, **kwargs)
    if poison == 'response_mic':
        _m4_meb(name + '_cleanup', False, mi_response_payload(2), **kwargs)

def _m4_meb_read(name, *, meb=True, inline=True, **kwargs):
    _m4_meb(name + '_req', True, mi_request_payload(5, cdw1=8),
             meb=meb, **kwargs)
    _m4_meb(name + '_resp', False,
             mi_response_payload_with_data(0, _MEB_INLINE_DATA)
             if inline else mi_response_payload(0), **kwargs)

_m4_meb_read('capability_free')
_m4_meb_list('list_only')
_m4_meb_read('list_only_probe', tag=1)
_m4_meb_port('other_physical_port', address=0x3B)
_m4_meb_read('other_physical_probe', tag=1)
_m4_meb_port('capability_port')
_m4_meb('buffer_write_inline_req', True,
         mi_request_payload(6, cdw1=8) + _MEB_INLINE_DATA, meb=True, tag=1)
_m4_meb('buffer_write_inline_resp', False, mi_response_payload(0), tag=1)
_m4_meb('buffer_write_req', True, mi_request_payload(6, cdw1=8),
         meb=True, tag=1)
_m4_meb('buffer_write_resp', False, mi_response_payload(0), tag=1)
_m4_meb_read('buffer_read_inline', tag=2)
_m4_meb_read('buffer_read', inline=False, tag=2)
_m4_meb('inline_write_req', True,
         mi_request_payload(6, cdw1=8) + _MEB_INLINE_DATA, tag=1)
_m4_meb('inline_write_resp', False, mi_response_payload(0), tag=1)
_m4_meb_read('inline_read', meb=False, tag=2)
_m4_meb('unlisted_req', True, mi_request_payload(1), meb=True, tag=1)
_m4_meb('unlisted_resp', False, mi_response_payload_with_data(0, nshds()), tag=1)
_m4_meb('ae_inline_req', True,
         mi_request_payload(3, cdw0=0x01050A04) + _MEB_AE_ENABLE_LIST,
         meb=True, tag=2)
_m4_meb('ae_inline_resp', False, mi_response_payload(0), tag=2)
_m4_meb_read('other_endpoint', endpoint=0x6F)
_m4_meb_read('other_ingress', iface=2)
_m4_meb_port('zero_mebs', size=0)
_m4_meb_read('zero_mebs_probe', tag=1)

# Integrity, complete-context and exact-length admission controls, each with a
# valid MEBS observation but no trustworthy matching command-list authority.
for i, poison in enumerate(['request_mic', 'response_mic', 'request_short',
                            'rdl', 'count', 'status', 'port', 'membership']):
    endpoint = 0x70 + i
    _m4_meb_port(poison + '_port', endpoint=endpoint)
    _m4_meb_list(poison + '_list', endpoint=endpoint, poison=poison,
                 port=8 if poison == 'port' else 7,
                 commands=(3,) if poison == 'membership' else (3, 5, 6))
    _m4_meb_read(poison + '_probe', endpoint=endpoint, tag=1)

_m4_meb_port('mebs_only', endpoint=0x78)
_m4_meb_read('mebs_only_probe', endpoint=0x78, tag=1)
# Capability observed after a request cannot retroactively select its routing.
_m4_meb('past_request', True, mi_request_payload(5, cdw1=8),
         endpoint=0x79, csi=1, tag=4, meb=True)
_m4_meb_port('future_port', endpoint=0x79)
_m4_meb_list('future_list', endpoint=0x79)
_m4_meb('past_response', False,
         mi_response_payload_with_data(0, _MEB_INLINE_DATA),
         endpoint=0x79, csi=1, tag=4)
_m4_meb_read('future_probe', endpoint=0x79, tag=1)
_m4_meb_list('remove_membership', endpoint=0x79, commands=(3,))
_m4_meb_read('removed_probe', endpoint=0x79, tag=1)

# MI 2.2 Figure 119 says of CMEADDR only "the current 2-Wire address" and gives
# no bit range, while Figure 16 prints the Management Endpoint's default as
# "3Ah", binary "0011_101xb" -- 7-bit 1Dh with the read/write bit.  This
# endpoint reports 74h, the 8-bit form of the 3Ah its SMBus frames carry as a
# 7-bit source address, and its Management Endpoint Buffer size must be learned
# exactly as the 3Ah-reporting ports above are.  F119-F124.
_m4_meb_port('eight_bit_port', endpoint=0x7A, address=0x74)
_m4_meb_list('eight_bit_list', endpoint=0x7A)
_m4_meb_read('eight_bit_probe', endpoint=0x7A, inline=False, tag=1)

# MI 2.1 section 5.7.6: with this port's MEBS cleared to 0h, DTYP 05h is a
# reserved value for it -- but only for it.  F125-F130.
_m4_meb_port('zero_mebs_dtyp', size=0, endpoint=0x7B)
_m4_meb_list('zero_mebs_dtyp_list', endpoint=0x7B)
_m4_meb_list('zero_mebs_dtyp_other_port', endpoint=0x7B, port=8)

def build_mi_events_config_pcapng(output_path):
    _build_sliced(output_path, packets_mi_events_config,
                  BASE_TS_MI_EVENTS_CONFIG_US)
    with open(output_path, 'ab') as f:
        f.write(idb(link_type=209) + idb(link_type=209))
        for n, (iface, pkt) in enumerate(packets_m4_meb, len(packets_mi_events_config)):
            raw, origlen = pkt if isinstance(pkt, tuple) else (pkt, None)
            f.write(epb(raw, BASE_TS_MI_EVENTS_CONFIG_US + n * 1_000_000,
                        interface_id=iface, origlen=origlen))
    print(f"Appended {len(packets_m4_meb)} capability/routing packets")


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F744-F752 - a Reset NVM Subsystem cut after RSTTYP
# ---------------------------------------------------------------------------
#
# RSTTYP is NMD0 bits 31:24, message byte 11 (Figures 67 and 125), so a Reset
# NVM Subsystem, which is owed no Success Response (5.8), is known once that
# byte is captured, whatever is lost after it.  EID D1h is used by no other
# section, so no other section's Command Slots reach these.
#
#   F1  Reset RSTTYP 00h, captured through message byte 11    tag 1
#   F2  NVM Subsystem Health Status Poll taking the slot      tag 1   is owed no response
#   F3  its response                                          tag 1
#   F4  the same Reset captured through byte 10 (no RSTTYP)   tag 2
#   F5  the command taking the slot                           tag 2   superseded
#   F6  its response                                          tag 2
#   F7  Reset RSTTYP 00h whose reported body ends at NMD0     tag 3
#   F8  the command taking the slot                           tag 3   superseded
#   F9  its response                                          tag 3

_RESET_SLICED_EID = 0xD1

def _reset_sliced_triple(reset, tag):
    """`reset` (a packet, or a sliced one), the command that takes its slot,
    and the command's response."""
    return [
        reset,
        make_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01),
                    bmc_eid=_RESET_SLICED_EID, tag=tag),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS),
                    bmc_eid=_RESET_SLICED_EID, tag=tag),
    ]

def _reset_sliced_req(payload, tag):
    return make_packet(True, NVME_MI_TYPE_MI, 0, payload,
                       bmc_eid=_RESET_SLICED_EID, tag=tag)

# SLL(16) + MCTP(4) + NVMe-MI header(4) + body bytes 0-7 is message byte 11.
packets_reset_sliced = (
    _reset_sliced_triple(_sliced(_reset_sliced_req(mi_request_payload(0x07), 1),
                                 32), tag=1)
    + _reset_sliced_triple(_sliced(_reset_sliced_req(mi_request_payload(0x07), 2),
                                   31), tag=2)
    + _reset_sliced_triple(_reset_sliced_req(mi_request_payload(0x07)[:8], 3),
                           tag=3)
)

BASE_TS_RESET_SLICED_US = 1713139200 * 1_000_000

def build_reset_sliced_pcapng(output_path):
    _build_sliced(output_path, packets_reset_sliced, BASE_TS_RESET_SLICED_US)

def pel_header_vectors():
    """MI-5a header cases, Base 2.3 Figure 230 / Base 2.4 Figure 480.

    Each tuple is (name, logical offset, DOFST, response data). Each case
    occupies one request and one response frame, in this order.
    """
    header = bytearray(512)
    header[0] = 0x0d
    struct.pack_into('<IQ', header, 4, 0x01020304, 0x0102030405060708)
    header[16] = 3
    struct.pack_into('<H', header, 18, 492)
    header[20:28] = bytes.fromhex('0605040302010300')
    header[28:44] = bytes.fromhex('1032547698badcfe0123456789abcdef')
    struct.pack_into('<QHH', header, 44, 0x1122334455667788, 0x1234, 0x5678)
    header[56:76] = b'PEL-SERIAL-012345678'
    header[76:116] = b'PEL MODEL'.ljust(40, b' ')
    nqn = b'nqn.2026-11.org.example:pel'
    header[116:116 + len(nqn)] = nqn
    struct.pack_into('<HI', header, 372, 0xabcd, 0x0006005a)
    header[480:482] = b'\xfe\xff'
    header[507] = 0xc0
    assert len(header) == 512
    vectors = [('full', 0, 0, bytes(header))]
    for name, pos, size in (
            ('prefix', 0, 20), ('timestamp', 20, 8),
            ('identity', 44, 72), ('context', 372, 8), ('bitmap', 480, 32),
            ('inside_poh', 32, 24), ('inside_timestamp', 24, 4)):
        vectors.append((name, pos, 0, bytes(header[pos:pos + size])))
    vectors.append(('combined_offsets', 368, 4, bytes(header[372:380])))
    for name, rci in (('no_context', 0), ('subsystem_port', 0x00051234),
                      ('reserved_port_type', 0x000700ab)):
        data = bytearray(header)
        struct.pack_into('<I', data, 374, rci)
        vectors.append((name, 0, 0, bytes(data)))
    for name, attributes in (('timestamp_clear', 0), ('synch_only', 1),
                             ('origin_only', 2), ('reserved_attributes', 0xfc)):
        data = bytearray(header)
        data[26] = attributes
        vectors.append((name, 0, 0, bytes(data)))
    for name, lhl, tll, rev in (
            ('short_lhl', 491, 512, 3), ('short_tll', 492, 511, 3),
            ('header_past_tll', 496, 512, 3), ('unknown_revision', 492, 512, 4),
            ('empty', 492, 512, 3), ('extended', 496, 520, 3),
            ('tll_bounds_data', 492, 512, 3)):
        data = bytearray(header)
        struct.pack_into('<IQ', data, 4, 0 if name == 'empty' else 1, tll)
        struct.pack_into('<H', data, 18, lhl)
        data[16] = rev
        if name in ('extended', 'tll_bounds_data'):
            data += bytes.fromhex('deadbeef01234567')
        vectors.append((name, 0, 0, bytes(data)))
    vectors.extend([
        ('event_window', 512, 0, bytes.fromhex('01020304')),
        ('large_lpo', 0x100000000, 0, bytes(header)),
        ('offset_overflow', 0xfffffffffffffffc, 8, bytes(header)),
    ])
    utf8_nqn = b'nqn.2026-11.org.example:caf\xc3\xa9'
    data = bytearray(header)
    data[116:372] = utf8_nqn.ljust(256, b'\x00')
    vectors.append(('utf8_nqn', 0, 0, bytes(data)))
    vectors.append(('partial_nqn', 116, 0, bytes(header[116:120])))
    # A window starting at TLL's own offset: bytes past TLL=512 are dropped.
    data = bytearray(header)
    struct.pack_into('<Q', data, 8, 512)
    vectors.append(('tll_bounds_offset', 8, 0,
                    bytes(data[8:]) + bytes.fromhex('deadbeef')))
    return vectors


def build_pel_header_pcapng(output_path):
    packets = []
    for _, offset, doff, data in pel_header_vectors():
        length = doff + len(data)
        numd = length // 4 - 1
        packets.extend([
            make_packet(True, NVME_MI_TYPE_ADMIN, 0, admin_request_payload(
                0x02, cns=0x0d | ((numd & 0xffff) << 16),
                cdw11=numd >> 16, lpo=offset, flags=0,
                doff=doff, dlen=len(data))),
            make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                        admin_response_payload(STATUS_SUCCESS) + data),
        ])
    write_pcapng(output_path, packets, 1713225600 * 1_000_000)


def pel_event(et, etr, data, vsi=b'', ext=b'', ehai=0x01, cntlid=0x0001):
    """A persistent event (Base 2.3 Figure 231): a 24-byte header with
    EHL = 21 + len(ext), then the extension, VSI, and event data."""
    head = bytearray(24)
    head[0:4] = bytes([et, etr, 21 + len(ext), ehai])
    struct.pack_into('<H', head, 4, cntlid)
    head[6:14] = bytes.fromhex('0807060504030100')  # 0x030405060708 ms, Synch, origin 0
    struct.pack_into('<H', head, 14, 0x0010)
    struct.pack_into('<HH', head, 20, len(vsi), len(vsi) + len(data))
    return bytes(head) + ext + vsi + data


def pel_log(events, tnev=None, gnum=1, rce=1):
    """A Persistent Event Log: the 512-byte header (Figure 230), then events."""
    body = b''.join(events)
    header = bytearray(512)
    header[0] = 0x0d
    struct.pack_into('<IQ', header, 4, len(events) if tnev is None else tnev,
                     512 + len(body))
    header[16] = 3
    struct.pack_into('<H', header, 18, 492)
    struct.pack_into('<HI', header, 372, gnum, 0x0002005a | (rce << 18))
    header[480] = 0x3e
    return bytes(header) + body


def pel_mandatory_events():
    smart = bytearray(512)
    smart[0] = 0x01
    struct.pack_into('<H', smart, 1, 310)
    smart[3] = 90
    fwc = (b'OLDFW001' + b'NEWFW002' +
           bytes([0x01, 0x02, 0x00, 0x00]) + struct.pack('<H', 0x1234))
    tsc = bytes.fromhex('0605040302010300') + struct.pack('<Q', 0x1122334455667788)
    desc = lambda cntlid, fa: (struct.pack('<HBB', cntlid, fa, 0x01) + bytes(12) +
                               struct.pack('<IQ', 7, 0x99) +
                               bytes.fromhex('0102030405060200'))
    por = b'FREV0003' + desc(0x0001, 0x01) + desc(0x0002, 0x02)
    pcie = (struct.pack('<HB', 0x0010, 0x01) + bytes(13) +
            bytes(range(0x10, 0x20)) + bytes(range(0x20, 0x30)) +
            bytes(range(0x30, 0x40)) + bytes(range(0x40, 0x50)))
    return [pel_event(0x01, 1, bytes(smart)),
            pel_event(0x02, 1, fwc),
            pel_event(0x03, 1, tsc),
            pel_event(0x04, 1, por),
            pel_event(0x05, 2, struct.pack('<HH', 0x0001, 0) + pcie)]


def pel_hw_error(code, ahei=b''):
    return pel_event(0x05, 2, struct.pack('<HH', code, 0) + ahei)


def pel_event_vectors():
    """MI-5a events: Base 2.3 Figures 229-243.

    Each tuple is (name, LSP, LPO, DOFST, response data). All share one
    endpoint, so one reporting context; order matters.
    """
    v = []
    v.append(('mandatory', 1, 0, 0, pel_log(pel_mandatory_events())))
    v.append(('hw_errors', 1, 0, 0, pel_log([
        pel_hw_error(0x02, struct.pack('<HB', 0x0020, 0x00) + bytes(13)),
        pel_hw_error(0x04, struct.pack('<H', 0x1043)),
        pel_hw_error(0x05),
        pel_hw_error(0x06, bytes([0x05])),
        pel_hw_error(0x07, bytes([0x0c, 0x00]) + struct.pack('<H', 0x0003)),
        pel_hw_error(0x08, struct.pack('<QQ', 42, 0) + bytes([0x01])),
        pel_hw_error(0x09),
        pel_hw_error(0x0a, bytes(range(0xa0, 0xb0))),
        pel_hw_error(0x0b, bytes([0x0d, 0, 0, 0])),
        pel_hw_error(0x0c, bytes.fromhex('cafef00d')),
    ])))
    tsc = bytes.fromhex('0605040302010300') + struct.pack('<Q', 5)
    v.append(('mixed', 1, 0, 0, pel_log([
        pel_event(0x11, 1, bytes.fromhex('0102030405')),
        pel_event(0xdf, 1, bytes.fromhex('aabbcc')),
        pel_event(0x03, 1, tsc, vsi=bytes.fromhex('11223344'),
                  ext=bytes.fromhex('e0e1e2e3'), ehai=0x02),
        pel_event(0x20, 1, b''),
    ])))
    v.append(('tnev_mismatch', 1, 0, 0, pel_log(pel_mandatory_events(), tnev=7)))
    bad_ehl = bytearray(pel_event(0x03, 1, tsc))
    bad_ehl[2] = 20
    v.append(('invalid_ehl', 1, 0, 0,
              pel_log([pel_event(0x03, 1, tsc), bytes(bad_ehl)])))
    bad_vsil = bytearray(pel_event(0x03, 1, tsc))
    struct.pack_into('<H', bad_vsil, 20, 17)
    v.append(('invalid_vsil', 1, 0, 0, pel_log([bytes(bad_vsil)])))
    past = bytearray(pel_event(0x03, 1, tsc))
    struct.pack_into('<H', past, 22, 17)
    v.append(('past_tll', 1, 0, 0, pel_log([bytes(past)])))
    v.append(('revision', 1, 0, 0, pel_log([
        pel_event(0x05, 1, struct.pack('<HH', 0x0004, 0) + b'\x43\x10'),
        pel_event(0x01, 2, bytes(512))])))
    v.append(('short_data', 1, 0, 0, pel_log([
        pel_event(0x02, 1, bytes(10)),
        pel_event(0x04, 1, b'FREV0004' + bytes(20))])))

    # One log read in windows: 03h at 512 (40 bytes), 04h at 552 (68 bytes),
    # 02h at 620 (46 bytes); TLL 666.
    fwc = b'OLDFW001' + b'NEWFW002' + bytes([0x01, 0x02, 0, 0, 0x34, 0x12])
    desc = struct.pack('<HBB', 0x0001, 0x01, 0x00) + bytes(12) + struct.pack('<IQ', 3, 4) + bytes(8)
    log = pel_log([pel_event(0x03, 1, tsc), pel_event(0x04, 1, b'FREV0005' + desc),
                   pel_event(0x02, 1, fwc)])
    assert len(log) == 666
    w = lambda name, lsp, lpo, doff, a, b: v.append((name, lsp, lpo, doff, log[a:b]))
    w('win_header', 1, 0, 0, 0, 512)
    w('win_unknown', 0, 560, 0, 560, 600)
    w('win_first', 0, 512, 0, 512, 552)
    w('win_hdr_cut', 0, 552, 0, 552, 562)
    w('win_body_cut', 0, 552, 0, 552, 582)
    w('win_resume', 0, 560, 20, 580, 666)
    w('win_duplicate', 0, 512, 0, 512, 552)
    w('win_past_tll', 0, 660, 0, 660, 666)
    v[-1] = v[-1][:4] + (log[660:666] + bytes.fromhex('deadbeef0102'),)
    v.append(('ecrh_rce1', 3, 4096, 0, log[:512]))
    w('after_rce1', 0, 620, 0, 620, 666)
    rce0 = pel_log([pel_event(0x03, 1, tsc), pel_event(0x04, 1, b'FREV0005' + desc),
                    pel_event(0x02, 1, fwc)], rce=0)
    v.append(('ecrh_rce0', 3, 0, 0, rce0[:512]))
    w('after_rce0', 0, 620, 0, 620, 666)
    w('relearn', 0, 512, 0, 512, 552)
    gnum2 = pel_log([pel_event(0x03, 1, tsc), pel_event(0x04, 1, b'FREV0005' + desc),
                     pel_event(0x02, 1, fwc)], gnum=2)
    v.append(('gnum_change', 0, 0, 0, gnum2[:512]))
    w('after_gnum', 0, 552, 0, 552, 620)
    v.append(('release', 2, 0, 0, log[:16]))
    v.extend(pel_mi5b_vectors())
    return v


def pel_vse_desc(vsec, vsedt, data, uidx=0):
    """A Vendor Specific Event Descriptor (Base 2.3 Figure 255)."""
    return struct.pack('<HBBH', vsec, vsedt, uidx, len(data)) + data


def pel_set_feature(cdws, mbuf=b'', ccdw0=None, dwc=None):
    """Set Feature event data (Base 2.3 Figure 250)."""
    sfel = ((len(cdws) if dwc is None else dwc) | (8 if ccdw0 is not None else 0) |
            (len(mbuf) << 16))
    return (struct.pack('<I', sfel) + b''.join(struct.pack('<I', c) for c in cdws) +
            mbuf + (b'' if ccdw0 is None else struct.pack('<I', ccdw0)))


def pel_mi5b_vectors():
    """MI-5b events: Base 2.3 Figures 244-256 and Base 2.4 Figure 257.
    Appended after the MI-5a vectors so their frame numbers hold."""
    v = []
    cns = (struct.pack('<I', 0x00000001) + bytes(4) + struct.pack('<Q', 0x1000) +
           bytes(8) + struct.pack('<Q', 0x800) + bytes([0x02, 0x01, 0x01, 0x00]) +
           struct.pack('<IHHI', 5, 1, 2, 0xffffffff))
    assert len(cns) == 48
    fmt_start = struct.pack('<IB3xI', 1, 0x05, 0x00000203)
    fmt_cmpl = struct.pack('<IBBHH2x', 1, 0x00, 0x03, 0xbeef, (0x0281 << 1) | 1)
    san_start = struct.pack('<IIII', 0x60000007, 0x00000202, 0xa5a5a5a5, 0xffffffff)
    san_cmpl = struct.pack('<HHH2xI', 0xffff, 0x0101, 0x0042, 0xffffffff)
    cdp = bytes([0x02, 0x03]) + bytes(10) + bytes.fromhex('c0c1c2')
    ensc_ns = struct.pack('<HB5xII', 0x0007, 0x02, 0x11, 0x22)
    ensc_ctrl = struct.pack('<HB5xII', 0x0007, 0x05, 0x0033, 0x0044)
    v.append(('mi5b_fixed', 1, 0, 0, pel_log([
        pel_event(0x06, 2, cns),
        pel_event(0x07, 1, fmt_start),
        pel_event(0x08, 2, fmt_cmpl),
        pel_event(0x09, 2, san_start),
        pel_event(0x0a, 2, san_cmpl),
        pel_event(0x0d, 1, bytes([0x07, 0x02])),
        pel_event(0x0e, 1, b''),
        pel_event(0x0f, 1, cdp),
        pel_event(0x10, 1, ensc_ns),
        pel_event(0x10, 1, ensc_ctrl),
    ])))
    til = bytearray(512)
    til[0] = 0x07
    struct.pack_into('<H', til, 8, 3)
    vse = (pel_vse_desc(0x0101, 0x01, b'THERMAL\x00') +
           pel_vse_desc(0x0102, 0x04, struct.pack('<q', -5), uidx=1) +
           pel_vse_desc(0x0103, 0x03, bytes.fromhex('0a0b')))
    v.append(('mi5b_variable', 1, 0, 0, pel_log([
        pel_event(0x0b, 1, pel_set_feature([0x00000004, 0x0000015e], mbuf=b'MBUF',
                                           ccdw0=0x12345678)),
        pel_event(0x0c, 1, bytes(til)),
        pel_event(0xde, 1, vse),
        pel_event(0xdf, 7, bytes.fromhex('d0d1')),
    ])))
    v.append(('mi5b_malformed', 1, 0, 0, pel_log([
        pel_event(0x0b, 1, pel_set_feature([0x00000004], mbuf=b'MB')[:-2]),
        pel_event(0xde, 1, pel_vse_desc(0x0201, 0x03, b'abcd')[:-1]),
        pel_event(0x0e, 1, bytes(4)),
        pel_event(0x07, 2, fmt_start),
        pel_event(0x0d, 1, b''),
    ])))
    # A Set Feature event read in two windows: the second resumes after the
    # SFEL and decodes from the layout learned in the first.
    sfe_log = pel_log([pel_event(0x0b, 1, pel_set_feature(
        [0x00000004, 0x0000015e], mbuf=b'MBUF', ccdw0=0x12345678))])
    assert len(sfe_log) == 556
    v.append(('sfe_head', 1, 0, 0, sfe_log[:540]))
    v.append(('sfe_rest', 0, 540, 0, sfe_log[540:]))
    # Namespace Management SEL 0h-3h (Base 2.4 Figure 446).
    v.append(('log1_sel', 1, 0, 0, pel_log([
        pel_event(0x06, 2, struct.pack('<I', sel) + cns[4:]) for sel in range(4)])))
    return v


def build_pel_events_pcapng(output_path):
    packets = []
    for _, lsp, offset, doff, data in pel_event_vectors():
        length = doff + len(data)
        numd = (length + 3) // 4 - 1
        packets.extend([
            make_packet(True, NVME_MI_TYPE_ADMIN, 0, admin_request_payload(
                0x02, cns=0x0d | (lsp << 8) | ((numd & 0xffff) << 16),
                cdw11=numd >> 16, lpo=offset, flags=0,
                doff=doff, dlen=len(data))),
            make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                        admin_response_payload(STATUS_SUCCESS) + data),
        ])
    write_pcapng(output_path, packets, 1713225600 * 1_000_000)


def build_mi4_regressions_pcapng(output_path):
    """Framing, MEB, Figure 139, and Reset response regressions for MI-4."""
    identify = lambda doff, dlen: admin_request_payload(
        0x06, cns=0x01, flags=0, doff=doff, dlen=dlen)
    packets = [
        # A final response after an MPR and Replay has the same message header
        # as the MPR, but is not a replay of that MPR (MI 2.1 §4.2.1.5).
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x10, flags=0, dlen=0),
                    bmc_eid=0xD2, tag=1),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    bytes([STATUS_MPR, 0, 4, 0]), bmc_eid=0xD2, tag=1),
        make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                    cp_request_payload(CP_OPC_REPLAY, tag=0x31),
                    bmc_eid=0xD2, tag=2),
        make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                    cp_response_payload(STATUS_SUCCESS, tag=0x31, cpsr=1),
                    bmc_eid=0xD2, tag=2),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS),
                    bmc_eid=0xD2, tag=2),

        # Non-success status appears in Info after the body decoder's text.
        make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                    cp_request_payload(CP_OPC_PAUSE, tag=0x32), tag=3),
        make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                    cp_response_payload(0x04, tag=0x32), tag=3),
        make_packet(True, NVME_MI_TYPE_MI, 0, mi_request_payload(0x01), tag=4),
        make_packet(False, NVME_MI_TYPE_MI, 0, bytes([0x04, 0, 0, 0]), tag=4),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x10, flags=0, dlen=0), tag=5),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload_short(0x04), tag=5),

        # CIAP/MEB are unused in Control Primitives; IC is mandatory on
        # out-of-band Response Messages (NVMe-MI 2.1 Figures 20 and §4.2.1).
        make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                    cp_request_payload(CP_OPC_PAUSE, tag=0x33), tag=6,
                    meb=True, ciap=True),
        make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                    cp_response_payload(STATUS_SUCCESS, tag=0x33), tag=6,
                    ic=False),

        # With MEB set, Admin data is external: do not compare DLEN with the
        # inline bytes, report a short response, or decode those bytes as TCG.
        make_packet(True, NVME_MI_TYPE_ADMIN, 0, identify(0, 16),
                    tag=7, meb=True),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS), tag=7, meb=True),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0, identify(0, 8),
                    tag=0, meb=True),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS) + ID4,
                    tag=0, meb=True),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(
                        NVME_AQ_OPC_SECURITY_SEND, flags=0,
                        cns=security_cdw10(0x02, 0x0004),
                        dlen=len(tcg_tper_reset_req),
                        cdw11=len(tcg_tper_reset_req)) + tcg_tper_reset_req,
                    tag=1, meb=True),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS), tag=1, meb=True),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(
                        NVME_AQ_OPC_SECURITY_RECV, flags=0,
                        cns=security_cdw10(0x02, 0x0000), dlen=16, cdw11=16),
                    tag=2, meb=True),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS), tag=2, meb=True),

        # Figure 139: zero/nonzero DLEN, no-response DOFST, and known completion
        # bounds. Get Features is selector-dependent: Number of Queues (07h)
        # uses no data buffer, so DLEN 0h is valid (Base 2.4 Figure 466).
        make_packet(True, NVME_MI_TYPE_ADMIN, 0, identify(0, 0), tag=3),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS), tag=3),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x10, flags=0, dlen=4), tag=4),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload_short(0x04), tag=4),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x80, flags=0, doff=8, dlen=0), tag=5),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload_short(0x04), tag=5),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0, identify(0xffc, 8), tag=6),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS) + bytes(8), tag=6),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x02, flags=0, doff=4, dlen=4,
                                          cns=0x02), tag=7),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload_short(0x04), tag=7),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x0a, flags=0, dlen=0, cns=0x07),
                    tag=0),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(STATUS_SUCCESS), tag=0),

        # A successful Reset NVM Subsystem response is not specified to exist.
        make_packet(True, NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0x07, cdw0=0), tag=1),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(STATUS_SUCCESS), tag=1),

        # MI Success with an NVMe CQE error keeps the two status layers distinct.
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x10, flags=0, dlen=0), tag=2),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(
                        STATUS_SUCCESS,
                        cqe3=admin_cqe3(cqe_status_word(sc=0x02))),
                    tag=2),
    ]
    write_pcapng(output_path, packets, 1740000000 * 1_000_000)


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F753-F784 - a MEB command list per port
# ---------------------------------------------------------------------------
#
# DTYP 05h returns the Management Endpoint Buffer Command Support List of the
# port PORTID names (Figure 112), and that list "may be different among
# Management Endpoints" (5.7.6), so a host may read other ports' lists through
# this endpoint.  MEB routing (4.2.3) for the responder's own port -- the
# 2-Wire port whose CMEADDR is the source address (Figure 119) -- follows that
# port's list, whatever was read for another port and in whichever order.
# Port 7 is the responder's, port 8 another.  Each case is its own endpoint,
# on EIDs D2h-D5h, which no other section uses.
#
#   F1-F8    D2h  Port Info 7; list 7 {03h, 05h, 06h}; list 8 {03h};
#                 VPD Read (05h) with MEB set and its response       routed
#   F9-F16   D3h  the same, with the two lists read in the other order routed
#   F17-F24  D4h  list 7 {03h}, list 8 {03h, 05h, 06h}           not routed
#   F25-F32  D5h  both lists, 7's first, before Port Info 7          routed

packets_meb_port_lists = []

def _meb_port_exchange(endpoint, request, response, *, tag=0, meb=False):
    """A request to `endpoint` at 3Ah and its response, over SMBus."""
    for is_request, payload in ((True, request), (False, response)):
        msg = nvme_mi_message(NVME_MI_TYPE_MI, 0, not is_request, payload,
                              meb=meb and is_request)
        packets_meb_port_lists.append(i2c_phdr() + smbus_mctp_frame(
            0x3A if is_request else 0x10, 0x10 if is_request else 0x3A,
            endpoint if is_request else HOST_EID,
            HOST_EID if is_request else endpoint, tag, is_request, msg,
            pec=True))

def _meb_port_info(endpoint, port=7):
    data = bytearray(port_info_twire())
    data[4:8] = struct.pack('<I', 4096)     # MEBS
    data[10] = 0x3A                         # CMEADDR, the responder's address
    _meb_port_exchange(endpoint,
                       mi_request_payload(0, cdw0=(1 << 24) | (port << 16)),
                       mi_response_payload_with_data(0, bytes(data),
                                                     nmresp=len(data)))

def _meb_port_list(endpoint, port, commands):
    data = struct.pack('<H', len(commands)) + b''.join(
        bytes([NVME_MI_TYPE_MI << 3, opc]) for opc in commands)
    _meb_port_exchange(endpoint,
                       mi_request_payload(0, cdw0=(5 << 24) | (port << 16)),
                       mi_response_payload_with_data(0, data, nmresp=len(data)))

def _meb_port_probe(endpoint):
    """VPD Read of 8 bytes with MEB set; routed, its data is in the MEB."""
    _meb_port_exchange(endpoint, mi_request_payload(5, cdw1=8),
                       mi_response_payload(0), tag=1, meb=True)

_meb_port_info(0xD2)
_meb_port_list(0xD2, 7, (3, 5, 6))
_meb_port_list(0xD2, 8, (3,))
_meb_port_probe(0xD2)

_meb_port_info(0xD3)
_meb_port_list(0xD3, 8, (3,))
_meb_port_list(0xD3, 7, (3, 5, 6))
_meb_port_probe(0xD3)

_meb_port_info(0xD4)
_meb_port_list(0xD4, 7, (3,))
_meb_port_list(0xD4, 8, (3, 5, 6))
_meb_port_probe(0xD4)

_meb_port_list(0xD5, 7, (3, 5, 6))
_meb_port_list(0xD5, 8, (3,))
_meb_port_info(0xD5)
_meb_port_probe(0xD5)

BASE_TS_MEB_PORT_LISTS_US = 1713225600 * 1_000_000

def build_meb_port_lists_pcapng(output_path):
    write_pcapng(output_path, packets_meb_port_lists, BASE_TS_MEB_PORT_LISTS_US, idb(link_type=209))


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F785-F791 - an AE Occurrence that overruns the list
# ---------------------------------------------------------------------------
#
# AEOLTL is AEOLHL plus the length of every AE Occurrence (Figure 61), and an
# occurrence is AELHLEN + AEOSIL + AEOVSIL bytes long (Figure 62).  When the
# last occurrence declares more than the list holds, that length field is the
# fault, and AEOLTL is reconciled against the bytes delivered, not against
# the declared stride.  Each list is one AE Occurrence header, NVM Subsystem
# scope, with one length too big.  The AE is vendor AE C1h (Figure 63), except
# in F2: a vendor AE has no Specific Info (Figure 62), so F2 is Composite
# Temperature (06h).
#
#   F1   AEOVSIL 40h; AEOLTL 16, the 16 bytes present
#   F2   AEOSIL 10h; AEOLTL 16, the 16 bytes present
#   F3   AELHLEN 20h; AEOLTL 16, the 16 bytes present
#   F4   F1's occurrence and 4 bytes of its Vendor Specific Info; AEOLTL 16
#        against the 20 bytes present
#   F5   NUMAEO 0 and AEOLHL 20h; AEOLTL 7, the 7 bytes present (AEOLTL is
#        the only field that shows the wrong AEOLHL)
#   F6/F7 an AEM Ack Configuration Set whose Response Data is F1's list, on
#        EID D6h, which no other section uses

def _aeo_overrun_occurrence(aelhlen=AEO_ENTRY_HDR_LEN, aeosil=0, aeovsil=0,
                            ae_id=0xC1):
    """An AE Occurrence header with its three lengths as given."""
    return (bytes([aelhlen, aeosil, aeovsil, ae_id]) + struct.pack('<I', 0)
            + bytes([AEO_SCOPE_SUBSYSTEM]))

_aeo_overrun_vendor = aeo_list([_aeo_overrun_occurrence(aeovsil=0x40)])

packets_aeo_overrun = (
    [aem_packet(_aeo_overrun_vendor),
     aem_packet(aeo_list([_aeo_overrun_occurrence(aeosil=0x10, ae_id=0x06)])),
     aem_packet(aeo_list([_aeo_overrun_occurrence(aelhlen=0x20)])),
     aem_packet(aeo_list([_aeo_overrun_occurrence(aeovsil=0x40)
                          + bytes([0x00, 0x01, 0x02, 0x03])], total_len=16)),
     aem_packet(aeo_list([], hdr_len=0x20, total_len=7))]
    + [make_packet(True, NVME_MI_TYPE_MI, 0,
                   mi_request_payload(0x03, cdw0=NVME_MI_CFGID_AE_ACK_CDW0)
                   + _aem_ack_enable_list, bmc_eid=0xD6, tag=1),
       make_packet(False, NVME_MI_TYPE_MI, 0,
                   mi_response_payload_with_data(STATUS_SUCCESS, _aeo_overrun_vendor),
                   bmc_eid=0xD6, tag=1)]
)

BASE_TS_AEO_OVERRUN_US = 1713312000 * 1_000_000

def build_aeo_overrun_pcapng(output_path):
    write_pcapng(output_path, packets_aeo_overrun, BASE_TS_AEO_OVERRUN_US)


# ---------------------------------------------------------------------------
# nvme-mi-transactions.pcapng F179-F246 - NVMe-MI version responses
# ---------------------------------------------------------------------------
#
# An NVM Subsystem states which revision of NVMe-MI it implements in exactly
# one place: bytes 01 and 02 of the NVM Subsystem Information data structure,
# returned by Read NVMe-MI Data Structure with DTYP 00h (NVMe-MI 2.1
# Figure 112 / 2.2 Figure 115, same offsets).
#
# The dissector keeps no version.  Controller Health Data Structure CSTS bit 8
# and Port Information PRTCAP bit 0 are labeled the same whichever revision an
# endpoint reported, so this file pairs version
# responses, good and inadmissible, with later frames whose labels must not
# change, and checks that none of them leaks from one endpoint to another.
#
# Two interfaces, so that the 2.2 endpoint and the 2.1 endpoint are separated
# by ingress as well as by EID:
#
#   IDB 0  WTAP_ENCAP_SLL   the MI 2.2 endpoint (A)
#   IDB 1  WTAP_ENCAP_SLL   the MI 2.1 endpoint (B) and every negative endpoint
#
# Every endpoint has a distinct EID, so the isolation asserted here does not
# depend on an ingress dimension that the NVMe-MI conversation key does not yet
# have.  Two MCTP networks that reuse an EID pair still
# share one context; that is a separate, already-recorded defect and this file
# deliberately does not encode an expectation about it.
#
# MCTP message tags are reused across endpoints on purpose (tag 0 is used by A,
# B and C; tags 3 and 4 by every negative endpoint).  A tag names a
# transaction, not a subsystem, so tag reuse must not carry one endpoint's
# version to another.
#
# The negative endpoints each pair one inadmissible version response with a
# later frame whose reading would change if it had been believed:
#
#   D  bad MIC          - 3.2.1.1 has the Management Endpoint itself discard a
#                         message whose Message Integrity Check fails
#   E  short body       - Response Data ends before byte 02, valid MIC, so the
#                         truncation is isolated from the integrity question
#   F  error status     - an error response has no Response Data at all; those
#                         bytes are the Parameter Error Location
#   G  orphan           - a response with no request, so nothing says which
#                         command it answers
#   H  MIC sliced away  - a complete, readable body with no integrity evidence
#   I  RDL 4 / 4 bytes   - the version bytes without the structure they belong
#                          to; four bytes is a prefix, not a data structure
#   J  RDL 31 / 31 bytes - the far end of the same incomplete interval
#   K  RDL 32 / 4 bytes  - RDL over-declares; the message contradicts itself
#   L  RDL 0 / 32 bytes  - RDL under-declares; the same contradiction inverted
#   M  bad request MIC   - a complete, conformant response answering a request
#                          the Management Endpoint would have discarded
#   N  sliced request    - the selector was never read, so the zeroes the
#                          request context was allocated with read as DTYP 00h
#   O  RDL 32 / 33 bytes  - a complete 32-byte prefix followed by one surplus
#                          byte; RDL and the body still contradict each other,
#                          and a good integrity check over the extra byte does
#                          not reconcile them
#
# None of them throws: each is decoded to the end, so the file also shows that
# ignoring a version response is not the same as failing to dissect.
#
# The last frame is an Asynchronous Event Message from endpoint A.  It owns its
# MCTP tag, the reverse of a command exchange, so it is the check that endpoint
# identity does not depend on tag ownership.
#
# Frame numbers are load-bearing for the tests, so new vectors belong at the
# end.

VC_HOST_EID = HOST_EID          # 0x0A
VC_EID_A    = 0x08              # reports MI 2.2, then a later, newer version
VC_EID_B    = 0x1D              # reports MI 2.1
VC_EID_C    = 0x2E              # never reports a version
VC_EID_D    = 0x3C              # version response with a bad MIC
VC_EID_E    = 0x4D              # version response whose body stops too soon
VC_EID_F    = 0x5E              # version request answered with an error
VC_EID_G    = 0x6F              # version response with no request
VC_EID_H    = 0x71              # version response cut off by the snaplen
VC_EID_I    = 0x82              # RDL 4 and a four-byte structure prefix
VC_EID_J    = 0x83              # RDL 31 and a thirty-one-byte prefix
VC_EID_K    = 0x84              # RDL 32 but only four Response Data bytes
VC_EID_L    = 0x85              # RDL 0 with a complete 32-byte body
VC_EID_M    = 0x86              # complete exchange whose *request* MIC is bad
VC_EID_N    = 0x87              # request sliced away before its DTYP selector
VC_EID_O    = 0x88              # RDL 32 with a 33-byte body: a surplus tail

# Read NVMe-MI Data Structure, NVMe Management Dword 0: DTYP is bits 31:24.
VC_NMD0_DTYP_SUBSYS = 0x00000000    # DTYP 00h, NVM Subsystem Information
VC_NMD0_DTYP_PORT   = 0x01000000    # DTYP 01h, Port Information, PORTID 0

# Controller Health Status Poll request: ALL=1, MAXRENT=0 (0's based -> 1
# entry), CCF=0 and the CSTS reporting flag set, as in nvme-mi-types.pcapng.
VC_CHSP_NMD0 = 0x80000000
VC_CHSP_NMD1 = 0x00000001

# One Controller Health Data Structure whose CSTS has bit 8 set.  In MI 2.1
# that bit is Telemetry Controller-Initiated Data Available; MI 2.2 retires it
# to "obsolete, shall be set to 1", which is why every conformant 2.2 response
# sets it.  The decoder labels the bit one way whatever version an endpoint
# reported.  Everything else in the entry is held constant so the only
# variable between the endpoints is the version they reported.
def vc_chds_tcida():
    return chds(1, 0x0101, 0x0136, 3, 100, 0x00, 0x0000)

def vc_chsp_pair(eid, tag):
    """Controller Health Status Poll request + response for one endpoint."""
    return [
        make_packet(True,  NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0x02, cdw0=VC_CHSP_NMD0,
                                       cdw1=VC_CHSP_NMD1),
                    host_eid=VC_HOST_EID, bmc_eid=eid, tag=tag),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload_with_data(STATUS_SUCCESS,
                                                  vc_chds_tcida(),
                                                  nmresp=0x010000),
                    host_eid=VC_HOST_EID, bmc_eid=eid, tag=tag),
    ]

def vc_version_request(eid, tag):
    return make_packet(True, NVME_MI_TYPE_MI, 0,
                       mi_request_payload(0x00, cdw0=VC_NMD0_DTYP_SUBSYS),
                       host_eid=VC_HOST_EID, bmc_eid=eid, tag=tag)

def vc_version_response(eid, tag, mjr, mnr, mic=None, data=None, rdl=None):
    """A Read NVMe-MI Data Structure Success response carrying an NVM
    Subsystem Information data structure.

    `data` overrides the 32-byte structure, and `rdl` overrides the Response
    Data Length the NVMe Management Response declares.  By default RDL is the
    length of the body actually sent, which is the conformant relationship;
    passing them separately is how the RDL-disagreement vectors are built.
    """
    body = subsys_info(mjr=mjr, mnr=mnr) if data is None else data
    return make_packet(False, NVME_MI_TYPE_MI, 0,
                       mi_response_payload_with_data(
                           STATUS_SUCCESS, body,
                           nmresp=len(body) if rdl is None else rdl),
                       host_eid=VC_HOST_EID, bmc_eid=eid, tag=tag, mic=mic)

def vc_version_exchange(eid, add, iface=1, tag=3, mjr=2, mnr=2, **kwargs):
    """A complete version request/response pair, then a health exchange whose
    reading is what the version would have qualified.

    Every negative endpoint has this shape: one way of failing admission, then
    a frame that proves the failure left the endpoint unknown rather than
    half-known.
    """
    add(iface, vc_version_request(eid, tag=tag))
    add(iface, vc_version_response(eid, tag=tag, mjr=mjr, mnr=mnr, **kwargs))
    for pkt in vc_chsp_pair(eid, tag=tag + 1):
        add(iface, pkt)

# (interface, packet bytes, reported length or None) triples.
def _vc_packets():
    p = []

    def add(iface, pkt, origlen=None):
        p.append((iface, pkt, origlen))

    # F1-F2  endpoint A, before it has reported anything.  The CSTS bit 8 here
    # must never be read under the 2.2 context that frame F4 establishes:
    # nothing had reported a version yet at this point in the capture, and a
    # two-pass run or a click on this packet must say the same thing a
    # single-pass run does.
    for pkt in vc_chsp_pair(VC_EID_A, tag=5):
        add(0, pkt)

    # F3-F4  endpoint A reports MI 2.2 (MJR 2h / MNR 2h, the row Figure 116
    # adds).  NNSC bit 0 is set, which is what 2.2 requires of it.
    add(0, vc_version_request(VC_EID_A, tag=0))
    add(0, vc_version_response(VC_EID_A, tag=0, mjr=2, mnr=2))

    # F5-F6  endpoint B reports MI 2.1, on the other interface and reusing
    # tag 0.  NNSC bit 0 is set here too -- in 2.1 that is the SRE capability,
    # which implementations later than 1.2 shall set, so the same byte is
    # conformant under both revisions and only its meaning differs.
    add(1, vc_version_request(VC_EID_B, tag=0))
    add(1, vc_version_response(VC_EID_B, tag=0, mjr=2, mnr=1))

    # F7-F10  the same Controller Health Data Structure from each of them.
    for pkt in vc_chsp_pair(VC_EID_A, tag=1):
        add(0, pkt)
    for pkt in vc_chsp_pair(VC_EID_B, tag=1):
        add(1, pkt)

    # F11-F14  the same Port Information structure from each of them, PRTCAP
    # bit 0 set: CIAPS in 2.1, obsolete-shall-be-1 in 2.2 (Figure 114 vs
    # Figure 117).  Bit 1 (AEMS) is set as well so the byte is not a lone bit.
    for iface, eid in ((0, VC_EID_A), (1, VC_EID_B)):
        add(iface, make_packet(True, NVME_MI_TYPE_MI, 0,
                               mi_request_payload(0x00,
                                                  cdw0=VC_NMD0_DTYP_PORT),
                               host_eid=VC_HOST_EID, bmc_eid=eid, tag=2))
        add(iface, make_packet(False, NVME_MI_TYPE_MI, 0,
                               mi_response_payload_with_data(
                                   STATUS_SUCCESS,
                                   port_info_twire(prtcap=0x03), nmresp=32),
                               host_eid=VC_HOST_EID, bmc_eid=eid, tag=2))

    # F15-F16  endpoint C: the identical health response from a subsystem that
    # never reports a version.  Unknown context, and tag 0 again.
    for pkt in vc_chsp_pair(VC_EID_C, tag=0):
        add(1, pkt)

    # F17-F20  endpoint D: a well-formed MI 2.2 version response whose MIC is
    # wrong, then the health response, whose labels must match those of an
    # endpoint that reported no version.
    add(1, vc_version_request(VC_EID_D, tag=3))
    add(1, vc_version_response(VC_EID_D, tag=3, mjr=2, mnr=2,
                               mic=0xDEADBEEF))
    for pkt in vc_chsp_pair(VC_EID_D, tag=4):
        add(1, pkt)

    # F21-F24  endpoint E: a Success response with a valid MIC whose Response
    # Data stops after MJR, so MNR was never reported.  Two bytes, not four:
    # half a version is not a version.
    add(1, vc_version_request(VC_EID_E, tag=3))
    add(1, vc_version_response(VC_EID_E, tag=3, mjr=2, mnr=2,
                               data=bytes([0x01, 0x02])))
    for pkt in vc_chsp_pair(VC_EID_E, tag=4):
        add(1, pkt)

    # F25-F28  endpoint F: the version request answered with Internal Error.
    # An error response carries no Response Data at all.
    add(1, vc_version_request(VC_EID_F, tag=3))
    add(1, make_packet(False, NVME_MI_TYPE_MI, 0,
                       mi_response_payload(0x02), host_eid=VC_HOST_EID,
                       bmc_eid=VC_EID_F, tag=3))
    for pkt in vc_chsp_pair(VC_EID_F, tag=4):
        add(1, pkt)

    # F29-F31  endpoint G: a version response with no request in the capture.
    # A response carries no opcode of its own, so nothing says these bytes are
    # an NVM Subsystem Information data structure.
    add(1, vc_version_response(VC_EID_G, tag=3, mjr=2, mnr=2))
    for pkt in vc_chsp_pair(VC_EID_G, tag=4):
        add(1, pkt)

    # F32-F35  endpoint H: a version response whose MIC the snaplen cut away.
    # The body is complete and readable -- MJR and MNR are both there -- and
    # only the integrity evidence is missing, which is what isolates this
    # vector from endpoint E's: the bytes are believable-looking but nothing
    # vouches for them, and 3.2.1.1 makes an unverified message one the
    # Management Endpoint would itself have discarded had the check failed.
    add(1, vc_version_request(VC_EID_H, tag=3))
    full = vc_version_response(VC_EID_H, tag=3, mjr=2, mnr=2)
    add(1, full[:len(full) - 4], origlen=len(full))
    for pkt in vc_chsp_pair(VC_EID_H, tag=4):
        add(1, pkt)

    # F36-F39  endpoint A advertises MJR 2h / MNR 3h -- a pair in neither
    # Figure 113 nor Figure 116.  Its provenance is unknown: it could be a
    # revision published after those tables, a vendor or prototype encoding,
    # or simply wrong.  What the dissector must not do is call it reserved or
    # invalid, and what it must not conclude is that it is newer than 2.2
    # merely because it is unfamiliar.  It supersedes A's 2.2 advertisement
    # from here on without disturbing what F7-F12 were told.
    add(0, vc_version_request(VC_EID_A, tag=6))
    add(0, vc_version_response(VC_EID_A, tag=6, mjr=2, mnr=3))
    for pkt in vc_chsp_pair(VC_EID_A, tag=7):
        add(0, pkt)

    # F40-F55  the structure/length admission boundary.  MI 2.1 Figure 112 /
    # 2.2 Figure 115 define one 32-byte structure, and the NVMe Management
    # Response declares its length in RDL (bits 15:0).  Four ways for a
    # good-MIC Success response to a good request to fail to be that
    # structure, each with a following health exchange that must still read
    # under no version context:
    #
    #   I  RDL 4  with 4 bytes    the version bytes are there, the structure
    #                             is not: four bytes is a prefix, not a
    #                             32-byte data structure
    #   J  RDL 31 with 31 bytes   the far end of the same interval
    #   K  RDL 32 with 4 bytes    RDL over-declares; the message contradicts
    #                             itself
    #   L  RDL 0  with 32 bytes   RDL under-declares; the same contradiction
    #                             the other way round, and the shape the
    #                             existing nvme-mi-sliced-context.pcapng F6
    #                             happens to have
    full = subsys_info(mjr=2, mnr=2)
    vc_version_exchange(VC_EID_I, add, data=full[:4])
    vc_version_exchange(VC_EID_J, add, data=full[:31])
    vc_version_exchange(VC_EID_K, add, data=full[:4], rdl=32)
    vc_version_exchange(VC_EID_L, add, data=full, rdl=0)

    # F56-F59  endpoint M: a complete, conformant version response whose
    # *request* carried a bad MIC.  The request's DTYP selector is fully
    # captured and parsed, so this isolates the request-integrity condition
    # from the selector-evidence one: section 3.2.1.1 has the Management
    # Endpoint discard a Request Message whose Message Integrity Check fails,
    # so a response paired with this request answers a command that may never
    # have been issued.
    add(1, make_packet(True, NVME_MI_TYPE_MI, 0,
                       mi_request_payload(0x00, cdw0=VC_NMD0_DTYP_SUBSYS),
                       host_eid=VC_HOST_EID, bmc_eid=VC_EID_M, tag=3,
                       mic=0x0BADC0DE))
    add(1, vc_version_response(VC_EID_M, tag=3, mjr=2, mnr=2))
    for pkt in vc_chsp_pair(VC_EID_M, tag=4):
        add(1, pkt)

    # F60-F63  endpoint N: the snaplen cut the request after its opcode, so
    # NVMe Management Dword 0 was never read and the request context keeps its
    # allocated zeroes -- which read as DTYP 00h, the very selector being
    # looked for.  The response is complete and conformant.  This is the shape
    # nvme-mi-sliced-context.pcapng F5/F6 already has, reproduced here where
    # its consequence for the labels can be asserted.
    #
    # Both request-side conditions refuse this one, and that overlap is not
    # accidental: out of band the MIC covers the whole message, so a request
    # whose check passes necessarily had its selector bytes captured.  The
    # selector-evidence condition is still stated separately because it is the
    # direct expression of the invariant -- a zeroed allocation is not a
    # parsed selector -- and it is the condition that survives an in-band
    # caller, which has no MIC at all (section 3.1.1 puts integrity in the
    # out-of-band mechanism only).  Endpoint M isolates the integrity half.
    req = make_packet(True, NVME_MI_TYPE_MI, 0,
                      mi_request_payload(0x00, cdw0=VC_NMD0_DTYP_SUBSYS),
                      host_eid=VC_HOST_EID, bmc_eid=VC_EID_N, tag=3)
    # 16 SLL + 4 MCTP + 4 NVMe-MI header + the opcode byte.
    add(1, req[:16 + 4 + 4 + 1], origlen=len(req))
    add(1, vc_version_response(VC_EID_N, tag=3, mjr=2, mnr=2))
    for pkt in vc_chsp_pair(VC_EID_N, tag=4):
        add(1, pkt)

    # F64  an Asynchronous Event Message from endpoint A.  aem_packet() builds
    # it between HOST_EID and BMC_EID, which are A's pair, and 4.4.4 has the
    # Management Endpoint own the tag -- the reverse of a command exchange.
    # The endpoint key ignores tag ownership, so this frame must resolve to
    # A's context and see A's current version, not no context.  An AEM is
    # never a version *producer*: it owns no Command Slot and answers no
    # request.
    add(0, aem_packet(aeo_list([aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM,
                                          specific=bytes([0x4B]))]), tag=1))

    # F65-F68  endpoint O: RDL 32 with 33 Response Data bytes.  The first 32
    # are a perfectly good NVM Subsystem Information data structure and the
    # message integrity check covers all 33, which is precisely why the extent
    # has to be exact in both directions: a declared length that disagrees
    # with the body present is a contradiction whichever way it points, and a
    # valid-looking prefix inside a longer field is not that field.  Appended
    # after the AEM so that every frame number established earlier is left
    # alone.
    vc_version_exchange(VC_EID_O, add, data=full + b'\x00', rdl=32)

    return p

packets_version_context = _vc_packets()

BASE_TS_VERSION_CONTEXT_US = 1712707200 * 1_000_000

def build_version_context_pcapng(output_path):
    write_pcapng(output_path, [(pkt, origlen, iface) for iface, pkt, origlen in packets_version_context], BASE_TS_VERSION_CONTEXT_US, idb(name='mctp-sll-mi22') + idb(name='mctp-sll-mi21'))


# ---------------------------------------------------------------------------
# nvme-mi-types.pcapng F169-F178 - the complete NVMe-MI Message Type domain
# ---------------------------------------------------------------------------
#
# The NVMe-MI Message Type field is four bits wide, and NVMe-MI 2.1 Figure 20
# (identical in 2.2) assigns every one of its sixteen values: 0h Control
# Primitive, 1h NVMe-MI Command, 2h NVMe Admin Command, 3h Reserved, 4h PCIe
# Command, 5h Asynchronous Event, and 6h to Fh Reserved.
#
# The same field is carried in two places -- the message header, and once per
# entry in the Optionally Supported Command List returned by Read NVMe-MI Data
# Structure with DTYP 04h -- and both places name it from one shared table.
#
# This file supplies the reserved-value vectors, at the boundaries that
# matter: the lone reserved value 3h, the first and last members of the reserved run 6h and
# Fh, and the defined values that sit either side of them, 2h, 4h and 5h.  It
# is a naming fixture and deliberately nothing else -- no version context is
# advertised, no command slot is left outstanding, and each request that opens
# a slot is answered in the next frame on its own MCTP tag.
#
# The reserved header frames are built from the numeric values themselves
# rather than from NVME_MI_TYPE_RESERVED, because the point of the fixture is
# the shape of the domain -- one reserved value on its own and a run of ten --
# and only one of those three values has a name to use.
#
#   F1   header  NMIMT 2h  Admin request, tag 0            defined, below 3h
#   F2   header  NMIMT 2h  Admin response, tag 0           pairs with F1
#   F3   header  NMIMT 3h  reserved singleton              reserved
#   F4   header  NMIMT 4h  PCIe request, tag 1             defined, above 3h
#   F5   header  NMIMT 4h  PCIe response, tag 1            pairs with F4
#   F6   header  NMIMT 5h  Asynchronous Event Message      defined, below 6h
#   F7   header  NMIMT 6h  reserved run, first value       reserved
#   F8   header  NMIMT Fh  reserved run, last value        reserved
#   F9   header  NMIMT 1h  Read NVMe-MI Data Structure request, tag 2
#   F10  header  NMIMT 1h  its response: an Optionally Supported Command List
#                          whose six entries carry NMIMT 2h, 3h, 4h, 5h, 6h
#                          and Fh in turn
#
# The three reserved header frames (F3, F7, F8) each raise the reserved-type
# expert and are decoded no further, which is existing behaviour this file
# holds still while the naming changes around it.

# NUMCMD, then one two-byte entry per value under test: byte 0 is CTYP, whose
# bits 6:3 hold the Message Type (so the value is shifted left three places and
# every other bit left clear), byte 1 is the opcode.  The opcodes are only
# named for 1h and 2h -- entry 0 is Device Self-test, and the rest are bare
# bytes by design, because no opcode table exists for a reserved type.
_NMIMT_CMDLIST = struct.pack('<H', 6) + bytes([
    (0x2 << 3), 0x14,
    (0x3 << 3), 0x01,
    (0x4 << 3), 0x02,
    (0x5 << 3), 0x03,
    (0x6 << 3), 0x04,
    (0xF << 3), 0x05,
])

packets_nmimt_range = [
    make_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01, dlen=4), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS, cqe1=0x00000001) + ID4, tag=0),
    make_packet(True,  0x3, 0, b'\xAA' * 4, tag=3),
    make_packet(True,  NVME_MI_TYPE_PCIE, 0, PCIE_CFG_READ_ID, tag=1),
    make_packet(False, NVME_MI_TYPE_PCIE, 0,
                pcie_response_payload(STATUS_SUCCESS, PCIE_CFG_ID_DATA), tag=1),
    aem_packet(aeo_list([aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM,
                                   specific=bytes([0x4B]))]), tag=5),
    make_packet(True,  0x6, 0, b'\xAA' * 4, tag=6),
    make_packet(True,  0xF, 0, b'\xAA' * 4, tag=7),
    make_packet(True,  NVME_MI_TYPE_MI, 0,
                mi_request_payload(0x00, cdw0=0x04000001), tag=2),
    make_packet(False, NVME_MI_TYPE_MI, 0,
                mi_response_payload_with_data(STATUS_SUCCESS, _NMIMT_CMDLIST,
                                              nmresp=len(_NMIMT_CMDLIST)),
                tag=2),
]

BASE_TS_NMIMT_RANGE_US = 1712793600 * 1_000_000


def build_nmimt_range_pcapng(output_path):
    write_pcapng(output_path, packets_nmimt_range, BASE_TS_NMIMT_RANGE_US, idb(name='mctp-sll-nmimt'))


# ---------------------------------------------------------------------------
# nvme-mi-control.pcapng - the Control Primitive value domain
# ---------------------------------------------------------------------------
#
# Three coverage gaps that no other fixture reaches:
#
#   (2) Resume is the only mandatory Control Primitive opcode with no
#       request/response pair anywhere.  It appears once, unanswered, in
#       nvme-mi-types.pcapng F125-F148.  4.2.1.2 makes both its CPSP and
#       its CPSR entirely Reserved, so the pair is also the cheapest to add.
#
#   (3) Wire-value coverage of the decoded fields.  Against the denominators
#       Figures 42, 43, 46 and 47 define, the committed corpus reaches CPAS 1
#       of 3 meaningful values, SSTA 2 of 4, RR 1 of 2, CESF 1 of 2 and the
#       Control STATUS 1 of 23 classes.  The frames below take CPAS and SSTA
#       to all of theirs, RR and CESF to both, and the STATUS to four classes.
#
#   (4) Reserved and vendor boundaries.  Figure 38 splits the opcode domain
#       05h-EFh Reserved and F0h-FFh Vendor Specific; Figure 29 leaves
#       09h-1Fh and 2Bh-DFh Reserved and E0h-FFh Vendor Specific.  Only the
#       ends of a run can show that the run is placed correctly, so each end
#       is present and nothing in between is.
#
# The NMIMT half of (4) -- 3h, 6h and Fh -- is already covered, completely and
# at both ends of the reserved run, by nvme-mi-types.pcapng F171/F175/F176 and
# by the command-list entries of its F10.  It is deliberately not repeated
# here: a second fixture for the same three values would have to be kept in
# step with the first for no added evidence.
#
#   F1/F2   Resume request and Success response, CPSP/CPSR both zero
#   F3/F4   Resume request and response with every reserved CPSP/CPSR bit set
#   F5/F6   Abort, CPAS 0h (no command was being processed)
#   F7/F8   Abort, CPAS 1h (aborted before it took effect)
#   F9/F10  Abort, CPAS 3h (the Reserved encoding of a two-bit field)
#   F11/F12 Get State, CESF 0, MES SSTA 0h (Idle)
#   F13/F14 Get State, CESF 1, MES SSTA 3h (Transmit)
#   F15/F16 Replay, RR 0 (no response is being replayed)
#   F17/F18 Replay, RR 1 (a response is being replayed)
#   F19/F20 Abort request answered with STATUS 08h, Unable to Abort, whose
#           response body is the Generic Error Response of Figure 30
#   F21/F22 Get State request answered with STATUS 09h, first Reserved value
#   F23/F24 Get State request answered with STATUS 1Fh, last of that run
#   F25/F26 Get State request answered with STATUS 2Bh, second run's first
#   F27/F28 Get State request answered with STATUS DFh, second run's last
#   F29/F30 Get State request answered with STATUS E0h, first Vendor Specific
#   F31/F32 Get State request answered with STATUS FFh, last Vendor Specific
#   F33     request with CPO 05h, first Reserved opcode
#   F34     request with CPO EFh, last Reserved opcode
#   F35/F36 request with CPO F0h, first Vendor Specific opcode, and a response
#   F37/F38 request with CPO FFh, last Vendor Specific opcode, and a response
#
# Every exchange is on its own Management Endpoint EID, so no two share the
# Control Primitive slot and no request displaces another: 4.2.1 permits a
# Management Controller to issue a Control Primitive without waiting for the
# previous one, and the dissector deliberately says nothing about an
# unanswered predecessor, but a fixture that relied on that would be asserting
# the slot model rather than the value domain.  F33 and F34 are unanswered on
# purpose -- a Reserved opcode has no defined response -- and each still sits
# on an EID of its own.

CTL_COV_EID_BASE = 0x40

_ctl_cov_eid = [CTL_COV_EID_BASE]

def _ctl_cov_pair(opcode, cpsp=0, cpsr=0, status=STATUS_SUCCESS, tag=0x11,
                  respond=True, resp_body=None):
    """One Control Primitive exchange on an EID of its own.

    `resp_body`, when given, is the four response body bytes verbatim.  It
    exists because Figures 39 and 40 are the *Success* Response layout, and
    only a Success Response has a Tag at byte 5 and a CPSR at bytes 7:6.  Any
    other status is a Generic Error Response (Figure 30) whose bytes 7:5 are
    Reserved, or an Invalid Parameter Error Response (Figures 31 and 32) whose
    bytes 7:5 are the Parameter Error Location, so writing a tag and a CPSR
    into them would put content in a run the specification has the endpoint
    clear.  cp_response_payload() builds the Success shape and stays the
    default; a status-aware body is passed in where the shape differs.
    """
    eid = _ctl_cov_eid[0]
    _ctl_cov_eid[0] += 1
    out = [make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                       cp_request_payload(opcode, tag=tag, cpsp=cpsp),
                       bmc_eid=eid, tag=1)]
    if respond:
        body = (resp_body if resp_body is not None
                else cp_response_payload(status, tag=tag, cpsr=cpsr))
        assert len(body) == 4, 'a Control Primitive body is exactly 4 bytes'
        out.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0, body,
                               bmc_eid=eid, tag=1))
    return out

# The one conformant defined-error exchange in the file: 4.2.1.3 has an
# endpoint that cannot perform an Abort answer with status 08h, "Unable to
# Abort", so the request is an Abort and not some other primitive.  Its
# response body is the Generic Error Response of Figure 30 -- STATUS at byte 4
# and bytes 7:5 Reserved -- written out in full, because [MI-1] 1.7 has
# hardware return 0h in a Reserved field and this frame is the file's positive
# control for what an ordinary error looks like.  The Reserved-boundary frames
# that follow deliberately keep the Success-shaped body, so the contrast
# between a conformant error response and a merely well-formed one is visible
# in the same file.
_CTL_COV_UNABLE_TO_ABORT = bytes([0x08, 0x00, 0x00, 0x00])

# Figure 43 Management Endpoint State: SSTA is bits 01:00, and the four
# encodings are 0h Idle, 1h Receive, 2h Process and 3h Transmit.  BMICE (bit
# 04) rides along on the Transmit frame so the response is not a single-field
# structure; it is already covered elsewhere and is here only as ballast.
_CTL_COV_MES_IDLE     = 0x0000
_CTL_COV_MES_TRANSMIT = 0x0013     # BMICE | SSTA 3h

packets_control_coverage = (
    # (2) the Resume pair, twice: all-zero, then every reserved bit set.
    _ctl_cov_pair(CP_OPC_RESUME, cpsp=0x0000, cpsr=0x0000)
    + _ctl_cov_pair(CP_OPC_RESUME, cpsp=0xFFFF, cpsr=0xFFFF)

    # (3) CPAS: Figure 42 gives 00b, 01b, 10b and a Reserved 11b.  10b is
    # already in nvme-mi-types.pcapng F58, so the other three are here.
    + _ctl_cov_pair(CP_OPC_ABORT, cpsr=0x0000)
    + _ctl_cov_pair(CP_OPC_ABORT, cpsr=0x0001)
    + _ctl_cov_pair(CP_OPC_ABORT, cpsr=0x0003)

    # (3) CESF both ways and the two SSTA encodings the corpus never reached.
    + _ctl_cov_pair(CP_OPC_GET_STATE, cpsp=0x0000, cpsr=_CTL_COV_MES_IDLE)
    + _ctl_cov_pair(CP_OPC_GET_STATE, cpsp=0x0001, cpsr=_CTL_COV_MES_TRANSMIT)

    # (3) RR both ways.  Figure 46's RRO rides on the request.
    + _ctl_cov_pair(CP_OPC_REPLAY, cpsp=0x0000, cpsr=0x0000)
    + _ctl_cov_pair(CP_OPC_REPLAY, cpsp=0x0007, cpsr=0x0001)

    # (3)/(4) the Control STATUS domain.  08h is the one Figure 29 status the
    # Control section names in its own text (4.2.1.3, an Abort that could not
    # be performed), so it rides on an Abort and carries the Generic Error
    # Response body Figure 30 defines; the rest are the boundaries of the two
    # Reserved runs and of the Vendor Specific run, and keep the Success-shaped
    # body so that the difference is on the wire rather than only in prose.
    + _ctl_cov_pair(CP_OPC_ABORT, resp_body=_CTL_COV_UNABLE_TO_ABORT)
    + _ctl_cov_pair(CP_OPC_GET_STATE, status=0x09)
    + _ctl_cov_pair(CP_OPC_GET_STATE, status=0x1F)
    + _ctl_cov_pair(CP_OPC_GET_STATE, status=0x2B)
    + _ctl_cov_pair(CP_OPC_GET_STATE, status=0xDF)
    + _ctl_cov_pair(CP_OPC_GET_STATE, status=0xE0)
    + _ctl_cov_pair(CP_OPC_GET_STATE, status=0xFF)

    # (4) the opcode domain.  A Reserved opcode has no defined response, so
    # those two are unanswered; the Vendor Specific pair is answered because
    # F0h-FFh is a legal, if unspecified, exchange.
    + _ctl_cov_pair(0x05, respond=False)
    + _ctl_cov_pair(0xEF, respond=False)
    + _ctl_cov_pair(0xF0, cpsr=0xBEEF)
    + _ctl_cov_pair(0xFF, cpsr=0xC0DE)
)

BASE_TS_CONTROL_COVERAGE_US = 1712880000 * 1_000_000


def build_control_coverage_pcapng(output_path):
    write_pcapng(output_path, packets_control_coverage, BASE_TS_CONTROL_COVERAGE_US, idb(name='mctp-sll-control'))


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F1-F74 (FX-I1) - the Read NVMe-MI Data Structure
# response bodies whose *shape* is the thing under test
# ---------------------------------------------------------------------------
#
# Two findings, one file, because both are about a structure returned by
# OPC 00h and both need an exactly-sized control beside the vector:
#
#   A Controller List (DTYP 02h) and an Optionally
#       Supported Command List (DTYP 04h) walk exactly the element count they
#       declare.  Bytes after the last element were in the capture and counted
#       in RDL but appeared nowhere in the tree.  NVMe-MI 2.1 5.7.3, 5.7.5 and
#       5.7.6 make these lists minimally sized, so those bytes are a
#       conformance event and must be both visible and flagged.
#
#   A Controller Information structure (DTYP 03h) whose
#       PCIe Routing ID is an ARI Device's: Figure 120's note replaces the
#       5-bit Device Number and 3-bit Function Number with one 8-bit Function
#       Number, so the legacy split shows two wrong values.
#
# Every exchange is a complete request/response pair on a Management Endpoint
# EID of its own, so no request displaces another's Command Slot and no
# response could link to the wrong one -- the same discipline
# nvme-mi-control.pcapng uses, and for the same reason: this is a
# response-body fixture and a superseded-request note would be noise in it.
#
# F1-F14 are the list-tail and routing-ID vectors; then declared/fixed
# response extents, health-list ordering and VPD windows.
#
#   F1/F2   DTYP 02h Controller List, NUMCIDS 1, RDL 4    exactly sized
#   F3/F4   DTYP 02h Controller List, NUMCIDS 1, RDL 10   6 surplus bytes
#   F5/F6   DTYP 02h Controller List, NUMCIDS 0, RDL 2    empty, exactly sized
#   F7/F8   DTYP 04h Command List,    NUMCMD 1, RDL 4     exactly sized
#   F9/F10  DTYP 04h Command List,    NUMCMD 1, RDL 10    6 surplus bytes
#   F11/F12 DTYP 03h Controller Information, non-ARI Routing ID
#   F13/F14 DTYP 03h Controller Information, ARI Routing ID

MI_STRUCT_EID_BASE = 0x70

#: The six bytes that follow the last declared element in F4 and F10.  Chosen
#: to be recognisable in a filter expression and to decode as nothing in
#: particular: they are surplus, and the point is that they are shown as
#: bytes rather than interpreted.
MI_STRUCT_SURPLUS = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0xAA])

#: PCIe Routing IDs for the Controller Information twins (Figure 120, bytes
#: 07:06, little-endian on the wire).
#:
#: The non-ARI value is a routing ID whose legacy split is meaningful: bus
#: 0Ah, device 03h, function 05h -> 0A18h | 0005h = 0A1Dh.
#:
#: The ARI value is bus 0Bh and the 8-bit Function Number 7Fh -> 0B7Fh.  Read
#: through the legacy split -- which is what the dissector did unconditionally
#: -- it becomes device 0Fh and function 7h: two numbers that are on no bus
#: anywhere, which is the defect this twin exists to show.
MI_STRUCT_PRI_LEGACY = (0x0A << 8) | (0x03 << 3) | 0x05
MI_STRUCT_PRI_ARI    = (0x0B << 8) | 0x7F


def mi_struct_nmd0(dtyp, portid=0, ctrlid=0):
    """Read NVMe-MI Data Structure NVMe Management Dword 0 (Figure 112):
    DTYP 31:24, PORTID 23:16, CTRLID 15:00."""
    return ((dtyp & 0xFF) << 24) | ((portid & 0xFF) << 16) | (ctrlid & 0xFFFF)


def mi_struct_ctrl_list(ctrl_ids, tail=b''):
    """Controller List data structure: NUMCIDS then one uint16le per entry."""
    return (struct.pack('<H', len(ctrl_ids))
            + b''.join(struct.pack('<H', cid) for cid in ctrl_ids) + tail)


def mi_struct_cmd_list(commands, tail=b''):
    """Optionally Supported / MEB Supported Command List (Figures 121-124):
    NUMCMD then one (CTYP, OPC) pair per entry.  CTYP bits 6:3 are the NVMe-MI
    Message Type, bits 7 and 2:0 Reserved."""
    return (struct.pack('<H', len(commands))
            + b''.join(bytes([(nmimt & 0x0F) << 3, opc])
                       for nmimt, opc in commands) + tail)


def mi_struct_ctrl_info(pri, portid=1, prii=0x01):
    """Controller Information data structure (Figure 120), 32 bytes.

    prii defaults to PCIERIV set, which is what a device that has captured its
    routing ID reports; the bit is decoded either way and is not the ARI
    selector (Figure 120 supplies none -- PRII bits 7:1 are Reserved).
    """
    return (bytes([portid]) + bytes(4) + bytes([prii])
            + struct.pack('<H', pri)
            + struct.pack('<HHHH', 0x8086, 0x0A54, 0x8086, 0x3906)
            + bytes([0x00]) + bytes(15))


_mi_struct_eid = [MI_STRUCT_EID_BASE]

#: Frame numbers by name, so the tests can name a vector instead of counting.
MI_STRUCT_FRAMES = {}

packets_mi_structures = []


def _mi_struct_pair(name, dtyp, data, ctrlid=0, portid=0, rdl=None):
    """One Read NVMe-MI Data Structure exchange on an EID of its own."""
    eid = _mi_struct_eid[0]
    _mi_struct_eid[0] += 1
    MI_STRUCT_FRAMES[name + '_req'] = len(packets_mi_structures) + 1
    packets_mi_structures.append(make_packet(
        True, NVME_MI_TYPE_MI, 0,
        mi_request_payload(0x00, cdw0=mi_struct_nmd0(dtyp, portid, ctrlid)),
        bmc_eid=eid, tag=1))
    MI_STRUCT_FRAMES[name] = len(packets_mi_structures) + 1
    packets_mi_structures.append(make_packet(
        False, NVME_MI_TYPE_MI, 0,
        mi_response_payload_with_data(STATUS_SUCCESS, data,
                                      nmresp=len(data) if rdl is None else rdl),
        bmc_eid=eid, tag=1))


_mi_struct_pair('ctrl_list_exact', 0x02, mi_struct_ctrl_list([0x0001]))
_mi_struct_pair('ctrl_list_surplus', 0x02,
                mi_struct_ctrl_list([0x0001], tail=MI_STRUCT_SURPLUS))
_mi_struct_pair('ctrl_list_empty', 0x02, mi_struct_ctrl_list([]))
_mi_struct_pair('cmd_list_exact', 0x04,
                mi_struct_cmd_list([(NVME_MI_TYPE_MI, 0x01)]))
_mi_struct_pair('cmd_list_surplus', 0x04,
                mi_struct_cmd_list([(NVME_MI_TYPE_MI, 0x01)],
                                   tail=MI_STRUCT_SURPLUS))
_mi_struct_pair('ctrl_info_legacy', 0x03,
                mi_struct_ctrl_info(MI_STRUCT_PRI_LEGACY), ctrlid=0x0001)
_mi_struct_pair('ctrl_info_ari', 0x03,
                mi_struct_ctrl_info(MI_STRUCT_PRI_ARI), ctrlid=0x0002)


def _mi_extent_pair(name, opcode, data, *, cdw0=0, cdw1=0, nmresp=0,
                    status=STATUS_SUCCESS, slice_request=False):
    eid = _mi_struct_eid[0]
    _mi_struct_eid[0] += 1
    request = make_packet(True, NVME_MI_TYPE_MI, 0,
                          mi_request_payload(opcode, cdw0=cdw0, cdw1=cdw1),
                          bmc_eid=eid, tag=1)
    MI_STRUCT_FRAMES[name + '_req'] = len(packets_mi_structures) + 1
    # Remove the MIC and the last command byte, retaining the original length.
    packets_mi_structures.append(
        (request[:-5], len(request)) if slice_request else request)
    MI_STRUCT_FRAMES[name] = len(packets_mi_structures) + 1
    packets_mi_structures.append(make_packet(False, NVME_MI_TYPE_MI, 0,
        mi_response_payload_with_data(status, data, nmresp=nmresp),
        bmc_eid=eid, tag=1))


# MI 2.1 Figs 94/96/97: MAXRENT is zero based; RENT is the actual count.
_chds_one = chds(1, 1, 300, 1, 100, 0, 0)
_chds_two = chds(2, 1, 301, 2, 99, 0, 0)
_mi_extent_pair('chds_exact', 2, _chds_one + _chds_two,
                cdw0=1 << 16, nmresp=2 << 16)                    # F16
_mi_extent_pair('chds_short', 2, _chds_one,
                cdw0=1 << 16, nmresp=2 << 16)                    # F18
_mi_extent_pair('chds_surplus', 2, _chds_one + _chds_two,
                cdw0=1 << 16, nmresp=1 << 16)                    # F20
_mi_extent_pair('chds_partial', 2, _chds_one + b'\xaa',
                cdw0=1 << 16, nmresp=2 << 16)                    # F22
_mi_extent_pair('chds_order', 2, _chds_two + _chds_one,
                cdw0=1 << 16, nmresp=2 << 16)                    # F24
_mi_extent_pair('chds_maxrent_invalid', 2, b'', cdw0=0xff << 16,
                status=0x04, nmresp=10 << 8)                     # F25/F26
_mi_extent_pair('chds_over_limit', 2, _chds_one + _chds_two,
                nmresp=2 << 16)                                 # F28
_mi_extent_pair('chds_empty', 2, b'', cdw0=0xfe << 16)              # F30

_subsys = bytes([0, 2, 1, 1]) + bytes(28)
_mi_struct_pair('subsys_exact', 0, _subsys)                        # F32
_mi_struct_pair('rdl_short', 0, _subsys[:16], rdl=32)               # F34
_mi_struct_pair('subsys_short', 0, _subsys[:17])                   # F36
_mi_struct_pair('port_surplus', 1, bytes(32) + MI_STRUCT_SURPLUS,
                rdl=32)                                        # F38
_mi_struct_pair('port_exact', 1, bytes(32))                        # F40
_mi_extent_pair('nshds_exact', 1, nshds())                         # F42
_mi_extent_pair('nshds_short', 1, nshds()[:7])                     # F44
_mi_extent_pair('nshds_long', 1, nshds() + b'\xaa')                 # F46
_mi_extent_pair('nshds_missing', 1, b'')                          # F48

# Figs 131-133: only DLEN selected bytes, not the full FRU, are returned.
_mi_extent_pair('vpd_window', 5, b'\x11\x22\x33\x44',
                cdw0=16, cdw1=4)                                # F50
_mi_extent_pair('vpd_long', 5, b'\x11\x22\x33\x44\x55\x66',
                cdw0=16, cdw1=4)                                # F52
_mi_extent_pair('vpd_short', 5, b'\x11\x22', cdw0=16, cdw1=4)       # F54
_mi_extent_pair('vpd_empty', 5, b'', cdw0=16)                      # F56
_mi_struct_pair('ctrl_info_short', 3,
                mi_struct_ctrl_info(MI_STRUCT_PRI_LEGACY)[:17])   # F58
_mi_struct_pair('subsys_long', 0, _subsys + MI_STRUCT_SURPLUS)      # F60
_mi_struct_pair('list_rdl_surplus', 2,
                mi_struct_ctrl_list([1], MI_STRUCT_SURPLUS),
                rdl=4)                                         # F62
_mi_struct_pair('rdl_missing', 0, b'', rdl=32)                     # F64
_mi_extent_pair('vpd_sliced_request', 5, b'\x11\x22\x33\x44',
                cdw0=16, cdw1=4, slice_request=True)              # F65/F66

# Figs 117-119: complete field prefixes remain readable without the
# reserved tail; an incomplete port-specific prefix remains raw.
_mi_struct_pair('pcie_port_partial', 1, port_info_pcie()[:9])     # F68
_mi_struct_pair('pcie_port_prefix', 1, port_info_pcie()[:14])      # F70
_mi_struct_pair('twire_port_partial', 1, port_info_twire()[:12])   # F72
_mi_struct_pair('twire_port_prefix', 1, port_info_twire()[:13])    # F74

BASE_TS_MI_STRUCTURES_US = 1713052800 * 1_000_000


def build_mi_structures_pcapng(output_path):
    write_pcapng(output_path, packets_mi_structures, BASE_TS_MI_STRUCTURES_US,
                 idb(name='mctp-sll-mi-structures'))


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F350-F373 - log pages whose records are variable-length
# ---------------------------------------------------------------------------
#
# Three log pages have records whose length lives inside the
# record, so a window that does not start at a position the page's own header
# (or a fixed normative position) places cannot be framed at all:
#
#   Asymmetric Namespace Access (LID 0Ch)  ANA Group Descriptor is
#                                          32 + 4 * NNV bytes
#                                          (NVMe Base 2.3 Figure 228)
#   LBA Status Information (LID 0Eh)       Namespace Element is
#                                          16 * (NLRD + 1) bytes
#                                          (NVM CS 1.2 Figures 110/111)
#   Discovery (LID 70h)                    an Extended Discovery Log Page
#                                          Entry is TEL bytes
#                                          (Base 2.3 Figures 311/312)
#
# Each interior window here is a *legal* NVMe-MI transfer -- Figure 203 and
# NVMe-MI 2.2 Figure 139 both require only dword alignment -- that must not be
# decoded confidently and wrongly: mid-list bytes named ANA Group ID / NNV /
# Change Count, an LBA Range Descriptor's RSLBA/RNLB named NEID/NLRD/RATYPE,
# or Discovery entries framed on a 1,024-byte grid the extended format does
# not use.  Every interior frame is therefore paired with
# a control at a position that *is* provable, so "stop decoding interior
# windows" cannot be mistaken for "stop decoding windowed transfers".
#
#   K1/K2    ANA, DOFST 0             full page: header + two descriptors
#   K3/K4    ANA, DOFST 16            Descriptor 0's own boundary
#   K5/K6    ANA, DOFST 32            interior: mid-Descriptor 0
#   K7/K8    LBA Status, DOFST 0      full page: header + one element
#   K9/K10   LBA Status, DOFST 16     the first Namespace Element
#   K11/K12  LBA Status, DOFST 32     interior: an LBA Range Descriptor
#   K13/K14  LBA Status, DOFST 36     dword-aligned, not 16-aligned
#   K15/K16  Discovery, DOFST 0       EXTEND page, TDLPL 3328, TEL 1152 x2
#   K17/K18  Discovery, DOFST 0       legacy page, DLPF 0, two 1,024 entries
#   K19/K20  Discovery, DOFST 2048    Figure 312's fixed position of Entry 1
#   K21/K22  Discovery, DOFST 1536    not a fixed position and not the header

NVME_LID_ANA        = 0x0C
NVME_LID_LBA_STATUS = 0x0E
NVME_LID_DISCOVERY  = 0x70


def _ana_descriptor(grp_id, nsids, state=0x01, chgcnt=0x1122334455667788):
    """One ANA Group Descriptor (NVMe Base 2.3 Figure 228).

    The 15 Reserved bytes are A5h rather than zero on purpose: a window
    starting inside them misread as a fresh descriptor prints ANA Group ID
    A5A5A501h instead of leaving the bytes unplaced."""
    d = struct.pack('<I', grp_id)
    d += struct.pack('<I', len(nsids))
    d += struct.pack('<Q', chgcnt)
    d += bytes([state]) + b'\xA5' * 15
    for n in nsids:
        d += struct.pack('<I', n)
    return d


_lw_ana_page = (struct.pack('<Q', 0x0102030405060708)   # 07:00 Change Count
                + struct.pack('<H', 2)                  # 09:08 NAGD
                + b'\x00' * 6                           # 15:10 Reserved
                + _ana_descriptor(0x11, [0x101])
                + _ana_descriptor(0x22, [0x202]))
assert len(_lw_ana_page) == 16 + 36 + 36


def _lba_range_descriptor(rslba, rnlb):
    """One LBA Range Descriptor (NVM CS 1.2 Figure 111), 16 bytes."""
    return struct.pack('<Q', rslba) + struct.pack('<I', rnlb) + b'\x00' * 4


# One Namespace Element (NVM CS 1.2 Figure 110) with two Range Descriptors.
# RSLBA of the first descriptor is 000000000000002Ah so that a window starting
# on it reads NEID 0000002Ah -- a plausible identifier -- if the modulo-16
# inference ever comes back.
_lw_lba_element = (struct.pack('<I', 0x2A)              # 03:00 NEID
                   + struct.pack('<I', 2)               # 07:04 NLRD
                   + bytes([0x10])                      # 08    RATYPE
                   + b'\x00' * 7                        # 15:09 Reserved
                   + _lba_range_descriptor(0x2A, 0x55556666)
                   + _lba_range_descriptor(0x0123456789ABCDEF, 0xBEEF))
assert len(_lw_lba_element) == 48

_lw_lba_page = (struct.pack('<I', 64)                   # 03:00 LSLPLEN
                + struct.pack('<I', 1)                  # 07:04 NLSLNE
                + struct.pack('<I', 0x99)               # 11:08 ESTULB
                + struct.pack('<H', 0)                  # 13:12 Reserved
                + struct.pack('<H', 0x77)               # 15:14 LSGC
                + _lw_lba_element)
assert len(_lw_lba_page) == 64


def _discovery_entry(trtype, portid, cntlid, extended_attrs=None, tel=None):
    """A Discovery Log Page Entry (Figure 310) or, when extended_attrs is
    given, an Extended Discovery Log Page Entry (Figure 311).

    The first 1,024 bytes are identical in both.  An extended entry adds TEL
    at 1027:1024, NUMEXAT at 1029:1028, Reserved at 1031:1030 and then the
    Extended Attribute list of Figure 533, padded to TEL."""
    r = bytearray(1024)
    r[0] = trtype
    r[1] = 0x01                                          # ADRFAM: IPv4
    r[2] = 0x02                                          # SUBTYPE
    r[3] = 0x1D                                          # TREQ
    struct.pack_into('<H', r, 4, portid)
    struct.pack_into('<H', r, 6, cntlid)
    struct.pack_into('<H', r, 8, 128)                    # ASQSZ
    struct.pack_into('<H', r, 10, 0x0007)                # EFLAGS
    out = bytes(r)
    if extended_attrs is None:
        return out
    attrs = b''
    for exattype, exatval in extended_attrs:
        assert exatval and len(exatval) % 4 == 0
        attrs += struct.pack('<HH', exattype, len(exatval)) + exatval
    body = out + struct.pack('<I', tel)
    body += struct.pack('<H', len(extended_attrs))
    body += b'\x00' * 2                                  # 1031:1030 Reserved
    body += attrs
    assert len(body) <= tel, (len(body), tel)
    return body + b'\x00' * (tel - len(body))


def _discovery_page(entries, dlpf=0, tdlpl=0, numrec=None):
    """Discovery log page (NVMe Base 2.3 Figure 312): a 1,024-byte header then
    the entry list."""
    h = bytearray(1024)
    struct.pack_into('<Q', h, 0, 0x1122334455667788)     # 07:00 GENCTR
    struct.pack_into('<Q', h, 8,
                     len(entries) if numrec is None else numrec)
    struct.pack_into('<H', h, 16, 0)                     # 17:16 RECFMT
    h[18] = dlpf                                         # 18    DLPF
    struct.pack_into('<I', h, 20, tdlpl)                 # 23:20 TDLPL
    return bytes(h) + b''.join(entries)


# Two Extended Discovery Log Page Entries, TEL = 1152 each.  1,152 - 1,032 is
# 120 bytes of Extended Attribute list: a 16-byte Host Identifier (EXATLEN 16,
# so 20 bytes with the header) plus a 96-byte Admin label ASCII (100 bytes),
# which is exactly 120 -- so the second attribute ends on the entry's last
# byte and a walk that mis-strides runs off it visibly.
_LW_TEL = 1152
_lw_ext_entry0 = _discovery_entry(
    0x03, 0x1000, 0x2000, tel=_LW_TEL, extended_attrs=[
        (0x0001, bytes(range(0xC0, 0xD0))),
        (0x0002,
         b'nqn.2014-08.org.nvmexpress.discovery:label-0'.ljust(96, b'\x00')),
    ])
_lw_ext_entry1 = _discovery_entry(
    0x01, 0x1001, 0x2001, tel=_LW_TEL, extended_attrs=[
        (0x0003, 'admin-label-utf8-\u00e9'.encode('utf-8').ljust(20, b'\x00')),
        (0xFF01, bytes(range(0x10, 0x60))),
    ])
assert len(_lw_ext_entry0) == _LW_TEL and len(_lw_ext_entry1) == _LW_TEL

# DLPF 07h sets EXTEND, PORTLCL and ALLSUB at once so all three bits, and the
# 7:3 Reserved run left clear, are testable from one frame.
_lw_disc_extended = _discovery_page([_lw_ext_entry0, _lw_ext_entry1],
                                    dlpf=0x07, tdlpl=1024 + 2 * _LW_TEL)
assert len(_lw_disc_extended) == 1024 + 2 * _LW_TEL

_lw_disc_legacy = _discovery_page([_discovery_entry(0x03, 0x3000, 0x4000),
                                   _discovery_entry(0x01, 0x3001, 0x4001)],
                                  dlpf=0x00, tdlpl=0)
assert len(_lw_disc_legacy) == 3072


def _lw_pair(lid, doff, data, tag):
    """A Get Log Page request/response pair over NVMe-MI at Data Offset
    `doff`, with the response carrying exactly the bytes the request's Data
    Length selects."""
    return [
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                          ctrl_id=0x0001, flags=0x00,
                                          cns=lid, doff=doff,
                                          dlen=len(data)), tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(data), tag=tag),
    ]


# Base 2.3 Figure 220: TCS is byte 381, not the Host-Initiated byte 380;
# bytes 380:20 are Reserved and there is no Host Data Generation Number.
_lw_telemetry_controller = bytearray(512)
_lw_telemetry_controller[0] = 0x08
_lw_telemetry_controller[381] = 0x02  # NVM subsystem scope
_lw_telemetry_controller[383] = 0x5A  # Controller Data Generation Number

packets_logpage_windows = (
    # K1..K6 -- ANA at the header, at Descriptor 0 and inside it
    _lw_pair(NVME_LID_ANA, 0, _lw_ana_page, 0)
    + _lw_pair(NVME_LID_ANA, 16, _lw_ana_page[16:], 1)
    + _lw_pair(NVME_LID_ANA, 32, _lw_ana_page[32:], 2)
    # K7..K14 -- LBA Status at the header, at Element 0, on a Range Descriptor
    # and at a dword-aligned offset that is not a multiple of 16
    + _lw_pair(NVME_LID_LBA_STATUS, 0, _lw_lba_page, 3)
    + _lw_pair(NVME_LID_LBA_STATUS, 16, _lw_lba_page[16:], 4)
    + _lw_pair(NVME_LID_LBA_STATUS, 32, _lw_lba_page[32:], 5)
    + _lw_pair(NVME_LID_LBA_STATUS, 36, _lw_lba_page[36:], 6)
    # K15/K16 -- the extended Discovery page, whole
    + _lw_pair(NVME_LID_DISCOVERY, 0, _lw_disc_extended, 7)
    # K17/K18 -- the legacy control: DLPF cleared, 1,024-byte entries
    + _lw_pair(NVME_LID_DISCOVERY, 0, _lw_disc_legacy, 0)
    # K19/K20 -- Figure 312's fixed position of Entry 1 on the legacy page
    + _lw_pair(NVME_LID_DISCOVERY, 2048, _lw_disc_legacy[2048:], 1)
    # K21/K22 -- half an entry in: neither the header nor a fixed position
    + _lw_pair(NVME_LID_DISCOVERY, 1536, _lw_disc_legacy[1536:], 2)
    # K23/K24 -- Controller-Initiated telemetry's distinct header branch
    + _lw_pair(0x08, 0, bytes(_lw_telemetry_controller), 3)
)

BASE_TS_LOGPAGE_WINDOWS_US = 1709390000 * 1_000_000


def build_logpage_windows_pcapng(output_path):
    write_pcapng(output_path, packets_logpage_windows, BASE_TS_LOGPAGE_WINDOWS_US, idb(name='mctp-sll-logpage-windows'))


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F171-F230 - the Admin window's own contracts
# ---------------------------------------------------------------------------
#
# Five separate rules about an NVMe-MI Admin window, each of
# which the dissector got wrong in a way that produced confident output:
#
#   Data Length bounds the *selected* response data (NVMe-MI 2.2 Figure 139);
#   an Identify list subtree may not claim more bytes than arrived;
#   Data Offset is absolute and only dword-aligned, so a Feature transfer's
#     records can start mid-window;
#   the direction a block travelled decides which structure it is;
#   a completion is successful only when SCT and SC are both 0h
#     (NVMe Base 2.3 Figures 96/101/102/103).
#
#   J1/J2    DLEN 8, 16-byte response      only the 8 selected bytes decode
#   J3/J4    DLEN 16, 16-byte response     the control
#   J5/J6    Identify CNS 04h, 176 bytes   partial NVM Set List entry
#   J7/J8    Identify CNS 15h, 48 bytes    partial Secondary Controller entry
#   J9/J10   Identify CNS 04h, 256 bytes   the whole-entry control
#   J11/J12  Identify CNS 15h, 64 bytes    the whole-entry control
#   J13/J14  Get Features 03h, DOFST 4     LBA Range Type out of phase
#   J15/J16  Get Features 03h, DOFST 0     the aligned control
#   J17/J18  Get Features 0Ch, DOFST 4     APST out of phase
#   J19/J20  Get Log Page request + tail   request data is not a log page
#   J21/J22  Identify request + tail       request data is not an Identify
#   J23/J24  Set Features request + data   the legitimate-request-data control
#   J25/J26  Set Features SCT 1h / SC 0h   a failure the SC-only test missed
#   J27/J28  Set Features SCT 0h / SC 0h   the success control
#   J29/J30  Get Features SCT 0h / SC 6h   a failed Get Features completion
#   J31/J32  Get Features SCT 0h / SC 0h   the success control
#   J33/J34  Get Log Page NUMD FFFFFFFFh   the maximum transfer size
#   J35/J36  Get Log Page NUMD 00000000h   the minimum control
#   J37/J38  Get Log Page NUMD FFFFFFFEh   the neighbouring control
#   J39/J40  response with CQE DW3 CID     a Command Id that must be 0h
#   J41/J42  response with CID 0h          the conformant control

NVME_LID_VENDOR_C0 = 0xC0
F_NUM_OF_QUEUES    = 0x07
F_POWER_MGMT       = 0x02
F_ERROR_RECOVERY   = 0x05
F_RSRV_NOT_MASK    = 0x82


def _aw_resp(data=b'', status=STATUS_SUCCESS, dw0=0, sct=0, sc=0, cid=0):
    """An Admin Success Response whose CQE dwords are stated explicitly."""
    cqe3 = admin_cqe3(cqe_status_word(sct=sct, sc=sc, phase=1), cid=cid)
    return admin_response_payload(status, cqe1=dw0, cqe3=cqe3) + data


def _aw_numd_cdws(lid, numd):
    """CDW10 and CDW11 for a Get Log Page whose combined NUMD is `numd`.

    NUMD is one 0's based dword count split across the dword boundary: NUMDL
    is CDW10 bits 31:16 and NUMDU is CDW11 bits 15:00 (NVMe Base 2.3 Figure
    203), which the dissector reads as one little-endian 32-bit field at
    request bytes 45:42."""
    return (lid | ((numd & 0xFFFF) << 16)), ((numd >> 16) & 0xFFFF)


def _aw_nvmset_entry(nvmsetid, endgid, r4krt, ows):
    """An NVM Set Attributes Entry through UNVMSC (NVMe Base 2.3 CNS 04h)."""
    return (struct.pack('<HH', nvmsetid, endgid) + b'\x00' * 4
            + struct.pack('<II', r4krt, ows)
            + bytes(range(0x40, 0x50)) + bytes(range(0x50, 0x60)))


# CNS 04h NVM Set List: a 1-byte NUMENT header, entries from structure offset
# 128, each 128 bytes.  176 bytes is one entry's first 48 -- through UNVMSC,
# which is exactly what the loop's guard admits and what a fixed 128-byte
# subtree extent then overran.
assert len(_aw_nvmset_entry(1, 2, 3, 4)) == 48
_aw_nvmset_full = (bytes([1]) + b'\x00' * 127
                   + _aw_nvmset_entry(0x0101, 0x0202, 0x03030303, 0x04040404)
                   + b'\x00' * 80)
assert len(_aw_nvmset_full) == 256
_aw_nvmset_partial = _aw_nvmset_full[:176]


def _aw_scl_entry(scid, pcid, scs, vfn, nvq, nvi):
    """A Secondary Controller Entry (NVMe Base 2.3 CNS 15h), 32 bytes."""
    return (struct.pack('<HH', scid, pcid) + bytes([scs]) + b'\x00' * 3
            + struct.pack('<HHH', vfn, nvq, nvi) + b'\x00' * 18)


# CNS 15h Secondary Controller List: a 1-byte NUMENT header, entries from
# structure offset 32, each 32 bytes.  48 bytes is one entry's first 16 --
# past NVI at 13:12, which the guard admits and a fixed 32-byte extent
# overran.
assert len(_aw_scl_entry(1, 2, 3, 4, 5, 6)) == 32
_aw_scl_full = (bytes([1]) + b'\x00' * 31
                + _aw_scl_entry(0x0111, 0x0222, 0x01, 0x0333, 0x0444, 0x0555))
assert len(_aw_scl_full) == 64
_aw_scl_partial = _aw_scl_full[:48]


def _aw_lbart_entry(type_, attr, slba, nlb, guid):
    """One LBA Range Type data structure entry (NVM CS 1.2 Figure 95)."""
    return (bytes([type_, attr]) + b'\x00' * 14
            + struct.pack('<Q', slba) + struct.pack('<Q', nlb)
            + guid + b'\x00' * 16)


# Three LBA Range Type entries.  The DOFST = 4 window starts 4 bytes into
# entry 0, so 60 bytes of it are a partial leader and entries 1 and 2 follow
# whole -- the phase and the caption index must account for the offset, and
# each entry's Type/SLBA/NLB differ so a wrong phase shows as a wrong number.
_aw_lbart_three = (
    _aw_lbart_entry(0x02, 0x03, 0x1000, 0x00FF, bytes(range(0xC0, 0xD0)))
    + _aw_lbart_entry(0x03, 0x01, 0x2000, 0x01FF, bytes(range(0xD0, 0xE0)))
    + _aw_lbart_entry(0x04, 0x02, 0x3000, 0x02FF, bytes(range(0xE0, 0xF0))))
assert len(_aw_lbart_three) == 192

# Non-Operational Power State Transition entries are 8 bytes each (NVMe Base
# 2.3 Auto Power State Transition).  DOFST = 4 puts the window half an entry
# in; the two whole entries that follow are entries 1 and 2 of the table.
_aw_apst_window = (b'\xAA\xBB\xCC\xDD'
                   + struct.pack('<Q', 0x0011223344556677)
                   + struct.pack('<Q', 0x8899AABBCCDDEEFF))
assert len(_aw_apst_window) == 20

# The 32-byte tail on a Get Log Page request.  Its first bytes spell a
# plausible SMART log page header, so a decoder that treats a request tail
# as a response structure produces named fields rather than nothing.
_aw_getlog_tail = bytes([0x01]) + struct.pack('<H', 0x0140) + b'\x00' * 29
assert len(_aw_getlog_tail) == 32

# The 16-byte tail on an Identify request: bytes that read as VID, SSVID and
# the start of SN in an Identify Controller data structure.
_aw_identify_tail = struct.pack('<HH', 0x8086, 0x8086) + b'PHYS12345678'
assert len(_aw_identify_tail) == 16

_aw_lba_status_header = (struct.pack('<I', 64)       # 03:00 LSLPLEN
                         + struct.pack('<I', 1)      # 07:04 NLSLNE
                         + struct.pack('<I', 0x99)   # 11:08 ESTULB
                         + struct.pack('<H', 0)      # 13:12 Reserved
                         + struct.pack('<H', 0x77))  # 15:14 LSGC
assert len(_aw_lba_status_header) == 16

_aw_numd_max_cdw10, _aw_numd_max_cdw11 = _aw_numd_cdws(NVME_LID_VENDOR_C0,
                                                       0xFFFFFFFF)
_aw_numd_min_cdw10, _aw_numd_min_cdw11 = _aw_numd_cdws(NVME_LID_VENDOR_C0, 0)
_aw_numd_near_cdw10, _aw_numd_near_cdw11 = _aw_numd_cdws(NVME_LID_VENDOR_C0,
                                                         0xFFFFFFFE)


# NVMe Base 2.3 Figure 328 defines the Power State Descriptors as thirty-two
# independent 32-byte fields (PSD0 at 2079:2048 ... PSD31 at 3071:3040), the
# Fabric Specific attributes as nine fields in 2047:1792, and 4095:3072 as
# Vendor Specific; NVMe-MI 2.2 Figure 139 lets a window start at any dword
# and end at any dword.  The decoder gated each block on the whole block
# being in the window, so a read of one descriptor, or a 512-byte chunk
# holding sixteen whole ones, rendered nothing.  Each descriptor names
# itself (MP 1000h+i, ENLAT 100+i, EXLAT 200+i, MBWS 3) so a wrong index
# reads as a wrong number; Vendor Specific byte k is k mod 256.
def _aw_psd(idx):
    """One Figure 329 Power State Descriptor, 32 bytes, that says which one it is."""
    return (struct.pack('<HBB', 0x1000 + idx, 0, 0)
            + struct.pack('<II', 100 + idx, 200 + idx)
            + bytes(17) + bytes([3]) + bytes(2))


assert len(_aw_psd(0)) == 32
_aw_idctrl = bytearray(4096)
_aw_idctrl[1792:1800] = struct.pack('<II', 4, 1)      # IOCCSZ 4, IORCSZ 1
_aw_idctrl[1803] = 0x10                                # MSDBD
_aw_idctrl[1807] = 4                                   # CCRL
for _i in range(32):
    _aw_idctrl[2048 + 32 * _i:2048 + 32 * (_i + 1)] = _aw_psd(_i)
_aw_idctrl[3072:4096] = bytes(range(256)) * 4
_aw_idctrl = bytes(_aw_idctrl)


def _aw_idctrl_pair(doff, dlen, tag):
    """An Identify Controller request for the window [doff, doff+dlen) and
    the response carrying exactly that slice of the image."""
    return [
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                          flags=0x00, cns=0x01, doff=doff,
                                          dlen=dlen), tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(_aw_idctrl[doff:doff + dlen]), tag=tag),
    ]


packets_admin_window = [
    # J1/J2 Data Length selects 8 of the 16 bytes the response carries.  The
    # LBA Status Information header is 16 bytes of four fields (NVM CS 1.2
    # Figure 109), so "only the selected bytes decoded" is an absence of the
    # last two rather than a difference in one.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=NVME_LID_LBA_STATUS,
                                      doff=0, dlen=8), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_lba_status_header), tag=0),
    # J3/J4 the control: the same response under a Data Length that selects
    # all of it.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=NVME_LID_LBA_STATUS,
                                      doff=0, dlen=16), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_lba_status_header), tag=1),

    # J5/J6 NVM Set List with 176 bytes present: entry 0 is admitted by the
    # loop's own guard and a fixed 128-byte subtree then reached byte 256.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x04, doff=0,
                                      dlen=176), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_nvmset_partial), tag=2),
    # J7/J8 Secondary Controller List with 48 bytes present: the same shape a
    # quarter the size.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x15, doff=0,
                                      dlen=48), tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_scl_partial), tag=3),
    # J9/J10 and J11/J12 the whole-entry controls for both lists.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x04, doff=0,
                                      dlen=256), tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_nvmset_full), tag=4),
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x15, doff=0,
                                      dlen=64), tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_scl_full), tag=5),

    # J13/J14 LBA Range Type at Data Offset 4: 60 bytes of entry 0, then
    # entries 1 and 2 whole.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_LBA_RANGE_TYPE, doff=4,
                                      dlen=188), tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_lbart_three[4:]), tag=6),
    # J15/J16 the aligned control: the same records from byte 0.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_LBA_RANGE_TYPE, doff=0,
                                      dlen=192), tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_lbart_three), tag=7),
    # J17/J18 Auto Power State Transition at Data Offset 4.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x0C, doff=4,
                                      dlen=len(_aw_apst_window)), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_apst_window), tag=0),

    # J19/J20 a Get Log Page *request* carrying a 32-byte tail.  Get Log Page
    # defines data in the controller-to-host direction only, so these bytes
    # are not a log page however much they look like one.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=0x02, doff=0,
                                      dlen=len(_aw_getlog_tail))
                + _aw_getlog_tail, tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=1),
    # J21/J22 the same for Identify.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x01, doff=0,
                                      dlen=len(_aw_identify_tail))
                + _aw_identify_tail, tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS) + _aw_idctrl[:16], tag=2),
    # J23/J24 the control: Set Features *does* define host-to-controller data,
    # so its request data decodes exactly as before.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_LBA_RANGE_TYPE, doff=0, dlen=64)
                + _aw_lbart_three[:64], tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=3),

    # J25/J26 Set Features Number of Queues completing with SCT 1h and SC 0h
    # -- a Command Specific Status that Figure 104 does not define for Set
    # Features.  The SC-only success test read this as a success and decoded
    # NCQA/NSQA out of Dword 0.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_NUM_OF_QUEUES, doff=0, dlen=0),
                tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                _aw_resp(dw0=0x000F000F, sct=1, sc=0), tag=4),
    # J27/J28 the success control for the same Feature.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_NUM_OF_QUEUES, doff=0, dlen=0),
                tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                _aw_resp(dw0=0x000F000F, sct=0, sc=0), tag=5),
    # J29/J30 Get Features Power Management completing with SC 6h (Internal
    # Error).  The Get Features arm checked no status at all.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_POWER_MGMT, doff=0, dlen=0),
                tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                _aw_resp(dw0=0x0000001F, sct=0, sc=6), tag=6),
    # J31/J32 the success control for the same Feature.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_POWER_MGMT, doff=0, dlen=0),
                tag=7),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                _aw_resp(dw0=0x0000001F, sct=0, sc=0), tag=7),

    # J33/J34 the largest NUMD the field can express.  (NUMD + 1) * 4 is
    # 17,179,869,184 bytes; computed 32-bit it wrapped to 0.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=_aw_numd_max_cdw10,
                                      cdw11=_aw_numd_max_cdw11,
                                      doff=0, dlen=0), tag=0),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=0),
    # J35/J36 the minimum: NUMD 0h is one dword.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=_aw_numd_min_cdw10,
                                      cdw11=_aw_numd_min_cdw11,
                                      doff=0, dlen=0), tag=1),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=1),
    # J37/J38 the neighbour: one dword below the maximum, which the 32-bit
    # computation got right, so the pair isolates the wrap.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_GET_LOG_PAGE,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=_aw_numd_near_cdw10,
                                      cdw11=_aw_numd_near_cdw11,
                                      doff=0, dlen=0), tag=2),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=2),

    # J39/J40 a response whose CQE Dword 3 Command Id is 1234h.  NVMe-MI
    # requires it cleared to 0h and the dissector had no field for it.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x01, doff=0, dlen=0),
                tag=3),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                _aw_resp(cid=0x1234), tag=3),
    # J41/J42 the conformant control.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x01, doff=0, dlen=0),
                tag=4),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                _aw_resp(cid=0x0000), tag=4),

    # J43/J44 Set Features Error Recovery (FID 05h) with Command Dword 11
    # FFFF1234h.  NVM CS 1.2 Figure 96 reserves bits 31:17, but the Reserved
    # field's mask was 00FE0000h -- bits 23:17 -- so the whole high byte fell
    # outside every field of the dword and a controller setting it looked
    # conformant.  DULBE (bit 16) is set and TLER is 1234h so the two defined
    # fields are non-zero too, which is what makes "the Reserved item took
    # them" distinguishable from "the Reserved item widened".
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_ERROR_RECOVERY,
                                      cdw11=0xFFFF1234, doff=0, dlen=0),
                tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=5),
    # J45/J46 Set Features Reservation Notification Mask (FID 82h) with
    # Command Dword 11 FFFFFFFFh.  NVMe Base 2.3 Figure 468 reserves 31:04 and
    # bit 00; the 31:04 mask was 00FFFFF0h, so bits 31:24 belonged to no field
    # at all.  Every defined bit is set as well, so the three notification
    # masks and the bit-0 Reserved run stay separable from the widened run.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_SET_FEATURES,
                                      ctrl_id=0x0001, flags=0x00,
                                      cns=F_RSRV_NOT_MASK,
                                      cdw11=0xFFFFFFFF, doff=0, dlen=0),
                tag=6),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_response_payload(STATUS_SUCCESS), tag=6),

    # J47/J48 PSD1 alone (DOFST 2080, DLEN 32): the window starts inside the
    # table, which the `off <= 2048` guard skipped outright.
    *_aw_idctrl_pair(2080, 32, 7),
    # J49/J50 PSD0 whole and the first 16 bytes of PSD1 (2048/48): the one
    # Mandatory descriptor, in a window that ends before the table does.
    # The cut descriptor is not rendered, and the table item covers the 48
    # bytes present rather than the table's 1024.
    *_aw_idctrl_pair(2048, 48, 0),
    # J51/J52 a 512-byte chunk of the table (2048/512): PSD0..PSD15 whole.
    *_aw_idctrl_pair(2048, 512, 1),
    # J53/J54 the 512-byte chunk before it (1536/512): 256 bytes of the
    # 1791:1024 Reserved run and the Fabric Specific block whole, ending
    # exactly at 2048 -- the control.
    *_aw_idctrl_pair(1536, 512, 2),
    # J55/J56 sixteen bytes inside Vendor Specific (3080/16).
    *_aw_idctrl_pair(3080, 16, 3),
    # J57/J58 a window across the boundary (2000/128): the last 48 bytes of
    # the Fabric Specific Reserved run -- no whole field, so the block item
    # has no children -- then PSD0 and PSD1 whole and 16 bytes of PSD2.
    *_aw_idctrl_pair(2000, 128, 4),

    # J59/J60 the other direction of the Data Length check.  DOFST 24, DLEN 40
    # selects Identify Controller bytes 63:24 -- an acceptable window -- and
    # the response carries 16 of the 40.  Figure 139: DLEN bytes "shall be
    # returned", so the Success is short and is noted; J2 above is the
    # over-long twin.
    make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                admin_request_payload(NVME_AQ_OPC_IDENTIFY, ctrl_id=0x0001,
                                      flags=0x00, cns=0x01, doff=24, dlen=40),
                tag=5),
    make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                admin_resp_with_data(_aw_idctrl[24:40]), tag=5),
]

BASE_TS_ADMIN_WINDOW_US = 1709391000 * 1_000_000


def build_admin_window_pcapng(output_path):
    write_pcapng(output_path, packets_admin_window, BASE_TS_ADMIN_WINDOW_US, idb(name='mctp-sll-admin-window'))


def tcg_m5_validation_vectors():
    """Core 2.01 Tables 20/21, 31/33/34/39/42/43; SIIS 1.20
    Tables 2/24; Base 2.3 Fig 395; MI 2.2 Fig 139.

    Return (interface, packet) records and exact case-to-frame pairs. Native
    NVMe/TCP carries byte-granular AL=2 without violating MI's aligned DLEN.
    SPC-5/SSC layouts are not decoded.
    """
    packets, cases = [], {}

    def pair(name, payload, secp=1, spsp=1, send=False, al=None):
        assert name not in cases
        frame = len(packets) + 1
        cases[name] = (frame, frame + 1)
        al = len(payload) if al is None else al
        assert len(payload) % 4 == 0
        tag = (frame // 2) % 8
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV,
            ctrl_id=1, flags=0, cns=security_cdw10(secp, spsp),
            cdw11=al, dlen=len(payload))
        packets.extend(((0, make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                                         request + (payload if send else b''), tag=tag)),
                        (0, make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                         admin_resp_with_data(b'' if send else payload), tag=tag))))

    def l0(features=b'', major=0, minor=1, plen=None):
        return struct.pack('>IHH', 44 + len(features) if plen is None else plen,
                           major, minor) + bytes(40) + features

    bodies = {1: b'\x41' + bytes(11), 2: b'\x03' + bytes(11),
              5: b'\x20\x05' + bytes(10)}
    features = {code: tcg_l0_feature(code, 1, body) for code, body in bodies.items()}
    all_features = b''.join(features.values())
    pair('l0-valid', l0(all_features))
    pair('l0-duplicate', l0(features[1] + features[1]))
    pair('l0-descending', l0(features[2] + features[1]))
    for code, body in bodies.items():
        for length in (0, 4, 16):
            pair(f'l0-{code}-length-{length}',
                 l0(tcg_l0_feature(code, 1, (body + bytes(4))[:length])))
        pair(f'l0-{code}-reserved', l0(tcg_l0_feature(code, 1, body[:-1] + b'\x80')))
        pair(f'l0-{code}-future', l0(tcg_l0_feature(code, 2, b'\xa5' * 16)))
    pair('l0-future-major', l0(all_features, major=1))
    pair('l0-future-minor', l0(all_features, minor=2))
    pair('l0-short-length', l0(plen=43))
    pair('l0-short-length-prefix', l0(plen=43)[:16])
    pair('l0-selected-header', l0(all_features)[:16])
    pair('l0-selected-feature', l0(all_features)[:52])
    pair('l0-unknown', l0(tcg_l0_feature(0x7777, 9, b'\xa5' * 4)))
    pair('l0-padding', l0(all_features) + bytes(4))

    def mgmt(code, available, body=b''):
        return struct.pack('>HHIHH', 0x1000, 1, code, 0, available) + body

    pair('no-response-valid', mgmt(0, 0) + bytes(4), secp=2, spsp=0x1000)
    pair('no-response-body', mgmt(0, 4, b'\xa1\xa2\xa3\xa4') + bytes(4),
         secp=2, spsp=0x1000)
    pair('no-response-header', mgmt(0, 4), secp=2, spsp=0x1000)
    pair('verify-partial-body', mgmt(1, 34, b'\x00\x00\x00\x03'),
         secp=2, spsp=0x1000)
    date = struct.pack('>HBBBBBHB', 2026, 9, 5, 12, 34, 56, 500, 0)
    expiry = struct.pack('>HBBBBBHB', 2026, 9, 5, 12, 35, 56, 500, 0)
    pair('verify-dates', mgmt(1, 34, b'\x00\x00\x00\x03' + date + expiry + date) + bytes(2),
         secp=2, spsp=0x1000)
    pair('unknown-response', mgmt(3, 4, b'\xa1\xa2\xa3\xa4') + bytes(4),
         secp=2, spsp=0x1000)
    pair('unknown-response-prefix', mgmt(3, 8, b'\xa1\xa2\xa3\xa4'),
         secp=2, spsp=0x1000)
    for code in (1, 2, 3, 0):
        pair(f'send-code-{code}', struct.pack('>HHI', 0x1000, 1, code) + bytes(4),
             secp=2, spsp=0x1000, send=True)
    pair('send-short-header', bytes(4), secp=2, spsp=0x1000, send=True)
    for length in (4, 8):
        pair(f'mgmt-selected-{length}', mgmt(0, 0)[:length], secp=2, spsp=0x1000)
    pair('mgmt-full-header', mgmt(0, 0), secp=2, spsp=0x1000)
    pair('get-full', bytes.fromhex('10000001'), secp=2, spsp=0)

    def cp(subpackets, hsn):
        return tcg_compacket(tcg_packet(subpackets, tsn=1, hsn=hsn), 0x1000, 1)

    data = tcg_subpacket(b'\x01')
    pair('data-pad-valid', cp(data, 1), spsp=0x1000)
    pair('data-pad-nonzero', cp(data[:-1] + b'\x80', 2), spsp=0x1000)
    # Complete Packet ends before its required pad, despite ample outer AL.
    pair('data-pad-missing', cp(data[:-3], 3) + bytes(3), spsp=0x1000)
    for length in (0, 4, 8):
        pair(f'credit-length-{length}', cp(tcg_subpacket(bytes(length), 0x8001), 10 + length),
             spsp=0x1000)
    pair('unknown-kind', cp(tcg_subpacket(b'\xa5' * 8, 0x8002), 20), spsp=0x1000)
    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID) + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS)
    eos = tcg_subpacket(b'\xfa')
    for name, malformed in (
            ('pad', eos[:-1] + b'\x80'),
            ('credit', eos + tcg_subpacket(bytes(8), 0x8001))):
        hsn = 100 + len(cases)
        pair(f'state-{name}-invalid', cp(malformed, hsn), spsp=0x1000)
        pair(f'state-{name}-recovery', cp(tcg_subpacket(call), hsn), spsp=0x1000)

    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                       'gen-nvme-tcp-test-capture.py'))
    sequence = [1, 1]

    def emit(pdu, send):
        side = 0 if send else 1
        src, dst = ('HOST', 'CTRL') if send else ('CTRL', 'HOST')
        tcp = tcpgen['tcp'](tcpgen[src + '_PORT'], tcpgen[dst + '_PORT'],
                            sequence[side], sequence[1 - side], pdu)
        ip = tcpgen['ipv4'](tcpgen[src + '_IP'], tcpgen[dst + '_IP'], tcp,
                            0x6000 + len(packets))
        packets.append((1, tcpgen['eth'](tcpgen[dst + '_MAC'], tcpgen[src + '_MAC'], ip)))
        sequence[side] += len(pdu)

    cases['native-admin-queue'] = (len(packets) + 1,)
    emit(tcpgen['capsule_cmd_pdu'](tcpgen['sqe'](6, 1, cdw10=1)), True)

    def native(name, payload, al, secp=2, spsp=0, offset=0):
        frame = len(packets) + 1
        cases[name] = (frame, frame + 1)
        cid = len(cases) + 1
        sqe = tcpgen['sqe'](NVME_AQ_OPC_SECURITY_RECV, cid,
                            cdw10=security_cdw10(secp, spsp), cdw11=al)
        emit(tcpgen['capsule_cmd_pdu'](sqe), True)
        emit(tcpgen['c2h_data_pdu'](cid, payload, datao=offset, pdo=24), False)

    native('get-al2', b'\x10\x00', 2)
    native('get-transfer-short', b'\x10\x00', 4)
    native('get-native-full', bytes.fromhex('10000001'), 4)
    native('mgmt-al2', b'\x10\x00', 2, spsp=0x1000)
    native('mgmt-native-full', mgmt(0, 0), 12, spsp=0x1000)
    native('data-pad-selected', cp(data, 30)[:-1], 60, secp=1, spsp=0x1000)
    for code, body in bodies.items():
        short = body[:2 if code == 5 else 1]
        native(f'l0-{code}-unaligned-length', l0(tcg_l0_feature(code, 1, short)),
               52 + len(short), secp=1, spsp=1)
    native('l0-unknown-unaligned', l0(tcg_l0_feature(0x7777, 1, b'\xa5')), 53,
           secp=1, spsp=1)

    # Core 2.01 §3.3.4.7.4 Tables 33/34: no RTC is a complete-tuple
    # indication; Invalid/Inactive ComIDs have no valid allocation/expiry.
    # Append MI pairs so the original 1-127 frame map remains unchanged.
    for name, state, allocation, expiration, reset in (
            ('verify-no-rtc', 3, bytes(10), bytes(10), bytes(10)),
            ('verify-zero-allocation', 3, bytes(10), expiry, date),
            ('verify-zero-expiry', 3, date, bytes(10), date),
            ('verify-zero-reset', 3, date, expiry, bytes(10)),
            ('verify-invalid-dates', 0, date, expiry, date),
            ('verify-inactive-dates', 1, date, expiry, date),
            ('verify-issued-dates', 2, date, expiry, date),
            ('verify-invalid-no-rtc', 0, bytes(10), bytes(10), bytes(10)),
            ('verify-inactive-no-rtc', 1, bytes(10), bytes(10), bytes(10))):
        pair(name, mgmt(1, 34, struct.pack('>I', state) + allocation + expiration + reset)
             + bytes(2), secp=2, spsp=0x1000)
    prefix = mgmt(1, 34, struct.pack('>I', 3) + bytes(12))
    pair('verify-no-rtc-selected', prefix, secp=2, spsp=0x1000)
    pair('verify-no-rtc-transfer-short', prefix, secp=2, spsp=0x1000, al=48)

    # Core 2.01 3.3.4.7.1-2: the payload ComID must be the SPSP ComID in both
    # directions; only an all-zero No Response Available (3.3.4.7.5) is exempt.
    def ext_mgmt(comid, ext, code, available, body=b''):
        return struct.pack('>HHIHH', comid, ext, code, 0, available) + body

    def ext_send(comid, ext, code):
        return struct.pack('>HHI', comid, ext, code) + bytes(4)

    pair('mismatch-recv', ext_mgmt(0x1001, 1, 3, 4, b'\xa1\xa2\xa3\xa4'),
         secp=2, spsp=0x1000)
    pair('mismatch-send', ext_send(0x1001, 1, 1), secp=2, spsp=0x1000, send=True)
    pair('mismatch-recv-code-0', ext_mgmt(0x1001, 1, 0, 0), secp=2, spsp=0x1000)
    pair('mismatch-send-zero', ext_send(0, 0, 0), secp=2, spsp=0x1000, send=True)
    pair('mismatch-recv-zero', ext_mgmt(0, 0, 3, 4, b'\xa1\xa2\xa3\xa4'),
         secp=2, spsp=0x1000)
    pair('no-response-zero', ext_mgmt(0, 0, 0, 0), secp=2, spsp=0x1000)
    pair('match-recv-ext', ext_mgmt(0x1000, 0xbeef, 3, 4, b'\xa1\xa2\xa3\xa4'),
         secp=2, spsp=0x1000)
    pair('match-send-ext', ext_send(0x1000, 0xbeef, 1), secp=2, spsp=0x1000, send=True)

    # Opal SSC 2.30 Tables 5/6: Geometry v1 Length is 1Ch and Opal SSC V2 v2
    # Length is 10h; later versions may differ. Ruby (Opal layout) follows.
    geometry = b'\x01' + bytes(7) + struct.pack('>IQQ', 512, 8, 0)
    opal = struct.pack('>HHBHHBB', 0x1000, 1, 0, 4, 8, 0, 0) + bytes(5)
    ruby = tcg_l0_feature(0x0304, 1, struct.pack('>H', 0x2000) + opal[2:])
    valid_opal = tcg_l0_feature(0x0203, 2, opal)
    for length in (0x18, 0x20):
        pair(f'geometry-v1-length-{length}',
             l0(tcg_l0_feature(0x0003, 1,
                               (geometry + b'\xa5' * 4)[:length]) + valid_opal))
    for length in (0x0c, 0x14):
        pair(f'opal-v2-length-{length}',
             l0(tcg_l0_feature(0x0203, 2, (opal + b'\xa5' * 4)[:length]) + ruby))
    valid_geometry = tcg_l0_feature(0x0003, 1, geometry)
    pair('fixed-lengths-valid', l0(valid_geometry + valid_opal))
    pair('geometry-v2-future', l0(tcg_l0_feature(0x0003, 2, geometry + bytes(4))))
    pair('opal-v3-future', l0(tcg_l0_feature(0x0203, 3, opal + bytes(4))))
    for name, feature in (('geometry', valid_geometry), ('opal', valid_opal)):
        full = l0(feature)
        pair(f'{name}-transfer-short', full[:60], secp=1, spsp=1, al=len(full))
    return packets, cases


def build_tcg_m5_validation_pcapng(output_path):
    packets, _ = tcg_m5_validation_vectors()
    write_pcapng(output_path, [(packet, None, interface) for interface, packet in packets], 1718000000 * 1_000_000, idb() + idb(link_type=1))


def tcg_conformance_vectors(corrective=False, final_corrective=False,
                            properties_extensions=False):
    """Core 2.01 3.2.2/3.2.3, 3.3.6, 5.2.3; SIIS 1.20 T1/T23/T24;
    Base 2.3 F395/F399; MI 2.1 F136. No SSC-specific layout is introduced.

    Return the exact request/response frame map with the packet list so fixture
    census/determinism checks do not need a dissector.
    """
    packets, cases = [], {}

    def pair(name, payload, send=False, al=None, dlen=None, off=0,
             wrong=b'', ctrl=1, eid=BMC_EID, secp=1, spsp=None):
        assert name not in cases
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        al = len(payload) if al is None else al
        dlen = len(payload) if dlen is None else dlen
        opcode = NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV
        if spsp is None:
            spsp = 1 if name.startswith('l0-') else 0x1000
        req = admin_request_payload(opcode, ctrl_id=ctrl, flags=0,
                                    cns=security_cdw10(secp, spsp),
                                    cdw11=al, dlen=dlen, doff=off)
        tag = (n // 2) % 8
        packets.extend((
            make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                        req + (payload if send else wrong), bmc_eid=eid, tag=tag),
            make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                        admin_resp_with_data(wrong if send else payload),
                        bmc_eid=eid, tag=tag)))

    def cp(tokens=b'', tsn=0x1234, hsn=None, seq=1, ext=0):
        if hsn is None:
            hsn = len(cases) + 1
        return tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn, seq),
                             0x1000, ext)

    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
            + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0' + tcg_bytes_atom(TCG_ADMIN_SP) + b'\xf1'
            + TCG_EOD_STATUS_SUCCESS)
    status = lambda atom: b'\xf0\xf1\xf9\xf0' + atom + b'\x00\x00\xf1'
    if properties_extensions:
        # Core 3.2.2.3.2.1 and 5.2.2.2 / Table 167. Each negotiation has its
        # own Extended ComID; one value per atom class, alternating between
        # the TPer and Host response lists.
        header = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                  + tcg_bytes_atom(bytes.fromhex('000000000000ff01')))

        def entry(name, value):
            return b'\xf2' + name + value + b'\xf3'

        def response(tper, host, outer=b'\x00'):
            return (header + b'\xf0\xf0' + tper + b'\xf1\xf2' + outer
                    + b'\xf0' + host + b'\xf1\xf3\xf1' + TCG_EOD_STATUS_SUCCESS)

        def known(asynchronous, sequence=1):
            return [entry(tcg_bytes_atom(b'SequenceNumbers'), bytes([sequence])),
                    entry(tcg_bytes_atom(b'Asynchronous'), bytes([asynchronous]))]

        nested = entry(tcg_bytes_atom(b'SequenceNumbers'), b'\x02')
        values = (
            ('bytes', b'\xa1X'),
            ('tiny-signed', b'\x41'), ('short-signed', b'\x91\xff'),
            ('wide-uint', b'\x89\x01' + bytes(8)),
            ('continued', b'\xb1X\xff\xb1Y\xff\xa1Z'),
            ('list', b'\xf0\x01\x41\xf1'),
            ('named', nested), ('nested', b'\xf0\xf0' + nested + b'\xf1\xf1'),
            ('continued-list', b'\xf0\xb1X\xff\xa1Y\xf1'),
            ('continued-named', b'\xf2\x01\xb1X\xff\xa1Y\xf3'),
        )
        ext = 70
        for i, (kind, value) in enumerate(values + (
                ('numeric-name', b'\x01'), ('signed-name', b'\x01'),
                ('wide-name', b'\x01'), ('empty-name', b'\x01'),
                ('split-wide', b'\x89\x01' + bytes(8)))):
            side = ('tper', 'host')[i % 2]
            name = f'extension-{side}-{kind}'
            key = {'numeric-name': b'\x01', 'signed-name': b'\x41',
                   'wide-name': b'\x89\x01' + bytes(8), 'empty-name': b'\xa0'}.get(
                       kind, tcg_bytes_atom(b'Extension'))
            entries = known(0)
            entries.insert(i % 3, entry(key, value))
            encoded = b''.join(entries)
            tokens = response(encoded if side == 'tper' else b''.join(known(0)),
                              encoded if side == 'host' else b''.join(known(0)))
            if kind == 'split-wide':
                cut = tokens.index(value) + 4
                payload = tcg_compacket(tcg_packet(
                    tcg_subpacket(tokens[:cut]) + tcg_subpacket(tokens[cut:]),
                    0, 0, 0), 0x1000, ext)
            else:
                payload = cp(tokens, 0, 0, 0, ext)
            pair(name + '-response', payload)
            pair(name + '-first', cp(call, 0x4800, 1, 1, ext))
            pair(name + '-duplicate', cp(call, 0x4800, 1, 1, ext))
            pair(name + '-sync-first', cp(call[:6], 0x4801, 1, 1, ext))
            pair(name + '-sync-last', cp(call[6:], 0x4801, 1, 2, ext))
            ext += 1

        # An explicit asynchronous twin proves the split probe can complete.
        pair('extension-async-response', cp(response(
            b''.join(known(1)), b''.join(known(1))), 0, 0, 0, ext))
        pair('extension-async-first', cp(call[:6], 0x4801, 1, 1, ext))
        pair('extension-async-last', cp(call[6:], 0x4801, 1, 2, ext))
        ext += 1

        invalid = (
            ('signed', b'\x41'), ('short-signed', b'\x91\x01'), ('bytes', b'\xa1X'),
            ('continued', b'\xb1X\xa1Y'),
            ('list', b'\xf0\x01\xf1'), ('named', nested),
            ('two', b'\x02'), ('wide', b'\x89\x01' + bytes(8)),
            ('wide-one', b'\x89' + bytes(8) + b'\x01'),
            ('zero-length', b'\x80'), ('duplicate', b'\x01'),
            ('conflicting', b'\x00'),
        )
        for j, prop in enumerate((b'SequenceNumbers', b'Asynchronous')):
            for i, (kind, value) in enumerate(invalid):
                side = ('tper', 'host')[(i + j) % 2]
                name = f'invalid-{side}-{prop.decode()}-{kind}'
                entries = known(1)
                entries.append(entry(tcg_bytes_atom(prop), value))
                if kind not in ('duplicate', 'conflicting'):
                    entries = [e for e in entries if e != entry(tcg_bytes_atom(prop), b'\x01')]
                    # A valid value on the other side and earlier entries
                    # cannot be observed from a later invalid entry.
                bad = b''.join(entries)
                pair(name + '-seed', cp(response(
                    b''.join(known(0, 0)), b''.join(known(0, 0))), 0, 0, 0, ext))
                pair(name + '-response', cp(response(
                    bad if side == 'tper' else b''.join(known(1)),
                    bad if side == 'host' else b''.join(known(1))), 0, 0, 0, ext))
                pair(name + '-first', cp(call, 0x4800, 1, 1, ext))
                pair(name + '-repeat', cp(call, 0x4800, 1, 1, ext))
                pair(name + '-sync-first', cp(call[:6], 0x4801, 1, 1, ext))
                pair(name + '-sync-last', cp(call[6:], 0x4801, 1, 2, ext))
                pair(name + '-recovery', cp(response(
                    b''.join(known(1)), b''.join(known(1))), 0, 0, 0, ext))
                pair(name + '-recovered-first', cp(call, 0x4802, 1, 1, ext))
                pair(name + '-recovered-duplicate', cp(call, 0x4802, 1, 1, ext))
                ext += 1

        for kind, value in (
                ('crossed', b'\xf0\xf2\x01\x01\xf1\xf3'),
                ('continued-integer', b'\xb1X\x01'),
                ('continued-list', b'\xb1X\xf0\xf1'),
                ('unfinished', b'\xb1X'),
                ('reserved', b'\xf4'), ('eod', b'\xf9')):
            name = 'malformed-extension-' + kind
            bad = b''.join(known(1)) + entry(tcg_bytes_atom(b'Extension'), value)
            pair(name + '-response', cp(response(bad, b''.join(known(1))), 0, 0, 0, ext))
            pair(name + '-first', cp(call, 0x4800, 1, 1, ext))
            pair(name + '-repeat', cp(call, 0x4800, 1, 1, ext))
            ext += 1
        for kind, outer in (('signed', b'\x40'), ('wide', b'\x89' + bytes(9)),
                            ('bytes', b'\xa1X'), ('one', b'\x01')):
            name = 'invalid-outer-' + kind
            pair(name + '-response', cp(response(b''.join(known(1)),
                b''.join(known(1)), outer), 0, 0, 0, ext))
            pair(name + '-first', cp(call, 0x4800, 1, 1, ext))
            pair(name + '-repeat', cp(call, 0x4800, 1, 1, ext))
            ext += 1
        # Wide optional names must still reject non-Properties methods:
        # treating one as zero would admit the following key observation.
        for wide_method in (0xff04, 0xff02):
            name = 'wide-option' if wide_method == 0xff04 else 'wide-start-option'
            for method in (0xff02, 0xff03, 0xff04, 0xff05):
                args = b'\x01' + (tcg_bytes_atom(TCG_ADMIN_SP) + b'\x01'
                                  if method == 0xff02 else b'\x82\x48\x03')
                if method == wide_method:
                    args += b'\xf2\x89' + bytes(9) + b'\x01\xf3'
                if method in (0xff04, 0xff05):
                    args += b'\xf2\x01\xa4KEY!\xf3'
                tokens = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                          + tcg_bytes_atom(method.to_bytes(8, 'big'))
                          + b'\xf0' + args + b'\xf1' + TCG_EOD_STATUS_SUCCESS)
                pair(f'{name}-{method:x}', cp(tokens, 0, 0, 0, ext),
                     send=method in (0xff02, 0xff04))
            pair(name + '-plain', cp(call, 0x4803, 1, 1, ext))
            ext += 1
        return packets, cases
    empty = tcg_compacket(b'', 0x1000)
    pair('send', cp(call), send=True)
    pair('receive', cp(status(b'\x00')))
    pair('wrong-receive-request', empty, wrong=empty)
    pair('wrong-send-response', empty, send=True, wrong=empty)
    pair('send-short', empty, send=True, al=24, dlen=24)
    pair('send-dlen', empty, send=True, dlen=24, al=28, off=4)
    pair('send-tl', empty, send=True, al=16)
    pair('send-offset', empty, send=True, off=4)
    pair('receive-al', empty + b'\xfa' * 4, al=20)
    pair('receive-dlen', empty + b'\xfa' * 4, al=24, dlen=20)
    pair('receive-offset', bytes(range(20)), al=64, off=4)
    pair('receive-end', empty, al=20, off=20)

    def l0(features, parameter_length=None):
        if parameter_length is None:
            parameter_length = 44 + len(features)
        return struct.pack('>IHH', parameter_length, 0, 1) + bytes(40) + features

    tper = tcg_l0_feature(1, 1, b'\x41' + bytes(11))
    locking = tcg_l0_feature(2, 1, b'\x03' + bytes(11))
    valid = l0(tper + locking)
    malformed = l0(tper + tcg_l0_feature(2, 1, b''))
    pair('l0-al16', valid[:16])
    # Complete immediate parents: outer AL cannot exonerate these lengths.
    pkt_bad = bytearray(tcg_packet(tcg_subpacket(b'\x01\x02\x03\x04')))
    struct.pack_into('>I', pkt_bad, 20, 400)
    pair('packet-parent', tcg_compacket(pkt_bad, 0x1000), al=4096)
    sp_bad = bytearray(tcg_subpacket(b''))
    struct.pack_into('>I', sp_bad, 8, 400)
    pair('subpacket-parent', tcg_compacket(tcg_packet(sp_bad), 0x1000), al=4096)
    pair('l0-body-cut', valid[:68], al=80)
    pair('l0-zero-body', malformed)
    pair('l0-exact-al', valid[:68])
    pair('l0-complete-parent', malformed, al=80)
    pair('l0-full', valid)
    pair('l0-padding', valid + bytes(16))
    pair('l0-parent', l0(tper + locking, 64))
    geometry = l0(tcg_l0_feature(3, 1, bytes(range(28))), 132)
    pair('l0-geometry-cut', geometry[:60], al=136)
    # Current leaf availability guards, NOT independently asserted SSC sizes.
    for code, declared in ((1, 12), (2, 12), (3, 28), (5, 12),
                           (0x100, 4), (0x200, 4), (0x201, 8), (0x202, 12),
                           (0x203, 12), (0x301, 12), (0x302, 12), (0x303, 12),
                           (0x304, 12), (0x402, 4), (0x403, 12), (0x404, 4)):
        body = l0(tcg_l0_feature(code, 1, bytes(declared)))
        pair(f'l0-leaf-{code:04x}', body[:52], al=len(body))
    for value in (0x0d, 0x13, 0x14, 0x1234, 0x100000001):
        pair(f'status-{value:x}', cp(status(tcg_short_uint(value, 8))))
    pair('zero-valid', cp(b'\xa0'))
    for token in (b'\x80', b'\x90', b'\xb0', b'\xc0\x00', b'\xc8\x00',
                  b'\xd0\x00', b'\xd8\x00', b'\xe0\x00\x00\x00',
                  b'\xe1\x00\x00\x00', b'\xe2\x00\x00\x00', b'\xe3\x00\x00\x00'):
        pair('zero-' + token.hex(), cp(token))
    for name, atom in (('tiny', b'\x40'), ('signed', b'\x91\x01'),
                       ('bytes', b'\xa1\x01'), ('name', b'\xf2\x01\x02\xf3'),
                       ('list', b'\xf0\x05\xf1')):
        pair('status-type-' + name, cp(status(atom)))
    pair('eos', cp(b'\xfa' + call + status(b'\x05')))
    pair('uid-opaque', cp(call))
    for name, tokens in (('crossed', b'\xf0\xf2\xf1\xf3'),
                         ('end-list', b'\xf1'), ('end-name', b'\xf3'),
                         ('unterminated', b'\xf0\x01\xf9')):
        pair('delimiter-' + name, cp(tokens))
    split = 6  # inside Invoking UID
    pair('split-subpackets', tcg_compacket(tcg_packet(
        tcg_subpacket(call[:split]) + tcg_subpacket(call[split:]),
        0x2100, 1), 0x1000))
    pair('split-packets', tcg_compacket(
        tcg_packet(tcg_subpacket(call[:split]), 0x2101, 1, 1)
        + tcg_packet(tcg_subpacket(call[split:]), 0x2101, 1, 2), 0x1000))
    pair('split-first', cp(call[:split], 0x2102, 1, 1))
    pair('isolate-hsn', cp(b'\x01', 0x2102, 2, 2))
    pair('isolate-tsn', cp(b'\x01', 0x2103, 1, 2))
    pair('isolate-ext', cp(b'\x01', 0x2102, 1, 2, 1))
    pair('split-controller-last', cp(call[split:], 0x2102, 1, 2), ctrl=2)
    pair('isolate-endpoint', cp(b'\x01', 0x2102, 1, 2), eid=BMC_EID + 1)
    pair('isolate-direction', cp(b'\x01', 0x2102, 1, 2), send=True)
    pair('split-last', cp(call, 0x2102, 1, 3))
    for name, atom in (('medium', tcg_medium_bytes_atom(bytes(range(20)))),
                       ('long', tcg_long_int(0x1234, 4))):
        pair('split-' + name, tcg_compacket(tcg_packet(
            tcg_subpacket(atom[:1]) + tcg_subpacket(atom[1:]),
            0x2200, len(cases)), 0x1000))
    # Core T241 and 5.2.3: four observed control-session methods, keys only
    # on optional names 1/2. Authentication-only exchange is a negative control.
    def startup(method, hsn, tsn, keys=False):
        args = tcg_tiny_uint(hsn)
        args += (tcg_bytes_atom(TCG_ADMIN_SP) + b'\x01' if method == 0xff02
                 else tcg_short_uint(tsn, 4))
        if keys:
            args += b'\xf2\x01\xa4KEY!\xf3'
        return (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                + tcg_bytes_atom(method.to_bytes(8, 'big')) + b'\xf0'
                + args + b'\xf1' + TCG_EOD_STATUS_SUCCESS)
    for name, hsn, tsn, keys in (('secure', 10, 0x3100, True),
                                 ('auth-only', 11, 0x3101, False)):
        for method in (0xff02, 0xff03, 0xff04, 0xff05):
            pair(f'{name}-{method:x}', cp(startup(method, hsn, tsn,
                 keys and method in (0xff04, 0xff05)), 0, 0),
                 send=method in (0xff02, 0xff04))
        # Looks exactly like plaintext; only prior evidence controls routing.
        pair(name + '-payload', cp(call, tsn, hsn))
    pair('secure-send-payload', cp(call, 0x3100, 10), send=True)
    pair('secure-other-controller', cp(call, 0x3100, 10), ctrl=2)
    pair('secure-other-extension', cp(call, 0x3100, 10, ext=1))
    pair('secure-unobserved', cp(call, 0x3102, 12))
    for name, ext, outstanding, minimum, send, pad in (
            ('inactive', 0xffff, 0, 0, False, 0),
            ('empty', 1, 0, 0, False, 0),
            ('polling', 1, 1, 0, False, 0),
            ('too-small', 1, 88, 88, False, 0),
            ('inactive-pad', 0xffff, 0, 0, False, 12),
            ('empty-send', 1, 0x11223344, 0x55667788, True, 0),
            ('inactive-send', 0xffff, 0, 0, True, 0)):
        body = struct.pack('>IHHIII', 0, 0x1000, ext, outstanding, minimum, 0)
        pair(name, body + bytes(pad), send=send)
    stream = status(b'\x13')
    pair('split-status-first', cp(stream[:4], 0x3300, 1, 1))
    pair('split-status-last', cp(stream[4:], 0x3300, 1, 2))
    pair('split-name', tcg_compacket(tcg_packet(
        tcg_subpacket(b'\xf0' * 70 + b'\xf2\x01') +
        tcg_subpacket(b'\x02\xf3' + b'\xf1' * 70),
        0x3301, 1), 0x1000))
    pair('eos-first', cp(b'\xfa', 0x3302, 1, 1))
    pair('eos-last', cp(call, 0x3302, 1, 2))
    pair('status-long-extent', cp(status(tcg_long_int(0x13, 8))))
    pair('uid-continued', cp(b'\xf8\xb8' + TCG_SMUID
                           + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
                           + b'\xf0\xf8' + tcg_bytes_atom(TCG_SMUID)
                           + tcg_bytes_atom(TCG_SYNTHETIC_METHOD) + b'\xf1'))
    pair('send-absent', b'', send=True, al=20, dlen=20)
    pair('non-tcg', bytes(range(16)), secp=0xea)
    if not (corrective or final_corrective):
        return packets, cases

    # Separate corrective corpus keeps the original MI/native frame numbers.
    packets.clear()
    cases.clear()
    control_sequences = {}

    def establish(name, hsn, tsn, ext=0, eid=BMC_EID, bad_method=None,
                  bad_status=None, bad_window=False):
        for method in (0xff02, 0xff03, 0xff04, 0xff05):
            tokens = startup(method, hsn, tsn, method in (0xff04, 0xff05))
            if method == bad_method:
                tokens = tokens[:-len(TCG_EOD_STATUS_SUCCESS)] + b'\xf9\xf0' + bad_status + b'\xf1'
            direction = method in (0xff02, 0xff04)
            sequence_key = (ext, eid, direction)
            sequence = control_sequences.get(sequence_key, 0) + 1
            control_sequences[sequence_key] = sequence
            payload = cp(tokens, 0, 0, seq=sequence, ext=ext)
            if bad_window and method == 0xff05:
                # Complete 100-byte ComPacket, one padding byte selected by an
                # invalid unaligned 101-byte window, within logical AL=104.
                assert len(payload) <= 100
                payload += bytes(101 - len(payload))
            pair(f'{name}-{method:x}', payload, send=method in (0xff02, 0xff04),
                 eid=eid, al=104 if bad_window and method == 0xff05 else None)

    establish('controller', 20, 0x4100)
    pair('controller-secure', cp(call, 0x4100, 20), ctrl=2)
    pair('endpoint-plain', cp(call, 0x4100, 20), eid=BMC_EID + 1)
    pair('control-eos', cp(b'\xfa', 0, 0), send=True)
    establish('after-eos', 21, 0x4101)
    pair('after-eos-secure', cp(call, 0x4101, 21))
    pair('after-eos-host-secure', cp(call, 0x4101, 21), send=True)

    bad_statuses = (
        ('signed-second', b'\x00\x40\x00'),
        ('bytes-third', b'\x00\x00\xa1X'),
        ('list-second', b'\x00\xf0\x00\xf1\x00'),
        ('signed-third', b'\x00\x00\x91\x00'),
        ('short-list', b'\x00\x00'),
        ('empty-list', b''),
    )
    for i, (name, tail) in enumerate(bad_statuses):
        establish(name, 24 + i, 0x4200 + i, bad_method=0xff05, bad_status=tail)
        pair(name + '-plain', cp(call, 0x4200 + i, 24 + i))
        pair(name + '-host-plain', cp(call, 0x4200 + i, 24 + i), send=True)
    # Additional unsigned statuses are allowed by Core 3.2.4.2.
    establish('extra-status', 30, 0x4206, bad_method=0xff05, bad_status=b'\x00\x01\x02\x03')
    pair('extra-status-secure', cp(call, 0x4206, 30))

    # A value of None leaves that property out of its list.
    def properties(name, ext, host_sequence, tper_sequence, host_async, tper_async,
                   eid=BMC_EID, response_spsp=None):
        def values(sequence, asynchronous):
            return b'\xf0' + b''.join(
                b'\xf2' + tcg_bytes_atom(key) + bytes([value]) + b'\xf3'
                for key, value in ((b'SequenceNumbers', sequence),
                                   (b'Asynchronous', asynchronous))
                if value is not None) + b'\xf1'
        header = b'\xf8' + tcg_bytes_atom(TCG_SMUID) + tcg_bytes_atom(bytes.fromhex('000000000000ff01'))
        host = b'\xf2\x00' + values(host_sequence, host_async) + b'\xf3'
        pair(name + '-request', cp(header + b'\xf0' + host + b'\xf1'
             + TCG_EOD_STATUS_SUCCESS, 0, 0, seq=0, ext=ext), send=True, eid=eid)
        pair(name + '-response', cp(header + b'\xf0' + values(tper_sequence, tper_async)
             + host + b'\xf1' + TCG_EOD_STATUS_SUCCESS, 0, 0, seq=0, ext=ext), eid=eid,
             spsp=response_spsp)

    properties('numbered', 10, 1, 1, 1, 1)
    pair('numbered-first', cp(call[:split], 0x4300, 1, 1, 10))
    pair('numbered-duplicate', cp(call[:split], 0x4300, 1, 1, 10))
    pair('numbered-last', cp(call[split:], 0x4300, 1, 2, 10))
    pair('numbered-old', cp(call, 0x4300, 1, 1, 10))
    pair('numbered-host', cp(call, 0x4300, 1, 1, 10), send=True)
    pair('numbered-other-session', cp(call, 0x4300, 2, 1, 10))
    properties('unnumbered', 11, 0, 1, 1, 1)
    pair('unnumbered-first', cp(call[:split], 0x4301, 1, 0, 11))
    pair('unnumbered-last', cp(call[split:], 0x4301, 1, 0, 11))
    pair('unnumbered-repeat', cp(call, 0x4301, 1, 0, 11))
    for name, ext, host_async, tper_async in (
            ('sync-host', 12, 0, 1), ('sync-tper', 13, 1, 0), ('async', 14, 1, 1)):
        properties(name, ext, 0, 0, host_async, tper_async)
        pair(name + '-first', cp(call[:split], 0x4400, 1, ext=ext))
        # Only a UID is outstanding; this continuation contains no new CALL.
        pair(name + '-last', cp(call[split:], 0x4400, 1, ext=ext))
        pair(name + '-packets', tcg_compacket(
            tcg_packet(tcg_subpacket(call[:split]), 0x4401, 1, 0)
            + tcg_packet(tcg_subpacket(call[split:]), 0x4401, 1, 0), 0x1000, ext))
        pair(name + '-subpackets', tcg_compacket(tcg_packet(
            tcg_subpacket(call[:split]) + tcg_subpacket(call[split:]),
            0x4402, 1, 0), 0x1000, ext))

    properties('reset-mode', 20, 1, 1, 1, 1)
    establish('reset-secure', 40, 0x4500, ext=20)
    pair('reset-before-secure', cp(call, 0x4500, 40, ext=20))
    pair('reset-fragment', cp(call[:split], 0x4501, 1, 9, 20))
    pair('reset-pending', cp(startup(0xff02, 41, 0x4502), 0, 0, 3, 20), send=True)
    establish('reset-isolation-extension', 42, 0x4503, ext=21)
    establish('reset-isolation-endpoint', 43, 0x4504, ext=20, eid=BMC_EID + 1)

    def reset(name, result=0, available=4, ext=20, dlen=None, al=None, eid=BMC_EID):
        payload = struct.pack('>HHIHH', 0x1000, ext, 2, 0, available)
        if available:
            payload += struct.pack('>I', result)
        pair(name, payload, secp=2, dlen=dlen, al=al, eid=eid)

    reset('reset-failure', result=1)
    pair('reset-failure-still-secure', cp(call, 0x4500, 40, 2, 20))
    reset('reset-in-progress', available=0)
    pair('reset-pending-still-secure', cp(call, 0x4500, 40, 3, 20))
    reset('reset-invalid-request', dlen=17, al=20)
    pair('reset-invalid-still-secure', cp(call, 0x4500, 40, 4, 20))
    reset('reset-success')
    pair('reset-after-plain', cp(call, 0x4500, 40, 1, 20))
    pair('reset-after-host-plain', cp(call, 0x4500, 40, 1, 20), send=True)
    pair('reset-after-fragment', cp(call, 0x4501, 1, 1, 20))
    for method in (0xff03, 0xff04, 0xff05):
        pair(f'reset-stale-{method:x}', cp(startup(method, 41, 0x4502,
             method in (0xff04, 0xff05)), 0, 0, ext=20), send=method == 0xff04)
    pair('reset-stale-plain', cp(call, 0x4502, 41, ext=20))
    pair('reset-other-extension-secure', cp(call, 0x4503, 42, ext=21))
    pair('reset-other-endpoint-secure', cp(call, 0x4504, 43, ext=20), eid=BMC_EID + 1)
    establish('reset-fresh', 40, 0x4500, ext=20)
    pair('reset-fresh-secure', cp(call, 0x4500, 40, ext=20))
    pair('reset-mode-repeat-first', cp(call[:split], 0x4505, 1, 0, 20))
    pair('reset-mode-repeat-last', cp(call[split:], 0x4505, 1, 0, 20))

    pair('receive-zero-dlen', b'', al=104, dlen=0)
    pair('receive-misaligned-offset', b'', al=104, dlen=100, off=1)
    pair('receive-over-max', b'', al=4100, dlen=4100)
    pair('receive-offset-at-al', b'', al=104, dlen=4, off=104)
    establish('invalid-window', 50, 0x4600, bad_window=True)
    pair('invalid-window-plain', cp(call, 0x4600, 50))
    pair('invalid-window-host-plain', cp(call, 0x4600, 50), send=True)
    # A valid retransmission of the final method can establish the session;
    # the invalid request was not allowed to consume its pending startup.
    pair('valid-window-recovery', cp(startup(0xff05, 50, 0x4600, True), 0, 0))
    pair('valid-window-secure', cp(call, 0x4600, 50))
    if not final_corrective:
        return packets, cases

    # N1-N3 are separate so the earlier MI/native corrective frame maps stay
    # stable. Core 2.01 r1.00 3.3.9.3, 3.2.3.3.1.2, 3.2.2.4.2(5);
    # MI 2.2 Chapter 6 Fig 139 and Request and Response Data.
    packets.clear()
    cases.clear()
    control_sequences.clear()
    properties('gap-mode', 30, 1, 1, 1, 1)
    first, missing, successor = call[:split], call[split:split + 1], call[split + 1:]
    pair('gap-first', cp(first, 0x4700, 1, 1, 30))
    pair('gap-successor', cp(successor, 0x4700, 1, 3, 30))
    pair('gap-host', cp(call, 0x4700, 1, 1, 30), send=True)
    pair('gap-other-session', cp(call, 0x4700, 2, 1, 30))
    pair('gap-other-extension', cp(call, 0x4700, 1, 1, 31))
    pair('gap-other-endpoint', cp(call, 0x4700, 1, 1, 30), eid=BMC_EID + 1)
    pair('gap-missing', cp(missing, 0x4700, 1, 2, 30))
    pair('gap-retransmit', cp(successor, 0x4700, 1, 3, 30))
    pair('gap-old', cp(first, 0x4700, 1, 1, 30))
    pair('gap-duplicate', cp(successor, 0x4700, 1, 3, 30))
    pair('gap-next', cp(call, 0x4700, 1, 4, 30))
    properties('no-numbering', 31, 0, 1, 1, 1)
    pair('no-numbering-first', cp(first, 0x4701, 1, 1, 31))
    pair('no-numbering-gap', cp(call[split:], 0x4701, 1, 3, 31))
    pair('no-numbering-max', cp(first, 0x4702, 1, 0xffffffff, 31))
    pair('no-numbering-zero', cp(call[split:], 0x4702, 1, 0, 31))

    # Late-capture anchor near the 32-bit maximum avoids billions of packets.
    # Max-1 -> Max is contiguous; Max -> 0 aborts, never concatenates an atom.
    pair('wrap-anchor', cp(first, 0x4710, 1, 0xfffffffe, 30))
    pair('wrap-max', cp(missing, 0x4710, 1, 0xffffffff, 30))
    pair('wrap-old', cp(first, 0x4710, 1, 0xfffffffe, 30))
    pair('wrap-duplicate', cp(missing, 0x4710, 1, 0xffffffff, 30))
    pair('wrap-zero', cp(successor, 0x4710, 1, 0, 30))
    pair('wrap-one', cp(successor, 0x4710, 1, 1, 30))
    pair('wrap-host-aborted', cp(call, 0x4710, 1, 1, 30), send=True)
    pair('wrap-other-session', cp(call, 0x4711, 1, 1, 30))
    pair('wrap-restart-ff02', cp(startup(0xff02, 1, 0x4710), 0, 0, 1, 30), send=True)
    pair('wrap-restart-ff03', cp(startup(0xff03, 1, 0x4710), 0, 0, 1, 30))
    pair('wrap-restart-gap', cp(call, 0x4710, 1, 3, 30))
    pair('wrap-restart-first', cp(call, 0x4710, 1, 1, 30))

    for name, ext, victim, prior, tsn in (
            ('packet-status', 32, 52, 54, 0x4800),
            ('subpacket-status', 33, 53, 55, 0x4810)):
        for label, hsn, session in (('victim', victim, tsn), ('prior', prior, tsn + 1)):
            for method in (0xff02, 0xff03):
                pair(f'{name}-{label}-{method:x}',
                     cp(startup(method, hsn, session), 0, 0, ext=ext),
                     send=method == 0xff02)
        before = startup(0xff04, prior, tsn + 1, True)
        bad = status(b'\x40')
        after = startup(0xff04, victim, tsn, True)
        if name == 'packet-status':
            subpackets = tcg_subpacket(before + bad + after)
        else:
            # Status StartList and violating atom are in different Subpackets;
            # the ignored method itself crosses another Subpacket boundary.
            subpackets = (tcg_subpacket(before + bad[:4])
                          + tcg_subpacket(bad[4:] + after[:split])
                          + tcg_subpacket(after[split:]))
        pair(name + '-invalid', tcg_compacket(tcg_packet(subpackets, 0, 0),
                                             0x1000, ext), send=True)
        pair(name + '-victim-response', cp(startup(0xff05, victim, tsn, True),
                                           0, 0, ext=ext))
        pair(name + '-victim-plain', cp(call, tsn, victim, ext=ext))
        pair(name + '-victim-host-plain', cp(call, tsn, victim, ext=ext), send=True)
        pair(name + '-prior-response', cp(startup(0xff05, prior, tsn + 1, True),
                                          0, 0, ext=ext))
        pair(name + '-prior-secure', cp(call, tsn + 1, prior, ext=ext))
        pair(name + '-prior-host-secure', cp(call, tsn + 1, prior, ext=ext), send=True)
        # A second Packet in the SAME ComPacket gets a fresh validity latch.
        pair(name + '-next-packet', tcg_compacket(
            tcg_packet(tcg_subpacket(bad), 0, 0)
            + tcg_packet(tcg_subpacket(after), 0, 0), 0x1000, ext), send=True)
        pair(name + '-recovery-response', cp(startup(0xff05, victim, tsn, True),
                                             0, 0, ext=ext))
        pair(name + '-recovery-secure', cp(call, tsn, victim, ext=ext))
        pair(name + '-recovery-host-secure', cp(call, tsn, victim, ext=ext), send=True)

    for method in (0xff02, 0xff03, 0xff04):
        pair(f'underfill-{method:x}', cp(startup(method, 56, 0x4900,
             method == 0xff04), 0, 0, ext=34), send=method != 0xff03)
    trusted = cp(startup(0xff05, 56, 0x4900, True), 0, 0, ext=34)
    assert len(trusted) == 100
    pair('underfill-trusted', trusted, dlen=104, al=104)
    pair('underfill-plain', cp(call, 0x4900, 56, ext=34))
    pair('underfill-host-plain', cp(call, 0x4900, 56, ext=34), send=True)
    pair('exact-trusted', trusted + bytes(4), dlen=104, al=104)
    pair('exact-secure', cp(call, 0x4900, 56, ext=34))
    pair('exact-host-secure', cp(call, 0x4900, 56, ext=34), send=True)
    reset('underfill-reset', ext=34, dlen=20, al=20)
    pair('underfill-reset-secure', cp(call, 0x4900, 56, ext=34))
    pair('underfill-reset-host-secure', cp(call, 0x4900, 56, ext=34), send=True)
    reset_data = struct.pack('>HHIHHI', 0x1000, 34, 2, 0, 4, 0)
    pair('exact-reset', reset_data + bytes(4), secp=2, dlen=20, al=20)
    pair('exact-reset-plain', cp(call, 0x4900, 56, ext=34))
    pair('exact-reset-host-plain', cp(call, 0x4900, 56, ext=34), send=True)

    # SequenceNumbers without AckNak. A packet missing from the capture
    # must not stall the session: the next one re-anchors (Core 3.2.3.3.1.2
    # ignores only SeqNumber <= the last acted-on packet), and the stream
    # across the hole is dropped. Asynchronous both sides, so only the gap
    # can reset it. Seq 3 of session 60 and Seq 1 of session 61 are absent.
    properties('lossy', 35, 1, 1, 1, 1)
    for seq, (hsn, tsn) in enumerate(((60, 0x4720), (61, 0x4721)), 1):
        for method in (0xff02, 0xff03):
            pair(f'lossy-{hsn}-{method:x}', cp(startup(method, hsn, tsn), 0, 0, seq, 35),
                 send=method == 0xff02)
    pair('lossy-1', cp(call, 0x4720, 60, 1, 35))
    pair('lossy-2', cp(call[:split], 0x4720, 60, 2, 35))
    pair('lossy-4', cp(call, 0x4720, 60, 4, 35))
    pair('lossy-5', cp(call, 0x4720, 60, 5, 35))
    pair('lossy-6', cp(call, 0x4720, 60, 6, 35))
    pair('lossy-5-again', cp(call, 0x4720, 60, 5, 35))
    pair('lossy-first-2', cp(call, 0x4721, 61, 2, 35))
    pair('lossy-first-3', cp(call, 0x4721, 61, 3, 35))
    # A secure session re-anchors through the secure_data commit; Seq 2 of
    # session 0x4730/40 is absent.
    properties('secgap', 37, 1, 1, 1, 1)
    sh = {0xff02: 1, 0xff03: 1, 0xff04: 2, 0xff05: 2}
    for method in (0xff02, 0xff03, 0xff04, 0xff05):
        pair(f'secgap-{method:x}', cp(startup(method, 40, 0x4730, method in (0xff04, 0xff05)),
                                      0, 0, sh[method], 37),
             send=method in (0xff02, 0xff04))
    pair('secgap-1', cp(call, 0x4730, 40, 1, 37))
    pair('secgap-3', cp(call, 0x4730, 40, 3, 37))
    pair('secgap-4', cp(call, 0x4730, 40, 4, 37))
    pair('secgap-4-again', cp(call, 0x4730, 40, 4, 37))

    # The ComPacket-boundary stream reset (Core 3.3.10.3(a))
    # also applies where the spec, not an observed Asynchronous value,
    # settles the Synchronous protocol (5.2.2.4.1.11). No Level 0 precedes
    # these in this section; a's below reports Async Supported = 1, b's 0.
    a, b = BMC_EID + 3, BMC_EID + 4
    # No evidence at all: the stream still carries, also to another
    # controller of the subsystem (SIIS 1.20 6.7.1.1).
    pair('carry-first', cp(first, 0x4740, 1, 0, 40), eid=a)
    pair('carry-controller-last', cp(call[split:], 0x4740, 1, 0, 40), eid=a, ctrl=2)
    # 5.2.2.2: a TPer list without Asynchronous does not support it. The
    # lone Long atom header claims 4096 bytes the next ComPacket cannot owe.
    properties('omit', 41, 0, 0, 1, None, eid=a)
    pair('omit-first', cp(b'\xe2\x00\x10\x00', 0x4741, 1, 0, 41), eid=a)
    pair('omit-next', cp(call, 0x4741, 1, 0, 41), eid=a)
    # 3.3.4.7.5 item 7: a STACK_RESET returns both sides to Table 168.
    properties('rs', 42, 0, 0, 1, 1, eid=a)
    pair('rs-first', cp(first, 0x4742, 1, 0, 42), eid=a)
    pair('rs-last', cp(call[split:], 0x4742, 1, 0, 42), eid=a)
    reset('rs-reset', ext=42, eid=a)
    pair('rs-after-first', cp(first, 0x4742, 1, 0, 42), eid=a)
    pair('rs-after-next', cp(call, 0x4742, 1, 0, 42), eid=a)
    # 3.3.6.4.2: only a cleared Async Supported bit settles the mode.
    pair('l0-async', l0(tcg_l0_feature(1, 1, b'\x43' + bytes(11)) + locking), eid=a)
    pair('async-l0-first', cp(first, 0x4743, 1, 0, 43), eid=a)
    pair('async-l0-last', cp(call[split:], 0x4743, 1, 0, 43), eid=a)
    pair('l0-sync', valid, eid=b)
    # The first ComPacket ends inside StartSession's parameter list.
    pair('sync-l0-partial', cp(b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                               + tcg_bytes_atom(bytes.fromhex('000000000000ff02'))
                               + b'\xf0\x01', 0, 0, 0, 44), send=True, eid=b)
    for method in (0xff02, 0xff03, 0xff04, 0xff05):
        pair(f'sync-l0-{method:x}', cp(startup(method, 62, 0x4744, method in (0xff04, 0xff05)),
                                       0, 0, 0, 44), send=method in (0xff02, 0xff04), eid=b)
    pair('sync-l0-secure', cp(call, 0x4744, 62, 0, 44), eid=b)
    # An observed Asynchronous = TRUE on both sides beats endpoint b's Level 0.
    properties('prec', 45, 0, 0, 1, 1, eid=b)
    pair('prec-first', cp(first, 0x4745, 1, 0, 45), eid=b)
    pair('prec-last', cp(call[split:], 0x4745, 1, 0, 45), eid=b)
    # The conformance block's split call and status list, now settled by its
    # endpoint's Level 0, again with no evidence on endpoint c: the carried
    # stream is keyed by HSN, TSN, Extended ComID, endpoint and direction.
    c = BMC_EID + 5
    pair('iso-first', cp(first, 0x4746, 1, 0, 46), eid=c)
    pair('iso-hsn', cp(b'\x01', 0x4746, 2, 0, 46), eid=c)
    pair('iso-tsn', cp(b'\x01', 0x4747, 1, 0, 46), eid=c)
    pair('iso-ext', cp(b'\x01', 0x4746, 1, 0, 47), eid=c)
    pair('iso-endpoint', cp(b'\x01', 0x4746, 1, 0, 46), eid=a)
    pair('iso-direction', cp(b'\x01', 0x4746, 1, 0, 46), send=True, eid=c)
    pair('iso-last', cp(call[split:], 0x4746, 1, 0, 46), eid=c)
    pair('iso-status-first', cp(stream[:4], 0x4748, 1, 0, 46), eid=c)
    pair('iso-status-last', cp(stream[4:], 0x4748, 1, 0, 46), eid=c)
    # Endpoint b's last Level 0 reports Async Supported = 1, so it is no
    # longer sync-only: the stream carries again.
    pair('l0-async-b', l0(tcg_l0_feature(1, 1, b'\x43' + bytes(11)) + locking), eid=b)
    pair('relevel-first', cp(first, 0x4749, 1, 0, 48), eid=b)
    pair('relevel-last', cp(call[split:], 0x4749, 1, 0, 48), eid=b)

    # Once Properties turns control-session numbering on, each
    # direction anchors on its next numbered Packet, not on the Properties
    # Packets (both Seq 0 here). The host restarts at 1. On ext 50 the TPer
    # counts from ComID issue (3.3.7.1.2), so its next Packet is Seq 2; on
    # ext 51 it is Seq 0.
    properties('renumber', 50, 1, 1, 1, 1)
    for hsn, tsn, host, tper in ((63, 0x4750, 1, 2), (59, 0x4751, 2, 3)):
        for method in (0xff02, 0xff03):
            pair(f'renumber-{hsn}-{method:x}', cp(startup(method, hsn, tsn), 0, 0,
                 host if method == 0xff02 else tper, 50), send=method == 0xff02)
    properties('tper-zero', 51, 1, 1, 1, 1)
    for method, seq in ((0xff02, 1), (0xff03, 0), (0xff04, 2), (0xff05, 1)):
        pair(f'tper-zero-{method:x}', cp(startup(method, 58, 0x4752, method in (0xff04, 0xff05)),
                                         0, 0, seq, 51), send=method in (0xff02, 0xff04))
    pair('tper-zero-secure', cp(call, 0x4752, 58, 1, 51))

    # GET_COMID issues an Inactive ComID (Core 3.3.3(a)), so a
    # re-issued Extended ComID starts over from the Table 168 initial
    # assumptions (5.2.2.4). Endpoint c has no Level 0, so only those make
    # the split call after the re-issue Synchronous.
    def get_comid(name, value):
        pair(name, struct.pack('>I', value) + bytes(4), secp=2, spsp=0, eid=c)

    def lifetime(name, ext, hsn, tsn, trusted):
        get_comid(name + '-get', 0x10000000 | ext)
        properties(name, ext, 1, 1, 1, 1, eid=c)
        methods = (0xff02, 0xff03, 0xff04, 0xff05) if trusted else (0xff02, 0xff03)
        for method in methods:
            pair(f'{name}-old-{method:x}', cp(startup(method, hsn, tsn, method in (0xff04, 0xff05)),
                                              0, 0, 1 if method < 0xff04 else 2, ext),
                 send=method in (0xff02, 0xff04), eid=c)

    lifetime('reissue', 52, 57, 0x4760, True)
    get_comid('reissue-again', 0x10000034)
    for method in (0xff02, 0xff03):
        pair(f'reissue-{method:x}', cp(startup(method, 56, 0x4761), 0, 0, 0, 52),
             send=method == 0xff02, eid=c)
    pair('reissue-stale', cp(call, 0x4760, 57, 1, 52), eid=c)
    pair('reissue-plain', cp(call, 0x4761, 56, 0, 52), eid=c)
    pair('reissue-plain-again', cp(call, 0x4761, 56, 0, 52), eid=c)
    pair('reissue-first', cp(first, 0x4761, 56, 0, 52), eid=c)
    pair('reissue-next', cp(call, 0x4761, 56, 0, 52), eid=c)
    # Issuing another Extension of ComID 1000h leaves ext 53 as it was.
    lifetime('twin', 53, 55, 0x4762, False)
    get_comid('twin-none', 0)
    get_comid('twin-inactive', 0x1000ffff)
    get_comid('twin-other', 0x10000036)
    pair('twin-ff02', cp(startup(0xff02, 54, 0x4763), 0, 0, 0, 53), send=True, eid=c)
    # Extension FFFFh is never assigned (3.3.4.3.1(b)), so a GET_COMID
    # returning 0x1000FFFF issues nothing: the channel keeps its anchors.
    lifetime('inact', 0xffff, 53, 0x4764, False)
    get_comid('inact-again', 0x1000ffff)
    pair('inact-ff02', cp(startup(0xff02, 52, 0x4765), 0, 0, 0, 0xffff), send=True, eid=c)

    # SPSP is the ComID the Security Send/Receive addresses (SIIS 1.20
    # Tables 23/24). A ComPacket whose header names another ComID is shown
    # but tracked on neither channel: the TPer discards it on IF-SEND (Core
    # 3.3.3.1) and answers IF-RECV only with the addressed ComID's sessions
    # (3.3.2). Here the header says 1000h and `other` is the SPSP.
    other = 0x1001
    for name, ext, hsn, tsn, stray in (('mis-send', 56, 33, 0x4770, 0xff02),
                                       ('mis-recv', 58, 31, 0x4772, 0xff03),
                                       ('mis-twin', 57, 32, 0x4771, None)):
        for method in (0xff02, 0xff03, 0xff04, 0xff05):
            pair(f'{name}-{method:x}', cp(startup(method, hsn, tsn, method in (0xff04, 0xff05)),
                                          0, 0, ext=ext),
                 send=method in (0xff02, 0xff04), eid=c,
                 spsp=other if method == stray else None)
        pair(name + '-payload', cp(call, tsn, hsn, ext=ext), eid=c)
    # The header names the twin's secure session, or names ComID 1001h on
    # the twin's SPSP; neither ends that session.
    pair('mis-twin-misrouted', cp(call, 0x4771, 32, ext=57), eid=c, spsp=other)
    pair('mis-twin-foreign', tcg_compacket(tcg_packet(tcg_subpacket(call), 0x4771, 32),
                                           other, 57), eid=c)
    pair('mis-twin-still-secure', cp(call, 0x4771, 32, ext=57), eid=c)
    # A misaddressed Properties response does not turn numbering on, and
    # a misaddressed numbered Packet does not anchor the control session.
    properties('mis-props', 59, 1, 1, 1, 1, eid=c, response_spsp=other)
    pair('mis-props-first', cp(call, 0, 0, 0, 59), eid=c)
    pair('mis-props-again', cp(call, 0, 0, 0, 59), eid=c)
    properties('mis-seq', 60, 1, 1, 1, 1, eid=c)
    pair('mis-seq-stray', cp(call, 0, 0, 1, 60), eid=c, spsp=other)
    pair('mis-seq-first', cp(call, 0, 0, 1, 60), eid=c)
    # Only an inactive-ComID response naming the addressed ComID is labelled
    # one (3.3.3.3).
    pair('mis-inactive', struct.pack('>IHHIII', 0, 0x1000, 0xffff, 0, 0, 0),
         eid=c, spsp=other)

    # A malformed status list aborts a regular session (dissector
    # policy after Core 3.2.2.4.2(5); see each case). Its later Packets, in
    # either direction, are not decoded until SyncSession starts it again.
    # A control session ignores only the rest of the Packet. Asynchronous on
    # both sides, so nothing else resets the stream between ComPackets.
    def latch(*packets, tsn=0x4780, hsn=1):
        return tcg_compacket(b''.join(tcg_packet(b''.join(map(tcg_subpacket, subs)),
                                                 tsn, hsn, 0) for subs in packets),
                             0x1000, 61)
    unmatched = b'\xf9\xf0\x00\xf3'
    properties('latch', 61, 0, 0, 1, 1)
    pair('latch-name', latch((unmatched, call)))
    pair('latch-name-next', latch((call,)))
    pair('latch-packets', latch((unmatched,), (call,), tsn=0x4784))
    pair('latch-eod', latch((b'\xf9\xf0\x00\xf9' + call,), tsn=0x4781))
    pair('latch-eod-next', latch((call,), tsn=0x4781))
    pair('latch-eod-host', latch((call,), tsn=0x4781), send=True)
    pair('latch-send', latch((unmatched,), tsn=0x4783), send=True)
    pair('latch-send-next', latch((call,), tsn=0x4783))
    pair('latch-signed', latch((b'\xf9\xf0\x00\x00\x00\x41\xf1',), tsn=0x4785))
    pair('latch-signed-next', latch((call,), tsn=0x4785))
    pair('latch-short', latch((b'\xf9\xf0\x00\x00\xf1',), tsn=0x4786))
    pair('latch-short-next', latch((call,), tsn=0x4786))
    pair('latch-zero', latch((b'\xf9\xf0\x00\x80\x00\x00\xf1',), tsn=0x4787))
    pair('latch-zero-next', latch((call,), tsn=0x4787))
    pair('latch-restart-ff02', cp(startup(0xff02, 1, 0x4780), 0, 0, 0, 61), send=True)
    pair('latch-restart-ff03', cp(startup(0xff03, 1, 0x4780), 0, 0, 0, 61))
    pair('latch-restart-first', latch((call,)))
    pair('latch-split-first', latch((stream[:4],), tsn=0x4782))
    pair('latch-split-last', latch((stream[4:],), tsn=0x4782))
    pair('latch-split-next', latch((call,), tsn=0x4782))
    pair('latch-control', latch((unmatched, call), tsn=0, hsn=0))
    pair('latch-control-next', latch((call,), tsn=0, hsn=0))
    return packets, cases


def build_tcg_final_corrective_pcapng(output_path):
    packets, _ = tcg_conformance_vectors(final_corrective=True)
    write_pcapng(output_path, packets, 1717000000 * 1_000_000)


def tcg_enclosing_completeness_vectors():
    """Core 2.01 Tables 17/18/20 and 3.2.3.1 prohibit a
    Subpacket spanning its Packet or a Packet spanning its ComPacket.
    Base 2.3 Fig 395's AL does not override a complete structural boundary.
    Return (interface, captured bytes, original length) and local frame map.
    """
    packets, cases = [], {}

    def payload(cp_len, pkt_len, sp_len, body):
        sp = tcg_subpacket(b'')[:8] + struct.pack('>I', sp_len) + body
        pkt = tcg_packet(sp, tsn=1, hsn=len(cases) + 1)
        pkt = pkt[:20] + struct.pack('>I', pkt_len) + pkt[24:]
        cp = tcg_compacket(pkt, 0x1000)
        return cp[:16] + struct.pack('>I', cp_len) + cp[20:]

    def pair(name, data):
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        req = admin_request_payload(NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1,
                                    flags=0, cns=security_cdw10(1, 0x1000),
                                    cdw11=4096, dlen=len(data), doff=0)
        for send, body in ((True, req), (False, admin_resp_with_data(data))):
            packet = make_packet(send, NVME_MI_TYPE_ADMIN, 0, body, tag=(n // 2) % 8)
            packets.append((0, packet, len(packet)))

    pair('leftover', payload(44, 100, 0, bytes(8)))
    pair('payload', payload(44, 100, 64, b'\xff' * 8))
    pair('leftover-short', payload(124, 100, 0, bytes(8)))
    pair('payload-short', payload(124, 100, 64, b'\xff' * 8))

    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                       'gen-nvme-tcp-test-capture.py'))
    sequence = [1, 1]

    def emit(pdu, send, keep=None):
        side = 0 if send else 1
        src, dst = ('HOST', 'CTRL') if send else ('CTRL', 'HOST')
        ports = {'HOST': 55200, 'CTRL': tcpgen['CTRL_PORT']}
        tcp = tcpgen['tcp'](ports[src], ports[dst], sequence[side],
                            sequence[1 - side], pdu)
        ip = tcpgen['ipv4'](tcpgen[src + '_IP'], tcpgen[dst + '_IP'], tcp,
                            0x7000 + len(packets))
        packet = tcpgen['eth'](tcpgen[dst + '_MAC'], tcpgen[src + '_MAC'], ip)
        original = len(packet)
        if keep is not None:
            # The C2H Data PDU has a 24-byte header; retain its declarations.
            packet = packet[:original - len(pdu) + 24 + keep]
        packets.append((1, packet, original))
        sequence[side] += len(pdu)

    cases['native-admin-queue'] = (len(packets) + 1,)
    emit(tcpgen['capsule_cmd_pdu'](tcpgen['sqe'](6, 1, cdw10=1)), True)

    def native(name, data, keep=None):
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        cid = len(cases) + 1
        sqe = tcpgen['sqe'](NVME_AQ_OPC_SECURITY_RECV, cid,
                            cdw10=security_cdw10(1, 0x1000), cdw11=4096)
        emit(tcpgen['capsule_cmd_pdu'](sqe), True)
        emit(tcpgen['c2h_data_pdu'](cid, data, pdo=24), False, keep)

    native('padding', payload(37, 100, 1, b'\xff'))
    native('padding-short', payload(40, 16, 1, b'\xff'))
    native('packet-complete', payload(124, 20, 0, bytes(8)))
    valid = payload(40, 16, 1, b'\xff' + bytes(3))
    native('valid', valid)
    native('snaplen-padding', valid, keep=57)
    # Retain the session key and SeqNumber read for the first-pass snapshot;
    # both passes then stop at the same captured Packet-header boundary.
    native('snaplen-header', valid, keep=32)
    return packets, cases


def tcg_continuation_domains_vectors():
    """Core 2.01 3.2.3.1 permits atom continuation, not Subpacket
    continuation across Packets. AL (Base 2.3 Fig 395) counts transfer bytes,
    never bytes in a synthetic continued-token child."""
    packets, cases = [], {}
    a = b'\x02\xaa\xbb' + b'\xff' * 27 + b'\xe0\x00'
    b = b'\x40' + b'\xff' * 31
    c = b'\x02\xaa\xbb' + b'\xff' * 27 + b'\xe0\x00\x00\x01\x01' + b'\xff' * 29

    def partial(body):
        return tcg_subpacket(b'')[:8] + struct.pack('>I', 64) + body

    def pair(name, data, allocation, keep=None):
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1, flags=0,
            cns=security_cdw10(1, 0x1000), cdw11=allocation,
            dlen=allocation, doff=0)
        for send, body in ((True, request), (False, admin_resp_with_data(data))):
            packet = make_packet(send, NVME_MI_TYPE_ADMIN, 0, body, tag=(n // 2) % 8)
            original = len(packet)
            if not send and keep is not None:
                packet = packet[:original - len(data) - 4 + keep]
            packets.append((packet, original))

    def transfer(body, short=False, padding=0):
        packet = tcg_packet(tcg_subpacket(b'\xd0') + partial(body), tsn=1, hsn=1)
        if short:
            packet = packet[:20] + struct.pack('>I', 92) + packet[24:]
        data = tcg_compacket(packet, 0x1000)
        if short:
            data = data[:16] + struct.pack('>I', 116) + data[20:]
        return data + bytes(padding)

    pair('malformed-a', transfer(a), 104)
    pair('malformed-b', transfer(b), 104)
    pair('short-a', transfer(a, short=True), 136)
    pair('short-b', transfer(b, short=True), 136)
    pair('healthy', transfer(c), 136)
    pair('snaplen', transfer(c), 136, keep=104)
    pair('padded-a', transfer(a, padding=4), 108)
    pair('generous-padded-a', transfer(a, padding=4), 136)
    pair('ordinary', tcg_compacket(tcg_packet(partial(a), tsn=1, hsn=2), 0x1000), 88)
    for name, body in (('witness-a', a), ('witness-b', b)):
        data = tcg_compacket(
            tcg_packet(tcg_subpacket(b'\xd0'), tsn=1, hsn=3)
            + tcg_packet(partial(body), tsn=1, hsn=3)
            + tcg_packet(tcg_subpacket(b'\x02\xaa\xbb'), tsn=1, hsn=3), 0x1000)
        pair(name, data, len(data))
    return packets, cases


def build_tcg_continuation_domains_pcapng(output_path):
    packets, _ = tcg_continuation_domains_vectors()
    write_pcapng(output_path, packets, 1720000000 * 1_000_000)


def tcg_synchronous_atom_vectors():
    """Core 2.01 3.3.10.3(a) forbids a synchronous method spanning
    ComPackets, so an atom that a complete, fully captured synchronous
    ComPacket cannot hold is rejected (Tables 10-13 atom sizes, 3.2.3.1,
    Table 20). Endpoint S settles synchronous mode only by Level 0 Async
    Supported = 0 (3.3.6.4.2) and reports no SSC feature: it is not an Opal
    endpoint, whose MaxIndTokenSize is at least 1992 (Opal 2.30 Table 17);
    no MaxIndTokenSize is asserted. Endpoint A observes Asynchronous = TRUE
    on both sides; endpoint N has no evidence. Return ((packet, original
    length) list, request/response frame map)."""
    packets, cases = [], {}
    S, A, N = 0x20, 0x21, 0x22
    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
            + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0' + tcg_bytes_atom(TCG_ADMIN_SP) + b'\xf1'
            + TCG_EOD_STATUS_SUCCESS)
    huge = b'\x01\xe2\xff\xff\xff'  # declares 16,777,219 bytes

    def pair(name, data, eid=S, send=False, al=None, keep=None, secp=1, spsp=0x1000):
        assert name not in cases
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        al = len(data) if al is None else al
        opcode = NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV
        request = admin_request_payload(opcode, ctrl_id=1, flags=0,
                                        cns=security_cdw10(secp, spsp),
                                        cdw11=al, dlen=al, doff=0)
        for is_request, body in ((True, request + (data if send else b'')),
                                 (False, admin_resp_with_data(b'' if send else data))):
            packet = make_packet(is_request, NVME_MI_TYPE_ADMIN, 0, body,
                                 bmc_eid=eid, tag=(n // 2) % 8)
            original = len(packet)
            if not is_request and keep is not None:
                packet = packet[:original - len(data) - 4 + keep]
            packets.append((packet, original))

    def pkt(tsn, hsn, *subpackets):
        return tcg_packet(b''.join(map(tcg_subpacket, subpackets)), tsn, hsn, 0)

    def cp(*pkts):
        return tcg_compacket(b''.join(pkts), 0x1000)

    def startup(method, hsn, tsn, keys=False):
        args = tcg_tiny_uint(hsn) + (tcg_bytes_atom(TCG_ADMIN_SP) + b'\x01'
                                     if method == 0xff02 else tcg_short_uint(tsn, 4))
        if keys:
            args += b'\xf2\x01\xa4KEY!\xf3'
        return (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                + tcg_bytes_atom(method.to_bytes(8, 'big')) + b'\xf0'
                + args + b'\xf1' + TCG_EOD_STATUS_SUCCESS)

    def establish(name, hsn, tsn):
        for method in (0xff03, 0xff04, 0xff05):
            pair(f'{name}-{method:x}', cp(pkt(0, 0, startup(
                method, hsn, tsn, method != 0xff03))), send=method == 0xff04)

    tper = tcg_l0_feature(1, 1, b'\x01' + bytes(11))  # Sync only, no SSC
    pair('l0-sync', struct.pack('>IHH', 44 + len(tper), 0, 1) + bytes(40) + tper, spsp=1)
    header = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
              + tcg_bytes_atom(bytes.fromhex('000000000000ff01')))
    values = (b'\xf0\xf2' + tcg_bytes_atom(b'Asynchronous') + b'\x01\xf3\xf1')
    host = b'\xf2\x00' + values + b'\xf3'
    pair('async-properties-request', cp(pkt(0, 0, header + b'\xf0' + host + b'\xf1'
                                            + TCG_EOD_STATUS_SUCCESS)), eid=A, send=True)
    pair('async-properties-response', cp(pkt(0, 0, header + b'\xf0' + values + host
                                             + b'\xf1' + TCG_EOD_STATUS_SUCCESS)), eid=A)

    # (1) Control session: the next Packet's StartSession is observed.
    pair('control', cp(pkt(0, 0, huge), pkt(0, 0, startup(0xff02, 0x31, 0))), send=True)
    # (2) A later Data Subpacket of the violating Packet is not observed.
    pair('control-subpacket', cp(pkt(0, 0, huge, startup(0xff02, 0x32, 0)),
                                 pkt(0, 0, startup(0xff02, 0x33, 0))), send=True)
    for hsn, tsn in ((0x31, 0x5100), (0x32, 0x5200), (0x33, 0x5300)):
        establish(f'control-{hsn:x}', hsn, tsn)
        pair(f'control-{hsn:x}-payload', cp(pkt(tsn, hsn, call)))
    # (3) Regular session: aborted in both directions until SyncSession.
    pair('regular', cp(pkt(0x5400, 0x34, huge, call), pkt(0x5401, 0x35, call)))
    pair('regular-next', cp(pkt(0x5400, 0x34, call)))
    pair('regular-host', cp(pkt(0x5400, 0x34, call)), send=True)
    pair('regular-other', cp(pkt(0x5401, 0x35, call)))
    pair('regular-ff02', cp(pkt(0, 0, startup(0xff02, 0x34, 0))), send=True)
    pair('regular-ff03', cp(pkt(0, 0, startup(0xff03, 0x34, 0x5400))))
    pair('regular-restarted', cp(pkt(0x5400, 0x34, call)))
    pair('regular-restarted-host', cp(pkt(0x5400, 0x34, call)), send=True)
    # (4) A legitimate atom continues across Packets of one ComPacket.
    pair('split', cp(pkt(0x5600, 0x36, b'\xd0\x02'), pkt(0x5600, 0x36, b'\xaa\xbb')))
    # (5) The first deferral is permitted; the completed header is not.
    pair('split-header', cp(pkt(0, 0, b'\xe2'), pkt(0, 0, b'\xff\xff\xff'), pkt(0, 0, call)))
    # (6) After reassembly the tail is measured in transfer coordinates:
    # D0 08 needs 10 bytes, but only 2 + 3 pad remain in the ComPacket; a
    # tail measured from the 6-byte child's endpoint would admit it.
    pair('reassembled', cp(pkt(0x5700, 0x37, b'\xd0'),
                           pkt(0x5700, 0x37, b'\x02\xaa\xbb\xe2\xff\xff\xff')))
    pair('reassembled-next', cp(pkt(0x5700, 0x37, call)))
    pair('reassembled-medium', cp(pkt(0x5701, 0x38, b'\xd0'),
                                  pkt(0x5701, 0x38, b'\x02\xaa\xbb\xd0\x08')))
    # (7) Asynchronous and no-evidence continuation across ComPackets is
    # kept, including the corrupt declaration (accepted residual gap).
    for prefix, eid in (('async', A), ('none', N)):
        pair(prefix + '-first', cp(pkt(0x5800, 0x38, b'\xd0\x02')), eid=eid)
        pair(prefix + '-last', cp(pkt(0x5800, 0x38, b'\xaa\xbb')), eid=eid)
        pair(prefix + '-huge', cp(pkt(0x5801, 0x39, huge)), eid=eid)
        pair(prefix + '-huge-next', cp(pkt(0x5801, 0x39, call)), eid=eid)
    # (8) Incomplete or clamped endpoints prove nothing.
    short = cp(pkt(0x5900, 0x39, huge))
    short = short[:16] + struct.pack('>I', len(short) - 12) + short[20:]
    pair('short-transfer', short, al=len(short) + 8)
    pair('short-transfer-next', cp(pkt(0x5900, 0x39, call)))
    # Keeps Packet 1 and the second Packet's TSN, HSN and SeqNumber.
    pair('snaplen', cp(pkt(0x5a00, 0x3a, huge), pkt(0x5a01, 0x3b, call)), keep=76)
    pair('snaplen-next', cp(pkt(0x5a00, 0x3a, call)))
    lying = tcg_subpacket(b'')[:8] + struct.pack('>I', 64) + huge + bytes(3)
    pair('lying', cp(tcg_packet(lying, 0x5c00, 0x3c, 0)))
    pair('lying-next', cp(pkt(0x5c00, 0x3c, call)))
    # (9) Transfer padding past the ComPacket never enlarges the bound.
    pair('padding', cp(pkt(0x5d00, 0x3d, b'\xd0\x10')) + bytes(32))
    pair('padding-next', cp(pkt(0x5d00, 0x3d, call)))
    # (10) Pad counts toward the bound: accepted conservative gap.
    pair('terminal', cp(pkt(0x5e00, 0x3e, b'\xd0')))
    pair('terminal-next', cp(pkt(0x5e00, 0x3e, call)))
    # (11) A 1992-byte medium atom fits a synchronous ComPacket.
    atom = tcg_medium_bytes_atom(bytes(i % 251 for i in range(1990)))
    assert atom[:2] == b'\xd7\xc6' and len(atom) == 1992
    pair('atom-1992', cp(pkt(0x5f00, 0x3f, atom)))
    pair('atom-1992-split', cp(pkt(0x5f00, 0x3f, atom[:996]), pkt(0x5f00, 0x3f, atom[996:])))
    pair('atom-1992-next', cp(pkt(0x5f00, 0x3f, call)))
    return packets, cases


def build_tcg_synchronous_atom_pcapng(output_path):
    packets, _ = tcg_synchronous_atom_vectors()
    write_pcapng(output_path, packets, 1721000000 * 1_000_000)


def tcg_level0_prefix_vectors():
    """Core 2.01 3.3.6.2 lets AL truncate Level 0 Discovery and owes
    padding past it; MI 2.2 Fig 139 DLEN selects the bytes returned at
    DOFST; NVMe/TCP 1.3 3.3.2.1 / Fig 33 LAST_PDU marks the final C2HData
    PDU.  Synthetic Core revision 0.1 discovery (not an Opal 2.30 response):
    48-byte header, version-1 TPer and Locking bodies of 12 at 48 and 64.
    MI on interface 0, NVMe/TCP on interface 1 (host port 55300).
    Return ((interface, captured bytes, original length) list, local map)."""
    packets, cases = [], {}

    def l0(features, plen=None):
        return struct.pack('>IHH', 44 + len(features) if plen is None else plen,
                           0, 1) + bytes(40) + features

    tper = tcg_l0_feature(1, 1, b'\x41' + bytes(11))
    locking = tcg_l0_feature(2, 1, b'\x03' + bytes(11))
    valid = l0(tper + locking)                           # R80/P76
    r64 = l0(tper)                                       # R64/P60
    overrun = l0(tper + locking[:4], plen=64)            # R68, Locking body 12
    tail = l0(tper + locking[:2], plen=62) + bytes(2)    # R66 + 2 padding
    assert (len(valid), len(r64), len(overrun), len(tail)) == (80, 64, 68, 68)

    def mi(name, data, al, dlen, dofst=0, keep=None):
        assert name not in cases
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1, flags=0,
            cns=security_cdw10(1, 1), cdw11=al, dlen=dlen, doff=dofst)
        for is_request, body in ((True, request), (False, admin_resp_with_data(data))):
            packet = make_packet(is_request, NVME_MI_TYPE_ADMIN, 0, body,
                                 tag=(n // 2) % 8)
            original = len(packet)
            if not is_request and keep is not None:
                # Captured: SLL/MCTP/MI/Admin headers and `keep` data bytes.
                packet = packet[:original - len(data) - 4 + keep]
            packets.append((0, packet, original))

    mi('selected-header', valid[:16], 128, 16)
    mi('selected-body', valid[:68], 128, 68)
    mi('allocation-body', valid[:68], 68, 68)
    mi('short-header', valid[:16], 128, 48)
    mi('short-body', valid[:68], 128, 80)
    mi('short-selected-body', valid[:68], 128, 72)
    mi('complete-parent-overrun', overrun, 128, 68)
    mi('complete-parent-header-tail', tail, 128, 68)
    mi('bad-length-prefix', l0(tper + locking, plen=43)[:16], 128, 16)
    mi('surplus', valid, 128, 68)
    mi('selected-snaplen', valid[:68], 128, 68, keep=60)
    mi('later-window', valid[4:68], 128, 64, dofst=4)
    mi('complete-selected', valid, 128, 80)
    mi('selected-padding', valid + bytes(16), 128, 96)
    # Complete R64 discovery against owed padding (Core 3.3.6.2).
    mi('padding-short-80', r64, 128, 80)
    mi('padding-short-68', r64, 128, 68)
    mi('padding-selected-64', r64, 128, 64)
    mi('padding-partial-80', r64 + bytes(4), 128, 80)
    mi('padding-complete-80', r64 + bytes(16), 128, 80)
    mi('padding-snaplen-80', r64 + bytes(16), 128, 80, keep=64)
    mi('padding-overrun-80', overrun, 128, 80)

    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                       'gen-nvme-tcp-test-capture.py'))
    sequence = [1, 1]
    ports = {'HOST': 55300, 'CTRL': tcpgen['CTRL_PORT']}

    def emit(pdu, send, keep=None):
        side = 0 if send else 1
        src, dst = ('HOST', 'CTRL') if send else ('CTRL', 'HOST')
        tcp = tcpgen['tcp'](ports[src], ports[dst], sequence[side],
                            sequence[1 - side], pdu)
        ip = tcpgen['ipv4'](tcpgen[src + '_IP'], tcpgen[dst + '_IP'], tcp,
                            0x7800 + len(packets))
        packet = tcpgen['eth'](tcpgen[dst + '_MAC'], tcpgen[src + '_MAC'], ip)
        original = len(packet)
        if keep is not None:
            # The C2HData PDU has a 24-byte header; retain its declarations.
            packet = packet[:original - len(pdu) + 24 + keep]
        packets.append((1, packet, original))
        sequence[side] += len(pdu)

    cases['native-admin-queue'] = (len(packets) + 1,)
    emit(tcpgen['capsule_cmd_pdu'](tcpgen['sqe'](6, 1, cdw10=1)), True)

    def native(name, al, *windows):
        """windows: (payload, DATAO, final, keep, DATAL) per C2HData PDU."""
        assert name not in cases
        frames = [len(packets) + i + 1 for i in range(1 + len(windows))]
        cases[name] = tuple(frames)
        cid = len(cases) + 1
        sqe = tcpgen['sqe'](NVME_AQ_OPC_SECURITY_RECV, cid,
                            cdw10=security_cdw10(1, 1), cdw11=al)
        emit(tcpgen['capsule_cmd_pdu'](sqe), True)
        for payload, datao, final, keep, datal in windows:
            emit(tcpgen['c2h_data_pdu'](cid, payload, datal=datal, datao=datao,
                                        pdo=24, last=final, success=final),
                 False, keep)

    def w(payload, datao=0, final=False, keep=None, datal=None):
        return (payload, datao, final, keep, datal)

    native('native-nonfinal-body', 80, w(valid[:68]), w(valid[68:], 68, True))
    native('native-nonfinal-header', 80, w(valid[:16]), w(valid[16:], 16, True))
    native('native-final-short-body', 80, w(valid[:68], final=True))
    native('native-padding-short', 80, w(r64, final=True))
    native('native-padding-nonfinal', 80, w(r64), w(bytes(16), 64, True))
    native('native-nonfinal-overrun', 80, w(overrun), w(bytes(12), 68, True))
    native('native-nonfinal-snaplen', 80, w(valid[:68], keep=60),
           w(valid[68:], 68, True))
    native('native-nonfinal-bad-span', 80, w(valid[:68], datal=80))
    # Leak order: a non-final initial window, then a final one at DATAO 0
    # for the same command; each dissection must recompute the prefix fact.
    native('native-leak-order', 80, w(valid[:68]), w(valid[:68], final=True))
    return packets, cases


def build_tcg_level0_prefix_pcapng(output_path):
    packets, _ = tcg_level0_prefix_vectors()
    write_pcapng(output_path, [(packet, original, interface) for interface, packet, original in packets], 1722000000 * 1_000_000, idb() + idb(link_type=1))


def mi_admin_frame(is_request, body, eid, tag, mic='good', keep=None):
    """One NVMe-MI Admin message to or from BMC EID `eid`, with its MIC
    'good', 'bad' (complemented), 'none' (IC = 0) or 'snap' (captured without
    the MIC); `keep` captures only that many Admin body bytes. Returns
    (packet, original length)."""
    bad = None
    if mic == 'bad':
        bad = crc32c(nvme_mi_header(NVME_MI_TYPE_ADMIN, 0, not is_request)
                     + body) ^ 0xFFFFFFFF
    packet = make_packet(is_request, NVME_MI_TYPE_ADMIN, 0, body, bmc_eid=eid,
                         tag=tag, ic=mic != 'none', mic=bad)
    original = len(packet)
    if mic == 'snap':
        packet = packet[:original - 4]
    if keep is not None:
        packet = packet[:original - (0 if mic == 'none' else 4) - len(body) + keep]
    return packet, original


def mi_security_request(send, secp, spsp, data=b'', tl=None, dlen=None, doff=0):
    """A Security Send (with its Request Data) or Receive Admin request; TL or
    AL defaults to len(data) and DLEN to TL/AL."""
    tl = len(data) if tl is None else tl
    opcode = NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV
    return admin_request_payload(opcode, ctrl_id=1, flags=0,
                                 cns=security_cdw10(secp, spsp), cdw11=tl,
                                 dlen=tl if dlen is None else dlen,
                                 doff=doff) + (data if send else b'')


def mi_replay_frames(eid, tag, ctl_tag, response):
    """A Replay Control Primitive on `tag`, its Response Replayed answer and the
    replayed Admin Response Message `response` (NVMe-MI 2.1 4.2.1.5)."""
    return [(p, len(p)) for p in (
        make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                    cp_request_payload(CP_OPC_REPLAY, tag=ctl_tag),
                    bmc_eid=eid, tag=tag),
        make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                    cp_response_payload(STATUS_SUCCESS, tag=ctl_tag, cpsr=0x0001),
                    bmc_eid=eid, tag=tag),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0, response, bmc_eid=eid, tag=tag))]


TCG_TX7_EID = 0xA0  # one fresh endpoint per case: A0h onward


def tcg_integrity_note_vectors():
    """NVMe-MI does not authorize tracked TCG Security state without
    verified-good MICs (NVMe-MI 2.1 3.2.1.1), and one generic
    nvme-mi.admin.security_state_integrity note says so wherever integrity
    alone withholds it from otherwise eligible Security data or a TPer Reset
    completion (Opal SSC 2.30 3.2.3). Every case is a request then its
    response unless noted, on an endpoint of its own so that no case
    supersedes another's request slot. Return ((packet, original length)
    list, {case: section frames})."""
    packets, cases = [], {}
    compacket = tcg_compacket(tcg_packet(tcg_subpacket(TCG_EOD_STATUS_SUCCESS),
                                         0x100, 0x1), 0x1000)
    level0 = struct.pack('>IHH', 44, 0, 1) + bytes(40)
    stack_reset = struct.pack('>HHI', 0x1000, 0, 2)
    secp0 = secp0_supported_list([0, 1, 2])
    secp0 += bytes(-len(secp0) % 4)
    good_cqe = admin_resp_with_data(b'')
    invalid_field = admin_response_payload(STATUS_SUCCESS, cqe3=admin_cqe3(
        cqe_status_word(sc=0x02, dnr=1, phase=1)))

    def add(name, *frames):
        assert name not in cases
        cases[name] = tuple(range(len(packets) + 1, len(packets) + 1 + len(frames)))
        packets.extend(frames)

    def pair(name, send, secp=1, spsp=0x1000, data=compacket, tl=None, dlen=None,
             doff=0, req='good', rsp='good', response=None, keep_req=None,
             keep_rsp=None):
        tag, eid = len(cases) % 8, TCG_TX7_EID + len(cases)
        request = mi_security_request(send, secp, spsp, data, tl, dlen, doff)
        if response is None:
            response = good_cqe if send else admin_resp_with_data(data)
        add(name, mi_admin_frame(True, request, eid, tag, req, keep_req),
            mi_admin_frame(False, response, eid, tag, rsp, keep_rsp))

    # (1)-(5) Eligible Security data: a note only without both verdicts.
    pair('send-good', True)
    pair('recv-good', False)
    pair('send-bad', True, req='bad')
    pair('recv-bad', False, rsp='bad')
    pair('recv-bad-request', False, req='bad')
    pair('recv-nomic-request', False, req='none')
    pair('send-snap', True, req='snap')
    pair('recv-snap', False, rsp='snap')
    # (6)-(7) Another gate withholds the data: no note.
    pair('send-sliced', True, keep_req=64 + 10)
    pair('recv-sliced', False, keep_rsp=16 + 10)
    add('recv-orphan', mi_admin_frame(False, admin_resp_with_data(compacket),
                                      TCG_TX7_EID + len(cases), 7, 'bad'))
    pair('recv-mi-error', False, rsp='bad',
         response=admin_response_payload_short(STATUS_INTERNAL_ERROR))
    pair('recv-cqe-error', False, rsp='bad', response=invalid_field + compacket)
    pair('send-invalid-window', True, data=compacket[:4], tl=8, req='bad')
    pair('recv-invalid-window', False, data=compacket[:4], tl=4, dlen=8, req='bad',
         response=admin_resp_with_data(compacket[:8]))
    pair('recv-later-window', False, tl=len(compacket), dlen=len(compacket) - 4, doff=4,
         rsp='bad', response=admin_resp_with_data(compacket[4:]))
    pair('recv-short', False, rsp='bad', response=admin_resp_with_data(compacket[:-4]))
    pair('recv-surplus', False, rsp='bad', response=admin_resp_with_data(compacket + bytes(4)))
    pair('send-response-data', True, rsp='bad', response=admin_resp_with_data(bytes(4)))
    # (8) Selector controls, each with one failing verdict.
    pair('tper-reset-send', True, secp=2, spsp=4, data=bytes(4), req='bad')
    pair('stack-reset-send', True, secp=2, data=stack_reset, req='bad')
    pair('level0-recv', False, spsp=1, data=level0, rsp='bad')
    pair('level0-send', True, spsp=1, data=bytes(4), req='bad')
    pair('secp3-send', True, secp=3, data=bytes(4), req='bad')
    pair('secp0-recv', False, secp=0, spsp=0, data=secp0, rsp='bad')
    # (10) CQE-only TPer Reset completions.
    tper = {'secp': 2, 'spsp': 4, 'data': bytes(4)}
    pair('tper-good', True, **tper)
    pair('tper-bad-request', True, req='bad', **tper)
    pair('tper-bad-response', True, rsp='bad', **tper)
    pair('tper-nomic-response', True, rsp='none', **tper)
    pair('tper-snap-response', True, rsp='snap', **tper)
    pair('tper-sliced-cqe', True, rsp='bad', keep_rsp=14, **tper)
    pair('tper-short-cqe', True, rsp='bad',
         response=admin_response_payload_short(STATUS_SUCCESS), **tper)
    pair('tper-cqe-error', True, rsp='bad', response=invalid_field, **tper)
    pair('tper-mi-error', True, rsp='bad',
         response=admin_response_payload_short(STATUS_INTERNAL_ERROR), **tper)
    add('tper-orphan', mi_admin_frame(False, good_cqe, TCG_TX7_EID + len(cases), 7, 'bad'))
    pair('tper-incomplete-request', True, rsp='bad', keep_req=64 + 2, **tper)
    pair('tper-invalid-request', True, rsp='bad', tl=8, **tper)
    pair('tper-response-data', True, rsp='bad', response=admin_resp_with_data(bytes(4)),
         **tper)
    pair('stack-reset-completion', True, secp=2, data=stack_reset, rsp='bad')
    pair('compacket-completion', True, rsp='bad')
    # Replays: the original response gets the note (its request has no MIC);
    # the replayed one never authorizes state, so it gets none.
    for name, send, data in (('recv-replay', False, compacket),
                             ('tper-replay', True, bytes(4))):
        tag, eid = len(cases) % 8, TCG_TX7_EID + len(cases)
        secp = 2 if send else 1
        spsp = 4 if send else 0x1000
        response = good_cqe if send else admin_resp_with_data(data)
        add(name,
            mi_admin_frame(True, mi_security_request(send, secp, spsp, data), eid, tag,
                           'none'),
            mi_admin_frame(False, response, eid, tag),
            *mi_replay_frames(eid, (tag + 1) % 8, 0x70 + tag, response))
    return packets, cases


def build_tcg_integrity_note_pcapng(output_path):
    packets, _ = tcg_integrity_note_vectors()
    write_pcapng(output_path, packets, 1723000000 * 1_000_000)


TCG_T34_EID = 0x60  # one or two fresh endpoints per case: 60h onward


def tcg_startup(method, hsn, tsn):
    """A Session Manager method call: StartSession (FF02h) carries the Admin
    SP, SyncSession (FF03h) and the trusted pair (FF04h/FF05h) the TSN, and
    the trusted pair adds a challenge."""
    args = tcg_tiny_uint(hsn)
    args += (tcg_bytes_atom(TCG_ADMIN_SP) + b'\x01' if method == 0xff02
             else tcg_short_uint(tsn, 4))
    if method in (0xff04, 0xff05):
        args += b'\xf2\x01\xa4KEY!\xf3'
    return (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
            + tcg_bytes_atom(method.to_bytes(8, 'big')) + b'\xf0'
            + args + b'\xf1' + TCG_EOD_STATUS_SUCCESS)


def tcg_reset_lifecycle_vectors():
    """A trusted STACK_RESET Success resets its Extended ComID immediately;
    a verified MI completion of a TPer Reset (Opal SSC 2.30 3.2.3) retires
    every ComID of its transport scope. Each case uses its own endpoint(s)
    on ComID 1000h.
    Return ((packet, original length) list, {case: section frames})."""
    packets, cases, tags, controls = [], {}, {}, {}
    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID) + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0' + tcg_bytes_atom(TCG_ADMIN_SP) + b'\xf1' + TCG_EOD_STATUS_SUCCESS)
    split = 6  # inside the Invoking UID
    good_cqe = admin_resp_with_data(b'')
    invalid_field = admin_response_payload(STATUS_SUCCESS, cqe3=admin_cqe3(
        cqe_status_word(sc=0x02, dnr=1, phase=1)))

    def add(name, *frames):
        assert name not in cases
        cases[name] = tuple(range(len(packets) + 1, len(packets) + 1 + len(frames)))
        packets.extend(frames)

    def pair(name, eid, send, data, secp=1, spsp=0x1000, tl=None, req='good',
             rsp='good', response=None, request_only=False):
        tag = tags.get(eid, 0)
        tags[eid] = (tag + 1) % 8
        if response is None:
            response = good_cqe if send else admin_resp_with_data(data)
        frames = [mi_admin_frame(True, mi_security_request(send, secp, spsp, data, tl),
                                 eid, tag, req)]
        if not request_only:
            frames.append(mi_admin_frame(False, response, eid, tag, rsp))
        add(name, *frames)

    def cp(tokens, tsn, hsn, seq, ext, comid=0x1000):
        return tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn, seq), comid, ext)

    def properties(name, eid, ext, status_word=None):
        """Both sides number Packets and are Asynchronous (Core 5.2.2.2)."""
        values = b'\xf0' + b''.join(b'\xf2' + tcg_bytes_atom(key) + b'\x01\xf3'
                                    for key in (b'SequenceNumbers', b'Asynchronous')) + b'\xf1'
        header = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                  + tcg_bytes_atom(bytes.fromhex('000000000000ff01')))
        host = b'\xf2\x00' + values + b'\xf3'
        pair(name + '-props', eid, True, cp(header + b'\xf0' + host + b'\xf1'
             + TCG_EOD_STATUS_SUCCESS, 0, 0, 0, ext))
        response_data = cp(header + b'\xf0' + values + host + b'\xf1'
                           + TCG_EOD_STATUS_SUCCESS, 0, 0, 0, ext)
        response = None
        if status_word is not None:
            response = (admin_response_payload(STATUS_SUCCESS,
                                               cqe3=admin_cqe3(status_word))
                        + response_data)
        pair(name + '-props-response', eid, False, response_data, response=response)

    def establish(name, eid, ext, hsn, tsn):
        """Trusted startup on the control session (Core 5.2.3), numbered per
        direction in case the Extended ComID numbers Packets."""
        for method in (0xff02, 0xff03, 0xff04, 0xff05):
            send = method in (0xff02, 0xff04)
            seq = controls.get((eid, ext, send), 0) + 1
            controls[(eid, ext, send)] = seq
            pair(f'{name}-{method:x}', eid, send, cp(tcg_startup(method, hsn, tsn), 0, 0, seq, ext))

    def reset_request(name, eid, ext, code=2):
        pair(name, eid, True, struct.pack('>HHI', 0x1000, ext, code), secp=2)

    def reset_result(name, eid, ext, result=0, available=4, code=2):
        body = struct.pack('>HHIHH', 0x1000, ext, code, 0, available)
        pair(name, eid, False, body + (struct.pack('>I', result) if available else b''),
             secp=2)

    def tper(name, eid, **kw):
        pair(name, eid, True, bytes(4), secp=2, spsp=4, **kw)

    def get_comid(name, eid, ext):
        pair(name, eid, False, struct.pack('>I', 0x10000000 | ext) + bytes(4), secp=2, spsp=0)

    def payload(name, eid, ext, tsn, hsn, seq=1, send=False, tokens=call, comid=0x1000):
        pair(name, eid, send, cp(tokens, tsn, hsn, seq, ext, comid), spsp=comid)

    # (1) Late Success: Properties and a trusted session ran after the request.
    e = TCG_T34_EID
    reset_request('late-reset', e, 1)
    properties('late', e, 1)
    establish('late', e, 1, 1, 0x6000)
    payload('late-secure', e, 1, 0x6000, 1, seq=1)
    reset_result('late-success', e, 1)
    payload('late-raw', e, 1, 0x6000, 1, seq=2)
    reset_result('late-repeat', e, 1)
    payload('late-duplicate', e, 1, 0x6000, 1, seq=2)
    payload('late-old', e, 1, 0x6000, 1, seq=1)

    # (2) Quiet Success: nothing between request and result. Its twins see one
    # empty or one duplicate ComPacket in between.
    e += 1
    establish('quiet', e, 2, 2, 0x6001)
    payload('quiet-secure', e, 2, 0x6001, 2)
    reset_request('quiet-reset', e, 2)
    reset_result('quiet-success', e, 2)
    payload('quiet-old', e, 2, 0x6001, 2)
    payload('quiet-first', e, 2, 0x6002, 1, tokens=call[:split])
    payload('quiet-next', e, 2, 0x6002, 1)
    establish('quiet-new', e, 2, 3, 0x6003)
    payload('quiet-new-secure', e, 2, 0x6003, 3)
    reset_result('quiet-repeat', e, 2)
    payload('quiet-new-again', e, 2, 0x6003, 3)
    for twin, traffic in (('empty', tcg_compacket(b'', 0x1000, 2)),
                          ('duplicate', cp(call, 0x6001, 2, 1, 2))):
        e += 1
        establish(twin, e, 2, 2, 0x6001)
        payload(twin + '-secure', e, 2, 0x6001, 2)
        reset_request(twin + '-reset', e, 2)
        pair(twin + '-traffic', e, False, traffic)
        reset_result(twin + '-success', e, 2)
        payload(twin + '-after', e, 2, 0x6001, 2)

    # (3) Supersession, failure, Pending and No Response Available.
    for name, code in (('verify', 1), ('unknown', 0x99)):
        e += 1
        establish(name, e, 4, 4, 0x6004)
        reset_request(name + '-reset', e, 4)
        reset_request(name + '-supersede', e, 4, code)
        reset_result(name + '-success', e, 4)
        payload(name + '-after', e, 4, 0x6004, 4)
    e += 1
    establish('fail', e, 6, 6, 0x6006)
    reset_request('fail-reset', e, 6)
    reset_result('fail-failure', e, 6, result=1)
    reset_result('fail-pending', e, 6, available=0)
    reset_result('fail-none', e, 6, available=0, code=0)
    payload('fail-secure', e, 6, 0x6006, 6)
    reset_result('fail-success', e, 6)
    payload('fail-raw', e, 6, 0x6006, 6)
    reset_request('fail-reset-again', e, 6)
    reset_result('fail-success-again', e, 6)
    establish('fail-new', e, 6, 7, 0x6007)
    payload('fail-new-secure', e, 6, 0x6007, 7)

    # (4) A replacement issued or retired before an old Success survives it.
    e += 1
    establish('reissue', e, 7, 8, 0x6008)
    reset_request('reissue-reset', e, 7)
    get_comid('reissue-get', e, 7)
    establish('reissue-new', e, 7, 9, 0x6009)
    reset_result('reissue-success', e, 7)
    payload('reissue-new-secure', e, 7, 0x6009, 9)
    payload('reissue-old', e, 7, 0x6008, 8)
    e += 1
    establish('retire', e, 8, 10, 0x600a)
    reset_request('retire-reset', e, 8)
    tper('retire-tper', e)
    establish('retire-new', e, 8, 11, 0x600b)
    reset_result('retire-success', e, 8)
    payload('retire-new-secure', e, 8, 0x600b, 11)

    # (5) TPer Reset retires all of scope a, not scope b.
    a, b = e + 1, e + 2
    e += 2
    for eid, side in ((a, 'a'), (b, 'b')):
        properties(f'{side}9', eid, 9)
        establish(f'{side}9', eid, 9, 12, 0x600c)
        establish(f'{side}10', eid, 10, 13, 0x600d)
    payload('a9-secure', a, 9, 0x600c, 12, seq=1)
    payload('a10-secure', a, 10, 0x600d, 13)
    payload('a9-first', a, 9, 0x600e, 14, seq=1, tokens=call[:split])
    tper('a-tper', a)
    payload('a9-old', a, 9, 0x600c, 12, seq=2)
    payload('a9-host-old', a, 9, 0x600c, 12, seq=1, send=True)
    payload('a10-old', a, 10, 0x600d, 13)
    payload('a9-next', a, 9, 0x600e, 14, seq=2, tokens=call[split:])
    payload('a9-reset-first', a, 9, 0x6016, 22, tokens=call[:split])
    payload('b9-first', b, 9, 0x6016, 22, tokens=call[:split])
    payload('b9-secure', b, 9, 0x600c, 12, seq=1)
    payload('b10-secure', b, 10, 0x600d, 13)
    establish('a10-new', a, 10, 15, 0x600f)
    payload('a10-new-secure', a, 10, 0x600f, 15)
    payload('a10-first', a, 10, 0x6010, 16, tokens=call[:split])
    payload('a10-next', a, 10, 0x6010, 16)

    # (6) TPer Reset requests whose completion does not show success.
    # (7) ... or whose integrity or context is not verified; and a Replay.
    for name, kw in (('mi-error', {'response': admin_response_payload_short(
                                           STATUS_INTERNAL_ERROR)}),
                     ('cqe-error', {'response': invalid_field}),
                     ('missing', {'request_only': True}),
                     ('short-cqe', {'response': admin_response_payload_short(
                                            STATUS_SUCCESS)}),
                     ('zero', {'tl': 0}),
                     ('invalid', {'tl': 8}),
                     ('data', {'response': admin_resp_with_data(bytes(4))}),
                     ('bad-response', {'rsp': 'bad'}),
                     ('bad-request', {'req': 'bad'}),
                     ('snap', {'rsp': 'snap'})):
        e += 1
        establish(name, e, 16, 17, 0x6011)
        if name == 'zero':
            pair('zero-tper', e, True, b'', secp=2, spsp=4)
        else:
            tper(name + '-tper', e, **kw)
        payload(name + '-secure', e, 16, 0x6011, 17)
    e += 1
    establish('orphan', e, 16, 17, 0x6011)
    add('orphan-tper', mi_admin_frame(False, good_cqe, e, 7))
    payload('orphan-secure', e, 16, 0x6011, 17)
    e += 1
    establish('replay', e, 16, 17, 0x6011)
    tag = tags[e]
    tags[e] = (tag + 2) % 8
    request = mi_security_request(True, 2, 4, bytes(4))
    add('replay-tper', mi_admin_frame(True, request, e, tag),
        mi_admin_frame(False, good_cqe, e, tag))
    establish('replay-new', e, 16, 18, 0x6012)
    add('replay-replayed', *mi_replay_frames(e, (tag + 1) % 8, 0x70 + tag, good_cqe))
    payload('replay-new-secure', e, 16, 0x6012, 18)

    # (8) An uncertain ComID's control session is forensic only.
    e += 1
    establish('forensic', e, 17, 19, 0x6013)
    payload('forensic-secure', e, 17, 0x6013, 19)
    reset_result('forensic-unmatched', e, 17)
    properties('forensic', e, 17)
    establish('forensic-revive', e, 17, 20, 0x6014)
    payload('forensic-revive-raw', e, 17, 0x6014, 20)
    reset_result('forensic-unmatched-again', e, 17)
    get_comid('forensic-get', e, 17)
    establish('forensic-new', e, 17, 21, 0x6015)
    payload('forensic-new-secure', e, 17, 0x6015, 21)

    # (9) A quiet STACK_RESET overrides an observed Asynchronous=TRUE.
    e += 1
    properties('sync', e, 18)
    payload('sync-async-first', e, 18, 0x6017, 23, seq=1, tokens=call[:split])
    reset_request('sync-reset', e, 18)
    reset_result('sync-success', e, 18)
    payload('sync-first', e, 18, 0x6017, 23, tokens=call[:split])

    # (10) M and DNR do not change a successful SCT/SC status.
    status_word = cqe_status_word(m=1, dnr=1, phase=1)
    e += 1
    properties('status-bits-properties', e, 19, status_word)
    establish('status-bits-properties', e, 19, 24, 0x6018)
    payload('status-bits-first', e, 19, 0x6018, 24, seq=1)
    payload('status-bits-gap', e, 19, 0x6018, 24, seq=3)
    e += 1
    establish('status-bits-tper', e, 20, 25, 0x6019)
    payload('status-bits-tper-secure', e, 20, 0x6019, 25)
    tper('status-bits-tper', e, response=admin_response_payload(
        STATUS_SUCCESS, cqe3=admin_cqe3(status_word)))
    payload('status-bits-tper-after', e, 20, 0x6019, 25)
    return packets, cases


def build_tcg_reset_lifecycle_pcapng(output_path):
    packets, _ = tcg_reset_lifecycle_vectors()
    write_pcapng(output_path, packets, 1724000000 * 1_000_000)


def tcg_level0_opal230_vectors():
    """Opal SSC 2.30 Level 0 Discovery descriptors over MI Security Receive:
    Locking Version 3 (Table 4) against Version 1 (Core 2.01 Table 43), TPer
    Version 2, SSC Minor Version 0x3 and the C_PIN_SID indicators (Tables 6/7),
    Data Removal Times (Tables 8/11/12), the Data Removal Mechanism Version 2
    Length (Table 9), whole and AL-clipped, and the Reserved feature code 0000h
    (Core 2.01 Table 40).
    Return ((interface, packet) list, {case: (request frame, response frame)})."""
    packets, cases = [], {}

    def pair(name, features, al=None):
        frame = len(packets) + 1
        cases[name] = (frame, frame + 1)
        payload = struct.pack('>IHH', 44 + len(features), 0, 1) + bytes(40) + features
        if al is not None:
            payload = payload[:al]      # AL-truncated Level 0 (Core 3.3.6.2)
        tag = (frame // 2) % 8
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1, flags=0,
            cns=security_cdw10(1, 1), cdw11=len(payload), dlen=len(payload))
        packets.extend(((0, make_packet(True, NVME_MI_TYPE_ADMIN, 0, request, tag=tag)),
                        (0, make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                        admin_resp_with_data(payload), tag=tag))))

    def opal2(minor, initial, revert):
        return tcg_l0_feature(0x0203, 2, struct.pack('>HHBHHBB', 0x1000, 1, 0, 4, 4,
                                                     initial, revert) + bytes(5), minor=minor)

    pair('locking-v3', tcg_l0_feature(2, 3, b'\xc5' + bytes(11)))
    pair('locking-v1-reserved', tcg_l0_feature(2, 1, b'\xc5' + bytes(11)))
    pair('locking-v2', tcg_l0_feature(2, 2, b'\xc5' + bytes(11)))
    pair('locking-v4-extended', tcg_l0_feature(2, 4, b'\xc5' + bytes(15)))
    pair('tper-v2', tcg_l0_feature(1, 2, b'\x13' + bytes(11)))
    pair('opal2-minor3-msid', opal2(3, 0x00, 0x00))
    pair('opal2-minor3-vu', opal2(3, 0xff, 0xff))
    pair('opal2-minor4-reserved', opal2(4, 0x7f, 0x01))
    drm = (bytes([0x00, 0x00, 0x27, 0x04])
           + struct.pack('>HHH', 0, 0xffff, 5) + bytes(4) + struct.pack('>H', 30)
           + bytes(16))
    pair('drm-times', tcg_l0_feature(0x0404, 2, drm))
    # Core 2.01 Table 40: 0000h is Reserved (and SHALL NOT be returned).
    pair('feature-0000', tcg_l0_feature(0, 1, b'')
         + tcg_l0_feature(1, 1, b'\x41' + bytes(11)))
    # Opal SSC 2.30 Table 9: Version 2 Length is 0x20.
    pair('drm-v2-len16', tcg_l0_feature(0x0404, 2, drm[:16]))
    pair('drm-v2-len36', tcg_l0_feature(0x0404, 2, drm + bytes(4)))
    pair('drm-v3-len16', tcg_l0_feature(0x0404, 3, drm[:16]))
    # AL clips a correctly declared body / a wrongly declared one.
    pair('drm-v2-window', tcg_l0_feature(0x0404, 2, drm), al=48 + 4 + 16)
    pair('drm-v2-len16-window', tcg_l0_feature(0x0404, 2, drm[:16]), al=48 + 4 + 8)
    return packets, cases


def build_tcg_level0_opal230_pcapng(output_path):
    packets, _ = tcg_level0_opal230_vectors()
    write_pcapng(output_path, [(packet, None, interface) for interface, packet in packets],
                 1725000000 * 1_000_000, idb() + idb(link_type=1))


def build_tcg_enclosing_completeness_pcapng(output_path):
    packets, _ = tcg_enclosing_completeness_vectors()
    write_pcapng(output_path, [(packet, original, interface) for interface, packet, original in packets], 1719000000 * 1_000_000, idb() + idb(link_type=1))


def build_tcg_properties_extensions_pcapng(output_path):
    packets, _ = tcg_conformance_vectors(properties_extensions=True)
    write_pcapng(output_path, packets, 1718000000 * 1_000_000)


def build_tcg_corrective_pcapng(output_path):
    packets, _ = tcg_conformance_vectors(corrective=True)
    write_pcapng(output_path, packets, 1716000000 * 1_000_000)


def build_tcg_conformance_pcapng(output_path):
    packets, _ = tcg_conformance_vectors()
    native = [(packet, None, 1) for packet in tcg_native_conformance_vectors()]
    write_pcapng(output_path, packets + native, 1715000000 * 1_000_000,
                 idb() + idb(link_type=1))


def tcg_native_conformance_vectors():
    """The NVMe/TCP generator's nvme-tcp-security.pcapng frames."""
    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                       'gen-nvme-tcp-test-capture.py'))
    return tcpgen['security_native_packets']()


def message_framing_packets():
    """Message header and Control Primitive framing vectors (MI 2.1 Figure 33).

    Each reserved run has zero/nonzero twins. Independent endpoints keep
    schema vectors separate from the explicit temporal sequences at the end.
    Tiny fragments draw the TU errors. Names are the deterministic frame map for the tests.
    """
    records = []
    eid = 0x20

    def add(name, packet, origlen=None):
        records.append((name, packet, origlen))

    def pair(name, kind, request, response, **kwargs):
        nonlocal eid
        eid += 1
        add(name + '_request', make_packet(True, kind, 0, request, bmc_eid=eid, **kwargs))
        add(name + '_response', make_packet(False, kind, 0, response, bmc_eid=eid, **kwargs))

    def mutate(packet, offset, value):
        packet = bytearray(packet)
        packet[20 + offset] = value
        if packet[20] & 0x80:
            packet[-4:] = struct.pack('<I', crc32c(packet[20:-4]))
        return bytes(packet)

    raw = bytes(4)
    add('request_ic0', make_packet(True, NVME_MI_TYPE_PCIE, 0, raw, bmc_eid=0x18, ic=False))
    add('request_ic1', make_packet(True, NVME_MI_TYPE_PCIE, 0, raw, bmc_eid=0x19))
    pair('response_ic0', NVME_MI_TYPE_PCIE, raw, raw)
    name, packet, _ = records[-1]
    add_packet = bytes([packet[20] & 0x7f]) + packet[21:-4]
    records[-1] = (name, packet[:20] + add_packet, None)
    pair('response_ic1', NVME_MI_TYPE_PCIE, raw, raw)
    aem = aem_packet(aeo_list([]))
    add('aem_ic0', aem_packet(aeo_list([]), ic=False))
    add('aem_ic1', aem)
    add('aem_ror', mutate(aem, 1, aem[21] | 0x80))
    add('aem_csi', mutate(aem, 1, aem[21] | 1))
    add('aem_ror_csi', mutate(aem, 1, aem[21] | 0x81))
    for offset, mask in ((1, 6), (2, 0xfc), (3, 0xff)):
        for nonzero in (False, True):
            eid += 1
            packet = make_packet(True, NVME_MI_TYPE_PCIE, 0, raw, bmc_eid=eid)
            add(f'header{offset}_{int(nonzero)}',
                mutate(packet, offset, packet[20 + offset] | (mask if nonzero else 0)))

    for opcode, mask, cpsr in ((0, 0xffff, 3), (1, 0xffff, 0),
                               (2, 0xffff, 0), (3, 0xfffe, 2), (4, 0xff00, 0)):
        for nonzero in (False, True):
            pair(f'cpsp{opcode}_{int(nonzero)}', NVME_MI_TYPE_CONTROL,
                 cp_request_payload(opcode, cpsp=mask if nonzero else 0),
                 cp_response_payload(0, cpsr=cpsr))
    for opcode, mask, cpsr in ((0, 0xfffc, 3), (1, 0xffff, 0),
                               (2, 0xfffc, 0), (3, 4, 2), (4, 0xfffe, 0)):
        for nonzero in (False, True):
            pair(f'cpsr{opcode}_{int(nonzero)}', NVME_MI_TYPE_CONTROL,
                 cp_request_payload(opcode),
                 cp_response_payload(0, cpsr=cpsr | (mask if nonzero else 0)))
    for name, opcode, cpsr in (('pause_bit0_clear', 0, 2),
                               ('pause_bit1_clear', 0, 1),
                               ('cpas_reserved', 2, 3),
                               ('mes_obsolete', 3, 0x22)):
        pair(name, NVME_MI_TYPE_CONTROL, cp_request_payload(opcode),
             cp_response_payload(0, cpsr=cpsr))
    for name, status, mask in (('pel', 4, 0xf8), ('generic', 2, 1)):
        for nonzero in (False, True):
            pair(f'{name}_{int(nonzero)}', NVME_MI_TYPE_CONTROL,
                 cp_request_payload(3), bytes([status, mask if nonzero else 0, 0, 0]))
    mi_request = bytes([1]) + bytes(11)
    admin_request = admin_request_payload(0xc0, flags=0, dlen=0)
    for name, kind, request in (('mi', NVME_MI_TYPE_MI, mi_request),
                                ('admin', NVME_MI_TYPE_ADMIN, admin_request)):
        for nonzero in (False, True):
            pair(f'mpr_{name}_{int(nonzero)}', kind, request,
                 bytes([1, 0xa5 if nonzero else 0, 10, 0]))
    pair('control_mpr', NVME_MI_TYPE_CONTROL, cp_request_payload(3),
         bytes([1, 0xa5, 10, 0]))
    for offset in (1, 16, 32, 36):
        for nonzero in (False, True):
            request = bytearray(admin_request)
            request[offset] = (0xf8 if offset == 1 else 0xa5) if nonzero else 0
            pair(f'admin_reserved{offset}_{int(nonzero)}', NVME_MI_TYPE_ADMIN,
                 bytes(request), admin_response_payload(0))
    for nonzero in (False, True):
        response = bytearray(admin_response_payload(0))
        response[1] = 0xa5 if nonzero else 0
        pair(f'admin_response_reserved_{int(nonzero)}', NVME_MI_TYPE_ADMIN,
             admin_request, bytes(response))
    pair('control_exact', NVME_MI_TYPE_CONTROL, cp_request_payload(3),
         cp_response_payload(0, cpsr=2))
    pair('control_long_request', NVME_MI_TYPE_CONTROL, cp_request_payload(3) + b'\xa5',
         cp_response_payload(0, cpsr=2))
    pair('control_long_response', NVME_MI_TYPE_CONTROL, cp_request_payload(3),
         cp_response_payload(0, cpsr=2) + b'\xa5')
    eid += 1
    add('control_short', make_packet(True, NVME_MI_TYPE_CONTROL, 0, bytes([3, 0, 0]),
                                    bmc_eid=eid))
    for name, body, captured in (('control_sliced', cp_request_payload(3), 26),
                                  ('control_excess_sliced', cp_request_payload(3) + b'\xa5', 28)):
        eid += 1
        packet = make_packet(True, NVME_MI_TYPE_CONTROL, 0, body, bmc_eid=eid)
        add(name, packet[:captured], len(packet))

    def fragments(name, kind, body, tu, response=False):
        nonlocal eid
        eid += 1
        packet = make_packet(not response, kind, 0, body, bmc_eid=eid)
        message = packet[20:]
        for index, off in enumerate(range(0, len(message), tu)):
            fst = ((0x80 if off == 0 else 0) |
                   (0x40 if off + tu >= len(message) else 0) |
                   ((index % 4) << 4) | (0 if response else 8))
            add(f'{name}_{index + 1}', packet[:19] + bytes([fst]) + message[off:off + tu])
        return len(message)

    fragments('control_fragmented', NVME_MI_TYPE_CONTROL, cp_request_payload(3), 6)
    add('control_fragmented_response', make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                                                  cp_response_payload(0, cpsr=2), bmc_eid=eid))
    for size in (4224, 4225):
        eid += 1
        add(f'size{size}', make_packet(True, NVME_MI_TYPE_PCIE, 0, bytes(size - 8),
                                       bmc_eid=eid))
    for size in (4224, 4225):
        assert fragments(f'fragmented_size{size}', NVME_MI_TYPE_PCIE,
                         bytes(size - 8), 64) == size
    assert fragments('tiny', NVME_MI_TYPE_PCIE, bytes(62), 1) == 70

    # Temporal vectors: one endpoint per sequence; slots/tags explicitly shared.
    def temporal(name, request, kind, body, csi=0, tag=0, bad_mic=False):
        packet = make_packet(request, kind, csi, body, bmc_eid=eid, tag=tag)
        if bad_mic:
            packet = packet[:-1] + bytes([packet[-1] ^ 1])
        add(name, packet)

    mpr = bytes([1, 0, 10, 0])
    final = bytes(12)  # four-byte response prefix plus the eight-byte NSHDS
    eid += 1
    for name, request, body in (('duplicate_request', True, mi_request),
                                ('duplicate_first', False, mpr),
                                ('duplicate_second', False, mpr),
                                ('duplicate_final', False, final)):
        temporal(name, request, NVME_MI_TYPE_MI, body)
    eid += 1
    for name, request, body, csi, tag in (
            ('slots_request0', True, mi_request, 0, 0),
            ('slots_request1', True, mi_request, 1, 1),
            ('slots_mpr0', False, mpr, 0, 0),
            ('slots_mpr1', False, mpr, 1, 1),
            ('slots_duplicate0', False, mpr, 0, 0),
            ('slots_final0', False, final, 0, 0),
            ('slots_final1', False, final, 1, 1)):
        temporal(name, request, NVME_MI_TYPE_MI, body, csi, tag)
    for replayed in (True, False):
        eid += 1
        name = 'replay' if replayed else 'no_replay'
        temporal(name + '_request', True, NVME_MI_TYPE_MI, mi_request)
        temporal(name + '_first', False, NVME_MI_TYPE_MI, mpr)
        temporal(name + '_cp_request', True, NVME_MI_TYPE_CONTROL, cp_request_payload(4), tag=2)
        temporal(name + '_cp_response', False, NVME_MI_TYPE_CONTROL,
                 cp_response_payload(0, cpsr=int(replayed)), tag=2)
        temporal(name + '_second', False, NVME_MI_TYPE_MI, mpr, tag=2 if replayed else 0)
        temporal(name + '_final', False, NVME_MI_TYPE_MI, final)
    eid += 1
    temporal('bad_mpr_request', True, NVME_MI_TYPE_MI, mi_request)
    temporal('bad_mpr_bad', False, NVME_MI_TYPE_MI, mpr, bad_mic=True)
    temporal('bad_mpr_first', False, NVME_MI_TYPE_MI, mpr)
    temporal('bad_mpr_second', False, NVME_MI_TYPE_MI, mpr)
    temporal('bad_mpr_final', False, NVME_MI_TYPE_MI, final)

    both = bytearray(admin_request)
    both[32] = both[36] = 0xa5
    pair('admin_reserved_both', NVME_MI_TYPE_ADMIN, bytes(both), admin_response_payload(0))
    eid += 1
    sliced = make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                          cp_request_payload(3) + b'\xa5', bmc_eid=eid)
    add('control_fixed_and_excess_sliced', sliced[:26], len(sliced))

    # MI 2.1 Figs 29–32: defined errors are four-byte bodies too. Preserve
    # reported length while slicing either the excess alone or the fixed body.
    for name, status in (('generic', 2), ('invalid_parameter', 4)):
        for suffix, captured in (('full', None), ('excess_sliced', 28),
                                  ('fixed_sliced', 26)):
            pair(f'control_{name}_long_{suffix}', NVME_MI_TYPE_CONTROL,
                 cp_request_payload(3), bytes([status, 0, 0, 0, 0xa5]))
            if captured is not None:
                label, packet, _ = records[-1]
                records[-1] = (label, packet[:captured], len(packet))

    # §4.1.2.3's prohibition is decidable from STATUS alone. Its absence is
    # deliberately distinct from either a short message or a sliced suffix.
    for name, body, captured in (
            ('control_mpr_short', b'\x01', None),
            ('control_mpr_sliced_after_status', bytes([1, 0xa5, 10, 0]), 25),
            ('control_mpr_status_sliced', bytes([1, 0xa5, 10, 0]), 24),
            ('control_error_status_sliced', bytes([2, 0, 0, 0, 0xa5]), 24)):
        pair(name, NVME_MI_TYPE_CONTROL, cp_request_payload(3), body)
        if captured is not None:
            label, packet, _ = records[-1]
            records[-1] = (label, packet[:captured], len(packet))

    # Both sides of Figure 29's status-range boundaries, including the
    # Reserved/Vendor layouts that must not inherit a four-byte maximum.
    for status in (3, 5, 8, 0x20, 0x2a, 9, 0x1f, 0x2b, 0xdf, 0xe0, 0xff):
        pair(f'control_status{status:02x}_long', NVME_MI_TYPE_CONTROL,
             cp_request_payload(3), bytes([status, 0, 0, 0, 0xa5]))

    fragments('control_capture_poisoned', NVME_MI_TYPE_CONTROL,
              cp_request_payload(3), 6)
    label, packet, _ = records[-2]
    records[-2] = (label, packet[:-1], len(packet))
    # Reuse the poisoned assembly's endpoint/tag, but not its dispatch context.
    add('control_after_poison_request', make_packet(
        True, NVME_MI_TYPE_CONTROL, 0, cp_request_payload(3), bmc_eid=eid))
    add('control_after_poison_response', make_packet(
        False, NVME_MI_TYPE_CONTROL, 0, cp_response_payload(0, cpsr=2), bmc_eid=eid))

    # Figure 29: a Vendor Specific status defines its own body, of any
    # length; matched, unmatched and capture-short.
    vendor = bytes([0xe0, 1, 2, 3, 4, 5])
    for length in (1, 2, 3, 4, 6):
        pair(f'control_vendor_e0_len{length}', NVME_MI_TYPE_CONTROL,
             cp_request_payload(3), vendor[:length])
    pair('control_vendor_ff_len2', NVME_MI_TYPE_CONTROL,
         cp_request_payload(3), bytes([0xff, 1]))
    for length in (1, 4):
        eid += 1
        add(f'control_vendor_e0_len{length}_unmatched', make_packet(
            False, NVME_MI_TYPE_CONTROL, 0, vendor[:length], bmc_eid=eid))
    pair('control_vendor_e0_sliced', NVME_MI_TYPE_CONTROL,
         cp_request_payload(3), vendor)
    label, packet, _ = records[-1]
    records[-1] = (label, packet[:27], len(packet))
    return records


def build_message_framing_pcapng(output_path):
    records = message_framing_packets()
    write_pcapng(output_path, [(packet, origlen) for _, packet, origlen in records],
                 1720000000000000, idb(name='mctp-m5-framing'))


def build_inband_pcapng(output_path):
    """Raw messages for the no-MCTP dispatch exemption oracle.

    A test Lua shim calls the named dissector without a MCTP transport.
    """
    packets = [nvme_mi_message(NVME_MI_TYPE_MI, 0, is_response=False,
                               payload=bytes([0xc0]) + bytes(size - 5), ic=False)
               for size in (4224, 4225)]
    packets += [nvme_mi_message(
        NVME_MI_TYPE_CONTROL, 0, is_response=response,
        payload=cp_response_payload(0, cpsr=2) if response else cp_request_payload(3),
        ic=False) for response in (False, True)]
    write_pcapng(output_path, packets, 1720001000000000,
                 idb(link_type=147, name='raw-mi-inband-exemption'))


def mi_contract_packets():
    """MI 2.1 Figs 61/62, 67, 82/83, 92/93, 105/108,
    110/111, 118–121, 126/132; Base 2.3 Figs 142/327.

    One variable per negative/control pair. The AE malformed and command
    surplus fixtures cover short counts, fixed recommendations and visible tails.
    The returned names are the authoritative frame map.
    """
    packets, frames = [], {}
    eid = 0x40

    def add(name, packet):
        frames[name] = len(packets) + 1
        packets.append(packet)

    def pair(name, opcode, request_data=b'', response_data=b'', cdw0=0,
             cdw1=0, nmresp=0, meb=False):
        nonlocal eid
        eid += 1
        add(name + '_req', make_packet(True, NVME_MI_TYPE_MI, 0,
            mi_request_payload(opcode, cdw0=cdw0, cdw1=cdw1) + request_data,
            bmc_eid=eid, meb=meb))
        add(name, make_packet(False, NVME_MI_TYPE_MI, 0,
            mi_response_payload_with_data(STATUS_SUCCESS, response_data,
                                          nmresp=nmresp), bmc_eid=eid))

    def ae(entries, total=None, header=5, tail=b''):
        body = b''.join(entries)
        size = header + len(body) + len(tail)
        return (bytes([len(entries), 0]) +
                struct.pack('<H', size if total is None else total) +
                bytes([header]) + bytes(max(0, header - 5)) + body + tail)

    def command_list(name, data, dtyp=4, iocsi=0):
        pair(name, 0, response_data=data, cdw0=dtyp << 24, cdw1=iocsi,
             nmresp=len(data))

    for name, opcode, declared, delivered in (
            ('vpd', 6, 64, 32), ('ses', 9, 2, 1), ('meb', 11, 2, 1)):
        pair(name + '_short', opcode, request_data=bytes(delivered), cdw1=declared)
        pair(name + '_exact', opcode, request_data=bytes(declared), cdw1=declared)
    pair('zero_dlen', 6)
    pair('read_dlen', 5, cdw1=1, response_data=b'\xa5')

    entry = b'\x03\x06\x80'
    pair('enable_total_over', 3, cdw0=4,
         request_data=ae([entry], total=12), response_data=aeo_list([]))
    pair('enable_total_exact', 3, cdw0=4,
         request_data=ae([entry]), response_data=aeo_list([]))
    pair('enable_entry_over', 3, cdw0=4,
         request_data=ae([b'\x04\x06\x80']), response_data=aeo_list([]))
    pair('supported_entry_over', 4, cdw0=4,
         response_data=ae([b'\x04\x06\x80']))
    pair('supported_entry_exact', 4, cdw0=4, response_data=ae([entry]))
    pair('enable_tail', 3, cdw0=4, request_data=ae([entry], total=8, tail=b'\xa5'),
         response_data=aeo_list([]))
    pair('supported_tail', 4, cdw0=4, response_data=ae([entry], total=8, tail=b'\xa5'))
    pair('enable_header_over', 3, cdw0=4,
         request_data=b'\0\0\x05\0\x07', response_data=aeo_list([]))
    pair('enable_ack', 3, cdw0=4, request_data=ae([]), response_data=aeo_list([]))

    # Adjacent list sizes; NUMCMD is a 16-bit count with no stated maximum in
    # NVMe-MI 2.2, so both decode in full and neither is a negative case.
    for count in (2048, 2047):
        command_list('commands_' + str(count),
                     struct.pack('<H', count) + b'\x08\x01' * count)
    command_list('command_short', b'\x01\0\x08')
    command_list('command_exact', b'\x01\0\x08\x01')
    command_list('command_empty', b'\0\0', dtyp=5)
    command_list('command_reserved', b'\x01\0\x8f\x01')
    command_list('command_class', b'\x01\0\x28\x01')
    command_list('command_pcie', b'\x01\0\x20\x01')
    for iocsi in (1, 0, 2):
        command_list('iocsi_' + str(iocsi), b'\x01\0\x10\x86', iocsi=iocsi)
    command_list('iocsi_meb', b'\x01\0\x10\x86', dtyp=5, iocsi=1)
    command_list('iocsi_common', b'\x02\0\x10\x06\x08\x06', iocsi=1)
    command_list('iocsi_cp', b'\x01\0\x10\x85', iocsi=4)

    for name, opcode, cdw0, nmresp, body in (
            ('hsp', 1, 0, 0, bytes(8)),
            ('set', 3, 4, 0, aeo_list([])),
            ('get', 4, 4, 0, ae([entry])),
            ('rds', 0, 4 << 24, 2, b'\0\0')):
        pair(name + '_missing', opcode, cdw0=cdw0, nmresp=nmresp)
        pair(name + '_present', opcode, cdw0=cdw0, nmresp=nmresp, response_data=body)
    pair('rds_zero', 0, cdw0=4 << 24)

    # Duplicate semantics: vary each tuple component independently; high
    # reserved bits alone cannot distinguish occurrences. Adjacent and
    # non-adjacent repetitions each get one expert on the later AEOUI.
    # Shutdown Status (02h) is the AE Figure 63 scopes as "Controller or NVM
    # Subsystem", so the Controller variants and the scope variant are all
    # conformant (the NVM Subsystem dword is Reserved, hence 0); Namespace
    # Attribute Changed (04h) is Controller scoped with no Figure 65 info.
    # The AEOSIL=0 length warning on 02h is kept deliberately: it is the
    # corpus's only exercise of that check.
    occurrence = aeo_entry(2, 1, scope_id=1)
    other = aeo_entry(2, 1, scope_id=2)
    reserved = occurrence[:8] + b'\x81'
    distinct = [occurrence, other, aeo_entry(4, 1, scope_id=1),
                aeo_entry(2, 2)]
    for name, entries in (
            ('duplicate', [occurrence, other, occurrence, occurrence]),
            ('distinct', distinct),
            ('reserved_duplicate', [occurrence, reserved]),
            ('reserved_distinct', [other, reserved]),
            ('reserved_scope', [aeo_entry(2, 6, scope_id=1)])):
        add(name + '_aem', aem_packet(aeo_list(entries)))
        pair(name + '_set', 3, cdw0=4, response_data=aeo_list(entries))
    add('occurrence_tail', aem_packet(aeo_list([]) + b'\xa5'))
    add('occurrence_empty', aem_packet(aeo_list([])))
    add('overflow_tail', aem_packet(aeo_list([], overflow=True) + b'\xa5'))
    add('overflow_empty', aem_packet(aeo_list([], overflow=True)))
    # Supported/Enable IDs have no Figure 62 uniqueness rule.
    pair('repeated_enable', 3, cdw0=4, request_data=ae([entry, entry]),
         response_data=aeo_list([]))
    pair('repeated_supported', 4, cdw0=4, response_data=ae([entry, entry]))

    # §4.2.3: without capability discovery, MEB=1 may select buffer data.
    # Keep DLEN/RDL nonzero: missing inline data must not be "fixed" by
    # clearing the declared transfer length.
    pair('unknown_meb_vpd', 6, cdw1=8, meb=True)
    pair('unknown_meb_ses', 9, cdw1=8, meb=True)
    pair('unknown_meb_get', 4, cdw0=4, meb=True)
    pair('unknown_meb_rds', 0, cdw0=4 << 24, nmresp=2, meb=True)
    # §5.2.4 exempts only Request Data: validate the inline AE Enable List
    # even with unknown capabilities, but do not demand an inline response.
    pair('enable_meb_total_over', 3, cdw0=4, meb=True,
         request_data=ae([entry], total=12))
    return packets, frames


def build_mi_contract_pcapng(output_path):
    packets, _ = mi_contract_packets()
    write_pcapng(output_path, packets, 1720002000000000, idb(name='mctp-sll-m5-mi'))


def build_m8_pcapng(output_path):
    """Representative presentation boundaries; no exhaustive enum sweep."""
    sanitize = bytearray(512)
    sanitize[0:2] = b'\xff\xff'   # SPROG: FFFFh when SOS is not Sanitizing (Fig 302)
    request = admin_request_payload(0x02, flags=0, dlen=512,
                                    cns=0x81 | (127 << 16))
    req_message = nvme_mi_message(NVME_MI_TYPE_ADMIN, 0, False, request)
    resp_message = nvme_mi_message(NVME_MI_TYPE_ADMIN, 0, True,
                                   admin_resp_with_data(sanitize))
    # MI 2.1 §1.8.41: request completes at F2, response begins at F3.
    packets = [
        _sll_mctp_fragment(req_message[:64], 0, 0, True, False),
        _sll_mctp_fragment(req_message[64:], 0, 1, False, True),
        _sll_mctp_fragment(resp_message[:64], 0, 0, True, False, False),
        _sll_mctp_fragment(resp_message[64:], 0, 1, False, True, False),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0, request, tag=1),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(sanitize), tag=1),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x81, flags=0, dlen=4,
                        cns=security_cdw10(1, 1), cdw11=4) + b'\x01\x02\x03\x04',
                    tag=2),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_resp_with_data(b''), tag=2),
        make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                    admin_request_payload(0x06, flags=0, cns=1), tag=3),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                    admin_response_payload(0,
                        cqe3=admin_cqe3(cqe_status_word(sct=1, sc=0x70))),
                    tag=3),
        sll_header(HOST_EID, True) + mctp_header(True, tag=4) + b'\x00\x80\x15',
        sll_header(7) + bytes([1, 0, 7, 0xc0, 0x0a, 0x55]),
        sll_header(8) + bytes([1, 255, 8, 0xc0, 0x0a, 0x55]),
        make_packet(True, NVME_MI_TYPE_MI, 0,
                    mi_request_payload(0, cdw0=6 << 24), tag=5),
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload(0x09), tag=5),
    ]
    write_pcapng(output_path, packets, 1720003000000000, idb(name='mctp-sll-m8'))


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F792- (mi9_command_set_vectors)
# ---------------------------------------------------------------------------
#
# MI Command Set completeness (MI 2.1 Figs 61-62, 76-133, 148, 194):
#   - SES Receive/Send (Figs 123-126) and MEB Read/Write (Figs 101-105) name
#     their NMD0/NMD1 fields, reconcile Response Data against RDL/DLEN, and
#     show surplus after the no-data responses of VPD Write, SES Send and
#     MEB Write.
#   - Nonzero reserved NMD0/NMD1/NMRESP bits are shown, unshifted, with no
#     expert (Configuration Get/Set SMBus/I2C Frequency, SES Send, CHSP).
#   - AE Occurrence List overflow with AEOLTL/NUMAEO set (Figure 61).
#   - VPD vendor specific Element Descriptor (Figure 194): PCIVID.
#   - Optionally Supported Command List entries with a PCIe CTYP (Fig 148).
#   - Controller Information shorter than 32 bytes decodes what is present.
#   - CHDS Composite Temperature in Kelvins, PDLU and SPARE in percent.
# Each case is a request/response pair on its own Management Endpoint EID.

def mi9_command_set_vectors():
    packets, frames = [], {}
    endpoint = 0x70

    def add(name, packet):
        frames[name] = len(packets) + 1
        packets.append(packet)

    def pair(name, request, response=None):
        nonlocal endpoint
        endpoint += 1
        add(name + '_req', make_packet(True, NVME_MI_TYPE_MI, 0, request,
                                       bmc_eid=endpoint))
        if response is not None:
            add(name, make_packet(False, NVME_MI_TYPE_MI, 0, response,
                                  bmc_eid=endpoint))

    ok = lambda data=b'', nmresp=0: mi_response_payload_with_data(
        STATUS_SUCCESS, data, nmresp=nmresp)
    page = bytes([0x02, 0x00, 0x00, 0x04, 0xa1, 0xa2, 0xa3, 0xa4])

    # MEB Read (0Ah): DOFST is all of NMD0, DLEN NMD1 15:00.
    pair('meb_read', mi_request_payload(0x0A, cdw0=0x100, cdw1=8),
         ok(bytes(range(8))))
    pair('meb_read_short', mi_request_payload(0x0A, cdw0=0, cdw1=8),
         ok(bytes(4)))
    # MEB Write (0Bh): no Response Data; NMD1 31:16 reserved.
    pair('meb_write', mi_request_payload(0x0B, cdw0=4, cdw1=0x00010004)
         + b'\xde\xad\xbe\xef', ok())
    pair('meb_write_surplus', mi_request_payload(0x0B, cdw0=0, cdw1=2)
         + b'\x01\x02', ok(b'\xa5\x5a'))
    # SES Receive (08h): PCODE NMD0 7:0, ALENGTH NMD1 15:0, RDL NMRESP 15:0.
    pair('ses_recv', mi_request_payload(0x08, cdw0=0x02, cdw1=16),
         ok(page, nmresp=len(page)))
    pair('ses_recv_surplus', mi_request_payload(0x08, cdw0=0x02, cdw1=16),
         ok(page + b'\xee' * 4, nmresp=len(page)))
    pair('ses_recv_over_alength', mi_request_payload(0x08, cdw0=0x02, cdw1=4),
         ok(page, nmresp=len(page)))
    # SES Send (09h): NMD0 reserved, DLEN NMD1 15:0, no Response Data.
    pair('ses_send', mi_request_payload(0x09, cdw0=0xFFFFFFFF, cdw1=4)
         + page[:4], ok(b'\xa5\x5a'))
    # VPD Write (06h): no Response Data.
    pair('vpd_write_surplus', mi_request_payload(0x06, cdw0=0, cdw1=2)
         + b'\x01\x02', ok(b'\xa5'))
    # Configuration Get SMBus/I2C Frequency: NMRESP 23:4 reserved.
    pair('cfg_get_sfreq', mi_request_payload(0x04, cdw0=0x01), ok(nmresp=0xFFFFF2))
    # Configuration Set SMBus/I2C Frequency: NMD0 23:12, NMD1 reserved.
    pair('cfg_set_sfreq', mi_request_payload(0x03, cdw0=0x00FFF001,
                                             cdw1=0xFFFFFFFF), ok())
    # An overflowed AE Occurrence List with AEOLTL and NUMAEO set.
    add('aem_overflow_set', aem_packet(aeo_list([], overflow=True,
                                                numaeo=2, total_len=7)))
    # Figure 194: vendor specific Element Descriptor F0h, PCIVID 8086h.
    for name, element in (
            ('vpd_vendor', bytes([0xF0, 0x03, 7]) + b'\x86\x80\x11\x22'),
            ('vpd_vendor_short', bytes([0xF1, 0x00, 4]) + b'\x86')):
        image = vpd(topology(element))
        pair(name, mi_request_payload(0x05, cdw0=0, cdw1=len(image)), ok(image))
    # Figure 148: PCIe opcodes 00h (Configuration Read) and 06h (Reserved).
    oscl = mi_struct_cmd_list([(NVME_MI_TYPE_PCIE, 0x00),
                               (NVME_MI_TYPE_PCIE, 0x06)])
    pair('oscl_pcie', mi_request_payload(0x00, cdw0=mi_struct_nmd0(4)),
         ok(oscl, nmresp=len(oscl)))
    # Figure 117 Controller Information cut at 6, 8 and 16 bytes.
    info = mi_struct_ctrl_info(0x0102)
    for cut in (6, 8, 16):
        pair(f'ctrl_info_{cut}', mi_request_payload(
            0x00, cdw0=mi_struct_nmd0(3, ctrlid=1)), ok(info[:cut], nmresp=cut))
    # Figure 97: CTEMP 300 K, PDLU 5 %, SPARE 90 %; NMD0 bit 27 reserved.
    chds = (struct.pack('<HHH', 1, 0x0001, 300) + bytes([5, 90])
            + bytes(8))
    pair('chsp', mi_request_payload(0x02, cdw0=0x08010000, cdw1=0x80000000),
         ok(chds, nmresp=1 << 16))
    return packets, frames


def build_mi9_command_set_pcapng(output_path):
    write_vectors_pcapng(output_path, 'mi9-command-set', 1731000000000000,
                         mi9_command_set_vectors())


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F829- (mi_response_format_vectors)
# ---------------------------------------------------------------------------

def mi_response_format_vectors():
    """Non-Success MI responses (NVMe-MI 2.2 Figures 29-34): the four-byte
    status-specific body is not NMRESP, and bytes after a defined format are
    surplus.  Each case owns an EID; '<name>_req' is the request and '<name>'
    its response.

      F1-2    Config Get AE, Invalid Parameter, PEL byte 4 bit 1
      F3-4    Generic Error (02h), 4 bytes
      F5-6    Generic Error, 4 surplus bytes                  flagged
      F7-8    F1-2 with 4 surplus bytes                       flagged
      F9-11   More Processing Required, 4 bytes, then Success
      F12-14  More Processing Required, 4 surplus bytes,      flagged
              then Success
      F15-20  Reserved 09h, 2Bh and Vendor Specific E0h with 4 trailing
              bytes: raw Data, not surplus
    """
    packets, frames = [], {}
    endpoint = 0x90

    def add(name, packet):
        frames[name] = len(packets) + 1
        packets.append(packet)

    def pair(name, request, response):
        nonlocal endpoint
        endpoint += 1
        add(name + '_req', make_packet(True, NVME_MI_TYPE_MI, 0, request,
                                       bmc_eid=endpoint))
        add(name, make_packet(False, NVME_MI_TYPE_MI, 0, response,
                              bmc_eid=endpoint))

    cfg_get_ae = mi_request_payload(0x04, cdw0=NVME_MI_CFGID_AE_GET_CDW0)
    # Invalid Parameter, PEL byte 4 bit 1: byte 1 is not Figure 81's AEELVER.
    pair('cfg_get_ae_pel', cfg_get_ae, mi_response_payload(0x04, nmresp=0x000401))
    # Defined formats (Figures 30-34) at exactly 4 bytes, then with 4 more.
    sfreq = mi_request_payload(0x04, cdw0=0x01)
    surplus = b'\xa5' * 4
    pair('generic', sfreq, mi_response_payload(0x02))
    pair('generic_surplus', sfreq, mi_response_payload(0x02) + surplus)
    pair('cfg_get_ae_pel_surplus', cfg_get_ae,
         mi_response_payload(0x04, nmresp=0x000401) + surplus)
    mpr = bytes([0x01, 0x00]) + struct.pack('<H', 10)
    for name, body in (('mpr', mpr), ('mpr_surplus', mpr + surplus)):
        pair(name, sfreq, body)
        add(name + '_final', make_packet(False, NVME_MI_TYPE_MI, 0,
                                         mi_response_payload(STATUS_SUCCESS,
                                                             nmresp=0x01),
                                         bmc_eid=endpoint))
    # Reserved and Vendor Specific Statuses define no format: raw Data.
    for status in (0x09, 0x2B, 0xE0):
        pair(f'status_{status:02x}', sfreq,
             mi_response_payload(status) + surplus)
    return packets, frames


def build_mi_response_format_pcapng(output_path):
    write_vectors_pcapng(output_path, 'mi-response-format', 1731500000000000,
                         mi_response_format_vectors())


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F849- - AE Enable List extent (NVMe-MI 2.2 5.2.4)
# ---------------------------------------------------------------------------
#
# Figure 91 states AEETL only as a "should", and 5.2.4 has the ME ignore data
# past a non-minimal list; an entry the data cannot hold is still malformed.
# Every list enables AE 06h only, so an accepted Set answers with its AE Sync
# occurrence; a list short of its declared entries is rejected with Figure 29
# status 06h.
#
#   F1/F2   AEETL 8 matches, 2 trailing bytes      -> silent, raw Data
#   F3/F4   AEETL 10 inside the data, not 8        -> AEETL mismatch Note
#   F5/F6   AEEL 4 with 3 bytes left (AEETL 9)     -> ae_list_invalid Error
#
# A Set with no Request Data has no NUMAEE, so is neither an AE Sync nor an
# AEM Ack (MEB does not excuse it, 5.2.4); a list of 1-4 bytes is already
# truncated.
#
#   F7/F8   no AE Enable List, MEB=0               -> truncated, status 06h
#   F9/F10  no AE Enable List, MEB=1               -> truncated, status 06h
#   F11/F12 AEM Ack, 5-byte list                    -> control: silent
#   F13/F14 3-byte list                             -> one truncated, 06h
#   F15/F16 Config Get AE, 12 bytes                 -> control: silent

BASE_TS_AE_ENABLE_LIST_EXTRA_US = 1730100000 * 1_000_000

def build_ae_enable_list_extra_pcapng(output_path):
    sync = mi_response_payload_with_data(STATUS_SUCCESS, _ae_sync_occurrences)
    rejected = mi_response_payload(0x06)
    set_ae = mi_request_payload(0x03, cdw0=NVME_MI_CFGID_AE_SET_CDW0)
    packets = []
    for ae_list, response in (
            (bytes.fromhex('0100080005030680aabb'), sync),
            (bytes.fromhex('01000a0005030680aabb'), sync),
            (bytes.fromhex('0100090005040680'), rejected)):
        packets += [make_packet(True, NVME_MI_TYPE_MI, 0, set_ae + ae_list),
                    make_packet(False, NVME_MI_TYPE_MI, 0, response)]
    for meb in (False, True):
        packets += [make_packet(True, NVME_MI_TYPE_MI, 0, set_ae, meb=meb),
                    make_packet(False, NVME_MI_TYPE_MI, 0, rejected)]
    packets += [make_packet(True, NVME_MI_TYPE_MI, 0,
                            mi_request_payload(0x03, cdw0=0x00000004)
                            + bytes.fromhex('0000050005')),
                make_packet(False, NVME_MI_TYPE_MI, 0,
                            mi_response_payload_with_data(STATUS_SUCCESS,
                                                          aeo_list([]))),
                make_packet(True, NVME_MI_TYPE_MI, 0,
                            set_ae + bytes.fromhex('000005')),
                make_packet(False, NVME_MI_TYPE_MI, 0, rejected)]
    packets += _ae_get_pair(_aes_well_formed)
    write_pcapng(output_path, packets, BASE_TS_AE_ENABLE_LIST_EXTRA_US)


def write_vectors_pcapng(output_path, if_name, base_us, vectors):
    """Write the (packets, frames) a *_vectors() builder returns, one frame per
    packet at base_us + frame ms, and print the frame map.  A packet may be a
    (bytes, origlen) pair for a sliced frame."""
    packets, frames = vectors
    write_pcapng(output_path, packets, base_us + 1000, idb(name=if_name), 1000)
    for name, frame in frames.items():
        print(f'{frame:3} {name}')


# ---------------------------------------------------------------------------
# nvme-mi-types.pcapng F604-F653 (reserved_vectors)
# ---------------------------------------------------------------------------

# Reserved fields of the MI Command Set: NVMe-MI 2.1 Figs 67, 76-97, 108-117.
#
# Each case is a request/response pair on its own Management Endpoint EID, so no
# case can share a Command Slot with another.  Prints the authoritative frame map

OPC_READ_DS, OPC_NSHSP, OPC_CHSP, OPC_CFG_SET, OPC_CFG_GET = 0, 1, 2, 3, 4
CID_SMBUS, CID_HSC, CID_MTUS, CID_AE = 1, 2, 3, 4


def mi_request(opcode, cdw0=0, cdw1=0, rsvd=b'\0\0\0', data=b''):
    """Figure 67: OPC, Reserved bytes 07:05, NMD0, NMD1, Request Data."""
    return bytes([opcode]) + rsvd + struct.pack('<II', cdw0, cdw1) + data


def ae_list(entries):
    """Figures 82/91: 5-byte header, then 3-byte (length, info word) entries."""
    body = b''.join(bytes([3]) + struct.pack('<H', info) for info in entries)
    return bytes([len(entries), 0]) + struct.pack('<H', 5 + len(body)) + \
        bytes([5]) + body


def pcie_port(prtcap=0x03, slsv=0x0f):
    data = bytearray(port_info_pcie())
    data[1], data[9] = prtcap, slsv
    return bytes(data)


def twire_port(twprt=0x82, nvmebm=0x00):
    data = bytearray(port_info_twire())
    data[11], data[12] = twprt, nvmebm
    return bytes(data)


def ctrl_info(prii=0x01):
    data = bytearray(32)
    data[5] = prii
    struct.pack_into('<HHHHH', data, 6, 0x0100, 0x144d, 0xa808, 0x144d, 0xa801)
    return bytes(data)


def reserved_vectors():
    packets, frames = [], {}
    endpoint = 0x40

    def add(name, packet):
        frames[name] = len(packets) + 1
        packets.append(packet)

    def pair(name, request, response, data=None):
        nonlocal endpoint
        endpoint += 1
        if data is not None:
            response = mi_response_payload_with_data(0, data,
                                                           nmresp=response)
        elif isinstance(response, int):
            response = mi_response_payload(0, nmresp=response)
        add(name + '_req', make_packet(True, 1, 0, request,
                                             bmc_eid=endpoint))
        add(name, make_packet(False, 1, 0, response, bmc_eid=endpoint))

    def read_ds(name, dtyp, data):
        pair(name, mi_request(OPC_READ_DS, cdw0=dtyp << 24), len(data), data)

    # Figure 67: request bytes 07:05.
    pair('req_rsvd_clean', mi_request(OPC_NSHSP), 0, nshds())
    pair('req_rsvd_set', mi_request(OPC_NSHSP, rsvd=b'\0\x5a\0'), 0,
         nshds())

    # NMRESP Reserved only where the section says so.
    pair('nshsp_nmresp_set', mi_request(OPC_NSHSP), 0x000100, nshds())
    pair('cfgget_hsc_nmresp_set', mi_request(OPC_CFG_GET, cdw0=CID_HSC),
         0x000001)
    # 5.2.2 is silent on NMRESP: it stays command specific, no diagnostic.
    pair('cfgset_hsc_nmresp', mi_request(OPC_CFG_SET, cdw0=CID_HSC), 0x000001)

    # Reserved bit runs inside Response Data structures.
    read_ds('nnsc_rsvd', 0, subsys_info(nnsc=0x81))
    read_ds('pcie_clean', 1, pcie_port())
    read_ds('prtcap_rsvd', 1, pcie_port(prtcap=0x07))
    read_ds('slsv_rsvd', 1, pcie_port(slsv=0x4f))
    read_ds('twprt_rsvd', 1, twire_port(twprt=0x86))
    read_ds('nvmebm_rsvd', 1, twire_port(nvmebm=0x02))
    read_ds('prii_rsvd', 3, ctrl_info(prii=0x03))
    flagged = bytearray(nshds())
    flagged[7] = 0x01
    pair('nshds_rsvd', mi_request(OPC_NSHSP), 0, bytes(flagged))
    clean = chds(1, 0x0021, 300, 5, 100, 0, 0)
    csts = chds(1, 0x0221, 300, 5, 100, 0, 0)
    tail = bytearray(clean)
    tail[12] = 0x01
    for name, entry in (('chds_clean', clean), ('chds_csts_rsvd', csts),
                        ('chds_tail_rsvd', bytes(tail))):
        pair(name, mi_request(OPC_CHSP, cdw0=(0x80000000 | (254 << 16)) | 0x01),
             1 << 16, entry)

    # Figures 83 and 92: AE info bits 14:08.
    pair('aes_rsvd', mi_request(OPC_CFG_GET, cdw0=CID_AE), 0,
         ae_list([0x8000, 0x0105]))
    pair('aee_rsvd', mi_request(OPC_CFG_SET, cdw0=CID_AE,
                                data=ae_list([0x8200])),
         0, aeo_list([]))

    # Configuration Identifier Specific runs, per CONFIGID and direction.
    pair('cfgset_smbus_clean',
         mi_request(OPC_CFG_SET, cdw0=(1 << 24) | (2 << 8) | CID_SMBUS), 0)
    pair('cfgset_smbus_rsvd',
         mi_request(OPC_CFG_SET, cdw0=(1 << 24) | 0x1000 | (2 << 8) | CID_SMBUS),
         0)
    pair('cfgget_ae_rsvd', mi_request(OPC_CFG_GET, cdw0=0x0100 | CID_AE), 0,
         ae_list([0x8000]))
    pair('cfgset_mtus_rsvd',
         mi_request(OPC_CFG_SET, cdw0=CID_MTUS, cdw1=0x00010040), 0)
    pair('cfgset_hsc_cdw1_rsvd',
         mi_request(OPC_CFG_SET, cdw0=CID_HSC, cdw1=0x00002001), 0)
    pair('cfgget_mtus_cdw1_rsvd',
         mi_request(OPC_CFG_GET, cdw0=CID_MTUS, cdw1=0x00000001), 64)
    pair('cfg_vendor', mi_request(OPC_CFG_GET, cdw0=0xffffff00 | 0xc0,
                                  cdw1=0xffffffff), 0)
    return packets, frames


# ---------------------------------------------------------------------------
# nvme-mi-spec-review.pcapng
# ---------------------------------------------------------------------------

# Admin completion Dword 0, Identify Namespace flag bytes and superseded
# Control Primitives, over NVMe-MI.
#
#   * Firmware Commit CQE Dword 0 (NVMe Base 2.3 Figure 186), on a success and
#     on an aborted completion.
#   * Set Features Power Measurement CQE Dword 0 (Figure 456).
#   * Identify Namespace flag bytes (NVM Command Set 1.2 Figure 114, Base 2.3
#     Figure 335) and the CNS 11h label.
#   * A late response to a Control Primitive that a second one on the same MCTP
#     tag superseded (NVMe-MI 2.1 section 4.2.1).
#
# Each case is on its own Management Endpoint EID, so no case can share a
# Command Slot with another.  Prints the authoritative frame map and SHA-256.

NMIMT_CONTROL, NMIMT_ADMIN = 0, 2
OPC_SET_FEATURES, OPC_IDENTIFY, OPC_FW_COMMIT = 0x09, 0x06, 0x10
CP_GET_STATE = 0x03
FID_POWER_MEASUREMENT = 0x25


def cqe_dw3(sct=0, sc=0):
    return cqe_status_word(sct=sct, sc=sc) << 16


def identify_ns():
    """128 bytes of Figure 114, with every flag byte set to a distinct
    pattern.  The NLBAF/NULBAF counts are 0 and the LBA Format region is not
    in the window, so only the fields under test decode."""
    data = bytearray(128)
    data[24] = 0x9f     # NSFEAT: OPTRPERF, OPTPERF 01b, UIDREUSE, DAE, NSABP, THINP
    data[26] = 0x53     # FLBAS: FIDXU 10b, MTELBA, FIDXL 3h
    data[27] = 0x03     # MC: MTSBS, MTELBAS
    data[28] = 0x1f     # DPC: PIILB, PIIFB, PIT3S, PIT2S, PIT1S
    data[29] = 0x09     # DPS: PIP, PIT 001b
    data[30] = 0x01     # NMIC: SHRNS
    data[31] = 0xff     # RESCAP: all eight
    data[32] = 0x99     # FPI: FPIS, RFNVM 25
    data[99] = 0x01     # NSATTR: CWP
    return bytes(data)


def admin_completion_vectors():
    packets, frames = [], {}
    endpoint = 0x50

    def add(name, packet):
        frames[name] = len(packets) + 1
        packets.append(packet)

    def next_endpoint():
        nonlocal endpoint
        endpoint += 1
        return endpoint

    def admin(name, request, response, data=b''):
        eid = next_endpoint()
        add(name + '_req', make_packet(True, NMIMT_ADMIN, 0, request,
                                             bmc_eid=eid))
        add(name, make_packet(False, NMIMT_ADMIN, 0, response + data,
                                    bmc_eid=eid))

    # Figure 186: MUD is "valid if the command is successful or aborted".
    admin('fwc_success',
          admin_request_payload(OPC_FW_COMMIT, dlen=0, flags=0),
          admin_response_payload(0, cqe1=0x00000002, cqe3=cqe_dw3()))
    admin('fwc_aborted',
          admin_request_payload(OPC_FW_COMMIT, dlen=0, flags=0),
          admin_response_payload(0, cqe1=0x00000001,
                                       cqe3=cqe_dw3(sct=1, sc=0x0b)))

    # Figure 456 defines Dword 0 for a Set Features of FID 25h as well.
    admin('set_pm',
          admin_request_payload(OPC_SET_FEATURES,
                                      cns=FID_POWER_MEASUREMENT,
                                      dlen=0, flags=0),
          admin_response_payload(0, cqe1=0x00123401, cqe3=cqe_dw3()))
    # Control: a Set Features FID other than Number of Queues and Power
    # Measurement (here Temperature Threshold, optional over NVMe-MI) still
    # renders Dword 0 raw.
    admin('set_temp_threshold',
          admin_request_payload(OPC_SET_FEATURES, cns=0x04,
                                      dlen=0, flags=0),
          admin_response_payload(0, cqe1=0x00123401, cqe3=cqe_dw3()))

    ns = identify_ns()
    admin('identify_ns',
          admin_request_payload(OPC_IDENTIFY, cns=0x00, dlen=len(ns),
                                      flags=0),
          admin_response_payload(0, cqe3=cqe_dw3()), ns)
    admin('identify_cns11',
          admin_request_payload(OPC_IDENTIFY, cns=0x11, dlen=len(ns),
                                      flags=0),
          admin_response_payload(0, cqe3=cqe_dw3()), ns)

    # Section 4.2.1: a second Control Primitive may be issued without waiting,
    # and the earlier one's response "may or may not be transmitted".  Both on
    # MCTP tag 2; the first one's response arrives after the second request.
    eid = next_endpoint()
    for name, is_request, payload in (
            ('cp_first_req', True, cp_request_payload(CP_GET_STATE, 0x11)),
            ('cp_second_req', True, cp_request_payload(CP_GET_STATE, 0x22)),
            ('cp_first_resp', False, cp_response_payload(0, 0x11)),
            ('cp_second_resp', False, cp_response_payload(0, 0x22))):
        add(name, make_packet(is_request, NMIMT_CONTROL, 0, payload,
                                    bmc_eid=eid, tag=2))

    # Control: a lone Control Primitive answered with the wrong Tag is still
    # a mismatch.
    eid = next_endpoint()
    add('cp_lone_req', make_packet(
        True, NMIMT_CONTROL, 0, cp_request_payload(CP_GET_STATE, 0x33),
        bmc_eid=eid, tag=2))
    add('cp_lone_resp', make_packet(
        False, NMIMT_CONTROL, 0, cp_response_payload(0, 0x44),
        bmc_eid=eid, tag=2))

    # A window that starts inside the structure (MI 2.2 Figure 139 allows any
    # dword-aligned DOFST): structure bytes 35:28, so DPC..FPI land at tvb
    # offsets 0..4 and only a correct offset translation decodes them.
    admin('identify_ns_window',
          admin_request_payload(OPC_IDENTIFY, cns=0x00, doff=28, dlen=8,
                                      flags=0),
          admin_response_payload(0, cqe3=cqe_dw3()), ns[28:36])

    # Once the newer primitive has been answered, the older one's late
    # answer still pairs by TAG.
    eid = next_endpoint()
    for name, is_request, payload in (
            ('cp_old_req', True, cp_request_payload(CP_GET_STATE, 0x55)),
            ('cp_new_req', True, cp_request_payload(CP_GET_STATE, 0x66)),
            ('cp_new_resp', False, cp_response_payload(0, 0x66)),
            ('cp_old_resp', False, cp_response_payload(0, 0x55))):
        add(name, make_packet(is_request, NMIMT_CONTROL, 0, payload,
                                    bmc_eid=eid, tag=2))
    return packets, frames


# ---------------------------------------------------------------------------
# nvme-mi-admin-identify.pcapng section 5 (mi12_admin_vectors)
# ---------------------------------------------------------------------------

OPC_NS_MGMT, OPC_NS_ATTACH, OPC_VIRT_MGMT, OPC_CAP_MGMT = 0x0d, 0x15, 0x1c, 0x20
OPC_SELF_TEST, OPC_EXP_SUBSYS_RECV, OPC_FORMAT_NVM = 0x14, 0x2a, 0x80
OPC_SANITIZE, OPC_GET_LBA_STATUS, OPC_SANITIZE_NS = 0x84, 0x86, 0x8c


def mi12_admin_vectors():
    """MI-allowed Admin commands (NVMe-MI 2.2 Figure 137): selector names,
    CQE Dword 0 per selector, and Command Specific Status Codes checked
    against the command (NVMe Base 2.4 Figure 104, NVM CS 1.3 Figure 19).
    Each vector is a request then its response."""
    packets, frames = [], {}
    endpoint = 0x60

    def admin(name, opcode, cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw15=0,
              dw0=0, sct=0, sc=0):
        nonlocal endpoint
        endpoint += 1
        sqe = bytearray(admin_request_payload(opcode, cns=cdw10, cdw11=cdw11,
                                              cdw12=cdw12, dlen=0, flags=0))
        struct.pack_into('<II', sqe, 52, cdw13, 0)
        struct.pack_into('<I', sqe, 60, cdw15)
        frames[name + '_req'] = len(packets) + 1
        packets.append(make_packet(True, NMIMT_ADMIN, 0, bytes(sqe),
                                   bmc_eid=endpoint))
        frames[name] = len(packets) + 1
        packets.append(make_packet(False, NMIMT_ADMIN, 0,
                                   admin_response_payload(0, cqe1=dw0,
                                                          cqe3=cqe_dw3(sct=sct, sc=sc)),
                                   bmc_eid=endpoint))

    # Namespace Management (Figures 446/447/450): CSI and the created NSID
    # belong to Create alone.
    admin('ns_create', OPC_NS_MGMT, cdw10=0, cdw11=0x02000000, dw0=5)
    admin('ns_delete', OPC_NS_MGMT, cdw10=1, cdw11=0x02000000, dw0=5)
    admin('ns_mgmt_rsvd', OPC_NS_MGMT, cdw10=3)
    # Namespace Attachment (Figure 443/444).
    admin('ns_detach', OPC_NS_ATTACH, cdw10=1, sct=1, sc=0x1a)
    admin('ns_attach_rsvd', OPC_NS_ATTACH, cdw10=2)
    # Virtualization Management (Figures 587/588/590): NRM for Assign only.
    admin('vm_assign', OPC_VIRT_MGMT, cdw10=(0x1234 << 16) | (1 << 8) | 8,
          cdw11=0x5678, dw0=0x10)
    admin('vm_online', OPC_VIRT_MGMT, cdw10=(0x1234 << 16) | 9, dw0=0x10)
    admin('vm_rsvd', OPC_VIRT_MGMT, cdw10=(5 << 8) | 2, sct=1, sc=0x21)
    # Capacity Management (Figures 162-166): CAPL/CAPU and CELID for the two
    # Create operations; a failed Create leaves Dword 0 raw.
    admin('cap_create_set', OPC_CAP_MGMT, cdw10=(7 << 16) | 3,
          cdw11=0x55667788, cdw12=0x11223344, dw0=9)
    admin('cap_delete_eg', OPC_CAP_MGMT, cdw10=(7 << 16) | 2,
          cdw11=0x55667788, dw0=9)
    admin('cap_rsvd', OPC_CAP_MGMT, cdw10=6, sct=1, sc=0x26)
    admin('cap_create_failed', OPC_CAP_MGMT, cdw10=1, dw0=9, sct=1, sc=0x2d)
    # Get LBA Status (NVM CS 1.3 Figures 136-138): MNDW is 0's based.
    admin('glbas', OPC_GET_LBA_STATUS, cdw10=0x55667788, cdw11=0x11223344,
          cdw12=0, cdw13=(0x02 << 24) | 0x10)
    admin('glbas_rsvd', OPC_GET_LBA_STATUS, cdw12=0xff, cdw13=0x03 << 24)
    # Device Self-test (Figures 177/178): DSTP is vendor specific for STC Eh.
    admin('dst_vs', OPC_SELF_TEST, cdw10=0xe, cdw15=0xdeadbeef)
    admin('dst_short', OPC_SELF_TEST, cdw10=1, cdw15=0x11, sct=1, sc=0x1d)
    # Manage Exported NVM Subsystem Receive (Figures 375/383): RA is the MOS
    # of Create Exported NVM Subsystem (SEL 00h) alone.
    admin('exp_create', OPC_EXP_SUBSYS_RECV, cdw10=0x100)
    admin('exp_list', OPC_EXP_SUBSYS_RECV, cdw10=0x101)
    admin('exp_vs', OPC_EXP_SUBSYS_RECV, cdw10=0xc5)
    # Command Specific Status Codes under their command and under another.
    admin('glp_09', OPC_GET_LOG_PAGE, sct=1, sc=0x09)
    admin('identify_09', OPC_IDENTIFY, sct=1, sc=0x09)
    admin('format_82', OPC_FORMAT_NVM, sct=1, sc=0x82)
    admin('sanitize_82', OPC_SANITIZE, sct=1, sc=0x82)
    admin('sanns_3c', OPC_SANITIZE_NS, sct=1, sc=0x3c)
    admin('sanitize_3c', OPC_SANITIZE, sct=1, sc=0x3c)
    # Directive Specific, Reserved and a vendor specific opcode: no claim.
    admin('identify_70', OPC_IDENTIFY, sct=1, sc=0x70)
    admin('identify_50', OPC_IDENTIFY, sct=1, sc=0x50)
    admin('vs_09', 0xc0, sct=1, sc=0x09)
    # SECP 00h with an SP Specific value SPC-5 reserves: no layout, raw.
    endpoint += 1
    data = bytes(range(0x20, 0x24))
    frames['secp0_spsp3_req'] = len(packets) + 1
    packets.append(make_packet(True, NMIMT_ADMIN, 0,
                               admin_request_payload(NVME_AQ_OPC_SECURITY_RECV,
                                                     cns=security_cdw10(0x00, 0x0003),
                                                     cdw11=len(data), dlen=len(data),
                                                     flags=0),
                               bmc_eid=endpoint))
    frames['secp0_spsp3'] = len(packets) + 1
    packets.append(make_packet(False, NMIMT_ADMIN, 0, admin_resp_with_data(data),
                               bmc_eid=endpoint))
    # SCT 7h is Vendor Specific (Base 2.4 Figure 102); Generic SC 02h control.
    admin('vendor_sc_00', OPC_SELF_TEST, cdw10=1, sct=7, sc=0x00)
    admin('vendor_sc_01', OPC_SELF_TEST, cdw10=1, sct=7, sc=0x01)
    admin('vendor_sc_ff', OPC_SELF_TEST, cdw10=1, sct=7, sc=0xff)
    admin('generic_sc_02', OPC_SELF_TEST, cdw10=1, sct=0, sc=0x02)
    return packets, frames


# ---------------------------------------------------------------------------
# nvme-mi-quality-review.pcapng
# ---------------------------------------------------------------------------

# Re-decoding the same NVMe-MI response bytes, over NVMe-MI.
#
#   * An ANA log (NVMe Base 2.3 Figures 227/228) window and its Replay
#     (NVMe-MI 2.1 section 4.2.1.5): the replayed Response Message is the same
#     message, so it must decode the same as the original.  One window starts
#     at the page header (DOFST 0), one inside Descriptor 0 (DOFST 16).
#   * A Replay Control Primitive sent with IC = 0 (NVMe-MI 2.1 Figure 20: IC
#     "should" be set on a request), answered Success with RR = 1, then the
#     replayed Response Message on the primitive's Msg tag.
#   * An Abort Control Primitive sent with IC = 0, answered Success with CPAS
#     01b (section 4.2.1.3), then a new Command Message on the freed slot.
#   * The same Abort with a wrong MIC (section 3.2.1.1: discarded), so the
#     slot is still occupied when the next Command Message arrives.
#   * A More Processing Required response (Figure 29, 01h), a Replay on the
#     command's own Msg tag, the replayed MPR and the final response.
#   * An Abort Control Primitive superseded on its Msg tag by a Get State
#     (section 4.2.1), then Unable to Abort (Figure 29, 08h; Figure 30 has no
#     TAG), then the Get State's own Success.
#   * Unable to Abort answering a lone Get State: no Abort is outstanding.
#   * Unable to Abort when the newest primitive is itself the Abort.
#   * A reserved NMIMT request sent with IC = 0 (Figure 20 "should"), and its
#     verified Invalid Parameter echo (section 4.1.2: the NMIMT is copied from
#     the request).
#   * The newest Control Primitive answered first, then a late answer to the
#     one it superseded: Unable to Abort for an Abort, Success by TAG for a
#     Get State; then duplicates of both answers.
#   * NVMe-MI messages shorter than the 4-byte Message Header (section 3.1.1):
#     3 bytes, and the MCTP type byte alone.
#   * Admin requests whose Data Length is not the Request Data size the
#     command requires (NVMe-MI 2.2 Figure 139): Set Features Timestamp and
#     Firmware Image Download carrying exactly DLEN bytes, then a Firmware
#     Image Download whose DLEN exceeds the bytes it carries.
#   * A Security Receive request carrying Request Data (NVMe Base 2.3 Figure
#     142: its data is controller to host only).
#   * Admin data in the direction its opcode does not define (NVMe Base 2.3
#     Figure 142): a Get Log Page request with Request Data, and a Set
#     Features Timestamp request answered with Response Data.
#   * Response Data on a command defined to transfer Request Data only
#     (NVMe-MI 2.1 "Request and Response Data"): two Firmware Image Download
#     requests with DLEN 16, answered with 8 and with 20 bytes.
#   * Lockdown requests whose OFI is a Feature Identifier (SCP 2h), an Admin
#     opcode (SCP 0h) and an MI Command Set opcode (SCP 3h) (NVMe Base 2.3
#     Figure 353: OFI is "identified by the Scope field").
#   * A Get Features request (Power Management) whose Info row must name its
#     Feature, as Identify and Get Log Page requests name their CNS / LID.
#   * Get and Set Features Temperature Threshold requests whose TMPSEL is Fh
#     and a Reserved 9h / Eh (NVMe Base 2.3 Figure 407: Fh is all sensors in a
#     Set Features and Reserved in a Get Features).
#   * Firmware Image Download completions whose Dword 0 is the Firmware
#     Commit layout (NVMe Base 2.3 Figure 186): a Success with MEFWO and an
#     Overlapping Range abort with ASQFWO.
#   * A Firmware Image Download request whose NUMD is FFFFFFFFh, the largest
#     0's based dword count (NVMe Base 2.3 Figure 189: 2^32 dwords).
#   * Security Receive requests with Security Protocol EAh whose SP Specific
#     value is RPMB (0001h) and a Reserved 0003h (NVMe Base 2.3 Figure 396).
#   * An Asynchronous Event Message whose AE Occurrence Specific Info values
#     (NVMe-MI 2.1 Figure 65) read in their units: Composite Temperature,
#     SMART Warnings and Power Threshold Exceeded.
#   * A VPD Read whose MultiRecords (NVMe-MI 2.2 Figures 172, 175, 176, 189,
#     194) carry a named Boot Failure Code and Form Factor, Reserved bytes in
#     byte order, and the PCIe and 2-Wire bit vectors: the NVMe and NVMe PCIe
#     Port MultiRecords and a Topology with an Upstream Connector, an NVM
#     Subsystem and a 2-Wire Mux.
#   * A VPD Read whose Topology carries FRU Information Device Element
#     Descriptors (NVMe-MI 2.2 Figure 196) with REV 1h, 0h and 2h.
#   * Identify structures that more than one CNS returns (NVMe Base 2.3
#     sections 5.2.13.2.20, 5.2.13.2.7): CNS 08h and 1Fh, CNS 02h and 07h; then
#     windows that start and end inside a field (Figure 335 at DOFST 6, the
#     Figure 343 vector array at DOFST 4).
#   * A VPD Read with a Product Info Area (NVMe-MI 2.1 section 8.2.2, Figures
#     170/171) ahead of a MultiRecord, the same with a wrong PICHK, and a
#     window that ends inside the Product Part/Model Number.
#   * NVM Subsystem Health Status Poll responses with inverted SMART Warnings,
#     and NSS, CCSF and CHSCF with their Reserved bits set.
#   * NVMe PCIe Port MultiRecords with PINFO Reserved bits set.
#
# Each case is on its own Management Endpoint EID, so no case can share a
# Command Slot with another.  Prints the authoritative frame map and SHA-256.

NMIMT_MI = 1
NMIMT_RESERVED = 3
OPC_GET_LOG_PAGE = 0x02
OPC_FW_DOWNLOAD = 0x11
OPC_SECURITY_RECV = 0x82
OPC_LOCKDOWN = 0x24
OPC_GET_FEATURES = 0x0a
LID_ANA = 0x0c
FID_TIMESTAMP = 0x0e
FID_POWER_MGMT = 0x02
FID_TEMP_THRESHOLD = 0x04
MI_OPC_VPD_READ = 0x05
REPLAY_TAG = 7
STATUS_UNABLE_TO_ABORT = 0x08


def ana_page():
    """Header CHGC 5, NAGD 2; Descriptor 0 = AGID 1, NNV 2, CHGC 7, ANAS 01h,
    NSIDs 10h, 11h (40 bytes); Descriptor 1 = AGID 2, NNV 1, CHGC 8, ANAS 02h,
    NSID 9 (36 bytes)."""
    hdr = struct.pack('<QH6x', 5, 2)
    d0 = struct.pack('<IIQB15x', 1, 2, 7, 0x01) + struct.pack('<II', 0x10, 0x11)
    d1 = struct.pack('<IIQB15x', 2, 1, 8, 0x02) + struct.pack('<I', 9)
    return hdr + d0 + d1


def edge_case_vectors():
    packets, frames = [], {}
    endpoint = 0x50
    page = ana_page()

    def add(name, packet):
        frames[name] = len(packets) + 1
        packets.append(packet)

    def next_endpoint():
        nonlocal endpoint
        endpoint += 1
        return endpoint

    # Request, response, Replay CP (CPSP RRO 0), CP Success with CPSR RR=1,
    # then the byte-identical Response Message on the CP's Msg tag: "The Msg
    # tag in each packet of the replayed Response Message shall be set to the
    # value of the Msg tag in the associated Replay Control Primitive."
    def ana_replay(name, dofst, dlen):
        eid = next_endpoint()
        request = admin_request_payload(
            OPC_GET_LOG_PAGE, cns=LID_ANA | (15 << 16), flags=0x03,
            doff=dofst, dlen=dlen)
        response = admin_resp_with_data(page[dofst:dofst + dlen])
        add(name + '_req', make_packet(True, NMIMT_ADMIN, 0, request,
                                             bmc_eid=eid))
        add(name, make_packet(False, NMIMT_ADMIN, 0, response,
                                    bmc_eid=eid))
        add(name + '_replay_req', make_packet(
            True, NMIMT_CONTROL, 0,
            cp_request_payload(CP_OPC_REPLAY, 0x21, cpsp=0),
            bmc_eid=eid, tag=REPLAY_TAG))
        add(name + '_replay_ack', make_packet(
            False, NMIMT_CONTROL, 0,
            cp_response_payload(0, 0x21, cpsr=0x0001),
            bmc_eid=eid, tag=REPLAY_TAG))
        add(name + '_replay', make_packet(False, NMIMT_ADMIN, 0, response,
                                                bmc_eid=eid, tag=REPLAY_TAG))

    ana_replay('ana_dofst0', 0, 40)
    ana_replay('ana_dofst16', 16, 24)

    def mi_req(eid, tag):
        return make_packet(True, NMIMT_MI, 0,
                                 mi_request_payload(OPC_NSHSP),
                                 bmc_eid=eid, tag=tag)

    def mi_resp(eid, tag, status=0):
        payload = (mi_response_payload_with_data(status, bytes(8))
                   if status == 0 else
                   mi_response_payload(status, nmresp=0x0a00))
        return make_packet(False, NMIMT_MI, 0, payload,
                                 bmc_eid=eid, tag=tag)

    def cp_req(eid, tag, opc, cp_tag, **kw):
        return make_packet(True, NMIMT_CONTROL, 0,
                                 cp_request_payload(opc, cp_tag, 0),
                                 bmc_eid=eid, tag=tag, **kw)

    def cp_ok(eid, tag, cp_tag, cpsr):
        return make_packet(False, NMIMT_CONTROL, 0,
                                 cp_response_payload(0, cp_tag, cpsr),
                                 bmc_eid=eid, tag=tag)

    def cp_resp(eid, tag, status, cp_tag=0, cpsr=0):
        return make_packet(False, NMIMT_CONTROL, 0,
                                 cp_response_payload(status, cp_tag, cpsr),
                                 bmc_eid=eid, tag=tag)

    # Replay CP with IC = 0, Success RR = 1, replayed response on its tag.
    eid = next_endpoint()
    add('replay_ic0_req', mi_req(eid, 0))
    add('replay_ic0_resp', mi_resp(eid, 0))
    add('replay_ic0_cp', cp_req(eid, 3, CP_OPC_REPLAY, 0x22, ic=False))
    add('replay_ic0_ack', cp_ok(eid, 3, 0x22, 0x0001))
    add('replay_ic0_replay', mi_resp(eid, 3))

    # Abort CP with IC = 0, Success CPAS 01b; the next command is not a
    # supersession.
    eid = next_endpoint()
    add('abort_ic0_req', mi_req(eid, 0))
    add('abort_ic0_cp', cp_req(eid, 1, CP_OPC_ABORT, 0x11, ic=False))
    add('abort_ic0_ack', cp_ok(eid, 1, 0x11, 0x0001))
    add('abort_ic0_next', mi_req(eid, 2))
    add('abort_ic0_next_resp', mi_resp(eid, 2))

    # Same, but the Abort's MIC is wrong: the endpoint discarded it, so the
    # slot stays occupied and the next command is still a supersession.
    eid = next_endpoint()
    add('abort_badmic_req', mi_req(eid, 0))
    add('abort_badmic_cp', cp_req(eid, 1, CP_OPC_ABORT, 0x11,
                                  mic=0xdeadbeef))
    add('abort_badmic_ack', cp_ok(eid, 1, 0x11, 0x0001))
    add('abort_badmic_next', mi_req(eid, 2))
    add('abort_badmic_next_resp', mi_resp(eid, 2))

    # MPR, Replay (IC = 1) on the command's own tag, replayed MPR, final.
    eid = next_endpoint()
    add('mpr_req', mi_req(eid, 0))
    add('mpr', mi_resp(eid, 0, status=1))
    add('mpr_replay_cp', cp_req(eid, 0, CP_OPC_REPLAY, 0x44))
    add('mpr_replay_ack', cp_ok(eid, 0, 0x44, 0x0001))
    add('mpr_replay', mi_resp(eid, 0, status=1))
    add('mpr_final', mi_resp(eid, 0))

    # Abort, then Get State on the same Msg tag before the Abort is answered
    # (section 4.2.1), Unable to Abort (Figure 29 08h; Figure 30, no TAG),
    # then the Get State's own Success.
    eid = next_endpoint()
    add('late_unable_abort', cp_req(eid, 1, CP_OPC_ABORT, 0x11))
    add('late_unable_get_state', cp_req(eid, 1, CP_OPC_GET_STATE, 0x22))
    add('late_unable_resp', cp_resp(eid, 1, STATUS_UNABLE_TO_ABORT))
    add('late_unable_get_state_ok', cp_resp(eid, 1, 0, 0x22, 0x0000))

    # Unable to Abort with no Abort outstanding: answers nothing captured.
    eid = next_endpoint()
    add('unable_no_abort_get_state',
        cp_req(eid, 2, CP_OPC_GET_STATE, 0x33))
    add('unable_no_abort_resp', cp_resp(eid, 2, STATUS_UNABLE_TO_ABORT))
    add('unable_no_abort_get_state_ok', cp_resp(eid, 2, 0, 0x33, 0x0000))

    # The newest primitive is itself the Abort; 08h answers it directly.
    eid = next_endpoint()
    add('unable_newest_get_state',
        cp_req(eid, 3, CP_OPC_GET_STATE, 0x44))
    add('unable_newest_abort', cp_req(eid, 3, CP_OPC_ABORT, 0x55))
    add('unable_newest_resp', cp_resp(eid, 3, STATUS_UNABLE_TO_ABORT))

    # Reserved NMIMT request with IC = 0; the echo is Invalid Parameter, PEL
    # byte 1 bit 3 (the NMIMT field), as nvme-mi-types.pcapng F156.
    eid = next_endpoint()
    add('nmimt_ic0_req', make_packet(True, NMIMT_RESERVED, 0, b'\xAA' * 4,
                                           bmc_eid=eid, tag=1, ic=False))
    add('nmimt_ic0_resp', make_packet(False, NMIMT_RESERVED, 0,
                                            bytes.fromhex('04 03 01 00'),
                                            bmc_eid=eid, tag=1))

    # The newest primitive is answered first; the superseded one's answer
    # still pairs (section 4.2.1).  08h finds the Abort; Success its TAG.
    eid = next_endpoint()
    add('after_newest_abort', cp_req(eid, 4, CP_OPC_ABORT, 0x71))
    add('after_newest_get_state', cp_req(eid, 4, CP_OPC_GET_STATE, 0x72))
    add('after_newest_get_state_ok', cp_resp(eid, 4, 0, 0x72, 0x0000))
    add('after_newest_unable', cp_resp(eid, 4, STATUS_UNABLE_TO_ABORT))
    eid = next_endpoint()
    add('after_newest_gs_old', cp_req(eid, 5, CP_OPC_GET_STATE, 0x81))
    add('after_newest_gs_new', cp_req(eid, 5, CP_OPC_GET_STATE, 0x82))
    add('after_newest_gs_new_ok', cp_resp(eid, 5, 0, 0x82, 0x0000))
    add('after_newest_gs_old_ok', cp_resp(eid, 5, 0, 0x81, 0x0000))
    add('after_newest_gs_old_dup', cp_resp(eid, 5, 0, 0x81, 0x0000))
    add('after_newest_gs_new_dup', cp_resp(eid, 5, 0, 0x82, 0x0000))

    # An MCTP message of type NVMe-MI shorter than the 4-byte NVMe-MI Message
    # Header (NVMe-MI 2.1 section 3.1.1): three header bytes, then only the
    # MCTP type byte.  IC = 1, as everywhere else in the corpus.
    def short_mi(eid, body):
        return (sll_header(HOST_EID, outgoing=True)
                + mctp_header(True, bmc_eid=eid, tag=0) + body)

    add('mi_short3', short_mi(next_endpoint(), bytes([0x84, 0x08, 0x00])))
    add('mi_short1', short_mi(next_endpoint(), bytes([0x84])))

    def admin_req(eid, opcode, cdw10, dlen, data=b'', cdw11=0):
        payload = admin_request_payload(opcode, cns=cdw10, cdw11=cdw11,
                                              flags=0, dlen=dlen) + data
        return make_packet(True, NMIMT_ADMIN, 0, payload, bmc_eid=eid)

    # Data Length against the command's required Request Data size
    # (NVMe-MI 2.2 Figure 139): Timestamp is 8 bytes (Base 2.3 Figures
    # 414/415), NUMD 3 is 16 bytes (Figure 189); then DLEN above the carried
    # field, the other Figure 139 condition.
    add('setf_ts_dlen16', admin_req(next_endpoint(), OPC_SET_FEATURES,
                                    FID_TIMESTAMP, 16, bytes(16)))
    add('fwdl_dlen8', admin_req(next_endpoint(), OPC_FW_DOWNLOAD, 3, 8,
                                bytes(8)))
    add('fwdl_dlen_over', admin_req(next_endpoint(), OPC_FW_DOWNLOAD, 3, 16,
                                    bytes(8)))

    # Security Receive (Base 2.3 Figure 142: data controller to host) with
    # 8 bytes of Request Data.  SECP 01h in CDW10 31:24, AL 512 in CDW11.
    add('secrecv_tail', admin_req(next_endpoint(), OPC_SECURITY_RECV,
                                  0x01 << 24, 16, bytes(8), cdw11=512))

    def admin_ok(eid, data):
        return make_packet(False, NMIMT_ADMIN, 0,
                                 admin_resp_with_data(data), bmc_eid=eid)

    # Data in the direction its opcode does not define (Base 2.3 Figure
    # 142): a Get Log Page request tail (LID 02h, NUMD 127 = 512 bytes), and a
    # Set Features Timestamp request answered with 8 bytes of Response Data.
    add('glp_tail', admin_req(next_endpoint(), OPC_GET_LOG_PAGE,
                              0x02 | (127 << 16), 512, bytes(range(8))))
    eid = next_endpoint()
    add('setf_ts_req', admin_req(eid, OPC_SET_FEATURES, FID_TIMESTAMP, 8,
                                 bytes(range(8))))
    add('setf_ts_resp', admin_ok(eid, bytes(range(0x10, 0x18))))

    # Response Data on a command that defines Request Data only (NVMe-MI 2.1
    # "Request and Response Data"): Firmware Image Download NUMD 3 / DLEN 16,
    # answered with 8 bytes (within DLEN) and, on another endpoint, 20 bytes.
    eid = next_endpoint()
    add('fwdl_req', admin_req(eid, OPC_FW_DOWNLOAD, 3, 16, bytes(16)))
    add('fwdl_resp_within', admin_ok(eid, bytes(8)))
    eid = next_endpoint()
    add('fwdl_long_req', admin_req(eid, OPC_FW_DOWNLOAD, 3, 16, bytes(16)))
    add('fwdl_long_resp', admin_ok(eid, bytes(20)))

    # Lockdown OFI names what its Scope selects (NVMe Base 2.3 Figure 353):
    # SCP 2h Feature 04h (PRHBT 1, IFC 01b), SCP 0h opcode 84h (IFC 10b),
    # SCP 3h MI Command Set opcode 01h (no table in packet-nvme.c).
    add('lockdown_scp2', admin_req(next_endpoint(), OPC_LOCKDOWN,
                                   (0x04 << 8) | (1 << 5) | 0x10 | 0x2, 0))
    add('lockdown_scp0', admin_req(next_endpoint(), OPC_LOCKDOWN,
                                   (0x84 << 8) | (2 << 5) | 0x10 | 0x0, 0))
    add('lockdown_scp3', admin_req(next_endpoint(), OPC_LOCKDOWN,
                                   (0x01 << 8) | (2 << 5) | 0x10 | 0x3, 0))

    # A Get Features whose row must name its Feature (Power Management).
    add('getf_pm', admin_req(next_endpoint(), OPC_GET_FEATURES,
                             FID_POWER_MGMT, 0))

    # Temperature Threshold TMPSEL (NVMe Base 2.3 Figure 407): Fh is all
    # sensors in a Set Features and Reserved in a Get Features; 9h-Eh are
    # Reserved.  TMPTH 0160h (352 K) on the Sets.
    add('getf_tt_all', admin_req(next_endpoint(), OPC_GET_FEATURES,
                                 FID_TEMP_THRESHOLD, 0, cdw11=0xf << 16))
    add('getf_tt_9', admin_req(next_endpoint(), OPC_GET_FEATURES,
                               FID_TEMP_THRESHOLD, 0, cdw11=0x9 << 16))
    add('setf_tt_all', admin_req(next_endpoint(), OPC_SET_FEATURES,
                                 FID_TEMP_THRESHOLD, 0,
                                 cdw11=(0xf << 16) | 0x0160))
    add('setf_tt_e', admin_req(next_endpoint(), OPC_SET_FEATURES,
                               FID_TEMP_THRESHOLD, 0,
                               cdw11=(0xe << 16) | 0x0160))

    # Firmware Image Download completion Dword 0 is Figure 186 (NVMe Base
    # 2.3 Firmware Image Download): MEFWO on a Success, ASQFWO on an abort
    # with SCT 1h / SC 14h Overlapping Range (Figure 191).
    def admin_cqe(eid, dw0, sct=0, sc=0):
        cqe3 = admin_cqe3(cqe_status_word(sct=sct, sc=sc, phase=1))
        return make_packet(False, NMIMT_ADMIN, 0,
                                 admin_response_payload(0, cqe1=dw0,
                                                              cqe3=cqe3),
                                 bmc_eid=eid)

    eid = next_endpoint()
    add('fwdl_mud_req', admin_req(eid, OPC_FW_DOWNLOAD, 3, 16, bytes(16)))
    add('fwdl_mud_ok', admin_cqe(eid, 0x2))
    eid = next_endpoint()
    add('fwdl_mud_abort_req', admin_req(eid, OPC_FW_DOWNLOAD, 3, 16,
                                        bytes(16)))
    add('fwdl_mud_abort', admin_cqe(eid, 0x1, sct=1, sc=0x14))

    # Firmware Image Download NUMD FFFFFFFFh: 2^32 dwords, the largest
    # 0's based count (NVMe Base 2.3 Figure 189).  No data can follow.
    add('fwdl_numd_max', admin_req(next_endpoint(), OPC_FW_DOWNLOAD,
                                   0xffffffff, 0))

    # Security Protocol EAh (NVMe Base 2.3 Figure 396): Security Receive with
    # SPSP 0001h (RPMB; NSSF is the RPMB Target, 0), and with SPSP 0003h
    # (Reserved) and NSSF 05h.  AL 512, DLEN 512.
    add('secrecv_rpmb', admin_req(next_endpoint(), OPC_SECURITY_RECV,
                                  (0xea << 24) | (0x0001 << 8) | 0x00, 512,
                                  cdw11=512))
    add('secrecv_ea_rsvd', admin_req(next_endpoint(), OPC_SECURITY_RECV,
                                     (0xea << 24) | (0x0003 << 8) | 0x05, 512,
                                     cdw11=512))

    # AE Occurrence Specific Info (NVMe-MI 2.2 Figure 65): 06h CTV D8h
    # (-40 C, Figure 105), 09h CWV FDh (only TAUT asserted, inverted sense),
    # 0Eh PMT 0h, PWRS 01b, PWRV 12345 (1.2345 W).
    add('aem_specific', aem_packet(aeo_list([
        aeo_entry(0x06, 2, 0, specific=b'\xd8'),
        aeo_entry(0x09, 2, 0, specific=b'\xfd'),
        aeo_entry(0x0e, 1, 10,
                        specific=struct.pack('<I', (1 << 16) | 12345)),
    ])))

    # VPD (NVMe-MI 2.2 section 8.2): Common Header (Figure 172), MultiRecords
    # with zero checksums.  One VPD Read on its own endpoint, DOFST 0.
    def vpd_record(kind, payload, last=False):
        header = bytes([kind, 0x82 if last else 0x02, len(payload),
                        -sum(payload) & 0xff])
        return header + bytes([-sum(header) & 0xff]) + payload

    def vpd_image(records, bfc=0):
        header = bytes([1, 0, 0, 0, 0, 1, bfc])
        return header + bytes([-sum(header) & 0xff]) + b''.join(records)

    def vpd_topology(*elements):
        return vpd_record(0x0d, bytes([0, 0, len(elements)]) + b''.join(elements),
                          last=True)

    def vpd_read(name, data):
        eid = next_endpoint()
        add(name + '_req', make_packet(
            True, NMIMT_MI, 0,
            mi_request_payload(MI_OPC_VPD_READ, cdw0=0, cdw1=len(data)),
            bmc_eid=eid))
        add(name, make_packet(
            False, NMIMT_MI, 0, mi_response_payload_with_data(0, data),
            bmc_eid=eid))

    # BFC 08h; NVMe MultiRecord, RLEN 20h (OCP 2.7 FRU-3), FF 22h, byte 17
    # 00h; NVMe PCIe Port MultiRecord, RLEN 08h (FRU-4): PCIELS 1Fh, x4, MCTPS
    # 1, RCCAP 07h; Topology: Upstream Connector (FF 22h), NVM Subsystem
    # (SADDRI 3Ah, TWCAP 51h), 2-Wire Mux (TWADDRI E9h, TWCAP C2h).
    nvme = bytearray(32)
    nvme[1] = 0x22
    nvme[8:12] = bytes([1, 2, 3, 4])
    nvme[13:19] = bytes([5, 6, 7, 8, 9, 25])
    nvme[19:32] = (0x1d1a94a2000).to_bytes(13, 'little')
    vpd_port = bytes([1, 0, 1, 0x1f, 4, 1, 0x07, 0])
    upstream = bytes([2, 0, 17, 0x22, 0, 0, 0, 0, 25, 0, 1,
                      1, 6, 0, 3, 1, 0])
    subsystem = (bytes([7, 1, 19, 0x3a, 0x51, 1, 0, 7, 0x1f, 4, 0x07, 0, 1])
                 + struct.pack('<HHH', 5, 10, 15))
    mux = bytes([5, 0, 10, 0xe9, 0xc2, 1, 0, 4, 1, 1])
    vpd_read('vpd_mr', vpd_image([vpd_record(0x0b, bytes(nvme)),
                                  vpd_record(0x0c, vpd_port),
                                  vpd_topology(upstream, subsystem, mux)],
                                 bfc=0x08))

    # FRU Information Device Element Descriptors (NVMe-MI 2.2 Figure 196):
    # REV 1h (the "shall"; TWADDRI A6h, TWCAP E1h, MFIDS 9 = 512 bytes, OCP
    # 2.7 FRU-2), REV 0h (the factory default; A4h, 00h, 8), REV 2h.
    vpd_read('vpd_fru', vpd_image([vpd_topology(
        bytes([8, 1, 6, 0xa6, 0xe1, 9]),
        bytes([8, 0, 6, 0xa4, 0x00, 8]),
        bytes([8, 2, 6, 0xa6, 0xe1, 9]))]))

    # Identify structures fetched by more than one CNS render one way
    # (NVMe Base 2.3 sections 5.2.13.2.20, 5.2.13.2.7): CNS 08h and 1Fh return
    # Figure 335, CNS 02h and 07h a Namespace List (Figure 139).  Then window
    # edges inside a field: Figure 335 at DOFST 6 / DLEN 16 (inside ANAGRPID
    # and RGRPID; Figure 139 flags the offset as not dword-aligned), and the
    # Figure 343 vector array at DOFST 4 / DLEN 16.
    def identify(name, cns, data, csi=0, dofst=0):
        eid = next_endpoint()
        add(name + '_req', make_packet(
            True, NMIMT_ADMIN, 0,
            admin_request_payload(OPC_IDENTIFY, cns=cns, cdw11=csi << 24,
                                        flags=0, doff=dofst, dlen=len(data)),
            bmc_eid=eid))
        add(name, admin_ok(eid, data))

    # NSFEAT 08h, ANAGRPID 7, NVMSETID 1, ENDGID 2, RGRPID 3; 31:24 Reserved.
    cs_ind = (bytes([0x08, 0, 0, 0]) + struct.pack('<I', 7) + bytes(2)
              + struct.pack('<HH', 1, 2) + bytes(6) + struct.pack('<I', 3)
              + bytes(8))
    identify('id_cns08', 0x08, cs_ind)
    identify('id_cns1f', 0x1f, cs_ind)
    identify('id_cns1f_cut', 0x1f, cs_ind[6:22], dofst=6)
    nslist = struct.pack('<IIII', 1, 3, 0, 0)
    identify('id_cns02', 0x02, nslist)
    identify('id_cns07', 0x07, nslist)
    identify('id_cns1c_cut', 0x1c, bytes(range(4, 20)), dofst=4)

    # VPD Product Info Area (NVMe-MI 2.2 section 8.2.2, Figure 174; IPMI FRU
    # 1.0 Table 12-1) at PIAOFF 1, before an NVMe PCIe Port MultiRecord
    # (Figure 176).  Asset Tag is binary (type code 00b); FRU File ID is
    # empty; one custom field.  Then the same image with a wrong PICHK, and a
    # 32-byte window that ends inside the Product Part/Model Number.
    def tl_field(text, tcode=3):
        return bytes([(tcode << 6) | len(text)]) + text

    def product_info(bad_sum=False):
        body = (bytes([0x01, 0, 0x19])
                + tl_field(b'ACME') + tl_field(b'NVMe SSD')
                + tl_field(b'MODEL-123') + tl_field(b'01')
                + tl_field(b'SN0001') + tl_field(b'\xbe\xef', tcode=0)
                + tl_field(b'') + tl_field(b'XYZ') + b'\xc1')
        palen = (len(body) + 1 + 7) // 8
        area = bytearray(body + bytes(palen * 8 - len(body)))
        area[1] = palen
        area[-1] = (-sum(area[:-1]) + (1 if bad_sum else 0)) & 0xff
        return bytes(area)

    def vpd_with_pia(bad_sum=False):
        pia = product_info(bad_sum)
        header = bytes([1, 0, 0, 0, 1, 1 + len(pia) // 8, 0])
        header += bytes([-sum(header) & 0xff])
        return header + pia + vpd_record(0x0c, bytes([1, 0, 1, 0x1f, 4, 1, 0x07, 0]),
                                         last=True)

    vpd_read('vpd_pia', vpd_with_pia())
    vpd_read('vpd_pia_badsum', vpd_with_pia(bad_sum=True))
    vpd_read('vpd_pia_cut', vpd_with_pia()[:32])

    def vpd_header(bia=0, pia=0, mri=0):
        header = bytes([1, 0, 0, bia, pia, mri, 0])
        return header + bytes([-sum(header) & 0xff])

    # MRIOFF 0: bytes outside every decoded area are still shown (8.2).
    vpd_read('vpd_board_only', vpd_header(bia=1) + bytes([1, 1, 0x19]) + bytes(5))
    vpd_read('vpd_pia_outside', vpd_header(pia=4) + b'\xaa' * 16)

    def health_poll(name, data):
        eid = next_endpoint()
        add(name + '_req', make_packet(True, NMIMT_MI, 0, mi_request_payload(OPC_NSHSP),
                                       bmc_eid=eid))
        add(name, make_packet(False, NMIMT_MI, 0, mi_response_payload_with_data(0, data),
                              bmc_eid=eid))

    # NSHDS SW is the inverted Critical Warning (MI 2.2 Figure 105): FFh is
    # healthy, 80h has every defined warning active, FDh only TAUT.
    for sw in (0xff, 0x80, 0xfd):
        data = bytearray(nshds())
        data[1] = sw
        health_poll(f'nshds_sw_{sw:02x}', bytes(data))

    # Reserved NSS bit 0 and CCSF bits 15:14 and 3 (Figure 105), then CHSCF
    # (Figure 97) with the same runs over four CHDS entries.
    for name, nss, ccsf in (('nss_rsvd', 0x39, 0x0211), ('ccsf_rsvd_15_14', 0x38, 0xc211),
                            ('ccsf_rsvd_3', 0x38, 0x0219), ('ccsf_rsvd_both', 0x38, 0xc008)):
        data = bytearray(nshds())
        data[0] = nss
        struct.pack_into('<H', data, 4, ccsf)
        health_poll('nshds_' + name, bytes(data))
    eid = next_endpoint()
    add('chscf_rsvd_req', make_packet(
        True, NMIMT_MI, 0,
        mi_request_payload(OPC_CHSP, cdw0=0x80000000 | (254 << 16) | 0x01), bmc_eid=eid))
    add('chscf_rsvd', make_packet(
        False, NMIMT_MI, 0,
        mi_response_payload_with_data(0, b''.join(
            chds(n + 1, 0x0001, 300, 5, 100, 0, chsc)
            for n, chsc in enumerate((0x1002, 0xd002, 0x100a, 0xc008))), nmresp=4 << 16),
        bmc_eid=eid))

    # NVMe PCIe Port MultiRecords (Figure 176), RLEN 08h then 0Bh: PINFO
    # 01h, FFh and FEh (bits 7:1 Reserved, bit 0 CPPC).
    ports = [(n, pinfo, extra) for n, (pinfo, extra) in enumerate(
        ((0x01, 0), (0xff, 0), (0xfe, 3), (0xff, 3)))]
    vpd_read('vpd_pinfo', vpd_image([
        vpd_record(0x0c, bytes([1, n, pinfo, 0x1f, 4, 1, 0x07, n]) + bytes(extra),
                   last=n == len(ports) - 1)
        for n, pinfo, extra in ports]))
    return packets, frames


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F231-F349 (m6_final_vectors)
# ---------------------------------------------------------------------------

# Representative layouts, MI 2.1 / Base 2.3 / NVM 1.2 / SIIS 1.20.
#
# No opcode/CNS/FID cross product. Print the frame map and deterministic hash.
# Prohibited Set Features requests receive an MI error, never invented success.

def m6_final_vectors():
    packets, frames = [], {}
    endpoint = 0x30

    def add(name, request, payload, eid):
        frames[name] = len(packets) + 1
        packets.append(make_packet(request, 2, 0, payload, bmc_eid=eid))

    def command(name, opcode=6, data=None, request_data=b'', off=0,
                cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0,
                dw0=0, status=0, mi_error=False):
        nonlocal endpoint
        endpoint += 1
        dlen = len(request_data) if request_data else len(data or b'')
        req = admin_request_payload(
            opcode, flags=0, cns=cdw10, cdw11=cdw11, cdw12=cdw12,
            cdw14=cdw14, doff=off, dlen=dlen)
        req = bytearray(req)
        struct.pack_into('<I', req, 52, cdw13)
        add(name + '_req', True, bytes(req) + request_data, endpoint)
        if mi_error:
            add(name, False, admin_response_payload_short(4), endpoint)
        elif data is not None:
            rsp = admin_response_payload(
                0, cqe1=dw0, cqe3=admin_cqe3(status)) + data
            add(name, False, rsp, endpoint)

    def log(name, lid, data=None, lsp=0, lsi=0, index=None, off=0):
        command(name, 2, data, off=off,
                cdw10=lid | (lsp << 8) | ((max(1, (off + len(data or b'')) // 4) - 1) << 16),
                cdw11=lsi << 16, cdw12=index or 0,
                cdw14=0x800000 if index is not None else 0)

    # Distinct LSP families and positive reserved anti-control.
    log('lsp_telemetry', 7, lsp=9)
    log('lsp_pel', 13, lsp=3)
    log('lsp_lockdown', 20, lsp=0x23)
    log('lsp_discovery', 0x70, lsp=7)
    log('lsp_boolean', 0x1a, lsp=1)
    log('lsp_reserved', 0x1f, lsp=0x7f)
    log('lsi_domain', 0x10, lsi=0x1234)
    log('lsi_target', 0x19, lsi=0x5678)
    supported = bytearray(1024)
    for lid, flags in ((7, 1), (13, 1), (0x70, 7), (0x71, 1)):
        struct.pack_into('<I', supported, lid * 4, 1 | (flags << 16))
    log('supported', 0, bytes(supported))

    ana = struct.pack('<IIQ', 0x11223344, 1, 0x0102030405060708)
    ana += b'\x01' + bytes(15) + struct.pack('<I', 0x55667788)
    log('ana_index', 0x0c, ana, index=3)
    log('ana_unplaced', 0x0c, b'\xa5\x5a\x12\x34', index=3, off=12)
    reach = struct.pack('<IIQ', 0x10203040, 1, 0x0102030405060708)
    reach += b'\x02' + bytes(15) + struct.pack('<I', 0x33445566)
    log('reach_index', 0x1b, reach, index=2)
    nqn = b'nqn.2026-01.com.example:m6'
    log('discovery_index_window', 0x70, (nqn + b'\0').ljust(256, b'\0'),
        index=5, off=256)
    host = bytearray(1056)
    host[0:2] = b'\x03\x01'
    struct.pack_into('<H', host, 10, 4)
    host[256:512] = (nqn + b'\0').ljust(256, b'\0')
    struct.pack_into('<IH', host, 1024, len(host), 1)
    struct.pack_into('<HH', host, 1032, 1, 16)
    host[1036:1052] = bytes(range(16))
    log('host_index', 0x71, bytes(host), index=2)
    log('unknown_index', 2, b'\xa5\x5a\x12\x34', index=1)

    # Command families, including reserved-only 28h.
    command('ns_create', 0x0d, cdw10=0, cdw11=0x02000000)
    command('virtualize', 0x1c, cdw10=0x12340108, cdw11=0x5678)
    command('capacity', 0x20, cdw10=0x12340003,
            cdw11=0x55667788, cdw12=0x11223344)
    command('export_access', 0x2d, cdw10=0x102)
    command('lba_status', 0x86, cdw10=0x55667788, cdw11=0x11223344,
            cdw12=31, cdw13=0x10000042)
    command('sanitize_ns', 0x8c, cdw10=0x40c)
    command('clear_export', 0x28, cdw10=0xa55aa55a)

    # Identify: shared fixed structures, two list widths, and CSI rejection.
    command('id_nvm_ns', data=struct.pack('<QBBHI', 0x0102030405060708, 9, 1, 0, 0x392),
            cdw10=5)
    command('id_nvm_ctrl_window', data=struct.pack('<IQ', 0x12345678, 0x0102030405060708),
            cdw10=6, off=4)
    command('id_unknown_csi', data=b'\xa5\x5a\x12\x34' * 4, cdw10=6, cdw11=0xfe000000)
    command('id_csi_list', data=struct.pack('<IIII', 1, 3, 0, 0), cdw10=7, cdw11=0x02000000)
    domain = bytearray(256)
    domain[0] = 1
    struct.pack_into('<H', domain, 128, 0x1234)
    domain[144:160] = (0x010203040506070809).to_bytes(16, 'little')
    command('id_domain', data=bytes(domain), cdw10=0x18)
    command('id_eg', data=struct.pack('<HHHH', 3, 1, 4, 0x1234), cdw10=0x19)
    command('id_iocsc', data=struct.pack('<QQ', 5, 0), cdw10=0x1c)
    underlying = struct.pack('<QQ', 7, 1) + (nqn + b'\0').ljust(256, b'\0')
    underlying += struct.pack('<IH', 0x12345678, 0x1234) + bytes(58)
    command('id_underlying', data=underlying, cdw10=0x1d)
    ports = bytearray(592)
    struct.pack_into('<QQ', ports, 0, 8, 1)
    struct.pack_into('<HBBB', ports, 528, 0x5678, 3, 1, 2)
    command('id_ports', data=bytes(ports), cdw10=0x1e)
    command('id_state', data=b'\x02\x01\x01\0\x02\0' + bytes(range(16)) + b'\0\0',
            cdw10=0x20)
    command('id_state_unplaced', data=b'\xa5\x5a\x12\x34', cdw10=0x20, off=8)

    def feature(name, fid, data=b'', set_value=False, prohibited=False, **kwargs):
        if set_value:
            command(name, 9, b'', request_data=data, cdw10=fid,
                    mi_error=prohibited, **kwargs)
        else:
            command(name, 10, data, cdw10=fid, **kwargs)

    feature('get_temperature', 4, cdw11=0x120000, dw0=0x120123)
    feature('get_metadata_selector', 0x7e, cdw11=1)
    feature('set_cdq', 0x21, set_value=True, prohibited=True,
            cdw11=0x80001234, cdw12=0x12345678, cdw13=0x55667788)
    feature('get_cdq', 0x21, struct.pack('<II', 0x12345678, 0x55667788),
            cdw11=0x1234, dw0=0x80001234)
    feature('set_threshold', 0x24, set_value=True, cdw11=0x80321234)
    feature('get_threshold', 0x24, dw0=0x80321234)
    feature('set_measurement', 0x25, set_value=True, cdw11=0x12340031)
    feature('get_measurement', 0x25, dw0=0x12345601)
    feature('set_fdp', 0x1d, set_value=True, prohibited=True,
            cdw11=0x1234, cdw12=0x5601)
    feature('get_fdp', 0x1d, cdw11=0x1234, dw0=0x5601)
    feature('set_events', 0x1e, b'\x01\x02\0\0', set_value=True, prohibited=True,
            cdw11=0x00021234, cdw12=1)
    feature('get_events', 0x1e, b'\x01\x01\x02\0', cdw11=0x1234, dw0=2)
    feature('get_hmb', 0x0d, struct.pack('<IIII', 0x1234, 0x56780000, 1, 2), dw0=13)
    feature('set_personality', 0x22, struct.pack('<I', 3), set_value=True, cdw13=0x301)
    feature('get_personality', 0x22, struct.pack('<II', 2, 6), cdw13=1, dw0=0x701)
    feature('unknown_personality', 0x22, b'\xa5\x5a\x12\x34', cdw13=0xfe)
    feature('set_limit', 0x23, set_value=True, cdw13=0x21234)
    feature('get_limit', 0x23, dw0=0x21234)
    feature('get_label', 0x1f, ('rack-€'.encode() + b'\0').ljust(256, b'\0'))
    feature('label_fragment', 0x1f, b'\xe2\x82\0\0')
    feature('get_address', 0x78, bytes(4) + b'https://bmc.example/'.ljust(508, b'\0'))
    feature('get_hostid', 0x81, bytes(range(16)), cdw11=1)
    feature('get_performance', 0x1c, b'\0\0\0\0\x12\0\0\0')
    feature('failed_cqe', 0x24, dw0=0x80321234, status=2)
    command('caps_not_value', 10, b'', cdw10=0x324, dw0=7)
    feature('unknown_feature', 0x86, b'\xa5\x5a\x12\x34', dw0=0x12345678)

    for name, revision in (('siis120', 0x20), ('siis_reserved', 0x0c)):
        body = tcg_l0_feature(5, 1, bytes([revision, 0]) + bytes(10))
        data = struct.pack('>II', 44 + len(body), 1) + bytes(40) + body
        command(name, 0x82, data, cdw10=security_cdw10(1, 1), cdw11=len(data))

    # Base 2.3 Figures 203/205/311/312; MI 2.2 Figures 139/143.
    # Index zero selects the header. Byte 2048 is Entry 0's TEL, not Entry 1.
    discovery = bytearray(1024 + 2 * 1056)
    struct.pack_into('<QQHBBI', discovery, 0, 7, 2, 0, 1, 0, len(discovery))
    for number, trtype in enumerate((3, 1)):
        start = 1024 + number * 1056
        struct.pack_into('<BBBBHHH', discovery, start,
                         trtype, 1, 2, 0, 0x1111 * (number + 1), 0xffff, 32)
        discovery[start + 256:start + 512] = (nqn + b'\0').ljust(256, b'\0')
        struct.pack_into('<IHHHH', discovery, start + 1024, 1056, 1, 0, 2, 20)
        discovery[start + 1036:start + 1056] = f'm6-entry-{number}'.encode().ljust(20, b'\0')
    log('discovery_zero_unplaced', 0x70, bytes(discovery[2048:2052]),
        index=0, off=2048, lsp=1)
    log('discovery_zero_proven', 0x70, bytes(discovery), index=0, lsp=1)
    # No header, but the request's EXTDLPE makes Entry 0's TEL its length.
    log('discovery_zero_unknown_stride', 0x70, bytes(discovery[1024:2052]),
        index=0, off=1024, lsp=1)

    # NVM 1.2 Figures 114/122; Base 2.3 Figure 326; MI 2.2 Figure 139.
    command('id_cns09_window', data=b'\0\x03\0\x03', cdw10=9, cdw11=1, off=24)
    command('id_cns09_partial', data=bytes(4), cdw10=9, cdw11=1, off=20)
    command('id_cns09_lbaf_unplaced', data=struct.pack('<I', 0x00091000),
            cdw10=9, cdw11=1, off=128)
    return packets, frames


# ---------------------------------------------------------------------------
# nvme-mi-admin-logpage.pcapng F451-F456 (discovery_index_tsas_vectors)
# ---------------------------------------------------------------------------

# An indexed Discovery entry (Get Log Page LID 70h, OT 1, index 1 = Entry 0)
# whose TRTYPE 03h and TSAS (SECTYPE 02h) are read in different NVMe-MI
# transactions.  DOFST is relative to the selected index (MI 2.2 Figure 143)
# and each transaction is decoded on its own, so the DOFST 512 response keeps
# its TSAS raw even after a DOFST 0 response showed the TRTYPE.  The whole
# entry in one response (F2) is the control.
#
#   F1/F2  index 1, DOFST 0, DLEN 1024   EID E0h
#   F3/F4  index 1, DOFST 0, DLEN 512    EID E1h
#   F5/F6  index 1, DOFST 512, DLEN 512  EID E1h, after F3/F4

def discovery_index_tsas_vectors():
    packets, frames = [], {}
    entry = bytearray(1024)
    entry[0:4] = b'\x03\x01\x02\x00'               # TRTYPE TCP, IPv4, NVM subsystem
    struct.pack_into('<H', entry, 4, 0x4001)       # PORTID
    entry[768] = 0x02                              # TSAS SECTYPE: TLS 1.3

    def read(name, eid, dofst, dlen):
        req = admin_request_payload(2, flags=0, cns=0x70 | (255 << 16),
                                    cdw14=0x800000, lpo=1, doff=dofst, dlen=dlen)
        frames[name + '_req'] = len(packets) + 1
        packets.append(make_packet(True, 2, 0, req, bmc_eid=eid))
        frames[name] = len(packets) + 1
        packets.append(make_packet(False, 2, 0, admin_response_payload(0) +
                                   bytes(entry[dofst:dofst + dlen]), bmc_eid=eid))

    read('tsas_whole', 0xE0, 0, 1024)
    read('tsas_first', 0xE1, 0, 512)
    read('tsas_second', 0xE1, 512, 512)
    return packets, frames


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F318-F418 (m6_structures_vectors)
# ---------------------------------------------------------------------------

# MI-only structures: MI 2.2 Figs 65/172/175-195; Base 2.3 Figs 138/310/462.
#
# Unknown/ambiguous VPD layouts and selected/captured string fragments stay raw.

def record(kind, payload, last=True):
    header = bytes([kind, 0x82 if last else 2, len(payload), -sum(payload) & 255])
    return header + bytes([-sum(header) & 255]) + payload


def vpd(*records):
    header = bytes([1, 0, 0, 0, 0, 1, 0, 254])
    assert sum(header) % 256 == 0
    return header + b''.join(records)


def label(value, rev=0):
    return bytes([4, rev, 3 + len(value)]) + value


def topology(*elements, last=True):
    return record(0x0d, bytes([0, 0, len(elements)]) + b''.join(elements), last)


def m6_structures_vectors():
    packets, frames = [], {}
    endpoint = 0x30

    def add(name, packet, cut=0):
        frames[name] = len(packets) + 1
        original = len(packet)
        packets.append((packet[:-cut-4] if cut else packet, original))

    def pair(name, kind, request, response, cut=0, eid=None):
        nonlocal endpoint
        endpoint += 1
        eid = endpoint if eid is None else eid
        add(name + '_req', make_packet(True, kind, 0, request, bmc_eid=eid))
        add(name, make_packet(False, kind, 0, response, bmc_eid=eid), cut)

    def mi_list(name, ids, count=None, floor=0, tail=b''):
        payload = struct.pack('<H', len(ids) if count is None else count)
        payload += b''.join(struct.pack('<H', cid) for cid in ids) + tail
        pair(name, 1, mi_request_payload(0, cdw0=(2 << 24) | floor),
             mi_response_payload_with_data(0, payload, nmresp=len(payload)))

    def admin(name, data, cns=0x13, off=0, floor=0, opcode=6, cdw10=None,
              cut=0, eid=None):
        if cdw10 is None:
            cdw10 = cns | (floor << 16)
        pair(name, 2, admin_request_payload(
            opcode, flags=0, cns=cdw10, dlen=len(data), doff=off),
            admin_resp_with_data(data), cut, eid)

    def base_list(name, ids, count=None, size=4096, **kwargs):
        data = struct.pack('<H', len(ids) if count is None else count)
        data += b''.join(struct.pack('<H', cid) for cid in ids)
        admin(name, data.ljust(size, b'\0'), **kwargs)

    def vpd_read(name, data, off=0, cut=0, eid=None):
        pair(name, 1, mi_request_payload(5, cdw0=off, cdw1=len(data)),
             mi_response_payload_with_data(0, data), cut, eid)

    mi_list('mi_ascending', [1, 3])
    mi_list('mi_descending', [3, 2, 1])
    mi_list('mi_floor', [4, 6], floor=5)
    mi_list('mi_overcount', list(range(1, 2049)))
    mi_list('mi_impossible_short', [1], count=60000, tail=b'\xa5')
    mi_list('mi_empty', [])
    mi_list('mi_surplus', [1], tail=b'\xa5\x5a')
    base_list('base_duplicate', [2, 2])
    base_list('base_overcount', list(range(1, 2048)), count=2048)
    base_list('base_floor', [4, 6], floor=5, cns=0x12)
    base_list('base_zero_unused', [5], floor=5)
    admin('base_nonzero_unused', struct.pack('<HH', 1, 5) + bytes(4090) + b'\xa5\x5a')
    # Same endpoint, separate commands: neither order may import NUMCIDS.
    base_list('base_prefix', [5], count=3, size=4, eid=0xb0)
    admin('base_later', b'\x01\x00\xa5\x5a', off=4, eid=0xb0)
    admin('base_later_first', b'\x01\x00\xa5\x5a', off=4, eid=0xb1)
    base_list('base_prefix_after', [5], count=3, size=4, eid=0xb1)

    # One packet covers all thirteen layouts with each occurrence's own scope.
    definitions = [
        (0, 1, 7, b'\x01'), (1, 1, 8, b'\x01'), (2, 2, 0, b'\x06'),
        (3, 1, 9, b'\x03'), (6, 2, 0, b'\x25'), (7, 2, 0, b'\x32'),
        (8, 2, 0, b'\x63'), (9, 2, 0, b'\x80'), (11, 4, 0x10001, b'\x01'),
        (12, 2, 0, b'\x01'), (13, 0, 0x1234, b'\x01'),
        (14, 1, 10, struct.pack('<I', 0xc21234)),
        (15, 1, 10, struct.pack('<I', (2 << 30) | (100 << 18) | (3 << 16)
                                | (1 << 14) | 3300)),
    ]
    entries = [aeo_entry(ae, scope, sid, specific=value)
               for ae, scope, sid, value in definitions]
    add('ae_defined', aem_packet(aeo_list(entries)))
    entries = [aeo_entry(ae, scope, specific=b'\xa5')
               for ae, scope in ((4, 1), (5, 2), (10, 2), (16, 1))]
    add('ae_undefined_raw', aem_packet(aeo_list(entries)))
    add('ae_power_short', aem_packet(aeo_list([
        aeo_entry(14, 1, specific=b'\x01')])))

    nvme = bytearray(32)
    nvme[1] = 0x0a
    nvme[8:12] = bytes([1, 2, 3, 4])
    nvme[13:19] = bytes([5, 6, 7, 8, 9, 10])
    nvme[19:32] = (123456789).to_bytes(13, 'little')
    port = bytes([1, 7, 1, 0x3f, 4, 1, 3, 1])
    # Upstream connector with one bounded PCIe child pointer (Fig 179/182).
    upstream = bytes([2, 0, 17, 10, 1, 0, 0, 2, 25, 0, 1, 1, 6, 0, 3, 2, 0])
    expansion = bytes([3, 0, 10, 10, 0, 1, 0, 4, 0, 3])
    mux = bytes([5, 0, 10, 0xe8, 0, 1, 0, 4, 1, 2])
    subsystem = bytes([7, 1, 19, 0x3a, 0x40, 1, 0, 7, 0x3f, 4, 3, 1, 1])
    subsystem += struct.pack('<HHH', 5, 10, 15)
    good_label = label('rack-€'.encode() + b'\0')
    unknown = bytes([0xee, 0, 5, 0xe2, 0x82])
    all_records = vpd(record(0x0b, bytes(nvme), False),
                      record(0x0c, port, False), record(0xee, b'\xe2\x82', False),
                      topology(upstream, good_label, expansion, mux, subsystem, unknown))
    vpd_read('vpd_known_and_unknown', all_records, eid=0xb2)
    vpd_read('vpd_later', all_records[8:], off=8, eid=0xb2)
    for name, at in (('vpd_bad_common_checksum', 7), ('vpd_bad_header_checksum', 12),
                     ('vpd_bad_record_checksum', 14)):
        bad = bytearray(vpd(record(0x0b, bytes(nvme))))
        bad[at] ^= 1
        vpd_read(name, bytes(bad))
    vpd_read('vpd_bad_record_length', vpd(record(0x0b, b'\0\0')))
    vpd_read('vpd_bad_element_length', vpd(topology(b'\x04\x00\x02')))
    vpd_read('vpd_bad_port_length', vpd(topology(upstream[:-5] + b'\0' * 5)))
    for name, text, rev in (
            ('vpd_incomplete_utf8', b'\xe2\x82\0', 0),
            ('vpd_postnul', b'ok\0\xff\xc2\x1f\x7f', 0),
            ('vpd_unknown_revision', b'\xe2\x82\0', 1)):
        vpd_read(name, vpd(topology(label(text, rev))))
    fragment = vpd(topology(label(b'\xe2\x82\xac\0')))
    vpd_read('vpd_selected_fragment', fragment[:-2])
    vpd_read('vpd_captured_fragment', fragment, cut=2)
    vpd_read('vpd_extended_fragment', vpd(
        topology(label(b'\xe2\x82'), last=False),
        topology(b'\x01\x00\x05\xac\0')))

    for name, value, rev, elen in (
            ('metadata_valid', b' ~\xe2\x82\xac', 0, 5),
            ('metadata_incomplete', b'\xe2\x82', 0, 2),
            ('metadata_unknown_revision', b'\xe2\x82', 1, 2),
            ('metadata_selected_fragment', b'\xe2\x82', 0, 3)):
        data = b'\x01\0\x01' + bytes([rev]) + struct.pack('<H', elen) + value
        data += bytes(-len(data) % 4)
        admin(name, data, opcode=10, cdw10=0x7e)
    prefix = b'nqn.2026-01.com.example:'
    for name, value in (
            ('nqn_valid', prefix + '€😀'.encode() + b'\0'),
            ('nqn_incomplete', prefix + b'\xe2\x82\0'),
            ('nqn_postnul', prefix + b'ok\0\xff\xc2\x1f\x7f'),
            ('nqn_unterminated', b'A' * 256)):
        admin(name, value.ljust(256, b'\0'), cns=1, off=768)
    admin('nqn_captured_fragment', (b'A' * 253 + b'\xe2\x82\0'),
          cns=1, off=768, cut=1)
    discovery = bytearray(512)
    discovery[256:256+len(prefix)+4] = prefix + '€'.encode() + b'\0'
    discovery[256+len(prefix)+4] = 0xff
    admin('discovery_nqn', bytes(discovery), opcode=2,
          cdw10=0x70 | (383 << 16), off=1024)
    unknown_format = bytearray(vpd(record(0x0b, bytes(nvme))))
    unknown_format[9] = 0x83
    unknown_format[12] = -sum(unknown_format[8:12]) & 255
    vpd_read('vpd_unknown_format', bytes(unknown_format))
    old_identify = bytearray(1024)
    struct.pack_into('<I', old_identify, 80, 0x00010200)
    old_identify[768:] = b'\xe2' * 256
    admin('identify_pre_nqn_revision', bytes(old_identify), cns=1)

    # MI 2.2 Fig 139 windows intersect Base 2.3 Fig 328's 1023:768 field.
    # Invalid octets in a fragment must be raw, not validated as a name.
    fragment = b'\x1f\x7f\xe2\x82'
    admin('nqn_selected_prefix', bytes(180) + fragment, cns=1, off=588)
    admin('nqn_selected_suffix', fragment + bytes(768), cns=1, off=1020)
    admin('nqn_selected_interior', fragment, cns=1, off=800)
    admin('discovery_nqn_selected_prefix', bytes(256) + fragment, opcode=2,
          cdw10=0x70 | (320 << 16), off=1024)

    # Base 2.3 §1.4.2 / MI 2.1 §1.7: well-formed UTF-8 is insufficient.
    vpd_read('vpd_del', vpd(topology(label(b'rack-\x7f\0'))))
    admin('metadata_c0', b'\x01\0\x01\0\x03\0a\x1fb\0\0\0',
          opcode=10, cdw10=0x7e)
    admin('nqn_c0_del', (prefix + b'\x1f\x7f\0').ljust(256, b'\0'),
          cns=1, off=768)
    return packets, frames


# ---------------------------------------------------------------------------
# Cross-layer capture: nvme-mi-tcg-cross-layer.pcapng.  mctp-version-state,
# which this suite also reads, comes from gen-mctp-test-capture.py.
# ---------------------------------------------------------------------------

# DSP0236 1.3.3 3.2/8.2/8.6/8.7; MI 2.1 4.2.1.5 Figures 46/47;
# TCG Core 2.01 3.2.2.4.1(6), 3.3.4.7.5, 5.2.3.3/5.2.3.4.

CROSS_LAYER_BASE_US = 1720000000 * 1_000_000


def cross_layer_pcapng(packets, linktype=113):
    return shb() + idb(link_type=linktype) + b''.join(
        epb(packet, CROSS_LAYER_BASE_US + n * 1_000_000)
        for n, packet in enumerate(packets))


def cross_layer_tcg_vectors():
    packets, cases = [], {}

    def pair(name, payload, send=False, csi=1, secp=1, tag=0):
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        assert len(payload) % 4 == 0
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV,
            ctrl_id=1, flags=0, cns=security_cdw10(secp, 0x1000),
            cdw11=len(payload), dlen=len(payload))
        packets.extend((
            make_packet(True, NVME_MI_TYPE_ADMIN, csi,
                          request + (payload if send else b''), tag=tag),
            make_packet(False, NVME_MI_TYPE_ADMIN, csi,
                          admin_resp_with_data(b'' if send else payload), tag=tag)))

    def cp(tokens, tsn=0, hsn=0, ext=0):
        return tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn),
                               0x1000, ext)

    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
            + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS)
    reset = struct.pack('>HHIHHI', 0x1000, 0, 2, 0, 4, 0)
    pair('old-reset', reset, csi=0, secp=2)
    for method in (0xff02, 0xff03, 0xff04, 0xff05):
        pair(f'new-{method:x}', cp(tcg_startup(method, 10, 0x5100)),
             send=method in (0xff02, 0xff04))
    pair('before-replay-secure', cp(call, 0x5100, 10))
    n = len(packets) + 1
    cases['replay'] = (n, n + 1, n + 2)
    packets.extend((
        make_packet(True, NVME_MI_TYPE_CONTROL, 0,
                      cp_request_payload(CP_OPC_REPLAY), tag=7),
        make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                      cp_response_payload(0, cpsr=1), tag=7),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                      admin_resp_with_data(reset), tag=7)))
    pair('after-replay-secure', cp(call, 0x5100, 10))
    pair('after-replay-host-secure', cp(call, 0x5100, 10), send=True)

    for name, token, ext in (('same-subpacket', 0xe4, 1),
                              ('cross-subpacket', 0xef, 2)):
        for label, hsn, tsn in (('victim', 20, 0x5200), ('prior', 21, 0x5201)):
            for method in (0xff02, 0xff03):
                pair(f'{name}-{label}-{method:x}', cp(tcg_startup(method, hsn, tsn), ext=ext),
                     send=method == 0xff02)
        before = tcg_startup(0xff04, 21, 0x5201)
        after = tcg_startup(0xff04, 20, 0x5200)
        bad = bytes([token])
        subpackets = (tcg_subpacket(before + bad + after) if ext == 1 else
                      tcg_subpacket(before + bad) + tcg_subpacket(after))
        pair(name + '-invalid', tcg_compacket(tcg_packet(subpackets), 0x1000, ext),
             send=True)
        pair(name + '-victim-response', cp(tcg_startup(0xff05, 20, 0x5200), ext=ext))
        pair(name + '-victim-plain', cp(call, 0x5200, 20, ext))
        pair(name + '-prior-response', cp(tcg_startup(0xff05, 21, 0x5201), ext=ext))
        pair(name + '-prior-secure', cp(call, 0x5201, 21, ext))
        # A fresh Packet in this same ComPacket must recover immediately.
        pair(name + '-next-packet', tcg_compacket(
            tcg_packet(tcg_subpacket(bad))
            + tcg_packet(tcg_subpacket(after)), 0x1000, ext), send=True)
        pair(name + '-recovery-response', cp(tcg_startup(0xff05, 20, 0x5200), ext=ext))
        pair(name + '-recovery-secure', cp(call, 0x5200, 20, ext))
    return packets, cases


def tcg_failed_send_vectors():
    """nvme-mi-tcg-failed-send.pcapng: a Security Send that completes with an
    error transfers no data (SIIS 1.20 Table 25), so the TPer does not act on
    it (inferred: Core 2.01 3.3.10.2.1 item 3 describes the state after an
    IF-SEND completed without error).  Each scenario has its own session; numbered
    ones run on ComID 1001h, where Properties negotiates SequenceNumbers.
    cases[(scenario, step)] = (request frame, response frame)."""
    packets, cases = [], {}
    anybody = bytes.fromhex('0000000900000001')
    get, set_ = bytes.fromhex('0000000600000016'), bytes.fromhex('0000000600000017')

    def exchange(key, tokens, comid, tsn=0, hsn=0, seq=0, send=True, outcome='ok'):
        payload = tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn, seq), comid)
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV,
            ctrl_id=1, flags=0, cns=security_cdw10(1, comid),
            cdw11=len(payload), dlen=len(payload))
        if outcome in ('abort', 'abort-nomic'):  # Abort Success, CPAS 01b: not executed
            n = len(packets) + 1
            cases[key] = (n, n + 2)
            packets.extend((
                make_packet(True, NVME_MI_TYPE_ADMIN, 1, request + payload),
                make_packet(True, NVME_MI_TYPE_CONTROL, 1,
                            cp_request_payload(CP_OPC_ABORT, tag=0x44), tag=2),
                make_packet(False, NVME_MI_TYPE_CONTROL, 1,
                            cp_response_payload(STATUS_SUCCESS, tag=0x44, cpsr=0x0001),
                            tag=2, ic=outcome == 'abort')))     # nomic: no MIC
            return
        if outcome == 'replay':     # no original response; the Replay carries the error
            n = len(packets) + 1
            cases[key] = (n, n + 3)
            packets.extend((
                make_packet(True, NVME_MI_TYPE_ADMIN, 1, request + payload),
                make_packet(True, NVME_MI_TYPE_CONTROL, 1,
                            cp_request_payload(CP_OPC_REPLAY, tag=0x45), tag=2),
                make_packet(False, NVME_MI_TYPE_CONTROL, 1,
                            cp_response_payload(STATUS_SUCCESS, tag=0x45, cpsr=0x0001),
                            tag=2),
                make_packet(False, NVME_MI_TYPE_ADMIN, 1,
                            admin_response_payload_short(0x04), tag=2)))
            return
        if outcome == 'mi-err':     # Invalid Parameter Error Response
            response = admin_response_payload_short(0x04)
        elif outcome == 'cqe-err':  # Command Sequence Error, DNR
            response = admin_response_payload(0, cqe3=admin_cqe3(
                cqe_status_word(sc=0x0c, dnr=1, phase=1)))
        else:
            response = admin_resp_with_data(b'' if send else payload)
        n = len(packets) + 1
        cases[key] = (n, n + 1)
        packets.extend((
            make_packet(True, NVME_MI_TYPE_ADMIN, 1, request + (payload if send else b'')),
            make_packet(False, NVME_MI_TYPE_ADMIN, 1, response)))

    def call(method):
        return (b'\xf8' + tcg_bytes_atom(anybody) + tcg_bytes_atom(method)
                + b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS)

    result = b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS
    values = b'\xf0' + b''.join(b'\xf2' + tcg_bytes_atom(key) + value + b'\xf3'
                                for key, value in ((b'SequenceNumbers', b'\x01'),
                                                   (b'Asynchronous', b'\x00'))) + b'\xf1'
    header = (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
              + tcg_bytes_atom(bytes.fromhex('000000000000ff01')))
    host = b'\xf2\x00' + values + b'\xf3'
    exchange(('properties', 'send'), header + b'\xf0' + host + b'\xf1'
             + TCG_EOD_STATUS_SUCCESS, 0x1001)
    exchange(('properties', 'recv'), header + b'\xf0' + values + host + b'\xf1'
             + TCG_EOD_STATUS_SUCCESS, 0x1001, send=False)
    control_seq = 0     # the numbered control session's last SeqNumber
    for i, (numbered, outcome, retry) in enumerate((
            (False, 'mi-err', True), (False, 'cqe-err', True),
            (True, 'mi-err', True), (True, 'cqe-err', True),
            (False, 'cqe-err', False), (False, 'abort', True), (True, 'abort', True),
            (False, 'replay', True), (True, 'replay', True),
            (False, 'abort-nomic', True))):
        name = (f'{"seq" if numbered else "noseq"}-{outcome}'
                f'-{"retry" if retry else "no-retry"}')
        comid, hsn, tsn = 0x1001 if numbered else 0x1000, 30 + i, 0x5300 + i
        control_seq += numbered
        for step, method in (('start', 0xff02), ('sync', 0xff03)):
            exchange((name, step), tcg_startup(method, hsn, tsn), comid,
                     seq=control_seq if numbered else 0, send=method == 0xff02)
        a, b = (1, 2) if numbered else (0, 0)
        exchange((name, 'fail'), call(get), comid, tsn, hsn, a, outcome=outcome)
        if retry:
            exchange((name, 'retry'), call(get), comid, tsn, hsn, a)
            exchange((name, 'result-a'), result, comid, tsn, hsn, a, send=False)
        else:
            b = a
        exchange((name, 'set'), call(set_), comid, tsn, hsn, b)
        exchange((name, 'result-b'), result, comid, tsn, hsn, b, send=False)
    return packets, cases


def tcg_failed_send_tcp_vectors():
    """nvme-tcp-tcg-failed-send.pcapng: the same, over NVMe/TCP: an Admin
    Security Send whose CapsuleResp carries an error.  Returns (Ethernet
    frames, {step: (request frame, response frame)})."""
    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                         'gen-nvme-tcp-test-capture.py'))
    packets, cases = [], {}
    sequence = [1, 1]
    host = (tcpgen['HOST_PORT'], tcpgen['HOST_IP'], tcpgen['HOST_MAC'])
    ctrl = (tcpgen['CTRL_PORT'], tcpgen['CTRL_IP'], tcpgen['CTRL_MAC'])

    def emit(pdu, send):
        side = 0 if send else 1
        (sport, sip, smac), (dport, dip, dmac) = (host, ctrl) if send else (ctrl, host)
        segment = tcpgen['tcp'](sport, dport, sequence[side], sequence[1 - side], pdu)
        packets.append(tcpgen['eth'](dmac, smac, tcpgen['ipv4'](
            sip, dip, segment, 0x6000 + len(packets))))
        sequence[side] += len(pdu)

    cid = [1]

    def exchange(key, tokens, send=True, tsn=0, hsn=0, ok=True):
        payload = tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn, 0), 0x1000)
        cid[0] += 1
        entry = tcpgen['sqe'](NVME_AQ_OPC_SECURITY_SEND if send else NVME_AQ_OPC_SECURITY_RECV,
                              cid[0], cdw10=security_cdw10(1, 0x1000), cdw11=len(payload))
        n = len(packets) + 1
        if send:
            emit(struct.pack('<BBBBI', 4, 0, 72, 72, 72 + len(payload)) + entry + payload, True)
        else:
            emit(tcpgen['capsule_cmd_pdu'](entry), True)
            emit(tcpgen['c2h_data_pdu'](cid[0], payload, pdo=24, last=True), False)
        emit(tcpgen['capsule_resp_pdu'](cid[0], sqid=0, status=0 if ok else
                                        cqe_status_word(sc=0x0c, dnr=1, phase=1)), False)
        cases[key] = (n, len(packets))

    anybody = bytes.fromhex('0000000900000001')
    get = bytes.fromhex('0000000600000016')

    def call(method):
        return (b'\xf8' + tcg_bytes_atom(anybody) + tcg_bytes_atom(method)
                + b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS)

    result = b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS
    emit(tcpgen['capsule_cmd_pdu'](tcpgen['sqe'](6, 1, cdw10=1)), True)
    exchange('start', tcg_startup(0xff02, 30, 0x5400))
    exchange('sync', tcg_startup(0xff03, 30, 0x5400), send=False)
    exchange('fail', call(get), tsn=0x5400, hsn=30, ok=False)
    exchange('retry', call(get), tsn=0x5400, hsn=30)
    exchange('result', result, send=False, tsn=0x5400, hsn=30)

    # Two Sends end in one segment: the first fails, the second does not.
    exchange('start2', tcg_startup(0xff02, 31, 0x5401))
    exchange('sync2', tcg_startup(0xff03, 31, 0x5401), send=False)
    sends = []
    for method in (get, bytes.fromhex('0000000600000017')):
        payload = tcg_compacket(tcg_packet(tcg_subpacket(call(method)), 0x5401, 31, 0), 0x1000)
        cid[0] += 1
        entry = tcpgen['sqe'](NVME_AQ_OPC_SECURITY_SEND, cid[0],
                              cdw10=security_cdw10(1, 0x1000), cdw11=len(payload))
        sends.append((cid[0], struct.pack('<BBBBI', 4, 0, 72, 72, 72 + len(payload))
                      + entry + payload))
    cases['pair'] = (len(packets) + 1,)
    emit(sends[0][1] + sends[1][1], True)
    emit(tcpgen['capsule_resp_pdu'](sends[0][0], sqid=0, status=cqe_status_word(
        sc=0x0c, dnr=1, phase=1)), False)
    emit(tcpgen['capsule_resp_pdu'](sends[1][0], sqid=0, status=0), False)
    exchange('result2', result, send=False, tsn=0x5401, hsn=31)
    return packets, cases


def cross_layer_fixtures():
    """{capture name: bytes}; suite_dissection_nvme_mi.py checks these."""
    tcg, _ = cross_layer_tcg_vectors()
    failed, _ = tcg_failed_send_vectors()
    tcp, _ = tcg_failed_send_tcp_vectors()
    return {'nvme-mi-tcg-cross-layer.pcapng': cross_layer_pcapng(tcg),
            'nvme-mi-tcg-failed-send.pcapng': cross_layer_pcapng(failed),
            'nvme-tcp-tcg-failed-send.pcapng': cross_layer_pcapng(tcp, linktype=1)}


# ---------------------------------------------------------------------------
# nvme-mi-mi-commands.pcapng F482-F743 (shared decode; its native twin is in
# gen-nvme-tcp-test-capture.py)
# ---------------------------------------------------------------------------

# Shared Admin/SECP 00h vectors; no build or dissector invocation.
#
# MI 2.2 Figures 137/139/144/148 and Base 2.3 Figures 142/215/216/220/222.
# SECP00 exercises the legacy length interpretation, not SPC-5 conformance:
# SPC-5 is not decoded. Every case is a request/response pair.
# Native twins have one initial Identify frame, then the same common pairs.

def shared_admin_cases():
    cases = []

    def add(name, opcode, *, cdw10=0, cdw11=0, cdw13=0, dlen=0, off=0,
            data=b'', response=b''):
        cases.append({'name': name, 'opcode': opcode, 'cdw10': cdw10,
                          'cdw11': cdw11, 'cdw13': cdw13, 'dlen': dlen, 'off': off,
                          'data': data, 'response': response})

    add('no-data-zero', 0x10)
    add('no-data-dlen', 0x10, dlen=4096)
    add('no-data-offset', 0x10, off=4)
    add('no-data-tail', 0x10, data=b'abcd')
    add('log-window-good', 2, cdw10=2 | (1023 << 16), dlen=4096)
    add('log-window-zero', 2, cdw10=2 | (1023 << 16))
    add('log-window-overrun', 2, cdw10=2 | (1023 << 16), dlen=8, off=4092)
    add('log-offset-end', 2, cdw10=2 | (1023 << 16), dlen=4, off=4096)
    add('log-request-tail', 2, cdw10=2 | (1023 << 16), dlen=4, data=b'abcd')
    add('identify-last-dword', 6, cdw10=1, dlen=4, off=4092)
    add('identify-overrun', 6, cdw10=1, dlen=8, off=4092)
    add('download-exact', 0x11, cdw10=1, dlen=8, data=b'abcdefgh')
    add('download-short-data', 0x11, cdw10=1, dlen=8, data=b'abcd')
    add('download-wrong-size', 0x11, cdw10=2, dlen=8, data=b'abcdefgh')
    add('download-offset', 0x11, cdw10=1, dlen=8, off=4, data=b'abcdefgh')
    add('namespace-delete', 0x0d, cdw10=1)
    add('namespace-create', 0x0d, dlen=4096, data=bytes(4096))
    add('namespace-delete-window', 0x0d, cdw10=1, dlen=4)
    add('set-timestamp', 9, cdw10=0x0e, dlen=8, data=bytes(8))
    add('get-timestamp-window', 0x0a, cdw10=0x0e, dlen=4, off=4)
    add('get-timestamp-overrun', 0x0a, cdw10=0x0e, dlen=8, off=4)
    add('get-timestamp-capabilities', 0x0a, cdw10=0x030e)
    add('get-timestamp-capabilities-window', 0x0a, cdw10=0x030e, dlen=8)
    # 26 P/P FIDs, with an adjacent Get carrying the appropriate buffer.
    prohibited = (1, 3, 5, 6, 7, 8, 9, 10, 11, 13, 15, 18, 19, 20,
                  21, 22, 24, 29, 30, 33, 128, 129, 130, 131, 132, 133)
    buffers = {3: 64, 13: 16, 19: 512, 22: 512, 30: 4, 33: 16, 129: 8}
    for fid in prohibited:
        size = buffers.get(fid, 0)
        set_size = 0 if fid in (13, 33) else size
        add(f'set-prohibited-{fid:02x}', 9, cdw10=fid, dlen=set_size,
            data=bytes(set_size))
        add(f'get-optional-{fid:02x}', 10, cdw10=fid, dlen=size)
    for fid in (2, 0x19, 0x1c, 0xc0):
        add(f'set-optional-{fid:02x}', 9, cdw10=fid)
    for lid in (0x1d, 0x1e, 0x1f, 0x20, 0xc0):
        add(f'lid-{lid:02x}', 2, cdw10=lid, dlen=4)
    # All seven O/P opcodes stay silent for the unknown/default Storage class.
    for opcode, cdw10, cdw11, dlen, data in (
            (0x0d, 1, 0, 0, b''), (0x15, 0, 0, 4096, bytes(4096)),
            (0x20, 0, 0, 0, b''), (0x80, 0, 0, 0, b''),
            (0x81, 0xee000000, 4, 4, b'abcd'),
            (0x82, 0xee000000, 4, 4, b''), (0x86, 0, 0, 4, b'')):
        add(f'opcode-optional-{opcode:02x}', opcode, cdw10=cdw10,
            cdw11=cdw11, dlen=dlen, data=data)
    for opcode in (0, 0x1d, 0x7f, 3, 0x7e, 0xbf, 0xc0, 0xff):
        add(f'opcode-{opcode:02x}', opcode)
    # Figure 447's no-buffer personality and a Security control.
    add('get-personality-manufacturing-default', 10, cdw10=0x22)
    add('get-personality-security', 10, cdw10=0x22, cdw13=1,
        dlen=8, response=bytes(8))
    # Base 2.3 Figures 442/423/426/446, MI 2.2 Figure 139: one legal
    # final dword plus representative offset-boundary and overrun failures.
    add('get-label-last-dword', 10, cdw10=0x1f, off=252, dlen=4,
        response=bytes(4))
    add('get-label-offset-end', 10, cdw10=0x1f, off=256, dlen=4)
    add('get-plmc-overrun', 10, cdw10=0x13, off=508, dlen=8)
    add('get-host-behavior-offset-end', 10, cdw10=0x16, off=512, dlen=4)
    add('get-controller-queue-overrun', 10, cdw10=0x21, off=508, dlen=8)
    return cases


def build_shared_decode_pcapng(output_path):
    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                         'gen-nvme-tcp-test-capture.py'))
    packets = []
    frame = 0
    for common, cases in ((True, tcpgen['shared_common_cases']()), (False, shared_admin_cases())):
        for case in cases:
            # A sliced response intentionally cannot retire a command slot.
            # Keep each pair on its own endpoint, isolating that state effect.
            endpoint = 0x30 + frame // 2
            req = admin_request_payload(
                case['opcode'], flags=0, cns=case['cdw10'],
                cdw11=case['cdw11'], dlen=case['dlen'], doff=case['off'])
            if not common:
                req = bytearray(req)
                struct.pack_into('<I', req, 52, case['cdw13'])
                req = bytes(req)
                req += case['data']
            resp = admin_resp_with_data(
                case['data'] if common else case['response'])
            for request, body in ((True, req), (False, resp)):
                packet = make_packet(request, 2, 0, body, bmc_eid=endpoint)
                original = len(packet)
                if not request and case.get('cut'):
                    # Slice inside data, omitting its last bytes AND the MIC.
                    packet = packet[:-case['cut'] - 4]
                frame += 1
                packets.append((packet, original))
            print(f"MI {frame-1:3}/{frame:3} {case['name']}")
    write_pcapng(output_path, packets, 1730000000001000, idb(name='m5-shared'), 1000)


# ---------------------------------------------------------------------------
# Merged captures: several builders' output, one pcapng section each
# ---------------------------------------------------------------------------
#
# A merged capture appends each builder's file as a section of its own, so no
# MCTP assembly, Command Slot or endpoint state crosses from one builder's
# frames to the next; each builder's frame map numbers its frames from 1.

def section_bytes(builder):
    """The bytes builder(path) writes."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'section.pcapng')
        with contextlib.redirect_stdout(io.StringIO()):
            builder(path)
        with open(path, 'rb') as f:
            return f.read()


def with_host_ports(builder, ports):
    """`builder`, with the TCP host ports in `ports` moved: pcapng sections do
    not separate TCP conversations, so two sections' NVMe/TCP frames on the
    same 5-tuple would share NVMe/TCP queue state (see with_host_ports() in
    gen-nvme-tcp-test-capture.py)."""
    import runpy
    tcpgen = runpy.run_path(os.path.join(os.path.dirname(__file__),
                                         'gen-nvme-tcp-test-capture.py'))

    def build(path):
        data = tcpgen['with_host_ports'](section_bytes(builder), ports)
        with open(path, 'wb') as f:
            f.write(data)
    return build


def build_merged(output_path, *builders):
    with open(output_path, 'wb') as f:
        f.write(b''.join(section_bytes(builder) for builder in builders))
    print(f"Written {len(builders)} sections to {output_path}")


TCG_SEMANTICS_EID = 0xE0  # one fresh endpoint per case: E0h onward


def tcg_method_semantics_vectors():
    """Method parameter names (Core 2.01 3.2.4.1 and the signatures of 5.2.3,
    5.3.3; Opal SSC 2.30 5.1.3), UIDs resolved only where the signature makes
    a parameter a uidref (Appendix 1 Tables 239-248, Opal 4.2/4.3), printable
    byte-sequence Names, and the Start/End Transaction status (Tables 15/16).
    Each case is a Security Send or Receive and its response on an endpoint
    of its own.  Return ((packet, original length) list, {case: (request
    frame, response frame)})."""
    packets, cases = [], {}

    def u(v):
        if v < 0x40:
            return tcg_tiny_uint(v)
        width = max(1, (v.bit_length() + 7) // 8)
        return tcg_short_uint(v, width)

    def uid(v):
        return tcg_bytes_atom(v.to_bytes(8, 'big'))

    def opt(number, value):
        return b'\xf2' + u(number) + value + b'\xf3'

    def call(invoking, method, *params):
        return (b'\xf8' + uid(invoking) + uid(method) + b'\xf0' + b''.join(params)
                + b'\xf1' + TCG_EOD_STATUS_SUCCESS)

    def pair(name, tokens, send=True, tsn=0x1001, hsn=0x55):
        tag, eid = len(cases) % 8, TCG_SEMANTICS_EID + len(cases)
        assert eid <= 0xEF and name not in cases
        data = tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn), 0x1000)
        response = admin_resp_with_data(b'') if send else admin_resp_with_data(data)
        cases[name] = (len(packets) + 1, len(packets) + 2)
        packets.extend((mi_admin_frame(True, mi_security_request(send, 1, 0x1000, data),
                                       eid, tag),
                        mi_admin_frame(False, response, eid, tag)))

    smuid, this_sp, admin_sp = 0xFF, 0x1, 0x0000020500000001
    get, set_, next_ = 0x0000000600000016, 0x0000000600000017, 0x0000000600000008
    admin_sp_bytes = admin_sp.to_bytes(8, 'big')

    # Session Manager: required, UID-typed and optional names (5.2.3.1).
    pair('start-session', call(smuid, 0xFF02, u(0x55), uid(admin_sp), u(1),
                               opt(1, uid(0x0000000900000006)),
                               opt(3, uid(0x0000000900010001)),
                               opt(5, u(30000))), tsn=0, hsn=0)
    # A Name that is not a uinteger does not move the next option's meaning.
    pair('bad-option-name', call(smuid, 0xFF02, u(0x56), uid(admin_sp), u(0),
                                 b'\xf2' + tcg_bytes_atom(b'xx') + u(1) + b'\xf3',
                                 opt(6, u(9000))), tsn=0, hsn=0)
    pair('locking-next', call(0x0000080200000000, next_,
                              opt(0, uid(0x0000080200030001)), opt(1, u(4))))
    # Cellblock names 1, 3 and 4 (5.1.4.2.3); 7 is not defined.
    pair('get-cellblock', call(0x0000000B00000000, get,
                               b'\xf0' + opt(1, uid(0x0000000B00030002)) + opt(3, u(3))
                               + opt(4, u(3)) + opt(7, u(0)) + b'\xf1'))
    # Proof holds the bytes of a UID but is not a uidref.
    pair('authenticate', call(this_sp, 0x000000060000001C, uid(0x0000000900000201),
                              opt(0, tcg_bytes_atom(admin_sp_bytes))))
    # Column values are not named or resolved, even with UID-sized bytes.
    pair('set-values', call(0x0000000B00000001, set_,
                            opt(1, b'\xf0' + opt(3, tcg_bytes_atom(admin_sp_bytes))
                                + b'\xf1')))
    pair('unknown-method', call(this_sp, 0x00000006000000AA, u(5),
                                tcg_bytes_atom(admin_sp_bytes), opt(2, u(1))))
    # Opal 5.1.3.2: KeepGlobalRangeKey is optional parameter 0x060000.
    pair('revert-sp', call(this_sp, 0x0000000600000011, opt(0x060000, u(1))))
    # A Feature Set option (SUM's SingleUserSelectionList) stays numbered.
    pair('activate-sum', call(0x0000020500000002, 0x0000000600000203,
                              opt(0x060000, b'\xf0' + uid(0x0000080200030001) + b'\xf1')))
    pair('delete-row', call(0x0000000900000000, 0x0000000600000005,
                            b'\xf0' + uid(0x0000000900030003) + uid(0x0000000900ABCDEF)
                            + b'\xf1'))
    pair('add-ace', call(0x0000000700000000, 0x000000060000000E,
                         uid(0x0000080200030002), uid(set_), uid(0x000000080003E002)))
    pair('genkey-range', call(0x0000080600030003, 0x0000000600000010, opt(1, u(32))))
    pair('descriptor-get', call(0x0000000100000802, get, b'\xf0\xf1'))
    # Core 3.2.2.3.3.4/5: the TPer mirrors the transaction tokens with the
    # actual status; End Transaction 1 means the SP aborted.
    pair('txn-host', b'\xfb' + u(0) + call(0x0000080200000001, get, b'\xf0\xf1')
         + b'\xfc' + u(0))
    pair('txn-tper-abort', b'\xfb' + u(0) + b'\xf0\xf1' + TCG_EOD_STATUS_SUCCESS
         + b'\xfc' + u(1), send=False)
    pair('txn-bad-status', b'\xfb' + tcg_bytes_atom(b'\x00') + b'\xfc' + u(0x7F),
         send=False)
    return packets, cases


def build_tcg_method_semantics_pcapng(output_path):
    packets, _ = tcg_method_semantics_vectors()
    write_pcapng(output_path, packets, 1726000000 * 1_000_000)


TCG_PAIRING_EID = 0xD0  # one endpoint per scenario: D0h onward


def tcg_method_pairing_vectors():
    """Regular-session responses paired with the calls they answer (Core
    3.2.4.2: every call gets a result list, End of Data and a status list,
    with no method header), and the results named from the method result
    signatures (Core 5.3.3, 5.4.3.1).  Each scenario is a run of Security
    Sends and Receives on an endpoint of its own.  Return ((packet, original
    length) list, {scenario: [frame, ...]})."""
    packets, cases = [], {}

    def u(v):
        if v < 0x40:
            return tcg_tiny_uint(v)
        return tcg_short_uint(v, max(1, (v.bit_length() + 7) // 8))

    def uid(v):
        return tcg_bytes_atom(v.to_bytes(8, 'big'))

    def opt(number, value):
        return b'\xf2' + u(number) + value + b'\xf3'

    def call(invoking, method, *params):
        return (b'\xf8' + uid(invoking) + uid(method) + b'\xf0' + b''.join(params)
                + b'\xf1' + TCG_EOD_STATUS_SUCCESS)

    def result(*values, status=0):
        return (b'\xf0' + b''.join(values) + b'\xf1\xf9\xf0' + u(status)
                + b'\x00\x00\xf1')

    def scenario(name, exchanges):
        eid = TCG_PAIRING_EID + len(cases)
        assert eid <= 0xDF and name not in cases
        cases[name] = []
        for tag, (send, tokens, tsn, hsn) in enumerate(exchanges):
            data = tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn), 0x1000)
            response = admin_resp_with_data(b'') if send else admin_resp_with_data(data)
            cases[name].append(len(packets) + 1 + (0 if send else 1))
            packets.extend((mi_admin_frame(True, mi_security_request(send, 1, 0x1000, data),
                                           eid, tag % 8),
                            mi_admin_frame(False, response, eid, tag % 8)))

    this_sp, get = 0x1, 0x0000000600000016
    gr, r1 = 0x0000080200000001, 0x0000080200030001
    a, b = (0x2001, 0x61), (0x2002, 0x62)

    # Get with RowValues (Core 5.3.3.6): ReadLockEnabled, WriteLockEnabled.
    scenario('get', [
        (True, call(gr, get, b'\xf0' + opt(3, u(5)) + opt(4, u(6)) + b'\xf1'), *a),
        (False, result(b'\xf0' + opt(5, u(1)) + opt(6, u(0)) + b'\xf1'), *a)])
    # One Send with three calls; one Receive answers them in order.
    scenario('multiple', [
        (True, call(0x0000080200000000, 0x0000000600000008, opt(1, u(2)))
         + call(this_sp, 0x000000060000001C, uid(0x0000000900010001))
         + call(0x0000000700000000, 0x000000060000000D, uid(r1), uid(get)), *a),
        (False, result(b'\xf0' + uid(gr) + uid(r1) + b'\xf1')
         + result(u(1))
         + result(b'\xf0' + uid(0x000000080003D001) + uid(0x0000000800000001) + b'\xf1'), *a)])
    # Two sessions on one ComID keep separate queues.
    scenario('interleaved', [
        (True, call(0x0000000B00008402, get, b'\xf0' + opt(3, u(3)) + opt(4, u(3))
                    + b'\xf1'), *a),
        (True, call(this_sp, 0x0000000600000601, u(8)), *b),
        (False, result(tcg_bytes_atom(bytes(range(8)))), *b),
        (False, result(b'\xf0' + opt(3, tcg_bytes_atom(b'MSIDPIN')) + b'\xf1'), *a)])
    # Without the call in the capture, nothing is paired.
    scenario('unpaired', [(False, result(u(1)), *a)])
    scenario('unknown-method', [
        (True, call(this_sp, 0x00000006000000AA), *a),
        (False, result(u(1), u(2), status=0x0F), *a)])
    scenario('empty-result', [
        (True, call(0x0000000B00000001, 0x0000000600000017,
                    opt(1, b'\xf0' + opt(3, tcg_bytes_atom(b'pw')) + b'\xf1')), *a),
        (False, result(), *a)])
    scenario('free-space', [
        (True, call(this_sp, 0x0000000600000009), *a),
        (False, result(u(0x1000), b'\xf0\xf1'), *a)])
    # Session Manager calls in the control session carry their own method
    # header and are never queued (Core 5.2.3).
    scenario('control-session', [
        (True, call(0xFF, 0xFF02, u(0x63), uid(0x0000020500000001), u(0)), 0, 0),
        (False, call(0xFF, 0xFF03, u(0x63), u(0x2003)), 0, 0),
        (False, result(u(1)), 0x2003, 0x63)])
    return packets, cases


def build_tcg_method_pairing_pcapng(output_path):
    packets, _ = tcg_method_pairing_vectors()
    write_pcapng(output_path, packets, 1727000000 * 1_000_000)


def tcg_trusted_failure_vectors():
    """A StartTrustedSession that fails leaves nothing for a later
    SyncTrustedSession to answer.  Core 2.01 5.3.4.1.5: the TPer reports the
    failure as a SyncTrustedSession carrying only HostSessionID and
    SPSessionID, with a non-Success status.  A Security Send completed with an
    error is taken as never acted on: 3.3.10.2.1 item 3 describes the state
    after an IF-SEND completed without error.  Each scenario runs on its own
    endpoint and session, ComID 1000h:
      ok         the four startup methods succeed: the session is secure
      reply-fail the TPer answers StartTrustedSession with a failure
      send-fail  the Security Send carrying StartTrustedSession fails
    and the last two then see a stray successful SyncTrustedSession.
    Return ((packet, original length) list, {case: section frames})."""
    packets, cases, tags = [], {}, {}
    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID) + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0' + tcg_bytes_atom(TCG_ADMIN_SP) + b'\xf1' + TCG_EOD_STATUS_SUCCESS)
    cqe_error = admin_response_payload(STATUS_SUCCESS, cqe3=admin_cqe3(
        cqe_status_word(sc=0x0c, dnr=1, phase=1)))

    def pair(name, eid, send, data, response=None):
        tag = tags.get(eid, 0)
        tags[eid] = (tag + 1) % 8
        if response is None:
            response = admin_resp_with_data(b'' if send else data)
        n = len(packets) + 1
        cases[name] = (n, n + 1)
        packets.extend((mi_admin_frame(True, mi_security_request(send, 1, 0x1000, data),
                                       eid, tag),
                        mi_admin_frame(False, response, eid, tag)))

    def cp(tokens, tsn=0, hsn=0):
        return tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn, 0), 0x1000)

    def failed_sync(hsn, tsn):
        """SyncTrustedSession[HostSessionID, SPSessionID], status
        NOT_AUTHORIZED (01h, Core 5.1.5.2)."""
        return (b'\xf8' + tcg_bytes_atom(TCG_SMUID)
                + tcg_bytes_atom((0xff05).to_bytes(8, 'big')) + b'\xf0'
                + tcg_tiny_uint(hsn) + tcg_short_uint(tsn, 4) + b'\xf1'
                + bytes([0xF9, 0xF0, 0x01, 0x00, 0x00, 0xF1]))

    for i, name in enumerate(('ok', 'reply-fail', 'send-fail')):
        eid, hsn, tsn = TCG_T34_EID + 0x40 + i, 2 + i, 0x6202 + i
        pair(name + '-ff02', eid, True, cp(tcg_startup(0xff02, hsn, tsn)))
        pair(name + '-ff03', eid, False, cp(tcg_startup(0xff03, hsn, tsn)))
        pair(name + '-ff04', eid, True, cp(tcg_startup(0xff04, hsn, tsn)),
             response=cqe_error if name == 'send-fail' else None)
        if name == 'reply-fail':
            pair(name + '-failed', eid, False, cp(failed_sync(hsn, tsn)))
        pair(name + '-ff05', eid, False, cp(tcg_startup(0xff05, hsn, tsn)))
        pair(name + '-payload', eid, False, cp(call, tsn, hsn))
    return packets, cases


def build_tcg_trusted_failure_pcapng(output_path):
    packets, _ = tcg_trusted_failure_vectors()
    write_pcapng(output_path, packets, 1728000000 * 1_000_000)


def tcg_level0_versions_vectors():
    """Level 0 Discovery descriptor versions that the SSCs and feature sets
    define besides Opal SSC 2.30, over MI Security Receive: Locking Version 2
    (Pyrite SSC 2.01 Table 5, Ruby SSC 1.00 Table 5) and Supported Data
    Removal Mechanism Version 1 (Pyrite SSC 2.01 Table 7, Key Per I/O SSC 1.00
    Table 6), Opal SSC V2 Version 1 (Opal SSC 2.01 Table 7), the Namespace
    Geometry Reporting Length (CNL 1.00 Table 10), Block SID Authentication
    Version 2 (Block SID 1.01 Table 2), the Feature Set Minor Version Number
    (ADT 1.01 Table 3, Configurable Locking 1.30 Table 7), versions no
    specification defines and feature codes that are only named.
    Return ((interface, packet) list, {case: (request frame, response frame)})."""
    packets, cases = [], {}

    def pair(name, features):
        frame = len(packets) + 1
        cases[name] = (frame, frame + 1)
        payload = struct.pack('>IHH', 44 + len(features), 0, 1) + bytes(40) + features
        tag = (frame // 2) % 8
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1, flags=0,
            cns=security_cdw10(1, 1), cdw11=len(payload), dlen=len(payload))
        packets.extend(((0, make_packet(True, NVME_MI_TYPE_ADMIN, 0, request, tag=tag)),
                        (0, make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                        admin_resp_with_data(payload), tag=tag))))

    # Supported | Enabled | Locked | MBR Shadowing Not Supported; bit 7 Reserved.
    pair('locking-v2', tcg_l0_feature(2, 2, b'\x47' + bytes(11)))
    # Supported Data Removal Mechanism Version 1 (Pyrite SSC 2.01 Tables 7/8,
    # Key Per I/O SSC 1.00 Tables 6/7): data byte 1 Processing | Interrupted
    # (bit 1 is Interrupted in Key Per I/O Table 6 only; Pyrite 2.01 Table 7
    # marks byte 5 bits 7:1 Reserved); mechanisms Overwrite, Block Erase, Unmap (bit 3) and Reset Write
    # Pointers (bit 4); the bit 3 time in minutes; one time per mechanism bit
    # 0-5; 16 Reserved bytes to Length 0x20.
    drm_v1 = (bytes([0x00, 0x03, 0x1b, 0x08])
              + struct.pack('>6H', 10, 20, 0, 30, 40, 0) + bytes(16))
    pair('drm-v1', tcg_l0_feature(0x0404, 1, drm_v1))
    pair('drm-v1-len16', tcg_l0_feature(0x0404, 1, drm_v1[:16]))
    # No specification defines a Version 0.
    pair('drm-v0', tcg_l0_feature(0x0404, 0, drm_v1))
    # Opal SSC V2 Version 1 (Opal SSC 2.00/2.01 Table 7): the Opal 2.30 body,
    # Length 0x10, but byte 2 bits 3:0 are Reserved (set here to 1).
    opal2_v1 = struct.pack('>HHBHHBB', 0x1000, 1, 0, 4, 8, 0, 0) + bytes(5)
    pair('opal2-v1', tcg_l0_feature(0x0203, 1, opal2_v1, minor=1))
    pair('opal2-v1-len12', tcg_l0_feature(0x0203, 1, opal2_v1[:12]))
    # Namespace Geometry Reporting Version 1 (CNL 1.00 Table 10) declaring
    # Length 12 instead of 0x1C.
    pair('ns-geometry-len12', tcg_l0_feature(0x0405, 1, b'\xa5' * 12))
    # Block SID Authentication data byte 0 bits 3:0 set: Version 2 (Block SID
    # 1.01 Table 2) names bit 2 Locking SP Freeze Lock supported and bit 3
    # Locking SP Freeze Lock State; Version 1 (1.00 Table 1) Reserves them.
    for version in (2, 1):
        pair(f'block-sid-v{version}', tcg_l0_feature(0x0402, version, b'\x0f\x01' + bytes(10)))
    # Byte 2 bits 3:0 = 1: the Feature Set Minor Version Number in Version 2
    # of Additional DataStore Tables (ADT 1.01 Tables 2/3) and Configurable
    # Namespace Locking (Configurable Locking 1.30 Tables 6/7), Reserved in
    # CNL 1.00 Table 6 (Version 1).
    adt = struct.pack('>HHII', 0, 9, 0x00A00000, 512)
    cnl = b'\xe0' + bytes(3) + struct.pack('>III', 64, 60, 8)
    for version in (2, 1):
        pair(f'datastore-v{version}-minor1', tcg_l0_feature(0x0202, version, adt, minor=1))
        pair(f'cnl-v{version}-minor1', tcg_l0_feature(0x0403, version, cnl, minor=1))
    # Versions no specification defines: Ruby 2 (Ruby SSC 1.00 Table 7 is
    # Version 1), Block SID 3 (1.01 Table 2 is Version 2), Namespace Geometry
    # 2 (CNL 1.00 Table 10 is Version 1).
    pair('ruby-v2', tcg_l0_feature(0x0304, 2, opal2_v1))
    pair('block-sid-v3', tcg_l0_feature(0x0402, 3, b'\x0f\x01' + bytes(10)))
    pair('ns-geometry-v2', tcg_l0_feature(0x0405, 2,
                                          b'\x01' + bytes(7) + struct.pack('>IQQ', 512, 8, 0)))
    # Feature codes the feature sets define but this dissector only names:
    # each body is opaque filler, then a truly unknown code.
    named = (0x0305, 0x0401, 0x0407, 0x0409, 0x040A, 0x040B, 0x040C, 0x040D)
    pair('named-only', b''.join(tcg_l0_feature(code, 1, b'\xa5' * 4) for code in named)
         + tcg_l0_feature(0x7777, 1, b'\xa5' * 4))
    return packets, cases


def build_tcg_level0_versions_pcapng(output_path):
    packets, _ = tcg_level0_versions_vectors()
    write_pcapng(output_path, [(packet, None, interface) for interface, packet in packets],
                 1729000000 * 1_000_000, idb() + idb(link_type=1))


def tcg_level0_coverage_vectors():
    """One Level 0 Discovery per feature descriptor listed here, each laid out
    from its defining table (desc byte N is data byte N - 4): Enterprise SSC 1.01
    Table 07, Opal SSC 1.00 Table 6, Single User Mode 1.00 Table 7,
    Additional DataStore Tables 1.01 Table 2, Opalite SSC 1.00 Table 6, Pyrite
    SSC 1.00 / 2.01 Table 6, Block SID 1.00 Table 1 / 1.01 Table 2 and
    Configurable Locking 1.30 Table 6; then a Supported Data Removal Mechanism
    descriptor with a Length below its 4-byte head.
    Return ((interface, packet) list, {case: (request frame, response frame)})."""
    packets, cases = [], {}

    def pair(name, features):
        frame = len(packets) + 1
        cases[name] = (frame, frame + 1)
        payload = struct.pack('>IHH', 44 + len(features), 0, 1) + bytes(40) + features
        tag = (frame // 2) % 8
        request = admin_request_payload(
            NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1, flags=0,
            cns=security_cdw10(1, 1), cdw11=len(payload), dlen=len(payload))
        packets.extend(((0, make_packet(True, NVME_MI_TYPE_ADMIN, 0, request, tag=tag)),
                        (0, make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                        admin_resp_with_data(payload), tag=tag))))

    # Base ComID (desc 4-5), Number of ComIDs (6-7), desc 8 bit 0 Range
    # Crossing, desc 9-19 Reserved; Version 1, Length 0x10.
    pair('enterprise', tcg_l0_feature(0x0100, 1, struct.pack('>HHB', 0x07FE, 2, 0x01) + bytes(11)))
    pair('opal1', tcg_l0_feature(0x0200, 1, struct.pack('>HHB', 0x1000, 1, 0x01) + bytes(11)))
    # Number of Locking Objects Supported (desc 4-7); desc 8 bit 0 Any, bit 1
    # All, bit 2 Policy; desc 9-15 Reserved; Version 1, Length 0x0C.
    pair('sum', tcg_l0_feature(0x0201, 1, struct.pack('>IB', 9, 0x05) + bytes(7)))
    # Reserved (desc 4-5), Maximum number of DataStore tables (6-7), Maximum
    # total size (8-11), size alignment (12-15); Version 2, minor 1 = v1.01.
    pair('datastore', tcg_l0_feature(0x0202, 2, struct.pack('>HHII', 0, 9, 0x00A00000, 512),
                                     minor=1))
    # Base ComID, Number of ComIDs, desc 8-12 Reserved, desc 13 Initial
    # C_PIN_SID PIN Indicator, desc 14 Behavior upon TPer Revert (0x00 only),
    # desc 15-19 Reserved; Version 1, Length 0x10.
    lite = struct.pack('>HH', 0x0800, 1) + bytes(5) + b'\x00\x00' + bytes(5)
    for name, code in (('opalite', 0x0301), ('pyrite1', 0x0302), ('pyrite2', 0x0303)):
        pair(name, tcg_l0_feature(code, 1, lite))
    # desc 4 bit 0 SID Value State, bit 1 SID Authentication Blocked State,
    # (Version 2) bit 2 Locking SP Freeze Lock supported, bit 3 Locking SP
    # Freeze Lock State, set only where the capability is supported (Block
    # SID 1.01 4.2.2); desc 5 bit 0 Hardware Reset; desc 6-15 Reserved;
    # Length 0x0C.
    pair('block-sid-v1', tcg_l0_feature(0x0402, 1, b'\x03\x01' + bytes(10)))
    pair('block-sid-v2', tcg_l0_feature(0x0402, 2, b'\x0f\x00' + bytes(10)))
    # desc 4 bit 7 Range_C, bit 6 Range_P, bit 5 SUM_C; desc 5-7 Reserved;
    # Maximum Key Count (8-11), Unused Key Count (12-15), Maximum Ranges Per
    # Namespace (16-19); Version 2, minor 3 = v1.30, Length 0x10.
    pair('cnl', tcg_l0_feature(0x0403, 2, b'\xe0' + bytes(3) + struct.pack('>III', 64, 60, 8),
                               minor=3))
    # Supported Data Removal Mechanism Version 1 declaring Length 0, not
    # 0x20 (Pyrite SSC 2.01 Table 7), inside a complete response.
    pair('drm-v1-len0', tcg_l0_feature(0x0404, 1, b''))
    return packets, cases


def build_tcg_level0_coverage_pcapng(output_path):
    packets, _ = tcg_level0_coverage_vectors()
    write_pcapng(output_path, [(packet, None, interface) for interface, packet in packets],
                 1732000000 * 1_000_000, idb() + idb(link_type=1))


def tcg_trusted_race_vectors():
    """Two IF-SENDs carrying StartTrustedSession for one session, ComID
    1000h, one per NVMe-MI Command Slot (CSI 0 and 1), both outstanding when
    the first completes with an error.  Core 2.01 3.3.10.2.1 item 3 refuses a
    second IF-SEND only after one completed without error, so the second can
    be in flight.  The second completes without error and its successful
    SyncTrustedSession follows: the first failure must not end the second
    request, so the session's data is secure.
    Return ((packet, original length) list, {case: section frames})."""
    packets, cases = [], {}
    eid, hsn, tsn = 0x80, 5, 0x6205     # an endpoint no earlier section uses
    call = (b'\xf8' + tcg_bytes_atom(TCG_SMUID) + tcg_bytes_atom(TCG_SYNTHETIC_METHOD)
            + b'\xf0' + tcg_bytes_atom(TCG_ADMIN_SP) + b'\xf1' + TCG_EOD_STATUS_SUCCESS)
    cqe_error = admin_response_payload(STATUS_SUCCESS, cqe3=admin_cqe3(
        cqe_status_word(sc=0x0c, dnr=1, phase=1)))

    def cp(tokens, tsn=0, hsn=0):
        return tcg_compacket(tcg_packet(tcg_subpacket(tokens), tsn, hsn, 0), 0x1000)

    def frame(is_request, csi, tag, body):
        packet = make_packet(is_request, NVME_MI_TYPE_ADMIN, csi, body, bmc_eid=eid, tag=tag)
        packets.append((packet, len(packet)))
        return len(packets)

    def pair(name, send, data, csi=0, tag=0):
        cases[name] = (frame(True, csi, tag, mi_security_request(send, 1, 0x1000, data)),
                       frame(False, csi, tag, admin_resp_with_data(b'' if send else data)))

    pair('ff02', True, cp(tcg_startup(0xff02, hsn, tsn)))
    pair('ff03', False, cp(tcg_startup(0xff03, hsn, tsn)))
    first = frame(True, 0, 1, mi_security_request(True, 1, 0x1000,
                                                    cp(tcg_startup(0xff04, hsn, tsn))))
    second = frame(True, 1, 2, mi_security_request(True, 1, 0x1000,
                                                     cp(tcg_startup(0xff04, hsn, tsn))))
    cases['first-ff04'] = (first, frame(False, 0, 1, cqe_error))
    cases['second-ff04'] = (second, frame(False, 1, 2, admin_resp_with_data(b'')))
    pair('ff05', False, cp(tcg_startup(0xff05, hsn, tsn)))
    pair('payload', False, cp(call, tsn, hsn))
    return packets, cases


def build_tcg_trusted_race_pcapng(output_path):
    packets, _ = tcg_trusted_race_vectors()
    write_pcapng(output_path, packets, 1733000000 * 1_000_000)


def tcg_sections():
    """The section builders of nvme-mi-tcg.pcapng, in order.  The NVMe/TCP twins
    of tcg_conformance_vectors() move to host port 55100, as the first section
    already uses 55000."""
    return (build_tcg_m5_validation_pcapng,
            with_host_ports(build_tcg_conformance_pcapng, {55000: 55100}),
            build_tcg_corrective_pcapng, build_tcg_final_corrective_pcapng,
            build_tcg_properties_extensions_pcapng,
            build_tcg_enclosing_completeness_pcapng,
            build_tcg_continuation_domains_pcapng,
            build_tcg_synchronous_atom_pcapng,
            build_tcg_level0_prefix_pcapng,
            build_tcg_integrity_note_pcapng,
            build_tcg_reset_lifecycle_pcapng,
            build_tcg_level0_opal230_pcapng,
            build_tcg_method_semantics_pcapng,
            build_tcg_method_pairing_pcapng,
            build_tcg_trusted_failure_pcapng,
            build_tcg_level0_versions_pcapng,
            build_tcg_level0_coverage_pcapng,
            build_tcg_trusted_race_pcapng)


# ---------------------------------------------------------------------------
# nvme-mi-spec-revisions.pcapng - values NVMe-MI 2.2, NVMe Base 2.4 and the
# NVM Command Set 1.3 assigned or renamed.  Every exchange is on an EID of its
# own, so no request supersedes another.
#
#   F1-F6    MI opcodes 0Dh-0Fh (PDA Read / Write / Write Zeroes), MI 2.2 Fig 68
#   F7       MI opcode 10h, now the first Reserved opcode (unanswered)
#   F8       AEM carrying AE 0Fh (Voltage Threshold Event), MI 2.2 Fig 63
#   F9-F10   VPD Read, NVMe MultiRecord FF 5Ch (E2 9.5 mm), MI 2.2 Fig 183
#   F11-F12  NSHSP with CCF, NSHDS CCSF (MI 2.2 Figs 95/105)
#   F13-F14  CHSP with CCF|CSC, CHDS with obsolete CS bit 8 and CHSCF (Fig 97)
#   F15-F16  Read DS NVM Subsystem Information, MJR 2 / MNR 2 (Fig 115)
#   F17-F18  Read DS Port Information, PRTCAP bit 0 obsolete (Fig 117)
#   F19-F20  Admin 2Ah Manage Exported NVM Subsystem Receive (Base 2.4 Fig 143)
#   F21-F28  Admin 2Dh Manage Exported NVM Subsystem Send answered with
#            SCT 1h SC 42h, 43h, 44h and Reserved 45h (Fig 104)
#   F29-F34  Get Log Page LID 24h, 27h, 28h (Base 2.4 Fig 209, NVM CS 1.3)
#   F35-F40  Set Features FID 26h, 27h, 28h; answered with SCT 0h SC 2Dh,
#            Reserved 2Eh and Success (Figs 103/385)
#   F41-F46  Configurable Device Personality PERID 03h, C5h (Set) and FFh
#            (Get, completion DW0 PERID 02h), Base 2.4 Fig 512
#   F47-F48  Get Log Page CSI 30h, Base 2.4 Fig 326 Vendor Specific range
#   F49-F50  Error Information CSI byte 30 = 30h
#   F51-F52  Identify Controller ICSVSCC / SNVSCF
#   F53-F54  Primary Controller Capabilities CRT byte and reserved bytes
#   F55-F58  Get Features FIDs 7Ah (Reserved for Management Features), 78h
#   F59-F60  Namespace Attachment opcode display
#   F61-F62  Invalid Command Opcode status name
#   F63-F64  NSHDS CTEMP 80h (more than 5 seconds old)
#   F65-F66  2-Wire MVPDFREQ 04h (Reserved)
#   F67-F68  Command and Feature Lockdown scope 3h (NVMe-MI opcodes)
# ---------------------------------------------------------------------------

def build_spec_revisions_pcapng(output_path):
    packets = []
    eid = [0x40]

    def pair(kind, request, response=None):
        bmc = eid[0]
        eid[0] += 1
        packets.append(make_packet(True, kind, 0, request, bmc_eid=bmc))
        if response is not None:
            packets.append(make_packet(False, kind, 0, response, bmc_eid=bmc))

    def admin_status(sct, sc):
        return admin_response_payload(
            STATUS_SUCCESS, cqe3=admin_cqe3(cqe_status_word(sct=sct, sc=sc, phase=1)))

    for opcode in (0x0D, 0x0E, 0x0F):
        pair(NVME_MI_TYPE_MI, mi_request_payload(opcode),
             mi_response_payload(STATUS_SUCCESS))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x10))

    packets.append(aem_packet(aeo_list([aeo_entry(
        0x0F, AEO_SCOPE_CONTROLLER, 1,
        specific=struct.pack('<I', (240 << 18) | (1 << 14) | 11000))])))

    nvme = bytearray(32)
    nvme[1] = 0x5C
    header = bytes([1, 0, 0, 0, 0, 1, 0])
    rec_hdr = bytes([0x0b, 0x82, len(nvme), -sum(nvme) & 0xff])
    image = (header + bytes([-sum(header) & 0xff])
             + rec_hdr + bytes([-sum(rec_hdr) & 0xff]) + bytes(nvme))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x05, cdw0=0, cdw1=len(image)),
         mi_response_payload_with_data(STATUS_SUCCESS, image))

    pair(NVME_MI_TYPE_MI, mi_request_payload(0x01, cdw1=0x80000000),
         mi_response_payload_with_data(STATUS_SUCCESS, nshds()))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x02, cdw1=0x80000001),
         mi_response_payload_with_data(
             STATUS_SUCCESS, chds(1, 0x0101, 0x0136, 3, 100, 0x00, 0x2101),
             nmresp=0x010000))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x00, cdw0=0x00000000),
         mi_response_payload_with_data(STATUS_SUCCESS, subsys_info(mjr=2, mnr=2),
                                       nmresp=32))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x00, cdw0=0x01000000),
         mi_response_payload_with_data(STATUS_SUCCESS, port_info_pcie(), nmresp=32))

    pair(NVME_MI_TYPE_ADMIN, admin_request_payload(0x2A, flags=0, dlen=0),
         admin_status(0, 0))
    for sc in (0x42, 0x43, 0x44, 0x45):
        pair(NVME_MI_TYPE_ADMIN, admin_request_payload(0x2D, flags=0, dlen=0),
             admin_status(1, sc))

    for lid in (0x24, 0x27, 0x28):
        pair(NVME_MI_TYPE_ADMIN, admin_request_payload(0x02, cns=lid, dlen=4),
             admin_resp_with_data(b'\0' * 4))

    for fid, sc in ((0x26, 0x2D), (0x27, 0x2E), (0x28, 0x00)):
        pair(NVME_MI_TYPE_ADMIN, admin_request_payload(0x09, cns=fid, flags=0, dlen=0),
             admin_status(0, sc))

    for perid in (0x03, 0xC5):
        pair(NVME_MI_TYPE_ADMIN,
             admin_request_payload(0x09, cns=0x22, flags=0, dlen=0, lpo=perid << 32),
             admin_status(0, 0))
    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x0A, cns=0x22, flags=0, dlen=0, lpo=0xFF << 32),
         admin_response_payload(STATUS_SUCCESS, cqe1=0x02,
                                cqe3=admin_cqe3(cqe_status_word(phase=1))))

    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x02, cns=0x01, flags=0, dlen=0,
                               cdw14=0x30000000),
         admin_status(0, 0))

    error_info = bytearray(64)
    error_info[30] = 0x30
    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x02, cns=0x01, dlen=len(error_info)),
         admin_resp_with_data(error_info))

    identify_ctrl = bytearray(4096)
    identify_ctrl[530] = 0x01
    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x06, cns=0x01, dlen=len(identify_ctrl)),
         admin_resp_with_data(identify_ctrl))

    primary_ctrl = bytearray(4096)
    primary_ctrl[4] = 0x03
    primary_ctrl[5:32] = bytes(range(1, 28))
    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x06, cns=0x14, dlen=len(primary_ctrl)),
         admin_resp_with_data(primary_ctrl))

    for fid in (0x7a, 0x78):
        pair(NVME_MI_TYPE_ADMIN,
             admin_request_payload(0x0A, cns=fid, flags=0, dlen=0),
             admin_status(0, 0))

    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x15, flags=0, dlen=0),
         admin_status(0, 0))
    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x80, flags=0, dlen=0),
         admin_status(0, 0x01))

    stale_nshds = bytearray(nshds())
    stale_nshds[2] = 0x80
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x01),
         mi_response_payload_with_data(STATUS_SUCCESS, stale_nshds))

    reserved_vpdfreq = bytearray(port_info_twire())
    reserved_vpdfreq[9] = 0x04
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x00, cdw0=0x01000000),
         mi_response_payload_with_data(STATUS_SUCCESS, reserved_vpdfreq,
                                       nmresp=len(reserved_vpdfreq)))

    lockdown = bytearray(512)
    lockdown[0] = 0x03
    lockdown[3] = 1
    lockdown[4] = 0x07
    pair(NVME_MI_TYPE_ADMIN,
         admin_request_payload(0x02, cns=0x14, dlen=len(lockdown)),
         admin_resp_with_data(lockdown))

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-spec-revisions'))


def _bmc_pair(packets, eid):
    """Return pair(kind, request, response), which appends a request and its
    response on BMC EID eid[0] and then advances eid[0]."""
    def pair(kind, request, response):
        bmc = eid[0]
        eid[0] += 1
        packets.append(make_packet(True, kind, 0, request, bmc_eid=bmc))
        packets.append(make_packet(False, kind, 0, response, bmc_eid=bmc))
    return pair


# ---------------------------------------------------------------------------
# nvme-mi-spec-revisions-fields.pcapng - bits and bytes NVMe Base 2.4, the
# NVM Command Set 1.3 and NVMe-MI 2.2 added to structures that earlier
# revisions already defined.  One EID per exchange.
#
#   F1-F2    Identify Controller: CHSI, RMDCA, MNENS/MNECPENS/MENSNN, ENSA,
#            ENDSFS, VSEN1/VSEN2, MSVMT and PSD MIIELL (Base 2.4 Fig 338/339)
#   F3-F4    I/O Command Set Identify Controller (CNS 06h, CSI 0): RLA, SLMC
#            (NVM CS 1.3 Fig 129)
#   F5-F6    Sanitize with PREQ (Fig 451)
#   F7-F8    Sanitize Namespace with PREQ (Fig 454)
#   F9-F10   Sanitize Status log SSTAT.PRGD (Fig 312)
#   F11-F12  Set Features AEC with RLCCN (Fig 409)
#   F13-F14  Set Features Power Management with IIELL (Fig 391)
#   F15-F16  Get Features Power Management, completion DW0 IIELL
#   F17-F18  Get Features Host ID, EXHID 0: 64-bit HOSTID + Reserved (Fig 538)
#   F19-F20  Get Features Host ID, EXHID 1: 128-bit HOSTID
#   F21-F22  Lockdown with CSEL and CSS (Figs 365/366)
#   F23-F24  Lockdown log, ELPF, NVM subsystem-wide, 3 x 4-byte descriptors
#   F25-F26  Lockdown log, ELPF, CFIDS 1 (smaller than a descriptor)
#   F27-F28  Lockdown log, ELPF, window that misses NCFID/CFIDS
#   F29-F30  FID Supported and Effects, FSP.RUHS (Fig 271)
#   F31-F32  2-Wire Port Information with PDAS and SDFORMAT (MI 2.2 Fig 119)
#   F33-F34  2-Wire Port Information with no PDA
# ---------------------------------------------------------------------------

def build_spec_revisions_fields_pcapng(output_path):
    packets = []
    eid = [0x40]

    pair = _bmc_pair(packets, eid)

    ok = admin_cqe3(cqe_status_word(phase=1))

    def admin(opcode, cdw10=0, cdw11=0, cdw14=0, data=None, dw0=0,
              doff=0, flags=None):
        n = len(data) if data is not None else 0
        if flags is None:
            flags = 0x01 if n else 0
        if opcode == 0x02:
            cdw10 |= ((doff + n) // 4 - 1) << 16    # NUMDL
        pair(NVME_MI_TYPE_ADMIN,
             admin_request_payload(opcode, cns=cdw10, cdw11=cdw11, cdw14=cdw14,
                                   flags=flags, doff=doff, dlen=n),
             admin_response_payload(STATUS_SUCCESS, cqe1=dw0, cqe3=ok)
             + (data or b''))

    idc = bytearray(4096)
    idc[103] = 0x01
    idc[362] = 0x05
    struct.pack_into('<HHIBB', idc, 396, 16, 4, 0x100, 0x03, 0x01)
    struct.pack_into('<II', idc, 406,
                     (3 << 24) | (10 << 16) | (2 << 14) | (1 << 12) | 240,
                     (1 << 14) | 66)
    struct.pack_into('<H', idc, 422, 30)
    struct.pack_into('<H', idc, 2048 + 30, 5)
    admin(0x06, cdw10=0x01, data=bytes(idc))

    nvm = bytearray(4096)
    nvm[25] = 0x03
    struct.pack_into('<H', nvm, 26, 3)
    admin(0x06, cdw10=0x06, data=bytes(nvm))

    admin(0x84, cdw10=0x802)
    admin(0x8C, cdw10=0x12)

    sanitize = bytearray(512)
    struct.pack_into('<H', sanitize, 2, 0x0801)
    admin(0x02, cdw10=0x81, data=bytes(sanitize))

    admin(0x09, cdw10=0x0B, cdw11=0x00400000)
    admin(0x09, cdw10=0x02, cdw11=(5 << 16) | 3)
    admin(0x0A, cdw10=0x02, dw0=(20 << 16) | 1)

    admin(0x0A, cdw10=0x81, data=bytes(range(0x30, 0x38)) + bytes(range(0xa0, 0xa8)))
    admin(0x0A, cdw10=0x81, cdw11=1, data=bytes(range(0x40, 0x50)))

    admin(0x24, cdw10=(1 << 16) | (0x06 << 8), cdw14=5 << 16)

    enh = bytearray(16)
    struct.pack_into('<BBHIHH', enh, 0, 1, 0x10, 0xFFFF, 28, 3, 4)
    enh += bytes([0x06, 0x01, 0, 0, 0x09, 0x00, 0xaa, 0xbb, 0x24, 0x01, 0, 0])
    admin(0x02, cdw10=0x14 | (0x40 << 8), cdw11=0xFFFF << 16, data=bytes(enh))

    short = bytearray(16)
    struct.pack_into('<BBHIHH', short, 0, 1, 0x02, 0x0001, 20, 2, 1)
    admin(0x02, cdw10=0x14 | (0x42 << 8), cdw11=1 << 16, data=bytes(short + b'\x0b\x00\x0c\x00'))

    admin(0x02, cdw10=0x14 | (0x40 << 8), data=bytes([0x06, 0x01, 0, 0] * 2),
          doff=16, flags=0x03)

    fids = struct.pack('<I', 0x08000001)
    admin(0x02, cdw10=0x12, data=fids)

    twire = bytearray(port_info_twire())
    struct.pack_into('<IB', twire, 13, 8, 0x0d)
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x00, cdw0=0x01000000),
         mi_response_payload_with_data(STATUS_SUCCESS, bytes(twire),
                                       nmresp=len(twire)))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x00, cdw0=0x01000000),
         mi_response_payload_with_data(STATUS_SUCCESS, port_info_twire(),
                                       nmresp=32))

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-spec-revisions-fields'))

# ---------------------------------------------------------------------------
# nvme-mi-voltage.pcapng -- Device Voltage Monitor (Base 2.4 8.1.32), the
# MI-reachable pieces: Set/Get Features FID 26h/27h, Get Log Page LID 27h
# and the NVMe-MI 2.2 Voltage Threshold Event AE (0Fh).
#
#   F1-F2    Set Features FID 26h: VSENS 2h, EVT, OVT 300, UVT 200 (Fig 525)
#   F3-F4    Get Features FID 26h selecting VSENS 2h; DW0 echoes Fig 525
#   F5-F6    Set Features FID 27h ACT 1h with the Fig 527 data structure
#            (VSSEL 1h, VMLT, SVMT 10 minutes, LUVT 180, LOVT 330)
#   F7-F8    Get Features FID 27h ACT 1h; DW0 ACT 1h, first 16 data bytes
#   F9-F10   Set Features FID 27h ACT 2h (Clear OVV and UVV), no data
#   F11-F12  Get Log Page LID 27h: NVMDS 4, NVMDE 2, VLVSS 4 (Figs 307/308)
#   F13-F14  Get Log Page LID 27h with NVMDE 2 > NVMDS 1 (expert)
#   F15      AEM, AE 0Fh with a 4-byte VTEI (MI 2.2 Figure 65)
#   F16      AEM, AE 0Fh with a 1-byte AEOSIL (expert)
# ---------------------------------------------------------------------------

def build_voltage_pcapng(output_path):
    packets = []
    eid = [0x40]

    pair = _bmc_pair(packets, eid)

    ok = admin_cqe3(cqe_status_word(phase=1))

    def admin(opcode, cdw10=0, cdw11=0, data=None, dw0=0, req_data=None):
        n = len(data) if data is not None else 0
        rn = len(req_data) if req_data is not None else 0
        if opcode == 0x02:
            cdw10 |= (n // 4 - 1) << 16    # NUMDL
        pair(NVME_MI_TYPE_ADMIN,
             admin_request_payload(opcode, cns=cdw10, cdw11=cdw11,
                                   flags=0x01 if (n or rn) else 0,
                                   dlen=n or rn) + (req_data or b''),
             admin_response_payload(STATUS_SUCCESS, cqe1=dw0, cqe3=ok)
             + (data or b''))

    vt = (2 << 29) | (1 << 28) | (300 << 14) | 200
    admin(0x09, cdw10=0x26, cdw11=vt)
    admin(0x0A, cdw10=0x26, cdw11=2 << 29, dw0=vt)

    svm = bytearray(4096)
    struct.pack_into('<HHI', svm, 0, 0x0005, 10, (330 << 16) | 180)
    admin(0x09, cdw10=0x27, cdw11=1, req_data=bytes(svm))
    admin(0x0A, cdw10=0x27, cdw11=1, dw0=1, data=bytes(svm[:16]))
    admin(0x09, cdw10=0x27, cdw11=2)

    def vlog(nvmds, nvmde, vlvss, descs, vs=b''):
        log = bytearray(64)
        log[0] = 3
        log[1] = 0x01 | 0x02 | (1 << 2) | 0x10
        struct.pack_into('<H', log, 2, (1 << 14) | (1 << 12) | 240)
        struct.pack_into('<IHHH', log, 4, 64 + 2 * nvmde + vlvss, nvmds, nvmde, 7)
        struct.pack_into("<Q", log, 14, (0x1 << 49) | (1 << 48) | 1000)
        struct.pack_into('<HH', log, 22, 1, vlvss)
        struct.pack_into('<HHH', log, 32, (1 << 14) | 12600, 3, 12500)
        struct.pack_into('<Q', log, 38, 2000)
        log[46] = 2
        struct.pack_into('<HHH', log, 47, (1 << 14) | 11400, 5, 11500)
        struct.pack_into('<Q', log, 53, 3000)
        log[61] = 255
        for d in descs:
            log += struct.pack('<H', d)
        return bytes(log + vs)

    admin(0x02, cdw10=0x27,
          data=vlog(4, 2, 4, [12000, (1 << 14) | 12100], b'\xde\xad\xbe\xef'))
    admin(0x02, cdw10=0x27, data=vlog(1, 2, 0, [12000, 12100]))

    vtei = (1 << 30) | (240 << 18) | (2 << 16) | (0 << 14) | 12500
    packets.append(aem_packet(aeo_list([aeo_entry(
        0x0F, AEO_SCOPE_CONTROLLER, 1, specific=struct.pack('<I', vtei))])))
    packets.append(aem_packet(aeo_list([aeo_entry(
        0x0F, AEO_SCOPE_CONTROLLER, 1, specific=b'\x01')])))

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-voltage'))

# ---------------------------------------------------------------------------
# nvme-mi-rate-limiting.pcapng -- Rate Limiting (NVM CS 1.3 4.1.3.9,
# 4.1.4.8), reached over the NVMe-MI Admin tunnel.
#
#   F1-F2    Set Features FID 28h TGT 0 TID 1 with the Fig 107 data buffer
#            (RLE, Soft Limit, BWSF 10 MiB/s, TBWV 300, WBWV 100, ratios 1:3
#            and 1:2, VS byte 0x5a)
#   F3-F4    Get Features FID 28h TGT 0 TID 1 returning the same buffer
#   F5-F6    Set Features FID 28h TGT 192 TID 7 with WIOPSR 0 (expert)
#   F7-F8    Get Log Page LID 28h laid out like Fig 196: one port at dword
#            5, controllers at dwords 263/345 sharing two Endurance Group
#            NSMA descriptors, the second listing a Namespace NSMA, then
#            two Supported Targets (0, 192) and two padding bytes
#   F9-F10   LID 28h with a port offset inside the header, a duplicate
#            controller reference, a self-referencing NSMA and a Supported
#            Target list past LPL (experts on F10)
#   F11-F12  LID 28h read with a 64-byte window: header and port offset
#            only, the descriptor is past the transfer (no expert)
#   F13-F14  LID 28h with 200 Port descriptors a dword apart, each with
#            the maximum entry count: their lists overlap, and each dword
#            is read as an offset once
# ---------------------------------------------------------------------------

def build_rate_limiting_pcapng(output_path):
    packets = []
    eid = [0x40]

    pair = _bmc_pair(packets, eid)

    ok = admin_cqe3(cqe_status_word(phase=1))

    def admin(opcode, cdw10=0, cdw11=0, data=None, req_data=None):
        n = len(data) if data is not None else 0
        rn = len(req_data) if req_data is not None else 0
        if opcode == 0x02:
            cdw10 |= (n // 4 - 1) << 16    # NUMDL
        pair(NVME_MI_TYPE_ADMIN,
             admin_request_payload(opcode, cns=cdw10, cdw11=cdw11,
                                   flags=0x01 if (n or rn) else 0,
                                   dlen=n or rn) + (req_data or b''),
             admin_response_payload(STATUS_SUCCESS, cqe3=ok) + (data or b''))

    def rl_buf(ratios):
        b = bytearray(1024)
        struct.pack_into('<H', b, 0, 0x8001)
        b[7] = 1
        struct.pack_into('<QQII', b, 8, 300, 100, 500000, 200000)
        b[32:36] = bytes(ratios)
        b[512] = 0x5a
        return bytes(b)

    admin(0x09, cdw10=0x28, cdw11=(0 << 16) | 1, req_data=rl_buf([1, 3, 1, 2]))
    admin(0x0A, cdw10=0x28, cdw11=(0 << 16) | 1, data=rl_buf([1, 3, 1, 2]))
    admin(0x09, cdw10=0x28, cdw11=(192 << 16) | 7, req_data=rl_buf([1, 0, 1, 2]))

    def rlma(sf, rbw, wbw, riops, wiops):
        return struct.pack('<B7xQQII', sf, rbw, wbw, riops, wiops)

    def port(portid, ctrl_offs):
        d = bytearray(1024)
        struct.pack_into('<HH', d, 0, portid, len(ctrl_offs) - 1)
        d[7] = 3
        d[8:40] = rlma(3, 14, 12, 3000000, 1000000)
        struct.pack_into('<QQII', d, 40, 10, 8, 2000000, 500000)
        d[512] = 0xa5
        return bytes(d) + b''.join(struct.pack('<I', o) for o in ctrl_offs)

    def ctrl(cntlid, nsma_offs):
        d = bytearray(320)
        struct.pack_into('<HH', d, 0, cntlid, len(nsma_offs))
        d[8:40] = rlma(2, 140, 120, 1500000, 500000)
        return bytes(d) + b''.join(struct.pack('<I', o) for o in nsma_offs)

    def nsma(sc, si, offs):
        d = bytearray(64)
        struct.pack_into('<BxHI', d, 0, sc, len(offs), si)
        d[8:40] = rlma(1, 50, 40, 750000, 250000)
        return bytes(d) + b''.join(struct.pack('<I', o) for o in offs)

    def log(np_offs, nst, lpl, body, targets=b''):
        hdr = struct.pack('<HHIIHH', 0, len(np_offs) - 1, lpl, 9, nst - 1, 0)
        out = hdr + b''.join(struct.pack('<I', o) for o in np_offs) + body + targets
        return out + bytes(-len(out) % 4)

    # Byte offsets: port 20, ctrl 1052/1380, EG NSMAs 1708/1772, NS NSMA 1840.
    body = (port(0, [263, 345]) + ctrl(0, [427, 443]) + ctrl(1, [427, 443])
            + nsma(2, 1, []) + nsma(2, 2, [460]) + nsma(3, 5, []))
    assert len(body) == 1904 - 20
    admin(0x02, cdw10=0x28, data=log([5], 2, 477, body, bytes([0, 192])))

    # Ports at dword 2 (the header) and 6; that port lists the controller
    # at byte 1056 twice; the controller's one NSMA (byte 1380) lists itself.
    body = port(1, [264, 264]) + ctrl(2, [345]) + nsma(0, 0, [345])
    assert len(body) == 1448 - 24
    admin(0x02, cdw10=0x28, data=log([2, 6], 4, 1448 // 4, body))

    admin(0x02, cdw10=0x28, data=log([5], 2, 477, b'')[:20] + bytes(44))

    # 200 Port descriptors at bytes 816, 820, ...: the word at 'at + 2' is
    # 0xffff, so each lists 65536 offsets up to the end of the 4096 bytes.
    ports, size = 200, 4096
    admin(0x02, cdw10=0x28,
          data=(struct.pack('<HHIIHH', 0, ports - 1, size // 4 + 100, 9, 0, 0)
                + b''.join(struct.pack('<I', 204 + i) for i in range(ports))
                + struct.pack('<I', 0xffff0000) * ((size - 16 - 4 * ports) // 4)))

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-rate-limiting'))


# ---------------------------------------------------------------------------
# nvme-mi-mfr-defaults.pcapng -- Restore Manufacturing Default Settings
# (TP4195) and Lockdown Persistence Personality (TP4200), Base 2.4.
#
#   F1-F2    Get Log Page LID 24h: MDCSV 0, MDCS DSCS and DCCS (Fig 304)
#   F3-F4    LID 24h with MI DOFST 1: MDCS only (reserved bits set)
#   F5-F6    Set Features FID 22h PERID 02h CHPS, CDW11 LDPE (Fig 518)
#   F7-F8    Get Features FID 22h PERID 02h: DW0 PERID 02h, DW1 LDPS (Fig 519)
#   F9-F10   Get Features FID 22h PERID 01h: DW1 not decoded
#   F11-F12  Get Features FID 22h PERID 02h SEL 011b: DW1 not decoded
#   F13-F14  Get Features FID 22h PERID 02h failing: DW1 not decoded
#   F15-F16  Set Features FID 22h PERID 03h: CDW11 not decoded as LDPE
#   F17-F18  Namespace Management SEL 2h (Restore Default Namespace Config)
#   F19-F20  Capacity Management OPER 5h failing with Failed to Restore
#            Configuration (generic 2Dh)
#   F21-F32  Get Features FID 22h PERID 02h SEL 1h, 2h: DW1 LDPS; SEL 4h-7h
#            (Reserved, Figure 198): DW1 not decoded
# ---------------------------------------------------------------------------

def build_mfr_defaults_pcapng(output_path):
    packets = []
    eid = [0x40]

    def pair(request, response):
        bmc = eid[0]
        eid[0] += 1
        packets.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, request, bmc_eid=bmc))
        packets.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, response, bmc_eid=bmc))

    ok = admin_cqe3(cqe_status_word(phase=1))

    def admin(opcode, cdw10=0, cdw11=0, cdw13=0, doff=0, data=None,
              dw0=0, dw1=0, cqe3=ok):
        n = len(data) if data is not None else 0
        if opcode == 0x02:
            cdw10 |= 0 << 16               # NUMDL: one dword
        flags = (0x01 if n else 0) | (0x02 if doff else 0)
        pair(admin_request_payload(opcode, cns=cdw10, cdw11=cdw11,
                                   flags=flags, doff=doff, dlen=n,
                                   lpo=cdw13 << 32),
             admin_response_payload(STATUS_SUCCESS, cqe1=dw0, cqe2=dw1, cqe3=cqe3)
             + (data or b''))

    admin(0x02, cdw10=0x24, data=bytes([0x00, 0x05, 0x00, 0x00]))
    admin(0x02, cdw10=0x24, doff=1, data=bytes([0xfe, 0x00, 0x00]))

    admin(0x09, cdw10=0x22, cdw11=0x1, cdw13=0x200 | 0x02)
    admin(0x0A, cdw10=0x22, cdw13=0x02, dw0=0x02, dw1=0x1)
    admin(0x0A, cdw10=0x22, cdw13=0x01, dw0=0x01, dw1=0x1)
    admin(0x0A, cdw10=0x22 | (3 << 8), cdw13=0x02, dw0=0x5, dw1=0x1)
    admin(0x0A, cdw10=0x22, cdw13=0x02, dw1=0x1,
          cqe3=admin_cqe3(cqe_status_word(sc=0x02, phase=1)))
    admin(0x09, cdw10=0x22, cdw11=0x1, cdw13=0x200 | 0x03)

    admin(0x0D, cdw10=0x2)
    admin(0x20, cdw10=0x5,
          cqe3=admin_cqe3(cqe_status_word(sct=0, sc=0x2d, dnr=1, phase=1)))
    for sel in (1, 2, 4, 5, 6, 7):
        admin(0x0A, cdw10=0x22 | sel << 8, cdw13=0x02, dw0=0x02, dw1=0x1)

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-mfr-defaults'))

def build_csi_lid_names_pcapng(output_path):
    """CSI-specific Get Log Page names (Base 2.4 Figure 31, MI 2.2 Figure 144).

    Each pair is a Get Log Page with CDW14.CSI set and a one-dword response:
      F1-2   LID 82h CSI 04h  Program List
      F3-4   LID 83h CSI 04h  Downloadable Program Types List
      F5-6   LID 84h CSI 04h  Memory Range Set List
      F7-8   LID 85h CSI 03h  Host Addressable Namespaces
      F9-10  LID BFh CSI 02h  Changed Zone List
      F11-12 LID 85h CSI 00h  generic: I/O Command Set Specific
      F13-14 LID 82h CSI 03h  generic: I/O Command Set Specific
      F15-16 LID BFh CSI 00h  generic: Zoned Namespace Command Set
    """
    packets = []
    eid = [0x40]

    def get_log(lid, csi):
        bmc = eid[0]
        eid[0] += 1
        data = b'\x00' * 4
        req = admin_request_payload(0x02, cns=lid, flags=0x01, dlen=len(data),
                                    cdw14=csi << 24)
        rsp = admin_response_payload(STATUS_SUCCESS) + data
        packets.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, req, bmc_eid=bmc))
        packets.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, rsp, bmc_eid=bmc))

    for lid, csi in ((0x82, 0x04), (0x83, 0x04), (0x84, 0x04), (0x85, 0x03),
                     (0xBF, 0x02), (0x85, 0x00), (0x82, 0x03), (0xBF, 0x00)):
        get_log(lid, csi)

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-csi-lid-names'))


def build_identify_underlying_pcapng(output_path):
    """Identify CNS 21h and 22h (Base 2.4 Figure 336, section 5.2.14.3.1 and
    Figure 359).

      F1-2   CNS 21h CNTID 5: Controller List NUMCIDS 2, IDs 5 and 7
      F3-4   CNS 22h: reserved 0, ENST1, ENST2, zero entry ends the list
      F5-6   CNS 22h, DOFST 24: ENST1 cut (raw), ENST2 whole, zero ends
      F7-8   CNS 22h: nonzero reserved bytes, ENST1 only, 32-byte window
      F9-10  CNS 23h: reserved, raw data and expert
    """
    packets = []
    eid = [0x40]

    def identify(cns, data, cntid=0, doff=0):
        bmc = eid[0]
        eid[0] += 1
        flags = 0x01 | (0x02 if doff else 0)
        req = admin_request_payload(0x06, cns=(cntid << 16) | cns, flags=flags,
                                    doff=doff, dlen=len(data))
        rsp = admin_response_payload(STATUS_SUCCESS) + data
        packets.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, req, bmc_eid=bmc))
        packets.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, rsp, bmc_eid=bmc))

    enst1 = bytes(range(0x10, 0x20))
    enst2 = bytes(range(0xa0, 0xb0))
    identify(0x21, struct.pack('<HHHH', 2, 5, 7, 0), cntid=5)
    identify(0x22, b'\x00' * 16 + enst1 + enst2 + b'\x00' * 16)
    identify(0x22, enst1[8:] + enst2 + b'\x00' * 16, doff=24)
    identify(0x22, b'\xee' * 16 + enst1)
    identify(0x23, b'\x5a' * 8)

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-identify-underlying'))


def build_pda_pcapng(output_path):
    """NVMe-MI PDA commands 0Dh-0Fh (NVMe-MI 2.2 section 5.7, Figures 106-111).

      F1-2    PDA Read, DFORMAT 3h (bytes), DOFST 16, DLEN 8: 8 data bytes
      F3-4    PDA Read, DFORMAT 2h (512B), DOFST 2, DLEN 1: 512 data bytes
      F5-6    PDA Read, DFORMAT 1h (4KiB), DLEN 0: Success, no data
      F7-8    PDA Read, DFORMAT 3h, DLEN 8, only 6 bytes returned (expert)
      F9-10   PDA Read, DFORMAT 0h (Reserved, expert), response data raw
      F11-12  PDA Write, DFORMAT 3h, DLEN 4 with 4 REQD bytes: Success
      F13-14  PDA Write, DFORMAT 3h, DLEN 4 with 3 REQD bytes (expert), then
              Invalid Command Input Data Size
      F15-16  PDA Write Zeroes, NMD0/NMD1 nonzero (reserved), Success
      F17-18  PDA Read, Invalid Parameter, PEL at DOFST
      F19     PDA Write Zeroes, 8 bytes (truncated request)

    DLEN above a conservative per-DFORMAT ceiling from Figures 109/111 is
    flagged: 4096 for 1h, 512 for 2h (its "512B" maximum may mean units or
    bytes) and 4096 for Write 3h; Read 3h ("Byte Level") has no maximum:
      F20-21  PDA Read, DFORMAT 1h, DLEN 4097: flagged
      F22-23  PDA Read, DFORMAT 1h, DLEN 4096: silent
      F24-25  PDA Read, DFORMAT 2h, DLEN 4097: flagged
      F26-27  PDA Read, DFORMAT 3h, DLEN 4097: silent
      F28-29  PDA Write, DFORMAT 3h, DLEN 4097 with 4097 REQD bytes: flagged
      F30-31  PDA Write, DFORMAT 3h, DLEN 4096 with 4096 REQD bytes: silent
      F32-33  PDA Write, DFORMAT 1h, DLEN 4097, no REQD: flagged
      F34-35  PDA Write, DFORMAT 1h, DLEN 4096, no REQD: silent
      F36-37  PDA Write, DFORMAT 2h, DLEN 4097, no REQD: flagged
      F38-39  PDA Write, DFORMAT 2h, DLEN 4096, no REQD: flagged
      F40-41  PDA Read, DFORMAT 2h, DLEN 513: flagged
      F42-43  PDA Read, DFORMAT 2h, DLEN 512: silent
      F44-45  PDA Write, DFORMAT 2h, DLEN 513, no REQD: flagged
      F46-47  PDA Write, DFORMAT 2h, DLEN 512, no REQD: silent
    Reads answer Invalid Parameter with PEL at DLEN; Writes without REQD
    answer Invalid Command Input Data Size.
    """
    packets = []
    eid = [0x50]

    def pda_req(opcode, dformat, dofst=0, dlen=0, data=b''):
        return (bytes([opcode, dformat, 0, 0]) +
                struct.pack('<II', dofst, dlen) + data)

    def pair(req, rsp):
        bmc = eid[0]
        eid[0] += 1
        packets.append(make_packet(True, NVME_MI_TYPE_MI, 0, req, bmc_eid=bmc))
        if rsp is not None:
            packets.append(make_packet(False, NVME_MI_TYPE_MI, 0, rsp,
                                       bmc_eid=bmc))

    pair(pda_req(0x0D, 3, 16, 8),
         mi_response_payload_with_data(STATUS_SUCCESS, bytes(range(1, 9))))
    pair(pda_req(0x0D, 2, 2, 1),
         mi_response_payload_with_data(STATUS_SUCCESS, b'\xa5' * 512))
    pair(pda_req(0x0D, 1, 0, 0), mi_response_payload(STATUS_SUCCESS))
    pair(pda_req(0x0D, 3, 0, 8),
         mi_response_payload_with_data(STATUS_SUCCESS, b'\x11' * 6))
    pair(pda_req(0x0D, 0, 0, 4),
         mi_response_payload_with_data(STATUS_SUCCESS, b'\x22' * 4))
    pair(pda_req(0x0E, 3, 32, 4, b'\xde\xad\xbe\xef'),
         mi_response_payload(STATUS_SUCCESS))
    pair(pda_req(0x0E, 3, 32, 4, b'\xde\xad\xbe'),
         mi_response_payload(0x06))
    pair(pda_req(0x0F, 3, 0x1234, 0x5678), mi_response_payload(STATUS_SUCCESS))
    pair(pda_req(0x0D, 3, 0xFFFFFF00, 1),
         mi_response_payload(0x04, nmresp=0x000800))
    pair(bytes([0x0F, 3, 0, 0, 0, 0, 0, 0]), None)

    dlen_err = mi_response_payload(0x04, nmresp=0x000C00)
    pair(pda_req(0x0D, 1, 0, 4097), dlen_err)
    pair(pda_req(0x0D, 1, 0, 4096), dlen_err)
    pair(pda_req(0x0D, 2, 0, 4097), dlen_err)
    pair(pda_req(0x0D, 3, 0, 4097), dlen_err)
    pair(pda_req(0x0E, 3, 0, 4097, b'\x5a' * 4097), dlen_err)
    pair(pda_req(0x0E, 3, 0, 4096, b'\x5a' * 4096),
         mi_response_payload(STATUS_SUCCESS))
    # A conformant REQD of 4096 4KiB or 512B units would not fit a message,
    # so none is sent; each also draws the REQD-length expert.
    size_err = mi_response_payload(0x06)
    pair(pda_req(0x0E, 1, 0, 4097), size_err)
    pair(pda_req(0x0E, 1, 0, 4096), size_err)
    pair(pda_req(0x0E, 2, 0, 4097), size_err)
    pair(pda_req(0x0E, 2, 0, 4096), size_err)
    pair(pda_req(0x0D, 2, 0, 513), dlen_err)
    pair(pda_req(0x0D, 2, 0, 512), dlen_err)
    pair(pda_req(0x0E, 2, 0, 513), size_err)
    pair(pda_req(0x0E, 2, 0, 512), size_err)

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-pda'))


def build_ror_tag_owner_pcapng(output_path):
    """ROR against the MCTP Tag Owner bit (NVMe-MI 2.2 Figure 20, TP6042).

      F1  Subsystem HSP request, CSI 0 (TO=1, ROR=0)
      F2  host to device, ROR=1 with TO=1: an errant response delivered as a
          request; the Responder drops it.  Flagged, and it must not pair
          with F1 or close its slot
      F3  the real response to F1 (TO=0, ROR=1): pairs with F1
      F4  host to device, ROR=0 with TO=0: flagged, no slot opened
      F5  Asynchronous Event Message (TO=1, ROR=0): not flagged
    """
    to_off = len(sll_header(HOST_EID, outgoing=True)) + 3

    def flip_to(pkt):
        b = bytearray(pkt)
        b[to_off] ^= 0x08
        return bytes(b)

    hsp = mi_request_payload(0x01)
    stray = make_packet(False, NVME_MI_TYPE_MI, 0,
                        mi_response_payload(STATUS_SUCCESS))
    # Re-address the stray response as host to device, keeping TO=1.
    stray = make_packet(True, NVME_MI_TYPE_MI, 0, b'')[:to_off + 1] + \
        stray[to_off + 1:]
    packets = [
        make_packet(True, NVME_MI_TYPE_MI, 0, hsp),
        stray,
        make_packet(False, NVME_MI_TYPE_MI, 0,
                    mi_response_payload_with_data(STATUS_SUCCESS, bytes(8))),
        flip_to(make_packet(True, NVME_MI_TYPE_MI, 1, hsp)),
        aem_packet(aeo_list([aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM,
                                       specific=bytes([0x4B]))])),
    ]
    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-ror-tag-owner'))


def build_admin_transfer_pcapng(output_path):
    """Admin DLEN against the data the command dwords define (NVMe-MI 2.2
    Figure 139, Base 2.4 Figure 92), Response Data on opcodes that return
    none, CID and Error Response surplus (MI 2.2 Figures 30-34 and 141).

      F1-2    FW Image Download NUMD 3h (16 bytes), DLEN 8          flagged
      F3-4    FW Image Download NUMD 1h (8 bytes), DLEN 8           valid
      F5-6    NS Attachment SEL 0h, DLEN 8 (not 4096)               flagged
      F7-8    NS Attachment SEL 2h (Reserved), DLEN 0               valid
      F9-10   NS Management SEL 0h Create, DLEN 0                   flagged
      F11-12  NS Management SEL 1h Delete, DLEN 4                   flagged
      F13-14  NS Management SEL 1h Delete, DLEN 0                   valid
      F15-16  MENS Receive SEL 00h, DLEN 0                          flagged
      F17-18  MENS Receive SEL 06h (Reserved), DLEN 0               valid
      F19-20  MENS Send SEL 02h, DLEN 0                             flagged
      F21-22  MENS Send SEL 01h Delete, ESUBIDV 1, DLEN 0           valid
      F23-24  MENS Send SEL 01h Delete, ESUBIDV 0, DLEN 0           flagged
      F25-26  Manage Exported Namespace SEL 01h, DLEN 0             flagged
      F27-28  Manage Exported Port SEL 02h, DLEN 0                  flagged
      F29-30  Security Send TL 16, DLEN 8                           flagged
      F31-32  Security Send TL 0, DLEN 0                            valid
      F33-34  Security Receive AL 16, DLEN 0                        flagged
      F35-36  Security Receive AL 0, DLEN 0                         valid
      F37-38  Get LBA Status, DLEN 0                                flagged
      F39-40  Set Features Timestamp (0Eh), DLEN 0                  flagged
      F41-42  Get Features Timestamp, SEL 0h, DLEN 0                flagged
      F43-44  Get Features Timestamp, SEL 3h (capabilities), DLEN 0 valid
      F45-46  Set Features Host Memory Buffer (0Dh), DLEN 0         valid
      F47-48  Get Features Host Memory Buffer, DLEN 0               flagged
      F49-50  Firmware Commit (00b) answered with 8 data bytes      flagged
      F51-52  Device Self-test (00b) answered with 4 data bytes     flagged
      F53-54  Reserved opcode 30h answered with 4 data bytes        valid
      F55-56  Identify DLEN 4 answered with 8 bytes: Excess Data    flagged
      F57-58  Identify DLEN 8 answered with 4 bytes: short          noted
      F59-60  Identify answered with CID 5h                         flagged
      F61-62  Identify answered Invalid Parameter + 12 bytes        flagged
      F63-64  Identify answered Vendor Specific E0h + 12 bytes      valid
      F65-66  Identify answered Reserved 10h + 12 bytes             valid
      F67-68  PCIe Config Read answered Invalid Parameter + 4 bytes flagged
      F69-70  PCIe Config Read answered Vendor Specific E1h + 4     valid
      F71-72  Identify answered with CID 0h                         valid

    Features DLEN/DOFST against the transfer the FID, SEL and dwords define
    (Base 2.4 Figure 466, NVM CS 1.3 Figure 92); "+N" is N inline bytes.

      F73-74    Set Timestamp, DLEN 4 +4 (8 required)               flagged
      F75-76    Get Timestamp, DOFST 8, DLEN 4                      flagged
      F77-78    Get Timestamp, DOFST 4, DLEN 4, 4 bytes returned    valid
      F79-80    Set Timestamp, DOFST 4, DLEN 8 +8                   flagged
      F81-82    Get Features C0h (vendor specific), DLEN 8          valid
      F83-84    Get Timestamp, SEL 3h, DLEN 8, 8 bytes returned     flagged
      F85-86    Get Arbitration, DLEN 4                             flagged
      F87-88    Get Arbitration, DOFST 4                            flagged
      F89-90    Get CDP, PERID 01h, DLEN 8                          valid
      F91-92    Get CDP, PERID 05h (Reserved), DLEN 0               valid
      F93-94    Set CDP, PERID 01h, CHPS 0, DLEN 0                  valid
      F95-96    Set CDP, PERID 01h, CHPS 1, DLEN 4 +4               valid
      F97-98    Get Host Identifier EXHID 1, DOFST 8, DLEN 8        valid
      F99-100   Get Host Identifier EXHID 1, DOFST 16, DLEN 4       flagged
      F101-102  Get Host Identifier EXHID 0, DLEN 8                 valid
      F103-104  Set CDP, PERID 01h, CHPS 0, DLEN 4 +4               valid
      F105-106  Set CDP, PERID 02h, CHPS 0, DLEN 4 +4               valid
      F107-108  Set CDP, PERID 02h, CHPS 1, DLEN 4 +4               flagged
      F109-110  Set CDP, PERID 05h (Reserved), CHPS 1, DLEN 4 +4    valid
      F111-112  Set Voltage Measurement ACT 0h, DLEN 0              valid
      F113-114  Set Voltage Measurement ACT 2h, DLEN 4 +4           flagged
      F115-116  Set Voltage Measurement ACT 1h, DLEN 8 +8           flagged
      F117-118  Set Voltage Measurement ACT 3h (Reserved), DLEN 4   valid
      F119-120  Set Voltage Measurement ACT Ah (VS), DLEN 4 +4      valid
      F121-122  Get Voltage Measurement ACT 1h, DOFST 4096, DLEN 4  flagged
      F123-124  Set Rate Limiting TGT 0, DLEN 512 +512              flagged
      F125-126  Set Rate Limiting TGT 1 (Reserved), DLEN 4 +4       valid
      F127-128  Set Rate Limiting TGT C0h (VS), DLEN 4 +4           valid
      F129-130  Get Rate Limiting TGT 0, DOFST 1020, DLEN 8         flagged
      F131-132  Get Perf Characteristics ATTRI 05h, DLEN 0          valid
      F133-134  Set Perf Characteristics ATTRI C1h RVSPA 1, DLEN 4  valid
      F135-136  Set Perf Characteristics ATTRI C1h, DLEN 0          flagged
      F137-138  Get Perf Characteristics ATTRI C0h, DOFST 4092 +8   flagged
      F139-140  Set Power Management, DLEN 4 +4                     flagged
      F141-142  Get Timestamp, SEL 4h (Reserved), DLEN 8            flagged
      F143-144  Get Error Recovery, DLEN 4                          flagged

    MI-prohibited log pages and Set Features FIDs (MI 2.2 Figures 144, 148).

      F145-146  Get Log Page LID 1Eh, NUMD 0, DLEN 4                flagged
      F147-148  Set I/O Command Set Profile (19h), DLEN 0           valid
      F149-150  Get Host Memory Buffer, DLEN 4096                   valid

    Inline data with MEB set (MI 2.2 section 4.2.3).

      F151-152  Get Timestamp, MEB, DLEN 8, 8 inline bytes          flagged

    Response Data windows within and across a SMART field (MI 2.2 Figures
    142/143): a window inside DUR decodes nothing and stays raw.

      F153-154  Get SMART, NUMD 127, DOFST 40, DLEN 8               raw
      F155-156  Get SMART, NUMD 127, DOFST 32, DLEN 16              decoded

    Get Features Select 011b returns capabilities in CQE DW0 and no Response
    Data (Base 2.4 Figure 201).

      F157-158  Get Timestamp, SEL 3h, DOFST 4, DLEN 8, 8 bytes     flagged
      F159-160  Get Host Identifier, SEL 3h, DOFST 4, DLEN 16, 16   flagged
      F161-162  Get Timestamp, SEL 3h, capabilities 5h in DW0       valid

    Vendor specific opcodes follow the data transfer bits 1:0 (Base 2.4
    Figure 92).

      F163-164  C0h (00b), DLEN 4                                   flagged
      F165-166  C0h (00b), DOFST 4                                  flagged
      F167-168  C1h (01b), DOFST 4, DLEN 4 +4                       flagged
      F169-170  C1h (01b), DLEN 4, no Request Data                  flagged
      F171-172  C2h (10b), DOFST 4, DLEN 4, 4 bytes returned        valid
      F173-174  C3h (11b), DOFST 4, DLEN 4 +4, 4 bytes returned     valid
      F175-176  C0h (00b) answered with 4 data bytes                flagged

    DOFST/DLEN against the maximum completion data: Get LBA Status MNDW
    (NVM CS 1.3 Figure 137) and the Security Receive AL of SECP 00h-03h
    (SIIS 1.20 Table 24).

      F177-178  Get LBA Status MNDW 2 (12 bytes), DOFST 8, DLEN 8   flagged
      F179-180  Get LBA Status MNDW 2, DOFST 12, DLEN 4             flagged
      F181-182  Get LBA Status MNDW 2, DOFST 8, DLEN 4              valid
      F183-184  Get LBA Status MNDW FFFFFFFFh, DOFST FFFFFFFCh      valid
      F185-190  Security Receive SECP 01h AL 12: DOFST 8 DLEN 8,
                DOFST 12 DLEN 4, DOFST 8 DLEN 4                     flagged x2
      F191-196  The same for SECP 00h                               flagged x2
      F197-202  The same for SECP 02h SPSP 1000h                    flagged x2
      F203-204  SECP 03h AL 12, DOFST 8, DLEN 8                     flagged
      F205-206  SECP EEh AL 12, DOFST 8, DLEN 8                     valid
      F207-208  SECP 01h AL 0, DLEN 4                               valid
      F209      SECP 01h AL 12, DOFST 12, DLEN 4, no response       flagged
      F210-211  SECP 01h AL 12, DOFST 8, DLEN 8, CQE error          flagged
      F212-213  SECP 01h AL 64, DLEN 8, 8 bytes returned            valid

    The ME ignores RAE (NVMe-MI 2.2 Figure 137 note 2).

      F214-215  Get Log Page LID 00h, RAE 1, NUMD 1, 4 bytes        valid
    """
    packets = []
    eid = [0x40]
    ok16 = admin_response_payload(STATUS_SUCCESS,
                                  cqe3=admin_cqe3(cqe_status_word(phase=1)))

    def pair(req, resp, msg_type=NVME_MI_TYPE_ADMIN, meb=False):
        bmc = eid[0]
        eid[0] += 1
        packets.append(make_packet(True, msg_type, 0, req, bmc_eid=bmc,
                                   meb=meb))
        packets.append(make_packet(False, msg_type, 0, resp, bmc_eid=bmc))

    def req(opcode, cdw10=0, dlen=0, cdw11=0, cdw14=0, data=b'', doff=0,
            cdw13=0, cdw12=0):
        assert len(data) in (0, dlen)
        return admin_request_payload(opcode, ctrl_id=0x0001, cns=cdw10,
                                     flags=0, doff=doff, dlen=dlen,
                                     cdw11=cdw11, cdw14=cdw14,
                                     lpo=cdw12 | cdw13 << 32) + data

    secp = 0xef << 24
    pair(req(0x11, cdw10=3, dlen=8, data=bytes(8)), ok16)
    pair(req(0x11, cdw10=1, dlen=8, data=bytes(8)), ok16)
    pair(req(0x15, cdw10=0x0, dlen=8, data=bytes(8)), ok16)
    pair(req(0x15, cdw10=0x2), ok16)
    pair(req(0x0d, cdw10=0x0), ok16)
    pair(req(0x0d, cdw10=0x1, dlen=4, data=bytes(4)), ok16)
    pair(req(0x0d, cdw10=0x1), ok16)
    pair(req(0x2a, cdw10=0x00), ok16)
    pair(req(0x2a, cdw10=0x06), ok16)
    pair(req(0x2d, cdw10=0x02), ok16)
    pair(req(0x2d, cdw10=0x01, cdw14=0x80), ok16)
    pair(req(0x2d, cdw10=0x01), ok16)
    pair(req(0x31, cdw10=0x01), ok16)
    pair(req(0x35, cdw10=0x02), ok16)
    pair(req(0x81, cdw10=secp, cdw11=16, dlen=8, data=bytes(8)), ok16)
    pair(req(0x81, cdw10=secp), ok16)
    pair(req(0x82, cdw10=secp, cdw11=16), ok16)
    pair(req(0x82, cdw10=secp), ok16)
    pair(req(0x86), ok16)
    pair(req(0x09, cdw10=0x0e), ok16)
    pair(req(0x0a, cdw10=0x0e), ok16)
    pair(req(0x0a, cdw10=0x30e), ok16)
    pair(req(0x09, cdw10=0x0d), ok16)
    pair(req(0x0a, cdw10=0x0d), ok16)
    pair(req(0x10), ok16 + bytes(8))
    pair(req(0x14), ok16 + bytes(4))
    pair(req(0x30), ok16 + bytes(4))
    pair(req(0x06, cdw10=0x01, dlen=4), ok16 + ID4 + bytes(4))
    pair(req(0x06, cdw10=0x01, dlen=8), ok16 + ID4)
    pair(req(0x06, cdw10=0x01, dlen=4),
         admin_response_payload(STATUS_SUCCESS,
                                cqe3=admin_cqe3(cqe_status_word(phase=1),
                                                cid=5)) + ID4)
    pair(req(0x06, cdw10=0x01, dlen=4), bytes([0x04, 0, 0, 0]) + bytes(12))
    pair(req(0x06, cdw10=0x01, dlen=4), bytes([0xe0, 0, 0, 0]) + bytes(12))
    pair(req(0x06, cdw10=0x01, dlen=4), bytes([0x10, 0, 0, 0]) + bytes(12))
    pair(PCIE_CFG_READ_ID, pcie_response_payload(0x04, data=bytes(4)),
         NVME_MI_TYPE_PCIE)
    pair(PCIE_CFG_READ_ID, pcie_response_payload(0xe1, data=bytes(4)),
         NVME_MI_TYPE_PCIE)
    pair(req(0x06, cdw10=0x01, dlen=4), ok16 + ID4)

    def setf(fid, dlen=0, **kw):
        return req(0x09, cdw10=fid, dlen=dlen, data=bytes(dlen), **kw)

    def getf(fid, sel=0, **kw):
        return req(0x0a, cdw10=fid | sel << 8, **kw)

    pair(setf(0x0e, 4), ok16)
    pair(getf(0x0e, doff=8, dlen=4), ok16)
    pair(getf(0x0e, doff=4, dlen=4), ok16 + bytes(4))
    pair(setf(0x0e, 8, doff=4), ok16)
    pair(getf(0xc0, dlen=8), ok16 + bytes(8))
    pair(getf(0x0e, sel=3, dlen=8), ok16 + bytes(8))
    pair(getf(0x01, dlen=4), ok16 + bytes(4))
    pair(getf(0x01, doff=4), ok16)
    pair(getf(0x22, cdw13=0x01, dlen=8), ok16 + bytes(8))
    pair(getf(0x22, cdw13=0x05), ok16)
    pair(setf(0x22, cdw13=0x01), ok16)
    pair(setf(0x22, 4, cdw13=0x201), ok16)
    pair(getf(0x81, cdw11=1, doff=8, dlen=8), ok16 + bytes(8))
    pair(getf(0x81, cdw11=1, doff=16, dlen=4), ok16)
    pair(getf(0x81, dlen=8), ok16 + bytes(8))
    pair(setf(0x22, 4, cdw13=0x01), ok16)
    pair(setf(0x22, 4, cdw13=0x02), ok16)
    pair(setf(0x22, 4, cdw13=0x202), ok16)
    pair(setf(0x22, 4, cdw13=0x205), ok16)
    pair(setf(0x27, cdw11=0x0), ok16)
    pair(setf(0x27, 4, cdw11=0x2), ok16)
    pair(setf(0x27, 8, cdw11=0x1), ok16)
    pair(setf(0x27, 4, cdw11=0x3), ok16)
    pair(setf(0x27, 4, cdw11=0xa), ok16)
    pair(getf(0x27, cdw11=0x1, doff=4096, dlen=4), ok16)
    # Nonzero ratio portions (NVM CS 1.3 Figure 107) keep only the DLEN expert.
    rl = bytearray(512)
    rl[32:36] = b'\x01\x01\x01\x01'
    pair(req(0x09, cdw10=0x28, dlen=512, data=bytes(rl)), ok16)
    pair(setf(0x28, 4, cdw11=0x01_0000), ok16)
    pair(setf(0x28, 4, cdw11=0xc0_0000), ok16)
    pair(getf(0x28, doff=1020, dlen=8), ok16)
    pair(getf(0x1c, cdw11=0x05), ok16)
    pair(setf(0x1c, 4, cdw11=0x1c1), ok16)
    pair(setf(0x1c, cdw11=0xc1), ok16)
    pair(getf(0x1c, cdw11=0xc0, doff=4092, dlen=8), ok16)
    pair(setf(0x02, 4), ok16)
    pair(getf(0x0e, sel=4, dlen=8), ok16 + bytes(8))
    pair(getf(0x05, dlen=4), ok16 + bytes(4))
    pair(req(0x02, cdw10=0x1e, dlen=4), ok16 + bytes(4))
    pair(setf(0x19), ok16)
    pair(getf(0x0d, dlen=4096), ok16 + bytes(4096))
    pair(getf(0x0e, dlen=8) + bytes(8), ok16, meb=True)
    pair(req(0x02, cdw10=0x02 | 127 << 16, doff=40, dlen=8), ok16 + bytes(8))
    pair(req(0x02, cdw10=0x02 | 127 << 16, doff=32, dlen=16),
         ok16 + bytes(16))
    pair(getf(0x0e, sel=3, doff=4, dlen=8), ok16 + bytes(8))
    pair(getf(0x81, sel=3, doff=4, dlen=16), ok16 + bytes(16))
    pair(getf(0x0e, sel=3),
         admin_response_payload(STATUS_SUCCESS, cqe1=0x5,
                                cqe3=admin_cqe3(cqe_status_word(phase=1))))
    pair(req(0xc0, dlen=4), ok16)
    pair(req(0xc0, doff=4), ok16)
    pair(req(0xc1, doff=4, dlen=4, data=bytes(4)), ok16)
    pair(req(0xc1, dlen=4), ok16)
    pair(req(0xc2, doff=4, dlen=4), ok16 + bytes(4))
    pair(req(0xc3, doff=4, dlen=4, data=bytes(4)), ok16 + bytes(4))
    pair(req(0xc0), ok16 + bytes(4))

    def lba(mndw, doff, dlen):
        pair(req(0x86, cdw12=mndw, doff=doff, dlen=dlen), ok16 + bytes(dlen))

    def recv(secp_id, al, doff, dlen, spsp=0x0001):
        return req(0x82, cdw10=secp_id << 24 | spsp << 8, cdw11=al,
                   doff=doff, dlen=dlen)

    lba(2, 8, 8)
    lba(2, 12, 4)
    lba(2, 8, 4)
    lba(0xffffffff, 0xfffffffc, 4)
    for secp_id, spsp in ((0x01, 0x0001), (0x00, 0x0000), (0x02, 0x1000)):
        for doff, dlen in ((8, 8), (12, 4), (8, 4)):
            pair(recv(secp_id, 12, doff, dlen, spsp), ok16 + bytes(dlen))
    pair(recv(0x03, 12, 8, 8), ok16 + bytes(8))
    pair(recv(0xee, 12, 8, 8), ok16 + bytes(8))
    pair(recv(0x01, 0, 0, 4), ok16 + bytes(4))
    packets.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                               recv(0x01, 12, 12, 4), bmc_eid=eid[0]))
    eid[0] += 1
    pair(recv(0x01, 12, 8, 8),
         admin_response_payload(STATUS_SUCCESS, cqe3=admin_cqe3(
             cqe_status_word(sc=0x02, phase=1))) + bytes(8))
    # A Level 0 Discovery prefix: Length 30h, version 0.1 (Core 3.3.6.2).
    pair(recv(0x01, 64, 0, 8), ok16 + struct.pack('>II', 0x30, 1))
    pair(req(0x02, cdw10=0x00 | 1 << 15, dlen=4), ok16 + struct.pack('<I', 1))
    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-admin-transfer'))


def build_tcg_field_checks_pcapng(output_path):
    """TPer Reset Transfer Length, Subpacket Kind and Credit Control Length,
    and IF-RECV on the TPER_RESET ComID (Opal SSC 2.30 3.2.3 Table 13; Core
    2.01 Tables 19 and 21, 3.3.4.7.5).  Each pair is on an endpoint of its own.

      F1-2    Security Send SECP 02h SPSP 0004h TL 0               flagged
      F3-4    Security Send SECP 02h SPSP 0004h TL 4 (TPer Reset)  valid
      F5-6    Security Send SECP 01h SPSP 0004h TL 0               valid
      F7-8    ComPacket with a Credit Control Subpacket, Length 8  flagged
      F9-10   ComPacket with a Credit Control Subpacket, Length 4  valid
      F11-12  ComPacket with a Subpacket of Kind 1234h             flagged
      F13-14  IF-RECV ComID 0004h: No Response Available, ComID 0  noted
      F15-16  IF-RECV ComID 0004h: STACK_RESET answer, ComID 1000h noted, flagged
      F17-18  IF-RECV ComID 0004h: No Response Available, ComID 4  noted
      F19-20  IF-RECV ComID 1000h: No Response Available, ComID 0  valid
    """
    packets = []
    eid = [0x40]

    def pair(request, data=b''):
        packets.append(mi_admin_frame(True, request, eid[0], 0))
        packets.append(mi_admin_frame(False, admin_resp_with_data(data), eid[0], 0))
        eid[0] += 1

    def credit(length):
        body = struct.pack('>I', 0x100) + bytes(length - 4)
        return b'\x00' * 6 + struct.pack('>HI', 0x8001, length) + body

    def send_cp(subpacket):
        data = tcg_compacket(tcg_packet(subpacket), 0x1000)
        return mi_security_request(True, 0x01, 0x1000, data)

    def comid_resp(comid, req_code, body=b''):
        return (struct.pack('>HHIHH', comid, 0, req_code, 0, len(body)) + body)

    pair(mi_security_request(True, 0x02, 0x0004))
    pair(mi_security_request(True, 0x02, 0x0004, bytes(4)))
    pair(mi_security_request(True, 0x01, 0x0004))
    pair(send_cp(credit(8)))
    pair(send_cp(credit(4)))
    pair(send_cp(tcg_subpacket(b'\xa1\x00', kind=0x1234)))
    for spsp, data in ((0x0004, comid_resp(0x0000, 0)),
                       (0x0004, comid_resp(0x1000, 2, bytes(4))),
                       (0x0004, comid_resp(0x0004, 0)),
                       (0x1000, comid_resp(0x0000, 0))):
        pair(mi_security_request(False, 0x02, spsp, tl=len(data)), data)
    write_pcapng(output_path, packets, 1736000000 * 1_000_000)


def build_decode_correctness_pcapng(output_path):
    """PCC CRT bits, SMART INFW and Telemetry TCDA (Base 2.4 Figures 360,
    213, 221 and 223).

      F1-2    Identify CNS 14h, CRT 01h: VQRS only
      F3-4    Identify CNS 14h, CRT 02h: VIRS only
      F5-6    SMART / Health (LID 02h), INFW 01h (VLTHW)
      F7-8    SMART / Health, INFW FFh (VLTHW and reserved bits 7:1)
      F9-10   SMART / Health, INFW 00h
      F11-12  Telemetry Host-Initiated (LID 07h), TCDA 1h
      F13-14  Telemetry Controller-Initiated (LID 08h), TCDA 0h
    """
    packets = []
    eid = [0x60]

    def pair(opcode, cdw10, data):
        bmc = eid[0]
        eid[0] += 1
        req = admin_request_payload(opcode, ctrl_id=0x0001, cns=cdw10,
                                    dlen=len(data))
        packets.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0, req,
                                   bmc_eid=bmc))
        packets.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0,
                                   admin_resp_with_data(data), bmc_eid=bmc))

    def pcc(crt):
        buf = bytearray(4096)
        struct.pack_into('<HH', buf, 0, 0x0001, 0x0002)  # CNTLID, PORTID
        buf[4] = crt
        return bytes(buf)

    def smart(infw):
        buf = bytearray(smart_data())
        buf[7] = infw
        buf[8] = 0x5a                       # first byte of Reserved 31:08
        return bytes(buf)

    def telemetry(lid, tcda):
        buf = bytearray(512)
        buf[0] = lid
        buf[382] = tcda
        return bytes(buf)

    def log_cdw10(lid, length):
        return lid | (((length // 4) - 1) << 16)

    pair(NVME_AQ_OPC_IDENTIFY, 0x14, pcc(0x01))
    pair(NVME_AQ_OPC_IDENTIFY, 0x14, pcc(0x02))
    for infw in (0x01, 0xff, 0x00):
        pair(NVME_AQ_OPC_GET_LOG_PAGE, log_cdw10(0x02, 512), smart(infw))
    pair(NVME_AQ_OPC_GET_LOG_PAGE, log_cdw10(0x07, 512), telemetry(0x07, 1))
    pair(NVME_AQ_OPC_GET_LOG_PAGE, log_cdw10(0x08, 512), telemetry(0x08, 0))

    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-decode-correctness'))


def build_frame_rules_pcapng(output_path):
    """Header and MI command field rules (NVMe-MI 2.2 Figures 20, 29, 61-64
    and 94; IPMI FRU 1.0r1.3 Table 16-2), each violation with its control.

      F1      AEM with MEB set: flagged (Figure 20)
      F2      conformant AEM: silent; ROR reads "not applicable to AEMs"
      F3/F4   Abort with CSI 1, Success: silent (only Pause and Resume
              leave CSI unused, 4.2.1.1 and 4.2.1.2)
      F5/F6   Configuration Get with 4 bytes of Request Data: flagged
      F7/F8   Subsystem Health Status Poll with Request Data: flagged
      F9/F10  VPD Write with its DLEN of Request Data: silent
      F11/F12 Vendor Specific opcode C0h with data: silent
      F13/F14 Controller HSP, MAXRENT 00h: silent (FFh is in
              nvme-mi-mi-commands.pcapng)
      F15/F16 VPD Read: MultiRecords 01h, 0Eh, 20h and C0h name IPMI,
              Reserved (NVMe), Reserved and OEM record types
      F17/F18 Configuration Get, Invalid Parameter at byte 4 bit 3:
              BYTLOC and BITLOC labels
      F19     AEM with AEOLHL 8h and AELHLEN Ah: both flagged, the extra
              header bytes shown raw
      F20     AEM, PCIe Link Active with AEOPT 1 and AEOPID 15:8 set: flagged
              (Figure 64)
      F21     AEM, Reserved AEOI 20h (Controller scope): a Note
      F22     AEM, Controller Fatal Status with Reserved AESS 7h: a Note,
              and no scope mismatch on top
      F23     AEM, vendor specific AE C5h with Namespace scope: silent
      F24-F26 Get State requests with CIAP, MEB, and both set: one warning
              per set bit, on that bit (Figure 20)
      F27/F28 Get State with neither bit set: silent request; its Success
              response with MEB set: flagged without Invalid Parameter
    """
    packets = []
    eid = [0x70]

    pair = _bmc_pair(packets, eid)

    def aem(entries, meb=False, lst=None):
        if lst is None:
            lst = aeo_list(entries)
        if not meb:
            return aem_packet(lst)
        sll = sll_header(BMC_EID, outgoing=False)
        mctp = bytes([0x01, HOST_EID, BMC_EID, 0xC8])
        return sll + mctp + nvme_mi_message(NVME_MI_TYPE_AEM, 0, False, lst,
                                            meb=True)

    temp = aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM, specific=bytes([0x4B]))
    packets.append(aem([temp], meb=True))
    packets.append(aem([temp]))
    pair(NVME_MI_TYPE_CONTROL, cp_request_payload(0x02, tag=0x11),
         cp_response_payload(STATUS_SUCCESS, tag=0x11))
    packets[-2] = make_packet(True, NVME_MI_TYPE_CONTROL, 1,
                              cp_request_payload(0x02, tag=0x11),
                              bmc_eid=eid[0] - 1)
    packets[-1] = make_packet(False, NVME_MI_TYPE_CONTROL, 1,
                              cp_response_payload(STATUS_SUCCESS, tag=0x11),
                              bmc_eid=eid[0] - 1)
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x04, cdw0=0x01) + bytes(4),
         mi_response_payload(STATUS_SUCCESS, nmresp=0x01))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x01) + bytes(4),
         mi_response_payload_with_data(STATUS_SUCCESS, bytes(8)))
    pair(NVME_MI_TYPE_MI,
         mi_request_payload(0x06, cdw0=0, cdw1=4) + b'\x5a' * 4,
         mi_response_payload(STATUS_SUCCESS))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0xC0) + bytes(4),
         mi_response_payload(STATUS_SUCCESS))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x02),
         mi_response_payload(STATUS_SUCCESS))
    image = vpd(record(0x01, bytes(13), last=False),
                record(0x0E, bytes(4), last=False),
                record(0x20, bytes(4), last=False),
                record(0xC0, bytes(4)))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x05, cdw0=0, cdw1=len(image)),
         mi_response_payload_with_data(STATUS_SUCCESS, image))
    pair(NVME_MI_TYPE_MI, mi_request_payload(0x04, cdw0=0x01),
         mi_response_payload(0x04, nmresp=0x03 | (4 << 8)))

    entry = aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM, specific=bytes([0x4B]))
    entry = bytes([AEO_ENTRY_HDR_LEN + 1]) + entry[1:9] + b'\xbb' + entry[9:]
    lst = aeo_list([entry], hdr_len=AEO_LIST_HDR_LEN + 1)
    packets.append(aem(None, lst=lst[:7] + b'\xaa' + lst[7:]))
    packets.append(aem([aeo_entry(0x0B, AEO_SCOPE_PORT,
                                  scope_id=0x00010000 | 0x0100 | 0x01,
                                  specific=bytes([0x01]))]))
    packets.append(aem([aeo_entry(0x20, AEO_SCOPE_CONTROLLER, scope_id=1)]))
    packets.append(aem([aeo_entry(0x01, 0x07, scope_id=1,
                                  specific=bytes([0x01]))]))
    packets.append(aem([aeo_entry(0xC5, 0x00, scope_id=1)]))
    get_state = cp_request_payload(CP_OPC_GET_STATE, tag=0x21)
    for ciap, meb in ((True, False), (False, True), (True, True)):
        packets.append(make_packet(True, NVME_MI_TYPE_CONTROL, 0, get_state,
                                   bmc_eid=eid[0], ciap=ciap, meb=meb))
        eid[0] += 1
    packets.append(make_packet(True, NVME_MI_TYPE_CONTROL, 0, get_state,
                               bmc_eid=eid[0]))
    packets.append(make_packet(False, NVME_MI_TYPE_CONTROL, 0,
                               cp_response_payload(STATUS_SUCCESS, tag=0x21),
                               bmc_eid=eid[0], meb=True))
    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-frame-rules'))


def build_csi_candidate_pcapng(output_path):
    """A response whose CSI names an empty Command Slot while the other slot
    holds an unanswered same-type request: a possible CSI mismatch, noted but
    never paired (NVMe-MI 2.2 Figure 20).  One endpoint per scenario.

      F1-F5   S1 MI: request CSI 0; response CSI 1 (candidate); response
              CSI 0 (answers F1); request and response CSI 0
      F6-F8   S2 Admin: request CSI 0; response CSI 1 (candidate); CSI 0
      F9-F11  S3 PCIe: request CSI 0; response CSI 1 (candidate); CSI 0
      F12/F13 S4 MI request CSI 0, Admin response CSI 1: no candidate
      F14     S5 MI response CSI 1 with no request: no candidate
      F15/F16 S6 MI request CSI 0 tag 2, response CSI 1 tag 3: no candidate
      F17-F19 S7 MI request and response CSI 0, then a stray response CSI 1:
              no candidate
      F20-F22 S8 MI request CSI 0; response CSI 1 with a bad MIC: no
              candidate; response CSI 0 answers F20
    """
    packets = []
    mi_req = mi_request_payload(0x01)
    mi_resp = mi_response_payload_with_data(STATUS_SUCCESS, bytes(8))
    adm_req = admin_request_payload(NVME_AQ_OPC_IDENTIFY, cns=0x01, dlen=4)
    adm_resp = admin_resp_with_data(ID4)
    pcie_resp = pcie_response_payload(STATUS_SUCCESS, PCIE_CFG_ID_DATA)

    def pkt(is_request, kind, csi, payload, eid, tag=1, mic=None):
        packets.append(make_packet(is_request, kind, csi, payload,
                                   bmc_eid=eid, tag=tag, mic=mic))

    for kind, req, resp, eid in (
            (NVME_MI_TYPE_MI, mi_req, mi_resp, 0x80),
            (NVME_MI_TYPE_ADMIN, adm_req, adm_resp, 0x81),
            (NVME_MI_TYPE_PCIE, PCIE_CFG_READ_ID, pcie_resp, 0x82)):
        pkt(True, kind, 0, req, eid)
        pkt(False, kind, 1, resp, eid)
        pkt(False, kind, 0, resp, eid)
        if kind == NVME_MI_TYPE_MI:
            pkt(True, kind, 0, req, eid)
            pkt(False, kind, 0, resp, eid)
    pkt(True, NVME_MI_TYPE_MI, 0, mi_req, 0x83)
    pkt(False, NVME_MI_TYPE_ADMIN, 1, adm_resp, 0x83)
    pkt(False, NVME_MI_TYPE_MI, 1, mi_resp, 0x84)
    pkt(True, NVME_MI_TYPE_MI, 0, mi_req, 0x85, tag=2)
    pkt(False, NVME_MI_TYPE_MI, 1, mi_resp, 0x85, tag=3)
    pkt(True, NVME_MI_TYPE_MI, 0, mi_req, 0x86)
    pkt(False, NVME_MI_TYPE_MI, 0, mi_resp, 0x86)
    pkt(False, NVME_MI_TYPE_MI, 1, mi_resp, 0x86)
    pkt(True, NVME_MI_TYPE_MI, 0, mi_req, 0x87)
    pkt(False, NVME_MI_TYPE_MI, 1, mi_resp, 0x87, mic=0xdeadbeef)
    pkt(False, NVME_MI_TYPE_MI, 0, mi_resp, 0x87)
    write_pcapng(output_path, packets, 1735000000 * 1_000_000,
                 idb(name='mctp-sll-csi-candidate'))


if __name__ == '__main__':
    captures_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'test', 'captures')
    build_merged(os.path.join(captures_dir, 'nvme-mi-tcg.pcapng'), *tcg_sections())

    # nvme-mi-types.pcapng — comprehensive coverage capture, F1-F107 (the
    # count is asserted in _packets_comprehensive), then the framing
    # captures, a section per builder:
    #   F108-F114  build_pcapng (MPR and concurrent CSI slots)
    #   F115-F118  build_reserved_type_pcapng
    #   F119-F124  build_typemismatch_pcapng
    #   F125-F148  build_framing_conformance_pcapng
    #   F149-F168  build_nmimt_error_pcapng
    #   F169-F178  build_nmimt_range_pcapng
    #   F179-F202  build_mic_integrity_pcapng
    #   F203-F599  build_message_framing_pcapng
    #   F600-F603  build_inband_pcapng (raw NVMe-MI on LINKTYPE_USER0, which
    #              only a test's Lua shim decodes)
    #   F604-F653  reserved_vectors
    #   F654-F761  edge_case_vectors
    build_merged(os.path.join(captures_dir, 'nvme-mi-types.pcapng'),
                 build_comprehensive_pcapng, build_pcapng, build_reserved_type_pcapng,
                 build_typemismatch_pcapng, build_framing_conformance_pcapng,
                 build_nmimt_error_pcapng, build_nmimt_range_pcapng,
                 build_mic_integrity_pcapng, build_message_framing_pcapng, build_inband_pcapng,
                 lambda path: write_vectors_pcapng(path, 'nvme-mi-reserved', 1740000000000000,
                                                   reserved_vectors()),
                 lambda path: write_vectors_pcapng(path, 'nvme-mi-quality-review',
                                                   1741000000000000, edge_case_vectors()))
    print()

    # nvme-mi-transactions.pcapng — Command Slot, version context and
    # conversation keying, a section per builder:
    #   F1-F178    build_slot_lifecycle_pcapng
    #   F179-F246  build_version_context_pcapng
    #   F247-F258  build_mctp_bridge_pcapng (several Management Endpoints
    #              behind one SMBus address)
    #   F259-F287  build_error_paths_pcapng
    #   F288-F296  build_null_dest_sll2_pcapng
    #   F297-F304  build_null_dest_slot_pcapng
    #   F305-F311  build_null_dest_slot_pcapng, answer_eid_request=False
    #   F312-F314  build_null_dest_stale_pcapng
    #   F315-F317  build_null_dest_stale_pcapng, linux_mctp=True
    #   F318-F321  build_null_dest_sll2_version_pcapng
    #   F322-F330  build_replay_alias_pcapng, 'stale'
    #   F331-F338  build_replay_alias_pcapng, 'abort'
    #   F339-F345  build_replay_alias_pcapng, 'alias'
    #   F346-F352  build_replay_alias_pcapng, 'between'
    #   F353-F366  build_replay_lost_original_pcapng, 'transmit'
    #   F367-F375  build_replay_lost_original_pcapng, 'partial'
    #   F376-F385  build_replay_lost_original_pcapng, 'alias'
    #   F386-F392  build_replay_lost_original_pcapng, 'between'
    #   F393-F402  build_replay_lost_original_pcapng, 'mismatch'
    #   F403-F412  build_replay_lost_original_pcapng, 'unanswered'
    #   F413-F421  build_replay_eid_alias_pcapng, 'stale'
    #   F422-F429  build_replay_eid_alias_pcapng, 'abort'
    #   F430-F436  build_replay_eid_alias_pcapng, 'alias'
    #   F437-F443  build_replay_eid_alias_pcapng, 'between'
    #   F444-F451  build_replay_eid_alias_pcapng, 'lost'
    build_merged(os.path.join(captures_dir, 'nvme-mi-transactions.pcapng'),
                 build_slot_lifecycle_pcapng, build_version_context_pcapng,
                 build_mctp_bridge_pcapng, build_error_paths_pcapng,
                 build_null_dest_sll2_pcapng, build_null_dest_slot_pcapng,
                 lambda path: build_null_dest_slot_pcapng(path, answer_eid_request=False),
                 build_null_dest_stale_pcapng,
                 lambda path: build_null_dest_stale_pcapng(path, linux_mctp=True),
                 build_null_dest_sll2_version_pcapng,
                 lambda path: build_replay_alias_pcapng(path, 'stale'),
                 lambda path: build_replay_alias_pcapng(path, 'abort'),
                 lambda path: build_replay_alias_pcapng(path, 'alias'),
                 lambda path: build_replay_alias_pcapng(path, 'between'),
                 *(lambda path, v=v: build_replay_lost_original_pcapng(path, v)
                   for v in ('transmit', 'partial', 'alias', 'between', 'mismatch',
                             'unanswered')),
                 *(lambda path, v=v: build_replay_eid_alias_pcapng(path, v)
                   for v in ('stale', 'abort', 'alias', 'between', 'lost')))
    print()

    build_merged(os.path.join(captures_dir, 'nvme-mi-mi4.pcapng'),
                 build_mi4_regressions_pcapng)
    print()

    build_merged(os.path.join(captures_dir, 'nvme-mi-pel.pcapng'),
                 build_pel_header_pcapng)
    build_merged(os.path.join(captures_dir, 'nvme-mi-pel-events.pcapng'),
                 build_pel_events_pcapng)
    print()

    # nvme-mi-admin-identify.pcapng — Admin Identify response payload decode
    # F1-F28, Admin SQE CDW10-15 shared decode F29-F41, Admin
    # response status + CQE DW0 decode F42-F51, admin_completion_vectors
    # F52-F75, mi12_admin_vectors F76-F141
    build_merged(os.path.join(captures_dir, 'nvme-mi-admin-identify.pcapng'),
                 build_admin_identify_pcapng, build_admin_decode_pcapng,
                 build_admin_resp_pcapng,
                 lambda path: write_vectors_pcapng(path, 'nvme-mi-spec-review',
                                                   1741000000000000, admin_completion_vectors()),
                 lambda path: write_vectors_pcapng(path, 'nvme-mi-admin-selectors',
                                                   1742000000000000, mi12_admin_vectors()))
    print()

    # nvme-mi-admin-logpage.pcapng — Admin Get Log Page response payload
    # F1-F42, then the other log page builders, a section each:
    #   F43-F170   build_admin_logpage_windowed_pcapng
    #   F171-F230  build_admin_window_pcapng
    #   F231-F349  m6_final_vectors
    #   F350-F373  build_logpage_windows_pcapng
    #   F374-F415  build_field_encoding_pcapng
    #   F416-F430  build_m8_pcapng
    #   F431-F454  build_admin_eom_pcapng
    #   F455-F460  discovery_index_tsas_vectors
    build_merged(os.path.join(captures_dir, 'nvme-mi-admin-logpage.pcapng'),
                 build_admin_logpage_pcapng, build_admin_logpage_windowed_pcapng,
                 build_admin_window_pcapng,
                 lambda path: write_vectors_pcapng(path, 'm6-final-mi', 1730000000000000,
                                                   m6_final_vectors()),
                 build_logpage_windows_pcapng, build_field_encoding_pcapng,
                 build_m8_pcapng, build_admin_eom_pcapng,
                 lambda path: write_vectors_pcapng(path, 'discovery-index-tsas',
                                                   1731000000000000,
                                                   discovery_index_tsas_vectors()))
    print()

    # nvme-mi-admin-features.pcapng — Admin Get/Set Features payload decode
    # F1-F44; F45-F66 the windowed transfers
    # (build_features_windowed_pcapng)
    build_merged(os.path.join(captures_dir, 'nvme-mi-admin-features.pcapng'),
                 build_admin_features_pcapng, build_features_windowed_pcapng)
    print()

    # nvme-mi-features-sel.pcapng — Get Features Select and feature units
    build_features_sel_pcapng(os.path.join(captures_dir, 'nvme-mi-features-sel.pcapng'))
    build_identify_win_pcapng(os.path.join(captures_dir, 'nvme-mi-identify-win.pcapng'))
    build_logpage_fixed_pcapng(os.path.join(captures_dir, 'nvme-mi-logpage-fixed.pcapng'))
    build_logpage_desc_pcapng(os.path.join(captures_dir, 'nvme-mi-logpage-desc.pcapng'))
    build_nvme_p2_5_pcapng(os.path.join(captures_dir, 'nvme-mi-p2-5.pcapng'))
    print()

    # nvme-mi-security.pcapng — Security Send/Receive payload decode, a
    # section per builder:
    #   F1-F24   build_admin_security_pcapng
    #   F25-F34  build_security_short_xfer_pcapng
    #   F35-F40  build_security_windowed_pcapng
    #   F41-F42  build_tcg_atom_classes_pcapng
    #   F43-F58  build_tcg_comid_mgmt_pcapng
    #   F59-F70  build_tcg_malformed_pcapng
    #   F71-F98  build_security_selector_pcapng
    build_merged(os.path.join(captures_dir, 'nvme-mi-security.pcapng'),
                 build_admin_security_pcapng, build_security_short_xfer_pcapng,
                 build_security_windowed_pcapng, build_tcg_atom_classes_pcapng,
                 build_tcg_comid_mgmt_pcapng, build_tcg_malformed_pcapng,
                 build_security_selector_pcapng)
    print()

    # nvme-mi-mi-commands.pcapng - MI Command Set bodies, a section per builder:
    #   F1-F74     build_mi_structures_pcapng
    #   F75-F204   build_mi_events_config_pcapng
    #   F205-F317  build_mi_contract_pcapng
    #   F318-F418  m6_structures_vectors
    #   F419-F458  build_ae_list_malformed_pcapng
    #   F459-F481  build_aem_pcapng
    #   F482-F743  build_shared_decode_pcapng (twins of nvme-tcp-admin.pcapng F26-F76)
    #   F744-F752  build_reset_sliced_pcapng
    #   F753-F784  build_meb_port_lists_pcapng
    #   F785-F791  build_aeo_overrun_pcapng
    #   F792-F828  build_mi9_command_set_pcapng
    #   F829-F848  build_mi_response_format_pcapng
    #   F849-      build_ae_enable_list_extra_pcapng
    build_merged(os.path.join(captures_dir, 'nvme-mi-mi-commands.pcapng'),
                 build_mi_structures_pcapng, build_mi_events_config_pcapng,
                 build_mi_contract_pcapng,
                 lambda path: write_vectors_pcapng(path, 'm6-mi-structures', 1730000000000000,
                                                   m6_structures_vectors()),
                 build_ae_list_malformed_pcapng, build_aem_pcapng, build_shared_decode_pcapng,
                 build_reset_sliced_pcapng, build_meb_port_lists_pcapng,
                 build_aeo_overrun_pcapng, build_mi9_command_set_pcapng,
                 build_mi_response_format_pcapng,
                 build_ae_enable_list_extra_pcapng)
    print()

    # The promoted session artefacts and the multi-interface shapes.  These
    # take no positional argument: they postdate the numbered list above, and
    # extending it would make the ordering of the existing entries load-bearing
    # in a way it is not.
    for name, builder in (
            ('nvme-mi-sliced-context.pcapng',   build_sliced_context_pcapng),
            ('nvme-mi-control.pcapng', build_control_coverage_pcapng),
            ('nvme-mi-spec-revisions.pcapng', build_spec_revisions_pcapng),
            ('nvme-mi-spec-revisions-fields.pcapng', build_spec_revisions_fields_pcapng),
            ('nvme-mi-voltage.pcapng', build_voltage_pcapng),
            ('nvme-mi-rate-limiting.pcapng', build_rate_limiting_pcapng),
            ('nvme-mi-mfr-defaults.pcapng', build_mfr_defaults_pcapng),
            ('nvme-mi-csi-lid-names.pcapng', build_csi_lid_names_pcapng),
            ('nvme-mi-identify-underlying.pcapng', build_identify_underlying_pcapng),
            ('nvme-mi-pda.pcapng', build_pda_pcapng),
            ('nvme-mi-ror-tag-owner.pcapng', build_ror_tag_owner_pcapng),
            ('nvme-mi-decode-correctness.pcapng', build_decode_correctness_pcapng),
            ('nvme-mi-admin-transfer.pcapng', build_admin_transfer_pcapng),
            ('nvme-mi-tcg-field-checks.pcapng', build_tcg_field_checks_pcapng),
            ('nvme-mi-frame-rules.pcapng', build_frame_rules_pcapng),
    ):
        builder(os.path.join(captures_dir, name))
        print()

    build_merged(os.path.join(captures_dir, 'nvme-mi-csi-candidate.pcapng'),
                 build_csi_candidate_pcapng)
    print()

    for name, data in cross_layer_fixtures().items():
        with open(os.path.join(captures_dir, name), 'wb') as output:
            output.write(data)
        print(f"Written {len(data)} bytes to {name}")
