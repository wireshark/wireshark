# Helper module for the tcg_storage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers copied from tools/gen-nvme-mi-test-capture.py (Linux SLL +
MCTP + NVMe-MI framing, pcapng blocks, admin request/response payloads)."""
import struct

_CRC32C_POLY = 0x82F63B78
LINUX_SLL_P_MCTP = 0x00FA
HOST_EID  = 0x0A
BMC_EID   = 0x08
NVME_MI_TYPE_ADMIN   = 0x2
NVME_MI_TYPE_MI      = 0x1
STATUS_SUCCESS = 0x00
STATUS_MPR     = 0x01   # More Processing Required


def crc32c(data):
    """Return the standard CRC32C checksum of data (seed=0xFFFFFFFF, final XOR=0xFFFFFFFF)."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            mask = -(crc & 1) & 0xFFFFFFFF
            crc = (crc >> 1) ^ (_CRC32C_POLY & mask)
    return crc ^ 0xFFFFFFFF


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


def sll_header(src_eid, outgoing=False):
    pkt_type = 0x0004 if outgoing else 0x0000
    arphrd   = 0x0000
    ha_len   = 1
    ha       = bytes([src_eid]) + b'\x00' * 7
    return struct.pack('>HHH8sH', pkt_type, arphrd, ha_len, ha, LINUX_SLL_P_MCTP)


def mctp_header(is_request, host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0):
    src = host_eid if is_request else bmc_eid
    dst = bmc_eid  if is_request else host_eid
    fst = (0xC8 | (tag & 0x07)) if is_request else (0xC0 | (tag & 0x07))
    return bytes([0x01, dst, src, fst])


def nvme_mi_header(msg_type, csi, is_response, ic=False, meb=False, ciap=False):
    b0 = 0x04 | (0x80 if ic else 0x00)  # bit 7 = IC (Integrity Check enabled)
    b1 = (msg_type << 3) | (csi & 0x01)
    if is_response:
        b1 |= 0x80
    # Byte 2 bit 0 = MEB, bit 1 = CIAP (bits 16 and 17 of the 32-bit LE header)
    b2 = (0x01 if meb else 0x00) | (0x02 if ciap else 0x00)
    return bytes([b0, b1, b2, 0x00])


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
