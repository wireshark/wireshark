#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a pcapng test capture for the core NVMe dissector (packet-nvme.c)
driven over NVMe/TCP (packet-nvme-tcp.c).

nvme-tcp-admin.pcapng  (383 frames; F1-F8 below, the rest per build_admin_capture)
  A single NVMe/TCP connection (host 10.0.0.1:55000 <-> controller
  10.0.0.2:4420) carrying Admin-queue CapsuleCommand PDUs.  Each command
  exercises one arm of the admin-queue opcode switch in dissect_nvme_cmd()
  (epan/dissectors/packet-nvme.c), now the shared
  nvme_dissect_admin_sqe_cdws() helper:

    Frame 1  Identify (06h), CNS=01h Identify Controller   -> CNS/CNTID decode
                                                              + CNS COL_INFO append
    Frame 2  Get Log Page (02h), LID=02h SMART             -> LID decode
                                                              + log-page COL_INFO append
    Frame 3  Set Features (09h), FID=02h Power Management  -> FID decode
    Frame 4  Get Features (0Ah), FID=04h Temperature Thr.  -> FID decode
    Frame 5  Format NVM (80h)                              -> default/unhandled
                                                              CDW10-15 raw decode
    Frame 6  Fabrics Property Get (7Fh, FCTYPE 04h)        -> ATTRIB container
    Frame 7  H2CTermReq with PLEN=20 (< the 24-byte hdr)   -> no ICReq, so not
                                                              a PDU start
    Frame 8  Identify (06h) with CDW2/CDW3 markers set     -> SQE bytes 15:08
                                                              as two dwords

  No CQE responses are emitted; test/suite_dissection_nvme.py checks the
  request decode of these frames.

  The commands land on the admin queue (qid 0) without a Fabrics Connect: none
  of the opcodes is an I/O opcode, so nvme-tcp's qid heuristic
  (nvme_cmd_implies_admin_queue) defaults the queue to admin.

nvme-tcp-fdp-events.pcapng  (14 frames, build_fdp_events)
  Get Features FDP Events (FID 1Eh) data that precedes the completion carrying
  its NOET: a successful read in one and in two windows, an FDP Disabled error,
  and a C2HData SUCCESS completion.  Frame map at build_fdp_events.

Wire format layers (outer to inner):
  Ethernet II            (14 bytes, DLT_EN10MB = 1)
  IPv4                   (20 bytes)
  TCP                    (20 bytes, dport 4420)
  NVMe/TCP CapsuleCmd    (8-byte common header + 64-byte SQE)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import itertools

from pcapng_testgen import DLT_EN10MB, crc32c, epb, eth, idb, ipv4, shb, tcp

# ---------------------------------------------------------------------------
# Ethernet / IPv4 / TCP framing
# ---------------------------------------------------------------------------

HOST_MAC = bytes.fromhex('020000000001')
CTRL_MAC = bytes.fromhex('020000000002')
HOST_IP  = bytes(map(int, ['10', '0', '0', '1']))
CTRL_IP  = bytes(map(int, ['10', '0', '0', '2']))
HOST_PORT = 55000
CTRL_PORT = 4420   # IANA NVMe/TCP


class Conn:
    """NVMe/TCP connections between HOST and CTRL, one Ethernet frame per PDU."""

    def __init__(self, ident, ts, port=HOST_PORT):
        self.out = bytearray(shb() + idb(DLT_EN10MB))
        self.ident, self.ts, self.port = ident, ts, port
        self.frame_no = 0
        self.seq = {}

    def segment(self, to_ctrl, pdu, port=None):
        """The frame carrying pdu; advances its direction's sequence number."""
        port = self.port if port is None else port
        mine = self.seq.get((port, to_ctrl), 1)
        theirs = self.seq.get((port, not to_ctrl), 1)
        self.seq[port, to_ctrl] = (mine + len(pdu)) & 0xFFFFFFFF
        ident = self.ident + self.frame_no
        if to_ctrl:
            return eth(CTRL_MAC, HOST_MAC, ipv4(HOST_IP, CTRL_IP,
                       tcp(port, CTRL_PORT, mine, theirs, pdu), ident))
        return eth(HOST_MAC, CTRL_MAC, ipv4(CTRL_IP, HOST_IP,
                   tcp(CTRL_PORT, port, mine, theirs, pdu), ident))

    def write(self, frame, caplen=None):
        """Append frame as the next EPB."""
        self.out += epb(frame, self.ts + self.frame_no * 1000, caplen=caplen)
        self.frame_no += 1

    def emit(self, to_ctrl, pdu, port=None, caplen=None):
        """Write pdu in its own frame."""
        self.write(self.segment(to_ctrl, pdu, port), caplen)

# ---------------------------------------------------------------------------
# NVMe/TCP CapsuleCommand PDU
# ---------------------------------------------------------------------------
# Common header (8 bytes): type(1) flags(1) hlen(1) pdo(1) plen(4, LE)
# For a command PDU HLEN covers the common header + the 64-byte SQE.

NVME_TCP_CMD = 0x04

def capsule_cmd_pdu(sqe, data=b'', pdo=0, hdgst=False, ddgst=False,
                    corrupt_ddgst=False):
    """CapsuleCmd PDU: the 8-byte common header, the 64-byte SQE and, with
    `data`, in-capsule data (NVMe/TCP 1.3 Figure 30).

    The defaults are no in-capsule data, no digests and PDO 0.

    `pdo` is the common header's PDU Data Offset: the offset from byte 0 to the
    CCICD field.  A `pdo` past the 72-byte header and its optional digest
    inserts that many bytes of alignment padding, which is what a host does to
    satisfy the controller's negotiated PDU Data Alignment (Figure 27's CPDA).
    Figure 30 has no data-length field: the capsule ends at the last byte of
    capsule data, so the length is implied by PLEN, PDO and the data digest.
    The padding is a recognisable non-zero fill rather than zeroes, so a decoder
    that reads it by mistake produces a visibly wrong value.
    """
    assert len(sqe) == 64
    hlen = 8 + 64
    hdgst_len = NVME_TCP_DIGEST_LENGTH if hdgst else 0
    ddgst_len = NVME_TCP_DIGEST_LENGTH if ddgst else 0
    first = hlen + hdgst_len
    assert pdo == 0 or pdo >= first, \
        'a nonzero PDU Data Offset must be at or after the header and its digest'
    assert pdo % 4 == 0, 'the alignment is counted in dwords'
    assert data or not (pdo or hdgst or ddgst), \
        'the digests and the data offset only mean something with in-capsule data'
    pad = b'\xEE' * (pdo - first) if pdo else b''
    flags = (NVME_TCP_F_HDGST if hdgst else 0) | (NVME_TCP_F_DDGST if ddgst else 0)
    plen = first + len(pad) + len(data) + ddgst_len
    ch = struct.pack('<BBBBI', NVME_TCP_CMD, flags, hlen, pdo & 0xFF, plen)
    unit = ch + sqe
    if hdgst:
        # Covers the header only, and never the padding that follows it.
        unit += struct.pack('<I', crc32c(unit))
    unit += pad + data
    if ddgst:
        # Covers the in-capsule data alone: not the padding in front of it, and
        # not itself.
        value = crc32c(data)
        if corrupt_ddgst:
            value ^= 0xFFFFFFFF
        unit += struct.pack('<I', value)
    assert len(unit) == plen
    return unit

# ---------------------------------------------------------------------------
# 64-byte NVMe Submission Queue Entry
# ---------------------------------------------------------------------------

def sqe(opcode, cid, nsid=0, cdw2=0, cdw3=0, cdw10=0, cdw11=0, cdw12=0,
        cdw13=0, cdw14=0, cdw15=0):
    b = bytearray(64)
    b[0] = opcode & 0xFF
    b[1] = 0x00                                   # PSDT/FUSE
    struct.pack_into('<H', b, 2, cid & 0xFFFF)    # CID
    struct.pack_into('<I', b, 4, nsid & 0xFFFFFFFF)
    struct.pack_into('<I', b, 8, cdw2 & 0xFFFFFFFF)
    struct.pack_into('<I', b, 12, cdw3 & 0xFFFFFFFF)
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
AQ_FW_IMG_DOWNLOAD = 0x11
AQ_FORMAT_NVM   = 0x80

# Fabrics command set (NVMe Base 2.3 section 6): opcode 7Fh, with the Fabrics
# Command Type in SQE byte 4 -- which sqe() writes as the low byte of `nsid`.
FABRICS_OPC       = 0x7F
FCTYPE_PROP_GET   = 0x04

# Identify CNS=01h (Controller); Get Log LID=02h (SMART);
# Set FID=02h (Power Mgmt); Get FID=04h (Temperature Threshold);
# Fabrics Property Get: ATTRIB (byte 40, the low byte of CDW10) = 81h --
# Property Return Size 1h (8 bytes) in bits 2:0 plus a set Reserved bit 7
# (NVMe Base 2.3 Figure 585), so the Attributes container item, which spans
# the whole byte, is distinguishable from the size field inside it.
COMMANDS = [
    sqe(AQ_IDENTIFY,     cid=1, cdw10=0x00000001),
    sqe(AQ_GET_LOG_PAGE, cid=2, cdw10=0x00000002),
    sqe(AQ_SET_FEATURES, cid=3, cdw10=0x00000002, cdw11=0x00000001),
    sqe(AQ_GET_FEATURES, cid=4, cdw10=0x00000004),
    sqe(AQ_FORMAT_NVM,   cid=5, cdw10=0x000000AB),
    sqe(FABRICS_OPC,     cid=6, nsid=FCTYPE_PROP_GET, cdw10=0x00000081,
        cdw11=0x00000014),
]

# SQE bytes 15:08 are Command Dword 2 and Command Dword 3 -- two separate
# command-specific dwords in the Common Command Format (NVMe Base 2.3
# Figure 92).  Only Figure 93, the optional format for vendor specific
# commands, reserves 15:08 as one field.  Every other command in this capture
# leaves both dwords zero, which cannot tell a correct two-dword decode from a
# swapped or mis-sized one, so the trailing frame carries two distinct,
# byte-asymmetric markers.
CDW2_MARKER = 0x11223344
CDW3_MARKER = 0x55667788

CDW23_COMMAND = sqe(AQ_IDENTIFY, cid=7, cdw2=CDW2_MARKER, cdw3=CDW3_MARKER,
                    cdw10=0x00000001)


# ---------------------------------------------------------------------------
# H2CTermReq PDU with a deliberately short PLEN
# ---------------------------------------------------------------------------
# A Termination Request header is 24 bytes: the 8-byte common header, FES at
# offset 8, FEI at offset 10, reserved out to 24, then the header of the PDU
# that caused the termination.  dissect_nvme_tcp_h2ctermreq() computed that
# trailing length as `packet_len - 24` on an unsigned PLEN, so a PLEN below 24
# wrapped to a huge value.
#
# tcp_dissect_pdus() only rejects PLEN < 8, and dissect_nvme_tcp_pdu() only
# returns early when PLEN - HLEN underflows, so HLEN is set to PLEN here to
# reach the TermReq arm of the switch at all.  PLEN 20 is large enough for FES
# and FEI to be read (the pre-fix code got that far) and short enough to
# underflow the trailing length.

NVME_TCP_H2C_TERM = 0x02
NVME_TCP_FES_INVALID_PDU_HDR = 0x01


def h2ctermreq_pdu(plen, fes=NVME_TCP_FES_INVALID_PDU_HDR, fei=0):
    ch = struct.pack('<BBBBI', NVME_TCP_H2C_TERM, 0x00, plen & 0xFF, 0x00, plen)
    body = ch + struct.pack('<HI', fes, fei)
    assert len(body) <= plen
    return body + b'\x00' * (plen - len(body))


SHORT_TERMREQ_PLEN = 20


def build():
    conn = Conn(0x1000, 1_700_000_000_000_000)
    pdus = [capsule_cmd_pdu(s) for s in COMMANDS]
    pdus.append(h2ctermreq_pdu(SHORT_TERMREQ_PLEN))
    for pdu in pdus:
        conn.emit(True, pdu)

    # Frame 8: the CDW2/CDW3 marker command.  It is appended rather than
    # inserted so the frame numbers the existing tests assert stay put, and it
    # runs on a second connection because frame 7 terminated the first one.
    conn.emit(True, capsule_cmd_pdu(CDW23_COMMAND), HOST_PORT + 1)
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# NVMe/TCP C2HData PDU
# ---------------------------------------------------------------------------

NVME_TCP_C2H_DATA = 0x07
NVME_TCP_DATA_PDU_SIZE = 24

NVME_TCP_F_HDGST = 0x01
NVME_TCP_F_DDGST = 0x02
NVME_TCP_DIGEST_LENGTH = 4


def c2h_data_pdu(cid, payload, datal=None, datao=0, pdo=0,
                 hdgst=False, ddgst=False, corrupt_ddgst=False,
                 last=False, success=False):
    """Controller-to-host data PDU: 8-byte common header then
    cccid(2) ttag(2) data-offset(4) data-length(4) rsvd(4), then the payload.

    `last` and `success` set FLAGS bits 2 (LAST_PDU) and 3 (SUCCESS) of
    NVMe/TCP 1.3 Figure 33.  Both default to clear, as every capture written
    before this function took them has them.

    `datao` is the Data Offset field: where the payload belongs in the
    command's data buffer.  `pdo` is the common header's PDU Data Offset: where
    the payload starts inside this PDU.  They are different coordinates and
    both default to zero.

    A `pdo` greater than the 24-byte header inserts that many bytes of
    alignment padding between the header and the payload, which is what a
    controller does to satisfy the host's negotiated PDU Data Alignment
    (NVMe/TCP 1.3 Figures 25 and 26).  The padding is written as a recognisable
    non-zero fill rather than zeroes, so a decoder that reads it by mistake
    produces a visibly wrong value instead of a plausible-looking zero.
    """
    if datal is None:
        datal = len(payload)
    hdgst_len = NVME_TCP_DIGEST_LENGTH if hdgst else 0
    ddgst_len = NVME_TCP_DIGEST_LENGTH if ddgst else 0
    first = NVME_TCP_DATA_PDU_SIZE + hdgst_len
    assert pdo == 0 or pdo >= first, \
        'a nonzero PDU Data Offset must be at or after the header and its digest'
    assert pdo % 4 == 0, 'the alignment is counted in dwords'
    pad = b'\xEE' * (pdo - first) if pdo else b''
    flags = ((NVME_TCP_F_HDGST if hdgst else 0)
             | (NVME_TCP_F_DDGST if ddgst else 0)
             | (NVME_TCP_F_LAST_PDU if last else 0)
             | (NVME_TCP_F_SUCCESS if success else 0))
    plen = first + len(pad) + len(payload) + ddgst_len
    ch = struct.pack('<BBBBI', NVME_TCP_C2H_DATA, flags,
                     NVME_TCP_DATA_PDU_SIZE, pdo & 0xFF, plen)
    hdr = struct.pack('<HH', cid & 0xFFFF, 0)      # CCCID, TTAG
    hdr += struct.pack('<I', datao & 0xFFFFFFFF)   # Data Offset
    hdr += struct.pack('<I', datal & 0xFFFFFFFF)   # Data Length
    hdr += bytes(4)                                # reserved
    assert len(ch) + len(hdr) == NVME_TCP_DATA_PDU_SIZE

    unit = ch + hdr
    if hdgst:
        # Covers the header only, and never the padding that follows it.
        unit += struct.pack('<I', crc32c(unit))
    unit += pad + payload
    if ddgst:
        # Covers the data only: not the padding in front of it, and not
        # itself.  Computing it over anything else is the failure this vector
        # exists to catch, so it is computed here from the payload alone.
        value = crc32c(payload)
        if corrupt_ddgst:
            value ^= 0xFFFFFFFF
        unit += struct.pack('<I', value)
    assert len(unit) == plen
    return unit


NVME_TCP_H2C_DATA = 0x06
NVME_TCP_R2T = 0x09
NVME_TCP_R2T_PDU_SIZE = 24
NVME_TCP_F_LAST_PDU = 0x04
NVME_TCP_F_SUCCESS = 0x08


def h2c_data_pdu(cid, payload, datal=None, datao=0, pdo=0, ttag=1, last=False,
                 hdgst=False, ddgst=False, corrupt_ddgst=False):
    """Host-to-controller data PDU: the mirror of c2h_data_pdu() for the write
    direction (NVMe/TCP 1.3 Figure 32) -- the same 24-byte header shape, the
    same two coordinates, the same PAD row, and the LAST_PDU flag Figure 32
    adds at FLAGS bit 2.

    `datao` is the Data Offset field: where the payload belongs in the command's
    data buffer.  `pdo` is the PDU Data Offset: where it starts inside this PDU,
    after the header, any header digest and the alignment padding inserted for
    the controller's negotiated PDU Data Alignment (Figure 27's CPDA).  The
    padding is 0xEE rather than zeroes, so a digest computed over the wrong
    range produces a visibly wrong value instead of a plausible one.
    """
    if datal is None:
        datal = len(payload)
    hdgst_len = NVME_TCP_DIGEST_LENGTH if hdgst else 0
    ddgst_len = NVME_TCP_DIGEST_LENGTH if ddgst else 0
    first = NVME_TCP_DATA_PDU_SIZE + hdgst_len
    assert pdo == 0 or pdo >= first, \
        'a nonzero PDU Data Offset must be at or after the header and its digest'
    assert pdo % 4 == 0, 'the alignment is counted in dwords'
    pad = b'\xEE' * (pdo - first) if pdo else b''
    flags = ((NVME_TCP_F_HDGST if hdgst else 0)
             | (NVME_TCP_F_DDGST if ddgst else 0)
             | (NVME_TCP_F_LAST_PDU if last else 0))
    plen = first + len(pad) + len(payload) + ddgst_len
    ch = struct.pack('<BBBBI', NVME_TCP_H2C_DATA, flags,
                     NVME_TCP_DATA_PDU_SIZE, pdo & 0xFF, plen)
    hdr = struct.pack('<HH', cid & 0xFFFF, ttag & 0xFFFF)   # CCCID, TTAG
    hdr += struct.pack('<I', datao & 0xFFFFFFFF)            # Data Offset
    hdr += struct.pack('<I', datal & 0xFFFFFFFF)            # Data Length
    hdr += bytes(4)                                         # reserved
    assert len(ch) + len(hdr) == NVME_TCP_DATA_PDU_SIZE

    unit = ch + hdr
    if hdgst:
        unit += struct.pack('<I', crc32c(unit))
    unit += pad + payload
    if ddgst:
        value = crc32c(payload)
        if corrupt_ddgst:
            value ^= 0xFFFFFFFF
        unit += struct.pack('<I', value)
    assert len(unit) == plen
    return unit


def r2t_pdu(cid, ttag, r2to, r2tl):
    """Ready to Transfer PDU (NVMe/TCP 1.3 Figure 34): a fixed 24-byte header --
    the common header then CCCID, TTAG, R2TO, R2TL and four reserved bytes."""
    ch = struct.pack('<BBBBI', NVME_TCP_R2T, 0x00, NVME_TCP_R2T_PDU_SIZE, 0x00,
                     NVME_TCP_R2T_PDU_SIZE)
    body = struct.pack('<HHII', cid & 0xFFFF, ttag & 0xFFFF,
                       r2to & 0xFFFFFFFF, r2tl & 0xFFFFFFFF) + bytes(4)
    assert len(ch) + len(body) == NVME_TCP_R2T_PDU_SIZE
    return ch + body


# ---------------------------------------------------------------------------
# nvme-tcp-h2c-digest.pcapng - the write direction's data digest and its
# padding
# ---------------------------------------------------------------------------
#
# The counterpart of build_data_offset() for the two PDU types that carry a data
# digest host to controller.  NVMe/TCP 1.3 section 3.3 makes PDU PAD bytes
# reserved and protected by neither digest, and section 3.3.1.1 names the three
# PDUs that carry one: a Command Capsule with in-capsule data, H2CData and
# C2HData.  Only the last had its digest range resolved from the PDU Data
# Offset; the other two checksummed what was left after the header and its
# digest, which is the padding length too many bytes -- over the data digest
# itself where the pad is four bytes, off the end of the PDU where it is eight.
#
# One TCP connection, ten frames.  The write is 160 bytes, transferred as five
# 32-byte windows, so every H2CData frame is a distinct slice of one buffer and
# the five Data Offsets sum to exactly the R2T's R2TL.
#
#   F1  CapsuleCmd, Fabrics Connect, QID 0     fixes the queue as the admin queue,
#                                             where the shared data path renders
#                                             the block's bytes as nvme.data --
#                                             so the span that is checksummed is
#                                             also the span a test can read
#   F2  CapsuleCmd, Firmware Image Download    the command the data belongs to,
#       with a Command Data Buffer SGL        an Admin opcode whose data travels
#                                             host to controller
#   F3  R2T, TTAG 1, R2TO 0, R2TL 160          the controller asks for it
#   F4  H2CData, PDO 32, DATAO 0,   DDGST      eight pad bytes: the old range ran
#                                             over the digest and past the PDU
#   F5  H2CData, PDO 32, DATAO 32,  both       four pad bytes, because the header
#                                             digest takes four of them: the old
#                                             range ended exactly on the digest
#   F6  H2CData, PDO 24, DATAO 64,  DDGST      unpadded control: both ranges agree
#   F7  H2CData, PDO 32, DATAO 96,  DDGST      the same shape as F4 with a
#                                             deliberately wrong digest
#   F8  H2CData, PDO 0,  DATAO 128, no digest  the legacy shape: a sender that
#                                             leaves the PDU Data Offset zero
#                                             describes no span, so the
#                                             bytes are shown at offset 0
#   F9  CapsuleCmd, the same command with 32 bytes of in-capsule data, PDO 80,
#       DDGST
#                                             the second vector: Figure 30 has
#                                             no data-length field, so the span
#                                             comes from PLEN, PDO and the digest
#   F10 the same, with a deliberately wrong digest
#
# The padding is 0xEE, so a digest computed over a range that includes it cannot
# accidentally match.

H2C_HOST_PORT = 55400
H2C_XFER_LEN = 160
H2C_WINDOW = 32
H2C_INCAPSULE_LEN = 32

# Distinct per-byte values so a range read from the wrong place is visible.
H2C_PAYLOAD = bytes(((i * 7 + 11) & 0xFF) for i in range(H2C_XFER_LEN))
H2C_INCAPSULE = bytes(((i * 11 + 5) & 0xFF) for i in range(H2C_INCAPSULE_LEN))

# SGL Descriptor Sub Type 1h is in-capsule data; a Transport SGL Data Block with
# Sub Type Ah is the Command Data Buffer the R2T/H2CData exchange fills
# (NVMe/TCP 1.3 section 3.3).
SGL_SUB_IN_CAPSULE = 0x1
SGL_SUB_CMD_DATA_BUFFER = 0xA


def build_h2c_digest():
    conn = Conn(0xA000, 1_701_000_000_000_000, H2C_HOST_PORT)

    def emit(pdu, to_ctrl=True):
        conn.emit(to_ctrl, pdu)

    emit(capsule_cmd_pdu(connect_sqe(cid=1, qid=0)))

    # Firmware Image Download (NVMe Base 2.3 section 5.1.5): CDW10 NUMD is the
    # number of dwords to transfer, 0's based; CDW11 OFST is the offset in
    # dwords.
    download = sqe(AQ_FW_IMG_DOWNLOAD, cid=1,
                   cdw10=(H2C_XFER_LEN // 4) - 1, cdw11=0)
    emit(capsule_cmd_pdu(sqe_with_sgl(download, sgl_descriptor(
        0x5, SGL_SUB_CMD_DATA_BUFFER, struct.pack('<Q', 0),
        H2C_XFER_LEN, bytes(3)))))
    emit(r2t_pdu(cid=1, ttag=1, r2to=0, r2tl=H2C_XFER_LEN), to_ctrl=False)

    # (Data Offset, PDU Data Offset, kwargs)
    windows = (
        (0,   32, {'ddgst': True}),
        (32,  32, {'hdgst': True, 'ddgst': True}),
        (64,  24, {'ddgst': True}),
        (96,  32, {'ddgst': True, 'corrupt_ddgst': True}),
        (128, 0,  {'last': True}),
    )
    for datao, pdo, kw in windows:
        emit(h2c_data_pdu(cid=1, payload=H2C_PAYLOAD[datao:datao + H2C_WINDOW],
                          datao=datao, pdo=pdo, **kw))

    for cid, corrupt in ((2, False), (3, True)):
        incapsule = sqe_with_sgl(
            sqe(AQ_FW_IMG_DOWNLOAD, cid=cid,
                cdw10=(H2C_INCAPSULE_LEN // 4) - 1, cdw11=0),
            sgl_descriptor(0x0, SGL_SUB_IN_CAPSULE, struct.pack('<Q', 0),
                           H2C_INCAPSULE_LEN, bytes(3)))
        emit(capsule_cmd_pdu(incapsule, data=H2C_INCAPSULE, pdo=80, ddgst=True,
                             corrupt_ddgst=corrupt))

    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F14-F17 (build_logpage_datal) - a lying DATAL on a log
# page
# ---------------------------------------------------------------------------
#
# DATAL is read straight off the C2HData PDU by dissect_nvme_tcp_data_pdu() and
# handed to dissect_nvme_data_response() as the response length, while the
# payload tvb is only a tvb_new_subset_remaining().  The per-structure decoders
# in packet-nvme.c all bound their fields on that length, so a DATAL larger than
# the bytes actually sent must be clamped to them.
#
# SMART (LID 02h) is deliberately an ordinary log page: the clamp has to hold
# for every LID, not just the ones whose decoders were hardened individually,
# and this is by construction the coverage for the whole shared admin data
# path being reached from NVMe/TCP rather than from NVMe-MI.
#
#   Frame 1  Identify (06h)                     -> pins the queue as admin
#   Frame 2  Get Log Page (02h), LID=02h        -> request
#   Frame 3  C2HData, 200 bytes, honest DATAL   -> the reference field set
#   Frame 4  C2HData, the same 200 bytes, DATAL=512 (the full page)
#
# Frames 3 and 4 carry byte-identical payloads, so any difference between their
# dissections is caused solely by the wire-declared length.

NVME_LID_SMART = 0x02
SMART_FULL_LEN = 512
SMART_SENT_LEN = 200

# Distinct per-byte values so a field read at the wrong offset is visible.
SMART_LOG_PAGE = bytes(((i * 5 + 3) & 0xFF) for i in range(SMART_FULL_LEN))


def build_logpage_datal():
    conn = Conn(0x3000, 1_700_200_000_000_000)
    sent = SMART_LOG_PAGE[:SMART_SENT_LEN]
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001)))
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=2,
                                        cdw10=NVME_LID_SMART |
                                        (((SMART_FULL_LEN // 4) - 1) << 16))))
    for datal in (None, SMART_FULL_LEN):
        conn.emit(False, c2h_data_pdu(cid=2, payload=sent, datal=datal))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F77-F82 (build_ana_redecode) - the first window of an
# ANA log read decodes the same on every pass
# ---------------------------------------------------------------------------
#
# The ANA log decoder carries its descriptor walk from one C2HData PDU of a
# command to the next in the per-command context.  That context outlives the
# first pass, so a second pass (tshark -2, or a GUI click) must not reach the
# DATAO 0 window holding the state the last window left.  "The first C2HData
# PDU of a command shall start with an offset of zero" (NVMe/TCP 1.3 3.3.2.1),
# so that window always starts at the page header.
#
# Page (NVMe Base 2.3 Figures 227/228): header CHGC 5, NAGD 2; Descriptor 0 =
# AGID 1, NNV 3, CHGC 7, ANAS 01h, NSIDs 1,2,3 (44 bytes); Descriptor 1 =
# AGID 2, NNV 1, CHGC 8, ANAS 02h, NSID 9 (36 bytes); 96 bytes in all.
#
#   Frame 1  Identify (06h) CID 1               -> pins the queue as admin
#   Frame 2  Get Log Page CID 2, LID 0Ch, 56 bytes
#   Frame 3  C2HData CID 2, DATAO 0, page[0:56] (ends inside Descriptor 0's
#            NSID list)
#   Frame 4  Get Log Page CID 3, LID 0Ch, 96 bytes
#   Frame 5  C2HData CID 3, DATAO 0, page[0:56]
#   Frame 6  C2HData CID 3, DATAO 56, page[56:96] -- continues the walk

NVME_LID_ANA = 0x0C


def build_ana_redecode():
    conn = Conn(0x3100, 1_700_210_000_000_000)
    hdr = struct.pack('<QH6x', 5, 2)
    d0 = struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
    d1 = struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)
    page = hdr + d0 + d1

    def host(s):
        conn.emit(True, capsule_cmd_pdu(s))

    def ctrl(cid, datao, payload):
        # PDO names where the data starts, so the window's DATAO placement
        # is known and frame 6 continues frame 5's walk.
        conn.emit(False, c2h_data_pdu(cid=cid, payload=payload, datao=datao,
                                      pdo=NVME_TCP_DATA_PDU_SIZE))

    host(sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001))
    host(sqe(AQ_GET_LOG_PAGE, cid=2,
             cdw10=NVME_LID_ANA | (((56 // 4) - 1) << 16)))
    ctrl(2, 0, page[:56])
    host(sqe(AQ_GET_LOG_PAGE, cid=3,
             cdw10=NVME_LID_ANA | (((len(page) // 4) - 1) << 16)))
    ctrl(3, 0, page[:56])
    ctrl(3, 56, page[56:])
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F17-F25 (build_data_offset) - PDU data origin: physical
# span and logical placement are two different coordinates
# ---------------------------------------------------------------------------
#
# A C2HData PDU says two separate things about the bytes it carries.  The
# common header's PDU Data Offset (NVMe/TCP 1.3 Figure 25 byte 3) says where
# they start *inside the PDU*, after the 24-byte header, any header digest and
# any alignment padding the controller inserted for the host's negotiated PDU
# Data Alignment (Figure 26).  The C2HData header's Data Offset field
# (Figure 33 bytes 15:12) says where they belong *in the command's data
# buffer*.  Reading a field that lives at a fixed logical offset needs both:
# the wrong physical start reads padding, and the wrong logical placement reads
# the wrong part of the structure.
#
# Identify Controller (CNS 01h) is the vehicle because its Version field sits
# at logical bytes 83:80 (NVMe Base 2.3 Figure 328 / 2.4 Figure 338) -- far
# enough into the structure that a transfer split across blocks puts it in a
# later one, at a local offset that only the Data Offset field can supply.
#
#   Frame 1  Identify (06h), CNS 01h            -> the request every block
#                                                  below associates with
#   Frame 2  C2HData, PDU Data Offset 24, Data Offset 0, 64 bytes
#            an unpadded control: the physical start is the first byte after
#            the header, exactly where every capture written before this one
#            put it, and the logical origin is the start of the structure
#   Frame 3  C2HData, PDU Data Offset 32, Data Offset 64, 32 bytes
#            eight bytes of padding, then logical bytes 95:64 -- so the
#            Version field is at local offset 16 and nowhere else.  Read from
#            the header instead of the padded start, local 16 lands in the
#            payload's Firmware Revision bytes; read at logical offset zero it
#            is not read at all
#   Frame 4  C2HData, PDU Data Offset 32, Data Offset 128, 32 bytes
#            the same padded shape, a later window.  Logical bytes 159:128
#            contain no Version field, and its bytes at local 83:80 are
#            unrelated -- a block placed at offset zero would read them as one
#            and overwrite what frame 3 established
#   Frame 5  C2HData, PDU Data Offset 0, Data Offset 80, 4 bytes
#            the legacy shape: a sender that leaves the PDU Data Offset zero
#            describes no physical span at all.  The best-effort
#            rendering stays -- the bytes are still shown, still read
#            from immediately after the header and still placed at offset zero
#            -- but the PDU has not said where they are, so nothing may be
#            attributed to a specification field from them.  Had its zero been
#            taken at face value, the Version field would have decoded here
#
# The padding is 0xEE rather than zeroes so that a decoder reading it produces
# a visibly wrong value instead of a plausible-looking zero.

# Identify Controller data structure bytes, laid out so every window below is
# a real slice of one structure.
IDCTRL_VER = 0x00020300          # 2.3.0, as the Version field encodes it

def _identify_ctrl_bytes():
    b = bytearray(160)
    struct.pack_into('<H', b, 0, 0x1B36)              # VID
    struct.pack_into('<H', b, 2, 0x1AF4)              # SSVID
    b[4:24] = b'SN0123456789ABCDEFGH'                 # SN
    b[24:64] = b'ORIGIN MODEL'.ljust(40, b' ')        # MN
    b[64:72] = b'FR1.02  '                            # FR
    b[72] = 0x03                                      # RAB
    b[73:76] = bytes((0x00, 0xA0, 0x98))              # IEEE
    b[76] = 0x02                                      # CMIC
    b[77] = 0x07                                      # MDTS
    struct.pack_into('<H', b, 78, 0x0001)             # CNTLID
    struct.pack_into('<I', b, 80, IDCTRL_VER)         # VER
    struct.pack_into('<I', b, 84, 0x00030D40)         # RTD3R
    struct.pack_into('<I', b, 88, 0x000186A0)         # RTD3E
    struct.pack_into('<I', b, 92, 0x00000200)         # OAES
    struct.pack_into('<I', b, 96, 0x00000001)         # CTRATT
    # 128:129 CRDT1, then the rest of this window.  The bytes at 131:128 are
    # deliberately the byte-swapped Version value, so a window read at the
    # wrong logical origin would produce a recognisably wrong descriptor
    # rather than something that could be mistaken for a real one.
    struct.pack_into('<I', b, 128, 0x00030200)
    struct.pack_into('<I', b, 132, 0xA5A5A5A5)
    return bytes(b)

IDCTRL = _identify_ctrl_bytes()

IDENTIFY_CNS_CTRL = 0x01


def build_data_offset():
    conn = Conn(0x9000, 1_700_800_000_000_000)
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=7,
                                        cdw10=IDENTIFY_CNS_CTRL)))

    blocks = (
        # (payload, Data Offset field, PDU Data Offset, kwargs)
        (IDCTRL[0:64],    0,   NVME_TCP_DATA_PDU_SIZE, {}),
        (IDCTRL[64:96],   64,  32, {}),
        (IDCTRL[128:160], 128, 32, {}),
        (IDCTRL[80:84],   80,  0,  {}),
        # F6-F9, appended so the five frames above keep their bytes and order.
        #
        # The data digest is where the two coordinates stop being a display
        # question.  It protects the data and nothing else -- not the padding
        # in front of it, not itself -- so it can only be checked over the
        # resolved span.  Checking the leftover count from the data start
        # instead reads past a unit whose padding is eight bytes, and over the
        # digest itself where it is four.
        #
        # F6  padded, data digest, no header digest      8 bytes of padding
        # F7  padded, both digests                       4 bytes of padding,
        #                                                so the header digest
        #                                                moves the data start
        # F8  unpadded control, data digest              padding length zero
        # F9  padded, deliberately wrong data digest     the negative control
        (IDCTRL[64:96],   64,  32, {'ddgst': True}),
        (IDCTRL[64:96],   64,  32, {'hdgst': True, 'ddgst': True}),
        (IDCTRL[0:64],    0,   NVME_TCP_DATA_PDU_SIZE, {'ddgst': True}),
        (IDCTRL[64:96],   64,  32, {'ddgst': True, 'corrupt_ddgst': True}),
    )
    for payload, datao, pdo, kw in blocks:
        conn.emit(False, c2h_data_pdu(cid=7, payload=payload, datao=datao,
                                      pdo=pdo, **kw))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-truncated.pcapng - a genuinely snaplen-sliced C2HData response
# ---------------------------------------------------------------------------
#
# The counterpart to build_logpage_datal.  There the declared length
# is a lie about bytes that were never sent, and the dissector must decode what
# arrived without complaint.  Here the declared length is honest and the
# *capture* is short, which Wireshark reports as
# [Packet size limited during capture] for every other protocol.
#
# The two are only distinguishable because dissect_nvme_data_response() clamps
# the transport's declared length to tvb_reported_length() rather than to
# tvb_captured_length(): the reported length still counts the sliced-off bytes,
# so the decoders read into them and throw BoundsError.  Clamping to the
# captured length instead silently renders a short frame as a complete one.
#
#   Frame 1  Identify (06h)                     -> pins the queue as admin
#   Frame 2  Get Log Page (02h), LID=02h        -> request
#   Frame 3  C2HData, 200 bytes, fully captured -> control: SMART decodes
#   Frame 4  the same frame, stored with 100 of its 200 payload bytes
#
# Frames 3 and 4 are byte-identical on the wire and carry an identical honest
# DATAL; they differ only in the EPB's Captured/Original Packet Length pair, so
# any difference between their dissections is caused solely by the capture
# slice.  The Interface Description Block keeps its 65535 snaplen: Wireshark
# derives the per-frame captured/reported split from the EPB, not the IDB.

TRUNC_KEPT_PAYLOAD = 100


def build_truncated():
    conn = Conn(0x5000, 1_700_400_000_000_000)
    sent = SMART_LOG_PAGE[:SMART_SENT_LEN]
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001)))
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=2,
                                        cdw10=NVME_LID_SMART |
                                        (((SMART_FULL_LEN // 4) - 1) << 16))))
    pdu = c2h_data_pdu(cid=2, payload=sent)
    conn.emit(False, pdu)
    frame = conn.segment(False, pdu)
    conn.write(frame, len(frame) - (SMART_SENT_LEN - TRUNC_KEPT_PAYLOAD))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F11-F13 (build_discovery) - a Discovery response longer
# than NUMREC claims
# ---------------------------------------------------------------------------
#
# The Discovery Log Page (NVMe Base 2.3 Figure 312) is a 1024-byte header whose
# NUMREC field at bytes 15:08 counts the Discovery Log Entries that follow, each
# also 1024 bytes.  dissect_nvme_get_logpage_ify_resp() renders the first entry
# unconditionally and then loops "while (len && rcrd_ctr <= recnum)" with
# rcrd_ctr already at 1, so it rendered NUMREC + 1 entries whenever the response
# carried the bytes for them -- e.g. a host that asks for a fixed window rather
# than sizing the request from a previous NUMREC.
#
#   Frame 1  Identify (06h)                 -> pins the queue as admin (qid 0)
#   Frame 2  Get Log Page (02h), LID=70h    -> request for the full 3072 bytes
#   Frame 3  C2HData: NUMREC=1, two entries -> only DLE0 is real
#
# The two entries carry different Transport Types so "which entries rendered"
# is answerable by value and not just by count.

NVME_LID_DISCOVERY = 0x70
DISCOVERY_HDR_LEN = 1024
DISCOVERY_RCRD_LEN = 1024


def discovery_log_page(numrec, nentries):
    """Discovery log page header plus `nentries` Discovery Log Entries.

    `numrec` is what the header claims; `nentries` is how many are actually
    appended.  They differ for the over-long response this fixture is for.
    TRTYPE (byte 0 of each entry) is 3h TCP for DLE0 and 1h RDMA for DLE1, so a
    spurious extra entry is identifiable rather than merely counted.

    TREQ (byte 03) and EFLAGS (bytes 11:10) carry every sub-field set to a
    distinct non-zero value, per NVMe Base 2.3 Figure 310:
      TREQ 1Dh   -> TSC 01b (Required), SQFCD 1, ZHIDS 1, TASC 01b
      EFLAGS 7h  -> DUPRETINFO 1, EPCSD 1, NCC 1
    Both were decoded against the pre-2.0 layout, which had a 1-bit secure
    channel flag with SQ flow control on bit 1 and no NCC bit at all."""
    h = bytearray(DISCOVERY_HDR_LEN)
    struct.pack_into('<Q', h, 0, 0x1122334455667788)   # 07:00 GENCTR
    struct.pack_into('<Q', h, 8, numrec)               # 15:08 NUMREC
    struct.pack_into('<H', h, 16, 1)                   # 17:16 RECFMT
    out = bytes(h)
    for i in range(nentries):
        r = bytearray(DISCOVERY_RCRD_LEN)
        r[0] = 0x03 if i == 0 else 0x01                # TRTYPE: TCP / RDMA
        r[1] = 0x01                                    # ADRFAM: IPv4
        r[2] = 0x02                                    # SUBTYPE: NVM subsystem
        r[3] = 0x1D                                    # 03 TREQ
        struct.pack_into('<H', r, 4, 0x1000 + i)       # 05:04 PORTID
        struct.pack_into('<H', r, 6, 0x2000 + i)       # 07:06 CNTLID
        struct.pack_into('<H', r, 8, 128)              # 09:08 ASQSZ
        struct.pack_into('<H', r, 10, 0x0007)          # 11:10 EFLAGS
        out += bytes(r)
    return out


def build_discovery():
    conn = Conn(0x4000, 1_700_300_000_000_000)
    log = discovery_log_page(numrec=1, nentries=2)
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001)))
    conn.emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=2,
                                        cdw10=NVME_LID_DISCOVERY |
                                        (((len(log) // 4) - 1) << 16))))
    conn.emit(False, c2h_data_pdu(cid=2, payload=log))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F9-F10 (build_css) - CC.CSS decoded against the current
# Base 2.3 enum
# ---------------------------------------------------------------------------
#
# css_table mapped CC.CSS (bits 06:04 of Controller Configuration) as 0h="NVM
# IO Command Set", 1h="Admin Command Set Only".  Base 2.3 Figure 41 makes 1h
# Reserved and puts the two legal non-zero settings at 110b (All Supported
# I/O Command Sets) and 111b (Admin Command Set Only, the normal setting for
# an Administrative or Discovery controller) -- both of which rendered
# "Unknown".  A Fabrics Property Set command carries the value to write in
# the request itself (NVMe Base 2.3 section 6), so this needs no paired
# response: a single request frame per CSS value is a complete, self-
# contained decode.  This is Fabrics-only (Fabrics opcode 7Fh is Prohibited
# over NVMe-MI), so NVMe/TCP is the only place this table is reachable from.
#
#   Frame 1  Fabrics Property Set (7Fh, FCTYPE 00h), offset 14h (CC),
#            value 60h -> CSS = 110b (All Supported I/O Command Sets)
#   Frame 2  Same, value 70h -> CSS = 111b (Admin Command Set Only)

FCTYPE_PROP_SET = 0x00
PROP_OFFSET_CC = 0x14


def build_css():
    conn = Conn(0x6000, 1_700_500_000_000_000)
    for cid, cc in ((1, 0x00000060), (2, 0x00000070)):
        conn.emit(True, capsule_cmd_pdu(sqe(FABRICS_OPC, cid=cid,
                                            nsid=FCTYPE_PROP_SET,
                                            cdw10=0x00000000,
                                            cdw11=PROP_OFFSET_CC, cdw12=cc)))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F1-F7 (build_ioq_cqe) - the Admin CQE Dword 0 decoder must
# not run on an I/O completion
# ---------------------------------------------------------------------------
#
# Admin and I/O opcodes share one numbering space, so a completion cannot be
# decoded from its opcode alone.  09h is Set Features on the Admin queue and
# Dataset Management on an I/O queue; 0Ch is Asynchronous Event Request and
# Verify.  dissect_nvme_cqe() ran nvme_dissect_admin_cqe_dw0() on every
# completion, so an I/O completion was decoded against the Admin meaning of its
# opcode while COL_INFO, which has always been queue-aware, named the I/O one
# in the same frame.
#
# Nothing populates cmd_ctx->cmd_ctx for an I/O command either (dissect_nvme_cmd
# only fills it on the Admin arm), so the Set Features arm read a Feature
# Identifier that was never on the wire.
#
# Two TCP connections, so the file carries both queues and the *same* CQE
# Dword 0 can be shown decoding differently on each:
#
#   Connection A, host port 55000 -- Admin queue (qid 0)
#     Frame 1  Asynchronous Event Request (0Ch)  -> 0Ch with NSID 0h, so
#                                                   nvme_cmd_implies_admin_queue()
#                                                   pins the queue to admin
#     Frame 2  CapsuleResponse, DW0 = 00080202h  -> the control: the Async Event
#                                                   subtree is correct here and
#                                                   must survive the fix
#
#   Connection B, host port 55001 -- I/O queue (qid 1)
#     Frame 3  Fabrics Connect (7Fh/01h) QID=1   -> sets the queue id explicitly
#                                                   rather than relying on the
#                                                   opcode heuristic, which does
#                                                   not list Verify
#     Frame 4  Verify (0Ch)
#     Frame 5  CapsuleResponse, DW0 = 00080202h  -> the same dword, shown
#                                                   plain, with no Async Event
#                                                   subtree
#     Frame 6  Dataset Management (09h)
#     Frame 7  CapsuleResponse, same DW0, status SCT=1h SC=0Eh -> no "Set
#                                                   Features Error Specific
#                                                   Code"; the status is
#                                                   non-zero because only then
#                                                   would the Set Features arm
#                                                   differ from the plain dword.
#
# DW0 08 02 02h is AET 010b (Notice), AEI 02h (Telemetry Log Changed), Log Page
# Identifier 08h -- a fully populated Async Event.

NVME_TCP_RSP = 0x05
NVME_TCP_RSP_PDU_SIZE = 24

FCTYPE_CONNECT = 0x01

AQ_ASYNC_EVE_REQ = 0x0C
IOQ_DATASET_MGMT = 0x09
IOQ_VERIFY       = 0x0C

# AET 010b Notice | AEI 02h Telemetry Log Changed | LPI 08h
IOQ_CQE_DW0 = (0x08 << 16) | (0x02 << 8) | 0x02

# CQE status word: Phase(0) | SC(8:1) | SCT(11:9).  SCT 1h Command Specific,
# SC 0Eh -- non-zero, which is what makes the Set Features arm visible.
IOQ_CQE_STATUS_ERR = (0x0E << 1) | (0x1 << 9)


def capsule_resp_pdu(cid, dw0=0, dw1=0, sqhd=0, sqid=0, status=0):
    """Controller-to-host CapsuleResponse: the 8-byte common header then the
    16-byte CQE (DW0, DW1, SQHD, SQID, CID, Status)."""
    ch = struct.pack('<BBBBI', NVME_TCP_RSP, 0x00,
                     NVME_TCP_RSP_PDU_SIZE, 0x00, NVME_TCP_RSP_PDU_SIZE)
    cqe = struct.pack('<IIHHHH', dw0, dw1, sqhd, sqid, cid, status)
    assert len(ch) + len(cqe) == NVME_TCP_RSP_PDU_SIZE
    return ch + cqe


NVME_TCP_ICREQ = 0x00
NVME_TCP_ICRESP = 0x01
NVME_TCP_IC_PDU_SIZE = 128
IC_MAXH2CDATA = 0x20000


def ic_pdu(pdu_type, last_dword):
    """ICReq (NVMe/TCP 1.3 Figure 26) or ICResp (Figure 27): HLEN and PLEN
    both 128, PFV 0, HPDA/CPDA 0, no digests, then MAXR2T (ICReq) or
    MAXH2CDATA (ICResp) at bytes 15:12."""
    ch = struct.pack('<BBBBI', pdu_type, 0x00, NVME_TCP_IC_PDU_SIZE, 0x00,
                     NVME_TCP_IC_PDU_SIZE)
    psh = struct.pack('<HBBI', 0, 0, 0, last_dword)
    return ch + psh + bytes(NVME_TCP_IC_PDU_SIZE - len(ch) - len(psh))


def icreq_pdu():
    return ic_pdu(NVME_TCP_ICREQ, 0)                # MAXR2T 0: one R2T


def icresp_pdu():
    return ic_pdu(NVME_TCP_ICRESP, IC_MAXH2CDATA)


def connect_sqe(cid, qid, recfmt=0, sqsize=127):
    """Fabrics Connect (NVMe Base 2.3 Figure 587): RECFMT at SQE bytes 41:40 and
    QID at 43:42 -- the two halves of Command Dword 10 -- with SQSIZE in the low
    half of Dword 11."""
    return sqe(FABRICS_OPC, cid=cid, nsid=FCTYPE_CONNECT,
               cdw10=((qid & 0xFFFF) << 16) | (recfmt & 0xFFFF),
               cdw11=sqsize & 0xFFFF)


IOQ_HOST_PORT = 55001


def build_ioq_cqe():
    conn = Conn(0x7000, 1_700_600_000_000_000)

    def emit(host_port, pdu, to_ctrl):
        conn.emit(to_ctrl, pdu, host_port)

    # Connection A: admin queue
    emit(HOST_PORT, capsule_cmd_pdu(sqe(AQ_ASYNC_EVE_REQ, cid=1)), True)
    emit(HOST_PORT, capsule_resp_pdu(cid=1, dw0=IOQ_CQE_DW0), False)

    # Connection B: I/O queue
    emit(IOQ_HOST_PORT, capsule_cmd_pdu(connect_sqe(cid=1, qid=1)), True)
    emit(IOQ_HOST_PORT, capsule_cmd_pdu(sqe(IOQ_VERIFY, cid=2, nsid=1)), True)
    emit(IOQ_HOST_PORT, capsule_resp_pdu(cid=2, dw0=IOQ_CQE_DW0), False)
    emit(IOQ_HOST_PORT, capsule_cmd_pdu(sqe(IOQ_DATASET_MGMT, cid=3, nsid=1)), True)
    emit(IOQ_HOST_PORT, capsule_resp_pdu(cid=3, dw0=IOQ_CQE_DW0,
                                         status=IOQ_CQE_STATUS_ERR), False)
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F18-F25 (build_aer_immediate) - the Immediate and
# One-Shot Asynchronous Event Information enumerations
# ---------------------------------------------------------------------------
#
# NVMe Base 2.3 Figure 150 selects the Asynchronous Event Information table
# from the Asynchronous Event Type: 011b is Immediate (Figure 156) and 100b is
# One-Shot (Figure 157).  nvme_dissect_admin_cqe_dw0() decoded neither, so both
# enumerations rendered as the bare AEI byte -- including Immediate 00h, NVM
# Subsystem Normal Shutdown, which is what a controller reports once it has
# processed an NVMe-MI Shutdown command.
#
# Four Asynchronous Event Request commands and their completions on one admin
# connection.  The AEI values are chosen so that decoding an event against the
# wrong table cannot produce the right string: 00h and 01h mean different
# things in the two tables, and 02h is Power Threshold Exceeded in One-Shot but
# reserved in Immediate.
#
#   F1/F2  AET 011b AEI 00h -> NVM Subsystem Normal Shutdown
#   F3/F4  AET 011b AEI 01h -> Temperature Threshold Hysteresis Recovery
#   F5/F6  AET 100b AEI 00h -> Controller Data Queue Tail Pointer
#   F7/F8  AET 100b AEI 02h -> Power Threshold Exceeded

AET_IMMEDIATE = 0x3
AET_ONE_SHOT  = 0x4


def aev_dw0(aet, aei, lid=0):
    """Asynchronous Event Request CQE Dword 0 (NVMe Base 2.3 Figure 150):
    AET in bits 02:00, Reserved in 07:03, AEI in 15:08, LID in 23:16."""
    return ((lid & 0xFF) << 16) | ((aei & 0xFF) << 8) | (aet & 0x7)


def build_aer_immediate():
    conn = Conn(0x8000, 1_700_700_000_000_000)
    events = (
        (AET_IMMEDIATE, 0x00),
        (AET_IMMEDIATE, 0x01),
        (AET_ONE_SHOT,  0x00),
        (AET_ONE_SHOT,  0x02),
    )
    for cid, (aet, aei) in enumerate(events, 1):
        conn.emit(True, capsule_cmd_pdu(sqe(AQ_ASYNC_EVE_REQ, cid=cid)))
        conn.emit(False, capsule_resp_pdu(cid=cid, dw0=aev_dw0(aet, aei)))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F8-F11 (build_ioq_noconnect) - the queue-type guess when
# no Connect was captured
# ---------------------------------------------------------------------------
#
# dissect_nvme_tcp_command() guesses the queue type from the commands on a
# connection whose Fabrics Connect was never captured:
#
#     if ((queue->n_q_ctx.qid == UINT16_MAX) && !nvme_is_io_queue_opcode(opcode))
#         queue->n_q_ctx.qid = 0;
#
# (now nvme_cmd_implies_admin_queue(); build_ioq_guess has the current rule).
# The guess is one-way and sticky: once pinned to 0 the connection is an Admin
# queue for every later frame.  nvme_is_io_queue_opcode() listed only the
# eleven NVM commands that predate NVMe 1.4, so Verify (0Ch), I/O Management
# Receive (12h), Cancel (18h), Copy (19h) and I/O Management Send (1Dh) were
# all read as evidence of an Admin queue.
#
# 12h is the one of those five that is not *also* an assigned Admin opcode
# (NVM Command Set 1.2 Figure 21 and NVMe Base 2.3 Figure 589 both list it as
# an I/O command; the Admin opcode space leaves 12h unassigned), so guessing
# Admin for it names a Reserved command and mis-decodes everything that
# follows on the same connection.
#
#   Connection A, host port 55000 -- an I/O queue, no Connect
#     F1  I/O Management Receive (12h)  -> named "Reserved (0x12)" before the
#                                          fix, and pins the connection Admin
#     F2  Read (02h), SLBA 2h, NLB 7    -> the consequence: on a connection
#                                          pinned to Admin this decodes as Get
#                                          Log Page and reads LID 02h (SMART)
#                                          out of the Starting LBA
#
#   Connection B, host port 55001 -- an Admin queue, no Connect
#     F3  Asynchronous Event Request (0Ch)
#     F4  Get Log Page (02h), LID 02h   -> the control.  0Ch, 18h and 1Dh
#                                          are I/O opcodes that are also
#                                          assigned Admin opcodes; with NSID
#                                          0h, which no I/O command carries,
#                                          they are the Admin commands.  F3's
#                                          NSID is 0h; read 0Ch as I/O
#                                          regardless and F4 decodes as a
#                                          Read.

IOQ_IO_MGMT_RECV = 0x12
IOQ_READ         = 0x02
IOQ_WRITE        = 0x01

NOCONN_IOQ_PORT = 55000
NOCONN_AQ_PORT  = 55001

NOCONN_SLBA = 0x0000000000000002   # low byte 02h == LID 02h if read as CDW10
NOCONN_NLB0 = 7                    # 0's based: eight logical blocks


def build_ioq_noconnect():
    conn = Conn(0x9000, 1_700_800_000_000_000)

    def emit(host_port, pdu):
        conn.emit(True, pdu, host_port)

    emit(NOCONN_IOQ_PORT, capsule_cmd_pdu(
        sqe(IOQ_IO_MGMT_RECV, cid=1, nsid=1, cdw10=0x00000001)))
    emit(NOCONN_IOQ_PORT, capsule_cmd_pdu(
        sqe(IOQ_READ, cid=2, nsid=1,
            cdw10=NOCONN_SLBA & 0xFFFFFFFF,
            cdw11=(NOCONN_SLBA >> 32) & 0xFFFFFFFF,
            cdw12=NOCONN_NLB0)))
    emit(NOCONN_AQ_PORT, capsule_cmd_pdu(sqe(AQ_ASYNC_EVE_REQ, cid=1)))
    emit(NOCONN_AQ_PORT, capsule_cmd_pdu(
        sqe(AQ_GET_LOG_PAGE, cid=2, cdw10=NVME_LID_SMART)))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F12-F16 (build_sgl_transport) - SGL Entry 1 carrying a
# Transport SGL Data Block descriptor (SGL Descriptor Type 5h)
# ---------------------------------------------------------------------------
#
# dissect_nvme_cmd_sgl()'s switch had cases for types 0h..4h and then fell
# through to the vendor-specific/default no-op, so type 5h -- which is in
# sgl_type_tbl and is therefore *named* on the wire -- rendered nothing below
# the SGL Identifier byte.  NVMe/TCP Transport 1.3 section 3.3.2 makes it the
# Command Data Buffer Descriptor (Sub Type Ah) for every command whose data
# moves outside the capsule, so the transfer size the host asked for was
# invisible on most real frames.
#
# NVMe Base 2.3 Figure 123: 07:00 Reserved, 11:08 Length (LEN), 14:12
# Reserved, 15 SGL Identifier.
#
#   F1  Read (02h) with a type 5h / sub type Ah descriptor.  LEN = 112233h and
#       both Reserved runs are deliberately non-zero and byte-asymmetric, so a
#       Length item reading the wrong four bytes shows a wrong value rather
#       than a zero any offset renders alike.
#   F2  Read with a type 0h / sub type 0h SGL Data Block descriptor -- the
#       control for the case that always worked, and the one where the leading
#       eight bytes are an Address rather than Reserved.
#   F3  Read with a type Fh Vendor Specific descriptor, which stays undecoded:
#       the pin that the new case is type 5h only and did not broaden the
#       default.
#
# F4 rides along on the same capture for an unrelated reason: it is the only
# Read in the corpus whose end-to-end protection tags are non-zero, and the
# two Command Dword 15 halves had their display labels transposed.  NVM
# Command Set 1.2 Figure 57 (Read - Command Dword 15) puts ELBAT at bits
# 15:00 (SQE bytes 61:60) and ELBATM at bits 31:16 (bytes 63:62); the
# dissector's offsets and abbrevs matched that, but nvme.cmd.elbat was
# captioned "... Tag Mask" and nvme.cmd.elbatm "... Tag", so a filter and a
# visual read of the tree gave opposite answers.  Its SGL is type Fh, like
# F3's, so it adds nothing to the SGL censuses above.
#
#   F4  Read whose CDW14 (ELBTL) is 8BADF00Dh, ELBAT is A51Ch and ELBATM is
#       F00Dh -- three distinct values, so a swap of either the labels or the
#       offsets shows.
#
# F5 rides along for the same reason F4 does.  dissect_nvme_rw_cmd() serves
# Read and Write alike, so all three of those fields were captioned with
# Read's Expected names on a Write too.  NVM Command Set 1.2 Figures 73 and 74
# name Write's Dword 14 and Dword 15 fields LBTL, LBAT and LBATM -- no
# "Expected" -- because they are values to be written, not values the
# controller is asked to check.  Its SGL is type Fh like F3's and F4's.
#
#   F5  Write whose CDW14 (LBTL) is C0FFEE11h, LBAT is 1234h and LBATM is
#       BEEFh.  All six values across F4 and F5 are distinct, so neither the
#       Read and Write field sets nor the tag and mask can be confused.

SGL_TRANSPORT_LEN = 0x00112233
SGL_DATA_BLOCK_LEN = 0x00004000

SGL_XPORT_PORT = 55200


def sgl_descriptor(desc_type, sub_type, first8, length, last3):
    """SGL Entry 1, SQE bytes 39:24 (NVMe Base 2.3 Figures 120-123)."""
    return (first8 + struct.pack('<I', length) + last3
            + bytes([((desc_type & 0xF) << 4) | (sub_type & 0xF)]))


def sqe_with_sgl(base, descriptor):
    b = bytearray(base)
    assert len(descriptor) == 16
    b[24:40] = descriptor
    return bytes(b)


def build_sgl_transport():
    conn = Conn(0x9600, 1_700_950_000_000_000, SGL_XPORT_PORT)

    def emit(pdu):
        conn.emit(True, pdu)

    read = sqe(IOQ_READ, cid=1, nsid=1, cdw12=7)
    emit(capsule_cmd_pdu(sqe_with_sgl(read, sgl_descriptor(
        0x5, 0xA, bytes.fromhex('FFEEDDCCBBAA9988'), SGL_TRANSPORT_LEN,
        bytes.fromhex('445566')))))
    emit(capsule_cmd_pdu(sqe_with_sgl(sqe(IOQ_READ, cid=2, nsid=1, cdw12=7),
                                      sgl_descriptor(
        0x0, 0x0, struct.pack('<Q', 0x00007F0011223344), SGL_DATA_BLOCK_LEN,
        bytes.fromhex('000000')))))
    emit(capsule_cmd_pdu(sqe_with_sgl(sqe(IOQ_READ, cid=3, nsid=1, cdw12=7),
                                      sgl_descriptor(
        0xF, 0xF, bytes.fromhex('0102030405060708'), 0x99887766,
        bytes.fromhex('0A0B0C')))))
    # F4: CDW15 = ELBATM:ELBAT = F00D:A51C, CDW14 (EILBRT) = 8BADF00Dh.
    emit(capsule_cmd_pdu(sqe_with_sgl(sqe(IOQ_READ, cid=4, nsid=1, cdw12=7,
                                          cdw14=0x8BADF00D, cdw15=0xF00DA51C),
                                      sgl_descriptor(
        0xF, 0xF, bytes.fromhex('0102030405060708'), 0x99887766,
        bytes.fromhex('0A0B0C')))))
    # F5: the Write forms of the same three fields.  CDW15 = LBATM:LBAT =
    # BEEF:1234, CDW14 (LBTL) = C0FFEE11h.
    emit(capsule_cmd_pdu(sqe_with_sgl(sqe(IOQ_WRITE, cid=5, nsid=1, cdw12=7,
                                          cdw14=0xC0FFEE11, cdw15=0xBEEF1234),
                                      sgl_descriptor(
        0xF, 0xF, bytes.fromhex('0102030405060708'), 0x99887766,
        bytes.fromhex('0A0B0C')))))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F26-F34 (build_c2h_cid_zero) - C2HData for CID 0000h
# beside C2HData whose CID is a CID 0 block's frame number
# ---------------------------------------------------------------------------
#
# nvme_add_data_tr_pkt() keyed a data block by [CCCID, frame], except for
# CCCID 0, which it keyed by [frame] alone (the 0 meant "no RDMA key").  CID
# 0000h is legal (NVMe Base 2.3 Figure 91; only FFFFh is to be avoided), so
# one connection's tree held both shapes, and a frame number F and a CID F
# met at the same top-level node.  The tree walk then read a command context
# as a subtree and allocated through a wild pointer.
#
#   Connection 55030 (the forward order)
#     F1  Read, CID 0
#     F2  C2HData CCCID 0       -> was the leaf [F2]
#     F3  Read, CID = F2's frame
#     F4  C2HData CCCID = F2    -> was [F2, F4], through that leaf: crash
#
#   Connection 55031 (the reverse order)
#     F5  Read, CID = F8's frame
#     F6  C2HData CCCID = F8    -> [F8, F6]: F8 is now a subtree
#     F7  Read, CID 0
#     F8  C2HData CCCID 0       -> was [F8], overwriting that subtree
#     F9  C2HData CCCID = F8, Data Offset 32
#                               -> was [F8, F9], through ctx0: crash; and
#                                  F6 lost its command link on a revisit
#
# Every block must link to its own command on both passes.

C2H_CID0_FWD_PORT = 55030
C2H_CID0_REV_PORT = 55031


def build_c2h_cid_zero(first):
    """`first` is the absolute frame number this section starts at: the
    CIDs that must equal a frame number are computed from it."""

    conn = Conn(0x9A00, 1_701_000_000_000_000)

    def emit(port, pdu, to_ctrl):
        conn.emit(to_ctrl, pdu, port)

    payload = bytes((i * 3 + 1) & 0xFF for i in range(32))

    def command(port, cid):
        emit(port, capsule_cmd_pdu(sqe(IOQ_READ, cid=cid, nsid=1)), True)

    def block(port, cid, datao=0):
        emit(port, c2h_data_pdu(cid=cid, payload=payload, datao=datao), False)

    command(C2H_CID0_FWD_PORT, 0)                     # F1
    block(C2H_CID0_FWD_PORT, 0)                       # F2
    command(C2H_CID0_FWD_PORT, first + 1)             # F3: CID = F2's frame
    block(C2H_CID0_FWD_PORT, first + 1)               # F4
    command(C2H_CID0_REV_PORT, first + 7)             # F5: CID = F8's frame
    block(C2H_CID0_REV_PORT, first + 7)               # F6
    command(C2H_CID0_REV_PORT, 0)                     # F7
    block(C2H_CID0_REV_PORT, 0)                       # F8
    block(C2H_CID0_REV_PORT, first + 7, datao=32)     # F9
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F35-F41 (build_h2c_keyed_sgl) - a Keyed SGL Data Block
# descriptor whose Address matches an H2CData block's tracking key
# ---------------------------------------------------------------------------
#
# NVMe/TCP correlated H2CData by [frame, CCCID] in the queue's data_requests
# tree, which dissect_nvme_cmd_sgl() also fills with a Keyed SGL Data Block
# descriptor's [Address low, Address high, Key, Length].  Keyed SGLs are an
# RDMA mechanism: NVMe/TCP 1.3 section 3.3.2 allows only the SGL Data Block
# (Sub Type 1h) and Transport SGL Data Block (Sub Type Ah) descriptors and
# has the controller reject any other.  A capsule that carries one anyway, with
# an Address of (CID << 32) | frame, walked the four-level key into an H2CData
# leaf, used a command context as a subtree and allocated through a wild
# pointer.
#
#   Connection 55040 (H2CData first)
#     F1  Write, CID 7, Transport SGL
#     F2  H2CData CCCID 7           -> [F2, 7]
#     F3  Write, CID 8, Keyed SGL, Address (7 << 32) | F2
#                                   -> was [F2, 7, Key, Length], through
#                                      that leaf: crash
#
#   Connection 55041 (Keyed SGL first)
#     F4  Write, CID 9, Keyed SGL, Address (10 << 32) | F6
#                                   -> was [F6, 10, Key, Length]
#     F5  Write, CID 10, Transport SGL
#     F6  H2CData CCCID 10          -> [F6, 10], over that subtree
#     F7  Write, CID 11, Keyed SGL, the same Address as F4
#                                   -> was through the F6 leaf: crash
#
# The Keyed SGL fields still decode from the wire, and each H2CData block
# links to its own command on both passes.

H2C_KEYED_FWD_PORT = 55040
H2C_KEYED_REV_PORT = 55041
KEYED_SGL_LEN = 0x123456
KEYED_SGL_KEY = 0xCAFEF00D


def keyed_sgl_descriptor(addr, length, key):
    """Keyed SGL Data Block descriptor, Sub Type 0h (NVMe Base 2.3 Figure
    122): Address 07:00, Length 10:08, Key 14:11, SGL Identifier 15."""
    return (struct.pack('<Q', addr) + struct.pack('<I', length)[:3]
            + struct.pack('<I', key) + bytes([0x40]))


def build_h2c_keyed_sgl(first):
    """`first` is the absolute frame number this section starts at: the
    Addresses that must equal an H2CData key are computed from it."""

    conn = Conn(0x9B00, 1_701_050_000_000_000)

    def emit(port, pdu):
        conn.emit(True, pdu, port)

    payload = bytes((i * 5 + 2) & 0xFF for i in range(64))

    def write(port, cid, descriptor):
        emit(port, capsule_cmd_pdu(sqe_with_sgl(
            sqe(IOQ_WRITE, cid=cid, nsid=1), descriptor)))

    def buffered_write(port, cid):
        write(port, cid, sgl_descriptor(0x5, SGL_SUB_CMD_DATA_BUFFER, bytes(8),
                                        len(payload), bytes(3)))

    def keyed_write(port, cid, cccid, frame):
        write(port, cid, keyed_sgl_descriptor((cccid << 32) | frame,
                                              KEYED_SGL_LEN, KEYED_SGL_KEY))

    def block(port, cid):
        emit(port, h2c_data_pdu(cid=cid, payload=payload, last=True))

    buffered_write(H2C_KEYED_FWD_PORT, 7)                         # F1
    block(H2C_KEYED_FWD_PORT, 7)                                  # F2
    keyed_write(H2C_KEYED_FWD_PORT, 8, 7, first + 1)              # F3
    keyed_write(H2C_KEYED_REV_PORT, 9, 10, first + 5)             # F4
    buffered_write(H2C_KEYED_REV_PORT, 10)                        # F5
    block(H2C_KEYED_REV_PORT, 10)                                 # F6
    keyed_write(H2C_KEYED_REV_PORT, 11, 10, first + 5)            # F7
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F42-F44 (build_nlb_bounds) - the two ends of the Read and
# Write NLB
# ---------------------------------------------------------------------------
#
# NLB is a 0's based value (NVM Command Set 1.2 Figures 53 and 70), so 0000h
# is one logical block and FFFFh is 65,536.  nvme.cmd.nlb was published as
# NLB + 1 in 16 bits, which made FFFFh 0.
#
#   Connection 55050
#     F1  Fabrics Connect, QID 1       -> an I/O queue
#     F2  Read, CID 2, NLB FFFFh        -> was 0
#     F3  Write, CID 3, NLB 0000h

NLB_PORT = 55050
NLB_MAX  = 0xFFFF
NLB_MIN  = 0x0000


def build_nlb_bounds():
    conn = Conn(0x9E00, 1_701_080_000_000_000, NLB_PORT)

    def emit(pdu):
        conn.emit(True, pdu)

    emit(capsule_cmd_pdu(connect_sqe(cid=1, qid=1)))                       # F1
    emit(capsule_cmd_pdu(sqe(IOQ_READ, cid=2, nsid=1, cdw12=NLB_MAX)))     # F2
    emit(capsule_cmd_pdu(sqe(IOQ_WRITE, cid=3, nsid=1, cdw12=NLB_MIN)))    # F3
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F45-F84 (build_ioq_guess) - what shows a connection
# without a captured Connect to be an Admin queue
# ---------------------------------------------------------------------------
#
# Without a Connect, a connection is read as an I/O queue until one of its
# commands shows it is the Admin queue, so a valid I/O command such as Verify
# or Copy must not do so.  A command shows an Admin queue only when no I/O
# queue may carry it (NVMe Base 2.3 Figures 142, 574 and 589, NVM Command Set
# 1.2 Figure 21): an Admin opcode below 80h that no I/O command uses, a
# Property Get or Set, or 0Ch, 18h, 1Dh or 84h with NSID 0h.  Those four
# Admin commands use no NSID (Figure 142), while every I/O command does
# (Figure 589 note 2) and 0h is not a valid one (section 3.2.1.2).
#
#   Connection 55060 -- an I/O queue, no Connect, NSID 1 throughout
#     F1   Read (02h), CID 1, SLBA 2h
#     F2   Write (01h), CID 2
#     F3   Verify (0Ch)                  -> made the queue Admin
#     F4   Copy (19h)
#     F5   Cancel (18h)
#     F6   I/O Management Send (1Dh)
#     F7   Vendor Specific 84h           (Sanitize's Admin opcode)
#     F8   Vendor Specific 90h
#     F9   7Dh, I/O Command Set specific (reserved in Figure 142)
#     F10  Fabrics Authentication Send   (allowed on an I/O queue, Figure 574)
#     F11  Read, CID 11, SLBA 2h         -> was Get Log Page, LID 02h
#     F12  C2HData for CID 11
#     F13  CapsuleResp for CID 11
#
#   Connection 55061 -- an Admin queue, no Connect
#     F14  Get Log Page (02h), CID 1     -> a Read: nothing shows Admin yet
#     F15  Keep Alive (18h), NSID 0h     -> shows the Admin queue
#     F16  C2HData for CID 1             } decoded as F14 was, a Read; they
#     F17  CapsuleResp for CID 1         } were decoded as Get Log Page
#     F18  CapsuleResp for CID 2
#     F19  Get Log Page, CID 3, LID 02h  -> Admin from F15 on
#     F20  C2HData for CID 3
#     F21  CapsuleResp for CID 3
#
#   Connections 55062-55065 -- Admin queues, no Connect.  Each first command
#   is the only evidence, and each Get Log Page (LID 02h, NSID 0h) after it
#   decodes as a Read unless that evidence was taken.
#     F22  Property Get (7Fh, FCTYPE 04h)  -> shows the Admin queue
#     F23  Get Log Page
#     F24  Property Set (7Fh, FCTYPE 00h)  -> shows the Admin queue
#     F25  Get Log Page
#     F26  NVMe-MI Send (1Dh), NSID 0h     -> shows the Admin queue
#     F27  Get Log Page
#     F28  Sanitize (84h), NSID 0h         -> shows the Admin queue
#     F29  Get Log Page
#
#   Connection 55066 -- an I/O queue whose Connect was cut by the snaplen
#     F30  Connect for QID 1, frame cut to 100 bytes: SQE bytes 38 on are not
#          captured, so the QID (SQE byte 42) is unknown -> made the queue Admin
#     F31  Read, CID 2, SLBA 2h
#     F32  CapsuleResp for CID 2
#     F33  Write, CID 3
#
#   Connection 55067 -- an I/O queue
#     F34  Async Event Request / Verify (0Ch), frame cut to 68 bytes: the NSID
#          (SQE bytes 4-7) is not all captured, so it shows nothing
#                                        -> made the queue Admin
#     F35  Read, CID 2, SLBA 2h
#
#   Connection 55068 -- an Admin queue, no Connect: host data follows its
#   command's queue type
#     F36  Set Features (09h), NSID 0h, buffered SGL, 64 bytes, CID 1
#                                        -> a Dataset Management, as F14
#     F37  Keep Alive (18h), NSID 0h     -> shows the Admin queue
#     F38  H2CData for CID 1             } decoded as F36 was; they were
#     F39  CapsuleResp for CID 1         } decoded as Set Features
#     F40  CapsuleResp for CID 2
#
# A second pass decoded F1, F2 and F14 from the queue type the first pass
# ended with, so the two passes differed.

GUESS_IOQ_PORT = 55060
GUESS_AQ_PORT = 55061
GUESS_PROP_GET_PORT = 55062
GUESS_PROP_SET_PORT = 55063
GUESS_MI_SEND_PORT = 55064
GUESS_SANITIZE_PORT = 55065
GUESS_CUT_CONNECT_PORT = 55066
GUESS_CUT_AER_PORT = 55067
GUESS_H2C_PORT = 55068

IOQ_COPY = 0x19
IOQ_CANCEL = 0x18
IOQ_IO_MGMT_SEND = 0x1D
AQ_KEEP_ALIVE = 0x18
AQ_MI_SEND = 0x1D
AQ_SANITIZE = 0x84
FCTYPE_AUTH_SEND = 0x05

# Ethernet 14 + IPv4 20 + TCP 20 + CapsuleCmd header 8: SQE byte 0 is frame
# byte 62.
GUESS_CUT_CONNECT_CAPLEN = 100   # SQE bytes 0-37: the QID is at byte 42
GUESS_CUT_AER_CAPLEN = 68        # SQE bytes 0-5: half the NSID


def build_ioq_guess():
    conn = Conn(0x9F00, 1_701_090_000_000_000)

    def emit(port, to_ctrl, pdu, caplen=None):
        conn.emit(to_ctrl, pdu, port, caplen)

    def command(port, opcode, cid, nsid=1, caplen=None, **cdws):
        emit(port, True,
             capsule_cmd_pdu(sqe(opcode, cid=cid, nsid=nsid, **cdws)), caplen)

    def respond(port, cid, payload=None):
        if payload is not None:
            emit(port, False, c2h_data_pdu(cid=cid, payload=payload,
                                           pdo=NVME_TCP_DATA_PDU_SIZE))
        emit(port, False, capsule_resp_pdu(cid=cid))

    io, aq = GUESS_IOQ_PORT, GUESS_AQ_PORT
    data = bytes(range(64))
    smart = NVME_LID_SMART | (((len(data) // 4) - 1) << 16)

    command(io, IOQ_READ, 1, cdw10=NOCONN_SLBA, cdw12=NOCONN_NLB0)  # F1
    command(io, IOQ_WRITE, 2, cdw10=NOCONN_SLBA)                    # F2
    command(io, IOQ_VERIFY, 3)                                      # F3
    command(io, IOQ_COPY, 4)                                        # F4
    command(io, IOQ_CANCEL, 5)                                      # F5
    command(io, IOQ_IO_MGMT_SEND, 6)                                # F6
    command(io, 0x84, 7)                                            # F7
    command(io, 0x90, 8)                                            # F8
    command(io, 0x7D, 9)                                            # F9
    # A Fabrics command's FCTYPE is SQE byte 4, where other commands carry
    # the NSID, so sqe() takes it through nsid (see FABRICS_OPC).
    command(io, FABRICS_OPC, 10, nsid=FCTYPE_AUTH_SEND)             # F10
    command(io, IOQ_READ, 11, cdw10=NOCONN_SLBA, cdw12=NOCONN_NLB0) # F11
    respond(io, 11, data)                                           # F12-F13

    command(aq, AQ_GET_LOG_PAGE, 1, nsid=0, cdw10=smart)            # F14
    command(aq, AQ_KEEP_ALIVE, 2, nsid=0)                           # F15
    respond(aq, 1, data)                                            # F16-F17
    respond(aq, 2)                                                  # F18
    command(aq, AQ_GET_LOG_PAGE, 3, nsid=0, cdw10=smart)            # F19
    respond(aq, 3, data)                                            # F20-F21

    for port, opcode, nsid in (                                     # F22-F29
            (GUESS_PROP_GET_PORT, FABRICS_OPC, FCTYPE_PROP_GET),
            (GUESS_PROP_SET_PORT, FABRICS_OPC, FCTYPE_PROP_SET),
            (GUESS_MI_SEND_PORT, AQ_MI_SEND, 0),
            (GUESS_SANITIZE_PORT, AQ_SANITIZE, 0)):
        command(port, opcode, 1, nsid=nsid)
        command(port, AQ_GET_LOG_PAGE, 2, nsid=0, cdw10=smart)

    cut = GUESS_CUT_CONNECT_PORT
    emit(cut, True, capsule_cmd_pdu(connect_sqe(cid=1, qid=1)),
         GUESS_CUT_CONNECT_CAPLEN)                                  # F30
    command(cut, IOQ_READ, 2, cdw10=NOCONN_SLBA, cdw12=NOCONN_NLB0) # F31
    respond(cut, 2)                                                 # F32
    command(cut, IOQ_WRITE, 3, cdw10=NOCONN_SLBA)                   # F33

    cut = GUESS_CUT_AER_PORT
    command(cut, AQ_ASYNC_EVE_REQ, 1, nsid=0,
            caplen=GUESS_CUT_AER_CAPLEN)                            # F34
    command(cut, IOQ_READ, 2, cdw10=NOCONN_SLBA, cdw12=NOCONN_NLB0) # F35

    h2c = GUESS_H2C_PORT
    emit(h2c, True, capsule_cmd_pdu(sqe_with_sgl(
        sqe(AQ_SET_FEATURES, cid=1, nsid=0, cdw10=0x07),
        sgl_descriptor(0x5, SGL_SUB_CMD_DATA_BUFFER, bytes(8), len(data),
                       bytes(3)))))                                 # F36
    command(h2c, AQ_KEEP_ALIVE, 2, nsid=0)                          # F37
    emit(h2c, True, h2c_data_pdu(cid=1, payload=data, last=True))   # F38
    respond(h2c, 1)                                                 # F39
    respond(h2c, 2)                                                 # F40
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-plen-zero.pcapng (build_plen_zero) - a PDU header with PLEN 0
# ---------------------------------------------------------------------------
#
# PLEN counts the whole PDU, the 8-byte common header included (NVMe/TCP 1.3
# Figure 25), so 0 is never valid.  tcp_dissect_pdus() reads a PDU length of
# 0 as "one more segment", so a PLEN 0 header held every later segment in
# that direction in a reassembly that never completed.  The heuristic does
# not take a PLEN 0 header for a PDU start (Figure 31), so the connection
# opens with ICReq/ICResp (section 3.1): only they pin it, and once pinned
# every PDU header reaches tcp_dissect_pdus().
#
#   F1  ICReq                              host to controller
#   F2  ICResp                             controller to host
#   F3  Identify, CID 1                    host to controller
#   F4  CapsuleResp common header, PLEN 0  -> malformed (05 00 18 00 00 00 00 00)
#   F5  CapsuleResp, CID 1                 -> was held by F4's reassembly
#   F6  Identify, CID 2                    host to controller
#   F7  CapsuleResp, CID 2                 -> was held by F4's reassembly
#
# F4 is malformed on purpose, so this capture is not in the suite's CAPTURES.

def build_plen_zero():
    conn = Conn(0x9C00, 1_701_060_000_000_000)

    def emit(direction, pdu):
        conn.emit(direction == 'h2c', pdu)

    plen_zero = struct.pack('<BBBBI', NVME_TCP_RSP, 0x00,
                            NVME_TCP_RSP_PDU_SIZE, 0x00, 0)
    emit('h2c', icreq_pdu())                                           # F1
    emit('c2h', icresp_pdu())                                          # F2
    emit('h2c', capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=1)))   # F3
    emit('c2h', plen_zero)                                             # F4
    emit('c2h', capsule_resp_pdu(cid=1, sqhd=1))                       # F5
    emit('h2c', capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=2, cdw10=1)))   # F6
    emit('c2h', capsule_resp_pdu(cid=2, sqhd=2))                       # F7
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-pdu-queue-parity.pcapng (build_pdu_queue_parity) - two PDUs in one
# segment, the second of which shows the queue
# ---------------------------------------------------------------------------
#
# With no Connect captured, a command only an Admin queue takes (Identify)
# makes the queue Admin, and later PDUs follow it.  A PDU decoded before that
# in the same segment is not told apart by the frame, so its queue was the one
# learned later on every pass but the first: Write on the first pass, Create
# I/O Submission Queue after.
#
#   F1  ICReq
#   F2  ICResp
#   F3  opcode 01h CID 1, then Identify CID 2, in one segment
#   F4  CapsuleResp CID 1
#   F5  CapsuleResp CID 2

def build_pdu_queue_parity():
    conn = Conn(0x9E00, 1_701_070_000_000_000)

    conn.emit(True, icreq_pdu())                                       # F1
    conn.emit(False, icresp_pdu())                                     # F2
    conn.emit(True, capsule_cmd_pdu(sqe(0x01, cid=1))
              + capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=2, cdw10=1)))     # F3
    conn.emit(False, capsule_resp_pdu(cid=1, sqhd=1))                  # F4
    conn.emit(False, capsule_resp_pdu(cid=2, sqhd=2))                  # F5
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-ddgst-truncated.pcapng (build_ddgst_truncated) - a data digest the
# capture did not keep
# ---------------------------------------------------------------------------
#
# The data digest is the last field of a PDU that sets DDGSTF (NVMe/TCP 1.3
# Figures 30 and 33).  It was read before the PDU type was dispatched, so when
# it was not captured the read threw and the command or transfer was never
# tracked: the Connect's CQE showed as unknown data and its queue ID was never
# learned, and the C2HData was never linked to its Read.
#
#   F1  Connect, 1024 bytes in-capsule data, DDGST  stored without the digest
#   F2  CapsuleResp for F1
#   F3  Read, CID 2
#   F4  C2HData for F3, 512 bytes, DDGST    stored without 2 digest bytes
#   F5  CapsuleResp for F3
#   F6-F10  the same on a second connection, F6 and F9 stored at 200 bytes,
#           which cuts their data as well
#   F11 F1's PDU without its digest, F12 the digest: two full segments, one
#       PDU, so with TCP reassembly off F11 is a fragment that lacks it
#   F13 CapsuleResp for F11
#
# F11 is a reassembly segment whose Info differs between passes, so this
# capture is not in the suite's CAPTURES.

DDGST_CUT_PORT = 55500
DDGST_SNAP_PORT = 55501
DDGST_SPLIT_PORT = 55502
DDGST_SNAPLEN = 200
DDGST_CONNECT_LEN = 1024
DDGST_READ_LEN = 512
DDGST_CONNECT_DATA = bytes(((i * 7 + 1) & 0xFF)
                           for i in range(DDGST_CONNECT_LEN))
DDGST_READ_DATA = bytes(((i * 5 + 3) & 0xFF) for i in range(DDGST_READ_LEN))


def build_ddgst_truncated():
    conn = Conn(0x9D00, 1_701_070_000_000_000)

    def emit(port, pdu, to_ctrl, cut=0):
        """cut: bytes left off the end of the stored frame, or None for the
        DDGST_SNAPLEN snaplen."""
        frame = conn.segment(to_ctrl, pdu, port)
        conn.write(frame, DDGST_SNAPLEN if cut is None else len(frame) - cut)

    def connect(cid):
        s = sqe_with_sgl(connect_sqe(cid=cid, qid=1),
                         sgl_descriptor(0x0, SGL_SUB_IN_CAPSULE,
                                        struct.pack('<Q', 0),
                                        DDGST_CONNECT_LEN, bytes(3)))
        return capsule_cmd_pdu(s, data=DDGST_CONNECT_DATA, pdo=72, ddgst=True)

    def read(cid):
        return capsule_cmd_pdu(sqe(IOQ_READ, cid=cid, nsid=1,
                                   cdw12=(DDGST_READ_LEN // 512) - 1))

    def data(cid):
        return c2h_data_pdu(cid=cid, payload=DDGST_READ_DATA, pdo=24,
                            ddgst=True)

    for port, cut in ((DDGST_CUT_PORT, (4, 2)),
                      (DDGST_SNAP_PORT, (None, None))):
        emit(port, connect(1), True, cut=cut[0])                # F1 / F6
        emit(port, capsule_resp_pdu(cid=1), False)              # F2 / F7
        emit(port, read(2), True)                               # F3 / F8
        emit(port, data(2), False, cut=cut[1])                  # F4 / F9
        emit(port, capsule_resp_pdu(cid=2, sqhd=1), False)      # F5 / F10
    pdu = connect(1)
    emit(DDGST_SPLIT_PORT, pdu[:-4], True)                      # F11
    emit(DDGST_SPLIT_PORT, pdu[-4:], True)                      # F12
    emit(DDGST_SPLIT_PORT, capsule_resp_pdu(cid=1), False)      # F13
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-security.pcapng: native Security Send/Receive windows
# ---------------------------------------------------------------------------
# Admin Security Send (81h) / Receive (82h) over NVMe/TCP carrying TCG
# ComPackets and Level 0 Discovery data: an Identify first, then whole,
# short, padded and windowed transfers, and data on the wrong half of a
# transaction in each direction.  gen-nvme-mi-test-capture.py appends the same
# frames to nvme-mi-tcg-conformance.pcapng.

AQ_SECURITY_SEND = 0x81
AQ_SECURITY_RECV = 0x82


def security_cdw10(secp, spsp):
    """Security Send/Receive Command Dword 10 (NSSF unused)."""
    return ((secp & 0xff) << 24) | ((spsp & 0xffff) << 8)


def tcg_l0_feature(code, version, data):
    """Level 0 feature descriptor: Code(2) + Version(7:4 of byte 2) + Length."""
    return struct.pack('>HBB', code, (version & 0x0f) << 4, len(data)) + data


def tcg_compacket(payload, comid):
    """ComPacket: Reserved(4) + ComID(2) + Ext(2) + Outstanding(4) +
    MinTransfer(4) + Length(4), then the payload."""
    return struct.pack('>IHHIII', 0, comid, 0, 0, 0, len(payload)) + payload


def security_native_packets():
    """The Ethernet frames of nvme-tcp-security.pcapng, in order."""
    packets = []
    sequence = [1, 1]

    host = (HOST_PORT, HOST_IP, HOST_MAC)
    ctrl = (CTRL_PORT, CTRL_IP, CTRL_MAC)

    def emit(pdu, send):
        side = 0 if send else 1
        (sport, sip, smac), (dport, dip, dmac) = (host, ctrl) if send else (ctrl, host)
        segment = tcp(sport, dport, sequence[side], sequence[1 - side], pdu)
        packets.append(eth(dmac, smac, ipv4(sip, dip, segment, 0x5000 + len(packets))))
        sequence[side] += len(pdu)

    def command(cid, send, xfer, spsp=0x1000, inline=b''):
        entry = sqe(AQ_SECURITY_SEND if send else AQ_SECURITY_RECV, cid,
                    cdw10=security_cdw10(1, spsp), cdw11=xfer)
        pdu = capsule_cmd_pdu(entry)
        if inline:
            pdu = struct.pack('<BBBBI', 4, 0, 72, 72, 72 + len(inline)) + entry + inline
        emit(pdu, True)

    def response(cid, data, offset=0):
        emit(c2h_data_pdu(cid, data, datao=offset, pdo=24), False)

    empty = tcg_compacket(b'', 0x1000)
    emit(capsule_cmd_pdu(sqe(6, 1, cdw10=1)), True)
    command(2, True, 20, inline=empty)
    command(3, True, 20, inline=empty[:16])
    command(4, True, 20, inline=empty + b'\xfa' * 4)
    level0 = (struct.pack('>IHH', 76, 0, 1) + bytes(40)
              + tcg_l0_feature(1, 1, b'\x41' + bytes(11))
              + tcg_l0_feature(2, 1, b'\x03' + bytes(11)))
    command(5, False, 16, spsp=1)
    response(5, level0[:16])
    command(6, False, 64)
    response(6, empty, 4)
    command(7, False, 20)
    response(7, empty + b'\xfa' * 4)
    command(8, False, 20)
    response(8, empty)
    command(9, False, 80, spsp=1)
    response(9, level0[:68])
    command(10, True, 20)
    response(10, empty)  # wrong native transaction half, not Security Send data
    command(11, False, 20, inline=empty)  # wrong half in the other direction
    return packets


def build_security():
    out = shb() + idb(DLT_EN10MB)
    for i, packet in enumerate(security_native_packets()):
        out += epb(packet, 1_701_000_000_000_000 + i * 1_000_000)
    return out


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F26-F76 (build_shared_decode_native): the native twin of
# nvme-mi-mi-commands.pcapng F482-F743
# ---------------------------------------------------------------------------

# Shared Admin/SECP 00h vectors; no build or dissector invocation.
#
# MI 2.1 Figures 134/136/141/145 and Base 2.3 Figures 142/215/216/220/222.
# SECP00 exercises the legacy length interpretation, not SPC-5 conformance:
# SPC-5 is not decoded. Every case is a request/response pair.
# Native twins have one initial Identify frame, then the same common pairs.

def shared_common_cases():
    cases = []

    def add(name, opcode=2, cdw10=0, cdw11=0, off=0, dlen=None,
            data=b'', cut=0):
        cases.append({'name': name, 'opcode': opcode, 'cdw10': cdw10,
                          'cdw11': cdw11, 'off': off,
                          'dlen': len(data) if dlen is None else dlen,
                          'data': data, 'cut': cut})

    for name, header, nibble in (
            ('selftest-zero', 0, 0), ('selftest-header', 0xa55a, 0),
            ('selftest-vdi', 0, 0xa0)):
        data = bytearray(32)
        struct.pack_into('<H', data, 2, header)
        data[4] = 0x10
        data[6] = nibble
        add(name, cdw10=6 | (7 << 16), data=bytes(data))
    for value in (0, 0xb0):
        add(f'egcw-{value:02x}', cdw10=9, data=bytes([value, 0, 0, 100]))
    for value in (0, 1, 2, 255):
        add(f'tcda-{value:02x}', cdw10=8 | (127 << 16),
            off=380, data=bytes([0, 1, value, 0]))
    # Raw RAE=1 control; all preceding Get Log Page commands have wire RAE=0.
    add('rae-one', cdw10=8 | 0x8000 | (127 << 16),
        off=380, data=bytes([0, 1, 1, 0]))

    for spsp, prefix in ((0, 'list'), (1, 'cert')):
        header = 8 if spsp == 0 else 4
        for name, declared, al, dlen, cut in (
                ('exact', 4, header + 4, header + 4, 0),
                ('contradiction', 8, header + 8, header + 8, 0),
                ('allocation-prefix', 8, header + 4, header + 4, 0),
                ('selected-prefix', 8, header + 8, header + 4, 0),
                ('tail', 2, header + 4, header + 4, 0),
                ('captured-prefix', 8, header + 8, header + 8, 4)):
            body = b'\x00\x01\x02\xee'
            if cut:
                body += b'\xaa\xbb\xcc\xdd'
            data = bytes(header - 2) + struct.pack('>H', declared) + body
            add(f'{prefix}-{name}', opcode=0x82, cdw10=spsp << 8,
                cdw11=al, dlen=dlen, data=data, cut=cut)
    add('list-short-header', opcode=0x82, cdw11=4, data=bytes(4))
    add('list-later-window', opcode=0x82, cdw11=16, off=4,
        data=b'\x00\x04\x01\xee')
    add('secp00-unknown-selector', opcode=0x82, cdw10=3 << 8,
        cdw11=4, data=b'\xde\xad\xbe\xef')
    return cases


def build_shared_decode_native():
    out = shb() + idb(DLT_EN10MB)
    seq = [1, 1]
    frame = 0

    def emit(request, pdu, cut=0):
        nonlocal out, frame
        frame += 1
        sender = 0 if request else 1
        ip = (HOST_IP, CTRL_IP)
        mac = (HOST_MAC, CTRL_MAC)
        port = (HOST_PORT, CTRL_PORT)
        packet = eth(mac[1-sender], mac[sender],
            ipv4(ip[sender], ip[1-sender],
                tcp(port[sender], port[1-sender], seq[sender],
                           seq[1-sender], pdu), frame))
        seq[sender] += len(pdu)
        out += epb(packet, 1730000000000000 + frame * 1000,
                           caplen=len(packet)-cut)

    emit(True, capsule_cmd_pdu(sqe(6, 1, cdw10=1)))
    for cid, case in enumerate(shared_common_cases(), 2):
        # A native allocation prefix is the analogue of an MI-selected prefix.
        al = case['cdw11']
        if case['name'].endswith('selected-prefix'):
            al = case['dlen']
        emit(True, capsule_cmd_pdu(sqe(
            case['opcode'], cid, cdw10=case['cdw10'], cdw11=al)))
        emit(False, c2h_data_pdu(
            cid, case['data'], datao=case['off'], pdo=24), case['cut'])
        print(f"TCP {frame-1:3}/{frame:3} {case['name']}")
    return out


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F83-F96 (build_prop_offset) - a Property Get or Set
# CQE names the property its command named
# ---------------------------------------------------------------------------
#
# OFST is bytes 47:44 of a Property Get or Set (NVMe Base 2.3 Figures 585 and
# 587), and the property map runs past FFh (Figures 33 and 35: PMRCAP at
# E00h, Vendor Specific from 1300h on a message-based controller).  The
# command context kept only OFST's low byte, so each CQE below was named, and
# a Property Get's value decoded, as the register in brackets while its
# command said Unknown Property.  The reserved offsets read as 0h (section
# 3.1.4).
#
#   F1-F2    Property Get, OFST 108h,  PRS 000b   [VS]
#   F3-F4    Property Get, OFST 1000h, PRS 001b   [CAP]
#   F5-F6    Property Get, OFST 1014h, PRS 000b   [CC]
#   F7-F8    Property Get, OFST 1300h, PRS 001b   [CAP], Vendor Specific
#   F9-F10   Property Set, OFST 1014h, PUS 000b   [CC]
#   F11-F12  Property Get, OFST 14h (CC)          -> control
#   F13-F14  Property Set, OFST 14h (CC)          -> control

PROP_VENDOR_VALUE = 0x0123456789ABCDEF
PROP_CC_VALUE = 0x00460001       # EN, IOSQES 6, IOCQES 4 (Figure 41)


def build_prop_offset():
    conn = Conn(0x6200, 1_701_100_000_000_000)
    emit = conn.emit


    def prop_get(cid, ofst, prs, value=0):
        emit(True, capsule_cmd_pdu(sqe(FABRICS_OPC, cid=cid, nsid=FCTYPE_PROP_GET,
                                       cdw10=prs, cdw11=ofst)))
        emit(False, capsule_resp_pdu(cid=cid, dw0=value & 0xFFFFFFFF,
                                     dw1=value >> 32))

    def prop_set(cid, ofst, value=0):
        emit(True, capsule_cmd_pdu(sqe(FABRICS_OPC, cid=cid, nsid=FCTYPE_PROP_SET,
                                       cdw11=ofst, cdw12=value)))
        emit(False, capsule_resp_pdu(cid=cid))

    prop_get(1, 0x00000108, 0)                              # F1-F2
    prop_get(2, 0x00001000, 1)                              # F3-F4
    prop_get(3, 0x00001014, 0)                              # F5-F6
    prop_get(4, 0x00001300, 1, PROP_VENDOR_VALUE)           # F7-F8
    prop_set(5, 0x00001014)                                 # F9-F10
    prop_get(6, PROP_OFFSET_CC, 0, PROP_CC_VALUE)           # F11-F12
    prop_set(7, PROP_OFFSET_CC, PROP_CC_VALUE)              # F13-F14
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F97-F100 (build_capsule_size) - IOCCSZ and IORCSZ byte
# counts past 32 bits
# ---------------------------------------------------------------------------
#
# IOCCSZ (bytes 1795:1792) and IORCSZ (1799:1796) of the Identify Controller
# data structure are 32-bit counts of 16-byte units with no maximum (NVMe Base
# 2.3 Figure 328), so a byte count takes up to 36 bits.  Their label
# multiplied in 32 bits: FFFFFFFFh showed 4294967280 bytes and 10000000h
# showed 0.  ICDOFF (1801:1800, at most FFFFh) shares the label and cannot
# wrap.
#
#   F1-F2  Identify Controller, IOCCSZ FFFFFFFFh, IORCSZ 10000000h, ICDOFF FFFFh
#   F3-F4  Identify Controller, IOCCSZ 10000000h, IORCSZ FFFFFFFFh, ICDOFF 2h

CAPSULE_SIZE_CASES = (
    # (IOCCSZ, IORCSZ, ICDOFF)
    (0xFFFFFFFF, 0x10000000, 0xFFFF),
    (0x10000000, 0xFFFFFFFF, 0x0002),
)


def build_capsule_size():
    conn = Conn(0x6300, 1_701_110_000_000_000)
    emit = conn.emit


    for cid, (ioccsz, iorcsz, icdoff) in enumerate(CAPSULE_SIZE_CASES, 1):
        data = bytearray(4096)
        struct.pack_into('<I', data, 80, IDCTRL_VER)        # VER
        struct.pack_into('<IIH', data, 1792, ioccsz, iorcsz, icdoff)
        emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=cid,
                                       cdw10=IDENTIFY_CNS_CTRL)))
        emit(False, c2h_data_pdu(cid=cid, payload=bytes(data),
                                 pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F101-F116 (build_ana_split) - an ANA log read whose
# C2HData PDUs split a descriptor field
# ---------------------------------------------------------------------------
#
# C2HData DATAO and DATAL are dword multiples (NVMe/TCP 1.3 Figure 33), so a
# PDU boundary can fall at descriptor byte 12 (inside Change Count, 15:08) or
# 20, 24 or 28 (inside Reserved, 31:17) of an ANA Group Descriptor (NVMe Base
# 2.3 Figure 228).  The walk counted only the fields it rendered, so the next
# PDU resumed 3 to 11 bytes early: CHGC, ANAS and the NSIDs were read from
# the wrong bytes and Descriptor 1 was framed from Descriptor 0's NSIDs.
#
# The page is build_ana_redecode's: header CHGC 5, NAGD 2; Descriptor 0 =
# AGID 1, NNV 3, CHGC 7, ANAS 01h, NSIDs 1,2,3 (44 bytes); Descriptor 1 =
# AGID 2, NNV 1, CHGC 8, ANAS 02h, NSID 9 (36 bytes); 96 bytes in all.
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-4   Get Log Page CID 2, LID 0Ch, 96 bytes; C2HData DATAO 0
#                page[0:28], DATAO 28 page[28:96]  (cut at Descriptor 0
#                byte 12, inside CHGC)
#   Frames 5-7   CID 3, cut at page byte 36 (Descriptor 0 byte 20, Reserved)
#   Frames 8-10  CID 4, cut at page byte 40 (Descriptor 0 byte 24, Reserved)
#   Frames 11-13 CID 5, cut at page byte 44 (Descriptor 0 byte 28, Reserved)
#   Frames 14-16 CID 6, cut at page byte 60 (the Descriptor 1 boundary; the
#                control)

ANA_SPLIT_CUTS = (28, 36, 40, 44, 60)


def build_ana_split():
    conn = Conn(0x6400, 1_701_120_000_000_000)
    emit = conn.emit
    hdr = struct.pack('<QH6x', 5, 2)
    d0 = struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
    d1 = struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)
    page = hdr + d0 + d1


    cdw10 = NVME_LID_ANA | (((len(page) // 4) - 1) << 16)
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, cut in enumerate(ANA_SPLIT_CUTS, 2):
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10)))
        for datao, payload in ((0, page[:cut]), (cut, page[cut:])):
            emit(False, c2h_data_pdu(cid=cid, payload=payload, datao=datao,
                                     pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F117-F121 (build_ana_unplaced) - a C2HData PDU whose
# data span cannot be resolved leaves the ANA walk alone
# ---------------------------------------------------------------------------
#
# A C2HData PDU with DATAL 0 describes no data span, so it is rendered at a
# guessed offset of 0 and nothing may be retained from it, so it must not
# restart the read's descriptor walk.  The next PDU's DATAO is the empty PDU's
# DATAO plus its
# DATAL (NVMe/TCP 1.3 3.3.2.1), so it continues the first PDU's walk.
#
# The page is build_ana_redecode's: header CHGC 5, NAGD 2; Descriptor 0 =
# AGID 1, NNV 3, CHGC 7, ANAS 01h, NSIDs 1,2,3 (44 bytes); Descriptor 1 =
# AGID 2, NNV 1, CHGC 8, ANAS 02h, NSID 9 (36 bytes); 96 bytes in all.
#
#   Frame 1  Identify (06h) CID 1               -> pins the queue as admin
#   Frame 2  Get Log Page CID 2, LID 0Ch, 96 bytes
#   Frame 3  C2HData CID 2, DATAO 0, page[0:56] (ends inside Descriptor 0's
#            NSID list)
#   Frame 4  C2HData CID 2, DATAO 56, DATAL 0 -- no data span
#   Frame 5  C2HData CID 2, DATAO 56, page[56:96] -- continues frame 3's walk

def build_ana_unplaced():
    conn = Conn(0x6500, 1_701_130_000_000_000)
    emit = conn.emit
    hdr = struct.pack('<QH6x', 5, 2)
    d0 = struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
    d1 = struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)
    page = hdr + d0 + d1


    cdw10 = NVME_LID_ANA | (((len(page) // 4) - 1) << 16)
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=2, cdw10=cdw10)))
    for datao, payload in ((0, page[:56]), (56, b''), (56, page[56:])):
        emit(False, c2h_data_pdu(cid=2, payload=payload, datao=datao,
                                 pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F122-F139 (build_ana_gap) - a C2HData PDU after a gap
# in an ANA log read is not decoded from the walk
# ---------------------------------------------------------------------------
#
# ANA Group Descriptors are variable-length (NVMe Base 2.3 Figure 228), so a
# later window is placed only by walking every byte before it.  When a PDU of
# the read is lost from the capture, or cannot be placed (PDO 0: no data span,
# decoded at a guessed offset of 0 and retaining nothing), the next PDU's DATAO
# is not where the last walked window ended, so it is not decoded from that
# window's walk state.
#
# The page is build_ana_redecode's: header CHGC 5, NAGD 2; Descriptor 0 =
# AGID 1, NNV 3, CHGC 7, ANAS 01h, NSIDs 1,2,3 (page bytes 16-59);
# Descriptor 1 = AGID 2, NNV 1, CHGC 8, ANAS 02h, NSID 9 (bytes 60-95).
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-4   Get Log Page CID 2; C2HData DATAO 0 page[0:60] (ends on the
#                Descriptor 1 boundary); DATAO 60 page[60:76] is not captured
#                (a TCP sequence gap); DATAO 76 page[76:96]
#   Frames 5-7   CID 3, the same with DATAO 0 page[0:56] (ends inside
#                Descriptor 0's NSID list) and DATAO 56 page[56:76] lost
#   Frames 8-11  CID 4: DATAO 0 page[0:56]; PDO 0 DATAO 56 page[56:60]
#                (unplaced); DATAO 60 page[60:96]
#   Frames 12-15 CID 5: DATAO 0 page[0:56]; PDO 0 DATAO 56 page[56:76]
#                (unplaced); DATAO 76 page[76:96]
#   Frames 16-18 CID 6, no gap: DATAO 0 page[0:22] ends inside Descriptor 0's
#                NNV (a DATAL that is not a dword multiple), so the walk loses
#                the descriptor's end; DATAO 22 page[22:96] is not decoded

ANA_GAP_READS = (
    # (cid, ((DATAO, end, how), ...)); each PDU carries page[DATAO:end]
    (2, ((0, 60, 'placed'), (60, 76, 'lost'), (76, 96, 'placed'))),
    (3, ((0, 56, 'placed'), (56, 76, 'lost'), (76, 96, 'placed'))),
    (4, ((0, 56, 'placed'), (56, 60, 'unplaced'), (60, 96, 'placed'))),
    (5, ((0, 56, 'placed'), (56, 76, 'unplaced'), (76, 96, 'placed'))),
    (6, ((0, 22, 'placed'), (22, 96, 'placed'))),
)


def build_ana_gap():
    hdr = struct.pack('<QH6x', 5, 2)
    d0 = struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
    d1 = struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)
    page = hdr + d0 + d1

    conn = Conn(0x6600, 1_701_140_000_000_000)

    def emit(to_ctrl, pdu, captured=True):
        frame = conn.segment(to_ctrl, pdu)
        if captured:
            conn.write(frame)

    cdw10 = NVME_LID_ANA | (((len(page) // 4) - 1) << 16)
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, pdus in ANA_GAP_READS:
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10)))
        for datao, end, how in pdus:
            pdo = 0 if how == 'unplaced' else NVME_TCP_DATA_PDU_SIZE
            emit(False, c2h_data_pdu(cid=cid, payload=page[datao:end], datao=datao,
                                     pdo=pdo),
                 captured=how != 'lost')
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F140-F150 (build_discovery_extdlpe) - Discovery reads
# that start past the header, with and without LSP EXTDLPE
# ---------------------------------------------------------------------------
#
# A Discovery window that starts at page byte 1024 holds neither DLPF (byte 18)
# nor TDLPL (23:20), so only the request can say that its entries may be
# Extended Discovery Log Page Entries, each TEL bytes long: LSP bit 0, EXTDLPE
# (NVMe Base 2.3 Figure 309).
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-3   CID 2, LSP 01h, LPO 0: the whole extended page; the header's
#                DLPF EXTEND places both TEL 1040 entries
#   Frames 4-5   CID 3, LSP 01h, LPO 1024: the same two entries, no header
#   Frames 6-7   CID 4, LSP 00h, LPO 1024: the same bytes without EXTDLPE keep
#                Figure 312's 1,024-byte grid
#   Frames 8-9   CID 5, LSP 01h, LPO 0: discovery_log_page(2, 2), DLPF 0
#   Frames 10-11 CID 6, LSP 01h, LPO 1024: its two 1,024-byte entries, no
#                header; where a TEL would be are DLE1's TRTYPE, ADRFAM,
#                SUBTYPE and TREQ, which are not a valid TEL

DISCOVERY_EXT_TEL = 1040


def discovery_extended_page():
    """discovery_log_page(2, 2) with both entries extended (Figure 311): TEL
    1040, NUMEXAT 1 and one Vendor Specific (FF01h) attribute with a 4-byte
    value (1032 + 4 + 4); the header sets DLPF EXTEND and TDLPL 3104."""
    legacy = discovery_log_page(numrec=2, nentries=2)
    hdr = bytearray(legacy[:DISCOVERY_HDR_LEN])
    hdr[18] = 0x01                                       # DLPF: EXTEND
    struct.pack_into('<I', hdr, 20, DISCOVERY_HDR_LEN + 2 * DISCOVERY_EXT_TEL)
    out = bytes(hdr)
    for i in range(2):
        start = DISCOVERY_HDR_LEN + i * DISCOVERY_RCRD_LEN
        out += legacy[start:start + DISCOVERY_RCRD_LEN]
        out += struct.pack('<IHH', DISCOVERY_EXT_TEL, 1, 0)  # TEL, NUMEXAT
        out += struct.pack('<HH', 0xFF01, 4) + bytes([0xA1 + i, 0xB2, 0xC3, 0xD4])
    assert len(out) == DISCOVERY_HDR_LEN + 2 * DISCOVERY_EXT_TEL
    return out


def build_discovery_extdlpe():
    conn = Conn(0x6700, 1_701_150_000_000_000)
    emit = conn.emit
    extended = discovery_extended_page()
    legacy = discovery_log_page(numrec=2, nentries=2)


    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, lsp, lpo, page in ((2, 1, 0, extended), (3, 1, 1024, extended),
                                (4, 0, 1024, extended), (5, 1, 0, legacy),
                                (6, 1, 1024, legacy)):
        data = page[lpo:]
        cdw10 = NVME_LID_DISCOVERY | (lsp << 8) | (((len(data) // 4) - 1) << 16)
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10,
                                       cdw12=lpo)))
        emit(False, c2h_data_pdu(cid=cid, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F151-F183 (build_ana_revisit) - ANA log reads in three
# C2HData PDUs, for re-dissecting one PDU out of order
# ---------------------------------------------------------------------------
#
# The GUI first-passes the whole file, then re-dissects whichever frame is
# selected, so a later window of an ANA read must not be decoded from the
# walk state its read's last window left (NVMe Base 2.3 Figures 227/228).
# tshark -2 re-dissects in order and cannot show this; the test drives sharkd.
# Every PDU is placed (PDO 24) and in wire order, so one-pass and -2 agree.
#
# The page is build_ana_redecode's: header CHGC 5, NAGD 2; Descriptor 0 =
# AGID 1, NNV 3, CHGC 7, ANAS 01h, NSIDs 1,2,3 (page bytes 16-59);
# Descriptor 1 = AGID 2, NNV 1, CHGC 8, ANAS 02h, NSID 9 (bytes 60-95).
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   then per read a Get Log Page and its three C2HData PDUs:
#   Frames 2-5   CID 2 NUMD 96: [0:56] [56:76] [76:96]
#   Frames 6-9   CID 3 NUMD 96: [0:16] [16:60] [60:96]  (second PDU at byte 16)
#   Frames 10-13 CID 4 NUMD 96: [0:12] [12:60] [60:96]  (inside the header,
#                                                         past NAGD)
#   Frames 14-17 CID 5 NUMD 96: [0:8]  [8:60]  [60:96]  (holds NAGD)
#   Frames 18-29 CID 6-8 NUMD 76: the same three second-PDU starts, the read
#                ending at byte 76, inside Descriptor 1, so the last walked
#                window leaves a descriptor in progress
#   Frames 30-33 CID 9 NUMD 96: [0:12] [12:62] [62:96]; the second PDU ends
#                inside Descriptor 1's AGID (a DATAL that is not a dword
#                multiple), so the walk loses its framing there

ANA_REVISIT_READS = (
    # (cid, transfer length, the two cuts)
    (2, 96, (56, 76)),
    (3, 96, (16, 60)),
    (4, 96, (12, 60)),
    (5, 96, (8, 60)),
    (6, 76, (16, 56)),
    (7, 76, (12, 56)),
    (8, 76, (8, 56)),
    (9, 96, (12, 62)),
)


def build_ana_revisit():
    conn = Conn(0x6800, 1_701_160_000_000_000)
    emit = conn.emit
    hdr = struct.pack('<QH6x', 5, 2)
    d0 = struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
    d1 = struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)
    page = hdr + d0 + d1


    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, total, cuts in ANA_REVISIT_READS:
        cdw10 = NVME_LID_ANA | (((total // 4) - 1) << 16)
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10)))
        bounds = (0, *cuts, total)
        for start, end in itertools.pairwise(bounds):
            emit(False, c2h_data_pdu(cid=cid, payload=page[start:end], datao=start,
                                     pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F184-F194 (build_h2c_lbart) - H2CData windows placed
# by their Data Offset
# ---------------------------------------------------------------------------
#
# Each H2CData PDU says where its data belongs in the Command Data Buffer
# (DATAO, NVMe/TCP 1.3 Figure 32), and an R2T may split a transfer anywhere on
# a dword: Figure 16's own example sends 1,000 bytes and then the rest.  The
# 64-byte LBA Range Type entries (NVM Command Set 1.2 Figure 95) of a later
# window are framed and numbered from its DATAO.
#
# The buffer is the whole 4,096-byte LBA Range Type data structure, 64
# entries: entry i is Type 0, Attributes 01h, SLBA 10000h + i * 100h, NLB FFh
# and a GUID of sixteen bytes i.
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-6   Set Features CID 2, FID 03h, NUM 63; R2T 0/1000, H2CData
#                DATAO 0 buffer[0:1000]; R2T 1000/3096, H2CData DATAO 1000
#                buffer[1000:4096] (starts at entry 15's byte 40)
#   Frames 7-11  CID 3, the same, with the second H2CData in the legacy PDO 0
#                shape: no data span, so it stays at offset 0

LBART_FID = 0x03
LBART_LEN = 4096
LBART_SPLIT = 1000


def lbart_entry(i):
    """NVM CS 1.2 Figure 95: Type, Attributes, Reserved 15:02, SLBA 23:16,
    NLB 31:24 (0's based), GUID 47:32, Reserved 63:48."""
    return (struct.pack('<BB14xQQ', 0x00, 0x01, 0x10000 + i * 0x100, 0xFF)
            + bytes([i] * 16) + bytes(16))


def build_h2c_lbart():
    conn = Conn(0x6900, 1_701_170_000_000_000)
    emit = conn.emit
    data = b''.join(lbart_entry(i) for i in range(LBART_LEN // 64))


    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    ttag = 1
    for cid, second_pdo in ((2, NVME_TCP_DATA_PDU_SIZE), (3, 0)):
        emit(True, capsule_cmd_pdu(sqe_with_sgl(
            sqe(AQ_SET_FEATURES, cid=cid, cdw10=LBART_FID, cdw11=LBART_LEN // 64 - 1),
            sgl_descriptor(0x5, SGL_SUB_CMD_DATA_BUFFER, struct.pack('<Q', 0),
                           LBART_LEN, bytes(3)))))
        for start, end, pdo in ((0, LBART_SPLIT, NVME_TCP_DATA_PDU_SIZE),
                                (LBART_SPLIT, LBART_LEN, second_pdo)):
            emit(False, r2t_pdu(cid=cid, ttag=ttag, r2to=start, r2tl=end - start))
            emit(True, h2c_data_pdu(cid=cid, payload=data[start:end], datao=start,
                                    pdo=pdo, ttag=ttag, last=True))
            ttag += 1
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F195-F206 (build_stale_cid) - data PDUs that carry the
# CID of a command that has already completed
# ---------------------------------------------------------------------------
#
# A command's CID names it only while it is outstanding (NVMe Base 2.3
# Figure 91); once its CapsuleResp is seen the host may reuse the CID.  Data
# that arrives for that CID after the completion belongs to a newer command
# whose capsule the capture does not hold (a drop, or a mid-stream start), and
# NVMe/TCP 1.3 sections 3.3.2.1 and 3.3.2.2 make such a PDU a fatal error at
# the receiver, so it is not bound to the completed command.
#
#   Frame 1   Identify (06h) CID 10h, CNS 01h
#   Frame 2   C2HData CID 10h, the 4,096-byte Identify Controller structure
#   Frame 3   CapsuleResp CID 10h
#   Frame 4   C2HData CID 10h, 4,096 bytes of AAh (the dropped command's data)
#   Frame 5   CapsuleResp CID 10h (the dropped command's completion)
#   Frame 6   Set Features CID 20h, FID 03h, NUM 0: one 64-byte LBA Range entry
#   Frames 7-9  R2T, H2CData DATAO 0 (64 bytes), CapsuleResp CID 20h
#   Frames 10-12  R2T, H2CData and CapsuleResp CID 20h of a dropped write
#
# Frames 4, 5, 11 and 12 must render as unknown data, and frames 1 and 6 keep
# the links to their own transfers.

STALE_IDENTIFY_CID = 0x10
STALE_SETF_CID = 0x20


def build_stale_cid():
    conn = Conn(0x6A00, 1_701_180_000_000_000)
    emit = conn.emit


    cid = STALE_IDENTIFY_CID
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=cid, cdw10=IDENTIFY_CNS_CTRL)))
    emit(False, c2h_data_pdu(cid=cid, payload=IDCTRL.ljust(4096, b'\x00'),
                             pdo=NVME_TCP_DATA_PDU_SIZE))
    emit(False, capsule_resp_pdu(cid=cid))
    emit(False, c2h_data_pdu(cid=cid, payload=b'\xAA' * 4096,
                             pdo=NVME_TCP_DATA_PDU_SIZE))
    emit(False, capsule_resp_pdu(cid=cid))

    cid = STALE_SETF_CID
    emit(True, capsule_cmd_pdu(sqe_with_sgl(
        sqe(AQ_SET_FEATURES, cid=cid, cdw10=LBART_FID, cdw11=0),
        sgl_descriptor(0x5, SGL_SUB_CMD_DATA_BUFFER, struct.pack('<Q', 0),
                       64, bytes(3)))))
    for ttag, payload in ((1, lbart_entry(0)), (2, b'\xBB' * 64)):
        emit(False, r2t_pdu(cid=cid, ttag=ttag, r2to=0, r2tl=64))
        emit(True, h2c_data_pdu(cid=cid, payload=payload,
                                pdo=NVME_TCP_DATA_PDU_SIZE, ttag=ttag, last=True))
        emit(False, capsule_resp_pdu(cid=cid))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F207-F215 (build_c2h_success) - commands completed by
# a C2HData PDU's SUCCESS flag, with no CapsuleResp
# ---------------------------------------------------------------------------
#
# A controller that supports disabling SQHD updates may set SUCCESS in the
# last C2HData PDU of a command; the command is then complete and no Response
# Capsule follows (NVMe/TCP 1.3 Figure 33 and section 3.3.2.1).  SUCCESS
# without LAST_PDU is a fatal transport error and completes nothing.  The
# dissector ignored the flag, so such a command never completed: a revisit of
# its capsule found no completed command and decoded against an empty context,
# and later PDUs carrying its CID were still bound to it.
#
#   Frame 1   Identify (06h) CID 30h, CNS 01h
#   Frame 2   C2HData CID 30h, LAST_PDU|SUCCESS, Identify Controller
#   Frame 3   Identify CID 31h, CNS 01h
#   Frame 4   C2HData CID 31h, LAST_PDU|SUCCESS, Identify Controller
#   Frame 5   C2HData CID 31h, 4,096 bytes of AAh (after the completion)
#   Frame 6   CapsuleResp CID 31h (none is sent after SUCCESS)
#   Frame 7   Identify CID 32h, CNS 01h
#   Frame 8   C2HData CID 32h, SUCCESS without LAST_PDU (no completion)
#   Frame 9   CapsuleResp CID 32h
#
# Frames 2 and 4 complete frames 1 and 3, so frames 5 and 6 are unknown data;
# frame 9, not frame 8, completes frame 7.

C2H_SUCCESS_CIDS = (0x30, 0x31, 0x32)


def build_c2h_success():
    conn = Conn(0x6B00, 1_701_190_000_000_000)
    emit = conn.emit
    data = IDCTRL.ljust(4096, b'\x00')


    def identify(cid, **flags):
        emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=cid, cdw10=IDENTIFY_CNS_CTRL)))
        emit(False, c2h_data_pdu(cid=cid, payload=data,
                                 pdo=NVME_TCP_DATA_PDU_SIZE, **flags))

    first, second, third = C2H_SUCCESS_CIDS
    identify(first, last=True, success=True)
    identify(second, last=True, success=True)
    emit(False, c2h_data_pdu(cid=second, payload=b'\xAA' * 4096,
                             pdo=NVME_TCP_DATA_PDU_SIZE))
    emit(False, capsule_resp_pdu(cid=second))
    identify(third, success=True)
    emit(False, capsule_resp_pdu(cid=third))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F216-F223 (build_missing_cqe) - commands whose
# completion the capture does not hold
# ---------------------------------------------------------------------------
#
# A capture that stops early, or drops a segment, leaves commands with data
# but no CapsuleResp.  The first pass binds each data PDU to its command
# (NVMe/TCP 1.3 Figures 32 and 33: CCCID is the command's CID), but a revisit
# of such a command's capsule found no completed command and decoded against a
# fresh, empty context, so the links to its data were lost on every later
# pass, and each revisit allocated another context that lived until the file
# was closed.
#
#   Frame 1   Identify (06h) CID 40h, CNS 01h
#   Frame 2   C2HData CID 40h, LAST_PDU, Identify Controller; no CapsuleResp
#   Frame 3   Set Features CID 41h, FID 03h, NUM 0: one 64-byte LBA Range entry
#   Frame 4   R2T CID 41h, TTAG 1, 0/64
#   Frame 5   H2CData CID 41h, DATAO 0, LAST_PDU (entry 0); no CapsuleResp
#   Frame 6   Identify CID 42h, CNS 01h (the control: it completes)
#   Frame 7   C2HData CID 42h, LAST_PDU, Identify Controller
#   Frame 8   CapsuleResp CID 42h
#
# On a second pass frame 1 links to frame 2 and frame 3 to frame 5, as frame
# 6 links to frames 7 and 8.

MISSING_CQE_CIDS = (0x40, 0x41, 0x42)


def build_missing_cqe():
    conn = Conn(0x6C00, 1_701_200_000_000_000)
    emit = conn.emit
    data = IDCTRL.ljust(4096, b'\x00')


    read, write, control = MISSING_CQE_CIDS
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=read, cdw10=IDENTIFY_CNS_CTRL)))
    emit(False, c2h_data_pdu(cid=read, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE,
                             last=True))
    emit(True, capsule_cmd_pdu(sqe_with_sgl(
        sqe(AQ_SET_FEATURES, cid=write, cdw10=LBART_FID, cdw11=0),
        sgl_descriptor(0x5, SGL_SUB_CMD_DATA_BUFFER, struct.pack('<Q', 0),
                       64, bytes(3)))))
    emit(False, r2t_pdu(cid=write, ttag=1, r2to=0, r2tl=64))
    emit(True, h2c_data_pdu(cid=write, payload=lbart_entry(0),
                            pdo=NVME_TCP_DATA_PDU_SIZE, ttag=1, last=True))
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=control, cdw10=IDENTIFY_CNS_CTRL)))
    emit(False, c2h_data_pdu(cid=control, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE,
                             last=True))
    emit(False, capsule_resp_pdu(cid=control))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F224-F228 (build_midstream_start) - a capture that
# starts in the middle of two connections
# ---------------------------------------------------------------------------
#
# The first segment the dissector sees on a connection may be the middle of a
# PDU, or of a TLS record.  The PDU-start check accepted any type up to 0Bh
# with HLEN and PLEN of at least 8, and the segment it accepts pins the
# connection to NVMe/TCP, so such a segment was framed from its garbage PLEN
# and the later PDUs in that direction were held in a reassembly that never
# completed.  Every PDU type has a fixed HLEN (NVMe/TCP 1.3 Figures 26-37).
#
#   Frame 1   controller to host, host port 55180: the tail of a C2HData
#             PDU's data, reading 05 00 30 00 00 00 10 00 (CapsuleResp, HLEN
#             30h, PLEN 1 MiB)
#   Frame 2   Get Features (0Ah) CID 50h, FID 07h Number of Queues
#   Frame 3   CapsuleResp CID 50h
#   Frame 4   controller to host, host port 55181: the middle of a TLS
#             record, reading 07 5a 2c 91 e3 40 7d 1b (C2HData, HLEN 2Ch)
#   Frame 5   a TLS application-data record
#
# Frames 1 and 4 are not NVMe/TCP; frame 2 starts the PDUs on its connection,
# frame 3 completes it, and frame 5 is TLS.

MIDSTREAM_CID = 0x50
MIDSTREAM_FID = 0x07                        # Number of Queues: no data
MIDSTREAM_CONTINUATION = (bytes.fromhex('0500300000001000')
                          + bytes(((i * 37 + 3) & 0xFF) for i in range(56)))
MIDSTREAM_CIPHERTEXT = (bytes.fromhex('075a2c91e3407d1b')
                        + bytes(((i * 53 + 9) & 0xFF) for i in range(56)))
MIDSTREAM_TLS_RECORD = (bytes.fromhex('1703030020')
                        + bytes(((i * 29 + 1) & 0xFF) for i in range(32)))


def build_midstream_start():
    conn = Conn(0x6D00, 1_701_210_000_000_000)
    # Mid-connection: neither direction starts at sequence 1.
    conn.seq = {(port, to_ctrl): base for port in (HOST_PORT, HOST_PORT + 1)
                for to_ctrl, base in ((True, 0x00051001), (False, 0x00C30001))}

    def emit(port, to_ctrl, payload):
        conn.emit(to_ctrl, payload, port)

    emit(HOST_PORT, False, MIDSTREAM_CONTINUATION)
    emit(HOST_PORT, True, capsule_cmd_pdu(sqe(AQ_GET_FEATURES, cid=MIDSTREAM_CID,
                                              cdw10=MIDSTREAM_FID)))
    emit(HOST_PORT, False, capsule_resp_pdu(cid=MIDSTREAM_CID, dw0=0x003F003F))
    emit(HOST_PORT + 1, False, MIDSTREAM_CIPHERTEXT)
    emit(HOST_PORT + 1, False, MIDSTREAM_TLS_RECORD)
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F229-F243 (build_wrong_direction) - Admin data that
# travels against its opcode's data direction
# ---------------------------------------------------------------------------
#
# Each Admin opcode moves data one way only (NVMe Base 2.3 Figure 142, Data
# Transfer bits 01:00): Identify, Get Log Page and Get Features controller to
# host, Set Features host to controller.  Each NVMe/TCP PDU type moves data one
# way only: in-capsule data and H2CData host to controller, C2HData controller
# to host (NVMe/TCP 1.3 Figures 30, 32 and 33).  Bytes that go against the
# opcode are not that command's data structure.  Only Security Send/Receive was
# told the transport's direction, so the others were decoded as the
# structure: the host's bytes as an Identify Controller, the controller's as
# LBA Range Type entries.
#
#   Frame 1   Identify (06h) CID 60h, CNS 01h, with the 4,096-byte Identify
#             Controller structure as in-capsule data
#   Frame 2   CapsuleResp CID 60h
#   Frame 3   Set Features (09h) CID 61h, FID 03h, NUM 0: one 64-byte entry
#   Frame 4   C2HData CID 61h, LAST_PDU, LBA Range entry 0 (SLBA 10000h)
#   Frame 5   CapsuleResp CID 61h
#   Frame 6   Identify CID 62h, CNS 01h
#   Frame 7   H2CData CID 62h, DATAO 0, LAST_PDU, Identify Controller (no R2T:
#             nothing asks for it)
#   Frame 8   CapsuleResp CID 62h
#   Frames 9-11   Identify CID 63h with its C2HData and CapsuleResp (control)
#   Frames 12-15  Set Features CID 64h, FID 03h, with R2T, H2CData of entry 0
#                 and CapsuleResp (control)
#
# Frames 1, 4 and 7 carry the wrong-direction note and raw data; frames 10
# and 14 decode as before.

WRONG_DIR_CIDS = (0x60, 0x61, 0x62, 0x63, 0x64)


def build_wrong_direction():
    conn = Conn(0x6E00, 1_701_220_000_000_000)
    emit = conn.emit
    data = IDCTRL.ljust(4096, b'\x00')


    def set_features(cid):
        emit(True, capsule_cmd_pdu(sqe_with_sgl(
            sqe(AQ_SET_FEATURES, cid=cid, cdw10=LBART_FID, cdw11=0),
            sgl_descriptor(0x5, SGL_SUB_CMD_DATA_BUFFER, struct.pack('<Q', 0),
                           64, bytes(3)))))

    in_capsule, c2h, h2c, read, write = WRONG_DIR_CIDS
    emit(True, capsule_cmd_pdu(sqe_with_sgl(
        sqe(AQ_IDENTIFY, cid=in_capsule, cdw10=IDENTIFY_CNS_CTRL),
        sgl_descriptor(0x0, SGL_SUB_IN_CAPSULE, struct.pack('<Q', 0),
                       len(data), bytes(3))), data=data, pdo=72))
    emit(False, capsule_resp_pdu(cid=in_capsule))
    set_features(c2h)
    emit(False, c2h_data_pdu(cid=c2h, payload=lbart_entry(0),
                             pdo=NVME_TCP_DATA_PDU_SIZE, last=True))
    emit(False, capsule_resp_pdu(cid=c2h))
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=h2c, cdw10=IDENTIFY_CNS_CTRL)))
    emit(True, h2c_data_pdu(cid=h2c, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE,
                            last=True))
    emit(False, capsule_resp_pdu(cid=h2c))

    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=read, cdw10=IDENTIFY_CNS_CTRL)))
    emit(False, c2h_data_pdu(cid=read, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE,
                             last=True))
    emit(False, capsule_resp_pdu(cid=read))
    set_features(write)
    emit(False, r2t_pdu(cid=write, ttag=1, r2to=0, r2tl=64))
    emit(True, h2c_data_pdu(cid=write, payload=lbart_entry(0),
                            pdo=NVME_TCP_DATA_PDU_SIZE, ttag=1, last=True))
    emit(False, capsule_resp_pdu(cid=write))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F244-F251 (build_prop_size) - a Property Get CQE takes
# its value width from the command's PRS
# ---------------------------------------------------------------------------
#
# A Property Get's ATTRIB.PRS (byte 40 bits 2:0) is 000b for a 4-byte and
# 001b for an 8-byte property (NVMe Base 2.3 Figure 585); for a 4-byte one the
# response VALUE is bytes 03:00 and bytes 07:04 are reserved (Figure 586).
# The CQE decode always assumed 8 bytes for a property it does not decode
# field by field, so each 4-byte read below showed one 64-bit value spanning
# CQE Dwords 0 and 1.  CRTO and NSSD are 4-byte properties (Figure 33); a
# Vendor Specific property (1300h and up, Figure 35) has only the host's PRS
# to give its width.
#
#   F1-F2  Property Get, OFST 68h (CRTO),   PRS 000b, VALUE 00280050h
#   F3-F4  Property Get, OFST 64h (NSSD),   PRS 000b, VALUE 0h, Dword 1
#          DEADBEEFh: a reserved dword that is not 0h, shown, not merged
#   F5-F6  Property Get, OFST 1304h,        PRS 000b, VALUE 89ABCDEFh
#   F7-F8  Property Get, OFST 1308h,        PRS 001b  -> 8-byte control

PROP_OFFSET_NSSD = 0x64
PROP_OFFSET_CRTO = 0x68
PROP_CRTO_VALUE = 0x00280050     # CRIMT 28h, CRWMT 50h (Figure 57)


def build_prop_size():
    conn = Conn(0x6F00, 1_701_230_000_000_000)
    emit = conn.emit


    def prop_get(cid, ofst, prs, dw0, dw1=0):
        emit(True, capsule_cmd_pdu(sqe(FABRICS_OPC, cid=cid, nsid=FCTYPE_PROP_GET,
                                       cdw10=prs, cdw11=ofst)))
        emit(False, capsule_resp_pdu(cid=cid, dw0=dw0, dw1=dw1))

    prop_get(1, PROP_OFFSET_CRTO, 0, PROP_CRTO_VALUE)               # F1-F2
    prop_get(2, PROP_OFFSET_NSSD, 0, 0, 0xDEADBEEF)                 # F3-F4
    prop_get(3, 0x00001304, 0, 0x89ABCDEF)                          # F5-F6
    prop_get(4, 0x00001308, 1, PROP_VENDOR_VALUE & 0xFFFFFFFF,
             PROP_VENDOR_VALUE >> 32)                               # F7-F8
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F252-F264 (build_discovery_numrec) - Discovery reads
# past the end of the page, delivered in C2HData windows at DATAO 2048 and 3072
# ---------------------------------------------------------------------------
#
# NUMREC is the number of records in the page (NVMe Base 2.3 Figure 312), and
# a host may read past its end: the controller returns the page "with
# undefined results for dwords beyond the end of the log page" (Figure 201).
# A later window that starts on an entry boundary decodes no entries past the
# last record.
#
# Pages: discovery_log_page(2, 2) (3,072 bytes) read as 4,096 bytes, the
# last 1,024 zero; and discovery_log_page(3, 3), exactly 4,096 bytes.
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-4   CID 2, NUMREC 2: DATAO 0 page[0:2048] (header, DLE0);
#                DATAO 2048 page[2048:4096] (DLE1, then zero fill)
#   Frames 5-8   CID 3, NUMREC 2: DATAO 0 page[0:2048]; DATAO 2048
#                page[2048:3072] (DLE1); DATAO 3072 page[3072:4096] (zero
#                fill only: no entry)
#   Frames 9-11  CID 4, NUMREC 3: DATAO 0 page[0:2048]; DATAO 2048
#                page[2048:4096] (DLE1 and DLE2, both real)
#   Frames 12-13 CID 5, NUMREC 2: one C2HData with all 4,096 bytes

DISCOVERY_NUMREC_READ = 4096
DISCOVERY_NUMREC_READS = (
    # (cid, NUMREC, DATAO of each C2HData PDU)
    (2, 2, (0, 2048)),
    (3, 2, (0, 2048, 3072)),
    (4, 3, (0, 2048)),
    (5, 2, (0,)),
)


def build_discovery_numrec():
    conn = Conn(0x7000, 1_701_240_000_000_000)
    emit = conn.emit


    cdw10 = NVME_LID_DISCOVERY | (((DISCOVERY_NUMREC_READ // 4) - 1) << 16)
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, numrec, windows in DISCOVERY_NUMREC_READS:
        page = discovery_log_page(numrec=numrec, nentries=numrec)
        page += bytes(DISCOVERY_NUMREC_READ - len(page))
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10)))
        for datao, end in zip(windows, windows[1:] + (DISCOVERY_NUMREC_READ,)):
            emit(False, c2h_data_pdu(cid=cid, payload=page[datao:end], datao=datao,
                                     pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F265-F276 (build_discovery_tel_window) - Discovery
# windows that end inside an entry's TEL
# ---------------------------------------------------------------------------
#
# When a Discovery log page may hold Extended Discovery Log Page Entries, an
# entry's length is its TEL at bytes 1027:1024 (NVMe Base 2.3 Figures 311 and
# 312).  A window that ends before the TEL cannot say where the entry ends.
# The windows below end 2 bytes into a TEL, which a dword-aligned transfer
# never does; they stand for a malformed or cut-short response.
#
# Pages, all read with LSP 01h (EXTDLPE): discovery_extended_page() (two TEL
# 1040 entries, DLPF EXTEND, TDLPL 3104), and a mixed page with the same
# header flags whose Entry 0 is a 1,024-byte Discovery Log Page Entry and
# whose Entry 1 is a TEL 1040 entry (TDLPL 3088).
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-4   CID 2, LPO 0: DATAO 0 page[0:2050] (header, Entry 0, then 2
#                bytes of its TEL); DATAO 2050 page[2050:3104]
#   Frames 5-7   CID 3, LPO 0: DATAO 0 page[0:3090] (header, Entry 0, Entry 1
#                and 2 bytes of its TEL: NUMREC stops the walk first);
#                DATAO 3090 page[3090:3104]
#   Frames 8-10  CID 4, LPO 1024: DATAO 0 page[1024:2050] (Entry 0 and 2 bytes
#                of its TEL; no header, so only EXTDLPE says a TEL is there);
#                DATAO 1026 page[2050:3104]
#   Frames 11-12 CID 5, LPO 0: the mixed page in one window; Entry 0's
#                missing TEL is Entry 1's first 4 bytes, not a valid TEL

DISCOVERY_TEL_WINDOW_READS = (
    # (cid, LPO, page byte where each C2HData PDU's data starts)
    (2, 0, (0, 2050)),
    (3, 0, (0, 3090)),
    (4, 1024, (1024, 2050)),
)


def discovery_mixed_page():
    """discovery_extended_page() with Entry 0 replaced by the 1,024-byte
    Discovery Log Page Entry it extends (Figure 310): TDLPL 3088."""
    ext = discovery_extended_page()
    hdr = bytearray(ext[:DISCOVERY_HDR_LEN])
    struct.pack_into('<I', hdr, 20, 2 * DISCOVERY_HDR_LEN + DISCOVERY_EXT_TEL)
    entry0 = ext[DISCOVERY_HDR_LEN:DISCOVERY_HDR_LEN + DISCOVERY_RCRD_LEN]
    out = bytes(hdr) + entry0 + ext[DISCOVERY_HDR_LEN + DISCOVERY_EXT_TEL:]
    assert len(out) == 2 * DISCOVERY_HDR_LEN + DISCOVERY_EXT_TEL
    return out


def build_discovery_tel_window():
    conn = Conn(0x7100, 1_701_250_000_000_000)
    emit = conn.emit
    extended = discovery_extended_page()


    def read(cid, lpo, page, starts):
        data = len(page) - lpo
        cdw10 = NVME_LID_DISCOVERY | (1 << 8) | ((((data + 3) // 4) - 1) << 16)
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10,
                                       cdw12=lpo)))
        for start, end in zip(starts, starts[1:] + (len(page),)):
            emit(False, c2h_data_pdu(cid=cid, payload=page[start:end],
                                     datao=start - lpo, pdo=NVME_TCP_DATA_PDU_SIZE))

    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, lpo, starts in DISCOVERY_TEL_WINDOW_READS:
        read(cid, lpo, extended, starts)
    read(5, 0, discovery_mixed_page(), (0,))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F277-F287 (build_discovery_index_tsas) - an indexed
# Discovery entry split across C2HData PDUs
# ---------------------------------------------------------------------------
#
# With OT set, LPO 1 selects Entry 0 of the Discovery log page (NVMe Base 2.3
# section 5.2.12.3.3), so the transfer is that one 1,024-byte entry.  The
# entry's TRTYPE (byte 00) selects the layout of its TSAS (bytes 1023:768,
# Figure 310; NVMe/TCP 1.3 Figure 17, NVMe/RDMA 1.3 Figure 3).  Here TRTYPE
# is in the DATAO 0 PDU and TSAS in the DATAO 512 PDU of the same command.
#
#   Frame 1      Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-4   CID 2: TCP entry (TRTYPE 03h, SECTYPE 02h), DATAO 0 and 512
#   Frames 5-6   CID 3: the same entry in one C2HData (control)
#   Frames 7-9   CID 4: RDMA entry (TRTYPE 01h, RDMA_QPTYPE 1, RDMA_PRTYPE 4,
#                RDMA_CMS 1, RDMA_PKEY 8001h), DATAO 0 and 512
#   Frames 10-11 CID 5: the TCP entry's DATAO 512 PDU only; with no TRTYPE
#                seen, TSAS stays raw

DISCOVERY_INDEX_TSAS_READS = (
    # (cid, TRTYPE, DATAO of each C2HData PDU)
    (2, 0x03, (0, 512)),
    (3, 0x03, (0,)),
    (4, 0x01, (0, 512)),
    (5, 0x03, (512,)),
)


def discovery_index_entry(trtype):
    """Entry 0 of discovery_log_page() with TRTYPE `trtype` and a TSAS for
    that transport: SECTYPE 02h (TLS 1.3) for TCP, or RDMA_QPTYPE 1,
    RDMA_PRTYPE 4, RDMA_CMS 1 and RDMA_PKEY 8001h for RDMA."""
    r = bytearray(discovery_log_page(1, 1)[DISCOVERY_HDR_LEN:])
    r[0] = trtype
    if trtype == 0x03:
        r[768] = 0x02
    else:
        r[768:771] = b'\x01\x04\x01'
        struct.pack_into('<H', r, 776, 0x8001)
    return bytes(r)


def build_discovery_index_tsas():
    conn = Conn(0x7200, 1_701_260_000_000_000)
    emit = conn.emit


    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, trtype, starts in DISCOVERY_INDEX_TSAS_READS:
        entry = discovery_index_entry(trtype)
        cdw10 = NVME_LID_DISCOVERY | (((len(entry) // 4) - 1) << 16)
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10,
                                       cdw12=1, cdw14=1 << 23)))     # OT, index 1
        for start, end in zip(starts, starts[1:] + (len(entry),)):
            emit(False, c2h_data_pdu(cid=cid, payload=entry[start:end],
                                     datao=start, pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F288-F298 (build_ana_inferred) - ANA log reads that
# start past the header, so no window holds the descriptor count
# ---------------------------------------------------------------------------
#
# With LPO 16 (dword aligned, NVMe Base 2.3 Figure 203) the transfer starts at
# ANA Group Descriptor 0, so NAGD (Figure 227, bytes 09:08) is in no window:
# each window walks the descriptors it holds and notes that their count is
# inferred, and the next window keeps the note.  A window that starts inside
# a descriptor can hold one piece more than its length / 32, so the inferred
# bound allows for the carried-over descriptor.
#
# Page A is build_ana_redecode's: header CHGC 5, NAGD 2; Descriptor 0 =
# AGID 1, NNV 3, CHGC 7, ANAS 01h, NSIDs 1,2,3 (page bytes 16-59);
# Descriptor 1 = AGID 2, NNV 1, CHGC 8, ANAS 02h, NSID 9 (bytes 60-95).
# Page B: header CHGC 5, NAGD 4; Descriptor 0 = AGID 1, NNV 0 (16-47);
# Descriptor 1 = AGID 2, NNV 1, NSID 9 (48-83); Descriptor 2 = AGID 3, NNV 0
# (84-115); Descriptor 3 = AGID 4, NNV 1, NSID 0Bh (116-151).
# Each read is LPO 16 to the page end, so a PDU's DATAO is its page byte - 16.
#
#   Frame 1     Identify (06h) CID 1          -> pins the queue as admin
#   Frames 2-4  CID 2, page A: DATAO 0 page[16:68] (all of Descriptor 0,
#               then Descriptor 1's AGID and NNV); DATAO 52 page[68:96]
#   Frames 5-7  CID 3, page A, the control: DATAO 0 page[16:56] (ends inside
#               Descriptor 0's NSID list, so none completes); DATAO 40
#               page[56:96]
#   Frames 8-11 CID 4, page B: DATAO 0 page[16:80]; DATAO 64 page[80:140]
#               (60 bytes: the end of Descriptor 1, all of Descriptor 2, the
#               start of Descriptor 3, three pieces); DATAO 124 page[140:152]

ANA_INFERRED_LPO = 16
ANA_INFERRED_READS = (
    # (cid, page, page bytes at which each C2HData PDU starts, then the end)
    (2, 'A', (16, 68, 96)),
    (3, 'A', (16, 56, 96)),
    (4, 'B', (16, 80, 140, 152)),
)


def build_ana_inferred():
    conn = Conn(0x7300, 1_701_270_000_000_000)
    emit = conn.emit
    pages = {
        'A': (struct.pack('<QH6x', 5, 2)
              + struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
              + struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)),
        'B': (struct.pack('<QH6x', 5, 4)
              + struct.pack('<IIQB15x', 1, 0, 7, 1)
              + struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9)
              + struct.pack('<IIQB15x', 3, 0, 9, 1)
              + struct.pack('<IIQB15x', 4, 1, 10, 3) + struct.pack('<I', 11)),
    }


    lpo = ANA_INFERRED_LPO
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, name, bounds in ANA_INFERRED_READS:
        page = pages[name]
        cdw10 = NVME_LID_ANA | ((((len(page) - lpo) // 4) - 1) << 16)
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid, cdw10=cdw10,
                                       cdw12=lpo)))
        for start, end in itertools.pairwise(bounds):
            emit(False, c2h_data_pdu(cid=cid, payload=page[start:end],
                                     datao=start - lpo, pdo=NVME_TCP_DATA_PDU_SIZE))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F299-F301 (build_shared_cid_frame) - one frame holds a
# completion and a new command with the same CID
# ---------------------------------------------------------------------------
#
# Once a command completes, its CID may be reused (NVMe Base 2.3 Figures 91
# and 98).  A frame can then hold both the completion of one command and a new
# command with that CID; NVMe/TCP 1.3 Figure 10 gives the two PDU types
# opposite directions, so one segment carrying both is not conformant, but the
# dissector reads PDUs by type.  The done list recorded command frames and
# completion frames under one [CID, frame] key, so the second command's entry
# for its own frame replaced the first command's completion there: a revisit
# of that completion found the second command, decoded the CQE as its
# completion and moved its completion to this frame.
#
#   Frame 1   Get Features (0Ah) CID 70h, FID 07h Number of Queues
#   Frame 2   one host-to-controller segment: CapsuleResp CID 70h (frame 1's
#             completion), then Set Features (09h) CID 70h, FID 07h
#   Frame 3   CapsuleResp CID 70h (frame 2's command's completion)
#
# On every pass frame 2's CQE links to frame 1 and its command to frame 3.

SHARED_CID = 0x70
SHARED_CID_FID = 0x07                       # Number of Queues: no data


def build_shared_cid_frame():
    conn = Conn(0x7400, 1_701_280_000_000_000)
    emit = conn.emit


    cid, fid = SHARED_CID, SHARED_CID_FID
    emit(True, capsule_cmd_pdu(sqe(AQ_GET_FEATURES, cid=cid, cdw10=fid)))
    emit(True, capsule_resp_pdu(cid=cid, dw0=0x003F003F)
         + capsule_cmd_pdu(sqe(AQ_SET_FEATURES, cid=cid, cdw10=fid, cdw11=0x001F001F)))
    emit(False, capsule_resp_pdu(cid=cid, dw0=0x001F001F))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F302-F309 (build_ic_pin) - only an ICReq or ICResp
# pins a connection
# ---------------------------------------------------------------------------
#
# A capture that starts mid-connection can catch one direction at a PDU start
# and the other in the middle of a PDU.  The first PDU start the heuristic
# took pinned the connection, both directions, to NVMe/TCP, so the other
# direction was framed from whatever its first captured segment held.  Only
# the ICReq/ICResp exchange that opens a connection (NVMe/TCP 1.3 section 3.1)
# says the capture has every PDU boundary from there on.
#
#   Frame 1   host port 55260, mid-connection: Get Features (0Ah) CID 80h,
#             FID 07h Number of Queues
#   Frame 2   64 bytes from the middle of a controller PDU, reading
#             5a 11 22 33 04 05 06 07 (a reserved type; PLEN 07060504h)
#   Frame 3   CapsuleResp CID 80h
#   Frame 4   host port 55261: ICReq
#   Frame 5   ICResp
#   Frame 6   H2CTermReq with HLEN = PLEN = 20 (< the 24-byte header)
#   Frame 7   host port 55262: ICResp (the ICReq was not captured)
#   Frame 8   H2CTermReq with HLEN = PLEN = 20
#
# Frame 2 is not NVMe/TCP and frame 3 completes frame 1.  No PDU start has
# HLEN 20, so frames 6 and 8 reach the PLEN guard only because frames 4 and 7
# pinned their connections.

IC_PIN_CID = 0x80
IC_PIN_FID = 0x07                           # Number of Queues: no data
IC_PIN_CONTINUATION = (bytes.fromhex('5a11223304050607')
                       + bytes(((i * 41 + 7) & 0xFF) for i in range(56)))


def build_ic_pin():
    conn = Conn(0x7500, 1_701_290_000_000_000)
    # HOST_PORT starts mid-connection; HOST_PORT + 2's ICReq was not captured.
    conn.seq = {(HOST_PORT, True): 0x00051001, (HOST_PORT, False): 0x00C30001,
                (HOST_PORT + 2, True): 1 + NVME_TCP_IC_PDU_SIZE}

    def emit(port, to_ctrl, payload):
        conn.emit(to_ctrl, payload, port)

    emit(HOST_PORT, True, capsule_cmd_pdu(sqe(AQ_GET_FEATURES, cid=IC_PIN_CID,
                                              cdw10=IC_PIN_FID)))
    emit(HOST_PORT, False, IC_PIN_CONTINUATION)
    emit(HOST_PORT, False, capsule_resp_pdu(cid=IC_PIN_CID, dw0=0x003F003F))
    emit(HOST_PORT + 1, True, icreq_pdu())
    emit(HOST_PORT + 1, False, icresp_pdu())
    emit(HOST_PORT + 1, True, h2ctermreq_pdu(SHORT_TERMREQ_PLEN))
    emit(HOST_PORT + 2, False, icresp_pdu())
    emit(HOST_PORT + 2, True, h2ctermreq_pdu(SHORT_TERMREQ_PLEN))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F310-F324 (build_subnqn_ver_order) - Identify
# Controller data whose VER and SUBNQN come in separate C2HData PDUs
# ---------------------------------------------------------------------------
#
# SUBNQN (bytes 1023:768) is decoded whatever VER (83:80) the Identify data
# reports, so the order of the DATAO 0 and DATAO 768 PDUs does not matter
# (NVMe/TCP 1.3 section 3.3.2.1).
#
#   Frames 1-2    ICReq, ICResp
#   Frames 3-6    Identify CNS 01h CID 90h: DATAO 768 (SUBNQN), then DATAO 0
#                 (VER 1.2.0), CapsuleResp
#   Frames 7-10   CID 91h: DATAO 0 (VER 1.2.0), DATAO 768, CapsuleResp
#   Frames 11-15  CID 92h: DATAO 0 (VER 1.2.0), DATAO 768, DATAO 0 (VER
#                 2.3.0), CapsuleResp
#
# On every pass frames 4, 9 and 13 are SUBNQN.

SUBNQN_VER_CIDS = (0x90, 0x91, 0x92)
SUBNQN_VER_OLD = 0x00010200                 # 1.2.0
SUBNQN_VER_NQN = b'nqn.2026-10.com.example:subnqn-order'


def build_subnqn_ver_order():
    conn = Conn(0x7700, 1_701_310_000_000_000)
    emit = conn.emit

    def head(ver):
        data = bytearray(768)
        struct.pack_into('<I', data, 80, ver)           # VER
        return bytes(data)

    nqn = SUBNQN_VER_NQN.ljust(256, b'\0')
    reversed_, in_order, repeated = SUBNQN_VER_CIDS
    emit(True, icreq_pdu())
    emit(False, icresp_pdu())
    for cid, blocks in (
            (reversed_, ((768, nqn), (0, head(SUBNQN_VER_OLD)))),
            (in_order, ((0, head(SUBNQN_VER_OLD)), (768, nqn))),
            (repeated, ((0, head(SUBNQN_VER_OLD)), (768, nqn),
                        (0, head(IDCTRL_VER))))):
        emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=cid,
                                       cdw10=IDENTIFY_CNS_CTRL)))
        for datao, payload in blocks:
            emit(False, c2h_data_pdu(cid=cid, payload=payload, datao=datao,
                                     pdo=NVME_TCP_DATA_PDU_SIZE))
        emit(False, capsule_resp_pdu(cid=cid))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F325-F338 (build_rab_mdts) - RAB and MDTS exponents of
# 64 and up
# ---------------------------------------------------------------------------
#
# RAB (byte 72) and MDTS (byte 77) of the Identify Controller data structure
# are 8-bit exponents n of 2^n (NVMe Base 2.3 Figure 328), with no upper bound;
# MDTS 0h means no limit.  Their labels shifted a 64-bit 1 left by n, which is
# undefined for n >= 64.
#
#   Frames 1-2    ICReq, ICResp
#   Frames 3-5    Identify CNS 01h CID A0h, RAB 00h, MDTS 00h: C2HData, CapsuleResp
#   Frames 6-8    CID A1h, RAB 3Fh, MDTS 3Fh (the largest exact 2^n)
#   Frames 9-11   CID A2h, RAB 40h, MDTS 80h
#   Frames 12-14  CID A3h, RAB FFh, MDTS FFh

RAB_MDTS_CASES = (
    # (CID, RAB, MDTS)
    (0xA0, 0x00, 0x00),
    (0xA1, 0x3F, 0x3F),
    (0xA2, 0x40, 0x80),
    (0xA3, 0xFF, 0xFF),
)


def build_rab_mdts():
    conn = Conn(0x7800, 1_701_320_000_000_000)
    emit = conn.emit


    emit(True, icreq_pdu())
    emit(False, icresp_pdu())
    for cid, rab, mdts in RAB_MDTS_CASES:
        data = bytearray(4096)
        data[72] = rab
        data[77] = mdts
        struct.pack_into('<I', data, 80, IDCTRL_VER)        # VER
        emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=cid,
                                       cdw10=IDENTIFY_CNS_CTRL)))
        emit(False, c2h_data_pdu(cid=cid, payload=bytes(data),
                                 pdo=NVME_TCP_DATA_PDU_SIZE))
        emit(False, capsule_resp_pdu(cid=cid))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F339-F344 (build_cap_labels) - the CAP fields with
# custom labels
# ---------------------------------------------------------------------------
#
# A Property Get of CAP (OFST 0h, PRS 001b: 8 bytes, NVMe Base 2.3 Figures 33
# and 585) answered with two CAP values (Figure 36).  MQES, TO, DSTRD, CSS,
# MPSMIN and MPSMAX are 64-bit fields with custom labels; the labels must
# show the field's own bits for every value the field can hold.
#
#   Frames 1-2  ICReq, ICResp
#   Frames 3-4  Property Get CAP CID 1: MQES 3FFh, CQR, TO 1Eh, DSTRD 0h,
#               CSS 41h (IOCSS, NCSS), MPSMIN 0h, MPSMAX 4h
#   Frames 5-6  Property Get CAP CID 2: every bit set, so each field holds its
#               largest value

CAP_TYPICAL = (0x03FF                 # MQES 15:00, 0's based
               | 1 << 16              # CQR, 1 for a message-based controller
               | 0x1E << 24           # TO 31:24, 500 ms units
               | 0x41 << 37           # CSS 44:37: IOCSS, NCSS
               | 4 << 52)             # MPSMAX 55:52; DSTRD, MPSMIN 0h
CAP_ALL_ONES = 0xFFFFFFFFFFFFFFFF


def build_cap_labels():
    conn = Conn(0x7900, 1_701_330_000_000_000)
    emit = conn.emit


    emit(True, icreq_pdu())
    emit(False, icresp_pdu())
    for cid, cap in ((1, CAP_TYPICAL), (2, CAP_ALL_ONES)):
        emit(True, capsule_cmd_pdu(sqe(FABRICS_OPC, cid=cid, nsid=FCTYPE_PROP_GET,
                                       cdw10=1, cdw11=0)))       # PRS 001b, CAP
        emit(False, capsule_resp_pdu(cid=cid, dw0=cap & 0xFFFFFFFF, dw1=cap >> 32))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-split-header.pcapng (build_split_header) - a PDU header split
# where a reassembled PDU ends
# ---------------------------------------------------------------------------
#
# No ICReq, so the connection is never pinned and each segment that is not
# inside a reassembly goes back to the heuristic.  When the multi-segment
# C2HData completes, TCP hands the rest of its last segment, the first 4
# bytes of the CapsuleResp header, to the heuristic on its own.  That is too
# short for test_nvme() to check.
#
#   Frame 1   mid-connection: Identify (06h) CNS 01h CID 81h
#   Frame 2   C2HData CID 81h, 4,096 bytes, LAST_PDU: first 1,448 bytes
#   Frame 3   the next 1,448 bytes
#   Frame 4   the last 1,224 bytes of the C2HData, then 4 bytes of the
#             CapsuleResp header
#   Frame 5   the last 20 bytes of the CapsuleResp CID 81h
#
# Frame 5 completes frame 1.  A capture of its own, like plen-zero: TCP
# itself gives frames 2-3 a different Protocol and Info column on a second
# pass ([TCP PDU reassembled in 4]), so the capture-wide pass-parity test
# cannot hold for it.

SPLIT_HDR_CID = 0x81
SPLIT_HDR_CUT = 4                           # CapsuleResp bytes in frame 4
SPLIT_HDR_MSS = 1448


def build_split_header():
    conn = Conn(0x7600, 1_701_300_000_000_000)
    conn.seq = {(HOST_PORT, True): 0x00052001, (HOST_PORT, False): 0x00C40001}
    emit = conn.emit

    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=SPLIT_HDR_CID, cdw10=1)))
    data = c2h_data_pdu(SPLIT_HDR_CID, bytes(((i * 7 + 3) & 0xFF) for i in range(4096)),
                        last=True)
    stream = data + capsule_resp_pdu(cid=SPLIT_HDR_CID, sqhd=1)
    cuts = (SPLIT_HDR_MSS, 2 * SPLIT_HDR_MSS, len(data) + SPLIT_HDR_CUT, len(stream))
    start = 0
    for end in cuts:
        emit(False, stream[start:end])
        start = end
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-fdp-events.pcapng (build_fdp_events) - Get Features FDP Events data
# that arrives before the completion carrying its count
# ---------------------------------------------------------------------------
#
# The number of descriptors in the Get Features FDP Events data buffer is NOET,
# which only Dword 0 of a successful completion carries (NVMe Base 2.3 Figure
# 436; Figure 440 lists NOET two-byte descriptors, Figure 441 their layout).
# CDW11 NOET is ignored on a Get Features command (Figure 437), so every
# command sets it to 7 on purpose.  NVMe/TCP sends the completion after the
# data, so a first pass has no count when it dissects the data.  The 8-byte
# buffer holds three descriptors (01h enabled, 02h disabled, 03h enabled) and
# two trailing bytes (7Fh, 01h) that only a length-based decode would read.
#
#   Frames 1-2    ICReq, ICResp
#   Frames 3-5    CID B0h: C2HData DATAO 0, 8 bytes, LAST; CapsuleResp, DW0 3
#   Frames 6-9    CID B1h: C2HData DATAO 0 (bytes 0-3), C2HData DATAO 4
#                 (bytes 4-7, LAST); CapsuleResp, DW0 3
#   Frames 10-12  CID B2h: C2HData, 8 bytes, LAST; CapsuleResp status 29h
#                 (FDP Disabled, Figure 102; the status word is SC << 1),
#                 DW0 3
#   Frames 13-14  CID B3h: C2HData, 8 bytes, LAST and SUCCESS, no CapsuleResp
#                 (NVMe/TCP 1.3 section 3.3.2.1: the synthesized completion's
#                 Command Specific field is 0h)
#
# A capture of its own: the descriptors of CID B0h and B1h decode only once
# the completion has been seen, so the capture-wide pass-parity test cannot
# hold for it.

FDP_EVENTS_FID = 0x1E
FDP_EVENTS_DESC = bytes.fromhex('0101020003017f01')
FDP_EVENTS_NOET = 3
FDP_DISABLED = 0x29 << 1


def build_fdp_events():
    conn = Conn(0x7A00, 1_701_340_000_000_000)
    emit = conn.emit


    def get_features(cid):
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_FEATURES, cid=cid, nsid=1,
                                       cdw10=FDP_EVENTS_FID, cdw11=0x00070000)))

    def data(cid, payload, datao=0, **flags):
        emit(False, c2h_data_pdu(cid, payload, datao=datao,
                                 pdo=NVME_TCP_DATA_PDU_SIZE, **flags))

    emit(True, icreq_pdu())
    emit(False, icresp_pdu())

    get_features(0xB0)
    data(0xB0, FDP_EVENTS_DESC, last=True)
    emit(False, capsule_resp_pdu(cid=0xB0, dw0=FDP_EVENTS_NOET))

    get_features(0xB1)
    data(0xB1, FDP_EVENTS_DESC[:4])
    data(0xB1, FDP_EVENTS_DESC[4:], datao=4, last=True)
    emit(False, capsule_resp_pdu(cid=0xB1, dw0=FDP_EVENTS_NOET))

    get_features(0xB2)
    data(0xB2, FDP_EVENTS_DESC, last=True)
    emit(False, capsule_resp_pdu(cid=0xB2, dw0=FDP_EVENTS_NOET, status=FDP_DISABLED))

    get_features(0xB3)
    data(0xB3, FDP_EVENTS_DESC, last=True, success=True)
    return bytes(conn.out)


def with_host_ports(data, ports):
    """`data` (a pcapng section) with each TCP port P in `ports` rewritten to
    ports[P].  A merged capture appends each source capture as a section of
    its own, but TCP conversations, and so NVMe/TCP queue state, are keyed by
    address and port, not by section; a host port per section keeps them
    apart.  TCP checksums are left 0 here, so nothing else changes."""
    out, pos = bytearray(data), 0
    while pos < len(out):
        block_type, block_len = struct.unpack_from('<II', out, pos)
        if block_type == 6:                       # Enhanced Packet Block
            caplen = struct.unpack_from('<I', out, pos + 20)[0]
            packet = pos + 28
            if caplen >= 34 and out[packet + 12:packet + 14] == b'\x08\x00' \
                    and out[packet + 23] == 6:     # IPv4, TCP
                tcp_at = packet + 14 + (out[packet + 14] & 0x0F) * 4
                for field in (tcp_at, tcp_at + 2):
                    if field + 2 <= packet + caplen:
                        port = struct.unpack_from('>H', out, field)[0]
                        struct.pack_into('>H', out, field, ports.get(port, port))
        pos += block_len
    return bytes(out)


def build_admin_capture():
    """nvme-tcp-admin.pcapng: build()'s F1-F8, then the other Admin-queue
    captures as sections of their own (frame maps in their builders):

      F9-F10   build_css                   host port 55010
      F11-F13  build_discovery             host port 55020
      F14-F17  build_logpage_datal         host port 55030
      F18-F25  build_aer_immediate         host port 55040
      F26-F76  build_shared_decode_native      host port 55050
      F77-F82  build_ana_redecode          host port 55060
      F83-F96  build_prop_offset           host port 55070
      F97-F100 build_capsule_size          host port 55080
      F101-F116 build_ana_split            host port 55090
      F117-F121 build_ana_unplaced         host port 55100
      F122-F139 build_ana_gap              host port 55110
      F140-F150 build_discovery_extdlpe    host port 55120
      F151-F183 build_ana_revisit          host port 55130
      F184-F194 build_h2c_lbart            host port 55140
      F195-F206 build_stale_cid            host port 55150
      F207-F215 build_c2h_success          host port 55160
      F216-F223 build_missing_cqe          host port 55170
      F224-F228 build_midstream_start      host ports 55180/55181
      F229-F243 build_wrong_direction      host port 55190
      F244-F251 build_prop_size            host port 55200
      F252-F264 build_discovery_numrec     host port 55210
      F265-F276 build_discovery_tel_window host port 55220
      F277-F287 build_discovery_index_tsas host port 55230
      F288-F298 build_ana_inferred         host port 55240
      F299-F301 build_shared_cid_frame     host port 55250
      F302-F309 build_ic_pin               host ports 55260-55262
      F310-F324 build_subnqn_ver_order     host port 55270
      F325-F338 build_rab_mdts             host port 55280
      F339-F344 build_cap_labels           host port 55290
      F345-F350 build_ana_one_segment      host port 55300
      F351-F357 build_connect_nqn          host port 55310
      F358-F359 build_connect_pdo          host port 55320
      F360-F365 build_termreq_fes          host port 55330
      F366-F376 build_dnps_window_end      host port 55340
      F377-F383 build_scc_window           host port 55350
    """
    return b''.join((
        build(),
        with_host_ports(build_css(), {HOST_PORT: 55010}),
        with_host_ports(build_discovery(), {HOST_PORT: 55020}),
        with_host_ports(build_logpage_datal(), {HOST_PORT: 55030}),
        with_host_ports(build_aer_immediate(), {HOST_PORT: 55040}),
        with_host_ports(build_shared_decode_native(), {HOST_PORT: 55050}),
        with_host_ports(build_ana_redecode(), {HOST_PORT: 55060}),
        with_host_ports(build_prop_offset(), {HOST_PORT: 55070}),
        with_host_ports(build_capsule_size(), {HOST_PORT: 55080}),
        with_host_ports(build_ana_split(), {HOST_PORT: 55090}),
        with_host_ports(build_ana_unplaced(), {HOST_PORT: 55100}),
        with_host_ports(build_ana_gap(), {HOST_PORT: 55110}),
        with_host_ports(build_discovery_extdlpe(), {HOST_PORT: 55120}),
        with_host_ports(build_ana_revisit(), {HOST_PORT: 55130}),
        with_host_ports(build_h2c_lbart(), {HOST_PORT: 55140}),
        with_host_ports(build_stale_cid(), {HOST_PORT: 55150}),
        with_host_ports(build_c2h_success(), {HOST_PORT: 55160}),
        with_host_ports(build_missing_cqe(), {HOST_PORT: 55170}),
        with_host_ports(build_midstream_start(),
                        {HOST_PORT: 55180, HOST_PORT + 1: 55181}),
        with_host_ports(build_wrong_direction(), {HOST_PORT: 55190}),
        with_host_ports(build_prop_size(), {HOST_PORT: 55200}),
        with_host_ports(build_discovery_numrec(), {HOST_PORT: 55210}),
        with_host_ports(build_discovery_tel_window(), {HOST_PORT: 55220}),
        with_host_ports(build_discovery_index_tsas(), {HOST_PORT: 55230}),
        with_host_ports(build_ana_inferred(), {HOST_PORT: 55240}),
        with_host_ports(build_shared_cid_frame(), {HOST_PORT: 55250}),
        with_host_ports(build_ic_pin(), {HOST_PORT: 55260, HOST_PORT + 1: 55261,
                                         HOST_PORT + 2: 55262}),
        with_host_ports(build_subnqn_ver_order(), {HOST_PORT: 55270}),
        with_host_ports(build_rab_mdts(), {HOST_PORT: 55280}),
        with_host_ports(build_cap_labels(), {HOST_PORT: 55290}),
        with_host_ports(build_ana_one_segment(), {HOST_PORT: 55300}),
        with_host_ports(build_connect_nqn(), {HOST_PORT: 55310}),
        with_host_ports(build_connect_pdo(), {HOST_PORT: 55320}),
        with_host_ports(build_termreq_fes(), {HOST_PORT: 55330}),
        with_host_ports(build_dnps_window_end(), {HOST_PORT: 55340}),
        with_host_ports(build_scc_window(), {HOST_PORT: 55350}),
    ))


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F345-F350 (build_ana_one_segment) - two ANA reads whose
# second windows share one TCP segment and one DATAO
# ---------------------------------------------------------------------------
#
# Each read walks its own page (NVMe Base 2.3 Figures 227/228), so the walk
# state a window starts with belongs to the command, not to the frame or to
# the window's offset.  Page A is build_ana_redecode's (NAGD 2, 96 bytes).
# Page B has NAGD 1: Descriptor 0 = AGID 5, NNV 1, NSID 7 (bytes 16-51), then
# 32 bytes that look like a descriptor with AGID 77h but are past NAGD.
#
#   Frame 1  Identify (06h) CID 1          -> pins the queue as admin
#   Frame 2  Get Log Page CID 2, ANA, NUMD 96 (page A)
#   Frame 3  Get Log Page CID 3, ANA, NUMD 84 (page B)
#   Frame 4  C2HData CID 2 [0:16]
#   Frame 5  C2HData CID 3 [0:16]
#   Frame 6  one segment: C2HData CID 2 [16:96], then C2HData CID 3 [16:84],
#            both at DATAO 16

def build_ana_one_segment():
    conn = Conn(0x7B00, 1_701_350_000_000_000)
    emit = conn.emit
    page_a = (struct.pack('<QH6x', 5, 2)
              + struct.pack('<IIQB15x', 1, 3, 7, 1) + struct.pack('<III', 1, 2, 3)
              + struct.pack('<IIQB15x', 2, 1, 8, 2) + struct.pack('<I', 9))
    page_b = (struct.pack('<QH6x', 6, 1)
              + struct.pack('<IIQB15x', 5, 1, 9, 1) + struct.pack('<I', 7)
              + struct.pack('<IIQB15x', 0x77, 0, 10, 1))

    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, page in ((2, page_a), (3, page_b)):
        emit(True, capsule_cmd_pdu(sqe(AQ_GET_LOG_PAGE, cid=cid,
                                       cdw10=NVME_LID_ANA | (((len(page) // 4) - 1) << 16))))
    for cid, page in ((2, page_a), (3, page_b)):
        emit(False, c2h_data_pdu(cid=cid, payload=page[:16], datao=0,
                                 pdo=NVME_TCP_DATA_PDU_SIZE))
    emit(False, b''.join(c2h_data_pdu(cid=cid, payload=page[16:], datao=16,
                                      pdo=NVME_TCP_DATA_PDU_SIZE)
                         for cid, page in ((2, page_a), (3, page_b))))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F351-F357 (build_connect_nqn) - NQN fields with and
# without a terminating NUL
# ---------------------------------------------------------------------------
#
# An NQN is a null-terminated UTF-8 string of at most 223 bytes in a 256-byte
# field (NVMe Base 2.4 section 4.7; Figure 636 SUBNQN/HOSTNQN, Figure 338
# SUBNQN).  Base 2.4 section 1.4.2 says such a field "should be padded with
# nulls", so the bytes after the NUL are not guaranteed to be 00h.  A field with
# no NUL at all breaks the 4.7 rule, but must still show all 256 bytes and
# nothing past them.
#
#   Frames 1-2  ICReq, ICResp
#   Frame 3     Connect CID 1, QID 0, 1024 bytes of in-capsule data: SUBNQN
#               NUL-padded with a two-byte UTF-8 character, HOSTNQN 256
#               non-NUL bytes
#   Frame 4     CapsuleResp CID 1
#   Frame 5     Identify CNS 01h CID 2
#   Frame 6     C2HData CID 2, DATAO 768: SUBNQN 256 non-NUL bytes
#   Frame 7     CapsuleResp CID 2

CONNECT_NQN_SUB = 'nqn.2026-11.com.example:caf\u00e9-subsystem'.encode('utf-8')
CONNECT_NQN_FULL = (b'nqn.2026-11.com.example:' + b'h' * 256)[:256]


def build_connect_nqn():
    conn = Conn(0x7C00, 1_701_360_000_000_000)
    emit = conn.emit
    data = bytearray(1024)
    data[256:256 + len(CONNECT_NQN_SUB)] = CONNECT_NQN_SUB
    data[512:768] = CONNECT_NQN_FULL
    emit(True, icreq_pdu())
    emit(False, icresp_pdu())
    emit(True, capsule_cmd_pdu(sqe_with_sgl(
        connect_sqe(cid=1, qid=0),
        sgl_descriptor(0x0, SGL_SUB_IN_CAPSULE, struct.pack('<Q', 0),
                       len(data), bytes(3))), data=bytes(data), pdo=72))
    emit(False, capsule_resp_pdu(cid=1))
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=2, cdw10=IDENTIFY_CNS_CTRL)))
    emit(False, c2h_data_pdu(cid=2, payload=CONNECT_NQN_FULL, datao=768,
                             pdo=NVME_TCP_DATA_PDU_SIZE))
    emit(False, capsule_resp_pdu(cid=2))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F358-F359 (build_connect_pdo) - the Connect data item
# of a capsule with a header digest, padding and a data digest
# ---------------------------------------------------------------------------
#
# build_connect_nqn's Connect has PDO 72, so its data starts right after the
# header.  Here PDO is 128, so the data follows the 4-byte header digest and 52
# bytes of padding (NVMe/TCP 1.3 Figure 30), and a data digest ends the PDU.
# The nvme-tcp.cmd.data item must start at PDO and be the capsule's data, no
# more and no less.
#
# The capture starts mid-connection, as build_h2c_digest's does: an ICReq and
# ICResp would negotiate the digests (Figures 26 and 27) and these would be
# either off or claimed, so none is sent.
#
#   Frame 1     Connect CID 1, QID 0, HDGST, DDGST, PDO 128, 1024 bytes of data
#   Frame 2     CapsuleResp CID 1

CONNECT_PDO_PDO = 128


def build_connect_pdo():
    conn = Conn(0x7D00, 1_701_370_000_000_000)
    emit = conn.emit
    data = bytes(((i * 3 + 5) & 0xFF) for i in range(1024))
    emit(True, capsule_cmd_pdu(sqe_with_sgl(
        connect_sqe(cid=1, qid=0),
        sgl_descriptor(0x0, SGL_SUB_IN_CAPSULE, struct.pack('<Q', 0),
                       len(data), bytes(3))), data=data, pdo=CONNECT_PDO_PDO,
        hdgst=True, ddgst=True))
    emit(False, capsule_resp_pdu(cid=1))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F360-F365 (build_termreq_fes) - the Fatal Error Status
# of the two Termination Requests
# ---------------------------------------------------------------------------
#
# The two PDUs name FES 05h differently: an H2CTermReq (Figure 28) reports "R2T
# Limit Exceeded", a C2HTermReq (Figure 29) "Data Transfer Limit Exceeded".  06h
# is Unsupported Parameter in both.  Each PDU is the 24-byte TermReq header plus
# the offending PDU's header, with a total PLEN of at most 152 bytes.
#
#   Frames 1-2  ICReq, ICResp
#   Frame 3     H2CTermReq, FES 05h
#   Frame 4     C2HTermReq, FES 05h
#   Frame 5     H2CTermReq, FES 06h, FEI 12
#   Frame 6     C2HTermReq, FES 06h, FEI 12

NVME_TCP_C2H_TERM = 0x03
NVME_TCP_TERMREQ_PDU_SIZE = 24
NVME_TCP_FES_R2T_LIMIT = 0x05            # H2CTermReq; C2HTermReq: data transfer limit
NVME_TCP_FES_UNSUPPORTED_PARAM = 0x06


def termreq_pdu(pdu_type, fes, fei=0):
    """H2CTermReq or C2HTermReq: HLEN 24, then FES, FEI and the 24-byte header
    of the PDU in error."""
    trailer = bytes(range(0xA0, 0xA0 + 24))
    plen = NVME_TCP_TERMREQ_PDU_SIZE + len(trailer)
    ch = struct.pack('<BBBBI', pdu_type, 0x00, NVME_TCP_TERMREQ_PDU_SIZE, 0x00, plen)
    return ch + struct.pack('<HI', fes, fei) + bytes(10) + trailer


def build_termreq_fes():
    conn = Conn(0x7E00, 1_701_380_000_000_000)
    emit = conn.emit
    emit(True, icreq_pdu())
    emit(False, icresp_pdu())
    emit(True, termreq_pdu(NVME_TCP_H2C_TERM, NVME_TCP_FES_R2T_LIMIT))
    emit(False, termreq_pdu(NVME_TCP_C2H_TERM, NVME_TCP_FES_R2T_LIMIT))
    emit(True, termreq_pdu(NVME_TCP_H2C_TERM, NVME_TCP_FES_UNSUPPORTED_PARAM, 12))
    emit(False, termreq_pdu(NVME_TCP_C2H_TERM, NVME_TCP_FES_UNSUPPORTED_PARAM, 12))
    return bytes(conn.out)


def get_log_page_sqe(cid, lid, nbytes, lpo=0, nsid=0):
    """Get Log Page with the Number of Dwords (NUMD, 0's based) of `nbytes` and
    the 64-bit Log Page Offset split over Command Dwords 12 and 13."""
    numd = nbytes // 4 - 1
    return sqe(AQ_GET_LOG_PAGE, cid=cid, nsid=nsid,
               cdw10=lid | ((numd & 0xFFFF) << 16), cdw11=numd >> 16,
               cdw12=lpo & 0xFFFFFFFF, cdw13=lpo >> 32)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F366-F376 (build_dnps_window_end) - a Dispersed
# Namespace Participating NVM Subsystems window that ends at 2^32
# ---------------------------------------------------------------------------
#
# Entry i of the list is at byte 256 + 256 * i of the page (NVMe Base 2.3 Figure
# 275) and each is named after its i.  The dissector models 16,777,214 entries,
# so the last one it decodes ends at 2^32 - 256.  Each window is a single
# transfer at LPO and no more than a few KiB: no 4 GiB page is needed to read
# an entry at so high an offset.  A window whose end is at 2^32 once lost every
# entry, where the same window cut short of it kept them.
#
#   Frame 1      Identify CNS 01h, CID 1 -> an Admin queue
#   Frames 2-3   CID 2, LPO FFFFFC00h, 768 bytes (ends at 2^32 - 256): entries
#                16777211-16777213
#   Frames 4-5   CID 3, LPO FFFFFC00h, 1024 bytes (ends at 2^32): the same
#                three entries and a fourth that the entry cap leaves out
#   Frames 6-7   CID 4, LPO FFFFFD00h, 512 bytes (ends at 2^32 - 256):
#                entries 16777212-16777213
#   Frames 8-9   CID 5, LPO FFFFFE00h, 512 bytes (ends at 2^32): entry
#                16777213
#   Frames 10-11 CID 6, LPO FFFFFE00h, 256 bytes: the same entry, cut short
#
# Frames 2, 4, 6, 8 and 10 are the commands, the others each a C2HData.

NVME_LID_DNPS = 0x17
DNPS_ENTRY_FIRST = 256
DNPS_ENTRY_SIZE = 256
DNPS_READS = (
    # (cid, LPO, bytes)
    (2, 0xFFFFFC00, 768),
    (3, 0xFFFFFC00, 1024),
    (4, 0xFFFFFD00, 512),
    (5, 0xFFFFFE00, 512),
    (6, 0xFFFFFE00, 256),
)


def dnps_entry(lpo_byte):
    """The NQN entry that the page holds at byte `lpo_byte`."""
    slot = (lpo_byte - DNPS_ENTRY_FIRST) // DNPS_ENTRY_SIZE
    name = f'nqn.2026-11.com.example:dnps-{slot}'.encode('ascii')
    return name + bytes(DNPS_ENTRY_SIZE - len(name))


def build_dnps_window_end():
    conn = Conn(0x7F00, 1_701_390_000_000_000)
    emit = conn.emit
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, lpo, nbytes in DNPS_READS:
        emit(True, capsule_cmd_pdu(get_log_page_sqe(cid, NVME_LID_DNPS, nbytes, lpo, nsid=1)))
        data = b''.join(dnps_entry(lpo + i) for i in range(0, nbytes, DNPS_ENTRY_SIZE))
        emit(False, c2h_data_pdu(cid=cid, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE,
                                 last=True))
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-admin.pcapng F377-F383 (build_scc_window) - Supported Capacity
# Configuration List windows that do not start at LPO 0
# ---------------------------------------------------------------------------
#
# Descriptors start at byte 16 of the log page and are 32 bytes with no
# Endurance Group: CCID, DID and EGCN 0 (NVMe Base 2.3 Figures 261 and 262).  A
# window past the header does not know the descriptor count (SCCN), so the list
# ends where the bytes left in the window are all zero: the descriptors decode
# through the last non-zero byte.
#
#   Frame 1     Identify CNS 01h, CID 1 -> an Admin queue
#   Frames 2-3  CID 2, LPO 4: 12 header bytes, descriptors CCID 0101h and
#               0202h, then 96 zero bytes
#   Frames 4-5  CID 3, LPO 4: the same two descriptors, an all-zero descriptor
#               and CCID 0404h, then 64 zero bytes
#   Frames 6-7  CID 4, LPO 16: descriptors CCID 0505h and 0606h, then 64 zero
#               bytes

NVME_LID_SCC = 0x11
SCC_DESC_SIZE = 32
SCC_READS = (
    # (cid, LPO, CCIDs of the descriptors, zero bytes after them)
    (2, 4, (0x0101, 0x0202), 96),
    (3, 4, (0x0101, 0x0202, 0, 0x0404), 64),
    (4, 16, (0x0505, 0x0606), 64),
)


def scc_descriptor(ccid):
    """A descriptor of CCID `ccid`, DID `ccid` + 1 and no Endurance Group."""
    return struct.pack('<HHH', ccid, ccid + 1 if ccid else 0, 0) + bytes(26)


def build_scc_window():
    conn = Conn(0x8100, 1_701_400_000_000_000)
    emit = conn.emit
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    for cid, lpo, ccids, zeros in SCC_READS:
        data = (bytes(16 - lpo) + b''.join(scc_descriptor(c) for c in ccids) + bytes(zeros))
        emit(True, capsule_cmd_pdu(get_log_page_sqe(cid, NVME_LID_SCC, len(data), lpo)))
        emit(False, c2h_data_pdu(cid=cid, payload=data, pdo=NVME_TCP_DATA_PDU_SIZE,
                                 last=True))
    return bytes(conn.out)


# A window of SCC_SCAN_LEN bytes at LPO 4 that is zero up to its last byte, so
# a decoder that rescans the rest of the window for every descriptor takes
# quadratic time.  It is built by the test that needs it and is not one of the
# captures main() writes.
SCC_SCAN_LEN = 1 << 20
TCP_SEGMENT_MAX = 60000


def build_scc_scan(length=SCC_SCAN_LEN):
    conn = Conn(0x8200, 1_701_410_000_000_000)
    emit = conn.emit
    emit(True, capsule_cmd_pdu(sqe(AQ_IDENTIFY, cid=1, cdw10=IDENTIFY_CNS_CTRL)))
    emit(True, capsule_cmd_pdu(get_log_page_sqe(2, NVME_LID_SCC, length, 4)))
    pdu = c2h_data_pdu(cid=2, payload=bytes(length - 1) + b'\x01',
                       pdo=NVME_TCP_DATA_PDU_SIZE, last=True)
    for start in range(0, len(pdu), TCP_SEGMENT_MAX):
        emit(False, pdu[start:start + TCP_SEGMENT_MAX])
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F85-F93 (build_rw_cdw13) - Read and Write Command Dword 13
# ---------------------------------------------------------------------------
#
# CDW13 bits 7:0 are the Dataset Management field of a Read or a Write (NVM
# Command Set 1.3 Figures 55 and 72): access frequency in 3:0, access latency
# in 5:4, Sequential Request in bit 6 and Incompressible in bit 7.  CDW12
# CETYPE is 0, so nothing else is set.
#
#   Connection 55070
#     F1       Fabrics Connect, QID 1
#     F2-F5    Read, CID 2-5, CDW13 00h, 40h, 80h, C0h
#     F6-F9    Write, CID 6-9, CDW13 00h, 40h, 80h, C0h

RW_CDW13_PORT = 55070
RW_CDW13_VALUES = (0x00, 0x40, 0x80, 0xC0)


def build_rw_cdw13():
    conn = Conn(0x8300, 1_701_420_000_000_000, RW_CDW13_PORT)
    emit = conn.emit
    emit(True, capsule_cmd_pdu(connect_sqe(cid=1, qid=1)))
    cid = 2
    for opcode in (IOQ_READ, IOQ_WRITE):
        for cdw13 in RW_CDW13_VALUES:
            emit(True, capsule_cmd_pdu(sqe(opcode, cid=cid, nsid=1, cdw13=cdw13)))
            cid += 1
    return bytes(conn.out)


# ---------------------------------------------------------------------------
# nvme-tcp-io.pcapng F94-F97 (build_unknown_data) - the data of a PDU whose
# command is not known, with digests
# ---------------------------------------------------------------------------
#
# The data of such a PDU is shown raw where the PDU header puts it: PDO, after
# the header, its digest and the padding (NVMe/TCP 1.3 Figures 32 and 33).  Here
# PDO is 32 with a 4-byte header digest, so 4 bytes of padding precede 64 bytes
# of data and a data digest follows it.  The capture starts mid-connection, as
# build_h2c_digest's does, so that no ICReq/ICResp negotiates the digests off.
#
#   Connection 55080
#     F1  Fabrics Connect, QID 1, CID 1
#     F2  CapsuleResp CID 1
#     F3  C2HData CID 31h, no such command: HDGST, DDGST, PDO 32, 64 bytes
#     F4  H2CData CID 32h, no such command: HDGST, DDGST, PDO 32, 64 bytes

UNKNOWN_DATA_PORT = 55080
UNKNOWN_DATA_PDO = 32
UNKNOWN_DATA_LEN = 64


def build_unknown_data():
    conn = Conn(0x8400, 1_701_430_000_000_000, UNKNOWN_DATA_PORT)
    emit = conn.emit
    payload = bytes(((i * 11 + 9) & 0xFF) for i in range(UNKNOWN_DATA_LEN))
    emit(True, capsule_cmd_pdu(connect_sqe(cid=1, qid=1)))
    emit(False, capsule_resp_pdu(cid=1))
    emit(False, c2h_data_pdu(cid=0x31, payload=payload, pdo=UNKNOWN_DATA_PDO,
                             hdgst=True, ddgst=True, last=True))
    emit(True, h2c_data_pdu(cid=0x32, payload=payload, pdo=UNKNOWN_DATA_PDO,
                            hdgst=True, ddgst=True, last=True))
    return bytes(conn.out)


def frame_count(data):
    """The number of Enhanced Packet Blocks in pcapng `data`."""
    pos = count = 0
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        count += block_type == 6
        pos += block_len
    return count


def build_io_capture():
    """nvme-tcp-io.pcapng: I/O-queue captures, each a section of its own
    (frame maps in their builders):

      F1-F7    build_ioq_cqe               host ports 55000/55001
      F8-F11   build_ioq_noconnect         host ports 55010/55011
      F12-F16  build_sgl_transport         host port 55200
      F17-F25  build_data_offset           host port 55020
      F26-F34  build_c2h_cid_zero          host ports 55030/55031
      F35-F41  build_h2c_keyed_sgl         host ports 55040/55041
      F42-F44  build_nlb_bounds            host port 55050
      F45-F84  build_ioq_guess             host ports 55060-55068
      F85-F93  build_rw_cdw13              host port 55070
      F94-F97  build_unknown_data          host port 55080
    """
    head = b''.join((
        build_ioq_cqe(),
        with_host_ports(build_ioq_noconnect(),
                        {NOCONN_IOQ_PORT: 55010, NOCONN_AQ_PORT: 55011}),
        build_sgl_transport(),
        with_host_ports(build_data_offset(), {HOST_PORT: 55020}),
    ))
    head += build_c2h_cid_zero(frame_count(head) + 1)
    head += build_h2c_keyed_sgl(frame_count(head) + 1)
    return (head + build_nlb_bounds() + build_ioq_guess() + build_rw_cdw13()
            + build_unknown_data())


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    captures = os.path.normpath(os.path.join(here, '..', 'test', 'captures'))
    for name, builder in (
            ('nvme-tcp-admin.pcapng', build_admin_capture),
            ('nvme-tcp-io.pcapng', build_io_capture),
            ('nvme-tcp-truncated.pcapng', build_truncated),
            ('nvme-tcp-h2c-digest.pcapng', build_h2c_digest),
            ('nvme-tcp-security.pcapng', build_security),
            ('nvme-tcp-plen-zero.pcapng', build_plen_zero),
            ('nvme-tcp-pdu-queue-parity.pcapng', build_pdu_queue_parity),
            ('nvme-tcp-ddgst-truncated.pcapng', build_ddgst_truncated),
            ('nvme-tcp-split-header.pcapng', build_split_header),
            ('nvme-tcp-fdp-events.pcapng', build_fdp_events)):
        path = os.path.join(captures, name)
        data = builder()
        with open(path, 'wb') as f:
            f.write(data)
        print(f'wrote {path} ({len(data)} bytes)')


if __name__ == '__main__':
    sys.exit(main())
