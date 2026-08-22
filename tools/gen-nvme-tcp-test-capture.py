#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a pcapng test capture for the core NVMe dissector (packet-nvme.c)
driven over NVMe/TCP (packet-nvme-tcp.c).

nvme-tcp-admin.pcapng  (7 frames)
  A single NVMe/TCP connection (host 10.0.0.1:55000 <-> controller
  10.0.0.2:4420) carrying Admin-queue CapsuleCommand PDUs.  Each command
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
    Frame 6  Fabrics Property Get (7Fh, FCTYPE 04h)        -> ATTRIB container
    Frame 7  H2CTermReq with PLEN=20 (< the 24-byte hdr)   -> short-PDU guard

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

import os
import struct
import sys

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

def epb(packet_bytes, ts_us, caplen=None):
    """Enhanced Packet Block.

    caplen defaults to the whole packet.  Passing a smaller value writes the
    block the way a snaplen-limited capture does: the Original Packet Length
    stays the full frame size while only Captured Packet Length bytes are
    stored, which is exactly the condition tvb_reported_length() reports and
    tvb_captured_length() does not."""
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  =  ts_us & 0xFFFFFFFF
    origlen = len(packet_bytes)
    if caplen is None:
        caplen = origlen
    data = packet_bytes[:caplen]
    padded = data + b'\x00' * (_pad4(caplen) - caplen)
    body = struct.pack('<IIIII', 0, ts_high, ts_low, caplen, origlen) + padded
    return _block(0x00000006, body)

# ---------------------------------------------------------------------------
# Ethernet / IPv4 / TCP framing
# ---------------------------------------------------------------------------

HOST_MAC = bytes.fromhex('020000000001')
CTRL_MAC = bytes.fromhex('020000000002')
HOST_IP  = bytes(map(int, ['10', '0', '0', '1']))
CTRL_IP  = bytes(map(int, ['10', '0', '0', '2']))
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
    out = bytearray()
    out += shb()
    out += idb()

    seq = 1
    ack = 1
    ident = 0x1000
    ts = 1_700_000_000_000_000   # fixed base timestamp (us)
    pdus = [capsule_cmd_pdu(s) for s in COMMANDS]
    pdus.append(h2ctermreq_pdu(SHORT_TERMREQ_PLEN))
    for i, pdu in enumerate(pdus):
        frame = eth(CTRL_MAC, HOST_MAC,
                    ipv4(HOST_IP, CTRL_IP, tcp(HOST_PORT, CTRL_PORT, seq, ack, pdu),
                         ident + i))
        out += epb(frame, ts + i * 1000)
        seq = (seq + len(pdu)) & 0xFFFFFFFF
    return bytes(out)


# ---------------------------------------------------------------------------
# NVMe/TCP C2HData PDU
# ---------------------------------------------------------------------------

NVME_TCP_C2H_DATA = 0x07
NVME_TCP_DATA_PDU_SIZE = 24

def c2h_data_pdu(cid, payload, datal=None):
    """Controller-to-host data PDU: 8-byte common header then
    cccid(2) ttag(2) datao(4) datal(4) rsvd(4), then the payload."""
    if datal is None:
        datal = len(payload)
    plen = NVME_TCP_DATA_PDU_SIZE + len(payload)
    ch = struct.pack('<BBBBI', NVME_TCP_C2H_DATA, 0x00,
                     NVME_TCP_DATA_PDU_SIZE, 0x00, plen)
    hdr = struct.pack('<HH', cid & 0xFFFF, 0)      # CCCID, TTAG
    hdr += struct.pack('<I', 0)                    # DATAO
    hdr += struct.pack('<I', datal & 0xFFFFFFFF)   # DATAL
    hdr += bytes(4)                                # reserved
    assert len(ch) + len(hdr) == NVME_TCP_DATA_PDU_SIZE
    return ch + hdr + payload


# ---------------------------------------------------------------------------
# nvme-tcp-logpage-datal.pcapng - a lying DATAL on a log page
# ---------------------------------------------------------------------------
#
# DATAL is read straight off the C2HData PDU by dissect_nvme_tcp_data_pdu() and
# handed to dissect_nvme_data_response() as the response length, while the
# payload tvb is only a tvb_new_subset_remaining().  The per-structure decoders
# in packet-nvme.c all bound their fields on that length, so a DATAL larger than
# the bytes actually sent used to walk off the end of the tvb; the exception
# then replaced the frame's COL_INFO with [Malformed Packet] and flagged it at
# severity Error, even though the fields that had already been added survived.
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
    out = bytearray()
    out += shb()
    out += idb()

    host_seq, ctrl_seq = 1, 1
    ident = 0x3000
    ts = 1_700_200_000_000_000
    sent = SMART_LOG_PAGE[:SMART_SENT_LEN]

    for i, s in enumerate((sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001),
                           sqe(AQ_GET_LOG_PAGE, cid=2,
                               cdw10=NVME_LID_SMART |
                               (((SMART_FULL_LEN // 4) - 1) << 16)))):
        pdu = capsule_cmd_pdu(s)
        frame = eth(CTRL_MAC, HOST_MAC,
                    ipv4(HOST_IP, CTRL_IP,
                         tcp(HOST_PORT, CTRL_PORT, host_seq, ctrl_seq, pdu),
                         ident + i))
        out += epb(frame, ts + i * 1000)
        host_seq = (host_seq + len(pdu)) & 0xFFFFFFFF

    for i, datal in enumerate((None, SMART_FULL_LEN)):
        pdu = c2h_data_pdu(cid=2, payload=sent, datal=datal)
        frame = eth(HOST_MAC, CTRL_MAC,
                    ipv4(CTRL_IP, HOST_IP,
                         tcp(CTRL_PORT, HOST_PORT, ctrl_seq, host_seq, pdu),
                         ident + 2 + i))
        out += epb(frame, ts + (2 + i) * 1000)
        ctrl_seq = (ctrl_seq + len(pdu)) & 0xFFFFFFFF
    return bytes(out)


# ---------------------------------------------------------------------------
# nvme-tcp-truncated.pcapng - a genuinely snaplen-sliced C2HData response
# ---------------------------------------------------------------------------
#
# The counterpart to nvme-tcp-logpage-datal.pcapng.  There the declared length
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
    out = bytearray()
    out += shb()
    out += idb()

    host_seq, ctrl_seq = 1, 1
    ident = 0x5000
    ts = 1_700_400_000_000_000
    sent = SMART_LOG_PAGE[:SMART_SENT_LEN]

    for i, s in enumerate((sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001),
                           sqe(AQ_GET_LOG_PAGE, cid=2,
                               cdw10=NVME_LID_SMART |
                               (((SMART_FULL_LEN // 4) - 1) << 16)))):
        pdu = capsule_cmd_pdu(s)
        frame = eth(CTRL_MAC, HOST_MAC,
                    ipv4(HOST_IP, CTRL_IP,
                         tcp(HOST_PORT, CTRL_PORT, host_seq, ctrl_seq, pdu),
                         ident + i))
        out += epb(frame, ts + i * 1000)
        host_seq = (host_seq + len(pdu)) & 0xFFFFFFFF

    pdu = c2h_data_pdu(cid=2, payload=sent)
    for i in range(2):
        frame = eth(HOST_MAC, CTRL_MAC,
                    ipv4(CTRL_IP, HOST_IP,
                         tcp(CTRL_PORT, HOST_PORT, ctrl_seq, host_seq, pdu),
                         ident + 2 + i))
        caplen = None
        if i == 1:
            caplen = len(frame) - (SMART_SENT_LEN - TRUNC_KEPT_PAYLOAD)
        out += epb(frame, ts + (2 + i) * 1000, caplen)
        ctrl_seq = (ctrl_seq + len(pdu)) & 0xFFFFFFFF
    return bytes(out)


# ---------------------------------------------------------------------------
# nvme-tcp-discovery.pcapng - a Discovery response longer than NUMREC claims
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
    out = bytearray()
    out += shb()
    out += idb()

    log = discovery_log_page(numrec=1, nentries=2)
    host_seq, ctrl_seq = 1, 1
    ident = 0x4000
    ts = 1_700_300_000_000_000

    for i, s in enumerate((sqe(AQ_IDENTIFY, cid=1, cdw10=0x00000001),
                           sqe(AQ_GET_LOG_PAGE, cid=2,
                               cdw10=NVME_LID_DISCOVERY |
                               (((len(log) // 4) - 1) << 16)))):
        pdu = capsule_cmd_pdu(s)
        frame = eth(CTRL_MAC, HOST_MAC,
                    ipv4(HOST_IP, CTRL_IP,
                         tcp(HOST_PORT, CTRL_PORT, host_seq, ctrl_seq, pdu),
                         ident + i))
        out += epb(frame, ts + i * 1000)
        host_seq = (host_seq + len(pdu)) & 0xFFFFFFFF

    pdu = c2h_data_pdu(cid=2, payload=log)
    frame = eth(HOST_MAC, CTRL_MAC,
                ipv4(CTRL_IP, HOST_IP,
                     tcp(CTRL_PORT, HOST_PORT, ctrl_seq, host_seq, pdu),
                     ident + 2))
    out += epb(frame, ts + 2000)
    return bytes(out)


# ---------------------------------------------------------------------------
# nvme-tcp-css.pcapng - CC.CSS decoded against the current Base 2.3 enum
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
    out = bytearray()
    out += shb()
    out += idb()

    host_seq = 1
    ident = 0x6000
    ts = 1_700_500_000_000_000
    commands = (
        sqe(FABRICS_OPC, cid=1, nsid=FCTYPE_PROP_SET, cdw10=0x00000000,
            cdw11=PROP_OFFSET_CC, cdw12=0x00000060),
        sqe(FABRICS_OPC, cid=2, nsid=FCTYPE_PROP_SET, cdw10=0x00000000,
            cdw11=PROP_OFFSET_CC, cdw12=0x00000070),
    )
    for i, s in enumerate(commands):
        pdu = capsule_cmd_pdu(s)
        frame = eth(CTRL_MAC, HOST_MAC,
                    ipv4(HOST_IP, CTRL_IP,
                         tcp(HOST_PORT, CTRL_PORT, host_seq, 1, pdu),
                         ident + i))
        out += epb(frame, ts + i * 1000)
        host_seq = (host_seq + len(pdu)) & 0xFFFFFFFF
    return bytes(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, '..', 'test', 'captures', 'nvme-tcp-admin.pcapng')
    out_path = os.path.normpath(out_path)
    data = build()
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f'wrote {out_path} ({len(COMMANDS) + 1} frames, {len(data)} bytes)')

    datal_path = os.path.join(here, '..', 'test', 'captures',
                              'nvme-tcp-logpage-datal.pcapng')
    datal_path = os.path.normpath(datal_path)
    datal_data = build_logpage_datal()
    with open(datal_path, 'wb') as f:
        f.write(datal_data)
    print(f'wrote {datal_path} (4 frames, {len(datal_data)} bytes)')

    trunc_path = os.path.join(here, '..', 'test', 'captures',
                              'nvme-tcp-truncated.pcapng')
    trunc_path = os.path.normpath(trunc_path)
    trunc_data = build_truncated()
    with open(trunc_path, 'wb') as f:
        f.write(trunc_data)
    print(f'wrote {trunc_path} (4 frames, {len(trunc_data)} bytes)')

    disc_path = os.path.join(here, '..', 'test', 'captures',
                             'nvme-tcp-discovery.pcapng')
    disc_path = os.path.normpath(disc_path)
    disc_data = build_discovery()
    with open(disc_path, 'wb') as f:
        f.write(disc_data)
    print(f'wrote {disc_path} (3 frames, {len(disc_data)} bytes)')

    css_path = os.path.join(here, '..', 'test', 'captures',
                            'nvme-tcp-css.pcapng')
    css_path = os.path.normpath(css_path)
    css_data = build_css()
    with open(css_path, 'wb') as f:
        f.write(css_data)
    print(f'wrote {css_path} (2 frames, {len(css_data)} bytes)')


if __name__ == '__main__':
    sys.exit(main())
