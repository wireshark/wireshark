#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate the MCTP transport test captures (epan/dissectors/packet-mctp.c).

Produces test/captures/mctp-transport.pcapng, eight pcapng sections whose maps
number their frames from 1:

  F1-F33    reassembly_section: message assembly against DSP0236 1.3.3
            clauses 8.6-8.9, mapped below
  F34-F81   size_rules_section: the size-rule oracles, F(33 + n)
  F82-F87   empty_final_section: header-only packets, F(81 + n)
  F88-F95   transport_limits_section, F(87 + n)
  F96-F103  header_malformed_section, F(95 + n)
  F104-F107 sll2_parity_section, F(103 + n)
  F108-F137 assembly_limit_section, F(107 + n)
  F138-F145 vdm_section: Vendor Defined messages, F(137 + n)

and, in its section near the end of this file, mctp-ingress-scope.

DSP0236 8.6 defines a message terminus as (source EID, TO, message tag), so
each scenario below uses its own source EID and/or tag and cannot interfere
with the others.

  1/2   Positive control: a well-formed two-packet message on one terminus
        (SOM/seq0 then EOM/seq1).  This must still reassemble after the
        8.7/8.9 checks are added.

  3     8.7 "unexpected end packet": SOM=0, EOM=1 with no assembly in
        progress for this terminus.  The packet is dropped, and in
        particular its first payload byte (0x04) must NOT be taken as the
        MCTP message type and handed to the NVMe-MI dissector.

  4     8.7 "unexpected middle packet": SOM=0, EOM=0 with no assembly in
        progress.  Dropped, and must not START an assembly either - 8.7 is
        explicit that dropped packets "will not cause a message assembly to
        be started or terminated".  Frame 11 is the probe for that second
        half: an EOM on frame 4's terminus, which must find nothing to
        complete and be dropped in turn.

  5/6/7 8.9 "receipt of a new start packet".  Three packets on one terminus
        (src EID 0x40, dst EID 0x20, TO=1, tag=6): SOM/seq0 carrying
        04 11 11, a SECOND SOM/seq0 carrying 04 22 22, then EOM/seq1
        carrying 33 33.  Before the fix these concatenated into one 8-byte
        message 04 11 11 04 22 22 33 33 which NVMe-MI rendered as an
        "NVMe Admin command Request (Fabric Zoning Receive)" carrying a
        spurious "Admin opcode is Prohibited over the Management Interface"
        warning - an entire command that was never on the wire.  Frame 6
        must terminate frame 5's assembly and begin its own, so frame 7
        completes 04 22 22 33 33.

  12/13 8.9 "out-of-sequence packet sequence number", in the shape the
        audit reproduced: SOM/seq0 followed by EOM/seq3, a two-packet gap.
        Before the fix these spliced into 04 11 11 22 22, which NVMe-MI
        rendered as an Admin command carrying a spurious "Admin opcode is
        Prohibited over the Management Interface" warning.

  14/15/16 The same rule on a "middle" packet, plus the other half of the
        clause: "All data for the message assembly that was in progress is
        dropped."  Frame 15 is SOM/seq0 -> seq3, so frame 16's EOM must find
        nothing left to complete and be dropped under 8.7 in turn.  Before
        the fix all three spliced into 04 44 44 55 55 66 66.

  17/18/19 The negative control, and the reason a naive "previous + 1" test
        is wrong: seq3 -> seq0 -> seq1 is a legal modulo-4 run across the
        wrap, and must reassemble with no complaint.  Message type 0x0A has
        no registered dissector, so the reassembled message is pinned by its
        bytes without an upper dissector's opinions landing on the frame.

  20/21 A repeated sequence number (seq2 -> seq2).  It is not a modulo-4
        increment either, so it is the same error condition -- and it is the
        case a "seq went backwards" test would miss.

  8/9/10 The same 8.9 rule for a start packet that is also an end packet.
        8.9's condition is "a packet with SOM = 1b", unqualified, so a
        single-packet message (SOM=1, EOM=1) arriving on a terminus with an
        assembly in progress terminates that assembly too.  Frame 8 starts
        an assembly, frame 9 is a complete single-packet MCTP Control
        message on the same terminus, and frame 10 is an EOM that must then
        find nothing to attach to (frame 8's data having been dropped) and
        be dropped itself under 8.7.  Without the 8.9 handling, frame 10
        splices onto frame 8 and fabricates 04 77 77 88 88.

  22-25 8.3 Table 2, the Null Source EID.  Two devices at SMBus slave
        addresses 0x40 and 0x41 both send with source EID 0 and destination
        EID 0 - what an endpoint does before it has been assigned an EID -
        both using TO=1 tag=5, interleaved SOM/EOM.  The message terminus of
        8.6 is not an identity here, because "a message ... coming from an
        endpoint that is using physical addressing only" is exactly what EID
        0 means, so the reassembly key has to fall back on the physical
        address the SMBus binding publishes.  Before the fix the two devices
        shared one key: frame 23 raised the 8.9 "assembly restarted" error
        against a device that had done nothing wrong, frame 24 completed
        0A BB BB A1 A1 out of device B's start and device A's end, and
        frame 25 was dropped under 8.7.

  26-29 The same rule for the Null *Destination* EID, which is the case a
        key that merely substitutes the physical address for a null EID pair
        would still get wrong.  The controller has EID 0x08 and addresses two
        devices, at slave 0x40 and 0x41, by physical address with destination
        EID 0 - Table 2's "the destination EID value is to be ignored and ...
        only physical addressing is used".  Both messages carry TO=1 tag=4,
        so the tag owner (the source) has a perfectly good EID and only the
        destination is null.  Before the fix these collided in the same way.

  30-33 The fallback, over a binding that publishes no physical address at
        all: back on Linux SLL, with two messages on one tag interleaved,
        one from an endpoint using the Null Source EID and one from EID
        0x48.  There is nothing but the EIDs to key on and the EIDs are what
        must be used; the pair must still be told apart, and neither the
        null EID nor the absent physical address may collapse them into one
        assembly or crash.  This holds both before and after the fix, which
        is its job.

Wire format layers (outer to inner), same framing as
tools/gen-mctp-control-test-capture.py:
  Linux SLL cooked capture header (16 bytes, DLT=113, proto 0x00FA MCTP)
  MCTP transport header            (4 bytes)
  MCTP message payload             (byte 0 of the SOM packet is the type)

Frames 22-29 need a transport binding that publishes physical addresses, so
they are MCTP over SMBus/I2C instead, on a second interface in the same file
(DLT_LINUX_I2C = 209, with the 5-byte Linux I2C pseudo-header).  Framing per
DSP0237 6.3, the same as tools/gen-mctp-smbus-test-capture.py:
  I2C Linux pseudo-header          (5 bytes)
  destination slave address, command code 0x0F, byte count, source slave
  MCTP transport header            (4 bytes)
  MCTP message payload
  PEC                              (SMBus CRC-8 over the whole transaction)
"""

import os
import struct
import sys

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

# ---------------------------------------------------------------------------
# MCTP transport header (DSP0236 Table 1): ver, dst EID, src EID,
# SOM(0x80) | EOM(0x40) | seq(0x30) | TO(0x08) | tag(0x07)
# ---------------------------------------------------------------------------

SOM = 0x80
EOM = 0x40

CONTROLLER_EID = 0x20

def _fst(flags, seq, tag, to):
    return flags | ((seq & 3) << 4) | (0x08 if to else 0) | (tag & 7)

# Both frame builders return (packet bytes, interface id): the capture has two
# interfaces, DLT 113 for the SLL frames and DLT 209 for the SMBus ones.
SLL_IFACE = 0
I2C_IFACE = 1

def frame(src_eid, flags, seq, tag, payload, to=True, dst_eid=CONTROLLER_EID):
    return (sll_header(src_eid)
            + bytes([0x01, dst_eid, src_eid, _fst(flags, seq, tag, to)])
            + payload, SLL_IFACE)

# ---------------------------------------------------------------------------
# MCTP over SMBus/I2C (DSP0237 6.3), for the frames that need the transport
# binding to publish a physical address.  DLT_LINUX_I2C = 209, with the
# 5-byte pcap pseudo-header wiretap/pcap-common.c expects.
# ---------------------------------------------------------------------------

def smbus_frame(dst_slave, src_slave, dst_eid, src_eid, flags, seq, tag,
                payload, to=True):
    mctp = bytes([0x01, dst_eid, src_eid, _fst(flags, seq, tag, to)]) + payload
    body = (bytes([dst_slave << 1, 0x0F, 1 + len(mctp), (src_slave << 1) | 1])
            + mctp)
    i2c_phdr = bytes([0]) + struct.pack('>I', 0)   # bus 0, no flags
    return i2c_phdr + body + bytes([smbus_pec(body)]), I2C_IFACE

def reassembly_section():
    frames = []

    # -- 1/2: positive control, a well-formed two-packet message ----------
    #    src 0x40, TO=1, tag 1.  Reassembles to 04 11 22 33 44 55 66.
    frames.append(frame(0x40, SOM, 0, 1, bytes([0x04, 0x11, 0x22, 0x33])))
    frames.append(frame(0x40, EOM, 1, 1, bytes([0x44, 0x55, 0x66])))

    # -- 3: 8.7 unexpected "end" packet, no assembly in progress ----------
    #    src 0x41, TO=1, tag 2.  First payload byte 0x04 is the bait: it is
    #    the NVMe-MI message type, and must not be read as one.
    frames.append(frame(0x41, EOM, 0, 2,
                        bytes([0x04, 0x11, 0x11, 0x04, 0x22, 0x22])))

    # -- 4: 8.7 unexpected "middle" packet, no assembly in progress -------
    #    src 0x42, TO=1, tag 3.
    frames.append(frame(0x42, 0, 0, 3, bytes([0x04, 0xAA, 0xBB])))

    # -- 5/6/7: 8.9 receipt of a new "start" packet -----------------------
    #    src 0x40, TO=1, tag 6 - the audit's probe, verbatim.
    frames.append(frame(0x40, SOM, 0, 6, bytes([0x04, 0x11, 0x11])))
    frames.append(frame(0x40, SOM, 0, 6, bytes([0x04, 0x22, 0x22])))
    frames.append(frame(0x40, EOM, 1, 6, bytes([0x33, 0x33])))

    # -- 8/9/10: 8.9 for a start packet that is also an end packet --------
    #    src 0x43, TO=1, tag 7.  Frame 9 is a complete MCTP Control
    #    Get Endpoint ID request (type 0x00, Rq, instance 2, command 0x02).
    frames.append(frame(0x43, SOM, 0, 7, bytes([0x04, 0x77, 0x77])))
    frames.append(frame(0x43, SOM | EOM, 0, 7, bytes([0x00, 0x82, 0x02])))
    frames.append(frame(0x43, EOM, 1, 7, bytes([0x88, 0x88])))

    # -- 11: the "did frame 4 start an assembly?" probe -------------------
    #    Same terminus as frame 4 (src 0x42, TO=1, tag 3), EOM/seq1.  8.7
    #    says frame 4 could not have started an assembly, so this one has
    #    nothing to complete and is dropped in turn.  Before the fix frame 4
    #    did start one, and this frame closed it into a fabricated
    #    04 AA BB CC DD NVMe-MI message.
    frames.append(frame(0x42, EOM, 1, 3, bytes([0xCC, 0xDD])))

    # -- 12/13: 8.9 out-of-sequence packet sequence number ----------------
    #    src 0x44, TO=1, tag 4.  SOM/seq0 then EOM/seq3: seq3 is not the
    #    modulo-4 increment of seq0, so two packets are missing.  Before the
    #    fix these reassembled silently into 04 11 11 22 22.
    frames.append(frame(0x44, SOM, 0, 4, bytes([0x04, 0x11, 0x11])))
    frames.append(frame(0x44, EOM, 3, 4, bytes([0x22, 0x22])))

    # -- 14/15/16: the same rule on a "middle" packet ---------------------
    #    src 0x45, TO=1, tag 4.  Frame 15 breaks the sequence, which drops
    #    "all data for the message assembly that was in progress", so frame
    #    16's EOM has nothing to complete and is dropped under 8.7.  Before
    #    the fix all three spliced into 04 44 44 55 55 66 66.
    frames.append(frame(0x45, SOM, 0, 4, bytes([0x04, 0x44, 0x44])))
    frames.append(frame(0x45, 0, 3, 4, bytes([0x55, 0x55])))
    frames.append(frame(0x45, EOM, 0, 4, bytes([0x66, 0x66])))

    # -- 17/18/19: negative control, a legal run across the modulo-4 wrap -
    #    src 0x46, TO=1, tag 4.  seq3 -> seq0 -> seq1.  Table 1 in 8.2 says
    #    the increment is modulo 4 and that a start packet's own sequence
    #    number "can be any value (0-3)", so none of these is an error and
    #    the message must still reassemble.  Message type 0x0A has no
    #    registered dissector, so nothing above MCTP comments on it.
    frames.append(frame(0x46, SOM, 3, 4, bytes([0x0A, 0x77, 0x77])))
    frames.append(frame(0x46, 0, 0, 4, bytes([0x88, 0x88])))
    frames.append(frame(0x46, EOM, 1, 4, bytes([0x99, 0x99])))

    # -- 20/21: a repeated sequence number --------------------------------
    #    src 0x47, TO=1, tag 4.  seq2 -> seq2 is not a modulo-4 increment
    #    either.  Before the fix this reassembled into 04 AA AA BB BB.
    frames.append(frame(0x47, SOM, 2, 4, bytes([0x04, 0xAA, 0xAA])))
    frames.append(frame(0x47, EOM, 2, 4, bytes([0xBB, 0xBB])))

    # -- 22/23/24/25: 8.3 Table 2, two endpoints on the Null Source EID ----
    #    Devices A (slave 0x40) and B (slave 0x41) both report to the
    #    controller (slave 0x20) before EID assignment, so both send source
    #    EID 0 and destination EID 0, both with TO=1 tag=5.  The message
    #    terminus of 8.6 is identical for the two of them; only the SMBus
    #    slave address tells them apart.  A reassembles 0A AA AA A1 A1 and B
    #    0A BB BB B1 B1; before the fix frame 24 completed 0A BB BB A1 A1
    #    out of one device's start and the other's end.
    frames.append(smbus_frame(0x20, 0x40, 0x00, 0x00, SOM, 0, 5,
                              bytes([0x0A, 0xAA, 0xAA])))
    frames.append(smbus_frame(0x20, 0x41, 0x00, 0x00, SOM, 0, 5,
                              bytes([0x0A, 0xBB, 0xBB])))
    frames.append(smbus_frame(0x20, 0x40, 0x00, 0x00, EOM, 1, 5,
                              bytes([0xA1, 0xA1])))
    frames.append(smbus_frame(0x20, 0x41, 0x00, 0x00, EOM, 1, 5,
                              bytes([0xB1, 0xB1])))

    # -- 26/27/28/29: the Null Destination EID -----------------------------
    #    The controller (EID 0x08, slave 0x20) addresses two un-enumerated
    #    devices by physical address, destination EID 0, both TO=1 tag=4.
    #    Here the tag owner - the source - has a real EID, so a key that only
    #    reaches for the physical address when the *tag owner* is null still
    #    merges these two.  A gets 0A C0 C0 C1 C1 and B 0A D0 D0 D1 D1.
    frames.append(smbus_frame(0x40, 0x20, 0x00, 0x08, SOM, 0, 4,
                              bytes([0x0A, 0xC0, 0xC0])))
    frames.append(smbus_frame(0x41, 0x20, 0x00, 0x08, SOM, 0, 4,
                              bytes([0x0A, 0xD0, 0xD0])))
    frames.append(smbus_frame(0x40, 0x20, 0x00, 0x08, EOM, 1, 4,
                              bytes([0xC1, 0xC1])))
    frames.append(smbus_frame(0x41, 0x20, 0x00, 0x08, EOM, 1, 4,
                              bytes([0xD1, 0xD1])))

    # -- 30/31/32/33: no physical address at all ---------------------------
    #    Back on Linux SLL, which publishes none.  Two interleaved messages
    #    on tag 2, one from the Null Source EID and one from EID 0x48, both
    #    to the controller.  The EIDs are the whole key here and must still
    #    separate them: 0A E0 E0 E1 E1 and 0A F0 F0 F1 F1.
    frames.append(frame(0x00, SOM, 0, 2, bytes([0x0A, 0xE0, 0xE0])))
    frames.append(frame(0x48, SOM, 0, 2, bytes([0x0A, 0xF0, 0xF0])))
    frames.append(frame(0x00, EOM, 1, 2, bytes([0xE1, 0xE1])))
    frames.append(frame(0x48, EOM, 1, 2, bytes([0xF1, 0xF1])))

    return shb() + idb(113) + idb(DLT_LINUX_I2C) + b''.join(
        epb(pkt, 1000000 + i * 1000, iface) for i, (pkt, iface) in enumerate(frames))

def size_rules_section():
    """DSP0236 8.4.2 / 11.6, measured after the four-byte transport header.

    Type/IC remains part of the SOM payload (Figure 4 / Table 1). Control
    command FFh is transport-specific (Table 12); its opaque body avoids
    unrelated fixed-command length checks. Type 0Ah exercises raw fallback.

     1       Control 64 bytes: exact boundary
     2       Control 70 bytes: sentence 1 only
     3-4     Control 64/6: sentence 2 only
     5-6     Control IC=1, 64/6: IC and fragmentation once, on SOM
     7-9     Non-Control 4/4/2: one sub-baseline expert per non-final unit
    10-12    Non-Control 64/80/4: middle-size mismatch only
    13-15    Non-Control 64/64/4: valid smaller final unit
    16-18    Non-Control 80/80/4: larger TUs are not unconditionally invalid
    19       Non-Control 70 bytes: no Control-size rule
    20       Control Get Endpoint ID, 3 bytes: valid small single packet
    21-22    Control 80/4: fragmented at SOM; oversized at the reassembled EOM
    23-25    Control 64/70/4: oversized middle packet, start metadata needed
    26-28    Non-Control 64/4/4: both distinct 8.4.2 violations at the middle
    29-31    Non-Control 64/64/4, middle captured at 4: poison, not TU error
    32-33    SOM type not captured; final starts with 00h: never guess Control.
             The final's 70 bytes exceed the reported 64 (8.4.2), poison or not
    34-35    Control 64/70: oversized final uses retained type (11.6) and
             exceeds the start packet's transmission unit (8.4.2)
    36-37    Non-Control 80/70, final starts with 80h: not an IC/type byte
    38-41    Interleaved Control 64/6 and non-Control 80/70, identical
             termini on separate SLL interfaces: no metadata cross-talk
    42-45    Control SOM64 restarted by non-Control 80/80/4 on the same key
    46       Single Control reports 70, captures 64: still oversized
    47-48    Control SOM64 captured at 4, EOM70: poison, retained type, and
             the same 8.4.2 final-packet excess
    """
    frames = []

    def control(size, ic=False):
        return bytes([0x80 if ic else 0, 0x80, 0xff]) + bytes(size - 3)

    def opaque(size):
        return bytes([0x0a]) + bytes(n % 256 for n in range(1, size))

    def add(src, flags, seq, payload, iface=0, captured_payload=None):
        packet, _ = frame(src, flags, seq, 1, payload)
        caplen = None if captured_payload is None else 20 + captured_payload
        frames.append((packet, iface, caplen))

    def message(src, payload, sizes):
        assert sum(sizes) == len(payload)
        offset = 0
        for n, size in enumerate(sizes):
            flags = (SOM if n == 0 else 0) | (EOM if n == len(sizes) - 1 else 0)
            add(src, flags, n & 3, payload[offset:offset + size])
            offset += size

    message(0x40, control(64), [64])
    message(0x41, control(70), [70])
    message(0x42, control(70), [64, 6])
    message(0x43, control(70, ic=True), [64, 6])
    message(0x44, opaque(10), [4, 4, 2])
    message(0x45, opaque(148), [64, 80, 4])
    message(0x46, opaque(132), [64, 64, 4])
    message(0x47, opaque(164), [80, 80, 4])
    message(0x48, opaque(70), [70])
    message(0x49, bytes([0, 0x80, 0x02]), [3])
    message(0x4a, control(84), [80, 4])
    message(0x4b, control(138), [64, 70, 4])
    message(0x4c, opaque(72), [64, 4, 4])
    data = opaque(132)
    add(0x4d, SOM, 0, data[:64])
    add(0x4d, 0, 1, data[64:128], captured_payload=4)
    add(0x4d, EOM, 2, data[128:])
    add(0x4e, SOM, 0, control(64), captured_payload=0)
    add(0x4e, EOM, 1, bytes(70))
    message(0x4f, control(134), [64, 70])
    message(0x50, bytes([0x0a]) + bytes(79) + b'\x80' + bytes(69), [80, 70])

    add(0x60, SOM, 0, control(64), iface=0)
    add(0x60, SOM, 0, opaque(80), iface=1)
    add(0x60, EOM, 1, bytes(6), iface=0)
    add(0x60, EOM, 1, bytes(70), iface=1)

    add(0x61, SOM, 0, control(64))
    message(0x61, opaque(164), [80, 80, 4])
    add(0x62, SOM | EOM, 0, control(70), captured_payload=64)
    add(0x63, SOM, 0, control(64), captured_payload=4)
    add(0x63, EOM, 1, bytes(70))
    assert len(frames) == 48

    return shb() + idb(113) + idb(113) + b''.join(
        epb(pkt, 2000000 + i * 1000, iface, caplen=caplen)
        for i, (pkt, iface, caplen) in enumerate(frames))


# ---------------------------------------------------------------------------
# Helpers shared with gen-nvme-mi-test-capture.py, for the captures below
# ---------------------------------------------------------------------------

HOST_EID  = 0x0A
BMC_EID   = 0x08


def mctp_header(is_request, host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0,
                som=True, eom=True, seq=0):
    src = host_eid if is_request else bmc_eid
    dst = bmc_eid  if is_request else host_eid
    to  = 0x08 if is_request else 0x00
    fst = ((0x80 if som else 0x00) | (0x40 if eom else 0x00)
           | ((seq & 0x03) << 4) | to | (tag & 0x07))
    return bytes([0x01, dst, src, fst])


NVME_MI_TYPE_MI      = 0x1
NVME_MI_TYPE_ADMIN   = 0x2


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


def mi_response_payload_with_data(status, data, nmresp=0):
    """MI command response with trailing data bytes (exercises nvme-mi.mi.data)."""
    return bytes([status]) + struct.pack('<I', nmresp)[:3] + data


AEO_LIST_HDR_LEN  = 7      # AEOLHL "shall be set to 7h" (Figure 61)
AEO_ENTRY_HDR_LEN = 9      # AELHLEN "shall be set to 9h" (Figure 62)


AEO_SCOPE_SUBSYSTEM  = 0x2


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


def subsys_info(mjr=0x02, mnr=0x01, nnsc=0x01, nump=0x01):
    """NVM Subsystem Information data structure (Figure 112), 32 bytes.

    Bytes 01 and 02 are the only place an NVM Subsystem advertises which
    revision of NVMe-MI it implements (Figure 112 in NVMe-MI 2.1, Figure 115
    in 2.2 -- the offsets did not move), and Figure 113 / Figure 116 map them
    onto published versions: 2h/1h is 2.1 and 2h/2h is 2.2, the row 2.2 added.
    Neither table has a catch-all Reserved row, so a pair that appears in
    neither must not be diagnosed as reserved or invalid -- but neither is it
    proof of a later publication.  Such a tuple has uncertain provenance and
    is carried as the bytes it is.

    The defaults are exactly what this function emitted before it took
    arguments (MJR 2 / MNR 1 / NNSC bit 0 set), so every capture built before
    the parameters existed is byte-for-byte unchanged.
    """
    return bytes([
        nump,                       # NUMP (0's based -> nump + 1 ports)
        mjr,                        # MJR
        mnr,                        # MNR
        nnsc,                       # NNSC (bit 0: SRE in 2.1, obsolete in 2.2)
    ]) + b'\x00' * 28               # reserved to 32 bytes


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


def _sliced(pkt, caplen):
    """(bytes, reported length) for a frame the capture cut at `caplen`."""
    return (pkt[:caplen], len(pkt))


def _sliced_section(packets, base_ts):
    data = shb() + idb()
    for i, pkt in enumerate(packets):
        ts = base_ts + i * 1_000_000
        if isinstance(pkt, tuple):
            data += epb(pkt[0], ts, origlen=pkt[1])
        else:
            data += epb(pkt, ts)
    return data


# ---------------------------------------------------------------------------
# mctp-transport.pcapng F88-F95 (transport_limits_section) - reassembly at the
# captured length, and the 4,224-byte out-of-band message bound
# ---------------------------------------------------------------------------
#
# Two transport-level bounds, both unenforced today:
#
#   A snaplen-sliced fragment is appended to the assembly at its *captured*
#   length; a later EOM closes the shortened sequence and the result is
#   presented as a complete message with no truncation marker, then dispatched.
#   Bytes never adjacent on the wire become adjacent in mctp.reassembled.data.
#   (There is no normative basis for this one -- it rests on Wireshark's own
#   reported-versus-captured contract.)
#
#   DSP0235 7.6 and NVMe-MI 2.1 3.1 L122 cap an out-of-band NVMe-MI Message at
#   4,224 bytes measured from the IC/type byte inclusive; neither the bound nor
#   its 66-packet corollary is tested.  F5 is the boundary that must stay
#   silent and F6 the first invalid length -- the corpus had neither.
#
#   F1/F2 two-packet MI request, both packets intact         positive twin
#   F3/F4 the same, first packet reports 14 and captures 9
#   F5    single-packet message of exactly 4,224 bytes       positive control
#   F6    single-packet message of 4,225 bytes
#
# Every experiment here is on its own MCTP tag -- 1, 2, 5 and 6 -- so nothing
# in the file shares a Command Slot with anything else.  That matters most for
# F5/F6: they are two unanswered Command Messages, and on one tag the second
# would displace the first and collect a superseded-request note, which would
# make "both boundary frames are silent today" false for a reason that has
# nothing to do with the message-size bound under test.

_LIMITS_MSG = nvme_mi_message(NVME_MI_TYPE_MI, 0, False, mi_request_payload(0x01))
assert len(_LIMITS_MSG) == 20

def _sll_mctp_fragment(payload, tag, seq, som, eom, is_request=True):
    src = HOST_EID if is_request else BMC_EID
    return (sll_header(src, outgoing=is_request)
            + mctp_header(is_request, tag=tag, som=som, eom=eom, seq=seq)
            + payload)

def _oversize_message(total, tag):
    """One NVMe-MI Message of exactly `total` bytes, IC/type byte included."""
    payload = mi_request_payload(0x01) + bytes(total - 4 - 12 - 4)
    return (sll_header(HOST_EID, outgoing=True)
            + mctp_header(True, tag=tag)
            + nvme_mi_message(NVME_MI_TYPE_MI, 0, False, payload))

packets_transport_limits = [
    _sll_mctp_fragment(_LIMITS_MSG[:10],  tag=1, seq=0, som=True,  eom=False),
    _sll_mctp_fragment(_LIMITS_MSG[10:],  tag=1, seq=1, som=False, eom=True),

    _sliced(_sll_mctp_fragment(_LIMITS_MSG[:10], tag=2, seq=0, som=True,
                               eom=False), 25),
    _sll_mctp_fragment(_LIMITS_MSG[10:],  tag=2, seq=1, som=False, eom=True),

    _oversize_message(4224, tag=5),
    _oversize_message(4225, tag=6),

    # F7/F8  The cut lands on the *final* fragment instead of the
    # first.  The assembly is poisoned by the same packet that completes it,
    # which is the other side of the bookkeeping -- F3/F4 mark an assembly
    # that completes a frame later, this one marks and completes at once.
    # Tag 3, so neither the intact twin on tag 1 nor the F3/F4 experiment can
    # be affected by it.
    _sll_mctp_fragment(_LIMITS_MSG[:10],  tag=3, seq=0, som=True,  eom=False),
    _sliced(_sll_mctp_fragment(_LIMITS_MSG[10:], tag=3, seq=1, som=False,
                               eom=True), 26),
]

BASE_TS_TRANSPORT_LIMITS_US = 1712275200 * 1_000_000

def transport_limits_section():
    return _sliced_section(packets_transport_limits, BASE_TS_TRANSPORT_LIMITS_US)


# ---------------------------------------------------------------------------
# mctp-transport.pcapng F96-F103 (header_malformed_section) - the packets
# the MCTP dissector rejects
# ---------------------------------------------------------------------------
#
# packet-mctp.c screens every packet on two conditions before it adds anything
# to the tree: the packet must be at least five octets (the four-byte
# transport header plus the message type byte), and DSP0236 Table 1's header
# version nibble must be 1 ("shall be set to 0001b").  Both rejections used to
# return having claimed the whole packet and added no item at all, which
# produced a filterability inversion: the protocol column said "MCTP" while
# the display filter `mctp` did not match the frame, `mctp.version != 1` --
# the one filter a conformance engineer reaches for -- could never find a
# bad-version packet, and, full consumption having been claimed, the caller
# added no data item either, so the octets appeared nowhere.
#
# No committed capture contained either shape: packet-mctp-smbus.c rejects a
# bad-version frame before the MCTP dissector is reached, and no SLL frame
# was short or mis-versioned.  This file supplies both, each with a positive
# twin that differs in exactly the byte under test.
#
#   F1  header version 2 (byte 0 = 0x02), message type 0Ah, 3-byte payload
#   F2  the four-byte header and nothing after it: reported length 4
#   F3  header version 1, length exactly 5: header + type byte, no payload
#   F4  byte 0 = 0xF1 -- version 1 with Table 1's RSVD nibble set to Fh, which
#       neither DSP0236 Table 1 nor DSP0237 Table 1 gives a required value, so
#       it must render and raise nothing here
#   F5  message type 8Ah: type 0Ah with the IC bit set.  An encapsulated-type
#       decoder does not read the type byte and so cannot know where a
#       type-specific integrity check would be, which is why IC = 1 excludes
#       the mctp.encap-type table; the payload must still be placed
#   F6  F1's twin with version 1: same destination, source, tag, type and
#       payload, so the version byte is the only difference between them
#   F7  no MCTP octets at all -- the SLL header and nothing else.  The header
#       fields cannot be read because they are not there, and none may be
#       invented; the protocol item and the diagnostic are what is left
#   F8  F7's octets with F6's *reported* length: the record was cut by the
#       snaplen exactly at the end of the SLL header, so the MCTP packet
#       reports eight octets and none of them were kept
#
# F7 and F8 are the two ways a dissector can find no header bytes, and they
# are not the same finding.  F7's packet really is shorter than the MCTP
# minimum -- a statement about the wire, and a malformed one.  F8's packet is
# a perfectly ordinary eight-octet MCTP packet that this capture did not keep
# -- a statement about the capture, and not a defect in the traffic at all.
# Reporting the second as malformed, or reading a version out of octets that
# were never stored, would blame the sender for the analyst's snaplen; the
# reported length is what separates them.
#
# Message type 0Ah is used throughout because DSP0239 Table 1 leaves it
# unassigned, so no dissector claims it and the payload's fate is decided by
# packet-mctp.c alone.

FXF_HOST_EID = 0x0A
FXF_DEV_EID  = 0x30


def _mctp_hdr(hdr_byte, dst, src, fst):
    return bytes([hdr_byte, dst, src, fst])


def _fxf_frame(mctp_bytes, src_eid=FXF_HOST_EID):
    return sll_header(src_eid) + mctp_bytes


# The SLL v1 cooked header sll_header() emits: packet type, ARPHRD type,
# link-layer address length, the eight-octet address, and the protocol type.
SLL_HEADER_LEN = 16

# SOM|EOM, sequence 0, TO set, tag 0.
_FXF_FST = 0xC8
_FXF_PAYLOAD = bytes([0xB1, 0xB2, 0xB3])

packets_header_malformed = [
    # F1: version 2
    _fxf_frame(_mctp_hdr(0x02, FXF_DEV_EID, FXF_HOST_EID, _FXF_FST)
               + bytes([0x0A]) + _FXF_PAYLOAD),
    # F2: reported length 4 - the header alone, one octet short of the
    #     minimum, with a valid version so that only the length is wrong
    _fxf_frame(_mctp_hdr(0x01, FXF_DEV_EID, FXF_HOST_EID, _FXF_FST)),
    # F3: exactly the minimum - header plus the message type byte
    _fxf_frame(_mctp_hdr(0x01, FXF_DEV_EID, FXF_HOST_EID, _FXF_FST)
               + bytes([0x0A])),
    # F4: reserved nibble Fh alongside version 1
    _fxf_frame(_mctp_hdr(0xF1, FXF_DEV_EID, FXF_HOST_EID, _FXF_FST)
               + bytes([0x0A, 0xC1, 0xC2])),
    # F5: the same unclaimed type with the IC bit set
    _fxf_frame(_mctp_hdr(0x01, FXF_DEV_EID, FXF_HOST_EID, _FXF_FST)
               + bytes([0x8A]) + _FXF_PAYLOAD),
    # F6: F1's twin, version 1
    _fxf_frame(_mctp_hdr(0x01, FXF_DEV_EID, FXF_HOST_EID, _FXF_FST)
               + bytes([0x0A]) + _FXF_PAYLOAD),
    # F7: the SLL header and nothing else
    _fxf_frame(b''),
    # F8: the same captured octets, but reporting F6's eight-octet MCTP
    #     packet behind them.  SLL_HEADER_LEN + 8 is the origlen; the caplen
    #     stops at the SLL header, so the MCTP tvb reports 8 and captures 0.
    (_fxf_frame(b''), SLL_HEADER_LEN + 8),
]

BASE_TS_HEADER_MALFORMED_US = 1713139200 * 1_000_000


def header_malformed_section():
    data = shb() + idb()
    for i, pkt in enumerate(packets_header_malformed):
        ts = BASE_TS_HEADER_MALFORMED_US + i * 1_000_000
        # A (bytes, origlen) pair is a snaplen-cut record; a bare bytes
        # object is a whole one, and emits exactly what it always did.
        if isinstance(pkt, tuple):
            data += epb(pkt[0], ts, origlen=pkt[1])
        else:
            data += epb(pkt, ts)
    return data


# ---------------------------------------------------------------------------
# mctp-ingress-scope.pcapng - one capture, four ingress domains
# ---------------------------------------------------------------------------
#
# DSP0236 3 makes an EID unique only within one MCTP network, and DSP0233 5.1.3
# lets one controller drive several logical buses, so the same
# (physical pair, EID pair, tag) triple can legitimately name two *different*
# transactions when the two frames arrived on different interfaces.  The
# NVMe-MI conversation key carries no ingress dimension at all, so the two
# collide.  Expressing that needs several IDBs in one file, which is what the
# interface_id parameter on epb() is for.
#
#   IDB 0  WTAP_ENCAP_I2C_LINUX, frames tagged I2C bus 0
#   IDB 1  WTAP_ENCAP_I2C_LINUX, frames tagged I2C bus 4
#   IDB 2  WTAP_ENCAP_SLL
#   IDB 3  WTAP_ENCAP_SLL
#
#   F1 bus 0  Identify request      0x10 -> 0x3A, EID 08h -> 1Eh, tag 0, CSI 0
#   F2 bus 4  Get Log Page request  the identical addressing, a different opcode
#   F3 bus 4  response to F2                            crossed order
#   F4 bus 0  response to F1
#   F5 SLL #0 first packet of a two-packet message, EID 0Ah -> 08h, tag 0
#   F6 SLL #1 first packet of another, the identical EID pair, TO and tag
#   F7 SLL #0 its EOM
#   F8 SLL #1 its EOM
#
# The two SLL interfaces supply no physical addresses at all, so their two
# AT_NONE addresses compare equal and the key collapses to the EID pair plus
# the tag -- the reassembly half of the same defect.

packets_ingress_scope = [
    (0, bridge_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                      admin_request_payload(0x06, ctrl_id=0x0001, cns=0x01,
                                            flags=0x00, doff=0, dlen=0),
                      BRIDGE_ME_A_EID, tag=0, bus=0)),
    (1, bridge_packet(True,  NVME_MI_TYPE_ADMIN, 0,
                      admin_request_payload(0x02, ctrl_id=0x0001, cns=0x02,
                                            flags=0x00, doff=0, dlen=0),
                      BRIDGE_ME_A_EID, tag=0, bus=4)),
    (1, bridge_packet(False, NVME_MI_TYPE_ADMIN, 0,
                      admin_response_payload(STATUS_SUCCESS, cqe1=0xBBBB0004),
                      BRIDGE_ME_A_EID, tag=0, bus=4)),
    (0, bridge_packet(False, NVME_MI_TYPE_ADMIN, 0,
                      admin_response_payload(STATUS_SUCCESS, cqe1=0xAAAA0000),
                      BRIDGE_ME_A_EID, tag=0, bus=0)),

    (2, _sll_mctp_fragment(_LIMITS_MSG[:10], tag=0, seq=0, som=True,
                           eom=False)),
    (3, _sll_mctp_fragment(_LIMITS_MSG[:10], tag=0, seq=0, som=True,
                           eom=False)),
    (2, _sll_mctp_fragment(_LIMITS_MSG[10:], tag=0, seq=1, som=False,
                           eom=True)),
    (3, _sll_mctp_fragment(_LIMITS_MSG[10:], tag=0, seq=1, som=False,
                           eom=True)),

    # F9-F12  the endpoint conversation is scoped too.
    #
    # Retained NVMe-MI version context hangs off an *endpoint* conversation,
    # which is keyed on the physical and EID pairs and no tag.  Those pairs are
    # identical on bus 0 and bus 4 in this file, so without a scope the two
    # endpoints were one and an advertisement on either spoke for both.
    #
    #   F9/F10  bus 0: Read NVMe-MI Data Structure, DTYP 00h, answered with a
    #           32-byte NVM Subsystem Information structure advertising 2.1
    #   F11     bus 4: the same physical and EID identity, no advertisement of
    #           its own, so it must show no retained version
    #   F12     bus 0 again: the positive control, which must still see 2.1
    (0, bridge_packet(True,  NVME_MI_TYPE_MI, 0,
                      mi_request_payload(0x00, cdw0=0x00000000),
                      BRIDGE_ME_A_EID, tag=1, bus=0)),
    (0, bridge_packet(False, NVME_MI_TYPE_MI, 0,
                      mi_response_payload_with_data(STATUS_SUCCESS,
                                                    subsys_info(),
                                                    nmresp=32),
                      BRIDGE_ME_A_EID, tag=1, bus=0)),
    (1, bridge_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01),
                      BRIDGE_ME_A_EID, tag=1, bus=4)),
    (0, bridge_packet(True,  NVME_MI_TYPE_MI, 0, mi_request_payload(0x01),
                      BRIDGE_ME_A_EID, tag=2, bus=0)),
]

BASE_TS_INGRESS_SCOPE_US = 1712534400 * 1_000_000

def build_ingress_scope_pcapng(output_path):
    data = (shb()
            + idb(link_type=DLT_LINUX_I2C, name='i2c-0')
            + idb(link_type=DLT_LINUX_I2C, name='i2c-4')
            + idb(name='mctp-sll-0')
            + idb(name='mctp-sll-1'))
    for i, (iface, pkt) in enumerate(packets_ingress_scope):
        data += epb(pkt, BASE_TS_INGRESS_SCOPE_US + i * 1_000_000,
                    interface_id=iface)
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(packets_ingress_scope)} packets to {output_path}")


# ---------------------------------------------------------------------------
# mctp-transport.pcapng F104-F107 (sll2_parity_section) - the SLL v2 emitter,
# and its SLL v1 twins
# ---------------------------------------------------------------------------
#
# LINKTYPE_LINUX_SLL2 (276 / WTAP_ENCAP_SLL2) has zero coverage in the corpus,
# and the generator could not emit it: idb() wrote DLT 113 unconditionally.
# Each pair below carries byte-identical MCTP and NVMe-MI bytes behind the two
# cooked-capture header versions, so every field above the link layer must come
# out the same on both.
#
# Both message types are chosen so that the twins are *state-neutral*: a twin
# pair is by construction the same message on the same EID pair, Tag Owner bit
# and tag, so anything that consumed per-conversation state would have the
# second frame of the pair disturb the first and the comparison would be
# measuring the state machine rather than the link layer.
# nvme_mi_type_tracks_slot() excludes exactly two NMIMTs from the Command Slot
# lifecycle -- an Asynchronous Event Message and a Reserved type -- and a
# single-packet MCTP message (SOM and EOM together) starts no assembly, so
# neither pair leaves anything behind.
#
#   IDB 0  WTAP_ENCAP_SLL   (113)
#   IDB 1  WTAP_ENCAP_SLL2  (276)
#
#   F1 SLL1  Asynchronous Event Message, tag 0   device -> host, pkttype 0
#   F2 SLL2  the same message
#   F3 SLL1  Reserved NMIMT 3h message, tag 1    host -> device, pkttype 4
#   F4 SLL2  the same message
#
# The two directions are deliberate.
# packet-sll.c once read the SLL2 packet type with a 16-bit fetch at offset 10,
# which spans the one-byte packet type and the one-byte address length: with
# the one-byte MCTP addresses here an incoming frame read as 00 01 -- the
# LINUX_SLL_BROADCAST value, so the right direction for the wrong reason and
# the wrong summary text -- and an outgoing one read as 04 01, matching no
# packet type at all, so its direction was never set.  The tree item was
# always a correct one-byte read, which is why nothing in any field showed it
# and why both an incoming and an outgoing twin are needed.

_SLL2_AEM_MCTP = bytes([0x01, HOST_EID, BMC_EID, 0xC8])
_SLL2_AEM_MSG  = nvme_mi_message(
    NVME_MI_TYPE_AEM, 0, False,
    aeo_list([aeo_entry(0x06, AEO_SCOPE_SUBSYSTEM, specific=bytes([0x4B]))]))

_SLL2_RSVD_MCTP = mctp_header(True, tag=1)
_SLL2_RSVD_MSG  = nvme_mi_message(NVME_MI_TYPE_RESERVED, 0, False,
                                  b'\xAA' * 4)

packets_sll2_parity = [
    (0, sll_header(BMC_EID, outgoing=False) + _SLL2_AEM_MCTP + _SLL2_AEM_MSG),
    (1, sll2_header(BMC_EID, outgoing=False, ifindex=2) + _SLL2_AEM_MCTP
        + _SLL2_AEM_MSG),
    (0, sll_header(HOST_EID, outgoing=True) + _SLL2_RSVD_MCTP
        + _SLL2_RSVD_MSG),
    (1, sll2_header(HOST_EID, outgoing=True, ifindex=2) + _SLL2_RSVD_MCTP
        + _SLL2_RSVD_MSG),
]

BASE_TS_SLL2_PARITY_US = 1712620800 * 1_000_000

def sll2_parity_section():
    data = shb() + idb() + idb(link_type=DLT_LINUX_SLL2)
    for i, (iface, pkt) in enumerate(packets_sll2_parity):
        data += epb(pkt, BASE_TS_SLL2_PARITY_US + i * 1_000_000,
                    interface_id=iface)
    return data


# ---------------------------------------------------------------------------
# mctp-transport.pcapng F82-F87 (empty_final_section) - header-only packets
# over Linux SLL
# ---------------------------------------------------------------------------
#
# DSP0236 Table 1 carries the message type byte in a message's first packet
# only, so a continuation packet may be the four-byte transport header alone.
#   F1  start packet, 64-byte payload, type 0Ah (unclaimed), tag 1
#   F2  end packet, header only: completes F1's message at 64 bytes
#   F3  start+end packet, header only: still short (needs a type byte)
#   F4  end packet, header only, tag 2, no assembly in progress: orphan
#   F5  start packet, tag 3: a whole 64-byte NVMe-MI VPD Write request
#   F6  end packet, header only: completes F5, and NVMe-MI 2.1 section 3.2.1
#       says an MCTP packet payload contains at least one byte

EMPTY_FINAL_HOST_EID = 0x0A
EMPTY_FINAL_DEV_EID = 0x30
EMPTY_FINAL_TYPE = 0x0A          # Reserved in DSP0239: no dissector claims it


def _empty_final_header(som, eom, seq, tag):
    fst = (0x80 if som else 0) | (0x40 if eom else 0) | (seq << 4) | 0x08 | tag
    return bytes([1, EMPTY_FINAL_DEV_EID, EMPTY_FINAL_HOST_EID, fst])


def _empty_final_vpd_write():
    """An NVMe-MI VPD Write request (MI 2.1 Figure 124) sized to exactly 64
    bytes with its header and MIC, so the start packet carries all of it."""
    data = bytes(range(44))
    message = nvme_mi_message(1, 0, False, mi_request_payload(6, 0, len(data)) + data)
    assert len(message) == 64
    return message


def empty_final_section():
    payload = bytes([EMPTY_FINAL_TYPE]) + bytes(range(1, 64))
    sll = sll_header(EMPTY_FINAL_HOST_EID, outgoing=True)
    frames = [
        sll + _empty_final_header(True, False, 0, 1) + payload,
        sll + _empty_final_header(False, True, 1, 1),
        sll + _empty_final_header(True, True, 0, 1),
        sll + _empty_final_header(False, True, 1, 2),
        sll + _empty_final_header(True, False, 0, 3) + _empty_final_vpd_write(),
        sll + _empty_final_header(False, True, 1, 3),
    ]
    data = shb() + idb(113, name='mctp-empty-final.pcapng')
    for n, frame in enumerate(frames, 1):
        data += epb(frame, 1750000000000000 + n * 1000)
    return data


# ---------------------------------------------------------------------------
# mctp-transport.pcapng F108-F137 (assembly_limit_section) - the packets per
# message assembly preference (mctp.max_assembly_packets)
# ---------------------------------------------------------------------------
#
# DSP0236 8.5 leaves message size to each message type, so the base protocol
# does not bound how many packets one assembly takes; the dissector caps it
# with a preference.  The suite runs this section with the cap at 8.  Every
# payload is the 64-byte baseline transmission unit, so no 8.4.2 rule fires,
# and type 0Ah (Reserved) keeps upper dissectors out.
#
#   F1-F8    tag 1: start, six middles, end: 8 packets, exactly the cap
#   F9-F16   tag 2: start and seven middles, 8 packets
#   F17      tag 2: a ninth packet, in sequence: the assembly is terminated
#   F18/F19  tag 2: a middle and an end with nothing in progress: orphans
#   F20/F21  tag 2: a new two-packet message on the same terminus
#   F22-F30  tag 3: start, seven middles, end: the ninth packet is the end
#
# At the default cap every message reassembles: F8 (512 bytes), F19 (704),
# F21 (128) and F30 (576).

ASSEMBLY_LIMIT_HOST_EID = 0x0B
ASSEMBLY_LIMIT_DEV_EID = 0x30
ASSEMBLY_LIMIT_TYPE = 0x0A       # Reserved in DSP0239: no dissector claims it


def _assembly_limit_packets(tag, count):
    """A `count`-packet message on `tag`: a start, middles and an end."""
    sll = sll_header(ASSEMBLY_LIMIT_HOST_EID, outgoing=True)
    frames = []
    for i in range(count):
        flags = (SOM if i == 0 else 0) | (EOM if i == count - 1 else 0)
        payload = bytes([ASSEMBLY_LIMIT_TYPE]) + bytes(63) if i == 0 else bytes([tag]) * 64
        frames.append(sll + bytes([0x01, ASSEMBLY_LIMIT_DEV_EID, ASSEMBLY_LIMIT_HOST_EID,
                                   _fst(flags, i, tag, True)]) + payload)
    return frames


def assembly_limit_section():
    frames = (_assembly_limit_packets(1, 8) + _assembly_limit_packets(2, 11)
              + _assembly_limit_packets(2, 2) + _assembly_limit_packets(3, 9))
    assert len(frames) == 30
    data = shb() + idb(113, name='mctp-assembly-limit')
    for n, frame in enumerate(frames, 1):
        data += epb(frame, 1760000000000000 + n * 1000)
    return data


def vdm_section():
    """DSP0236 13.1 Table 40 / 13.2 Table 41: the vendor ID, MSB first,
    then a vendor-defined body.

      1  PCI (7Eh), vendor 8086h, 3-byte body
      2  IANA (7Fh), enterprise 343, 2-byte body
      3  PCI, vendor 1AB4h, no body
      4  PCI with 1 of its 2 vendor ID bytes: too short
      5  IANA with 3 of its 4 enterprise ID bytes: too short
      6  PCI message type byte alone: too short
      7  PCI with IC set: the 4 trailing bytes stay in the vendor body
      8  IANA, enterprise 0, no body
    """
    payloads = (
        bytes.fromhex('7e8086010203'),
        bytes.fromhex('7f00000157aabb'),
        bytes.fromhex('7e1ab4'),
        bytes.fromhex('7e80'),
        bytes.fromhex('7f000001'),
        bytes.fromhex('7e'),
        bytes.fromhex('fe808601deadbeef'),
        bytes.fromhex('7f00000000'),
    )
    data = shb() + idb(113, name='mctp-vdm')
    for n, payload in enumerate(payloads, 1):
        packet, _ = frame(0x50 + n, SOM | EOM, 0, 0, payload)
        data += epb(packet, 1760100000000000 + n * 1000)
    return data


def build_transport_capture(path):
    # One pcapng section each, so no assembly crosses from one map to the next.
    data = b''.join(section() for section in (
        reassembly_section, size_rules_section, empty_final_section,
        transport_limits_section, header_malformed_section, sll2_parity_section,
        assembly_limit_section, vdm_section))
    with open(path, 'wb') as f:
        f.write(data)
    print(f'wrote {path} (145 frames)')




# ---------------------------------------------------------------------------
# Cross-layer capture: mctp-version-state.pcapng
# ---------------------------------------------------------------------------

# DSP0236 1.3.3 3.2/8.2/8.6/8.7.  The frames carry NVMe-MI messages, so the
# NVMe-MI suite reads it too, but what it establishes is MCTP's: a packet with
# an unsupported version neither ends an assembly nor starts one.

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
                host_eid=HOST_EID, bmc_eid=BMC_EID, tag=0, ic=True, meb=False,
                ciap=False, mic=None):
    src_eid  = host_eid if is_request else bmc_eid
    sll      = sll_header(src_eid, outgoing=is_request)
    mctp     = mctp_header(is_request, host_eid=host_eid, bmc_eid=bmc_eid, tag=tag)
    return sll + mctp + nvme_mi_message(msg_type, csi,
                                        is_response=not is_request,
                                        payload=payload, ic=ic, meb=meb,
                                        ciap=ciap, mic=mic)


def nshds():
    """NVM Subsystem Health Data Structure (Figure 108), 8 bytes."""
    return (bytes([
        0x38,                       # NSS = DF | RNR | P0LA
        0xFF,                       # SW (all-healthy: inverted CW field)
        0x2D,                       # CTEMP = 45 C
        0x05,                       # PDLU = 5 %
    ]) + struct.pack('<H', 0x0211)  # CCS = CTEMP | NSSRO | RDY
       + b'\x00' * 2)               # reserved


CROSS_LAYER_BASE_US = 1720000000 * 1_000_000


def cross_layer_pcapng(packets, linktype=113):
    return shb() + idb(link_type=linktype) + b''.join(
        epb(packet, CROSS_LAYER_BASE_US + n * 1_000_000)
        for n, packet in enumerate(packets))


def cross_layer_version_vectors():
    """A bad version neither terminates an existing assembly nor starts one."""
    request = make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                            admin_request_payload(0x06, flags=0, cns=1, dlen=4))
    message = request[20:]

    def fragment(data, som, eom, seq, version=1, tag=0):
        header = mctp_header(True, som=som, eom=eom, seq=seq, tag=tag)
        return request[:16] + bytes([version]) + header[1:] + data

    return [
        fragment(message[:64], True, False, 0),
        fragment(message, True, True, 0, version=2),
        fragment(message[64:], False, True, 1),
        make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_resp_with_data(bytes(4))),
        fragment(message[:64], True, False, 0, version=2, tag=1),
        fragment(message[64:], False, True, 1, tag=1),
    ]


def cross_layer_fixtures():
    """{capture name: bytes}; suite_dissection_mctp.py checks these."""
    return {
        'mctp-version-state.pcapng': cross_layer_pcapng(cross_layer_version_vectors()),
    }


def main():
    captures_dir = os.path.join(os.path.dirname(__file__), '..',
                                'test', 'captures')
    if len(sys.argv) > 1:
        build_transport_capture(sys.argv[1])
        return
    build_transport_capture(os.path.join(captures_dir, 'mctp-transport.pcapng'))
    build_ingress_scope_pcapng(os.path.join(captures_dir, 'mctp-ingress-scope.pcapng'))
    for name, data in cross_layer_fixtures().items():
        with open(os.path.join(captures_dir, name), 'wb') as output:
            output.write(data)

if __name__ == '__main__':
    main()
