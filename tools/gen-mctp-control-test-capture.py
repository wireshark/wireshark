#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a pcapng test capture for the MCTP Control Protocol dissector
(epan/dissectors/packet-mctp-control.c) command-specific payload decode.

Produces test/captures/mctp-control.pcapng (407 frames in ten pcapng
sections).  F1-F53, mapped below, exercise the per-command payload layouts of
DSP0236 1.3.3 clause 12.  The other sections number their frames from 1 in
their own maps:

  F54-F96    payloads_section (Tables 20-39 command layouts):  F(53 + n)
  F97-F104   control_conformance_section (Table 11, 12.7.2):  F(96 + n)
  F105-F310  lengths_section (every closed layout, reserved runs):  F(104 + n)
  F311-F346  pairing_section (Table 10 pairing, binding addresses):  F(310 + n)
  F347-F359  smbus_pairing_section (null-EID pairing by SMBus address,
             repeated broadcast responses, Tables 24/25/32 values):  F(346 + n)
  F360-F377  eid_ranges_section (DSP0236 Table 2 reserved EIDs):  F(359 + n)
  F378       size_section (DSP0236 11.6 64-byte control payload):  F(377 + n)
  F379-F389  get_version_section (Table 18 entry count):  F(378 + n)
  F390-F407  response_values_section (Tables 2, 14, 15, 19):  F(389 + n)

  1/2   Set Endpoint ID (0x01) Set op request + accepted response with
        "requires EID pool allocation" status (Table 14)
  3/4   Set Endpoint ID Force op request + accepted response, no pool
  5/6   Set Endpoint ID Set op request + REJECTED-assignment response
        (status [5:4]=01b) with "already received allocation" [1:0]=10b
  7/8   Get Endpoint ID (0x02) empty request + response (Table 15):
        EID 0x42, endpoint type = bus owner/bridge, EID type = static
        supported/matches, medium-specific info 0x00
  9/10  Get Endpoint UUID (0x03) empty request + 16-byte RFC4122 UUID
        response (Tables 16/17)
  11/12 Get MCTP Version Support (0x04) request for type 0xFF + response
        with 4 entries covering all section 12.7.2 encoding rules:
        0xF1F0FF00 ("1.0"), 0xF1F3F300 ("1.3.3"), 0xF3F71061 ("3.7.10a"),
        0x1011F700 ("10.11.7")
  13/14 Get Message Type Support (0x05) empty request + response listing
        0x04 (NVMe-MI), 0x05 (SPDM), 0x7E (Table 19 excludes Control)
  15/16 Allocate Endpoint IDs (0x08) Allocate op + accepted response
        (Table 23)
  17/18 Allocate Endpoint IDs Get-allocation-information op + response
  19/20 Endpoint Discovery (0x0C) — no payload either direction (Table 29)
  21/22 Discovery Notify (0x0D) — no payload either direction (Table 30)

Adversarial frames:
  23    Get Endpoint ID response with error CC (0x05 unsupported command)
        carrying 3 stale payload bytes: per section 12.3 the payload must
        NOT be decoded as fields; the bytes must fall to mctpc.data
  24    Truncated Set Endpoint ID response: CC=0 but only 1 of 3 payload
        bytes present — must raise a tvb bounds exception (_ws.malformed),
        not crash or over-read
  25    Get MCTP Version Support response claiming count=10 with only one
        4-byte entry present — loop must terminate via bounds exception
  26    Get Endpoint ID response with 2 extra trailing bytes after a fully
        decoded payload — fields decoded AND leftovers in mctpc.data
  27    Get MCTP Version Support response with a spec-illegal 0xFF major
        BCD byte (only the update byte may be 0xFF, section 12.7.2) —
        must raise the mctpc.get_ver.entry.invalid_bcd expert warning

  28    Get Routing Table Entries (0x0A) response with two entries of
        different shape (Table 27): a dynamic single-endpoint entry with
        a 1-byte SMBus address, and a statically configured bridge
        EID-range entry with a 2-byte PCIe address
  29    Get Routing Table Entries response declaring 2 entries but
        carrying only one entry's bytes
  30    Routing table entry declaring a 255-byte physical address with
        only 2 address bytes present
  31    Routing table entry whose 6-byte fixed header is itself split
        (3 bytes present) — 29/30/31 must each raise the precise
        mctpc.payload.truncated expert and no generic
        _ws.malformed

Reserved-bit-run frames (DSP0236 1.3.3 section 5.3):
  32    Set Endpoint ID request whose Table 14 byte 1 [7:2] reserved run
        is non-zero (0x21), operation [1:0] still 00b
  33/34 Allocate Endpoint IDs request and response whose Table 23 byte 1
        / byte 2 [7:2] reserved runs are non-zero (0x32 / 0x1F) — the
        same defect as 32, so a fix applied to only one command fails

Clause 11 flag-bit conformance frames:
  36    Control message with the IC bit set, which section 11.4.2 says
        shall always be 0b
  37/38 (TO, Rq, D) triples of (0b,1b,0b) and (1b,0b,1b), neither a row of
        section 11.7 Table 11, which has the receiver silently discard such
        a message — so neither completion code nor payload may be decoded
  39    (1b,1b,1b), Table 11's Datagram row and therefore legal: the only
        frame in the capture with D set, so a check that just required
        D = 0b would fail here
  40    MCTP header byte 0 = 0xF1: version 1 with a non-zero DSP0236
        Table 1 RSVD nibble, contrary to section 5.3's zero requirement

Values the specs name:
  41/42 Completion codes 0x06 and 0x7F, the ends of Table 13's closing
        "All other | Reserved" row
  43    Completion code 0x80, the first COMMAND_SPECIFIC code and the
        neighbour that Reserved row must not swallow
  44/45 Get Endpoint ID responses with Table 15 Endpoint Type [5:4] =
        10b and 11b, both named "reserved" there
  46/47 Get MCTP Version Support requests for message types 0x7E and
        0x7F, which Table 18 calls out by number
  48    Routing entry with physical media type 0x07, DSP0239 Table 2's
        one discrete Reserved row (and next handle 0xFF)

Version alpha byte (section 12.7.2):
  49    Version entry 0xF1F3F330 — alpha byte '0', neither 0x00 nor
        [a-zA-Z], and dropped from the rendered label
  50    Version entry 0xF1F3F35A — alpha byte 'Z', legal uppercase
  51    Get Endpoint ID: simple endpoint using a dynamic EID (Table 15)
  52/53 Get Version Support for Control (type 00h), version 1.3.3 (Table 18)

Wire format layers (outer to inner), same framing as
tools/gen-nvme-mi-test-capture.py:
  Linux SLL cooked capture header (16 bytes, DLT=113, proto 0x00FA MCTP)
  MCTP transport header            (4 bytes)
  MCTP control message             (byte 0 = MCTP type 0x00, IC clear;
                                    byte 1 = Rq(0x80)|D(0x40)|InstanceID(0x1f);
                                    byte 2 = command code;
                                    responses: byte 3 = completion code;
                                    then command-specific payload)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapng_testgen import DLT_LINUX_I2C, epb, i2c_phdr, idb, shb, sll_header, smbus_pec

# ---------------------------------------------------------------------------
# MCTP transport header (4 bytes): ver, dst EID, src EID, SOM|EOM|seq|TO|tag
# ---------------------------------------------------------------------------

HOST_EID     = 0x0A
ENDPOINT_EID = 0x42
DEV_EID      = 0x30
BMC_EID      = 0x08
BCAST_EID    = 0xFF

def mctp_header(dst, src, to, hdr_byte=0x01):
    """SOM|EOM, sequence 0, tag 0; byte 0 is [7:4] RSVD and [3:0] the version."""
    return bytes([hdr_byte, dst, src, 0xC8 if to else 0xC0])

# ---------------------------------------------------------------------------
# MCTP control message body (DSP0236 1.3.3 clause 11.4/11.5)
# ---------------------------------------------------------------------------
# Byte 0: MCTP message type 0x00 (control), IC bit clear (11.4.2)
# Byte 1: [7]=Rq, [6]=D, [5]=rsvd, [4:0]=Instance ID
# Byte 2: command code (Table 12)
# Responses only: byte 3 = completion code (Table 13)

def ctrl_request(cmd, iid, payload=b''):
    return bytes([0x00, 0x80 | (iid & 0x1F), cmd]) + payload

def ctrl_response(cmd, iid, cc=0x00, payload=b''):
    return bytes([0x00, iid & 0x1F, cmd, cc]) + payload

def ctrl_msg(cmd, iid, rq, d, ic=False, payload=b''):
    """A control message with every DSP0236 Table 10 flag under caller
    control, for the conformance frames that must violate one."""
    return bytes([0x80 if ic else 0x00,
                  (0x80 if rq else 0x00) | (0x40 if d else 0x00) | (iid & 0x1F),
                  cmd]) + payload

def frame(is_request, body, to=None, hdr_byte=0x01):
    """A HOST_EID <-> ENDPOINT_EID frame; to overrides the direction's Tag Owner bit."""
    src, dst = (HOST_EID, ENDPOINT_EID) if is_request else (ENDPOINT_EID, HOST_EID)
    return sll_header(src) + mctp_header(dst, src, is_request if to is None else to,
                                         hdr_byte) + body


def control_frame(dst, src, to, rq, d, cmd, payload=b'', iid=1):
    """A control message with every Table 11 input under caller control."""
    return sll_header(src) + mctp_header(dst, src, to) + ctrl_msg(cmd, iid, rq, d,
                                                                  payload=payload)


def section(packets, base_us, step_us=1_000_000):
    """A pcapng section; a packet may be a (bytes, origlen) pair."""
    data = shb() + idb()
    for i, packet in enumerate(packets):
        packet, origlen = packet if isinstance(packet, tuple) else (packet, None)
        data += epb(packet, base_us + i * step_us, origlen=origlen)
    return data

def build_capture(path):
    frames = []

    # -- Set Endpoint ID (0x01), Table 14 ---------------------------------
    # 1: request, operation 00b Set EID, EID 0x42
    frames.append(frame(True, ctrl_request(0x01, 1, bytes([0x00, 0x42]))))
    # 2: response, accepted ([5:4]=00b), requires pool allocation ([1:0]=01b),
    #    EID setting 0x42, pool size 4
    frames.append(frame(False, ctrl_response(0x01, 1,
                        payload=bytes([0x01, 0x42, 0x04]))))
    # 3: request, operation 01b Force EID, EID 0x43
    frames.append(frame(True, ctrl_request(0x01, 2, bytes([0x01, 0x43]))))
    # 4: response, accepted, no EID pool, EID setting 0x43, pool size 0
    frames.append(frame(False, ctrl_response(0x01, 2,
                        payload=bytes([0x00, 0x43, 0x00]))))
    # 5: request, operation 00b Set EID, EID 0x50 (will be rejected)
    frames.append(frame(True, ctrl_request(0x01, 3, bytes([0x00, 0x50]))))
    # 6: response, REJECTED ([5:4]=01b) + already-received allocation
    #    ([1:0]=10b) = 0x12, present EID setting 0x42, pool size 2
    frames.append(frame(False, ctrl_response(0x01, 3,
                        payload=bytes([0x12, 0x42, 0x02]))))

    # -- Get Endpoint ID (0x02), Table 15 ---------------------------------
    # 7: request, no payload
    frames.append(frame(True, ctrl_request(0x02, 4)))
    # 8: response: EID 0x42; endpoint type byte = bus owner/bridge
    #    ([5:4]=01b) + static EID matches ([1:0]=10b) = 0x12; medium 0x00
    frames.append(frame(False, ctrl_response(0x02, 4,
                        payload=bytes([0x42, 0x12, 0x00]))))

    # -- Get Endpoint UUID (0x03), Tables 16/17 ---------------------------
    # 9: request, no payload
    frames.append(frame(True, ctrl_request(0x03, 5)))
    # 10: response: 16-byte UUID, MSB first per RFC4122
    uuid = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    frames.append(frame(False, ctrl_response(0x03, 5, payload=uuid)))

    # -- Get MCTP Version Support (0x04), Table 18 / 12.7.2 ---------------
    # 11: request for message type 0xFF (MCTP base specification)
    frames.append(frame(True, ctrl_request(0x04, 6, bytes([0xFF]))))
    # 12: response, 4 entries covering all 12.7.2 encoding rules
    vers = struct.pack('>I', 0xF1F0FF00)   # "1.0"    (update 0xFF skipped)
    vers += struct.pack('>I', 0xF1F3F300)  # "1.3.3"
    vers += struct.pack('>I', 0xF3F71061)  # "3.7.10a" (2-digit update, alpha)
    vers += struct.pack('>I', 0x1011F700)  # "10.11.7" (2-digit major/minor)
    frames.append(frame(False, ctrl_response(0x04, 6,
                        payload=bytes([4]) + vers)))

    # -- Get Message Type Support (0x05), Table 19 ------------------------
    # 13: request, no payload
    frames.append(frame(True, ctrl_request(0x05, 7)))
    # 14: Table 19 counts only types in addition to implicit Control (00h).
    frames.append(frame(False, ctrl_response(0x05, 7,
                        payload=bytes([3, 0x04, 0x05, 0x7E]))))

    # -- Allocate Endpoint IDs (0x08), Table 23 ---------------------------
    # 15: request, operation 00b Allocate EIDs, 4 EIDs starting at 0x50
    frames.append(frame(True, ctrl_request(0x08, 8, bytes([0x00, 4, 0x50]))))
    # 16: response: accepted ([1:0]=00b), pool size 4, first EID 0x50
    frames.append(frame(False, ctrl_response(0x08, 8,
                        payload=bytes([0x00, 4, 0x50]))))
    # 17: request, operation 10b Get allocation information
    frames.append(frame(True, ctrl_request(0x08, 9, bytes([0x02, 0, 0x00]))))
    # 18: response: accepted, pool size 4, first EID 0x50
    frames.append(frame(False, ctrl_response(0x08, 9,
                        payload=bytes([0x00, 4, 0x50]))))

    # -- Endpoint Discovery (0x0C), Table 29: no payload ------------------
    # 19/20: request + success response, completion code only
    frames.append(frame(True, ctrl_request(0x0C, 10)))
    frames.append(frame(False, ctrl_response(0x0C, 10)))

    # -- Discovery Notify (0x0D), Table 30: no payload --------------------
    # 21/22: request + success response
    frames.append(frame(True, ctrl_request(0x0D, 11)))
    frames.append(frame(False, ctrl_response(0x0D, 11)))

    # -- Adversarial frames ------------------------------------------------
    # 23: Get Endpoint ID response with error CC 0x05 (unsupported command)
    #     and 3 stale payload bytes.  Per 12.3 these must NOT be decoded as
    #     Table 15 fields; they must appear only as mctpc.data.
    frames.append(frame(False, ctrl_response(0x02, 12, cc=0x05,
                        payload=bytes([0x42, 0x12, 0x00]))))
    # 24: truncated Set Endpoint ID response: CC=0 but only the status byte
    #     of the 3-byte payload is present -> tvb bounds exception
    frames.append(frame(False, ctrl_response(0x01, 13,
                        payload=bytes([0x11]))))
    # 25: Get MCTP Version Support response claiming 10 entries but carrying
    #     only one -> the entry loop must stop via a bounds exception
    frames.append(frame(False, ctrl_response(0x04, 14,
                        payload=bytes([10]) + struct.pack('>I', 0xF1F0FF00))))
    # 26: Get Endpoint ID response with 2 trailing bytes after the complete
    #     Table 15 payload -> fields decoded, leftovers in mctpc.data
    frames.append(frame(False, ctrl_response(0x02, 15,
                        payload=bytes([0x42, 0x12, 0x00, 0xDE, 0xAD]))))
    # 27: Get MCTP Version Support response with an illegal 0xFF major BCD
    #     byte (12.7.2 defines 0xFF only for the update byte) -> expert warn
    frames.append(frame(False, ctrl_response(0x04, 16,
                        payload=bytes([1]) + struct.pack('>I', 0xFFF1F000))))

    # -- Get Routing Table Entries (0x0A) responses, Table 27 --------------
    # Entry: range size, starting EID, [7:6] type/[5] static/[4:0] port,
    # binding ID, media type, address size, MSB-first physical address.
    def routing_entry(range_size, start_eid, type_port, binding, media, addr):
        return bytes([range_size, start_eid, type_port, binding, media,
                      len(addr)]) + addr

    # 28: next handle 0x01, 2 entries of different shape:
    #     single endpoint, dynamic, port 2, SMBus binding, 1-byte address;
    #     bridge EID range of 8 starting at its own EID, statically
    #     configured, port 3, PCIe VDM binding, 2-byte address
    frames.append(frame(False, ctrl_response(0x0A, 17,
                        payload=bytes([0x01, 0x02]) +
                        routing_entry(1, 0x10, 0x02, 0x01, 0x01, b'\x51') +
                        routing_entry(8, 0x20, 0x63, 0x02, 0x08, b'\x00\x1b'))))
    # 29: count claims 2 entries, only one entry's bytes present
    frames.append(frame(False, ctrl_response(0x0A, 18,
                        payload=bytes([0x01, 0x02]) +
                        routing_entry(1, 0x10, 0x02, 0x01, 0x01, b'\x51'))))
    # 30: entry declares a 255-byte physical address, 2 bytes present
    frames.append(frame(False, ctrl_response(0x0A, 19,
                        payload=bytes([0x01, 0x01]) +
                        bytes([1, 0x10, 0x02, 0x01, 0x01, 255]) + b'\xAA\xBB')))
    # 31: entry's 6-byte fixed header split — only 3 bytes present
    frames.append(frame(False, ctrl_response(0x0A, 20,
                        payload=bytes([0x01, 0x01]) +
                        bytes([1, 0x10, 0x02]))))

    # -- Non-zero [7:2] reserved runs (Tables 14 and 23) -------------------
    # DSP0236 5.3 requires reserved bit fields be written as 0; a sender that
    # does not is only visible if the run is registered.  Each frame keeps
    # the [1:0] enum at a known value so a mask error is distinguishable
    # from a missing field.
    # 32: Set Endpoint ID request, op byte 0x84 -> rsvd [7:2] = 0x21,
    #     operation [1:0] = 00b (Set EID)
    frames.append(frame(True, ctrl_request(0x01, 21, bytes([0x84, 0x42]))))
    # 33: Allocate Endpoint IDs request, op byte 0xC8 -> rsvd = 0x32,
    #     operation [1:0] = 00b (Allocate EIDs)
    frames.append(frame(True, ctrl_request(0x08, 22, bytes([0xC8, 4, 0x50]))))
    # 34: Allocate Endpoint IDs response, status byte 0x7D -> rsvd = 0x1F,
    #     status [1:0] = 01b (Allocation rejected)
    frames.append(frame(False, ctrl_response(0x08, 22,
                        payload=bytes([0x7D, 4, 0x50]))))

    # -- Transport Specific command range (Table 12, section 12.24) --------
    # 35: command 0xF1, inside Table 12's 0xF0-0xFF "Transport Specific"
    #     row. Table 39 defines the common binding/media prefix;
    #     only the remaining AA command data is binding-defined.
    frames.append(frame(True, ctrl_request(0xF1, 23,
                        bytes([0x01, 0x01, 0xAA]))))

    # -- Clause 11 flag-bit conformance (11.4.2 and 11.7 Table 11) ---------
    # 36: Get Endpoint ID request with the IC bit set.  11.4.2: "MCTP
    #     control messages do not use a Message Integrity Check field.
    #     Therefore, the IC bit in MCTP control messages shall always be
    #     0b."  The (TO, Rq, D) triple is the legal (1b, 1b, 0b), so this
    #     frame isolates the IC rule.
    frames.append(frame(True, ctrl_msg(0x02, 24, rq=True, d=False, ic=True)))
    # 37: Set Endpoint ID request payload sent with (TO, Rq, D) =
    #     (0b, 1b, 0b) -- a responder that left Rq set.  Not a Table 11 row,
    #     so 11.7 has the receiver silently discard it: the 2-byte Table 14
    #     request payload must fall to mctpc.data rather than decode.
    frames.append(frame(False, ctrl_msg(0x01, 25, rq=True, d=False,
                                        payload=bytes([0x00, 0x42])),
                        to=False))
    # 38: Get Endpoint ID response shape sent with (TO, Rq, D) =
    #     (1b, 0b, 1b), also outside Table 11.  Rq = 0b would otherwise make
    #     byte 3 a completion code, so this frame proves the completion code
    #     is skipped along with the payload.
    frames.append(frame(True, ctrl_msg(0x02, 26, rq=False, d=True,
                                       payload=bytes([0x00, 0x42, 0x12,
                                                      0x00])),
                        to=True))
    # 39: Datagram: (TO, Rq, D) = (1b, 1b, 1b) is Table 11's fourth row and
    #     therefore legal.  No frame above sets D, so without this one a
    #     check that merely required D = 0b would pass 37 and 38.
    frames.append(frame(True, ctrl_msg(0x01, 27, rq=True, d=True,
                                       payload=bytes([0x00, 0x44]))))
    # 40: MCTP header byte 0 = 0xF1: version 1 with the DSP0236 Table 1
    #     RSVD nibble [7:4] set to Fh. Section 5.3 requires reserved fields
    #     to be written as zero and ignored when read, so this frame retains
    #     decoding while showing the reserved nibble.
    frames.append(frame(True, ctrl_request(0x02, 28), hdr_byte=0xF1))

    # -- Named-but-unenumerated table values -------------------------------
    # Each of these renders "Unknown" unless the spec's own name for the
    # value is carried in the dissector's table.
    # 41/42: completion codes at both ends of Table 13's closing
    #     "All other | Reserved" row, which is the 0x06 - 0x7F run.
    frames.append(frame(False, ctrl_response(0x02, 29, cc=0x06)))
    frames.append(frame(False, ctrl_response(0x02, 30, cc=0x7F)))
    # 43: completion code 0x80, the first COMMAND_SPECIFIC code.  It is the
    #     neighbour the Reserved row must not swallow.
    frames.append(frame(False, ctrl_response(0x02, 31, cc=0x80)))
    # 44/45: Get Endpoint ID responses whose Table 15 byte 3 Endpoint Type
    #     [5:4] is 10b and 11b, both of which the table names "reserved".
    #     The Endpoint ID Type [1:0] beside it differs in each frame, so a
    #     [5:4]/[1:0] mask swap changes what is asserted.
    frames.append(frame(False, ctrl_response(0x02, 32,
                        payload=bytes([0x42, 0x21, 0x00]))))
    frames.append(frame(False, ctrl_response(0x02, 33,
                        payload=bytes([0x42, 0x32, 0x00]))))
    # 46/47: Get MCTP Version Support requests for message types 0x7E and
    #     0x7F, which Table 18 calls out by number.
    frames.append(frame(True, ctrl_request(0x04, 34, bytes([0x7E]))))
    frames.append(frame(True, ctrl_request(0x04, 35, bytes([0x7F]))))
    # 48: routing entry whose physical media type is 0x07, DSP0239 Table 2's
    #     one discrete Reserved row.  Next handle 0xFF ("no more entries")
    #     is otherwise unexercised too.
    frames.append(frame(False, ctrl_response(0x0A, 36,
                        payload=bytes([0xFF, 0x01]) +
                        routing_entry(1, 0x10, 0x02, 0x01, 0x07, b'\x51'))))

    # -- Version alpha byte (section 12.7.2) -------------------------------
    # 49: alpha byte 0x30 ('0'), neither 0x00 nor [a-zA-Z].  The renderer
    #     drops it, so "1.3.3" is all that is shown and the deviation is
    #     invisible without an expert.  Frame 12's 'a' and the 0x00 alpha
    #     bytes elsewhere are the negative controls.
    frames.append(frame(False, ctrl_response(0x04, 37,
                        payload=bytes([1]) + struct.pack('>I', 0xF1F3F330))))
    # 50: alpha byte 0x5A ('Z').  12.7.2 allows [a-z, A-Z]; frame 12 only
    #     covers lowercase, so a check limited to [a-z] would flag this.
    frames.append(frame(False, ctrl_response(0x04, 38,
                        payload=bytes([1]) + struct.pack('>I', 0xF1F3F35A))))

    # Common zero encodings complement the reserved-value examples above.
    frames.append(frame(False, ctrl_response(0x02, 39,
                        payload=bytes([0x42, 0x00, 0x00]))))
    frames.append(frame(True, ctrl_request(0x04, 40, bytes([0x00]))))
    frames.append(frame(False, ctrl_response(0x04, 40,
                        payload=bytes([1]) + struct.pack('>I', 0xF1F3F300))))

    with open(path, 'wb') as f:
        # Separate sections, so no state crosses from one map to the next.
        f.write(section(frames, 1000000, 1000) + payloads_section()
                + control_conformance_section() + lengths_section()
                + pairing_section() + smbus_pairing_section()
                + eid_ranges_section() + size_section()
                + get_version_section() + response_values_section())

    print(f'wrote {path} ({len(frames)} + 43 + 8 + 206 + 36 + 13 + 18 + 1 + 11 + 18 frames)')

def payloads_section():
    """DSP0236 Tables 20-39: 26 representative frames and 17 bounds/open-layout controls.

    1/2   F0 transport-specific common envelope (Table 39).
    3/4   FF vendor transport envelope with IANA prefix (Table 39).
    5/6   Network UUID (Table 31).
    7/8   Resolve EID, binding-defined address tail (Table 22).
    9/10  Vendor PCI format; trailing bytes are excess (Tables 20/21).
    11/12 Vendor IANA format (Tables 20/21).
    13/14 Two routing updates; only first common prefix locatable (24/25).
    15/16 Query Hop; the two TU fields, read at 4:5 and 6:7 (Table 32).
    17/18 Resolve UUID; two self-delimited records and excess tail (33/34).
    19/20 Supported Interfaces; two pairs (Table 38).
    21/22 Query Rate Limit (Table 35).
    23/24 Request TX Rate Limit: 24-bit request / 32-bit response burst (36).
    25/26 Update Rate Limit (Table 37).
    27/28 Transport envelope missing media / split vendor IANA.
    29    Unknown vendor format: no assumed ID or command-set extent.
    30/31 Vendor response split PCI ID / split command-set value.
    32    Resolve EID response missing bridge EID.
    33    Routing Update first prefix split; no address-size inference.
    34    Query Hop response missing common message-type field.
    35/36 Resolve UUID split record header / missing second record.
    37    Resolve UUID address-size 255 exceeds remaining bytes.
    38/39 Supported Interfaces zero count (invalid) / split counted pair.
    40    Snaplen loss in Resolve UUID address, correct reported length.
    41    Non-success vendor response: residue, no payload decode.
    42    Resolve UUID zero entries: trailing bytes are excess.
    43    Resolve EID response whose address tail is one byte, on a binding
          that is not SMBus/I2C.  DSP0237 6.8 Table 3's one-byte form applies
          only to a bus using that binding, and this capture is SLL-framed, so
          the tail must stay the raw Table 22 field: the size coincidence must
          not be mistaken for the binding.  Frame 8's three-byte tail cannot
          prove that, since its length alone rules Table 3 out.
    """
    frames = []

    def request(cmd, payload=b''):
        frames.append((frame(True, ctrl_request(cmd, 1, payload)), None))

    def response(cmd, payload=b'', cc=0):
        frames.append((frame(False, ctrl_response(cmd, 1, cc, payload)), None))

    uuid = bytes.fromhex('123456789abc4ef08122334455667788')
    request(0xf0, bytes.fromhex('0104aa55'))
    response(0xf0)
    request(0xff, bytes.fromhex('ff0001020304dead'))
    response(0xff)
    request(0x0e)
    response(0x0e, uuid)
    request(0x07, b'\x42')
    response(0x07, bytes.fromhex('501234a6'))
    request(0x06, b'\x00')
    response(0x06, bytes.fromhex('ff001234a1b2dead'))
    request(0x06, b'\x01')
    response(0x06, bytes.fromhex('ff0101020304a5b6'))
    request(0x09, bytes.fromhex('02030451aa55000162cc'))
    response(0x09)
    request(0x0f, bytes.fromhex('4204'))
    response(0x0f, bytes.fromhex('50ff11223344'))
    request(0x10, uuid + b'\x00')
    response(0x10, bytes.fromhex('ff02420104015043020b021234dead'))
    request(0x14)
    response(0x14, bytes.fromhex('0204420b43'))
    request(0x11)
    response(0x11, bytes.fromhex(
        '01020304 11223344 21324354 31425364 010203 040506 41526374 01'))
    request(0x12, bytes.fromhex('01020312345678'))
    response(0x12, bytes.fromhex('234567893456789a'))
    request(0x13, bytes.fromhex('020304456789ab'))
    response(0x13)
    request(0xf0, b'\x01')
    request(0xff, bytes.fromhex('ff00000001'))
    response(0x06, bytes.fromhex('ff02deadbeef'))
    response(0x06, bytes.fromhex('ff0012'))
    response(0x06, bytes.fromhex('ff001234aa'))
    response(0x07)
    request(0x09, bytes.fromhex('020104'))
    response(0x0f, b'\x50')
    response(0x10, bytes.fromhex('ff01420104'))
    response(0x10, bytes.fromhex('ff024201040150'))
    response(0x10, bytes.fromhex('ff01420104ffaa'))
    response(0x14, b'\x00')
    response(0x14, bytes.fromhex('0204420b'))
    complete = frame(False, ctrl_response(0x10, 1,
                     payload=bytes.fromhex('ff0142020b021234')))
    frames.append((complete[:-1], len(complete)))
    response(0x06, bytes.fromhex('ff001234a1b2'), cc=0x80)
    response(0x10, bytes.fromhex('ff00dead'))
    response(0x07, bytes.fromhex('5062'))

    return section(frames, 1000000, 1000)


# ---------------------------------------------------------------------------
# mctp-control.pcapng F97-F104 (control_conformance_section) - DSP0236 Table 11, 12.7.2
# ---------------------------------------------------------------------------
#
# Table 11 lists five legal MCTP control message classes and closes with a
# "Reserved for future definition | all other" row, and its first column is
# the *destination EID*:
#
#   Command/Request      Target EID     TO 1b  Rq 1b  D 0b
#   Response             Target EID     TO 0b  Rq 0b  D 0b
#   Broadcast Request    Broadcast EID  TO 1b  Rq 1b  D 0b
#   Datagram             Target EID     TO 1b  Rq 1b  D 1b
#   Broadcast Datagram   Broadcast EID  TO 1b  Rq 1b  D 1b
#
#   F1  Request            dst 30h  TO 1 Rq 1 D 0   Get Endpoint ID
#   F2  Response           dst 0Ah  TO 0 Rq 0 D 0   cc 00h Success
#   F3  Response           dst 0Ah  TO 0 Rq 0 D 0   cc 05h unsupported command
#   F4  Datagram           dst 30h  TO 1 Rq 1 D 1   Discovery Notify
#   F5  Broadcast Request  dst FFh  TO 1 Rq 1 D 0   Prepare for Endpoint Discovery
#   F6  Broadcast Datagram dst FFh  TO 1 Rq 1 D 1   Endpoint Discovery
#   F7  dst FFh            TO 0 Rq 0 D 0            no Table 11 row
#   F8  Get MCTP Version Support response, five entries covering 12.7.2
#
# Each pair differs in one input: F2/F3 in the completion code, F1/F4 in D,
# F1/F5, F4/F6 and F2/F7 in the destination.

# Get Endpoint ID response payload (Table 15): EID 30h, endpoint type byte,
# medium-specific info.  Present so that F2's successful response has
# something below the completion code and F3's failing one visibly does not.
GET_EID_RESP = bytes([0x30, 0x12, 0x00])

# DSP0236 12.7.2 in five entries:
#   F1F3F300  major 1, minor 3, update 3, no alpha        -> "1.3.3"
#   F1F0FF61  update FFh means the field is absent, alpha -> "1.0a"
#   F1FAF300  minor FAh: low nibble Ah is not a BCD digit
#   F1F31A00  update 1Ah: same, in the update byte
#   FFF1F000  major FFh, which 12.7.2 forbids
VERSIONS = b''.join(struct.pack('>I', v) for v in (
    0xF1F3F300, 0xF1F0FF61, 0xF1FAF300, 0xF1F31A00, 0xFFF1F000))

packets_control_conformance = [
    control_frame(DEV_EID, HOST_EID, to=True, rq=True, d=False,
               cmd=0x02, iid=1),
    control_frame(HOST_EID, DEV_EID, to=False, rq=False, d=False,
               cmd=0x02, iid=1, payload=bytes([0x00]) + GET_EID_RESP),
    control_frame(HOST_EID, DEV_EID, to=False, rq=False, d=False,
               cmd=0x02, iid=2, payload=bytes([0x05])),
    control_frame(DEV_EID, HOST_EID, to=True, rq=True, d=True,
               cmd=0x0D, iid=3),
    control_frame(BCAST_EID, HOST_EID, to=True, rq=True, d=False,
               cmd=0x0B, iid=4),
    control_frame(BCAST_EID, HOST_EID, to=True, rq=True, d=True,
               cmd=0x0C, iid=5),
    control_frame(BCAST_EID, DEV_EID, to=False, rq=False, d=False,
               cmd=0x02, iid=6, payload=bytes([0x00]) + GET_EID_RESP),
    control_frame(HOST_EID, DEV_EID, to=False, rq=False, d=False,
               cmd=0x04, iid=7,
               payload=bytes([0x00, 5]) + VERSIONS),
]

BASE_TS_CONTROL_CONFORMANCE_US = 1713225600 * 1_000_000


def control_conformance_section():
    return section(packets_control_conformance, BASE_TS_CONTROL_CONFORMANCE_US)


def _reserved_run_packets():
    """DSP0236 5.3 / Tables 14, 15, 23: the MCTP Control reserved runs, each zero then nonzero."""
    out = []
    for request, body, offset, mask in (
            (True, b'\x00\x80\x02', 1, 0x20),                     # header
            (True, b'\x00\x80\x01\x00\x30', 3, 0xfc),             # Set EID request
            (False, b'\x00\x00\x01\x00\x00\x30\x00', 4, 0xc0),   # Set EID status high
            (False, b'\x00\x00\x01\x00\x00\x30\x00', 4, 0x0c),   # Set EID status low
            (False, b'\x00\x00\x02\x00\x30\x00\x00', 5, 0xc0),   # Get EID type high
            (False, b'\x00\x00\x02\x00\x30\x00\x00', 5, 0x0c),   # Get EID type low
            (True, b'\x00\x80\x08\x00\x01\x30', 3, 0xfc),         # Allocate EIDs request
            (False, b'\x00\x00\x08\x00\x00\x01\x30', 4, 0xfc)):  # Allocate EIDs response
        src, dst = (HOST_EID, BMC_EID) if request else (BMC_EID, HOST_EID)
        for nonzero in (False, True):
            payload = bytearray(body)
            payload[offset] |= mask if nonzero else 0
            out.append(sll_header(src, outgoing=request)
                       + mctp_header(dst, src, request) + bytes(payload))
    return out


def _packets_lengths():
    packets = []

    def add(cmd, rq, payload=b'', *, captured_body=None):
        packet = control_frame(
            DEV_EID if rq else HOST_EID,
            HOST_EID if rq else DEV_EID,
            to=rq, rq=rq, d=False, cmd=cmd, payload=payload)
        if captured_body is not None:
            packets.append((packet[:20 + captured_body], len(packet)))
        else:
            packets.append(packet)

    # 1/2: exact byte twins of mctp-control.pcapng frame 40, with
    # only the reserved nibble changed. 3-14: every operation with null,
    # broadcast and ordinary EIDs (illegal only at 3,4,6,7).
    zero_nibble = control_frame(0x42, 0x0a, to=True, rq=True, d=False, cmd=2, iid=28)
    packets.extend((zero_nibble, zero_nibble[:16] + b'\xf1' + zero_nibble[17:]))
    for operation in range(4):
        for eid in (0, 0xff, 0x42):
            add(1, True, bytes([operation, eid]))

    # 15-90: all nineteen closed requests, in command order. Each quartet
    # is exact / reported one short / two excess / captured one short.
    # Table 24 Routing Information Update is variable and is not closed.
    requests = (
        (1, b'\x00\x42'), (2, b''), (3, b''), (4, b'\xff'), (5, b''),
        (6, b'\x00'), (7, b'\x42'), (8, b'\x00\x04\x50'),
        (10, b'\x00'), (11, b''), (12, b''), (13, b''), (14, b''),
        (15, b'\x42\x00'), (16, bytes(16) + b'\x00'), (17, b''),
        (18, bytes(7)), (19, bytes(7)), (20, b''),
    )
    # 91-146: twelve closed standard successes and both ends of Table 39.
    # Table 32's overlapping TU extents are deliberately not inferred.
    successes = (
        (1, b'\x00\x42\x00'), (2, b'\x42\x00\x00'), (3, bytes(16)),
        (8, b'\x00\x04\x50'), (9, b''), (11, b''), (12, b''),
        (13, b''), (14, bytes(16)), (17, bytes(27)), (18, bytes(8)),
        (19, b''), (0xf0, b''), (0xff, b''),
    )
    for rq, layouts in ((True, requests), (False, successes)):
        for cmd, data in layouts:
            payload = data if rq else b'\x00' + data
            add(cmd, rq, payload)
            add(cmd, rq, payload)
            packets[-1] = packets[-1][:-1]
            add(cmd, rq, payload + b'\xde\xad')
            add(cmd, rq, payload, captured_body=3 + len(payload) - 1)

    assert len(packets) == 146
    # 147-150: generic error exact / missing CC / excess / missing captured CC.
    add(2, False, b'\x05')
    add(2, False)
    add(2, False, b'\x05\xde\xad')
    add(2, False, b'\x05', captured_body=3)
    # 151-154: the two command-specific 80h results, each with an 81h control.
    for cmd in (4, 9):
        add(cmd, False, b'\x80')
        add(cmd, False, b'\x81')

    # 155-168: T18 and T19 count-bearing response windows. Bytes past the
    # counted entries are excess (158, 165).
    for cmd, entry in ((4, bytes.fromhex('f1f3f300')), (5, b'\x04')):
        add(cmd, False, b'\x00\x01' + entry)
        add(cmd, False, b'\x00\x02' + entry + entry[:-1])
        add(cmd, False, b'\x00\x01' + entry, captured_body=4 + len(entry))
        add(cmd, False, b'\x00\x01' + entry + b'\xde\xad')
        add(cmd, False, b'\x00')
        add(cmd, False, b'\x00\x01' + entry, captured_body=4)
        add(cmd, False, b'\x00\x00')

    # 169-175: routing entry exact / captured fixed header / captured address /
    # missing count / missing captured count / excess tail / reported short header.
    routing = b'\x00\xff\x01\x01\x42\x00\x01\x01\x02\x50\x51'
    add(10, False, routing)
    add(10, False, routing, captured_body=8)
    add(10, False, routing, captured_body=13)
    add(10, False, b'\x00\xff')
    add(10, False, routing, captured_body=5)
    add(10, False, routing + b'\xde\xad')
    add(10, False, routing[:6])

    # 176-187: raw/open layouts (including unknown/reserved command values)
    # and both interpretations of Table 32: only 4 TU bytes (7 bytes of
    # response data) are well-formed, so 182's 3 bytes are flagged.
    for cmd, rq, payload in (
            (0x20, True, b'\xde\xad'), (0x20, False, b'\x00\xde\xad'),
            (7, False, b'\x00\x42\x50\x51\x52'),
            (6, False, b'\x00\xff\x00\x12\x34\x00\x01'),
            (6, False, b'\x00\xff\x01\x00\x00\x01\x9c\x00\x01'),
            (9, True, b'\x01\x00\x01\x42\x50'),
            (15, False, bytes(6)), (15, False, bytes(7)),
            (16, False, b'\x00\xff\x00'),
            (20, False, b'\x00\x01\x01\x42'),
            (0xf0, True, b'\x01\x01\xde\xad'),
            (0xff, True, b'\xff\x00\x00\x00\x01\x9c\xde\xad')):
        add(cmd, rq, payload)
    # 188/189: EIDs 01h and 07h are reserved values (DSP0236 Table 2),
    # flagged as invalid values but not as reserved bit fields; 190: a
    # reserved command code.
    for eid in (1, 7):
        add(1, True, bytes([0, eid]))
    add(0, True, b'\xde\xad')
    assert len(packets) == 190
    # 191-206: the reserved runs, zero then nonzero.
    packets.extend(_reserved_run_packets())
    assert len(packets) == 206
    return packets


def lengths_section():
    return section(_packets_lengths(), BASE_TS_CONTROL_CONFORMANCE_US)


BASE_TS_PAIRING_US = 1713312000 * 1_000_000


def _tagged(src, dst, tag, rq, cmd, iid, payload=b'', cc=None, d=False):
    """A control message between any two EIDs with a caller-chosen tag;
    requests carry TO=1, responses TO=0 (DSP0236 Table 11)."""
    body = ctrl_msg(cmd, iid, rq, d,
                    payload=(b'' if cc is None else bytes([cc])) + payload)
    return (sll_header(src, outgoing=src == HOST_EID)
            + bytes([0x01, dst, src, 0xC0 | (0x08 if rq else 0) | (tag & 7)])
            + body)


def _packets_pairing():
    """DSP0236 Table 10 request/response pairing, and the DSP0237 /
    DSP0238 / DSP0233 physical-address layouts.  A response pairs with the
    latest request from its destination to its source with the same tag,
    Instance ID and command; a broadcast or null-EID request pairs with any
    responder.

    1/2   Get EID and Get UUID requests, tags 1/2 (interleaved).
    3/4   Their responses in reverse order: 3 -> 2, 4 -> 1.
    5/6   Get EID again, same tag and IID after the exchange completed.
    7/8   Same tag and IID to two endpoints (0x42, 0x30) at once.
    9/10  The responses, 0x30's first: 9 -> 8, 10 -> 7.
    11/12 Instance ID 31, then 13/14 its wrap to 0 with an error response.
    15    Get EID request, tag 4, IID 5.
    16    Response with the same tag/IID but another command: unmatched.
    17    The real response -> 15.
    18    Orphan response, nothing requested: unmatched.
    19    A second response to 15, already answered: unmatched.
    20    Broadcast Endpoint Discovery request (dst FFh).
    21/22 Responses from 0x42 and 0x30, both -> 20.
    23/24 Get EID request to the null EID (00h), its response -> 23.
    25/26 Discovery Notify datagram (D=1, not tracked), then a response
          to it: unmatched.
    27/28 Get Routing Table Entries request, then a response whose entries
          cover every binding layout: SMBus 01h (rsvd bit 0), I2C 05h
          (rsvd bit 1), PCIe 08h BDF, PCIe 0Eh, Flit 40h with segment,
          I3C 30h, I2C high-speed 06h (raw, no binding), PCIe 0Bh with
          a 1-byte address (size mismatch), and SMBus 02h with no address.
    29/30 Resolve UUID request, then a response with an I3C entry and a
          Flit 41h entry of the wrong size.
    31/32 Query Hop request; response with TUs 0x0000 (64 bytes) and
          0xffff (the largest).
    33/34 Get Version Support request; response whose alpha bytes are
          00h, 'A', 'z', 30h ('0', invalid) and 7Fh (invalid).
    35/36 Get EID request with IC set; its response still pairs.
    """
    H, E, D, B = HOST_EID, ENDPOINT_EID, DEV_EID, BCAST_EID
    get_eid = bytes([E]) + bytes([0x12, 0x00])
    uuid = bytes.fromhex('123456789abc4ef08122334455667788')

    def entry(range_size, start_eid, binding, media, addr):
        return bytes([range_size, start_eid, 0x00, binding, media,
                      len(addr)]) + addr

    routing = bytes([0xff, 9]) + b''.join((
        entry(1, 0x10, 0x01, 0x01, b'\x52'),
        entry(1, 0x11, 0x01, 0x05, b'\x53'),
        entry(1, 0x12, 0x02, 0x08, b'\x1b\x0a'),
        entry(1, 0x13, 0x02, 0x0e, b'\xff\xff'),
        entry(1, 0x14, 0x02, 0x40, b'\x01\x02\x1a'),
        entry(1, 0x15, 0x06, 0x30, b'\x10'),
        entry(1, 0x16, 0x01, 0x06, b'\x50'),
        entry(1, 0x17, 0x02, 0x0b, b'\x1b'),
        entry(1, 0x18, 0x01, 0x02, b''),
    ))
    resolve = bytes([0xff, 2]) + bytes([0x50, 0x06, 0x30, 1, 0x11]) + \
        bytes([0x51, 0x02, 0x41, 2, 0x01, 0x02])
    versions = bytes([5]) + b''.join(struct.pack('>I', v) for v in (
        0xF1F3F300, 0xF1F3F341, 0xF1F3F37A, 0xF1F3F330, 0xF1F3F37F))
    # SLL (16) and the MCTP header (4) precede the IC/message type byte.
    ic_request = bytearray(_tagged(H, E, 6, True, 0x02, 14))
    ic_request[20] |= 0x80
    return [
        _tagged(H, E, 1, True, 0x02, 1),
        _tagged(H, E, 2, True, 0x03, 2),
        _tagged(E, H, 2, False, 0x03, 2, uuid, cc=0),
        _tagged(E, H, 1, False, 0x02, 1, get_eid, cc=0),
        _tagged(H, E, 1, True, 0x02, 1),
        _tagged(E, H, 1, False, 0x02, 1, get_eid, cc=0),
        _tagged(H, E, 3, True, 0x02, 4),
        _tagged(H, D, 3, True, 0x02, 4),
        _tagged(D, H, 3, False, 0x02, 4, bytes([D, 0x12, 0x00]), cc=0),
        _tagged(E, H, 3, False, 0x02, 4, get_eid, cc=0),
        _tagged(H, E, 0, True, 0x05, 31),
        _tagged(E, H, 0, False, 0x05, 31, bytes([1, 0x04]), cc=0),
        _tagged(H, E, 0, True, 0x05, 0),
        _tagged(E, H, 0, False, 0x05, 0, cc=0x05),
        _tagged(H, E, 4, True, 0x02, 5),
        _tagged(E, H, 4, False, 0x03, 5, uuid, cc=0),
        _tagged(E, H, 4, False, 0x02, 5, get_eid, cc=0),
        _tagged(E, H, 5, False, 0x02, 6, get_eid, cc=0),
        _tagged(E, H, 4, False, 0x02, 5, get_eid, cc=0),
        _tagged(H, B, 6, True, 0x0C, 7),
        _tagged(E, H, 6, False, 0x0C, 7, cc=0),
        _tagged(D, H, 6, False, 0x0C, 7, cc=0),
        _tagged(H, 0x00, 7, True, 0x02, 8),
        _tagged(E, H, 7, False, 0x02, 8, get_eid, cc=0),
        _tagged(H, E, 0, True, 0x0D, 9, d=True),
        _tagged(E, H, 0, False, 0x0D, 9, cc=0),
        _tagged(H, E, 1, True, 0x0A, 10, b'\x00'),
        _tagged(E, H, 1, False, 0x0A, 10, routing, cc=0),
        _tagged(H, E, 2, True, 0x10, 11, uuid + b'\x00'),
        _tagged(E, H, 2, False, 0x10, 11, resolve, cc=0),
        _tagged(H, E, 3, True, 0x0F, 12, bytes([D, 0x04])),
        _tagged(E, H, 3, False, 0x0F, 12, bytes([0x50, 0x04, 0x00, 0x00, 0xff, 0xff]), cc=0),
        _tagged(H, E, 5, True, 0x04, 13, b'\x00'),
        _tagged(E, H, 5, False, 0x04, 13, versions, cc=0),
        bytes(ic_request),
        _tagged(E, H, 6, False, 0x02, 14, get_eid, cc=0),
    ]


def pairing_section():
    packets = _packets_pairing()
    assert len(packets) == 36
    return section(packets, BASE_TS_PAIRING_US, step_us=1000)


BASE_TS_SMBUS_PAIRING_US = 1713398400 * 1_000_000
SMBUS_HOST_ADDR = 0x10
SMBUS_DEV_A_ADDR = 0x1D
SMBUS_DEV_B_ADDR = 0x1E


def _smbus(dst_addr, src_addr, dst, src, tag, rq, cmd, iid, payload=b'', cc=None):
    """A DSP0237 SMBus block write with PEC carrying one control message;
    requests carry TO=1, responses TO=0."""
    body = ctrl_msg(cmd, iid, rq, False,
                    payload=(b'' if cc is None else bytes([cc])) + payload)
    mctp = bytes([0x01, dst, src, 0xC0 | (0x08 if rq else 0) | (tag & 7)]) + body
    record = bytes([dst_addr << 1, 0x0F, 1 + len(mctp),
                    (src_addr << 1) | 0x01]) + mctp
    return i2c_phdr() + record + bytes([smbus_pec(record)])


def _packets_smbus_pairing():
    """Pairing that needs the SMBus physical addresses, and invalid values.

    A null-EID request is routed by physical address alone (DSP0236
    Table 2), so concurrent ones to different targets pair by address; a
    broadcast request takes one response per responder.

    1/2   Get EID to the null EID at slaves 1Dh and 1Eh, same tag and IID.
    3/4   1Eh's response -> 2, then 1Dh's -> 1.
    5     1Dh answers again: unmatched.
    6     Broadcast Endpoint Discovery (dst FFh).
    7/8   Responses from 42h at 1Dh and 43h at 1Eh, both -> 6.
    9     42h at 1Dh answers again: unmatched.
    10/11 Query Hop with the reserved target EIDs 00h and FFh (Table 32).
    12    Routing Information Update with count 0 (Table 24, 1-based).
    13    Routing Information Update entry type 4, undefined (Table 25).
    """
    H, A, B = SMBUS_HOST_ADDR, SMBUS_DEV_A_ADDR, SMBUS_DEV_B_ADDR
    host = HOST_EID
    eid_a, eid_b = ENDPOINT_EID, ENDPOINT_EID + 1

    def get_eid(eid):
        return bytes([eid, 0x00, 0x00])

    return [
        _smbus(A, H, 0x00, host, 1, True, 0x02, 1),
        _smbus(B, H, 0x00, host, 1, True, 0x02, 1),
        _smbus(H, B, host, 0x00, 1, False, 0x02, 1, get_eid(0x00), cc=0),
        _smbus(H, A, host, 0x00, 1, False, 0x02, 1, get_eid(0x00), cc=0),
        _smbus(H, A, host, 0x00, 1, False, 0x02, 1, get_eid(0x00), cc=0),
        _smbus(A, H, BCAST_EID, host, 2, True, 0x0C, 2),
        _smbus(H, A, host, eid_a, 2, False, 0x0C, 2, cc=0),
        _smbus(H, B, host, eid_b, 2, False, 0x0C, 2, cc=0),
        _smbus(H, A, host, eid_a, 2, False, 0x0C, 2, cc=0),
        _smbus(A, H, eid_a, host, 3, True, 0x0F, 3, bytes([0x00, 0x04])),
        _smbus(A, H, eid_a, host, 4, True, 0x0F, 4, bytes([0xFF, 0x04])),
        _smbus(A, H, eid_a, host, 5, True, 0x09, 5, b'\x00'),
        _smbus(A, H, eid_a, host, 6, True, 0x09, 6,
               bytes([1, 0x04, 0x01, 0x50, 0x3A << 1])),
    ]


def smbus_pairing_section():
    packets = _packets_smbus_pairing()
    assert len(packets) == 13
    data = shb() + idb(DLT_LINUX_I2C)
    for i, packet in enumerate(packets):
        data += epb(packet, BASE_TS_SMBUS_PAIRING_US + i * 1000)
    return data


BASE_TS_EID_RANGES_US = 1713484800 * 1_000_000


def _packets_eid_ranges():
    """DSP0236 Table 2 reserves EIDs 01h-07h; Tables 14 and 23 assign them.

    1     Set EID op 0, EID 05h: reserved.
    2     Force EID op 1, EID 01h: reserved.
    3     Set EID op 0, EID 08h: the first assignable EID.
    4/5   Reset EID (op 2) and Set Discovered Flag (op 3) ignore the EID.
    6     Allocate op 0, 4 EIDs from 03h: the pool includes 03h-06h.
    7     Force allocation op 1, 2 EIDs from FEh: runs past FEh.
    8     Allocate op 0, 1 EID from FEh: exactly FEh.
    9     Allocate op 0, count 0 (legal) from 00h.
    10/11 Get allocation information (op 2) and op 3 ignore count and start.
    12    Allocate op 0, 4 EIDs from 08h.
    13/14 Allocate responses with first EID 00h (pool 4 and pool 0).
    15/16 Allocate responses with first EID 05h (reserved) and FFh.
    17    Set EID response, rejected, present setting 00h.
    18    Set EID response, accepted, setting 05h (the request is flagged).
    """
    def rq(cmd, iid, payload):
        return control_frame(DEV_EID, HOST_EID, True, True, False, cmd,
                             payload, iid)

    def rsp(cmd, iid, payload):
        return control_frame(HOST_EID, DEV_EID, False, False, False, cmd,
                             b'\x00' + payload, iid)

    return [
        rq(0x01, 1, b'\x00\x05'),
        rq(0x01, 2, b'\x01\x01'),
        rq(0x01, 3, b'\x00\x08'),
        rq(0x01, 4, b'\x02\x05'),
        rq(0x01, 5, b'\x03\x03'),
        rq(0x08, 6, b'\x00\x04\x03'),
        rq(0x08, 7, b'\x01\x02\xfe'),
        rq(0x08, 8, b'\x00\x01\xfe'),
        rq(0x08, 9, b'\x00\x00\x00'),
        rq(0x08, 10, b'\x02\x04\x03'),
        rq(0x08, 11, b'\x03\x04\x03'),
        rq(0x08, 12, b'\x00\x04\x08'),
        rsp(0x08, 9, b'\x00\x04\x00'),
        rsp(0x08, 10, b'\x00\x00\x00'),
        rsp(0x08, 6, b'\x00\x04\x05'),
        rsp(0x08, 7, b'\x00\x04\xff'),
        rsp(0x01, 3, b'\x10\x00\x00'),
        rsp(0x01, 1, b'\x00\x05\x00'),
    ]


def eid_ranges_section():
    packets = _packets_eid_ranges()
    assert len(packets) == 18
    return section(packets, BASE_TS_EID_RANGES_US, step_us=1000)


BASE_TS_SIZE_US = 1713571200 * 1_000_000


def _packets_size():
    """DSP0236 11.6: a control message payload is at most 64 bytes.

    1     Transport-specific command FFh, 65 payload bytes: one too many.
    """
    return [control_frame(DEV_EID, HOST_EID, True, True, False, 0xFF,
                          bytes(62))]


def size_section():
    packets = _packets_size()
    assert len(packets) == 1
    return section(packets, BASE_TS_SIZE_US, step_us=1000)


BASE_TS_GET_VERSION_US = 1713657600 * 1_000_000


def _packets_get_version():
    """DSP0236 Table 18: the Version Number Entry count is 1-based, except
    for the vendor-defined 7Eh/7Fh selectors.

    1/2   Selector 00h; success with count 0.
    3/4   Selector 00h; success with count 1 (1.3.3).
    5/6   Selector 7Eh; success with count 0.
    7/8   Selector 7Fh; success with count 0.
    9/10  Selector 00h; completion code 80h, no data.
    11    Unmatched success with count 0.
    """
    def rq(iid, selector):
        return control_frame(DEV_EID, HOST_EID, True, True, False, 0x04,
                             bytes([selector]), iid)

    def rsp(iid, payload):
        return control_frame(HOST_EID, DEV_EID, False, False, False, 0x04,
                             payload, iid)

    return [
        rq(1, 0x00), rsp(1, b'\x00\x00'),
        rq(2, 0x00), rsp(2, b'\x00\x01\xf1\xf3\xf3\x00'),
        rq(3, 0x7e), rsp(3, b'\x00\x00'),
        rq(4, 0x7f), rsp(4, b'\x00\x00'),
        rq(5, 0x00), rsp(5, b'\x80'),
        rsp(6, b'\x00\x00'),
    ]


def get_version_section():
    packets = _packets_get_version()
    assert len(packets) == 11
    return section(packets, BASE_TS_GET_VERSION_US, step_us=1000)


BASE_TS_RESPONSE_VALUES_US = 1713744000 * 1_000_000


def _packets_response_values():
    """Values a successful response reports.

    1     Get Message Type Support listing 00h and 04h: Table 19 counts
          types in addition to control, so 00h is invalid.
    2     Get Message Type Support listing 04h alone.
    3-8   Get EID responses with EID 00h (unassigned, Table 15), 01h, 07h,
          08h, FEh and FFh: Table 2 reserves 01h-07h, FFh is broadcast.
    9-14  Accepted Set EID responses with the same settings (Table 14).
    15    Rejected Set EID response, present setting 20h.
    16    Accepted Set EID response from 30h, setting 42h.
    17/18 Reset EID with EID FFh and Set Discovered Flag with EID 01h:
          the byte is ignored.
    """
    def rq(cmd, iid, payload):
        return control_frame(DEV_EID, HOST_EID, True, True, False, cmd,
                             payload, iid)

    def rsp(cmd, iid, payload):
        return control_frame(HOST_EID, DEV_EID, False, False, False, cmd,
                             b'\x00' + payload, iid)

    eids = (0x00, 0x01, 0x07, 0x08, 0xFE, 0xFF)
    return [
        rsp(0x05, 1, b'\x02\x00\x04'),
        rsp(0x05, 2, b'\x01\x04'),
        *[rsp(0x02, 3 + i, bytes([eid, 0x00, 0x00])) for i, eid in enumerate(eids)],
        *[rsp(0x01, 9 + i, bytes([0x00, eid, 0x00])) for i, eid in enumerate(eids)],
        rsp(0x01, 15, b'\x10\x20\x00'),
        rsp(0x01, 16, b'\x00\x42\x00'),
        rq(0x01, 17, b'\x02\xff'),
        rq(0x01, 18, b'\x03\x01'),
    ]


def response_values_section():
    packets = _packets_response_values()
    assert len(packets) == 18
    return section(packets, BASE_TS_RESPONSE_VALUES_US, step_us=1000)


def main():
    captures_dir = os.path.join(os.path.dirname(__file__), '..',
                                'test', 'captures')
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        captures_dir, 'mctp-control.pcapng')
    build_capture(out)

if __name__ == '__main__':
    main()
