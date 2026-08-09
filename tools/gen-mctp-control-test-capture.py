#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a pcapng test capture for the MCTP Control Protocol dissector
(epan/dissectors/packet-mctp-control.c) command-specific payload decode.

Produces test/captures/mctp-control.pcapng (27 frames), exercising the
per-command payload layouts of DSP0236 1.3.3 clause 12:

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
        0x00, 0x04 (NVMe-MI), 0x05 (SPDM), 0x7E (Table 19)
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

# ---------------------------------------------------------------------------
# pcapng helpers
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

def idb(link_type=113, snaplen=65535):
    body = struct.pack('<HHI', link_type, 0, snaplen)
    return _block(0x00000001, body)

def epb(packet_bytes, ts_us):
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low = ts_us & 0xFFFFFFFF
    caplen = len(packet_bytes)
    padded = packet_bytes + b'\x00' * (_pad4(caplen) - caplen)
    body = struct.pack('<IIIII', 0, ts_high, ts_low, caplen, caplen) + padded
    return _block(0x00000006, body)

# ---------------------------------------------------------------------------
# Linux SLL cooked capture header (16 bytes, DLT_LINUX_SLL = 113)
# ---------------------------------------------------------------------------

LINUX_SLL_P_MCTP = 0x00FA

def sll_header(src_eid):
    return struct.pack('>HHH8sH', 0, 0, 1,
                       bytes([src_eid]) + b'\x00' * 7, LINUX_SLL_P_MCTP)

# ---------------------------------------------------------------------------
# MCTP transport header (4 bytes): ver, dst EID, src EID, SOM|EOM|seq|TO|tag
# ---------------------------------------------------------------------------

BUS_OWNER_EID = 0x0A
ENDPOINT_EID  = 0x42

def mctp_header(is_request):
    src = BUS_OWNER_EID if is_request else ENDPOINT_EID
    dst = ENDPOINT_EID if is_request else BUS_OWNER_EID
    fst = 0xC8 if is_request else 0xC0   # SOM|EOM, seq 0, TO on request, tag 0
    return bytes([0x01, dst, src, fst])

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

def frame(is_request, body):
    src = BUS_OWNER_EID if is_request else ENDPOINT_EID
    return sll_header(src) + mctp_header(is_request) + body

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
    # 14: response: count 4; list = control, NVMe-MI, SPDM, Vendor PCI
    frames.append(frame(False, ctrl_response(0x05, 7,
                        payload=bytes([4, 0x00, 0x04, 0x05, 0x7E]))))

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

    with open(path, 'wb') as f:
        f.write(shb())
        f.write(idb())
        for i, pkt in enumerate(frames):
            f.write(epb(pkt, 1000000 + i * 1000))

    print('wrote {} ({} frames)'.format(path, len(frames)))

def main():
    captures_dir = os.path.join(os.path.dirname(__file__), '..',
                                'test', 'captures')
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        captures_dir, 'mctp-control.pcapng')
    build_capture(out)

if __name__ == '__main__':
    main()
