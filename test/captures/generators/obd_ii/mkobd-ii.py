#!/usr/bin/env python3
# Generates test/captures/obd_ii_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic OBD-II coverage captures.  Usage: mkobd-ii.py <outdir>

obd-ii-coverage.pcap     SocketCAN (linktype 227): ISO-TP carried OBD-II on
                         CAN IDs 0x7DF/0x7E0-0x7E7 and extended IDs, then
                         raw (no ISO-TP PCI) OBD frames for the CAN heuristic.
obd-ii-coverage-malformed.pcap
                         frames only malformed or rejected input reaches.
Built with struct only."""
import struct
import sys
import os

SFF_QUERY = 0x7DF
EFF = 0x80000000
RTR = 0x40000000
ERR = 0x20000000
EFF_QUERY = 0x18DB33F1

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 227))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def can(can_id, data, eff=False, fd=False, flags=0, dlc=None, pad=True):
    """SocketCAN frame: id (BE, with EFF flag), length, fd flags, 2 reserved,
    data padded to 8 bytes (classic) or to the given length (FD)."""
    cid = can_id | (EFF if eff else 0) | flags
    n = len(data) if dlc is None else dlc
    body = data
    if fd:
        body = data + bytes(max(0, 12 - len(data)))
        n = len(body) if dlc is None else dlc
        return struct.pack('>IBBBB', cid, n, 0x04, 0, 0) + body
    if pad:
        body = data + bytes(max(0, 8 - len(data)))
    return struct.pack('>IBBBB', cid, n, 0, 0, 0) + body

def sf(payload, size=8):
    """ISO-TP single frame, zero padded."""
    return bytes([len(payload)]) + payload + bytes(max(0, size - 1 - len(payload)))

F = []
def add(fr): F.append(fr)

VALS = bytes([0x12, 0x34, 0x56, 0x78, 0x9A])

# (pid, number of value bytes the dissector expects) for mode 01
M1 = [(0x00, 4), (0x20, 4), (0x40, 4), (0x60, 4), (0x80, 4), (0xA0, 4), (0xC0, 4),
      (0x03, 2), (0x04, 1), (0x05, 1), (0x06, 1), (0x07, 1), (0x08, 1), (0x09, 1), (0x0A, 1), (0x0B, 1),
      (0x0C, 2), (0x0D, 1), (0x0E, 1), (0x0F, 1), (0x10, 2), (0x11, 1), (0x12, 1), (0x13, 1)]
M1 += [(p, 2) for p in range(0x14, 0x1C)]
M1 += [(0x1C, 1), (0x1D, 1), (0x1F, 2), (0x21, 2), (0x22, 2), (0x23, 2)]
M1 += [(p, 4) for p in range(0x24, 0x2C)]
M1 += [(0x2C, 1), (0x2D, 1), (0x2E, 1), (0x2F, 1), (0x30, 1), (0x31, 2), (0x32, 2), (0x33, 1)]
M1 += [(p, 4) for p in range(0x34, 0x3C)]
M1 += [(p, 2) for p in range(0x3C, 0x40)]
M1 += [(0x42, 2), (0x43, 2), (0x44, 2), (0x45, 1), (0x46, 1), (0x47, 1), (0x48, 1), (0x49, 1), (0x4A, 1),
       (0x4B, 1), (0x4C, 1), (0x4D, 2), (0x4E, 2), (0x51, 1), (0x52, 1), (0x53, 2)]
M1 += [(p, 2) for p in range(0x55, 0x59)]
M1 += [(0x59, 2), (0x5A, 1), (0x5B, 1), (0x5C, 1), (0x5D, 2), (0x5E, 2), (0x61, 1), (0x62, 1), (0x63, 2)]
# not decoded by the dissector: shown as raw bytes
M1_RAW = [0x01, 0x02, 0x1E, 0x41, 0x4F, 0x50, 0x54, 0x5F, 0x64, 0x7F, 0x87, 0xFF]

def resp(pid, n, rid=0x7E8, eff=False, mode=0x41):
    return can(rid, sf(bytes([mode, pid]) + VALS[:n]), eff)

# ---- queries (0x7DF), mode 01 with one and two byte PIDs, 04, 07, 09, unknown
for pid in (0x00, 0x0C, 0x0D, 0x05, 0x99):
    add(can(EFF_QUERY, sf(bytes([0x01, pid])), eff=True))
add(can(EFF_QUERY, sf(bytes([0x01, 0x01, 0x02])), eff=True))                 # two byte PID
add(can(EFF_QUERY, sf(bytes([0x04])), eff=True))                             # mode 04
add(can(EFF_QUERY, sf(bytes([0x07])), eff=True))                             # mode 07
for pid in (0x00, 0x02, 0x0A, 0x7F):
    add(can(EFF_QUERY, sf(bytes([0x09, pid])), eff=True))
add(can(EFF_QUERY, sf(bytes([0x09, 0x02, 0x00])), eff=True))
for mode in (0x02, 0x03, 0x05, 0x06, 0x08, 0x0A):
    add(can(EFF_QUERY, sf(bytes([mode, 0x00])), eff=True))
add(can(EFF_QUERY, sf(bytes([0x01])), eff=True))                            # mode 01 without PID: not OBD-II
add(can(EFF_QUERY, sf(bytes([0x0B, 0x00])), eff=True))                      # mode > 0x0A
add(can(EFF_QUERY, sf(bytes([0x01, 0x00, 0x00, 0x00])), eff=True))          # four byte payload
add(can(EFF_QUERY, sf(bytes([0x01, 0x0C]), size=5), eff=True, dlc=5))       # not 8 bytes: padding warning

# ---- every mode 01 PID, right length, at the lower and upper response ids
for i, (pid, n) in enumerate(M1):
    add(resp(pid, n, rid=0x7E0 + (i % 8)))
for pid in M1_RAW:
    add(resp(pid, 3, rid=0x7E1))
# ---- wrong lengths: the value is shown raw
for i, (pid, n) in enumerate(M1):
    w = n + 1 if n < 5 else n - 1
    add(resp(pid, w, rid=0x7E2 + (i % 4)))
add(can(0x7E3, sf(bytes([0x41, 0x0C]))))                          # no value bytes
add(can(0x7E3, sf(bytes([0x41]))))                                # one byte: rejected
add(can(0x7E3, sf(bytes([0x41, 0x0C, 1, 2, 3, 4, 5]), size=8)))
# ---- mode 03/04/07/09 responses
add(can(0x7E4, sf(bytes([0x43, 0x01, 0x33, 0x00, 0x00]))))
add(can(0x7E4, sf(bytes([0x44]))))                                # clear DTC: one byte allowed
add(can(0x7E4, sf(bytes([0x44, 0x00]))))
for k in range(0, 6):
    add(can(0x7E4, sf(bytes([0x47]) + bytes(range(1, 2 + k)))))      # mode 07 with 1..6 raw bytes
add(can(0x7E5, sf(bytes([0x47, 0x01]), size=3), dlc=3))
add(can(0x7E5, sf(bytes([0x49, 0x00, 0xBE, 0x1F, 0xA8, 0x13]))))
add(can(0x7E5, sf(bytes([0x49, 0x02, 0x01, 0x41, 0x42, 0x43]))))     # VIN single frame
add(can(0x7E5, sf(bytes([0x49, 0x0A, 0x01, 0x45, 0x43, 0x4D]))))     # ECU name single frame
for pid in (0x04, 0x06, 0x08, 0x0B, 0x7F):
    add(can(0x7E5, sf(bytes([0x49, pid, 1, 2, 3]))))
# multi frame VIN and ECU name (First Frame, Flow Control, Consecutive Frames)
vin = bytes([0x49, 0x02, 0x01]) + b'TESTVIN0123456789'
add(can(0x7E0, bytes([0x10, len(vin)]) + vin[:6]))
add(can(EFF_QUERY, bytes([0x30, 0, 0, 0, 0, 0, 0, 0]), eff=True))
add(can(0x7E0, bytes([0x21]) + vin[6:13]))
add(can(0x7E0, bytes([0x22]) + vin[13:20]))
ecu = bytes([0x49, 0x0A, 0x01]) + b'ECM-Engine' + bytes(10)
add(can(0x7E8 - 8 + 2, bytes([0x10, len(ecu)]) + ecu[:6]))          # 0x7E2
add(can(0x7E8 - 8 + 2, bytes([0x21]) + ecu[6:13]))
add(can(0x7E8 - 8 + 2, bytes([0x22]) + ecu[13:20]))
add(can(0x7E8 - 8 + 2, bytes([0x23]) + ecu[20:23]))
# ---- ID checks: not an OBD-II ID, mode < 0x40 on a response ID, and the
# reproducer frames of "OBD-II: Do not pass a can_info_t as an
# iso15765_info_t" (IDs 0x7DF, 0x001, 0x7E8, data 02 01 0C)
add(can(0x7DE, sf(bytes([0x01, 0x0C]))))
add(can(0x7E4, sf(bytes([0x01, 0x0C]))))
add(can(0x7E4, sf(bytes([0x30, 0x0C]))))
# ---- extended identifiers
for rid in (0x18DA10F1, 0x18DA11F1):
    add(can(rid, sf(bytes([0x41, 0x0C, 0x1A, 0xF8])), eff=True))
    add(can(rid, sf(bytes([0x49, 0x02, 0x01, 0x58, 0x59, 0x5A])), eff=True))
add(can(0x18DC1234, sf(bytes([0x41, 0x0C, 0x1A, 0xF8])), eff=True))   # not an OBD-II ID
# ---- CAN FD
add(can(EFF_QUERY, sf(bytes([0x01, 0x0C]), size=12), eff=True, fd=True))
add(can(0x7E2, sf(bytes([0x41, 0x0C, 0x1A, 0xF8]), size=12), fd=True))
add(can(0x18DA10F1, sf(bytes([0x41, 0x05, 0x7B]), size=16), eff=True, fd=True))
# ---- flags: remote request and error frames are not OBD-II
add(can(0x7E2, b'', flags=RTR, dlc=0, pad=False)[:8] + bytes(8))
add(can(0x7E2, sf(bytes([0x41, 0x0C, 0x1A, 0xF8])), flags=ERR))
N_ISO = len(F)

# ---- reproducer frames of the CAN heuristic fix: IDs 0x7DF, 0x001, 0x7E8
for cid in (0x7DF, 0x001, 0x7E8):
    add(struct.pack('>IB3x', cid, 8) + bytes([0x02, 0x01, 0x0C, 0, 0, 0, 0, 0]))
N_REPRO = len(F)
# ---- raw OBD-II (no ISO-TP PCI byte) for the CAN heuristic, upper response
# range and the extended query/response patterns not in the ISO-TP ID lists
add(can(0x7DF, bytes([0x01, 0x0C]), dlc=2))                           # query, not 8 bytes: padding warning
add(can(0x7DF, bytes([0x09, 0x02]), dlc=2))
add(can(0x7DF, bytes([0x01, 0x00, 0x00]), dlc=3))                    # two byte PID
add(can(0x7DF, bytes([0x04]), dlc=1))
add(can(0x7E8, bytes([0x41, 0x0C, 0x1A, 0xF8]), dlc=4))
add(can(0x7E9, bytes([0x41, 0x0D, 0x37]), dlc=3))
add(can(0x7EF, bytes([0x49, 0x02, 0x01, 0x41, 0x42, 0x43]), dlc=6))
add(can(0x7E8, bytes([0x44]), dlc=1))
add(can(0x7E8, bytes([0x47, 0x01, 0x02]), dlc=3))
add(can(EFF_QUERY, bytes([0x01, 0x05]), eff=True, dlc=2))
add(can(0x18DAF110, bytes([0x41, 0x05, 0x6E]), eff=True, dlc=3))      # upper extended range
add(can(0x18DA12F1, bytes([0x41, 0x05, 0x6E]), eff=True, dlc=3))      # lower extended range
add(can(0x18DAF1FF, bytes([0x41, 0x0C, 1, 2]), eff=True, dlc=4))
add(can(0x7E8, bytes([0x30, 0x01]), dlc=2))                           # response id, mode below 0x40
add(can(0x7E8, bytes([0x41]), dlc=1))                                 # one byte response
add(can(0x7DF, bytes([0x20, 0x01]), dlc=2))                           # mode above 0x0a
add(can(0x7DF, bytes([0x01, 0x0C, 0x00, 0x00, 0x00]), dlc=5))         # five byte query
add(can(0x123, bytes([0x41, 0x0C, 1, 2]), dlc=4))                     # not an OBD-II ID
add(can(0x7DF, bytes([0x01, 0x0C, 0, 0, 0, 0]), flags=RTR, dlc=2))    # remote frame
add(can(0x7E8, bytes([0x41, 0x0C, 0x1A, 0xF8]), fd=True, dlc=12))     # CAN FD on the heuristic
add(can(0x7DF, bytes([0x01, 0x0C]), fd=True, dlc=12))

write_pcap(os.path.join(sys.argv[1], 'obd-ii-coverage.pcap'), F)
print(len(F), 'frames;', N_ISO, 'ISO-TP frames,', N_REPRO - N_ISO, 'reproducer frames')

# ---------------------------------------------------------------- malformed
F = []
# ISO-TP frames with a short or inconsistent payload and truncated frames
add(can(0x7E8, sf(bytes([0x41, 0x0C, 0x1A, 0xF8]))[:3] + b'', dlc=3, pad=False))
add(can(0x7E8, bytes([0x07, 0x41, 0x0C, 0x1A]), dlc=4, pad=False))        # SF length 7, 3 bytes
add(can(0x7DF, bytes([0x03, 0x01, 0x0C]), dlc=3, pad=False))               # SF length 3, 2 bytes
add(can(0x7E8, bytes([0x10, 0x14, 0x49, 0x02, 0x01, 0x41, 0x42, 0x43])))  # first frame never completed
add(can(0x7E8, bytes([0x21, 1, 2, 3, 4, 5, 6, 7])))                         # consecutive frame, wrong sequence
add(can(0x7E8, bytes([0x10, 0x04, 0x41, 0x0C, 0x1A, 0xF8, 0, 0])))          # first frame shorter than 8
add(can(0x7E8, sf(bytes([0x49, 0x02]))))                                    # VIN without a count/chars
add(can(0x7E8, sf(bytes([0x49, 0x0A]))))                                    # ECU name without chars
add(can(0x7E8, sf(bytes([0x49, 0x02, 0x01]))))                              # one value byte: no VIN chars
add(can(0x7E8, sf(bytes([0x49, 0x0A, 0x01]))))
add(can(0x7E8, sf(bytes([0x41, 0x0C, 0x1A, 0xF8])) , dlc=0, pad=False))     # zero length
write_pcap(os.path.join(sys.argv[1], 'obd-ii-coverage-malformed.pcap'), F)
print(len(F), 'frames in the malformed capture')
