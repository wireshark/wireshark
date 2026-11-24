#!/usr/bin/env python3
# Generates test/captures/oampdu_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic OAMPDU coverage captures.  Usage: mkoampdu.py <outdir>

oampdu-coverage.pcap            Ethernet Slow Protocols (0x8809, subtype 3):
                                information, event notification, variable
                                request/response, loopback control and the
                                CableLabs DPoE vendor specific PDUs
oampdu-coverage-malformed.pcap  input only error paths reach
Built with struct only."""
import struct
import sys
import os

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def oam(flags, code, body=b'', src=1):
    """Ethernet frame: Slow Protocols address, ethertype 0x8809, subtype 3 (OAM)."""
    return (bytes.fromhex('0180c2000002') + bytes([0x02, 0, 0, 0, 0, src]) + struct.pack('>H', 0x8809) +
            bytes([0x03]) + struct.pack('>H', flags) + bytes([code]) + body)

CL = bytes([0x00, 0x10, 0x00])      # CableLabs OUI
F = []
def add(*a, **k): F.append(oam(*a, **k))

# ---------------------------------------------------------------- Information
def info_tlv(typ, state=0x00, config=0x00, rev=0x0001, oui=bytes([0x00, 0x1c, 0x2e]), vendor=b'\1\2\3\4'):
    return (bytes([typ, 16, 1]) + struct.pack('>H', rev) + bytes([state, config]) + struct.pack('>H', 1500) +
            oui + vendor)

def org_tlv(data, oui=bytes([0x00, 0x10, 0x00])):
    return bytes([0xFE, 5 + len(data)]) + oui + data

add(0x0050, 0x00, info_tlv(1, state=0x00, config=0x1f) + info_tlv(2, state=0x03, config=0x0e) + bytes([0]))
add(0x0000, 0x00, info_tlv(1, state=0x01, config=0x01) + info_tlv(2, state=0x01, config=0x01) + bytes([0]))
add(0x0007, 0x00, info_tlv(1, state=0x02, config=0x02) + info_tlv(2, state=0x02, config=0x02))
add(0x007f, 0x00, info_tlv(1, state=0x01, config=0x05) + org_tlv(b'vendor data') + org_tlv(b'') + bytes([0]))
add(0x0018, 0x00, bytes([0x05, 0x06, 1, 2, 3, 4]) + info_tlv(2) + bytes([0]))      # unknown type skipped
add(0x0020, 0x00, bytes([0]))
add(0x0020, 0x00)                                                                  # no TLVs at all
add(0x0040, 0x00, info_tlv(1, rev=0xffff, oui=bytes([0xff, 0xff, 0xff]), vendor=b'\xff' * 4))

# ---------------------------------------------------------------- Event notification
def ev_header(seq=1): return struct.pack('>H', seq)
def espe(): return bytes([1, 40]) + struct.pack('>H', 100) + struct.pack('>QQQQ', 1000, 10, 11, 22) + struct.pack('>I', 3)
def efe():  return bytes([2, 26]) + struct.pack('>H', 100) + struct.pack('>HIIQI', 1000, 1, 2, 33, 4)
def efpe(): return bytes([3, 28]) + struct.pack('>H', 100) + struct.pack('>IIIQI', 1000, 5, 6, 44, 7)
def efsse():return bytes([4, 18]) + struct.pack('>H', 100) + struct.pack('>HHHII', 60, 5, 6, 77, 8)
def ose_cl(evt, raised, obj_type, inst):
    val = inst
    return bytes([0xFE, 2 + 3 + 1 + 1 + 2 + len(val)]) + CL + bytes([evt, raised]) + struct.pack('>H', obj_type) + val
add(0x0004, 0x01, ev_header(1) + espe() + bytes([0]))
add(0x0004, 0x01, ev_header(2) + efe() + efpe() + efsse() + bytes([0]))
add(0x0004, 0x01, ev_header(3) + espe() + efe() + efpe() + efsse())
# DPoE events: only the first one of a PDU is decoded (the offset is not advanced past it)
add(0x0002, 0x01, ev_header(4) + ose_cl(0x07, 1, 0x0000, b'\x00\x01') + ose_cl(0x08, 0, 0x0004, b'\x01\x02\x03\x04') + bytes([0]))
add(0x0002, 0x01, ev_header(4) + ose_cl(0x08, 0, 0x0400, b'\x05\x06\x07\x08') + bytes([0]))
add(0x0002, 0x01, ev_header(4) + ose_cl(0x01, 1, 0x0002, b'\x00\x02') + bytes([0]))
add(0x0002, 0x01, ev_header(4) + espe() + ose_cl(0x02, 1, 0x0003, b'\x00\x03') + bytes([0]))
add(0x0002, 0x01, ev_header(5) + bytes([0xFE, 8, 0x00, 0x0c, 0x29, 1, 2, 3]) + bytes([0]))                   # other OUI: skipped
add(0x0002, 0x01, ev_header(7) + bytes([0x77, 0]))                                                         # unknown event type
add(0x0002, 0x01, ev_header(0xffff))

# ---------------------------------------------------------------- Variable request / response
def leaf16(branch, leaf): return bytes([branch]) + struct.pack('>H', leaf)
add(0x0050, 0x02, leaf16(3, 0x0015) + leaf16(4, 0x0001) + leaf16(6, 0x0002) + leaf16(7, 0x0003) + leaf16(5, 0x0004) + bytes([0]))
add(0x0050, 0x02, bytes([0]))
# responses: object/package lists of width+value ending in an indication, binding/attribute with one entry
add(0x0050, 0x03, leaf16(3, 0x0015) + bytes([4]) + b'\x00\x00\x01\x02' + bytes([2]) + b'\xaa\xbb' + bytes([0x81]) + bytes([0]))
add(0x0050, 0x03, leaf16(4, 0x0001) + bytes([1, 0x55, 0x80 | 5]) + leaf16(7, 0x0003) + bytes([0xA0]) + leaf16(6, 0x0002) + bytes([3]) + b'\1\2\3' +
    leaf16(7, 0x0010) + bytes([1, 9]) + bytes([0]))
add(0x0050, 0x03, leaf16(7, 0x0004) + bytes([0]) + b'\x5a' * 128 + bytes([0]))                      # width 0 means 128
add(0x0050, 0x03, leaf16(5, 0x0004) + bytes([0x82]) + bytes([0]))                                   # unknown branch
add(0x0050, 0x03, bytes([0]))

# ---------------------------------------------------------------- Loopback control
add(0x0050, 0x04, bytes([0x01]))
add(0x0050, 0x04, bytes([0x02]))
add(0x0050, 0x04, bytes([0x03]))
add(0x0050, 0x04, bytes([0x00]))
add(0x0050, 0x04)

# ---------------------------------------------------------------- Vendor specific, not CableLabs / too short
add(0x0050, 0xFE, bytes([0x00, 0x0c, 0x29, 0x01, 0x02, 0x03]))
add(0x0050, 0xFE, bytes([0x00, 0x10]))
add(0x0050, 0xFE)
add(0x0050, 0x77, b'unknown code')                                                                   # reserved OAMPDU code

# ---------------------------------------------------------------- DPoE
def leaf(lb, data): return struct.pack('>I', lb)[1:] + bytes([len(data)]) + data
def leafrc(lb, code): return struct.pack('>I', lb)[1:] + bytes([code])
def dpoe(op, body, flags=0x0050): add(flags, 0xFE, CL + bytes([op]) + body)

# Get-Request: plain descriptors, object descriptors with and without instances
dpoe(0x01, bytes.fromhex('D70002') + bytes.fromhex('D70003') + bytes.fromhex('D70004') + bytes([0]))
dpoe(0x01, leaf(0xD60000, b'') + leaf(0xD60001, b'\x01') + leaf(0xD60002, b'\x05') + leaf(0xD60003, b'\x02') +
     leaf(0xD60004, bytes.fromhex('00040102')) + leaf(0xD60006, b'\x09') + leaf(0xD60004, b'\x01\x02') +
     leaf(0xD60002, b'\x01\x02\x03') + bytes([0]))
dpoe(0x00, b'\x00')
for op in (0x05, 0x06, 0x07, 0x08, 0x55):
    dpoe(op, b'\x01\x02\x03')

# Get-Response with every leaf
R = []
R.append(leaf(0xD70002, bytes.fromhex('001c2e010203')))
R.append(leaf(0xD70003, struct.pack('>HIHI', 0x0102, 0xdeadbeef, 0x0304, 0xcafef00d)))
R.append(leaf(0xD70004, struct.pack('>HI', 0x1234, 0x0000abcd) + b'\0\0\0\1'[:0]))   # jedec + model; version overlaps
R.append(leaf(0xD70005, bytes.fromhex('20261108')))                                   # BCD date
R.append(leaf(0xD70005, bytes.fromhex('1419010a')))                                   # year as two decimal bytes
R.append(leaf(0xD70005, struct.pack('>HBB', 2026, 11, 8)))                            # year as a 16 bit number
R.append(leaf(0xD70005, bytes.fromhex('3000090c')))                                   # no valid year
R.append(leaf(0xD70005, bytes.fromhex('202f0108')))                                   # BCD year with a 0xF nibble: 'Unknown'
R.append(leaf(0xD70006, b'SERIAL0123456789'))                                         # at most 32 bytes: no vendor data
R.append(leaf(0xD70006, b'S' * 32))
R.append(leaf(0xD70006, b'S' * 32 + b'vendor specific'))
R.append(leaf(0xD70007, struct.pack('>HH', 8, 4)))
R.append(leaf(0xD70008, b'\x04'))
R.append(leaf(0xD70009, struct.pack('>H', 2)))
R.append(leaf(0xD7000A, bytes([8, 4, 1, 8, 4, 1]) + struct.pack('>HHH', 1000, 500, 400)))
R.append(leaf(0xD7000C, b'\x01'))
R.append(leaf(0xD7000D, bytes([1, 10])))
R.append(leaf(0xD7000E, b'Example Manufacturing'))
R.append(leaf(0xD7000F, b'20261108120000' [:13] + b'20261109130000'[:13]))
R.append(leaf(0xD70010, b'\x01'))                                                     # S1 port type: generic value
R.append(leaf(0xD70011, b'Vendor Inc'))
R.append(leaf(0xD70012, b'Model-1'))
R.append(leaf(0xD70013, b'HW 1.0'))
R.append(leaf(0xD70014, b'\x02'))                                                     # EPON mode: generic value
R.append(leaf(0xD70015, b'bundle-1.2.3\0\0\0'))
R.append(leaf(0xD70105, struct.pack('>H', 0x01ff)))
R.append(leaf(0xD70303, bytes([1, 1, 2, 0, 3, 1])))
R.append(leaf(0xD70402, b'\x02'))
R.append(leaf(0xD70403, b'\x01'))
R.append(leaf(0xD60003, b'\x02'))
R.append(leaf(0xD60004, bytes.fromhex('00040102')))
R.append(leaf(0xD7010E, b'firmware.bin\0\0\0\0'))
R.append(leaf(0xD70114, b'\x24'))
R.append(leaf(0xD70115, b'\x02' + struct.pack('>II', 1024, 2048)))
R.append(leaf(0x07001A, b'\x01'))
R.append(leaf(0x07001D, bytes.fromhex('001c2e0a0b0c')))
R.append(leaf(0x070020, b'\x03'))
R.append(leaf(0x070047, b'\x04'))
R.append(leaf(0x07004F, struct.pack('>I', 2)))
R.append(leaf(0x07005A, b'\x03'))
R.append(leaf(0x07005D, struct.pack('>H', 0x0003)))
R.append(leaf(0xD90107, bytes([0, 0x12, 0x34])))                                      # multicast LLID actions
R.append(leaf(0xD90107, bytes([1, 0x56, 0x78])))
R.append(leaf(0xD90107, bytes([2, 0x00, 0x00])))
R.append(leaf(0xD7FFFF, b'unknown leaf'))
R.append(leafrc(0xD70002, 0x80) + leafrc(0xD70003, 0xA0))                              # response codes
R.append(leaf(0xD7000B, b'\x00\x00'))                                                  # empty report threshold
# Leaves with a nested layout (alarm list, 1904.1 queue config) advance the offset twice, so zero
# padding follows every leaf
for r in R:
    dpoe(0x02, r + b'\x00' * 16)
# several leaves in one PDU
dpoe(0x02, b''.join(R[:6]) + b'\x00')
dpoe(0x02, leaf(0xD70011, b'A') + leaf(0xD70012, b'\x00'.join([b'B'] * 1)) + leafrc(0xD70013, 0x81) + b'\x00')
# value of 128 bytes (length 0)
dpoe(0x02, bytes.fromhex('D70099') + bytes([0]) + bytes(range(128)) + b'\x00')

# Queue configuration (nested counts), with n=2 upstream links and p=2 downstream ports
qc = bytes([2, 2, 10, 20, 3, 30, 31, 32, 2, 2, 40, 41, 1, 50])
dpoe(0x02, leaf(0xD7010D, qc) + b'\x00')
dpoe(0x02, leaf(0xD7010D, bytes([0, 0])) + b'\x00')
dpoe(0x03, leaf(0xD7010D, qc) + b'\x00')

# Port ingress rule: terminator, header, clause (match value of 2 and of 0 bytes), results
def pir(sub, *rest): return leaf(0xD70501, bytes([sub]) + bytes(rest))
dpoe(0x03, pir(0) + pir(1, 5) + pir(2, 1, 2, 3, 4, 5, 2, 0xAA, 0xBB) + pir(2, 1, 2, 3, 4, 5, 0) + b'\x00')
for rr in range(0, 13):
    extra = {3: bytes([0, 4, 1, 2]), 4: bytes([7, 8, 9, 10, 11]), 5: bytes([0, 0, 1, 2, 3, 4]),
             6: bytes([0, 1]), 7: bytes([0, 2]), 8: bytes([0, 3]), 9: bytes([0, 4]), 10: bytes([0, 5]), 11: bytes([0, 6])}.get(rr, b'')
    dpoe(0x03, pir(3, rr, *extra) + b'\x00')
dpoe(0x03, pir(3, 4, 7, 8) + b'\x00')                                                   # set output field without a value
dpoe(0x03, pir(9, 1, 2) + b'\x00')                                                      # unknown subtype

# Report threshold: set-request with entries, bounded by the container
dpoe(0x03, leaf(0xD7000B, bytes([2, 3]) + b''.join(struct.pack('>H', v) for v in range(1, 7))) + b'\x00')
dpoe(0x03, leaf(0xD7000B, bytes([1, 1, 0x01, 0x02])) + b'\x00')
dpoe(0x03, leaf(0xD7000B, bytes([4, 4]) + b''.join(struct.pack('>H', v) for v in range(1, 6))) + b'\x00')   # 16 entries announced, 5 fit
dpoe(0x03, leaf(0xD7000B, bytes([255, 255]) + b'\x00\x07' * 3) + b'\x00')
dpoe(0x03, leaf(0xD7000B, b'\x02') + b'\x00')                                           # one byte only: no entries
# Reproducer of "OAMPDU: Bound the DPoE report threshold loop by its container": 6 byte containers with
# nqs = rvpqs = 255 and no room for entries, repeated to the end of the frame
dpoe(0x03, bytes([0xD7, 0x00, 0x0B, 0x02, 0xFF, 0xFF]) * 60 + b'\x00' * 8)
# a full size frame of them
body = bytes([0xD7, 0x00, 0x0B, 0x02, 0xFF, 0xFF]) * 200
dpoe(0x03, body + b'\x00' * 8)

# Set-Request / Set-Response / ONU vendor leaves
dpoe(0x03, leaf(0xD7000C, b'\x01') + leaf(0xD70402, b'\x02') + leaf(0xD7010E, b'upgrade.img\0') + b'\x00')
dpoe(0x04, leafrc(0xD7000C, 0x80) + leafrc(0xD70402, 0x81) + leafrc(0xD70105, 0xA3) + b'\x00')
dpoe(0x04, leaf(0xD70105, struct.pack('>H', 0x0003)) + b'\x00')

# File transfer: write request, data block, ack, unknown opcode
dpoe(0x09, bytes([1]) + b'dpoe-image-1.bin\0')
dpoe(0x09, bytes([2]) + struct.pack('>HH', 7, 4) + b'data')
dpoe(0x09, bytes([3]) + struct.pack('>H', 7) + bytes([0]))
dpoe(0x09, bytes([4, 1, 2, 3]))

write_pcap(os.path.join(sys.argv[1], 'oampdu-coverage.pcap'), F)
print(len(F), 'frames')

# ---------------------------------------------------------------- malformed
F = []
add(0x0002, 0x01, ev_header(1) + bytes([0xFE, 1, 0xaa]) + bytes([0]))                 # event length below 2 (error expert info)
add(0x0002, 0x01, ev_header(1) + bytes([0xFE, 0]) + bytes([0]))
add(0x0002, 0x01, ev_header(5) + bytes([0xFE, 2]) + bytes([0]))                          # length 2, OUI past the end
add(0x0002, 0x01, ev_header(6) + bytes([0xFE, 5, 0x00, 0x10, 0x00, 1, 2]) + bytes([0]))  # CL OUI with a short event
add(0x0002, 0x01, b'\x00')                                                            # no sequence number
add(0x0002, 0x01, ev_header(1) + espe()[:20])                                         # truncated event
add(0x0002, 0x01, ev_header(1) + bytes([0xFE, 8, 0x00, 0x10, 0x00, 1]))               # CL event cut short
add(0x0050, 0x00, info_tlv(1)[:8])                                                    # truncated information TLV
add(0x0050, 0x00, bytes([0xFE, 4, 0, 0x10, 0x00]))                                    # organization TLV shorter than 5
add(0x0050, 0x00, bytes([0xFE, 20, 0, 0x10, 0x00, 1]))                                # organization data past the end
add(0x0050, 0x02, leaf16(3, 0x0015))                                                  # request without terminator
add(0x0050, 0x02, bytes([3, 0x00]))                                                   # request cut short
add(0x0050, 0x03, leaf16(3, 0x0015) + bytes([4, 1]))                                  # response value past the end
add(0x0050, 0x03, leaf16(7, 0x0015))                                                  # response without value
add(0x0050, 0x03, leaf16(7, 0x0015) + bytes([0]) + b'\x01' * 20)                      # width 0 (128) past the end
add(0x0050, 0x03)                                                                     # response with nothing
add(0x0050, 0x02)
add(0x0050, 0xFE, CL)                                                                 # DPoE without an opcode
dpoe(0x01, bytes.fromhex('D70002'))                                                   # get-request without terminator
dpoe(0x01, bytes.fromhex('D6000301'))
dpoe(0x01, bytes.fromhex('D60004') + bytes([4, 0, 4]))                                # queue instance cut short
dpoe(0x02, bytes.fromhex('D70003') + bytes([12]) + b'\1\2')                            # fixed layout longer than the container
dpoe(0x02, leaf(0xD70002, b'\1'))
dpoe(0x02, bytes.fromhex('D70005') + bytes([2]) + b'\x20')                            # date cut short
dpoe(0x02, bytes.fromhex('D70006') + bytes([40]) + b'S' * 10)                         # serial number past the end
dpoe(0x02, leaf(0xD70006, b'S' * 33) + b'\x00')                                       # one byte of vendor data
dpoe(0x02, bytes.fromhex('D7000A') + bytes([12]) + b'\1\2\3')                         # packet buffer cut short
dpoe(0x02, bytes.fromhex('D7000F') + bytes([26]) + b'abc')                            # time varying controls cut short
dpoe(0x03, bytes.fromhex('D7000B') + bytes([2]) + bytes([4, 4]) + b'\0')              # report threshold cut short
dpoe(0x03, bytes.fromhex('D7000B') + bytes([6]) + bytes([2, 2, 0, 1]))
dpoe(0x03, bytes.fromhex('D7010D') + bytes([5]) + bytes([9, 9, 1]))                   # queue config counts past the end
dpoe(0x03, bytes.fromhex('D70501') + bytes([3]) + bytes([2, 1, 2]))                   # ingress clause cut short
dpoe(0x03, bytes.fromhex('D70501') + bytes([9]) + bytes([2, 1, 2, 3, 4, 5, 9, 1, 2])) # match value past the end
dpoe(0x03, bytes.fromhex('D70501') + bytes([3]) + bytes([3, 5, 0, 0]))                # result cut short
dpoe(0x03, bytes.fromhex('D70115') + bytes([3]) + bytes([5, 0, 0]))                   # 1904.1 queue config cut short
dpoe(0x02, bytes.fromhex('D70008') + bytes([3]) + b'\1\2\3')                          # three byte integer for a 16 bit field
dpoe(0x09, bytes([1]) + b'name-without-terminator')                                   # file name without terminator
dpoe(0x09, bytes([2]) + b'\0')                                                        # data block cut short
dpoe(0x09, bytes([3]))
dpoe(0x09, b'')
dpoe(0x02, bytes.fromhex('D90107') + bytes([2]) + bytes([0, 1]))                      # multicast LLID cut short
dpoe(0x02, bytes.fromhex('07001D') + bytes([2]) + b'\1\2')
dpoe(0x02, bytes.fromhex('D70303') + bytes([3]) + b'\1\2\3')                          # alarm list with an odd length
dpoe(0x02, leaf(0xD70303, bytes([1, 1, 2, 0, 3, 1])) + b'\x00')                      # offset advanced twice: next byte past the end
dpoe(0x02, leaf(0xD70115, b'\x02' + struct.pack('>II', 1, 2)) + b'\x00')
add(0x0050, 0xFE, CL[:2])
add(0x0050, 0x00, bytes([1]))
write_pcap(os.path.join(sys.argv[1], 'oampdu-coverage-malformed.pcap'), F)
print(len(F), 'frames in the malformed capture')
