#!/usr/bin/env python3
# Helper module for the ansi_tcap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic ANSI TCAP captures for robustness checks of packet-ansi_tcap.c.

Exported PDU (linktype 252), EXP_PDU_TAG_DISSECTOR_NAME = "ansi_tcap".
All data is synthetic.

Usage: ansi_tcap_gen.py <outdir>
"""
import os
import struct
import sys


def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tag(cls, cons, num):
    first = (cls << 6) | (0x20 if cons else 0)
    if num < 31:
        return bytes([first | num])
    out = [num & 0x7f]
    num >>= 7
    while num:
        out.append(0x80 | (num & 0x7f))
        num >>= 7
    return bytes([first | 0x1f]) + bytes(reversed(out))


CTX, PRI = 2, 3


def tlv(cls, cons, num, content):
    return tag(cls, cons, num) + blen(len(content)) + content


def invoke(inv_id, opcode_private, params, last=True):
    body = tlv(PRI, 0, 15, bytes([inv_id & 0xff]))
    body += tlv(PRI, 0, 17, struct.pack('>H', opcode_private))
    if params is not None:
        body += tlv(PRI, 1, 18, params)
    return tlv(PRI, 1, 9 if last else 13, body)


def invoke_national(inv_id, opcode, params, last=True):
    body = tlv(PRI, 0, 15, bytes([inv_id & 0xff]))
    body += tlv(PRI, 0, 16, struct.pack('>H', opcode))
    if params is not None:
        body += params
    return tlv(PRI, 1, 9 if last else 13, body)


def return_result(inv_id, params, last=True):
    body = tlv(PRI, 0, 15, bytes([inv_id & 0xff]))
    if params is not None:
        body += tlv(PRI, 1, 18, params)
    return tlv(PRI, 1, 10 if last else 14, body)


def package(ptype, tid, comps):
    body = tlv(PRI, 0, 7, tid) + tlv(PRI, 1, 8, b''.join(comps))
    return tlv(PRI, 1, ptype, body)


def exp_pdu(payload, dissector='ansi_tcap'):
    name = dissector.encode()
    pad = (-len(name)) % 4
    hdr = struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad
    hdr += struct.pack('>HH', 0, 0)
    return hdr + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'

    # 1. Layer limit: one package with N ANSI MAP invoke components.
    #    Each component calls ansi_map through call_dissector_with_data(),
    #    which adds a layer that stays, until saved_layers_len reaches
    #    gui_max_tree_depth (500) and DISSECTOR_ASSERT() fires.
    teleid = tlv(CTX, 0, 116, struct.pack('>H', 4098))
    for name, n in (('ansi_tcap_many_components.pcap', 600),
                    ('ansi_tcap_many_components_ok.pcap', 400)):
        comps = [invoke(i, 0x0900 | 53, teleid, last=(i == n - 1))
                 for i in range(n)]
        write_pcap(os.path.join(out, name),
                   [exp_pdu(package(2, b'\x00\x00\x00\x01', comps))])

    # 1b. Same with AIN private opcodes (family 0x6x) and with national
    #     opcodes for LNP (0x0301), which go through dissector_try_uint().
    comps = [invoke(i, 0x6101, b'', last=(i == 599)) for i in range(600)]
    write_pcap(os.path.join(out, 'ansi_tcap_many_components_ain.pcap'),
               [exp_pdu(package(2, b'\x00\x00\x00\x02', comps))])
    comps = [invoke_national(i, 0x8301, tlv(PRI, 1, 18, b''),
                             last=(i == 599)) for i in range(600)]
    write_pcap(os.path.join(out, 'ansi_tcap_many_components_lnp.pcap'),
               [exp_pdu(package(2, b'\x00\x00\x00\x03', comps))])

    # 2. Same-frame matching: invoke A (opcode 53), returnResult,
    #    invoke B (opcode 13) all in one package with one TID.  Pass 1
    #    matches the ReturnResult to A (only A is in the table yet), pass 2
    #    matches it to B (insert32 for the same frame replaced A).
    comps = [invoke(1, 0x0900 | 53, teleid, last=False),
             return_result(1, b'', last=False),
             invoke(2, 0x0900 | 13, b'', last=True)]
    write_pcap(os.path.join(out, 'ansi_tcap_same_frame_match.pcap'),
               [exp_pdu(package(4, b'\x00\x00\x00\x10', comps))])

    # 3. Odd transaction IDs: 8 octets, 300 octets (uint8_t length
    #    truncates to 44), 256 octets (truncates to 0).
    comps = [invoke(1, 0x0900 | 53, teleid)]
    frames = []
    for tid in (bytes(range(8)), bytes(300), bytes(256), b'\x01\x02\x03'):
        frames.append(exp_pdu(package(2, tid, comps)))
    write_pcap(os.path.join(out, 'ansi_tcap_tid_lengths.pcap'), frames)

    # 4. National opcode without a registered dissector: the template
    #    parses the parameter set [PRIVATE 18] (0xf2) with parameter_type().
    #    Parameter values claiming long lengths (generic name 255 chars,
    #    digits 255) near the end of the tvb.
    psets = [
        bytes([0xf2, 0xff]) + bytes([0x8a, 0x00, 0x05]) + b'\x01' * 8,
        bytes([0xf2, 0x10]) + bytes([0x8f, 0x8f, 0x00, 0xff]) + b'\x02',
        bytes([0xf2, 0x7f]) + (bytes([0x81, 0x00, 0x02, 0xff, 0xff]) * 30),
    ]
    frames = []
    for i, ps in enumerate(psets):
        comps = [invoke_national(1, 0x8105, ps)]
        frames.append(exp_pdu(package(2, struct.pack('>I', 0x20 + i), comps)))
    write_pcap(os.path.join(out, 'ansi_tcap_national_params.pcap'), frames)


if __name__ == '__main__':
    main()
