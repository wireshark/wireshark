#!/usr/bin/env python3
# Helper module for the ansi_map capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic ANSI-41 MAP (over ANSI TCAP) captures for robustness checks.

Uses Exported PDU (linktype 252) with EXP_PDU_TAG_DISSECTOR_NAME = "ansi_tcap".
All data is synthetic.

Usage: ansi_map_gen.py <outdir>
"""
import struct
import sys
import os


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


def invoke(inv_id, opcode, params, last=True):
    body = tlv(PRI, 0, 15, bytes([inv_id]))
    body += tlv(PRI, 0, 17, struct.pack('>H', 0x0900 | opcode))
    if params is not None:
        body += tlv(PRI, 1, 18, params)
    return tlv(PRI, 1, 9 if last else 13, body)


def return_result(inv_id, params, last=True):
    body = tlv(PRI, 0, 15, bytes([inv_id]))
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


# ANSI-MAP parameters (context-specific, implicit)
def p_bearer(data):
    return tlv(CTX, 0, 105, data)


def p_teleid(v):
    return tlv(CTX, 0, 116, struct.pack('>H', v))


def p_service_ind(v):
    return tlv(CTX, 0, 193, bytes([v]))


# IS-637 bearer data: Message Identifier subparameter (id 0, len 3)
BEARER_SMALL = bytes([0x00, 0x03, 0x20, 0x01, 0x00])


def bearer_big(n):
    # many User Data-ish subparameters; just repeat Message Identifier
    return BEARER_SMALL * n


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'

    # 1. SMSDeliveryPointToPoint (53) with TeleserviceIdentifier 4098 (CMT-95)
    #    and bearer data -> ansi_637 should decode the bearer data.
    params = p_teleid(4098) + p_bearer(BEARER_SMALL)
    f1 = package(2, b'\x00\x00\x00\x01', [invoke(1, 53, params)])
    params = p_bearer(BEARER_SMALL) + p_teleid(4098)
    f2 = package(2, b'\x00\x00\x00\x02', [invoke(1, 53, params)])
    write_pcap(os.path.join(out, 'ansi_map_teleid.pcap'),
               [exp_pdu(f1), exp_pdu(f2)])

    # 2. Amplification: one bearer data, many repeated SMS-TeleserviceIdentifier
    #    / ServiceIndicator parameters. Each repeat re-dissects the bearer data.
    for name, nrep, nb in (('ansi_map_amplify_small.pcap', 10, 1000),
                           ('ansi_map_amplify.pcap', 4000, 6000)):
        bd = bearer_big(nb)
        params = p_bearer(bd) + p_teleid(4098) * nrep
        f = package(2, b'\x00\x00\x00\x03', [invoke(1, 53, params)])
        write_pcap(os.path.join(out, name), [exp_pdu(f)])
    for name, nrep, nb in (('ansi_map_amplify_si_small.pcap', 10, 1000),
                           ('ansi_map_amplify_si.pcap', 4000, 6000)):
        bd = bearer_big(nb)
        params = p_bearer(bd) + p_service_ind(4) * nrep
        f = package(2, b'\x00\x00\x00\x04', [invoke(1, 53, params)])
        write_pcap(os.path.join(out, name), [exp_pdu(f)])

    # 3. Stale OperationCode across packets for ReturnResult.
    #    frame1: invoke RegistrationNotification (13), TID 0xA, malformed params
    #            (exception in ansi_map before update_saved_invokedata)
    #    frame2: invoke SMSDeliveryPointToPoint (53), TID 0xB, fine
    #    frame3: returnResult for TID 0xA -> TCAP knows opcode 13, ANSI MAP
    #            uses the stale opcode (53) from frame2.
    bad = tlv(CTX, 0, 21, b'\x01')  # MSCID needs 3 octets -> bounds exception
    f1 = package(2, b'\x00\x00\x00\x0a', [invoke(1, 13, bad)])
    f2 = package(2, b'\x00\x00\x00\x0b', [invoke(1, 53, p_teleid(4098))])
    # RegistrationNotificationRes: [PRIVATE 18] SET { systemMyTypeCode [22] ...}
    res = tlv(CTX, 0, 22, b'\x01')
    f3 = package(4, b'\x00\x00\x00\x0a', [return_result(1, res)])
    write_pcap(os.path.join(out, 'ansi_map_stale_opcode.pcap'),
               [exp_pdu(f1), exp_pdu(f2), exp_pdu(f3)])

    # 4. Unidirectional (empty TID) with invoke + returnResult in one package:
    #    returnResult reaches ansi_map with TransactionID_str == NULL.
    f = package(1, b'', [invoke(1, 53, p_teleid(4098), last=False),
                         return_result(1, tlv(CTX, 0, 153, b'\x00'))])
    write_pcap(os.path.join(out, 'ansi_map_null_tid.pcap'), [exp_pdu(f)])

    # 5. Tap: unknown opcode (120) then known opcode (53) twice.
    f1 = package(2, b'\x00\x00\x00\x21', [invoke(1, 120, b'')])
    f2 = package(2, b'\x00\x00\x00\x22', [invoke(1, 53, p_teleid(4098))])
    f3 = package(2, b'\x00\x00\x00\x23', [invoke(1, 53, p_teleid(4098))])
    write_pcap(os.path.join(out, 'ansi_map_tap.pcap'),
               [exp_pdu(f2), exp_pdu(f1), exp_pdu(f3)])

    # 6. ReturnError: Info column uses the OperationCode of the previously
    #    dissected packet instead of the matched invoke.
    def return_error(inv_id, err, params):
        body = tlv(PRI, 0, 15, bytes([inv_id])) + tlv(PRI, 0, 20, bytes([err]))
        body += tlv(PRI, 1, 18, params)
        return tlv(PRI, 1, 11, body)
    f1 = package(2, b'\x00\x00\x00\x30', [invoke(1, 13, tlv(CTX, 0, 22, b'\x01'))])
    f2 = package(2, b'\x00\x00\x00\x31', [invoke(1, 53, p_teleid(4098))])
    f3 = package(4, b'\x00\x00\x00\x30', [return_error(1, 0x81, b'')])
    write_pcap(os.path.join(out, 'ansi_map_return_error.pcap'),
               [exp_pdu(f1), exp_pdu(f2), exp_pdu(f3)])

    # 7. 600 repeated ServiceIndicator / TeleserviceIdentifier parameters after
    #    one SMS-BearerData: every repeat re-dispatches the bearer data and adds
    #    a layer; after 500 layers DISSECTOR_ASSERT in call_dissector_work fires.
    params = p_bearer(BEARER_SMALL * 2) + p_service_ind(4) * 600
    f = package(2, b'\x00\x00\x00\x40', [invoke(1, 53, params)])
    write_pcap(os.path.join(out, 'ansi_map_layers_assert.pcap'), [exp_pdu(f)])
    params = p_bearer(BEARER_SMALL * 2) + p_teleid(4098) * 600
    f = package(2, b'\x00\x00\x00\x41', [invoke(1, 53, params)])
    write_pcap(os.path.join(out, 'ansi_map_layers_assert_teleid.pcap'), [exp_pdu(f)])


if __name__ == '__main__':
    main()
