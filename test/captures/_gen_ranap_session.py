#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate ranap_session.pcap: a synthetic Iu-PS SCCP connection with RANAP
# (SCCP over M3UA over SCTP) and the GTP-U of its RAB, for the IMSI of the
# SCCP connection (sccp.trace_sccp) and GTP session tracking
# (gtp.track_gtp_session). The IMSI and addresses are made up.
#
#   1  RNC -> SGSN   SCCP Connection Request to SSN 142 (RANAP)
#   2  SGSN -> RNC   SCCP Connection Confirm
#   3  SGSN -> RNC   RANAP Common ID with the IMSI
#   4  SGSN -> RNC   RANAP RAB Assignment Request: SGSN TEID
#   5  RNC -> SGSN   RANAP RAB Assignment Response: RNC TEID
#   6  RNC -> SGSN   GTP-U T-PDU to the SGSN TEID (frame 4)
#   7  SGSN -> RNC   GTP-U T-PDU to the RNC TEID (frame 5)

import struct
import sys

M3UA_PORT = 2905
GTPU_PORT = 2152

RNC = (10, 0, 6, 1)
SGSN = (10, 0, 6, 2)
RNC_PC = 101
SGSN_PC = 102

RNC_LR = 0x000101
SGSN_LR = 0x000201

IMSI = '001010000000006'

SGSN_TEID = 0x5101
RNC_TEID = 0x6101

SSN_RANAP = 142


class Aper:
    '''A minimal writer of ALIGNED PER bits.'''

    def __init__(self):
        self.bits = []

    def put(self, value, width):
        self.bits += [(value >> (width - 1 - i)) & 1 for i in range(width)]

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def octets(self, data):
        self.align()
        for octet in data:
            self.put(octet, 8)

    def bytes(self):
        self.align()
        return bytes(int(''.join(map(str, self.bits[i:i + 8])), 2)
                     for i in range(0, len(self.bits), 8))


def open_type(value):
    # Aligned length determinant (< 128) and the value
    return bytes((len(value),)) + value


def criticality(crit):
    return bytes((crit << 6,))  # 2 bits, then the open type aligns


REJECT, IGNORE = 0, 1


def protocol_ie_field(ie_id, crit, value):
    return struct.pack('!H', ie_id) + criticality(crit) + open_type(value)


def protocol_ie_container(*fields):
    return struct.pack('!H', len(fields)) + b''.join(fields)


def message(*fields):
    # SEQUENCE { protocolIEs, protocolExtensions OPTIONAL, ... }: extension
    # bit and the optional bit, then the container
    return b'\x00' + protocol_ie_container(*fields)


def ranap_pdu(choice, procedure_code, crit, value):
    # CHOICE of 4 with extension: 3 bits, then the aligned procedure code
    return bytes((choice << 5, procedure_code)) + criticality(crit) + open_type(value)


INITIATING_MESSAGE, OUTCOME = 0, 3
ID_RAB_ASSIGNMENT = 0
ID_COMMON_ID = 15
ID_PERMANENT_NAS_UE_ID = 23
ID_RAB_SETUP_OR_MODIFIED_ITEM = 51
ID_RAB_SETUP_OR_MODIFIED_LIST = 52
ID_RAB_SETUP_OR_MODIFY_ITEM = 53
ID_RAB_SETUP_OR_MODIFY_LIST = 54


def tbcd(digits):
    if len(digits) % 2:
        digits += 'f'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16)
                 for i in range(0, len(digits), 2))


def permanent_nas_ue_id(imsi):
    value = tbcd(imsi)
    w = Aper()
    w.put(0, 1)                     # CHOICE extension bit
    w.put(len(value) - 3, 3)        # IMSI SIZE (3..8)
    w.octets(value)
    return w.bytes()


def transport_layer_address(w, ipv4):
    w.put(0, 1)                     # SIZE extension bit
    w.put(32 - 1, 8)                # SIZE (1..160)
    w.octets(bytes(ipv4))


def iu_transport_association(w, teid):
    w.put(0, 1)                     # CHOICE extension bit
    w.put(0, 1)                     # gTP-TEI
    w.octets(struct.pack('!I', teid))


def rab_setup_or_modify_item_first(rab_id, ipv4, teid):
    w = Aper()
    w.put(0, 1)                     # extension bit
    w.put(0b000100, 6)              # transportLayerInformation present
    w.put(rab_id, 8)                # rAB-ID
    w.put(0, 1)                     # TransportLayerInformation extension bit
    w.put(0, 1)                     # no iE-Extensions
    transport_layer_address(w, ipv4)
    iu_transport_association(w, teid)
    return w.bytes()


def rab_setup_or_modified_item(rab_id, ipv4, teid):
    w = Aper()
    w.put(0, 1)                     # extension bit
    w.put(0b1100, 4)                # transportLayerAddress, iuTransportAssociation
    w.put(rab_id, 8)                # rAB-ID
    transport_layer_address(w, ipv4)
    iu_transport_association(w, teid)
    return w.bytes()


def common_id(imsi):
    return ranap_pdu(INITIATING_MESSAGE, ID_COMMON_ID, IGNORE, message(
        protocol_ie_field(ID_PERMANENT_NAS_UE_ID, IGNORE, permanent_nas_ue_id(imsi))))


def rab_assignment_request(rab_id, ipv4, teid):
    first = rab_setup_or_modify_item_first(rab_id, ipv4, teid)
    second = b'\x00'                # RAB-SetupOrModifyItemSecond, all absent
    pair = struct.pack('!H', ID_RAB_SETUP_OR_MODIFY_ITEM) + \
        criticality(REJECT) + open_type(first) + criticality(IGNORE) + open_type(second)
    # SIZE (1..maxNrOfRABs) list of containers of one pair
    rab_list = b'\x00' + protocol_ie_container(pair)
    return ranap_pdu(INITIATING_MESSAGE, ID_RAB_ASSIGNMENT, REJECT, message(
        protocol_ie_field(ID_RAB_SETUP_OR_MODIFY_LIST, IGNORE, rab_list)))


def rab_assignment_response(rab_id, ipv4, teid):
    item = protocol_ie_field(ID_RAB_SETUP_OR_MODIFIED_ITEM, IGNORE,
                             rab_setup_or_modified_item(rab_id, ipv4, teid))
    rab_list = b'\x00' + protocol_ie_container(item)
    return ranap_pdu(OUTCOME, ID_RAB_ASSIGNMENT, REJECT, message(
        protocol_ie_field(ID_RAB_SETUP_OR_MODIFIED_LIST, IGNORE, rab_list)))


def lr(value):
    return struct.pack('<I', value)[:3]


def sccp_cr(slr):
    called = bytes((0x42, SSN_RANAP))  # route on SSN, SSN present
    # Protocol class 2, pointer to the called party, no optional part
    return b'\x01' + lr(slr) + b'\x02' + b'\x02\x00' + bytes((len(called),)) + called


def sccp_cc(dlr, slr):
    return b'\x02' + lr(dlr) + lr(slr) + b'\x02' + b'\x00'


def sccp_dt1(dlr, data):
    return b'\x06' + lr(dlr) + b'\x00' + b'\x01' + bytes((len(data),)) + data


def pad4(data):
    return data + bytes(-len(data) % 4)


def m3ua_data(opc, dpc, sccp):
    # Protocol Data: OPC, DPC, SI 3 (SCCP), NI 2 (national), MP, SLS
    param = struct.pack('!IIBBBB', opc, dpc, 3, 2, 0, 0) + sccp
    param = struct.pack('!HH', 0x0210, 4 + len(param)) + param
    body = pad4(param)
    return struct.pack('!BBBBI', 1, 0, 1, 1, 8 + len(body)) + body


def sctp(vtag, tsn, payload):
    # DATA chunk, B and E, stream 0, PPID 3 (M3UA); the checksum is not checked
    chunk = struct.pack('!BBHIHHI', 0, 0x03, 16 + len(payload), tsn, 0, tsn, 3) + payload
    return struct.pack('!HHII', M3UA_PORT, M3UA_PORT, vtag, 0) + pad4(chunk)


def gtpu_tpdu(teid):
    # An IPv4 packet with protocol 253 (for experimentation) as the T-PDU
    tpdu = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 24, 0, 0x4000, 64, 253, 0,
                       bytes((192, 168, 0, 1)), bytes((192, 168, 0, 2))) + bytes(4)
    return struct.pack('!BBHI', 0x30, 0xff, len(tpdu), teid) + tpdu


def udp(port, payload):
    return struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload


def frame(src, dst, proto, payload):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                     bytes(src), bytes(dst))
    return eth + ip + payload


def iu(tsn, from_rnc, sccp):
    # Each direction has its own verification tag and TSNs
    if from_rnc:
        return frame(RNC, SGSN, 132, sctp(0x1001, 0x1000 + tsn, m3ua_data(RNC_PC, SGSN_PC, sccp)))
    return frame(SGSN, RNC, 132, sctp(0x2001, 0x2000 + tsn, m3ua_data(SGSN_PC, RNC_PC, sccp)))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'ranap_session.pcap'
    frames = [
        iu(1, True, sccp_cr(RNC_LR)),
        iu(1, False, sccp_cc(RNC_LR, SGSN_LR)),
        iu(2, False, sccp_dt1(RNC_LR, common_id(IMSI))),
        iu(3, False, sccp_dt1(RNC_LR, rab_assignment_request(5, SGSN, SGSN_TEID))),
        iu(2, True, sccp_dt1(SGSN_LR, rab_assignment_response(5, RNC, RNC_TEID))),
        frame(RNC, SGSN, 17, udp(GTPU_PORT, gtpu_tpdu(SGSN_TEID))),
        frame(SGSN, RNC, 17, udp(GTPU_PORT, gtpu_tpdu(RNC_TEID))),
    ]
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, rec in enumerate(frames):
            f.write(struct.pack('!IIII', i, 0, len(rec), len(rec)))
            f.write(rec)


if __name__ == '__main__':
    main()
