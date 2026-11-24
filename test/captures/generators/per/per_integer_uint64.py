#!/usr/bin/env python3
# Helper module for the per capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# PER: dissect_per_integer() adds FT_IS_UINT/FT_IS_INT fields with
# proto_tree_add_uint()/proto_tree_add_int(), which only accept 8..32-bit
# types. TETRA's TETRA-NETWORK-TIME/network-time (INTEGER(SIZE(24)), an
# unconstrained INTEGER for asn2wrs) has an FT_UINT64 field, so decoding it
# hits REPORT_DISSECTOR_BUG in proto_tree_add_uint().
# Frame: UDP 7074 (default TETRA port) tetra-UNITDATA-REQ, one SCH/F downlink
# MAC-RESOURCE -> SSI -> D-LLC bl-udata -> D-MLE mle -> D-NWRK-BROADCAST with
# tetra-network-time present.
import os
import sys
from s8net import udp_frame, Bits
from s8ber import write_pcap

b = Bits()
b.put(0, 2)        # MAC-RESOURCE pdu-type
b.put(0, 1)        # fill-bit-indication
b.put(0, 1)        # position-of-grant
b.put(0, 2)        # encryption-mode
b.put(0, 1)        # access-ack
b.put(20, 6)       # lengthIndication
b.put(1, 3)        # address: ssi
b.put(0x123456, 24)  # ssi
b.put(0, 1); b.put(0, 1); b.put(0, 1)  # power-control/slot-granting/channel-allocation: none
b.put(2, 4)        # D-LLC-PDU: bl-udata
b.put(5, 3)        # D-MLE-PDU: mle
b.put(2, 3)        # DMLE-PDU: d-nwrk-broadcast
b.put(2, 3)        # pdu-type
b.put(0x1234, 16)  # cell-re-select-parameters
b.put(1, 2)        # cell-service-level
b.put(1, 1)        # optional-elements: type2-parameters
b.put(1, 1)        # tetra-network-time present
b.put(3, 8)        # network-time: length determinant 3
b.put(0x0a0b0c, 24)
b.put(0, 1 + 6 + 6)  # sign, offset, year
b.put(1, 8); b.put(0, 8)  # reserved: length 1, value 0
b.put(0, 1)        # number-of-neighbour-cells: none
pdu = b.bytes(pad_to=34)  # SCH/F: 268 bits

txreg = (0 << 0) | (2 << 2)  # 1 channel, SCH/F
payload = bytes([1, 0]) + (0).to_bytes(4, 'little') + txreg.to_bytes(4, 'little') + pdu
FRAME = udp_frame(40000, 7074, payload)
if __name__ == "__main__":
    write_pcap("per_integer_uint64.pcap", [FRAME], linktype=1)
