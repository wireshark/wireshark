# Helper module for the awdl capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# AWDL HT Capabilities TLV (7) whose first Rx MCS byte is 0: streams==0 is used
# as the item length for FT_UINT32 hf_awdl_mcsset_rx_bitmask_0to7 -> "Trying to
# fetch an unsigned integer with length 0" exception, rest of the frame lost.
import sys; sys.path.insert(0,'.')
from awdl_common import action, pcap, tlv
pcap('awdl_ht_streams0.pcap',[action(tlv(7,b'\x00\x00'+b'\x2c\x01'+b'\x17'+b'\x00\xff\x00\x00'+b'\x00\x00')+tlv(21,b'\x3e\x01'))])
