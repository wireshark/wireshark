#!/usr/bin/env python3
# Helper module for the pkcs12 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# PKCS#12: PFX and AuthenticatedSafe replace the "ber.oid" entry for id-data
# (1.2.840.113549.1.7.1) with dissector_change_string() and restore it only
# after the body returns. Frame 1 (Exported PDU "cms", ContentInfo with
# contentType pkcs-9-at-PKCS12 -> PFX -> AuthenticatedSafe) has an
# AuthenticatedSafe whose only element is a lone tag byte, so the body throws
# after id-data was switched to SafeContents and the reset is skipped. Frame 2, an ordinary CMS id-data
# ContentInfo, is then dissected as PKCS#12 SafeContents (and so is every
# id-data in later packets and later files).
from s8ber import tlv, oid, exp_pdu, write_pcap

ID_DATA = '1.2.840.113549.1.7.1'
PFX_OID = '2.16.840.1.113730.3.1.216'

auth_safe = tlv(0x30, oid(ID_DATA) + tlv(0xa0, tlv(0x04, tlv(0x30, b'\x30'))))
pfx = tlv(0x30, b'\x02\x01\x03' + auth_safe)
p1 = tlv(0x30, oid(PFX_OID) + tlv(0xa0, pfx))
p2 = tlv(0x30, oid(ID_DATA) + tlv(0xa0, tlv(0x04, b'hello world')))
write_pcap('pkcs12_dtbl_leak.pcap', [exp_pdu('cms', p1), exp_pdu('cms', p2)])
