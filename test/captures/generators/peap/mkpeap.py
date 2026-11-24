#!/usr/bin/env python3
# Generates test/captures/peap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-peap.c. usage: mkpeap.py <outdir>
#
# PEAP is only called by the EAP dissector as the application data dissector
# of the TLS dissector, i.e. for decrypted TLS records of an EAP-PEAP
# exchange. Decryption needs the TLS keys (and ciphertext), which this
# capture does not have (see README.md). The only frames that reach the
# dissector are Exported PDU frames that name it: there is no EAP layer, so
# it returns 0.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from lib import epb, exp_pdu, gz, idb, shb, write_pcapng

out = sys.argv[1]

main = [shb(), idb(252)]
for data in (b'\x01\x00\x00\x05\x01', b'', b'\x01\x02\x03\x04\x05\x06\x07\x08', bytes(range(64))):
    main.append(epb(exp_pdu('peap', data)))
write_pcapng(out + '/peap-coverage.pcapng', main)
gz(out + '/peap-coverage.pcapng')
print('ok')
