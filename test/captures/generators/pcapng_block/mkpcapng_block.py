#!/usr/bin/env python3
# Generates test/captures/pcapng_block_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pcapng_block.c. usage: mkpcapng_block.py <outdir>
#
# The dissector is registered for the "wtap_fts_rec" table of the pcapng file
# type, which no pcapng record reaches in the tree today (the pcapng reader
# skips block types it has no handler for, and block types with handlers
# produce other record types). It is reachable through Exported PDU with the
# dissector name "pcapng". The block type it looks up is then read from the
# union member that holds the reported packet length of the frame, so the
# length of the Exported PDU frame selects the "block type". Frame lengths
# 516, 534 and 545 (the sysdig event block types) find no dissector either:
# packet-sysdig-event.c registers them only for Logray (event_reg_handoff).
import sys
from lib import epb, exp_pdu, gz, idb, shb, write_pcapng

out = sys.argv[1]

def frame(total_len, fill=0x55):
    '''An Exported PDU frame for "pcapng" that is total_len bytes long.'''
    hdr = exp_pdu('pcapng', b'')
    assert total_len >= len(hdr)
    return exp_pdu('pcapng', bytes([fill]) * (total_len - len(hdr)))

main = [shb(), idb(252)]
for n in (16, 17, 20, 33, 64, 100, 255, 256, 515, 516, 517, 534, 545, 1000):
    main.append(epb(frame(n)))
write_pcapng(out + '/pcapng_block-coverage.pcapng', main)

gz(out + '/pcapng_block-coverage.pcapng')
print('ok')
