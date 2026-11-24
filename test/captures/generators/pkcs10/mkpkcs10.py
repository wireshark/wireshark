#!/usr/bin/env python3
# Generates test/captures/pkcs10_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for packet-pkcs10.c: mkpkcs10.py <outdir>. Exported PDU frames
(link type 252) built with the DER helpers of pkixlib.py; frames.py has the
frame sets of all PKIX dissectors, this directory uses `pkcs10`.
Nothing comes from a real network; made-up keys, zero signatures."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from pkixlib import write_pcap
import frames

out = sys.argv[1] if len(sys.argv) > 1 else '.'
main, bad = frames.pkcs10()
write_pcap(os.path.join(out, 'pkcs10-coverage.pcap'), main)
write_pcap(os.path.join(out, 'pkcs10-coverage-malformed.pcap'), bad)
