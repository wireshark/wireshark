#!/usr/bin/env python3
# Generates test/captures/pkix1explicit_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for packet-pkix1explicit.c: mkpkix1explicit.py <outdir>. Exported PDU frames
(link type 252) built with the DER helpers of pkixlib.py; frames.py has the
frame sets of all PKIX dissectors, this directory uses `pkix1explicit`.
Nothing comes from a real network; made-up keys, zero signatures."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from pkixlib import write_pcap
import frames

out = sys.argv[1] if len(sys.argv) > 1 else '.'
main, bad = frames.pkix1explicit()
write_pcap(os.path.join(out, 'pkix1explicit-coverage.pcap'), main)
write_pcap(os.path.join(out, 'pkix1explicit-coverage-malformed.pcap'), bad)
