#!/usr/bin/env python3
# Generates test/captures/pkixtsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for packet-pkixtsp.c: mkpkixtsp.py <outdir>. Exported PDU frames
(link type 252) built with the DER helpers of pkixlib.py; frames.py has the
frame sets of all PKIX dissectors, this directory uses `pkixtsp`.
Nothing comes from a real network; made-up keys, zero signatures."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from pkixlib import write_pcap
import frames

out = sys.argv[1] if len(sys.argv) > 1 else '.'
main, bad = frames.pkixtsp()
write_pcap(os.path.join(out, 'pkixtsp-coverage.pcap'), main)
write_pcap(os.path.join(out, 'pkixtsp-coverage-malformed.pcap'), bad)
