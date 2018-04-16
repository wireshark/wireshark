# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testMembership(dftest.DFTest):
    trace_file = "http.pcap"

    def test_membership_1_match(self):
        dfilter = 'tcp.port in {80 3267}'
        self.assertDFilterCount(dfilter, 1)

    def test_membership_2_range_match(self):
        dfilter = 'tcp.port in {80..81}'
        self.assertDFilterCount(dfilter, 1)

    def test_membership_3_range_no_match(self):
        dfilter = 'tcp.dstport in {1 .. 79 81 .. 65535}'
        self.assertDFilterCount(dfilter, 0)

    def test_membership_4_range_no_match_multiple(self):
        # Verifies that multiple fields cannot satisfy different conditions.
        dfilter = 'tcp.port in {1 .. 79 81 .. 3266 3268 .. 65535}'
        self.assertDFilterCount(dfilter, 0)

    def test_membership_5_negative_range_float(self):
        dfilter = 'frame.time_delta in {-2.0 .. 0.0}'
        self.assertDFilterCount(dfilter, 1)

    def test_membership_6_both_negative_range_float(self):
        dfilter = 'frame.time_delta in {-20 .. -.7}'
        self.assertDFilterCount(dfilter, 0)

    def test_membership_7_string(self):
        dfilter = 'http.request.method in {"GET" "HEAD"}'
        self.assertDFilterCount(dfilter, 1)

    def test_membership_8_ip_range(self):
        dfilter = 'ip.addr in { 10.0.0.5 .. 10.0.0.9 10.0.0.1..10.0.0.1 }'
        self.assertDFilterCount(dfilter, 1)

    def test_membership_9_range_weird_float(self):
        # expression should be parsed as "0.1 .. .7"
        dfilter = 'frame.time_delta in {0.1...7}'
        self.assertDFilterCount(dfilter, 0)
