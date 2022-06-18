# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_membership(unittest.TestCase):
    trace_file = "http.pcap"

    def test_membership_match_1(self, checkDFilterCount):
        dfilter = 'tcp.port in {80, 3267}'
        checkDFilterCount(dfilter, 1)

    def test_membership_match_2(self, checkDFilterCount):
        dfilter = 'tcp.port in {80,3267}'
        checkDFilterCount(dfilter, 1)

    def test_membership_match_3(self, checkDFilterCount):
        dfilter = 'tcp.port in {80 ,3267}'
        checkDFilterCount(dfilter, 1)

    def test_membership_match_4(self, checkDFilterCount):
        dfilter = 'tcp.port in {80 , 3267}'
        checkDFilterCount(dfilter, 1)

    def test_membership_match_5(self, checkDFilterCount):
        dfilter = 'tcp.port in {  80  ,  3267  }'
        checkDFilterCount(dfilter, 1)

    def test_membership_range_match_1(self, checkDFilterCount):
        dfilter = 'tcp.port in {80..81}'
        checkDFilterCount(dfilter, 1)

    def test_membership_range_match_2(self, checkDFilterCount):
        dfilter = 'tcp.port in {80 ..81}'
        checkDFilterCount(dfilter, 1)

    def test_membership_range_match_3(self, checkDFilterCount):
        dfilter = 'tcp.port in {80.. 81}'
        checkDFilterCount(dfilter, 1)

    def test_membership_range_match_4(self, checkDFilterCount):
        dfilter = 'tcp.port in {80 .. 81}'
        checkDFilterCount(dfilter, 1)

    def test_membership_3_range_no_match(self, checkDFilterCount):
        dfilter = 'tcp.dstport in {1 .. 79, 81 .. 65535}'
        checkDFilterCount(dfilter, 0)

    def test_membership_4_range_no_match_multiple(self, checkDFilterCount):
        # Verifies that multiple fields cannot satisfy different conditions.
        dfilter = 'tcp.port in {1 .. 79,81 .. 3266,3268 .. 65535}'
        checkDFilterCount(dfilter, 0)

    def test_membership_5_negative_range_float(self, checkDFilterCount):
        dfilter = 'frame.time_delta in {-2.0 .. 0.0}'
        checkDFilterCount(dfilter, 1)

    def test_membership_6_both_negative_range_float(self, checkDFilterCount):
        dfilter = 'frame.time_delta in {-20 .. -0.7}'
        checkDFilterCount(dfilter, 0)

    def test_membership_7_string(self, checkDFilterCount):
        dfilter = 'http.request.method in {"GET", "HEAD"}'
        checkDFilterCount(dfilter, 1)

    def test_membership_8_ip_range(self, checkDFilterCount):
        dfilter = 'ip.addr in { 10.0.0.5 .. 10.0.0.9 , 10.0.0.1..10.0.0.1 }'
        checkDFilterCount(dfilter, 1)

    def test_membership_9_range_invalid_float(self, checkDFilterFail):
        # expression should be parsed as "0.1 .. .7"
        # .7 is the identifier (protocol) named "7"
        dfilter = 'frame.time_delta in {0.1...7}'
        error = 'not a valid protocol or protocol field'
        checkDFilterFail(dfilter, error)

    def test_membership_10_bad_lhs_number(self, checkDFilterFail):
        dfilter = '123 in {ip}'
        error = 'Only a field may be tested for membership in a set.'
        checkDFilterFail(dfilter, error)

    def test_membership_11_bad_rhs_string(self, checkDFilterFail):
        dfilter = 'frame.number in {1, "foo"}'
        error = 'Unsigned integer (4 bytes) cannot be converted from a string'
        checkDFilterFail(dfilter, error)

    def test_membership_12_value_string(self, checkDFilterCount):
        dfilter = 'tcp.checksum.status in {"Unverified", "Good"}'
        checkDFilterCount(dfilter, 1)
