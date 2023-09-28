#
# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterString:
    trace_file = "http.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = 'http.request.method == "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = 'http.request.method == "POST"'
        checkDFilterCount(dfilter, 0)

    def test_gt_1(self, checkDFilterCount):
        dfilter = 'http.request.method > "HEAC"'
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = 'http.request.method > "HEAD"'
        checkDFilterCount(dfilter, 0)

    def test_gt_3(self, checkDFilterCount):
        dfilter = 'http.request.method > "HEAE"'
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = 'http.request.method >= "HEAC"'
        checkDFilterCount(dfilter, 1)

    def test_ge_2(self, checkDFilterCount):
        dfilter = 'http.request.method >= "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = 'http.request.method >= "HEAE"'
        checkDFilterCount(dfilter, 0)

    def test_lt_1(self, checkDFilterCount):
        dfilter = 'http.request.method < "HEAC"'
        checkDFilterCount(dfilter, 0)

    def test_lt_2(self, checkDFilterCount):
        dfilter = 'http.request.method < "HEAD"'
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = 'http.request.method < "HEAE"'
        checkDFilterCount(dfilter, 1)

    def test_le_1(self, checkDFilterCount):
        dfilter = 'http.request.method <= "HEAC"'
        checkDFilterCount(dfilter, 0)

    def test_le_2(self, checkDFilterCount):
        dfilter = 'http.request.method <= "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = 'http.request.method <= "HEAE"'
        checkDFilterCount(dfilter, 1)

    def test_slice_1(self, checkDFilterCount):
        dfilter = 'http.request.method[0] == "H"'
        checkDFilterCount(dfilter, 1)

    def test_slice_2(self, checkDFilterCount):
        dfilter = 'http.request.method[0] == "P"'
        checkDFilterCount(dfilter, 0)

    def test_slice_3(self, checkDFilterCount):
        dfilter = 'http.request.method[0:4] == "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_slice_4(self, checkDFilterCount):
        dfilter = 'http.request.method[0:4] != "HEAD"'
        checkDFilterCount(dfilter, 0)

    def test_slice_5(self, checkDFilterCount):
        dfilter = 'http.request.method[1:2] == "EA"'
        checkDFilterCount(dfilter, 1)

    def test_slice_6(self, checkDFilterCount):
        dfilter = 'http.request.method[1:2] > "EA"'
        checkDFilterCount(dfilter, 0)

    def test_slice_7(self, checkDFilterCount):
        dfilter = 'http.request.method[-1] == "D"'
        checkDFilterCount(dfilter, 1)

    def test_slice_8(self, checkDFilterCount):
        dfilter = 'http.request.method[-2] == "D"'
        checkDFilterCount(dfilter, 0)

    def xxxtest_stringz_1(self):
            return self.DFilterCount(pkt_tftp,
                    'tftp.type == "octet"', 1)

    def xxxtest_stringz_2(self):
            return self.DFilterCount(pkt_tftp,
                    'tftp.type == "junk"', 0)

    def test_contains_1(self, checkDFilterCount):
        dfilter = 'http.request.method contains "E"'
        checkDFilterCount(dfilter, 1)

    def test_contains_2(self, checkDFilterCount):
        dfilter = 'http.request.method contains "EA"'
        checkDFilterCount(dfilter, 1)

    def test_contains_3(self, checkDFilterCount):
        dfilter = 'http.request.method contains "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_contains_4(self, checkDFilterCount):
        dfilter = 'http.request.method contains "POST"'
        checkDFilterCount(dfilter, 0)

    def test_contains_5(self, checkDFilterCount):
        dfilter = 'http.request.method contains "\x50\x4f\x53\x54"' # "POST"
        checkDFilterCount(dfilter, 0)

    def test_contains_6(self, checkDFilterCount):
        dfilter = 'http.request.method contains "\x48\x45\x41\x44"' # "HEAD"
        checkDFilterCount(dfilter, 1)

    def test_contains_7(self, checkDFilterCount):
        dfilter = 'http.request.method contains 48:45:41:44' # "48:45:41:44"
        checkDFilterCount(dfilter, 0)

    def test_contains_fail_0(self, checkDFilterCount):
        dfilter = 'http.user_agent contains "update"'
        checkDFilterCount(dfilter, 0)

    def test_contains_fail_1(self, checkDFilterCount):
        dfilter = 'http.user_agent contains "UPDATE"'
        checkDFilterCount(dfilter, 0)

    def test_contains_upper_0(self, checkDFilterCount):
        dfilter = 'upper(http.user_agent) contains "UPDATE"'
        checkDFilterCount(dfilter, 1)

    def test_contains_upper_1(self, checkDFilterCount):
        dfilter = 'upper(http.user_agent) contains "update"'
        checkDFilterCount(dfilter, 0)

    def test_contains_upper_2(self, checkDFilterFail):
        dfilter = 'upper(tcp.seq) == 4'
        checkDFilterFail(dfilter, 'Only string type fields can be used')

    def test_contains_lower_0(self, checkDFilterCount):
        dfilter = 'lower(http.user_agent) contains "UPDATE"'
        checkDFilterCount(dfilter, 0)

    def test_contains_lower_1(self, checkDFilterCount):
        dfilter = 'lower(http.user_agent) contains "update"'
        checkDFilterCount(dfilter, 1)

    def test_eq_lower_1(self, checkDFilterFail):
        dfilter = 'lower(tcp.seq) == 4'
        checkDFilterFail(dfilter, 'Only string type fields can be used')

    def test_string_len(self, checkDFilterCount):
        dfilter = 'len(http.request.method) == 4'
        checkDFilterCount(dfilter, 1)

    def test_eq_unicode(self, checkDFilterCount):
        dfilter = 'tcp.flags.str == "·······AP···"'
        checkDFilterCount(dfilter, 1)

    def test_contains_unicode(self, checkDFilterCount):
        dfilter = 'tcp.flags.str contains "·······AP···"'
        checkDFilterCount(dfilter, 1)

    def test_value_string_1(self, checkDFilterCount):
        dfilter = 'tcp.checksum.status == "Unverified" || tcp.checksum.status == "Good"'
        checkDFilterCount(dfilter, 1)

    def test_value_string_2(self, checkDFilterCount):
        dfilter = 'tcp.checksum.status matches "unverified|good"'
        checkDFilterCount(dfilter, 1)

    def test_value_string_3(self, checkDFilterSucceed):
        dfilter = 'tcp.checksum.status == Unverified'
        checkDFilterSucceed(dfilter, 'Writing value strings without double quotes is deprecated')

class TestDfilterStringz:
    trace_file = "tftp.pcap"

    def test_stringz_1(self, checkDFilterCount):
        dfilter = 'tftp.type == octet'
        checkDFilterCount(dfilter, 1)

    def test_stringz_2(self, checkDFilterCount):
        dfilter = 'tftp.type == "octet"'
        checkDFilterCount(dfilter, 1)

    def test_stringz_3(self, checkDFilterCount):
        dfilter = 'tftp.type == junk'
        checkDFilterCount(dfilter, 0)

class TestDfilterStringIndex:
    trace_file = "data-utf8.pcap"

    def test_index_1(self, checkDFilterCount):
        dfilter = 'data.text[3] == "á"'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 1, prefs)

    def test_index_2(self, checkDFilterCount):
        dfilter = 'data.text[3] == "a"'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 0, prefs)

    def test_index_3(self, checkDFilterCount):
        dfilter = 'data.text[40:] == "cão preguiçoso"'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 1, prefs)

    def test_index_4(self, checkDFilterCount):
        # Byte offset
        dfilter = '@data.text[41:] == "cão preguiçoso"'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 1, prefs)

    def test_index_5(self, checkDFilterCount):
        # Byte offset
        dfilter = '@data.text[41:] == 63:c3:a3:6f:20:70:72:65:67:75:69:c3:a7:6f:73:6f'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 1, prefs)

    def test_strlen_1(self, checkDFilterCount):
        dfilter = 'len(data.text) == 54'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 1, prefs)

    def test_strlen_2(self, checkDFilterCount):
        # Byte length
        dfilter = 'len(@data.text) == 57'
        prefs = "data.show_as_text:true"
        checkDFilterCount(dfilter, 1, prefs)

