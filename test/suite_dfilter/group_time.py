# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterTime:
    trace_file = "http.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = 'frame.time == "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = 'frame.time == "Jan 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_eq_3(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_eq_4(self, checkDFilterCount):
        dfilter = 'frame.time == 1041342931.3'
        checkDFilterCount(dfilter, 1)

    def test_ne_1(self, checkDFilterCount):
        dfilter = 'frame.time != "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ne_2(self, checkDFilterCount):
        dfilter = 'frame.time != "Jan 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_gt_1(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_gt_3(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ge_2(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_1(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_2(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_le_1(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_le_2(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_utc_time_1(self, checkDFilterCount):
        dfilter = 'frame.time == "Dec 31, 2002 13:55:31.3 UTC"'
        checkDFilterCount(dfilter, 1)

    def test_utc_time_2(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 13:55:31.3 UTC"'
        checkDFilterCount(dfilter, 1)

    def test_bad_time_2(self, checkDFilterFail):
        # Miliseconds can only occur after seconds.
        dfilter = 'frame.time == "2002-12-31 13:55.3"'
        error = 'requires a seconds field'
        checkDFilterFail(dfilter, error)

    def test_bad_time_3(self, checkDFilterFail):
        # Reject months in a different locale (mrt is March in nl_NL.UTF-8).
        dfilter = 'frame.time == "mrt 1, 2000 00:00:00"'
        error = '"mrt 1, 2000 00:00:00" is not a valid absolute time. Example: "Nov 12, 1999 08:55:44.123" or "2011-07-04 12:34:56"'
        checkDFilterFail(dfilter, error)

class TestDfilterTimeRelative:
    trace_file = "nfs.pcap"

    def test_relative_time_1(self, checkDFilterCount):
        dfilter = "frame.time_delta == 0.7"
        checkDFilterCount(dfilter, 1)

    def test_relative_time_2(self, checkDFilterCount):
        dfilter = "frame.time_delta > 0.7"
        checkDFilterCount(dfilter, 0)

    def test_relative_time_3(self, checkDFilterCount):
        dfilter = "frame.time_delta < 0.7"
        checkDFilterCount(dfilter, 1)

class TestDfilterTimezone:
    trace_file = "http.pcap"

    # These are all the same value expressed in different
    # ways and timezones

    def test_time_1(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_time_2(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 13:55:31.3Z"'
        checkDFilterCount(dfilter, 1)

    def test_time_3(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 15:55:31.3 +02:00"'
        checkDFilterCount(dfilter, 1)

    def test_time_4(self, checkDFilterCount):
        # Foxtrot time zone
        dfilter = 'frame.time == "2002-12-31 19:55:31.3    F"'
        checkDFilterCount(dfilter, 1)

    def test_time_5(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 05:55:31.3 PST"'
        checkDFilterCount(dfilter, 1)

    def test_time_6(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 07:55:31.3 CST"'
        checkDFilterCount(dfilter, 1)

class TestDfilterTimeArithmetic:
    trace_file = "sip-rtp.pcapng"

    def test_time_math_1(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.time_relative > ${frame.time_relative} + 10'
        # select frame 4, expect 425 frames out of 562.
        checkDFilterCountWithSelectedFrame(dfilter, 425, 4)

    def test_time_math_2(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.time_relative > ${frame.time_relative} - 2'
        # select frame 14, expect 557 frames out of 562.
        checkDFilterCountWithSelectedFrame(dfilter, 557, 14)

    def test_time_math_3(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.time_relative > ${frame.time_relative} * 2'
        # select frame 4, expect 557 frames out of 562.
        checkDFilterCountWithSelectedFrame(dfilter, 557, 4)

    def test_time_math_4(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.time_relative > ${frame.time_relative} / 3'
        # select frame 532, expect 528 frames out of 562.
        checkDFilterCountWithSelectedFrame(dfilter, 528, 532)

    def test_time_math_5(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.time_relative > ${frame.time_relative} * 2.5'
        # select frame 8, expect 355 frames out of 562.
        checkDFilterCountWithSelectedFrame(dfilter, 355, 8)

    def test_time_math_6(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.time_relative > ${frame.time_relative} / 2.5'
        # select frame 440, expect 483 frames out of 562.
        checkDFilterCountWithSelectedFrame(dfilter, 483, 440)
