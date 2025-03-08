# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterIEEE11073FLOAT:
    trace_file = "bt_attr.pcapng"
    # btatt.blood_pressure_measurement.pulse_rate is erroneously encoded
    # in this file as the wrong endianness (the reverse of the other values.)
    # This is useful because it makes the value negative.

    def test_eq_1(self, checkDFilterCount):
        dfilter = "btatt.temperature_measurement.value.celsius == 28.461"
        decode_as = ("btatt.handle==0x000f,btgatt.uuid0x2a1c",
                     "btatt.handle==0x0012,btgatt.uuid0x2a35")

        checkDFilterCount(dfilter, 1, decode_as=decode_as)

    def test_gt_1(self, checkDFilterCount):
        dfilter = "btatt.blood_pressure_measurement.compound_value.systolic.mmhg > btatt.blood_pressure_measurement.compound_value.diastolic.mmhg"
        decode_as = ("btatt.handle==0x000f,btgatt.uuid0x2a1c",
                     "btatt.handle==0x0012,btgatt.uuid0x2a35")

        checkDFilterCount(dfilter, 1, decode_as=decode_as)

    def test_neg_1(self, checkDFilterSucceed):
        dfilter = "btatt.blood_pressure_measurement.pulse_rate == -1792000"

        checkDFilterSucceed(dfilter)

    def test_neg_2(self, checkDFilterCount):
        dfilter = "btatt.blood_pressure_measurement.pulse_rate == -1792000"
        decode_as = ("btatt.handle==0x000f,btgatt.uuid0x2a1c",
                     "btatt.handle==0x0012,btgatt.uuid0x2a35")

        checkDFilterCount(dfilter, 1, decode_as=decode_as)
