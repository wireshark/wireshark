#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Wireshark ASTERIX dissector tests
# By Atli Guðmundsson <atli@tern.is>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''ASTERIX dissector tests'''

# Standard modules
import inspect

# Wireshark modules
import fixtures
import subprocesstest
from suite_dissectors.dissectorstest import *


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_asterix(subprocesstest.SubprocessTestCase):

    def test_for_asterix(self, dissection_validator):
        '''Verifies that the asterix dissector is installed and accessible'''

        tester = dissection_validator('asterix')
        tester.add_dissection(
            [0x13, 0x00, 0x03],
            {
                "asterix.category": "19",
                "asterix.length": "3"
            }
        )
        tester.check_dissections()


class _asterix_validator_real:

    def __init__(self, category, dissection_validator):
        self.category = category
        self.validator = dissection_validator("asterix")

    def add_dissection(self, byte_list, field, expected_message, line_no=None):
        '''pre-wrap asterix category messages with proper asterix structure'''

        total_length = len(byte_list) + 3
        byte_list = [
            self.category,
            (total_length // 256) % 256,
            total_length % 256
        ] + byte_list
        expected_result = {
            "asterix.category": "{}".format(self.category),
            "asterix.length": "{}".format(total_length),
            "asterix.message":
            {
                "asterix.fspec": "",
                field: expected_message
            }
        }
        if line_no is None:
            caller = inspect.getframeinfo(inspect.stack()[1][0])
            line_no = caller.lineno
        self.validator.add_dissection(byte_list, expected_result, line_no)

    def check_dissections(self):
        self.validator.check_dissections()


@fixtures.fixture
def asterix_validator(dissection_validator):

    def generate_asterix_validator(category):
        retval = _asterix_validator_real(category, dissection_validator)
        return retval

    return generate_asterix_validator


class _asterix_re_validator_real(_asterix_validator_real):

    def __init__(self, category, re_byte_list, dissection_validator):
        super().__init__(category, dissection_validator)
        self.re_byte_list = re_byte_list

    def add_re_dissection(self, byte_list, field, expected_message, line_no=None):
        '''pre-wrap asterix RE messages with proper asterix RE structure'''

        re_length = len(byte_list) + 1
        byte_list = self.re_byte_list + [
            re_length % 256
        ] + byte_list
        expected_result = {
            "asterix.re_field_len": "{}".format(re_length),
            "asterix.fspec": "",
            "asterix.{:03}_RE_{}".format(self.category, field): expected_message
        }
        if line_no is None:
            caller = inspect.getframeinfo(inspect.stack()[1][0])
            line_no = caller.lineno
        self.add_dissection(byte_list, "asterix.{:03}_RE".format(
            self.category), expected_result, line_no)


@fixtures.fixture
def asterix_re_validator(dissection_validator):

    def generate_re_asterix_validator(category, re_byte_list):
        retval = _asterix_re_validator_real(
            category, re_byte_list, dissection_validator)
        return retval

    return generate_re_asterix_validator


def fspec_local(key, idx, value):
    result = {
        "asterix.fspec": "",
        "asterix.{}".format(key):
        {
            "asterix.{}_{}".format(key, idx): value
        }
    }
    return result


def fspec_global(key, idx, value):
    result = {
        "asterix.fspec": "",
        "asterix.{}".format(key):
        {
            "asterix.{}".format(idx): value
        }
    }
    return result


def dict_local(vmap, key, idx, value):
    result = vmap.copy()
    result["asterix.{}_{}".format(key, idx)] = value
    return result


def dict_global(vmap, key, value):
    result = vmap.copy()
    result["asterix.{}".format(key)] = value
    return result


def dict_fspec_local(vmap, key, idx, value):
    result = {
        "asterix.fspec": "",
        "asterix.{}".format(key): dict_local(vmap, key, idx, value)
    }
    return result


def dict_fspec_global(vmap, key, idx, value):
    result = {
        "asterix.fspec": "",
        "asterix.{}".format(key): dict_global(vmap, idx, value)
    }
    return result


def counter_local(vmap, counter, key, idx, value):
    result = {
        "asterix.fspec": "",
        "asterix.{}".format(key):
        {
            "asterix.counter": counter,
            "asterix.{}".format(key): dict_local(vmap, key, idx, value)
        }
    }
    return result


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_category_019(subprocesstest.SubprocessTestCase):
    '''
    Unittest case for ASTERIX Category 019

    Online specification:
    https://www.eurocontrol.int/publications/cat019-multilateration-system-status-messages-part-18

    Part 18 : Category 019 (1.3)
    Multilateration System
    Status Messages

    Standard User Application Profile

    FRN Data Item Information                                Length
     1  I019/010  Data Source Identifier                      2
     2  I019/000  Message Type                                1
     3  I019/140  Time of Day                                 3
     4  I019/550  System Status                               1
     5  I019/551  Tracking Processor Detailed Status          1
     6  I019/552  Remote Sensor Detailed Status               1+
     7  I019/553  Reference Transponder Detailed Status       1+
    FX   -        Field Extension Indicator                   -
     8  I019/600  Position of the MLT System Reference point  8
     9  I019/610  Height of the MLT System Reference point    2
    10  I019/620  WGS-84 Undulation                           1
    11   -        Spare                                       -
    12   -        Spare                                       -
    13  RE        Reserved Expansion Field                    -
    14  SP        Special Purpose Field                       -
    FX   -        Field Extension Indicator                   -
    '''

    maxDiff = None

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(19)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.019_010",
            {
                "asterix.SAC": "255",
                "asterix.SIC": "0"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.019_010",
            {
                "asterix.SAC": "0",
                "asterix.SIC": "255"
            }
        )
        validator.add_dissection(
            [0x40, 0x03],
            "asterix.019_000",
            {
                "asterix.019_000_MT": "3"
            }
        )
        validator.add_dissection(
            [0x20, 0xa8, 0xbf, 0xff],
            "asterix.019_140",
            {
                "asterix.TOD": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x10, 0xc0],
            "asterix.019_550",
            {
                "asterix.019_550_NOGO": "3",
                "asterix.019_550_OVL": "0",
                "asterix.019_550_TSV": "0",
                "asterix.019_550_TTF": "0"
            }
        )
        validator.add_dissection(
            [0x10, 0x20],
            "asterix.019_550",
            {
                "asterix.019_550_NOGO": "0",
                "asterix.019_550_OVL": "1",
                "asterix.019_550_TSV": "0",
                "asterix.019_550_TTF": "0"
            }
        )
        validator.add_dissection(
            [0x10, 0x10],
            "asterix.019_550",
            {
                "asterix.019_550_NOGO": "0",
                "asterix.019_550_OVL": "0",
                "asterix.019_550_TSV": "1",
                "asterix.019_550_TTF": "0"
            }
        )
        validator.add_dissection(
            [0x10, 0x08],
            "asterix.019_550",
            {
                "asterix.019_550_NOGO": "0",
                "asterix.019_550_OVL": "0",
                "asterix.019_550_TSV": "0",
                "asterix.019_550_TTF": "1"
            }
        )
        validator.add_dissection(
            [0x08, 0x80],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "1",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x40],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "1",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x20],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "1",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x10],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "1",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x08],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "1",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x04],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "1",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x02],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "1",
                "asterix.019_551_SP4_GOOD": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01],
            "asterix.019_551",
            {
                "asterix.019_551_SP1_EXEC": "0",
                "asterix.019_551_SP1_GOOD": "0",
                "asterix.019_551_SP2_EXEC": "0",
                "asterix.019_551_SP2_GOOD": "0",
                "asterix.019_551_SP3_EXEC": "0",
                "asterix.019_551_SP3_GOOD": "0",
                "asterix.019_551_SP4_EXEC": "0",
                "asterix.019_551_SP4_GOOD": "1"
            }
        )
        validator.add_dissection(
            [0x04, 0x00],
            "asterix.019_552",
            {
                "asterix.counter": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0xff, 0x00],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "255",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0x00, 0x40],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "0",
                    "asterix.019_552_Receiver_1090_MHz": "1",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0x00, 0x20],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "0",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "1",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0x00, 0x10],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "0",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "1",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0x00, 0x08],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "0",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "1",
                    "asterix.019_552_RS_Operational": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0x00, 0x04],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "0",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "1"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0x0c],
            "asterix.019_552",
            {
                "asterix.counter": "3",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "18",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "1",
                    "asterix.019_552_Transmitter_1090_MHz": "1",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "1"
                },
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "86",
                    "asterix.019_552_Receiver_1090_MHz": "1",
                    "asterix.019_552_Transmitter_1030_MHz": "1",
                    "asterix.019_552_Transmitter_1090_MHz": "1",
                    "asterix.019_552_RS_Status": "1",
                    "asterix.019_552_RS_Operational": "0"
                },
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "154",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "1",
                    "asterix.019_552_RS_Operational": "1"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0xc0],
            "asterix.019_553",
            {
                "asterix.019_553_Ref_Trans_1_Status": "3",
                "asterix.019_553_Ref_Trans_2_Status": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x02, 0x0c],
            "asterix.019_553",
            {
                "asterix.019_553_Ref_Trans_1_Status": "0",
                "asterix.019_553_Ref_Trans_2_Status": "3",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x02, 0x01, 0x01, 0x0c],
            "asterix.019_553",
            {
                "asterix.019_553_Ref_Trans_1_Status": "0",
                "asterix.019_553_Ref_Trans_2_Status": "0",
                "asterix.019_553_Ref_Trans_3_Status": "0",
                "asterix.019_553_Ref_Trans_4_Status": "0",
                "asterix.019_553_Ref_Trans_5_Status": "0",
                "asterix.019_553_Ref_Trans_6_Status": "3",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "90",
                "asterix.019_600_Longitude": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "-90",
                "asterix.019_600_Longitude": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "0",
                "asterix.019_600_Longitude": "180"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "0",
                "asterix.019_600_Longitude": "-180"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x7f, 0xff],
            "asterix.019_610",
            {
                "asterix.019_610_Height": "8191.75"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x80, 0x00],
            "asterix.019_610",
            {
                "asterix.019_610_Height": "-8192"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x7f],
            "asterix.019_620",
            {
                "asterix.019_620_Undulation": "127"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x81],
            "asterix.019_620",
            {
                "asterix.019_620_Undulation": "-127"
            }
        )

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_validator):
        '''verifies that the dissector can dissect undefined field values by setting
        the maximum value of bits or by setting all undefined bits'''

        validator = asterix_validator(19)

        validator.add_dissection(
            [0x40, 0xff],
            "asterix.019_000",
            {
                "asterix.019_000_MT": "255"
            }
        )
        validator.add_dissection(
            [0x20, 0xff, 0xff, 0xff],
            "asterix.019_140",
            {
                "asterix.TOD": "131071.9921875"
            }
        )
        validator.add_dissection(
            [0x10, 0x07],
            "asterix.019_550",
            {
                "asterix.019_550_NOGO": "0",
                "asterix.019_550_OVL": "0",
                "asterix.019_550_TSV": "0",
                "asterix.019_550_TTF": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0x01, 0x00, 0x83],
            "asterix.019_552",
            {
                "asterix.counter": "1",
                "asterix.019_552":
                {
                    "asterix.019_552_RS_Identification": "0",
                    "asterix.019_552_Receiver_1090_MHz": "0",
                    "asterix.019_552_Transmitter_1030_MHz": "0",
                    "asterix.019_552_Transmitter_1090_MHz": "0",
                    "asterix.019_552_RS_Status": "0",
                    "asterix.019_552_RS_Operational": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x32],
            "asterix.019_553",
            {
                "asterix.019_553_Ref_Trans_1_Status": "0",
                "asterix.019_553_Ref_Trans_2_Status": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x02, 0x33, 0x33, 0x32],
            "asterix.019_553",
            {
                "asterix.019_553_Ref_Trans_1_Status": "0",
                "asterix.019_553_Ref_Trans_2_Status": "0",
                "asterix.019_553_Ref_Trans_3_Status": "0",
                "asterix.019_553_Ref_Trans_4_Status": "0",
                "asterix.019_553_Ref_Trans_5_Status": "0",
                "asterix.019_553_Ref_Trans_6_Status": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "359.999999832362",
                "asterix.019_600_Longitude": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "-360",
                "asterix.019_600_Longitude": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "0",
                "asterix.019_600_Longitude": "359.999999832362"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_Latitude": "0",
                "asterix.019_600_Longitude": "-360"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x80],
            "asterix.019_620",
            {
                "asterix.019_620_Undulation": "-128"
            }
        )
        validator.add_dissection(
            [0x01, 0x10],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x08],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x04, 0x02, 0x00],
            "asterix.019_RE",
            {
                "asterix.re_field_len": "2",
                "asterix.fspec": ""
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.019_RE",
            {
                "asterix.fspec": "",
                "asterix.re_field_len": "16"
            }
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01],
            "asterix.019_SP",
            ""
        )
        validator.add_dissection(
            [0x01, 0x02, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.019_SP",
            ""
        )

        validator.check_dissections()


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_category_034(subprocesstest.SubprocessTestCase):
    '''
    Unittest case for ASTERIX Category 034

    Online specification:
    https://www.eurocontrol.int/publications/cat034-monoradar-service-messages-part-2b-next-version-cat-002

    Part 2b
    Transmission of Monoradar Service Messages

    Standard User Application Profile

    FRN Data Item Information                                        Length
     1  I034/010  Data Source Identifier                              2
     2  I034/000  Message Type                                        1
     3  I034/030  Time-of-Day                                         3
     4  I034/020  Sector Number                                       1
     5  I034/041  Antenna Rotation Period                             2
     6  I034/050  System Configuration and Status                     1+
     7  I034/060  System Processing Mode                              1+
    FX  N/A.      Field Extension Indicator                           N/A.
     8  I034/070  Message Count Values                                (1+2*N)
     9  I034/100  Generic Polar Window                                8
    10  I034/110  Data Filter                                         1
    11  I034/120  3D-Position of Data Source                          8
    12  I034/090  Collimation Error                                   2
    13  RE-Data   Item Reserved Expansion Field                       1+1+
    14  SP-Data   Item Special Purpose Field                          1+1+
    FX  N/A.      Field Extension Indicator                           n.a.
    '''

    maxDiff = None

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(34)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.034_010",
            {
                "asterix.SAC": "255",
                "asterix.SIC": "0"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.034_010",
            {
                "asterix.SAC": "0",
                "asterix.SIC": "255"
            }
        )
        validator.add_dissection(
            [0x40, 0x04],
            "asterix.034_000",
            {
                "asterix.034_000_MT": "4"
            }
        )
        validator.add_dissection(
            [0x20, 0xa8, 0xbf, 0xff],
            "asterix.034_030",
            {
                "asterix.TOD": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x10, 0xff],
            "asterix.034_020",
            {
                "asterix.034_020_SN": "358.59375"
            }
        )
        validator.add_dissection(
            [0x08, 0xff, 0xff],
            "asterix.034_041",
            {
                "asterix.034_041_ARS": "511.9921875"
            }
        )
        x_050_01 = {
            "asterix.034_050_01_NOGO": "0",
            "asterix.034_050_01_RDPC": "0",
            "asterix.034_050_01_RDPR": "0",
            "asterix.034_050_01_OVL_RDP": "0",
            "asterix.034_050_01_OVL_XMT": "0",
            "asterix.034_050_01_MSC": "0",
            "asterix.034_050_01_TSV": "0"
        }
        validator.add_dissection(
            [0x04, 0x80, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "NOGO", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x40],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "RDPC", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x20],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "RDPR", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x10],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "OVL_RDP", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x08],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "OVL_XMT", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x04],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "MSC", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x02],
            "asterix.034_050",
            dict_fspec_local(x_050_01, "034_050_01", "TSV", "1")
        )
        x_050_02 = {
            "asterix.034_050_02_ANT": "0",
            "asterix.034_050_02_CHAB": "0",
            "asterix.034_050_02_OVL": "0",
            "asterix.034_050_02_MSC": "0"
        }
        validator.add_dissection(
            [0x04, 0x10, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_02, "034_050_02", "ANT", "1")
        )
        validator.add_dissection(
            [0x04, 0x10, 0x60],
            "asterix.034_050",
            dict_fspec_local(x_050_02, "034_050_02", "CHAB", "3")
        )
        validator.add_dissection(
            [0x04, 0x10, 0x10],
            "asterix.034_050",
            dict_fspec_local(x_050_02, "034_050_02", "OVL", "1")
        )
        validator.add_dissection(
            [0x04, 0x10, 0x08],
            "asterix.034_050",
            dict_fspec_local(x_050_02, "034_050_02", "MSC", "1")
        )
        x_050_03 = {
            "asterix.034_050_03_ANT": "0",
            "asterix.034_050_03_CHAB": "0",
            "asterix.034_050_03_OVL": "0",
            "asterix.034_050_03_MSC": "0"
        }
        validator.add_dissection(
            [0x04, 0x08, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_03, "034_050_03", "ANT", "1")
        )
        validator.add_dissection(
            [0x04, 0x08, 0x60],
            "asterix.034_050",
            dict_fspec_local(x_050_03, "034_050_03", "CHAB", "3")
        )
        validator.add_dissection(
            [0x04, 0x08, 0x10],
            "asterix.034_050",
            dict_fspec_local(x_050_03, "034_050_03", "OVL", "1")
        )
        validator.add_dissection(
            [0x04, 0x08, 0x08],
            "asterix.034_050",
            dict_fspec_local(x_050_03, "034_050_03", "MSC", "1")
        )
        x_050_04 = {
            "asterix.034_050_04_ANT": "0",
            "asterix.034_050_04_CHAB": "0",
            "asterix.034_050_04_OVL_SUR": "0",
            "asterix.034_050_04_MSC": "0",
            "asterix.034_050_04_SCF": "0",
            "asterix.034_050_04_DLF": "0",
            "asterix.034_050_04_OVL_SCF": "0",
            "asterix.034_050_04_OVL_DLF": "0"
        }
        validator.add_dissection(
            [0x04, 0x04, 0x80, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "ANT", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x60, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "CHAB", "3")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x10, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "OVL_SUR", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x08, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "MSC", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x04, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "SCF", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x02, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "DLF", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x01, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "OVL_SCF", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x00, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_04, "034_050_04", "OVL_DLF", "1")
        )
        x_060_01 = {
            "asterix.034_060_01_RED_RDP": "0",
            "asterix.034_060_01_RED_XMT": "0"
        }
        validator.add_dissection(
            [0x02, 0x80, 0x70],
            "asterix.034_060",
            dict_fspec_local(x_060_01, "034_060_01", "RED_RDP", "7")
        )
        validator.add_dissection(
            [0x02, 0x80, 0x0e],
            "asterix.034_060",
            dict_fspec_local(x_060_01, "034_060_01", "RED_XMT", "7")
        )
        x_060_02 = {
            "asterix.034_060_02_POL": "0",
            "asterix.034_060_02_RED_RAD": "0",
            "asterix.034_060_02_STC": "0"
        }
        validator.add_dissection(
            [0x02, 0x10, 0x80],
            "asterix.034_060",
            dict_fspec_local(x_060_02, "034_060_02", "POL", "1")
        )
        validator.add_dissection(
            [0x02, 0x10, 0x70],
            "asterix.034_060",
            dict_fspec_local(x_060_02, "034_060_02", "RED_RAD", "7")
        )
        validator.add_dissection(
            [0x02, 0x10, 0x0c],
            "asterix.034_060",
            dict_fspec_local(x_060_02, "034_060_02", "STC", "3")
        )
        validator.add_dissection(
            [0x02, 0x08, 0xe0],
            "asterix.034_060",
            fspec_local("034_060_03", "RED_RAD", "7")
        )
        x_060_06 = {
            "asterix.034_060_04_RED_RAD": "0",
            "asterix.034_060_04_CLU": "0"
        }
        validator.add_dissection(
            [0x02, 0x04, 0xe0],
            "asterix.034_060",
            dict_fspec_local(x_060_06, "034_060_04", "RED_RAD", "7")
        )
        validator.add_dissection(
            [0x02, 0x04, 0x10],
            "asterix.034_060",
            dict_fspec_local(x_060_06, "034_060_04", "CLU", "1")
        )
        x_070 = {
            "asterix.034_070_TYP": "0",
            "asterix.034_070_COUNTER": "0"
        }
        validator.add_dissection(
            [0x01, 0x80, 0x01, 0x80, 0x00],
            "asterix.034_070",
            {
                "asterix.counter": "1",
                "asterix.034_070":
                dict_local(x_070, "034_070", "TYP", "16")
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x03, 0x80, 0x00, 0x87, 0xff, 0x07, 0xff],
            "asterix.034_070",
            {
                "asterix.counter": "3",
                "asterix.034_070":
                dict_local(x_070, "034_070", "TYPE", "16"),
                "asterix.034_070":
                {
                    "asterix.034_070_TYP": "16",
                    "asterix.034_070_COUNTER": "2047"
                },
                "asterix.034_070":
                dict_local(x_070, "034_070", "COUNTER", "2047"),
            }
        )
        x_100 = {
            "asterix.034_100_RHOS": "0",
            "asterix.034_100_RHOE": "0",
            "asterix.034_100_THETAS": "0",
            "asterix.034_100_THETAE": "0"
        }
        validator.add_dissection(
            [0x01, 0x40, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_100",
            dict_local(x_100, "034_100", "RHOS", "255.99609375")
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_100",
            dict_local(x_100, "034_100", "RHOE", "255.99609375")
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00],
            "asterix.034_100",
            dict_local(x_100, "034_100", "THETAS", "359.994506835938")
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff],
            "asterix.034_100",
            dict_local(x_100, "034_100", "THETAE", "359.994506835938")
        )
        validator.add_dissection(
            [0x01, 0x20, 0x09],
            "asterix.034_110",
            {
                "asterix.034_110_TYP": "9"
            }
        )
        x_120 = {
            "asterix.034_120_H": "0",
            "asterix.034_120_LAT": "0",
            "asterix.034_120_LON": "0"
        }
        validator.add_dissection(
            [0x01, 0x10, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "H", "32767")
        )
        validator.add_dissection(
            [0x01, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "H", "-32768")
        )
        validator.add_dissection(
            [0x01, 0x10, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "LAT", "90")
        )
        validator.add_dissection(
            [0x01, 0x10, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "LAT", "-90")
        )
        validator.add_dissection(
            [0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff],
            "asterix.034_120",
            dict_local(x_120, "034_120", "LON", "179.999978542328")
        )
        validator.add_dissection(
            [0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "LON", "-180")
        )
        x_090 = {
            "asterix.034_090_RE": "0",
            "asterix.034_090_AE": "0"
        }
        validator.add_dissection(
            [0x01, 0x08, 0x7f, 0x00],
            "asterix.034_090",
            dict_local(x_090, "034_090", "RE", "0.9921875")
        )
        validator.add_dissection(
            [0x01, 0x08, 0x80, 0x00],
            "asterix.034_090",
            dict_local(x_090, "034_090", "RE", "-1")
        )
        validator.add_dissection(
            [0x01, 0x08, 0x00, 0x80],
            "asterix.034_090",
            dict_local(x_090, "034_090", "AE", "-2.8125")
        )

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_validator):
        '''verifies that the dissector can dissect undefined field values by setting
        the maximum value of bits or by setting all undefined bits'''

        validator = asterix_validator(34)

        validator.add_dissection(
            [0x40, 0xff],
            "asterix.034_000",
            {
                "asterix.034_000_MT": "255"
            }
        )
        validator.add_dissection(
            [0x20, 0xff, 0xff, 0xff],
            "asterix.034_030",
            {
                "asterix.TOD": "131071.9921875"
            }
        )
        validator.add_dissection(
            [0x04, 0x63, 0x00],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.spare": ""
            }
        )
        validator.add_dissection(
            [0x04, 0x80, 0x01],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_01":
                {
                    "asterix.034_050_01_NOGO": "0",
                    "asterix.034_050_01_RDPC": "0",
                    "asterix.034_050_01_RDPR": "0",
                    "asterix.034_050_01_OVL_RDP": "0",
                    "asterix.034_050_01_OVL_XMT": "0",
                    "asterix.034_050_01_MSC": "0",
                    "asterix.034_050_01_TSV": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x10, 0x07],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_02":
                {
                    "asterix.034_050_02_ANT": "0",
                    "asterix.034_050_02_CHAB": "0",
                    "asterix.034_050_02_OVL": "0",
                    "asterix.034_050_02_MSC": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x08, 0x07],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_03":
                {
                    "asterix.034_050_03_ANT": "0",
                    "asterix.034_050_03_CHAB": "0",
                    "asterix.034_050_03_OVL": "0",
                    "asterix.034_050_03_MSC": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x04, 0x00, 0x7f],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_04":
                {
                    "asterix.034_050_04_ANT": "0",
                    "asterix.034_050_04_CHAB": "0",
                    "asterix.034_050_04_OVL_SUR": "0",
                    "asterix.034_050_04_MSC": "0",
                    "asterix.034_050_04_SCF": "0",
                    "asterix.034_050_04_DLF": "0",
                    "asterix.034_050_04_OVL_SCF": "0",
                    "asterix.034_050_04_OVL_DLF": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x63, 0x00],
            "asterix.034_060",
            {
                "asterix.fspec": "",
                "asterix.spare": ""
            }
        )
        validator.add_dissection(
            [0x02, 0x80, 0x81],
            "asterix.034_060",
            {
                "asterix.fspec": "",
                "asterix.034_060_01":
                {
                    "asterix.034_060_01_RED_RDP": "0",
                    "asterix.034_060_01_RED_XMT": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x10, 0x03],
            "asterix.034_060",
            {
                "asterix.fspec": "",
                "asterix.034_060_02":
                {
                    "asterix.034_060_02_POL": "0",
                    "asterix.034_060_02_RED_RAD": "0",
                    "asterix.034_060_02_STC": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x08, 0x1f],
            "asterix.034_060",
            fspec_local("034_060_03", "RED_RAD", "0")
        )
        validator.add_dissection(
            [0x02, 0x04, 0x0f],
            "asterix.034_060",
            {
                "asterix.fspec": "",
                "asterix.034_060_04":
                {
                    "asterix.034_060_04_RED_RAD": "0",
                    "asterix.034_060_04_CLU": "0"
                }
            }
        )
        x_070 = {
            "asterix.034_070_TYP": "0",
            "asterix.034_070_COUNTER": "0"
        }
        validator.add_dissection(
            [0x01, 0x80, 0x01, 0xf8, 0x00],
            "asterix.034_070",
            {
                "asterix.counter": "1",
                "asterix.034_070":
                dict_local(x_070, "034_070", "TYP", "31")
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0xff],
            "asterix.034_110",
            {
                "asterix.034_110_TYP": "255"
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x02, 0xfe],
            "asterix.034_RE",
            {
                "asterix.re_field_len": "2",
                "asterix.fspec": ""
            }
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01],
            "asterix.034_SP",
            ""
        )
        validator.add_dissection(
            [0x01, 0x02, 0x11, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.034_SP",
            ""
        )

        validator.check_dissections()


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_category_063(subprocesstest.SubprocessTestCase):
    '''
    Unittest case for ASTERIX Category 063

    Online specification:
    https://www.eurocontrol.int/publications/cat063-sensor-status-messages-part-10

    Part 10: Category 63 (1.4)
    Sensor Status Messages

    Standard User Application Profile

    FRN Data Item Information                                Length
     1  I063/010  Data Source Identifier                      2
     2  I063/015  Service Identification                      1
     3  I063/030  Time of Message                             3
     4  I063/050  Sensor Identifier                           2
     5  I063/060  Sensor Configuration and Status             1+1
     6  I063/070  Time Stamping Bias                          2
     7  I063/080  SSR/Mode S Range Gain and Bias              4
    FX   -        Field extension indicator                   -
     8  I063/081  SSR/Mode S Azimuth Bias                     2
     9  I063/090  PSR Range Gain and Bias                     4
    10  I063/091  PSR Azimuth Bias                            2
    11  I063/092  PSR Elevation Bias                          2
    12   -        spare                                       -
    13  RE        Reserved Expansion Field                    1+1+
    14  SP        Special Purpose Field                       1+1+
    FX   -        Field extension indicator                   -
    '''

    maxDiff = None

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(63)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.063_010",
            {
                "asterix.SAC": "255",
                "asterix.SIC": "0"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.063_010",
            {
                "asterix.SAC": "0",
                "asterix.SIC": "255"
            }
        )
        validator.add_dissection(
            [0x40, 0xff],
            "asterix.063_015",
            {
                "asterix.063_015_SI": "255"
            }
        )
        validator.add_dissection(
            [0x20, 0xa8, 0xbf, 0xff],
            "asterix.063_030",
            {
                "asterix.TOD": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x10, 0xff, 0x00],
            "asterix.063_050",
            {
                "asterix.SAC": "255",
                "asterix.SIC": "0"
            }
        )
        validator.add_dissection(
            [0x10, 0x00, 0xff],
            "asterix.063_050",
            {
                "asterix.SAC": "0",
                "asterix.SIC": "255"
            }
        )
        validator.add_dissection(
            [0x08, 0xc0],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "3",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x20],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "1",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x10],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "1",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x08],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "1",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x04],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "1",
                "asterix.063_060_MLT": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x02],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "1",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01, 0x80],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.063_060_OPS": "1",
                "asterix.063_060_ODP": "0",
                "asterix.063_060_OXT": "0",
                "asterix.063_060_MSC": "0",
                "asterix.063_060_TSV": "0",
                "asterix.063_060_NPW": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01, 0x40],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.063_060_OPS": "0",
                "asterix.063_060_ODP": "1",
                "asterix.063_060_OXT": "0",
                "asterix.063_060_MSC": "0",
                "asterix.063_060_TSV": "0",
                "asterix.063_060_NPW": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01, 0x20],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.063_060_OPS": "0",
                "asterix.063_060_ODP": "0",
                "asterix.063_060_OXT": "1",
                "asterix.063_060_MSC": "0",
                "asterix.063_060_TSV": "0",
                "asterix.063_060_NPW": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01, 0x10],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.063_060_OPS": "0",
                "asterix.063_060_ODP": "0",
                "asterix.063_060_OXT": "0",
                "asterix.063_060_MSC": "1",
                "asterix.063_060_TSV": "0",
                "asterix.063_060_NPW": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01, 0x08],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.063_060_OPS": "0",
                "asterix.063_060_ODP": "0",
                "asterix.063_060_OXT": "0",
                "asterix.063_060_MSC": "0",
                "asterix.063_060_TSV": "1",
                "asterix.063_060_NPW": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01, 0x04],
            "asterix.063_060",
            {
                "asterix.063_060_CON": "0",
                "asterix.063_060_PSR": "0",
                "asterix.063_060_SSR": "0",
                "asterix.063_060_MDS": "0",
                "asterix.063_060_ADS": "0",
                "asterix.063_060_MLT": "0",
                "asterix.063_060_OPS": "0",
                "asterix.063_060_ODP": "0",
                "asterix.063_060_OXT": "0",
                "asterix.063_060_MSC": "0",
                "asterix.063_060_TSV": "0",
                "asterix.063_060_NPW": "1",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0xff, 0xff],
            "asterix.063_070",
            {
                "asterix.063_070_TSB": "65535"
            }
        )
        validator.add_dissection(
            [0x02, 0x7f, 0xff, 0x00, 0x00],
            "asterix.063_080",
            {
                "asterix.063_080_SRG": "0.32767",
                "asterix.063_080_SRB": "0"
            }
        )
        validator.add_dissection(
            [0x02, 0x80, 0x00, 0x00, 0x00],
            "asterix.063_080",
            {
                "asterix.063_080_SRG": "-0.32768",
                "asterix.063_080_SRB": "0"
            }
        )
        validator.add_dissection(
            [0x02, 0x00, 0x00, 0x7f, 0xff],
            "asterix.063_080",
            {
                "asterix.063_080_SRG": "0",
                "asterix.063_080_SRB": "255.9921875"
            }
        )
        validator.add_dissection(
            [0x02, 0x00, 0x00, 0x80, 0x00],
            "asterix.063_080",
            {
                "asterix.063_080_SRG": "0",
                "asterix.063_080_SRB": "-256"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x7f, 0xff],
            "asterix.063_081",
            {
                "asterix.063_081_SAB": "179.994506835938"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x80, 0x00],
            "asterix.063_081",
            {
                "asterix.063_081_SAB": "-180"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x7f, 0xff, 0x00, 0x00],
            "asterix.063_090",
            {
                "asterix.063_090_PRG": "0.32767",
                "asterix.063_090_PRB": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x40,  0x80, 0x00, 0x00, 0x00],
            "asterix.063_090",
            {
                "asterix.063_090_PRG": "-0.32768",
                "asterix.063_090_PRB": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0x7f, 0xff],
            "asterix.063_090",
            {
                "asterix.063_090_PRG": "0",
                "asterix.063_090_PRB": "255.9921875"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0x80, 0x00],
            "asterix.063_090",
            {
                "asterix.063_090_PRG": "0",
                "asterix.063_090_PRB": "-256"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x7f, 0xff],
            "asterix.063_091",
            {
                "asterix.063_091_PAB": "179.994506835938"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x80, 0x00],
            "asterix.063_091",
            {
                "asterix.063_091_PAB": "-180"
            }
        )
        validator.add_dissection(
            [0x01, 0x10, 0x7f, 0xff],
            "asterix.063_092",
            {
                "asterix.063_092_PEB": "179.994506835938"
            }
        )
        validator.add_dissection(
            [0x01, 0x10, 0x80, 0x00],
            "asterix.063_092",
            {
                "asterix.063_092_PEB": "-180"
            }
        )

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_validator):
        '''verifies that the dissector can dissect undefined field values by
        setting the maximum value of bits or by setting all undefined bits'''

        validator = asterix_validator(63)

        validator.add_dissection(
            [0x01, 0x08],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x04, 0x02, 0x00],
            "asterix.063_RE",
            {
                "asterix.re_field_len": "2",
                "asterix.fspec": ""
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.063_RE",
            {
                "asterix.fspec": "",
                "asterix.re_field_len": "16"
            }
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01],
            "asterix.063_SP",
            ""
        )
        validator.add_dissection(
            [0x01, 0x02, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.063_SP",
            ""
        )

        validator.check_dissections()


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_category_065(subprocesstest.SubprocessTestCase):
    '''
    Unittest case for ASTERIX Category 065

    Online specification:
    https://www.eurocontrol.int/publications/cat065-surveillance-data-processing-system-sdps-service-status-messages-part-15
    https://www.eurocontrol.int/publications/cat065-coding-rules-reserved-expansion-field-part-15-appendix

    Part 15 Category 65 (1.4)
    SDPS Service Status Reports

    Standard User Application Profile

    FRN Data Item Information                                Length
     1  I065/010  Data Source Identifier                      2
     2  I065/000  Message Type                                1
     3  I065/015  Service Identification                      1
     4  I065/030  Time of Message                             3
     5  I065/020  Batch Number                                1
     6  I065/040  SDPS Configuration and Status               1
     7  I065/050  Service Status Report                       1
    FX   -        Field extension indicator                   -
     8   -        Spare                                       -
     9   -        Spare                                       -
    10   -        Spare                                       -
    11   -        Spare                                       -
    12   -        Spare                                       -
    13  RE        Reserved Expansion Field                    1+1+
    14  SP        Special Purpose Field                       1+1+
    FX   -        Field extension indicator                   -
    '''

    maxDiff = None

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(65)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.065_010",
            {
                "asterix.SAC": "255",
                "asterix.SIC": "0"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.065_010",
            {
                "asterix.SAC": "0",
                "asterix.SIC": "255"
            }
        )
        validator.add_dissection(
            [0x40, 0x03],
            "asterix.065_000",
            {
                "asterix.065_000_MT": "3"
            }
        )
        validator.add_dissection(
            [0x20, 0xff],
            "asterix.065_015",
            {
                "asterix.065_015_SI": "255"
            }
        )
        validator.add_dissection(
            [0x10, 0xa8, 0xbf, 0xff],
            "asterix.065_030",
            {
                "asterix.TOD": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x08, 0xff],
            "asterix.065_020",
            {
                "asterix.065_020_BTN": "255"
            }
        )
        validator.add_dissection(
            [0x04, 0xc0],
            "asterix.065_040",
            {
                "asterix.065_040_NOGO": "3",
                "asterix.065_040_OVL": "0",
                "asterix.065_040_TSV": "0",
                "asterix.065_040_PSS": "0",
                "asterix.065_040_STTN": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0x20],
            "asterix.065_040",
            {
                "asterix.065_040_NOGO": "0",
                "asterix.065_040_OVL": "1",
                "asterix.065_040_TSV": "0",
                "asterix.065_040_PSS": "0",
                "asterix.065_040_STTN": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0x10],
            "asterix.065_040",
            {
                "asterix.065_040_NOGO": "0",
                "asterix.065_040_OVL": "0",
                "asterix.065_040_TSV": "1",
                "asterix.065_040_PSS": "0",
                "asterix.065_040_STTN": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0x0c],
            "asterix.065_040",
            {
                "asterix.065_040_NOGO": "0",
                "asterix.065_040_OVL": "0",
                "asterix.065_040_TSV": "0",
                "asterix.065_040_PSS": "3",
                "asterix.065_040_STTN": "0"
            }
        )
        validator.add_dissection(
            [0x04, 0x02],
            "asterix.065_040",
            {
                "asterix.065_040_NOGO": "0",
                "asterix.065_040_OVL": "0",
                "asterix.065_040_TSV": "0",
                "asterix.065_040_PSS": "0",
                "asterix.065_040_STTN": "1"
            }
        )
        validator.add_dissection(
            [0x02, 0xff],
            "asterix.065_050",
            {
                "asterix.065_050_REP": "255"
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x02, 0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "2",
                "asterix.fspec": ""
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "90",
                    "asterix.065_RE_SRP_Longitude": "0"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "-90",
                    "asterix.065_RE_SRP_Longitude": "0"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "0",
                    "asterix.065_RE_SRP_Longitude": "180"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "0",
                    "asterix.065_RE_SRP_Longitude": "-180"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x04, 0x40, 0xff, 0xfc],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "4",
                "asterix.fspec": "",
                "asterix.065_RE_ARL":
                {
                    "asterix.065_RE_ARL_ARL": "65532"
                }
            }
        )

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_validator):
        '''verifies that the dissector can dissect undefined field values by
        setting the maximum value of bits or by setting all undefined bits'''

        validator = asterix_validator(65)

        validator.add_dissection(
            [0x40, 0xff],
            "asterix.065_000",
            {
                "asterix.065_000_MT": "255"
            }
        )
        validator.add_dissection(
            [0x10, 0xff, 0xff, 0xff],
            "asterix.065_030",
            {
                "asterix.TOD": "131071.9921875"
            }
        )
        validator.add_dissection(
            [0x04, 0x01],
            "asterix.065_040",
            {
                "asterix.065_040_NOGO": "0",
                "asterix.065_040_OVL": "0",
                "asterix.065_040_TSV": "0",
                "asterix.065_040_PSS": "0",
                "asterix.065_040_STTN": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x40],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x20],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x10],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x08],
            "asterix.spare",
            ""
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "359.999999832362",
                    "asterix.065_RE_SRP_Longitude": "0"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "-360",
                    "asterix.065_RE_SRP_Longitude": "0"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff,
             0xff],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "0",
                    "asterix.065_RE_SRP_Longitude": "359.999999832362"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
             0x00],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "10",
                "asterix.fspec": "",
                "asterix.065_RE_SRP":
                {
                    "asterix.065_RE_SRP_Latitude": "0",
                    "asterix.065_RE_SRP_Longitude": "-360"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x04, 0x04, 0x40, 0xff, 0xff],
            "asterix.065_RE",
            {
                "asterix.re_field_len": "4",
                "asterix.fspec": "",
                "asterix.065_RE_ARL":
                {
                    "asterix.065_RE_ARL_ARL": "65535"
                }
            }
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01],
            "asterix.065_SP",
            ""
        )
        validator.add_dissection(
            [0x01, 0x02, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.065_SP",
            ""
        )

        validator.check_dissections()
