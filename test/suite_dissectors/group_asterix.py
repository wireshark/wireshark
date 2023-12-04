#
# Wireshark ASTERIX dissector tests
# By Atli Guðmundsson <atli@tern.is>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''ASTERIX dissector tests'''

import inspect
import pytest

# Wireshark modules
from suite_dissectors.dissectorstest import *


class TestAsterix:

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


@pytest.fixture
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


@pytest.fixture
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


class TestCategory019:
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

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(19)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.019_010",
            {
                "asterix.019_010_SAC": "0xff",
                "asterix.019_010_SIC": "0x00"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.019_010",
            {
                "asterix.019_010_SAC": "0x00",
                "asterix.019_010_SIC": "0xff"
            }
        )
        validator.add_dissection(
            [0x40, 0x03],
            "asterix.019_000",
            {
                "asterix.019_000_VALUE": "3"
            }
        )
        validator.add_dissection(
            [0x20, 0xa8, 0xbf, 0xff],
            "asterix.019_140",
            {
                "asterix.019_140_VALUE": "86399.9921875"
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
                "asterix.019_551_TP1A": "1",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x40],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "1",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x20],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "1",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x10],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "1",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x08],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "1",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x04],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "1",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x02],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "1",
                "asterix.019_551_TP4B": "0"
            }
        )
        validator.add_dissection(
            [0x08, 0x01],
            "asterix.019_551",
            {
                "asterix.019_551_TP1A": "0",
                "asterix.019_551_TP1B": "0",
                "asterix.019_551_TP2A": "0",
                "asterix.019_551_TP2B": "0",
                "asterix.019_551_TP3A": "0",
                "asterix.019_551_TP3B": "0",
                "asterix.019_551_TP4A": "0",
                "asterix.019_551_TP4B": "1"
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
                    "asterix.019_552_RSI": "0xff",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "0"
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
                    "asterix.019_552_RSI": "0x00",
                    "asterix.019_552_RS1090": "1",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "0"
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
                    "asterix.019_552_RSI": "0x00",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "1",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "0"
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
                    "asterix.019_552_RSI": "0x00",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "1",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "0"
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
                    "asterix.019_552_RSI": "0x00",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "1",
                    "asterix.019_552_RSO": "0"
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
                    "asterix.019_552_RSI": "0x00",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "1"
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
                    "asterix.019_552_RSI": "18",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "1",
                    "asterix.019_552_TX1090": "1",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "1"
                },
                "asterix.019_552":
                {
                    "asterix.019_552_RSI": "86",
                    "asterix.019_552_RS1090": "1",
                    "asterix.019_552_TX1030": "1",
                    "asterix.019_552_TX1090": "1",
                    "asterix.019_552_RSS": "1",
                    "asterix.019_552_RSO": "0"
                },
                "asterix.019_552":
                {
                    "asterix.019_552_RSI": "0x9a",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "1",
                    "asterix.019_552_RSO": "1"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0xc0],
            "asterix.019_553",
            {
                "asterix.019_553_REFTR1": "3",
                "asterix.019_553_REFTR2": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x02, 0x0c],
            "asterix.019_553",
            {
                "asterix.019_553_REFTR1": "0",
                "asterix.019_553_REFTR2": "3",
                "asterix.FX": "0"
            }
        )
        '''TODO: check this testcase, it has too many subitems
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
        '''
        validator.add_dissection(
            [0x01, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "90",
                "asterix.019_600_LON": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "-90",
                "asterix.019_600_LON": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "0",
                "asterix.019_600_LON": "180"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "0",
                "asterix.019_600_LON": "-180"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x7f, 0xff],
            "asterix.019_610",
            {
                "asterix.019_610_VALUE": "8191.75"
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x80, 0x00],
            "asterix.019_610",
            {
                "asterix.019_610_VALUE": "-8192"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x7f],
            "asterix.019_620",
            {
                "asterix.019_620_VALUE": "127"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x81],
            "asterix.019_620",
            {
                "asterix.019_620_VALUE": "-127"
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
                "asterix.019_000_VALUE": "255"
            }
        )
        validator.add_dissection(
            [0x20, 0xff, 0xff, 0xff],
            "asterix.019_140",
            {
                "asterix.019_140_VALUE": "131071.9921875"
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
                    "asterix.019_552_RSI": "0x00",
                    "asterix.019_552_RS1090": "0",
                    "asterix.019_552_TX1030": "0",
                    "asterix.019_552_TX1090": "0",
                    "asterix.019_552_RSS": "0",
                    "asterix.019_552_RSO": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x32],
            "asterix.019_553",
            {
                "asterix.019_553_REFTR1": "0",
                "asterix.019_553_REFTR2": "0",
                "asterix.FX": "0"
            }
        )
        '''TODO: check this testcase, it has too many subitems
        validator.add_dissection(
            [0x02, 0x33, 0x33, 0x32],
            "asterix.019_553",
            {
                "asterix.019_553_REFTR1": "0",
                "asterix.019_553_REFTR2": "0",
                "asterix.019_553_REFTR3": "0",
                "asterix.019_553_REFTR4": "0",
                "asterix.019_553_Ref_Trans_5_Status": "0",
                "asterix.019_553_Ref_Trans_6_Status": "0",
                "asterix.FX": "0"
            }
        )
        '''
        validator.add_dissection(
            [0x01, 0x80, 0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "359.999999832362",
                "asterix.019_600_LON": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "-360",
                "asterix.019_600_LON": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "0",
                "asterix.019_600_LON": "359.999999832362"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00],
            "asterix.019_600",
            {
                "asterix.019_600_LAT": "0",
                "asterix.019_600_LON": "-360"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x80],
            "asterix.019_620",
            {
                "asterix.019_620_VALUE": "-128"
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
        '''TODO: re-enable RE and SP tests when implemented
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
        '''

        validator.check_dissections()


# Fails after automatic updates on December 3, 2023 / MR 13535
class _disabled_TestCategory034:
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

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(34)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.034_010",
            {
                "asterix.034_010_SAC": "0xff",
                "asterix.034_010_SIC": "0x00"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.034_010",
            {
                "asterix.034_010_SAC": "0x00",
                "asterix.034_010_SIC": "0xff"
            }
        )
        validator.add_dissection(
            [0x40, 0x04],
            "asterix.034_000",
            {
                "asterix.034_000_VALUE": "4"
            }
        )
        validator.add_dissection(
            [0x20, 0xa8, 0xbf, 0xff],
            "asterix.034_030",
            {
                "asterix.034_030_VALUE": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x10, 0xff],
            "asterix.034_020",
            {
                "asterix.034_020_VALUE": "358.59375"
            }
        )
        validator.add_dissection(
            [0x08, 0xff, 0xff],
            "asterix.034_041",
            {
                "asterix.034_041_VALUE": "511.9921875"
            }
        )
        x_050_COM = {
            "asterix.034_050_COM_NOGO": "0",
            "asterix.034_050_COM_RDPC": "0",
            "asterix.034_050_COM_RDPR": "0",
            "asterix.034_050_COM_OVLRDP": "0",
            "asterix.034_050_COM_OVLXMT": "0",
            "asterix.034_050_COM_MSC": "0",
            "asterix.034_050_COM_TSV": "0"
        }
        validator.add_dissection(
            [0x04, 0x80, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "NOGO", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x40],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "RDPC", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x20],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "RDPR", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x10],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "OVLRDP", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x08],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "OVLXMT", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x04],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "MSC", "1")
        )
        validator.add_dissection(
            [0x04, 0x80, 0x02],
            "asterix.034_050",
            dict_fspec_local(x_050_COM, "034_050_COM", "TSV", "1")
        )
        x_050_PSR = {
            "asterix.034_050_PSR_ANT": "0",
            "asterix.034_050_PSR_CHAB": "0",
            "asterix.034_050_PSR_OVL": "0",
            "asterix.034_050_PSR_MSC": "0"
        }
        validator.add_dissection(
            [0x04, 0x10, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_PSR, "034_050_PSR", "ANT", "1")
        )
        validator.add_dissection(
            [0x04, 0x10, 0x60],
            "asterix.034_050",
            dict_fspec_local(x_050_PSR, "034_050_PSR", "CHAB", "3")
        )
        validator.add_dissection(
            [0x04, 0x10, 0x10],
            "asterix.034_050",
            dict_fspec_local(x_050_PSR, "034_050_PSR", "OVL", "1")
        )
        validator.add_dissection(
            [0x04, 0x10, 0x08],
            "asterix.034_050",
            dict_fspec_local(x_050_PSR, "034_050_PSR", "MSC", "1")
        )
        x_050_SSR = {
            "asterix.034_050_SSR_ANT": "0",
            "asterix.034_050_SSR_CHAB": "0",
            "asterix.034_050_SSR_OVL": "0",
            "asterix.034_050_SSR_MSC": "0"
        }
        validator.add_dissection(
            [0x04, 0x08, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_SSR, "034_050_SSR", "ANT", "1")
        )
        validator.add_dissection(
            [0x04, 0x08, 0x60],
            "asterix.034_050",
            dict_fspec_local(x_050_SSR, "034_050_SSR", "CHAB", "3")
        )
        validator.add_dissection(
            [0x04, 0x08, 0x10],
            "asterix.034_050",
            dict_fspec_local(x_050_SSR, "034_050_SSR", "OVL", "1")
        )
        validator.add_dissection(
            [0x04, 0x08, 0x08],
            "asterix.034_050",
            dict_fspec_local(x_050_SSR, "034_050_SSR", "MSC", "1")
        )
        x_050_MDS = {
            "asterix.034_050_MDS_ANT": "0",
            "asterix.034_050_MDS_CHAB": "0",
            "asterix.034_050_MDS_OVLSUR": "0",
            "asterix.034_050_MDS_MSC": "0",
            "asterix.034_050_MDS_SCF": "0",
            "asterix.034_050_MDS_DLF": "0",
            "asterix.034_050_MDS_OVLSCF": "0",
            "asterix.034_050_MDS_OVLDLF": "0"
        }
        validator.add_dissection(
            [0x04, 0x04, 0x80, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "ANT", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x60, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "CHAB", "3")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x10, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "OVLSUR", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x08, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "MSC", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x04, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "SCF", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x02, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "DLF", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x01, 0x00],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "OVLSCF", "1")
        )
        validator.add_dissection(
            [0x04, 0x04, 0x00, 0x80],
            "asterix.034_050",
            dict_fspec_local(x_050_MDS, "034_050_MDS", "OVLDLF", "1")
        )
        x_060_COM = {
            "asterix.034_060_COM_REDRDP": "0",
            "asterix.034_060_COM_REDXMT": "0"
        }
        validator.add_dissection(
            [0x02, 0x80, 0x70],
            "asterix.034_060",
            dict_fspec_local(x_060_COM, "034_060_COM", "REDRDP", "7")
        )
        validator.add_dissection(
            [0x02, 0x80, 0x0e],
            "asterix.034_060",
            dict_fspec_local(x_060_COM, "034_060_COM", "REDXMT", "7")
        )
        x_060_PSR = {
            "asterix.034_060_PSR_POL": "0",
            "asterix.034_060_PSR_REDRAD": "0",
            "asterix.034_060_PSR_STC": "0"
        }
        validator.add_dissection(
            [0x02, 0x10, 0x80],
            "asterix.034_060",
            dict_fspec_local(x_060_PSR, "034_060_PSR", "POL", "1")
        )
        validator.add_dissection(
            [0x02, 0x10, 0x70],
            "asterix.034_060",
            dict_fspec_local(x_060_PSR, "034_060_PSR", "REDRAD", "7")
        )
        validator.add_dissection(
            [0x02, 0x10, 0x0c],
            "asterix.034_060",
            dict_fspec_local(x_060_PSR, "034_060_PSR", "STC", "3")
        )
        validator.add_dissection(
            [0x02, 0x08, 0xe0],
            "asterix.034_060",
            fspec_local("034_060_SSR", "REDRAD", "7")
        )
        x_060_06 = {
            "asterix.034_060_MDS_REDRAD": "0",
            "asterix.034_060_MDS_CLU": "0"
        }
        validator.add_dissection(
            [0x02, 0x04, 0xe0],
            "asterix.034_060",
            dict_fspec_local(x_060_06, "034_060_MDS", "REDRAD", "7")
        )
        validator.add_dissection(
            [0x02, 0x04, 0x10],
            "asterix.034_060",
            dict_fspec_local(x_060_06, "034_060_MDS", "CLU", "1")
        )
        x_070 = {
            "asterix.034_070_TYP": "0",
            "asterix.034_070_COUNT": "0"
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
                    "asterix.034_070_COUNT": "2047"
                },
                "asterix.034_070":
                dict_local(x_070, "034_070", "COUNT", "2047"),
            }
        )
        x_100 = {
            "asterix.034_100_RHOST": "0",
            "asterix.034_100_RHOEND": "0",
            "asterix.034_100_THETAST": "0",
            "asterix.034_100_THETAEND": "0"
        }
        validator.add_dissection(
            [0x01, 0x40, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_100",
            dict_local(x_100, "034_100", "RHOST", "255.99609375")
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_100",
            dict_local(x_100, "034_100", "RHOEND", "255.99609375")
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00],
            "asterix.034_100",
            dict_local(x_100, "034_100", "THETAST", "359.994506835938")
        )
        validator.add_dissection(
            [0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff],
            "asterix.034_100",
            dict_local(x_100, "034_100", "THETAEND", "359.994506835938")
        )
        validator.add_dissection(
            [0x01, 0x20, 0x09],
            "asterix.034_110",
            {
                "asterix.034_110_VALUE": "9"
            }
        )
        x_120 = {
            "asterix.034_120_HGT": "0",
            "asterix.034_120_LAT": "0",
            "asterix.034_120_LON": "0"
        }
        validator.add_dissection(
            [0x01, 0x10, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "HGT", "32767")
        )
        validator.add_dissection(
            [0x01, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.034_120",
            dict_local(x_120, "034_120", "HGT", "32768")
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
        '''TODO: re-enable RE and SP tests when implemented
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
        '''

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_validator):
        '''verifies that the dissector can dissect undefined field values by setting
        the maximum value of bits or by setting all undefined bits'''

        validator = asterix_validator(34)

        validator.add_dissection(
            [0x40, 0xff],
            "asterix.034_000",
            {
                "asterix.034_000_VALUE": "255"
            }
        )
        validator.add_dissection(
            [0x20, 0xff, 0xff, 0xff],
            "asterix.034_030",
            {
                "asterix.034_030_VALUE": "131071.9921875"
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
                "asterix.034_050_COM":
                {
                    "asterix.034_050_COM_NOGO": "0",
                    "asterix.034_050_COM_RDPC": "0",
                    "asterix.034_050_COM_RDPR": "0",
                    "asterix.034_050_COM_OVLRDP": "0",
                    "asterix.034_050_COM_OVLXMT": "0",
                    "asterix.034_050_COM_MSC": "0",
                    "asterix.034_050_COM_TSV": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x10, 0x07],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_PSR":
                {
                    "asterix.034_050_PSR_ANT": "0",
                    "asterix.034_050_PSR_CHAB": "0",
                    "asterix.034_050_PSR_OVL": "0",
                    "asterix.034_050_PSR_MSC": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x08, 0x07],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_SSR":
                {
                    "asterix.034_050_SSR_ANT": "0",
                    "asterix.034_050_SSR_CHAB": "0",
                    "asterix.034_050_SSR_OVL": "0",
                    "asterix.034_050_SSR_MSC": "0"
                }
            }
        )
        validator.add_dissection(
            [0x04, 0x04, 0x00, 0x7f],
            "asterix.034_050",
            {
                "asterix.fspec": "",
                "asterix.034_050_MDS":
                {
                    "asterix.034_050_MDS_ANT": "0",
                    "asterix.034_050_MDS_CHAB": "0",
                    "asterix.034_050_MDS_OVLSUR": "0",
                    "asterix.034_050_MDS_MSC": "0",
                    "asterix.034_050_MDS_SCF": "0",
                    "asterix.034_050_MDS_DLF": "0",
                    "asterix.034_050_MDS_OVLSCF": "0",
                    "asterix.034_050_MDS_OVLDLF": "0"
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
                "asterix.034_060_COM":
                {
                    "asterix.034_060_COM_REDRDP": "0",
                    "asterix.034_060_COM_REDXMT": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x10, 0x03],
            "asterix.034_060",
            {
                "asterix.fspec": "",
                "asterix.034_060_PSR":
                {
                    "asterix.034_060_PSR_POL": "0",
                    "asterix.034_060_PSR_REDRAD": "0",
                    "asterix.034_060_PSR_STC": "0"
                }
            }
        )
        validator.add_dissection(
            [0x02, 0x08, 0x1f],
            "asterix.034_060",
            fspec_local("034_060_SSR", "REDRAD", "0")
        )
        validator.add_dissection(
            [0x02, 0x04, 0x0f],
            "asterix.034_060",
            {
                "asterix.fspec": "",
                "asterix.034_060_MDS":
                {
                    "asterix.034_060_MDS_REDRAD": "0",
                    "asterix.034_060_MDS_CLU": "0"
                }
            }
        )
        x_070 = {
            "asterix.034_070_TYP": "0",
            "asterix.034_070_COUNT": "0"
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
                "asterix.034_110_VALUE": "255"
            }
        )
        '''TODO: re-enable RE and SP tests when implemented
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
        '''

        validator.check_dissections()


class TestCategory048:
    '''
    Unittest case for ASTERIX Category 048

    Online specification:
    https://www.eurocontrol.int/publications/cat048-monoradar-target-reports-part-4-next-version-cat-001
    https://www.eurocontrol.int/publications/cat048-reserved-expansion-field-part-4-appendix

    Part 4 Category 048
    Monoradar Target Reports

    Standard User Application Profile

    FRN Data Item Information                                        Length
     1  I048/010  Data Source Identifier                              2
     2  I048/140  Time-of-Day                                         3
     3  I048/020  Target Report Descriptor                            1+
     4  I048/040  Measured Position in Slant Polar Coordinates        4
     5  I048/070  Mode-3/A Code in Octal Representation               2
     6  I048/090  Flight Level in Binary Representation               2
     7  I048/130  Radar Plot Characteristics                          1+1+
    FX  n.a.      Field Extension Indicator                           n.a.
     8  I048/220  Aircraft Address                                    3
     9  I048/240  Aircraft Identification                             6
    10  I048/250  Mode S MB Data                                      1+8*n
    11  I048/161  Track Number                                        2
    12  I048/042  Calculated Position in Cartesian Coordinates        4
    13  I048/200  Calculated Track Velocity in Polar Representation   4
    14  I048/170  Track Status                                        1+
    FX  n.a.      Field Extension Indicator                           n.a.
    15  I048/210  Track Quality                                       4
    16  I048/030  Warning/Error Conditions                            1+
    17  I048/080  Mode-3/A Code Confidence Indicator                  2
    18  I048/100  Mode-C Code and Confidence Indicator                4
    19  I048/110  Height Measured by 3D Radar                         2
    20  I048/120  Radial Doppler Speed                                1+
    21  I048/230  Communications / ACAS Capability and Flight Status  2
    FX  n.a.      Field Extension Indicator                           n.a.
    22  I048/260  ACAS Resolution Advisory Report                     7
    23  I048/055  Mode-1 Code in Octal Representation                 1
    24  I048/050  Mode-2 Code in Octal Representation                 2
    25  I048/065  Mode-1 Code Confidence Indicator                    1
    26  I048/060  Mode-2 Code Confidence Indicator                    2
    27  SP-Data   Item Special Purpose Field                          1+1+
    28  RE-Data   Item Reserved Expansion Field                       1+1+
    FX  n.a.      Field Extension Indicator                           n.a.
    '''

    def test_for_fields(self, asterix_re_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_re_validator(48, [0x01, 0x01, 0x01, 0x02])

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.048_010",
            {
                "asterix.048_010_SAC": "0xff",
                "asterix.048_010_SIC": "0x00"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.048_010",
            {
                "asterix.048_010_SAC": "0x00",
                "asterix.048_010_SIC": "0xff"
            }
        )
        validator.add_dissection(
            [0x40, 0xa8, 0xbf, 0xff],
            "asterix.048_140",
            {
                "asterix.048_140_VALUE": "86399.9921875"
            }
        )
        x_020 = {
            "asterix.048_020_TYP": "0",
            "asterix.048_020_SIM": "0",
            "asterix.048_020_RDP": "0",
            "asterix.048_020_SPI": "0",
            "asterix.048_020_RAB": "0",
            "asterix.FX": "0"
        }
        validator.add_dissection(
            [0x20, 0xe0],
            "asterix.048_020",
            dict_local(x_020, "048_020", "TYP", "7")
        )
        validator.add_dissection(
            [0x20, 0x08],
            "asterix.048_020",
            dict_local(x_020, "048_020", "RDP", "1")
        )
        validator.add_dissection(
            [0x20, 0x04],
            "asterix.048_020",
            dict_local(x_020, "048_020", "SPI", "1")
        )
        validator.add_dissection(
            [0x20, 0x02],
            "asterix.048_020",
            dict_local(x_020, "048_020", "RAB", "1")
        )
        x_020.update({
            "asterix.048_020_TST": "0",
            "asterix.048_020_ERR": "0",
            "asterix.048_020_XPP": "0",
            "asterix.048_020_ME": "0",
            "asterix.048_020_MI": "0",
            "asterix.048_020_FOEFRI": "0"
        })
        validator.add_dissection(
            [0x20, 0x01, 0x80],
            "asterix.048_020",
            dict_local(x_020, "048_020", "TST", "1")
        )
        validator.add_dissection(
            [0x20, 0x01, 0x40],
            "asterix.048_020",
            dict_local(x_020, "048_020", "ERR", "1")
        )
        validator.add_dissection(
            [0x20, 0x01, 0x20],
            "asterix.048_020",
            dict_local(x_020, "048_020", "XPP", "1")
        )
        validator.add_dissection(
            [0x20, 0x01, 0x10],
            "asterix.048_020",
            dict_local(x_020, "048_020", "ME", "1")
        )
        validator.add_dissection(
            [0x20, 0x01, 0x08],
            "asterix.048_020",
            dict_local(x_020, "048_020", "MI", "1")
        )
        validator.add_dissection(
            [0x20, 0x01, 0x06],
            "asterix.048_020",
            dict_local(x_020, "048_020", "FOEFRI", "3")
        )
        x_040 = {
            "asterix.048_040_RHO": "0",
            "asterix.048_040_THETA": "0"
        }
        validator.add_dissection(
            [0x10, 0xff, 0xff, 0x00, 0x00],
            "asterix.048_040",
            dict_local(x_040, "048_040", "RHO", "255.99609375")
        )
        validator.add_dissection(
            [0x10, 0x00, 0x00, 0xff, 0xff],
            "asterix.048_040",
            dict_local(x_040, "048_040", "THETA", "359.994506835938")
        )
        x_070 = {
            "asterix.048_070_V": "0",
            "asterix.048_070_G": "0",
            "asterix.048_070_L": "0",
            "asterix.048_070_MODE3A": "0"
        }
        validator.add_dissection(
            [0x08, 0x80, 0x00],
            "asterix.048_070",
            dict_local(x_070, "048_070", "V", "1")
        )
        validator.add_dissection(
            [0x08, 0x40, 0x00],
            "asterix.048_070",
            dict_local(x_070, "048_070", "G", "1")
        )
        validator.add_dissection(
            [0x08, 0x20, 0x00],
            "asterix.048_070",
            dict_local(x_070, "048_070", "L", "1")
        )
        validator.add_dissection(
            [0x08, 0x0e, 0x00],
            "asterix.048_070",
            dict_local(x_070, "048_070", "MODE3A", "3584")  # 07000
        )
        validator.add_dissection(
            [0x08, 0x01, 0xc0],
            "asterix.048_070",
            dict_local(x_070, "048_070", "MODE3A", "448")  # 0700
        )
        validator.add_dissection(
            [0x08, 0x00, 0x38],
            "asterix.048_070",
            dict_local(x_070, "048_070", "MODE3A", "56")  # 070
        )
        validator.add_dissection(
            [0x08, 0x00, 0x07],
            "asterix.048_070",
            dict_local(x_070, "048_070", "MODE3A", "7")  # 07
        )
        x_090 = {
            "asterix.048_090_V": "0",
            "asterix.048_090_G": "0",
            "asterix.048_090_FL": "0"
        }
        validator.add_dissection(
            [0x04, 0x80, 0x00],
            "asterix.048_090",
            dict_local(x_090, "048_090", "V", "1")
        )
        validator.add_dissection(
            [0x04, 0x40, 0x00],
            "asterix.048_090",
            dict_local(x_090, "048_090", "G", "1")
        )
        validator.add_dissection(
            [0x04, 0x1f, 0xff],
            "asterix.048_090",
            dict_local(x_090, "048_090", "FL", "2047.75")
        )
        validator.add_dissection(
            [0x04, 0x20, 0x00],
            "asterix.048_090",
            dict_local(x_090, "048_090", "FL", "2048")
        )
        validator.add_dissection(
            [0x02, 0x80, 0xff],
            "asterix.048_130",
            fspec_local("048_130_SRL", "VALUE", "11.2060546875")
        )
        validator.add_dissection(
            [0x02, 0x40, 0xff],
            "asterix.048_130",
            fspec_local("048_130_SRR", "VALUE", "255")
        )
        validator.add_dissection(
            [0x02, 0x20, 0x7f],
            "asterix.048_130",
            fspec_local("048_130_SAM", "VALUE", "127")
        )
        validator.add_dissection(
            [0x02, 0x20, 0x80],
            "asterix.048_130",
            fspec_local("048_130_SAM", "VALUE", "-128")
        )
        validator.add_dissection(
            [0x02, 0x10, 0xff],
            "asterix.048_130",
            fspec_local("048_130_PRL", "VALUE", "11.2060546875")
        )
        validator.add_dissection(
            [0x02, 0x08, 0x7f],
            "asterix.048_130",
            fspec_local("048_130_PAM", "VALUE", "127")
        )
        validator.add_dissection(
            [0x02, 0x08, 0x80],
            "asterix.048_130",
            fspec_local("048_130_PAM", "VALUE", "-128")
        )
        validator.add_dissection(
            [0x02, 0x04, 0x7f],
            "asterix.048_130",
            fspec_local("048_130_RPD", "VALUE", "0.49609375")
        )
        validator.add_dissection(
            [0x02, 0x04, 0x80],
            "asterix.048_130",
            fspec_local("048_130_RPD", "VALUE", "-0.5")
        )
        validator.add_dissection(
            [0x02, 0x02, 0x7f],
            "asterix.048_130",
            fspec_local("048_130_APD", "VALUE", "2.79052734375")
        )
        validator.add_dissection(
            [0x02, 0x02, 0x80],
            "asterix.048_130",
            fspec_local("048_130_APD", "VALUE", "-2.8125")
        )
        validator.add_dissection(
            [0x01, 0x80, 0xff, 0xff, 0xff],
            "asterix.048_220",
            {
                "asterix.048_220_VALUE": '0xffffff'
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0xff, 0xff, 0xff],
            "asterix.048_220",
            {
                "asterix.048_220_VALUE": '0xffffff'
            }
        )
        validator.add_dissection(
            [0x01, 0x40, 0x04, 0x20, 0xda, 0x83, 0x0c, 0x79],
            "asterix.048_240",
            {
                "asterix.048_240_VALUE": "ABCZ 019"
            }
        )
        x_250 = {
            "asterix.048_250_MBDATA": "00:00:00:00:00:00:00",
            "asterix.048_250_BDS1": "0",
            "asterix.048_250_BDS2": "0"
        }
        validator.add_dissection(
            [0x01, 0x20,
             0x01,
             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
             0x00],
            "asterix.048_250",
            {
                "asterix.counter": "1",
                "asterix.048_250":
                    dict_global(x_250, "048_250_MBDATA", '0x0011223344556677'),
            }
        )
        '''TODO: result seems correct, check dict format
        validator.add_dissection(
            [0x01, 0x20,
             0x01,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0xf0],
            "asterix.048_250",
            {
                "asterix.counter": "1",
                "asterix.048_250":
                    dict_global(x_250, "048_250_BDS1", "15"),
            }
        )
        validator.add_dissection(
            [0x01, 0x20,
             0x01,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x0f],
            "asterix.048_250",
            {
                "asterix.counter": "1",
                "asterix.048_250":
                dict_global(x_250, "BDS2", "15"),
            }
        )
        validator.add_dissection(
            [0x01, 0x20,
             0x03,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0xf0,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x0f],
            "asterix.048_250",
            {
                "asterix.counter": "3",
                "asterix.048_250":
                    dict_global(x_250, "048_250_MBDATA", '0x0011223344556677'),
                "asterix.048_250":
                    dict_global(x_250, "048_250_BDS1", "15"),
                "asterix.048_250":
                    dict_global(x_250, "048_250_BDS2", "15"),
            }
        )
        '''
        validator.add_dissection(
            [0x01, 0x10, 0x0f, 0xff],
            "asterix.048_161",
            {
                "asterix.048_161_TRN": "4095"
            }
        )
        x_042 = {
            "asterix.048_042_X": "0",
            "asterix.048_042_Y": "0"
        }
        validator.add_dissection(
            [0x01, 0x08, 0x7f, 0xff, 0x00, 0x00],
            "asterix.048_042",
            dict_local(x_042, "048_042", "X", "255.9921875")
        )
        validator.add_dissection(
            [0x01, 0x08, 0x80, 0x00, 0x00, 0x00],
            "asterix.048_042",
            dict_local(x_042, "048_042", "X", "-256")
        )
        validator.add_dissection(
            [0x01, 0x08, 0x00, 0x0, 0x7f, 0xff],
            "asterix.048_042",
            dict_local(x_042, "048_042", "Y", "255.9921875")
        )
        validator.add_dissection(
            [0x01, 0x08, 0x00, 0x0, 0x80, 0x00],
            "asterix.048_042",
            dict_local(x_042, "048_042", "Y", "-256")
        )
        x_200 = {
            "asterix.048_200_GSP": "0",
            "asterix.048_200_HDG": "0"
        }
        validator.add_dissection(
            [0x01, 0x04, 0xff, 0xff, 0x00, 0x00],
            "asterix.048_200",
            dict_local(x_200, "048_200", "GSP", "3.99993896484375")
        )
        validator.add_dissection(
            [0x01, 0x04, 0x00, 0x00, 0xff, 0xff],
            "asterix.048_200",
            dict_local(x_200, "048_200", "HDG", "359.994506835938")
        )
        x_170 = {
            "asterix.048_170_CNF": "0",
            "asterix.048_170_RAD": "0",
            "asterix.048_170_DOU": "0",
            "asterix.048_170_MAH": "0",
            "asterix.048_170_CDM": "0",
            "asterix.FX": "0"
        }
        validator.add_dissection(
            [0x01, 0x02, 0x80],
            "asterix.048_170",
            dict_local(x_170, "048_170", "CNF", "1")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x60],
            "asterix.048_170",
            dict_local(x_170, "048_170", "RAD", "3")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x10],
            "asterix.048_170",
            dict_local(x_170, "048_170", "DOU", "1")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x08],
            "asterix.048_170",
            dict_local(x_170, "048_170", "MAH", "1")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x06],
            "asterix.048_170",
            dict_local(x_170, "048_170", "CDM", "3")
        )
        x_170.update({
            "asterix.048_170_TRE": "0",
            "asterix.048_170_GHO": "0",
            "asterix.048_170_SUP": "0",
            "asterix.048_170_TCC": "0"
        })
        validator.add_dissection(
            [0x01, 0x02, 0x01, 0x80],
            "asterix.048_170",
            dict_local(x_170, "048_170", "TRE", "1")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01, 0x40],
            "asterix.048_170",
            dict_local(x_170, "048_170", "GHO", "1")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01, 0x20],
            "asterix.048_170",
            dict_local(x_170, "048_170", "SUP", "1")
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01, 0x10],
            "asterix.048_170",
            dict_local(x_170, "048_170", "TCC", "1")
        )
        x_210 = {
            "asterix.048_210_SIGX": "0",
            "asterix.048_210_SIGY": "0",
            "asterix.048_210_SIGV": "0",
            "asterix.048_210_SIGH": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x80, 0xff, 0x00, 0x00, 0x00],
            "asterix.048_210",
            dict_local(x_210, "048_210", "SIGX", "1.9921875")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x80, 0x00, 0xff, 0x00, 0x00],
            "asterix.048_210",
            dict_local(x_210, "048_210", "SIGY", "1.9921875")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x80, 0x00, 0x00, 0xff, 0x00],
            "asterix.048_210",
            dict_local(x_210, "048_210", "SIGV", "0.01556396484375")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x80, 0x00, 0x00, 0x00, 0xff],
            "asterix.048_210",
            dict_local(x_210, "048_210", "SIGH", "22.412109375")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x40, 0x2e],
            "asterix.048_030",
            {
                "asterix.048_030_Subitem": "23",
                "asterix.FX": "0"
            }
        )
        '''TODO: check this test, not according to the specs
        validator.add_dissection(
            [0x01, 0x01, 0x40, 0x2f, 0x03, 0x05, 0x06],
            "asterix.048_030",
            {
                "asterix.048_030_WE": "23",
                "asterix.048_030_1_WE": "1",
                "asterix.048_030_2_WE": "2",
                "asterix.048_030_3_WE": "3",
                "asterix.FX": "0"
            }
        )
        '''
        x_080 = {
            "asterix.048_080_QA4": "0",
            "asterix.048_080_QA2": "0",
            "asterix.048_080_QA1": "0",
            "asterix.048_080_QB4": "0",
            "asterix.048_080_QB2": "0",
            "asterix.048_080_QB1": "0",
            "asterix.048_080_QC4": "0",
            "asterix.048_080_QC2": "0",
            "asterix.048_080_QC1": "0",
            "asterix.048_080_QD4": "0",
            "asterix.048_080_QD2": "0",
            "asterix.048_080_QD1": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x08, 0x00],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QA4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x04, 0x00],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QA2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x02, 0x00],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QA1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x01, 0x00],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QB4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x80],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QB2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x40],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QB1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x20],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QC4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x10],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QC2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x08],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QC1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x04],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QD4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x02],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QD2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0x00, 0x01],
            "asterix.048_080",
            dict_local(x_080, "048_080", "QD1", "1")
        )
        '''TODO: A,B,C,D values need to go to single subitem 'MODEC'
        x_100 = {
            "asterix.048_100_V": "0",
            "asterix.048_100_G": "0",
            "asterix.048_100_C1": "0",
            "asterix.048_100_A1": "0",
            "asterix.048_100_C2": "0",
            "asterix.048_100_A2": "0",
            "asterix.048_100_C4": "0",
            "asterix.048_100_A4": "0",
            "asterix.048_100_B1": "0",
            "asterix.048_100_D1": "0",
            "asterix.048_100_B2": "0",
            "asterix.048_100_D2": "0",
            "asterix.048_100_B4": "0",
            "asterix.048_100_D4": "0",
            "asterix.048_100_QC1": "0",
            "asterix.048_100_QA1": "0",
            "asterix.048_100_QC2": "0",
            "asterix.048_100_QA2": "0",
            "asterix.048_100_QC4": "0",
            "asterix.048_100_QA4": "0",
            "asterix.048_100_QB1": "0",
            "asterix.048_100_QD1": "0",
            "asterix.048_100_QB2": "0",
            "asterix.048_100_QD2": "0",
            "asterix.048_100_QB4": "0",
            "asterix.048_100_QD4": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x80, 0x00, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "V", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x40, 0x00, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "G", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x08, 0x00, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "C1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x04, 0x00, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "A1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "C2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x01, 0x00, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "A2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x80, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "C4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x40, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "A4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x20, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "B1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x10, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "D1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x08, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "B2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x04, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "D2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x02, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "B4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "D4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x08, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QC1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x04, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QA1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x02, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QC2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x01, 0x00],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QA2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x80],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QC4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x40],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QA4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x20],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QB1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x10],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QD1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x08],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QB2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x04],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QD2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x02],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QB4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01],
            "asterix.048_100",
            dict_local(x_100, "048_100", "QD4", "1")
        )
        '''
        validator.add_dissection(
            [0x01, 0x01, 0x08, 0x1f, 0xff],
            "asterix.048_110",
            {
                "asterix.048_110_3DH": "204775"
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x08, 0x20, 0x00],
            "asterix.048_110",
            {
                "asterix.048_110_3DH": "-204800"
            }
        )
        x_120_01 = {
            "asterix.048_120_CAL_D": "0",
            "asterix.048_120_CAL_CAL": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x80, 0x80, 0x00],
            "asterix.048_120",
            dict_fspec_local(x_120_01, "048_120_CAL", "D", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x80, 0x01, 0xff],
            "asterix.048_120",
            dict_fspec_local(x_120_01, "048_120_CAL", "CAL", "511")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x80, 0x02, 0x00],
            "asterix.048_120",
            dict_fspec_local(x_120_01, "048_120_CAL", "CAL", "-512")
        )
        x_120_RDS = {
            "asterix.048_120_RDS_DOP": "0",
            "asterix.048_120_RDS_AMB": "0",
            "asterix.048_120_RDS_FRQ": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x40, 0x01, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x00],
            "asterix.048_120",
            counter_local(x_120_RDS, "1", "048_120_RDS", "DOP", "32767")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x40, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00],
            "asterix.048_120",
            counter_local(x_120_RDS, "1", "048_120_RDS", "DOP", "32768")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x40, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00],
            "asterix.048_120",
            counter_local(x_120_RDS, "1", "048_120_RDS", "AMB", "65535")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff],
            "asterix.048_120",
            counter_local(x_120_RDS, "1", "048_120_RDS", "FRQ", "65535")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x40, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
             0xff],
            "asterix.048_120",
            {
                "asterix.fspec": "",
                "asterix.048_120_RDS":
                {
                    "asterix.counter": "3",
                    "asterix.048_120_RDS":
                    dict_local(x_120_RDS, "048_120_RDS", "DOP", "-32768"),
                    "asterix.048_120_RDS":
                    dict_local(x_120_RDS, "048_120_RDS", "AMB", "65535"),
                    "asterix.048_120_RDS":
                    dict_local(x_120_RDS, "048_120_RDS", "FRQ", "65535")
                }
            }
        )
        x_230 = {
            "asterix.048_230_COM": "0",
            "asterix.048_230_STAT": "0",
            "asterix.048_230_SI": "0",
            "asterix.048_230_MSSC": "0",
            "asterix.048_230_ARC": "0",
            "asterix.048_230_AIC": "0",
            "asterix.048_230_B1A": "0",
            "asterix.048_230_B1B": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0xe0, 0x00],
            "asterix.048_230",
            dict_local(x_230, "048_230", "COM", "7")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x1c, 0x00],
            "asterix.048_230",
            dict_local(x_230, "048_230", "STAT", "7")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x02, 0x00],
            "asterix.048_230",
            dict_local(x_230, "048_230", "SI", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x00, 0x80],
            "asterix.048_230",
            dict_local(x_230, "048_230", "MSSC", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x00, 0x40],
            "asterix.048_230",
            dict_local(x_230, "048_230", "ARC", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x00, 0x20],
            "asterix.048_230",
            dict_local(x_230, "048_230", "AIC", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x00, 0x10],
            "asterix.048_230",
            dict_local(x_230, "048_230", "B1A", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x00, 0x0f],
            "asterix.048_230",
            dict_local(x_230, "048_230", "B1B", "15")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            "asterix.048_260",
            {
                "asterix.048_260_VALUE": '0x0011223344556677'
            }
        )
        x_055 = {
            "asterix.048_055_V": "0",
            "asterix.048_055_G": "0",
            "asterix.048_055_L": "0",
            "asterix.048_055_MODE1": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x40, 0x80],
            "asterix.048_055",
            dict_local(x_055, "048_055", "V", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x40, 0x40],
            "asterix.048_055",
            dict_local(x_055, "048_055", "G", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x40, 0x20],
            "asterix.048_055",
            dict_local(x_055, "048_055", "L", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x40, 0x1f],
            "asterix.048_055",
            dict_local(x_055, "048_055", "MODE1", "31")
        )
        x_050 = {
            "asterix.048_050_V": "0",
            "asterix.048_050_G": "0",
            "asterix.048_050_L": "0",
            "asterix.048_050_MODE2": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x20, 0x80, 0x00],
            "asterix.048_050",
            dict_local(x_050, "048_050", "V", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x20, 0x40, 0x00],
            "asterix.048_050",
            dict_local(x_050, "048_050", "G", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x20, 0x20, 0x00],
            "asterix.048_050",
            dict_local(x_050, "048_050", "L", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x20, 0x0f, 0xff],
            "asterix.048_050",
            dict_local(x_050, "048_050", "MODE2", "4095")
        )
        x_065 = {
            "asterix.048_065_QA4": "0",
            "asterix.048_065_QA2": "0",
            "asterix.048_065_QA1": "0",
            "asterix.048_065_QB2": "0",
            "asterix.048_065_QB1": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x10, 0x10],
            "asterix.048_065",
            dict_local(x_065, "048_065", "QA4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x10, 0x08],
            "asterix.048_065",
            dict_local(x_065, "048_065", "QA2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x10, 0x04],
            "asterix.048_065",
            dict_local(x_065, "048_065", "QA1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x10, 0x02],
            "asterix.048_065",
            dict_local(x_065, "048_065", "QB2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x10, 0x01],
            "asterix.048_065",
            dict_local(x_065, "048_065", "QB1", "1")
        )
        x_060 = {
            "asterix.048_060_QA4": "0",
            "asterix.048_060_QA2": "0",
            "asterix.048_060_QA1": "0",
            "asterix.048_060_QB4": "0",
            "asterix.048_060_QB2": "0",
            "asterix.048_060_QB1": "0",
            "asterix.048_060_QC4": "0",
            "asterix.048_060_QC2": "0",
            "asterix.048_060_QC1": "0",
            "asterix.048_060_QD4": "0",
            "asterix.048_060_QD2": "0",
            "asterix.048_060_QD1": "0"
        }
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x08, 0x00],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QA4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x04, 0x00],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QA2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x02, 0x00],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QA1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x01, 0x00],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QB4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x80],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QB2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x40],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QB1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x20],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QC4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x10],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QC2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x08],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QC1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x04],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QD4", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x02],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QD2", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x08, 0x00, 0x01],
            "asterix.048_060",
            dict_local(x_060, "048_060", "QD1", "1")
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x04, 0x01],
            "asterix.048_SP",
            ""
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x04, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
             0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "asterix.048_SP",
            ""
        )
        '''TODO: re-enable RE and SP tests when implemented
        x_re_md5 = {
            "asterix.048_RE_MD5_01_M5": "0",
            "asterix.048_RE_MD5_01_ID": "0",
            "asterix.048_RE_MD5_01_DA": "0",
            "asterix.048_RE_MD5_01_M1": "0",
            "asterix.048_RE_MD5_01_M2": "0",
            "asterix.048_RE_MD5_01_M3": "0",
            "asterix.048_RE_MD5_01_MC": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x80, 0x80],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "M5", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x80, 0x40],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "ID", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x80, 0x20],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "DA", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x80, 0x10],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "M1", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x80, 0x08],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "M2", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x80, 0x04],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "M3", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x80, 0x02],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "MC", "1")
        )
        x_re_pmn = {
            "asterix.048_RE_MD5_02_PIN": "0",
            "asterix.048_RE_MD5_02_NAV": "0",
            "asterix.048_RE_MD5_02_NAT": "0",
            "asterix.048_RE_MD5_02_MIS": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x40, 0x3f, 0xff, 0x00, 0x00],
            "MD5",
            dict_fspec_local(x_re_pmn, "048_RE_MD5_02", "PIN", "16383")
        )
        validator.add_re_dissection(
            [0x80, 0x40, 0x00, 0x00, 0x20, 0x00],
            "MD5",
            dict_fspec_local(x_re_pmn, "048_RE_MD5_02", "NAV", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x40, 0x00, 0x00, 0x1f, 0x00],
            "MD5",
            dict_fspec_local(x_re_pmn, "048_RE_MD5_02", "NAT", "31")
        )
        validator.add_re_dissection(
            [0x80, 0x40, 0x00, 0x00, 0x00, 0x3f],
            "MD5",
            dict_fspec_local(x_re_pmn, "048_RE_MD5_02", "MIS", "63")
        )
        x_re_pos = {
            "asterix.048_RE_MD5_03_LAT": "0",
            "asterix.048_RE_MD5_03_LON": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00],
            "MD5",
            dict_fspec_local(x_re_pos, "048_RE_MD5_03", "LAT", "90")
        )
        validator.add_re_dissection(
            [0x80, 0x20, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00],
            "MD5",
            dict_fspec_local(x_re_pos, "048_RE_MD5_03", "LAT", "-90")
        )
        validator.add_re_dissection(
            [0x80, 0x20, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff],
            "MD5",
            dict_fspec_local(x_re_pos, "048_RE_MD5_03",
                             "LON", "179.999978542328")
        )
        validator.add_re_dissection(
            [0x80, 0x20, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00],
            "MD5",
            dict_fspec_local(x_re_pos, "048_RE_MD5_03", "LON", "-180")
        )
        x_re_ga = {
            "asterix.048_RE_MD5_04_RES": "0",
            "asterix.048_RE_MD5_04_GA": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x10, 0x40, 0x00],
            "MD5",
            dict_fspec_local(x_re_ga, "048_RE_MD5_04", "RES", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x10, 0x1f, 0xff],
            "MD5",
            dict_fspec_local(x_re_ga, "048_RE_MD5_04", "GA", "204775")
        )
        validator.add_re_dissection(
            [0x80, 0x10, 0x20, 0x00],
            "MD5",
            dict_fspec_local(x_re_ga, "048_RE_MD5_04", "GA", "-204800")
        )
        x_re_em1 = {
            "asterix.048_RE_MD5_05_V": "0",
            "asterix.048_RE_MD5_05_G": "0",
            "asterix.048_RE_MD5_05_L": "0",
            "asterix.048_RE_MD5_05_MODE3A": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x08, 0x80, 0x00],
            "MD5",
            dict_fspec_local(x_re_em1, "048_RE_MD5_05", "V", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x08, 0x40, 0x00],
            "MD5",
            dict_fspec_local(x_re_em1, "048_RE_MD5_05", "G", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x08, 0x20, 0x00],
            "MD5",
            dict_fspec_local(x_re_em1, "048_RE_MD5_05", "L", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x08, 0x0f, 0xff],
            "MD5",
            dict_fspec_local(x_re_em1, "048_RE_MD5_05", "MODE3A", "4095")
        )
        validator.add_re_dissection(
            [0x80, 0x04, 0x7f],
            "MD5",
            fspec_local("048_RE_MD5_06", "TOS", "0.9921875")
        )
        validator.add_re_dissection(
            [0x80, 0x04, 0x80],
            "MD5",
            fspec_local("048_RE_MD5_06", "TOS", "-1")
        )
        x_re_xp = {
            "asterix.048_RE_MD5_07_XP": "0",
            "asterix.048_RE_MD5_07_X5": "0",
            "asterix.048_RE_MD5_07_XC": "0",
            "asterix.048_RE_MD5_07_X3": "0",
            "asterix.048_RE_MD5_07_X2": "0",
            "asterix.048_RE_MD5_07_X1": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x02, 0x20],
            "MD5",
            dict_fspec_local(x_re_xp, "048_RE_MD5_07", "XP", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x02, 0x10],
            "MD5",
            dict_fspec_local(x_re_xp, "048_RE_MD5_07", "X5", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x02, 0x08],
            "MD5",
            dict_fspec_local(x_re_xp, "048_RE_MD5_07", "XC", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x02, 0x04],
            "MD5",
            dict_fspec_local(x_re_xp, "048_RE_MD5_07", "X3", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x02, 0x02],
            "MD5",
            dict_fspec_local(x_re_xp, "048_RE_MD5_07", "X2", "1")
        )
        validator.add_re_dissection(
            [0x80, 0x02, 0x01],
            "MD5",
            dict_fspec_local(x_re_xp, "048_RE_MD5_07", "X1", "1")
        )
        x_re_md5 = {
            "asterix.048_RE_M5N_01_M5": "0",
            "asterix.048_RE_M5N_01_ID": "0",
            "asterix.048_RE_M5N_01_DA": "0",
            "asterix.048_RE_M5N_01_M1": "0",
            "asterix.048_RE_M5N_01_M2": "0",
            "asterix.048_RE_M5N_01_M3": "0",
            "asterix.048_RE_M5N_01_MC": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x80, 0x80],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "M5", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x80, 0x40],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "ID", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x80, 0x20],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "DA", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x80, 0x10],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "M1", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x80, 0x08],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "M2", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x80, 0x04],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "M3", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x80, 0x02],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "MC", "1")
        )
        x_re_pmn = {
            "asterix.048_RE_M5N_02_PIN": "0",
            "asterix.048_RE_M5N_02_NOV": "0",
            "asterix.048_RE_M5N_02_NO": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x40, 0x3f, 0xff, 0x00, 0x00],
            "M5N",
            dict_fspec_local(x_re_pmn, "048_RE_M5N_02", "PIN", "16383")
        )
        validator.add_re_dissection(
            [0x40, 0x40, 0x00, 0x00, 0x08, 0x00],
            "M5N",
            dict_fspec_local(x_re_pmn, "048_RE_M5N_02", "NOV", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x40, 0x00, 0x00, 0x07, 0xff],
            "M5N",
            dict_fspec_local(x_re_pmn, "048_RE_M5N_02", "NO", "2047")
        )
        x_re_pos = {
            "asterix.048_RE_M5N_03_LAT": "0",
            "asterix.048_RE_M5N_03_LON": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00],
            "M5N",
            dict_fspec_local(x_re_pos, "048_RE_M5N_03", "LAT", "90")
        )
        validator.add_re_dissection(
            [0x40, 0x20, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00],
            "M5N",
            dict_fspec_local(x_re_pos, "048_RE_M5N_03", "LAT", "-90")
        )
        validator.add_re_dissection(
            [0x40, 0x20, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff],
            "M5N",
            dict_fspec_local(x_re_pos, "048_RE_M5N_03",
                             "LON", "179.999978542328")
        )
        validator.add_re_dissection(
            [0x40, 0x20, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00],
            "M5N",
            dict_fspec_local(x_re_pos, "048_RE_M5N_03", "LON", "-180")
        )
        x_re_ga = {
            "asterix.048_RE_M5N_04_RES": "0",
            "asterix.048_RE_M5N_04_GA": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x10, 0x40, 0x00],
            "M5N",
            dict_fspec_local(x_re_ga, "048_RE_M5N_04", "RES", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x10, 0x1f, 0xff],
            "M5N",
            dict_fspec_local(x_re_ga, "048_RE_M5N_04", "GA", "204775")
        )
        validator.add_re_dissection(
            [0x40, 0x10, 0x20, 0x00],
            "M5N",
            dict_fspec_local(x_re_ga, "048_RE_M5N_04", "GA", "-204800")
        )
        x_re_em1 = {
            "asterix.048_RE_M5N_05_V": "0",
            "asterix.048_RE_M5N_05_G": "0",
            "asterix.048_RE_M5N_05_L": "0",
            "asterix.048_RE_M5N_05_MODE3A": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x08, 0x80, 0x00],
            "M5N",
            dict_fspec_local(x_re_em1, "048_RE_M5N_05", "V", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x08, 0x40, 0x00],
            "M5N",
            dict_fspec_local(x_re_em1, "048_RE_M5N_05", "G", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x08, 0x20, 0x00],
            "M5N",
            dict_fspec_local(x_re_em1, "048_RE_M5N_05", "L", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x08, 0x0f, 0xff],
            "M5N",
            dict_fspec_local(x_re_em1, "048_RE_M5N_05", "MODE3A", "4095")
        )
        validator.add_re_dissection(
            [0x40, 0x04, 0x7f],
            "M5N",
            fspec_local("048_RE_M5N_06", "TOS", "0.9921875")
        )
        validator.add_re_dissection(
            [0x40, 0x04, 0x80],
            "M5N",
            fspec_local("048_RE_M5N_06", "TOS", "-1")
        )
        x_re_xp = {
            "asterix.048_RE_M5N_07_XP": "0",
            "asterix.048_RE_M5N_07_X5": "0",
            "asterix.048_RE_M5N_07_XC": "0",
            "asterix.048_RE_M5N_07_X3": "0",
            "asterix.048_RE_M5N_07_X2": "0",
            "asterix.048_RE_M5N_07_X1": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x02, 0x20],
            "M5N",
            dict_fspec_local(x_re_xp, "048_RE_M5N_07", "XP", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x02, 0x10],
            "M5N",
            dict_fspec_local(x_re_xp, "048_RE_M5N_07", "X5", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x02, 0x08],
            "M5N",
            dict_fspec_local(x_re_xp, "048_RE_M5N_07", "XC", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x02, 0x04],
            "M5N",
            dict_fspec_local(x_re_xp, "048_RE_M5N_07", "X3", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x02, 0x02],
            "M5N",
            dict_fspec_local(x_re_xp, "048_RE_M5N_07", "X2", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x02, 0x01],
            "M5N",
            dict_fspec_local(x_re_xp, "048_RE_M5N_07", "X1", "1")
        )
        validator.add_re_dissection(
            [0x40, 0x01, 0x80, 0x1f],
            "M5N",
            fspec_local("048_RE_M5N_08", "FOM", "31")
        )
        validator.add_re_dissection(
            [0x20, 0x06],
            "M4E",
            {
                "asterix.048_RE_M4E_FOE_FRI": "3",
                "asterix.FX": "0"
            }
        )
        validator.add_re_dissection(
            [0x10, 0x80, 0xff],
            "RPC",
            fspec_local("048_RE_RPC_01", "SCO", "255")
        )
        validator.add_re_dissection(
            [0x10, 0x40, 0xff, 0xff],
            "RPC",
            fspec_local("048_RE_RPC_02", "SCR", "6553.5")
        )
        validator.add_re_dissection(
            [0x10, 0x20, 0xff, 0xff],
            "RPC",
            fspec_local("048_RE_RPC_03", "RW", "255.99609375")
        )
        validator.add_re_dissection(
            [0x10, 0x10, 0xff, 0xff],
            "RPC",
            fspec_local("048_RE_RPC_04", "AR", "255.99609375")
        )
        validator.add_re_dissection(
            [0x08, 0xff, 0xff, 0xff],
            "ERR",
            {
                "asterix.048_RE_ERR_RHO": "65535.99609375"
            }
        )
        '''

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_re_validator):
        '''verifies that the dissector can dissect undefined field values by
        setting the maximum value of bits or by setting all undefined bits'''

        validator = asterix_re_validator(48, [0x01, 0x01, 0x01, 0x02])

        validator.add_dissection(
            [0x08, 0x10, 0x00],
            "asterix.048_070",
            {
                "asterix.048_070_V": "0",
                "asterix.048_070_G": "0",
                "asterix.048_070_L": "0",
                "asterix.048_070_MODE3A": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x10, 0xf0, 0x00],
            "asterix.048_161",
            {
                "asterix.048_161_TRN": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x02, 0x01, 0x0e],
            "asterix.048_170",
            {
                "asterix.048_170_CNF": "0",
                "asterix.048_170_RAD": "0",
                "asterix.048_170_DOU": "0",
                "asterix.048_170_MAH": "0",
                "asterix.048_170_CDM": "0",
                "asterix.048_170_TRE": "0",
                "asterix.048_170_GHO": "0",
                "asterix.048_170_SUP": "0",
                "asterix.048_170_TCC": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x40, 0xfe],
            "asterix.048_030",
            {
                "asterix.048_030_Subitem": "127",
                "asterix.FX": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x20, 0xf0, 0x00],
            "asterix.048_080",
            {
                "asterix.048_080_QA4": "0",
                "asterix.048_080_QA2": "0",
                "asterix.048_080_QA1": "0",
                "asterix.048_080_QB4": "0",
                "asterix.048_080_QB2": "0",
                "asterix.048_080_QB1": "0",
                "asterix.048_080_QC4": "0",
                "asterix.048_080_QC2": "0",
                "asterix.048_080_QC1": "0",
                "asterix.048_080_QD4": "0",
                "asterix.048_080_QD2": "0",
                "asterix.048_080_QD1": "0"
            }
        )
        '''TODO: A,B,C,D values need to go to single subitem 'MODEC'
        validator.add_dissection(
            [0x01, 0x01, 0x10, 0x30, 0x00, 0xf0, 0x00],
            "asterix.048_100",
            {
                "asterix.048_100_V": "0",
                "asterix.048_100_G": "0",
                "asterix.048_100_A1": "0",
                "asterix.048_100_C2": "0",
                "asterix.048_100_A2": "0",
                "asterix.048_100_C4": "0",
                "asterix.048_100_A4": "0",
                "asterix.048_100_B1": "0",
                "asterix.048_100_D1": "0",
                "asterix.048_100_B2": "0",
                "asterix.048_100_D2": "0",
                "asterix.048_100_B4": "0",
                "asterix.048_100_D4": "0",
                "asterix.048_100_QC1": "0",
                "asterix.048_100_QA1": "0",
                "asterix.048_100_QC2": "0",
                "asterix.048_100_QA2": "0",
                "asterix.048_100_QC4": "0",
                "asterix.048_100_QA4": "0",
                "asterix.048_100_QB1": "0",
                "asterix.048_100_QD1": "0",
                "asterix.048_100_QB2": "0",
                "asterix.048_100_QD2": "0",
                "asterix.048_100_QB4": "0",
                "asterix.048_100_QD4": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x80, 0x7c, 0x00],
            "asterix.048_120",
            {
                "asterix.fspec": "",
                "asterix.048_120_01":
                {
                    "asterix.048_120_01_D": "0",
                    "asterix.048_120_01_CAL": "0"
                }
            }
        )
        '''
        validator.add_dissection(
            [0x01, 0x01, 0x04, 0x3e],
            "asterix.048_120",
            {
                "asterix.fspec": ""
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x02, 0x01, 0x00],
            "asterix.048_230",
            {
                "asterix.048_230_COM": "0",
                "asterix.048_230_STAT": "0",
                "asterix.048_230_SI": "0",
                "asterix.048_230_MSSC": "0",
                "asterix.048_230_ARC": "0",
                "asterix.048_230_AIC": "0",
                "asterix.048_230_B1A": "0",
                "asterix.048_230_B1B": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x20, 0x10, 0x00],
            "asterix.048_050",
            {
                "asterix.048_050_V": "0",
                "asterix.048_050_G": "0",
                "asterix.048_050_L": "0",
                "asterix.048_050_MODE2": "0"
            }
        )
        validator.add_dissection(
            [0x01, 0x01, 0x01, 0x10, 0xe0],
            "asterix.048_065",
            {
                "asterix.048_065_QA4": "0",
                "asterix.048_065_QA2": "0",
                "asterix.048_065_QA1": "0",
                "asterix.048_065_QB2": "0",
                "asterix.048_065_QB1": "0"
            }
        )
        '''TODO: re-enable RE and SP tests when implemented
        x_re_md5 = {
            "asterix.048_RE_MD5_01_M5": "0",
            "asterix.048_RE_MD5_01_ID": "0",
            "asterix.048_RE_MD5_01_DA": "0",
            "asterix.048_RE_MD5_01_M1": "0",
            "asterix.048_RE_MD5_01_M2": "0",
            "asterix.048_RE_MD5_01_M3": "0",
            "asterix.048_RE_MD5_01_MC": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x80, 0x01, 0x00],
            "MD5",
            dict_fspec_local(x_re_md5, "048_RE_MD5_01", "M5", "0")
        )
        x_re_pmn = {
            "asterix.048_RE_MD5_02_PIN": "0",
            "asterix.048_RE_MD5_02_NAV": "0",
            "asterix.048_RE_MD5_02_NAT": "0",
            "asterix.048_RE_MD5_02_MIS": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x40, 0xc0, 0x00, 0xc0, 0xc0],
            "MD5",
            dict_fspec_local(x_re_pmn, "048_RE_MD5_02", "PIN", "0")
        )
        x_re_em1 = {
            "asterix.048_RE_MD5_05_V": "0",
            "asterix.048_RE_MD5_05_G": "0",
            "asterix.048_RE_MD5_05_L": "0",
            "asterix.048_RE_MD5_05_MODE3A": "0"
        }
        validator.add_re_dissection(
            [0x80, 0x08, 0x10, 0x00],
            "MD5",
            dict_fspec_local(x_re_em1, "048_RE_MD5_05", "V", "0")
        )
        x_re_md5 = {
            "asterix.048_RE_M5N_01_M5": "0",
            "asterix.048_RE_M5N_01_ID": "0",
            "asterix.048_RE_M5N_01_DA": "0",
            "asterix.048_RE_M5N_01_M1": "0",
            "asterix.048_RE_M5N_01_M2": "0",
            "asterix.048_RE_M5N_01_M3": "0",
            "asterix.048_RE_M5N_01_MC": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x80, 0x01, 0x00],
            "M5N",
            dict_fspec_local(x_re_md5, "048_RE_M5N_01", "M5", "0")
        )
        x_re_pmn = {
            "asterix.048_RE_M5N_02_PIN": "0",
            "asterix.048_RE_M5N_02_NOV": "0",
            "asterix.048_RE_M5N_02_NO": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x40, 0xc0, 0x00, 0xf0, 0x00],
            "M5N",
            dict_fspec_local(x_re_pmn, "048_RE_M5N_02", "PIN", "0")
        )
        x_re_em1 = {
            "asterix.048_RE_M5N_05_V": "0",
            "asterix.048_RE_M5N_05_G": "0",
            "asterix.048_RE_M5N_05_L": "0",
            "asterix.048_RE_M5N_05_MODE3A": "0"
        }
        validator.add_re_dissection(
            [0x40, 0x08, 0x10, 0x00],
            "M5N",
            dict_fspec_local(x_re_em1, "048_RE_M5N_05", "V", "0")
        )
        validator.add_re_dissection(
            [0x40, 0x01, 0x80, 0xe0],
            "M5N",
            fspec_local("048_RE_M5N_08", "FOM", "0")
        )
        validator.add_re_dissection(
            [0x20, 0xf8],
            "M4E",
            {
                "asterix.048_RE_M4E_FOE_FRI": "0",
                "asterix.FX": "0"
            }
        )
        validator.add_re_dissection(
            [0x20, 0x01, 0x00],
            "M4E",
            {
                "asterix.048_RE_M4E_FOE_FRI": "0",
                "asterix.FX": "1"
            }
        )
        '''

        validator.check_dissections()


class TestCategory063:
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

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(63)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.063_010",
            {
                "asterix.063_010_SAC": "0xff",
                "asterix.063_010_SIC": "0x00"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.063_010",
            {
                "asterix.063_010_SAC": "0x00",
                "asterix.063_010_SIC": "0xff"
            }
        )
        validator.add_dissection(
            [0x40, 0xff],
            "asterix.063_015",
            {
                "asterix.063_015_VALUE": "0xff"
            }
        )
        validator.add_dissection(
            [0x20, 0xa8, 0xbf, 0xff],
            "asterix.063_030",
            {
                "asterix.063_030_VALUE": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x10, 0xff, 0x00],
            "asterix.063_050",
            {
                "asterix.063_050_SAC": "0xff",
                "asterix.063_050_SIC": "0x00"
            }
        )
        validator.add_dissection(
            [0x10, 0x00, 0xff],
            "asterix.063_050",
            {
                "asterix.063_050_SAC": "0x00",
                "asterix.063_050_SIC": "0xff"
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
                "asterix.063_070_VALUE": "-1"
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
                "asterix.063_081_VALUE": "179.994506835938"
            }
        )
        validator.add_dissection(
            [0x01, 0x80, 0x80, 0x00],
            "asterix.063_081",
            {
                "asterix.063_081_VALUE": "-180"
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
                "asterix.063_091_VALUE": "179.994506835938"
            }
        )
        validator.add_dissection(
            [0x01, 0x20, 0x80, 0x00],
            "asterix.063_091",
            {
                "asterix.063_091_VALUE": "-180"
            }
        )
        validator.add_dissection(
            [0x01, 0x10, 0x7f, 0xff],
            "asterix.063_092",
            {
                "asterix.063_092_VALUE": "179.994506835938"
            }
        )
        validator.add_dissection(
            [0x01, 0x10, 0x80, 0x00],
            "asterix.063_092",
            {
                "asterix.063_092_VALUE": "-180"
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
        '''TODO: re-enable RE and SP tests when implemented
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
        '''

        validator.check_dissections()


class TestCategory065:
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

    def test_for_fields(self, asterix_validator):
        '''verifies existence of all fields and their maximum value'''

        validator = asterix_validator(65)

        validator.add_dissection(
            [0x80, 0xff, 0x00],
            "asterix.065_010",
            {
                "asterix.065_010_SAC": "0xff",
                "asterix.065_010_SIC": "0x00"
            }
        )
        validator.add_dissection(
            [0x80, 0x00, 0xff],
            "asterix.065_010",
            {
                "asterix.065_010_SAC": "0x00",
                "asterix.065_010_SIC": "0xff"
            }
        )
        validator.add_dissection(
            [0x40, 0x03],
            "asterix.065_000",
            {
                "asterix.065_000_VALUE": "3"
            }
        )
        validator.add_dissection(
            [0x20, 0xff],
            "asterix.065_015",
            {
                "asterix.065_015_VALUE": "0xff"
            }
        )
        validator.add_dissection(
            [0x10, 0xa8, 0xbf, 0xff],
            "asterix.065_030",
            {
                "asterix.065_030_VALUE": "86399.9921875"
            }
        )
        validator.add_dissection(
            [0x08, 0xff],
            "asterix.065_020",
            {
                "asterix.065_020_VALUE": "255"
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
                "asterix.065_050_VALUE": "255"
            }
        )
        '''TODO: re-enable RE and SP tests when implemented
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
        '''

        validator.check_dissections()

    def test_undefined_value_handling(self, asterix_validator):
        '''verifies that the dissector can dissect undefined field values by
        setting the maximum value of bits or by setting all undefined bits'''

        validator = asterix_validator(65)

        validator.add_dissection(
            [0x40, 0xff],
            "asterix.065_000",
            {
                "asterix.065_000_VALUE": "255"
            }
        )
        validator.add_dissection(
            [0x10, 0xff, 0xff, 0xff],
            "asterix.065_030",
            {
                "asterix.065_030_VALUE": "131071.9921875"
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
        '''TODO: re-enable RE and SP tests when implemented
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
        '''

        validator.check_dissections()
