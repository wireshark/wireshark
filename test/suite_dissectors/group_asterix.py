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
