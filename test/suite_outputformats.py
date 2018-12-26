# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Copyright (c) 2018 Dario Lombardo <lomato@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''outputformats tests'''

import json
import os.path
import subprocesstest
import fixtures
from matchers import *

@fixtures.fixture
def check_outputformat(cmd_tshark, dirs, capture_file):
    ''' Check a capture file against a sample, in json format. '''
    def check_outputformat_real(self, pcap_file, format_option, format_file, multiline=False):
        self.maxDiff = 1000000
        tshark_proc = self.assertRun((cmd_tshark, '-r', capture_file(pcap_file), '-T', format_option,))

        expected = open(os.path.join(dirs.baseline_dir, format_file)).read()
        actual = tshark_proc.stdout_str
        if multiline:
            expected = expected.splitlines()
            actual = actual.splitlines()
            self.assertEqual(len(expected), len(actual))
            for line1, line2 in zip(expected, actual):
                json.loads(line1)
                json.loads(line2)
                self.assertEqual(json.loads(line1), json.loads(line2))
        else:
            expected = json.loads(expected)
            actual = json.loads(actual)
            self.assertEqual(expected, actual)

    return check_outputformat_real

@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_outputformats(subprocesstest.SubprocessTestCase):
    def test_outputformat_json(self, check_outputformat):
        '''Decode some captures into json'''
        check_outputformat(self, "dhcp.pcap", "json", "dhcp.json")

    def test_outputformat_jsonraw(self, check_outputformat):
        '''Decode some captures into jsonraw'''
        check_outputformat(self, "dhcp.pcap", "jsonraw", "dhcp.jsonraw")

    def test_outputformat_ek(self, check_outputformat):
        '''Decode some captures into ek'''
        check_outputformat(self, "dhcp.pcap", "ek", "dhcp.ek", True)
