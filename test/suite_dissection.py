#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Dissection tests'''

import config
import os.path
import subprocesstest
import unittest

class case_dissect_http2(subprocesstest.SubprocessTestCase):
    def test_http2_data_reassembly(self):
        '''HTTP2 data reassembly'''
        if not config.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        capture_file = os.path.join(config.capture_dir, 'http2-data-reassembly.pcap')
        key_file = os.path.join(config.key_dir, 'http2-data-reassembly.keys')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'ssl.keylog_file: {}'.format(key_file),
                '-d', 'tcp.port==8443,ssl',
                '-Y', 'http2.data.data matches "PNG" && http2.data.data matches "END"',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('DATA'))
