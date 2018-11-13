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

import os.path
import subprocesstest
import unittest
import fixtures

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_http2(subprocesstest.SubprocessTestCase):
    def test_http2_data_reassembly(self, cmd_tshark, features, dirs, capture_file):
        '''HTTP2 data reassembly'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        self.runProcess((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-d', 'tcp.port==8443,tls',
                '-Y', 'http2.data.data matches "PNG" && http2.data.data matches "END"',
            ))
        self.assertTrue(self.grepOutput('DATA'))

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_tcp(subprocesstest.SubprocessTestCase):
    def check_tcp_out_of_order(self, cmd_tshark, dirs, extraArgs=[]):
        capture_file = os.path.join(dirs.capture_dir, 'http-ooo.pcap')
        self.runProcess([cmd_tshark,
                '-r', capture_file,
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'http',
            ] + extraArgs)
        self.assertEqual(self.countOutput('HTTP'), 5)
        # TODO PDU /1 (segments in frames 1, 2, 4) should be reassembled in
        # frame 4, but it is currently done in frame 6 because the current
        # implementation reassembles only contiguous segments and PDU /2 has
        # segments in frames 6, 3, 7.
        self.assertTrue(self.grepOutput(r'^\s*6\s.*PUT /1 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*7\s.*GET /2 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*10\s.*PUT /3 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*11\s.*PUT /4 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*15\s.*PUT /5 HTTP/1.1'))

    def test_tcp_out_of_order_onepass(self, cmd_tshark, dirs):
        self.check_tcp_out_of_order(cmd_tshark, dirs)

    @unittest.skip("MSP splitting is not implemented yet")
    def test_tcp_out_of_order_twopass(self, cmd_tshark, dirs):
        self.check_tcp_out_of_order(cmd_tshark, dirs, extraArgs=['-2'])

    def test_tcp_out_of_order_twopass_with_bug(self, cmd_tshark, capture_file):
        # TODO fix the issue below, remove this and enable
        # "test_tcp_out_of_order_twopass"
        self.runProcess((cmd_tshark,
                '-r', capture_file('http-ooo.pcap'),
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'http',
                '-2',
            ))
        self.assertEqual(self.countOutput('HTTP'), 3)
        self.assertTrue(self.grepOutput(r'^\s*7\s.*PUT /1 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*7\s.*GET /2 HTTP/1.1'))
        # TODO ideally this should not be concatenated.
        # Normally a multi-segment PDU (MSP) covers only a single PDU, but OoO
        # segments can extend MSP such that it covers two (or even more) PDUs.
        # Until MSP splitting is implemented, two PDUs are shown in a single
        # packet (and in case of -2, they are only shown in the last packet).
        self.assertTrue(self.grepOutput(r'^\s*11\s.*PUT /3 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*11\s.*PUT /4 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*15\s.*PUT /5 HTTP/1.1'))

    def test_tcp_out_of_order_data_after_syn(self, cmd_tshark, capture_file):
        '''Test when the first non-empty segment is OoO.'''
        proc = self.runProcess((cmd_tshark,
                '-r', capture_file('dns-ooo.pcap'),
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'dns', '-Tfields', '-edns.qry.name',
            ))
        self.assertEqual(proc.stdout_str.strip(), 'example.com')
