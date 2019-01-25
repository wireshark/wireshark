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
        self.assertRun((cmd_tshark,
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
        self.assertRun([cmd_tshark,
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
        self.assertRun((cmd_tshark,
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
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('dns-ooo.pcap'),
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'dns', '-Tfields', '-edns.qry.name',
            ))
        self.assertEqual(proc.stdout_str.strip(), 'example.com')

    def test_tcp_out_of_order_first_gap(self, cmd_tshark, capture_file):
        '''
        Test reporting of "reassembled_in" in the OoO frame that contains the
        initial segment (Bug 15420). Additionally, test for proper reporting
        when the initial segment is retransmitted.
        For PDU H123 (where H is the HTTP Request header and 1, 2 and 3 are part
        of the body), the order is: (SYN) 2 H H 1 3 H.
        '''
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('http-ooo2.pcap'),
            '-otcp.reassemble_out_of_order:TRUE',
            '-Tfields',
            '-eframe.number', '-etcp.reassembled_in', '-e_ws.col.Info',
            '-2',
            ))
        lines = proc.stdout_str.replace('\r', '').split('\n')
        # 2 - start of OoO MSP
        self.assertIn('2\t6\t[TCP Previous segment not captured]', lines[1])
        self.assertIn('[TCP segment of a reassembled PDU]', lines[1])
        # H - first time that the start of the MSP is delivered
        self.assertIn('3\t6\t[TCP Out-Of-Order]', lines[2])
        self.assertIn('[TCP segment of a reassembled PDU]', lines[2])
        # H - first retransmission.
        self.assertIn('4\t\t', lines[3])
        self.assertNotIn('[TCP segment of a reassembled PDU]', lines[3])
        # 1 - continue reassembly
        self.assertIn('5\t6\t[TCP Out-Of-Order]', lines[4])
        self.assertIn('[TCP segment of a reassembled PDU]', lines[4])
        # 3 - finish reassembly
        self.assertIn('6\t\tPUT /0 HTTP/1.1', lines[5])
        # H - second retransmission.
        self.assertIn('7\t\t', lines[6])
        self.assertNotIn('[TCP segment of a reassembled PDU]', lines[6])

    def test_tcp_reassembly_more_data_1(self, cmd_tshark, capture_file):
        '''
        Tests that reassembly also works when a new packet begins at the same
        sequence number as the initial segment. This models behavior with the
        ZeroWindowProbe: the initial segment contains a single byte. The second
        segment contains that byte, plus the remainder.
        '''
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('retrans-tls.pcap'),
            '-Ytls', '-Tfields', '-eframe.number', '-etls.record.length',))
        output = proc.stdout_str.replace('\r', '')
        # First pass dissection actually accepted the first frame as TLS, but
        # subsequently requested reassembly.
        self.assertEqual(output, '1\t\n2\t16\n')

    def test_tcp_reassembly_more_data_2(self, cmd_tshark, capture_file):
        '''
        Like test_tcp_reassembly_more_data_1, but checks the second pass (-2).
        '''
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('retrans-tls.pcap'),
            '-Ytls', '-Tfields', '-eframe.number', '-etls.record.length', '-2'))
        output = proc.stdout_str.replace('\r', '')
        self.assertEqual(output, '2\t16\n')
