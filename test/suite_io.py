#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''File I/O tests'''

import io
import os.path
import subprocesstest
import sys
import unittest
import fixtures

testout_pcap = 'testout.pcap'
baseline_file = 'io-rawshark-dhcp-pcap.txt'


@fixtures.fixture(scope='session')
def io_baseline_str(dirs):
    with open(os.path.join(dirs.baseline_dir, baseline_file), 'r') as f:
        return f.read()


def check_io_4_packets(self, capture_file, cmd=None, from_stdin=False, to_stdout=False):
    # Test direct->direct, stdin->direct, and direct->stdout file I/O.
    # Similar to suite_capture.check_capture_10_packets and
    # suite_capture.check_capture_stdin.
    self.assertIsNotNone(cmd)
    testout_file = self.filename_from_id(testout_pcap)
    if from_stdin and to_stdout:
        # XXX If we support this, should we bother with separate stdin->direct
        # and direct->stdout tests?
        self.fail('Stdin and stdout not supported in the same test.')
    elif from_stdin:
        # cat -B "${CAPTURE_DIR}dhcp.pcap" | $DUT -r - -w ./testout.pcap 2>./testout.txt
        cat_dhcp_cmd = subprocesstest.cat_dhcp_command('cat')
        stdin_cmd = '{0} | "{1}" -r - -w "{2}"'.format(cat_dhcp_cmd, cmd, testout_file)
        io_proc = self.assertRun(stdin_cmd, shell=True)
    elif to_stdout:
        # $DUT -r "${CAPTURE_DIR}dhcp.pcap" -w - > ./testout.pcap 2>./testout.txt
        stdout_cmd = '"{0}" -r "{1}" -w - > "{2}"'.format(cmd, capture_file('dhcp.pcap'), testout_file)
        io_proc = self.assertRun(stdout_cmd, shell=True)
    else: # direct->direct
        # $DUT -r "${CAPTURE_DIR}dhcp.pcap" -w ./testout.pcap > ./testout.txt 2>&1
        io_proc = self.assertRun((cmd,
            '-r', capture_file('dhcp.pcap'),
            '-w', testout_file,
        ))
    self.assertTrue(os.path.isfile(testout_file))
    self.checkPacketCount(4)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_io(subprocesstest.SubprocessTestCase):
    def test_tshark_io_stdin_direct(self, cmd_tshark, capture_file):
        '''Read from stdin and write direct using TShark'''
        check_io_4_packets(self, capture_file, cmd=cmd_tshark, from_stdin=True)

    def test_tshark_io_direct_stdout(self, cmd_tshark, capture_file):
        '''Read direct and write to stdout using TShark'''
        check_io_4_packets(self, capture_file, cmd=cmd_tshark, to_stdout=True)

    def test_tshark_io_direct_direct(self, cmd_tshark, capture_file):
        '''Read direct and write direct using TShark'''
        check_io_4_packets(self, capture_file, cmd=cmd_tshark)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_rawshark_io(subprocesstest.SubprocessTestCase):
    @unittest.skipUnless(sys.byteorder == 'little', 'Requires a little endian system')
    def test_rawshark_io_stdin(self, cmd_rawshark, capture_file, io_baseline_str):
        '''Read from stdin using Rawshark'''
        # tail -c +25 "${CAPTURE_DIR}dhcp.pcap" | $RAWSHARK -dencap:1 -R "udp.port==68" -nr - > $IO_RAWSHARK_DHCP_PCAP_TESTOUT 2> /dev/null
        # diff -u --strip-trailing-cr $IO_RAWSHARK_DHCP_PCAP_BASELINE $IO_RAWSHARK_DHCP_PCAP_TESTOUT > $DIFF_OUT 2>&1
        capture_file = capture_file('dhcp.pcap')
        testout_file = self.filename_from_id(testout_pcap)
        raw_dhcp_cmd = subprocesstest.cat_dhcp_command('raw')
        rawshark_cmd = '{0} | "{1}" -r - -n -dencap:1 -R "udp.port==68"'.format(raw_dhcp_cmd, cmd_rawshark)
        rawshark_proc = self.assertRun(rawshark_cmd, shell=True)
        self.assertTrue(self.diffOutput(rawshark_proc.stdout_str, io_baseline_str, 'rawshark', baseline_file))
