#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''File format conversion tests'''

import os.path
import subprocesstest
import unittest
import fixtures

# XXX Currently unused. It would be nice to be able to use this below.
time_output_args = ('-Tfields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta')

# Microsecond pcap, direct read was used to generate the baseline:
# tshark -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta \
#   -r captures/dhcp.pcap > baseline/ff-ts-usec-pcap-direct.txt
baseline_file = 'ff-ts-usec-pcap-direct.txt'


@fixtures.fixture(scope='session')
def fileformats_baseline_str(dirs):
    with open(os.path.join(dirs.baseline_dir, baseline_file), 'r') as f:
        return f.read()


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_fileformat_pcap(subprocesstest.SubprocessTestCase):
    def test_pcap_usec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs microsecond pcap stdin'''
        capture_proc = self.runProcess(' '.join((cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                '<', capture_file('dhcp.pcap')
                )),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))

    def test_pcap_nsec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs nanosecond pcap stdin'''
        capture_proc = self.runProcess(' '.join((cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                '<', capture_file('dhcp-nanosecond.pcap')
                )),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))

    def test_pcap_nsec_direct(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs nanosecond pcap direct'''
        capture_proc = self.runProcess((cmd_tshark,
                '-r', capture_file('dhcp-nanosecond.pcap'),
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            )
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_fileformat_pcapng(subprocesstest.SubprocessTestCase):
    def test_pcapng_usec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs microsecond pcapng stdin'''
        capture_proc = self.runProcess(' '.join((cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta'
                '<', capture_file('dhcp.pcapng')
                )),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))

    def test_pcapng_usec_direct(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs microsecond pcapng direct'''
        capture_proc = self.runProcess((cmd_tshark,
                '-r', capture_file('dhcp.pcapng'),
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            )
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))

    def test_pcapng_nsec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs nanosecond pcapng stdin'''
        capture_proc = self.runProcess(' '.join((cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta'
                '<', capture_file('dhcp-nanosecond.pcapng')
                )),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))

    def test_pcapng_nsec_direct(self, cmd_tshark, capture_file, fileformats_baseline_str):
        '''Microsecond pcap direct vs nanosecond pcapng direct'''
        capture_proc = self.runProcess((cmd_tshark,
                '-r', capture_file('dhcp-nanosecond.pcapng'),
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            )
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, fileformats_baseline_str, 'tshark', baseline_file))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_fileformat_mime(subprocesstest.SubprocessTestCase):
    def test_mime_pcapng_gz(self, cmd_tshark, capture_file):
        '''Test that the full uncompressed contents is shown.'''
        proc = self.runProcess((cmd_tshark,
                '-r', capture_file('icmp.pcapng.gz'),
                '-Xread_format:MIME Files Format',
                '-Tfields', '-e', 'frame.len', '-e', 'pcapng.block.length',
            ))
        self.assertEqual(proc.stdout_str.strip(), '480\t128,128,88,88,132,132,132,132')
