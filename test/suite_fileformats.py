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

import config
import io
import os.path
import subprocesstest
import sys
import unittest

# XXX Currently unused. It would be nice to be able to use this below.
time_output_args = ('-Tfields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta')

# Microsecond pcap, direct read was used to generate the baseline:
# tshark -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta \
#   -r captures/dhcp.pcap > baseline/ff-ts-usec-pcap-direct.txt
baseline_file = 'ff-ts-usec-pcap-direct.txt'
baseline_fd = io.open(os.path.join(config.baseline_dir, baseline_file), 'r', encoding='UTF-8', errors='replace')
baseline_str = baseline_fd.read()
baseline_fd.close()

class case_fileformat_pcap(subprocesstest.SubprocessTestCase):
    def test_pcap_usec_stdin(self):
        '''Microsecond pcap direct vs microsecond pcap stdin'''
        capture_file = os.path.join(config.capture_dir, 'dhcp.pcap')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                '<', capture_file
                , shell=True),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

    def test_pcap_nsec_stdin(self):
        '''Microsecond pcap direct vs nanosecond pcap stdin'''
        capture_file = os.path.join(config.capture_dir, 'dhcp-nanosecond.pcap')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                '<', capture_file
                , shell=True),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

    def test_pcap_nsec_direct(self):
        '''Microsecond pcap direct vs nanosecond pcap direct'''
        capture_file = os.path.join(config.capture_dir, 'dhcp-nanosecond.pcap')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            )
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

class case_fileformat_pcapng(subprocesstest.SubprocessTestCase):
    def test_pcapng_usec_stdin(self):
        '''Microsecond pcap direct vs microsecond pcapng stdin'''
        capture_file = os.path.join(config.capture_dir, 'dhcp.pcapng')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta'
                '<', capture_file
                , shell=True),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

    def test_pcapng_usec_direct(self):
        '''Microsecond pcap direct vs microsecond pcapng direct'''
        capture_file = os.path.join(config.capture_dir, 'dhcp.pcapng')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            )
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

    def test_pcapng_nsec_stdin(self):
        '''Microsecond pcap direct vs nanosecond pcapng stdin'''
        capture_file = os.path.join(config.capture_dir, 'dhcp-nanosecond.pcapng')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta'
                '<', capture_file
                , shell=True),
            shell=True)
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

    def test_pcapng_nsec_direct(self):
        '''Microsecond pcap direct vs nanosecond pcapng direct'''
        capture_file = os.path.join(config.capture_dir, 'dhcp-nanosecond.pcapng')
        capture_proc = self.runProcess(subprocesstest.capture_command(config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            )
        self.assertTrue(self.diffOutput(capture_proc.stdout_str, baseline_str, 'tshark', baseline_file))

