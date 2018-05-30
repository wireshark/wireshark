#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Command line option tests'''

import config
import os.path
import subprocess
import subprocesstest
import unittest

#glossaries = ('fields', 'protocols', 'values', 'decodes', 'defaultprefs', 'currentprefs')

glossaries = ('decodes', 'values')
testout_pcap = 'testout.pcap'

class case_dumpcap_invalid_chars(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_invalid_chars(self):
        '''Invalid dumpcap parameters'''
        for char_arg in 'CEFGHJKNOQRTUVWXYejloxz':
            self.assertRun((config.cmd_dumpcap, '-' + char_arg),
                           expected_return=self.exit_command_line)


class case_dumpcap_valid_chars(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_valid_chars(self):
        for char_arg in 'hv':
            self.assertRun((config.cmd_dumpcap, '-' + char_arg))


class case_dumpcap_invalid_interface_chars(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_interface_chars(self):
        '''Valid dumpcap parameters requiring capture permissions'''
        valid_returns = [self.exit_ok, self.exit_error]
        for char_arg in 'DL':
            process = self.runProcess((config.cmd_dumpcap, '-' + char_arg))
            self.assertIn(process.returncode, valid_returns)


class case_dumpcap_capture_clopts(subprocesstest.SubprocessTestCase):
    def test_dumpcap_invalid_capfilter(self):
        '''Invalid capture filter'''
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        invalid_filter = '__invalid_protocol'
        # $DUMPCAP -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((config.cmd_dumpcap, '-f', invalid_filter, '-w', testout_file ))
        self.assertTrue(self.grepOutput('Invalid capture filter "' + invalid_filter + '" for interface'))

    def test_dumpcap_invalid_interface_name(self):
        '''Invalid capture interface name'''
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        invalid_interface = '__invalid_interface'
        # $DUMPCAP -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((config.cmd_dumpcap, '-i', invalid_interface, '-w', testout_file))
        self.assertTrue(self.grepOutput('The capture session could not be initiated'))

    def test_dumpcap_invalid_interface_index(self):
        '''Invalid capture interface index'''
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        invalid_index = '0'
        # $DUMPCAP -i 0 -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((config.cmd_dumpcap, '-i', invalid_index, '-w', testout_file))
        self.assertTrue(self.grepOutput('There is no interface with that adapter index'))


class case_basic_clopts(subprocesstest.SubprocessTestCase):
    def test_existing_file(self):
        # $TSHARK -r "${CAPTURE_DIR}dhcp.pcap" > ./testout.txt 2>&1
        cap_file = os.path.join(config.capture_dir, 'dhcp.pcap')
        self.assertRun((config.cmd_tshark, '-r', cap_file))

    def test_nonexistent_file(self):
        # $TSHARK - r ThisFileDontExist.pcap > ./testout.txt 2 > &1
        cap_file = os.path.join(config.capture_dir, '__ceci_nest_pas_une.pcap')
        self.assertRun((config.cmd_tshark, '-r', cap_file),
                       expected_return=self.exit_error)


class case_tshark_invalid_chars(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_invalid_chars(self):
        '''Invalid tshark parameters'''
        for char_arg in 'ABCEFHJKMNORTUWXYZabcdefijkmorstuwyz':
            self.assertRun((config.cmd_tshark, '-' + char_arg),
                           expected_return=self.exit_command_line)


class case_tshark_valid_chars(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_valid_chars(self):
        for char_arg in 'Ghv':
            self.assertRun((config.cmd_tshark, '-' + char_arg))


class case_tshark_invalid_interface_chars(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_interface_chars(self):
        '''Valid tshark parameters requiring capture permissions'''
        valid_returns = [self.exit_ok, self.exit_error]
        for char_arg in 'DL':
            process = self.runProcess((config.cmd_tshark, '-' + char_arg))
            self.assertIn(process.returncode, valid_returns)


class case_tshark_capture_clopts(subprocesstest.SubprocessTestCase):
    def test_tshark_invalid_capfilter(self):
        '''Invalid capture filter'''
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        invalid_filter = '__invalid_protocol'
        # $TSHARK -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((config.cmd_tshark, '-f', invalid_filter, '-w', testout_file ))
        self.assertTrue(self.grepOutput('Invalid capture filter "' + invalid_filter + '" for interface'))

    def test_tshark_invalid_interface_name(self):
        '''Invalid capture interface name'''
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        invalid_interface = '__invalid_interface'
        # $TSHARK -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((config.cmd_tshark, '-i', invalid_interface, '-w', testout_file))
        self.assertTrue(self.grepOutput('The capture session could not be initiated'))

    def test_tshark_invalid_interface_index(self):
        '''Invalid capture interface index'''
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        invalid_index = '0'
        # $TSHARK -i 0 -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((config.cmd_tshark, '-i', invalid_index, '-w', testout_file))
        self.assertTrue(self.grepOutput('There is no interface with that adapter index'))


class case_tshark_name_resolution_clopts(subprocesstest.SubprocessTestCase):
    def test_tshark_valid_name_resolution(self):
        if not config.canCapture():
            self.skipTest('Test requires capture privileges and an interface.')
        # $TSHARK -N mntC -a duration:1 > ./testout.txt 2>&1
        self.assertRun((config.cmd_tshark, '-N', 'mntC', '-a', 'duration: 1'))

    # XXX Add invalid name resolution.

class case_tshark_unicode_clopts(subprocesstest.SubprocessTestCase):
    def test_tshark_unicode_display_filter(self):
        '''Unicode (UTF-8) display filter'''
        cap_file = os.path.join(config.capture_dir, 'http.pcap')
        self.runProcess((config.cmd_tshark, '-r', cap_file, '-Y', 'tcp.flags.str == "·······AP···"'))
        self.assertTrue(self.grepOutput('HEAD.*/v4/iuident.cab'))


class case_tshark_dump_glossaries(subprocesstest.SubprocessTestCase):
    def test_tshark_dump_glossary(self):
        for glossary in glossaries:
            try:
                self.log_fd.truncate()
            except:
                pass
            self.assertRun((config.cmd_tshark, '-G', glossary))
            self.assertEqual(self.countOutput(count_stdout=False, count_stderr=True), 0, 'Found error output while printing glossary ' + glossary)

    def test_tshark_glossary_valid_utf8(self):
        for glossary in glossaries:
            env = os.environ.copy()
            env['LANG'] = 'en_US.UTF-8'
            g_contents = subprocess.check_output((config.cmd_tshark, '-G', glossary), env=env, stderr=subprocess.PIPE)
            decoded = True
            try:
                g_contents.decode('UTF-8')
            except UnicodeDecodeError:
                decoded = False
            self.assertTrue(decoded, '{} is not valid UTF-8'.format(glossary))

    def test_tshark_glossary_plugin_count(self):
        self.runProcess((config.cmd_tshark, '-G', 'plugins'), env=os.environ.copy())
        self.assertGreaterEqual(self.countOutput('dissector'), 10, 'Fewer than 10 dissector plugins found')


# Purposefully fail a test. Used for testing the test framework.
# class case_fail_on_purpose(subprocesstest.SubprocessTestCase):
#     def test_fail_on_purpose(self):
#         self.runProcess(('echo', 'hello, world'))
#         self.fail('Not implemented')
