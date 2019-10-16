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

import json
import sys
import os.path
import subprocess
import subprocesstest
import fixtures
import shutil

#glossaries = ('fields', 'protocols', 'values', 'decodes', 'defaultprefs', 'currentprefs')

glossaries = ('decodes', 'values')
testout_pcap = 'testout.pcap'


@fixtures.uses_fixtures
class case_dumpcap_options(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_invalid_chars(self, cmd_dumpcap, base_env):
        '''Invalid dumpcap parameters'''
        for char_arg in 'CEFGHJKNOQRTUVWXYejloxz':
            self.assertRun((cmd_dumpcap, '-' + char_arg), env=base_env,
                           expected_return=self.exit_command_line)

    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_valid_chars(self, cmd_dumpcap, base_env):
        for char_arg in 'hv':
            self.assertRun((cmd_dumpcap, '-' + char_arg), env=base_env)

    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_interface_chars(self, cmd_dumpcap, base_env):
        '''Valid dumpcap parameters requiring capture permissions'''
        valid_returns = [self.exit_ok, self.exit_error]
        for char_arg in 'DL':
            process = self.runProcess((cmd_dumpcap, '-' + char_arg), env=base_env)
            self.assertIn(process.returncode, valid_returns)


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_dumpcap_capture_clopts(subprocesstest.SubprocessTestCase):
    def test_dumpcap_invalid_capfilter(self, cmd_dumpcap, capture_interface):
        '''Invalid capture filter'''
        invalid_filter = '__invalid_protocol'
        # $DUMPCAP -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((cmd_dumpcap, '-f', invalid_filter, '-w', testout_file))
        self.assertTrue(self.grepOutput('Invalid capture filter "' + invalid_filter + '" for interface'))

    def test_dumpcap_invalid_interface_name(self, cmd_dumpcap, capture_interface):
        '''Invalid capture interface name'''
        invalid_interface = '__invalid_interface'
        # $DUMPCAP -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((cmd_dumpcap, '-i', invalid_interface, '-w', testout_file))
        self.assertTrue(self.grepOutput('The capture session could not be initiated'))

    def test_dumpcap_invalid_interface_index(self, cmd_dumpcap, capture_interface):
        '''Invalid capture interface index'''
        invalid_index = '0'
        # $DUMPCAP -i 0 -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((cmd_dumpcap, '-i', invalid_index, '-w', testout_file))
        self.assertTrue(self.grepOutput('There is no interface with that adapter index'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_basic_clopts(subprocesstest.SubprocessTestCase):
    def test_existing_file(self, cmd_tshark, capture_file):
        # $TSHARK -r "${CAPTURE_DIR}dhcp.pcap" > ./testout.txt 2>&1
        self.assertRun((cmd_tshark, '-r', capture_file('dhcp.pcap')))

    def test_nonexistent_file(self, cmd_tshark, capture_file):
        # $TSHARK - r ThisFileDontExist.pcap > ./testout.txt 2 > &1
        self.assertRun((cmd_tshark, '-r', capture_file('__ceci_nest_pas_une.pcap')),
                       expected_return=self.exit_error)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_options(subprocesstest.SubprocessTestCase):
    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_invalid_chars(self, cmd_tshark):
        '''Invalid tshark parameters'''
        for char_arg in 'ABCEFHJKMNORTUWXYZabcdefijkmorstuwyz':
            self.assertRun((cmd_tshark, '-' + char_arg),
                           expected_return=self.exit_command_line)

    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_valid_chars(self, cmd_tshark):
        for char_arg in 'Ghv':
            self.assertRun((cmd_tshark, '-' + char_arg))

    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_interface_chars(self, cmd_tshark, cmd_dumpcap):
        '''Valid tshark parameters requiring capture permissions'''
        # These options require dumpcap
        valid_returns = [self.exit_ok, self.exit_error]
        for char_arg in 'DL':
            process = self.runProcess((cmd_tshark, '-' + char_arg))
            self.assertIn(process.returncode, valid_returns)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_capture_clopts(subprocesstest.SubprocessTestCase):
    def test_tshark_invalid_capfilter(self, cmd_tshark, capture_interface):
        '''Invalid capture filter'''
        invalid_filter = '__invalid_protocol'
        # $TSHARK -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((cmd_tshark, '-f', invalid_filter, '-w', testout_file ))
        self.assertTrue(self.grepOutput('Invalid capture filter "' + invalid_filter + '" for interface'))

    def test_tshark_invalid_interface_name(self, cmd_tshark, capture_interface):
        '''Invalid capture interface name'''
        invalid_interface = '__invalid_interface'
        # $TSHARK -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((cmd_tshark, '-i', invalid_interface, '-w', testout_file))
        self.assertTrue(self.grepOutput('The capture session could not be initiated'))

    def test_tshark_invalid_interface_index(self, cmd_tshark, capture_interface):
        '''Invalid capture interface index'''
        invalid_index = '0'
        # $TSHARK -i 0 -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        self.runProcess((cmd_tshark, '-i', invalid_index, '-w', testout_file))
        self.assertTrue(self.grepOutput('There is no interface with that adapter index'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_name_resolution_clopts(subprocesstest.SubprocessTestCase):
    def test_tshark_valid_name_resolution(self, cmd_tshark, capture_interface):
        # $TSHARK -N mnNtdv -a duration:1 > ./testout.txt 2>&1
        self.assertRun((cmd_tshark, '-N', 'mnNtdv', '-a', 'duration: 1'))

    # XXX Add invalid name resolution.

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_unicode_clopts(subprocesstest.SubprocessTestCase):
    def test_tshark_unicode_display_filter(self, cmd_tshark, capture_file):
        '''Unicode (UTF-8) display filter'''
        self.assertRun((cmd_tshark, '-r', capture_file('http.pcap'), '-Y', 'tcp.flags.str == "·······AP···"'))
        self.assertTrue(self.grepOutput('HEAD.*/v4/iuident.cab'))


@fixtures.uses_fixtures
class case_tshark_dump_glossaries(subprocesstest.SubprocessTestCase):
    def test_tshark_dump_glossary(self, cmd_tshark, base_env):
        for glossary in glossaries:
            try:
                self.log_fd.truncate()
            except:
                pass
            self.assertRun((cmd_tshark, '-G', glossary), env=base_env)
            self.assertEqual(self.countOutput(count_stdout=False, count_stderr=True), 0, 'Found error output while printing glossary ' + glossary)

    def test_tshark_glossary_valid_utf8(self, cmd_tshark, base_env):
        for glossary in glossaries:
            env = base_env
            env['LANG'] = 'en_US.UTF-8'
            g_contents = subprocess.check_output((cmd_tshark, '-G', glossary), env=env, stderr=subprocess.PIPE)
            decoded = True
            try:
                g_contents.decode('UTF-8')
            except UnicodeDecodeError:
                decoded = False
            self.assertTrue(decoded, '{} is not valid UTF-8'.format(glossary))

    def test_tshark_glossary_plugin_count(self, cmd_tshark, base_env):
        self.assertRun((cmd_tshark, '-G', 'plugins'), env=base_env)
        self.assertGreaterEqual(self.countOutput('dissector'), 10, 'Fewer than 10 dissector plugins found')

    def test_tshark_elastic_mapping(self, cmd_tshark, dirs, base_env):
        def get_ip_props(obj):
            return obj['mappings']['doc']['properties']['layers']['properties']['ip']['properties']
        self.maxDiff = None
        baseline_file = os.path.join(dirs.baseline_dir, 'elastic-mapping-ip-subset.json')
        with open(baseline_file) as f:
            expected_obj = json.load(f)
        keys_to_check = get_ip_props(expected_obj).keys()
        proc = self.assertRun((cmd_tshark, '-G', 'elastic-mapping', '--elastic-mapping-filter', 'ip'))
        actual_obj = json.loads(proc.stdout_str)
        ip_props = get_ip_props(actual_obj)
        for key in list(ip_props.keys()):
            if key not in keys_to_check:
                del ip_props[key]
        self.assertEqual(actual_obj, expected_obj)

    def test_tshark_unicode_folders(self, cmd_tshark, unicode_env, features):
        '''Folders output with unicode'''
        if not features.have_lua:
            self.skipTest('Test requires Lua scripting support.')
        proc = self.assertRun((cmd_tshark, '-G', 'folders'), env=unicode_env.env)
        out = proc.stdout_str
        pluginsdir = [x.split('\t', 1)[1] for x in out.splitlines() if x.startswith('Personal Lua Plugins:')]
        self.assertEqual([unicode_env.pluginsdir], pluginsdir)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_z_expert(subprocesstest.SubprocessTestCase):
    def test_tshark_z_expert_all(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert',
            '-r', capture_file('http-ooo.pcap')))
        self.assertTrue(self.grepOutput('Errors'))
        self.assertTrue(self.grepOutput('Warns'))
        self.assertTrue(self.grepOutput('Chats'))

    def test_tshark_z_expert_error(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,error',
            '-r', capture_file('http-ooo.pcap')))
        self.assertTrue(self.grepOutput('Errors'))
        self.assertFalse(self.grepOutput('Warns'))
        self.assertFalse(self.grepOutput('Chats'))

    def test_tshark_z_expert_warn(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,warn',
            '-r', capture_file('http-ooo.pcap')))
        self.assertTrue(self.grepOutput('Errors'))
        self.assertTrue(self.grepOutput('Warns'))
        self.assertFalse(self.grepOutput('Chats'))

    def test_tshark_z_expert_note(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,note',
            '-r', capture_file('http2-data-reassembly.pcap')))
        self.assertTrue(self.grepOutput('Warns'))
        self.assertTrue(self.grepOutput('Notes'))
        self.assertFalse(self.grepOutput('Chats'))

    def test_tshark_z_expert_chat(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,chat',
            '-r', capture_file('http-ooo.pcap')))
        self.assertTrue(self.grepOutput('Errors'))
        self.assertTrue(self.grepOutput('Warns'))
        self.assertTrue(self.grepOutput('Chats'))

    def test_tshark_z_expert_comment(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,comment',
            '-r', capture_file('sip.pcapng')))
        self.assertTrue(self.grepOutput('Notes'))
        self.assertTrue(self.grepOutput('Comments'))

    def test_tshark_z_expert_invalid_filter(self, cmd_tshark, capture_file):
        invalid_filter = '__invalid_protocol'
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,' + invalid_filter,
            '-r', capture_file('http-ooo.pcap')),
            expected_return=self.exit_command_line)
        self.assertTrue(self.grepOutput('Filter "' + invalid_filter + '" is invalid'))

    def test_tshark_z_expert_error_invalid_filter(self, cmd_tshark, capture_file):
        invalid_filter = '__invalid_protocol'
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,error,' + invalid_filter,
            '-r', capture_file('http-ooo.pcap')),
            expected_return=self.exit_command_line)
        self.assertTrue(self.grepOutput('Filter "' + invalid_filter + '" is invalid'))

    def test_tshark_z_expert_filter(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,udp',  # udp is a filter
            '-r', capture_file('http-ooo.pcap')))
        self.assertFalse(self.grepOutput('Errors'))
        self.assertFalse(self.grepOutput('Warns'))
        self.assertFalse(self.grepOutput('Chats'))

    def test_tshark_z_expert_error_filter(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark, '-q', '-z', 'expert,error,udp',  # udp is a filter
            '-r', capture_file('http-ooo.pcap')))
        self.assertFalse(self.grepOutput('Errors'))
        self.assertFalse(self.grepOutput('Warns'))
        self.assertFalse(self.grepOutput('Chats'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_extcap(subprocesstest.SubprocessTestCase):
    # dumpcap dependency has been added to run this test only with capture support
    def test_tshark_extcap_interfaces(self, cmd_tshark, cmd_dumpcap, test_env, home_path):
        # Script extcaps don't work with the current code on windows.
        # https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
        # TODO: skip this test until it will get fixed.
        if sys.platform == 'win32':
            self.skipTest('FIXME extcap .py scripts needs special treatment on Windows')
        extcap_dir_path = os.path.join(home_path, 'extcap')
        os.makedirs(extcap_dir_path)
        test_env['WIRESHARK_EXTCAP_DIR'] = extcap_dir_path
        source_file = os.path.join(os.path.dirname(__file__), 'sampleif.py')
        shutil.copy2(source_file, extcap_dir_path)
        # Ensure the test extcap_tool is properly loaded
        self.assertRun((cmd_tshark, '-D'), env=test_env)
        self.assertEqual(1, self.countOutput('sampleif'))
        # Ensure tshark lists 2 interfaces in the preferences
        self.assertRun((cmd_tshark, '-G', 'currentprefs'), env=test_env)
        self.assertEqual(2, self.countOutput('extcap.sampleif.test'))
