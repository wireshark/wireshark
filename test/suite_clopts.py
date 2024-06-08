#
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
from subprocesstest import ExitCodes, grep_output, count_output
import shutil
import pytest

#glossaries = ('fields', 'protocols', 'values', 'decodes', 'defaultprefs', 'currentprefs')

glossaries = ('decodes', 'values')
testout_pcap = 'testout.pcap'


class TestDumpcapOptions:
    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_invalid_chars(self, cmd_dumpcap, base_env):
        '''Invalid dumpcap parameters'''
        for char_arg in 'CEFGHJKNORTUVWXYejloxz':
            process = subprocesstest.run((cmd_dumpcap, '-' + char_arg), env=base_env)
            assert process.returncode == ExitCodes.COMMAND_LINE

    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_valid_chars(self, cmd_dumpcap, base_env):
        for char_arg in 'hv':
            process = subprocesstest.run((cmd_dumpcap, '-' + char_arg), env=base_env)
            assert process.returncode == ExitCodes.OK

    # XXX Should we generate individual test functions instead of looping?
    def test_dumpcap_interface_chars(self, cmd_dumpcap, base_env):
        '''Valid dumpcap parameters requiring capture permissions'''
        valid_returns = [ExitCodes.OK, ExitCodes.INVALID_INTERFACE]
        for char_arg in 'DL':
            process = subprocesstest.run((cmd_dumpcap, '-' + char_arg), env=base_env)
            assert process.returncode in valid_returns


class TestDumpcapClopts:
    def test_dumpcap_invalid_capfilter(self, cmd_dumpcap, capture_interface, result_file, base_env):
        '''Invalid capture filter'''
        invalid_filter = '__invalid_protocol'
        # $DUMPCAP -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = result_file(testout_pcap)
        process = subprocesstest.run((cmd_dumpcap, '-f', invalid_filter, '-w', testout_file), capture_output=True, env=base_env)
        assert grep_output(process.stderr, 'Invalid capture filter "' + invalid_filter + '" for interface')

    def test_dumpcap_invalid_interface_name(self, cmd_dumpcap, capture_interface, result_file, base_env):
        '''Invalid capture interface name'''
        invalid_interface = '__invalid_interface'
        # $DUMPCAP -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = result_file(testout_pcap)
        process = subprocesstest.run((cmd_dumpcap, '-i', invalid_interface, '-w', testout_file), capture_output=True, env=base_env)
        assert grep_output(process.stderr, 'There is no device named "__invalid_interface"') or \
                grep_output(process.stderr, 'The capture session could not be initiated on capture device "__invalid_interface"')

    def test_dumpcap_invalid_interface_index(self, cmd_dumpcap, capture_interface, result_file, base_env):
        '''Invalid capture interface index'''
        invalid_index = '0'
        # $DUMPCAP -i 0 -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = result_file(testout_pcap)
        process = subprocesstest.run((cmd_dumpcap, '-i', invalid_index, '-w', testout_file), capture_output=True, env=base_env)
        assert grep_output(process.stderr, 'There is no interface with that adapter index')


class TestBasicClopts:
    def test_existing_file(self, cmd_tshark, capture_file, test_env):
        # $TSHARK -r "${CAPTURE_DIR}dhcp.pcap" > ./testout.txt 2>&1
        process = subprocesstest.run((cmd_tshark, '-r', capture_file('dhcp.pcap')), env=test_env)
        assert process.returncode == ExitCodes.OK

    def test_existing_file_longopt(self, cmd_tshark, capture_file, test_env):
        # $TSHARK -r "${CAPTURE_DIR}dhcp.pcap" > ./testout.txt 2>&1
        process = subprocesstest.run((cmd_tshark, '--read-file', capture_file('dhcp.pcap'),
            '--display-filter', 'dhcp'), env=test_env)
        assert process.returncode == ExitCodes.OK

    def test_nonexistent_file(self, cmd_tshark, capture_file, test_env):
        # $TSHARK - r ThisFileDontExist.pcap > ./testout.txt 2 > &1
        process = subprocesstest.run((cmd_tshark, '-r', capture_file('__ceci_nest_pas_une.pcap')), env=test_env)
        assert process.returncode == ExitCodes.INVALID_FILE_ERROR


class TestTsharkOptions:
    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_invalid_chars(self, cmd_tshark, test_env):
        '''Invalid tshark parameters'''
        for char_arg in 'ABCEFHJKMNORTUWXYZabcdefijkmorstuwyz':
            process = subprocesstest.run((cmd_tshark, '-' + char_arg), env=test_env)
            assert process.returncode == ExitCodes.COMMAND_LINE

    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_valid_chars(self, cmd_tshark, test_env):
        for char_arg in 'Ghv':
            process = subprocesstest.run((cmd_tshark, '-' + char_arg), env=test_env)
            assert process.returncode == ExitCodes.OK

    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_interface_chars(self, cmd_tshark, cmd_dumpcap, test_env):
        '''Valid tshark parameters requiring capture permissions'''
        # These options require dumpcap, but may fail with a pacp error
        # if WinPcap or Npcap are not present
        valid_returns = [ExitCodes.OK, ExitCodes.PCAP_ERROR, ExitCodes.INVALID_CAPABILITY, ExitCodes.INVALID_INTERFACE]
        for char_arg in 'DL':
            process = subprocesstest.run((cmd_tshark, '-' + char_arg), env=test_env)
            assert process.returncode in valid_returns

    def test_tshark_disable_protos(self, cmd_tshark, capture_file, test_env):
        '''--disable-protocol/--enable-protocol from !16923'''
        process = subprocesstest.run((cmd_tshark, "-r", capture_file("http.pcap"),
                    "--disable-protocol", "ALL",
                    "--enable-protocol", "eth,ip",
                    "-Tjson", "-eeth.type", "-eip.proto", "-ehttp.host",
                    ), capture_output=True, env=test_env)
        assert process.returncode == ExitCodes.OK
        obj = json.loads(process.stdout)[0]['_source']['layers']
        assert obj.get('eth.type', 'NOT FOUND') == ['0x0800']
        assert obj.get('ip.proto', 'NOT FOUND') == ['6']
        assert obj.get('http.host', 'NOT FOUND') == 'NOT FOUND'


class TestTsharkCaptureClopts:
    def test_tshark_invalid_capfilter(self, cmd_tshark, capture_interface, result_file, test_env):
        '''Invalid capture filter'''
        invalid_filter = '__invalid_protocol'
        # $TSHARK -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = result_file(testout_pcap)
        process = subprocesstest.run((cmd_tshark, '-f', invalid_filter, '-w', testout_file ), capture_output=True, env=test_env)
        assert grep_output(process.stderr, 'Invalid capture filter "' + invalid_filter + '" for interface')

    def test_tshark_invalid_interface_name(self, cmd_tshark, capture_interface, result_file, test_env):
        '''Invalid capture interface name'''
        invalid_interface = '__invalid_interface'
        # $TSHARK -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = result_file(testout_pcap)
        process = subprocesstest.run((cmd_tshark, '-i', invalid_interface, '-w', testout_file), capture_output=True, env=test_env)
        assert grep_output(process.stderr, 'There is no device named "__invalid_interface"') or \
                grep_output(process.stderr, 'The capture session could not be initiated on capture device "__invalid_interface"')

    def test_tshark_invalid_interface_index(self, cmd_tshark, capture_interface, result_file, test_env):
        '''Invalid capture interface index'''
        invalid_index = '0'
        # $TSHARK -i 0 -w './testout.pcap' > ./testout.txt 2>&1
        testout_file = result_file(testout_pcap)
        process = subprocesstest.run((cmd_tshark, '-i', invalid_index, '-w', testout_file), capture_output=True, env=test_env)
        assert grep_output(process.stderr, 'There is no interface with that adapter index')


class TestTsharkNameResolutionClopts:
    def test_tshark_valid_name_resolution(self, cmd_tshark, capture_file, test_env):
        # $TSHARK -N mnNtdv -a duration:1 > ./testout.txt 2>&1
        process = subprocesstest.run((cmd_tshark,
            '-r', capture_file('empty.pcap'),
            '-N', 'mnNtdv',
        ), env=test_env)
        assert process.returncode == 0

    # XXX Add invalid name resolution.

class TestTsharkUnicodeClopts:
    def test_tshark_unicode_display_filter(self, cmd_tshark, capture_file, test_env):
        '''Unicode (UTF-8) display filter'''
        process = subprocesstest.run((cmd_tshark, '-r', capture_file('http.pcap'), '-Y', 'tcp.flags.str == "·······AP···"'), capture_output=True, env=test_env)
        assert grep_output(process.stdout, 'HEAD.*/v4/iuident.cab')


class TestTsharkDumpGlossaries:
    def test_tshark_dump_glossary(self, cmd_tshark, base_env):
        for glossary in glossaries:
            process = subprocesstest.run((cmd_tshark, '-G', glossary), capture_output=True, env=base_env)
            assert not process.stderr, 'Found error output while printing glossary ' + glossary

    def test_tshark_glossary_valid_utf8(self, cmd_tshark, base_env):
        for glossary in glossaries:
            env = base_env
            env['LANG'] = 'en_US.UTF-8'
            # subprocess.run() returns bytes here.
            proc = subprocess.run((cmd_tshark, '-G', glossary), capture_output=True, env=env)
            assert proc.returncode == 0
            proc.stdout.decode('UTF-8')

    def test_tshark_glossary_plugin_count(self, cmd_tshark, base_env, features):
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        process = subprocesstest.run((cmd_tshark, '-G', 'plugins'), capture_output=True, env=base_env)
        assert count_output(process.stdout, 'dissector') >= 10, 'Fewer than 10 dissector plugins found'

    def test_tshark_elastic_mapping(self, cmd_tshark, dirs, base_env):
        def get_ip_props(obj):
            return obj['mappings']['properties']['layers']['properties']['ip']['properties']
        baseline_file = os.path.join(dirs.baseline_dir, 'elastic-mapping-ip-subset.json')
        with open(baseline_file) as f:
            expected_obj = json.load(f)
        keys_to_check = get_ip_props(expected_obj).keys()
        proc = subprocesstest.run((cmd_tshark, '-G', 'elastic-mapping', '--elastic-mapping-filter', 'ip'), capture_output=True, env=base_env)
        actual_obj = json.loads(proc.stdout)
        ip_props = get_ip_props(actual_obj)
        for key in list(ip_props.keys()):
            if key not in keys_to_check:
                del ip_props[key]
        assert actual_obj == expected_obj

    def test_tshark_unicode_folders(self, cmd_tshark, unicode_env, features):
        '''Folders output with unicode'''
        if not features.have_lua:
            pytest.skip('Test requires Lua scripting support.')
        if sys.platform == 'win32' and not features.have_lua_unicode:
            pytest.skip('Test requires a patched Lua build with UTF-8 support.')
        proc = subprocesstest.run((cmd_tshark, '-G', 'folders'), capture_output=True, env=unicode_env.env)
        out = proc.stdout
        pluginsdir = [x.split('\t', 1)[1] for x in out.splitlines() if x.startswith('Personal Lua Plugins:')]
        assert [unicode_env.pluginsdir] == pluginsdir


class TestTsharkZExpert:
    def test_tshark_z_expert_all(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert',
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        # http2-data-reassembly.pcap has Errors, Warnings, Notes, and Chats
        # when TCP checksum are verified.
        assert grep_output(proc.stdout, 'Errors')
        assert grep_output(proc.stdout, 'Warns')
        assert grep_output(proc.stdout, 'Notes')
        assert grep_output(proc.stdout, 'Chats')

    def test_tshark_z_expert_error(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,error',
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        assert grep_output(proc.stdout, 'Errors')
        assert not grep_output(proc.stdout, 'Warns')
        assert not grep_output(proc.stdout, 'Notes')
        assert not grep_output(proc.stdout, 'Chats')

    def test_tshark_z_expert_warn(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,warn',
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        assert grep_output(proc.stdout, 'Errors')
        assert grep_output(proc.stdout, 'Warns')
        assert not grep_output(proc.stdout, 'Notes')
        assert not grep_output(proc.stdout, 'Chats')

    def test_tshark_z_expert_note(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,note',
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        assert grep_output(proc.stdout, 'Errors')
        assert grep_output(proc.stdout, 'Warns')
        assert grep_output(proc.stdout, 'Notes')
        assert not grep_output(proc.stdout, 'Chats')

    def test_tshark_z_expert_chat(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,chat',
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        assert grep_output(proc.stdout, 'Errors')
        assert grep_output(proc.stdout, 'Warns')
        assert grep_output(proc.stdout, 'Notes')
        assert grep_output(proc.stdout, 'Chats')

    def test_tshark_z_expert_comment(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,comment',
            '-r', capture_file('sip.pcapng')), capture_output=True, env=test_env)
        assert grep_output(proc.stdout, 'Notes')
        assert grep_output(proc.stdout, 'Comments')

    def test_tshark_z_expert_invalid_filter(self, cmd_tshark, capture_file, test_env):
        invalid_filter = '__invalid_protocol'
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,' + invalid_filter,
            '-r', capture_file('http-ooo.pcap')), capture_output=True, env=test_env)
        assert proc.returncode == ExitCodes.COMMAND_LINE
        assert grep_output(proc.stdout, 'Filter "' + invalid_filter + '" is invalid')

    def test_tshark_z_expert_error_invalid_filter(self, cmd_tshark, capture_file, test_env):
        invalid_filter = '__invalid_protocol'
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,error,' + invalid_filter,
            '-r', capture_file('http-ooo.pcap')), capture_output=True, env=test_env)
        assert proc.returncode == ExitCodes.COMMAND_LINE
        assert grep_output(proc.stdout, 'Filter "' + invalid_filter + '" is invalid')

    def test_tshark_z_expert_filter(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,udp',
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        # Filtering for UDP should produce no expert infos.
        assert not grep_output(proc.stdout, 'Errors')
        assert not grep_output(proc.stdout, 'Warns')
        assert not grep_output(proc.stdout, 'Notes')
        assert not grep_output(proc.stdout, 'Chats')

    def test_tshark_z_expert_error_filter(self, cmd_tshark, capture_file, test_env):
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,note,http',  # tls is a filter
            '-o', 'tcp.check_checksum:TRUE',
            '-r', capture_file('http-ooo-fuzzed.pcapng')), capture_output=True, env=test_env)
        # Filtering for HTTP and Note level expert info should produce only
        # Error and Warning level expert infos with checksumming turned on.
        # The Note warnings on are packets with TCP but not HTTP, and we're
        # filtering out the Chat level.
        assert grep_output(proc.stdout, 'Errors')
        assert grep_output(proc.stdout, 'Warns')
        assert not grep_output(proc.stdout, 'Notes')
        assert not grep_output(proc.stdout, 'Chats')


class TestTsharkExtcap:
    # dumpcap dependency has been added to run this test only with capture support
    def test_tshark_extcap_interfaces(self, cmd_tshark, cmd_dumpcap, test_env, home_path):
        # Script extcaps don't work with the current code on windows.
        # https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
        # TODO: skip this test until it will get fixed.
        if sys.platform == 'win32':
            pytest.skip('FIXME extcap .py scripts needs special treatment on Windows')
        extcap_dir_path = os.path.join(home_path, 'extcap')
        os.makedirs(extcap_dir_path)
        test_env['WIRESHARK_EXTCAP_DIR'] = extcap_dir_path
        source_file = os.path.join(os.path.dirname(__file__), 'sampleif.py')
        # We run our tests in a bare, reproducible home environment. This can result in an
        # invalid or missing Python interpreter if our main environment has a wonky Python
        # path, as is the case in the GitLab SaaS macOS runners which use `asdf`. Force
        # sampleif.py to use our current Python executable.
        with open(source_file, 'r') as sf:
            sampleif_py = sf.read()
            sampleif_py = sampleif_py.replace('/usr/bin/env python3', sys.executable)
            sys.stderr.write(sampleif_py)
            extcap_file = os.path.join(extcap_dir_path, 'sampleif.py')
            with open(extcap_file, 'w') as ef:
                ef.write(sampleif_py)
                os.fchmod(ef.fileno(), os.fstat(sf.fileno()).st_mode)

        # Ensure the test extcap_tool is properly loaded
        proc = subprocesstest.run((cmd_tshark, '-D'), capture_output=True, env=test_env)
        assert count_output(proc.stdout, 'sampleif') == 1
        # Ensure tshark lists 2 interfaces in the preferences
        proc = subprocesstest.run((cmd_tshark, '-G', 'currentprefs'), capture_output=True, env=test_env)
        assert count_output(proc.stdout, 'extcap.sampleif.test') == 2
