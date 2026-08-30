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
import os.path
import shutil
import subprocess
import sys
import sysconfig
import types

import pytest

import subprocesstest
from subprocesstest import ExitCodes, count_output, grep_output

#glossaries = ('fields', 'protocols', 'values', 'decodes', 'defaultprefs', 'currentprefs')

glossaries = ('decodes', 'values')
profiles = ('all', 'global', 'personal')
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
        # Most of these are valid but require a mandatory parameter
        for char_arg in 'ABCEFGHJKMNORTUWXYZabcdefijkmorstuwyz':
            process = subprocesstest.run((cmd_tshark, '-' + char_arg), env=test_env)
            assert process.returncode == ExitCodes.COMMAND_LINE

    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_valid_chars(self, cmd_tshark, test_env):
        for char_arg in 'hv':
            process = subprocesstest.run((cmd_tshark, '-' + char_arg), env=test_env)
            assert process.returncode == ExitCodes.OK

    # XXX Should we generate individual test functions instead of looping?
    def test_tshark_interface_chars(self, cmd_tshark, cmd_dumpcap, test_env):
        '''Valid tshark parameters requiring capture permissions'''
        # These options require dumpcap, but may fail with a pcap error
        # if Npcap is not present
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

    def test_tshark_dump_profiles(self, cmd_tshark, base_env):
        for profile in profiles:
            process = subprocesstest.run((cmd_tshark, '-G', 'profiles', profile), capture_output=True, env=base_env)
            assert not process.stderr, 'Found error output while printing profiles ' + profile

    def test_tshark_unicode_folders(self, cmd_tshark, unicode_env, features):
        '''Folders output with unicode'''
        if not features.have_lua:
            pytest.skip('Test requires Lua scripting support.')
#        if sys.platform == 'win32' and not features.have_lua_unicode:
#            pytest.skip('Test requires a patched Lua build with UTF-8 support.')
        proc = subprocesstest.run((cmd_tshark, '-G', 'folders'), capture_output=True, env=unicode_env.env)
        out = proc.stdout
        pluginsdir = [x.split('\t', 1)[1] for x in out.splitlines() if x.startswith('Personal Lua Plugins:')]
        if sys.platform == 'win32' and sysconfig.get_platform().startswith('mingw') and os.altsep:
            # https://www.msys2.org/docs/python
            # TShark (wsutil/filesystem) always uses the Windows path separator
            # ('\') on MSYS2, but MSYS2's CPython swaps the path separators and
            # prefers '/' when running inside an active MSYS2 environment
            # (e.g., when compiling and running tests.) unicode.env.pluginsdir,
            # unicode_env.path, unicode_env.env['APPDATA'] all use '/' from
            # os.sep in such case. wsutil/filesystem.c probably should use
            # g_build_filename and g_path_get_basename in order to try to
            # handle both directory separator options, but normalize around
            # that for now.
            pluginsdir = [path.replace(os.altsep, os.sep) for path in pluginsdir]
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
        assert grep_output(proc.stderr, 'Filter "' + invalid_filter + '" is invalid')

    def test_tshark_z_expert_error_invalid_filter(self, cmd_tshark, capture_file, test_env):
        invalid_filter = '__invalid_protocol'
        proc = subprocesstest.run((cmd_tshark, '-q', '-z', 'expert,error,' + invalid_filter,
            '-r', capture_file('http-ooo.pcap')), capture_output=True, env=test_env)
        assert proc.returncode == ExitCodes.COMMAND_LINE
        assert grep_output(proc.stderr, 'Filter "' + invalid_filter + '" is invalid')

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


@pytest.fixture
def extcap_pyenv(home_path, test_env, features):
    if not features.have_pcap:
        pytest.skip('Test requires libpcap at runtime.')
    # Various guides and vulnerability scanners recommend setting /tmp noexec.
    # If our temp path is such, the extcap script won't work.
    try:
        if os.statvfs(home_path).f_flag & os.ST_NOEXEC:
            pytest.skip('Test requires temp directory to allow execution')
    except AttributeError:
        # Most Linux and NetBSD have ST_NOEXEC; Darwin and other *BSDs don't.
        # Windows doesn't have statvfs
        pass
    # If the git config core.fileMode is set to false, then the execute bit
    # won't be set. Respect the security policy rather than overriding it.
    if not os.access(home_path, os.X_OK):
        pytest.skip('Test requires execute permission for sampleif.py (is git config core.fileMode false?)')
    extcap_dir_path = os.path.join(home_path, 'extcap')
    os.makedirs(extcap_dir_path)
    test_env['WIRESHARK_EXTCAP_DIR'] = extcap_dir_path
    if sys.platform == 'win32':
        # Assume that Python files (.py) are associated with an appropriate
        # Python interpreter. (We could check this with winreg, perhaps?)
        # To ensure that files are seen as executable,
        # PATHEXT must contain the .py extension. Note this does not affect
        # what Python returns for os.access(source_file, os.X_OK), which uses
        # hardcoded extensions. It does affect what shutil.which() returns.
        test_env['PATHEXT'] += ';.py'
    return types.SimpleNamespace(
        env=test_env,
        extcap_dir=extcap_dir_path
    )

class TestTsharkExtcap:
    # dumpcap dependency has been added to run this test only with capture support
    def test_tshark_extcap_interfaces(self, cmd_tshark, cmd_dumpcap, extcap_pyenv):
        source_file = os.path.join(os.path.dirname(__file__), 'sampleif.py')
        # We run our tests in a bare, reproducible home environment. This can result in an
        # invalid or missing Python interpreter if our main environment has a wonky Python
        # path, as is the case in the GitLab SaaS macOS runners which use `asdf`. Force
        # sampleif.py to use our current Python executable.
        with open(source_file, 'r') as sf:
            sampleif_py = sf.read()
            sampleif_py = sampleif_py.replace('/usr/bin/env python3', sys.executable)
            sys.stderr.write(sampleif_py)
            extcap_file = os.path.join(extcap_pyenv.extcap_dir, 'sampleif.py')
            with open(extcap_file, 'w') as ef:
                ef.write(sampleif_py)
                os.fchmod(ef.fileno(), os.fstat(sf.fileno()).st_mode)

        # Ensure the test extcap_tool is properly loaded
        proc = subprocesstest.run((cmd_tshark, '-D'), capture_output=True, env=extcap_pyenv.env)
        assert count_output(proc.stdout, 'sampleif') == 1
        # Ensure tshark lists 2 interfaces in the preferences
        proc = subprocesstest.run((cmd_tshark, '-G', 'currentprefs'), capture_output=True, env=extcap_pyenv.env)
        assert count_output(proc.stdout, 'extcap.sampleif.test') == 2

class TestStratoOptions:
    # XXX Should we generate individual test functions instead of looping?
    def test_strato_invalid_chars(self, cmd_strato, test_env):
        '''Invalid tshark parameters'''
        # Most of these are valid but require a mandatory parameter
        for char_arg in 'ABCEFGHJKMNORTUWXYZabcdefijkmorstuwyz':
            process = subprocesstest.run((cmd_strato, '-' + char_arg), env=test_env)
            assert process.returncode == ExitCodes.COMMAND_LINE

    # XXX Should we generate individual test functions instead of looping?
    def test_strato_valid_chars(self, cmd_strato, test_env):
        for char_arg in 'hv':
            process = subprocesstest.run((cmd_strato, '-' + char_arg), env=test_env)
            assert process.returncode == ExitCodes.OK

    # # XXX Should we generate individual test functions instead of looping?
    # def test_tshark_interface_chars(self, cmd_tshark, cmd_dumpcap, test_env):
    #     '''Valid tshark parameters requiring capture permissions'''
    #     # These options require dumpcap, but may fail with a pcap error
    #     # if Npcap is not present
    #     valid_returns = [ExitCodes.OK, ExitCodes.PCAP_ERROR, ExitCodes.INVALID_CAPABILITY, ExitCodes.INVALID_INTERFACE]
    #     for char_arg in 'DL':
    #         process = subprocesstest.run((cmd_tshark, '-' + char_arg), env=test_env)
    #         assert process.returncode in valid_returns

    # def test_tshark_disable_protos(self, cmd_tshark, capture_file, test_env):
    #     '''--disable-protocol/--enable-protocol from !16923'''
    #     process = subprocesstest.run((cmd_tshark, "-r", capture_file("http.pcap"),
    #                 "--disable-protocol", "ALL",
    #                 "--enable-protocol", "eth,ip",
    #                 "-Tjson", "-eeth.type", "-eip.proto", "-ehttp.host",
    #                 ), capture_output=True, env=test_env)
    #     assert process.returncode == ExitCodes.OK
    #     obj = json.loads(process.stdout)[0]['_source']['layers']
    #     assert obj.get('eth.type', 'NOT FOUND') == ['0x0800']
    #     assert obj.get('ip.proto', 'NOT FOUND') == ['6']
    #     assert obj.get('http.host', 'NOT FOUND') == 'NOT FOUND'

class TestDftestUnicodeClopts:
    def test_dftest_unicode_display_filter(self, cmd_dftest, test_env):
        '''Dftest Unicode (UTF-8) display filter'''
        process = subprocesstest.run((cmd_dftest, 'tcp.payload contains "é" and _ws.string contains "\U0001F988"'), capture_output=True, env=test_env)
        assert grep_output(process.stdout, 'contains c3:a9')
        assert grep_output(process.stdout, 'contains f0:9f:a6:88') # Unicode Shark
