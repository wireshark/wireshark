#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Wireshark Lua scripting tests'''

import sys
import filecmp
import os.path
import shutil
import subprocess
import pytest
import logging

dhcp_pcap = 'dhcp.pcap'
dns_port_pcap = 'dns_port.pcap'
empty_pcap = 'empty.pcap'
segmented_fpm_pcap = 'segmented_fpm.pcap'
sip_pcapng = 'sip.pcapng'
sipmsg_log = 'sipmsg.log'
wpa_induction_pcap_gz = 'wpa-Induction.pcap.gz'


@pytest.fixture
def check_lua_script(cmd_tshark, features, dirs, capture_file, test_env):
    if not features.have_lua:
        pytest.skip('Test requires Lua scripting support.')
    def check_lua_script_real(lua_script, cap_file, check_passed, *args):
        tshark_cmd = [cmd_tshark,
            '-r', capture_file(cap_file),
            '-X', 'lua_script:' + os.path.join(dirs.lua_dir, lua_script)
        ]
        tshark_cmd += args
        tshark_proc = subprocess.run(tshark_cmd, check=True, capture_output=True, encoding='utf-8', env=test_env)

        if check_passed:
            logging.info(tshark_proc.stdout)
            logging.info(tshark_proc.stderr)
            if not 'All tests passed!' in tshark_proc.stdout:
                pytest.fail("Some test failed, check the logs (eg: pytest --lf --log-cli-level=info)")

        return tshark_proc
    return check_lua_script_real


@pytest.fixture
def check_lua_script_verify(check_lua_script, result_file):
    def check_lua_script_verify_real(lua_script, cap_file, check_stage_1=False, heur_regmode=None):
        # First run tshark with the dissector script.
        if heur_regmode is None:
            tshark_proc = check_lua_script(lua_script, cap_file, check_stage_1,
                '-V'
            )
        else:
            tshark_proc = check_lua_script(lua_script, cap_file, check_stage_1,
                '-V',
                '-X', 'lua_script1:heur_regmode={}'.format(heur_regmode)
            )

        # then dump tshark's output to a verification file.
        verify_file = result_file('testin.txt')
        with open(verify_file, 'w', newline='\n') as f:
            f.write(tshark_proc.stdout)

        # finally run tshark again with the verification script and the verification file.
        if heur_regmode is None:
            check_lua_script('verify_dissector.lua', empty_pcap, True,
                '-X', 'lua_script1:verify_file=' + verify_file,
            )
        else:
            check_lua_script('verify_dissector.lua', empty_pcap, True,
                '-X', 'lua_script1:verify_file=' + verify_file,
                '-X', 'lua_script1:no_heur',
            )
    return check_lua_script_verify_real


class TestWslua:
    def test_wslua_dir(self, check_lua_script):
        '''wslua directory functions'''
        check_lua_script('dir.lua', empty_pcap, True)

    def test_wslua_util(self, check_lua_script):
        '''wslua utility functions'''
        check_lua_script('util.lua', empty_pcap, True)

    # Mode_1, mode_2, and mode_3, and fpm were all under wslua_step_dissector_test
    # in the Bash version.
    def test_wslua_dissector_mode_1(self, check_lua_script_verify):
        '''wslua dissector functions, mode 1'''
        check_lua_script_verify('dissector.lua', dns_port_pcap)

    def test_wslua_dissector_mode_2(self, check_lua_script_verify):
        '''wslua dissector functions, mode 2'''
        check_lua_script_verify('dissector.lua', dns_port_pcap, heur_regmode=2)

    def test_wslua_dissector_mode_3(self, check_lua_script_verify):
        '''wslua dissector functions, mode 3'''
        check_lua_script_verify('dissector.lua', dns_port_pcap, heur_regmode=3)

    def test_wslua_dissector_fpm(self, check_lua_script):
        '''wslua dissector functions, fpm'''
        tshark_fpm_tcp_proc = check_lua_script('dissectFPM.lua', segmented_fpm_pcap, False,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'fpm',
            '-e', 'fpm.version',
            '-e', 'fpm.type',
            '-e', 'fpm.length',
            '-o', 'fpm.dissect_tcp:true'
        )

        tshark_fpm_no_tcp_proc = check_lua_script('dissectFPM.lua', segmented_fpm_pcap, False,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'fpm',
            '-e', 'fpm.version',
            '-e', 'fpm.type',
            '-e', 'fpm.length',
            '-o', 'fpm.dissect_tcp:false'
        )

        assert tshark_fpm_tcp_proc.stdout == tshark_fpm_no_tcp_proc.stdout

    def test_wslua_field(self, check_lua_script):
        '''wslua fields'''
        check_lua_script('field.lua', dhcp_pcap, True, '-q', '-c1')

    # reader, writer, and acme_reader were all under wslua_step_file_test
    # in the Bash version.
    def test_wslua_file_reader(self, check_lua_script, cmd_tshark, capture_file, test_env):
        '''wslua file reader'''
        cap_file_1 = capture_file(dhcp_pcap)
        cap_file_2 = capture_file(wpa_induction_pcap_gz)

        # First run tshark with the pcap_file_reader script.
        lua_proc_1 = check_lua_script('pcap_file.lua', cap_file_1, False)
        lua_proc_2 = check_lua_script('pcap_file.lua', cap_file_2, False)
        lua_out = lua_proc_1.stdout + lua_proc_2.stdout

        # then run tshark again without the script
        tshark_proc_1 = subprocess.run((cmd_tshark, '-r', cap_file_1), check=True, capture_output=True, encoding='utf-8', env=test_env)
        tshark_proc_2 = subprocess.run((cmd_tshark, '-r', cap_file_2), check=True, capture_output=True, encoding='utf-8', env=test_env)
        tshark_out = tshark_proc_1.stdout + tshark_proc_2.stdout

        assert lua_out == tshark_out

    def test_wslua_file_writer(self, check_lua_script, capture_file, result_file):
        '''wslua file writer'''
        cap_file_1 = capture_file(dhcp_pcap)
        cap_file_2 = result_file('lua_writer.pcap')

        # Generate a new capture file using the Lua writer.
        check_lua_script('pcap_file.lua', cap_file_1, False,
            '-w', cap_file_2,
            '-F', 'lua_pcap2',
        )
        assert filecmp.cmp(cap_file_1, cap_file_2), cap_file_1 + ' differs from ' + cap_file_2

    def test_wslua_file_acme_reader(self, check_lua_script, cmd_tshark, capture_file, result_file, test_env):
        '''wslua acme file reader'''

        cap_file = result_file('lua_acme_reader.pcap')
        # Read an acme sipmsg.log using the acme Lua reader, writing it out as pcapng.
        check_lua_script('acme_file.lua', sipmsg_log, False,
            '-w', cap_file,
            '-F', 'pcapng',
        )

        # Read lua_acme_reader.pcap and sip.pcapng and compare their verbose outputs.
        tshark_proc_1 = subprocess.run((cmd_tshark,
            '-r', cap_file,
            '-V'
        ), check=True, capture_output=True, encoding='utf-8', env=test_env)
        tshark_proc_2 = subprocess.run((cmd_tshark,
            '-r', capture_file(sip_pcapng),
            '-V'
        ), check=True, capture_output=True, encoding='utf-8', env=test_env)

        assert tshark_proc_1.stdout == tshark_proc_2.stdout

    def test_wslua_listener(self, check_lua_script):
        '''wslua listener'''
        check_lua_script('listener.lua', dhcp_pcap, True)

    def test_wslua_nstime(self, check_lua_script):
        '''wslua nstime'''
        check_lua_script('nstime.lua', dhcp_pcap, True, '-q')

    def test_wslua_pinfo(self, check_lua_script):
        '''wslua pinfo'''
        check_lua_script('pinfo.lua', dhcp_pcap, True)

    def test_wslua_proto(self, check_lua_script):
        '''wslua proto'''
        check_lua_script('proto.lua', empty_pcap, True)

    def test_wslua_byte_array(self, check_lua_script):
        '''wslua byte_array'''
        check_lua_script('byte_array.lua', empty_pcap, True)

    def test_wslua_protofield_tree(self, check_lua_script):
        '''wslua protofield with a tree'''
        check_lua_script('protofield.lua', dns_port_pcap, True,
            '-V',
            '-Y', 'test.filtered==1',
        )

    def test_wslua_protofield_no_tree(self, check_lua_script):
        '''wslua protofield without a tree'''
        check_lua_script('protofield.lua', dns_port_pcap, True,
            '-Y', 'test.filtered==1',
        )

    def test_wslua_int64(self, check_lua_script):
        '''wslua int64'''
        check_lua_script('int64.lua', empty_pcap, True)

    def test_wslua_args_1(self, check_lua_script):
        '''wslua args 1'''
        check_lua_script('script_args.lua', empty_pcap, True,
            '-X', 'lua_script1:1',
        )

    def test_wslua_args_2(self, check_lua_script):
        '''wslua args 2'''
        check_lua_script('script_args.lua', empty_pcap, True,
            '-X', 'lua_script1:3',
            '-X', 'lua_script1:foo',
            '-X', 'lua_script1:bar',
        )

    def test_wslua_args_3(self, check_lua_script, dirs):
        '''wslua args 3'''
        check_lua_script('script_args.lua', empty_pcap, True,
            '-X', 'lua_script:' + os.path.join(dirs.lua_dir, 'script_args.lua'),
            '-X', 'lua_script1:3',
            '-X', 'lua_script2:1',
            '-X', 'lua_script1:foo',
            '-X', 'lua_script1:bar',
        )

    def test_wslua_args_4(self, check_lua_script):
        '''wslua args 4'''
        tshark_proc = check_lua_script('script_args.lua', empty_pcap, False)
        assert 'All tests passed!' not in tshark_proc.stdout

    def test_wslua_args_5(self, check_lua_script):
        '''wslua args 5'''
        tshark_proc = check_lua_script('script_args.lua', empty_pcap, False,
            '-X', 'lua_script1:3',
        )
        assert 'All tests passed!' not in tshark_proc.stdout

    def test_wslua_globals(self, check_lua_script, dirs):
        '''wslua globals'''
        check_lua_script('verify_globals.lua', empty_pcap, True,
            '-X', 'lua_script1:' + os.path.join(dirs.lua_dir, ''),
            '-X', 'lua_script1:' + os.path.join(dirs.lua_dir, 'globals_4.4.txt'),
        )

    def test_wslua_struct(self, check_lua_script):
        '''wslua struct'''
        check_lua_script('struct.lua', empty_pcap, True)

    def test_wslua_tvb_tree(self, check_lua_script):
        '''wslua tvb with a tree'''
        check_lua_script('tvb.lua', dns_port_pcap, True, '-c1', '-V')

    def test_wslua_tvb_no_tree(self, check_lua_script):
        '''wslua tvb without a tree'''
        check_lua_script('tvb.lua', dns_port_pcap, True, '-c1')

    def test_wslua_try_heuristics(self, check_lua_script):
        '''wslua try_heuristics'''
        check_lua_script('try_heuristics.lua', dns_port_pcap, True)

    def test_wslua_add_packet_field(self, check_lua_script):
        '''wslua add_packet_field'''
        check_lua_script('add_packet_field.lua', dns_port_pcap, True)

class TestWsluaUnicode:
    def test_wslua_unicode(self, cmd_tshark, features, dirs, capture_file, unicode_env):
        '''Check handling of unicode paths.'''
        if not features.have_lua:
            pytest.skip('Test requires Lua scripting support.')
        if sys.platform == 'win32' and not features.have_lua_unicode:
            pytest.skip('Test requires a patched Lua build with UTF-8 support.')

        # Prepare test environment, put files in the right places.
        uni_script = os.path.join(unicode_env.pluginsdir, 'script-Ф-€-中.lua')
        shutil.copy(os.path.join(dirs.lua_dir, 'unicode.lua'), uni_script)
        with open(unicode_env.path('load-Ф-€-中.lua'), 'w', encoding='utf8') as f:
            f.write('return "Contents of Ф-€-中"\n')
        uni_pcap = unicode_env.path('file-Ф-€-中.pcap')
        shutil.copy(capture_file('empty.pcap'), uni_pcap)

        # Run process from a Unicode path as working directory.
        proc = subprocess.Popen((cmd_tshark, '-r', uni_pcap), env=unicode_env.env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                cwd=unicode_env.path())
        stdout, stderr = proc.communicate(timeout=60)
        stdout_str = stdout.decode('utf8', 'replace')
        stderr_str = stderr.decode('utf8', 'replace')
        assert 'All tests passed!' in stdout_str
        assert stderr_str == ""
        with open(unicode_env.path('written-by-lua-Ф-€-中.txt'), encoding='utf8') as f:
            assert f.read() == 'Feedback from Lua: Ф-€-中\n'
