#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Wireshark Lua scripting tests'''

import filecmp
import os.path
import shutil
import subprocess
import subprocesstest
import unittest
import fixtures

dhcp_pcap = 'dhcp.pcap'
dns_port_pcap = 'dns_port.pcap'
empty_pcap = 'empty.pcap'
segmented_fpm_pcap = 'segmented_fpm.pcap'
sip_pcapng = 'sip.pcapng'
sipmsg_log = 'sipmsg.log'
wpa_induction_pcap_gz = 'wpa-Induction.pcap.gz'


@fixtures.fixture(scope='session')
def check_lua_script(cmd_tshark, features, dirs, capture_file):
    if not features.have_lua:
        fixtures.skip('Test requires Lua scripting support.')
    def check_lua_script_real(self, lua_script, cap_file, check_passed, *args):
        tshark_cmd = [cmd_tshark,
            '-r', capture_file(cap_file),
            '-X', 'lua_script:' + os.path.join(dirs.lua_dir, lua_script)
        ]
        tshark_cmd += args
        tshark_proc = self.assertRun(tshark_cmd)

        if check_passed:
            self.assertIn('All tests passed!', tshark_proc.stdout_str)

        return tshark_proc
    return check_lua_script_real


@fixtures.fixture(scope='session')
def check_lua_script_verify(check_lua_script):
    def check_lua_script_verify_real(self, lua_script, cap_file, check_stage_1=False, heur_regmode=None):
        # First run tshark with the dissector script.
        if heur_regmode is None:
            tshark_proc = check_lua_script(self, lua_script, dns_port_pcap, check_stage_1,
                '-V'
            )
        else:
            tshark_proc = check_lua_script(self, lua_script, dns_port_pcap, check_stage_1,
                '-V',
                '-X', 'lua_script1:heur_regmode={}'.format(heur_regmode)
            )

        # then dump tshark's output to a verification file.
        verify_file = self.filename_from_id('testin.txt')
        with open(verify_file, 'w', newline='\n') as f:
            f.write(tshark_proc.stdout_str)

        # finally run tshark again with the verification script and the verification file.
        if heur_regmode is None:
            check_lua_script(self, 'verify_dissector.lua', empty_pcap, True,
                '-X', 'lua_script1:verify_file=' + verify_file,
            )
        else:
            check_lua_script(self, 'verify_dissector.lua', empty_pcap, True,
                '-X', 'lua_script1:verify_file=' + verify_file,
                '-X', 'lua_script1:no_heur',
            )
    return check_lua_script_verify_real


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_wslua(subprocesstest.SubprocessTestCase):
    def test_wslua_dir(self, check_lua_script):
        '''wslua directory functions'''
        check_lua_script(self, 'dir.lua', empty_pcap, True)

    # Mode_1, mode_2, and mode_3, and fpm were all under wslua_step_dissector_test
    # in the Bash version.
    def test_wslua_dissector_mode_1(self, check_lua_script_verify):
        '''wslua dissector functions, mode 1'''
        check_lua_script_verify(self, 'dissector.lua', dns_port_pcap)

    def test_wslua_dissector_mode_2(self, check_lua_script_verify):
        '''wslua dissector functions, mode 2'''
        check_lua_script_verify(self, 'dissector.lua', dns_port_pcap, heur_regmode=2)

    def test_wslua_dissector_mode_3(self, check_lua_script_verify):
        '''wslua dissector functions, mode 3'''
        check_lua_script_verify(self, 'dissector.lua', dns_port_pcap, heur_regmode=3)

    def test_wslua_dissector_fpm(self, check_lua_script):
        '''wslua dissector functions, fpm'''
        tshark_fpm_tcp_proc = check_lua_script(self, 'dissectFPM.lua', segmented_fpm_pcap, False,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'fpm',
            '-e', 'fpm.version',
            '-e', 'fpm.type',
            '-e', 'fpm.length',
            '-o', 'fpm.dissect_tcp:true'
        )

        tshark_fpm_no_tcp_proc = check_lua_script(self, 'dissectFPM.lua', segmented_fpm_pcap, False,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'fpm',
            '-e', 'fpm.version',
            '-e', 'fpm.type',
            '-e', 'fpm.length',
            '-o', 'fpm.dissect_tcp:false'
        )

        self.diffOutput(tshark_fpm_tcp_proc.stdout_str,
            tshark_fpm_no_tcp_proc.stdout_str,
            'fpm.dissect_tcp:true',
            'fpm.dissect_tcp:false',
        )

    def test_wslua_field(self, check_lua_script):
        '''wslua fields'''
        check_lua_script(self, 'field.lua', dhcp_pcap, True)

    # reader, writer, and acme_reader were all under wslua_step_file_test
    # in the Bash version.
    def test_wslua_file_reader(self, check_lua_script, cmd_tshark, capture_file):
        '''wslua file reader'''
        cap_file_1 = capture_file(dhcp_pcap)
        cap_file_2 = capture_file(wpa_induction_pcap_gz)

        # First run tshark with the pcap_file_reader script.
        lua_proc_1 = check_lua_script(self, 'pcap_file.lua', cap_file_1, False)
        lua_proc_2 = check_lua_script(self, 'pcap_file.lua', cap_file_2, False)
        lua_out = lua_proc_1.stdout_str + lua_proc_2.stdout_str

        # then run tshark again without the script
        tshark_proc_1 = self.assertRun((cmd_tshark, '-r', cap_file_1))
        tshark_proc_2 = self.assertRun((cmd_tshark, '-r', cap_file_2))
        tshark_out = tshark_proc_1.stdout_str + tshark_proc_2.stdout_str

        self.diffOutput(lua_out, tshark_out, 'tshark + lua script', 'tshark only')

    def test_wslua_file_writer(self, check_lua_script, capture_file):
        '''wslua file writer'''
        cap_file_1 = capture_file(dhcp_pcap)
        cap_file_2 = self.filename_from_id('lua_writer.pcap')

        # Generate a new capture file using the Lua writer.
        check_lua_script(self, 'pcap_file.lua', cap_file_1, False,
            '-w', cap_file_2,
            '-F', 'lua_pcap2',
        )
        self.assertTrue(filecmp.cmp(cap_file_1, cap_file_2), cap_file_1 + ' differs from ' + cap_file_2)

    def test_wslua_file_acme_reader(self, check_lua_script, cmd_tshark, capture_file):
        '''wslua acme file reader'''

        cap_file = self.filename_from_id('lua_acme_reader.pcap')
        # Read an acme sipmsg.log using the acme Lua reader, writing it out as pcapng.
        check_lua_script(self, 'acme_file.lua', sipmsg_log, False,
            '-w', cap_file,
            '-F', 'pcapng',
        )

        # Read lua_acme_reader.pcap and sip.pcapng and compare their verbose outputs.
        tshark_proc_1 = self.assertRun((cmd_tshark,
            '-r', cap_file,
            '-V'
        ))
        tshark_proc_2 = self.assertRun((cmd_tshark,
            '-r', capture_file(sip_pcapng),
            '-V'
        ))
        self.diffOutput(tshark_proc_1.stdout_str, tshark_proc_2.stdout_str, 'sipmsg.log', 'sip.pcapng')

    def test_wslua_listener(self, check_lua_script):
        '''wslua listener'''
        check_lua_script(self, 'listener.lua', dhcp_pcap, True)

    def test_wslua_nstime(self, check_lua_script):
        '''wslua nstime'''
        check_lua_script(self, 'nstime.lua', dhcp_pcap, True)

    def test_wslua_pinfo(self, check_lua_script):
        '''wslua pinfo'''
        check_lua_script(self, 'pinfo.lua', dhcp_pcap, True)

    def test_wslua_proto(self, check_lua_script_verify):
        '''wslua proto'''
        check_lua_script_verify(self, 'proto.lua', dns_port_pcap, check_stage_1=True)

    def test_wslua_protofield_tree(self, check_lua_script):
        '''wslua protofield with a tree'''
        check_lua_script(self, 'protofield.lua', dns_port_pcap, True,
            '-V',
            '-Y', 'test.filtered==1',
        )

    def test_wslua_protofield_no_tree(self, check_lua_script):
        '''wslua protofield without a tree'''
        check_lua_script(self, 'protofield.lua', dns_port_pcap, True,
            '-Y', 'test.filtered==1',
        )

    def test_wslua_int64(self, check_lua_script):
        '''wslua int64'''
        check_lua_script(self, 'int64.lua', empty_pcap, True)

    def test_wslua_args_1(self, check_lua_script):
        '''wslua args 1'''
        check_lua_script(self, 'script_args.lua', empty_pcap, True,
            '-X', 'lua_script1:1',
        )

    def test_wslua_args_2(self, check_lua_script):
        '''wslua args 2'''
        check_lua_script(self, 'script_args.lua', empty_pcap, True,
            '-X', 'lua_script1:3',
            '-X', 'lua_script1:foo',
            '-X', 'lua_script1:bar',
        )

    def test_wslua_args_3(self, check_lua_script, dirs):
        '''wslua args 3'''
        check_lua_script(self, 'script_args.lua', empty_pcap, True,
            '-X', 'lua_script:' + os.path.join(dirs.lua_dir, 'script_args.lua'),
            '-X', 'lua_script1:3',
            '-X', 'lua_script2:1',
            '-X', 'lua_script1:foo',
            '-X', 'lua_script1:bar',
        )

    def test_wslua_args_4(self, check_lua_script):
        '''wslua args 4'''
        check_lua_script(self, 'script_args.lua', empty_pcap, False)
        self.assertFalse(self.grepOutput(r'All tests passed!'))

    def test_wslua_args_5(self, check_lua_script):
        '''wslua args 5'''
        check_lua_script(self, 'script_args.lua', empty_pcap, False,
            '-X', 'lua_script1:3',
        )
        self.assertFalse(self.grepOutput(r'All tests passed!'))

    def test_wslua_globals(self, check_lua_script, dirs):
        '''wslua globals'''
        check_lua_script(self, 'verify_globals.lua', empty_pcap, True,
            '-X', 'lua_script1:' + os.path.join(dirs.lua_dir, ''),
            '-X', 'lua_script1:' + os.path.join(dirs.lua_dir, 'globals_2.2.txt'),
        )

    @unittest.skip('GRegex tests are broken since PCRE 8.34, see bug 12997.')
    def test_wslua_gregex(self, check_lua_script, dirs):
        '''wslua GRegex'''
        check_lua_script(self, 'gregex.lua', empty_pcap, True,
            '-X', 'lua_script1:' + os.path.join(dirs.lua_dir, ''),
            '-X', 'lua_script1:glib',
            '-X', 'lua_script1:-V',
        )

    def test_wslua_struct(self, check_lua_script):
        '''wslua struct'''
        check_lua_script(self, 'struct.lua', empty_pcap, True)

    def test_wslua_tvb_tree(self, check_lua_script):
        '''wslua tvb with a tree'''
        check_lua_script(self, 'tvb.lua', dns_port_pcap, True, '-V')

    def test_wslua_tvb_no_tree(self, check_lua_script):
        '''wslua tvb without a tree'''
        check_lua_script(self, 'tvb.lua', dns_port_pcap, True)


@fixtures.uses_fixtures
class case_wslua_unicode(subprocesstest.SubprocessTestCase):
    def test_wslua_unicode(self, cmd_tshark, features, dirs, capture_file, unicode_env):
        '''Check handling of unicode paths.'''
        if not features.have_lua:
            self.skipTest('Test requires Lua scripting support.')

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
        print("-- Begin stdout")
        print(stdout_str)
        print("-- End stdout")
        if stderr_str:
            print("-- Begin stderr")
            print(stderr_str)
            print("-- End stderr")
        self.assertIn('All tests passed!', stdout_str)
        assert stderr_str == ""
        with open(unicode_env.path('written-by-lua-Ф-€-中.txt'), encoding='utf8') as f:
            assert f.read() == 'Feedback from Lua: Ф-€-中\n'
