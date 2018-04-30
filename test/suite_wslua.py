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

import config
import filecmp
import io
import os.path
import subprocesstest
import unittest

dhcp_pcap = 'dhcp.pcap'
dns_port_pcap = 'dns_port.pcap'
empty_pcap = 'empty.pcap'
segmented_fpm_pcap = 'segmented_fpm.pcap'
sip_pcapng = 'sip.pcapng'
sipmsg_log = 'sipmsg.log'
wpa_induction_pcap_gz = 'wpa-Induction.pcap.gz'

def check_lua_script(self, lua_script, cap_file, check_passed, *args):
    if not config.have_lua:
        self.skipTest('Test requires Lua scripting support.')
    tshark_cmd = [config.cmd_tshark,
        '-r', os.path.join(config.capture_dir, cap_file),
        '-X', 'lua_script:' + os.path.join(config.lua_dir, lua_script)
    ]
    tshark_cmd += args
    tshark_proc = self.assertRun(tshark_cmd)

    if check_passed:
        self.assertTrue(self.grepOutput(r'All tests passed!'))

    return tshark_proc

def check_lua_script_verify(self, lua_script, cap_file, check_stage_1=False, heur_regmode=None):
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
    with io.open(verify_file, 'w', newline='\n') as testin_fd:
        testin_fd.write(tshark_proc.stdout_str)
        testin_fd.close()

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

class case_wslua(subprocesstest.SubprocessTestCase):
    def test_wslua_dir(self):
        '''wslua directory functions'''
        check_lua_script(self, 'dir.lua', empty_pcap, True)

    # Mode_1, mode_2, and mode_3, and fpm were all under wslua_step_dissector_test
    # in the Bash version.
    def test_wslua_dissector_mode_1(self):
        '''wslua dissector functions, mode 1'''
        check_lua_script_verify(self, 'dissector.lua', dns_port_pcap)

    def test_wslua_dissector_mode_2(self):
        '''wslua dissector functions, mode 2'''
        check_lua_script_verify(self, 'dissector.lua', dns_port_pcap, heur_regmode=2)

    def test_wslua_dissector_mode_3(self):
        '''wslua dissector functions, mode 3'''
        check_lua_script_verify(self, 'dissector.lua', dns_port_pcap, heur_regmode=3)

    def test_wslua_dissector_fpm(self):
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

    def test_wslua_field(self):
        '''wslua fields'''
        check_lua_script(self, 'field.lua', dhcp_pcap, True)

    # reader, writer, and acme_reader were all under wslua_step_file_test
    # in the Bash version.
    def test_wslua_file_reader(self):
        '''wslua file reader'''
        cap_file_1 = os.path.join(config.capture_dir, dhcp_pcap)
        cap_file_2 = os.path.join(config.capture_dir, wpa_induction_pcap_gz)

        # First run tshark with the pcap_file_reader script.
        lua_proc_1 = check_lua_script(self, 'pcap_file.lua', cap_file_1, False)
        lua_proc_2 = check_lua_script(self, 'pcap_file.lua', cap_file_2, False)
        lua_out = lua_proc_1.stdout_str + lua_proc_2.stdout_str

        # then run tshark again without the script
        tshark_proc_1 = self.assertRun((config.cmd_tshark, '-r', cap_file_1))
        tshark_proc_2 = self.assertRun((config.cmd_tshark, '-r', cap_file_2))
        tshark_out = tshark_proc_1.stdout_str + tshark_proc_2.stdout_str

        self.diffOutput(lua_out, tshark_out, 'tshark + lua script', 'tshark only')

    def test_wslua_file_writer(self):
        '''wslua file writer'''
        cap_file_1 = os.path.join(config.capture_dir, dhcp_pcap)
        cap_file_2 = self.filename_from_id('lua_writer.pcap')

        # Generate a new capture file using the Lua writer.
        check_lua_script(self, 'pcap_file.lua', cap_file_1, False,
            '-w', cap_file_2,
            '-F', 'lua_pcap2',
        )
        self.assertTrue(filecmp.cmp(cap_file_1, cap_file_2), cap_file_1 + ' differs from ' + cap_file_2)

    def test_wslua_file_acme_reader(self):
        '''wslua acme file reader'''

        cap_file = self.filename_from_id('lua_acme_reader.pcap')
        # Read an acme sipmsg.log using the acme Lua reader, writing it out as pcapng.
        check_lua_script(self, 'acme_file.lua', sipmsg_log, False,
            '-w', cap_file,
            '-F', 'pcapng',
        )

        # Read lua_acme_reader.pcap and sip.pcapng and compare their verbose outputs.
        tshark_proc_1 = self.assertRun((config.cmd_tshark,
            '-r', cap_file,
            '-V'
        ))
        tshark_proc_2 = self.assertRun((config.cmd_tshark,
            '-r', os.path.join(config.capture_dir, sip_pcapng),
            '-V'
        ))
        self.diffOutput(tshark_proc_1.stdout_str, tshark_proc_2.stdout_str, 'sipmsg.log', 'sip.pcapng')

    def test_wslua_listener(self):
        '''wslua listener'''
        check_lua_script(self, 'listener.lua', dhcp_pcap, True)

    def test_wslua_nstime(self):
        '''wslua nstime'''
        check_lua_script(self, 'nstime.lua', dhcp_pcap, True)

    def test_wslua_pinfo(self):
        '''wslua pinfo'''
        check_lua_script(self, 'pinfo.lua', dhcp_pcap, True)

    def test_wslua_proto(self):
        '''wslua proto'''
        check_lua_script_verify(self, 'proto.lua', dns_port_pcap, check_stage_1=True)

    def test_wslua_protofield_tree(self):
        '''wslua protofield with a tree'''
        check_lua_script(self, 'protofield.lua', dns_port_pcap, True,
            '-V',
            '-Y', 'test.filtered==1',
        )

    def test_wslua_protofield_no_tree(self):
        '''wslua protofield without a tree'''
        check_lua_script(self, 'protofield.lua', dns_port_pcap, True,
            '-Y', 'test.filtered==1',
        )

    def test_wslua_int64(self):
        '''wslua int64'''
        check_lua_script(self, 'int64.lua', empty_pcap, True)

    def test_wslua_args_1(self):
        '''wslua args 1'''
        check_lua_script(self, 'script_args.lua', empty_pcap, True,
            '-X', 'lua_script1:1',
        )

    def test_wslua_args_2(self):
        '''wslua args 2'''
        check_lua_script(self, 'script_args.lua', empty_pcap, True,
            '-X', 'lua_script1:3',
            '-X', 'lua_script1:foo',
            '-X', 'lua_script1:bar',
        )

    def test_wslua_args_3(self):
        '''wslua args 3'''
        check_lua_script(self, 'script_args.lua', empty_pcap, True,
            '-X', 'lua_script:' + os.path.join(config.lua_dir, 'script_args.lua'),
            '-X', 'lua_script1:3',
            '-X', 'lua_script2:1',
            '-X', 'lua_script1:foo',
            '-X', 'lua_script1:bar',
        )

    def test_wslua_args_4(self):
        '''wslua args 4'''
        check_lua_script(self, 'script_args.lua', empty_pcap, False)
        self.assertFalse(self.grepOutput(r'All tests passed!'))

    def test_wslua_args_5(self):
        '''wslua args 5'''
        check_lua_script(self, 'script_args.lua', empty_pcap, False,
            '-X', 'lua_script1:3',
        )
        self.assertFalse(self.grepOutput(r'All tests passed!'))

    def test_wslua_globals(self):
        '''wslua globals'''
        check_lua_script(self, 'verify_globals.lua', empty_pcap, True,
            '-X', 'lua_script1:' + os.path.join(config.lua_dir, ''),
            '-X', 'lua_script1:' + os.path.join(config.lua_dir, 'globals_2.2.txt'),
        )

    @unittest.skip('GRegex tests are broken since PCRE 8.34, see bug 12997.')
    def test_wslua_gregex(self):
        '''wslua GRegex'''
        check_lua_script(self, 'gregex.lua', empty_pcap, True,
            '-X', 'lua_script1:' + os.path.join(config.lua_dir, ''),
            '-X', 'lua_script1:glib',
            '-X', 'lua_script1:-V',
        )

    def test_wslua_struct(self):
        '''wslua struct'''
        check_lua_script(self, 'struct.lua', empty_pcap, True)

    def test_wslua_tvb_tree(self):
        '''wslua tvb with a tree'''
        check_lua_script(self, 'tvb.lua', dns_port_pcap, True, '-V')

    def test_wslua_tvb_no_tree(self):
        '''wslua tvb without a tree'''
        check_lua_script(self, 'tvb.lua', dns_port_pcap, True)
