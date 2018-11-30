#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Name resolution tests'''

import os.path
import shutil
import subprocesstest
import fixtures

tf_str = { True: 'TRUE', False: 'FALSE' }

custom_profile_name = 'Custom Profile'

@fixtures.fixture
def nameres_env(test_env, program_path, conf_path):
    bundle_path = os.path.join(program_path, 'Wireshark.app', 'Contents', 'MacOS')
    if os.path.isdir(bundle_path):
        global_path = bundle_path
    else:
        global_path = program_path
    custom_profile_path = os.path.join(conf_path, 'profiles', custom_profile_name)
    os.makedirs(custom_profile_path)
    this_dir = os.path.dirname(__file__)
    hosts_path_pfx = os.path.join(this_dir, 'hosts.')
    shutil.copyfile(hosts_path_pfx + 'global', os.path.join(global_path, 'hosts'))
    shutil.copyfile(hosts_path_pfx + 'personal', os.path.join(conf_path, 'hosts'))
    shutil.copyfile(hosts_path_pfx + 'custom', os.path.join(custom_profile_path, 'hosts'))
    return test_env


@fixtures.fixture
def check_name_resolution(cmd_tshark, capture_file, nameres_env):
    def check_name_resolution_real(self, o_net_name, o_external_name_res, o_hosts_file, custom_profile, grep_str, fail_on_match=False):
        tshark_cmd = (cmd_tshark,
            '-r', capture_file('dns+icmp.pcapng.gz'),
            '-o', 'nameres.network_name: ' + tf_str[o_net_name],
            '-o', 'nameres.use_external_name_resolver: ' + tf_str[o_external_name_res],
            '-o', 'nameres.hosts_file_handling: ' + tf_str[o_hosts_file],
            )
        if custom_profile:
            tshark_cmd += ('-C', custom_profile_name)
        self.assertRun(tshark_cmd, env=nameres_env)
        if fail_on_match:
            self.assertFalse(self.grepOutput(grep_str))
        else:
            self.assertTrue(self.grepOutput(grep_str))
    return check_name_resolution_real


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_name_resolution(subprocesstest.SubprocessTestCase):

    def test_name_resolution_net_t_ext_f_hosts_f_global(self, check_name_resolution):
        '''Name resolution, no external, no profile hosts, global profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: False
        # Profile: Default
        check_name_resolution(self, True, False, False, False, 'global-8-8-8-8')

    def test_name_resolution_net_t_ext_f_hosts_f_personal(self, check_name_resolution):
        '''Name resolution, no external, no profile hosts, personal profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: False
        # Profile: Default
        check_name_resolution(self, True, False, False, False, 'personal-8-8-4-4')

    def test_name_resolution_net_t_ext_f_hosts_f_custom(self, check_name_resolution):
        '''Name resolution, no external, no profile hosts, custom profile.'''
        # nameres.network_name: True
        # nameres_use_external_name_resolver: False
        # nameres.hosts_file_handling: False
        # Profile: Custom
        check_name_resolution(self, True, False, False, True, 'custom-4-2-2-2')

    def test_name_resolution_net_t_ext_f_hosts_t_global(self, check_name_resolution):
        '''Name resolution, no external, profile hosts, global profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: True
        # Profile: Default
        check_name_resolution(self, True, False, True, False, 'global-8-8-8-8', True)

    def test_name_resolution_net_t_ext_f_hosts_t_personal(self, check_name_resolution):
        '''Name resolution, no external, profile hosts, personal profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: True
        # Profile: Default
        check_name_resolution(self, True, False, True, False, 'personal-8-8-4-4')

    def test_name_resolution_net_t_ext_f_hosts_t_custom(self, check_name_resolution):
        '''Name resolution, no external, profile hosts, custom profile.'''
        # nameres.network_name: True
        # nameres_use_external_name_resolver: False
        # nameres.hosts_file_handling: True
        # Profile: Custom
        check_name_resolution(self, True, False, True, True, 'custom-4-2-2-2')

    def test_hosts_any(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dns+icmp.pcapng.gz'),
                '-qz', 'hosts',
                ))
        self.assertTrue(self.grepOutput('174.137.42.65\twww.wireshark.org'))
        self.assertTrue(self.grepOutput('fe80::6233:4bff:fe13:c558\tCrunch.local'))

    def test_hosts_ipv4(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dns+icmp.pcapng.gz'),
                '-qz', 'hosts,ipv4',
                ))
        self.assertTrue(self.grepOutput('174.137.42.65\twww.wireshark.org'))
        self.assertFalse(self.grepOutput('fe80::6233:4bff:fe13:c558\tCrunch.local'))

    def test_hosts_ipv6(self, cmd_tshark, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dns+icmp.pcapng.gz'),
                '-qz', 'hosts,ipv6',
                ))
        self.assertTrue(self.grepOutput('fe80::6233:4bff:fe13:c558\tCrunch.local'))
        self.assertFalse(self.grepOutput('174.137.42.65\twww.wireshark.org'))
