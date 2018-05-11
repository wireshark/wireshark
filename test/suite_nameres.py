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

import config
import os.path
import subprocesstest
import unittest

dns_icmp_pcapng = os.path.join(config.capture_dir, 'dns+icmp.pcapng.gz')

tf_str = { True: 'TRUE', False: 'FALSE' }

def check_name_resolution(self, o_net_name, o_external_name_res, o_hosts_file, custom_profile, grep_str, fail_on_match=False):
    tshark_cmd = (config.cmd_tshark,
        '-r', dns_icmp_pcapng,
        '-o', 'nameres.network_name: ' + tf_str[o_net_name],
        '-o', 'nameres.use_external_name_resolver: ' + tf_str[o_external_name_res],
        '-o', 'nameres.hosts_file_handling: ' + tf_str[o_hosts_file],
        )
    if custom_profile:
        tshark_cmd += ('-C', config.custom_profile_name)
    self.assertRun(tshark_cmd, env=config.test_env)
    if fail_on_match:
        self.assertFalse(self.grepOutput(grep_str))
    else:
        self.assertTrue(self.grepOutput(grep_str))


class case_name_resolution(subprocesstest.SubprocessTestCase):

    def test_name_resolution_net_t_ext_f_hosts_f_global(self):
        '''Name resolution, no external, no profile hosts, global profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: False
        # Profile: Default
        check_name_resolution(self, True, False, False, False, 'global-8-8-8-8')

    def test_name_resolution_net_t_ext_f_hosts_f_personal(self):
        '''Name resolution, no external, no profile hosts, personal profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: False
        # Profile: Default
        check_name_resolution(self, True, False, False, False, 'personal-8-8-4-4')

    def test_name_resolution_net_t_ext_f_hosts_f_custom(self):
        '''Name resolution, no external, no profile hosts, custom profile.'''
        # nameres.network_name: True
        # nameres_use_external_name_resolver: False
        # nameres.hosts_file_handling: False
        # Profile: Custom
        check_name_resolution(self, True, False, False, True, 'custom-4-2-2-2')

    def test_name_resolution_net_t_ext_f_hosts_t_global(self):
        '''Name resolution, no external, profile hosts, global profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: True
        # Profile: Default
        check_name_resolution(self, True, False, True, False, 'global-8-8-8-8', True)

    def test_name_resolution_net_t_ext_f_hosts_t_personal(self):
        '''Name resolution, no external, profile hosts, personal profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # nameres.hosts_file_handling: True
        # Profile: Default
        check_name_resolution(self, True, False, True, False, 'personal-8-8-4-4')

    def test_name_resolution_net_t_ext_f_hosts_t_custom(self):
        '''Name resolution, no external, profile hosts, custom profile.'''
        # nameres.network_name: True
        # nameres_use_external_name_resolver: False
        # nameres.hosts_file_handling: True
        # Profile: Custom
        check_name_resolution(self, True, False, True, True, 'custom-4-2-2-2')

    def test_hosts_any(self):
        self.runProcess((config.cmd_tshark,
                '-r', dns_icmp_pcapng,
                '-qz', 'hosts',
                ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('174.137.42.65\twww.wireshark.org'))
        self.assertTrue(self.grepOutput('fe80::6233:4bff:fe13:c558\tCrunch.local'))

    def test_hosts_ipv4(self):
        self.runProcess((config.cmd_tshark,
                '-r', dns_icmp_pcapng,
                '-qz', 'hosts,ipv4',
                ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('174.137.42.65\twww.wireshark.org'))
        self.assertFalse(self.grepOutput('fe80::6233:4bff:fe13:c558\tCrunch.local'))

    def test_hosts_ipv6(self):
        self.runProcess((config.cmd_tshark,
                '-r', dns_icmp_pcapng,
                '-qz', 'hosts,ipv6',
                ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('fe80::6233:4bff:fe13:c558\tCrunch.local'))
        self.assertFalse(self.grepOutput('174.137.42.65\twww.wireshark.org'))
