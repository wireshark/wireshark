#
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
import subprocess
from subprocesstest import grep_output
import pytest

tf_str = { True: 'TRUE', False: 'FALSE' }

custom_profile_name = 'Custom Profile'

@pytest.fixture
def nameres_setup(program_path, conf_path):
    bundle_path = os.path.join(program_path, 'Wireshark.app', 'Contents', 'MacOS')
    if os.path.isdir(bundle_path):
        # Don't modify our application bundle.
        global_path = None
    else:
        global_path = program_path
    custom_profile_path = os.path.join(conf_path, 'profiles', custom_profile_name)
    os.makedirs(custom_profile_path)
    this_dir = os.path.dirname(__file__)
    hosts_path_pfx = os.path.join(this_dir, 'hosts.')

    if global_path is not None:
        shutil.copyfile(hosts_path_pfx + 'global', os.path.join(global_path, 'hosts'))
    shutil.copyfile(hosts_path_pfx + 'personal', os.path.join(conf_path, 'hosts'))
    shutil.copyfile(hosts_path_pfx + 'custom', os.path.join(custom_profile_path, 'hosts'))
    return global_path is not None


@pytest.fixture
def check_name_resolution(cmd_tshark, capture_file, nameres_setup, test_env):
    def check_name_resolution_real(o_net_name, o_external_name_res, custom_profile, grep_str, fail_on_match=False):
        if grep_str.startswith('global') and not nameres_setup:
            pytest.skip('Global name resolution tests would require modifying the application bundle')
        tshark_cmd = (cmd_tshark,
            '-r', capture_file('dns+icmp.pcapng.gz'),
            '-o', 'nameres.network_name: ' + tf_str[o_net_name],
            '-o', 'nameres.use_external_name_resolver: ' + tf_str[o_external_name_res],
            )
        if custom_profile:
            tshark_cmd += ('-C', custom_profile_name)
        proc = subprocess.run(tshark_cmd, check=True, capture_output=True, encoding='utf-8', env=test_env)
        if fail_on_match:
            assert not grep_output(proc.stdout, grep_str)
        else:
            assert grep_output(proc.stdout, grep_str)
    return check_name_resolution_real


class TestNameResolution:

    def test_name_resolution_net_t_ext_f_hosts_f_global(self, check_name_resolution):
        '''Name resolution, no external, global profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # Profile: Default
        check_name_resolution(True, False, False, 'global-8-8-8-8')

    def test_name_resolution_net_t_ext_f_hosts_f_personal(self, check_name_resolution):
        '''Name resolution, no external, personal profile.'''
        # nameres.network_name: True
        # nameres.use_external_name_resolver: False
        # Profile: Default
        check_name_resolution(True, False, False, 'personal-8-8-4-4')

    def test_name_resolution_net_t_ext_f_hosts_f_custom(self, check_name_resolution):
        '''Name resolution, no external, no profile hosts, custom profile.'''
        # nameres.network_name: True
        # nameres_use_external_name_resolver: False
        # Profile: Custom
        check_name_resolution(True, False, True, 'custom-4-2-2-2')

    def test_hosts_any(self, cmd_tshark, capture_file):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns+icmp.pcapng.gz'),
                '-qz', 'hosts',
                ), encoding='utf-8')
        assert '174.137.42.65\twww.wireshark.org' in stdout
        assert 'fe80::6233:4bff:fe13:c558\tCrunch.local' in stdout

    def test_hosts_ipv4(self, cmd_tshark, capture_file):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns+icmp.pcapng.gz'),
                '-qz', 'hosts,ipv4',
                ), encoding='utf-8')
        assert '174.137.42.65\twww.wireshark.org' in stdout
        assert 'fe80::6233:4bff:fe13:c558\tCrunch.local' not in stdout

    def test_hosts_ipv6(self, cmd_tshark, capture_file):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns+icmp.pcapng.gz'),
                '-qz', 'hosts,ipv6',
                ), encoding='utf-8')
        assert '174.137.42.65\twww.wireshark.org' not in stdout
        assert 'fe80::6233:4bff:fe13:c558\tCrunch.local' in stdout
