#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Copyright (c) 2019 Dario Lombardo <lomato@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''extcap tests'''

import json
import os
import re
import subprocess
import sys

import pytest

# The following must match extcap.c.

def bookmark_ifname(ifname, bookmark_name):
    '''The interface name that we give a bookmark.'''
    return f'{ifname}:{bookmark_name}'


def bookmark_listing(ifname, description, bookmark_name):
    '''How "tshark -D" lists a bookmark.'''
    return (f'{bookmark_ifname(ifname, bookmark_name)}'
            f' ({description}, {bookmark_name} bookmark)')


def pref_ifname(ifname):
    '''The preference name that we give an interface.'''
    return re.sub(r'[^a-zA-Z0-9_]', '_', ifname).lower()


@pytest.fixture
def check_extcap_execution(cmd_extcap, program_path, base_env):
    def check_extcap_interface_execution(extcap_name, interface, stratoshark_extcap):
        ''' Check if an extcap runs flawlessly for interface configuration. '''

        subprocess.check_call([cmd_extcap(extcap_name, stratoshark_extcap), '--extcap-interface',
                        interface, '--extcap-dlts'], cwd=program_path, env=base_env)
        subprocess.check_call([cmd_extcap(extcap_name, stratoshark_extcap), '--extcap-interface',
                        interface, '--extcap-config'], cwd=program_path, env=base_env)

    def extcap_get_interfaces(extcap_output):
        ''' Extract the interface name from extcap. '''
        parser = re.compile("{value=(.*?)}")
        interfaces = []
        for line in extcap_output.splitlines():
            if line.startswith('interface '):
                interfaces.append(parser.findall(line)[0])
        return interfaces

    def check_extcap_execution_real(extcap_name, request=None, stratoshark_extcap=False, always_present=True):
        '''
        Check if an extcap runs flawlessly.
        always_present: at least one interface is always offered by the extcap.
        '''

        subprocess.check_call([cmd_extcap(extcap_name, stratoshark_extcap), '--help'], cwd=program_path, env=base_env)
        extcap_stdout = subprocess.check_output(
            [cmd_extcap(extcap_name, stratoshark_extcap), '--extcap-interfaces'], cwd=program_path, encoding='utf-8', env=base_env)
        interfaces = extcap_get_interfaces(extcap_stdout)
        if always_present:
            assert len(interfaces) > 0
        for interface in interfaces:
            check_extcap_interface_execution(extcap_name, interface, stratoshark_extcap)

    return check_extcap_execution_real


class TestExtcaps:
    def test_androiddump(self, check_extcap_execution):
        ''' extcap interface tests for androiddump '''
        check_extcap_execution("androiddump", always_present=False)

    def test_ciscodump(self, check_extcap_execution):
        ''' extcap interface tests for ciscodump '''
        check_extcap_execution("ciscodump")

    def test_dpauxmon(self, check_extcap_execution):
        ''' extcap interface tests for dpauxmon '''
        if not sys.platform.startswith('linux'):
            pytest.skip('dpauxmon available on Linux only')
        check_extcap_execution("dpauxmon")

    def test_falcodump(self, request, check_extcap_execution):
        ''' extcap interface tests for falcodump '''
        check_extcap_execution("falcodump", stratoshark_extcap=True)

    # if sys.platform == 'linux':
    #     def test_dumpcalls(self, check_extcap_execution):
    #         ''' extcap interface tests for dumpcalls '''
    #         check_extcap_execution("dumpcalls", stratoshark_extcap=True, always_present=False)

    def test_randpktdump(self, check_extcap_execution):
        ''' extcap interface tests for randpktdump '''
        check_extcap_execution("randpktdump")

    def test_sdjournal(self, check_extcap_execution):
        ''' extcap interface tests for sdjournal '''
        if not sys.platform.startswith('linux'):
            pytest.skip('sdjournal is available on Linux only')
        check_extcap_execution("sdjournal", stratoshark_extcap=True)

    def test_sshdig(self, check_extcap_execution):
        ''' extcap interface tests for sshdig '''
        check_extcap_execution("sshdig", stratoshark_extcap=True)

    def test_sshdump(self, check_extcap_execution):
        ''' extcap interface tests for sshdump '''
        check_extcap_execution("sshdump")

    def test_wifidump(self, check_extcap_execution):
        ''' extcap interface tests for wifidump '''
        check_extcap_execution("wifidump")

    def test_udpdump(self, check_extcap_execution):
        ''' extcap interface tests for udpdump '''
        check_extcap_execution("udpdump")


@pytest.fixture
def bookmark_conf_path(conf_path):
    '''A configuration directory with a bookmark for the randpkt interface.'''
    with open(os.path.join(conf_path, 'interfaces.json'), 'w') as f:
        f.write('[ {"randpktdump": {"extcap-interfaces": ['
                '{"randpkt": {"bookmarks": ["Random test"]}}'
                ']}} ]\n')
    # Our bookmark's preferences are named after its interface.
    random_test = pref_ifname(bookmark_ifname('randpkt', 'Random test'))
    # The parent interface and the bookmark have different configurations.
    with open(os.path.join(conf_path, 'extcap.cfg'), 'w') as f:
        f.write('extcap.randpkt.type: arp\n')
        f.write('extcap.randpkt.count: 2\n')
        f.write(f'extcap.{random_test}.type: dns\n')
        f.write(f'extcap.{random_test}.count: 5\n')
    return conf_path


@pytest.fixture
def written_bookmark_conf_path(conf_path):
    '''A configuration directory with bookmarks in the form that we write.'''
    info = [{'randpktdump': {'extcap-interfaces': [
                {'randpkt': {'bookmarks': ['Random test', 'Wire🦈 "quoted" / slashed']}}]}},
            {'sshdump': {'extcap-interfaces': [
                {'sshdump': {'bookmarks': ['My server']}}]}}]
    with open(os.path.join(conf_path, 'interfaces.json'), 'w') as f:
        json.dump(info, f, indent=2)
    return conf_path


class TestExtcapBookmarks:
    def test_extcap_bookmark_written_info(self, cmd_tshark, program_path,
            written_bookmark_conf_path, base_env):
        '''We can read the interface information that we write'''
        if sys.platform == 'win32':
            pytest.skip('Test requires Npcap.')
        iface_list = subprocess.check_output((cmd_tshark, '-D'),
                cwd=program_path, encoding='utf-8', env=base_env)
        quoted = 'Wire🦈 "quoted" / slashed'
        assert bookmark_listing('randpkt', 'Random packet generator', 'Random test') in iface_list
        assert bookmark_listing('randpkt', 'Random packet generator', quoted) in iface_list
        assert bookmark_listing('sshdump', 'SSH remote capture', 'My server') in iface_list

    def test_extcap_bookmark_list(self, cmd_tshark, program_path, bookmark_conf_path, base_env):
        '''A bookmark is listed alongside its extcap interface'''
        if sys.platform == 'win32':
            pytest.skip('Test requires Npcap.')
        iface_list = subprocess.check_output((cmd_tshark, '-D'),
                cwd=program_path, encoding='utf-8', env=base_env)
        assert re.search(r'^\d+\. randpkt \(Random packet generator\)$', iface_list, re.MULTILINE)
        assert bookmark_listing('randpkt', 'Random packet generator', 'Random test') in iface_list

    def test_extcap_bookmark_dlts(self, cmd_tshark, program_path, bookmark_conf_path, base_env):
        '''A bookmark reports the same link-layer types as its extcap interface'''
        if sys.platform == 'win32':
            pytest.skip('Test requires Npcap.')
        # Fetching capabilities for more than one interface uses a different
        # code path than fetching them for a single interface.
        dlt_list = subprocess.check_output((cmd_tshark, '-i', 'randpkt',
                '-i', bookmark_ifname('randpkt', 'Random test'), '-L'),
                cwd=program_path, encoding='utf-8', env=base_env)
        assert dlt_list.count('randpkt (Generator dependent DLT)') == 2

    def test_extcap_bookmark_capture(self, cmd_tshark, cmd_capinfos, program_path,
            bookmark_conf_path, base_env, result_file):
        '''Capturing from a bookmark uses the bookmark's own configuration'''
        if sys.platform == 'win32':
            pytest.skip("Test doesn't work on Windows.")
        testout_file = result_file('testout.pcapng')
        subprocess.check_call((cmd_tshark, '-i', bookmark_ifname('randpkt', 'Random test'),
                '-a', 'packets:5', '-w', testout_file),
                cwd=program_path, env=base_env)
        tshark_stdout = subprocess.check_output((cmd_tshark, '-r', testout_file),
                encoding='utf-8')
        assert tshark_stdout.count('DNS') >= 5

    def test_extcap_bookmark_other_profile(self, cmd_tshark, program_path,
            bookmark_conf_path, base_env, result_file):
        '''A bookmark's configuration is shared by all of our profiles'''
        if sys.platform == 'win32':
            pytest.skip("Test doesn't work on Windows.")
        os.makedirs(os.path.join(bookmark_conf_path, 'profiles', 'Other'))
        testout_file = result_file('testout.pcapng')
        # Our shared extcap.cfg gives the bookmark five DNS packets.
        subprocess.check_call((cmd_tshark, '-C', 'Other',
                '-i', bookmark_ifname('randpkt', 'Random test'),
                '-a', 'duration:30', '-w', testout_file),
                cwd=program_path, env=base_env)
        protocols = subprocess.check_output((cmd_tshark, '-r', testout_file,
                '-T', 'fields', '-e', 'frame.protocols'),
                encoding='utf-8').splitlines()
        assert len(protocols) == 5
        assert all(':dns' in protocol for protocol in protocols)

    def test_extcap_bookmark_config_preserved(self, cmd_tshark, program_path,
            bookmark_conf_path, base_env, capture_file, features, result_file):
        '''Saving preferences elsewhere leaves our extcap.cfg alone'''
        if not features.have_lua:
            pytest.skip('Test requires Lua.')
        os.makedirs(os.path.join(bookmark_conf_path, 'profiles', 'Other'))
        # Saving preferences is a GUI action, so have Lua do it for us. Our
        # extcap preferences aren't registered here, so writing them would
        # replace our configuration with a set of default values.
        lua_script = result_file('apply_prefs.lua')
        with open(lua_script, 'w') as f:
            f.write('local tap = Listener.new("frame")\n'
                    'function tap.packet(pinfo, tvb)\n'
                    '    apply_preferences()\n'
                    'end\n')
        subprocess.check_call((cmd_tshark, '-C', 'Other',
                '-X', 'lua_script:' + lua_script,
                '-r', capture_file('dhcp.pcap'), '-c', '1', '-q'),
                cwd=program_path, env=base_env)
        with open(os.path.join(bookmark_conf_path, 'extcap.cfg')) as f:
            shared_cfg = f.read()
        assert 'extcap.randpkt.count: 2' in shared_cfg
        # Our bookmark's values are still there too.
        assert '.count: 5' in shared_cfg
        assert not os.path.exists(os.path.join(bookmark_conf_path,
                'profiles', 'Other', 'extcap.cfg'))


@pytest.fixture
def profile_conf_path(conf_path):
    '''A configuration directory with a per-profile extcap.cfg.'''
    profile_dir = os.path.join(conf_path, 'profiles', 'Test lab')
    os.makedirs(profile_dir)
    with open(os.path.join(profile_dir, 'extcap.cfg'), 'w') as f:
        # Commented out preferences are at their default values.
        f.write('#extcap.randpkt.maxbytes: 5000\n')
        f.write('extcap.randpkt.count: 7\n')
        f.write('extcap.randpkt.type: dns\n')
    return conf_path


class TestExtcapProfileConfig:
    def test_extcap_profile_config_bookmark(self, cmd_tshark, program_path,
            profile_conf_path, base_env):
        '''A profile's extcap configuration becomes a bookmark named after the profile'''
        if sys.platform == 'win32':
            pytest.skip('Test requires Npcap.')
        iface_list = subprocess.check_output((cmd_tshark, '-C', 'Test lab', '-D'),
                cwd=program_path, encoding='utf-8', env=base_env)
        assert bookmark_listing('randpkt', 'Random packet generator', 'Test lab') in iface_list
        # The default profile's extcap.cfg is the shared one.
        iface_list = subprocess.check_output((cmd_tshark, '-D'),
                cwd=program_path, encoding='utf-8', env=base_env)
        assert bookmark_ifname('randpkt', 'Test lab') not in iface_list

    def test_extcap_profile_config_capture(self, cmd_tshark, program_path,
            profile_conf_path, base_env, result_file):
        '''Capturing from the bookmark uses the profile's configuration'''
        if sys.platform == 'win32':
            pytest.skip("Test doesn't work on Windows.")
        testout_file = result_file('testout.pcapng')
        # The packet count and type come from the profile, not the command line.
        subprocess.check_call((cmd_tshark, '-C', 'Test lab',
                '-i', bookmark_ifname('randpkt', 'Test lab'),
                '-a', 'duration:30', '-w', testout_file),
                cwd=program_path, env=base_env)
        protocols = subprocess.check_output((cmd_tshark, '-r', testout_file,
                '-T', 'fields', '-e', 'frame.protocols'),
                encoding='utf-8').splitlines()
        assert len(protocols) == 7
        assert all(':dns' in protocol for protocol in protocols)
