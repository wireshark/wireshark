#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Copyright (c) 2019 Dario Lombardo <lomato@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''extcap tests'''

import subprocess
import re
import os
import sys
import pytest


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

    def check_extcap_execution_real(extcap_name, stratoshark_extcap=False, always_present=True):
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

    def test_falcodump(self, check_extcap_execution):
        ''' extcap interface tests for falcodump '''
        check_extcap_execution("falcodump", stratoshark_extcap=True, always_present=False)

    def test_randpktdump(self, check_extcap_execution):
        ''' extcap interface tests for randpktdump '''
        check_extcap_execution("randpktdump")

    def test_sdjournal(self, check_extcap_execution):
        ''' extcap interface tests for sdjournal '''
        if not sys.platform.startswith('linux'):
            pytest.skip('sdjournal is available on Linux only')
        check_extcap_execution("sdjournal")

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
