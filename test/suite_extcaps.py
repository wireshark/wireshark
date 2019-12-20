# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Copyright (c) 2019 Dario Lombardo <lomato@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''extcap tests'''

import subprocesstest
import fixtures
import re
import os
import sys


@fixtures.fixture
def check_extcap_execution(cmd_extcap, program_path, request):
    def check_extcap_interface_execution(extcap_name, interface):
        ''' Check if an extcap runs flawlessly for interface configuration. '''
        self = request.instance
        self.assertRun([cmd_extcap(extcap_name), '--extcap-interface',
                        interface, '--extcap-dlts'], cwd=program_path)
        self.assertRun([cmd_extcap(extcap_name), '--extcap-interface',
                        interface, '--extcap-config'], cwd=program_path)

    def extcap_get_interfaces(extcap_output):
        ''' Extract the interface name from extcap. '''
        parser = re.compile("{value=(.*?)}")
        interfaces = []
        for line in extcap_output.splitlines():
            if line.startswith('interface '):
                interfaces.append(parser.findall(line)[0])
        return interfaces

    def check_extcap_execution_real(extcap_name, always_present=True):
        '''
        Check if an extcap runs flawlessly.
        always_present: at least one interface is always offered by the extcap.
        '''
        self = request.instance
        self.assertRun([cmd_extcap(extcap_name), '--help'], cwd=program_path)
        extcap_proc = self.assertRun(
            [cmd_extcap(extcap_name), '--extcap-interfaces'], cwd=program_path)
        interfaces = extcap_get_interfaces(extcap_proc.stdout_str)
        if always_present:
            self.assertGreaterEqual(len(interfaces), 1)
        for interface in interfaces:
            check_extcap_interface_execution(extcap_name, interface)

    return check_extcap_execution_real


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_extcaps(subprocesstest.SubprocessTestCase):
    def test_androiddump(self, check_extcap_execution):
        ''' extcap interface tests for androiddump '''
        check_extcap_execution("androiddump", always_present=False)

    def test_ciscodump(self, check_extcap_execution):
        ''' extcap interface tests for ciscodump '''
        check_extcap_execution("ciscodump")

    def test_dpauxmon(self, check_extcap_execution):
        ''' extcap interface tests for dpauxmon '''
        if not sys.platform.startswith('linux'):
            fixtures.skip('dpauxmon available on Linux only')
        check_extcap_execution("dpauxmon")

    def test_randpktdump(self, check_extcap_execution):
        ''' extcap interface tests for randpktdump '''
        check_extcap_execution("randpktdump")

    def test_sdjournal(self, check_extcap_execution):
        ''' extcap interface tests for sdjournal '''
        if not sys.platform.startswith('linux'):
            fixtures.skip('sdjournal is available on Linux only')
        check_extcap_execution("sdjournal")

    def test_sshdump(self, check_extcap_execution):
        ''' extcap interface tests for sshdump '''
        check_extcap_execution("sshdump")

    def test_udpdump(self, check_extcap_execution):
        ''' extcap interface tests for udpdump '''
        check_extcap_execution("udpdump")
