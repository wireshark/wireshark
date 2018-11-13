#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''sharkd tests'''

import json
import subprocess
import subprocesstest
import fixtures


@fixtures.fixture(scope='session')
def cmd_sharkd(program):
    return program('sharkd')


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_sharkd(subprocesstest.SubprocessTestCase):
    def test_sharkd_hello_no_pcap(self, cmd_sharkd):
        '''sharkd hello message, no capture file'''
        sharkd_proc = self.startProcess((cmd_sharkd, '-'),
            stdin=subprocess.PIPE
        )

        sharkd_commands = b'{"req":"status"}\n'
        sharkd_proc.stdin.write(sharkd_commands)
        self.waitProcess(sharkd_proc)

        self.assertEqual(self.countOutput('Hello in child.', count_stdout=False, count_stderr=True), 1, 'No hello message.')

        try:
            jdata = json.loads(sharkd_proc.stdout_str)
            self.assertEqual(jdata['duration'], 0.0, 'Missing duration.')
        except:
            self.fail('Invalid JSON: "{}"'.format(sharkd_proc.stdout_str))

    def test_sharkd_hello_dhcp_pcap(self, cmd_sharkd, capture_file):
        '''sharkd hello message, simple capture file'''
        sharkd_proc = self.startProcess((cmd_sharkd, '-'),
            stdin=subprocess.PIPE
        )

        sharkd_commands = b'{"req":"load","file":'
        sharkd_commands += json.dumps(capture_file('dhcp.pcap')).encode('utf8')
        sharkd_commands += b'}\n'
        sharkd_commands += b'{"req":"status"}\n'
        sharkd_commands += b'{"req":"frames"}\n'

        sharkd_proc.stdin.write(sharkd_commands)
        self.waitProcess(sharkd_proc)

        has_dhcp = False
        for line in sharkd_proc.stdout_str.splitlines():
            line = line.strip()
            if not line: continue
            try:
                jdata = json.loads(line)
            except:
                self.fail('Invalid JSON for "{}"'.format(line))

            try:
                if 'DHCP' in jdata[0]['c']:
                    has_dhcp = True
            except:
                pass

        self.assertTrue(has_dhcp, 'Failed to find DHCP in JSON output')
