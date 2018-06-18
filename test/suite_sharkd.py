#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''sharkd tests'''

import config
import json
import os.path
import subprocess
import subprocesstest
import sys
import unittest

dhcp_pcap = os.path.join(config.capture_dir, 'dhcp.pcap')

class case_sharkd(subprocesstest.SubprocessTestCase):
    def test_sharkd_hello_no_pcap(self):
        '''sharkd hello message, no capture file'''
        sharkd_proc = self.startProcess((config.cmd_sharkd, '-'),
            stdin=subprocess.PIPE
        )

        sharkd_commands = '{"req":"status"}\n'
        if sys.version_info[0] >= 3:
            sharkd_commands = sharkd_commands.encode('UTF-8')
        sharkd_proc.stdin.write(sharkd_commands)
        self.waitProcess(sharkd_proc)

        self.assertEqual(self.countOutput('Hello in child.', count_stdout=False, count_stderr=True), 1, 'No hello message.')

        try:
            jdata = json.loads(sharkd_proc.stdout_str)
            self.assertEqual(jdata['duration'], 0.0, 'Missing duration.')
        except:
            self.fail('Invalid JSON: "{}"'.format(sharkd_proc.stdout_str))

    def test_sharkd_hello_dhcp_pcap(self):
        '''sharkd hello message, simple capture file'''
        sharkd_proc = self.startProcess((config.cmd_sharkd, '-'),
            stdin=subprocess.PIPE
        )

        sharkd_commands = ''
        sharkd_commands = '{"req":"load","file":' + json.JSONEncoder().encode(dhcp_pcap) + '}\n'
        sharkd_commands += '{"req":"status"}\n'
        sharkd_commands += '{"req":"frames"}\n'
        if sys.version_info[0] >= 3:
            sharkd_commands = sharkd_commands.encode('UTF-8')

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
