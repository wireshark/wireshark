#
# Wireshark tests
#
# Copyright 2026 by Michael Kirsche <michael.kirsche@codewerk.de>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''OPC UA tests'''

import subprocess

import pytest


class TestDissectOpcua:

    def test_opcua_extension_object_not_ns0(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env, features):
        '''An ExtensionObject whose TypeId is outside namespace 0 is not
        decoded with the built-in parser of the same numeric ID.

        A single MSG chunk (no HEL/ACK/OPN, so SecurityMode None) with a
        ReadResponse (i=634). Its one result is a DataValue with an
        ExtensionObject of TypeId ns=1;i=886 (i=886 is the encoding ID of
        Range in namespace 0) and a 16-byte body (the Doubles 1.0 and 2.0).
        It must be shown as ByteString, not as Range (Low 1, High 2).'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        testin_file = result_file('opcua-extobj-ns1.txt')
        testout_file = result_file('opcua-extobj-ns1.pcap')
        payload = '''\
000000 4d 53 47 46 57 00 00 00 01 00 00 00 01 00 00 00
000010 01 00 00 00 01 00 00 00 01 00 7a 02 00 00 00 00
000020 00 00 00 00 01 00 00 00 00 00 00 00 00 ff ff ff
000030 ff 00 00 00 01 00 00 00 01 16 01 01 76 03 01 10
000040 00 00 00 00 00 00 00 00 00 f0 3f 00 00 00 00 00
000050 00 00 40 ff ff ff ff
'''
        with open(testin_file, 'w') as f:
            f.write(payload)
        subprocess.check_call((cmd_text2pcap, '-T', '1234,4840', testin_file, testout_file), env=base_env)

        stdout = subprocess.check_output((cmd_tshark,
                '-r', testout_file,
                '-Tfields',
                '-eopcua.ByteString',
                '-eopcua.Low',
            ), encoding='utf-8', env=test_env)
        assert stdout == '000000000000f03f0000000000000040\t\n'
