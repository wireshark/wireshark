#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""NTLMSSP dissector tests."""

import subprocess


def test_av_flags(cmd_tshark, capture_file, test_env):
    # Synthetic messages exercise all three MsvAvFlags bits in both AV lists.
    fields = (
        'frame.number',
        'ntlmssp.challenge.target_info.flags',
        'ntlmssp.challenge.target_info.flags.constrained_authentication',
        'ntlmssp.challenge.target_info.flags.mic_present',
        'ntlmssp.challenge.target_info.flags.untrusted_target_spn',
        'ntlmssp.ntlmv2_response.flags',
        'ntlmssp.ntlmv2_response.flags.constrained_authentication',
        'ntlmssp.ntlmv2_response.flags.mic_present',
        'ntlmssp.ntlmv2_response.flags.untrusted_target_spn',
        '_ws.malformed',
    )
    output = subprocess.check_output((
        cmd_tshark,
        '-r', capture_file('ntlmssp-av-flags.pcapng'),
        '-T', 'fields',
        *(arg for field in fields for arg in ('-e', field)),
    ), encoding='utf-8', env=test_env)

    assert [line.split('\t') for line in output.splitlines()] == [
        ['1', '0x00000001', 'True', 'False', 'False', '', '', '', '', ''],
        ['2', '', '', '', '', '0x00000001', 'True', 'False', 'False', ''],
        ['3', '0x00000002', 'False', 'True', 'False', '', '', '', '', ''],
        ['4', '', '', '', '', '0x00000002', 'False', 'True', 'False', ''],
        ['5', '0x00000004', 'False', 'False', 'True', '', '', '', '', ''],
        ['6', '', '', '', '', '0x00000004', 'False', 'False', 'True', ''],
    ]
