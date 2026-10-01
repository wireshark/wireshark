#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""Kerberos dissector tests."""

import subprocess


def test_gssapi_iakerb_finished(cmd_tshark, capture_file, test_env):
    # Synthetic KRB-SAFE messages carry 0x8003 checksums to exercise the
    # checksum parser without any ticket, key, or authenticator material.
    output = subprocess.check_output((
        cmd_tshark,
        '-r', capture_file('kerberos-gssapi-extensions.pcap'),
        '-T', 'fields',
        '-e', 'kerberos.gssapi.extension.type',
        '-e', 'kerberos.gssapi.extension.length',
        '-e', 'kerberos.gssapi.extension.data',
        '-e', 'kerberos.gss_mic_element',
        '-e', 'kerberos.cksumtype',
        '-e', 'kerberos.checksum',
        '-e', 'kerberos.gssapi.dlglen',
        '-e', 'kerberos.gssapi.extension.length.error',
        '-e', '_ws.malformed',
    ), encoding='utf-8', env=test_env)

    rows = [line.split('\t') for line in output.splitlines()]
    assert [row[0] for row in rows] == ['2', '1', '2', '', '99']
    assert rows[0][1] == rows[1][1] == '31'
    assert rows[0][2] == rows[1][2] == '301da11b3019a003020110a1120410' + '11' * 16
    assert rows[0][3] and rows[1][3]
    assert rows[0][4] == rows[1][4] == '32771,16'
    assert rows[0][5].endswith(',' + '11' * 16)
    assert rows[1][5].endswith(',' + '11' * 16)
    assert all(row[6] == '' for row in rows)
    assert rows[0][7:] == ['', '']
    assert rows[1][7:] == ['', '']
    assert rows[2][7] and rows[2][8]
    assert rows[3][7] and rows[3][8]
    assert rows[4][2] == '78797a'
    assert rows[4][7:] == ['', '']
