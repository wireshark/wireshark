#
# Wireshark tests
#
# Copyright (c) 2026 by the Wireshark developers
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Statistics tap tests'''

import subprocess
import pytest


class TestMkaConnectivityAssociations:
    '''
    EAPOL-MKA Connectivity Associations analysis (-z mka,ca).

    mka_ca.pcapng is a synthetic capture: an MKA exchange between a key
    server and two peers forming one Connectivity Association, generated
    from a hand-written hex description so it contains no real traffic.
    See doc/wsdg_src or the capture's companion text for how it was built.
    '''

    def test_mka_ca_lists_the_ca_and_peers(self, cmd_tshark, capture_file, test_env):
        '''The analysis lists the Connectivity Association and its peers.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('mka_ca.pcapng'),
                '-q',
                '-z', 'mka,ca',
            ), encoding='utf-8', env=test_env)
        assert 'MKA Connectivity Associations' in stdout
        # The CA is reported even when its CKN is not configured.
        assert 'CA:' in stdout
        # Peers are listed by SCI.
        assert 'Peer SCI' in stdout

    def test_mka_ca_reports_a_formation(self, cmd_tshark, capture_file, test_env):
        '''At least one peer group formation is reconstructed and classified.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('mka_ca.pcapng'),
                '-q',
                '-z', 'mka,ca',
            ), encoding='utf-8', env=test_env)
        assert 'Peer Group Formations' in stdout
        # The first distribution from a fresh key server is a startup.
        assert 'Key Server Startup' in stdout

    def test_mka_ca_with_display_filter(self, cmd_tshark, capture_file, test_env):
        '''The optional filter argument is accepted.'''
        completed = subprocess.run((cmd_tshark,
                '-r', capture_file('mka_ca.pcapng'),
                '-q',
                '-z', 'mka,ca,eapol',
            ), capture_output=True, encoding='utf-8', env=test_env)
        assert completed.returncode == 0
