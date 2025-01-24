#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''File I/O tests'''

import io
import os.path
import subprocess
from subprocesstest import cat_dhcp_command, check_packet_count
import sys
import pytest

testout_pcap = 'testout.pcap'
baseline_file = 'io-rawshark-dhcp-pcap.txt'


@pytest.fixture(scope='session')
def io_baseline_str(dirs):
    with open(os.path.join(dirs.baseline_dir, baseline_file), 'r') as f:
        return f.read()


def check_io_4_packets(capture_file, result_file, cmd_tshark, cmd_capinfos, from_stdin=False, to_stdout=False, env=None):
    # Test direct->direct, stdin->direct, and direct->stdout file I/O.
    # Similar to suite_capture.check_capture_10_packets and
    # suite_capture.check_capture_stdin.

    testout_file = result_file(testout_pcap)
    if from_stdin and to_stdout:
        # XXX If we support this, should we bother with separate stdin->direct
        # and direct->stdout tests?
        pytest.fail('Stdin and stdout not supported in the same test.')
    elif from_stdin:
        # cat -B "${CAPTURE_DIR}dhcp.pcap" | $DUT -r - -w ./testout.pcap 2>./testout.txt
        cat_dhcp_cmd = cat_dhcp_command('cat')
        stdin_cmd = '{0} | "{1}" -r - -w "{2}"'.format(cat_dhcp_cmd, cmd_tshark, testout_file)
        subprocess.check_call(stdin_cmd, shell=True, env=env)
    elif to_stdout:
        # $DUT -r "${CAPTURE_DIR}dhcp.pcap" -w - > ./testout.pcap 2>./testout.txt
        stdout_cmd = '"{0}" -r "{1}" -w - > "{2}"'.format(cmd_tshark, capture_file('dhcp.pcap'), testout_file)
        subprocess.check_call(stdout_cmd, shell=True, env=env)
    else: # direct->direct
        # $DUT -r "${CAPTURE_DIR}dhcp.pcap" -w ./testout.pcap > ./testout.txt 2>&1
        subprocess.check_call((cmd_tshark,
            '-r', capture_file('dhcp.pcap'),
            '-w', testout_file,
        ), env=env)
    assert os.path.isfile(testout_file)
    check_packet_count(cmd_capinfos, 4, testout_file)


class TestTsharkIO:
    def test_tshark_io_stdin_direct(self, cmd_tshark, cmd_capinfos, capture_file, result_file, test_env):
        '''Read from stdin and write direct using TShark'''
        check_io_4_packets(capture_file, result_file, cmd_tshark, cmd_capinfos, from_stdin=True, env=test_env)

    def test_tshark_io_direct_stdout(self, cmd_tshark, cmd_capinfos, capture_file, result_file, test_env):
        '''Read direct and write to stdout using TShark'''
        check_io_4_packets(capture_file, result_file, cmd_tshark, cmd_capinfos, to_stdout=True, env=test_env)

    def test_tshark_io_direct_direct(self, cmd_tshark, cmd_capinfos, capture_file, result_file, test_env):
        '''Read direct and write direct using TShark'''
        check_io_4_packets(capture_file, result_file, cmd_tshark, cmd_capinfos, env=test_env)


@pytest.mark.skipif(sys.byteorder != 'little', reason='Requires a little endian system')
class TestRawsharkIO:
    def test_rawshark_io_stdin(self, cmd_rawshark, capture_file, result_file, io_baseline_str, test_env):
        '''Read from stdin using Rawshark'''
        # tail -c +25 "${CAPTURE_DIR}dhcp.pcap" | $RAWSHARK -dencap:1 -R "udp.port==68" -nr - > $IO_RAWSHARK_DHCP_PCAP_TESTOUT 2> /dev/null
        # diff -u --strip-trailing-cr $IO_RAWSHARK_DHCP_PCAP_BASELINE $IO_RAWSHARK_DHCP_PCAP_TESTOUT > $DIFF_OUT 2>&1
        capture_file = capture_file('dhcp.pcap')
        testout_file = result_file(testout_pcap)
        raw_dhcp_cmd = cat_dhcp_command('raw')
        rawshark_cmd = '{0} | "{1}" -r - -n -dencap:1 -R "udp.port==68"'.format(raw_dhcp_cmd, cmd_rawshark)
        rawshark_stdout = subprocess.check_output(rawshark_cmd, shell=True, encoding='utf-8', env=test_env)
        assert rawshark_stdout == io_baseline_str
