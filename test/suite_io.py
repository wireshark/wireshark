#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''File I/O tests'''

import os.path
import subprocess
import sys

import pytest

from subprocesstest import cat_dhcp_command, check_packet_count

testout_pcap = 'testout.pcap'
baseline_file = 'io-rawshark-dhcp-pcap.txt'


class TestZstandardOutput:
    @pytest.mark.parametrize('file_format', ['pcap', 'pcapng'])
    @pytest.mark.parametrize('to_stdout', [False, True])
    def test_zstd_round_trip(self, cmd_editcap, cmd_tshark, capture_file,
                             result_file, features, test_env, file_format, to_stdout):
        if not features.have_zstd:
            pytest.skip('Zstandard is unavailable')
        output = result_file('capture.' + file_format + '.zst')
        command = [cmd_editcap, '-F', file_format, '--compress', 'zstd',
                   capture_file('dhcp.pcap'), '-' if to_stdout else output]
        if to_stdout:
            with open(output, 'wb') as stream:
                subprocess.check_call(command, stdout=stream, env=test_env)
        else:
            subprocess.check_call(command, env=test_env)
        with open(output, 'rb') as stream:
            assert stream.read(4) == b'\x28\xb5\x2f\xfd'
        fields = ['-T', 'fields', '-e', 'frame.number', '-e', 'frame.len',
                  '-e', 'eth.src', '-e', 'ip.src', '-e', 'udp.srcport']
        expected = subprocess.check_output(
            [cmd_tshark, '-r', capture_file('dhcp.pcap')] + fields, env=test_env)
        actual = subprocess.check_output([cmd_tshark, '-r', output] + fields, env=test_env)
        assert actual == expected
        # Compare canonical pcap bytes to verify every packet and timestamp,
        # including payload bytes not exposed by the fields above.
        baseline = result_file('baseline.pcap')
        restored = result_file('restored.pcap')
        subprocess.check_call([cmd_editcap, '-F', 'pcap', capture_file('dhcp.pcap'),
                               baseline], env=test_env)
        subprocess.check_call([cmd_editcap, '-F', 'pcap', output, restored], env=test_env)
        with open(baseline, 'rb') as original, open(restored, 'rb') as decoded:
            # pcapng conversion may change the global snaplen. Packet records
            # still retain their exact timestamps, lengths and payloads.
            original.seek(24)
            decoded.seek(24)
            assert original.read() == decoded.read()

    @pytest.mark.parametrize('level', [0, 1, 3, 9, 22])
    def test_tshark_zstd_output(self, cmd_tshark, capture_file, result_file,
                               features, test_env, level):
        if not features.have_zstd:
            pytest.skip('Zstandard is unavailable')
        output = result_file('tshark.pcapng.zst')
        subprocess.check_call([cmd_tshark, '-r', capture_file('dhcp.pcap'),
                               '-w', output, '--compress', 'zstd',
                               '-o', f'capture.zstd_compression_level:{level}'], env=test_env)
        fields = ['-T', 'fields', '-e', 'frame.number', '-e', 'frame.len']
        assert subprocess.check_output([cmd_tshark, '-r', output] + fields, env=test_env) == \
            subprocess.check_output([cmd_tshark, '-r', capture_file('dhcp.pcap')] + fields,
                                    env=test_env)

    @pytest.mark.parametrize('file_format', ['pcap', 'pcapng'])
    def test_zstd_multiframe_round_trip(self, cmd_editcap, cmd_tshark, capture_file,
                                       result_file, features, test_env, file_format):
        if not features.have_zstd:
            pytest.skip('Zstandard is unavailable')
        # Repeat valid packet records to cross multiple 4 MiB frame boundaries.
        baseline = result_file('baseline.pcap')
        subprocess.check_call([cmd_editcap, '-F', 'pcap', capture_file('dhcp.pcap'),
                               baseline], env=test_env)
        with open(baseline, 'rb') as stream:
            header, records = stream.read(24), stream.read()
        records *= (9 * 1024 * 1024 // len(records)) + 1
        source = result_file('multiframe.pcap')
        with open(source, 'wb') as stream:
            stream.write(header)
            stream.write(records)
        output = result_file('multiframe.' + file_format + '.zst')
        subprocess.check_call([cmd_tshark, '-r', source, '-F', file_format, '-w', output,
                               '--compress', 'zstd', '-o', 'capture.zstd_compression_level:19'],
                              env=test_env)
        # Two-pass dissection rereads packet offsets using Wiretap's seek handle.
        fields = ['-2', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch',
                  '-e', 'frame.len', '-e', 'eth.src', '-e', 'ip.src', '-e', 'udp.srcport']
        expected = subprocess.check_output([cmd_tshark, '-r', source] + fields, env=test_env)
        actual = subprocess.check_output([cmd_tshark, '-r', output] + fields, env=test_env)
        assert actual == expected
        restored = result_file('restored.pcap')
        subprocess.check_call([cmd_editcap, '-F', 'pcap', output, restored], env=test_env)
        with open(restored, 'rb') as stream:
            stream.seek(24)
            assert stream.read() == records

    def test_zstd_level_preference(self, cmd_tshark, capture_file, result_file,
                                   features, test_env, tmp_path):
        if not features.have_zstd:
            pytest.skip('Zstandard is unavailable')
        compressed = {}
        for level in [0, 1, 3, 9]:
            output = result_file(f'level-{level}.pcap.zst')
            subprocess.check_call([cmd_tshark, '-r', capture_file('dhcp.pcap'),
                                   '-F', 'pcap', '-w', output, '--compress', 'zstd',
                                   '-o', f'capture.zstd_compression_level:{level}'], env=test_env)
            with open(output, 'rb') as stream:
                compressed[level] = stream.read()
        assert compressed[0] == compressed[3]
        assert compressed[1] != compressed[9]

        # A saved preference must take effect without a command-line override.
        profile = tmp_path / 'zstd-profile'
        profile.mkdir()
        (profile / 'preferences').write_text('capture.zstd_compression_level: 9\n')
        profile_env = dict(test_env, WIRESHARK_CONFIG_DIR=str(profile))
        output = result_file('profile-level.pcap.zst')
        subprocess.check_call([cmd_tshark, '-r', capture_file('dhcp.pcap'), '-F', 'pcap',
                               '-w', output, '--compress', 'zstd'], env=profile_env)
        with open(output, 'rb') as stream:
            assert stream.read() == compressed[9]

    def test_zstd_invalid_level(self, cmd_tshark, capture_file, result_file,
                                features, test_env):
        if not features.have_zstd:
            pytest.skip('Zstandard is unavailable')
        output = result_file('invalid-level.pcapng.zst')
        result = subprocess.run([cmd_tshark, '-r', capture_file('dhcp.pcap'), '-w', output,
                                 '--compress', 'zstd', '-o', 'capture.zstd_compression_level:4294967295'],
                                env=test_env, capture_output=True)
        assert result.returncode != 0

    def test_zstd_filename_extension(self, cmd_editcap, cmd_tshark, capture_file,
                                     result_file, features, test_env):
        if not features.have_zstd:
            pytest.skip('Zstandard is unavailable')
        output = result_file('inferred.pcapng.zst')
        subprocess.check_call([cmd_editcap, capture_file('dhcp.pcap'), output], env=test_env)
        with open(output, 'rb') as stream:
            assert stream.read(4) == b'\x28\xb5\x2f\xfd'
        frames = subprocess.check_output([cmd_tshark, '-r', output, '-T', 'fields',
                                          '-e', 'frame.number'], env=test_env)
        assert frames.splitlines() == [b'1', b'2', b'3', b'4']


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
        stdin_cmd = f'{cat_dhcp_cmd} | "{cmd_tshark}" -r - -w "{testout_file}"'
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
        result_file(testout_pcap)
        raw_dhcp_cmd = cat_dhcp_command('raw')
        rawshark_cmd = f'{raw_dhcp_cmd} | "{cmd_rawshark}" --log-fatal=warning -r - -n -dencap:1 -R "udp.port==68"'
        rawshark_stdout = subprocess.check_output(rawshark_cmd, shell=True, encoding='utf-8', env=test_env)
        assert rawshark_stdout == io_baseline_str
