#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''File format conversion tests'''

import os.path
from subprocesstest import count_output
import subprocess
import pytest
from pathlib import PurePath

# XXX Currently unused. It would be nice to be able to use this below.
time_output_args = ('-Tfields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta')

# Microsecond pcap, direct read was used to generate the baseline:
# tshark -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta \
#   -r captures/dhcp.pcap > baseline/ff-ts-usec-pcap-direct.txt
baseline_file = 'ff-ts-usec-pcap-direct.txt'


@pytest.fixture(scope='session')
def fileformats_baseline_str(dirs):
    with open(os.path.join(dirs.baseline_dir, baseline_file), 'r') as f:
        return f.read()


class TestFileFormatPcap:
    def test_pcap_usec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs microsecond pcap stdin'''
        capture_stdout = subprocess.check_output(' '.join((f'"{cmd_tshark}"',
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                '<', capture_file('dhcp.pcap')
                )),
            shell=True, encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str

    def test_pcap_nsec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs nanosecond pcap stdin'''
        capture_stdout = subprocess.check_output(' '.join((f'"{cmd_tshark}"',
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                '<', capture_file('dhcp-nanosecond.pcap')
                )),
            shell=True, encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str

    def test_pcap_nsec_direct(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs nanosecond pcap direct'''
        capture_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dhcp-nanosecond.pcap'),
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str


class TestFileFormatsPcapng:
    def test_pcapng_usec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs microsecond pcapng stdin'''
        capture_stdout = subprocess.check_output(' '.join((f'"{cmd_tshark}"',
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta'
                '<', capture_file('dhcp.pcapng')
                )),
            shell=True, encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str

    def test_pcapng_usec_direct(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs microsecond pcapng direct'''
        capture_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dhcp.pcapng'),
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str

    def test_pcapng_nsec_stdin(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs nanosecond pcapng stdin'''
        capture_stdout = subprocess.check_output(' '.join((f'"{cmd_tshark}"',
                '-r', '-',
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta'
                '<', capture_file('dhcp-nanosecond.pcapng')
                )),
            shell=True, encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str

    def test_pcapng_nsec_direct(self, cmd_tshark, capture_file, fileformats_baseline_str, test_env):
        '''Microsecond pcap direct vs nanosecond pcapng direct'''
        capture_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dhcp-nanosecond.pcapng'),
                '-Tfields',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
                ),
            encoding='utf-8', env=test_env)
        assert capture_stdout == fileformats_baseline_str

@pytest.fixture
def check_pcapng_dsb_fields(request, cmd_tshark):
    '''Factory that checks whether the DSB within the capture file matches.'''
    def check_dsb_fields_real(outfile, fields, env=None):
        proc_stdout = subprocess.check_output((cmd_tshark,
                '-r', outfile,
                '-Xread_format:MIME Files Format',
                '-Tfields',
                '-e', 'pcapng.dsb.secrets_type',
                '-e', 'pcapng.dsb.secrets_length',
                '-e', 'pcapng.dsb.secrets_data',
                '-Y', 'pcapng.dsb.secrets_data'
            ), encoding='utf-8', env=env)
        # Convert "t1,t2 l1,l2 v1,2" -> [(t1, l1, v1), (t2, l2, v2)]
        output = proc_stdout.strip()
        actual = list(zip(*[x.split(",") for x in output.split('\t')]))
        def format_field(field):
            t, l, v = field
            v_hex = ''.join('%02x' % c for c in v)
            return ('0x%08x' % t, str(l), v_hex)
        fields = [format_field(field) for field in fields]
        assert fields == actual
    return check_dsb_fields_real


class TestFileFormatsPcapngDsb:
    def test_pcapng_dsb_1(self, cmd_tshark, dirs, capture_file, result_file, check_pcapng_dsb_fields, base_env):
        '''Check that DSBs are preserved while rewriting files.'''
        dsb_keys1 = os.path.join(dirs.key_dir, 'tls12-dsb-1.keys')
        dsb_keys2 = os.path.join(dirs.key_dir, 'tls12-dsb-2.keys')
        outfile = result_file('tls12-dsb-same.pcapng')
        subprocess.run((cmd_tshark,
            '-r', capture_file('tls12-dsb.pcapng'),
            '-w', outfile,
        ), check=True, env=base_env)
        with open(dsb_keys1, 'r') as f:
            dsb1_contents = f.read().encode('utf8')
        with open(dsb_keys2, 'r') as f:
            dsb2_contents = f.read().encode('utf8')
        check_pcapng_dsb_fields(outfile, (
            (0x544c534b, len(dsb1_contents), dsb1_contents),
            (0x544c534b, len(dsb2_contents), dsb2_contents),
        ), env=base_env)

    def test_pcapng_dsb_2(self, cmd_editcap, dirs, capture_file, result_file, check_pcapng_dsb_fields, base_env):
        '''Insert a single DSB into a pcapng file.'''
        key_file = os.path.join(dirs.key_dir, 'dhe1_keylog.dat')
        outfile = result_file('dhe1-dsb.pcapng')
        subprocess.run((cmd_editcap,
            '--inject-secrets', 'tls,%s' % key_file,
            capture_file('dhe1.pcapng.gz'), outfile
        ), check=True, env=base_env)
        with open(key_file, 'rb') as f:
            keylog_contents = f.read()
        check_pcapng_dsb_fields(outfile, (
            (0x544c534b, len(keylog_contents), keylog_contents),
        ), env=base_env)

    def test_pcapng_dsb_3(self, cmd_editcap, dirs, capture_file, result_file, check_pcapng_dsb_fields, base_env):
        '''Insert two DSBs into a pcapng file.'''
        key_file1 = os.path.join(dirs.key_dir, 'dhe1_keylog.dat')
        key_file2 = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        outfile = result_file('dhe1-dsb.pcapng')
        subprocess.run((cmd_editcap,
            '--inject-secrets', 'tls,%s' % key_file1,
            '--inject-secrets', 'tls,%s' % key_file2,
            capture_file('dhe1.pcapng.gz'), outfile
        ), check=True, env=base_env)
        with open(key_file1, 'rb') as f:
            keylog1_contents = f.read()
        with open(key_file2, 'rb') as f:
            keylog2_contents = f.read()
        check_pcapng_dsb_fields(outfile, (
            (0x544c534b, len(keylog1_contents), keylog1_contents),
            (0x544c534b, len(keylog2_contents), keylog2_contents),
        ), env=base_env)

    def test_pcapng_dsb_4(self, cmd_editcap, dirs, capture_file, result_file, check_pcapng_dsb_fields, base_env):
        '''Insert a single DSB into a pcapng file with existing DSBs.'''
        dsb_keys1 = os.path.join(dirs.key_dir, 'tls12-dsb-1.keys')
        dsb_keys2 = os.path.join(dirs.key_dir, 'tls12-dsb-2.keys')
        key_file = os.path.join(dirs.key_dir, 'dhe1_keylog.dat')
        outfile = result_file('tls12-dsb-extra.pcapng')
        subprocess.run((cmd_editcap,
            '--inject-secrets', 'tls,%s' % key_file,
            capture_file('tls12-dsb.pcapng'), outfile
        ), check=True, env=base_env)
        with open(dsb_keys1, 'r') as f:
            dsb1_contents = f.read().encode('utf8')
        with open(dsb_keys2, 'r') as f:
            dsb2_contents = f.read().encode('utf8')
        with open(key_file, 'rb') as f:
            keylog_contents = f.read()
        # New DSBs are inserted before the first record. Due to the current
        # implementation, this is inserted before other (existing) DSBs. This
        # might change in the future if it is deemed more logical.
        check_pcapng_dsb_fields(outfile, (
            (0x544c534b, len(keylog_contents), keylog_contents),
            (0x544c534b, len(dsb1_contents), dsb1_contents),
            (0x544c534b, len(dsb2_contents), dsb2_contents),
        ), env=base_env)

    def test_pcapng_dsb_bad_key(self, cmd_editcap, dirs, capture_file, result_file, check_pcapng_dsb_fields, base_env):
        '''Insertion of a RSA key file is not very effective.'''
        rsa_keyfile = os.path.join(dirs.key_dir, 'rsasnakeoil2.key')
        p12_keyfile = os.path.join(dirs.key_dir, 'key.p12')
        outfile = result_file('rsasnakeoil2-dsb.pcapng')
        proc = subprocess.run((cmd_editcap,
            '--inject-secrets', 'tls,%s' % rsa_keyfile,
            '--inject-secrets', 'tls,%s' % p12_keyfile,
            capture_file('rsasnakeoil2.pcap'), outfile
        ), capture_output=True, encoding='utf-8', check=True, env=base_env)
        assert count_output(proc.stderr, 'unsupported private key file') == 2
        with open(rsa_keyfile, 'rb') as f:
            dsb1_contents = f.read()
        with open(p12_keyfile, 'rb') as f:
            dsb2_contents = f.read()
        check_pcapng_dsb_fields(outfile, (
            (0x544c534b, len(dsb1_contents), dsb1_contents),
            (0x544c534b, len(dsb2_contents), dsb2_contents),
        ), env=base_env)

    def test_pcapng_dsb_extract(self, cmd_editcap, dirs, capture_file, result_file, check_pcapng_dsb_fields, base_env):
        '''Check that extracted DSBs match the original key log files.'''
        dsb_keys1 = os.path.join(dirs.key_dir, 'tls12-dsb-1.keys')
        dsb_keys2 = os.path.join(dirs.key_dir, 'tls12-dsb-2.keys')
        outfile = result_file('tls12-dsb-extract.key')
        subprocess.run((cmd_editcap,
            '--extract-secrets',
            capture_file('tls12-dsb.pcapng'), outfile
        ), check=True, env=base_env)
        p = PurePath(outfile)
        with open(dsb_keys1, 'r') as f:
            dsb1_contents = f.read().encode('utf8')
        with open(dsb_keys2, 'r') as f:
            dsb2_contents = f.read().encode('utf8')
        # Python 3.9 and higher has p.with_stem(p.stem + "_00000"))
        with open(p.with_name(p.stem + "_00000" + p.suffix)) as f:
            dsb1_out = f.read().encode('utf8')
        with open(p.with_name(p.stem + "_00001" + p.suffix)) as f:
            dsb2_out = f.read().encode('utf8')
        assert dsb1_contents == dsb1_out
        assert dsb2_contents == dsb2_out

class TestFileFormatMime:
    def test_mime_pcapng_gz(self, cmd_tshark, capture_file, test_env):
        '''Test that the full uncompressed contents is shown.'''
        proc_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('icmp.pcapng.gz'),
                '-Xread_format:MIME Files Format',
                '-Tfields',
                '-e', 'frame.len',
                '-e', 'pcapng.block.length',
                '-e', 'pcapng.block.length_trailer',
            ), encoding='utf-8', env=test_env)
        assert proc_stdout.strip() == '480\t128,88,132,132\t128,88,132,132'
