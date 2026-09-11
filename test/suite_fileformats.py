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
import subprocess
from pathlib import PurePath

import pytest

from subprocesstest import count_output

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
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
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
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'frame.time_delta',
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
            t, length, v = field
            v_hex = ''.join(f'{c:02x}' for c in v)
            return (f'0x{t:08x}', str(length), v_hex)
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
            '--inject-secrets', f'tls,{key_file}',
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
            '--inject-secrets', f'tls,{key_file1}',
            '--inject-secrets', f'tls,{key_file2}',
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
            '--inject-secrets', f'tls,{key_file}',
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
            '--log-fatal', 'warning',
            '--inject-secrets', f'tls,{rsa_keyfile}',
            '--inject-secrets', f'tls,{p12_keyfile}',
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

class TestFileFormatsPcapngProcessInformation:
    '''pcapng process information blocks.

    Process information carried in Wireshark custom blocks (PEN 32622, block
    entry type 3) and in legacy Darwin process information blocks (block type
    0x80000001) is read into the process information table of the file, not
    returned as records, and written back in the same form.  The captures are
    generated by test/captures/_gen_process_info_blocks.py.
    '''
    WIRESHARK_CAPTURE = 'process_info_wireshark_cb.pcapng'
    DARWIN_CAPTURE = 'process_info_darwin_dpib.pcapng'

    # The custom data (everything after the PEN) of each Wireshark custom
    # block in WIRESHARK_CAPTURE, in file order, as the generator prints it.
    PIB_0 = ('0300000094000000d2040000020004006375726c03000d002f7573722f62696e2f6375726c000000'
             '040019006375726c0068747470733a2f2f6578616d706c652e636f6d2f000000050004000100000006000400'
             'e803000007000500616c696365000000080010006b8b4567327b23c6643c986966334873090008000000faed'
             '5172861801000d0066697273742070726f6365737300000000000000')
    PIB_1 = '0300000004000000e1100000'
    UNKNOWN_ENTRY = '630000000500000068656c6c6f000000'
    PIB_2 = '03000000180000004d00000002000400737368640600040000000000000000000001000b73656374696f6e2074776f0000000000'
    # PIB 2 as written back: the comment among the options of the custom
    # block itself moves into the (little-endian) entry, after its options.
    PIB_2_REWRITTEN = '03000000280000004d0000000200040073736864060004000000000001000b0073656374696f6e2074776f0000000000'

    def custom_blocks(self, cmd_tshark, path, env):
        '''The (PEN, custom data) of the custom blocks in a pcapng file.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', path,
                '-Xread_format:MIME Files Format',
                '-Tfields',
                '-e', 'pcapng.cb.pen',
                '-e', 'pcapng.cb.custom_data',
                '-Y', 'pcapng.cb.pen',
            ), encoding='utf-8', env=env)
        pens, data = stdout.strip().split('\t')
        return list(zip(pens.split(','), data.split(',')))

    def test_pcapng_pib_wireshark_cb_records(self, tshark_fields):
        '''Process information blocks are not records; an unknown entry type is.'''
        stdout = tshark_fields(self.WIRESHARK_CAPTURE, fields=('frame.number', 'frame.protocols'))
        assert stdout.split('\n')[:4] == [
            '1\teth:ethertype:ip:udp:data',
            '2\tdata',
            '3\teth:ethertype:ip:udp:data',
            '4\teth:ethertype:ip:udp:data',
        ]

    def test_pcapng_pib_wireshark_cb_rewrite(self, cmd_tshark, cmd_editcap, capture_file, result_file, base_env):
        '''Wireshark custom blocks are preserved while rewriting files.'''
        infile = capture_file(self.WIRESHARK_CAPTURE)
        outfile = result_file('process_info_wireshark_cb-rewritten.pcapng')
        assert self.custom_blocks(cmd_tshark, infile, base_env) == [
            ('32622', self.PIB_0),
            ('32622', self.PIB_1),
            ('32622', self.UNKNOWN_ENTRY),
            ('32622', self.PIB_2),
        ]
        subprocess.run((cmd_editcap, infile, outfile), check=True, env=base_env)
        assert self.custom_blocks(cmd_tshark, outfile, base_env) == [
            ('32622', self.PIB_0),
            ('32622', self.PIB_1),
            ('32622', self.UNKNOWN_ENTRY),
            ('32622', self.PIB_2_REWRITTEN),
        ]

    def test_pcapng_pib_darwin_fields(self, assert_frames_match):
        '''Legacy Darwin process information blocks are looked up by the frame dissector.'''
        assert_frames_match(self.DARWIN_CAPTURE, [
            (1, 'frame.darwin.process_info.pid == 501 && frame.darwin.process_info.pname == "mDNSResponder"'),
            (2, 'frame.darwin.process_info.pid == 1 && frame.darwin.process_info.pname == "launchd"'),
        ])

    def test_pcapng_pib_darwin_rewrite(self, cmd_tshark, cmd_editcap, capture_file, result_file, base_env):
        '''Legacy Darwin process information blocks are written back as such.'''
        infile = capture_file(self.DARWIN_CAPTURE)
        outfile = result_file('process_info_darwin_dpib-rewritten.pcapng')
        subprocess.run((cmd_editcap, infile, outfile), check=True, env=base_env)
        stdout = subprocess.check_output((cmd_tshark,
                '-r', outfile,
                '-Xread_format:MIME Files Format',
                '-Tfields',
                '-e', 'pcapng.block.type',
                '-e', 'pcapng.darwin.process_id',
                '-e', 'pcapng.darwin.process_name',
                '-e', 'pcapng.darwin.process_uuid',
            ), encoding='utf-8', env=base_env)
        block_types, pids, names, uuids = stdout.strip().split('\t')
        assert block_types.split(',').count('0x80000001') == 2
        assert pids == '501,1'
        assert names == 'mDNSResponder,launchd'
        assert uuids == '6b8b4567-327b-23c6-643c-986966334873'
        stdout = subprocess.check_output((cmd_tshark,
                '-r', outfile,
                '-Tfields',
                '-e', 'frame.darwin.process_info.pid',
                '-e', 'frame.darwin.process_info.pname',
            ), encoding='utf-8', env=base_env)
        assert stdout.split('\n')[:2] == ['501\tmDNSResponder', '1\tlaunchd']


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

@pytest.fixture
def check_scap_event_block_options(request, cmd_strato, capture_file, test_env):
    '''Dump the comments in curl_google_comments.scap.gz. Requires the
    falco-events plugin and a non-Debug build.
    '''
    if request.config.getoption('--build-type').lower() == 'debug':
        pytest.skip('libsinsp debug builds have strict assertion checks')

    plugins = subprocess.check_output((cmd_strato, '-G', 'plugins'),
        encoding='utf-8', env=test_env)
    if 'falco-events' not in plugins:
        pytest.skip('The Falco Events plugin is not available')

    def dump_comments_real(show_internal):
        return subprocess.check_output((cmd_strato,
                '-r', capture_file('curl_google_comments.scap.gz'),
                '-o', f'falcoevents.show_internal_events:{show_internal}',
                '-Y', 'frame.comment',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'sysdig.event_len',
                '-e', 'sysdig.event_data_len',
                '-e', 'frame.comment',
            ), encoding='utf-8', env=test_env)
    return dump_comments_real


class TestFileFormatScap:
    def test_scap_event_block_options_internal(self, check_scap_event_block_options):
        '''Check Falco/Sysdig event block options, including an internal event's.'''
        proc_stdout = check_scap_event_block_options('TRUE')
        assert proc_stdout.strip().splitlines() == [
            '1\t42\t20\tInternal block comment',
            '211\t2360\t2338\tVisible block comment, no padding',
            '213\t50\t28\tVisible block comment, padding',
        ]

    def test_scap_event_block_options_no_internal(self, check_scap_event_block_options):
        '''Check that hiding internal events hides their options too.'''
        proc_stdout = check_scap_event_block_options('FALSE')
        assert 'Internal block comment' not in proc_stdout
        assert proc_stdout.strip().splitlines() == [
            '211\t2360\t2338\tVisible block comment, no padding',
            '213\t50\t28\tVisible block comment, padding',
        ]

class TestFileFormatCllog:
    def test_cllog_cl2000(self, cmd_tshark, capture_file, test_env):
        '''Basic test of CAN Logger file format reader.'''
        proc_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('canlogger-cl2000.txt'),
                '-Xread_format:CSS Electronics CLX000 CAN log',
                '-Tfields',
                '-e', 'can.id',
            ), encoding='utf-8', env=test_env)
        assert ' '.join(proc_stdout.strip().splitlines()) == \
            '2015 2024 2015 2024 2015 2024 2015 2024'
