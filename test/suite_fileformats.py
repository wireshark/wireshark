#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''File format conversion tests'''

import gzip
import hashlib
import json
import os.path
import struct
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
    DARWIN_CAPTURES = ('process_info_darwin_dpib.pcapng', 'process_info_darwin_dpib_be.pcapng')

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

    def test_pcapng_several_processes_rewrite(self, cmd_tshark, cmd_editcap, capture_file, result_file, base_env):
        '''Several epb_processid_threadid options of a packet survive rewriting.'''
        infile = capture_file('process_info_several.pcapng')
        outfile = result_file('process_info_several-rewritten.pcapng')
        fields = ('-T', 'fields', '-e', 'frame.number', '-e', 'frame.process.pid', '-e', 'frame.process.name')
        before = subprocess.check_output((cmd_tshark, '-r', infile) + fields, encoding='utf-8', env=base_env)
        assert before.splitlines() == ['1\t10,20,30\tsender,receiver,other', '2\t20\treceiver']
        subprocess.run((cmd_editcap, infile, outfile), check=True, env=base_env)
        after = subprocess.check_output((cmd_tshark, '-r', outfile) + fields, encoding='utf-8', env=base_env)
        assert after == before

    @pytest.mark.parametrize('capture,block_type', [
        ('process_info_several.pcapng', '0x00000bad'),
        ('process_info_darwin_dpib.pcapng', '0x80000001'),
    ])
    def test_pcapng_pib_discard(self, cmd_tshark, cmd_editcap, capture_file, result_file, base_env, capture, block_type):
        '''editcap --discard-process-info drops the process blocks, Wireshark's
        and Darwin's, and the options of the packets that refer to them; the
        packets themselves and their other options stay.'''
        infile = capture_file(capture)
        outfile = result_file(capture.replace('.pcapng', '-no-processes.pcapng'))
        subprocess.run((cmd_editcap, '--discard-process-info', infile, outfile), check=True, env=base_env)
        structure = ('-Xread_format:MIME Files Format', '-T', 'fields', '-e', 'pcapng.block.type')
        before = subprocess.check_output((cmd_tshark, '-r', infile) + structure, encoding='utf-8', env=base_env).strip().split(',')
        after = subprocess.check_output((cmd_tshark, '-r', outfile) + structure, encoding='utf-8', env=base_env).strip().split(',')
        assert block_type in before
        assert block_type not in after
        assert after.count('0x00000006') == before.count('0x00000006')
        fields = ('-T', 'fields', '-e', 'frame.number', '-e', 'frame.process.pid', '-e', 'frame.process.name',
                  '-e', 'frame.darwin.process_info.pid', '-e', 'frame.darwin.process_info.epid')
        packets = subprocess.check_output((cmd_tshark, '-r', outfile) + fields, encoding='utf-8', env=base_env).splitlines()
        assert len(packets) == before.count('0x00000006')
        for line in packets:
            number, pid, name, dpid, depid = line.split('\t')
            assert (pid, name, dpid, depid) == ('', '', '', ''), line

    @pytest.mark.parametrize('capture', DARWIN_CAPTURES)
    def test_pcapng_pib_darwin_fields(self, assert_frames_match, capture):
        '''Legacy Darwin process information blocks are looked up by the frame
        dissector, whatever the byte order of the section.'''
        assert_frames_match(capture, [
            (1, 'frame.darwin.process_info.pid == 501 && frame.darwin.process_info.pname == "mDNSResponder"'),
            (2, 'frame.darwin.process_info.pid == 1 && frame.darwin.process_info.pname == "launchd"'),
        ])

    @pytest.mark.parametrize('capture', DARWIN_CAPTURES)
    def test_pcapng_pib_darwin_file_dissector(self, cmd_tshark, capture_file, base_env, capture):
        '''The pcapng file dissector reads the Darwin integer fields as
        little-endian in a section of either byte order, as wiretap does.
        A file rewritten on a big-endian host is such a big-endian section.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file(capture),
                '-Xread_format:MIME Files Format',
                '-Tfields',
                '-e', 'pcapng.darwin.process_id',
                '-e', 'pcapng.options.option.data.packet.darwin.dpib_id',
                '-e', 'pcapng.options.option.data.packet.darwin.edpib_id',
            ), encoding='utf-8', env=base_env)
        pids, dpib_ids, edpib_ids = stdout.strip().split('\t')
        assert pids == '501,1'
        assert dpib_ids == '0,1,0'
        assert edpib_ids == '1'

    @pytest.mark.parametrize('capture', DARWIN_CAPTURES)
    def test_pcapng_pib_darwin_rewrite(self, cmd_tshark, cmd_editcap, capture_file, result_file, base_env, capture):
        '''Legacy Darwin process information blocks are written back as such.'''
        infile = capture_file(capture)
        outfile = result_file(capture.replace('.pcapng', '-rewritten.pcapng'))
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

    # libsinsp versions before 0.21 can't read this capture, because its
    # section header block has options. The dissector reports that instead of
    # extracting fields, so it can't tell which events are internal.
    unreadable = subprocess.check_output((cmd_strato,
            '-r', capture_file('curl_google_comments.scap.gz'),
            '-Y', 'frame.number == 1 && falcoevents.capture_unreadable',
            '-Tfields',
            '-e', 'frame.number',
        ), encoding='utf-8', env=test_env)
    dump_comments_real.sinsp_can_read = unreadable.strip() == ''
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
        if not check_scap_event_block_options.sinsp_can_read:
            pytest.skip('libsinsp cannot read this capture, so internal events are unknown')
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


class TestFileFormatDtsdi:
    def test_dtsdi_v2_gzip(self, cmd_tshark, capture_file, test_env):
        '''Basic test of the DekTec DTSDI V2 file reader.'''
        proc_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtsdi-vanc-op47.dtsdi.gz'),
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'frame.len',
                '-e', 'frame.time_epoch',
            ), encoding='utf-8', env=test_env)
        assert proc_stdout == '1\t7425000\t0.000000000\n'

    def test_dtsdi_v2_inferred_frame_metadata(self, cmd_tshark, capture_file,
                                               test_env):
        '''Checks inference when the V2 frame size and count are zero.'''
        proc_stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtsdi-v2-16bit-st352.dtsdi.gz'),
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'frame.len',
                '-e', 'frame.time_epoch',
            ), encoding='utf-8', env=test_env)
        assert proc_stdout == '1\t4950000\t0.000000000\n'

    def test_dtsdi_v2_truncated_frame(self, cmd_tshark, capture_file,
                                      result_file, test_env):
        '''Checks rejection of an incomplete final frame.'''
        with gzip.open(capture_file('dtsdi-v2-16bit-st352.dtsdi.gz'), 'rb') as fh:
            contents = fh.read()
        truncated_file = result_file('dtsdi-v2-truncated.dtsdi')
        with open(truncated_file, 'wb') as fh:
            fh.write(contents[:-1])

        proc = subprocess.run((cmd_tshark, '-r', truncated_file),
                              capture_output=True, encoding='utf-8',
                              env=test_env)
        assert proc.returncode != 0
        assert 'not a supported number of 4950000-byte frames' in proc.stderr

    def test_dtsdi_truncated_header(self, cmd_tshark, capture_file,
                                    result_file, test_env):
        '''Checks that a recognized file with a short header is rejected.'''
        with gzip.open(capture_file('dtsdi-v2-16bit-st352.dtsdi.gz'), 'rb') as fh:
            contents = fh.read(12)
        truncated_file = result_file('dtsdi-truncated-header.dtsdi')
        with open(truncated_file, 'wb') as fh:
            fh.write(contents)

        proc = subprocess.run((cmd_tshark, '-r', truncated_file),
                              capture_output=True, encoding='utf-8',
                              env=test_env)
        assert proc.returncode != 0
        assert 'cut short in the middle of a packet' in proc.stderr

    def test_dtsdi_v2_undersized_frame(self, cmd_tshark, capture_file,
                                       result_file, test_env):
        '''Checks rejection of a declared frame smaller than its raster.'''
        with gzip.open(capture_file('dtsdi-v2-16bit-st352.dtsdi.gz'), 'rb') as fh:
            contents = bytearray(fh.read())
        contents[16:20] = (1).to_bytes(4, 'little')
        malformed_file = result_file('dtsdi-v2-undersized.dtsdi')
        with open(malformed_file, 'wb') as fh:
            fh.write(contents)

        proc = subprocess.run((cmd_tshark, '-r', malformed_file),
                              capture_output=True, encoding='utf-8',
                              env=test_env)
        assert proc.returncode != 0
        assert 'frame size 1 is smaller than the minimum 4950000-byte full frame' in proc.stderr


# The packets of mdf_coverage.mf4.gz: frame number, interface name, time,
# direction flags of the packet (1 inbound, 2 outbound, None if not in the
# file), length, captured length and the data of the packet (as hex, or the
# start of its SHA-256 if it is longer than 48 bytes).
#
# The file is generated, nothing in it comes from a real network. It has
# Ethernet, CAN, CAN FD, LIN and FlexRay events, stored in sorted and unsorted
# data groups with record IDs of one and two bytes, with the payload in a
# variable length channel group, in signal data blocks (in a data list), in
# fixed size arrays, with the data in data blocks, data lists and header lists
# of plain, compressed and transposed compressed blocks, with real and
# constant (virtual) bus channels and with integer and floating point time
# stamps. It also has groups the reader has to skip: temperature values and
# CAN frames in ZStd compressed blocks.
MDF_PACKETS = [
    (1, 'CAN-1', '1767225600.001000000', 1, 16, 16,
     '00000123080000000714212e3b485562'),
    (2, 'ETH-1', '1767225600.002000000', 1, 60, 60,
     'sha256:754fdc44706fd1eb'),
    (3, 'LIN-1', '1767225600.003000000', 1, 16, 16,
     '01000000828bb50015222f3c49566370'),
    (4, 'FR-1', '1767225600.004000000', 1, 15, 15,
     '0100301908a9431c293643505d6a77'),
    (5, 'CAN-1', '1767225600.005000000', 2, 13, 13,
     '9abcdef00500000023303d4a57'),
    (6, 'CAN-1', '1767225600.006000000', 1, 8, 8,
     '4000005500000000'),
    (7, 'CAN-1', '1767225600.007000000', None, 16, 16,
     '20000000080000000000000000000000'),
    (8, 'CAN-1', '1767225600.008000000', None, 16, 16,
     '20000008080000000000010000000000'),
    (9, 'CAN-4', '1767225600.009000000', None, 16, 16,
     '00000321080000002a3744515e6b7885'),
    (10, 'ETH-1', '1767225600.010000000', 2, 74, 74,
     'sha256:f9b4543c0e469af4'),
    (11, 'LIN-1', '1767225600.011000000', 1, 12, 12,
     '01000000216a7f0038450000'),
    (12, 'FR-1', '1767225600.012000000', 1, 23, 23,
     '8100f86411ffff3f4c596673808d9aa7b4c1cedbe8f502'),
    (13, 'CAN-2', '1767225600.013000000', 1, 72, 72,
     'sha256:ab8e2b192375ff58'),
    (14, 'CAN-1', '1767225600.014000000', None, 16, 16,
     '20000008080000000000020000000000'),
    (15, 'CAN-3', '1767225600.015000000', None, 16, 16,
     '20000008080000000000200000000000'),
    (16, 'FR-1', '1767225600.016000000', None, 11, 11,
     '0100001904554400000000'),
    (17, 'ETH-1', '1767225600.017000000', 1, 14, 14,
     '02000000000102000000000288b5'),
    (18, 'LIN-2', '1767225600.018000000', 1, 12, 12,
     '010000000050000000000000'),
    (19, 'CAN-2', '1767225600.019000000', 1, 20, 20,
     '800012340c0600004d5a6774818e9ba8b5c2cfdc'),
    (20, 'CAN-1', '1767225600.020000000', None, 16, 16,
     '20000008080000000000040000000000'),
    (21, 'CAN-4', '1767225600.021000000', None, 12, 12,
     '9ffffff00400000054616e7b'),
    (22, 'FR-2', '1767225600.022000000', 1, 17, 13,
     '010020070a00415b6875828f9c'),
    (23, 'CAN-2', '1767225600.023000000', 2, 8, 8,
     'c01abcde00000000'),
    (24, 'ETH-2', '1767225600.024000000', 1, 318, 318,
     'sha256:fa9b88af2d1ea6ac'),
    (25, 'LIN-1', '1767225600.025000000', 1, 16, 16,
     '0100000082201108697683909daab7c4'),
    (26, 'CAN-1', '1767225600.026000000', None, 16, 16,
     '20000008080000000000000800000000'),
    (27, 'CAN-1', '1767225600.027000000', 1, 8, 8,
     '0000010000000000'),
    (28, 'FR-2', '1767225600.028000000', None, 7, 7,
     '8100186301ffff'),
    (29, 'CAN-1', '1767225600.029000000', None, 16, 16,
     '20000020080000000000000000000000'),
    (30, 'LIN-1', '1767225600.030000000', None, 12, 12,
     '010000004061000100000000'),
    (31, 'ETH-1', '1767225600.031000000', 1, 1514, 1514,
     'sha256:d0680e4926218679'),
    (32, 'LIN-2', '1767225600.032000000', None, 12, 12,
     '010000000080000200000000'),
    (33, 'CAN-1', '1767225600.033000000', 1, 16, 11,
     '000007e008000000778491'),
    (34, 'ETH-1', '1767225600.034000000', 2, 114, 114,
     'sha256:b307213860c74275'),
    (35, 'FR-1', '1767225600.035000000', 1, 9, 9,
     '010027ff0200008592'),
    (36, 'CAN-4', '1767225600.036000000', None, 10, 10,
     '000007ff020000008c99'),
    (37, 'CAN-1', '1767225602.500000000', 1, 16, 16,
     '000004560800000093a0adbac7d4e1ee'),
    (38, 'LIN-1', '1767225602.501000000', 1, 16, 16,
     '0100000051c1fe009aa7b4c1ce000000'),
]

MDF_COVERAGE = 'mdf_coverage.mf4.gz'


def mdf_packets(cmd_tshark, capture, test_env, *options):
    '''Returns the metadata and the data of the packets of a capture file as
    tuples like those in MDF_PACKETS.'''
    fields = subprocess.check_output((cmd_tshark, *options, '-r', capture, '-Tfields',
            '-eframe.number', '-eframe.interface_name', '-eframe.time_epoch',
            '-eframe.packet_flags_direction', '-eframe.len', '-eframe.cap_len',
        ), encoding='utf-8', env=test_env).splitlines()
    packets = json.loads(subprocess.check_output((cmd_tshark, *options, '-r', capture, '-Tjson', '-x'),
        encoding='utf-8', env=test_env))
    assert len(fields) == len(packets)
    result = []
    for line, packet in zip(fields, packets):
        number, name, epoch, direction, length, caplen = line.split('\t')
        data = packet['_source']['layers']['frame_raw'][0]
        if len(data) > 96:
            data = 'sha256:' + hashlib.sha256(bytes.fromhex(data)).hexdigest()[:16]
        result.append((int(number), name, epoch, int(direction, 16) if direction else None,
                       int(length), int(caplen), data))
    return result


class TestFileFormatMdf:
    def test_mdf_file_type(self, cmd_capinfos, capture_file, test_env):
        '''The file is read by the MDF reader and not shown as MIME file.'''
        stdout = subprocess.check_output((cmd_capinfos, '-t', capture_file(MDF_COVERAGE)),
            encoding='utf-8', env=test_env)
        assert 'File type:           MDF Logfile (gzip compressed)' in stdout

    def test_mdf_packets(self, cmd_tshark, capture_file, test_env):
        '''All packets of all bus types, in time order across the data groups.'''
        assert mdf_packets(cmd_tshark, capture_file(MDF_COVERAGE), test_env) == MDF_PACKETS

    def test_mdf_packets_two_pass(self, cmd_tshark, capture_file, test_env):
        '''Reading the packets again at random gives the same packets.'''
        assert mdf_packets(cmd_tshark, capture_file(MDF_COVERAGE), test_env, '-2') == MDF_PACKETS

    def test_mdf_interfaces(self, cmd_tshark, capture_file, test_env):
        '''One interface per bus type and bus channel, numbered in the order of the first packet.'''
        stdout = subprocess.check_output((cmd_tshark, '-r', capture_file(MDF_COVERAGE),
                '-Tfields', '-eframe.interface_id', '-eframe.interface_name',
            ), encoding='utf-8', env=test_env)
        names = []
        for line in stdout.splitlines():
            interface_id, name = line.split('\t')
            if name not in names:
                names.append(name)
            assert names.index(name) == int(interface_id)
        assert names == ['CAN-1', 'ETH-1', 'LIN-1', 'FR-1', 'CAN-4', 'CAN-2', 'CAN-3', 'LIN-2', 'FR-2', 'ETH-2']

    def test_mdf_can(self, cmd_tshark, capture_file, test_env):
        '''CAN IDs, remote and error frames, and the CAN FD flags.'''
        stdout = subprocess.check_output((cmd_tshark, '-r', capture_file(MDF_COVERAGE),
                '-Y', 'can || canfd', '-Tfields',
                '-eframe.number', '-e_ws.col.protocol', '-ecan.id', '-ecan.flags.xtd',
                '-ecan.flags.rtr', '-ecan.flags.err', '-ecanfd.flags.brs', '-ecanfd.flags.esi',
            ), encoding='utf-8', env=test_env)
        rows = {int(line.split('\t')[0]): line.split('\t') for line in stdout.splitlines()}
        assert len(rows) == 19
        # standard and extended data frames, with and without the IDE bit
        assert rows[1][1:5] == ['CAN', '291', 'False', 'False']
        assert rows[5][1:5] == ['CAN', str(0x1ABCDEF0), 'True', 'False']
        assert rows[21][1:5] == ['CAN', str(0x1FFFFFF0), 'True', 'False']
        # remote frames
        assert rows[6][1:5] == ['CAN', '85', 'False', 'True']
        assert rows[23][1:5] == ['CAN', str(0x1ABCDE), 'True', 'True']
        # CAN FD, bit rate switch and error state indicator
        assert rows[13][1:3] == ['CANFD', '2047'] and rows[13][6:8] == ['True', 'False']
        assert rows[19][1:3] == ['CANFD', str(0x1234)] and rows[19][6:8] == ['False', 'True']
        # error frames: the six error types and the overload frame
        assert [n for n, row in rows.items() if row[5] == 'True'] == [7, 8, 14, 15, 20, 26, 29]

    def test_mdf_lin(self, cmd_tshark, capture_file, test_env):
        '''LIN frames with their protected ID, checksum type and error flags.'''
        stdout = subprocess.check_output((cmd_tshark, '-r', capture_file(MDF_COVERAGE),
                '-Y', 'lin', '-Tfields',
                '-eframe.number', '-elin.frame_id', '-elin.protected_id', '-elin.frame_parity',
                '-elin.checksum_type', '-elin.errors',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '3\t0x0b\t0x8b\t0x02\t2\t0x00',    # enhanced checksum
            '11\t0x2a\t0x6a\t0x01\t1\t0x00',    # classic checksum
            '18\t0x10\t0x50\t0x01\t0\t0x00',    # unknown checksum model
            '25\t0x20\t0x20\t0x00\t2\t0x08',    # checksum error
            '30\t0x21\t0x61\t0x01\t0\t0x01',    # no slave response
            '32\t0x00\t0x80\t0x02\t0\t0x02',    # receive error without ID
            '38\t0x01\t0xc1\t0x03\t1\t0x00',    # classic checksum, 5 bytes
        ]

    def test_mdf_flexray(self, cmd_tshark, capture_file, test_env):
        '''FlexRay frames and null frames, and a payload that is shorter than its length.'''
        stdout = subprocess.check_output((cmd_tshark, '-r', capture_file(MDF_COVERAGE),
                '-Y', 'flexray', '-Tfields',
                '-eframe.number', '-eflexray.fid', '-eflexray.cc', '-eflexray.ch', '-eflexray.pl',
                '-eflexray.nfi', '-eflexray.sfi', '-eflexray.stfi', '-eflexray.ppi',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '4\t25\t3\tFalse\t4\tTrue\tTrue\tFalse\tFalse',
            '12\t100\t63\tTrue\t8\tTrue\tTrue\tTrue\tTrue',
            '16\t25\t4\tFalse\t2\tFalse\tFalse\tFalse\tFalse',     # null frame
            '22\t7\t1\tFalse\t5\tTrue\tFalse\tFalse\tFalse',
            '28\t99\t63\tTrue\t0\tFalse\tTrue\tTrue\tFalse',      # null frame
            '35\t2047\t0\tFalse\t1\tTrue\tFalse\tFalse\tFalse',
        ]
        stdout = subprocess.check_output((cmd_tshark, '-r', capture_file(MDF_COVERAGE),
                '-Y', '_ws.malformed || _ws.expert.severity >= warning', '-Tfields',
                '-eframe.number', '-e_ws.expert.message',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['22\tTruncated Frame Payload']

    def test_mdf_ethernet(self, cmd_tshark, capture_file, test_env):
        '''Ethernet frames with a VLAN tag, without payload and with a jumbo payload.'''
        stdout = subprocess.check_output((cmd_tshark, '-r', capture_file(MDF_COVERAGE),
                '-Y', 'eth', '-Tfields',
                '-eframe.number', '-eeth.dst', '-eeth.src', '-eeth.type', '-eframe.len',
            ), encoding='utf-8', env=test_env)
        rows = [line.split('\t') for line in stdout.splitlines()]
        assert [row[0] for row in rows] == ['2', '10', '17', '24', '31', '34']
        assert rows[0][1:] == ['02:00:00:00:00:02', '02:00:00:00:00:01', '0x88b5', '60']
        assert rows[1][1] == 'ff:ff:ff:ff:ff:ff'
        assert rows[2][4] == '14'                       # the payload is empty
        assert rows[3][3] == '0x8100'                   # VLAN tagged
        assert rows[4][4] == str(14 + 1500)

    def test_mdf_no_bus_logging(self, cmd_tshark, result_file, capture_file, test_env):
        '''Files without bus logging data are reported as not supported.'''
        with gzip.open(capture_file(MDF_COVERAGE), 'rb') as fh:
            contents = bytearray(fh.read())
        struct.pack_into('<Q', contents, 64 + 24, 0)    # no data groups
        path = result_file('no-data-groups.mf4')
        with open(path, 'wb') as fh:
            fh.write(contents)
        proc = subprocess.run((cmd_tshark, '-r', path), capture_output=True, encoding='utf-8', env=test_env)
        assert proc.returncode != 0
        assert 'no bus logging data' in proc.stderr

    def test_mdf_not_readable(self, cmd_tshark, cmd_capinfos, result_file, capture_file, test_env):
        '''Files the reader cannot read are handed on to the MDF dissector.'''
        name = 'unfinalized'
        with gzip.open(capture_file(MDF_COVERAGE), 'rb') as fh:
            contents = bytearray(fh.read())
        contents[60] = 1
        path = result_file(name + '.mf4')
        with open(path, 'wb') as fh:
            fh.write(contents)
        stdout = subprocess.check_output((cmd_capinfos, '-t', path), encoding='utf-8', env=test_env)
        assert 'File type:           MIME File Format' in stdout
        stdout = subprocess.check_output((cmd_tshark, '-r', path, '-Tfields', '-eframe.protocols'),
            encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['mime_dlt:file-mdf']

    def test_mdf_damaged(self, cmd_tshark, result_file, capture_file, test_env):
        '''Truncated and damaged files do not crash the reader.'''
        with gzip.open(capture_file(MDF_COVERAGE), 'rb') as fh:
            contents = fh.read()
        variants = [contents[:size] for size in (0, 7, 64, 100, 200, 1000, 5000, 15000, len(contents) - 1)]
        for seed in range(40):
            damaged = bytearray(contents)
            for i in range(1 + seed % 8):
                position = (seed * 7919 + i * 104729) % (4096 if i % 2 else len(damaged))
                damaged[position] ^= 0x55 + seed
            variants.append(bytes(damaged))
        path = result_file('damaged.mf4')
        for variant in variants:
            with open(path, 'wb') as fh:
                fh.write(variant)
            for options in ((), ('-2',)):
                proc = subprocess.run((cmd_tshark, *options, '-r', path, '-Tfields', '-eframe.number'),
                    capture_output=True, encoding='utf-8', env=test_env, timeout=60)
                # tshark reports files it cannot read with a return code,
                # a negative one means that it was killed by a signal
                assert 0 <= proc.returncode < 128, proc.stderr
