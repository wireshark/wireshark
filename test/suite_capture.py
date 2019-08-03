#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Capture tests'''

import fixtures
import glob
import hashlib
import os
import socket
import subprocess
import subprocesstest
import sys
import threading
import time
import uuid

capture_duration = 5

testout_pcap = 'testout.pcap'
testout_pcapng = 'testout.pcapng'
snapshot_len = 96

class UdpTrafficGenerator(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stopped = False

    def run(self):
        while not self.stopped:
            time.sleep(.05)
            self.sock.sendto(b'Wireshark test\n', ('127.0.0.1', 9))

    def stop(self):
        if not self.stopped:
            self.stopped = True
            self.join()


@fixtures.fixture
def traffic_generator():
    '''
    Traffic generator factory. Invoking it returns a tuple (start_func, cfilter)
    where cfilter is a capture filter to match the generated traffic.
    start_func can be invoked to start generating traffic and returns a function
    which can be used to stop traffic generation early.
    Currently generates a bunch of UDP traffic to localhost.
    '''
    threads = []
    def start_processes():
        thread = UdpTrafficGenerator()
        thread.start()
        threads.append(thread)
        return thread.stop
    try:
        yield start_processes, 'udp port 9'
    finally:
        for thread in threads:
            thread.stop()


@fixtures.fixture(scope='session')
def wireshark_k(wireshark_command):
    return tuple(list(wireshark_command) + ['-k'])


def capture_command(*cmd_args, shell=False):
    if type(cmd_args[0]) != str:
        # Assume something like ['wireshark', '-k']
        cmd_args = list(cmd_args[0]) + list(cmd_args)[1:]
    if shell:
        cmd_args = ' '.join(cmd_args)
    return cmd_args


@fixtures.fixture
def check_capture_10_packets(capture_interface, cmd_dumpcap, traffic_generator):
    start_traffic, cfilter = traffic_generator
    def check_capture_10_packets_real(self, cmd=None, to_stdout=False):
        self.assertIsNotNone(cmd)
        testout_file = self.filename_from_id(testout_pcap)
        stop_traffic = start_traffic()
        if to_stdout:
            capture_proc = self.runProcess(capture_command(cmd,
                '-i', '"{}"'.format(capture_interface),
                '-p',
                '-w', '-',
                '-c', '10',
                '-a', 'duration:{}'.format(capture_duration),
                '-f', '"{}"'.format(cfilter),
                '>', testout_file,
                shell=True
            ),
            shell=True
            )
        else:
            capture_proc = self.runProcess(capture_command(cmd,
                '-i', capture_interface,
                '-p',
                '-w', testout_file,
                '-c', '10',
                '-a', 'duration:{}'.format(capture_duration),
                '-f', cfilter,
            ))
        stop_traffic()
        capture_returncode = capture_proc.returncode
        if capture_returncode != 0:
            self.log_fd.write('{} -D output:\n'.format(cmd))
            self.runProcess((cmd, '-D'))
        self.assertEqual(capture_returncode, 0)
        self.checkPacketCount(10)
    return check_capture_10_packets_real


@fixtures.fixture
def check_capture_fifo(cmd_dumpcap):
    if sys.platform == 'win32':
        fixtures.skip('Test requires OS fifo support.')

    def check_capture_fifo_real(self, cmd=None):
        self.assertIsNotNone(cmd)
        testout_file = self.filename_from_id(testout_pcap)
        fifo_file = self.filename_from_id('testout.fifo')
        try:
            # If a previous test left its fifo laying around, e.g. from a failure, remove it.
            os.unlink(fifo_file)
        except:
            pass
        os.mkfifo(fifo_file)
        slow_dhcp_cmd = subprocesstest.cat_dhcp_command('slow')
        fifo_proc = self.startProcess(
            ('{0} > {1}'.format(slow_dhcp_cmd, fifo_file)),
            shell=True)
        capture_proc = self.assertRun(capture_command(cmd,
            '-i', fifo_file,
            '-p',
            '-w', testout_file,
            '-a', 'duration:{}'.format(capture_duration),
        ))
        fifo_proc.kill()
        self.assertTrue(os.path.isfile(testout_file))
        self.checkPacketCount(8)
    return check_capture_fifo_real


@fixtures.fixture
def check_capture_stdin(cmd_dumpcap):
    # Capturing always requires dumpcap, hence the dependency on it.
    def check_capture_stdin_real(self, cmd=None):
        # Similar to suite_io.check_io_4_packets.
        self.assertIsNotNone(cmd)
        testout_file = self.filename_from_id(testout_pcap)
        slow_dhcp_cmd = subprocesstest.cat_dhcp_command('slow')
        capture_cmd = capture_command(cmd,
            '-i', '-',
            '-w', testout_file,
            '-a', 'duration:{}'.format(capture_duration),
            shell=True
        )
        is_gui = type(cmd) != str and '-k' in cmd[0]
        if is_gui:
            capture_cmd += ' -o console.log.level:127'
        pipe_proc = self.assertRun(slow_dhcp_cmd + ' | ' + capture_cmd, shell=True)
        if is_gui:
            self.assertTrue(self.grepOutput('Wireshark is up and ready to go'), 'No startup message.')
            self.assertTrue(self.grepOutput('Capture started'), 'No capture start message.')
            self.assertTrue(self.grepOutput('Capture stopped'), 'No capture stop message.')
        self.assertTrue(os.path.isfile(testout_file))
        self.checkPacketCount(8)
    return check_capture_stdin_real


@fixtures.fixture
def check_capture_read_filter(capture_interface, traffic_generator):
    start_traffic, cfilter = traffic_generator
    def check_capture_read_filter_real(self, cmd=None):
        self.assertIsNotNone(cmd)
        testout_file = self.filename_from_id(testout_pcap)
        stop_traffic = start_traffic()
        capture_proc = self.assertRun(capture_command(cmd,
            '-i', capture_interface,
            '-p',
            '-w', testout_file,
            '-2',
            '-R', 'dcerpc.cn_call_id==123456', # Something unlikely.
            '-c', '10',
            '-a', 'duration:{}'.format(capture_duration),
            '-f', cfilter,
        ))
        stop_traffic()
        self.checkPacketCount(0)
    return check_capture_read_filter_real

@fixtures.fixture
def check_capture_snapshot_len(capture_interface, cmd_tshark, traffic_generator):
    start_traffic, cfilter = traffic_generator
    def check_capture_snapshot_len_real(self, cmd=None):
        self.assertIsNotNone(cmd)
        stop_traffic = start_traffic()
        testout_file = self.filename_from_id(testout_pcap)
        capture_proc = self.assertRun(capture_command(cmd,
            '-i', capture_interface,
            '-p',
            '-w', testout_file,
            '-s', str(snapshot_len),
            '-a', 'duration:{}'.format(capture_duration),
            '-f', cfilter,
        ))
        stop_traffic()
        self.assertTrue(os.path.isfile(testout_file))

        # Use tshark to filter out all packets larger than 68 bytes.
        testout2_file = self.filename_from_id('testout2.pcap')

        filter_proc = self.assertRun((cmd_tshark,
            '-r', testout_file,
            '-w', testout2_file,
            '-Y', 'frame.cap_len>{}'.format(snapshot_len),
        ))
        self.checkPacketCount(0, cap_file=testout2_file)
    return check_capture_snapshot_len_real


@fixtures.fixture
def check_dumpcap_autostop_stdin(cmd_dumpcap):
    def check_dumpcap_autostop_stdin_real(self, packets=None, filesize=None):
        # Similar to check_capture_stdin.
        testout_file = self.filename_from_id(testout_pcap)
        cat100_dhcp_cmd = subprocesstest.cat_dhcp_command('cat100')
        condition='oops:invalid'

        self.assertTrue(packets is not None or filesize is not None, 'Need one of packets or filesize')
        self.assertFalse(packets is not None and filesize is not None, 'Need one of packets or filesize')

        if packets is not None:
            condition = 'packets:{}'.format(packets)
        elif filesize is not None:
            condition = 'filesize:{}'.format(filesize)

        capture_cmd = ' '.join((cmd_dumpcap,
            '-i', '-',
            '-w', testout_file,
            '-a', condition,
        ))
        pipe_proc = self.assertRun(cat100_dhcp_cmd + ' | ' + capture_cmd, shell=True)
        self.assertTrue(os.path.isfile(testout_file))

        if packets is not None:
            self.checkPacketCount(packets)
        elif filesize is not None:
            capturekb = os.path.getsize(testout_file) / 1000
            self.assertGreaterEqual(capturekb, filesize)
    return check_dumpcap_autostop_stdin_real


@fixtures.fixture
def check_dumpcap_ringbuffer_stdin(cmd_dumpcap):
    def check_dumpcap_ringbuffer_stdin_real(self, packets=None, filesize=None):
        # Similar to check_capture_stdin.
        rb_unique = 'dhcp_rb_' + uuid.uuid4().hex[:6] # Random ID
        testout_file = '{}.{}.pcapng'.format(self.id(), rb_unique)
        testout_glob = '{}.{}_*.pcapng'.format(self.id(), rb_unique)
        cat100_dhcp_cmd = subprocesstest.cat_dhcp_command('cat100')
        condition='oops:invalid'

        self.assertTrue(packets is not None or filesize is not None, 'Need one of packets or filesize')
        self.assertFalse(packets is not None and filesize is not None, 'Need one of packets or filesize')

        if packets is not None:
            condition = 'packets:{}'.format(packets)
        elif filesize is not None:
            condition = 'filesize:{}'.format(filesize)

        capture_cmd = ' '.join((cmd_dumpcap,
            '-i', '-',
            '-w', testout_file,
            '-a', 'files:2',
            '-b', condition,
        ))
        pipe_proc = self.assertRun(cat100_dhcp_cmd + ' | ' + capture_cmd, shell=True)

        rb_files = glob.glob(testout_glob)
        for rbf in rb_files:
            self.cleanup_files.append(rbf)

        self.assertEqual(len(rb_files), 2)

        for rbf in rb_files:
            self.assertTrue(os.path.isfile(rbf))
            if packets is not None:
                self.checkPacketCount(packets, cap_file=rbf)
            elif filesize is not None:
                capturekb = os.path.getsize(rbf) / 1000
                self.assertGreaterEqual(capturekb, filesize)
    return check_dumpcap_ringbuffer_stdin_real


@fixtures.fixture
def check_dumpcap_pcapng_sections(cmd_dumpcap, cmd_tshark, capture_file):
    if sys.platform == 'win32':
        fixtures.skip('Test requires OS fifo support.')
    def check_dumpcap_pcapng_sections_real(self, multi_input=False, multi_output=False):
        # Make sure we always test multiple SHBs in an input.
        in_files_l = [ [
            capture_file('many_interfaces.pcapng.1'),
            capture_file('many_interfaces.pcapng.2')
            ] ]
        if multi_input:
            in_files_l.append([ capture_file('many_interfaces.pcapng.3') ])
        fifo_files = []
        fifo_procs = []
        # Default values for our validity tests
        check_val_d = {
            'filename': None,
            'packet_count': 0,
            'idb_count': 0,
            'ua_pt1_count': 0,
            'ua_pt2_count': 0,
            'ua_pt3_count': 0,
            'ua_dc_count': 0,
        }
        check_vals = [ check_val_d ]

        for in_files in in_files_l:
            fifo_file = self.filename_from_id('dumpcap_pcapng_sections_{}.fifo'.format(len(fifo_files) + 1))
            fifo_files.append(fifo_file)
            # If a previous test left its fifo laying around, e.g. from a failure, remove it.
            try:
                os.unlink(fifo_file)
            except: pass
            os.mkfifo(fifo_file)
            cat_cmd = subprocesstest.cat_cap_file_command(in_files)
            fifo_procs.append(self.startProcess(('{0} > {1}'.format(cat_cmd, fifo_file)), shell=True))

        if multi_output:
            rb_unique = 'sections_rb_' + uuid.uuid4().hex[:6] # Random ID
            testout_glob = '{}.{}_*.pcapng'.format(self.id(), rb_unique)
            testout_file = '{}.{}.pcapng'.format(self.id(), rb_unique)
            check_vals.append(check_val_d.copy())
            # check_vals[]['filename'] will be filled in below
        else:
            testout_file = self.filename_from_id(testout_pcapng)
            check_vals[0]['filename'] = testout_file

        # Capture commands
        if not multi_input and not multi_output:
            # Passthrough SHBs, single output file
            capture_cmd_args = (
                '-i', fifo_files[0],
                '-w', testout_file
            )
            check_vals[0]['packet_count'] = 79
            check_vals[0]['idb_count'] = 22
            check_vals[0]['ua_pt1_count'] = 1
            check_vals[0]['ua_pt2_count'] = 1
        elif not multi_input and multi_output:
            # Passthrough SHBs, multiple output files
            capture_cmd_args = (
                '-i', fifo_files[0],
                '-w', testout_file,
                '-a', 'files:2',
                '-b', 'packets:53'
            )
            check_vals[0]['packet_count'] = 53
            check_vals[0]['idb_count'] = 11
            check_vals[0]['ua_pt1_count'] = 1
            check_vals[1]['packet_count'] = 26
            check_vals[1]['idb_count'] = 22
            check_vals[1]['ua_pt1_count'] = 1
            check_vals[1]['ua_pt2_count'] = 1
        elif multi_input and not multi_output:
            # Dumpcap SHBs, single output file
            capture_cmd_args = (
                '-i', fifo_files[0],
                '-i', fifo_files[1],
                '-w', testout_file
            )
            check_vals[0]['packet_count'] = 88
            check_vals[0]['idb_count'] = 35
            check_vals[0]['ua_dc_count'] = 1
        else:
            # Dumpcap SHBs, multiple output files
            capture_cmd_args = (
                '-i', fifo_files[0],
                '-i', fifo_files[1],
                '-w', testout_file,
                '-a', 'files:2',
                '-b', 'packets:53'
            )
            check_vals[0]['packet_count'] = 53
            check_vals[0]['idb_count'] = 13
            check_vals[0]['ua_dc_count'] = 1
            check_vals[1]['packet_count'] = 35
            check_vals[1]['idb_count'] = 35
            check_vals[1]['ua_dc_count'] = 1

        capture_cmd = capture_command(cmd_dumpcap, *capture_cmd_args)

        capture_proc = self.assertRun(capture_cmd)
        for fifo_proc in fifo_procs: fifo_proc.kill()

        rb_files = []
        if multi_output:
            rb_files = sorted(glob.glob(testout_glob))
            self.assertEqual(len(rb_files), 2)
            check_vals[0]['filename'] = rb_files[0]
            check_vals[1]['filename'] = rb_files[1]

        for rbf in rb_files:
            self.cleanup_files.append(rbf)
            self.assertTrue(os.path.isfile(rbf))

        # Output tests

        if not multi_input and not multi_output:
            # Check strict bit-for-bit passthrough.
            in_hash = hashlib.sha256()
            out_hash = hashlib.sha256()
            for in_file in in_files_l[0]:
                in_cap_file = capture_file(in_file)
                with open(in_cap_file, 'rb') as f:
                    in_hash.update(f.read())
            with open(testout_file, 'rb') as f:
                out_hash.update(f.read())
            self.assertEqual(in_hash.hexdigest(), out_hash.hexdigest())

        # many_interfaces.pcapng.1 : 64 packets written by "Passthrough test #1"
        # many_interfaces.pcapng.2 : 15 packets written by "Passthrough test #2"
        # many_interfaces.pcapng.3 : 9 packets written by "Passthrough test #3"
        # Each has 11 interfaces.
        idb_compare_eq = True
        if multi_input and multi_output:
            # Having multiple inputs forces the use of threads. In our
            # case this means that non-packet block counts in the first
            # file in is nondeterministic.
            idb_compare_eq = False
        for check_val in check_vals:
            self.checkPacketCount(check_val['packet_count'], cap_file=check_val['filename'])

            tshark_proc = self.assertRun(capture_command(cmd_tshark,
                '-r', check_val['filename'],
                '-V',
                '-X', 'read_format:MIME Files Format'
            ))
            # XXX Are there any other sanity checks we should run?
            if idb_compare_eq:
                self.assertEqual(self.countOutput(r'Block: Interface Description Block',
                    proc=tshark_proc), check_val['idb_count'])
            else:
                self.assertGreaterEqual(self.countOutput(r'Block: Interface Description Block',
                    proc=tshark_proc), check_val['idb_count'])
                idb_compare_eq = True
            self.assertEqual(self.countOutput(r'Option: User Application = Passthrough test #1',
                proc=tshark_proc), check_val['ua_pt1_count'])
            self.assertEqual(self.countOutput(r'Option: User Application = Passthrough test #2',
                proc=tshark_proc), check_val['ua_pt2_count'])
            self.assertEqual(self.countOutput(r'Option: User Application = Passthrough test #3',
                proc=tshark_proc), check_val['ua_pt3_count'])
            self.assertEqual(self.countOutput(r'Option: User Application = Dumpcap \(Wireshark\)',
                proc=tshark_proc), check_val['ua_dc_count'])
    return check_dumpcap_pcapng_sections_real


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_wireshark_capture(subprocesstest.SubprocessTestCase):
    def test_wireshark_capture_10_packets_to_file(self, wireshark_k, check_capture_10_packets, make_screenshot_on_error):
        '''Capture 10 packets from the network to a file using Wireshark'''
        with make_screenshot_on_error():
            check_capture_10_packets(self, cmd=wireshark_k)

    # Wireshark doesn't currently support writing to stdout while capturing.
    # def test_wireshark_capture_10_packets_to_stdout(self, wireshark_k, check_capture_10_packets):
    #     '''Capture 10 packets from the network to stdout using Wireshark'''
    #     check_capture_10_packets(self, cmd=wireshark_k, to_stdout=True)

    def test_wireshark_capture_from_fifo(self, wireshark_k, check_capture_fifo, make_screenshot_on_error):
        '''Capture from a fifo using Wireshark'''
        with make_screenshot_on_error():
            check_capture_fifo(self, cmd=wireshark_k)

    def test_wireshark_capture_from_stdin(self, wireshark_k, check_capture_stdin, make_screenshot_on_error):
        '''Capture from stdin using Wireshark'''
        with make_screenshot_on_error():
            check_capture_stdin(self, cmd=wireshark_k)

    def test_wireshark_capture_snapshot_len(self, wireshark_k, check_capture_snapshot_len, make_screenshot_on_error):
        '''Capture truncated packets using Wireshark'''
        with make_screenshot_on_error():
            check_capture_snapshot_len(self, cmd=wireshark_k)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_tshark_capture(subprocesstest.SubprocessTestCase):
    def test_tshark_capture_10_packets_to_file(self, cmd_tshark, check_capture_10_packets):
        '''Capture 10 packets from the network to a file using TShark'''
        check_capture_10_packets(self, cmd=cmd_tshark)

    def test_tshark_capture_10_packets_to_stdout(self, cmd_tshark, check_capture_10_packets):
        '''Capture 10 packets from the network to stdout using TShark'''
        check_capture_10_packets(self, cmd=cmd_tshark, to_stdout=True)

    def test_tshark_capture_from_fifo(self, cmd_tshark, check_capture_fifo):
        '''Capture from a fifo using TShark'''
        check_capture_fifo(self, cmd=cmd_tshark)

    def test_tshark_capture_from_stdin(self, cmd_tshark, check_capture_stdin):
        '''Capture from stdin using TShark'''
        check_capture_stdin(self, cmd=cmd_tshark)

    def test_tshark_capture_snapshot_len(self, cmd_tshark, check_capture_snapshot_len):
        '''Capture truncated packets using TShark'''
        check_capture_snapshot_len(self, cmd=cmd_tshark)


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_dumpcap_capture(subprocesstest.SubprocessTestCase):
    def test_dumpcap_capture_10_packets_to_file(self, cmd_dumpcap, check_capture_10_packets):
        '''Capture 10 packets from the network to a file using Dumpcap'''
        check_capture_10_packets(self, cmd=cmd_dumpcap)

    def test_dumpcap_capture_10_packets_to_stdout(self, cmd_dumpcap, check_capture_10_packets):
        '''Capture 10 packets from the network to stdout using Dumpcap'''
        check_capture_10_packets(self, cmd=cmd_dumpcap, to_stdout=True)

    def test_dumpcap_capture_from_fifo(self, cmd_dumpcap, check_capture_fifo):
        '''Capture from a fifo using Dumpcap'''
        check_capture_fifo(self, cmd=cmd_dumpcap)

    def test_dumpcap_capture_from_stdin(self, cmd_dumpcap, check_capture_stdin):
        '''Capture from stdin using Dumpcap'''
        check_capture_stdin(self, cmd=cmd_dumpcap)

    def test_dumpcap_capture_snapshot_len(self, check_capture_snapshot_len, cmd_dumpcap):
        '''Capture truncated packets using Dumpcap'''
        check_capture_snapshot_len(self, cmd=cmd_dumpcap)


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_dumpcap_autostop(subprocesstest.SubprocessTestCase):
    # duration, filesize, packets, files
    def test_dumpcap_autostop_filesize(self, check_dumpcap_autostop_stdin):
        '''Capture from stdin using Dumpcap until we reach a file size limit'''
        check_dumpcap_autostop_stdin(self, filesize=15)

    def test_dumpcap_autostop_packets(self, check_dumpcap_autostop_stdin):
        '''Capture from stdin using Dumpcap until we reach a packet limit'''
        check_dumpcap_autostop_stdin(self, packets=97) # Last prime before 100. Arbitrary.


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_dumpcap_ringbuffer(subprocesstest.SubprocessTestCase):
    # duration, interval, filesize, packets, files
    def test_dumpcap_ringbuffer_filesize(self, check_dumpcap_ringbuffer_stdin):
        '''Capture from stdin using Dumpcap and write multiple files until we reach a file size limit'''
        check_dumpcap_ringbuffer_stdin(self, filesize=15)

    def test_dumpcap_ringbuffer_packets(self, check_dumpcap_ringbuffer_stdin):
        '''Capture from stdin using Dumpcap and write multiple files until we reach a packet limit'''
        check_dumpcap_ringbuffer_stdin(self, packets=47) # Last prime before 50. Arbitrary.


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_dumpcap_pcapng_sections(subprocesstest.SubprocessTestCase):
    def test_dumpcap_pcapng_single_in_single_out(self, check_dumpcap_pcapng_sections):
        '''Capture from a single pcapng source using Dumpcap and write a single file'''
        if sys.byteorder == 'big':
            fixtures.skip('this test is supported on little endian only')
        check_dumpcap_pcapng_sections(self)

    def test_dumpcap_pcapng_single_in_multi_out(self, check_dumpcap_pcapng_sections):
        '''Capture from a single pcapng source using Dumpcap and write two files'''
        if sys.byteorder == 'big':
            fixtures.skip('this test is supported on little endian only')
        check_dumpcap_pcapng_sections(self, multi_output=True)

    def test_dumpcap_pcapng_multi_in_single_out(self, check_dumpcap_pcapng_sections):
        '''Capture from two pcapng sources using Dumpcap and write a single file'''
        if sys.byteorder == 'big':
            fixtures.skip('this test is supported on little endian only')
        check_dumpcap_pcapng_sections(self, multi_input=True)

    def test_dumpcap_pcapng_multi_in_multi_out(self, check_dumpcap_pcapng_sections):
        '''Capture from two pcapng sources using Dumpcap and write two files'''
        if sys.byteorder == 'big':
            fixtures.skip('this test is supported on little endian only')
        check_dumpcap_pcapng_sections(self, multi_input=True, multi_output=True)
