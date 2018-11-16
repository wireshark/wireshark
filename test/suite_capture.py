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

import glob
import os
import subprocess
import subprocesstest
import sys
import time
import uuid
import fixtures

capture_duration = 5

testout_pcap = 'testout.pcap'
snapshot_len = 96

@fixtures.fixture
def traffic_generator():
    '''
    Traffic generator factory. Invoking it returns a tuple (start_func, cfilter)
    where cfilter is a capture filter to match the generated traffic.
    start_func can be invoked to start generating traffic and returns a function
    which can be used to stop traffic generation early.
    Currently calls ping www.wireshark.org for 60 seconds.
    '''
    # XXX replace this by something that generates UDP traffic to localhost?
    # That would avoid external access which is forbidden by the Debian policy.
    nprocs = 1
    if sys.platform.startswith('win32'):
        # XXX Check for psping? https://docs.microsoft.com/en-us/sysinternals/downloads/psping
        args_ping = ('ping', '-n', '60', '-l', '100', 'www.wireshark.org')
        nprocs = 3
    elif sys.platform.startswith('linux') or sys.platform.startswith('freebsd'):
        args_ping = ('ping', '-c', '240', '-s', '100', '-i', '0.25', 'www.wireshark.org')
    elif sys.platform.startswith('darwin'):
        args_ping = ('ping', '-c', '1', '-g', '1', '-G', '240', '-i', '0.25', 'www.wireshark.org')
    else:
        # XXX Other BSDs, Solaris, etc
        fixtures.skip('ping utility is unavailable - cannot generate traffic')
    procs = []
    def kill_processes():
        for proc in procs:
            proc.kill()
        for proc in procs:
            proc.wait()
        procs.clear()
    def start_processes():
        for i in range(nprocs):
            if i > 0:
                # Fake subsecond interval if the ping utility lacks support.
                time.sleep(0.1)
            proc = subprocess.Popen(args_ping, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            procs.append(proc)
        return kill_processes
    try:
        yield start_processes, 'icmp || icmp6'
    finally:
        kill_processes()


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
        if (capture_returncode == 0):
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
        capture_proc = self.runProcess(capture_command(cmd,
            '-i', fifo_file,
            '-p',
            '-w', testout_file,
            '-a', 'duration:{}'.format(capture_duration),
        ))
        fifo_proc.kill()
        self.assertTrue(os.path.isfile(testout_file))
        capture_returncode = capture_proc.returncode
        self.assertEqual(capture_returncode, 0)
        if (capture_returncode == 0):
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
        pipe_proc = self.runProcess(slow_dhcp_cmd + ' | ' + capture_cmd, shell=True)
        pipe_returncode = pipe_proc.returncode
        self.assertEqual(pipe_returncode, 0)
        if is_gui:
            self.assertTrue(self.grepOutput('Wireshark is up and ready to go'), 'No startup message.')
            self.assertTrue(self.grepOutput('Capture started'), 'No capture start message.')
            self.assertTrue(self.grepOutput('Capture stopped'), 'No capture stop message.')
        self.assertTrue(os.path.isfile(testout_file))
        if (pipe_returncode == 0):
            self.checkPacketCount(8)
    return check_capture_stdin_real


@fixtures.fixture
def check_capture_read_filter(capture_interface, traffic_generator):
    start_traffic, cfilter = traffic_generator
    def check_capture_read_filter_real(self, cmd=None):
        self.assertIsNotNone(cmd)
        testout_file = self.filename_from_id(testout_pcap)
        stop_traffic = start_traffic()
        capture_proc = self.runProcess(capture_command(cmd,
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
        capture_returncode = capture_proc.returncode
        self.assertEqual(capture_returncode, 0)

        if (capture_returncode == 0):
            self.checkPacketCount(0)
    return check_capture_read_filter_real

@fixtures.fixture
def check_capture_snapshot_len(capture_interface, cmd_tshark, traffic_generator):
    start_traffic, cfilter = traffic_generator
    def check_capture_snapshot_len_real(self, cmd=None):
        self.assertIsNotNone(cmd)
        stop_traffic = start_traffic()
        testout_file = self.filename_from_id(testout_pcap)
        capture_proc = self.runProcess(capture_command(cmd,
            '-i', capture_interface,
            '-p',
            '-w', testout_file,
            '-s', str(snapshot_len),
            '-a', 'duration:{}'.format(capture_duration),
            '-f', cfilter,
        ))
        stop_traffic()
        capture_returncode = capture_proc.returncode
        self.assertEqual(capture_returncode, 0)
        self.assertTrue(os.path.isfile(testout_file))

        # Use tshark to filter out all packets larger than 68 bytes.
        testout2_file = self.filename_from_id('testout2.pcap')

        filter_proc = self.runProcess((cmd_tshark,
            '-r', testout_file,
            '-w', testout2_file,
            '-Y', 'frame.cap_len>{}'.format(snapshot_len),
        ))
        filter_returncode = filter_proc.returncode
        self.assertEqual(capture_returncode, 0)
        if (capture_returncode == 0):
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
        pipe_proc = self.runProcess(cat100_dhcp_cmd + ' | ' + capture_cmd, shell=True)
        pipe_returncode = pipe_proc.returncode
        self.assertEqual(pipe_returncode, 0)
        self.assertTrue(os.path.isfile(testout_file))
        if (pipe_returncode != 0):
            return

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
        pipe_proc = self.runProcess(cat100_dhcp_cmd + ' | ' + capture_cmd, shell=True)
        pipe_returncode = pipe_proc.returncode
        self.assertEqual(pipe_returncode, 0)
        if (pipe_returncode != 0):
            return

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


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_wireshark_capture(subprocesstest.SubprocessTestCase):
    def test_wireshark_capture_10_packets_to_file(self, wireshark_k, check_capture_10_packets):
        '''Capture 10 packets from the network to a file using Wireshark'''
        check_capture_10_packets(self, cmd=wireshark_k)

    # Wireshark doesn't currently support writing to stdout while capturing.
    # def test_wireshark_capture_10_packets_to_stdout(self, wireshark_k, check_capture_10_packets):
    #     '''Capture 10 packets from the network to stdout using Wireshark'''
    #     check_capture_10_packets(self, cmd=wireshark_k, to_stdout=True)

    def test_wireshark_capture_from_fifo(self, wireshark_k, check_capture_fifo):
        '''Capture from a fifo using Wireshark'''
        check_capture_fifo(self, cmd=wireshark_k)

    def test_wireshark_capture_from_stdin(self, wireshark_k, check_capture_stdin):
        '''Capture from stdin using Wireshark'''
        check_capture_stdin(self, cmd=wireshark_k)

    def test_wireshark_capture_snapshot_len(self, wireshark_k, check_capture_snapshot_len):
        '''Capture truncated packets using Wireshark'''
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
    # Need a function that finds ringbuffer file names.
    def test_dumpcap_ringbuffer_filesize(self, check_dumpcap_ringbuffer_stdin):
        '''Capture from stdin using Dumpcap and write multiple files until we reach a file size limit'''
        check_dumpcap_ringbuffer_stdin(self, filesize=15)

    def test_dumpcap_ringbuffer_packets(self, check_dumpcap_ringbuffer_stdin):
        '''Capture from stdin using Dumpcap and write multiple files until we reach a packet limit'''
        check_dumpcap_ringbuffer_stdin(self, packets=47) # Last prime before 50. Arbitrary.
