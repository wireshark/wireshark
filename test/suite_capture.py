#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Capture tests'''

import config
import os
import re
import subprocess
import subprocesstest
import sys
import time
import unittest

capture_duration = 5

testout_pcap = 'testout.pcap'
snapshot_len = 96
capture_env = os.environ.copy()
capture_env['WIRESHARK_QUIT_AFTER_CAPTURE'] = 'True'

def capture_command(cmd, *args, **kwargs):
    shell = kwargs.pop('shell', False)
    if shell:
        cap_cmd = ['"' + cmd + '"']
    else:
        cap_cmd = [cmd]
    if cmd == config.cmd_wireshark:
        cap_cmd += ('-o', 'gui.update.enabled:FALSE', '-k')
    cap_cmd += args
    if shell:
        return ' '.join(cap_cmd)
    else:
        return cap_cmd

def slow_dhcp_command():
    # XXX Do this in Python in a thread?
    sd_cmd = ''
    if sys.executable:
        sd_cmd = '"{}" '.format(sys.executable)
    sd_cmd += os.path.join(config.this_dir, 'util_slow_dhcp_pcap.py')
    return sd_cmd

def start_pinging(self):
    ping_procs = []
    if sys.platform.startswith('win32'):
        # Fake '-i' with a subsecond interval.
        for st in (0.1, 0.1, 0):
            ping_procs.append(self.startProcess(config.args_ping))
            time.sleep(st)
    else:
        ping_procs.append(self.startProcess(config.args_ping))
    return ping_procs

def stop_pinging(ping_procs):
    for proc in ping_procs:
        proc.kill()

def check_testout_num_packets(self, num_packets, cap_file=None):
    got_num_packets = False
    if not cap_file:
        cap_file = self.filename_from_id(testout_pcap)
    self.log_fd.write(u'\nOutput of {0} {1}:\n'.format(config.cmd_capinfos, cap_file))
    capinfos_testout = str(subprocess.check_output((config.cmd_capinfos, cap_file)))
    self.log_fd_write_bytes(capinfos_testout)
    count_pat = 'Number of packets:\s+{}'.format(num_packets)
    if re.search(count_pat, capinfos_testout):
        got_num_packets = True
    self.assertTrue(got_num_packets, 'Failed to capture exactly {} packets'.format(num_packets))

def check_capture_10_packets(self, cmd=None, to_stdout=False):
    if not config.canCapture():
        self.skipTest('Test requires capture privileges and an interface.')
    if cmd == config.cmd_wireshark and not config.canDisplay():
        self.skipTest('Test requires a display.')
    if not config.args_ping:
        self.skipTest('Your platform ({}) does not have a defined ping command.'.format(sys.platform))
    self.assertIsNotNone(cmd)
    testout_file = self.filename_from_id(testout_pcap)
    ping_procs = start_pinging(self)
    if to_stdout:
        capture_proc = self.runProcess(capture_command(cmd,
            '-i', '"{}"'.format(config.capture_interface),
            '-p',
            '-w', '-',
            '-c', '10',
            '-a', 'duration:{}'.format(capture_duration),
            '-f', '"icmp || icmp6"',
            '>', testout_file,
            shell=True
        ),
        env=capture_env,
        shell=True
        )
    else:
        capture_proc = self.runProcess(capture_command(cmd,
            '-i', config.capture_interface,
            '-p',
            '-w', testout_file,
            '-c', '10',
            '-a', 'duration:{}'.format(capture_duration),
            '-f', 'icmp || icmp6',
        ),
        env=capture_env
        )
    capture_returncode = capture_proc.returncode
    stop_pinging(ping_procs)
    self.cleanup_files.append(testout_file)
    if capture_returncode != 0:
        self.log_fd.write('{} -D output:\n'.format(cmd))
        self.runProcess((cmd, '-D'))
    self.assertEqual(capture_returncode, 0)
    if (capture_returncode == 0):
        check_testout_num_packets(self, 10)

def check_capture_fifo(self, cmd=None):
    if not config.canMkfifo():
        self.skipTest('Test requires OS fifo support.')
    if cmd == config.cmd_wireshark and not config.canDisplay():
        self.skipTest('Test requires a display.')
    self.assertIsNotNone(cmd)
    capture_file = os.path.join(config.capture_dir, 'dhcp.pcap')
    testout_file = self.filename_from_id(testout_pcap)
    fifo_file = self.filename_from_id('testout.fifo')
    self.cleanup_files.append(fifo_file)
    try:
        # If a previous test left its fifo laying around, e.g. from a failure, remove it.
        os.unlink(fifo_file)
    except:
        pass
    os.mkfifo(fifo_file)
    slow_dhcp_cmd = slow_dhcp_command()
    fifo_proc = self.startProcess(
        ('{0} > {1}'.format(slow_dhcp_cmd, fifo_file)),
        shell=True)
    capture_proc = self.runProcess(capture_command(cmd,
        '-i', fifo_file,
        '-p',
        '-w', testout_file,
        '-a', 'duration:{}'.format(capture_duration),
    ),
    env=capture_env
    )
    self.cleanup_files.append(testout_file)
    fifo_proc.kill()
    self.assertTrue(os.path.isfile(testout_file))
    capture_returncode = capture_proc.returncode
    self.assertEqual(capture_returncode, 0)
    if (capture_returncode == 0):
        check_testout_num_packets(self, 8)

def check_capture_stdin(self, cmd=None):
    if cmd == config.cmd_wireshark and not config.canDisplay():
        self.skipTest('Test requires a display.')
    self.assertIsNotNone(cmd)
    capture_file = os.path.join(config.capture_dir, 'dhcp.pcap')
    testout_file = self.filename_from_id(testout_pcap)
    slow_dhcp_cmd = slow_dhcp_command()
    capture_cmd = capture_command(cmd,
        '-i', '-',
        '-w', testout_file,
        '-a', 'duration:{}'.format(capture_duration),
        shell=True
    )
    if cmd == config.cmd_wireshark:
        capture_cmd += ' -o console.log.level:127'
    pipe_proc = self.runProcess(slow_dhcp_cmd + ' | ' + capture_cmd, env=capture_env, shell=True)
    self.cleanup_files.append(testout_file)
    pipe_returncode = pipe_proc.returncode
    self.assertEqual(pipe_returncode, 0)
    if cmd == config.cmd_wireshark:
        self.assertTrue(self.grepOutput('Wireshark is up and ready to go'), 'No startup message.')
        self.assertTrue(self.grepOutput('Capture started'), 'No capture start message.')
        self.assertTrue(self.grepOutput('Capture stopped'), 'No capture stop message.')
    self.assertTrue(os.path.isfile(testout_file))
    if (pipe_returncode == 0):
        check_testout_num_packets(self, 8)

def check_capture_2multi_10packets(self, cmd=None):
    # This was present in the Bash version but was incorrect and not part of any suite.
    # It's apparently intended to test file rotation.
    self.skipTest('Not yet implemented')

def check_capture_read_filter(self, cmd=None):
    if not config.canCapture():
        self.skipTest('Test requires capture privileges and an interface.')
    if cmd == config.cmd_wireshark and not config.canDisplay():
        self.skipTest('Test requires a display.')
    if not config.args_ping:
        self.skipTest('Your platform ({}) does not have a defined ping command.'.format(sys.platform))
    self.assertIsNotNone(cmd)
    ping_procs = start_pinging(self)
    testout_file = self.filename_from_id(testout_pcap)
    capture_proc = self.runProcess(capture_command(cmd,
        '-i', config.capture_interface,
        '-p',
        '-w', testout_file,
        '-2',
        '-R', 'dcerpc.cn_call_id==123456', # Something unlikely.
        '-c', '10',
        '-a', 'duration:{}'.format(capture_duration),
        '-f', 'icmp || icmp6',
    ),
    env=capture_env
    )
    capture_returncode = capture_proc.returncode
    stop_pinging(ping_procs)
    self.cleanup_files.append(testout_file)
    self.assertEqual(capture_returncode, 0)

    if (capture_returncode == 0):
        check_testout_num_packets(self, 0)

def check_capture_snapshot_len(self, cmd=None):
    if not config.canCapture():
        self.skipTest('Test requires capture privileges and an interface.')
    if cmd == config.cmd_wireshark and not config.canDisplay():
        self.skipTest('Test requires a display.')
    if not config.args_ping:
        self.skipTest('Your platform ({}) does not have a defined ping command.'.format(sys.platform))
    self.assertIsNotNone(cmd)
    ping_procs = start_pinging(self)
    testout_file = self.filename_from_id(testout_pcap)
    capture_proc = self.runProcess(capture_command(cmd,
        '-i', config.capture_interface,
        '-p',
        '-w', testout_file,
        '-s', str(snapshot_len),
        '-a', 'duration:{}'.format(capture_duration),
        '-f', 'icmp || icmp6',
    ),
    env=capture_env
    )
    capture_returncode = capture_proc.returncode
    stop_pinging(ping_procs)
    self.cleanup_files.append(testout_file)
    self.assertEqual(capture_returncode, 0)
    self.assertTrue(os.path.isfile(testout_file))

    # Use tshark to filter out all packets larger than 68 bytes.
    testout2_file = self.filename_from_id('testout2.pcap')

    filter_proc = self.runProcess((config.cmd_tshark,
        '-r', testout_file,
        '-w', testout2_file,
        '-Y', 'frame.cap_len>{}'.format(snapshot_len),
    ))
    filter_returncode = filter_proc.returncode
    self.cleanup_files.append(testout2_file)
    self.assertEqual(capture_returncode, 0)
    if (capture_returncode == 0):
        check_testout_num_packets(self, 0, cap_file=testout2_file)

class case_wireshark_capture(subprocesstest.SubprocessTestCase):
    def test_wireshark_capture_10_packets_to_file(self):
        '''Capture 10 packets from the network to a file using Wireshark'''
        check_capture_10_packets(self, cmd=config.cmd_wireshark)

    # Wireshark doesn't currently support writing to stdout while capturing.
    # def test_wireshark_capture_10_packets_to_stdout(self):
    #     '''Capture 10 packets from the network to stdout using Wireshark'''
    #     check_capture_10_packets(self, cmd=config.cmd_wireshark, to_stdout=True)

    def test_wireshark_capture_from_fifo(self):
        '''Capture from a fifo using Wireshark'''
        check_capture_fifo(self, cmd=config.cmd_wireshark)

    def test_wireshark_capture_from_stdin(self):
        '''Capture from stdin using Wireshark'''
        check_capture_stdin(self, cmd=config.cmd_wireshark)

    def test_wireshark_capture_snapshot_len(self):
        '''Capture truncated packets using Wireshark'''
        check_capture_snapshot_len(self, cmd=config.cmd_wireshark)

class case_tshark_capture(subprocesstest.SubprocessTestCase):
    def test_tshark_capture_10_packets_to_file(self):
        '''Capture 10 packets from the network to a file using TShark'''
        check_capture_10_packets(self, cmd=config.cmd_tshark)

    def test_tshark_capture_10_packets_to_stdout(self):
        '''Capture 10 packets from the network to stdout using TShark'''
        check_capture_10_packets(self, cmd=config.cmd_tshark, to_stdout=True)

    def test_tshark_capture_from_fifo(self):
        '''Capture from a fifo using TShark'''
        check_capture_fifo(self, cmd=config.cmd_tshark)

    def test_tshark_capture_from_stdin(self):
        '''Capture from stdin using TShark'''
        check_capture_stdin(self, cmd=config.cmd_tshark)

    def test_tshark_capture_snapshot_len(self):
        '''Capture truncated packets using TShark'''
        check_capture_snapshot_len(self, cmd=config.cmd_tshark)

class case_dumpcap_capture(subprocesstest.SubprocessTestCase):
    def test_dumpcap_capture_10_packets_to_file(self):
        '''Capture 10 packets from the network to a file using Dumpcap'''
        check_capture_10_packets(self, cmd=config.cmd_dumpcap)

    def test_dumpcap_capture_10_packets_to_stdout(self):
        '''Capture 10 packets from the network to stdout using Dumpcap'''
        check_capture_10_packets(self, cmd=config.cmd_dumpcap, to_stdout=True)

    def test_dumpcap_capture_from_fifo(self):
        '''Capture from a fifo using Dumpcap'''
        check_capture_fifo(self, cmd=config.cmd_dumpcap)

    def test_dumpcap_capture_from_stdin(self):
        '''Capture from stdin using Dumpcap'''
        check_capture_stdin(self, cmd=config.cmd_dumpcap)

    def test_dumpcap_capture_snapshot_len(self):
        '''Capture truncated packets using Dumpcap'''
        check_capture_snapshot_len(self, cmd=config.cmd_dumpcap)
