#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Subprocess test case superclass'''

import os
import os.path
import re
import subprocess
import sys
import enum

# To do:
# - Add a subprocesstest.SkipUnlessCapture decorator?
# - Try to catch crashes? See the comments below in waitProcess.

process_timeout = 300 # Seconds

class ExitCodes(enum.IntEnum):
    OK = 0
    COMMAND_LINE = 1
    INVALID_INTERFACE = 2
    INVALID_FILE_ERROR = 3
    INVALID_FILTER_ERROR = 4
    INVALID_CAPABILITY = 5
    IFACE_NO_LINK_TYPES = 6
    IFACE_HAS_NO_TIMESTAMP_TYPES = 7
    INIT_FAILED = 8
    OPEN_ERROR = 9
    PCAP_NOT_SUPPORTED = 10
    DUMPCAP_NOT_SUPPORTED = 11
    NO_INTERFACES = 12
    PCAP_ERROR = 13

def run(*args, capture_output=False, stdout=None, stderr=None, encoding='utf-8', **kwargs):
    ''' Wrapper for subprocess.run() that captures and decodes output.'''

    # If the user told us what to do with standard streams use that.
    if capture_output or stdout or stderr:
        return subprocess.run(*args, capture_output=capture_output, stdout=stdout, stderr=stderr, encoding=encoding, **kwargs)

    # If the user doesn't want to capture output try to ensure the child inherits the parents stdout and stderr on
    # all platforms, so pytest can reliably capture it and do the right thing. Otherwise the child output may be interleaved
    # on the console with the parent and mangle pytest's status output.
    #
    # Make the child inherit only the parents stdout and stderr.
    return subprocess.run(*args, close_fds=True, stdout=sys.stdout, stderr=sys.stderr, encoding=encoding, **kwargs)

def check_run(*args, **kwargs):
    ''' Same as run(), also check child process returns 0 (success)'''
    proc = run(*args, check=True, **kwargs)
    return proc

def cat_dhcp_command(mode):
    '''Create a command string for dumping dhcp.pcap to stdout'''
    # XXX Do this in Python in a thread?
    sd_cmd = ''
    if sys.executable:
        sd_cmd = '"{}" '.format(sys.executable)
    this_dir = os.path.dirname(__file__)
    sd_cmd += '"{}" {}'.format(os.path.join(this_dir, 'util_dump_dhcp_pcap.py'), mode)
    return sd_cmd

def cat_cap_file_command(cap_files):
    '''Create a command string for dumping one or more capture files to stdout'''
    # XXX Do this in Python in a thread?
    if isinstance(cap_files, str):
        cap_files = [ cap_files ]
    quoted_paths = ' '.join('"{}"'.format(cap_file) for cap_file in cap_files)
    if sys.platform.startswith('win32'):
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb491026(v=technet.10)
        # says that the `type` command "displays the contents of a text
        # file." Copy to the console instead.
        return 'copy {} CON'.format(quoted_paths)
    return 'cat {}'.format(quoted_paths)

def count_output(text, search_pat=None):
    '''Returns the number of output lines (search_pat=None), otherwise returns a match count.'''

    if not text:
        return 0

    if not search_pat:
        return len(text.splitlines())

    match_count = 0

    search_re = re.compile(search_pat)
    for line in text.splitlines():
        if search_re.search(line):
            match_count += 1

    return match_count

def grep_output(text, search_pat):
    return count_output(text, search_pat) > 0

def check_packet_count(cmd_capinfos, num_packets, cap_file):
    '''Make sure a capture file contains a specific number of packets.'''
    got_num_packets = False
    capinfos_testout = subprocess.run([cmd_capinfos, cap_file], capture_output=True, check=True, encoding='utf-8')
    assert capinfos_testout.returncode == 0
    assert capinfos_testout.stdout
    count_pat = r'Number of packets:\s+{}'.format(num_packets)
    if re.search(count_pat, capinfos_testout.stdout):
        got_num_packets = True
    assert got_num_packets, 'Failed to capture exactly {} packets'.format(num_packets)

def get_capture_info(cmd_capinfos, capinfos_args, cap_file):
    '''Run capinfos on a capture file and log its output.

    capinfos_args must be a sequence.'''

    capinfos_cmd = [cmd_capinfos]
    if capinfos_args:
        capinfos_cmd += capinfos_args
    capinfos_cmd.append(cap_file)
    capinfos_data = subprocess.check_output(capinfos_cmd)
    capinfos_stdout = capinfos_data.decode('UTF-8', 'replace')
    return capinfos_stdout
