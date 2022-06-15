#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Mergecap tests'''

import re
import subprocesstest
import fixtures

testout_pcap = 'testout.pcap'
testout_pcapng = 'testout.pcapng'

file_type_to_descr = {
    'pcap': 'Wireshark/tcpdump/... - pcap',
    'pcapng': 'Wireshark/... - pcapng',
}

file_type_to_testout = {
    'pcap': testout_pcap,
    'pcapng': testout_pcapng,
}

# common checking code:
# arg 1 = return value from mergecap command
# arg 2 = file type string
# arg 3 = file encap
# arg 4 = number of IDBs generated
# arg 5 = number of file packets merged
# arg 6 = number of some IDB packets merged
def check_mergecap(self, mergecap_proc, file_type, encapsulation, tot_packets, generated_idbs, idb_packets):
    mergecap_returncode = mergecap_proc.returncode
    self.assertEqual(mergecap_returncode, 0)
    if mergecap_returncode != 0:
        return

    mergecap_success = self.grepOutput('merging complete')
    self.assertTrue(mergecap_success)
    if not mergecap_success:
        return

    self.assertTrue(file_type in file_type_to_descr, 'Invalid file type')

    testout_file = self.filename_from_id(file_type_to_testout[file_type])
    capinfos_testout = self.getCaptureInfo(capinfos_args=('-t', '-E', '-I', '-c'), cap_file=testout_file)

    file_descr = file_type_to_descr[file_type]
    type_pat = r'File type:\s+{}'.format(file_descr)
    self.assertTrue(re.search(type_pat, capinfos_testout) is not None,
        'Failed to generate a {} file'.format(file_type))

    encap_pat = r'File encapsulation:\s+{}'.format(encapsulation)
    self.assertTrue(re.search(encap_pat, capinfos_testout) is not None,
        'Failed to generate an {} encapsulation'.format(encapsulation))

    pkt_pat = r'Number of packets:\s+{}'.format(tot_packets)
    self.assertTrue(re.search(pkt_pat, capinfos_testout) is not None,
        'Failed to generate {} packets'.format(tot_packets))

    gidb_pat = r'Number of interfaces in file:\s+{}'.format(generated_idbs)
    self.assertTrue(re.search(gidb_pat, capinfos_testout) is not None,
        'Failed to generate {} IDBs'.format(generated_idbs))

    midb_pat = r'\s+Number of packets\s+=\s+{}'.format(idb_packets)
    self.assertTrue(re.search(midb_pat, capinfos_testout) is not None,
        'Failed to merge {} IDB packets'.format(idb_packets))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_mergecap_pcap(subprocesstest.SubprocessTestCase):
    def test_mergecap_basic_1_pcap_pcap(self, cmd_mergecap, capture_file):
        '''Merge a single pcap file to pcap'''
        # $MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-F', 'pcap',
            '-w', testout_file,
            capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcap', 'Ethernet', 4, 1, 4)

    def test_mergecap_basic_2_pcap_pcap(self, cmd_mergecap, capture_file):
        '''Merge two pcap files to pcap'''
        # $MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-F', 'pcap',
            '-w', testout_file,
            capture_file('dhcp.pcap'), capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcap', 'Ethernet', 8, 1, 8)

    def test_mergecap_basic_3_empty_pcap_pcap(self, cmd_mergecap, capture_file):
        '''Merge three pcap files to pcap, two empty'''
        # $MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}empty.pcap" "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}empty.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-F', 'pcap',
            '-w', testout_file,
            capture_file('empty.pcap'), capture_file('dhcp.pcap'), capture_file('empty.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcap', 'Ethernet', 4, 1, 4)

    def test_mergecap_basic_2_nano_pcap_pcap(self, cmd_mergecap, capture_file):
        '''Merge two pcap files to pcap, one with nanosecond timestamps'''
        # $MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}dhcp-nanosecond.pcap" "${CAPTURE_DIR}rsasnakeoil2.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcap)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-F', 'pcap',
            '-w', testout_file,
            capture_file('dhcp-nanosecond.pcap'), capture_file('rsasnakeoil2.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcap', 'Ethernet', 62, 1, 62)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_mergecap_pcapng(subprocesstest.SubprocessTestCase):
    def test_mergecap_basic_1_pcap_pcapng(self, cmd_mergecap, capture_file):
        '''Merge a single pcap file to pcapng'''
        # $MERGECAP -v -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-w', testout_file,
            capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Ethernet', 4, 1, 4)

    def test_mergecap_basic_2_pcap_pcapng(self, cmd_mergecap, capture_file):
        '''Merge two pcap files to pcapng'''
        # $MERGECAP -v -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-w', testout_file,
            capture_file('dhcp.pcap'), capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Ethernet', 8, 1, 8)

    def test_mergecap_basic_2_pcap_none_pcapng(self, cmd_mergecap, capture_file):
        '''Merge two pcap files to pcapng, "none" merge mode'''
        # $MERGECAP -vI 'none' -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'none',
            '-w', testout_file,
            capture_file('dhcp.pcap'), capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Ethernet', 8, 2, 4)

    def test_mergecap_basic_2_pcap_all_pcapng(self, cmd_mergecap, capture_file):
        '''Merge two pcap files to pcapng, "all" merge mode'''
        # $MERGECAP -vI 'all' -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'all',
            '-w', testout_file,
            capture_file('dhcp.pcap'), capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Ethernet', 8, 1, 8)

    def test_mergecap_basic_2_pcap_any_pcapng(self, cmd_mergecap, capture_file):
        '''Merge two pcap files to pcapng, "any" merge mode'''
        # $MERGECAP -vI 'any' -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'any',
            '-w', testout_file,
            capture_file('dhcp.pcap'), capture_file('dhcp.pcap'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Ethernet', 8, 1, 8)

    def test_mergecap_basic_1_pcapng_pcapng(self, cmd_mergecap, capture_file):
        '''Merge a single pcapng file to pcapng'''
        # $MERGECAP -v -w testout.pcap "${CAPTURE_DIR}dhcp.pcapng" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-w', testout_file,
            capture_file('dhcp.pcapng'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Ethernet', 4, 1, 4)

    def test_mergecap_1_pcapng_many_pcapng(self, cmd_mergecap, capture_file):
        '''Merge one pcapng file with many interfaces to pcapng'''
        # $MERGECAP -v -w testout.pcap "${CAPTURE_DIR}many_interfaces.pcapng.1" > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-w', testout_file,
            capture_file('many_interfaces.pcapng.1'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Per packet', 64, 11, 62)

    def test_mergecap_3_pcapng_pcapng(self, cmd_mergecap, capture_file):
        '''Merge multiple pcapng files with many interfaces to pcapng'''
        # $MERGECAP -v -w testout.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-w', testout_file,
            capture_file('many_interfaces.pcapng.1'),
            capture_file('many_interfaces.pcapng.2'),
            capture_file('many_interfaces.pcapng.3'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Per packet', 88, 11, 86)

    def test_mergecap_3_pcapng_none_pcapng(self, cmd_mergecap, capture_file):
        '''Merge multiple pcapng files with many interfaces to pcapng, "none" merge mode'''
        # $MERGECAP -vI 'none' -w testout.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'none',
            '-w', testout_file,
            capture_file('many_interfaces.pcapng.1'),
            capture_file('many_interfaces.pcapng.2'),
            capture_file('many_interfaces.pcapng.3'),
        ))
        check_mergecap(self, mergecap_proc, 'pcapng', 'Per packet', 88, 33, 62)

    def test_mergecap_3_pcapng_all_pcapng(self, cmd_mergecap, capture_file):
        '''Merge multiple pcapng files to pcapng in "none" mode, then merge that to "all" mode.'''
        # build a pcapng of all the interfaces repeated by using mode 'none'
        # $MERGECAP -vI 'none' -w testin.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
        testin_file = self.filename_from_id('testin.pcapng')
        self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'none',
            '-w', testin_file,
            capture_file('many_interfaces.pcapng.1'),
            capture_file('many_interfaces.pcapng.2'),
            capture_file('many_interfaces.pcapng.3'),
        ))
        # the above generated 33 IDBs, 88 total pkts, 62 in first IDB

        # and use that generated pcap for our test
        # $MERGECAP -vI 'all' -w testout.pcap ./testin.pcap ./testin.pcap ./testin.pcap > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'all',
            '-w', testout_file,
            testin_file, testin_file, testin_file,
        ))
        # check for 33 IDBs, 88*3=264 total pkts, 62*3=186 in first IDB
        check_mergecap(self, mergecap_proc, 'pcapng', 'Per packet', 264, 33, 186)

    def test_mergecap_3_pcapng_any_pcapng(self, cmd_mergecap, capture_file):
        '''Merge multiple pcapng files to pcapng in "none" mode, then merge that to "all" mode.'''
        # build a pcapng of all the interfaces repeated by using mode 'none'
        # $MERGECAP -vI 'none' -w testin.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
        testin_file = self.filename_from_id('testin.pcapng')
        self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'none',
            '-w', testin_file,
            capture_file('many_interfaces.pcapng.1'),
            capture_file('many_interfaces.pcapng.2'),
            capture_file('many_interfaces.pcapng.3'),
        ))
        # the above generated 33 IDBs, 88 total pkts, 62 in first IDB

        # and use that generated pcap for our test
        # $MERGECAP -vI 'any' -w testout.pcap ./testin.pcap ./testin.pcap ./testin.pcap > testout.txt 2>&1
        testout_file = self.filename_from_id(testout_pcapng)
        mergecap_proc = self.assertRun((cmd_mergecap,
            '-V',
            '-I', 'any',
            '-w', testout_file,
            testin_file, testin_file, testin_file,
        ))
        # check for 11 IDBs, 88*3=264 total pkts, 86*3=258 in first IDB
        check_mergecap(self, mergecap_proc, 'pcapng', 'Per packet', 264, 11, 258)
