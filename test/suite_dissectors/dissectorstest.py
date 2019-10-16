#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Wireshark dissector tests
# By Atli Guðmundsson <atli@tern.is>
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Standard modules
import inspect
import json

# Wireshark modules
import fixtures
import subprocesstest


class _dissection_validator_real:
    '''
    Collects a set of byte bundles, matching json objects and a protocol
    name and verifies that a byte bundle converts into the matching json
    object using the following execution chain:

        byte bundle -> text2pcap -> tshark <protocol> -> json

    Note: The idea for this approach came about when it was realized that
    calling text2pcap and tshark for each byte bundle resulted in
    unacceptable overhead during execution of the unittests.
    '''

    def __init__(self, protocol, request, cmd_tshark, cmd_text2pcap):
        self.dissection_list = []
        self.protocol = protocol
        self.cmd_tshark = cmd_tshark
        self.cmd_text2pcap = cmd_text2pcap
        self.test_case = request.instance

    def add_dissection(self, byte_list, expected_result, line_no=None):
        '''Adds a byte bundle and an expected result to the set of byte
        bundles to verify.

        byte bundles must be iterable.'''

        hex_string = ' '.join('{:02x}'.format(ele) for ele in bytes(byte_list))

        if line_no is None:
            caller = inspect.getframeinfo(inspect.stack()[1][0])
            line_no = caller.lineno

        self.dissection_list.append((line_no, hex_string, expected_result))

# Uncomment the following lines to record in a text file all the dissector byte
# bundles, in the order they are presented:
#
#         with open("full.txt", 'a') as f:
#             f.write("0 {}\n".format(hex_string))

# Then use the following command to convert full.txt into a pcap file,
# replacing <port> with the default port of your protocol:
#       # text2pcap -u <port>,<port> full.txt out.pcap

    def check_dissections(self):
        '''Processes and verifies all added byte bundles and their expected
        results. At the end of processing the current set is emptied.'''

        text_file = self.test_case.filename_from_id('txt')
        pcap_file = self.test_case.filename_from_id('pcap')

        # create our text file of hex encoded messages
        with open(text_file, 'w') as f:
            for line_no, hex_string, expected_result in self.dissection_list:
                f.write("0 {}\n".format(hex_string))

        # generate our pcap file by feeding the messages to text2pcap
        self.test_case.assertRun((
            self.cmd_text2pcap,
            '-u', '1234,1234',
            text_file, pcap_file
        ))

        # generate our dissection from our pcap file
        tshark_proc = self.test_case.assertRun((
            self.cmd_tshark,
            '-r', pcap_file,
            '-T', 'json',
            '-d', 'udp.port==1234,{}'.format(self.protocol),
            '-J', self.protocol
        ))

        dissections = json.loads(tshark_proc.stdout_str)
        for (line_no, hex_string, expected_result), dissection in zip(self.dissection_list, dissections):

            # strip away everything except the protocol
            result = dissection['_source']['layers']
            self.test_case.assertIn(self.protocol, result)
            result = result[self.protocol]

            # verify that the dissection is as expected
            self.test_case.assertEqual(
                expected_result,
                result,
                "expected != result, while dissecting [{}] from line {}.".format(hex_string, line_no))

        # cleanup for next test
        self.dissection_list = []


@fixtures.fixture
def dissection_validator(request, cmd_tshark, cmd_text2pcap):

    def generate_validator(protocol):
        retval = _dissection_validator_real(
            protocol,
            request,
            cmd_tshark,
            cmd_text2pcap)
        return retval

    return generate_validator
