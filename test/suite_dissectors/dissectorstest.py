#
# Wireshark dissector tests
# By Atli Guðmundsson <atli@tern.is>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import inspect
import json
import subprocess
import pytest


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

    def __init__(self, protocol, request, cmd_tshark, cmd_text2pcap, result_file, env):
        self.dissection_list = []
        self.protocol = protocol
        self.cmd_tshark = cmd_tshark
        self.cmd_text2pcap = cmd_text2pcap
        self.test_case = request.instance
        self.result_file = result_file
        self.env = env

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

        text_file = self.result_file('txt')
        pcap_file = self.result_file('pcap')

        # create our text file of hex encoded messages
        with open(text_file, 'w') as f:
            for line_no, hex_string, expected_result in self.dissection_list:
                f.write("0 {}\n".format(hex_string))

        # generate our pcap file by feeding the messages to text2pcap
        subprocess.check_call((
            self.cmd_text2pcap,
            '-u', '1234,1234',
            text_file, pcap_file
        ), env=self.env)

        # generate our dissection from our pcap file
        tshark_stdout = subprocess.check_output((
            self.cmd_tshark,
            '-r', pcap_file,
            '-T', 'json',
            '-d', 'udp.port==1234,{}'.format(self.protocol),
            '-J', self.protocol
        ), encoding='utf-8', env=self.env)

        dissections = json.loads(tshark_stdout)
        for (line_no, hex_string, expected_result), dissection in zip(self.dissection_list, dissections):

            # strip away everything except the protocol
            result = dissection['_source']['layers']
            assert self.protocol in result
            result = result[self.protocol]

            # verify that the dissection is as expected
            assert expected_result == result, \
                "expected != result, while dissecting [{}] from line {}.".format(hex_string, line_no)

        # cleanup for next test
        self.dissection_list = []


@pytest.fixture
def dissection_validator(request, cmd_tshark, cmd_text2pcap, result_file, test_env):

    def generate_validator(protocol):
        retval = _dissection_validator_real(
            protocol,
            request,
            cmd_tshark,
            cmd_text2pcap,
            result_file,
            test_env)
        return retval

    return generate_validator
