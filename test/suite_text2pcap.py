#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Text2pcap tests'''

import re
import subprocess
from subprocesstest import get_capture_info, grep_output
import json
import pytest

testin_txt = 'testin.txt'
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

encap_to_link_type_long = {
    'Ethernet': 1,
    'Raw IP': 14,
    'Linux cooked-mode capture v1': 113,
    'IEEE 802.11 plus radiotap radio header': 127,
    'DVB-CI (Common Interface)': 235,
}

encap_to_link_type = {
    'ether': 1,
    'rawip': 14,
    'linux-sll': 113,
    'ieee-802-11-radiotap': 127,
    'dvbci': 235,
}

def check_capinfos_info(cmd_capinfos, cap_file):
    cap_info = {
        'filetype': None,
        'encapsulation': None,
        'packets': None,
        'datasize': None,
        'timeend': None,
    }
    str_pats = {
        'filetype': 'File type',
        'encapsulation': 'File encapsulation',
        'timeend': 'Last packet time',
    }
    int_pats = {
        'packets': 'Number of packets',
        'datasize': 'Data size',
    }
    capinfos_out = get_capture_info(cmd_capinfos, ('-tEcdMe',), cap_file)

    for ci_line in capinfos_out.splitlines():
        for sp_key in str_pats:
            str_pat = r'{}:\s+([\S ]+)'.format(str_pats[sp_key])
            str_res = re.search(str_pat, ci_line)
            if str_res is not None:
                cap_info[sp_key] = str_res.group(1)

        for ip_key in int_pats:
            int_pat = r'{}:\s+(\d+)'.format(int_pats[ip_key])
            int_res = re.search(int_pat, ci_line)
            if int_res is not None:
                cap_info[ip_key] = int(int_res.group(1))

    return cap_info

def get_capinfos_cmp_info(cii):
    cmp_keys = ('encapsulation', 'packets', 'datasize')
    return { k: v for k, v in cii.items() if k in cmp_keys }

def compare_capinfos_info(cii1, cii2, filename1, filename2):
    cii_cmp_i1 = get_capinfos_cmp_info(cii1)
    cii_cmp_i2 = get_capinfos_cmp_info(cii2)
    assert cii_cmp_i1 == cii_cmp_i2

@pytest.fixture
def check_text2pcap(cmd_tshark, cmd_text2pcap, cmd_capinfos, capture_file, result_file, base_env):
    def check_text2pcap_real(cap_filename, file_type, expected_packets=None, expected_datasize=None):
        # Perform the following actions
        # - Get information for the input pcap file with capinfos
        # - Generate an ASCII hexdump with TShark
        # - Convert the ASCII hexdump back to pcap using text2pcap
        # - Get information for the output pcap file with capinfos
        # - Check that file type, encapsulation type, number of packets and data size
        #   in the output file are the same as in the input file

        cap_file = capture_file(cap_filename)
        pre_cap_info = check_capinfos_info(cmd_capinfos, cap_file)
        # Due to limitations of "tshark -x", the output might contain more than one
        # data source which is subsequently interpreted as additional frame data.
        # See https://gitlab.com/wireshark/wireshark/-/issues/14639
        if expected_packets is not None:
            assert pre_cap_info['packets'] != expected_packets
            pre_cap_info['packets'] = expected_packets
        if expected_datasize is not None:
            assert pre_cap_info['datasize'] != expected_datasize
            pre_cap_info['datasize'] = expected_datasize
        assert pre_cap_info['encapsulation'] in encap_to_link_type

        assert file_type in file_type_to_testout, 'Invalid file type'

        # text2pcap_generate_input()
        # $TSHARK -o 'gui.column.format:"Time","%t"' -tad -P -x -r $1 > testin.txt
        testin_file = result_file(testin_txt)
        tshark_cmd = '"{cmd}" -r "{cf}" -o gui.column.format:"Time","%t" -t ad -P --hexdump frames > "{of}"'.format(
            cmd = cmd_tshark,
            cf = cap_file,
            of = testin_file,
        )
        subprocess.check_call(tshark_cmd, shell=True, env=base_env)

        testout_fname = file_type_to_testout[file_type]
        testout_file = result_file(testout_fname)
        # The first word is the file type (the rest might be compression info)
        filetype_flag = pre_cap_info['filetype'].split()[0]
        # We want the -a flag, because the tshark -x format is a hex+ASCII
        # format where the ASCII can be confused for hex bytes without it.
        # XXX: -t ISO also works now too for this output
        text2pcap_cmd = '"{cmd}" -a -F {filetype} -l {linktype} -t "%Y-%m-%d %H:%M:%S.%f" "{in_f}" "{out_f}"'.format(
            cmd = cmd_text2pcap,
            filetype = filetype_flag,
            linktype = encap_to_link_type[pre_cap_info['encapsulation']],
            in_f = testin_file,
            out_f = testout_file,
        )
        proc = subprocess.run(text2pcap_cmd, shell=True, check=True, capture_output=True, encoding='utf-8', env=base_env)
        assert grep_output(proc.stderr, 'potential packet'), "text2pcap didn't complete"
        assert not grep_output(proc.stderr, 'Inconsistent offset'), 'text2pcap detected inconsistent offset'

        post_cap_info = check_capinfos_info(cmd_capinfos, testout_file)
        compare_capinfos_info(pre_cap_info, post_cap_info, cap_file, testout_fname)
    return check_text2pcap_real


class TestText2pcapPcap:
    def test_text2pcap_empty_pcap(self, check_text2pcap):
        '''Test text2pcap with empty.pcap.'''
        check_text2pcap('empty.pcap', 'pcap')

    def test_text2pcap_dhcp_pcap(self, check_text2pcap):
        '''Test text2pcap with dhcp.pcap.'''
        check_text2pcap('dhcp.pcap', 'pcap')

    def test_text2pcap_dhcp_nanosecond_pcap(self, check_text2pcap):
        '''Test text2pcap with dhcp-nanosecond.pcap.'''
        check_text2pcap('dhcp-nanosecond.pcap', 'pcap')

    def test_text2pcap_segmented_fpm_pcap(self, check_text2pcap):
        '''Test text2pcap with segmented_fpm.pcap.'''
        check_text2pcap('segmented_fpm.pcap', 'pcap')

    def test_text2pcap_c1222_std_example8_pcap(self, check_text2pcap):
        '''Test text2pcap with c1222_std_example8.pcap.'''
        check_text2pcap('c1222_std_example8.pcap', 'pcap')

    def test_text2pcap_dns_port_pcap(self, check_text2pcap):
        '''Test text2pcap with dns_port.pcap.'''
        check_text2pcap('dns_port.pcap', 'pcap')

    def test_text2pcap_dvb_ci_uv1_0000_pcap(self, check_text2pcap):
        '''Test text2pcap with dvb-ci_UV1_0000.pcap.'''
        check_text2pcap('dvb-ci_UV1_0000.pcap', 'pcap')

    def test_text2pcap_ikev1_certs_pcap(self, check_text2pcap):
        '''Test text2pcap with ikev1-certs.pcap.'''
        check_text2pcap('ikev1-certs.pcap', 'pcap')

    def test_text2pcap_rsa_p_lt_q_pcap(self, check_text2pcap):
        '''Test text2pcap with rsa-p-lt-q.pcap.'''
        check_text2pcap('rsa-p-lt-q.pcap', 'pcap')

    def test_text2pcap_rsasnakeoil2_pcap(self, check_text2pcap):
        '''Test text2pcap with rsasnakeoil2.pcap.'''
        check_text2pcap('rsasnakeoil2.pcap', 'pcap')

    def test_text2pcap_sample_control4_2012_03_24_pcap(self, check_text2pcap):
        '''Test text2pcap with sample_control4_2012-03-24.pcap.'''
        # Tests handling additional data source (decrypted ZigBee packets)
        # Either tshark must not output the additional data source,
        # or text2pcap must ignore it.
        check_text2pcap('sample_control4_2012-03-24.pcap', 'pcap')

    def test_text2pcap_snakeoil_dtls_pcap(self, check_text2pcap):
        '''Test text2pcap with snakeoil-dtls.pcap.'''
        check_text2pcap('snakeoil-dtls.pcap', 'pcap')

    def test_text2pcap_wpa_eap_tls_pcap_gz(self, check_text2pcap):
        '''Test text2pcap with wpa-eap-tls.pcap.gz.'''
        # Tests handling additional data source (reassemblies)
        # Either tshark must not output the additional data source,
        # or text2pcap must ignore it.
        check_text2pcap('wpa-eap-tls.pcap.gz', 'pcap')

    def test_text2pcap_wpa_induction_pcap(self, check_text2pcap):
        '''Test text2pcap with wpa-Induction.pcap.gz.'''
        check_text2pcap('wpa-Induction.pcap.gz', 'pcap')


class TestText2pcapPcapng:
    def test_text2pcap_dhcp_pcapng(self, check_text2pcap):
        '''Test text2pcap with dhcp.pcapng.'''
        check_text2pcap('dhcp.pcapng', 'pcapng')

    def test_text2pcap_dhcp_nanosecond_pcapng(self, check_text2pcap):
        '''Test text2pcap with dhcp-nanosecond.pcapng.'''
        check_text2pcap('dhcp-nanosecond.pcapng', 'pcapng')

    def test_text2pcap_dhe1_pcapng_gz(self, check_text2pcap):
        '''Test text2pcap with dhe1.pcapng.gz.'''
        check_text2pcap('dhe1.pcapng.gz', 'pcapng')

    def test_text2pcap_dmgr_pcapng(self, check_text2pcap):
        '''Test text2pcap with dmgr.pcapng.'''
        check_text2pcap('dmgr.pcapng', 'pcapng')

    def test_text2pcap_dns_icmp_pcapng_gz(self, check_text2pcap):
        '''Test text2pcap with dns+icmp.pcapng.gz.'''
        # This file needs (and thus tests) the -a flag to identify when the
        # start of the ASCII dump looks like hex.
        check_text2pcap('dns+icmp.pcapng.gz', 'pcapng')

    def test_text2pcap_packet_h2_14_headers_pcapng(self, check_text2pcap):
        '''Test text2pcap with packet-h2-14_headers.pcapng.'''
        check_text2pcap('packet-h2-14_headers.pcapng', 'pcapng')

    def test_text2pcap_sip_pcapng(self, check_text2pcap):
        '''Test text2pcap with sip.pcapng.'''
        check_text2pcap('sip.pcapng', 'pcapng')


@pytest.fixture
def check_rawip(run_text2pcap_capinfos_tshark):
    def check_rawip_real(pdata, packets, datasize):

        assert {'encapsulation': 'rawip4', 'packets': packets, \
            'datasize': datasize, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(pdata, ("-l228",))
    return check_rawip_real


class TestText2pcapParsing:
    def test_text2pcap_eol_hash(self, cmd_text2pcap, cmd_capinfos, capture_file, result_file, base_env):
        '''Test text2pcap hash sign at the end-of-line.'''
        txt_fname = 'text2pcap_hash_eol.txt'
        testout_file = result_file(testout_pcap)
        proc = subprocess.run((cmd_text2pcap,
            '-F', 'pcapng',
            '-t', '%Y-%m-%d %H:%M:%S.',
            capture_file(txt_fname),
            testout_file,
        ), check=True, capture_output=True, encoding='utf-8', env=base_env)
        assert not grep_output(proc.stderr, 'Inconsistent offset'), 'text2pcap failed to parse the hash sign at the end of the line'
        assert grep_output(proc.stderr, r'Directive \[ test_directive'), 'text2pcap failed to parse #TEXT2PCAP test_directive'
        pre_cmp_info = {'encapsulation': 'ether', 'packets': 1, 'datasize': 96, 'timeend': '2015-10-01 21:16:24.317453000'}
        post_cmp_info = check_capinfos_info(cmd_capinfos, testout_file)
        compare_capinfos_info(pre_cmp_info, post_cmp_info, txt_fname, testout_pcap)

    def test_text2pcap_doc_no_line_limit(self, check_rawip):
        '''
        Verify: There is no limit on the width or number of bytes per line and
        Bytes/hex numbers can be uppercase or lowercase.
        '''
        pdata = "0000  45 00 00 21 00 01 00 00 40 11\n" \
                "000A  7C C9 7F 00 00 01" \
                " 7f 00 00 01 ff 98 00 13 00 0d b5 48 66 69 72 73\n" \
                "0020  74\n"
        check_rawip(pdata, 1, 33)

    def test_text2pcap_doc_ignore_text(self, check_rawip):
        '''
        Verify: the text dump at the end of the line is ignored. Any hex numbers
        in this text are also ignored. Any lines of text between the bytestring
        lines is ignored. Any line where the first non-whitespace character is
        '#' will be ignored as a comment.
        '''
        pdata = "0000 45 00 00 21 00 01 00 00  40 11 7c c9 7f 00 00 01 bad\n" \
                "0010 7f 00 00 01 ff 98 00 13  00 0d b5 48 66 69 72 73 - 42\n" \
                "0020 74\n" \
                "0021\n" \
                "That 0021 should probably be ignored as it this: 00 20\n" \
                "0000 45 00 00 22 00 01 00 00 40 11 7c c8 7f 00 00 01\n" \
                "0010 7f 00 00 01 ff 99 00 13 00 0e bc e9 73 65 63 6f  ...\n" \
                " \t# 0020 12 34 56<-- comment, ignore this!\n" \
                "0020 6e 64\n" \
                "12 34 56 78 90 # ignore this due to missing offset!\n"
        check_rawip(pdata, 2, 67)

    def test_text2pcap_doc_leading_text_ignored(self, check_rawip):
        '''
        Verify: Any test before the offset is ignored, including email
        forwarding characters '>'. An offset is a hex number longer than two
        characters. An offset of zero is indicative of starting a new packet.
        '''
        pdata = "> >> 000  45 00 00 21 00 01 00 00 40 11 7c c9 7f 00 00 01\n" \
                "> >> 010  7f 00 00 01 ff 98 00 13 00 0d b5 48 66 69 72 73\n" \
                "> >> 020  74\n" \
                "> >> 000  45 00 00 22 00 01 00 00 40 11 7c c8 7f 00 00 01\n" \
                "> >> 010  7f 00 00 01 ff 99 00 13 00 0e bc e9 73 65 63 6f\n" \
                "> >> 020  6e 64\n"
        check_rawip(pdata, 2, 67)

    def test_text2pcap_doc_require_offset(self, check_rawip):
        '''Any line which has only bytes without a leading offset is ignored.'''
        pdata = "45 00 00 21 00 01 00 00 40 11 7c c9 7f 00 00 01\n" \
                "7f 00 00 01 ff 98 00 13 00 0d b5 48 66 69 72 73\n"
        check_rawip(pdata, 0, 0)

    def test_text2pcap_eol_missing(self, check_rawip):
        '''Verify that the last LF can be missing.'''
        pdata = "0000  45 00 00 21 00 01 00 00 40 11 7c c9 7f 00 00 01\n" \
                "0010  7f 00 00 01 ff 98 00 13 00 0d b5 48 66 69 72 73\n" \
                "0020  74"
        check_rawip(pdata, 1, 33)


@pytest.fixture
def run_text2pcap_capinfos_tshark(cmd_text2pcap, cmd_tshark, cmd_capinfos, result_file, base_env):
    def run_text2pcap_capinfos_tshark_real(content, args):

        testin_file = result_file(testin_txt)
        testout_file = result_file(testout_pcap)

        with open(testin_file, "w") as f:
            f.write(content)
        subprocess.check_call((cmd_text2pcap,) + args + (testin_file, testout_file), env=base_env)

        capinfo = get_capinfos_cmp_info(check_capinfos_info(cmd_capinfos, testout_file))

        stdout = subprocess.check_output((cmd_tshark, '-q', '-z', 'expert,warn',
            '-o', 'udp.check_checksum: TRUE',
            '-o', 'tcp.check_checksum: TRUE',
            '-o', 'sctp.checksum:TRUE',
            '-r', testout_file),
            encoding='utf-8', env=base_env)
        capinfo['expert'] = stdout
        return capinfo
    return run_text2pcap_capinfos_tshark_real


class TestText2pcapHeaders:
    '''Test TCP, UDP or SCTP header without -4 or -6 option'''
    maxDiff = None

    def test_text2pcap_tcp(self, run_text2pcap_capinfos_tshark):
        '''Test TCP over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 60, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000: ff ff ff ff\n", ("-T", "1234,1234"))

    def test_text2pcap_udp(self, run_text2pcap_capinfos_tshark):
        '''Test UDP over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 60, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000: ff ff ff ff\n", ("-u", "1234,1234"))

    def test_text2pcap_sctp(self, run_text2pcap_capinfos_tshark):
        '''Test SCTP over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 70, 'expert': ''}, \
            run_text2pcap_capinfos_tshark(
                "0000   00 03 00 18 00 00 00 00 00 00 00 00 00 00 00 03\n" +
                "0010   01 00 03 03 00 00 00 08\n",
                ("-s", "2905,2905,3"))

    def test_text2pcap_sctp_data(self, run_text2pcap_capinfos_tshark):
        '''Test SCTP DATA over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 70, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000: 01 00 03 03 00 00 00 08\n",
                ("-S", "2905,2905,3"))


@pytest.fixture
def run_text2pcap_ipv4(run_text2pcap_capinfos_tshark):
    def run_text2pcap_ipv4_real(content, args):
        return run_text2pcap_capinfos_tshark(content,
                ("-4", "127.0.0.1,127.0.0.1") + args)
    return run_text2pcap_ipv4_real


class TestText2pcapIpv4:
    '''Test TCP, UDP or SCTP header with -4 option'''
    maxDiff = None

    def test_text2pcap_ipv4_tcp(self, run_text2pcap_ipv4):
        '''Test TCP over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 60, 'expert': ''} == \
            run_text2pcap_ipv4("0000: ff ff ff ff\n", ("-T", "1234,1234"))

    def test_text2pcap_ipv4_udp(self, run_text2pcap_ipv4):
        '''Test UDP over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 60, 'expert': ''} == \
            run_text2pcap_ipv4("0000: ff ff ff ff\n", ("-u", "1234,1234"))

    def test_text2pcap_ipv4_sctp(self, run_text2pcap_ipv4):
        '''Test SCTP over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 70, 'expert': ''} == \
            run_text2pcap_ipv4(
                "0000   00 03 00 18 00 00 00 00 00 00 00 00 00 00 00 03\n" +
                "0010   01 00 03 03 00 00 00 08\n",
                ("-s", "2905,2905,3"))

    def test_text2pcap_ipv4_sctp_data(self, run_text2pcap_ipv4):
        '''Test SCTP DATA over IPv4'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 70, 'expert': ''} == \
            run_text2pcap_ipv4("0000: 01 00 03 03 00 00 00 08\n",
                ("-S", "2905,2905,3"))


@pytest.fixture
def run_text2pcap_ipv6(cmd_tshark, run_text2pcap_capinfos_tshark, result_file, base_env):

    def run_text2pcap_ipv6_real(content, text2pcap_args, tshark_args = ()):
        #Run the common text2pcap tests
        result = run_text2pcap_capinfos_tshark(content,
                ("-6", "::1,::1") + text2pcap_args)

        #Decode the output pcap in JSON format
        stdout = subprocess.check_output((cmd_tshark, '-T', 'json',
            '-r', result_file(testout_pcap)) + tshark_args,
            encoding='utf-8', env=base_env)
        data = json.loads(stdout)

        #Add IPv6 payload length and payload length tree to the result dict
        ipv6 = data[0]['_source']['layers']['ipv6']
        result['ipv6'] = {
                'plen': ipv6.get('ipv6.plen', None),
                'plen_tree': ipv6.get('ipv6.plen_tree', None)}
        return result
    return run_text2pcap_ipv6_real


class TestText2pcapIpv6:
    '''Test TCP, UDP or SCTP header with -6 option'''
    maxDiff = None

    def test_text2pcap_ipv6_tcp(self, run_text2pcap_ipv6):
        '''Test TCP over IPv6'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 78, 'expert': '', \
            'ipv6': {'plen': '24', 'plen_tree': None}} == \
            run_text2pcap_ipv6("0000: ff ff ff ff\n", ("-T", "1234,1234"))

    def test_text2pcap_ipv6_udp(self, run_text2pcap_ipv6):
        '''Test UDP over IPv6'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 66, 'expert': '', \
            'ipv6': {'plen': '12', 'plen_tree': None}} == \
            run_text2pcap_ipv6("0000: ff ff ff ff\n", ("-u", "1234,1234"))

    def test_text2pcap_ipv6_sctp(self, run_text2pcap_ipv6):
        '''Test SCTP over IPv6'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 90, 'expert': '', \
            'ipv6': {'plen': '36', 'plen_tree': None}} == \
            run_text2pcap_ipv6(
                "0000   00 03 00 18 00 00 00 00 00 00 00 00 00 00 00 03\n" +
                "0010   01 00 03 03 00 00 00 08\n",
                ("-s", "2905,2905,3"))

    def test_text2pcap_ipv6_sctp_data(self, run_text2pcap_ipv6):
        '''Test SCTP DATA over IPv6'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 90, 'expert': '', \
            'ipv6': {'plen': '36', 'plen_tree': None}} == \
            run_text2pcap_ipv6("0000: 01 00 03 03 00 00 00 08\n",
                ("-S", "2905,2905,3"))


class TestText2pcapIProto:
    '''Test -i <proto> for IPv4 and IPv6'''
    maxDiff = None

    def test_text2pcap_i_icmp(self, run_text2pcap_capinfos_tshark):
        '''Test -i <proto> without -4 or -6'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 98, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000   08 00 bb b3 d7 3b 00 00 51 a7 d6 7d 00 04 51 e4\n" +
                "0010   08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17\n" +
                "0020   18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27\n" +
                "0030   28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37\n",
                ("-i", "1"))

    def test_text2pcap_i_icmp_ipv4(self, run_text2pcap_capinfos_tshark):
        '''Test -i <proto> with IPv4 (-4) header'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 98, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000   08 00 bb b3 d7 3b 00 00 51 a7 d6 7d 00 04 51 e4\n" +
                "0010   08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17\n" +
                "0020   18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27\n" +
                "0030   28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37\n",
                ("-i", "1", "-4", "127.0.0.1,127.0.0.1"))

    def test_text2pcap_i_icmpv6_ipv6(self, run_text2pcap_capinfos_tshark):
        '''Test -i <proto> with IPv6 (-6) header'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 86, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000   87 00 f2 62 00 00 00 00 fe 80 00 00 00 00 00 00\n" +
                "0010   00 00 00 00 00 00 00 02 01 01 52 54 00 12 34 56\n",
                ("-i", "58", "-6", "::1,::1"))

    def test_text2pcap_i_sctp_ipv6(self, run_text2pcap_capinfos_tshark):
        '''Test -i <proto> with IPv6 (-6) header'''
        assert {'encapsulation': 'ether', 'packets': 1, \
            'datasize': 90, 'expert': ''} == \
            run_text2pcap_capinfos_tshark(
                "0000   0b 59 0b 59 00 00 00 00 26 98 58 51 00 03 00 18\n" +
                "0010   00 00 00 00 00 00 00 00 00 00 00 03 01 00 03 03\n" +
                "0020   00 00 00 08\n",
                ("-i", "132", "-6", "::1,::1"))


class TestText2pcapOtherOptions:
    '''Test other command line options'''
    def test_text2pcap_option_N(self, cmd_text2pcap, cmd_tshark, capture_file, result_file, base_env):
        '''Test -N <intf-name> option'''
        testin_file = result_file(testin_txt)
        testout_file = result_file(testout_pcapng)

        with open(testin_file, 'w') as f:
            f.write("0000 00\n")
            f.close()
        subprocess.check_call((cmd_text2pcap, "-F", "pcapng", "-N", "your-interface-name", testin_file, testout_file), env=base_env)
        stdout = subprocess.check_output((cmd_tshark, "-r", testout_file, "-Tfields", "-eframe.interface_name", "-c1"), encoding='utf-8', env=base_env)
        assert stdout.rstrip() == "your-interface-name"
