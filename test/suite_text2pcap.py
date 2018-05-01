#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Text2pcap tests'''

import config
import os.path
import pprint
import re
import subprocesstest
import unittest

# XXX We should probably generate these automatically in config.py.
c1222_std_example8_pcap = os.path.join(config.capture_dir, 'c1222_std_example8.pcap')
dhcp_nanosecond_pcap = os.path.join(config.capture_dir, 'dhcp-nanosecond.pcap')
dhcp_nanosecond_pcapng = os.path.join(config.capture_dir, 'dhcp-nanosecond.pcapng')
dhcp_pcap = os.path.join(config.capture_dir, 'dhcp.pcap')
dhcp_pcapng = os.path.join(config.capture_dir, 'dhcp.pcapng')
dhe1_pcapng_gz = os.path.join(config.capture_dir, 'dhe1.pcapng.gz')
dmgr_pcapng = os.path.join(config.capture_dir, 'dmgr.pcapng')
dns_icmp_pcapng_gz = os.path.join(config.capture_dir, 'dns+icmp.pcapng.gz')
dns_port_pcap = os.path.join(config.capture_dir, 'dns_port.pcap')
dvb_ci_uv1_0000_pcap = os.path.join(config.capture_dir, 'dvb-ci_UV1_0000.pcap')
empty_pcap = os.path.join(config.capture_dir, 'empty.pcap')
ikev1_certs_pcap = os.path.join(config.capture_dir, 'ikev1-certs.pcap')
packet_h2_14_headers_pcapng = os.path.join(config.capture_dir, 'packet-h2-14_headers.pcapng')
rsa_p_lt_q_pcap = os.path.join(config.capture_dir, 'rsa-p-lt-q.pcap')
rsasnakeoil2_pcap = os.path.join(config.capture_dir, 'rsasnakeoil2.pcap')
sample_control4_2012_03_24_pcap = os.path.join(config.capture_dir, 'sample_control4_2012-03-24.pcap')
segmented_fpm_pcap = os.path.join(config.capture_dir, 'segmented_fpm.pcap')
sip_pcapng = os.path.join(config.capture_dir, 'sip.pcapng')
snakeoil_dtls_pcap = os.path.join(config.capture_dir, 'snakeoil-dtls.pcap')
wpa_induction_pcap_gz = os.path.join(config.capture_dir, 'wpa-Induction.pcap.gz')
wpa_eap_tls_pcap_gz = os.path.join(config.capture_dir, 'wpa-eap-tls.pcap.gz')

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

encap_to_link_type = {
    'Ethernet': 1,
    'Raw IP': 14,
    'Linux cooked-mode capture': 113,
    'IEEE 802.11 plus radiotap radio header': 127,
    'DVB-CI (Common Interface)': 235,
}

def check_capinfos_info(self, cap_file):
    cap_info = {
        'filetype': None,
        'encapsulation': None,
        'packets': None,
        'datasize': None,
    }
    str_pats = {
        'filetype': 'File type',
        'encapsulation': 'File encapsulation',
    }
    int_pats = {
        'packets': 'Number of packets',
        'datasize': 'Data size',
    }
    capinfos_out = self.getCaptureInfo(capinfos_args=('-t', '-E', '-c', '-d', '-M'), cap_file=cap_file)

    for ci_line in capinfos_out.splitlines():
        for sp_key in str_pats:
            str_pat = '{}:\s+([\S ]+)'.format(str_pats[sp_key])
            str_res = re.search(str_pat, ci_line)
            if str_res is not None:
                cap_info[sp_key] = str_res.group(1)

        for ip_key in int_pats:
            int_pat = '{}:\s+(\d+)'.format(int_pats[ip_key])
            int_res = re.search(int_pat, ci_line)
            if int_res is not None:
                cap_info[ip_key] = int(int_res.group(1))

    return cap_info

def get_capinfos_cmp_info(cii):
    cmp_keys = ('encapsulation', 'packets', 'datasize')
    return { k: v for k, v in cii.items() if k in cmp_keys }

def compare_capinfos_info(self, cii1, cii2, filename1, filename2):
    cii_cmp_i1 = get_capinfos_cmp_info(cii1)
    cii_cmp_i2 = get_capinfos_cmp_info(cii2)
    if not cii_cmp_i1 == cii_cmp_i2:
        cii1_pp = pprint.pformat(cii_cmp_i1)
        cii2_pp = pprint.pformat(cii_cmp_i2)
        self.diffOutput(cii1_pp, cii2_pp, filename1, filename2)
        self.fail('text2pcap output file differs from input file.')

def check_text2pcap(self, cap_file, file_type, expected_packets=None, expected_datasize=None):
    # Perfom the following actions
    # - Get information for the input pcap file with capinfos
    # - Generate an ASCII hexdump with TShark
    # - Convert the ASCII hexdump back to pcap using text2pcap
    # - Get information for the output pcap file with capinfos
    # - Check that file type, encapsulation type, number of packets and data size
    #   in the output file are the same as in the input file

    pre_cap_info = check_capinfos_info(self, cap_file)
    self.assertTrue(pre_cap_info['encapsulation'] in encap_to_link_type)

    self.assertTrue(file_type in file_type_to_testout, 'Invalid file type')

    # text2pcap_generate_input()
    # $TSHARK -o 'gui.column.format:"Time","%t"' -tad -P -x -r $1 > testin.txt
    testin_file = self.filename_from_id(testin_txt)
    cf_path = os.path.join(config.capture_dir, cap_file)
    tshark_cmd = '{cmd} -r {cf} -o gui.column.format:"Time","%t" -t ad -P -x > {of}'.format(
        cmd = config.cmd_tshark,
        cf = cf_path,
        of = testin_file,
    )
    self.assertRun(tshark_cmd, shell=True, env=os.environ.copy())

    testout_fname = file_type_to_testout[file_type]
    testout_file = self.filename_from_id(testout_fname)
    if 'pcapng' in pre_cap_info['filetype'] or 'nanosecond libpcap' in pre_cap_info['filetype']:
        pcapng_flag = '-n'
    else:
        pcapng_flag = ''
    text2pcap_cmd = '{cmd} {ns} -d -l {linktype} -t "%Y-%m-%d %H:%M:%S." {in_f} {out_f}'.format(
        cmd = config.cmd_text2pcap,
        ns = pcapng_flag,
        linktype = encap_to_link_type[pre_cap_info['encapsulation']],
        in_f = testin_file,
        out_f = testout_file,
    )
    self.assertRun(text2pcap_cmd, shell=True)
    self.assertTrue(self.grepOutput('potential packet'), "text2pcap didn't complete")
    self.assertFalse(self.grepOutput('Inconsistent offset'), 'text2pcap detected inconsistent offset')

    post_cap_info = check_capinfos_info(self, testout_file)
    if expected_packets is not None:
        post_cap_info['packtets'] = expected_packets
    if expected_datasize is not None:
        post_cap_info['datasize'] = expected_datasize
    compare_capinfos_info(self, pre_cap_info, post_cap_info, cap_file, testout_fname)


class case_text2pcap_pcap(subprocesstest.SubprocessTestCase):
    def test_text2pcap_empty_pcap(self):
        '''Test text2pcap with empty.pcap.'''
        check_text2pcap(self, empty_pcap, 'pcap')

    def test_text2pcap_dhcp_pcap(self):
        '''Test text2pcap with dhcp.pcap.'''
        check_text2pcap(self, dhcp_pcap, 'pcap')

    def test_text2pcap_dhcp_nanosecond_pcap(self):
        '''Test text2pcap with dhcp-nanosecond.pcap.'''
        check_text2pcap(self, dhcp_nanosecond_pcap, 'pcap')

    def test_text2pcap_segmented_fpm_pcap(self):
        '''Test text2pcap with segmented_fpm.pcap.'''
        check_text2pcap(self, segmented_fpm_pcap, 'pcap')

    def test_text2pcap_c1222_std_example8_pcap(self):
        '''Test text2pcap with c1222_std_example8.pcap.'''
        check_text2pcap(self, c1222_std_example8_pcap, 'pcap')

    def test_text2pcap_dns_port_pcap(self):
        '''Test text2pcap with dns_port.pcap.'''
        check_text2pcap(self, dns_port_pcap, 'pcap')

    def test_text2pcap_dvb_ci_uv1_0000_pcap(self):
        '''Test text2pcap with dvb-ci_UV1_0000.pcap.'''
        check_text2pcap(self, dvb_ci_uv1_0000_pcap, 'pcap')

    def test_text2pcap_ikev1_certs_pcap(self):
        '''Test text2pcap with ikev1-certs.pcap.'''
        check_text2pcap(self, ikev1_certs_pcap, 'pcap')

    def test_text2pcap_rsa_p_lt_q_pcap(self):
        '''Test text2pcap with rsa-p-lt-q.pcap.'''
        check_text2pcap(self, rsa_p_lt_q_pcap, 'pcap')

    def test_text2pcap_rsasnakeoil2_pcap(self):
        '''Test text2pcap with rsasnakeoil2.pcap.'''
        check_text2pcap(self, rsasnakeoil2_pcap, 'pcap')

    def test_text2pcap_sample_control4_2012_03_24_pcap(self):
        '''Test text2pcap with sample_control4_2012-03-24.pcap.'''
        # tshark currently output decrypted ZigBee packets and
        # as a result the number of packets and data size are different
        check_text2pcap(self, sample_control4_2012_03_24_pcap, 'pcap', 239, 10103)

    def test_text2pcap_snakeoil_dtls_pcap(self):
        '''Test text2pcap with snakeoil-dtls.pcap.'''
        check_text2pcap(self, snakeoil_dtls_pcap, 'pcap')

    def test_text2pcap_wpa_eap_tls_pcap_gz(self):
        '''Test text2pcap with wpa-eap-tls.pcap.gz.'''
        # tshark reassembles some packets and because of this
        # the number of packets and data size are different
        check_text2pcap(self, wpa_eap_tls_pcap_gz, 'pcap', 88, 38872)

    def test_text2pcap_wpa_induction_pcap(self):
        '''Test text2pcap with wpa-Induction.pcap.gz.'''
        check_text2pcap(self, wpa_induction_pcap_gz, 'pcap')

class case_text2pcap_pcap(subprocesstest.SubprocessTestCase):
    def test_text2pcap_dhcp_pcapng(self):
        '''Test text2pcap with dhcp.pcapng.'''
        check_text2pcap(self, dhcp_pcapng, 'pcapng')

    def test_text2pcap_dhcp_nanosecond_pcapng(self):
        '''Test text2pcap with dhcp-nanosecond.pcapng.'''
        check_text2pcap(self, dhcp_nanosecond_pcapng, 'pcapng')

    def test_text2pcap_dhe1_pcapng_gz(self):
        '''Test text2pcap with dhe1.pcapng.gz.'''
        check_text2pcap(self, dhe1_pcapng_gz, 'pcapng')

    def test_text2pcap_dmgr_pcapng(self):
        '''Test text2pcap with dmgr.pcapng.'''
        check_text2pcap(self, dmgr_pcapng, 'pcapng')

    def test_text2pcap_dns_icmp_pcapng_gz(self):
        '''Test text2pcap with dns+icmp.pcapng.gz.'''
        # Different data size
        # Most probably the problem is that input file timestamp precision is in microseconds
        # File timestamp precision: microseconds (6)
        check_text2pcap(self, dns_icmp_pcapng_gz, 'pcapng', None, 3180)

    def test_text2pcap_packet_h2_14_headers_pcapng(self):
        '''Test text2pcap with packet-h2-14_headers.pcapng.'''
        check_text2pcap(self, packet_h2_14_headers_pcapng, 'pcapng')

    def test_text2pcap_sip_pcapng(self):
        '''Test text2pcap with sip.pcapng.'''
        check_text2pcap(self, sip_pcapng, 'pcapng')

class case_text2pcap_eol_hash(subprocesstest.SubprocessTestCase):
    def test_text2pcap_eol_hash(self):
        '''Test text2pcap hash sign at the end-of-line.'''
        txt_fname = 'text2pcap_hash_eol.txt'
        txt_file = os.path.join(config.capture_dir, txt_fname)
        testout_file = self.filename_from_id(testout_pcap)
        self.assertRun((config.cmd_text2pcap,
            '-n',
            '-d',
            '-t', '%Y-%m-%d %H:%M:%S.',
            txt_file,
            testout_file,
        ))
        self.assertFalse(self.grepOutput('Inconsistent offset'), 'text2pcap failed to parse the hash sign at the end of the line')
        self.assertTrue(self.grepOutput('Directive \[ test_directive'), 'text2pcap failed to parse #TEXT2PCAP test_directive')
        pre_cmp_info = {'encapsulation': 'Ethernet', 'packets': 1, 'datasize': 96 }
        post_cmp_info = check_capinfos_info(self, testout_file)
        compare_capinfos_info(self, pre_cmp_info, post_cmp_info, txt_fname, testout_pcap)



# 	test_step_add "hash sign at the end of the line" text2pcap_step_hash_at_eol



# text2pcap_step_hash_at_eol() {
# 	$TEXT2PCAP -n -d -t "%Y-%m-%d %H:%M:%S."\
# 		"${CAPTURE_DIR}/text2pcap_hash_eol.txt" testout.pcap > testout.txt 2>&1
# 	RETURNVALUE=$?

# 	grep -q "Inconsistent offset" testout.txt
# 	if [ $? -eq 0 ]; then
# 		cat ./testout.txt
# 		test_step_failed "text2pcap failed to parse the hash sign at the end of the line"
# 	fi

# 	#Check that #TEXT2PCAP is not prased as a comment
# 	grep -q "Directive \[ test_directive" testout.txt
# 	if [ $? -ne 0 ]; then
# 		cat ./testout.txt
# 		test_step_failed "text2pcap failed to parse #TEXT2PCAP test_directive"
# 	fi

# 	text2pcap_common_pcapng_check $RETURNVALUE "Ethernet" 1 96
# 	test_step_ok
# }


