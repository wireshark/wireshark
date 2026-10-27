#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Dissection tests'''

import os.path
import struct
import subprocess
import sys

import pytest

from subprocesstest import count_output, grep_output


class TestDissectHttpHeaderSyntax:
    def test_http_header_syntax_expert_warnings(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        testin_file = result_file('http-header-syntax.txt')
        testout_file = result_file('http-header-syntax.pcap')
        payload = '''\
00000000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
00000010  48 6f 73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f
00000020  6d 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74
00000030  68 20 3a 20 35 0d 0a 58 2d 54 65 73 74 3a 20 61
00000040  62 63 00 64 65 66 0d 0a 0d 0a 68 65 6c 6c 6f
'''
        with open(testin_file, 'w') as f:
            f.write(payload)
        subprocess.check_call((cmd_text2pcap, '-T', '12345,80', testin_file, testout_file), env=base_env)

        stdout = subprocess.check_output((cmd_tshark,
                '-r', testout_file,
                '-Tfields',
                '-eframe.number',
                '-Y', 'http.header_name.trailing_whitespace && http.header_value.invalid_nul_char',
            ), encoding='utf-8', env=test_env)
        assert stdout == '1\n'


class TestDissectIcmpv6NeighborDiscovery:
    def test_nd_hop_limit_validation(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        valid_in = result_file('icmpv6-nd-hlim-valid.txt')
        invalid_in = result_file('icmpv6-nd-hlim-invalid.txt')
        valid_pcap = result_file('icmpv6-nd-hlim-valid.pcap')
        invalid_pcap = result_file('icmpv6-nd-hlim-invalid.pcap')

        valid_payload = '''\
00000000  60 00 00 00 00 08 3a ff fe 80 00 00 00 00 00 00
00000010  00 00 00 00 00 00 00 01 ff 02 00 00 00 00 00 00
00000020  00 00 00 00 00 00 00 02 85 00 7d 36 00 00 00 00
'''
        invalid_payload = '''\
00000000  60 00 00 00 00 08 3a 40 fe 80 00 00 00 00 00 00
00000010  00 00 00 00 00 00 00 01 ff 02 00 00 00 00 00 00
00000020  00 00 00 00 00 00 00 02 85 00 7d 36 00 00 00 00
'''

        for path, payload, output in (
            (valid_in, valid_payload, valid_pcap),
            (invalid_in, invalid_payload, invalid_pcap),
        ):
            with open(path, 'w') as f:
                f.write(payload)
            subprocess.check_call((cmd_text2pcap, '-e', '0x86dd', path, output), env=base_env)

        stdout = subprocess.check_output((cmd_tshark, '-G', 'fields'),
                                         encoding='utf-8', env=test_env)
        assert 'icmpv6.nd.hlim.invalid' in stdout

        stdout = subprocess.check_output((cmd_tshark,
                '-r', valid_pcap,
                '-Tfields',
                '-eframe.number',
                '-Y', 'icmpv6.nd.hlim.invalid',
            ), encoding='utf-8', env=test_env)
        assert stdout == ''

        stdout = subprocess.check_output((cmd_tshark,
                '-r', invalid_pcap,
                '-Tfields',
                '-eframe.number',
                '-e_ws.expert.message',
                '-Y', 'icmpv6.nd.hlim.invalid',
            ), encoding='utf-8', env=test_env)
        assert stdout == '1\tIPv6 Hop Limit must be 255 for this ICMPv6 message (found 64)\n'


class TestDissectDtnTcpcl:
    def test_tcpclv3_xfer(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_tcpclv3_bpv6_transfer.pcapng'),
                '-Tfields',
                '-etcpcl.ack.length',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['1064', '1064']

    def test_tcpclv4_xfer(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_tcpclv4_bpv7_transfer.pcapng'),
                '-Tfields',
                '-etcpcl.v4.xfer_ack.ack_len',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['100,199,100', '199']


class TestDissectBpv7:
    '''
    The UDP test captures were generated from the BP/UDPCL example files with command:
    for FN in test/captures/dtn_udpcl*.cbordiag; do python3 tools/generate_udp_pcap.py --dport 4556 --infile $FN --outfile ${FN%.cbordiag}.pcap; done
    '''
    def test_bpv7_admin_status(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bib_admin.pcap'),
                '-Tfields',
                '-ebpv7.status_rep.identity',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'Source: ipn:93.185, DTN Time: 1396536125, Seq: 281'

    def test_bpv7_eid_dtn(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_eid_schemes.pcap'),
                '-Tfields',
                '-ebpv7.primary.dst_uri',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'dtn://auth/svc'

    def test_bpv7_eid_ipn(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_eid_schemes.pcap'),
                '-Tfields',
                '-ebpv7.primary.src_uri',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'ipn:977000.5279.7390'

    def test_bpv7_eid_unknown(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_eid_schemes.pcap'),
                '-Tfields',
                '-ebpv7.primary.report_uri',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == ''

    def test_bpv7_eid_ipn_update(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_ipn_3comp.pcap'),
                '-Tfields',
                '-ebpv7.eid.uri',
                '-ebpv7.eid.ipn_altform',
            ), encoding='utf-8', env=test_env)
        expect = [
            'ipn:0.26622.12070,ipn:977000.5279.7390,ipn:4196183048196785.1111,ipn:93.185',
            'ipn:26622.12070,ipn:4196183048197279.7390,ipn:977000.4785.1111,ipn:0.93.185',
        ]
        assert stdout.strip() == '\t'.join(expect)

    def test_bpv7_eid_ipn_invalid(self, cmd_tshark, capture_file, test_env):
        ''' URIs are absent, not NONE or <MISSING> '''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_ipn_invalid.pcap'),
                '-Tfields',
                '-ebpv7.primary.src_uri',
                '-ebpv7.primary.dst_uri',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == ''

    def test_bpv7_bpsec_bib(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bib_admin.pcap'),
                '-Tfields',
                '-ebpsec.asb.ctxid',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '1'

    def test_bpv7_bpsec_bib_admin_type(self, cmd_tshark, capture_file, test_env):
        # BIB doesn't alter payload
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bib_admin.pcap'),
                '-Tfields',
                '-ebpv7.admin_rec.type_code',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '1'

    def test_bpv7_bpsec_bcb(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bcb_admin.pcap'),
                '-Tfields',
                '-ebpsec.asb.ctxid',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '2'

    def test_bpv7_bpsec_bcb_admin_type(self, cmd_tshark, capture_file, test_env):
        # BCB inhibits payload dissection
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bcb_admin.pcap'),
                '-Tfields',
                '-ebpv7.admin_rec.type_code',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == ''

    def test_bpv7_bpsec_cose_mac0_result_alg(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_cose_mac0.pcap'),
                '-Tfields',
                '-ebpsec.asb.ctxid',
                '-ebpsec.asb.result.id',
                '-ecose.alg.int',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '\t'.join(['3', '17', '5'])

    def test_bpv7_bpsec_cose_encrypt_result_alg(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_cose_encrypt_ec.pcap'),
                '-Tfields',
                '-ebpsec.asb.ctxid',
                '-ebpsec.asb.result.id',
                '-ecose.alg.int',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '\t'.join(['3', '96', '3,-31'])


class TestDissectCbor:
    '''
    Test captures generated from the CBOR example files with commands:
    python3 tools/generate_cbor_pcap.py --infile test/captures/cbor_variety.cbordiag --outfile test/captures/cbor_variety.pcap http
    python3 tools/generate_cbor_pcap.py --infile test/captures/cborseq_variety.cbordiag --outfile test/captures/cborseq_variety.pcap http --content-type application/cbor-seq
    '''

    def test_cbor_variety_diag(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cbor_variety.pcap'),
                '-o', 'cbor.dissect_embeded_bstr:TRUE',
                '-o', 'cbor.display_diagnostic:top',
                '-T', 'fields',
                '-E', 'occurrence=l',
                '-E', 'escape=n',
                '-e', 'cbor.diagnostic',
            ), encoding='utf-8', env=test_env)
        expect = (
            '[_ '
            '[undefined, null, false, true, simple(10)], '
            '[0, 10, 9223372036854775807, 18446744073709551615], '
            '[-1, -10, -9223372036854775808, -9223372036854775809, -18446744073709551616], '
            '[0.00000, 10.0000, 65504.0, -65504.0, NaN, -Infinity, Infinity], '
            '[65505.0000000000, -65505.0000000000, 3.40282346638529e+38, -3.40282346638529e+38], '
            '[3.40282346638529e+39, -3.40282346638529e+39, 1.79769313486232e+308, -1.79769313486232e+308], '
            r"""['', ''_, 'test', 'Café', '\\'in"', h'00cafe', (_ 'te', 'st')], """
            r"""["", ""_, "test", "Café", "'in\\"", "\\t\\n\\u200B", (_ "te", "st")], """
            '[[], [_ ], [_ 1, 2, 3]], '
            '[{}, {_ }, {_ 1: 2, 3: 4}], '
            r"""[2(h'66691b50'), 24(<<10>>)], """
            '[<<10>>, <<1, 2, "hi">>]'
            ']'
        )
        assert stdout.strip() == expect

    def test_cborseq_variety_diag(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cborseq_variety.pcap'),
                '-o', 'cbor.dissect_embeded_bstr:TRUE',
                '-o', 'cbor.display_diagnostic:top',
                '-T', 'fields',
                '-E', 'occurrence=l',
                '-E', 'escape=n',
                '-e', 'cbor.diagnostic',
            ), encoding='utf-8', env=test_env)
        expect = (
            '[undefined, null, false, true, simple(10)], '
            '[0, 10, 9223372036854775807, 18446744073709551615], '
            '[-1, -10, -9223372036854775808, -9223372036854775809, -18446744073709551616], '
            '[0.00000, 10.0000, 65504.0, -65504.0, NaN, -Infinity, Infinity], '
            '[65505.0000000000, -65505.0000000000, 3.40282346638529e+38, -3.40282346638529e+38], '
            '[3.40282346638529e+39, -3.40282346638529e+39, 1.79769313486232e+308, -1.79769313486232e+308], '
            r"""['', 'test', 'Café', '\\'in"', h'00cafe', (_ 'te', 'st')], """
            r"""["", "test", "Café", "'in\\"", "\\t\\n\\u200B", (_ "te", "st")], """
            '[[], [_ 1, 2, 3]], '
            '[{}, {_ 1: 2, 3: 4}], '
            r"""[2(h'66691b50'), 24(<<10>>)], """
            '[<<10>>, <<1, 2, "hi">>]'
        )
        assert stdout.strip() == expect


class TestDissectCose:
    '''
    These test captures were generated from the COSE example files with command:
    for FN in test/captures/cose*.cbordiag; do python3 tools/generate_cbor_pcap.py --content-type 'application/cose' --infile $FN --outfile ${FN%.cbordiag}.pcap; done
    '''
    def test_cose_sign_tagged(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_sign_tagged.pcap'),
                '-Tfields',
                '-ecose.msg.signature',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a,00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297'

    def test_cose_sign1_tagged(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_sign1_tagged.pcap'),
                '-Tfields',
                '-ecose.msg.signature',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36'

    def test_cose_encrypt_tagged(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_encrypt_tagged.pcap'),
                '-Tfields',
                '-ecose.kid',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '6f75722d736563726574'

    def test_cose_encrypt0_tagged(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_encrypt0_tagged.pcap'),
                '-Tfields',
                '-ecose.iv',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '89f52f65a1c580933b5261a78c'

    def test_cose_mac_tagged(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_mac_tagged.pcap'),
                '-Tfields',
                '-ecose.msg.mac_tag',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e'

    def test_cose_mac0_tagged(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_mac0_tagged.pcap'),
                '-Tfields',
                '-ecose.msg.mac_tag',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '726043745027214f'

    def test_cose_keyset(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('cose_keyset.pcap'),
                '-Tfields',
                '-ecose.key.k',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188'


class TestDissectGprpc:
    def test_grpc_with_json(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC with JSON payload'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_person_search_json_with_image.pcapng.gz'),
                '-d', 'tcp.port==50052,http2',
                '-2',
                '-Y', 'grpc.message_length == 208 && json.value.string == "87561234"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC/JSON')

    def test_grpc_with_protobuf(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC with Protobuf payload'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_person_search_protobuf_with_image.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-d', 'tcp.port==50051,http2',
                '-2',
                '-Y', 'protobuf.message.name == "tutorial.PersonSearchRequest"'
                      ' || (grpc.message_length == 66 && protobuf.field.value.string == "Jason"' +
                      '     && protobuf.field.value.int64 == 1602601886)',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'tutorial.PersonSearchService/Search') # grpc request
        assert grep_output(stdout, 'tutorial.Person') # grpc response

    def test_grpc_streaming_mode_reassembly(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC/HTTP2 streaming mode reassembly'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_stream_reassembly_sample.pcapng.gz'),
                '-d', 'tcp.port==50051,http2',
                '-d', 'tcp.port==44363,http2',
                '-2', # make http2.body.reassembled.in available
                '-Y', # Case1: In frame28, one http DATA contains 4 completed grpc messages (json data seq=1,2,3,4).
                      '(frame.number == 28 && grpc && json.value.number == 1 && json.value.number == 2' +
                      ' && json.value.number == 3 && json.value.number == 4 && http2.body.reassembled.in == 45) ||' +
                      # Case2: In frame28, last grpc message (the 5th) only has 4 bytes, which need one more byte
                      # to be a message head. a completed message is reassembled in frame45. (json data seq=5)
                      '(frame.number == 45 && grpc && http2.body.fragment == 28 && json.value.number == 5' +
                      ' && http2.body.reassembled.in == 61) ||' +
                      # Case3: In frame45, one http DATA frame contains two partial fragment, one is part of grpc
                      # message of previous http DATA (frame28), another is first part of grpc message of next http
                      # DATA (which will be reassembled in next http DATA frame61). (json data seq=6)
                      '(frame.number == 61 && grpc && http2.body.fragment == 45 && json.value.number == 6) ||' +
                      # Case4: A big grpc message across frame100, frame113, frame126 and finally reassembled in frame139.
                      '(frame.number == 100 && grpc && http2.body.reassembled.in == 139) ||' +
                      '(frame.number == 113 && !grpc && http2.body.reassembled.in == 139) ||' +
                      '(frame.number == 126 && !grpc && http2.body.reassembled.in == 139) ||' +
                      '(frame.number == 139 && grpc && json.value.number == 9) ||' +
                      # Case5: An large grpc message of 200004 bytes.
                      '(frame.number == 164 && grpc && grpc.message_length == 200004)',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'DATA') == 8

    def test_grpc_http2_fake_headers(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP2/gRPC fake headers (used when HTTP2 initial HEADERS frame is missing)'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_person_search_protobuf_with_image-missing_headers.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:http2_fake_headers: "{}","{}","{}","{}","{}","{}","{}"'.format(
                            '50051','3','IN',':path','/tutorial.PersonSearchService/Search','FALSE', 'TRUE'),
                '-o', 'uat:http2_fake_headers: "{}","{}","{}","{}","{}","{}","{}"'.format(
                            '50051','0','IN','content-type','application/grpc','FALSE','TRUE'),
                '-o', 'uat:http2_fake_headers: "{}","{}","{}","{}","{}","{}","{}"'.format(
                            '50051','0','OUT','content-type','application/grpc','FALSE','TRUE'),
                '-d', 'tcp.port==50051,http2',
                '-2',
                '-Y', 'protobuf.field.value.string == "Jason" || protobuf.field.value.string == "Lily"',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'DATA') == 2


class TestDissectGrpcWeb:
    def test_grpc_web_unary_call_over_http1(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web unary call over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-2',
                '-Y', '(tcp.stream eq 0) && (pbf.greet.HelloRequest.name == "88888888"' +
                        '|| pbf.greet.HelloRequest.name == "99999999"' +
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 1

    def test_grpc_web_unary_call_over_http2(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web unary call over http2'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-2',
                '-Y', '(tcp.stream eq 1) && (pbf.greet.HelloRequest.name == "88888888"' +
                        '|| pbf.greet.HelloRequest.name == "99999999"' +
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 1

    def test_grpc_web_reassembly_and_stream_over_http2(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web data reassembly and server stream over http2'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-2',
                '-Y', '(tcp.stream eq 2) && ((pbf.greet.HelloRequest.name && grpc.message_length == 80004)' +
                       '|| (pbf.greet.HelloReply.message && (grpc.message_length == 23 || grpc.message_length == 80012)))',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 4

    def test_grpc_web_text_unary_call_over_http1(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web-Text unary call over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-2',
                '-Y', '(tcp.stream eq 5) && (pbf.greet.HelloRequest.name == "88888888"' +
                        '|| pbf.greet.HelloRequest.name == "99999999"' +
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC-Web-Text')
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 1

    def test_grpc_web_text_unary_call_over_http2(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web-Text unary call over http2'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-2',
                '-Y', '(tcp.stream eq 6) && (pbf.greet.HelloRequest.name == "88888888"' +
                        '|| pbf.greet.HelloRequest.name == "99999999"' +
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC-Web-Text')
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 1

    def test_grpc_web_text_reassembly_and_stream_over_http2(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web-Text data reassembly and server stream over http2'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-2',
                '-Y', '(tcp.stream eq 8) && ((pbf.greet.HelloRequest.name && grpc.message_length == 80004)' +
                       '|| (pbf.greet.HelloReply.message && (grpc.message_length == 23 || grpc.message_length == 80012)))',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC-Web-Text')
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 4

    def test_grpc_web_text_reassembly_over_http1(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web-Text data reassembly over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-2',
                '-Y', '(tcp.stream eq 7) && (grpc.message_length == 80004 || grpc.message_length == 80010)',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC-Web-Text')
        assert count_output(stdout, 'greet.HelloRequest') == 1
        assert count_output(stdout, 'greet.HelloReply') == 1

    def test_grpc_web_server_stream_over_http1(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web data server stream over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-2',
                '-Y', '(tcp.stream eq 9) && ((pbf.greet.HelloRequest.name && grpc.message_length == 10)' +
                       '|| (pbf.greet.HelloReply.message && grpc.message_length == 18))',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC-Web')
        assert count_output(stdout, 'greet.HelloRequest') == 1
        assert count_output(stdout, 'greet.HelloReply') == 9

    def test_grpc_web_reassembly_and_stream_over_http1(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''gRPC-Web data reassembly and server stream over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-2',
                '-Y', '(tcp.stream eq 10) && ((pbf.greet.HelloRequest.name && grpc.message_length == 80004)' +
                       '|| (pbf.greet.HelloReply.message && (grpc.message_length == 23 || grpc.message_length == 80012)))',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GRPC-Web')
        assert count_output(stdout, 'greet.HelloRequest') == 2
        assert count_output(stdout, 'greet.HelloReply') == 6



class TestDissectHttp:
    def test_http_request_target_whitespace(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http-tab-request.pcapng'),
                '-Tfields',
                '-e_ws.expert',
                '-ehttp.request.method',
                '-ehttp.request.uri',
                '-ehttp.request.version',
                '-ehttp.request.full_uri',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'GET')
        assert '/foo\\tbar' in stdout
        assert grep_output(stdout, 'HTTP/1.1')
        assert 'http://example.com/foo\\tbar' in stdout
        assert grep_output(stdout, 'Request target contains whitespace')

    def test_http_brotli_decompression(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP brotli decompression'''
        if not features.have_brotli:
            pytest.skip('Requires brotli.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http-brotli.pcapng'),
                '-Y', 'http.response.code==200',
                '-Tfields', '-etext',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'This is a test file for testing brotli decompression in Wireshark')

class TestDissectHttp2:
    def test_http2_data_reassembly(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP2 data reassembly'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', f'tls.keylog_file: {key_file}',
                '-d', 'tcp.port==8443,tls',
                '-Y', 'http2.data.data matches "PNG" && http2.data.data matches "END"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'DATA')

    def test_http2_brotli_decompression(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP2 brotli decompression'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        if not features.have_brotli:
            pytest.skip('Requires brotli.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http2-brotli.pcapng'),
                '-Y', 'http2.data.data matches "This is a test file for testing brotli decompression in Wireshark"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'DATA')

    def test_http2_zstd_decompression(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP/2 zstd decompression'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        if not features.have_zstd:
            pytest.skip('Requires zstd.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http2-zstd.pcapng'),
                '-Y', 'http2.data.data matches "Your browser supports decompressing Zstandard."',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'DATA')

    def test_http2_follow_0(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Follow HTTP/2 Stream ID 0 test'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', f'tls.keylog_file: {key_file}',
                '-z', 'follow,http2,hex,0,0'
            ), encoding='utf-8', env=test_env)
        # Stream ID 0 bytes
        assert grep_output(stdout, '00000000  00 00 12 04 00 00 00 00')
        # Stream ID 1 bytes, decrypted but compressed by HPACK
        assert not grep_output(stdout, '00000000  00 00 2c 01 05 00 00 00')
        # Stream ID 1 bytes, decrypted and uncompressed, human readable
        assert not grep_output(stdout, '00000000  3a 6d 65 74 68 6f 64 3a')

    def test_http2_follow_1(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Follow HTTP/2 Stream ID 1 test'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', f'tls.keylog_file: {key_file}',
                '-z', 'follow,http2,hex,0,1'
            ), encoding='utf-8', env=test_env)
        # Stream ID 0 bytes
        assert not grep_output(stdout, '00000000  00 00 12 04 00 00 00 00')
        # Stream ID 1 bytes, decrypted but compressed by HPACK
        assert not grep_output(stdout, '00000000  00 00 2c 01 05 00 00 00')
        # Stream ID 1 bytes, decrypted and uncompressed, human readable
        assert grep_output(stdout, '00000000  3a 6d 65 74 68 6f 64 3a')

    def test_http2_window_size_multiple_frames(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP/2 calculated window sizes with multiple flow-controlled frames per packet'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http2-window-size-multiframe.pcap'),
                '-d', 'tcp.port==8080,http2',
                '-2',
                '-Y', 'http2.type == 0 || http2.type == 8',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'http2.calculated.connection.window_size.before',
                '-e', 'http2.calculated.connection.window_size.after',
                '-e', 'http2.calculated.stream.window_size.before',
                '-e', 'http2.calculated.stream.window_size.after',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            # HEADERS, then DATA of 10 and 20 bytes on stream 1
            '4\t65535,65525\t65525,65505\t65535,65525\t65525,65505',
            # WINDOW_UPDATE +10 on stream 0, +30 on stream 1, +20 on stream 0
            '5\t65505,65515\t65515,65535\t65505\t65535',
        ]

class TestDissectHttp3:
    def test_http3_qpack_reassembly(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''HTTP/3 QPACK encoder stream reassembly'''
        if not features.have_nghttp3:
            pytest.skip('Requires nghttp3.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('http3-qpack-reassembly-anon.pcapng'),
                '-Y', 'http3.frame_type == "HEADERS"',
                '-T', 'fields', '-e', 'http3.headers.method',
                '-e', 'http3.headers.authority',
                '-e', 'http3.headers.referer', '-e', 'http3.headers.user_agent',
                '-e', 'http3.qpack.encoder.icnt'
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'POST')
        assert grep_output(stdout, 'googlevideo.com')
        assert grep_output(stdout, 'https://www.youtube.com')
        assert grep_output(stdout, 'Mozilla/5.0')
        assert grep_output(stdout, '21') # Total number of QPACK insertions

class TestDissectProtobuf:
    def test_protobuf_udp_message_mapping(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test Protobuf UDP Message Mapping and parsing google.protobuf.Timestamp features'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_udp_addressbook_with_image_ts.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8127","tutorial.AddressBook"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.tutorial.Person.name == "Jason"'
                      ' && pbf.tutorial.Person.last_updated > "2020-10-15"' +
                      ' && pbf.tutorial.Person.last_updated < "2020-10-19"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'tutorial.AddressBook')

    def test_protobuf_message_type_leading_with_dot(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test Protobuf Message type is leading with dot'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_test_leading_dot.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8123","a.b.msg"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.a.b.a.b.c.param3 contains "in a.b.a.b.c" && pbf.a.b.c.param6 contains "in a.b.c"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'PB[(]a.b.msg[)]')

    def test_protobuf_map_and_oneof_types(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test Protobuf map and oneof types, and taking keyword as identification'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_test_map_and_oneof_types.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8124","test.map.MapMaster"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.test.map.MapMaster.param3 == "I\'m param3 for oneof test."' +  # test oneof type
                      ' && pbf.test.map.MapMaster.param4MapEntry.value == 1234' +         # test map type
                      ' && pbf.test.map.Foo.param1 == 88 && pbf.test.map.MapMaster.param5MapEntry.key == 88'
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'PB[(]test.map.MapMaster[)]')

    def test_protobuf_default_value(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test Protobuf feature adding missing fields with default values'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_test_default_value.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8128","wireshark.protobuf.test.TestDefaultValueMessage"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-o', 'protobuf.add_default_value: all',
                '-O', 'protobuf',
                '-Y', 'pbf.wireshark.protobuf.test.TestDefaultValueMessage.enumFooWithDefaultValue_Fouth == -4' +
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.boolWithDefaultValue_False == false' +
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.int32WithDefaultValue_0 == 0' +
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.doubleWithDefaultValue_Negative0point12345678 == -0.12345678' +
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.stringWithDefaultValue_SymbolPi contains "Pi."' +
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.bytesWithDefaultValue_1F2F890D0A00004B == 1f:2f:89:0d:0a:00:00:4b' +
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.optional' +  # test taking keyword 'optional' as identification
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.message' +  # test taking keyword 'message' as identification
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.stringWithNoValue == ""' +  # test default value is empty for strings
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.bytesWithNoValue == ""'  # test default value is empty for bytes
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'floatWithDefaultValue_0point23: 0.23') # another default value will be displayed
        assert grep_output(stdout, 'missing required field \'missingRequiredField\'') # check the missing required field export warn

    def test_protobuf_field_subdissector(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test "protobuf_field" subdissector table'''
        if not features.have_lua:
            pytest.skip('Test requires Lua scripting support.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        lua_file = os.path.join(dirs.lua_dir, 'protobuf_test_field_subdissector_table.lua')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_udp_addressbook_with_image_ts.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8127","tutorial.AddressBook"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-X', f'lua_script:{lua_file}',
                '-Y', 'pbf.tutorial.Person.name == "Jason" && pbf.tutorial.Person.last_updated && png',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'PB[(]tutorial.AddressBook[)]')

    def test_protobuf_called_by_custom_dissector(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test Protobuf invoked by other dissector (passing type by pinfo.private)'''
        if not features.have_lua:
            pytest.skip('Test requires Lua scripting support.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        lua_file = os.path.join(dirs.lua_dir, 'protobuf_test_called_by_custom_dissector.lua')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_tcp_addressbook.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-X', f'lua_script:{lua_file}',
                '-d', 'tcp.port==18127,addrbook',
                '-Y', 'pbf.tutorial.Person.name == "Jason" && pbf.tutorial.Person.last_updated',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'tutorial.AddressBook')

    def test_protobuf_complex_syntax(self, cmd_tshark, features, dirs, capture_file, test_env):
        '''Test Protobuf parsing complex syntax .proto files'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        complex_proto_files_dir = os.path.join(dirs.protobuf_lang_files_dir, 'complex_proto_files').replace('\\', '/')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('protobuf_udp_addressbook_with_image_ts.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(complex_proto_files_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.wireshark.protobuf.test.complex.syntax.TestFileParsed.last_field_for_wireshark_test' +
                      ' && pbf.protobuf_unittest.TestFileParsed.last_field_for_wireshark_test',
            ), encoding='utf-8', env=test_env)
        # the output must be empty and not contain something like:
        #   tshark: "pbf.xxx.TestFileParsed.last_field_for_wireshark_test" is neither a field nor a protocol name.
        # or
        #   tshark: Protobuf: Error(s)
        assert not grep_output(stdout, '.last_field_for_wireshark_test')
        assert not grep_output(stdout, 'Protobuf: Error')

class TestDissectRtpproxy:
    def test_rtpengine_bencode_good(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_good_bencode.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'rtpproxy.cookie == "19384_1139339" && bencode.str == "sdp"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'RTPproxy-ng')

    def test_rtpengine_bencode_bad(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_bad_bencode.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'rtpproxy.cookie == "19509_1136304" && bencode.str == "delete"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'RTPproxy-ng')

    def test_rtpengine_bencode_error_reply(self, cmd_tshark, capture_file, test_env):
        '''An "offer" refused with an error, and a "delete" answered with a warning'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_error_reply.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'bencode.str == "Unknown call-id"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'RTPproxy-ng')

        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_error_reply.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'bencode.str contains "Call-ID not found or tags"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'RTPproxy-ng')

    def test_rtpengine_ng_command_tracking(self, cmd_tshark, capture_file, test_env):
        '''The ng messages name themselves, and requests are matched to replies'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_error_reply.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'rtpproxy.ng.command == "delete"',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Request: delete')

        # The reply to it carries no Call-ID of its own
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_error_reply.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-2',
                '-Y', 'rtpproxy.ng.result == "error" && rtpproxy.request_in',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Reply: error')

    def test_rtpengine_ng_sdp(self, cmd_tshark, capture_file, test_env):
        '''The session description carried by an ng message reaches the SDP dissector'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_query_reassembled.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'rtpproxy.ng.command == "offer" && sdp.media.port == 8000',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'RTPproxy-ng/SDP')

    def test_rtpengine_bencode_reassembled(self, cmd_tshark, capture_file, test_env):
        '''A reply long enough to be split over two IP fragments'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpengine_query_reassembled.pcap'),
                '-d', 'udp.port==12222,rtpproxy',
                '-Y', 'bencode.str == "last signal" && ip.reassembled.length == 1704',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'RTPproxy-ng')

    def test_rtpproxy_no_lf_on_tcp(self, cmd_tshark, capture_file, test_env):
        '''Over TCP a message must end with an LF; one without is flagged, one with is not'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rtpproxy_tcp.pcap'),
                '-d', 'tcp.port==12222,rtpproxy',
                '-Y', 'rtpproxy.no_lf_on_tcp',
                '-T', 'fields', '-e', 'frame.number',
            ), encoding='utf-8', env=test_env)
        # Only the first frame (no trailing LF) is flagged; the second has one.
        assert stdout.strip() == '1'

class TestDissectErldp:
    def test_erldp_flags(self, cmd_tshark, capture_file, test_env):
        '''The distribution flags added in OTP 25 to 29 are named, not left in Reserved or Spare'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_flags.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-Y', 'erldp.flags.mandatory_25_digest && erldp.flags.altact_sig'
                      ' && erldp.flags.native_records && erldp.flags.local_ext == 0'
                      ' && erldp.flags.reserved == 0 && erldp.flags.spare == 0',
                '-T', 'fields', '-e', 'erldp.name',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'a@127.0.0.1'

    def test_erldp_complement(self, cmd_tshark, capture_file, test_env):
        '''After an old name message, the complement message carries the high flags and the creation'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_complement.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-T', 'fields', '-e', '_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            'SEND_NAME a@127.0.0.1', 'SEND_STATUS ok', 'SEND_CHALLENGE b@127.0.0.1',
            'SEND_COMPLEMENT', 'SEND_CHALLENGE_REPLY', 'SEND_CHALLENGE_ACK',
        ]
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_complement.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-Y', 'erldp.flags_high && erldp.flags.spawn && erldp.flags.alias'
                      ' && erldp.flags.altact_sig && erldp.flags.native_records'
                      ' && erldp.flags.name_me == 0 && erldp.flags.spare == 0',
                '-T', 'fields', '-e', 'frame.number', '-e', 'erldp.flags_high',
                '-e', 'erldp.creation',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '4\t0x0000006d\t1554098974'

    def test_erldp_ctlmsg(self, cmd_tshark, capture_file, test_env):
        '''The control messages added in OTP 24 to 28 are named'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_ctlmsg.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-T', 'fields', '-e', '_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == [
            'ALIAS_SEND', 'ALIAS_SEND_TT', 'UNLINK_ID', 'UNLINK_ID_ACK',
            'ALTACT_SIG_SEND', 'ALTACT_SIG_SEND', 'ALTACT_SIG_SEND',
        ]

    def test_erldp_small_big(self, cmd_tshark, capture_file, test_env):
        '''A bignum of up to 8 bytes is shown once, as a decimal integer'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_ctlmsg.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-Y', 'erldp.small_big_ext_len',
                '-T', 'fields', '-e', 'erldp.big_ext_int', '-e', 'erldp.big_ext_str',
            ), encoding='utf-8', env=test_env)
        # The Id of UNLINK_ID and UNLINK_ID_ACK
        assert stdout.splitlines() == ['1234605616436508552\t'] * 2

    def test_erldp_altact_flags(self, cmd_tshark, capture_file, test_env):
        '''The flags of ALTACT_SIG_SEND tell what To is and what kind of signal it is'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_ctlmsg.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-Y', 'erldp.altact_flags',
                '-T', 'fields', '-e', 'frame.number', '-e', 'erldp.altact_flags',
                '-e', 'erldp.altact_flags.prio', '-e', 'erldp.altact_flags.token',
                '-e', 'erldp.altact_flags.alias', '-e', 'erldp.altact_flags.name',
                '-e', 'erldp.altact_flags.exit',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '5\t0x09\tTrue\tFalse\tFalse\tTrue\tFalse',    # priority, to a name
            '6\t0x06\tFalse\tTrue\tTrue\tFalse\tFalse',    # to an alias, with a token
            '7\t0x10\tFalse\tFalse\tFalse\tFalse\tTrue',   # an exit signal
        ]

    def test_erldp_record_ext(self, cmd_tshark, capture_file, test_env):
        '''A native record (OTP 29) is decoded, and so is the term after it'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_record.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-T', 'fields', '-e', 'erldp.record_ext.num_fields',
                '-e', 'erldp.record_ext.flags.exported', '-e', 'erldp.atom_text',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '2\tTrue\ta@127.0.0.1,b@127.0.0.1,users,user,name,age,done',
            '0\tFalse\ta@127.0.0.1,b@127.0.0.1,shop,empty,done',
        ]

    def test_erldp_old_tags(self, cmd_tshark, capture_file, test_env):
        '''Deprecated atoms and references are decoded, local data is kept
        opaque, and an unknown tag is flagged rather than silently misread'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_old_tags.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-T', 'fields', '-e', 'erldp.atom_text', '-e', 'erldp.ref_ext.id',
                '-e', 'erldp.local_ext.hash', '-e', 'erldp.undecoded',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            # Latin-1 atoms, then the atom after the reference
            'a@127.0.0.1,b@127.0.0.1,h\u00e9llo,b@127.0.0.1,done\t0x0000002a\t\t',
            'a@127.0.0.1,b@127.0.0.1\t\t0xc0ffee11\t',
            'a@127.0.0.1,b@127.0.0.1\t\t\t02037704646f6e65',
        ]
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('erldp_old_tags.pcap'),
                '-d', 'tcp.port==45000,erldp',
                '-Y', 'erldp.unknown_tag',
                '-T', 'fields', '-e', 'frame.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '3'

class TestDissectTcp:
    @staticmethod
    def check_tcp_out_of_order(cmd_tshark, dirs, test_env, extraArgs=None):
        if extraArgs is None:
            extraArgs = []
        capture_file = os.path.join(dirs.capture_dir, 'http-ooo.pcap')
        stdout = subprocess.check_output([cmd_tshark,
                '-r', capture_file,
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'http',
            ] + extraArgs, encoding='utf-8', env=test_env)
        assert count_output(stdout, 'HTTP') == 5
        assert grep_output(stdout, r'^\s*4\s.*PUT /1 HTTP/1.1')
        assert grep_output(stdout, r'^\s*7\s.*GET /2 HTTP/1.1')
        assert grep_output(stdout, r'^\s*10\s.*PUT /3 HTTP/1.1')
        assert grep_output(stdout, r'^\s*11\s.*PUT /4 HTTP/1.1')
        assert grep_output(stdout, r'^\s*15\s.*PUT /5 HTTP/1.1')

    def test_tcp_out_of_order_onepass(self, cmd_tshark, dirs, test_env):
        self.check_tcp_out_of_order(cmd_tshark, dirs, test_env)

    def test_tcp_out_of_order_twopass(self, cmd_tshark, dirs, test_env):
        self.check_tcp_out_of_order(cmd_tshark, dirs, test_env, extraArgs=['-2'])

    def test_tcp_out_of_order_data_after_syn(self, cmd_tshark, capture_file, test_env):
        '''Test when the first non-empty segment is OoO.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns-ooo.pcap'),
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'dns', '-Tfields', '-edns.qry.name',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == 'example.com'

    def test_tcp_out_of_order_first_gap(self, cmd_tshark, capture_file, test_env):
        '''
        Test reporting of "reassembled_in" in the OoO frame that contains the
        initial segment (Bug 15420). Additionally, test for proper reporting
        when the initial segment is retransmitted.
        For PDU H123 (where H is the HTTP Request header and 1, 2 and 3 are part
        of the body), the order is: (SYN) 2 H H 1 3 H.
        '''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('http-ooo2.pcap'),
            '-otcp.reassemble_out_of_order:TRUE',
            '-Tfields',
            '-eframe.number', '-etcp.reassembled_in', '-e_ws.col.info',
            '-2',
            ), encoding='utf-8', env=test_env)
        lines = stdout.split('\n')
        # 2 - start of OoO MSP
        assert '2\t6\t[TCP Previous segment not captured]' in lines[1]
        assert '[TCP segment of a reassembled PDU]' in lines[1] or '[TCP PDU reassembled in' in lines[1]

        # H - first time that the start of the MSP is delivered
        assert '3\t6\t[TCP Out-Of-Order]' in lines[2]
        assert '[TCP segment of a reassembled PDU]' in lines[2] or '[TCP PDU reassembled in' in lines[2]

        # H - first retransmission. Because this is before the reassembly
        # completes we can add it to the reassembly
        assert '4\t6\t[TCP Retransmission]' in lines[3]
        assert '[TCP segment of a reassembled PDU]' in lines[3] or '[TCP PDU reassembled in' in lines[3]

        # 1 - continue reassembly
        assert '5\t6\t[TCP Out-Of-Order]' in lines[4]
        assert '[TCP segment of a reassembled PDU]' in lines[4] or '[TCP PDU reassembled in' in lines[4]

        # 3 - finish reassembly
        assert '6\t\tPUT /0 HTTP/1.1' in lines[5]

        # H - second retransmission. This is after the reassembly completes
        # so we do not add it to the reassembly (but throw a ReassemblyError.)
        assert '7\t\t' in lines[6]
        assert '[TCP segment of a reassembled PDU]' not in lines[6] and '[TCP PDU reassembled in' not in lines[6]

    def test_tcp_reassembly_more_data_1(self, cmd_tshark, capture_file, test_env):
        '''
        Tests that reassembly also works when a new packet begins at the same
        sequence number as the initial segment. This models behavior with the
        ZeroWindowProbe: the initial segment contains a single byte. The second
        segment contains that byte, plus the remainder.
        '''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('retrans-tls.pcap'),
            '-Ytls', '-Tfields', '-eframe.number', '-etls.record.length',),
            encoding='utf-8', env=test_env)
        # First pass dissection actually accepted the first frame as TLS, but
        # subsequently requested reassembly.
        assert stdout == '1\t\n2\t16\n'

    def test_tcp_reassembly_more_data_2(self, cmd_tshark, capture_file, test_env):
        '''
        Like test_tcp_reassembly_more_data_1, but checks the second pass (-2).
        '''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('retrans-tls.pcap'),
            '-Ytls', '-Tfields', '-eframe.number', '-etls.record.length', '-2'),
            encoding='utf-8', env=test_env)
        assert stdout == '2\t16\n'

    def test_tcp_rst_diagnostic_compact_iana(self, cmd_tshark, capture_file, test_env):
        '''RST diagnostic payload with IANA reason code (PEN=0).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tcp-rst-diagnostic.pcap'),
            '-Tfields', '-eframe.number', '-etcp.rst_diagnostic.reason_code',
            '-Y', 'tcp.rst_diagnostic.reason_code == 9',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '1\t9'

    def test_tcp_rst_diagnostic_compact_vendor(self, cmd_tshark, capture_file, test_env):
        '''RST diagnostic payload with vendor-specific reason code and PEN.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tcp-rst-diagnostic.pcap'),
            '-Tfields', '-eframe.number',
            '-etcp.rst_diagnostic.vendor_reason_code',
            '-etcp.rst_diagnostic.pen',
            '-Y', 'tcp.rst_diagnostic.pen == 32473',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '2\t3\t32473'

    def test_tcp_rst_diagnostic_legacy_fallback(self, cmd_tshark, capture_file, test_env):
        '''RST without magic number falls back to plain ASCII reset cause.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tcp-rst-diagnostic.pcap'),
            '-Tfields', '-eframe.number', '-etcp.reset_cause',
            '-Y', 'frame.number == 3',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '3\tConnection refused'

    def test_tcp_rst_diagnostic_malformed_fallback(self, cmd_tshark, capture_file, test_env):
        '''RST with magic but wrong length falls back to ASCII.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tcp-rst-diagnostic.pcap'),
            '-Tfields', '-eframe.number', '-etcp.reset_cause',
            '-Y', 'frame.number == 4',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip().startswith('4\t')

class TestDissectGit:
    def test_git_prot(self, cmd_tshark, capture_file, features, test_env):
        '''
        Check for Git protocol version 2, flush and delimiter packets.
        Ensure there are no malformed packets.
        '''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('gitOverTCP.pcap'),
                '-Ygit', '-Tfields', '-egit.version', '-egit.packet_type',
                '-zexpert', '-e_ws.expert',
            ), encoding='utf-8', env=test_env)
        # `epan/dissectors/packet-git.c` parses the Git Protocol version
        # from ASCII '1' or '2' to integers 49 or 50 in grep output.
        # 0x0000 are flush packets.
        # 0x0001 are delimiter packets.
        # Pre-existing git Malformed Packets in this pcap were addressed
        # with the parsing of the delimiter packets. This test ensures
        # pcap gitOverTCP's delim packets are parsed and that there are no
        # malformed packets with "Expert Info/Errors" in the same pcap.
        # Additional test cases for other scenarios, i.e actually malformed
        # git packets, might be required.
        assert stdout == '50\t\t\n\t0\t\n\t\t\n\t1,0\t\n'

class TestDissectTls:
    @staticmethod
    def check_tls_handshake_reassembly(cmd_tshark, capture_file, test_env,
                                       extraArgs=None):
        if extraArgs is None:
            extraArgs = []
        # Include -zexpert just to be sure that no exception has occurred. It
        # is not strictly necessary as the extension to be matched is the last
        # one in the handshake message.
        stdout = subprocess.check_output([cmd_tshark,
                               '-r', capture_file('tls-fragmented-handshakes.pcap.gz'),
                               '-zexpert',
                               '-Ytls.handshake.extension.data',
                               '-Tfields', '-etls.handshake.extension.data'] + extraArgs,
                               encoding='utf-8', env=test_env)
        stdout = stdout.replace(',', '\n')
        # Expected output are lines with 0001, 0002, ..., 03e8
        expected = ''.join(f'{i:04x}\n' for i in range(1, 1001))
        assert stdout == expected

    @staticmethod
    def check_tls_reassembly_over_tcp_reassembly(cmd_tshark, capture_file, test_env,
                                                 extraArgs=None):
        if extraArgs is None:
            extraArgs = []
        stdout = subprocess.check_output([cmd_tshark,
                               '-r', capture_file('tls-fragmented-over-tcp-segmented.pcapng.gz'),
                               '-zexpert,note',
                               '-Yhttp.host',
                               '-Tfields', '-ehttp.host'] + extraArgs,
                               encoding='utf-8', env=test_env)
        stdout = stdout.replace(',', '\n')
        assert stdout == 'reports.crashlytics.com\n'

    def test_tls_handshake_reassembly(self, cmd_tshark, capture_file, test_env):
        '''Verify that TCP and TLS handshake reassembly works.'''
        self.check_tls_handshake_reassembly(cmd_tshark, capture_file, test_env)

    def test_tls_handshake_reassembly_2(self, cmd_tshark, capture_file, test_env):
        '''Verify that TCP and TLS handshake reassembly works (second pass).'''
        self.check_tls_handshake_reassembly(
            cmd_tshark, capture_file, test_env, extraArgs=['-2'])

    def test_tls_reassembly_over_tcp_reassembly(self, cmd_tshark, capture_file, features, test_env):
        '''Verify that TLS reassembly over TCP reassembly works.'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        self.check_tls_reassembly_over_tcp_reassembly(cmd_tshark, capture_file, test_env)

    def test_tls_reassembly_over_tcp_reassembly_2(self, cmd_tshark, capture_file, features, test_env):
        '''Verify that TLS reassembly over TCP reassembly works (second pass).'''
        # pinfo->curr_layer_num can be different on the second pass than the
        # first pass, because the HTTP dissector isn't called for the first
        # TLS record on the second pass.
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        self.check_tls_reassembly_over_tcp_reassembly(cmd_tshark, capture_file,
            test_env, extraArgs=['-2'])

    @staticmethod
    def check_tls_out_of_order(cmd_tshark, capture_file, test_env, extraArgs=None):
        if extraArgs is None:
            extraArgs = []
        stdout = subprocess.check_output([cmd_tshark,
                '-r', capture_file('challenge01_ooo_stream.pcapng.gz'),
                '-otcp.reassemble_out_of_order:TRUE',
                '-q',
                '-zhttp,stat,png or image-jfif',
            ] + extraArgs, encoding='utf-8', env=test_env)
        assert grep_output(stdout, r'200 OK\s*11')

    def test_tls_out_of_order(self, cmd_tshark, capture_file, features, test_env):
        '''Verify that TLS reassembly over TCP reassembly works.'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        self.check_tls_out_of_order(cmd_tshark, capture_file, test_env)

    def test_tls_out_of_order_second_pass(self, cmd_tshark, capture_file, features, test_env):
        '''Verify that TLS reassembly over TCP reassembly works (second pass).'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        self.check_tls_out_of_order(cmd_tshark, capture_file,
            test_env, extraArgs=['-2'])

class TestDissectRoq:
    def test_roq_recognized(self, cmd_tshark, capture_file, test_env):
        '''Verify that RTP over QUIC packets are recognized as RoQ.'''
        stdout = subprocess.check_output((
            cmd_tshark,
            '-2',
            '-d', 'udp.port==4433,quic',
            '-r', capture_file('roq-with-keys.pcapng.gz'),
            '-Y', 'roq',
            '-Tfields', '-e', 'frame.number',
        ), encoding='utf-8', env=test_env)

        assert stdout.splitlines() == ['9', '88', '165', '243']

    def test_roq_payload_is_rtp(self, cmd_tshark, capture_file, test_env):
        '''Verify that RoQ media payload is handed to the RTP dissector.'''
        stdout = subprocess.check_output((
            cmd_tshark,
            '-2',
            '-d', 'udp.port==4433,quic',
            '-r', capture_file('roq-with-keys.pcapng.gz'),
            '-Y', 'roq && rtp',
            '-Tfields', '-e', 'frame.number',
        ), encoding='utf-8', env=test_env)

        assert stdout.splitlines() == ['88', '165', '243']

class TestDissectQuic:
    @staticmethod
    def check_quic_tls_handshake_reassembly(cmd_tshark, capture_file, test_env,
                                       extraArgs=None):
        # An assortment of QUIC carrying TLS handshakes that need to be
        # reassembled, including fragmented in one packet, fragmented in
        # multiple packets, fragmented in multiple out of order packets,
        # retried, retried with overlap from the original packets, and retried
        # with one of the original packets missing (but all data there.)
        # Include -zexpert just to be sure that nothing Warn or higher occurred.
        # Note level expert infos may be expected with the overlaps and
        # retransmissions.
        if extraArgs is None:
            extraArgs = []

        stdout = subprocess.check_output([cmd_tshark,
                               '-r', capture_file('quic-fragmented-handshakes.pcapng.gz'),
                               '-zexpert,warn',
                               '-Ytls.handshake.type',
                               '-o', 'gui.column.format:"Handshake Type","%Cus:tls.handshake.type:0:R"',
                               ] + extraArgs,
                               encoding='utf-8', env=test_env)
        assert count_output(stdout, 'Client Hello') == 18
        assert count_output(stdout, 'Server Hello') == 2
        assert count_output(stdout, 'Finished') == 2
        assert count_output(stdout, 'New Session Ticket,New Session Ticket') == 1
        assert count_output(stdout, 'Certificate') == 2
        assert not grep_output(stdout, 'Warns')
        assert not grep_output(stdout, 'Errors')

    def test_quic_tls_handshake_reassembly(self, cmd_tshark, capture_file, test_env):
        '''Verify that QUIC and TLS handshake reassembly works.'''
        self.check_quic_tls_handshake_reassembly(cmd_tshark, capture_file, test_env)

    def test_quic_tls_handshake_reassembly_2(self, cmd_tshark, capture_file, test_env):
        '''Verify that QUIC and TLS handshake reassembly works (second pass).'''
        self.check_quic_tls_handshake_reassembly(
            cmd_tshark, capture_file, test_env, extraArgs=['-2'])

    def test_quic_multiple_retry(self, cmd_tshark, capture_file, test_env):
        '''Verify that a second Retry is correctly ignored.'''
        stdout = subprocess.check_output([cmd_tshark,
                               '-r', capture_file('quic-double-retry.pcapng.gz'),
                               '-zexpert,warn',
                               ],
                               encoding='utf-8', env=test_env)
        assert not grep_output(stdout, 'Warns')
        assert not grep_output(stdout, 'Errors')

@pytest.mark.parametrize("pass_args", [(), ("-2",)], ids=["one-pass", "two-pass"])
class TestDissectMoqLite:
    '''
    moq-lite-05 over QUIC. The capture was generated with aioquic and exercises
    every message of the draft, including a frame that spans several QUIC
    packets and a group delivered as a datagram.
    '''
    def test_moq_lite_messages(self, cmd_tshark, capture_file, test_env, pass_args):
        '''Every moq-lite message is dissected on the expected stream.'''
        stdout = subprocess.check_output((cmd_tshark, *pass_args,
                '-r', capture_file('moq-lite-05.pcapng.gz'),
                '-Y', 'moql',
                '-T', 'fields', '-e', 'moql.message_type',
            ), encoding='utf-8', env=test_env)
        messages = [m for line in stdout.splitlines() for m in line.split(',') if m]
        # SETUP, ANNOUNCE_REQUEST, ANNOUNCE_OK, 2x ANNOUNCE_BROADCAST, ...
        assert messages.count('1') == 2      # SETUP, one per direction
        assert messages.count('10') == 2     # ANNOUNCE_BROADCAST
        assert messages.count('23') == 5     # FRAME
        # Every message of the draft appears at least once.
        assert set(messages) == {'1', '8', '9', '10', '11', '12', '14', '15',
                                 '16', '17', '18', '19', '20', '21', '22', '23'}

    def test_moq_lite_subscription(self, cmd_tshark, capture_file, test_env, pass_args):
        '''Group streams and datagrams are matched to their subscription.'''
        stdout = subprocess.check_output((cmd_tshark, *pass_args,
                '-r', capture_file('moq-lite-05.pcapng.gz'),
                '-Y', 'moql.group_sequence',
                '-T', 'fields', '-e', 'moql.group_sequence',
                '-e', 'moql.broadcast_path', '-e', 'moql.track_name',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '^6\t/room/alice\tvideo$')      # FETCH
        assert grep_output(stdout, '^8\t/room/alice\tvideo$')      # GROUP
        assert grep_output(stdout, '^12\t/room/alice\tvideo$')     # datagram
        # The GROUP and each of its three FRAMEs carry the annotation.
        assert grep_output(stdout, r'^7\t(/room/alice,){3}/room/alice\t(video,){3}video$')

    def test_moq_lite_frame_timestamps(self, cmd_tshark, capture_file, test_env, pass_args):
        '''Frame timestamps accumulate the zigzag encoded deltas.'''
        stdout = subprocess.check_output((cmd_tshark, *pass_args,
                '-r', capture_file('moq-lite-05.pcapng.gz'),
                '-Y', 'moql.frame.timestamp',
                '-T', 'fields', '-e', 'moql.frame.timestamp_delta',
                '-e', 'moql.frame.timestamp',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '^0,33,-3\t0,33,30$')

    def test_moq_lite_reassembly(self, cmd_tshark, capture_file, test_env, pass_args):
        '''A frame spanning several QUIC packets is reassembled.'''
        stdout = subprocess.check_output((cmd_tshark, *pass_args,
                '-r', capture_file('moq-lite-05.pcapng.gz'),
                '-Y', 'moql.message_length > 1000',
                '-T', 'fields', '-e', 'moql.message_length',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['5120']

    def test_moq_lite_no_reassembly(self, cmd_tshark, capture_file, test_env, pass_args):
        """Disabling reassembly leaves the split frame incomplete."""
        stdout = subprocess.check_output((cmd_tshark, *pass_args,
                '-r', capture_file('moq-lite-05.pcapng.gz'),
                '-o', 'moql.desegment:FALSE',
                '-Y', 'moql.incomplete_message || moql.message_length == 5120',
                '-T', 'fields', '-e', 'moql.incomplete_message',
                '-e', 'moql.message_length',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip()
        assert all(line.startswith('1\t') for line in stdout.splitlines())
        assert '5120' not in stdout

    def test_moq_lite_expert(self, cmd_tshark, capture_file, test_env, pass_args):
        '''Only the deliberately unknown stream type is flagged.'''
        stdout = subprocess.check_output((cmd_tshark, *pass_args,
                '-r', capture_file('moq-lite-05.pcapng.gz'),
                '-zexpert,warn,moql', '-Y', 'moql',
                ), encoding='utf-8', env=test_env)
        assert not grep_output(stdout, 'Errors')
        assert count_output(stdout, 'Unknown bidirectional stream type') == 1
        assert 'Warns (1)' in stdout


@pytest.mark.parametrize("pass_args", [(), ("-2",)], ids=["one-pass", "two-pass"])
class TestDissectMoqLiteEdges:
    @pytest.mark.parametrize("name,delta", [("positive", (1 << 61) - 1),
                                           ("negative", -(1 << 61))])
    def test_timestamp_limits(self, cmd_tshark, capture_file, test_env, pass_args, name, delta):
        rows = self.read(cmd_tshark, capture_file, test_env, pass_args,
                         f'moql.message_type == 23 && moql.track_name == "{name}"',
                         "moql.frame.timestamp", "moql.frame.time", "moql.protocol_violation")
        expected = []
        for count in range(1, 5):
            timestamp = delta * count
            nanos = abs(timestamp) * 1_000_000_000 // ((1 << 62) - 1)
            seconds, fraction = divmod(nanos, 1_000_000_000)
            sign = "-" if timestamp < 0 else ""
            expected.append([str(timestamp), f"{sign}{seconds}.{fraction:09d}", ""])
        # Once the running sum overflows, subsequent absolute times are unknown.
        assert rows == expected + [["", "", "1"], ["", "", "1"]]

    def test_track_identity(self, cmd_tshark, capture_file, test_env, pass_args):
        rows = self.read(cmd_tshark, capture_file, test_env, pass_args,
                         'moql.frame.timestamp == 1000 && moql.broadcast_path != "/nul"',
                         "moql.broadcast_path", "moql.track_name", "moql.frame.time")
        assert rows == [
            ["/long", "t" * 400 + "A", "1.000000000"],
            ["/long", "t" * 400 + "B", "0.500000000"],
            [r"/a\\nb", "c", "1.000000000"],
            ["/a", r"b\\nc", "0.500000000"],
        ]

    def test_embedded_nul_identity(self, cmd_tshark, capture_file, test_env, pass_args):
        rows = self.read(cmd_tshark, capture_file, test_env, pass_args,
                         'moql.frame.timestamp == 1000 && moql.broadcast_path == "/nul"',
                         "moql.frame.time")
        assert rows == [["1.000000000"], ["0.500000000"], ["0.250000000"]]

    def test_draft04_alpn(self, cmd_tshark, capture_file, test_env, pass_args):
        rows = self.read(cmd_tshark, capture_file, test_env, pass_args,
                         'moql.frame.payload == 6f:6c:64',
                         "moql.message_type", "moql.frame.timestamp", "_ws.malformed")
        assert rows == [["23", "", ""]]

    @staticmethod
    def read(cmd_tshark, capture_file, test_env, pass_args, display_filter, *fields):
        command = [
            cmd_tshark, *pass_args,
            '-r', capture_file('moq-lite-edge.pcapng.gz'),
            '-d', 'udp.port==4433,quic',
            '-Y', display_filter,
            '-T', 'fields',
        ]
        for field in fields:
            command.extend(('-e', field))

        output = subprocess.check_output(
            command, encoding='utf-8', env=test_env
        )
        return [line.split('\t') for line in output.splitlines()]

class TestDissectMoqLiteDatagram:
    @pytest.mark.parametrize("encoded,value", [
        ("3f", "63"),
        ("4040", "64"),
        ("80004000", "16384"),
        ("c000000040000000", "1073741824"),
        ("ffffffffffffffff", "4611686018427387903"),
    ])
    def test_varints(self, cmd_text2pcap, cmd_tshark, result_file, test_env, encoded, value):
        """All QUIC varint widths preserve IDs, sequences and timestamps."""
        fields = self.dissect(cmd_text2pcap, cmd_tshark, result_file, test_env,
                              bytes.fromhex(encoded * 3 + "abcd"))
        assert fields == [value, value, value, "abcd", "", ""]

    @pytest.mark.parametrize("payload", [
        "40", "8000", "c0000000",  # truncated subscription ID
        "0040", "00008000",      # truncated sequence or timestamp
    ])
    def test_truncated(self, cmd_text2pcap, cmd_tshark, result_file, test_env, payload):
        """A truncated varint is reported as malformed without crashing."""
        fields = self.dissect(cmd_text2pcap, cmd_tshark, result_file, test_env,
                              bytes.fromhex(payload))
        assert "_ws.malformed" in fields[-1].split(",")

    @pytest.mark.parametrize("size,violation", [(1200, ""), (1201, "1")])
    def test_size_limit(self, cmd_text2pcap, cmd_tshark, result_file, test_env, size, violation):
        """The datagram limit includes its three varint headers."""
        fields = self.dissect(cmd_text2pcap, cmd_tshark, result_file, test_env,
                              b"\x00" * size)
        assert fields[4:] == [violation, ""]
        assert len(fields[3]) == (size - 3) * 2

    @staticmethod
    def dissect(cmd_text2pcap, cmd_tshark, result_file, test_env, payload):
        # Exported PDUs invoke the real datagram dissector without QUIC encryption.
        text_file = result_file("moql.txt")
        capture = result_file("moql.pcapng")
        with open(text_file, "w") as output:
            output.writelines(f"{offset:06x}  {payload[offset:offset + 16].hex(' ')}\n" for offset in range(0, len(payload), 16))
        subprocess.check_call((cmd_text2pcap, "-q", "-P", "moq-lite.datagram",
                               text_file, capture), env=test_env)
        command = [cmd_tshark, "-r", capture, "-T", "fields"]
        for field in ("moql.subscribe_id", "moql.group_sequence", "moql.datagram.timestamp",
                      "moql.frame.payload", "moql.protocol_violation", "_ws.malformed"):
            command.extend(("-e", field))
        return subprocess.check_output(command, encoding="utf-8", env=test_env).rstrip("\n").split("\t")


class TestDecompressSmb2:
    @staticmethod
    def extract_compressed_payload(cmd_tshark, capture_file, test_env, frame_num):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('smb311-lz77-lz77huff-lznt1.pcap.gz'),
                '-Tfields', '-edata.data',
                '-Y', f'frame.number == {frame_num}'
        ), encoding='utf-8', env=test_env)
        assert b'a'*4096 == bytes.fromhex(stdout.strip())

    def test_smb311_read_lz77(self, cmd_tshark, capture_file, test_env):
        self.extract_compressed_payload(cmd_tshark, capture_file, test_env, 1)

    def test_smb311_read_lz77huff(self, cmd_tshark, capture_file, test_env):
        self.extract_compressed_payload(cmd_tshark, capture_file, test_env, 2)

    def test_smb311_read_lznt1(self, cmd_tshark, capture_file, test_env):
        if sys.byteorder == 'big':
            pytest.skip('this test is supported on little endian only')
        self.extract_compressed_payload(cmd_tshark, capture_file, test_env, 3)

    def extract_chained_compressed_payload(self, cmd_tshark, capture_file, test_env, frame_num):
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('smb311-chained-patternv1-lznt1.pcapng.gz'),
            '-Tfields', '-edata.data',
            '-Y', f'frame.number == {frame_num}'
        ), encoding='utf-8', env=test_env)
        assert b'\xaa'*256 == bytes.fromhex(stdout.strip())

    def test_smb311_chained_lznt1_patternv1(self, cmd_tshark, capture_file, test_env):
        if sys.byteorder == 'big':
            pytest.skip('this test is supported on little endian only')
        self.extract_chained_compressed_payload(cmd_tshark, capture_file, test_env, 1)

    def test_smb311_chained_none_patternv1(self, cmd_tshark, capture_file, test_env):
        self.extract_chained_compressed_payload(cmd_tshark, capture_file, test_env, 2)

class TestDissectCommunityId:
    @staticmethod
    def check_baseline(dirs, output, baseline):
        baseline_file = os.path.join(dirs.baseline_dir, baseline)
        with open(baseline_file) as f:
            baseline_data = f.read()

        assert output == baseline_data

    def test_communityid(self, cmd_tshark, features, dirs, capture_file, test_env):
        # Run tshark on our Community ID test pcap, enabling the
        # postdissector (it is disabled by default), and asking for
        # the Community ID value as field output. Verify that this
        # exits successfully:
        stdout = subprocess.check_output(
            (cmd_tshark,
             '--enable-protocol', 'communityid',
             '-r', capture_file('communityid.pcap.gz'),
             '-Tfields', '-ecommunityid.hash',
             ), encoding='utf-8', env=test_env)

        self.check_baseline(dirs, stdout, 'communityid.txt')

    def test_communityid_filter(self, cmd_tshark, features, dirs, capture_file, test_env):
        # Run tshark on our Community ID test pcap, enabling the
        # postdissector and filtering the result.
        stdout = subprocess.check_output(
            (cmd_tshark,
             '--enable-protocol', 'communityid',
             '-r', capture_file('communityid.pcap.gz'),
             '-Tfields', '-ecommunityid.hash',
             'communityid.hash=="1:d/FP5EW3wiY1vCndhwleRRKHowQ="'
             ), encoding='utf-8', env=test_env)

        self.check_baseline(dirs, stdout, 'communityid-filtered.txt')

class TestDissectTns:
    '''TNS (Oracle wire protocol) dissector tests, exercising two captures
    that previously tripped buffer-overrun / wrong-state bugs in the OPI
    parameter-value path.'''

    def test_tns_malformed_piggyback(self, cmd_tshark, capture_file, test_env):
        '''A cursor count or an integer width chosen by the sender is malformed
        input, not a dissector bug.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_malformed.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-V',
        ), encoding='utf-8', env=test_env)
        # A count larger than the packet is reported against the count itself
        assert grep_output(stdout, 'Cursor count is larger than the data left')
        # and neither frame may be blamed on the dissector
        assert not grep_output(stdout, 'Dissector bug')

    def test_tns_bad(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bad.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_opi.param_value == "06DE79977310E5B78E5A9493CB4FB3D6F5A0975F2B3B5D46737189DD4B7B92AA1A36B309D39D4471568CE287A52093BA"',
        ), encoding='utf-8', env=test_env)
        assert 'Return OPI Parameter' in stdout

    def test_tns_bad2(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bad2.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_opi.param_value == "7BD0E1244A35B13E8E194519B105257020D2DAC3816B3C5F5A71D0A3E5C217C6E796E1B592719A0FD47B7A18EF8A0311"',
        ), encoding='utf-8', env=test_env)
        assert 'Return OPI Parameter' in stdout

    def test_tns_dty(self, cmd_tshark, capture_file, test_env):
        '''TTI_DTY (Set Datatypes) request: charset fields, capability
        header, table header, identity map, and ~50 type-override entries
        must all decode without losing sync.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dty.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_id',
            '-e', 'tns.data_setdt.charset_in',
            '-e', 'tns.data_setdt.charset_out',
            '-e', 'tns.data_setdt.caphdr.version',
            '-e', 'tns.data_setdt.override.client',
        ), encoding='utf-8', env=test_env)
        # data_id = 2 (Set Datatypes); charset = 871 (UTF8) both ways;
        # version triple in capability header = 0x260601 (38, 6, 1);
        # override client list ends with the 0 terminator and includes
        # both long entries (e.g. 91) and short entries (e.g. 13).
        fields = stdout.strip().split('\t')
        assert fields[0] == '0x00000002', fields
        assert fields[1] == '871' and fields[2] == '871', fields
        assert fields[3] == '0x260601', fields
        clients = fields[4].split(',')
        assert clients[0] == '2' and clients[-1] == '0', clients
        assert '91' in clients and '13' in clients, clients

    def test_tns_oer(self, cmd_tshark, capture_file, test_env):
        '''TTI_OER (Oracle Error Return) decodes call_status, rowcount,
        err_code, cursor_id, and the trailing ORA-NNNNN message text.
        Four frames: a successful DML (rowcount=3, err=0), a failed DML
        (err=1, with message body), one whose message is the null marker,
        and one carrying a non-empty oerrdd.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oer.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_oer.call_status',
            '-e', 'tns.data_oer.rowcount',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.cursor_id',
            '-e', 'tns.data_oer.message',
        ), encoding='utf-8', env=test_env)
        # Not stdout.strip(): the last row ends in an empty field, and
        # stripping would take the tab that holds it with the newline.
        rows = [r.split('\t') for r in stdout.splitlines() if r]
        assert len(rows) == 4, rows
        assert rows[0] == ['0', '3', '0', '42', ''], rows[0]
        assert rows[1][0] == '0' and rows[1][2] == '1' and rows[1][3] == '42', rows[1]
        assert 'ORA-00001' in rows[1][4], rows[1]
        # 0xFF is the null marker and stands for itself. Read as a length it
        # claims 255 bytes that are not there.
        assert rows[2][2] == '1722' and rows[2][3] == '9', rows[2]
        assert rows[2][4] == '', rows[2]
        # oerrdd is a ub4 count and then a DALC, not a bare DALC. Taking the
        # count for a length puts every later field one field early, and the
        # message is the first thing that visibly goes missing.
        assert rows[3][2] == '942' and rows[3][3] == '7', rows[3]
        assert 'ORA-00942' in rows[3][4], rows[3]

    def test_tns_oer_no_malformed(self, cmd_tshark, capture_file, test_env):
        '''No OER frame may be reported as malformed.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oer.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', '_ws.malformed',
            '-T', 'fields', '-e', 'frame.number',
        ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '', stdout

    def test_tns_iov(self, cmd_tshark, capture_file, test_env):
        '''TTI_IOV (I/O vector) decodes the bind count and the per-bind
        direction vector. Two frames: a PL/SQL block with IN/OUT/IN OUT
        binds (followed by a TTI_RXD row of returned values, left raw), and
        a block with two pure-IN binds (no values follow).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_iov.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_id',
            '-e', 'tns.data_iov.num_binds',
            '-e', 'tns.data_iov.bind_dir',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # data_id = 11 (Sending I/O Vec only for fast UPI).
        assert rows[0][0] == '0x0000000b', rows[0]
        # 16 = OUT, 32 = IN, 48 = IN OUT.
        assert rows[0][1] == '3' and rows[0][2] == '32,16,48', rows[0]
        assert rows[1][1] == '2' and rows[1][2] == '32,32', rows[1]

    def test_tns_dcb(self, cmd_tshark, capture_file, test_env):
        '''TTI_DCB (Describe) decodes the column count and per-column
        metadata (type, scale, charset, name), and TTI_RXH (Row Header)
        decodes the iteration counts. Two frames: a 2-column describe
        (NUMBER "ID" / VARCHAR2 "NAME") and a row header.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dcb.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_dcb.num_columns',
            '-e', 'tns.data_col.type',
            '-e', 'tns.data_col.scale',
            '-e', 'tns.data_col.charset',
            '-e', 'tns.data_col.name',
            '-e', 'tns.data_rxh.num_iters',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # DCB: 2 columns; types 2 (NUMBER) and 1 (VARCHAR); NUMBER scale
        # -127; VARCHAR charset 873 (AL32UTF8); names ID and NAME.
        assert rows[0][0] == '2', rows[0]
        assert rows[0][1] == '2,1', rows[0]
        assert '-127' in rows[0][2].split(','), rows[0]
        assert '873' in rows[0][3].split(','), rows[0]
        assert rows[0][4] == 'ID,NAME', rows[0]
        # RXH: num_iters = 2.
        assert rows[1][5] == '2', rows[1]

    def test_tns_all8(self, cmd_tshark, capture_file, test_env):
        '''TTI_ALL8 (SQL execute) decodes the options bitmask, fetch rows,
        bind count and the SQL text. Three frames: a SELECT (options 0x8021,
        fetch 15), an autocommit DELETE (options 0x8121), and a two-bind
        UPDATE (options 0x8029).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_all8.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_oci.id',
            '-e', 'tns.data_all8.options',
            '-e', 'tns.data_all8.options.commit',
            '-e', 'tns.data_all8.fetch_rows',
            '-e', 'tns.data_all8.bind_count',
            '-e', 'tns.data_all8.sql',
            '-e', 'tns.data_col.type',
            '-e', 'tns.data_bind.value',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 3, rows
        # oci id 0x5e = 94 (TTI_ALL8) on all.
        assert all(r[0] == '0x5e' for r in rows), rows
        # SELECT: options 0x8021, autocommit off, fetch 15, no binds.
        assert rows[0][1] == '0x00008021', rows[0]
        assert rows[0][2] == 'False' and rows[0][3] == '15' and rows[0][4] == '0', rows[0]
        assert rows[0][5] == 'SELECT ID, NAME FROM USERS', rows[0]
        # DELETE: options 0x8121, autocommit on, fetch 0.
        assert rows[1][1] == '0x00008121', rows[1]
        assert rows[1][2] == 'True' and rows[1][3] == '0', rows[1]
        assert rows[1][5] == 'DELETE FROM USERS WHERE ID = 5', rows[1]
        # UPDATE with two binds: VARCHAR (1) then NUMBER (2), values "hi"
        # (6869) and Oracle NUMBER 10 (c10b).
        assert rows[2][1] == '0x00008029' and rows[2][4] == '2', rows[2]
        assert rows[2][5] == 'UPDATE USERS SET NAME=:1 WHERE ID=:2', rows[2]
        assert rows[2][6] == '1,2', rows[2]
        assert rows[2][7] == '6869,c10b', rows[2]

    def test_tns_fetch(self, cmd_tshark, capture_file, test_env):
        '''TTI_FETCH decodes the cursor id and row count. Two frames:
        fetch 15 rows from cursor 3, and 100 rows from cursor 7.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_fetch.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_oci.id',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_fetch.rows',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # oci id 0x05 = 5 (TTI_FETCH / "Fetch a Row").
        assert rows[0] == ['0x05', '3', '15'], rows[0]
        assert rows[1] == ['0x05', '7', '100'], rows[1]

    def test_tns_lobops(self, cmd_tshark, capture_file, test_env):
        '''TTI_LOBOPS decodes the operation, the source offset, the locator,
        and what trails it. Four frames: a READ (op 0x0002) of 8192 and a
        GET_LENGTH (op 0x0001), both from source offset 1; a CREATE_TEMP
        (op 0x0110) with its charset; a WRITE (op 0x0040) of 6 bytes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lobops.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_oci.id',
            '-e', 'tns.data_lob.op',
            '-e', 'tns.data_lob.offset',
            '-e', 'tns.data_lob.amount',
            '-e', 'tns.data_lob.charset',
            '-e', 'tns.data_lob.data',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 4, rows
        # oci id 0x60 = 96 (TTI_LOBOPS / "LOB and FILE related calls").
        assert rows[0] == ['0x60', '0x00000002', '1', '8192', '', '', ''], rows[0]
        assert rows[1] == ['0x60', '0x00000001', '1', '', '', '', ''], rows[1]
        assert rows[2] == ['0x60', '0x00000110', '', '', '873', '', ''], rows[2]
        assert rows[3] == ['0x60', '0x00000040', '1', '', '', '006100620063', ''], rows[3]

    def test_tns_marker(self, cmd_tshark, capture_file, test_env):
        '''TNS_MARKER decodes the break/reset function byte. Two frames:
        a break marker (01 00 01) and a reset marker (01 00 02).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_marker.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.type',
            '-e', 'tns.marker.function',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # packet type 12 = Marker; function 1 = break, 2 = reset.
        assert rows[0] == ['12', '1'], rows[0]
        assert rows[1] == ['12', '2'], rows[1]

    def test_tns_rxd(self, cmd_tshark, capture_file, test_env):
        '''TTI_RXD row data is split into per-column values using the column
        types remembered from the preceding TTI_DCB (threaded through
        conversation state). A describe of two columns (NUMBER, VARCHAR2)
        then a row-data packet of two rows: (10, "hi") and (20, NULL).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rxd.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'tns.data_dcb.num_columns',
            '-e', 'tns.data_col.value',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # Frame 1 describes 2 columns; frame 2 carries their values.
        assert rows[0][1] == '2', rows[0]
        # NUMBER 10 (c10b), VARCHAR "hi" (6869), NUMBER 20 (c115), NULL (00).
        assert rows[1][2] == 'c10b,6869,c115,00', rows[1]

    def test_tns_rxd_types(self, cmd_tshark, capture_file, test_env):
        '''TTI_RXD splits a row with mixed column kinds using their per-type
        value framings: an ordinary NUMBER, a structured ROWID, a LONG, and
        a DATE (rendered as a datetime).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rxd_types.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'tns.data_col.value',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # NUMBER 10 shown data-only (c10b); ROWID and LONG shown whole:
        #   ROWID: 0a | 0164 | 0104 | 00 | 0132 | 00
        #   LONG "abc": 03 616263 | 00 | 00
        #   DATE: 787c010f0b1f01
        vals = rows[1][1].split(',')
        assert len(vals) == 6, vals
        assert vals[0] == 'c10b', vals
        assert vals[1] == '0a0164010400013200', vals
        assert vals[2] == '036162630000', vals
        assert vals[3] == '787c010f0b1f01', vals
        assert vals[4] == 'bfc00000', vals
        assert vals[5] == 'c002000000000000', vals
        # DATE and the binary floats are rendered in the tree label.
        verbose = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rxd_types.pcap'),
            '-d', 'tcp.port==1521,tns', '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert '2024-01-15 10:30:00' in verbose, verbose
        assert '(BINARY_FLOAT): 1.5' in verbose, verbose
        assert '(BINARY_DOUBLE): 2.25' in verbose, verbose

    def test_tns_oci_call_info(self, cmd_tshark, capture_file, test_env):
        '''The specific OCI call name is added to the Info column, not just
        the generic "User OCI Functions". A TTI_FETCH names "Fetch a Row".'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_fetch.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', '_ws.col.info',
        ), encoding='utf-8', env=test_env)
        lines = stdout.strip().splitlines()
        assert lines, stdout
        assert all('Fetch a Row' in line for line in lines), lines

    def test_tns_number_render(self, cmd_tshark, capture_file, test_env):
        '''A NUMBER row value is rendered as its decimal string in the tree
        (raw bytes stay filterable). The tns_rxd fixture carries 10 and 20.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rxd.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert '(NUMBER): 10' in stdout, stdout
        assert '(NUMBER): 20' in stdout, stdout
        # The VARCHAR value "hi" is rendered as text, not raw bytes.
        assert '(VARCHAR): hi' in stdout, stdout

    def test_tns_dalc_absent(self, cmd_tshark, capture_file, test_env):
        '''A bind value of FD 01 is the DALC absent-value placeholder, not a
        length of 253. The binds after it keep their values: NUMBER 10 and
        VARCHAR "ok".'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dalc_absent.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_bind.value',
            '-e', '_ws.expert',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 1, rows
        assert rows[0][0] == 'fd01,c10b,6f6b', rows[0]
        assert rows[0][1] == '', rows[0]
        verbose = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dalc_absent.pcap'),
            '-d', 'tcp.port==1521,tns', '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Bind 1 (VARCHAR): no value' in verbose, verbose
        assert 'Bind 3 (VARCHAR): ok' in verbose, verbose

    def test_tns_rxd_nodata(self, cmd_tshark, capture_file, test_env):
        '''A column the describe gives a zero data length carries no bytes in
        the row. Describe (NUMBER, VARCHAR of length 0, VARCHAR), then two
        rows that hold only the first and last values.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rxd_nodata.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (NUMBER): 10' in stdout, stdout
        assert 'Column 2 (VARCHAR): NULL (no data length)' in stdout, stdout
        assert 'Column 3 (VARCHAR): hi' in stdout, stdout
        assert 'Column 1 (NUMBER): 20' in stdout, stdout
        assert 'Column 3 (VARCHAR): yo' in stdout, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_piggyback(self, cmd_tshark, capture_file, test_env):
        '''The close-cursors piggyback is a pointer byte, a count and the
        cursor ids. Two frames: cursors 3 and 5, then 300 and 70000.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_piggyback.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_piggyback.id',
            '-e', 'tns.data.cursor',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [['0x69', '3,5'], ['0x69', '300,70000']], rows

    def test_tns_walk(self, cmd_tshark, capture_file, test_env):
        '''Every TTC message in a packet is decoded, not only the first. A
        close-cursors piggyback in front of an execute, then a response that
        carries describe, row header, two rows and the closing status.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_walk.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_all8.sql',
            '-e', 'tns.data_dcb.num_columns',
            '-e', 'tns.data_rxh.num_iters',
            '-e', 'tns.data_col.value',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.cursor_id',
            '-e', 'tns.data_oer.message',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 2, rows
        # The piggyback's two cursors, then the execute's own (new) cursor.
        assert rows[0][0] == '3,5,0', rows[0]
        assert rows[0][1] == 'SELECT ID, NAME FROM USERS', rows[0]
        assert rows[1][2] == '2' and rows[1][3] == '2', rows[1]
        assert rows[1][4] == 'c10b,6869,c115,796f', rows[1]
        assert rows[1][5] == '1403' and rows[1][6] == '7', rows[1]
        assert rows[1][7].startswith('ORA-01403: no data found'), rows[1]

    def test_tns_sta(self, cmd_tshark, capture_file, test_env):
        '''TTI_STA decodes its call status and end-to-end sequence, and the
        END_OF_RESPONSE marker behind it is named.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_sta.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_sta.call_status',
            '-e', 'tns.data_sta.seq',
            '-e', '_ws.col.info',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 3, rows
        assert rows[1][:2] == ['0x00000001', '0'], rows[1]
        assert rows[2][:2] == ['0x00000005', '300'], rows[2]
        assert rows[1][2].endswith('Function Complete, End of Response'), rows[1]

    def test_tns_txn(self, cmd_tshark, capture_file, test_env):
        '''The call status of TTI_OER and TTI_STA flags an open transaction
        (0x02). An uncommitted INSERT has it; a query and a commit do not.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_txn.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data.call_status.txn_in_progress',
        ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['True', 'False', 'False'], stdout

    def test_tns_all8_option_bits(self, cmd_tshark, capture_file, test_env):
        '''The execute options name FETCH (0x40) and NOT_PLSQL (0x8000) by
        their own bits. tns_all8.pcap's SELECT is 0x8021 (no fetch), the
        SELECT in tns_walk.pcap is 0x8061 (fetch).'''
        fields = ('-T', 'fields',
            '-e', 'tns.data_all8.options.fetch',
            '-e', 'tns.data_all8.options.not_plsql',
            '-Y', 'tns.data_all8.options')
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_all8.pcap'),
            '-d', 'tcp.port==1521,tns') + fields, encoding='utf-8', env=test_env)
        assert stdout.splitlines()[0].split('\t') == ['False', 'True'], stdout
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_walk.pcap'),
            '-d', 'tcp.port==1521,tns') + fields, encoding='utf-8', env=test_env)
        assert stdout.splitlines()[0].split('\t') == ['True', 'True'], stdout

    def test_tns_all8_parse_only(self, cmd_tshark, capture_file, test_env):
        '''cursor.parse() sends PARSE without EXECUTE, and a query adds
        DESCRIBE (0x20000). An executemany with batcherrors sets
        BATCH_ERRORS (0x80000).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_parse.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_all8.options.parse',
            '-e', 'tns.data_all8.options.execute',
            '-e', 'tns.data_all8.options.describe',
            '-e', 'tns.data_all8.options.batch_errors',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [
            ['True', 'False', 'True', 'False'],
            ['True', 'False', 'False', 'False'],
            ['True', 'True', 'False', 'True'],
            ['False', 'False', 'False', 'False'],
            ['False', 'False', 'False', 'False'],
            ['False', 'False', 'False', 'False'],
        ], rows

    def test_tns_all8_al8i4(self, cmd_tshark, capture_file, test_env):
        '''The al8i4 execute arguments: slot 1 is a prefetch row count for a
        query and an execution count for DML, told apart by slot 7; slot 9
        holds the execute flags, 10 and 11 a scroll position.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_al8i4.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_all8.prefetch',
            '-e', 'tns.data_all8.iterations',
            '-e', 'tns.data_all8.is_query',
            '-e', 'tns.data_all8.exec_flags.dml_rowcounts',
            '-e', 'tns.data_all8.exec_flags.scrollable',
            '-e', 'tns.data_all8.fetch_orientation',
            '-e', 'tns.data_all8.fetch_pos',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [
            ['0', '', 'True', 'False', 'False', '0x00000000', '0'],
            ['100', '', 'True', 'False', 'False', '0x00000000', '0'],
            ['', '4', 'False', 'True', 'False', '0x00000000', '0'],
            ['1', '', 'True', 'False', 'True', '0x00000020', '5'],
        ], rows

    def test_tns_all8_nosql_binds(self, cmd_tshark, capture_file, test_env):
        '''An execute with no SQL text still carries bind descriptors unless
        its bind area starts on a TTI_RXD. The first frame's descriptors and
        rows are decoded; the second frame has none and is not misread.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_all8_nosql.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_col.type',
            '-e', 'tns.data_bind.value',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 2, rows
        assert rows[0] == ['2,1', 'c104,63,c105,64', ''], rows[0]
        assert rows[1] == ['', '', ''], rows[1]

    def test_tns_all8_defines(self, cmd_tshark, capture_file, test_env):
        '''A define execute (options 0x8010) carries one OAC per column in
        place of binds. The define here asks for a CLOB column as LONG.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_define.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_all8.options',
            '-T', 'fields',
            '-e', 'tns.data_all8.options.define',
            '-e', 'tns.data_all8.bind_count',
            '-e', 'tns.data_all8.define_count',
            '-e', 'tns.data_col.type',
            '-e', 'tns.data_col.max_length',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [['True', '0', '1', '8', '2147483647']], rows

    def test_tns_define_rows(self, cmd_tshark, capture_file, test_env):
        '''The rows that answer a define are framed as the define asked, not
        as the describe said: a CLOB column defined as LONG arrives inline.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_define.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (LONG)' in stdout, stdout
        values = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_define.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_col.value',
            '-T', 'fields',
            '-e', 'tns.data_col.value',
        ), encoding='utf-8', env=test_env)
        # the LONG value "blob_4620" and its two trailing ub4 indicators
        assert values.strip() == '09626c6f625f343632300000', values

    def test_tns_reexecute(self, cmd_tshark, capture_file, test_env):
        '''The re-execute calls (4 and 78) carry a cursor, an iteration
        count and two options words. For 78 the count is a prefetch size.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_reexec.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_oci.id == 4 || tns.data_oci.id == 78',
            '-T', 'fields',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_reexec.iterations',
            '-e', 'tns.data_all8.prefetch',
            '-e', 'tns.data_all8.options.execute',
            '-e', 'tns.data_reexec.options2.commit',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [
            ['8', '1', '', 'False', 'True'],
            ['9', '', '100', 'True', 'False'],
        ], rows

    def test_tns_reexecute_binds(self, cmd_tshark, capture_file, test_env):
        '''Values sent without bind descriptors are typed by the execute
        that opened the cursor; its status names the cursor id. Both the
        REEXECUTE row and the descriptor-less TTI_ALL8 row are split.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_reexec.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'tns.data_bind.value',
        ), encoding='utf-8', env=test_env)
        values = dict(r.split('\t') for r in stdout.strip().splitlines())
        assert values['1'] == 'c102,726f7731', values
        assert values['3'] == 'c103,726f7732', values
        assert values['5'] == 'c104,726f7733', values

    def test_tns_return_params(self, cmd_tshark, capture_file, test_env):
        '''The TTI_RPA that answers an execute is a return-parameters block:
        al8o4 words, al8txl, key/value pairs, a registration, and the
        per-iteration row counts when DML_ROWCOUNTS was asked for.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rpa.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_rpa.num_al8o4',
            '-T', 'fields',
            '-e', 'tns.data_rpa.num_al8o4',
            '-e', 'tns.data_rpa.dml_rowcount',
            '-e', 'tns.data_kv.text',
            '-e', 'tns.data_kv.keyword',
            '-e', 'tns.data_oer.cursor_id',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [
            ['6', '1,1,0,2', '', '', '3'],
            ['6', '', 'PYO', '168', '0'],
            ['6', '', '', '', '4'],
        ], rows

    def test_tns_server_piggyback(self, cmd_tshark, capture_file, test_env):
        '''A server-side piggyback (0x17) is decoded by its opcode: the SYNC
        that reports a changed CURRENT_SCHEMA as key/value pairs, a logical
        transaction id, and a session return with its session id.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_spb.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_spb.opcode',
            '-T', 'fields',
            '-e', 'tns.data_spb.opcode',
            '-e', 'tns.data_kv.text',
            '-e', 'tns.data_kv.keyword',
            '-e', 'tns.data_spb.session_id',
            '-e', 'tns.data_spb.serial_num',
            '-e', 'tns.data_oer.err_code',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [
            ['5', 'PYO', '168,169', '', '', '0'],
            ['7,4', '', '', '123', '45', '0'],
        ], rows

    def test_tns_warning(self, cmd_tshark, capture_file, test_env):
        '''TTI_WRN carries a warning number and message; the status behind
        it is still decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_wrn.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_wrn.code',
            '-T', 'fields',
            '-e', 'tns.data_wrn.code',
            '-e', 'tns.data_wrn.message',
            '-e', 'tns.data_oer.err_code',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [['24344', 'ORA-24344: success with compilation error', '0']], rows

    def test_tns_bit_vector(self, cmd_tshark, capture_file, test_env):
        '''After a TTI_BVC a row sends only the columns whose bit is set; the
        others repeat the previous row. The row after the bit vector here is
        just the NUMBER 2, and the status behind it is still decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bvc.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (NUMBER): 2' in stdout, stdout
        assert 'Column 2 (VARCHAR): same as previous row' in stdout, stdout
        assert 'Column 3 (VARCHAR): same as previous row' in stdout, stdout
        assert 'ORA-01403' in stdout, stdout

    def test_tns_lob_column(self, cmd_tshark, capture_file, test_env):
        '''A CLOB / BLOB column value comes with or without the LOB's size
        and chunk size ahead of the locator; both forms are read.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lob_column.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_col.value',
            '-T', 'fields',
            '-e', 'tns.data_lob.size',
            '-e', 'tns.data_lob.chunk_size',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [['3000,5', '8060,8060']], rows
        verbose = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lob_column.pcap'),
            '-d', 'tcp.port==1521,tns', '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (BLOB): locator, size 3000' in verbose, verbose
        assert 'Column 1 (BLOB): NULL' in verbose, verbose
        assert 'Column 2 (CLOB): locator, size 5' in verbose, verbose
        assert 'Malformed' not in verbose, verbose

    def test_tns_json_vector_column(self, cmd_tshark, capture_file, test_env):
        '''A JSON or VECTOR column value carries its image in the row, in the
        LOB metadata framing with the image ahead of the locator. Both are
        consumed, so the NUMBER after them decodes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_json_column.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (JSON): OSON image, 42 bytes' in stdout, stdout
        assert 'Column 2 (VECTOR): vector image, 29 bytes' in stdout, stdout
        assert 'Column 3 (NUMBER): 7' in stdout, stdout
        assert 'Column 1 (JSON): NULL' in stdout, stdout
        assert 'Column 2 (VECTOR): locator only' in stdout, stdout
        assert 'Column 3 (NUMBER): 8' in stdout, stdout
        images = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_json_column.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_json.image',
            '-T', 'fields', '-e', 'tns.data_json.image',
        ), encoding='utf-8', env=test_env)
        assert images.strip().startswith('ff4a5a01'), images

    def test_tns_object_column(self, cmd_tshark, capture_file, test_env):
        '''An object column value is framed with its type OID, OID, snapshot,
        version, image length and flags; a NULL object keeps the frame with
        a zero image length. The NUMBER after each is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_object_column.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (ADT): object, 12-byte image' in stdout, stdout
        assert 'Column 2 (NUMBER): 7' in stdout, stdout
        assert 'Column 1 (ADT): NULL object' in stdout, stdout
        assert 'Column 2 (NUMBER): 8' in stdout, stdout
        toids = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_object_column.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_obj.toid',
            '-T', 'fields', '-e', 'tns.data_obj.toid', '-e', 'tns.data_obj.image',
        ), encoding='utf-8', env=test_env)
        assert toids.strip() == ('5b5c96bccc225afce0639600a8c02ca9,5b5c96bccc225afce0639600a8c02ca9'
                                 '\t8401fe0000000c0002c102ff'), toids

    def test_tns_cursor_column(self, cmd_tshark, capture_file, test_env):
        '''A CURSOR(...) column value carries its result set's describe
        inline and the cursor id; the next row follows straight after.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_cursor_column.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 2 (REFCURSOR): cursor 12' in stdout, stdout
        assert 'Column 1 (NUMBER): 2' in stdout, stdout
        assert 'Column 2 (REFCURSOR): cursor 13' in stdout, stdout
        assert 'Column 1: X (VARCHAR)' in stdout, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_cursor_fetch(self, cmd_tshark, capture_file, test_env):
        '''Before 23ai, a nested cursor in the rows of a TTI_FETCH reply is
        cut short to its length byte and cursor id, with no describe; the
        row after it decodes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_cursor_fetch.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 2 (REFCURSOR): cursor 3' in stdout, stdout
        assert 'Column 1 (NUMBER): 2' in stdout, stdout
        assert 'Column 2 (REFCURSOR): cursor 5' in stdout, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_refcursor_bind(self, cmd_tshark, capture_file, test_env):
        '''A client's REF CURSOR bind is a count of cursor ids and the ids:
        none for an OUT bind, the cursor passed for an IN one. The bind
        after it decodes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_refcursor_bind.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Bind 1 (REFCURSOR): a new cursor' in stdout, stdout
        assert 'Bind 1 (REFCURSOR): cursor 3' in stdout, stdout
        assert stdout.count('Bind 2 (NUMBER): 7') == 2, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_implicit_results(self, cmd_tshark, capture_file, test_env):
        '''The implicit result sets message carries, per result, a describe
        and the cursor id to fetch it with; the status behind it follows.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_implicit_results.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_irs.num_results',
            '-T', 'fields',
            '-e', 'tns.data_irs.num_results',
            '-e', 'tns.data_col.name',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_oer.err_code',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [['2', 'A,B', '21,22', '0']], rows

    def test_tns_out_binds(self, cmd_tshark, capture_file, test_env):
        '''The TTI_RXD after a TTI_IOV holds the OUT bind values, typed by
        the execute's binds and each followed by its actual length; IN binds
        have no value there. The status behind them is decoded too.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_out_binds.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
            '-Y', 'tns.data_iov.num_binds',
        ), encoding='utf-8', env=test_env)
        assert 'Bind 1 (NUMBER): 11' in stdout, stdout
        assert 'Bind 3 (VARCHAR): hi' in stdout, stdout
        assert 'Bind 2' not in stdout.split('Out Binds')[1], stdout
        assert 'Actual Length: 0' in stdout, stdout
        assert 'Oracle Error Return' in stdout, stdout

    def test_tns_lob_reply(self, cmd_tshark, capture_file, test_env):
        '''The reply to a LOB operation: LOB_DATA with the content for a
        READ, then return parameters holding the locator as the server now
        sees it and the amount, then the status.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lob_reply.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521',
            '-T', 'fields',
            '-e', 'tns.data_lob.data',
            '-e', 'tns.data_lob.amount',
            '-e', 'tns.data_oer.err_code',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['4142434445', '5', '0', ''],
            ['', '260', '0', ''],
        ], rows

    def test_tns_piggyback_bodies(self, cmd_tshark, capture_file, test_env):
        '''The piggybacks a thin client sends in front of a call are decoded
        by function, and the call behind them too: end-to-end attributes,
        set schema, close temporary LOBs and session state, then a commit.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_piggybacks.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_piggyback.module',
            '-e', 'tns.data_piggyback.action',
            '-e', 'tns.data_piggyback.schema',
            '-e', 'tns.data_lob.op',
            '-e', 'tns.data_lob.locator',
            '-e', 'tns.data_piggyback.session_state',
            '-e', 'tns.data_oci.id',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 1, rows
        r = rows[0]
        assert r[0:4] == ['mod', 'act', 'HR', '0x00080111'], r
        assert len(r[4].split(',')) == 2 and r[4].startswith('0026'), r
        assert r[5] == '0x0000000000000005' and r[6] == '0x0e', r

    def test_tns_connect_long(self, cmd_tshark, capture_file, test_env):
        '''A connect descriptor over 230 bytes is not in the CONNECT: the
        CONNECT gives its length and offset but ends there, and the
        descriptor follows in a Data packet of its own.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_connect_long.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.connect_data_length',
            '-e', 'tns.connect_data.next_packet',
            '-e', 'tns.connect_data',
            '-e', '_ws.col.info',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 2, rows
        assert rows[0][0] == '238' and rows[0][1] != '' and rows[0][2] == '', rows[0]
        assert rows[1][2].startswith('(DESCRIPTION=') and len(rows[1][2]) == 238, rows[1]
        assert rows[1][3].endswith('Connect Data'), rows[1]

    def test_tns_txn_priority(self, cmd_tshark, capture_file, test_env):
        '''A 23ai client sets its transaction priority with an ALTER SESSION
        piggyback in front of the next call, an empty value restoring the
        default, and the server reports it back as keyword 204 of a
        session-state sync.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_txn_priority.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'frame.number > 1',
            '-T', 'fields',
            '-e', 'tns.data_piggyback.alter_session_param',
            '-e', 'tns.data_piggyback.alter_session_value',
            '-e', 'tns.data_kv.keyword',
            '-e', 'tns.data_oci.id',
            '-e', 'data.len',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['TXN_PRIORITY', 'low', '', '0x0e', '', ''],
            ['', '', '204', '', '', ''],
            ['TXN_PRIORITY', '', '', '0x0e', '', ''],
        ], rows
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_txn_priority.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert ': TXN_PRIORITY' in stdout, stdout
        assert 'Session Parameter: TXN_PRIORITY = (default)' in stdout, stdout

    def test_tns_app_context(self, cmd_tshark, capture_file, test_env):
        '''An application context namespace is set or cleared with a
        piggyback in front of the next call. A zero byte ahead of the
        namespace comes from field version 12.1 on, and the call behind
        the piggyback decodes in either form.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_app_context.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_piggyback.app_context_op',
            '-T', 'fields',
            '-E', 'aggregator=|',
            '-e', 'tns.data_piggyback.app_context_op',
            '-e', 'tns.data_piggyback.app_context_namespace',
            '-e', 'tns.data_piggyback.app_context_attr',
            '-e', 'tns.data_piggyback.app_context_value',
            '-e', 'tns.data_oci.id',
            '-e', 'data.len',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['1', 'CLIENTCONTEXT', 'ATTR1|ATTR2', 'VALUE1|V2', '0x0e', '', ''],
            ['2', 'CLIENTCONTEXT', '', '', '0x0e', '', ''],
        ], rows

    def test_tns_rowid_render(self, cmd_tshark, capture_file, test_env):
        '''ROWID and UROWID values are rendered as the strings Oracle prints:
        an 18-character extended rowid, and "*" + base-64 for a logical
        UROWID.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_rowid.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (RID): AAAK6JAAEAAACGPAAA' in stdout, stdout
        assert 'Column 2 (UROWID): *BAEAGYMCwQL+' in stdout, stdout
        assert 'Column 1 (RID): NULL' in stdout, stdout
        assert 'Column 2 (UROWID): AAAK6JAAEAAACGPAAA' in stdout, stdout

    def test_tns_timestamp_tz_render(self, cmd_tshark, capture_file, test_env):
        '''TIMESTAMP WITH TIME ZONE holds the instant in UTC plus the zone.
        An offset zone is shown in local time with the offset, a named zone
        in UTC with its region id. The form a server sends an OCI client
        holds the local time already, flagged in the zone's hour byte.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_timestamp_tz.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert '(TIMESTAMP WITH TIME ZONE): 2024-01-15 10:30:00 +02:00' in stdout, stdout
        assert '(TIMESTAMP WITH TIME ZONE): 2024-01-15 20:00:00.500000000 -03:30' in stdout, stdout
        assert '(TIMESTAMP WITH TIME ZONE): 2024-06-01 12:00:00 UTC (time zone region 64)' in stdout, stdout
        assert '(TIMESTAMP WITH TIME ZONE): 2024-01-02 03:04:05.500000000 -05:30' in stdout, stdout
        assert '(TIMESTAMP WITH TIME ZONE): 2024-01-01 00:30:00 +02:00' in stdout, stdout

    def test_tns_interval_render(self, cmd_tshark, capture_file, test_env):
        '''INTERVAL values are rendered as Oracle writes an interval
        literal, sign included.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_interval.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert '(INTERVAL YEAR TO MONTH): 3-07' in stdout, stdout
        assert '(INTERVAL DAY TO SECOND): 5 04:03:02.123456000' in stdout, stdout
        assert '(INTERVAL YEAR TO MONTH): -1-02' in stdout, stdout
        assert '(INTERVAL DAY TO SECOND): -2 03:00:00' in stdout, stdout

    def test_tns_binary_integer_render(self, cmd_tshark, capture_file, test_env):
        '''A BINARY_INTEGER (type 3) value carries NUMBER bytes and is
        rendered as a number: c1 20 is 31, not raw bytes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_binary_integer.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (BINARY_INTEGER): 31' in stdout, stdout
        assert 'Column 1 (BINARY_INTEGER): 0' in stdout, stdout

    def test_tns_boolean_render(self, cmd_tshark, capture_file, test_env):
        '''BOOLEAN values are rendered as TRUE / FALSE; a NULL BOOLEAN bind
        is the FD 01 placeholder and the bind after it still decodes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_boolean.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (BOOLEAN): TRUE' in stdout, stdout
        assert 'Column 1 (BOOLEAN): FALSE' in stdout, stdout
        assert 'Column 1 (BOOLEAN): NULL' in stdout, stdout
        assert 'Bind 1 (BOOLEAN): TRUE' in stdout, stdout
        assert 'Bind 2 (BOOLEAN): no value' in stdout, stdout
        assert 'Bind 3 (NUMBER): 1' in stdout, stdout

    def test_tns_nchar_render(self, cmd_tshark, capture_file, test_env):
        '''A value of the national character set form travels as UTF-16BE,
        in a column and an OUT bind alike, and is rendered as text.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_nchar.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Column 1 (VARCHAR): Called' in stdout, stdout
        assert 'Column 2 (VARCHAR): hi' in stdout, stdout
        assert 'Bind 1 (VARCHAR): Called' in stdout, stdout

    def test_tns_oci_all8(self, cmd_tshark, capture_file, test_env):
        '''An OCI client's execute has a fixed preamble in one of two widths,
        told apart by where its second pointer indicator sits. The options,
        cursor id, bind count and SQL are found in both; SET AUTOCOMMIT ON
        shows as the options' commit bit.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_all8.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_all8.sql',
            '-T', 'fields',
            '-e', 'tns.data_all8.oci_preamble',
            '-e', 'tns.data_all8.options',
            '-e', 'tns.data_all8.options.commit',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_all8.bind_count',
            '-e', 'tns.data_all8.sql',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [
            ['OCI, wide (8-byte slots)', '0x00000000', 'False', '0', '0', 'SELECT * FROM DUAL'],
            ['OCI, narrow (4-byte slots)', '0x00000000', 'False', '5', '1', 'SELECT :v FROM DUAL'],
            ['OCI, narrow (4-byte slots)', '0x00008021', 'False', '0', '0', 'INSERT INTO T VALUES (1)'],
            ['OCI, narrow (4-byte slots)', '0x00008121', 'True', '0', '0', 'INSERT INTO T VALUES (1)'],
        ], rows

    def test_tns_oci_10_2_all8(self, cmd_tshark, capture_file, test_env):
        '''sqlplus 10.2 sends a narrow preamble with the SQL at 148 and real
        addresses in its pointer fields; the session's field version, from
        its data-type round, says which form it is.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_10_2_all8.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_all8.oci_preamble',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'tns.data_all8.oci_preamble',
            '-e', 'tns.data_all8.options',
            '-e', 'tns.data_all8.bind_count',
            '-e', 'tns.data_all8.sql',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        # Frame 5, on a connection whose negotiation was not seen, is not
        # taken for one.
        assert rows == [
            ['3', 'OCI, narrow (4-byte slots), 10.2', '0x00008061', '0', 'SELECT USER FROM DUAL'],
            ['4', 'OCI, narrow (4-byte slots), 10.2', '0x00040429', '1', 'BEGIN :r := 42; END;\\n'],
        ], rows

    def test_tns_oci_sql_length(self, cmd_tshark, capture_file, test_env):
        '''An OCI client declares the SQL's byte length in AL32UTF8 and three
        times it in any other character set; the SQL decodes either way.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_sql_length.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_all8.sql',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['select 1 from dual', '']] * 2, rows

    def test_tns_oci_status(self, cmd_tshark, capture_file, test_env):
        '''A server answers an OCI client with a fixed-width little-endian
        status block - 136 bytes, or a compact 24 - and a 7-byte TTI_STA
        for a commit. Its fields are decoded once the conversation is known
        to be an OCI client's. Outside a DML's status, the full block's
        warning flags say an object was created with compilation errors.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_status.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521',
            '-T', 'fields',
            '-e', 'tns.data_oer.oci_status',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.rowcount',
            '-e', 'tns.data_oer.command_type',
            '-e', 'tns.data_oer.call_seq',
            '-e', 'tns.data_oer.message',
            '-e', 'tns.data_sta.seq',
            '-e', 'tns.data_oer.warn_flags',
            '-e', 'tns.data_oer.warn_flags.compilation_error',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 5, rows
        assert rows[0][:5] == ['5', '942', '0', '3', '4'], rows[0]
        assert rows[0][5].startswith('ORA-00942'), rows[0]
        assert rows[0][7:] == ['0x00', 'False'], rows[0]
        assert rows[1][:5] == ['1', '0', '1', '2', '6'], rows[1]
        assert rows[1][7:] == ['', ''], rows[1]
        assert rows[2][:5] == ['1', '0', '0', '3', ''], rows[2]
        assert rows[3][6] == '7', rows[3]
        assert rows[4][:5] == ['1', '0', '0', '24', '9'], rows[4]
        assert rows[4][7:] == ['0x21', 'True'], rows[4]

    def test_tns_returning(self, cmd_tshark, capture_file, test_env):
        '''DML RETURNING ... INTO: the return binds send no value in the
        request, and the reply carries a row count and the values for each.
        A PL/SQL block is never this form.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_returning.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_bind.value',
            '-e', 'tns.data_oer.rowcount',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['78,c106', '', ''],
            ['c107,c108,78,78', '2', ''],
            ['79,fd01', '', ''],
        ], rows

    def test_tns_field_version(self, cmd_tshark, capture_file, test_env):
        '''The TTC field version is compile capability 7 of the client's
        TTI_DTY; the 11g client in tns_dty.pcap negotiated 6 (11.2).'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dty.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_setdt.field_version',
        ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '6', stdout

    def test_tns_chunked_field_version(self, cmd_tshark, capture_file, test_env):
        '''From field version 12.2 on, the chunks of a long value are
        prefixed with a ub4 length, not a single byte. The amount after a
        chunked LOB_DATA decodes only when that is honoured.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_chunked_122.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_lob.data',
            '-T', 'fields',
            '-e', 'tns.data.field_version',
            '-e', 'tns.data_lob.amount',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['8', '300', '']], rows

    def test_tns_describe_field_version(self, cmd_tshark, capture_file, test_env):
        '''From field version 12.2 a column descriptor's scale is one signed
        byte and an oaccolid follows its max size; the describe, its rows
        and bind descriptors all decode.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_describe_122.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_col.scale',
            '-e', 'tns.data_col.name',
            '-e', 'tns.data_col.value',
            '-e', 'tns.data_col.type',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[1] == ['-127,0', 'ID,NAME', '', '2,1', ''], rows[1]
        assert rows[2][2] == 'c10b,6869', rows[2]
        assert rows[3][3] == '112,2' and rows[3][4] == '', rows[3]

    def test_tns_describe_versions(self, cmd_tshark, capture_file, test_env):
        '''A describe's column fields depend on the field version: 23ai adds
        the SQL domain, annotations and vector dimensions; 10g lacks the uds
        flags and the query-cache key. The rows after both decode.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_describe_versions.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_col.domain_name',
            '-e', 'tns.data_col.annotation',
            '-e', 'tns.data_col.vector_dims',
            '-e', 'tns.data_col.value',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[1][0] == 'EMAIL_D' and rows[1][1] == 'DISPLAY', rows[1]
        assert rows[1][2] == '0,3,0', rows[1]
        assert rows[2][3] == '614062,00,c106', rows[2]
        assert rows[5][3] == 'c107' and rows[5][4] == '', rows[5]

    def test_tns_oer_extended(self, cmd_tshark, capture_file, test_env):
        '''From field version 12.1 the error block carries the error number
        and row count at full width, and from 20.1 the SQL type and a
        checksum; the message and the end-of-response marker follow. The
        row count is read on an error too: it is what the call managed
        before it raised.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oer_12c.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_oer.err_code',
            '-T', 'fields',
            '-e', 'tns.data_oer.err_num',
            '-e', 'tns.data_oer.rowcount64',
            '-e', 'tns.data_oer.message',
            '-e', '_ws.col.info',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[0][:2] == ['942', '0'], rows[0]
        assert rows[0][2].startswith('ORA-00942'), rows[0]
        assert rows[0][3].endswith('End of Response'), rows[0]
        assert rows[1][:3] == ['0', '70000', ''], rows[1]
        # a batch that raised on its third row still applied two
        assert rows[2][:2] == ['1', '2'], rows[2]
        assert '[2 rows applied]' in rows[2][3], rows[2]

    def test_tns_all8_field_version(self, cmd_tshark, capture_file, test_env):
        '''A 12.2 execute has more header fields than an 11g one and a
        length-prefixed SQL text; its SQL, bind descriptors and values
        decode.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_all8_12c.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_all8.sql',
            '-T', 'fields',
            '-e', 'tns.data_all8.sql',
            '-e', 'tns.data_col.type',
            '-e', 'tns.data_bind.value',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['UPDATE T SET S = :1 WHERE ID = :2', '1,2', '6869,c10b', '']], rows

    def test_tns_token(self, cmd_tshark, capture_file, test_env):
        '''From field version 23.1 ext 1 every call and piggyback header
        carries a ub8 token after its sequence number, and the reply echoes
        it in a TOKEN message. A 23ai request and reply decode in full.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_token.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data.token',
            '-T', 'fields',
            '-e', 'tns.data.token',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_all8.sql',
            '-e', 'tns.data_col.value',
            '-e', 'tns.data_oer.err_num',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['7,7', '3,0', 'SELECT 1 FROM DUAL', '', '', ''],
            ['7', '', '', 'c102', '1403', ''],
        ], rows

    def test_tns_auth_request(self, cmd_tshark, capture_file, test_env):
        '''The authentication calls carry the user, the mode and key/value
        pairs: the first the client's identity, the second the proof and
        the driver name.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_auth.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_auth.user',
            '-e', 'tns.data_auth.mode.with_password',
            '-e', 'tns.data_opi.param_name',
            '-e', 'tns.data_opi.param_value',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows[0][:2] == ['SCOTT', 'False'], rows[0]
        assert rows[0][2] == 'AUTH_TERMINAL,AUTH_PROGRAM_NM,AUTH_MACHINE,AUTH_PID,AUTH_SID', rows[0]
        assert rows[0][3] == 'pts/1,python3,db-client,4242,petro', rows[0]
        assert rows[1][:2] == ['SCOTT', 'True'], rows[1]
        assert rows[1][2] == 'AUTH_SESSKEY,AUTH_PASSWORD,SESSION_CLIENT_DRIVER_NAME', rows[1]

    def test_tns_pro_reply(self, cmd_tshark, capture_file, test_env):
        '''The server's TTI_PRO reply: after the banner its charset, the
        national charset from the fdo block, and its capabilities, offering
        field version 24.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_pro.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521',
            '-T', 'fields',
            '-e', 'tns.data_setp_resp.banner',
            '-e', 'tns.data_setp_resp.charset',
            '-e', 'tns.data_setp_resp.ncharset',
            '-e', 'tns.data_setp_resp.field_version',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['x86_64/Linux 2.4.xx', '873', '2000', '24', '']], rows

    def test_tns_tpc(self, cmd_tshark, capture_file, test_env):
        '''The two-phase commit calls carry an operation and an XID; the
        switch's reply returns a transaction context, the state change's
        the branch's new state.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_tpc.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_tpc.switch_op',
            '-e', 'tns.data_tpc.change_op',
            '-e', 'tns.data_tpc.format_id',
            '-e', 'tns.data_tpc.gtrid',
            '-e', 'tns.data_tpc.bqual',
            '-e', 'tns.data_tpc.context',
            '-e', 'tns.data_tpc.state',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[0][:5] == ['0x00000001', '', '4660', '67747269642d31', '62712d31'], rows[0]
        assert rows[1][5] == 'cafebabe', rows[1]
        assert rows[2][1] == '0x00000003' and rows[2][5] == 'cafebabe', rows[2]
        assert rows[3][6] == '1', rows[3]
        assert all(r[7] == '' for r in rows), rows

    def test_tns_session_release(self, cmd_tshark, capture_file, test_env):
        '''A DRCP session release carries a tag and a release mode.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_session_release.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_release.mode.deauthenticate',
        ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['False', 'True'], stdout

    def test_tns_newer_call_names(self, cmd_tshark, capture_file, test_env):
        '''The newer calls are named: the session-state piggyback (176) in
        tns_piggybacks.pcap.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_piggybacks.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Session state (0xb0)' in stdout, stdout

    def test_tns_pipeline(self, cmd_tshark, capture_file, test_env):
        '''A pipeline begins with a piggyback in front of a call and ends
        with its own call; both decode to their last byte.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_pipeline.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_piggyback.pipeline_mode',
            '-e', 'tns.data_oci.id',
            '-e', 'data.data',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['1', '0x0e', ''], ['', '0xc8', '']], rows

    def test_tns_ano(self, cmd_tshark, capture_file, test_env):
        '''The native network encryption negotiation: the algorithms a
        client offers and the ones the server picks are named.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_ano.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_sns.service',
            '-e', 'tns.data_sns.encryption',
            '-e', 'tns.data_sns.integrity',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['4,1,2,3', '0,17,16,15', '0,5,3', ''],
            ['4,2,3', '17', '5', ''],
            ['3', '', '', ''],
            ['', '', '', ''],
            ['', '', '', ''],
        ], rows

    def test_tns_ano_version(self, cmd_tshark, capture_file, test_env):
        '''A release word from 18c on packs the release update's fields,
        an older one the major, minor, component and patch set.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_ano_version.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_sns.cli_vers',
            '-e', 'tns.data_sns.srv_vers',
        ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['387588096', '352518144', '186647040', '301989888'], stdout
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_ano_version.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Client Version: 23.26.2.0.0' in stdout, stdout
        assert 'Server Version: 21.3.0.0.0' in stdout, stdout
        assert 'Client Version: 11.2.0.2.0' in stdout, stdout
        assert 'Server Version: 18.0.0.0.0' in stdout, stdout

    def test_tns_ano_encrypted(self, cmd_tshark, capture_file, test_env):
        '''Once the server has picked an encryption algorithm and the client
        has sent its second round, data packets are ciphertext and are not
        decoded as TTC.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_ano.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', '_ws.col.info',
        ), encoding='utf-8', env=test_env)
        rows = dict(r.split('\t') for r in stdout.strip().splitlines())
        assert 'Encrypted' not in rows['3'], rows
        assert rows['4'].endswith('Encrypted Data'), rows
        assert rows['5'].endswith('Encrypted Data'), rows

    def test_tns_flush_out_binds(self, cmd_tshark, capture_file, test_env):
        '''A failed DML RETURNING is answered with the flush-out-binds
        message and then the error.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_flush_binds.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521',
            '-T', 'fields',
            '-e', 'tns.data_id',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.message',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows[0][0] == '0x00000013,0x00000004', rows[0]
        assert rows[0][1] == '1476' and rows[0][2].startswith('ORA-01476'), rows[0]

    def test_tns_oer_server_fv(self, cmd_tshark, capture_file, test_env):
        '''The status block's SQL type and checksum follow the server's
        release, not the negotiated field version: a 23ai server sends them
        to a session that settled on 12.1, and the message after them
        decodes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oer_server_fv.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_oer.err_code',
            '-T', 'fields',
            '-e', 'tns.data_oer.err_num',
            '-e', 'tns.data_oer.sql_type',
            '-e', 'tns.data_oer.message',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['1722', '0', 'ORA-01722: invalid number', '']], rows

    def test_tns_accept_flags2(self, cmd_tshark, capture_file, test_env):
        '''From version 315 an ACCEPT offers the session data unit again as
        32 bits, and from 318 a flags2 word saying whether replies end with
        an end-of-response marker and whether fast authentication is on
        offer. An older ACCEPT has neither.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_accept_flags2.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.version',
            '-e', 'tns.accept_sdu',
            '-e', 'tns.accept_flags2',
            '-e', 'tns.accept_flags2.end_of_response',
            '-e', 'tns.accept_flags2.fast_auth',
            '-e', 'tns.accept_flags2.check_oob',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['319', '2097152', '0x1a000000', 'True', 'True', 'False', ''],
            ['314', '', '', '', '', '', ''],
        ], rows

    def test_tns_pipeline_flags(self, cmd_tshark, capture_file, test_env):
        '''The DATA flags of a pipeline: BEGIN_PIPELINE and END_OF_REQUEST
        mark the calls, END_OF_RESPONSE the packet that ends a reply.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_pipeline_flags.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_flag.begin_pipeline',
            '-e', 'tns.data_flag.end_of_request',
            '-e', 'tns.data_flag.end_of_response',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['True', 'True', 'False', ''],
            ['False', 'True', 'False', ''],
            ['False', 'False', 'True', ''],
        ], rows

    def test_tns_vector_render(self, cmd_tshark, capture_file, test_env):
        '''A VECTOR image is rendered by its storage format: FLOAT32 and
        FLOAT64 from their order-preserving encoding, INT8, BINARY as packed
        bytes, and a sparse vector as index: value pairs.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_vector.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert '(VECTOR): FLOAT32[3]: [1.5, 2.5, 3.5]' in stdout, stdout
        assert '(VECTOR): INT8[4]: [1, -2, 3, -4]' in stdout, stdout
        assert '(VECTOR): BINARY[16]: [170, 1]' in stdout, stdout
        assert '(VECTOR): FLOAT64[1]: [0.25]' in stdout, stdout
        assert '(VECTOR): sparse FLOAT32 of 300 dimensions: {299: 1.5}' in stdout, stdout

    def test_tns_oson_render(self, cmd_tshark, capture_file, test_env):
        '''An OSON image is rendered as JSON text: relative offsets and a
        shared field-id object of a compressed column, a version 3 image
        with a field name over 255 bytes, and nested containers.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oson.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert '(JSON): [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]' in stdout, stdout
        # the label is cut short; the full text is past its length
        assert '(JSON): {"' + 'A' * 100 in stdout, stdout
        assert '(JSON): {"k": [true, null, "s"]}' in stdout, stdout

    def test_tns_clob_text(self, cmd_tshark, capture_file, test_env):
        '''The content a READ returns is text when the locator it named is a
        CLOB's, encoded as the locator's flags say: UTF-16BE with the
        variable-length charset bit, UTF-8 without; a BLOB's is not text.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_clob_text.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_lob.data',
            '-T', 'fields',
            '-e', 'tns.data_lob.text',
        ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['abc', '', 'héllo'], stdout

    def test_tns_warn_flags(self, cmd_tshark, capture_file, test_env):
        '''The warning flags of a successful status say whether the PL/SQL
        object the statement created compiles.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_warn_flags.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_oer.warn_flags',
            '-T', 'fields',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.warn_flags',
            '-e', 'tns.data_oer.warn_flags.compilation_error',
            '-e', '_ws.expert.message',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[0][:3] == ['0', '0x21', 'True'], rows[0]
        assert 'compiled with errors' in rows[0][3], rows[0]
        assert rows[1][:4] == ['0', '0x00', 'False', ''], rows[1]

    def test_tns_oer_flags(self, cmd_tshark, capture_file, test_env):
        '''Below 12.1 the third of a status's six one-byte fields is a
        variable-length ub2, which a warning makes two bytes wide; the
        warning flags after it are read in place on either side of 12.1,
        and with no field version known.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oer_flags.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_oer.warn_flags',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'tns.data_oer.warn_flags',
            '-e', 'tns.data_oer.rowcount64',
            '-e', '_ws.expert.message',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['2', '0x05', '', ''],
            ['4', '0x05', '1', ''],
            ['5', '0x05', '', ''],
        ], rows

    def test_tns_parse_only(self, cmd_tshark, capture_file, test_env):
        '''An execute that asks for no work - no EXECUTE, DEFINE or FETCH -
        is a parse, whether or not it sets the PARSE bit: a parse of a
        cached statement sets none. A define round trip and a scroll
        re-execute ask for no run either but are not parses.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_parse.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_all8.options',
            '-e', 'tns.data_all8.parse_only',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['0x00020001', 'True'],
            ['0x00000001', 'True'],
            ['0x00080129', ''],
            ['0x00000000', 'True'],
            ['0x00008010', ''],
            ['0x00008040', ''],
        ], rows

    def test_tns_bfile(self, cmd_tshark, capture_file, test_env):
        '''A BFILE's locator names its directory and file, found whether
        the locator comes whole, as in a fetched column, or without its
        leading length, as a LOB operation sends it.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bfile.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert "Column 1 (BFILE): BFILENAME('DATA_DIR', 'report.txt')" in stdout, stdout
        assert 'Column 1 (BFILE): NULL' in stdout, stdout
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bfile.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_lob.op',
            '-T', 'fields',
            '-e', 'tns.data_lob.directory',
            '-e', 'tns.data_lob.file_name',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['DATA_DIR', 'report.txt', '']] * 3, rows
        # a FILE_OPEN sends its mode as the amount, and the reply echoes it
        # after the locator, ahead of the status
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bfile.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521 && tns.data_lob.amount',
            '-T', 'fields',
            '-e', 'tns.data_lob.amount',
            '-e', 'tns.data_oer.err_code',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        assert stdout == '11\t0\t\n', stdout

    def test_tns_oci_12c(self, cmd_tshark, capture_file, test_env):
        '''At the 12c band an OCI client's narrow execute preamble inserts
        64 zero bytes ahead of the SQL, which moves from 176 to 240; the
        11g layout still decodes beside it.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_12c.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_all8.oci_preamble',
            '-T', 'fields',
            '-e', 'tns.data_all8.oci_preamble',
            '-e', 'tns.data_all8.sql',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['OCI, narrow (4-byte slots), 12c band', 'SELECT * FROM T', ''],
            ['OCI, narrow (4-byte slots)', 'SELECT * FROM T', ''],
        ], rows

    def test_tns_oci_12c_status(self, cmd_tshark, capture_file, test_env):
        '''At the 12c band an OCI status block is 144 bytes: the error
        number again at 132 and a ub8 row count at 136, which is the row
        count sqlplus reports for a DML. An error's message follows it.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_12c.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_oer.err_code',
            '-T', 'fields',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.err_num',
            '-e', 'tns.data_oer.rowcount64',
            '-e', 'tns.data_oer.message',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['0', '0', '3', '', ''],
            ['942', '942', '0', 'ORA-00942: table or view does not exist', ''],
        ], rows

    def test_tns_oci_long_error(self, cmd_tshark, capture_file, test_env):
        '''An error message too long for a length byte follows an OCI
        status block chunked, with single-byte chunk lengths from an 11g
        server and ub4 LE ones from an 18c server. Either way the whole
        333-byte message is read and nothing is left over.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_long_error.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521',
            '-T', 'fields',
            '-e', 'tns.data_oer.err_code',
            '-e', 'tns.data_oer.message',
            '-e', 'data.len',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['20001', 'ORA-20001: ' + 'A' * 321, '', '']] * 2, rows

    def test_tns_oci_dty(self, cmd_tshark, capture_file, test_env):
        '''An OCI client's TTI_DTY has encoding flag 2 and no type table: a
        time zone block, from 11.2 on a timezone file version, and the
        national charset follow its capabilities, and the server answers
        with its own time zone block. The flag marks the client as an OCI
        one, so a status block after it is read in the OCI layout.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_dty.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_setdt.field_version',
            '-e', 'tns.data_setdt.tz_offset',
            '-e', 'tns.data_setdt.tzfile_version',
            '-e', 'tns.data_setdt.ncharset',
            '-e', 'tns.data_oer.oci_status',
            '-e', 'data.len',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['6', '+00:00:00', '14', '2000', '', '', ''],
            ['', '+00:00:00', '14', '', '', '', ''],
            ['', '', '', '', '1', '', ''],
            ['4', '+00:00:00', '', '2000', '', '', ''],
            ['', '+00:00:00', '', '', '', '', ''],
        ], rows

    def test_tns_oci_kod(self, cmd_tshark, capture_file, test_env):
        '''An OCI client describes an object type with TTI_KOD, by name or
        by REF. The reply is a name header for a by-name call, a record
        per type descriptor and a status; a descriptor that is an instance
        of SYS.KOTTD names the type, its version and its typecode. The
        12c band's longer header and bare record descriptor are read
        too, and a by-name call that names the schema.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_kod.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-E', 'aggregator=|',
            '-e', 'tns.data_kod.opcode',
            '-e', 'tns.data_kod.kind',
            '-e', 'tns.data_kod.schema',
            '-e', 'tns.data_kod.name',
            '-e', 'tns.data_kod.system_type',
            '-e', 'tns.data_kod.typecode',
            '-e', 'tns.data_oer.err_code',
            '-e', 'data.len',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['3', '', '', 'DBMSOUTPUT_LINESARRAY', '', '', '', '', ''],
            ['', '2|1', 'PYO|SYS', 'DBMSOUTPUT_LINESARRAY|DBMSOUTPUT_LINESARRAY', '0x01', '122', '0', '', ''],
            ['4', '', '', '', '0x01', '', '', '', ''],
            ['', '1', 'SYS', 'KOTTD', '0x01', '108', '0', '', ''],
        ] * 2 + [
            ['3', '', 'SYS', 'XMLTYPE', '', '', '', '', ''],
        ], rows

    def test_tns_oci_fetch(self, cmd_tshark, capture_file, test_env):
        '''An OCI client's fetch carries the cursor id and the row count as
        fixed-width little-endian ub4s: sqlplus 23.26 asks cursor 2 for 15
        rows.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_12c.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_fetch.rows',
            '-T', 'fields',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_fetch.rows',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['2', '15', '']], rows

    def test_tns_oci_reexecute(self, cmd_tshark, capture_file, test_env):
        '''An OCI client runs an open cursor again in two ways: an execute
        with no SQL that names the cursor, as sqlplus prints a REF CURSOR,
        and a re-execute with fixed-width fields, as it fetches the next
        SERVEROUTPUT batch.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_all8.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'frame.number >= 5',
            '-T', 'fields',
            '-e', 'tns.data_all8.oci_preamble',
            '-e', 'tns.data_all8.options',
            '-e', 'tns.data.cursor',
            '-e', 'tns.data_reexec.iterations',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['OCI, by cursor id', '0x00000040', '256', '', ''],
            ['', '', '4', '1', ''],
        ], rows

    def test_tns_oci_binds(self, cmd_tshark, capture_file, test_env):
        '''An OCI client's execute carries a fixed-width descriptor per
        bind, 49 bytes from 12c and 41 before, and the row of values. A
        bind with a buffer wider than 4000 bytes sends its value last, an
        NCHAR value is UTF-16, and a repeated name sends none.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_binds.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_col.type',
            '-e', 'tns.data_col.max_length',
            '-e', 'tns.data_col.csform',
            '-e', 'tns.data_bind.oci_flags.repeat',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        six = ['1,1,96,96,1,2', '21,12000,39,10,18,22', '1,1,1,2,2,0',
               'False,False,False,False,False,False', '']
        assert rows == [six, six, ['2,2', '22,0', '0,0', 'False,True', '']], rows
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_oci_binds.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        values = [line.strip() for line in stdout.splitlines() if line.strip().startswith('Bind ') and '(' in line]
        six = ['Bind 1 (VARCHAR): abc', 'Bind 3 (CHAR): ij', 'Bind 4 (CHAR): ?',
               'Bind 5 (VARCHAR): ?', 'Bind 6 (NUMBER): 42', 'Bind 2 (VARCHAR): defgh']
        assert values == six + six + ['Bind 1 (NUMBER): 42'], values

    def test_tns_array_binds(self, cmd_tshark, capture_file, test_env):
        '''An associative-array bind's value is an element count and the
        elements, in the request and in the OUT reply alike.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_array_binds.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_bind.num_elements',
            '-T', 'fields',
            '-e', 'tns.data_col.max_elements',
            '-e', 'tns.data_bind.num_elements',
            '-e', 'tns.data_bind.value',
            '-e', 'tns.data_oer.err_code',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['10', '3', 'c102,c103,c104', '', ''],
            ['', '3', 'c103,c105,c107', '0', ''],
        ], rows

    def test_tns_bind_framing(self, cmd_tshark, capture_file, test_env):
        '''A bind value is framed as a client sends it, not as a fetched
        column: a LONG has no trailing indicators and a ROWID is a string.
        The NUMBER after each decodes.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bind_framing.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Bind 2 (NUMBER): 8' in stdout, stdout
        assert 'Bind 1 (RID): AAAK6JAAEAAACGPAAA' in stdout, stdout
        assert 'Bind 2 (NUMBER): 9' in stdout, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_long_bind_order(self, cmd_tshark, capture_file, test_env):
        '''In a SQL statement a LONG-class bind value comes after all the
        others; a PL/SQL block takes its values in bind order.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_long_bind.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Bind 2 (NUMBER): 7' in stdout, stdout
        assert 'Bind 2 (NUMBER): 8' in stdout, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_aq(self, cmd_tshark, capture_file, test_env):
        '''Advanced Queuing: an enqueue names its queue, correlation and
        payload, and is answered with the message id; a dequeue names its
        consumer, mode and condition, and is answered with the message.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_aq.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_aq.queue || tns.data_aq.msgid',
            '-T', 'fields',
            '-e', 'tns.data_aq.queue',
            '-e', 'tns.data_aq.correlation',
            '-e', 'tns.data_aq.consumer',
            '-e', 'tns.data_aq.condition',
            '-e', 'tns.data_aq.msgid',
            '-e', 'tns.data_aq.enq_time',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 4, rows
        assert rows[0][:2] == ['MYQ', 'corr-1'] and rows[0][6] == '', rows[0]
        assert rows[1][4] == '202122232425262728292a2b2c2d2e2f', rows[1]
        assert rows[2][:4] == ['MYQ', '', 'SUB1', 'priority = 1'], rows[2]
        assert rows[3][5] == '2024-03-04 05:07:09' and rows[3][6] == '', rows[3]

    def test_tns_aq_array(self, cmd_tshark, capture_file, test_env):
        '''The array queuing call enqueues or dequeues several messages at
        once: a row per message on the way out, the queue's options
        repeated per message on the way in, and the ids on the way back.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_aq_array.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tns.data_aq.array_op || tns.data_aq.msgid',
            '-T', 'fields',
            '-e', 'tns.data_aq.array_op',
            '-e', 'tns.data_aq.num_messages',
            '-e', 'tns.data_aq.queue',
            '-e', 'tns.data_aq.correlation',
            '-e', 'tns.data_aq.consumer',
            '-e', 'tns.data_aq.msgid',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert len(rows) == 4, rows
        assert rows[0][:4] == ['1', '2', 'MYQ', 'corr-1,corr-2'], rows[0]
        assert rows[1][5].count(',') == 1, rows[1]
        assert rows[2][:3] == ['2', '2', 'MYQ'] and rows[2][4] == 'SUB1,SUB1', rows[2]
        assert all(r[6] == '' for r in rows), rows

    def test_tns_dty_12c(self, cmd_tshark, capture_file, test_env):
        '''A 12c+ client's TTI_DTY: capability arrays of their own lengths,
        and a type table of big-endian 16-bit entries.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dty_12c.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_setdt.field_version',
            '-e', 'tns.data_setdt.type',
            '-e', 'tns.data_setdt.rep',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [['24', '1,2,112', '1,10,1', '']], rows

    def test_tns_dty_reply(self, cmd_tshark, capture_file, test_env):
        '''A 12c+ server's TTI_DTY reply lists 16-bit type pairs up to a 0
        type; the message after it is decoded too.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_dty_reply.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-Y', 'tcp.srcport == 1521',
            '-T', 'fields',
            '-e', 'tns.data_setdt.type',
            '-e', 'tns.data_setdt.conv_type',
            '-e', 'tns.data_sta.call_status',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert rows == [['1,2', '1,0', '0x00000001']], rows

    def test_tns_fast_auth(self, cmd_tshark, capture_file, test_env):
        '''A 23ai client bundles the protocol, data types and session key
        messages into one fast-authentication packet; the call inside it
        carries no token, though the connection's field version is 24 and
        the execute after it does.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_fast_auth.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_setp_req.cli_plat',
            '-e', 'tns.data_setdt.field_version',
            '-e', 'tns.data_auth.user',
            '-e', 'tns.data_opi.param_name',
            '-e', 'tns.data.token',
            '-e', 'tns.data_all8.sql',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[0][:4] == ['python', '13,24', 'SCOTT',
                               'AUTH_PROGRAM_NM,AUTH_MACHINE'], rows[0]
        assert rows[0][4] == '', rows[0]
        assert rows[1][4] == '0' and rows[1][5] == 'SELECT 1 FROM DUAL', rows[1]

    def test_tns_lob_binds(self, cmd_tshark, capture_file, test_env):
        '''A LOB value carried by a bind is a bare locator on the way out and
        the LOB block - its size and chunk size before the locator - on the
        way back, for an OUT bind and a RETURNING bind alike. A LONG return
        bind is a plain DALC.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lob_binds.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        assert 'Bind 1 (CLOB): locator\n' in stdout, stdout
        assert 'Bind 2 (NUMBER): 10' in stdout, stdout
        assert stdout.count('Bind 1 (CLOB): locator, size 50005') == 1, stdout
        assert stdout.count('Bind 2 (CLOB): locator, size 50005') == 1, stdout
        assert 'LOB Chunk Size: 8132' in stdout, stdout
        assert 'Bind 3 (LONG): nineteen bytes here' in stdout, stdout
        # a JSON bind sends its locator and image; the value returned for
        # it is the same block a LOB's is
        assert 'Bind 1 (JSON): {"k": 5}' in stdout, stdout
        assert 'Bind 1 (JSON): locator, size 50005' in stdout, stdout
        assert 'Malformed' not in stdout, stdout

    def test_tns_actual_length(self, cmd_tshark, capture_file, test_env):
        '''Each value a server returns for a bind is followed by its actual
        length: 0 when it fitted, -1 when NULL, else its length before the
        server cut it to the declared size - which is truncation only when
        more than arrived.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_actual_length.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_bind.actual_len',
            '-e', '_ws.expert.message',
            '-e', '_ws.col.info',
            '-Y', 'tns.data_bind.actual_len',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert [r[0] for r in rows] == ['23,-1', '5,11'], rows
        assert rows[0][1] == 'The value was cut to 2 of its 23', rows[0]
        assert rows[1][1] == 'The value was cut to 5 of its 11', rows[1]
        assert all('[truncated]' in r[2] for r in rows), rows

    def test_tns_create_temp(self, cmd_tshark, capture_file, test_env):
        '''A CREATE_TEMP carries the charset form and type of the LOB to
        create where other LOB operations carry offsets; an NCLOB is a
        CLOB with the national form and charset.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_create_temp.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_lob.csform',
            '-e', 'tns.data_lob.type',
            '-e', 'tns.data_lob.charset',
            '-e', 'tns.data_lob.offset',
            '-e', '_ws.col.info',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert [r[:4] for r in rows] == [
            ['1', '112', '873', ''],
            ['2', '112', '2000', ''],
            ['0', '113', '873', ''],
        ], rows
        assert [r[4].split('[CREATE_TEMP] ')[1] for r in rows] == ['[CLOB]', '[NCLOB]', '[BLOB]'], rows
        assert all(r[5] == '' for r in rows), rows

    def test_tns_bc_date(self, cmd_tshark, capture_file, test_env):
        '''A DATE or TIMESTAMP before year 1 counts its century and year
        down from the same bias and is shown as the BC year it is; a date
        after it is unchanged.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_bc_date.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-O', 'tns',
        ), encoding='utf-8', env=test_env)
        for value in ('Column 1 (DATE): 4712-01-01 00:00:00 BC',
                      'Column 2 (TIMESTAMP): 0044-03-15 12:30:05.500000000 BC',
                      'Column 1 (DATE): 0044-03-15 00:00:00 BC',
                      'Column 1 (DATE): 0001-12-31 23:59:59 BC',
                      'Column 1 (DATE): 0101-06-01 00:00:00 BC',
                      'Column 1 (DATE): 2026-09-22 00:00:00\n'):
            assert value in stdout, value

    def test_tns_lastrowid(self, cmd_tshark, capture_file, test_env):
        '''The status block names the rowid of the last row a DML touched,
        rendered as the extended rowid; a zero block means there is none.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lastrowid.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_oer.rowid',
            '-e', 'tns.data_oer.rowcount',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['AAAfXBAAAAAAVrtAAA', '1', ''],
            ['AAAfXBAQAAAAVrtAAA', '1', ''],
            ['', '0', ''],
        ], rows

    def test_tns_fv_12_1(self, cmd_tshark, capture_file, test_env):
        '''A session at field version 12.1 already uses the 12c forms: a
        one-byte describe scale, the array flag in the OAC's flag byte,
        ub4 chunk lengths, and no trailing byte after a CLOB bind's
        descriptor; the oaccolid waits for 12.2.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_fv_12_1.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_col.scale',
            '-e', 'tns.data_col.value',
            '-e', 'tns.data_bind.num_elements',
            '-e', 'tns.data_bind.value',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows[1][0] == '-127,0', rows[1]
        values = rows[2][1].split(',')
        assert values[0] == 'c102' and len(values[1]) // 2 == 304, rows[2]
        assert rows[3][2] == '2', rows[3]
        binds = rows[3][3].split(',')
        assert binds[:2] == ['c102', 'c103'] and len(binds) == 3, rows[3]
        assert all(r[4] == '' for r in rows), rows

    def test_tns_plsql_reexec(self, cmd_tshark, capture_file, test_env):
        '''A PL/SQL block's bind directions, reported only in the reply to
        its first execute, are remembered against its cursor: a re-execute
        sends no value for the OUT bind, and each iteration's OUT value
        comes back in a TTI_RXD of its own, with no IOV.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_plsql_reexec.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_bind.value',
            '-e', 'tns.data_bind.actual_len',
            '-e', 'tns.data_oer.cursor_id',
            '-e', '_ws.malformed',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.rstrip('\n').splitlines()]
        assert rows == [
            ['6869,c106,fd01', '', '', ''],
            ['c107', '0', '3', ''],
            ['796f,c115,6f6b,c111', '', '', ''],
            ['c116,c112', '0,0', '3', ''],
        ], rows

class TestDecompressMongo:
    def test_decompress_zstd(self, cmd_tshark, features, capture_file, test_env):
        if not features.have_zstd:
            pytest.skip('Requires zstd.')
        stdout = subprocess.check_output((cmd_tshark,
                '-d', 'tcp.port==27017,mongo',
                '-r', capture_file('mongo-zstd.pcapng'),
                '-Tfields', '-emongo.element.name'
        ), encoding='utf-8', env=test_env)
        # Check the element names of the decompressed body.
        assert 'drop,lsid,id,$db' == stdout.strip()

class TestDissectOvsNetlink:
    '''Open vSwitch Generic Netlink protocol dissector tests.

    Uses a capture generated by exercising the OVS kernel module via
    ovs-vsctl, ovs-ofctl and ovs-appctl.  The pcap contains CTRL_CMD_NEWFAMILY
    discovery packets so that tshark can map numeric family IDs to the
    named dissectors (ovs_datapath, ovs_vport, ovs_flow, ovs_meter,
    ovs_ct_limit).
    '''

    def test_ovs_datapath_name(self, cmd_tshark, capture_file, test_env):
        '''ovs_datapath: verify datapath name is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_datapath.name == "ovs-system"',
                '-Tfields', '-eovs_datapath.name',
            ), encoding='utf-8', env=test_env)
        assert 'ovs-system' in stdout

    def test_ovs_datapath_stats(self, cmd_tshark, capture_file, test_env):
        '''ovs_datapath: verify datapath stats fields exist.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_datapath.name == "ovs-system" && ovs_datapath.stats.n_hit',
                '-Tfields', '-eovs_datapath.masks_cache_size',
            ), encoding='utf-8', env=test_env)
        assert '256' in stdout

    def test_ovs_vport_name_type(self, cmd_tshark, capture_file, test_env):
        '''ovs_vport: verify vport name and type are decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_vport.name == "testport-cap"',
                '-Tfields', '-eovs_vport.type', '-eovs_vport.port_no',
            ), encoding='utf-8', env=test_env)
        lines = [line for line in stdout.strip().splitlines() if line.strip()]
        assert any('2' in line for line in lines)

    def test_ovs_vport_ifindex(self, cmd_tshark, capture_file, test_env):
        '''ovs_vport: verify ifindex field is present.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_vport.name == "testport-cap" && ovs_vport.ifindex',
                '-Tfields', '-eovs_vport.ifindex',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() != ''

    def test_ovs_flow(self, cmd_tshark, capture_file, test_env):
        '''ovs_flow: verify flow frames are decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_flow',
                '-Tfields', '-eovs_flow.cmd',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() != ''

    def test_ovs_meter_band(self, cmd_tshark, capture_file, test_env):
        '''ovs_meter: verify meter band type and rate are decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_meter.band.type == 1',
                '-Tfields', '-eovs_meter.band.rate',
            ), encoding='utf-8', env=test_env)
        assert '1000' in stdout

    def test_ovs_ct_limit_zone(self, cmd_tshark, capture_file, test_env):
        '''ovs_ct_limit: verify zone limit fields are decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_ct_limit.zone_id == 5',
                '-Tfields', '-eovs_ct_limit.limit',
            ), encoding='utf-8', env=test_env)
        assert '500' in stdout

    def test_ovs_packet_miss(self, cmd_tshark, capture_file, test_env):
        '''ovs_packet: verify MISS upcall is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ovs-netlink.pcapng'),
                '-Y', 'ovs_packet.cmd == 1',
                '-Tfields', '-eovs_packet.cmd',
            ), encoding='utf-8', env=test_env)
        assert '1' in stdout

class TestDissectUsbHid:
    def test_usb_hid_descriptor_usage(self, cmd_tshark, capture_file, test_env):
        '''Verify usage page and usage are properly decoded in the descriptor.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('usb-hid.pcapng'),
                '-Y', 'usbhid',
                '-Tfields', '-eusbhid.item.global.usage', '-eusbhid.item.local.usage',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '0x000c,0xff00\t0x0001,0x008a,0x0196,0x0239,0x0030,0x0001,0x0023'

    def test_usb_hid_data_array(self, cmd_tshark, capture_file, test_env):
        '''Verify array is properly decoded in the data.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('usb-hid.pcapng'),
                '-Y', 'usb.transfer_type == 1 and usb.urb_status == 0',
                '-Tfields', '-eusbhid.data.array', '-eusbhid.data.array.usage',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '0f\tTrue,True\n09\tTrue,True\n00\tFalse,False'

    def test_usb_hid_data_vendor(self, cmd_tshark, capture_file, test_env):
        '''Verify vendor data is properly decoded in the data.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('usb-hid.pcapng'),
                '-Y', 'usb.transfer_type == 1 and usb.urb_status == 0',
                '-Tfields', '-eusbhid.data.vendor',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '01,0f\n01,0d\n00,00'

    def test_usb_hid_data_padding(self, cmd_tshark, capture_file, test_env):
        '''Verify padding is properly decoded in the data.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('usb-hid.pcapng'),
                '-Y', 'usb.transfer_type == 1 and usb.urb_status == 0',
                '-Tfields', '-eusbhid.data.padding',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '03,ff07\n01,b907\n00,0000'

class TestDissectUsbPtp:
    def test_usb_ptp_class_data_type(self, cmd_text2pcap, cmd_tshark, result_file, test_env):
        '''PTP must not use class data that another USB class stored on its interface.'''
        def urb(urb_id, event, xfer_type, endpoint, setup=None, data=b''):
            # Linux usbmon header (LINKTYPE_USB_LINUX_MMAPPED) followed by the data
            setup_flag = 0 if setup else ord('-')
            data_flag = 0 if data else ord('<')
            status = -115 if event == 'S' else 0
            return struct.pack('<QBBBBHbbqiiII8siiII', urb_id, ord(event), xfer_type, endpoint, 1, 1,
                               setup_flag, data_flag, 0, 0, status, len(data), len(data),
                               setup or bytes(8), 0, 0, 0, 0) + data

        config_descriptor = bytes.fromhex(
            '090239000201008032'    # configuration, 2 interfaces
            '09040000010a000000'    # interface 0, alternate setting 0: CDC Data
            '07058102000200'        # bulk IN endpoint 0x81
            '090400010106010100'    # interface 0, alternate setting 1: Still Image (PTP)
            '07058102000200'        # bulk IN endpoint 0x81
            '090401000106010100'    # interface 1: Still Image (PTP)
            '07058202000200')       # bulk IN endpoint 0x82
        ptp_response = bytes.fromhex('0c00000003000120' '01000000')    # OK, transaction 1
        packets = [
            urb(1, 'S', 2, 0x80, setup=bytes.fromhex('8006000200003900')),    # GET_DESCRIPTOR
            urb(1, 'C', 2, 0x80, data=config_descriptor),
            urb(2, 'C', 3, 0x81, data=bytes(4)),                             # CDC Data on interface 0
            urb(3, 'S', 2, 0x00, setup=bytes.fromhex('010b010000000000')),    # SET_INTERFACE 0 to setting 1
            urb(4, 'C', 3, 0x81, data=ptp_response),                         # PTP on interface 0
            urb(5, 'C', 3, 0x82, data=ptp_response),                         # PTP on interface 1
        ]
        text_file = result_file('usb-ptp.txt')
        capture = result_file('usb-ptp.pcapng')
        with open(text_file, 'w') as f:
            f.writelines(f'000000  {packet.hex(" ")}\n' for packet in packets)
        subprocess.check_call((cmd_text2pcap, '-q', '-l', '220', text_file, capture), env=test_env)

        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture,
                '-Y', 'usbcom || usb-ptp.container.length',
                '-Tfields', '-eframe.number', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        # Interface 0's class data belongs to CDC Data, so PTP leaves frame 5 undissected.
        assert stdout == '3\tUSBCOM\n6\tUSB-PTP\n'

class TestDissectUltraEthernet:
    def test_uet_crc(self, cmd_tshark, capture_file, test_env):
        '''Verify we compute a good CRC for various IP and UDP encapsulations.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('uet-generated-crc-encaps.pcap'),
                '-ouet.has_crc:TRUE',
                '-ouet.validate_crc:TRUE',
                '-dip.proto==253,uet',
                '-Tfields', '-euet.crc.status',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip().split() == (['1'] * 48)


# UDX ships its heuristic disabled, so the tests enable it explicitly.
UDX_HEUR = ('--enable-heuristic', 'udx_udp')


class TestDissectUdx:
    def test_udx_heuristic_disabled_by_default(self, cmd_tshark, capture_file, test_env):
        '''The heuristic is off unless the user asks for it.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('udx_clean.pcap.gz'),
                '-Y', 'udx',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_udx_heuristic(self, cmd_tshark, capture_file, test_env):
        '''Every packet of a UDX capture is recognised by the heuristic.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_clean.pcap.gz'),
                '-Y', 'udx',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 130

    def test_udx_header_fields(self, cmd_tshark, capture_file, test_env):
        '''Header fields decode with the little-endian byte order UDX uses.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_clean.pcap.gz'),
                '-c', '1',
                '-Tfields', '-eudx.id', '-eudx.seq', '-eudx.ack', '-eudx.rwnd',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '101\t0\t0\t4194304'

    def test_udx_sack_blocks(self, cmd_tshark, capture_file, test_env):
        '''Selective acknowledgement ranges are decoded as pairs.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_loss.pcap.gz'),
                '-Y', 'udx.sack.start',
                '-Tfields', '-eudx.sack.start', '-eudx.sack.end',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, r'^6\t8')

    def test_udx_many_sack_blocks(self, cmd_tshark, capture_file, test_env):
        '''A selective acknowledgement is not limited to what data_offset can
        delimit.

        A packet carrying no payload leaves data_offset zero and its blocks run
        to the end of the datagram, which is how libudx reports a badly
        fragmented receive window. It sends up to fifty of them, well past the
        thirty-one that would fit in a delimited area.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_sackblocks.pcap.gz'),
                '-Y', 'udx.type.sack == 1',
                '-Tfields', '-eudx.sack.start',
            ), encoding='utf-8', env=test_env)
        assert len(stdout.strip().split(',')) == 40

    def test_udx_repeat_below_the_timers(self, cmd_tshark, capture_file, test_env):
        '''A repeat too soon to be either of libudx's timers is just a repeat.

        Nothing on this flow has been acknowledged, so there is no round trip
        time and both the retransmission timeout and the probe timer sit at
        their floor of one second. A repeat half a second in cannot be either,
        and saying which timer fired would be inventing one.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_norto.pcap.gz'),
                '-V',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'This packet was retransmitted')
        assert not grep_output(stdout, 'Retransmission timeout')
        assert not grep_output(stdout, 'Tail loss probe')

    def test_udx_stream_pairing(self, cmd_tshark, capture_file, test_env):
        '''Three streams multiplexed over one socket pair are told apart.

        Packets carry only the receiver's stream id, so each flow has to be
        matched with its reverse by correlating acknowledgements.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_multi.pcap.gz'),
                '-Tfields', '-eudx.stream',
            ), encoding='utf-8', env=test_env)
        assert sorted(set(stdout.split())) == ['0', '1', '2']

    def test_udx_fast_retransmission(self, cmd_tshark, capture_file, test_env):
        '''A packet resent while later ones were selectively acknowledged.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_loss.pcap.gz'),
                '-Y', 'udx.analysis.fast_retransmission',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 2

    def test_udx_keepalive(self, cmd_tshark, capture_file, test_env):
        '''A bare heartbeat with the window open is a keepalive.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_keepalive.pcap.gz'),
                '-Y', 'udx.analysis.keepalive',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 3

    def test_udx_zero_window_probe(self, cmd_tshark, capture_file, test_env):
        '''The same heartbeat is a probe once the peer closes its window.

        Keepalives and zero-window probes are identical on the wire; only the
        window last advertised by the peer separates them.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_zerowindow.pcap.gz'),
                '-Y', 'udx.analysis.zero_window_probe',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 2

        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_zerowindow.pcap.gz'),
                '-Y', 'udx.analysis.window_update',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 1

    def test_udx_mtu_probe(self, cmd_tshark, capture_file, test_env):
        '''Padding without SACK blocks marks a path MTU probe.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_mtuprobe.pcap.gz'),
                '-Y', 'udx.analysis.mtu_probe',
                '-Tfields', '-eframe.number', '-eudx.data_offset',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 3
        assert grep_output(stdout, r'\t32$')

    def test_udx_sequence_wraparound(self, cmd_tshark, capture_file, test_env):
        '''Analysis survives sequence numbers crossing 2^32.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_seqwrap.pcap.gz'),
                '-Tfields', '-eudx.stream', '-eudx.analysis.acks_frame',
            ), encoding='utf-8', env=test_env)
        assert sorted(set(stdout.split('\n')[0].split('\t'))) == ['', '0']
        assert grep_output(stdout, r'^0\t1$')

    def test_udx_rto_beats_sack(self, cmd_tshark, capture_file, test_env):
        '''A full timeout decides a retransmission, even with later SACKs.

        Sequence 0 is lost while 1 and 2 arrive and are selectively
        acknowledged, so the highest selectively acknowledged sequence sits
        above the resent one. The resend still comes a second and a half
        later, which makes it a timer retransmission rather than a fast one.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_rto.pcap.gz'),
                '-V',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Retransmission timeout')
        assert not grep_output(stdout, 'Fast retransmission')

    def test_udx_sack_acknowledges(self, cmd_tshark, capture_file, test_env):
        '''A selective acknowledgement acknowledges the packet it names.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_rto.pcap.gz'),
                '-Tfields', '-eframe.number', '-eudx.analysis.acked_in',
            ), encoding='utf-8', env=test_env)
        # Sequences 1 and 2 are acknowledged by the first SACK, in frame 4,
        # not by the cumulative acknowledgement that arrives in frame 7.
        assert grep_output(stdout, r'^2\t4$')
        assert grep_output(stdout, r'^3\t4$')

    def test_udx_tail_loss_probe_with_new_data(self, cmd_tshark, capture_file, test_env):
        '''A probe that carries new data is still a probe.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_tlpnew.pcap.gz'),
                '-V',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Tail loss probe')

    def test_udx_follow_stream(self, cmd_tshark, capture_file, test_env):
        '''Following a stream yields the payload in both directions.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_clean.pcap.gz'),
                '-q', '-z', 'follow,udx,ascii,0',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Node 0: 10.0.0.1:40000')
        assert grep_output(stdout, 'Node 1: 10.0.0.2:40001')

    def test_udx_follow_reassembly(self, cmd_tshark, capture_file, test_env):
        '''Loss and retransmission do not change the reassembled payload.

        The same transfer is captured cleanly and with two packets lost; the
        payload handed to the application must be identical in both.
        '''
        def payload(name):
            stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                    '-r', capture_file(name),
                    '-q', '-z', 'follow,udx,ascii,0',
                ), encoding='utf-8', env=test_env)
            # Keep the data lines, dropping the header and the byte counts.
            return [l for l in stdout.splitlines() if l.strip() and not l.strip().isdigit()]

        assert payload('udx_clean.pcap.gz')[-20:] == payload('udx_loss.pcap.gz')[-20:]

    def test_udx_follow_superseded_fragment(self, cmd_tshark, capture_file, test_env):
        '''A held packet that is delivered by another copy stops holding up
        the ones behind it.

        Sequence 2 is held while the gap at 1 is open and arrives a second
        time before that gap closes. Filling the gap delivers one copy; the
        other has to be discarded rather than left at the head of the pending
        list, where it would block every packet after it.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_followstall.pcap.gz'),
                '-q', '-z', 'follow,udx,ascii,0',
            ), encoding='utf-8', env=test_env)
        # All six packets, in sequence order, including the one sent last.
        payload = [l for l in stdout.splitlines() if l and set(l) <= set('abcdef')]
        assert ''.join(payload) == ''.join(c * 16 for c in 'abcdef')

    def test_udx_acknowledges_below_first_seen(self, cmd_tshark, capture_file, test_env):
        '''The first packet on the wire need not hold the lowest sequence.

        Sequence 0 was lost and resent, so it appears after 1 and 2. The
        cumulative acknowledgement covers all three and has to retire it.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_lateseq.pcap.gz'),
                '-Tfields', '-eframe.number', '-eudx.analysis.acked_in',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, r'^3\t4$')

    def test_udx_rtt_measured_on_sending_flow(self, cmd_tshark, capture_file, test_env):
        '''The round trip time belongs to the flow whose packet was timed.

        Only one side sends data here, so if the sample were credited to the
        flow carrying the acknowledgements the sending flow would never have
        one, and this six millisecond pause would fall under the floor that
        applies when no round trip time is known.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR, '-2',
                '-r', capture_file('udx_rtttlp.pcap.gz'),
                '-V',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Tail loss probe')

    def test_udx_conversations_split_multiplexed_streams(self, cmd_tshark, capture_file, test_env):
        '''Three streams on one socket pair are three UDX conversations.

        The enclosing UDP flow counts them together, so the UDP table shows a
        single conversation for the same capture.
        '''
        def rows(table):
            stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                    '-r', capture_file('udx_multi.pcap.gz'),
                    '-q', '-z', table,
                ), encoding='utf-8', env=test_env)
            return [l for l in stdout.splitlines() if '<->' in l]

        assert len(rows('conv,udp')) == 1
        assert len(rows('conv,udx')) == 3

    def test_udx_conversation_totals(self, cmd_tshark, capture_file, test_env):
        '''The streams account for exactly what the UDP conversation carried.

        Each of the three streams reports 127 frames and 75728 bytes, which adds
        up to the 381 frames and 227184 bytes the UDP table reports for the whole
        capture. Byte counts are asked for machine readable so the columns are
        plain integers rather than SI prefixed.
        '''
        def total(table):
            stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                    '-r', capture_file('udx_multi.pcap.gz'),
                    '-o', 'conv.machine_readable:TRUE',
                    '-q', '-z', table,
                ), encoding='utf-8', env=test_env)
            rows = [l.split() for l in stdout.splitlines() if '<->' in l]
            return [(int(r[7]), int(r[8])) for r in rows]

        assert total('conv,udx') == [(127, 75728)] * 3
        assert total('conv,udp') == [(381, 227184)]

    def test_udx_endpoints(self, cmd_tshark, capture_file, test_env):
        '''Both ends appear once, with the traffic split by direction.'''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_multi.pcap.gz'),
                '-o', 'conv.machine_readable:TRUE',
                '-q', '-z', 'endpoints,udx',
            ), encoding='utf-8', env=test_env)
        rows = [l.split() for l in stdout.splitlines() if l.startswith('10.0.0.')]
        assert [(r[0], int(r[1]), int(r[2])) for r in rows] == [
            ('10.0.0.1', 381, 227184),
            ('10.0.0.2', 381, 227184),
        ]
        # Sent one way is received the other.
        assert (int(rows[0][3]), int(rows[0][4])) == (int(rows[1][5]), int(rows[1][6]))

    def test_udx_conversations_follow_analysis_preference(self, cmd_tshark, capture_file, test_env):
        '''The tables carry the stream index, so they need sequence analysis.

        With the preference off the dissector assigns no stream number, the same
        condition under which udx.stream is absent from the tree.
        '''
        stdout = subprocess.check_output((cmd_tshark, *UDX_HEUR,
                '-r', capture_file('udx_multi.pcap.gz'),
                '-oudx.analyze_sequence_numbers:FALSE',
                '-q', '-z', 'conv,udx',
            ), encoding='utf-8', env=test_env)
        assert len([l for l in stdout.splitlines() if '<->' in l]) == 0


class TestDissectGsmtapUm:
    def test_gsmtap_um_encap(self, cmd_tshark, capture_file, test_env):
        '''A LINKTYPE_GSMTAP_UM (217) capture opens and every frame reaches
        the GSMTAP dissector.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('gsmtap_um_lte.pcap'),
                '-Tfields', '-egsmtap.type',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip().split() == ['15', '13', '15', '15', '15', '18']

    def test_gsmtap_lte_mac_framed_rar(self, cmd_tshark, capture_file, test_env):
        '''A GSMTAP LTE MAC framed payload reaches mac-lte: RAR fields decode.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('gsmtap_um_lte.pcap'),
                '-Y', 'mac-lte.rar',
                '-Tfields', '-emac-lte.rar.rapid', '-emac-lte.rar.ta',
                '-emac-lte.rar.temporary-crnti',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '0x06\t0\t70'

    def test_gsmtap_lte_mac_framed_rrc_chain(self, cmd_tshark, capture_file, test_env):
        '''MAC framed payloads chain through mac-lte into the RRC dissector
        (frames 1, 4 and 5); frame 2 is a plain GSMTAP LTE RRC packet.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('gsmtap_um_lte.pcap'),
                '-Y', 'lte_rrc',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip().split() == ['1', '2', '4', '5']


class TestDissectPcapngProcessIdThreadId:
    '''The pcapng epb_processid_threadid option (code 8) as frame.process.pid
    and frame.process.tid.

    The capture is generated by test/captures/_gen_epb_processid_threadid.py
    and has a little-endian and a big-endian section, so that the option is
    read in both byte orders.
    '''
    CAPTURE = 'epb_processid_threadid.pcapng'

    def test_frame_process_fields(self, assert_frames_match):
        assert_frames_match(self.CAPTURE, [
            (1, 'frame.process.pid == 1234 && frame.process.tid == 5678'),
            (2, 'frame.process.pid == 0 && frame.process.tid == 0'),
            (3, 'frame.process.pid == 4321 && frame.process.tid == 8765'),
            (4, '!frame.process'),
        ])

    def test_frame_process_fields_survive_rewrite(self, cmd_editcap, cmd_tshark, capture_file, result_file, base_env, test_env):
        '''Rewriting the file must keep the process and thread IDs in the
        right order whatever the byte order of the input sections.'''
        testout_file = result_file('epb_processid_threadid_rewritten.pcapng')
        subprocess.check_call((cmd_editcap, '-F', 'pcapng', capture_file(self.CAPTURE), testout_file), env=base_env)
        stdout = subprocess.check_output((cmd_tshark, '-r', testout_file,
                '-Tfields', '-e', 'frame.number', '-e', 'frame.process.pid', '-e', 'frame.process.tid',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['1\t1234\t5678', '2\t0\t0', '3\t4321\t8765', '4\t\t']


class TestDissectPcapngProcessInformation:
    '''Process information from the pcapng process information blocks of a
    file, looked up by the process ID in the epb_processid_threadid option,
    as frame.process fields.

    The captures are generated by test/captures/_gen_process_info_blocks.py.
    '''

    def test_frame_process_info_fields(self, assert_frames_match):
        assert_frames_match('process_info_wireshark_cb.pcapng', [
            (1, 'frame.process.pid == 1234 && frame.process.name == "curl"' +
                ' && frame.process.path == "/usr/bin/curl"' +
                ' && frame.process.cmdline == "curl https://example.com/"' +
                ' && frame.process.ppid == 1 && frame.process.uid == 1000' +
                ' && frame.process.user == "alice"' +
                ' && frame.process.uuid == 6b8b4567-327b-23c6-643c-986966334873' +
                ' && frame.process.start_time == "2026-01-01T00:00:00Z"'),
            # A block with nothing but a process ID.
            (3, 'frame.process.pid == 4321 && !frame.process.name && !frame.process.uid'),
            # A block in a big-endian section.
            (4, 'frame.process.pid == 77 && frame.process.name == "sshd"' +
                ' && frame.process.uid == 0 && !frame.process.user'),
        ])

    def test_frame_process_info_user_name_column(self, cmd_tshark, capture_file, test_env):
        '''The user the process runs as fills the user name column, even
        when no protocol tree is built.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('process_info_wireshark_cb.pcapng'),
                '-o', 'gui.column.format:"No.","%m","User","%U"',
            ), encoding='utf-8', env=test_env)
        assert [line.split() for line in stdout.splitlines()] == [['1', 'alice'], ['2'], ['3'], ['4']]

    def test_frame_process_info_several_processes(self, cmd_tshark, capture_file, test_env, assert_frames_match):
        '''A packet can belong to several processes, one epb_processid_threadid
        option each; all of them are shown, in the order of the file.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('process_info_several.pcapng'),
                '-T', 'fields', '-e', 'frame.process.pid', '-e', 'frame.process.name',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['10,20,30\tsender,receiver,other', '20\treceiver']
        assert_frames_match('process_info_several.pcapng', [
            (1, 'frame.process.pid == 20 && frame.process.pid == 10'),
            (2, 'frame.process.pid == 20 && !(frame.process.pid == 10)'),
        ])

    def test_frame_process_info_pid_reuse(self, assert_frames_match):
        '''With several blocks for one process ID, the start times and
        the time stamp of the packet decide which one it is matched with;
        if every block started later, the last one before the packet.'''
        assert_frames_match('process_info_pid_reuse.pcapng', [
            (1, 'frame.process.name == "first"'),
            (2, 'frame.process.name == "second"'),
            (3, 'frame.process.name == "second"'),
            (4, 'frame.process.name == "new"'),
            (5, 'frame.process.pid == 700 && !frame.process.name'),
        ])

    def test_frame_process_info_file_order(self, assert_frames_match):
        '''Only the blocks that precede a packet in the file are considered,
        as a writer describes a process before its first packet; the last of
        them wins when start times are absent or all later than the packet,
        and blocks after the packet are used only if none precedes it (which
        takes the second pass, as the first has not read them yet).'''
        assert_frames_match('process_info_pid_reuse_order.pcapng', [
            (1, 'frame.process.name == "first"'),
            (2, 'frame.process.name == "first"'),
            (3, 'frame.process.name == "second"'),
            (4, 'frame.process.name == "second"'),
            (5, 'frame.process.name == "a"'),
            (6, 'frame.process.name == "b"'),
            (7, 'frame.process.name == "x"'),
            (8, 'frame.process.name == "late"'),
        ], two_pass=True)

    @pytest.mark.parametrize('capture', ('process_info_darwin_dpib.pcapng', 'process_info_darwin_dpib_be.pcapng'))
    def test_frame_darwin_effective_process(self, assert_frames_match, capture):
        '''The effective process of a Darwin packet is shown when it
        differs from the process, whatever the byte order of the section.'''
        assert_frames_match(capture, [
            (1, 'frame.darwin.process_info.pid == 501 && !frame.darwin.process_info.epid'),
            (3, 'frame.darwin.process_info.pid == 501 && frame.darwin.process_info.epid == 1' +
                ' && frame.darwin.process_info.epname == "launchd"'),
        ])


class TestDissectDnsMqtype:
    '''DNS Multiple QTYPEs EDNS options (RFC 10029).'''

    def test_mqtype_query(self, cmd_tshark, capture_file, test_env):
        '''MQTYPE-Query option (code 20) is decoded with named QTYPEs.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_mqtype.pcap'),
                '-Y', 'frame.number == 1',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.mqtype',
            ), encoding='utf-8', env=test_env)
        # Option code 20 (MQTYPE-Query), QTYPEs AAAA (28) and HTTPS (65)
        assert '20' in stdout
        assert '28' in stdout
        assert '65' in stdout

    def test_mqtype_response(self, cmd_tshark, capture_file, test_env):
        '''MQTYPE-Response option (code 21) is decoded with named QTYPEs.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_mqtype.pcap'),
                '-Y', 'frame.number == 2',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.mqtype',
            ), encoding='utf-8', env=test_env)
        # Option code 21 (MQTYPE-Response), QTYPE AAAA (28) only
        assert '21' in stdout
        assert '28' in stdout

    def test_mqtype_response_empty(self, cmd_tshark, capture_file, test_env):
        '''MQTYPE-Response with an empty QTYPE list is accepted (RFC 10029 §3.4).'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_mqtype.pcap'),
                '-Y', 'frame.number == 3',
                '-Tfields',
                '-e', 'dns.opt.code',
            ), encoding='utf-8', env=test_env)
        # Option code 21 present, no QTYPEs
        assert '21' in stdout


class TestDissectDnsEdnsKeyTag:
    '''DNS edns-key-tag EDNS option (code 14, RFC 8145).'''

    def test_key_tag_single(self, cmd_tshark, capture_file, test_env):
        '''edns-key-tag option with a single key tag value is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_edns_key_tag.pcap'),
                '-Y', 'frame.number == 1',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.key_tag',
            ), encoding='utf-8', env=test_env)
        # Option code 14 (edns-key-tag), key tag 12345
        assert '14' in stdout
        assert '12345' in stdout

    def test_key_tag_multiple(self, cmd_tshark, capture_file, test_env):
        '''edns-key-tag option with multiple key tag values is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_edns_key_tag.pcap'),
                '-Y', 'frame.number == 2',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.key_tag',
            ), encoding='utf-8', env=test_env)
        # Option code 14, two key tags 12345 and 54321
        assert '14' in stdout
        assert '12345' in stdout
        assert '54321' in stdout


class TestDissectDnsUpdateLease:
    def test_ul_lease_only(self, cmd_tshark, capture_file, test_env):
        '''Update Lease option with LEASE field only (4-byte variant) is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_update_lease.pcap'),
                '-Y', 'frame.number == 1',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.ul.lease',
            ), encoding='utf-8', env=test_env)
        # Option code 2 (Update Lease), lease 300 seconds
        assert '2' in stdout
        assert '300' in stdout

    def test_ul_lease_and_key_lease(self, cmd_tshark, capture_file, test_env):
        '''Update Lease option with LEASE and KEY-LEASE fields (8-byte variant) is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_update_lease.pcap'),
                '-Y', 'frame.number == 2',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.ul.lease',
                '-e', 'dns.opt.ul.key_lease',
            ), encoding='utf-8', env=test_env)
        # Option code 2, lease 300 seconds, key lease 600 seconds
        assert '2' in stdout
        assert '300' in stdout
        assert '600' in stdout

class TestTcpFingerprint:
    # Test cases come from
    # https://github.com/ntop/nDPI/blob/dev/fingerprint/nDPI_TCP_fingerprint.md#appendix-a--test-vectors
    @pytest.mark.parametrize("tcpfp_case", [
            # capture file, packet number, fingerprint, option list
            ('fp_tcp_linux_ubuntu24.pcap', 1, '2_64_64240_789c1d1f', '2,4,8,1,3:7'),
            ('fp_tcp_android13.pcapng', 1, '2_64_65535_58b6a464', '2,4,8,1,3:10'),
            ('fp_tcp_android16.pcapng', 1, '2_64_65535_58b6a464', '2,4,8,1,3:10'),
            ('fp_tcp_freebsd15.pcap', 3, '2_64_65535_2b9b4c52', '2,1,3:6,4,8'),
            ('fp_tcp_macos27.pcapng', 1, '194_64_65535_e76f0f14', '2,1,3:6,1,1,8,4,0'),
            ('fp_tcp_iPadOS27.pcapng', 1, '194_64_65535_e76f0f14', '2,1,3:6,1,1,8,4,0'),
            ('fp_tcp_iOS27_iphone.pcapng', 1, '2_64_65535_e76f0f14', '2,1,3:6,1,1,8,4,0'),
            ('fp_tcp_iOS18_iPad.pcapng', 1, '2_64_65535_e76f0f14', '2,1,3:6,1,1,8,4,0'),
            ('fp_tcp_iOS15_iPhone.pcapng', 1, '194_64_65535_2b6d3038', '2,1,3:5,1,1,8,4,0'),
            ('fp_tcp_win10.pcapng', 1, '2_128_64240_47466ece', '2,1,3:8,1,1,4'),
            ('fp_tcp_win11.pcapng', 1, '2_128_65535_47466ece', '2,1,3:8,1,1,4'),
            ('fp_tcp_win11.pcapng', 3, '2_128_65535_47466ece', '2,1,3:8,1,1,4'),
        ])
    def test_tcpfp(self, cmd_tshark, capture_file, test_env, tcpfp_case):
        (cap_file, frame_num, fp, fp_raw) = tcpfp_case
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file(os.path.join("tcpfp", cap_file)),
                '-Y', 'frame.number == '+str(frame_num),
                '-Tfields',
                '-e', 'tcp.fingerprint',
                '-e', 'tcp.fingerprint.raw',
            ), encoding='utf-8', env=test_env)
        (out_fp, out_fp_raw) = stdout.strip().split()
        assert out_fp == fp
        assert out_fp_raw == fp_raw


class TestDissectDnsEdnsExpire:
    def test_edns_expire_query(self, cmd_tshark, capture_file, test_env):
        '''EDNS EXPIRE option in query (zero-length) is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_edns_expire.pcap'),
                '-Y', 'frame.number == 1',
                '-Tfields',
                '-e', 'dns.opt.code',
            ), encoding='utf-8', env=test_env)
        # Option code 9 (EDNS EXPIRE), no data
        assert '9' in stdout

    def test_edns_expire_response(self, cmd_tshark, capture_file, test_env):
        '''EDNS EXPIRE option in response with expire value is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_edns_expire.pcap'),
                '-Y', 'frame.number == 2',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.edns_expire',
            ), encoding='utf-8', env=test_env)
        # Option code 9, expire 86400 seconds
        assert '9' in stdout
        assert '86400' in stdout


class TestDissectDnsNsid:
    def test_nsid_query(self, cmd_tshark, capture_file, test_env):
        '''NSID option in query (zero-length) is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_nsid.pcap'),
                '-Y', 'frame.number == 1',
                '-Tfields',
                '-e', 'dns.opt.code',
            ), encoding='utf-8', env=test_env)
        # Option code 3 (NSID), no data
        assert '3' in stdout

    def test_nsid_response(self, cmd_tshark, capture_file, test_env):
        '''NSID option in response with identifier bytes is decoded.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dns_nsid.pcap'),
                '-Y', 'frame.number == 2',
                '-Tfields',
                '-e', 'dns.opt.code',
                '-e', 'dns.opt.nsid',
            ), encoding='utf-8', env=test_env)
        # Option code 3, NSID = hex of "nyc-dns-01"
        assert '3' in stdout
        assert '6e79632d646e732d3031' in stdout


# acn_coverage.pcap.gz is synthetic: every packet was generated, to cover
# as much of the ACN dissector as possible (ACN SDT and DMP, ETC blobs,
# sACN, Magic Bullet and RDMnet). Its heuristics ship disabled.
ACN_OPTS = ('--enable-heuristic', 'acn',
            '--enable-heuristic', 'rdmnet_udp',
            '--enable-heuristic', 'rdmnet_tcp',
            '-o', 'acn.dmx_enable:TRUE')


class TestDissectAcn:
    def test_acn_heuristics_disabled_by_default(self, cmd_tshark, capture_file, test_env):
        '''Nothing is dissected as ACN unless the heuristics are enabled.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('acn_coverage.pcap.gz'),
                '-Y', 'acn || magic || rdmnet',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_acn_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every part of the capture is found by its heuristic, with no
        malformed packets.'''
        stdout = subprocess.check_output((cmd_tshark, *ACN_OPTS,
                '-r', capture_file('acn_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.split()
        assert protocols.count('ACN') == 56
        assert protocols.count('MAGIC') == 18
        assert protocols.count('RDMnet') == 43
        stdout = subprocess.check_output((cmd_tshark, *ACN_OPTS,
                '-r', capture_file('acn_coverage.pcap.gz'),
                '-Y', '_ws.malformed || _ws.expert.severity == error',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_acn_sacn_universe_discovery(self, cmd_tshark, capture_file, test_env):
        '''Universe lists are shown 16 to a line, including lists of more
        than one universe, which made fortified builds abort.'''
        stdout = subprocess.check_output((cmd_tshark, *ACN_OPTS,
                '-r', capture_file('acn_coverage.pcap.gz'),
                '-Y', 'acn.dmx.discovery.list',
                '-Tfields', '-eacn.dmx.discovery.list', '-E', 'aggregator=|',
            ), encoding='utf-8', env=test_env)
        lists = [[line.split() for line in frame.split('|')[1:]] for frame in stdout.splitlines()]
        assert lists == [
            [['1', '2', '3']],
            [['10', '5', '20', '1']],
            [],
            [[str(u) for u in range(1, 17)], [str(u) for u in range(17, 33)],
             [str(u) for u in range(33, 40)]],
        ]


AJP13_OPTS = ('-d', 'tcp.port==8009,ajp13')  # 8009 is nvme-tcp by default


class TestDissectAjp13:
    def test_ajp13_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every message type, method, coded and named header and request
        attribute decodes without malformed packets, in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark, *AJP13_OPTS,
                '-r', capture_file('ajp13_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.split()
        assert protocols.count('AJP13') == 111
        assert protocols.count('TCP') == 30
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *AJP13_OPTS, *passes,
                    '-r', capture_file('ajp13_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_ajp13_large_query_string(self, cmd_tshark, capture_file, test_env):
        '''A request with a 31000 octet URI and 11000 null query_string
        attributes decodes. It used to keep a copy of the URI for each
        attribute, about 1.4 GB.'''
        stdout = subprocess.check_output((cmd_tshark, *AJP13_OPTS,
                '-r', capture_file('ajp13_coverage.pcap.gz'),
                '-Y', 'ajp13.query_string',
                '-Tfields', '-eframe.number', '-eajp13.uri',
                '-e', 'ajp13.query_string', '-E', 'aggregator=|',
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        assert [f[0] for f in frames] == ['4', '58', '137']
        number, uri, query_strings = frames[2]
        assert uri.endswith('/big')
        assert query_strings == '|' * 10999

    def test_ajp13_export_objects(self, cmd_tshark, capture_file, features, test_env, tmp_path):
        '''Request and response bodies are reassembled and exported,
        uncompressed, and the query string is appended to the URI once.'''
        export_dir = tmp_path / 'export'
        export_dir.mkdir()
        subprocess.check_call((cmd_tshark, *AJP13_OPTS,
                '-r', capture_file('ajp13_coverage.pcap.gz'),
                '-q', '--export-objects', f'ajp13,{export_dir}',
            ), env=test_env)
        text = b'The quick brown fox jumps over the lazy servlet. ' * 8
        files = {p.name: p.read_bytes() for p in export_dir.iterdir()}
        assert sorted(files) == [
            'bad.txt', 'big%3f', 'c.txt', 'd.txt', 'form%3fa=1&b=2', 'form%3fa=1&b=2(1)',
            'index.html%3fq=all&x=1', 'items(1).json', 'items.json',
            'object118.text%2fplain', 'raw', 'raw(1)', 'z.txt',
        ]
        # The large request: a single "?" for the 11000 empty query strings
        assert files['big%3f'] == b'big response\n'
        # Request body over three body packets
        assert files['form%3fa=1&b=2'] == b'name=alice&city=springfield&x=1'
        # gzip response over three chunks and four segments, deflate,
        # x-gzip, x-deflate and an unknown encoding
        assert files['form%3fa=1&b=2(1)'] == text
        assert files['d.txt'] == text
        assert files['c.txt'] == text
        assert files['raw'] == text
        assert files['items.json'] == files['items(1).json']
        assert files['items.json'].startswith(b'{"items":[{"id":0},')
        # Data that is not gzip is exported as it is
        assert files['bad.txt'] == b'this is not gzip data'
        if features.have_brotli:
            assert files['raw(1)'] == text
        if features.have_zstd:
            assert files['z.txt'] == text[:200]


# TCP port 5190 belongs to the "aol" dissector by default.
AIM_OPTS = ('-d', 'tcp.port==5190,aim')


class TestDissectAim:
    def test_aim_port_not_aim_by_default(self, cmd_tshark, capture_file, test_env):
        '''Port 5190 goes to the AOL dissector unless Decode As says AIM.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aim_coverage.pcap.gz'),
                '-Y', 'aim',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_aim_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every SNAC family is dissected, with no malformed packets and
        no errors.'''
        stdout = subprocess.check_output((cmd_tshark, *AIM_OPTS,
                '-r', capture_file('aim_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 261
        assert protocols.count('AIM') == 14
        assert protocols.count('AIM Administration') == 10
        assert protocols.count('AIM Advertisements') == 3
        assert protocols.count('AIM BOS') == 8
        assert protocols.count('AIM Buddylist') == 11
        assert protocols.count('AIM Chat') == 17
        assert protocols.count('AIM ChatNav') == 9
        assert protocols.count('AIM Directory') == 5
        assert protocols.count('AIM Email') == 4
        assert protocols.count('AIM Generic') == 33
        assert protocols.count('AIM ICQ') == 11
        assert protocols.count('AIM Invitation') == 3
        assert protocols.count('AIM Location') == 12
        assert protocols.count('AIM Messaging') == 26
        assert protocols.count('AIM Popup') == 7
        assert protocols.count('AIM Signon') == 9
        assert protocols.count('AIM SSI') == 35
        assert protocols.count('AIM SST') == 7
        assert protocols.count('AIM Stats') == 4
        assert protocols.count('AIM Translate') == 3
        assert protocols.count('AIM User Lookup') == 3
        assert protocols.count('TLSv1.2') == 11
        stdout = subprocess.check_output((cmd_tshark, *AIM_OPTS,
                '-r', capture_file('aim_coverage.pcap.gz'),
                '-Y', '_ws.malformed || _ws.expert.severity == error',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_aim_chat_long_messages(self, cmd_tshark, capture_file, test_env):
        '''Chat messages longer than 999 octets are not shown, and the
        Info column does not pick up an uninitialised buffer.'''
        stdout = subprocess.check_output((cmd_tshark, *AIM_OPTS,
                '-r', capture_file('aim_coverage.pcap.gz'),
                '-Y', 'aim_chat && aim.datalen > 999',
                '-Tfields', '-eframe.number', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '151\tAIM Chat, Outgoing Message -> ',
            '152\tAIM Chat, Incoming Messagefrom:  -> ',
        ]

    def test_aim_chat_short_messages(self, cmd_tshark, capture_file, test_env):
        '''The text of a short chat message is taken from the HTML.'''
        stdout = subprocess.check_output((cmd_tshark, *AIM_OPTS,
                '-r', capture_file('aim_coverage.pcap.gz'),
                '-Y', 'aim_chat.screen_name == "bob"',
                '-Tfields', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            'AIM Chat, Incoming Messagefrom: bob -> llmmtthh',
            'AIM Chat, Incoming Messagefrom: bob -> Hi everybody',
            'AIM Chat, Incoming Messagefrom: bob -> hi',
        ]

    def test_aim_tls_heuristic(self, cmd_tshark, capture_file, test_env):
        '''AIM in a TLS session (NULL cipher) is found by the aim_tls
        heuristic when it is enabled.'''
        stdout = subprocess.check_output((cmd_tshark, *AIM_OPTS,
                '--enable-heuristic', 'aim_tls',
                '-r', capture_file('aim_coverage.pcap.gz'),
                '-Y', 'tls && aim',
                '-Tfields', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            'New Connection',
            'AIM Generic, Server Ready',
        ]

    def test_aim_two_pass(self, cmd_tshark, capture_file, test_env):
        '''One pass and two passes give the same AIM output.'''
        def aim_info(*opts):
            return subprocess.check_output((cmd_tshark, *AIM_OPTS, *opts,
                    '-r', capture_file('aim_coverage.pcap.gz'),
                    '-Y', 'aim',
                    '-Tfields', '-eframe.number', '-e_ws.col.info',
                ), encoding='utf-8', env=test_env)
        assert aim_info() == aim_info('-2')


class TestDissectAfs:
    def test_afs_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every RX data packet is dissected as AFS, with no malformed
        packets or error expert infos.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('afs_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 392
        assert protocols.count('AFS (RX)') == 391
        assert protocols.count('RX') == 1
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('afs_coverage.pcap.gz'),
                '-Y', '_ws.malformed || _ws.expert.severity == error',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_afs_full_tree(self, cmd_tshark, capture_file, test_env):
        '''With the whole tree shown every field is added, which is where
        a field added with the wrong encoding shows up as a dissector bug,
        as the get-xstats timestamp did.'''
        for defragment in ('FALSE', 'TRUE'):
            stdout = subprocess.check_output((cmd_tshark,
                    '-r', capture_file('afs_coverage.pcap.gz'),
                    '-o', 'afs.defragment:' + defragment,
                    '-V', '-O', 'afs',
                ), encoding='utf-8', env=test_env)
            assert 'Malformed Packet' not in stdout
            assert 'Expert Info (Error' not in stdout

    def test_afs_defragment(self, cmd_tshark, capture_file, test_env):
        '''With afs.defragment, the multi-packet store-data request and
        fetch-data reply are reassembled.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('afs_coverage.pcap.gz'),
                '-o', 'afs.defragment:TRUE',
                '-Y', 'afs.fragment.count',
                '-Tfields', '-eframe.number', '-eafs.fragment.count',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['382', '3', '386', '2']

    def test_afs_store_acl(self, cmd_tshark, capture_file, test_env):
        '''Store ACL requests with a huge positive count and with 16000
        entries in one datagram decode quickly and completely.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('afs_coverage.pcap.gz'),
                '-Y', 'frame.number >= 389',
                '-Tfields', '-eframe.number', '-eafs.fs.acl.count.positive',
                '-eafs.fs.acl.entity', '-E', 'aggregator=|',
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        assert [(f[0], f[1], len(f[2].split('|'))) for f in frames] == [
            ('389', '2', 3),
            ('390', '2147483647', 1),
            ('391', '2147483647', 1),
            ('392', '16000', 16000),
        ]


# The capture is SS7 over M3UA with ANSI point codes and SCCP addresses.
AIN_OPTS = ('-o', 'mtp3.standard:ANSI')


class TestDissectAin:
    def test_ain_needs_ansi_mtp3(self, cmd_tshark, capture_file, test_env):
        '''With the default (ITU) MTP3 standard the ANSI SCCP addresses do
        not route to TCAP, so nothing is dissected as AIN.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ain_coverage.pcap.gz'),
                '-Y', 'ain',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_ain_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every operation is dissected, with no malformed packets and no
        warning or error expert infos.'''
        stdout = subprocess.check_output((cmd_tshark, *AIN_OPTS,
                '-r', capture_file('ain_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 131
        assert protocols.count('AIN') == 130
        # the Reject is not passed to AIN
        assert protocols.count('ANSI TCAP') == 1
        stdout = subprocess.check_output((cmd_tshark, *AIN_OPTS,
                '-r', capture_file('ain_coverage.pcap.gz'),
                '-Y', '_ws.malformed || _ws.expert.severity >= "Warning"',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_ain_parameters(self, cmd_tshark, capture_file, test_env):
        '''The hand-written AINDigits, CarrierFormat and AMAslpID bodies and
        the ExtensionParameter OID callback decode their values.'''
        for dfilter, frames in (
                ('ain.bcd_digits == "9085551212"', 47),
                ('ain.carrier_bcd_digits == "0288"', 17),
                ('ain.amaslpid == "123456789"', 29),
                ('ain.ext_type_oid == "2.5.4.3" && x509sat.printableString == "AIN synthetic extension"', 121),
                ):
            stdout = subprocess.check_output((cmd_tshark, *AIN_OPTS,
                    '-r', capture_file('ain_coverage.pcap.gz'),
                    '-Y', dfilter,
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == frames, dfilter

    def test_ain_return_result(self, cmd_tshark, capture_file, test_env):
        '''An Invoke and its ReturnResult in one package (it used to hit
        DISSECTOR_ASSERT_NOT_REACHED in dissect_ain()) decodes the result
        of the invoked operation.'''
        stdout = subprocess.check_output((cmd_tshark, *AIN_OPTS,
                '-r', capture_file('ain_coverage.pcap.gz'),
                '-Y', 'frame.number == 1',
                '-Tfields', '-e_ws.col.info', '-eain.actResult', '-e_ws.malformed',
            ), encoding='utf-8', env=test_env)
        assert stdout == 'activityTest ReturnResult \t0\t\n'
        # Every ReturnResult (one for each of the 12 operations with a
        # result, more for those sent several times) gets its operation
        stdout = subprocess.check_output((cmd_tshark, *AIN_OPTS,
                '-r', capture_file('ain_coverage.pcap.gz'),
                '-Y', '_ws.col.info contains "ReturnResult"',
                '-Tfields', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 33
        assert 'Unknown' not in stdout

    def test_ain_two_pass(self, cmd_tshark, capture_file, test_env):
        '''Two passes give the same AIN output as one.'''
        outputs = []
        for passes in ((), ('-2',)):
            outputs.append(subprocess.check_output((cmd_tshark, *AIN_OPTS, *passes,
                    '-r', capture_file('ain_coverage.pcap.gz'),
                    '-O', 'ain', '-V',
                ), encoding='utf-8', env=test_env))
        assert outputs[0] == outputs[1]


# AMP is reached by default from BPv6 bundles on UDP port 4556; frames
# 54-56 are AMP directly on UDP, which is only offered in Decode As.
AMP_OPTS = ('-d', 'udp.port==40001,amp')


class TestDissectAmp:
    def amp_fields(self, cmd_tshark, capture_file, test_env, *fields, opts=AMP_OPTS):
        args = []
        for field in fields:
            args += ['-e', field]
        stdout = subprocess.check_output((cmd_tshark, *opts,
                '-r', capture_file('amp_coverage.pcap.gz'),
                '-Tfields', '-E', 'aggregator=|', '-e', 'frame.number', *args,
            ), encoding='utf-8', env=test_env)
        return {int(line.split('\t')[0]): line.split('\t')[1:] for line in stdout.splitlines()}

    def test_amp_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every message type, CBOR head form and TNVC data item kind
        decodes without malformed packets or error expert infos, in one
        and two passes, with and without the UDP Decode As.'''
        for opts, bundle, amp, udp in (((), 53, 0, 3), (AMP_OPTS, 53, 3, 0)):
            stdout = subprocess.check_output((cmd_tshark, *opts,
                    '-r', capture_file('amp_coverage.pcap.gz'),
                    '-Tfields', '-e_ws.col.protocol',
                ), encoding='utf-8', env=test_env)
            protocols = stdout.split()
            assert protocols.count('Bundle') == bundle
            assert protocols.count('AMP') == amp
            assert protocols.count('UDP') == udp
            for passes in ((), ('-2',)):
                stdout = subprocess.check_output((cmd_tshark, *opts, *passes,
                        '-r', capture_file('amp_coverage.pcap.gz'),
                        '-Y', '_ws.malformed || _ws.expert.severity >= warning',
                        '-Tfields', '-eframe.number',
                    ), encoding='utf-8', env=test_env)
                assert count_output(stdout) == 0

    def test_amp_in_bundles(self, cmd_tshark, capture_file, test_env):
        '''Bundles with service numbers 5 and 6 carry AMP by default: all
        but frame 39 (only a timestamp) have an AMP message.'''
        frames = self.amp_fields(cmd_tshark, capture_file, test_env, 'amp.opcode', opts=())
        with_messages = [n for n, (opcodes,) in frames.items() if opcodes]
        assert with_messages == [n for n in range(1, 54) if n != 39]

    def test_amp_messages(self, cmd_tshark, capture_file, test_env):
        '''Several messages in one PDU, with Perform Control, Table Set and
        undefined opcodes between Register Agent messages.'''
        frames = self.amp_fields(cmd_tshark, capture_file, test_env,
                                 'amp.opcode', 'amp.agent_name')
        assert frames[40] == ['0|2|0|3|4|5|6|7|0', 'agent-7|agent-8|agent-9']
        assert frames[2] == ['0', 'agent-2.example']
        assert frames[54] == ['0', 'udp-agent']

    def test_amp_tnvc_items(self, cmd_tshark, capture_file, test_env):
        '''TNVC data items of valid sizes are all dissected, and the
        dissector steps over each one correctly. A larger-than-packet
        item stops the loop with an expert info ("AMP: Stop at a TNVC item
        larger than the packet"); these must not be affected.'''
        frames = self.amp_fields(cmd_tshark, capture_file, test_env,
                                 'amp.rx_name', 'amp.string', 'amp.report.integer8_small',
                                 'amp.report.integer', 'amp.report.data')
        # Every item kind: strings, uvast of every size, a non-integer
        # uvast, a byte string of an unhandled type, a text string and
        # an integer item
        assert frames[46] == ['mgr-1', 'ifInOctets|' + 'x' * 30, '23',
                              '200|4660|305419896|1311768467463790320', '726177|41']
        # Two reports with timestamps
        assert frames[44] == ['mgr-1|mgr-2.example', 'ok', '5', '', '']
        # The PDU goes on after the TNVC items: a Register Agent follows
        stdout = subprocess.check_output((cmd_tshark, *AMP_OPTS,
                '-r', capture_file('amp_coverage.pcap.gz'),
                '-Y', 'frame.number == 53',
                '-Tfields', '-eamp.opcode', '-eamp.report.integer', '-eamp.agent_name',
                '-E', 'aggregator=|',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '1|0\t42\tagent-10'
        # The same over UDP
        assert frames[55] == ['udp-mgr', 'udp', '', '77', '']


# amr_coverage.pcapng.gz is synthetic: every packet was generated, to
# cover as much of the AMR dissector as possible. SIP/SDP sets up RTP
# with AMR and AMR-WB in every fmtp variant; one RTP flow has no SDP and
# needs Decode As; the rest are Exported PDUs (named AMR dissectors and
# an H.245 TerminalCapabilitySet with the AMR capabilities).
AMR_OPTS = ('-d', 'udp.port==50000,rtp',
            '-d', 'rtp.pt==97,amr',
            '-d', 'rtp.pt==98,amr_wb')


class TestDissectAmr:
    def test_amr_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every part of the capture decodes, with no malformed packets or
        errors, in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 113
        # 9 AMR and 8 AMR-WB frames are IF1/IF2
        assert protocols.count('AMR') == 61
        assert protocols.count('AMR-WB') == 45
        assert protocols.count('SIP/SDP') == 4
        assert protocols.count('SIP') == 2
        assert protocols.count('H.245') == 1
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS, *passes,
                    '-r', capture_file('amr_coverage.pcapng.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_amr_exported_pdu_tcp_info(self, cmd_tshark, capture_file, test_env):
        '''An exported PDU for "amr" or "amr-wb" with a TCP information tag
        decodes as AMR with the preferences (octet-aligned). The struct
        tcpinfo used to be handed to AMR, which read it as RTP
        information and crashed.'''
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Y', 'exported_pdu.tcp_dissector_data.version == 1',
                '-Tfields', '-eframe.number', '-e_ws.col.protocol',
                '-eamr.payload_decoded_as', '-eamr.nb.toc.ft', '-eamr.wb.toc.ft',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '90\tAMR\t0\t7\t',
            '91\tAMR-WB\t0\t\t8',
        ]

    def test_amr_sdp_fmtp(self, cmd_tshark, capture_file, test_env):
        '''The SDP fmtp parameters of each RTP payload type choose the
        format: octet-aligned for octet-align=1, crc=1, interleaving or
        robust-sorting, bandwidth-efficient otherwise.'''
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Y', 'rtp && udp.port != 50000 && !amr.reserved.not_zero',
                '-Tfields', '-ertp.p_type', '-eamr.payload_decoded_as',
            ), encoding='utf-8', env=test_env)
        formats = {}
        for line in stdout.splitlines():
            pt, fmt = line.split('\t')
            formats.setdefault(int(pt), set()).add(fmt)
        assert formats == {
            96: {'1'}, 97: {'0'}, 98: {'0'}, 99: {'0'}, 100: {'0'}, 101: {'1'}, 102: {'0'},
            104: {'1'}, 105: {'0'}, 106: {'0'}, 107: {'0'}, 108: {'0'}, 109: {'1'},
        }
        # CRCs and interleaving headers from the SDP
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Y', 'amr.crc || amr.ill',
                '-Tfields', '-eframe.number', '-eamr.crc', '-eamr.ill', '-eamr.ilp',
                '-E', 'aggregator=,',
            ), encoding='utf-8', env=test_env)
        lines = stdout.splitlines()
        assert '39\t0xa0,0xa1,0xa2\t\t' in lines
        assert '43\t\t3\t3' in lines
        assert '80\t0xa0,0xa1\t\t' in lines
        assert len(lines) == 14

    def test_amr_preferences(self, cmd_tshark, capture_file, test_env):
        '''The encoding preference applies to RTP set up by Decode As and
        to exported PDUs, not to RTP set up by SDP.'''
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-o', 'amr.encoding.version:bw_efficient',
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Y', 'frame.number in {23, 85, 88, 90, 92}',
                '-Tfields', '-eframe.number', '-eamr.payload_decoded_as',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['23\t0', '85\t1', '88\t1', '90\t1', '92\t1']

    def test_amr_h245_capability(self, cmd_tshark, capture_file, test_env):
        '''The AMR names the H.245 generic audio capability parameters.'''
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Y', 'h245', '-O', 'h245', '-V',
            ), encoding='utf-8', env=test_env)
        assert 'genericAudioCapability (20): H.245 - GSM AMR Capability Identifier' in stdout
        for name in ('maxAl-sduAudioFrames', 'gsmAmrComfortNoise', 'gsmEfrComfortNoise',
                     'is-641ComfortNoise', 'pdcEFRComfortNoise', 'maxAl-sduFrames',
                     'octetAlign', 'modeSet', 'modeChangePeriod', 'modeChangeNeighbour',
                     'robustSorting', 'interleaving'):
            assert f': {name}\n' in stdout

    def test_amr_if1_if2(self, cmd_tshark, capture_file, test_env):
        '''The IF1 and IF2 dissectors, called by name.'''
        stdout = subprocess.check_output((cmd_tshark, *AMR_OPTS,
                '-r', capture_file('amr_coverage.pcapng.gz'),
                '-Y', 'exported_pdu.prot_name matches "^amr_if"',
                '-Tfields', '-eexported_pdu.prot_name',
                '-eamr.nb.if1.ft', '-eamr.wb.if1.ft', '-eamr.nb.if2.ft', '-eamr.wb.if2.ft',
                '-eamr.if1.sti', '-eamr.if2.sti',
            ), encoding='utf-8', env=test_env)
        lines = [line.split('\t') for line in stdout.splitlines()]
        assert [line[0] for line in lines] == \
            ['amr_if1_nb'] * 5 + ['amr_if1_wb'] * 4 + ['amr_if2_nb'] * 4 + ['amr_if2_wb'] * 4
        assert [line[1] for line in lines[:5]] == ['7', '0', '8', '8', '5']
        assert [line[2] for line in lines[5:9]] == ['8', '0', '9', '2']
        assert [line[3] for line in lines[9:13]] == ['7', '2', '8', '15']
        assert [line[4] for line in lines[13:]] == ['8', '1', '9', '15']
        # SID frames: SID_UPDATE in IF1, SID_UPDATE in IF2
        assert lines[2][5] == 'True' and lines[7][5] == 'True'
        assert lines[11][6] == 'True' and lines[15][6] == 'True'



class TestDissectExportedPdu:
    def run_fields(self, cmd_tshark, capture_file, test_env, *args):
        return subprocess.check_output((cmd_tshark,
                '-r', capture_file('exported_pdu_coverage.pcap.gz'), *args,
            ), encoding='utf-8', env=test_env)

    def test_exported_pdu_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every tag and the three ways to name the next dissector decode
        without malformed packets, in one and two passes.'''
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Tfields', '-e_ws.col.protocol')
        protocols = stdout.splitlines()
        assert len(protocols) == 104
        assert protocols.count('HTTP') == 10
        assert protocols.count('DNS') == 10
        assert protocols.count('Rlogin') == 6
        assert protocols.count('NBSS') == 6
        assert protocols.count('RTMP') == 3
        assert protocols.count('TLSv1.3') == 3
        assert protocols.count('FINGER') == 3
        assert protocols.count('SIP') == 3
        assert protocols.count('MPA') == 2
        assert protocols.count('WHOIS') == 2
        assert protocols.count('AMR') == 1
        assert protocols.count('AMR-WB') == 1
        assert protocols.count('SS7') == 4
        assert protocols.count('CI+ SAC message') == 2
        assert protocols.count('Exported PDU') == 6
        for passes in ((), ('-2',)):
            stdout = self.run_fields(cmd_tshark, capture_file, test_env, *passes,
                    '-Y', '_ws.malformed || _ws.expert.severity >= error',
                    '-Tfields', '-eframe.number')
            assert count_output(stdout) == 0

    def test_exported_pdu_tcpinfo_not_for_amr(self, cmd_tshark, capture_file, test_env):
        '''AMR named with a TCP information tag decodes. The struct tcpinfo
        used to be passed to it, read as a struct _rtp_info, and crashed.'''
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Y', 'amr', '-Tfields', '-eframe.number', '-eexported_pdu.prot_name',
                '-eexported_pdu.tcp_dissector_data.version', '-eamr.nb.toc.ft', '-eamr.wb.toc.ft')
        assert stdout.splitlines() == ['35\tamr\t1\t7\t', '36\tamr-wb\t1\t\t8']

    def test_exported_pdu_tcpinfo_for_tcp(self, cmd_tshark, capture_file, test_env):
        '''The TCP information still reaches dissectors that TCP calls:
        by name, through a "tcp" heuristic and through the tcp.port table.'''
        # rlogin sees the urgent pointer: tcp.port table (14, 33), by name (25)
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Y', 'rlogin.control_message', '-Tfields', '-eframe.number',
                '-erlogin.control_message')
        assert stdout.splitlines() == ['14\t0x80', '25\t0x02', '33\t0x10']
        # NBSS rejects a PDU without TCP information: with it by table (15,
        # 16, 34) and by name (26); with no tag (40) or an unsupported
        # version (41) it is given empty TCP information
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Y', 'nbss', '-Tfields', '-eframe.number')
        assert stdout.split() == ['15', '16', '26', '34', '40', '41']
        # RTMP names the handshake from the sequence numbers; MPA is found by
        # the iwarp_mpa_tcp heuristic (19) and by name (28)
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Y', 'rtmpt || iwarp_mpa', '-Tfields', '-eframe.number', '-e_ws.col.info')
        assert stdout.splitlines() == [
            '17\tHandshake C0+C1', '18\tHandshake S0+S1+S2', '19\t40009 > 40100 MPA Request Frame',
            '27\tHandshake C0+C1', '28\t40022 > 40101 MPA Request Frame']
        # The rtmpt_tcp heuristic matches the server handshake at sequence
        # number 1 and acknowledgment 1538 only
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '--enable-heuristic', 'rtmpt_tcp', '-Y', 'frame.number == 32',
                '-Tfields', '-e_ws.col.protocol', '-e_ws.col.info')
        assert stdout.strip() == 'RTMP\tHandshake S0+S1+S2'

    def test_exported_pdu_tags(self, cmd_tshark, capture_file, test_env):
        '''Decoded values of the address, 3GPP and column tags, and the
        warnings for unknown tags, short 3GPP identities and unsupported
        TCP information versions.'''
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Y', 'exported_pdu.3gpp.id_type || exported_pdu.3gpp_ue_id_type',
                '-Tfields', '-eframe.number', '-eexported_pdu.3gpp.ci',
                '-eexported_pdu.3gpp.eci', '-eexported_pdu.3gpp.nci',
                '-ee212.assoc.imsi', '-E', 'occurrence=f')
        lines = stdout.splitlines()
        assert lines[:3] == ['88\t0x5678\t\t\t', '89\t\t0x0abcdef1\t\t', '90\t\t\t0x0000000123456789\t']
        assert lines[7:9] == ['96\t\t\t\t001010123456789', '97\t\t\t\t310410987654321']
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-Y', 'frame.number in {20, 65, 67, 77, 80}', '-Tfields', '-eframe.number',
                '-e_ws.col.def_src', '-e_ws.col.def_dst', '-e_ws.col.info')
        assert stdout.splitlines() == [
            '20\t2001:db8::1\t2001:db8::2\tGET /index.html HTTP/1.1 ',
            '65\t2001:db8::1\t2001:db8::2\tStandard query 0x1234 A example.com',
            '67\t4661\t1384\tSS7 standard 1',
            '77\t10.1.0.1\t10.1.0.2\tStandard query 0x1234 A example.com',
            '80\t\t\tno dissector tag']
        # frames with each warning
        for expert, count in (('exported_pdu.tag.unknown', 3),
                              ('exported_pdu.tag_len.unexpected', 4),
                              ('exported_pdu.tcp_dissector_data.version.invalid', 3)):
            stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                    '-Y', expert, '-Tfields', '-eframe.number')
            assert count_output(stdout) == count

    def test_exported_pdu_user_data_pdu(self, cmd_tshark, capture_file, test_env):
        '''The User Data PDU tag uses the dissector in the preference.'''
        stdout = self.run_fields(cmd_tshark, capture_file, test_env,
                '-o', 'exported_pdu.user_data_pdu:http', '-Y', 'frame.number == 87',
                '-Tfields', '-ehttp.request.uri')
        assert stdout.strip() == '/index.html'


# amqp_coverage.pcap.gz is synthetic: an AMQP 0-8, 0-9 and 0-10 part
# (hosts in 10.0.0.0/24) and an AMQP 1.0 part (hosts in 10.1.0.0/24).
AMQP0_HOSTS = 'ip.addr==10.0.0.0/24'


def amqp0_fields(cmd_tshark, capture_file, test_env, dfilter, *fields, passes=()):
    '''Run tshark on the AMQP 0-x frames and return one list of field
    values per frame.'''
    args = []
    for f in fields:
        args += ['-e', f]
    stdout = subprocess.check_output((cmd_tshark, *passes,
            '-r', capture_file('amqp_coverage.pcap.gz'),
            '-Y', f'{AMQP0_HOSTS} && ({dfilter})',
            '-Tfields', *args,
        ), encoding='utf-8', env=test_env)
    return [line.split('\t') for line in stdout.splitlines()]


def amqp0_base(cmd_tshark, capture_file, test_env):
    '''Frame number before the first AMQP 0-x frame (the SYN of the first
    0-9 connection is frame base + 1).'''
    frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                          'ip.src==10.0.0.1 && tcp.flags.syn==1', 'frame.number')
    return int(frames[0][0]) - 1


AMQP10_HOSTS = 'ip.addr==10.1.0.0/24'


class TestDissectAmqp:
    def test_amqp0_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every AMQP 0-8, 0-9, 0-9-1 and 0-10 class, method, control,
        command and struct decodes without malformed packets or error
        expert infos, in one and two passes.'''
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'frame', '_ws.col.protocol')
        protocols = [f[0] for f in frames]
        assert protocols.count('AMQP') == 261
        assert protocols.count('AMQP/JSON') == 13
        assert protocols.count('TCP') == 31
        for passes in ((), ('-2',)):
            frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                                  '_ws.malformed || _ws.expert.severity == error',
                                  'frame.number', passes=passes)
            assert frames == []

    def test_amqp0_classes(self, cmd_tshark, capture_file, test_env):
        '''All twelve 0-9 method classes, all ten 0-10 classes, every
        field table type and every 0-10 struct.'''
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.method.class',
                              'amqp.method.class')
        classes = {int(c) for f in frames for c in f[0].split(',')}
        assert classes == {10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 100, 110}
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.class', 'amqp.class')
        assert {int(c) for f in frames for c in f[0].split(',')} == set(range(1, 11))
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.field.type', 'amqp.field.type')
        types = {t for f in frames for t in f[0].split(',')}
        assert types == {f"'{t}'" for t in 'AbBdDfFiIlsStTuVx'}
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.struct32.class',
                              'amqp.struct32.class', 'amqp.struct32.struct')
        structs = {(int(c), int(s)) for f in frames
                   for c, s in zip(f[0].split(','), f[1].split(','))}
        assert structs == {(4, 1), (4, 2), (4, 3), (4, 4), (4, 5), (6, 1), (6, 3),
                           (7, 1), (7, 2), (8, 1), (9, 1), (10, 1)}

    def test_amqp0_version_detection(self, cmd_tshark, capture_file, test_env):
        '''The 0-9, 0-9-1, 0-8 and 0-10 protocol headers set the version.
        The 0-11 header is not recognised, so it is shown as an unknown
        version and the frames that follow are recognised as 0-9 by their
        frame end octet; connections captured mid-way are recognised too.'''
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.init.version_minor',
                              'amqp.init.version_major', 'amqp.init.version_minor')
        assert frames == [['0', '9'], ['9', '1'], ['8', '0'], ['0', '9'], ['0', '10'], ['0', '10']]
        frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                              '_ws.col.info == "AMQP (unknown version)"', 'tcp.srcport')
        assert frames == [['40004']]
        # The mid-way 0-9 and 0-10 connections
        frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                              'ip.addr==10.0.0.6 || ip.addr==10.0.0.9', '_ws.col.info')
        assert [f[0].split()[0] for f in frames] == [
            'Basic.Deliver', 'Basic.Ack', 'Heartbeat', 'message.transfer', 'message.accept']

    def test_amqp0_delivery_tracking(self, cmd_tshark, capture_file, test_env):
        '''Basic.Publish is numbered per channel, and Basic.Ack, Nack and
        Reject point at the messages they acknowledge (multiple too, and a
        multiple ack of tag 0 acknowledges all), in each direction. A second
        pass keeps them and adds the frame that acknowledges each message.'''
        base = amqp0_base(cmd_tshark, capture_file, test_env)
        frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                              'amqp.method.arguments.publish_number',
                              'frame.number', 'amqp.method.arguments.publish_number')
        assert [(int(n) - base, int(p)) for n, p in frames] == [
            (47, 1), (106, 2), (128, 1), (129, 2), (130, 3), (131, 4), (132, 5)]
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.message_in',
                              'frame.number', 'amqp.message_in')
        acks = {int(n) - base: [int(m) - base for m in msgs.split(',')] for n, msgs in frames}
        assert acks == {
            50: [49], 53: [52],                         # deliver, get-ok
            133: [128, 129], 134: [130], 135: [131, 132],  # publisher confirms
            145: [141], 146: [142, 143], 147: [144],      # consumer ack, nack, reject
            149: [148], 152: [151], 154: [153], 184: [183],
        }
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.message_in',
                              'frame.number', 'amqp.message_in', passes=('-2',))
        assert {int(n) - base: [int(m) - base for m in msgs.split(',')] for n, msgs in frames} == acks
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'amqp.ack_in',
                              'frame.number', 'amqp.ack_in', passes=('-2',))
        assert {int(n) - base: int(a) - base for n, a in frames} == {
            msg: ack for ack, msgs in acks.items() for msg in msgs}

    def test_amqp0_content(self, cmd_tshark, capture_file, test_env):
        '''Content bodies are handed to the dissector for the content-type
        of the basic content header on the same channel, a body is
        reassembled from three TCP segments, and a 0-10 message.transfer
        split over TCP segments is joined.'''
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'json', 'amqp.method.class')
        assert len(frames) == 13
        frames = amqp0_fields(cmd_tshark, capture_file, test_env, 'data-text-lines',
                              'amqp.method.properties.content_type')
        assert frames == [['text/plain'], ['text/plain']]
        frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                              'amqp.payload && len(amqp.payload) == 3000', 'tcp.reassembled.length')
        assert frames == [['3008']]
        frames = amqp0_fields(cmd_tshark, capture_file, test_env,
                              'amqp.message.message-properties.content-type',
                              'amqp.message.message-properties.content-type',
                              'amqp.message.delivery-properties.routing-key')
        assert frames == [['application/json', 'rk.orders'], ['text/plain', 'rk.orders']]

    def test_amqp10_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every AMQP 1.0 performative, SASL frame, message section, type
        encoding and delivery state decodes without malformed packets or
        error expert infos, in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', AMQP10_HOSTS,
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.split()
        assert protocols.count('AMQP') == 136
        assert protocols.count('TCP') == 75
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('amqp_coverage.pcap.gz'),
                    '-Y', f'{AMQP10_HOSTS} && (_ws.malformed || _ws.expert.severity == error)',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_amqp10_frames(self, cmd_tshark, capture_file, test_env):
        '''Protocol headers (AMQP, TLS, SASL), all nine performatives and
        all five SASL frames.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && amqp',
                '-Tfields', '-eamqp.init.id', '-eamqp.performative', '-eamqp.sasl.method',
                '-E', 'occurrence=a', '-E', 'aggregator=,',
            ), encoding='utf-8', env=test_env)
        ids, performatives, sasl = [], [], []
        for line in stdout.splitlines():
            i, p, s = line.split('\t')
            ids += [int(v) for v in i.split(',') if v]
            performatives += [int(v) for v in p.split(',') if v]
            sasl += [int(v) for v in s.split(',') if v]
        assert (ids.count(0), ids.count(2), ids.count(3)) == (10, 2, 12)
        assert [performatives.count(p) for p in range(0x10, 0x19)] == [8, 8, 11, 5, 31, 10, 4, 4, 8]
        assert [sasl.count(s) for s in range(0x40, 0x45)] == [6, 6, 1, 1, 6]

    def test_amqp10_sections_and_states(self, cmd_tshark, capture_file, test_env):
        '''Every message section, delivery state, outcome, lifetime policy
        and transaction type is found.'''
        fields = ('amqp.header', 'amqp.deliveryAnnotations', 'amqp.messageAnnotations',
                  'amqp.properties', 'amqp.applicationProperties', 'amqp.data',
                  'amqp.sequence', 'amqp.value', 'amqp.footer',
                  'amqp.delivery-state.received', 'amqp.delivery-state.accepted',
                  'amqp.delivery-state.rejected', 'amqp.delivery-state.released',
                  'amqp.delivery-state.modified', 'amqp.performative.arguments.error',
                  'amqp.lifetime-policy.deleteOnClose', 'amqp.lifetime-policy.deleteOnNoLinks',
                  'amqp.lifetime-policy.deleteOnNoMessages',
                  'amqp.lifetime-policy.deleteOnNoLinksOrMessages',
                  'amqp.tx.coordinator', 'amqp.tx.declare', 'amqp.tx.declared',
                  'amqp.tx.discharge', 'amqp.tx.transactionalState')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && amqp', '-T', 'json',
            ), encoding='utf-8', env=test_env)
        missing = [f for f in fields if f'"{f}"' not in stdout]
        assert missing == []

    def test_amqp10_values(self, cmd_tshark, capture_file, test_env):
        '''Values decoded with the native field types: integers, strings,
        symbols, binaries, timestamps and UUIDs, including the
        type-specific message-id fields.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && amqp.performative.arguments.containerId == "client-container-1"',
                '-Tfields', '-eamqp.performative.arguments.maxFrameSize',
                '-eamqp.performative.arguments.channelMax',
                '-eamqp.performative.arguments.idleTimeout',
                '-eamqp.performative.arguments.outgoingLocales_sym',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '65536\t255\t30000\ten-US'
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && amqp.message.messageId.guid',
                '-Tfields', '-eamqp.message.messageId.guid',
                '-eamqp.message.correlationId.bytes',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '01234567-89ab-cdef-0123-456789abcdef\t010203'
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && amqp.message.creationTime',
                '-Tfields', '-eamqp.message.messageId.uint', '-eamqp.message.to.string',
                '-eamqp.message.creationTime', '-eamqp.message.expiryTime',
                '-eamqp.message.groupSequence',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip().split('\t') == ['7', 'queue://orders',
                                               '2025-10-09T08:53:20.123000000Z',
                                               '2025-10-09T09:53:20.123000000Z', '3']

    def test_amqp10_primitive_types(self, cmd_tshark, capture_file, test_env):
        '''Every primitive type encoding in a custom list is shown with its
        type name and value.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && amqp.performative.arguments.deliveryTag == "types-1"',
                '-O', 'amqp', '-V',
            ), encoding='utf-8', env=test_env)
        assert 'AMQP-Sequence (list of 46 elements)' in stdout
        for text in ('list-item: (null)', 'list-item (bool): true', 'list-item (ubyte): 200',
                     'list-item (ushort): 60000', 'list-item (uint): 4000000000',
                     'list-item (uint0): 0', 'list-item (ulong): 1234605616436508552',
                     'list-item (smallulong): 99', 'list-item (ulong0): 0',
                     'list-item (byte): -100', 'list-item (short): -30000',
                     'list-item (int): -2000000000', 'list-item (smallint): -17',
                     'list-item (long): -77162851027281784', 'list-item (smalllong): -99',
                     'list-item (decimal32): (not supported)',
                     'list-item (decimal128): (not supported)', 'list-item (char): €',
                     'list-item (timestamp): Oct  9, 2025 08:53:20.123000000',
                     'list-item (uuid): 01234567-89ab-cdef-0123-456789abcdef',
                     'list-item (vbin32): ffffff', 'list-item (str32-utf8): long-form string',
                     'list-item (sym32): long-form-symbol', 'k32 (uint): 32',
                     'list-item (array of 2 elements)'):
            assert text in stdout, text
        # Floats are shown with the decimal separator of the locale
        for text in ('list-item (float): 1.500000', 'list-item (double): -2.250000'):
            assert text in stdout or text.replace('.', ',') in stdout, text

    def test_amqp10_reassembly(self, cmd_tshark, capture_file, test_env):
        '''A transfer over three TCP segments (the first split inside the
        frame header) and frames that share a segment are reassembled;
        a connection captured in the middle is still found to be 1.0.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', 'ip.addr==10.1.0.5 && amqp.data',
                '-Tfields', '-eamqp.data', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        data = [line.split('\t') for line in stdout.splitlines()]
        assert data[0][0] == bytes(range(256)).hex() * 3
        assert data[1][0] == b'tail of the message'.hex()
        # the next transfer starts in the same segment and ends in the
        # segment that also carries the one after it
        assert data[2] == [b'partial'.hex(), 'transfer transfer ']
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', 'ip.addr==10.1.0.6 && amqp',
                '-Tfields', '-eamqp.performative',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['19', '20']

    def test_amqp10_message_decoding(self, cmd_tshark, capture_file, test_env):
        '''The "Message Decoding" table hands the data section to another
        dissector for messages whose "to" address matches, for each match
        criterion.'''
        uat = ('"Equal to","sensors/equal"', '"Contains","contains-me"',
               '"Starts with","prefix/"', '"Ends with",".suffix"',
               '"Regular Expression","^regex-[0-9]+$"')
        opts = []
        for entry in uat:
            # The payload dissector is "data", which ignores the dissector
            # data (the "Additional Data" string).
            opts += ['-o', f'uat:amqp_message_decoding:{entry},"data",""']
        stdout = subprocess.check_output((cmd_tshark, *opts,
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', 'ip.addr==10.1.0.9 && amqp.performative == 20',
                '-V', '-Tfields', '-eamqp.message.to.string', '-edata.data', '-eamqp.data',
            ), encoding='utf-8', env=test_env)
        rows = [line.split('\t') for line in stdout.splitlines()]
        decoded = [to for to, data, amqp_data in rows if data and not amqp_data]
        assert decoded == ['sensors/equal', 'x/contains-me/y', 'prefix/abc', 'abc.suffix', 'regex-42']
        assert len(rows) == 8

    def test_amqp10_message_decoding_additional_data(self, cmd_tshark, capture_file, test_env):
        '''The "Additional Data" string of a Message Decoding entry is not
        given to a dissector that reads its data as a structure of its own
        (data-text-lines reads it as a media_content_info_t, and crashed).'''
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'uat:amqp_message_decoding:"Equal to","sensors/equal","data-text-lines","message,example.Reading"',
                '-r', capture_file('amqp_coverage.pcap.gz'),
                '-Y', f'{AMQP10_HOSTS} && data-text-lines',
                '-Tfields', '-eamqp.message.to.string',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['sensors/equal']


class TestDissectAnsi637:
    @staticmethod
    def fields(cmd_tshark, capture_file, test_env, frames, *fields, passes=()):
        '''Return {frame number: [field values]} for the given frames.'''
        args = [cmd_tshark, *passes, '-r', capture_file('ansi_637_coverage.pcap.gz'),
                '-Y', ' || '.join(f'frame.number == {n}' for n in frames),
                '-Tfields', '-E', 'aggregator=|', '-e', 'frame.number']
        for f in fields:
            args += ['-e', f]
        stdout = subprocess.check_output(args, encoding='utf-8', env=test_env)
        out = {}
        for line in stdout.splitlines():
            values = line.split('\t')
            out[int(values[0])] = values[1:]
        return out

    def test_ansi_637_protocols(self, cmd_tshark, capture_file, test_env):
        '''The transport layer over SIP and the IOS A interface, the
        teleservice layer over ANSI-41 MAP and both by name decode without
        malformed packets or errors, in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_637_coverage.pcap.gz'),
                '-Tfields', '-e', 'frame.protocols',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.split()
        assert len(protocols) == 133
        assert protocols.count('exported_pdu:ip:udp:sip:ansi_637_trans:ansi_637_tele') == 35
        assert protocols.count('exported_pdu:ip:udp:sip:ansi_637_trans') == 26
        assert protocols.count('exported_pdu:ansi_tcap:ansi_map:ansi_637_tele') == 60
        assert protocols.count('exported_pdu:ansi_a_bsmap:ansi_637_trans:ansi_637_tele') == 1
        assert protocols.count('exported_pdu:ansi_a_dtap:ansi_637_trans:ansi_637_tele') == 1
        assert protocols.count('exported_pdu:ansi_a_dtap:ansi_637_trans') == 1
        assert protocols.count('exported_pdu:ansi_637_trans:ansi_637_tele') == 6
        assert protocols.count('exported_pdu:ansi_637_trans') == 1
        assert protocols.count('exported_pdu:ansi_637_tele') == 2
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('ansi_637_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity >= error',
                    '-Tfields', '-e', 'frame.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_ansi_637_user_data_length(self, cmd_tshark, capture_file, test_env):
        '''User Data longer than its text is Extraneous Data instead of an
        assertion (GSM 7-bit) or a dissector bug (Latin); text longer than
        its User Data is Short Data and the subparameters after it are
        still dissected.'''
        out = self.fields(cmd_tshark, capture_file, test_env, (115, 116, 117),
                          'ansi_637_tele.user_data.text', 'ansi_637_tele.subparam_id',
                          'ansi_637.extraneous_data', 'ansi_637.short_data')
        assert out[115][0] == '$' and out[115][2] != ''
        assert out[116][0] == 'A' and out[116][2] != ''
        text, subparams, extraneous, short = out[117]
        assert text == ''
        assert subparams == '0|1|' + '|'.join(['13'] * 8)
        assert short != ''

    def test_ansi_637_aligned_text(self, cmd_tshark, capture_file, test_env):
        '''Multiple Encoding User Data and Service Category Program Data text
        that starts on an octet boundary is read from the right octet.'''
        out = self.fields(cmd_tshark, capture_file, test_env, (73, 80, 118),
                          'ansi_637_tele.mult_enc_user_data.text',
                          'ansi_637_tele.srvc_cat_prog_data.text')
        assert out[73][0] == 'AB|XYZ'
        assert out[118][0] == 'AB|XYZ'
        assert out[80][1] == 'Alert|Weather'

    def test_ansi_637_long_messages(self, cmd_tshark, capture_file, test_env):
        '''Transport (SIP) and teleservice (ANSI-41 MAP) messages over 255
        octets are dissected to the end.'''
        out = self.fields(cmd_tshark, capture_file, test_env, (111, 112),
                          'ansi_637_trans.param_id', 'ansi_637_trans.bearer_reply.seq_num',
                          'ansi_637_tele.subparam_id', 'ansi_637_tele.msg_display_mode')
        assert out[111][0] == '0|4|5|2|8|6'
        assert out[111][1] == '33'
        assert out[111][2] == '0|1|13|8'
        assert out[112][2] == '0|1|1|3|15'
        assert out[112][3] == '2'

    def test_ansi_637_stale_broadcast(self, cmd_tshark, capture_file, test_env):
        '''A teleservice message after a Broadcast transport message is not
        decoded as CMAS, in one and two passes.'''
        for passes in ((), ('-2',)):
            out = self.fields(cmd_tshark, capture_file, test_env, (113, 114, 121, 122, 123),
                              'ansi_637_tele.user_data.text', 'ansi_637_tele.cmas.num_fields',
                              'ansi_637_tele.cmas.text', passes=passes)
            assert out[113][1:] == ['19', 'Test alert']
            assert out[114] == ['Not an alert', '', '']
            assert out[121] == out[123] == ['\\b(H', '', '']
            assert out[122] == ['', '', '']

    def test_ansi_637_cmas(self, cmd_tshark, capture_file, test_env):
        '''CMAS alert text in several encodings, and type 0 records of
        length 0 reported as Short Data.'''
        out = self.fields(cmd_tshark, capture_file, test_env, (89, 90, 91, 96, 98, 120),
                          'ansi_637_tele.cmas.text', 'ansi_637_tele.cmas.record_len',
                          'ansi_637_tele.cmas.category', 'ansi_637.short_data')
        assert out[89][0] == 'Presidential Alert: test'
        assert out[89][1] == '22|4|10'
        assert out[90][0] == 'Évacuez la zone'
        assert out[91][0] == 'Ω Severe'
        assert out[96][0] == 'Flash flood now!'
        assert out[98][0] == 'Torn'
        assert out[120][1] == '0|0|0'
        assert out[120][3].count('|') == 2

    def test_ansi_637_cmas_reserved_bits(self, cmd_tshark, capture_file, test_env):
        '''CMAS in a User Data that is the last subparameter, with no type 0
        record, type 0 after type 1 and type 0 first: no exception, and the
        3 reserved bits after the CMAS message are in the last octet of the
        User Data subparameter.'''
        import xml.etree.ElementTree as ET
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_637_coverage.pcap.gz'),
                '-Y', 'frame.number >= 105 && frame.number <= 107', '-T', 'pdml',
            ), encoding='utf-8', env=test_env)
        packets = ET.fromstring(stdout).findall('packet')
        assert len(packets) == 3
        for packet in packets:
            assert packet.find(".//field[@name='_ws.malformed']") is None
            user_data = [f for f in packet.iter('field') if f.get('show') == 'User Data']
            assert len(user_data) == 1
            ud = user_data[0]
            reserved = [f for f in ud if f.get('name') == 'ansi_637_tele.reserved']
            assert len(reserved) == 1
            assert int(reserved[0].get('pos')) == int(ud.get('pos')) + int(ud.get('size')) - 1

    def test_ansi_637_encodings(self, cmd_tshark, capture_file, test_env):
        '''User Data in each encoding, with and without a User Data Header.'''
        out = self.fields(cmd_tshark, capture_file, test_env, (2, 18, 38, 39, 42, 44, 47, 49, 51, 55, 57),
                          'ansi_637_tele.user_data.text', '_ws.col.info')
        assert out[2][0] == 'Café crème à 8 h'
        assert out[18][0] == 'Enhanced part one'
        assert out[18][1].endswith('(Short Message fragment 1 of 2)')
        assert out[38][0] == 'IA5 text @ 10:30'
        assert out[39][0] == 'Unicode Ω ☺'
        assert out[42][0] == 'שלום'
        assert out[44][0] == 'GSM default alphabet'
        assert out[47][0] == '한국어'
        assert out[49][0] == 'first part'
        assert out[51][0] == 'second part'
        assert out[55][0] == 'GSM part two'
        assert out[57][0] == 'Unicode Ω part'


class TestDissectAnsi801:
    def test_ansi_801_frames(self, cmd_tshark, capture_file, test_env):
        '''Every forward and reverse request and response type, both
        PD_MSG_TYPE header forms, IS-801 in ANSI MAP and ANSI A, without
        malformed packets in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Tfields', '-eframe.protocols', '-eansi_801.for_sess_tag',
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        assert len(frames) == 109
        assert all(p.endswith(':ansi_801') for p, _ in frames)
        assert sum(':ansi_map:' in p for p, _ in frames) == 4
        assert sum(':ansi_a_dtap:' in p for p, _ in frames) == 2
        # Forward link frames have the forward session tag
        assert sum(t != '' for _, t in frames) == 59
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('ansi_801_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity >= error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_ansi_801_forward_requests(self, cmd_tshark, capture_file, test_env):
        '''Each forward request type is decoded with its own fields. The
        function table used to be one entry out of step: Request Location
        Response was shown as data, and Pseudorange, Pilot Phase and Time
        Offset Measurement used the function of the next type.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'frame.number <= 19 && ansi_801.for_req_type',
                '-Tfields', '-eframe.number', '-eansi_801.for_req_type',
                '-eansi_801.pref_resp_qual', '-eansi_801.offset_req',
                '-eansi_801.desired_pilot_phase_resolution', '-eansi_801.height_incl',
                '-eansi_801.use_action_time_indicator', '-eansi_801.action_time',
                '-eansi_801.cancellation_type', '-eansi_801.data',
            ), encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in stdout.splitlines()] == [
            # The review reproducer
            ['1', '4', '5', 'False', '', '', '', '', '', ''],
            ['2', '1', '5', '', '', 'False', '', '', '', ''],
            ['3', '5', '5', 'False', 'True', '', '', '', '', ''],
            # One frame for each type
            ['9', '0', '', '', '', '', '', '', '', '5a'],
            ['10', '1', '4', '', '', 'True', '', '', '', ''],
            ['11', '2', '', '', '', '', '', '', '', ''],
            ['12', '2', '', '', '', '', '', '', '', '0102'],
            ['13', '3', '', '', '', '', '', '', '', ''],
            ['14', '4', '2', 'False', '', '', '', '', '', ''],
            ['15', '5', '1', 'False', 'True', '', '', '', '', ''],
            ['16', '6', '', '', '', '', 'True', '21', '', ''],
            ['17', '6', '', '', '', '', 'False', '', '', ''],
            ['18', '7', '', '', '', '', '', '', '4', ''],
            ['19', '7', '', '', '', '', '', '', '14', ''],
        ]

    def test_ansi_801_response_count(self, cmd_tshark, capture_file, test_env):
        '''Messages with PD_MSG_TYPE 1: the forward response used to start
        one octet late, and in both directions the response count was not
        shifted down (16 times too large), so Short Data was reported after
        the last response.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'ansi_801.pd_message_type == 1',
                '-Tfields', '-eframe.number',
                '-eansi_801.for_message_number_responses', '-eansi_801.rev_message_number_responses',
                '-eansi_801.for_rsp_type', '-eansi_801.rev_rsp_type',
                '-eansi_801.reject_request_type', '-e_ws.expert',
            ), encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in stdout.splitlines()] == [
            # The review reproducer: one Reject of type 2 in each direction
            ['4', '1', '', '0', '', '2', ''],
            ['5', '', '1', '', '0', '2', ''],
            ['43', '3', '', '2,1,12', '', '', ''],
            ['44', '2', '', '0,8', '', '8', ''],
            # A request count, requests not decoded
            ['45', '1', '', '0', '', '8', ''],
            ['82', '', '3', '', '2,1,6', '', ''],
            ['83', '', '1', '', '0', '4', ''],
            # In ANSI MAP
            ['107', '', '1', '', '7', '', ''],
        ]
        # Short Data only where requests or responses are missing
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'ansi_801.short_data',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['88', '90', '92', '94', '96', '97', '100', '101']

    def test_ansi_801_location_response(self, cmd_tshark, capture_file, test_env):
        '''The Provide Location Response bit fields, with and without the
        optional velocity, clock and height parts.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'frame.number in {37..41,77}',
                '-Tfields', '-eframe.number', '-eansi_801.lat', '-eansi_801.long',
                '-eansi_801.velocity_hor', '-eansi_801.velocity_ver',
                '-eansi_801.clock_bias', '-eansi_801.height', '-eansi_801.reserved_bits',
            ), encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in stdout.splitlines()] == [
            ['37', '33.75', '67.5', '50', '8', '250', '112', '0'],
            ['38', '-67.5', '-135', '127.75', '', '', '-500', '0'],
            ['39', '33.75', '67.5', '', '', '', '', '0'],
            ['40', '33.75', '67.5', '0.25', '-62.5', '-13000', '', ''],
            ['41', '33.75', '67.5', '', '', '', '15883', '0'],
            ['77', '-84.375', '90', '', '', '249143', '780', ''],
        ]

    def test_ansi_801_carriage(self, cmd_tshark, capture_file, test_env):
        '''IS-801 in ANSI MAP SMSDeliveryPointToPoint (Invoke forward,
        ReturnResult reverse, through the saved ServiceIndicator) and in an
        ANSI A ADDS Deliver (direction from the packet direction).'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'ansi_map || ansi_a_dtap',
                '-Tfields', '-eframe.number', '-eansi_801.for_sess_tag',
                '-eansi_801.rev_sess_tag', '-eansi_801.for_rsp_type', '-eansi_801.rev_rsp_type',
            ), encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in stdout.splitlines()] == [
            ['104', '11', '', '2', ''],
            ['105', '', '11', '', '2,1'],
            ['106', '11', '', '4', ''],
            ['107', '', '11', '', '7'],
            ['108', '12', '', '5,2', ''],
            ['109', '', '12', '', '1'],
        ]

    def test_ansi_801_sensitivity_assistance(self, cmd_tshark, capture_file, test_env):
        '''Provide GPS Sensitivity Assistance is decoded from the octets the
        field masks are for, within its 4 octets, also when it is the last
        element. It used to be read one octet late, past the element.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'frame.number in {28,29,108}',
                '-Tfields', '-eframe.number', '-eansi_801.ref_bit_num',
                '-eansi_801.num_dr_p', '-eansi_801.dr_size', '-eansi_801.part_num',
                '-eansi_801.total_parts', '-eansi_801.data_records', '-e_ws.expert',
            ), encoding='utf-8', env=test_env)
        # 12 34 56 78 in each: then a Reject, last in the message, in ANSI A
        assert [line.split('\t') for line in stdout.splitlines()] == [
            [n, '145', '10', '43', '1', '7', '0', ''] for n in ('28', '29', '108')
        ]

    def test_ansi_801_reserved_message_type(self, cmd_tshark, capture_file, test_env):
        '''Reserved and manufacturer specific message types, with and
        without data after the type. Without data it used to be Malformed.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_801_coverage.pcap.gz'),
                '-Y', 'ansi_801.pd_message_type >= 2',
                '-Tfields', '-eframe.number', '-eansi_801.pd_message_type',
                '-eansi_801.proprietary_data', '-e_ws.expert',
            ), encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in stdout.splitlines()] == [
            ['46', '2', '010203', ''],
            ['47', '200', 'deadbeef', ''],
            ['48', '255', '00', ''],
            ['49', '255', '', ''],
            ['84', '48', '00', ''],
            ['85', '254', '70726f7072696574617279', ''],
            ['86', '255', 'ff', ''],
            ['87', '192', '', ''],
        ]


class TestDissectAnsi683:
    def test_ansi_683_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every forward and reverse message and parameter block, over the
        ansi_a.ota table, ANSI A DTAP ADDS Deliver and ANSI MAP SMDPP,
        decodes without malformed packets or errors in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_683_coverage.pcap.gz'),
                '-Tfields', '-eframe.protocols',
                '-eansi_683.for_msg_type', '-eansi_683.rev_msg_type',
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        assert len(frames) == 240
        protocols = [f[0] for f in frames]
        assert protocols.count('exported_pdu:ansi_683') == 216
        assert protocols.count('exported_pdu:ansi_a_dtap:ansi_683') == 12
        assert protocols.count('exported_pdu:ansi_tcap:ansi_map:ansi_683') == 12
        # Every message type 0-23 in both directions
        assert {int(f[1]) for f in frames if f[1]} >= set(range(24))
        assert {int(f[2]) for f in frames if f[2]} >= set(range(24))
        # ANSI A and ANSI MAP alternate forward (base station) and reverse
        # (mobile station) messages
        for carriage in ('ansi_a_dtap', 'ansi_map'):
            dirs = ['F' if f[1] else 'R' for f in frames if carriage in f[0]]
            assert dirs == ['F', 'R'] * 6
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('ansi_683_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_ansi_683_reserved_bits(self, cmd_tshark, capture_file, test_env):
        '''Reserved fields are shown after the fields before them, not over
        them: Secure Mode Request (STOP, reserved 010), CDMA NAM block of a
        Configuration Response (reserved 11, SLOTTED_MODE, reserved 00101),
        OTAPA Request and Response (reserved before NAM_LOCK_IND), the
        IMSI_T block (reserved after IMSI_T_S) and the FRESH_INCL octet.'''
        for frame, lines in (
                (53, ('0... .... = Secure Mode: Stop',
                      '.... .010 = Reserved: True')),
                (50, ('.000 0... = Security: SMCK generation using SSD_A and SSD_B',
                      '.... .101 = Reserved: True')),
                (75, ('11.. .... = Reserved: True',
                      '..1. .... = Slotted Mode: 1',
                      '...0 0101 = Reserved: True')),
                (38, ('0... .... = OTAPA session: Stop',
                      '.111 1111 = Reserved: True')),
                (9, ('0... .... = FRESH_INCL: False',
                     '.111 1111 = Reserved: True')),
                (105, ('0000 000. = Reserved: False',
                       '.... ...1 = NAM_LOCK indicator: 1')),
                (5, ('The least significant 10 digits of the IMSI_T (IMSI_T_S) (34 bits): 4344454647',
                     '.... ...1 = Reserved: True')),
                ):
            stdout = subprocess.check_output((cmd_tshark,
                    '-r', capture_file('ansi_683_coverage.pcap.gz'),
                    '-Y', f'frame.number == {frame}',
                    '-O', 'ansi_683', '-V',
                ), encoding='utf-8', env=test_env)
            text = [line.strip() for line in stdout.splitlines()]
            for line in lines:
                assert line in text, (frame, line)

    def test_ansi_683_puzl_config_req(self, cmd_tshark, capture_file, test_env):
        '''The PUZL Configuration Request block data starts after the block
        type (it used to repeat the block type).'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_683_coverage.pcap.gz'),
                '-Y', 'ansi_683.for_msg_type == 11',
                '-Tfields', '-eframe.number', '-eansi_683.param_block_puzl',
                '-eansi_683.block_data',
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        assert frames[:3] == [
            ['40', '3', ''],
            ['41', '128', '01020304'],
            ['149', '1', 'aabb'],
        ]

    def test_ansi_683_mdn_and_values(self, cmd_tshark, capture_file, test_env):
        '''Mobile directory numbers (odd, even, 15 digits) and the Secure
        Mode random number decode.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_683_coverage.pcap.gz'),
                '-Y', 'frame.number in {4, 8, 51, 219}',
                '-Tfields', '-eansi_683.mobile_directory_number',
                '-eansi_683.random_number_smck_generation',
            ), encoding='utf-8', env=test_env)
        assert stdout == (
            '6135550123,5550199\t\n'
            '180055501234567\t\n'
            '\t0xc8c9cacbcccdcecf\n'
            '\t0xc8c9cacbcccdcecf\n')

    def test_ansi_683_short_data(self, cmd_text2pcap, cmd_tshark, result_file, test_env):
        '''A Secure Mode Request, System Tag Configuration Request and
        System Tag Download Response one or two octets too short give the
        Short Data expert info instead of an exception.'''
        def ota(direction, payload):
            # Exported PDU: dissector table "ansi_a.ota", direction as value
            return (struct.pack('>HH', 14, 12) + b'ansi_a.ota\0\0'
                    + struct.pack('>HHI', 32, 4, direction)
                    + struct.pack('>HH', 0, 0) + payload)
        packets = [
            ota(0, bytes([15, 0x80]) + b'\x11' * 7),   # 7 of 8 random octets
            ota(0, bytes([19, 0x01, 0x00, 0x10])),     # 2 of 3 segment octets
            ota(1, bytes([20, 0x01, 0x00, 0x10])),     # 2 of 3 segment octets
        ]
        text_file = result_file('ansi_683_short.txt')
        capture = result_file('ansi_683_short.pcapng')
        with open(text_file, 'w') as f:
            f.writelines(f'000000  {packet.hex(" ")}\n' for packet in packets)
        subprocess.check_call((cmd_text2pcap, '-q', '-l', '252', text_file, capture), env=test_env)
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture,
                '-Y', 'ansi_683.short_data',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout == '1\n2\n3\n'
        # Short Data is in the Malformed group, but no exception follows it
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture,
                '-Y', '_ws.malformed.expert',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0


ANSI_A_OPTS = ('-d', 'sccp.ssn==252,bsap')  # BSAP has no fixed SCCP SSN
ANSI_A_IOS5 = ('-o', 'ansi_a_bsmap.global_variant:ios-5.0.1')


class TestDissectAnsiA:
    def ansi_a(self, cmd_tshark, capture_file, test_env, ios5, *args):
        capture = 'ansi_a_ios5_coverage.pcap.gz' if ios5 else 'ansi_a_coverage.pcap.gz'
        return subprocess.check_output((cmd_tshark, *ANSI_A_OPTS, *(ANSI_A_IOS5 if ios5 else ()),
                '-r', capture_file(capture), *args,
            ), encoding='utf-8', env=test_env)

    def test_ansi_a_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every BSMAP and DTAP message of both variants, over M3UA/SCCP, in
        a femtocell SIP MESSAGE and in ANSI-41 MAP, decodes without malformed
        packets or errors, in one and two passes.'''
        for ios5, counts in ((False, {'BSAP': 268, 'SCCP (Int. ITU)': 20, 'SIP': 12, 'ANSI MAP': 3,
                                      'IS-637-A': 4, 'IS-683': 2, 'IS-801': 2}),
                             (True, {'BSAP': 283, 'SCCP (Int. ITU)': 22, 'SIP': 12, 'ANSI MAP': 3,
                                     'IS-637-A': 4, 'IS-683': 2, 'IS-801': 2,
                                     'EVRC': 4, 'RTP': 1, 'RTP EVENT': 1})):
            stdout = self.ansi_a(cmd_tshark, capture_file, test_env, ios5,
                    '-Tfields', '-e_ws.col.protocol')
            protocols = stdout.splitlines()
            assert {p: protocols.count(p) for p in set(protocols)} == counts
            for passes in ((), ('-2',)):
                stdout = self.ansi_a(cmd_tshark, capture_file, test_env, ios5, *passes,
                        '-Y', '_ws.malformed || _ws.expert.severity == error',
                        '-Tfields', '-eframe.number')
                assert count_output(stdout) == 0

    def test_ansi_a_statistics(self, cmd_tshark, capture_file, test_env):
        '''The BSMAP and DTAP statistics count every message of the variant
        (56 BSMAP and 37 DTAP messages in IOS 4.0.1, 62 and 37 in IOS 5.0.1).'''
        for ios5, rows in ((False, 93), (True, 99)):
            stdout = self.ansi_a(cmd_tshark, capture_file, test_env, ios5,
                    '-q', '-z', 'ansi_a,bsmap', '-z', 'ansi_a,dtap')
            counts = [int(line.split('|')[2]) for line in stdout.splitlines() if line.startswith('0x')]
            assert len(counts) == rows
            assert 0 not in counts

    def test_ansi_a_ios4_tag_after_status_request(self, cmd_tshark, capture_file, test_env):
        '''In IOS 4.0.1 mode the IOS 5 only elements of Status Request are
        skipped, and the Tag after them is shown. They used to take the
        rest of the message.'''
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, False,
                '-Y', 'ansi_a_bsmap.msgtype == 0x6a',
                '-Tfields', '-eframe.number', '-eansi_a_bsmap.tag.value')
        assert stdout.splitlines() == ['38\t16909060', '244\t16909060', '297\t42']

    def test_ansi_a_access_network_identifiers(self, cmd_tshark, capture_file, test_env):
        '''Access Network Identifiers (a TV element in Handoff Required) shows
        SID, NID and PZID at their own offsets, and the Service Option List
        after it is dissected. NID and PZID used to be read at the SID offset
        and the rest of the message taken as extraneous data.'''
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, False,
                '-Y', 'ansi_a_bsmap.nid',
                '-Tfields', '-eframe.number', '-eansi_a_bsmap.sid', '-eansi_a_bsmap.nid',
                '-eansi_a_bsmap.pzid', '-eansi_a_bsmap.so_list.num')
        assert stdout.splitlines() == ['129\t257\t514\t3\t3', '296\t1\t2\t3\t1', '305\t257,291\t514\t3\t3']

    def test_ansi_a_cell_list(self, cmd_tshark, capture_file, test_env):
        '''A Cell Identifier List whose only cell runs past the element has
        one cell. The unsigned length used to wrap and the rest of the
        message was read as cells.'''
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, False,
                '-Y', 'frame.number == 298',
                '-Tfields', '-eansi_a_bsmap.cell_ci')
        assert stdout.strip() == '0x0022'

    def test_ansi_a_ios5_rtp_setup(self, cmd_tshark, capture_file, test_env):
        '''The A2p Bearer Format-Specific Parameters set up the RTP streams
        (IPv4 and IPv6, session or format address) with their dynamic payload
        types, including telephone-event for an in-band signaling format.'''
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, True,
                '-Y', 'rtp',
                '-Tfields', '-eframe.number', '-e_ws.col.protocol', '-ertp.p_type',
                '-ertp.setup-frame', '-ertp.setup-method')
        assert stdout.splitlines() == [
            '79\tEVRC\t97\t45\tIOS5',
            '80\tRTP EVENT\t101\t45\tIOS5',
            '153\tEVRC\t97\t152\tIOS5',
            '154\tEVRC\t102\t148\tIOS5',
            '214\tEVRC\t98\t211\tIOS5',
            '327\tRTP\t98\t321\tIOS5',
        ]

    def test_ansi_a_femto(self, cmd_tshark, capture_file, test_env):
        '''BSMAP and DTAP messages in a femtointerfacemsg SIP body.'''
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, False,
                '-Y', 'sip',
                '-Tfields', '-eansi_a_bsmap.msgtype', '-eansi_a_bsmap.dtap_msgtype')
        assert stdout.splitlines() == [
            '0x57\t', '\t0x24', '\t0x04', '0x45\t', '\t0x27', '\t0x33', '\t0x2c',
            '\t', '0x09\t', '\t', '\t0x4a', '0x00\t',
        ]

    def test_ansi_a_fill_bits(self, cmd_tshark, capture_file, test_env):
        '''The fill bits of bit-exact contents are the low bits of the last
        octet, as many as the fill bit count (1 to 7). One fill bit used to
        add a zero-width field, a dissector bug.'''
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, False,
                '-Y', 'frame.number >= 307 && frame.number <= 310', '-V', '-O', 'ansi_a_bsmap')
        fill = [line.strip() for line in stdout.splitlines() if '= Fill Bits:' in line]
        assert fill == [
            # Mobile Capabilities FCH, DCCH, FOR_PDCH, REV_PDCH (1, 3, 7, 4 fill bits)
            '.... ...1 = Fill Bits: 1', '.... .101 = Fill Bits: 5',
            '.101 0101 = Fill Bits: 85', '.... 1100 = Fill Bits: 12',
            # (2, 5, 6, none)
            '.... ..01 = Fill Bits: 1', '...1 1110 = Fill Bits: 30', '..00 0011 = Fill Bits: 3',
            # Non-Negotiable Service Configuration Record (1, 6)
            '.... ...1 = Fill Bits: 1', '..10 1001 = Fill Bits: 41',
        ]
        stdout = self.ansi_a(cmd_tshark, capture_file, test_env, False,
                '-Y', '_ws.expert.group == "Dissector bug"', '-Tfields', '-eframe.number')
        assert count_output(stdout) == 0

    def test_ansi_a_a1_element_type_0(self, cmd_tshark, capture_file, test_env):
        '''A CDMA2000 A1 element of type 0x00 in ANSI-41 MAP is stepped over
        and the element after it is decoded. It used to match the end of the
        element table and loop forever.'''
        for ios5, frame in ((False, '311'), (True, '334')):
            stdout = self.ansi_a(cmd_tshark, capture_file, test_env, ios5,
                    '-Y', 'frame.number == ' + frame,
                    '-Tfields', '-eansi_a_bsmap.cause_1', '-eansi_a_bsmap.esn')
            assert stdout.strip() == '9\t0x8a123456'


# The capture is SS7 over M3UA with ANSI point codes and SCCP addresses.
ANSI_MAP_OPTS = ('-o', 'mtp3.standard:ANSI')


class TestDissectAnsiMap:
    def test_ansi_map_needs_ansi_mtp3(self, cmd_tshark, capture_file, test_env):
        '''With the default (ITU) MTP3 standard the ANSI SCCP addresses do
        not route to TCAP, so nothing is dissected as ANSI MAP.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Y', 'ansi_map',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_ansi_map_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every operation, as Invoke and ReturnResult with all of its
        parameters, decodes without malformed packets or error expert infos,
        in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 336
        assert protocols.count('ANSI MAP') == 297
        # The Reject and the ReturnError without parameters are not passed
        # to ANSI MAP
        assert protocols.count('ANSI TCAP') == 2
        # SMS bearer data handed to IS-637, IS-683 and IS-801
        assert protocols.count('IS-637-A') == 26
        assert protocols.count('IS-683') == 4
        assert protocols.count('IS-801') == 7
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS, *passes,
                    '-r', capture_file('ansi_map_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_ansi_map_bearer_data_once(self, cmd_tshark, capture_file, test_env):
        '''The SMS bearer data is handed to IS-637/IS-801 once, however
        many TeleserviceIdentifier or ServiceIndicator parameters follow.
        Each one used to dissect it again, until 600 of them failed the
        layer limit assertion.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Y', 'frame.number in {290, 291, 325, 327, 328, 329}',
                '-Tfields', '-eframe.number', '-eframe.protocols',
            ), encoding='utf-8', env=test_env)
        frames = dict(line.split('\t') for line in stdout.splitlines())
        # 5 and 600 ServiceIndicator: IS-801 once
        for number in ('290', '328', '329'):
            assert frames[number].split(':').count('ansi_801') == 1
        # 5, 600 and 4000 TeleserviceIdentifier: IS-637 once
        for number in ('291', '325', '327'):
            assert frames[number].split(':').count('ansi_637_tele') == 1

    def test_ansi_map_result_operation(self, cmd_tshark, capture_file, test_env):
        '''A ReturnResult whose Invoke ANSI MAP did not save (frame 300
        goes to another node than the Invoke came from) is dissected with
        the operation TCAP matched, not that of the previous packet (an SMS
        Delivery Point to Point Invoke). ReturnError names the matched
        operation, and a unidirectional package (no transaction ID) with
        an Invoke and a ReturnResult decodes.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Y', 'frame.number in {299, 300, 303, 306, 309, 312, 330}',
                '-Tfields', '-eframe.number', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '299\tSMS Delivery Point to Point Invoke ',
            '300\tRegistration Notification ReturnResult ',
            '303\tRegistration Notification ReturnError ',
            '306\tLocation Request ReturnError ',
            '309\tSMS Delivery Point to Point ReturnError ',
            '312\tAuthentication Directive ReturnError ',
            '330\tSMS Delivery Point to Point ReturnResult ',
        ]
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Y', 'ansi_map.registrationNotificationRes_element || ansi_map.sms_CauseCode',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        frames = stdout.split()
        assert '300' in frames and '330' in frames

    def test_ansi_map_response_matching(self, cmd_tshark, capture_file, test_env):
        '''ansi_map.transaction.matchtype: frame 295 answers a
        RegistrationNotification VLR->HLR whose transaction ID a later
        LocationRequest MSC-B->MC reused. Matching on the transaction ID
        only takes the LocationRequest.'''
        for matchtype, info in (
                ('tid', 'Location Request ReturnResult '),
                ('tid_source', 'Registration Notification ReturnResult '),
                ('tid_source_dest', 'Registration Notification ReturnResult '),
                ):
            stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                    '-o', f'ansi_map.transaction.matchtype:{matchtype}',
                    '-r', capture_file('ansi_map_coverage.pcap.gz'),
                    '-Y', 'frame.number == 295',
                    '-Tfields', '-e_ws.col.info',
                ), encoding='utf-8', env=test_env)
            assert stdout.strip('\n') == info

    def test_ansi_map_parameters(self, cmd_tshark, capture_file, test_env):
        '''The hand-written parameter decoders give the expected values, and
        the bearer data of a ReturnResult goes to the IS-683/IS-801 reverse
        link with the ServiceIndicator saved from its Invoke.'''
        for dfilter, frames in (
                ('ansi_683.for_msg_type', '280 282'),
                ('ansi_683.rev_msg_type', '281 283'),
                ('ansi_801', '284 285 286 287 290 328 329'),
                ('ansi_801.rev_sess_tag', '285 287'),
                ):
            stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                    '-r', capture_file('ansi_map_coverage.pcap.gz'),
                    '-Y', dfilter,
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert ' '.join(stdout.split()) == frames, dfilter
        for dfilter, count in (
                ('ansi_map.bcd_digits == "2015550123"', 95),
                ('ansi_map.ia5_digits == "5551212"', 38),
                ('ansi_map.SSN == 6', 53),
                ('ansi_map.win_trigger_list', 21),
                ):
            stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                    '-r', capture_file('ansi_map_coverage.pcap.gz'),
                    '-Y', dfilter,
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == count, dfilter

    def test_ansi_map_mslocation_teleservice(self, cmd_tshark, capture_file, test_env):
        '''MSLocation with a 1 and a 2 octet resolution decodes (the
        resolution used to be added with length -1, which always threw),
        and a 1-octet TeleserviceIdentifier is shown with its length
        instead of throwing.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Y', 'frame.number in {334, 335}',
                '-Tfields', '-eframe.number', '-eansi_map.mslocation.lat',
                '-eansi_map.mslocation.long', '-eansi_map.mslocation.res',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '334\t4198964\t8410744\t5',
            '335\t4198964\t8410744\t1281',
        ]
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-Y', 'frame.number == 336',
                '-V', '-O', 'ansi_map',
            ), encoding='utf-8', env=test_env)
        assert 'sms-TeleserviceIdentifier: 10 length 1' in stdout
        assert 'Malformed' not in stdout
        assert 'IS-637' not in stdout

    def test_ansi_map_statistics(self, cmd_tshark, capture_file, test_env):
        '''-z ansi_map counts every known operation, also after the
        unknown ones (a static flag used to stop the counting at the first
        unknown operation code).'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_MAP_OPTS,
                '-r', capture_file('ansi_map_coverage.pcap.gz'),
                '-q', '-z', 'ansi_map',
            ), encoding='utf-8', env=test_env)
        counts = {}
        for line in stdout.splitlines():
            fields = [f.strip() for f in line.split('|')]
            if len(fields) >= 3 and fields[0].startswith('0x'):
                counts[fields[0]] = int(fields[2])
        assert counts['0x0d'] == 7     # Registration Notification
        assert counts['0x35'] == 39    # SMS Delivery Point to Point
        assert counts['0x70'] == 2     # QualificationRequest2 (the last)
        assert counts['0x67'] == 0     # not an ANSI MAP operation


# The capture is SS7 over M3UA with ANSI point codes and SCCP addresses.
ANSI_TCAP_OPTS = ('-o', 'mtp3.standard:ANSI')


class TestDissectAnsiTcap:
    def test_ansi_tcap_needs_ansi_mtp3(self, cmd_tshark, capture_file, test_env):
        '''With the default (ITU) MTP3 standard the ANSI SCCP addresses do
        not route to TCAP, so nothing is dissected as ANSI TCAP.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'ansi_tcap',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_ansi_tcap_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every package type, component type, operation code family and
        national parameter decodes without malformed packets or error expert
        infos, and two passes give the same result as one.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 135
        assert protocols.count('ANSI TCAP') == 86
        assert protocols.count('ANSI MAP') == 24
        assert protocols.count('IS-637-A') == 19
        assert protocols.count('AIN') == 3
        assert protocols.count('LNPDQP') == 3
        outputs = []
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS, *passes,
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0
            outputs.append(subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS, *passes,
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'), '-V',
                ), encoding='utf-8', env=test_env))
        assert outputs[0] == outputs[1]

    def test_ansi_tcap_many_components(self, cmd_tshark, capture_file, test_env):
        '''Packages of 600 components (ANSI MAP, AIN, national LNP) used to
        fail the layer limit DISSECTOR_ASSERT() in call_dissector_work().
        The components are handed over until the frame nears the limit,
        the rest are reported with a warning. 400 components fit.'''
        expected = {
            '127': ('ansi_map', 475, 125),
            '128': ('ansi_map', 400, 0),
            '129': ('ain', 475, 125),
            '130': ('lnpdqp', 475, 125),
        }
        for frame, (proto, handed, skipped) in expected.items():
            stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                    '-Y', f'frame.number == {frame}', '-V',
                ), encoding='utf-8', env=test_env)
            assert 'Dissector bug' not in stdout
            assert 'Malformed Packet' not in stdout
            assert count_output(stdout, r'Expert Info \(Warning/Undecoded\): Too many components in one package') == skipped
            stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                    '-Y', f'frame.number == {frame}',
                    '-Tfields', '-eframe.protocols',
                ), encoding='utf-8', env=test_env)
            assert stdout.strip().split(':').count(proto) == handed

    def test_ansi_tcap_same_frame_match(self, cmd_tshark, capture_file, test_env):
        '''A package with an Invoke, a ReturnResult and a second Invoke of
        the same transaction: the ReturnResult is matched only with Invokes
        of earlier frames, so it does not get the second Invoke's
        operation, and two passes give the same result as one.'''
        outputs = []
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS, *passes,
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                    '-Y', 'frame.number == 131',
                    '-Tfields', '-eansi_tcap.private',
                ), encoding='utf-8', env=test_env)
            # The two Invokes' private operation codes, and no generated
            # operation code for the ReturnResult
            assert stdout.strip() == '2357,2317'
            outputs.append(subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS, *passes,
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                    '-Y', 'frame.number == 131', '-V',
                ), encoding='utf-8', env=test_env))
        assert outputs[0] == outputs[1]

    def test_ansi_tcap_long_transaction_id(self, cmd_tshark, capture_file, test_env):
        '''A transaction ID of 260 octets is used whole for invoke/result
        matching (its length was truncated to 8 bits): a result whose ID
        differs after the first four octets is not matched, one with the
        same ID is.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'frame.number >= 21 && frame.number <= 23',
                '-Tfields', '-eframe.number', '-eansi_tcap.identifier', '-eansi_tcap.national',
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        assert [len(f[1]) for f in frames] == [520, 520, 520]
        assert frames[0][1][:8] == frames[1][1][:8] == 'c1c2c3c4'
        assert frames[1][2] == ''
        assert frames[2][2] == '257'

    def test_ansi_tcap_matching(self, cmd_tshark, capture_file, test_env):
        '''Invoke/result matching by transaction ID only (the default), by
        ID and source, and by ID, source and destination: a result from a
        relay and a result to another node.'''
        expected = {
            'tid': '112\t257\n114\t257\n116\t257\n',
            'tid_source': '112\t257\n114\t257\n116\t\n',
            'tid_source_dest': '112\t257\n114\t\n116\t\n',
        }
        for matchtype, result in expected.items():
            stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                    '-o', f'ansi_tcap.transaction.matchtype:{matchtype}',
                    '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                    '-Y', 'frame.number in {112, 114, 116}',
                    '-Tfields', '-eframe.number', '-eansi_tcap.national',
                ), encoding='utf-8', env=test_env)
            assert stdout == result
        # The AIN ReturnResult gets its operation from the matched Invoke
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'frame.number == 108',
                '-Tfields', '-eansi_tcap.private', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.startswith('26886\tactivityTest ReturnResult')

    def test_ansi_tcap_values(self, cmd_tshark, capture_file, test_env):
        '''Abort causes, reject problems, error codes and national
        parameters.'''
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'ansi_tcap.abortCause',
                '-Tfields', '-eansi_tcap.abortCause',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == [str(c) for c in range(1, 11)] + ['42', '6']
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'frame.number == 58',
                '-Tfields', '-eansi_tcap.rejectProblem',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '257,258,259,260,513,514,515,516,769,770,771,1025,1026,1027,1028,1029,1281,1282,1283,1284,1285,1286'
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'ansi_tcap.parameter',
                '-Tfields', '-eansi_tcap.parameter', '-E', 'occurrence=a',
            ), encoding='utf-8', env=test_env)
        params = set(','.join(stdout.split()).split(','))
        assert len(params) == 38
        stdout = subprocess.check_output((cmd_tshark, *ANSI_TCAP_OPTS,
                '-r', capture_file('ansi_tcap_coverage.pcap.gz'),
                '-Y', 'frame.number == 121 || frame.number == 124 || frame.number == 125',
                '-Tfields', '-eansi_tcap.timestamp.difference', '-eansi_tcap.generic_name.characters',
                '-eansi_tcap.display_text',
            ), encoding='utf-8', env=test_env)
        assert stdout == '-5\t\t\n\tALICE\t\n\t\tHELLO\n'


class TestDissectTcap:
    def test_tcap_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every message type, dialogue PDU and component type, selected by
        application context, SSN or the data fallback, decodes without
        malformed packets or error expert infos, in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.splitlines()
        assert len(protocols) == 139
        assert protocols.count('GSM MAP') == 99
        assert protocols.count('TCAP') == 27
        assert protocols.count('Camel-v2') == 4
        assert protocols.count('Camel') == 2
        assert protocols.count('INAP') == 3
        assert protocols.count('ANSI TCAP') == 1
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('tcap_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_tcap_too_many_components(self, cmd_tshark, capture_file, test_env):
        '''A Begin with 600 GSM MAP invokes (frame 138) used to fail the
        layer limit assertion in call_dissector_work(). The components are
        handed to GSM MAP until the frame is 16 layers from the limit, the
        rest get a warning. Frame 139 has 520 components for the data
        dissector and then one of every component type and problem code,
        which TCAP dissects itself once the limit is near.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'frame.number in {138, 139}',
                '-Tfields', '-eframe.number', '-eframe.protocols',
                '-e_ws.expert.message', '-E', 'aggregator=|',
            ), encoding='utf-8', env=test_env)
        frames = {}
        for line in stdout.splitlines():
            number, protos, experts = line.split('\t')
            frames[number] = (protos.split(':'), experts.split('|'))
        for number, proto, total in (('138', 'gsm_map', 600), ('139', 'data', 549)):
            protos, experts = frames[number]
            assert set(experts) == {'Too many components in one message, not dissected'}
            assert protos.count(proto) >= 470
            assert protos.count(proto) + len(experts) == total
        # The first ~480 invokes of the reproducer are GSM MAP mo-forwardSM
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'frame.number == 138',
                '-Tfields', '-egsm_old.localValue', '-egsm_old.invokeID',
            ), encoding='utf-8', env=test_env)
        opcodes, invoke_ids = stdout.strip('\n').split('\t')
        opcodes = opcodes.split(',')
        assert len(opcodes) >= 470 and set(opcodes) == {'46'}
        assert invoke_ids.split(',')[:3] == ['0', '1', '2']
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'frame.number == 139',
                '-Tfields', '-etcap.generalProblem', '-etcap.invokeProblem',
                '-etcap.returnResultProblem', '-etcap.returnErrorProblem',
                '-etcap.nationaler', '-etcap.privateer', '-etcap.linkedID',
                '-etcap.globalValue', '-etcap.constructor_eoc',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip('\n').split('\t') == [
            '0,1,2', '0,1,2,3,4,5,6,7', '0,1,2', '0,1,2,3,4', '-300', '70000',
            '1', '0.4.0.0.1.2.3', '0x0000']

    def test_tcap_subdissector(self, cmd_tshark, capture_file, test_env):
        '''The components go to the subdissector of the application context
        (also when only an earlier message of the transaction had it, or
        the response changes it), else that of the called SSN, else data.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Tfields', '-eframe.number', '-eframe.protocols',
            ), encoding='utf-8', env=test_env)
        last = {}
        for line in stdout.splitlines():
            number, protos = line.split('\t')
            last[int(number)] = protos.split(':')[-1]
        for numbers, proto in (
                # by ACN; dialogue-only Begin, then components without dialogue
                ((1, 2, 22, 23), 'gsm_map'),
                # unknown ACN: GSM MAP by SSN 6, data at SSN 10/11
                ((26, 27, 30, 31), 'gsm_map'),
                ((28, 29, 32, 33, 36, 38), 'data'),
                # Unidirectional by ACN and by SSN
                ((34, 35, 37), 'gsm_map'),
                # CAMEL by ACN and by SSN 146, INAP by SSN 106 and by ACN
                ((111, 112, 114, 115, 117, 118), 'camel'),
                ((119, 120, 121), 'inap'),
                # dialogue only, aborts
                ((21, 24, 89, 102, 122), 'tcap'),
                # ANSI TCAP through the ITU TCAP dissector
                ((125,), 'ansi_tcap'),
                # SSN 20/21: not TCAP without an SCCP users table entry
                ((43, 44), 'data'),
                ):
            for number in numbers:
                assert last[number] == proto, number
        # The SCCP users table hands SSN 20 at PC 808 to GSM MAP over TCAP
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'uat:sccp_users:"2","808","20","GSM MAP"',
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'frame.number in {43, 44}',
                '-Tfields', '-e_ws.col.info', '-etcap.srt.session_id',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            'invoke sendAuthenticationInfo \t14,14',
            'returnResultLast sendAuthenticationInfo \t14,14',
        ]

    def test_tcap_transactions(self, cmd_tshark, capture_file, test_env):
        '''Begin, Continue, End and Abort are matched into sessions: by the
        Begin key, the Continue key in both directions, the End key; a
        Continue from the initiator; SUA (IP addresses instead of point
        codes); TIDs reused after an End, after the repetition and the lost
        timeouts, or by other nodes; a duplicate Begin; unmatched messages.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Tfields', '-eframe.number', '-etcap.srt.session_id',
                '-etcap.srt.end', '-etcap.srt.duplicate', '-etcap.srt.sessiontime',
                '-E', 'occurrence=f',
            ), encoding='utf-8', env=test_env)
        srt = {}
        for line in stdout.splitlines():
            number, *fields = line.split('\t')
            srt[int(number)] = fields
        for number, fields in (
                (2, ['1', '1', '', '0.250000000']),       # End answers the Begin
                (6, ['2', '3', '', '0.750000000']),       # Begin/Continue/Continue/End
                (13, ['4', '12', '', '0.250000000']),     # U-Abort
                (23, ['8', '20', '', '0.750000000']),     # dialogue-only Begin
                (46, ['', '', '45', '']),                 # duplicate of frame 45 (session 14)
                (47, ['14', '45', '', '2.250000000']),
                (49, ['15', '48', '', '0.250000000']),    # TID reused after the End
                (51, ['16', '50', '', '0.250000000']),
                (56, ['19', '', '', '']),                 # after the repetition timeout
                (58, ['20', '', '', '']),                 # unanswered
                (60, ['21', '59', '', '0.250000000']),    # after the lost timeout
                (63, ['22', '61', '', '0.500000000']),    # Continue from the initiator
                (66, ['', '', '', '']),                   # second responder, not matched
                (82, ['26', '78', '', '1.000000000']),    # Continue TIDs reused
                (85, ['27', '83', '', '0.500000000']),    # same TIDs, other nodes
                (86, ['', '', '', '']),                   # retransmitted End
                (87, ['', '', '', '']),
                (40, ['', '', '', '']),                   # End without a Begin
                (130, ['45', '127', '', '0.750000000']),  # SUA
                (132, ['46', '131', '', '0.250000000']),
                (135, ['47', '133', '', '0.500000000']),
                ):
            assert srt[number] == fields, number
        # The duplicate is shown as such
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'tcap.srt.duplicate',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['46']
        # With a longer lost timeout the unanswered Begin's TID reused 35 s
        # later is a duplicate too
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'tcap.losttimeout:60',
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'tcap.srt.duplicate',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['46', '59']
        # Two passes: the Begin links to the frame that ends its session
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'frame.number in {1, 3, 68}',
                '-Tfields', '-etcap.srt.begin', '-E', 'occurrence=f',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['2', '6', '72']

    def test_tcap_dialogue(self, cmd_tshark, capture_file, test_env):
        '''Dialogue portion: AARE results and diagnostics (ACN fallback),
        P-Abort causes, ABRT sources, and dialogue PDUs nested in the user
        information.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'tcap.p_abortCause || tcap.abort_source || tcap.result == 1',
                '-Tfields', '-eframe.number', '-etcap.p_abortCause',
                '-etcap.abort_source', '-etcap.dialogue_service_user',
                '-etcap.dialogue_service_provider',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '13\t\t\t2\t',      # application-context-name-not-supported
            '89\t0\t\t\t', '91\t1\t\t\t', '93\t2\t\t\t', '95\t3\t\t\t', '97\t4\t\t\t',
            '100\t\t0\t\t', '102\t\t1\t\t',
            '104\t\t\t\t2', '108\t\t\t\t1', '110\t\t\t1\t',
            '116\t\t0\t\t',     # CAMEL, with a CAP U-Abort reason
            '132\t4\t\t\t',     # SUA
        ]
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tcap_coverage.pcap.gz'),
                '-Y', 'frame.number == 39',
                '-Tfields', '-etcap.UniDialoguePDU', '-etcap.DialoguePDU',
                '-etcap.aarq_application_context_name',
                '-etcap.audt_application_context_name',
            ), encoding='utf-8', env=test_env)
        # The outer AUDT is dissected as an AARQ (same tag), the nested AUDT
        # as a UniDialoguePDU
        assert stdout.strip('\n').split('\t') == [
            '0', '0', '0.4.0.0.1.0.21.2,0.4.0.0.1.0.19.2', '0.4.0.0.1.0.21.2']


class TestDissectAodv:
    def test_aodv_types(self, cmd_tshark, capture_file, test_env):
        '''Every message type over IPv4, IPv6 and draft-01 IPv6 is
        dissected, with no malformed packets and no errors.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aodv_coverage.pcap.gz'),
                '-Y', 'aodv',
                '-Tfields', '-eaodv.type',
            ), encoding='utf-8', env=test_env)
        types = stdout.splitlines()
        assert len(types) == 66
        assert types.count('1') == 22     # RREQ
        assert types.count('2') == 13     # RREP
        assert types.count('3') == 8      # RERR
        assert types.count('4') == 4      # RREP-ACK
        assert types.count('16') == 9     # draft-01 IPv6 RREQ
        assert types.count('17') == 5     # draft-01 IPv6 RREP
        assert types.count('18') == 3     # draft-01 IPv6 RERR
        assert types.count('19') == 2     # draft-01 IPv6 RREP-ACK
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('aodv_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_aodv_ipv6(self, cmd_tshark, capture_file, test_env):
        '''RFC 3561 types over IPv6 have IPv6 addresses; the draft-01
        RERR has the sequence number before the address.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aodv_coverage.pcap.gz'),
                '-Y', 'aodv.type == 3 || aodv.type == 18',
                '-Tfields', '-eframe.number', '-eaodv.flags.rerr_nodelete',
                '-eaodv.destcount', '-eaodv.unreach_dest_ip',
                '-eaodv.unreach_dest_ipv6', '-eaodv.dest_seqno',
            ), encoding='utf-8', env=test_env)
        lines = stdout.splitlines()
        assert lines[2] == '22\tFalse\t4\t192.0.2.7,192.0.2.8,192.0.2.9,192.0.2.10\t\t2,3,4,4294967295'
        assert lines[6] == '43\tFalse\t3\t\t2001:db8::7,2001:db8::8,2001:db8::9\t1,2,3'
        assert lines[9] == '59\tFalse\t3\t\t2001:db8::1,2001:db8::2,2001:db8::3\t7,8,9'

    def test_aodv_extensions(self, cmd_tshark, capture_file, test_env):
        '''Hello Interval, Timestamp, None and unknown extensions, alone
        and chained, longer than needed (the excess is skipped).'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aodv_coverage.pcap.gz'),
                '-Y', 'aodv.ext_type && frame.number < 61',
                '-Tfields', '-eframe.number', '-eaodv.ext_type',
                '-eaodv.ext_length', '-eaodv.hello_interval', '-eaodv.timestamp',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '8\t2\t4\t1000\t',
            '9\t3\t8\t\t81985529216486895',
            '10\t1\t2\t\t',
            '11\t200\t3\t\t',
            '12\t2,3,1,7\t6,9,1,1\t500\t42',
            '18\t2\t4\t1000\t',
            '19\t3,2\t8,4\t250\t1',
            '36\t2,3,1,9\t4,8,2,2\t1000\t99',
            '40\t2\t4\t1000\t',
            '52\t2,3,1,9\t4,8,2,2\t1000\t7',
            '56\t2,3\t4,8\t1000\t8',
        ]

    def test_aodv_many_extensions(self, cmd_tshark, capture_file, test_env):
        '''A RREQ with 470 one octet unknown extensions and a draft-01
        RREQ with 100 (batch46-55 reproducers) dissect every one.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aodv_coverage.pcap.gz'),
                '-Y', 'frame.number == 61 || frame.number == 67',
                '-Tfields', '-eaodv.ext_type',
            ), encoding='utf-8', env=test_env)
        assert [len(line.split(',')) for line in stdout.splitlines()] == [470, 100]

    def test_aodv_udp_port_pref(self, cmd_tshark, capture_file, test_env):
        '''Frame 28 is AODV on UDP port 6540, dissected only once the port
        is added to the preference.'''
        def frame28(*opts):
            return subprocess.check_output((cmd_tshark, *opts,
                    '-r', capture_file('aodv_coverage.pcap.gz'),
                    '-Y', 'frame.number == 28',
                    '-Tfields', '-eaodv.rreq_id', '-eaodv.flags.rreq_destinationonly',
                ), encoding='utf-8', env=test_env)
        assert frame28() == '\t\n'
        assert frame28('-o', 'aodv.udp.port:654,6540') == '300\tTrue\n'

    def test_aodv_short_extension(self, cmd_text2pcap, cmd_tshark, result_file, test_env):
        '''A Hello Interval extension shorter than 4 octets and a Timestamp
        extension shorter than 8 get the "Invalid option length" expert
        info and are skipped, without an exception; the extension after
        them is dissected.'''
        def ext(t, data):
            return struct.pack('!BB', t, len(data)) + data
        rreq = (struct.pack('!BHBI', 1, 0x8000, 3, 7) + bytes([192, 0, 2, 9])
                + struct.pack('!I', 5) + bytes([192, 0, 2, 1]) + struct.pack('!I', 6))
        packets = [
            rreq + ext(2, b'\x00\x01') + ext(2, struct.pack('!I', 5)),
            rreq + ext(3, bytes(7)) + ext(2, struct.pack('!I', 9)),
        ]
        text_file = result_file('aodv_short_ext.txt')
        capture = result_file('aodv_short_ext.pcapng')
        with open(text_file, 'w') as f:
            f.writelines(f'000000  {packet.hex(" ")}\n' for packet in packets)
        subprocess.check_call((cmd_text2pcap, '-q', '-4', '192.0.2.1,192.0.2.2',
                               '-u', '654,654', text_file, capture), env=test_env)
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture,
                '-Tfields', '-eframe.number', '-eaodv.ext_length.invalid',
                '-eaodv.hello_interval', '-eaodv.timestamp', '-e_ws.malformed.expert',
            ), encoding='utf-8', env=test_env)
        # The expert info is in the Malformed group, but no exception follows it
        assert stdout == '1\t1\t5\t\t\n2\t1\t9\t\t\n'


class TestDissectAol:
    def test_aol_types(self, cmd_tshark, capture_file, test_env):
        '''Every P3 frame type is dissected on port 5190 without Decode As,
        with no malformed packets and no errors.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aol_coverage.pcap.gz'),
                '-Y', 'aol',
                '-Tfields', '-eaol.type',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 38
        types = stdout.replace('\n', ',').rstrip(',').split(',')
        assert len(types) == 43
        assert types.count('0x20') == 15    # Data
        assert types.count('0x21') == 3     # SS Request
        assert types.count('0x22') == 2     # SS Response
        assert types.count('0x23') == 8     # Init
        assert types.count('0x24') == 5     # ACK
        assert types.count('0x25') == 2     # NAK
        assert types.count('0x26') == 6     # Heartbeat
        assert types.count('0x27') == 1     # unknown
        assert types.count('0x3f') == 1     # unknown
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aol_coverage.pcap.gz'),
                '-Y', 'aim',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *passes,
                    '-r', capture_file('aol_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_aol_init(self, cmd_tshark, capture_file, test_env):
        '''INIT in each layout: WAOL 1.5 (no filler), later versions (filler),
        4.0 (unparsed tail) and one octet short (end marker missing).
        aol.init.win_ver holds the Windows version, not the DOS version
        (frame 61 is the batch46-55 reproducer: DOS 6.22, Windows 10.0).'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aol_coverage.pcap.gz'),
                '-Y', 'aol.type == 0x23 && aol.init_data',
                '-Tfields', '-eframe.number', '-eaol.init.platform',
                '-eaol.init.dos_ver', '-eaol.init.win_ver', '-eaol.init.filler',
                '-eaol.init.conn_spd', '-eaol.udata', '-eaol.end_missing',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '4\t0x03\t0x0616\t0x0000030a\t0x00\t0x05\t\t',
            '31\t0x0c\t0x0616\t0x0000030a\t\t0x05\t\t',
            '32\t0x03\t0x0616\t0x00000400\t\t\t000102030405060708090a0b0c0d0e\t',
            '33\t0x07\t0x0700\t0x00000500\t0x01\t0x05\t\t',
            '34\t0x03\t0x0616\t0x0000030a\t0x00\t0x05\t\t',
            '35\t0x03\t0x0616\t0x0000030a\t\t0x0d\t\t1',
            '61\t0x03\t0x0616\t0x00000a00\t0x00\t0x05\t\t',
        ]
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aol_coverage.pcap.gz'),
                '-Y', 'aol.init.win_ver == 0x0a00',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout == '61\n'

    def test_aol_reassembly(self, cmd_tshark, capture_file, test_env):
        '''PDUs split across segments (also inside the fixed header) are
        reassembled, and several PDUs in one segment are all dissected.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aol_coverage.pcap.gz'),
                '-Y', 'aol && tcp.stream == 2',
                '-Tfields', '-eframe.number', '-eaol.len', '-eaol.token',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '45\t305\tAb',
            '47\t17\tCd',
            '49\t3\t',
            '50\t3,8,3,8\tEf,Gh',
            '51\t3,3\t',
            '52\t55,3\tIj',
            '53\t3\t',
            '54\t85\tKl',
        ]

    def test_aol_desegment_pref(self, cmd_tshark, capture_file, test_env):
        '''With aol.desegment off, the first segment of a split PDU is
        dissected alone and reported as unreassembled.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'aol.desegment:FALSE',
                '-r', capture_file('aol_coverage.pcap.gz'),
                '-Y', 'aol && _ws.unreassembled',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout == '43\n48\n51\n53\n65\n67\n'

    def test_aol_tcp_port_pref(self, cmd_tshark, capture_file, test_env):
        '''The last connection is AOL on port 15190, dissected only once
        the port is added to the preference.'''
        def alt_port(*opts):
            return subprocess.check_output((cmd_tshark, *opts,
                    '-r', capture_file('aol_coverage.pcap.gz'),
                    '-Y', 'aol && tcp.port == 15190',
                    '-Tfields', '-eaol.token',
                ), encoding='utf-8', env=test_env)
        assert alt_port() == ''
        assert alt_port('-o', 'aol.tcp.port:5190,15190') == 'Pq\nRs\n'

    def test_aol_two_pass(self, cmd_tshark, capture_file, test_env):
        '''One pass and two passes give the same AOL output; the frame
        with a 65535 octet length is left waiting for its data.'''
        def aol_info(*opts):
            return subprocess.check_output((cmd_tshark, *opts,
                    '-r', capture_file('aol_coverage.pcap.gz'),
                    '-Y', 'aol || frame.number == 67',
                    '-Tfields', '-eframe.number', '-e_ws.col.info', '-eaol.len',
                ), encoding='utf-8', env=test_env)
        one_pass = aol_info()
        assert one_pass == aol_info('-2')
        assert one_pass.splitlines()[-1].startswith('67\t40000 → 5190 [PSH, ACK]')


# applemidi_coverage.pcap.gz is synthetic: every packet was generated, to
# cover as much of the AppleMIDI dissector as possible. Its heuristic is
# disabled by default.
APPLEMIDI_OPTS = ('--enable-heuristic', 'applemidi_udp')


class TestDissectAppleMidi:
    def applemidi_fields(self, cmd_tshark, capture_file, test_env, *fields, opts=APPLEMIDI_OPTS):
        args = []
        for field in fields:
            args += ['-e', field]
        stdout = subprocess.check_output((cmd_tshark, *opts,
                '-r', capture_file('applemidi_coverage.pcap.gz'),
                '-Tfields', '-E', 'aggregator=|', '-e', 'frame.number', *args,
            ), encoding='utf-8', env=test_env)
        return {int(line.split('\t')[0]): line.split('\t')[1:] for line in stdout.splitlines()}

    def test_applemidi_heuristic_disabled_by_default(self, cmd_tshark, capture_file, test_env):
        '''Nothing is dissected as AppleMIDI unless the heuristic is enabled.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('applemidi_coverage.pcap.gz'),
                '-Y', 'applemidi || rtpmidi',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_applemidi_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every command, on the control and data ports, over IPv4 and
        IPv6, and RTP-MIDI after the session set-up, decode without
        malformed packets or error expert infos, in one and two passes.'''
        stdout = subprocess.check_output((cmd_tshark, *APPLEMIDI_OPTS,
                '-r', capture_file('applemidi_coverage.pcap.gz'),
                '-Tfields', '-e_ws.col.protocol',
            ), encoding='utf-8', env=test_env)
        protocols = stdout.split()
        assert protocols.count('AppleMIDI') == 42
        assert protocols.count('RTP-MIDI') == 14
        # The heuristic rejects 3 octets, an unknown first command and
        # a packet without the 0xffff signature
        assert protocols.count('UDP') == 3
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *APPLEMIDI_OPTS, *passes,
                    '-r', capture_file('applemidi_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity >= warning',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0

    def test_applemidi_commands(self, cmd_tshark, capture_file, test_env):
        '''Each command and its fields.'''
        frames = self.applemidi_fields(cmd_tshark, capture_file, test_env,
                                       'applemidi.command', 'applemidi.count',
                                       'applemidi.rtp_sequence_number',
                                       'applemidi.bitrate_limit', 'applemidi.unknown_data')
        assert frames[1] == ['0x494e', '', '', '', '']             # IN
        assert frames[2] == ['0x4f4b', '', '', '', '']             # OK
        assert frames[29] == ['0x4e4f', '', '', '', '']            # NO
        assert frames[26] == ['0x4259', '', '', '', '']            # BY
        assert [frames[n][1] for n in (5, 6, 7)] == ['0', '1', '2']  # CK
        assert frames[24] == ['0x5253', '', '1', '', 'beef']       # RS
        assert frames[20] == ['0x524c', '', '', '31250', '']       # RL
        # An unknown command once the conversation is set up
        assert frames[21] == ['0x5a5a', '', '', '', '01020304']

    def test_applemidi_names(self, cmd_tshark, capture_file, test_env):
        '''The name length is taken from the NUL in the packet, not from
        the name converted to UTF-8: a name without a NUL and a name in
        invalid UTF-8 decode without malformed packets, and what follows
        the NUL is shown as unknown data.'''
        frames = self.applemidi_fields(cmd_tshark, capture_file, test_env,
                                       'applemidi.name', 'applemidi.unknown_data',
                                       '_ws.malformed')
        assert frames[36] == ['peer', '', '']
        assert frames[37] == ['peer', '', '']            # no NUL
        assert frames[38] == ['�' * 4, '7461696c', '']  # invalid UTF-8, then "tail"
        assert frames[39] == ['Studio Köln ♫', '', '']
        assert frames[40] == ['', '', '']                 # only the NUL
        assert frames[41] == ['ab��', '', '']   # invalid UTF-8, no NUL

    def test_applemidi_rtp_midi(self, cmd_tshark, capture_file, test_env):
        '''After the invitation, RTP on the session's ports is dissected as
        RTP-MIDI (dynamic payload type 97 set up by AppleMIDI), in both
        directions, in one and two passes.'''
        rtp_frames = [str(n) for n in range(8, 19)] + ['44', '54', '55']
        setup = ['3'] * 11 + ['42', '51', '51']
        for passes in ((), ('-2',)):
            stdout = subprocess.check_output((cmd_tshark, *APPLEMIDI_OPTS, *passes,
                    '-r', capture_file('applemidi_coverage.pcap.gz'),
                    '-Y', 'rtpmidi',
                    '-Tfields', '-eframe.number', '-ertp.setup-frame', '-ertp.p_type',
                ), encoding='utf-8', env=test_env)
            frames = [line.split('\t') for line in stdout.splitlines()]
            assert [f[0] for f in frames] == rtp_frames
            assert [f[1] for f in frames] == setup
            assert all(f[2] == '97' for f in frames)
        frames = self.applemidi_fields(cmd_tshark, capture_file, test_env, '_ws.col.info')
        assert frames[44] == ['Note On (c=1, n=C4, v=64)']
        assert frames[11] == ['Program Change (c=3, p=5), Channel Pressure (c=3, p=48), '
                              'Pitch Bend Change (c=3, pb=8192)']


APRS_OPTS = ('-o', 'ax25_nol3.showaprs:TRUE')  # APRS decoding is off by default


class TestDissectAprs:
    def run_fields(self, cmd_tshark, capture_file, test_env, *args, decimals=()):
        stdout = subprocess.check_output((cmd_tshark, *APRS_OPTS,
                '-r', capture_file('aprs_coverage.pcap.gz'),
                '-Tfields', *args,
            ), encoding='utf-8', env=test_env)
        frames = [line.split('\t') for line in stdout.splitlines()]
        # The columns in decimals are shown with the decimal separator of the locale
        for f in frames:
            for c in decimals:
                f[c] = f[c].replace(',', '.')
        return frames

    def test_aprs_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every data type indicator, position format, extension, Mic-E
        destination character, weather field, item, object and message
        decodes without malformed packets, in one and two passes and with
        the lax preference.'''
        protocols = [f[0] for f in self.run_fields(cmd_tshark, capture_file, test_env,
                                                   '-e_ws.col.protocol')]
        assert protocols.count('APRS') == 162
        assert protocols.count('AX.25-NoL3') == 2
        for opts in ((), ('-2',), ('-o', 'aprs.showaprslax:TRUE')):
            stdout = subprocess.check_output((cmd_tshark, *APRS_OPTS, *opts,
                    '-r', capture_file('aprs_coverage.pcap.gz'),
                    '-Y', '_ws.malformed || _ws.expert.severity == error',
                    '-Tfields', '-eframe.number',
                ), encoding='utf-8', env=test_env)
            assert count_output(stdout) == 0
        # Without the ax25_nol3 preference nothing is APRS
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('aprs_coverage.pcap.gz'),
                '-Y', 'aprs', '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_aprs_compressed_course(self, cmd_tshark, capture_file, test_env):
        '''The compressed course is (c - 33) * 4 up to 356 for 'z'; it was
        kept in 8 bits.'''
        frames = self.run_fields(cmd_tshark, capture_file, test_env,
                                 '-Y', 'frame.number == 1 || (frame.number >= 32 && frame.number <= 35)',
                                 '-eframe.number', '-eaprs.msg.cse', '-eaprs.msg.spd',
                                 decimals=(2,))
        assert frames == [['1', '356', '   1.00'], ['32', '0', '  37.23'],
                          ['33', '88', '  37.23'], ['34', '188', '  37.23'],
                          ['35', '356', '  37.23']]

    def test_aprs_mic_e(self, cmd_tshark, capture_file, test_env):
        '''Mic-E: the course takes the units of DC as hundreds (251 for
        DC=30, SE=79; the units used to be multiplied by 10), speed and
        course wrap at 800 and 400, the destination address gives the
        latitude and the eight message codes.'''
        frames = self.run_fields(cmd_tshark, capture_file, test_env,
                                 '-Y', 'aprs.mic_e_current', '-eframe.number',
                                 '-eaprs.mic_e_current', '-eaprs.mic_e.speed_dc',
                                 '-eaprs.mic_e.speed_se')
        mic_e = {int(f[0]): f[1:] for f in frames}
        assert mic_e[2] == ['Lat: 3325.64N Long: 11220.50W, Cse: 251, Spd: 20, SSID: 0, Msg Returning',
                            '0x1e', '0x4f']
        assert mic_e[80][0] == 'Lat: 3325.64N Long: 07201.75W, Cse: 111, Spd: 14, SSID: 0, Msg Returning'
        messages = [mic_e[n][0].split(', Msg ')[1] for n in range(53, 61)]
        assert messages == ['Off Duty', 'En Route', 'In Service', 'Returning',
                            'Committed', 'Special', 'Priority', 'Emergency']
        # Longitude degrees with and without the offset of 100, and the
        # 180-189 and 190-199 ranges
        longitudes = [mic_e[n][0].split('Long: ')[1][:9] for n in range(74, 80)]
        assert longitudes == ['05001.99W', '11001.99W', '10001.99W',
                              '00001.99W', '10001.99W', '00501.99W']

    def test_aprs_items(self, cmd_tshark, capture_file, test_env):
        '''Item names end at the first '!' or '_' in the packet; a name with
        octets over 0x7f is as long as in the packet (the position after it
        decodes) and a killed item ending in '_' is found.'''
        frames = self.run_fields(cmd_tshark, capture_file, test_env,
                                 '-Y', 'aprs.item', '-eframe.number', '-eaprs.item',
                                 '-eaprs.position.lat', '-eaprs.position.long',
                                 decimals=(2, 3))
        assert frames == [
            ['3', '\ufffd' * 9, '4903.50N', '07201.75W'],
            ['91', 'AID #2', '4903.50N', '07201.75W'],
            ['92', 'ITEM', '4903.50N', '07201.75W'],
            ['93', 'AB', ' 49.50', ' -72.75'],
            ['94', 'AB', '-33.59', ' -72.75'],
            ['95', 'TENCHARSXX', '4903.50N', '07201.75W'],
            ['96', 'MOBIL', ' 49.50', ' -72.75'],
            ['97', 'G1', '4903.50N', '07201.75W'],
            ['98', '\ufffd\ufffdt\ufffd\ufffd', '4903.50N', '07201.75W'],
            ['161', 'NOCMT', '4903.50N', '07201.75W'],
        ]

    def test_aprs_compression_type(self, cmd_tshark, capture_file, test_env):
        '''The compression type subfields are the bits of the octet minus 33,
        not of the octet itself.'''
        frames = self.run_fields(cmd_tshark, capture_file, test_env,
                                 '-Y', 'frame.number == 1 || (frame.number >= 41 && frame.number <= 48)',
                                 '-eaprs.ct', '-eaprs.ct.gps_fix', '-eaprs.ct.nmea_src',
                                 '-eaprs.ct.origin')
        assert frames == [
            ['0x33', '0x01', '0x02', '0x03'],
            ['0x00', '0x00', '0x00', '0x00'],
            ['0x09', '0x00', '0x01', '0x01'],
            ['0x12', '0x00', '0x02', '0x02'],
            ['0x1b', '0x00', '0x03', '0x03'],
            ['0x24', '0x01', '0x00', '0x04'],
            ['0x2d', '0x01', '0x01', '0x05'],
            ['0x36', '0x01', '0x02', '0x06'],
            ['0x3f', '0x01', '0x03', '0x07'],
        ]

    def test_aprs_lax(self, cmd_tshark, capture_file, test_env):
        '''A position without messaging is read as having an extension
        unless the lax preference is set, which takes only D, P, R and T.'''
        for opts, expected in (((), [['5', '1', '5'], ['10', '1', '']]),
                               (('-o', 'aprs.showaprslax:TRUE'), [['5', '1', '5'], ['10', '0', '']])):
            frames = self.run_fields(cmd_tshark, capture_file, test_env, *opts,
                                     '-Y', 'frame.number == 10 || frame.number == 5',
                                     '-eframe.number', '-e', 'count(aprs.msg)',
                                     '-eaprs.msg.phg.p')
            assert frames == expected

    def test_aprs_storm(self, cmd_tshark, capture_file, test_env):
        '''Storm reports as in APRS101: the course and speed are the
        position's extension (or the compressed course/speed), the storm
        data starts with the type.'''
        frames = self.run_fields(cmd_tshark, capture_file, test_env,
                                 '-Y', 'aprs.storm', '-eframe.number',
                                 '-eaprs.msg.cse', '-eaprs.msg.spd',
                                 '-eaprs.storm.type', '-eaprs.storm.sws',
                                 '-eaprs.storm.pwg', '-eaprs.storm.central_pressure',
                                 '-eaprs.storm.radius_hurricane_winds',
                                 '-eaprs.storm.radius_tropical_storms_winds',
                                 '-eaprs.storm.radius_whole_gale',
                                 decimals=(2,))
        hc = ['/HC', '/150', '^200', '/0980', '>090', '&050', '%040']
        ts = ['/TS', '/090', '^120', '/0995', '>000', '&030', '%020']
        assert frames == [
            ['12', '088', '036', *hc],     # '!' uncompressed
            ['13', '088', '036', *ts],     # '!' alternate table
            ['28', '088', '036', *hc],     # '@' with timestamp
            ['51', '88', '  37.23', *hc],  # compressed
            ['52', '88', '  37.23', *ts],  # compressed, alternate table
            ['102', '088', '036', *hc],    # object with MDHM timestamp
            ['163', '088', '036', *hc],    # '/' with timestamp, no comment
        ]

    def test_aprs_no_comment(self, cmd_tshark, capture_file, test_env):
        '''Uncompressed positions with no comment or one of 1-6 octets
        ('!', '=', '/', '@', an item and an object) decode with no
        extension and no malformed packet, with and without lax mode.'''
        comments = ['', 'A', 'PHG51', '088/03'] * 4 + ['', '']
        for opts in ((), ('-o', 'aprs.showaprslax:TRUE')):
            frames = self.run_fields(cmd_tshark, capture_file, test_env, *opts,
                                     '-Y', 'frame.number >= 145 && frame.number <= 162',
                                     '-eframe.number', '-e', 'count(aprs.msg)',
                                     '-eaprs.comment', '-e_ws.malformed',
                                     '-eaprs.position.lat')
            assert frames == [[str(n), '0', c, '', '4903.50N']
                              for n, c in zip(range(145, 163), comments)]


# ar_drone_coverage.pcap.gz is synthetic: every packet was generated, to
# cover as much of the AR Drone dissector as possible. No UDP port is
# registered for it by default and its heuristic is disabled.
AR_DRONE_OPTS = ('-d', 'udp.port==5556,ar_drone')
AR_DRONE_HEUR = ('--enable-heuristic', 'ar_drone_udp')


class TestDissectArDrone:
    def ar_drone_fields(self, cmd_tshark, capture_file, test_env, *fields, opts=AR_DRONE_OPTS):
        args = []
        for field in fields:
            args += ['-e', field]
        stdout = subprocess.check_output((cmd_tshark, *opts,
                '-r', capture_file('ar_drone_coverage.pcap.gz'),
                '-Tfields', '-E', 'aggregator=|', '-e', 'frame.number', *args,
            ), encoding='utf-8', env=test_env)
        return {int(line.split('\t')[0]): line.split('\t')[1:] for line in stdout.splitlines()}

    def ar_drone_tree(self, cmd_tshark, capture_file, test_env, frame):
        stdout = subprocess.check_output((cmd_tshark, *AR_DRONE_OPTS,
                '-r', capture_file('ar_drone_coverage.pcap.gz'),
                '-Y', f'frame.number == {frame}', '-V', '-O', 'ar_drone',
            ), encoding='utf-8', env=test_env)
        return [line.strip() for line in stdout.splitlines() if line.startswith('    ')]

    def test_ar_drone_not_by_default(self, cmd_tshark, capture_file, test_env):
        '''Nothing is dissected as AR Drone without Decode As or the heuristic.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ar_drone_coverage.pcap.gz'),
                '-Y', 'ar_drone',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert count_output(stdout) == 0

    def test_ar_drone_protocols(self, cmd_tshark, capture_file, test_env):
        '''Every command decodes without malformed packets or error expert
        infos, in one and two passes, by port and by the heuristic.'''
        for opts, ar_drone, udp in ((AR_DRONE_OPTS, 39, 8), (AR_DRONE_HEUR, 40, 7)):
            stdout = subprocess.check_output((cmd_tshark, *opts,
                    '-r', capture_file('ar_drone_coverage.pcap.gz'),
                    '-Tfields', '-e_ws.col.protocol',
                ), encoding='utf-8', env=test_env)
            protocols = stdout.split()
            assert protocols.count('ar_drone') == ar_drone
            assert protocols.count('UDP') == udp
            for passes in ((), ('-2',)):
                stdout = subprocess.check_output((cmd_tshark, *opts, *passes,
                        '-r', capture_file('ar_drone_coverage.pcap.gz'),
                        '-Y', '_ws.malformed || _ws.short || _ws.expert.severity >= warning',
                        '-Tfields', '-eframe.number',
                    ), encoding='utf-8', env=test_env)
                assert count_output(stdout) == 0

    def test_ar_drone_commands(self, cmd_tshark, capture_file, test_env):
        '''Every command, several per packet, and their fields.'''
        frames = self.ar_drone_fields(cmd_tshark, capture_file, test_env,
                                      'ar_drone.command', 'ar_drone.ref.ctrl',
                                      'ar_drone.ctrl.mode', 'ar_drone.config.name',
                                      'ar_drone.led.anim', 'ar_drone.anim.num')
        assert frames[27] == ['PCMD|REF|CONFIG_IDS|ANIM|FTRIM|CONFIG|LED|COMWDG|CTRL',
                              '290718208', '5', '"control:altitude_max"', '2', '3']
        assert frames[25][0] == 'REF|PCMD|FTRIM'
        assert [frames[n][2] for n in range(3, 8)] == ['4', '5', '6', '0', '4']
        # Parsing stops at data that is not an AT command
        assert frames[29][0] == 'COMWDG'
        assert frames[30][0] == 'REF'
        assert frames[31][0] == 'REF|FOO'
        assert self.ar_drone_tree(cmd_tshark, capture_file, test_env, 3)[-2] == \
            'Control Mode: 4 (CFG_GET_CONTROL_MODE)'
        assert self.ar_drone_tree(cmd_tshark, capture_file, test_env, 6)[-2] == \
            'Control Mode: 0 (Unknown Mode)'

    def test_ar_drone_pcmd_directions(self, cmd_tshark, capture_file, test_env):
        '''Each direction of roll, pitch, gaz and yaw. An empty value has
        no direction.'''
        def values(frame):
            return self.ar_drone_tree(cmd_tshark, capture_file, test_env, frame)[-4:]
        assert values(14) == ['Roll: 0 (NO CHANGE)', 'Pitch: 0 (NO CHANGE)',
                              'Gaz: 0 (NO CHANGE)', 'Yaw: 0 (NO CHANGE)']
        assert values(15) == ['Roll: 1056964608 (ROLL RIGHT)',
                              'Pitch: 1056964608 (PITCH BACKWARD)',
                              'Gaz: 1056964608 (INCREASE VERT SPEED)',
                              'Yaw: 1056964608 (ROTATE RIGHT)']
        assert values(16) == ['Roll: -1090519040 (ROLL LEFT)',
                              'Pitch: -1090519040 (PITCH FORWARD)',
                              'Gaz: -1090519040 (DECREASE VERT SPEED)',
                              'Yaw: -1090519040 (ROTATE LEFT)']
        assert values(17) == ['Roll: -0 (NO CHANGE)', 'Pitch: -0 (NO CHANGE)',
                              'Gaz: -0 (NO CHANGE)', 'Yaw: -0 (NO CHANGE)']
        # The empty Roll value of the review reproducer
        assert values(20) == ['Roll:', 'Pitch: 0 (NO CHANGE)',
                              'Gaz: 0 (NO CHANGE)', 'Yaw: 0 (NO CHANGE)']
        assert values(24) == ['Roll:', 'Pitch:', 'Gaz:', 'Yaw:']

    def test_ar_drone_equals_sign_early(self, cmd_tshark, capture_file, test_env):
        '''A second command with '=' at its first or second octet is not an
        AT command and ends the packet. Its length used to wrap and the
        packet was shown as "Packet size limited during capture".'''
        frames = self.ar_drone_fields(cmd_tshark, capture_file, test_env,
                                      'ar_drone.command', '_ws.short', '_ws.malformed')
        assert frames[34] == ['REF', '', '']
        assert frames[35] == ['COMWDG', '', '']

    def test_ar_drone_not_ours_decode_as(self, cmd_tshark, capture_file, test_env):
        '''Through Decode As too, a packet whose first command is unknown or
        has no '=' is left as plain UDP: nothing is added to the columns or
        the tree (frames 42 and 43, with both ports 5556, used to get the
        items twice).'''
        frames = self.ar_drone_fields(cmd_tshark, capture_file, test_env,
                                      '_ws.col.protocol', 'ar_drone.command')
        # AT*FOO=1,2; AT*; ATX*REF=1,2; AT*COMWDG without '='; AT*=1
        for n in (36, 40, 41, 42, 43):
            assert frames[n] == ['UDP', ''], n
        stdout = subprocess.check_output((cmd_tshark, *AR_DRONE_OPTS,
                '-r', capture_file('ar_drone_coverage.pcap.gz'),
                '-Y', 'ar_drone',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == [str(n) for n in [*range(1, 36), 37, 38, 39, 44]]
        stdout = subprocess.check_output((cmd_tshark, *AR_DRONE_OPTS,
                '-r', capture_file('ar_drone_coverage.pcap.gz'),
                '-Y', 'frame.number in {36, 42, 43}', '-V',
            ), encoding='utf-8', env=test_env)
        assert 'AR Drone' not in stdout
        assert stdout.count('Data (') == 3

    def test_ar_drone_heuristic(self, cmd_tshark, capture_file, test_env):
        '''The heuristic takes a known first command with a '=', on any
        port, and leaves other packets, AT*FOO among them, untouched as
        plain UDP.'''
        frames = self.ar_drone_fields(cmd_tshark, capture_file, test_env,
                                      '_ws.col.protocol', 'ar_drone.command',
                                      opts=AR_DRONE_HEUR)
        assert frames[36] == ['UDP', '']         # AT*FOO=1,2
        assert frames[45] == ['ar_drone', 'REF']  # not on port 5556
        assert frames[46] == ['UDP', '']         # AT*FOO=1
        assert frames[47] == ['UDP', '']         # no '='
        stdout = subprocess.check_output((cmd_tshark, *AR_DRONE_HEUR,
                '-r', capture_file('ar_drone_coverage.pcap.gz'),
                '-Y', 'frame.number == 36', '-V',
            ), encoding='utf-8', env=test_env)
        assert 'AR Drone' not in stdout
        assert 'Data (11 bytes)' in stdout
