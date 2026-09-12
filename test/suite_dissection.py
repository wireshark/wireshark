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

class TestDissectTcp:
    @staticmethod
    def check_tcp_out_of_order(cmd_tshark, dirs, test_env, extraArgs=[]):
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
                                       extraArgs=[]):
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
        expected = ''.join('%04x\n' % i for i in range(1, 1001))
        assert stdout == expected

    @staticmethod
    def check_tls_reassembly_over_tcp_reassembly(cmd_tshark, capture_file, test_env,
                                                 extraArgs=[]):
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
    def check_tls_out_of_order(cmd_tshark, capture_file, test_env, extraArgs=[]):
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
                                       extraArgs=[]):
        # An assortment of QUIC carrying TLS handshakes that need to be
        # reassembled, including fragmented in one packet, fragmented in
        # multiple packets, fragmented in multiple out of order packets,
        # retried, retried with overlap from the original packets, and retried
        # with one of the original packets missing (but all data there.)
        # Include -zexpert just to be sure that nothing Warn or higher occurred.
        # Note level expert infos may be expected with the overlaps and
        # retransmissions.
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
        # data_id = 2 (Set Datatypes); charset = 871 (US7ASCII) both ways;
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
        '''TTI_LOBOPS decodes the operation opcode and source offset. Two
        frames: a READ (op 0x0002) and a GET_LENGTH (op 0x0001), both from
        source offset 1.'''
        stdout = subprocess.check_output((cmd_tshark,
            '-r', capture_file('tns_lobops.pcap'),
            '-d', 'tcp.port==1521,tns',
            '-T', 'fields',
            '-e', 'tns.data_oci.id',
            '-e', 'tns.data_lob.op',
            '-e', 'tns.data_lob.offset',
        ), encoding='utf-8', env=test_env)
        rows = [r.split('\t') for r in stdout.strip().splitlines()]
        assert len(rows) == 2, rows
        # oci id 0x60 = 96 (TTI_LOBOPS / "LOB and FILE related calls").
        assert rows[0] == ['0x60', '0x00000002', '1'], rows[0]
        assert rows[1] == ['0x60', '0x00000001', '1'], rows[1]

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
        value framings: an ordinary NUMBER, a structured ROWID, and a LONG.'''
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
        vals = rows[1][1].split(',')
        assert len(vals) == 3, vals
        assert vals[0] == 'c10b', vals
        assert vals[1] == '0a0164010400013200', vals
        assert vals[2] == '036162630000', vals

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
            (1, 'frame.process.pid == 1234 && frame.process.name == "curl"'
                ' && frame.process.path == "/usr/bin/curl"'
                ' && frame.process.cmdline == "curl https://example.com/"'
                ' && frame.process.ppid == 1 && frame.process.uid == 1000'
                ' && frame.process.user == "alice"'
                ' && frame.process.uuid == 6b8b4567-327b-23c6-643c-986966334873'
                ' && frame.process.start_time == "2026-01-01T00:00:00Z"'),
            # A block with nothing but a process ID.
            (3, 'frame.process.pid == 4321 && !frame.process.name && !frame.process.uid'),
            # A block in a big-endian section.
            (4, 'frame.process.pid == 77 && frame.process.name == "sshd"'
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

    def test_frame_process_info_pid_reuse(self, assert_frames_match):
        '''With several blocks for one process ID, the start times and
        the time stamp of the packet decide which one it is matched with.'''
        assert_frames_match('process_info_pid_reuse.pcapng', [
            (1, 'frame.process.name == "first"'),
            (2, 'frame.process.name == "second"'),
            (3, 'frame.process.name == "first"'),
            (4, 'frame.process.name == "new"'),
            (5, 'frame.process.pid == 700 && !frame.process.name'),
        ])

    def test_frame_darwin_effective_process(self, assert_frames_match):
        '''The effective process of a Darwin packet is shown when it
        differs from the process.'''
        assert_frames_match('process_info_darwin_dpib.pcapng', [
            (1, 'frame.darwin.process_info.pid == 501 && !frame.darwin.process_info.epid'),
            (3, 'frame.darwin.process_info.pid == 501 && frame.darwin.process_info.epid == 1'
                ' && frame.darwin.process_info.epname == "launchd"'),
        ])
