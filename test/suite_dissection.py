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
import subprocesstest
import unittest
import fixtures
import sys


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_dtn_tcpcl(subprocesstest.SubprocessTestCase):

    def test_tcpclv3_xfer(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_tcpclv3_bpv6_transfer.pcapng'),
                '-Tfields', '-etcpcl.ack.length',
            ))
        self.assertEqual(self.countOutput(r'1064'), 2)

    def test_tcpclv4_xfer(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_tcpclv4_bpv7_transfer.pcapng'),
                '-Tfields', '-etcpcl.v4.xfer_ack.ack_len',
            ))
        self.assertEqual(self.countOutput(r'199'), 2)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_bpv7(subprocesstest.SubprocessTestCase):

    def test_bpv7_admin_status(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bib_admin.pcapng'),
                '-Tfields', '-ebpv7.status_rep.identity',
            ))
        self.assertTrue(self.grepOutput(r'Source: ipn:93.185, DTN Time: 1396536125, Seq: 281'))

    def test_bpv7_bpsec_bib(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bib_admin.pcapng'),
                '-Tfields', '-ebpsec.asb.ctxid',
            ))
        self.assertEqual(self.countOutput(r'1'), 1)

    def test_bpv7_bpsec_bib_admin_type(self, cmd_tshark, features, dirs, capture_file):
        # BIB doesn't alter payload
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bib_admin.pcapng'),
                '-Tfields', '-ebpv7.admin_rec.type_code',
            ))
        self.assertEqual(self.countOutput(r'1'), 1)

    def test_bpv7_bpsec_bcb(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bcb_admin.pcapng'),
                '-Tfields', '-ebpsec.asb.ctxid',
            ))
        self.assertEqual(self.countOutput(r'2'), 1)

    def test_bpv7_bpsec_bcb_admin_type(self, cmd_tshark, features, dirs, capture_file):
        # BCB inhibits payload dissection
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtn_udpcl_bpv7_bpsec_bcb_admin.pcapng'),
                '-Tfields', '-ebpv7.admin_rec.type_code',
            ))
        self.assertEqual(self.countOutput(r'1'), 0)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_cose(subprocesstest.SubprocessTestCase):
    '''
    These test captures were generated from the COSE example files with command:
    for FN in test/captures/cose*.cbordiag; do python3 tools/generate_cbor_pcap.py --content-type 'application/cose' --infile $FN --outfile ${FN%.cbordiag}.pcap; done
    '''
    def test_cose_sign_tagged(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_sign_tagged.pcap'),
                '-Tfields', '-ecose.msg.signature',
            ))
        self.assertTrue(self.grepOutput('e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a'))

    def test_cose_sign1_tagged(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_sign1_tagged.pcap'),
                '-Tfields', '-ecose.msg.signature',
            ))
        self.assertTrue(self.grepOutput('8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36'))

    def test_cose_encrypt_tagged(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_encrypt_tagged.pcap'),
                '-Tfields', '-ecose.kid',
            ))
        self.assertTrue(self.grepOutput('6f75722d736563726574'))

    def test_cose_encrypt0_tagged(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_encrypt0_tagged.pcap'),
                '-Tfields', '-ecose.iv',
            ))
        self.assertTrue(self.grepOutput('89f52f65a1c580933b5261a78c'))

    def test_cose_mac_tagged(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_mac_tagged.pcap'),
                '-Tfields', '-ecose.kid',
            ))
        self.assertTrue(self.grepOutput('30313863306165352d346439622d343731622d626664362d656566333134626337303337'))

    def test_cose_mac0_tagged(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_mac0_tagged.pcap'),
                '-Tfields', '-ecose.msg.mac_tag',
            ))
        self.assertTrue(self.grepOutput('726043745027214f'))

    def test_cose_keyset(self, cmd_tshark, features, dirs, capture_file):
        self.assertRun((cmd_tshark,
                '-r', capture_file('cose_keyset.pcap'),
                '-Tfields', '-ecose.key.k',
            ))
        self.assertTrue(self.grepOutput('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_grpc(subprocesstest.SubprocessTestCase):
    def test_grpc_with_json(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC with JSON payload'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_person_search_json_with_image.pcapng.gz'),
                '-d', 'tcp.port==50052,http2',
                '-Y', 'grpc.message_length == 208 && json.value.string == "87561234"',
            ))
        self.assertTrue(self.grepOutput('GRPC/JSON'))

    def test_grpc_with_protobuf(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC with Protobuf payload'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_person_search_protobuf_with_image.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-d', 'tcp.port==50051,http2',
                '-Y', 'protobuf.message.name == "tutorial.PersonSearchRequest"'
                      ' || (grpc.message_length == 66 && protobuf.field.value.string == "Jason"'
                      '     && protobuf.field.value.int64 == 1602601886)',
            ))
        self.assertTrue(self.grepOutput('tutorial.PersonSearchService/Search')) # grpc request
        self.assertTrue(self.grepOutput('tutorial.Person')) # grpc response

    def test_grpc_streaming_mode_reassembly(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC/HTTP2 streaming mode reassembly'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_stream_reassembly_sample.pcapng.gz'),
                '-d', 'tcp.port==50051,http2',
                '-d', 'tcp.port==44363,http2',
                '-2', # make http2.body.reassembled.in available
                '-Y', # Case1: In frame28, one http DATA contains 4 completed grpc messages (json data seq=1,2,3,4).
                      '(frame.number == 28 && grpc && json.value.number == "1" && json.value.number == "2"'
                      ' && json.value.number == "3" && json.value.number == "4" && http2.body.reassembled.in == 45) ||'
                      # Case2: In frame28, last grpc message (the 5th) only has 4 bytes, which need one more byte
                      # to be a message head. a completed message is reassembled in frame45. (json data seq=5)
                      '(frame.number == 45 && grpc && http2.body.fragment == 28 && json.value.number == "5"'
                      ' && http2.body.reassembled.in == 61) ||'
                      # Case3: In frame45, one http DATA frame contains two partial fragment, one is part of grpc
                      # message of previous http DATA (frame28), another is first part of grpc message of next http
                      # DATA (which will be reassembled in next http DATA frame61). (json data seq=6)
                      '(frame.number == 61 && grpc && http2.body.fragment == 45 && json.value.number == "6") ||'
                      # Case4: A big grpc message across frame100, frame113, frame126 and finally reassembled in frame139.
                      '(frame.number == 100 && grpc && http2.body.reassembled.in == 139) ||'
                      '(frame.number == 113 && !grpc && http2.body.reassembled.in == 139) ||'
                      '(frame.number == 126 && !grpc && http2.body.reassembled.in == 139) ||'
                      '(frame.number == 139 && grpc && json.value.number == "9") ||'
                      # Case5: An large grpc message of 200004 bytes.
                      '(frame.number == 164 && grpc && grpc.message_length == 200004)',
            ))
        self.assertEqual(self.countOutput('DATA'), 8)

    def test_grpc_http2_fake_headers(self, cmd_tshark, features, dirs, capture_file):
        '''HTTP2/gRPC fake headers (used when HTTP2 initial HEADERS frame is missing)'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_person_search_protobuf_with_image-missing_headers.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:http2_fake_headers: "{}","{}","{}","{}","{}","{}"'.format(
                            '50051','3','IN',':path','/tutorial.PersonSearchService/Search','TRUE'),
                '-o', 'uat:http2_fake_headers: "{}","{}","{}","{}","{}","{}"'.format(
                            '50051','0','IN','content-type','application/grpc','TRUE'),
                '-o', 'uat:http2_fake_headers: "{}","{}","{}","{}","{}","{}"'.format(
                            '50051','0','OUT','content-type','application/grpc','TRUE'),
                '-d', 'tcp.port==50051,http2',
                '-Y', 'protobuf.field.value.string == "Jason" || protobuf.field.value.string == "Lily"',
            ))
        self.assertEqual(self.countOutput('DATA'), 2)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_grpc_web(subprocesstest.SubprocessTestCase):

    def test_grpc_web_unary_call_over_http1(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web unary call over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-Y', '(tcp.stream eq 0) && (pbf.greet.HelloRequest.name == "88888888"'
                        '|| pbf.greet.HelloRequest.name == "99999999"'
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 2)
        self.assertEqual(self.countOutput('greet.HelloReply'), 1)

    def test_grpc_web_unary_call_over_http2(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web unary call over http2'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-Y', '(tcp.stream eq 1) && (pbf.greet.HelloRequest.name == "88888888"'
                        '|| pbf.greet.HelloRequest.name == "99999999"'
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 2)
        self.assertEqual(self.countOutput('greet.HelloReply'), 1)

    def test_grpc_web_reassembly_and_stream_over_http2(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web data reassembly and server stream over http2'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-Y', '(tcp.stream eq 2) && ((pbf.greet.HelloRequest.name && grpc.message_length == 80004)'
                       '|| (pbf.greet.HelloReply.message && (grpc.message_length == 23 || grpc.message_length == 80012)))',
            ))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 2)
        self.assertEqual(self.countOutput('greet.HelloReply'), 4)

    def test_grpc_web_text_unary_call_over_http1(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web-Text unary call over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-Y', '(tcp.stream eq 5) && (pbf.greet.HelloRequest.name == "88888888"'
                        '|| pbf.greet.HelloRequest.name == "99999999"'
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ))
        self.assertTrue(self.grepOutput('GRPC-Web-Text'))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 2)
        self.assertEqual(self.countOutput('greet.HelloReply'), 1)

    def test_grpc_web_text_unary_call_over_http2(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web-Text unary call over http2'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-Y', '(tcp.stream eq 6) && (pbf.greet.HelloRequest.name == "88888888"'
                        '|| pbf.greet.HelloRequest.name == "99999999"'
                        '|| pbf.greet.HelloReply.message == "Hello 99999999")',
            ))
        self.assertTrue(self.grepOutput('GRPC-Web-Text'))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 2)
        self.assertEqual(self.countOutput('greet.HelloReply'), 1)

    def test_grpc_web_text_reassembly_and_stream_over_http2(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web-Text data reassembly and server stream over http2'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57228,http2',
                '-Y', '(tcp.stream eq 8) && ((pbf.greet.HelloRequest.name && grpc.message_length == 80004)'
                       '|| (pbf.greet.HelloReply.message && (grpc.message_length == 23 || grpc.message_length == 80012)))',
            ))
        self.assertTrue(self.grepOutput('GRPC-Web-Text'))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 2)
        self.assertEqual(self.countOutput('greet.HelloReply'), 4)

    def test_grpc_web_text_reassembly_over_http1(self, cmd_tshark, features, dirs, capture_file):
        '''gRPC-Web-Text data reassembly over http1'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('grpc_web.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-d', 'tcp.port==57226,http',
                '-Y', '(tcp.stream eq 7) && (grpc.message_length == 80004 || grpc.message_length == 80010)',
            ))
        self.assertTrue(self.grepOutput('GRPC-Web-Text'))
        self.assertEqual(self.countOutput('greet.HelloRequest'), 1)
        self.assertEqual(self.countOutput('greet.HelloReply'), 1)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_http(subprocesstest.SubprocessTestCase):
    def test_http_brotli_decompression(self, cmd_tshark, features, dirs, capture_file):
        '''HTTP brotli decompression'''
        if not features.have_brotli:
            self.skipTest('Requires brotli.')
        self.assertRun((cmd_tshark,
                '-r', capture_file('http-brotli.pcapng'),
                '-Y', 'http.response.code==200',
                '-Tfields', '-etext',
            ))
        self.assertTrue(self.grepOutput('This is a test file for testing brotli decompression in Wireshark'))

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_http2(subprocesstest.SubprocessTestCase):
    def test_http2_data_reassembly(self, cmd_tshark, features, dirs, capture_file):
        '''HTTP2 data reassembly'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        self.assertRun((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-d', 'tcp.port==8443,tls',
                '-Y', 'http2.data.data matches "PNG" && http2.data.data matches "END"',
            ))
        self.assertTrue(self.grepOutput('DATA'))

    def test_http2_brotli_decompression(self, cmd_tshark, features, dirs, capture_file):
        '''HTTP2 brotli decompression'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        if not features.have_brotli:
            self.skipTest('Requires brotli.')
        self.assertRun((cmd_tshark,
                '-r', capture_file('http2-brotli.pcapng'),
                '-Y', 'http2.data.data matches "This is a test file for testing brotli decompression in Wireshark"',
            ))
        self.assertTrue(self.grepOutput('DATA'))

    def test_http2_follow_0(self, cmd_tshark, features, dirs, capture_file):
        '''Follow HTTP/2 Stream ID 0 test'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        self.assertRun((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-z', 'follow,http2,hex,0,0'
            ))
        # Stream ID 0 bytes
        self.assertTrue(self.grepOutput('00000000  00 00 12 04 00 00 00 00'))
        # Stream ID 1 bytes, decrypted but compressed by HPACK
        self.assertFalse(self.grepOutput('00000000  00 00 2c 01 05 00 00 00'))
        # Stream ID 1 bytes, decrypted and uncompressed
        self.assertFalse(self.grepOutput('00000000  00 00 00 07 3a 6d 65 74'))

    def test_http2_follow_1(self, cmd_tshark, features, dirs, capture_file):
        '''Follow HTTP/2 Stream ID 1 test'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        key_file = os.path.join(dirs.key_dir, 'http2-data-reassembly.keys')
        self.assertRun((cmd_tshark,
                '-r', capture_file('http2-data-reassembly.pcap'),
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-z', 'follow,http2,hex,0,1'
            ))
        # Stream ID 0 bytes
        self.assertFalse(self.grepOutput('00000000  00 00 12 04 00 00 00 00'))
        # Stream ID 1 bytes, decrypted but compressed by HPACK
        self.assertFalse(self.grepOutput('00000000  00 00 2c 01 05 00 00 00'))
        # Stream ID 1 bytes, decrypted and uncompressed
        self.assertTrue(self.grepOutput('00000000  00 00 00 07 3a 6d 65 74'))

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_protobuf(subprocesstest.SubprocessTestCase):
    def test_protobuf_udp_message_mapping(self, cmd_tshark, features, dirs, capture_file):
        '''Test Protobuf UDP Message Mapping and parsing google.protobuf.Timestamp features'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_udp_addressbook_with_image_ts.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8127","tutorial.AddressBook"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.tutorial.Person.name == "Jason"'
                      ' && pbf.tutorial.Person.last_updated > "2020-10-15"'
                      ' && pbf.tutorial.Person.last_updated < "2020-10-19"',
            ))
        self.assertTrue(self.grepOutput('tutorial.AddressBook'))

    def test_protobuf_message_type_leading_with_dot(self, cmd_tshark, features, dirs, capture_file):
        '''Test Protobuf Message type is leading with dot'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_test_leading_dot.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8123","a.b.msg"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.a.b.a.b.c.param3 contains "in a.b.a.b.c" && pbf.a.b.c.param6 contains "in a.b.c"',
            ))
        self.assertTrue(self.grepOutput('PB[(]a.b.msg[)]'))

    def test_protobuf_map_and_oneof_types(self, cmd_tshark, features, dirs, capture_file):
        '''Test Protobuf map and oneof types, and taking keyword as identification'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_test_map_and_oneof_types.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8124","test.map.MapMaster"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.test.map.MapMaster.param3 == "I\'m param3 for oneof test."'  # test oneof type
                      ' && pbf.test.map.MapMaster.param4MapEntry.value == 1234'        # test map type
                      ' && pbf.test.map.Foo.param1 == 88 && pbf.test.map.MapMaster.param5MapEntry.key == 88'
            ))
        self.assertTrue(self.grepOutput('PB[(]test.map.MapMaster[)]'))

    def test_protobuf_default_value(self, cmd_tshark, features, dirs, capture_file):
        '''Test Protobuf feature adding missing fields with default values'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_test_default_value.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8128","wireshark.protobuf.test.TestDefaultValueMessage"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-o', 'protobuf.add_default_value: all',
                '-O', 'protobuf',
                '-Y', 'pbf.wireshark.protobuf.test.TestDefaultValueMessage.enumFooWithDefaultValue_Fouth == -4'
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.boolWithDefaultValue_False == false'
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.int32WithDefaultValue_0 == 0'
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.doubleWithDefaultValue_Negative0point12345678 == -0.12345678'
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.stringWithDefaultValue_SymbolPi contains "Pi."'
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.bytesWithDefaultValue_1F2F890D0A00004B == 1f:2f:89:0d:0a:00:00:4b'
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.optional' # test taking keyword 'optional' as identification
                      ' && pbf.wireshark.protobuf.test.TestDefaultValueMessage.message' # test taking keyword 'message' as identification
            ))
        self.assertTrue(self.grepOutput('floatWithDefaultValue_0point23: 0.23')) # another default value will be displayed
        self.assertTrue(self.grepOutput('missing required field \'missingRequiredField\'')) # check the missing required field export warn

    def test_protobuf_field_subdissector(self, cmd_tshark, features, dirs, capture_file):
        '''Test "protobuf_field" subdissector table'''
        if not features.have_lua:
            self.skipTest('Test requires Lua scripting support.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        lua_file = os.path.join(dirs.lua_dir, 'protobuf_test_field_subdissector_table.lua')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_udp_addressbook_with_image_ts.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'uat:protobuf_udp_message_types: "8127","tutorial.AddressBook"',
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-X', 'lua_script:{}'.format(lua_file),
                '-Y', 'pbf.tutorial.Person.name == "Jason" && pbf.tutorial.Person.last_updated && png',
            ))
        self.assertTrue(self.grepOutput('PB[(]tutorial.AddressBook[)]'))

    def test_protobuf_called_by_custom_dissector(self, cmd_tshark, features, dirs, capture_file):
        '''Test Protobuf invoked by other dissector (passing type by pinfo.private)'''
        if not features.have_lua:
            self.skipTest('Test requires Lua scripting support.')
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        user_defined_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'user_defined_types').replace('\\', '/')
        lua_file = os.path.join(dirs.lua_dir, 'protobuf_test_called_by_custom_dissector.lua')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_tcp_addressbook.pcapng.gz'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(user_defined_types_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-X', 'lua_script:{}'.format(lua_file),
                '-d', 'tcp.port==18127,addrbook',
                '-Y', 'pbf.tutorial.Person.name == "Jason" && pbf.tutorial.Person.last_updated',
            ))
        self.assertTrue(self.grepOutput('tutorial.AddressBook'))

    def test_protobuf_complex_syntax(self, cmd_tshark, features, dirs, capture_file):
        '''Test Protobuf parsing complex syntax .proto files'''
        well_know_types_dir = os.path.join(dirs.protobuf_lang_files_dir, 'well_know_types').replace('\\', '/')
        complex_proto_files_dir = os.path.join(dirs.protobuf_lang_files_dir, 'complex_proto_files').replace('\\', '/')
        self.assertRun((cmd_tshark,
                '-r', capture_file('protobuf_udp_addressbook_with_image_ts.pcapng'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(well_know_types_dir, 'FALSE'),
                '-o', 'uat:protobuf_search_paths: "{}","{}"'.format(complex_proto_files_dir, 'TRUE'),
                '-o', 'protobuf.preload_protos: TRUE',
                '-o', 'protobuf.pbf_as_hf: TRUE',
                '-Y', 'pbf.wireshark.protobuf.test.complex.syntax.TestFileParsed.last_field_for_wireshark_test'
                      ' && pbf.protobuf_unittest.TestFileParsed.last_field_for_wireshark_test',
            ))
        # the output must be empty and not contain something like:
        #   tshark: "pbf.xxx.TestFileParsed.last_field_for_wireshark_test" is neither a field nor a protocol name.
        # or
        #   tshark: Protobuf: Error(s)
        self.assertFalse(self.grepOutput('.last_field_for_wireshark_test'))
        self.assertFalse(self.grepOutput('Protobuf: Error'))

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_tcp(subprocesstest.SubprocessTestCase):
    def check_tcp_out_of_order(self, cmd_tshark, dirs, extraArgs=[]):
        capture_file = os.path.join(dirs.capture_dir, 'http-ooo.pcap')
        self.assertRun([cmd_tshark,
                '-r', capture_file,
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'http',
            ] + extraArgs)
        self.assertEqual(self.countOutput('HTTP'), 5)
        self.assertTrue(self.grepOutput(r'^\s*4\s.*PUT /1 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*7\s.*GET /2 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*10\s.*PUT /3 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*11\s.*PUT /4 HTTP/1.1'))
        self.assertTrue(self.grepOutput(r'^\s*15\s.*PUT /5 HTTP/1.1'))

    def test_tcp_out_of_order_onepass(self, cmd_tshark, dirs):
        self.check_tcp_out_of_order(cmd_tshark, dirs)

    def test_tcp_out_of_order_twopass(self, cmd_tshark, dirs):
        self.check_tcp_out_of_order(cmd_tshark, dirs, extraArgs=['-2'])

    def test_tcp_out_of_order_data_after_syn(self, cmd_tshark, capture_file):
        '''Test when the first non-empty segment is OoO.'''
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('dns-ooo.pcap'),
                '-otcp.reassemble_out_of_order:TRUE',
                '-Y', 'dns', '-Tfields', '-edns.qry.name',
            ))
        self.assertEqual(proc.stdout_str.strip(), 'example.com')

    def test_tcp_out_of_order_first_gap(self, cmd_tshark, capture_file):
        '''
        Test reporting of "reassembled_in" in the OoO frame that contains the
        initial segment (Bug 15420). Additionally, test for proper reporting
        when the initial segment is retransmitted.
        For PDU H123 (where H is the HTTP Request header and 1, 2 and 3 are part
        of the body), the order is: (SYN) 2 H H 1 3 H.
        '''
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('http-ooo2.pcap'),
            '-otcp.reassemble_out_of_order:TRUE',
            '-Tfields',
            '-eframe.number', '-etcp.reassembled_in', '-e_ws.col.Info',
            '-2',
            ))
        lines = proc.stdout_str.split('\n')
        # 2 - start of OoO MSP
        self.assertIn('2\t6\t[TCP Previous segment not captured]', lines[1])
        self.assertIn('[TCP segment of a reassembled PDU]', lines[1])
        # H - first time that the start of the MSP is delivered
        self.assertIn('3\t6\t[TCP Out-Of-Order]', lines[2])
        self.assertIn('[TCP segment of a reassembled PDU]', lines[2])
        # H - first retransmission.
        self.assertIn('4\t\t', lines[3])
        self.assertNotIn('[TCP segment of a reassembled PDU]', lines[3])
        # 1 - continue reassembly
        self.assertIn('5\t6\t[TCP Out-Of-Order]', lines[4])
        self.assertIn('[TCP segment of a reassembled PDU]', lines[4])
        # 3 - finish reassembly
        self.assertIn('6\t\tPUT /0 HTTP/1.1', lines[5])
        # H - second retransmission.
        self.assertIn('7\t\t', lines[6])
        self.assertNotIn('[TCP segment of a reassembled PDU]', lines[6])

    def test_tcp_reassembly_more_data_1(self, cmd_tshark, capture_file):
        '''
        Tests that reassembly also works when a new packet begins at the same
        sequence number as the initial segment. This models behavior with the
        ZeroWindowProbe: the initial segment contains a single byte. The second
        segment contains that byte, plus the remainder.
        '''
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('retrans-tls.pcap'),
            '-Ytls', '-Tfields', '-eframe.number', '-etls.record.length',))
        # First pass dissection actually accepted the first frame as TLS, but
        # subsequently requested reassembly.
        self.assertEqual(proc.stdout_str, '1\t\n2\t16\n')

    def test_tcp_reassembly_more_data_2(self, cmd_tshark, capture_file):
        '''
        Like test_tcp_reassembly_more_data_1, but checks the second pass (-2).
        '''
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('retrans-tls.pcap'),
            '-Ytls', '-Tfields', '-eframe.number', '-etls.record.length', '-2'))
        self.assertEqual(proc.stdout_str, '2\t16\n')

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_git(subprocesstest.SubprocessTestCase):
    def test_git_prot(self, cmd_tshark, capture_file, features):
        '''
        Check for Git protocol version 2, flush and delimiter packets.
        Ensure there are no malformed packets.
        '''
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('gitOverTCP.pcap'),
                '-Ygit', '-Tfields', '-egit.version', '-egit.packet_type',
                '-zexpert', '-e_ws.expert',
            ))
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
        self.assertEqual(proc.stdout_str, '50\t\t\n\t0\t\n\t\t\n\t1,0\t\n')

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_tls(subprocesstest.SubprocessTestCase):
    def check_tls_handshake_reassembly(self, cmd_tshark, capture_file,
                                       extraArgs=[]):
        # Include -zexpert just to be sure that no exception has occurred. It
        # is not strictly necessary as the extension to be matched is the last
        # one in the handshake message.
        proc = self.assertRun([cmd_tshark,
                               '-r', capture_file('tls-fragmented-handshakes.pcap.gz'),
                               '-zexpert',
                               '-Ytls.handshake.extension.data',
                               '-Tfields', '-etls.handshake.extension.data'] + extraArgs)
        output = proc.stdout_str.replace(',', '\n')
        # Expected output are lines with 0001, 0002, ..., 03e8
        expected = ''.join('%04x\n' % i for i in range(1, 1001))
        self.assertEqual(output, expected)

    def test_tls_handshake_reassembly(self, cmd_tshark, capture_file):
        '''Verify that TCP and TLS handshake reassembly works.'''
        self.check_tls_handshake_reassembly(cmd_tshark, capture_file)

    def test_tls_handshake_reassembly_2(self, cmd_tshark, capture_file):
        '''Verify that TCP and TLS handshake reassembly works (second pass).'''
        self.check_tls_handshake_reassembly(
            cmd_tshark, capture_file, extraArgs=['-2'])

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_dissect_quic(subprocesstest.SubprocessTestCase):
    def check_quic_tls_handshake_reassembly(self, cmd_tshark, capture_file,
                                       extraArgs=[]):
        # An assortment of QUIC carrying TLS handshakes that need to be
        # reassembled, including fragmented in one packet, fragmented in
        # multiple packets, fragmented in multiple out of order packets,
        # retried, retried with overlap from the original packets, and retried
        # with one of the original packets missing (but all data there.)
        # Include -zexpert just to be sure that nothing Warn or higher occured.
        # Note level expert infos may be expected with the overlaps and
        # retransmissions.
        proc = self.assertRun([cmd_tshark,
                               '-r', capture_file('quic-fragmented-handshakes.pcapng.gz'),
                               '-zexpert,warn',
                               '-Ytls.handshake.type',
                               '-o', 'gui.column.format:"Handshake Type","%Cus:tls.handshake.type:0:R"',
                               ] + extraArgs)
        self.assertEqual(self.countOutput('Client Hello'), 18)
        self.assertEqual(self.countOutput('Server Hello'), 2)
        self.assertEqual(self.countOutput('Finished'), 2)
        self.assertEqual(self.countOutput('New Session Ticket,New Session Ticket'), 1)
        self.assertEqual(self.countOutput('Certificate'), 2)
        self.assertFalse(self.grepOutput('Warns'))
        self.assertFalse(self.grepOutput('Errors'))

    def test_quic_tls_handshake_reassembly(self, cmd_tshark, capture_file):
        '''Verify that QUIC and TLS handshake reassembly works.'''
        self.check_quic_tls_handshake_reassembly(cmd_tshark, capture_file)

    def test_quic_tls_handshake_reassembly_2(self, cmd_tshark, capture_file):
        '''Verify that QUIC and TLS handshake reassembly works (second pass).'''
        self.check_quic_tls_handshake_reassembly(
            cmd_tshark, capture_file, extraArgs=['-2'])

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decompress_smb2(subprocesstest.SubprocessTestCase):
    def extract_compressed_payload(self, cmd_tshark, capture_file, frame_num):
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('smb311-lz77-lz77huff-lznt1.pcap.gz'),
                '-Tfields', '-edata.data',
                '-Y', 'frame.number == %d'%frame_num,
        ))
        self.assertEqual(b'a'*4096, bytes.fromhex(proc.stdout_str.strip()))

    def test_smb311_read_lz77(self, cmd_tshark, capture_file):
        self.extract_compressed_payload(cmd_tshark, capture_file, 1)

    def test_smb311_read_lz77huff(self, cmd_tshark, capture_file):
        self.extract_compressed_payload(cmd_tshark, capture_file, 2)

    def test_smb311_read_lznt1(self, cmd_tshark, capture_file):
        if sys.byteorder == 'big':
            fixtures.skip('this test is supported on little endian only')
        self.extract_compressed_payload(cmd_tshark, capture_file, 3)

    def extract_chained_compressed_payload(self, cmd_tshark, capture_file, frame_num):
        proc = self.assertRun((cmd_tshark,
            '-r', capture_file('smb311-chained-patternv1-lznt1.pcapng.gz'),
            '-Tfields', '-edata.data',
            '-Y', 'frame.number == %d'%frame_num,
        ))
        self.assertEqual(b'\xaa'*256, bytes.fromhex(proc.stdout_str.strip()))

    def test_smb311_chained_lznt1_patternv1(self, cmd_tshark, capture_file):
        if sys.byteorder == 'big':
            fixtures.skip('this test is supported on little endian only')
        self.extract_chained_compressed_payload(cmd_tshark, capture_file, 1)

    def test_smb311_chained_none_patternv1(self, cmd_tshark, capture_file):
        self.extract_chained_compressed_payload(cmd_tshark, capture_file, 2)

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_communityid(subprocesstest.SubprocessTestCase):
    # Show full diffs in case of divergence
    maxDiff = None

    def assertBaseline(self, dirs, output, baseline):
        baseline_file = os.path.join(dirs.baseline_dir, baseline)
        with open(baseline_file) as f:
            baseline_data = f.read()

        self.assertEqual(output, baseline_data)

    def test_communityid(self, cmd_tshark, features, dirs, capture_file):
        # Run tshark on our Community ID test pcap, enabling the
        # postdissector (it is disabled by default), and asking for
        # the Community ID value as field output. Verify that this
        # exits successfully:
        proc = self.assertRun(
            (cmd_tshark,
             '--enable-protocol', 'communityid',
             '-r', capture_file('communityid.pcap.gz'),
             '-Tfields', '-ecommunityid',
             ))

        self.assertBaseline(dirs, proc.stdout_str, 'communityid.txt')

    def test_communityid_filter(self, cmd_tshark, features, dirs, capture_file):
        # Run tshark on our Community ID test pcap, enabling the
        # postdissector and filtering the result.
        proc = self.assertRun(
            (cmd_tshark,
             '--enable-protocol', 'communityid',
             '-r', capture_file('communityid.pcap.gz'),
             '-Tfields', '-ecommunityid',
             'communityid=="1:d/FP5EW3wiY1vCndhwleRRKHowQ="'
             ))

        self.assertBaseline(dirs, proc.stdout_str, 'communityid-filtered.txt')
