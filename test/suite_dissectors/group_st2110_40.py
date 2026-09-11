#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''SMPTE ST 2110-40 tests'''

import hashlib
import subprocess


DECODE_AS_ARGS = (
    # The captures contain RTP without signaling identifying it as RTP.
    '-d', 'udp.port==5000,rtp',
    '-d', 'udp.port==5010,rtp',
    '-d', 'udp.port==1234,rtp',
    '-d', 'udp.port==20000,rtp',

    # RTP payload type 100 is dynamic. The captures have no SDP identifying
    # PT 100 as ST 2110-40, so explicitly decode it.
    '-d', 'rtp.pt==100,st2110_40',
)


def _tshark_fields(cmd_tshark, capture, fields, env):
    return subprocess.check_output((
        cmd_tshark,
        '-r', capture,
        *DECODE_AS_ARGS,
        '-Y', 'st2110_40',
        '-T', 'fields',
        '-E', 'occurrence=a',
        '-E', 'aggregator=|',
        *(arg for field in fields for arg in ('-e', field)),
    ), encoding='utf-8', env=env)


def _byte_field_signatures(cmd_tshark, capture, field, env):
    stdout = _tshark_fields(
        cmd_tshark, capture, ('frame.number', field), env)
    signatures = []
    for line in stdout.splitlines():
        _frame, field_value = line.split('\t')
        values = field_value.split('|') if field_value else []
        signatures.append([
            (len(value_bytes), hashlib.sha256(value_bytes).hexdigest())
            for value in values
            for value_bytes in (bytes.fromhex(value),)
        ])
    return signatures


class TestSt2110_40:

    def test_st2110_40_decode_as(self, cmd_tshark, capture_file, test_env):
        fields = (
            'frame.number', 'rtp.p_type',
            'st2110_40.extendedsequencenumber', 'st2110_40.length',
            'st2110_40.anc_count', 'st2110_40.f', 'st2110_40.c',
            'st2110_40.line_number', 'st2110_40.ho', 'st2110_40.s',
            'st2110_40.streamnum', 'st291.did', 'st291.sdid', 'st291.dbn',
            'st2110_40.data_count', 'st2110_40.checksum',
            'st2110_40.checksum_calculated', 'st12_2.timecode',
            '_ws.expert.message',
        )
        stdout = _tshark_fields(
            cmd_tshark, capture_file('st2110-40.pcap.gz'), fields, test_env)

        # Cover all ST 2110-40 header and ANC packet fields in the capture,
        # along with the RTP payload type and decoded ST 12-2 timecodes. The
        # final empty column also verifies that no expert warnings are present.
        assert stdout == (
            '1\t100\t0x522e\t0\t0\t0x00\t\t\t\t\t\t\t\t\t\t\t\t\t\n'
            '2\t100\t0x3dda\t32\t1\t0x00\tFalse\t2047\t4095\tFalse\t0\t0x60\t0x60\t\t16\t0x01b8\t0x01b8\t16:16:10;12\t\n'
            '3\t100\t0xe7e0\t20\t1\t0x00\tFalse\t2047\t4095\tFalse\t0\t0x41\t0x05\t\t8\t0x0192\t0x0192\t\t\n'
            '4\t100\t0x0000\t64\t1\t0x00\tFalse\t9\t0\tFalse\t0\t0x61\t0x01\t\t43\t0x018d\t0x018d\t\t\n'
            '5\t100\t0x0000\t148\t3\t0x00\tFalse|False|False\t9|9|10\t1296|0|1296\tFalse|False|False\t0|0|0\t0x60|0x61|0x60\t0x60|0x01|0x60\t\t16|59|16\t0x0218|0x029d|0x0110\t0x0218|0x029d|0x0110\t01:04:33;23|01:04:33;23\t\n'
            '6\t100\t0x0000\t64\t1\t0x00\tFalse\t10\t0\tFalse\t0\t0x61\t0x01\t\t43\t0x028d\t0x028d\t\t\n'
            '7\t100\t0x0000\t216\t4\t0x02\tFalse|False|False|False\t9|9|10|12\t4094|4093|4094|4093\tFalse|False|False|False\t0|0|0|0\t0x60|0x53|0x60|0x43\t0x60|0x02|0x60|0x02\t\t16|46|16|58\t0x02c8|0x0190|0x01c0|0x027e\t0x02c8|0x0190|0x01c0|0x027e\t00:00:50:19|00:00:50:19\t\n'
        )

    def test_st2110_40_udw_payloads(self, cmd_tshark, capture_file, test_env):
        signatures = _byte_field_signatures(
            cmd_tshark, capture_file('st2110-40.pcap.gz'),
            'st2110_40.udw', test_env)

        # Lengths and hashes cover every UDW payload without embedding several
        # hundred characters of packed 10-bit data in the test source.
        assert signatures == [
            [],
            [(21, 'b597062ba2bdaacefd6c6cca71458940368dc20ca879ed347a3d320fa0a18bc5')],
            [(11, '05a5b3b1f0be8720c334f448c5617cfcc1e4c8fa91b1e8c897db5f7fbc9946ba')],
            [(55, '950bf1fe495a4a5a7e62a1f409cd0f3ff113d1955f814acd9ce0d74fc83aff8d')],
            [
                (21, '863cb2bd1cc7edcb7a7912210b0ce2b75c610810e3f9a3a54e495a828237c473'),
                (75, '0ed7f1f979731f0fb1ab0a21352312443ccac6fea87f30491349db74c6dda3c2'),
                (21, '89cfc163cb503b1d0a4cdd9d16e4ade065e4d8e446db5d4d5e96fede69a7e948'),
            ],
            [(55, 'f17e85e004dafd6d6d37a4ce43c8f8a6fbad69b04d1e650b274474b272ead254')],
            [
                (21, 'ca6003ecaa201339edbd0ddb8f360a67b3d8fea51996052cbe21a4e4783ba9e2'),
                (59, '234c2e6d1e87fbe35b1a2d61c5c0f1d6294f6e6bbef3d1ababfdcfb829ffc1a0'),
                (21, '74db342f09bf82c7812548f64974ec774184cfc68b95528eb08e55dca9f6de28'),
                (74, '75b7cc8817dc91528cbdf279a48e29e817d16248be8a68b4a17dbe6a343f720e'),
            ],
        ]

    def test_st2110_40_malformed(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('st2110-40-malformed.pcap.gz')

        fields = (
            'frame.number', 'st2110_40.extendedsequencenumber',
            'st2110_40.length', 'st2110_40.anc_count', 'st2110_40.f',
            'st2110_40.c', 'st2110_40.line_number', 'st2110_40.ho',
            'st2110_40.s', 'st2110_40.streamnum', 'st291.did', 'st291.sdid',
            'st291.dbn', 'st2110_40.data_count', 'st2110_40.udw',
            'st2110_40.udw_array', 'st2110_40.checksum',
            'st2110_40.checksum_calculated',
        )
        stdout = _tshark_fields(cmd_tshark, capture, fields, test_env)
        rows = stdout.splitlines()

        # Valid empty, Type 1, and Type 2 packets cover modes absent from the
        # public capture. The last packet preserves the distinction between
        # the packed 10-bit source bytes and the legacy eight-bit UDW array.
        assert rows[0] == '1\t0x0001\t0\t0\t0x00\t\t\t\t\t\t\t\t\t\t\t\t\t'
        assert rows[5] == (
            '6\t0x0006\t12\t1\t0x02\tTrue\t12\t345\tTrue\t7\t0x80\t\t0x34\t0\t'
            '\t<MISSING>\t0x02b4\t0x02b4'
        )
        assert rows[11] == (
            '12\t0x000c\t12\t1\t0x00\tFalse\t9\t0\tFalse\t0\t0x50\t0x01\t\t1\t'
            '06ab\tab\t0x02fd\t0x02fd'
        )

        expert_fields = (
            'frame.number', 'st2110_40.checksum.bad',
            'st2110_40.length.bad', 'st2110_40.truncated',
            'st2110_40.reserved.nonzero', 'st2110_40.field.invalid',
            'st2110_40.st291_parity_bad', 'st2110_40.word_align.nonzero',
            'st2110_40.st291_sdid_reserved', '_ws.expert.message',
        )
        stdout = _tshark_fields(cmd_tshark, capture, expert_fields, test_env)

        # Exercise every expert field registered by the dissector and verify
        # the warning is attached only to its intended malformed packet.
        assert stdout == (
            '1\t\t\t\t\t\t\t\t\t\n'
            '2\t\t\t\t1\t1\t\t\t\tF field value 1 is invalid|The 22 reserved RTP payload-header bits are non-zero (0x1)\n'
            '3\t\t1\t1\t\t\t\t\t\tANC_Count is 1, but Length is zero|Truncated ST 2110-40 ANC packet\n'
            '4\t\t1|1\t\t\t\t\t\t\tANC_Count is zero, but Length is 4 (RFC 8331 requires Length=0)|Length is 4 bytes, but ANC_Count=0 accounts for 0 bytes\n'
            '5\t\t1|1\t\t\t\t\t\t\tST 2110-40 payload claims 20 bytes, but only 8 were captured|ANC_Count is zero, but Length is 12 (RFC 8331 requires Length=0)\n'
            '6\t\t\t\t\t\t\t\t\t\n'
            '7\t\t\t\t\t\t1\t\t\tInvalid ST 291 DID parity (raw word 0x350)\n'
            '8\t1\t\t\t\t\t\t\t\tThe calculated ANC checksum and ANC checksum word do not match\n'
            '9\t\t\t\t\t\t\t1\t\t24 word_align bits must be zero\n'
            '10\t\t\t\t\t\t\t\t1\tSDID 0x00 is reserved for Type 2 ANC packets\n'
            '11\t\t1\t1\t\t\t\t\t\tANC packet 1 extends past the RFC 8331 Length boundary|Length is 8 bytes, but ANC_Count=1 accounts for 0 bytes\n'
            '12\t\t\t\t\t\t\t\t\t\n'
        )
