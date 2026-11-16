#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""MCTP over SMBus/I2C (packet-mctp-smbus.c) and I2C (packet-i2c.c) tests.

The captures come from tools/gen-mctp-smbus-test-capture.py, which holds the
frame maps.
"""

import os
import subprocess
from typing import ClassVar

import pytest
from dissection_helpers import column

CAPTURE = 'mctp-smbus.pcapng'
CAPTURES = (CAPTURE, 'mctp-smbus-ingress.pcapng', 'mctp-smbus-reassembly.pcapng')


def frames(table, first, last):
    """The rows of frames first..last: one section of a merged capture."""
    return {n: row for n, row in table.items() if first <= n <= last}


@pytest.mark.parametrize('capture', CAPTURES)
def test_no_dissector_exceptions(tshark_fields, capture):
    """Only F33's cut-short Table 25 list raises a tvb exception."""
    assert tshark_fields(capture, '_ws.dissector_bug').strip() == ''
    malformed = '33' if capture == CAPTURE else ''
    assert tshark_fields(capture, '_ws.malformed.expert').strip() == malformed


@pytest.mark.parametrize('capture', (*CAPTURES, 'i2c-transport-edge.pcapng'))
def test_second_pass_matches_first(assert_pass_parity, capture):
    assert_pass_parity(capture)


class TestMctpSmbusTransport:
    FIELDS = ('i2c', 'mctp.smbus', 'mctp.smbus.pec', 'mctp.smbus.pec.status',
              'mctp.smbus.pec_bad', 'mctp.physical_layer_drop',
              '_ws.col.info', '_ws.expert.message',
              'mctp.tag.value', 'mctp.tag.to', 'mctp.reassembled.length',
              'mctp.reassembled.data', 'mctp.fragment', 'nvme-mi')

    def test_fields(self, assert_frames_match):
        """DSP0237 6.3 Figure 1: the binding header and PEC location, while
        bad PEC or trailing bytes remain visible but cannot alter reassembly."""
        assert_frames_match(CAPTURE, [
            (1, ('mctp.smbus.dst_addr == 0x20 && mctp.smbus.rw == 0'
                 ' && mctp.smbus.command_code == 0x0f && mctp.smbus.byte_count == 8'
                 ' && mctp.smbus.src_addr == 0x40 && mctp.smbus.src_mctp_flag == 1'
                 ' && !mctp.smbus.pec && mctp.dst == 0x20 && mctp.src == 0x40')),
            (2, 'mctp.smbus.pec == 0x60'),
            (6, 'mctp.smbus && mctp.flags.som && mctp.flags.eom == 0'),
            (7, ('mctp.smbus && mctp.flags.som == 0 && mctp.flags.eom'
                 ' && mctp.smbus.pec == 0xfe && mctp.smbus.pec.status == 1'
                 ' && nvme-mi.mi.opcode == 0x01')),
            (8, 'mctp.smbus && nvme-mi.ror == 1 && nvme-mi.response_to'),
            (9, ('mctp.smbus && mctp.smbus.length_mismatch && mctp.dst == 0x20'
                 ' && mctp.smbus.pec == 0x60 && mctp.smbus.pec.status == 1'
                 ' && mctp.physical_layer_drop')),
            (10, '!mctp.smbus && i2c'),
            (15, ('mctpc.command == 0x0a && mctpc.get_routing.handle == 0x00'
                  ' && !_ws.malformed')),
            (16, 'mctp.dst == 0x20'),
            # The SMBus R/W# bit, not the capture metadata, gives the direction.
            (19, 'i2c.flags.rd == 1 && mctp.smbus.rw == 0 && mctp && mctpc'),
        ])

    def test_tag_owner_and_message_tag_summary(self, dissect_pdml, cmd_tshark,
                                              capture_file, test_env):
        output = subprocess.check_output(
            (cmd_tshark, '-r', capture_file(CAPTURE), '-Y',
             'frame.number == 1', '-V'),
            encoding='utf-8', env=test_env)
        assert 'Flags SOM|EOM, seq 0, tag 0, TO 1' in output
        pdml = dissect_pdml(CAPTURE)
        tag = pdml.field(1, 'mctp.tag')
        assert 'Tag Owner and Message Tag:' in tag['showname']

    def test_detection_and_pec_census(self, fields_table):
        """The heuristic claims only valid frames; only F16's PEC is bad,
        while F9 is excluded from assembly for its trailing bytes."""
        t = frames(fields_table(CAPTURE, self.FIELDS), 1, 19)
        assert list(column(t, 'i2c')) == list(range(1, 20))
        assert list(column(t, 'mctp.smbus')) == [1, 2, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 19]
        # 1 is Good, 0 Bad (3, Not present, on the frames without a PEC).
        assert {n: v for n, v in column(t, 'mctp.smbus.pec.status').items()
                if v in ('0', '1')} == {2: '1', 7: '1', 9: '1', 16: '0'}
        assert t[16]['mctp.smbus.pec'] == '0x9f'
        assert list(column(t, 'mctp.smbus.pec_bad')) == [16]
        assert list(column(t, 'mctp.physical_layer_drop')) == [9, 16]
        assert '2 extra trailing bytes' in t[9]['_ws.expert.message']
        assert t[1]['_ws.col.info'].startswith('[0x40->0x20]')
        assert t[8]['_ws.col.info'].startswith('[0x20->0x40]')
        assert t[15]['_ws.col.info'] == '[0x40->0x20] MCTP Get Routing Table Entries Request'
        assert [t[n]['_ws.col.info'] for n in (9, 16)] == [
            '[0x40->0x20] MCTP message dropped by physical-layer validation'] * 2

    def test_tag_owner_separates_concurrent_messages(self, fields_table):
        """DSP0236 Table 1: the tag is tracked per Tag Owner value, so F11-F14
        (tag 2, TO 0/1/0/1) reassemble as two messages of their own."""
        t = fields_table(CAPTURE, self.FIELDS)
        assert [(t[n]['mctp.tag.value'], t[n]['mctp.tag.to']) for n in range(11, 15)] == [
            ('0x02', 'False'), ('0x02', 'True'), ('0x02', 'False'), ('0x02', 'True')]
        assert [(t[n]['mctp.reassembled.length'], t[n]['mctp.reassembled.data'],
                 t[n]['mctp.fragment']) for n in (13, 14)] == [
            ('8', '04 88 00 00 00 a1 a2 a3', '11,13'),
            ('12', '04 88 00 00 00 b1 b2 b3 b4 b5 b6 b7', '12,14')]
        assert [n for n in column(t, 'nvme-mi') if 11 <= n <= 19] == [13, 14]

    @pytest.mark.parametrize('forced', [False, True])
    def test_expert_reachability(self, cmd_tshark, capture_file, test_env, forced):
        """A heuristic refusal is silent; Decode As diagnoses the same frames
        (F3/F4 signature, F17/F18 byte count, F37 short record; F10, cut by
        the snaplen, stays unclaimed), while F9's
        padding and F16's PEC are diagnosed either way."""
        fields = ('frame.number', 'mctp.smbus', 'mctp.smbus.malformed',
                  'mctp.smbus.length_mismatch', 'mctp.smbus.pec_bad',
                  'mctp', '_ws.malformed.expert', '_ws.expert.message')
        args = [cmd_tshark, '-r', capture_file(CAPTURE)]
        if forced:
            args += ['-d', 'i2c.message,mctp.smbus']
        args += ['-Y', 'frame.number in {3,4,9,10,16,17,18,37}',
                 '-Tfields', '-E', 'separator=|']
        for field in fields:
            args += ['-e', field]
        rows = {
            int(parts[0]): parts[1:] for line in subprocess.check_output(
                args, encoding='utf-8', env=test_env).splitlines()
            if (parts := line.split('|'))
        }
        assert set(rows) == {3, 4, 9, 10, 16, 17, 18, 37}
        # SMBus present, malformed, length mismatch, PEC bad, MCTP, exception.
        expected = {
            3: (forced, forced, False, False, False, False),
            4: (forced, forced, False, False, False, False),
            9: (True, False, True, False, True, False),
            10: (False, False, False, False, False, False),
            16: (True, False, False, True, True, False),
            17: (forced, forced, False, False, False, False),
            18: (forced, False, forced, False, False, False),
            # F37 is a whole 7-byte record, not a snaplen cut like F10.
            37: (forced, forced, False, False, False, False),
        }
        for frame, values in expected.items():
            assert tuple(bool(v) for v in rows[frame][:6]) == values, frame
        if forced:
            assert 'Byte count 4 is below minimum 5' in rows[17][6]
            assert 'Byte count 9 implies frame length >= 12' in rows[18][6]
            assert 'Frame length 7 is below the minimum 8' in rows[37][6]
        else:
            assert all(not rows[frame][6] for frame in (3, 4, 10, 17, 18, 37))

    def test_physical_address_summary(self, dissect_pdml):
        packet = dissect_pdml('mctp-smbus-ingress.pcapng')[1]
        node = packet.find(".//proto[@name='mctp.smbus']")
        assert node.get('showname').endswith(
            'Src: 0x10, Dst: 0x3a (7-bit physical addresses)')

    # fields_table also reads the Protocol and Info columns.
    NET_COLUMNS: ClassVar = {'gui.column.format': '"Protocol","%p","Info","%i","NS","%ns",'
                                        '"ND","%nd","S","%s","D","%d"'}

    def test_net_columns_show_slave_addresses(self, fields_table):
        """DSP0237 Table 1: the Net columns hold 7-bit slave addresses in hex,
        the Src/Dst columns the EIDs in decimal."""
        t = fields_table(CAPTURE, ('_ws.col.def_net_src', '_ws.col.def_net_dst',
                                   '_ws.col.def_src', '_ws.col.def_dst'),
                         prefs=self.NET_COLUMNS)
        assert (t[1]['_ws.col.def_net_src'], t[1]['_ws.col.def_net_dst']) == ('0x40', '0x20')
        assert (t[1]['_ws.col.def_src'], t[1]['_ws.col.def_dst']) == ('64', '32')

    def test_net_column_generated_filter(self, fields_table, field_registry,
                                         tshark_fields, dirs):
        """Apply as Filter on a Net column joins the address type's column
        filter field and the column text as "<field> == <text>"
        (ui/qt/packet_list.cpp); tshark cannot print that filter, so build it
        the same way and check it selects the frames showing that text."""
        # Mirrors mctp_smbus_addr_col_filter_str() in packet-mctp-smbus.c.
        col_filter = {'src': 'mctp.smbus.src_addr', 'dst': 'mctp.smbus.dst_addr'}
        source = os.path.join(dirs.tools_dir, '..', 'epan', 'dissectors',
                              'packet-mctp-smbus.c')
        if not os.path.exists(source):
            pytest.skip('packet-mctp-smbus.c is not available')
        with open(source, encoding='utf-8') as f:
            text = f.read()
        body = text[text.index('mctp_smbus_addr_col_filter_str('):]
        body = body[:body.index('}')]
        for abbrev in col_filter.values():
            assert f'"{abbrev}"' in body
            # Not a string field, so the filter is unquoted.
            assert field_registry[abbrev][3] == 'FT_UINT8'

        t = fields_table(CAPTURE, ('_ws.col.def_net_src', '_ws.col.def_net_dst'),
                         prefs=self.NET_COLUMNS)
        for side, col in (('src', '_ws.col.def_net_src'),
                          ('dst', '_ws.col.def_net_dst')):
            values = {row[col] for row in t.values() if row[col]}
            assert values
            for val in values:
                flt = f'{col_filter[side]} == {val}'
                got = {int(n) for n in tshark_fields(CAPTURE, flt).split()}
                want = {n for n, row in t.items() if row[col] == val}
                assert got == want, flt


class TestMctpSmbusIngressScope:
    """The reassembly scope keeps the I2C bus, pcapng section and interface apart."""

    def test_scope_isolates_assemblies(self, assert_frames_match):
        assert_frames_match('mctp-smbus-ingress.pcapng', [
            (21, 'mctp.assembly.orphan && !mctp.reassembled.length && !mctp.msg.type'),
            (22, 'mctp.assembly.orphan && !mctp.reassembled.length && !mctp.msg.type'),
            (23, 'mctp.flags.som == 1 && !mctp.assembly.restarted'),
            (24, 'mctp.reassembled.length == 3 && mctp.reassembled.data == 0a:dd:ee'),
            (25, ('frame.interface_id == 0 && i2c.bus == 0'
                  ' && mctp.flags.som == 1 && !mctp.assembly.restarted')),
            (26, ('frame.interface_id == 1 && i2c.bus == 0 && mctp.assembly.orphan'
                  ' && !mctp.reassembled.length && !mctp.msg.type')),
            (27, ('frame.interface_id == 0 && !mctp.assembly.orphan'
                  ' && mctp.reassembled.length == 3 && mctp.reassembled.data == 0a:a6:c8'
                  ' && mctp.fragment == 25 && mctp.fragment == 27')),
        ])


class TestMctpSmbusIngress:
    """SMBus heuristic, PEC status and declared-packet truncation (DSP0237 6.3)."""

    FILE = 'mctp-smbus-ingress.pcapng'
    DECODE_AS = ('-d', 'i2c.message,mctp.smbus')
    FIELDS = ('mctp.smbus', 'mctp', 'nvme-mi', 'mctp.smbus.pec.status',
              'mctp.reassembled.length', 'data.data',
              '_ws.col.protocol', '_ws.col.info')

    def test_claims_and_pec_status(self, fields_table, assert_frames_match):
        t = frames(fields_table(self.FILE, self.FIELDS), 1, 19)
        claimed = [1, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 17, 18, 19]
        assert list(column(t, 'mctp.smbus')) == claimed
        assert list(column(t, 'mctp')) == claimed
        assert list(column(t, 'nvme-mi')) == [1, 2, 5, 7, 8, 9, 10, 12, 13, 17, 19]
        status = column(t, 'mctp.smbus.pec.status')
        assert {v: [n for n in status if status[n] == v] for v in set(status.values())} == {
            '0': [3, 18], '1': [1, 2, 4, 5, 10, 12, 13, 17, 19], '2': [9], '3': [7, 8]}
        assert t[14]['_ws.col.protocol'].startswith('I2C Write')
        no_pec = ('mctp.smbus && !mctp.smbus.pec && mctp.smbus.pec.status == 3'
                  ' && !mctp.smbus.malformed && !mctp.smbus.length_mismatch'
                  ' && !mctp.smbus.pec_bad')
        assert_frames_match(self.FILE, [
            (7, no_pec), (8, no_pec),
            (9, 'mctp.smbus.pec.status == 2 && !mctp.smbus.pec && nvme-mi.mi.opcode == 0x01'),
            # The SMBus address/R/W# octet, not capture metadata, gives the direction.
            (12, 'i2c.flags.rd == 1 && mctp.smbus.rw == 0 && mctp && nvme-mi'),
            (13, 'mctp.smbus.byte_count == 25 && mctp && nvme-mi'),
            (14, 'i2c.addr == 0x3a && !mctp'),
        ])

    def test_decode_as_reports_what_the_heuristic_declines(self, cmd_tshark, capture_file,
                                                           test_env):
        """Forced onto F6 and F11, the binding renders the wrapper and hands
        the captured bytes to MCTP; the capture cut is left to the layers
        above.  F11's trailing octets are still reported."""
        out = subprocess.check_output(
            (cmd_tshark, '-r', capture_file(self.FILE)) + self.DECODE_AS + (
                '-Y', 'frame.number in {6, 11}', '-Tfields', '-E', 'separator=|',
                '-e', 'frame.number', '-e', 'mctp.smbus.byte_count',
                '-e', 'mctp.smbus.pec.status',
                '-e', 'mctp.smbus.length_mismatch', '-e', 'mctp.smbus.pec',
                '-e', 'mctp', '-e', '_ws.expert.message'),
            encoding='utf-8', env=test_env)
        rows = {int(r.split('|')[0]): r.split('|')[1:] for r in out.strip().splitlines()}
        assert rows[6][:4] == ['20', '3', '', ''] and rows[6][4]
        assert rows[11][:4] == ['25', '2', '1', ''] and rows[11][4]
        for text in ('frame length is 31', '2 extra trailing bytes'):
            assert text in rows[11][5], text

    def test_address_zero_names_depend_on_direction(self, dissect_pdml):
        pdml = dissect_pdml(self.FILE)
        assert pdml.field(15, 'i2c.addr')['showname'].endswith('0x00 (General Call)')
        assert pdml.field(16, 'i2c.addr')['showname'].endswith('0x00 (START byte)')


class TestMctpSmbusReassembly:
    FILE = 'mctp-smbus-reassembly.pcapng'
    FIELDS = ('mctp.smbus.pec_bad', 'mctp.physical_layer_drop',
              'mctp.assembly.restarted', 'mctp.assembly.seq_gap',
              'mctp.assembly.timeout',
              'mctp.reassembled.length', 'mctp.reassembled.data',
              'mctp.msg.type', 'mctpc', '_ws.expert.message')

    def test_bad_pec_does_not_mutate_reassembly(self, fields_table):
        t = fields_table(self.FILE, self.FIELDS)
        assert list(column(t, 'mctp.smbus.pec_bad')) == [2, 5, 9]
        assert list(column(t, 'mctp.physical_layer_drop')) == [2, 5, 9]
        assert t[4]['mctp.reassembled.length'] == '132'
        assert not t[6]['mctp.assembly.restarted']
        assert t[7]['mctp.reassembled.length'] == '68'
        assert t[9]['mctp.msg.type'] and not t[9]['mctpc']
        assert not t[9]['mctp.reassembled.length']
        assert t[10]['mctp.reassembled.length'] == '68'
        assert not t[16]['mctp.physical_layer_drop']
        assert t[17]['mctp.reassembled.length'] == '68'

    def test_bad_pec_preference_can_restore_legacy_assembly(self, fields_table):
        t = fields_table(self.FILE, self.FIELDS,
                         prefs={'mctp.smbus.drop_bad_pec': 'FALSE'})
        assert not column(t, 'mctp.physical_layer_drop')
        assert list(column(t, 'mctp.assembly.seq_gap')) == [3, 10]
        assert not t[4]['mctp.reassembled.length']
        assert t[6]['mctp.assembly.restarted']
        assert t[9]['mctp.assembly.restarted']
        assert t[7]['mctp.reassembled.length'] == '68'

    def test_timeout_diagnosis_and_optional_drop(self, fields_table):
        """Only capture timestamps are available, so the gap is reduced by
        the larger packet's worst-case bus time, 250 us per byte (DSP0237
        Table 8 PT1a/PT1b), before it is compared with DSP0237 Table 9's
        MT3a: F12's 119 ms gap leaves about 100.75 ms, F19's 118.25 ms
        exactly 100 ms, F21's 160 ms after a 254-byte packet about 95.25 ms
        and F22's 170 ms about 105.25 ms."""
        t = fields_table(self.FILE, self.FIELDS)
        assert sorted(t) == list(range(1, 23))
        assert list(column(t, 'mctp.assembly.timeout')) == [12, 14, 22]
        assert t[12]['mctp.reassembled.length'] == '68'
        assert ('Capture-timestamp gap of 119 ms (about 101 ms after an estimated'
                ' 19 ms of worst-case DSP0237 PT1a/PT1b bus time) exceeds the 100 ms'
                ' inter-packet limit (DSP0237 MT3a') in t[12]['_ws.expert.message']
        assert 'gap of 170 ms (about 106 ms after an estimated 65 ms' in \
            t[22]['_ws.expert.message']
        assert not t[21]['mctp.assembly.timeout']
        assert t[22]['mctp.reassembled.length'] == '504'
        assert t[14]['mctp.assembly.timeout']
        assert not t[14]['mctp.assembly.restarted']
        # DSP0236 8.9: the SOM's timeout belongs to the abandoned assembly.
        assert (
            'Previous message assembly on this terminus timed out and was dropped'
            ' (DSP0236 8.9): gap of 200 ms since frame 13, about 182 ms after an'
            ' estimated 19 ms of bus time, exceeds the 100 ms limit (DSP0237'
            ' MT3a)'
        ) in t[14]['_ws.expert.message']
        assert 'Previous message assembly' not in t[12]['_ws.expert.message']
        assert t[15]['mctp.reassembled.length'] == '68'
        two = fields_table(self.FILE, self.FIELDS, two_pass=True)
        assert two[14]['_ws.expert.message'] == t[14]['_ws.expert.message']
        assert not t[19]['mctp.assembly.timeout']
        assert t[19]['mctp.reassembled.length'] == '68'

        dropped = fields_table(
            self.FILE, self.FIELDS,
            prefs={'mctp.drop_timed_out_assembly': 'TRUE'})
        assert dropped[12]['mctp.assembly.timeout']
        assert not dropped[12]['mctp.reassembled.length']
        assert dropped[14]['mctp.assembly.timeout']
        assert not dropped[14]['mctp.assembly.restarted']
        assert dropped[15]['mctp.reassembled.length'] == '68'
        assert not dropped[19]['mctp.assembly.timeout']
        assert dropped[19]['mctp.reassembled.length'] == '68'
        assert list(column(dropped, 'mctp.assembly.timeout')) == [12, 14, 22]
        assert not dropped[21]['mctp.assembly.timeout']
        assert not dropped[22]['mctp.reassembled.length']


class TestMctpSmbusBodyException:
    """The [src->dst] prefix survives cut records and bodies that cannot finish."""

    FILE = CAPTURE
    FIELDS = ('mctp.smbus', 'nvme-mi', '_ws.col.info', '_ws.expert', '_ws.short',
              'mctp.smbus.pec.status')

    def test_claims_and_prefixes(self, fields_table):
        t = frames(fields_table(self.FILE, self.FIELDS), 20, 27)
        assert list(column(t, 'mctp.smbus')) == [20, 21, 24, 26, 27]
        assert list(column(t, 'nvme-mi')) == [20, 21, 24, 26, 27]
        for frame in (20, 24, 26):
            assert t[frame]['_ws.col.info'].startswith('[0x10->0x3a]'), frame
        for frame in (21, 27):
            assert t[frame]['_ws.col.info'].startswith('[0x3a->0x10]'), frame
        assert column(t, '_ws.short') == {}
        assert not any(t[n]['_ws.expert'] or t[n]['mctp.smbus'] for n in (22, 23, 25))
        assert (t[26]['mctp.smbus.pec.status'], t[27]['mctp.smbus.pec.status']) == ('1', '1')


class TestI2cTransportEdge:
    """I2C direction from the R/W# bit, the IPMB handoff and short records (packet-i2c.c)."""

    FILE = 'i2c-transport-edge.pcapng'
    FIELDS = ('_ws.col.info', '_ws.col.protocol', 'i2c.addr', 'i2c.flags',
              'ipmi.bus_command_data', 'i2c.record_too_short', '_ws.expert', '_ws.short',
              '_ws.malformed', '_ws.malformed.expert', 'ipmb')

    def test_records(self, fields_table, assert_frames_match):
        t = fields_table(self.FILE, self.FIELDS)
        assert sorted(t) == list(range(1, 14))
        assert [t[n]['_ws.col.info'] for n in (1, 2)] == [
            'I2C Write, 12 bytes', 'I2C Write, 13 bytes']
        assert [t[n]['ipmi.bus_command_data'] for n in (1, 2)] == [
            '20b828100001a1a2a309', '20b828100001b1b2b3b425']
        assert [(t[n]['_ws.col.protocol'], t[n]['i2c.addr']) for n in (5, 6)] == [
            ('I2C Write', '0x10'), ('I2C', '')]
        assert [n for n in column(t, 'ipmb') if n >= 5] == []
        assert [(t[n]['i2c.addr'], t[n]['i2c.flags']) for n in (7, 10)] == [
            ('', '0x00000000'), ('0x10', '0x00000000')]
        # The upper error bits qualify the offline event (bit 3), not detach.
        assert [t[n]['_ws.col.info'] for n in (8, 9)] == [
            'The I2C controller is non-operational: clock low timeout',
            'The I2C controller is detached from an I2C bus']
        # Short on the wire is diagnosed; cut by the snaplen is not.
        assert list(column(t, 'i2c.record_too_short')) == [5, 6, 7]
        assert list(column(t, '_ws.expert')) == [5, 6, 7]
        assert list(column(t, '_ws.malformed')) == [5, 6, 7]
        assert list(column(t, '_ws.malformed.expert')) == [5, 6]
        assert list(column(t, '_ws.short')) == [11, 12, 13]
        assert t[11]['_ws.col.info'] == '[Packet size limited during capture]'
        assert t[12]['_ws.col.protocol'] == 'I2C Write'
        assert t[12]['_ws.col.info'].startswith('I2C Write, 3 bytes')
        assert t[13]['_ws.col.info'].startswith('I2C Write, 0 bytes')
        for n in (12, 13):
            assert t[n]['_ws.col.info'].endswith('[Packet size limited during capture]'), n
        assert_frames_match(self.FILE, [
            (1, 'i2c.addr == 0x10'),
            (2, 'i2c.addr == 0x10'),
            (10, 'i2c.flags == 0x00000000 && i2c.flags.rd == 0'),
            (11, ('i2c && _ws.short && !i2c.addr && !i2c.record_too_short && !_ws.malformed'
                  ' && !_ws.expert && !ipmb')),
            (12, ('i2c.addr == 0x10 && _ws.short && !i2c.record_too_short && !_ws.malformed'
                  ' && !_ws.expert && !ipmb')),
            (13, ('i2c && _ws.short && !i2c.addr && i2c.flags == 0x00000000'
                  ' && i2c.flags.rd == 0 && !i2c.record_too_short && !_ws.malformed'
                  ' && !_ws.expert && !data')),
        ])

    def test_address_item(self, dissect_pdml, tshark_fields):
        pdml = dissect_pdml(self.FILE)
        assert pdml.field(3, 'i2c.addr')['showname'].endswith('0x00 (General Call)')
        assert pdml.field(4, 'i2c.addr')['showname'].endswith('0x00 (START byte)')
        for frame in (1, 2):
            assert pdml.field(frame, 'i2c.addr')['showname'].endswith('0x10'), frame
        # One octet at record offset 2, not the length and port octets too.
        assert (pdml.field(1, 'i2c.addr')['pos'], pdml.field(1, 'i2c.addr')['size']) == ('2', '1')
        assert tshark_fields(self.FILE, 'i2c.flags.rd == 1').split() == []


class TestMctpSmbusHeaderOnlyAndVersion:
    """F34-F36: a header-only End packet and a non-1 header version."""

    FILE = CAPTURE

    def test_header_only_end_packet_over_smbus(self, tshark_fields, assert_frames_match):
        """DSP0237 byte count 5 is the source address plus the transport
        header; the heuristic declines F36's non-1 header version."""
        assert tshark_fields(self.FILE, 'frame.number >= 34 && mctp.smbus').split() == [
            '34', '35']
        assert_frames_match(self.FILE, [
            (35, ('mctp.smbus.byte_count == 5 && mctp.smbus.pec.status == 1'
                 ' && !mctp.smbus.malformed && !mctp.too_short'
                 ' && mctp.reassembled.length == 64')),
        ])

    def test_forced_decode_hands_a_non_1_version_to_mctp(self, cmd_tshark,
                                                         capture_file,
                                                         test_env):
        """DSP0236 8.7 makes a bad header version a drop condition, and
        packet-mctp.c reports it as one; the SMBus wrapper is not malformed."""
        out = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(self.FILE),
             '-d', 'i2c.message,mctp.smbus', '-Y', 'frame.number == 36',
             '-Tfields', '-E', 'separator=|',
             '-e', 'mctp.smbus', '-e', 'mctp.smbus.malformed',
             '-e', 'mctp.version', '-e', 'mctp.version.unsupported',
             '-e', 'mctp.smbus.pec.status'],
            encoding='utf-8', env=test_env)
        smbus, malformed, version, unsupported, pec = \
            out.rstrip('\r\n').split('|')
        assert smbus and not malformed
        assert version == '2' and unsupported
        assert pec == '1'
