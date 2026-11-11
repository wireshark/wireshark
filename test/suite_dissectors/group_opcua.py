#
# Wireshark tests
#
# Copyright 2026 by Michael Kirsche <michael.kirsche@codewerk.de>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''OPC UA tests'''

import subprocess

import pytest

# A single MSG chunk (no HEL/ACK/OPN, so SecurityMode None) with a
# ReadResponse (i=634). Its one result is a DataValue with an
# ExtensionObject of TypeId ns=1;i=886 (i=886 is the encoding ID of
# Range in namespace 0) and a 16-byte body (the Doubles 1.0 and 2.0).
# Converted with text2pcap -T 1234,4840.
READ_RESPONSE = '''\
000000 4d 53 47 46 57 00 00 00 01 00 00 00 01 00 00 00
000010 01 00 00 00 01 00 00 00 01 00 7a 02 00 00 00 00
000020 00 00 00 00 01 00 00 00 00 00 00 00 00 ff ff ff
000030 ff 00 00 00 01 00 00 00 01 16 01 01 76 03 01 10
000040 00 00 00 00 00 00 00 00 00 f0 3f 00 00 00 00 00
000050 00 00 40 ff ff ff ff
'''


def read_response(type_id):
    '''READ_RESPONSE with another TypeId (NodeId bytes) of the ExtensionObject.'''
    data = bytearray.fromhex(''.join(line[7:] for line in READ_RESPONSE.splitlines()))
    data[0x3a:0x3e] = type_id
    data[4:8] = len(data).to_bytes(4, 'little')  # MessageSize
    return ''.join(f'{offset:06x} {data[offset:offset + 16].hex(" ")}\n' for offset in range(0, len(data), 16))


# UADP NetworkMessages with one DataSetMessage (key frame of Variants),
# converted with text2pcap -u 1234,4840. The types are those of
# test/captures/opcua-infomodel.xml.

# An ExtensionObject ns=1;i=5001 (Shape: Id 7, Name "tri", Points
# [(1, 2), (3, -4)], Colors [Green, Red], Tag ca fe, no Scale), then the
# Int32 42.
UADP_ARRAYS = '''\
000000 f1 01 00 00 01 00 00 01 00 00 01 02 00 16 01 01
000010 89 13 01 35 00 00 00 02 00 00 00 07 00 00 00 03
000020 00 00 00 74 72 69 02 00 00 00 01 00 00 00 02 00
000030 00 00 03 00 00 00 fc ff ff ff 02 00 00 00 01 00
000040 00 00 00 00 00 00 02 00 00 00 ca fe 06 2a 00 00
000050 00
'''

# Two ExtensionObjects ns=1;i=5001 whose bodies do not match Shape: 12
# bytes (the Name runs past the body) and 22 bytes (2 more than needed),
# then the Int32 42.
UADP_MISMATCH = '''\
000000 f1 01 00 00 01 00 00 01 00 00 01 03 00 16 01 01
000010 89 13 01 0c 00 00 00 02 00 00 00 07 00 00 00 10
000020 00 00 00 16 01 01 89 13 01 16 00 00 00 00 00 00
000030 00 01 00 00 00 ff ff ff ff 00 00 00 00 ff ff ff
000040 ff ab ab 06 2a 00 00 00
'''

# An ExtensionObject ns=1;i=5002 (Outer: Inner, whose field Sub allows
# subtypes, then After), then the Int32 42.
UADP_STOP = '''\
000000 f1 01 00 00 01 00 00 01 00 00 01 02 00 16 01 01
000010 8a 13 01 08 00 00 00 01 00 00 00 02 00 00 00 06
000020 2a 00 00 00
'''


@pytest.fixture
def dissect_infomodel(cmd_text2pcap, cmd_tshark, capture_file, result_file, base_env, test_env, features):
    '''Convert a hexdump with text2pcap (-T or -u 1234,4840), dissect it
    with the information model test/captures/opcua-infomodel.xml (and
    further preferences, -o) and return the given fields (-Tfields).'''
    if not features.have_plugins:
        pytest.skip('Test requires binary plugin support.')

    def dissect(hexdump, text2pcap_transport, *fields, prefs=()):
        testin_file = result_file('opcua-infomodel.txt')
        testout_file = result_file('opcua-infomodel.pcap')
        with open(testin_file, 'w') as f:
            f.write(hexdump)
        subprocess.check_call((cmd_text2pcap, text2pcap_transport, '1234,4840', testin_file, testout_file), env=base_env)
        args = [cmd_tshark,
                '-o', 'opcua.information_model:' + capture_file('opcua-infomodel.xml'),
                '-r', testout_file,
                '-Tfields']
        for pref in prefs:
            args += ['-o', pref]
        for field in fields:
            args += ['-e', field]
        return subprocess.check_output(args, encoding='utf-8', env=test_env)
    return dissect


class TestDissectOpcua:

    def test_opcua_extension_object_not_ns0(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env, features):
        '''An ExtensionObject whose TypeId is outside namespace 0 is not
        decoded with the built-in parser of the same numeric ID.

        The ExtensionObject ns=1;i=886 of READ_RESPONSE must be shown as
        ByteString, not as Range (Low 1, High 2).'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        testin_file = result_file('opcua-extobj-ns1.txt')
        testout_file = result_file('opcua-extobj-ns1.pcap')
        with open(testin_file, 'w') as f:
            f.write(READ_RESPONSE)
        subprocess.check_call((cmd_text2pcap, '-T', '1234,4840', testin_file, testout_file), env=base_env)

        stdout = subprocess.check_output((cmd_tshark,
                '-r', testout_file,
                '-Tfields',
                '-eopcua.ByteString',
                '-eopcua.Low',
            ), encoding='utf-8', env=test_env)
        assert stdout == '000000000000f03f0000000000000040\t\n'

    def test_opcua_infomodel_client_server(self, dissect_infomodel):
        '''With the information model, the ExtensionObject ns=1;i=886 of
        READ_RESPONSE (client/server) is decoded as the custom datatype Pair
        (A 1, B 2), not as ByteString or Range.'''
        stdout = dissect_infomodel(READ_RESPONSE, '-T',
                'opcua.custom_field.Pair.A',
                'opcua.custom_field.Pair.B',
                'opcua.ByteString',
                'opcua.Low')
        assert stdout == '1\t2\t\t\n'

    def test_opcua_infomodel_arrays(self, dissect_infomodel):
        '''Custom datatypes in a PubSub DataSetMessage: structure fields,
        an array of a structure, an array of an enumeration (Int32 1, 0)
        and optional fields; the Int32 42 after the body.'''
        stdout = dissect_infomodel(UADP_ARRAYS, '-u',
                'opcua.custom_field.Shape.Id',
                'opcua.custom_field.Shape.Name',
                'opcua.custom_field.Point.X',
                'opcua.custom_field.Point.Y',
                'opcua.custom_field.Shape.Scale',
                'opcua.custom_field.Shape.Tag',
                'opcua.Int32')
        assert stdout == '7\ttri\t1,3\t2,-4\t\tcafe\t1,0,42\n'

    def test_opcua_infomodel_mismatch(self, dissect_infomodel):
        '''A body that does not match its type is contained: the too short
        one ends in an exception, the too long one in an expert info, and
        the Int32 42 after them is still decoded.'''
        stdout = dissect_infomodel(UADP_MISMATCH, '-u',
                'opcua.custom_field.Shape.Id',
                'opcua.Int32',
                '_ws.expert.message')
        assert stdout == '7,1\t42\tMalformed Packet (Exception occurred),' \
                '2 bytes of the body not dissected, check the information model\n'

    def test_opcua_infomodel_stop(self, dissect_infomodel):
        '''After a field that cannot be decoded (AllowSubTypes), the rest
        of the body cannot be located: Outer.After is not shown, the Int32
        42 after the body is.'''
        stdout = dissect_infomodel(UADP_STOP, '-u',
                'opcua.custom_field.Outer.After',
                'opcua.Int32',
                '_ws.expert.message')
        assert stdout == '\t42\tField Sub: AllowSubTypes not yet implemented\n'

    def test_opcua_infomodel_union_field(self, dissect_infomodel):
        '''A union (not decoded yet) as a structure field stops the body:
        READ_RESPONSE with the TypeId ns=1;i=5003 (Holder: the union Choice,
        then After). After is not read from the union's bytes.'''
        stdout = dissect_infomodel(read_response(bytes.fromhex('01018b13')), '-T',
                'opcua.custom_field.Holder.After',
                '_ws.expert.message')
        assert stdout == '\tCustom type Choice: unions and types with an unknown parent not yet implemented\n'

    def test_opcua_infomodel_ns_offset(self, dissect_infomodel):
        '''opcua.ns_offset is added to the namespace indexes of the model:
        READ_RESPONSE with the TypeId ns=3;i=886 is Pair (ns=1 in the model)
        with the offset 2.'''
        stdout = dissect_infomodel(read_response(bytes.fromhex('01037603')), '-T',
                'opcua.custom_field.Pair.A',
                'opcua.custom_field.Pair.B',
                prefs=('opcua.ns_offset:2',))
        assert stdout == '1\t2\n'

    def test_opcua_infomodel_string_typeid(self, dissect_infomodel):
        '''A string TypeId matches an encoding with a string NodeId:
        READ_RESPONSE with the TypeId ns=1;s=Pair is Pair.'''
        stdout = dissect_infomodel(read_response(bytes.fromhex('0301000400000050616972')), '-T',
                'opcua.custom_field.Pair.A',
                'opcua.custom_field.Pair.B')
        assert stdout == '1\t2\n'

    def test_opcua_infomodel_field_names(self, cmd_tshark, capture_file, test_env, features):
        '''The information model loads with any field names: the non-ASCII
        field of Weather gets a placeholder abbreviation, and the fields
        a-b (String) and a_b (UInt32) of Clash get different abbreviations,
        as they have different types.'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'opcua.information_model:' + capture_file('opcua-infomodel.xml'),
                '-G', 'fields',
            ), encoding='utf-8', env=test_env)
        assert '\t温度\topcua.custom_field.Weather.field0\tFT_DOUBLE\t' in stdout
        assert '\ta-b\topcua.custom_field.Clash.a_b\tFT_STRING\t' in stdout
        assert '\ta_b\topcua.custom_field.Clash.a_b_2\tFT_UINT32\t' in stdout

    def test_opcua_abort_message(self, cmd_tshark, capture_file, test_env, features):
        '''An Abort chunk (MSG, chunk type A) has its Error and Reason after
        the sequence header, and the message header is shown once.

        test/captures/opcua-abort-message.pcapng (TCP port 48020) has two
        Abort messages with the Error BadResponseTooLarge (0x80b90000).'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'opcua.tcp.port:48020',
                '-r', capture_file('opcua-abort-message.pcapng'),
                '-Y', 'opcua.transport.chunk == "A"',
                '-Tfields',
                '-eopcua.transport.scid',
                '-eopcua.transport.error',
            ), encoding='utf-8', env=test_env)
        assert stdout == '3510954351\t0x80b90000\n3510954352\t0x80b90000\n'


class TestOpcuaEnhancedSecurity:
    '''Tests for OPC UA ECC / AEAD Enhanced Security Profiles and unencrypted
    OpenSecureChannel (OPN) dissection.'''

    @pytest.mark.parametrize('pcap_name', (
        'opcua_none.pcapng',
        'opcua_brainp384_aesgcm.pcapng',
        'opcua_brainp384_chachapoly.pcapng',
        'opcua_nistp384_aesgcm.pcapng',
        'opcua_nistp384_chachapoly.pcapng',
        'opcua_rsa_dh_aesgcm.pcapng',
        'opcua_rsa_dh_chachapoly.pcapng',
        'opcua_rsa_legacy.pcapng',
    ))
    def test_opcua_opn_security_mode_none_unencrypted(self, cmd_tshark, capture_file, test_env, features, pcap_name):
        '''Verify that OpenSecureChannel (OPN) messages with SecurityPolicy#None
        are parsed as unencrypted and report MessageSecurityMode None (0x00000001).'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        pcap_path = capture_file(pcap_name)

        stdout = subprocess.check_output((
            cmd_tshark,
            '-o', 'opcua.tcp.port:48030',
            '-r', pcap_path,
            '-Y', 'opcua.transport.type == "OPN" && opcua.security.spu == "http://opcfoundation.org/UA/SecurityPolicy#None"',
            '-Tfields',
            '-e', 'opcua.transport.type',
            '-e', 'opcua.servicenodeid.numeric',
            '-e', 'opcua.MessageSecurityMode',
            '-e', '_ws.col.Info',
        ), encoding='utf-8', env=test_env)

        rows = [line.split('\t') for line in stdout.splitlines() if line.strip()]
        assert len(rows) >= 2
        # OpenSecureChannelRequest (NodeId 446) has MessageSecurityMode == None (0x00000001)
        req_rows = [r for r in rows if r[1] == '446']
        resp_rows = [r for r in rows if r[1] == '449']
        assert len(req_rows) >= 1
        assert len(resp_rows) >= 1
        for r in req_rows:
            assert r[0] == 'OPN'
            assert int(r[2], 16) == 1  # MessageSecurityMode: None (1)
            assert '(encrypted)' not in r[3]
        for r in resp_rows:
            assert r[0] == 'OPN'
            assert '(encrypted)' not in r[3]

    @pytest.mark.parametrize('pcap_name,policy_fragment,scid', (
        ('opcua_brainp384_aesgcm.pcapng', 'ECC_brainpoolP384r1_AesGcm', '2910720'),
        ('opcua_brainp384_chachapoly.pcapng', 'ECC_brainpoolP384r1_ChaChaPoly', '2910723'),
        ('opcua_nistp384_aesgcm.pcapng', 'ECC_nistP384_AesGcm', '2910707'),
        ('opcua_nistp384_chachapoly.pcapng', 'ECC_nistP384_ChaChaPoly', '2910714'),
        ('opcua_rsa_dh_aesgcm.pcapng', 'RSA_DH_AesGcm', '2910701'),
        ('opcua_rsa_dh_chachapoly.pcapng', 'RSA_DH_ChaChaPoly', '2910704'),
    ))
    def test_opcua_ecc_aead_opn_unencrypted_and_msg_decryption(
            self, cmd_tshark, capture_file, key_file, test_env, features, pcap_name, policy_fragment, scid):
        '''Verify that for ECC / AEAD Enhanced Security Profiles:
        1. OpenSecureChannel (OPN) messages are dissected as unencrypted (ServiceIds 446, 449).
        2. Subsequent symmetric OPC UA messages (MSG, CLO) are decrypted using opcuakeys.log
           and expose generic OPC UA service NodeIds without checking user-specific payloads.'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        pcap_path = capture_file(pcap_name)
        keylog_path = key_file('opcua_keys.log')

        # 1. Verify OPN messages for the ECC/AEAD policy are parsed unencrypted
        opn_stdout = subprocess.check_output((
            cmd_tshark,
            '-o', 'opcua.tcp.port:48030',
            '-r', pcap_path,
            '-Y', f'opcua.transport.type == "OPN" && opcua.security.spu contains "{policy_fragment}"',
            '-Tfields',
            '-e', 'opcua.transport.type',
            '-e', 'opcua.servicenodeid.numeric',
            '-e', 'opcua.MessageSecurityMode',
            '-e', '_ws.col.Info',
        ), encoding='utf-8', env=test_env)

        opn_rows = [line.split('\t') for line in opn_stdout.splitlines() if line.strip()]
        assert len(opn_rows) == 2
        # Request (446) and Response (449) must be decoded in plaintext
        assert opn_rows[0][0] == 'OPN' and opn_rows[0][1] == '446'
        assert int(opn_rows[0][2], 16) == 3  # MessageSecurityMode: SignAndEncrypt (3)
        assert '(encrypted)' not in opn_rows[0][3]
        assert opn_rows[1][0] == 'OPN' and opn_rows[1][1] == '449'
        assert '(encrypted)' not in opn_rows[1][3]

        # 2. Verify that without the keylog file, subsequent MSG packets remain encrypted
        enc_stdout = subprocess.check_output((
            cmd_tshark,
            '-o', 'opcua.tcp.port:48030',
            '-r', pcap_path,
            '-Y', f'opcua.transport.type == "MSG" && opcua.transport.scid == {scid}',
            '-Tfields',
            '-e', 'opcua.servicenodeid.numeric',
            '-e', '_ws.col.Info',
        ), encoding='utf-8', env=test_env)
        enc_rows = [line.split('\t') for line in enc_stdout.splitlines() if line.strip()]
        assert len(enc_rows) > 0
        assert all(r[0] == '' and '(encrypted)' in r[1] for r in enc_rows)

        # 3. Verify that with opcuakeys.log configured via opcua.debug_file, subsequent
        # MSG and CLO packets are decrypted and expose generic service TypeIds.
        dec_stdout = subprocess.check_output((
            cmd_tshark,
            '-o', 'opcua.tcp.port:48030',
            '-o', f'opcua.debug_file:{keylog_path}',
            '-r', pcap_path,
            '-Y', f'(opcua.transport.type == "MSG" || opcua.transport.type == "CLO") && opcua.transport.scid == {scid}',
            '-Tfields',
            '-e', 'opcua.transport.type',
            '-e', 'opcua.servicenodeid.numeric',
            '-e', '_ws.col.Info',
        ), encoding='utf-8', env=test_env)

        dec_rows = [line.split('\t') for line in dec_stdout.splitlines() if line.strip()]
        assert len(dec_rows) > 0
        service_ids = {r[1] for r in dec_rows if r[1]}
        # Generic OPC UA Service NodeIds:
        # 461=CreateSessionRequest, 464=CreateSessionResponse,
        # 467=ActivateSessionRequest, 470=ActivateSessionResponse,
        # 631=ReadRequest, 634=ReadResponse,
        # 473=CloseSessionRequest, 476=CloseSessionResponse,
        # 452=CloseSecureChannelRequest
        expected_generic_ids = {'461', '464', '467', '470', '631', '634', '473', '476', '452'}
        assert expected_generic_ids.issubset(service_ids)
        assert all('(decrypted)' in r[2] for r in dec_rows)

    def test_opcua_ecc_aead_chunked_reassembly_decryption(self, cmd_tshark, capture_file, key_file, test_env, features):
        '''Verify decryption and reassembly of multi-chunk AEAD messages using
        opcuakeys_BigMessage.log.'''
        if not features.have_plugins:
            pytest.skip('Test requires binary plugin support.')
        pcap_path = capture_file('opcua_big_message.pcapng')
        keylog_path = key_file('opcua_keys_big_message.log')

        stdout = subprocess.check_output((
            cmd_tshark,
            '-o', 'opcua.tcp.port:48030',
            '-o', f'opcua.debug_file:{keylog_path}',
            '-r', pcap_path,
            '-Y', 'opcua.transport.scid == 2910695 && opcua.servicenodeid.numeric == 829 && opcua.reassembled.length',
            '-Tfields',
            '-e', 'opcua.transport.type',
            '-e', 'opcua.transport.chunk',
            '-e', 'opcua.servicenodeid.numeric',
            '-e', '_ws.col.Info',
        ), encoding='utf-8', env=test_env)

        rows = [line.split('\t') for line in stdout.splitlines() if line.strip()]
        assert len(rows) == 1
        assert rows[0][0] == 'MSG'
        assert rows[0][1] == 'F'
        assert rows[0][2] == '829'  # PublishResponse
        assert '(Message Reassembled)' in rows[0][3]
        assert '(decrypted)' in rows[0][3]

