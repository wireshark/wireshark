#
# Wireshark BGP SR Policy dissector tests
#
# Raw BGP UPDATE message bytes extracted from a real BGP SR Policy capture:
#   tshark -r bgp.pcap -Tfields -e tcp.payload (frame 31)
# Split on 16-byte BGP markers into individual messages.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''BGP SR Policy dissector tests (Tunnel Encapsulation Attribute, Type 23)'''

import subprocess


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

import struct


def _bgp_fields(cmd_tshark, cmd_text2pcap, pcap_path, txt_path, msg_bytes, fields, env):
    '''Write raw BGP message bytes to a pcap via text2pcap and extract field
    values with tshark.  msg_bytes must be a complete BGP message (including
    the 16-byte marker).  Returns tshark -Tfields output stripped of newline.
    Multiple -e fields are tab-separated in the output.'''
    # text2pcap hex input: 16 bytes per line with hex offsets
    with open(txt_path, 'w') as f:
        for i in range(0, len(msg_bytes), 16):
            chunk = msg_bytes[i:i + 16]
            f.write('{:06x}  {}\n'.format(i, ' '.join(f'{b:02x}' for b in chunk)))

    subprocess.check_call(
        [cmd_text2pcap, '-T', '179,179', txt_path, pcap_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    args = [cmd_tshark, '-r', pcap_path, '-Tfields']
    for field in fields:
        args += ['-e', field]
    return subprocess.check_output(args, encoding='utf-8', env=env).strip()


def _make_bgp_update(seg_type, seg_data):
    '''Build a minimal but valid BGP UPDATE containing a single Segment List
    sub-TLV with one segment of the given type and data bytes.

    Sub-TLV header rules (from RFC 9012 / packet-bgp.c):
      type < 128  → 1-byte length field
      type >= 128 → 2-byte length field  (Segment List is type 128 = 0x80)

    The NLRI uses Distinguisher=0, Color=100, Endpoint=10.1.1.1.
    The next hop is 192.0.2.1.
    '''
    # Inner segment sub-TLV: type(1) + length(1) + data
    seg_subtlv   = bytes([seg_type, len(seg_data)]) + seg_data
    # Segment List (type=128): type(1) + length(2 bytes) + reserved(1) + subtlv
    seg_list_val = bytes([0x00]) + seg_subtlv
    seg_list     = bytes([0x80]) + len(seg_list_val).to_bytes(2, 'big') + seg_list_val
    # SR Policy TLV: type(2) + length(2) + value
    sr_policy    = bytes([0x00, 0x0F]) + len(seg_list).to_bytes(2, 'big') + seg_list
    # TUNNEL_ENCAP attr: flags=0xC0 (no ext-len) → 1-byte length
    tunnel       = bytes([0xC0, 0x17, len(sr_policy)]) + sr_policy
    # MP_REACH_NLRI: AFI=1, SAFI=73, nexthop=192.0.2.1, NLRI distg=0 color=100 ep=10.1.1.1
    nlri_val     = bytes([0x00, 0x01, 0x49, 0x04, 0xC0, 0x00, 0x02, 0x01, 0x00,
                          0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
                          0x0A, 0x01, 0x01, 0x01])
    mp_reach     = bytes([0x80, 0x0E, len(nlri_val)]) + nlri_val
    origin       = bytes([0x40, 0x01, 0x01, 0x00])
    aspath       = bytes([0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xEA])
    path_attrs   = origin + aspath + tunnel + mp_reach
    body         = bytes([0x00, 0x00]) + len(path_attrs).to_bytes(2, 'big') + path_attrs
    total_len    = 19 + len(body)
    return bytes([0xFF] * 16) + total_len.to_bytes(2, 'big') + bytes([0x02]) + body


# ---------------------------------------------------------------------------
# Raw BGP message bytes (from bgp.pcap frame 31, split per BGP message)
# ---------------------------------------------------------------------------

# UPDATE 1 – MPLS-based SR Policy
#   NLRI      : Distinguisher=0, Color=100, Endpoint=10.1.1.1
#   sub-TLVs  : Preference(100), MPLS Binding SID(label=24000)
#   Seg. List : Weight(flags=0,val=1), Type-A MPLS(16001), Type-A MPLS(16002)
_MSG1_MPLS = bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x70, 0x02, 0x00, 0x00, 0x00, 0x59, 0x40,
    0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
    0x00, 0x00, 0xfd, 0xea, 0xc0, 0x17, 0x30, 0x00,
    0x0f, 0x00, 0x2c, 0x0c, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x64, 0x0d, 0x06, 0x10, 0x00, 0x05,
    0xdc, 0x01, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x06, 0x00, 0x00, 0x03, 0xe8, 0x11, 0x00, 0x01,
    0x06, 0x00, 0x00, 0x03, 0xe8, 0x21, 0x00, 0x80,
    0x0e, 0x16, 0x00, 0x01, 0x49, 0x04, 0xc0, 0x00,
    0x02, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x64, 0x0a, 0x01, 0x01, 0x01,
])

# UPDATE 2 – SRv6-based SR Policy
#   NLRI      : Distinguisher=0, Color=200, Endpoint=10.2.2.2
#   sub-TLVs  : Preference(100), SRv6 Binding SID(fc00::100)
#   Seg. List : Weight(1), Type-B SRv6(fc00::1), Type-B SRv6(fc00::2)
_MSG2_SRV6 = bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x94, 0x02, 0x00, 0x00, 0x00, 0x7d, 0x40,
    0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
    0x00, 0x00, 0xfd, 0xea, 0xc0, 0x17, 0x54, 0x00,
    0x0f, 0x00, 0x50, 0x0c, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x64, 0x14, 0x12, 0x00, 0x00, 0xfc,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80,
    0x00, 0x31, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x0d, 0x12, 0x00, 0x00, 0xfc,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0d,
    0x12, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x80, 0x0e, 0x16, 0x00, 0x01,
    0x49, 0x04, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x0c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8,
    0x0a, 0x02, 0x02, 0x02,
])


# UPDATE 3 – SRv6 SR Policy with Endpoint Behavior and Policy Name
#   NLRI      : Distinguisher=1, Color=300, Endpoint=10.3.3.3
#   sub-TLVs  : Preference(200), SRv6 Binding SID(fc00::200),
#               Policy Name("gold-service")
#   Seg. List : Weight(1), Type-B SRv6(fc00::1) + Endpoint Behavior
#               (code=5126, lb_len=32, func_len=16)
_MSG3_SRV6_EB = bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x98, 0x02, 0x00, 0x00, 0x00, 0x81, 0x40,
    0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
    0x00, 0x00, 0xfd, 0xea, 0xc0, 0x17, 0x58, 0x00,
    0x0f, 0x00, 0x54, 0x0c, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc8, 0x14, 0x12, 0x00, 0x00, 0xfc,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x82,
    0x00, 0x0d, 0x00, 0x67, 0x6f, 0x6c, 0x64, 0x2d,
    0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x80,
    0x00, 0x25, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x0d, 0x1a, 0x80, 0x00, 0xfc,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x14,
    0x06, 0x00, 0x41, 0x20, 0x00, 0x10, 0x00, 0x80,
    0x0e, 0x16, 0x00, 0x01, 0x49, 0x04, 0xc0, 0x00,
    0x02, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c, 0x0a, 0x03, 0x03, 0x03,
])

# UPDATE 4 – MP_UNREACH_NLRI (SR Policy withdrawal, AFI=IPv4, SAFI=SR Policy)
_MSG4_WITHDRAW = bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x1e, 0x02, 0x00, 0x00, 0x00, 0x07, 0x90,
    0x0f, 0x00, 0x03, 0x00, 0x01, 0x49,
])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBgpSrPolicyMpls:
    '''UPDATE 1: MPLS-based SR Policy – Preference, MPLS Binding SID,
    Segment List with Weight sub-TLV and Type-A MPLS SID segments.'''

    def _fields(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           _MSG1_MPLS, fields, test_env)

    def test_nlri_distinguisher_decimal(self, cmd_tshark, cmd_text2pcap,
                                        result_file, test_env):
        '''Distinguisher displayed as decimal (was raw FT_BYTES hex before)'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_distinguisher')
        assert out == '0'

    def test_nlri_color(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_policy_color')
        assert out == '100'

    def test_nlri_endpoint(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_endpoint_ipv4')
        assert out == '10.1.1.1'

    def test_weight_subtlv_flags(self, cmd_tshark, cmd_text2pcap,
                                  result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.weight.flags')
        assert out == '0x00'

    def test_weight_subtlv_value(self, cmd_tshark, cmd_text2pcap,
                                  result_file, test_env):
        '''Weight decoded as uint32 (was raw FT_BYTES data blob before)'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.weight')
        assert out == '1'

    def test_segment_list_subtlv_types(self, cmd_tshark, cmd_text2pcap,
                                        result_file, test_env):
        '''Weight(9), Type-A MPLS SID(1), Type-A MPLS SID(1)'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv.type')
        assert out == '9,1,1'

    def test_mpls_sid_labels(self, cmd_tshark, cmd_text2pcap,
                              result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.mpls_label')
        assert out == '24000,16001,16002'

    def test_preference_value(self, cmd_tshark, cmd_text2pcap,
                               result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.pref.preference')
        assert out == '00000064'


class TestBgpSrPolicySrv6:
    '''UPDATE 2: SRv6-based SR Policy – SRv6 Binding SID and
    Segment List with Weight and Type-B SRv6 SID segments.'''

    def _fields(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           _MSG2_SRV6, fields, test_env)

    def test_nlri_distinguisher(self, cmd_tshark, cmd_text2pcap,
                                 result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_distinguisher')
        assert out == '0'

    def test_nlri_color(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_policy_color')
        assert out == '200'

    def test_nlri_endpoint(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_endpoint_ipv4')
        assert out == '10.2.2.2'

    def test_segment_list_subtlv_types(self, cmd_tshark, cmd_text2pcap,
                                        result_file, test_env):
        '''Weight(9), two Type-B SRv6 SID segments(13)'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv.type')
        assert out == '9,13,13'

    def test_weight_value(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.weight')
        assert out == '1'

    def test_srv6_sid_values(self, cmd_tshark, cmd_text2pcap,
                              result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.srv6_sid')
        assert out == 'fc00::1,fc00::2'


class TestBgpSrPolicySrv6EndpointBehavior:
    '''UPDATE 3: SRv6 SR Policy with Endpoint Behavior and Policy Name.'''

    def _fields(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           _MSG3_SRV6_EB, fields, test_env)

    def test_nlri_distinguisher_nonzero(self, cmd_tshark, cmd_text2pcap,
                                         result_file, test_env):
        '''Non-zero distinguisher – verifies decimal display'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_distinguisher')
        assert out == '1'

    def test_nlri_color(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.sr_policy_nlri_policy_color')
        assert out == '300'

    def test_endpoint_behavior_code(self, cmd_tshark, cmd_text2pcap,
                                     result_file, test_env):
        '''Endpoint Behavior code (now BASE_DEC_HEX with VALS name lookup)'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.srv6_endpoint_behavior.code')
        assert out == '5126'

    def test_endpoint_behavior_reserved(self, cmd_tshark, cmd_text2pcap,
                                         result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.srv6_endpoint_behavior.reserved')
        assert out == '0x0041'

    def test_srv6_sid_locator_block_length(self, cmd_tshark, cmd_text2pcap,
                                            result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.srv6_lb_length')
        assert out == '32'

    def test_srv6_sid_function_length(self, cmd_tshark, cmd_text2pcap,
                                       result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.srv6_func_length')
        assert out == '16'

    def test_weight_value(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.weight')
        assert out == '1'


class TestBgpSrPolicyWithdraw:
    '''UPDATE 4: MP_UNREACH_NLRI – SR Policy withdrawal (AFI=1, SAFI=73).'''

    def _fields(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           _MSG4_WITHDRAW, fields, test_env)

    def test_unreach_afi(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.path_attribute.mp_unreach_nlri.afi')
        assert out == '1'

    def test_unreach_safi(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        '''SAFI 73 = SR Policy'''
        out = self._fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                           'bgp.update.path_attribute.mp_unreach_nlri.safi')
        assert out == '73'


# ---------------------------------------------------------------------------
# Common field filter strings used by the synthetic segment-type tests
# ---------------------------------------------------------------------------
_F_TYPE    = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv.type'
_F_ALGO    = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.sr_algorithm'
_F_IPV4N   = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.ipv4_node_address'
_F_IPV6N   = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.ipv6_node_address'
_F_LOCIFID = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.local_interface_id'
_F_REMIFID = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.remote_interface_id'
_F_LOCIPV4 = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.local_ipv4_address'
_F_REMIPV4 = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.remote_ipv4_address'
_F_LOCIPV6 = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.local_ipv6_address'
_F_REMIPV6 = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.remote_ipv6_address'
_F_SRV6SID = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.srv6_sid'
_F_MPLS    = 'bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.mpls_label'
_F_NEXTHOP = 'bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv4'

# Shared test addresses
_IPV6_FD00_1 = bytes.fromhex('fd000000000000000000000000000001')
_IPV6_FD00_2 = bytes.fromhex('fd000000000000000000000000000002')
# MPLS label=1000 (0x3E8), TC=0, S=1 (bottom-of-stack), TTL=0
_MPLS_SID    = bytes([0x00, 0x3E, 0x81, 0x00])


class TestBgpSrPolicyNextHop:
    '''Next hop field in MP_REACH_NLRI path attribute.'''

    def test_nexthop_ipv4(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        '''MP_REACH_NLRI next hop is decoded as an IPv4 address.'''
        out = _bgp_fields(cmd_tshark, cmd_text2pcap,
                          result_file('pcap'), result_file('txt'),
                          _MSG1_MPLS, [_F_NEXTHOP], test_env)
        assert out == '192.0.2.1'


class TestBgpSegmentTypeC:
    '''Type C – IPv4 Node Address + SR Algorithm + optional SR-MPLS SID (RFC 9831 §2.1).'''

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, seg_data, *fields):
        msg = _make_bgp_update(3, seg_data)
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + bytes([1,1,1,1]), _F_TYPE)
        assert out == '3'

    def test_sr_algorithm(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + bytes([1,1,1,1]), _F_ALGO)
        assert out == '0'

    def test_ipv4_node_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + bytes([1,1,1,1]), _F_IPV4N)
        assert out == '1.1.1.1'

    def test_mpls_sid(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        '''With optional SR-MPLS SID (label=1000).'''
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + bytes([1,1,1,1]) + _MPLS_SID, _F_MPLS)
        assert out == '1000'


class TestBgpSegmentTypeD:
    '''Type D – IPv6 Node Address + SR Algorithm + optional SR-MPLS SID (RFC 9831 §2.2).'''

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, seg_data, *fields):
        msg = _make_bgp_update(4, seg_data)
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1, _F_TYPE)
        assert out == '4'

    def test_sr_algorithm(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1, _F_ALGO)
        assert out == '0'

    def test_ipv6_node_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1, _F_IPV6N)
        assert out == 'fd00::1'

    def test_mpls_sid(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        '''With optional SR-MPLS SID (label=1000).'''
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1 + _MPLS_SID, _F_MPLS)
        assert out == '1000'


class TestBgpSegmentTypeE:
    '''Type E – IPv4 Node + Local Interface ID + optional SR-MPLS SID (RFC 9831 §2.3).'''

    def _seg(self):
        # flags(1) + reserved(1) + local_interface_id(4) + ipv4_node(4)
        return bytes([0x00, 0x00]) + struct.pack('>I', 1) + bytes([1, 1, 1, 2])

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        msg = _make_bgp_update(5, self._seg())
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_TYPE) == '5'

    def test_local_interface_id(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIFID) == '1'

    def test_ipv4_node_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_IPV4N) == '1.1.1.2'


class TestBgpSegmentTypeF:
    '''Type F – IPv4 adjacency (local/remote addresses) + optional SR-MPLS SID (RFC 9831 §2.4).'''

    def _seg(self):
        # flags(1) + reserved(1) + local_ipv4(4) + remote_ipv4(4)
        return bytes([0x00, 0x00]) + bytes([10,0,0,1]) + bytes([10,0,0,2])

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        msg = _make_bgp_update(6, self._seg())
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_TYPE) == '6'

    def test_local_ipv4_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIPV4) == '10.0.0.1'

    def test_remote_ipv4_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIPV4) == '10.0.0.2'


class TestBgpSegmentTypeG:
    '''Type G – IPv6 link-local adjacency with node addresses and interface IDs
    + optional SR-MPLS SID (RFC 9831 §2.5).'''

    def _seg(self):
        # flags(1) + reserved(1) + local_if_id(4) + local_ipv6(16) + remote_if_id(4) + remote_ipv6(16)
        return (bytes([0x00, 0x00]) + struct.pack('>I', 1) + _IPV6_FD00_1
                + struct.pack('>I', 2) + _IPV6_FD00_2)

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        msg = _make_bgp_update(7, self._seg())
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_TYPE) == '7'

    def test_local_interface_id(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIFID) == '1'

    def test_remote_interface_id(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIFID) == '2'

    def test_local_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIPV6) == 'fd00::1'

    def test_remote_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIPV6) == 'fd00::2'


class TestBgpSegmentTypeH:
    '''Type H – IPv6 adjacency (local/remote addresses) + optional SR-MPLS SID (RFC 9831 §2.6).'''

    def _seg(self):
        # flags(1) + reserved(1) + local_ipv6(16) + remote_ipv6(16)
        return bytes([0x00, 0x00]) + _IPV6_FD00_1 + _IPV6_FD00_2

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        msg = _make_bgp_update(8, self._seg())
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_TYPE) == '8'

    def test_local_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIPV6) == 'fd00::1'

    def test_remote_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIPV6) == 'fd00::2'


class TestBgpSegmentTypeI:
    '''Type I – SRv6 IPv6 Node Address + SR Algorithm + optional SRv6 SID (RFC 9831 §2.7).
    Type code is 14 per RFC 9831 IANA allocation.'''

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, seg_data, *fields):
        msg = _make_bgp_update(14, seg_data)
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1, _F_TYPE)
        assert out == '14'

    def test_sr_algorithm(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1, _F_ALGO)
        assert out == '0'

    def test_ipv6_node_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1, _F_IPV6N)
        assert out == 'fd00::1'

    def test_srv6_sid(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        '''With optional SRv6 SID.'''
        out = self._run(cmd_tshark, cmd_text2pcap, result_file, test_env,
                        bytes([0x00, 0x00]) + _IPV6_FD00_1 + _IPV6_FD00_1, _F_SRV6SID)
        assert out == 'fd00::1'


class TestBgpSegmentTypeJ:
    '''Type J – SRv6 IPv6 link-local adjacency with node addresses and interface IDs
    + optional SRv6 SID (RFC 9831 §2.8).
    Type code is 15 per RFC 9831 IANA allocation.'''

    def _seg(self):
        # flags(1) + sr_algo(1) + local_if_id(4) + local_ipv6(16) + remote_if_id(4) + remote_ipv6(16)
        return (bytes([0x00, 0x00]) + struct.pack('>I', 1) + _IPV6_FD00_1
                + struct.pack('>I', 2) + _IPV6_FD00_2)

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        msg = _make_bgp_update(15, self._seg())
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_TYPE) == '15'

    def test_sr_algorithm(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_ALGO) == '0'

    def test_local_interface_id(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIFID) == '1'

    def test_remote_interface_id(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIFID) == '2'

    def test_local_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIPV6) == 'fd00::1'

    def test_remote_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIPV6) == 'fd00::2'


class TestBgpSegmentTypeK:
    '''Type K – SRv6 IPv6 adjacency (local/remote addresses) + optional SRv6 SID (RFC 9831 §2.9).
    Type code is 16 per RFC 9831 IANA allocation.'''

    def _seg(self):
        # flags(1) + sr_algo(1) + local_ipv6(16) + remote_ipv6(16)
        return bytes([0x00, 0x00]) + _IPV6_FD00_1 + _IPV6_FD00_2

    def _run(self, cmd_tshark, cmd_text2pcap, result_file, test_env, *fields):
        msg = _make_bgp_update(16, self._seg())
        return _bgp_fields(cmd_tshark, cmd_text2pcap,
                           result_file('pcap'), result_file('txt'),
                           msg, fields, test_env)

    def test_subtlv_type(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_TYPE) == '16'

    def test_sr_algorithm(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_ALGO) == '0'

    def test_local_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_LOCIPV6) == 'fd00::1'

    def test_remote_ipv6_address(self, cmd_tshark, cmd_text2pcap, result_file, test_env):
        assert self._run(cmd_tshark, cmd_text2pcap, result_file, test_env, _F_REMIPV6) == 'fd00::2'
