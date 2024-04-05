# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterSyntax:
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "frame"
        checkDFilterCount(dfilter, 1)

    def test_exists_2(self, checkDFilterCount):
        # Protocol using minus
        dfilter = "mac-lte"
        checkDFilterCount(dfilter, 0)

    def test_exists_3(self, checkDFilterCount):
        # Protocol starting with digit
        dfilter = "9p or http"
        checkDFilterCount(dfilter, 1)

    # The HTTP dissector no longer has a expert Chat
        # def test_exists_4(self, checkDFilterCount):
        # Protocol with dot
        # dfilter = "_ws.expert"
        # checkDFilterCount(dfilter, 1)

    def test_exists_5(self, checkDFilterSucceed):
        # Protocol field name with leading digit and minus
        dfilter = "diameter.3GPP-Reporting-Reason"
        checkDFilterSucceed(dfilter)

    def test_commute_1(self, checkDFilterCount):
        dfilter = "ip.proto == 6"
        checkDFilterCount(dfilter, 1)

    def test_commute_2(self, checkDFilterCount):
        dfilter = "6 == ip.proto"
        checkDFilterCount(dfilter, 1)

    def test_commute_3(self, checkDFilterFail):
        dfilter = "6 == 7"
        error = "Constant expression is invalid"
        checkDFilterFail(dfilter, error)

    def test_func_1(self, checkDFilterCount):
        dfilter = "len(frame) == 207"
        checkDFilterCount(dfilter, 1)

    def test_value_string_1(self, checkDFilterSucceed):
        dfilter = 'eth.fcs.status=="Bad"'
        checkDFilterSucceed(dfilter)

    def test_matches_1(self, checkDFilterSucceed):
        dfilter = 'http.request.method matches "^HEAD"'
        checkDFilterSucceed(dfilter)

    def test_matches_2(self, checkDFilterFail):
        dfilter = 'http.request.method matches HEAD'
        checkDFilterFail(dfilter, 'requires a double quoted string')

    def test_matches_3(self, checkDFilterFail):
        dfilter = 'http.request.method matches "^HEAD" matches "^POST"'
        checkDFilterFail(dfilter, '"matches" was unexpected in this context.')

    def test_matches_4(self, checkDFilterCount):
        dfilter = r'http.host matches r"update\.microsoft\.c.."'
        checkDFilterCount(dfilter, 1)

    def test_matches_5(self, checkDFilterSucceed):
        # case insensitive
        dfilter = 'http.request.method matches "^head"'
        checkDFilterSucceed(dfilter)

    def test_equal_1(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5'
        checkDFilterCount(dfilter, 1)

    def test_equal_2(self, checkDFilterCount):
        dfilter = 'ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_equal_3(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5 or ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_equal_4(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5 and ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_not_equal_1(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_2(self, checkDFilterCount):
        dfilter = 'ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_3(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5 and ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_4(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5 or ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_deprecated_1(self, checkDFilterSucceed):
        dfilter = "bootp"
        checkDFilterSucceed(dfilter, "Deprecated token \"bootp\"")

    def test_charconst_bytes_1(self, checkDFilterCount):
        # Bytes as a character constant.
        dfilter = "frame contains 'H'"
        checkDFilterCount(dfilter, 1)

    def test_charconst_bytes_2(self, checkDFilterCount):
        dfilter = "frame[54] == 'H'"
        checkDFilterCount(dfilter, 1)

    def test_charconst_invalid(self, checkDFilterFail):
        dfilter = r"ip.proto == '\Z'"
        checkDFilterFail(dfilter, "isn't a valid character constant")

    def test_bool_1(self, checkDFilterCount):
        dfilter = "tcp.flags.push == 1"
        checkDFilterCount(dfilter, 1)

    def test_bool_2(self, checkDFilterCount):
        dfilter = "tcp.flags.push == True"
        checkDFilterCount(dfilter, 1)

    def test_bool_2(self, checkDFilterCount):
        dfilter = "tcp.flags.push == FALSE"
        checkDFilterCount(dfilter, 0)

    def test_misc_1(self, checkDFilterSucceed):
        # Issue #18418
        dfilter = "icmp and ((icmp.type > 0 and icmp.type < 8) or icmp.type > 8)"
        checkDFilterSucceed(dfilter)

    def test_whitespace(self, checkDFilterSucceed):
        dfilter = '\ttcp.stream \r\n== 1'
        checkDFilterSucceed(dfilter)

    def test_func_name_clash1(self, checkDFilterFail):
        # "tcp" is a (non-existent) function, not a protocol
        error = "Function 'tcp' does not exist"
        dfilter = 'frame == tcp()'
        checkDFilterFail(dfilter, error)

class TestDfilterEquality:
    trace_file = "sip.pcapng"

    def test_all_eq_1(self, checkDFilterCount):
        dfilter = "udp.port === 5060"
        checkDFilterCount(dfilter, 2)

    def test_any_ne_1(self, checkDFilterCount):
        dfilter = "udp.port !== 5060"
        checkDFilterCount(dfilter, 4)

    def test_any_eq_1(self, checkDFilterCount):
        dfilter = "udp.port == 5060"
        checkDFilterCount(dfilter, 5)

    def test_all_ne_1(self, checkDFilterCount):
        dfilter = "udp.port != 5060"
        checkDFilterCount(dfilter, 1)

    def test_root_1(self, checkDFilterCount):
        dfilter = "udp.srcport == .udp.dstport"
        checkDFilterCount(dfilter, 2)

    def test_literal_3(self, checkDFilterCount):
        dfilter = "frame[0:10] contains :00:01:6c"
        checkDFilterCount(dfilter, 1)

    def test_literal_4(self, checkDFilterCount):
        dfilter = "frame[0:10] contains :00016c"
        checkDFilterCount(dfilter, 1)

    def test_literal_5(self, checkDFilterCount):
        dfilter = "frame[0:10] contains :00.01.6c"
        checkDFilterCount(dfilter, 1)

    def test_literal_6(self, checkDFilterCount):
        dfilter = "frame[0:10] contains :00-01-6c"
        checkDFilterCount(dfilter, 1)

    def test_rhs_bias_1(self, checkDFilterCount):
        # Protocol "Fibre Channel" on the RHS
        dfilter = 'frame[37] == fc'
        checkDFilterCount(dfilter, 0)

    def test_rhs_bias_2(self, checkDFilterCount):
        # Byte 0xFC on the RHS
        dfilter = 'frame[37] == :fc'
        checkDFilterCount(dfilter, 1)

    def test_rhs_bias_3(self, checkDFilterCount):
        # Byte 0xFC on the RHS
        dfilter = 'frame[37] == fc:'
        checkDFilterCount(dfilter, 1)

    def test_rhs_bias_4(self, checkDFilterCount):
        # Protocol "Fibre Channel" on the RHS
        dfilter = 'frame[37] == .fc'
        checkDFilterCount(dfilter, 0)

    def test_rhs_bias_5(self, checkDFilterSucceed):
        # Protocol "Fibre Channel" on the RHS (with warning)
        dfilter = 'frame contains fc'
        checkDFilterSucceed(dfilter, 'Interpreting "fc" as Fibre Channel')

    def test_rhs_bias_6(self, checkDFilterSucceed):
        # Protocol "Fibre Channel" on the RHS (without warning)
        dfilter = 'frame contains .fc'
        checkDFilterSucceed(dfilter)

    def test_rhs_bias_7(self, checkDFilterSucceed):
        # Byte 0xFC on the RHS
        dfilter = 'frame contains fc:'
        checkDFilterSucceed(dfilter)

class TestDfilterBitwise:
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "tcp.flags & 0x8"
        checkDFilterCount(dfilter, 1)

    def test_exists_2(self, checkDFilterCount):
        dfilter = "tcp.flags bitand 0x8"
        checkDFilterCount(dfilter, 1)

    def test_exists_3(self, checkDFilterCount):
        dfilter = "eth[0] & 1"
        checkDFilterCount(dfilter, 0)

    def test_equal_1(self, checkDFilterCount):
        dfilter = "tcp.flags & 0x0F == 8"
        checkDFilterCount(dfilter, 1)

    def test_equal_2(self, checkDFilterCount):
        dfilter = "tcp.srcport != tcp.dstport & 0x0F"
        checkDFilterCount(dfilter, 1)

    def test_equal_3(self, checkDFilterCount):
        dfilter = "tcp.srcport != tcp.dstport bitand 0x0F"
        checkDFilterCount(dfilter, 1)

    def test_equal_4(self, checkDFilterCount):
        dfilter = "tcp.srcport != tcp.dstport bitwise_and 0x0F"
        checkDFilterCount(dfilter, 1)

class TestDfilterUnaryMinus:
    trace_file = "http.pcap"

    def test_minus_const_1(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -1"
        checkDFilterCount(dfilter, 1)

    def test_minus_const_2(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -2"
        checkDFilterCount(dfilter, 0)

    def test_plus_const_1(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == +1"
        checkDFilterCount(dfilter, 0)

    def test_unary_1(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -tcp.dstport"
        checkDFilterCount(dfilter, 0)

    def test_unary_2(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == +tcp.dstport"
        checkDFilterCount(dfilter, 0)

    def test_unary_3(self, checkDFilterCount):
        dfilter = "-2 == tcp.dstport"
        checkDFilterCount(dfilter, 0)

    def test_unary_4(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -{tcp.dstport * 20}"
        checkDFilterCount(dfilter, 0)

    def test_unary_invalid_1(self, checkDFilterFail):
        error = 'FT_PROTOCOL cannot be negated'
        dfilter = "-tcp"
        checkDFilterFail(dfilter, error)

class TestDfilterArithmetic:
    trace_file = "dhcp.pcap"

    def test_add_1(self, checkDFilterCount):
        dfilter = "udp.dstport == udp.srcport + 1"
        checkDFilterCount(dfilter, 2)

    def test_add_2(self, checkDFilterCount):
        dfilter = "udp.dstport == 66 + 1"
        checkDFilterCount(dfilter, 2)

    def test_add_3(self, checkDFilterCount):
        dfilter = "udp.dstport == 66+1"
        checkDFilterCount(dfilter, 2)

    def test_add_4(self, checkDFilterCount):
        dfilter = "1 + 2 == frame.number"
        checkDFilterCount(dfilter, 1)

    def test_add_5(self, checkDFilterFail):
        error = 'Constant expression is invalid'
        dfilter = "1 + 2 == 2 + 1"
        checkDFilterFail(dfilter, error)

    def test_add_6(self, checkDFilterFail):
        error = 'Constant expression is invalid'
        dfilter = "1 - 2"
        checkDFilterFail(dfilter, error)

    def test_add_7(self, checkDFilterCount):
        dfilter = r"udp.dstport == 66+'\x01'"
        checkDFilterCount(dfilter, 2)

    def test_sub_1(self, checkDFilterCount):
        dfilter = "udp.srcport == udp.dstport - 1"
        checkDFilterCount(dfilter, 2)

    def test_sub_2(self, checkDFilterCount):
        dfilter = "udp.dstport == 68 - 1"
        checkDFilterCount(dfilter, 2)

    def test_sub_3(self, checkDFilterCount):
        dfilter = "udp.length == ip.len - 20"
        checkDFilterCount(dfilter, 4)

    def test_sub_no_space_1(self, checkDFilterFail):
        # Minus operator requires whitespace preceding it.
        error = '"68-1" cannot be converted to Unsigned integer'
        dfilter = "udp.dstport == 68-1"
        checkDFilterFail(dfilter, error)

    def test_sub_no_space_2(self, checkDFilterFail):
        # Different case, 68-67 should not be parsed
        # as bytes separated by hyphen XX-XX-XX
        # Minus operator still requires whitespace preceding it.
        error = '"68-67" cannot be converted to Unsigned integer'
        dfilter = "frame.number == 68-67"
        checkDFilterFail(dfilter, error)

    def test_expr_1(self, checkDFilterCount):
        dfilter = 'udp.port * { 10 / {5 - 4} } == udp.port * { {50 + 50} / 2 - 40 }'
        checkDFilterCount(dfilter, 4)

    def test_expr_2(self, checkDFilterCount):
        dfilter = 'udp.dstport * { udp.srcport / {5 - 4} } == udp.srcport * { 2 * udp.dstport - 68 }'
        checkDFilterCount(dfilter, 2)

class TestDfilterFieldReference:
    trace_file = "ipoipoip.pcap"

    def test_ref_1(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.number < ${frame.number}'
        # select frame 2, expect 1 frames out of 2.
        checkDFilterCountWithSelectedFrame(dfilter, 1, 2)

    def test_ref_2(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'ip.src#3 == ${ip.src#4}'
        # select frame 1, expect 1 frames out of 2.
        checkDFilterCountWithSelectedFrame(dfilter, 1, 1)

    def test_ref_3(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame.number < $frame.number'
        # select frame 2, expect 1 frames out of 2.
        checkDFilterCountWithSelectedFrame(dfilter, 1, 2)

    def test_ref_4(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'ip.src#3 == $ip.src#4'
        # select frame 1, expect 1 frames out of 2.
        checkDFilterCountWithSelectedFrame(dfilter, 1, 1)

    def test_ref_5(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame[52-54] == ${@ip.src}[0-2]'
        # select frame 1, expect 1 frames out of 2.
        checkDFilterCountWithSelectedFrame(dfilter, 1, 1)

    def test_ref_6(self, checkDFilterCountWithSelectedFrame):
        dfilter = 'frame[52-54] == $@ip.src[0-2]'
        # select frame 1, expect 1 frames out of 2.
        checkDFilterCountWithSelectedFrame(dfilter, 1, 1)

    def test_ref_7(self, checkDFilterFail):
        # anything after $ must be a field
        dfilter = 'frame == $aaaa'
        error = '"aaaa" is not a valid protocol or protocol field'
        checkDFilterFail(dfilter, error)

class TestDfilterLayer:
    trace_file = "ipoipoip.pcap"

    def test_layer_1(self, checkDFilterCount):
        dfilter = 'ip.addr#2 == 4.4.4.4'
        checkDFilterCount(dfilter, 1)

    def test_layer_2(self, checkDFilterCount):
        dfilter = 'ip.addr#5'
        checkDFilterCount(dfilter, 1)

    def test_layer_3(self, checkDFilterCount):
        dfilter = 'ip.addr#6'
        checkDFilterCount(dfilter, 0)

    def test_layer_4(self, checkDFilterCount):
        dfilter = 'ip.dst#[2-4] == 8.8.8.8'
        checkDFilterCount(dfilter, 1)

    def test_layer_5(self, checkDFilterCount):
        dfilter = 'ip.dst#[-1] == 8.8.8.8'
        checkDFilterCount(dfilter, 0)

    def test_layer_6(self, checkDFilterCount):
        dfilter = 'ip.dst#[-1] == 9.9.9.9'
        checkDFilterCount(dfilter, 1)

    def test_layer_7(self, checkDFilterCount):
        dfilter = 'ip.dst#[-5] == 2.2.2.2'
        checkDFilterCount(dfilter, 1)

class TestDfilterQuantifiers:
    trace_file = "ipoipoip.pcap"

    def test_any_1(self, checkDFilterCount):
        dfilter = 'any ip.addr > 1.1.1.1'
        checkDFilterCount(dfilter, 2)

    def test_all_1(self, checkDFilterCount):
        dfilter = 'all ip.addr > 1.1.1.1'
        checkDFilterCount(dfilter, 1)

class TestDfilterRawModifier:
    trace_file = "s7comm-fuzz.pcapng.gz"

    def test_regular(self, checkDFilterCount):
        dfilter = 's7comm.blockinfo.blocktype == "0\uFFFD"'
        checkDFilterCount(dfilter, 3)

    def test_raw1(self, checkDFilterCount):
        dfilter = '@s7comm.blockinfo.blocktype == 30:aa'
        checkDFilterCount(dfilter, 2)

    def test_raw2(self, checkDFilterCount):
        dfilter = '@s7comm.blockinfo.blocktype == 30:fe'
        checkDFilterCount(dfilter, 1)

    def test_raw_ref(self, checkDFilterCountWithSelectedFrame):
        dfilter = '@s7comm.blockinfo.blocktype == ${@s7comm.blockinfo.blocktype}'
        # select frame 3, expect 2 frames out of 3.
        checkDFilterCountWithSelectedFrame(dfilter, 2, 3)

class TestDfilterRawSlice:
    trace_file = "http.pcap"

    def test_raw_slice1(self, checkDFilterFail):
        dfilter = 'tcp.port[1] == 0xc3'
        checkDFilterFail(dfilter, "cannot be sliced")

    def test_raw_slice2(self, checkDFilterCount):
        dfilter = '@tcp.port[1] == 0xc3'
        checkDFilterCount(dfilter, 1)

    def test_raw_slice3(self, checkDFilterFail):
        dfilter = 'tcp.port[0:] == 0c:c3'
        checkDFilterFail(dfilter, "cannot be sliced")

    def test_raw_slice4(self, checkDFilterCount):
        dfilter = '@tcp.port[0:] == 0c:c3'
        checkDFilterCount(dfilter, 1)

class TestDfilterXor:
    trace_file = "ipoipoip.pcap"

    def test_xor_1(self, checkDFilterCount):
        dfilter = 'ip.src == 7.7.7.7 xor ip.dst == 7.7.7.7'
        checkDFilterCount(dfilter, 1)

    def test_xor_2(self, checkDFilterCount):
        dfilter = 'ip.src == 7.7.7.7 ^^ ip.dst == 7.7.7.7'
        checkDFilterCount(dfilter, 1)

    def test_xor_3(self, checkDFilterCount):
        dfilter = 'ip.src == 9.9.9.9 xor ip.dst == 9.9.9.9'
        checkDFilterCount(dfilter, 0)

    def test_xor_4(self, checkDFilterCount):
        dfilter = 'ip.src == 9.9.9.9 ^^ ip.dst == 9.9.9.9'
        checkDFilterCount(dfilter, 0)

class TestDfilterTFSValueString:
    trace_file = "http.pcap"

    def test_tfs_1(self, checkDFilterCount):
        dfilter = 'ip.flags.df == True'
        checkDFilterCount(dfilter, 1)

    def test_tfs_2(self, checkDFilterCount):
        dfilter = 'ip.flags.df == "True"'
        checkDFilterCount(dfilter, 1)

    def test_tfs_3(self, checkDFilterCount):
        dfilter = 'ip.flags.df == "Set"'
        checkDFilterCount(dfilter, 1)

    def test_tfs_4(self, checkDFilterCount):
        dfilter = 'frame.ignored == False'
        checkDFilterCount(dfilter, 1)

    def test_tfs_5(self, checkDFilterCount):
        dfilter = 'frame.ignored == "False"'
        checkDFilterCount(dfilter, 1)

    def test_tfs_6(self, checkDFilterFail):
        error = 'expected "True" or "False", not "Unset"'
        dfilter = 'frame.ignored == "Unset"'
        checkDFilterFail(dfilter, error)
