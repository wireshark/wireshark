#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import argparse
import signal
import subprocess

# This utility scans the dissector code for various issues.
# TODO:
# - Create maps from type -> display types for hf items (see display (FIELDDISPLAY)) in docs/README.dissector


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


warnings_found = 0
errors_found = 0

def name_has_one_of(name, substring_list):
    for word in substring_list:
        if name.lower().find(word) != -1:
            return True
    return False

# An individual call to an API we are interested in.
# Used by APICheck below.
class Call:
    def __init__(self, hf_name, macros, line_number=None, length=None, fields=None):
        self.hf_name = hf_name
        self.line_number = line_number
        self.fields = fields
        self.length = None
        if length:
            try:
                self.length = int(length)
            except Exception:
                if length.isupper():
                    if length in macros:
                        try:
                            self.length = int(macros[length])
                        except Exception:
                            pass
                pass


# These are variable names that have been seen to be used in calls..
common_hf_var_names = { 'hf_index', 'hf_item', 'hf_idx', 'hf_x', 'hf_id', 'hf_cookie', 'hf_flag',
                        'hf_dos_time', 'hf_dos_date', 'hf_value', 'hf_num',
                        'hf_cause_value', 'hf_uuid',
                        'hf_endian', 'hf_ip', 'hf_port', 'hf_suff', 'hf_string', 'hf_uint',
                        'hf_tag', 'hf_type', 'hf_hdr', 'hf_field', 'hf_opcode', 'hf_size',
                        'hf_entry', 'field' }

item_lengths = {}
item_lengths['FT_CHAR']  = 1
item_lengths['FT_UINT8']  = 1
item_lengths['FT_INT8']   = 1
item_lengths['FT_UINT16'] = 2
item_lengths['FT_INT16']  = 2
item_lengths['FT_UINT24'] = 3
item_lengths['FT_INT24']  = 3
item_lengths['FT_UINT32'] = 4
item_lengths['FT_INT32']  = 4
item_lengths['FT_UINT40'] = 5
item_lengths['FT_INT40']  = 5
item_lengths['FT_UINT48'] = 6
item_lengths['FT_INT48']  = 6
item_lengths['FT_UINT56'] = 7
item_lengths['FT_INT56']  = 7
item_lengths['FT_UINT64'] = 8
item_lengths['FT_INT64']  = 8
item_lengths['FT_ETHER']  = 6
item_lengths['FT_IPv4']   = 4
item_lengths['FT_IPv6']   = 16

# TODO: other types...


# A check for a particular API function.
class APICheck:
    def __init__(self, fun_name, allowed_types, positive_length=False):
        self.fun_name = fun_name
        self.allowed_types = allowed_types
        self.positive_length = positive_length
        self.calls = []

        if fun_name.startswith('ptvcursor'):
            # RE captures function name + 1st 2 args (always ptvc + hfindex)
            self.p = re.compile('[^\n]*' +  self.fun_name + r'\s*\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+)')
        elif fun_name.find('add_bitmask') == -1:
            # Normal case.
            # RE captures function name + 1st 2 args (always tree + hfindex + length)
            self.p = re.compile('[^\n]*' +  self.fun_name + r'\s*\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)')
        else:
            # _add_bitmask functions.
            # RE captures function name + 1st + 4th args (always tree + hfindex)
            # 6th arg is 'fields'
            self.p = re.compile('[^\n]*' +  self.fun_name + r'\s*\(([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*,\s*([a-zA-Z0-9_]+)\s*,')

        self.file = None
        self.mask_allowed = True
        if fun_name.find('proto_tree_add_bits_') != -1:
            self.mask_allowed = False


    def find_calls(self, file, macros):
        self.file = file
        self.calls = []

        with open(file, 'r', encoding="utf8") as f:
            contents = f.read()
            lines = contents.splitlines()
            total_lines = len(lines)
            for line_number,line in enumerate(lines):
                # Want to check this, and next few lines
                to_check = lines[line_number-1] + '\n'
                # Nothing to check if function name isn't in it
                if to_check.find(self.fun_name) != -1:
                    # Ok, add the next file lines before trying RE
                    for i in range(1, 4):
                        if to_check.find(';') != -1:
                            break
                        elif line_number+i < total_lines:
                            to_check += (lines[line_number-1+i] + '\n')
                    m = self.p.search(to_check)
                    if m:
                        fields = None
                        length = None

                        if self.fun_name.find('add_bitmask') != -1:
                            fields = m.group(3)
                        else:
                            if self.p.groups == 3:
                                length = m.group(3)

                        # Add call. We have length if re had 3 groups.
                        self.calls.append(Call(m.group(2),
                                               macros,
                                               line_number=line_number,
                                               length=length,
                                               fields=fields))

    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    def does_mask_cover_value(self, mask, value):
        # Walk past any l.s. 0 bits in value
        n = 0

        # Walk through any bits that are set and check they are in mask
        while self.check_bit(value, n) and n <= 63:
            if not self.check_bit(mask, n):
                return False
            n += 1

        return True

    def check_against_items(self, items_defined, items_declared, items_declared_extern, check_missing_items=False,
                            field_arrays=None):
        global errors_found
        global warnings_found

        for call in self.calls:

            # Check lengths, but for now only for APIs that have length in bytes.
            if self.fun_name.find('add_bits') == -1 and call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in item_lengths:
                    if item_lengths[items_defined[call.hf_name].item_type] < call.length:
                        # Don't warn if adding value - value is unlikely to just be bytes value
                        if self.fun_name.find('_add_uint') == -1:
                            print('Warning:', self.file + ':' + str(call.line_number),
                                self.fun_name + ' called for', call.hf_name, ' - ',
                                'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)
                            warnings_found += 1

            # Needs a +ve length
            if self.positive_length and call.length is not None:
                if call.length != -1 and call.length <= 0:
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with length ' + str(call.length) + ' - must be > 0 or -1')
                    errors_found += 1

            if call.hf_name in items_defined:
                # Is type allowed?
                if items_defined[call.hf_name].item_type not in self.allowed_types:
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with type ' + items_defined[call.hf_name].item_type)
                    print('    (allowed types are', self.allowed_types, ')\n')
                    errors_found += 1
                # No mask allowed
                if not self.mask_allowed and items_defined[call.hf_name].mask_value != 0:
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with mask ' + items_defined[call.hf_name].mask + '    (must be zero!)\n')
                    errors_found += 1

            if self.fun_name.find('add_bitmask') != -1 and call.hf_name in items_defined and field_arrays:
                if call.fields in field_arrays:
                    if (items_defined[call.hf_name].mask_value and
                        field_arrays[call.fields][1] != 0 and items_defined[call.hf_name].mask_value != field_arrays[call.fields][1]):
                        # TODO: only really a problem if bit is set in array but not in top-level item?
                        if not self.does_mask_cover_value(items_defined[call.hf_name].mask_value,
                                                          field_arrays[call.fields][1]):
                            print('Warning:', self.file, call.hf_name, call.fields, "masks don't match. root=",
                                items_defined[call.hf_name].mask,
                                "array has", hex(field_arrays[call.fields][1]))
                            warnings_found += 1

            if check_missing_items:
                if call.hf_name in items_declared and call.hf_name not in items_defined and call.hf_name not in items_declared_extern:
                #not in common_hf_var_names:
                    print('Warning:', self.file + ':' + str(call.line_number),
                          self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')
                    warnings_found += 1


# Specialization of APICheck for add_item() calls
class ProtoTreeAddItemCheck(APICheck):
    def __init__(self, ptv=None):

        # RE will capture whole call.

        if not ptv:
            # proto_item *
            # proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
            #                     const gint start, gint length, const guint encoding)
            self.fun_name = 'proto_tree_add_item'
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\(\s*[a-zA-Z0-9_]+?,\s*([a-zA-Z0-9_]+?),\s*[a-zA-Z0-9_\+\s]+?,\s*[^,.]+?,\s*(.+),\s*([^,.]+?)\);')
        else:
            # proto_item *
            # ptvcursor_add(ptvcursor_t *ptvc, int hfindex, gint length,
            #               const guint encoding)
            self.fun_name = 'ptvcursor_add'
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\([^,.]+?,\s*([^,.]+?),\s*([^,.]+?),\s*([a-zA-Z0-9_\-\>]+)')


    def find_calls(self, file, macros):
        self.file = file
        self.calls = []
        with open(file, 'r', encoding="utf8") as f:

            contents = f.read()
            lines = contents.splitlines()
            total_lines = len(lines)
            for line_number,line in enumerate(lines):
                # Want to check this, and next few lines
                to_check = lines[line_number-1] + '\n'
                # Nothing to check if function name isn't in it
                fun_idx = to_check.find(self.fun_name)
                if fun_idx != -1:
                    # Ok, add the next file lines before trying RE
                    for i in range(1, 5):
                        if to_check.find(';') != -1:
                            break
                        elif line_number+i < total_lines:
                            to_check += (lines[line_number-1+i] + '\n')
                    # Lose anything before function call itself.
                    to_check = to_check[fun_idx:]
                    m = self.p.search(to_check)
                    if m:
                        # Throw out if parens not matched
                        if m.group(0).count('(') != m.group(0).count(')'):
                            continue

                        enc = m.group(3)
                        hf_name = m.group(1)
                        if not enc.startswith('ENC_'):
                            if enc not in { 'encoding', 'enc', 'client_is_le', 'cigi_byte_order', 'endian', 'endianess', 'machine_encoding', 'byte_order', 'bLittleEndian',
                                            'p_mq_parm->mq_str_enc', 'p_mq_parm->mq_int_enc',
                                            'iEnc', 'strid_enc', 'iCod', 'nl_data->encoding',
                                            'argp->info->encoding', 'gquic_info->encoding', 'writer_encoding',
                                            'tds_get_int2_encoding(tds_info)',
                                            'tds_get_int4_encoding(tds_info)',
                                            'tds_get_char_encoding(tds_info)',
                                            'info->encoding',
                                            'item->encoding',
                                            'DREP_ENC_INTEGER(drep)', 'string_encoding', 'item', 'type',
                                            'dvb_enc_to_item_enc(encoding)',
                                            'packet->enc',
                                            'IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII',
                                            'DREP_ENC_INTEGER(hdr->drep)',
                                            'dhcp_uuid_endian',
                                            'payload_le',
                                            'local_encoding',
                                            'big_endian',
                                            'hf_data_encoding',
                                            'IS_EBCDIC(eStr) ? ENC_EBCDIC : ENC_ASCII',
                                            'big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN',
                                            '(skip == 1) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN',
                                            'pdu_info->sbc', 'pdu_info->mbc',
                                            'seq_info->txt_enc | ENC_NA',
                                            'BASE_SHOW_UTF_8_PRINTABLE',
                                            'dhcp_secs_endian',
                                            'is_mdns ? ENC_UTF_8|ENC_NA : ENC_ASCII|ENC_NA',
                                            'xl_encoding',
                                            'my_frame_data->encoding_client', 'my_frame_data->encoding_results'

                                          }:
                                global warnings_found

                                print('Warning:', self.file + ':' + str(line_number),
                                      self.fun_name + ' called for "' + hf_name + '"',  'check last/enc param:', enc, '?')
                                warnings_found += 1
                        self.calls.append(Call(hf_name, macros, line_number=line_number, length=m.group(2)))

    def check_against_items(self, items_defined, items_declared, items_declared_extern,
                            check_missing_items=False, field_arrays=None):
        # For now, only complaining if length if call is longer than the item type implies.
        #
        # Could also be bugs where the length is always less than the type allows.
        # Would involve keeping track (in the item) of whether any call had used the full length.

        global warnings_found

        for call in self.calls:
            if call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in item_lengths:
                    if item_lengths[items_defined[call.hf_name].item_type] < call.length:
                        # On balance, it is not worth complaining about these - the value is unlikely to be
                        # just the value found in these bytes..
                        if self.fun_name.find('_add_uint') == -1:
                            print('Warning:', self.file + ':' + str(call.line_number),
                                self.fun_name + ' called for', call.hf_name, ' - ',
                                'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)
                            warnings_found += 1
            elif check_missing_items:
                if call.hf_name in items_declared and call.hf_name not in items_declared_extern:
                #not in common_hf_var_names:
                    print('Warning:', self.file + ':' + str(call.line_number),
                          self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')
                    warnings_found += 1



##################################################################################################
# This is a set of items (by filter name) where we know that the bitmask is non-contiguous,
# but is still believed to be correct.
known_non_contiguous_fields = { 'wlan.fixed.capabilities.cfpoll.sta',
                                'wlan.wfa.ie.wme.qos_info.sta.reserved',
                                'btrfcomm.frame_type',   # https://os.itec.kit.edu/downloads/sa_2006_roehricht-martin_flow-control-in-bluez.pdf
                                'capwap.control.message_element.ac_descriptor.dtls_policy.r', # RFC 5415
                                'couchbase.extras.subdoc.flags.reserved',
                                'wlan.fixed.capabilities.cfpoll.ap',   # These are 3 separate bits...
                                'wlan.wfa.ie.wme.tspec.ts_info.reserved', # matches other fields in same sequence
                                'zbee_zcl_se.pp.attr.payment_control_configuration.reserved', # matches other fields in same sequence
                                'zbee_zcl_se.pp.snapshot_payload_cause.reserved',  # matches other fields in same sequence
                                'ebhscr.eth.rsv',  # matches other fields in same sequence
                                'v120.lli',  # non-contiguous field (http://www.acacia-net.com/wwwcla/protocol/v120_l2.htm)
                                'stun.type.class',
                                'bssgp.csg_id', 'tiff.t6.unused', 'artnet.ip_prog_reply.unused',
                                'telnet.auth.mod.enc', 'osc.message.midi.bender', 'btle.data_header.rfu',
                                'stun.type.method', # figure 3 in rfc 5389
                                'tds.done.status', # covers all bits in bitset
                                'hf_iax2_video_csub',  # RFC 5456, table 8.7
                                'iax2.video.subclass',
                                'dnp3.al.ana.int',
                                'pwcesopsn.cw.lm',
                                'gsm_a.rr.format_id', # EN 301 503
                                'siii.mst.phase', # comment in code seems convinced
                                'xmcp.type.class',
                                'xmcp.type.method',
                                'hf_hiqnet_flags',
                                'hf_hiqnet_flagmask',
                                'hf_h223_mux_mpl',
                                'rdp.flags.pkt',
                                'erf.flags.if_raw'  # confirmed by Stephen Donnelly
                              }
##################################################################################################


field_widths = {
    'FT_BOOLEAN' : 64,   # TODO: Width depends upon 'display' field
    'FT_CHAR'    : 8,
    'FT_UINT8'   : 8,
    'FT_INT8'    : 8,
    'FT_UINT16'  : 16,
    'FT_INT16'   : 16,
    'FT_UINT24'  : 24,
    'FT_INT24'   : 24,
    'FT_UINT32'  : 32,
    'FT_INT32'   : 32,
    'FT_UINT40'  : 40,
    'FT_INT40'   : 40,
    'FT_UINT48'  : 48,
    'FT_INT48'   : 48,
    'FT_UINT56'  : 56,
    'FT_INT56'   : 56,
    'FT_UINT64'  : 64,
    'FT_INT64'   : 64
}

def is_ignored_consecutive_filter(filter):
    ignore_filters = {
        'elf.sh_type',
        'elf.p_type',
        'btavrcp.pdu_id',
        'netlogon.dummy_string',
        'opa.reserved',
        'wassp.data.mu_mac',
        'thrift.type',
        'quake2.game.client.command.move.angles',
        'ipp.enum_value',
        'idrp.error.subcode',
        'ftdi-ft.lValue',
        '6lowpan.src',
        'couchbase.flex_frame.frame.id',
        'rtps.param.id',
        'rtps.locator.port',
        'sigcomp.udvm.value',
        'opa.mad.attributemodifier.n',
        'smb.cmd',
        'sctp.checksum',
        'dhcp.option.end',
        'nfapi.num.bf.vector.bf.value',
        'dnp3.al.range.abs',
        'dnp3.al.range.quantity',
        'dnp3.al.index',
        'dnp3.al.size',
        'ftdi-ft.hValue',
        'homeplug_av.op_attr_cnf.data.sw_sub',
        'radiotap.he_mu.preamble_puncturing',
        'ndmp.file',
        'ocfs2.dlm.lvb',
        'oran_fh_cus.reserved',
        'qnet6.kif.msgsend.msg.read.xtypes0-7',
        'qnet6.kif.msgsend.msg.write.xtypes0-7',
        'mih.sig_strength',
        'couchbase.flex_frame.frame.len',
        'nvme-rdma.read_to_host_req',
        'rpcap.dummy',
        'sflow.flow_sample.output_interface',
        'socks.results',
        'opa.mad.attributemodifier.p',
        'v5ua.efa',
        'zbncp.data.tx_power',
        'zbncp.data.nwk_addr',
        'zbee_zcl_hvac.pump_config_control.attr.ctrl_mode',
        'nat-pmp.external_port',
        'zbee_zcl.attr.float',
        'wpan-tap.phr.fsk_ms.mode',
        'mysql.exec_flags',
        'pim.metric_pref',
        'modbus.regval_float',
        'alcap.cau.value',
        'bpv7.crc_field',
        'at.chld.mode',
        'btl2cap.psm',
        'srvloc.srvtypereq.nameauthlistlen',
        'a11.ext.code',
        'adwin_config.port',
        'afp.unknown',
        'ansi_a_bsmap.mid.digit_1',
        'ber.unknown.OCTETSTRING',
        'btatt.handle',
        'btl2cap.option_flushto',
        'cip.network_segment.prod_inhibit',
        'cql.result.rows.table_name',
        'dcom.sa.vartype',
        'f5ethtrailer.slot',
        'ipdr.cm_ipv6_addr',
        'mojito.kuid',
        'mtp3.priority',
        'pw.cw.length',
        'rlc.ciphered_data',
        'vp8.pld.pictureid',
        'gryphon.sched.channel',
        'pn_io.ioxs',
        'pn_dcp.block_qualifier_reset',
        'pn_dcp.suboption_device_instance',
        'nfs.attr',
        'nfs.create_session_flags',
        'rmt-lct.toi64',
        'gryphon.data.header_length',
        'quake2.game.client.command.move.movement',
        'isup.parameter_type',
        'cip.port',
        'adwin.fifo_no',
        'bthci_evt.hci_vers_nr',
        'gryphon.usdt.stmin_active',
        'dnp3.al.anaout.int',
        'dnp3.al.ana.int',
        'dnp3.al.cnt',
        'bthfp.chld.mode',
        'nat-pmp.pml',
        'isystemactivator.actproperties.ts.hdr',
        'rtpdump.txt_addr',
        'unistim.vocoder.id',
        'mac.ueid',
        'cip.symbol.size',
        'dnp3.al.range.start',
        'dnp3.al.range.stop',
        'gtpv2.mp',
        'gvcp.cmd.resend.firstpacketid',
        'gvcp.cmd.resend.lastpacketid',
        'wlan.bf.reserved',
        'opa.sa.reserved',
        'rmt-lct.ext_tol_transfer_len',
        'pn_io.error_code2',
        'gryphon.ldf.schedsize',
        'wimaxmacphy.burst_opt_mimo_matrix_indicator',
        'ccsds.packet_type',
        'iso15765.flow_control.stmin',
        'msdo.PieceSize',
        'opa.clasportinfo.redirect.reserved',
        'p_mul.unused',
        'opa.pm.dataportcounters.reserved',
        'opa.switchinfo.switchcapabilitymask.reserved',
        'nvme-rdma.read_from_host_resp',
        'nvme-rdma.write_to_host_req',
        'netlink-route.ifla_linkstats.rx_errors.fifo_errs',
        'mtp3mg.japan_spare',
        'ixveriwave.errors.ip_checksum_error',
        'bpsec.asb.result_count',
        'btle.control.phys.le_coded_phy',
        'gsm_rlcmac.ul.gprs_multislot_class_exist',
        'tpm.resp.size',
        'sasp.flags.quiesce'
    }
    if filter in ignore_filters:
        return True


    ignore_patterns = [
        re.compile(r'^nstrace.trcdbg.val(\d+)'),
        re.compile(r'^mpls_pm.timestamp\d\..*'),
        re.compile(r'alcap.*bwt.*.[b|f]w'),
        re.compile(r'btle.control.phys.le_[1|2]m_phy'),
        re.compile(r'ansi_a_bsmap.cm2.scm.bc_entry.opmode[0|1]'),
    ]
    for patt in ignore_patterns:
        if patt.match(filter):
            return True

    return False


class ValueString:
    def __init__(self, file, name, vals, macros, do_extra_checks=False):
        self.file = file
        self.name = name
        self.raw_vals = vals
        self.parsed_vals = {}
        self.seen_labels = set()
        self.valid = True
        self.min_value =  99999
        self.max_value = -99999

        # Now parse out each entry in the value_string
        matches = re.finditer(r'\{\s*([0-9_A-Za-z]*)\s*,\s*(".*?")\s*}\s*,', self.raw_vals)
        for m in matches:
            value,label = m.group(1), m.group(2)
            if value in macros:
                value = macros[value]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in value):
                self.valid = False
                return

            try:
                # Read according to the appropriate base.
                if value.lower().startswith('0x'):
                    value = int(value, 16)
                elif value.startswith('0b'):
                    value = int(value[2:], 2)
                elif value.startswith('0'):
                    value = int(value, 8)
                else:
                    value = int(value, 10)
            except Exception:
                return

            global warnings_found

            # Check for value conflict before inserting
            if do_extra_checks and value in self.parsed_vals and label == self.parsed_vals[value]:
                print('Warning:', self.file, ': value_string', self.name, '- value ', value, 'repeated with same string - ', label)
                warnings_found += 1

            if value in self.parsed_vals and label != self.parsed_vals[value]:
                print('Warning:', self.file, ': value_string', self.name, '- value ', value, 'repeated with different values - was',
                    self.parsed_vals[value], 'now', label)
                warnings_found += 1
            else:
                # Add into table, while checking for repeated label
                self.parsed_vals[value] = label
                if do_extra_checks and label in self.seen_labels:
                    # These are commonly repeated..
                    exceptions = [ 'reserved', 'invalid', 'unused', 'not used', 'unknown', 'undefined', 'spare',
                                   'unallocated', 'not assigned', 'implementation specific', 'unspecified',
                                   'other', 'for further study', 'future', 'vendor specific', 'obsolete', 'none',
                                   'shall not be used', 'national use', 'unassigned', 'oem', 'user defined',
                                   'manufacturer specific', 'not specified', 'proprietary', 'operator-defined',
                                   'dynamically allocated', 'user specified', 'xxx', 'default', 'planned', 'not req',
                                   'deprecated', 'not measured', 'unspecified', 'nationally defined', 'nondisplay', 'general',
                                   'tbd' ]
                    excepted = False
                    for ex in exceptions:
                        if label.lower().find(ex) != -1:
                            excepted = True
                            break

                    if not excepted and len(label)>2:
                        print('Warning:', self.file, ': value_string', self.name, '- label ', label, 'repeated')
                        warnings_found += 1
                else:
                    self.seen_labels.add(label)

                if value > self.max_value:
                    self.max_value = value
                if value < self.min_value:
                    self.min_value = value

    def extraChecks(self):
        global warnings_found

        # Look for one value missing in range (quite common...)
        num_items = len(self.parsed_vals)
        span = self.max_value - self.min_value + 1
        if num_items > 4 and span > num_items and (span-num_items <=1):
            for val in range(self.min_value, self.max_value):
                if val not in self.parsed_vals:
                    print('Warning:', self.file, ': value_string', self.name, '- value', val, 'missing?', '(', num_items, 'entries)')
                    global warnings_found
                    warnings_found += 1

        # Do most of the labels match the number?
        matching_label_entries = set()
        for val in self.parsed_vals:
            if self.parsed_vals[val].find(str(val)) != -1:
                # TODO: pick out multiple values rather than concat into wrong number
                parsed_value = int(''.join(d for d in self.parsed_vals[val] if d.isdecimal()))
                if val == parsed_value:
                    matching_label_entries.add(val)

        if len(matching_label_entries) >= 4 and len(matching_label_entries) > 0 and len(matching_label_entries) < num_items and len(matching_label_entries) >= num_items-1:
            # Be forgiving about first or last entry
            first_val = list(self.parsed_vals)[0]
            last_val =  list(self.parsed_vals)[-1]
            if first_val not in matching_label_entries or last_val not in matching_label_entries:
                return
            print('Warning:', self.file, ': value_string', self.name, 'Labels match value except for 1!', matching_label_entries, num_items, self)

        # Do all labels start with lower-or-upper char?
        startLower,startUpper = 0,0
        for val in self.parsed_vals:
            first_letter = self.parsed_vals[val][1]
            if first_letter.isalpha():
                if first_letter.isupper():
                    startUpper += 1
                else:
                    startLower += 1
        if startLower > 0 and startUpper > 0:
            if startLower+startUpper > 10 and (startLower <=3 or startUpper <=3):
                standouts = []
                if startLower < startUpper:
                    standouts += [self.parsed_vals[val] for val in self.parsed_vals if self.parsed_vals[val][1].islower()]
                if startLower > startUpper:
                    standouts += [self.parsed_vals[val] for val in self.parsed_vals if self.parsed_vals[val][1].isupper()]

                print('Note:', self.file, ': value_string', self.name, 'mix of upper', startUpper, 'and lower', startLower, standouts)


    def __str__(self):
        return  self.name + '= { ' + self.raw_vals + ' }'


class RangeStringEntry:
    def __init__(self, min, max, label):
        self.min = min
        self.max = max
        self.label = label

    def hides(self, min, max):
        return min >= self.min and max <= self.max

    def __str__(self):
        return '(' + str(self.min) + ', ' + str(self.max) + ') -> ' + self.label


class RangeString:
    def __init__(self, file, name, vals, macros, do_extra_checks=False):
        self.file = file
        self.name = name
        self.raw_vals = vals
        self.parsed_vals = []
        self.seen_labels = set()
        self.valid = True
        self.min_value =  99999
        self.max_value = -99999

        # Now parse out each entry in the value_string
        matches = re.finditer(r'\{\s*([0-9_A-Za-z]*)\s*,\s*([0-9_A-Za-z]*)\s*,\s*(".*?")\s*\}\s*,', self.raw_vals)
        for m in matches:
            min,max,label = m.group(1), m.group(2), m.group(3)
            if min in macros:
                min = macros[min]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in min):
                self.valid = False
                return
            if max in macros:
                max = macros[max]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in max):
                self.valid = False
                return

            try:
                # Read according to the appropriate base.
                if min.lower().startswith('0x'):
                    min = int(min, 16)
                elif min.startswith('0b'):
                    min = int(min[2:], 2)
                elif min.startswith('0'):
                    min = int(min, 8)
                else:
                    min = int(min, 10)

                if max.lower().startswith('0x'):
                    max = int(max, 16)
                elif max.startswith('0b'):
                    max = int(max[2:], 2)
                elif max.startswith('0'):
                    max = int(max, 8)
                else:
                    max = int(max, 10)
            except Exception:
                return

            # Now check what we've found.
            global warnings_found

            if min < self.min_value:
                self.min_value = min
            # For overall max value, still use min of each entry.
            # It is common for entries to extend to e.g. 0xff, but at least we can check for items
            # that can never match if we only check the min.
            if min > self.max_value:
                self.max_value = min

            # This value should not be entirely hidden by earlier entries
            for prev in self.parsed_vals:
                if prev.hides(min, max):
                    print('Warning:', self.file, ': range_string label', label, 'hidden by', prev)
                    warnings_found += 1

            # Min should not be > max
            if min > max:
                print('Warning:', self.file, ': range_string', self.name, 'entry', label, 'min', min, '>', max)
                warnings_found += 1

            # Check label.
            if label[1:-1].startswith(' ') or label[1:-1].endswith(' '):
                print('Warning:', self.file, ': range_string', self.name, 'entry', label, 'starts or ends with space')
                warnings_found += 1

            # OK, add this entry
            self.parsed_vals.append(RangeStringEntry(min, max, label))

        # TODO: mark as not valid if not all pairs were successfully parsed?

    def extraChecks(self):
        global warnings_found

        # if in all cases min==max, suggest value_string instead?
        could_use_value_string = True
        for val in self.parsed_vals:
            if val.min != val.max:
                could_use_value_string = False
                break
        if could_use_value_string:
            print('Warning:', self.file, ': range_string', self.name, 'could be value_string instead!')
            warnings_found += 1

        # TODO: can multiple values be coalesced into fewer?
        # TODO: Partial overlapping?



class StringString:
    def __init__(self, file, name, vals, macros, do_extra_checks=False):
        self.file = file
        self.name = name
        self.raw_vals = vals
        self.parsed_vals = {}

        terminated = False
        global errors_found

        # Now parse out each entry in the string_string
        matches = re.finditer(r'\{\s*(["0-9_A-Za-z\s\-]*?)\s*,\s*(["0-9_A-Za-z\s\-]*)\s*', self.raw_vals)
        for m in matches:
            key = m.group(1).strip()
            value = m.group(2).strip()
            if key in self.parsed_vals:
                print('Error:', self.file, ': string_string', self.name, 'entry', key, 'has been added twice (values',
                      self.parsed_vals[key], 'and now', value, ')')
                errors_found += 1

            else:
                self.parsed_vals[key] = value
                # TODO: Also allow key to be "0" ?
                if (key in { "NULL" }) and value == "NULL":
                    terminated = True

        if not terminated:
            print('Error:', self.file, ': string_string', self.name, "is not terminated with { NULL, NULL }")
            errors_found += 1

    def extraChecks(self):
        pass
        # TODO: ?



# Look for value_string entries in a dissector file.  Return a dict name -> ValueString
def findValueStrings(filename, macros, do_extra_checks=False):
    vals_found = {}

    #static const value_string radio_type_vals[] =
    #{
    #    { 0,      "FDD"},
    #    { 1,      "TDD"},
    #    { 0, NULL }
    #};

    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches =   re.finditer(r'.*const value_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9_\-\*\#\.:\/\(\)\'\s\"]*)\};', contents)
        for m in matches:
            name = m.group(1)
            vals = m.group(2)
            vals_found[name] = ValueString(filename, name, vals, macros, do_extra_checks)

    return vals_found

# Look for range_string entries in a dissector file.  Return a dict name -> RangeString
def findRangeStrings(filename, macros, do_extra_checks=False):
    vals_found = {}

    #static const range_string symbol_table_shndx_rvals[] = {
    #    { 0x0000, 0x0000,  "Undefined" },
    #    { 0x0001, 0xfeff,  "Normal Section" },
    #    { 0, 0, NULL }
    #};

    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches =   re.finditer(r'.*const range_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9_\-\*\#\.:\/\(\)\'\s\"]*)\};', contents)
        for m in matches:
            name = m.group(1)
            vals = m.group(2)
            vals_found[name] = RangeString(filename, name, vals, macros, do_extra_checks)

    return vals_found

# Look for string_string entries in a dissector file.  Return a dict name -> StringString
def findStringStrings(filename, macros, do_extra_checks=False):
    vals_found = {}

    #static const string_string ice_candidate_types[] = {
    #    { "host",       "Host candidate" },
    #    { "srflx",      "Server reflexive candidate" },
    #    { 0, NULL }
    #};

    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches =   re.finditer(r'.*const string_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9_\-\*\#\.:\/\(\)\'\s\"]*)\};', contents)
        for m in matches:
            name = m.group(1)
            vals = m.group(2)
            vals_found[name] = StringString(filename, name, vals, macros, do_extra_checks)

    return vals_found


# The relevant parts of an hf item.  Used as value in dict where hf variable name is key.
class Item:

    # Keep the previous few items
    previousItems = []

    def __init__(self, filename, hf, filter, label, item_type, display, strings, macros,
                 value_strings, range_strings,
                 mask=None, check_mask=False, mask_exact_width=False, check_label=False,
                 check_consecutive=False, blurb=''):
        self.filename = filename
        self.hf = hf
        self.filter = filter
        self.label = label
        self.blurb = blurb
        self.mask = mask
        self.strings = strings
        self.mask_exact_width = mask_exact_width

        global warnings_found, errors_found

        if blurb == '0':
            print('Error:', filename, hf, ': - filter "' + filter +
                '" has blurb of 0 - if no string, please set NULL instead')
            errors_found += 1

        self.set_mask_value(macros)

        if check_consecutive:
            for previous_index,previous_item in enumerate(Item.previousItems):
                if previous_item.filter == filter:
                    if label != previous_item.label:
                        if not is_ignored_consecutive_filter(self.filter):
                            print('Warning:', filename, hf, ': - filter "' + filter +
                                '" appears ' + str(previous_index+1) + ' items before - labels are "' + previous_item.label + '" and "' + label + '"')
                            warnings_found += 1

            # Add this one to front of (short) previous list
            Item.previousItems = [self] + Item.previousItems
            if len(Item.previousItems) > 5:
                # Get rid of oldest one now
                #Item.previousItems = Item.previousItems[:-1]
                Item.previousItems.pop()

        self.item_type = item_type

        self.display = display
        self.set_display_value(macros)

        # Optionally check label (short and long).
        if check_label:
            self.check_label(label, 'label')
            #self.check_label(blurb, 'blurb')
            self.check_blurb_vs_label()

        # Optionally check that mask bits are contiguous
        if check_mask:
            if self.mask_read and mask not in { 'NULL', '0x0', '0', '0x00' }:
                self.check_contiguous_bits(mask)
                self.check_num_digits(self.mask)
                # N.B., if last entry in set is removed, see around 18,000 warnings
                self.check_digits_all_zeros(self.mask)

        # N.B. these checks are already done by checkApis.pl
        if strings.find('RVALS') != -1 and display.find('BASE_RANGE_STRING') == -1:
            print('Warning: ' + filename, hf, 'filter "' + filter + ' strings has RVALS but display lacks BASE_RANGE_STRING')
            warnings_found += 1

        # For RVALS, is BASE_RANGE_STRING also set (checked by checkApis.pl)?
        if strings.find('VALS_EXT_PTR') != -1 and display.find('BASE_EXT_STRING') == -1:
            print('Warning: ' + filename, hf, 'filter "' + filter + ' strings has VALS_EXT_PTR but display lacks BASE_EXT_STRING')
            warnings_found += 1

        # For VALS, lookup the corresponding ValueString and try to check range.
        vs_re = re.compile(r'VALS\(([a-zA-Z0-9_]*)\)')
        m = vs_re.search(strings)
        if m:
            self.vs_name = m.group(1)
            if self.vs_name in value_strings:
                vs = value_strings[self.vs_name]
                self.check_value_string_range(vs.min_value, vs.max_value)

        # For RVALS, lookup the corresponding RangeString and try to check range.
        rs_re = re.compile(r'RVALS\(([a-zA-Z0-9_]*)\)')
        m = rs_re.search(strings)
        if m:
            self.rs_name = m.group(1)
            if self.rs_name in range_strings:
                rs = range_strings[self.rs_name]
                self.check_range_string_range(rs.min_value, rs.max_value)

        # Could/should this item be FT_FRAMENUM ?
        #if ((self.label.lower().find(' frame') != -1 or self.label.lower().find('frame ') != -1) and self.label.lower().find('frames') == -1 and
        #    (self.label.lower().find('in') != -1 or self.label.lower().find('for') != -1) and
        #    self.item_type == 'FT_UINT32' and self.mask_value == 0x0):
        #    print('Warning: ' + self.filename, self.hf, 'filter "' + self.filter + '", label "' + label + '"', 'item type is', self.item_type, '- could be FT_FRANENUM?')
        #    warnings_found += 1


    def __str__(self):
        return 'Item ({0} {1} "{2}" {3} type={4}:{5} {6} mask={7})'.format(self.filename, self.hf, self.label, self.filter, self.item_type, self.display, self.strings, self.mask)

    def check_label(self, label, label_name):
        global warnings_found

        # TODO: this is masking a bug where the re for the item can't cope with macro for containing ',' for mask arg..
        if label.count('"') == 1:
            return

        if label.startswith(' ') or label.endswith(' '):
            print('Warning: ' + self.filename, self.hf, 'filter "' + self.filter, label_name,  '"' + label + '" begins or ends with a space')
            warnings_found += 1

        if (label.count('(') != label.count(')') or
            label.count('[') != label.count(']') or
            label.count('{') != label.count('}')):
            # Ignore if includes quotes, as may be unbalanced.
            if label.find("'") == -1:
                print('Warning: ' + self.filename, self.hf, 'filter "' + self.filter + '"', label_name, '"' + label + '"', 'has unbalanced parens/braces/brackets')
                warnings_found += 1
        if self.item_type != 'FT_NONE' and label.endswith(':'):
            print('Warning: ' + self.filename, self.hf, 'filter "' + self.filter + '"', label_name, '"' + label + '"', 'ends with an unnecessary colon')
            warnings_found += 1

    def check_blurb_vs_label(self):
        global warnings_found
        if self.blurb == "NULL":
            return

        # Is the label longer than the blurb?
        # Generated dissectors tend to write the type into the blurb field...
        #if len(self.label) > len(self.blurb):
        #    print('Warning:', self.filename, self.hf, 'label="' + self.label + '" blurb="' + self.blurb + '"', "- label longer than blurb!!!")

        # Is the blurb just the label in a different order?
        label_words = self.label.lower().split(' ')
        label_words.sort()
        blurb_words = self.blurb.lower().split(' ')
        blurb_words.sort()

        # Subset - often happens when part specific to that field is dropped
        if set(label_words) > set(blurb_words):
            print('Warning:', self.filename, self.hf, 'label="' + self.label + '" blurb="' + self.blurb + '"', "- words in blurb are subset of label words")
            warnings_found += 1

        # Just a re-ordering (but may also contain capitalization changes.)
        if blurb_words == label_words:
            print('Warning:', self.filename, self.hf, 'label="' + self.label + '" blurb="' + self.blurb + '"', "- blurb words are label words (re-ordered?)")
            warnings_found += 1

        # TODO: could have item know protocol name(s) from file this item was found in, and complain if blurb is just prot-name + label ?


    def set_mask_value(self, macros):
        try:
            self.mask_read = True
            # PIDL generator adds annoying parenthesis and spaces around mask..
            self.mask = self.mask.strip('() ')

            # Substitute mask if found as a macro..
            if self.mask in macros:
                self.mask = macros[self.mask]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in self.mask):
                self.mask_read = False
                self.mask_value = 0
                #print(self.filename, 'Could not read:', '"' + self.mask + '"')
                return

            # Read according to the appropriate base.
            if self.mask.startswith('0x'):
                self.mask_value = int(self.mask, 16)
            elif self.mask.startswith('0'):
                self.mask_value = int(self.mask, 8)
            else:
                self.mask_value = int(self.mask, 10)
        except Exception:
            self.mask_read = False
            self.mask_value = 0

        #if not self.mask_read:
        #    print('Could not read:', self.mask)


    def set_display_value(self, macros):
        try:
            self.display_read = True
            display = self.display

            # Substitute display if found as a macro..
            if display in macros:
                display = macros[display]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in display):
                self.display_read = False
                self.display_value = 0
                return

            # Read according to the appropriate base.
            if self.display.startswith('0x'):
                self.display_value = int(display, 16)
            elif self.display.startswith('0'):
                self.display_value = int(display, 8)
            else:
                self.display_value = int(display, 10)
        except Exception:
            self.display_read = False
            self.display_value = 0


    def check_value_string_range(self, vs_min, vs_max):
        item_width = self.get_field_width_in_bits()

        if item_width is None:
            # Type field defined by macro?
            return

        if self.mask_value > 0:
            # Distance between first and last '1'
            bitBools = bin(self.mask_value)[2:]
            mask_width = bitBools.rfind('1') - bitBools.find('1') + 1
        else:
            # No mask is effectively a full mask..
            mask_width = item_width

        item_max = (2 ** mask_width)
        if vs_max > item_max:
            global warnings_found
            print('Warning:', self.filename, self.hf, 'filter=', self.filter,
                  self.strings, "has max value", vs_max, '(' + hex(vs_max) + ')', "which doesn't fit into", mask_width, 'bits',
                  '( mask is', hex(self.mask_value), ')')
            warnings_found += 1

    def check_range_string_range(self, rs_min, rs_max):
        item_width = self.get_field_width_in_bits()

        if item_width is None:
            # Type field defined by macro?
            return

        if self.mask_value > 0:
            # Distance between first and last '1'
            bitBools = bin(self.mask_value)[2:]
            mask_width = bitBools.rfind('1') - bitBools.find('1') + 1
        else:
            # No mask is effectively a full mask..
            mask_width = item_width

        item_max = (2 ** mask_width)
        if rs_max > item_max:
            global warnings_found
            print('Warning:', self.filename, self.hf, 'filter=', self.filter,
                  self.strings, "has values", rs_min, rs_max, '(' + hex(rs_max) + ')', "which doesn't fit into", mask_width, 'bits',
                  '( mask is', hex(self.mask_value), ')')
            warnings_found += 1




    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    # Output a warning if non-contiguous bits are found in the mask (guint64).
    # Note that this legimately happens in several dissectors where multiple reserved/unassigned
    # bits are conflated into one field.
    # - there is probably a cool/efficient way to check this (+1 => 1-bit set?)
    def check_contiguous_bits(self, mask):
        if not self.mask_value:
            return

        # Do see legitimate non-contiguous bits often for these..
        if name_has_one_of(self.hf, ['reserved', 'unknown', 'unused', 'spare']):
            return
        if name_has_one_of(self.label, ['reserved', 'unknown', 'unused', 'spare']):
            return


        # Walk past any l.s. 0 bits
        n = 0
        while not self.check_bit(self.mask_value, n) and n <= 63:
            n += 1
        if n==63:
            return

        mask_start = n
        # Walk through any bits that are set
        while self.check_bit(self.mask_value, n) and n <= 63:
            n += 1
        n += 1

        if n >= 63:
            return

        # Look up the field width
        field_width = 0
        if self.item_type not in field_widths:
            print('unexpected item_type is ', self.item_type)
            field_width = 64
        else:
            field_width = self.get_field_width_in_bits()


        # Its a problem is the mask_width is > field_width - some of the bits won't get looked at!?
        mask_width = n-1-mask_start
        if field_width is not None and (mask_width > field_width):
            # N.B. No call, so no line number.
            print(self.filename + ':', self.hf, 'filter=', self.filter, self.item_type, 'so field_width=', field_width,
                  'but mask is', mask, 'which is', mask_width, 'bits wide!')
            global warnings_found
            warnings_found += 1
        # Now, any more zero set bits are an error!
        if self.filter in known_non_contiguous_fields or self.filter.startswith('rtpmidi'):
            # Don't report if we know this one is Ok.
            # TODO: also exclude items that are used as root in add_bitmask() calls?
            return
        while n <= 63:
            if self.check_bit(self.mask_value, n):
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - mask with non-contiguous bits',
                      mask, '(', hex(self.mask_value), ')')
                warnings_found += 1
                return
            n += 1

    def get_field_width_in_bits(self):
        if self.item_type == 'FT_BOOLEAN':
            if self.display == 'NULL':
                return 8  # i.e. 1 byte
            elif self.display == 'SEP_DOT':   # from proto.h, only meant for FT_BYTES
                return 64
            else:
                try:
                    # For FT_BOOLEAN, modifier is just numerical number of bits. Round up to next nibble.
                    return int((int(self.display) + 3)/4)*4
                except Exception:
                    return None
        else:
            if self.item_type in field_widths:
                # Lookup fixed width for this type
                return field_widths[self.item_type]
            else:
                return None

    def check_num_digits(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            global warnings_found
            global errors_found

            width_in_bits = self.get_field_width_in_bits()
            # Warn if odd number of digits.  TODO: only if >= 5?
            if len(mask) % 2  and self.item_type != 'FT_BOOLEAN':
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - mask has odd number of digits', mask,
                      'expected max for', self.item_type, 'is', int(width_in_bits/4))
                warnings_found += 1

            if self.item_type in field_widths:
                # Longer than it should be?
                if width_in_bits is None:
                    return
                if len(mask)-2 > width_in_bits/4:
                    extra_digits = mask[2:2+(len(mask)-2 - int(width_in_bits/4))]
                    # Its definitely an error if any of these are non-zero, as they won't have any effect!
                    if extra_digits != '0'*len(extra_digits):
                        print('Error:', self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len is", len(mask)-2,
                              "but type", self.item_type, " indicates max of", int(width_in_bits/4),
                              "and extra digits are non-zero (" + extra_digits + ")")
                        errors_found += 1
                    else:
                        # Has extra leading zeros, still confusing, so warn.
                        print('Warning:', self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len", len(mask)-2,
                              "but type", self.item_type, " indicates max of", int(width_in_bits/4))
                        warnings_found += 1

                # Strict/fussy check - expecting mask length to match field width exactly!
                # Currently only doing for FT_BOOLEAN, and don't expect to be in full for 64-bit fields!
                if self.mask_exact_width:
                    ideal_mask_width = int(width_in_bits/4)
                    if self.item_type == 'FT_BOOLEAN' and ideal_mask_width < 16 and len(mask)-2 != ideal_mask_width:
                        print('Warning:', self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len", len(mask)-2,
                                "but type", self.item_type, "|", self.display,  " indicates should be", int(width_in_bits/4))
                        warnings_found += 1

            else:
                # This type shouldn't have a mask set at all.
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - item has type', self.item_type, 'but mask set:', mask)
                warnings_found += 1

    def check_digits_all_zeros(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            if mask[2:] == '0'*(len(mask)-2):
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - item mask has all zeros - this is confusing! :', '"' + mask + '"')
                global warnings_found
                warnings_found += 1

    # A mask where all bits are set should instead be 0.
    # Exceptions might be where:
    # - in add_bitmask()
    # - represents flags, but dissector is not yet decoding them
    def check_full_mask(self, mask, field_arrays):
        if self.item_type == "FT_BOOLEAN":
            return
        if self.label.lower().find('mask') != -1 or self.label.lower().find('flag') != -1 or self.label.lower().find('bitmap') != -1:
            return
        if mask.startswith('0x') and len(mask) > 3:
            width_in_bits = self.get_field_width_in_bits()
            if not width_in_bits:
                return
            num_digits = int(width_in_bits / 4)
            if num_digits is None:
                return
            if mask[2:] == 'f'*num_digits   or   mask[2:] == 'F'*num_digits:
                # Don't report if appears in a 'fields' array
                for arr in field_arrays:
                    list = field_arrays[arr][0]
                    if self.hf in list:
                        # These need to have a mask - don't judge for being 0
                        return

                print('Note:', self.filename, self.hf, 'filter=', self.filter, " - mask is all set - if only want value (rather than bits), set 0 instead? :", '"' + mask + '"')

    # An item that appears in a bitmask set, needs to have a non-zero mask.
    def check_mask_if_in_field_array(self, mask, field_arrays):
        # Work out if this item appears in a field array
        found = False
        for arr in field_arrays:
            list = field_arrays[arr][0]
            if self.hf in list:
                # These need to have a mask - don't judge for being 0
                found = True
                break

        if found:
            # It needs to have a non-zero mask.
            if self.mask_read and self.mask_value == 0:
                print('Error:', self.filename, self.hf, 'is in fields array', arr, 'but has a zero mask - this is not allowed')
                global errors_found
                errors_found += 1



    # Return True if appears to be a match
    def check_label_vs_filter(self, reportError=True, reportNumericalMismatch=True):
        global warnings_found

        last_filter = self.filter.split('.')[-1]
        last_filter_orig = last_filter
        last_filter = last_filter.replace('-', '')
        last_filter = last_filter.replace('_', '')
        last_filter = last_filter.replace(' ', '')
        label = self.label
        label_orig = label
        label = label.replace(' ', '')
        label = label.replace('-', '')
        label = label.replace('_', '')
        label = label.replace('(', '')
        label = label.replace(')', '')
        label = label.replace('/', '')
        label = label.replace("'", '')


        # OK if filter is abbrev of label.
        label_words = self.label.split(' ')
        label_words = [w for w in label_words if len(w)]
        if len(label_words) == len(last_filter):
            #print(label_words)
            abbrev_letters = [w[0] for w in label_words]
            abbrev = ''.join(abbrev_letters)
            if abbrev.lower() == last_filter.lower():
                return True

        # If both have numbers, they should probably match!
        label_numbers =  [int(n) for n in re.findall(r'\d+', label_orig)]
        filter_numbers = [int(n) for n in re.findall(r'\d+', last_filter_orig)]
        if len(label_numbers) == len(filter_numbers) and label_numbers != filter_numbers:
            if reportNumericalMismatch:
                print('Note:', self.filename, self.hf, 'label="' + self.label + '" has different **numbers** from  filter="' + self.filter + '"')
                print(label_numbers, filter_numbers)
            return False

        # If they match after trimming number from filter, they should match.
        if label.lower() == last_filter.lower().rstrip("0123456789"):
            return True

        # Are they just different?
        if label.lower().find(last_filter.lower()) == -1:
            if reportError:
                print('Warning:', self.filename, self.hf, 'label="' + self.label + '" does not seem to match filter="' + self.filter + '"')
                warnings_found += 1
            return False

        return True

    def check_boolean_length(self):
        global errors_found
        # If mask is 0, display must be BASE_NONE.
        if self.item_type == 'FT_BOOLEAN' and self.mask_read and self.mask_value == 0 and self.display.find('BASE_NONE') == -1:
            print('Error:', self.filename, self.hf, 'type is FT_BOOLEAN, no mask set (', self.mask, ') - display should be BASE_NONE, is instead', self.display)
            errors_found += 1
        # TODO: check for length > 64?

    def check_string_display(self):
        global warnings_found
        if self.item_type in { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING'}:
            if self.display.find('BASE_NONE')==-1:
                print('Warning:', self.filename, self.hf, 'type is', self.item_type, 'display must be BASE_NONE, is instead', self.display)
                warnings_found += 1




    def check_ipv4_display(self):
        global errors_found
        if self.item_type == 'FT_IPv4' and self.display not in { 'BASE_NETMASK', 'BASE_NONE' }:
            print('Error:', self.filename, self.hf, 'type is FT_IPv4, should be BASE_NETMASK or BASE_NONE, is instead', self.display)
            errors_found += 1


class CombinedCallsCheck:
    def __init__(self, file, apiChecks):
        self.file = file
        self.apiChecks = apiChecks
        self.get_all_calls()

    def get_all_calls(self):
        self.all_calls = []
        # Combine calls into one list.
        for check in self.apiChecks:
            self.all_calls += check.calls

        # Sort by line number.
        self.all_calls.sort(key=lambda x:x.line_number)

    def check_consecutive_item_calls(self):
        lines = open(self.file, 'r', encoding="utf8").read().splitlines()

        prev = None
        for call in self.all_calls:

            # These names commonly do appear together..
            if name_has_one_of(call.hf_name, [ 'unused', 'unknown', 'spare', 'reserved', 'default']):
                return

            if prev and call.hf_name == prev.hf_name:
                # More compelling if close together..
                if call.line_number>prev.line_number and call.line_number-prev.line_number <= 4:
                    scope_different = False
                    for no in range(prev.line_number, call.line_number-1):
                        if lines[no].find('{') != -1 or lines[no].find('}') != -1 or lines[no].find('else') != -1 or lines[no].find('break;') != -1 or lines[no].find('if ') != -1:
                            scope_different = True
                            break
                    # Also more compelling if check for and scope changes { } in lines in-between?
                    if not scope_different:
                        print('Warning:', f + ':' + str(call.line_number),
                              call.hf_name + ' called consecutively at line', call.line_number, '- previous at', prev.line_number)
                        global warnings_found
                        warnings_found += 1
            prev = call




# These are APIs in proto.c that check a set of types at runtime and can print '.. is not of type ..' to the console
# if the type is not suitable.
apiChecks = []
apiChecks.append(APICheck('proto_tree_add_item_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_boolean', { 'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_display_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING',
                                                                                 'FT_STRINGZPAD', 'FT_STRINGZTRUNC', 'FT_BYTES', 'FT_UINT_BYTES'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_time_string', { 'FT_ABSOLUTE_TIME', 'FT_RELATIVE_TIME'}))
apiChecks.append(APICheck('proto_tree_add_uint', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format_value', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format_value', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_boolean64', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_float', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format_value', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_double', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format_value', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format_value', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_guid', { 'FT_GUID'}))
apiChecks.append(APICheck('proto_tree_add_oid', { 'FT_OID'}))
apiChecks.append(APICheck('proto_tree_add_none_format', { 'FT_NONE'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_varint', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                                                              'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM',
                                                              'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',}))
apiChecks.append(APICheck('proto_tree_add_boolean_bits_format_value', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_ascii_7bits_item', { 'FT_STRING'}))
# TODO: positions are different, and takes 2 hf_fields..
#apiChecks.append(APICheck('proto_tree_add_checksum', { 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_int64_bits_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))

# TODO: add proto_tree_add_bytes_item, proto_tree_add_time_item ?

bitmask_types = { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32',
                  'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32',
                  'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',
                  'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                   'FT_BOOLEAN'}
apiChecks.append(APICheck('proto_tree_add_bitmask', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_tree', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_ret_uint64', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_with_flags', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_with_flags_ret_uint64', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_value', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_value_with_flags', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_len', bitmask_types))
# N.B., proto_tree_add_bitmask_list does not have a root item, just a subtree...

add_bits_types = { 'FT_CHAR', 'FT_BOOLEAN',
                   'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',
                   'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                    'FT_BYTES'}
apiChecks.append(APICheck('proto_tree_add_bits_item',    add_bits_types))
apiChecks.append(APICheck('proto_tree_add_bits_ret_val', add_bits_types))

# TODO: doesn't even have an hf_item !
#apiChecks.append(APICheck('proto_tree_add_bitmask_text', bitmask_types))

# Check some ptvcuror calls too.
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}))


# Also try to check proto_tree_add_item() calls (for length)
apiChecks.append(ProtoTreeAddItemCheck())
apiChecks.append(ProtoTreeAddItemCheck(True)) # for ptvcursor_add()



def removeComments(code_string):
    code_string = re.sub(re.compile(r"/\*.*?\*/",re.DOTALL ) ,"" , code_string) # C-style comment
    code_string = re.sub(re.compile(r"//.*?\n" ) ,"" , code_string)             # C++-style comment
    code_string = re.sub(re.compile(r"#if 0.*?#endif",re.DOTALL ) ,"" , code_string) # Ignored region

    return code_string

# Test for whether the given file was automatically generated.
def isGeneratedFile(filename):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        return False

    # Open file
    f_read = open(os.path.join(filename), 'r', encoding="utf8")
    lines_tested = 0
    for line in f_read:
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if lines_tested > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Generated Automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False


# TODO: could also look for macros in related/included header file(s)?
def find_macros(filename):
    # Pre-populate with some useful values..
    macros = { 'BASE_NONE' : 0,  'BASE_DEC' : 1 }

    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches = re.finditer( r'#define\s*([A-Za-z0-9_]*)\s*([0-9xa-fA-F]*)\s*\n', contents)
        for m in matches:
            # Store this mapping.
            macros[m.group(1)] = m.group(2)

        # Also look for what could be enumeration assignments
        matches = re.finditer( r'\s*([A-Za-z0-9_]*)\s*=\s*([0-9xa-fA-F]*)\s*,?\n', contents)
        for m in matches:
            # Store this mapping.
            macros[m.group(1)] = m.group(2)

    return macros


# Look for hf items (i.e. full item to be registered) in a dissector file.
def find_items(filename, macros, value_strings, range_strings,
               check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False):
    is_generated = isGeneratedFile(filename)
    items = {}
    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        # N.B. re extends all the way to HFILL to avoid greedy matching
        # TODO: fix a problem where re can't cope with mask that involve a macro with commas in it...
        matches = re.finditer( r'.*\{\s*\&(hf_[a-z_A-Z0-9]*)\s*,\s*{\s*\"(.*?)\"\s*,\s*\"(.*?)\"\s*,\s*(.*?)\s*,\s*([0-9A-Z_\|\s]*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*([a-zA-Z0-9\W\s_\u00f6\u00e4]*?)\s*,\s*HFILL', contents)
        for m in matches:
            # Store this item.
            hf = m.group(1)

            blurb = m.group(8)
            if blurb.startswith('"'):
                blurb = blurb[1:-1]

            items[hf] = Item(filename, hf, filter=m.group(3), label=m.group(2), item_type=m.group(4),
                             display=m.group(5),
                             strings=m.group(6),
                             macros=macros,
                             value_strings=value_strings,
                             range_strings=range_strings,
                             mask=m.group(7),
                             blurb=blurb,
                             check_mask=check_mask,
                             mask_exact_width=mask_exact_width,
                             check_label=check_label,
                             check_consecutive=(not is_generated and check_consecutive))
    return items


# Looking for args to ..add_bitmask_..() calls that are not NULL-terminated or  have repeated items.
# TODO: some dissectors have similar-looking hf arrays for other reasons, so need to cross-reference with
# the 6th arg of ..add_bitmask_..() calls...
# TODO: return items (rather than local checks) from here so can be checked against list of calls for given filename
def find_field_arrays(filename, all_fields, all_hf):
    field_entries = {}
    global warnings_found
    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        # Find definition of hf array
        matches = re.finditer(r'static\s*g?int\s*\*\s*const\s+([a-zA-Z0-9_]*)\s*\[\]\s*\=\s*\{([a-zA-Z0-9,_\&\s]*)\}', contents)
        for m in matches:
            name = m.group(1)
            # Ignore if not used in a call to an _add_bitmask_ API
            if name not in all_fields:
                continue

            fields_text = m.group(2)
            fields_text = fields_text.replace('&', '')
            fields_text = fields_text.replace(',', '')

            # Get list of each hf field in the array
            fields = fields_text.split()

            if fields[0].startswith('ett_'):
                continue
            if fields[-1].find('NULL') == -1 and fields[-1] != '0':
                print('Warning:', filename, name, 'is not NULL-terminated - {', ', '.join(fields), '}')
                warnings_found += 1
                continue

            # Do any hf items reappear?
            seen_fields = set()
            for f in fields:
                if f in seen_fields:
                    print(filename, name, f, 'already added!')
                    warnings_found += 1
                seen_fields.add(f)

            # Check for duplicated flags among entries..
            combined_mask = 0x0
            for f in fields[0:-1]:
                if f in all_hf:
                    new_mask = all_hf[f].mask_value
                    if new_mask & combined_mask:
                        print('Warning:', filename, name, 'has overlapping mask - {', ', '.join(fields), '} combined currently', hex(combined_mask), f, 'adds', hex(new_mask))
                        warnings_found += 1
                    combined_mask |= new_mask

            # Make sure all entries have the same width
            set_field_width = None
            for f in fields[0:-1]:
                if f in all_hf:
                    new_field_width = all_hf[f].get_field_width_in_bits()
                    if set_field_width is not None and new_field_width != set_field_width:
                        # Its not uncommon for fields to be used in multiple sets, some of which can be different widths..
                        print('Note:', filename, name, 'set items not all same width - {', ', '.join(fields), '} seen', set_field_width, 'now', new_field_width)
                    set_field_width = new_field_width

            # Add entry to table
            field_entries[name] = (fields[0:-1], combined_mask)

    return field_entries

def find_item_declarations(filename):
    items = set()

    with open(filename, 'r', encoding="utf8") as f:
        lines = f.read().splitlines()
        p = re.compile(r'^static int (hf_[a-zA-Z0-9_]*)\s*\=\s*-1;')
        for line in lines:
            m = p.search(line)
            if m:
                items.add(m.group(1))
    return items

def find_item_extern_declarations(filename):
    items = set()
    with open(filename, 'r', encoding="utf8") as f:
        lines = f.read().splitlines()
        p = re.compile(r'^\s*(hf_[a-zA-Z0-9_]*)\s*\=\s*proto_registrar_get_id_byname\s*\(')
        for line in lines:
            m = p.search(line)
            if m:
                items.add(m.group(1))
    return items


def is_dissector_file(filename):
    p = re.compile(r'.*(packet|file)-.*\.c$')
    return p.match(filename)


def findDissectorFilesInFolder(folder, recursive=False):
    dissector_files = []

    if recursive:
        for root, subfolders, files in os.walk(folder):
            for f in files:
                if should_exit:
                    return
                f = os.path.join(root, f)
                dissector_files.append(f)
    else:
        for f in sorted(os.listdir(folder)):
            if should_exit:
                return
            filename = os.path.join(folder, f)
            dissector_files.append(filename)

    return [x for x in filter(is_dissector_file, dissector_files)]



# Run checks on the given dissector file.
def checkFile(filename, check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False,
              check_missing_items=False, check_bitmask_fields=False, label_vs_filter=False, extra_value_string_checks=False):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    # Find simple macros so can substitute into items and calls.
    macros = find_macros(filename)

    # Find (and sanity-check) value_strings
    value_strings = findValueStrings(filename, macros, do_extra_checks=extra_value_string_checks)
    if extra_value_string_checks:
        for name in value_strings:
            value_strings[name].extraChecks()

    # Find (and sanity-check) range_strings
    range_strings = findRangeStrings(filename, macros, do_extra_checks=extra_value_string_checks)
    if extra_value_string_checks:
        for name in range_strings:
            range_strings[name].extraChecks()

    # Find (and sanity-check) string_strings
    string_strings = findStringStrings(filename, macros, do_extra_checks=extra_value_string_checks)
    if extra_value_string_checks:
        for name in string_strings:
            string_strings[name].extraChecks()


    # Find important parts of items.
    items_defined = find_items(filename, macros, value_strings, range_strings,
                               check_mask, mask_exact_width, check_label, check_consecutive)
    items_extern_declared = {}

    items_declared = {}
    if check_missing_items:
        items_declared = find_item_declarations(filename)
        items_extern_declared = find_item_extern_declarations(filename)

    fields = set()

    # Get 'fields' out of calls
    for c in apiChecks:
        c.find_calls(filename, macros)
        for call in c.calls:
            # From _add_bitmask() calls
            if call.fields:
                fields.add(call.fields)

    # Checking for lists of fields for add_bitmask calls
    field_arrays = {}
    if check_bitmask_fields:
        field_arrays = find_field_arrays(filename, fields, items_defined)

    if check_mask and check_bitmask_fields:
        for i in items_defined:
            item = items_defined[i]
            item.check_full_mask(item.mask, field_arrays)
            item.check_mask_if_in_field_array(item.mask, field_arrays)

    # Now actually check the calls
    for c in apiChecks:
        c.check_against_items(items_defined, items_declared, items_extern_declared, check_missing_items, field_arrays)


    if label_vs_filter:
        matches = 0
        for hf in items_defined:
            if items_defined[hf].check_label_vs_filter(reportError=False, reportNumericalMismatch=True):
                matches += 1

        # Only checking if almost every field does match.
        checking = len(items_defined) and matches<len(items_defined) and ((matches / len(items_defined)) > 0.93)
        if checking:
            print(filename, ':', matches, 'label-vs-filter matches out of', len(items_defined), 'so reporting mismatches')
            for hf in items_defined:
                items_defined[hf].check_label_vs_filter(reportError=True, reportNumericalMismatch=False)

    for hf in items_defined:
        items_defined[hf].check_boolean_length()
        items_defined[hf].check_string_display()
        items_defined[hf].check_ipv4_display()



#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--folder', action='store', default='',
                    help='specify folder to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--mask', action='store_true',
                   help='when set, check mask field too')
parser.add_argument('--mask-exact-width', action='store_true',
                   help='when set, check width of mask against field width')
parser.add_argument('--label', action='store_true',
                   help='when set, check label field too')
parser.add_argument('--consecutive', action='store_true',
                    help='when set, copy copy/paste errors between consecutive items')
parser.add_argument('--missing-items', action='store_true',
                    help='when set, look for used items that were never registered')
parser.add_argument('--check-bitmask-fields', action='store_true',
                    help='when set, attempt to check arrays of hf items passed to add_bitmask() calls')
parser.add_argument('--label-vs-filter', action='store_true',
                    help='when set, check whether label matches last part of filter')
parser.add_argument('--extra-value-string-checks', action='store_true',
                    help='when set, do extra checks on parsed value_strings')
parser.add_argument('--all-checks', action='store_true',
                    help='when set, apply all checks to selected files')


args = parser.parse_args()

# Turn all checks on.
if args.all_checks:
    args.mask = True
    args.mask_exact_width = True
    args.consecutive = True
    args.check_bitmask_fields = True
    args.label = True
    args.label_vs_filter = True
    args.extra_value_string_checks

if args.check_bitmask_fields:
    args.mask = True


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.folder:
    # Add all files from a given folder.
    folder = args.folder
    if not os.path.isdir(folder):
        print('Folder', folder, 'not found!')
        exit(1)
    # Find files from folder.
    print('Looking for files in', folder)
    files = findDissectorFilesInFolder(folder, recursive=True)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', '--diff-filter=d', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Will examine dissector files only
    files = list(filter(lambda f : is_dissector_file(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only', '--diff-filter=d']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : is_dissector_file(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only', '--diff-filter=d']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : is_dissector_file(f), files_staged))
    for f in files_staged:
        if f not in files:
            files.append(f)
else:
    # Find all dissector files.
    files  = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))
    files += findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True)


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Now check the files.
for f in files:
    if should_exit:
        exit(1)
    checkFile(f, check_mask=args.mask, mask_exact_width=args.mask_exact_width, check_label=args.label,
              check_consecutive=args.consecutive, check_missing_items=args.missing_items,
              check_bitmask_fields=args.check_bitmask_fields, label_vs_filter=args.label_vs_filter,
              extra_value_string_checks=args.extra_value_string_checks)

    # Do checks against all calls.
    if args.consecutive:
        combined_calls = CombinedCallsCheck(f, apiChecks)
        # This hasn't really found any issues, but shows lots of false positives (and are difficult to investigate)
        #combined_calls.check_consecutive_item_calls()


# Show summary.
print(warnings_found, 'warnings')
if errors_found:
    print(errors_found, 'errors')
    exit(1)
