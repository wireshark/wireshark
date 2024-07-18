#!/usr/bin/env python3
# Parses the nl80211.h interface and generate appropriate enums and fields
# (value_string) for packet-netlink-nl80211.c
#
# Copyright (c) 2017, Peter Wu <peter@lekensteyn.nl>
# Copyright (c) 2018, Mikael Kanstrup <mikael.kanstrup@sony.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
#
# To update the dissector source file, run this from the source directory:
#
#   python tools/generate-nl80211-fields.py --update
#

import argparse
import re
import requests
import sys

# Begin of comment, followed by the actual array definition
HEADER = "/* Definitions from linux/nl80211.h {{{ */\n"
FOOTER = "/* }}} */\n"
# Enums to extract from the header file
EXPORT_ENUMS = {
    # 'enum_name': ('field_name', field_type', 'field_blurb')
    'nl80211_commands': ('Command', 'FT_UINT8', '"Generic Netlink Command"'),
    'nl80211_attrs': (None, None, None),
    'nl80211_iftype': (None, None, None),
    'nl80211_sta_flags': (None, None, None),
    'nl80211_sta_p2p_ps_status': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_he_gi': (None, None, None),
    'nl80211_he_ltf': (None, None, None),
    'nl80211_he_ru_alloc': (None, None, None),
    'nl80211_eht_gi': (None, None, None),
    'nl80211_eht_ru_alloc': (None, None, None),
    'nl80211_rate_info': (None, None, None),
    'nl80211_sta_bss_param': (None, None, None),
    'nl80211_sta_info': (None, None, None),
    'nl80211_tid_stats': (None, None, None),
    'nl80211_txq_stats': (None, None, None),
    'nl80211_mpath_flags': (None, None, None),
    'nl80211_mpath_info': (None, None, None),
    'nl80211_band_iftype_attr': (None, None, None),
    'nl80211_band_attr': (None, None, None),
    'nl80211_wmm_rule': (None, None, None),
    'nl80211_frequency_attr': (None, None, None),
    'nl80211_bitrate_attr': (None, None, None),
    'nl80211_reg_initiator': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_reg_type': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_reg_rule_attr': (None, None, None),
    'nl80211_sched_scan_match_attr': (None, None, None),
    'nl80211_reg_rule_flags': (None, None, None),
    'nl80211_dfs_regions': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_user_reg_hint_type': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_survey_info': (None, None, None),
    'nl80211_mntr_flags': (None, None, None),
    'nl80211_mesh_power_mode': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_meshconf_params': (None, None, None),
    'nl80211_mesh_setup_params': (None, None, None),
    'nl80211_txq_attr': (None, None, None),
    'nl80211_ac': (None, None, None),
    'nl80211_channel_type': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_key_mode': (None, None, None),
    'nl80211_chan_width': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_bss_scan_width': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_bss_use_for': (None, None, None),
    'nl80211_bss_cannot_use_reasons': (None, None, None),
    'nl80211_bss': (None, None, None),
    'nl80211_bss_status': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_auth_type': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_key_type': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_mfp': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_wpa_versions': (None, None, None),
    'nl80211_key_default_types': (None, None, None),
    'nl80211_key_attributes': (None, None, None),
    'nl80211_tx_rate_attributes': (None, None, None),
    'nl80211_txrate_gi': (None, None, None),
    'nl80211_band': (None, None, None),
    'nl80211_ps_state': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_attr_cqm': (None, None, None),
    'nl80211_cqm_rssi_threshold_event': (None, None, None),
    'nl80211_tx_power_setting': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_tid_config': (None, None, None),
    'nl80211_tx_rate_setting': (None, None, None),
    'nl80211_tid_config_attr': (None, None, None),
    'nl80211_packet_pattern_attr': (None, None, None),
    'nl80211_wowlan_triggers': (None, None, None),
    'nl80211_wowlan_tcp_attrs': (None, None, None),
    'nl80211_attr_coalesce_rule': (None, None, None),
    'nl80211_coalesce_condition': (None, None, None),
    'nl80211_iface_limit_attrs': (None, None, None),
    'nl80211_if_combination_attrs': (None, None, None),
    'nl80211_plink_state': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_plink_action': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_rekey_data': (None, None, None),
    'nl80211_hidden_ssid': (None, None, None),
    'nl80211_sta_wme_attr': (None, None, None),
    'nl80211_pmksa_candidate_attr': (None, None, None),
    'nl80211_tdls_operation': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_ap_sme_features': (None, None, None),
    'nl80211_feature_flags': (None, None, None),
    'nl80211_ext_feature_index': (None, None, None),
    'nl80211_probe_resp_offload_support_attr': (None, None, None),
    'nl80211_connect_failed_reason': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_timeout_reason': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_scan_flags': (None, None, None),
    'nl80211_acl_policy': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_smps_mode': ('Attribute Value', 'FT_UINT8', None),
    'nl80211_radar_event': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_dfs_state': (None, None, None),
    'nl80211_protocol_features': (None, None, None),
    'nl80211_crit_proto_id': ('Attribute Value', 'FT_UINT16', None),
    'nl80211_rxmgmt_flags': (None, None, None),
    'nl80211_tdls_peer_capability': (None, None, None),
    'nl80211_sched_scan_plan': (None, None, None),
    'nl80211_bss_select_attr': (None, None, None),
    'nl80211_nan_function_type': (None, None, None),
    'nl80211_nan_publish_type': (None, None, None),
    'nl80211_nan_func_term_reason': (None, None, None),
    'nl80211_nan_func_attributes': (None, None, None),
    'nl80211_nan_srf_attributes': (None, None, None),
    'nl80211_nan_match_attributes': (None, None, None),
    'nl80211_external_auth_action': ('Attribute Value', 'FT_UINT32', None),
    'nl80211_ftm_responder_attributes': (None, None, None),
    'nl80211_ftm_responder_stats': (None, None, None),
    'nl80211_preamble': (None, None, None),
    'nl80211_peer_measurement_type': (None, None, None),
    'nl80211_peer_measurement_status': (None, None, None),
    'nl80211_peer_measurement_req': (None, None, None),
    'nl80211_peer_measurement_resp': (None, None, None),
    'nl80211_peer_measurement_peer_attrs': (None, None, None),
    'nl80211_peer_measurement_attrs': (None, None, None),
    'nl80211_peer_measurement_ftm_capa': (None, None, None),
    'nl80211_peer_measurement_ftm_req': (None, None, None),
    'nl80211_peer_measurement_ftm_failure_reasons': (None, None, None),
    'nl80211_peer_measurement_ftm_resp': (None, None, None),
    'nl80211_obss_pd_attributes': (None, None, None),
    'nl80211_bss_color_attributes': (None, None, None),
    'nl80211_iftype_akm_attributes': (None, None, None),
    'nl80211_fils_discovery_attributes': (None, None, None),
    'nl80211_unsol_bcast_probe_resp_attributes': (None, None, None),
    'nl80211_sae_pwe_mechanism': (None, None, None),
    'nl80211_sar_type': (None, None, None),
    'nl80211_sar_attrs': (None, None, None),
    'nl80211_sar_specs_attrs': (None, None, None),
    'nl80211_mbssid_config_attributes': (None, None, None),
    'nl80211_ap_settings_flags': (None, None, None),
    'nl80211_wiphy_radio_attrs': (None, None, None),
    'nl80211_wiphy_radio_freq_range': (None, None, None),
}
# File to be patched
SOURCE_FILE = "epan/dissectors/packet-netlink-nl80211.c"
# URL where the latest version can be found
URL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/nl80211.h"

def make_enum(name, values, expressions, indent):
    code = 'enum ws_%s {\n' % name
    for value, expression in zip(values, expressions):
        if expression and 'NL80211' in expression:
            expression = 'WS_%s' % expression
        if expression:
            code += '%sWS_%s = %s,\n' % (indent, value, expression)
        else:
            code += '%sWS_%s,\n' % (indent, value)

    code += '};\n'
    return code

def make_value_string(name, values, indent,):
    code = 'static const value_string ws_%s_vals[] = {\n' % name
    align = 40
    for value in values:
        code += indent + ('{ WS_%s,' % value).ljust(align - 1) + ' '
        code += '"%s" },\n' % value
    code += '%s{ 0, NULL }\n' % indent
    code += '};\n'
    code += 'static value_string_ext ws_%s_vals_ext =' % name
    code += ' VALUE_STRING_EXT_INIT(ws_%s_vals);\n' % name
    return code

def remove_prefix(prefix, text):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def make_hf_defs(name, indent):
    code = 'static int hf_%s;' % name
    return code

def make_hf(name, indent):
    (field_name, field_type, field_blurb) = EXPORT_ENUMS.get(name)
    field_abbrev = name

    # Fill in default values
    if not field_name:
        field_name = 'Attribute Type'
    if not field_type:
        field_type = 'FT_UINT16'
    if not field_blurb:
        field_blurb = 'NULL'

    # Special treatment of already existing field names
    rename_fields = {
        'nl80211_attrs': 'nl80211_attr_type',
        'nl80211_commands': 'nl80211_cmd'
    }
    if rename_fields.get(name):
        field_abbrev = rename_fields[name]
    field_abbrev = remove_prefix('nl80211_', field_abbrev)

    code = indent + indent + '{ &hf_%s,\n' % name
    code += indent*3 + '{ "%s", "nl80211.%s",\n' % (field_name, field_abbrev)
    code += indent*3 + '  %s, BASE_DEC | BASE_EXT_STRING,\n' % (field_type)
    code += indent*3 + '  VALS_EXT_PTR(&ws_%s_vals_ext), 0x00,\n' % (name)
    code += indent*3 + '  %s, HFILL },\n' % (field_blurb)
    code += indent + indent + '},'
    return code

def make_ett_defs(name, indent):
    code = 'static int ett_%s;' % name
    return code

def make_ett(name, indent):
    code = indent + indent + '&ett_%s,' % name
    return code

class EnumStore(object):
    __RE_ENUM_VALUE = re.compile(
        r'\s+?(?P<value>\w+)(?:\ /\*.*?\*\/)?(?:\s*=\s*(?P<expression>.*?))?(?:\s*,|$)',
        re.MULTILINE | re.DOTALL)

    def __init__(self, name, values):
        self.name = name
        self.values = []
        self.expressions = []
        self.active = True
        self.parse_values(values)


    def parse_values(self, values):
        for m in self.__RE_ENUM_VALUE.finditer(values):
            value, expression = m.groups()
            if value.startswith('NUM_'):
                break
            if value.endswith('_AFTER_LAST'):
                break
            if value.endswith('_LAST'):
                break
            if value.startswith('__') and value.endswith('_NUM'):
                break
            if expression and expression in self.values:
                # Skip aliases
                continue
            self.values.append(value)
            self.expressions.append(expression)

    def finish(self):
        return self.name, self.values, self.expressions

RE_ENUM = re.compile(
    r'enum\s+?(?P<enum>\w+)\s+?\{(?P<values>.*?)\}\;',
    re.MULTILINE | re.DOTALL)
RE_COMMENT = re.compile(r'/\*.*?\*/', re.MULTILINE | re.DOTALL)

def parse_header(content):
    # Strip comments
    content = re.sub(RE_COMMENT, '', content)

    enums = []
    for m in RE_ENUM.finditer(content):
        enum = m.group('enum')
        values = m.group('values')
        if enum in EXPORT_ENUMS:
            enums.append(EnumStore(enum, values).finish())

    return enums

def parse_source():
    """
    Reads the source file and tries to split it in the parts before, inside and
    after the block.
    """
    begin, block, end = '', '', ''
    parts = []
    # Stages: 1 (before block), 2 (in block, skip), 3 (after block)
    stage = 1
    with open(SOURCE_FILE) as f:
        for line in f:
            if line == FOOTER and stage == 2:
                stage = 3   # End of block
            if stage == 1:
                begin += line
            elif stage == 2:
                block += line
            elif stage == 3:
                end += line
            if line == HEADER and stage == 1:
                stage = 2   # Begin of block
            if line == HEADER and stage == 3:
                stage = 2   # Begin of next code block
                parts.append((begin, block, end))
                begin, block, end = '', '', ''

    parts.append((begin, block, end))
    if stage != 3 or len(parts) != 3:
        raise RuntimeError("Could not parse file (in stage %d) (parts %d)" % (stage, len(parts)))
    return parts

parser = argparse.ArgumentParser()
parser.add_argument("--update", action="store_true",
        help="Update %s as needed instead of writing to stdout" % SOURCE_FILE)
parser.add_argument("--indent", default=" " * 4,
        help="indentation (use \\t for tabs, default 4 spaces)")
parser.add_argument("header_file", nargs="?", default=URL,
        help="nl80211.h header file (use - for stdin or a HTTP(S) URL, "
             "default %(default)s)")

def main():
    args = parser.parse_args()

    indent = args.indent.replace("\\t", "\t")

    if any(args.header_file.startswith(proto) for proto in ('http:', 'https')):
        r = requests.get(args.header_file)
        r.raise_for_status()
        enums = parse_header(r.text)
    elif args.header_file == "-":
        enums = parse_header(sys.stdin.read())
    else:
        with open(args.header_file) as f:
            enums = parse_header(f.read())

    assert len(enums) == len(EXPORT_ENUMS), \
            "Could not parse data, found %d/%d results" % \
            (len(enums), len(EXPORT_ENUMS))

    code_enums, code_vals, code_hf_defs, code_ett_defs, code_hf, code_ett = '', '', '', '', '', ''
    for enum_name, enum_values, expressions in enums:
        code_enums += make_enum(enum_name, enum_values, expressions, indent) + '\n'
        code_vals += make_value_string(enum_name, enum_values, indent) + '\n'
        code_hf_defs += make_hf_defs(enum_name, indent) + '\n'
        code_ett_defs += make_ett_defs(enum_name, indent) + '\n'
        code_hf += make_hf(enum_name, indent) + '\n'
        code_ett += make_ett(enum_name, indent) + '\n'

    code_top = code_enums + code_vals + code_hf_defs + '\n' + code_ett_defs
    code_top = code_top.rstrip("\n") + "\n"

    code = [code_top, code_hf, code_ett]

    update = False
    if args.update:
        parts = parse_source()

        # Check if file needs update
        for (begin, old_code, end), new_code in zip(parts, code):
            if old_code != new_code:
                update = True
                break
        if not update:
            print("File is up-to-date")
            return
        # Update file
        with open(SOURCE_FILE, "w") as f:
            for (begin, old_code, end), new_code in zip(parts, code):
                f.write(begin)
                f.write(new_code)
                f.write(end)
        print("Updated %s" % SOURCE_FILE)
    else:
        for new_code in code:
            print(new_code)

if __name__ == '__main__':
    main()

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# tab-width: 8
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 tabstop=8 expandtab:
# :indentSize=4:tabSize=8:noTabs=true:
#
