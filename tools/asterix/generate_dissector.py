#!/usr/bin/env python3
#
# By Boštjan Polanc <bostjan.polanc@gmail.com>
#
# Use asterix specifications in JSON format,
# to generate C/C++ structures, suitable for wireshark.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import math

def generate_header(gitrev):
    ret = """/* packet-asterix-generated.h
*
* Notice:
* This file is auto generated, do not edit!
* See tools/asterix/README.md for details.
*
"""
    ret += """* Data source: {}
""".format(gitrev)
    ret += """*
* Generated definitions for ASTERIX dissector
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "packet-asterix.h"

static int hf_asterix_category;
static int hf_asterix_length;
static int hf_asterix_record;
static int hf_asterix_fspec;
static int hf_asterix_fspec_bitstring;
static int hf_asterix_datablock;
static int hf_asterix_counter;
static int hf_asterix_possible_interpretation;
static int hf_asterix_possible_interpretations;
static int hf_asterix_spare;

static int ett_asterix_subtree;

"""
    return ret

field_array = []
expansion_variable_index = 0
expansion_variables = []
repetitive_function_counter = 0

def reverse_lookup(d, val):
    for a, b in d.items():
        if val == b:
            return a

def get_non_spare_from_data_item(db, cat, ed_major, ed_minor, data_item):
    for i in db.asterix:
        if (str(i[1][0]) == cat and str(i[1][1][0]) == ed_major and str(i[1][1][1]) == ed_minor):
            for data_field in i[1][2]:
                nonspare = reverse_lookup(db.nonspare, data_field)
                if (nonspare[0] == data_item):
                    return nonspare
    return None

value_maps = []
def add_value_map(value_map, code):
    for t in value_maps:
        if t[0] == value_map:
            return
    pair = (value_map, code, "value_map_" + str(value_map))
    value_maps.append(pair)
    return pair

def get_value_map(value_map):
    for t in value_maps:
        if t[0] == value_map:
            return t
    return None

def get_value_map(content_table_id, content):
    for t in value_maps:
        if t[0] == content_table_id:
            return t
    value_description = "value_map_" + str(content_table_id)
    value_map = "static const value_string " + value_description + "[] = {\n"
    for v in content[1]:
        value_map += '  { ' + str(v[0]) + ', "' + v[1] + '" },\n'
    value_map += '  { 0, NULL }\n'
    value_map += "};\n"
    return add_value_map(content_table_id, value_map)

def add_field_array(db, var_name, data_field, data_field_code, content_table_id = None, type = None, format = None, size = None):
    global expansion_variable_index
    unit = ""
    value_map = None
    content = None
    if (content_table_id != None):
        content = reverse_lookup(db.content, content_table_id)
        if (content[0] == "ContentQuantity" and type == None):
            unit = " [" + content[1][2] + "]"
            if (content[1][0] == 'Signed'):
                type = "FT_INT"
            else:
                type = "FT_UINT"
            type += str(size * 8)
            format = "BASE_DEC"
            if (content[1][1] != 0 and content[1][1] != 1):
                type = "FT_DOUBLE"
        elif (content[0] == "ContentInteger" and type == None):
            if (content[1] == 'Signed'):
                type = "FT_INT"
            else:
                type = "FT_UINT"
            type += str(size * 8)
            format = "BASE_DEC"
        elif (content[0] == "ContentRaw"):
            type = "FT_UINT8"
            format = "BASE_DEC"
        elif (content[0] == "ContentQuantity"):
            unit = " [" + content[1][2] + "]"
        elif (content[0] == "ContentString"):
            type = "FT_STRING"
            format = "BASE_NONE"
        elif (content[0] == "ContentTable"):
            value_map = get_value_map(content_table_id, content)
            type = "FT_UINT8"
            format = "BASE_DEC"
        elif (content[0] == "ContentBds"):
            type = "FT_BYTES"
            format = "BASE_NONE"
    expansion_variable_name = 'expand_var_' + str(expansion_variable_index)
    vals = "NULL"
    if (value_map != None):
        type = "FT_UINT8"
        format = "BASE_DEC"
        vals = "VALS(" + value_map[2] + ")"
    if (type == None):
        type = "FT_NONE"
    if (format == None):
        format = "BASE_NONE"
    field_array.append('{ &' + expansion_variable_name + ', { "' + data_field.strip() + unit + '", "asterix.' + data_field_code + '", ' + type + ', ' + format + ', ' + vals + ', 0x0, NULL, HFILL } }')
    expansion_variables.insert(0, expansion_variable_name)
    expansion_variable_index = expansion_variable_index + 1
    return expansion_variable_name

uap_index = 0

variation_functions = []
def add_variation_function(variation, function_name, function_declaration, var_name):
    for t in variation_functions:
        if t[0] == variation:
            return
    variation_functions.append((variation, function_name, function_declaration, var_name))

def get_variation_function(variation):
    for t in variation_functions:
        if t[0] == variation:
            return t
    return None

def parse_group(db, group, var_name, nonspare, bits_offset, sub_tree_name = "sub_tree", add_sub_tree = True, variable_counter = None, datafield_name = None):
    group_var_name =  var_name + '_group'
    items = ""
    initial_offset = bits_offset
    bits = bits_offset
    bytes_length = 0
    ret = ''
    if (variable_counter == None):
        variable_counter = 0
    group_counter = 0
    group_name = sub_tree_name + '_group_' + str(variable_counter)
    for var in group:
        description = ""
        item = reverse_lookup(db.item, var)
        variation = None
        if (item[0] == "Spare"):
            spare_length = item[1]
            spare_tree_name = sub_tree_name
            if (add_sub_tree):
                spare_tree_name = group_name
            spare_item_name = "spare_item_" + str(bits_offset)
            items += "  proto_item *" + spare_item_name + " = proto_tree_add_bits_item(" + spare_tree_name + ", hf_asterix_spare, tvb, (offset * 8) + " + str(bits_offset) + ", " + str(spare_length) + ", ENC_NA);\n"
            items += "  check_spare_bits (tvb, (offset * 8) + " + str(bits_offset) + ", " + str(spare_length) + ", " + spare_item_name + ");\n"
            bits_offset += spare_length
        else:
            item_nonspare = reverse_lookup(db.nonspare, item[1])
            ruleVariation = reverse_lookup(db.ruleVariation, item_nonspare[2])
            variation = reverse_lookup(db.variation, ruleVariation[1])
            if (variation[0] == "Element"):
                name = group_var_name + '_item_' + str(item_nonspare[0])
                description = item_nonspare[0]
                if (item_nonspare[1] != ""):
                    description += " : " + item_nonspare[1]
                ruleContent = reverse_lookup(db.ruleContent, variation[1][2])
                name = add_field_array(db, name, description, datafield_name, ruleContent[1], size = (int)(math.ceil(variation[1][1] / 8)))
                if (add_sub_tree):
                    items += data_field_add_element(db, variation, group_name, name, False, bits_offset)
                else:
                    items += data_field_add_element(db, variation, sub_tree_name, name, False, bits_offset)
                bits_offset += variation[1][1]
            elif (variation[0] == "Group"):
                var_name_tree = add_field_array(db, group_var_name, item_nonspare[0] + " : " + item_nonspare[1], datafield_name)
                res = parse_group(db, variation[1], var_name_tree, item_nonspare, bits_offset, group_name, variable_counter = group_counter + 1, datafield_name = datafield_name)
                items += res[0]
                bits_offset = res[1]
                group_counter = res[2]
    bits = bits_offset - bits
    bytes_length = int(bits / 8)
    if ((bits % 8) != 0):
        bytes_length += 1
    bytes_offset = int(initial_offset / 8)
    if ((initial_offset % 8) != 0):
        bytes_offset += 1
    if (add_sub_tree):
        if (sub_tree_name == "tree"):
            #first level, use expand_var
            ret += '  proto_item *' + sub_tree_name + '_group_item_' + str(variable_counter) + ' = proto_tree_add_item (' + sub_tree_name + ', expand_var, tvb, offset + ' + str(bytes_offset) + ', ' + str(bytes_length) + ', ENC_NA);\n'
        else:
            # sub-level, use nonspare description
            ret += '  proto_item *' + sub_tree_name + '_group_item_' + str(variable_counter) + ' = proto_tree_add_item (' + sub_tree_name + ', ' + var_name + ', tvb, offset + ' + str(bytes_offset) + ', ' + str(bytes_length) + ', ENC_NA);\n'
        ret += '  proto_tree *' + sub_tree_name + '_group_' + str(variable_counter) + ' = proto_item_add_subtree (' + sub_tree_name + '_group_item_' + str(variable_counter) + ', ett_asterix_subtree);\n'
    ret += items
    return (ret, bits_offset, variable_counter)

def data_field_add_field_array(db, nonspare, variation, var_name):
    var_name = var_name + '_' + variation[0].lower()
    if (variation[0] == "Element"):
        ruleContent = reverse_lookup(db.ruleContent, variation[1][2])
        data_field_size = int(variation[1][1] / 8)
        if (data_field_size == 0):
            # length less that 8 bits
            data_field_size = 1
        var_name = add_field_array(db, var_name, nonspare[0] + " : " + nonspare[1], var_name, ruleContent[1], size = data_field_size)
    else:
        var_name =  add_field_array(db, var_name, nonspare[0] + " : " + nonspare[1], var_name)
    return var_name

def add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask):
    ret = ""
    if (byte_end_bit_mask > 0):
        ret += "  " + variable_name + " = " + variable_name + " >> " + str(byte_end_bit_mask) + ";\n"
    if (byte_start_bits_mask > 0):
        bit_mask = "0b"
        for i in range(0, byte_start_bits_mask):
            bit_mask += "0"
        for i in range(0, bits):
            bit_mask += "1"
        ret += "  " + variable_name + " = " + variable_name + " & " + bit_mask + ";\n"
    return ret

def data_field_add_element(db, variation, sub_tree_name, name, add_sub_tree, bits_offset):
    if (bits_offset == None):
        bits_offset = 0
    ruleContent = reverse_lookup(db.ruleContent, variation[1][2])
    content = reverse_lookup(db.content, ruleContent[1])
    bits = variation[1][1]
    data_field_size = int((bits) / 8)
    if ((bits % 8) != 0):
        data_field_size = data_field_size + 1
    ret = ""
    byte_offset = (int)(bits_offset / 8)
    byte_start_bits_mask = (bits_offset % 8)
    byte_end_bit_mask = 8 - ((byte_start_bits_mask + bits) % 8)
    if (byte_end_bit_mask == 8):
        byte_end_bit_mask = 0
    expand_var = "expand_var"
    if (name != None):
        expand_var = name
    tree_name = "tree"
    if (sub_tree_name != None):
        tree_name = sub_tree_name
    variable_name = "value_" + name
    if (content[0] == "ContentQuantity"):
        if (data_field_size == 0):
            # length less that 8 bits
            data_field_size = 1
        if (content[0] == "ContentQuantity"):
            if (content[1][1] != 0 and content[1][1] != 1):
                ret += "  unsigned int " + variable_name + " = "
                if (content[1][0] == 'Unsigned'):
                    ret += "asterix_get_unsigned_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
                    ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
                    ret += "  double " + variable_name + "_d = (double)" + variable_name + " * " +  str(content[1][1]) + ";\n"
                else:
                    ret += "asterix_get_unsigned_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
                    ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
                    ret += "  int " + variable_name + "_s = get_signed_int(" + variable_name + ", " + str(bits) + ");\n"
                    ret += "  double " + variable_name + "_d = (double)" + variable_name + "_s * " +  str(content[1][1]) + ";\n"
                ret += "  proto_tree_add_double (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", " + variable_name + "_d);\n"
            elif (content[1][0] == 'Unsigned'):
                ret += "  unsigned int " + variable_name + " = "
                ret += "asterix_get_unsigned_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
                ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
                ret += "  proto_tree_add_uint (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", " + variable_name + ");\n"
            else:
                ret += "  int " + variable_name + " = "
                ret += "asterix_get_signed_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
                ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
                ret += "  proto_tree_add_int (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", " + variable_name + ");\n"
    elif (content[0] == "ContentTable"):
        if (add_sub_tree == True):
            ret += "  proto_tree_add_item(" + tree_name + ", " + expand_var + ", tvb, offset, " + str(data_field_size) + ", ENC_BIG_ENDIAN);\n"
        else:
            ret += "  proto_tree_add_bits_item(" + tree_name + ", " + expand_var + ", tvb, (offset * 8) + " + str(bits_offset) + ", " + str(bits) + ", ENC_BIG_ENDIAN);\n"
    elif (content[0] == "ContentInteger"):
        if (content[1] == "Unsigned"):
            ret += "  unsigned int " + variable_name + " = "
            ret += "asterix_get_unsigned_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
            ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
            ret += "  proto_tree_add_uint (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", " + variable_name + ");\n"
        else:
            ret += "  int " + variable_name + " = "
            ret += "asterix_get_signed_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
            ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
            ret += "  proto_tree_add_int (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", " + variable_name + ");\n"
    elif (content[0] == "ContentString"):
        if (content[1] == "StringOctal"):
            ret += "  print_octal_string (tvb, offset + " + str(byte_offset) + ", " + str(byte_start_bits_mask) + ", " + str(bits) + ", " + str(data_field_size) + ", " + tree_name + ", " + expand_var + ");\n"
        elif (content[1] == 'StringAscii'):
            ret += "  proto_tree_add_item(" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size)  + ", ENC_ASCII | ENC_NA);\n"
        elif (content[1] == 'StringICAO'):
            ret += "  print_icao_string (tvb, offset + " + str(byte_offset) + ", " + str(byte_start_bits_mask) + ", " + str(bits) + ", " + str(data_field_size) + ", " + tree_name + ", " + expand_var + ");\n"
    elif (content[0] == "ContentBds"):
        ret += "  proto_tree_add_item (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", ENC_NA);\n"
    else:
        ret += "  unsigned int " + variable_name + " = asterix_get_unsigned_value (tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ");\n"
        ret += add_bit_mask(variable_name, byte_start_bits_mask, bits, bits_offset, byte_end_bit_mask)
        ret += "  proto_tree_add_uint (" + tree_name + ", " + expand_var + ", tvb, offset + " + str(byte_offset) + ", " + str(data_field_size) + ", " + variable_name + ");\n"
    return ret

def generate_re_datafield_function(db, cat, ed_major, ed_minor, data_field, data_field_index, fspec_len, name_suffix):
    nonspare = get_non_spare_from_data_item(db, cat, ed_major, ed_minor, data_field)
    ruleVariation = reverse_lookup(db.ruleVariation, nonspare[2])
    variation = reverse_lookup(db.variation, ruleVariation[1])
    var_name = cat + '_' + ed_major + '_' + ed_minor + '_' + str(data_field_index)
    var_name = data_field_add_field_array(db, nonspare, variation, var_name)

    ret = "static int "
    function_name = "dissect_cat_" + cat + "_ed_major_" + ed_major + "_ed_minor_" + ed_minor + "_datafield_" + str(data_field_index)
    if (name_suffix != None):
        function_name += name_suffix
    ret += function_name
    ret += "(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int expand_var) //RE\n"
    function_declaration = ret + ";\n"
    ret += "{\n"
    ret += '  int offset_start = offset;\n'
    ret += '  unsigned len = tvb_get_uint8(tvb, offset);\n'
    if (fspec_len == None):
        ret += '  (void)tree;(void)expand_var;\n'
        ret += '  offset+=len;\n'
    else:
        ret += '  proto_item *item = proto_tree_add_item (tree, expand_var, tvb, offset++, len, ENC_NA);\n'
        ret += '  proto_tree *sub_tree = proto_item_add_subtree (item, ett_asterix_subtree);\n'
        ret += '  offset+=asterix_parse_re_field (tvb, offset, sub_tree, ' + str(fspec_len) + ', '+ cat + ');\n'
    ret += '  return offset - offset_start;\n'
    ret += "}\n"
    return [ret, var_name]

def generate_uap_datafield_function(db, cat, ed_major, ed_minor, data_field, data_field_index, uap_index, variation = None, name_suffix = None, nonspare = None):
    global repetitive_function_counter
    data_field_size = 0
    pre_code = ""
    ret = "static int "
    function_name = "dissect_cat_" + cat + "_ed_major_" + ed_major + "_ed_minor_" + ed_minor + "_datafield_" + str(data_field_index)
    if (name_suffix != None):
        function_name += name_suffix
    ret += function_name
    ret += "(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int expand_var)"
    function_declaration = ret + ";\n"
    if (nonspare == None):
        nonspare = get_non_spare_from_data_item(db, cat, ed_major, ed_minor, data_field)
    if (variation == None):
        if (nonspare == None):
            return ["", None]
        ruleVariation = reverse_lookup(db.ruleVariation, nonspare[2])
        variation = reverse_lookup(db.variation, ruleVariation[1])
    uap = str(uap_index) #nonspare[0]
    uap_index += 1
    datafield_name = cat + '_' + ed_major + '_' + ed_minor + '_' + data_field
    if (name_suffix != None):
        datafield_name += name_suffix
    var_name = data_field_add_field_array(db, nonspare, variation, datafield_name)
    ret += " //" + str(data_field) + " " + str(var_name) + "\n"
    ret += "{\n"
    existing_function = get_variation_function(variation)
    if (existing_function != None):
        ret += '  return ' + existing_function[1] + '(tvb, offset, tree, expand_var);\n'
        ret += '}\n'
        return [ret, var_name]
    datafield_name += '_' + variation[0].lower()
    if (variation[0] == "Element"):
        ret += data_field_add_element(db, variation, None, "expand_var", True, None)
        data_field_size = (int)(variation[1][1] / 8)
        if (data_field_size == 0):
            data_field_size = 1
    elif (variation[0] == "Group"):
        parse_result = parse_group(db, variation[1], var_name, nonspare, 0, "tree", datafield_name = datafield_name)
        ret += parse_result[0]
        bits_offset = parse_result[1]
        if ((bits_offset % 8) != 0):
            bits_offset += 8 - (bits_offset % 8)
        data_field_size = int(bits_offset / 8)
    elif (variation[0] == "Repetitive"):
        variant = reverse_lookup(db.variation, variation[1][1])
        datafield = generate_uap_datafield_function(db, cat, ed_major, ed_minor, data_field, data_field_index, uap_index, variant, "_rep" + str(repetitive_function_counter), nonspare)
        if (datafield[0] != ""):
            pre_code += datafield[0]
        ret += '  int fun_len;\n'
        ret += '  unsigned offset_start = offset;\n'
        ret += '  proto_item *item = proto_tree_add_item (tree, expand_var, tvb, offset, 0, ENC_NA);\n'
        ret += '  proto_tree *sub_tree = proto_item_add_subtree (item, ett_asterix_subtree);\n'
        if (variation[1][0] == None):
            ret += '  while (true) {\n'
            ret += '    fun_len = dissect_cat_' + cat + '_ed_major_' + ed_major + '_ed_minor_' + ed_minor + '_datafield_' + str(data_field_index) + '_rep' + str(repetitive_function_counter) + '(tvb, offset, sub_tree, ' + str(datafield[1]) + ');\n'
            ret += '    if (fun_len == -1) {\n'
            ret += '      return -1;\n'
            ret += '    };\n'
            ret += '    offset += fun_len;\n'
            ret += '    if (asterix_extended_end(tvb, offset - 1)) break;\n'
            ret += '  }\n'
        else:
            ret += '  proto_tree_add_item (sub_tree, hf_asterix_counter, tvb, offset_start, 1, ENC_BIG_ENDIAN);\n'
            ret += '  unsigned repetitive_length = asterix_get_unsigned_value(tvb, offset, ' + str(variation[1][0]) + ');\n'
            ret += '  offset+=' + str(variation[1][0]) + ';\n'
            ret += '  for (unsigned i = 0; i < repetitive_length; i++)\n'
            ret += '  {\n'
            ret += '    fun_len = dissect_cat_' + cat + '_ed_major_' + ed_major + '_ed_minor_' + ed_minor + '_datafield_' + str(data_field_index) + '_rep' + str(repetitive_function_counter) + '(tvb, offset, sub_tree, ' + str(datafield[1]) + ');\n'
            ret += '    if (fun_len == -1) {\n'
            ret += '      return -1;\n'
            ret += '    };\n'
            ret += '    offset += fun_len;\n'
            ret += '  }\n'
        ret += '  proto_item_set_len(item, offset - offset_start);\n'
        data_field_size = 'offset - offset_start'
        repetitive_function_counter = repetitive_function_counter + 1
    elif (variation[0] == "Extended"):
        ruleVariation = reverse_lookup(db.ruleVariation, nonspare[2])
        ret += '  int offset_start = offset;\n'
        ret += '  proto_item *sub_tree = proto_tree_add_item (tree, expand_var, tvb, offset, 0, ENC_NA);\n'
        sub_tree_name = 'datablock_tree'
        ret +=   '  proto_tree *' + sub_tree_name + ' = proto_item_add_subtree (sub_tree, ett_asterix_subtree);\n'
        bit_name = ""
        bits = 0
        bytes_offset = 0
        bits_offset = 0
        goto_used = False
        for item in variation[1]:
            extended_item = reverse_lookup(db.item, item)
            if (extended_item != None):
                if (extended_item[0] == 'Item'):
                    extended_item_nonspare = reverse_lookup(db.nonspare, extended_item[1])
                    item_rv = reverse_lookup(db.ruleVariation, extended_item_nonspare[2])
                    content2 = reverse_lookup(db.variation, item_rv[1])
                    if (content2[0] == 'Element'):
                        bits_size = content2[1][1]
                        bytes_size = (int)(bits_size / 8)
                        if (bytes_size == 0):
                            bytes_size = 1
                        bit_name = datafield_name + "_" + extended_item_nonspare[0]
                        content_table_id = reverse_lookup(db.ruleContent, content2[1][2])[1]
                        description = ""
                        if (extended_item_nonspare[1] != ""):
                            description = '(' + extended_item_nonspare[1] + ')'
                        name = add_field_array(db, bit_name, extended_item_nonspare[0] + description, bit_name, content_table_id = content_table_id, size = bytes_size)
                        ret += data_field_add_element(db, content2, sub_tree_name, name, False, bits_offset)
                        bits_offset += bits_size
                    elif (content2[0] == 'Group'):
                        parse_result = parse_group(db, content2[1], var_name, nonspare, bits_offset, sub_tree_name, False, datafield_name = datafield_name)
                        ret += parse_result[0]
                        bits_offset = parse_result[1]
                        continue
                else:
                    #spare
                    spare_item_name = "spare_item_" + str(bytes_offset) + "_" + str(bits_offset)
                    ret += "  proto_item *" + spare_item_name + " = proto_tree_add_bits_item(" + sub_tree_name + ", hf_asterix_spare, tvb, (offset * 8) + " + str(bits_offset) + ", " + str(extended_item[1]) + ", ENC_NA);\n"
                    ret += "  check_spare_bits (tvb, (offset * 8) + " + str(bits_offset) + ", " + str(extended_item[1]) + ", " + spare_item_name + ");\n"
                    bits_offset += extended_item[1]
            else: #last extended item
                bit_name = datafield_name + '_' + nonspare[0] + "_FX_" + str(bits_offset)
                bit_name = add_field_array(db, bit_name, "FX", bit_name, type="FT_UINT8", format="BASE_DEC")
                ret += '  proto_tree_add_bits_item(' + sub_tree_name + ', ' + bit_name + ', tvb, (offset * 8) + ' + str(bits_offset) + ', 1, ENC_BIG_ENDIAN);\n'
                bits_offset += 1
                bytes_length = int(bits_offset / 8)
                if (bytes_length > 1):
                    ret += '  if (asterix_extended_end(tvb, offset + ' + str(bytes_length - 1) + '))\n'
                else:
                    ret += '  if (asterix_extended_end(tvb, offset))\n'
                if ((bits_offset % 8) != 0):
                    bytes_length += 1
                ret += '  {\n'
                ret += '    offset+=' + str(bytes_length) + ';\n'
                ret += '    goto end;\n'
                goto_used = True
                ret += '  }\n'
                ret += '  offset+=' + str(bytes_length) + ';\n'
                bytes_offset += bytes_length
                data_field_size = 'offset - offset_start'
                bits_offset = 0
        if (goto_used):
            ret += 'end:\n'
        data_field_size = 'offset - offset_start'
        ret += '  proto_item_set_len(sub_tree, ' + str(data_field_size) + ');\n'
    elif (variation[0] == "Compound"):
        bitIndex = 0
        compount = '  unsigned offset_start = offset;\n'
        compount += '  unsigned fspec_len = asterix_fspec_len (tvb, offset);\n'
        compount += '  proto_item *ti = proto_tree_add_item (tree, expand_var, tvb, offset, 0, ENC_NA);\n'
        compount += '  proto_tree *asterix_packet_tree = proto_item_add_subtree (ti, ett_asterix_subtree);\n'
        compount += '  asterix_dissect_fspec (tvb, offset, asterix_packet_tree);\n'
        compount += '  offset += fspec_len;\n'
        compount += '  if (!asterix_fspec_check (fspec_len, ' + str(len(variation[1])) + ', ti))\n'
        compount += '  {\n'
        compount += '    return -1;\n'
        compount += '  }\n'
        bitIndex = 0
        goto_used = False
        for item in variation[1]:
            if (((bitIndex + 1) % 8) == 0):
                compount += '  if (!asterix_field_exists (tvb, offset_start, ' + str(bitIndex) + '))\n'
                compount += '  {\n'
                compount += '    goto end;\n'
                goto_used = True
                compount += '  }\n'
                bitIndex = bitIndex + 1
            if (item == None):
                bitIndex = bitIndex + 1
            else:
                nonspare = reverse_lookup(db.nonspare, item)
                uap = nonspare[0] + ' : ' + nonspare[1]
                ruleVariation = reverse_lookup(db.ruleVariation, nonspare[2])
                compound_variation = reverse_lookup(db.variation, ruleVariation[1])
                fun_name = 'dissect_cat_' + cat + '_ed_major_' + ed_major + '_ed_minor_' + ed_minor + '_datafield_' + str(data_field_index) + "_" + str(item) + '_compound_' + str(item)
                existing_function = generate_uap_datafield_function(db, cat, ed_major, ed_minor, data_field, data_field_index, uap_index, compound_variation, "_" + str(item) + "_compound_" + str(item), nonspare)
                pre_code += existing_function[0]
                fun_var_name = existing_function[1]
                compount += '  if (asterix_field_exists (tvb, offset_start, ' + str(bitIndex) + '))\n'
                compount += '  {\n'
                compount += '    int fun_len = ' + fun_name + '(tvb, offset, asterix_packet_tree, ' + fun_var_name + ');\n'
                compount += '    if (fun_len == -1) {\n'
                compount += '      return -1;\n'
                compount += '    }\n'
                compount += '    offset += fun_len;\n'
                compount += '  }\n'
                bitIndex = bitIndex + 1
        ret += compount
        data_field_size = 'offset - offset_start'
        if (goto_used):
            ret += 'end:\n'
        ret += '  proto_item_set_len(ti, ' + str(data_field_size) + ');\n'
    elif (variation[0] == "Explicit"):
        ret += "  unsigned int bytes = asterix_get_unsigned_value(tvb , offset, 1);\n"
        ret += "  int len = 1 + bytes;\n"
        ret += '  proto_tree_add_item (tree, expand_var, tvb, offset, len, ENC_NA);\n'
        data_field_size = 'len'
    #else:
        #print(variation[0])
        #raise Exception("Unknown type.")
    ret += "  return " + str(data_field_size) + ";\n"
    ret += "}\n"
    add_variation_function(variation, function_name, function_declaration, var_name)
    return [pre_code + ret, var_name]

def get_fslen(db, cat, major, minor):
    latest = None
    for asterix in db.asterix:
        if (asterix[0] == 'AsterixExpansion'):
            if (str(asterix[1][0]) == cat):
                latest = str(asterix[1][2])
    return latest

def generate_uap(db, cat, uap, ed_major, ed_minor):
    ret = ""
    uap_index = 0
    table_name = "cat_" + cat  + "_ed_major_" + ed_major + "_ed_minor_" + ed_minor + "_" + uap[0].lower() + "_table"
    table_name_expand = "int* " + table_name + "_expand[] = {\n"
    for data_field in uap[1]:
        if (data_field == "RE"):
            fspec_len = get_fslen(db, cat, ed_major, ed_minor)
            data_field_function = generate_re_datafield_function(db, cat, ed_major, ed_minor, data_field, uap_index, fspec_len, name_suffix="_" + uap[0].lower())
        else:
            data_field_function = generate_uap_datafield_function(db, cat, ed_major, ed_minor, data_field, uap_index, uap_index, name_suffix="_" + uap[0].lower())
        ret += data_field_function[0]
        if (data_field_function[1] == None):
            table_name_expand += '  NULL,\n'
        else:
            table_name_expand += '  &' + data_field_function[1] + ", //" + data_field + "\n"
        uap_index = uap_index + 1
    table_name_expand = table_name_expand[:-2]
    table_name_expand += "\n};\n"
    ret += table_name_expand

    ret += "static const ttt " + table_name + "[] = {\n"
    index = 0
    for item in uap[1]:
        if (item != None):
            ret += "  &dissect_cat_" + cat + "_ed_major_" + ed_major + "_ed_minor_" + ed_minor + "_datafield_" + str(index) + "_" + uap[0].lower() + ", //" + item + "\n"
        else:
            ret += "  NULL,\n"
        index = index + 1
    ret = ret[:-2]
    ret += "\n};\n"
    return ret

def generate_table_entry(cat, ed_major, ed_minor, asterix, uap, first):
    table = ""
    line = "  "
    if (first == False):
        line += "else "
    line += "if (cat == " + cat + " && ed == value_" + cat + "_" + ed_major + "_" + ed_minor
    if (uap != None):
        line += " && uap == uap_" + cat + "_" + ed_major + "_" + ed_minor + "_" + uap[0].lower()
    else:
        uap = ""
    line += ")\n"
    table += line
    table += "  {\n"
    table += "    table->table_size = " + str(len(uap[1]) - 1) + ";\n"
    if (uap != None):
        table += '    snprintf(table->uap_name, sizeof(table->uap_name), "%s", ' + '"' + uap[0].lower() + '");\n'
    table += "    table->table_pointer = cat_" + cat + "_ed_major_" + str(asterix[1][1][0]) + "_ed_minor_" + str(asterix[1][1][1]) + "_" + uap[0].lower() + "_table;\n"
    table += "    table->table_pointer_expand = cat_" + cat + "_ed_major_" + str(asterix[1][1][0]) + "_ed_minor_" + str(asterix[1][1][1]) + "_" + uap[0].lower() + "_table_expand;\n"
    table += "  }\n"
    return table

def generate_uaps(db):
    ret = ""
    for asterix in db.asterix:
        cat = str(asterix[1][0])
        ed_major = str(asterix[1][1][0])
        ed_minor = str(asterix[1][1][1])
        if (asterix[0] == 'AsterixBasic'):
            uap = reverse_lookup(db.uap, asterix[1][3])
            if (uap[0] == "Uaps"):
                for uap in uap[1]:
                   ret += generate_uap(db, cat, uap, ed_major, ed_minor)
            else:
                ret += generate_uap(db, cat, uap, ed_major, ed_minor)
        else:
            table_name = "cat_" + cat  + "_ed_major_" + ed_major + "_ed_minor_" + ed_minor + "_uap_table_expansion"
            table_name_expand = "int* " + table_name + "_expand[] = {\n"
            table_name = "static const ttt " + table_name + "[] = {\n"
            index = 0
            for i in asterix[1][3]:
                non_spare = reverse_lookup(db.nonspare, i)
                datafield = generate_uap_datafield_function(db, cat, ed_major, ed_minor, "0", index, 0, nonspare=non_spare, name_suffix="_" + uap[0])
                ret += datafield[0]
                if (datafield[1] == None):
                    table_name_expand += '  NULL,\n'
                else:
                    table_name_expand += '  &' + datafield[1] + ',\n'
                table_name += "  &dissect_cat_" + cat + "_ed_major_" + ed_major + "_ed_minor_" + ed_minor + "_datafield_" + str(index) + "_" + uap[0] + ",\n"
                index = index + 1

            table_name_expand = table_name_expand[:-2]
            table_name_expand += "\n};\n"
            ret += table_name_expand
            table_name = table_name[:-2]
            table_name += "\n};\n"
            ret += table_name
    expansion_table = "static void get_expansion_table(unsigned int cat, int ed, table_params *table)\n{\n"
    uaps_table = "static void get_uap_tables(unsigned int cat, int ed, uap_table_indexes *indexes)\n{\n"
    uaps_enums = "static const enum uaps_enums_e {\n"
    uap_table = "static void get_category_uap_table(unsigned int cat, int ed, int uap, table_params *table)\n{\n"
    enum_index = 0
    if_statement_index = 0

    first_element = True
    for asterix in db.asterix:
        cat = str(asterix[1][0])
        ed_major = str(asterix[1][1][0])
        ed_minor = str(asterix[1][1][1])
        uap = reverse_lookup(db.uap, asterix[1][3])
        if (asterix[0] == 'AsterixBasic'):
            if (uap[0] == "Uaps"):
                first_enum = ""
                enum_index_start = enum_index
                for u in uap[1]:
                    uap_table += generate_table_entry(cat, ed_major, ed_minor, asterix, u, first_element)
                    enum = "uap_" + cat + "_" + ed_major + "_" + ed_minor + "_" + u[0].lower()
                    first_enum = enum
                    uaps_enums += "  " + enum + ",\n"
                    enum_index = enum_index + 1
                    first_element = False
                if (if_statement_index == 0):
                    uaps_table += "  if (cat == " + cat + " && ed == value_" + cat + "_" + ed_major + "_" + ed_minor + ")\n"
                else:
                    uaps_table += "  else if (cat == " + cat + " && ed == value_" + cat + "_" + ed_major + "_" + ed_minor + ")\n"
                uaps_table += "  {\n"
                uaps_table += "    indexes->start_index = " + str(enum_index_start) + ";\n"
                uaps_table += "    indexes->end_index = " + str(enum_index - 1) + ";\n"
                uaps_table += "  }\n"
            else:
                uap_table += generate_table_entry(cat, ed_major, ed_minor, asterix, uap, first_element)
                first_element = False
                if (if_statement_index == 0):
                    uaps_table += "  if (cat == " + cat + " && ed == value_" + cat + "_" + ed_major + "_" + ed_minor + ")\n"
                else:
                    uaps_table += "  else if (cat == " + cat + " && ed == value_" + cat + "_" + ed_major + "_" + ed_minor + ")\n"
                uaps_table += "  {\n"
                uaps_table += "    indexes->start_index = " + str(enum_index) + ";\n"
                uaps_table += "    indexes->end_index = " + str(enum_index) + ";\n"
                enum = "uap_" + cat + "_" + ed_major + "_" + ed_minor + "_uap"
                uaps_enums += "  " + enum + ",\n"
                uaps_table += "  }\n"
                enum_index = enum_index + 1
            if_statement_index = if_statement_index + 1
        else:
            expansion_table += "  if (cat == " + cat + " && ed == value_" + cat + "_" + ed_major + "_" + ed_minor + "_re)\n"
            expansion_table += "  {\n"
            expansion_table += "    table->table_size = " + str(len(asterix[1][3])) + ";\n"
            expansion_table += "    table->table_pointer = cat_" + cat + "_ed_major_" + str(asterix[1][1][0]) + "_ed_minor_" + str(asterix[1][1][1]) + "_uap_table_expansion;\n"
            expansion_table += "    table->table_pointer_expand = cat_" + cat + "_ed_major_" + str(asterix[1][1][0]) + "_ed_minor_" + str(asterix[1][1][1]) + "_uap_table_expansion_expand;\n"
            expansion_table += "  }\n"
    expansion_table += "  return;\n"
    uap_table += "  else\n  {\n"
    uap_table += "    table->table_size = 0;\n"
    uap_table += "    table->table_pointer = NULL;\n"
    uap_table += "    table->table_pointer_expand = NULL;\n"
    uap_table += "  }\n"
    uap_table += "}\n"
    expansion_table += "}"
    uaps_table += "  else\n  {\n"
    uaps_table += "    indexes->start_index = 0;\n"
    uaps_table += "    indexes->end_index = 0;\n"
    uaps_table += "  }\n"
    uaps_table += "  return;\n"
    uaps_table += "}\n"
    uaps_enums = uaps_enums[:-2]
    uaps_enums += "\n} uaps_enums;\n"
    ret += uaps_enums
    ret += uaps_table
    ret += uap_table
    ret += expansion_table

    return ret

def generate_field_array_table():
    ret = 'static hf_register_info hf[] = {\n'
    ret += '{ &hf_asterix_category, { "Category", "asterix.category", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_length,   { "Length", "asterix.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_fspec,    { "FSPEC", "asterix.fspec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_fspec_bitstring,    { "FSPEC", "asterix.fspec", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_datablock,{ "ASTERIX DATA BLOCK", "asterix.datablock", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_record,   { "RECORD", "asterix.record", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_counter,   { "Repetition", "asterix.counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_possible_interpretation,   { "Possible interpretation", "asterix.possible_interpretation", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_possible_interpretations,   { "Possible interpretations:", "asterix.possible_interpretations", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },\n'
    ret += '{ &hf_asterix_spare,   { "Spare bits", "asterix.spare_bit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },\n'

    for l in field_array:
        ret += l + ',\n'

    ret = ret[:-2]
    ret += '\n'
    ret += '};\n'
    return ret

def generate_expansion_variable():
    ret = ""
    for v in value_maps:
        ret += v[1]
    for e in expansion_variables:
        ret = "static int " + e + ";\n" + ret
    return ret

def generate_code(db):
    return generate_uaps(db)

def get_cat_from_list(cat, list):
    for category in list:
        if (category[0] == cat):
            return category
    return None

def generate_dissector_properties_code(db, cat):
    ret = ""
    dialog_table = ""

    re = ""
    basic = "true"
    if (cat[2] == False):
        re = "_re"
        basic = "false"

    enum_name = "value_cat_" + str(cat[0]) + re
    ed_enum = "static enum " + enum_name + "_e {\n"
    enums_name = "cat_" + str(cat[0]) + "_enum_vals" + re
    cat_enum = "static const enum_val_t " + enums_name + "[] = {\n"
    index = 0
    for ed in cat[1]:
        value_name = "value_" + str(cat[0]) + "_" + str(ed[0]) + "_" + str(ed[1]) + re
        ed_enum += '  ' + value_name + ',\n'
        cat_enum += '  {"cat_' + str(cat[0]) + '_ed_' + str(ed[0]) + "_" + str(ed[1]) + '", "edition_' + str(ed[0]) + "_" + str(ed[1]) + '", ' + value_name + '},\n'
        index += 1
        last_ed = value_name
    cat_enum += "  {NULL, NULL, 0}\n};\n\n"
    ed_enum = ed_enum[:-2]
    ed_enum += "\n} " + enum_name + ";\n"
    latest_ed = last_ed + "_default"
    defaults = "static int " + latest_ed + " = " + last_ed + ";\n"
    dialog_table = '  { ' + str(cat[0]) + ', (int*)&' + enum_name + ', &' + latest_ed + ', ' + enums_name + ', "cat_' + str(cat[0]) + re + '", ' + basic + ' },\n'

    ret += ed_enum
    ret += cat_enum
    ret += defaults
    return (ret, dialog_table)

def generate_dissector_properties(db):
    category_list = []
    expansion_list = []
    for asterix in db.asterix:
        cat = str(asterix[1][0])
        ed_major = str(asterix[1][1][0])
        ed_minor = str(asterix[1][1][1])
        if (asterix[0] == 'AsterixBasic'):
            uap = reverse_lookup(db.uap, asterix[1][3])
            category = get_cat_from_list(cat, category_list)
            if (category == None):
                category_list.append((cat, [(ed_major, ed_minor)], True))
            else:
                category[1].append((ed_major, ed_minor))
        else:
            uap = reverse_lookup(db.uap, asterix[1][2])
            expansion = get_cat_from_list(cat, expansion_list)
            if (expansion == None):
                expansion_list.append((cat, [(ed_major, ed_minor)], False))
            else:
                expansion[1].append((ed_major, ed_minor))

    ret = ""
    dialog_table = "dialog_cat_struct asterix_properties[] = {\n"
    for cat in category_list:
        cat_code = generate_dissector_properties_code(db, cat)
        ret += cat_code[0]
        dialog_table += cat_code[1]
        for cat_ex in expansion_list:
            if (cat[0] == cat_ex[0]):
                cat_code = generate_dissector_properties_code(db, cat_ex)
                ret += cat_code[0]
                dialog_table += cat_code[1]

    dialog_table = dialog_table[:-2]
    dialog_table += "\n};\n"
    ret += dialog_table
    return ret

def generate_file(gitrev, db):
    ret = generate_header(gitrev)
    code = generate_code(db)
    ret += generate_dissector_properties(db)
    ret += generate_expansion_variable()
    ret += generate_field_array_table()
    ret += code
    return ret
