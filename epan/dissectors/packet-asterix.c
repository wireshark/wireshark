/* packet-asterix.c
 * Routines for ASTERIX decoding
 *
 * By Boštjan Polanc <bostjan.polanc@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ASTERIX (All-purpose structured EUROCONTROL surveillances
 * information exchange) is a protocol/data format related to air traffic control.
 *
 * Specifications can be downloaded from:
 *  - https://www.eurocontrol.int/asterix (original specifications - in PDF)
 *  - https://zoranbosnjak.github.io/asterix-specs/ (structured version)
 */

#include <config.h>

#include "exceptions.h"
#include "packet-asterix.h"
#include "packet-asterix-generated.h"
#include "packet-tcp.h"

#define HEADER_LENGTH 3
#define ASTERIX_PORT 8600
#define MAX_INTERPRETATIONS 100
#define MAX_INTERPRETATION_DEPTH 30
#define MAX_FSPEC_BIT_LENGTH 1024
#define OCTAL_BIT_LENGTH 3
#define ICAO_BIT_LENGTH 6

static int proto_asterix;

static char fspec_bit_string[MAX_FSPEC_BIT_LENGTH];

static dissector_handle_t asterix_handle;
static dissector_handle_t asterix_tcp_handle;

static int ett_asterix;
static int ett_asterix_record;
static int ett_asterix_possible_interpretation;
static int ett_asterix_possible_interpretations;
static int ett_asterix_spare_error;

/* With invalid data (e.g. fuzz tests), to great of interpretation depth can cause "freezes",
   where search for interpretations can last a long time. By default depth is set to 15,
   which should never be a problem for random data. Users can select a higher depth.
*/
static unsigned selected_interpretations_depth = depth_15;

static unsigned int solution_count;
static int solutions[MAX_INTERPRETATIONS][MAX_INTERPRETATION_DEPTH + 1];

static unsigned asterix_get_unsigned_value(tvbuff_t *tvb, unsigned offset, unsigned bytes)
{
    switch (bytes)
    {
        case 1:
            return tvb_get_uint8(tvb, offset);
        case 2:
            return tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        case 3:
            return tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN);
        case 4:
            return tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
        default:
            return -1;
    }
}

static int asterix_get_signed_value(tvbuff_t *tvb, unsigned offset, unsigned bytes)
{
    switch (bytes)
    {
        case 1:
            return tvb_get_int8(tvb, offset);
        case 2:
            return tvb_get_int16(tvb, offset, ENC_BIG_ENDIAN);
        case 3:
            return tvb_get_int24(tvb, offset, ENC_BIG_ENDIAN);
        case 4:
            return tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
        default:
            return -1;
    }
}

// get signed integer from specified number of bits
static int get_signed_int(unsigned value, unsigned bits)
{
    int ret = 0;
    int sign = 1;
    if ((value >> (bits - 1) & 1))
    {
        sign = -1;
        value = ~value;
        value++;
    }

    unsigned int mask = 1;
    for (unsigned int i = 0; i < (bits - 1); i++)
    {
        if ((value >> i) & 1)
        {
            ret |= mask;
        }
        mask *= 2;
    }
    return ret * sign;
}

// test extended FX bit
static bool asterix_extended_end (tvbuff_t *tvb, unsigned offset)
{
  uint8_t val = tvb_get_uint8(tvb, offset);
  if ((val & 0x01) == 0)
  {
    return true;
  }
  else
  {
    return false;
  }
}

// test FSPEC bit
static bool asterix_field_exists (tvbuff_t *tvb, unsigned offset, unsigned bit_index)
{
    unsigned int byte_index = bit_index / 8;
    uint8_t value = tvb_get_uint8 (tvb, offset + byte_index);
    bit_index = bit_index % 8;
    return 0x80 == ( (value << bit_index) & 0x80);
}

// prints null terminated octal string
static void print_octal_string (tvbuff_t *tvb, unsigned offset, unsigned bit_offset, unsigned bit_size, unsigned byte_size, proto_tree *tree, int expand_var)
{
    if ((bit_size % OCTAL_BIT_LENGTH) != 0)
    {
        return;
    }
    unsigned count = bit_size / OCTAL_BIT_LENGTH;
    char buff[1024];
    if (count > (sizeof(buff) - 1))
    {
        return;
    }
    for (unsigned i = 0; i < count; i++)
    {
        uint8_t value = tvb_get_bits8(tvb, offset * 8 + bit_offset, OCTAL_BIT_LENGTH);
        bit_offset += OCTAL_BIT_LENGTH;

        buff[i] = value + 0x30;
    }
    buff[count] = 0;

    proto_tree_add_string(tree, expand_var, tvb, offset, byte_size, buff);
}

static char decode_icao_char(uint8_t x)
{
    if (x >= 0x01 && x <= 0x1A)
    {
        return 'A' + (x - 1);
    }
    else if (x == 0x20)
    {
        return ' ';
    }
    else if (x >= 0x30 && x <= 0x39)
    {
        return '0' + (x - 0x30);
    }
    return '?';
}

// prints null terminated ICAO string
static void print_icao_string (tvbuff_t *tvb, unsigned offset, unsigned bit_offset, unsigned bit_size, unsigned byte_size, proto_tree *tree, int expand_var)
{
    if ((bit_size % ICAO_BIT_LENGTH) != 0)
    {
        return;
    }
    unsigned count = bit_size / ICAO_BIT_LENGTH;
    char buff[1024];
    if (count > (sizeof(buff) - 1))
    {
        return;
    }
    for (unsigned i = 0; i < count; i++)
    {
        uint8_t value = tvb_get_bits8(tvb, offset * 8 + bit_offset, ICAO_BIT_LENGTH);
        bit_offset += ICAO_BIT_LENGTH;

        buff[i] = decode_icao_char(value);
    }
    buff[count] = 0;

    proto_tree_add_string(tree, expand_var, tvb, offset, byte_size, buff);
}

static void check_spare_bits (tvbuff_t *tvb, unsigned bit_offset, unsigned bit_size, proto_item *item)
{
    if (bit_size > (64 - bit_offset))
    {
        return;
    }
    uint64_t bits = tvb_get_bits64(tvb, bit_offset, bit_size, ENC_BIG_ENDIAN);
    if (bits != 0)
    {
        expert_add_info_format(NULL, item, &hf_asterix_spare_error, "Spare bit error");
    }
}

static unsigned asterix_fspec_len (tvbuff_t *tvb, unsigned offset)
{
    unsigned int i;
    unsigned int max_length = tvb_reported_length (tvb) - offset;
    for (i = 0; (tvb_get_uint8 (tvb, offset + i) & 1) && i < max_length; i++);
    return i + 1;
}

static bool asterix_fspec_check (unsigned fspec_len, unsigned list_length, proto_item *ti)
{
    unsigned fspec_expected_len = list_length / 7;
    if ((list_length % 7) != 0) {
        fspec_expected_len++;
    }
    if (fspec_len > fspec_expected_len) {
        expert_add_info_format(NULL, ti, &hf_asterix_fspec_error, "FSPEC error");
        return false;
    }
    return true;
}

static unsigned asterix_dissect_fspec (tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    unsigned fspec_len = asterix_fspec_len (tvb, offset);

    if (fspec_len > 4) {
        proto_tree_add_item (tree, hf_asterix_fspec, tvb, offset, fspec_len, ENC_NA);
    } else {
        unsigned value = asterix_get_unsigned_value(tvb, offset, fspec_len);
        unsigned fspec_bit_length = fspec_len * 9 + 1;
        memset(fspec_bit_string, 0, fspec_bit_length);
        unsigned str_index = 0;
        for (unsigned int i = 0; i < fspec_len * 8; i++) {
            fspec_bit_string[str_index] = (value & (1 << ((fspec_len * 8 - 1) - i))) ? '1' : '0';
            if (i > 0 && ((i + 1) % 8) == 0) {
                str_index++;
                fspec_bit_string[str_index] = ' ';
            }
            str_index++;
        }
        proto_tree_add_string_format_value (tree, hf_asterix_fspec_bitstring, tvb, offset, fspec_len, NULL, "%s", fspec_bit_string);
    }
    return fspec_len;
}

static unsigned asterix_parse_re_field (tvbuff_t *tvb, unsigned offset, proto_tree *tree, unsigned fspec_len, unsigned cat)
{
    unsigned i = 0;
    int start_offset = offset;
    offset+=fspec_len;

    unsigned int ed = -1;
    for (i = 0; i < sizeof(asterix_properties) / sizeof(asterix_properties[0]); i++)
    {
        dialog_cat_struct prop_cat = asterix_properties[i];
        if (prop_cat.cat == cat && !prop_cat.cat_basic)
        {
            ed = *prop_cat.cat_default_value;
        }
    }

    table_params table_p = {0};
    get_expansion_table(cat, ed, &table_p);

    i = 0;
    while (i < table_p.table_size) {
        if (asterix_field_exists(tvb, start_offset, i)) {
            int *expand = table_p.table_pointer_expand[i];
            int expand_value = -1;
            if (expand != NULL)
            {
                expand_value = *expand;
            }
            offset += table_p.table_pointer[i](tvb, offset, tree, expand_value);
        }
        i++;
    }
    return offset - start_offset;
}

static bool check_fspec_validity (tvbuff_t *tvb, unsigned offset, table_params *table)
{
    unsigned i = 0;
    unsigned fs_index = 0;
    while (fs_index < MAX_FSPEC_BIT_LENGTH && i < table->table_size) {
        if (((fs_index + 1) % 8) == 0) {
            if (!asterix_field_exists(tvb, offset, fs_index)) {
                // FSPEC end, all fields may not have been present, but thats ok
                return true;
            }
            fs_index++;
        }
        if (asterix_field_exists(tvb, offset, fs_index)) {
            if (table->table_pointer[i] == NULL) {
                // bit should not be set, FSPEC invalid
                return false;
            }
        }
        i++;
        fs_index++;
    }
    if (fs_index >= MAX_FSPEC_BIT_LENGTH) {
        return false;
    }
    unsigned fs_end_index = ((fs_index / 8) + 1) * 8 - 1;
    if (asterix_field_exists(tvb, offset, fs_end_index)) {
        // FSPEC should not go beyond current byte
        return false;
    }
    return true;
}

static int probe_possible_record (tvbuff_t *tvb, unsigned offset, unsigned int cat, unsigned int ed, unsigned int record)
{
    // use NULL pointer for proto_tree pointer, so that wireshark ignores all tree add calls
    proto_tree *asterix_packet_tree = NULL;

    int start_offset = offset;

    table_params table_p;
    get_category_uap_table(cat, ed, record, &table_p);

    if (table_p.table_pointer == NULL) {
        //unknown category, abort
        return -1;
    }
    if (!check_fspec_validity (tvb, start_offset, &table_p)) {
        return -1;
    }

    offset += asterix_dissect_fspec (tvb, offset, asterix_packet_tree);
    unsigned i = 0;
    unsigned fs_index = 0;
    while (i < table_p.table_size) {
        if (((fs_index + 1) % 8) == 0) {
            if (!asterix_field_exists(tvb, start_offset, fs_index)) {
                break;
            }
            fs_index++;
        }
        if (asterix_field_exists(tvb, start_offset, fs_index)) {
            int *expand = table_p.table_pointer_expand[i];
            int expand_value = -1;
            if (expand != NULL)
            {
                expand_value = *expand;
            }
            int fun_len = table_p.table_pointer[i](tvb, offset, asterix_packet_tree, expand_value);
            if (fun_len == -1) {
                return -1;
            }
            offset += fun_len;
        }
        i++;
        fs_index++;
    }
    return offset;
}

/* possible return values:
    0 success
    -1 to many interpretations
    -2 recursive depth limit breached
*/
// NOLINTNEXTLINE(misc-no-recursion)
static int probe_possible_records (tvbuff_t *tvb, packet_info *pinfo, int offset, int datablock_end, unsigned int cat, unsigned int ed, uap_table_indexes *indexes, unsigned int *stack, unsigned int depth)
{
    for (volatile unsigned int i = indexes->start_index; i <= indexes->end_index; i++)
    {
        volatile int new_offset = (int)offset;
        stack[depth] = i;
        TRY
        {
            new_offset = probe_possible_record (tvb, new_offset, cat, ed, i);
        }
        CATCH_NONFATAL_ERRORS
        {
            new_offset = -1;
        }
        ENDTRY;
        if (new_offset != -1) {
            if (new_offset == datablock_end)
            {
                for (unsigned int j = 0; j <= depth; j++)
                {
                    solutions[solution_count][j] = stack[j];
                }
                solution_count++;
                if (solution_count >= MAX_INTERPRETATIONS)
                {
                    return -1;
                }
            }
            else if (new_offset < datablock_end)
            {
                if ((depth + 1) >= selected_interpretations_depth)
                {
                    return -2;
                }
                int result = probe_possible_records (tvb, pinfo, new_offset, datablock_end, cat, ed, indexes, stack, depth + 1);
                if (result != 0)
                {
                    return result;
                }
            }
        }
    }
    return 0;
}

/* possible return values:
    -1 for error
    new offset value, larger by at least one byte (fspec)
*/
static int dissect_asterix_record (tvbuff_t *tvb, packet_info *pinfo, unsigned offset, unsigned datablock_end, proto_tree *tree, unsigned int cat, unsigned int ed, unsigned int uap)
{
    proto_item *ti;
    proto_tree *asterix_packet_tree;

    ti = proto_tree_add_item (tree, hf_asterix_record, tvb, offset, 0, ENC_NA);
    asterix_packet_tree = proto_item_add_subtree (ti, ett_asterix);

    table_params table_p;
    get_category_uap_table(cat, ed, uap, &table_p);

    if (table_p.table_pointer == NULL || table_p.table_pointer_expand == NULL) {
        // skip unknown category
        expert_add_info_format(pinfo, ti, &ei_asterix_overflow, "Unknown category");
        return -1;
    }
    if (!check_fspec_validity (tvb, offset, &table_p)) {
        // something wrong with FSPEC field
        expert_add_info_format(pinfo, ti, &ei_asterix_overflow, "FSPEC field invalid");
        return -1;
    }
    int start_offset = offset;

    offset += asterix_dissect_fspec (tvb, offset, asterix_packet_tree);
    unsigned i = 0;
    unsigned fs_index = 0;
    while (i < table_p.table_size) {
        if (((fs_index + 1) % 8) == 0 && fs_index > 0) {
            if (!asterix_field_exists(tvb, start_offset, fs_index)) {
                break;
            }
            fs_index++;
        }
        if (asterix_field_exists(tvb, start_offset, fs_index)) {
            int *expand = table_p.table_pointer_expand[i];
            int expand_value = -1;
            if (expand != NULL)
            {
                expand_value = *expand;
            }
            if (table_p.table_pointer[i] != NULL) {
                int fun_len = table_p.table_pointer[i](tvb, offset, asterix_packet_tree, expand_value);
                if (fun_len == -1) {
                    return -1;
                }
                offset += fun_len;
            } else {
                return -1;
            }
        }
        i++;
        fs_index++;
    }
    unsigned int item_length = offset - start_offset;
    proto_item_set_len(ti, item_length);
    proto_item_append_text(ti, ", length %u", item_length);
    proto_item_append_text(ti, ", %s", table_p.uap_name);

    if (offset > datablock_end) {
        //record outside datablock
        expert_add_info_format(pinfo, ti, &ei_asterix_overflow, "Record out of bounds");
    }
    return offset;
}

static void dissect_asterix_records (tvbuff_t *tvb, packet_info *pinfo, int offset, unsigned datablock_length, proto_tree *tree, unsigned int cat)
{
    int datablock_end = offset + datablock_length;

    // get edition from settings
    unsigned int ed = -1;
    for (unsigned i = 0; i < sizeof(asterix_properties) / sizeof(asterix_properties[0]); i++)
    {
        dialog_cat_struct prop_cat = asterix_properties[i];
        if (prop_cat.cat == cat && prop_cat.cat_basic)
        {
            ed = *prop_cat.cat_default_value;
            break;
        }
    }

    memset(solutions, -1, sizeof(solutions));
    solution_count = 0;
    unsigned int stack[MAX_INTERPRETATION_DEPTH];

    uap_table_indexes indexes;
    get_uap_tables(cat, ed, &indexes);

    // if category unknown both start_index and end_index are 0
    if ((indexes.end_index - indexes.start_index) > 0)
    {
        int result = probe_possible_records (tvb, pinfo, offset, datablock_end, cat, ed, &indexes, stack, 0);

        unsigned int backup_offset = offset;

        proto_item *possibilities_ti = proto_tree_add_item (tree, hf_asterix_possible_interpretations, tvb, offset, 0, ENC_NA);
        proto_tree *possibilities_tree = proto_item_add_subtree (possibilities_ti, ett_asterix_possible_interpretations);
        proto_item_append_text (possibilities_tree, " %u", solution_count);

        if (result < 0) {
            if (result == -1) {
                expert_add_info_format(pinfo, possibilities_ti, &ei_asterix_overflow, "Interpretations number of solutions exceeded");
            } else {
                expert_add_info_format(pinfo, possibilities_ti, &ei_asterix_overflow, "Interpretations depth exceeded");
            }
        }

        if (solution_count == 0) {
            expert_add_info_format(pinfo, possibilities_ti, &ei_asterix_overflow, "No possible solution found");
        } else {
            for (unsigned int i = 0; i < solution_count; i++) {
                offset = backup_offset;
                proto_item *possible_ti = proto_tree_add_item (possibilities_tree, hf_asterix_possible_interpretation, tvb, offset, 0, ENC_NA);
                proto_item_append_text (possible_ti, " (%u/%u)", i + 1, solution_count);
                proto_tree *possible_tree = proto_item_add_subtree (possible_ti, ett_asterix_possible_interpretation);

                for (unsigned int j = 0; solutions[i][j] != -1; j++) {
                    int new_offset = dissect_asterix_record (tvb, pinfo, offset, datablock_end, possible_tree, cat, ed, solutions[i][j]);
                    // there should not be any error, as this solution already tried, but check anyway
                    if (new_offset <= offset) {
                        return;
                    }
                    offset = new_offset;
                }
            }
        }
    }
    else {
        while (offset < datablock_end) {
            int new_offset = dissect_asterix_record (tvb, pinfo, offset, datablock_end, tree, cat, ed, indexes.start_index);
            if (new_offset <= offset) {
                return;
            }
            offset = new_offset;
        }
    }
}

static bool check_datagram_datablocks (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i = 0;
    int n = tvb_reported_length (tvb);

    while (i < n) {
        int remaining = n - i;
        proto_item *item;

        if (remaining < 4) {
            item = proto_tree_add_item (tree, hf_asterix_datablock, tvb, i, remaining, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_asterix_overflow, "Data length less than 4B");
            return false;
        }

        uint16_t len = tvb_get_uint16 (tvb, i+1, ENC_BIG_ENDIAN);
        if (len < 4) {
            item = proto_tree_add_item (tree, hf_asterix_datablock, tvb, i, len, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_asterix_overflow, "Datablock length less than 4B");
            return false;
        }

        if (remaining < len) {
            item = proto_tree_add_item (tree, hf_asterix_datablock, tvb, i, len, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_asterix_overflow, "Not enough data for datablock");
            return false;
        }
        // move to next datablock
        i += len;
    }
    if (i == n) {
        return true;
    }
    else {
        proto_item *item = proto_tree_add_item (tree, hf_asterix_datablock, tvb, i, n, ENC_NA);
        expert_add_info_format(pinfo, item, &ei_asterix_overflow, "Datablocks datagram misalignment");
        return false;
    }
}

static void dissect_asterix_data_blocks (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i = 0;
    int n = tvb_reported_length (tvb);

    // Datablock parsing is strict. This means that all datablocks must be aligned with UDP datagram data. If not, no datablock is parsed.
    // In future versions strictness level may be added as a configuration option.
    if (check_datagram_datablocks (tvb, pinfo, tree))
    {
        while (i < n) {
            uint8_t cat = tvb_get_uint8 (tvb, i);
            uint16_t len = tvb_get_uint16 (tvb, i+1, ENC_BIG_ENDIAN);

            proto_item *datablock = proto_tree_add_item (tree, hf_asterix_datablock, tvb, i, len, ENC_NA);
            proto_tree *datablock_tree = proto_item_add_subtree (datablock, ett_asterix_record);

            proto_item_append_text (datablock_tree, ", Category %03d", cat);
            proto_tree_add_item (datablock_tree, hf_asterix_category, tvb, i, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (datablock_tree, hf_asterix_length, tvb, i + 1, 2, ENC_BIG_ENDIAN);

            dissect_asterix_records (tvb, pinfo, i + HEADER_LENGTH, len - HEADER_LENGTH, datablock_tree, cat);

            // move to next datablock
            i += len;
        }
    }
}

static int dissect_asterix (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "ASTERIX");
    col_clear (pinfo->cinfo, COL_INFO);

    if (hf_asterix_category <= 0) {
        proto_registrar_get_byname("asterix.category");
    }

    if (tree) { /* we are being asked for details */
        dissect_asterix_data_blocks (tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static unsigned get_asterix_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint16_t plen;
    plen = tvb_get_uint16 (tvb, offset + 1, ENC_BIG_ENDIAN);
    return plen;
}

static int dissect_asterix_tcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* We do delayed field registration if needed in dissect_asterix. */
    tcp_dissect_pdus(tvb, pinfo, tree, true, 3, get_asterix_pdu_len, dissect_asterix, data);
    return tvb_reported_length (tvb);
}

static void register_asterix_fields(const char* unused _U_)
{
    proto_register_field_array (proto_asterix, hf, array_length (hf));

    static int *ett[] = {
        &ett_asterix,
        &ett_asterix_record,
        &ett_asterix_subtree,
        &ett_asterix_possible_interpretation,
        &ett_asterix_possible_interpretations,
        &ett_asterix_spare_error
    };

    proto_register_subtree_array (ett, array_length (ett));
}

void proto_register_asterix (void)
{
    static ei_register_info ei[] = {
        { &ei_asterix_overflow, { "asterix.overflow", PI_PROTOCOL, PI_ERROR, "Asterix overflow", EXPFILL }},
        { &hf_asterix_spare_error, { "asterix.spare_error", PI_PROTOCOL, PI_WARN, "Spare bit error", EXPFILL }},
        { &hf_asterix_fx_error, { "asterix.fx_error", PI_PROTOCOL, PI_ERROR, "FX end bit error", EXPFILL }},
        { &hf_asterix_fspec_error, { "asterix.fspec_error", PI_PROTOCOL, PI_ERROR, "FSPEC error", EXPFILL }}
    };

    proto_asterix = proto_register_protocol ("ASTERIX packet", "ASTERIX", "asterix");

    /* Delay registration of ASTERIX fields */
    proto_register_prefix("asterix", register_asterix_fields);

    asterix_module = prefs_register_protocol(proto_asterix, NULL);
    asterix_handle = register_dissector ("asterix", dissect_asterix, proto_asterix);
    asterix_tcp_handle = register_dissector ("asterix-tcp", dissect_asterix_tcp, proto_asterix);

    expert_asterix = expert_register_protocol(proto_asterix);
    expert_register_field_array(expert_asterix, ei, array_length(ei));

    for (unsigned i = 0; i < sizeof(asterix_properties) / sizeof(asterix_properties[0]); i++)
    {
        dialog_cat_struct cat = asterix_properties[i];
        prefs_register_enum_preference(asterix_module, cat.cat_name, cat.cat_name, NULL, cat.cat_default_value, cat.cat_enums, FALSE);
    }

    prefs_register_enum_preference(asterix_module, "interpretations_depth", "Interpretations depth",
                                   "Interpretations depth for categories with multiple possible UAPs",
                                   &selected_interpretations_depth, interpretations_level_enum_vals, false);
}

void proto_reg_handoff_asterix (void)
{
    dissector_add_uint_with_preference("udp.port", ASTERIX_PORT, asterix_handle);
    dissector_add_uint_with_preference("tcp.port", ASTERIX_PORT, asterix_tcp_handle);
}
