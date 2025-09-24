/* packet-asterix.h
 *
 * Common definitions for ASTERIX dissector
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ASTERIX_H__
#define __PACKET_ASTERIX_H__

#include <epan/packet.h>
#include <epan/expert.h>

#define MAX_UAP_NAME_LENGTH 255

module_t *asterix_module;
expert_module_t* expert_asterix;
typedef struct {
    unsigned cat;
    unsigned *cat_enum;
    unsigned *cat_default_value;
    const enum_val_t *cat_enums;
    const char *cat_name;
    bool cat_basic;
} dialog_cat_struct;

typedef int (*ttt)(tvbuff_t *, unsigned, proto_tree *, int);
typedef struct {
    const ttt *table_pointer;
    int** table_pointer_expand;
    unsigned int table_size;
    char uap_name[MAX_UAP_NAME_LENGTH];
} table_params;

typedef struct {
    unsigned int start_index;
    unsigned int end_index;
} uap_table_indexes;

static bool asterix_extended_end (tvbuff_t *tvb, unsigned offset);
static unsigned asterix_get_unsigned_value(tvbuff_t *tvb, unsigned offset, unsigned bytes);
static int asterix_get_signed_value(tvbuff_t *tvb, unsigned offset, unsigned bytes);
static int get_signed_int(unsigned value, unsigned bits);
static unsigned asterix_dissect_fspec (tvbuff_t *tvb, unsigned offset, proto_tree *tree);
static bool asterix_field_exists (tvbuff_t *tvb, unsigned offset, unsigned bitIndex);
static unsigned asterix_fspec_len (tvbuff_t *tvb, unsigned offset);
static bool asterix_fspec_check (unsigned fspec_len, unsigned list_length, proto_item *ti);
static void get_expansion_table(unsigned int cat, int ed, table_params *table);
static unsigned asterix_parse_re_field (tvbuff_t *tvb, unsigned offset, proto_tree *tree, unsigned fspec_len, unsigned cat);
static void print_octal_string (tvbuff_t *tvb, unsigned offset, unsigned bit_offset, unsigned bit_size, unsigned byte_size, proto_tree *tree, int expand_var);
static void print_icao_string (tvbuff_t *tvb, unsigned offset, unsigned bit_offset, unsigned bit_size, unsigned byte_size, proto_tree *tree, int expand_var);
static void check_spare_bits (tvbuff_t *tvb, unsigned bit_offset, unsigned bit_size, proto_item *item);

static expert_field ei_asterix_overflow;
static expert_field hf_asterix_spare_error;
static expert_field hf_asterix_fspec_error;

#endif /* __PACKET_ASTERIX_H__ */
