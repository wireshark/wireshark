/*

Notice:


This file is auto generated, do not edit!
See tools/asterix/README.md for details.


Data source:
---{gitrev}---


*/

/* packet-asterix.c
 * Routines for ASTERIX decoding
 * By Marko Hrastovec <marko.hrastovec@sloveniacontrol.si>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ASTERIX (All-purpose structured EUROCONTROL surveillances
 * information exchange) is a protocol related to air traffic control.
 *
 * The specifications can be downloaded from
 * http://www.eurocontrol.int/services/asterix
 */

#include <config.h>

#include <wsutil/bits_ctz.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

void proto_register_asterix(void);
void proto_reg_handoff_asterix(void);

#define PROTO_TAG_ASTERIX   "ASTERIX"
#define ASTERIX_PORT        8600

#define MAX_DISSECT_STR     1024
#define MAX_BUFFER           256

static int proto_asterix;

static int hf_asterix_category;
static int hf_asterix_length;
static int hf_asterix_message;
static int hf_asterix_fspec;
static int hf_re_field_len;
static int hf_spare;
static int hf_counter;
static int hf_XXX_FX;

static int ett_asterix;
static int ett_asterix_category;
static int ett_asterix_length;
static int ett_asterix_message;
static int ett_asterix_subtree;

static dissector_handle_t asterix_handle;
/* The following defines tell us how to decode the length of
 * fields and how to construct their display structure */
#define FIXED          1
#define REPETITIVE     2
#define FX             3
/*#define FX_1           4*/
/*#define RE             5*/
#define COMPOUND       6
/*#define SP             7*/
/*#define FX_UAP         8*/
#define EXP            9    /* Explicit (RE or SP) */

/* The following defines tell us how to
 * decode and display individual fields. */
#define FIELD_PART_INT        0
#define FIELD_PART_UINT       1
#define FIELD_PART_FLOAT      2
#define FIELD_PART_UFLOAT     3
#define FIELD_PART_SQUAWK     4
#define FIELD_PART_CALLSIGN   5
#define FIELD_PART_ASCII      6
#define FIELD_PART_FX         7
#define FIELD_PART_HEX        8
#define FIELD_PART_IAS_IM     9
#define FIELD_PART_IAS_ASPD   10

typedef struct FieldPart_s FieldPart;
struct FieldPart_s {
    uint16_t    bit_length;     /* length of field in bits */
    double      scaling_factor; /* scaling factor of the field (for instance: 1/128) */
    uint8_t     type;           /* Pre-defined type for proper presentation */
    int        *hf;             /* Pointer to hf representing this kind of data */
    const char *format_string;  /* format string for showing float values */
};

typedef struct AsterixField_s AsterixField;
struct AsterixField_s {
    uint8_t                    type;                    /* type of field */
    unsigned                   length;                  /* fixed length */
    unsigned                   repetition_counter_size; /* size of repetition counter, length of one item is in length */
    unsigned                   header_length;           /* the size is in first header_length bytes of the field */
    int                       *hf;                      /* pointer to Wireshark hf_register_info */
    const FieldPart * const   *part;                    /* Look declaration and description of FieldPart above. */
    const AsterixField * const field[];                 /* subfields */
};

static void dissect_asterix_packet (tvbuff_t *, packet_info *pinfo, proto_tree *);
static void dissect_asterix_data_block (tvbuff_t *tvb, packet_info *pinfo, unsigned, proto_tree *, uint8_t, int);
static int dissect_asterix_fields (tvbuff_t *, packet_info *pinfo, unsigned, proto_tree *, uint8_t, const AsterixField * const []);

static void asterix_build_subtree (tvbuff_t *, packet_info *pinfo, unsigned, proto_tree *, const AsterixField *);
static void twos_complement (int64_t *, int);
static uint8_t asterix_bit (uint8_t, uint8_t);
static unsigned asterix_fspec_len (tvbuff_t *, unsigned);
static uint8_t asterix_field_exists (tvbuff_t *, unsigned, int);
static uint8_t asterix_get_active_uap (tvbuff_t *, unsigned, uint8_t);
static int asterix_field_length (tvbuff_t *, unsigned, const AsterixField * const);
static int asterix_field_offset (tvbuff_t *, unsigned, const AsterixField * const [], int);
static int asterix_message_length (tvbuff_t *, unsigned, uint8_t, uint8_t);

static const char AISCode[] = { ' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
                                'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', ' ', ' ', ' ', ' ',
                                ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
                                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' ', ' ', ' ', ' ', ' ', ' ' };

static const value_string valstr_XXX_FX[] = {
    { 0, "End of data item" },
    { 1, "Extension into next extent" },
    { 0, NULL }
};
static const FieldPart IXXX_FX = { 1, 1.0, FIELD_PART_FX, &hf_XXX_FX, NULL };
static const FieldPart IXXX_1bit_spare = { 1, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_2bit_spare = { 2, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_3bit_spare = { 3, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_4bit_spare = { 4, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_5bit_spare = { 5, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_6bit_spare = { 6, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_7bit_spare = { 7, 1.0, FIELD_PART_UINT, NULL, NULL };

/* Spare Item */
static const AsterixField IX_SPARE = { FIXED, 0, 0, 0, &hf_spare, NULL, { NULL } };

/* insert1 */
---{insert1}---
/* insert1 */

/* settings which category version to use for each ASTERIX category */
static int global_categories_version[] = {
    0, /* 000 */
    0, /* 001 */
    0, /* 002 */
    0, /* 003 */
    0, /* 004 */
    0, /* 005 */
    0, /* 006 */
    0, /* 007 */
    0, /* 008 */
    0, /* 009 */
    0, /* 010 */
    0, /* 011 */
    0, /* 012 */
    0, /* 013 */
    0, /* 014 */
    0, /* 015 */
    0, /* 016 */
    0, /* 017 */
    0, /* 018 */
    0, /* 019 */
    0, /* 020 */
    0, /* 021 */
    0, /* 022 */
    0, /* 023 */
    0, /* 024 */
    0, /* 025 */
    0, /* 026 */
    0, /* 027 */
    0, /* 028 */
    0, /* 029 */
    0, /* 030 */
    0, /* 031 */
    0, /* 032 */
    0, /* 033 */
    0, /* 034 */
    0, /* 035 */
    0, /* 036 */
    0, /* 037 */
    0, /* 038 */
    0, /* 039 */
    0, /* 040 */
    0, /* 041 */
    0, /* 042 */
    0, /* 043 */
    0, /* 044 */
    0, /* 045 */
    0, /* 046 */
    0, /* 047 */
    0, /* 048 */
    0, /* 049 */
    0, /* 050 */
    0, /* 051 */
    0, /* 052 */
    0, /* 053 */
    0, /* 054 */
    0, /* 055 */
    0, /* 056 */
    0, /* 057 */
    0, /* 058 */
    0, /* 059 */
    0, /* 060 */
    0, /* 061 */
    0, /* 062 */
    0, /* 063 */
    0, /* 064 */
    0, /* 065 */
    0, /* 066 */
    0, /* 067 */
    0, /* 068 */
    0, /* 069 */
    0, /* 070 */
    0, /* 071 */
    0, /* 072 */
    0, /* 073 */
    0, /* 074 */
    0, /* 075 */
    0, /* 076 */
    0, /* 077 */
    0, /* 078 */
    0, /* 079 */
    0, /* 080 */
    0, /* 081 */
    0, /* 082 */
    0, /* 083 */
    0, /* 084 */
    0, /* 085 */
    0, /* 086 */
    0, /* 087 */
    0, /* 088 */
    0, /* 089 */
    0, /* 090 */
    0, /* 091 */
    0, /* 092 */
    0, /* 093 */
    0, /* 094 */
    0, /* 095 */
    0, /* 096 */
    0, /* 097 */
    0, /* 098 */
    0, /* 099 */
    0, /* 100 */
    0, /* 101 */
    0, /* 102 */
    0, /* 103 */
    0, /* 104 */
    0, /* 105 */
    0, /* 106 */
    0, /* 107 */
    0, /* 108 */
    0, /* 109 */
    0, /* 110 */
    0, /* 111 */
    0, /* 112 */
    0, /* 113 */
    0, /* 114 */
    0, /* 115 */
    0, /* 116 */
    0, /* 117 */
    0, /* 118 */
    0, /* 119 */
    0, /* 120 */
    0, /* 121 */
    0, /* 122 */
    0, /* 123 */
    0, /* 124 */
    0, /* 125 */
    0, /* 126 */
    0, /* 127 */
    0, /* 128 */
    0, /* 129 */
    0, /* 130 */
    0, /* 131 */
    0, /* 132 */
    0, /* 133 */
    0, /* 134 */
    0, /* 135 */
    0, /* 136 */
    0, /* 137 */
    0, /* 138 */
    0, /* 139 */
    0, /* 140 */
    0, /* 141 */
    0, /* 142 */
    0, /* 143 */
    0, /* 144 */
    0, /* 145 */
    0, /* 146 */
    0, /* 147 */
    0, /* 148 */
    0, /* 149 */
    0, /* 150 */
    0, /* 151 */
    0, /* 152 */
    0, /* 153 */
    0, /* 154 */
    0, /* 155 */
    0, /* 156 */
    0, /* 157 */
    0, /* 158 */
    0, /* 159 */
    0, /* 160 */
    0, /* 161 */
    0, /* 162 */
    0, /* 163 */
    0, /* 164 */
    0, /* 165 */
    0, /* 166 */
    0, /* 167 */
    0, /* 168 */
    0, /* 169 */
    0, /* 170 */
    0, /* 171 */
    0, /* 172 */
    0, /* 173 */
    0, /* 174 */
    0, /* 175 */
    0, /* 176 */
    0, /* 177 */
    0, /* 178 */
    0, /* 179 */
    0, /* 180 */
    0, /* 181 */
    0, /* 182 */
    0, /* 183 */
    0, /* 184 */
    0, /* 185 */
    0, /* 186 */
    0, /* 187 */
    0, /* 188 */
    0, /* 189 */
    0, /* 190 */
    0, /* 191 */
    0, /* 192 */
    0, /* 193 */
    0, /* 194 */
    0, /* 195 */
    0, /* 196 */
    0, /* 197 */
    0, /* 198 */
    0, /* 199 */
    0, /* 200 */
    0, /* 201 */
    0, /* 202 */
    0, /* 203 */
    0, /* 204 */
    0, /* 205 */
    0, /* 206 */
    0, /* 207 */
    0, /* 208 */
    0, /* 209 */
    0, /* 210 */
    0, /* 211 */
    0, /* 212 */
    0, /* 213 */
    0, /* 214 */
    0, /* 215 */
    0, /* 216 */
    0, /* 217 */
    0, /* 218 */
    0, /* 219 */
    0, /* 220 */
    0, /* 221 */
    0, /* 222 */
    0, /* 223 */
    0, /* 224 */
    0, /* 225 */
    0, /* 226 */
    0, /* 227 */
    0, /* 228 */
    0, /* 229 */
    0, /* 230 */
    0, /* 231 */
    0, /* 232 */
    0, /* 233 */
    0, /* 234 */
    0, /* 235 */
    0, /* 236 */
    0, /* 237 */
    0, /* 238 */
    0, /* 239 */
    0, /* 240 */
    0, /* 241 */
    0, /* 242 */
    0, /* 243 */
    0, /* 244 */
    0, /* 245 */
    0, /* 246 */
    0, /* 247 */
    0, /* 248 */
    0, /* 249 */
    0, /* 250 */
    0, /* 251 */
    0, /* 252 */
    0, /* 253 */
    0, /* 254 */
    0  /* 255 */
};

static int dissect_asterix (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "ASTERIX");
    col_clear (pinfo->cinfo, COL_INFO);

    if (tree) { /* we are being asked for details */
        dissect_asterix_packet (tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static void dissect_asterix_packet (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned i;
    uint8_t category;
    uint16_t length;
    proto_item *asterix_packet_item;
    proto_tree *asterix_packet_tree;

    for (i = 0; i < tvb_reported_length (tvb); i += length + 3) {
        /* all ASTERIX messages have the same structure:
         *
         * header:
         *
         *   1 byte   category  even though a category is referenced as I019,
         *                      this is just stored as decimal 19 (i.e. 0x13)
         *   2 bytes  length    the total length of this ASTERIX message, the
         *                      length includes the size of the header.
         *
         *                      Note that the there was a structural change at
         *                      one point that changes whether multiple
         *                      records can occur after the header or not
         *                      (each category specifies this explicitly. All
         *                      of the currently supported categories can have
         *                      multiple records so this implementation just
         *                      assumes that is always the case)
         *
         * record (multiple records can exists):
         *
         *   n bytes  FSPEC     the field specifier is a bit mask where the
         *                      lowest bit of each byte is called the FX bit.
         *                      When the FX bit is set this indicates that
         *                      the FSPEC extends into the next byte.
         *                      Any other bit indicates the presence of the
         *                      field that owns that bit (as per the User
         *                      Application Profile (UAP)).
         *   X bytes  Field Y   X is as per the specification for field Y.
         *   etc.
         *
         * The User Application Profile (UAP) is simply a mapping from the
         * FSPEC to fields. Each category has its own UAP.
         */
        category = tvb_get_uint8 (tvb, i);
        length = (tvb_get_uint8 (tvb, i + 1) << 8) + tvb_get_uint8 (tvb, i + 2) - 3; /* -3 for category and length */

        asterix_packet_item = proto_tree_add_item (tree, proto_asterix, tvb, i, length + 3, ENC_NA);
        proto_item_append_text (asterix_packet_item, ", Category %03d", category);
        asterix_packet_tree = proto_item_add_subtree (asterix_packet_item, ett_asterix);
        proto_tree_add_item (asterix_packet_tree, hf_asterix_category, tvb, i, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (asterix_packet_tree, hf_asterix_length, tvb, i + 1, 2, ENC_BIG_ENDIAN);

        dissect_asterix_data_block (tvb, pinfo, i + 3, asterix_packet_tree, category, length);
    }
}

static void dissect_asterix_data_block (tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, uint8_t category, int length)
{
    uint8_t active_uap;
    int fspec_len, inner_offset, size, counter;
    proto_item *asterix_message_item = NULL;
    proto_tree *asterix_message_tree = NULL;

    for (counter = 1, inner_offset = 0; inner_offset < length; counter++) {

        /* This loop handles parsing of each ASTERIX record */

        active_uap = asterix_get_active_uap (tvb, offset + inner_offset, category);
        size = asterix_message_length (tvb, offset + inner_offset, category, active_uap);
        if (size > 0) {
            asterix_message_item = proto_tree_add_item (tree, hf_asterix_message, tvb, offset + inner_offset, size, ENC_NA);
            proto_item_append_text (asterix_message_item, ", #%02d, length: %d", counter, size);
            asterix_message_tree = proto_item_add_subtree (asterix_message_item, ett_asterix_message);
            fspec_len = asterix_fspec_len (tvb, offset + inner_offset);
            /*show_fspec (tvb, asterix_message_tree, offset + inner_offset, fspec_len);*/
            proto_tree_add_item (asterix_message_tree, hf_asterix_fspec, tvb, offset + inner_offset, fspec_len, ENC_NA);

            size = dissect_asterix_fields (tvb, pinfo, offset + inner_offset, asterix_message_tree, category, categories[category][global_categories_version[category]][active_uap]);

            inner_offset += size + fspec_len;
        }
        else {
            inner_offset = length;
        }
    }
}

// We're transported over UDP and our offset always advances.
// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_asterix_fields (tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, uint8_t category, const AsterixField * const current_uap [])
{
    unsigned i, j, size, start, len, inner_offset, fspec_len;
    uint64_t counter;
    proto_item *asterix_field_item = NULL;
    proto_tree *asterix_field_tree = NULL;
    proto_item *asterix_field_item2 = NULL;
    proto_tree *asterix_field_tree2 = NULL;

    if (current_uap == NULL)
        return 0;

    for (i = 0, size = 0; current_uap[i] != NULL; i++) {
        start = asterix_field_offset (tvb, offset, current_uap, i);
        if (start > 0) {
            len = asterix_field_length (tvb, offset + start, current_uap[i]);
            size += len;
            switch(current_uap[i]->type) {
                case COMPOUND:
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    fspec_len = asterix_fspec_len (tvb, offset + start);
                    proto_tree_add_item (asterix_field_tree, hf_asterix_fspec, tvb, offset + start, fspec_len, ENC_NA);
                    dissect_asterix_fields (tvb, pinfo, offset + start, asterix_field_tree, category, current_uap[i]->field);
                    break;
                case REPETITIVE:
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    for (j = 0, counter = 0; j < current_uap[i]->repetition_counter_size; j++) {
                        counter = (counter << 8) + tvb_get_uint8 (tvb, offset + start + j);
                    }
                    proto_tree_add_item (asterix_field_tree, hf_counter, tvb, offset + start, current_uap[i]->repetition_counter_size, ENC_BIG_ENDIAN);
                    for (j = 0, inner_offset = 0; j < counter; j++, inner_offset += current_uap[i]->length) {
                        asterix_field_item2 = proto_tree_add_item (asterix_field_tree, *current_uap[i]->hf, tvb, offset + start + current_uap[i]->repetition_counter_size + inner_offset, current_uap[i]->length, ENC_NA);
                        asterix_field_tree2 = proto_item_add_subtree (asterix_field_item2, ett_asterix_subtree);
                        asterix_build_subtree (tvb, pinfo, offset + start + current_uap[i]->repetition_counter_size + inner_offset, asterix_field_tree2, current_uap[i]);
                    }
                    break;
                /* currently not generated from asterix-spec*/
                /*case EXP:
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    proto_tree_add_item (asterix_field_tree, hf_re_field_len, tvb, offset + start, 1, ENC_BIG_ENDIAN);
                    start++;
                    fspec_len = asterix_fspec_len (tvb, offset + start);
                    proto_tree_add_item (asterix_field_tree, hf_asterix_fspec, tvb, offset + start, fspec_len, ENC_NA);
                    dissect_asterix_fields (tvb, pinfo, offset + start, asterix_field_tree, category, current_uap[i]->field);
                    break;*/
                default: /* FIXED, FX, FX_1, FX_UAP */
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    asterix_build_subtree (tvb, pinfo, offset + start, asterix_field_tree, current_uap[i]);
                    break;
            }
        }
    }
    return size;
}

static void asterix_build_subtree (tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *parent, const AsterixField *field)
{
    header_field_info* hfi;
    int bytes_in_type, byte_offset_of_mask;
    int i, inner_offset, offset_in_tvb, length_in_tvb;
    uint8_t go_on;
    int64_t value;
    char *str_buffer = NULL;
    double scaling_factor = 1.0;
    uint8_t *air_speed_im_bit;
    if (field->part != NULL) {
        for (i = 0, inner_offset = 0, go_on = 1; go_on && field->part[i] != NULL; i++) {
            value = tvb_get_bits64 (tvb, offset * 8 + inner_offset, field->part[i]->bit_length, ENC_BIG_ENDIAN);
            if (field->part[i]->hf != NULL) {
                offset_in_tvb = offset + inner_offset / 8;
                length_in_tvb = (inner_offset % 8 + field->part[i]->bit_length + 7) / 8;
                switch (field->part[i]->type) {
                    case FIELD_PART_FX:
                        if (!value) go_on = 0;
                        /* Fall through */
                    case FIELD_PART_INT:
                    case FIELD_PART_UINT:
                    case FIELD_PART_HEX:
                    case FIELD_PART_ASCII:
                    case FIELD_PART_SQUAWK:
                        hfi = proto_registrar_get_nth (*field->part[i]->hf);
                        if (hfi->bitmask)
                        {
                            // for a small bit field to decode correctly with
                            // a mask that belongs to a large(r) one we need to
                            // re-adjust offset_in_tvb and length_in_tvb to
                            // correctly align with the given hf mask.
                            //
                            // E.g. the following would not decode correctly:
                            //   { &hf_020_050_V, ... FT_UINT16, ... 0x8000, ...
                            // instead one would have to use
                            //   { &hf_020_050_V, ... FT_UINT8, ... 0x80, ...
                            //
                            bytes_in_type = ftype_wire_size(hfi->type);
                            if (bytes_in_type > 1)
                            {
                                byte_offset_of_mask = bytes_in_type - (ws_ilog2 (hfi->bitmask) + 8)/8;
                                if (byte_offset_of_mask >= 0)
                                {
                                    offset_in_tvb -= byte_offset_of_mask;
                                    length_in_tvb = bytes_in_type;
                                }
                            }
                        }
                        proto_tree_add_item (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, ENC_BIG_ENDIAN);
                        break;
                    case FIELD_PART_FLOAT:
                        twos_complement (&value, field->part[i]->bit_length);
                        /* Fall through */
                    case FIELD_PART_UFLOAT:
                        scaling_factor = field->part[i]->scaling_factor;
                        if (field->part[i]->format_string != NULL)
                            proto_tree_add_double_format_value (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, value * scaling_factor, field->part[i]->format_string, value * scaling_factor);
                        else
                            proto_tree_add_double (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, value * scaling_factor);
                        break;
                    case FIELD_PART_CALLSIGN:
                        str_buffer = wmem_strdup_printf(
                            pinfo->pool,
                            "%c%c%c%c%c%c%c%c",
                            AISCode[(value >> 42) & 63],
                            AISCode[(value >> 36) & 63],
                            AISCode[(value >> 30) & 63],
                            AISCode[(value >> 24) & 63],
                            AISCode[(value >> 18) & 63],
                            AISCode[(value >> 12) & 63],
                            AISCode[(value >> 6) & 63],
                            AISCode[value & 63]);
                        proto_tree_add_string (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, str_buffer);
                        break;
                    case FIELD_PART_IAS_IM:
                        /* special processing for I021/150 and I062/380#4 because Air Speed depends on IM subfield */
                        air_speed_im_bit = wmem_new (pinfo->pool, uint8_t);
                        *air_speed_im_bit = (tvb_get_uint8 (tvb, offset_in_tvb) & 0x80) >> 7;
                        /* Save IM info for the packet. key = 21150. */
                        p_add_proto_data (pinfo->pool, pinfo, proto_asterix, 21150, air_speed_im_bit);
                        proto_tree_add_item (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, ENC_BIG_ENDIAN);
                        break;
                    case FIELD_PART_IAS_ASPD:
                        /* special processing for I021/150 and I062/380#4 because Air Speed depends on IM subfield */
                        air_speed_im_bit = (uint8_t *)p_get_proto_data (pinfo->pool, pinfo, proto_asterix, 21150);
                        if (!air_speed_im_bit || *air_speed_im_bit == 0)
                            scaling_factor = 1.0/16384.0;
                        else
                            scaling_factor = 0.001;
                        proto_tree_add_double (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, value * scaling_factor);
                        break;
                }
            }
            inner_offset += field->part[i]->bit_length;
        }
    } /* if not null */
}

static uint8_t asterix_bit (uint8_t b, uint8_t bitNo)
{
    return bitNo < 8 && (b & (0x80 >> bitNo)) > 0;
}

/* Function makes int64_t two's complement.
 * Only the bit_len bit are set in int64_t. All more significant
 * bits need to be set to have proper two's complement.
 * If the number is negative, all other bits must be set to 1.
 * If the number is positive, all other bits must remain 0. */
static void twos_complement (int64_t *v, int bit_len)
{
    if (*v & (UINT64_C(1) << (bit_len - 1))) {
        *v |= (UINT64_C(0xffffffffffffffff) << bit_len);
    }
}

static unsigned asterix_fspec_len (tvbuff_t *tvb, unsigned offset)
{
    unsigned i;
    unsigned max_length = tvb_reported_length (tvb) - offset;
    for (i = 0; (tvb_get_uint8 (tvb, offset + i) & 1) && i < max_length; i++);
    return i + 1;
}

static uint8_t asterix_field_exists (tvbuff_t *tvb, unsigned offset, int bitIndex)
{
    uint8_t bitNo, i;
    bitNo = bitIndex + bitIndex / 7;
    for (i = 0; i < bitNo / 8; i++) {
        if (!(tvb_get_uint8 (tvb, offset + i) & 1)) return 0;
    }
    return asterix_bit (tvb_get_uint8 (tvb, offset + i), bitNo % 8);
}

// We're transported over UDP and our offset always advances.
// NOLINTNEXTLINE(misc-no-recursion)
static int asterix_field_length (tvbuff_t *tvb, unsigned offset, const AsterixField * const field)
{
    unsigned size;
    uint64_t count;
    uint8_t i;

    size = 0;
    switch(field->type) {
        case FIXED:
            size = field->length;
            break;
        case REPETITIVE:
            for (i = 0, count = 0; i < field->repetition_counter_size && i < sizeof (count); i++)
                count = (count << 8) + tvb_get_uint8 (tvb, offset + i);
            size = (unsigned)(field->repetition_counter_size + count * field->length);
            break;
        case FX:
            for (size = field->length + field->header_length; tvb_get_uint8 (tvb, offset + size - 1) & 1; size += field->length);
            break;
        case EXP:
            for (i = 0, size = 0; i < field->header_length; i++) {
                size = (size << 8) + tvb_get_uint8 (tvb, offset + i);
            }
            break;
        case COMPOUND:
            /* FSPEC */
            for (size = 0; tvb_get_uint8 (tvb, offset + size) & 1; size++);
            size++;

            for (i = 0; field->field[i] != NULL; i++) {
                if (asterix_field_exists (tvb, offset, i))
                    size += asterix_field_length (tvb, offset + size, field->field[i]);
            }
            break;
    }
    return size;
}

/* This works for category 001. For other it may require changes. */
static uint8_t asterix_get_active_uap (tvbuff_t *tvb, unsigned offset, uint8_t category)
{
    int i, inner_offset;
    AsterixField const * const *current_uap;

    if ((category == 1) && (categories[category] != NULL)) { /* if category is supported */
        if (categories[category][global_categories_version[category]][1] != NULL) { /* if exists another uap */
            current_uap = categories[category][global_categories_version[category]][0];
            if (current_uap != NULL) {
                inner_offset = asterix_fspec_len (tvb, offset);
                for (i = 0; current_uap[i] != NULL; i++) {
                    if (asterix_field_exists (tvb, offset, i)) {
                        if (i == 1) {  /* uap selector (I001/020) is always at index '1' */
                            return tvb_get_uint8 (tvb, offset + inner_offset) >> 7;
                        }
                        inner_offset += asterix_field_length (tvb, offset + inner_offset, current_uap[i]);
                    }
                }
            }
        }
    }
    return 0;
}

static int asterix_field_offset (tvbuff_t *tvb, unsigned offset, const AsterixField * const current_uap[], int field_index)
{
    int i, inner_offset;
    inner_offset = 0;
    if (asterix_field_exists (tvb, offset, field_index)) {
        inner_offset = asterix_fspec_len (tvb, offset);
        for (i = 0; i < field_index; i++) {
            if (asterix_field_exists (tvb, offset, i))
                inner_offset += asterix_field_length (tvb, offset + inner_offset, current_uap[i]);
        }
    }
    return inner_offset;
}

static int asterix_message_length (tvbuff_t *tvb, unsigned offset, uint8_t category, uint8_t active_uap)
{
    int i, size;
    AsterixField const * const *current_uap;

    if (categories[category] != NULL) { /* if category is supported */
        current_uap = categories[category][global_categories_version[category]][active_uap];
        if (current_uap != NULL) {
            size = asterix_fspec_len (tvb, offset);
            for (i = 0; current_uap[i] != NULL; i++) {
                if (asterix_field_exists (tvb, offset, i)) {
                    size += asterix_field_length (tvb, offset + size, current_uap[i]);
                }
            }
            return size;
        }
    }
    return 0;
}

void proto_register_asterix (void)
{
    static hf_register_info hf[] = {
        { &hf_asterix_category, { "Category", "asterix.category", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_asterix_length, { "Length", "asterix.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_asterix_message, { "Asterix message", "asterix.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_asterix_fspec, { "FSPEC", "asterix.fspec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_re_field_len, { "RE LEN", "asterix.re_field_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_spare, { "Spare", "asterix.spare", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_counter, { "Counter", "asterix.counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_XXX_FX, { "FX", "asterix.FX", FT_UINT8, BASE_DEC, VALS (valstr_XXX_FX), 0x01, "Extension into next extent", HFILL } },
/* insert2 */
---{insert2}---
/* insert2 */
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_asterix,
        &ett_asterix_category,
        &ett_asterix_length,
        &ett_asterix_message,
        &ett_asterix_subtree
    };

    module_t *asterix_prefs_module;

    proto_asterix = proto_register_protocol (
        "ASTERIX packet", /* name       */
        "ASTERIX",        /* short name */
        "asterix"         /* abbrev     */
    );

    proto_register_field_array (proto_asterix, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

    asterix_handle = register_dissector ("asterix", dissect_asterix, proto_asterix);

    asterix_prefs_module = prefs_register_protocol (proto_asterix, NULL);

/* insert3 */
---{insert3}---
/* insert3 */
}

void proto_reg_handoff_asterix (void)
{
    dissector_add_uint_with_preference("udp.port", ASTERIX_PORT, asterix_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
