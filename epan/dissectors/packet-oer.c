/* packet-oer.c
 * Routines for ASN1 Octet Encoding Rules
 *
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Ref: ITU-T X.696 (08/2015) https://www.itu.int/itu-t/recommendations/rec.aspx?rec=12487
 * Based on the BER and PER dissectors by Ronnie Sahlberg.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/exceptions.h>

#include "packet-oer.h"


#define PNAME  "Octet Encoding Rules (ASN.1)"
#define PSNAME "OER"
#define PFNAME "oer"

void proto_register_oer(void);
void proto_reg_handoff_oer(void);

/* Initialize the protocol and registered fields */
static int proto_oer;

static int hf_oer_optional_field_bit;
static int hf_oer_class;
static int hf_oer_tag;
static int hf_oer_length_determinant;
static int hf_oer_extension_present_bit;
static int hf_oer_open_type_length;

/* Initialize the subtree pointers */
static int ett_oer;
static int ett_oer_sequence_of_item;
static int ett_oer_open_type;

static expert_field ei_oer_not_decoded_yet;
static expert_field ei_oer_undecoded;
static expert_field ei_oer_open_type;

/* whether the OER helpers should put the internal OER fields into the tree or not. */
static bool display_internal_oer_fields;

/*
#define DEBUG_ENTRY(x) \
printf("#%u  %s   tvb:0x%08x\n",actx->pinfo->num,x,(int)tvb);
*/
#define DEBUG_ENTRY(x) \
	;

#define SEQ_MAX_COMPONENTS 128

/*
* XXX - if the specified length is less than the remaining length
* of data in the tvbuff, either 1) the specified length is bad and
* we should report that with an expert info or 2) the tvbuff is
* unreassembled and we should make the new tvbuff also be an
* unreassembled tvbuff.
*/
static tvbuff_t *
oer_tvb_new_subset_length(tvbuff_t *tvb, const int backing_offset, const int backing_length)
{
    int length_remaining;

    length_remaining = tvb_reported_length_remaining(tvb, backing_offset);
    return tvb_new_subset_length(tvb, backing_offset, (length_remaining > backing_length) ? backing_length : length_remaining);
}

static void
dissect_oer_not_decoded_yet(proto_tree* tree, packet_info* pinfo, tvbuff_t *tvb, const char* reason)
{
    proto_tree_add_expert_format(tree, pinfo, &ei_oer_undecoded, tvb, 0, 0, "something unknown here [%s]", reason);
    col_append_fstr(pinfo->cinfo, COL_INFO, "[UNKNOWN OER: %s]", reason);
    THROW(ReportedBoundsError);
}

/* Given the ordinal of the option in the sequence, print the name. eg find the 1:th then the 2:nd etc*/
static const char *
index_get_optional_name(const oer_sequence_t *sequence, int idx)
{
    int i;
    header_field_info *hfi;

    for (i = 0; sequence[i].p_id; i++) {
        if ((sequence[i].extension != ASN1_NOT_EXTENSION_ROOT) && (sequence[i].optional == ASN1_OPTIONAL)) {
            if (idx == 0) {
                hfi = proto_registrar_get_nth(*sequence[i].p_id);
                return (hfi) ? hfi->name : "<unknown field>";
            }
            idx--;
        }
    }
    return "<unknown type>";
}


static const char *
index_get_field_name(const oer_sequence_t *sequence, int idx)
{
    header_field_info *hfi;

    hfi = proto_registrar_get_nth(*sequence[idx].p_id);
    return (hfi) ? hfi->name : "<unknown field>";
}


/* 8.6 Length determinant */
static uint32_t
dissect_oer_length_determinant(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, uint32_t *length)
{
    proto_item *item;
    uint8_t oct, value_len;
    uint32_t len;

    if (!length) {
        length = &len;
    }

    *length = 0;

    /* 8.6.3 There are two forms of length determinant - a short form and a long form...
     * 8.6.4 The short form of length determinant consists of a single octet. Bit 8 of this octet shall be set to '0',
     * and bits 7 to 1 of this octet shall contain the length (0 to 127) encoded as an unsigned binary integer into 7 bits.
     */
    oct = tvb_get_uint8(tvb, offset);
    if ((oct & 0x80) == 0) {
        /* Short form */
        *length = oct;
        if (hf_index > 0) {
            item = proto_tree_add_item(tree, hf_index, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (!display_internal_oer_fields) proto_item_set_hidden(item);
        }
        offset++;

        return offset;
    }
    offset++;
    /* Long form */
    /* 8.6.5 The long form of length determinant consists of an initial octet followed by one or more subsequent octets.
     * Bit 8 of the initial octet shall be set to 1, and bits 7 to 1 of this octet shall indicate the number of subsequent octets (1 to 127).
     * The length shall be encoded as a variable-size unsigned number into the subsequent octets.
     */
    value_len = oct & 0x7f;
    switch (value_len) {
    case 1:
        *length = tvb_get_uint8(tvb, offset);
        offset++;
        break;
    case 2:
        *length = tvb_get_ntohs(tvb, offset);
        offset+=2;
        break;
    case 3:
        *length = tvb_get_ntoh24(tvb, offset);
        offset+=3;
        break;
    case 4:
        *length = tvb_get_ntohl(tvb, offset);
        offset+=4;
        break;
    default:
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_oer_not_decoded_yet, tvb, offset, 1,
            "Length determinant: Long form %u octets not handled", value_len);
        return tvb_reported_length(tvb);
    }

    return offset;

}

/* 9 Encoding of Boolean values */
uint32_t dissect_oer_boolean(tvbuff_t* tvb, uint32_t offset, asn1_ctx_t* actx, proto_tree* tree, int hf_index, bool* bool_val)
{
    uint32_t val = 0;
    DEBUG_ENTRY("dissect_oer_boolean");

    actx->created_item = proto_tree_add_item_ret_uint(tree, hf_index, tvb, offset, 1, ENC_BIG_ENDIAN, &val);
    offset++;

    if (bool_val) {
        *bool_val = (bool)val;
    }

    return offset;
}

/* 10 Encoding of integer values */

uint32_t
dissect_oer_constrained_integer(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int64_t min, int64_t max, uint32_t *value, bool has_extension _U_)
{
    DEBUG_ENTRY("dissect_oer_constrained_integer");
    uint32_t val = 0;

    if (min >= 0) {
        /* 10.2 There are two main cases:
         *      a) The effective value constraint has a lower bound, and that lower bound is zero or positive.
         */
        if (max < 0x100) {
            /* One octet */
            proto_tree_add_item_ret_uint(tree, hf_index, tvb, offset, 1, ENC_BIG_ENDIAN, &val);
            offset++;
        } else if (max < 0x10000) {
            /* Two octets */
            proto_tree_add_item_ret_uint(tree, hf_index, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
            offset += 2;
        } else if (max == 0xFFFFFFFF) {
            /* Four octets */
            proto_tree_add_item_ret_uint(tree, hf_index, tvb, offset, 4, ENC_BIG_ENDIAN, &val);
            offset += 4;
        } else {
            /* To large not handlet yet*/
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer to large value");
        }

    } else {
        /* b) The effective value constraint has either a negative lower bound or no lower bound. */
        if ((min >= -128) && (max <= 127)) {
            /* 10.4 a a) If the lower bound is greater than or equal to -2^7 (-128) and the upper bound is less than or equal to 2^7-1 (127),
             * then every value of the integer type shall be encoded as a fixed-size signed number in a one-octet word;
             */
            proto_tree_add_item_ret_int(tree, hf_index, tvb, offset, 1, ENC_BIG_ENDIAN, &val);
            offset++;
        } else if ((min >= -32768) && (max <= 32767)) {
            /* if the lower bound is greater than or equal to -2^15 (-32768) and the upper bound is less than or equal to 2^15-1 (32767),
             * then every value of the integer type shall be encoded as a fixed-size signed number in a two octet word;
             */
            proto_tree_add_item_ret_int(tree, hf_index, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
            offset += 2;
        } else if ((min >= -2147483648LL) && (max <= 2147483647)) {
            /* if the lower bound is greater than or equal to -2^31 (-2147483648) and the upper bound is less than or equal to 2^31-1 (2147483647),
             * then every value of the integer type shall be encoded as a fixed-size signed number in a four-octet word
             */
            proto_tree_add_item_ret_int(tree, hf_index, tvb, offset, 4, ENC_BIG_ENDIAN, &val);
            offset += 4;
        } else {
            /* To large not handlet yet*/
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer to large value");
        }

    }

    if (value) {
        *value = val;
    }

    return offset;

}

uint32_t
dissect_oer_constrained_integer_64b(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int64_t min, uint64_t max, uint64_t *value, bool has_extension _U_)
{
    uint64_t val = 0;

    /* XXX Negative numbers ???*/
    if (min >= 0) {
        /* 10.2 There are two main cases:
        *      a) The effective value constraint has a lower bound, and that lower bound is zero or positive.
        */
        /* 10.3 */
        if (max < 0x100) {
            /* One octet, upper bound is less than or equal to 2 exp 8 - 1 (255) */
            proto_tree_add_item_ret_uint64(tree, hf_index, tvb, offset, 1, ENC_BIG_ENDIAN, &val);
            offset++;
        } else if (max < 0x10000) {
            /* Two octets, upper bound is less than or equal to 2 exp 16 - 1 (65535), */
            proto_tree_add_item_ret_uint64(tree, hf_index, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
            offset += 2;
        } else if (max < 0x100000000) {
            /* Four octets, upper bound is less than or equal to 2 exp 32 - 1 (4294967295), */
            proto_tree_add_item_ret_uint64(tree, hf_index, tvb, offset, 4, ENC_BIG_ENDIAN, &val);
            offset += 4;
        } else if (max == UINT64_C(18446744073709551615)) {
            /* Eight octets, upper bound is less than or equal to 2 exp 64 - 1 (4294967295), */
            proto_tree_add_item_ret_uint64(tree, hf_index, tvb, offset, 8, ENC_BIG_ENDIAN, &val);
            offset += 8;
        } else {
            /* eight-octet, upper bound is less than or equal to 2 exp 64 - 1 (18446744073709551615) */
            /* To large not handlet yet*/
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer to large value");
        }

    } else {
        /* b) The effective value constraint has either a negative lower bound or no lower bound. */
        dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer negative value");
    }

    if (value) {
        *value = val;
    }

    return offset;

}

uint32_t
dissect_oer_constrained_integer_64b_no_ub(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int64_t min, uint64_t max _U_, uint64_t *value, bool has_extension _U_)
{
    uint64_t val = 0;
    uint32_t length;

    /* Negative numbers ???*/
    if (min >= 0) {

        /* (the effective value constraint has either an upper bound greater than 2 exp 64-1 or no upper bound)
        * every value of the integer type shall be encoded as a length determinant (see 8.6)
        * followed by a variable-size unsigned number
        * (occupying at least as many whole octets as are necessary to carry the value).
        */
        offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
        if (length > 0) {
            if (length < 5) {
                proto_tree_add_item_ret_uint64(tree, hf_index, tvb, offset, length, ENC_BIG_ENDIAN, &val);
                offset += length;
            } else {
                dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer NO_BOUND to many octets");
            }
        } else {
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer unexpected length");
        }
    }
    if (value) {
        *value = val;
    }

    return offset;

}

uint32_t
dissect_oer_integer(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int32_t *value)
{
    int32_t val = 0;
    uint32_t length;
    /* 10.4 e) (the effective value constraint has a lower bound less than -263, no lower bound,
     * an upper bound greater than 2 exp 63-1, or no upper bound) every value of the integer type
     * shall be encoded as a length determinant (see 8.6) followed by a variable-size signed number
     * (occupying at least as many whole octets as are necessary to carry the value).
     */
    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
    if (length > 0) {
        if (length < 5) {
            /* extend sign bit for signed fields */
            enum ftenum type = FT_INT32;
            /* This should be signed, because the field should only be
             * unsigned if there's a constraint, and then we don't get here. */
            if (hf_index > 0) {
                type = proto_registrar_get_ftype(hf_index);
            }
            uint8_t first = tvb_get_uint8(tvb, offset);
            if (first & 0x80 && FT_IS_INT(type)) {
                val = -1;
            }
            for (unsigned i = 0; i < length; i++) {
                val = ((uint32_t)val << 8) | tvb_get_uint8(tvb, offset);
                offset++;
            }
        } else {
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer NO_BOUND too many octets");
        }
    } else {
        dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "constrained_integer unexpected length");
    }

    if (hf_index > 0) {
        header_field_info* hfi;
        hfi = proto_registrar_get_nth(hf_index);
        if (FT_IS_UINT32(hfi->type)) {
            actx->created_item = proto_tree_add_uint(tree, hf_index, tvb, offset - length, length, (uint32_t)val);
        } else if (FT_IS_INT32(hfi->type)) {
            actx->created_item = proto_tree_add_int(tree, hf_index, tvb, offset - length, length, val);
        } else {
            DISSECTOR_ASSERT_NOT_REACHED();
        }
    }

    if (value) {
        *value = val;
    }

    return offset;

}
/* 11 Encoding of enumerated values */
uint32_t
dissect_oer_enumerated(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, uint32_t root_num _U_, uint32_t *value, bool has_extension _U_, uint32_t ext_num _U_, uint32_t *value_map _U_)
{
    int old_offset = offset;
    uint32_t val;
    /* 11.2 There are two forms of enumerated type encoding - a short form and a long form... */

    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, -1 /*Don't show length value as internal field*/, &val);
    actx->created_item = proto_tree_add_uint(tree, hf_index, tvb, old_offset, offset - old_offset, val);

    if (value) {
        *value = val;
    }

    return offset;


}
/* 13 Encoding of bitstring values */

/* 13.1 General
 * The encoding of a bitstring value depends on the effective size constraint of the bitstring type (see 8.2.8).
 *  If the lower and upper bounds of the effective size constraint are identical, 13.2 applies, otherwise 13.3 applies.
 */
uint32_t
dissect_oer_bit_string(tvbuff_t *tvb, uint32_t offset _U_, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_, int min_len _U_, int max_len _U_, bool has_extension _U_, int * const *named_bits _U_, int num_named_bits _U_, tvbuff_t **value_tvb _U_, int *len _U_)
{
    dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "Encoding of bitstring values not handled yet");

    return tvb_reported_length(tvb);
}

static uint32_t
dissect_oer_bit_string_unconstr(tvbuff_t *tvb, uint32_t offset _U_, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_, int min_len _U_, int max_len _U_, bool has_extension _U_, int * const *named_bits _U_, int num_named_bits _U_, tvbuff_t **value_tvb _U_, uint8_t * const values, int values_size, int *len _U_)
{
    int length;
    uint8_t unused_bit_count = 0;

    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, -1 /*Don't show length value as internal field*/, &length);
    if (length > 0) {
        unused_bit_count = tvb_get_uint8(tvb, offset);
        if (unused_bit_count > 7) {
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "too high unused bit count");
            return offset + length;
        }
        offset += 1;
        length -= 1;
    }

    *len = length;
    if (values) {
        memset(values, 0, values_size);
        if (length > values_size) {
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "too many bitstring elements");
        }
        for (int i = 0; i < length; i++) {
            uint8_t value = tvb_get_uint8(tvb, offset);
            if (i + 1 == length) {
                /* unused bits of the last octet shall be set to zeros */
                value &= (0xFF << unused_bit_count);
            }
            if (i < values_size) {
                values[i] = value;
            }
            offset += 1;
        }
    }

    return offset;
}

/* 14 Encoding of octet string values */
uint32_t
dissect_oer_octet_string(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension _U_, tvbuff_t **value_tvb)
{
    unsigned length;
    /* 14.1 For an octetstring type in which the lower and upper bounds of the effective size constraint are identical,
     * the encoding shall consist of the octets of the octetstring value (zero or more octets), with no length determinant.
     */
    if ((min_len != NO_BOUND ) && (min_len == max_len)) {
        actx->created_item = proto_tree_add_item(tree, hf_index, tvb, offset, min_len, ENC_NA);
        if (value_tvb) {
            *value_tvb = oer_tvb_new_subset_length(tvb, offset, min_len);
        }
        return offset + min_len;
    }

    /* 14.2 For any other octetstring type, the encoding shall consist of a length determinant (see 8.6)
     * followed by the octets of the octetstring value (zero or more octets).
     */
    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
    actx->created_item = proto_tree_add_item(tree, hf_index, tvb, offset, length, ENC_NA);
    if (value_tvb) {
        *value_tvb = oer_tvb_new_subset_length(tvb, offset, length);
    }

    offset = offset + length;

    return offset;

}

/* 15 Encoding of the null value */
uint32_t
dissect_oer_null(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index)
{
    /* The encoding of the null value shall be empty. */
    proto_item *ti_tmp;

    ti_tmp = proto_tree_add_item(tree, hf_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_tmp, ": NULL");

    return offset;
}

static const value_string oer_class_vals[] = {
    {   0, "universal" },
    {   1, "application" },
    {   2, "context-specific" },
    {   3, "private" },
    { 0, NULL }
};

static const value_string oer_extension_present_bit_vals[] = {
    {   0, "Not present" },
    {   1, "Present" },
    { 0, NULL }
};



/* 16 Encoding of sequence values */
uint32_t
dissect_oer_sequence(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const oer_sequence_t *sequence)
{
    uint64_t optional_field_flag;
    proto_item *item;
    proto_tree *tree;
    uint32_t old_offset = offset;
    uint32_t i, j, num_opts;
    uint32_t optional_mask[SEQ_MAX_COMPONENTS >> 5];
    int bit_offset = 0;
    uint64_t extensions_present = 0;

    DEBUG_ENTRY("dissect_oer_sequence");

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 0, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree(item, ett_index);


    /* first check if there should be an extension bit for this SEQUENSE.
    * we do this by just checking the first entry
    */
    bit_offset = offset << 3;
    if (sequence[0].extension == ASN1_NO_EXTENSIONS) {
        /*extension_present=0;  ?? */
    } else {
        /* 16.2.2 The extension bit shall be present (as bit 8 of the first octet of the preamble)
         * if, and only if, the sequence type definition contains an extension marker...
         */
        actx->created_item = proto_tree_add_bits_ret_val(tree, hf_oer_extension_present_bit, tvb, bit_offset, 1, &extensions_present, ENC_BIG_ENDIAN);
        bit_offset++;
        if (!display_internal_oer_fields) proto_item_set_hidden(actx->created_item);
    }
    /* The presence bitmap is encoded as a bit string with a fixed size constraint (see 16.2.3),
    * and has one bit for each field of the sequence type that has the keyword OPTIONAL or DEFAULT,
    * in specification order.
    */
    num_opts = 0;
    for (i = 0; sequence[i].p_id; i++) {
        if ((sequence[i].extension != ASN1_NOT_EXTENSION_ROOT) && (sequence[i].optional == ASN1_OPTIONAL)) {
            num_opts++;
        }
    }
    if (num_opts > SEQ_MAX_COMPONENTS) {
        dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "too many optional/default components");
    }

    memset(optional_mask, 0, sizeof(optional_mask));
    for (i = 0; i<num_opts; i++) {
        actx->created_item = proto_tree_add_bits_ret_val(tree, hf_oer_optional_field_bit, tvb, bit_offset, 1, &optional_field_flag, ENC_BIG_ENDIAN);
        bit_offset++;
        if (tree) {
            proto_item_append_text(actx->created_item, " (%s %s present)",
                index_get_optional_name(sequence, i), optional_field_flag ? "is" : "is NOT");
        }
        if (!display_internal_oer_fields) proto_item_set_hidden(actx->created_item);
        if (optional_field_flag) {
            optional_mask[i >> 5] |= 0x80000000 >> (i & 0x1f);
        }
    }
    if (num_opts > 0) {
        uint8_t len = num_opts >> 3;
        uint8_t remaining_bits = num_opts % 8;
        if (remaining_bits) {
            len++;
        }
        offset += len;
    }

    /*  */
    for (i = 0, j = 0; sequence[i].p_id; i++) {
        if ((sequence[i].extension == ASN1_NO_EXTENSIONS)
            || (sequence[i].extension == ASN1_EXTENSION_ROOT)) {
            if (sequence[i].optional == ASN1_OPTIONAL) {
                bool is_present;
                if (num_opts == 0) {
                    continue;
                }
                is_present = (0x80000000 >> (j & 0x1f))&optional_mask[j >> 5];
                num_opts--;
                j++;
                if (!is_present) {
                    continue;
                }
            }
            if (sequence[i].func) {
                offset = sequence[i].func(tvb, offset, actx, tree, *sequence[i].p_id);
            } else {
                dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, index_get_field_name(sequence, i));
            }
        }
    }

    if (extensions_present) {
        /* Parse the Extension Bitmap */
        int ext_bmp_len;
        uint8_t extension_mask[SEQ_MAX_COMPONENTS >> 3];
        offset = dissect_oer_bit_string_unconstr(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, false, NULL, 0, NULL, extension_mask, SEQ_MAX_COMPONENTS >> 3, &ext_bmp_len);

        /* find first extension */
        int seq_pos;
        for (seq_pos = 0; sequence[seq_pos].p_id; seq_pos++) {
            if (sequence[seq_pos].extension == ASN1_NOT_EXTENSION_ROOT) {
                break;
            }
        }
        for (int bitstr_pos = 0; bitstr_pos < ext_bmp_len; bitstr_pos++) {
            int8_t octet = extension_mask[bitstr_pos];
            for (int octet_pos = 0; octet_pos < 8; octet_pos++) {
                bool ext_present = ((octet << octet_pos) & (0x80)) >> 7;
                if (ext_present) {
                    /* If any extensions still known - use functions */
                    if (sequence[seq_pos].p_id) {
                        unsigned length;
                        offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
                        if (sequence[seq_pos].func) {
                            offset = sequence[seq_pos].func(tvb, offset, actx, tree, *sequence[seq_pos].p_id);
                        } else {
                            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, index_get_field_name(sequence, seq_pos    ));
                        }
                    } else {
                        offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, false, NULL);
                    }
                }
                /* if still within known sequence elements - move to next */
                if (sequence[seq_pos].p_id) {
                    seq_pos++;
                }
            }
        }

    }

    proto_item_set_len(item, offset - old_offset);
    actx->created_item = item;
    return offset;
}

/* 17 Encoding of sequence-of values */

static uint32_t
dissect_oer_sequence_of_helper(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, oer_type_fn func, int hf_index, uint32_t length)
{
    uint32_t i;

    DEBUG_ENTRY("dissect_oer_sequence_of_helper");
    for (i = 0; i<length; i++) {
        uint32_t lold_offset = offset;
        proto_item *litem;
        proto_tree *ltree;

        ltree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_oer_sequence_of_item, &litem, "Item %d", i);

        offset = (*func)(tvb, offset, actx, ltree, hf_index);
        proto_item_set_len(litem, offset - lold_offset);
    }

    return offset;
}

uint32_t
dissect_oer_sequence_of(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const oer_sequence_t *seq)
{
    proto_item *item;
    proto_tree *tree;
    uint32_t old_offset = offset;
    uint32_t occ_len, occurrence;
    header_field_info *hfi;

    DEBUG_ENTRY("dissect_oer_sequence_of");

    /* 17.1 The encoding of a sequence-of value shall consist of a quantity field...*/

    /* 17.2 The quantity field shall be a non-negative integer value indicating the number of occurrences.
     * This number shall be encoded as a length determinant (see 8.6) followed by a variable-size unsigned number
     * (occupying at least as many whole octets as are necessary to carry the value).
     */
    offset = dissect_oer_length_determinant(tvb, offset, actx, parent_tree, hf_oer_length_determinant, &occ_len);

    switch (occ_len) {
    case 1:
        occurrence = tvb_get_uint8(tvb, offset);
        break;
    case 2:
        occurrence = tvb_get_ntohs(tvb, offset);
        break;
    case 3:
        occurrence = tvb_get_ntoh24(tvb, offset);
        break;
    case 4:
        occurrence = tvb_get_ntohl(tvb, offset);
        break;
    default:
        proto_tree_add_expert_format(parent_tree, actx->pinfo, &ei_oer_not_decoded_yet, tvb, offset, 1,
            "sequence_of Occurrence %u octets not handled", occ_len);
        return tvb_reported_length(tvb);
    }

    offset = offset + occ_len;
    hfi = proto_registrar_get_nth(hf_index);
    if (FT_IS_UINT(hfi->type)) {
        item = proto_tree_add_uint(parent_tree, hf_index, tvb, old_offset, occ_len, occurrence);
        proto_item_append_text(item, (occurrence == 1) ? " item" : " items");
    } else {
        item = proto_tree_add_item(parent_tree, hf_index, tvb, old_offset, 0, ENC_BIG_ENDIAN);
    }
    tree = proto_item_add_subtree(item, ett_index);

    offset = dissect_oer_sequence_of_helper(tvb, offset, actx, tree, seq->func, *seq->p_id, occurrence);


    proto_item_set_len(item, offset - old_offset);
    return offset;

}

/* As we are using the per ASN1 generator define this "dummy" function */
uint32_t
dissect_oer_constrained_sequence_of(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const oer_sequence_t *seq, int min_len _U_, int max_len _U_ , bool has_extension _U_)
{
    return dissect_oer_sequence_of(tvb, offset, actx, parent_tree, hf_index, ett_index, seq);

}
/* 20 Encoding of choice values */
uint32_t
dissect_oer_choice(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int ett_index, const oer_choice_t *choice, int *value)
{
    proto_tree *choice_tree;
    proto_item *item, *choice_item;
    int bit_offset = offset << 3;
    uint64_t oer_class;
    uint8_t tag, oct;
    int old_offset = offset;

    /* 20.1 The encoding of a value of a choice type shall consist of the encoding of the outermost tag of the type of the chosen alternative
     * as specified in 8.7, followed by the encoding of the value of the chosen alternative.
     */

    /* 8.7.2.1 Bits 8 and 7 of the first octet shall denote the tag class */
    item = proto_tree_add_bits_ret_val(tree, hf_oer_class, tvb, bit_offset, 2, &oer_class, ENC_BIG_ENDIAN);
    if (!display_internal_oer_fields) proto_item_set_hidden(item);
    bit_offset += 2;

    tag = tvb_get_bits8(tvb, bit_offset, 6);
    offset++;
    /* 8.7.2.3 If the tag number is greater or equal to 63, Bits 6 to 1 of the initial octet shall be set to '111111'B.*/
    if (tag == 0x3f) {
        /* The tag number shall be encoded into bits 7 to 1 of each subsequent octet (seven bits in each octet),
         * with bit 1 of the final subsequent octet containing the least significant bit of the tag number ("big-endian" encoding).
         */
        oct = tvb_get_uint8(tvb, offset);
        if ((oct & 0x80) == 0x80) {
            dissect_oer_not_decoded_yet(tree, actx->pinfo, tvb, "Choice, Tag value > 0x7f not implemented yet");
        } else {
            /* Bits 7 to 1 of the first subsequent octet shall not be all set to 0.*/
            tag = oct;
            item = proto_tree_add_uint(tree, hf_oer_tag, tvb, offset, 1, tag);
            if (!display_internal_oer_fields) proto_item_set_hidden(item);
        }
    } else {
        /* Tag value in first octet */
        item = proto_tree_add_bits_item(tree, hf_oer_tag, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
        if (!display_internal_oer_fields) proto_item_set_hidden(item);
    }

    /* 20.2 If the choice type contains an extension marker in the "AlternativeTypeLists" and the chosen alternative
     * is one of the extension additions, then the value of the chosen alternative shall be encoded as if it were contained
     * in an open type (see clause 30), otherwise it shall be encoded normally.
     */
    if (value) {
        (*value) = -1;
    }

    /* XXX Extension handling is not implemented */
    while (choice->func) {
        if (choice->value == tag) {
            choice_item = proto_tree_add_uint(tree, hf_index, tvb, old_offset, 0, choice->value);
            choice_tree = proto_item_add_subtree(choice_item, ett_index);
            /* For known extensions parse length prefix */
            if (choice->extension == ASN1_NOT_EXTENSION_ROOT) {
                unsigned length;
                offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
            }
            offset = choice->func(tvb, offset, actx, choice_tree, *choice->p_id);
            proto_item_set_len(choice_item, offset - old_offset);
            if (value) {
                (*value) = tag;
            }
            return offset;
        }
        choice++;
    }
    /* None of the known choice options matched, parse the contents as an extension */
    // XXX : should check if the extensions are present in the CHOICE definition
    offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, false, NULL);

    return offset;
}

/* 21 Encoding of object identifier values
 * The encoding of an object identifier value shall consist of a length determinant (see 8.6) followed by a series of octets,
 * which are the contents octets of BER encoding of the object identifier value (see Rec. ITU-T X.690 | ISO/IEC 8825-1,8.19).
 */
static uint32_t
dissect_oer_any_oid(tvbuff_t* tvb, uint32_t offset, asn1_ctx_t* actx, proto_tree* tree, int hf_index, tvbuff_t** value_tvb,
    bool is_absolute)
{
    unsigned length;
    const char* str;
    header_field_info* hfi;

    DEBUG_ENTRY("dissect_oer_any_oid");

    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);

    actx->created_item = NULL;
    hfi = proto_registrar_get_nth(hf_index);
    if ((is_absolute && hfi->type == FT_OID) || (!is_absolute && hfi->type == FT_REL_OID)) {
        actx->created_item = proto_tree_add_item(tree, hf_index, tvb, offset, length, ENC_BIG_ENDIAN);
    }
    else if (FT_IS_STRING(hfi->type)) {
        str = oid_encoded2string(actx->pinfo->pool, tvb_get_ptr(tvb, offset, length), length);
        actx->created_item = proto_tree_add_string(tree, hf_index, tvb, offset, length, str);
        if (actx->created_item) {
            /* see if we know the name of this oid */
            str = oid_resolved_from_encoded(actx->pinfo->pool, tvb_get_ptr(tvb, offset, length), length);
            if (str) {
                proto_item_append_text(actx->created_item, " (%s)", str);
            }
        }
    }
    else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    if (value_tvb)
        *value_tvb = tvb_new_subset_length(tvb, offset, length);

    return offset;
}

uint32_t
dissect_oer_object_identifier(tvbuff_t* tvb, uint32_t offset, asn1_ctx_t* actx, proto_tree* tree, int hf_index, tvbuff_t** value_tvb)
{
    return dissect_oer_any_oid(tvb, offset, actx, tree, hf_index, value_tvb, true);
}

/* 27 Encoding of values of the restricted character string types
 * 27.1 The encoding of a restricted character string type depends on whether the type is a known-multiplier character
 * string type or not. The following types are known-multiplier character string types:
 *  IA5String, VisibleString, ISO646String, PrintableString, NumericString, BMPString, and UniversalString.
 */


uint32_t
dissect_oer_IA5String(tvbuff_t* tvb, uint32_t offset, asn1_ctx_t* actx, proto_tree* tree, int hf_index, int min_len, int max_len, bool has_extension _U_)
{
    uint32_t length = 0;

    /* 27.2 For a known-multiplier character string type in which the lower and upper bounds of the effective size constraint
     * are identical, the encoding shall consist of the series of octets specified in 27.4, with no length determinant.
     */
    if ((min_len == max_len) && (min_len != NO_BOUND )){
        length = min_len;
    }
    else {
        offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
    }
    actx->created_item = proto_tree_add_item(tree, hf_index, tvb, offset, length, ENC_ASCII | ENC_NA);

    return offset + length;

}

uint32_t
dissect_oer_UTF8String(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len _U_, int max_len _U_, bool has_extension _U_)
{
    uint32_t length = 0;
    /* 27.3 For every other character string type, the encoding shall consist of a length determinant
     * (see 8.6) followed by the series of octets specified in 27.4.
     */
    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_length_determinant, &length);
    actx->created_item = proto_tree_add_item( tree, hf_index, tvb, offset, length, ENC_UTF_8 | ENC_NA);

    return offset + length;

}

/* 30 Encoding of open type values
 *NOTE – An open type is an ASN.1 type that can take any abstract value of any ASN.1 type. Each value of an open type consists
 * of:
 * a) a contained type; and
 * b) a value of the contained type.
 * The encoding of an open type value shall consist of a length determinant (see 8.6) followed by a series of octets, which
 * are the encoding of the value of the contained type.
 */

static uint32_t
dissect_oer_open_type_internal(tvbuff_t* tvb, uint32_t offset, asn1_ctx_t* actx, proto_tree* tree, int hf_index, void* type_cb, asn1_cb_variant variant)
{
    int type_length, start_offset;
    tvbuff_t* val_tvb = NULL;
    proto_tree* subtree = tree;

    start_offset = offset;


    offset = dissect_oer_length_determinant(tvb, offset, actx, tree, hf_oer_open_type_length, &type_length);
    val_tvb = tvb_new_subset_length(tvb, offset, type_length);

    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, type_length, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(actx->created_item, ett_oer_open_type);

    if (variant == CB_NEW_DISSECTOR) {
        add_new_data_source(actx->pinfo, val_tvb, "OCTET STRING");
    }

    if (type_cb) {
        switch (variant) {
        case CB_ASN1_ENC:
            ((oer_type_fn)type_cb)(val_tvb, 0, actx, tree, hf_index);
            break;
        case CB_NEW_DISSECTOR:
            /* Pas actx->private_data as "data" to the called function */
            ((dissector_t)type_cb)(val_tvb, actx->pinfo, subtree, actx->private_data);
            break;
        case CB_DISSECTOR_HANDLE:
            break;
        }
    }
    else {
        actx->created_item = proto_tree_add_expert(tree, actx->pinfo, &ei_oer_open_type, tvb, start_offset, offset - start_offset);
    }

    return offset;
}
uint32_t
dissect_oer_open_type(tvbuff_t* tvb, uint32_t offset, asn1_ctx_t* actx, proto_tree* tree, int hf_index, oer_type_fn type_cb)
{
    return dissect_oer_open_type_internal(tvb, offset, actx, tree, hf_index, (void*)type_cb, CB_ASN1_ENC);
}

/*--- proto_register_oer ----------------------------------------------*/
void proto_register_oer(void) {

    /* List of fields */
    static hf_register_info hf[] = {
        { &hf_oer_optional_field_bit,
        { "Optional Field Bit", "oer.optional_field_bit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oer_class,
        { "Class", "oer.class",
            FT_UINT8, BASE_DEC, VALS(oer_class_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_oer_tag,
        { "Tag", "oer.tag",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oer_length_determinant,
        { "length_determinant", "oer.length_determinant",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oer_extension_present_bit,
        { "Extension Present Bit", "oer.extension_present_bit",
        FT_UINT8, BASE_DEC, VALS(oer_extension_present_bit_vals), 0x00,
        NULL, HFILL } },
        { &hf_oer_open_type_length,
        { "Open Type Length", "oer.open_type_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

    };

    /* List of subtrees hf_oer_extension*/
    static int *ett[] = {
        &ett_oer,
        &ett_oer_sequence_of_item,
        &ett_oer_open_type,
    };

    module_t *oer_module;
    expert_module_t* expert_oer;

    /* Register protocol */
    proto_oer = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Register fields and subtrees */
    proto_register_field_array(proto_oer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    static ei_register_info ei[] = {
        { &ei_oer_not_decoded_yet,
            { "oer.not_decoded_yet", PI_UNDECODED, PI_WARN, "Not decoded yet", EXPFILL }},
        { &ei_oer_undecoded,
            { "oer.error.undecoded", PI_UNDECODED, PI_WARN, "OER: Something unknown here", EXPFILL } },
        { &ei_oer_open_type,
            { "oer.open_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Open Type", EXPFILL }},
    };

    expert_oer = expert_register_protocol(proto_oer);
    expert_register_field_array(expert_oer, ei, array_length(ei));

    oer_module = prefs_register_protocol(proto_oer, NULL);
    prefs_register_bool_preference(oer_module, "display_internal_oer_fields",
        "Display the internal OER fields in the tree",
        "Whether the dissector should put the internal OER data in the tree or if it should hide it",
        &display_internal_oer_fields);


    proto_set_cant_toggle(proto_oer);

}


        /*--- proto_reg_handoff_oer -------------------------------------------*/
void proto_reg_handoff_oer(void) {

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
