/*
XXX all this offset>>3 and calculations of bytes in the tvb everytime
we put something in the tree is just silly.  should be replaced with some
proper helper routines
*/
/* packet-per.c
 * Routines for dissection of ASN.1 Aligned PER
 * 2003  Ronnie Sahlberg
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <math.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/asn1.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include "packet-per.h"


static int proto_per = -1;
static int hf_per_GeneralString_length = -1;
static int hf_per_extension_bit = -1;
static int hf_per_extension_present_bit = -1;
static int hf_per_choice_index = -1;
static int hf_per_choice_extension_index = -1;
static int hf_per_enum_index = -1;
static int hf_per_enum_extension_index = -1;
static int hf_per_num_sequence_extensions = -1;
static int hf_per_small_number_bit = -1;
static int hf_per_optional_field_bit = -1;
static int hf_per_sequence_of_length = -1;
static int hf_per_object_identifier_length = -1;
static int hf_per_open_type_length = -1;
static int hf_per_real_length = -1;
static int hf_per_octet_string_length = -1;
static int hf_per_bit_string_length = -1;
static int hf_per_const_int_len = -1;
static int hf_per_direct_reference = -1;          /* T_direct_reference */
static int hf_per_indirect_reference = -1;        /* T_indirect_reference */
static int hf_per_data_value_descriptor = -1;     /* T_data_value_descriptor */
static int hf_per_encoding = -1;                  /* External_encoding */
static int hf_per_single_ASN1_type = -1;          /* T_single_ASN1_type */
static int hf_per_octet_aligned = -1;             /* T_octet_aligned */
static int hf_per_arbitrary = -1;                 /* T_arbitrary */
static int hf_per_integer_length = -1;			  /* Show integer length if "show internal per fields" */
static int hf_per_debug_pos = -1;

static gint ett_per_open_type = -1;
static gint ett_per_containing = -1;
static gint ett_per_sequence_of_item = -1;
static gint ett_per_External = -1;
static gint ett_per_External_encoding = -1;

/*
#define DEBUG_ENTRY(x) \
printf("#%u  %s   tvb:0x%08x\n",actx->pinfo->fd->num,x,(int)tvb);
*/
#define DEBUG_ENTRY(x) \
	;

#define BLEN(old_offset, offset) (((offset)>>3)!=((old_offset)>>3)?((offset)>>3)-((old_offset)>>3):1)

/* whether the PER helpers should put the internal PER fields into the tree
   or not.
*/
static gboolean display_internal_per_fields = FALSE;



static const true_false_string tfs_extension_present_bit = {
	"",
	""
};
static const true_false_string tfs_extension_bit = {
	"Extension bit is set",
	"Extension bit is clear"
};
static const true_false_string tfs_small_number_bit = {
	"The number is small, 0-63",
	"The number is large, >63"
};
static const true_false_string tfs_optional_field_bit = {
	"",
	""
};


#define BYTE_ALIGN_OFFSET(offset) if(offset&0x07){offset=(offset&0xfffffff8)+8;}

static void per_check_value(guint32 value, guint32 min_len, guint32 max_len, asn1_ctx_t *actx, proto_item *item, gboolean is_signed)
{
	if ((is_signed == FALSE) && (value > max_len)) {
		expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %u (%u .. %u)", value, min_len, max_len);
	} else if ((is_signed == TRUE) && ((gint32)value > (gint32)max_len)) {
		expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %d (%d .. %d)", (gint32)value, (gint32)min_len, (gint32)max_len);
	}
}

static void per_check_value64(guint64 value, guint64 min_len, guint64 max_len, asn1_ctx_t *actx, proto_item *item, gboolean is_signed)
{
	if ((is_signed == FALSE) && (value > max_len)) {
		expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %" G_GINT64_MODIFIER "u (%" G_GINT64_MODIFIER "u .. %" G_GINT64_MODIFIER "u)", value, min_len, max_len);
	} else if ((is_signed == TRUE) && ((gint64)value > (gint64)max_len)) {
		expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %" G_GINT64_MODIFIER "d (%" G_GINT64_MODIFIER "d .. %" G_GINT64_MODIFIER "d)", (gint64)value, (gint64)min_len, (gint64)max_len);
	}
}

static void per_check_items(guint32 cnt, int min_len, int max_len, asn1_ctx_t *actx, proto_item *item)
{
	if (min_len != NO_BOUND && cnt < (guint32)min_len) {
		expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: too few items: %d (%d .. %d)", cnt, min_len, max_len);
	} else if (max_len != NO_BOUND && cnt > (guint32)max_len) {
		expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: too many items: %d (%d .. %d)", cnt, min_len, max_len);
	}
}

static tvbuff_t *new_octet_aligned_subset(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, guint32 length)
{
  tvbuff_t *sub_tvb = NULL;
  guint32 boffset = offset >> 3;
  unsigned int i, shift0, shift1;
  guint8 octet0, octet1, *buf;
  guint32 actual_length;

  /*  XXX - why are we doing this?  Shouldn't we throw an exception if we've
   *  been asked to decode more octets than exist?
   */
  actual_length = tvb_length_remaining(tvb,boffset);
  if (length <= actual_length)
	  actual_length = length;

  if (offset & 0x07) {  /* unaligned */
    shift1 = offset & 0x07;
    shift0 = 8 - shift1;
    buf = g_malloc(actual_length);
    octet0 = tvb_get_guint8(tvb, boffset);
    for (i=0; i<actual_length; i++) {
      octet1 = octet0;
      octet0 = tvb_get_guint8(tvb, boffset + i + 1);
      buf[i] = (octet1 << shift1) | (octet0 >> shift0);
    }
    sub_tvb = tvb_new_child_real_data(tvb, buf, actual_length, length);
    tvb_set_free_cb(sub_tvb, g_free);
    add_new_data_source(actx->pinfo, sub_tvb, "Unaligned OCTET STRING");
  } else {  /* aligned */
    sub_tvb = tvb_new_subset(tvb, boffset, actual_length, length);
  }
  return sub_tvb;
}

/* 10 Encoding procedures -------------------------------------------------- */

/* 10.2 Open type fields --------------------------------------------------- */
static guint32
dissect_per_open_type_internal(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, void* type_cb, asn1_cb_variant variant)
{
	guint32 type_length, end_offset;
	tvbuff_t *val_tvb = NULL;
	header_field_info *hfi;
	proto_tree *subtree = tree;

	hfi = (hf_index == -1) ? NULL : proto_registrar_get_nth(hf_index);

	offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_open_type_length, &type_length);
	if (actx->aligned) BYTE_ALIGN_OFFSET(offset);
	end_offset = offset + type_length * 8;

    if ((variant==CB_DISSECTOR)||(variant==CB_NEW_DISSECTOR)) {
		val_tvb = new_octet_aligned_subset(tvb, offset, actx, type_length);
		if (hfi) {
			if (IS_FT_UINT(hfi->type)||IS_FT_INT(hfi->type)) {
				if (IS_FT_UINT(hfi->type))
					actx->created_item = proto_tree_add_uint(tree, hf_index, val_tvb, 0, type_length, type_length);
				else
					actx->created_item = proto_tree_add_int(tree, hf_index, val_tvb, 0, type_length, type_length);
				proto_item_append_text(actx->created_item, plurality(type_length, " octet", " octets"));
			} else {
				actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, type_length, ENC_BIG_ENDIAN);
			}
			subtree = proto_item_add_subtree(actx->created_item, ett_per_open_type);
		}
	}

	if (type_cb) {
		switch (variant) {
			case CB_ASN1_ENC:
				((per_type_fn)type_cb)(tvb, offset, actx, tree, hf_index);
				break;
			case CB_DISSECTOR:
				((dissector_t)type_cb)(val_tvb, actx->pinfo, subtree);
				break;
			case CB_NEW_DISSECTOR:
				((new_dissector_t)type_cb)(val_tvb, actx->pinfo, subtree, NULL);
				break;
			case CB_DISSECTOR_HANDLE:
				break;
		}
	} else {
		actx->created_item = proto_tree_add_text(tree, tvb, offset>>3, BLEN(offset, end_offset), "Unknown Open Type");
	}

	return end_offset;
}

guint32
dissect_per_open_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb)
{
	return dissect_per_open_type_internal(tvb, offset, actx, tree, hf_index, (void*)type_cb, CB_ASN1_ENC);
}

guint32
dissect_per_open_type_pdu(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, dissector_t type_cb)
{
	return dissect_per_open_type_internal(tvb, offset, actx, tree, hf_index, (void*)type_cb, CB_DISSECTOR);
}

guint32
dissect_per_open_type_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, new_dissector_t type_cb)
{
	return dissect_per_open_type_internal(tvb, offset, actx, tree, hf_index, (void*)type_cb, CB_NEW_DISSECTOR);
}

/* 10.9 General rules for encoding a length determinant --------------------

	  NOTE 1 - (Tutorial) The procedures of this subclause are invoked when an explicit length field is needed
				for some part of the encoding regardless of whether the length count is bounded above
				(by PER-visible constraints) or not. The part of the encoding to which the length applies may
				be a bit string (with the length count in bits), an octet string (with the length count in octets),
				a known-multiplier character string (with the length count in characters), or a list of fields
				(with the length count in components of a sequence-of or set-of).

	  NOTE 2 - (Tutorial) In the case of the ALIGNED variant if the length count is bounded above by an upper bound
				that is less than 64K, then the constrained whole number encoding is used for the length.
				For sufficiently small ranges the result is a bit-field, otherwise the unconstrained length ("n" say)
				is encoded into an octet-aligned bit-field in one of three ways (in order of increasing size):
		a)	("n" less than 128) a single octet containing "n" with bit 8 set to zero;
		b)	("n" less than 16K) two octets containing "n" with bit 8 of the first octet set to 1 and bit 7 set to zero;
		c)	(large "n") a single octet containing a count "m" with bit 8 set to 1 and bit 7 set to 1.
			The count "m" is one to four, and the length indicates that a fragment of the material follows
			(a multiple "m" of 16K items). For all values of "m", the fragment is then followed by another length encoding
			for the remainder of the material.

	  NOTE 3 - (Tutorial) In the UNALIGNED variant, if the length count is bounded above by an upper bound that is less
			than 64K, then the constrained whole number encoding is used to encode the length in the minimum number of
			bits necessary to represent the range. Otherwise, the unconstrained length ("n" say) is encoded into a bit
			field in the manner described above in Note 2.

 */
guint32
dissect_per_length_determinant(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index, guint32 *length)
{
	guint8 byte;
	guint32 len;
	proto_item *pi;
	int num_bits;
	int i, bit, str_length, str_index;
	gboolean tmp;

	if(!length){
		length=&len;
	}

	/* byte aligned */
	if (actx->aligned){
		BYTE_ALIGN_OFFSET(offset);
		byte=tvb_get_guint8(tvb, offset>>3);
		offset+=8;
	}else{
		char *str;
		guint32 val;

		val = 0;

		/* prepare the string (max number of bits + quartet separators + prepended space) */
		str_length = 256+64+1;
		str=ep_alloc(str_length+1);
		str_index = 0;

		str_length = g_snprintf(str, str_length+1, " ");
		for(bit=0;bit<((int)(offset&0x07));bit++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if (str_index < str_length) str[str_index++] = '.';
		}
		/* read the bits for the int */
		num_bits = 8;
		for(i=0;i<num_bits;i++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if(bit&&(!(bit%8))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			bit++;
			offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &tmp);
			val<<=1;
			if(tmp){
				val|=1;
				if (str_index < str_length) str[str_index++] = '1';
				if (i==0) { /* bit 8 is 1, so not a single byte length */
					num_bits = 16;
				}
				else if (i==1 && val==3) { /* bits 8 and 7 both 1, so unconstrained */
					PER_NOT_DECODED_YET("10.9 Unconstrained");
					return offset;
				}
			} else {
				if (str_index < str_length) str[str_index++] = '0';
			}
		}
		str[str_index] = '\0'; /* Terminate string */
		if((val&0x80)==0 && num_bits==8){
			*length = val;
			if(hf_index!=-1){
				pi = proto_tree_add_uint(tree, hf_index, tvb, (offset>>3)-1, 1, *length);
				if (display_internal_per_fields)
					proto_item_append_text(pi," %s", str);
				else
					PROTO_ITEM_SET_HIDDEN(pi);
			}

			return offset;
		}
		else if (num_bits==16) {
			*length = val&0x3fff;
			if(hf_index!=-1){
				pi = proto_tree_add_uint(tree, hf_index, tvb, (offset>>3)-1, 1, *length);
				if (display_internal_per_fields)
					proto_item_append_text(pi," %s", str);
				else
					PROTO_ITEM_SET_HIDDEN(pi);
			}

			return offset;
		}
		PER_NOT_DECODED_YET("10.9 Unaligned");
		return offset;

	}

	/* 10.9.3.6 */
	if((byte&0x80)==0){
		*length=byte;
		if(hf_index!=-1){
			pi = proto_tree_add_uint(tree, hf_index, tvb, (offset>>3)-1, 1, *length);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
		}
		return offset;
	}

	/* 10.9.3.7 */
	if((byte&0xc0)==0x80){
		*length=(byte&0x3f);
		*length=((*length)<<8)+tvb_get_guint8(tvb, offset>>3);
		offset+=8;
		if(hf_index!=-1){
			pi = proto_tree_add_uint(tree, hf_index, tvb, (offset>>3)-2, 2, *length);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
		}
		return offset;
	}
	PER_NOT_DECODED_YET("10.9.3.8.1");
	return offset;
}

/* 10.6   normally small non-negative whole number */
static guint32
dissect_per_normally_small_nonnegative_whole_number(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 *length)
{
	gboolean small_number, length_bit;
	guint32 len;
	proto_item *pi;

DEBUG_ENTRY("dissect_per_normally_small_nonnegative_whole_number");
	if(!length){
		length=&len;
	}

	offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_small_number_bit, &small_number);
	if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	if(!small_number){
		int i;
		/* 10.6.1 */
		*length=0;
		for(i=0;i<6;i++){
			offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &length_bit);
			*length<<=1;
			if (length_bit) {
				*length|=1;
			}
		}
		if(hf_index!=-1){
			pi = proto_tree_add_uint(tree, hf_index, tvb, (offset-6)>>3, (offset%8<6)?2:1, *length);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
		}
		return offset;
	}

	/* 10.6.2 */
	offset=dissect_per_length_determinant(tvb, offset, actx, tree, hf_index, length);

	return offset;
}



/* this function reads a GeneralString */
/* currently based on pure guesswork since RFC2833 didnt tell me much
   i guess that the PER encoding for this is a normally-small-whole-number
   followed by a ascii string.

   based on pure guesswork.  it looks ok in the only capture i have where
   there is a 1 byte general string encoded
*/
guint32
dissect_per_GeneralString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	guint32 length;

	offset=dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_GeneralString_length, &length);

	proto_tree_add_item(tree, hf_index, tvb, offset>>3, length, ENC_BIG_ENDIAN);

	offset+=length*8;

	return offset;
}

/* 17 Encoding the null type */
guint32
dissect_per_null(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  proto_item *ti_tmp;

  ti_tmp = proto_tree_add_item(tree, hf_index, tvb, offset>>3, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(ti_tmp, ": NULL");

  return offset;
}

/* 19 this function dissects a sequence of */
static guint32
dissect_per_sequence_of_helper(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, per_type_fn func, int hf_index, guint32 length)
{
	guint32 i;

DEBUG_ENTRY("dissect_per_sequence_of_helper");
	for(i=0;i<length;i++){
		guint32 lold_offset=offset;
		proto_item *litem;
		proto_tree *ltree;

		litem=proto_tree_add_text(tree, tvb, offset>>3, 0, "Item %d", i);
		ltree=proto_item_add_subtree(litem, ett_per_sequence_of_item);

		offset=(*func)(tvb, offset, actx, ltree, hf_index);
		proto_item_set_len(litem, (offset>>3)!=(lold_offset>>3)?(offset>>3)-(lold_offset>>3):1);
	}

	return offset;
}
guint32
dissect_per_sequence_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq)
{
	proto_item *item;
	proto_tree *tree;
	guint32 old_offset=offset;
	guint32 length;
	header_field_info *hfi;

DEBUG_ENTRY("dissect_per_sequence_of");

	/* semi-constrained whole number for number of elements */
	/* each element encoded as 10.9 */

	offset=dissect_per_length_determinant(tvb, offset, actx, parent_tree, hf_per_sequence_of_length, &length);

	hfi = proto_registrar_get_nth(hf_index);
	if (IS_FT_UINT(hfi->type)) {
		item = proto_tree_add_uint(parent_tree, hf_index, tvb, old_offset>>3, 0, length);
		proto_item_append_text(item, (length==1)?" item":" items");
	} else {
		item=proto_tree_add_item(parent_tree, hf_index, tvb, old_offset>>3, 0, ENC_BIG_ENDIAN);
	}
	tree=proto_item_add_subtree(item, ett_index);

	offset=dissect_per_sequence_of_helper(tvb, offset, actx, tree, seq->func, *seq->p_id, length);


	proto_item_set_len(item, (offset>>3)!=(old_offset>>3)?(offset>>3)-(old_offset>>3):1);
	return offset;
}


/* XXX we don't do >64k length strings   yet */
static guint32
dissect_per_restricted_character_string_sorted(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension _U_,const char *alphabet, int alphabet_length, tvbuff_t **value_tvb)
{
	guint32 length;
	gboolean byte_aligned;
	guint8 *buf;
	guint char_pos;
	int bits_per_char;
	guint32 old_offset;

DEBUG_ENTRY("dissect_per_restricted_character_string");

	/* xx.x if the length is 0 bytes there will be no encoding */
	if(max_len==0){
		if (value_tvb) {
			*value_tvb = tvb_new_child_real_data(tvb, NULL, 0, 0);
		}
		return offset;
	}


	if (min_len == NO_BOUND) {
		min_len=0;
	}


	/* 27.5.2 depending of the alphabet length, find how many bits
	   are used to encode each character */
/* unaligned PER */
	if (actx->aligned){

		if(alphabet_length<=2){
			bits_per_char=1;
		} else if(alphabet_length<=4){
			bits_per_char=2;
		} else if(alphabet_length<=16){
			bits_per_char=4;
		} else {
			bits_per_char=8;
		}
	}else{
		if(alphabet_length<=2){
			bits_per_char=1;
		} else if(alphabet_length<=4){
			bits_per_char=2;
		} else if(alphabet_length<=8){
			bits_per_char=3;
		} else if(alphabet_length<=16){
			bits_per_char=4;
		} else if(alphabet_length<=32){
			bits_per_char=5;
		} else if(alphabet_length<=64){
			bits_per_char=6;
		} else if(alphabet_length<=128){
			bits_per_char=7;
		} else {
			bits_per_char=8;
		}
	}
	/* 27.4	If the type is extensible for PER encodings (see 9.3.16),
	 * then a bit-field consisting of a single bit shall be added to the field-list.
	 * The single bit shall be set to zero if the value is within the range of the extension root,
	 * and to one otherwise. If the value is outside the range of the extension root,
	 * then the following encoding shall be as if there was no effective size constraint,
	 * and shall have an effective permitted-alphabet constraint that consists of the set of characters
	 * of the unconstrained type.
	 * 	NOTE - Only the known-multiplier character string types can be extensible for PER encodings.
	 * Extensibility markers on other character string types do not affect the PER encoding.
	 */

	if (has_extension) {
		gboolean extension_present;
		offset = dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_present);
		if(extension_present){
			min_len = NO_BOUND;
			max_len = NO_BOUND;
		}
	}

	byte_aligned=TRUE;
	if((min_len==max_len)&&(max_len<=2)){
		byte_aligned=FALSE;
	}
	if ((max_len != NO_BOUND) && (max_len < 2)) {
		byte_aligned=FALSE;
	}

	/* xx.x */
	length=max_len;
	if (max_len == NO_BOUND) {
		offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_octet_string_length, &length);
		/* the unconstrained strings are always byte aligned (27.6.3)*/
		byte_aligned=TRUE;
	} else if(min_len!=max_len){
		offset=dissect_per_constrained_integer(tvb, offset, actx,
			tree, hf_per_octet_string_length, min_len, max_len,
			&length, FALSE);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	}

	if(!length){
		/* there is no string at all, so don't do any byte alignment */
		/* byte_aligned=FALSE; */
		/* Advance offset to next 'element' */
		offset = offset + 1;	}

	if((byte_aligned)&&(actx->aligned)){
		BYTE_ALIGN_OFFSET(offset);
	}


	buf = g_malloc(length+1);
	old_offset=offset;
	for(char_pos=0;char_pos<length;char_pos++){
		guchar val;
		int i;
		gboolean bit;

		val=0;
		for(i=0;i<bits_per_char;i++){
			offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &bit);
			val=(val<<1)|bit;
		}
		/* ALIGNED PER does not do any remapping of chars if
		   bitsperchar is 8
		*/
		/* If alphabet is not provided, do not do any remapping either */
		if((bits_per_char==8) || (alphabet==NULL)){
			buf[char_pos]=val;
		} else {
			if (val < alphabet_length){
				buf[char_pos]=alphabet[val];
			} else {
				buf[char_pos] = '?';	/* XXX - how to mark this? */
			}
		}
	}
	buf[char_pos]=0;
	proto_tree_add_string(tree, hf_index, tvb, (old_offset>>3), (offset>>3)-(old_offset>>3), (char*)buf);
	if (value_tvb) {
		*value_tvb = tvb_new_child_real_data(tvb, buf, length, length);
		tvb_set_free_cb(*value_tvb, g_free);
	} else {
		g_free(buf);
	}
	return offset;
}

static const char*
sort_alphabet(char *sorted_alphabet, const char *alphabet, int alphabet_length)
{
  int i, j;
  char c, c_max, c_min;
  char tmp_buf[256];

  if (!alphabet_length) return sorted_alphabet;
  memset(tmp_buf, 0, 256);
  c_min = c_max = alphabet[0];
  for (i=0; i<alphabet_length; i++) {
    c = alphabet[i];
    tmp_buf[(int)c] = 1;
    if (c > c_max) c_max = c;
    else if (c < c_min) c_min = c;
  }
  for (i=c_min,j=0; i<=c_max; i++) {
    if (tmp_buf[i]) sorted_alphabet[j++] = i;
  }
  return sorted_alphabet;
}

guint32
dissect_per_restricted_character_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb)
{
  const char *alphabet_ptr;
  char sorted_alphabet[128];

  if (alphabet_length > 127) {
    alphabet_ptr = alphabet;
  } else {
    alphabet_ptr = sort_alphabet(sorted_alphabet, alphabet, alphabet_length);
  }
  return dissect_per_restricted_character_string_sorted(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension, alphabet_ptr, alphabet_length, value_tvb);
}

/* dissect a constrained IA5String that consists of the full ASCII set,
   i.e. no FROM stuff limiting the alphabet
*/
guint32
dissect_per_IA5String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension,
		NULL, 128, NULL);

	return offset;
}

guint32
dissect_per_NumericString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension,
		" 0123456789", 11, NULL);

	return offset;
}
guint32
dissect_per_PrintableString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension,
		" '()+,-.*0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 74, NULL);
	return offset;
}
guint32
dissect_per_VisibleString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension,
		" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", 95, NULL);
	return offset;
}
guint32
dissect_per_BMPString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension _U_)
{
	guint32 length;
	static char *str;

	/* xx.x if the length is 0 bytes there will be no encoding */
	if(max_len==0){
		return offset;
	}


	if (min_len == NO_BOUND) {
		min_len = 0;
	}


	/* xx.x */
	length=max_len;
	if(min_len!=max_len){
		offset=dissect_per_constrained_integer(tvb, offset, actx,
			tree, hf_per_octet_string_length, min_len, max_len,
			&length, FALSE);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	}


	/* align to byte boundary */
	BYTE_ALIGN_OFFSET(offset);

	if(length>=1024){
		PER_NOT_DECODED_YET("BMPString too long");
		length=1024;
	}

	str = tvb_get_ephemeral_unicode_string(tvb, offset>>3, length*2, ENC_BIG_ENDIAN);

	proto_tree_add_string(tree, hf_index, tvb, offset>>3, length*2, str);

	offset+=(length<<3)*2;

	return offset;
}

guint32
dissect_per_object_descriptor(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb)
{
	offset=dissect_per_octet_string(tvb, offset, actx, tree, hf_index, -1, -1, FALSE, value_tvb);

	return offset;
}


/* this function dissects a constrained sequence of */
guint32
dissect_per_constrained_sequence_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len, gboolean has_extension _U_)
{
	proto_item *item;
	proto_tree *tree;
	guint32 old_offset=offset;
	guint32 length;
	header_field_info *hfi;

DEBUG_ENTRY("dissect_per_constrained_sequence_of");

	/* 19.4	If there is a PER-visible constraint and an extension marker is present in it,
	 * a single bit shall be added to the field-list in a bit-field of length one
	 */
	if(has_extension){
		gboolean extension_present;
		offset=dissect_per_boolean(tvb, offset, actx, parent_tree, hf_per_extension_present_bit, &extension_present);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		if(extension_present){
			/* 10.9 shall be invoked to add the length determinant as a semi-constrained whole number to the field-list,
			 * followed by the component values
			 * TODO: Handle extension
			 */
			proto_tree_add_text(parent_tree, tvb, (offset>>3), 1, "dissect_per_constrained_sequence_of with extension is not handled");
		}
	}

	/* 19.5 if min==max and min,max<64k ==> no length determinant */
	if((min_len==max_len) && (min_len<65536)){
		length=min_len;
		goto call_sohelper;
	}

	/* 19.6 ub>=64k or unset */
	if ((max_len >= 65536) || (max_len == NO_BOUND)) {
		/* no constraint, see 10.9.4.2 */
		offset=dissect_per_length_determinant(tvb, offset, actx, parent_tree, hf_per_sequence_of_length, &length);
		goto call_sohelper;
	}

	/* constrained whole number for number of elements */
	offset=dissect_per_constrained_integer(tvb, offset, actx,
		parent_tree, hf_per_sequence_of_length, min_len, max_len,
		&length, FALSE);
	if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);

call_sohelper:
	hfi = proto_registrar_get_nth(hf_index);
	if (IS_FT_UINT(hfi->type)) {
		item = proto_tree_add_uint(parent_tree, hf_index, tvb, offset>>3, 0, length);
		proto_item_append_text(item, (length==1)?" item":" items");
	} else {
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset>>3, 0, ENC_BIG_ENDIAN);
	}
	tree=proto_item_add_subtree(item, ett_index);
	per_check_items(length, min_len, max_len, actx, item);

	old_offset = offset;
	offset=dissect_per_sequence_of_helper(tvb, offset, actx, tree, seq->func, *seq->p_id, length);

	if (offset == old_offset)
		length = 0;
	else if (offset >> 3 == old_offset >> 3)
			length = 1;
		else
			length = (offset >> 3) - (old_offset >> 3);

	proto_item_set_len(item, length);
	return offset;
}

/* this function dissects a constrained set of */
guint32
dissect_per_constrained_set_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len, gboolean has_extension)
{
	/* for basic-per  a set-of is encoded in the same way as a sequence-of */
DEBUG_ENTRY("dissect_per_constrained_set_of");
	offset=dissect_per_constrained_sequence_of(tvb, offset, actx, parent_tree, hf_index, ett_index, seq, min_len, max_len, has_extension);
	return offset;
}






/* this function dissects a set of */
guint32
dissect_per_set_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq)
{
	/* for basic-per  a set-of is encoded in the same way as a sequence-of */
DEBUG_ENTRY("dissect_per_set_of");
	offset=dissect_per_sequence_of(tvb, offset, actx, parent_tree, hf_index, ett_index, seq);
	return offset;
}




/* 23 Encoding the object identifier type */
guint32
dissect_per_object_identifier(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index, tvbuff_t **value_tvb)
{
  guint length;
  const char *str;
  tvbuff_t *val_tvb = NULL;
  header_field_info *hfi;

DEBUG_ENTRY("dissect_per_object_identifier");

  offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_object_identifier_length, &length);
  if (actx->aligned) BYTE_ALIGN_OFFSET(offset);
  val_tvb = new_octet_aligned_subset(tvb, offset, actx, length);

  hfi = proto_registrar_get_nth(hf_index);
  if (hfi->type == FT_OID) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, length, ENC_BIG_ENDIAN);
  } else if (IS_FT_STRING(hfi->type)) {
    str = oid_encoded2string(tvb_get_ptr(val_tvb, 0, length), length);
    actx->created_item = proto_tree_add_string(tree, hf_index, val_tvb, 0, length, str);
  } else {
    DISSECTOR_ASSERT_NOT_REACHED();
  }

  if (value_tvb) *value_tvb = val_tvb;

  offset += 8 * length;

  return offset;
}

guint32
dissect_per_object_identifier_str(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx)
{
  tvbuff_t *value_tvb = NULL;
  guint length;

  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, (value_stringx) ? &value_tvb : NULL);

  if (value_stringx) {
    if (value_tvb && (length = tvb_length(value_tvb))) {
      *value_stringx = oid_encoded2string(tvb_get_ptr(value_tvb, 0, length), length);
    } else {
      *value_stringx = "";
    }
  }

  return offset;
}



/* this function reads a single bit */
guint32
dissect_per_boolean(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gboolean *bool_val)
{
	guint8 ch, mask;
	gboolean value;
	header_field_info *hfi;

DEBUG_ENTRY("dissect_per_boolean");

	ch=tvb_get_guint8(tvb, offset>>3);
	mask=1<<(7-(offset&0x07));
	if(ch&mask){
		value=1;
	} else {
		value=0;
	}
	if(hf_index!=-1){
		char *str;
		hfi = proto_registrar_get_nth(hf_index);
		str=ep_strdup_printf("%c%c%c%c %c%c%c%c %s: %s",
			mask&0x80?'0'+value:'.',
			mask&0x40?'0'+value:'.',
			mask&0x20?'0'+value:'.',
			mask&0x10?'0'+value:'.',
			mask&0x08?'0'+value:'.',
			mask&0x04?'0'+value:'.',
			mask&0x02?'0'+value:'.',
			mask&0x01?'0'+value:'.',
			hfi->name,
			value?"True":"False"
		);
		actx->created_item = proto_tree_add_boolean_format(tree, hf_index, tvb, offset>>3, 1, value, "%s", str);
	} else {
		actx->created_item = NULL;
	}

	if(bool_val){
		*bool_val=value;
	}
	return offset+1;
}




/* we currently only handle integers up to 32 bits in length. */
guint32
dissect_per_integer(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint32 *value)
{
	guint32 i, length;
	gint32 val;
	proto_item *it=NULL;
	header_field_info *hfi;

	/* 12.2.6 b */
	offset=dissect_per_length_determinant(tvb, offset, actx, tree,hf_per_integer_length, &length);
	/* gassert here? */
	if(length>4){
PER_NOT_DECODED_YET("too long integer(per_integer)");
		length=4;
	}

	val=0;
	for(i=0;i<length;i++){
		if(i==0){
			if(tvb_get_guint8(tvb, offset>>3)&0x80){
				/* negative number */
				val=0xffffffff;
			} else {
				/* positive number */
				val=0;
			}
		}
		val=(val<<8)|tvb_get_guint8(tvb,offset>>3);
		offset+=8;
	}

	hfi = proto_registrar_get_nth(hf_index);
	if (! hfi)
		THROW(ReportedBoundsError);
        if (IS_FT_INT(hfi->type)) {
		it=proto_tree_add_int(tree, hf_index, tvb, (offset>>3)-(length+1), length+1, val);
        } else if (IS_FT_UINT(hfi->type)) {
		it=proto_tree_add_uint(tree, hf_index, tvb, (offset>>3)-(length+1), length+1, val);
	} else {
		proto_tree_add_text(tree, tvb, (offset>>3)-(length+1), length+1, "Field is not an integer: %s", hfi->abbrev);
		REPORT_DISSECTOR_BUG("PER integer field that's not an FT_INT* or FT_UINT*");
	}


	actx->created_item = it;

	if(value){
		*value=val;
	}

	return offset;
}
/* 64 bits experimental version, internal for now */
static guint32
dissect_per_integer64b(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint64 *value)
{
	guint32 i, length;
	gint64 val;
	proto_item *it=NULL;
	header_field_info *hfi;

	/* 12.2.6 b */
	offset=dissect_per_length_determinant(tvb, offset, actx, tree, -1, &length);
	/* gassert here? */
	if(length>8){
PER_NOT_DECODED_YET("too long integer (64b)");
		length=4;
	}

	val=0;
	for(i=0;i<length;i++){
		if(i==0){
			if(tvb_get_guint8(tvb, offset>>3)&0x80){
				/* negative number */
				val=G_GINT64_CONSTANT(0xffffffffffffffff);
			} else {
				/* positive number */
				val=0;
			}
		}
		val=(val<<8)|tvb_get_guint8(tvb,offset>>3);
		offset+=8;
	}

	hfi = proto_registrar_get_nth(hf_index);
	if (! hfi)
		THROW(ReportedBoundsError);
        if (IS_FT_INT(hfi->type)) {
		it=proto_tree_add_int64(tree, hf_index, tvb, (offset>>3)-(length+1), length+1, val);
        } else if (IS_FT_UINT(hfi->type)) {
		it=proto_tree_add_uint64(tree, hf_index, tvb, (offset>>3)-(length+1), length+1, val);
	} else {
		proto_tree_add_text(tree, tvb, (offset>>3)-(length+1), length+1, "Field is not an integer: %s", hfi->abbrev);
		REPORT_DISSECTOR_BUG("PER integer field that's not an FT_INT* or FT_UINT*");
	}


	actx->created_item = it;

	if(value){
		*value=val;
	}

	return offset;
}
/* this function reads a constrained integer  with or without a
   PER visible extension marker present

   has_extension==TRUE  would map to asn constructs such as:
		rfc-number	INTEGER (1..32768, ...)
   while has_extension==FALSE would map to:
		t35CountryCode	INTEGER (0..255)

   it only handles integers that fit inside a 32 bit integer
10.5.1 info only
10.5.2 info only
10.5.3 range=ub-lb+1
10.5.4 empty range
10.5.5 info only
	10.5.6 unaligned version
10.5.7 aligned version
10.5.7.1 decoding of 0-255 1-8 bits
10.5.7.2 decoding og 0-256 8 bits
10.5.7.3 decoding of 0-65535 16 bits
	10.5.7.4
*/
guint32
dissect_per_constrained_integer(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 min, guint32 max, guint32 *value, gboolean has_extension)
{
	proto_item *it=NULL;
	guint32 range, val;
	gint val_start, val_length;
	nstime_t timeval;
	header_field_info *hfi;
	int num_bits;
	gboolean tmp;

DEBUG_ENTRY("dissect_per_constrained_integer");
	if(has_extension){
		gboolean extension_present;
		offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_present);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		if(extension_present){
			offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, (gint32*)value);
			return offset;
		}
	}

	hfi = proto_registrar_get_nth(hf_index);

	/* 10.5.3 Let "range" be defined as the integer value ("ub" - "lb"   1), and let the value to be encoded be "n".
	 * 10.5.7	In the case of the ALIGNED variant the encoding depends on whether
	 *			d)	"range" is greater than 64K (the indefinite length case).
	 */
	if(((max-min)>65536)&&(actx->aligned)){
		/* just set range really big so it will fall through
		   to the bottom of the encoding */
		range=1000000;
	} else {
		/* Really ugly hack.
		 * We should really use guint64 as parameters for min/max.
		 * This is to prevent range from being 0 if
		 * the range for a signed integer spans the entire 32 bit range.
		 * Special case the 2 common cases when this can happen until
		 * a real fix is implemented.
		 */
		if( (max==0x7fffffff && min==0x80000000)
		||  (max==0xffffffff && min==0x00000000) ){
			range=0xffffffff;
		} else {
			range=max-min+1;
		}
	}

	val=0;
	timeval.secs=val; timeval.nsecs=0;
	/* 10.5.4 If "range" has the value 1, then the result of the encoding shall be an empty bit-field (no bits).*/

	/* something is really wrong if range is 0 */
	DISSECTOR_ASSERT(range!=0);

	if(range==1){
		val_start = offset>>3; val_length = 0;
		val = min;
	} else if((range<=255)||(!actx->aligned)) {
		/* 10.5.7.1
		 * 10.5.6	In the case of the UNALIGNED variant the value ("n" - "lb") shall be encoded
		 * as a non-negative  binary integer in a bit field as specified in 10.3 with the minimum
		 * number of bits necessary to represent the range.
		 */
		char *str;
		int  str_index = 0;
		int i, bit, length, str_length;
		guint32 mask,mask2;
		/* We only handle 32 bit integers */
		mask  = 0x80000000;
		mask2 = 0x7fffffff;
		i = 32;
		while ((range & mask)== 0){
			i = i - 1;
			mask = mask>>1;
			mask2 = mask2>>1;
		}
		if ((range & mask2) == 0)
			i = i-1;

		num_bits = i;
		length=1;
		if(range<=2){
			num_bits=1;
		}

		/* prepare the string (max number of bits + quartet separators + field name + ": ") */
		str_length = 256+64+(int)strlen(hfi->name)+2;
		str=ep_alloc(str_length+1);
		str_index = g_snprintf(str, str_length+1, "%s: ", hfi->name);
		for(bit=0;bit<((int)(offset&0x07));bit++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if (str_index < str_length) str[str_index++] = '.';
		}
		/* read the bits for the int */
		for(i=0;i<num_bits;i++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if(bit&&(!(bit%8))){
				length+=1;
				if (str_index < str_length) str[str_index++] = ' ';
			}
			bit++;
			offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &tmp);
			val<<=1;
			if(tmp){
				val|=1;
				if (str_index < str_length) str[str_index++] = '1';
			} else {
				if (str_index < str_length) str[str_index++] = '0';
			}
		}
		for(;bit%8;bit++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if (str_index < str_length) str[str_index++] = '.';
		}
		str[str_index] = '\0'; /* Terminate string */
		val_start = (offset-num_bits)>>3; val_length = length;
		val+=min;
		if (display_internal_per_fields)
			proto_tree_add_text(tree, tvb, val_start,val_length,"Range = %u Bitfield length %u, %s", range, num_bits, str);
	} else if(range==256){
		/* 10.5.7.2 */

		/* in the aligned case, align to byte boundary */
		BYTE_ALIGN_OFFSET(offset);
		val=tvb_get_guint8(tvb, offset>>3);
		offset+=8;

		val_start = (offset>>3)-1; val_length = 1;
		val+=min;
	} else if(range<=65536){
		/* 10.5.7.3 */

		/* in the aligned case, align to byte boundary */
		BYTE_ALIGN_OFFSET(offset);
		val=tvb_get_guint8(tvb, offset>>3);
		val<<=8;
		offset+=8;
		val|=tvb_get_guint8(tvb, offset>>3);
		offset+=8;

		val_start = (offset>>3)-2; val_length = 2;
		val+=min;
	} else {
		int i,num_bytes;
		gboolean bit;

		/* 10.5.7.4 */
		/* 12.2.6 */
		offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &bit);
		num_bytes=bit;
		offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &bit);
		num_bytes=(num_bytes<<1)|bit;

		num_bytes++;  /* lower bound for length determinant is 1 */
		if (display_internal_per_fields)
			proto_tree_add_uint(tree, hf_per_const_int_len, tvb, (offset>>3), 1, num_bytes);

		/* byte aligned */
		BYTE_ALIGN_OFFSET(offset);
		val=0;
		for(i=0;i<num_bytes;i++){
			val=(val<<8)|tvb_get_guint8(tvb,offset>>3);
			offset+=8;
		}
		val_start = (offset>>3)-(num_bytes+1); val_length = num_bytes+1;
		val+=min;
	}

	timeval.secs = val;
	if (IS_FT_UINT(hfi->type)) {
		it = proto_tree_add_uint(tree, hf_index, tvb, val_start, val_length, val);
		per_check_value(val, min, max, actx, it, FALSE);
	} else if (IS_FT_INT(hfi->type)) {
		it = proto_tree_add_int(tree, hf_index, tvb, val_start, val_length, val);
		per_check_value(val, min, max, actx, it, TRUE);
	} else if (IS_FT_TIME(hfi->type)) {
		it = proto_tree_add_time(tree, hf_index, tvb, val_start, val_length, &timeval);
	} else {
		THROW(ReportedBoundsError);
	}
	actx->created_item = it;
	if (value) *value = val;
	return offset;
}

guint32
dissect_per_constrained_integer_64b(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint64 min, guint64 max, guint64 *value, gboolean has_extension)
{
	proto_item *it=NULL, *int_item=NULL;
	guint64 range, val;
	gint val_start, val_length;
	nstime_t timeval;
	header_field_info *hfi;
	int num_bits;
	gboolean tmp;

DEBUG_ENTRY("dissect_per_constrained_integer_64b");
	if(has_extension){
		gboolean extension_present;
		offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_present);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		if(extension_present){
			offset = dissect_per_integer64b(tvb, offset, actx, tree, hf_index, (gint64*)value);
			return offset;
		}
	}

	hfi = proto_registrar_get_nth(hf_index);

	/* 10.5.3 Let "range" be defined as the integer value ("ub" - "lb"   1), and let the value to be encoded be "n".
	 * 10.5.7	In the case of the ALIGNED variant the encoding depends on whether
	 *			d)	"range" is greater than 64K (the indefinite length case).
	 */
	if(((max-min)>65536)&&(actx->aligned)){
		/* just set range really big so it will fall through
		   to the bottom of the encoding */
		/* range=1000000; */
		range = max-min;
		if (range==65536)
			range++; /* make it fall trough? */
	} else {
		/* Copied from the 32 bit version, assuming the same problem occurs
		 * at 64 bit boundary.
		 * Really ugly hack.
		 * We should really use guint64 as parameters for min/max.
		 * This is to prevent range from being 0 if
		 * the range for a signed integer spans the entire 32 bit range.
		 * Special case the 2 common cases when this can happen until
		 * a real fix is implemented.
		 */
		if( (max==G_GINT64_CONSTANT(0x7fffffffffffffff) && min==G_GINT64_CONSTANT(0x8000000000000000))
		||  (max==G_GINT64_CONSTANT(0xffffffffffffffff) && min==0) ){
			range=G_GINT64_CONSTANT(0xffffffffffffffff);
		} else {
			range=max-min+1;
		}
	}

	val=0;
	timeval.secs=0; timeval.nsecs=0;
	/* 10.5.4 If "range" has the value 1, then the result of the encoding shall be an empty bit-field (no bits).*/

	/* something is really wrong if range is 0 */
	DISSECTOR_ASSERT(range!=0);

	if(range==1){
		val_start = offset>>3; val_length = 0;
		val = min;
	} else if((range<=255)||(!actx->aligned)) {
		/* 10.5.7.1
		 * 10.5.6	In the case of the UNALIGNED variant the value ("n" - "lb") shall be encoded
		 * as a non-negative  binary integer in a bit field as specified in 10.3 with the minimum
		 * number of bits necessary to represent the range.
		 */
		char *str;
		int i, bit, length, str_length, str_index;
		guint64 mask,mask2;
		/* We only handle 64 bit integers */
		mask  = G_GINT64_CONSTANT(0x8000000000000000);
		mask2 = G_GINT64_CONSTANT(0x7fffffffffffffff);
		i = 64;
		while ((range & mask)== 0){
			i = i - 1;
			mask = mask>>1;
			mask2 = mask2>>1;
		}
		if ((range & mask2) == 0)
			i = i-1;

		num_bits = i;
		length=1;
		if(range<=2){
			num_bits=1;
		}

		/* prepare the string (max number of bits + quartet separators + field name + ": ") */
		str_length = 512+128+(int)strlen(hfi->name)+2;
		str = ep_alloc(str_length+1);
		str_index = 0;
		str_index = g_snprintf(str, str_length+1, "%s: ", hfi->name);
		for(bit=0;bit<((int)(offset&0x07));bit++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if (str_index < str_length) str[str_index++] = '.';
		}
		/* read the bits for the int */
		for(i=0;i<num_bits;i++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if(bit&&(!(bit%8))){
				length+=1;
				if (str_index < str_length) str[str_index++] = ' ';
			}
			bit++;
			offset=dissect_per_boolean(tvb, offset, actx, tree, -1, &tmp);
			val<<=1;
			if(tmp){
				val|=1;
				if (str_index < str_length) str[str_index++] = '1';
			} else {
				if (str_index < str_length) str[str_index++] = '0';
			}
		}
		for(;bit%8;bit++){
			if(bit&&(!(bit%4))){
				if (str_index < str_length) str[str_index++] = ' ';
			}
			if (str_index < str_length) str[str_index++] = '.';
		}
		str[str_index] = '\0'; /* Terminate string */
		val_start = (offset-num_bits)>>3; val_length = length;
		val+=min;
		if (display_internal_per_fields)
			proto_tree_add_text(tree, tvb, val_start,val_length,"Range = (%" G_GINT64_MODIFIER "u) Bitfield length %u, %s",range, num_bits, str);
	} else if(range==256){
		/* 10.5.7.2 */

		/* in the aligned case, align to byte boundary */
		BYTE_ALIGN_OFFSET(offset);
		val=tvb_get_guint8(tvb, offset>>3);
		offset+=8;

		val_start = (offset>>3)-1; val_length = 1;
		val+=min;
	} else if(range<=65536){
		/* 10.5.7.3 */

		/* in the aligned case, align to byte boundary */
		BYTE_ALIGN_OFFSET(offset);
		val=tvb_get_guint8(tvb, offset>>3);
		val<<=8;
		offset+=8;
		val|=tvb_get_guint8(tvb, offset>>3);
		offset+=8;

		val_start = (offset>>3)-2; val_length = 2;
		val+=min;
	} else {
		int i,num_bytes,n_bits;

		/* 10.5.7.4 */
		/* 12.2.6 */
		/* calculate the number of bits to hold the length */
		if ((range & G_GINT64_CONSTANT(0xffffffff0000000)) != 0){
			n_bits=3;
		}else{
			n_bits=2;
		}
		num_bytes =tvb_get_bits8(tvb, offset, n_bits);
		num_bytes++;  /* lower bound for length determinant is 1 */
		if (display_internal_per_fields){
			int_item = proto_tree_add_bits_item(tree, hf_per_const_int_len, tvb, offset,n_bits, ENC_BIG_ENDIAN);
			proto_item_append_text(int_item,"+1=%u bytes, Range = (%" G_GINT64_MODIFIER "u)",num_bytes, range);
		}
		offset = offset+n_bits;
		/* byte aligned */
		BYTE_ALIGN_OFFSET(offset);
		val=0;
		for(i=0;i<num_bytes;i++){
			val=(val<<8)|tvb_get_guint8(tvb,offset>>3);
			offset+=8;
		}
		val_start = (offset>>3)-(num_bytes+1); val_length = num_bytes+1;
		val+=min;
	}


	if (IS_FT_UINT(hfi->type)) {
		it = proto_tree_add_uint64(tree, hf_index, tvb, val_start, val_length, val);
		per_check_value64(val, min, max, actx, it, FALSE);
	} else if (IS_FT_INT(hfi->type)) {
		it = proto_tree_add_int64(tree, hf_index, tvb, val_start, val_length, val);
		per_check_value64(val, min, max, actx, it, TRUE);
	} else if (IS_FT_TIME(hfi->type)) {
		timeval.secs = (guint32)val;
		it = proto_tree_add_time(tree, hf_index, tvb, val_start, val_length, &timeval);
	} else {
		THROW(ReportedBoundsError);
	}
	actx->created_item = it;
	if (value) *value = val;
	return offset;
}

/* 13 Encoding the enumerated type */
guint32
dissect_per_enumerated(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 root_num, guint32 *value, gboolean has_extension, guint32 ext_num, guint32 *value_map)
{

	proto_item *it=NULL;
	guint32 enum_index, val;
	guint32 start_offset = offset;
	gboolean extension_present = FALSE;
	header_field_info *hfi;

	if (has_extension) {
		/* Extension bit */
		offset = dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_present);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	}

	if (!extension_present) {
		/* 13.2  */
		offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_per_enum_index, 0, root_num - 1, &enum_index, FALSE);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	} else {
		/* 13.3  */
		if (ext_num == 1) {
			/* 10.5.4	If "range" has the value 1,
			 * then the result of the encoding shall be
			 * an empty bit-field (no bits).
			 */
			enum_index = 0;
		} else {
			/* 13.3 ".. and the value shall be added to the field-list as a
			 * normally small non-negative whole number whose value is the
			 * enumeration index of the additional enumeration and with "lb" set to 0.."
			 */
			offset = dissect_per_normally_small_nonnegative_whole_number(tvb, offset, actx, tree, hf_per_enum_extension_index, &enum_index);
		}
		enum_index += root_num;
	}
    val = (value_map && (enum_index<(root_num+ext_num))) ? value_map[enum_index] : enum_index;
	hfi = proto_registrar_get_nth(hf_index);
	if (IS_FT_UINT(hfi->type)) {
		it = proto_tree_add_uint(tree, hf_index, tvb, start_offset>>3, BLEN(start_offset, offset), val);
	} else {
		THROW(ReportedBoundsError);
	}
	actx->created_item = it;
	if (value) *value = val;
	return offset;
}

/* 14 Encoding the real type */
guint32
dissect_per_real(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, double *value)
{
	guint32 val_length, end_offset;
	tvbuff_t *val_tvb;
	double val = 0;

	offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_real_length, &val_length);
	if (actx->aligned) BYTE_ALIGN_OFFSET(offset);
	val_tvb = new_octet_aligned_subset(tvb, offset, actx, val_length);
	end_offset = offset + val_length * 8;

	val = asn1_get_real(tvb_get_ptr(val_tvb, 0, val_length), val_length);
	actx->created_item = proto_tree_add_double(tree, hf_index, val_tvb, 0, val_length, val);

	if (value) *value = val;

	return end_offset;
}

/* 22 Encoding the choice type */
guint32
dissect_per_choice(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint ett_index, const per_choice_t *choice, gint *value)
{
	gboolean /*extension_present,*/ extension_flag;
	int extension_root_entries;
	int extension_addition_entries;
	guint32 choice_index;
	int i, idx, cidx;
	guint32 ext_length;
	guint32 old_offset = offset;
	proto_item *choice_item = NULL;
	proto_tree *choice_tree = NULL;

DEBUG_ENTRY("dissect_per_choice");

	if (value) *value = -1;

	/* 22.5 */
	if (choice[0].extension == ASN1_NO_EXTENSIONS){
		/*extension_present = FALSE; ?? */
		extension_flag = FALSE;
	} else {
		/*extension_present = TRUE; ?? */
		offset = dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_bit, &extension_flag);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	}

	/* count the number of entries in the extension root and extension addition */
	extension_root_entries = 0;
	extension_addition_entries = 0;
	for (i=0; choice[i].p_id; i++) {
		switch(choice[i].extension){
			case ASN1_NO_EXTENSIONS:
			case ASN1_EXTENSION_ROOT:
				extension_root_entries++;
				break;
			case ASN1_NOT_EXTENSION_ROOT:
				extension_addition_entries++;
				break;
		}
	}

	if (!extension_flag) {  /* 22.6, 22.7 */
		if (extension_root_entries == 1) {  /* 22.5 */
			choice_index = 0;
		} else {
			offset = dissect_per_constrained_integer(tvb, offset, actx,
				tree, hf_per_choice_index, 0, extension_root_entries - 1,
				&choice_index, FALSE);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		}

		idx = -1; cidx = choice_index;
		for (i=0; choice[i].p_id; i++) {
			if(choice[i].extension != ASN1_NOT_EXTENSION_ROOT){
				if (!cidx) { idx = i; break; }
				cidx--;
			}
		}
	} else {  /* 22.8 */
		offset = dissect_per_normally_small_nonnegative_whole_number(tvb, offset, actx, tree, hf_per_choice_extension_index, &choice_index);
		offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_open_type_length, &ext_length);

		idx = -1; cidx = choice_index;
		for (i=0; choice[i].p_id; i++) {
			if(choice[i].extension == ASN1_NOT_EXTENSION_ROOT){
				if (!cidx) { idx = i; break; }
				cidx--;
			}
		}
	}

	if (idx != -1) {
		choice_item = proto_tree_add_uint(tree, hf_index, tvb, old_offset>>3, 0, choice[idx].value);
		choice_tree = proto_item_add_subtree(choice_item, ett_index);
		if (!extension_flag) {
			offset = choice[idx].func(tvb, offset, actx, choice_tree, *choice[idx].p_id);
		} else {
			choice[idx].func(tvb, offset, actx, choice_tree, *choice[idx].p_id);
			offset += ext_length * 8;
		}
		proto_item_set_len(choice_item, BLEN(old_offset, offset));
	} else {
		if (!extension_flag) {
			PER_NOT_DECODED_YET("unknown extension root index in choice");
		} else {
			offset += ext_length * 8;
			proto_tree_add_text(tree, tvb, old_offset>>3, BLEN(old_offset, offset), "Choice no. %d in extension", choice_index);
			expert_add_info_format(actx->pinfo, choice_item, PI_UNDECODED, PI_NOTE, "unknown choice extension");
		}
	}

	if (value && (idx != -1))
		*value = choice[idx].value;

	return offset;
}


static const char *
index_get_optional_name(const per_sequence_t *sequence, int idx)
{
	int i;
	header_field_info *hfi;

	for(i=0;sequence[i].p_id;i++){
		if((sequence[i].extension!=ASN1_NOT_EXTENSION_ROOT)&&(sequence[i].optional==ASN1_OPTIONAL)){
			if (idx == 0) {
				hfi = proto_registrar_get_nth(*sequence[i].p_id);
				return (hfi) ? hfi->name : "<unknown filed>";
			}
			idx--;
		}
	}
	return "<unknown type>";
}

static const char *
index_get_extension_name(const per_sequence_t *sequence, int idx)
{
	int i;
	header_field_info *hfi;

	for(i=0;sequence[i].p_id;i++){
		if(sequence[i].extension==ASN1_NOT_EXTENSION_ROOT){
			if (idx == 0) {
				if (*sequence[i].p_id == -1) return "extension addition group";
				hfi = proto_registrar_get_nth(*sequence[i].p_id);
				return (hfi) ? hfi->name : "<unknown filed>";
			}
			idx--;
		}
	}
	return "<unknown type>";
}

static const char *
index_get_field_name(const per_sequence_t *sequence, int idx)
{
	header_field_info *hfi;

	hfi = proto_registrar_get_nth(*sequence[idx].p_id);
	return (hfi) ? hfi->name : "<unknown filed>";
}

/* this functions decodes a SEQUENCE
   it can only handle SEQUENCES with at most 32 DEFAULT or OPTIONAL fields
18.1 extension bit
18.2 optinal/default items in root
18.3 we ignore the case where n>64K
18.4 the root sequence
	   18.5
	   18.6
	   18.7
	   18.8
	   18.9
*/
guint32
dissect_per_sequence(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *sequence)
{
	gboolean /*extension_present,*/ extension_flag, optional_field_flag;
	proto_item *item;
	proto_tree *tree;
	guint32 old_offset=offset;
	guint32 i, num_opts;
	guint32 optional_mask;

DEBUG_ENTRY("dissect_per_sequence");

	item=proto_tree_add_item(parent_tree, hf_index, tvb, offset>>3, 0, ENC_BIG_ENDIAN);
	tree=proto_item_add_subtree(item, ett_index);


	/* first check if there should be an extension bit for this CHOICE.
	   we do this by just checking the first choice arm
	 */
	/* 18.1 */
	extension_flag=0;
	if(sequence[0].extension==ASN1_NO_EXTENSIONS){
		/*extension_present=0;  ?? */
	} else {
		/*extension_present=1; ?? */
		offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_bit, &extension_flag);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	}
	/* 18.2 */
	num_opts=0;
	for(i=0;sequence[i].p_id;i++){
		if((sequence[i].extension!=ASN1_NOT_EXTENSION_ROOT)&&(sequence[i].optional==ASN1_OPTIONAL)){
			num_opts++;
		}
	}

	optional_mask=0;
	for(i=0;i<num_opts;i++){
		offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_optional_field_bit, &optional_field_flag);
		if (tree) {
			proto_item_append_text(actx->created_item, " (%s %s present)",
				index_get_optional_name(sequence, i), optional_field_flag?"is":"is NOT");
		}
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		optional_mask<<=1;
		if(optional_field_flag){
			optional_mask|=0x01;
		}
	}


	/* 18.4 */
	for(i=0;sequence[i].p_id;i++){
		if( (sequence[i].extension==ASN1_NO_EXTENSIONS)
		||  (sequence[i].extension==ASN1_EXTENSION_ROOT) ){
			if(sequence[i].optional==ASN1_OPTIONAL){
				gboolean is_present;
				if (num_opts == 0){
					continue;
				}
				is_present=(1<<(num_opts-1))&optional_mask;
				num_opts--;
				if(!is_present){
					continue;
				}
			}
			if(sequence[i].func){
				offset=sequence[i].func(tvb, offset, actx, tree, *sequence[i].p_id);
			} else {
				PER_NOT_DECODED_YET(index_get_field_name(sequence, i));
			}
		}
	}


	if(extension_flag){
		gboolean extension_bit;
		guint32 num_known_extensions;
		guint32 num_extensions;
		guint32 extension_mask;

		offset=dissect_per_normally_small_nonnegative_whole_number(tvb, offset, actx, tree, hf_per_num_sequence_extensions, &num_extensions);
		/* the X.691 standard is VERY unclear here.
		   there is no mention that the lower bound lb for this
		   (apparently) semiconstrained value is 1,
		   apart from the NOTE: comment in 18.8 that this value can
		   not be 0.
		   In my book, there is a semantic difference between having
		   a comment that says that the value can not be zero
		   and stating that the lb is 1.
		   I don't know if this is right or not but it makes
		   some of the very few captures I have decode properly.

		   It could also be that the captures I have are generated by
		   a broken implementation.
		   If this is wrong and you don't report it as a bug
		   then it won't get fixed!
		*/
		num_extensions+=1;

		extension_mask=0;
		for(i=0;i<num_extensions;i++){
			offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_bit);
			if (tree) {
				proto_item_append_text(actx->created_item, " (%s %s present)",
					index_get_extension_name(sequence, i), extension_bit?"is":"is NOT");
			}
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);

			extension_mask=(extension_mask<<1)|extension_bit;
		}

		/* find how many extensions we know about */
		num_known_extensions=0;
		for(i=0;sequence[i].p_id;i++){
			if(sequence[i].extension==ASN1_NOT_EXTENSION_ROOT){
				num_known_extensions++;
			}
		}

		/* decode the extensions one by one */
		for(i=0;i<num_extensions;i++){
			proto_item *cause;
			guint32 length;
			guint32 new_offset;
			guint32 difference;
			guint32 extension_index;
			guint32 j,k;

			if(!((1L<<(num_extensions-1-i))&extension_mask)){
				/* this extension is not encoded in this PDU */
				continue;
			}

			offset=dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_open_type_length, &length);

			if(i>=num_known_extensions){
				/* we don't know how to decode this extension */
				offset+=length*8;
				expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_NOTE, "unknown sequence extension");
				continue;
			}

			extension_index=0;
			for(j=0,k=0;sequence[j].p_id;j++){
				if(sequence[j].extension==ASN1_NOT_EXTENSION_ROOT){
					if(k==i){
						extension_index=j;
						break;
					}
					k++;
				}
			}

			if(sequence[extension_index].func){
				new_offset=sequence[extension_index].func(tvb, offset, actx, tree, *sequence[extension_index].p_id);
				offset+=length*8;
				difference = offset - new_offset;
				/* A difference of 7 or less might be byte aligning */
                /* Difference could be 8 if open type has no bits and the length is 1 */
				if ((length > 1) && (difference > 7)) {
					cause=proto_tree_add_text(tree, tvb, new_offset>>3, (offset-new_offset)>>3,
						"[Possible encoding error full length not decoded. Open type length %u ,decoded %u]",length, length - (difference>>3));
					proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
					expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN,
						"Possible encoding error full length not decoded. Open type length %u ,decoded %u",length, length - (difference>>3));
				}
			} else {
				PER_NOT_DECODED_YET(index_get_field_name(sequence, extension_index));
				offset+=length*8;
			}
		}
	}

	proto_item_set_len(item, (offset>>3)!=(old_offset>>3)?(offset>>3)-(old_offset>>3):1);
	actx->created_item = item;
	return offset;
}

guint32
dissect_per_sequence_eag(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, const per_sequence_t *sequence)
{
	gboolean optional_field_flag;
	guint32 i, num_opts;
	guint32 optional_mask;

DEBUG_ENTRY("dissect_per_sequence_eag");

	num_opts=0;
	for(i=0;sequence[i].p_id;i++){
		if(sequence[i].optional==ASN1_OPTIONAL){
			num_opts++;
		}
	}

	optional_mask=0;
	for(i=0;i<num_opts;i++){
		offset=dissect_per_boolean(tvb, offset, actx, tree, hf_per_optional_field_bit, &optional_field_flag);
		if (tree) {
			proto_item_append_text(actx->created_item, " (%s %s present)",
				index_get_optional_name(sequence, i), optional_field_flag?"is":"is NOT");
		}
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		optional_mask<<=1;
		if(optional_field_flag){
			optional_mask|=0x01;
		}
	}

	for(i=0;sequence[i].p_id;i++){
		if(sequence[i].optional==ASN1_OPTIONAL){
			gboolean is_present;
			if (num_opts == 0){
				continue;
			}
			is_present=(1<<(num_opts-1))&optional_mask;
			num_opts--;
			if(!is_present){
				continue;
			}
		}
		if(sequence[i].func){
			offset=sequence[i].func(tvb, offset, actx, tree, *sequence[i].p_id);
		} else {
			PER_NOT_DECODED_YET(index_get_field_name(sequence, i));
		}
	}

	return offset;
}


/* 15 Encoding the bitstring type

   max_len or min_len == NO_BOUND means there is no lower/upper constraint

*/

static tvbuff_t *dissect_per_bit_string_display(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, header_field_info *hfi, guint32 length)
{
	tvbuff_t *out_tvb = NULL;
	guint32  pad_length=0;
	guint64  value;

	out_tvb = tvb_new_octet_aligned(tvb, offset, length);
	add_new_data_source(actx->pinfo, out_tvb, "Bitstring tvb");

	if (hfi) {
		actx->created_item = proto_tree_add_item(tree, hf_index, out_tvb, 0, -1, ENC_BIG_ENDIAN);
		proto_item_append_text(actx->created_item, " [bit length %u", length);
		if (length%8) {
			pad_length = 8-(length%8);
			proto_item_append_text(actx->created_item, ", %u LSB pad bits", pad_length);
		}

		if (length<=64) { /* if read into 64 bits also handle length <= 24, 40, 48, 56 bits */
			if (length<=8) {
				value = tvb_get_bits8(out_tvb, 0, length);
			}else if (length<=16) {
				value = tvb_get_bits16(out_tvb, 0, length, ENC_BIG_ENDIAN);
			}else if (length<=24) { /* first read 16 and then the remaining bits */
				value = tvb_get_bits16(out_tvb, 0, 16, ENC_BIG_ENDIAN);
				value <<= 8 - pad_length;
				value |= tvb_get_bits8(out_tvb, 16, length - 16);
			}else if (length<=32) {
				value = tvb_get_bits32(out_tvb, 0, length, ENC_BIG_ENDIAN);
			}else if (length<=40) { /* first read 32 and then the remaining bits */
				value = tvb_get_bits32(out_tvb, 0, 32, ENC_BIG_ENDIAN);
				value <<= 8 - pad_length;
				value |= tvb_get_bits8(out_tvb, 32, length - 32);
			}else if (length<=48) { /* first read 32 and then the remaining bits */
				value = tvb_get_bits32(out_tvb, 0, 32, ENC_BIG_ENDIAN);
				value <<= 16 - pad_length;
				value |= tvb_get_bits16(out_tvb, 32, length - 32, ENC_BIG_ENDIAN);
			}else if (length<=56) { /* first read 32 and 16 then the remaining bits */
				value = tvb_get_bits32(out_tvb, 0, 32, ENC_BIG_ENDIAN);
				value <<= 16;
				value |= tvb_get_bits16(out_tvb, 32, 16, ENC_BIG_ENDIAN);
				value <<= 8 - pad_length;
				value |= tvb_get_bits8(out_tvb, 48, length - 48);
			}else {
				value = tvb_get_bits64(out_tvb, 0, length, ENC_BIG_ENDIAN);
			}
			proto_item_append_text(actx->created_item, ", %s decimal value %" G_GINT64_MODIFIER "u",
				decode_bits_in_field(0, length, value), value);
		}
		proto_item_append_text(actx->created_item, "]");
	}

	return out_tvb;
}
guint32
dissect_per_bit_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb)
{
	/*gint val_start, val_length;*/
	guint32 length;
	header_field_info *hfi;
	tvbuff_t *out_tvb = NULL;

	hfi = (hf_index==-1) ? NULL : proto_registrar_get_nth(hf_index);

DEBUG_ENTRY("dissect_per_bit_string");
	/* 15.8 if the length is 0 bytes there will be no encoding */
	if(max_len==0) {
		return offset;
	}

	if (min_len == NO_BOUND) {
		min_len = 0;
	}
	/* 15.6	If an extension marker is present in the size constraint specification of the bitstring type,
	 * a single bit shall be added to the field-list in a bit-field of length one.
	 * The bit shall be set to 1 if the length of this encoding is not within the range of the extension root,
	 * and zero otherwise.
	 */
	 if (has_extension) {
		 gboolean extension_present;
		 offset = dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_present);
		 if(extension_present){
			offset=dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_bit_string_length, &length);
			if(length){
				/* align to byte */
				if (actx->aligned){
					BYTE_ALIGN_OFFSET(offset);
				}
				out_tvb = dissect_per_bit_string_display(tvb, offset, actx, tree, hf_index, hfi, length);
			}
			/* XXX: ?? */
			/*val_start = offset>>3;*/
			/*val_length = (length+7)/8;*/
			offset+=length;

			if (value_tvb)
				*value_tvb = out_tvb;

			return offset;
		 }
	 }

	/* 15.9 if length is fixed and less than or equal to sixteen bits*/
	if ((min_len==max_len) && (max_len<=16)) {
		out_tvb = dissect_per_bit_string_display(tvb, offset, actx, tree, hf_index, hfi, min_len);
		offset+=min_len;
		if (value_tvb)
			*value_tvb = out_tvb;
		return offset;
	}


	/* 15.10 if length is fixed and less than to 64kbits*/
	if((min_len==max_len)&&(min_len<65536)){
		/* (octet-aligned in the ALIGNED variant)
		 * align to byte
		 */
		if (actx->aligned){
			BYTE_ALIGN_OFFSET(offset);
		}
		out_tvb = dissect_per_bit_string_display(tvb, offset, actx, tree, hf_index, hfi, min_len);
		offset+=min_len;
		if (value_tvb)
			*value_tvb = out_tvb;
		return offset;
	}

	/* 15.11 */
	if (max_len != NO_BOUND) {
		offset=dissect_per_constrained_integer(tvb, offset, actx,
			tree, hf_per_bit_string_length, min_len, max_len,
			&length, FALSE);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
	} else {
		offset=dissect_per_length_determinant(tvb, offset, actx, tree, hf_per_bit_string_length, &length);
	}
	if(length){
		/* align to byte */
		if (actx->aligned){
			BYTE_ALIGN_OFFSET(offset);
		}
		out_tvb = dissect_per_bit_string_display(tvb, offset, actx, tree, hf_index, hfi, length);
	}
	/* XXX: ?? */
	/*val_start = offset>>3;*/
	/*val_length = (length+7)/8;*/
	offset+=length;

	if (value_tvb)
		*value_tvb = out_tvb;

	return offset;
}

guint32 dissect_per_bit_string_containing_pdu(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, dissector_t type_cb)
{
	tvbuff_t *val_tvb = NULL;
	proto_tree *subtree = tree;

	offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension, &val_tvb);

	if (type_cb && val_tvb) {
		subtree = proto_item_add_subtree(actx->created_item, ett_per_containing);
		type_cb(val_tvb, actx->pinfo, subtree);
	}

	return offset;
}

guint32 dissect_per_bit_string_containing_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, new_dissector_t type_cb)
{
	tvbuff_t *val_tvb = NULL;
	proto_tree *subtree = tree;

	offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension, &val_tvb);

	if (type_cb && val_tvb) {
		subtree = proto_item_add_subtree(actx->created_item, ett_per_containing);
		type_cb(val_tvb, actx->pinfo, subtree, NULL);
	}

	return offset;
}

/* this fucntion dissects an OCTET STRING
	16.1
	16.2
	16.3
	16.4
	16.5
	16.6
	16.7
	16.8

   max_len or min_len == NO_BOUND means there is no lower/upper constraint

   hf_index can either be a FT_BYTES or an FT_STRING
*/
guint32
dissect_per_octet_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb)
{
	gint val_start = 0, val_length;
	guint32 length = 0;
	header_field_info *hfi;
	tvbuff_t *out_tvb = NULL;

	hfi = (hf_index==-1) ? NULL : proto_registrar_get_nth(hf_index);

DEBUG_ENTRY("dissect_per_octet_string");

	if (has_extension) {  /* 16.3 an extension marker is present */
		gboolean extension_present;
		offset = dissect_per_boolean(tvb, offset, actx, tree, hf_per_extension_present_bit, &extension_present);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(actx->created_item);
		if (extension_present) max_len = NO_BOUND;  /* skip to 16.8 */
	}

	if (min_len == NO_BOUND) {
		min_len = 0;
	}
	if (max_len==0) {  /* 16.5 if the length is 0 bytes there will be no encoding */
		val_start = offset>>3;
		val_length = 0;

	} else if((min_len==max_len)&&(max_len<=2)) {
		/* 16.6 if length is fixed and less than or equal to two bytes*/
		val_start = offset>>3;
		val_length = min_len;
		out_tvb = new_octet_aligned_subset(tvb, offset, actx, val_length);
		offset+=min_len*8;

	} else if ((min_len==max_len)&&(min_len<65536)) {
		/* 16.7 if length is fixed and less than to 64k*/

		/* align to byte */
		if (actx->aligned){
			BYTE_ALIGN_OFFSET(offset);
		}
		val_start = offset>>3;
		val_length = min_len;
		out_tvb = new_octet_aligned_subset(tvb, offset, actx, val_length);
		offset+=min_len*8;

	} else {  /* 16.8 */
		if(max_len>0) {
			offset = dissect_per_constrained_integer(tvb, offset, actx, tree,
				hf_per_octet_string_length, min_len, max_len, &length, FALSE);

				if (!display_internal_per_fields)
					PROTO_ITEM_SET_HIDDEN(actx->created_item);
		} else {
			offset = dissect_per_length_determinant(tvb, offset, actx, tree,
				hf_per_octet_string_length, &length);
		}

		if(length){
			/* align to byte */
			if (actx->aligned){
				BYTE_ALIGN_OFFSET(offset);
			}
			out_tvb = new_octet_aligned_subset(tvb, offset, actx, length);
		} else {
			val_start = offset>>3;
		}
		val_length = length;
		offset+=length*8;
	}

	if (hfi) {
		if (IS_FT_UINT(hfi->type)||IS_FT_INT(hfi->type)) {
			/* If the type has been converted to FT_UINT or FT_INT in the .cnf file
			 * display the length of this octet string instead of the octetstring itself
			 */
			if (IS_FT_UINT(hfi->type))
				actx->created_item = proto_tree_add_uint(tree, hf_index, out_tvb, 0, val_length, val_length);
			else
				actx->created_item = proto_tree_add_int(tree, hf_index, out_tvb, 0, val_length, val_length);
			proto_item_append_text(actx->created_item, plurality(val_length, " octet", " octets"));
		} else {
			if(out_tvb){
				actx->created_item = proto_tree_add_item(tree, hf_index, out_tvb, 0, val_length, ENC_BIG_ENDIAN);
			}else{
				/* Length = 0 */
				actx->created_item = proto_tree_add_item(tree, hf_index, tvb, val_start, val_length, ENC_BIG_ENDIAN);
			}
		}
	}

	if (value_tvb)
		*value_tvb = (out_tvb) ? out_tvb : tvb_new_subset(tvb, val_start, val_length, val_length);

	return offset;
}

guint32 dissect_per_octet_string_containing_pdu(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, dissector_t type_cb)
{
	tvbuff_t *val_tvb = NULL;
	proto_tree *subtree = tree;

	offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension, &val_tvb);

	if (type_cb && val_tvb) {
		subtree = proto_item_add_subtree(actx->created_item, ett_per_containing);
		type_cb(val_tvb, actx->pinfo, subtree);
	}

	return offset;
}

guint32 dissect_per_octet_string_containing_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, new_dissector_t type_cb)
{
	tvbuff_t *val_tvb = NULL;
	proto_tree *subtree = tree;

	offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension, &val_tvb);

	if (type_cb && val_tvb) {
		subtree = proto_item_add_subtree(actx->created_item, ett_per_containing);
		type_cb(val_tvb, actx->pinfo, subtree, NULL);
	}

	return offset;
}

guint32 dissect_per_size_constrained_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb, const gchar *name, int min_len, int max_len, gboolean has_extension)
{
  asn1_stack_frame_push(actx, name);
  asn1_param_push_integer(actx, min_len);
  asn1_param_push_integer(actx, max_len);
  asn1_param_push_boolean(actx, has_extension);

  offset = type_cb(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, name);

  return offset;
}

gboolean get_size_constraint_from_stack(asn1_ctx_t *actx, const gchar *name, int *pmin_len, int *pmax_len, gboolean *phas_extension)
{
  asn1_par_t *par;

  if (pmin_len) *pmin_len = NO_BOUND;
  if (pmax_len) *pmax_len = NO_BOUND;
  if (phas_extension) *phas_extension = FALSE;

  if (!actx->stack) return FALSE;
  if (strcmp(actx->stack->name, name)) return FALSE;

  par = actx->stack->par;
  if (!par || (par->ptype != ASN1_PAR_INTEGER)) return FALSE;
  if (pmin_len) *pmin_len = par->value.v_integer;
  par = par->next;
  if (!par || (par->ptype != ASN1_PAR_INTEGER)) return FALSE;
  if (pmax_len) *pmax_len = par->value.v_integer;
  par = par->next;
  if (!par || (par->ptype != ASN1_PAR_BOOLEAN)) return FALSE;
  if (phas_extension) *phas_extension = par->value.v_boolean;

  return TRUE;
}


/* 26 Encoding of a value of the external type */

/* code generated from definition in 26.1 */
/*
[UNIVERSAL 8] IMPLICIT SEQUENCE {
  direct-reference OBJECT IDENTIFIER OPTIONAL,
  indirect-reference INTEGER OPTIONAL,
  data-value-descriptor ObjectDescriptor OPTIONAL,
    encoding CHOICE {
    single-ASN1-type [0] ABSTRACT-SYNTAX.&Type,
    octet-aligned [1] IMPLICIT OCTET STRING,
    arbitrary [2] IMPLICIT BIT STRING
  }
}
*/
/* NOTE: This sequence type differs from that in ITU-T Rec. X.680 | ISO/IEC 8824-1 for historical reasons. */

static int
dissect_per_T_direct_reference(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &actx->external.direct_reference);

  actx->external.direct_ref_present = TRUE;
  return offset;
}



static int
dissect_per_T_indirect_reference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, &actx->external.indirect_reference);

  actx->external.indirect_ref_present = TRUE;
  return offset;
}



static int
dissect_per_T_data_value_descriptor(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_descriptor(tvb, offset, actx, tree, hf_index, &actx->external.data_value_descriptor);

  actx->external.data_value_descr_present = TRUE;
  return offset;
}



static int
dissect_per_T_single_ASN1_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, actx->external.hf_index, actx->external.u.per.type_cb);

  return offset;
}



static int
dissect_per_T_octet_aligned(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &actx->external.octet_aligned);

  if (actx->external.u.per.type_cb) {
    actx->external.u.per.type_cb(actx->external.octet_aligned, 0, actx, tree, actx->external.hf_index);
    } else {
        actx->created_item = proto_tree_add_text(tree, actx->external.octet_aligned, 0, -1, "Unknown EXTERNAL Type");
    }
  return offset;
}



static int
dissect_per_T_arbitrary(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, &actx->external.arbitrary);

  if (actx->external.u.per.type_cb) {
    actx->external.u.per.type_cb(actx->external.arbitrary, 0, actx, tree, actx->external.hf_index);
    } else {
        actx->created_item = proto_tree_add_text(tree, actx->external.arbitrary, 0, -1, "Unknown EXTERNAL Type");
    }
  return offset;
}


static const value_string per_External_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const per_choice_t External_encoding_choice[] = {
  {   0, &hf_per_single_ASN1_type, ASN1_NO_EXTENSIONS     , dissect_per_T_single_ASN1_type },
  {   1, &hf_per_octet_aligned   , ASN1_NO_EXTENSIONS     , dissect_per_T_octet_aligned },
  {   2, &hf_per_arbitrary       , ASN1_NO_EXTENSIONS     , dissect_per_T_arbitrary },
  { 0, NULL, 0, NULL }
};

static int
dissect_per_External_encoding(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_per_External_encoding, External_encoding_choice,
                                 &actx->external.encoding);

  return offset;
}


static const per_sequence_t External_sequence[] = {
  { &hf_per_direct_reference, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_per_T_direct_reference },
  { &hf_per_indirect_reference, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_per_T_indirect_reference },
  { &hf_per_data_value_descriptor, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_per_T_data_value_descriptor },
  { &hf_per_encoding        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_per_External_encoding },
  { NULL, 0, 0, NULL }
};

static int
dissect_per_External(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_per_External, External_sequence);

  return offset;
}

guint32
dissect_per_external_type(tvbuff_t *tvb _U_, guint32 offset, asn1_ctx_t *actx, proto_tree *tree _U_, int hf_index _U_, per_type_fn type_cb)
{
  asn1_ctx_clean_external(actx);
  actx->external.u.per.type_cb = type_cb;
  offset = dissect_per_External(tvb, offset, actx, tree, hf_index);

  asn1_ctx_clean_external(actx);
  return offset;
}


void
proto_register_per(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_per_num_sequence_extensions,
		{ "Number of Sequence Extensions", "per.num_sequence_extensions", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of extensions encoded in this sequence", HFILL }},
	{ &hf_per_choice_index,
		{ "Choice Index", "per.choice_index", FT_UINT32, BASE_DEC,
		NULL, 0, "Which index of the Choice within extension root is encoded", HFILL }},
	{ &hf_per_choice_extension_index,
		{ "Choice Extension Index", "per.choice_extension_index", FT_UINT32, BASE_DEC,
		NULL, 0, "Which index of the Choice within extension addition is encoded", HFILL }},
	{ &hf_per_enum_index,
		{ "Enumerated Index", "per.enum_index", FT_UINT32, BASE_DEC,
		NULL, 0, "Which index of the Enumerated within extension root is encoded", HFILL }},
	{ &hf_per_enum_extension_index,
		{ "Enumerated Extension Index", "per.enum_extension_index", FT_UINT32, BASE_DEC,
		NULL, 0, "Which index of the Enumerated within extension addition is encoded", HFILL }},
	{ &hf_per_GeneralString_length,
		{ "GeneralString Length", "per.generalstring_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the GeneralString", HFILL }},
	{ &hf_per_extension_bit,
		{ "Extension Bit", "per.extension_bit", FT_BOOLEAN, 8,
		TFS(&tfs_extension_bit), 0x01, "The extension bit of an aggregate", HFILL }},
	{ &hf_per_extension_present_bit,
		{ "Extension Present Bit", "per.extension_present_bit", FT_BOOLEAN, 8,
		TFS(&tfs_extension_present_bit), 0x01, "Whether this optional extension is present or not", HFILL }},
	{ &hf_per_small_number_bit,
		{ "Small Number Bit", "per.small_number_bit", FT_BOOLEAN, 8,
		TFS(&tfs_small_number_bit), 0x01, "The small number bit for a section 10.6 integer", HFILL }},
	{ &hf_per_optional_field_bit,
		{ "Optional Field Bit", "per.optional_field_bit", FT_BOOLEAN, 8,
		TFS(&tfs_optional_field_bit), 0x01, "This bit specifies the presence/absence of an optional field", HFILL }},
	{ &hf_per_sequence_of_length,
		{ "Sequence-Of Length", "per.sequence_of_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of items in the Sequence Of", HFILL }},
	{ &hf_per_object_identifier_length,
		{ "Object Identifier Length", "per.object_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the object identifier", HFILL }},
	{ &hf_per_open_type_length,
		{ "Open Type Length", "per.open_type_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of an open type encoding", HFILL }},
	{ &hf_per_real_length,
		{ "Real Length", "per.real_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of an real encoding", HFILL }},
	{ &hf_per_octet_string_length,
		{ "Octet String Length", "per.octet_string_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes in the Octet String", HFILL }},
	{ &hf_per_bit_string_length,
		{ "Bit String Length", "per.bit_string_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bits in the Bit String", HFILL }},
	{ &hf_per_const_int_len,
		{ "Constrained Integer Length", "per.const_int_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes in the Constrained Integer", HFILL }},
    { &hf_per_direct_reference,
      { "direct-reference", "per.direct_reference",
        FT_OID, BASE_NONE, NULL, 0,
        "per.T_direct_reference", HFILL }},
    { &hf_per_indirect_reference,
      { "indirect-reference", "per.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "per.T_indirect_reference", HFILL }},
    { &hf_per_data_value_descriptor,
      { "data-value-descriptor", "per.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        "per.T_data_value_descriptor", HFILL }},
    { &hf_per_encoding,
      { "encoding", "per.encoding",
        FT_UINT32, BASE_DEC, VALS(per_External_encoding_vals), 0,
        "per.External_encoding", HFILL }},
    { &hf_per_single_ASN1_type,
      { "single-ASN1-type", "per.single_ASN1_type",
        FT_NONE, BASE_NONE, NULL, 0,
        "per.T_single_ASN1_type", HFILL }},
    { &hf_per_octet_aligned,
      { "octet-aligned", "per.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "per.T_octet_aligned", HFILL }},
    { &hf_per_arbitrary,
      { "arbitrary", "per.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "per.T_arbitrary", HFILL }},
    { &hf_per_integer_length,
      { "integer length", "per.integer_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
	{ &hf_per_debug_pos,
      { "Current bit offset", "per.debug_pos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
	};
	static gint *ett[] =
	{
		&ett_per_open_type,
		&ett_per_containing,
		&ett_per_sequence_of_item,
		&ett_per_External,
		&ett_per_External_encoding,
	};
	module_t *per_module;

	proto_per = proto_register_protocol("Packed Encoding Rules (ASN.1 X.691)", "PER", "per");
	proto_register_field_array(proto_per, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	proto_set_cant_toggle(proto_per);

	per_module = prefs_register_protocol(proto_per, NULL);
	prefs_register_bool_preference(per_module, "display_internal_per_fields",
		"Display the internal PER fields in the tree",
		"Whether the dissector should put the internal PER data in the tree or if it should hide it",
		&display_internal_per_fields);

}

void
proto_reg_handoff_per(void)
{
}

