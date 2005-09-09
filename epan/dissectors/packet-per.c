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
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-per.h"
#include "packet-ber.h"


static int proto_per = -1;
static int hf_per_GeneralString_length = -1;
static int hf_per_extension_bit = -1;
static int hf_per_extension_present_bit = -1;
static int hf_per_choice_index = -1;
static int hf_per_choice_extension_index = -1;
static int hf_per_num_sequence_extensions = -1;
static int hf_per_small_number_bit = -1;
static int hf_per_optional_field_bit = -1;
static int hf_per_sequence_of_length = -1;
static int hf_per_object_identifier_length = -1;
static int hf_per_open_type_length = -1;
static int hf_per_octet_string_length = -1;
static int hf_per_bit_string_length = -1;

static gint ett_per_sequence_of_item = -1;


/*
#define DEBUG_ENTRY(x) \
printf("#%d  %s   tvb:0x%08x\n",pinfo->fd->num,x,(int)tvb);
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

#define BYTE_ALIGN_OFFSET(offset)		\
	if(offset&0x07){			\
		offset=(offset&0xfffffff8)+8;	\
	}

/* 10.9 General rules for encoding a length determinant -------------------- */
guint32
dissect_per_length_determinant(tvbuff_t *tvb, guint32 offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index, guint32 *length)
{
	guint8 byte;
	guint32 len;
	proto_item *pi;

	if(!length){
		length=&len;
	}

	/* byte aligned */
	BYTE_ALIGN_OFFSET(offset);
	byte=tvb_get_guint8(tvb, offset>>3);
	offset+=8;

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
dissect_per_normally_small_nonnegative_whole_number(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, guint32 *length)
{
	gboolean small_number;
	guint32 len;
	proto_item *pi;

DEBUG_ENTRY("dissect_per_normally_small_nonnegative_whole_number");
	if(!length){
		length=&len;
	}

	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_per_small_number_bit, &small_number, &pi);
	if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
	if(!small_number){
		int i;
		/* 10.6.1 */
		*length=0;
		for(i=0;i<6;i++){
			offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &small_number, NULL);
			*length<<=1;
			if(small_number){
				*length|=1;
			}
		}
		if(hf_index!=-1){
			if((offset&0x07)<7){
				pi = proto_tree_add_uint(tree, hf_index, tvb, (offset>>3)-1, 1, *length);
			} else {
				pi = proto_tree_add_uint(tree, hf_index, tvb, (offset>>3), 1, *length);
			}
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
		}
		return offset;
	}

	/* 10.6.2 */
	offset=dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_index, length);

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
dissect_per_GeneralString(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index)
{
	guint32 length;

	offset=dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_per_GeneralString_length, &length);


	proto_tree_add_item(tree, hf_index, tvb, offset>>3, length, FALSE);

	offset+=length*8;

	return offset;
}

/* 17 Encoding the null type */
guint32
dissect_per_null(tvbuff_t *tvb, guint32 offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  proto_item *ti_tmp;

  ti_tmp = proto_tree_add_item(tree, hf_index, tvb, offset>>8, 0, FALSE);
  proto_item_append_text(ti_tmp, ": NULL");

  return offset;
}

/* 19 this function dissects a sequence of */
static guint32
dissect_per_sequence_of_helper(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int (*func)(tvbuff_t *, int , packet_info *, proto_tree *), guint32 length)
{
	guint32 i;

DEBUG_ENTRY("dissect_per_sequence_of_helper");
	for(i=0;i<length;i++){
		guint32 lold_offset=offset;
		proto_item *litem;
		proto_tree *ltree;

		litem=proto_tree_add_text(tree, tvb, offset>>3, 0, "Item %d", i);
		ltree=proto_item_add_subtree(litem, ett_per_sequence_of_item);

		offset=(*func)(tvb, offset, pinfo, ltree);
		proto_item_set_len(litem, (offset>>3)!=(lold_offset>>3)?(offset>>3)-(lold_offset>>3):1);
	}

	return offset;
}
guint32
dissect_per_sequence_of(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq)
{
	proto_item *item;
	proto_tree *tree;
	guint32 old_offset=offset;
	guint32 length;
	header_field_info *hfi;

DEBUG_ENTRY("dissect_per_sequence_of");

	/* semi-constrained whole number for number of elements */
	/* each element encoded as 10.9 */

	offset=dissect_per_length_determinant(tvb, offset, pinfo, parent_tree, hf_per_sequence_of_length, &length);

	hfi = proto_registrar_get_nth(hf_index);
	if (IS_FT_UINT(hfi->type)) {
		item = proto_tree_add_uint(parent_tree, hf_index, tvb, offset>>3, 0, length);
		proto_item_append_text(item, (length==1)?" item":" items");
	} else {
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset>>3, 0, FALSE);
	}
	tree=proto_item_add_subtree(item, ett_index);

	offset=dissect_per_sequence_of_helper(tvb, offset, pinfo, tree, seq->func, length);


	proto_item_set_len(item, (offset>>3)!=(old_offset>>3)?(offset>>3)-(old_offset>>3):1);
	return offset;
}


/* dissect a constrained IA5String that consists of the full ASCII set,
   i.e. no FROM stuff limiting the alphabet
*/
guint32
dissect_per_IA5String(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index, min_len, max_len, NULL);

	return offset;
}

/* XXX we dont do >64k length strings   yet */
static guint32
dissect_per_restricted_character_string_sorted(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb)
{
	guint32 length;
	gboolean byte_aligned;
	guint8 *buf;
	guint char_pos;
	int bits_per_char;
	guint32 old_offset;
	proto_item *pi;

DEBUG_ENTRY("dissect_per_restricted_character_string");

	/* xx.x if the length is 0 bytes there will be no encoding */
	if(max_len==0){
		if (value_tvb) {
			*value_tvb = tvb_new_real_data(NULL, 0, 0); 
			tvb_set_child_real_data_tvbuff(tvb, *value_tvb);
		}
		return offset;
	}


	if(min_len==-1){
		min_len=0;
	}


	/* 27.5.2 depending of the alphabet length, find how many bits
	   are used to encode each character */
/* unaligned PER
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
*/
	if(alphabet_length<=2){
		bits_per_char=1;
	} else if(alphabet_length<=4){
		bits_per_char=2;
	} else if(alphabet_length<=16){
		bits_per_char=4;
	} else {
		bits_per_char=8;
	}


	byte_aligned=TRUE;
	if((min_len==max_len)&&(max_len<=2)){
		byte_aligned=FALSE;
	}
	if((max_len!=-1)&&(max_len<2)){
		byte_aligned=FALSE;
	}

	/* xx.x */
	length=max_len;
	if(max_len==-1){
		offset = dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_per_octet_string_length, &length);
		/* the unconstrained strings are always byte aligned (27.6.3)*/
		byte_aligned=TRUE;
	} else if(min_len!=max_len){
		offset=dissect_per_constrained_integer(tvb, offset, pinfo,
			tree, hf_per_octet_string_length, min_len, max_len,
			&length, &pi, FALSE);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
	}

	if(!length){
		/* there is no string at all, so dont do any byte alignment */
		/* byte_aligned=FALSE; */
		/* Advance offset to next 'element' */
		offset = offset + 1;	}

	if(byte_aligned){
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
			offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
			val=(val<<1)|bit;
		}
		/* ALIGNED PER does not do any remapping of chars if 
		   bitsperchar is 8 
		*/
		if(bits_per_char==8){
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
		*value_tvb = tvb_new_real_data(buf, length, length); 
		tvb_set_free_cb(*value_tvb, g_free);
		tvb_set_child_real_data_tvbuff(tvb, *value_tvb);
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
dissect_per_restricted_character_string(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb)
{
  const char *alphabet_ptr;
  char sorted_alphabet[128];

  if (alphabet_length > 127) {
    alphabet_ptr = alphabet;
  } else {
    alphabet_ptr = sort_alphabet(sorted_alphabet, alphabet, alphabet_length);
  }
  return dissect_per_restricted_character_string_sorted(tvb, offset, pinfo, tree, hf_index, min_len, max_len, alphabet_ptr, alphabet_length, value_tvb);
}

guint32
dissect_per_NumericString(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, pinfo, tree, hf_index, min_len, max_len, 
		" 0123456789", 11, NULL);

	return offset;
}
guint32
dissect_per_PrintableString(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, pinfo, tree, hf_index, min_len, max_len, 
		" '()+,-.*0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 74, NULL);
	return offset;
}
guint32
dissect_per_VisibleString(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len)
{
	offset=dissect_per_restricted_character_string_sorted(tvb, offset, pinfo, tree, hf_index, min_len, max_len,
		" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", 95, NULL);
	return offset;
}
guint32
dissect_per_BMPString(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len)
{
	guint32 length;
	static char *str;
	proto_item *pi;

	/* xx.x if the length is 0 bytes there will be no encoding */
	if(max_len==0){
		return offset;
	}


	if(min_len==-1){
		min_len=0;
	}


	/* xx.x */
	length=max_len;
	if(min_len!=max_len){
		offset=dissect_per_constrained_integer(tvb, offset, pinfo,
			tree, hf_per_octet_string_length, min_len, max_len,
			&length, &pi, FALSE);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
	}


	/* align to byte boundary */
	BYTE_ALIGN_OFFSET(offset);

	if(length>=1024){
		PER_NOT_DECODED_YET("BMPString too long");
		length=1024;
	}

	str = tvb_get_ephemeral_faked_unicode(tvb, offset>>3, length, FALSE);

	proto_tree_add_string(tree, hf_index, tvb, offset>>3, length*2, str);

	offset+=(length<<3)*2;

	return offset;
}


/* this function dissects a constrained sequence of */
guint32
dissect_per_constrained_sequence_of(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len)
{
	proto_item *item;
	proto_tree *tree;
	guint32 old_offset=offset;
	guint32 length;
	header_field_info *hfi;
	proto_item *pi;


DEBUG_ENTRY("dissect_per_constrained_sequence_of");

	/* 19.5 if min==max and min,max<64k ==> no length determinant */
	if((min_len==max_len) && (min_len<65536)){
		length=min_len;
		goto call_sohelper;
	}

	/* 19.6 ub>=64k or unset */
	if(max_len>=65536){
		/* semi-constrained whole number for number of elements */
		/* each element encoded as 10.9 */
		offset=dissect_per_length_determinant(tvb, offset, pinfo, parent_tree, hf_per_sequence_of_length, &length);
		length+=min_len;
		goto call_sohelper;
	}

	/* constrained whole number for number of elements */
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		parent_tree, hf_per_sequence_of_length, min_len, max_len,
		&length, &pi, FALSE);
	if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);

call_sohelper:
	hfi = proto_registrar_get_nth(hf_index);
	if (IS_FT_UINT(hfi->type)) {
		item = proto_tree_add_uint(parent_tree, hf_index, tvb, offset>>3, 0, length);
		proto_item_append_text(item, (length==1)?" item":" items");
	} else {
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset>>3, 0, FALSE);
	}
	tree=proto_item_add_subtree(item, ett_index);

	offset=dissect_per_sequence_of_helper(tvb, offset, pinfo, tree, seq->func, length);


	proto_item_set_len(item, (offset>>3)!=(old_offset>>3)?(offset>>3)-(old_offset>>3):1);
	return offset;
}

/* this function dissects a constrained set of */
guint32
dissect_per_constrained_set_of(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len)
{
	/* for basic-per  a set-of is encoded in the same way as a sequence-of */
DEBUG_ENTRY("dissect_per_constrained_set_of");
	offset=dissect_per_constrained_sequence_of(tvb, offset, pinfo, parent_tree, hf_index, ett_index, seq, min_len, max_len);
	return offset;
}






/* this function dissects a set of */
guint32
dissect_per_set_of(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq)
{
	/* for basic-per  a set-of is encoded in the same way as a sequence-of */
DEBUG_ENTRY("dissect_per_set_of");
	offset=dissect_per_sequence_of(tvb, offset, pinfo, parent_tree, hf_index, ett_index, seq);
	return offset;
}




/* 23 Encoding the object identifier type */
guint32
dissect_per_object_identifier(tvbuff_t *tvb, guint32 offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index, char *value_string)
{
	guint length;
	char *str, *name;
	proto_item *item;

DEBUG_ENTRY("dissect_per_object_identifier");

	offset = dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_per_object_identifier_length, &length);

	str = oid_to_str(tvb_get_ptr(tvb, offset>>3, length), length);
	item = proto_tree_add_string(tree, hf_index, tvb, offset>>3, length, str);
	offset += 8 * length;

	/* see if we know the name of this oid */
	if(item){
		name = get_ber_oid_name(str);
		if(name){
			proto_item_append_text(item, " (%s)", name);
		}
	}

	if (value_string) {
		strcpy(value_string, str);
	}

	return offset;
}




/* this function reads a single bit */
guint32
dissect_per_boolean(tvbuff_t *tvb, guint32 offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index, gboolean *bool, proto_item **item)
{
	guint8 ch, mask;
	gboolean value;
	header_field_info *hfi;
	proto_item *it;

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
		str=ep_alloc(256);
		g_snprintf(str, 256, "%c%c%c%c %c%c%c%c %s: %s",
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
		it=proto_tree_add_boolean_format(tree, hf_index, tvb, offset>>3, 1, value, str);
		if(item){
			*item=it;
		}
	}

	if(bool){
		*bool=value;
	}
	return offset+1;
}




/* we currently only handle integers up to 32 bits in length. */
guint32
dissect_per_integer(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, gint32 *value, proto_item **item)
{
	guint32 i, length;
	gint32 val;
	proto_item *it=NULL;
	header_field_info *hfi;

	/* 12.2.6 b */
	offset=dissect_per_length_determinant(tvb, offset, pinfo, tree, -1, &length);
	/* gassert here? */
	if(length>4){
PER_NOT_DECODED_YET("too long integer");
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


	if(item){
		*item=it;
	}
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
dissect_per_constrained_integer(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, guint32 min, guint32 max, guint32 *value, proto_item **item, gboolean has_extension)
{
	proto_item *it=NULL;
	guint32 range, val;
	gint val_start, val_length;
	nstime_t timeval;
	header_field_info *hfi;
	int num_bits;
	int pad;
	gboolean tmp;

DEBUG_ENTRY("dissect_per_constrained_integer");
	if(has_extension){
		gboolean extension_present;
		offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &extension_present, NULL);
		if(extension_present){
			offset=dissect_per_integer(tvb, offset, pinfo, tree,
				hf_index,
				NULL, NULL);
			return offset;
		}
	}

	hfi = proto_registrar_get_nth(hf_index);

	/* 10.5.3 */
	if((max-min)>65536){
		/* just set range really big so it will fall through
		   to the bottom of the encoding */
		range=1000000;
	} else {
		range=max-min+1;
	}

	num_bits=0;
	pad=0;
	val=0;
	timeval.secs=val; timeval.nsecs=0;
	/* 10.5.4 */
	if(range==1){
		val_start = offset>>3; val_length = 0;
		val = min; 
	} else if(range<=255) {
		/* 10.5.7.1 */
		char *str;
		int i, bit, length;

		length=1;
		if(range<=2){
			num_bits=1;
		} else if(range<=4){
			num_bits=2;
		} else if(range<=8){
			num_bits=3;
		} else if(range<=16){
			num_bits=4;
		} else if(range<=32){
			num_bits=5;
		} else if(range<=64){
			num_bits=6;
		} else if(range<=128){
			num_bits=7;
		} else if(range<=256){
			num_bits=8;
		}
		/* prepare the string */
		str=ep_alloc(256);
		g_snprintf(str, 256, "%s: ", hfi->name);
		for(bit=0;bit<((int)(offset&0x07));bit++){
			if(bit&&(!(bit%4))){
				strcat(str, " ");
			}
			strcat(str,".");
		}
		/* read the bits for the int */
		for(i=0;i<num_bits;i++){
			if(bit&&(!(bit%4))){
				strcat(str, " ");
			}
			if(bit&&(!(bit%8))){
				length+=1;
				strcat(str, " ");
			}
			bit++;
			offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &tmp, NULL);
			val<<=1;
			if(tmp){
				val|=1;
				strcat(str, "1");
			} else {
				strcat(str, "0");
			}
		}
		for(;bit%8;bit++){
			if(bit&&(!(bit%4))){
				strcat(str, " ");
			}
			strcat(str,".");
		}
		val_start = (offset-num_bits)>>3; val_length = length;
		val+=min;
	} else if(range==256){
		/* 10.5.7.2 */
		num_bits=8;
		pad=7-(offset&0x07);

		/* in the aligned case, align to byte boundary */
		BYTE_ALIGN_OFFSET(offset);
		val=tvb_get_guint8(tvb, offset>>3);
		offset+=8;

		val_start = (offset>>3)-1; val_length = 1;
		val+=min;
	} else if(range<=65536){
		/* 10.5.7.3 */
		num_bits=16;
		pad=7-(offset&0x07);

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
		offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
		num_bytes=bit;
		offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
		num_bytes=(num_bytes<<1)|bit;

		num_bytes++;  /* lower bound for length determinant is 1 */

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
	} else if (IS_FT_INT(hfi->type)) {
		it = proto_tree_add_int(tree, hf_index, tvb, val_start, val_length, val);
	} else if (IS_FT_TIME(hfi->type)) {
		it = proto_tree_add_time(tree, hf_index, tvb, val_start, val_length, &timeval);
	} else {
		THROW(ReportedBoundsError);
	}
	if (item) *item = it;
	if (value) *value = val;
	return offset;}

/* 22 Encoding the choice type */
guint32
dissect_per_choice(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, gint ett_index, const per_choice_t *choice, const char *name, guint32 *value)
{
	gboolean extension_present, extension_flag;
	int extension_root_entries;
	int extension_addition_entries;
	guint32 choice_index;
	int i, index, cidx;
	guint32 ext_length;
	guint32 old_offset = offset;
	proto_item *choice_item = NULL;
	proto_tree *choice_tree = NULL;
	proto_item *pi;

DEBUG_ENTRY("dissect_per_choice");

	/* 22.5 */
	if (choice[0].extension == ASN1_NO_EXTENSIONS){
		extension_present = FALSE;
		extension_flag = FALSE;
	} else {
		extension_present = TRUE;
		offset = dissect_per_boolean(tvb, offset, pinfo, tree, hf_per_extension_bit, &extension_flag, &pi);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
	}

	/* count the number of entries in the extension root and extension addition */
	extension_root_entries = 0;
	extension_addition_entries = 0;
	for (i=0; choice[i].func; i++) {
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
			offset = dissect_per_constrained_integer(tvb, offset, pinfo,
				tree, hf_per_choice_index, 0, extension_root_entries - 1,
				&choice_index, &pi, FALSE);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
		}

		index = -1; cidx = choice_index;
		for (i=0; choice[i].func; i++) {
			if(choice[i].extension != ASN1_NOT_EXTENSION_ROOT){
				if (!cidx) { index = i; break; }
				cidx--;
			}
		}
	} else {  /* 22.8 */
		offset = dissect_per_normally_small_nonnegative_whole_number(tvb, offset, pinfo, tree, hf_per_choice_extension_index, &choice_index);
		offset = dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_per_open_type_length, &ext_length);

		index = -1; cidx = choice_index;
		for (i=0; choice[i].func; i++) {
			if(choice[i].extension == ASN1_NOT_EXTENSION_ROOT){
				if (!cidx) { index = i; break; }
				cidx--;
			}
		}
	}

	if (index != -1) {
		choice_item = proto_tree_add_uint(tree, hf_index, tvb, old_offset>>3, 0, choice[index].value);
		choice_tree = proto_item_add_subtree(choice_item, ett_index);
		if (!extension_flag) {
			offset = choice[index].func(tvb, offset, pinfo, choice_tree);
		} else {
			choice[index].func(tvb, offset, pinfo, choice_tree);
			offset += ext_length * 8;
		}
		proto_item_set_len(choice_item, BLEN(old_offset, offset));
	} else {
		if (!extension_flag) {
			PER_NOT_DECODED_YET("unknown extension root index in choice");
		} else {
			offset += ext_length * 8;
			proto_tree_add_text(tree, tvb, old_offset>>3, BLEN(old_offset, offset), "Choice no. %d in extension", choice_index);
			PER_NOT_DECODED_YET("unknown choice extension");
		}
	}

	if (value) *value = choice[index].value;

	return offset;
}


static const char *
index_get_optional_name(const per_sequence_t *sequence, int index)
{
	int i;

	for(i=0;sequence[i].name;i++){
		if((sequence[i].extension!=ASN1_NOT_EXTENSION_ROOT)&&(sequence[i].optional==ASN1_OPTIONAL)){
			if(index==0){
				return sequence[i].name;
			}
			index--;
		}
	}
	return "<unknown type>";
}

static const char *
index_get_extension_name(const per_sequence_t *sequence, int index)
{
	int i;

	for(i=0;sequence[i].name;i++){
		if(sequence[i].extension==ASN1_NOT_EXTENSION_ROOT){
			if(index==0){
				return sequence[i].name;
			}
			index--;
		}
	}
	return "<unknown type>";
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
dissect_per_sequence(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *sequence)
{
	gboolean extension_present, extension_flag, optional_field_flag;
	proto_item *item;
	proto_tree *tree;
	guint32 old_offset=offset;
	guint32 i, num_opts;
	guint32 optional_mask;
	proto_item *pi;


DEBUG_ENTRY("dissect_per_sequence");

	item=proto_tree_add_item(parent_tree, hf_index, tvb, offset>>3, 0, FALSE);
	tree=proto_item_add_subtree(item, ett_index);


	/* first check if there should be an extension bit for this CHOICE.
	   we do this by just checking the first choice arm
	 */
	/* 18.1 */
	extension_flag=0;
	if(sequence[0].extension==ASN1_NO_EXTENSIONS){
		extension_present=0;
	} else {
		extension_present=1;
		offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_per_extension_bit, &extension_flag, &pi);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
	}
	/* 18.2 */
	num_opts=0;
	for(i=0;sequence[i].name;i++){
		if((sequence[i].extension!=ASN1_NOT_EXTENSION_ROOT)&&(sequence[i].optional==ASN1_OPTIONAL)){
			num_opts++;
		}
	}

	optional_mask=0;
	for(i=0;i<num_opts;i++){
		proto_item *it=NULL;
		offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_per_optional_field_bit, &optional_field_flag, &it);
		if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(it);
		optional_mask<<=1;
		if(optional_field_flag){
			optional_mask|=0x01;
		}
		if(it){
			proto_item_append_text(it, " (%s %s present)",
				index_get_optional_name(sequence, i),
				optional_field_flag?"is":"is NOT"
				);
		}
	}


	/* 18.4 */
	for(i=0;sequence[i].name;i++){
		if( (sequence[i].extension==ASN1_NO_EXTENSIONS)
		||  (sequence[i].extension==ASN1_EXTENSION_ROOT) ){
			if(sequence[i].optional==ASN1_OPTIONAL){
				gboolean is_present;
				is_present=(1<<(num_opts-1))&optional_mask;
				num_opts--;
				if(!is_present){
					continue;
				}
			}
			if(sequence[i].func){
				offset=sequence[i].func(tvb, offset, pinfo, tree);
			} else {
				PER_NOT_DECODED_YET(sequence[i].name);
			}
		}
	}


	if(extension_flag){
		gboolean extension_bit;
		guint32 num_known_extensions;
		guint32 num_extensions;
		guint32 extension_mask;
		proto_item *it=NULL;

		offset=dissect_per_normally_small_nonnegative_whole_number(tvb, offset, pinfo, tree, hf_per_num_sequence_extensions, &num_extensions);
		/* the X.691 standard is VERY unclear here.
		   there is no mention that the lower bound lb for this
		   (apparently) semiconstrained value is 1,
		   apart from the NOTE: comment in 18.8 that this value can
		   not be 0.
		   In my book, there is a semantic difference between having
		   a comment that says that the value can not be zero
		   and stating that the lb is 1.
		   I dont know if this is right or not but it makes
		   some of the very few captures I have decode properly.

		   It could also be that the captures I have are generated by
		   a broken implementation.
		   If this is wrong and you dont report it as a bug
		   then it wont get fixed!
		*/
		num_extensions+=1;

		extension_mask=0;
		for(i=0;i<num_extensions;i++){
			offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_per_extension_present_bit, &extension_bit, &it);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(it);
			extension_mask=(extension_mask<<1)|extension_bit;
			if(it){
				proto_item_append_text(it, " (%s %s present)",
					index_get_extension_name(sequence, i),
					extension_bit?"is":"is NOT"
					);
			}

		}

		/* find how many extensions we know about */
		num_known_extensions=0;
		for(i=0;sequence[i].name;i++){
			if(sequence[i].extension==ASN1_NOT_EXTENSION_ROOT){
				num_known_extensions++;
			}
		}

		/* decode the extensions one by one */
		for(i=0;i<num_extensions;i++){
			guint32 length;
			guint32 new_offset;
			guint32 extension_index;
			guint32 j,k;

			if(!((1L<<(num_extensions-1-i))&extension_mask)){
				/* this extension is not encoded in this PDU */
				continue;
			}

			offset=dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_per_open_type_length, &length);

			if(i>=num_known_extensions){
				/* we dont know how to decode this extension */
				offset+=length*8;
				PER_NOT_DECODED_YET("unknown sequence extension");
				continue;
			}

			extension_index=0;
			for(j=0,k=0;sequence[j].name;j++){
				if(sequence[j].extension==ASN1_NOT_EXTENSION_ROOT){
					if(k==i){
						extension_index=j;
						break;
					}
					k++;
				}
			}

			if(sequence[extension_index].func){
				new_offset=sequence[extension_index].func(tvb, offset, pinfo, tree);
			} else {
				PER_NOT_DECODED_YET(sequence[extension_index].name);
			}
			offset+=length*8;

		}
	}


	proto_item_set_len(item, (offset>>3)!=(old_offset>>3)?(offset>>3)-(old_offset>>3):1);
	return offset;
}



/* 15 Encoding the bitstring type

   max_len or min_len == -1 means there is no lower/upper constraint

*/
guint32
dissect_per_bit_string(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len)
{
	guint32 length;
	header_field_info *hfi;

	hfi = (hf_index==-1) ? NULL : proto_registrar_get_nth(hf_index);

DEBUG_ENTRY("dissect_per_bit_string");
	/* 15.8 if the length is 0 bytes there will be no encoding */
	if(max_len==0) {
		return offset;
	}

	if(min_len==-1) {
		min_len=0;
	}

	/* 15.9 if length is fixed and less than or equal to sixteen bits*/
	if((min_len==max_len)&&(max_len<=16)){
		static guint8 bytes[4];
		int i;
		guint32 old_offset=offset;
		gboolean bit;

		bytes[0]=bytes[1]=bytes[2]=0;
		for(i=0;i<min_len;i++){
			offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
			bytes[0]=(bytes[0]<<1)|bit;
		}
		if(min_len>8){
			for(i=8;i<min_len;i++){
				offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
				bytes[1]=(bytes[1]<<1)|bit;
			}
			if(min_len<16){
				bytes[1]|=bytes[0]<<(min_len-8);
				bytes[0]>>=16-min_len;
			}
		}
		if (hfi) {
			proto_tree_add_bytes(tree, hf_index, tvb, old_offset>>3, (min_len+7)/8+(offset&0x07)?1:0, bytes);
		}
		return offset;
	}


	/* 15.10 if length is fixed and less than to 64kbits*/
	if((min_len==max_len)&&(min_len<65536)){
		/* align to byte */
		BYTE_ALIGN_OFFSET(offset);
		if (hfi) {
			proto_tree_add_item(tree, hf_index, tvb, offset>>3, (min_len+7)/8, FALSE);
		}
		offset+=min_len;
		return offset;
	}

	/* 15.11 */
	if(max_len>0){
		proto_item *pi;

		offset=dissect_per_constrained_integer(tvb, offset, pinfo,
			tree, hf_per_bit_string_length, min_len, max_len,
			&length, &pi, FALSE);
			if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
	} else {
		offset=dissect_per_length_determinant(tvb, offset, pinfo, tree, hf_per_bit_string_length, &length);
	}
	if(length){
		/* align to byte */
		BYTE_ALIGN_OFFSET(offset);
		if (hfi) {
			proto_tree_add_item(tree, hf_index, tvb, offset>>3, (length+7)/8, FALSE);
		}
	}
	offset+=length;

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

   max_len or min_len == -1 means there is no lower/upper constraint

   hf_index can either be a FT_BYTES or an FT_STRING
*/
guint32
dissect_per_octet_string(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, int hf_index, int min_len, int max_len, tvbuff_t **value_tvb)
{
	proto_item *it = NULL;
	gint val_start, val_length;
	guint32 length;
	header_field_info *hfi;
	static guint8 bytes[4];
	guint8 *pbytes = NULL;
	proto_item *pi;

	hfi = (hf_index==-1) ? NULL : proto_registrar_get_nth(hf_index);

DEBUG_ENTRY("dissect_per_octet_string");

	if(min_len==-1){
		min_len=0;
	}
	
	if (max_len==0) {  /* 16.5 if the length is 0 bytes there will be no encoding */
		val_start = offset>>3; 
		val_length = 0;

	} else if((min_len==max_len)&&(max_len<=2)) {  /* 16.6 if length is fixed and less than or equal to two bytes*/
		guint32 i, old_offset=offset;
		gboolean bit;

		for(i=0;i<8;i++){
			offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
			bytes[0]=(bytes[0]<<1)|bit;
		}
		if(min_len==2){
			for(i=0;i<8;i++){
				offset=dissect_per_boolean(tvb, offset, pinfo, tree, -1, &bit, NULL);
				bytes[1]=(bytes[1]<<1)|bit;
			}
		}
		bytes[min_len]=0;
		pbytes = bytes;
		val_start = old_offset>>3; 
		val_length = min_len+(offset&0x07)?1:0;

	} else if ((min_len==max_len)&&(min_len<65536)) {  /* 16.7 if length is fixed and less than to 64k*/
		/* align to byte */
		BYTE_ALIGN_OFFSET(offset);
		val_start = offset>>3; 
		val_length = min_len;
		offset+=min_len*8;

	} else {  /* 16.8 */
		if(max_len>0) {  
			offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree,
				hf_per_octet_string_length, min_len, max_len,
				&length, &pi, FALSE);
				if (!display_internal_per_fields) PROTO_ITEM_SET_HIDDEN(pi);
		} else {
			offset = dissect_per_length_determinant(tvb, offset, pinfo, tree, 
				hf_per_octet_string_length, &length);
		}

		if(length){
			/* align to byte */
			BYTE_ALIGN_OFFSET(offset);
		}
		val_start = offset>>3; 
		val_length = length;
		offset+=length*8;
	}

	if (hfi) {
		if (IS_FT_UINT(hfi->type)||IS_FT_INT(hfi->type)) {
			if (IS_FT_UINT(hfi->type))
				it = proto_tree_add_uint(tree, hf_index, tvb, val_start, val_length, val_length);
			else
				it = proto_tree_add_int(tree, hf_index, tvb, val_start, val_length, val_length);
			proto_item_append_text(it, plurality(val_length, " octet", " octets"));
		} else {
			if (pbytes) {
				if(IS_FT_STRING(hfi->type)){
					proto_tree_add_string(tree, hf_index, tvb, val_start, val_length, (char*)pbytes);
				} else if (hfi->type==FT_BYTES) {
					proto_tree_add_bytes(tree, hf_index, tvb, val_start, val_length, pbytes);
				} else {
					THROW(ReportedBoundsError);
				}
			} else {
				proto_tree_add_item(tree, hf_index, tvb, val_start, val_length, FALSE);
			}
		}
	}
	if (value_tvb)
		*value_tvb = tvb_new_subset(tvb, val_start, val_length, val_length);
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
		{ "Object Length", "per.object_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the object identifier", HFILL }},
	{ &hf_per_open_type_length,
		{ "Open Type Length", "per.open_type_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of an open type encoding", HFILL }},
	{ &hf_per_octet_string_length,
		{ "Octet String Length", "per.octet_string_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes in the Octet String", HFILL }},
	{ &hf_per_bit_string_length,
		{ "Bit String Length", "per.bit_string_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bits in the Bit String", HFILL }},
	};

	static gint *ett[] =
	{
		&ett_per_sequence_of_item
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

