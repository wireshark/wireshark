/* packet-ber.c
 * Helpers for ASN.1/BER dissection
 * Ronnie Sahlberg (C) 2004
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

/* 
 * ITU-T Recommendation X.690 (07/2002),
 *   Information technology ASN.1 encoding rules:
 *     Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
 * 
 */ 

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/prefs.h>
#include "packet-ber.h"


static gint proto_ber = -1;
static gint hf_ber_id_class = -1;
static gint hf_ber_id_pc = -1;
static gint hf_ber_id_uni_tag = -1;
static gint hf_ber_id_tag = -1;
static gint hf_ber_length = -1;
static gint hf_ber_bitstring_padding = -1;

static gint ett_ber_octet_string = -1;

static gboolean show_internal_ber_fields = FALSE;

proto_item *ber_last_created_item=NULL;

static dissector_table_t ber_oid_dissector_table=NULL;

static const value_string ber_class_codes[] = {
	{ BER_CLASS_UNI,	"Universal" },
	{ BER_CLASS_APP,	"Application" },
	{ BER_CLASS_CON,	"Context Specific" },
	{ BER_CLASS_PRI,	"Private" },
	{ 0, NULL }
};

static const true_false_string ber_pc_codes = {
	"Constructed Encoding",
	"Primitive Encoding"
};

static const value_string ber_uni_tag_codes[] = {
	{ BER_UNI_TAG_EOC				, "'end-of-content'" },
	{ BER_UNI_TAG_BOOLEAN			, "BOOLEAN" },
	{ BER_UNI_TAG_INTEGER			, "INTEGER" },
	{ BER_UNI_TAG_BITSTRING		, "BIT STRING" },
	{ BER_UNI_TAG_OCTETSTRING		, "OCTET STRING" },
	{ BER_UNI_TAG_NULL			, "NULL" },
	{ BER_UNI_TAG_OID			 	, "OBJECT IDENTIFIER" },
	{ BER_UNI_TAG_ObjectDescriptor, "ObjectDescriptor" },
	{ BER_UNI_TAG_REAL			, "REAL" },
	{ BER_UNI_TAG_ENUMERATED		, "ENUMERATED" },
	{ BER_UNI_TAG_EMBEDDED_PDV	, "EMBEDDED PDV" },
	{ BER_UNI_TAG_UTF8String		, "UTF8String" },
	{ BER_UNI_TAG_RELATIVE_OID	, "RELATIVE-OID" },
	{ BER_UNI_TAG_SEQUENCE		, "SEQUENCE, SEQUENCE OF" },
	{ BER_UNI_TAG_SET				, "SET, SET OF" },
	{ BER_UNI_TAG_NumericString	, "NumericString" },
	{ BER_UNI_TAG_PrintableString	, "PrintableString" },
	{ BER_UNI_TAG_TeletextString	, "TeletextString, T61String" },
	{ BER_UNI_TAG_VideotexString	, "VideotexString" },
	{ BER_UNI_TAG_IA5String		, "IA5String" },
	{ BER_UNI_TAG_UTCTime		, "UTCTime" },
	{ BER_UNI_TAG_GeneralizedTime	, "GeneralizedTime" },
	{ BER_UNI_TAG_GraphicString	, "GraphicString" },
	{ BER_UNI_TAG_VisibleString	, "VisibleString, ISO64String" },
	{ BER_UNI_TAG_GeneralString	, "GeneralString" },
	{ BER_UNI_TAG_UniversalString	, "UniversalString" },
	{ BER_UNI_TAG_CHARACTERSTRING	, "CHARACTER STRING" },
	{ BER_UNI_TAG_BMPString		, "BMPString" },
	{ 0, NULL }
};


proto_item *get_ber_last_created_item(void) {
  return ber_last_created_item;
}


static GHashTable *oid_table=NULL;

void
dissect_ber_oid_NULL_callback(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return;
}

void
register_ber_oid_dissector(char *oid, dissector_t dissector, int proto, char *name)
{
	dissector_handle_t dissector_handle;

	dissector_handle=create_dissector_handle(dissector, proto);
	dissector_add_string("ber.oid", oid, dissector_handle);
	g_hash_table_insert(oid_table, oid, name);
}

int
call_ber_oid_callback(char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_length_remaining(tvb, offset));
	if(!dissector_try_string(ber_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: Dissector for OID:%s not implemented. Contact Ethereal developers if you want this supported", oid);
	}

	return offset;
}


static int dissect_ber_sq_of(gboolean implicit_tag, guint32 type, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence *seq, gint hf_id, gint ett_id);

/* 8.1 General rules for encoding */

/*  8.1.2 Identifier octets */
int get_ber_identifier(tvbuff_t *tvb, int offset, guint8 *class, gboolean *pc, guint32 *tag) {
	guint8 id, t;
	guint8 tmp_class;
	gboolean tmp_pc;
	guint32 tmp_tag;

	id = tvb_get_guint8(tvb, offset);
	offset += 1;
	
	/* 8.1.2.2 */
	tmp_class = (id>>6) & 0x03;
	tmp_pc = (id>>5) & 0x01;
	tmp_tag = id&0x1F;
	/* 8.1.2.4 */
	if (tmp_tag == 0x1F) {
		tmp_tag = 0;
		while (tvb_length_remaining(tvb, offset) > 0) {
			t = tvb_get_guint8(tvb, offset);
			offset += 1;
			tmp_tag <<= 7;       
			tmp_tag |= t & 0x7F;
			if (t & 0x80) break;
		}
	}

	if (class)
		*class = tmp_class;
	if (pc)
		*pc = tmp_pc;
	if (tag)
		*tag = tmp_tag;

	return offset;
}

int dissect_ber_identifier(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 *class, gboolean *pc, guint32 *tag) 
{
	int old_offset = offset;
	guint8 tmp_class;
	gboolean tmp_pc;
	guint32 tmp_tag;

	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
	
	if(show_internal_ber_fields){
		proto_tree_add_uint(tree, hf_ber_id_class, tvb, old_offset, 1, tmp_class<<6);
		proto_tree_add_boolean(tree, hf_ber_id_pc, tvb, old_offset, 1, (tmp_pc)?0x20:0x00);
		if(tmp_class==BER_CLASS_UNI){
			proto_tree_add_uint(tree, hf_ber_id_uni_tag, tvb, old_offset, offset - old_offset, tmp_tag);
		} else {
			proto_tree_add_uint(tree, hf_ber_id_tag, tvb, old_offset, offset - old_offset, tmp_tag);
		}
	}

	if (class)
		*class = tmp_class;
	if (pc)
		*pc = tmp_pc;
	if (tag)
		*tag = tmp_tag;

	return offset;
}

/* this function gets the length octets of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
/* 8.1.3 Length octets */
int
get_ber_length(tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind) {
	guint8 oct, len;
	guint32 tmp_length;
	gboolean tmp_ind;

	tmp_length = 0;
	tmp_ind = FALSE;

	oct = tvb_get_guint8(tvb, offset);
	offset += 1;
	
	if (!(oct&0x80)) {
		/* 8.1.3.4 */
		tmp_length = oct;
	} else {
		len = oct & 0x7F;
		if (len) {
			/* 8.1.3.5 */
			while (len--) {
				oct = tvb_get_guint8(tvb, offset);
				offset++;
				tmp_length = (tmp_length<<8) + oct;
			}
		} else {
			/* 8.1.3.6 */
			tmp_ind = TRUE;
			/* TO DO */
		}
	}

	if (length)
		*length = tmp_length;
	if (ind)
		*ind = tmp_ind;

	return offset;
}

/* this function dissects the length octets of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
int
dissect_ber_length(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind)
{
	int old_offset = offset;
	guint32 tmp_length;
	gboolean tmp_ind;

	offset = get_ber_length(tvb, offset, &tmp_length, &tmp_ind);
	
	if(show_internal_ber_fields){
		if(tmp_ind){
			proto_tree_add_text(tree, tvb, old_offset, 1, "Length: Indefinite length");
		} else {
			proto_tree_add_uint(tree, hf_ber_length, tvb, old_offset, offset - old_offset, tmp_length);
		}
	}
	if (length)
		*length = tmp_length;
	if (ind)
		*ind = tmp_ind;
	return offset;
}

/* 8.7 Encoding of an octetstring value */
int 
dissect_ber_octet_string(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb) {
	guint8 class;
	gboolean pc, ind;
	guint32 tag;
	guint32 len;
	int end_offset;
	proto_item *it;

	/* read header and len for the octet string */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
	end_offset=offset+len;

	/* sanity check: we only handle Constructed Universal Sequences */
	if (!implicit_tag) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
	    	    proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
			return end_offset;
		}
	}

	ber_last_created_item = NULL;
	if (pc) {
		/* constructed */
		/* TO DO */
	} else {
		/* primitive */
		if (hf_id != -1) {
			it = proto_tree_add_item(tree, hf_id, tvb, offset, len, FALSE);
			ber_last_created_item = it;
		}
		if (out_tvb) {
			*out_tvb = tvb_new_subset(tvb, offset, len, len);
		}
	}
	return end_offset;
}

int dissect_ber_octet_string_wcb(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func)
{
	tvbuff_t *out_tvb;

	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_id, (func)?&out_tvb:NULL);
	if (func && (tvb_length(out_tvb)>0)) {
		if (hf_id != -1)
			tree = proto_item_add_subtree(ber_last_created_item, ett_ber_octet_string);
		func(pinfo, tree, out_tvb, 0);
	}
	return offset;
}


int
dissect_ber_integer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	gint32 val;
	gint64 val64;
	guint32 i;

	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);

/*	if(class!=BER_CLASS_UNI)*/

	/* ok,  we cant handle >4 byte integers so lets fake them */
	if(len>8){
		header_field_info *hfinfo;
		proto_item *pi;

		hfinfo = proto_registrar_get_nth(hf_id);
		pi=proto_tree_add_text(tree, tvb, offset, len, "%s : 0x", hfinfo->name);
		if(pi){
			for(i=0;i<len;i++){
				proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
				offset++;
			}
		}
		return offset;
	}
	if(len>4){
		header_field_info *hfinfo;

		val64=0;
		if (len > 0) {
			/* extend sign bit */
			val64 = (gint8)tvb_get_guint8(tvb, offset);
			offset++;
		}
		for(i=1;i<len;i++){
			val64=(val64<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
		hfinfo = proto_registrar_get_nth(hf_id);
		proto_tree_add_text(tree, tvb, offset-len, len, "%s: %" PRIu64, hfinfo->name, val64);
		return offset;
	}
	
	val=0;
	if (len > 0) {
		/* extend sign bit */
		val = (gint8)tvb_get_guint8(tvb, offset);
		offset++;
	}
	for(i=1;i<len;i++){
		val=(val<<8)|tvb_get_guint8(tvb, offset);
		offset++;
	}

	ber_last_created_item=NULL;

	if(hf_id!=-1){	
		/* XXX - what if "len" is not 1, 2, 3, or 4? */
		ber_last_created_item=proto_tree_add_item(tree, hf_id, tvb, offset-len, len, FALSE);
	}
	if(value){
		*value=val;
	}

	return offset;
}





int
dissect_ber_boolean(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	guint8 val;
	header_field_info *hfi;

	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);

/*	if(class!=BER_CLASS_UNI)*/
	
	val=tvb_get_guint8(tvb, offset);
	offset+=1;

	ber_last_created_item=NULL;

	if(hf_id!=-1){
		hfi = proto_registrar_get_nth(hf_id);
		if (hfi->type == FT_BOOLEAN)
			ber_last_created_item=proto_tree_add_boolean(tree, hf_id, tvb, offset-1, 1, val);
		else
			ber_last_created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-1, 1, val?1:0);
	}

	return offset;
}





/* this function dissects a BER sequence 
 */
int dissect_ber_sequence(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence *seq, gint hf_id, gint ett_id) {
	guint8 class;
	gboolean pc, ind, ind_field;
	guint32 tag;
	guint32 len;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	int end_offset;
	tvbuff_t *next_tvb;

	/* first we must read the sequence header */
	offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
	if(ind){
	  /* if the length is indefinite we dont really know (yet) where the
	   * object ends so assume it spans the rest of the tvb for now.
           */
	  end_offset = tvb_length(tvb);
	} else {
	  end_offset = offset + len;
	}

	/* sanity check: we only handle Constructed Universal Sequences */
	if ((!pc)
		||(!implicit_tag&&((class!=BER_CLASS_UNI)
							||(tag!=BER_UNI_TAG_SEQUENCE)))) {
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}

	/* create subtree */
	if (hf_id != -1) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		guint8 class;
		gboolean pc;
		guint32 tag;
		guint32 len;
		int hoffset, eoffset, count;

		if(ind){ /* this sequence was of indefinite length, so check for EOC */
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, offset, 2, "EOC");
				}
				return offset+2;
			}
		}
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;

ber_sequence_try_again:
		/* have we run out of known entries in the sequence ?*/
		if (!seq->func) {
			/* it was not,  move to the enxt one and try again */
			proto_tree_add_text(tree, tvb, offset, len, "BER Error: This field lies beyond the end of the known sequence definition.");
			offset = eoffset;
			continue;
		}

		/* Verify that this one is the one we want.
		 * Skip check completely if class==ANY
		 */
		if( (seq->class!=BER_CLASS_ANY) 
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the enxt one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_sequence_try_again;
			}
			if (!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SEQUENCE");
				seq++;
				offset=eoffset;
				continue;
			}
		}

		if (!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
		}
		
		/* call the dissector for this field */
		if(ind_field){
			/* creating a subtvb for indefinite length,  just
			 * give it all of the tvb and hope for the best.
			 */
			next_tvb = tvb_new_subset(tvb, hoffset, tvb_length_remaining(tvb,hoffset), tvb_length_remaining(tvb,hoffset));
		} else {
			next_tvb = tvb_new_subset(tvb, hoffset, eoffset-hoffset, eoffset-hoffset);
		}

		count=seq->func(pinfo, tree, next_tvb, 0);
		if(ind_field){
			/* previous field was of indefinite length so we have
			 * no choice but use whatever the subdissector told us
			 * as size for the field.
			 */
			seq++;
			offset = hoffset+count;
		} else {
			seq++;
			offset = eoffset;
		}
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if (offset != end_offset) {
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence ate %d too many bytes", offset-end_offset);
	}

	return end_offset;
}



/* this function dissects a BER choice 
 */
int
dissect_ber_choice(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice *choice, gint hf_id, gint ett_id)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	const ber_choice *ch;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset;
	int hoffset = offset;
	header_field_info	*hfinfo;

	/* read header and len for choice field */
	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, NULL);
	end_offset=offset+len;

	/* Some sanity checks.  
	 * The hf field passed to us MUST be an integer type 
	 */
	if(hf_id!=-1){
		hfinfo=proto_registrar_get_nth(hf_id);
		switch(hfinfo->type) {
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				break;
		default:
			proto_tree_add_text(tree, tvb, offset, len,"dissect_ber_choice(): Was passed a HF field that was not integer type : %s",hfinfo->abbrev);
			fprintf(stderr,"dissect_ber_choice(): frame:%d offset:%d Was passed a HF field that was not integer type : %s\n",pinfo->fd->num,offset,hfinfo->abbrev);
			return end_offset;
		}
	}

	

	/* loop over all entries until we find the right choice or 
	   run out of entries */
	ch = choice;
	while(ch->func){
		if( (ch->class==class)
		  &&(ch->tag==tag) ){
			if (!(ch->flags & BER_FLAGS_NOOWNTAG) && !(ch->flags & BER_FLAGS_IMPLTAG)) {
				/* dissect header and len for field */
				hoffset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
			}
			/* create subtree */
			if(hf_id!=-1){
				if(parent_tree){
					item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
					tree = proto_item_add_subtree(item, ett_id);
				}
			}
			offset=ch->func(pinfo, tree, tvb, hoffset);
			return end_offset;
			break;
		}
		ch++;
	}
	/* oops no more entries and we still havent found
	 * our guy :-(
	 */
	proto_tree_add_text(tree, tvb, offset, len, "BER Error: This choice field was not found.");

	return end_offset;
}

#if 0
/* this function dissects a BER GeneralString
 */
int
dissect_ber_GeneralString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, int name_len)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	int end_offset;
	char str_arr[256];
	guint32 max_len;
	char *str;

	str=str_arr;
	max_len=255;
	if(name_string){
		str=name_string;
		max_len=name_len;
	}

	/* first we must read the GeneralString header */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	end_offset=offset+len;

	/* sanity check: we only handle Universal GeneralString*/
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GENSTR) ){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: GeneralString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}

	if(len>=(max_len-1)){
		len=max_len-1;
	}
	
	tvb_memcpy(tvb, str, offset, len);
	str[len]=0;

	if(hf_id!=-1){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	return end_offset;
}
#endif
int
dissect_ber_restricted_string(gboolean implicit_tag, guint32 type, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb) {
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	int eoffset;
	int hoffset = offset;

	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset = get_ber_length(tvb, offset, &len, NULL);
	eoffset = offset + len;

	/* sanity check */
	if (!implicit_tag) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag != type) ){
	    	    proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: String with tag=%d expected but Class:%d PC:%d Tag:%d was unexpected", type, class, pc, tag);
			return eoffset;
		}
	}

	/* 8.21.3 */
	return dissect_ber_octet_string(TRUE, pinfo, tree, tvb, hoffset, hf_id, out_tvb);
}

int
dissect_ber_GeneralString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, guint name_len)
{
	tvbuff_t *out_tvb;

	offset = dissect_ber_restricted_string(FALSE, BER_UNI_TAG_GeneralString, pinfo, tree, tvb, offset, hf_id, (name_string)?&out_tvb:NULL);

	if (name_string) {
		if (tvb_length(out_tvb) >= name_len) {
			tvb_memcpy(out_tvb, name_string, 0, name_len-1);
			name_string[name_len-1] = '\0';
		} else {
			tvb_memcpy(out_tvb, name_string, 0, -1);
			name_string[tvb_length(out_tvb)] = '\0';
		}
	}

	return offset;
}

/* 8.19 Encoding of an object identifier value */
int dissect_ber_object_identifier(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *value_string) {
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 i, len;
	int eoffset;
	guint8 byte;
	guint32 value;
	char str[256],*strp, *name;
	proto_item *item;

	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	eoffset = offset + len;

	if (value_string) {
		value_string[0] = '\0';
	}

	/* sanity check */
	if (!implicit_tag) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag != BER_UNI_TAG_OID) ){
	    	    proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Object Identifier expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
			return eoffset;
		}
	}

	value=0;
	for (i=0,strp=str; i<len; i++){
		byte = tvb_get_guint8(tvb, offset);
		offset++;

		if((strp-str)>200){
    	    proto_tree_add_text(tree, tvb, offset, eoffset - offset, "BER Error: too long Object Identifier");
			return offset;
		}

		/* 8.19.4 */
		if (i == 0) {
			strp += sprintf(strp, "%d.%d", byte/40, byte%40);
			continue;
		}

		value = (value << 7) | (byte & 0x7F);
		if (byte & 0x80) {
			continue;
		}

		strp += sprintf(strp, ".%d", value);
		value = 0;
	}
	*strp = '\0';

	if (hf_id != -1) {
		item=proto_tree_add_string(tree, hf_id, tvb, offset - len, len, str);
		/* see if we know the name of this oid */
		if(item){
			name=g_hash_table_lookup(oid_table, str);
			if(name){
				proto_item_append_text(item, " (%s)", name);
			}
		}
	}

	if (value_string) {
		strcpy(value_string, str);
	}

	return eoffset;
}

static int dissect_ber_sq_of(gboolean implicit_tag, guint32 type, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence *seq, gint hf_id, gint ett_id) {
	guint8 class;
	gboolean pc, ind;
	guint32 tag;
	guint32 len;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	int cnt, hoffset, end_offset;
	header_field_info *hfi;

	/* first we must read the sequence header */
	offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
	end_offset = offset + len;

	/* sanity check: we only handle Constructed Universal Sequences */
	if (!pc
		||(!implicit_tag&&((class!=BER_CLASS_UNI)
							||(tag!=type)))) {
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: %s Of expected but Class:%d PC:%d Tag:%d was unexpected", 
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", class, pc, tag);
		return end_offset;
	}

	/* count number of items */
	cnt = 0;
	hoffset = offset;
	while (offset < end_offset){
		guint32 len;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
		offset = get_ber_length(tvb, offset, &len, NULL);
		offset += len;
		cnt++;
	}
	offset = hoffset;

	/* create subtree */
	if (hf_id != -1) {
		hfi = proto_registrar_get_nth(hf_id);
		if(parent_tree){
			if (hfi->type == FT_NONE) {
				item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
				proto_item_append_text(item, ":");
			} else {
				item = proto_tree_add_uint(parent_tree, hf_id, tvb, offset, len, cnt);
				proto_item_append_text(item, (cnt==1)?" item":" items");
			}
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		guint8 class;
		gboolean pc;
		guint32 tag;
		guint32 len;
		int eoffset;
		int hoffset;

		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, NULL);
		eoffset = offset + len;

		/* verify that this one is the one we want */
		if ((seq->class!=class)
			||(seq->tag!=tag) ){
			if (!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SQ OF");
				offset = eoffset;
				continue;
			}
		}

		if (!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
		}
		
		/* call the dissector for this field */
		seq->func(pinfo, tree, tvb, hoffset);
		cnt++;
		offset = eoffset;
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if (offset != end_offset) {
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: %s Of ate %d too many bytes", 
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", offset-end_offset);
	}

	return end_offset;
}

int dissect_ber_sequence_of(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, pinfo, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int dissect_ber_set_of(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SET, pinfo, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int 
dissect_ber_generalized_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	char str[32];
	const guint8 *tmpstr;
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	int end_offset;

	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	end_offset=offset+len;

	/* sanity check. we only handle universal/generalized time */
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GeneralizedTime)){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: GeneralizedTime expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
		end_offset=offset+len;
	}

	tmpstr=tvb_get_ptr(tvb, offset, len);
	snprintf(str, 31, "%.4s-%.2s-%.2s %.2s:%.2s:%.2s (%.1s)",
		tmpstr, tmpstr+4, tmpstr+6, tmpstr+8,
		tmpstr+10, tmpstr+12, tmpstr+14);
	str[31]=0; /* just in case ... */
		
	if(hf_id!=-1){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	offset+=len;
	return offset;
}

/* 8.6 Encoding of a bitstring value */
int dissect_ber_bitstring(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb) 
{
	guint8 class;
	gboolean pc, ind;
	guint32 tag;
	guint32 len;
	guint8 pad=0, b0, b1, val;
	int end_offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	const asn_namedbit *nb;
	char *sep;
	gboolean term;

	/* read header and len for the octet string */
	offset = dissect_ber_identifier(pinfo, parent_tree, tvb, offset, &class, &pc, &tag);
	offset = dissect_ber_length(pinfo, parent_tree, tvb, offset, &len, &ind);
	end_offset = offset + len;

	/* sanity check: we only handle Universal BitSrings */
	if (!implicit_tag) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag!=BER_UNI_TAG_BITSTRING) ){
	    	    proto_tree_add_text(parent_tree, tvb, offset-2, 2, "BER Error: BitString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
			return end_offset;
		}
	}

	ber_last_created_item = NULL;

	if (pc) {
		/* constructed */
		/* TO DO */
	} else {
		/* primitive */
		/* padding */
		pad = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(parent_tree, hf_ber_bitstring_padding, tvb, offset, 1, FALSE);
		offset++;
		len--;
		if ( hf_id != -1) {
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			ber_last_created_item = item;
			if (ett_id != -1) {
				tree = proto_item_add_subtree(item, ett_id);
			}
		}
		if (out_tvb) {
			*out_tvb = tvb_new_subset(tvb, offset, len, 8*len-pad);
		}
	}

	if (named_bits) {
		sep = " (";
		term = FALSE;
		nb = named_bits;
		while (nb->p_id) {
			if (nb->bit < (8*len-pad)) {
				val = tvb_get_guint8(tvb, offset + nb->bit/8);
				val &= 0x80 >> (nb->bit%8);
				b0 = (nb->gb0 == -1) ? nb->bit/8 :
						       ((guint32)nb->gb0)/8;
				b1 = (nb->gb1 == -1) ? nb->bit/8 :
						       ((guint32)nb->gb1)/8;
				proto_tree_add_item(tree, *(nb->p_id), tvb, offset + b0, b1 - b0 + 1, FALSE);
			} else {  /* 8.6.2.4 */
				val = 0;
				proto_tree_add_boolean(tree, *(nb->p_id), tvb, offset + len, 0, 0x00);
			}
			if (val) {
				if (item && nb->tstr)
					proto_item_append_text(item, "%s%s", sep, nb->tstr);
			} else {
				if (item && nb->fstr)
					proto_item_append_text(item, "%s%s", sep, nb->fstr);
			}
			nb++;
			sep = ", ";
			term = TRUE;
		}
		if (term)
			proto_item_append_text(item, ")");
	}

	return end_offset;
}

int dissect_ber_bitstring32(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int **bit_fields, gint hf_id, gint ett_id, tvbuff_t **out_tvb) 
{
	tvbuff_t *tmp_tvb;
	proto_tree *tree;
	guint32 val;
	int **bf;
	header_field_info *hfi;
	char *sep;
	gboolean term;
	unsigned int i, tvb_len;

	offset = dissect_ber_bitstring(implicit_tag, pinfo, parent_tree, tvb, offset, NULL, hf_id, ett_id, &tmp_tvb);
	
	tree = proto_item_get_subtree(ber_last_created_item);
	if (bit_fields && tree) {
		/* tmp_tvb points to the actual bitstring (including any pad bits at the end.
		 * note that this bitstring is not neccessarily always encoded as 4 bytes
		 * so we have to read it byte by byte.
		 */
		val=0;
		tvb_len=tvb_length(tmp_tvb);
		for(i=0;i<4;i++){
			val<<=8;
			if(i<tvb_len){
				val|=tvb_get_guint8(tmp_tvb,i);
			}
		}
		bf = bit_fields;
		sep = " (";
		term = FALSE;
		while (*bf) {
			proto_tree_add_boolean(tree, **bf, tmp_tvb, 0, tvb_len, val);
			hfi = proto_registrar_get_nth(**bf);
			if (val & hfi->bitmask) {
				proto_item_append_text(ber_last_created_item, "%s%s", sep, hfi->name);
				sep = ", ";
				term = TRUE;
			}
			bf++;
		}
		if (term)
			proto_item_append_text(ber_last_created_item, ")");
	}

	if (out_tvb)
		*out_tvb = tmp_tvb;

	return offset;
}

void
proto_register_ber(void)
{
    static hf_register_info hf[] = {
	{ &hf_ber_id_class, {
	    "Class", "ber.id.class", FT_UINT8, BASE_DEC,
	    VALS(ber_class_codes), 0xc0, "Class of BER TLV Identifier", HFILL }},
	{ &hf_ber_bitstring_padding, {
	    "Padding", "ber.bitstring.padding", FT_UINT8, BASE_DEC,
	    NULL, 0x0, "Number of unsused bits in the last octet of the bitstring", HFILL }},
	{ &hf_ber_id_pc, {
	    "P/C", "ber.id.pc", FT_BOOLEAN, 8,
	    TFS(&ber_pc_codes), 0x20, "Primitive or Constructed BER encoding", HFILL }},
	{ &hf_ber_id_uni_tag, {
	    "Tag", "ber.id.uni_tag", FT_UINT8, BASE_DEC,
	    VALS(ber_uni_tag_codes), 0x1f, "Universal tag type", HFILL }},
	{ &hf_ber_id_tag, {
	    "Tag", "ber.id.tag", FT_UINT32, BASE_DEC,
	    NULL, 0, "Tag value for non-Universal classes", HFILL }},
	{ &hf_ber_length, {
	    "Length", "ber.length", FT_UINT32, BASE_DEC,
	    NULL, 0, "Length of contents", HFILL }},

    };

    static gint *ett[] = {
	&ett_ber_octet_string,
    };
    module_t *ber_module;

    proto_ber = proto_register_protocol("Basic Encoding Rules (ASN.1 X.690)", "BER", "ber");
    proto_register_field_array(proto_ber, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	proto_set_cant_toggle(proto_ber);

    /* Register preferences */
    ber_module = prefs_register_protocol(proto_ber, NULL);
    prefs_register_bool_preference(ber_module, "show_internals",
	"Show internal BER encapsulation tokens",
	"Whether the dissector should also display internal"
	" ASN.1 BER details such as Identifier and Length fields", &show_internal_ber_fields);

    ber_oid_dissector_table = register_dissector_table("ber.oid", "BER OID Dissectors", FT_STRING, BASE_NONE);
    oid_table=g_hash_table_new(g_str_hash, g_str_equal);
}

void
proto_reg_handoff_ber(void)
{
}
