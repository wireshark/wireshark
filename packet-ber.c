/* packet-ber.c
 * Helpers for ASN.1/BER dissection
 * Ronnie Sahlberg (C) 2004
 *
 * $Id: packet-ber.c,v 1.2 2004/02/26 12:02:45 sahlberg Exp $
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>

#include <epan/strutil.h>
#include "prefs.h"
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
	{ BER_UNI_TAG_BOOLEAN,		"Boolean" },
	{ BER_UNI_TAG_INTEGER,		"Integer" },
	{ BER_UNI_TAG_BITSTRING,	"Bit-String" },
	{ BER_UNI_TAG_OCTETSTRING,	"Octet String" },
	{ BER_UNI_TAG_SEQUENCE,		"Sequence" },
	{ BER_UNI_TAG_GENTIME,		"Generalized Time" },
	{ BER_UNI_TAG_GENSTR,		"General String" },
	{ 0, NULL }
};


/* this function dissects the identifier octer of the BER TLV.
 * We only handle TAGs (and LENGTHs) that fit inside 32 bit integers.
 */
int
dissect_ber_identifier(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 *class, gboolean *pc, guint32 *tag)
{
	guint8 id;
	int old_offset=offset;

	id=tvb_get_guint8(tvb, offset);
	offset+=1;
	
	*class=(id>>6)&0x03;
	*pc=(id>>5)&0x01;
	*tag=id&0x1f;
/*XXX handle case when TAG==0x1f */

	if(show_internal_ber_fields){
		proto_tree_add_uint(tree, hf_ber_id_class, tvb, old_offset, 1, id);
		proto_tree_add_boolean(tree, hf_ber_id_pc, tvb, old_offset, 1, id);
		if(*class==BER_CLASS_UNI){
			proto_tree_add_uint(tree, hf_ber_id_uni_tag, tvb, old_offset, 1, *tag);
		} else {
			proto_tree_add_uint(tree, hf_ber_id_tag, tvb, old_offset, 1, *tag);
		}

	}

	return offset;
}

/* this function dissects the identifier octer of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
int
dissect_ber_length(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length)
{
	guint8 id;
	int old_offset=offset;

	*length=0;

	id=tvb_get_guint8(tvb, offset);
	offset+=1;
	
	if(!(id&0x80)){
		*length=id;
		if(show_internal_ber_fields){
			proto_tree_add_uint(tree, hf_ber_length, tvb, old_offset, 1, *length);
		}
		return offset;
	}

	/* length byte has bit 8 set ! */
	id&=0x7f;
	while(id--){
		guint tmpl;
		tmpl=tvb_get_guint8(tvb, offset);
		offset++;
		*length=((*length)<<8)+tmpl;
	}
	if(show_internal_ber_fields){
/*XXX show the len byte */
		proto_tree_add_uint(tree, hf_ber_length, tvb, old_offset+1, offset-old_offset+1, *length);
	}

	return offset;
}


/* func is NULL normally but
 * if the octet string contains an ber encode struct we provide func as the 
 * dissector for that struct
 */
int 
dissect_ber_octet_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	int end_offset;
	proto_item *it;

	/* read header and len for the octet string */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
	end_offset=offset+len;

	/* sanity check: we only handle Constructed Universal Sequences */
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}
	

	if(hf_id!=-1){
		it=proto_tree_add_item(tree, hf_id, tvb, offset, len, FALSE);
		tree=proto_item_add_subtree(it, ett_ber_octet_string);
	}
	if(func){
		tvbuff_t *next_tvb;
		next_tvb=tvb_new_subset(tvb, offset, len, len);
		func(pinfo, tree, next_tvb, 0);
	}
/*qqq*/

	return end_offset;
}


int
dissect_ber_integer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	guint32 val;
	guint32 i;

	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);

/*	if(class!=BER_CLASS_UNI)*/
	
	val=0;
	for(i=0;i<len;i++){
		val=(val<<8)|tvb_get_guint8(tvb, offset);
		offset++;
	}

	ber_last_created_item=NULL;

	if(hf_id!=-1){	
		ber_last_created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-len, len, val);
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

	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);

/*	if(class!=BER_CLASS_UNI)*/
	
	val=tvb_get_guint8(tvb, offset);
	offset+=1;

	ber_last_created_item=NULL;

	if(hf_id!=-1){	
		ber_last_created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-1, 1, val?1:0);
	}

	return offset;
}





/* this function dissects a BER sequence 
 */
int
dissect_ber_sequence(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, ber_sequence *seq, gint hf_id, gint ett_id)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset;

	/* first we must read the sequence header */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
	end_offset=offset+len;


	/* sanity check: we only handle Constructed Universal Sequences */
	if( (class!=BER_CLASS_UNI)
	  ||(!pc)
	  ||(tag!=BER_UNI_TAG_SEQUENCE) ){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}

	/* create subtree */
	if(hf_id!=-1){
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}


	/* loop over all entries until we reach the end of the sequence */
	while(offset<end_offset){
		guint8 class;
		gboolean pc;
		guint32 tag;
		guint32 len;
		int eoffset;

		/* read header and len for next field */
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
		eoffset=offset+len;

		
ber_sequence_try_again:
		/* have we run out of known entries in the sequence ?*/
		if(!seq->func){
			/* it was not,  move to the enxt one and try again */
		        proto_tree_add_text(tree, tvb, offset, len, "BER Error: This field lies beyond the end of the known sequence definition.");
			offset=eoffset;
			continue;
		}

		/* verify that this one is the one we want */
		if( (seq->class!=class)
		  ||(seq->tag!=tag) ){
			/* it was not,  move to the enxt one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_sequence_try_again;
			}
		        proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field");
			seq++;
			offset=eoffset;
			continue;
		}

		/* call the dissector for this field */
		seq->func(pinfo, tree, tvb, offset);


		seq++;
		offset=eoffset;
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset!=end_offset){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence ate %d too many bytes", offset-end_offset);
	}

	return end_offset;
}



/* this function dissects a BER choice 
 */
int
dissect_ber_choice(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice *ch, gint hf_id, gint ett_id)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset;

	/* first we must read the sequence header */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
	end_offset=offset+len;


	/* create subtree */
	if(hf_id!=-1){
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}


	/* loop over all entries until we find the right choice or 
	   run out of entries */
	while(ch->func){
		if( (ch->class==class)
		  &&(ch->tag==tag) ){
			offset=ch->func(pinfo, tree, tvb, offset);
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
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
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

/* this function dissects a BER sequence of
 */
int
dissect_ber_sequence_of(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, ber_callback func, gint hf_id, gint ett_id)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset;

	/* first we must read the sequence header */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
	end_offset=offset+len;

	/* sanity check: we only handle Constructed Universal Sequences */
	if( (class!=BER_CLASS_UNI)
	  ||(!pc)
	  ||(tag!=BER_UNI_TAG_SEQUENCE) ){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: SequenceOf expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}

	/* create subtree */
	if(hf_id!=-1){
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* loop over all entries until we reach the end of the sequence */
	while(offset<end_offset){
		/* call the dissector for this field */
		offset=func(pinfo, tree, tvb, offset);
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset!=end_offset){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: SequenceOf ate %d too many bytes", offset-end_offset);
	}

	return end_offset;
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
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
	end_offset=offset+len;

	/* sanity check. we only handle universal/generalized time */
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GENTIME)){
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



/* this function dissects a BER BIT-STRING
 */
int
dissect_ber_bitstring(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint hf_id, gint ett_id, unsigned char *bitstring, int bitstring_len, proto_item **it, proto_tree **tr)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset;
	guint8 pad;
	gboolean first_time=TRUE;

	/* first we must read the sequence header */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);
	end_offset=offset+len;

	/* sanity check: we only handle Universal BitSrings */
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_BITSTRING) ){
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: BitString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}


	/* create subtree */
	if(hf_id!=-1){
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	if(tr){
		*tr=tree;
	}
	if(it){
		*it=item;
	}

	/* padding */
	pad=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_ber_bitstring_padding, tvb, offset, 1, FALSE);
	offset+=1;
	len--;


	/* XXX we should handle segmented bitstrings */

	while(len--){
		guint8 tmp;

		tmp=tvb_get_guint8(tvb, offset);
		offset++;

		if(item){
			if(first_time){
				proto_item_append_text(item, " 0x");
			}
			proto_item_append_text(item, "%02x",tmp);
			first_time=FALSE;
		}

		if(bitstring){
			*(bitstring++)=tmp;
			if(--bitstring_len<=0){
				bitstring=NULL;
			}
		}
	}

	return end_offset;
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

    proto_ber = proto_register_protocol("ASN.1 BER", "BER", "ber");
    proto_register_field_array(proto_ber, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    ber_module = prefs_register_protocol(proto_ber, NULL);
    prefs_register_bool_preference(ber_module, "show_internals",
	"Show internal BER encapsulation tokens",
	"Whether the dissector should also display internal"
	" ASN.1 BER details such as Identifier and Length fields", &show_internal_ber_fields);
}

void
proto_reg_handoff_ber(void)
{
}
