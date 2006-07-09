/*#define DEBUG_BER 1 */
/* TODO: change #.REGISTER signature to new_dissector_t and
 * update call_ber_oid_callback() accordingly.
 *
 * Since we don't pass the TAG/LENGTH from the CHOICE/SEQUENCE/SEQUENCE OF/
 * SET OF helpers through the callbacks to the next pabket-ber helper
 * when the tags are IMPLICIT, this causes a problem when we also have
 * indefinite length at the same time as the tags are implicit.
 *
 * While the proper fix is to change the signatures for packet-ber.c helpers
 * as well as the signatures for the callbacks to include the indefinite length
 * indication that would be a major job.
 *
 * Originally we used a kludge - we set a global variable in the
 * CHOICE/SEQUENCE [OF]/SET [OF] helpers to indicate to the next helper
 * whether the length is indefinite or not.
 * That had currently only been implemented for {SEQUENCE|SET} [OF] but not
 * CHOICE.
 *
 * This version attacks the problem(s) in a different way.  If we see
 * indefinite length the get_ber_length traverses the tags within the
 * compound value and then we return the true length of the compound value
 * including the EOC. Thus the tvb length is now always correct even for
 * indefinite length, then if we get implicit tags they can be handled as
 * if they were definite length.
 */

/* packet-ber.c
 * Helpers for ASN.1/BER dissection
 * Ronnie Sahlberg (C) 2004
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
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/emem.h>
#include <epan/oid_resolv.h>
#include "packet-ber.h"

static gint proto_ber = -1;
static gint hf_ber_id_class = -1;
static gint hf_ber_id_pc = -1;
static gint hf_ber_id_uni_tag = -1;
static gint hf_ber_id_uni_tag_ext = -1;
static gint hf_ber_id_tag = -1;
static gint hf_ber_id_tag_ext = -1;
static gint hf_ber_length = -1;
static gint hf_ber_bitstring_padding = -1;
static gint hf_ber_unknown_OID = -1;
static gint hf_ber_unknown_BOOLEAN = -1;
static gint hf_ber_unknown_OCTETSTRING = -1;
static gint hf_ber_unknown_GraphicString = -1;
static gint hf_ber_unknown_NumericString = -1;
static gint hf_ber_unknown_PrintableString = -1;
static gint hf_ber_unknown_TeletexString = -1;
static gint hf_ber_unknown_IA5String = -1;
static gint hf_ber_unknown_UTCTime = -1;
static gint hf_ber_unknown_UTF8String = -1;
static gint hf_ber_unknown_GeneralizedTime = -1;
static gint hf_ber_unknown_INTEGER = -1;
static gint hf_ber_unknown_BITSTRING = -1;
static gint hf_ber_unknown_ENUMERATED = -1;

static gint ett_ber_octet_string = -1;
static gint ett_ber_unknown = -1;
static gint ett_ber_SEQUENCE = -1;

static gboolean show_internal_ber_fields = FALSE;

proto_item *ber_last_created_item=NULL;

static dissector_table_t ber_oid_dissector_table=NULL;

static const value_string ber_class_codes[] = {
	{ BER_CLASS_UNI,	"UNIVERSAL" },
	{ BER_CLASS_APP,	"APPLICATION" },
	{ BER_CLASS_CON,	"CONTEXT" },
	{ BER_CLASS_PRI,	"PRIVATE" },
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
	{ BER_UNI_TAG_SEQUENCE		, "SEQUENCE" },
	{ BER_UNI_TAG_SET				, "SET" },
	{ BER_UNI_TAG_NumericString	, "NumericString" },
	{ BER_UNI_TAG_PrintableString	, "PrintableString" },
	{ BER_UNI_TAG_TeletexString	, "TeletexString, T61String" },
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
	{ 31				, "Continued" },
	{ 0, NULL }
};


proto_item *get_ber_last_created_item(void) {
  return ber_last_created_item;
}


void
dissect_ber_oid_NULL_callback(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return;
}


void
register_ber_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name)
{
	dissector_add_string("ber.oid", oid, dissector);
	add_oid_str_name(oid, name);
}

void
register_ber_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name)
{
	dissector_handle_t dissector_handle;

	dissector_handle=create_dissector_handle(dissector, proto);
	dissector_add_string("ber.oid", oid, dissector_handle);
	add_oid_str_name(oid, name);
}

int dissect_ber_tagged_type(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint8 tag_cls, gint32 tag_tag, gboolean tag_impl, ber_type_fn type)
{
 gint8 tmp_cls;
 gint32 tmp_tag;
 guint32 tmp_len;
 tvbuff_t *next_tvb = tvb;

 if (implicit_tag) {
	offset = type(tag_impl, tvb, offset, pinfo, tree, hf_id);
	return offset;
 }

 offset = get_ber_identifier(tvb, offset, &tmp_cls, NULL, &tmp_tag);
 offset = get_ber_length(tree, tvb, offset, &tmp_len, NULL);
 if ((tmp_cls != tag_cls) || (tmp_tag != tag_tag)) {
	proto_tree_add_text(tree, tvb, offset, tmp_len,
		"BER Error: Wrong tag in tagged type - expected class:%d (%s) tag:%d(%s) but found class:%d(%s) tag:%d",
		tag_cls, val_to_str(tag_cls, ber_class_codes, "Unknown"), tag_tag, val_to_str(tag_tag, ber_uni_tag_codes,"Unknown"),
		tmp_cls, val_to_str(tmp_cls, ber_class_codes,"Unknown"), tmp_tag);
 }

 if (tag_impl) {
	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tmp_len);
	type(tag_impl, next_tvb, 0, pinfo, tree, hf_id);
	offset += tmp_len;
 } else {
	offset = type(tag_impl, tvb, offset, pinfo, tree, hf_id);
 }

 return offset;
}

int dissect_unknown_ber(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree)
{
	int start_offset;
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	proto_item *item=NULL;
	proto_tree *next_tree=NULL;
	guint8 c;
	guint32 i;
	gboolean is_printable;
	proto_item *pi;

	start_offset=offset;

	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(NULL, tvb, offset, &len, &ind);

	if(len>(guint32)tvb_length_remaining(tvb, offset)){
		/* hmm   maybe something bad happened or the frame is short,
		   since these are not vital outputs just return instead of
		   throwing an exception.
		 */

		offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
		proto_tree_add_text(tree, tvb, offset, len, "BER: Error length:%u longer than tvb_length_ramaining:%d",len, tvb_length_remaining(tvb, offset));
		return tvb_length(tvb);
	}
/* we dont care about the class only on the constructor flag */
	switch(pc){

	case FALSE: /* this is not constructed */

	  switch(class) { /* we do care about the class */
	  case BER_CLASS_UNI: /* it a Universal tag - we can decode it */
		switch(tag){
		case BER_UNI_TAG_EOC:
		  /* XXX: shouldn't really get here */
		  break;
		case BER_UNI_TAG_INTEGER:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_INTEGER, NULL);
			break;
		case BER_UNI_TAG_BITSTRING:
			offset = dissect_ber_bitstring(FALSE, pinfo, tree, tvb, start_offset, NULL, hf_ber_unknown_BITSTRING, -1, NULL);
			break;
		case BER_UNI_TAG_ENUMERATED:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_ENUMERATED, NULL);
			break;
		case BER_UNI_TAG_GraphicString:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_GraphicString, NULL);
			break;
		case BER_UNI_TAG_OCTETSTRING:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_OCTETSTRING, NULL);
			break;
		case BER_UNI_TAG_OID:
			offset=dissect_ber_object_identifier_str(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_OID, NULL);
			break;
		case BER_UNI_TAG_NumericString:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_NumericString, NULL);
			break;
		case BER_UNI_TAG_PrintableString:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_PrintableString, NULL);
			break;
		case BER_UNI_TAG_TeletexString:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_TeletexString, NULL);
			break;
		case BER_UNI_TAG_IA5String:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_IA5String, NULL);
			break;
		case BER_UNI_TAG_UTCTime:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_UTCTime, NULL);
			break;
		case BER_UNI_TAG_NULL:
			proto_tree_add_text(tree, tvb, offset, len, "NULL tag");
			break;
		case BER_UNI_TAG_UTF8String:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_UTF8String, NULL);
			break;
		case BER_UNI_TAG_GeneralizedTime:
			offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_GeneralizedTime, NULL);
			break;
		case BER_UNI_TAG_BOOLEAN:
			offset = dissect_ber_boolean(FALSE, pinfo, tree, tvb, start_offset, hf_ber_unknown_BOOLEAN);
			break;
		default:
			offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
			offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
			proto_tree_add_text(tree, tvb, offset, len, "BER: Error can not handle universal tag:%d",tag);
			offset += len;
		}
		break;
	  case BER_CLASS_APP:
	  case BER_CLASS_CON:
	  case BER_CLASS_PRI:
	  default:
	    /* we can't dissect this directly as it is specific */
	    pi = proto_tree_add_text(tree, tvb, offset, len, "[%s %d] ", val_to_str(class,ber_class_codes,"Unknown"), tag);
	    /* we may want to do better and show the bytes */
	    is_printable = TRUE;
	    for(i=0;i<len;i++){
	      c = tvb_get_guint8(tvb, offset+i);

	      if(is_printable && !g_ascii_isprint(c))
			      is_printable=FALSE;

	      proto_item_append_text(pi,"%02x",c);
	    }

	    if(is_printable) { /* give a nicer representation if it looks like a string */
	      proto_item_append_text(pi," (");
	      for(i=0;i<len;i++){
		proto_item_append_text(pi,"%c",tvb_get_guint8(tvb, offset+i));
	      }
	      proto_item_append_text(pi,")");
	    }

	    offset += len;
	    break;
	  }
	  break;

	case TRUE: /* this is constructed */

	  switch(class) {
	  case BER_CLASS_UNI:
       	    item=proto_tree_add_text(tree, tvb, offset, len, "%s", val_to_str(tag,ber_uni_tag_codes,"Unknown"));
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_SEQUENCE);
		}
		while(offset < (int)(start_offset + len))
		  offset=dissect_unknown_ber(pinfo, tvb, offset, next_tree);
		break;
	  case BER_CLASS_APP:
	  case BER_CLASS_CON:
	  case BER_CLASS_PRI:
	  default:
       	    item=proto_tree_add_text(tree, tvb, offset, len, "[%s %d]", val_to_str(class,ber_class_codes,"Unknown"), tag);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_SEQUENCE);
		}
		while(offset < (int)(start_offset + len))
		  offset=dissect_unknown_ber(pinfo, tvb, offset, next_tree);
		break;

	  }
	  break;

	}

	return offset;
}


int
call_ber_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	if(oid == NULL ||
	    !dissector_try_string(ber_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;

		if (oid == NULL)
			item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: No OID supplied to call_ber_oid_callback");
		else
			item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_unknown);
		}
		dissect_unknown_ber(pinfo, next_tvb, 0, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


static int dissect_ber_sq_of(gboolean implicit_tag, gint32 type, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id);

/* 8.1 General rules for encoding */

/*  8.1.2 Identifier octets */
int get_ber_identifier(tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag) {
	guint8 id, t;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

	id = tvb_get_guint8(tvb, offset);
	offset += 1;
#ifdef DEBUG_BER
printf ("BER ID=%02x", id);
#endif
	/* 8.1.2.2 */
	tmp_class = (id>>6) & 0x03;
	tmp_pc = (id>>5) & 0x01;
	tmp_tag = id&0x1F;
	/* 8.1.2.4 */
	if (tmp_tag == 0x1F) {
		tmp_tag = 0;
		while (tvb_length_remaining(tvb, offset) > 0) {
			t = tvb_get_guint8(tvb, offset);
#ifdef DEBUG_BER
printf (" %02x", t);
#endif
			offset += 1;
			tmp_tag <<= 7;
			tmp_tag |= t & 0x7F;
			if (!(t & 0x80)) break;
		}
	}

#ifdef DEBUG_BER
printf ("\n");
#endif
	if (class)
		*class = tmp_class;
	if (pc)
		*pc = tmp_pc;
	if (tag)
		*tag = tmp_tag;

	return offset;
}

int dissect_ber_identifier(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag)
{
	int old_offset = offset;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	if(show_internal_ber_fields){
		proto_tree_add_uint(tree, hf_ber_id_class, tvb, old_offset, 1, tmp_class<<6);
		proto_tree_add_boolean(tree, hf_ber_id_pc, tvb, old_offset, 1, (tmp_pc)?0x20:0x00);
		if(tmp_tag==0x1F){
			proto_tree_add_uint(tree, hf_ber_id_uni_tag, tvb, old_offset, 1, tmp_tag);
			if(tmp_class==BER_CLASS_UNI){
				proto_tree_add_uint(tree, hf_ber_id_uni_tag_ext, tvb, old_offset + 1, offset - (old_offset + 1), tmp_tag);
			} else {
				proto_tree_add_uint(tree, hf_ber_id_tag_ext, tvb, old_offset + 1, offset - (old_offset + 1), tmp_tag);
			}
		} else {
			if(tmp_class==BER_CLASS_UNI){
				proto_tree_add_uint(tree, hf_ber_id_uni_tag, tvb, old_offset, 1, tmp_tag);
			} else {
				proto_tree_add_uint(tree, hf_ber_id_tag, tvb, old_offset, 1, tmp_tag);
			}
		}
	}

	if(class)
		*class = tmp_class;
	if(pc)
		*pc = tmp_pc;
	if(tag)
		*tag = tmp_tag;

	return offset;
}

/* this function gets the length octets of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
/* 8.1.3 Length octets */
int
get_ber_length(proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind) {
	guint8 oct, len;
	guint32 tmp_len;
	guint32 tmp_length;
	gboolean tmp_ind;
	int tmp_offset,s_offset;
	gint8 tclass;
	gboolean tpc;
	gint32 ttag;
	tmp_length = 0;
	tmp_ind = FALSE;

	oct = tvb_get_guint8(tvb, offset);
	offset += 1;

	if(!(oct&0x80)) {
		/* 8.1.3.4 */
		tmp_length = oct;
	} else {
		len = oct & 0x7F;
		if(len) {
			/* 8.1.3.5 */
			while (len--) {
				oct = tvb_get_guint8(tvb, offset);
				offset++;
				tmp_length = (tmp_length<<8) + oct;
			}
		} else {
			/* 8.1.3.6 */

			tmp_offset = offset;
			/* ok in here we can traverse the BER to find the length, this will fix most indefinite length issues */
			/* Assumption here is that indefinite length is always used on constructed types*/
			/* check for EOC */
			while ((tvb_reported_length_remaining(tvb,offset)>0) && ( tvb_get_guint8(tvb, offset) || tvb_get_guint8(tvb,offset+1)))
				{
				/* not an EOC at offset */
				s_offset=offset;
				offset= get_ber_identifier(tvb, offset, &tclass, &tpc, &ttag);
				offset= get_ber_length(tree,tvb,offset, &tmp_len, NULL);
				tmp_length += tmp_len+(offset-s_offset); /* length + tag and length */
				offset += tmp_len;
                                /* Make sure we've moved forward in the packet */
				if (offset <= s_offset)
					THROW(ReportedBoundsError);
				}
			tmp_length += 2;
			tmp_ind = TRUE;
			offset = tmp_offset;
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

	offset = get_ber_length(tree, tvb, offset, &tmp_length, &tmp_ind);

	if(show_internal_ber_fields){
		if(tmp_ind){
			proto_tree_add_text(tree, tvb, old_offset, 1, "Length: Indefinite length %d", tmp_length);
		} else {
			proto_tree_add_uint(tree, hf_ber_length, tvb, old_offset, offset - old_offset, tmp_length);
		}
	}
	if(length)
		*length = tmp_length;
	if(ind)
		*ind = tmp_ind;
	return offset;
}
static int
reassemble_octet_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 con_len, gboolean ind, tvbuff_t **out_tvb)
{
  static GHashTable *octet_segment_table = NULL;
  static GHashTable *octet_reassembled_table = NULL;
  fragment_data *fd_head = NULL;
  tvbuff_t *next_tvb = NULL;
  tvbuff_t *reassembled_tvb = NULL;
  guint16 dst_ref = 0;
  int start_offset = offset;
  gboolean fragment = TRUE;
  gboolean firstFragment = TRUE;

  if(octet_segment_table == NULL) {
    /* I assume I can take this late binding approach */
    fragment_table_init(&octet_segment_table);
    reassembled_table_init(&octet_reassembled_table);

  }

  /* so we need to consume octet strings for the given length */

  /* not sure we need this */
  pinfo->fragmented = TRUE;

  while(!fd_head) {

    offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_ber_unknown_OCTETSTRING, &next_tvb);

    if (next_tvb == NULL) {
      /* Assume that we have a malformed packet. */
      THROW(ReportedBoundsError);
    }

    if(ind) {
      /* this was indefinite length - so check for EOC */

      if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)) {
	fragment = FALSE;
	/* skip past EOC */
	offset +=2;
      }
    } else {

    if((guint32)(offset - start_offset) >= con_len)
	fragment = FALSE;
    }

    if(!fragment && firstFragment) {
      /* there is only one fragment (I'm sure there's a reason it was constructed) */
      /* anyway, we can get out of here */
      reassembled_tvb = next_tvb;
      break;
    }


    if (tvb_length(next_tvb) < 1) {
      /* Don't cause an assertion in the reassembly code. */
      THROW(ReportedBoundsError);
    }
    fd_head = fragment_add_seq_next(next_tvb, 0, pinfo, dst_ref,
				    octet_segment_table,
				    octet_reassembled_table,
				    tvb_length(next_tvb),
				    fragment);

    firstFragment = FALSE;
  }

  if(fd_head) {
    if(fd_head->next) {
      reassembled_tvb = tvb_new_real_data(fd_head->data,
					  fd_head->len,
					  fd_head->len);

      tvb_set_child_real_data_tvbuff(next_tvb, reassembled_tvb);

      /* not sure I really want to do this here - should be nearer the application where we can give it a better name*/
      add_new_data_source(pinfo, reassembled_tvb, "Reassembled OCTET STRING");

    }
  }

  if(out_tvb)
    *out_tvb = reassembled_tvb;

  /* again - not sure we need this */
  pinfo->fragmented = FALSE;

  return offset;

}

/* 8.7 Encoding of an octetstring value */
int
dissect_ber_octet_string(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb) {
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	int end_offset;
	proto_item *it;
  guint32 i;

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("OCTET STRING dissect_ber_octet string(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("OCTET STRING dissect_ber_octet_string(%s) entered\n",name);
}
}
#endif

	if (!implicit_tag) {
		/* read header and len for the octet string */
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
		end_offset=offset+len;

		/* sanity check: we only handle Constructed Universal Sequences */
		if ((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))

		if( (class!=BER_CLASS_UNI)
		  ||((tag<BER_UNI_TAG_NumericString)&&(tag!=BER_UNI_TAG_OCTETSTRING)&&(tag!=BER_UNI_TAG_UTF8String)) ){
		    tvb_ensure_bytes_exist(tvb, offset-2, 2);
	    	    proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
			if(out_tvb)
				*out_tvb=NULL;
			return end_offset;
		}
	} else {
		/* implicit tag so just trust the length of the tvb */
		pc=FALSE;
		len=tvb_length_remaining(tvb,offset);
		end_offset=offset+len;
	}

	ber_last_created_item = NULL;
	if (pc) {
		/* constructed */
		end_offset = reassemble_octet_string(pinfo, tree, tvb, offset, len, ind, out_tvb);
	} else {
		/* primitive */
		gint length_remaining;

		length_remaining = tvb_length_remaining(tvb, offset);
		if(length_remaining<1){
			if(out_tvb)
				*out_tvb=NULL;
			return end_offset;
		}

		if(len<=(guint32)length_remaining){
			length_remaining=len;
		}
		if(hf_id >= 0) {
			it = proto_tree_add_item(tree, hf_id, tvb, offset, length_remaining, FALSE);
			ber_last_created_item = it;
		} else {
			proto_item *pi;

			pi=proto_tree_add_text(tree, tvb, offset, len, "Unknown OctetString: Length: 0x%02x, Value: 0x", len);
			if(pi){
				for(i=0;i<len;i++){
					proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
					offset++;
				}
			}
		}

		if(out_tvb) {
			*out_tvb = tvb_new_subset(tvb, offset, length_remaining, len);
		}
	}
	return end_offset;
}

int dissect_ber_octet_string_wcb(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func)
{
	tvbuff_t *out_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_id, (func)?&out_tvb:NULL);
	if (func && out_tvb && (tvb_length(out_tvb)>0)) {
		if (hf_id >= 0)
			tree = proto_item_add_subtree(ber_last_created_item, ett_ber_octet_string);
		func(pinfo, tree, out_tvb, 0);
	}
	return offset;
}

/* 8.8 Encoding of a null value */
int
dissect_ber_null(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id) {
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 len;
  int offset_old;
if (!implicit_tag)
{
  offset_old = offset;
  offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
  if((pc) ||
      (!implicit_tag && ((class != BER_CLASS_UNI) || (tag != BER_UNI_TAG_NULL)))) {
    proto_tree_add_text(tree, tvb, offset_old, offset - offset_old, "BER Error: NULL expected but Class:%d(%s) PC:%d Tag:%d was unexpected", class,val_to_str(class,ber_class_codes,"Unknown"), pc, tag);
  }

  offset_old = offset;
  offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
  if(len) {
    proto_tree_add_text(tree, tvb, offset_old, offset - offset_old, "BER Error: NULL expect zero length but Length=%d", len);
    proto_tree_add_text(tree, tvb, offset, len, "BER Error: unexpected data in NULL type");
    offset += len;
  }
}
  if (hf_id >= 0)
	  proto_tree_add_item(tree, hf_id, tvb, offset, 0, FALSE);
  return offset;
}

int
dissect_ber_integer64(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint64 *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	gint64 val;
	guint32 i;

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("INTEGERnew dissect_ber_integer(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("INTEGERnew dissect_ber_integer(%s) entered implicit_tag:%d \n",name,implicit_tag);
}
}
#endif


	if(!implicit_tag){
	  offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	  offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	} else {
	  gint32 remaining=tvb_length_remaining(tvb, offset);
	  len=remaining>0 ? remaining : 0;
	}

	/* we cant handle integers > 64 bits */
	if(len>8){
		header_field_info *hfinfo;
		proto_item *pi = NULL;

		if (hf_id >= 0) {
			hfinfo = proto_registrar_get_nth(hf_id);
			pi=proto_tree_add_text(tree, tvb, offset, len, "%s : 0x", hfinfo->name);
		}
		if(pi){
			for(i=0;i<len;i++){
				proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
				offset++;
			}
		} else {
			offset += len;
		}
		return offset;
	}

	val=0;
	if(len > 0) {
		/* extend sign bit */
		if(tvb_get_guint8(tvb, offset)&0x80){
			val=-1;
		}
		for(i=0;i<len;i++){
			val=(val<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
	}

	ber_last_created_item=NULL;

	if(hf_id >= 0){
		/*  */
		if(len < 1 || len > 8) {
			proto_tree_add_text(tree, tvb, offset-len, len, "Can't handle integer length: %u", len);
		} else {
			header_field_info* hfi;

			hfi = proto_registrar_get_nth(hf_id);
			switch(hfi->type){
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				ber_last_created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-len, len, (guint32)val);
				break;
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				ber_last_created_item=proto_tree_add_int(tree, hf_id, tvb, offset-len, len, (gint32)val);
				break;
			case FT_INT64:
				ber_last_created_item=proto_tree_add_int64(tree, hf_id, tvb, offset-len, len, val);
				break;
			case FT_UINT64:
				ber_last_created_item=proto_tree_add_uint64(tree, hf_id, tvb, offset-len, len, (guint64)val);
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
			}
		}
	}
	if(value){
		*value=val;
	}

	return offset;
}

int
dissect_ber_integer(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, pinfo, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=(guint32)val;
	}

	return offset;
}


int
dissect_ber_boolean_value(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gboolean *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	guint8 val;
	header_field_info *hfi;

	if(!implicit_tag){
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
		/*if(class!=BER_CLASS_UNI)*/
	} else {
		/* nothing to do here, yet */
	}

	val=tvb_get_guint8(tvb, offset);
	offset+=1;

	ber_last_created_item=NULL;

	if(hf_id >= 0){
		hfi = proto_registrar_get_nth(hf_id);
		if(hfi->type == FT_BOOLEAN)
			ber_last_created_item=proto_tree_add_boolean(tree, hf_id, tvb, offset-1, 1, val);
		else
			ber_last_created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-1, 1, val?1:0);
	}

	if(value){
		*value=(val?TRUE:FALSE);
	}

	return offset;
}

int
dissect_ber_boolean(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	return dissect_ber_boolean_value(implicit_tag, pinfo, tree, tvb, offset, hf_id, NULL);
}




/* this function dissects a BER sequence
 */
int dissect_ber_sequence(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 class;
	gboolean pc, ind = 0, ind_field;
	gint32 tag;
	guint32 len;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	int end_offset, s_offset;
	gint length_remaining;
	tvbuff_t *next_tvb;

	s_offset = offset;
#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SEQUENCE dissect_ber_sequence(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SEQUENCE dissect_ber_sequence(%s) entered\n",name);
}
}
#endif
	if(!implicit_tag){
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
		if(ind){
		/*  Fixed the length is correctly returned from dissect ber_length
		  end_offset = tvb_length(tvb);*/
		  end_offset = offset + len -2;
		} else {
		  end_offset = offset + len;
		}

		/* sanity check: we only handle Constructed Universal Sequences */
		if((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))
		if((!pc)
		||(!implicit_tag&&((class!=BER_CLASS_UNI)
					||(tag!=BER_UNI_TAG_SEQUENCE)))) {
			tvb_ensure_bytes_exist(tvb, offset-2, 2);
			proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence expected but Class:%d(%s) PC:%d Tag:%d was unexpected", class,val_to_str(class,ber_class_codes,"Unknown"), pc, tag);
			return end_offset;
		}
	} else {
		/* was implicit tag so just use the length of the tvb */
		len=tvb_length_remaining(tvb,offset);
		end_offset=offset+len;
	}

	/* create subtree */
	if(hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int hoffset, eoffset, count;

		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
					but tcap dissector uses this to eat the tag length then pass into here... EOC still on there...*/
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "ERROR WRONG SEQ EOC");
				}
				return end_offset;
			}
		/*}*/
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tree, tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                /* Make sure we move forward */
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		if(ind_field && (len == 2)){
    			/* disgusting indefinite length zero length field, what are these people doing */
			offset = eoffset;
			continue;
		}

ber_sequence_try_again:
		/* have we run out of known entries in the sequence ?*/
		if(!seq->func) {
			/* it was not,  move to the next one and try again */
			offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
			proto_tree_add_text(tree, tvb, offset, len, "BER Error: This field lies beyond the end of the known sequence definition.");
			offset = eoffset;
			continue;
		}

		/* Verify that this one is the one we want.
		 * Skip check completely if class==ANY
		 * of if NOCHKTAG is set
		 */
/* XXX Bug in asn2eth,
 * for   scope            [7]  Scope OPTIONAL,
 * it generates
 *   { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
 * and there should not be a NOTCHKTAG here
 */
		if( ((seq->class==BER_CLASS_CON)||(seq->class==BER_CLASS_APP)||(seq->class==BER_CLASS_PRI)) && (!(seq->flags&BER_FLAGS_NOOWNTAG)) ){
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the next one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_sequence_try_again;
			}
			offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
				proto_tree_add_text(tree, tvb, offset, len,
				    "BER Error: Wrong field in SEQUENCE  expected class:%d (%s) tag:%d (%s) but found class:%d tag:%d",
				    seq->class,val_to_str(seq->class,ber_class_codes,"Unknown"),
				    seq->tag,val_to_str(seq->tag,ber_uni_tag_codes,"Unknown"),
				    class,tag);
			}else{
				proto_tree_add_text(tree, tvb, offset, len,
				    "BER Error: Wrong field in SEQUENCE  expected class:%d (%s) tag:%d but found class:%d tag:%d",
				    seq->class,val_to_str(seq->class,ber_class_codes,"Unknown"),
				    seq->tag,class,tag);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
	        } else if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the next one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_sequence_try_again;
			}

			offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
				proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in sequence  expected class:%d (%s) tag:%d(%s) but found class:%d(%s) tag:%d",seq->class,val_to_str(seq->class,ber_class_codes,"Unknown"),seq->tag,val_to_str(seq->tag,ber_uni_tag_codes,"Unknown"),class,val_to_str(class,ber_class_codes,"Unknown"),tag);
			}else{
				proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in sequence  expected class:%d (%s) tag:%d but found class:%d(%s) tag:%d",seq->class,val_to_str(seq->class,ber_class_codes,"Unknown"),seq->tag,class,val_to_str(class,ber_class_codes,"Unknown"),tag);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if (length_remaining>eoffset-hoffset-(2*ind_field))
				length_remaining=eoffset-hoffset-(2*ind_field);
			next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
		}
		else {
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if (length_remaining>eoffset-hoffset)
				length_remaining=eoffset-hoffset;
			next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
		}

		/* call the dissector for this field */
		/*if 	((eoffset-hoffset)>length_remaining) {*/
			/* If the field is indefinite (i.e. we dont know the
			 * length) of if the tvb is short, then just
			 * give it all of the tvb and hope for the best.
			 */
			/*next_tvb = tvb_new_subset(tvb, hoffset, -1, -1);*/
		/*} else {*/

		/*}*/

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SEQUENCE dissect_ber_sequence(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SEQUENCE dissect_ber_sequence(%s) calling subdissector\n",name);
}
}
#endif
		if (next_tvb == NULL) {
			/* Assume that we have a malformed packet. */
			THROW(ReportedBoundsError);
		}
		count=seq->func(pinfo, tree, next_tvb, 0);

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("SEQUENCE dissect_ber_sequence(%s) subdissector ate %d bytes\n",name,count);
}
#endif
		/* if it was optional and no bytes were eaten and it was */
		/* supposed to (len<>0), just try again. */
		if((len!=0)&&(count==0)&&(seq->flags&BER_FLAGS_OPTIONAL)){
			seq++;
			goto ber_sequence_try_again;
		/* move the offset to the beginning of the next sequenced item */
		}
		offset = eoffset;
		seq++;
		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			/* if we stripped the tag and length we should also strip the EOC is ind_len */
			if(ind_field == 1)
			{
				/* skip over EOC */
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, offset, count, "SEQ FIELD EOC");
				}
			}
		}
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence ate %d too many bytes", offset-end_offset);
	}
	if(ind){
		/*  need to eat this EOC
		end_offset = tvb_length(tvb);*/
		end_offset += 2;
		if(show_internal_ber_fields){
			proto_tree_add_text(tree, tvb, end_offset-2,2 , "SEQ EOC");
		}
	}
	return end_offset;
}

/* This function dissects a BER set
 */
int dissect_ber_set(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *set, gint hf_id, gint ett_id) {
	gint8 class;
	gboolean pc, ind = 0, ind_field;
	gint32 tag;
	guint32 len;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	int end_offset, s_offset;
	gint length_remaining;
	tvbuff_t *next_tvb;
	const ber_sequence_t *cset = NULL;
# define MAX_SET_ELEMENTS 32
	guint32   mandatory_fields = 0;
	guint8   set_idx;
	gboolean first_pass;
	s_offset = offset;
#ifdef DEBUG_BER
	{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SET dissect_ber_set(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SET dissect_ber_set(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag){
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
		if(ind){
		/*  Fixed the length is correctly returned from dissect ber_length
		  end_offset = tvb_length(tvb);*/
		  end_offset = offset + len -2;
		} else {
		  end_offset = offset + len;
		}

		/* sanity check: we only handle Constructed Universal Sets */
		if ((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))
		if ((!pc)
		||(!implicit_tag&&((class!=BER_CLASS_UNI)
							||(tag!=BER_UNI_TAG_SET)))) {
		  tvb_ensure_bytes_exist(tvb, offset-2, 2);
		  proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: SET expected but Class:%d(%s) PC:%d Tag:%d was found", class,val_to_str(class,ber_class_codes,"Unknown"), pc, tag);
		  return end_offset;
		}
	} else {
		/* was implicit tag so just use the length of the tvb */
		len=tvb_length_remaining(tvb,offset);
		end_offset=offset+len;
	}

	/* create subtree */
	if (hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* record the mandatory elements of the set so we can check we founf everything at the end
	   we can only record 32 elements for now ... */
	for(set_idx = 0; (cset=&set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	  if(!(cset->flags & BER_FLAGS_OPTIONAL))
	      mandatory_fields |= 1 << set_idx;

	}

	/* loop over all entries until we reach the end of the set */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int hoffset, eoffset, count;

		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
		  but tcap dissector uses this to eat the tag length then pass into here... EOC still on there...*/

			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "SEQ EOC");
				}
				return end_offset;
			}
			/* } */
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tree, tvb, offset, &len, &ind_field);
		eoffset = offset + len;

		/* Look through the Set to see if this class/id exists and
		 * hasn't been seen before
		 * Skip check completely if class==ANY
		 * of if NOCHKTAG is set
		 */


		for(first_pass=TRUE, cset = set, set_idx = 0; cset->func || first_pass; cset++, set_idx++) {

		  /* we reset for a second pass when we will look for choices */
		  if(!cset->func) {
		    first_pass = FALSE;

		    cset=set; /* reset to the beginning */
		    set_idx = 0;
		  }

		  if((first_pass && ((cset->class==class) && (cset->tag==tag))) ||
		     (!first_pass && ((cset->class== BER_CLASS_ANY) && (cset->tag == -1))) ) /* choices */
		  {

			if (!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
		      /* dissect header and len for field */
				hoffset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
		    }
			else {
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset)
					length_remaining=eoffset-hoffset;
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
			}


			/* call the dissector for this field */
			/*if 	((eoffset-hoffset)>length_remaining) {*/
				/* If the field is indefinite (i.e. we dont know the
				 * length) of if the tvb is short, then just
				 * give it all of the tvb and hope for the best.
				 */
				/*next_tvb = tvb_new_subset(tvb, hoffset, -1, -1);*/
			/*} else {*/

			/*}*/

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SET dissect_ber_set(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SET dissect_ber_set(%s) calling subdissector\n",name);
}
}
#endif
			if (next_tvb == NULL) {
				/* Assume that we have a malformed packet. */
				THROW(ReportedBoundsError);
			}
			count=cset->func(pinfo, tree, next_tvb, 0);

			if(count) {
			    /* we found it! */
			    if(set_idx < MAX_SET_ELEMENTS)
				  mandatory_fields &= ~(1 << set_idx);

				offset = eoffset;

				if(!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
				  /* if we stripped the tag and length we should also strip the EOC is ind_len */
				  if(ind_field == 1){
					  /* skip over EOC */
					  if(show_internal_ber_fields){
						  proto_tree_add_text(tree, tvb, offset, count, "SET FIELD EOC");
					  }
				  }
				}
				break;
			}
		  }
		}

		if(!cset->func) {
		  /* we didn't find a match */
		  proto_tree_add_text(tree, tvb, hoffset, len, "BER Error: Unknown field in SET class:%d(%s) tag:%d",class,val_to_str(class,ber_class_codes,"Unknown"),tag);
		  offset = eoffset;
		}
	}

	if(mandatory_fields) {

	  /* OK - we didn't find some of the elements we expected */

	  for(set_idx = 0;  (cset = &set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	    if(mandatory_fields & (1 << set_idx)) {

	      /* here is something we should have seen - but didn't! */
	      proto_tree_add_text(tree, tvb, offset, len,
				  "BER Error: Missing field in SET class:%d (%s) tag:%d expected",
				  cset->class,val_to_str(cset->class,ber_class_codes,"Unknown"),
				  cset->tag);

	    }

	  }
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if (offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: SET ate %d too many bytes", offset-end_offset);
	}

	if(ind){
		/*  need to eat this EOC
		  end_offset = tvb_length(tvb);*/
		  end_offset += 2;
		  if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, end_offset-2,2 , "SET EOC");
		  }
	}

	return end_offset;

}


/* this function dissects a BER choice
 * If we did not find a matching choice,  just return offset unchanged
 * in case it was a CHOICE { } OPTIONAL
 */
int
dissect_ber_choice(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice_t *choice, gint hf_id, gint ett_id, gint *branch_taken)
{
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	const ber_choice_t *ch;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset, start_offset, count;
	int hoffset = offset;
	header_field_info	*hfinfo;
	gint length, length_remaining;
	tvbuff_t *next_tvb;
	gboolean first_pass;

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("CHOICE dissect_ber_choice(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("CHOICE dissect_ber_choice(%s) entered len:%d\n",name,tvb_length_remaining(tvb,offset));
}
}
#endif
	start_offset=offset;

	/* read header and len for choice field */
	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(parent_tree, tvb, offset, &len, &ind);
	  end_offset = offset + len ;

	/* Some sanity checks.
	 * The hf field passed to us MUST be an integer type
	 */
	if(hf_id >= 0){
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
	if(branch_taken){
		*branch_taken=-1;
	}
	first_pass = TRUE;
	while(ch->func || first_pass){
		if(branch_taken){
			(*branch_taken)++;
		}
	  /* we reset for a second pass when we will look for choices */
	  if(!ch->func) {
	    first_pass = FALSE;
	    ch = choice; /* reset to the beginning */
		if(branch_taken){
			*branch_taken=-1;
		}
	  }

choice_try_again:
#ifdef DEBUG_BER
printf("CHOICE testing potential subdissector class:%d:(expected)%d  tag:%d:(expected)%d flags:%d\n",class,ch->class,tag,ch->tag,ch->flags);
#endif
		if( (first_pass && (((ch->class==class)&&(ch->tag==tag))
		     ||  ((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)))) ||
		    (!first_pass && (((ch->class == BER_CLASS_ANY) && (ch->tag == -1)))) /* we failed on the first pass so now try any choices */
		){
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
				/* dissect header and len for field */
				hoffset = dissect_ber_identifier(pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
				start_offset=hoffset;
				if (ind)
					{
					length = len-2;
					}
				else
					{
					length = len;
					}

			}
			else
				length = end_offset- hoffset;
			/* create subtree */
			if(hf_id >= 0){
				if(parent_tree){
					item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
					tree = proto_item_add_subtree(item, ett_id);
				}
			}
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if(length_remaining>length)
				length_remaining=length;

#ifdef REMOVED
			/* This is bogus and makes the OID_1.0.9506.1.1.cap file
			 * in Steven J Schaeffer's email of 2005-09-12 fail to dissect
			 * properly.  Maybe we should get rid of 'first_pass'
			 * completely.
			 * It was added as a qad workaround for some problem CMIP
			 * traces anyway.
			 * God, this file is a mess and it is my fault. /ronnie
			 */
			if(first_pass)
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);
			else
			  next_tvb = tvb; /* we didn't make selection on this class/tag so pass it on */
#endif
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);


#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("CHOICE dissect_ber_choice(%s) calling subdissector start_offset:%d offset:%d len:%d %02x:%02x:%02x\n",name,start_offset,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("CHOICE dissect_ber_choice(%s) calling subdissector len:%d\n",name,tvb_length(next_tvb));
}
}
#endif
			if (next_tvb == NULL) {
				/* Assume that we have a malformed packet. */
				THROW(ReportedBoundsError);
			}
			count=ch->func(pinfo, tree, next_tvb, 0);
#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_choice(%s) subdissector ate %d bytes\n",name,count);
}
#endif
			if((count==0)&&(((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)) || !first_pass)){
				/* wrong one, break and try again */
				ch++;
				goto choice_try_again;
			}
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
			 if(ind)
			 	{
			 	/* we are traversing a indfinite length choice where we did not pass the tag length */
			 	/* we need to eat the EOC */
			 	if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, start_offset, count+2, "CHOICE EOC");
				}
			 }
			}
			return end_offset;
			break;
		}
		ch++;
	}
	if(branch_taken){
		/* none of the branches were taken so set the param
		   back to -1 */
		*branch_taken=-1;
	}

#ifdef REMOVED
	/*XXX here we should have another flag to the CHOICE to distinguish
	 * between teh case when we know it is a mandatory   or if the CHOICE is optional == no arm matched */

	/* oops no more entries and we still havent found
	 * our guy :-(
	 */
	proto_tree_add_text(tree, tvb, offset, len, "BER Error: This choice field was not found.");

	return end_offset;
#endif

	return start_offset;
}

#if 0
/* this function dissects a BER GeneralString
 */
int
dissect_ber_GeneralString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, int name_len)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
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
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: GeneralString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}

	if(len>=(max_len-1)){
		len=max_len-1;
	}

	tvb_memcpy(tvb, str, offset, len);
	str[len]=0;

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	return end_offset;
}
#endif
int dissect_ber_restricted_string(gboolean implicit_tag, gint32 type, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb) {
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int eoffset;
	int hoffset = offset;

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("RESTRICTED STRING dissect_ber_octet string(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("RESTRICTED STRING dissect_ber_octet_string(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tree, tvb, offset, &len, NULL);
		eoffset = offset + len;

		/* sanity check */
		if( (class!=BER_CLASS_UNI)
		  ||(tag != type) ){
	            tvb_ensure_bytes_exist(tvb, offset-2, 2);
	    	    proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: String with tag=%d expected but Class:%d PC:%d Tag:%d was unexpected", type, class, pc, tag);
			return eoffset;
		}
	}

	/* 8.21.3 */
	return dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, hoffset, hf_id, out_tvb);
}

int
dissect_ber_GeneralString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, guint name_len)
{
	tvbuff_t *out_tvb = NULL;

	offset = dissect_ber_restricted_string(FALSE, BER_UNI_TAG_GeneralString, pinfo, tree, tvb, offset, hf_id, (name_string)?&out_tvb:NULL);

	if(name_string) {
		if(out_tvb && tvb_length(out_tvb) >= name_len) {
			tvb_memcpy(out_tvb, name_string, 0, name_len-1);
			name_string[name_len-1] = '\0';
		} else if(out_tvb) {
			tvb_memcpy(out_tvb, name_string, 0, -1);
			name_string[tvb_length(out_tvb)] = '\0';
		}
	}

	return offset;
}

/* 8.19 Encoding of an object identifier value.
 * if value_string is non-NULL it must point to a buffer of at least
 * MAX_OID_STR_LEN bytes.
 */
int dissect_ber_object_identifier(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **value_tvb)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int eoffset;
	char *str;
	proto_item *item = NULL;
	header_field_info *hfi;
	const gchar *name;

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("OBJECT IDENTIFIER dissect_ber_object_identifier(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("OBJECT IDENTIFIER dissect_ber_object_identifier(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag) {
		/* sanity check */
		offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
		eoffset = offset + len;
		if( (class!=BER_CLASS_UNI)
		  ||(tag != BER_UNI_TAG_OID) ){
	            tvb_ensure_bytes_exist(tvb, offset-2, 2);
	    	    proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Object Identifier expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
			return eoffset;
		}
	} else {
		len=tvb_length_remaining(tvb,offset);
		eoffset=offset+len;
	}

	hfi = proto_registrar_get_nth(hf_id);
	if (hfi->type == FT_OID) {
		item = proto_tree_add_item(tree, hf_id, tvb, offset, len, FALSE);
	} else if (IS_FT_STRING(hfi->type)) {
		str = oid_to_str(tvb_get_ptr(tvb, offset, len), len);
		item = proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
		if(item){
			/* see if we know the name of this oid */
			name = get_oid_name(tvb_get_ptr(tvb, offset, len), len);
			if(name){
				proto_item_append_text(item, " (%s)", name);
			}
		}
	} else {
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	if (value_tvb)
		*value_tvb = tvb_new_subset(tvb, offset, len, len);

	return eoffset;
}

int dissect_ber_object_identifier_str(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, const char **value_string)
{
  tvbuff_t *value_tvb = NULL;
  guint length;

  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_id, (value_string) ? &value_tvb : NULL);

  if (value_string) {
    if (value_tvb && (length = tvb_length(value_tvb))) {
      *value_string = oid_to_str(tvb_get_ptr(value_tvb, 0, length), length);
    } else {
      *value_string = "";
    }
  }

  return offset;
}


static int dissect_ber_sq_of(gboolean implicit_tag, gint32 type, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 class;
	gboolean pc, ind = FALSE, ind_field;
	gint32 tag;
	guint32 len;

	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	int cnt, hoffset, end_offset;
	header_field_info *hfi;

#ifdef DEBUG_BER
{
char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SQ OF dissect_ber_sq_of(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SQ OF dissect_ber_sq_of(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag){
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
		if(ind){
		  /* if the length is indefinite we dont really know (yet) where the
		   * object ends so assume it spans the rest of the tvb for now.
        	   */
		  end_offset = offset + len;
		} else {
		  end_offset = offset + len;
		}

		/* sanity check: we only handle Constructed Universal Sequences */
		if((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))
		if(!pc
			||(!implicit_tag&&((class!=BER_CLASS_UNI)
							||(tag!=type)))) {
			tvb_ensure_bytes_exist(tvb, offset-2, 2);
			proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: %s Of expected but Class:%d PC:%d Tag:%d was unexpected",
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", class, pc, tag);
			return end_offset;
		}
	} else {
		/* the tvb length should be correct now nope we could be comming from an implicit choice or sequence, thus we
		read the items we match and return the length*/
		len=tvb_length_remaining(tvb,offset);
		end_offset = offset + len;
	}

	/* count number of items */
	cnt = 0;
	hoffset = offset;
	/* only count the number of items IFF we have the full blob,
	 * else this will just generate a [short frame] before we even start
	 * dissecting a single item.
	 */
	/* XXX Do we really need to count them at all ?  ronnie */
	if(tvb_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){
		while (offset < end_offset){
			guint32 len;
                        gint s_offset;

                        s_offset = offset;

			if(ind){ /* this sequence of was of indefinite length, so check for EOC */
				if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
					break;
				}
			}

			/* read header and len for next field */
			offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
			offset = get_ber_length(tree, tvb, offset, &len, NULL);
			/* best place to get real length of implicit sequence of or set of is here... */
			/* adjust end_offset if we find somthing that doesnt match */
			offset += len;
			cnt++;
			if (offset <= s_offset)
				THROW(ReportedBoundsError);
		}
	}
	offset = hoffset;

	/* create subtree */
	if(hf_id >= 0) {
		hfi = proto_registrar_get_nth(hf_id);
		if(parent_tree){
			if(hfi->type == FT_NONE) {
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
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset;
		int hoffset, count;

		hoffset = offset;
	 	if(ind){ /*this sequence of was of indefinite length, so check for EOC */
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, hoffset, end_offset-hoffset, "SEQ OF EOC");
				}
				return offset+2;
			}
		}
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tree, tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                /* Make sure we move forward */
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		/* verify that this one is the one we want */
		/* ahup if we are implicit then we return to the uper layer how much we have used */
		if(seq->class!=BER_CLASS_ANY){
		  if((seq->class!=class)
			||(seq->tag!=tag) ){
			if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SQ OF");
				offset = eoffset;
				continue;
				/* wrong.... */
			}
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(pinfo, tree, tvb, hoffset, NULL, NULL);
		}

		/* call the dissector for this field */
		count=seq->func(pinfo, tree, tvb, hoffset)-hoffset;
				/* hold on if we are implicit and the result is zero, i.e. the item in the sequence of
				doesnt match the next item, thus this implicit sequence is over, return the number of bytes
				we have eaten to allow the possible upper sequence continue... */
		cnt++; /* rubbish*/
		offset = eoffset;
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: %s Of ate %d too many bytes",
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", offset-end_offset);
	}

	return end_offset;
}

int dissect_ber_sequence_of(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, pinfo, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int dissect_ber_set_of(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SET, pinfo, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int
dissect_ber_GeneralizedTime(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	char str[32];
	const guint8 *tmpstr;
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int end_offset;

	if(!implicit_tag){
	  offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	  offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	  end_offset=offset+len;

	  /* sanity check. we only handle universal/generalized time */
	  if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GeneralizedTime)){
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
	        proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: GeneralizedTime expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
		end_offset=offset+len;
	  }
        } else {
	  len=tvb_length_remaining(tvb,offset);
	  end_offset=offset+len;
	}


	tmpstr=tvb_get_ptr(tvb, offset, len);
	g_snprintf(str, 32, "%.4s-%.2s-%.2s %.2s:%.2s:%.2s (%.1s)",
		tmpstr, tmpstr+4, tmpstr+6, tmpstr+8,
		tmpstr+10, tmpstr+12, tmpstr+14);
	str[31]=0; /* just in case ... */

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	offset+=len;
	return offset;
}

/* 8.6 Encoding of a bitstring value */
int dissect_ber_bitstring(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	guint8 pad=0, b0, b1, val;
	int end_offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	const asn_namedbit *nb;
	char *sep;
	gboolean term;

	if(!implicit_tag){
	  /* read header and len for the octet string */
	  offset = dissect_ber_identifier(pinfo, parent_tree, tvb, offset, &class, &pc, &tag);
	  offset = dissect_ber_length(pinfo, parent_tree, tvb, offset, &len, &ind);
	  end_offset = offset + len;

	  /* sanity check: we only handle Universal BitSrings */

	  /* for an IMPLICIT APPLICATION tag asn2eth seems to call this
	     function with implicit_tag = FALSE. BER_FLAGS_NOOWNTAG was
	     set so the APPLICATION tag was still present.
	     So here we relax it for APPLICATION tags. CONTEXT tags may
	     still cause a problem. */

	  if(!implicit_tag && (class!=BER_CLASS_APP)) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag!=BER_UNI_TAG_BITSTRING) ){
		    tvb_ensure_bytes_exist(tvb, offset-2, 2);
	    	    proto_tree_add_text(parent_tree, tvb, offset-2, 2, "BER Error: BitString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
			return end_offset;
		}
	  }
	} else {
	  pc=0;
	  len=tvb_length_remaining(tvb,offset);
	  end_offset=offset+len;
	}

	ber_last_created_item = NULL;

	if(pc) {
		/* constructed */
		/* TO DO */
	} else {
		/* primitive */
		/* padding */
		pad = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(parent_tree, hf_ber_bitstring_padding, tvb, offset, 1, FALSE);
		offset++;
		len--;
		if( hf_id >= 0) {
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			ber_last_created_item = item;
			if(ett_id != -1) {
				tree = proto_item_add_subtree(item, ett_id);
			}
		}
		if(out_tvb) {
			if(len<=(guint32)tvb_length_remaining(tvb, offset)){
				*out_tvb = tvb_new_subset(tvb, offset, len, len);
			} else {
				*out_tvb = tvb_new_subset(tvb, offset, -1, -1);
			}
		}
	}

	if(named_bits) {
		sep = " (";
		term = FALSE;
		nb = named_bits;
		while (nb->p_id) {
			if(nb->bit < (8*len-pad)) {
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
			if(val) {
				if(item && nb->tstr) {
					proto_item_append_text(item, "%s%s", sep, nb->tstr);
					sep = ", ";
					term = TRUE;
				}
			} else {
				if(item && nb->fstr) {
					proto_item_append_text(item, "%s%s", sep, nb->fstr);
					sep = ", ";
					term = TRUE;
				}
			}
			nb++;
		}
		if(term)
			proto_item_append_text(item, ")");
	}

	return end_offset;
}

int dissect_ber_bitstring32(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int **bit_fields, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
	tvbuff_t *tmp_tvb = NULL;
	proto_tree *tree;
	guint32 val;
	int **bf;
	header_field_info *hfi;
	char *sep;
	gboolean term;
	unsigned int i, tvb_len;

	offset = dissect_ber_bitstring(implicit_tag, pinfo, parent_tree, tvb, offset, NULL, hf_id, ett_id, &tmp_tvb);

	tree = proto_item_get_subtree(ber_last_created_item);
	if(bit_fields && tree && tmp_tvb) {
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
			if (**bf >= 0) {
				hfi = proto_registrar_get_nth(**bf);
				if(val & hfi->bitmask) {
					proto_item_append_text(ber_last_created_item, "%s%s", sep, hfi->name);
					sep = ", ";
					term = TRUE;
				}
			}
			bf++;
		}
		if(term)
			proto_item_append_text(ber_last_created_item, ")");
	}

	if(out_tvb)
		*out_tvb = tmp_tvb;

	return offset;
}

static void
dissect_ber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Unknown BER");
  }

  (void) dissect_unknown_ber(pinfo, tvb, 0, tree);

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
	{ &hf_ber_id_uni_tag_ext, {
	    "Tag", "ber.id.uni_tag", FT_UINT32, BASE_DEC,
	    NULL, 0, "Universal tag type", HFILL }},
	{ &hf_ber_id_tag, {
	    "Tag", "ber.id.tag", FT_UINT8, BASE_DEC,
	    NULL, 0x1f, "Tag value for non-Universal classes", HFILL }},
	{ &hf_ber_id_tag_ext, {
	    "Tag", "ber.id.tag", FT_UINT32, BASE_DEC,
	    NULL, 0, "Tag value for non-Universal classes", HFILL }},
	{ &hf_ber_length, {
	    "Length", "ber.length", FT_UINT32, BASE_DEC,
	    NULL, 0, "Length of contents", HFILL }},
	{ &hf_ber_unknown_OCTETSTRING, {
	    "OCTETSTRING", "ber.unknown.OCTETSTRING", FT_BYTES, BASE_HEX,
	    NULL, 0, "This is an unknown OCTETSTRING", HFILL }},
	{ &hf_ber_unknown_OID, {
	    "OID", "ber.unknown.OID", FT_OID, BASE_NONE,
	    NULL, 0, "This is an unknown Object Identifier", HFILL }},
	    	{ &hf_ber_unknown_GraphicString, {
	    "GRAPHICSTRING", "ber.unknown.GRAPHICSTRING", FT_STRING, BASE_HEX,
	    NULL, 0, "This is an unknown GRAPHICSTRING", HFILL }},

	{ &hf_ber_unknown_NumericString, {
	    "NumericString", "ber.unknown.NumericString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown NumericString", HFILL }},
	{ &hf_ber_unknown_PrintableString, {
	    "PrintableString", "ber.unknown.PrintableString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown PrintableString", HFILL }},
	{ &hf_ber_unknown_TeletexString, {
	    "TeletexString", "ber.unknown.TeletexString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown TeletexString", HFILL }},
	{ &hf_ber_unknown_IA5String, {
	    "IA5String", "ber.unknown.IA5String", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown IA5String", HFILL }},
	{ &hf_ber_unknown_UTCTime, {
	    "UTCTime", "ber.unknown.UTCTime", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown UTCTime", HFILL }},
	{ &hf_ber_unknown_UTF8String, {
	    "UTF8String", "ber.unknown.UTF8String", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown UTF8String", HFILL }},
	{ &hf_ber_unknown_GeneralizedTime, {
	    "GeneralizedTime", "ber.unknown.GeneralizedTime", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown GeneralizedTime", HFILL }},
	{ &hf_ber_unknown_INTEGER, {
	    "INTEGER", "ber.unknown.INTEGER", FT_UINT32, BASE_DEC,
	    NULL, 0, "This is an unknown INTEGER", HFILL }},
	{ &hf_ber_unknown_BITSTRING, {
	    "BITSTRING", "ber.unknown.BITSTRING", FT_BYTES, BASE_DEC,
	    NULL, 0, "This is an unknown BITSTRING", HFILL }},
	{ &hf_ber_unknown_BOOLEAN, {
	    "BOOLEAN", "ber.unknown.BOOLEAN", FT_UINT8, BASE_HEX,
	    NULL, 0, "This is an unknown BOOLEAN", HFILL }},
	{ &hf_ber_unknown_ENUMERATED, {
	    "ENUMERATED", "ber.unknown.ENUMERATED", FT_UINT32, BASE_DEC,
	    NULL, 0, "This is an unknown ENUMERATED", HFILL }},
    };

    static gint *ett[] = {
	&ett_ber_octet_string,
	&ett_ber_unknown,
	&ett_ber_SEQUENCE,
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
}

void
proto_reg_handoff_ber(void)
{
        dissector_handle_t ber_handle;

	add_oid_str_name("2.1.1","joint-iso-itu-t(2) asn1(1) basic-encoding(1)");

	ber_handle = create_dissector_handle(dissect_ber, proto_ber);
	dissector_add("wtap_encap", WTAP_ENCAP_BER, ber_handle);

}
