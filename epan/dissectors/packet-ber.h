/* packet-ber.h
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

#ifndef __PACKET_BER_H__
#define __PACKET_BER_H__

#include <epan/proto.h>
#include <epan/to_str.h>

#define BER_NOT_DECODED_YET(x) \
proto_tree_add_text(tree, tvb, offset, 0, "something unknown here [%s]",x); \
fprintf(stderr,"Not decoded yet in packet : %d  [%s]\n", pinfo->fd->num,x); \
if (check_col(pinfo->cinfo, COL_INFO)){ \
	col_append_fstr(pinfo->cinfo, COL_INFO, "[UNKNOWN BER: %s]", x); \
} \
tvb_get_guint8(tvb, 9999);

typedef int (*ber_callback)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
typedef int (*ber_type_fn)(gboolean, tvbuff_t*, int, packet_info*, proto_tree*, int);


#define BER_CLASS_UNI	0
#define BER_CLASS_APP	1
#define BER_CLASS_CON	2
#define BER_CLASS_PRI	3
#define BER_CLASS_ANY   99			/* dont check class nor tag */

#define BER_UNI_TAG_EOC					0	/* 'end-of-content' */
#define BER_UNI_TAG_BOOLEAN				1
#define BER_UNI_TAG_INTEGER				2
#define BER_UNI_TAG_BITSTRING		    3
#define BER_UNI_TAG_OCTETSTRING		    4
#define BER_UNI_TAG_NULL				5
#define BER_UNI_TAG_OID					6	/* OBJECT IDENTIFIER */
#define BER_UNI_TAG_ObjectDescriptor	7
#define BER_UNI_TAG_REAL				9
#define BER_UNI_TAG_ENUMERATED		    10
#define BER_UNI_TAG_EMBEDDED_PDV	    11
#define BER_UNI_TAG_UTF8String		    12
#define BER_UNI_TAG_RELATIVE_OID	    13
#define BER_UNI_TAG_SEQUENCE		    16	/* SEQUENCE, SEQUENCE OF */
#define BER_UNI_TAG_SET					17	/* SET, SET OF */
#define BER_UNI_TAG_NumericString	    18
#define BER_UNI_TAG_PrintableString	    19
#define BER_UNI_TAG_TeletexString	    20  /* TeletextString, T61String */
#define BER_UNI_TAG_VideotexString	    21
#define BER_UNI_TAG_IA5String		    22
#define BER_UNI_TAG_UTCTime				23
#define BER_UNI_TAG_GeneralizedTime	    24
#define BER_UNI_TAG_GraphicString	    25
#define BER_UNI_TAG_VisibleString	    26  /* VisibleString, ISO64String */
#define BER_UNI_TAG_GeneralString	    27
#define BER_UNI_TAG_UniversalString	    28
#define BER_UNI_TAG_CHARACTERSTRING	    29
#define BER_UNI_TAG_BMPString		    30


/* this function dissects the identifier octer of the BER TLV.
 * We only handle TAGs (and LENGTHs) that fit inside 32 bit integers.
 */
extern int get_ber_identifier(tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag);
extern int dissect_ber_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag);
extern int dissect_unknown_ber(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
/* this function dissects the identifier octer of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
extern int get_ber_length(proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind);
extern int dissect_ber_length(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind);

extern int dissect_ber_tagged_type(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint8 tag_cls, gint32 tag_tag, gboolean tag_impl, ber_type_fn type);

extern int dissect_ber_octet_string(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb);
extern int dissect_ber_octet_string_wcb(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func);

extern int dissect_ber_integer64(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint64 *value);

extern int dissect_ber_integer(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value);

extern int dissect_ber_null(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id);

extern int dissect_ber_boolean(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id);
extern int dissect_ber_boolean_value(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gboolean *value);


#define BER_FLAGS_OPTIONAL	0x00000001
#define BER_FLAGS_IMPLTAG	0x00000002
#define BER_FLAGS_NOOWNTAG	0x00000004
#define BER_FLAGS_NOTCHKTAG	0x00000008
typedef struct _ber_sequence_t {
	gint8	class;
	gint32	tag;
	guint32	flags;
	ber_callback	func;
} ber_sequence_t;

/* this function dissects a BER sequence 
 */
extern int dissect_ber_sequence(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id);
extern int dissect_ber_set(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id);


typedef struct _ber_choice_t {
	guint32	value;
	gint8	class;
	gint32	tag;
	guint32	flags;
	ber_callback	func;
} ber_choice_t;


/* this function dissects a BER choice 
 */
extern int dissect_ber_choice(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice_t *ch, gint hf_id, gint ett_id, gint *branch_taken);


/* this function dissects a BER strings
 */
extern int dissect_ber_restricted_string(gboolean implicit_tag, gint32 type, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb);
extern int dissect_ber_GeneralString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, guint name_len);


/* this function dissects a BER Object Identifier
 */
extern int dissect_ber_object_identifier(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **value_tvb);
extern int dissect_ber_object_identifier_str(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, const char **value_string);

/* this function dissects a BER sequence of
 */
extern int dissect_ber_sequence_of(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id);

extern int dissect_ber_set_of(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id);


extern int dissect_ber_GeneralizedTime(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id);

typedef struct _asn_namedbit {
	guint32 bit;
	int *p_id;
	gint32 gb0;  /* the 1st bit of "bit group", -1 = the 1st bit of current byte */
	gint32 gb1;  /* last bit of "bit group", -1 = last bit of current byte */
	const gchar *tstr;  /* true string */
	const gchar *fstr;  /* false string */
} asn_namedbit;
/* this function dissects a BER BIT-STRING
 */
extern int dissect_ber_bitstring(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb);
extern int dissect_ber_bitstring32(gboolean implicit_tag, packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int **bit_fields, gint hf_id, gint ett_id, tvbuff_t **out_tvb);


extern proto_item *ber_last_created_item;
extern proto_item *get_ber_last_created_item(void);

int call_ber_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
void register_ber_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto, const char *name);
void register_ber_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name);
void register_ber_syntax_dissector(const char *oid, int proto, dissector_t dissector);
void register_ber_oid_name(const char *oid, const char *name);
void register_ber_oid_syntax(const char *oid, const char *name, const char *syntax);
void dissect_ber_oid_NULL_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void ber_decode_as_foreach(GHFunc func, gpointer user_data); /* iterate through known syntaxes */
void ber_decode_as(gchar *syntax); /* decode the current capture as this syntax */
void ber_set_filename(gchar *filename); /* name of current BER-encoded file */

gboolean oid_has_dissector(const char *oid);

#endif  /* __PACKET_BER_H__ */

