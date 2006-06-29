/* packet-per.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_PER_H__
#define __PACKET_PER_H__

/*--- ASN.1 Context, will be moved to common ASN.1 header when created --- */

typedef enum {
  ASN_ENC_BER,  /* X.690 - BER, CER, DER */
  ASN_ENC_PER,  /* X.691 - PER */
  ASN_ENC_ECN,  /* X.692 - ECN */
  ASN_ENC_XER   /* X.693 - XER */
} asn_enc_e;

typedef struct _asn_ctx_t {
  asn_enc_e encoding;
  gboolean aligned;
  packet_info *pinfo;
  proto_item *created_item;
  void *private_data;
} asn_ctx_t;

void asn_ctx_init(asn_ctx_t *actx, asn_enc_e encoding, gboolean aligned, packet_info *pinfo);



#define PER_NOT_DECODED_YET(x) \
proto_tree_add_text(tree, tvb, 0, 0, "something unknown here [%s]",x); \
fprintf(stderr,"[%s %u] Not decoded yet in packet : %d  [%s]\n", __FILE__, __LINE__, actx->pinfo->fd->num,x); \
if (check_col(actx->pinfo->cinfo, COL_INFO)){ \
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "[UNKNOWN PER: %s]", x); \
} \
tvb_get_guint8(tvb, 9999);

typedef int (*per_callback)(tvbuff_t *, int, asn_ctx_t *, proto_tree *);
typedef int (*per_type_fn)(tvbuff_t*, int, asn_ctx_t*, proto_tree*, int);

/* in all functions here, offset is guint32 and is
   byteposition<<3 + bitposition
*/

/* value for value and size constraints */
#define NO_BOUND -1


/* values for extensions */
#define ASN1_NO_EXTENSIONS	0
#define ASN1_EXTENSION_ROOT	1
#define ASN1_NOT_EXTENSION_ROOT	2

/* value for optional */
#define ASN1_NOT_OPTIONAL	0
#define ASN1_OPTIONAL		1

typedef struct _per_choice_t {
	int value;
	const int *p_id;
	int extension;
	per_type_fn func;
} per_choice_t;

typedef struct _per_sequence_t {
	const char *name;
	const int *p_id;
	int extension;
	int optional;
	per_type_fn func;
} per_sequence_t;

extern guint32 dissect_per_length_determinant(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, guint32 *length);

extern guint32 dissect_per_null(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);

extern guint32 dissect_per_GeneralString(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);

extern guint32 dissect_per_sequence_of(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq);

extern guint32 dissect_per_IA5String(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len);

extern guint32 dissect_per_NumericString(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len);

extern guint32 dissect_per_PrintableString(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len);

extern guint32 dissect_per_VisibleString(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len);

extern guint32 dissect_per_BMPString(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len);

extern guint32 dissect_per_constrained_sequence_of(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len);

extern guint32 dissect_per_constrained_set_of(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len);

extern guint32 dissect_per_set_of(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq);

extern guint32 dissect_per_object_identifier(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
extern guint32 dissect_per_object_identifier_str(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_string);

extern guint32 dissect_per_boolean(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, gboolean *bool);

extern guint32 dissect_per_integer(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, gint32 *value);

extern guint32 dissect_per_constrained_integer(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, guint32 min, guint32 max, guint32 *value, gboolean has_extension);

extern guint32 dissect_per_choice(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, gint ett_index, const per_choice_t *choice, guint32 *value);

extern guint32 dissect_per_sequence(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *sequence);

extern guint32 dissect_per_octet_string(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, tvbuff_t **value_tvb);

extern guint32 dissect_per_bit_string(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb);

extern guint32 dissect_per_restricted_character_string(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb);

extern guint32 dissect_per_enumerated(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, guint32 root_num, guint32 *value, gboolean has_extension, guint32 ext_num, guint32 *value_map);

extern guint32 dissect_per_open_type(tvbuff_t *tvb, guint32 offset, asn_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type);

#endif  /* __PACKET_PER_H__ */
