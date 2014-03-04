/* packet-per.h
 * Routines for dissection of ASN.1 Aligned PER
 * 2003  Ronnie Sahlberg
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

#ifndef __PACKET_PER_H__
#define __PACKET_PER_H__

#include "ws_symbol_export.h"

#define PER_NOT_DECODED_YET(x) \
proto_tree_add_text(tree, tvb, 0, 0, "something unknown here [%s]",x); \
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, "[UNKNOWN PER: %s]", x); \
tvb_get_guint8(tvb, 9999);

typedef int (*per_type_fn)(tvbuff_t*, int, asn1_ctx_t*, proto_tree*, int);

/* in all functions here, offset is guint32 and is
   byteposition<<3 + bitposition
*/

/* value for value and size constraints */
#define NO_BOUND -1


/* values for extensions */
#define ASN1_NO_EXTENSIONS	0
#define ASN1_EXTENSION_ROOT	    ASN1_EXT_ROOT
#define ASN1_NOT_EXTENSION_ROOT	ASN1_EXT_EXT

/* value for optional */
#define ASN1_NOT_OPTIONAL	0
#define ASN1_OPTIONAL		ASN1_OPT

typedef struct _per_choice_t {
	gint value;
	const int *p_id;
	int extension;
	per_type_fn func;
} per_choice_t;

typedef struct _per_sequence_t {
	const int *p_id;
	int extension;
	int optional;
	per_type_fn func;
} per_sequence_t;

WS_DLL_PUBLIC guint32 dissect_per_null(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

WS_DLL_PUBLIC guint32 dissect_per_GeneralString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

WS_DLL_PUBLIC guint32 dissect_per_sequence_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq);

WS_DLL_PUBLIC guint32 dissect_per_IA5String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_NumericString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_PrintableString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_VisibleString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_BMPString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

extern guint32 dissect_per_UTF8String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

extern guint32 dissect_per_object_descriptor(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);

WS_DLL_PUBLIC guint32 dissect_per_constrained_sequence_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_constrained_set_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq, int min_len, int max_len, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_set_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *seq);

WS_DLL_PUBLIC guint32 dissect_per_object_identifier(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
WS_DLL_PUBLIC guint32 dissect_per_object_identifier_str(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx);

WS_DLL_PUBLIC guint32 dissect_per_relative_oid(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
WS_DLL_PUBLIC guint32 dissect_per_relative_oid_str(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx);

WS_DLL_PUBLIC guint32 dissect_per_boolean(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gboolean *bool_val);

WS_DLL_PUBLIC guint32 dissect_per_integer(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint32 *value);

WS_DLL_PUBLIC guint32 dissect_per_constrained_integer(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 min, guint32 max, guint32 *value, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_constrained_integer_64b(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint64 min, guint64 max, guint64 *value, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_per_real(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, double *value);

WS_DLL_PUBLIC guint32 dissect_per_choice(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint ett_index, const per_choice_t *choice, gint *value);

WS_DLL_PUBLIC guint32 dissect_per_sequence(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const per_sequence_t *sequence);
WS_DLL_PUBLIC guint32 dissect_per_sequence_eag(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, const per_sequence_t *sequence);

WS_DLL_PUBLIC guint32 dissect_per_octet_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb);
WS_DLL_PUBLIC guint32 dissect_per_octet_string_containing_pdu(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, dissector_t type_cb);
WS_DLL_PUBLIC guint32 dissect_per_octet_string_containing_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, new_dissector_t type_cb);

WS_DLL_PUBLIC guint32 dissect_per_bit_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb, int *len);
WS_DLL_PUBLIC guint32 dissect_per_bit_string_containing_pdu(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, dissector_t type_cb);
WS_DLL_PUBLIC guint32 dissect_per_bit_string_containing_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, new_dissector_t type_cb);

WS_DLL_PUBLIC guint32 dissect_per_restricted_character_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len,  gboolean has_extension, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb);

WS_DLL_PUBLIC guint32 dissect_per_enumerated(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 root_num, guint32 *value, gboolean has_extension, guint32 ext_num, guint32 *value_map);

WS_DLL_PUBLIC guint32 dissect_per_open_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb);
WS_DLL_PUBLIC guint32 dissect_per_open_type_pdu(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, dissector_t type_cb);
WS_DLL_PUBLIC guint32 dissect_per_open_type_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, new_dissector_t type_cb);

WS_DLL_PUBLIC guint32 dissect_per_external_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb);

extern guint32 dissect_per_size_constrained_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb, const gchar *name, int min_len, int max_len, gboolean has_extension);
extern gboolean get_size_constraint_from_stack(asn1_ctx_t *actx, const gchar *name, int *pmin_len, int *pmax_len, gboolean *phas_extension);

extern guint32 dissect_per_length_determinant(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index, guint32 *length);

#endif  /* __PACKET_PER_H__ */
