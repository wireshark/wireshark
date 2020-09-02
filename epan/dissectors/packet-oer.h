/* packet-per.h
 * Routines for dissection of ASN.1  OER
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_OER_H__
#define __PACKET_OER_H__

#include "ws_symbol_export.h"

typedef int (*oer_type_fn)(tvbuff_t*, int, asn1_ctx_t*, proto_tree*, int);


/* value for value and size constraints */
#define NO_BOUND -1


/* values for extensions */
#define ASN1_NO_EXTENSIONS	0
#define ASN1_EXTENSION_ROOT	    ASN1_EXT_ROOT
#define ASN1_NOT_EXTENSION_ROOT	ASN1_EXT_EXT

/* value for optional */
#define ASN1_NOT_OPTIONAL	0
#define ASN1_OPTIONAL		ASN1_OPT

typedef struct _oer_choice_t {
	gint value;
	const int *p_id;
	int extension;
	oer_type_fn func;
} oer_choice_t;

typedef struct _oer_sequence_t {
	const int *p_id;
	int extension;
	int optional;
	oer_type_fn func;
} oer_sequence_t;

//WS_DLL_PUBLIC void dissect_oer_not_decoded_yet(proto_tree* tree, packet_info* pinfo, tvbuff_t *tvb, const char* reason);

WS_DLL_PUBLIC guint32 dissect_oer_null(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

//WS_DLL_PUBLIC guint32 dissect_oer_GeneralString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

WS_DLL_PUBLIC guint32 dissect_oer_sequence_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const oer_sequence_t *seq);

WS_DLL_PUBLIC guint32 dissect_oer_IA5String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_NumericString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_PrintableString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_VisibleString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_BMPString(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

extern guint32 dissect_oer_UTF8String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

//extern guint32 dissect_oer_object_descriptor(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);

WS_DLL_PUBLIC guint32 dissect_oer_constrained_sequence_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const oer_sequence_t *seq, int min_len, int max_len, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_constrained_set_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const oer_sequence_t *seq, int min_len, int max_len, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_set_of(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const oer_sequence_t *seq);

//WS_DLL_PUBLIC guint32 dissect_oer_object_identifier(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
//WS_DLL_PUBLIC guint32 dissect_oer_object_identifier_str(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx);

//WS_DLL_PUBLIC guint32 dissect_oer_relative_oid(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
//WS_DLL_PUBLIC guint32 dissect_oer_relative_oid_str(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx);

WS_DLL_PUBLIC guint32 dissect_oer_boolean(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gboolean *bool_val);

WS_DLL_PUBLIC guint32 dissect_oer_integer(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint32 *value);

WS_DLL_PUBLIC guint32 dissect_oer_constrained_integer(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint64 min, gint64 max, guint32 *value, gboolean has_extension);

WS_DLL_PUBLIC guint32 dissect_oer_constrained_integer_64b(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint64 min, guint64 max, guint64 *value, gboolean has_extension);
WS_DLL_PUBLIC guint32 dissect_oer_constrained_integer_64b_no_ub(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint64 min, guint64 max, guint64 *value, gboolean has_extension);

//WS_DLL_PUBLIC guint32 dissect_oer_real(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, double *value);

WS_DLL_PUBLIC guint32 dissect_oer_choice(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, gint ett_index, const oer_choice_t *choice, gint *value);

WS_DLL_PUBLIC guint32 dissect_oer_sequence(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, gint ett_index, const oer_sequence_t *sequence);
//WS_DLL_PUBLIC guint32 dissect_oer_sequence_eag(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, const oer_sequence_t *sequence);

WS_DLL_PUBLIC guint32 dissect_oer_octet_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb);
//WS_DLL_PUBLIC guint32 dissect_oer_octet_string_containing_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, dissector_t type_cb);

WS_DLL_PUBLIC guint32
dissect_oer_bit_string(tvbuff_t *tvb, guint32 offset _U_, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_, int min_len _U_, int max_len _U_, gboolean has_extension _U_, int * const *named_bits _U_, gint num_named_bits _U_, tvbuff_t **value_tvb _U_, int *len _U_);
//WS_DLL_PUBLIC guint32 dissect_oer_bit_string_containing_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, dissector_t type_cb);

//WS_DLL_PUBLIC guint32 dissect_oer_restricted_character_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len,  gboolean has_extension, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb);

WS_DLL_PUBLIC guint32 dissect_oer_enumerated(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 root_num, guint32 *value, gboolean has_extension, guint32 ext_num, guint32 *value_map);

//WS_DLL_PUBLIC guint32 dissect_oer_open_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, oer_type_fn type_cb);
//WS_DLL_PUBLIC guint32 dissect_oer_open_type_pdu_new(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, dissector_t type_cb);

//WS_DLL_PUBLIC guint32 dissect_oer_external_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, oer_type_fn type_cb);

//extern guint32 dissect_oer_size_constrained_type(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, oer_type_fn type_cb, const gchar *name, int min_len, int max_len, gboolean has_extension);
///extern gboolean get_size_constraint_from_stack(asn1_ctx_t *actx, const gchar *name, int *pmin_len, int *pmax_len, gboolean *phas_extension);

//extern guint32 dissect_oer_length_determinant(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index, guint32 *length, gboolean *is_fragmented);

//WS_DLL_PUBLIC int call_oer_oid_callback(const char *oid, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, asn1_ctx_t *actx, int hf_index);
//WS_DLL_PUBLIC void register_oer_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name);

#endif  /* __PACKET_OER_H__ */
