/* packet-ber.h
 * Helpers for ASN.1/BER dissection
 * Ronnie Sahlberg (C) 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BER_H__
#define __PACKET_BER_H__

#include <epan/proto.h>
#include <epan/to_str.h>
#include <epan/asn1.h>
#include "ws_symbol_export.h"

/* value for value and size constraints */
#ifndef NO_BOUND
#define NO_BOUND -1
#endif

typedef int (*ber_callback)(bool imp_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
typedef int (*ber_type_fn)(bool, tvbuff_t*, int, asn1_ctx_t *actx, proto_tree*, int);
/* To be removed when the transition to the "New" type is complete */

#define BER_CLASS_UNI	0
#define BER_CLASS_APP	1
#define BER_CLASS_CON	2
#define BER_CLASS_PRI	3
#define BER_CLASS_ANY   99			/* don't check class nor tag */

#define BER_UNI_TAG_EOC					0	/* 'end-of-content' */
#define BER_UNI_TAG_BOOLEAN				1
#define BER_UNI_TAG_INTEGER				2
#define BER_UNI_TAG_BITSTRING		    3
#define BER_UNI_TAG_OCTETSTRING		    4
#define BER_UNI_TAG_NULL				5
#define BER_UNI_TAG_OID					6	/* OBJECT IDENTIFIER */
#define BER_UNI_TAG_ObjectDescriptor	7
#define BER_UNI_TAG_EXTERNAL			8
#define BER_UNI_TAG_REAL				9
#define BER_UNI_TAG_ENUMERATED		    10
#define BER_UNI_TAG_EMBEDDED_PDV	    11
#define BER_UNI_TAG_UTF8String		    12
#define BER_UNI_TAG_RELATIVE_OID	    13
/* UNIVERSAL 14-15
 * Reserved for future editions of this
 * Recommendation | International Standard
 */
#define BER_UNI_TAG_SEQUENCE		    16	/* SEQUENCE, SEQUENCE OF */
#define BER_UNI_TAG_SET					17	/* SET, SET OF */
/* UNIVERSAL 18-22 Character string types */
#define BER_UNI_TAG_NumericString	    18
#define BER_UNI_TAG_PrintableString	    19
#define BER_UNI_TAG_TeletexString	    20  /* TeletextString, T61String */
#define BER_UNI_TAG_VideotexString	    21
#define BER_UNI_TAG_IA5String		    22
/* UNIVERSAL 23-24 Time types */
#define BER_UNI_TAG_UTCTime				23
#define BER_UNI_TAG_GeneralizedTime	    24
/* UNIVERSAL 25-30 Character string types */
#define BER_UNI_TAG_GraphicString	    25
#define BER_UNI_TAG_VisibleString	    26  /* VisibleString, ISO64String */
#define BER_UNI_TAG_GeneralString	    27
#define BER_UNI_TAG_UniversalString	    28
#define BER_UNI_TAG_CHARACTERSTRING	    29
#define BER_UNI_TAG_BMPString		    30
/* UNIVERSAL 31- ...
 * Reserved for addenda to this Recommendation | International Standard
 */


/* this function dissects the identifier octer of the BER TLV.
 * We only handle TAGs (and LENGTHs) that fit inside 32 bit integers.
 */
WS_DLL_PUBLIC int get_ber_identifier(tvbuff_t *tvb, int offset, int8_t *ber_class, bool *pc, int32_t *tag);
WS_DLL_PUBLIC int dissect_ber_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, int8_t *ber_class, bool *pc, int32_t *tag);
WS_DLL_PUBLIC int dissect_unknown_ber(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
/* this function dissects the identifier octer of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
WS_DLL_PUBLIC int get_ber_length(tvbuff_t *tvb, int offset, uint32_t *length, bool *ind);
WS_DLL_PUBLIC int dissect_ber_length(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t *length, bool *ind);

WS_DLL_PUBLIC int dissect_ber_tagged_type(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, int8_t tag_cls, int32_t tag_tag, bool tag_impl, ber_type_fn type);

extern int dissect_ber_constrained_octet_string(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int32_t min_len, int32_t max_len, int hf_id, tvbuff_t **out_tvb);
WS_DLL_PUBLIC int dissect_ber_octet_string(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, tvbuff_t **out_tvb);
WS_DLL_PUBLIC int dissect_ber_octet_string_with_encoding(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, tvbuff_t **out_tvb, unsigned encoding);
extern int dissect_ber_octet_string_wcb(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, ber_callback func);

WS_DLL_PUBLIC int dissect_ber_integer64(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, int64_t *value);
extern int dissect_ber_constrained_integer64(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int64_t min_len, int64_t max_len, int hf_id, int64_t *value);

WS_DLL_PUBLIC int dissect_ber_integer(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, uint32_t *value);
extern int dissect_ber_constrained_integer(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int32_t min_len, int32_t max_len, int hf_id, uint32_t *value);

WS_DLL_PUBLIC int dissect_ber_null(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id);

WS_DLL_PUBLIC int dissect_ber_boolean(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, bool *value);
WS_DLL_PUBLIC int dissect_ber_real(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, double *value);

extern int dissect_ber_external_type(bool implicit_tag, proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, int hf_id, ber_callback func);
WS_DLL_PUBLIC int dissect_ber_EmbeddedPDV_Type(bool implicit_tag, proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, int hf_id, ber_callback func);

#define BER_FLAGS_OPTIONAL	0x00000001
#define BER_FLAGS_IMPLTAG	0x00000002
#define BER_FLAGS_NOOWNTAG	0x00000004
#define BER_FLAGS_NOTCHKTAG	0x00000008
typedef struct _ber_sequence_t {
	const int *p_id;
	int8_t	ber_class;
	int32_t	tag;
	uint32_t	flags;
	ber_callback	func;
} ber_sequence_t;

/*
 * This function dissects a BER sequence
 */
WS_DLL_PUBLIC int dissect_ber_sequence(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, int hf_id, int ett_id);
WS_DLL_PUBLIC int dissect_ber_set(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, int hf_id, int ett_id);

typedef struct _ber_choice_t {
	uint32_t	value;
	const int *p_id;
	int8_t	ber_class;
	int32_t	tag;
	uint32_t	flags;
	ber_callback	func;
} ber_choice_t;

/*
 * This function dissects a BER choice
 */
WS_DLL_PUBLIC int dissect_ber_choice(asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice_t *ch, int hf_id, int ett_id, int *branch_taken);
/* To be removed when the transition to the "New" type is complete */

/*
 * This function dissects a BER strings
 */
extern int dissect_ber_constrained_restricted_string(bool implicit_tag, int32_t type,  asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int32_t min_len, int32_t max_len, int hf_id, tvbuff_t **out_tvb);
WS_DLL_PUBLIC int dissect_ber_restricted_string(bool implicit_tag, int32_t type, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, tvbuff_t **out_tvb);
extern int dissect_ber_GeneralString(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, char *name_string, unsigned name_len);


/* this function dissects a BER Object Identifier
 */
WS_DLL_PUBLIC int dissect_ber_object_identifier(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, tvbuff_t **value_tvb);
WS_DLL_PUBLIC int dissect_ber_object_identifier_str(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, const char **value_stringx);

/* this function dissects a BER Relative Object Identifier
 */
WS_DLL_PUBLIC int dissect_ber_relative_oid(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, tvbuff_t **value_tvb);
WS_DLL_PUBLIC int dissect_ber_relative_oid_str(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, const char **value_stringx);

/* this function dissects a BER sequence of
 */
extern int dissect_ber_constrained_sequence_of(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int32_t min_len, int32_t max_len, const ber_sequence_t *seq, int hf_id, int ett_id);
WS_DLL_PUBLIC int dissect_ber_sequence_of(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, int hf_id, int ett_id);

extern int dissect_ber_constrained_set_of(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int32_t min_len, int32_t max_len, const ber_sequence_t *seq, int hf_id, int ett_id);
WS_DLL_PUBLIC int dissect_ber_set_of(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, int hf_id, int ett_id);

WS_DLL_PUBLIC int dissect_ber_GeneralizedTime(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id);

WS_DLL_PUBLIC int dissect_ber_UTCTime(bool implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id, char **datestrptr, uint32_t *tvblen);

extern int dissect_ber_constrained_bitstring(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int32_t min_len, int32_t max_len, int * const *named_bits, int num_named_bits, int hf_id, int ett_id, tvbuff_t **out_tvb);
WS_DLL_PUBLIC int dissect_ber_bitstring(bool implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int * const *named_bits, int num_named_bits, int hf_id, int ett_id, tvbuff_t **out_tvb);

WS_DLL_PUBLIC
int call_ber_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data);
WS_DLL_PUBLIC
void register_ber_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto, const char *name);
WS_DLL_PUBLIC
void register_ber_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name);
WS_DLL_PUBLIC
void register_ber_syntax_dissector(const char *syntax, int proto, dissector_t dissector);
void register_ber_oid_name(const char *oid, const char *name);
WS_DLL_PUBLIC
void register_ber_oid_syntax(const char *oid, const char *name, const char *syntax);
int dissect_ber_oid_NULL_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

WS_DLL_PUBLIC
void ber_decode_as_foreach(GHFunc func, void *user_data); /* iterate through known syntaxes */

WS_DLL_PUBLIC
bool oid_has_dissector(const char *oid);

WS_DLL_PUBLIC
void add_ber_encoded_label(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);
#endif  /* __PACKET_BER_H__ */

