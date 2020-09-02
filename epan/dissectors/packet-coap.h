/* packet-coap.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_COAP_H__
#define __PACKET_COAP_H__

#include "packet-oscore.h"

/* bitmasks */
#define COAP_VERSION_MASK					0xC0
#define COAP_TYPE_MASK						0x30
#define COAP_TOKEN_LEN_MASK					0x0F
#define COAP_BLOCK_MFLAG_MASK					0x08
#define COAP_BLOCK_SIZE_MASK					0x07
#define COAP_OBJECT_SECURITY_RESERVED_MASK			0xE0
#define COAP_OBJECT_SECURITY_KID_CONTEXT_MASK			0x10
#define COAP_OBJECT_SECURITY_KID_MASK				0x08
#define COAP_OBJECT_SECURITY_PIVLEN_MASK			0x07

/* CoAP Message information */
typedef struct {
	const gchar *ctype_str;
	guint ctype_value;
	guint block_option;                     /* Indicates Block1 or Block2 option */
	guint block_number;
	guint block_mflag;
	wmem_strbuf_t *uri_str_strbuf;		/* the maximum is 1024 > 510 = Uri-Host:255 + Uri-Path:255 x 2 */
	wmem_strbuf_t *uri_query_strbuf;	/* the maximum is 1024 >         765 = Uri-Query:255 x 3 */
	gboolean object_security;
	oscore_info_t *oscore_info;		/* OSCORE data needed to decrypt */
} coap_info;

/* CoAP Conversation information */
typedef struct {
	wmem_map_t *messages;
} coap_conv_info;

/* CoAP Transaction tracking information */
typedef struct {
	wmem_map_t    *req_rsp;
	wmem_strbuf_t *uri_str_strbuf;
	oscore_info_t *oscore_info;		/* OSCORE transaction to decrypt response */
} coap_transaction;

typedef struct {
	guint32  req_frame;
	guint32  rsp_frame;
	nstime_t req_time;
} coap_request_response;

/* common header fields, subtrees and expert info for SSL and DTLS dissectors */
typedef struct coap_common_dissect {
	struct {
		/* Header fields */
		int code;
		/* Payload fields */
		int payload;
		int payload_desc;
		int payload_length;

		/* Option fields */
		int opt_name;
		int opt_desc;
		int opt_delta;
		int opt_delta_ext;
		int opt_length;
		int opt_length_ext;
		int opt_end_marker;
		int opt_ctype;
		int opt_max_age;
		int opt_proxy_uri;
		int opt_proxy_scheme;
		int opt_size1;
		int opt_etag;
		int opt_uri_host;
		int opt_location_path;
		int opt_uri_port;
		int opt_location_query;
		int opt_uri_path;
		int opt_uri_path_recon;
		int opt_observe_req;
		int opt_observe_rsp;
		int opt_hop_limit;
		int opt_accept;
		int opt_if_match;
		int opt_block_number;
		int opt_block_mflag;
		int opt_block_size;
		int opt_uri_query;
		int opt_unknown;
		int opt_object_security_reserved;
		int opt_object_security_kid_context_present;
		int opt_object_security_kid_present;
		int opt_object_security_piv_len;
		int opt_object_security_piv;
		int opt_object_security_kid_context_len;
		int opt_object_security_kid_context;
		int opt_object_security_kid;

	/* do not forget to update COAP_COMMON_LIST_T and COAP_COMMON_HF_LIST! */
	} hf;

	struct {
		gint payload;
		gint option;

	/* do not forget to update COAP_COMMON_LIST_T and COAP_COMMON_ETT_LIST! */
	} ett;

	struct {
		/* Generic expert info for malformed packets. */
		expert_field opt_unknown_number;
		expert_field opt_invalid_number;
		expert_field opt_invalid_range;
		expert_field opt_length_bad;
		expert_field opt_object_security_bad;

        /* do not forget to update COAP_COMMON_LIST_T and COAP_COMMON_EI_LIST! */
	} ei;
} coap_common_dissect_t;

guint8 dissect_coap_code(tvbuff_t *tvb, proto_tree *coap_tree, gint *offset, coap_common_dissect_t *dissect_hf, guint8 *code_class);
int dissect_coap_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, gint offset, gint offset_end, guint8 code_class, coap_info *coinfo, coap_common_dissect_t *dissect_hf);
void dissect_coap_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, proto_tree *parent_tree, gint offset, gint offset_end, guint8 code_class, coap_info *coinfo, coap_common_dissect_t *dissect_hf, gboolean oscore);

extern const value_string coap_vals_observe_options[];
extern value_string_ext coap_vals_code_ext;

/* {{{ */
#define COAP_COMMON_LIST_T(name)						\
coap_common_dissect_t name = {							\
	/* hf */ {								\
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,				\
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,				\
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,				\
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,				\
		-1, 								\
		},								\
	/* ett */ {								\
		-1, -1,								\
		},								\
	/* ei */ {								\
		EI_INIT, EI_INIT, EI_INIT, EI_INIT, EI_INIT,			\
		},								\
}
/* }}} */

/* {{{ */
#define COAP_COMMON_HF_LIST(name, prefix)					\
	{ & name .hf.code,							\
	  { "Code", prefix ".code",						\
	    FT_UINT8, BASE_DEC | BASE_EXT_STRING, &coap_vals_code_ext, 0x0,	\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.payload,							\
	  { "Payload",  prefix ".payload",					\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.payload_desc,						\
	  { "Payload Desc",  prefix ".payload_desc",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.payload_length,						\
	  { "Payload Length",  prefix ".payload_length",			\
	    FT_UINT32, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_name,							\
	  { "Opt Name",  prefix ".opt.name",					\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_desc,							\
	  { "Opt Desc",  prefix ".opt.desc",					\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_delta,							\
	  { "Opt Delta",  prefix ".opt.delta",					\
	    FT_UINT8, BASE_DEC, NULL, 0xf0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_delta_ext,						\
	  { "Opt Delta extended",  prefix ".opt.delta_ext",			\
	    FT_UINT16, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_length,						\
	  { "Opt Length",  prefix ".opt.length",				\
	    FT_UINT8, BASE_DEC, NULL, 0x0f,					\
	    "Option Length", HFILL }						\
	},									\
	{ & name .hf.opt_length_ext,						\
	  { "Opt Length extended",  prefix ".opt.length_ext",			\
	    FT_UINT16, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_end_marker,						\
	  { "End of options marker",  prefix ".opt.end_marker",			\
	    FT_UINT8, BASE_DEC, NULL, 0x00,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_ctype,							\
	  { "Content-type",  prefix ".opt.ctype",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_max_age,						\
	  { "Max-age",  prefix ".opt.max_age",					\
	    FT_UINT32, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_proxy_uri,						\
	  { "Proxy-Uri",  prefix ".opt.proxy_uri",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_proxy_scheme,						\
	  { "Proxy-Scheme",  prefix ".opt.proxy_scheme",			\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_size1,							\
	  { "Size1",  prefix ".opt.size1",					\
	    FT_UINT32, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_etag,							\
	  { "Etag",  prefix ".opt.etag",					\
	    FT_BYTES, BASE_NONE, NULL, 0x0,					\
	    "Option Etag", HFILL }						\
	},									\
	{ & name .hf.opt_uri_host,						\
	  { "Uri-Host",  prefix ".opt.uri_host",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_location_path,						\
	  { "Location-Path",  prefix ".opt.location_path",			\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_uri_port,						\
	  { "Uri-Port",  prefix ".opt.uri_port",				\
	    FT_UINT16, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_location_query,					\
	  { "Location-Query",  prefix ".opt.location_query",			\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_reserved,				\
	  { "Reserved",  prefix ".opt.object_security_reserved",		\
	    FT_BOOLEAN, 8, NULL, COAP_OBJECT_SECURITY_RESERVED_MASK,		\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_kid_context_present,			\
	  { "Key ID Context Present",  prefix ".opt.object_security_kid_context_present",\
	    FT_BOOLEAN, 8, NULL, COAP_OBJECT_SECURITY_KID_CONTEXT_MASK,		\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_kid_present,				\
	  { "Key ID Present",  prefix ".opt.object_security_kid_present",	\
	    FT_BOOLEAN, 8, NULL, COAP_OBJECT_SECURITY_KID_MASK,			\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_piv_len,				\
	  { "Partial IV Length",  prefix ".opt.object_security_piv_len",	\
	    FT_UINT8, BASE_DEC, NULL, COAP_OBJECT_SECURITY_PIVLEN_MASK,		\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_piv,					\
	  { "Partial IV",  prefix ".opt.object_security_piv",			\
	    FT_BYTES, BASE_NONE, NULL, 0x00,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_kid_context_len,			\
	  { "Key ID Context Length",  prefix ".opt.object_security_kid_context_len",\
	    FT_UINT8, BASE_DEC, NULL, 0x00,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_kid_context,				\
	  { "Key ID Context",  prefix ".opt.object_security_kid_context",	\
	    FT_BYTES, BASE_NONE, NULL, 0x00,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_object_security_kid,					\
	  { "Key ID",  prefix ".opt.object_security_kid",			\
	    FT_BYTES, BASE_NONE, NULL, 0x00,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_uri_path,						\
	  { "Uri-Path",  prefix ".opt.uri_path",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_uri_path_recon,					\
	  { "Uri-Path",  prefix ".opt.uri_path_recon",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_observe_req,						\
	  { "Observe",  prefix ".opt.observe",					\
	    FT_UINT32, BASE_DEC, VALS(coap_vals_observe_options), 0x0,		\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_observe_rsp,						\
	  { "Observe sequence number",  prefix ".opt.observe",			\
	    FT_UINT32, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_hop_limit,						\
	  { "Hop Limit",  prefix ".opt.hop_limit",				\
	    FT_UINT8, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_accept,						\
	  { "Accept",  prefix ".opt.accept",					\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_if_match,						\
	  { "If-Match",  prefix ".opt.if_match",				\
	    FT_BYTES, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_block_number,						\
	  { "Block Number",  prefix ".opt.block_number",			\
	    FT_UINT32, BASE_DEC, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_block_mflag,						\
	  { "More Flag",  prefix ".opt.block_mflag",				\
	    FT_UINT8, BASE_DEC, NULL, COAP_BLOCK_MFLAG_MASK,			\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_block_size,						\
	  { "Encoded Block Size",  prefix ".opt.block_size",			\
	    FT_UINT8, BASE_DEC, NULL, COAP_BLOCK_SIZE_MASK,			\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_uri_query,						\
	  { "Uri-Query",  prefix ".opt.uri_query",				\
	    FT_STRING, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
	{ & name .hf.opt_unknown,						\
	  { "Unknown",  prefix ".opt.unknown",					\
	    FT_BYTES, BASE_NONE, NULL, 0x0,					\
	    NULL, HFILL }							\
	},									\
/* }}} */

/* {{{ */
#define COAP_COMMON_ETT_LIST(name)						\
	& name .ett.payload,							\
	& name .ett.option,							\

/* }}} */

/* {{{ */
#define COAP_COMMON_EI_LIST(name, prefix)					\
	{ & name .ei.opt_unknown_number,					\
	  { prefix ".unknown_option_number", PI_UNDECODED, PI_WARN,		\
	    "Unknown Option Number", EXPFILL }					\
	},									\
	{ & name .ei.opt_invalid_number,					\
	  { prefix ".invalid_option_number", PI_MALFORMED, PI_WARN,		\
	    "Invalid Option Number", EXPFILL }					\
	},									\
	{ & name .ei.opt_invalid_range,						\
	  { prefix ".invalid_option_range", PI_MALFORMED, PI_WARN,		\
	    "Invalid Option Range", EXPFILL }					\
	},									\
	{ & name .ei.opt_length_bad,						\
	  { prefix ".option_length_bad", PI_MALFORMED, PI_WARN,			\
	    "Option length bad", EXPFILL }					\
	},									\
	{ & name .ei.opt_object_security_bad,					\
	  { prefix ".option_oscore_bad", PI_MALFORMED, PI_WARN,	\
	    "Invalid OSCORE Option Format", EXPFILL }			\
	},									\

/* }}} */

#endif /* __PACKET_COAP_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
