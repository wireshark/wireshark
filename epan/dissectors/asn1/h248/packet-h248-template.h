/* packet-h248.h
 * Definitions for H.248/MEGACO packet dissection
 *
 * Ronnie Sahlberg 2004
 * Luis Ontanon 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_H248_H
#define PACKET_H248_H

#include "ws_symbol_export.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/nstime.h>

/* Gateway Control Protocol -- Context Tracking */

typedef struct _gcp_hf_ett_t {
	struct {
		int ctx;
		int ctx_cmd;
		int ctx_term;
		int ctx_term_type;
		int ctx_term_bir;
		int ctx_term_nsap;
	} hf;

	struct {
		int ctx;
		int ctx_cmds;
		int ctx_terms;
		int ctx_term;
	} ett;
} gcp_hf_ett_t;

#define NULL_CONTEXT 0
#define CHOOSE_CONTEXT 0xFFFFFFFE
#define ALL_CONTEXTS 0xFFFFFFFF


typedef enum {
	GCP_CMD_NONE,
	GCP_CMD_ADD_REQ,
	GCP_CMD_MOVE_REQ,
	GCP_CMD_MOD_REQ,
	GCP_CMD_SUB_REQ,
	GCP_CMD_AUDITCAP_REQ,
	GCP_CMD_AUDITVAL_REQ,
	GCP_CMD_NOTIFY_REQ,
	GCP_CMD_SVCCHG_REQ,
	GCP_CMD_TOPOLOGY_REQ,
	GCP_CMD_CTX_ATTR_AUDIT_REQ,
	GCP_CMD_OTHER_REQ,
	GCP_CMD_ADD_REPLY,
	GCP_CMD_MOVE_REPLY,
	GCP_CMD_MOD_REPLY,
	GCP_CMD_SUB_REPLY,
	GCP_CMD_AUDITCAP_REPLY,
	GCP_CMD_AUDITVAL_REPLY,
	GCP_CMD_NOTIFY_REPLY,
	GCP_CMD_SVCCHG_REPLY,
	GCP_CMD_TOPOLOGY_REPLY,
	GCP_CMD_REPLY
} gcp_cmd_type_t;

typedef enum {
	GCP_TRX_NONE,
	GCP_TRX_REQUEST,
	GCP_TRX_PENDING,
	GCP_TRX_REPLY,
	GCP_TRX_ACK
} gcp_trx_type_t;


typedef struct _gcp_msg_t {
	uint32_t lo_addr;
	uint32_t hi_addr;
	uint32_t framenum;
	nstime_t frametime;
	struct _gcp_trx_msg_t* trxs;
	bool committed;
} gcp_msg_t;

typedef struct _gcp_trx_msg_t {
	struct _gcp_trx_t* trx;
	struct _gcp_trx_msg_t* next;
	struct _gcp_trx_msg_t* last;
} gcp_trx_msg_t;

typedef struct _gcp_cmd_msg_t {
	struct _gcp_cmd_t* cmd;
	struct _gcp_cmd_msg_t* next;
	struct _gcp_cmd_msg_t* last;
} gcp_cmd_msg_t;

typedef struct _gcp_trx_t {
	gcp_msg_t* initial;
	uint32_t id;
	gcp_trx_type_t type;
	unsigned pendings;
	struct _gcp_cmd_msg_t* cmds;
	struct _gcp_trx_ctx_t* ctxs;
	unsigned error;
} gcp_trx_t;

#define GCP_TERM_TYPE_UNKNOWN 0
#define GCP_TERM_TYPE_AAL1 1
#define GCP_TERM_TYPE_AAL2 2
#define GCP_TERM_TYPE_AAL1_STRUCT 3
#define GCP_TERM_TYPE_IP_RTP 4
#define GCP_TERM_TYPE_TDM 5

typedef enum _gcp_wildcard_t {
	GCP_WILDCARD_NONE,
	GCP_WILDCARD_CHOOSE,
	GCP_WILDCARD_ALL
} gcp_wildcard_t;

typedef struct _gcp_term_t {
	const char* str;

	const uint8_t* buffer;
	unsigned len;

	unsigned type;
	char* bir;
	char* nsap;

	gcp_msg_t* start;

} gcp_term_t;

typedef struct _gcp_terms_t {
	gcp_term_t* term;
	struct _gcp_terms_t* next;
	struct _gcp_terms_t* last;
} gcp_terms_t;

typedef struct _gcp_cmd_t {
	unsigned offset;
	const char* str;
	gcp_cmd_type_t type;
	gcp_terms_t terms;
	struct _gcp_msg_t* msg;
	struct _gcp_trx_t* trx;
	struct _gcp_ctx_t* ctx;
	unsigned error;
} gcp_cmd_t;


typedef struct _gcp_ctx_t {
	gcp_msg_t* initial;
	uint32_t id;
	struct _gcp_cmd_msg_t* cmds;
	struct _gcp_ctx_t* prev;
	gcp_terms_t terms;
} gcp_ctx_t;

extern gcp_msg_t* gcp_msg(packet_info* pinfo, int o, bool persistent);
extern gcp_trx_t* gcp_trx(gcp_msg_t* m ,uint32_t t_id , gcp_trx_type_t type, packet_info *pinfo, bool persistent);
extern gcp_ctx_t* gcp_ctx(gcp_msg_t* m, gcp_trx_t* t, uint32_t c_id, packet_info *pinfo, bool persistent);
extern gcp_cmd_t* gcp_cmd(gcp_msg_t* m, gcp_trx_t* t, gcp_ctx_t* c, gcp_cmd_type_t type, unsigned offset, packet_info *pinfo, bool persistent);
extern gcp_term_t* gcp_cmd_add_term(gcp_msg_t* m, gcp_trx_t* tr, gcp_cmd_t* c, gcp_term_t* t, gcp_wildcard_t wildcard, packet_info *pinfo, bool persistent);
extern void gcp_analyze_msg(proto_tree* gcp_tree, packet_info* pinfo, tvbuff_t* gcp_tvb, gcp_msg_t* m, gcp_hf_ett_t* ids, expert_field* command_err);

#define GCP_ETT_ARR_ELEMS(gi)     &(gi.ett.ctx),&(gi.ett.ctx_cmds),&(gi.ett.ctx_terms),&(gi.ett.ctx_term)

#define GCP_HF_ARR_ELEMS(n,gi) \
	{ &(gi.hf.ctx), { "Context", n ".ctx", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }}, \
	{ &(gi.hf.ctx_term), { "Termination", n ".ctx.term", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, \
	{ &(gi.hf.ctx_term_type), { "Type", n ".ctx.term.type", FT_UINT32, BASE_HEX, VALS(gcp_term_types), 0, NULL, HFILL }}, \
	{ &(gi.hf.ctx_term_bir), { "BIR", n ".ctx.term.bir", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, \
	{ &(gi.hf.ctx_term_nsap), { "NSAP", n ".ctx.term.nsap", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, \
	{ &(gi.hf.ctx_cmd), { "Command in Frame", n ".ctx.cmd", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }}

WS_DLL_PUBLIC const value_string gcp_cmd_type[];
WS_DLL_PUBLIC const value_string gcp_term_types[];

extern const char* gcp_msg_to_str(gcp_msg_t* m, wmem_allocator_t *scope, bool persistent);

#define gcp_cmd_set_error(c,e) (c->error = e)
#define gcp_trx_set_error(t,e) (t->error = e)

/* END Gateway Control Protocol -- Context Tracking */

typedef struct _h248_curr_info_t h248_curr_info_t;

typedef void (*h248_pkg_param_dissector_t)(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo _U_, int hfid, h248_curr_info_t*, void*);

extern void h248_param_bytes_item(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_uint_item(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
WS_DLL_PUBLIC void h248_param_ber_integer(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_octetstring(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_boolean(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void external_dissector(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* dissector_handle);
extern void h248_param_PkgdName(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl);
extern void h248_param_external_dissector(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl);

typedef enum {
	ADD_PKG,	/* add package at registration ONLY if no matching package ID */
	REPLACE_PKG,	/* replace/add package at registration */
	MERGE_PKG_HIGH,		/* merge h248_package_t at registration favor new package */
	MERGE_PKG_LOW		/* merge h248_package_t at registration favor current package */
} pkg_reg_action;

typedef struct _h248_pkg_param_t {
	uint32_t id;
	int* hfid;
	h248_pkg_param_dissector_t dissector;
	void* data;
} h248_pkg_param_t;

typedef struct _h248_pkg_sig_t {
	uint32_t id;
	int* hfid;
	int* ett;
	const h248_pkg_param_t* parameters;
	const value_string* param_names;
} h248_pkg_sig_t;

typedef struct _h248_pkg_evt_t {
	uint32_t id;
	int* hfid;
	int* ett;
	const h248_pkg_param_t* parameters;
	const value_string* param_names;
} h248_pkg_evt_t;

typedef struct _h248_pkg_stat_t {
	uint32_t id;
	int* hfid;
	int* ett;
	const h248_pkg_param_t* parameters;
	const value_string* param_names;
} h248_pkg_stat_t;

typedef struct _h248_package_t {
	uint32_t id;                            /**< Package ID */
	int* hfid;                             /**< hfid that will display the package name */
	int* ett;                             /**< The ett for this item */
	const value_string* param_names;       /**< The parameter names, Value 00000 should be the package name */
	const value_string* signal_names;
	const value_string* event_names;
	const value_string* stats_names;
	const h248_pkg_param_t* properties;
	const h248_pkg_sig_t* signals;
	const h248_pkg_evt_t* events;
	const h248_pkg_stat_t* statistics;
} h248_package_t;

typedef struct _save_h248_package_t {
	h248_package_t *pkg;
	bool is_default;
} s_h248_package_t;

struct _h248_curr_info_t {
	gcp_ctx_t* ctx;
	gcp_trx_t* trx;
	gcp_msg_t* msg;
	gcp_term_t* term;
	gcp_cmd_t* cmd;
	const h248_package_t* pkg;
	const h248_pkg_evt_t* evt;
	const h248_pkg_sig_t* sig;
	const h248_pkg_stat_t* stat;
	const h248_pkg_param_t* par;
};

typedef struct h248_term_info {
	uint8_t wild_card;
	char *str;
} h248_term_info_t;

WS_DLL_PUBLIC
void h248_register_package(h248_package_t* pkg, pkg_reg_action reg_action);

#endif  /* PACKET_H248_H */
