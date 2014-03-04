/* gcp.h
 * Gateway Control Protocol -- Context Tracking
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
#ifndef __GCP_H_
#define __GCP_H_

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-q931.h>
#include <epan/dissectors/packet-mtp3.h>
#include <epan/dissectors/packet-alcap.h>
#include <epan/dissectors/packet-isup.h>

#include <epan/sctpppids.h>
#include "ws_symbol_export.h"

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
        gint ctx;
        gint ctx_cmds;
        gint ctx_terms;
        gint ctx_term;
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
    guint32 lo_addr;
    guint32 hi_addr;
    guint32 framenum;
    nstime_t time;
    struct _gcp_trx_msg_t* trxs;
    gboolean commited;
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
    guint32 id;
    gcp_trx_type_t type;
    guint pendings;
    struct _gcp_cmd_msg_t* cmds;
    struct _gcp_trx_ctx_t* ctxs;
    guint error;
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
    const gchar* str;

    const guint8* buffer;
    guint len;

    guint type;
    gchar* bir;
    gchar* nsap;

    gcp_msg_t* start;

} gcp_term_t;

typedef struct _gcp_terms_t {
    gcp_term_t* term;
    struct _gcp_terms_t* next;
    struct _gcp_terms_t* last;
} gcp_terms_t;

typedef struct _gcp_cmd_t {
    guint offset;
    const gchar* str;
    gcp_cmd_type_t type;
    gcp_terms_t terms;
    struct _gcp_msg_t* msg;
    struct _gcp_trx_t* trx;
    struct _gcp_ctx_t* ctx;
    guint error;
} gcp_cmd_t;


typedef struct _gcp_ctx_t {
    gcp_msg_t* initial;
    guint32 id;
    struct _gcp_cmd_msg_t* cmds;
    struct _gcp_ctx_t* prev;
    gcp_terms_t terms;
} gcp_ctx_t;

WS_DLL_PUBLIC const value_string gcp_cmd_type[];
WS_DLL_PUBLIC const value_string gcp_term_types[];

extern void gcp_init(void);
extern gcp_msg_t* gcp_msg(packet_info* pinfo, int o, gboolean persistent);
extern gcp_trx_t* gcp_trx(gcp_msg_t* m ,guint32 t_id , gcp_trx_type_t type, gboolean persistent);
extern gcp_ctx_t* gcp_ctx(gcp_msg_t* m, gcp_trx_t* t, guint32 c_id, gboolean persistent);
extern gcp_cmd_t* gcp_cmd(gcp_msg_t* m, gcp_trx_t* t, gcp_ctx_t* c, gcp_cmd_type_t type, guint offset, gboolean persistent);
extern gcp_term_t* gcp_cmd_add_term(gcp_msg_t* m, gcp_trx_t* tr, gcp_cmd_t* c, gcp_term_t* t, gcp_wildcard_t wildcard, gboolean persistent);
extern void gcp_analyze_msg(proto_tree* gcp_tree, packet_info* pinfo, tvbuff_t* gcp_tvb, gcp_msg_t* m, gcp_hf_ett_t* ids, expert_field* command_err);

extern const gchar* gcp_cmd_to_str(gcp_cmd_t* c, gboolean persistent);
extern const gchar* gcp_msg_to_str(gcp_msg_t* m, gboolean persistent);

#define gcp_cmd_set_error(c,e) (c->error = e)
#define gcp_trx_set_error(t,e) (t->error = e)

#define GCP_ETT_ARR_ELEMS(gi)     &(gi.ett.ctx),&(gi.ett.ctx_cmds),&(gi.ett.ctx_terms),&(gi.ett.ctx_term)

#define GCP_HF_ARR_ELEMS(n,gi) \
  { &(gi.hf.ctx), { "Context", n ".ctx", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }}, \
  { &(gi.hf.ctx_term), { "Termination", n ".ctx.term", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, \
  { &(gi.hf.ctx_term_type), { "Type", n ".ctx.term.type", FT_UINT32, BASE_HEX, VALS(gcp_term_types), 0, NULL, HFILL }}, \
  { &(gi.hf.ctx_term_bir), { "BIR", n ".ctx.term.bir", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, \
  { &(gi.hf.ctx_term_nsap), { "NSAP", n ".ctx.term.nsap", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, \
  { &(gi.hf.ctx_cmd), { "Command in Frame", n ".ctx.cmd", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }}

#endif
