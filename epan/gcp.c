/*
 * gcp.c
 * Gateway Control Protocol -- Context Tracking
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
  * TO DO:
  *  - handle text-encoded termination wildcards adequtelly
  *  - avoid persistent tracking of NULL and ALL contexts
  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "gcp.h"

static emem_tree_t* msgs = NULL;
static emem_tree_t* trxs = NULL;
static emem_tree_t* ctxs_by_trx = NULL;
static emem_tree_t* ctxs = NULL;

const value_string gcp_cmd_type[] = {
    { GCP_CMD_NONE, "NoCommand"},
    { GCP_CMD_ADD_REQ, "addReq"},
    { GCP_CMD_MOVE_REQ, "moveReq"},
    { GCP_CMD_MOD_REQ, "modReq"},
    { GCP_CMD_SUB_REQ, "subtractReq"},
    { GCP_CMD_AUDITCAP_REQ, "auditCapRequest"},
    { GCP_CMD_AUDITVAL_REQ, "auditValueRequest"},
    { GCP_CMD_NOTIFY_REQ, "notifyReq"},
    { GCP_CMD_SVCCHG_REQ, "serviceChangeReq"},
    { GCP_CMD_TOPOLOGY_REQ, "topologyReq"},
    { GCP_CMD_CTX_ATTR_AUDIT_REQ, "ctxAttrAuditReq"},
    { GCP_CMD_ADD_REPLY, "addReply"},
    { GCP_CMD_MOVE_REPLY, "moveReply"},
    { GCP_CMD_MOD_REPLY, "modReply"},
    { GCP_CMD_SUB_REPLY, "subtractReply"},
    { GCP_CMD_AUDITCAP_REPLY, "auditCapReply"},
    { GCP_CMD_AUDITVAL_REPLY, "auditValReply"},
    { GCP_CMD_NOTIFY_REPLY, "notifyReply"},
    { GCP_CMD_SVCCHG_REPLY, "serviceChangeReply"},
    { GCP_CMD_TOPOLOGY_REPLY, "topologyReply"},
    { 0, NULL }
};

const value_string gcp_term_types[] = {
    { GCP_TERM_TYPE_AAL1, "aal1" },
    { GCP_TERM_TYPE_AAL2, "aal2" },
    { GCP_TERM_TYPE_AAL1_STRUCT, "aal1struct" },
    { GCP_TERM_TYPE_IP_RTP, "ipRtp" },
    { GCP_TERM_TYPE_TDM, "tdm" },
    { 0, NULL }
};


void gcp_init(void) {
    static gboolean gcp_initialized = FALSE;

    if (gcp_initialized)
        return;

    msgs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "gcp_msgs");
    trxs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "gcp_trxs");
    ctxs_by_trx = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "gcp_ctxs_by_trx");
    ctxs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "gcp_ctxs");
    gcp_initialized = TRUE;
}

gcp_msg_t* gcp_msg(packet_info* pinfo, int o, gboolean keep_persistent_data) {
    gcp_msg_t* m;
    guint32 framenum = (guint32)pinfo->fd->num;
    guint32 offset = (guint32)o;
    address* src = &(pinfo->src);
    address* dst = &(pinfo->dst);
    address* lo_addr;
    address* hi_addr;

    if (keep_persistent_data) {
        emem_tree_key_t key[] = {
            {1,&(framenum)},
            {1,&offset},
            {0,NULL}
        };

        if (( m = se_tree_lookup32_array(msgs,key) )) {
            m->commited = TRUE;
            return m;
        } else {
            m = se_alloc(sizeof(gcp_msg_t));
            m->framenum = framenum;
            m->time = pinfo->fd->abs_ts;
            m->trxs = NULL;
            m->commited = FALSE;

            se_tree_insert32_array(msgs,key,m);
        }
    } else {
        m = ep_new0(gcp_msg_t);
        m->framenum = framenum;
        m->trxs = NULL;
        m->commited = FALSE;
    }

    if (CMP_ADDRESS(src, dst) < 0)  {
        lo_addr = src;
        hi_addr = dst;
    } else {
        lo_addr = dst;
        hi_addr = src;
    }

    switch(lo_addr->type) {
        case AT_NONE:
            m->lo_addr = 0;
            m->hi_addr = 0;
            break;
        case AT_IPv4:
            memcpy((guint8*)&(m->hi_addr),hi_addr->data,4);
            memcpy((guint8*)&(m->lo_addr),lo_addr->data,4);
            break;
        case AT_SS7PC:
            m->hi_addr = mtp3_pc_hash((const mtp3_addr_pc_t *)hi_addr->data);
            m->lo_addr = mtp3_pc_hash((const mtp3_addr_pc_t *)lo_addr->data);
            break;
        default:
            /* XXX: heuristic and error prone */
            m->hi_addr = g_str_hash(ep_address_to_str(hi_addr));
            m->lo_addr = g_str_hash(ep_address_to_str(lo_addr));
        break;
    }

    return m;
}

gcp_trx_t* gcp_trx(gcp_msg_t* m ,guint32 t_id , gcp_trx_type_t type, gboolean keep_persistent_data) {
    gcp_trx_t* t = NULL;
    gcp_trx_msg_t* trxmsg;

    if ( !m ) return NULL;

    if (keep_persistent_data) {
        if (m->commited) {

            for ( trxmsg = m->trxs; trxmsg; trxmsg = trxmsg->next) {
                if (trxmsg->trx && trxmsg->trx->id == t_id) {
                    return trxmsg->trx;
                }
            }
            DISSECTOR_ASSERT_NOT_REACHED();
        } else {
            emem_tree_key_t key[] = {
                {1,&(m->hi_addr)},
                {1,&(m->lo_addr)},
                {1,&(t_id)},
                {0,NULL}
            };

            trxmsg = se_alloc(sizeof(gcp_trx_msg_t));
            t = se_tree_lookup32_array(trxs,key);

            if (!t) {
                t = se_alloc(sizeof(gcp_trx_t));
                t->initial = m;
                t->id = t_id;
                t->type = type;
                t->pendings = 0;
                t->error = 0;
                t->cmds = NULL;

                se_tree_insert32_array(trxs,key,t);
            }

            /* XXX: request, reply and ack + point to frames where they are */
            switch ( type ) {
                case GCP_TRX_PENDING:
                    t->pendings++;
                    break;
                default:
                    break;
            }

        }
    } else {
        t = ep_new(gcp_trx_t);
        trxmsg = ep_new(gcp_trx_msg_t);
        t->initial = NULL;
        t->id = t_id;
        t->type = type;
        t->pendings = 0;
        t->error = 0;
        t->cmds = NULL;
    }

    DISSECTOR_ASSERT(trxmsg);

    trxmsg->trx = t;
    trxmsg->next = NULL;
    trxmsg->last = trxmsg;

    if (m->trxs) {
        m->trxs->last = m->trxs->last->next = trxmsg;
    } else {
        m->trxs = trxmsg;
    }

    return t;
}


gcp_ctx_t* gcp_ctx(gcp_msg_t* m, gcp_trx_t* t, guint32 c_id, gboolean persistent) {
    gcp_ctx_t* context = NULL;
    gcp_ctx_t** context_p = NULL;

    if ( !m || !t ) return NULL;

    if (persistent) {

        emem_tree_key_t ctx_key[] = {
            {1,&(m->hi_addr)},
            {1,&(m->lo_addr)},
            {1,&(c_id)},
            {0,NULL}
        };

        emem_tree_key_t trx_key[] = {
            {1,&(m->hi_addr)},
            {1,&(m->lo_addr)},
            {1,&(t->id)},
            {0,NULL}
        };

        if (m->commited) {
            if (( context = se_tree_lookup32_array(ctxs_by_trx,trx_key) )) {
                return context;
            } if ((context_p = se_tree_lookup32_array(ctxs,ctx_key))) {
                context = *context_p;

                do {
                    if (context->initial->framenum <= m->framenum) {
                        return context;
                    }
                } while(( context = context->prev ));

                DISSECTOR_ASSERT(! "a context should exist");
            }
        } else {
            if (c_id == CHOOSE_CONTEXT) {
                if (! ( context = se_tree_lookup32_array(ctxs_by_trx,trx_key))) {
                    context = se_alloc(sizeof(gcp_ctx_t));
                    context->initial = m;
                    context->cmds = NULL;
                    context->id = c_id;
                    context->terms.last = &(context->terms);
                    context->terms.next = NULL;
                    context->terms.term = NULL;

                    se_tree_insert32_array(ctxs_by_trx,trx_key,context);
                }
            } else {
                if (( context = se_tree_lookup32_array(ctxs_by_trx,trx_key) )) {
                    if (( context_p = se_tree_lookup32_array(ctxs,ctx_key) )) {
                        if (context != *context_p) {
                            context = se_alloc(sizeof(gcp_ctx_t));
                            context->initial = m;
                            context->id = c_id;
                            context->cmds = NULL;
                            context->terms.last = &(context->terms);
                            context->terms.next = NULL;
                            context->terms.term = NULL;

                            context->prev = *context_p;
                            *context_p = context;
                        }
                    } else {
                        context_p = se_alloc(sizeof(void*));
                        *context_p = context;
                        context->initial = m;
                        context->id = c_id;
                        se_tree_insert32_array(ctxs,ctx_key,context_p);
                    }
                } else if (! ( context_p = se_tree_lookup32_array(ctxs,ctx_key) )) {
                    context = se_alloc(sizeof(gcp_ctx_t));
                    context->initial = m;
                    context->id = c_id;
                    context->cmds = NULL;
                    context->terms.last = &(context->terms);
                    context->terms.next = NULL;
                    context->terms.term = NULL;

                    context_p = se_alloc(sizeof(void*));
                    *context_p = context;
                    se_tree_insert32_array(ctxs,ctx_key,context_p);
                } else {
                    context = *context_p;
                }
            }
        }
    } else {
        context = ep_new(gcp_ctx_t);
        context->initial = m;
        context->cmds = NULL;
        context->id = c_id;
        context->terms.last = &(context->terms);
        context->terms.next = NULL;
        context->terms.term = NULL;
    }

    return context;
}

gcp_cmd_t* gcp_cmd(gcp_msg_t* m, gcp_trx_t* t, gcp_ctx_t* c, gcp_cmd_type_t type, guint offset, gboolean persistent) {
    gcp_cmd_t* cmd;
    gcp_cmd_msg_t* cmdtrx;
    gcp_cmd_msg_t* cmdctx;

    if ( !m || !t || !c ) return NULL;

    if (persistent) {
        if (m->commited) {
            DISSECTOR_ASSERT(t->cmds != NULL);

            for (cmdctx = t->cmds; cmdctx; cmdctx = cmdctx->next) {
                cmd = cmdctx->cmd;
                if (cmd->msg == m && cmd->offset == offset) {
                    return cmd;
                }
            }

            DISSECTOR_ASSERT(!"called for a command that does not exist!");

            return NULL;
        } else {
            cmd = se_alloc(sizeof(gcp_cmd_t));
            cmdtrx = se_alloc(sizeof(gcp_cmd_msg_t));
            cmdctx = se_alloc(sizeof(gcp_cmd_msg_t));
        }
    } else {
        cmd = ep_new(gcp_cmd_t);
        cmdtrx = ep_new(gcp_cmd_msg_t);
        cmdctx = ep_new(gcp_cmd_msg_t);
    }

    cmd->type = type;
    cmd->offset = offset;
    cmd->terms.term = NULL;
    cmd->terms.next = NULL;
    cmd->terms.last = &(cmd->terms);
    cmd->str = NULL;
    cmd->msg = m;
    cmd->trx = t;
    cmd->ctx = c;
    cmd->error = 0;

    cmdctx->cmd = cmdtrx->cmd = cmd;
    cmdctx->next =  cmdtrx->next = NULL;
    cmdctx->last = cmdtrx->last = NULL;

    if (t->cmds) {
        t->cmds->last->next = cmdtrx;
        t->cmds->last = cmdtrx;
    } else {
        t->cmds = cmdtrx;
        t->cmds->last = cmdtrx;
    }

    if (c->cmds) {
        c->cmds->last->next = cmdctx;
        c->cmds->last = cmdctx;
    } else {
        c->cmds = cmdctx;
        c->cmds->last = cmdctx;
    }

    return cmd;
}


gcp_term_t* gcp_cmd_add_term(gcp_msg_t* m, gcp_trx_t* tr, gcp_cmd_t* c, gcp_term_t* t, gcp_wildcard_t wildcard, gboolean persistent) {
    gcp_terms_t* ct;
    gcp_terms_t* ct2;

    static gcp_term_t all_terms = {"$",(guint8*)"",1,GCP_TERM_TYPE_UNKNOWN,NULL,NULL,NULL};

    if ( !c ) return NULL;

    if ( wildcard == GCP_WILDCARD_CHOOSE) {
        return &all_terms;
    }

    if (persistent) {
        if ( c->msg->commited ) {
            if (wildcard == GCP_WILDCARD_ALL) {
                for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                    /* XXX not handling more wilcards in one msg */
                    if ( ct->term->start == m ) {
                        return ct->term;
                    }
                }
                return NULL;
            } else {
                for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                    if ( g_str_equal(ct->term->str,t->str) ) {
                        return ct->term;
                    }
                }
                return NULL;
            }
        } else {

            for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                if ( g_str_equal(ct->term->str,t->str) || ct->term->start == m) {
                    break;
                }
            }

            if ( ! ct ) {

                if (wildcard == GCP_WILDCARD_ALL) {
                    ct = se_alloc(sizeof(gcp_terms_t));
                    ct->next = NULL;
                    ct->term = se_alloc0(sizeof(gcp_term_t));

                    ct->term->start = m;
                    ct->term->str = "*";
                    ct->term->buffer = NULL;
                    ct->term->len = 0;

                    c->terms.last = c->terms.last->next = ct;

                    ct2 = se_alloc0(sizeof(gcp_terms_t));
                    ct2->term = ct->term;

                    c->ctx->terms.last->next = ct2;
                    c->ctx->terms.last = ct2;

                    return ct->term;
                } else {
                    for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                        /* XXX not handling more wilcards in one msg */
                        if ( ct->term->buffer == NULL && tr->cmds->cmd->msg == ct->term->start ) {
                            ct->term->str = se_strdup(t->str);
                            ct->term->buffer = se_memdup(t->buffer,t->len);
                            ct->term->len = t->len;

                            ct2 = se_alloc0(sizeof(gcp_terms_t));
                            ct2->term = ct->term;

                            c->terms.last = c->terms.last->next = ct2;

                            return ct->term;
                        }

                        if  ( g_str_equal(ct->term->str,t->str) ) {
                            ct2 = se_alloc0(sizeof(gcp_terms_t));
                            ct2->term = ct->term;

                            c->terms.last = c->terms.last->next = ct2;

                            return ct->term;
                        }
                    }

                    ct = se_alloc(sizeof(gcp_terms_t));
                    ct->next = NULL;
                    ct->term = se_alloc0(sizeof(gcp_term_t));

                    ct->term->start = m;
                    ct->term->str = se_strdup(t->str);
                    ct->term->buffer = se_memdup(t->buffer,t->len);
                    ct->term->len = t->len;

                    ct2 = se_alloc0(sizeof(gcp_terms_t));
                    ct2->term = ct->term;

                    c->terms.last = c->terms.last->next = ct2;

                    ct2 = se_alloc0(sizeof(gcp_terms_t));
                    ct2->term = ct->term;

                    c->ctx->terms.last = c->ctx->terms.last->next = ct2;

                    return ct->term;
                }
            } else {
                ct2 = se_alloc0(sizeof(gcp_terms_t));
                ct2->term = ct->term;

                c->terms.last = c->terms.last->next = ct2;
                return ct->term;
            }

            DISSECTOR_ASSERT_NOT_REACHED();
        }
    } else {
        ct = ep_new(gcp_terms_t);
        ct->term = t;
        ct->next = NULL;
        c->terms.last = c->terms.last->next = ct;

        return t;
    }

}

gchar* gcp_cmd_to_str(gcp_cmd_t* c, gboolean persistent) {
    gchar* s;
    gcp_terms_t* term;

    if ( !c ) return "-";

    switch (c->type) {
        case GCP_CMD_NONE:
            return "-";
            break;
        case GCP_CMD_ADD_REQ:
            s = "AddReq {";
            break;
        case GCP_CMD_MOVE_REQ:
            s = "MoveReq {";
            break;
        case GCP_CMD_MOD_REQ:
            s = "ModReq {";
            break;
        case GCP_CMD_SUB_REQ:
            s = "SubReq {";
            break;
        case GCP_CMD_AUDITCAP_REQ:
            s = "AuditCapReq {";
            break;
        case GCP_CMD_AUDITVAL_REQ:
            s = "AuditValReq {";
            break;
        case GCP_CMD_NOTIFY_REQ:
            s = "NotifyReq {";
            break;
        case GCP_CMD_SVCCHG_REQ:
            s = "SvcChgReq {";
            break;
        case GCP_CMD_TOPOLOGY_REQ:
            s = "TopologyReq {";
            break;
        case GCP_CMD_CTX_ATTR_AUDIT_REQ:
            s = "CtxAttribAuditReq {";
            break;
        case GCP_CMD_ADD_REPLY:
            s = "AddReply {";
            break;
        case GCP_CMD_MOVE_REPLY:
            s = "MoveReply {";
            break;
        case GCP_CMD_MOD_REPLY:
            s = "ModReply {";
            break;
        case GCP_CMD_SUB_REPLY:
            s = "SubReply {";
            break;
        case GCP_CMD_AUDITCAP_REPLY:
            s = "AuditCapReply {";
            break;
        case GCP_CMD_AUDITVAL_REPLY:
            s = "AuditValReply {";
            break;
        case GCP_CMD_NOTIFY_REPLY:
            s = "NotifyReply {";
            break;
        case GCP_CMD_SVCCHG_REPLY:
            s = "SvcChgReply {";
            break;
        case GCP_CMD_TOPOLOGY_REPLY:
            s = "TopologyReply {";
            break;
        case GCP_CMD_REPLY:
            s = "ActionReply {";
            break;
        case GCP_CMD_OTHER_REQ:
            s = "Request {";
            break;
        default:
            s = "-";
            break;
    }

    for (term = c->terms.next; term; term = term->next) {
        s = ep_strdup_printf("%s %s",s,term->term->str);
    }

    if (c->error) {
        s = ep_strdup_printf("%s Error=%i",s,c->error);
    }

    s = ep_strdup_printf("%s }", s);

    if (persistent) {
        if (! c->str) c->str = se_strdup(s);
    } else {
        c->str = s;
    }

    return s;
}

static gchar* gcp_trx_to_str(gcp_msg_t* m, gcp_trx_t* t, gboolean persistent) {
    gchar* s;
    gcp_cmd_msg_t* c;

    if ( !m || !t ) return "-";

    s = ep_strdup_printf("T %x { ",t->id);

    if (t->cmds) {
        if (t->cmds->cmd->ctx) {
            s = ep_strdup_printf("%s C %x {",s,t->cmds->cmd->ctx->id);

            for (c = t->cmds; c; c = c->next) {
                if (c->cmd->msg == m) {
                    s = ep_strdup_printf("%s %s",s,gcp_cmd_to_str(c->cmd,persistent));
                }
            }

            s = ep_strdup_printf("%s %s",s,"}");
        }
    }

    if (t->error) {
        s = ep_strdup_printf("%s Error=%i",s,t->error);
    }

    return ep_strdup_printf("%s %s",s,"}");
}

gchar* gcp_msg_to_str(gcp_msg_t* m, gboolean persistent) {
    gcp_trx_msg_t* t;
    gchar* s = "";

    if ( !m ) return "-";

    for (t = m->trxs; t; t = t->next) {
        s = ep_strdup_printf("%s %s",s,gcp_trx_to_str(m,t->trx, persistent));
    }

    return s;
}

typedef struct _gcp_ctxs_t {
    struct _gcp_ctx_t* ctx;
    struct _gcp_ctxs_t* next;
} gcp_ctxs_t;

/*static const gchar* trx_types[] = {"None","Req","Reply","Pending","Ack"};*/

void gcp_analyze_msg(proto_tree* gcp_tree, tvbuff_t* gcp_tvb, gcp_msg_t* m, gcp_hf_ett_t* ids) {
    gcp_trx_msg_t* t;
    gcp_ctxs_t contexts = {NULL,NULL};
    gcp_ctxs_t* ctx_node;
    gcp_cmd_msg_t* c;


    for (t = m->trxs; t; t = t->next) {
        for (c = t->trx->cmds; c; c = c->next) {
            gcp_ctx_t* ctx = c->cmd->ctx;

            for (ctx_node = contexts.next; ctx_node; ctx_node = ctx_node->next) {
                if (ctx_node->ctx->id == ctx->id) {
                    break;
                }
            }

            if (! ctx_node) {
                ctx_node = ep_new(gcp_ctxs_t);
                ctx_node->ctx = ctx;
                ctx_node->next = contexts.next;
                contexts.next = ctx_node;
            }
        }
    }

    for (ctx_node = contexts.next; ctx_node; ctx_node = ctx_node->next) {
        gcp_ctx_t* ctx = ctx_node->ctx;
        proto_item* ctx_item = proto_tree_add_uint(gcp_tree,ids->hf.ctx,gcp_tvb,0,0,ctx->id);
        proto_tree* ctx_tree = proto_item_add_subtree(ctx_item,ids->ett.ctx);
        gcp_terms_t *ctx_term;

        PROTO_ITEM_SET_GENERATED(ctx_item);

        if (ctx->cmds) {
            proto_item* history_item = proto_tree_add_text(ctx_tree,gcp_tvb,0,0,"[ Command History ]");
            proto_tree* history_tree = proto_item_add_subtree(history_item,ids->ett.ctx_cmds);

            for (c = ctx->cmds; c; c = c->next) {
                proto_item* cmd_item = proto_tree_add_uint(history_tree,ids->hf.ctx_cmd,gcp_tvb,0,0,c->cmd->msg->framenum);
                if (c->cmd->str) proto_item_append_text(cmd_item,"  %s ",c->cmd->str);
                PROTO_ITEM_SET_GENERATED(cmd_item);
                if (c->cmd->error) {
                    proto_item_set_expert_flags(cmd_item, PI_RESPONSE_CODE, PI_WARN);
                }
            }
        }

        if (( ctx_term = ctx->terms.next )) {
            proto_item* terms_item = proto_tree_add_text(ctx_tree,gcp_tvb,0,0,"[ Terminations Used ]");
            proto_tree* terms_tree = proto_item_add_subtree(terms_item,ids->ett.ctx_terms);

            for (; ctx_term; ctx_term = ctx_term->next ) {
                if ( ctx_term->term && ctx_term->term->str) {
                    proto_item* pi = proto_tree_add_string(terms_tree,ids->hf.ctx_term,gcp_tvb,0,0,ctx_term->term->str);
                    proto_tree* term_tree = proto_item_add_subtree(pi,ids->ett.ctx_term);

                    PROTO_ITEM_SET_GENERATED(pi);

                    if (ctx_term->term->type) {
                        pi = proto_tree_add_uint(term_tree,ids->hf.ctx_term_type,gcp_tvb,0,0,ctx_term->term->type);
                        PROTO_ITEM_SET_GENERATED(pi);
                    }

                    if (ctx_term->term->bir) {
                        pi = proto_tree_add_string(term_tree,ids->hf.ctx_term_bir,gcp_tvb,0,0,ctx_term->term->bir);
                        PROTO_ITEM_SET_GENERATED(pi);
                    }

                    if (ctx_term->term->nsap) {
                        pi = proto_tree_add_string(term_tree,ids->hf.ctx_term_nsap,gcp_tvb,0,0,ctx_term->term->nsap);
                        PROTO_ITEM_SET_GENERATED(pi);
                    }

                    if (ctx_term->term->bir && ctx_term->term->nsap) {
                        gchar* tmp_key = ep_strdup_printf("%s:%s",ctx_term->term->nsap,ctx_term->term->bir);
						gchar* key = g_ascii_strdown(tmp_key, -1);
                        alcap_tree_from_bearer_key(term_tree, gcp_tvb, key);
						g_free(key);
                    }
                }
            }
        }
    }
}
