/* packet-megaco.c
 * Routines for megaco packet disassembly
 * RFC 3015
 *
 * Christian Falckenberg, 2002/10/17
 * Copyright (c) 2002 by Christian Falckenberg
 *                       <christian.falckenberg@nortelnetworks.com>
 *
 * Christoph Wiest,      2003/06/28
 * Modified 2003 by      Christoph Wiest
 *                       <ch.wiest@tesionmail.de>
 * Modified 2004 by      Anders Broman
 *                       <anders.broman@ericsson.com>
 * To handle TPKT headers if over TCP
 * Modified 2005 by      Karl Knoebl
 *                       <karl.knoebl@siemens.com>
 *   provide info to COL_INFO and some "prettification"
 *
 * Copyright (c) 2006 Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/tap.h>
#include <epan/rtd_table.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/exported_pdu.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <wsutil/strtoi.h>
#include "packet-ber.h"
#include "packet-tpkt.h"
#include "packet-h245.h"
#include "packet-h248.h"
#include "packet-ip.h"
#include "packet-http.h"
#include "packet-sdp.h"

void proto_register_megaco(void);
void proto_reg_handoff_megaco(void);

#define PORT_MEGACO_TXT 2944
#define PORT_MEGACO_BIN 2945

static pref_t *sip_hide_generated_call_ids;


/* Define the megaco proto */
static int proto_megaco         = -1;

/* Define headers for megaco */
static int hf_megaco_start          = -1;
static int hf_megaco_version        = -1;
static int hf_megaco_transaction    = -1;
static int hf_megaco_transid        = -1;
static int hf_megaco_Context        = -1;
/* static int hf_megaco_command_line   = -1; */
static int hf_megaco_command        = -1;
static int hf_megaco_command_optional = -1;
static int hf_megaco_wildcard_response = -1;
static int hf_megaco_termid         = -1;



/* Define headers in subtree for megaco */
static int hf_megaco_modem_descriptor           = -1;
static int hf_megaco_multiplex_descriptor       = -1;
static int hf_megaco_media_descriptor           = -1;
static int hf_megaco_Local_descriptor           = -1;
static int hf_megaco_events_descriptor          = -1;
static int hf_megaco_signal_descriptor          = -1;
static int hf_megaco_audit_descriptor           = -1;
/* static int hf_megaco_servicechange_descriptor   = -1; */
static int hf_megaco_digitmap_descriptor        = -1;
static int hf_megaco_statistics_descriptor      = -1;
static int hf_megaco_observedevents_descriptor  = -1;
static int hf_megaco_topology_descriptor        = -1;
static int hf_megaco_error_descriptor           = -1;
static int hf_megaco_error_code                 = -1;
static int hf_megaco_error_string               = -1;
static int hf_megaco_TerminationState_descriptor= -1;
static int hf_megaco_Remote_descriptor          = -1;
static int hf_megaco_LocalControl_descriptor    = -1;
static int hf_megaco_packages_descriptor        = -1;
static int hf_megaco_Service_State              = -1;
static int hf_megaco_Event_Buffer_Control       = -1;
static int hf_megaco_mode                       = -1;
static int hf_megaco_reserve_group              = -1;
static int hf_megaco_h324_muxtbl_in             = -1;
static int hf_megaco_h324_muxtbl_out            = -1;
static int hf_megaco_ds_dscp                    = -1;
static int hf_megaco_gm_saf                     = -1;
static int hf_megaco_gm_sam                     = -1;
static int hf_megaco_gm_spf                     = -1;
static int hf_megaco_gm_spr                     = -1;
static int hf_megaco_gm_esas                    = -1;
static int hf_megaco_tman_pol                   = -1;
static int hf_megaco_gm_rsb                     = -1;
static int hf_megaco_tman_sdr                   = -1;
static int hf_megaco_tman_mbs                   = -1;
static int hf_megaco_tman_pdr                   = -1;
static int hf_megaco_tman_dvt                   = -1;
static int hf_megaco_ipdc_realm                 = -1;
static int hf_megaco_h324_h223capr              = -1;
static int hf_megaco_reserve_value              = -1;
static int hf_megaco_streamid                   = -1;
static int hf_megaco_requestid                  = -1;
static int hf_megaco_pkgdname                   = -1;
static int hf_megaco_mId                        = -1;
static int hf_megaco_h245                       = -1;
static int hf_megaco_h223Capability             = -1;
static int hf_megaco_audititem                  = -1;
static int hf_megaco_priority                   = -1;

/* Define the trees for megaco */
static int ett_megaco                           = -1;
static int ett_megaco_message                   = -1;
static int ett_megaco_message_body              = -1;
static int ett_megaco_context                   = -1;
static int ett_megaco_command_line              = -1;
static int ett_megaco_mediadescriptor           = -1;
static int ett_megaco_descriptors               = -1;
static int ett_megaco_raw_text                  = -1;
static int ett_megaco_error_descriptor          = -1;
static int ett_megaco_TerminationState          = -1;
static int ett_megaco_Localdescriptor           = -1;
static int ett_megaco_Remotedescriptor          = -1;
static int ett_megaco_LocalControldescriptor    = -1;
static int ett_megaco_auditdescriptor           = -1;
static int ett_megaco_eventsdescriptor          = -1;
static int ett_megaco_statisticsdescriptor      = -1;
static int ett_megaco_observedeventsdescriptor  = -1;
static int ett_megaco_observedevent             = -1;
static int ett_megaco_packagesdescriptor        = -1;
static int ett_megaco_requestedevent            = -1;
static int ett_megaco_signalsdescriptor         = -1;
static int ett_megaco_requestedsignal           = -1;
static int ett_megaco_h245                      = -1;

static gcp_hf_ett_t megaco_ctx_ids = {{-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1}};

static expert_field ei_megaco_errored_command = EI_INIT;
static expert_field ei_megaco_no_command = EI_INIT;
static expert_field ei_megaco_no_descriptor = EI_INIT;
static expert_field ei_megaco_error_descriptor_transaction_list = EI_INIT;
static expert_field ei_megaco_parse_error = EI_INIT;
static expert_field ei_megaco_audit_descriptor = EI_INIT;
static expert_field ei_megaco_signal_descriptor = EI_INIT;
static expert_field ei_megaco_reason_invalid = EI_INIT;
static expert_field ei_megaco_error_code_invalid = EI_INIT;
static expert_field ei_megaco_invalid_sdr = EI_INIT;

static dissector_handle_t megaco_text_handle;

static int megaco_tap = -1;
static gint exported_pdu_tap = -1;


/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_whitespace;
static ws_mempbrk_pattern pbrk_braces;

/* Used when command type is needed to diferentiate parsing, extend as needed */
typedef enum
{
    MEGACO_CMD_NOT_SET = 0,
    MEGACO_CMD_PRIORITY,
} megaco_commands_enum_t;

/*
* Here are the global variables associated with
* the various user definable characteristics of the dissection
*
* MEGACO has two kinds of message formats: text and binary
*
* global_megaco_raw_text determines whether we are going to display
* the raw text of the megaco message, much like the HTTP dissector does.
*
* global_megaco_dissect_tree determines whether we are going to display
* a detailed tree that expresses a somewhat more semantically meaningful
* decode.
*/
#if 0
static guint global_megaco_bin_sctp_port = PORT_MEGACO_BIN;
static guint global_megaco_bin_tcp_port = PORT_MEGACO_BIN;
static guint global_megaco_bin_udp_port = PORT_MEGACO_BIN;
#endif
static gboolean global_megaco_raw_text = TRUE;
static gboolean global_megaco_dissect_tree = TRUE;

static const value_string megaco_context_vals[] = {
   { CHOOSE_CONTEXT,       "Choose one"     },
   { ALL_CONTEXTS,         "All"            },
   { NULL_CONTEXT,         "NULL"           },

   { 0,                    NULL }
};

/* Some basic utility functions that are specific to this dissector */
static gint megaco_tvb_skip_wsp(tvbuff_t *tvb, gint offset);
static gint megaco_tvb_skip_wsp_return(tvbuff_t *tvb, gint offset);

#define NUM_TIMESTATS 12

static const value_string megaco_message_type[] = {
    {  0, "ADD "},
    {  1, "MOVE"},
    {  2, "MDFY"},
    {  3, "SUBT"},
    {  4, "AUCP"},
    {  5, "AUVL"},
    {  6, "NTFY"},
    {  7, "SVCC"},
    {  8, "TOPO"},
    {  9, "NONE"},
    { 10, "ALL "},
    {  0, NULL}
};

#define GCP_CMD_REPLY_CASE \
    case GCP_CMD_ADD_REPLY: \
    case GCP_CMD_MOVE_REPLY: \
    case GCP_CMD_MOD_REPLY: \
    case GCP_CMD_SUB_REPLY: \
    case GCP_CMD_AUDITCAP_REPLY: \
    case GCP_CMD_AUDITVAL_REPLY: \
    case GCP_CMD_NOTIFY_REPLY: \
    case GCP_CMD_SVCCHG_REPLY: \
    case GCP_CMD_TOPOLOGY_REPLY: \
    case GCP_CMD_REPLY:

#define GCP_CMD_REQ_CASE \
    case GCP_CMD_ADD_REQ: \
    case GCP_CMD_MOVE_REQ: \
    case GCP_CMD_MOD_REQ: \
    case GCP_CMD_SUB_REQ: \
    case GCP_CMD_AUDITCAP_REQ: \
    case GCP_CMD_AUDITVAL_REQ: \
    case GCP_CMD_NOTIFY_REQ: \
    case GCP_CMD_SVCCHG_REQ: \
    case GCP_CMD_TOPOLOGY_REQ: \
    case GCP_CMD_CTX_ATTR_AUDIT_REQ: \
    case GCP_CMD_OTHER_REQ:

static gboolean
megacostat_is_duplicate_reply(const gcp_cmd_t* cmd)
{
    switch (cmd->type) {

    GCP_CMD_REPLY_CASE
        {
            gcp_cmd_msg_t *cmd_msg;
            /* cycle through commands to find same command in the transaction */
            for (cmd_msg = cmd->trx->cmds;
                (cmd_msg != NULL) && (cmd_msg->cmd->msg->framenum != cmd->msg->framenum);
                cmd_msg = cmd_msg->next) {
                if (cmd_msg->cmd->type == cmd->type)
                    return TRUE;
            }

            return FALSE;
        }
        break;
    default:
        return FALSE;
        break;
    }
}

static gboolean
megacostat_had_request(const gcp_cmd_t* cmd)
{
    switch (cmd->type) {

    GCP_CMD_REPLY_CASE
        {
            gcp_cmd_msg_t *cmd_msg;
            /* cycle through commands to find a request in the transaction */
            for (cmd_msg = cmd->trx->cmds;
                    (cmd_msg != NULL) && (cmd_msg->cmd->msg->framenum != cmd->msg->framenum);
                    cmd_msg = cmd_msg->next) {

                    switch (cmd_msg->cmd->type) {

                    GCP_CMD_REQ_CASE
                        return TRUE;
                        break;
                    default:
                        return FALSE;
                        break;
                    }
            }

            return FALSE;
        }
        break;
    default:
        return FALSE;
        break;
    }
}

static void
megacostat_filtercheck(const char *opt_arg _U_, const char **filter _U_, char** err)
{
    pref_t *megaco_ctx_track, *h248_ctx_track;

    megaco_ctx_track = prefs_find_preference(prefs_find_module("megaco"), "ctx_info");
    h248_ctx_track = prefs_find_preference(prefs_find_module("h248"), "ctx_info");

    if (!megaco_ctx_track || !h248_ctx_track) {
        /* No such preferences */
        return;
    }

    if (!prefs_get_bool_value(megaco_ctx_track, pref_current) || !prefs_get_bool_value(h248_ctx_track, pref_current)) {
        *err = ws_strdup_printf("Track Context option at Protocols -> MEGACO and Protocols -> H248 preferences\n"
                                "has to be set to true to enable measurement of service response times.\n");
    }
}

static tap_packet_status
megacostat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pmi, tap_flags_t flags _U_)
{
    rtd_data_t* rtd_data = (rtd_data_t*)pms;
    rtd_stat_table* ms = &rtd_data->stat_table;
    const gcp_cmd_t *mi=(const gcp_cmd_t*)pmi;
    nstime_t delta;
    tap_packet_status ret = TAP_PACKET_DONT_REDRAW;

    switch (mi->type) {

    GCP_CMD_REQ_CASE
        if(!mi->trx->initial) {
            /* Track Context is probably disabled, we cannot
                * measure service response time */
            return TAP_PACKET_DONT_REDRAW;
        }

        else if(mi->trx->initial->framenum != mi->msg->framenum){
            /* Duplicate is ignored */
            ms->time_stats[0].req_dup_num++;
        }
        else {
            ms->time_stats[0].open_req_num++;
        }
        break;

    GCP_CMD_REPLY_CASE
        if(megacostat_is_duplicate_reply(mi)){
            /* Duplicate is ignored */
            ms->time_stats[0].rsp_dup_num++;
        }
        else if (!megacostat_had_request(mi)) {
            /* no request was seen */
            ms->time_stats[0].disc_rsp_num++;
        }
        else {
            ms->time_stats[0].open_req_num--;
            /* calculate time delta between request and response */
            nstime_delta(&delta, &pinfo->abs_ts, &mi->trx->initial->frametime);

            switch(mi->type) {

            case GCP_CMD_ADD_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[0]),&delta, pinfo);
                break;
            case GCP_CMD_MOVE_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[1]),&delta, pinfo);
                break;
            case GCP_CMD_MOD_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[2]),&delta, pinfo);
                break;
            case GCP_CMD_SUB_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[3]),&delta, pinfo);
                break;
            case GCP_CMD_AUDITCAP_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[4]),&delta, pinfo);
                break;
            case GCP_CMD_AUDITVAL_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[5]),&delta, pinfo);
                break;
            case GCP_CMD_NOTIFY_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[6]),&delta, pinfo);
                break;
            case GCP_CMD_SVCCHG_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[7]),&delta, pinfo);
                break;
            case GCP_CMD_TOPOLOGY_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[8]),&delta, pinfo);
                break;
            case GCP_CMD_REPLY:
                time_stat_update(&(ms->time_stats[0].rtd[9]),&delta, pinfo);
                break;
            default:
                time_stat_update(&(ms->time_stats[0].rtd[11]),&delta, pinfo);
            }

            time_stat_update(&(ms->time_stats[0].rtd[10]),&delta, pinfo);
            ret = TAP_PACKET_REDRAW;
        }
        break;

    default:
        break;
    }

    return ret;
}

/* Call the export PDU tap with relevant data */
static void
export_megaco_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
    exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "megaco", EXP_PDU_TAG_PROTO_NAME);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;

    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);

}

/*
* The various functions that either dissect some
* subpart of MEGACO.  These aren't really proto dissectors but they
* are written in the same style.
*
*/
static void
dissect_megaco_descriptors(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_descriptors_start_offset, gint tvb_descriptors_end_offset, proto_tree *top_tree, guint32 context);
static void
dissect_megaco_digitmapdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_topologydescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_errordescriptor(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_TerminationStatedescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_LocalRemotedescriptor(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset, guint32 context, gboolean is_local);
static void
dissect_megaco_LocalControldescriptor(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset, proto_tree *top_tree);
static void
dissect_megaco_Packagesdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);
static void
tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree);
static int
dissect_megaco_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static gint
megaco_tvb_find_token(tvbuff_t *tvb, gint offset, gint maxlength);
static dissector_handle_t data_handle;
static dissector_handle_t sdp_handle;
static dissector_handle_t h245_handle;
static dissector_handle_t h248_handle;
static dissector_handle_t h248_otp_handle;

static gboolean keep_persistent_data = FALSE;

/*
 * dissect_megaco_text over TCP, there will be a TPKT header there
 *
 */
static int dissect_megaco_text_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int lv_tpkt_len;

    /* This code is copied from the Q.931 dissector, some parts skipped.
     * Check whether this looks like a TPKT-encapsulated
     * MEGACO packet.
     *
     * The minimum length of a MEGACO message is 6?:
     * Re-assembly ?
     */
    lv_tpkt_len = is_tpkt(tvb, 6);
    if (lv_tpkt_len == -1) {
        /*
         * It's not a TPKT packet;
         * Is in MEGACO ?
         */
        dissect_megaco_text(tvb, pinfo, tree, data);
    }
    dissect_tpkt_encap(tvb, pinfo, tree, TRUE,
        megaco_text_handle);

    return tvb_captured_length(tvb);
}

#define ERRORTOKEN          1
#define TRANSTOKEN          2
#define REPLYTOKEN          3
#define PENDINGTOKEN        4
#define RESPONSEACKTOKEN    5

typedef struct {
    const char *name;
    const char *compact_name;
} megaco_tokens_t;

static const megaco_tokens_t megaco_messageBody_names[] = {
    { "Unknown-token",              NULL }, /* 0 Pad so that the real headers start at index 1 */
    { "Error",                      "ER" }, /* 1 */
    { "Transaction",                "T" },  /* 2 */
    { "Reply",                      "P" },  /* 3 */
    { "Pending",                    "PN" }, /* 4 */
    { "TransactionResponseAck",     "K" },  /* 5 */
};

/* Returns index of megaco_tokens_t */
static gint find_megaco_messageBody_names(tvbuff_t *tvb, int offset, guint header_len)
{
    guint i;

    for (i = 1; i < array_length(megaco_messageBody_names); i++) {
        if (header_len == strlen(megaco_messageBody_names[i].name) &&
            tvb_strncaseeql(tvb, offset, megaco_messageBody_names[i].name, header_len) == 0)
            return i;
        if (megaco_messageBody_names[i].compact_name != NULL &&
            header_len == strlen(megaco_messageBody_names[i].compact_name) &&
            tvb_strncaseeql(tvb, offset, megaco_messageBody_names[i].compact_name, header_len) == 0)
            return i;
    }

    return -1;
}

static proto_item *
megaco_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb,
             gint start, gint length, const char *value)
{
    proto_item *pi;

    pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
    if (!global_megaco_dissect_tree) {
        proto_item_set_hidden(pi);
    }

    return(pi);
}

static proto_item *
my_proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb,
             gint start, gint length, guint32 value)
{
    proto_item *pi;

    pi = proto_tree_add_uint(tree, hfindex, tvb, start, 1, value);
    /* String length may be longer than FT_UINT will allow */
    proto_item_set_len(pi, length);

    if (!global_megaco_dissect_tree) {
        proto_item_set_hidden(pi);
    }

    return(pi);
}

/*
 * dissect_megaco_text - The dissector for the MEGACO Protocol, using
 * text encoding.
 */
static int
dissect_megaco_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint        tvb_len, len;
    gint        tvb_offset,tvb_current_offset,tvb_previous_offset,tvb_next_offset,tokenlen;
    gint        context_offset, context_length, save_offset, save_length;
    gint        tvb_command_start_offset, tvb_command_end_offset;
    gint        tvb_descriptors_start_offset, tvb_descriptors_end_offset;
    gint        tvb_transaction_end_offset;
    proto_tree  *megaco_tree, *message_body_tree, *megaco_tree_command_line, *ti, *sub_ti;

    guint8      word[15];
    guint8      TermID[30];
    guint8      tempchar;
    gint        tvb_RBRKT, tvb_LBRKT,  RBRKT_counter, LBRKT_counter;
    guint       token_index=0;
    guint32     dword;
    guchar      needle;

    gcp_msg_t      *msg       = NULL;
    gcp_trx_t      *trx       = NULL;
    gcp_ctx_t      *ctx       = NULL;
    gcp_cmd_t      *cmd       = NULL;
    gcp_term_t     *term      = NULL;
    gcp_trx_type_t  trx_type  = GCP_TRX_NONE;
    guint32         trx_id    = 0, pending_id;
    guint32         ctx_id    = 0;
    gcp_cmd_type_t  cmd_type  = GCP_CMD_NONE;
    gcp_wildcard_t  wild_term = GCP_WILDCARD_NONE;
    gboolean        short_form;

    megaco_commands_enum_t megaco_command = MEGACO_CMD_NOT_SET;
    /* Initialize variables */
    tvb_len                     = tvb_reported_length(tvb);
    megaco_tree                 = NULL;
    ti                          = NULL;
    tvb_offset                  = 0;
    RBRKT_counter               = 0;
    LBRKT_counter               = 0;

    /* Check if H.248 in otp(Erlang) internal format
     * XXX Needs improvement?
     * Ref:
     * http://www.erlang.org/doc/apps/megaco/part_frame.html
     * 4.1 Internal form of messages
     * 4.2 The different encodings
     */
    dword = tvb_get_ntoh24(tvb,0);
    if ((dword == 0x836803)&&(h248_otp_handle)){
        call_dissector(h248_otp_handle, tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    msg = gcp_msg(pinfo, tvb_raw_offset(tvb), keep_persistent_data);

    /*
     * Check to see whether we're really dealing with MEGACO by looking
     * for the "MEGACO" string or a "!".This needs to be improved when supporting
     * binary encodings. Bugfix add skipping of leading spaces.
     */
    tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);

    /* Quick fix for MEGACO not following the RFC, hopefully not breaking any thing
     * Turned out to be TPKT in case of TCP, added some code to handle that.
     *
     * tvb_offset = tvb_find_guint8(tvb, tvb_offset, 5, 'M');
     */
    if(!tvb_get_nstringz0(tvb,tvb_offset,sizeof(word),word)) return tvb_captured_length(tvb);

    /* Quick fix for MEGACO packet with Authentication Header,
     * marked as "AU" or "Authentication".
     */
    if ((g_ascii_strncasecmp(word, "Authentication", 14) == 0) ||
        (g_ascii_strncasecmp(word, "AU", 2) == 0)) {
        gint counter;
        guint8 next;

        /* move offset to end of auth header (EOL or WSP) */
        for ( counter = tvb_offset; counter < tvb_len; counter++ ) {
            needle = tvb_get_guint8(tvb, counter);
            if (needle == ' ' || needle == '\r' || needle == '\n') {
                next = tvb_get_guint8(tvb, counter+1);
                if (next == ' ' || next == '\r' || next == '\n') {
                    continue;
                }
                tvb_offset = counter + 1;
                break;
            }
        }
    }

    short_form = (tvb_get_guint8(tvb, tvb_offset ) == '!');

    if (g_ascii_strncasecmp(word, "MEGACO", 6) != 0 && !short_form){
        gint8 ber_class;
        gboolean pc;
        gint32 tag;
        dissector_handle_t handle = data_handle;

        get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

        if (ber_class == BER_CLASS_UNI && pc && tag == BER_UNI_TAG_SEQUENCE ) {
            handle = h248_handle;
        }

        call_dissector(handle,tvb,pinfo,tree);
        return tvb_captured_length(tvb);
    }


    /* Display MEGACO in protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEGACO");

    /* Report this packet to the tap */
    if (!pinfo->flags.in_error_pkt) {
        if (have_tap_listener(exported_pdu_tap)) {
            export_megaco_pdu(pinfo, tvb);
        }
    }

    /* Build the info tree if we've been given a root */
    /* Create megaco subtree */
    ti = proto_tree_add_item(tree,proto_megaco,tvb, 0, -1, ENC_NA);
    megaco_tree = proto_item_add_subtree(ti, ett_megaco);

    /*  Format of 'message' is = MegacopToken SLASH Version SEP mId SEP messageBody */
    /*  MegacopToken = "MEGACO" or "!"                      */
    /*  According to H248.1-200205 Annex B Text encoding ( protocol version 2 )     */

    /* Find version */
    tvb_previous_offset = tvb_find_guint8(tvb, 0,
        tvb_len, '/');
    if (tvb_previous_offset == -1) {
        expert_add_info_format(pinfo, ti, &ei_megaco_parse_error,
            "Sorry, no \"/\" in the MEGACO header, I can't parse this packet");
        return tvb_captured_length(tvb);
    }

    megaco_tree_add_string(megaco_tree, hf_megaco_start, tvb, 0, tvb_previous_offset+1,
                    tvb_get_string_enc(wmem_packet_scope(), tvb, 0, tvb_previous_offset, ENC_UTF_8|ENC_NA));

    /* skip / */
    tvb_previous_offset++;

    /* assume at least one digit in version */
    tvb_current_offset = tvb_previous_offset + 1;

    if (g_ascii_isdigit(tvb_get_guint8(tvb, tvb_current_offset))) {
        /* 2-digit version */
        tvb_current_offset++;
    }

    megaco_tree_add_string(megaco_tree, hf_megaco_version, tvb, tvb_previous_offset, tvb_current_offset - tvb_previous_offset,
                    tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_previous_offset, tvb_current_offset - tvb_previous_offset, ENC_UTF_8|ENC_NA));

    tvb_previous_offset = tvb_current_offset;
    tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);

    if (tvb_previous_offset == tvb_current_offset) {
        expert_add_info_format(pinfo, ti, &ei_megaco_parse_error,
            "[ Parse error: missing SEP in MEGACO header ]");
        return tvb_current_offset;
    }

    tvb_previous_offset = tvb_current_offset;

    /* mId should follow here,
     * mId = (( domainAddress / domainName ) [":" portNumber]) / mtpAddress / deviceName
     * domainAddress = "[" (IPv4address / IPv6address) "]"
     * domainName = "<" (ALPHA / DIGIT) *63(ALPHA / DIGIT / "-" /".") ">"
     * mtpAddress = MTPToken LBRKT 4*8 (HEXDIG) RBRKT
     * MTPToken = ("MTP")
     * deviceName = pathNAME
     * pathNAME = ["*"] NAME *("/" / "*"/ ALPHA / DIGIT /"_" / "$" )["@" pathDomainName ]
     */

    tvb_current_offset = tvb_ws_mempbrk_pattern_guint8(tvb, tvb_current_offset, -1, &pbrk_whitespace, &needle);
    if (tvb_current_offset == -1) {
        expert_add_info_format(pinfo, ti, &ei_megaco_parse_error,
            "[ Parse error: no body in MEGACO message (missing SEP after mId) ]");
        return tvb_captured_length(tvb);
    }

    tvb_next_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset);

   /* At this point we should point to the "\n" ending the mId element
    * or to the next character after white space SEP
    */
    megaco_tree_add_string(megaco_tree, hf_megaco_mId, tvb, tvb_previous_offset, tvb_current_offset - tvb_previous_offset,
                    tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_previous_offset, tvb_current_offset - tvb_previous_offset, ENC_UTF_8|ENC_NA));

    col_clear(pinfo->cinfo, COL_INFO);
    do{
    tvb_previous_offset = tvb_next_offset;

/* Next part is
 *  : messageBody = ( errorDescriptor / transactionList )
 *      errorDescriptor = ErrorToken EQUAL ErrorCode LBRKT [quotedString] RBRKT
 *          ErrorToken = ("Error" / "ER")
 *
 *      transactionList = 1*( transactionRequest / transactionReply /
 *                  transactionPending / transactionResponseAck )
 *
 *      transactionResponseAck = ResponseAckToken LBRKT
 *          transactionAck*(COMMA transactionAck) RBRKT
 *              ResponseAckToken = ("TransactionResponseAck"/ "K")
 *
 *      transactionPending = PendingToken EQUAL TransactionID LBRKT RBRKT
 *          PendingToken = ("Pending" / "PN")
 *
 *      transactionReply = ReplyToken EQUAL TransactionID LBRKT
 *          [ ImmAckRequiredToken COMMA]( errorDescriptor / actionReplyList ) RBRKT
 *          ReplyToken = ("Reply" / "P")
 *
 *      transactionRequest = TransToken EQUAL TransactionID LBRKT
 *          actionRequest *(COMMA actionRequest) RBRKT
 *          TransToken = ("Transaction" / "T")
 */

    /* Find token length */
    for (tvb_offset=tvb_previous_offset; tvb_offset < tvb_len-1; tvb_offset++){
        if (!g_ascii_isalpha(tvb_get_guint8(tvb, tvb_offset ))){
            break;
        }
    }
    tokenlen = tvb_offset - tvb_previous_offset;
    token_index = find_megaco_messageBody_names(tvb, tvb_previous_offset, tokenlen);
    /* Debug code
        ws_warning("token_index %u",token_index);
    */

    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_len, '{');
    tvb_current_offset = tvb_LBRKT;
    tvb_transaction_end_offset = megaco_tvb_find_token(tvb, tvb_LBRKT - 1, tvb_len);

    switch ( token_index ){
        /* errorDescriptor */
        case ERRORTOKEN:
            col_set_str(pinfo->cinfo, COL_INFO, "Error  ");

            tvb_current_offset = megaco_tvb_find_token(tvb, tvb_offset, tvb_len); /*tvb_find_guint8(tvb, tvb_offset+1, tvb_len, '}');*/

            ti = proto_tree_add_format_text(megaco_tree, tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset);
            message_body_tree = proto_item_add_subtree(ti, ett_megaco_message_body);

            if (tree) {
                megaco_tree_add_string(message_body_tree, hf_megaco_transaction, tvb,
                tvb_previous_offset, tokenlen,
                "Error" );

                tvb_command_start_offset = tvb_previous_offset;
                dissect_megaco_errordescriptor(tvb, pinfo, megaco_tree, tvb_len-1, tvb_command_start_offset);
            }
            return tvb_captured_length(tvb);
            /* transactionResponseAck
             * transactionResponseAck = ResponseAckToken LBRKT transactionAck
             *                           *(COMMA transactionAck) RBRKT
             * transactionAck = transactionID / (transactionID "-" transactionID)
             */
        case RESPONSEACKTOKEN:
            tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '{');
            tvb_offset = tvb_LBRKT;
            save_offset = tvb_previous_offset;
            save_length = tvb_current_offset-tvb_previous_offset;

            megaco_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
                    save_offset, save_length, "TransactionResponseAck" );

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_offset+1);
            tvb_current_offset = tvb_find_guint8(tvb, tvb_offset+1, tvb_len, '}');
            /*tvb_current_offset = megaco_tvb_find_token(tvb, tvb_offset, tvb_transaction_end_offset);*/
            tvb_current_offset = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset)-1; /* cut last RBRKT */
            len = tvb_current_offset - tvb_previous_offset;

            pending_id = (guint)strtoul(tvb_format_text(pinfo->pool, tvb,tvb_previous_offset,len),NULL,10);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%d TransactionResponseAck", pending_id);

            my_proto_tree_add_uint(megaco_tree, hf_megaco_transid, tvb, save_offset, save_length, pending_id);

            if(global_megaco_raw_text){
                tvb_raw_text_add(tvb, megaco_tree);
            }
            return tvb_captured_length(tvb);
        /* Pe and PN is transactionPending, P+"any char" is transactionReply */
        case PENDINGTOKEN:

            tvb_offset  = tvb_find_guint8(tvb, tvb_previous_offset, tvb_transaction_end_offset, '=')+1;
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
            tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '{');
            tvb_current_offset = tvb_LBRKT;
            save_offset = tvb_previous_offset;
            save_length = tvb_current_offset-tvb_previous_offset;

            megaco_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
                    save_offset, save_length, "Reply" );

            tvb_current_offset  = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1);
            len = tvb_current_offset - tvb_offset;

            pending_id = (guint)strtoul(tvb_format_text(pinfo->pool, tvb,tvb_offset,len),NULL,10);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%d Pending", pending_id);

            my_proto_tree_add_uint(megaco_tree, hf_megaco_transid, tvb, save_offset, save_length, pending_id);
            return tvb_captured_length(tvb);

        /* transactionReply */
        case REPLYTOKEN:
            trx_type = GCP_TRX_REPLY;
            tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '{');
            save_offset = tvb_previous_offset;
            save_length = tvb_LBRKT-tvb_previous_offset;

            megaco_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
                    save_offset, save_length, "Reply" );

            tvb_offset  = tvb_find_guint8(tvb, tvb_previous_offset, tvb_transaction_end_offset, '=')+1;
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
            tvb_current_offset  = megaco_tvb_skip_wsp_return(tvb, tvb_LBRKT-1);
            len = tvb_current_offset - tvb_offset;

            trx_id = (guint)strtoul(tvb_format_text(pinfo->pool, tvb,tvb_offset,len),NULL,10);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%d Reply  ", trx_id);

            my_proto_tree_add_uint(megaco_tree, hf_megaco_transid, tvb, save_offset, save_length, trx_id);

            /* Find if we have a errorDescriptor or actionReplyList */
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            tempchar = tvb_get_guint8(tvb,tvb_offset);
            if ((tempchar == 'E')||(tempchar == 'e')){
                dissect_megaco_errordescriptor(tvb, pinfo, megaco_tree, tvb_transaction_end_offset-1, tvb_offset);
                return tvb_captured_length(tvb);
            }
            /* Offset should be at first printable char after { */
            tvb_previous_offset = tvb_offset;
            break;
        case TRANSTOKEN:
            /* TransactionRequest   */
            trx_type = GCP_TRX_REQUEST;
            save_offset = tvb_previous_offset;
            save_length = tvb_current_offset-tvb_previous_offset;
            megaco_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
                    save_offset, save_length, "Request" );

            tvb_offset  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '=')+1;
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
            tvb_current_offset  = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1);
            len = tvb_current_offset - tvb_offset;

            trx_id = (guint)strtoul(tvb_format_text(pinfo->pool, tvb,tvb_offset,len),NULL,10);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%d Request", trx_id);

            my_proto_tree_add_uint(megaco_tree, hf_megaco_transid, tvb, save_offset, save_length, trx_id);
            /* Offset should be at first printable char after { */
            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);

            break;
        default :
            proto_tree_add_expert_format(tree, pinfo, &ei_megaco_error_descriptor_transaction_list, tvb, 0, -1,
                    "Sorry, can't understand errorDescriptor / transactionList = %s, can't parse it pos %u",
                        tvb_format_text(pinfo->pool, tvb,tvb_previous_offset,2),tvb_previous_offset);
            return tvb_captured_length(tvb);
        } /* end switch */
/*      Only these remains now
 *      transactionReply = ReplyToken EQUAL TransactionID LBRKT
 *          [ ImmAckRequiredToken COMMA]( errorDescriptor / actionReplyList ) RBRKT
 *          ReplyToken = ("Reply" / "P")
 *
 *      errorDescriptor   = ErrorToken EQUAL ErrorCode
 *                     LBRKT [quotedString] RBRKT
 *
 *      transactionRequest = TransToken EQUAL TransactionID LBRKT
 *          actionRequest *(COMMA actionRequest) RBRKT
 *          TransToken = ("Transaction" / "T")
 */

        trx = gcp_trx(msg , trx_id , trx_type, pinfo, keep_persistent_data);

        /* Find Context */
nextcontext:




        tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_transaction_end_offset, '{');
        context_offset = tvb_previous_offset;
        context_length = tvb_next_offset-tvb_previous_offset+1;

        tvb_previous_offset = tvb_find_guint8(tvb, tvb_current_offset, tvb_transaction_end_offset, '=')+1;
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);

        if (tvb_current_offset >= tvb_next_offset) {
            proto_tree_add_expert_format(megaco_tree, pinfo, &ei_megaco_parse_error,
                                    tvb, context_offset, context_length, "Parse error: Invalid offset");
            return tvb_captured_length(tvb);
        }
        tvb_current_offset = tvb_next_offset;


        tokenlen = tvb_current_offset - tvb_previous_offset;
        tempchar = tvb_get_guint8(tvb, tvb_previous_offset );

        if (tvb_get_guint8(tvb, tvb_current_offset-1 ) == ' '){
            tokenlen--;
        }

        switch ( tempchar ){
        case '$':
            ctx_id = CHOOSE_CONTEXT;
            break;
        case '*':
            ctx_id = ALL_CONTEXTS;
            break;
        case '-':
            ctx_id = NULL_CONTEXT;
            break;
        default:
            ctx_id = (guint)strtoul(tvb_format_text(pinfo->pool, tvb, tvb_previous_offset, tokenlen),NULL,10);
        }

        my_proto_tree_add_uint(megaco_tree, hf_megaco_Context, tvb, context_offset, context_length, ctx_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, " |=%s", val_to_str(ctx_id, megaco_context_vals, "%d"));

        ctx = gcp_ctx(msg,trx,ctx_id,pinfo,keep_persistent_data);

        /* Find Commands */

        /* If Transaction is Request, Reply or Pending */
        tvb_command_start_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_command_end_offset = tvb_command_start_offset;

        tvb_LBRKT = tvb_command_start_offset;
        tvb_RBRKT = tvb_command_start_offset;

        /* The following loop find the individual contexts, commands and call the for every Descriptor a subroutine */

        do {
            tvb_command_end_offset = tvb_find_guint8(tvb, tvb_command_end_offset +1,
                tvb_transaction_end_offset, ',');

            if ( tvb_command_end_offset == -1 || tvb_command_end_offset > tvb_transaction_end_offset){
                tvb_command_end_offset = tvb_transaction_end_offset ;

            }

            /* checking how many left brackets are before the next comma */

            while ( tvb_find_guint8(tvb, tvb_LBRKT+1,tvb_transaction_end_offset, '{') != -1
                && (tvb_find_guint8(tvb, tvb_LBRKT+1,tvb_transaction_end_offset, '{') < tvb_command_end_offset)){

                tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT+1,
                    tvb_transaction_end_offset, '{');

                LBRKT_counter++;
            }

            /* checking how many right brackets are before the next comma */

            while ( (tvb_find_guint8(tvb, tvb_RBRKT+1,tvb_transaction_end_offset, '}') != -1 )
                    && (tvb_find_guint8(tvb, tvb_RBRKT+1,tvb_transaction_end_offset, '}') <= tvb_command_end_offset)
                && LBRKT_counter != 0){

                tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
                    tvb_transaction_end_offset, '}');
                RBRKT_counter++;


            }

            /* If equal or more right brackets before the comma, one command is complete */

            if ( LBRKT_counter <= RBRKT_counter ){

                tvb_current_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                    tvb_transaction_end_offset, '{');


                /* includes no descriptors */

                if ( LBRKT_counter == 0 ){

                    tvb_current_offset = tvb_command_end_offset;

                    /* the last command in a context */

                    if ( tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '}') < tvb_current_offset
                        && tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '}') != -1){

                        tvb_previous_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                            tvb_transaction_end_offset, '}');

                        len = tvb_previous_offset - tvb_command_start_offset;

                        tvb_previous_offset = megaco_tvb_skip_wsp_return(tvb, tvb_previous_offset -1);

                        tokenlen =  tvb_previous_offset - tvb_command_start_offset;

                    }

                    /* not the last command in a context*/

                    else{
                        len =  tvb_current_offset - tvb_command_start_offset;
                        tvb_current_offset = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset -1);

                        tokenlen =  tvb_current_offset - tvb_command_start_offset;
                    }
                }

                /* command includes descriptors */

                else{
                    len =  tvb_current_offset - tvb_command_start_offset;
                    tvb_current_offset = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset -1);

                    tokenlen =  tvb_current_offset - tvb_command_start_offset;
                }

                /* if a next context is specified */

                if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'C'){
                    tvb_current_offset = tvb_command_start_offset;
                    tvb_previous_offset = tvb_command_start_offset;
                    LBRKT_counter = 0;
                    RBRKT_counter = 0;
                    goto nextcontext;
                }

                megaco_tree_command_line = proto_tree_add_subtree(megaco_tree, tvb, tvb_command_start_offset, len+1, ett_megaco_command_line, &sub_ti, "Command: ");
                megaco_command = MEGACO_CMD_NOT_SET;
                /* creation of the megaco_tree_command_line additionally Command and Transaction ID will be printed in this line */
                /* Changed to use the lines above. this code is saved if there is complaints
                sub_ti = proto_tree_add_item(megaco_tree,hf_megaco_command_line,tvb,tvb_command_start_offset,tokenlen, ENC_UTF_8);
                megaco_tree_command_line = proto_item_add_subtree(sub_ti, ett_megaco_command_line);
                */
                if (!global_megaco_dissect_tree) {
                    proto_item_set_hidden(sub_ti);
                }

                tvb_next_offset = tvb_command_start_offset + tokenlen;

                /* Try to dissect Topology Descriptor before the command */
                tempchar = tvb_get_guint8(tvb, tvb_command_start_offset);
                if ( (tempchar >= 'a')&& (tempchar <= 'z')){
                    tempchar = tempchar - 0x20;
                }
                if ( tempchar == 'T') {
                    tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);

                    if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                        tempchar = tempchar - 0x20;

                    if ( tempchar == 'P' || tempchar == 'O'){
                        gint tvb_topology_end_offset = tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '}');
                        if ( tvb_topology_end_offset == -1 ){
                            expert_add_info_format(pinfo, sub_ti, &ei_megaco_parse_error, "Parse error: Missing \"}\"");
                            return tvb_captured_length(tvb);
                        }

                        tvb_command_start_offset = tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '{');
                        if ( tvb_command_start_offset == -1 ){
                            expert_add_info_format(pinfo, sub_ti, &ei_megaco_parse_error, "Parse error: Missing \"{\"");
                            return tvb_captured_length(tvb);
                        }
                        dissect_megaco_topologydescriptor(tvb, megaco_tree_command_line, tvb_topology_end_offset-1, tvb_command_start_offset+1);

                        /* Command after Topology Descriptor */
                        tvb_command_start_offset = tvb_find_guint8(tvb, tvb_topology_end_offset + 1,
                            tvb_transaction_end_offset, ',');

                        if ( tvb_command_start_offset == -1 ){
                            /* No Command present after Topology Descriptor */
                            break;

                        } else {
                            /* Try to find the first char of the command */
                            tvb_command_start_offset =  megaco_tvb_skip_wsp(tvb, tvb_command_start_offset + 1);
                            RBRKT_counter = 0;
                            LBRKT_counter = 0;
                            tvb_LBRKT = tvb_command_start_offset;
                            tvb_RBRKT = tvb_command_start_offset;
                            /*tvb_next_offset = tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '{');*/
                            continue;
                        }

                    }
                }

                /* Additional value */
                if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'O'){

                    proto_tree_add_item(megaco_tree_command_line, hf_megaco_command_optional, tvb, tvb_command_start_offset, 2, ENC_NA);
                    tvb_command_start_offset = tvb_command_start_offset+2;

                }

                /* Additional value */
                if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'W'){

                    proto_tree_add_item(megaco_tree_command_line, hf_megaco_wildcard_response, tvb, tvb_command_start_offset, 2, ENC_NA );
                    tvb_command_start_offset = tvb_command_start_offset+2;
                }

                tvb_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                    tvb_transaction_end_offset, '=');
                if (tvb_offset == -1 ) {
                    proto_tree_add_expert_format(megaco_tree, pinfo, &ei_megaco_parse_error, tvb, tvb_command_start_offset, len+1, "Parse error: Missing \"=\"");
                    return tvb_captured_length(tvb);
                }
                tvb_offset = megaco_tvb_skip_wsp_return(tvb, tvb_offset -1);
                tokenlen = tvb_offset - tvb_command_start_offset;

                tempchar = tvb_get_guint8(tvb, tvb_command_start_offset);
                if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                    tempchar = tempchar - 0x20;

                if ( tempchar != 'E' ){
                    /* Short form used */
                    if (short_form){

                        switch ( tempchar ){

                        case 'A':

                            tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
                            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                                tempchar = tempchar - 0x20;

                            switch ( tempchar ){

                            case 'V':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_AUDITVAL_REPLY; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_AUDITVAL_REQ; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }

                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "AuditValue");
                                col_append_str(pinfo->cinfo, COL_INFO, " AuditValue");
                                proto_item_append_text(sub_ti, "AuditValue");
                                break;

                            case 'C':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_AUDITCAP_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_AUDITCAP_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "AuditCapability");
                                col_append_str(pinfo->cinfo, COL_INFO, " AuditCapability");
                                proto_item_append_text(sub_ti, "AuditCapability");
                                break;

                            default:
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_ADD_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_ADD_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }

                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Add");
                                col_append_str(pinfo->cinfo, COL_INFO, " Add");
                                proto_item_append_text(sub_ti, "Add");
                                break;
                            }
                            break;

                        case 'I':
                            /* "IEPS" */
                            tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
                            if(tempchar == 'E'){
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "IEPSCall");
                                col_append_str(pinfo->cinfo, COL_INFO, " IEPSCall");
                                proto_item_append_text(sub_ti, "IEPSCall");
                            }
                            cmd_type = GCP_CMD_NONE;
                            break;
                        case 'N':
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_NOTIFY_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_NOTIFY_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }

                            proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                tvb_command_start_offset, tokenlen, "Notify");
                            col_append_str(pinfo->cinfo, COL_INFO, " Notify");
                            proto_item_append_text(sub_ti, "Notify");
                            break;

                        case 'M':

                            tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
                            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                                tempchar = tempchar - 0x20;

                            switch ( tempchar ){
                            case 'F':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_MOD_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_MOD_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }

                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Modify");
                                col_append_str(pinfo->cinfo, COL_INFO, " Modify");
                                proto_item_append_text(sub_ti, "Modify");
                                break;

                            case 'V':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_MOVE_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_MOVE_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Move");
                                col_append_str(pinfo->cinfo, COL_INFO, " Move");
                                proto_item_append_text(sub_ti, "Move");
                                break;
                            }
                            break;

                        case 'P':
                            cmd_type = GCP_CMD_NONE;
                            /*
                            PackagesToken   = ("Packages"   / "PG")
                            PendingToken    = ("Pending"    / "PN")
                            PriorityToken   = ("Priority"   / "PR")
                            ProfileToken    = ("Profile"    / "PF")
                            */
                            tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
                            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                                tempchar = tempchar - 0x20;

                            switch ( tempchar ){
                            case 'G':
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Packages");
                                col_append_str(pinfo->cinfo, COL_INFO, " Packages");
                                proto_item_append_text(sub_ti, "Packages");
                                break;
                            case 'N':
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Pending");
                                col_append_str(pinfo->cinfo, COL_INFO, " Pending");
                                proto_item_append_text(sub_ti, "Pending");
                                break;
                            case 'R':
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Priority");
                                col_append_str(pinfo->cinfo, COL_INFO, " Priority");
                                proto_item_append_text(sub_ti, "Priority");
                                megaco_command = MEGACO_CMD_PRIORITY;
                                break;
                            case 'F':
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Profile");
                                col_append_str(pinfo->cinfo, COL_INFO, " Profile");
                                proto_item_append_text(sub_ti, "Profile");
                                break;
                            }
                            break;

                        case 'S':
                            tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
                            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                                tempchar = tempchar - 0x20;

                            switch ( tempchar ){

                            case 'C':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_SVCCHG_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_SVCCHG_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "ServiceChange");
                                col_append_str(pinfo->cinfo, COL_INFO, " ServiceChange");
                                proto_item_append_text(sub_ti, "ServiceChange");
                                break;

                            default:
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_SUB_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_SUB_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen, "Subtract");
                                col_append_str(pinfo->cinfo, COL_INFO, " Subtract");
                                proto_item_append_text(sub_ti, "Subtract");
                                break;
                            }
                            break;

                        default:
                            proto_item_append_text(sub_ti, "<None> 0x%02x", tempchar);
                            expert_add_info(pinfo, sub_ti, &ei_megaco_no_command);
                            return tvb_captured_length(tvb);
                        }
                    }
                    else{
                        gchar* command = tvb_format_text(pinfo->pool, tvb, tvb_command_start_offset, tokenlen);

                        if ( g_str_equal(command,"Subtract") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_SUB_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_SUB_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"AuditValue") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_AUDITVAL_REPLY; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_AUDITVAL_REQ; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"AuditCapability") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_AUDITCAP_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_AUDITCAP_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"Add") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_ADD_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_ADD_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"Notify") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_NOTIFY_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_NOTIFY_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"Modify") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_MOD_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_MOD_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"Move") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_MOVE_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_MOVE_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else if ( g_str_equal(command,"ServiceChange") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_SVCCHG_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_SVCCHG_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_OTHER_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        }


                        proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                            tvb_command_start_offset, tokenlen, command);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", command);
                        proto_item_append_text(sub_ti, " %s", command);
                    }

                    if (cmd_type == GCP_CMD_NONE && trx_type == GCP_TRX_REPLY) {
                        cmd_type = GCP_CMD_REPLY;
                    }

                    if (cmd_type != GCP_CMD_NONE) {
                        cmd = gcp_cmd(msg, trx, ctx, cmd_type, tvb_command_start_offset, pinfo, keep_persistent_data);
                        tap_queue_packet(megaco_tap, pinfo, cmd);
                    }

                    tvb_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                        tvb_transaction_end_offset, '=');
                    if (tvb_offset == -1 ) {
                        expert_add_info_format(pinfo, sub_ti, &ei_megaco_parse_error, "Parse error: Missing \"=\"");
                        return tvb_captured_length(tvb);
                    }
                    tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset+1);
                    tokenlen = tvb_next_offset - tvb_offset;
                    if (tokenlen+1 <= 0) {
                        expert_add_info_format(pinfo, sub_ti, &ei_megaco_parse_error, "Parse error: Invalid token length (%d)", tokenlen+1);
                        return tvb_captured_length(tvb);
                    }

                    tempchar = tvb_get_guint8(tvb, tvb_offset);
                    if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                        tempchar = tempchar - 0x20;

                    term = wmem_new0(wmem_packet_scope(), gcp_term_t);
                    wild_term = GCP_WILDCARD_NONE;
                    term->type = GCP_TERM_TYPE_UNKNOWN;

                    switch ( tempchar ){

                    case 'E':
                        if ((tokenlen+1 > (int) sizeof(TermID))) {
                            expert_add_info_format(pinfo, sub_ti, &ei_megaco_parse_error, "Parse error: Invalid TermID length (%d)", tokenlen+1);
                            return tvb_captured_length(tvb);
                        }
                        tvb_get_nstringz0(tvb,tvb_offset,tokenlen+1,TermID);
                        TermID[0] = 'e';

                        term->len = tokenlen;
                        term->str = (const gchar*)(term->buffer = TermID);

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, pinfo, keep_persistent_data);

                        /*** TERM ***/
                        proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen, TermID);
                        break;

                    case '*':
                        wild_term = GCP_WILDCARD_ALL;
                        term->len = 1;
                        term->buffer = (const guint8*)(term->str = "*");

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, pinfo, keep_persistent_data);

                        proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen,
                            "WildCard all");
                            col_append_str(pinfo->cinfo, COL_INFO, "=*");
                        break;

                    case '$':
                        wild_term = GCP_WILDCARD_CHOOSE;

                        term->len = 1;
                        term->buffer = (term->str = "$");

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, pinfo, keep_persistent_data);

                        proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen,
                            "WildCard any");
                            col_append_str(pinfo->cinfo, COL_INFO, "=$");
                        break;
                    case 'O':
                        break;

                    default:
                        /*** TERM ***/
                        switch (megaco_command) {
                        case MEGACO_CMD_PRIORITY:
                            proto_tree_add_string(megaco_tree_command_line, hf_megaco_priority, tvb,
                                tvb_offset, tokenlen,
                                tvb_format_text(pinfo->pool, tvb, tvb_offset,
                                    tokenlen));
                            break;
                        default:
                            proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                                tvb_offset, tokenlen,
                                tvb_format_text(pinfo->pool, tvb, tvb_offset,
                                    tokenlen));

                            term->len = tokenlen;
                            term->buffer = (const guint8*)(term->str = tvb_format_text(pinfo->pool, tvb, tvb_offset, tokenlen));

                            gcp_cmd_add_term(msg, trx, cmd, term, wild_term, pinfo, keep_persistent_data);
                            break;
                        }

                        col_append_fstr(pinfo->cinfo, COL_INFO, "=%s",tvb_format_text(pinfo->pool, tvb, tvb_offset,tokenlen));
                        break;
                    }

            }
            /* Dissect the Descriptors */


            if ( LBRKT_counter != 0 && tvb_current_offset != tvb_command_end_offset){

                tvb_descriptors_start_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                    tvb_transaction_end_offset, '{');

                tvb_descriptors_end_offset = tvb_descriptors_start_offset;
                if ( tvb_descriptors_end_offset > tvb_transaction_end_offset )
                    tvb_descriptors_end_offset = tvb_transaction_end_offset;

                while ( LBRKT_counter > 0 ){

                    tvb_descriptors_end_offset = tvb_find_guint8(tvb, tvb_descriptors_end_offset+1,
                        tvb_transaction_end_offset, '}');

                    LBRKT_counter--;

                }

                tempchar = tvb_get_guint8(tvb, tvb_command_start_offset);

                if ( tempchar == 'E'|| tempchar == 'e'){
                    dissect_megaco_descriptors(tvb, megaco_tree_command_line, pinfo, tvb_command_start_offset-1,tvb_descriptors_end_offset, tree, ctx_id);
                }
                else {
                    dissect_megaco_descriptors(tvb, megaco_tree_command_line, pinfo, tvb_descriptors_start_offset,tvb_descriptors_end_offset, tree, ctx_id);
                }
            }
            RBRKT_counter = 0;
            LBRKT_counter = 0;
            tvb_command_start_offset = megaco_tvb_skip_wsp(tvb, tvb_command_end_offset +1);
            tvb_LBRKT = tvb_command_start_offset;
            tvb_RBRKT = tvb_command_start_offset;

            }

        } while ( tvb_command_end_offset < tvb_transaction_end_offset );

        if (keep_persistent_data) {
            gcp_msg_to_str(msg,pinfo->pool,keep_persistent_data);
            gcp_analyze_msg(megaco_tree, pinfo, tvb, msg, &megaco_ctx_ids, &ei_megaco_errored_command);
        }

        tvb_next_offset = tvb_transaction_end_offset;
    }
    while( tvb_transaction_end_offset > 0 && tvb_transaction_end_offset < tvb_len - 2);

    if(global_megaco_raw_text){
        tvb_raw_text_add(tvb, megaco_tree);
    }

    return tvb_captured_length(tvb);
}

#define MEGACO_MODEM_TOKEN          1
#define MEGACO_MUX_TOKEN            2
#define MEGACO_MEDIA_TOKEN          3
#define MEGACO_SIGNALS_TOKEN        4
#define MEGACO_SERVICES_TOKEN       5
#define MEGACO_STATS_TOKEN          6
#define MEGACO_ERROR_TOKEN          7
#define MEGACO_EVENTS_TOKEN         8
#define MEGACO_AUDIT_TOKEN          9
#define MEGACO_DIGITMAP_TOKEN       10
#define MEGACO_OE_TOKEN             11
#define MEGACO_TOPOLOGY_TOKEN       12
#define MEGACO_PACKAGES_TOKEN       13

static const megaco_tokens_t megaco_descriptors_names[] = {
    { "Unknown-token",              NULL }, /* 0 Pad so that the real headers start at index 1 */
    { "Modem",                      "MD" }, /* 1 */
    { "Mux",                        "MX" }, /* 2 */
    { "Media",                      "M" },  /* 3 */
    { "Signals",                    "SG" }, /* 4 */
    { "Services",                   "SV" }, /* 5 */
    { "Statistics",                 "SA" }, /* 6 */
    { "Error",                      "ER" }, /* 7 */
    { "Events",                     "E" },  /* 8 */
    { "Audit",                      "AT" }, /* 9 */
    { "DigitMap",                   "DM" }, /* 10 */
    { "ObservedEvents",             "OE" }, /* 11 */
    { "Topology",                   "TP" }, /* 12 */
    { "Packages",                   "PG" }, /* 13 */
};

/* Returns index of megaco_tokens_t */
/* note - also called by dissect_megaco_auditdescriptor */
static gint find_megaco_descriptors_names(tvbuff_t *tvb, int offset, guint header_len)
{
    guint i;

    for (i = 1; i < array_length(megaco_descriptors_names); i++) {
        if (header_len == strlen(megaco_descriptors_names[i].name) &&
            tvb_strncaseeql(tvb, offset, megaco_descriptors_names[i].name, header_len) == 0)
            return i;
        if (megaco_descriptors_names[i].compact_name != NULL &&
            header_len == strlen(megaco_descriptors_names[i].compact_name) &&
            tvb_strncaseeql(tvb, offset, megaco_descriptors_names[i].compact_name, header_len) == 0)
            return i;
    }
    return -1;
}

static void
dissect_megaco_modemdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_modem_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(wmem_packet_scope(), tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_multiplexdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_multiplex_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(wmem_packet_scope(), tvb, tvb_previous_offset,
                            tokenlen));

}

/* mediaDescriptor = MediaToken LBRKT mediaParm *(COMMA mediaParm) RBRKT
 *  MediaToken = ("Media" / "M")
 *
 *      mediaParm = (streamParm / streamDescriptor /terminationStateDescriptor)
 *
 *  ; at-most one terminationStateDescriptor
 *  ; and either streamParm(s) or streamDescriptor(s) but not both
 *          streamParm = ( localDescriptor / remoteDescriptor /localControlDescriptor )
 *              localDescriptor = LocalToken LBRKT octetString RBRKT
 *                          LocalToken = ("Local" / "L")
 *                          octetString = *(nonEscapeChar)
 *                                  nonEscapeChar = ( "\}" / %x01-7C / %x7E-FF )
 *              remoteDescriptor = RemoteToken LBRKT octetString RBRKT
 *                          RemoteToken = ("Remote" / "R")
 *              localControlDescriptor = LocalControlToken LBRKT localParm*(COMMA localParm) RBRKT
 *                          LocalControlToken = ("LocalControl" / "O")
 *                          localParm = ( streamMode / propertyParm / reservedValueMode
 *          streamDescriptor = StreamToken EQUAL StreamID LBRKT streamParm*(COMMA streamParm) RBRKT
 *                          StreamToken = ("Stream" / "ST")
 *          terminationStateDescriptor = TerminationStateToken LBRKTterminationStateParm
 *                              *( COMMA terminationStateParm ) RBRKT
 *                          TerminationStateToken = ("TerminationState" / "TS")
 *                          terminationStateParm =(propertyParm / serviceStates / eventBufferControl )
 */

#define MEGACO_LOCAL_TOKEN              1
#define MEGACO_REMOTE_TOKEN             2
#define MEGACO_LOCAL_CONTROL_TOKEN      3
#define MEGACO_STREAM_TOKEN             4
#define MEGACO_TERMINATION_STATE_DESC   5

static const megaco_tokens_t megaco_mediaParm_names[] = {
    { "Unknown-token",              NULL }, /* 0 Pad so that the real headers start at index 1 */
    { "Local",                      "L" },  /* 1 */
    { "Remote",                     "R" },  /* 2 */
    { "LocalControl",               "O" },  /* 3 */
    { "Stream",                     "ST" }, /* 4 */
    { "TerminationState",           "TS" }, /* 5 */
};

/* Returns index of megaco_tokens_t */
static gint find_megaco_mediaParm_names(tvbuff_t *tvb, int offset, guint header_len)
{
    guint i;

    for (i = 1; i < array_length(megaco_mediaParm_names); i++) {
        if (header_len == strlen(megaco_mediaParm_names[i].name) &&
            tvb_strncaseeql(tvb, offset, megaco_mediaParm_names[i].name, header_len) == 0)
            return i;
        if (megaco_mediaParm_names[i].compact_name != NULL &&
            header_len == strlen(megaco_mediaParm_names[i].compact_name) &&
            tvb_strncaseeql(tvb, offset, megaco_mediaParm_names[i].compact_name, header_len) == 0)
            return i;
    }

    return -1;
}

static void
dissect_megaco_mediadescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,packet_info *pinfo,  gint tvb_last_RBRKT,
                                gint tvb_previous_offset, gint start_offset, proto_tree *top_tree, guint32 context)
{

    gint    tokenlen, tvb_LBRKT, tvb_RBRKT;
    gint    tvb_next_offset, tvb_current_offset, tvb_offset, equal_offset, save_offset;
    gint    mediaParm;
    guint   streamId;

    proto_tree  *megaco_mediadescriptor_tree;
    proto_item  *megaco_mediadescriptor_ti, *ti;

    megaco_mediadescriptor_ti = proto_tree_add_item(megaco_tree_command_line, hf_megaco_media_descriptor, tvb, start_offset, 1, ENC_NA);
    megaco_mediadescriptor_tree = proto_item_add_subtree(megaco_mediadescriptor_ti, ett_megaco_mediadescriptor);

    while ( tvb_previous_offset < tvb_last_RBRKT){
        /* Start of token */
        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);

        /* Find token length */
        for (tvb_next_offset=tvb_current_offset; tvb_next_offset < tvb_last_RBRKT; tvb_next_offset++){
                if (!g_ascii_isalpha(tvb_get_guint8(tvb, tvb_next_offset ))){
                break;
            }
        }
        tokenlen = tvb_next_offset - tvb_current_offset;

        mediaParm = find_megaco_mediaParm_names(tvb, tvb_current_offset, tokenlen);

        tvb_LBRKT = tvb_find_guint8(tvb, tvb_next_offset , tvb_last_RBRKT, '{');
        tvb_next_offset = tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_last_RBRKT, '}');
        tvb_RBRKT = tvb_next_offset;

        switch ( mediaParm ){
        case MEGACO_LOCAL_TOKEN:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_LocalRemotedescriptor(tvb, megaco_mediadescriptor_tree, pinfo,
                tvb_RBRKT, tvb_current_offset, context, TRUE);
            tvb_current_offset = tvb_RBRKT;
            break;
        case MEGACO_REMOTE_TOKEN:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_LocalRemotedescriptor(tvb, megaco_mediadescriptor_tree, pinfo,
                tvb_RBRKT, tvb_current_offset, context, FALSE);
            tvb_current_offset = tvb_RBRKT;
            break;
        case MEGACO_LOCAL_CONTROL_TOKEN:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_LocalControldescriptor(tvb, megaco_mediadescriptor_tree, pinfo,
                tvb_RBRKT, tvb_current_offset, top_tree);
            tvb_current_offset = tvb_RBRKT;
            break;
        case MEGACO_STREAM_TOKEN:
            save_offset = tvb_current_offset;
            equal_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_last_RBRKT, '=');
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, equal_offset+1);
            tvb_offset = megaco_tvb_skip_wsp_return(tvb, tvb_LBRKT-1);
            tokenlen =  tvb_offset - tvb_current_offset;

            streamId = (guint)strtoul(tvb_format_text(pinfo->pool, tvb, tvb_current_offset,tokenlen),NULL,10);
            ti = proto_tree_add_uint(megaco_mediadescriptor_tree, hf_megaco_streamid, tvb,
                save_offset, 1, streamId);
            proto_item_set_len(ti, tvb_offset-save_offset+tokenlen);
            tvb_previous_offset = tvb_LBRKT+1;
            continue;
        case MEGACO_TERMINATION_STATE_DESC:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_TerminationStatedescriptor(tvb, megaco_mediadescriptor_tree,
                tvb_RBRKT, tvb_current_offset);
            tvb_current_offset = tvb_RBRKT;
            break;
        default:
            break;
        };
        /* more parameters ? */
        tvb_next_offset = tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_last_RBRKT, ',');
        if (tvb_next_offset > tvb_last_RBRKT) tvb_next_offset = tvb_last_RBRKT;
        if ( tvb_next_offset != -1 ){
            /* (raw formatting removed)
               tokenlen = tvb_next_offset - tvb_RBRKT+1;
               proto_tree_add_format_text(megaco_mediadescriptor_tree, tvb, tvb_RBRKT, tokenlen); */
            tvb_previous_offset = tvb_next_offset+1;
        } else{
            /* Add the trailing '}' (raw formatting removed) */
            /* proto_tree_add_format_text(megaco_mediadescriptor_tree, tvb, tvb_RBRKT, 1); */
            tvb_previous_offset = tvb_last_RBRKT;
        }

    } /* End while */

    proto_item_set_end(megaco_mediadescriptor_ti, tvb, tvb_previous_offset);
}

static void
dissect_megaco_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree, gint offset, gint len, proto_tree *top_tree)
{
    /*proto_item *item;*/
    /*proto_tree *tree;*/
    gchar *msg = tvb_format_text(pinfo->pool, tvb, offset, len);

    /*item= */proto_tree_add_item(megaco_tree, hf_megaco_h245, tvb, offset, len, ENC_NA);
    /*tree = proto_item_add_subtree(item, ett_megaco_h245); */

    /* arbitrary maximum length */
    if(len<20480){
        int i;
        tvbuff_t *h245_tvb;
        guint8 *buf = (guint8 *)wmem_alloc(pinfo->pool, 10240);

        /* first, skip to where the encoded pdu starts, this is
           the first hex digit after the '=' char.
        */
        while(1){
            if((*msg==0)||(*msg=='\n')){
                return;
            }
            if(*msg=='='){
                msg++;
                break;
            }
            msg++;
        }
        while(1){
            if((*msg==0)||(*msg=='\n')){
                return;
            }
            if( ((*msg>='0')&&(*msg<='9'))
            ||  ((*msg>='a')&&(*msg<='f'))
            ||  ((*msg>='A')&&(*msg<='F'))){
                break;
            }
            msg++;
        }
        i=0;
        while( ((*msg>='0')&&(*msg<='9'))
             ||((*msg>='a')&&(*msg<='f'))
             ||((*msg>='A')&&(*msg<='F'))  ){
            int val;
            if((*msg>='0')&&(*msg<='9')){
                val=(*msg)-'0';
            } else if((*msg>='a')&&(*msg<='f')){
                val=(*msg)-'a'+10;
            } else if((*msg>='A')&&(*msg<='F')){
                val=(*msg)-'A'+10;
            } else {
                return;
            }
            val<<=4;
            msg++;
            if((*msg>='0')&&(*msg<='9')){
                val|=(*msg)-'0';
            } else if((*msg>='a')&&(*msg<='f')){
                val|=(*msg)-'a'+10;
            } else if((*msg>='A')&&(*msg<='F')){
                val|=(*msg)-'A'+10;
            } else {
                return;
            }
            msg++;

            buf[i]=(guint8)val;
            i++;
        }
        if(i==0){
            return;
        }
        h245_tvb = tvb_new_child_real_data(tvb, buf,i,i);
        add_new_data_source(pinfo, h245_tvb, "H.245 over MEGACO");
        /* should go through a handle, however,  the two h245 entry
           points are different, one is over tpkt and the other is raw
        */
        call_dissector(h245_handle, h245_tvb, pinfo, top_tree);
/*      dissect_h245_MultimediaSystemControlMessage(h245_tvb, pinfo, tree);*/
    }
}

static void
dissect_megaco_h324_h223caprn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree, gint offset _U_, gint len, gchar *msg)
{
    asn1_ctx_t actx;

    /* arbitrary maximum length */
    if(len<20480){
        int i;
        tvbuff_t *h245_tvb;
        guint8 *buf = (guint8 *)wmem_alloc(pinfo->pool, 10240);

        /* first, skip to where the encoded pdu starts, this is
           the first hex digit after the '=' char.
        */
        while(1){
            if((*msg==0)||(*msg=='\n')){
                return;
            }
            if(*msg=='='){
                msg++;
                break;
            }
            msg++;
        }
        while(1){
            if((*msg==0)||(*msg=='\n')){
                return;
            }
            if( ((*msg>='0')&&(*msg<='9'))
            ||  ((*msg>='a')&&(*msg<='f'))
            ||  ((*msg>='A')&&(*msg<='F'))){
                break;
            }
            msg++;
        }
        i=0;
        while( ((*msg>='0')&&(*msg<='9'))
             ||((*msg>='a')&&(*msg<='f'))
             ||((*msg>='A')&&(*msg<='F'))  ){
            int val;
            if((*msg>='0')&&(*msg<='9')){
                val=(*msg)-'0';
            } else if((*msg>='a')&&(*msg<='f')){
                val=(*msg)-'a'+10;
            } else if((*msg>='A')&&(*msg<='F')){
                val=(*msg)-'A'+10;
            } else {
                return;
            }
            val<<=4;
            msg++;
            if((*msg>='0')&&(*msg<='9')){
                val|=(*msg)-'0';
            } else if((*msg>='a')&&(*msg<='f')){
                val|=(*msg)-'a'+10;
            } else if((*msg>='A')&&(*msg<='F')){
                val|=(*msg)-'A'+10;
            } else {
                return;
            }
            msg++;

            buf[i]=(guint8)val;
            i++;
        }
        if(i==0){
            return;
        }
        h245_tvb = tvb_new_child_real_data(tvb, buf,i,i);
        add_new_data_source(pinfo, h245_tvb, "H.245 over MEGACO");
        /* should go through a handle, however,  the two h245 entry
           points are different, one is over tpkt and the other is raw
        */
        asn1_ctx_init(&actx, ASN1_ENC_PER, TRUE, pinfo);
        dissect_h245_H223Capability(h245_tvb, 0, &actx, megaco_tree, hf_megaco_h223Capability);
    }
}

static void
dissect_megaco_eventsdescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset, proto_tree *top_tree)
{

    gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_events_end_offset, tvb_LBRKT;
    proto_tree  *megaco_eventsdescriptor_tree, *megaco_requestedevent_tree;
    proto_item  *megaco_eventsdescriptor_ti, *megaco_requestedevent_ti, *ti;

    gint requested_event_start_offset = 0,
         requested_event_end_offset = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;

    megaco_eventsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_events_descriptor,tvb,tvb_previous_offset, tokenlen, ENC_NA);
    megaco_eventsdescriptor_tree = proto_item_add_subtree(megaco_eventsdescriptor_ti, ett_megaco_eventsdescriptor);

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
    tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');

    if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){

        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_next_offset-1);

        tokenlen =  tvb_help_offset - tvb_current_offset;

        ti = proto_tree_add_uint(megaco_eventsdescriptor_tree, hf_megaco_requestid, tvb,
            tvb_current_offset, 1,
            (guint32) strtoul(tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen), NULL, 10));
        proto_item_set_len(ti, tokenlen);

        tvb_events_end_offset   = tvb_RBRKT;

        tvb_RBRKT = tvb_next_offset+1;
        tvb_LBRKT = tvb_next_offset+1;
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_next_offset+1);


        do {

            tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
                tvb_events_end_offset, '}');
            tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
                tvb_events_end_offset, '{');

            tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
                tvb_events_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_events_end_offset){
                tvb_current_offset = tvb_events_end_offset;
            }


            /* Descriptor includes no parameters */

            if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){

                tvb_RBRKT = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
            }

            /* Descriptor includes Parameters */

            if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){

                while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){

                    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
                        tvb_events_end_offset, '{');
                    if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
                        tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
                        tvb_events_end_offset, '}');
                }

            }

            tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_events_end_offset, '{');

            /* if there are eventparameter  */

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                requested_event_start_offset = tvb_help_offset;
                requested_event_end_offset   = tvb_RBRKT;
                tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_help_offset-1);
                tokenlen = tvb_help_offset - tvb_previous_offset;
            }
            /* no parameters */
            else {
                tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
            }

            megaco_requestedevent_ti = proto_tree_add_item(megaco_eventsdescriptor_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,tokenlen, ENC_UTF_8);
            megaco_requestedevent_tree = proto_item_add_subtree(megaco_requestedevent_ti, ett_megaco_requestedevent);

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                requested_event_start_offset = megaco_tvb_skip_wsp(tvb, requested_event_start_offset +1);
                requested_event_end_offset = megaco_tvb_skip_wsp_return(tvb, requested_event_end_offset-1);

                if (!tvb_strncaseeql(tvb, requested_event_start_offset, "dm", 2)) {
                    dissect_megaco_digitmapdescriptor(tvb, megaco_requestedevent_tree, requested_event_end_offset, requested_event_start_offset);
                }
                else{
                    tokenlen =  requested_event_end_offset - requested_event_start_offset;
                    if(!tvb_strneql(tvb, requested_event_start_offset, "h245", 4)){
                        dissect_megaco_h245(tvb, pinfo, megaco_requestedevent_tree, requested_event_start_offset, tokenlen, top_tree);
                    } else {
                        proto_tree_add_format_text(megaco_requestedevent_tree, tvb, requested_event_start_offset, tokenlen);
                    }
                }

            }

            tvb_previous_offset = tvb_current_offset;
            tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
                tvb_events_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_events_end_offset || tvb_current_offset < tvb_previous_offset ) {
                tvb_current_offset = tvb_events_end_offset;
            }

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);

            tvb_LBRKT = tvb_previous_offset;
            tvb_RBRKT = tvb_previous_offset;

        } while ( tvb_current_offset < tvb_events_end_offset );
    }
}

static void
dissect_megaco_signaldescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset, proto_tree *top_tree)
{

    gint tokenlen, pkg_tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_signals_end_offset, tvb_signals_start_offset, tvb_LBRKT;
    proto_tree  *megaco_signalsdescriptor_tree, *megaco_requestedsignal_tree;
    proto_item  *megaco_signalsdescriptor_ti, *megaco_requestedsignal_ti;

    gint requested_signal_start_offset = 0,
         requested_signal_end_offset = 0;

    tvb_signals_end_offset   = tvb_RBRKT;
    tvb_signals_start_offset = tvb_previous_offset;

    if(g_ascii_toupper(tvb_get_guint8(tvb, tvb_previous_offset+1))=='G')
      tokenlen = 2;                             /* token is compact text (SG) */
    else
      tokenlen = 7;                             /* token must be verbose text (Signals) */

    tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset+tokenlen);

    if(tvb_get_guint8(tvb, tvb_current_offset)!='{') {          /* {} has been omitted */

      megaco_signalsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line, hf_megaco_signal_descriptor, tvb, tvb_signals_start_offset, tokenlen, ENC_NA);
      expert_add_info(pinfo, megaco_signalsdescriptor_ti, &ei_megaco_signal_descriptor);

      col_append_str(pinfo->cinfo, COL_INFO, " (Signal:none)");     /* then say so */

      return;                               /* and return */
    }

    tvb_LBRKT = tvb_find_guint8(tvb, tvb_previous_offset, tvb_signals_end_offset, '{');
    tokenlen =  (tvb_LBRKT+1) - tvb_signals_start_offset;

    megaco_signalsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_signal_descriptor,tvb,tvb_previous_offset,tokenlen, ENC_NA);
    megaco_signalsdescriptor_tree = proto_item_add_subtree(megaco_signalsdescriptor_ti, ett_megaco_signalsdescriptor);

    tvb_current_offset = tvb_LBRKT;
    tvb_next_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (Signal:%s)",tvb_format_text(pinfo->pool, tvb, tvb_current_offset,tokenlen-tvb_current_offset+tvb_previous_offset));


    if ( tvb_current_offset < tvb_signals_end_offset && tvb_current_offset != -1 && tvb_next_offset != tvb_signals_end_offset){


        tvb_RBRKT = tvb_next_offset+1;
        tvb_LBRKT = tvb_next_offset+1;
        tvb_previous_offset = tvb_next_offset;


        do {

            tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
                tvb_signals_end_offset, '}');
            tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
                tvb_signals_end_offset, '{');

            tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
                tvb_signals_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_signals_end_offset){
                tvb_current_offset = tvb_signals_end_offset;
            }


            /* Descriptor includes no parameters */

            if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){

                tvb_RBRKT = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
            }

            /* Descriptor includes Parameters */

            if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){

                while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){

                    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
                        tvb_signals_end_offset, '{');
                    if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
                        tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
                        tvb_signals_end_offset, '}');
                }

            }

            tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_signals_end_offset, '{');

            /* if there are signalparameter  */

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                requested_signal_start_offset = tvb_help_offset;
                requested_signal_end_offset  = tvb_RBRKT;
                tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_help_offset-1);
                pkg_tokenlen = tvb_help_offset - tvb_previous_offset;
            }
            /* no parameters */
            else {
                 pkg_tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
             }

            megaco_requestedsignal_ti = proto_tree_add_item(megaco_signalsdescriptor_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,pkg_tokenlen, ENC_UTF_8);
            megaco_requestedsignal_tree = proto_item_add_subtree(megaco_requestedsignal_ti, ett_megaco_requestedsignal);

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
                requested_signal_start_offset = megaco_tvb_skip_wsp(tvb, requested_signal_start_offset +1);
                requested_signal_end_offset = megaco_tvb_skip_wsp_return(tvb, requested_signal_end_offset-1);

                tokenlen =  requested_signal_end_offset - requested_signal_start_offset;

                if(!tvb_strneql(tvb, requested_signal_start_offset, "h245", 4)){
                    dissect_megaco_h245(tvb, pinfo,  megaco_requestedsignal_tree, requested_signal_start_offset, tokenlen, top_tree);
                } else {
                    proto_tree_add_format_text( megaco_requestedsignal_tree, tvb, requested_signal_start_offset, tokenlen);
                }
                /* Print the trailing '}' (raw formatting removed) */
                /* proto_tree_add_format_text( megaco_requestedsignal_tree, tvb, tvb_RBRKT, 1); */
            }

            tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
                tvb_signals_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_signals_end_offset || tvb_current_offset < tvb_previous_offset){
                tvb_current_offset = tvb_signals_end_offset;
            }

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);

            tvb_LBRKT = tvb_previous_offset;
            tvb_RBRKT = tvb_previous_offset;
            /* Print the trailing '}' (raw formatting removed) */
            /* proto_tree_add_format_text(megaco_tree_command_line, tvb, tvb_signals_end_offset, 1); */

        } while ( tvb_current_offset < tvb_signals_end_offset );
    }else{
        /* signals{} (raw formatting removed)
        proto_tree_add_format_text(megaco_tree_command_line, tvb, tvb_signals_end_offset, 1); */
    }


}

/*
   auditDescriptor      = AuditToken LBRKT [ auditItem *(COMMA auditItem) ] RBRKT

   auditItem            = ( MuxToken / ModemToken / MediaToken /
                           SignalsToken / EventBufferToken /
                           DigitMapToken / StatsToken / EventsToken /
                           ObservedEventsToken / PackagesToken )                     */
static void
dissect_megaco_auditdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree, packet_info *pinfo _U_,  gint tvb_stop, gint tvb_offset)
{
    gint        tokenlen, tvb_end, tvb_next, token_index;
    proto_tree  *megaco_auditdescriptor_tree, *megaco_auditdescriptor_ti;

    tvb_next  = tvb_find_guint8(tvb, tvb_offset, tvb_stop, '{');           /* find opening LBRKT - is this already checked by caller?*/
    if( tvb_next == -1 )                                                   /* complain and give up if not there */
    {
        expert_add_info(pinfo, megaco_tree, &ei_megaco_audit_descriptor);
        return;
    }
    tokenlen = (tvb_stop + 1) - tvb_offset;

    megaco_auditdescriptor_ti = proto_tree_add_item( megaco_tree, hf_megaco_audit_descriptor, tvb, tvb_offset, tokenlen, ENC_NA);
    megaco_auditdescriptor_tree = proto_item_add_subtree( megaco_auditdescriptor_ti, ett_megaco_auditdescriptor );

    tvb_offset = tvb_next;

    while( tvb_offset < tvb_stop )
    {
        tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset+1);                                          /* find start of an auditItem */
        if( tvb_get_guint8(tvb, tvb_offset) != '}' )                                                  /* got something */
        {
            tvb_next = tvb_find_guint8(tvb, tvb_offset, tvb_stop, ',');                           /* end of an auditItem */
            if (tvb_next == -1)                                                                   /* last item doesn't have a comma */
                tvb_next = tvb_stop;
            tvb_end = megaco_tvb_skip_wsp_return(tvb, tvb_next-1);                                /* trim any trailing whitespace */
            tokenlen =  tvb_end - tvb_offset;                                                     /* get length of token */

            token_index = find_megaco_descriptors_names(tvb, tvb_offset, tokenlen);               /* lookup the token */
            if( token_index == -1 )                                                               /* if not found then 0 => Unknown */
                token_index = 0;

            proto_tree_add_string(megaco_auditdescriptor_tree, hf_megaco_audititem, tvb,
                    tvb_offset, tokenlen, megaco_descriptors_names[token_index].name);    /* and display the long form */

            tvb_offset = tvb_next;                                                                /* advance pointer */
        }
    }
}

/*
 *    serviceChangeDescriptor = ServicesToken LBRKT serviceChangeParm
 *                          *(COMMA serviceChangeParm) RBRKT
 *
 *    ServicesToken              = ("Services"              / "SV")
 *
 *    serviceChangeParm    = (serviceChangeMethod / serviceChangeReason /
 *                        serviceChangeDelay / serviceChangeAddress /
 *                       serviceChangeProfile / extension / TimeStamp /
 *                        serviceChangeMgcId / serviceChangeVersion )
 *
 */
#define MEGACO_REASON_TOKEN     1
#define MEGACO_DELAY_TOKEN      2
#define MEGACO_SC_ADDR_TOKEN    3
#define MEGACO_MGC_ID_TOKEN     4
#define MEGACO_PROFILE_TOKEN    5
#define MEGACO_VERSION_TOKEN    6
#define MEGACO_METHOD_TOKEN     7

static const megaco_tokens_t megaco_serviceChangeParm_names[] = {
    { "Unknown-token",              NULL }, /* 0 Pad so that the real headers start at index 1 */
    /* streamMode */
    { "Reason",                     "RE" }, /* 1 ReasonToken*/
    { "Delay",                      "DL" }, /* 2 DelayToken */
    { "ServiceChangeAddress",       "AD" }, /* 3 ServiceChangeAddressToken */
    { "MgcIdToTry",                 "MG" }, /* 4 MgcIdToken */
    { "Profile",                    "PF" }, /* 5 ProfileToken */
    { "Version",                    "V"  }, /* 6 VersionToken */
    { "Method",                     "MT" }, /* 7  MethodToken */
};

/* Returns index of megaco_tokens_t */
static gint find_megaco_megaco_serviceChangeParm_names(tvbuff_t *tvb, int offset, guint header_len)
{
    guint i;

    for (i = 1; i < array_length(megaco_serviceChangeParm_names); i++) {
        if (header_len == strlen(megaco_serviceChangeParm_names[i].name) &&
            tvb_strncaseeql(tvb, offset, megaco_serviceChangeParm_names[i].name, header_len) == 0)
            return i;
        if (megaco_serviceChangeParm_names[i].compact_name != NULL &&
            header_len == strlen(megaco_serviceChangeParm_names[i].compact_name) &&
            tvb_strncaseeql(tvb, offset, megaco_serviceChangeParm_names[i].compact_name, header_len) == 0)
            return i;
    }

    return -1;
}
/*
 * ServiceChangeReasons                                    References
 * --------------------                                    ----------
 */
static const value_string MEGACO_ServiceChangeReasons_vals[] = {
    {900, "Service Restored"},
    {901, "Cold Boot"},
    {902, "Warm Boot"},
    {903, "MGC Directed Change"},
    {904, "Termination malfunctioning"},
    {905, "Termination taken out of service"},
    {906, "Loss of lower layer connectivity (e.g. downstream sync)"},
    {907, "Transmission Failure"},
    {908, "MG Impending Failure"},
    {909, "MGC Impending Failure"},
    {910, "Media Capability Failure"},
    {911, "Modem Capability Failure"},
    {912, "Mux Capability Failure"},
    {913, "Signal Capability Failure"},
    {914, "Event Capability Failure"},
    {915, "State Loss"},
    {916, "Packages Change"},
    {917, "Capabilities Change"},
    {918, "Cancel Graceful"},
    {919, "Warm Failover"},
    {920, "Cold Failover"},
    {  0, NULL }
};

static void
dissect_megaco_servicechangedescriptor(tvbuff_t *tvb, packet_info* pinfo, proto_tree *megaco_tree,  gint tvb_RBRKT,
    gint tvb_previous_offset)
{

    gint        tokenlen, tvb_LBRKT, tvb_offset;
    gint        token_index;
    gint        tvb_current_offset;
    gboolean    more_params = TRUE;
    proto_item* item;
    gint                reason;
    gboolean            reason_valid;
    guint8              ServiceChangeReason_str[4];

    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
    /*
    if (tvb_LBRKT == -1)
        return;
        */
    tokenlen = (tvb_LBRKT + 1) - tvb_previous_offset;
    proto_tree_add_format_text(megaco_tree, tvb, tvb_previous_offset, tokenlen);

    /* Start dissecting serviceChangeParm */
    tvb_previous_offset = tvb_LBRKT + 1;
    while (more_params){
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);
        /* Find token length */
        for (tvb_offset=tvb_previous_offset; tvb_offset < tvb_RBRKT; tvb_offset++){
            if (!g_ascii_isalpha(tvb_get_guint8(tvb, tvb_offset ))){
                break;
            }
        }
        tokenlen = tvb_offset - tvb_previous_offset;
        token_index = find_megaco_megaco_serviceChangeParm_names(tvb, tvb_previous_offset, tokenlen);

        tvb_offset  = tvb_find_guint8(tvb, tvb_offset, tvb_RBRKT, ',');
        if ((tvb_offset == -1)||(tvb_offset >=tvb_RBRKT)){
            more_params = FALSE;
            tvb_offset = megaco_tvb_skip_wsp_return(tvb, tvb_RBRKT-1);
        }
        tokenlen = tvb_offset - tvb_previous_offset;
        if (more_params == TRUE )
            /* Include ',' */
            tokenlen++;
        switch(token_index){
        case MEGACO_REASON_TOKEN:
            /* ReasonToken  EQUAL VALUE
             * VALUE                = quotedString / 1*(SafeChar)
             */
            item = proto_tree_add_format_text(megaco_tree, tvb, tvb_previous_offset, tokenlen);

            /* As the reason code ( if a digit ) can be in quoted string or 'just' digit
             * look for a nine and hope for the best.
             */
            tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '9');
            if ( tvb_current_offset == -1)
                break;

            tvb_get_nstringz0(tvb,tvb_current_offset,4,ServiceChangeReason_str);
            reason_valid = ws_strtoi32(ServiceChangeReason_str, NULL, &reason);
            proto_item_append_text(item,"[ %s ]", val_to_str(reason, MEGACO_ServiceChangeReasons_vals,"Unknown (%u)"));
            if (!reason_valid)
                expert_add_info(pinfo, item, &ei_megaco_reason_invalid);
            break;
        case MEGACO_DELAY_TOKEN:
        case MEGACO_SC_ADDR_TOKEN:
        case MEGACO_MGC_ID_TOKEN:
        case MEGACO_PROFILE_TOKEN:
        case MEGACO_VERSION_TOKEN:
        case MEGACO_METHOD_TOKEN:
            /* No special dissection: fall through */
        default:
        /* Unknown or:
         * extension            = extensionParameter parmValue
         * extensionParameter   = "X"  ("-" / "+") 1*6(ALPHA / DIGIT)
         */
            proto_tree_add_format_text(megaco_tree, tvb, tvb_previous_offset, tokenlen);
            break;
        }

        tvb_previous_offset = tvb_offset +1;

    }/*End while */

    /* extension            = extensionParameter parmValue
     * extensionParameter   = "X"  ("-" / "+") 1*6(ALPHA / DIGIT)
     */

     /*
    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_servicechange_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(pinfo->pool, tvb, tvb_previous_offset,
                            tokenlen));
    */
    proto_tree_add_format_text(megaco_tree, tvb, tvb_RBRKT, 1);

}
static void
dissect_megaco_digitmapdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen =  tvb_RBRKT - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_digitmap_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(wmem_packet_scope(), tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_statisticsdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
    gint    tokenlen;
    proto_tree  *megaco_statisticsdescriptor_tree;
    proto_item  *megaco_statisticsdescriptor_ti;
    gint tvb_help_offset, param_start_offset, param_end_offset = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;

    megaco_statisticsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_statistics_descriptor,tvb,tvb_previous_offset,tokenlen, ENC_NA);
    megaco_statisticsdescriptor_tree = proto_item_add_subtree(megaco_statisticsdescriptor_ti, ett_megaco_statisticsdescriptor);

    tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset+1, tvb_RBRKT, '{');
    do {
        param_start_offset = megaco_tvb_skip_wsp(tvb, tvb_help_offset+1);

        tvb_help_offset = tvb_find_guint8(tvb, tvb_help_offset+1, tvb_RBRKT, ',');

        if ( tvb_help_offset > tvb_RBRKT || tvb_help_offset == -1){
            tvb_help_offset = tvb_RBRKT;
            param_end_offset = megaco_tvb_skip_wsp_return(tvb, tvb_RBRKT-1);
            tokenlen =  param_end_offset - param_start_offset;
        } else {
            param_end_offset = megaco_tvb_skip_wsp(tvb, tvb_help_offset-1);
            tokenlen =  param_end_offset - param_start_offset+1;
        }

        proto_tree_add_format_text(megaco_statisticsdescriptor_tree, tvb,param_start_offset, tokenlen);

    } while ( tvb_help_offset < tvb_RBRKT );
}

static void
dissect_megaco_observedeventsdescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset, proto_tree *top_tree)
{

    gint tokenlen, pkg_tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_observedevents_end_offset, tvb_LBRKT;
    proto_tree  *megaco_observedeventsdescriptor_tree, *megaco_observedevent_tree;
    proto_item  *megaco_observedeventsdescriptor_ti, *megaco_observedevent_ti, *ti;

    gint requested_event_start_offset, requested_event_end_offset, param_start_offset, param_end_offset;

    requested_event_start_offset    = 0;
    requested_event_end_offset  = 0;

    tvb_LBRKT = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
    tvb_next_offset = tvb_LBRKT;
    tokenlen =  (tvb_next_offset+1) - tvb_previous_offset;

    megaco_observedeventsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_observedevents_descriptor,tvb,tvb_previous_offset,tokenlen, ENC_NA);
    megaco_observedeventsdescriptor_tree = proto_item_add_subtree(megaco_observedeventsdescriptor_ti, ett_megaco_observedeventsdescriptor);

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
    tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');

    if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){

        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_next_offset-1);

        tokenlen =  tvb_help_offset - tvb_current_offset;

        ti = proto_tree_add_uint(megaco_observedeventsdescriptor_tree, hf_megaco_requestid, tvb,
            tvb_current_offset, 1,
            (guint32) strtoul(tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen), NULL, 10));
        proto_item_set_len(ti, tokenlen);

        tvb_observedevents_end_offset   = tvb_RBRKT;

        tvb_RBRKT = tvb_next_offset+1;
        tvb_LBRKT = tvb_next_offset+1;
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_next_offset+1);


        do {

            tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
                tvb_observedevents_end_offset, '}');
            tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
                tvb_observedevents_end_offset, '{');

            tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
                tvb_observedevents_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_observedevents_end_offset){
                tvb_current_offset = tvb_observedevents_end_offset;
            }


            /* Descriptor includes no parameters */

            if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){

                tvb_RBRKT = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
            }

            /* Descriptor includes Parameters */

            if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){

                while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){

                    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
                        tvb_observedevents_end_offset, '{');
                    if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1){
                        tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
                            tvb_observedevents_end_offset, '}');
                    }
                }

            }

            tvb_LBRKT = tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_observedevents_end_offset, '{');

            /* if there are eventparameter  */

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                requested_event_start_offset = tvb_help_offset;
                requested_event_end_offset   = tvb_RBRKT;
                tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_help_offset-1);
                pkg_tokenlen = tvb_help_offset - tvb_previous_offset;
                tokenlen = tvb_LBRKT+1 - tvb_previous_offset;
            }
            /* no parameters */
            else {
                tokenlen = pkg_tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
            }

            megaco_observedevent_ti = proto_tree_add_format_text(megaco_tree_command_line, tvb, tvb_previous_offset, tokenlen);

            megaco_observedevent_tree = proto_item_add_subtree(megaco_observedevent_ti, ett_megaco_observedevent);

            proto_tree_add_item(megaco_observedevent_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,pkg_tokenlen, ENC_UTF_8);

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                requested_event_start_offset = megaco_tvb_skip_wsp(tvb, requested_event_start_offset +1)-1;
                requested_event_end_offset = megaco_tvb_skip_wsp_return(tvb, requested_event_end_offset-1);

                tvb_help_offset = requested_event_start_offset;

                do {
                    param_start_offset = megaco_tvb_skip_wsp(tvb, tvb_help_offset+1);

                    tvb_help_offset = tvb_find_guint8(tvb, tvb_help_offset+1,requested_event_end_offset, ',');

                    if ( tvb_help_offset > requested_event_end_offset || tvb_help_offset == -1){
                        tvb_help_offset = requested_event_end_offset;
                    }

                    param_end_offset = megaco_tvb_skip_wsp(tvb, tvb_help_offset-1);

                    tokenlen =  param_end_offset - param_start_offset+1;
                    if(!tvb_strneql(tvb, param_start_offset, "h245", 4)){
                        dissect_megaco_h245(tvb, pinfo, megaco_tree_command_line, param_start_offset, tokenlen, top_tree);
                    } else {
                        proto_tree_add_format_text(megaco_tree_command_line, tvb, param_start_offset, tokenlen);
                    }


                } while ( tvb_help_offset < requested_event_end_offset );
            }

            tvb_previous_offset = tvb_current_offset;
            tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
                tvb_observedevents_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_observedevents_end_offset ){
                tvb_current_offset = tvb_observedevents_end_offset;
            }
            if (tvb_current_offset < tvb_previous_offset) {
                expert_add_info_format(pinfo, megaco_observedevent_ti, &ei_megaco_parse_error, "Parse error: Invalid offset");
                return;
            }

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);

            tvb_LBRKT = tvb_previous_offset;
            tvb_RBRKT = tvb_previous_offset;
            /* Print the trailing '}' (raw formatting removed) */
            /* proto_tree_add_format_text(megaco_tree_command_line, tvb, tvb_observedevents_end_offset, 1); */

        } while ( tvb_current_offset < tvb_observedevents_end_offset );
    }
}
static void
dissect_megaco_topologydescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_topology_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text_wsp(wmem_packet_scope(), tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_Packagesdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_packages_end_offset, tvb_LBRKT;
    proto_tree  *megaco_packagesdescriptor_tree;
    proto_item  *megaco_packagesdescriptor_ti, *ti;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;

    megaco_packagesdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_packages_descriptor,tvb,tvb_previous_offset,tokenlen, ENC_UTF_8);
    megaco_packagesdescriptor_tree = proto_item_add_subtree(megaco_packagesdescriptor_ti, ett_megaco_packagesdescriptor);

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
    tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');

    if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){

        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_next_offset-1);

        tokenlen =  tvb_help_offset - tvb_current_offset;

        ti = proto_tree_add_uint(megaco_packagesdescriptor_tree, hf_megaco_requestid, tvb,
            tvb_current_offset, 1,
            (guint32) strtoul(tvb_format_text(wmem_packet_scope(), tvb, tvb_current_offset, tokenlen), NULL, 10));
        proto_item_set_len(ti, tokenlen);

        tvb_packages_end_offset   = tvb_RBRKT;

        tvb_RBRKT = tvb_next_offset+1;
        tvb_LBRKT = tvb_next_offset+1;
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_next_offset+1);


        do {

            tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
                tvb_packages_end_offset, '}');
            tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
                tvb_packages_end_offset, '{');

            tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
                tvb_packages_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_packages_end_offset){
                tvb_current_offset = tvb_packages_end_offset;
            }


            /* Descriptor includes no parameters */

            if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){

                tvb_RBRKT = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
            }

            /* Descriptor includes Parameters */

            if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){

                while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){

                    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
                        tvb_packages_end_offset, '{');
                    if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
                        tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
                        tvb_packages_end_offset, '}');
                }

            }

            tokenlen = tvb_RBRKT+1 - tvb_previous_offset;

            proto_tree_add_format_text(megaco_packagesdescriptor_tree, tvb, tvb_previous_offset, tokenlen);

            tvb_current_offset      = tvb_find_guint8(tvb, tvb_RBRKT,
                tvb_packages_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_packages_end_offset ){
                tvb_current_offset = tvb_packages_end_offset;
            }

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);

            tvb_LBRKT = tvb_previous_offset;
            tvb_RBRKT = tvb_previous_offset;

        } while ( tvb_current_offset < tvb_packages_end_offset );
    }

}
/* The list of error code values is fetched from http://www.iana.org/assignments/megaco-h248    */
/* 2003-08-28                                           */

static const value_string MEGACO_error_code_vals[] = {

    {400, "Syntax error in message"},
    {401, "Protocol Error"},
    {402, "Unauthorized"},
    {403, "Syntax error in transaction request"},
    {406, "Version Not Supported"},
    {410, "Incorrect identifier"},
    {411, "The transaction refers to an unknown ContextId"},
    {412, "No ContextIDs available"},
    {421, "Unknown action or illegal combination of actions"},
    {422, "Syntax Error in Action"},
    {430, "Unknown TerminationID"},
    {431, "No TerminationID matched a wildcard"},
    {432, "Out of TerminationIDs or No TerminationID available"},
    {433, "TerminationID is already in a Context"},
    {434, "Max number of Terminations in a Context exceeded"},
    {435, "Termination ID is not in specified Context"},
    {440, "Unsupported or unknown Package"},
    {441, "Missing Remote or Local Descriptor"},
    {442, "Syntax Error in Command"},
    {443, "Unsupported or Unknown Command"},
    {444, "Unsupported or Unknown Descriptor"},
    {445, "Unsupported or Unknown Property"},
    {446, "Unsupported or Unknown Parameter"},
    {447, "Descriptor not legal in this command"},
    {448, "Descriptor appears twice in a command"},
    {450, "No such property in this package"},
    {451, "No such event in this package"},
    {452, "No such signal in this package"},
    {453, "No such statistic in this package"},
    {454, "No such parameter value in this package"},
    {455, "Property illegal in this Descriptor"},
    {456, "Property appears twice in this Descriptor"},
    {457, "Missing parameter in signal or event"},
    {458, "Unexpected Event/Request ID"},
    {459, "Unsupported or Unknown Profile"},
    {471, "Implied Add for Multiplex failure"},

    {500, "Internal software Failure in MG"},
    {501, "Not Implemented"},
    {502, "Not ready."},
    {503, "Service Unavailable"},
    {504, "Command Received from unauthorized entity"},
    {505, "Transaction Request Received before a Service Change Reply has been received"},
    {506, "Number of Transaction Pendings Exceeded"},
    {510, "Insufficient resources"},
    {512, "Media Gateway unequipped to detect requested Event"},
    {513, "Media Gateway unequipped to generate requested Signals"},
    {514, "Media Gateway cannot send the specified announcement"},
    {515, "Unsupported Media Type"},
    {517, "Unsupported or invalid mode"},
    {518, "Event buffer full"},
    {519, "Out of space to store digit map"},
    {520, "Digit Map undefined in the MG"},
    {521, "Termination is ServiceChanging"},
    {526, "Insufficient bandwidth"},
    {529, "Internal hardware failure in MG"},
    {530, "Temporary Network failure"},
    {531, "Permanent Network failure"},
    {532, "Audited Property, Statistic, Event or Signal does not exist"},
    {533, "Response exceeds maximum transport PDU size"},
    {534, "Illegal write or read only property"},
    {540, "Unexpected initial hook state"},
    {581, "Does Not Exist"},

    {600, "Illegal syntax within an announcement specification"},
    {601, "Variable type not supported"},
    {602, "Variable value out of range"},
    {603, "Category not supported"},
    {604, "Selector type not supported"},
    {605, "Selector value not supported"},
    {606, "Unknown segment ID"},
    {607, "Mismatch between play specification and provisioned data"},
    {608, "Provisioning error"},
    {609, "Invalid offset"},
    {610, "No free segment IDs"},
    {611, "Temporary segment not found"},
    {612, "Segment in use"},
    {613, "ISP port limit overrun"},
    {614, "No modems available"},
    {615, "Calling number unacceptable"},
    {616, "Called number unacceptable"},
    {  0, NULL }
};



static void
dissect_megaco_errordescriptor(tvbuff_t *tvb, packet_info* pinfo, proto_tree *megaco_tree_command_line,
    gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint                tokenlen;
    gint                error_code;
    guint8              error[4];
    gint                tvb_current_offset;
    proto_item*         item;
    proto_tree*         error_tree;
    gboolean            error_code_valid;

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset , tvb_RBRKT, '=');
    tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);

    tokenlen =  (tvb_RBRKT) - tvb_previous_offset+1;

    item = proto_tree_add_item(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
                            tvb_previous_offset, tokenlen, ENC_NA);
    error_tree = proto_item_add_subtree(item, ett_megaco_error_descriptor);

    /* Get the error code */
    tvb_get_nstringz0(tvb,tvb_current_offset,4,error);
    error_code_valid = ws_strtoi32(error, NULL, &error_code);
    item = proto_tree_add_uint(error_tree, hf_megaco_error_code, tvb, tvb_current_offset, 3, error_code);
    if (!error_code_valid)
        expert_add_info(pinfo, item, &ei_megaco_error_code_invalid);

    /* Get the error string (even though we have a value_string that should match) */
    tvb_previous_offset = tvb_find_guint8(tvb, tvb_current_offset, tvb_RBRKT, '\"');
    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset+1, tvb_RBRKT, '\"');

    tokenlen =  tvb_current_offset - tvb_previous_offset-1;
    proto_tree_add_item(error_tree, hf_megaco_error_string, tvb, tvb_previous_offset+1, tokenlen, ENC_UTF_8);
}
static void
dissect_megaco_TerminationStatedescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,  gint tvb_next_offset, gint tvb_current_offset)
{
    gint tokenlen;
    gint tvb_offset;
    guint8 tempchar;

    proto_tree  *megaco_TerminationState_tree, *megaco_TerminationState_ti;

    tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');

    tokenlen = tvb_next_offset - tvb_current_offset;
    megaco_TerminationState_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_TerminationState_descriptor,tvb,tvb_current_offset,tokenlen, ENC_NA);
    megaco_TerminationState_tree = proto_item_add_subtree(megaco_TerminationState_ti, ett_megaco_TerminationState);

    while ( tvb_offset < tvb_next_offset && tvb_offset != -1 ){

        tempchar = tvb_get_guint8(tvb, tvb_current_offset);
        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
        if ( (tempchar >= 'a')&& (tempchar <= 'z'))
            tempchar = tempchar - 0x20;

        switch ( tempchar ){

        case 'S':
            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tokenlen = tvb_offset - tvb_current_offset;

            proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Service_State, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(wmem_packet_scope(), tvb, tvb_current_offset,
                tokenlen));

            break;

        case 'B':

            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tokenlen = tvb_offset - tvb_current_offset;

            proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Event_Buffer_Control, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(wmem_packet_scope(), tvb, tvb_current_offset,
                tokenlen));

            break;

        case 'E':
            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tokenlen = tvb_offset - tvb_current_offset;

            proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Event_Buffer_Control, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(wmem_packet_scope(), tvb, tvb_current_offset,
                tokenlen));

            break;

        default:
            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tokenlen = tvb_offset - tvb_current_offset;

            proto_tree_add_format_text(megaco_TerminationState_tree, tvb, tvb_current_offset, tokenlen);
            break;
        }


        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
        tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');

    }
    /* (raw formatting removed)
    proto_tree_add_format_text(megaco_mediadescriptor_tree, tvb, tvb_next_offset, 1); */
}

static void
dissect_megaco_LocalRemotedescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree, packet_info *pinfo,
                          gint tvb_next_offset, gint tvb_current_offset, guint32 context, gboolean is_local)
{
    gint tokenlen;
    tvbuff_t *next_tvb;
    http_message_info_t message_info = { SIP_DATA, NULL, NULL, NULL };

    sdp_setup_info_t setup_info;

    /* Only fill in the info when we have valid contex */
    if ((context != 0) && (context < 0xfffffffe)) {
        setup_info.hf_id = hf_megaco_Context;
        setup_info.hf_type = SDP_TRACE_ID_HF_TYPE_GUINT32;
        if (!sip_hide_generated_call_ids) {
            setup_info.add_hidden = FALSE;
        } else {
            setup_info.add_hidden = prefs_get_bool_value(sip_hide_generated_call_ids, pref_current);
        }
        setup_info.trace_id.num = context;
        message_info.data = &setup_info;
    }

    proto_tree  *megaco_localdescriptor_tree;
    proto_item  *megaco_localdescriptor_item;

    tokenlen = tvb_next_offset - tvb_current_offset;

    if (is_local) {
        megaco_localdescriptor_item = proto_tree_add_item(megaco_mediadescriptor_tree, hf_megaco_Local_descriptor, tvb, tvb_current_offset, tokenlen, ENC_NA);
        megaco_localdescriptor_tree = proto_item_add_subtree(megaco_localdescriptor_item, ett_megaco_Localdescriptor);
    } else {
        megaco_localdescriptor_item = proto_tree_add_item(megaco_mediadescriptor_tree, hf_megaco_Remote_descriptor, tvb, tvb_current_offset, tokenlen, ENC_NA);
        megaco_localdescriptor_tree = proto_item_add_subtree(megaco_localdescriptor_item, ett_megaco_Remotedescriptor);
    }

    if ( tokenlen > 3 ){
        next_tvb = tvb_new_subset_length(tvb, tvb_current_offset, tokenlen);
        call_dissector_with_data(sdp_handle, next_tvb, pinfo, megaco_localdescriptor_tree, &message_info);
    }
}

/*
 *   localControlDescriptor = LocalControlToken LBRKT localParm
 *                          *(COMMA localParm) RBRKT
 *   ; at-most-once per item
 *   localParm            = ( streamMode / propertyParm / reservedValueMode / reservedGroupMode )
 */

#define MEGACO_MODETOKEN            1
#define MEGACO_RESERVEDVALUETOKEN   2
#define MEGACO_RESERVEDGROUPTOKEN   3
#define MEGACO_H324_H223CAPR        4
#define MEGACO_H324_MUXTBL_IN       5
#define MEGACO_H324_MUXTBL_OUT      6
#define MEGACO_DS_DSCP              7
#define MEGACO_GM_SAF               8
#define MEGACO_GM_SAM               9
#define MEGACO_GM_SPF               10
#define MEGACO_GM_SPR               11
#define MEGACO_GM_ESAS              12
#define MEGACO_GM_LSA               13
#define MEGACO_GM_ESPS              14
#define MEGACO_GM_LSP               15
#define MEGACO_GM_RSB               16
#define MEGACO_TMAN_POL             17
#define MEGACO_TMAN_SDR             18
#define MEGACO_TMAN_MBS             19
#define MEGACO_TMAN_PDR             20
#define MEGACO_TMAN_DVT             21
#define MEGACO_IPDC_REALM           22

static const megaco_tokens_t megaco_localParam_names[] = {
    { "Unknown-token",              NULL }, /* 0 Pad so that the real headers start at index 1 */
    /* streamMode */
    { "Mode",                       "MO" }, /* 1 */
    { "ReservedValue",              "RV" }, /* 2 */
    { "ReservedGroup",              "RG" }, /* 3 */
    /* propertyParm         = pkgdName parmValue
     * Add more package names as needed.
     */
    { "h324/h223capr",              NULL }, /* 4 */
    { "h324/muxtbl_in",             NULL }, /* 5 */
    { "h324/muxtbl_out",            NULL }, /* 6 */
    { "ds/dscp",                    NULL }, /* 7 */
    { "gm/saf",                     NULL }, /* 8 */
    { "gm/sam",                     NULL }, /* 9 */
    { "gm/spf",                     NULL }, /* 10 */
    { "gm/spr",                     NULL }, /* 11 */
    { "gm/esas",                    NULL }, /* 12 */
    { "gm/lsa",                     NULL }, /* 13 */
    { "gm/esps",                    NULL }, /* 14 */
    { "gm/lsp",                     NULL }, /* 15 */
    { "gm/rsb",                     NULL }, /* 16 */
    { "tman/pol",                   NULL }, /* 17 */
    { "tman/sdr",                   NULL }, /* 18 */
    { "tman/mbs",                   NULL }, /* 19 */
    { "tman/pdr",                   NULL }, /* 20 */
    { "tman/dvt",                   NULL }, /* 21 */
    { "ipdc/realm",                 NULL }, /* 22 */
};

/* Returns index of megaco_tokens_t */
static gint find_megaco_localParam_names(tvbuff_t *tvb, int offset, guint header_len)
{
    guint i;

    for (i = 1; i < array_length(megaco_localParam_names); i++) {
        if (header_len == strlen(megaco_localParam_names[i].name) &&
            tvb_strncaseeql(tvb, offset, megaco_localParam_names[i].name, header_len) == 0)
            return i;
        if (megaco_localParam_names[i].compact_name != NULL &&
            header_len == strlen(megaco_localParam_names[i].compact_name) &&
            tvb_strncaseeql(tvb, offset, megaco_localParam_names[i].compact_name, header_len) == 0)
            return i;
    }

    return -1;
}

static void
dissect_megaco_LocalControldescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree, packet_info *pinfo,  gint tvb_next_offset, gint tvb_current_offset, proto_tree *top_tree)
{
    gint tokenlen;
    guint token_name_len;
    gint tvb_offset = 0,tvb_help_offset;
    gint token_index = 0;
    gchar *msg;
    proto_item* item;
    guint8              code_str[3];

    proto_tree  *megaco_LocalControl_tree;
    proto_item  *megaco_LocalControl_item;

    tokenlen = tvb_next_offset - tvb_current_offset;

    megaco_LocalControl_item = proto_tree_add_item(megaco_mediadescriptor_tree, hf_megaco_LocalControl_descriptor, tvb, tvb_current_offset, tokenlen, ENC_NA);
    megaco_LocalControl_tree = proto_item_add_subtree(megaco_LocalControl_item, ett_megaco_LocalControldescriptor);

    while ( tvb_offset < tvb_next_offset && tvb_offset != -1 ){

        tvb_help_offset = tvb_current_offset;

        /*
         * Find local parameter name
         * localParm            = ( streamMode / propertyParm / reservedValueMode / reservedGroupMode )
         * pkgdName             = (PackageName SLASH ItemID) ;specific item
         *                    / (PackageName SLASH "*") ;all events in package
         *                    / ("*" SLASH "*") ; all events supported by the MG
         */
        /* Find token length */
        for (tvb_offset=tvb_current_offset; tvb_offset < tvb_next_offset; tvb_offset++){
            guint8 octet;
            octet = tvb_get_guint8(tvb, tvb_offset);
            if (!g_ascii_isalnum(octet)){
                if ((octet!='/')&&(octet!='_')){
                    break;
                }
            }
        }
        token_name_len = tvb_offset - tvb_current_offset;
        /* Debug Code
        proto_tree_add_format_text(megaco_LocalControl_tree, tvb, tvb_current_offset, token_name_len);
         */
        token_index = find_megaco_localParam_names(tvb, tvb_current_offset, token_name_len);
        /* Find start of parameter value */
        tvb_offset = tvb_find_guint8(tvb, tvb_offset , tvb_next_offset, '=');
        if (tvb_offset == -1) {
            expert_add_info(pinfo, megaco_LocalControl_item, &ei_megaco_parse_error);
            return;
        }
        /* Start search after '=' in case there is no SP*/
        tvb_offset++;
        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);

        /* find if there are more parameters or not */
        tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
        if ( tvb_offset < 0 || tvb_offset > tvb_next_offset ){
            tvb_offset = tvb_next_offset;
        }

        tokenlen = megaco_tvb_skip_wsp_return(tvb,tvb_offset-1) - tvb_current_offset;
        /* Debug Code
        proto_tree_add_format_text(megaco_LocalControl_tree, tvb, tvb_current_offset, tokenlen);
         */
        switch ( token_index ){

        case MEGACO_MODETOKEN: /* Mode */
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_mode, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset,
                tvb_format_text(pinfo->pool, tvb, tvb_current_offset,
                tokenlen));
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Mode:%s)",tvb_format_text(pinfo->pool, tvb, tvb_current_offset,tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        case MEGACO_RESERVEDVALUETOKEN: /* ReservedValue */
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_reserve_value, tvb,
                    tvb_help_offset, tvb_offset-tvb_help_offset,
                    tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_RESERVEDGROUPTOKEN: /* ReservedGroup */
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_reserve_group, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset,
                tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        case MEGACO_H324_H223CAPR: /* h324/h223capr */
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_h324_h223capr, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset,
                tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            tokenlen = tvb_offset - tvb_help_offset;
            msg=tvb_format_text(pinfo->pool, tvb,tvb_help_offset, tokenlen);
            dissect_megaco_h324_h223caprn(tvb, pinfo, megaco_mediadescriptor_tree, tvb_help_offset, tokenlen, msg);

            break;

        case MEGACO_H324_MUXTBL_IN: /* h324/muxtbl_in */

            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_h324_muxtbl_in, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset,
                tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);

            tokenlen = tvb_offset - tvb_help_offset;
            /* Call the existing routine with tree = NULL to avoid an entry to the tree */
            dissect_megaco_h245(tvb, pinfo, NULL, tvb_help_offset, tokenlen, top_tree);

            break;

        case MEGACO_H324_MUXTBL_OUT:

            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_h324_muxtbl_out, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(pinfo->pool, tvb, tvb_current_offset,
                tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);

            tokenlen = tvb_offset - tvb_help_offset;
            /* Call the existing routine with tree = NULL to avoid an entry to the tree */
            dissect_megaco_h245(tvb, pinfo, NULL, tvb_help_offset, tokenlen, top_tree);

            break;

        case MEGACO_DS_DSCP:
            tvb_get_nstringz0(tvb,tvb_current_offset,3,code_str);
            item = proto_tree_add_uint(megaco_LocalControl_tree, hf_megaco_ds_dscp, tvb,
                tvb_help_offset, 1, (guint32) strtoul(code_str,NULL,16));
            proto_item_set_len(item, tvb_offset-tvb_help_offset);
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        case MEGACO_GM_SAF:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_gm_saf, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_SAM:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_gm_sam, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_SPF:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_gm_spf, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_SPR:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_gm_spr, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_ESAS:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_gm_esas, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_RSB:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_gm_rsb, tvb,
                tvb_help_offset, tvb_offset - tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset + 1);
            break;
        case MEGACO_TMAN_POL:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_tman_pol, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_TMAN_SDR:
        {
            gint32 sdr;
            gboolean sdr_valid;
            proto_item* pi;

            sdr_valid = ws_strtoi32(tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen), NULL, &sdr);
            pi =proto_tree_add_int(megaco_LocalControl_tree, hf_megaco_tman_sdr, tvb, tvb_help_offset,
                tvb_offset - tvb_help_offset, sdr);
            proto_item_append_text(pi, " [%i b/s]", sdr*8);
            if (!sdr_valid) {
                expert_add_info(pinfo, pi, &ei_megaco_invalid_sdr);
            }
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset + 1);
        }
            break;
        case MEGACO_TMAN_MBS:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_tman_mbs, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_TMAN_PDR:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_tman_pdr, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_TMAN_DVT:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_tman_dvt, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_IPDC_REALM:
            proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_ipdc_realm, tvb,
                tvb_help_offset, tvb_offset-tvb_help_offset, tvb_format_text(pinfo->pool, tvb, tvb_current_offset, tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        default:
            tokenlen = tvb_offset - tvb_help_offset;
            proto_tree_add_format_text(megaco_LocalControl_tree, tvb, tvb_help_offset, tokenlen);
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);

            break;
        }
    }
}

static void
dissect_megaco_descriptors(tvbuff_t *tvb, proto_tree *megaco_command_tree, packet_info *pinfo, gint tvb_descriptors_start_offset,
    gint tvb_descriptors_end_offset, proto_tree *top_tree, guint32 context)
{
    gint        tvb_len, token_index, tvb_offset, temp_offset;
    gint        tvb_current_offset,tvb_previous_offset,save_offset,tokenlen;
    gint        tvb_RBRKT, tvb_LBRKT;
    proto_tree* descriptor_tree;
    proto_item* descriptor_item;

    tvb_len     = tvb_reported_length(tvb);

    descriptor_tree = proto_tree_add_subtree(megaco_command_tree, tvb, tvb_descriptors_start_offset,
                                            tvb_descriptors_end_offset-tvb_descriptors_start_offset, ett_megaco_descriptors, &descriptor_item, "Descriptors");

    tvb_LBRKT = megaco_tvb_skip_wsp(tvb, tvb_descriptors_start_offset +1);

    tvb_previous_offset = tvb_LBRKT;
    tvb_RBRKT = tvb_descriptors_start_offset;


    do {

        tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
            tvb_len, '}');
        tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
            tvb_len, '{');

        tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
            tvb_len, ',');

        if (tvb_current_offset == -1 || tvb_current_offset > tvb_descriptors_end_offset){
            tvb_current_offset = tvb_descriptors_end_offset;

        }
        if (tvb_current_offset <= tvb_previous_offset) {
            expert_add_info_format(pinfo, descriptor_item, &ei_megaco_parse_error, "Parse error: Invalid offset");
            return;
        }

        /* Descriptor includes no parameters */

        if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){

            if ( tvb_current_offset > tvb_RBRKT ){
                tvb_current_offset = tvb_RBRKT;
            }

            tvb_RBRKT = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
        }

        /* Descriptor includes Parameters */
        if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){

            while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){


                tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
                    tvb_len, '{');
                if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
                    tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,tvb_len, '}');
            }

        }

        /* Find token length */
        for (tvb_offset=tvb_previous_offset; tvb_offset < tvb_descriptors_end_offset -1; tvb_offset++){
            if (!g_ascii_isalpha(tvb_get_guint8(tvb, tvb_offset ))){
                break;
            }
        }
        tokenlen =  tvb_offset - tvb_previous_offset;
        token_index = find_megaco_descriptors_names(tvb, tvb_previous_offset, tokenlen);
        if (tvb_RBRKT > tvb_descriptors_end_offset)
            tvb_RBRKT = tvb_descriptors_end_offset;
        switch ( token_index ){
        case MEGACO_MODEM_TOKEN:
            dissect_megaco_modemdescriptor(tvb, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_MUX_TOKEN:
            dissect_megaco_multiplexdescriptor(tvb, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_MEDIA_TOKEN:
            /*TODO: Move this to the top when all branches fixed !!!*/
            temp_offset = tvb_find_guint8(tvb, tvb_previous_offset,tvb_descriptors_end_offset, '{');
            save_offset = tvb_previous_offset;

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, temp_offset +1);
            dissect_megaco_mediadescriptor(tvb, descriptor_tree, pinfo, tvb_RBRKT, tvb_previous_offset, save_offset, top_tree, context);
            break;
        case MEGACO_SIGNALS_TOKEN:
            dissect_megaco_signaldescriptor(tvb, pinfo, descriptor_tree, tvb_RBRKT, tvb_previous_offset, top_tree);
            break;
        case MEGACO_SERVICES_TOKEN:
            dissect_megaco_servicechangedescriptor(tvb, pinfo, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_STATS_TOKEN:
            dissect_megaco_statisticsdescriptor(tvb, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_ERROR_TOKEN:
            dissect_megaco_errordescriptor(tvb, pinfo, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_EVENTS_TOKEN:
            dissect_megaco_eventsdescriptor(tvb, pinfo, descriptor_tree, tvb_RBRKT, tvb_previous_offset, top_tree);
            break;
        case MEGACO_AUDIT_TOKEN:
            dissect_megaco_auditdescriptor(tvb, descriptor_tree, pinfo, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_DIGITMAP_TOKEN:
            dissect_megaco_digitmapdescriptor(tvb, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_OE_TOKEN:
            /* ObservedEventsToken */
            dissect_megaco_observedeventsdescriptor(tvb, pinfo, descriptor_tree, tvb_RBRKT, tvb_previous_offset, top_tree);
            break;
        case MEGACO_TOPOLOGY_TOKEN:
            dissect_megaco_topologydescriptor(tvb, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_PACKAGES_TOKEN:
            dissect_megaco_Packagesdescriptor(tvb, descriptor_tree, tvb_RBRKT, tvb_previous_offset);
            break;
        default:
            tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
            proto_tree_add_expert(descriptor_tree, pinfo, &ei_megaco_no_descriptor, tvb, tvb_previous_offset, tokenlen);
            break;
        }

        tvb_current_offset      = tvb_find_guint8(tvb, tvb_RBRKT, tvb_len, ',');
        if (tvb_current_offset == -1 || tvb_descriptors_end_offset < tvb_current_offset){
            tvb_current_offset = tvb_descriptors_end_offset;
        }
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);
        tvb_LBRKT = tvb_previous_offset;
        tvb_RBRKT = tvb_previous_offset;

    } while ( tvb_current_offset < tvb_descriptors_end_offset );

}

/* Copied from MGCP dissector, prints whole message in raw text */

static void tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree){

    gint tvb_linebegin,tvb_lineend,linelen;
    proto_tree* text_tree;

    tvb_linebegin = 0;

    if (tree) {
        text_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_megaco_raw_text, NULL, "-------------- (RAW text output) ---------------");

        do {
            linelen = tvb_find_line_end(tvb,tvb_linebegin,-1,&tvb_lineend,FALSE);
            proto_tree_add_format_wsp_text(text_tree, tvb, tvb_linebegin, linelen);
            tvb_linebegin = tvb_lineend;
        } while (tvb_offset_exists(tvb, tvb_lineend) && linelen > 0);
    }
}

/*
* megaco_tvb_skip_wsp - Returns the position in tvb of the first non-whitespace
*        character following offset or offset + maxlength -1 whichever
*        is smaller.
*
* Parameters:
* tvb - The tvbuff in which we are skipping whitespaces, tab and end_of_line characters.
* offset - The offset in tvb from which we begin trying to skip whitespace.
*
* Returns: The position in tvb of the first non-whitespace
*/
static gint megaco_tvb_skip_wsp(tvbuff_t* tvb, gint offset ){
    gint counter = offset;
    gint end = tvb_reported_length(tvb);

    for(counter = offset; counter < end &&
        (g_ascii_isspace(tvb_get_guint8(tvb,counter))); counter++);
    return (counter);
}

static gint megaco_tvb_skip_wsp_return(tvbuff_t* tvb, gint offset){
    gint counter = offset;
    gint end = 0;

    for(counter = offset; counter > end &&
        (g_ascii_isspace(tvb_get_guint8(tvb,counter))); counter--);
    counter++;
    return (counter);
}

static gint megaco_tvb_find_token(tvbuff_t* tvb, gint offset, gint maxlength){
    gint counter = 0;
    gint pos = offset;
    guchar needle;

    do {
        pos = tvb_ws_mempbrk_pattern_guint8(tvb, pos + 1, maxlength, &pbrk_braces, &needle);
        if(pos == -1)
            return -1;
        switch(needle){
        case '{':
            counter++;
            break;
        case '}':
            counter--;
            break;
        default:
            break;
        }
    } while (counter>0);
    if(counter<0)
        return -1;
    else
    {
        pos = megaco_tvb_skip_wsp(tvb,pos+1);
        return pos;
    }
}

static void
megaco_fmt_content( gchar *result, guint32 context )
{
    switch(context)
    {
    case CHOOSE_CONTEXT:
    case ALL_CONTEXTS:
    case NULL_CONTEXT:
        (void) g_strlcpy(result, val_to_str_const(context, megaco_context_vals, "Unknown"), ITEM_LABEL_LENGTH);
        break;
    default:
        snprintf( result, ITEM_LABEL_LENGTH, "%d", context);
    }
}

void
proto_register_megaco(void)
{
    static hf_register_info hf[] = {
        { &hf_megaco_audititem,
          { "Audit Item", "megaco.audititem", FT_STRING, BASE_NONE, NULL, 0x0,
            "Identity of item to be audited", HFILL }},
        { &hf_megaco_audit_descriptor,
          { "Audit Descriptor", "megaco.audit", FT_NONE, BASE_NONE, NULL, 0x0,
            "Audit Descriptor of the megaco Command", HFILL }},
#if 0
        { &hf_megaco_command_line,
          { "Command line", "megaco.command_line", FT_STRING, BASE_NONE, NULL, 0x0,
            "Commands of this message", HFILL }},
#endif
        { &hf_megaco_command,
          { "Command", "megaco.command", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_command_optional,
          { "Optional Command", "megaco.command_optional", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_wildcard_response,
          { "Wildcarded response to a command", "megaco.wildcard_response", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_megaco_Context,
          { "Context", "megaco.context", FT_UINT32, BASE_CUSTOM, CF_FUNC(megaco_fmt_content), 0x0,
            "Context ID of this message", HFILL }},
        { &hf_megaco_digitmap_descriptor,
          { "DigitMap Descriptor", "megaco.digitmap", FT_STRING, BASE_NONE, NULL, 0x0,
            "DigitMap Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_error_descriptor,
          { "ERROR Descriptor", "megaco.error", FT_NONE, BASE_NONE, NULL, 0x0,
            "Error Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_error_code,
          { "ERROR Code", "megaco.error_code", FT_UINT32, BASE_DEC, VALS(MEGACO_error_code_vals), 0x0,
            "Error Code of the megaco Command", HFILL }},
        { &hf_megaco_error_string,
          { "ERROR String", "megaco.error_string", FT_STRING, BASE_NONE, NULL, 0x0,
            "Error String of the megaco Command", HFILL }},
        { &hf_megaco_Event_Buffer_Control,
          { "Event Buffer Control", "megaco.eventbuffercontrol", FT_STRING, BASE_NONE, NULL, 0x0,
            "Event Buffer Control in Termination State Descriptor", HFILL }},
        { &hf_megaco_events_descriptor,
          { "Events Descriptor", "megaco.events", FT_NONE, BASE_NONE, NULL, 0x0,
            "Events Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_Local_descriptor,
          { "Local Descriptor", "megaco.localdescriptor", FT_NONE, BASE_NONE, NULL, 0x0,
            "Local Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_LocalControl_descriptor,
          { "Local Control Descriptor", "megaco.localcontroldescriptor", FT_NONE, BASE_NONE, NULL, 0x0,
            "Local Control Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_media_descriptor,
          { "Media Descriptor", "megaco.media", FT_NONE, BASE_NONE, NULL, 0x0,
            "Media Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_modem_descriptor,
          { "Modem Descriptor", "megaco.modem", FT_STRING, BASE_NONE, NULL, 0x0,
            "Modem Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_mode,
          { "Mode", "megaco.mode", FT_STRING, BASE_NONE, NULL, 0x0,
            "Mode  sendonly/receiveonly/inactive/loopback", HFILL }},
        { &hf_megaco_multiplex_descriptor,
          { "Multiplex Descriptor", "megaco.multiplex", FT_STRING, BASE_NONE, NULL, 0x0,
            "Multiplex Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_observedevents_descriptor,
          { "Observed Events Descriptor", "megaco.observedevents", FT_NONE, BASE_NONE, NULL, 0x0,
            "Observed Events Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_packages_descriptor,
          { "Packages Descriptor", "megaco.packagesdescriptor", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_pkgdname,
          { "pkgdName", "megaco.pkgdname", FT_STRING, BASE_NONE, NULL, 0x0,
            "PackageName SLASH ItemID", HFILL }},
        { &hf_megaco_Remote_descriptor,
          { "Remote Descriptor", "megaco.remotedescriptor", FT_NONE, BASE_NONE, NULL, 0x0,
            "Remote Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_reserve_group,
          { "Reserve Group", "megaco.reservegroup", FT_STRING, BASE_NONE, NULL, 0x0,
            "Reserve Group on or off", HFILL }},
        { &hf_megaco_h324_muxtbl_in,
          { "h324/muxtbl_in", "megaco.h324_muxtbl_in", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_h324_muxtbl_out,
          { "h324/muxtbl_out", "megaco.h324_muxtbl_out", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_ds_dscp,
          { "Differentiated Services Code Point", "megaco.ds_dscp", FT_UINT32, BASE_HEX|BASE_EXT_STRING, &dscp_vals_ext, 0x0,
            NULL, HFILL }},
        { &hf_megaco_gm_saf,
          { "Remote Source Address Filtering", "megaco.gm_saf", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_gm_sam,
          { "Remote Source Address Mask", "megaco.gm_sam", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_gm_spf,
          { "Remote Source Port Filtering", "megaco.gm_spf", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_gm_spr,
          { "Remote Source Port Range", "megaco.gm_spr", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_gm_esas,
          { "Explicit Source Address Setting", "megaco.gm_esas", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_tman_pol,
          { "Policing", "megaco.tman_pol", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_gm_rsb,
          { "RTCP Allocation Specific Behaviour", "megaco.gm_rsb", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_tman_sdr,
          { "Sustainable Data Rate", "megaco.tman_sdr", FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytespsecond, 0x0,
            NULL, HFILL }},
        { &hf_megaco_tman_mbs,
          { "Maximum Burst Rate", "megaco.tman_mbs", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_tman_pdr,
          { "Peak Data Rate", "megaco.tman_pdr", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_tman_dvt,
          { "Delay Variation Tolerance", "megaco.tman_dvt", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_ipdc_realm,
          { "IP Realm Identifier", "megaco.ipdc_realm", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_h324_h223capr,
          { "h324/h223capr", "megaco.h324_h223capr", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_reserve_value,
          { "Reserve Value", "megaco.reservevalue", FT_STRING, BASE_NONE, NULL, 0x0,
            "Reserve Value on or off", HFILL }},
        { &hf_megaco_requestid,
          { "RequestID", "megaco.requestid", FT_UINT32, BASE_DEC, NULL, 0x0,
            "RequestID in Events or Observedevents Descriptor", HFILL }},
#if 0
        { &hf_megaco_servicechange_descriptor,
          { "Service Change Descriptor", "megaco.servicechange", FT_STRING, BASE_NONE, NULL, 0x0,
            "Service Change Descriptor of the megaco Command", HFILL }},
#endif
        { &hf_megaco_Service_State,
          { "Service State", "megaco.servicestates", FT_STRING, BASE_NONE, NULL, 0x0,
            "Service States in Termination State Descriptor", HFILL }},
        { &hf_megaco_signal_descriptor,
          { "Signal Descriptor", "megaco.signal", FT_NONE, BASE_NONE, NULL, 0x0,
            "Signal Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_statistics_descriptor,
          { "Statistics Descriptor", "megaco.statistics", FT_NONE, BASE_NONE, NULL, 0x0,
            "Statistics Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_streamid,
          { "StreamID", "megaco.streamid", FT_UINT32, BASE_DEC, NULL, 0x0,
            "StreamID in the Media Descriptor", HFILL }},
        { &hf_megaco_termid,
          { "Termination ID", "megaco.termid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Termination ID of this Command", HFILL }},
        { &hf_megaco_TerminationState_descriptor,
          { "Termination State Descriptor", "megaco.terminationstate", FT_NONE, BASE_NONE, NULL, 0x0,
            "Termination State Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_topology_descriptor,
          { "Topology Descriptor", "megaco.topology", FT_STRING, BASE_NONE, NULL, 0x0,
            "Topology Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_transaction,
          { "Transaction", "megaco.transaction", FT_STRING, BASE_NONE, NULL, 0x0,
            "Message Originator", HFILL }},
        { &hf_megaco_transid,
          { "Transaction ID", "megaco.transid", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Transaction ID of this message", HFILL }},
        { &hf_megaco_mId,
          { "MediagatewayID", "megaco.mId", FT_STRING, BASE_NONE, NULL, 0x0,
            "Mediagateway ID", HFILL }},
        { &hf_megaco_version,
          { "Version", "megaco.version", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_start,
          { "Start token", "megaco.start_token", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_h245,
          { "h245", "megaco.h245", FT_NONE, BASE_NONE, NULL, 0x0,
            "Embedded H.245 message", HFILL }},
        { &hf_megaco_h223Capability,
          { "h223Capability", "megaco.h245.h223Capability", FT_NONE, BASE_NONE, NULL, 0,
            "megaco.h245.H223Capability", HFILL }},
        { &hf_megaco_priority,
          { "Priority", "megaco.priority", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        GCP_HF_ARR_ELEMS("megaco",megaco_ctx_ids),

        /* Add more fields here */
    };
    static gint *ett[] = {
        &ett_megaco,
        &ett_megaco_message,
        &ett_megaco_message_body,
        &ett_megaco_context,
        &ett_megaco_command_line,
        &ett_megaco_descriptors,
        &ett_megaco_raw_text,
        &ett_megaco_error_descriptor,
        &ett_megaco_mediadescriptor,
        &ett_megaco_TerminationState,
        &ett_megaco_Remotedescriptor,
        &ett_megaco_Localdescriptor,
        &ett_megaco_LocalControldescriptor,
        &ett_megaco_auditdescriptor,
        &ett_megaco_eventsdescriptor,
        &ett_megaco_statisticsdescriptor,
        &ett_megaco_observedeventsdescriptor,
        &ett_megaco_observedevent,
        &ett_megaco_packagesdescriptor,
        &ett_megaco_requestedevent,
        &ett_megaco_signalsdescriptor,
        &ett_megaco_requestedsignal,
        &ett_megaco_h245,
        GCP_ETT_ARR_ELEMS(megaco_ctx_ids),
    };

    static ei_register_info ei[] = {
        { &ei_megaco_errored_command, { "megaco.errored_command", PI_RESPONSE_CODE, PI_WARN, "Errored Command", EXPFILL }},
        { &ei_megaco_parse_error, { "megaco.parse_error", PI_MALFORMED, PI_ERROR, "Parse error", EXPFILL }},
        { &ei_megaco_error_descriptor_transaction_list, { "megaco.error_descriptor_transaction_list.invalid", PI_MALFORMED, PI_ERROR, "Sorry, can't understand errorDescriptor / transactionList", EXPFILL }},
        { &ei_megaco_audit_descriptor, { "megaco.audit.malformed", PI_MALFORMED, PI_ERROR, "Badly constructed audit descriptor (no { )", EXPFILL }},
        { &ei_megaco_signal_descriptor, { "megaco.signal_descriptor.empty", PI_PROTOCOL, PI_NOTE, "Empty Signal Descriptor", EXPFILL }},
        { &ei_megaco_no_command, { "megaco.no_command", PI_PROTOCOL, PI_WARN, "No Command detectable", EXPFILL }},
        { &ei_megaco_no_descriptor, { "megaco.no_descriptor", PI_PROTOCOL, PI_WARN, "No Descriptor detectable", EXPFILL }},
        { &ei_megaco_reason_invalid, { "megaco.change_reason.invalid", PI_MALFORMED, PI_ERROR, "Invalid Service Change Reason", EXPFILL }},
        { &ei_megaco_error_code_invalid,{ "megaco.error_code.invalid", PI_MALFORMED, PI_ERROR, "Invalid error code", EXPFILL } },
        { &ei_megaco_invalid_sdr, { "megaco.sdr.invalid", PI_MALFORMED, PI_ERROR, "Invalid Sustainable Data Rate", EXPFILL }}
    };

    module_t *megaco_module;
    expert_module_t* expert_megaco;

    proto_megaco = proto_register_protocol("MEGACO", "MEGACO", "megaco");

    megaco_text_handle = register_dissector("megaco", dissect_megaco_text, proto_megaco);

    proto_register_field_array(proto_megaco, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_megaco = expert_register_protocol(proto_megaco);
    expert_register_field_array(expert_megaco, ei, array_length(ei));

    /* Register our configuration options, particularly our ports */

    megaco_module = prefs_register_protocol(proto_megaco, NULL);

#if 0
    prefs_register_uint_preference(megaco_module, "sctp.bin_port",
                                   "MEGACO Binary SCTP Port",
                                   "Set the SCTP port for MEGACO binary messages",
                                   10, &global_megaco_bin_sctp_port);

    prefs_register_uint_preference(megaco_module, "tcp.bin_port",
                                   "MEGACO Binary TCP Port",
                                   "Set the TCP port for MEGACO binary messages",
                                   10, &global_megaco_bin_tcp_port);

    prefs_register_uint_preference(megaco_module, "udp.bin_port",
                                   "MEGACO Binary UDP Port",
                                   "Set the UDP port for MEGACO binary messages",
                                   10, &global_megaco_bin_udp_port);
#endif

    prefs_register_bool_preference(megaco_module, "display_raw_text",
                                   "Display raw text for MEGACO message",
                                   "Specifies that the raw text of the "
                                   "MEGACO message should be displayed "
                                   "instead of (or in addition to) the "
                                   "dissection tree",
                                   &global_megaco_raw_text);

    prefs_register_bool_preference(megaco_module, "display_dissect_tree",
                                   "Display tree dissection for MEGACO message",
                                   "Specifies that the dissection tree of the "
                                   "MEGACO message should be displayed "
                                   "instead of (or in addition to) the "
                                   "raw text",
                                   &global_megaco_dissect_tree);
    prefs_register_bool_preference(megaco_module, "ctx_info",
                                   "Track Context",
                                   "Maintain relationships between transactions and contexts "
                                   "and display an extra tree showing context data",
                                   &keep_persistent_data);

    megaco_tap = register_tap("megaco");

    /* compile patterns */
    ws_mempbrk_compile(&pbrk_whitespace, " \t\r\n");
    ws_mempbrk_compile(&pbrk_braces, "{}");

    register_rtd_table(proto_megaco, NULL, 1, NUM_TIMESTATS, megaco_message_type, megacostat_packet, megacostat_filtercheck);
}

/* Register all the bits needed with the filtering engine */
/* The registration hand-off routine */
void
proto_reg_handoff_megaco(void)
{
    dissector_handle_t megaco_text_tcp_handle;

        /*
    * Variables to allow for proper deletion of dissector registration when
    * the user changes port from the gui.
    */
#if 0
    static guint bin_sctp_port;
    static guint bin_tcp_port;
    static guint bin_udp_port;
#endif

    sdp_handle = find_dissector_add_dependency("sdp", proto_megaco);
    h245_handle = find_dissector_add_dependency("h245dg", proto_megaco);
    h248_handle = find_dissector_add_dependency("h248", proto_megaco);
    h248_otp_handle = find_dissector_add_dependency("h248_otp", proto_megaco);
    data_handle = find_dissector("data");

    megaco_text_tcp_handle = create_dissector_handle(dissect_megaco_text_tcp, proto_megaco);

    dissector_add_uint_with_preference("tcp.port", PORT_MEGACO_TXT, megaco_text_tcp_handle);
    dissector_add_uint_with_preference("udp.port", PORT_MEGACO_TXT, megaco_text_handle);
    dissector_add_uint_with_preference("sctp.port", PORT_MEGACO_TXT, megaco_text_handle);
    dissector_add_uint("sctp.ppi", H248_PAYLOAD_PROTOCOL_ID,   megaco_text_handle);

    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);

    sip_hide_generated_call_ids = prefs_find_preference(prefs_find_module("sip"), "hide_generated_call_id");

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
