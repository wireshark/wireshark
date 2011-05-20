/* packet-megaco.c
* Routines for megaco packet disassembly
* RFC 3015
*
* $Id$
*
* Christian Falckenberg, 2002/10/17
* Copyright (c) 2002 by Christian Falckenberg
*                       <christian.falckenberg@nortelnetworks.com>
*
* Christoph Wiest,      2003/06/28
* Modified 2003 by      Christoph Wiest
*                       <ch.wiest@tesionmail.de>
* Modifyed 2004 by      Anders Broman
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/sctpppids.h>
#include <epan/dissectors/packet-tpkt.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-per.h>
#include <epan/dissectors/packet-h245.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/dissectors/packet-ber.h>

#include <epan/gcp.h>
#include <epan/tap.h>

#define PORT_MEGACO_TXT 2944
#define PORT_MEGACO_BIN 2945

/* Define the megaco proto */
static int proto_megaco         = -1;

/* Define headers for megaco */
static int hf_megaco_version        = -1;
static int hf_megaco_transaction    = -1;
static int hf_megaco_transid        = -1;
static int hf_megaco_Context        = -1;
static int hf_megaco_command_line   = -1;
static int hf_megaco_command        = -1;
static int hf_megaco_termid         = -1;



/* Define headers in subtree for megaco */
static int hf_megaco_modem_descriptor           = -1;
static int hf_megaco_multiplex_descriptor       = -1;
static int hf_megaco_media_descriptor           = -1;
static int hf_megaco_events_descriptor          = -1;
static int hf_megaco_signal_descriptor          = -1;
static int hf_megaco_audit_descriptor           = -1;
static int hf_megaco_servicechange_descriptor   = -1;
static int hf_megaco_digitmap_descriptor        = -1;
static int hf_megaco_statistics_descriptor      = -1;
static int hf_megaco_observedevents_descriptor  = -1;
static int hf_megaco_topology_descriptor        = -1;
static int hf_megaco_error_descriptor           = -1;
static int hf_megaco_TerminationState_descriptor= -1;
static int hf_megaco_Remote_descriptor          = -1;
static int hf_megaco_Local_descriptor           = -1;
static int hf_megaco_LocalControl_descriptor    = -1;
static int hf_megaco_packages_descriptor        = -1;
static int hf_megaco_error_Frame                = -1;
static int hf_megaco_Service_State              = -1;
static int hf_megaco_Event_Buffer_Control       = -1;
static int hf_megaco_mode                       = -1;
static int hf_megaco_reserve_group              = -1;
static int hf_megaco_h324_muxtbl_in             = -1;
static int hf_megaco_h324_muxtbl_out            = -1;
static int hf_megaco_ds_dscp                    = -1;
static int hf_megaco_h324_h223capr              = -1;
static int hf_megaco_reserve_value              = -1;
static int hf_megaco_streamid                   = -1;
static int hf_megaco_requestid                  = -1;
static int hf_megaco_pkgdname                   = -1;
static int hf_megaco_mId                        = -1;
static int hf_megaco_h245                       = -1;
static int hf_megaco_h223Capability             = -1;
static int hf_megaco_audititem                  = -1;

/* Define the trees for megaco */
static int ett_megaco                           = -1;
static int ett_megaco_message                   = -1;
static int ett_megaco_message_body              = -1;
static int ett_megaco_context                   = -1;
static int ett_megaco_command_line              = -1;
static int ett_megaco_mediadescriptor           = -1;
static int ett_megaco_descriptors               = -1;
static int ett_megaco_TerminationState          = -1;
static int ett_megaco_Localdescriptor           = -1;
static int ett_megaco_Remotedescriptor          = -1;
static int ett_megaco_LocalControldescriptor    = -1;
static int ett_megaco_auditdescriptor           = -1;
static int ett_megaco_eventsdescriptor          = -1;
static int ett_megaco_observedeventsdescriptor  = -1;
static int ett_megaco_observedevent             = -1;
static int ett_megaco_packagesdescriptor        = -1;
static int ett_megaco_requestedevent            = -1;
static int ett_megaco_signalsdescriptor         = -1;
static int ett_megaco_requestedsignal           = -1;
static int ett_megaco_h245                      = -1;

static gcp_hf_ett_t megaco_ctx_ids = {{-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1}};

static dissector_handle_t megaco_text_handle;

static int megaco_tap = -1;

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
static guint global_megaco_txt_tcp_port = PORT_MEGACO_TXT;
static guint global_megaco_txt_udp_port = PORT_MEGACO_TXT;
#if 0
static guint global_megaco_bin_tcp_port = PORT_MEGACO_BIN;
static guint global_megaco_bin_udp_port = PORT_MEGACO_BIN;
#endif
static gboolean global_megaco_raw_text = TRUE;
static gboolean global_megaco_dissect_tree = TRUE;

/* Some basic utility functions that are specific to this dissector */
static gint megaco_tvb_skip_wsp(tvbuff_t* tvb, gint offset);
static gint megaco_tvb_skip_wsp_return(tvbuff_t* tvb, gint offset);
/*
* The various functions that either dissect some
* subpart of MEGACO.  These aren't really proto dissectors but they
* are written in the same style.
*
*/
static void
dissect_megaco_descriptors(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_descriptors_start_offset, gint tvb_descriptors_end_offset);
static void
dissect_megaco_modemdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_multiplexdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_mediadescriptor(tvbuff_t *tvb, proto_tree *tree,packet_info *pinfo, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_eventsdescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_signaldescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_auditdescriptor(tvbuff_t *tvb, proto_tree *tree,packet_info *pinfo, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_servicechangedescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_digitmapdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_statisticsdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_observedeventsdescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_topologydescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_errordescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_TerminationStatedescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_Localdescriptor(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_LocalControldescriptor(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_Packagesdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);
static void
tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree);
static void
dissect_megaco_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint
megaco_tvb_find_token(tvbuff_t* tvb, gint offset, gint maxlenght);
static dissector_handle_t data_handle;
static dissector_handle_t sdp_handle;
static dissector_handle_t h245_handle;
static dissector_handle_t h248_handle;
static dissector_handle_t h248_otp_handle;

static gboolean keep_persistent_data = FALSE;

static proto_tree *top_tree;
/*
 * dissect_megaco_text over TCP, there will be a TPKT header there
 *
 */
static void dissect_megaco_text_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
        dissect_megaco_text(tvb, pinfo, tree);
    }
    dissect_tpkt_encap(tvb, pinfo, tree, TRUE,
        megaco_text_handle);
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
my_proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb,
             gint start, gint length, const char *value)
{
    proto_item *pi;

    pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
    if (!global_megaco_dissect_tree) {
        PROTO_ITEM_SET_HIDDEN(pi);
    }

    return(pi);
}
/*
 * dissect_megaco_text - The dissector for the MEGACO Protocol, using
 * text encoding.
 */
static void
dissect_megaco_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint        tvb_len, len;
    gint        tvb_offset,tvb_current_offset,tvb_previous_offset,tvb_next_offset,tokenlen;
    gint        line_start_offset, ver_offset, ver_length, mId_offset, mId_length;
    gint        tvb_command_start_offset, tvb_command_end_offset;
    gint        tvb_descriptors_start_offset, tvb_descriptors_end_offset;
    gint        tvb_transaction_end_offset;
    proto_tree  *megaco_tree, *message_tree, *message_body_tree, *megaco_context_tree, *megaco_tree_command_line, *ti, *sub_ti;

    guint8      word[7];
    guint8      TermID[30];
    guint8      tempchar;
    gint        tvb_RBRKT, tvb_LBRKT,  RBRKT_counter, LBRKT_counter;
    guint       token_index=0;
    guint32     dword;

    gcp_msg_t* msg = NULL;
    gcp_trx_t* trx = NULL;
    gcp_ctx_t* ctx = NULL;
    gcp_cmd_t* cmd = NULL;
    gcp_term_t* term = NULL;
    gcp_trx_type_t trx_type = GCP_TRX_NONE;
    guint32 trx_id = 0;
    guint32 ctx_id = 0;
    gcp_cmd_type_t cmd_type = GCP_CMD_NONE;
    gcp_wildcard_t wild_term = GCP_WILDCARD_NONE;
    proto_item *hidden_item;

    top_tree=tree;
    /* Initialize variables */
    tvb_len                     = tvb_length(tvb);
    megaco_tree                 = NULL;
    ti                          = NULL;
    tvb_previous_offset         = 0;
    tvb_current_offset          = 0;
    tvb_offset                  = 0;
    tvb_next_offset             = 0;
    tvb_command_start_offset    = 0;
    tvb_command_end_offset      = 0;
    tvb_RBRKT                   = 0;
    tvb_LBRKT                   = 0;
    RBRKT_counter               = 0;
    LBRKT_counter               = 0;

    /* Check if H.248 in otp(Erlang) internal format
     * XXX Needs improvment?
     * Ref:
     * http://www.erlang.org/doc/apps/megaco/part_frame.html
     * 4.1 Internal form of messages
     * 4.2 The different encodings
     */
    dword = tvb_get_ntoh24(tvb,0);
    if ((dword == 0x836803)&&(h248_otp_handle)){
        call_dissector(h248_otp_handle, tvb, pinfo, tree);
        return;
    }

    msg = gcp_msg(pinfo, TVB_RAW_OFFSET(tvb), keep_persistent_data);

    /*
     * Check to see whether we're really dealing with MEGACO by looking
     * for the "MEGACO" string or a "!".This needs to be improved when supporting
     * binary encodings. Bugfix add skipping of leading spaces.
     */
    tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
    line_start_offset = tvb_offset;
    /* Quick fix for MEGACO not following the RFC, hopfully not breaking any thing
     * Turned out to be TPKT in case of TCP, added some code to handle that.
     *
     * tvb_offset = tvb_find_guint8(tvb, tvb_offset, 5, 'M');
     */
    if(!tvb_get_nstringz0(tvb,tvb_offset,sizeof(word),word)) return;




    if (g_ascii_strncasecmp(word, "MEGACO", 6) != 0 && tvb_get_guint8(tvb, tvb_offset ) != '!'){
        gint8 class;
        gboolean pc;
        gint32 tag;
        dissector_handle_t handle = data_handle;

        get_ber_identifier(tvb, 0, &class, &pc, &tag);

        if (class == BER_CLASS_UNI && pc && tag == BER_UNI_TAG_SEQUENCE ) {
            handle = h248_handle;
        }

        call_dissector(handle,tvb,pinfo,tree);

        return;
    }


    /* Display MEGACO in protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEGACO");

    /* Build the info tree if we've been given a root */
    /* Create megaco subtree */
    ti = proto_tree_add_item(tree,proto_megaco,tvb, 0, -1, FALSE);
    megaco_tree = proto_item_add_subtree(ti, ett_megaco);

    /*  Format of 'message' is = MegacopToken SLASH Version SEP mId SEP messageBody */
    /*  MegacopToken = "MEGACO" or "!"                      */
    /*  According to H248.1-200205 Annex B Text encoding ( protocol version 2 )     */

    /* Find version */
    tvb_previous_offset = tvb_find_guint8(tvb, 0,
        tvb_len, '/');
    if (tvb_previous_offset == -1) {
        proto_tree_add_text(megaco_tree, tvb, 0, -1,
            "Sorry, no \"/\" in the MEGACO header, I can't parse this packet");
        return;
    }
    tvb_previous_offset = tvb_previous_offset + 1;
    /* As version should follow /, just add 1, works till ver 9 */
    tvb_current_offset  = tvb_previous_offset + 1;


    tokenlen = tvb_current_offset - tvb_previous_offset;
    ver_offset = tvb_previous_offset;
    ver_length = tokenlen;

    /* Pos of version + 2 should take us past version + SEP                 */

    tvb_previous_offset = tvb_previous_offset + 2;
    /* in case of CRLF              */
    if (tvb_get_guint8(tvb, tvb_current_offset ) == '\n')
        tvb_previous_offset++;
    if (tvb_get_guint8(tvb, tvb_current_offset ) == '\r')
        tvb_previous_offset++;

    /* mId should follow here,
     * mId = (( domainAddress / domainName ) [":" portNumber]) / mtpAddress / deviceName
     * domainAddress = "[" (IPv4address / IPv6address) "]"
     * domainName = "<" (ALPHA / DIGIT) *63(ALPHA / DIGIT / "-" /".") ">"
     * mtpAddress = MTPToken LBRKT 4*8 (HEXDIG) RBRKT
     * MTPToken = ("MTP")
     * deviceName = pathNAME
     * pathNAME = ["*"] NAME *("/" / "*"/ ALPHA / DIGIT /"_" / "$" )["@" pathDomainName ]
     */

    tokenlen = tvb_find_line_end( tvb, tvb_previous_offset, -1, &tvb_next_offset, FALSE);
    /* accept white spaces as SEParator too */
    if ( (tvb_current_offset=tvb_find_guint8(tvb, tvb_previous_offset, tokenlen, ' ')) != -1 ) {
        /* SEP after mID might be spaces only */
        tokenlen = tvb_current_offset-tvb_previous_offset;
        tvb_next_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset);
    }

   /* Att this point we should point to the "\n" ending the mId element
    * or to the next character after white space SEP
    */
    mId_offset = tvb_previous_offset;
    mId_length = tokenlen;

    /* Add the first line to the tree */
    tokenlen = tvb_next_offset - line_start_offset - 1;
    ti = proto_tree_add_text(megaco_tree, tvb, line_start_offset, tokenlen,
            "%s",tvb_format_text(tvb,line_start_offset,tokenlen));
    message_tree = proto_item_add_subtree(ti, ett_megaco_message);
    if (tree){
        if(global_megaco_dissect_tree){
            proto_tree_add_item(message_tree, hf_megaco_version,tvb, ver_offset, ver_length, FALSE);
            proto_tree_add_item(message_tree, hf_megaco_mId,tvb, mId_offset, mId_length, FALSE);
        }else{
            hidden_item = proto_tree_add_item(message_tree, hf_megaco_version,tvb, ver_offset, ver_length, FALSE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            hidden_item = proto_tree_add_item(message_tree, hf_megaco_mId,tvb, mId_offset, mId_length, FALSE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
    }
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
    tempchar = tvb_get_guint8(tvb, tvb_previous_offset);
    if ( (tempchar >= 'a')&& (tempchar <= 'z'))
        tempchar = tempchar - 0x20;

    /* Find token length */
    for (tvb_offset=tvb_previous_offset; tvb_offset < tvb_len-1; tvb_offset++){
        if (!isalpha(tvb_get_guint8(tvb, tvb_offset ))){
            break;
        }
    }
    tokenlen = tvb_offset - tvb_previous_offset;
    token_index = find_megaco_messageBody_names(tvb, tvb_previous_offset, tokenlen);
    /* Debug code
        g_warning("token_index %u",token_index);
    */

    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_len, '{');
    tvb_current_offset = tvb_LBRKT;
    tvb_transaction_end_offset = megaco_tvb_find_token(tvb, tvb_LBRKT - 1, tvb_len);

    switch ( token_index ){
        /* errorDescriptor */
        case ERRORTOKEN:
            col_set_str(pinfo->cinfo, COL_INFO, "Error  ");

            tvb_current_offset = megaco_tvb_find_token(tvb, tvb_offset, tvb_len); /*tvb_find_guint8(tvb, tvb_offset+1, tvb_len, '}');*/

            ti = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset,
                    "%s",tvb_format_text(tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset+1));
            message_body_tree = proto_item_add_subtree(ti, ett_megaco_message_body);

            if (tree) {
                my_proto_tree_add_string(message_body_tree, hf_megaco_transaction, tvb,
                tvb_previous_offset, tokenlen,
                "Error" );

                tvb_command_start_offset = tvb_previous_offset;
                dissect_megaco_errordescriptor(tvb, megaco_tree, tvb_len-1, tvb_command_start_offset);
            }
            return;
            /* transactionResponseAck
             * transactionResponseAck = ResponseAckToken LBRKT transactionAck
             *                           *(COMMA transactionAck) RBRKT
             * transactionAck = transactionID / (transactionID "-" transactionID)
             */
        case RESPONSEACKTOKEN:
            trx_type = GCP_TRX_ACK;
            tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '{');
            tvb_offset = tvb_LBRKT;

            ti = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tvb_offset-tvb_previous_offset,
                "%s",tvb_format_text(tvb, tvb_previous_offset, tvb_offset-tvb_previous_offset+1));
            message_body_tree = proto_item_add_subtree(ti, ett_megaco_message_body);

            my_proto_tree_add_string(message_body_tree, hf_megaco_transaction, tvb,
                tvb_previous_offset, tokenlen,
                "TransactionResponseAck" );

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_offset+1);
            tvb_current_offset = tvb_find_guint8(tvb, tvb_offset+1, tvb_len, '}');
            /*tvb_current_offset = megaco_tvb_find_token(tvb, tvb_offset, tvb_transaction_end_offset);*/
            tvb_current_offset = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset)-1; /* cut last RBRKT */
            len = tvb_current_offset - tvb_previous_offset;

            if (check_col(pinfo->cinfo, COL_INFO) )
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s TransactionResponseAck",
                tvb_format_text(tvb,tvb_previous_offset,len));

                trx_id = strtoul(tvb_format_text(tvb,tvb_offset,len),NULL,10);

            if(tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transid, tvb,
                tvb_previous_offset, len,
                tvb_format_text(tvb,tvb_previous_offset,len));

                if(global_megaco_raw_text){
                    tvb_raw_text_add(tvb, megaco_tree);
                }
            tvb_previous_offset = tvb_LBRKT +1;
            return;
        /* Pe and PN is transactionPending, P+"any char" is transactionReply */
        case PENDINGTOKEN:
            trx_type = GCP_TRX_PENDING;

            tvb_offset  = tvb_find_guint8(tvb, tvb_previous_offset, tvb_transaction_end_offset, '=')+1;
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
            tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '{');
            tvb_current_offset = tvb_LBRKT;
            ti = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset,
                "%s",tvb_format_text(tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset+1));
            message_body_tree = proto_item_add_subtree(ti, ett_megaco_message_body);

            tvb_current_offset  = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1);
            len = tvb_current_offset - tvb_offset;
            if (tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transaction, tvb,
                    tvb_previous_offset, tokenlen,
                    "Pending" );

            if (check_col(pinfo->cinfo, COL_INFO) )
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s Pending",
                tvb_format_text(tvb,tvb_offset,len));
                trx_id = strtoul(tvb_format_text(tvb,tvb_offset,len),NULL,10);

            if(tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transid, tvb,
                tvb_offset, len,
                tvb_format_text(tvb,tvb_offset,len));
            return;

        /* transactionReply */
        case REPLYTOKEN:
            trx_type = GCP_TRX_REPLY;
            tvb_LBRKT  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '{');
            ti = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tvb_LBRKT-tvb_previous_offset,
                    "%s",tvb_format_text(tvb, tvb_previous_offset, tvb_LBRKT-tvb_previous_offset+1));
            message_body_tree = proto_item_add_subtree(ti, ett_megaco_message_body);

            if (tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transaction, tvb,
                    tvb_previous_offset, tokenlen,
                    "Reply" );

            tvb_offset  = tvb_find_guint8(tvb, tvb_previous_offset, tvb_transaction_end_offset, '=')+1;
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
            tvb_current_offset  = megaco_tvb_skip_wsp_return(tvb, tvb_LBRKT-1);
            len = tvb_current_offset - tvb_offset;

            if (check_col(pinfo->cinfo, COL_INFO) )
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s Reply  ",
                tvb_format_text(tvb,tvb_offset,len));
                trx_id = strtoul(tvb_format_text(tvb,tvb_offset,len),NULL,10);

            if(tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transid, tvb,
                    tvb_offset, len, tvb_format_text(tvb,tvb_offset,len));

            /* Find if we have a errorDescriptor or actionReplyList */
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            tempchar = tvb_get_guint8(tvb,tvb_offset);
            if ((tempchar == 'E')||(tempchar == 'e')){
                dissect_megaco_errordescriptor(tvb, megaco_tree, tvb_transaction_end_offset-1, tvb_offset);
                return;
            }
            /* Offset should be at first printarable char after { */
            tvb_previous_offset = tvb_offset;
            break;
        case TRANSTOKEN:
            /* TransactionRequest   */
            trx_type = GCP_TRX_REQUEST;
            ti = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset,
                    "%s",tvb_format_text(tvb, tvb_previous_offset, tvb_current_offset-tvb_previous_offset+1));
            message_body_tree = proto_item_add_subtree(ti, ett_megaco_message_body);

            if(tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transaction, tvb,
                    tvb_previous_offset, tokenlen,
                    "Request" );
            tvb_offset  = tvb_find_guint8(tvb, tvb_offset, tvb_transaction_end_offset, '=')+1;
            tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset);
            tvb_current_offset  = megaco_tvb_skip_wsp_return(tvb, tvb_current_offset-1);
            len = tvb_current_offset - tvb_offset;
            if (check_col(pinfo->cinfo, COL_INFO) )
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s Request",
                tvb_format_text(tvb,tvb_offset,len));
                trx_id = strtoul(tvb_format_text(tvb,tvb_offset,len),NULL,10);
            if(tree)
                my_proto_tree_add_string(message_body_tree, hf_megaco_transid, tvb, tvb_offset,len,
                    tvb_format_text(tvb,tvb_offset,len));
            /* Offset should be at first printarable char after { */
            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);

            break;
        default :
            ti = proto_tree_add_item(tree,proto_megaco,tvb, 0, -1, FALSE);
            megaco_tree = proto_item_add_subtree(ti, ett_megaco);
            proto_tree_add_text(megaco_tree, tvb, 0, -1,
            "Sorry, can't understand errorDescriptor / transactionList = %s, can't parse it pos %u",
                        tvb_format_text(tvb,tvb_previous_offset,2),tvb_previous_offset);
            return;
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

        trx = gcp_trx(msg , trx_id , trx_type, keep_persistent_data);

        /* Find Context */
nextcontext:




        tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_transaction_end_offset, '{');
        ti = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tvb_next_offset-tvb_previous_offset+1,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tvb_next_offset-tvb_previous_offset+1));
        megaco_context_tree = proto_item_add_subtree(ti, ett_megaco_context);

        tvb_previous_offset = tvb_find_guint8(tvb, tvb_current_offset,
            tvb_transaction_end_offset, '=')+1;
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);
        if (tvb_current_offset >= tvb_next_offset) {
            proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Invalid offset ]");
            return;
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
            my_proto_tree_add_string(megaco_context_tree, hf_megaco_Context, tvb,
                tvb_previous_offset, 1,
                "Choose one");
            col_append_str(pinfo->cinfo, COL_INFO, " |=Choose one");
            break;
        case '*':
            ctx_id = ALL_CONTEXTS;
            my_proto_tree_add_string(megaco_context_tree, hf_megaco_Context, tvb,
                tvb_previous_offset, 1,
                "All");
            col_append_str(pinfo->cinfo, COL_INFO, " |=All");
            break;
        case '-':
            ctx_id = NULL_CONTEXT;
            proto_tree_add_text(megaco_context_tree, tvb, tvb_previous_offset, tokenlen, "Context: NULL" );
            col_append_str(pinfo->cinfo, COL_INFO, " |=NULL");
            break;
        default:
            my_proto_tree_add_string(megaco_context_tree, hf_megaco_Context, tvb,
                tvb_previous_offset, tokenlen,
                tvb_format_text(tvb, tvb_previous_offset,
                tokenlen));
            ctx_id = strtoul(tvb_format_text(tvb, tvb_previous_offset, tokenlen),NULL,10);

            if (check_col(pinfo->cinfo, COL_INFO) )
                col_append_fstr(pinfo->cinfo, COL_INFO, " |=%s",tvb_format_text(tvb, tvb_previous_offset,tokenlen));
        }

        ctx = gcp_ctx(msg,trx,ctx_id,keep_persistent_data);

        /* Find Commands */

        /* If Transaction is is Request, Reply or Pending */
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

                sub_ti = proto_tree_add_text(megaco_tree, tvb, tvb_command_start_offset, len+1,
                        "%s", tvb_format_text(tvb, tvb_command_start_offset, len+1));
                megaco_tree_command_line = proto_item_add_subtree(sub_ti, ett_megaco_command_line);
                /* creation of the megaco_tree_command_line additionally Command and Transaction ID will be printed in this line */
                /* Changed to use the lines above. this code is saved if there is complaints
                sub_ti = proto_tree_add_item(megaco_tree,hf_megaco_command_line,tvb,tvb_command_start_offset,tokenlen, FALSE);
                megaco_tree_command_line = proto_item_add_subtree(sub_ti, ett_megaco_command_line);
                */

                tvb_next_offset = tvb_command_start_offset + tokenlen;

                /* Try to dissect Topology Descriptor before the command */
                if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'T') {
                    tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);

                    if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                        tempchar = tempchar - 0x20;

                    if ( tempchar == 'P' || tempchar == 'O'){
                        gint tvb_topology_end_offset = tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '}');
                        if ( tvb_topology_end_offset == -1 ){
                            proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Missing \"}\" ]");
                            return;
                        }

                        tvb_command_start_offset = tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '{');
                        if ( tvb_command_start_offset == -1 ){
                            proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Missing \"{\" ]");
                            return;
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
                            tvb_next_offset = tvb_find_guint8(tvb, tvb_command_start_offset, tvb_transaction_end_offset, '{');
                            continue;
                        }

                    }
                }

                /* Additional value */

                if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'O'){

                    proto_tree_add_text(megaco_tree_command_line, tvb, tvb_command_start_offset, 2, "O- indicates an optional command" );
                    tvb_command_start_offset = tvb_command_start_offset+2;

                }

                /* Additional value */

                if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'W'){

                    proto_tree_add_text(megaco_tree_command_line, tvb, tvb_command_start_offset, 2, "W- indicates a wildcarded response to a command" );
                    tvb_command_start_offset = tvb_command_start_offset+2;

                }



                tvb_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                    tvb_transaction_end_offset, '=');
                if (tvb_offset == -1 ) {
                    proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Missing \"=\" ]");
                    return;
                }
                tvb_offset = megaco_tvb_skip_wsp_return(tvb, tvb_offset -1);
                tokenlen = tvb_offset - tvb_command_start_offset;

                tempchar = tvb_get_guint8(tvb, tvb_command_start_offset);
                if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                    tempchar = tempchar - 0x20;

                if ( tempchar != 'E' ){

                    if ( tvb_get_guint8(tvb, 0 ) == '!'){

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

                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "AuditValue");
                                col_append_str(pinfo->cinfo, COL_INFO, " AuditValue");
                                break;

                            case 'C':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_AUDITCAP_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_AUDITCAP_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "AuditCapability");
                                col_append_str(pinfo->cinfo, COL_INFO, " AuditCapability");
                                break;

                            default:
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_ADD_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_ADD_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }

                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Add");
                                col_append_str(pinfo->cinfo, COL_INFO, " Add");
                                break;
                            }
                            break;

                        case 'N':
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_NOTIFY_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_NOTIFY_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }

                            my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                tvb_command_start_offset, tokenlen,
                                "Notify");
                                col_append_str(pinfo->cinfo, COL_INFO, " Notify");
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

                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Modify");
                                col_append_str(pinfo->cinfo, COL_INFO, " Modify");
                                break;

                            case 'V':
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_MOVE_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_MOVE_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Move");
                                col_append_str(pinfo->cinfo, COL_INFO, " Move");
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
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Packages");
                                break;
                            case 'N':
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Pending");
                                break;
                            case 'R':
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Priority");
                                break;
                            case 'F':
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Profile");
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
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "ServiceChange");
                                break;

                            default:
                                switch(trx_type) {
                                    case GCP_TRX_REQUEST: cmd_type = GCP_CMD_SUB_REQ; break;
                                    case GCP_TRX_REPLY: cmd_type = GCP_CMD_SUB_REPLY; break;
                                    default: cmd_type = GCP_CMD_NONE; break;
                                }
                                my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                                    tvb_command_start_offset, tokenlen,
                                    "Subtract");
                                col_append_str(pinfo->cinfo, COL_INFO, " Subtract");
                                break;
                            }
                            break;

                        default:
                            tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
                            tvb_ensure_bytes_exist(tvb, tvb_previous_offset, tokenlen);
                            proto_tree_add_string(megaco_tree, hf_megaco_error_Frame, tvb,
                                tvb_previous_offset, tokenlen,
                                "No Command detectable !");
                            return;
                        }
                    }
                    else{
                        gchar* command = tvb_format_text(tvb, tvb_command_start_offset, tokenlen);

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
                        } else if ( g_str_equal(command,"Subtract") ) {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_SUB_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_SUB_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        } else {
                            switch(trx_type) {
                                case GCP_TRX_REQUEST: cmd_type = GCP_CMD_OTHER_REQ; break;
                                case GCP_TRX_REPLY: cmd_type = GCP_CMD_REPLY; break;
                                default: cmd_type = GCP_CMD_NONE; break;
                            }
                        }


                        my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
                            tvb_command_start_offset, tokenlen,
                            tvb_format_text(tvb, tvb_command_start_offset,
                            tokenlen));
                            if (check_col(pinfo->cinfo, COL_INFO) )
                                col_append_fstr(pinfo->cinfo, COL_INFO, " %s",command);
                    }

                    if (cmd_type == GCP_CMD_NONE && trx_type == GCP_TRX_REPLY) {
                        cmd_type = GCP_CMD_REPLY;
                    }

                    if (cmd_type != GCP_CMD_NONE) {
                        cmd = gcp_cmd(msg, trx, ctx, cmd_type, tvb_command_start_offset, keep_persistent_data);
                        tap_queue_packet(megaco_tap, pinfo, cmd);
                    }

                    tvb_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
                        tvb_transaction_end_offset, '=');
                    if (tvb_offset == -1 ) {
                        proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Missing \"=\" ]");
                        return;
                    }
                    tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset+1);
                    tokenlen = tvb_next_offset - tvb_offset;
                    if (tokenlen+1 <= 0) {
                        proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Invalid token length (%d) ]", tokenlen+1);
                        return;
                    }

                    tempchar = tvb_get_guint8(tvb, tvb_offset);
                    if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                        tempchar = tempchar - 0x20;

                    term = ep_new0(gcp_term_t);
                    wild_term = GCP_WILDCARD_NONE;
                    term->type = GCP_TERM_TYPE_UNKNOWN;

                    switch ( tempchar ){

                    case 'E':
                        if ((tokenlen+1 > (int) sizeof(TermID))) {
                            proto_tree_add_text(megaco_tree, tvb, 0, 0, "[ Parse error: Invalid TermID length (%d) ]", tokenlen+1);
                            return;
                        }
                        tvb_get_nstringz0(tvb,tvb_offset,tokenlen+1,TermID);
                        TermID[0] = 'e';

                        term->len = tokenlen;
                        term->str = (gchar*)(term->buffer = TermID);

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, keep_persistent_data);

                        /*** TERM ***/
                        my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen,
                            TermID);
                        break;

                    case '*':
                        wild_term = GCP_WILDCARD_ALL;
                        term->len = 1;
                        term->buffer = (guint8*)(term->str = "*");

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, keep_persistent_data);

                        my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen,
                            "WildCard all");
                            col_append_str(pinfo->cinfo, COL_INFO, "=*");
                        break;

                    case '$':
                        wild_term = GCP_WILDCARD_CHOOSE;

                        term->len = 1;
                        term->buffer = (term->str = "$");

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, keep_persistent_data);

                        my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen,
                            "WildCard any");
                            col_append_str(pinfo->cinfo, COL_INFO, "=$");
                        break;

                    default:
                        /*** TERM ***/
                        my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
                            tvb_offset, tokenlen,
                            tvb_format_text(tvb, tvb_offset,
                            tokenlen));

                        term->len = tokenlen;
                        term->buffer = (guint8*)(term->str = tvb_format_text(tvb, tvb_offset, tokenlen));

                        gcp_cmd_add_term(msg, trx, cmd, term, wild_term, keep_persistent_data);

                            if (check_col(pinfo->cinfo, COL_INFO) )
                                col_append_fstr(pinfo->cinfo, COL_INFO, "=%s",tvb_format_text(tvb, tvb_offset,tokenlen));
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
                    dissect_megaco_descriptors(tvb, megaco_tree, pinfo, tvb_command_start_offset-1,tvb_descriptors_end_offset);
                }
                else {
                    dissect_megaco_descriptors(tvb, megaco_tree, pinfo, tvb_descriptors_start_offset,tvb_descriptors_end_offset);
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
            gcp_msg_to_str(msg,keep_persistent_data);
            gcp_analyze_msg(megaco_tree, tvb, msg, &megaco_ctx_ids );
        }

        tvb_next_offset = tvb_transaction_end_offset;

    }
    while( tvb_transaction_end_offset < tvb_len - 2);

    if(global_megaco_raw_text){
        tvb_raw_text_add(tvb, megaco_tree);
    }
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
dissect_megaco_descriptors(tvbuff_t *tvb, proto_tree *megaco_tree_command_line, packet_info *pinfo, gint tvb_descriptors_start_offset, gint tvb_descriptors_end_offset)
{
    gint        tvb_len, len, token_index, tvb_offset, temp_offset;
    gint        tvb_current_offset,tvb_previous_offset,tokenlen;
    gint        tvb_RBRKT, tvb_LBRKT,  RBRKT_counter, LBRKT_counter;
    tvb_len     = tvb_length(tvb);


    len             = 0;
    tvb_RBRKT       = 0;
    tvb_LBRKT       = 0;
    RBRKT_counter   = 0;
    LBRKT_counter   = 0;


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
            proto_tree_add_text(megaco_tree_command_line, tvb, 0, 0, "[ Parse error: Invalid offset ]");
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
            if (!isalpha(tvb_get_guint8(tvb, tvb_offset ))){
                break;
            }
        }
        tokenlen =  tvb_offset - tvb_previous_offset;
        token_index = find_megaco_descriptors_names(tvb, tvb_previous_offset, tokenlen);
        if (tvb_RBRKT > tvb_descriptors_end_offset) tvb_RBRKT = tvb_descriptors_end_offset;
        switch ( token_index ){
        case MEGACO_MODEM_TOKEN:
            dissect_megaco_modemdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_MUX_TOKEN:
            dissect_megaco_multiplexdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_MEDIA_TOKEN:
            /*TODO: Move tis to the top when all branches fixed !!!*/
            temp_offset = tvb_find_guint8(tvb, tvb_previous_offset,tvb_descriptors_end_offset, '{');
            tokenlen =  temp_offset - tvb_previous_offset+1;
            proto_tree_add_text(megaco_tree_command_line, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, temp_offset +1);
            dissect_megaco_mediadescriptor(tvb, megaco_tree_command_line, pinfo, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_SIGNALS_TOKEN:
            dissect_megaco_signaldescriptor(tvb, pinfo, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_SERVICES_TOKEN:
            dissect_megaco_servicechangedescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_STATS_TOKEN:
            dissect_megaco_statisticsdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_ERROR_TOKEN:
            dissect_megaco_errordescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_EVENTS_TOKEN:
            dissect_megaco_eventsdescriptor(tvb, pinfo, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_AUDIT_TOKEN:
            dissect_megaco_auditdescriptor(tvb, megaco_tree_command_line, pinfo, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_DIGITMAP_TOKEN:
            dissect_megaco_digitmapdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_OE_TOKEN:
            /* ObservedEventsToken */
            dissect_megaco_observedeventsdescriptor(tvb, pinfo, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_TOPOLOGY_TOKEN:
            dissect_megaco_topologydescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        case MEGACO_PACKAGES_TOKEN:
            dissect_megaco_Packagesdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
            break;
        default:
            tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
            proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_Frame, tvb,
                tvb_previous_offset, tokenlen,
                "No Descriptor detectable !");
            break;
        }

        tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;

        tvb_current_offset      = tvb_find_guint8(tvb, tvb_RBRKT, tvb_len, ',');
        if (tvb_current_offset == -1 || tvb_descriptors_end_offset < tvb_current_offset){
            tvb_current_offset = tvb_descriptors_end_offset;
        }
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);
        tvb_LBRKT = tvb_previous_offset;
        tvb_RBRKT = tvb_previous_offset;

    } while ( tvb_current_offset < tvb_descriptors_end_offset );

}

static void
dissect_megaco_modemdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen = 0;



    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_modem_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_multiplexdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_multiplex_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(tvb, tvb_previous_offset,
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
dissect_megaco_mediadescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,packet_info *pinfo,  gint tvb_last_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen, tvb_LBRKT, tvb_RBRKT;
    gint    tvb_next_offset, tvb_current_offset, tvb_offset,  equal_offset;
    gint    mediaParm;


    proto_tree  *megaco_mediadescriptor_tree, *megaco_mediadescriptor_ti;

    tokenlen            = 0;
    tvb_next_offset     = 0;
    tvb_current_offset  = 0;
    tvb_offset          = 0;

    /*
    megaco_mediadescriptor_ti = proto_tree_add_text(megaco_tree_command_line,tvb,tvb_previous_offset,tokenlen,"Media Descriptor");
    megaco_mediadescriptor_tree = proto_item_add_subtree(megaco_mediadescriptor_ti, ett_megaco_mediadescriptor);
    */
    while ( tvb_previous_offset < tvb_last_RBRKT){
        /* Start of token */
        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);

        /* Find token length */
        for (tvb_next_offset=tvb_current_offset; tvb_next_offset < tvb_last_RBRKT; tvb_next_offset++){
                if (!isalpha(tvb_get_guint8(tvb, tvb_next_offset ))){
                break;
            }
        }
        tokenlen = tvb_next_offset - tvb_current_offset;

        mediaParm = find_megaco_mediaParm_names(tvb, tvb_current_offset, tokenlen);

        tvb_LBRKT = tvb_find_guint8(tvb, tvb_next_offset , tvb_last_RBRKT, '{');
        tvb_next_offset = tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_last_RBRKT, '}');
        tvb_RBRKT = tvb_next_offset;

        tokenlen = tvb_LBRKT - tvb_current_offset +1;
        megaco_mediadescriptor_ti = proto_tree_add_text(megaco_tree_command_line,tvb,tvb_current_offset,
                tokenlen,"%s",tvb_format_text(tvb, tvb_current_offset,tokenlen));

        switch ( mediaParm ){
        case MEGACO_LOCAL_TOKEN:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_Localdescriptor(tvb,megaco_tree_command_line , pinfo,
                tvb_RBRKT, tvb_current_offset);
            tvb_current_offset = tvb_RBRKT;
            break;
        case MEGACO_REMOTE_TOKEN:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_Localdescriptor(tvb,megaco_tree_command_line , pinfo,
                tvb_RBRKT, tvb_current_offset);
            tvb_current_offset = tvb_RBRKT;
            break;
        case MEGACO_LOCAL_CONTROL_TOKEN:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_LocalControldescriptor(tvb,megaco_tree_command_line, pinfo ,
                tvb_RBRKT, tvb_current_offset);
            tvb_current_offset = tvb_RBRKT;
            break;
        case MEGACO_STREAM_TOKEN:
            megaco_mediadescriptor_tree = proto_item_add_subtree(megaco_mediadescriptor_ti, ett_megaco_mediadescriptor);

            equal_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_last_RBRKT, '=');
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, equal_offset+1);
            tvb_offset = megaco_tvb_skip_wsp_return(tvb, tvb_LBRKT-1);
            tokenlen =  tvb_offset - tvb_current_offset;

            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_streamid, tvb,
                tvb_current_offset, tokenlen, tvb_format_text(tvb, tvb_current_offset,tokenlen));
            tvb_previous_offset = tvb_LBRKT+1;
            continue;
        case MEGACO_TERMINATION_STATE_DESC:
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_LBRKT+1);
            dissect_megaco_TerminationStatedescriptor(tvb,megaco_tree_command_line ,
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
            tokenlen = tvb_next_offset - tvb_RBRKT+1;
            proto_tree_add_text(megaco_tree_command_line, tvb, tvb_RBRKT, tokenlen,
                "%s", tvb_format_text(tvb, tvb_RBRKT, tokenlen));
            tvb_previous_offset = tvb_next_offset+1;
        }else{
            /* Add the trailing '}'*/
            proto_tree_add_text(megaco_tree_command_line, tvb, tvb_RBRKT, 1,
                "%s", tvb_format_text(tvb, tvb_RBRKT, 1));
            tvb_previous_offset = tvb_last_RBRKT;
        }

    } /* End while */
}

static void
dissect_megaco_h245(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree, gint offset, gint len, gchar *msg)
{
    /*proto_item *item;*/
    /*proto_tree *tree;*/

    /*item=proto_tree_add_string(megaco_tree, hf_megaco_h245, tvb,
        offset, len, msg );
        */
    /*item = */proto_tree_add_text(megaco_tree, tvb, offset, len, "%s", msg);

    /*tree = proto_item_add_subtree(item, ett_megaco_h245); */

    /* arbitrary maximum length */
    if(len<20480){
        int i;
        tvbuff_t *h245_tvb;
        guint8 *buf = g_malloc(10240);

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
        tvb_set_free_cb(h245_tvb, g_free);
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
        guint8 *buf = g_malloc(10240);

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
        tvb_set_free_cb(h245_tvb, g_free);
        /* should go through a handle, however,  the two h245 entry
           points are different, one is over tpkt and the other is raw
        */
        asn1_ctx_init(&actx, ASN1_ENC_PER, TRUE, pinfo);
        dissect_h245_H223Capability(h245_tvb, 0, &actx, megaco_tree, hf_megaco_h223Capability);
    }
}

static void
dissect_megaco_eventsdescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_events_end_offset, tvb_events_start_offset, tvb_LBRKT;
    proto_tree  *megaco_eventsdescriptor_tree, *megaco_eventsdescriptor_ti;

    guint8 tempchar;
    gint requested_event_start_offset, requested_event_end_offset;
    proto_tree  *megaco_requestedevent_tree, *megaco_requestedevent_ti;

    tokenlen                        = 0;
    tvb_current_offset              = 0;
    tvb_next_offset                 = 0;
    tvb_help_offset                 = 0;
    tvb_events_end_offset           = 0;
    tvb_events_start_offset         = 0;
    tvb_help_offset                 = 0;
    requested_event_start_offset    = 0;
    requested_event_end_offset      = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;

    megaco_eventsdescriptor_ti = proto_tree_add_text(megaco_tree_command_line, tvb, tvb_previous_offset, tokenlen,
        "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));

    /*
    megaco_eventsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_events_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
    */
    megaco_eventsdescriptor_tree = proto_item_add_subtree(megaco_eventsdescriptor_ti, ett_megaco_eventsdescriptor);

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
    tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');

    if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){

        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_next_offset-1);

        tokenlen =  tvb_help_offset - tvb_current_offset;

        proto_tree_add_string(megaco_eventsdescriptor_tree, hf_megaco_requestid, tvb,
            tvb_current_offset, tokenlen,
            tvb_format_text(tvb, tvb_current_offset,
            tokenlen));

        tvb_events_end_offset   = tvb_RBRKT;
        tvb_events_start_offset = tvb_previous_offset;

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

            megaco_requestedevent_ti = proto_tree_add_item(megaco_eventsdescriptor_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,tokenlen, FALSE);
            megaco_requestedevent_tree = proto_item_add_subtree(megaco_requestedevent_ti, ett_megaco_requestedevent);

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                tvb_help_offset = megaco_tvb_skip_wsp(tvb, requested_event_start_offset +1);
                tempchar = tvb_get_guint8(tvb, tvb_help_offset);

                requested_event_start_offset = megaco_tvb_skip_wsp(tvb, requested_event_start_offset +1);
                requested_event_end_offset = megaco_tvb_skip_wsp_return(tvb, requested_event_end_offset-1);

                if ( tempchar == 'D' || tempchar == 'd'){
                    dissect_megaco_digitmapdescriptor(tvb, megaco_requestedevent_tree, requested_event_end_offset, requested_event_start_offset);
                }
                else{
                    gchar *msg;

                    tokenlen =  requested_event_end_offset - requested_event_start_offset;
                    msg=tvb_format_text(tvb,requested_event_start_offset, tokenlen);
                    if(!strncmp("h245", msg, 4)){
                        dissect_megaco_h245(tvb, pinfo, megaco_requestedevent_tree, requested_event_start_offset, tokenlen, msg);
                    } else {
                        proto_tree_add_text(megaco_requestedevent_tree, tvb, requested_event_start_offset, tokenlen,
                            "%s", msg);
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
dissect_megaco_signaldescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint tokenlen, pkg_tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_signals_end_offset, tvb_signals_start_offset, tvb_LBRKT;
    /*proto_tree  *megaco_signalsdescriptor_tree, *megaco_signalsdescriptor_ti;*/

    gint requested_signal_start_offset, requested_signal_end_offset;
    proto_tree  *megaco_requestedsignal_tree, *megaco_requestedsignal_ti;

    tokenlen                        = 0;
    tvb_current_offset              = 0;
    tvb_next_offset                 = 0;
    tvb_help_offset                 = 0;
    tvb_signals_end_offset          = 0;
    tvb_signals_start_offset        = 0;
    tvb_LBRKT                       = 0;
    requested_signal_start_offset   = 0;
    requested_signal_end_offset     = 0;

    tvb_signals_end_offset   = tvb_RBRKT;
    tvb_signals_start_offset = tvb_previous_offset;

    if(toupper(tvb_get_guint8(tvb, tvb_previous_offset+1))=='G')
      tokenlen = 2;                             /* token is compact text (SG) */
    else
      tokenlen = 7;                             /* token must be verbose text (Signals) */

    tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset+tokenlen);

    if(tvb_get_guint8(tvb, tvb_current_offset)!='{') {          /* {} has been omitted */

      proto_tree_add_text(megaco_tree_command_line, tvb, tvb_signals_start_offset, tokenlen,
                "%s", "Empty Signal Descriptor");

      col_append_str(pinfo->cinfo, COL_INFO, " (Signal:none)");     /* then say so */

      return;                               /* and return */
    }

    tvb_LBRKT = tvb_find_guint8(tvb, tvb_previous_offset, tvb_signals_end_offset, '{');
    tokenlen =  (tvb_LBRKT+1) - tvb_signals_start_offset;

    proto_tree_add_text(megaco_tree_command_line, tvb, tvb_signals_start_offset, tokenlen,
        "%s", tvb_format_text(tvb, tvb_signals_start_offset, tokenlen));

    /*
    megaco_signalsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_signal_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
    megaco_signalsdescriptor_tree = proto_item_add_subtree(megaco_signalsdescriptor_ti, ett_megaco_signalsdescriptor);
    */

    tvb_current_offset = tvb_LBRKT;
    tvb_next_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);
    if (check_col(pinfo->cinfo, COL_INFO) )
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Signal:%s)",tvb_format_text(tvb, tvb_current_offset,tokenlen-tvb_current_offset+tvb_previous_offset));


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

            tvb_help_offset = tvb_LBRKT = tvb_find_guint8(tvb, tvb_previous_offset, tvb_signals_end_offset, '{');

            /* if there are signalparameter  */

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                requested_signal_start_offset = tvb_help_offset;
                requested_signal_end_offset  = tvb_RBRKT;
                tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_help_offset-1);
                pkg_tokenlen = tvb_help_offset - tvb_previous_offset;
                tokenlen = tvb_LBRKT+1 - tvb_previous_offset;
            }
            /* no parameters */
            else {
                tokenlen = pkg_tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
            }

            megaco_requestedsignal_ti = proto_tree_add_text(megaco_tree_command_line, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));
            megaco_requestedsignal_tree = proto_item_add_subtree(megaco_requestedsignal_ti, ett_megaco_requestedsignal);

            proto_tree_add_item(megaco_requestedsignal_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,pkg_tokenlen, FALSE);

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
                gchar *msg;

                requested_signal_start_offset = megaco_tvb_skip_wsp(tvb, requested_signal_start_offset +1);
                requested_signal_end_offset = megaco_tvb_skip_wsp_return(tvb, requested_signal_end_offset-1);

                tokenlen =  requested_signal_end_offset - requested_signal_start_offset;

                msg=tvb_format_text(tvb,requested_signal_start_offset, tokenlen+1);
                if(!strncmp("h245", msg, 4)){
                    dissect_megaco_h245(tvb, pinfo, megaco_tree_command_line, requested_signal_start_offset, tokenlen, msg);
                } else {
                    proto_tree_add_text(megaco_tree_command_line, tvb, requested_signal_start_offset, tokenlen,
                        "%s", msg);
                }
                /* Print the trailing '}' */
                proto_tree_add_text(megaco_tree_command_line, tvb, tvb_RBRKT, 1,
                    "%s", tvb_format_text(tvb, tvb_RBRKT, 1));
            }

            tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
                tvb_signals_end_offset, ',');

            if (tvb_current_offset == -1 || tvb_current_offset > tvb_signals_end_offset || tvb_current_offset < tvb_previous_offset){
                tvb_current_offset = tvb_signals_end_offset;
            }

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);

            tvb_LBRKT = tvb_previous_offset;
            tvb_RBRKT = tvb_previous_offset;
            /* Print the trailing '}' */
            proto_tree_add_text(megaco_tree_command_line, tvb, tvb_signals_end_offset, 1,
                "%s", tvb_format_text(tvb, tvb_signals_end_offset, 1));

        } while ( tvb_current_offset < tvb_signals_end_offset );
    }else{
        /* signals{}*/
        proto_tree_add_text(megaco_tree_command_line, tvb, tvb_signals_end_offset, 1,
                "%s", tvb_format_text(tvb, tvb_signals_end_offset, 1));
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
        proto_tree_add_text(megaco_tree, tvb, tvb_offset, tvb_stop+1-tvb_offset, "Badly constructed audit descriptor (no { )");
        return;
    }
    tokenlen = (tvb_stop + 1) - tvb_offset;

    megaco_auditdescriptor_ti = proto_tree_add_none_format( megaco_tree, hf_megaco_audit_descriptor,
                                tvb, tvb_offset, tokenlen, "Audit descriptor" );

    megaco_auditdescriptor_tree = proto_item_add_subtree( megaco_auditdescriptor_ti, ett_megaco_auditdescriptor );

    tokenlen = tvb_next + 1 - tvb_offset;

    proto_tree_add_text( megaco_auditdescriptor_tree, tvb, tvb_offset, tokenlen, "Audit token {" );

    tvb_offset = tvb_next;

    while( tvb_offset < tvb_stop )
    {
        tvb_offset = megaco_tvb_skip_wsp(tvb, tvb_offset+1);                                          /* find start of an auditItem */
                if( tvb_get_guint8(tvb, tvb_offset) != '}' )                                                  /* got something */
                {
            tvb_next = tvb_find_guint8(tvb, tvb_offset, tvb_stop, ',');                           /* end of an auditItem */
                    if (tvb_next == -1)  tvb_next = tvb_stop;                                             /* last item doesn't have a comma */
            tvb_end = megaco_tvb_skip_wsp_return(tvb, tvb_next-1);                                /* trim any trailing whitespace */
            tokenlen =  tvb_end - tvb_offset;                                                     /* get length of token */

            token_index = find_megaco_descriptors_names(tvb, tvb_offset, tokenlen);               /* lookup the token */
            if( token_index == -1 )  token_index = 0;                                             /* if not found then 0 => Unknown */

            proto_tree_add_string(megaco_auditdescriptor_tree, hf_megaco_audititem, tvb,
                    tvb_offset, tokenlen, megaco_descriptors_names[token_index].name);    /* and display the long form */

            tvb_offset = tvb_next;                                                                /* advance pointer */
        }
    }
    proto_tree_add_text(megaco_auditdescriptor_tree, tvb, tvb_stop, 1, "}");                              /* End of auditDescriptor */
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
dissect_megaco_servicechangedescriptor(tvbuff_t *tvb, proto_tree *megaco_tree,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint        tokenlen, tvb_LBRKT, tvb_offset;
    gint        token_index;
    gint        tvb_current_offset;
    gboolean    more_params = TRUE;
    proto_item* item;
    gint                reason;
    guint8              ServiceChangeReason_str[4];

    tvb_LBRKT  = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
    /*
    if (tvb_LBRKT == -1)
        return;
        */
    tokenlen = (tvb_LBRKT + 1) - tvb_previous_offset;
    proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));


    /* Start dissecting serviceChangeParm */
    tvb_previous_offset = tvb_LBRKT + 1;
    while (more_params){
        tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_previous_offset);
        /* Find token length */
        for (tvb_offset=tvb_previous_offset; tvb_offset < tvb_RBRKT; tvb_offset++){
            if (!isalpha(tvb_get_guint8(tvb, tvb_offset ))){
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
            item = proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));

            /* As the reason code ( if a digit ) can be in quoted string or 'just' digit
             * look for a nine and hope for the best.
             */
            tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '9');
            if ( tvb_current_offset == -1)
                break;

            tvb_get_nstringz0(tvb,tvb_current_offset,4,ServiceChangeReason_str);
            reason = atoi(ServiceChangeReason_str);

            proto_item_append_text(item,"[ %s ]", val_to_str(reason, MEGACO_ServiceChangeReasons_vals,"Unknown (%u)"));
            break;
        case MEGACO_DELAY_TOKEN:
        case MEGACO_SC_ADDR_TOKEN:
        case MEGACO_MGC_ID_TOKEN:
        case MEGACO_PROFILE_TOKEN:
        case MEGACO_VERSION_TOKEN:
        case MEGACO_METHOD_TOKEN:
            /* No special dissection: fall trough */
        default:
        /* Unknown or:
         * extension            = extensionParameter parmValue
         * extensionParameter   = "X"  ("-" / "+") 1*6(ALPHA / DIGIT)
         */
            proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));
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
                            tvb_format_text(tvb, tvb_previous_offset,
                            tokenlen));
    */
    proto_tree_add_text(megaco_tree, tvb, tvb_RBRKT, 1,"%s", tvb_format_text(tvb, tvb_RBRKT, 1));

}
static void
dissect_megaco_digitmapdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen = 0;

    tokenlen =  tvb_RBRKT - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_digitmap_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_statisticsdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_statistics_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_observedeventsdescriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint tokenlen, pkg_tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_observedevents_end_offset, tvb_observedevents_start_offset, tvb_LBRKT;
    proto_tree  *megaco_observedeventsdescriptor_tree, *megaco_observedeventsdescriptor_ti;

    guint8 tempchar;
    gint requested_event_start_offset, requested_event_end_offset, param_start_offset, param_end_offset;
    proto_tree  *megaco_observedevent_tree, *megaco_observedevent_ti;

    tokenlen                        = 0;
    tvb_current_offset              = 0;
    tvb_next_offset                 = 0;
    tvb_help_offset                 = 0;
    tvb_observedevents_end_offset   = 0;
    tvb_observedevents_start_offset = 0;
    tvb_LBRKT                       = 0;
    requested_event_start_offset    = 0;
    requested_event_end_offset  = 0;


    tvb_LBRKT = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
    tvb_next_offset = tvb_LBRKT;
    tokenlen =  (tvb_next_offset+1) - tvb_previous_offset;

    /*
    megaco_observedeventsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_observedevents_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
    megaco_observedeventsdescriptor_tree = proto_item_add_subtree(megaco_observedeventsdescriptor_ti, ett_megaco_observedeventsdescriptor);
    */

    megaco_observedeventsdescriptor_ti = proto_tree_add_text(megaco_tree_command_line, tvb, tvb_previous_offset, tokenlen,
        "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));
    megaco_observedeventsdescriptor_tree = proto_item_add_subtree(megaco_observedeventsdescriptor_ti, ett_megaco_observedeventsdescriptor);

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
    tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');

    if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){

        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_next_offset-1);

        tokenlen =  tvb_help_offset - tvb_current_offset;

        proto_tree_add_string(megaco_observedeventsdescriptor_tree, hf_megaco_requestid, tvb,
            tvb_current_offset, tokenlen,
            tvb_format_text(tvb, tvb_current_offset,
            tokenlen));

        tvb_observedevents_end_offset   = tvb_RBRKT;
        tvb_observedevents_start_offset = tvb_previous_offset;

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

            megaco_observedevent_ti = proto_tree_add_text(megaco_tree_command_line, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb, tvb_previous_offset, tokenlen));

            megaco_observedevent_tree = proto_item_add_subtree(megaco_observedevent_ti, ett_megaco_observedevent);

            proto_tree_add_item(megaco_observedevent_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,pkg_tokenlen, FALSE);

            if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){

                tvb_help_offset = megaco_tvb_skip_wsp(tvb, requested_event_start_offset +1);
                tempchar = tvb_get_guint8(tvb, tvb_help_offset);
                if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                    tempchar = tempchar - 0x20;

                requested_event_start_offset = megaco_tvb_skip_wsp(tvb, requested_event_start_offset +1)-1;
                requested_event_end_offset = megaco_tvb_skip_wsp_return(tvb, requested_event_end_offset-1);

                tvb_help_offset = requested_event_start_offset;

                do {
                    gchar *msg;

                    param_start_offset = megaco_tvb_skip_wsp(tvb, tvb_help_offset+1);

                    tvb_help_offset = tvb_find_guint8(tvb, tvb_help_offset+1,requested_event_end_offset, ',');

                    if ( tvb_help_offset > requested_event_end_offset || tvb_help_offset == -1){
                        tvb_help_offset = requested_event_end_offset;
                    }

                    param_end_offset = megaco_tvb_skip_wsp(tvb, tvb_help_offset-1);

                    tokenlen =  param_end_offset - param_start_offset+1;
                    msg=tvb_format_text(tvb,param_start_offset, tokenlen);
                    if(!strncmp("h245", msg, 4)){
                        dissect_megaco_h245(tvb, pinfo, megaco_tree_command_line, param_start_offset, tokenlen, msg);
                    } else {
                        proto_tree_add_text(megaco_tree_command_line, tvb, param_start_offset, tokenlen,
                            "%s", msg);
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
                proto_tree_add_text(megaco_observedevent_tree, tvb, 0, 0, "[ Parse error: Invalid offset ]");
                return;
            }

            tvb_previous_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset+1);

            tvb_LBRKT = tvb_previous_offset;
            tvb_RBRKT = tvb_previous_offset;
            /* Print the trailing '}' */
            proto_tree_add_text(megaco_tree_command_line, tvb, tvb_observedevents_end_offset, 1,
                "%s", tvb_format_text(tvb, tvb_observedevents_end_offset, 1));

        } while ( tvb_current_offset < tvb_observedevents_end_offset );
    }
}
static void
dissect_megaco_topologydescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint    tokenlen;

    tokenlen = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
    proto_tree_add_string(megaco_tree_command_line, hf_megaco_topology_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text_wsp(tvb, tvb_previous_offset,
                            tokenlen));

}
static void
dissect_megaco_Packagesdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
    gint tvb_packages_end_offset, tvb_packages_start_offset, tvb_LBRKT;
    proto_tree  *megaco_packagesdescriptor_tree, *megaco_packagesdescriptor_ti;

    tokenlen                    = 0;
    tvb_current_offset          = 0;
    tvb_next_offset             = 0;
    tvb_help_offset             = 0;
    tvb_packages_end_offset     = 0;
    tvb_packages_start_offset   = 0;
    tvb_LBRKT                   = 0;

    tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;

    megaco_packagesdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_packages_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
    megaco_packagesdescriptor_tree = proto_item_add_subtree(megaco_packagesdescriptor_ti, ett_megaco_packagesdescriptor);



    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
    tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');

    if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){

        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
        tvb_help_offset = megaco_tvb_skip_wsp_return(tvb, tvb_next_offset-1);

        tokenlen =  tvb_help_offset - tvb_current_offset;

        proto_tree_add_string(megaco_packagesdescriptor_tree, hf_megaco_requestid, tvb,
            tvb_current_offset, tokenlen,
            tvb_format_text(tvb, tvb_current_offset,
            tokenlen));

        tvb_packages_end_offset   = tvb_RBRKT;
        tvb_packages_start_offset = tvb_previous_offset;

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

            proto_tree_add_text(megaco_packagesdescriptor_tree, tvb, tvb_previous_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_previous_offset,
                tokenlen));


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
dissect_megaco_errordescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{

    gint                tokenlen;
    gint                error_code;
    guint8              error[4];
    gint                tvb_next_offset, tvb_current_offset,tvb_len;
    proto_item*         item;
    proto_item*         hidden_item;

    tvb_len             = tvb_length(tvb);
    tokenlen            = 0;
    tvb_next_offset         = 0;
    tvb_current_offset      = 0;
    tvb_len             = 0;

    tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset , tvb_RBRKT, '=');
    tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_current_offset +1);
    tvb_get_nstringz0(tvb,tvb_current_offset,4,error);
    error_code = atoi(error);
    hidden_item = proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
                            tvb_current_offset, 3,
                            tvb_format_text(tvb, tvb_current_offset,
                            3));
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tokenlen =  (tvb_RBRKT) - tvb_previous_offset+1;


    proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
                            tvb_previous_offset, tokenlen,
                            tvb_format_text(tvb, tvb_previous_offset,
                            tokenlen));

    item = proto_tree_add_text(megaco_tree_command_line, tvb, tvb_current_offset, 3,
        "Error code: %s",
        val_to_str(error_code, MEGACO_error_code_vals,
          "Unknown (%u)"));

    PROTO_ITEM_SET_GENERATED(item);

}
static void
dissect_megaco_TerminationStatedescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,  gint tvb_next_offset, gint tvb_current_offset)
{
    gint tokenlen;
    gint tvb_offset;
    guint8 tempchar;

    proto_tree  *megaco_TerminationState_tree, *megaco_TerminationState_ti;

    tokenlen        = 0;
    tvb_offset      = 0;

    tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');

    tokenlen = tvb_next_offset - tvb_current_offset;
    /*
    megaco_TerminationState_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_TerminationState_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
    megaco_TerminationState_tree = proto_item_add_subtree(megaco_TerminationState_ti, ett_megaco_TerminationState);
    */
    megaco_TerminationState_ti = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_current_offset, tokenlen,
                                    "%s", tvb_format_text(tvb, tvb_current_offset, tokenlen));
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

            tempchar = tvb_get_guint8(tvb, tvb_current_offset);
            tokenlen = tvb_offset - tvb_current_offset;
            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                tempchar = tempchar - 0x20;

            proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Service_State, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            break;

        case 'B':

            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tempchar = tvb_get_guint8(tvb, tvb_current_offset);
            tokenlen = tvb_offset - tvb_current_offset;
            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                tempchar = tempchar - 0x20;

            proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Event_Buffer_Control, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            break;

        case 'E':
            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tempchar = tvb_get_guint8(tvb, tvb_current_offset);
            tokenlen = tvb_offset - tvb_current_offset;
            if ( (tempchar >= 'a')&& (tempchar <= 'z'))
                tempchar = tempchar - 0x20;

            proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Event_Buffer_Control, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            break;

        default:
            tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
            if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
                tvb_offset = tvb_next_offset;
            }

            tokenlen = tvb_offset - tvb_current_offset;

            proto_tree_add_text(megaco_TerminationState_tree, tvb, tvb_current_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_current_offset,tokenlen));
            break;
        }


        tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
        tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');

    }
    proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_next_offset, 1,
            "%s", tvb_format_text(tvb, tvb_next_offset, 1));

}

static void
dissect_megaco_Localdescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset)
{
    gint tokenlen;
    tvbuff_t *next_tvb;

    proto_tree  *megaco_localdescriptor_tree, *megaco_localdescriptor_ti;

    tokenlen = 0;

    tokenlen = tvb_next_offset - tvb_current_offset;


    /*
    megaco_localdescriptor_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_Local_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
    */
    megaco_localdescriptor_ti = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_current_offset, tokenlen,
        "%s", tvb_format_text(tvb, tvb_current_offset, tokenlen));
    megaco_localdescriptor_tree = proto_item_add_subtree(megaco_localdescriptor_ti, ett_megaco_Localdescriptor);

    tokenlen = tvb_next_offset - tvb_current_offset;
    if ( tokenlen > 3 ){
        next_tvb = tvb_new_subset(tvb, tvb_current_offset, tokenlen, tokenlen);
        call_dissector(sdp_handle, next_tvb, pinfo, megaco_localdescriptor_tree);
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
dissect_megaco_LocalControldescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree, packet_info *pinfo,  gint tvb_next_offset, gint tvb_current_offset)
{
    gint tokenlen;
    guint token_name_len;
    gint tvb_offset,tvb_help_offset;
    gint token_index = 0;
    gchar *msg;
    proto_item* item;
    guint8              code_str[3];

    /*proto_tree  *megaco_LocalControl_tree, *megaco_LocalControl_ti; */

    tokenlen        = 0;
    tvb_offset      = 0;
    tvb_help_offset = 0;


    tokenlen = tvb_next_offset - tvb_current_offset;
    /*
    megaco_LocalControl_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_LocalControl_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
    megaco_LocalControl_tree = proto_item_add_subtree(megaco_LocalControl_ti, ett_megaco_LocalControldescriptor);
    */
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
            if (!isalnum(octet)){
                if ((octet!='/')&&(octet!='_')){
                    break;
                }
            }
        }
        token_name_len = tvb_offset - tvb_current_offset;
        /* Debug Code
        proto_tree_add_text(megaco_LocalControl_tree, tvb, tvb_current_offset, token_name_len,
                "%s", tvb_format_text(tvb,tvb_current_offset,token_name_len));

         */
        token_index = find_megaco_localParam_names(tvb, tvb_current_offset, token_name_len);
        /* Find start of parameter value */
        tvb_offset = tvb_find_guint8(tvb, tvb_offset , tvb_next_offset, '=');
        if (tvb_offset == -1)
            THROW(ReportedBoundsError);
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
        proto_tree_add_text(megaco_LocalControl_tree, tvb, tvb_current_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_current_offset,tokenlen));

         */
        switch ( token_index ){

        case MEGACO_MODETOKEN: /* Mode */
            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_mode, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));
            if (check_col(pinfo->cinfo, COL_INFO) )
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Mode:%s)",tvb_format_text(tvb, tvb_current_offset,tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        case MEGACO_RESERVEDVALUETOKEN: /* ReservedValue */
            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_reserve_value, tvb,
                    tvb_current_offset, tokenlen,
                    tvb_format_text(tvb, tvb_current_offset,
                    tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_RESERVEDGROUPTOKEN: /* ReservedGroup */
            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_reserve_group, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        case MEGACO_H324_H223CAPR: /* h324/h223capr */
            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_h324_h223capr, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            tokenlen = tvb_offset - tvb_help_offset;
            msg=tvb_format_text(tvb,tvb_help_offset, tokenlen);
            dissect_megaco_h324_h223caprn(tvb, pinfo, megaco_mediadescriptor_tree, tvb_help_offset, tokenlen, msg);

            break;

        case MEGACO_H324_MUXTBL_IN: /* h324/muxtbl_in */

            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_h324_muxtbl_in, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);

            tokenlen = tvb_offset - tvb_help_offset;
            msg=tvb_format_text(tvb,tvb_help_offset, tokenlen);
            /* Call the existing rotine with tree = NULL to avoid an entry to the tree */
            dissect_megaco_h245(tvb, pinfo, NULL, tvb_help_offset, tokenlen, msg);

            break;

        case MEGACO_H324_MUXTBL_OUT:

            proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_h324_muxtbl_out, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);

            tokenlen = tvb_offset - tvb_help_offset;
            msg=tvb_format_text(tvb,tvb_help_offset, tokenlen);
            /* Call the existing rotine with tree = NULL to avoid an entry to the tree */
            dissect_megaco_h245(tvb, pinfo, NULL, tvb_help_offset, tokenlen, msg);

            break;

        case MEGACO_DS_DSCP:
            item = proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_ds_dscp, tvb,
                tvb_current_offset, tokenlen,
                tvb_format_text(tvb, tvb_current_offset,
                tokenlen));

            tvb_get_nstringz0(tvb,tvb_current_offset,3,code_str);
            proto_item_append_text(item,"[ %s ]", val_to_str(strtoul(code_str,NULL,16), dscp_vals,"Unknown (%u)"));

            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;

        case MEGACO_GM_SAF:
            tokenlen = tvb_offset - tvb_help_offset;
            item = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_help_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_help_offset,
                tokenlen));
            proto_item_append_text(item," [Remote Source Address Filtering]");
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_SAM:
            tokenlen = tvb_offset - tvb_help_offset;
            item = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_help_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_help_offset,
                tokenlen));
            proto_item_append_text(item," [Remote Source Address Mask]");
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_SPF:
            tokenlen = tvb_offset - tvb_help_offset;
            item = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_help_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_help_offset,
                tokenlen));
            proto_item_append_text(item," [Remote Source Port Filtering]");
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_SPR:
            tokenlen = tvb_offset - tvb_help_offset;
            item = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_help_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_help_offset,
                tokenlen));
            proto_item_append_text(item," [Remote Source Port Range]");
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        case MEGACO_GM_ESAS:
            tokenlen = tvb_offset - tvb_help_offset;
            item = proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_help_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_help_offset,
                tokenlen));
            proto_item_append_text(item," [Explicit Source Address Setting]");
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);
            break;
        default:
            tokenlen = tvb_offset - tvb_help_offset;
            proto_tree_add_text(megaco_mediadescriptor_tree, tvb, tvb_help_offset, tokenlen,
                "%s", tvb_format_text(tvb,tvb_help_offset,
                tokenlen));
            tvb_current_offset = megaco_tvb_skip_wsp(tvb, tvb_offset +1);

            break;
        }
    }
}
/* Copied from MGCP dissector, prints whole message in raw text */

static void tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree){

    gint tvb_linebegin,tvb_lineend,tvb_len,linelen;

    tvb_linebegin = 0;
    tvb_len = tvb_length(tvb);

    proto_tree_add_text(tree, tvb, 0, -1,"-------------- (RAW text output) ---------------");

    do {
        linelen = tvb_find_line_end(tvb,tvb_linebegin,-1,&tvb_lineend,FALSE);
        proto_tree_add_text(tree, tvb, tvb_linebegin, linelen,
                            "%s", tvb_format_text_wsp(tvb,tvb_linebegin,
                                                      linelen));
        tvb_linebegin = tvb_lineend;
    } while ( tvb_lineend < tvb_len );
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
    gint end,tvb_len;
    guint8 tempchar;
    tvb_len = tvb_length(tvb);
    end = tvb_len;

    for(counter = offset; counter < end &&
        ((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
        tempchar == '\t' || tempchar == '\n' || tempchar == '\r'); counter++);
    return (counter);
}

static gint megaco_tvb_skip_wsp_return(tvbuff_t* tvb, gint offset){
    gint counter = offset;
    gint end;
    guint8 tempchar;
    end = 0;

    for(counter = offset; counter > end &&
        ((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
        tempchar == '\t' || tempchar == '\n' || tempchar == '\r'); counter--);
    counter++;
    return (counter);
}

static gint megaco_tvb_find_token(tvbuff_t* tvb, gint offset, gint maxlength){
    gint counter = 0;
    gint pos = offset;
    guchar needle;

    do {
        pos = tvb_pbrk_guint8(tvb, pos + 1, maxlength,(guint8*)"{}", &needle);
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

void proto_reg_handoff_megaco(void);

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
        { &hf_megaco_command_line,
          { "Command line", "megaco.command_line", FT_STRING, BASE_NONE, NULL, 0x0,
            "Commands of this message", HFILL }},
        { &hf_megaco_command,
          { "Command", "megaco.command", FT_STRING, BASE_NONE, NULL, 0x0,
            "Command of this message", HFILL }},
        { &hf_megaco_Context,
          { "Context", "megaco.context", FT_STRING, BASE_NONE, NULL, 0x0,
            "Context ID of this massage", HFILL }},
        { &hf_megaco_digitmap_descriptor,
          { "DigitMap Descriptor", "megaco.digitmap", FT_STRING, BASE_NONE, NULL, 0x0,
            "DigitMap Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_error_descriptor,
          { "ERROR Descriptor", "megaco.error", FT_STRING, BASE_NONE, NULL, 0x0,
            "Error Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_error_Frame,
          { "ERROR frame", "megaco.error_frame", FT_STRING, BASE_NONE, NULL, 0x0,
            "Syntax error", HFILL }},
        { &hf_megaco_Event_Buffer_Control,
          { "Event Buffer Control", "megaco.eventbuffercontrol", FT_STRING, BASE_NONE, NULL, 0x0,
            "Event Buffer Control in Termination State Descriptor", HFILL }},
        { &hf_megaco_events_descriptor,
          { "Events Descriptor", "megaco.events", FT_STRING, BASE_NONE, NULL, 0x0,
            "Events Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_Local_descriptor,
          { "Local Descriptor", "megaco.localdescriptor", FT_STRING, BASE_NONE, NULL, 0x0,
            "Local Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_LocalControl_descriptor,
          { "Local Control Descriptor", "megaco.localcontroldescriptor", FT_STRING, BASE_NONE, NULL, 0x0,
            "Local Control Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_media_descriptor,
          { "Media Descriptor", "megaco.media", FT_STRING, BASE_NONE, NULL, 0x0,
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
          { "Observed Events Descriptor", "megaco.observedevents", FT_STRING, BASE_NONE, NULL, 0x0,
            "Observed Events Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_packages_descriptor,
          { "Packages Descriptor", "megaco.packagesdescriptor", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_pkgdname,
          { "pkgdName", "megaco.pkgdname", FT_STRING, BASE_NONE, NULL, 0x0,
            "PackageName SLASH ItemID", HFILL }},
        { &hf_megaco_Remote_descriptor,
          { "Remote Descriptor", "megaco.remotedescriptor", FT_STRING, BASE_NONE, NULL, 0x0,
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
          { "ds/dscp", "megaco.ds_dscp", FT_STRING, BASE_NONE, NULL, 0x0,
            "ds/dscp Differentiated Services Code Point", HFILL }},
        { &hf_megaco_h324_h223capr,
          { "h324/h223capr", "megaco._h324_h223capr", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_reserve_value,
          { "Reserve Value", "megaco.reservevalue", FT_STRING, BASE_NONE, NULL, 0x0,
            "Reserve Value on or off", HFILL }},
        { &hf_megaco_requestid,
          { "RequestID", "megaco.requestid", FT_STRING, BASE_NONE, NULL, 0x0,
            "RequestID in Events or Observedevents Descriptor", HFILL }},
        { &hf_megaco_servicechange_descriptor,
          { "Service Change Descriptor", "megaco.servicechange", FT_STRING, BASE_NONE, NULL, 0x0,
            "Service Change Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_Service_State,
          { "Service State", "megaco.servicestates", FT_STRING, BASE_NONE, NULL, 0x0,
            "Service States in Termination State Descriptor", HFILL }},
        { &hf_megaco_signal_descriptor,
          { "Signal Descriptor", "megaco.signal", FT_STRING, BASE_NONE, NULL, 0x0,
            "Signal Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_statistics_descriptor,
          { "Statistics Descriptor", "megaco.statistics", FT_STRING, BASE_NONE, NULL, 0x0,
            "Statistics Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_streamid,
          { "StreamID", "megaco.streamid", FT_STRING, BASE_NONE, NULL, 0x0,
            "StreamID in the Media Descriptor", HFILL }},
        { &hf_megaco_termid,
          { "Termination ID", "megaco.termid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Termination ID of this Command", HFILL }},
        { &hf_megaco_TerminationState_descriptor,
          { "Termination State Descriptor", "megaco.terminationstate", FT_STRING, BASE_NONE, NULL, 0x0,
            "Termination State Descriptor in Media Descriptor", HFILL }},
        { &hf_megaco_topology_descriptor,
          { "Topology Descriptor", "megaco.topology", FT_STRING, BASE_NONE, NULL, 0x0,
            "Topology Descriptor of the megaco Command", HFILL }},
        { &hf_megaco_transaction,
          { "Transaction", "megaco.transaction", FT_STRING, BASE_NONE, NULL, 0x0,
            "Message Originator", HFILL }},
        { &hf_megaco_transid,
          { "Transaction ID", "megaco.transid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Transaction ID of this message", HFILL }},
        { &hf_megaco_mId,
          { "MediagatewayID", "megaco.mId", FT_STRING, BASE_NONE, NULL, 0x0,
            "Mediagateway ID", HFILL }},
        { &hf_megaco_version,
          { "Version", "megaco.version", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_megaco_h245,
          { "h245", "megaco.h245", FT_STRING, BASE_NONE, NULL, 0x0,
            "Embedded H.245 message", HFILL }},
        { &hf_megaco_h223Capability,
          { "h223Capability", "megaco.h245.h223Capability", FT_NONE, BASE_NONE, NULL, 0,
            "megaco.h245.H223Capability", HFILL }},

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
        &ett_megaco_mediadescriptor,
        &ett_megaco_TerminationState,
        &ett_megaco_Remotedescriptor,
        &ett_megaco_Localdescriptor,
        &ett_megaco_LocalControldescriptor,
        &ett_megaco_auditdescriptor,
        &ett_megaco_eventsdescriptor,
        &ett_megaco_observedeventsdescriptor,
        &ett_megaco_observedevent,
        &ett_megaco_packagesdescriptor,
        &ett_megaco_requestedevent,
        &ett_megaco_signalsdescriptor,
        &ett_megaco_requestedsignal,
        &ett_megaco_h245,
        GCP_ETT_ARR_ELEMS(megaco_ctx_ids),
    };

    module_t *megaco_module;

    proto_megaco = proto_register_protocol("MEGACO",
                                           "MEGACO", "megaco");

    register_dissector("megaco", dissect_megaco_text, proto_megaco);

    proto_register_field_array(proto_megaco, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register our configuration options, particularly our ports */

    megaco_module = prefs_register_protocol(proto_megaco, proto_reg_handoff_megaco);

    prefs_register_uint_preference(megaco_module, "tcp.txt_port",
                                   "MEGACO Text TCP Port",
                                   "Set the TCP port for MEGACO text messages",
                                   10, &global_megaco_txt_tcp_port);

    prefs_register_uint_preference(megaco_module, "udp.txt_port",
                                   "MEGACO Text UDP Port",
                                   "Set the UDP port for MEGACO text messages",
                                   10, &global_megaco_txt_udp_port);

#if 0
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
                                   "Mantain relationships between transactions and contexts "
                                   "and display an extra tree showing context data",
                                   &keep_persistent_data);

    megaco_tap = register_tap("megaco");

}

/* Register all the bits needed with the filtering engine */
/* The registration hand-off routine */
void
proto_reg_handoff_megaco(void)
{
    static gboolean megaco_prefs_initialized = FALSE;
    static dissector_handle_t megaco_text_tcp_handle;
    /*
    * Variables to allow for proper deletion of dissector registration when
    * the user changes port from the gui.
    */
    static guint txt_tcp_port;
    static guint txt_udp_port;
#if 0
    static guint bin_tcp_port;
    static guint bin_udp_port;
#endif

    if (!megaco_prefs_initialized) {
        sdp_handle = find_dissector("sdp");
        h245_handle = find_dissector("h245dg");
        h248_handle = find_dissector("h248");
        h248_otp_handle = find_dissector("h248_otp");
        data_handle = find_dissector("data");

        megaco_text_handle = find_dissector("megaco");
        megaco_text_tcp_handle = create_dissector_handle(dissect_megaco_text_tcp, proto_megaco);

        dissector_add_uint("sctp.ppi", H248_PAYLOAD_PROTOCOL_ID,   megaco_text_handle);

        megaco_prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", txt_tcp_port, megaco_text_tcp_handle);
        dissector_delete_uint("udp.port", txt_udp_port, megaco_text_handle);
    }

    /* Set our port number for future use */

    txt_tcp_port = global_megaco_txt_tcp_port;
    txt_udp_port = global_megaco_txt_udp_port;

    dissector_add_uint("tcp.port", global_megaco_txt_tcp_port, megaco_text_tcp_handle);
    dissector_add_uint("udp.port", global_megaco_txt_udp_port, megaco_text_handle);

}

