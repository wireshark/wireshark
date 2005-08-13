/* packet-jxta.c
 * Routines for JXTA packet dissection
 * Copyright 2004-05, Mike Duigou <bondolo@jxta.org>
 * Heavily based on packet-jabber.c, which in turn is heavily based on 
 * on packet-acap.c, which in turn is heavily based on 
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c, packet-jabber.c, packet-udp.c
 *
 * JXTA specification from http://spec.jxta.org
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
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-jxta.h"

static const gchar JXTA_UDP_SIG[] = { 'J', 'X', 'T', 'A' };
static const gchar JXTA_MSG_SIG[] = { 'j', 'x', 'm', 'g' };
static const gchar JXTA_MSGELEM_SIG[] = { 'j', 'x', 'e', 'l' };

static const gchar JXTA_WELCOME_MSG_SIG[] = { 'J', 'X', 'T', 'A', 'H', 'E', 'L', 'L', 'O', ' ' };

static int proto_jxta = -1;
static int proto_welcome_jxta = -1;
static int proto_udp_jxta = -1;
static int proto_framing_jxta = -1;
static int proto_message_jxta = -1;
static int jxta_tap = -1;

static dissector_table_t media_type_dissector_table = NULL;
static dissector_handle_t tcp_jxta_handle = NULL;

static int hf_jxta_udpsig = -1;
static int hf_jxta_welcome_initiator = -1;
static int hf_jxta_welcome_sig = -1;
static int hf_jxta_welcome_destAddr = -1;
static int hf_jxta_welcome_pubAddr = -1;
static int hf_jxta_welcome_peerid = -1;
static int hf_jxta_welcome_noProp = -1;
static int hf_jxta_welcome_version = -1;
static int hf_jxta_framing_header = -1;
static int hf_jxta_framing_header_name = -1;
static int hf_jxta_framing_header_value_length = -1;
static int hf_jxta_framing_header_value = -1;
static int hf_jxta_message_address = -1;
static int hf_jxta_message_src = -1;
static int hf_jxta_message_dst = -1;
static int hf_jxta_message_sig = -1;
static int hf_jxta_message_version = -1;
static int hf_jxta_message_namespaces_count = -1;
static int hf_jxta_message_namespace_name = -1;
static int hf_jxta_message_element_count = -1;
static int hf_jxta_element = -1;
static int hf_jxta_element_sig = -1;
static int hf_jxta_element_namespaceid = -1;
static int hf_jxta_element_flags = -1;
static int hf_jxta_element_flag_hasType = -1;
static int hf_jxta_element_flag_hasEncoding = -1;
static int hf_jxta_element_flag_hasSignature = -1;
static int hf_jxta_element_name = -1;
static int hf_jxta_element_type = -1;
static int hf_jxta_element_encoding = -1;
static int hf_jxta_element_content_len = -1;
static int hf_jxta_element_content = -1;
static int hf_jxta_element_content_text = -1;

/** our header fields */
static hf_register_info hf[] = {
    {&hf_jxta_udpsig,
     {"Signature", "jxta.udpsig", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA UDP Signature", HFILL}
     },
    {&hf_jxta_welcome_initiator,
     {"Initiator", "jxta.welcome.initiator", FT_BOOLEAN, BASE_NONE, NULL, 0x00,
      "JXTA Connection Welcome Message Initiator", HFILL}
     },
    {&hf_jxta_welcome_sig,
     {"Signature", "jxta.welcome.signature", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message Signature", HFILL}
     },
    {&hf_jxta_welcome_destAddr,
     {"Destination Address", "jxta.welcome.destAddr", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message Destination Address", HFILL}
     },
    {&hf_jxta_welcome_pubAddr,
     {"Public Address", "jxta.welcome.pubAddr", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message Public Address", HFILL}
     },
    {&hf_jxta_welcome_peerid,
     {"PeerID", "jxta.welcome.peerid", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message PeerID", HFILL}
     },
    {&hf_jxta_welcome_noProp,
     {"No Propagate Flag", "jxta.welcome.noPropFlag", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message No Propagate Flag", HFILL}
     },
    {&hf_jxta_welcome_version,
     {"Version", "jxta.welcome.version", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message Version", HFILL}
     },
    {&hf_jxta_framing_header,
     {"Header", "jxta.framing.header", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA Message Framing Header", HFILL}
     },
    {&hf_jxta_framing_header_name,
     {"Name", "jxta.framing.header.name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Framing Header Name", HFILL}
     },
    {&hf_jxta_framing_header_value_length,
     {"Value Length", "jxta.framing.header.valuelen", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Framing Header Value Length", HFILL}
     },
    {&hf_jxta_framing_header_value,
     {"Value", "jxta.framing.header.value", FT_BYTES, BASE_HEX, NULL, 0x0,
      "JXTA Message Framing Header Value", HFILL}
     },
    {&hf_jxta_message_address,
     {"Address", "jxta.message.address", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Address (source or destination)", HFILL}
     },
    {&hf_jxta_message_src,
     {"Source", "jxta.message.source", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Source", HFILL}
     },
    {&hf_jxta_message_dst,
     {"Destination", "jxta.message.destination", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Destination", HFILL}
     },
    {&hf_jxta_message_sig,
     {"Signature", "jxta.message.signature", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Signature", HFILL}
     },
    {&hf_jxta_message_version,
     {"Version", "jxta.message.version", FT_UINT8, BASE_DEC, NULL, 0x0,
      "JXTA Message Version", HFILL}
     },
    {&hf_jxta_message_namespaces_count,
     {"Namespace Count", "jxta.message.namespaces", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Namespaces", HFILL}
     },
    {&hf_jxta_message_namespace_name,
     {"Namespace Name", "jxta.message.namespace.name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Namespace Name", HFILL}
     },
    {&hf_jxta_message_element_count,
     {"Element Count", "jxta.message.elements", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Count", HFILL}
     },
    {&hf_jxta_element,
     {"JXTA Message Element", "jxta.message.element", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA Message Element", HFILL}
     },
    {&hf_jxta_element_sig,
     {"Signature", "jxta.message.element.signature", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Signature", HFILL}
     },
    {&hf_jxta_element_namespaceid,
     {"Namespace ID", "jxta.message.element.namespaceid", FT_UINT8, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Namespace ID", HFILL}
     },
    {&hf_jxta_element_flags,
     {"Flags", "jxta.message.element.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
      "JXTA Message Element Flags", HFILL}
     },
    {&hf_jxta_element_flag_hasType,
     {"hasType", "jxta.message.element.flags.hasType", FT_BOOLEAN, 3, TFS(&flags_set_truth), 0x01,
      "JXTA Message Element Flag -- hasType", HFILL}
     },
    {&hf_jxta_element_flag_hasEncoding,
     {"hasEncoding", "jxta.message.element.flags.hasEncoding", FT_BOOLEAN, 3, TFS(&flags_set_truth), 0x02,
      "JXTA Message Element Flag -- hasEncoding", HFILL}
     },
    {&hf_jxta_element_flag_hasSignature,
     {"hasSignature", "jxta.message.element.flags.hasSignature", FT_BOOLEAN, 3, TFS(&flags_set_truth), 0x04,
      "JXTA Message Element Flag -- hasSignature", HFILL}
     },
    {&hf_jxta_element_name,
     {"Element Name", "jxta.message.element.name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Name", HFILL}
     },
    {&hf_jxta_element_type,
     {"Element Type", "jxta.message.element.type", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Name", HFILL}
     },
    {&hf_jxta_element_encoding,
     {"Element Type", "jxta.message.element.encoding", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Encoding", HFILL}
     },
    {&hf_jxta_element_content_text,
     {"Element Content", "jxta.message.element.text_content", FT_UINT_STRING, BASE_HEX, NULL, 0x0,
      "JXTA Message Element Text Content", HFILL}
     },
    {&hf_jxta_element_content_len,
     {"Element Content Length", "jxta.message.element.content.length", FT_UINT32, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Content Length", HFILL}
     },
    {&hf_jxta_element_content,
     {"Element Content", "jxta.message.element.content", FT_BYTES, BASE_HEX, NULL, 0x0,
      "JXTA Message Element Content", HFILL}
     },
};

/**
*    JXTA Protocol subtree handles
**/
static gint ett_jxta_welcome = -1;
static gint ett_jxta_udp = -1;
static gint ett_jxta_framing = -1;
static gint ett_jxta_framing_header = -1;
static gint ett_jxta_msg = -1;
static gint ett_jxta_elem = -1;
static gint ett_jxta_elem_flags = -1;

/** 
*   JXTA Protocol subtree array
**/
static gint *const ett[] = {
    &ett_jxta_welcome,
    &ett_jxta_udp,
    &ett_jxta_framing,
    &ett_jxta_framing_header,
    &ett_jxta_msg,
    &ett_jxta_elem,
    &ett_jxta_elem_flags
};

/** 
*   global preferences
**/
static gboolean gDESEGMENT = TRUE;
static gboolean gUDP_HEUR = FALSE;
static gboolean gTCP_HEUR = FALSE;

/**
*   Stream Conversation data
**/
struct jxta_stream_conversation_data {
    port_type tpt_ptype;
    guint32 initiator_welcome_frame;
    address initiator_tpt_address;
    guint32 initiator_tpt_port;
    address initiator_address;
    guint32 receiver_welcome_frame;
    address receiver_tpt_address;
    guint32 receiver_tpt_port;
    address receiver_address;
};

typedef struct jxta_stream_conversation_data jxta_stream_conversation_data;

/**
*   Prototypes
**/
static gboolean dissect_jxta_UDP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);
static gboolean dissect_jxta_TCP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

static int dissect_jxta_udp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);
static int dissect_jxta_tcp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

static int dissect_jxta_welcome(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, address * found_addr, gboolean initiator);
static int dissect_jxta_message_framing(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint64 * content_length,
                                        gchar **content_type);
static int dissect_jxta_message(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);
static int dissect_jxta_message_element(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint ns_count,
                                        const gchar **namespaces);

void proto_reg_handoff_jxta(void);
void proto_reg_handoff_message_jxta(void);

/**
*   Heuristically dissect a tvbuff containing a JXTA UDP Message
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return TRUE if the tvb contained JXTA data which was dissected otherwise FALSE
**/
static gboolean dissect_jxta_UDP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!gUDP_HEUR)
        return FALSE;

    if (tvb_memeql(tvb, 0, JXTA_UDP_SIG, sizeof(JXTA_UDP_SIG)) != 0) {
        return FALSE;
    }

    return dissect_jxta_udp(tvb, pinfo, tree) > 0;
}

/**
*   Heuristically dissect a tvbuff containing a JXTA TCP Stream
*    
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return TRUE if the tvb contained JXTA data which was dissected otherwise FALSE
**/
static gboolean dissect_jxta_TCP_heur(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    /* This is a heuristic dissector, which means we get all the TCP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!gTCP_HEUR)
        return FALSE;

    if (tvb_memeql(tvb, 0, JXTA_WELCOME_MSG_SIG, sizeof(JXTA_WELCOME_MSG_SIG)) != 0) {
        return FALSE;
    }

    return dissect_jxta_tcp(tvb, pinfo, tree) > 0;
}

/**
*   Dissect a tvbuff containing a JXTA UDP header, JXTA Message framing and a JXTA Message
*    
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return number of bytes from the tvbuff_t which were processed.
**/
static int dissect_jxta_udp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    guint offset = 0;
    guint available;
    gint needed = 0;

    conversation_t *conversation =
        find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

    if (conversation == NULL) {
        /*
         * No conversation exists yet - create one.
         */
        conversation =
            conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    }

    DISSECTOR_ASSERT(find_dissector("jxta.udp"));

    conversation_set_dissector(conversation, find_dissector("jxta.udp"));

    while (TRUE) {
        tvbuff_t *jxta_message_framing_tvb;
        gint processed = 0;
        guint64 content_length = -1;

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(JXTA_UDP_SIG)) {
            needed = (gint) (available - sizeof(JXTA_UDP_SIG));
            break;
        }

        if (tvb_memeql(tvb, offset, JXTA_UDP_SIG, sizeof(JXTA_UDP_SIG)) != 0) {
            /* not ours */
            return 0;
        }

        offset += sizeof(JXTA_UDP_SIG);

        jxta_message_framing_tvb = tvb_new_subset(tvb, offset, -1, -1);
        processed = dissect_jxta_message_framing(jxta_message_framing_tvb, pinfo, NULL, &content_length, NULL);

        if (0 == processed) {
            /* rejected! */
            return 0;
        }

        if (processed < 0) {
            needed = -processed;
            break;
        }

        offset += processed;

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < content_length) {
            needed = (gint) (available - content_length);
            break;
        }

        offset += (guint) content_length;

        break;
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");
    }

    if (tree) {
        guint tree_offset = 0;
        proto_item *jxta_udp_tree_item = proto_tree_add_protocol_format(tree, proto_udp_jxta, tvb, tree_offset, -1, "JXTA UDP Message" );
        proto_tree *jxta_udp_tree = proto_item_add_subtree(jxta_udp_tree_item, ett_jxta_udp);
        tvbuff_t *jxta_message_framing_tvb;
        guint64 content_length = -1;
        gchar *content_type = NULL;
        tvbuff_t *jxta_message_tvb;
        gboolean dissected = FALSE;
        gint processed = 0;
        dissector_handle_t mime_dissector_handle;

        proto_tree_add_item(jxta_udp_tree, hf_jxta_udpsig, tvb, tree_offset, sizeof(JXTA_UDP_SIG), FALSE);
        tree_offset += sizeof(JXTA_UDP_SIG);

        jxta_message_framing_tvb = tvb_new_subset(tvb, tree_offset, -1, -1);
        processed = dissect_jxta_message_framing(jxta_message_framing_tvb, pinfo, tree, &content_length, &content_type);
        tree_offset += processed;

        jxta_message_tvb = tvb_new_subset(tvb, tree_offset, (gint) content_length, (gint) content_length);
        mime_dissector_handle = dissector_get_string_handle(media_type_dissector_table, content_type);
        dissected = 0 < call_dissector(mime_dissector_handle, jxta_message_tvb, pinfo, tree);        

        if (!dissected) {
            dissector_handle_t data_handle = find_dissector("data");
            call_dissector(data_handle, jxta_message_tvb, pinfo, tree);
        }

        tree_offset += (guint) content_length;

        proto_item_set_end(jxta_udp_tree_item, tvb, tree_offset);

        DISSECTOR_ASSERT(offset == tree_offset);
    }
    
    return offset;
}

/**
*   Dissect a tvbuff containing JXTA TCP PDUs
*    
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return number of bytes from the tvbuff_t which were processed.
**/
static int dissect_jxta_tcp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    guint offset = 0;
    guint available = 0;
    gint processed;
    conversation_t *tpt_conversation =
        find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    jxta_stream_conversation_data * tpt_conv_data;

    if (tpt_conversation == NULL) {
        /*
         * No conversation exists yet - create one.
         */
        tpt_conversation =
            conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    }

    conversation_set_dissector(tpt_conversation, tcp_jxta_handle);
    
    tpt_conv_data = (jxta_stream_conversation_data*) conversation_get_proto_data(tpt_conversation, proto_jxta);
    
    if( NULL == tpt_conv_data ) {
        tpt_conv_data = se_alloc(sizeof( jxta_stream_conversation_data ));
        tpt_conv_data->tpt_ptype = PT_NONE;
        tpt_conv_data->initiator_welcome_frame = 0;
        tpt_conv_data->initiator_address.type = AT_NONE;
        tpt_conv_data->initiator_address.len = 0;
        tpt_conv_data->initiator_address.data = NULL;
        tpt_conv_data->receiver_welcome_frame = 0;
        tpt_conv_data->receiver_address.type = AT_NONE;
        tpt_conv_data->receiver_address.len = 0;
        tpt_conv_data->receiver_address.data = NULL;
        conversation_add_proto_data(tpt_conversation, proto_jxta, tpt_conv_data);
    }
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");
    }

    if (0 == tvb_memeql(tvb, 0, JXTA_WELCOME_MSG_SIG, sizeof(JXTA_WELCOME_MSG_SIG))) {
        address * welcome_addr;
        gboolean initiator = FALSE;

        if( 0 == tpt_conv_data->initiator_welcome_frame ) {
            tpt_conv_data->tpt_ptype= pinfo->ptype;
            tpt_conv_data->initiator_welcome_frame = pinfo->fd->num;
            COPY_ADDRESS( &tpt_conv_data->initiator_tpt_address, &pinfo->src );
            tpt_conv_data->initiator_tpt_port = pinfo->srcport;

            welcome_addr = &tpt_conv_data->initiator_address;
            initiator = TRUE;
        } else {
            if( tpt_conv_data->initiator_welcome_frame >= pinfo->fd->num ) {
                /* what we saw previously was the receiver welcome message */
                tpt_conv_data->receiver_welcome_frame = tpt_conv_data->initiator_welcome_frame;
                tpt_conv_data->receiver_tpt_address = tpt_conv_data->initiator_tpt_address;
                tpt_conv_data->receiver_tpt_port = tpt_conv_data->initiator_tpt_port;
                tpt_conv_data->receiver_address = tpt_conv_data->initiator_address;
                tpt_conv_data->initiator_welcome_frame = pinfo->fd->num;
                COPY_ADDRESS( &tpt_conv_data->initiator_tpt_address, &pinfo->src );
                tpt_conv_data->initiator_tpt_port = pinfo->srcport;

                welcome_addr = &tpt_conv_data->initiator_address;
                initiator = TRUE;
            } else {
                tpt_conv_data->tpt_ptype= pinfo->ptype;
                tpt_conv_data->receiver_welcome_frame = pinfo->fd->num;
                COPY_ADDRESS( &tpt_conv_data->receiver_tpt_address, &pinfo->src );
                tpt_conv_data->receiver_tpt_port = pinfo->srcport;

                welcome_addr = &tpt_conv_data->receiver_address;
                initiator = FALSE;
            }
        }

        processed = dissect_jxta_welcome(tvb, pinfo, tree, welcome_addr, initiator);
    } else {
        guint64 content_length = 0;
        gchar *content_type = NULL;
        gboolean dissected;
        conversation_t *peer_conversation = NULL;
        address saved_src_addr;
        guint32 saved_src_port = 0;
        address saved_dst_addr;
        guint32 saved_dst_port = 0;
        port_type saved_port_type = PT_NONE;

        if( (AT_NONE != tpt_conv_data->initiator_address.type) && (AT_NONE != tpt_conv_data->receiver_address.type) ) {
            peer_conversation =
                find_conversation(pinfo->fd->num, &tpt_conv_data->initiator_address, &tpt_conv_data->receiver_address, PT_NONE, 0, 0, NO_PORT_B);

            if( NULL == peer_conversation ) {
                peer_conversation =
                    conversation_new(pinfo->fd->num, &tpt_conv_data->initiator_address, &tpt_conv_data->receiver_address, PT_NONE, 0, 0, NO_PORT_B);
            }

            conversation_set_dissector(peer_conversation, tcp_jxta_handle);
        } else {
/*            g_warning( "Uninitialized peer conversation" ); */
        }

        /* Use our source and destination addresses if we have them */
        if( NULL != peer_conversation ) {
             saved_src_addr = pinfo->src;
             saved_src_port = pinfo->srcport;
             saved_dst_addr = pinfo->dst;
             saved_dst_port = pinfo->destport;
             saved_port_type = pinfo->ptype;
/*                 g_warning( "%d Tpt %s:%d -> %s:%d", pinfo->fd->num, ip_to_str(tpt_conv_data->initiator_tpt_address.data), tpt_conv_data->initiator_tpt_port, ip_to_str(tpt_conv_data->receiver_tpt_address.data), tpt_conv_data->receiver_tpt_port ); */
             if( ADDRESSES_EQUAL( &pinfo->src, &tpt_conv_data->initiator_tpt_address ) && 
                tpt_conv_data->initiator_tpt_port == pinfo->srcport ) {
/*                    g_warning( "%d From initiator : %s -> %s ", pinfo->fd->num, tpt_conv_data->initiator_address.data, tpt_conv_data->receiver_address.data ); */
                 pinfo->src = tpt_conv_data->initiator_address;
                 pinfo->dst = tpt_conv_data->receiver_address;
             } else if( ADDRESSES_EQUAL( &pinfo->src, &tpt_conv_data->receiver_tpt_address ) && 
                 tpt_conv_data->receiver_tpt_port == pinfo->srcport ) {
/*                    g_warning( "%d From receiver : %s -> %s ", pinfo->fd->num, tpt_conv_data->receiver_address.data, tpt_conv_data->initiator_address.data ); */
                 pinfo->src = tpt_conv_data->receiver_address;
                 pinfo->dst = tpt_conv_data->initiator_address;
             } else {
/*                    g_warning( "%d Nothing matches %s:%d -> %s:%d", pinfo->fd->num, ip_to_str(pinfo->src.data), pinfo->srcport, ip_to_str(pinfo->dst.data), pinfo->destport ); */
             }
             /* JXTA doesn't use ports */
             pinfo->ptype = PT_NONE;
             pinfo->srcport = 0;
             pinfo->destport = 0;
        }

        processed = dissect_jxta_message_framing(tvb, pinfo, tree, &content_length, &content_type);

        if ((processed > 0) && (NULL != content_type) && (0 != content_length)) {
            guint msg_offset = offset + processed;

            available = tvb_reported_length_remaining(tvb, msg_offset);
            if (available >= content_length) {
                tvbuff_t *jxta_message_tvb = tvb_new_subset(tvb, msg_offset, (gint)content_length, (gint)content_length);

                dissected = dissector_try_string(media_type_dissector_table, content_type, jxta_message_tvb, pinfo, tree);

                if (!dissected) {
                    dissector_handle_t data_handle = find_dissector("data");
                    call_dissector(data_handle, jxta_message_tvb, pinfo, tree);
                }

                processed += (guint) content_length;
            } else {
                processed = available - (guint) content_length;
            }

        }

        /* Restore the saved src and dst addresses */
        if( NULL != peer_conversation ) {
            pinfo->src = saved_src_addr;
            pinfo->srcport = saved_src_port;
            pinfo->dst = saved_dst_addr;
            pinfo->destport = saved_dst_port;
            pinfo->ptype = saved_port_type;
        }
    }

    if (processed <= 0) {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = -processed;
        return processed;
    }

    offset += processed;

    return offset;
}

/**
*   Dissect a tvbuff containing a JXTA Welcome Message
*
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @param  found_addr The address found in the welcome message.
*   @param  initiator If TRUE then we believe this welcome message to be the initiator's.
*   @return number of bytes from the tvbuff_t which were processed.
**/
static int dissect_jxta_welcome(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, address *found_addr, gboolean initiator )
{
    guint offset = 0;
    gint afterwelcome;
    gint first_linelen;
    guint available = tvb_reported_length_remaining(tvb, offset);

    if (available < sizeof(JXTA_WELCOME_MSG_SIG)) {
        return (gint) (available - sizeof(JXTA_WELCOME_MSG_SIG));
    }

    if (0 != tvb_memeql(tvb, 0, JXTA_WELCOME_MSG_SIG, sizeof(JXTA_WELCOME_MSG_SIG))) {
        /* not ours! */
        return 0;
    }

    first_linelen = tvb_find_line_end(tvb, offset, -1, &afterwelcome, gDESEGMENT && pinfo->can_desegment);

    if (-1 == first_linelen) {
        if (available > 4096) {
            /* it's too far too be reasonable */
            return 0;
        } else {
            /* ask for more bytes */
            return -1;
        }
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_str(pinfo->cinfo, COL_INFO, "Welcome");
    }

    {
        gchar * welcomeline = tvb_get_ephemeral_string( tvb, offset, first_linelen );
        gchar** tokens = g_strsplit( welcomeline, " ", 6 );
        gchar** current_token = tokens;
        guint token_offset = offset;
        proto_item *jxta_welcome_tree_item = NULL;
        proto_tree *jxta_welcome_tree = NULL;  

        if (tree) {
           jxta_welcome_tree_item = proto_tree_add_protocol_format(tree, proto_welcome_jxta, tvb, offset, afterwelcome, "JXTA Connection Welcome Message, %s", welcomeline);
           jxta_welcome_tree = proto_item_add_subtree(jxta_welcome_tree_item, ett_jxta_welcome);
           }
        
        if( jxta_welcome_tree ) {
            proto_item *jxta_welcome_initiator_item = proto_tree_add_boolean(jxta_welcome_tree, hf_jxta_welcome_initiator, tvb, 0, 0, initiator);
            PROTO_ITEM_SET_GENERATED(jxta_welcome_initiator_item);
            }

        if( NULL != *current_token ) {
            if( jxta_welcome_tree ) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_sig, tvb, token_offset, strlen( *current_token ), FALSE);
            }

            token_offset += strlen( *current_token ) + 1;
            current_token++;
            }

        if( NULL != *current_token ) {
            if( jxta_welcome_tree ) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_destAddr, tvb, token_offset, strlen( *current_token ), FALSE);
            }

            token_offset += strlen( *current_token ) + 1;
            current_token++;
            }

        if( NULL != *current_token ) {
            if( jxta_welcome_tree ) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_pubAddr, tvb, token_offset, strlen( *current_token ), FALSE);
            }

            token_offset += strlen( *current_token ) + 1;
            current_token++;
            }

        if( NULL != *current_token ) {
            if( jxta_welcome_tree ) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_peerid, tvb, token_offset, strlen( *current_token ), FALSE);
            }

            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_str( pinfo->cinfo, COL_INFO, ", " );
                col_append_str( pinfo->cinfo, COL_INFO, *current_token );
            }

            if( NULL != found_addr ) {
                found_addr->type = AT_URI;
                found_addr->len = strlen( *current_token );
                /* FIXME 20050605 bondolo THIS ALLOCATION IS A MEMORY LEAK! */
                found_addr->data = g_strdup( *current_token );
            }

            token_offset += strlen( *current_token ) + 1;
            current_token++;
            }

        if( NULL != *current_token ) {
            if( jxta_welcome_tree ) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_noProp, tvb, token_offset, strlen( *current_token ), FALSE);
            }

            token_offset += strlen( *current_token ) + 1;
            current_token++;
            }

        if( NULL != *current_token ) {
            if( jxta_welcome_tree ) {
                proto_tree_add_item(jxta_welcome_tree, hf_jxta_welcome_version, tvb, token_offset, strlen( *current_token ), FALSE);
            }
            token_offset += strlen( *current_token ) + 1;
            current_token++;
            }

        g_strfreev(tokens);
    }

    col_set_writable(pinfo->cinfo, FALSE);

    return afterwelcome;
}

/**
*   Dissect a tvbuff containing JXTA Message framing.
*    
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return number of bytes from the tvbuff_t which were processed.
**/
static int dissect_jxta_message_framing(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint64 * content_length,
                                        gchar **content_type)
{
    guint offset = 0;
    guint available;
    gint needed = 0;

    /*
     *   First go around. Make sure all of the bytes are there.
     */
    do {
        guint8 headername_len;
        guint8 headername_offset;
        guint16 headervalue_len;
        guint16 headervalue_offset;

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint8)) {
            needed = (gint) (available - sizeof(guint8));
            break;
        } else {
            headername_len = tvb_get_guint8(tvb, offset);
            offset += sizeof(guint8);
            headername_offset = offset;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < headername_len) {
                needed = (gint) (available - headername_len);
                break;
            }

            if (0 == headername_len) {
                break;
            }
            offset += headername_len;
        }

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint16)) {
            needed = (gint) (available - sizeof(guint16));
            break;
        } else {
            headervalue_len = tvb_get_ntohs(tvb, offset);
            offset += sizeof(guint16);
            headervalue_offset = offset;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < headervalue_len) {
                needed = (gint) (available - headervalue_len);
                break;
            }

            offset += headervalue_len;
        }

        if (content_type && (sizeof("content-type") - 1) == headername_len) {
            if (0 == tvb_strncaseeql(tvb, headername_offset, "content-type", sizeof("content-type") - 1)) {
                *content_type = tvb_get_ephemeral_string(tvb, headervalue_offset, headervalue_len);
            }
        }


        if (content_length && (sizeof(guint64) == headervalue_len) && ((sizeof("content-length") - 1) == headername_len)) {
            if (0 == tvb_strncaseeql(tvb, headername_offset, "content-length", sizeof("content-length") - 1)) {
                *content_length = tvb_get_ntoh64(tvb, headervalue_offset);
            }
        }
    } while (TRUE);

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    /*
     *   Second (optional pass) Now that we are sure that all the bytes are there we update the protocol tree.
     */
    if (tree) {
        guint tree_offset = 0;
        proto_item *framing_tree_item = proto_tree_add_protocol_format(tree, proto_framing_jxta, tvb, tree_offset, -1, "JXTA Message Framing Headers");
        proto_tree *framing_tree = proto_item_add_subtree(framing_tree_item, ett_jxta_framing);

        /* parse framing headers */
        do {
            guint8 headernamelen = tvb_get_guint8(tvb, tree_offset);
            proto_item *framing_header_tree_item =
                proto_tree_add_item(framing_tree, hf_jxta_framing_header, tvb, tree_offset, -1, FALSE);
            proto_tree *framing_header_tree = proto_item_add_subtree(framing_header_tree_item, ett_jxta_framing_header);

            /*
             *   Put header name into the protocol tree
             */
            proto_tree_add_item(framing_header_tree, hf_jxta_framing_header_name, tvb, tree_offset, 1, headernamelen);

            /*
             *   Append header name into the header protocol item. It's a nice hint so you don't have to reveal all headers.
             */
            if (headernamelen > 0) {
                proto_item_append_text(framing_header_tree_item, " \"%s\"",
                                       tvb_format_text(tvb, tree_offset + sizeof(guint8), headernamelen));
            }

            tree_offset += sizeof(guint8) + headernamelen;

            if (headernamelen > 0) {
                guint16 headervaluelen = tvb_get_ntohs(tvb, tree_offset);

                if (tree) {
                    proto_tree_add_uint(framing_header_tree, hf_jxta_framing_header_value_length, tvb, tree_offset,
                                        sizeof(guint16), headervaluelen);

                /** TODO bondolo Add specific handling for known header types */

                    /*
                     * Put header value into protocol tree.
                     */
                    proto_tree_add_item(framing_header_tree, hf_jxta_framing_header_value, tvb, tree_offset + sizeof(guint16),
                                        headervaluelen, FALSE);
                }

                tree_offset += sizeof(guint16) + headervaluelen;
            }

            proto_item_set_end(framing_header_tree_item, tvb, tree_offset);

            if (0 == headernamelen) {
                break;
            }
        } while (TRUE);

        proto_item_set_end(framing_tree_item, tvb, tree_offset);

        DISSECTOR_ASSERT(offset == tree_offset);
    }

    /* return how many bytes we used up. */
    return offset;
}

/**
*   Dissect a tvbuff containing a JXTA Message.
*    
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return number of bytes from the tvbuff_t which were processed.
**/
static int dissect_jxta_message(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    guint offset = 0;
    guint available;
    gint needed = 0;

    while (TRUE) {
        /* First pass. Make sure all of the bytes we need are available */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(JXTA_MSG_SIG)) {
            needed = (gint) (available - sizeof(JXTA_MSG_SIG));
            break;
        }

        if (tvb_memeql(tvb, offset, JXTA_MSG_SIG, sizeof(JXTA_MSG_SIG)) != 0) {
            /* It is not one of ours */
            return 0;
        }

        offset += sizeof(JXTA_MSG_SIG);

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint8)) {
            needed = (gint) (available - sizeof(guint8));
            break;
        } else {
            guint8 message_version = tvb_get_guint8(tvb, offset);

            offset += sizeof(guint8);

            if (0 != message_version) {
                /* Sort of a lie, we say that we don't recognize it at all. */
                return 0;
            }
        }

        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint16)) {
            needed = (gint) (available - sizeof(guint16));
            break;
        } else {
            guint16 msg_ns_count = tvb_get_ntohs(tvb, offset);
            guint each_namespace;

            offset += sizeof(guint16);

            for (each_namespace = 0; each_namespace < msg_ns_count; each_namespace++) {
                guint16 namespace_len;

                available = tvb_reported_length_remaining(tvb, offset);
                if (available < sizeof(namespace_len)) {
                    needed = (gint) (available - sizeof(namespace_len));
                    break;
                }

                namespace_len = tvb_get_ntohs(tvb, offset);

                available = tvb_reported_length_remaining(tvb, offset + sizeof(namespace_len));
                if (available < namespace_len) {
                    needed = (gint) (available - namespace_len);
                    break;
                }

                offset += sizeof(namespace_len) + namespace_len;
            }
        }

        /* parse element count */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint16)) {
            needed = (gint) (available - sizeof(guint16));
            break;
        } else {
            guint16 elem_count = tvb_get_ntohs(tvb, offset);
            guint each_elem;

            offset += sizeof(guint16);

            /* parse elements */

            for (each_elem = 0; each_elem < elem_count; each_elem++) {
                tvbuff_t *jxta_message_element_tvb = tvb_new_subset(tvb, offset, -1, -1);
                int processed = dissect_jxta_message_element(jxta_message_element_tvb, pinfo, NULL, 0, NULL);

                if (processed < 0) {
                    needed = -processed;
                    break;
                }
                
                if( 0 == processed ) {
                    /* XXX bondolo Not really clear what we should do! */
/*                    g_warning( "Failure processing message element #%d of %d of frame %d", each_elem, elem_count, pinfo->fd->num ); */
                    return 0;
                }

                offset += processed;
            }
        }

        break;
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        gchar src_addr[256];
        gchar dst_addr[256];
     
        address_to_str_buf( &pinfo->src, src_addr, sizeof src_addr );
        address_to_str_buf( &pinfo->dst, dst_addr, sizeof dst_addr );
        
        if( PT_NONE != pinfo->ptype ) {
           size_t len = strlen( src_addr );
           src_addr[len] = ':';
           g_snprintf( &src_addr[len+1], 256 - len - 1, "%d", pinfo->srcport );

           len = strlen( dst_addr );
           dst_addr[len] = ':';
           g_snprintf( &dst_addr[len+1], 256 - len - 1, "%d", pinfo->destport );
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Message, %s -> %s", src_addr, dst_addr );

        col_set_writable(pinfo->cinfo, FALSE);
    }

    if (tree) {
        guint tree_offset = 0;
        proto_item *jxta_msg_tree_item = NULL;
        proto_tree *jxta_msg_tree = NULL;
        guint8 message_version;
        const gchar **namespaces = NULL;
        guint16 msg_ns_count;
        guint each_namespace;
        guint16 elem_count;
        guint each_elem;
        gchar src_addr[256];
        gchar dst_addr[256];
        proto_item * tree_item;
        
        address_to_str_buf( &pinfo->src, src_addr, sizeof src_addr );
        address_to_str_buf( &pinfo->dst, dst_addr, sizeof dst_addr );
        
        if( PT_NONE != pinfo->ptype ) {
           size_t len = strlen( src_addr );
           src_addr[len] = ':';
           g_snprintf( &src_addr[len+1], 256 - len - 1, "%d", pinfo->srcport );

           len = strlen( dst_addr );
           dst_addr[len] = ':';
           g_snprintf( &dst_addr[len+1], 256 - len - 1, "%d", pinfo->destport );
        }

        jxta_msg_tree_item = proto_tree_add_protocol_format(tree, proto_message_jxta, tvb, tree_offset, -1,
	    "JXTA Message, %s -> %s", src_addr, dst_addr );

        jxta_msg_tree = proto_item_add_subtree(jxta_msg_tree_item, ett_jxta_msg);

        proto_tree_add_item(jxta_msg_tree, hf_jxta_message_sig, tvb, tree_offset, sizeof(JXTA_MSG_SIG), FALSE);
        tree_offset += sizeof(JXTA_MSG_SIG);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_src, tvb, 0, 0, src_addr);
        PROTO_ITEM_SET_GENERATED(tree_item);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_address, tvb, 0, 0, src_addr);
        PROTO_ITEM_SET_HIDDEN(tree_item);
        PROTO_ITEM_SET_GENERATED(tree_item);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_dst, tvb, 0, 0, dst_addr);
        PROTO_ITEM_SET_GENERATED(tree_item);

        tree_item = proto_tree_add_string(jxta_msg_tree, hf_jxta_message_address, tvb, 0, 0, dst_addr);
        PROTO_ITEM_SET_HIDDEN(tree_item);
        PROTO_ITEM_SET_GENERATED(tree_item);

        message_version = tvb_get_guint8(tvb, tree_offset);
        proto_tree_add_uint(jxta_msg_tree, hf_jxta_message_version, tvb, tree_offset, sizeof(guint8), message_version);
        tree_offset += sizeof(guint8);

        msg_ns_count = tvb_get_ntohs(tvb, tree_offset);
        proto_tree_add_uint(jxta_msg_tree, hf_jxta_message_namespaces_count, tvb, tree_offset, sizeof(guint16), msg_ns_count);
        tree_offset += sizeof(guint16);

        namespaces = ep_alloc((msg_ns_count + 2) * sizeof(const gchar *));
        namespaces[0] = "";
        namespaces[1] = "jxta";

        /* parse namespaces */
        for (each_namespace = 0; each_namespace < msg_ns_count; each_namespace++) {
            guint16 namespace_len = tvb_get_ntohs(tvb, tree_offset);

            namespaces[2 + each_namespace] = tvb_get_ephemeral_string(tvb, tree_offset + sizeof(namespace_len), namespace_len);
            proto_tree_add_item(jxta_msg_tree, hf_jxta_message_namespace_name, tvb, tree_offset, sizeof(namespace_len), FALSE);
            tree_offset += sizeof(namespace_len) + namespace_len;
        }

        /* parse element count */
        elem_count = tvb_get_ntohs(tvb, tree_offset);
        proto_tree_add_item(jxta_msg_tree, hf_jxta_message_element_count, tvb, tree_offset, sizeof(guint16), FALSE);
        tree_offset += sizeof(guint16);

        /* parse elements */
        for (each_elem = 0; each_elem < elem_count; each_elem++) {
            tvbuff_t *jxta_message_element_tvb = tvb_new_subset(tvb, tree_offset, -1, -1);

            tree_offset +=
                dissect_jxta_message_element(jxta_message_element_tvb, pinfo, jxta_msg_tree, msg_ns_count + 2, namespaces);
        }

        proto_item_set_end(jxta_msg_tree_item, tvb, tree_offset);

        DISSECTOR_ASSERT(tree_offset == offset);              
    }

    if ((offset > 0) && (AT_URI == pinfo->src.type) && (AT_URI == pinfo->dst.type)) {
        jxta_tap_header * tap_header = se_alloc(sizeof( jxta_tap_header ));
        
        tap_header->src_address = pinfo->src;
        tap_header->dest_address = pinfo->dst;
        tap_header->size = offset;

        tap_queue_packet(jxta_tap, pinfo, tap_header);
    }

    return offset;
}

/**
*   Dissect a tvbuff containing a JXTA Message Element.
*    
*   @param  tvb The buffer to dissect.
*   @param  pinfo Packet Info.
*   @param  tree The protocol tree.
*   @return number of bytes from the tvbuff_t which were processed.
**/
static int dissect_jxta_message_element(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint ns_count,
                                        const gchar **namespaces)
{
    guint offset = 0;
    guint available;
    gint needed = 0;
    guint8 flags;

    /* First pass. Make sure all of the bytes we need are available */

    while (TRUE) {
         /* signature field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(JXTA_MSGELEM_SIG)) {
            needed = (gint) (available - sizeof(JXTA_MSGELEM_SIG));
        }

        if (tvb_memeql(tvb, offset, JXTA_MSGELEM_SIG, sizeof(JXTA_MSGELEM_SIG)) != 0) {
            /* It is not one of ours */
            return 0;
        }

        offset += sizeof(JXTA_MSGELEM_SIG);

        /* namespace id field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint8)) {
            needed = (gint) (available - sizeof(guint8));
            break;
        }

        offset += sizeof(guint8);

        /* flags field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint8)) {
            needed = (gint) (available - sizeof(guint8));
            break;
        } else {
            flags = tvb_get_guint8(tvb, offset);
            offset += sizeof(guint8);
        }

        /* name field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint16)) {
            needed = (gint) (available - sizeof(guint16));
            break;
        } else {
            guint16 name_len = tvb_get_ntohs(tvb, offset);
            offset += sizeof(guint16);

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < name_len) {
                needed = (gint) (available - name_len);
                break;
            }

            offset += name_len;
        }

        /* type field */
        if ((flags & 0x01) != 0) {
            guint16 type_len;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < sizeof(guint16)) {
                needed = (gint) (available - sizeof(guint16));
                break;
            }

            type_len = tvb_get_ntohs(tvb, offset);
            offset += sizeof(guint16);

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < type_len) {
                needed = (gint) (available - type_len);
                break;
            }

            offset += type_len;
        }

        /* encoding field */
        if ((flags & 0x02) != 0) {
            guint16 encoding_len;

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < sizeof(guint16)) {
                needed = (gint) (available - sizeof(guint16));
                break;
            }

            encoding_len = tvb_get_ntohs(tvb, offset);
            offset += sizeof(guint16);

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < encoding_len) {
                needed = (gint) (available - encoding_len);
                break;
            }

            offset += encoding_len;
        }

        /* content field */
        available = tvb_reported_length_remaining(tvb, offset);
        if (available < sizeof(guint16)) {
            needed = (gint) (available - sizeof(guint16));
            break;
        } else {
            guint32 content_len = tvb_get_ntohl(tvb, offset);
            offset += sizeof(guint32);

            available = tvb_reported_length_remaining(tvb, offset);
            if (available < content_len) {
                needed = (gint) (available - content_len);
                break;
            }

            offset += content_len;
        }

        /* signature element field */
        if ((flags & 0x04) != 0) {
            tvbuff_t *jxta_signature_element_tvb;
            int processed;

            jxta_signature_element_tvb = tvb_new_subset(tvb, offset, -1, -1);

            processed = dissect_jxta_message_element(jxta_signature_element_tvb, pinfo, NULL, 0, NULL);

            if (processed == 0) {
                return offset;
            }

            if (processed < 0) {
                needed = -processed;
                break;
            }

            offset += processed;
        }

        break;
    }

    if ((needed > 0) && gDESEGMENT && pinfo->can_desegment) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = needed;
        return -needed;
    }

    /* Second (optional) pass : build the proto tree */
    if (tree) {
        guint tree_offset = 0;
        proto_item *jxta_elem_tree_item = proto_tree_add_item(tree, hf_jxta_element, tvb, tree_offset, -1, FALSE);
        proto_tree *jxta_elem_tree = proto_item_add_subtree(jxta_elem_tree_item, ett_jxta_elem);
        guint8 namespaceID;
        proto_item *namespace_ti;
        guint16 name_len;
        proto_item *flags_ti;
        proto_tree *jxta_elem_flags_tree = NULL;
        guint32 content_len;
        gchar *mediatype = NULL;
        gboolean media_type_recognized = FALSE;
        tvbuff_t *element_content_tvb;

        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_sig, tvb, tree_offset, sizeof(JXTA_MSGELEM_SIG), FALSE);
        tree_offset += sizeof(JXTA_MSGELEM_SIG);

        namespaceID = tvb_get_guint8(tvb, tree_offset);
        namespace_ti =
            proto_tree_add_uint(jxta_elem_tree, hf_jxta_element_namespaceid, tvb, tree_offset, sizeof(guint8), namespaceID);
        if (namespaceID < ns_count) {
            proto_item_append_text(namespace_ti, " (%s)", namespaces[namespaceID]);
        } else {
            proto_item_append_text(namespace_ti, " * BAD *");
        }
        tree_offset += sizeof(guint8);

        flags = tvb_get_guint8(tvb, tree_offset);
        flags_ti = proto_tree_add_uint(jxta_elem_tree, hf_jxta_element_flags, tvb, tree_offset, sizeof(guint8), flags);
        jxta_elem_flags_tree = proto_item_add_subtree(flags_ti, ett_jxta_elem_flags);
        proto_tree_add_boolean(jxta_elem_flags_tree, hf_jxta_element_flag_hasType, tvb, tree_offset, 1, flags);
        proto_tree_add_boolean(jxta_elem_flags_tree, hf_jxta_element_flag_hasEncoding, tvb, tree_offset, 1, flags);
        proto_tree_add_boolean(jxta_elem_flags_tree, hf_jxta_element_flag_hasSignature, tvb, tree_offset, 1, flags);
        tree_offset += sizeof(guint8);

        name_len = tvb_get_ntohs(tvb, tree_offset);
        proto_item_append_text(jxta_elem_tree_item, " \"%s\"", tvb_format_text(tvb, tree_offset + sizeof(guint16), name_len));
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_name, tvb, tree_offset, sizeof(guint16), FALSE);
        tree_offset += sizeof(guint16) + name_len;

        /* process type */
        if ((flags & 0x01) != 0) {
            guint16 type_len = tvb_get_ntohs(tvb, tree_offset);
            proto_tree_add_item(jxta_elem_tree, hf_jxta_element_type, tvb, tree_offset, sizeof(guint16), FALSE);
            tree_offset += sizeof(guint16);

            mediatype = tvb_get_ephemeral_string(tvb, tree_offset, type_len);

            /* remove any params */
            {
                gchar *parms_at = strchr(mediatype, ';');

                if (NULL != parms_at) {
                    *parms_at = '\0';
                }
            }

            /* force to lower case */
#if GLIB_MAJOR_VERSION < 2
            g_strdown(mediatype);
#else
            {
                gchar *mediatype_lowercase = g_ascii_strdown(mediatype, -1);
                mediatype = mediatype_lowercase;
            }
#endif
            tree_offset += type_len;
        }

        /* process encoding */
        if ((flags & 0x02) != 0) {
            guint16 encoding_len = tvb_get_ntohs(tvb, tree_offset);
            proto_tree_add_item(jxta_elem_tree, hf_jxta_element_encoding, tvb, tree_offset, sizeof(guint16), FALSE);
            tree_offset += sizeof(guint16) + encoding_len;
        }

        /* content */
        content_len = tvb_get_ntohl(tvb, tree_offset);
        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_content_len, tvb, tree_offset, sizeof(guint32), FALSE);
        tree_offset += sizeof(guint32);

        element_content_tvb = tvb_new_subset(tvb, tree_offset, content_len, content_len);

        if (mediatype) {
            if( 0 == strcmp( "application/x-jxta-tls-block", mediatype ) ) {
                /* If we recognize it as a TLS packet then we shuffle it off to ssl dissector. */
                dissector_handle_t ssl_handle = find_dissector("ssl");
                if( NULL != ssl_handle ) {
                    int processed = call_dissector(ssl_handle, element_content_tvb, pinfo, jxta_elem_tree);
                    media_type_recognized = processed > 0;
                    }
            } else {
                media_type_recognized = dissector_try_string(media_type_dissector_table,
                                                         mediatype, element_content_tvb, pinfo, jxta_elem_tree);
            }
            
        }

        if (!media_type_recognized) {
            dissector_handle_t data_handle = find_dissector("data");
            call_dissector(data_handle, element_content_tvb, pinfo, jxta_elem_tree);
        }
        tree_offset += content_len;

        if ((flags & 0x04) != 0) {
            tvbuff_t *jxta_message_element_tvb = tvb_new_subset(tvb, tree_offset, -1, -1);

            tree_offset += dissect_jxta_message_element(jxta_message_element_tvb, pinfo, jxta_elem_tree, ns_count, namespaces);
        }

        proto_item_set_end(jxta_elem_tree_item, tvb, tree_offset);

        DISSECTOR_ASSERT(tree_offset == offset);
    }

    return offset;
}

/**
*    Register jxta protocol and jxta message protocol, header fields, subtree types, preferences.
**/
void proto_register_jxta(void)
{
    module_t *jxta_module;

    /* register re-init routine */

    proto_jxta = proto_register_protocol("JXTA P2P", "JXTA", "jxta");

    jxta_tap = register_tap("jxta");

    proto_welcome_jxta = proto_register_protocol("JXTA Connection Welcome Message", "JXTA Welcome", "jxta.welcome");
    
    proto_udp_jxta = proto_register_protocol("JXTA UDP", "JXTA UDP", "jxta.udp");

    proto_framing_jxta = proto_register_protocol("JXTA Message Framing", "JXTA Framing", "jxta.framing");
    
    proto_message_jxta = proto_register_protocol("JXTA Message", "JXTA Message", "jxta.message");

    /* Register header fields */
    proto_register_field_array(proto_jxta, hf, array_length(hf));

    /* Register JXTA Sub-tree */
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    jxta_module = prefs_register_protocol(proto_jxta, proto_reg_handoff_jxta);

    prefs_register_bool_preference(jxta_module, "desegment",
                                   "Reassemble JXTA messages spanning multiple UDP/TCP/HTTP segments",
                                   "Whether the JXTA dissector should reassemble messages spanning multiple UDP/TCP segments."
                                   " To use this option you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings "
                                   " and enable \"Reassemble fragmented IP datagrams\" in the IP protocol settings.",
                                   &gDESEGMENT);

    prefs_register_bool_preference(jxta_module, "udp.heuristic", "Try to discover JXTA in UDP datagrams",
                                   "Enable to inspect UDP datagrams for JXTA messages.", &gUDP_HEUR);

    prefs_register_bool_preference(jxta_module, "tcp.heuristic", "Try to discover JXTA in TCP connections",
                                   "Enable to inspect TCP connections for JXTA conversations.", &gTCP_HEUR);
}

void proto_reg_handoff_jxta(void)
{
    static gboolean init_done = FALSE;

    if (!init_done) {
        new_register_dissector("jxta.udp", dissect_jxta_udp, proto_jxta);
        heur_dissector_add("udp", dissect_jxta_UDP_heur, proto_udp_jxta);

        new_register_dissector("jxta.tcp", dissect_jxta_tcp, proto_jxta);
        tcp_jxta_handle = find_dissector("jxta.tcp");
        heur_dissector_add("tcp", dissect_jxta_TCP_heur, proto_jxta);

        init_done = TRUE;
    }
}

void proto_reg_handoff_message_jxta(void)
{
    static gboolean init_done = FALSE;
    static dissector_handle_t message_jxta_handle;

    if (!init_done) {
        message_jxta_handle = new_create_dissector_handle(dissect_jxta_message, proto_message_jxta);

        media_type_dissector_table = find_dissector_table("media_type");

        dissector_add_string("media_type", "application/x-jxta-msg", message_jxta_handle);

        init_done = TRUE;
    }
}
