/* packet-lbttcp.c
 * Routines for LBM TCP Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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

#include "config.h"
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/uat.h>
#include <epan/wmem/wmem.h>
#include <epan/address.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include "packet-lbm.h"
#include "packet-lbttcp.h"

void proto_register_lbttcp(void);
void proto_reg_handoff_lbttcp(void);

/* Protocol handle */
static int proto_lbttcp = -1;

/* Dissector handle */
static dissector_handle_t lbttcp_dissector_handle;

/*----------------------------------------------------------------------------*/
/* LBT-TCP protocol management.                                               */
/*----------------------------------------------------------------------------*/

typedef struct
{
    wmem_tree_t * frame_tree;
    wmem_tree_t * session_tree;
} lbttcp_transport_conv_data_t;

static const address lbttcp_null_address = { AT_NONE, -1, 0, NULL };

lbttcp_transport_t * lbttcp_transport_find(const address * source_address, guint16 source_port, guint32 session_id, guint32 frame)
{
    lbttcp_transport_t * entry = NULL;
    conversation_t * conv = NULL;
    lbttcp_transport_conv_data_t * conv_data = NULL;

    conv = find_conversation(frame, source_address, &lbttcp_null_address, PT_TCP, source_port, 0, 0);
    if (conv != NULL)
    {
        conv_data = (lbttcp_transport_conv_data_t *) conversation_get_proto_data(conv, proto_lbttcp);
        if (conv_data != NULL)
        {
            entry = (lbttcp_transport_t *) wmem_tree_lookup32(conv_data->session_tree, session_id);
        }
    }
    return (entry);
}

static lbttcp_transport_t * lbttcp_transport_create(const address * source_address, guint16 source_port, guint32 session_id)
{
    lbttcp_transport_t * transport = NULL;

    transport = wmem_new(wmem_file_scope(), lbttcp_transport_t);
    SE_COPY_ADDRESS(&(transport->source_address), source_address);
    transport->source_port = source_port;
    transport->session_id = session_id;
    transport->channel = lbm_channel_assign(LBM_CHANNEL_TRANSPORT_LBTTCP);
    transport->next_client_id = 1;
    transport->client_list = wmem_list_new(wmem_file_scope());
    return (transport);
}

lbttcp_transport_t * lbttcp_transport_add(const address * source_address, guint16 source_port, guint32 session_id, guint32 frame)
{
    lbttcp_transport_t * entry = NULL;
    conversation_t * conv = NULL;
    lbttcp_transport_conv_data_t * conv_data = NULL;

    conv = find_conversation(frame, source_address, &lbttcp_null_address, PT_TCP, source_port, 0, 0);
    if (conv == NULL)
    {
        conv = conversation_new(frame, source_address, &lbttcp_null_address, PT_TCP, source_port, 0, 0);
    }
    conv_data = (lbttcp_transport_conv_data_t *) conversation_get_proto_data(conv, proto_lbttcp);
    if (conv_data == NULL)
    {
        conv_data = wmem_new(wmem_file_scope(), lbttcp_transport_conv_data_t);
        conv_data->frame_tree = wmem_tree_new(wmem_file_scope());
        conv_data->session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_lbttcp, (void *) conv_data);
    }
    entry = (lbttcp_transport_t *) wmem_tree_lookup32(conv_data->session_tree, session_id);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = lbttcp_transport_create(source_address, source_port, session_id);
    wmem_tree_insert32(conv_data->session_tree, session_id, (void *) entry);
    wmem_tree_insert32(conv_data->frame_tree, frame, (void *) entry);
    return (entry);
}

static lbttcp_client_transport_t * lbttcp_client_transport_find(lbttcp_transport_t * transport, const address * receiver_address, guint16 receiver_port, guint32 frame)
{
    lbttcp_client_transport_t * entry = NULL;
    conversation_t * client_conv = NULL;

    if (transport == NULL)
    {
        return (NULL);
    }
    client_conv = find_conversation(frame, &(transport->source_address), receiver_address, PT_TCP, transport->source_port, receiver_port, 0);
    if (client_conv != NULL)
    {
        wmem_tree_t * session_tree = NULL;

        session_tree = (wmem_tree_t *) conversation_get_proto_data(client_conv, proto_lbttcp);
        if (session_tree != NULL)
        {
            entry = (lbttcp_client_transport_t *) wmem_tree_lookup32(session_tree, transport->session_id);
        }
    }
    return (entry);
}

static lbttcp_client_transport_t * lbttcp_client_transport_add(lbttcp_transport_t * transport, const address * receiver_address, guint16 receiver_port, guint32 frame)
{
    lbttcp_client_transport_t * entry;
    conversation_t * client_conv = NULL;
    wmem_tree_t * session_tree = NULL;

    if (transport == NULL)
    {
        return (NULL);
    }
    entry = lbttcp_client_transport_find(transport, receiver_address, receiver_port, frame);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbttcp_client_transport_t);
    SE_COPY_ADDRESS(&(entry->receiver_address), receiver_address);
    entry->receiver_port = receiver_port;
    entry->id = transport->next_client_id++;

    /* See if a conversation for this address/port pair exists. */
    client_conv = find_conversation(frame, &(transport->source_address), receiver_address, PT_TCP, transport->source_port, receiver_port, 0);
    if (client_conv == NULL)
    {
        client_conv = conversation_new(frame, &(transport->source_address), receiver_address, PT_TCP, transport->source_port, receiver_port, 0);
        session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(client_conv, proto_lbttcp, (void *) session_tree);
    }
    session_tree = (wmem_tree_t *) conversation_get_proto_data(client_conv, proto_lbttcp);
    if (session_tree == NULL)
    {
        session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(client_conv, proto_lbttcp, (void *) session_tree);
    }
    wmem_tree_insert32(session_tree, transport->session_id, (void *) entry);

    /* Add this client to the transport. */
    wmem_list_append(transport->client_list, (void *) entry);
    return (entry);
}

char * lbttcp_transport_source_string(const address * source_address, guint16 source_port, guint32 session_id)
{
    char * bufptr = NULL;

    if (session_id == 0)
    {
        bufptr = wmem_strdup_printf(wmem_file_scope(), "TCP:%s:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), source_address), source_port);
    }
    else
    {
        bufptr = wmem_strdup_printf(wmem_file_scope(), "TCP:%s:%" G_GUINT16_FORMAT ":%08x", address_to_str(wmem_packet_scope(), source_address), source_port, session_id);
    }
    return (bufptr);
}

gboolean lbttcp_transport_sid_find(const address * source_address, guint16 source_port, guint32 frame, guint32 * session_id)
{
    conversation_t * conv = NULL;
    lbttcp_transport_conv_data_t * conv_data = NULL;
    lbttcp_transport_t * transport = NULL;

    conv = find_conversation(frame, source_address, &lbttcp_null_address, PT_TCP, source_port, 0, 0);
    if (conv == NULL)
    {
        return (FALSE);
    }
    conv_data = (lbttcp_transport_conv_data_t *) conversation_get_proto_data(conv, proto_lbttcp);
    if (conv_data == NULL)
    {
        return (FALSE);
    }
    if (conv_data->frame_tree == NULL)
    {
        return (FALSE);
    }
    transport = (lbttcp_transport_t *)wmem_tree_lookup32_le(conv_data->frame_tree, frame);
    if (transport == NULL)
    {
        return (FALSE);
    }
    *session_id = transport->session_id;
    return (TRUE);
}

void lbttcp_transport_sid_add(const address * source_address, guint16 source_port, guint32 frame, guint32 session_id)
{
    conversation_t * conv = NULL;
    lbttcp_transport_conv_data_t * conv_data = NULL;
    lbttcp_transport_t * transport = NULL;

    conv = find_conversation(frame, source_address, &lbttcp_null_address, PT_TCP, source_port, 0, 0);
    if (conv == NULL)
    {
        conv = conversation_new(frame, source_address, &lbttcp_null_address, PT_TCP, source_port, 0, 0);
    }
    conv_data = (lbttcp_transport_conv_data_t *) conversation_get_proto_data(conv, proto_lbttcp);
    if (conv_data == NULL)
    {
        conv_data = wmem_new(wmem_file_scope(), lbttcp_transport_conv_data_t);
        conv_data->frame_tree = wmem_tree_new(wmem_file_scope());
        conv_data->session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_lbttcp, (void *) conv_data);
    }
    /* Lookup by frame */
    transport = (lbttcp_transport_t *) wmem_tree_lookup32_le(conv_data->frame_tree, frame);
    if (transport != NULL)
    {
        if (transport->session_id != session_id)
        {
            transport = NULL;
        }
    }
    if (transport == NULL)
    {
        transport = lbttcp_transport_create(source_address, source_port, session_id);
        wmem_tree_insert32(conv_data->session_tree, session_id, (void *) transport);
        wmem_tree_insert32(conv_data->frame_tree, frame, (void *) transport);
    }
}

/*----------------------------------------------------------------------------*/
/* Preferences.                                                               */
/*----------------------------------------------------------------------------*/

/* Preferences default values. */
#define LBTTCP_DEFAULT_SOURCE_PORT_LOW 14371
#define LBTTCP_DEFAULT_SOURCE_PORT_HIGH 14390
#define LBTTCP_DEFAULT_REQUEST_PORT_LOW 14391
#define LBTTCP_DEFAULT_REQUEST_PORT_HIGH 14395
#define LBTTCP_DEFAULT_STORE_PORT_LOW 0
#define LBTTCP_DEFAULT_STORE_PORT_HIGH 0

/* Global preferences variables (altered by the preferences dialog). */
static guint32 global_lbttcp_source_port_low = LBTTCP_DEFAULT_SOURCE_PORT_LOW;
static guint32 global_lbttcp_source_port_high  = LBTTCP_DEFAULT_SOURCE_PORT_HIGH;
static guint32 global_lbttcp_request_port_low = LBTTCP_DEFAULT_REQUEST_PORT_LOW;
static guint32 global_lbttcp_request_port_high = LBTTCP_DEFAULT_REQUEST_PORT_HIGH;
static guint32 global_lbttcp_store_port_low = LBTTCP_DEFAULT_STORE_PORT_LOW;
static guint32 global_lbttcp_store_port_high = LBTTCP_DEFAULT_STORE_PORT_HIGH;
static gboolean global_lbttcp_use_tag = FALSE;

/* Local preferences variables (used by the dissector). */
static guint32 lbttcp_source_port_low = LBTTCP_DEFAULT_SOURCE_PORT_LOW;
static guint32 lbttcp_source_port_high = LBTTCP_DEFAULT_SOURCE_PORT_HIGH;
static guint32 lbttcp_request_port_low = LBTTCP_DEFAULT_REQUEST_PORT_LOW;
static guint32 lbttcp_request_port_high = LBTTCP_DEFAULT_REQUEST_PORT_HIGH;
static guint32 lbttcp_store_port_low = LBTTCP_DEFAULT_STORE_PORT_LOW;
static guint32 lbttcp_store_port_high = LBTTCP_DEFAULT_STORE_PORT_HIGH;
static gboolean lbttcp_use_tag = FALSE;

/* Tag definitions. */
typedef struct
{
    char * name;
    guint32 source_port_low;
    guint32 source_port_high;
    guint32 request_port_low;
    guint32 request_port_high;
    guint32 store_port_low;
    guint32 store_port_high;
} lbttcp_tag_entry_t;

static lbttcp_tag_entry_t * lbttcp_tag_entry = NULL;
static guint lbttcp_tag_count  = 0;

UAT_CSTRING_CB_DEF(lbttcp_tag, name, lbttcp_tag_entry_t)
UAT_DEC_CB_DEF(lbttcp_tag, source_port_low, lbttcp_tag_entry_t)
UAT_DEC_CB_DEF(lbttcp_tag, source_port_high, lbttcp_tag_entry_t)
UAT_DEC_CB_DEF(lbttcp_tag, request_port_low, lbttcp_tag_entry_t)
UAT_DEC_CB_DEF(lbttcp_tag, request_port_high, lbttcp_tag_entry_t)
UAT_DEC_CB_DEF(lbttcp_tag, store_port_low, lbttcp_tag_entry_t)
UAT_DEC_CB_DEF(lbttcp_tag, store_port_high, lbttcp_tag_entry_t)
static uat_field_t lbttcp_tag_array[] =
{
    UAT_FLD_CSTRING(lbttcp_tag, name, "Tag name", "Tag name"),
    UAT_FLD_DEC(lbttcp_tag, source_port_low, "Source port low", "Source port low"),
    UAT_FLD_DEC(lbttcp_tag, source_port_high, "Source port high", "Source port high"),
    UAT_FLD_DEC(lbttcp_tag, request_port_low, "Request port low", "Request port low"),
    UAT_FLD_DEC(lbttcp_tag, request_port_high, "Request port high", "Request port high"),
    UAT_FLD_DEC(lbttcp_tag, store_port_low, "Store port low", "Store port low"),
    UAT_FLD_DEC(lbttcp_tag, store_port_high, "Store port high", "Store port high"),
    UAT_END_FIELDS
};

/*----------------------------------------------------------------------------*/
/* UAT callback functions.                                                    */
/*----------------------------------------------------------------------------*/
static void lbttcp_tag_update_cb(void * record, const char * * error_string)
{
    lbttcp_tag_entry_t * tag = (lbttcp_tag_entry_t *)record;

    if (tag->name == NULL)
    {
        *error_string = g_strdup_printf("Tag name can't be empty");
    }
    else
    {
        g_strstrip(tag->name);
        if (tag->name[0] == 0)
        {
            *error_string = g_strdup_printf("Tag name can't be empty");
        }
    }
}

static void * lbttcp_tag_copy_cb(void * destination, const void * source, size_t length _U_)
{
    const lbttcp_tag_entry_t * src = (const lbttcp_tag_entry_t *)source;
    lbttcp_tag_entry_t * dest = (lbttcp_tag_entry_t *)destination;

    dest->name = g_strdup(src->name);
    dest->source_port_low = src->source_port_low;
    dest->source_port_high = src->source_port_high;
    dest->request_port_low = src->request_port_low;
    dest->request_port_high = src->request_port_high;
    dest->store_port_low = src->store_port_low;
    dest->store_port_high = src->store_port_high;
    return (dest);
}

static void lbttcp_tag_free_cb(void * record)
{
    lbttcp_tag_entry_t * tag = (lbttcp_tag_entry_t *)record;

    if (tag->name != NULL)
    {
        g_free(tag->name);
        tag->name = NULL;
    }
}

static const lbttcp_tag_entry_t * lbttcp_tag_locate(packet_info * pinfo)
{
    guint idx;
    const lbttcp_tag_entry_t * tag = NULL;

    if (!lbttcp_use_tag)
    {
        return (NULL);
    }

    for (idx = 0; idx < lbttcp_tag_count; ++idx)
    {
        tag = &(lbttcp_tag_entry[idx]);
        if (((pinfo->srcport >= tag->source_port_low) && (pinfo->srcport <= tag->source_port_high))
            || ((pinfo->destport >= tag->source_port_low) && (pinfo->destport <= tag->source_port_high))
            || ((pinfo->srcport >= tag->request_port_low) && (pinfo->srcport <= tag->request_port_high))
            || ((pinfo->destport >= tag->request_port_low) && (pinfo->destport <= tag->request_port_high))
            || ((pinfo->srcport >= tag->store_port_low) && (pinfo->srcport <= tag->store_port_high))
            || ((pinfo->destport >= tag->store_port_low) && (pinfo->destport <= tag->store_port_high)))
        {
            return (tag);
        }
    }
    return (NULL);
}

static char * lbttcp_tag_find(packet_info * pinfo)
{
    const lbttcp_tag_entry_t * tag = NULL;

    if (!lbttcp_use_tag)
    {
        return (NULL);
    }

    tag = lbttcp_tag_locate(pinfo);
    if (tag != NULL)
    {
        return tag->name;
    }
    return (NULL);
}

/*----------------------------------------------------------------------------*/
/* Handles of all types.                                                      */
/*----------------------------------------------------------------------------*/

/* Dissector tree handles */
static gint ett_lbttcp = -1;
static gint ett_lbttcp_channel = -1;

/* Dissector field handles */
static int hf_lbttcp_tag = -1;
static int hf_lbttcp_channel = -1;
static int hf_lbttcp_channel_id = -1;
static int hf_lbttcp_channel_client = -1;

static gboolean lbttcp_packet_is_transport_source(packet_info * pinfo, const lbttcp_tag_entry_t * tag)
{
    gboolean is_transport_source_packet = FALSE;

    if (tag == NULL)
    {
        if ((pinfo->srcport >= lbttcp_source_port_low) && (pinfo->srcport <= lbttcp_source_port_high))
        {
            is_transport_source_packet = TRUE;
        }
    }
    else
    {
        if ((pinfo->srcport >= tag->source_port_low) && (pinfo->srcport <= tag->source_port_high))
        {
            is_transport_source_packet = TRUE;
        }
    }
    return (is_transport_source_packet);
}

static gboolean lbttcp_packet_is_transport_client(packet_info * pinfo, const lbttcp_tag_entry_t * tag)
{
    gboolean is_transport_client_packet = FALSE;

    if (tag == NULL)
    {
        if ((pinfo->destport >= lbttcp_source_port_low) && (pinfo->destport <= lbttcp_source_port_high))
        {
            is_transport_client_packet = TRUE;
        }
    }
    else
    {
        if ((pinfo->destport >= tag->source_port_low) && (pinfo->destport <= tag->source_port_high))
        {
            is_transport_client_packet = TRUE;
        }
    }
    return (is_transport_client_packet);
}

static guint get_lbttcp_pdu_length(packet_info * pinfo _U_, tvbuff_t * tvb, int offset)
{
    return lbmc_get_message_length(tvb, offset);
}

static int dissect_lbttcp_pdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * dissector_data _U_)
{
    proto_tree * lbttcp_tree = NULL;
    proto_item * ti = NULL;
    char * tag_name = NULL;
    int len_dissected;
    const lbttcp_tag_entry_t * tag = NULL;
    guint64 channel = LBM_CHANNEL_NO_CHANNEL;
    guint32 client_id = 0;
    gboolean from_source = FALSE;
    gboolean transport_packet = FALSE;

    if (lbttcp_use_tag)
    {
        tag = lbttcp_tag_locate(pinfo);
        tag_name = lbttcp_tag_find(pinfo);
    }
    if (tag_name != NULL)
    {
        ti = proto_tree_add_protocol_format(tree, proto_lbttcp, tvb, 0, -1, "LBT-TCP Protocol (Tag: %s)", tag_name);
    }
    else
    {
        ti = proto_tree_add_protocol_format(tree, proto_lbttcp, tvb, 0, -1, "LBT-TCP Protocol");
    }
    lbttcp_tree = proto_item_add_subtree(ti, ett_lbttcp);
    if (tag_name != NULL)
    {
        proto_item * item = NULL;

        item = proto_tree_add_string(lbttcp_tree, hf_lbttcp_tag, tvb, 0, 0, tag_name);
        PROTO_ITEM_SET_GENERATED(item);
    }
    if (lbttcp_packet_is_transport_source(pinfo, tag))
    {
        from_source = TRUE;
        transport_packet = TRUE;
    }
    else if (lbttcp_packet_is_transport_client(pinfo, tag))
    {
        from_source = FALSE;
        transport_packet = TRUE;
    }
    if (transport_packet)
    {
        address source_address;
        address client_address;
        guint16 srcport;
        guint16 clntport;
        guint32 sid = 0;
        lbttcp_transport_t * transport = NULL;
        lbttcp_client_transport_t * client = NULL;

        if (from_source)
        {
            COPY_ADDRESS_SHALLOW(&source_address, &(pinfo->src));
            srcport = pinfo->srcport;
            COPY_ADDRESS_SHALLOW(&client_address, &(pinfo->dst));
            clntport = pinfo->destport;
        }
        else
        {
            COPY_ADDRESS_SHALLOW(&source_address, &(pinfo->dst));
            srcport = pinfo->destport;
            COPY_ADDRESS_SHALLOW(&client_address, &(pinfo->src));
            clntport = pinfo->srcport;
        }
        /* See if we have a matching transport with no session ID. */
        transport = lbttcp_transport_find(&source_address, srcport, sid, pinfo->fd->num);
        if (transport == NULL)
        {
            /* See if we know about a SID */
            if (lbttcp_transport_sid_find(&source_address, srcport, pinfo->fd->num, &sid))
            {
                transport = lbttcp_transport_find(&source_address, srcport, sid, pinfo->fd->num);
            }
        }
        if (transport != NULL)
        {
            channel = transport->channel;
            /* See if we already know about this client */
            client = lbttcp_client_transport_find(transport, &client_address, clntport, pinfo->fd->num);
            if (client == NULL)
            {
                /* No - add it. */
                client = lbttcp_client_transport_add(transport, &client_address, clntport, pinfo->fd->num);
            }
            if (client != NULL)
            {
                client_id = client->id;
            }
        }
        else
        {
            if (PINFO_FD_VISITED(pinfo))
            {
                /* No TIR and no session ID seen, so create the transport */
                transport = lbttcp_transport_add(&source_address, srcport, 0, pinfo->fd->num);
                if (transport != NULL)
                {
                    channel = transport->channel;
                    client = lbttcp_client_transport_add(transport, &client_address, clntport, pinfo->fd->num);
                    if (client != NULL)
                    {
                        client_id = client->id;
                    }
                }
            }
            else
            {
                /* Defer determining the channel. */
                if (from_source)
                {
                    channel = lbm_channel_assign_unknown_transport_source_lbttcp();
                }
                else
                {
                    channel = lbm_channel_assign_unknown_transport_client_lbttcp();
                }
            }
        }
    }
    else
    {
        channel = lbm_channel_assign_unknown_stream_tcp();
    }
    if (lbm_channel_is_known(channel))
    {
        proto_item * channel_item = NULL;
        proto_tree * channel_tree = NULL;

        channel_item = proto_tree_add_item(lbttcp_tree, hf_lbttcp_channel, tvb, 0, 0, ENC_NA);
        PROTO_ITEM_SET_GENERATED(channel_item);
        channel_tree = proto_item_add_subtree(channel_item, ett_lbttcp_channel);
        channel_item = proto_tree_add_uint64(channel_tree, hf_lbttcp_channel_id, tvb, 0, 0, channel);
        PROTO_ITEM_SET_GENERATED(channel_item);
        channel_item = proto_tree_add_uint(channel_tree, hf_lbttcp_channel_client, tvb, 0, 0, client_id);
        PROTO_ITEM_SET_GENERATED(channel_item);
    }
    len_dissected = lbmc_dissect_lbmc_packet(tvb, 0, pinfo, tree, tag_name, channel);
    return (len_dissected);
}

/*
 * dissect_lbttcp_real - The "common" dissection for LBT-TCP
 */
static int dissect_lbttcp_real(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    char * tag_name = NULL;

    col_add_str(pinfo->cinfo, COL_PROTOCOL, "LBT-TCP");
    col_clear(pinfo->cinfo, COL_INFO);
    if (lbttcp_use_tag)
    {
        tag_name = lbttcp_tag_find(pinfo);
    }
    if (tag_name != NULL)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "[Tag: %s]", tag_name);
    }
    col_set_fence(pinfo->cinfo, COL_INFO);
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, lbmc_get_minimum_length(), /* Need at least the msglen */
        get_lbttcp_pdu_length, dissect_lbttcp_pdu, NULL);

    return tvb_captured_length(tvb);
}

/*
 * dissect_lbttcp - The dissector for LBT-TCP
 */
static int dissect_lbttcp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data)
{
    if (!lbmc_test_lbmc_header(tvb, 0))
        return 0;

    return dissect_lbttcp_real(tvb, pinfo, tree, data);
}

static gboolean test_lbttcp_packet(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data)
{
    /* Destination address must be IPV4 and 4 bytes in length. */
    if ((pinfo->dst.type != AT_IPv4) || (pinfo->dst.len != 4))
    {
        return (FALSE);
    }

    if (lbttcp_use_tag)
    {
        if (lbttcp_tag_find(pinfo) != NULL)
        {
            dissect_lbttcp_real(tvb, pinfo, tree, data);
            return (TRUE);
        }
        else
        {
            return (FALSE);
        }
    }

    /*
        Source port or destination port must be in the source port range, or destination port must be in
        the request port range, or either port in the UME store port range.
    */
    if (!(((pinfo->srcport >= lbttcp_source_port_low) && (pinfo->srcport <= lbttcp_source_port_high))
          || ((pinfo->destport >= lbttcp_source_port_low) && (pinfo->destport <= lbttcp_source_port_high))
          || ((pinfo->srcport >= lbttcp_request_port_low) && (pinfo->srcport <= lbttcp_request_port_high))
          || ((pinfo->destport >= lbttcp_request_port_low) && (pinfo->destport <= lbttcp_request_port_high))
          || ((pinfo->srcport >= lbttcp_store_port_low) && (pinfo->srcport <= lbttcp_store_port_high))
          || ((pinfo->destport >= lbttcp_store_port_low) && (pinfo->destport <= lbttcp_store_port_high))))
    {
        return (FALSE);
    }

    if (!lbmc_test_lbmc_header(tvb, 0))
        return FALSE;

    /* One of ours. Probably. */
    dissect_lbttcp_real(tvb, pinfo, tree, data);
    return (TRUE);
}

/* Register all the bits needed with the filtering engine */
void proto_register_lbttcp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_lbttcp_tag,
            { "Tag", "lbttcp.tag", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbttcp_channel,
            { "Channel", "lbttcp.channel", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbttcp_channel_id,
            { "Channel ID", "lbttcp.channel.channel", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbttcp_channel_client,
            { "Channel Client", "lbttcp.channel.client", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };
    static gint * ett[] =
    {
        &ett_lbttcp,
        &ett_lbttcp_channel
    };
    module_t * lbttcp_module;
    uat_t * tag_uat;

    proto_lbttcp = proto_register_protocol("LBT TCP Protocol", "LBT-TCP", "lbttcp");

    proto_register_field_array(proto_lbttcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    lbttcp_module = prefs_register_protocol_subtree("29West", proto_lbttcp, proto_reg_handoff_lbttcp);
    prefs_register_uint_preference(lbttcp_module,
        "source_port_low",
        "Source port range low (default " MAKESTRING(LBTTCP_DEFAULT_SOURCE_PORT_LOW)")",
        "Set the low end of the LBT-TCP source TCP port range (context transport_tcp_port_low)",
        10,
        &global_lbttcp_source_port_low);

    prefs_register_uint_preference(lbttcp_module,
        "source_port_high",
        "Source port range high (default " MAKESTRING(LBTTCP_DEFAULT_SOURCE_PORT_HIGH)")",
        "Set the high end of the LBT-TCP source TCP port range (context transport_tcp_port_high)",
        10,
        &global_lbttcp_source_port_high);

    prefs_register_uint_preference(lbttcp_module,
        "request_port_low",
        "Request port range low (default " MAKESTRING(LBTTCP_DEFAULT_REQUEST_PORT_LOW)")",
        "Set the low end of the LBT-TCP request TCP port range (context request_tcp_port_low)",
        10,
        &global_lbttcp_request_port_low);

    prefs_register_uint_preference(lbttcp_module,
        "request_port_high",
        "Request port range high (default " MAKESTRING(LBTTCP_DEFAULT_REQUEST_PORT_HIGH)")",
        "Set the high end of the LBT-TCP request TCP port range (context request_tcp_port_high)",
        10,
        &global_lbttcp_request_port_high);

    prefs_register_uint_preference(lbttcp_module,
        "store_port_low",
        "UME Store port range low (default " MAKESTRING(LBTTCP_DEFAULT_STORE_PORT_LOW)")",
        "Set the low end of the LBT-TCP UME Store TCP port range",
        10,
        &global_lbttcp_store_port_low);

    prefs_register_uint_preference(lbttcp_module,
        "store_port_high",
        "UME Store port range high (default " MAKESTRING(LBTTCP_DEFAULT_STORE_PORT_HIGH)")",
        "Set the high end of the LBT-TCP UME Store TCP port range",
        10,
        &global_lbttcp_store_port_high);

    prefs_register_bool_preference(lbttcp_module,
        "use_lbttcp_domain",
        "Use LBT-TCP tag table",
        "Use table of LBT-TCP tags to decode the packet instead of above values",
        &global_lbttcp_use_tag);
    tag_uat = uat_new("LBT-TCP tag definitions",
        sizeof(lbttcp_tag_entry_t),
        "lbttcp_domains",
        TRUE,
        (void * *)&lbttcp_tag_entry,
        &lbttcp_tag_count,
        UAT_AFFECTS_DISSECTION,
        NULL,
        lbttcp_tag_copy_cb,
        lbttcp_tag_update_cb,
        lbttcp_tag_free_cb,
        NULL,
        lbttcp_tag_array);
    prefs_register_uat_preference(lbttcp_module,
        "tnw_lbttcp_tags",
        "LBT-TCP Tags",
        "A table to define LBT-TCP tags",
        tag_uat);
}

/* The registration hand-off routine */
void proto_reg_handoff_lbttcp(void)
{
    static gboolean already_registered = FALSE;

    if (!already_registered)
    {
        lbttcp_dissector_handle = new_create_dissector_handle(dissect_lbttcp, proto_lbttcp);
        dissector_add_for_decode_as("tcp.port", lbttcp_dissector_handle);
        heur_dissector_add("tcp", test_lbttcp_packet, proto_lbttcp);
    }

    /* Make sure the source port low is <= the source port high. If not, don't change them. */
    if (global_lbttcp_source_port_low <= global_lbttcp_source_port_high)
    {
        lbttcp_source_port_low = global_lbttcp_source_port_low;
        lbttcp_source_port_high = global_lbttcp_source_port_high;
    }

    /* Make sure the request port low is <= the request port high. If not, don't change them. */
    if (global_lbttcp_request_port_low <= global_lbttcp_request_port_high)
    {
        lbttcp_request_port_low = global_lbttcp_request_port_low;
        lbttcp_request_port_high = global_lbttcp_request_port_high;
    }

    /* Make sure the store port low is <= the store port high. If not, don't change them. */
    if (global_lbttcp_store_port_low <= global_lbttcp_store_port_high)
    {
        lbttcp_store_port_low = global_lbttcp_store_port_low;
        lbttcp_store_port_high = global_lbttcp_store_port_high;
    }

    lbttcp_use_tag = global_lbttcp_use_tag;

    already_registered = TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
