/* packet-rdt.c
 *
 * Routines for RDT dissection
 * RDT = Real Data Transport
 *
 * Copyright 2005
 * Written by Martin Mathieson
 *
 * $Id: packet-rdt.c 13357 2005-02-08 21:12:54Z lroland $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-rdt.h"
#include <epan/conversation.h>

#include <epan/prefs.h>

static dissector_handle_t rdt_handle;

/* RDT header fields             */
static int proto_rdt           = -1;

/* RDT setup fields */
static int hf_rdt_setup             = -1;
static int hf_rdt_setup_frame       = -1;
static int hf_rdt_setup_method      = -1;
static int hf_rdt_stream_id         = -1;
static int hf_rdt_sequence_number   = -1;
static int hf_rdt_flags             = -1;
static int hf_rdt_packet_size       = -1;
static int hf_rdt_timestamp         = -1;
static int hf_rdt_unparsed          = -1;

/* RDT fields defining a sub tree */
static gint ett_rdt                 = -1;
static gint ett_rdt_setup           = -1;

static void dissect_rdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Preferences bool to control whether or not setup info should be shown */
static gboolean global_rdt_show_setup_info = TRUE;

/* Memory chunk for storing conversation and per-packet info */
static GMemChunk *rdt_conversations = NULL;


#define RETRANSMISSION_REQUEST_STREAM_ID 0
#define AUDIO_STREAM_ID 64
#define VIDEO_STREAM_ID 66

const value_string rdt_stream_id_vals[] =
{
    { RETRANSMISSION_REQUEST_STREAM_ID, "Retransmission Request" },
    { AUDIO_STREAM_ID,                  "Audio" },
    { VIDEO_STREAM_ID,                  "Video" },
    { 0,                                NULL },
};


/* Set up an RDT conversation */
void rdt_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     gchar *setup_method, guint32 setup_frame_number)
{
    address null_addr;
    conversation_t* p_conv;
    struct _rdt_conversation_info *p_conv_data = NULL;

    /*
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if (pinfo->fd->flags.visited)
    {
        return;
    }

    SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

    /*
     * Check if the ip address and port combination is not
     * already registered as a conversation.
     */
    p_conv = find_conversation(setup_frame_number, addr, &null_addr, PT_UDP, port, other_port,
                               NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    /*
     * If not, create a new conversation.
     */
    if ( !p_conv || p_conv->setup_frame != setup_frame_number)
    {
        p_conv = conversation_new(setup_frame_number, addr, &null_addr, PT_UDP,
                                  (guint32)port, (guint32)other_port,
                                  NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, rdt_handle);

    /*
     * Check if the conversation has data associated with it.
     */
    p_conv_data = conversation_get_proto_data(p_conv, proto_rdt);

    /*
     * If not, add a new data item.
     */
    if (!p_conv_data)
    {
        /* Create conversation data */
        p_conv_data = g_mem_chunk_alloc(rdt_conversations);

        conversation_add_proto_data(p_conv, proto_rdt, p_conv_data);
    }

    /*
     * Update the conversation data.
     */
    strncpy(p_conv_data->method, setup_method, MAX_RDT_SETUP_METHOD_SIZE);
    p_conv_data->method[MAX_RDT_SETUP_METHOD_SIZE] = '\0';
    p_conv_data->frame_number = setup_frame_number;
}

static void rdt_init(void)
{
    /* (Re)allocate mem chunk for conversations */
    if (rdt_conversations)
    {
        g_mem_chunk_destroy(rdt_conversations);
    }

    rdt_conversations = g_mem_chunk_new("rdt_conversations",
                                        sizeof(struct _rdt_conversation_info),
                                        20 * sizeof(struct _rdt_conversation_info),
                                        G_ALLOC_ONLY);
}



/*********************************/
/* Main dissection function      */
/*********************************/
static void
dissect_rdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;
    proto_item  *ti = NULL;
    proto_tree  *rdt_tree = NULL;
    guint8      stream_id;
    guint16     sequence_number;
    guint16     packet_size;
    guint32     timestamp;
    guint8      flags;
        
    /* Set columns */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDT" );
    }
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_set_str(pinfo->cinfo, COL_INFO, "RealPlayer:  ");
    }

    /* Build tree (inside guard?) */
    /* Create RDT protocol tree */
    ti = proto_tree_add_item(tree, proto_rdt, tvb, offset, -1, FALSE);
    rdt_tree = proto_item_add_subtree(ti, ett_rdt);

    /* Conversation setup info */
    if (global_rdt_show_setup_info)
    {
        show_setup_info(tvb, pinfo, rdt_tree);
    }

    
    /* Stream ID */
    stream_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(rdt_tree, hf_rdt_stream_id, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        switch (stream_id)
        {
            case AUDIO_STREAM_ID:
                col_append_str(pinfo->cinfo, COL_INFO, "AUDIO ");
                break;
            case VIDEO_STREAM_ID:
                col_append_str(pinfo->cinfo, COL_INFO, "VIDEO ");
                break;
            case RETRANSMISSION_REQUEST_STREAM_ID:
                col_append_str(pinfo->cinfo, COL_INFO, "Retransmit Request ? ");
                break;
            default:
                col_append_str(pinfo->cinfo, COL_INFO, "Unknown ");
                break;
        }
    }
    
    if ((stream_id != AUDIO_STREAM_ID) && (stream_id != VIDEO_STREAM_ID))
    {
        /* Don't know what to do with others... */
        proto_tree_add_item(rdt_tree, hf_rdt_unparsed, tvb, offset, -1, FALSE);        
        return;
    }
    
    
    /* Sequence number */
    sequence_number = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(rdt_tree, hf_rdt_sequence_number, tvb, offset, 2, FALSE);
    offset += 2;
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " seq=%d ", sequence_number);        
    }

    /* These sequence numbers are short packets: give up */
    if ((sequence_number & 0xff00) == 0xff00)
    {
        proto_tree_add_item(rdt_tree, hf_rdt_unparsed, tvb, offset, -1, FALSE);        
        return;
    }

    /* Packet size (not present if 1st byte's m.s. bit was set) */
    if (stream_id & 0x80)
    {
        packet_size = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(rdt_tree, hf_rdt_packet_size, tvb, offset, 2, FALSE);
        offset += 2;
    
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " size=%d ", packet_size);        
        }
    }

    /* Flags */
    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(rdt_tree, hf_rdt_flags, tvb, offset, 1, FALSE);
    offset++;
    
    
    /* Timestamp */
    timestamp = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(rdt_tree, hf_rdt_timestamp, tvb, offset, 4, FALSE);
    offset += 4;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " ts=%d ", timestamp);        
    }

    /* The remaining data is unparsed. */
    proto_tree_add_item(rdt_tree, hf_rdt_unparsed, tvb, offset, -1, FALSE);
}


/* Look for conversation info and display any setup info found */
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Conversation and current data */
    conversation_t *p_conv = NULL;
    struct _rdt_conversation_info *p_conv_data = NULL;

    /* Use existing packet info if available */
    p_conv_data = p_get_proto_data(pinfo->fd, proto_rdt);

    if (!p_conv_data)
    {
        /* First time, get info from conversation */
        p_conv = find_conversation(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src,
                                   pinfo->ptype,
                                   pinfo->destport, pinfo->srcport, NO_ADDR_B);
        if (p_conv)
        {
            /* Create space for conversation info */
            struct _rdt_conversation_info *p_conv_packet_data;
            p_conv_data = conversation_get_proto_data(p_conv, proto_rdt);

            if (p_conv_data)
            {
                /* Save this conversation info into packet info */
                p_conv_packet_data = g_mem_chunk_alloc(rdt_conversations);
                strcpy(p_conv_packet_data->method, p_conv_data->method);
                p_conv_packet_data->frame_number = p_conv_data->frame_number;
                p_add_proto_data(pinfo->fd, proto_rdt, p_conv_packet_data);
            }
        }
    }

    /* Create setup info subtree with summary info. */
    if (p_conv_data)
    {
        proto_tree *rdt_setup_tree;
        proto_item *ti =  proto_tree_add_string_format(tree, hf_rdt_setup, tvb, 0, 0,
                                                       "",
                                                       "Stream setup by %s (frame %d)",
                                                       p_conv_data->method,
                                                       p_conv_data->frame_number);
        PROTO_ITEM_SET_GENERATED(ti);
        rdt_setup_tree = proto_item_add_subtree(ti, ett_rdt_setup);
        if (rdt_setup_tree)
        {
            /* Add details into subtree */
            proto_item* item = proto_tree_add_uint(rdt_setup_tree, hf_rdt_setup_frame,
                                                   tvb, 0, 0, p_conv_data->frame_number);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_string(rdt_setup_tree, hf_rdt_setup_method,
                                         tvb, 0, 0, p_conv_data->method);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }
}


void
proto_register_rdt(void)
{
    static hf_register_info hf[] =
    {
        {
            &hf_rdt_stream_id,
            {
                "StreamID",
                "rdt.stream_id",
                FT_UINT8,
                BASE_DEC,
                VALS(rdt_stream_id_vals),
                0x0,
                "", HFILL
            }
        },
        {
            &hf_rdt_sequence_number,
            {
                "Sequence number",
                "rdt.sequence_number",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },        
        {
            &hf_rdt_flags,
            {
                "Flags",
                "rdt.flags",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_rdt_packet_size,
            {
                "Packet size",
                "rdt.packet_size",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },                
        {
            &hf_rdt_timestamp,
            {
                "Timestamp",
                "rdt.timestamp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "Timestamp", HFILL
            }
        },
        {
            &hf_rdt_setup,
            {
                "Stream setup",
                "rdt.setup",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Stream setup, method and frame number", HFILL
            }
        },
        {
            &hf_rdt_setup_frame,
            {
                "Setup frame",
                "rdt.setup-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame that set up this stream", HFILL
            }
        },
        {
            &hf_rdt_setup_method,
            {
                "Setup Method",
                "rdt.setup-method",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Method used to set up this stream", HFILL
            }
        },
        {
            &hf_rdt_unparsed,
            {
                "Unparsed Data",
                "rdt.unparsed",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
               "", HFILL
            }
        }
    };

    static gint *ett[] =
    {
        &ett_rdt,
        &ett_rdt_setup
    };

    module_t *rdt_module;

    /* Register protocol and fields */
    proto_rdt = proto_register_protocol("Real Data Transport", "RDT", "rdt");
    proto_register_field_array(proto_rdt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("rdt", dissect_rdt, proto_rdt);

    /* Preference settings */
    rdt_module = prefs_register_protocol(proto_rdt, NULL);
    prefs_register_bool_preference(rdt_module, "show_setup_info",
                                   "Show stream setup information",
                                   "Where available, show which protocol and frame caused "
                                   "this RDT stream to be created",
                                   &global_rdt_show_setup_info);

    register_init_routine( &rdt_init );
}

void
proto_reg_handoff_rdt(void)
{
    rdt_handle = find_dissector("rdt");    
}

