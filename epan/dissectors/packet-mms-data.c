/* packet-mms-data.c
 *
 * Routines for MMS data message dissection
 * MMS = Microsoft Media Server
 *
 * Copyright 2005
 * Written by Martin Mathieson
 *
 * $Id: packet-rdt.c 14456 2005-05-27 18:35:19Z etxrab $
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

/* Information sources:
 * sdp.ppona.com
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/conversation.h>

static dissector_handle_t mms_data_handle;

static gint   proto_mms_data                             = -1;

/* Fields */

/* Pre-header fields */
static gint   hf_mms_data_sequence_number                = -1;
static gint   hf_mms_data_packet_id_type                 = -1;
static gint   hf_mms_data_packet_length                  = -1;

/* UDP command fields */
static gint   hf_mms_data_header_id                      = -1;
static gint   hf_mms_data_client_id                      = -1;
static gint   hf_mms_data_command_id                     = -1;
static gint   hf_mms_data_packet_to_resend               = -1;

static gint   ett_mms_data                               = -1;

#define MMS_UDP_COMMAND_PORT 1755

/* Parse the only known UDP command (0x01) */
static void dissect_mms_data_udp_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;

    /* Header ID */
    proto_tree_add_item(tree, hf_mms_data_header_id, tvb, offset, 4, TRUE);
    offset += 4;

    /* Client ID */
    proto_tree_add_item(tree, hf_mms_data_client_id, tvb, offset, 4, TRUE);
    offset += 4;

    /* Command ID */
    proto_tree_add_item(tree, hf_mms_data_command_id, tvb, offset, 2, TRUE);
    offset += 4;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_add_str(pinfo->cinfo, COL_INFO, "Request to resend packet(s):");
    }

    /* Show list of packets to resend */
    while (tvb_length_remaining(tvb, offset) >= 4)
    {
        guint32 packet_number = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(tree, hf_mms_data_packet_to_resend, tvb, offset, 4, TRUE);
        offset += 4;

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %u", packet_number);
        }
    }
}


/****************************************************************************/
/* Main dissection function                                                 */
/****************************************************************************/
static void dissect_mms_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    proto_item  *ti = NULL;
    proto_tree  *mms_tree = NULL;
    guint32 sequence_number;
    guint16 packet_length;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS-d");
    }

    /* Create MMS data protocol tree */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_mms_data, tvb, offset, -1, FALSE);
        mms_tree = proto_item_add_subtree(ti, ett_mms_data);
    }

    /* May be the command asking for packets to be resent */
    if ((pinfo->ptype == PT_UDP) && (pinfo->destport == MMS_UDP_COMMAND_PORT))
    {
        dissect_mms_data_udp_command(tvb, pinfo, mms_tree);
        return;
    }

    /* Sequence number */
    sequence_number = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(mms_tree, hf_mms_data_sequence_number, tvb, offset, 4, TRUE);
    offset += 4;

    /* Packet ID type */
    proto_tree_add_item(mms_tree, hf_mms_data_packet_id_type, tvb, offset, 1, TRUE);
    offset++;

    /* TODO: flags depending upon whether UDP or TCP */
    offset++;

    /* Packet Length */
    packet_length = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(mms_tree, hf_mms_data_packet_length, tvb, offset, 2, TRUE);
    offset += 2;

    /* Show summary in info column */
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Data: s=%05u, l=%05u",
                     sequence_number, packet_length);
    }
}


/* Set up an MMS-d conversation */
void mms_data_add_address(packet_info *pinfo, address *addr, port_type pt, int port)
{
    address null_addr;
    conversation_t* p_conv;

    /* If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again. */
    if (pinfo->fd->flags.visited)
    {
        return;
    }

    SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

    /* Check if the ip address and port combination is not
     * already registered as a conversation. */
    p_conv = find_conversation(pinfo->fd->num, addr, &null_addr, pt, port, 0,
                               NO_ADDR_B | NO_PORT_B);

    /* If not, create a new conversation. */
    if (!p_conv)
    {
        p_conv = conversation_new(pinfo->fd->num, addr, &null_addr, pt,
                                  (guint32)port, 0, NO_ADDR2 | NO_PORT2);
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, mms_data_handle);
}


/**************************/
/* Register protocol      */
void proto_register_mms_data(void)
{
    static hf_register_info hf[] =
    {
        {
            &hf_mms_data_sequence_number,
            {
                "Sequence number",
                "mms.data.sequence",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_data_packet_id_type,
            {
                "Packet ID type",
                "mms.data.packet-id-type",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_data_packet_length,
            {
                "Packet length",
                "mms.data.packet-length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },

        {
            &hf_mms_data_header_id,
            {
                "Header ID",
                "mms.data.header-id",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_data_client_id,
            {
                "Client ID",
                "mms.data.client-id",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_data_command_id,
            {
                "Command ID",
                "mms.data.command-id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_data_packet_to_resend,
            {
                "Packet to resend",
                "mms.data.packet-to-resend",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_mms_data
    };

    /* Register protocol and fields */
    proto_mms_data = proto_register_protocol("Microsoft Media Server Data",
                                             "MMS-d", "mms-d");
    proto_register_field_array(proto_mms_data, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("mms-d", dissect_mms_data, proto_mms_data);
}

void proto_reg_handoff_mms_data(void)
{
    mms_data_handle = find_dissector("mms-d");
    dissector_add_handle("udp.port", mms_data_handle);
    dissector_add_handle("tcp.port", mms_data_handle);
    dissector_add("udp.port", MMS_UDP_COMMAND_PORT, mms_data_handle);
}


