/* packet-mms-control.c
 *
 * Routines for MMS control message dissection
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

#include "packet-tcp.h"

static dissector_handle_t mms_command_handle;

static gint    proto_mms_command                         = -1;

/* Fields */

/* Command header */
static gint    hf_mms_command_common_header              = -1;
static gint    hf_mms_command_version                    = -1;
static gint    hf_mms_command_signature                  = -1;
static gint    hf_mms_command_length                     = -1;
static gint    hf_mms_command_protocol_type              = -1;
static gint    hf_mms_command_length_remaining           = -1;
static gint    hf_mms_command_sequence_number            = -1;
static gint    hf_mms_command_timestamp                  = -1;
static gint    hf_mms_command_length_remaining2          = -1;
static gint    hf_mms_command_to_client_id               = -1;
static gint    hf_mms_command_to_server_id               = -1;
static gint    hf_mms_command_direction                  = -1;

static gint    hf_mms_command_prefix1                    = -1;
static gint    hf_mms_command_prefix2                    = -1;
static gint    hf_mms_command_unknown                    = -1;

static gint    hf_mms_command_client_transport_info      = -1;
static gint    hf_mms_command_client_player_info         = -1;


/* Subtrees */
static gint    ett_mms_command                           = -1;
static gint    ett_mms_command_common_header             = -1;


#define MMS_TCP_PORT 1755

extern void mms_data_add_address(packet_info *pinfo, address *addr,
                                 port_type pt, int port);


/* Main dissection function */
static void dissect_mms_command_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Command details */
static void dissect_client_transport_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          guint offset, guint length_remaining);
static void dissect_client_player_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       guint offset, guint length_remaining);


/* Known command types */

#define SERVER_COMMAND_CONNECT_INFO                0x01
#define SERVER_COMMAND_TRANSPORT_INFO              0x02
#define SERVER_COMMAND_PROTOCOL_SELECTION_ERROR    0x03
#define SERVER_COMMAND_REQUEST_SERVER_FILE         0x05
#define SERVER_COMMAND_START_SENDING_FROM          0x07
#define SERVER_COMMAND_STOP_BUTTON_PRESSED         0x09
#define SERVER_COMMAND_CANCEL_PROTOCOL             0x0d
#define SERVER_COMMAND_HEADER_REQUEST              0x15
#define SERVER_COMMAND_TIMING_TEST_DATA_RESPONSE   0x18
#define SERVER_COMMAND_AUTHENTICATION_RESPONSE     0x1a
#define SERVER_COMMAND_NETWORK_TIMER_TEST_RESPONSE 0x1b
#define SERVER_COMMAND_ACTIVATE_FF_RW_BUTTONS      0x28
#define SERVER_COMMAND_HAVE_STOPPED_PLAYING        0x30
#define SERVER_COMMAND_LOCAL_COMPUTER_DETAILS      0x32
#define SERVER_COMMAND_MEDIA_STREAM_MBR_SELECTOR   0x33

static const value_string to_server_command_vals[] =
{
    { SERVER_COMMAND_CONNECT_INFO,                "Connect info" },
    { SERVER_COMMAND_TRANSPORT_INFO,              "Transport info" },
    { SERVER_COMMAND_PROTOCOL_SELECTION_ERROR,    "Protocol selection error" },
    { SERVER_COMMAND_REQUEST_SERVER_FILE,         "Request server file"  },
    { SERVER_COMMAND_START_SENDING_FROM,          "Start sending from.." },
    { SERVER_COMMAND_STOP_BUTTON_PRESSED,         "Stop button pressed" },
    { SERVER_COMMAND_CANCEL_PROTOCOL,             "Cancel protocol" },
    { SERVER_COMMAND_HEADER_REQUEST,              "Header request" },
    { SERVER_COMMAND_TIMING_TEST_DATA_RESPONSE,   "Timing test data request" },
    { SERVER_COMMAND_AUTHENTICATION_RESPONSE,     "Authentication response" },
    { SERVER_COMMAND_NETWORK_TIMER_TEST_RESPONSE, "Network timer test response" },
    { SERVER_COMMAND_ACTIVATE_FF_RW_BUTTONS,      "Activate FF/Rewind buttons" },
    { SERVER_COMMAND_HAVE_STOPPED_PLAYING,        "Have stopped playing" },
    { SERVER_COMMAND_LOCAL_COMPUTER_DETAILS,      "Local computer details" },
    { SERVER_COMMAND_MEDIA_STREAM_MBR_SELECTOR,   "Media Stream MBR selector" },
    { 0,      NULL }
};


#define CLIENT_COMMAND_SERVER_INFO                0x01
#define CLIENT_COMMAND_TRANSPORT_INFO_ACK         0x02
#define CLIENT_COMMAND_PROTOCOL_SELECTION_ERROR   0x03
#define CLIENT_COMMAND_SENDING_MEDIA_FILE_NOW     0x05
#define CLIENT_COMMAND_MEDIA_DETAILS              0x06
#define CLIENT_COMMAND_FF_RW                      0x0a
#define CLIENT_COMMAND_SENDING_HEADER_RESPONSE    0x11
#define CLIENT_COMMAND_TIMING_TEST_DATA_RESPONSE  0x15
#define CLIENT_COMMAND_TIMING_TEST_DATA_REQUEST   0x18
#define CLIENT_COMMAND_AUTHENTICATION_CHALLENGE   0x1a
#define CLIENT_COMMAND_NETWORK_TIMER_TEST         0x1b
#define CLIENT_COMMAND_END_OF_MEDIA_STREAM        0x1e
#define CLIENT_COMMAND_MEDIA_CHANGING_INDICATOR   0x20
#define CLIENT_COMMAND_STREAM_SELECTION_INDICATOR 0x21

static const value_string to_client_command_vals[] =
{
    { CLIENT_COMMAND_SERVER_INFO,                "Server info" },
    { CLIENT_COMMAND_TRANSPORT_INFO_ACK,         "Transport info ack" },
    { CLIENT_COMMAND_PROTOCOL_SELECTION_ERROR,   "Protocol selection error" },
    { CLIENT_COMMAND_SENDING_MEDIA_FILE_NOW,     "Sending media file now"  },
    { CLIENT_COMMAND_MEDIA_DETAILS,              "Media details"  },
    { CLIENT_COMMAND_FF_RW,                      "FF/Rewind" },
    { CLIENT_COMMAND_SENDING_HEADER_RESPONSE,    "Sending header response" },
    { CLIENT_COMMAND_TIMING_TEST_DATA_RESPONSE,  "Timing test data response" },
    { CLIENT_COMMAND_TIMING_TEST_DATA_REQUEST,   "Timing test data request" },
    { CLIENT_COMMAND_AUTHENTICATION_CHALLENGE,   "Authentication challenge" },
    { CLIENT_COMMAND_NETWORK_TIMER_TEST,         "Network timer test" },
    { CLIENT_COMMAND_END_OF_MEDIA_STREAM,        "End of media stream" },
    { CLIENT_COMMAND_MEDIA_CHANGING_INDICATOR,   "Media changing indicator" },
    { CLIENT_COMMAND_STREAM_SELECTION_INDICATOR, "Stream selection indicator" },
    { 0,      NULL }
};

/* Command direction */

#define  TO_SERVER      0x03
#define  TO_CLIENT      0x04

static const value_string command_direction_vals[] =
{
    { TO_SERVER,  "To Server"},
    { TO_CLIENT,  "To Client"},
    { 0, NULL }
};


/**************************************************************************/
/* Packet dissection functions                                            */
/**************************************************************************/
static void dissect_mms_command_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint        offset = 0;
    proto_item  *ti = NULL;
    proto_tree  *mms_tree = NULL;
    proto_tree  *mms_common_command_tree = NULL;
    guint32     sequence_number;
    guint16     command_id;
    guint16     command_dir;
    guint32     length_remaining;

    /* Set columns */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS-c");
    }
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Control: ");
    }

    /* Create MMS control protocol tree */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_mms_command, tvb, offset, -1, FALSE);
        mms_tree = proto_item_add_subtree(ti, ett_mms_command);
    }


    /*************************/
    /* Common command header */

    /* Add a tree for common header */
    if (tree)
    {
        ti =  proto_tree_add_string(mms_tree, hf_mms_command_common_header, tvb, offset, -1,
                                    "");
        mms_common_command_tree = proto_item_add_subtree(ti, ett_mms_command_common_header);
    }

    /* Format of 1st 4 bytes unknown.  May be version... */
    offset += 4;

    /* Rude signature */
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_signature, tvb, offset, 4, TRUE);
    offset += 4;

    /* Length of command */
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_length, tvb, offset, 4, TRUE);
    offset += 4;

    /* Protocol name */
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_protocol_type, tvb, offset, 4, TRUE);
    offset += 4;

    /* Remaining length in multiples of 8 bytes */
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_length_remaining, tvb, offset, 4, TRUE);
    offset += 4;

    /* Sequence number */
    sequence_number = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_sequence_number, tvb, offset, 4, TRUE);
    offset += 4;

    /* Timestamp */
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_timestamp, tvb, offset, 8, TRUE);
    offset += 8;

    /* Another length remaining field... */
    length_remaining = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_length_remaining2, tvb, offset, 4, TRUE);
    offset += 4;

    /* Command ID */
    command_dir = tvb_get_letohs(tvb, offset+2);
    command_id = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(mms_common_command_tree,
                        (command_id == TO_SERVER) ?
                            hf_mms_command_to_server_id :
                            hf_mms_command_to_client_id,
                        tvb, offset, 2, TRUE);
    offset += 2;

    /* Command direction */
    proto_tree_add_item(mms_common_command_tree, hf_mms_command_direction, tvb, offset, 2, TRUE);
    offset += 2;

    /* This is the end of the common command header */
    proto_item_set_len(mms_common_command_tree, offset);


    /* Show summary in info column */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "s=%03u: %s %s",
                        sequence_number,
                        (command_dir == TO_SERVER) ? "-->" : "<--",
                        (command_dir == TO_SERVER) ?
                            val_to_str(command_id, to_server_command_vals, "Unknown") :
                            val_to_str(command_id, to_client_command_vals, "Unknown"));
    }

    /* Adjust this value for passing to command-specific details */
    length_remaining = (length_remaining*8) - 8;

    /* Now parse command-specific params */
    if (command_dir == TO_SERVER)
    {
        /* Commands to server */
        switch (command_id)
        {
            case SERVER_COMMAND_TRANSPORT_INFO:
                dissect_client_transport_info(tvb, pinfo, mms_tree,
                                              offset, length_remaining);
                break;
            case SERVER_COMMAND_CONNECT_INFO:
                dissect_client_player_info(tvb, pinfo, mms_tree,
                                           offset, length_remaining);
                break;
            /* TODO: other commands */

            default:
                break;
        }
    }
    else
    {
        /* Commands to client */
        switch (command_id)
        {
            /* TODO commands: */
            default:
                break;
        }
    }
}

/* Return the number of bytes in this PDU */
static guint32 get_mms_command_pdu_len(tvbuff_t *tvb, gint offset)
{
    return tvb_get_letohl(tvb, offset+8) + 16;
}

/* Dissect a TCP command PDU */
static void dissect_mms_command_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree,
                     TRUE,  /* i.e. always desegment */
                     12,    /* Must have 12 bytes to determine length */
                     get_mms_command_pdu_len,
                     dissect_mms_command_pdu);
}


/******************************/
/* Individual command details */
/******************************/

/* Transport information (address, port, etc) */
void dissect_client_transport_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   guint offset, guint length_remaining)
{
    char    *transport_info = "";
    guint   ipaddr[4];
    char    protocol[3];
    guint   port;
    int fields_matched;

    /* These are flags */
    proto_tree_add_item(tree, hf_mms_command_prefix1, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_mms_command_prefix1, tvb, offset, 4, TRUE);
    offset += 4;

    /* These 12 bytes are not understood */
    proto_tree_add_item(tree, hf_mms_command_unknown, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_mms_command_unknown, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_mms_command_unknown, tvb, offset, 4, TRUE);
    offset += 4;

    /* Extract and show the string in tree and info column */
    transport_info = tvb_fake_unicode(tvb, offset, (length_remaining - 20)/2, TRUE);

    proto_tree_add_string_format(tree, hf_mms_command_client_transport_info, tvb,
                                 offset, length_remaining-20,
                                 transport_info, "Transport: (%s)", transport_info);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", transport_info);
    }


    /* Extract details from this string */
    fields_matched = sscanf(transport_info, "%*c%*c%u.%u.%u.%u%*c%3s%*c%u",
                            &ipaddr[0], &ipaddr[1], &ipaddr[2], &ipaddr[3],
                            protocol, &port);

    /* Use this information to set up a conversation for the data stream */
    if (fields_matched == 6)
    {
        port_type pt = PT_NONE;

        /* Work out the port type */
        if (strncmp(protocol, "UDP", 3) == 0)
        {
            pt = PT_UDP;
        }
/*      TODO: add when tested with capture
        else
        if (strncmp(protocol, "TCP", 3) == 0)
        {
            pt = PT_TCP;
        }
*/
        /* Set the dissector for indicated conversation */
        if (pt != PT_NONE)
        {
            guint8 octets[4] = {ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]};

            address addr = {AT_IPv4, 4, octets};
            mms_data_add_address(pinfo, &addr, pt, port);
        }
    }

    /* Can now free this string */
    if (transport_info != NULL && strlen(transport_info))
    {
        g_free(transport_info);
    }
}

/* Player (client) information */
void dissect_client_player_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                guint offset, guint length_remaining)
{
    char *player_info = "";

    /* These are flags */
    proto_tree_add_item(tree, hf_mms_command_prefix1, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_mms_command_prefix1, tvb, offset, 4, TRUE);
    offset += 4;

    /* These 4 bytes are not understood */
    proto_tree_add_item(tree, hf_mms_command_unknown, tvb, offset, 4, TRUE);
    offset += 4;

    /* Extract and show the string in tree and info column */
    player_info = tvb_fake_unicode(tvb, offset, (length_remaining - 12)/2, TRUE);

    proto_tree_add_string_format(tree, hf_mms_command_client_player_info, tvb,
                                 offset, length_remaining-12,
                                 player_info, "Player details: (%s)", player_info);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", player_info);
    }

    /* Can now free this string */
    if (player_info != NULL && strlen(player_info))
    {
        g_free(player_info);
    }
}


/*************************/
/* Register protocol     */
void proto_register_mms_command(void)
{
    static hf_register_info hf[] =
    {
        {
            &hf_mms_command_common_header,
            {
                "Command common header",
                "mms.command.common-header",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "MMS command common header", HFILL
            }
        },

        {
            &hf_mms_command_version,
            {
                "Version",
                "mms.command.version",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_signature,
            {
                "Command signature",
                "mms.command.signature",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_length,
            {
                "Command length",
                "mms.command.length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_protocol_type,
            {
                "Protocol type",
                "mms.command.protocol-type",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_length_remaining,
            {
                "Length until end (8-byte blocks)",
                "mms.command.length-remaining",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_sequence_number,
            {
                "Sequence number",
                "mms.command.sequence-number",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_timestamp,
            {
                "Time stamp (s)",
                "mms.command.timestamp",
                FT_DOUBLE,
                BASE_NONE,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_length_remaining2,
            {
                "Length until end (8-byte blocks)",
                "mms.command.length-remaining2",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_to_server_id,
            {
                "Command",
                "mms.command.to-server-id",
                FT_UINT16,
                BASE_HEX,
                VALS(to_server_command_vals),
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_to_client_id,
            {
                "Command",
                "mms.command.to-client-id",
                FT_UINT16,
                BASE_HEX,
                VALS(to_client_command_vals),
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_direction,
            {
                "Command direction",
                "mms.command.direction",
                FT_UINT16,
                BASE_HEX,
                VALS(command_direction_vals),
                0x0,
                "", HFILL
            }
        },

        {
            &hf_mms_command_prefix1,
            {
                "Prefix 1",
                "mms.command.prefix1",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_prefix2,
            {
                "Prefix 2",
                "mms.command.prefix2",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_unknown,
            {
                "Unknown",
                "mms.command.unknown",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_client_transport_info,
            {
                "Client transport info",
                "mms.command.client-transport-info",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "", HFILL
            }
        },
        {
            &hf_mms_command_client_player_info,
            {
                "Player info",
                "mms.command.player-info",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "", HFILL
            }
        }
    };

    static gint *ett[] =
    {
        &ett_mms_command,
        &ett_mms_command_common_header
    };

    /* Register protocol and fields */
    proto_mms_command = proto_register_protocol("Microsoft Media Server Control",
                                                "MMS-c", "mms-c");
    proto_register_field_array(proto_mms_command, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("mms-c", dissect_mms_command_pdu, proto_mms_command);
}

void proto_reg_handoff_mms_command(void)
{
    mms_command_handle = create_dissector_handle(dissect_mms_command_tcp,
                                                 proto_mms_command);
    dissector_add("tcp.port", MMS_TCP_PORT, mms_command_handle);
}


