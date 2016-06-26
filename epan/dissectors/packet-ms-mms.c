/* packet-ms-mms.c
 *
 * Routines for MicroSoft MMS (Microsoft Media Server) message dissection
 *
 * See
 *
 *    http://msdn.microsoft.com/en-us/library/cc234711.aspx
 *
 * for the [MS-MMSP] specification.
 *
 * Copyright 2005
 * Written by Martin Mathieson
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

/* Information sources:
 * sdp.ppona.com
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>

static dissector_handle_t msmms_handle;
static gint               proto_msmms                      = -1;


/* Command fields */
static gint   hf_msmms_command                             = -1;
static gint   hf_msmms_command_common_header               = -1;
/* static gint   hf_msmms_command_version                     = -1; */
static gint   hf_msmms_command_signature                   = -1;
static gint   hf_msmms_command_length                      = -1;
static gint   hf_msmms_command_protocol_type               = -1;
static gint   hf_msmms_command_length_remaining            = -1;
static gint   hf_msmms_command_sequence_number             = -1;
static gint   hf_msmms_command_timestamp                   = -1;
static gint   hf_msmms_command_length_remaining2           = -1;
static gint   hf_msmms_command_to_client_id                = -1;
static gint   hf_msmms_command_to_server_id                = -1;
static gint   hf_msmms_command_direction                   = -1;

static gint   hf_msmms_command_prefix1                     = -1;
static gint   hf_msmms_command_prefix1_error               = -1;
static gint   hf_msmms_command_prefix1_command_level       = -1;
static gint   hf_msmms_command_prefix2                     = -1;

static gint   hf_msmms_command_client_transport_info       = -1;
static gint   hf_msmms_command_client_player_info          = -1;

static gint   hf_msmms_command_server_version              = -1;
static gint   hf_msmms_command_tool_version                = -1;
static gint   hf_msmms_command_update_url                  = -1;
static gint   hf_msmms_command_password_type               = -1;

static gint   hf_msmms_command_server_version_length       = -1;
static gint   hf_msmms_command_tool_version_length         = -1;
static gint   hf_msmms_command_update_url_length           = -1;
static gint   hf_msmms_command_password_type_length        = -1;

static gint   hf_msmms_command_number_of_words             = -1;
static gint   hf_msmms_command_client_id                   = -1;
static gint   hf_msmms_command_server_file                 = -1;

static gint   hf_msmms_command_result_flags                = -1;

static gint   hf_msmms_command_broadcast_indexing          = -1;
static gint   hf_msmms_command_broadcast_liveness          = -1;

static gint   hf_msmms_command_recorded_media_length       = -1;
static gint   hf_msmms_command_media_packet_length         = -1;

static gint   hf_msmms_command_strange_string              = -1;

static gint   hf_msmms_command_stream_structure_count      = -1;
static gint   hf_msmms_stream_selection_flags              = -1;
static gint   hf_msmms_stream_selection_stream_id          = -1;
static gint   hf_msmms_stream_selection_action             = -1;

static gint   hf_msmms_command_header_packet_id_type       = -1;


/* Data fields */
static gint   hf_msmms_data                                = -1;
static gint   hf_msmms_data_sequence_number                = -1;
static gint   hf_msmms_data_packet_id_type                 = -1;
static gint   hf_msmms_data_udp_sequence                   = -1;
static gint   hf_msmms_data_tcp_flags                      = -1;
static gint   hf_msmms_data_packet_length                  = -1;

static gint   hf_msmms_data_header_id                      = -1;
static gint   hf_msmms_data_client_id                      = -1;
static gint   hf_msmms_data_command_id                     = -1;
static gint   hf_msmms_data_packet_to_resend               = -1;

static gint   hf_msmms_data_timing_pair                    = -1;
static gint   hf_msmms_data_timing_pair_seqno              = -1;
static gint   hf_msmms_data_timing_pair_flags              = -1;
static gint   hf_msmms_data_timing_pair_id                 = -1;
static gint   hf_msmms_data_timing_pair_flag               = -1;
static gint   hf_msmms_data_timing_pair_packet_length      = -1;

static gint   hf_msmms_data_unparsed                       = -1;


/* Subtrees */
static gint   ett_msmms_command                            = -1;
static gint   ett_msmms_command_common_header              = -1;
static gint   ett_msmms_data                               = -1;
static gint   ett_msmms_data_timing_packet_pair            = -1;

#define MSMMS_PORT 1755


/* Known command IDs */
#define SERVER_COMMAND_CONNECT_INFO                0x01
#define SERVER_COMMAND_TRANSPORT_INFO              0x02
#define SERVER_COMMAND_PROTOCOL_SELECTION_ERROR    0x03
#define SERVER_COMMAND_REQUEST_SERVER_FILE         0x05
#define SERVER_COMMAND_START_SENDING_FROM          0x07
#define SERVER_COMMAND_STOP_BUTTON_PRESSED         0x09
#define SERVER_COMMAND_CANCEL_PROTOCOL             0x0d
#define SERVER_COMMAND_HEADER_REQUEST              0x15
#define SERVER_COMMAND_TIMING_TEST_DATA_REQUEST    0x18
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
    { SERVER_COMMAND_START_SENDING_FROM,          "Start sending from:" },
    { SERVER_COMMAND_STOP_BUTTON_PRESSED,         "Stop button pressed" },
    { SERVER_COMMAND_CANCEL_PROTOCOL,             "Cancel protocol" },
    { SERVER_COMMAND_HEADER_REQUEST,              "Header request" },
    { SERVER_COMMAND_TIMING_TEST_DATA_REQUEST,    "Timing test data request" },
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

#define  TO_SERVER      0x0003
#define  TO_CLIENT      0x0004

static const value_string command_direction_vals[] =
{
    { TO_SERVER,  "To Server"},
    { TO_CLIENT,  "To Client"},
    { 0, NULL }
};

static const value_string tcp_flags_vals[] =
{
    { 0x00,     "Middle of packet series" },
    { 0x04,     "First packet of a packet series" },
    { 0x08,     "Last packet of a packet series" },
    { 0x0C,     "There is only one packet in this series"  },
    { 0x10,     "UDP packet pair timing packet" },
    { 0,        NULL }
};

static const value_string media_result_flags_vals[] =
{
    { 0x01,  "Media file name was accepted (no auth)"},
    { 0x02,  "Authentication for this media was accepted (BASIC auth)"},
    { 0x03,  "Authentication accepted (NTLM auth)"},
    { 0, NULL }
};

static const value_string broadcast_indexing_vals[] =
{
    { 0x00,  "No indexed seeking (live or no video streams)"},
    { 0x80,  "Indexed seeking (video streams available)"},
    { 0, NULL }
};

static const value_string broadcast_liveness_vals[] =
{
    { 0x01,  "Pre-recorded broadcast"},
    { 0x02,  "Live broadcast"},
    { 0x42,  "Presentation which includes a script command"},
    { 0, NULL }
};

static const value_string stream_selection_action_vals[] =
{
    { 0x00,  "Stream at full frame rate"},
    { 0x01,  "Only stream key frames"},
    { 0x02,  "No stream, switch it off"},
    { 0, NULL }
};


/* Server to client error codes */
static const value_string server_to_client_error_vals[] =
{
    { 0x00000000,  "OK"},
    { 0xC00D001A,  "File was not found"},
    { 0xC00D000E,  "The network is busy"},
    { 0xC00D000F,  "Too many connection sessions to server exist, cannot connect"},
    { 0xC00D0029,  "The network has failed - connection was lost"},
    { 0xC00D0034,  "There is no more data in the stream (UDP)"},
    { 0x80070005,  "You do not have access to the location or file"},
    { 0xC00D0013,  "There was no timely response from the server"},
    { 0x80070057,  "A parameter in the location is incorrect"},
    { 0x8000FFFF,  "File failed to open"},
    { 0, NULL }
};




/*************************/
/* Function declarations */
void proto_register_msmms(void);
void proto_reg_handoff_msmms_command(void);

static gint dissect_msmms_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint dissect_msmms_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint dissect_msmms_data_udp_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_client_transport_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          guint offset, guint length_remaining);
static void dissect_server_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                guint offset);
static void dissect_client_player_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       guint offset, guint length_remaining);
static void dissect_start_sending_from_info(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_cancel_info(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_timing_test_request(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_timing_test_response(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_request_server_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        guint offset, guint length_remaining);
static void dissect_media_details(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_header_response(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_network_timer_test_response(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_transport_info_response(tvbuff_t *tvb, proto_tree *tree, guint offset,
                                            guint length_remaining);
static void dissect_media_stream_mbr_selector(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_header_request(tvbuff_t *tvb, proto_tree *tree, guint offset);
static void dissect_stop_button_pressed(tvbuff_t *tvb, proto_tree *tree, guint offset);

static void msmms_data_add_address(packet_info *pinfo, address *addr, port_type pt, int port);



/****************************/
/* Main dissection function */
/****************************/
static gint dissect_msmms_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Work out what type of packet this is and dissect it as such */

    /* Just don't dissect if can't even read command signature */
    if (tvb_captured_length(tvb) < 8) {
        return 0;
    }

    /* Command */
    if (tvb_get_letohl(tvb, 4) == 0xb00bface)
    {
        return dissect_msmms_command(tvb, pinfo, tree);
    }
    else
    /* UDP data command */
    if ((pinfo->ptype == PT_UDP) && (pinfo->destport == MSMMS_PORT))
    {
        return dissect_msmms_data_udp_command(tvb, pinfo, tree);
    }
    else
    /* Assume data (don't consider frames from client->server data...) */
    if (pinfo->destport != MSMMS_PORT)
    {
        return dissect_msmms_data(tvb, pinfo, tree);
    }

    /* It was none of the above so assume not really an MMS packet */
    return 0;
}


/*************************************/
/* Dissection of different PDU types */
/*************************************/

/* Dissect command packet */
static gint dissect_msmms_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint        offset                    = 0;
    proto_item *ti;
    proto_tree *msmms_tree;
    proto_tree *msmms_common_command_tree;
    guint32     sequence_number;
    guint16     command_id;
    guint16     command_dir;
    gint32      length_of_command;
    guint32     length_remaining;

    /******************************/
    /* Check for available length */

    /* Need to have enough bytes for length field */
    if (tvb_reported_length_remaining(tvb, offset) < 12)
    {
        pinfo->desegment_offset = 0;  /* Start at beginning next time */
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;     /* Need one more byte to try again */
        return -1;
    }

    /* Read length field and see if we're short */
    length_of_command = tvb_get_letohl(tvb, offset+8);
    if (tvb_reported_length_remaining(tvb, 16) < length_of_command)
    {
        pinfo->desegment_offset = 0; /* Start at beginning next time */
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;   /* Need one more byte to try again */
        return -1;
    }


    /* Set columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSMMS");
    col_set_str(pinfo->cinfo, COL_INFO, "Command: ");

    /* Add hidden filter for "msmms.command" */
    ti = proto_tree_add_item(tree, hf_msmms_command, tvb, 0, 0, ENC_ASCII|ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti);

    /* Create MSMMS control protocol tree */
    ti = proto_tree_add_item(tree, proto_msmms, tvb, offset, -1, ENC_NA);
    msmms_tree = proto_item_add_subtree(ti, ett_msmms_command);


    /* Read command ID and direction now so can give common command header a
       descriptive label */
    command_id = tvb_get_letohs(tvb, 36);
    command_dir = tvb_get_letohs(tvb, 36+2);


    /*************************/
    /* Common command header */

    /* Add a tree for common header */
    ti =  proto_tree_add_string_format(msmms_tree, hf_msmms_command_common_header, tvb, offset, -1,
            "",
            "%s (to %s)",
            (command_dir == TO_SERVER) ?
            val_to_str_const(command_id, to_server_command_vals, "Unknown") :
            val_to_str_const(command_id, to_client_command_vals, "Unknown"),
            (command_dir == TO_SERVER) ? "server" : "client");
    msmms_common_command_tree = proto_item_add_subtree(ti, ett_msmms_command_common_header);

    /* Format of 1st 4 bytes unknown.  May be version... */
    offset += 4;

    /* Signature (already verified by main dissection function) */
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Length of command */
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Protocol name.  Must be "MMS"... */
    if (strncmp((char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 3, ENC_ASCII), "MMS", 3) != 0)
    {
        return offset;
    }
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_protocol_type, tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;

    /* Remaining length in multiples of 8 bytes */
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_length_remaining, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Sequence number */
    sequence_number = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Timestamp */
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Another length remaining field... */
    length_remaining = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_length_remaining2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Command depends up on direction */
    proto_tree_add_item(msmms_common_command_tree,
                        (command_dir == TO_SERVER) ?
                            hf_msmms_command_to_server_id :
                            hf_msmms_command_to_client_id,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Direction */
    proto_tree_add_item(msmms_common_command_tree, hf_msmms_command_direction, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* This is the end of the common command header */
    proto_item_set_len(msmms_common_command_tree, offset);


    /* Show summary in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO,
                    "seq=%03u: %s %s",
                    sequence_number,
                    (command_dir == TO_SERVER) ? "-->" : "<--",
                    (command_dir == TO_SERVER) ?
                        val_to_str_const(command_id, to_server_command_vals, "Unknown") :
                        val_to_str_const(command_id, to_client_command_vals, "Unknown"));

    /* Adjust length_remaining for command-specific details */
    length_remaining = (length_remaining*8) - 8;

    /* Now parse any command-specific params */
    if (command_dir == TO_SERVER)
    {
        /* Commands to server */
        switch (command_id)
        {
            case SERVER_COMMAND_TRANSPORT_INFO:
                dissect_client_transport_info(tvb, pinfo, msmms_tree,
                                              offset, length_remaining);
                break;
            case SERVER_COMMAND_CONNECT_INFO:
                dissect_client_player_info(tvb, pinfo, msmms_tree,
                                           offset, length_remaining);
                break;
            case SERVER_COMMAND_START_SENDING_FROM:
                dissect_start_sending_from_info(tvb, msmms_tree, offset);
                break;
            case SERVER_COMMAND_CANCEL_PROTOCOL:
                dissect_cancel_info(tvb, msmms_tree, offset);
                break;
            case SERVER_COMMAND_TIMING_TEST_DATA_REQUEST:
                dissect_timing_test_request(tvb, tree, offset);
                break;
            case SERVER_COMMAND_REQUEST_SERVER_FILE:
                dissect_request_server_file(tvb, pinfo, tree, offset, length_remaining);
                break;
            case SERVER_COMMAND_NETWORK_TIMER_TEST_RESPONSE:
                dissect_network_timer_test_response(tvb, tree, offset);
                break;
            case SERVER_COMMAND_MEDIA_STREAM_MBR_SELECTOR:
                dissect_media_stream_mbr_selector(tvb, tree, offset);
                break;
            case SERVER_COMMAND_HEADER_REQUEST:
                dissect_header_request(tvb, tree, offset);
                break;
            case SERVER_COMMAND_STOP_BUTTON_PRESSED:
                dissect_stop_button_pressed(tvb, tree, offset);
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
            case CLIENT_COMMAND_SERVER_INFO:
                dissect_server_info(tvb, pinfo, msmms_tree, offset);
                break;
            case CLIENT_COMMAND_TIMING_TEST_DATA_RESPONSE:
                dissect_timing_test_response(tvb, tree, offset);
                break;
            case CLIENT_COMMAND_MEDIA_DETAILS:
                dissect_media_details(tvb, tree, offset);
                break;
            case CLIENT_COMMAND_SENDING_HEADER_RESPONSE:
                dissect_header_response(tvb, tree, offset);
                break;
            case CLIENT_COMMAND_TRANSPORT_INFO_ACK:
                dissect_transport_info_response(tvb, tree, offset, length_remaining);
                break;

            /* TODO: other commands: */
            default:
                break;
        }
    }

    /* Got to the end so assume it belongs to this protocol */
    return length_of_command + 12;
}


/* Parse the only known UDP command (0x01) */
static gint dissect_msmms_data_udp_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *msmms_tree;
    gint        offset     = 0;

    /* Set protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSMMS");

    /* Create MSMMS data protocol tree */
    ti = proto_tree_add_item(tree, proto_msmms, tvb, offset, -1, ENC_NA);
    msmms_tree = proto_item_add_subtree(ti, ett_msmms_data);

    /* Header ID */
    proto_tree_add_item(msmms_tree, hf_msmms_data_header_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Client ID */
    proto_tree_add_item(msmms_tree, hf_msmms_data_client_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Command ID */
    proto_tree_add_item(msmms_tree, hf_msmms_data_command_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 4;

    col_set_str(pinfo->cinfo, COL_INFO, "Request to resend packet(s):");

    /* Show list of packets to resend */
    while (tvb_reported_length_remaining(tvb, offset) >= 4)
    {
        guint32 packet_number = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(msmms_tree, hf_msmms_data_packet_to_resend, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        col_append_fstr(pinfo->cinfo, COL_INFO, " %u", packet_number);
    }

    /* Report that whole of UDP packet was dissected */
    return tvb_reported_length_remaining(tvb, 0);
}


/* Dissect a data packet */
static gint dissect_msmms_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint        offset = 0;
    proto_item  *ti;
    proto_tree  *msmms_tree;
    proto_tree  *msmms_data_timing_pair = NULL;
    guint32     sequence_number;
    guint16     packet_length;
    guint16     packet_length_found;
    guint8      value = 0;

    /* How many bytes do we need? */
    packet_length = tvb_get_letohs(tvb, 6);

    /* How many bytes have we got? */
    packet_length_found = tvb_reported_length_remaining(tvb, 0);

    /* Reject frame reported not to reach length field */
    if (packet_length < 8)
    {
        return 0;
    }

    /* Stop and ask for more bytes if necessary */
    if (packet_length_found < packet_length)
    {
        pinfo->desegment_offset = 0;  /* Start from beginning again next time */
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;     /* Try again with even one more byte */
        return -1;
    }


    /* Will reject packet if is TCP and has invalid flag */
    if (pinfo->ptype == PT_TCP)
    {
        /* Flag value is in 5th byte */
        value = tvb_get_guint8(tvb, 5);
        /* Reject packet if not a recognised packet type */
        if (try_val_to_str(value, tcp_flags_vals) == NULL)
        {
            return 0;
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSMMS");

    /* Add hidden filter for "msmms.data" */
    ti = proto_tree_add_item(tree, hf_msmms_data, tvb, 0, 0, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti);

    /* Create MSMMS data protocol tree */
    ti = proto_tree_add_item(tree, proto_msmms, tvb, offset, -1, ENC_NA);
    msmms_tree = proto_item_add_subtree(ti, ett_msmms_data);

    /* Sequence number */
    sequence_number = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(msmms_tree, hf_msmms_data_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Packet ID type */
    proto_tree_add_item(msmms_tree, hf_msmms_data_packet_id_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* Next byte depends upon whether UDP or TCP */
    if (pinfo->ptype == PT_UDP)
    {
        /* UDP */
        proto_tree_add_item(msmms_tree, hf_msmms_data_udp_sequence, tvb,
                            offset, 1, ENC_LITTLE_ENDIAN);
    }
    else
    {
        /* TCP */
        proto_tree_add_item(msmms_tree, hf_msmms_data_tcp_flags, tvb,
                            offset, 1, ENC_LITTLE_ENDIAN);
    }
    offset++;

    /* Packet Length */
    packet_length = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(msmms_tree, hf_msmms_data_packet_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Parse UDP Timing packet pair headers if present */
    if (value == 0x01)
    {
        ti =  proto_tree_add_string(msmms_tree, hf_msmms_data_timing_pair, tvb, offset, 8, "");
        msmms_data_timing_pair = proto_item_add_subtree(ti, ett_msmms_data_timing_packet_pair);

        proto_tree_add_item(msmms_data_timing_pair, hf_msmms_data_timing_pair_seqno, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(msmms_data_timing_pair, hf_msmms_data_timing_pair_flags, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
        proto_tree_add_item(msmms_data_timing_pair, hf_msmms_data_timing_pair_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(msmms_data_timing_pair, hf_msmms_data_timing_pair_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(msmms_data_timing_pair, hf_msmms_data_timing_pair_packet_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    /* Everything else is marked as unparsed data */
    proto_tree_add_item(msmms_tree, hf_msmms_data_unparsed, tvb, offset, packet_length-offset, ENC_NA);
    offset = packet_length;

    /* Show summary in info column */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Data: seq=%05u, len=%05u",
                 sequence_number, packet_length);

    /* Whole of packet length has been dissected now */
    return offset;
}



/***************************************/
/* Dissect command-specific parameters */
/***************************************/

/* Transport information (address, port, etc) */
static void dissect_client_transport_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          guint offset, guint length_remaining)
{
    char    *transport_info;
    guint   ipaddr[4];
    char    protocol[3+1] = "";
    guint   port;
    int     fields_matched;

    /* Flags */
    proto_tree_add_item(tree, hf_msmms_command_prefix1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* These 12 bytes are not understood */
    offset += 4;
    offset += 4;
    offset += 4;

    /* Extract and show the string in tree and info column */
    transport_info = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length_remaining - 20, ENC_UTF_16|ENC_LITTLE_ENDIAN);

    proto_tree_add_string_format(tree, hf_msmms_command_client_transport_info, tvb,
                                 offset, length_remaining-20,
                                 transport_info, "Transport: (%s)", transport_info);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    format_text((guchar*)transport_info, length_remaining - 20));


    /* Try to extract details from this string */
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
        else
        if (strncmp(protocol, "TCP", 3) == 0)
        {
            pt = PT_TCP;
        }

        /* Set the dissector for indicated conversation */
        if (pt != PT_NONE)
        {
            guint8 octets[4];
            address addr;
            octets[0] = ipaddr[0];
            octets[1] = ipaddr[1];
            octets[2] = ipaddr[2];
            octets[3] = ipaddr[3];
            addr.type = AT_IPv4;
            addr.len = 4;
            addr.data = octets;
            msmms_data_add_address(pinfo, &addr, pt, port);
        }
    }
}

/* Dissect server data */
static void dissect_server_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                guint offset)
{
    guint32       server_version_length;
    guint32       tool_version_length;
    guint32       download_update_player_length;
    guint32       password_encryption_type_length;
    const guint8 *server_version;

    /* ErrorCode */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_error, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Next 8 words are not understood */
    offset += 4;
    offset += 4;
    offset += 4;
    offset += 4;
    offset += 4;
    offset += 4;
    offset += 4;
    offset += 4;


    /* Length of server version */
    server_version_length = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_msmms_command_server_version_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Length of tool version */
    tool_version_length = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_msmms_command_tool_version_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Length of download update player URL */
    download_update_player_length = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_msmms_command_update_url_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Length of password encryption type */
    password_encryption_type_length = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_msmms_command_password_type_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Server version string. */
    if (server_version_length > 1)
    {
        /* Server version string */
        proto_tree_add_item_ret_string(tree, hf_msmms_command_server_version, tvb,
                            offset, server_version_length*2,
                            ENC_UTF_16|ENC_LITTLE_ENDIAN, wmem_packet_scope(), &server_version);

        col_append_fstr(pinfo->cinfo, COL_INFO, " (version='%s')",
                    format_text((guchar*)server_version, strlen(server_version)));
    }
    offset += (server_version_length*2);


    /* Tool version string. */
    if (tool_version_length > 1)
    {
        proto_tree_add_item(tree, hf_msmms_command_tool_version, tvb,
                            offset, tool_version_length*2,
                            ENC_UTF_16|ENC_LITTLE_ENDIAN);
    }
    offset += (tool_version_length*2);

    /* Download update player url string. */
    if (download_update_player_length > 1)
    {
        proto_tree_add_item(tree, hf_msmms_command_update_url, tvb,
                            offset, download_update_player_length*2,
                            ENC_UTF_16|ENC_LITTLE_ENDIAN);
    }
    offset += (download_update_player_length*2);

    /* Password encryption type string. */
    if (password_encryption_type_length > 1)
    {
        proto_tree_add_item(tree, hf_msmms_command_password_type, tvb,
                            offset, password_encryption_type_length*2,
                            ENC_UTF_16|ENC_LITTLE_ENDIAN);
    }
/*    offset += (password_encryption_type_length*2); */
}

/* Player (client) information */
static void dissect_client_player_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       guint offset, guint length_remaining)
{
    const guint8 *player_info;

    /* Flags */
    proto_tree_add_item(tree, hf_msmms_command_prefix1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* These 4 bytes are not understood */
    offset += 4;

    /* Extract and show the string in tree and info column */
    proto_tree_add_item_ret_string(tree, hf_msmms_command_client_player_info, tvb,
                        offset, length_remaining-12,
                        ENC_UTF_16|ENC_LITTLE_ENDIAN, wmem_packet_scope(), &player_info);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    format_text((guchar*)player_info, strlen(player_info)));
}

/* Dissect info about where client wants to start playing from */
static void dissect_start_sending_from_info(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    /* 40 bytes follow the prefixes... */
}

/* Dissect cancel parameters */
static void dissect_cancel_info(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect timing test data request */
static void dissect_timing_test_request(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* Flags */
    proto_tree_add_item(tree, hf_msmms_command_prefix1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect timing test data response */
static void dissect_timing_test_response(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* ErrorCode */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_error, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Flags */
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Number of 4 byte fields in structure */
    proto_tree_add_item(tree, hf_msmms_command_number_of_words, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset += 4;
    offset += 4;

    /* Client ID */
    proto_tree_add_item(tree, hf_msmms_command_client_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    /* 20 more bytes... */
}

/* Dissect request for server file */
static void dissect_request_server_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        guint offset, guint length_remaining)
{
    const guint8 *server_file;

    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    offset += 4;
    offset += 4;

    /* File path on server */
    proto_tree_add_item_ret_string(tree, hf_msmms_command_server_file, tvb,
                        offset, length_remaining-16,
                        ENC_UTF_16|ENC_LITTLE_ENDIAN, wmem_packet_scope(), &server_file);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    format_text((guchar*)server_file, strlen(server_file)));
}

/* Dissect media details from server */
static void dissect_media_details(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* ErrorCode */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_error, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Result flags */
    proto_tree_add_item(tree, hf_msmms_command_result_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    offset += 4;
    offset += 4;

    /* Broadcast flags. */
    proto_tree_add_item(tree, hf_msmms_command_broadcast_indexing, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_msmms_command_broadcast_liveness, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* These 8 bytes may be a time field... */
    offset += 4;
    offset += 4;

    /* Media length in seconds */
    proto_tree_add_item(tree, hf_msmms_command_recorded_media_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    offset += 4;
    offset += 4;
    offset += 4;
    offset += 4;

    /* Packet length in bytes */
    proto_tree_add_item(tree, hf_msmms_command_media_packet_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect header response */
static void dissect_header_response(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* ErrorCode */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_error, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Packet ID type */
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    /* 8 more bytes */
}

/* Dissect network timer test response */
static void dissect_network_timer_test_response(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect transport info response */
static void dissect_transport_info_response(tvbuff_t *tvb, proto_tree *tree,
                                            guint offset, guint length_remaining)
{
    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Length */
    proto_tree_add_item(tree, hf_msmms_command_number_of_words, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Read this strange string */
    proto_tree_add_item(tree, hf_msmms_command_strange_string, tvb,
                        offset, length_remaining-12,
                        ENC_UTF_16|ENC_LITTLE_ENDIAN);
}

/* Media stream MBR selector */
static void dissect_media_stream_mbr_selector(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* Stream structure count (always 1) */
    proto_tree_add_item(tree, hf_msmms_command_stream_structure_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Stream selection structure */
    proto_tree_add_item(tree, hf_msmms_stream_selection_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_msmms_stream_selection_stream_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_msmms_stream_selection_action, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

/* Dissect header request */
static void dissect_header_request(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    gint n;

    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Skip 8 unknown words */
    for (n=0; n < 8; n++)
    {
        offset += 4;
    }

    /* Header packet ID type */
    proto_tree_add_item(tree, hf_msmms_command_header_packet_id_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

/* Dissect stop button pressed */
static void dissect_stop_button_pressed(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    /* Command Level */
    proto_tree_add_item(tree, hf_msmms_command_prefix1_command_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_msmms_command_prefix2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}


/********************************************************/
/* Helper function to set up an MS-MMS data conversation */
/********************************************************/
static void msmms_data_add_address(packet_info *pinfo, address *addr, port_type pt, int port)
{
    address         null_addr;
    conversation_t *p_conv;

    /* If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again. */
    if (pinfo->fd->flags.visited)
    {
        return;
    }

    clear_address(&null_addr);

    /* Check if the ip address and port combination is not
     * already registered as a conversation. */
    p_conv = find_conversation(pinfo->num, addr, &null_addr, pt, port, 0,
                               NO_ADDR_B | NO_PORT_B);

    /* If not, create a new conversation. */
    if (!p_conv)
    {
        p_conv = conversation_new(pinfo->num, addr, &null_addr, pt,
                                  (guint32)port, 0, NO_ADDR2 | NO_PORT2);
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, msmms_handle);
}



/*************************/
/* Register protocol     */
/*************************/

void proto_register_msmms(void)
{
    static hf_register_info hf[] =
    {

        /* Command fields */
        {
            &hf_msmms_command,
            {
                "Command",
                "msmms.command",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "MSMMS command hidden filter", HFILL
            }
        },
        {
            &hf_msmms_command_common_header,
            {
                "Command common header",
                "msmms.command.common-header",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "MSMMS command common header", HFILL
            }
        },

#if 0
        {
            &hf_msmms_command_version,
            {
                "Version",
                "msmms.command.version",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
#endif
        {
            &hf_msmms_command_signature,
            {
                "Command signature",
                "msmms.command.signature",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_length,
            {
                "Command length",
                "msmms.command.length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_protocol_type,
            {
                "Protocol type",
                "msmms.command.protocol-type",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_length_remaining,
            {
                "Length until end (8-byte blocks)",
                "msmms.command.length-remaining",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_sequence_number,
            {
                "Sequence number",
                "msmms.command.sequence-number",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_timestamp,
            {
                "Time stamp (s)",
                "msmms.command.timestamp",
                FT_DOUBLE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_length_remaining2,
            {
                "Length until end (8-byte blocks)",
                "msmms.command.length-remaining2",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_to_server_id,
            {
                "Command",
                "msmms.command.to-server-id",
                FT_UINT16,
                BASE_HEX,
                VALS(to_server_command_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_to_client_id,
            {
                "Command",
                "msmms.command.to-client-id",
                FT_UINT16,
                BASE_HEX,
                VALS(to_client_command_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_direction,
            {
                "Command direction",
                "msmms.command.direction",
                FT_UINT16,
                BASE_HEX,
                VALS(command_direction_vals),
                0x0,
                NULL, HFILL
            }
        },

        {
            &hf_msmms_command_prefix1,
            {
                "Prefix 1",
                "msmms.command.prefix1",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_prefix1_error,
            {
                "Prefix 1 ErrorCode",
                "msmms.command.prefix1-error-code",
                FT_UINT32,
                BASE_HEX,
                VALS(server_to_client_error_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_prefix1_command_level,
            {
                "Prefix 1 Command Level",
                "msmms.command.prefix1-command-level",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_prefix2,
            {
                "Prefix 2",
                "msmms.command.prefix2",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_client_transport_info,
            {
                "Client transport info",
                "msmms.command.client-transport-info",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_client_player_info,
            {
                "Player info",
                "msmms.command.player-info",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_server_version_length,
            {
                "Server Version Length",
                "msmms.command.server-version-length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_tool_version_length,
            {
                "Tool Version Length",
                "msmms.command.tool-version-length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_update_url_length,
            {
                "Download update URL length",
                "msmms.command.download-update-player-url-length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_password_type_length,
            {
                "Password encryption type length",
                "msmms.command.password-encryption-type-length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_server_version,
            {
                "Server version",
                "msmms.command.server-version",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_tool_version,
            {
                "Tool version",
                "msmms.command.tool-version",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_update_url,
            {
                "Download update player URL",
                "msmms.command.download-update-player-url",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_password_type,
            {
                "Password encryption type",
                "msmms.command.password-encryption-type",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_number_of_words,
            {
                "Number of 4 byte fields in structure",
                "msmms.data.words-in-structure",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_client_id,
            {
                "Client ID",
                "msmms.data.client-id",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_server_file,
            {
                "Server file",
                "msmms.command.server-file",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_result_flags,
            {
                "Result flags",
                "msmms.command.result-flags",
                FT_UINT32,
                BASE_HEX,
                VALS(media_result_flags_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_broadcast_indexing,
            {
                "Broadcast indexing",
                "msmms.command.broadcast-indexing",
                FT_UINT8,
                BASE_HEX,
                VALS(broadcast_indexing_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_broadcast_liveness,
            {
                "Broadcast liveness",
                "msmms.command.broadcast-liveness",
                FT_UINT8,
                BASE_HEX,
                VALS(broadcast_liveness_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_recorded_media_length,
            {
                "Pre-recorded media length (seconds)",
                "msmms.data.prerecorded-media-length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_media_packet_length,
            {
                "Media packet length (bytes)",
                "msmms.data.media-packet-length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_strange_string,
            {
                "Strange string",
                "msmms.command.strange-string",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_stream_structure_count,
            {
                "Stream structure count",
                "msmms.data.stream-structure-count",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_stream_selection_flags,
            {
                "Stream selection flags",
                "msmms.data.stream-selection-flags",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_stream_selection_stream_id,
            {
                "Stream id",
                "msmms.data.selection-stream-id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_stream_selection_action,
            {
                "Action",
                "msmms.data.selection-stream-action",
                FT_UINT16,
                BASE_DEC,
                VALS(stream_selection_action_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_command_header_packet_id_type,
            {
                "Header packet ID type",
                "msmms.data.header-packet-id-type",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },


        /* Data fields */
        {
            &hf_msmms_data,
            {
                "Data",
                "msmms.data",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_sequence_number,
            {
                "Sequence number",
                "msmms.data.sequence",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_packet_id_type,
            {
                "Packet ID type",
                "msmms.data.packet-id-type",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_packet_length,
            {
                "Packet length",
                "msmms.data.packet-length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        {
            &hf_msmms_data_header_id,
            {
                "Header ID",
                "msmms.data.header-id",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_client_id,
            {
                "Client ID",
                "msmms.data.client-id",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_command_id,
            {
                "Command ID",
                "msmms.data.command-id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_packet_to_resend,
            {
                "Packet to resend",
                "msmms.data.packet-to-resend",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_udp_sequence,
            {
                "UDP Sequence",
                "msmms.data.udp-sequence",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_tcp_flags,
            {
                "TCP flags",
                "msmms.data.tcp-flags",
                FT_UINT8,
                BASE_HEX,
                VALS(tcp_flags_vals),
                0x0,
                NULL, HFILL
            }
        },

        {
            &hf_msmms_data_timing_pair,
            {
                "Data timing pair",
                "msmms.data.timing-pair",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_timing_pair_seqno,
            {
                "Sequence number",
                "msmms.data.timing-pair.sequence-number",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_timing_pair_flags,
            {
                "Flags",
                "msmms.data.timing-pair.flags",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_timing_pair_id,
            {
                "ID",
                "msmms.data.timing-pair.id",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_timing_pair_flag,
            {
                "Flag",
                "msmms.data.timing-pair.flag",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_msmms_data_timing_pair_packet_length,
            {
                "Packet length",
                "msmms.data.timing-pair.packet-length",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        /* Unparsed data */
        {
            &hf_msmms_data_unparsed,
            {
                "Unparsed data",
                "msmms.data.unparsed",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_msmms_command,
        &ett_msmms_command_common_header,
        &ett_msmms_data,
        &ett_msmms_data_timing_packet_pair
    };

    /* Register protocol and fields */
    proto_msmms = proto_register_protocol("Microsoft Media Server", "MSMMS", "msmms");
    proto_register_field_array(proto_msmms, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("msmms", dissect_msmms_pdu, proto_msmms);
}

void proto_reg_handoff_msmms_command(void)
{
    msmms_handle = find_dissector("msmms");
    /* Control commands using TCP port */
    dissector_add_uint("tcp.port", MSMMS_PORT, msmms_handle);
    /* Data command(s) using UDP port */
    dissector_add_uint("udp.port", MSMMS_PORT, msmms_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
