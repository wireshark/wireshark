/* packet-kingfisher.c
 * Routines for kingfisher packet dissection
 * By Rob Casey 2007
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>

void proto_register_kingfisher(void);
void proto_reg_handoff_kingfisher(void);

#define SUPPORT_KINGFISHER_SERIES_2

#define TCP_PORT_KINGFISHER         4058
#define UDP_PORT_KINGFISHER         4058
#ifdef SUPPORT_KINGFISHER_SERIES_2
#define TCP_PORT_KINGFISHER_OLD     473
#define UDP_PORT_KINGFISHER_OLD     473
#endif

static int proto_kingfisher = -1;
static int hf_kingfisher_version = -1;
static int hf_kingfisher_system = -1;
static int hf_kingfisher_length = -1;
static int hf_kingfisher_from = -1;
static int hf_kingfisher_target = -1;
static int hf_kingfisher_via = -1;
static int hf_kingfisher_message = -1;
static int hf_kingfisher_function = -1;
static int hf_kingfisher_checksum = -1;

static dissector_handle_t kingfisher_conv_handle;


typedef struct _kingfisher_packet_t
{
    guint8      version;
    guint8      system;
    guint16     from;
    guint16     target;
    guint16     via;
    guint8      length;
    guint8      message;
    guint8      function;
    guint16     checksum;
} kingfisher_packet_t;

static gint ett_kingfisher = -1;

static const value_string function_code_vals[] =
{
    { 0x00, "Acknowledgement" },
    { 0x01, "Negative Acknowledgement" },
    { 0x02, "No Access" },
    { 0x03, "Message Buffer Full" },
    { 0x0a, "Get Data Frame" },
    { 0x0b, "Send Data Frame" },
    { 0x0c, "Get Data Blocks" },
    { 0x0d, "Send Data Blocks" },
    { 0x0e, "Check RTU Update" },
    { 0x0f, "Send RTU Update" },
    { 0x10, "Get Multiple Data" },
    { 0x11, "Send Multiple Data" },
    { 0x12, "Get Multiple Network Data" },
    { 0x13, "Send Multiple Network Data" },
    { 0x1e, "Cold Start" },
    { 0x1f, "Warm Start" },
    { 0x21, "Program Control" },
    { 0x22, "Get RTU Status" },
    { 0x23, "Send RTU Status" },
    { 0x24, "Set RTC" },
    { 0x25, "Swap Master CPU" },
    { 0x26, "Send I/O Module Message" },
    { 0x28, "Get Diagnostic Information" },
    { 0x29, "Send Diagnostic Information" },
    { 0x2b, "Send Pager Information" },
    { 0x2c, "Get Pager Information" },
    { 0x2d, "Send Port Data Information" },
    { 0x2e, "Get Port Data Information" },
    { 0x2f, "Send RTU Data Information" },
    { 0x30, "Get RTU Data Information" },
    { 0x31, "Unlock Port" },
    { 0x33, "Carrier Test" },
    { 0x34, "Program Flash RAM" },
    { 0x35, "Get I/O Values" },
    { 0x36, "Send I/O Values" },
    { 0x37, "Synchronise Clock" },
    { 0x38, "Send Communications Module Message" },
    { 0x39, "Get Communications Module Message" },
    { 0x3a, "Get Driver Information" },
    { 0x3b, "Send Driver Information" },
    { 0x3c, "Communications Analyser" },
    { 0x41, "Dial Site" },
    { 0x42, "Hang-up Site" },
    { 0x46, "Send File" },
    { 0x47, "Get File" },
    { 0x50, "Get Event Logging" },
    { 0x51, "Send Event Logging" },
    { 0x80, "Acknowledgement" },
    { 0x81, "Negative Acknowledgement" },
    { 0x84, "Get Named Variable" },
    { 0x85, "Send Named Variable" },
    { 0x87, "Get Module Information" },
    { 0x88, "Send Module Information" },
    { 0x89, "Get I/O Values" },
    { 0x8a, "Send I/O Values" },
    { 0x9e, "Cold Start" },
    { 0x9f, "Warm Start" },
    { 0xa2, "Get RTU Status" },
    { 0xa3, "Send RTU Status" },
    { 0xa4, "Set RTC" },
    { 0xa8, "Get Diagnostic Information" },
    { 0xa9, "Send Diagnostic Information" },
    { 0xd1, "Set Event Log" },
    { 0xd2, "Clear Event Log" },
    { 0xd3, "Get Number of Events" },
    { 0xd4, "Send Number of Events" },
    { 0xd5, "Get Event Log" },
    { 0xd6, "Continue Event Log" },
    { 0xd7, "Send Event Log" },
    { 0xe0, "Send File Start" },
    { 0xe1, "Send File Start Acknowledgement" },
    { 0xe2, "Send File Data" },
    { 0xe3, "Send File Data Acknowledgement" },
    {0, NULL}
};


static unsigned short
kingfisher_checksum(tvbuff_t *tvb, int offset)
{
    gint c, i, j, len;
    unsigned short crc;

    crc = 0;
    len = tvb_reported_length_remaining(tvb, offset) - 2;
    for( i = 1; i < len; i++ )
    {
        c = ( ( unsigned char ) tvb_get_guint8( tvb, i ) ) & 0xff;
        for( j = 0; j < 8; ++j )
        {
            if( crc & 0x8000 )
            {
                crc <<= 1;
                crc += ( ( ( c <<= 1 ) & 0x100 ) != 0 );
                crc ^= 0x1021;
            }
            else
            {
                crc <<= 1;
                crc += ( ( ( c <<= 1 ) & 0x100 ) != 0 );
            }
        }
    }
    return crc;
}


static gboolean
dissect_kingfisher(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_conv_dissector)
{
    kingfisher_packet_t kfp;
    proto_tree *kingfisher_tree=NULL;
    proto_item *item=NULL;
    const char *func_string = NULL;
    unsigned short checksum;
    int message;


    /* There can be one byte reply packets. we only test for these when we
       are called from the conversation dissector since that is the only time
       we can be certain this is kingfisher
     */
    if(is_conv_dissector && (tvb_reported_length(tvb)==1)){
        /*
          Perform a check to see if the message is a single byte acknowledgement
          message - Note that in this instance there is no information in the packet
          with regard to source or destination RTU address which can be used in the
          population of dissector fields.
         */
        switch(tvb_get_guint8(tvb, 0)){
        case 0x00:
        case 0x01:
        case 0x80:
        case 0x81:
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kingfisher");
            func_string = val_to_str_const(tvb_get_guint8(tvb, 0), function_code_vals, "Unknown function");
            col_add_fstr(pinfo->cinfo, COL_INFO, "(%s)", func_string);
            proto_tree_add_protocol_format(tree, proto_kingfisher, tvb, 0, -1, "Kingfisher Protocol, %s", func_string);
            return TRUE;
        }
        /* othervise it is way too short to be kingfisger */
        return FALSE;
    }


    /* Verify that it looks like kingfisher */
    /* the packet must be at least 9 bytes */
    if(tvb_reported_length(tvb)<9){
        return FALSE;
    }

    /* the function code must be known */
    kfp.function = tvb_get_guint8( tvb, 6 );
    if (try_val_to_str(kfp.function, function_code_vals) == NULL) {
        /* This appears not to be a kingfisher packet */
        return FALSE;
    }

    /* verify the length */
    kfp.length = tvb_get_guint8(tvb, 2);
    if((kfp.length+1) != (guint8)tvb_length(tvb)){
        return FALSE;
    }

    /* verify the checksum */
    kfp.checksum = tvb_get_ntohs(tvb, kfp.length - 1);
    checksum = kingfisher_checksum(tvb, 0);
    if(kfp.checksum!=checksum){
        return FALSE;
    }


    kfp.version = (kfp.function & 0x80)?3:2;
    kfp.system = tvb_get_guint8( tvb, 0 );
    kfp.message = tvb_get_guint8( tvb, 5 );

    kfp.target = tvb_get_guint8( tvb, 1 );
    kfp.from = tvb_get_guint8( tvb, 3 );
    kfp.via = tvb_get_guint8( tvb, 4 );

    if( kfp.version == 3 )
    {
        kfp.target |= ( tvb_get_guint8( tvb, 7 ) << 8 );
        kfp.from   |= ( tvb_get_guint8( tvb, 8 ) << 8 );
        kfp.via    |= ( tvb_get_guint8( tvb, 9 ) << 8 );
    }


    /* Ok  this does look like Kingfisher, so lets dissect it */
    func_string = val_to_str_const(kfp.function, function_code_vals, "Unknown function");

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kingfisher");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%u > %u (%s)", kfp.from, kfp.target, func_string);


    message = (kfp.message & 0x0f) | ((kfp.message & 0xf0) >> 4);

    if(tree){
        item = proto_tree_add_protocol_format(tree, proto_kingfisher, tvb, 0, -1, "Kingfisher Protocol, From RTU: %d, Target RTU: %d", kfp.from, kfp.target );
        kingfisher_tree = proto_item_add_subtree( item, ett_kingfisher );
    }

    /* version */
    proto_tree_add_uint(kingfisher_tree, hf_kingfisher_version, tvb, 6, 1, kfp.version);

    /* system id */
    proto_tree_add_uint(kingfisher_tree, hf_kingfisher_system, tvb, 0, 1, kfp.system);

    /* target rtu */
    proto_tree_add_uint(kingfisher_tree, hf_kingfisher_target, tvb, 1, 1, kfp.target);

    /* length */
    proto_tree_add_uint(kingfisher_tree, hf_kingfisher_length, tvb, 2, 1, kfp.length);

    /* from rtu */
    proto_tree_add_uint(kingfisher_tree, hf_kingfisher_from, tvb, 3, 1, kfp.from);

    /* via rtu */
    proto_tree_add_uint(kingfisher_tree, hf_kingfisher_via, tvb, 4, 1, kfp.via);

    /* message number */
    proto_tree_add_uint_format_value(kingfisher_tree, hf_kingfisher_message, tvb, 5, 1, kfp.message, "%u (0x%02X, %s)", message, kfp.message, ((kfp.message & 0xf0)?"Response":"Request"));

    /* message function code */
    proto_tree_add_uint_format(kingfisher_tree, hf_kingfisher_function, tvb, 6, 1, kfp.function, "Message Function Code: %u (0x%02X, %s)", kfp.function, kfp.function, func_string);

    /* message data */
    if(kfp.length > ((kfp.version==3)?11:8)){
        proto_tree_add_text(kingfisher_tree, tvb, ((kfp.version==3)?10:7), kfp.length - ((kfp.version==3)?11:8), "Message Data");
    }

    /* checksum */
    proto_tree_add_uint_format_value(kingfisher_tree, hf_kingfisher_checksum, tvb, kfp.length-1, 2, kfp.checksum, "0x%04X [%s]", kfp.checksum, ((checksum != kfp.checksum)?"incorrect":"correct"));



    return TRUE;
}


static gboolean
dissect_kingfisher_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gboolean was_kingfisher;


    was_kingfisher=dissect_kingfisher(tvb, pinfo, tree, FALSE);

    if(was_kingfisher){
        conversation_t *conversation;

        /* Ok this was a genuine kingfisher packet. Now create a conversation
           dissector for this tcp/udp socket and attach a conversation
           dissector to it.
         */
        conversation = find_or_create_conversation(pinfo);

        conversation_set_dissector(conversation, kingfisher_conv_handle);
    }

    return was_kingfisher;
}

static gboolean
dissect_kingfisher_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_kingfisher(tvb, pinfo, tree, TRUE);
}

void
proto_register_kingfisher( void )
{
    static hf_register_info hf[] =
    {
            { &hf_kingfisher_version,       { "Version", "kingfisher.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_system,        { "System Identifier", "kingfisher.system", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_length,        { "Length", "kingfisher.length", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_from,          { "From RTU", "kingfisher.from", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_target,        { "Target RTU", "kingfisher.target", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_via,           { "Via RTU", "kingfisher.via", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_message,       { "Message Number", "kingfisher.message", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
            { &hf_kingfisher_function,      { "Function Code", "kingfisher.function", FT_UINT8, BASE_DEC, VALS( function_code_vals ), 0x0, NULL, HFILL } },
            { &hf_kingfisher_checksum,      { "Checksum", "kingfisher.checksum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_kingfisher
    };

    proto_kingfisher = proto_register_protocol( "Kingfisher", "Kingfisher", "kf" );
    proto_register_field_array( proto_kingfisher, hf, array_length( hf ) );
    proto_register_subtree_array( ett, array_length( ett ) );
}


void
proto_reg_handoff_kingfisher( void )
{
    dissector_handle_t kingfisher_handle=NULL;

    kingfisher_handle = new_create_dissector_handle(dissect_kingfisher_heur, proto_kingfisher);
    dissector_add_uint("tcp.port", TCP_PORT_KINGFISHER, kingfisher_handle);
    dissector_add_uint("udp.port", UDP_PORT_KINGFISHER, kingfisher_handle);

#ifdef SUPPORT_KINGFISHER_SERIES_2
    dissector_add_uint("tcp.port", TCP_PORT_KINGFISHER_OLD, kingfisher_handle);
    dissector_add_uint("udp.port", UDP_PORT_KINGFISHER_OLD, kingfisher_handle);
#endif
    kingfisher_conv_handle = new_create_dissector_handle(dissect_kingfisher_conv, proto_kingfisher);

}
