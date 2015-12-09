/* packet-optommp.c
 * Routines for optommp dissection
 * Copyright 2014, Opto22 wiresharkdissectorcoder@gmail.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

#define OPTO_FRAME_HEADER_LEN 8
#define OPTOMMP_MIN_LENGTH 12

#define OPTOMMP_WRITE_QUADLET_REQUEST 0
#define OPTOMMP_WRITE_BLOCK_REQUEST 1
#define OPTOMMP_WRITE_RESPONSE 2
#define OPTOMMP_READ_QUADLET_REQUEST 4
#define OPTOMMP_READ_BLOCK_REQUEST 5
#define OPTOMMP_READ_QUADLET_RESPONSE 6
#define OPTOMMP_READ_BLOCK_RESPONSE 7

/* Initialize the protocol and registered fields */
static gint proto_optommp = -1;
static dissector_handle_t optommp_tcp_handle;
static dissector_handle_t optommp_udp_handle;
static gint hf_optommp_nodest_id = -1;
static gint hf_optommp_dest_id = -1;
static gint hf_optommp_boot_id = -1;
static gint hf_optommp_tl = -1;
static gint hf_optommp_tcode = -1;
static gint hf_optommp_source_ID = -1;
static gint hf_optommp_rcode = -1;
static gint hf_optommp_quadlet_data = -1;
static gint hf_optommp_data_length = -1;
static gint hf_optommp_dest_offset  = -1;
static gint hf_optommp_data_block_byte  = -1;
static gint hf_optommp_data_block_quadlet  = -1;
/* Initialize the subtree pointers */
static gint ett_optommp = -1;
static gint ett_dest_id = -1;
static gint ett_data_block_q = -1;
static gint ett_data_block_b = -1;
/* PORT_PREF */
static guint gOPTOMMP_PORT_PREF = 0;


static const value_string optommp_tcode_names[] = {
    { 0, "Write Quadlet Request" },
    { 1, "Write Block Request" },
    { 2, "Write Response" },
    { 4, "Read Quadlet Request" },
    { 5, "Read Block Request" },
    { 6, "Read Quadlet Response" },
    { 7, "Read Block Response" },
    { 0, NULL }
};

static const value_string optommp_rcode_meanings[] = {
    { 0x0, "No error" },
    { 0x1, "Undefined command" },
    { 0x2, "Invalid point type" },
    { 0x3, "Invalid float" },
    { 0x4, "Powerup Clear expected" },
    { 0x5, "Invalid memory address/data" },
    { 0x6, "Invalid command length" },
    { 0x7, "Reserved" },
    { 0x8, "Busy" },
    { 0x9, "Cannot erase flash" },
    { 0xa, "Cannot program flash" },
    { 0xb, "Downloaded image too small" },
    { 0xc, "Image CRC mismatch" },
    { 0xd, "Image length mismatch" },
    { 0xe, "Feature is not yet implemented" },
    { 0xf, "Communications watchdog timeout" },
    { 0, NULL }
};

static const range_string optommp_mm_areas[] = {
    { 0xf0100000,   0xf01bffff,
            "Expanded Analog & Digital Point Configuration - Read/Write" },
    {   0xf01c0000, 0xf01c7fff,
            "Expanded Analog Point Calc & Set - Read/Write" },
    {   0xf01d4000, 0xf01dffff,
            "Expanded Analog Point Read & Clear - Read/Write" },
    {   0xf0260000, 0xf029ffff,
            "Expanded Analog Point Read - Read" },
    {   0xf02a0000, 0xf02dffff,
            "Expanded Analog Point Write - Read/Write" },
    {   0xf02e0000, 0xf02f7fff,
            "Expanded Digital Point Read & Clear - Read/Write" },
    {   0xf0300000, 0xf030024b,
            "Status Area Read - Read Only" },
    {   0xf0310400, 0xf031110f,
            "Communications Port Configuration - Read/Write" },
    {   0xf0329000, 0xf032efff,
            "Serial Pass-Through - Read/Write" },
    {   0xf0350000, 0xf0350023,
            "Date and Time Configuration - Read/Write" },
    {   0xf0380000, 0xf0380297,
            "Status Area Write - Read/Write" },
    {   0xf0390000, 0xf0390003,
            "Modbus Configuration - Read/Write" },
    {   0xf03a0004, 0xf03a0073,
            "Network Security Configuration - Read/Write" },
    {   0xf03a1000, 0xf03a1fff,
            "SSI Module Configuration - Read/Write" },
    {   0xf03a7f00, 0xf03a7ffa,
            "Serial Module Identification - Read Only" },
    {   0xf03a8000, 0xf03a840f,
            "Serial Module Configuration - Read/Write" },
    {   0xf03a8500, 0xf03a8dc3,
            "Wiegand Serial Module Configuration - Read/Write" },
    {   0xf03a9000, 0xf03a92bf,
            "SNAP-SCM-CAN2B Serial Module Configuration -Read/Write" },
    {   0xf03c0000, 0xf03c030b,
            "SNMP Configuration - Read/Write" },
    {   0xf03d0000, 0xf03d0079,
            "FTP User Name/Password Configuration - Read/Write" },
    {   0xf03e0000, 0xf03eb107,
            "PPP Configuration - Read/Write" },
    {   0xf03eb800, 0xf03fb827,
            "PPP Status - Read Only" },
    {   0xf03fffc4, 0xf03fffff,
            "Streaming Configuration - Read/Write" },
    {   0xf0400000, 0xf04001ff,
            "Digital Bank Read - Read Only" },
    {   0xf0500000, 0xf050001f,
            "Digital Bank Write - Read/Write" },
    {   0xf0600000, 0xf06003ff,
            "Analog Bank Read - Read Only" },
    {   0xf0700000, 0xf07001ff,
            "Analog Bank Write - Read/Write" },
    {   0xf0800000, 0xf0800fd3,
            "Digital Point Read - Read Only" },
    {   0xf0900000, 0xf0900fcf,
            "Digital Point Write - Read/Write" },
    {   0xf0a00000, 0xf0a00fcf,
            "Old Analog Point Read - Read Only" },
    {   0xf0b00000, 0xf0b00fcf,
            "Old Analog Point Write - Read/Write" },
    {   0xf0c00000, 0xf0c011ff,
            "Old A&D Point Configuration Information - Read/Write" },
    {   0xf0d00000, 0xf0d01fff,
            "Old Digital Events and Reactions - Read/Write" },
    {   0xf0d40000, 0xf0d4ffff,
            "Digital Events - Expanded - Read/Write" },
    {   0xf0d80000, 0xf0dc81ff,
            "Scratch Pad - Read/Write" },
    {   0xf0e00000, 0xf0e001ff,
            "Old Analog Point Calculation and Set - Read Only" },
    {   0xf0f00000, 0xf0f002ff,
            "Old Digital Read and Clear - Read Only" },
    {   0xf0f80000, 0xf0f801ff,
            "Old Analog Read and Clear/Restart - Read Only" },
    {   0xf1000000, 0xf100021f,
            "Streaming - Read Only" },
    {   0xf1001000, 0xf10017ff,
            "Analog EU or Digital Counter Packed Data - Read" },
    {   0xf1001800, 0xf100183f,
            "Digital Packed Data - Read/Write" },
    {   0xf1100000, 0xf1101fff,
            "Alarm Event Settings - Read/Write" },
    {   0xf1200000, 0xf12111ff,
            "Event Message Configuration - Read/Write" },
    {   0xf1300000, 0xf13000a3,
            "Email Configuration - Read/Write" },
    {   0xf1540000, 0xf1540efc,
            "Serial Event Configuration - Read/Write" },
    {   0xf1560000, 0xf1f60f7f,
            "Wiegand Serial Event Configuration - Read/Write" },
    {   0xf1808000, 0xf1809ffe,
            "SNAP High-Density Digital - Read Only" },
    {   0xf180a000, 0xf180bffe,
            "SNAP High-Density Digital Read and Clear - Read/Write" },
    {   0xf180c000, 0xf180c3fe,
            "SNAP High-Density Digital Write - Read/Write" },
    {   0xf2000000, 0xf2002edf,
            "PID Configuration and Status - Read/Write" },
    {   0xf2100000, 0xf21047ff,
            "PID Configuration and Status - Read/Write" },
    {   0xf3000000, 0xf3000707,
            "Data Logging Configuration - Read/Write" },
    {   0xf3020000, 0xf302176f,
            "Data Log - Read/Write" },
    {   0xf4000000, 0xf4000f6f,
            "PID Module Configuration - Read/Write" },
    {   0xf4080000, 0xf4080007,
            "Control Engine - Read/Write" },
    {   0xf7002000, 0xf7002103,
            "Serial Brain Communication - Read/Write" },
    {   0xf7002200, 0xf7002207,
            "microSD Card - Read/Write" },
    {   0xf7003000, 0xf700308f,
            "WLAN Status - Read Only" },
    {   0xf7004000, 0xf700553b,
            "WLAN Configuration - Read/Write" },
    {   0xf8000000, 0xf800000b,
            "WLAN Enable - Read/Write" },
    {   0xfffff008, 0xfffff077,
            "IP Settings - Read/Write" },
    {   0,          0,          NULL }
};

/* Function Prototypes */
static guint get_optommp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
    int offset, void *data _U_);
static gint dissect_optommp_reassemble_tcp(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data);
static gint dissect_optommp_reassemble_udp(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data);
static gint dissect_optommp(tvbuff_t *tvb, packet_info *pinfo, proto_tree
    *tree, void * data _U_);
static void dissect_optommp_dest_id(proto_tree *tree,
    tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_write_quadlet_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_write_block_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_write_response(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_read_quadlet_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_read_block_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_read_quadlet_response(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_read_block_response(proto_item **ti, proto_tree
    *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_source_ID(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_destination_offset_6(proto_item **ti,
     proto_tree *tree, tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_quadlet_data(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_rcode(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset);
static guint16 dissect_optommp_data_length(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_data_block(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset, guint16 data_length);
static void dissect_optommp_data_block_byte(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset);
static void dissect_optommp_data_block_quadlet(proto_item **ti, proto_tree
    *tree, tvbuff_t *tvb, guint *poffset);
static gint optommp_has_destination_offset(guint8 tcode);

void proto_register_optommp(void);
void proto_reg_handoff_optommp(void);


/****************************************************************************
function:       get_optommp_message_len()
parameters:     pinfo: not used
                tvb: poiner to packet data
                offset: not used
purpose:        Gets the message length depending on tcode and data_block len
****************************************************************************/
static guint get_optommp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
    int offset, void *data _U_)
{
    guint len = OPTO_FRAME_HEADER_LEN;
    guint8 tcode = 0;

    /* Just want the most significant nibble */
    tcode = tvb_get_guint8(tvb, offset + 3) >> 4;

    if( tcode == OPTOMMP_WRITE_QUADLET_REQUEST ||
        tcode == OPTOMMP_WRITE_BLOCK_REQUEST ||
        tcode == OPTOMMP_READ_BLOCK_REQUEST ||
        tcode == OPTOMMP_READ_QUADLET_RESPONSE ||
        tcode == OPTOMMP_READ_BLOCK_RESPONSE )
    {
        len = 16;
    }
    else if( tcode == OPTOMMP_WRITE_RESPONSE ||
        tcode == OPTOMMP_READ_QUADLET_REQUEST )
    {
        len = 12;
    }

    if( (tcode == OPTOMMP_WRITE_BLOCK_REQUEST ||
        tcode == OPTOMMP_READ_BLOCK_RESPONSE) &&
        tvb_reported_length_remaining(tvb, offset) >= 14 )
    {
        /* offset + 12 is the data_length of the packet */
        len += (guint) tvb_get_ntohs(tvb, offset + 12);
    }

    return len;
}

/****************************************************************************
function:       dissect_optommp_reassemble_tcp()
parameters:     void
purpose:        reassemble packets then send to dissector
****************************************************************************/
static gint dissect_optommp_reassemble_tcp(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, OPTO_FRAME_HEADER_LEN,
        get_optommp_message_len, dissect_optommp, data);

    return tvb_captured_length(tvb);
}

/****************************************************************************
function:       dissect_optommp_reassemble_udp()
parameters:     void
purpose:        reassemble packets then send to dissector
****************************************************************************/
static gint dissect_optommp_reassemble_udp(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data)
{
    dissect_optommp(tvb, pinfo, tree, data);

    return tvb_captured_length(tvb);
}

/****************************************************************************
function:       dissect_optommp()
parameters:     void
purpose:        add the optommp protocol subtree
****************************************************************************/
static gint dissect_optommp(tvbuff_t *tvb, packet_info *pinfo, proto_tree
    *tree, void *data _U_)
{
    /* Declare and init variables for each part of the packet */
    guint8 tcode = 0;

    /* Provide a summary label */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OptoMMP");
    col_clear(pinfo->cinfo, COL_INFO);
    if( tvb_reported_length(tvb) >= OPTOMMP_MIN_LENGTH)
    {
        /* the tcode is the most sig nibble of the 3rd byte */
        tcode = tvb_get_guint8(tvb, 3) >> 4;
        if( optommp_has_destination_offset(tcode) != 0 &&
            tvb_reported_length(tvb) >= 12)
        {
            guint64 destination_offset = 0;
            destination_offset = tvb_get_ntoh48(tvb, 6);
            col_add_fstr(pinfo->cinfo, COL_INFO,
                " type: %s, dest_off: 0x%012" G_GINT64_MODIFIER "x",
                val_to_str(tcode, optommp_tcode_names, "Unknown (0x%02x)"),
                destination_offset);
        }
        else
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, " type: %s",
                val_to_str(tcode, optommp_tcode_names, "Unknown (0x%02x)"));
        }
    }

    if( tree )
    {
        proto_item *root_ti = NULL;
        proto_item *ti = NULL;
        proto_tree *optommp_tree = NULL;
        guint offset = 0;

        /* Add the root node of our protocol */
        root_ti = proto_tree_add_item(tree, proto_optommp, tvb, 0, -1,
            ENC_NA);
        if( tvb_reported_length(tvb) >= OPTOMMP_MIN_LENGTH)
        {
            tcode = tvb_get_guint8(tvb, 3) >> 4;
            proto_item_append_text(root_ti, ", type: %s", val_to_str(tcode,
                optommp_tcode_names, "Unknown (0x%02x)"));
            if( optommp_has_destination_offset(tcode) != 0 )
            {
                guint64 destination_offset = 0;
                destination_offset = tvb_get_ntoh48(tvb, 6);
                proto_item_append_text(root_ti,
                    ", dest_off: 0x%012" G_GINT64_MODIFIER "x",
                    destination_offset);
            }
            /* Add an expansion to the tree */
            optommp_tree = proto_item_add_subtree(root_ti, ett_optommp);
            /* The destination id is the first two bytes of the packet */
            dissect_optommp_dest_id(optommp_tree, tvb, &offset);
            /* Dissect transaction label */
            ti = proto_tree_add_item(optommp_tree, hf_optommp_tl, tvb, offset,
                1, ENC_BIG_ENDIAN);
            ++offset;
            /* Dissect tcode */
            proto_tree_add_item(optommp_tree, hf_optommp_tcode, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            tcode = tvb_get_guint8(tvb, offset) >> 4;
            ++offset;
            /* Dissect the rest of the packet according to type */
            switch( tcode )
            {
            case 0:
                dissect_optommp_write_quadlet_request(&ti, optommp_tree, tvb,
                    &offset);
                break;
            case 1:
                dissect_optommp_write_block_request(&ti, optommp_tree, tvb,
                    &offset);
                break;
            case 2:
                dissect_optommp_write_response(&ti, optommp_tree, tvb,
                    &offset);
                break;
            case 4:
                dissect_optommp_read_quadlet_request(&ti, optommp_tree, tvb,
                    &offset);
                break;
            case 5:
                dissect_optommp_read_block_request(&ti, optommp_tree, tvb,
                    &offset);
                break;
            case 6:
                dissect_optommp_read_quadlet_response(&ti, optommp_tree, tvb,
                    &offset);
                break;
            case 7:
                dissect_optommp_read_block_response(&ti, optommp_tree, tvb,
                    &offset);
                break;
            }
        }
    }

    return tvb_captured_length(tvb);
}

/****************************************************************************
function:       dissect_optommp_dest_id()
parameters:     tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect destination id and boot id
****************************************************************************/
static void dissect_optommp_dest_id(proto_tree *tree,
    tvbuff_t *tvb, guint *poffset)
{
    proto_tree *dest_id_tree = NULL;
    guint16 dest_id = 0;

    /* Check whether boot id present */
    dest_id = tvb_get_ntohs(tvb, *poffset);
    if( (dest_id & 0x8000) == 0x8000 )
    {
        dest_id_tree = proto_tree_add_subtree(tree, tvb, *poffset,
            2, ett_dest_id, NULL, "destination_ID");
        proto_tree_add_item(dest_id_tree, hf_optommp_dest_id,
            tvb, *poffset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(dest_id_tree, hf_optommp_boot_id,
            tvb, *poffset, 2, ENC_BIG_ENDIAN);
    }
    else
    {
        proto_tree_add_item(tree, hf_optommp_nodest_id,
            tvb, *poffset, 2, ENC_BIG_ENDIAN);
    }
    *poffset += 2;
}

/****************************************************************************
function:       dissect_optommp_write_quadlet_request()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a write quadlet request
****************************************************************************/
static void dissect_optommp_write_quadlet_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_destination_offset_6(ti, tree, tvb, poffset);
    dissect_optommp_quadlet_data(ti, tree, tvb, poffset);
}

/****************************************************************************
function:       dissect_optommp_write_block_request()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a write block request
****************************************************************************/
static void dissect_optommp_write_block_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    guint16 data_length = 0;
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_destination_offset_6(ti, tree, tvb, poffset);
    data_length = dissect_optommp_data_length(ti, tree, tvb, poffset);
    *poffset += 2; /* skip extended_tcode */
    dissect_optommp_data_block(ti, tree, tvb, poffset, data_length);
}

/****************************************************************************
function:       dissect_optommp_write_response()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a write response
****************************************************************************/
static void dissect_optommp_write_response(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_rcode(ti, tree, tvb, poffset);
}

/****************************************************************************
function:       dissect_optommp_read_quadlet_request()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a read quadlet request
****************************************************************************/
static void dissect_optommp_read_quadlet_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_destination_offset_6(ti, tree, tvb, poffset);
}

/****************************************************************************
function:       dissect_optommp_read_block_request()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a read block request
****************************************************************************/
static void dissect_optommp_read_block_request(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_destination_offset_6(ti, tree, tvb, poffset);
    dissect_optommp_data_length(ti, tree, tvb, poffset);
}

/****************************************************************************
function:       dissect_optommp_read_quadlet_response
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a read quadlet response
****************************************************************************/
static void dissect_optommp_read_quadlet_response(proto_item **ti,
    proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_rcode(ti, tree, tvb, poffset);
    *poffset += 5; /* Skip reserved part for now */
    dissect_optommp_quadlet_data(ti, tree, tvb, poffset);
}

/****************************************************************************
function:       dissect_optommp_read_block_response()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a read block response
****************************************************************************/
static void dissect_optommp_read_block_response(proto_item **ti, proto_tree
    *tree, tvbuff_t *tvb, guint *poffset)
{
    guint16 data_length = 0;
    dissect_optommp_source_ID(ti, tree, tvb, poffset);
    dissect_optommp_rcode(ti, tree, tvb, poffset);
    *poffset += 5; /* Skip the reserved part for now */
    data_length = dissect_optommp_data_length(ti, tree, tvb, poffset);
    *poffset += 2; /* skip extended_tcode */
    dissect_optommp_data_block(ti, tree, tvb, poffset, data_length);
}

/****************************************************************************
function:       dissect_optommp_source_ID()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect the source id field.
****************************************************************************/
static void dissect_optommp_source_ID(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset)
{
    if( tvb_reported_length(tvb) >= *poffset + 2 )
    {
        *ti = proto_tree_add_item(tree, hf_optommp_source_ID, tvb, *poffset,
            2, ENC_BIG_ENDIAN);
    }
    *poffset += 2;
}

/****************************************************************************
function:       dissect_optommp_destination_offset_6()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Get the destination offset byte by byte and then reassemble
note:           This must be called when the reported length < offset + 8
****************************************************************************/
static void dissect_optommp_destination_offset_6(proto_item **ti,
     proto_tree *tree, tvbuff_t *tvb, guint *poffset)
{
    if( tvb_reported_length(tvb) >= *poffset + 6 )
    {
        *poffset += 2; /* The first two bytes are always 0xFFFF */
        *ti = proto_tree_add_item(tree, hf_optommp_dest_offset, tvb,
            *poffset, 4, ENC_BIG_ENDIAN);
    }
    *poffset += 4;
}

/****************************************************************************
function:       dissect_optommp_quadlet_data()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect the quadlet data part for packets that have it
****************************************************************************/
static void dissect_optommp_quadlet_data(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset)
{
    if( tvb_reported_length(tvb) >= *poffset + 4 )
    {
        *ti = proto_tree_add_item(tree, hf_optommp_quadlet_data, tvb,
            *poffset, 4, ENC_BIG_ENDIAN);
    }
    *poffset += 4;
}

/****************************************************************************
function:       dissect_optommp_data_length()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect data length
****************************************************************************/
static guint16 dissect_optommp_data_length(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset)
{
    guint16 data_length = 0;

    if( tvb_reported_length(tvb) >= *poffset + 2 )
    {
        data_length = tvb_get_ntohs(tvb, *poffset);
        *ti = proto_tree_add_item(tree, hf_optommp_data_length, tvb,
            *poffset, 2, ENC_BIG_ENDIAN);
    }

    *poffset += 2;

    return data_length;
}

/****************************************************************************
function:       dissect_optommp_rcode()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect rcode part for packets that have it
****************************************************************************/
static void dissect_optommp_rcode(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset)
{
    if( tvb_reported_length(tvb) >= *poffset + 1 )
    {
        *ti = proto_tree_add_item(tree, hf_optommp_rcode, tvb, *poffset,
            1, ENC_BIG_ENDIAN);
    }

    ++(*poffset);
}

/****************************************************************************
function:       dissect_optommp_data_block()
parameters:     ti:         The node to add the subtree to
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
                data_length:number of bytes in the data_block
purpose:        Dissect a data block.
****************************************************************************/
static void dissect_optommp_data_block(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset, guint16 data_length)
{
    proto_tree *data_block_tree_b = NULL;
    proto_tree *data_block_tree_q = NULL;
    guint i = 0;
    guint quadlet_offset = 0;
    guint byte_offset = 0;
    quadlet_offset = *poffset;
    byte_offset = *poffset;

    /* Create and fill quadlet subtree */
    data_block_tree_q = proto_tree_add_subtree(tree, tvb, *poffset,
        data_length, ett_data_block_q, ti, "data_block (as quadlets)");

    for( i = 0; i < (guint16) (data_length / 4); ++i )
    {
        dissect_optommp_data_block_quadlet(ti, data_block_tree_q, tvb,
            &quadlet_offset);
    }

    /* Create and fill byte subtree */
    data_block_tree_b = proto_tree_add_subtree(tree, tvb, *poffset,
        data_length, ett_data_block_b, ti, "data_block (as bytes)");

    for( i = 0; i < data_length; ++i )
    {
        dissect_optommp_data_block_byte(ti, data_block_tree_b, tvb,
            &byte_offset);
    }
}

/****************************************************************************
function:       dissect_optommp_data_block_byte()
parameters:     ti:         Reserved for future use
                tree:       The subtree to append nodes to
                tvb:        The data of the current node
                poffset:    Keeps track of our location in the tree
purpose:        Dissect a data block.
****************************************************************************/
static void dissect_optommp_data_block_byte(proto_item **ti, proto_tree *tree,
    tvbuff_t *tvb, guint *poffset)
{
    if( tvb_reported_length(tvb) >= *poffset + 1 )
    {
        GByteArray *unused_ret_val = NULL;
        unused_ret_val = g_byte_array_new();
        /* CheckAPI.pl complained when using ENC_BIG_ENDIAN as the sixth
        *  parameter, so set it to 0x0 */
        *ti = proto_tree_add_bytes_item(tree, hf_optommp_data_block_byte, tvb,
            *poffset, 1, 0x0, unused_ret_val, NULL, NULL);
        g_byte_array_free(unused_ret_val, TRUE);
    }

    ++(*poffset);
}

/****************************************************************************
function:       dissect_optommp_data_block_quadlet()
parameters:     ti:             Reserved for future use
                tree:           The subtree to append nodes to
                tvb:            The data of the current node
                poffset:        Keeps track of our location in the tree
purpose:        Dissect a data block.
****************************************************************************/
static void dissect_optommp_data_block_quadlet(proto_item **ti, proto_tree
    *tree, tvbuff_t *tvb, guint *poffset)
{
    if( tvb_reported_length(tvb) >= *poffset + 4 )
    {
        *ti = proto_tree_add_item(tree, hf_optommp_data_block_quadlet,
            tvb, *poffset, 4, ENC_NA);
    }

    *poffset += 4;
}

/****************************************************************************
function:       dissect_optommp_data_block_quadlet()
parameters:     ti:             Reserved for future use
                tree:           The subtree to append nodes to
                tvb:            The data of the current node
                poffset:        Keeps track of our location in the tree
returns:        1 if packet type has destination_offset field, 0 otherwise
purpose:        Dissect a data block.
****************************************************************************/
static gint optommp_has_destination_offset(guint8 tcode)
{
    if( tcode == 0 || tcode == 1 || tcode == 4 || tcode == 5 )
        return 1;

    return 0;
}

/****************************************************************************
function:       proto_register_optommp()
parameters:     void
purpose:        create and register the protocol, trees, and fields
****************************************************************************/
void proto_register_optommp(void)
{
    module_t *optommp_module;
    /* The fields */
    static hf_register_info hf[] =
    {
        /* When MSB not set, dest_ID is 0 */
        { &hf_optommp_nodest_id,
            { "destination_ID", "optommp.destination_ID",
            FT_UINT16, BASE_HEX,
            NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_optommp_dest_id,
            { "destination_ID", "optommp.destination_ID",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_optommp_boot_id,
            { "boot_ID", "optommp.boot_ID",
            FT_UINT16, BASE_HEX,
            NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_optommp_tl,
            { "tl", "optommp.tl",
            FT_UINT8, BASE_HEX,
            NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_optommp_tcode,
            { "tcode", "optommp.tcode",
            FT_UINT8, BASE_HEX,
            VALS(optommp_tcode_names), 0xF0,
            NULL, HFILL }
        },
        { &hf_optommp_source_ID,
            { "source_ID", "optommp.source_id",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_optommp_rcode,
            { "rcode", "optommp.rcode",
            FT_UINT8, BASE_HEX,
            VALS(optommp_rcode_meanings), 0xF0,
            NULL, HFILL }
        },
        { &hf_optommp_quadlet_data,
            { "quadlet_data", "optommp.quadlet_data",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_optommp_data_length,
            { "data_length", "optommp.data_length",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_optommp_dest_offset,
            { "destination_offset", "optommp.destination_offset",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING,
            RVALS(optommp_mm_areas), 0x0,
            NULL, HFILL }
        },
        { &hf_optommp_data_block_byte,
            { "data_block_byte", "optommp.data_block_byte",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_optommp_data_block_quadlet,
            { "data_block_quadlet", "optommp.data_block_quadlet",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* The subtrees */
    static gint *ett[] =
    {
        &ett_optommp,
        &ett_dest_id,
        &ett_data_block_q,
        &ett_data_block_b
    };
    /* The protocol */
    proto_optommp = proto_register_protocol(
        "OptoMMP",
        "OptoMMP",
        "optommp");
    proto_register_field_array(proto_optommp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    optommp_module = prefs_register_protocol(proto_optommp,
        proto_reg_handoff_optommp);
    prefs_register_uint_preference(optommp_module, "tcp.port",
        "OptoMMP TCP or UDP Port", " OptoMMP TCP or UDP port if other than the default",
        10, &gOPTOMMP_PORT_PREF);
}

/****************************************************************************
function:       proto_reg_handoff()
parameters:     void
purpose:        plug into wireshark with a handle
****************************************************************************/
void proto_reg_handoff_optommp(void)
{
    static gboolean initialized = FALSE;
    static gint currentPort;

    if( !initialized )
    {
        optommp_tcp_handle = create_dissector_handle(
            dissect_optommp_reassemble_tcp, proto_optommp);
        optommp_udp_handle = create_dissector_handle(
            dissect_optommp_reassemble_udp, proto_optommp);
        initialized = TRUE;
    }
    else
    {
        dissector_delete_uint("tcp.port", currentPort, optommp_tcp_handle);
        dissector_delete_uint("udp.port", currentPort, optommp_udp_handle);
    }

    currentPort = gOPTOMMP_PORT_PREF;
    dissector_add_uint("tcp.port", currentPort, optommp_tcp_handle);
    dissector_add_uint("udp.port", currentPort, optommp_udp_handle);
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
