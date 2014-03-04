/* packet-mactelnet.c
 * Routines for MAC-Telnet dissection
 * Copyright 2010, Haakon Nessjoen <haakon.nessjoen@gmail.com>
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

/*
 * Thanks to "omniflux" for dissecting the protocol by hand before me.
 * http://www.omniflux.com/devel/mikrotik/Mikrotik_MAC_Telnet_Procotol.txt
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

void proto_register_mactelnet(void);
void proto_reg_handoff_mactelnet(void);

#define PROTO_TAG_MACTELNET "MAC-Telnet"

/* Initialize the protocol and registered fields */
static gint proto_mactelnet = -1;
static gint hf_mactelnet_control_packet = -1;
static gint hf_mactelnet_type = -1;
static gint hf_mactelnet_protocolver = -1;
static gint hf_mactelnet_source_mac = -1;
static gint hf_mactelnet_destination_mac = -1;
static gint hf_mactelnet_session_id = -1;
static gint hf_mactelnet_client_type = -1;
static gint hf_mactelnet_databytes = -1;
static gint hf_mactelnet_datatype = -1;
static gint hf_mactelnet_control = -1;
static gint hf_mactelnet_control_length = -1;
static gint hf_mactelnet_control_encryption_key = -1;
static gint hf_mactelnet_control_password = -1;
static gint hf_mactelnet_control_username = -1;
static gint hf_mactelnet_control_terminal = -1;
static gint hf_mactelnet_control_width = -1;
static gint hf_mactelnet_control_height = -1;

/* Global port preference */
static guint global_mactelnet_port = 20561;

/* Control packet definition */
static const guint32 control_packet = 0x563412FF;

/* Initialize the subtree pointers */
static gint ett_mactelnet = -1;
static gint ett_mactelnet_control = -1;

static dissector_handle_t data_handle;

/* Packet types */
static const value_string packettypenames[] = {
    {   0, "Start session" },
    {   1, "Data" },
    {   2, "Acknowledge" },
    {   4, "Ping request" },
    {   5, "Ping response" },
    { 255, "End session" },
    { 0, NULL }
};

/* Known client types */
static const value_string clienttypenames[] = {
    { 0x0015, "MAC Telnet" },
    { 0x0f90, "Winbox" },
    { 0, NULL }
};

/* Known control-packet types */
static const value_string controlpackettypenames[] = {
    { 0, "Begin authentication" },
    { 1, "Encryption key" },
    { 2, "Password" },
    { 3, "Username" },
    { 4, "Terminal type" },
    { 5, "Terminal width" },
    { 6, "Terminal height" },
    { 9, "End authentication" },
    { 0, NULL }
};


static int
dissect_mactelnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *mactelnet_item;
    proto_tree *mactelnet_tree;
    proto_item *mactelnet_control_item;
    proto_tree *mactelnet_control_tree;
    int         foundping   = -1;
    int         foundclient = -1;
    int         foundserver = -1;
    guint16     type;

    /* Check that there's enough data */
    if (tvb_length(tvb) < 18)
        return 0;

    /*  Get the type byte */
    type = tvb_get_guint8(tvb, 1);

    if ((type == 4) || (type == 5)) { /* Ping */
        foundping = 1;
    } else {
        int i = 0;
        while (clienttypenames[i].strptr != NULL) {
            if (tvb_get_ntohs(tvb, 14) == clienttypenames[i].value) {
                foundserver = i;
                break;
            }
            if (tvb_get_ntohs(tvb, 16) == clienttypenames[i].value) {
                foundclient = i;
                break;
            }
            i++;
        }
    }

    /* Not a mactelnet packet */
    if ((foundping < 0) && (foundclient < 0) && (foundserver < 0)) {
        return 0;
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MACTELNET);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s Direction: %s Type: %s",
                    tvb_ether_to_str(tvb, 2),
                    tvb_ether_to_str(tvb, 8),
                    ((foundclient >= 0) || (type == 4) ? "Client->Server" : "Server->Client" ),
                    val_to_str(type, packettypenames, "Unknown Type:0x%02x")
        );

    if (tree) {
        guint32 offset = 0;

        /* create display subtree for the protocol */
        mactelnet_item = proto_tree_add_item(tree, proto_mactelnet, tvb, 0, -1, ENC_NA);
        mactelnet_tree = proto_item_add_subtree(mactelnet_item, ett_mactelnet);

        /* ver(1) */
        proto_tree_add_item(mactelnet_tree, hf_mactelnet_protocolver, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* ptype(1) */
        proto_tree_add_item(mactelnet_tree, hf_mactelnet_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* saddr(6) */
        proto_tree_add_item(mactelnet_tree, hf_mactelnet_source_mac, tvb, offset, 6, ENC_NA);
        offset += 6;

        /* dstaddr(6) */
        proto_tree_add_item(mactelnet_tree, hf_mactelnet_destination_mac, tvb, offset, 6, ENC_NA);
        offset += 6;

        if (foundserver >= 0) {
            /* Server to client */

            /* sessionid(2) */
            proto_tree_add_item(mactelnet_tree, hf_mactelnet_session_id, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* clienttype(2) */
            proto_tree_add_item(mactelnet_tree, hf_mactelnet_client_type, tvb, offset-2, 2, ENC_BIG_ENDIAN);
            offset += 2;
        } else if (foundclient >= 0) {
            /* Client to server */

            /* sessionid(2) */
            proto_tree_add_item(mactelnet_tree, hf_mactelnet_session_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* clienttype(2) */
            proto_tree_add_item(mactelnet_tree, hf_mactelnet_client_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        } else if (foundping >= 0) {
            /* Skip empty data */
            offset += 4;
        }

        if (foundping < 0) {
            /* counter(4) */
            proto_tree_add_item(mactelnet_tree, hf_mactelnet_databytes, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }

        /* Data packets only */
        if (type == 1) {
            while(tvb_reported_length_remaining(tvb, offset) > 0) {
                if ((tvb_reported_length_remaining(tvb, offset) > 4) && (tvb_get_ntohl(tvb, offset) == control_packet)) {
                    guint8  datatype;
                    guint32 datalength;

                    /* Add subtree for control packet */
                    mactelnet_control_item = proto_tree_add_item(mactelnet_tree, hf_mactelnet_control, tvb, offset, -1, ENC_NA);
                    mactelnet_control_tree = proto_item_add_subtree(mactelnet_control_item, ett_mactelnet);
                    /* Control packet magic number (4) */
                    proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_packet, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    /* Control packet type (1) */
                    datatype = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_datatype, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    /* Control packet length (4) */
                    datalength = tvb_get_ntohl(tvb, offset);
                    proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_length, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    switch (datatype) {
                        case 1: /* Encryption Key */
                            proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_encryption_key, tvb, offset, datalength, ENC_NA);
                            break;

                        case 2: /* Password */
                            proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_password, tvb, offset, datalength, ENC_NA);
                            break;

                        case 3: /* Username */
                            proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_username, tvb, offset, datalength, ENC_ASCII|ENC_NA);
                            break;

                        case 4: /* Terminal type */
                            proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_terminal, tvb, offset, datalength, ENC_ASCII|ENC_NA);
                            break;

                        case 5: /* Terminal width */
                            proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            break;

                        case 6: /* Terminal height */
                            proto_tree_add_item(mactelnet_control_tree, hf_mactelnet_control_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            break;

                        case 9: /* End authentication (no data) */
                            break;
                    }
                    proto_item_set_len (mactelnet_control_item, datalength + 9);
                    offset += datalength;
                } else {
                    /* Data packet, let wireshark handle it */
                    tvbuff_t *next_client = tvb_new_subset_remaining(tvb, offset);
                    return call_dissector(data_handle, next_client, pinfo, mactelnet_tree);
                }
            }
        } else if ((type == 4) || (type == 5)) {
            /* Data packet, let wireshark handle it */
            tvbuff_t *next_client = tvb_new_subset_remaining(tvb, offset);
            return call_dissector(data_handle, next_client, pinfo, mactelnet_tree);
        }


    }
    return tvb_reported_length(tvb);
}


void
proto_register_mactelnet(void)
{
    static hf_register_info hf[] = {
        { &hf_mactelnet_control_packet,
          { "Control Packet Magic Number", "mactelnet.control_packet",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_type,
          { "Type", "mactelnet.type",
            FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0,
            "Packet Type", HFILL }
        },
        { &hf_mactelnet_protocolver,
          { "Protocol Version", "mactelnet.protocol_version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_source_mac,
          { "Source MAC", "mactelnet.source_mac",
            FT_ETHER, BASE_NONE, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_destination_mac,
          { "Destination MAC", "mactelnet.destination_mac",
            FT_ETHER, BASE_NONE, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_session_id,
          { "Session ID", "mactelnet.session_id",
            FT_UINT16, BASE_HEX, NULL , 0x0,
            "Session ID for this connection", HFILL }
        },
        { &hf_mactelnet_client_type,
          { "Client Type", "mactelnet.client_type",
            FT_UINT16, BASE_HEX, VALS(clienttypenames) , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_databytes,
          { "Session Data Bytes", "mactelnet.session_bytes",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            "Session data bytes received", HFILL }
        },
        { &hf_mactelnet_datatype,
          { "Data Packet Type", "mactelnet.data_type",
            FT_UINT8, BASE_HEX, VALS(controlpackettypenames) , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_control,
          { "Control Packet", "mactelnet.control",
            FT_NONE, BASE_NONE, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_control_length,
          { "Control Data Length", "mactelnet.control_length",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            "Control packet length", HFILL }
        },
        { &hf_mactelnet_control_encryption_key,
          { "Encryption Key", "mactelnet.control_encryptionkey",
            FT_BYTES, BASE_NONE, NULL , 0x0,
            "Login encryption key", HFILL }
        },
        { &hf_mactelnet_control_password,
          { "Password MD5", "mactelnet.control_password",
            FT_BYTES, BASE_NONE, NULL , 0x0,
            "Null padded MD5 password", HFILL }
        },
        { &hf_mactelnet_control_username,
          { "Username", "mactelnet.control_username",
            FT_STRING, BASE_NONE, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_control_terminal,
          { "Terminal Type", "mactelnet.control_terminaltype",
            FT_STRING, BASE_NONE, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_control_width,
          { "Terminal Width", "mactelnet.control_width",
            FT_UINT16, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mactelnet_control_height,
          { "Terminal Height", "mactelnet.control_height",
            FT_UINT16, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mactelnet,
        &ett_mactelnet_control,
    };

    module_t *mactelnet_module;

    /* Register the protocol name and description */
    proto_mactelnet = proto_register_protocol ("MikroTik MAC-Telnet Protocol", PROTO_TAG_MACTELNET, "mactelnet");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array (proto_mactelnet, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

    mactelnet_module = prefs_register_protocol(proto_mactelnet, proto_reg_handoff_mactelnet);

    prefs_register_uint_preference(mactelnet_module, "port", "UDP Port",
                       "MAC-Telnet UDP port if other than the default",
                       10, &global_mactelnet_port);
}

void
proto_reg_handoff_mactelnet(void)
{
    static gboolean           initialized = FALSE;
    static guint              current_port;
    static dissector_handle_t mactelnet_handle;

    if (!initialized) {
        mactelnet_handle = new_create_dissector_handle(dissect_mactelnet, proto_mactelnet);
        data_handle = find_dissector("data");
        initialized = TRUE;
    } else {
        dissector_delete_uint("udp.port", current_port, mactelnet_handle);
    }

    current_port = global_mactelnet_port;
    dissector_add_uint("udp.port", current_port, mactelnet_handle);
}
