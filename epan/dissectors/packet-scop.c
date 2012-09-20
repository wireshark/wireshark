/* packet-scop.c
 * Owen Kirby <osk@exegin.com>
 *
 * $Id$
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

#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

/* Default SCOP Port numbers. */
#define SCOP_DEFAULT_PORT           17755
#define SCOP_DEFAULT_PORT_SECURED   17756

/* Structure to contain information from the SCoP packet. */
typedef struct {
    guint8      transport;
    guint8      version;
    guint16     length;
    gboolean    encrypted;
    guint8      service;
    guint8      type;
} scop_packet;

/* Header definitions for use with the TCP transport layer. */
#define SCOP_HEADER_LENGTH      4
#define SCOP_LENGTH_OFFSET      2

/* SCoP Transport Types */
#define SCOP_TRANSPORT_UDP        1
#define SCOP_TRANSPORT_TCP        2
#define SCOP_TRANSPORT_UDP_CCM  129
#define SCOP_TRANSPORT_TCP_CCM  130
#define SCOP_TRANSPORT_TCP_SSL  131

/* Service Identifier Field */
#define SCOP_SERVICE_SCOP       0x00
#define SCOP_SERVICE_BRIDGE     0x01
#define SCOP_SERVICE_GATEWAY    0x02

/* SCoP Command Values */
#define SCOP_CMD_HELLO          0x00
#define SCOP_CMD_HELLO_RESP     0x01
#define SCOP_CMD_HELLO_ACK      0x02
#define SCOP_CMD_GOODBYE        0x04
#define SCOP_CMD_GOODBYE_RESP   0x05
#define SCOP_CMD_KEEPALIVE_PING 0x06
#define SCOP_CMD_KEEPALIVE_PONG 0x07

/* Bridge Command type values. */
#define SCOP_BRIDGE_CMD         0x00
#define SCOP_BRIDGE_MSG         0x01

/*  Function declarations */
void proto_reg_handoff_scop(void);

static void dissect_scop           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_scop_tcp       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_scop_zip       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_scop_bridge    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static guint get_scop_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset);

/*  Initialize protocol and registered fields */
static int proto_scop = -1;
static int hf_scop_transport = -1;
static int hf_scop_version = -1;
static int hf_scop_length = -1;
static int hf_scop_service = -1;
static int hf_scop_type = -1;
static int hf_scop_status = -1;

static gint ett_scop = -1;

static const value_string scop_transports [] = {
    { SCOP_TRANSPORT_UDP,       "UDP Mode 1" },
    { SCOP_TRANSPORT_TCP,       "TCP Mode 2" },
    { SCOP_TRANSPORT_UDP_CCM,   "UDP Mode 1 with CCM* Security" },
    { SCOP_TRANSPORT_TCP_CCM,   "TCP Mode 2 with CCM* Security" },
    { SCOP_TRANSPORT_TCP_SSL,   "TCP Mode 3 with SSL/TSL Tunnel" },
    { 0, NULL }
};

static const value_string scop_types [] = {
    { SCOP_CMD_HELLO,           "Hello" },
    { SCOP_CMD_HELLO_RESP,      "Hello Response" },
    { SCOP_CMD_HELLO_ACK,       "Hello Acknowledgment" },
    { SCOP_CMD_GOODBYE,         "Goodbye" },
    { SCOP_CMD_GOODBYE_RESP,    "Goodbye Response" },
    { SCOP_CMD_KEEPALIVE_PING,  "Keep Alive Ping" },
    { SCOP_CMD_KEEPALIVE_PONG,  "Keep Alive Pong" },
    { 0, NULL }
};

static const value_string scop_services [] = {
    { SCOP_SERVICE_SCOP,    "SCoP" },
    { SCOP_SERVICE_BRIDGE,  "Bridge" },
    { SCOP_SERVICE_GATEWAY, "Gateway" },
    { 0, NULL }
};

static guint32  gPREF_scop_port         = SCOP_DEFAULT_PORT;
static guint32  gPREF_scop_port_secured = SCOP_DEFAULT_PORT_SECURED;

/*  Dissector handle */
static dissector_handle_t data_handle;
static dissector_handle_t ieee802154_handle;

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      get_scop_length
 *  DESCRIPTION
 *      Returns the length of a SCoP packet. For use with the TCP
 *      transport type.
 *  PARAMETERS
 *      packet_info *pinfo  - pointer to packet information fields
 *      tvbuff_t    *tvb    - pointer to buffer containing the packet.
 *      int         offset  - beginning of packet.
 *  RETURNS
 *      guint               - Length of SCoP packet
 *---------------------------------------------------------------
 */
static guint
get_scop_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    /* Byte  0:   Protocol Type.
     * Byte  1:   Protocol Version.
     * Bytes 2-3: Packet Length (network order).
     */
    return tvb_get_ntohs(tvb, offset + SCOP_LENGTH_OFFSET);
} /* get_scop_length */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_scop_tcp
 *  DESCRIPTION
 *      ZigBee SCoP packet dissection routine for Wireshark.
 *      for use with TCP ports.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_scop_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, SCOP_HEADER_LENGTH, get_scop_length, dissect_scop);
} /* dissect_scop_tcp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_scop
 *  DESCRIPTION
 *      ZigBee SCoP packet dissection routine for Wireshark.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_scop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t    *next_tvb;
    proto_item  *proto_root;
    proto_tree  *scop_tree;

    guint        offset = 0;
    scop_packet  packet;

    memset(&packet, 0, sizeof(packet));

    /* Set the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCoP");

    /* Clear the info column. */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create the protocol display tree. */
    proto_root = proto_tree_add_protocol_format(tree, proto_scop, tvb, 0, tvb_length(tvb),
                                                "ZigBee SCoP");
    scop_tree = proto_item_add_subtree(proto_root, ett_scop);

    /* Extract the SCoP Transport type. */
    packet.transport = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(scop_tree, hf_scop_transport, tvb, offset, 1, packet.transport);
    offset += 1;

    /* Extract the SCoP Version. */
    packet.version = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(scop_tree, hf_scop_version, tvb, offset, 1, packet.version);
    offset += 1;

    /* Extract the SCoP Packet length. */
    packet.length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(scop_tree, hf_scop_length, tvb, offset, 2, packet.length);
    offset += 2;

    if (   (packet.transport == SCOP_TRANSPORT_UDP_CCM)
        || (packet.transport == SCOP_TRANSPORT_TCP_CCM)) {
        next_tvb = NULL; /*dissect_zbee_secure(tvb, pinfo, scop_tree, offset, 0);*/
        if (next_tvb == NULL) {
            /* Decryption Failed. */
            return;
        }
        offset = 0;
    }
    else {
        next_tvb = tvb;
    }

    /* Extract the service type. */
    packet.service = tvb_get_guint8(next_tvb, offset);
    proto_tree_add_uint(scop_tree, hf_scop_service, next_tvb, offset, 1, packet.service);
    offset += 1;

    /* Call the appropriate helper routine to dissect based on the service type. */
    switch (packet.service) {
        case SCOP_SERVICE_SCOP:
            dissect_scop_zip(tvb_new_subset_remaining(next_tvb, offset), pinfo, scop_tree);
            break;
        case SCOP_SERVICE_BRIDGE:
            dissect_scop_bridge(tvb_new_subset_remaining(next_tvb, offset), pinfo, scop_tree);
            break;
        case SCOP_SERVICE_GATEWAY:
            /* Nothing yet defined for the gateway. Fall-Through. */
        default:
            /* Unknown Service Type. */
            call_dissector(data_handle, tvb_new_subset_remaining(next_tvb, offset), pinfo, tree);
            break;
    }
} /* dissect_scop() */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_scop_zip
 *  DESCRIPTION
 *      Intermediate dissector for the SCoP service type.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_scop_zip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;
    guint8      type = tvb_get_guint8(tvb, offset);
    guint16     status;

    /* Display the Packet type*/
    proto_tree_add_uint(tree, hf_scop_type, tvb, offset, 1, type);
    proto_item_append_text(tree, ", %s", val_to_str_const(type, scop_types, "Reserved Type"));
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(type, scop_types, "Reserved Type"));
    offset += 2;

    if (type == SCOP_CMD_HELLO_RESP) {
        status = tvb_get_ntohs(tvb, 1);
        proto_tree_add_uint_format(tree, hf_scop_status, tvb, offset, 2, status, "Status: %s", (status==0x0000)?"Success":"Failure");
        offset += 2;
    }

    /* If there are any bytes left over, pass them to the data dissector. */
    if (offset < tvb_length(tvb)) {
        tvbuff_t    *payload_tvb = tvb_new_subset_remaining(tvb, offset);
        proto_tree  *root        = proto_tree_get_root(tree);
        call_dissector(data_handle, payload_tvb, pinfo, root);
    }
} /* dissect_scop_zip() */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_scop_bridge
 *  DESCRIPTION
 *      Intermediate dissector for the Bridge service type.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_scop_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    call_dissector(ieee802154_handle, tvb, pinfo, proto_tree_get_root(tree));
} /* dissect_scop_bridge() */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_scop
 *  DESCRIPTION
 *      SCoP protocol registration.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_scop(void)
{
    module_t *scop_module;

    static hf_register_info hf[] = {
        { &hf_scop_transport,
        { "Transport Type",         "scop.transport", FT_UINT8, BASE_DEC, VALS(scop_transports), 0x0,
            "The type of transport used.", HFILL }},

        { &hf_scop_version,
        { "Version",                "scop.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The version of the sniffer.", HFILL }},

        { &hf_scop_length,
        { "Length",                 "scop.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_scop_service,
        { "Service Identifier",     "scop.service", FT_UINT8, BASE_DEC, VALS(scop_services), 0x0,
            NULL, HFILL }},

        { &hf_scop_type,
        { "Packet Type",            "scop.type", FT_UINT8, BASE_DEC, VALS(scop_types), 0x0,
            "Service-specific packet type.", HFILL }},

        { &hf_scop_status,
        { "Status",                 "scop.status", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Status of the SCoP Command.", HFILL }}
    };

    static gint *ett[] = {
        &ett_scop
    };

    /*  Register protocol name and description. */
    proto_scop = proto_register_protocol("ZigBee SCoP", "SCoP", "scop");

    /*  Register header fields and subtrees. */
    proto_register_field_array(proto_scop, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*  Register preferences module */
    scop_module = prefs_register_protocol(proto_scop, proto_reg_handoff_scop);

    /*  Register preferences */
    prefs_register_uint_preference(scop_module, "port", "SCoP Port",
                 "Set the port for SCoP\n",
                 10, &gPREF_scop_port);
    prefs_register_uint_preference(scop_module, "port_secure", "SCoP Secured Port",
                 "Set the port for secured SCoP\n",
                 10, &gPREF_scop_port_secured);

    /*  Register dissector with Wireshark. */
    register_dissector("scop.udp", dissect_scop, proto_scop);
    register_dissector("scop.tcp", dissect_scop_tcp, proto_scop);
} /* proto_register_scop() */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_scop
 *  DESCRIPTION
 *      Registers the zigbee dissector with Wireshark.
 *      Will be called every time 'apply' is pressed in the preferences menu.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_scop(void)
{
    static gboolean inited = FALSE;
    static guint32  lastPort;
    static guint32  lastPort_secured;

    static dissector_handle_t  scop_udp_handle;
    static dissector_handle_t  scop_tcp_handle;

    if (!inited){
        scop_udp_handle     = find_dissector("scop.udp");
        scop_tcp_handle     = find_dissector("scop.tcp");
        ieee802154_handle   = find_dissector("wpan_nofcs");
        data_handle         = find_dissector("data");
        inited = TRUE;
    } else {
        dissector_delete_uint("udp.port", lastPort, scop_udp_handle);
        dissector_delete_uint("tcp.port", lastPort, scop_tcp_handle);
        dissector_delete_uint("udp.port", lastPort_secured, scop_udp_handle);
        dissector_delete_uint("tcp.port", lastPort_secured, scop_tcp_handle);
    }
    dissector_add_uint("udp.port", gPREF_scop_port, scop_udp_handle);
    dissector_add_uint("tcp.port", gPREF_scop_port, scop_tcp_handle);
    dissector_add_uint("udp.port", gPREF_scop_port_secured, scop_udp_handle);
    dissector_add_uint("tcp.port", gPREF_scop_port_secured, scop_tcp_handle);

    lastPort         = gPREF_scop_port;
    lastPort_secured = gPREF_scop_port_secured;
} /* proto_reg_handoff_scop */

