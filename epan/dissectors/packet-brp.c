/* packet-brp.c
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
 * This is a dissector for the BRP (Bandwidth Reservation Protocol). This protocol
 * is used by various telecommunications vendors to establish VoD (Video
 * On-Demand) sessions between a STB (Set Top Box) at the customer's home and the
 * VoD server at the video head-end.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

/* Forward declaration we need below */
void proto_register_brp(void);
void proto_reg_handoff_brp(void);

#define PROTO_TAG_BRP   "BRP"

/* Wireshark ID of the BRP protocol */
static int proto_brp = -1;

static dissector_handle_t brp_handle;

/*static int global_brp_port = 1958; *//* The port is registered for another protocol */

static const value_string brp_packettype_names[] = {
    {  0, "BRP" },
    {  1, "Setup Request - BRC -> BRS" },
    {  2, "Setup Response - BRS -> BRC" },
    {  3, "Teardown Request - BRC -> BRS" },
    {  4, "Teardown Response - BRS -> BRC" },
    {  5, "Heartbeat Request - BRS -> BRC" },
    {  6, "Heartbeat Response - BRC -> BRS" },
    {  7, "Unidirectional Flow Create Request - BRC -> BRS" },
    {  8, "Flow Create Response - BRS -> BRC" },
    {  9, "Flow Delete Request BRC -> BRS" },
    { 10, "Flow Delete Response - BRS -> BRC" },
    { 11, "Flow Get Request - BRC -> BRS" },
    { 12, "Flow Get Response - BRS -> BRC" },
    { 13, "Flow Get Next Request - BRC -> BRS" },
    { 14, "Flow Get Next Response - BRS -> BRC" },
    { 15, "Flow Abort - BRS -> BRC" },
    { 0, NULL }
};

static const value_string brp_stat_vals[] = {
    {  0, "OK" },
    {  1, "Comm Error - Network connectivity has been lost (Client Message)." },
    {  2, "No Bandwidth - There is insufficient bandwidth available in the network to honor the request (Server Message)." },
    {  3, "Insufficient Resource - Either there is insufficient memory or resource available to transmit the request or,"
           " insufficient resources existed at the server to complete the request. Note that insufficient bandwidth in the"
           " network is handled by the previous status value. This is the catchall for all other resource deficiencies"
           " (Client/Server Message)." },
    {  4, "No Such - The requested flow does not exist (Server Message)." },
    {  5, "No Session - There is no active session. The server may return this in the event that the client and server"
           " are out of sync. In that eventuality, the client must reestablish its session and recreate any flows that"
           " it believes have been lost (Server Message)." },
    {  6, "Invalid Argument - One of the input arguments to the call was not valid (Client/Server Message)." },
    {  7, "Unreachable - The specified BRS is not reachable (Client Message)." },
    {  8, "Internal Error - An internal fault has occurred. This is generally indicative of a fatal condition within"
           " the client system (Server Message)." },
    {  9, "Already Exists - The flow or session that the client requested already exists (Server Message)." },
    { 10, "Flow Removed - The flow was removed or lost due to issues internal to the network (Server Message)." },
    { 11, "Invalid Sender - Received packet was from an unknown sender (Server Message)." },
    { 12, "Invalid Message - Input message is not defined or malformed (Client/Server Message)." },
    { 13, "Unsupported Version - The requested version (in a setup) is not supported (Server Message)." },
    { 14, "Pending - The requested operation is proceeding and a status will be returned with the final result"
           " shortly (Server Message)." },
    { 0, NULL }
};

/* The following hf_* variables are used to hold the Wireshark IDs of
* our data fields; they are filled out when we call
* proto_register_field_array() in proto_register_brp()
*/
static gint hf_brp_type = -1;
static gint hf_brp_trans = -1;
static gint hf_brp_ver = -1;
static gint hf_brp_stat = -1;
static gint hf_brp_srcip = -1;
static gint hf_brp_dstip = -1;
static gint hf_brp_dstuport = -1;
static gint hf_brp_mbz = -1;
static gint hf_brp_bw = -1;
static gint hf_brp_life = -1;
static gint hf_brp_flid = -1;
static gint hf_brp_rmttl = -1;
static gint hf_brp_fltype = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_brp = -1;
static gint ett_brp_type = -1;
static gint ett_brp_trans = -1;
static gint ett_brp_ver = -1;
static gint ett_brp_stat = -1;
static gint ett_brp_srcip = -1;
static gint ett_brp_dstip = -1;
static gint ett_brp_dstuport = -1;
static gint ett_brp_mbz = -1;
static gint ett_brp_bw = -1;
static gint ett_brp_life = -1;
static gint ett_brp_flid = -1;
static gint ett_brp_rmttl = -1;
static gint ett_brp_fltype = -1;

static expert_field ei_brp_type_unknown = EI_INIT;

/* Preferences */
static guint global_brp_port = 0;

static int
dissect_brp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    proto_item *brp_item    = NULL;
    proto_tree *brp_tree    = NULL;
    gint        offset      = 0;
    guint8      type        = 0;
    guint8      packet_type = tvb_get_guint8(tvb, 0);

    /* If there is a "tree" requested, we handle that request. */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_BRP);
    /* We add some snazzy bizness to the info field to quickly ascertain
        what type of message was sent to/from the BRS/BRC. */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type - %s",
            val_to_str(packet_type, brp_packettype_names, "Unknown (0x%02x)"));

    /* This call adds our tree to the main dissection tree. */

    if (tree) { /* we are being asked for details */

        /* Here we add our tree/subtree so we can have a collapsible branch. */
        brp_item = proto_tree_add_item( tree, proto_brp, tvb, 0, -1, ENC_NA );
        brp_tree = proto_item_add_subtree( brp_item, ett_brp);

        /* We use tvb_get_guint8 to get our type value out. */
        type = tvb_get_guint8(tvb, offset);
        offset += 0;

        brp_item = proto_tree_add_item( brp_tree, hf_brp_type, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset += 1;

        /* Now let's break down each packet and display it in the collapsible branch */
        switch(type)
        {
        case 1: /* Setup Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_ver, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 2: /* Setup Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_stat, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 3: /* Teardown Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            break;

        case 4: /* Teardown Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            break;

        case 5: /* Heartbeat Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            break;

        case 6: /* Heartbeat Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            break;

        case 7: /* Uni Flow Create Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_srcip, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_dstip, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_dstuport, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset +=2;
            proto_tree_add_item( brp_tree, hf_brp_mbz, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset +=2;
            proto_tree_add_item( brp_tree, hf_brp_bw, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_life, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 8: /* Flow Create Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_stat, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 9: /* Flow Delete Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 10: /* Flow Delete Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_stat, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 11: /* Flow Get Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 12: /* Flow Get Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_stat, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_rmttl, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_srcip, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_dstip, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_dstuport, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset +=2;
            proto_tree_add_item( brp_tree, hf_brp_mbz, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset +=2;
            proto_tree_add_item( brp_tree, hf_brp_fltype, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset +=1;
            proto_tree_add_item( brp_tree, hf_brp_bw, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset +=3;
            proto_tree_add_item( brp_tree, hf_brp_life, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 13: /* Flow Get Next Request */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 14: /* Flow Get Next Response */
            proto_tree_add_item( brp_tree, hf_brp_trans, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset += 3;
            proto_tree_add_item( brp_tree, hf_brp_stat, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_rmttl, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_srcip, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_dstip, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_dstuport, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset +=2;
            proto_tree_add_item( brp_tree, hf_brp_mbz, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset +=2;
            proto_tree_add_item( brp_tree, hf_brp_fltype, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset +=1;
            proto_tree_add_item( brp_tree, hf_brp_bw, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset +=3;
            proto_tree_add_item( brp_tree, hf_brp_life, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        case 15: /* Flow Abort */
            proto_tree_add_item( brp_tree, hf_brp_mbz, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset +=3;
            proto_tree_add_item( brp_tree, hf_brp_flid, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            break;

        default:
            /* Invalid type */
            expert_add_info(pinfo, brp_item, &ei_brp_type_unknown);
            break;
        }

    }
return offset;
}

/*--- proto_register_brp ----------------------------------------------*/
void proto_register_brp (void)
{
    module_t *brp_module;
    expert_module_t* expert_brp;

    /* A data field is something you can search/filter on.
    *
    * We create a structure to register our fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
    static hf_register_info hf[] = {
        { &hf_brp_type,
          { "Type", "brp.type", FT_UINT8, BASE_DEC, VALS(brp_packettype_names), 0x0,
            NULL, HFILL }},
        { &hf_brp_trans,
          { "Transaction ID", "brp.trans", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_ver,
          { "Version", "brp.ver", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_stat,
          { "Status", "brp.stat", FT_UINT8, BASE_DEC, VALS(brp_stat_vals), 0x0,
            NULL, HFILL }},
        { &hf_brp_srcip,
          { "Source IP Address", "brp.srcip", FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_dstip,
          { "Destination IP Address", "brp.dstip", FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_dstuport,
          { "Destination UDP Port", "brp.dstuport", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_mbz,
          { "MBZ", "brp.mbz", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_bw,
          { "Bandwidth - Kbytes/sec", "brp.bw", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_life,
          { "Lifetime", "brp.life", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_flid,
          { "Flow Identifier", "brp.flid", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_fltype,
          { "Flow Type", "brp.fltype", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_brp_rmttl,
          { "Remaining TTL", "brp.rmttl", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_brp,
        &ett_brp_type,
        &ett_brp_trans,
        &ett_brp_ver,
        &ett_brp_stat,
        &ett_brp_srcip,
        &ett_brp_dstip,
        &ett_brp_dstuport,
        &ett_brp_mbz,
        &ett_brp_bw,
        &ett_brp_life,
        &ett_brp_flid,
        &ett_brp_fltype,
        &ett_brp_rmttl

    };

    static ei_register_info ei[] = {
        { &ei_brp_type_unknown, { "brp.type.unknown", PI_UNDECODED, PI_WARN, "Unknown packet type", EXPFILL }},
    };

    proto_brp = proto_register_protocol ("BRP Protocol", "BRP", "brp");
    proto_register_field_array (proto_brp, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    expert_brp = expert_register_protocol(proto_brp);
    expert_register_field_array(expert_brp, ei, array_length(ei));

    /* Register preferences module */
    brp_module = prefs_register_protocol(proto_brp, proto_reg_handoff_brp);

    /* Register preferences */
    prefs_register_uint_preference(brp_module, "port",
                                   "BRP Port",
                                   "Set the UDP port for BRP messages",
                                   10, &global_brp_port);

    brp_handle = register_dissector("brp", dissect_brp, proto_brp);
}

/*--- proto_reg_handoff_brp -------------------------------------------*/
void proto_reg_handoff_brp(void)
{
    static gboolean           initialized = FALSE;
    static guint              saved_brp_port;

    if (!initialized) {
        dissector_add_for_decode_as("udp.port", brp_handle);
        initialized = TRUE;
    } else {
        if (saved_brp_port != 0) {
            dissector_delete_uint("udp.port", saved_brp_port, brp_handle);
        }
    }

    /* Set the port number */
    if (global_brp_port != 0) {
        dissector_add_uint("udp.port", global_brp_port, brp_handle);
    }
    saved_brp_port = global_brp_port;
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
