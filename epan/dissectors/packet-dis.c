/* packet-dis.c
 * Routines for Distributed Interactive Simulation packet
 * disassembly (IEEE-1278).
 * Copyright 2005, Scientific Research Corporation
 * Initial implementation by Jeremy Ouellette <jouellet@scires.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* TODO / NOTES:
 * Field handling isn't ideal; this dissector should probably register
 * each individual field via the proto_register_field_array mechanism.
 * This would lead to better PDML output (instead of requiring the end user
 * to manually parse out the key/value pairs) and better searchability in
 * interactive mode.
 *
 * Lots more PDUs to implement.  Only the basic engagement events are currently
 * handled (Fire, Detonation, Entity State).  Most of the basic field types are
 * complete, however, so declaring new PDUs should be fairly simple.
 *
 * Lots more enumerations to implement.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <epan/packet.h>
#include <epan/value_string.h>
#include <epan/prefs.h>
#include "packet-dis-enums.h"
#include "packet-dis-pdus.h"
#include "packet-dis-fields.h"

#define DEFAULT_DIS_UDP_PORT 3000

static gint proto_dis = -1;
static gint ett_dis = -1;
static gint ett_dis_header = -1;
static gint ett_dis_payload = -1;

static dissector_handle_t dis_dissector_handle;
static guint dis_udp_port = DEFAULT_DIS_UDP_PORT;

static const char* dis_proto_name = "Distributed Interactive Simulation";
static const char* dis_proto_name_short = "DIS";

/* Main dissector routine to be invoked for a DIS PDU.
 */
static gint dissect_dis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *dis_tree = 0;
    proto_item *dis_node = 0;
    proto_item *dis_header_tree = 0;
    proto_item *dis_header_node = 0;
    proto_item *dis_payload_tree = 0;
    proto_item *dis_payload_node = 0;
    gint offset = 0;
    const gchar *pduString = 0;
    DIS_ParserNode *pduParser = 0;

    /* DIS packets must be at least 12 bytes long.  DIS uses port 3000, by
     * default, but the Cisco Redundant Link Management protocol can also use
     * that port; RLM packets are 8 bytes long, so we use this to distinguish
     * between them.
     */
    if (tvb_reported_length(tvb) < 12)
    {
        return 0;
    }

    /* Reset the global PDU type variable -- this will be parsed as part of
     * the DIS header.
     */
    pduType = DIS_PDUTYPE_OTHER;
    numArticulations = 0;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, dis_proto_name_short);
    }

    /* Add the top-level DIS node under which the rest of the fields will be
     * displayed.
     */
    dis_node = proto_tree_add_protocol_format(tree, proto_dis, tvb, offset,
        -1, "Distributed Interactive Simulation");
    dis_tree = proto_item_add_subtree(dis_node, ett_dis);

    /* Add a node to contain the DIS header fields.
     */
    dis_header_node = proto_tree_add_text(dis_tree, tvb, offset, -1, "Header");
    dis_header_tree = proto_item_add_subtree(dis_header_node, ett_dis_header);
    offset = parseFields(tvb, dis_header_tree, offset, DIS_FIELDS_PDU_HEADER);
    proto_item_set_end(dis_header_node, tvb, offset);

    /* Locate the appropriate PDU parser, if type is known.
     */
    switch (pduType)
    {
    case DIS_PDUTYPE_ENTITY_STATE:
        pduParser = DIS_PARSER_ENTITY_STATE_PDU;
        break;
    case DIS_PDUTYPE_FIRE:
        pduParser = DIS_PARSER_FIRE_PDU;
        break;
    case DIS_PDUTYPE_DETONATION:
        pduParser = DIS_PARSER_DETONATION_PDU;
        break;
    default:
        pduParser = 0;
	break;
    }

    /* Locate the string name for the PDU type enumeration, or default to
     * "Unknown".
     */
    pduString = val_to_str(pduType, DIS_PDU_Type_Strings, "Unknown"); 

    /* Add a node to contain the DIS PDU fields.
     */
    dis_payload_node = proto_tree_add_text(dis_tree, tvb, offset, -1,
        "%s PDU", pduString);

    /* If a parser was located, invoke it on the data packet.
     */
    if (pduParser != 0)
    {
        dis_payload_tree = proto_item_add_subtree(dis_payload_node,
            ett_dis_payload);
        offset = parseFields(tvb, dis_payload_tree, offset, pduParser);
        proto_item_set_end(dis_payload_node, tvb, offset);
    }
    return tvb_length(tvb);
}

/* Register handoff routine for DIS dissector.  This will be invoked initially
 * and when the preferences are changed, to handle changing the UDP port for
 * which this dissector is registered.
 */
void proto_reg_handoff_dis(void)
{
    static gboolean dis_prefs_initialized = FALSE;

    if (!dis_prefs_initialized)
    {
        dis_dissector_handle = new_create_dissector_handle(dissect_dis, proto_dis);
    }
    else
    {
        dissector_delete("udp.port", dis_udp_port, dis_dissector_handle);
    }

    dissector_add("udp.port", dis_udp_port, dis_dissector_handle);
}

/* Registration routine for the DIS protocol.
 */
void proto_register_dis(void)
{
    /* Only these 3 ett variables will be present for every DIS PDU --
     * the rest are dynamic based on PDU type.
     */
    static gint *ett[] =
    {
        &ett_dis,
	&ett_dis_header,
        &ett_dis_payload
    };

    module_t *dis_module;

    proto_dis = proto_register_protocol(dis_proto_name, dis_proto_name_short,
        "dis");
    proto_register_subtree_array(ett, array_length(ett));

    dis_module = prefs_register_protocol(proto_dis, proto_reg_handoff_dis);

    /* Create an unsigned integer preference to allow the user to specify the
     * UDP port on which to capture DIS packets.
     */
    prefs_register_uint_preference(dis_module, "udp.port",
        "DIS UDP Port",
        "Set the UDP port for DIS messages",
        10, &dis_udp_port);

    /* Perform the one-time initialization of the DIS parsers.
     */
    initializeParsers();
}
