/* packet-pn-mrp.c
 * Routines for PN-MRP (PROFINET Media Redundancy Protocol)
 * packet dissection.
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/oui.h>
#include <epan/etypes.h>

#include "packet-pn.h"


static int proto_pn_mrp = -1;

static int hf_pn_mrp_type = -1;
static int hf_pn_mrp_length = -1;
static int hf_pn_mrp_version = -1;
static int hf_pn_mrp_sequence_id = -1;
static int hf_pn_mrp_sa = -1;
static int hf_pn_mrp_prio = -1;
static int hf_pn_mrp_port_role = -1;
static int hf_pn_mrp_ring_state = -1;
static int hf_pn_mrp_interval = -1;
static int hf_pn_mrp_transition = -1;
static int hf_pn_mrp_time_stamp = -1;
static int hf_pn_mrp_blocked = -1;
static int hf_pn_manufacturer_data = -1;
static int hf_pn_mrp_domain_uuid = -1;
static int hf_pn_mrp_oui = -1;


static gint ett_pn_mrp = -1;



static const value_string pn_mrp_block_type_vals[] = {
    { 0x00, "End" },
    { 0x01, "Common" },
    { 0x02, "Test" },
    { 0x03, "TopologyChange" },
    { 0x04, "LinkDown" },
    { 0x05, "LinkUp" },
    /*0x06 - 0x7E Reserved */
    { 0x7F, "Organizationally Specific"},
    { 0, NULL },
};

static const value_string pn_mrp_oui_vals[] = {
    { OUI_PROFINET,         "PROFINET" },
    { OUI_SIEMENS,          "SIEMENS" },

    { 0, NULL }
};



static const value_string pn_mrp_port_role_vals[] = {
    { 0x0000, "Primary ring port" },
    { 0x0001, "Secondary ring port"},
    /*0x0002 - 0xFFFF Reserved */

    { 0, NULL }
};
static const value_string pn_mrp_role_vals[] = {
    { 0x0000, "Media redundancy disabled" },
    { 0x0001, "Media redundancy client" },
    { 0x0002, "Media redundancy manager" },
    { 0x0003, "Media redundancy manager (auto)" },
    /*0x0004 - 0xFFFF Reserved */

    { 0, NULL }
};

static const value_string pn_mrp_ring_state_vals[] = {
    { 0x0000, "Ring open" },
    { 0x0001, "Ring closed"},
    /*0x0002 - 0xFFFF Reserved */

    { 0, NULL }
};


static const value_string pn_mrp_prio_vals[] = {
    { 0x8000, "Default priority for redundancy manager" },

    { 0, NULL }
};
/* routine disecting an uint16 and returning that item as well */
/* dissect a 16 bit unsigned integer */
int
dissect_pn_uint16_ret_item(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, guint16 *pdata, proto_item ** new_item)
{
    guint16     data;
    proto_item *item = NULL;

    data = tvb_get_ntohs (tvb, offset);

    if (tree) {
        item = proto_tree_add_uint(tree, hfindex, tvb, offset, 2, data);
    }
    if (pdata)
        *pdata = data;
    if (new_item)
        *new_item = item;
    return offset + 2;
}



static int
dissect_PNMRP_Common(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16  sequence_id;
    e_uuid_t uuid;


    /* MRP_SequenceID */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_sequence_id, &sequence_id);

    /* MRP_DomainUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_mrp_domain_uuid, &uuid);

    col_append_str(pinfo->cinfo, COL_INFO, "Common");

    proto_item_append_text(item, "Common");

    return offset;
}

#if 0
static int
dissect_PNMRP_LinkUp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint8  mac[6];
    guint16 port_role;
    guint16 interval;
    guint16 blocked;

    /* MRP_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrp_sa, mac);

    /* MRP_PortRole */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_port_role, &port_role);

    /* MRP_Interval */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_interval, &interval);

    /* MRP_Blocked */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_blocked, &blocked);

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    col_append_str(pinfo->cinfo, COL_INFO, "LinkUp");

    proto_item_append_text(item, "LinkUp");

    return offset;
}
#endif

static int
dissect_PNMRP_LinkDown(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint8      mac[6];
    guint16     port_role;
    guint16     interval;
    guint16     blocked;
    proto_item *sub_item;

    /* MRP_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrp_sa, mac);

    /* MRP_PortRole */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_port_role, &port_role);

    /* MRP_Interval */
    offset = dissect_pn_uint16_ret_item(tvb, offset, pinfo, tree, hf_pn_mrp_interval, &interval, &sub_item);
    if (tree)
    {
        proto_item_append_text(sub_item,"Interval for next topology change event (in ms)");
        if (interval <0x07D1)
            proto_item_append_text(sub_item,"Mandatory");
        else
            proto_item_append_text(sub_item,"Optional");
    /* MRP_Blocked */
        offset = dissect_pn_uint16_ret_item(tvb, offset, pinfo, tree, hf_pn_mrp_blocked, &blocked, &sub_item);
        if (blocked == 0)
            proto_item_append_text(sub_item,"The MRC is not able to receive and forward frames to port in state blocked");
        else
            if (blocked == 1)
                proto_item_append_text(sub_item,"The MRC is able to receive and forward frames to port in state blocked");
            else
                proto_item_append_text(sub_item,"Reserved");
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    col_append_str(pinfo->cinfo, COL_INFO, "LinkDown");

    proto_item_append_text(item, "LinkDown");

    return offset;
}

static char * mrp_Prio2msg(guint16 prio)
{

if (prio == 0x0000)
    return(" Highest priority redundancy manager");
if ((prio >= 0x1000) && (prio <= 0x7000))
    return(" High priorities");
if (prio == 0x8000)
    return(" Default priority for redundancy manager");
if ((prio >= 0x8001) && (prio <= 0x8FFF))
    return(" Low priorities for redundancy manager");
if ((prio >= 0x9000) && (prio <= 0x9FFF))
    return(" High priorities for redundancy manager (auto)");
if (prio == 0xA000)
    return(" Default priority for redundancy manager (auto)");
if ((prio >= 0xA001) && (prio <= 0xF000))
    return(" Low priorities for redundancy manager (auto)");
if (prio ==0xFFFF)
    return(" Lowest priority for redundancy manager (auto)");

    return(" Reserved");
}

static int
dissect_PNMRP_Test(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16     prio;
    guint8      mac[6];
    guint16     port_role;
    guint16     ring_state;
    guint16     transition;
    guint32     time_stamp;
    proto_item *sub_item;


    /* MRP_Prio */
    offset = dissect_pn_uint16_ret_item(tvb, offset, pinfo, tree, hf_pn_mrp_prio, &prio, &sub_item);
    if (tree)
        proto_item_append_text(sub_item, "%s", mrp_Prio2msg(prio));

    /* MRP_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrp_sa, mac);

    /* MRP_PortRole */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_port_role, &port_role);

    /* MRP_RingState */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_ring_state, &ring_state);

    /* MRP_Transition */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_transition, &transition);

    /* MRP_TimeStamp */
    offset = dissect_pn_uint32(tvb, offset, pinfo, tree, hf_pn_mrp_time_stamp, &time_stamp);

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    col_append_str(pinfo->cinfo, COL_INFO, "Test");
    if (tree)
    proto_item_append_text(item, "Test");

    return offset;
}


static int
dissect_PNMRP_TopologyChange(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16     prio;
    guint8      mac[6];
    guint16     interval;
    proto_item *sub_item;


    /* MRP_Prio */
    offset = dissect_pn_uint16_ret_item(tvb, offset, pinfo, tree, hf_pn_mrp_prio, &prio, &sub_item);
    if (tree)
        proto_item_append_text(sub_item, "%s", mrp_Prio2msg(prio));

    /* MRP_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrp_sa, mac);

    /* MRP_Interval */
    offset = dissect_pn_uint16_ret_item(tvb, offset, pinfo, tree, hf_pn_mrp_interval, &interval, &sub_item);
    if (tree)
    {
        proto_item_append_text(sub_item," Interval for next topology change event (in ms) ");
        if (interval <0x07D1)
            proto_item_append_text(sub_item,"Mandatory");
        else
            proto_item_append_text(sub_item,"Optional");
    }
    /* Padding */
    /*offset = dissect_pn_align4(tvb, offset, pinfo, tree);*/

    col_append_str(pinfo->cinfo, COL_INFO, "TopologyChange");
    if (tree)
    proto_item_append_text(item, "TopologyChange");

    return offset;
}

/* "dissect" Manufacture DATA */
static int
dissect_pn_ManuData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, guint32 length)
{


    proto_tree_add_string_format(tree, hf_pn_manufacturer_data, tvb, offset, length, "data",
        "MRP_ManufacturerData: %d bytes", length);

    return offset + length;
}


static int
dissect_PNMRP_Option(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 length)
{
    guint32 oui;


    /* OUI (organizational unique id) */
    offset = dissect_pn_oid(tvb, offset, pinfo,tree, hf_pn_mrp_oui, &oui);
    length -= 3;

    switch (oui)
    {
    case OUI_SIEMENS:
        proto_item_append_text(item, "Option(SIEMENS)");
        /* No Padding !
        if (offset % 4) {
            length -= 4 - (offset % 4);
            offset = dissect_pn_align4(tvb, offset, pinfo, tree);
        }  */
        if (length != 0) {
            offset = dissect_pn_ManuData(tvb, offset, pinfo, tree, length);
        }
        col_append_str(pinfo->cinfo, COL_INFO, "Option(Siemens)");
        break;
    default:
        proto_item_append_text(item, "Option(Unknown-OUI)");
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, length);

        col_append_str(pinfo->cinfo, COL_INFO, "Option");
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    return offset;
}


static int
dissect_PNMRP_PDU(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16   version;
    guint8    type;
    guint8    length;
    gint      i;
    tvbuff_t *new_tvb;


    /* MRP_Version */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_version, &version);

    /* the rest of the packet has 4byte alignment regarding to the beginning of the next TLV block! */
    /* XXX - do we have to free this new tvb below? */
    new_tvb = tvb_new_subset_remaining(tvb, offset);
    offset = 0;

    for(i=0; tvb_length_remaining(tvb, offset) > 0; i++) {
        /* MRP_TLVHeader.Type */
        offset = dissect_pn_uint8(new_tvb, offset, pinfo, tree, hf_pn_mrp_type, &type);

        /* MRP_TLVHeader.Length */
        offset = dissect_pn_uint8(new_tvb, offset, pinfo, tree, hf_pn_mrp_length, &length);

        if (i != 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");

            proto_item_append_text(item, ", ");
        }

        switch(type) {
        case 0x00:
            /* no content */
            col_append_str(pinfo->cinfo, COL_INFO, "End");
            proto_item_append_text(item, "End");
            return offset;
            break;
        case 0x01:
            offset = dissect_PNMRP_Common(new_tvb, offset, pinfo, tree, item);
            break;
        case 0x02:
            offset = dissect_PNMRP_Test(new_tvb, offset, pinfo, tree, item);
            break;
        case 0x03:
            offset = dissect_PNMRP_TopologyChange(new_tvb, offset, pinfo, tree, item);
            break;
        case 0x04:
        case 0x05: /* dissection of up and down is identical! */
            offset = dissect_PNMRP_LinkDown(new_tvb, offset, pinfo, tree, item);
            break;
        case 0x7f:
            offset = dissect_PNMRP_Option(new_tvb, offset, pinfo, tree, item, length);
            break;
        default:
            offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, length);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown TLVType 0x%x", type);
        proto_item_append_text(item, "Unknown TLVType 0x%x", type);
        }
    }

    return offset;
}


/* Dissect MRP packets */
static void
dissect_PNMRP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti       = NULL;
    proto_tree *mrp_tree = NULL;

    guint32 offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-MRP");

    /* Clear the information column on summary display */
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_pn_mrp, tvb, offset, -1, ENC_NA);
        mrp_tree = proto_item_add_subtree(ti, ett_pn_mrp);
    }

    dissect_PNMRP_PDU(tvb, offset, pinfo, mrp_tree, ti);
}


void
proto_register_pn_mrp (void)
{
    static hf_register_info hf[] = {
    { &hf_pn_mrp_type,
      { "MRP_TLVHeader.Type", "pn_mrp.type",
        FT_UINT8, BASE_HEX, VALS(pn_mrp_block_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_length,
      { "MRP_TLVHeader.Length", "pn_mrp.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_version,
      { "MRP_Version", "pn_mrp.version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_sequence_id,
      { "MRP_SequenceID", "pn_mrp.sequence_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Unique sequence number to each outstanding service request", HFILL }},

    { &hf_pn_mrp_sa,
      { "MRP_SA", "pn_mrp.sa",
        FT_ETHER, BASE_NONE, 0x0, 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_prio,
      { "MRP_Prio", "pn_mrp.prio",
        FT_UINT16, BASE_HEX, 0, 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_port_role,
      { "MRP_PortRole", "pn_mrp.port_role",
        FT_UINT16, BASE_HEX, VALS(pn_mrp_port_role_vals), 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_ring_state,
      { "MRP_RingState", "pn_mrp.ring_state",
        FT_UINT16, BASE_HEX, VALS(pn_mrp_ring_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_interval,
      { "MRP_Interval", "pn_mrp.interval",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Interval for next topology change event (in ms)", HFILL }},

    { &hf_pn_mrp_transition,
      { "MRP_Transition", "pn_mrp.transition",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Number of transitions between media redundancy lost and ok states", HFILL }},

    { &hf_pn_mrp_time_stamp,
      { "MRP_TimeStamp [ms]", "pn_mrp.time_stamp",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Actual counter value of 1ms counter", HFILL }},

    { &hf_pn_mrp_blocked,
      { "MRP_Blocked", "pn_mrp.blocked",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pn_manufacturer_data,
      { "MRP_ManufacturerData", "pn_mrp.ManufacturerData",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_domain_uuid,
      { "MRP_DomainUUID", "pn_mrp.domain_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_pn_mrp_oui,
      { "MRP_ManufacturerOUIr", "pn_mrp.oui",
        FT_UINT24, BASE_HEX, VALS(pn_mrp_oui_vals), 0x0,
        NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_pn_mrp
    };

    proto_pn_mrp = proto_register_protocol ("PROFINET MRP", "PN-MRP", "pn_mrp");
    proto_register_field_array (proto_pn_mrp, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
}


void
proto_reg_handoff_pn_mrp (void)
{
    dissector_handle_t mrp_handle;


    mrp_handle = create_dissector_handle(dissect_PNMRP,proto_pn_mrp);
    dissector_add_uint("ethertype", ETHERTYPE_MRP, mrp_handle);

}
