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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/oui.h>
#include <epan/etypes.h>
#include <epan/expert.h>

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
static int hf_pn_mrp_manufacturer_oui = -1;
static int hf_pn_mrp_domain_uuid = -1;
static int hf_pn_mrp_oui = -1;

static int hf_pn_mrp_data = -1;


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



/* XXX - use include file instead for these helpers */
extern int dissect_pn_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                  proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint16 *pdata);

extern int dissect_pn_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_int16(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, gint16 *pdata);

extern int dissect_pn_oid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_mac(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_uuid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, e_uuid_t *uuid);



static int
dissect_PNMRP_Common(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 sequence_id;
    e_uuid_t uuid;


    /* MRP_SequenceID */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_sequence_id, &sequence_id);

    /* MRP_DomainUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_mrp_domain_uuid, &uuid);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "Common");

    proto_item_append_text(item, "Common");

    return offset;
}


static int
dissect_PNMRP_LinkUp(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 port_role;
    guint16 interval;
    guint16 blocked;


    /* MRP_PortRole */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_port_role, &port_role);

    /* MRP_Interval */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_interval, &interval);

    /* MRP_Blocked */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_blocked, &blocked);

    /* Padding */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "LinkUp");

    proto_item_append_text(item, "LinkUp");

    return offset;
}


static int
dissect_PNMRP_LinkDown(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 port_role;
    guint16 interval;
    guint16 blocked;


    /* MRP_PortRole */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_port_role, &port_role);

    /* MRP_Interval */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_interval, &interval);

    /* MRP_Blocked */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_blocked, &blocked);

    /* Padding */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "LinkDown");

    proto_item_append_text(item, "LinkDown");

    return offset;
}


static int
dissect_PNMRP_Test(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 prio;
    guint8 mac[6];
    guint16 port_role;
    guint16 ring_state;
    guint16 transition;
    guint16 time_stamp;


    /* MRP_Prio */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_prio, &prio);

    /* MRP_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrp_sa, mac);

    /* MRP_PortRole */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_port_role, &port_role);

    /* MRP_RingState */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_ring_state, &ring_state);

    /* MRP_Transition */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_transition, &transition);

    /* MRP_TimeStamp */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_time_stamp, &time_stamp);

    /* Padding */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "Test");

    proto_item_append_text(item, "Test");

    return offset;
}


static int
dissect_PNMRP_TopologyChange(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 prio;
    guint8 mac[6];
    guint16 interval;


    /* MRP_Prio */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_prio, &prio);

    /* MRP_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrp_sa, mac);

    /* MRP_Interval */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_interval, &interval);

    /* Padding */
    /*if (offset % 4) {
        offset += 4 - (offset % 4);
    }*/

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "TopologyChange");

    proto_item_append_text(item, "TopologyChange");

    return offset;
}


static int
dissect_PNMRP_Option(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 length)
{
    proto_item *unknown_item;
	guint32 oui;


	/* OUI (organizational unique id) */
    offset = dissect_pn_oid(tvb, offset, pinfo,tree, hf_pn_mrp_oui, &oui);
    length -= 3;
	
	switch (oui)
	{
	case OUI_SIEMENS:
        proto_item_append_text(item, "Option(SIEMENS)");
        unknown_item = proto_tree_add_string_format(tree, hf_pn_mrp_data, tvb, offset, length, "data", 
		    "Undecoded %u bytes of Siemens Option field", length);
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
		    "Undecoded %u bytes of Siemens Option field", length);
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_fstr(pinfo->cinfo, COL_INFO, "Option(Siemens)");
		break;
	default:
        proto_item_append_text(item, "Option(Unknown-OUI)");
        unknown_item = proto_tree_add_string_format(tree, hf_pn_mrp_data, tvb, offset, length, "data", 
            "Unknown OUI Data: %d bytes", length);
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
			"Unknown OUI Data %u bytes", length);
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_fstr(pinfo->cinfo, COL_INFO, "Option");
	}

    offset += length;

    /* Padding */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }

    return offset;
}


static int
dissect_PNMRP_PDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 version;
    guint8 type;
    guint8 length;
    gint i = 0;
    proto_item *unknown_item;
    tvbuff_t *tvb_new;


    /* MRP_Version */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrp_version, &version);

    /* the rest of the packet has 4byte alignment regarding to the beginning of the next TLV block! */
    /* XXX - do we have to free this new tvb below? */
    tvb_new = tvb_new_subset(tvb, offset, -1, -1);
    offset = 0;

    while(tvb_length_remaining(tvb, offset) > 0) {
        /* MRP_TLVHeader.Type */
        offset = dissect_pn_uint8(tvb_new, offset, pinfo, tree, hf_pn_mrp_type, &type);

        /* MRP_TLVHeader.Length */
        offset = dissect_pn_uint8(tvb_new, offset, pinfo, tree, hf_pn_mrp_length, &length);

        if(i != 0) {
            if (check_col(pinfo->cinfo, COL_INFO))
              col_append_fstr(pinfo->cinfo, COL_INFO, ", ");

            proto_item_append_text(item, ", ");
        }

        i++;

        switch(type) {
        case(0x00):
            /* no content */
            if (check_col(pinfo->cinfo, COL_INFO))
              col_append_fstr(pinfo->cinfo, COL_INFO, "End");
            proto_item_append_text(item, "End");
            return offset;
            break;
        case(0x01):
            offset = dissect_PNMRP_Common(tvb_new, offset, pinfo, tree, item);
            break;
        case(0x02):
            offset = dissect_PNMRP_Test(tvb_new, offset, pinfo, tree, item);
            break;
        case(0x03):
            offset = dissect_PNMRP_TopologyChange(tvb_new, offset, pinfo, tree, item);
            break;
        case(0x04):
            offset = dissect_PNMRP_LinkDown(tvb_new, offset, pinfo, tree, item);
            break;
        case(0x05):
            offset = dissect_PNMRP_LinkUp(tvb_new, offset, pinfo, tree, item);
            break;
        case(0x7f):
            offset = dissect_PNMRP_Option(tvb_new, offset, pinfo, tree, item, length);
            break;
        default:
            unknown_item = proto_tree_add_string_format(tree, hf_pn_mrp_data, tvb_new, offset, length, "data", 
                "PN-MRP Unknown TLVType 0x%x, Data: %d bytes", type, length);
            expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
			    "Unknown TLVType 0x%x, %u bytes",
			    type, length);
	        if (check_col(pinfo->cinfo, COL_INFO))
		        col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown TLVType 0x%x", type);

	        proto_item_append_text(item, "Unknown TLVType 0x%x", type);

            offset += length;
        }
    }

    /* will never be reached */
    return offset;
}


/* Dissect MRP packets */
static void
dissect_PNMRP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *mrp_tree = NULL;
	
    guint32 offset = 0;

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-MRP");
		
    /* Clear the information column on summary display */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    if (tree) 
    {
        ti = proto_tree_add_item(tree, proto_pn_mrp, tvb, offset, -1, FALSE);
        mrp_tree = proto_item_add_subtree(ti, ett_pn_mrp);
    }

    dissect_PNMRP_PDU(tvb, offset, pinfo, mrp_tree, ti);
}	


void
proto_register_pn_mrp (void)
{
	static hf_register_info hf[] = {
    { &hf_pn_mrp_data,
        { "Undecoded Data", "pn_mrp.data", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_pn_mrp_type,
		{ "Type", "pn_mrp.type", FT_UINT8, BASE_HEX, VALS(pn_mrp_block_type_vals), 0x0, "", HFILL }},
	{ &hf_pn_mrp_length,
		{ "Length", "pn_mrp.length", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_mrp_version,
		{ "Version", "pn_mrp.version", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_mrp_sequence_id,
		{ "SequenceID", "pn_mrp.sequence_id", FT_UINT16, BASE_HEX, NULL, 0x0, "Unique sequence number to each outstanding service request", HFILL }},
	{ &hf_pn_mrp_sa,
        { "SA", "pn_mrp.sa", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_mrp_prio,
		{ "Prio", "pn_mrp.prio", FT_UINT16, BASE_HEX, VALS(pn_mrp_prio_vals), 0x0, "", HFILL }},
	{ &hf_pn_mrp_port_role,
		{ "PortRole", "pn_mrp.port_role", FT_UINT16, BASE_HEX, VALS(pn_mrp_port_role_vals), 0x0, "", HFILL }},
	{ &hf_pn_mrp_ring_state,
		{ "RingState", "pn_mrp.ring_state", FT_UINT16, BASE_HEX, VALS(pn_mrp_ring_state_vals), 0x0, "", HFILL }},
	{ &hf_pn_mrp_interval,
		{ "Interval", "pn_mrp.interval", FT_UINT16, BASE_DEC, NULL, 0x0, "Interval for next topologie change event (in ms)", HFILL }},
	{ &hf_pn_mrp_transition,
		{ "Transition", "pn_mrp.transition", FT_UINT16, BASE_HEX, NULL, 0x0, "Number of transitions between media redundancy lost and ok states", HFILL }},
	{ &hf_pn_mrp_time_stamp,
		{ "TimeStamp", "pn_mrp.time_stamp", FT_UINT16, BASE_HEX, NULL, 0x0, "Actual counter value of 1ms counter", HFILL }},
	{ &hf_pn_mrp_blocked,
		{ "Blocked", "pn_mrp.blocked", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_mrp_manufacturer_oui,
		{ "ManufacturerOUI", "pn_mrp.manufacturer_oui", FT_UINT24, BASE_HEX, VALS(pn_mrp_oui_vals), 0x0, "", HFILL }},
	{ &hf_pn_mrp_domain_uuid,
		{ "DomainUUID", "pn_mrp.domain_uuid", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_mrp_oui,
		{ "Organizationally Unique Identifier",	"pn_mrp.oui", FT_UINT24, BASE_HEX,
	   	VALS(pn_mrp_oui_vals), 0x0, "", HFILL }},
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
	dissector_add("ethertype", ETHERTYPE_MRP, mrp_handle);

}
