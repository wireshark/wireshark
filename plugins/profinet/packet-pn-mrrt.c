/* packet-pn-mrrt.c
 * Routines for PN-MRRT (PROFINET Media Redundancy for cyclic realtime data) 
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

#include "packet-pn.h"

static int proto_pn_mrrt = -1;

static int hf_pn_mrrt_sequence_id = -1;
static int hf_pn_mrrt_domain_uuid = -1;
static int hf_pn_mrrt_type = -1;
static int hf_pn_mrrt_length = -1;
static int hf_pn_mrrt_version = -1;
static int hf_pn_mrrt_sa = -1;


static gint ett_pn_mrrt = -1;



static const value_string pn_mrrt_block_type_vals[] = {
	{ 0x00, "End" },
	{ 0x01, "Common" },
	{ 0x02, "Test" },
    /*0x03 - 0x7E Reserved */
	{ 0x7F, "Organizationally Specific"},
	{ 0, NULL },
};




static int
dissect_PNMRRT_Common(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 length _U_)
{
    guint16 sequence_id;
    e_uuid_t uuid;


    /* MRRT_SequenceID */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrrt_sequence_id, &sequence_id);

    /* MRRT_DomainUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_mrrt_domain_uuid, &uuid);

    col_append_str(pinfo->cinfo, COL_INFO, "Common");

    proto_item_append_text(item, "Common");

    return offset;
}


static int
dissect_PNMRRT_Test(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 length _U_)
{
    guint8 mac[6];


    /* MRRT_SA */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_mrrt_sa, mac);

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    col_append_str(pinfo->cinfo, COL_INFO, "Test");

    proto_item_append_text(item, "Test");

    return offset;
}

static int
dissect_PNMRRT_PDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 version;
    guint8 type;
    guint8 length;
    gint    i =0;


    /* MRRT_Version */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_mrrt_version, &version);

    while(tvb_length_remaining(tvb, offset) > 0) {
        /* MRRT_TLVHeader.Type */
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_mrrt_type, &type);

        /* MRRT_TLVHeader.Length */
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_mrrt_length, &length);


        if(i != 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");

            proto_item_append_text(item, ", ");
        }

        i++;

        switch(type) {
        case(0x00):
            /* no content */
            col_append_str(pinfo->cinfo, COL_INFO, "End");
            proto_item_append_text(item, "End");
            return offset;
            break;
        case(0x01):
            offset = dissect_PNMRRT_Common(tvb, offset, pinfo, tree, item, length);
            break;
        case(0x02):
            offset = dissect_PNMRRT_Test(tvb, offset, pinfo, tree, item, length);
            break;
        default:
            offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, length);

	    col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown TLVType 0x%x", type);
	    proto_item_append_text(item, "Unknown TLVType 0x%x", type);
        }
    }

    return offset;
}


/* possibly dissect a PN-RT packet (frame ID must be in the appropriate range) */
static gboolean
dissect_PNMRRT_Data_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    guint16 u16FrameID;
    proto_item *item = NULL;
    proto_tree *mrrt_tree = NULL;
    int offset = 0;
	guint32 u32SubStart;


    /* the tvb will NOT contain the frame_id here, so get it from our private data! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

	/* frame id must be in valid range (MRRT) */
	if (u16FrameID != 0xFF60) {
        /* we are not interested in this packet */
        return FALSE;
    }
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-MRRT");
    col_clear(pinfo->cinfo, COL_INFO);

    /* subtree for MRRT */
	item = proto_tree_add_protocol_format(tree, proto_pn_mrrt, tvb, 0, 0, "PROFINET MRRT, ");
	mrrt_tree = proto_item_add_subtree(item, ett_pn_mrrt);
    u32SubStart = offset;

    offset = dissect_PNMRRT_PDU(tvb, offset, pinfo, mrrt_tree, item);

	proto_item_set_len(item, offset - u32SubStart);

    return TRUE;
}


void
proto_register_pn_mrrt (void)
{
	static hf_register_info hf[] = {

	{ &hf_pn_mrrt_type,
		{ "Type", "pn_mrrt.type", FT_UINT8, BASE_HEX, VALS(pn_mrrt_block_type_vals), 0x0, NULL, HFILL }},
	{ &hf_pn_mrrt_length,
		{ "Length", "pn_mrrt.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_pn_mrrt_version,
		{ "Version", "pn_mrrt.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_pn_mrrt_sequence_id,
		{ "SequenceID", "pn_mrrt.sequence_id", FT_UINT16, BASE_HEX, NULL, 0x0, "Unique sequence number to each outstanding service request", HFILL }},
	{ &hf_pn_mrrt_sa,
        { "SA", "pn_mrrt.sa", FT_ETHER, BASE_NONE, 0x0, 0x0, NULL, HFILL }},
	{ &hf_pn_mrrt_domain_uuid,
		{ "DomainUUID", "pn_mrrt.domain_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };


	static gint *ett[] = {
		&ett_pn_mrrt
    };

	proto_pn_mrrt = proto_register_protocol ("PROFINET MRRT", "PN-MRRT", "pn_mrrt");
	proto_register_field_array (proto_pn_mrrt, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}


void
proto_reg_handoff_pn_mrrt (void)
{

    /* register ourself as an heuristic pn-rt payload dissector */
	heur_dissector_add("pn_rt", dissect_PNMRRT_Data_heur, proto_pn_mrrt);
}
