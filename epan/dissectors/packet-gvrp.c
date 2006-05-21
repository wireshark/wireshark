/* packet-gvrp.c
 * Routines for GVRP (GARP VLAN Registration Protocol) dissection
 * Copyright 2000, Kevin Shi <techishi@ms22.hinet.net>
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
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/llcsaps.h>

/* Initialize the protocol and registered fields */
static int proto_gvrp = -1;
static int hf_gvrp_proto_id = -1;
static int hf_gvrp_attribute_type = -1;
static int hf_gvrp_attribute_length = -1;
static int hf_gvrp_attribute_event = -1;
static int hf_gvrp_attribute_value = -1;
/*static int hf_gvrp_end_of_mark = -1;*/

/* Initialize the subtree pointers */
static gint ett_gvrp = -1;
/*static gint ett_gvrp_message = -1;
static gint ett_gvrp_attribute_list = -1;
static gint ett_gvrp_attribute = -1;*/

static dissector_handle_t data_handle;

/* Constant definitions */
#define GARP_DEFAULT_PROTOCOL_ID	0x0001
#define GARP_END_OF_MARK		0x00

#define GVRP_ATTRIBUTE_TYPE		0x01

static const value_string attribute_type_vals[] = {
	{ GVRP_ATTRIBUTE_TYPE, "VID" },
	{ 0,                   NULL }
};

/* The length of GVRP LeaveAll attribute should be 2 octets (one for length
 * and the other for event) */
#define GVRP_LENGTH_LEAVEALL		(sizeof(guint8)+sizeof(guint8))

/* The length of GVRP attribute other than LeaveAll should be 4 octets (one
 * for length, one for event, and the last two for VID value).
 */
#define GVRP_LENGTH_NON_LEAVEALL	(sizeof(guint8)+sizeof(guint8)+sizeof(guint16))

/* Packet offset definitions */
#define GARP_PROTOCOL_ID		0

/* Event definitions */
#define GVRP_EVENT_LEAVEALL		0
#define GVRP_EVENT_JOINEMPTY		1
#define GVRP_EVENT_JOININ		2
#define GVRP_EVENT_LEAVEEMPTY		3
#define GVRP_EVENT_LEAVEIN		4
#define GVRP_EVENT_EMPTY		5

static const value_string event_vals[] = {
	{ GVRP_EVENT_LEAVEALL,   "Leave All" },
	{ GVRP_EVENT_JOINEMPTY,  "Join Empty" },
	{ GVRP_EVENT_JOININ,     "Join In" },
	{ GVRP_EVENT_LEAVEEMPTY, "Leave Empty" },
	{ GVRP_EVENT_LEAVEIN,    "Leave In" },
	{ GVRP_EVENT_EMPTY,      "Empty" },
	{ 0,                     NULL }
};

/* Code to actually dissect the packets */
static void
dissect_gvrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item   *ti;
    proto_tree   *gvrp_tree;
    guint16       protocol_id;
    guint8        octet;
    int           msg_index, attr_index, offset = 0, length = tvb_reported_length(tvb);

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GVRP");

    if (check_col(pinfo->cinfo, COL_INFO))
	col_set_str(pinfo->cinfo, COL_INFO, "GVRP");

    if (tree)
    {
	ti = proto_tree_add_item(tree, proto_gvrp, tvb, 0, length, FALSE);

	gvrp_tree = proto_item_add_subtree(ti, ett_gvrp);

	/* Read in GARP protocol ID */
	protocol_id = tvb_get_ntohs(tvb, GARP_PROTOCOL_ID);

	proto_tree_add_uint_format(gvrp_tree, hf_gvrp_proto_id, tvb,
				   GARP_PROTOCOL_ID, sizeof(guint16),
				   protocol_id,
				   "Protocol Identifier: 0x%04x (%s)",
				   protocol_id,
				   protocol_id == GARP_DEFAULT_PROTOCOL_ID ?
				     "GARP VLAN Registration Protocol" :
				     "Unknown Protocol");

	/* Currently only one protocol ID is supported */
	if (protocol_id != GARP_DEFAULT_PROTOCOL_ID)
	{
	    proto_tree_add_text(gvrp_tree, tvb, GARP_PROTOCOL_ID, sizeof(guint16),
 "   (Warning: this version of Wireshark only knows about protocol id = 1)");
	    call_dissector(data_handle,
	        tvb_new_subset(tvb, GARP_PROTOCOL_ID + sizeof(guint16), -1, -1),
	        pinfo, tree);
	    return;
	}

	offset += sizeof(guint16);
	length -= sizeof(guint16);

	msg_index = 0;

	/* Begin to parse GARP messages */
	while (length)
	{
	    proto_item   *msg_item;
	    int           msg_start = offset;

	    /* Read in attribute type. */
	    octet = tvb_get_guint8(tvb, offset);

	    /* Check for end of mark */
	    if (octet == GARP_END_OF_MARK)
	    {
		/* End of GARP PDU */
		if (msg_index)
		{
		    proto_tree_add_text(gvrp_tree, tvb, offset, sizeof(guint8),
					"End of mark");
		    break;
		}
		else
		{
		    call_dissector(data_handle,
		        tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
		    return;
		}
	    }

	    offset += sizeof(guint8);
	    length -= sizeof(guint8);

	    msg_item = proto_tree_add_text(gvrp_tree, tvb, msg_start, -1,
					   "Message %d", msg_index + 1);

	    proto_tree_add_uint(gvrp_tree, hf_gvrp_attribute_type, tvb,
				msg_start, sizeof(guint8), octet);

	    /* GVRP only supports one attribute type. */
	    if (octet != GVRP_ATTRIBUTE_TYPE)
	    {
		call_dissector(data_handle, tvb_new_subset(tvb, offset,-1, -1),
		    pinfo, tree);
		return;
	    }

	    attr_index = 0;

	    while (length)
	    {
		int          attr_start = offset;
		proto_item   *attr_item;

		/* Read in attribute length. */
		octet = tvb_get_guint8(tvb, offset);

		/* Check for end of mark */
		if (octet == GARP_END_OF_MARK)
		{
		    /* If at least one message has been already read,
		     * check for another end of mark.
		     */
		    if (attr_index)
		    {
			proto_tree_add_text(gvrp_tree, tvb, offset,
					    sizeof(guint8), "  End of mark");

			offset += sizeof(guint8);
			length -= sizeof(guint8);

			proto_item_set_len(msg_item, offset - msg_start);
			break;
		    }
		    else
		    {
			call_dissector(data_handle,
			    tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
			return;
		    }
		}
		else
		{
		    guint8   event;

		    offset += sizeof(guint8);
		    length -= sizeof(guint8);

		    attr_item = proto_tree_add_text(gvrp_tree, tvb,
			 attr_start, -1, "  Attribute %d", attr_index + 1);

		    proto_tree_add_uint(gvrp_tree, hf_gvrp_attribute_length,
			 tvb, attr_start, sizeof(guint8), octet);

		    /* Read in attribute event */
		    event = tvb_get_guint8(tvb, offset);

		    proto_tree_add_uint(gvrp_tree, hf_gvrp_attribute_event,
			 tvb, offset, sizeof(guint8), event);

		    offset += sizeof(guint8);
		    length -= sizeof(guint8);

		    switch (event) {

		    case GVRP_EVENT_LEAVEALL:
			if (octet != GVRP_LENGTH_LEAVEALL)
			{
			    call_dissector(data_handle,
			        tvb_new_subset(tvb, offset, -1, -1), pinfo,
			        tree);
			    return;
			}
			break;

		     case GVRP_EVENT_JOINEMPTY:
		     case GVRP_EVENT_JOININ:
		     case GVRP_EVENT_LEAVEEMPTY:
		     case GVRP_EVENT_LEAVEIN:
		     case GVRP_EVENT_EMPTY:
			if (octet != GVRP_LENGTH_NON_LEAVEALL)
			{
			    call_dissector(data_handle,
			        tvb_new_subset(tvb, offset, -1, -1),pinfo,
			        tree);
			    return;
			}

			/* Show attribute value */
			proto_tree_add_item(gvrp_tree, hf_gvrp_attribute_value,
			    tvb, offset, sizeof(guint16), FALSE);

			offset += sizeof(guint16);
			length -= sizeof(guint16);
			break;

		     default:
			call_dissector(data_handle,
			    tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
			return;
		    }
		}

		proto_item_set_len(attr_item, offset - attr_start);

		attr_index++;
	    }

	    msg_index++;
	}
    }
}


/* Register the protocol with Wireshark */
void
proto_register_gvrp(void)
{
    static hf_register_info hf[] = {
	{ &hf_gvrp_proto_id,
	    { "Protocol ID", "garp.protocol_id",
	    FT_UINT16,      BASE_HEX,      NULL,  0x0,
	    "", HFILL }
	},
	{ &hf_gvrp_attribute_type,
	    { "Type",        "garp.attribute_type",
	    FT_UINT8,        BASE_HEX,      VALS(attribute_type_vals),  0x0,
	    "", HFILL }
	},
	{ &hf_gvrp_attribute_length,
	    { "Length",      "garp.attribute_length",
	    FT_UINT8,        BASE_DEC,      NULL,  0x0,
	    "", HFILL }
	},
	{ &hf_gvrp_attribute_event,
	    { "Event",       "garp.attribute_event",
	    FT_UINT8,        BASE_DEC,      VALS(event_vals),  0x0,
	    "", HFILL }
	},
	{ &hf_gvrp_attribute_value,
	    { "Value",       "garp.attribute_value",
	    FT_UINT16,       BASE_DEC,      NULL,  0x0,
	    "", HFILL }
	}
    };

    static gint *ett[] = {
	&ett_gvrp
    };

    /* Register the protocol name and description for GVRP */
    proto_gvrp = proto_register_protocol("GARP VLAN Registration Protocol",
					 "GVRP", "gvrp");

    /* Required function calls to register the header fields and subtrees
     * used by GVRP */
    proto_register_field_array(proto_gvrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("gvrp", dissect_gvrp, proto_gvrp);
}

void
proto_reg_handoff_gvrp(void){
  data_handle = find_dissector("data");
}
