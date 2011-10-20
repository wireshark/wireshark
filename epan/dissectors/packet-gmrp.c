/* packet-gmrp.c
 * Routines for GMRP (GARP Multicast Registration Protocol) dissection
 * Copyright 2001, Markus Seehofer <mseehofe@nt.hirschmann.de>
 *
 * Based on the code from packet-gvrp.c (GVRP) from
 * Kevin Shi <techishi@ms22.hinet.net> Copyright 2000
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

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/llcsaps.h>

/* Initialize the protocol and registered fields */
static int proto_gmrp = -1;
static int hf_gmrp_proto_id = -1;
static int hf_gmrp_attribute_type = -1;
static int hf_gmrp_attribute_length = -1;
static int hf_gmrp_attribute_event = -1;
static int hf_gmrp_attribute_value_group_membership = -1;
static int hf_gmrp_attribute_value_service_requirement = -1;
/*static int hf_gmrp_end_of_mark = -1;*/

/* Initialize the subtree pointers */
static gint ett_gmrp = -1;
/*static gint ett_gmrp_message = -1;
static gint ett_gmrp_attribute_list = -1;
static gint ett_gmrp_attribute = -1;*/

static dissector_handle_t data_handle;

/* Constant definitions */
#define GARP_DEFAULT_PROTOCOL_ID	0x0001
#define GARP_END_OF_MARK			0x00

#define GMRP_ATTRIBUTE_TYPE_GROUP_MEMBERSHIP	0x01
#define GMRP_ATTRIBUTE_TYPE_SERVICE_REQUIREMENT	0x02

#define GMRP_SERVICE_REQUIREMENT_FORWARD_ALL				0x00
#define GMRP_SERVICE_REQUIREMENT_FORWARD_ALL_UNREGISTERED 	0x01

static const value_string attribute_type_vals[] = {
	{ GMRP_ATTRIBUTE_TYPE_GROUP_MEMBERSHIP    ,"Group Membership" },
	{ GMRP_ATTRIBUTE_TYPE_SERVICE_REQUIREMENT ,"Service Requirement" },
	{ 0,                   NULL }
};

/* The length of GMRP LeaveAll attribute should be 2 octets (one for length
 * and the other for event) */
#define GMRP_LENGTH_LEAVEALL		(sizeof(guint8)+sizeof(guint8))

/* The length of GMRP attribute other than LeaveAll should be:
*
*  8 bytes for Group Membership (1 for length, 1 for event and 6 for mac address to register)
*  or
*  3 bytes for Service Requirement (1 for length, 1 for event, 1 for attribute value)
*
 */
#define GMRP_GROUP_MEMBERSHIP_NON_LEAVEALL 		(sizeof(guint8)+sizeof(guint8)+(6*sizeof(guint8)))
#define GMRP_SERVICE_REQUIREMENT_NON_LEAVEALL	(sizeof(guint8)+sizeof(guint8)+sizeof(guint8))

/* Packet offset definitions */
#define GARP_PROTOCOL_ID		0

/* Event definitions */
#define GMRP_EVENT_LEAVEALL		0
#define GMRP_EVENT_JOINEMPTY	1
#define GMRP_EVENT_JOININ		2
#define GMRP_EVENT_LEAVEEMPTY	3
#define GMRP_EVENT_LEAVEIN		4
#define GMRP_EVENT_EMPTY		5

static const value_string event_vals[] = {
	{ GMRP_EVENT_LEAVEALL,   "Leave All" },
	{ GMRP_EVENT_JOINEMPTY,  "Join Empty" },
	{ GMRP_EVENT_JOININ,     "Join In" },
	{ GMRP_EVENT_LEAVEEMPTY, "Leave Empty" },
	{ GMRP_EVENT_LEAVEIN,    "Leave In" },
	{ GMRP_EVENT_EMPTY,      "Empty" },
	{ 0,                     NULL }
};


/* Code to actually dissect the packets */
static void
dissect_gmrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item   *ti;
    proto_tree   *gmrp_tree;
    guint16       protocol_id;
    guint8        octet;
    guint8		  attribute_type;
    int           msg_index, attr_index, offset = 0, length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GMRP");

    col_set_str(pinfo->cinfo, COL_INFO, "GMRP");

    if (tree)
    {
	ti = proto_tree_add_item(tree, proto_gmrp, tvb, 0, length, FALSE);

	gmrp_tree = proto_item_add_subtree(ti, ett_gmrp);

	/* Read in GARP protocol ID */
	protocol_id = tvb_get_ntohs(tvb, GARP_PROTOCOL_ID);

	proto_tree_add_uint_format(gmrp_tree, hf_gmrp_proto_id, tvb,
				   GARP_PROTOCOL_ID, sizeof(guint16),
				   protocol_id,
				   "Protocol Identifier: 0x%04x (%s)",
				   protocol_id,
				   protocol_id == GARP_DEFAULT_PROTOCOL_ID ?
				     "GARP Multicast Registration Protocol" :
				     "Unknown Protocol");

	/* Currently only one protocol ID is supported */
	if (protocol_id != GARP_DEFAULT_PROTOCOL_ID)
	{
	    proto_tree_add_text(gmrp_tree, tvb, GARP_PROTOCOL_ID, sizeof(guint16),
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
			attribute_type = octet = tvb_get_guint8(tvb, offset);

			/* Check for end of mark */
			if (octet == GARP_END_OF_MARK)
			{
				/* End of GARP PDU */
				if (msg_index)
				{
					proto_tree_add_text(gmrp_tree, tvb, offset, sizeof(guint8),
							"End of pdu");
					break;
				}
				else
				{
					call_dissector(data_handle,
					    tvb_new_subset_remaining(tvb, offset),
					    pinfo, tree);
					return;
				}
			}

			offset += sizeof(guint8);
			length -= sizeof(guint8);

			msg_item = proto_tree_add_text(gmrp_tree, tvb, msg_start, -1,
						   "Message %d", msg_index + 1);

			proto_tree_add_uint(gmrp_tree, hf_gmrp_attribute_type, tvb,
					msg_start, sizeof(guint8), octet);

			/* GMRP supports Group Membership and Service Requirement as attribute types */
			if ( (octet != GMRP_ATTRIBUTE_TYPE_GROUP_MEMBERSHIP) && (octet != GMRP_ATTRIBUTE_TYPE_SERVICE_REQUIREMENT) )
			{
				call_dissector(data_handle,
				    tvb_new_subset_remaining(tvb, offset), pinfo,
				    tree);
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
						proto_tree_add_text(gmrp_tree, tvb, offset,
									sizeof(guint8), "  End of mark");

						offset += sizeof(guint8);
						length -= sizeof(guint8);

						proto_item_set_len(msg_item, offset - msg_start);
						break;
					}
					else
					{
						call_dissector(data_handle,
						    tvb_new_subset_remaining(tvb, offset),
						    pinfo, tree);
						return;
					}
				}
				else
				{
					guint8   event;

					offset += sizeof(guint8);
					length -= sizeof(guint8);

					attr_item = proto_tree_add_text(gmrp_tree, tvb,
					 attr_start, -1, "  Attribute %d", attr_index + 1);

					proto_tree_add_uint(gmrp_tree, hf_gmrp_attribute_length,
					 tvb, attr_start, sizeof(guint8), octet);

					/* Read in attribute event */
					event = tvb_get_guint8(tvb, offset);

					proto_tree_add_uint(gmrp_tree, hf_gmrp_attribute_event,
					 tvb, offset, sizeof(guint8), event);

					offset += sizeof(guint8);
					length -= sizeof(guint8);

					switch (event) {

					case GMRP_EVENT_LEAVEALL:
						if (octet != GMRP_LENGTH_LEAVEALL)
						{
							call_dissector(data_handle,
							    tvb_new_subset_remaining(tvb, offset),
							    pinfo, tree);
							return;
						}
						break;

					 case GMRP_EVENT_JOINEMPTY:
					 case GMRP_EVENT_JOININ:
					 case GMRP_EVENT_LEAVEEMPTY:
					 case GMRP_EVENT_LEAVEIN:
					 case GMRP_EVENT_EMPTY:
						if ( (octet != GMRP_GROUP_MEMBERSHIP_NON_LEAVEALL) && (octet != GMRP_SERVICE_REQUIREMENT_NON_LEAVEALL) )
						{
							call_dissector(data_handle,
							    tvb_new_subset_remaining(tvb, offset),
							    pinfo, tree);
							return;
						}

					/* Show attribute value */

					if ( GMRP_ATTRIBUTE_TYPE_GROUP_MEMBERSHIP == attribute_type )
					{
						/* Group Membership */
						proto_tree_add_item(gmrp_tree, hf_gmrp_attribute_value_group_membership,
							tvb, offset, (6*sizeof(guint8)), ENC_NA);

						offset += 6*sizeof(guint8);
						length -= 6*sizeof(guint8);
					}
					else
					if ( GMRP_ATTRIBUTE_TYPE_SERVICE_REQUIREMENT == attribute_type )
					{
						/* Service Requirement */
						proto_tree_add_item(gmrp_tree, hf_gmrp_attribute_value_service_requirement,
							tvb, offset, sizeof(guint8), ENC_BIG_ENDIAN);

						offset += sizeof(guint8);
						length -= sizeof(guint8);
					}
					else
					{
						call_dissector(data_handle,
						    tvb_new_subset_remaining(tvb, offset),
						    pinfo, tree);
						return;
					}

					break;

					 default:
					call_dissector(data_handle,
					    tvb_new_subset_remaining(tvb, offset),
					    pinfo, tree);
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
proto_register_gmrp(void)
{
    static hf_register_info hf[] = {
	{ &hf_gmrp_proto_id,
	    { "Protocol ID", "gmrp.protocol_id",
	    FT_UINT16,      BASE_HEX,      NULL,  0x0,
	    NULL , HFILL }
	},
	{ &hf_gmrp_attribute_type,
	    { "Type",        "gmrp.attribute_type",
	    FT_UINT8,        BASE_HEX,      VALS(attribute_type_vals),  0x0,
	    NULL , HFILL }
	},
	{ &hf_gmrp_attribute_length,
	    { "Length",      "gmrp.attribute_length",
	    FT_UINT8,        BASE_DEC,      NULL,  0x0,
	    NULL , HFILL }
	},
	{ &hf_gmrp_attribute_event,
	    { "Event",       "gmrp.attribute_event",
	    FT_UINT8,        BASE_DEC,      VALS(event_vals),  0x0,
	    NULL , HFILL }
	},
	{ &hf_gmrp_attribute_value_group_membership,
	    { "Value",       "gmrp.attribute_value_group_membership",
	    FT_ETHER,        BASE_NONE,      NULL,  0x0,
	    NULL , HFILL }
	},
	{ &hf_gmrp_attribute_value_service_requirement,
	    { "Value",       "gmrp.attribute_value_service_requirement",
	    FT_UINT8,        BASE_HEX,      NULL,  0x0,
	    NULL , HFILL }
	}

    };

    static gint *ett[] = {
	&ett_gmrp
    };

    /* Register the protocol name and description for GMRP */
    proto_gmrp = proto_register_protocol("GARP Multicast Registration Protocol", "GMRP", "gmrp");

    /* Required function calls to register the header fields and subtrees
     * used by GMRP */
    proto_register_field_array(proto_gmrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("gmrp", dissect_gmrp, proto_gmrp);

}

void
proto_reg_handoff_gmrp(void){
  data_handle = find_dissector("data");
}
