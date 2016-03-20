/* packet-gvrp.c
 * Routines for GVRP (GARP VLAN Registration Protocol) dissection
 * Copyright 2000, Kevin Shi <techishi@ms22.hinet.net>
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

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_gvrp(void);

/* Initialize the protocol and registered fields */
static int proto_gvrp = -1;
static int hf_gvrp_proto_id = -1;
static int hf_gvrp_attribute_type = -1;
static int hf_gvrp_attribute_length = -1;
static int hf_gvrp_attribute_event = -1;
static int hf_gvrp_attribute_value = -1;
static int hf_gvrp_end_of_mark = -1;

/* Initialize the subtree pointers */
static gint ett_gvrp = -1;
static gint ett_gvrp_message = -1;
static gint ett_gvrp_attribute = -1;

static expert_field ei_gvrp_proto_id = EI_INIT;

/* Constant definitions */
#define GARP_DEFAULT_PROTOCOL_ID        0x0001
#define GARP_END_OF_MARK                0x00

#define GVRP_ATTRIBUTE_TYPE             0x01

static const value_string attribute_type_vals[] = {
    { GVRP_ATTRIBUTE_TYPE, "VID" },
    { 0,                   NULL }
};

/* The length of GVRP LeaveAll attribute should be 2 octets (one for length
 * and the other for event) */
#define GVRP_LENGTH_LEAVEALL            (int)(sizeof(guint8)+sizeof(guint8))

/* The length of GVRP attribute other than LeaveAll should be 4 octets (one
 * for length, one for event, and the last two for VID value).
 */
#define GVRP_LENGTH_NON_LEAVEALL        (int)(sizeof(guint8)+sizeof(guint8)+sizeof(guint16))

/* Packet offset definitions */
#define GARP_PROTOCOL_ID                0

/* Event definitions */
#define GVRP_EVENT_LEAVEALL             0
#define GVRP_EVENT_JOINEMPTY            1
#define GVRP_EVENT_JOININ               2
#define GVRP_EVENT_LEAVEEMPTY           3
#define GVRP_EVENT_LEAVEIN              4
#define GVRP_EVENT_EMPTY                5

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
static int
dissect_gvrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *id_item;
    proto_tree *gvrp_tree, *msg_tree, *attr_tree;
    guint16     protocol_id;
    guint8      octet;
    int         msg_index;
    int         attr_index;
    int         offset = 0;
    int         length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GVRP");

    col_set_str(pinfo->cinfo, COL_INFO, "GVRP");

    ti = proto_tree_add_item(tree, proto_gvrp, tvb, 0, length, ENC_NA);
    gvrp_tree = proto_item_add_subtree(ti, ett_gvrp);

    /* Read in GARP protocol ID */
    protocol_id = tvb_get_ntohs(tvb, GARP_PROTOCOL_ID);

    id_item = proto_tree_add_uint_format_value(gvrp_tree, hf_gvrp_proto_id, tvb,
                                GARP_PROTOCOL_ID, 2,
                                protocol_id,
                                "0x%04x (%s)",
                                protocol_id,
                                protocol_id == GARP_DEFAULT_PROTOCOL_ID ?
                                    "GARP VLAN Registration Protocol" :
                                    "Unknown Protocol");

    /* Currently only one protocol ID is supported */
    if (protocol_id != GARP_DEFAULT_PROTOCOL_ID)
    {
        expert_add_info(pinfo, id_item, &ei_gvrp_proto_id);
        call_data_dissector(tvb_new_subset_remaining(tvb, GARP_PROTOCOL_ID + 2),
            pinfo, tree);
        return tvb_captured_length(tvb);
    }

    offset += 2;
    length -= 2;

    msg_index = 0;

    /* Begin to parse GARP messages */
    while (length)
    {
        proto_item *msg_item;
        int         msg_start = offset;

        /* Read in attribute type. */
        octet = tvb_get_guint8(tvb, offset);

        /* Check for end of mark */
        if (octet == GARP_END_OF_MARK)
        {
            /* End of GARP PDU */
            if (msg_index)
            {
                proto_tree_add_item(gvrp_tree, hf_gvrp_end_of_mark, tvb, offset, 1, ENC_NA);
                break;
            }
            else
            {
                call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
                return tvb_captured_length(tvb);
            }
        }

        offset += 1;
        length -= 1;

        msg_tree = proto_tree_add_subtree_format(gvrp_tree, tvb, msg_start, -1, ett_gvrp_message, &msg_item,
                                        "Message %d", msg_index + 1);

        proto_tree_add_uint(msg_tree, hf_gvrp_attribute_type, tvb,
                            msg_start, 1, octet);

        /* GVRP only supports one attribute type. */
        if (octet != GVRP_ATTRIBUTE_TYPE)
        {
            call_data_dissector(tvb_new_subset_remaining(tvb, offset),
                pinfo, tree);
            return tvb_captured_length(tvb);
        }

        attr_index = 0;

        while (length)
        {
            int         attr_start = offset;
            proto_item *attr_item;

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
                    proto_tree_add_item(msg_tree, hf_gvrp_end_of_mark, tvb, offset, 1, ENC_NA);

                    offset += 1;
                    length -= 1;

                    proto_item_set_len(msg_item, offset - msg_start);
                    break;
                }
                else
                {
                    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
                    return tvb_captured_length(tvb);
                }
            }
            else
            {
                guint8 event;

                offset += 1;
                length -= 1;

                attr_tree = proto_tree_add_subtree_format(msg_tree, tvb, attr_start, -1,
                        ett_gvrp_attribute, &attr_item, "Attribute %d", attr_index + 1);

                proto_tree_add_uint(attr_tree, hf_gvrp_attribute_length,
                        tvb, attr_start, 1, octet);

                /* Read in attribute event */
                event = tvb_get_guint8(tvb, offset);

                proto_tree_add_uint(attr_tree, hf_gvrp_attribute_event,
                        tvb, offset, 1, event);

                offset += 1;
                length -= 1;

                switch (event) {

                case GVRP_EVENT_LEAVEALL:
                    if (octet != GVRP_LENGTH_LEAVEALL)
                    {
                        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo,
                            tree);
                        return tvb_captured_length(tvb);
                    }
                    break;

                    case GVRP_EVENT_JOINEMPTY:
                    case GVRP_EVENT_JOININ:
                    case GVRP_EVENT_LEAVEEMPTY:
                    case GVRP_EVENT_LEAVEIN:
                    case GVRP_EVENT_EMPTY:
                    if (octet != GVRP_LENGTH_NON_LEAVEALL)
                    {
                        call_data_dissector(tvb_new_subset_remaining(tvb, offset),pinfo,
                            tree);
                        return tvb_captured_length(tvb);
                    }

                    /* Show attribute value */
                    proto_tree_add_item(attr_tree, hf_gvrp_attribute_value,
                        tvb, offset, 2, ENC_BIG_ENDIAN);

                    offset += 2;
                    length -= 2;
                    break;

                    default:
                    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
                    return tvb_captured_length(tvb);
                }
            }

            proto_item_set_len(attr_item, offset - attr_start);

            attr_index++;
        }

        msg_index++;
    }
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_gvrp(void)
{
    static hf_register_info hf[] = {
        { &hf_gvrp_proto_id,
          { "Protocol Identifier", "gvrp.protocol_id",
            FT_UINT16,      BASE_HEX,      NULL,  0x0,
            NULL, HFILL }
        },
        { &hf_gvrp_attribute_type,
          { "Type",        "gvrp.attribute_type",
            FT_UINT8,        BASE_HEX,      VALS(attribute_type_vals),  0x0,
            NULL, HFILL }
        },
        { &hf_gvrp_attribute_length,
          { "Length",      "gvrp.attribute_length",
            FT_UINT8,        BASE_DEC,      NULL,  0x0,
            NULL, HFILL }
        },
        { &hf_gvrp_attribute_event,
          { "Event",       "gvrp.attribute_event",
            FT_UINT8,        BASE_DEC,      VALS(event_vals),  0x0,
            NULL, HFILL }
        },
        { &hf_gvrp_attribute_value,
          { "Value",       "gvrp.attribute_value",
            FT_UINT16,       BASE_DEC,      NULL,  0x0,
            NULL, HFILL },
        },
        { &hf_gvrp_end_of_mark,
          { "End of Mark",       "gvrp.end_of_mark",
            FT_NONE,       BASE_NONE,      NULL,  0x0,
            NULL, HFILL },
        },
    };

    static ei_register_info ei[] = {
        { &ei_gvrp_proto_id, { "gvrp.protocol_id.unknown", PI_PROTOCOL, PI_WARN, "Warning: this version of Wireshark only knows about protocol id = 1", EXPFILL }},
    };

    expert_module_t* expert_gvrp;

    static gint *ett[] = {
        &ett_gvrp,
        &ett_gvrp_message,
        &ett_gvrp_attribute,
    };


    /* Register the protocol name and description for GVRP */
    proto_gvrp = proto_register_protocol("GARP VLAN Registration Protocol", "GVRP", "gvrp");

    /* Required function calls to register the header fields and subtrees
     * used by GVRP */
    proto_register_field_array(proto_gvrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gvrp = expert_register_protocol(proto_gvrp);
    expert_register_field_array(expert_gvrp, ei, array_length(ei));

    register_dissector("gvrp", dissect_gvrp, proto_gvrp);
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
