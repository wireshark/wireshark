/* packet-mrp_mvrp.c
 * Routines for MVRP (MRP Multiple VLAN Registration Protocol) dissection
 * Copyright 2011, Pascal Levesque <plevesque[AT]orthogone.ca>
 *
 *
 * Based on the code from packet-mrp-mmrp.c (MMRP) from
 * Johannes Jochen <johannes.jochen[AT]belden.com>
 * Copyright 2011
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
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
 *
 * The MVRP Protocol specification can be found at the following:
 * http://standards.ieee.org/about/get/802/802.1.html
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

/* MVRP End Mark Sequence */
#define MVRP_END_MARK       0x0000

/**********************************************************/
/* Offsets of fields within an MVRP packet                */
/**********************************************************/
#define MVRP_PROTOCOL_VERSION_OFFSET        0

/* Next comes the MVRP Message group */
#define MVRP_MESSAGE_GROUP_OFFSET          (MVRP_PROTOCOL_VERSION_OFFSET + 1) /* Message is a group of fields */
#define MVRP_ATTRIBUTE_TYPE_OFFSET         (MVRP_MESSAGE_GROUP_OFFSET)
#define MVRP_ATTRIBUTE_LENGTH_OFFSET       (MVRP_ATTRIBUTE_TYPE_OFFSET + 1)

/* Next comes the MVRP AttributeList group */
#define MVRP_ATTRIBUTE_LIST_GROUP_OFFSET   (MVRP_ATTRIBUTE_LENGTH_OFFSET + 1) /* AttributeList is a group of fields */

/* Next comes the MVRP VectorAttribute group */
#define MVRP_VECTOR_ATTRIBUTE_GROUP_OFFSET (MVRP_ATTRIBUTE_LIST_GROUP_OFFSET) /* VectorAttribute is a group of fields */
#define MVRP_VECTOR_HEADER_OFFSET          (MVRP_VECTOR_ATTRIBUTE_GROUP_OFFSET) /* contains the following two fields */
#define MVRP_LEAVE_ALL_EVENT_OFFSET        (MVRP_VECTOR_HEADER_OFFSET)
#define MVRP_LEAVE_ALL_EVENT_MASK           0xE000
#define MVRP_NUMBER_OF_VALUES_OFFSET       (MVRP_VECTOR_HEADER_OFFSET)
#define MVRP_NUMBER_OF_VALUES_MASK          0x1fff

/* Next comes the MVRP FirstValue group */
#define MVRP_FIRST_VALUE_GROUP_OFFSET      (MVRP_VECTOR_HEADER_OFFSET + 2) /* FirstValue is a group of fields */

#define MVRP_VID_THREE_PACKED_OFFSET       (MVRP_FIRST_VALUE_GROUP_OFFSET + 2)

/**********************************************************/
/* Valid field contents                                   */
/**********************************************************/

/* Attribute Type definitions */
#define MVRP_ATTRIBUTE_TYPE_VID       0x01
static const value_string attribute_type_vals[] = {
    { MVRP_ATTRIBUTE_TYPE_VID, "VLAN Identifier" },
    { 0,                                    NULL }
};

/* Leave All Event definitions */
#define MVRP_NULLLEAVEALL   0
#define MVRP_LEAVEALL       1
static const value_string leave_all_vals[] = {
    { MVRP_NULLLEAVEALL, "Null" },
    { MVRP_LEAVEALL,     "Leave All" },
    { 0,                 NULL }
};

/* Three Packed Event definitions */
static const value_string three_packed_vals[] = {
    { 0, "New" },
    { 1, "JoinIn" },
    { 2, "In" },
    { 3, "JoinMt" },
    { 4, "Mt" },
    { 5, "Lv" },
    { 0, NULL }
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
static int proto_mvrp = -1;
static int hf_mvrp_proto_id = -1;
static int hf_mvrp_message = -1; /* Message is a group of fields */
static int hf_mvrp_attribute_type = -1;
static int hf_mvrp_attribute_length = -1;
static int hf_mvrp_attribute_list = -1; /* AttributeList is a group of fields */
static int hf_mvrp_vector_attribute = -1; /* VectorAttribute is a group of fields */

/* The following VectorHeader contains the LeaveAllEvent and NumberOfValues */
static int hf_mvrp_vector_header = -1;
static int hf_mvrp_leave_all_event = -1;
static int hf_mvrp_number_of_values = -1;
static gint ett_vector_header = -1;
static const int *vector_header_fields[] = {
    &hf_mvrp_leave_all_event,
    &hf_mvrp_number_of_values,
    NULL
};

static int hf_mvrp_first_value = -1; /* FirstValue is a group of fields */
static int hf_mvrp_vid = -1;
static int hf_mvrp_three_packed_event = -1;

static int hf_mvrp_end_mark = -1;

/* Initialize the subtree pointers */
static gint ett_mvrp = -1;
static gint ett_msg = -1;
static gint ett_attr_list = -1;
static gint ett_vect_attr = -1;
static gint ett_first_value = -1;



/**********************************************************/
/* Dissector starts here                                  */
/**********************************************************/

/* dissect_mvrp_common1 (called from dissect_mvrp)
 *
 * dissect the following fields which are common to all MVRP attributes:
 *   Attribute Type
 *   Attribute Length
 *   Attribute List Length
 */
static void
dissect_mvrp_common1(proto_tree *msg_tree, tvbuff_t *tvb, int msg_offset)
{
    proto_tree_add_item(msg_tree, hf_mvrp_attribute_type, tvb,
                        MVRP_ATTRIBUTE_TYPE_OFFSET + msg_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msg_tree, hf_mvrp_attribute_length, tvb,
                        MVRP_ATTRIBUTE_LENGTH_OFFSET + msg_offset, 1, ENC_BIG_ENDIAN);
}


/* dissect_mvrp_common2 (called from dissect_mvrp)
 *
 * dissect the following fields which are common to all MVRP attributes:
 *   Leave All Event
 *   Number of Values fields
 */
static void
dissect_mvrp_common2(proto_tree *vect_attr_tree, tvbuff_t *tvb, int msg_offset)
{
    proto_tree_add_bitmask(vect_attr_tree, tvb, MVRP_VECTOR_HEADER_OFFSET + msg_offset,
                           hf_mvrp_vector_header, ett_vector_header, vector_header_fields, ENC_BIG_ENDIAN);
}

/* dissect_mvrp_three_packed_event (called from dissect_mvrp)
 *
 * dissect one or more ThreePackedEvents
 */
static guint
dissect_mvrp_three_packed_event(proto_tree *vect_attr_tree, tvbuff_t *tvb, guint offset, guint16 number_of_values)
{
    guint counter;

    for ( counter = 0; counter < number_of_values; ) {
        guint8 value;
        guint8 three_packed_event[3];

        value = tvb_get_guint8(tvb, offset);
        three_packed_event[0] = value / 36;
        value -= 36 * three_packed_event[0];
        three_packed_event[1] = value / 6;
        value -=  6 * three_packed_event[1];
        three_packed_event[2] = value;

        proto_tree_add_uint(vect_attr_tree, hf_mvrp_three_packed_event, tvb, offset, sizeof(guint8),
                            three_packed_event[0]);
        counter++;
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_mvrp_three_packed_event, tvb, offset, sizeof(guint8),
                                three_packed_event[1]);
            counter++;
        }
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_mvrp_three_packed_event, tvb, offset, sizeof(guint8),
                                three_packed_event[2]);
            counter++;
        }

        offset++;
    }
    return( offset );
}

/* dissect_main
 *
 * main dissect function that calls the other functions listed above as necessary
 */
static void
dissect_mvrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtrees and manage them */
    proto_item *ti, *msg_ti, *attr_list_ti, *vect_attr_ti, *first_value_ti;
    proto_tree *mvrp_tree, *msg_tree, *attr_list_tree, *vect_attr_tree, *first_value_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MRP-MVRP");

    col_set_str(pinfo->cinfo, COL_INFO, "Multiple VLAN Registration Protocol");

    if (tree) {
        guint8 attribute_type;
        guint8 attribute_length;
        guint16 number_of_values;
        guint offset = 0;
        int vect_attr_len;
        int msg_offset;  /* Use when handling multiple messages.  This points to current msg being decoded. */
        int vect_offset; /* Use when handling multiple vector attributes.  This points to the current vector attribute being decoded. */

        ti = proto_tree_add_item(tree, proto_mvrp, tvb, 0, -1, ENC_NA);
        mvrp_tree = proto_item_add_subtree(ti, ett_mvrp);

        proto_tree_add_item(mvrp_tree, hf_mvrp_proto_id, tvb, MVRP_PROTOCOL_VERSION_OFFSET, 1, ENC_BIG_ENDIAN);

        /* MVRP supports multiple MRP Messages per frame.  Handle those Messages in
         * the following while() loop. You will know you are at the end of the list
         * of messages when the EndMark (0x0000) is encountered instead of an
         * Attribute Type and Attribute Length (guaranteed to not be 0x0000).
         */
        msg_offset = 0;
        while (tvb_get_ntohs(tvb, MVRP_ATTRIBUTE_TYPE_OFFSET + msg_offset) != MVRP_END_MARK) {

            attribute_type = tvb_get_guint8(tvb, MVRP_ATTRIBUTE_TYPE_OFFSET + msg_offset);
            attribute_length = tvb_get_guint8(tvb, MVRP_ATTRIBUTE_LENGTH_OFFSET + msg_offset);

            /* MVRP Message is a group of fields
             *
             * Contains AttributeType (1 byte)
             *        + AttributeLength (1 byte)
             *        + AttributeList (AttributeListLength bytes)
            *        bytes of data
            */
            msg_ti = proto_tree_add_item(mvrp_tree, hf_mvrp_message, tvb,
                                         MVRP_MESSAGE_GROUP_OFFSET + msg_offset,
                                         -1, ENC_NA);
            msg_tree = proto_item_add_subtree(msg_ti, ett_msg);

            /* Append AttributeType description to the end of the "Message" heading */
            proto_item_append_text(msg_tree, ": %s (%d)",
                                   val_to_str_const(attribute_type, attribute_type_vals, "<Unknown>"),
                                   attribute_type);

            dissect_mvrp_common1(msg_tree, tvb, msg_offset);

            /* MVRP AttributeList is a group of fields
             *
             * Contains AttributeListLength bytes of data NOT
             */
            attr_list_ti = proto_tree_add_item(msg_tree, hf_mvrp_attribute_list, tvb,
                                               MVRP_ATTRIBUTE_LIST_GROUP_OFFSET + msg_offset,
                                               -1, ENC_NA);
            attr_list_tree = proto_item_add_subtree(attr_list_ti, ett_attr_list);


            /* MVRP supports multiple MRP Vector Attributes per Attribute List.  Handle those
             * Vector Attributes in the following while() loop. You will know you are at the
             * end of the list of Vector Attributes when the EndMark (0x0000) is encountered
             * instead of a Vector Header (guaranteed to not be 0x0000).
             */
            vect_offset = 0;
            while (tvb_get_ntohs(tvb, MVRP_VECTOR_HEADER_OFFSET + msg_offset + vect_offset) != MVRP_END_MARK) {
                /* MVRP VectorAttribute is a group of fields
                 *
                 * Contains VectorHeader (2 bytes)
                 *        + FirstValue (AttributeLength bytes)
                 *        + VectorThreePacked (NumberOfValues @ 3/vector bytes)
                 *        + VectorFourPacked (NumberOfValues @ 4/vector bytes only for Listener attributes)
                 *        bytes of data
                 */
                number_of_values = tvb_get_ntohs(tvb, MVRP_NUMBER_OF_VALUES_OFFSET + msg_offset + vect_offset)
                                   & MVRP_NUMBER_OF_VALUES_MASK;

                vect_attr_len = 2 + attribute_length + (number_of_values + 2)/3; /* stores 3 values per byte */

                vect_attr_ti = proto_tree_add_item(attr_list_tree, hf_mvrp_vector_attribute, tvb,
                                                   MVRP_VECTOR_ATTRIBUTE_GROUP_OFFSET + msg_offset + vect_offset,
                                                   vect_attr_len, ENC_NA);

                vect_attr_tree = proto_item_add_subtree(vect_attr_ti, ett_vect_attr);

                dissect_mvrp_common2(vect_attr_tree, tvb, msg_offset + vect_offset);

                if (attribute_type == MVRP_ATTRIBUTE_TYPE_VID) {
                    /* MVRP VLAN ID FirstValue is a group of fields
                     *
                     * Contains VID (2 bytes)
                     *        bytes of data
                     */
                    first_value_ti = proto_tree_add_item(vect_attr_tree, hf_mvrp_first_value, tvb,
                                                         MVRP_FIRST_VALUE_GROUP_OFFSET + msg_offset + vect_offset,
                                                         attribute_length, ENC_NA);
                    first_value_tree = proto_item_add_subtree(first_value_ti, ett_first_value);

                    /* Add VLAN components to First Value tree */
                    proto_tree_add_item(first_value_tree, hf_mvrp_vid, tvb,
                                        MVRP_FIRST_VALUE_GROUP_OFFSET + msg_offset + vect_offset, 2, ENC_BIG_ENDIAN);

                    /* Decode three packed events. */
                    offset = dissect_mvrp_three_packed_event(vect_attr_tree, tvb,
                                                             MVRP_VID_THREE_PACKED_OFFSET + msg_offset + vect_offset,
                                                             number_of_values);

                }

                vect_offset += vect_attr_len; /* Move to next Vector Attribute, if there is one */
            } /* Multiple VectorAttribute while() */

            proto_tree_add_item(attr_list_tree, hf_mvrp_end_mark, tvb, offset, 2, ENC_NA); /* VectorAttribute EndMark */

            proto_item_set_len(attr_list_ti, vect_offset); /*without an endmark*/
            msg_offset += vect_offset + 2; /*  + endmark; Move to next Message, if there is one */
            proto_item_set_len(msg_ti, vect_offset + 2); /*length of message*/

        } /* Multiple Message while() */

        proto_tree_add_item(mvrp_tree, hf_mvrp_end_mark, tvb, offset+2, 2, ENC_NA); /* Message EndMark */
    }
}


/* Register the protocol with Wireshark */
void
proto_register_mrp_mvrp(void)
{
    static hf_register_info hf[] = {
        { &hf_mvrp_proto_id,
            { "Protocol Version",      "mrp-mvrp.protocol_version",
              FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_message, /* Message is a group of fields */
            { "Message",               "mrp-mvrp.message",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_attribute_type,
            { "Attribute Type",        "mrp-mvrp.attribute_type",
              FT_UINT8,  BASE_DEC, VALS(attribute_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_mvrp_attribute_length,
            { "Attribute Length",      "mrp-mvrp.attribute_length",
              FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_attribute_list, /* AttributeList is a group of fields */
            { "Attribute List",        "mrp-mvrp.attribute_list",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_vector_attribute, /* VectorAttribute is a group of fields */
            { "Vector Attribute",      "mrp-mvrp.vector_attribute",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_vector_header,
            { "Vector Header",         "mrp-mvrp.vector_header",
              FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_leave_all_event,
            { "Leave All Event",       "mrp-mvrp.leave_all_event",
              FT_UINT16, BASE_DEC, VALS(leave_all_vals), MVRP_LEAVE_ALL_EVENT_MASK, NULL, HFILL }
        },
        { &hf_mvrp_number_of_values,
            { "Number of Values",      "mrp-mvrp.number_of_values",
              FT_UINT16, BASE_DEC, NULL, MVRP_NUMBER_OF_VALUES_MASK, NULL, HFILL }
        },
        { &hf_mvrp_first_value, /* FirstValue is a group of fields */
            { "First Value",           "mrp-mvrp.first_value",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_vid,
            { "VLAN ID",               "mrp-mvrp.vid",
              FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL }
        },
        { &hf_mvrp_three_packed_event,
            { "Attribute Event",       "mrp-msrp.three_packed_event",
              FT_UINT8, BASE_DEC,  VALS(three_packed_vals), 0x0, NULL, HFILL }
        },
        { &hf_mvrp_end_mark,
            { "End Mark",              "mrp-mvrp.end_mark",
              FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mvrp,
        &ett_msg,
        &ett_attr_list,
        &ett_vect_attr,
        &ett_vector_header,
        &ett_first_value
    };

    /* Register the protocol name and description */
    proto_mvrp = proto_register_protocol("Multiple VLAN Registration Protocol",
                                         "MRP-MVRP", "mrp-mvrp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_mvrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mrp_mvrp(void)
{
    dissector_handle_t mvrp_handle;

    mvrp_handle = create_dissector_handle(dissect_mvrp, proto_mvrp);
    dissector_add_uint("ethertype", ETHERTYPE_MVRP, mvrp_handle);
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
