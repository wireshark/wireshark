/* packet-mrp_msrp.c
 * Routines for MSRP (MRP Multiple Stream Reservation Protocol) dissection
 * Copyright 2010, Torrey Atcitty <tatcitty@harman.com>
 *                 Craig Gunther <craig.gunther@harman.com>
 *
 * Based on the code from packet-mmrp.c (MMRP) from
 * Markus Seehofer <mseehofe@nt.hirschmann.de> Copyright 2001
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
 *
 * The MSRP Protocol specification can be found at the following:
 * http://www.ieee802.org/1/files/private/at-drafts/d6/802-1at-d6-0.pdf
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

/* MSRP End Mark Sequence */
#define MSRP_END_MARK       0x0000

/**********************************************************/
/* Offsets of fields within an MSRP packet                */
/**********************************************************/
#define MSRP_PROTOCOL_VERSION_OFFSET        0

/* Next comes the MSRP Message group */
#define MSRP_MESSAGE_GROUP_OFFSET          (MSRP_PROTOCOL_VERSION_OFFSET + 1) /* Message is a group of fields */
#define MSRP_ATTRIBUTE_TYPE_OFFSET         (MSRP_MESSAGE_GROUP_OFFSET)
#define MSRP_ATTRIBUTE_LENGTH_OFFSET       (MSRP_ATTRIBUTE_TYPE_OFFSET + 1)
#define MSRP_ATTRIBUTE_LIST_LENGTH_OFFSET  (MSRP_ATTRIBUTE_LENGTH_OFFSET + 1)

/* Next comes the MSRP AttributeList group */
#define MSRP_ATTRIBUTE_LIST_GROUP_OFFSET   (MSRP_ATTRIBUTE_LIST_LENGTH_OFFSET + 2) /* AttributeList is a group of fields */

/* Next comes the MSRP VectorAttribute group */
#define MSRP_VECTOR_ATTRIBUTE_GROUP_OFFSET (MSRP_ATTRIBUTE_LIST_GROUP_OFFSET) /* VectorAttribute is a group of fields */
#define MSRP_VECTOR_HEADER_OFFSET          (MSRP_VECTOR_ATTRIBUTE_GROUP_OFFSET) /* contains the following two fields */
#define MSRP_LEAVE_ALL_EVENT_OFFSET        (MSRP_VECTOR_HEADER_OFFSET)
#define MSRP_LEAVE_ALL_EVENT_MASK           0xE000
#define MSRP_NUMBER_OF_VALUES_OFFSET       (MSRP_VECTOR_HEADER_OFFSET)
#define MSRP_NUMBER_OF_VALUES_MASK          0x1fff

/* Next comes the MSRP FirstValue group */
#define MSRP_FIRST_VALUE_GROUP_OFFSET      (MSRP_VECTOR_HEADER_OFFSET + 2) /* FirstValue is a group of fields */
#define MSRP_STREAM_ID_OFFSET              (MSRP_FIRST_VALUE_GROUP_OFFSET)
#define MSRP_STREAM_DA_OFFSET              (MSRP_STREAM_ID_OFFSET + 8)
#define MSRP_VLAN_ID_OFFSET                (MSRP_STREAM_DA_OFFSET + 6)
#define MSRP_TSPEC_MAX_FRAME_SIZE_OFFSET       (MSRP_VLAN_ID_OFFSET + 2)
#define MSRP_TSPEC_MAX_INTERVAL_FRAMES_OFFSET  (MSRP_TSPEC_MAX_FRAME_SIZE_OFFSET + 2)
#define MSRP_PRIORITY_AND_RANK_OFFSET          (MSRP_TSPEC_MAX_INTERVAL_FRAMES_OFFSET + 2) /* contains the following two fields */
#define MSRP_PRIORITY_OFFSET               (MSRP_PRIORITY_AND_RANK_OFFSET)
#define MSRP_PRIORITY_MASK                  0xe0
#define MSRP_RANK_OFFSET                   (MSRP_PRIORITY_AND_RANK_OFFSET)
#define MSRP_RANK_MASK                      0x10
#define MSRP_RESERVED_OFFSET               (MSRP_PRIORITY_AND_RANK_OFFSET)
#define MSRP_RESERVED_MASK                  0x0F
#define MSRP_ACCUMULATED_LATENCY_OFFSET    (MSRP_PRIORITY_AND_RANK_OFFSET + 1)
#define MSRP_FAILURE_BRIDGE_ID_OFFSET      (MSRP_ACCUMULATED_LATENCY_OFFSET + 4)
#define MSRP_FAILURE_CODE_OFFSET           (MSRP_FAILURE_BRIDGE_ID_OFFSET + 8)

#define MSRP_DOMAIN_THREE_PACKED_OFFSET           (MSRP_FIRST_VALUE_GROUP_OFFSET + 4)
#define MSRP_LISTENER_THREE_PACKED_OFFSET         (MSRP_STREAM_ID_OFFSET + 8)
#define MSRP_TALKER_ADVERTISE_THREE_PACKED_OFFSET (MSRP_ACCUMULATED_LATENCY_OFFSET + 4)
#define MSRP_TALKER_FAILED_THREE_PACKED_OFFSET    (MSRP_FAILURE_CODE_OFFSET + 1)

/**********************************************************/
/* Valid field contents                                   */
/**********************************************************/

/* Attribute Type definitions */
#define MSRP_ATTRIBUTE_TYPE_TALKER_ADVERTISE    0x01
#define MSRP_ATTRIBUTE_TYPE_TALKER_FAILED       0x02
#define MSRP_ATTRIBUTE_TYPE_LISTENER            0x03
#define MSRP_ATTRIBUTE_TYPE_DOMAIN              0x04
static const value_string attribute_type_vals[] = {
    { MSRP_ATTRIBUTE_TYPE_TALKER_ADVERTISE, "Talker Advertise" },
    { MSRP_ATTRIBUTE_TYPE_TALKER_FAILED,    "Talker Failed" },
    { MSRP_ATTRIBUTE_TYPE_LISTENER,         "Listener" },
    { MSRP_ATTRIBUTE_TYPE_DOMAIN,           "Domain" },
    { 0,                                    NULL }
};

/* Leave All Event definitions */
#define MSRP_NULLLEAVEALL   0
#define MSRP_LEAVEALL       1
static const value_string leave_all_vals[] = {
    { MSRP_NULLLEAVEALL, "Null" },
    { MSRP_LEAVEALL,     "Leave All" },
    { 0,                 NULL }
};

/* Priority definitions */
 #define MSRP_TRAFFIC_CLASS_A    3
 #define MSRP_TRAFFIC_CLASS_B    2

static const value_string priority_vals[] = {
    { MSRP_TRAFFIC_CLASS_A, "Traffic Class A" },
    { MSRP_TRAFFIC_CLASS_B, "Traffic Class B" },
    { 0,                    NULL }
};

/* Rank definitions */
static const value_string rank_vals[] = {
    { 0, "Emergency" },
    { 1, "Non-emergency" },
    { 0, NULL }
};
static const value_string reserved_vals[] = {
    {  0, "Reserved-0" },
    {  1, "Reserved-1" },
    {  2, "Reserved-2" },
    {  3, "Reserved-3" },
    {  4, "Reserved-4" },
    {  5, "Reserved-5" },
    {  6, "Reserved-6" },
    {  7, "Reserved-7" },
    {  8, "Reserved-8" },
    {  9, "Reserved-9" },
    { 10, "Reserved-10" },
    { 11, "Reserved-11" },
    { 12, "Reserved-12" },
    { 13, "Reserved-13" },
    { 14, "Reserved-14" },
    { 15, "Reserved-15" },
    { 0,  NULL }
};

/* Failure Code definitions */
static const value_string failure_vals[] = {
    {  1, "Insufficient Bandwidth" },
    {  2, "Insufficient Bridge resources" },
    {  3, "Insufficient Bandwidth for Traffic Class" },
    {  4, "Stream ID in use by another Talker" },
    {  5, "Stream destination_address already in use" },
    {  6, "Stream preempted by higher rank" },
    {  7, "Reported latency has changed" },
    {  8, "Egress port in not AVB capable" },
    {  9, "Use a different destination address (i.e. MAC DA hash table full)" },
    { 10, "Out of MSRP resources" },
    { 11, "Out of MMRP resources" },
    { 12, "Cannot store destination_address (i.e. Bridge is out of MAC resources)" },
    { 13, "Requested priority not an SR Class (3.3) priority" },
    { 14, "MaxFrameSize (35.2.2.8.4(a)) is too large for media" },
    { 15, "msrpMaxFanInPorts (35.2.1.4(f)) limit has been reached" },
    { 16, "Changes in FirstValue for a registered StreamID" },
    { 17, "VLAN is blocked on this egress port (Registration Forbidden)" },
    { 18, "VLAN tagging is disabled on this egress port (untagged set)" },
    { 19, "SR class priority mismatch" },
    { 0, NULL }
};

/* SR class ID definitions */
 #define MSRP_SR_CLASS_A    6
 #define MSRP_SR_CLASS_B    5
 #define MSRP_SR_CLASS_C    4
 #define MSRP_SR_CLASS_D    3
 #define MSRP_SR_CLASS_E    2
 #define MSRP_SR_CLASS_F    1
 #define MSRP_SR_CLASS_G    0

static const value_string sr_class_vals[] = {
    { MSRP_SR_CLASS_A, "SR Class A" },
    { MSRP_SR_CLASS_B, "SR Class B" },
    { MSRP_SR_CLASS_C, "SR Class C" },
    { MSRP_SR_CLASS_D, "SR Class D" },
    { MSRP_SR_CLASS_E, "SR Class E" },
    { MSRP_SR_CLASS_F, "SR Class F" },
    { MSRP_SR_CLASS_G, "SR Class G" },
    { 0,                       NULL }
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

/* Four Packed Event definitions */
static const value_string four_packed_vals[] = {
    { 0, "Ignore" },
    { 1, "Asking Failed" },
    { 2, "Ready" },
    { 3, "Ready Failed" },
    { 0, NULL }
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
static int proto_msrp = -1;
static int hf_msrp_proto_id = -1;
static int hf_msrp_message = -1; /* Message is a group of fields */
static int hf_msrp_attribute_type = -1;
static int hf_msrp_attribute_length = -1;
static int hf_msrp_attribute_list_length = -1;
static int hf_msrp_attribute_list = -1; /* AttributeList is a group of fields */
static int hf_msrp_vector_attribute = -1; /* VectorAttribute is a group of fields */

/* The following VectorHeader contains the LeaveAllEvent and NumberOfValues */
static int hf_msrp_vector_header = -1;
static int hf_msrp_leave_all_event = -1;
static int hf_msrp_number_of_values = -1;
static gint ett_vector_header = -1;
static const int *vector_header_fields[] = {
    &hf_msrp_leave_all_event,
    &hf_msrp_number_of_values,
    NULL
};

static int hf_msrp_first_value = -1; /* FirstValue is a group of fields */
static int hf_msrp_stream_id = -1;
static int hf_msrp_stream_da = -1;
static int hf_msrp_vlan_id = -1;
static int hf_msrp_tspec_max_frame_size = -1;
static int hf_msrp_tspec_max_interval_frames = -1;
static int hf_msrp_priority_and_rank = -1;
static int hf_msrp_priority = -1;
static int hf_msrp_rank = -1;
static int hf_msrp_reserved = -1;
static gint ett_priority_and_rank = -1;
static const int *priority_and_rank_fields[] = {
    &hf_msrp_priority,
    &hf_msrp_rank,
    &hf_msrp_reserved,
    NULL
};

static int hf_msrp_sr_class_id = -1;
static int hf_msrp_sr_class_priority = -1;
static int hf_msrp_sr_class_vid = -1;

static int hf_msrp_accumulated_latency = -1;
static int hf_msrp_failure_bridge_id = -1;
static int hf_msrp_failure_code = -1;

static int hf_msrp_three_packed_event = -1;
static int hf_msrp_four_packed_event = -1;

static int hf_msrp_end_mark = -1;

/* Initialize the subtree pointers */
static gint ett_msrp = -1;
static gint ett_msg = -1;
static gint ett_attr_list = -1;
static gint ett_vect_attr = -1;
static gint ett_first_value = -1;



/**********************************************************/
/* Dissector starts here                                  */
/**********************************************************/

/* dissect_msrp_common1 (called from dissect_msrp)
 *
 * dissect the following fields which are common to all MSRP attributes:
 *   Attribute Type
 *   Attribute Length
 *   Attribute List Length
 */
static void
dissect_msrp_common1(proto_tree *msg_tree, tvbuff_t *tvb, int msg_offset)
{
    proto_tree_add_item(msg_tree, hf_msrp_attribute_type, tvb,
                        MSRP_ATTRIBUTE_TYPE_OFFSET + msg_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msg_tree, hf_msrp_attribute_length, tvb,
                        MSRP_ATTRIBUTE_LENGTH_OFFSET + msg_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msg_tree, hf_msrp_attribute_list_length, tvb,
                        MSRP_ATTRIBUTE_LIST_LENGTH_OFFSET + msg_offset, 2, ENC_BIG_ENDIAN);
}


/* dissect_msrp_common2 (called from dissect_msrp)
 *
 * dissect the following fields which are common to all MSRP attributes:
 *   Leave All Event
 *   Number of Values fields
 */
static void
dissect_msrp_common2(proto_tree *vect_attr_tree, tvbuff_t *tvb, int msg_offset)
{
    proto_tree_add_bitmask(vect_attr_tree, tvb, MSRP_VECTOR_HEADER_OFFSET + msg_offset,
                           hf_msrp_vector_header, ett_vector_header, vector_header_fields, FALSE);
}


/* dissect_msrp_talker_common (called from dissect_msrp)
 *
 * dissect the following fields which are common to all MSRP Talker attributes:
 *   Stream MAC DA
 *   Stream VLAN ID
 *   TSpec Bandwidth
 *   TSpec Frame Rate
 *   Priority (Traffic Class)
 *   Rank
 *   Accumulated Latency
 */
static void
dissect_msrp_talker_common(proto_tree *first_value_tree, tvbuff_t *tvb, int msg_offset)
{

    proto_tree_add_item(first_value_tree, hf_msrp_stream_da, tvb,
                        MSRP_STREAM_DA_OFFSET + msg_offset, 6, ENC_NA);
    proto_tree_add_item(first_value_tree, hf_msrp_vlan_id, tvb,
                        MSRP_VLAN_ID_OFFSET + msg_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(first_value_tree, hf_msrp_tspec_max_frame_size, tvb,
                        MSRP_TSPEC_MAX_FRAME_SIZE_OFFSET + msg_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(first_value_tree, hf_msrp_tspec_max_interval_frames, tvb,
                        MSRP_TSPEC_MAX_INTERVAL_FRAMES_OFFSET + msg_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(first_value_tree, tvb, MSRP_PRIORITY_AND_RANK_OFFSET + msg_offset,
                           hf_msrp_priority_and_rank, ett_priority_and_rank, priority_and_rank_fields, FALSE);
    proto_tree_add_item(first_value_tree, hf_msrp_accumulated_latency, tvb,
                        MSRP_ACCUMULATED_LATENCY_OFFSET + msg_offset, 4, ENC_BIG_ENDIAN);
}


/* dissect_msrp_talker_failed (called from dissect_msrp)
 *
 * dissect the following fields which are common to all MSRP Talker Failed attributes:
 *   Failure Information: Bridge ID
 *   Failure Information: Failure Code
 */
static void
dissect_msrp_talker_failed(proto_tree *first_value_tree, tvbuff_t *tvb, int msg_offset)
{

    proto_tree_add_item(first_value_tree, hf_msrp_failure_bridge_id, tvb,
                        MSRP_FAILURE_BRIDGE_ID_OFFSET + msg_offset, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(first_value_tree, hf_msrp_failure_code, tvb,
                        MSRP_FAILURE_CODE_OFFSET + msg_offset, 1, ENC_BIG_ENDIAN);
}


/* dissect_msrp_three_packed_event (called from dissect_msrp)
 *
 * dissect one or more ThreePackedEvents
 */
static guint
dissect_msrp_three_packed_event(proto_tree *vect_attr_tree, tvbuff_t *tvb, guint offset, guint16 number_of_values)
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

        proto_tree_add_uint(vect_attr_tree, hf_msrp_three_packed_event, tvb, offset, sizeof(guint8),
                            three_packed_event[0]);
        counter++;
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_msrp_three_packed_event, tvb, offset, sizeof(guint8),
                                three_packed_event[1]);
            counter++;
        }
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_msrp_three_packed_event, tvb, offset, sizeof(guint8),
                                three_packed_event[2]);
            counter++;
        }

        offset++;
    }
    return( offset );
}


/* dissect_msrp_four_packed_event (called from dissect_msrp)
 *
 * dissect one or more FourPackedEvents
 */
static guint
dissect_msrp_four_packed_event(proto_tree *vect_attr_tree, tvbuff_t *tvb, guint offset, guint16 number_of_values)
{
    guint counter;

    for ( counter = 0; counter < number_of_values; ) {
        guint8 value;
        guint8 four_packed_event[4];

        value = tvb_get_guint8(tvb, offset);
        four_packed_event[0] = (value & 0xc0) >> 6;
        four_packed_event[1] = (value & 0x30) >> 4;
        four_packed_event[2] = (value & 0x0c) >> 2;
        four_packed_event[3] = (value & 0x03);

        proto_tree_add_uint(vect_attr_tree, hf_msrp_four_packed_event, tvb, offset, sizeof(guint8),
                            four_packed_event[0]);
        counter++;
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_msrp_four_packed_event, tvb, offset, sizeof(guint8),
                                four_packed_event[1]);
            counter++;
        }
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_msrp_four_packed_event, tvb, offset, sizeof(guint8),
                                four_packed_event[2]);
            counter++;
        }
        if ( counter < number_of_values ) {
            proto_tree_add_uint(vect_attr_tree, hf_msrp_four_packed_event, tvb, offset, sizeof(guint8),
                                four_packed_event[3]);
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
dissect_msrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtrees and manage them */
    proto_item *ti, *msg_ti, *attr_list_ti, *vect_attr_ti, *first_value_ti;
    proto_tree *msrp_tree, *msg_tree, *attr_list_tree, *vect_attr_tree, *first_value_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MRP-MSRP");

    col_set_str(pinfo->cinfo, COL_INFO, "Multiple Stream Reservation Protocol");

    if (tree) {
        guint8 attribute_type;
        guint8 attribute_length;
        guint16 number_of_values;
        guint16 attribute_list_length;
        guint offset = 0;
        int vect_attr_len;
        int msg_length;  /* Length of MSRP/MRP Message */
        int msg_offset;  /* Use when handling multiple messages.  This points to current msg being decoded. */
        int vect_offset; /* Use when handling multiple vector attributes.  This points to the current vector attribute being decoded. */

        ti = proto_tree_add_item(tree, proto_msrp, tvb, 0, -1, FALSE);
        msrp_tree = proto_item_add_subtree(ti, ett_msrp);

        proto_tree_add_item(msrp_tree, hf_msrp_proto_id, tvb, MSRP_PROTOCOL_VERSION_OFFSET, 1, ENC_BIG_ENDIAN);

        /* MSRP supports multiple MRP Messages per frame.  Handle those Messages in
         * the following while() loop. You will know you are at the end of the list
         * of messages when the EndMark (0x0000) is encountered instead of an
         * Attribute Type and Attribute Length (guaranteed to not be 0x0000).
         */
        msg_offset = 0;
        while (tvb_get_ntohs(tvb, MSRP_ATTRIBUTE_TYPE_OFFSET + msg_offset) != MSRP_END_MARK) {

            attribute_type = tvb_get_guint8(tvb, MSRP_ATTRIBUTE_TYPE_OFFSET + msg_offset);
            attribute_length = tvb_get_guint8(tvb, MSRP_ATTRIBUTE_LENGTH_OFFSET + msg_offset);
            attribute_list_length = tvb_get_ntohs(tvb, MSRP_ATTRIBUTE_LIST_LENGTH_OFFSET + msg_offset);

            /* MSRP Message is a group of fields
             *
             * Contains AttributeType (1 byte)
             *        + AttributeLength (1 byte)
             *        + AttributeListLength (2 bytes)
             *        + AttributeList (AttributeListLength bytes)
            *        bytes of data
            */
            msg_length = 1 + 1 + 2 + attribute_list_length;
            msg_ti = proto_tree_add_item(msrp_tree, hf_msrp_message, tvb,
                                         MSRP_MESSAGE_GROUP_OFFSET + msg_offset,
                                         msg_length, ENC_NA);
            msg_tree = proto_item_add_subtree(msg_ti, ett_msg);

            /* Append AttributeType description to the end of the "Message" heading */
            proto_item_append_text(msg_tree, ": %s (%d)", val_to_str(attribute_type,
                                   attribute_type_vals, "<Unknown>"), attribute_type);

            dissect_msrp_common1(msg_tree, tvb, msg_offset);

            /* MSRP AttributeList is a group of fields
             *
             * Contains AttributeListLength bytes of data
             */
            attr_list_ti = proto_tree_add_item(msg_tree, hf_msrp_attribute_list, tvb,
                                               MSRP_ATTRIBUTE_LIST_GROUP_OFFSET + msg_offset,
                                               attribute_list_length, ENC_NA);
            attr_list_tree = proto_item_add_subtree(attr_list_ti, ett_attr_list);


            /* MSRP supports multiple MRP Vector Attributes per Attribute List.  Handle those
             * Vector Attributes in the following while() loop. You will know you are at the
             * end of the list of Vector Attributes when the EndMark (0x0000) is encountered
             * instead of a Vector Header (guaranteed to not be 0x0000).
             */
            vect_offset = 0;
            while (tvb_get_ntohs(tvb, MSRP_VECTOR_HEADER_OFFSET + msg_offset + vect_offset) != MSRP_END_MARK) {
                /* MSRP VectorAttribute is a group of fields
                 *
                 * Contains VectorHeader (2 bytes)
                 *        + FirstValue (AttributeLength bytes)
                 *        + VectorThreePacked (NumberOfValues @ 3/vector bytes)
                 *        + VectorFourPacked (NumberOfValues @ 4/vector bytes only for Listener attributes)
                 *        bytes of data
                 */
                number_of_values = tvb_get_ntohs(tvb, MSRP_NUMBER_OF_VALUES_OFFSET + msg_offset + vect_offset)
                                   & MSRP_NUMBER_OF_VALUES_MASK;

                vect_attr_len = 2 + attribute_length + (number_of_values + 2)/3; /* stores 3 values per byte */
                if (attribute_type == MSRP_ATTRIBUTE_TYPE_LISTENER)
                    vect_attr_len += (number_of_values + 3)/4; /* stores 4 values per byte */

                vect_attr_ti = proto_tree_add_item(attr_list_tree, hf_msrp_vector_attribute, tvb,
                                                   MSRP_VECTOR_ATTRIBUTE_GROUP_OFFSET + msg_offset + vect_offset,
                                                   vect_attr_len, ENC_NA);

                vect_attr_tree = proto_item_add_subtree(vect_attr_ti, ett_vect_attr);

                dissect_msrp_common2(vect_attr_tree, tvb, msg_offset + vect_offset);

                if(attribute_type == MSRP_ATTRIBUTE_TYPE_DOMAIN) {
                    /* MSRP Domain FirstValue is a group of fields
                     *
                     * Contains SRclassID (1 byte)
                     *        + SRclassPriority (1 byte)
                     *        + SRclassVID (2 bytes)
                     *        bytes of data
                     */
                    first_value_ti = proto_tree_add_item(vect_attr_tree, hf_msrp_first_value, tvb,
                                                         MSRP_FIRST_VALUE_GROUP_OFFSET + msg_offset + vect_offset,
                                                         attribute_length, ENC_NA);
                    first_value_tree = proto_item_add_subtree(first_value_ti, ett_first_value);

                    /* Add Domain components to First Value tree */
                    proto_tree_add_item(first_value_tree, hf_msrp_sr_class_id, tvb,
                                        MSRP_FIRST_VALUE_GROUP_OFFSET + msg_offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(first_value_tree, hf_msrp_sr_class_priority, tvb,
                                        MSRP_FIRST_VALUE_GROUP_OFFSET + msg_offset + 1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(first_value_tree, hf_msrp_sr_class_vid, tvb,
                                        MSRP_FIRST_VALUE_GROUP_OFFSET + msg_offset + 2, 2, ENC_BIG_ENDIAN);

                    /* Decode three packed events. */
                    offset = dissect_msrp_three_packed_event(vect_attr_tree, tvb,
                                                             MSRP_DOMAIN_THREE_PACKED_OFFSET + msg_offset + vect_offset,
                                                             number_of_values);

                }
                else {
                    /* MSRP Stream Reservations FirstValue is a group of fields
                     *
                     * Contains StreamID (8 bytes)
                     *        + DataFrameParameters (8 bytes on Talker attributes)
                     *        + TSpec (8 bytes on Talker attributes)
                     *        + PriorityAndRank (1 byte on Talker attributes)
                     *        + AccumulatedLatency (4 bytes on Talker attributes)
                     *        + FailureInformation (9 bytes on Talker Failed attributes)
                     *        bytes of data
                     */
                    first_value_ti = proto_tree_add_item(vect_attr_tree, hf_msrp_first_value, tvb,
                                                         MSRP_FIRST_VALUE_GROUP_OFFSET + msg_offset + vect_offset,
                                                         attribute_length, ENC_NA);
                    first_value_tree = proto_item_add_subtree(first_value_ti, ett_first_value);

                    /* Decode StreamID */
                    proto_tree_add_item(first_value_tree, hf_msrp_stream_id, tvb,
                                        MSRP_STREAM_ID_OFFSET + msg_offset + vect_offset, 8, ENC_BIG_ENDIAN);

                    switch ( attribute_type ) {
                    case MSRP_ATTRIBUTE_TYPE_LISTENER:
                        offset = dissect_msrp_three_packed_event(vect_attr_tree, tvb,
                                                                 MSRP_LISTENER_THREE_PACKED_OFFSET + msg_offset + vect_offset,
                                                                 number_of_values);
                        offset = dissect_msrp_four_packed_event(vect_attr_tree, tvb, offset, number_of_values);
                        break;
                    case MSRP_ATTRIBUTE_TYPE_TALKER_ADVERTISE:
                        dissect_msrp_talker_common(first_value_tree, tvb, msg_offset + vect_offset);
                        offset = dissect_msrp_three_packed_event(vect_attr_tree, tvb,
                                                                 MSRP_TALKER_ADVERTISE_THREE_PACKED_OFFSET + msg_offset + vect_offset,
                                                                 number_of_values);
                        break;
                    case MSRP_ATTRIBUTE_TYPE_TALKER_FAILED:
                        dissect_msrp_talker_common(first_value_tree, tvb, msg_offset + vect_offset);
                        dissect_msrp_talker_failed(first_value_tree, tvb, msg_offset + vect_offset);
                        offset = dissect_msrp_three_packed_event(vect_attr_tree, tvb,
                                                                 MSRP_TALKER_FAILED_THREE_PACKED_OFFSET + msg_offset + vect_offset,
                                                                 number_of_values);
                        break;
                    default:
                        proto_tree_add_text(first_value_tree, tvb, msg_offset + vect_offset, vect_attr_len, "Unknown Attribute");
                        break;
                    }
                }
                vect_offset += vect_attr_len; /* Move to next Vector Attribute, if there is one */
            } /* Multiple VectorAttribute while() */

            proto_tree_add_item(attr_list_tree, hf_msrp_end_mark, tvb, offset, 2, ENC_BIG_ENDIAN); /* VectorAttribute EndMark */

            msg_offset += msg_length; /* Move to next Message, if there is one */
        } /* Multiple Message while() */
        proto_tree_add_item(msrp_tree, hf_msrp_end_mark, tvb, offset+2, 2, ENC_BIG_ENDIAN); /* Message EndMark */
    }
}


/* Register the protocol with Wireshark */
void
proto_register_mrp_msrp(void)
{
    static hf_register_info hf[] = {
        { &hf_msrp_proto_id,
            { "Protocol Version",      "mrp-msrp.protocol_version",
              FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_message, /* Message is a group of fields */
            { "Message",               "mrp-msrp.message",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_attribute_type,
            { "Attribute Type",        "mrp-msrp.attribute_type",
              FT_UINT8,  BASE_DEC, VALS(attribute_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_msrp_attribute_length,
            { "Attribute Length",      "mrp-msrp.attribute_length",
              FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_attribute_list_length,
            { "Attribute List Length", "mrp-msrp.attribute_list_length",
              FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_attribute_list, /* AttributeList is a group of fields */
            { "Attribute List",        "mrp-msrp.attribute_list",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_vector_attribute, /* VectorAttribute is a group of fields */
            { "Vector Attribute",      "mrp-msrp.vector_attribute",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_vector_header,
            { "Vector Header",         "mrp-msrp.vector_header",
              FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_leave_all_event,
            { "Leave All Event",       "mrp-msrp.leave_all_event",
              FT_UINT16, BASE_DEC, VALS(leave_all_vals), MSRP_LEAVE_ALL_EVENT_MASK, NULL, HFILL }
        },
        { &hf_msrp_number_of_values,
            { "Number of Values",      "mrp-msrp.number_of_values",
              FT_UINT16, BASE_DEC, NULL, MSRP_NUMBER_OF_VALUES_MASK, NULL, HFILL }
        },
        { &hf_msrp_first_value, /* FirstValue is a group of fields */
            { "First Value",           "mrp-msrp.first_value",
              FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_stream_id,
            { "Stream ID",             "mrp-msrp.stream_id",
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msrp_stream_da,
            { "Stream DA",             "mrp-msrp.stream_da",
              FT_ETHER,  BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msrp_vlan_id,
            { "VLAN ID",               "mrp-msrp.vlan_id",
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msrp_tspec_max_frame_size,
            { "TSpec Max Frame Size",  "mrp-msrp.tspec_max_frame_size",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msrp_tspec_max_interval_frames,
            { "TSpec Max Frame Interval", "mrp-msrp.tspec_max_interval_frames",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msrp_priority_and_rank,
            { "Priority and Rank",     "mrp-msrp.priority_and_rank",
              FT_UINT8,  BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_priority,
            { "Priority",              "mrp-msrp.priority",
              FT_UINT8,  BASE_DEC, VALS(priority_vals), MSRP_PRIORITY_MASK, NULL, HFILL }
        },
        { &hf_msrp_rank,
            { "Rank",                  "mrp-msrp.rank",
              FT_UINT8,  BASE_DEC, VALS(rank_vals), MSRP_RANK_MASK, NULL, HFILL }
        },
        { &hf_msrp_reserved,
            { "Reserved",              "mrp-msrp.reserved",
              FT_UINT8,  BASE_DEC, VALS(reserved_vals), MSRP_RESERVED_MASK, NULL, HFILL }
        },
        { &hf_msrp_accumulated_latency,
            { "Accumulated Latency",   "mrp-msrp.accumulated_latency",
              FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_failure_bridge_id,
            { "Failure Bridge ID",     "mrp-msrp.failure_bridge_id",
              FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_failure_code,
            { "Failure Code",          "mrp-msrp.failure_code",
              FT_UINT8, BASE_DEC,  VALS(failure_vals), 0x0, NULL, HFILL }
        },
        { &hf_msrp_sr_class_id,
            { "SR Class ID",           "mrp-msrp.sr_class_id",
              FT_UINT8, BASE_DEC,  VALS(sr_class_vals), 0x0, NULL, HFILL }
        },
        { &hf_msrp_sr_class_priority,
            { "SR Class Priority",     "mrp-msrp.sr_class_priority",
              FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_sr_class_vid,
            { "SR Class VID",          "mrp-msrp.sr_class_vid",
              FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL }
        },
        { &hf_msrp_three_packed_event,
            { "Attribute Event",       "mrp-msrp.three_packed_event",
              FT_UINT8, BASE_DEC,  VALS(three_packed_vals), 0x0, NULL, HFILL }
        },
        { &hf_msrp_four_packed_event,
            { "Declaration Type",      "mrp-msrp.four_packed_event",
              FT_UINT8, BASE_DEC,  VALS(four_packed_vals), 0x0, NULL, HFILL }
        },
        { &hf_msrp_end_mark,
            { "End Mark",              "mrp-msrp.end_mark",
              FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_msrp,
        &ett_msg,
        &ett_attr_list,
        &ett_vect_attr,
        &ett_vector_header,
        &ett_first_value,
        &ett_priority_and_rank
    };

    /* Register the protocol name and description */
    proto_msrp = proto_register_protocol("Multiple Stream Reservation Protocol",
                                         "MRP-MSRP", "mrp-msrp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_msrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mrp_msrp(void)
{
    dissector_handle_t msrp_handle;

    msrp_handle = create_dissector_handle(dissect_msrp, proto_msrp);
    dissector_add_uint("ethertype", ETHERTYPE_MSRP, msrp_handle);
}
