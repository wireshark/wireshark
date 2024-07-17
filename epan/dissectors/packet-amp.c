/* packet-amp.c
 * Routines for Asynchronous management Protocol dissection
 * Copyright 2018, Krishnamurthy Mayya (krishnamurthymayya@gmail.com)
 * Updated to CBOR encoding: Keith Scott, 2019 (kscott@mitre.org)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include "packet-amp.h"

/* The AMP standard can be found here:
 * https://tools.ietf.org/html/draft-birrane-dtn-amp-04
 * https://tools.ietf.org/html/draft-birrane-dtn-amp-03
 */

#define AMP_APID 0x000 /* TODO - To be decided. Currently, the function 'dissect_amp_as_subtree' is
                          being called from dtn.c file when required to decode the bundle protocol's
                          data-payload as AMP. Later in the future, when a dedicated field is given to
                          this, this should be filled. */

/*
 */
static void
add_value_time_to_tree(uint64_t value, int len, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_time_format)
{
    nstime_t dtn_time;

    // If it's a relative time, just make it zero.
    if ( value < 558230400 ) {
        value = 0;
    }
    dtn_time.secs = (time_t)(value);
    dtn_time.nsecs = 0;
    proto_tree_add_time(tree, hf_time_format, tvb, offset, len, &dtn_time);

    return;
}

#define AMP_HDR_RESERVED         0xC0
#define AMP_HDR_ACL              0x20
#define AMP_HDR_NACK             0x10
#define AMP_HDR_ACK              0x08
#define AMP_HDR_OPCODE           0x07

#define AMP_ARI_NICKNAME         0x80
#define AMP_ARI_PARAMETERS       0x40
#define AMP_ARI_ISSUER           0x20
#define AMP_ARI_TAG              0x10
#define AMP_ARI_STRUCT           0x0F
#define AMP_ARI_VALUE            0xF0

#define AMP_CBOR_UINT_SMALL      0x1F

#define AMP_TNVC_RESERVED        0xF0
#define AMP_TNVC_MIXED           0x08
#define AMP_TNVC_TYPE            0x04
#define AMP_TNVC_NAME            0x02
#define AMP_TNVC_VALUE           0x01

#define AMP_MSG_REGISTER_AGENT   0x01
#define AMP_MSG_DATA_REPORT      0x00
#define AMP_MSG_PERFORM_CONTROL  0x02

static dissector_handle_t amp_handle;

void proto_register_amp(void);
void proto_reg_handoff_amp(void);

static int hf_amp_message_header;
static int hf_amp_report_bytestring;
static int hf_amp_report_data;
static int hf_amp_report_integer8_small;
static int hf_amp_report_integer;
static int hf_amp_cbor_header;
static int hf_amp_primary_timestamp;
static int hf_amp_agent_name;
static int hf_amp_text_string;
static int hf_amp_ari_flags;
static int hf_ari_value;
static int hf_ari_struct;
static int hf_ari_nickname;
static int hf_ari_parameters;
static int hf_ari_issuer;
static int hf_ari_tag;
static int hf_amp_tnvc_flags;
static int hf_amp_tnvc_reserved;
static int hf_amp_tnvc_mixed;
static int hf_amp_tnvc_typed;
static int hf_amp_tnvc_name;
static int hf_amp_tnvc_values;

/* Initialize the protocol and registered fields */
static int proto_amp;

static int ett_amp_message_header;
static int ett_amp_proto;
static int ett_amp;
static int ett_amp_cbor_header;
static int ett_amp_message;
static int ett_amp_register;
static int ett_amp_report_set;
static int ett_amp_report;
static int ett_amp_tnvc_flags;
static int ett_amp_ari_flags;

static int hf_amp_reserved;
static int hf_amp_acl;
static int hf_amp_nack;
static int hf_amp_ack;
static int hf_amp_opcode;
static int hf_amp_rx_name;

static expert_field ei_amp_cbor_malformed;

static const value_string opcode[] = {
    { 0, "Register Agent" },
    { 1, "Report Set" },
    { 2, "Perform Control" },
    { 0, NULL }
};

static const value_string amp_ari_struct_type[] = {
    { 0, "Const" },
    { 1, "Control" },
    { 2, "Externally Defined Data" },
    { 3, "Macro" },
    { 4, "Operation" },
    { 5, "Report Template" },
    { 6, "State-Based Rule" },
    { 7, "Table Templates" },
    { 8, "Time-Based Rule" },
    { 9, "Variables" },
    { 10, "Metadata" },
    { 11, "Reserved" },
    { 12, "Reserved" },
    { 13, "Reserved" },
    { 14, "Reserved" },
    { 15, "Reserved" },
    { 0, NULL }
};


/* AMP Message Header */
static int * const amp_message_header[] = {
    &hf_amp_reserved,
    &hf_amp_acl,
    &hf_amp_nack,
    &hf_amp_ack,
    &hf_amp_opcode,
    0
};

/* TNVC Flags */
static int * const amp_tnvc_flags[] = {
    &hf_amp_tnvc_reserved,
    &hf_amp_tnvc_mixed,
    &hf_amp_tnvc_typed,
    &hf_amp_tnvc_name,
    &hf_amp_tnvc_values,
    0
};

/* ARI Flags */
static int * const amp_ari_flags[] = {
    &hf_ari_nickname,
    &hf_ari_parameters,
    &hf_ari_issuer,
    &hf_ari_tag,
    &hf_ari_struct,
    0
};

/* CBOR Types */
typedef enum {
    CBOR_UNKNOWN = -1,
    CBOR_UINT = 0, // Positive, unsigned integer
    CBOR_INT = 1, // Negative integer
    CBOR_BYTESTRING = 2,
    CBOR_TEXTSTRING = 3,
    CBOR_ARRAY = 4,
    CBOR_MAP = 5,
    CBOR_SEMANTIC_TAG = 6,
    CBOR_PRIMITIVE = 7
} CBOR_TYPE;

typedef struct {
    int type;
    int size; // for integers, the value
              // for bytestrings and textstrings, the size of the string
              // for arrays, the number of elements in the array
    uint64_t totalSize; // total size (including size above and any bytestring
                       // size).
    uint64_t uint;
} cborObj;


// Decode the CBOR object at the given offset in the tvb.
// The returned cborObj contains the object (with type) and the size
// (including the CBOR identifier).
static cborObj cbor_info(tvbuff_t *tvb, int offset)
{
    int tmp = 0;
    cborObj ret;
    ret.type = CBOR_UNKNOWN;
    ret.size = 0;
    ret.totalSize = 0;
    ret.uint = -1;
    int theSize;

    tmp = tvb_get_uint8(tvb, offset);

    offset += 1;
    ret.size += 1;

    ret.type = (tmp & 0xE0)>>5; // Top 3 bits
    theSize = (tmp & 0x1F);

    switch ( ret.type )
    {
    case 0x00: // Positive / Unsigned integer
        if ( theSize<24 ) {
            ret.uint = (tmp & 0x1F); // May be actual size or indication of follow-on size
        } else if (theSize==24) { // next byte is uint8_t data
            ret.uint = tvb_get_uint8(tvb, offset);
            ret.size += 1;
        } else if (theSize==25) { // next 2 bytes are uint16_t data
            ret.uint = tvb_get_uint16(tvb, offset, 0);
            ret.size += 2;
        } else if (theSize==26) { // next 4 bytes are uint32_t data
            ret.uint = tvb_get_uint32(tvb, offset, 0);
            ret.size += 4;
        } else if (theSize==27) { // next 8 bytes are uint64_t data
            ret.uint = tvb_get_uint64(tvb, offset, 0);
            ret.size += 8;
        }
        ret.totalSize = ret.size;
        break;

    case 0x02: // Byte string
        if ( theSize<24 ) { // Array size is contained in the identifier byte
            ret.uint = (tmp & 0x1F);
        } else if (theSize==24) { // next byte is uint8_t data (length)
            ret.uint = tvb_get_uint8(tvb, offset);
            ret.size += 1;
        } else if (theSize==25) { // next 2bytes are uint16_t data (length)
            ret.uint = tvb_get_uint16(tvb, offset, 0);
            ret.size += 2;
        } else if (theSize==26) { // next 4bytes are uint32_t data
            ret.uint = tvb_get_uint32(tvb, offset, 0);
            ret.size += 4;
        } else if (theSize==27) { // next byte is uint64_t data
            ret.uint = tvb_get_uint64(tvb, offset, 0);
            ret.size += 8;
        }
        ret.totalSize = ret.size+ret.uint;
        break;

    case 0x03: // Text string
        if ( theSize<24 ) // Array size is contained in the identifier byte
        {
            ret.uint = (tmp & 0x1F);
        } else if (theSize==24) // next byte is uint8_t data
        {
            ret.uint = tvb_get_uint8(tvb, offset);
            ret.size += 1;
        } else if (theSize==25) // next 2bytes are uint16_t data
        {
            ret.uint = tvb_get_uint16(tvb, offset, 0);
            ret.size += 2;
        } else if (theSize==26) // next 4bytes are uint32_t data
        {
            ret.uint = tvb_get_uint32(tvb, offset, 0);
            ret.size += 4;
        } else if (theSize==27) // next byte is uint64_t data
        {
            ret.uint = tvb_get_uint64(tvb, offset, 0);
            ret.size += 8;
        }
        ret.totalSize = ret.size+ret.uint;
        break;

    case 0x04: // Array
        if ( theSize<24 ) // Array size is contained in the identifier byte
        {
            ret.uint = (tmp & 0x1F);
        } else if (theSize==24) // next byte is uint8_t data
        {
            ret.uint = tvb_get_uint8(tvb, offset);
            ret.size += 1;
        } else if (theSize==25) // next 2bytes are uint16_t data
        {
            ret.uint = tvb_get_uint16(tvb, offset, 0);
            ret.size += 2;
        } else if (theSize==26) // next 4bytes are uint32_t data
        {
            ret.uint = tvb_get_uint32(tvb, offset, 0);
            ret.size += 4;
        } else if (theSize==27) // next byte is uint64_t data
        {
            ret.uint = tvb_get_uint64(tvb, offset, 0);
            ret.size += 8;
        }
        // I know how many elements are in the array, but NOT the total
        // size of the array data.
        ret.totalSize = -1;
        break;

    case 0x06: // Semantic tag
        if ( theSize<24 )
        {
            ret.uint = (tmp & 0x1F);
        }
        ret.totalSize += ret.uint;
        break;

    case 0x01: // Negative integer
    case 0x07: // Primitives e.g. break, float, simple values
    default:
        // TODO -- not supported yet.
        break;
    }
    return ret;
}

void
dissect_amp_as_subtree(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int offset)
{
    uint64_t messages = 0;
    unsigned int i=0;
    unsigned int j=0;
    unsigned int k=0;
    unsigned int numTNVCEntries = 0;

    proto_tree *amp_tree = NULL;
    proto_tree *amp_items_tree = NULL;
    proto_tree *amp_register_tree = NULL;
    proto_tree *amp_report_set_tree = NULL;
    proto_tree *amp_report_tree = NULL;
    proto_tree *amp_report_TNVC_tree = NULL;
    proto_tree *amp_control_tree = NULL;
    proto_tree *amp_table_tree = NULL;
    proto_item *payload_item = NULL;
    proto_tree *amp_message_tree = NULL;
    proto_tree *amp_report_TNVC_sub_tree = NULL;
    proto_item  *amp_message = NULL;
    proto_item  *amp_register  = NULL;
    proto_item  *amp_report_set = NULL;
    proto_item  *amp_report = NULL;

    cborObj myObj;
    cborObj tmpObj;
    cborObj tmpObj2;
    cborObj tmpObj3;
    cborObj tmpObj4;
    int reportHasTimestamp = 0;
    int report_types_offset = 0;

    amp_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_amp_proto,
                                       &payload_item, "Payload Data: AMP Protocol");

    // First byte is the main CBOR type (probably an array of things)
    // e.g. 0x82 (byte array of 2 things)
    myObj = cbor_info(tvb, offset);
    offset += myObj.size;
    messages = myObj.uint;

    // Item 0 is the timestamp
    myObj = cbor_info(tvb, offset);
    add_value_time_to_tree((int) myObj.uint, MIN(myObj.size-1, 1), amp_tree, tvb, offset, hf_amp_primary_timestamp);
    offset += myObj.size;

    for ( i=1; i<messages; i++ ) {
        // Get the bytestring object that gives the total length of the AMP chunk
        myObj = cbor_info(tvb, offset);
        offset += myObj.size; // Note: myObj.uint is the length of the amp chunk; used later
                              // to advance offset past this message.

        // The first byte of this byte string (the AMP message) is going to be the message header
        // This is just a byte, not a CBOR uint8
        int ampHeader;
        ampHeader = tvb_get_uint8(tvb, offset);
        amp_message_tree = proto_tree_add_subtree(amp_tree, tvb, offset, -1,
                                                  ett_amp_message, &amp_message, "AMP Message");

        proto_tree_add_bitmask(amp_message_tree, tvb, offset, hf_amp_message_header, ett_amp_message_header,
                               amp_message_header, ENC_BIG_ENDIAN);
        offset += 1;
        int old_offset;

        switch ( ampHeader & 0x07)
        {
        case 0x00: // Register agent
            //amp_register_sub_tree = proto_item_add_subtree(amp_message_tree, ett_amp);
            amp_register_tree = proto_tree_add_subtree(amp_message_tree, tvb, offset-1, 1,
                                            ett_amp_register, &amp_register, "Register-Agent");
            tmpObj = cbor_info(tvb, offset); // Should come back a CBOR text string if some length.
            offset += tmpObj.size;
            proto_tree_add_item(amp_register_tree, hf_amp_agent_name, tvb, offset,
                                (int) tmpObj.uint, ENC_ASCII|ENC_NA);
            old_offset = offset;
            offset += (int) tmpObj.uint;
            if (offset < old_offset) {
                proto_tree_add_expert(amp_tree, pinfo, &ei_amp_cbor_malformed, tvb, offset, -1);
                return;
            }
            break;

        case 0x01: // Report set
            amp_report_set_tree = proto_tree_add_subtree(amp_message_tree, tvb, offset-2, -1,
                                            ett_amp_report_set, &amp_report_set, "Report-Set");

            // Rx Names
            tmpObj = cbor_info(tvb, offset); // Should come back a CBOR array of some size (Rx Names)
            if ( tmpObj.type != 0x04 ) {
                return;
            }
            offset += tmpObj.size;
            // read rx names
            for ( j=0; j<tmpObj.uint; j++ ) {
                tmpObj2 = cbor_info(tvb, offset); // Should be text string of some size
                offset += tmpObj2.size;
                proto_tree_add_item(amp_report_set_tree, hf_amp_rx_name, tvb, offset,
                                    (int) tmpObj2.uint, ENC_ASCII|ENC_NA);
                old_offset = offset;
                offset += (int) tmpObj2.uint;
                if (offset < old_offset) {
                    proto_tree_add_expert(amp_tree, pinfo, &ei_amp_cbor_malformed, tvb, offset, -1);
                    return;
                }
            }

            // How many reports?
            tmpObj2 = cbor_info(tvb, offset); // Should come back a CBOR array of some size
            offset += tmpObj.size;

            for ( j=0; j<tmpObj2.uint; j++ ) {
                // Internals of each report per section 8.4.7 of https://tools.ietf.org/pdf/draft-birrane-dtn-amp-07.pdf
                // amp_report_sub_tree = proto_item_add_subtree(amp_report_set_tree, ett_amp);
                amp_report_tree = proto_tree_add_subtree(amp_report_set_tree, tvb, offset, -1,
                                                             ett_amp_report, &amp_report, "Report");

                // Each Report is a:
                //     Tempate [ARI]
                //     Timestamp [TS] (opt)
                //     Entries [TNVC] (bytestring containing a TNVC)
                tmpObj3 = cbor_info(tvb, offset); // Should come back a CBOR array of size 2 or 3
                offset += tmpObj3.size;
                if ( tmpObj3.uint==3 )
                {
                    reportHasTimestamp = 1;
                } else
                {
                    reportHasTimestamp = 0;
                }

                // Tempate (bytestring); starts with ARI
                tmpObj3 = cbor_info(tvb, offset);
                offset += tmpObj3.size;
                uint8_t ariFlags;
                ariFlags = tvb_get_uint8(tvb, offset);

                if ( (ariFlags&0x0F)==0x03 ) {
                    // Literal
                    proto_tree_add_uint(amp_report_tree, hf_ari_value, tvb, offset, 1, ariFlags);
                } else {
                    // NOT literal
                    proto_tree_add_bitmask(amp_report_tree, tvb, offset, hf_amp_ari_flags, ett_amp_ari_flags,
                                           amp_ari_flags, ENC_BIG_ENDIAN);

                }
                //proto_tree_add_uint(amp_ari_tree, hf_ari_struct, tvb, offset, 1, ariFlags);

                if ( (ariFlags & 0x0F) != 0x03 )
                {
                    // ARI is NOT Literal
                    proto_tree_add_item(amp_report_tree, hf_amp_report_bytestring, tvb, offset+1, (int) tmpObj3.uint-1, ENC_NA);
                }
                old_offset = offset;
                offset += (int) tmpObj3.uint;
                if (offset < old_offset) {
                    proto_tree_add_expert(amp_tree, pinfo, &ei_amp_cbor_malformed, tvb, offset, -1);
                    return;
                }

                if ( reportHasTimestamp )
                {
                    tmpObj3 = cbor_info(tvb, offset);
                    offset += 1;
                    add_value_time_to_tree((int) tmpObj3.uint, 4, amp_report_tree, tvb, offset, hf_amp_primary_timestamp);
                    offset += (tmpObj3.size-1);
                }

                // Entries [TNVC] -- This is th collection of data values that comprise the report
                // contents in accordance with the associated Report Template.
                // Contained in a CBOR bytestring
                tmpObj3 = cbor_info(tvb, offset);
                offset += tmpObj3.size;

                // Now read array length for TNVC
                tmpObj3 = cbor_info(tvb, offset);
                offset += tmpObj3.size;
                numTNVCEntries = (int) tmpObj3.uint;

                // TNVC Flags
                proto_tree_add_bitmask(amp_report_tree, tvb, offset, hf_amp_tnvc_flags, ett_amp_tnvc_flags,
                                       amp_tnvc_flags, ENC_BIG_ENDIAN);
                offset += 1;

                // TNVC entries
                amp_report_TNVC_sub_tree = proto_item_add_subtree(amp_report_tree, ett_amp);
                amp_report_TNVC_tree = proto_tree_add_subtree(amp_report_TNVC_sub_tree, tvb, offset, -1,
                        ett_amp_message, &amp_message, "TNVC Entries");

                // Byte string containing data types
                tmpObj3 = cbor_info(tvb, offset);
                offset += tmpObj3.size;
                report_types_offset = offset;
                offset += (int) tmpObj3.uint;
                if (offset < report_types_offset) {
                    proto_tree_add_expert(amp_tree, pinfo, &ei_amp_cbor_malformed, tvb, offset, -1);
                    return;
                }

                // TNVC data items
                for ( k=0; k<numTNVCEntries-2; k++ ) {
                    tmpObj3 = cbor_info(tvb, offset);
                    switch ( tmpObj3.type ) {
                    case 0x02: // bytestring
                        // Get the type from the type dictionary
                        switch ( tvb_get_uint8(tvb, report_types_offset+k) ) {
                        case 0x12: // string
                            // It's a text string of some size INSIDE a byte string
                            tmpObj4 = cbor_info(tvb, offset+tmpObj3.size);
                            // printf("tmpObj4.type of (%02x) is (%d)\n", tvb_get_uint8(tvb, offset+tmpObj3.size), tmpObj4.type);
                            proto_tree_add_item(amp_report_TNVC_tree, hf_amp_text_string, tvb,
                                        offset+tmpObj3.size+tmpObj4.size,
                                        (int) tmpObj3.uint-tmpObj4.size, 0x00);
                            break;
                        case 0x16: // uvast
                            tmpObj4 = cbor_info(tvb, offset+tmpObj3.size);
                            if ( tmpObj4.type != CBOR_UINT ) {
                                break;
                            }
                            switch ( tmpObj4.size ) {
                            case 1:
                                proto_tree_add_item(amp_report_TNVC_tree, hf_amp_report_integer8_small,
                                                tvb, offset+tmpObj3.size, 1, 0x00);
                                break;
                            default: // Note: CBOR will only let these sizes be 1, 2, 4, or 8 bytes.
                                proto_tree_add_item(amp_report_TNVC_tree, hf_amp_report_integer,
                                                tvb, offset+tmpObj3.size+1, tmpObj4.size-1, 0x00);
                                break;
                            }
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        proto_tree_add_item(amp_report_TNVC_tree, hf_amp_report_data, tvb, offset+tmpObj3.size, (int) tmpObj3.uint, 0x00);
                        break;
                    }
                    if ( tmpObj3.totalSize > 0 ) {
                        DISSECTOR_ASSERT(tmpObj3.totalSize <= INT32_MAX);
                        offset += (int)tmpObj3.totalSize;
                    } else {
                        break;
                    }
                }

            }
            break;

        case 0x02: // Perform Control
            // TODO
            //amp_control_sub_tree = proto_item_add_subtree(amp_message_tree, ett_amp);
            amp_control_tree = proto_tree_add_subtree(amp_message_tree, tvb, offset-1, -1,
                                            ett_amp_message, &amp_message, "Perform-Control");
            proto_tree_add_item(amp_control_tree, hf_amp_cbor_header, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        case 0x03: // Table Set
            // TODO
            //amp_table_sub_tree = proto_item_add_subtree(amp_items_tree, ett_amp);
            amp_table_tree = proto_tree_add_subtree(amp_items_tree, tvb, offset, -1,
                                            ett_amp_message, &amp_message, "AMP Message: Table-Set");
            proto_tree_add_item(amp_table_tree, hf_amp_cbor_header, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            break;
        }
    }

    return;
}

/* Code to actually dissect the packets */
static int
dissect_amp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int offset = 0;
  proto_item  *amp_packet;
  proto_item  *amp_tree;
  int amp_packet_reported_length;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMP");
  col_clear(pinfo->cinfo, COL_INFO);

  amp_packet_reported_length = tvb_reported_length_remaining(tvb, 0);

  amp_packet = proto_tree_add_item(tree, proto_amp, tvb, 0, amp_packet_reported_length, ENC_NA);
  amp_tree   = proto_item_add_subtree(amp_packet, ett_amp);

  dissect_amp_as_subtree (tvb, pinfo, amp_tree, offset);

  return tvb_captured_length(tvb);
}

void
proto_register_amp(void)
{
    static hf_register_info hf[] = {

        { &hf_amp_message_header,
        { "AMP Message Header", "amp.message.header",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_amp_report_data,
        { "Report-Data", "amp.report.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amp_report_bytestring,
        { "Report-Bytestring", "amp.report.bytestring",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amp_report_integer8_small,
        { "Report-Integer8_small", "amp.report.integer8_small",
            FT_UINT8, BASE_DEC, NULL, AMP_CBOR_UINT_SMALL,
            NULL, HFILL }
        },
        { &hf_amp_report_integer,
        { "Report-Integer", "amp.report.integer",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amp_cbor_header,
        { "CBOR-Header", "amp.cbor_header",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amp_primary_timestamp,
        { "Timestamp", "amp.primary_timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        { &hf_amp_tnvc_flags,
        { "TNVC Flags", "amp.tnvc.flags",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_amp_tnvc_reserved,
        { "Reserved", "amp.tnvc.reserved",
          FT_UINT8, BASE_DEC, NULL, AMP_TNVC_RESERVED,
          NULL, HFILL }
        },
        { &hf_amp_tnvc_mixed,
        { "Mixed", "amp.tnvc.mixed",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), AMP_TNVC_MIXED,
          NULL, HFILL }
        },
        { &hf_amp_tnvc_typed,
        { "TNVC Values are Typed", "amp.tnvc.typed",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), AMP_TNVC_TYPE,
          NULL, HFILL }
        },
        { &hf_amp_tnvc_name,
        { "Name", "amp.tnvc.name",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), AMP_TNVC_NAME,
          NULL, HFILL }
        },
        { &hf_amp_tnvc_values,
        { "Values", "amp.tnvc.value",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), AMP_TNVC_VALUE,
          NULL, HFILL }
        },
        { &hf_ari_nickname,
        { "Nickname", "amp.nickname",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_ARI_NICKNAME,
          NULL, HFILL }
        },
        { &hf_amp_ari_flags,
        { "ARI Flags", "amp.ari.flags",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_ari_parameters,
        { "Parameters", "amp.parameters",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_ARI_PARAMETERS,
          NULL, HFILL }
        },
        { &hf_ari_issuer,
        { "Issuer", "amp.issuer",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_ARI_ISSUER,
          NULL, HFILL }
        },
        { &hf_ari_tag,
        { "Tag", "amp.tag",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_ARI_TAG,
          NULL, HFILL }
        },
        { &hf_ari_value,
        { "Value", "amp.value",
          FT_UINT8, BASE_DEC, NULL, AMP_ARI_VALUE,
          NULL, HFILL }
        },
        { &hf_ari_struct,
        { "Struct Type", "amp.struct",
          FT_UINT8, BASE_DEC, VALS(amp_ari_struct_type), AMP_ARI_STRUCT,
          NULL, HFILL }
        },
        { &hf_amp_reserved,
        { "Reserved", "amp.reserved",
          FT_UINT8, BASE_DEC, NULL, AMP_HDR_RESERVED,
          NULL, HFILL }
        },
        { &hf_amp_acl,
          { "ACL", "amp.acl",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_HDR_ACL,
          NULL, HFILL }
        },
        { &hf_amp_nack,
          { "NACK", "amp.nack",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_HDR_NACK,
          NULL, HFILL }
        },
        { &hf_amp_ack,
          { "ACK", "amp.ack",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), AMP_HDR_ACK,
          NULL, HFILL }
        },
        { &hf_amp_opcode,
          { "Opcode", "amp.opcode",
          FT_UINT8, BASE_DEC, VALS(opcode), AMP_HDR_OPCODE,
          NULL, HFILL }
        },
        {&hf_amp_agent_name,
         {"Agent-Name", "amp.agent_name",
          FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_amp_text_string,
         {"String", "amp.string",
          FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_amp_rx_name,
         {"Rx-Name", "amp.rx_name",
          FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_amp,
        &ett_amp_message_header,
        &ett_amp_cbor_header,
        &ett_amp_message,
        &ett_amp_register,
        &ett_amp_report_set,
        &ett_amp_report,
        &ett_amp_tnvc_flags,
        &ett_amp_ari_flags,
        &ett_amp_proto
    };

    static ei_register_info ei[] = {
        { &ei_amp_cbor_malformed, { "amp.cbor.malformed", PI_MALFORMED, PI_ERROR, "Malformed CBOR object", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_amp = proto_register_protocol("AMP", "AMP", "amp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_amp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t* expert_amp = expert_register_protocol(proto_amp);
    expert_register_field_array(expert_amp, ei, array_length(ei));

    amp_handle = register_dissector("amp", dissect_amp, proto_amp);
}

void
proto_reg_handoff_amp(void)
{
    dissector_add_uint("ccsds.apid", AMP_APID, amp_handle);
    dissector_add_for_decode_as_with_preference("udp.port", amp_handle);
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
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
