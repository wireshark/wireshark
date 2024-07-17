/* packet-hsms.c
 * Routines for High-speed SECS message service dissection
 * Copyright 2016, Benjamin Parzella <bparzella@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 *  HSMS - High-speed SECS message service (SEMI-E37)
 *  SECS - SEMI equipment communications standard (SEMI-E5)
 *
 *  TCP based protocol for semiconductor factory automation
 *  defined by SEMI (http://www.semi.org)
 *
 *  Usual TCP port: 5000
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"
#include <epan/expert.h>

#define PTYPE_SECS      0

#define STYPE_SECS_DATA         0
#define STYPE_SELECT_REQ        1
#define STYPE_SELECT_RSP        2
#define STYPE_DESELECT_REQ      3
#define STYPE_DESELECT_RSP      4
#define STYPE_LINKTEST_REQ      5
#define STYPE_LINKTEST_RSP      6
#define STYPE_REJECT_REQ        7
#define STYPE_SEPARATE_REQ      9

#define FORMAT_CODE_LIST    000
#define FORMAT_CODE_BINARY  010
#define FORMAT_CODE_BOOLEAN 011
#define FORMAT_CODE_ASCII   020
#define FORMAT_CODE_JIS8    021
#define FORMAT_CODE_2BYTE   022
#define FORMAT_CODE_I8      030
#define FORMAT_CODE_I1      031
#define FORMAT_CODE_I2      032
#define FORMAT_CODE_I4      034
#define FORMAT_CODE_F8      040
#define FORMAT_CODE_F4      044
#define FORMAT_CODE_U8      050
#define FORMAT_CODE_U1      051
#define FORMAT_CODE_U2      052
#define FORMAT_CODE_U4      054

/* Prototypes */
void proto_reg_handoff_hsms(void);
void proto_register_hsms(void);

static dissector_handle_t hsms_handle;

/* Initialize the protocol and registered fields */
static int proto_hsms;

static int hf_hsms_packet_length;
static int hf_hsms_header_sessionid;
static int hf_hsms_header_statusbyte2;
static int hf_hsms_header_wbit;
static int hf_hsms_header_stream;
static int hf_hsms_header_statusbyte3;
static int hf_hsms_header_function;
static int hf_hsms_header_ptype;
static int hf_hsms_header_stype;
static int hf_hsms_header_system;
static int hf_hsms_data_item_format;
static int hf_hsms_data_item_length_bytes;
static int hf_hsms_data_item_length;
static int hf_hsms_data_item_value_binary;
static int hf_hsms_data_item_value_boolean;
static int hf_hsms_data_item_value_string;
static int hf_hsms_data_item_value_i8;
static int hf_hsms_data_item_value_i1;
static int hf_hsms_data_item_value_i2;
static int hf_hsms_data_item_value_i4;
static int hf_hsms_data_item_value_f8;
static int hf_hsms_data_item_value_f4;
static int hf_hsms_data_item_value_u8;
static int hf_hsms_data_item_value_u1;
static int hf_hsms_data_item_value_u2;
static int hf_hsms_data_item_value_u4;

static expert_field ei_hsms_ptype;

static wmem_map_t *value_lengths;

/*
 *  Presentation type (ptype)
 *
 *  0        =>  SECS-II Encoding
 *  1-127    =>  Reserved for subsidiary standards
 *  128-255  =>  Reserved, not used
 */
static const value_string ptype_names[] = {
    { PTYPE_SECS, "SECS" },
    { 0, NULL }
};

/*
 *  Session type (stype)
 *
 *  0        =>  SECS-II data message
 *  1        =>  Select request
 *  2        =>  Select response
 *  3        =>  Deselect request
 *  4        =>  Deselect response
 *  5        =>  Link test request
 *  6        =>  Link test response
 *  7        =>  Packet reject request
 *  8        =>  Reserved, not used
 *  9        =>  Separate request
 *  10       =>  Reserved, not used
 *  11-127   =>  Reserved for subsidiary standards
 *  128-255  =>  Reserved, not used
 */
static const value_string stype_names[] = {
    { STYPE_SECS_DATA, "Data message" },
    { STYPE_SELECT_REQ, "Select.req" },
    { STYPE_SELECT_RSP, "Select.rsp" },
    { STYPE_DESELECT_REQ, "Deselect.req" },
    { STYPE_DESELECT_RSP, "Deselect.rsp" },
    { STYPE_LINKTEST_REQ, "Linktest.req" },
    { STYPE_LINKTEST_RSP, "Linktest.rsp" },
    { STYPE_REJECT_REQ, "Reject.req" },
    { STYPE_SEPARATE_REQ, "Separate.req" },
    { 0, NULL }
};

static const value_string item_format_names[] = {
    { FORMAT_CODE_LIST, "List" },
    { FORMAT_CODE_BINARY, "Binary" },
    { FORMAT_CODE_BOOLEAN, "Boolean" },
    { FORMAT_CODE_ASCII, "ASCII" },
    { FORMAT_CODE_JIS8, "JIS-8" },
    { FORMAT_CODE_2BYTE, "2-Byte Char" },
    { FORMAT_CODE_I8, "I8" },
    { FORMAT_CODE_I1, "I1" },
    { FORMAT_CODE_I2, "I2" },
    { FORMAT_CODE_I4, "I4" },
    { FORMAT_CODE_F8, "F8" },
    { FORMAT_CODE_F4, "F4" },
    { FORMAT_CODE_U8, "U8" },
    { FORMAT_CODE_U1, "U1" },
    { FORMAT_CODE_U2, "U2" },
    { FORMAT_CODE_U4, "U4" },
    { 0, NULL }
};

/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define HSMS_TCP_PORT 0

/* Initialize the subtree pointers */
static int ett_hsms;
static int ett_hsms_header;
static int ett_hsms_data;
static int ett_hsms_data_item;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define HSMS_MIN_LENGTH 14

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_secs_variable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, int *offset)
{
    proto_item *hdr_stream_item;
    proto_tree *hsms_data_item_tree, *hsms_data_item_header_tree;

    proto_item *hdr_item = NULL;

    unsigned item_format_code = -1;
    unsigned length_bytes = -1;
    unsigned length = 0;

    unsigned *value_length = NULL;

    int len = 0;
    int itemLength = 0;

    /* extract item format code and number of length bytes from byte #1 */
    item_format_code = (tvb_get_uint8(tvb, *offset) & 0xFC) >> 2;
    length_bytes = (tvb_get_uint8(tvb, *offset) & 0x3);

    /* extract item length in bytes */
    switch (length_bytes)
    {
    case 3:
        length = tvb_get_ntoh24(tvb, *offset + 1);
        break;
    case 2:
        length = tvb_get_ntohs(tvb, *offset + 1);
        break;
    case 1:
        length = tvb_get_uint8(tvb, *offset + 1);
        break;
    default:
        return -1;
    }

    /* list has no item length and length is alreaty the count of items */
    if (item_format_code != 0)
    {
        value_length = (unsigned*)wmem_map_lookup(value_lengths, GUINT_TO_POINTER(item_format_code));

        /* length must be dividable by item length, because it must be a multiple of items */
        if (length % GPOINTER_TO_UINT(value_length) != 0)
            return -1;

        /* shorten length to actual count of items */
        length = length / GPOINTER_TO_UINT(value_length);
    }

    /* add the item tree to the parent tree */
    hsms_data_item_tree = proto_tree_add_subtree_format(tree, tvb, *offset, -1, ett_hsms_data_item, &hdr_item, "%s (%d items)", val_to_str(item_format_code, item_format_names, "Unknown (%02o)"), length);

    /* add the formatcode/length bytes to the item tree */
    hsms_data_item_header_tree = proto_tree_add_subtree_format(hsms_data_item_tree, tvb, *offset, 1, ett_hsms_header, &hdr_stream_item, "Data format: %s, Length bytes: %d", val_to_str(item_format_code, item_format_names, "Unknown (%02o)"), length_bytes);
    proto_tree_add_item(hsms_data_item_header_tree, hf_hsms_data_item_format, tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hsms_data_item_header_tree, hf_hsms_data_item_length_bytes, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;

    /* add the length to the item tree */
    len = length_bytes;
    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_length, tvb, *offset, len, ENC_BIG_ENDIAN);
    *offset += len;

    /* add the actual item to the item tree */
    switch(item_format_code)
    {
    case FORMAT_CODE_BINARY:
        /* add binary value as one to item list */
        value_length = (unsigned*)wmem_map_lookup(value_lengths, GUINT_TO_POINTER(item_format_code));

        len = GPOINTER_TO_UINT(value_length) * length;
        proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_binary, tvb, *offset, len, ENC_NA);
        itemLength = len;
        *offset += len;
        break;
    case FORMAT_CODE_ASCII:
        /* add ascii value as one to item list */
        value_length = (unsigned*)wmem_map_lookup(value_lengths, GUINT_TO_POINTER(item_format_code));

        len = GPOINTER_TO_UINT(value_length) * length;
        proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_string, tvb, *offset, len, ENC_ASCII);
        itemLength = len;
        *offset += len;
        break;
    default:
        /* walk through the items */
        for(unsigned int counter=0; counter<length; counter++)
        {
            if (item_format_code == 0)
            {
                /* add sub items for list element to item tree */
                increment_dissection_depth(pinfo);
                int subItemLength = dissect_secs_variable(tvb, pinfo, hsms_data_item_tree, data, offset);
                decrement_dissection_depth(pinfo);

                /* check for parsing error in sub list */
                if (subItemLength == -1)
                {
                    return -1;
                }

                itemLength += subItemLength;
            }
            else
            {
                /* add single item of type item tree */
                value_length = (unsigned*)wmem_map_lookup(value_lengths, GUINT_TO_POINTER(item_format_code));

                len = GPOINTER_TO_UINT(value_length);
                switch(item_format_code)
                {
                case FORMAT_CODE_BOOLEAN:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_boolean, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_I8:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_i8, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_I1:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_i1, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_I2:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_i2, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_I4:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_i4, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_F8:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_f8, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_F4:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_f4, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_U8:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_u8, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_U1:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_u1, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_U2:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_u2, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                case FORMAT_CODE_U4:
                    proto_tree_add_item(hsms_data_item_tree, hf_hsms_data_item_value_u4, tvb, *offset, len, ENC_BIG_ENDIAN);
                    break;
                default:
                    return -1;
                }
                itemLength += len;
                *offset += len;
            }
        }
    }

    /* update length of item tree */
    proto_item_set_len(hsms_data_item_tree, itemLength + length_bytes + 1);

    return 1 + length_bytes + itemLength;
}

static int
dissect_secs_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, int *offset)
{
    return dissect_secs_variable(tvb, pinfo, tree, data, offset);
}

/* Code to actually dissect the hsms packets */
static int
dissect_hsms_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *hdr_item = NULL;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *hsms_tree, *hsms_header_tree, *hsms_header_stream_tree;

    /* Other misc. local variables. */
    unsigned    offset = 0;

    unsigned sessionId = -1;
    unsigned byte2 = -1;
    unsigned byte3 = -1;
    unsigned pType = -1;
    unsigned sType = -1;

    /*** HEURISTICS ***/

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < HSMS_MIN_LENGTH)
        return 0;

    /* Check if first byte describes length) */
    if ((tvb_get_ntohl(tvb, 0) + 4) != tvb_reported_length(tvb))
        return 0;

    sessionId = tvb_get_ntohs(tvb, 4);
    byte2 = tvb_get_uint8(tvb, 6);
    byte3 = tvb_get_uint8(tvb, 7);
    pType = tvb_get_uint8(tvb, 8);
    sType = tvb_get_uint8(tvb, 9);

    /* sTypes 8, 10 and 128+ are unused, 11-127 might be used for subsidiary standards */
    if ((sType == 8) || (sType == 10) || (sType > 127))
        return 0;

    /* see definition of stype_names for details on the sType values */
    switch (sType)
    {
    case STYPE_SECS_DATA:
        if (byte2 == 0) // stream must be set
            return 0;
        break;
    case STYPE_SELECT_REQ:
    case STYPE_DESELECT_REQ:
    case STYPE_SEPARATE_REQ:
        if ((byte2 != 0) || (byte3 != 0)) // byte2&3 must be zero
            return 0;
        if (tvb_reported_length(tvb) > HSMS_MIN_LENGTH) // no data for sType != 0
            return 0;
        break;
    case STYPE_SELECT_RSP:
    case STYPE_DESELECT_RSP:
        if (byte2 != 0) // byte2 must be zero
            return 0;
        if (tvb_reported_length(tvb) > HSMS_MIN_LENGTH) // no data for sType != 0
            return 0;
        break;
    case STYPE_LINKTEST_REQ:
    case STYPE_LINKTEST_RSP:
        if (sessionId != 0xFFFF) // Session ID must be max
            return 0;
        if (byte2 != 0) // byte2 must be zero
            return 0;
        if (byte3 != 0) // byte3 must be zero
            return 0;
        if (tvb_reported_length(tvb) > HSMS_MIN_LENGTH) // no data for sType != 0
            return 0;
        break;
    case STYPE_REJECT_REQ:
        if (tvb_reported_length(tvb) > HSMS_MIN_LENGTH) // no data for sType != 0
            return 0;
        break;
    }

    /*** COLUMN DATA ***/

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSMS");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    if (sType == STYPE_SECS_DATA)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "HSMS SECS Stream/Function S%02dF%02d",
                byte2 & 0x7F, byte3);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "HSMS Message %s",
                val_to_str(sType, stype_names, "Unknown (%02d)"));
    }


    /*** PROTOCOL TREE ***/

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_hsms, tvb, 0, -1, ENC_NA);

    hsms_tree = proto_item_add_subtree(ti, ett_hsms);

    /* packet size = 4 bytes */
    proto_tree_add_item(hsms_tree, hf_hsms_packet_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* header = 10 bytes */

    /* see definition of stype_names for details on the sType values */
    switch (sType)
    {
    case STYPE_SECS_DATA:
        hsms_header_tree = proto_tree_add_subtree_format(hsms_tree, tvb, offset, 10, ett_hsms_header, &hdr_item, "Header (S%02dF%02d)", byte2 & 0x7F, byte3);
        break;
    default:
        hsms_header_tree = proto_tree_add_subtree_format(hsms_tree, tvb, offset, 10, ett_hsms_header, &hdr_item, "Header (%s)", val_to_str(sType, stype_names, "Unknown (%02d)"));
        break;
    }

    /* session id = 2 bytes */
    proto_tree_add_item(hsms_header_tree, hf_hsms_header_sessionid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* see definition of stype_names for details on the sType values */
    switch (sType)
    {
    case STYPE_SECS_DATA:
        /* wbit=1bit + stream=7bits = 1 byte */
        hsms_header_stream_tree = proto_tree_add_subtree_format(hsms_header_tree, tvb, offset, 1, ett_hsms_header, &hdr_item, "Stream %d, Response requested: %s", byte2 & 0x7F, ((byte2 & 0x80) > 0) ? "Yes" : "No");
        proto_tree_add_item(hsms_header_stream_tree, hf_hsms_header_wbit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(hsms_header_stream_tree, hf_hsms_header_stream, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* function = 1 byte */
        proto_tree_add_item(hsms_header_tree, hf_hsms_header_function, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    default:
        /* status byte 2 = 1 byte */
        proto_tree_add_item(hsms_header_tree, hf_hsms_header_statusbyte2, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* status byte 3 = 1 byte */
        proto_tree_add_item(hsms_header_tree, hf_hsms_header_statusbyte3, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    }

    /* ptype = 1 byte */
    ti = proto_tree_add_item(hsms_header_tree, hf_hsms_header_ptype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (pType != 0)
        expert_add_info(pinfo, ti, &ei_hsms_ptype);

    /* stype = 1 byte */
    proto_tree_add_item(hsms_header_tree, hf_hsms_header_stype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* system = 4 bytes */
    proto_tree_add_item(hsms_header_tree, hf_hsms_header_system, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* decode secs data if available */
    if (tvb_reported_length(tvb) > HSMS_MIN_LENGTH)
    {
        if (pType == PTYPE_SECS)
            dissect_secs_message(tvb, pinfo, hsms_tree, data, &offset);
    }
    return offset;
}

/* determine PDU length of protocol foo */
static unsigned
get_hsms_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* first four bytes are length information */
    return (unsigned)tvb_get_ntohl(tvb, offset) + 4;
}

/* The main dissecting routine */
static int
dissect_hsms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 4,
                     get_hsms_message_len, dissect_hsms_message, data);
    return tvb_captured_length(tvb);
}

static void
hsms_init(void)
{
    value_lengths = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_LIST), GINT_TO_POINTER(0));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_BINARY), GINT_TO_POINTER(1));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_BOOLEAN), GINT_TO_POINTER(1));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_ASCII), GINT_TO_POINTER(1));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_JIS8), GINT_TO_POINTER(2));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_2BYTE), GINT_TO_POINTER(2));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_I8), GINT_TO_POINTER(8));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_I1), GINT_TO_POINTER(1));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_I2), GINT_TO_POINTER(2));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_I4), GINT_TO_POINTER(4));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_F8), GINT_TO_POINTER(8));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_F4), GINT_TO_POINTER(4));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_U8), GINT_TO_POINTER(8));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_U1), GINT_TO_POINTER(1));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_U2), GINT_TO_POINTER(2));
    wmem_map_insert(value_lengths, GINT_TO_POINTER(FORMAT_CODE_U4), GINT_TO_POINTER(4));
}

void
proto_register_hsms(void)
{
    expert_module_t* expert_hsms;

    static hf_register_info hf[] = {
        { &hf_hsms_packet_length,
            { "Packet length", "hsms.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_sessionid,
            { "Session ID", "hsms.header.sessionid",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_statusbyte2,
            { "Status byte 2", "hsms.header.statusbyte2",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_wbit,
            { "W-bit (Response required)", "hsms.header.wbit",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_hsms_header_stream,
            { "Stream", "hsms.header.stream",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_hsms_header_statusbyte3,
            { "Status byte 3", "hsms.header.statusbyte3",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_function,
            { "Function", "hsms.header.function",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_ptype,
            { "PType (Presentation type)", "hsms.header.ptype",
            FT_UINT8, BASE_DEC,
            VALS(ptype_names), 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_stype,
            { "SType (Session type)", "hsms.header.stype",
            FT_UINT8, BASE_DEC,
            VALS(stype_names), 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_header_system,
            { "System Bytes", "hsms.header.system",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_format,
            { "Data type", "hsms.data.item.format",
            FT_UINT8, BASE_OCT,
            VALS(item_format_names), 0xFC,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_length_bytes,
            { "Length bytes", "hsms.data.item.length_bytes",
            FT_UINT8, BASE_OCT,
            NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_length,
            { "Length", "hsms.data.item.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_binary,
            { "Value", "hsms.data.item.value.binary",
            FT_BYTES, SEP_COLON,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_boolean,
            { "Value", "hsms.data.item.value.boolean",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_string,
            { "Value", "hsms.data.item.value.string",
            FT_STRING, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_i8,
            { "Value", "hsms.data.item.value.int64",
            FT_INT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_i1,
            { "Value", "hsms.data.item.value.int8",
            FT_INT8, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_i2,
            { "Value", "hsms.data.item.value.int16",
            FT_INT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_i4,
            { "Value", "hsms.data.item.value.int32",
            FT_INT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_f8,
            { "Value", "hsms.data.item.value.double",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_f4,
            { "Value", "hsms.data.item.value.float",
            FT_FLOAT, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_u8,
            { "Value", "hsms.data.item.value.uint64",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_u1,
            { "Value", "hsms.data.item.value.uint8",
            FT_UINT8, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_u2,
            { "Value", "hsms.data.item.value.uint16",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsms_data_item_value_u4,
            { "Value", "hsms.data.item.value.uint32",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_hsms,
        &ett_hsms_header,
        &ett_hsms_data,
        &ett_hsms_data_item
    };

    static ei_register_info ei[] = {
        { &ei_hsms_ptype,
            { "hsms.header.ptype.unknown",
            PI_RESPONSE_CODE,
            PI_NOTE,
            "Unknown presentation type (ptype)",
            EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_hsms = proto_register_protocol ("High-speed SECS Message Service Protocol", "HSMS", "hsms");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_hsms, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_hsms = expert_register_protocol(proto_hsms);
    expert_register_field_array(expert_hsms, ei, array_length(ei));

    hsms_handle = register_dissector("hsms", dissect_hsms, proto_hsms);

    hsms_init();
}

void
proto_reg_handoff_hsms(void)
{
    dissector_add_for_decode_as_with_preference("tcp.port", hsms_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
