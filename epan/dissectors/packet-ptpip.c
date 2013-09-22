/* packet-ptpip.c
 * Routines for PTP/IP (Picture Transfer Protocol) packet dissection
 * 0xBismarck 2013
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

/**
 * References:
 * [1] CIPA DC-X005-2005 - PTP-IP
 * [2] BS ISO 15740:2008 - Photography Electronic still picture imaging - Picture transfer protocol (PTP)
 * for digital still photography devices
 * [3] gPhoto's Reversed Engineered PTP/IP documentation - http://gphoto.sourceforge.net/doc/ptpip.php
 * [4] gPhoto's ptp2 header file  https://gphoto.svn.sourceforge.net/svnroot/gphoto/trunk/libgphoto2/camlibs/ptp2/ptp.h
 *
 * @todo: This is being written as 1 dissector when in reality there is PTP/IP and PTP.  Future work should include splitting this into 2
 * so that the PTP layer may be used again for PTP/USB.
 */
#include "packet-ptpip.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>


/*Define*/
#define PTPIP_PORT            15740  /*[1] Section 2.2.3.1*/
#define PTPIP_GUID_SIZE        16 /*[1] Section 2.3.1*/
#define PTPIP_MAX_PARAM_COUNT    5 /*[1] Section 2.3.6*/

/*trees*/
static gint ett_ptpIP =  -1;
static gint ett_ptpIP_hdr = -1;


/*PTP/IP Fields*/
static int proto_ptpIP = -1;
static int hf_ptpIP_len = -1; /*[1] Section 2.3*/
static int hf_ptpIP_pktType = -1; /*[1] Section 2.3*/
static int hf_ptpIP_guid = -1;
static int hf_ptpIP_name = -1;
static int hf_ptpIP_version = -1;
static int hf_ptpIP_connectionNumber = -1;
static int hf_ptpIP_dataPhaseInfo = -1;

/*note: separating the fields to make it easier to divide this code later.*/

/*PTP Fields*/
/*picking hf_ptp for now. Might need to change later for namespace issues with Precision Time Protocol.*/
static int hf_ptp_opCode = -1;
static int hf_ptp_respCode = -1;
static int hf_ptp_eventCode = -1;
static int hf_ptp_transactionID = -1;
static int hf_ptp_totalDataLength = -1;
static int hf_ptp_opCode_param_sessionID = -1;

/* function declarations */
static int dissect_ptpIP (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
void dissect_ptpIP_init_command_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_init_command_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_init_event_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_init_event_ack(packet_info *pinfo);
void dissect_ptpIP_operation_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_operation_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_start_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_end_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_unicode_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_protocol_version(tvbuff_t *tvb, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_guid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void proto_register_ptpip( void );
void proto_reg_handoff_ptpIP( void );

/*String Names of packet types [3] & [4]*/
/* PTP/IP definitions*/
 /*enums reformatted from [4]*/
typedef enum {
    PTPIP_INVALID                = 0,
    PTPIP_INIT_COMMAND_REQUEST   = 1,
    PTPIP_INIT_COMMAND_ACK       = 2,
    PTPIP_INIT_EVENT_REQUEST     = 3,
    PTPIP_INIT_EVENT_ACK         = 4,
    PTPIP_INIT_FAIL              = 5,
    PTPIP_CMD_REQUEST            = 6,  /*possibly Operation request in [1] 2.3.6 agrees with [3]*/
    PTPIP_CMD_RESPONSE           = 7,  /*possibly Operation response in [1] 2.3.7  agrees with [3]*/
    PTPIP_EVENT                  = 8,
    PTPIP_START_DATA_PACKET      = 9,
    PTPIP_DATA_PACKET            = 10,
    PTPIP_CANCEL_TRANSACTION     = 11,
    PTPIP_END_DATA_PACKET        = 12,
    PTPIP_PING                   = 13, /*possibly Probe Request in [1] 2.3.13*/
    PTPIP_PONG                   = 14  /*possibly Probe Response in [1] 2.3.14*/
} ptpip_pktType;

/*Unless otherwise stated, names are based on info in [3]*/
static const value_string ptpip_pktType_names[] = {
    { PTPIP_INIT_COMMAND_REQUEST,    "Init Command Request Packet" },
    { PTPIP_INIT_COMMAND_ACK,        "Init Command ACK Packet" },
    { PTPIP_INIT_EVENT_REQUEST,      "Init Event Request Packet" },
    { PTPIP_INIT_EVENT_ACK,          "Init Event Ack Packet"},
    { PTPIP_INIT_FAIL,               "Init Fail Packet"},
    { PTPIP_CMD_REQUEST,             "Operation Request Packet"}, /* string based on [1]*/
    { PTPIP_CMD_RESPONSE,            "Operation Response Packet"}, /*string based on [1]*/
    { PTPIP_EVENT,                   "Event Packet"},
    { PTPIP_START_DATA_PACKET,       "Start Data Packet"},
    { PTPIP_DATA_PACKET,             "Data Packet"},
    { PTPIP_CANCEL_TRANSACTION,      "Cancel Packet"},
    { PTPIP_END_DATA_PACKET,         "End Data Packet"},
    { PTPIP_PING,                    "Probe Request Packet"}, /* string based on [1]*/
    { PTPIP_PONG,                    "Probe Response Packet"}, /* string based on [1]*/
    { PTPIP_INVALID,                 "Invalid" },
    { 0,                             NULL }
};


/**
 * Primary method to dissect a PTP/IP packet. When a subtype is encounter,
 * the method will call a subdissector.
 */
static
int dissect_ptpIP (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item_ptr;
    proto_tree *ptp_tree;
    guint16 offset = 0;

    guint32 pktType;

    /* Check that there's enough data */
    if ( tvb_length_remaining(tvb, offset) < 8 )    /* ptp-photo smallest packet size is 8 */
        return (0);

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "PTP/IP");

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Picture Transfer Protocol");

    item_ptr = proto_tree_add_protocol_format(tree, proto_ptpIP, tvb, offset,
         -1, "Picture Transfer Protocol");

    /*creating the tree*/
    ptp_tree = proto_item_add_subtree(item_ptr, ett_ptpIP);
    /*[1] Defines first 2 fields as length and packet type. (Section 2.3)
     * Also note: the standard lists all multibyte values in PTP-IP as little-endian
     */

    /* note: len field size included in total len*/
    proto_tree_add_item(ptp_tree, hf_ptpIP_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    /*@todo:maybe add some length verification checks to see if len advertised matches actual len*/

    pktType = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(ptp_tree, hf_ptpIP_pktType, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    switch (pktType) {
        case PTPIP_INIT_COMMAND_REQUEST:
            dissect_ptpIP_init_command_request(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_INIT_COMMAND_ACK:
            dissect_ptpIP_init_command_ack(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_INIT_EVENT_REQUEST:
            dissect_ptpIP_init_event_request(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_INIT_EVENT_ACK:
            dissect_ptpIP_init_event_ack(pinfo);
            break;
        case PTPIP_CMD_REQUEST:
            dissect_ptpIP_operation_request(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_CMD_RESPONSE:
            dissect_ptpIP_operation_response(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_EVENT:
            dissect_ptpIP_event(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_START_DATA_PACKET:
            dissect_ptpIP_start_data(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_DATA_PACKET:
            dissect_ptpIP_data(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_END_DATA_PACKET:
            dissect_ptpIP_end_data(tvb, pinfo, ptp_tree, &offset);
            break;
        default:
            break;
    }

    return (offset);
}

/**
 * Method to dissect the Init Command Request sent by the Initiator
 * in the connection. This packet is defined by [1] Section 2.3.1
 */
void dissect_ptpIP_init_command_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    *offset+=0;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Command Request");

    dissect_ptpIP_guid(tvb, pinfo, tree, offset);

    /*grabbing the name*/
    dissect_ptpIP_unicode_name(tvb, pinfo, tree, offset);

    /*grabbing protocol version
     * Note: [3] does not list this in the packet field. . [1] 2.3.1 states its the last 4
     * bytes of the packet.
    */
    dissect_ptpIP_protocol_version(tvb, tree, offset);
    return;
}

/**
 * Method to dissect the Init Command Ack sent by the Responder
 * in the connection. This packet is defined by [1] Section 2.3.2
 */
void dissect_ptpIP_init_command_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint32 connectionNumber;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Command Ack");

    /*Grabbing the Connection Number*/
    connectionNumber = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_ptpIP_connectionNumber, tvb, *offset, 4,ENC_LITTLE_ENDIAN);
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Connection #:%u",
        connectionNumber);
    *offset+=4;

    dissect_ptpIP_guid(tvb, pinfo, tree, offset);

    /*grabbing name*/
    dissect_ptpIP_unicode_name(tvb,pinfo, tree, offset);

    /*grabbing protocol version. Note: like in the Init Command Request, [3] doesn't mention
     * this field, but [1] Section 2.3.2 does.
     */
    dissect_ptpIP_protocol_version(tvb, tree, offset);
}

/**
 * Dissects the Init Event Request packet specified in [1] Section 2.3.3.
 * Standard states that the packet only has 1 field.
 */
void dissect_ptpIP_init_event_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint32 connectionNumber;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Event Request");

    /*Grabbing the Connection Number*/
    connectionNumber = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_ptpIP_connectionNumber, tvb, *offset, 4,ENC_LITTLE_ENDIAN);
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Connection #:%u",
        connectionNumber);
    *offset+=4;
}

/**
 * Dissects the Init Event Ack packet specified in [1] Section 2.3.4
 */
void dissect_ptpIP_init_event_ack(packet_info *pinfo)
{
    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Event Ack");

    /*packet has no payload.*/
}

/**
 * Dissects the Operation Request Packet specified in [1] Section 2.3.6
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_operation_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint16 opcode=0;
    guint16 transactionID_offset = *offset; /*need to save this to output transaction id in pinfo*/

    col_add_str(
        pinfo->cinfo,
        COL_INFO,
        "Operation Request Packet ");

    proto_tree_add_item(tree,hf_ptpIP_dataPhaseInfo, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset+= 4;

    opcode = tvb_get_letohs(tvb, *offset);
    proto_tree_add_item(tree, hf_ptp_opCode, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset+= 2;

    transactionID_offset = *offset; /*we'll dissect the transactionID later because opcode handling erases the column*/
    *offset+= 4;

    /*carving out the parameters. [1] 2.3.6 states there can be at most 5. Params are defined in [2] 10.1 & 10.4*/
    switch (opcode)
    {
        case PTP_OC_GetDeviceInfo:
            /*[1] 10.5.1*/
            col_set_str(
                pinfo->cinfo,
                COL_INFO,
                "GetDeviceInfo");
            /*No parameters*/
            break;
        case PTP_OC_OpenSession:
            dissect_ptp_opCode_openSession(tvb, pinfo, tree, offset);
            break;
        case PTP_OC_CloseSession:
            /*[1] 10.5.3*/
            col_set_str(
                pinfo->cinfo,
                COL_INFO,
                "CloseSession");
            /*No parameters*/
            break;
        case PTP_OC_GetStorageIDs:
            /*[2]  10.5.4*/
            col_set_str(
                pinfo->cinfo,
                COL_INFO,
                "GetStorageIDs");
            /*states data is a storage array. Needs eventual investigation.*/
            break;
        default:
            break;
    }
    dissect_ptp_transactionID(tvb, pinfo, tree, &transactionID_offset);
}

/**
 * Dissects the Operation Response Packet specified in [1] Section 2.3.7
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_operation_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    col_add_str(
        pinfo->cinfo,
        COL_INFO,
        "Operation Response Packet ");

    proto_tree_add_item(tree, hf_ptp_respCode, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset+= 2;

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);

}

/**
 * Dissects the Event Packet specified in [1] Section 2.3.8
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    col_add_str(
        pinfo->cinfo,
        COL_INFO,
        "Event Packet ");

    proto_tree_add_item(tree, hf_ptp_eventCode, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset+= 2;

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);
}

/**
 * Dissects the Event Packet specified in [1] Section 2.3.9
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_start_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint64 dataLen=0;

    col_add_str(
        pinfo->cinfo,
        COL_INFO,
        "Start Data Packet ");

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);


    dataLen = tvb_get_letoh64(tvb, *offset);
    proto_tree_add_item(tree, hf_ptp_totalDataLength, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset+= 8;
    if(dataLen == G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) /*[1] specifies in 2.3.9 if total data len this value then len unknown*/
    {
        col_append_str(
            pinfo->cinfo,
            COL_INFO,
            " Data Length Unknown");
    }
}

void dissect_ptpIP_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{

    col_add_str(
        pinfo->cinfo,
        COL_INFO,
        "Data Packet ");

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);

}

/**
 * Dissects the End Data specified in [1] Section 2.3.11
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_end_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{

    col_add_str(
        pinfo->cinfo,
        COL_INFO,
        "End Data Packet ");

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);
}

/**
 * Dissects the Opcode Open Session as defined by [2] 10.5.2
 */
void dissect_ptp_opCode_openSession(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "OpenSession");

    proto_tree_add_item(tree, hf_ptp_opCode_param_sessionID, tvb, *offset, 4 , ENC_LITTLE_ENDIAN);
    *offset+= 4;
}

/**
 * The transaction ID is defined  in [2]  9.3.1
 * and used in multiple message types. This method handles
 * parsing the field and adding the value to the info
 * column.
 *
 */
void dissect_ptp_transactionID(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint32 transactionID;

    transactionID = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_ptp_transactionID, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset+= 4;
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Transaction ID: %d",
        transactionID);
}

/**
 * This method handles dissecting the Unicode name that is
 * specificed in multiple packets.
 */
void dissect_ptpIP_unicode_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint8 *name;
    gint nameLen;

    nameLen = tvb_unicode_strsize(tvb, *offset);
    name = tvb_get_unicode_string(wmem_packet_scope(), tvb, *offset, nameLen, ENC_LITTLE_ENDIAN);
    proto_tree_add_unicode_string(tree, hf_ptpIP_name, tvb, *offset, nameLen, name);
    *offset+=nameLen;
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Name: %s",
        name);
}

/** Method dissects the protocol version from the packets.
 * Additional note, section 3 of [1] defines the Binary Protocol version
 * as 0x00010000 == 1.0 where the Most significant bits are the major version and the least
 * significant bits are the minor version.
 */
void dissect_ptpIP_protocol_version(tvbuff_t *tvb, proto_tree *tree, guint16 *offset)
{

    guint8 version[30];
    guint32 protoVersion;
    guint16 majorVersion, minorVersion;

    protoVersion = tvb_get_letohl(tvb, *offset);
    /*logic to format version*/
    minorVersion = protoVersion & 0xFFFF;
    majorVersion = (protoVersion & 0xFFFF0000) >>16;
    g_snprintf(version, 30, "%u.%u", majorVersion, minorVersion);
    proto_tree_add_string(tree, hf_ptpIP_version, tvb, *offset, 4, version);
    *offset += 4;
}

/*Grabbing the GUID*/
void dissect_ptpIP_guid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint8 *guid;

    guid = tvb_bytes_to_str(tvb, *offset, PTPIP_GUID_SIZE);
    proto_tree_add_item(tree, hf_ptpIP_guid, tvb, *offset, PTPIP_GUID_SIZE, ENC_NA);
    *offset += PTPIP_GUID_SIZE;
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " GUID: %s",
        guid);
}

void proto_register_ptpip( void )
{
    static hf_register_info hf[] = {
        /*PTP/IP layer*/
        { &hf_ptpIP_len, {
            "Length", "ptpip.len", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_pktType, {
            "Packet Type", "ptpip.pktType", FT_UINT32, BASE_HEX,
            VALS(ptpip_pktType_names), 0, NULL, HFILL }},
        { &hf_ptpIP_guid, {
            "GUID", "ptpip.guid", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_name, {
            "Host Name", "ptpip.name", FT_STRINGZ, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_version, {
            "Version", "ptpip.version", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_connectionNumber, {
            "Connection Number", "ptpip.connection", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_dataPhaseInfo, {
            "Data Phase Info", "ptpip.phaseinfo", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        /*PTP layer*/
             /*leaving names with "ptpip" to try and prevent namespace issues. probably changing later.*/
        { &hf_ptp_opCode, {
            "Operation Code", "ptpip.opcode", FT_UINT16, BASE_HEX,
            VALS(ptp_opcode_names), 0, NULL, HFILL }},
        { &hf_ptp_respCode, {
            "Response Code", "ptpip.respcode", FT_UINT16, BASE_HEX,
            VALS(ptp_respcode_names), 0, NULL, HFILL }},
        { &hf_ptp_eventCode, {
            "Event Code", "ptpip.eventcode", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_ptp_transactionID, {
            "Transaction ID", "ptpip.transactionID", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_ptp_totalDataLength, {
            "Total Data Length", "ptpip.datalen", FT_UINT64, BASE_DEC_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_ptp_opCode_param_sessionID, {
            "Session ID", "ptpip.opcode.param.sessionid", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},

    };
    static gint *ett[] = {
        &ett_ptpIP,
        &ett_ptpIP_hdr
    };

    proto_ptpIP = proto_register_protocol("Picture Transfer Protocol Over IP", "PTP/IP", "ptpip");

    proto_register_field_array(proto_ptpIP, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ptpIP( void ) {

    dissector_handle_t ptpIP_handle;

    /*  Use new_create_dissector_handle() to indicate that dissect_wol()
    *  returns the number of bytes it dissected (or 0 if it thinks the packet
    *  does not belong to PROTONAME).
    */

    ptpIP_handle = new_create_dissector_handle(dissect_ptpIP, proto_ptpIP);
    dissector_add_uint("tcp.port", PTPIP_PORT, ptpIP_handle);
}
