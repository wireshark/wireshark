/******************************************************************************
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Protocol Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-tcp.h>
#include "opcua_transport_layer.h"
#include "opcua_security_layer.h"
#include "opcua_application_layer.h"
#include "opcua_complextypeparser.h"
#include "opcua_serviceparser.h"
#include "opcua_enumparser.h"
#include "opcua_simpletypes.h"
#include "opcua_hfindeces.h"

void proto_register_opcua(void);

extern const value_string g_requesttypes[];
extern const int g_NumServices;

/* forward reference */
void proto_reg_handoff_opcua(void);
/* declare parse function pointer */
typedef int (*FctParse)(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);

static int proto_opcua = -1;
static dissector_handle_t opcua_handle;
static range_t *global_tcp_ports_opcua;
/** Official IANA registered port for OPC UA Binary Protocol. */
#define OPCUA_PORT 4840

/** subtree types used in opcua_transport_layer.c */
gint ett_opcua_extensionobject = -1;
gint ett_opcua_nodeid = -1;

/** subtree types used locally */
static gint ett_opcua_transport = -1;
static gint ett_opcua_fragment = -1;
static gint ett_opcua_fragments = -1;

static int hf_opcua_fragments = -1;
static int hf_opcua_fragment = -1;
static int hf_opcua_fragment_overlap = -1;
static int hf_opcua_fragment_overlap_conflicts = -1;
static int hf_opcua_fragment_multiple_tails = -1;
static int hf_opcua_fragment_too_long_fragment = -1;
static int hf_opcua_fragment_error = -1;
static int hf_opcua_fragment_count = -1;
static int hf_opcua_reassembled_in = -1;
static int hf_opcua_reassembled_length = -1;

static const fragment_items opcua_frag_items = {
    /* Fragment subtrees */
    &ett_opcua_fragment,
    &ett_opcua_fragments,
    /* Fragment fields */
    &hf_opcua_fragments,
    &hf_opcua_fragment,
    &hf_opcua_fragment_overlap,
    &hf_opcua_fragment_overlap_conflicts,
    &hf_opcua_fragment_multiple_tails,
    &hf_opcua_fragment_too_long_fragment,
    &hf_opcua_fragment_error,
    &hf_opcua_fragment_count,
    /* Reassembled in field */
    &hf_opcua_reassembled_in,
    /* Reassembled length field */
    &hf_opcua_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};


static reassembly_table opcua_reassembly_table;

/** OpcUa Transport Message Types */
enum MessageType
{
    MSG_HELLO = 0,
    MSG_ACKNOWLEDGE,
    MSG_ERROR,
    MSG_MESSAGE,
    MSG_OPENSECURECHANNEL,
    MSG_CLOSESECURECHANNEL,
    MSG_INVALID
};

/** OpcUa Transport Message Type Names */
static const char* g_szMessageTypes[] =
{
    "Hello message",
    "Acknowledge message",
    "Error message",
    "UA Secure Conversation Message",
    "OpenSecureChannel message",
    "CloseSecureChannel message",
    "Invalid message"
};




/** header length that is needed to compute
  * the pdu length.
  * @see get_opcua_message_len
  */
#define FRAME_HEADER_LEN 8

/** returns the length of an OpcUa message.
  * This function reads the length information from
  * the transport header.
  */
static guint get_opcua_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                   int offset, void *data _U_)
{
    gint32 plen;

    /* the message length starts at offset 4 */
    plen = tvb_get_letohl(tvb, offset + 4);

    return plen;
}

/** The OpcUa message dissector.
  * This method dissects full OpcUa messages.
  * It gets only called with reassembled data
  * from tcp_dissect_pdus.
  */
static int dissect_opcua_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    FctParse pfctParse = NULL;
    enum MessageType msgtype = MSG_INVALID;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpcUa");

    /* parse message type */
    if (tvb_memeql(tvb, 0, "HEL", 3) == 0)
    {
        msgtype = MSG_HELLO;
        pfctParse = parseHello;
    }
    else if (tvb_memeql(tvb, 0, "ACK", 3) == 0)
    {
        msgtype = MSG_ACKNOWLEDGE;
        pfctParse = parseAcknowledge;
    }
    else if (tvb_memeql(tvb, 0, "ERR", 3) == 0)
    {
        msgtype = MSG_ERROR;
        pfctParse = parseError;
    }
    else if (tvb_memeql(tvb, 0, "MSG", 3) == 0)
    {
        msgtype = MSG_MESSAGE;
        pfctParse = parseMessage;
    }
    else if (tvb_memeql(tvb, 0, "OPN", 3) == 0)
    {
        msgtype = MSG_OPENSECURECHANNEL;
        pfctParse = parseOpenSecureChannel;
    }
    else if (tvb_memeql(tvb, 0, "CLO", 3) == 0)
    {
        msgtype = MSG_CLOSESECURECHANNEL;
        pfctParse = parseCloseSecureChannel;
    }
    else
    {
        msgtype = MSG_INVALID;
    }

    /* Clear out stuff in the info column */
    col_set_str(pinfo->cinfo, COL_INFO, g_szMessageTypes[msgtype]);

    if (pfctParse)
    {
        gint offset = 0;
        int iServiceId = -1;
        tvbuff_t *next_tvb = tvb;
        gboolean bParseService = TRUE;
        gboolean bIsLastFragment = FALSE;

        /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *transport_tree = NULL;

        ti = proto_tree_add_item(tree, proto_opcua, tvb, 0, -1, ENC_NA);
        transport_tree = proto_item_add_subtree(ti, ett_opcua_transport);

        /* MSG_MESSAGE might be fragmented, check for that */
        if (msgtype == MSG_MESSAGE)
        {
            guint8 chunkType = 0;
            guint32 opcua_seqid = 0;
            guint32 opcua_num = 0;
            guint32 opcua_seqnum = 0;
            fragment_head *frag_msg = NULL;

            offset = 3;

            chunkType = tvb_get_guint8(tvb, offset); offset += 1;

            offset += 4; /* Message Size */
            offset += 4; /* SecureChannelId */
            offset += 4; /* Security Token Id */

            opcua_num = tvb_get_letohl(tvb, offset); offset += 4; /* Security Sequence Number */
            opcua_seqid = tvb_get_letohl(tvb, offset); offset += 4; /* Security RequestId */

            if (chunkType == 'A')
            {
                fragment_delete(&opcua_reassembly_table, pinfo, opcua_seqid, NULL);

                col_clear_fence(pinfo->cinfo, COL_INFO);
                col_set_str(pinfo->cinfo, COL_INFO, "Abort message");

                offset = 0;
                (*pfctParse)(transport_tree, tvb, pinfo, &offset);
                parseAbort(transport_tree, tvb, pinfo, &offset);

                return tvb_reported_length(tvb);
            }

            /* check if tvb is part of a chunked message:
               the UA protocol does not tell us that, so we look into
               opcua_reassembly_table if the opcua_seqid belongs to a
               chunked message */
            frag_msg = fragment_get(&opcua_reassembly_table, pinfo, opcua_seqid, NULL);
            if (frag_msg == NULL)
            {
                frag_msg = fragment_get_reassembled_id(&opcua_reassembly_table, pinfo, opcua_seqid);
            }

            if (frag_msg != NULL || chunkType != 'F')
            {
                gboolean bSaveFragmented = pinfo->fragmented;
                gboolean bMoreFragments = TRUE;
                tvbuff_t *new_tvb = NULL;

                pinfo->fragmented = TRUE;

                if (frag_msg == NULL)
                {
                    /* first fragment */
                    opcua_seqnum = 0;
                }
                else
                {
                    /* the UA protocol does not number the chunks beginning from 0 but from a
                       arbitrary value, so we have to fake the numbers in the stored fragments.
                       this way Wireshark reassembles the message, as it expects the fragment
                       sequence numbers to start at 0 */
                    while (frag_msg->next) {frag_msg = frag_msg->next;}
                    opcua_seqnum = frag_msg->offset + 1;

                    if (chunkType == 'F')
                    {
                        bMoreFragments = FALSE;
                    }
                }

                frag_msg = fragment_add_seq_check(&opcua_reassembly_table,
                                                  tvb,
                                                  offset,
                                                  pinfo,
                                                  opcua_seqid, /* ID for fragments belonging together */
                                                  NULL,
                                                  opcua_seqnum, /* fragment sequence number */
                                                  tvb_captured_length_remaining(tvb, offset), /* fragment length - to the end */
                                                  bMoreFragments); /* More fragments? */

                new_tvb = process_reassembled_data(tvb,
                                                   offset,
                                                   pinfo,
                                                   "Reassembled Message",
                                                   frag_msg,
                                                   &opcua_frag_items,
                                                   NULL,
                                                   transport_tree);

                if (new_tvb)
                {
                    /* Reassembled */
                    bIsLastFragment = TRUE;
                }
                else
                {
                    /* Not last packet of reassembled UA message */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u)", opcua_num);
                }

                if (new_tvb)
                {
                    /* take it all */
                    next_tvb = new_tvb;
                }
                else
                {
                    /* only show transport header */
                    bParseService = FALSE;
                    next_tvb = tvb_new_subset_remaining(tvb, 0);
                }

                pinfo->fragmented = bSaveFragmented;
            }
        }

        offset = 0;

        /* call the transport message dissector */
        iServiceId = (*pfctParse)(transport_tree, tvb, pinfo, &offset);

        /* parse the service if not chunked or last chunk */
        if (msgtype == MSG_MESSAGE && bParseService)
        {
            if (bIsLastFragment != FALSE)
            {
                offset = 0;
            }
            iServiceId = parseService(transport_tree, next_tvb, pinfo, &offset);
        }

        /* display the service type in addition to the message type */
        if (iServiceId != -1)
        {
            const gchar *szServiceName = val_to_str((guint32)iServiceId, g_requesttypes, "ServiceId %d");

            if (bIsLastFragment == FALSE)
            {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", g_szMessageTypes[msgtype], szServiceName);
            }
            else
            {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s (Message Reassembled)", g_szMessageTypes[msgtype], szServiceName);
            }
        }
    }

    return tvb_reported_length(tvb);
}

/** The main OpcUa dissector functions.
  * It uses tcp_dissect_pdus from packet-tcp.h
  * to reassemble the TCP data.
  */
static int dissect_opcua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                     get_opcua_message_len, dissect_opcua_message, data);
    return tvb_reported_length(tvb);
}

static void register_tcp_port(guint32 port)
{
    if (port != 0)
        dissector_add_uint("tcp.port", port, opcua_handle);
}

static void unregister_tcp_port(guint32 port)
{
    if (port != 0)
        dissector_delete_uint("tcp.port", port, opcua_handle);
}

static void
init_opcua(void)
{
    reassembly_table_init(&opcua_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
cleanup_opcua(void)
{
    reassembly_table_destroy(&opcua_reassembly_table);
}

/** plugin entry functions.
 * This registers the OpcUa protocol.
 */
void proto_register_opcua(void)
{
    char *tmp;

    static hf_register_info hf[] =
        {
            /* id                                    full name                                              abbreviation                        type            display     strings bitmask blurb HFILL */
            {&hf_opcua_fragments,                   {"Message fragments",                                   "opcua.fragments",                  FT_NONE,        BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment,                    {"Message fragment",                                    "opcua.fragment",                   FT_FRAMENUM,    BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_overlap,            {"Message fragment overlap",                            "opcua.fragment.overlap",           FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_overlap_conflicts,  {"Message fragment overlapping with conflicting data",  "opcua.fragment.overlap.conflicts", FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_multiple_tails,     {"Message has multiple tail fragments",                 "opcua.fragment.multiple_tails",    FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_too_long_fragment,  {"Message fragment too long",                           "opcua.fragment.too_long_fragment", FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_error,              {"Message defragmentation error",                       "opcua.fragment.error",             FT_FRAMENUM,    BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_count,              {"Message fragment count",                              "opcua.fragment.count",             FT_UINT32,      BASE_DEC,   NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_reassembled_in,              {"Reassembled in",                                      "opcua.reassembled.in",             FT_FRAMENUM,    BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_reassembled_length,          {"Reassembled length",                                  "opcua.reassembled.length",         FT_UINT32,      BASE_DEC,   NULL,   0x00,   NULL, HFILL}}
        };

    /** Setup protocol subtree array */
    static gint *ett[] =
        {
            &ett_opcua_extensionobject,
            &ett_opcua_nodeid,
            &ett_opcua_transport,
            &ett_opcua_fragment,
            &ett_opcua_fragments
        };

    module_t *opcua_module;

    proto_opcua = proto_register_protocol(
        "OpcUa Binary Protocol", /* name */
        "OpcUa",                 /* short name */
        "opcua"                  /* abbrev */
        );

    registerTransportLayerTypes(proto_opcua);
    registerSecurityLayerTypes(proto_opcua);
    registerApplicationLayerTypes(proto_opcua);
    registerSimpleTypes(proto_opcua);
    registerEnumTypes(proto_opcua);
    registerComplexTypes();
    registerServiceTypes();
    registerFieldTypes(proto_opcua);

    proto_register_subtree_array(ett, array_length(ett));

    tmp = g_strdup_printf("%d", OPCUA_PORT);
    range_convert_str(&global_tcp_ports_opcua, tmp,  65535);
    g_free(tmp);

    proto_register_field_array(proto_opcua, hf, array_length(hf));

    register_init_routine(&init_opcua);
    register_cleanup_routine(&cleanup_opcua);

    /* register user preferences */
    opcua_module = prefs_register_protocol(proto_opcua, proto_reg_handoff_opcua);
    prefs_register_range_preference(opcua_module, "tcp_ports",
                                    "OPC UA TCP Ports",
                                    "The TCP ports for the OPC UA TCP Binary Protocol (comma separated list)",
                                    &global_tcp_ports_opcua, 65535);

}

void proto_reg_handoff_opcua(void)
{
    static gboolean opcua_initialized = FALSE;
    static range_t *tcp_ports_opcua  = NULL;

    if(!opcua_initialized)
    {
        opcua_handle = create_dissector_handle(dissect_opcua, proto_opcua);
        opcua_initialized = TRUE;
    }
    else
    {
        /* clean up ports and their lists */
        if (tcp_ports_opcua != NULL)
        {
            range_foreach(tcp_ports_opcua, unregister_tcp_port);
            g_free(tcp_ports_opcua);
        }
    }

    /* If we now have a PDU tree, register for the port or ports we have */
    tcp_ports_opcua = range_copy(global_tcp_ports_opcua);
    range_foreach(tcp_ports_opcua, register_tcp_port);
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
