/* packet-pagp.c
 * Routines for PAgP (Port Aggregation Protocol - aka FEC) dissection
 * Original Author Mark C. Brown <mbrown@hp.com>
 * Copyright (C) 2004 Hewlett-Packard Development Company, L.P.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-slowprotocols.c
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
#include <epan/to_str.h>

void proto_register_pagp(void);
void proto_reg_handoff_pagp(void);

/* Offsets of fields within a PagP PDU */

#define PAGP_VERSION_NUMBER              0

#define PAGP_FLAGS                       1
#define PAGP_LOCAL_DEVICE_ID             2
#define PAGP_LOCAL_LEARN_CAP             8
#define PAGP_LOCAL_PORT_PRIORITY         9
#define PAGP_LOCAL_SENT_PORT_IFINDEX    10
#define PAGP_LOCAL_GROUP_CAPABILITY     14
#define PAGP_LOCAL_GROUP_IFINDEX        18
#define PAGP_PARTNER_DEVICE_ID          22
#define PAGP_PARTNER_LEARN_CAP          28
#define PAGP_PARTNER_PORT_PRIORITY      29
#define PAGP_PARTNER_SENT_PORT_IFINDEX  30
#define PAGP_PARTNER_GROUP_CAPABILITY   34
#define PAGP_PARTNER_GROUP_IFINDEX      38
#define PAGP_PARTNER_COUNT              42
#define PAGP_NUM_TLVS                   44
#define PAGP_FIRST_TLV                  46

#define PAGP_FLUSH_LOCAL_DEVICE_ID       2
#define PAGP_FLUSH_PARTNER_DEVICE_ID     8
#define PAGP_FLUSH_TRANSACTION_ID       14

/* PDU Versions */

#define PAGP_INFO_PDU                    1
#define PAGP_FLUSH_PDU                   2

/* Flag bits */

#define PAGP_FLAGS_SLOW_HELLO           0x01
#define PAGP_FLAGS_AUTO_MODE            0x02
#define PAGP_FLAGS_CONSISTENT_STATE     0x04

/* TLV Types */


#define PAGP_TLV_DEVICE_NAME             1
#define PAGP_TLV_PORT_NAME               2
#define PAGP_TLV_AGPORT_MAC              3
#define PAGP_TLV_RESERVED                4

/* Initialise the protocol and registered fields */

static int proto_pagp = -1;

static int hf_pagp_version_number = -1;

static int hf_pagp_flags = -1;
static int hf_pagp_flags_slow_hello = -1;
static int hf_pagp_flags_auto_mode = -1;
static int hf_pagp_flags_consistent_state = -1;
static int hf_pagp_local_device_id = -1;
static int hf_pagp_local_learn_cap = -1;
static int hf_pagp_local_port_priority = -1;
static int hf_pagp_local_sent_port_ifindex = -1;
static int hf_pagp_local_group_capability = -1;
static int hf_pagp_local_group_ifindex = -1;
static int hf_pagp_partner_device_id = -1;
static int hf_pagp_partner_learn_cap = -1;
static int hf_pagp_partner_port_priority = -1;
static int hf_pagp_partner_sent_port_ifindex = -1;
static int hf_pagp_partner_group_capability = -1;
static int hf_pagp_partner_group_ifindex = -1;
static int hf_pagp_partner_count = -1;
static int hf_pagp_num_tlvs = -1;
static int hf_pagp_tlv = -1;
static int hf_pagp_tlv_length = -1;
static int hf_pagp_tlv_device_name = -1;
static int hf_pagp_tlv_port_name = -1;
static int hf_pagp_tlv_agport_mac = -1;

static int hf_pagp_flush_local_device_id = -1;
static int hf_pagp_flush_partner_device_id = -1;
static int hf_pagp_flush_transaction_id = -1;

/* Initialise the subtree pointers */

static gint ett_pagp = -1;
static gint ett_pagp_flags = -1;
static gint ett_pagp_tlvs = -1;

static expert_field ei_pagp_tlv_length = EI_INIT;

/* General declarations and macros */

static const value_string pdu_vers[] = {
    { 1, "Info PDU" },
    { 2, "Flush PDU" },
    { 0, NULL }
};

static const value_string learn_cap[] = {
    { 1, "Source-based Distribution" },
    { 2, "Arbitrary Distribution" },
    { 0, NULL }
};

static const value_string tlv_types[] = {
    { 1, "Device Name TLV" },
    { 2, "Physical Port Name TLV" },
    { 3, "Agport MAC Address" },
    { 4, "Reserved" },
    { 0, NULL }
};

static const true_false_string automode = {
    "Yes",
    "Desirable Mode"
};

/* Code to actually dissect the PAGP packets */
static int
dissect_pagp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint32 raw_word;
    guint16 num_tlvs;
    guint16 tlv;
    guint16 len;
    guint16 ii;
    guint16 offset = PAGP_FIRST_TLV;
    guint8  raw_octet;

    guint8  flags;

    proto_tree *pagp_tree = NULL;
    proto_item *pagp_item, *len_item;
    proto_tree *tlv_tree;
    static const int * pagp_flags[] = {
        &hf_pagp_flags_slow_hello,
        &hf_pagp_flags_auto_mode,
        &hf_pagp_flags_consistent_state,
        NULL,
    };


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PAGP"); /* PAGP Protocol */

    col_clear(pinfo->cinfo, COL_INFO);

    raw_octet = tvb_get_guint8(tvb, PAGP_VERSION_NUMBER);
    if (tree) {
        pagp_item = proto_tree_add_protocol_format(tree, proto_pagp, tvb,
                                                   0, -1, "Port Aggregation Protocol");
        pagp_tree = proto_item_add_subtree(pagp_item, ett_pagp);
        proto_tree_add_uint(pagp_tree, hf_pagp_version_number, tvb,
                            PAGP_VERSION_NUMBER, 1, raw_octet);
    }
    col_append_str(pinfo->cinfo, COL_INFO,
                   val_to_str_const(raw_octet, pdu_vers, "Unknown PDU version"));

    if (raw_octet == PAGP_FLUSH_PDU) {

        col_append_fstr(pinfo->cinfo, COL_INFO, "; Local DevID: %s",
                        tvb_ether_to_str(tvb, PAGP_FLUSH_LOCAL_DEVICE_ID));

        proto_tree_add_item(pagp_tree, hf_pagp_flush_local_device_id, tvb,
                            PAGP_FLUSH_LOCAL_DEVICE_ID, 6, ENC_NA);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Partner DevID: %s",
                        tvb_ether_to_str(tvb, PAGP_FLUSH_PARTNER_DEVICE_ID));

        proto_tree_add_item(pagp_tree, hf_pagp_flush_partner_device_id, tvb,
                            PAGP_FLUSH_PARTNER_DEVICE_ID, 6, ENC_NA);

        raw_word = tvb_get_ntohl(tvb, PAGP_FLUSH_TRANSACTION_ID);
        col_append_fstr(pinfo->cinfo, COL_INFO, "; Transaction ID: 0x%x ", raw_word);

        proto_tree_add_uint(pagp_tree, hf_pagp_flush_transaction_id, tvb,
                            PAGP_FLUSH_TRANSACTION_ID, 4, raw_word);
        return tvb_captured_length(tvb);
    }

    /* Info PDU */

    flags = tvb_get_guint8(tvb, PAGP_FLAGS);
    col_append_fstr(pinfo->cinfo, COL_INFO, "; Flags 0x%x", flags);

    proto_tree_add_bitmask(pagp_tree, tvb, PAGP_FLAGS, hf_pagp_flags, ett_pagp_flags, pagp_flags, ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, "; Local DevID: %s",
                    tvb_ether_to_str(tvb, PAGP_LOCAL_DEVICE_ID));

    proto_tree_add_item(pagp_tree, hf_pagp_local_device_id, tvb,
                        PAGP_LOCAL_DEVICE_ID, 6, ENC_NA);

    if (tree) {
        proto_tree_add_item(pagp_tree, hf_pagp_local_learn_cap, tvb,
                            PAGP_LOCAL_LEARN_CAP, 1, ENC_NA);

        proto_tree_add_item(pagp_tree, hf_pagp_local_port_priority, tvb,
                            PAGP_LOCAL_PORT_PRIORITY, 1, ENC_NA);

        proto_tree_add_item(pagp_tree, hf_pagp_local_sent_port_ifindex, tvb,
                            PAGP_LOCAL_SENT_PORT_IFINDEX, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(pagp_tree, hf_pagp_local_group_capability, tvb,
                            PAGP_LOCAL_GROUP_CAPABILITY, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(pagp_tree, hf_pagp_local_group_ifindex, tvb,
                            PAGP_LOCAL_GROUP_IFINDEX, 4, ENC_BIG_ENDIAN);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Partner DevID: %s",
                    tvb_ether_to_str(tvb, PAGP_PARTNER_DEVICE_ID));

    proto_tree_add_item(pagp_tree, hf_pagp_partner_device_id, tvb,
                        PAGP_PARTNER_DEVICE_ID, 6, ENC_NA);

    proto_tree_add_item(pagp_tree, hf_pagp_partner_learn_cap, tvb,
                        PAGP_PARTNER_LEARN_CAP, 1, ENC_NA);

    proto_tree_add_item(pagp_tree, hf_pagp_partner_port_priority, tvb,
                        PAGP_PARTNER_PORT_PRIORITY, 1, ENC_NA);

    proto_tree_add_item(pagp_tree, hf_pagp_partner_sent_port_ifindex, tvb,
                        PAGP_PARTNER_SENT_PORT_IFINDEX, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(pagp_tree, hf_pagp_partner_group_capability, tvb,
                        PAGP_PARTNER_GROUP_CAPABILITY, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(pagp_tree, hf_pagp_partner_group_ifindex, tvb,
                        PAGP_PARTNER_GROUP_IFINDEX, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(pagp_tree, hf_pagp_partner_count, tvb,
                        PAGP_PARTNER_COUNT, 2, ENC_BIG_ENDIAN);

    num_tlvs = tvb_get_ntohs(tvb, PAGP_NUM_TLVS);
    proto_tree_add_uint(pagp_tree, hf_pagp_num_tlvs, tvb,
                        PAGP_NUM_TLVS, 2, num_tlvs);

    /* dump TLV entries */

    for ( ii = 0; ii < num_tlvs; ii++ ) {

        tlv = tvb_get_ntohs(tvb, offset);
        len = tvb_get_ntohs(tvb, offset + 2);

        tlv_tree = proto_tree_add_subtree_format(pagp_tree, tvb, offset, len,
                                                 ett_pagp_tlvs, NULL, "TLV Entry #%d", ii+1);

        proto_tree_add_uint(tlv_tree, hf_pagp_tlv, tvb, offset, 2, tlv);
        len_item = proto_tree_add_uint(tlv_tree, hf_pagp_tlv_length, tvb, offset+2, 2, len);
        if ( len == 0 ) {
            expert_add_info_format(pinfo, len_item, &ei_pagp_tlv_length,
                                   "Unknown data - TLV len=0");
            return offset;
        }
        if ( tvb_reported_length_remaining(tvb, offset) < len ) {
            expert_add_info_format(pinfo, len_item, &ei_pagp_tlv_length,
                                   "TLV length too large");
            return offset;
        }

        switch (tlv) {
            case PAGP_TLV_DEVICE_NAME:
                proto_tree_add_item(tlv_tree, hf_pagp_tlv_device_name,
                                      tvb, offset+4, len-4, ENC_NA|ENC_ASCII);
                break;
            case PAGP_TLV_PORT_NAME:
                proto_tree_add_item(tlv_tree, hf_pagp_tlv_port_name,
                                      tvb, offset+4, len-4, ENC_NA|ENC_ASCII);
                break;
            case PAGP_TLV_AGPORT_MAC:
                proto_tree_add_item(tlv_tree, hf_pagp_tlv_agport_mac,
                                    tvb, offset+4, 6, ENC_NA);
                break;
            case PAGP_TLV_RESERVED:
                break;
        }

        offset += len;

    }
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

void
proto_register_pagp(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {

        { &hf_pagp_version_number,
          { "Version",              "pagp.version",
            FT_UINT8,       BASE_HEX,       VALS(pdu_vers), 0x0,
            "Identifies the PAgP PDU version: 1 = Info, 2 = Flush", HFILL }},

        { &hf_pagp_flags,
          { "Flags",                "pagp.flags",
            FT_UINT8,       BASE_HEX,       NULL,   0x0,
            "Information flags", HFILL }},

        { &hf_pagp_flags_slow_hello,
          { "Slow Hello",           "pagp.flags.slowhello",
            FT_BOOLEAN,     8,      TFS(&tfs_yes_no), PAGP_FLAGS_SLOW_HELLO,
            "1 = using Slow Hello, 0 = Slow Hello disabled", HFILL }},

        { &hf_pagp_flags_auto_mode,
          { "Auto Mode",            "pagp.flags.automode",
            FT_BOOLEAN,     8,      TFS(&automode), PAGP_FLAGS_AUTO_MODE,
            "1 = Auto Mode enabled, 0 = Desirable Mode", HFILL }},

        { &hf_pagp_flags_consistent_state,
          { "Consistent State",     "pagp.flags.state",
            FT_BOOLEAN,     8,      NULL,   PAGP_FLAGS_CONSISTENT_STATE,
            "1 = Consistent State, 0 = Not Ready", HFILL }},

        { &hf_pagp_local_device_id,
          { "Local Device ID",      "pagp.localdevid",
            FT_ETHER,       BASE_NONE,      NULL,   0x0,
            NULL, HFILL }},

        { &hf_pagp_local_learn_cap,
          { "Local Learn Capability",       "pagp.localearncap",
            FT_UINT8,       BASE_HEX,       VALS(learn_cap),        0x0,
            NULL, HFILL }},

        { &hf_pagp_local_port_priority,
          { "Local Port Hot Standby Priority",      "pagp.localportpri",
            FT_UINT8,       BASE_DEC,       NULL,   0x0,
            "The local hot standby priority assigned to this port", HFILL }},

        { &hf_pagp_local_sent_port_ifindex,
          { "Local Sent Port ifindex",      "pagp.localsentportifindex",
            FT_UINT32,      BASE_DEC,       NULL,   0x0,
            "The interface index of the local port used to send PDU", HFILL }},

        { &hf_pagp_local_group_capability,
          { "Local Group Capability",       "pagp.localgroupcap",
            FT_UINT32,      BASE_HEX,       NULL,   0x0,
            "The local group capability", HFILL }},

        { &hf_pagp_local_group_ifindex,
          { "Local Group ifindex",          "pagp.localgroupifindex",
            FT_UINT32,      BASE_DEC,       NULL,   0x0,
            "The local group interface index", HFILL }},

        { &hf_pagp_partner_device_id,
          { "Partner Device ID",            "pagp.partnerdevid",
            FT_ETHER,       BASE_NONE,      NULL,   0x0,
            "Remote Device ID (MAC)", HFILL }},

        { &hf_pagp_partner_learn_cap,
          { "Partner Learn Capability",     "pagp.partnerlearncap",
            FT_UINT8,       BASE_HEX,       VALS(learn_cap),        0x0,
            "Remote learn capability", HFILL }},

        { &hf_pagp_partner_port_priority,
          { "Partner Port Hot Standby Priority",    "pagp.partnerportpri",
            FT_UINT8,       BASE_DEC,       NULL,   0x0,
            "Remote port priority", HFILL }},

        { &hf_pagp_partner_sent_port_ifindex,
          { "Partner Sent Port ifindex",    "pagp.partnersentportifindex",
            FT_UINT32,      BASE_DEC,       NULL,   0x0,
            "Remote port interface index sent", HFILL }},

        { &hf_pagp_partner_group_capability,
          { "Partner Group Capability",     "pagp.partnergroupcap",
            FT_UINT32,      BASE_HEX,       NULL,   0x0,
            "Remote group capability", HFILL }},

        { &hf_pagp_partner_group_ifindex,
          { "Partner Group ifindex",        "pagp.partnergroupifindex",
            FT_UINT32,      BASE_DEC,       NULL,   0x0,
            "Remote group interface index", HFILL }},

        { &hf_pagp_partner_count,
          { "Partner Count",                "pagp.partnercount",
            FT_UINT16,      BASE_DEC,       NULL,   0x0,
            NULL, HFILL }},

        { &hf_pagp_num_tlvs,
          { "Number of TLVs",               "pagp.numtlvs",
            FT_UINT16,      BASE_DEC,       NULL,   0x0,
            "Number of TLVs following", HFILL }},

        { &hf_pagp_tlv,
          { "Type",         "pagp.tlv",
            FT_UINT16,      BASE_DEC,       VALS(tlv_types),        0x0,
            "Type/Length/Value", HFILL }},

        { &hf_pagp_tlv_length,
          { "Length",               "pagp.tlv_length",
            FT_UINT16,      BASE_DEC,       NULL,   0x0,
            NULL, HFILL }},

        { &hf_pagp_tlv_device_name,
          { "Device Name",          "pagp.tlvdevname",
            FT_STRING,      BASE_NONE,      NULL,   0x0,
            "sysName of device", HFILL }},

        { &hf_pagp_tlv_port_name,
          { "Physical Port Name",           "pagp.tlvportname",
            FT_STRING,      BASE_NONE,      NULL,   0x0,
            "Name of port used to send PDU", HFILL }},

        { &hf_pagp_tlv_agport_mac,
          { "Agport MAC Address",           "pagp.tlvagportmac",
            FT_ETHER,       BASE_NONE,      NULL,   0x0,
            "Source MAC on frames for this aggregate", HFILL }},

        { &hf_pagp_flush_local_device_id,
          { "Flush Local Device ID",        "pagp.flushlocaldevid",
            FT_ETHER,       BASE_NONE,      NULL,   0x0,
            NULL, HFILL }},

        { &hf_pagp_flush_partner_device_id,
          { "Flush Partner Device ID",      "pagp.flushpartnerdevid",
            FT_ETHER,       BASE_NONE,      NULL,   0x0,
            "Flush remote device ID", HFILL }},

        { &hf_pagp_flush_transaction_id,
          { "Transaction ID",               "pagp.transid",
            FT_UINT32,      BASE_HEX,       NULL,   0x0,
            "Flush transaction ID", HFILL }},

    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_pagp,
        &ett_pagp_flags,
        &ett_pagp_tlvs,
    };

    static ei_register_info ei[] = {
        { &ei_pagp_tlv_length, { "pagp.tlv_length.invalid", PI_PROTOCOL, PI_WARN, "Invalid TLV length", EXPFILL }},
    };
    expert_module_t* expert_pagp;

    /* Register the protocol name and description */

    proto_pagp = proto_register_protocol("Port Aggregation Protocol", "PAGP", "pagp");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_pagp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pagp = expert_register_protocol(proto_pagp);
    expert_register_field_array(expert_pagp, ei, array_length(ei));
}


void
proto_reg_handoff_pagp(void)
{
    dissector_handle_t pagp_handle;

    pagp_handle = create_dissector_handle(dissect_pagp, proto_pagp);
    dissector_add_uint("llc.cisco_pid", 0x0104, pagp_handle);
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
