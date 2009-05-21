/* packet-zbee-aps.c
 * Dissector routines for the ZigBee Application Support Sub-layer (APS)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*  Include Files */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVEHCONFIG_H */

#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <gmodule.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#include "packet-zbee.h"
#include "packet-zbee-security.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-nwk.h"

/*************************
 * Function Declarations *
 *************************
 */
/* Protocol Registration */
void    proto_init_zbee_aps         (void);

/* Dissector Routines */
void    dissect_zbee_aps            (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void    dissect_zbee_aps_cmd        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void    dissect_zbee_apf            (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Command Dissector Helpers */
guint   dissect_zbee_aps_skke_challenge (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_skke_data      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_transport_key  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_update_device  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_remove_device  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_request_key    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_switch_key     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_auth_challenge (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_auth_data      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
guint   dissect_zbee_aps_tunnel         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/* Helper routine. */
guint   zbee_apf_transaction_len    (tvbuff_t *tvb, guint offset, guint8 type);

/********************
 * Global Variables *
 ********************
 */
/* Field indices. */
static int proto_zbee_aps = -1;
static int hf_zbee_aps_fcf_frame_type = -1;
static int hf_zbee_aps_fcf_delivery = -1;
static int hf_zbee_aps_fcf_indirect_mode = -1;  /* ZigBee 2004 and earlier. */
static int hf_zbee_aps_fcf_ack_mode = -1;       /* ZigBee 2007 and later. */
static int hf_zbee_aps_fcf_security = -1;
static int hf_zbee_aps_fcf_ack_req = -1;
static int hf_zbee_aps_fcf_ext_header = -1;
static int hf_zbee_aps_dst = -1;
static int hf_zbee_aps_group = -1;
static int hf_zbee_aps_cluster = -1;
static int hf_zbee_aps_profile = -1;
static int hf_zbee_aps_src = -1;
static int hf_zbee_aps_counter = -1;
static int hf_zbee_aps_fragmentation = -1;
static int hf_zbee_aps_block_number = -1;

static int hf_zbee_aps_cmd_id = -1;
static int hf_zbee_aps_cmd_initiator = -1;
static int hf_zbee_aps_cmd_responder = -1;
static int hf_zbee_aps_cmd_partner = -1;
static int hf_zbee_aps_cmd_initiator_flag = -1;
static int hf_zbee_aps_cmd_device = -1;
static int hf_zbee_aps_cmd_challenge = -1;
static int hf_zbee_aps_cmd_mac = -1;
static int hf_zbee_aps_cmd_key = -1;
static int hf_zbee_aps_cmd_key_type = -1;
static int hf_zbee_aps_cmd_dst = -1;
static int hf_zbee_aps_cmd_src = -1;
static int hf_zbee_aps_cmd_seqno = -1;
static int hf_zbee_aps_cmd_short_addr = -1;
static int hf_zbee_aps_cmd_device_status = -1;
static int hf_zbee_aps_cmd_ea_key_type = -1;
static int hf_zbee_aps_cmd_ea_data = -1;

/* Field indices for ZigBee 2003 & earlier Application Framework. */
static int proto_zbee_apf = -1;
static int hf_zbee_apf_count = -1;
static int hf_zbee_apf_type = -1;

/* Subtree indices. */
static gint ett_zbee_aps = -1;
static gint ett_zbee_aps_fcf = -1;
static gint ett_zbee_aps_ext = -1;
static gint ett_zbee_aps_cmd = -1;

/* Fragmentation indices. */
static int hf_zbee_aps_fragments = -1;
static int hf_zbee_aps_fragment = -1;
static int hf_zbee_aps_fragment_overlap = -1;
static int hf_zbee_aps_fragment_overlap_conflicts = -1;
static int hf_zbee_aps_fragment_multiple_tails = -1;
static int hf_zbee_aps_fragment_too_long_fragment = -1;
static int hf_zbee_aps_fragment_error = -1;
static int hf_zbee_aps_reassembled_in = -1;
static gint ett_zbee_aps_fragment = -1;
static gint ett_zbee_aps_fragments = -1;

/* Subtree indices for the ZigBee 2004 & earlier Application Framework. */
static gint ett_zbee_apf = -1;

/* Dissector Handles. */
static dissector_handle_t   data_handle;
static dissector_handle_t   zbee_aps_handle;
static dissector_handle_t   zbee_apf_handle;

/* Dissector List. */
static dissector_table_t    zbee_aps_dissector_table;

/* Fragment and Reassembly tables. */
static GHashTable   *zbee_aps_fragment_table = NULL;
static GHashTable   *zbee_aps_reassembled_table = NULL;

static const fragment_items zbee_aps_frag_items = {
    /* Fragment subtrees */
    &ett_zbee_aps_fragment,
    &ett_zbee_aps_fragments,
    /* Fragment fields */
    &hf_zbee_aps_fragments,
    &hf_zbee_aps_fragment,
    &hf_zbee_aps_fragment_overlap,
    &hf_zbee_aps_fragment_overlap_conflicts,
    &hf_zbee_aps_fragment_multiple_tails,
    &hf_zbee_aps_fragment_too_long_fragment,
    &hf_zbee_aps_fragment_error,
    /* Reassembled in field */
    &hf_zbee_aps_reassembled_in,
    /* Tag */
    "APS Message fragments"
};
/********************/
/* Field Names      */
/********************/
/* Frame Type Names */
const value_string zbee_aps_frame_types[] = {
    { ZBEE_APS_FCF_DATA,            "Data" },
    { ZBEE_APS_FCF_CMD,             "Command" },
    { ZBEE_APS_FCF_ACK,             "Ack" },
    { 0, NULL }
};

/* Delivery Mode Names */
const value_string zbee_aps_delivery_modes[] = {
    { ZBEE_APS_FCF_UNICAST,         "Unicast" },
    { ZBEE_APS_FCF_INDIRECT,        "Indirect" },
    { ZBEE_APS_FCF_BCAST,           "Broadcast" },
    { ZBEE_APS_FCF_GROUP,           "Group" },
    { 0, NULL }
};

/* Fragmentation Mode Names */
const value_string zbee_aps_fragmentation_modes[] = {
    { ZBEE_APS_EXT_FCF_FRAGMENT_NONE,   "None" },
    { ZBEE_APS_EXT_FCF_FRAGMENT_FIRST,  "First Block" },
    { ZBEE_APS_EXT_FCF_FRAGMENT_MIDDLE, "Middle Block" },
    { 0, NULL }
};

/* APS Command Names */
const value_string zbee_aps_cmd_names[] = {
    { ZBEE_APS_CMD_SKKE1,           "SKKE-1" },
    { ZBEE_APS_CMD_SKKE2,           "SKKE-2" },
    { ZBEE_APS_CMD_SKKE3,           "SKKE-3" },
    { ZBEE_APS_CMD_SKKE4,           "SKKE-4" },
    { ZBEE_APS_CMD_TRANSPORT_KEY,   "Transport Key" },
    { ZBEE_APS_CMD_UPDATE_DEVICE,   "Update Device" },
    { ZBEE_APS_CMD_REMOVE_DEVICE,   "Remove Device" },
    { ZBEE_APS_CMD_REQUEST_KEY,     "Request Key" },
    { ZBEE_APS_CMD_SWITCH_KEY,      "Switch Key" },
    { ZBEE_APS_CMD_EA_INIT_CHLNG,   "EA Initiator Challenge" },
    { ZBEE_APS_CMD_EA_RESP_CHLNG,   "EA Responder Challenge" },
    { ZBEE_APS_CMD_EA_INIT_MAC_DATA,"EA Initiator MAC" },
    { ZBEE_APS_CMD_EA_RESP_MAC_DATA,"EA Responder MAC" },
    { ZBEE_APS_CMD_TUNNEL,          "Tunnel" },
    { 0, NULL }
};

/* APS Key Names */
const value_string zbee_aps_key_names[] = {
    { ZBEE_APS_CMD_KEY_TC_MASTER,       "Trust Center Master Key" },
    { ZBEE_APS_CMD_KEY_STANDARD_NWK,    "Standard Network Key" },
    { ZBEE_APS_CMD_KEY_APP_MASTER,      "Application Master Key" },
    { ZBEE_APS_CMD_KEY_APP_LINK,        "Application Link Key" },
    { ZBEE_APS_CMD_KEY_TC_LINK,         "Trust Center Link Key" },
    { ZBEE_APS_CMD_KEY_HIGH_SEC_NWK,    "High-Security Network Key" },
    { 0, NULL }
};

/* APS Key Names (Entity-Authentication). */
const value_string zbee_aps_ea_key_names[] = {
    { ZBEE_APS_CMD_EA_KEY_NWK,          "Network Key" },
    { ZBEE_APS_CMD_EA_KEY_LINK,         "Link Key" },
    { 0, NULL }
};

/* Update Device Status Names */
const value_string zbee_aps_update_status_names[] = {
    { ZBEE_APS_CMD_UPDATE_STANDARD_SEC_REJOIN,  "Standard device secured rejoin" },
    { ZBEE_APS_CMD_UPDATE_STANDARD_UNSEC_JOIN,  "Standard device unsecured join" },
    { ZBEE_APS_CMD_UPDATE_LEAVE,                "Device left" },
    { ZBEE_APS_CMD_UPDATE_STANDARD_UNSEC_REJOIN,"Standard device unsecured rejoin" },
    { ZBEE_APS_CMD_UPDATE_HIGH_SEC_REJOIN,      "High security device secured rejoin" },
    { ZBEE_APS_CMD_UPDATE_HIGH_UNSEC_JOIN,      "High security device unsecured join" },
    { ZBEE_APS_CMD_UPDATE_HIGH_UNSEC_REJOIN,    "High security device unsecured rejoin" },
    { 0, NULL }
};

/* Outdated ZigBee 2004 Value Strings. */
const value_string zbee_apf_type_names[] = {
    { ZBEE_APP_TYPE_KVP,    "Key-Value Pair" },
    { ZBEE_APP_TYPE_MSG,    "Message" },
    { 0, NULL }
};

const value_string zbee_apf_kvp_command_names[] = {
    { ZBEE_APP_KVP_SET,         "Set" },
    { ZBEE_APP_KVP_EVENT,       "Event" },
    { ZBEE_APP_KVP_GET_ACK,     "Get Acknowledgement" },
    { ZBEE_APP_KVP_SET_ACK,     "Set Acknowledgement" },
    { ZBEE_APP_KVP_EVENT_ACK,   "Event Acknowledgement" },
    { ZBEE_APP_KVP_GET_RESP,    "Get Response" },
    { ZBEE_APP_KVP_SET_RESP,    "Set Response" },
    { ZBEE_APP_KVP_EVENT_RESP,  "Event Response" },
    { 0, NULL }
};

const value_string zbee_apf_kvp_type_names[] = {
    { ZBEE_APP_KVP_NO_DATA,     "No Data" },
    { ZBEE_APP_KVP_UINT8,       "8-bit Unsigned Integer" },
    { ZBEE_APP_KVP_INT8,        "8-bit Signed Integer" },
    { ZBEE_APP_KVP_UINT16,      "16-bit Unsigned Integer" },
    { ZBEE_APP_KVP_INT16,       "16-bit Signed Integer" },
    { ZBEE_APP_KVP_FLOAT16,     "16-bit Floating Point" },
    { ZBEE_APP_KVP_ABS_TIME,    "Absolute Time" },
    { ZBEE_APP_KVP_REL_TIME,    "Relative Time" },
    { ZBEE_APP_KVP_CHAR_STRING, "Character String" },
    { ZBEE_APP_KVP_OCT_STRING,  "Octet String" },
    { 0, NULL }
};

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps
 *  DESCRIPTION
 *      ZigBee Application Support Sublayer dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_aps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t            *payload_tvb = NULL;
    dissector_handle_t  profile_handle = NULL;

    proto_tree      *aps_tree = NULL;
    proto_tree      *field_tree = NULL;
    proto_item      *proto_root = NULL;
    proto_item      *ti;

    zbee_aps_packet packet;
    zbee_nwk_packet *nwk = pinfo->private_data;

    guint8          fcf;
    guint8          offset = 0;

    /* Init. */
    memset(&packet, 0, sizeof(zbee_aps_packet));

    /*  Create the protocol tree */
    if(tree){
        proto_root = proto_tree_add_protocol_format(tree, proto_zbee_aps, tvb, offset, tvb_length(tvb), "ZigBee Application Support Layer");
        aps_tree = proto_item_add_subtree(proto_root, ett_zbee_aps);
    }
    /* Set the protocol column, if the NWK layer hasn't already done so. */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee");
    }

    /*  Get the FCF */
    fcf = tvb_get_guint8(tvb, offset);
    packet.type         = get_bit_field(fcf, ZBEE_APS_FCF_FRAME_TYPE);
    packet.delivery     = get_bit_field(fcf, ZBEE_APS_FCF_DELIVERY_MODE);
    packet.indirect_mode = get_bit_field(fcf, ZBEE_APS_FCF_INDIRECT_MODE);
    packet.ack_mode     = get_bit_field(fcf, ZBEE_APS_FCF_ACK_MODE);
    packet.security     = get_bit_field(fcf, ZBEE_APS_FCF_SECURITY);
    packet.ack_req      = get_bit_field(fcf, ZBEE_APS_FCF_ACK_REQ);
    packet.ext_header   = get_bit_field(fcf, ZBEE_APS_FCF_EXT_HEADER);

    /* Display the frame type to the proto root and info column. */
    if (tree) {
        proto_item_append_text(proto_root, " %s", val_to_str(packet.type, zbee_aps_frame_types, "Unknown Type"));
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_clear(pinfo->cinfo, COL_INFO);
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str(packet.type, zbee_aps_frame_types, "Unknown Frame Type"));
    }

    /*  Display the FCF */
    if (tree) {
        /* Create the subtree */
        ti = proto_tree_add_text(aps_tree, tvb, offset, sizeof(guint8), "Frame Control Field: %s (0x%02x)",
                    val_to_str(packet.type, zbee_aps_frame_types, "Unknown"), fcf);
        field_tree = proto_item_add_subtree(ti, ett_zbee_aps_fcf);

        /* Add the frame type and delivery mode. */
        proto_tree_add_uint(field_tree, hf_zbee_aps_fcf_frame_type, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_FRAME_TYPE);
        proto_tree_add_uint(field_tree, hf_zbee_aps_fcf_delivery, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_DELIVERY_MODE);

        if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
            /* ZigBee 2007 and later uses an ack mode flag. */
            if (packet.type == ZBEE_APS_FCF_ACK) {
                proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_ack_mode, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_ACK_MODE);
            }
        }
        else {
            /* ZigBee 2004, uses indirect mode. */
            if (packet.delivery == ZBEE_APS_FCF_INDIRECT) {
                proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_indirect_mode, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_INDIRECT_MODE);
            }
        }

        /*  Add the rest of the flags */
        proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_security, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_SECURITY);
        proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_ack_req, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_ACK_REQ);
        proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_ext_header, tvb, offset, sizeof(guint8), fcf & ZBEE_APS_FCF_EXT_HEADER);
    }
    offset += sizeof(guint8);

    /* Check if the endpoint addressing fields are present. */
    switch (packet.type) {
        case ZBEE_APS_FCF_DATA:
            /* Endpoint addressing must exist to some extent on data frames. */
            break;

        case ZBEE_APS_FCF_ACK:
            if ((pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) && (packet.ack_mode)) {
                /* Command Ack: endpoint addressing does not exist. */
                goto dissect_zbee_aps_no_endpt;
            }
            break;

        default:
        case ZBEE_APS_FCF_CMD:
            /* Endpoint addressing does not exist for these frames. */
            goto dissect_zbee_aps_no_endpt;
    } /* switch */

    /* Determine whether the source and/or destination endpoints are present.
     * We should only get here for endpoint-addressed data or ack frames.
     */
    if ((packet.delivery == ZBEE_APS_FCF_UNICAST) || (packet.delivery == ZBEE_APS_FCF_BCAST)) {
        /* Source and destination endpoints exist. (Although, I strongly
         * disagree with the presence of the endpoint in broadcast delivery
         * mode).
         */
        packet.dst_present = TRUE;
        packet.src_present = TRUE;
    }
    else if ((packet.delivery == ZBEE_APS_FCF_INDIRECT) && (pinfo->zbee_stack_vers <= ZBEE_VERSION_2004)) {
        /* Indirect addressing was removed in ZigBee 2006, basically because it
         * was a useless, broken feature which only complicated things. Treat
         * this mode as invalid for ZigBee 2006 and later. When using indirect
         * addressing, only one of the source and destination endpoints exist,
         * and is controlled by the setting of indirect_mode.
         */
        packet.dst_present = (!packet.indirect_mode);
        packet.src_present = (packet.indirect_mode);
    }
    else if ((packet.delivery == ZBEE_APS_FCF_GROUP) && (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007)) {
        /* Group addressing was added in ZigBee 2006, and contains only the
         * source endpoint. (IMO, Broacast deliveries should do the same).
         */
        packet.dst_present = FALSE;
        packet.src_present = TRUE;
    }
    else {
        /* Illegal Delivery Mode. */
        expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_WARN, "Invalid Delivery Mode");
        return;

    }

    /* If the destination endpoint is present, get and display it. */
    if (packet.dst_present) {
        packet.dst = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(aps_tree, hf_zbee_aps_dst, tvb, offset, sizeof(guint8), packet.dst);
            proto_item_append_text(proto_root, ", Dst Endpt: %d", packet.dst);
        }
        offset += sizeof(guint8);

        /* Update the info column. */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst Endpt: %d", packet.dst);
        }
    }

    /* If the group address is present, display it. */
    if (packet.delivery == ZBEE_APS_FCF_GROUP) {
        packet.group = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(aps_tree, hf_zbee_aps_group, tvb, offset, sizeof(guint16), packet.group);
            proto_item_append_text(proto_root, ", Group: 0x%04x", packet.group);
        }
        offset += sizeof(guint16);

        /* Update the info column. */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Group: 0x%04x", packet.group);
        }
    }

    /* Get and display the cluster ID. */
    if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
        /* Cluster ID is 16-bits long in ZigBee 2007 and later. */
        pinfo->zbee_cluster_id = packet.cluster = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(aps_tree, hf_zbee_aps_cluster, tvb, offset, sizeof(guint16), packet.cluster);
        }
        offset += sizeof(guint16);
    }
    else {
        /* Cluster ID is 8-bits long in ZigBee 2004 and earlier. */
        pinfo->zbee_cluster_id = packet.cluster = tvb_get_guint8(tvb, offset);
        if (tree) {
#if 0
            proto_tree_add_uint(aps_tree, hf_zbee_aps_cluster, tvb, offset, sizeof(guint8), packet.cluster);
#endif
            proto_tree_add_uint_format_value(aps_tree, hf_zbee_aps_cluster, tvb, offset, sizeof(guint8), packet.cluster, "0x%02x", packet.cluster);
        }
        offset += sizeof(guint8);
    }

    /* Get and display the profile ID if it exists. */
    packet.profile = tvb_get_letohs(tvb, offset);
    profile_handle = dissector_get_port_handle(zbee_aps_dissector_table, packet.profile);
    if (tree) {
        ti = proto_tree_add_uint(aps_tree, hf_zbee_aps_profile, tvb, offset, sizeof(guint16), packet.profile);
        if (profile_handle) {
            int proto = dissector_handle_get_protocol_index(profile_handle);
            proto_item_append_text(ti, " (%s)", proto_get_protocol_name(proto));
        }
        offset += sizeof(guint16);
        /* Update the protocol root and info column later, after the source endpoint
         * so that the source and destination will be back-to-back in the text.
         */
    }

    /* The source endpoint is present for all cases except indirect /w indirect_mode == FALSE */
    if ((packet.delivery != ZBEE_APS_FCF_INDIRECT) || (!packet.indirect_mode)) {
        packet.src = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(aps_tree, hf_zbee_aps_src, tvb, offset, sizeof(guint8), packet.src);
            proto_item_append_text(proto_root, ", Src Endpt: %d", packet.src);
        }
        offset += sizeof(guint8);

        /* Update the info column. */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Src Endpt: %d", packet.src);
        }
    }

    /* Display the profile ID now that the source endpoint was listed. */
    if (packet.type == ZBEE_APS_FCF_DATA) {
        if (tree) {
            proto_item_append_text(proto_root, ", Profile: 0x%04x", packet.profile);
        }
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Profile: 0x%04x", packet.profile);
        }
    }

    /* Jump here if there is no endpoint addressing in this frame. */
dissect_zbee_aps_no_endpt:

    /* Get and display the APS counter. Only present on ZigBee 2007 and later. */
    if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
        packet.counter = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(aps_tree, hf_zbee_aps_counter, tvb, offset, sizeof(guint8), packet.counter);
        }
        offset += sizeof(guint8);
    }


    /* Get and display the extended header, if present. */
    if (packet.ext_header) {
        fcf = tvb_get_guint8(tvb, offset);
        packet.fragmentation = fcf & ZBEE_APS_EXT_FCF_FRAGMENT;
        if (tree) {
            /* Create a subtree */
            ti = proto_tree_add_text(aps_tree, tvb, offset, sizeof(guint8), "Extended Frame Control Field (0x%02x)", fcf);
            field_tree = proto_item_add_subtree(ti, ett_zbee_aps_fcf);

            /* Display the fragmentation sub-field. */
            proto_tree_add_uint(field_tree, hf_zbee_aps_fragmentation, tvb, offset, sizeof(guint8), packet.fragmentation);
        }
        offset += sizeof(guint8);

        /* If fragmentation is enabled, get and display the block number. */
        if (packet.fragmentation != ZBEE_APS_EXT_FCF_FRAGMENT_NONE) {
            packet.block_number = tvb_get_guint8(tvb, offset);
            if (tree) {
                proto_tree_add_uint(field_tree, hf_zbee_aps_block_number, tvb, offset, sizeof(guint8), packet.block_number);
            }
            offset += sizeof(guint8);
        }

        /* If fragmentation is enabled, and this is an acknowledgement,
         * get and display the ack bitfield.
         */
        if ((packet.fragmentation != ZBEE_APS_EXT_FCF_FRAGMENT_NONE) && (packet.type == ZBEE_APS_FCF_ACK)) {
            packet.ack_bitfield = tvb_get_guint8(tvb, offset);
            if (tree) {
                int     i, mask;
                gchar   tmp[16];
                for (i=0; i<8; i++) {
                    mask = (1<<i);
                    decode_bitfield_value(tmp, packet.ack_bitfield, mask, 8);
                    proto_tree_add_text(field_tree, tvb, offset, sizeof(guint8), "%sBlock %d: %s",
                            tmp, packet.block_number+i, (packet.ack_bitfield & mask)?"Acknowledged":"Not Acknowledged");
                } /* for */
            }
            offset += sizeof(guint8);
        }
    }
    else {
        /* Ensure the fragmentation mode is set off, so that the reassembly handler
         * doesn't get called.
         */
        packet.fragmentation = ZBEE_APS_EXT_FCF_FRAGMENT_NONE;
    }

    /* If a payload is present, and security is enabled, decrypt the payload. */
    if ((offset < tvb_length(tvb)) && packet.security) {
        payload_tvb = dissect_zbee_secure(tvb, pinfo, aps_tree, offset, 0);
        if (payload_tvb == NULL) {
            /* If Payload_tvb is NULL, then the security dissector cleaned up. */
            return;
        }
    }
    /* If the payload exists, create a tvb subset. */
    else if (offset < tvb_length(tvb)) {
        payload_tvb = tvb_new_subset(tvb, offset, -1, -1);
    }

    /* If the payload exstists, and the packet is fragmented, attempt reassembly. */
    if ((payload_tvb) && (packet.fragmentation != ZBEE_APS_EXT_FCF_FRAGMENT_NONE)) {
        guint32         msg_id;
        guint32         block_num;
        fragment_data   *frag_msg = NULL;
        tvbuff_t        *new_tvb;

        /* Set the fragmented flag. */
        pinfo->fragmented = TRUE;

        /* The source address and APS Counter pair form a unique identifier
         * for each message (fragmented or not). Hash these two together to
         * create the message id for the fragmentation handler.
         */
        msg_id = ((nwk->src)<<8) + packet.counter;

        /* If this is the first block of a fragmented message, than the block
         * number field is the maximum number of blocks in the message. Otherwise
         * the block number is the block being sent.
         */
        if (packet.fragmentation == ZBEE_APS_EXT_FCF_FRAGMENT_FIRST) {
            fragment_set_tot_len(pinfo, msg_id, zbee_aps_fragment_table, packet.block_number);
            block_num = 0;  /* first packet. */
        }
        else {
            block_num = packet.block_number;
        }

        /* Add this fragment to the reassembly handler. */
        frag_msg = fragment_add_seq_check(payload_tvb, 0, pinfo, msg_id, zbee_aps_fragment_table,
                zbee_aps_reassembled_table, block_num, tvb_length(payload_tvb), TRUE);

        new_tvb = process_reassembled_data(payload_tvb, 0, pinfo, "Reassembled Packet" ,
                frag_msg, &zbee_aps_frag_items, NULL, aps_tree);

        /* Update the info column regarding the fragmentation. */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            if (frag_msg)   col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
            else            col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u)", packet.counter);
        }

        if (new_tvb) {
            /* The reassembly handler defragmented the message, and created a new tvbuff. */
            payload_tvb = new_tvb;
        }
        else {
            /* The reassembly handler could not defragment the message. */
            call_dissector(data_handle, payload_tvb, pinfo, tree);
            return;
        }
    }

    /* Handle the packet type. */
    switch (packet.type) {
        case ZBEE_APS_FCF_DATA:
            if (!payload_tvb) {
                break;
            }
            if (pinfo->zbee_stack_vers <= ZBEE_VERSION_2004) {
                /*
                 * In ZigBee 2004, an "application framework" sits between the
                 * APS and application. Call a subdissector to handle it.
                 */
                pinfo->private_data = profile_handle;
                profile_handle = zbee_apf_handle;
            }
            else if (profile_handle == NULL) {
                /* Could not locate a profile dissector. */
                break;
            }
            call_dissector(profile_handle, payload_tvb, pinfo, tree);
            return;

        case ZBEE_APS_FCF_CMD:
            if (!payload_tvb) {
                /* Command packets MUST contain a payload. */
                expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_ERROR, "Missing Payload");
                THROW(BoundsError);
                return;
            }
            dissect_zbee_aps_cmd(payload_tvb, pinfo, aps_tree);
            return;

        case ZBEE_APS_FCF_ACK:
            /* Acks should never contain a payload. */
            break;

        default:
            /* Illegal frame type.  */
            break;
    } /* switch */
    /*
     * If we get this far, then no subdissectors have been called, use the data
     * dissector to display the leftover bytes, if any.
     */
    if (payload_tvb) {
        call_dissector(data_handle, payload_tvb, pinfo, tree);
    }
} /* dissect_zbee_aps */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_cmd
 *  DESCRIPTION
 *      ZigBee APS sub-dissector for APS Command frames
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      proto_item *proto_root - pointer to the root of the APS tree
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void dissect_zbee_aps_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *cmd_root = NULL;
    proto_tree  *cmd_tree = NULL;

    guint       offset = 0;
    guint8      cmd_id = tvb_get_guint8(tvb, offset);

    /*  Create a subtree for the APS Command frame, and add the command ID to it. */
    if(tree){
        cmd_root = proto_tree_add_text(tree, tvb, offset, tvb_length(tvb), "Command Frame: %s", val_to_str(cmd_id, zbee_aps_cmd_names, "Unknown"));
        cmd_tree = proto_item_add_subtree(cmd_root, ett_zbee_aps_cmd);

        /* Add the command ID. */
        proto_tree_add_uint(cmd_tree, hf_zbee_aps_cmd_id, tvb, offset, sizeof(guint8), cmd_id);
    }
    offset += sizeof(guint8);

    /* Add the command name to the info column. */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str(cmd_id, zbee_aps_cmd_names, "Unknown Command"));
    }

    /* Handle the contents of the command frame. */
    switch(cmd_id){
        case ZBEE_APS_CMD_SKKE1:
        case ZBEE_APS_CMD_SKKE2:
            offset = dissect_zbee_aps_skke_challenge(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_SKKE3:
        case ZBEE_APS_CMD_SKKE4:
            offset = dissect_zbee_aps_skke_data(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_TRANSPORT_KEY:
            /* Transport Key Command. */
            offset = dissect_zbee_aps_transport_key(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_UPDATE_DEVICE:
            /* Update Device Command. */
            offset = dissect_zbee_aps_update_device(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_REMOVE_DEVICE:
            /* Remove Device. */
            offset = dissect_zbee_aps_remove_device(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_REQUEST_KEY:
            /* Request Key Command. */
            offset = dissect_zbee_aps_request_key(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_SWITCH_KEY:
            /* Switch Key Command. */
            offset = dissect_zbee_aps_switch_key(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_EA_INIT_CHLNG:
        case ZBEE_APS_CMD_EA_RESP_CHLNG:
            /* Entity Authentication Challenge Command. */
            offset = dissect_zbee_aps_auth_challenge(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_EA_INIT_MAC_DATA:
        case ZBEE_APS_CMD_EA_RESP_MAC_DATA:
            /* Entity Authentication Data Command. */
            offset = dissect_zbee_aps_auth_data(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_TUNNEL:
            /* Tunnel Command. */
            offset = dissect_zbee_aps_tunnel(tvb, pinfo, cmd_tree, offset);
            break;

        default:
            break;
    } /* switch */

    /* Check for any excess bytes. */
    if (offset < tvb_length(tvb)) {
        /* There are leftover bytes! */
        guint       leftover_len    = tvb_length(tvb) - offset;
        proto_tree  *root           = NULL;
        tvbuff_t    *leftover_tvb   = tvb_new_subset(tvb, offset, leftover_len, leftover_len);

        if (tree) {
            /* Get the APS Root. */
            root = proto_tree_get_root(tree);

            /* Correct the length of the command tree. */
            proto_item_set_len(cmd_root, offset);
        }

        /* Dump the leftover to the data dissector. */
        call_dissector(data_handle, leftover_tvb, pinfo, root);
    }
} /* dissect_zbee_aps_cmd */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_skke_challenge
 *  DESCRIPTION
 *      Helper dissector for the SKKE Challenge commands (SKKE1 and
 *      SKKE2).
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_skke_challenge(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint64 init;
    guint64 resp;

    /* Get and display the initiator address. */
    init = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_initiator, tvb, offset, sizeof(guint64), init);
    }
    offset += sizeof(guint64);

    /* Get and display the responder address. */
    resp = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_responder, tvb, offset, sizeof(guint64), resp);
    }
    offset += sizeof(guint64);

    /* Get and display the SKKE data. */
    tvb_ensure_bytes_exist(tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH);
    if (tree) {
        proto_tree_add_bytes(tree, hf_zbee_aps_cmd_challenge, tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH, ep_tvb_memdup(tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH));
    }
    offset += ZBEE_APS_CMD_SKKE_DATA_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_skke_challenge */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_skke_data
 *  DESCRIPTION
 *      Helper dissector for the SKKE Data commands (SKKE3 and
 *      SKKE4).
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_skke_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint64 init;
    guint64 resp;

    /* Get and display the initiator address. */
    init = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_initiator, tvb, offset, sizeof(guint64), init);
    }
    offset += sizeof(guint64);

    /* Get and display the responder address. */
    resp = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_responder, tvb, offset, sizeof(guint64), resp);
    }
    offset += sizeof(guint64);

    /* Get and display the SKKE data. */
    tvb_ensure_bytes_exist(tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH);
    if (tree) {
        proto_tree_add_bytes(tree, hf_zbee_aps_cmd_mac, tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH, ep_tvb_memdup(tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH));
    }
    offset += ZBEE_APS_CMD_SKKE_DATA_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_skke_data */

guint   dissect_zbee_aps_skke_data      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_transport_key
 *  DESCRIPTION
 *      Helper dissector for the Transport Key command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_transport_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  key_type;
    gchar   *key = ep_alloc(ZBEE_APS_CMD_KEY_LENGTH);
    guint   i;

    /* Get and display the key type. */
    key_type = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_key_type, tvb, offset, sizeof(guint8), key_type);
    }
    offset += sizeof(guint8);

    /* Coincidentally, all the key descriptors start with the key. So
     * get and display it.
     */
    for (i=0;i<ZBEE_APS_CMD_KEY_LENGTH; i++) {
        /* Copy the key in while swapping because the key is transmitted in little-endian
         * order, but we want to display it in big-endian.
         */
        key[(ZBEE_APS_CMD_KEY_LENGTH-1)-i] = tvb_get_guint8(tvb, offset+i);
    } /* for */
    if (tree) {
        proto_tree_add_bytes(tree, hf_zbee_aps_cmd_key, tvb, offset, ZBEE_APS_CMD_KEY_LENGTH, key);
    }
    offset += ZBEE_APS_CMD_KEY_LENGTH;

    /* Parse the rest of the key descriptor. */
    switch (key_type) {
        case ZBEE_APS_CMD_KEY_STANDARD_NWK:
        case ZBEE_APS_CMD_KEY_HIGH_SEC_NWK:{
            /* Network Key */
            guint8  seqno;
            guint64 src;
            guint64 dst;

            /* Get and display the sequence number. */
            seqno = tvb_get_guint8(tvb, offset);
            if (tree) {
                proto_tree_add_uint(tree, hf_zbee_aps_cmd_seqno, tvb, offset, sizeof(guint8), seqno);
            }
            offset += sizeof(guint8);

            /* Get and display the destination address. */
            dst = tvb_get_letoh64(tvb, offset);
            if (tree) {
                proto_tree_add_eui64(tree, hf_zbee_aps_cmd_dst, tvb, offset, sizeof(guint64), dst);
            }
            offset += sizeof(guint64);

            /* Get and display the source address. */
            src = tvb_get_letoh64(tvb, offset);
            if (tree) {
                proto_tree_add_eui64(tree, hf_zbee_aps_cmd_src, tvb, offset, sizeof(guint64), src);
            }
            offset += sizeof(guint64);

            break;
        }
        case ZBEE_APS_CMD_KEY_TC_MASTER:
        case ZBEE_APS_CMD_KEY_TC_LINK:{
            /* Trust Center master key. */
            guint64 src;
            guint64 dst;

            /* Get and display the destination address. */
            dst = tvb_get_letoh64(tvb, offset);
            if (tree) {
                proto_tree_add_eui64(tree, hf_zbee_aps_cmd_dst, tvb, offset, sizeof(guint64), dst);
            }
            offset += sizeof(guint64);

            /* Get and display the source address. */
            src = tvb_get_letoh64(tvb, offset);
            if (tree) {
                proto_tree_add_eui64(tree, hf_zbee_aps_cmd_src, tvb, offset, sizeof(guint64), src);
            }
            offset += sizeof(guint64);

            break;
        }
        case ZBEE_APS_CMD_KEY_APP_MASTER:
        case ZBEE_APS_CMD_KEY_APP_LINK:{
            /* Application master or link key, both have the same format. */
            guint64 partner;
            guint8  initiator;

            /* get and display the parter address.  */
            partner = tvb_get_letoh64(tvb, offset);
            if (tree) {
                proto_tree_add_eui64(tree, hf_zbee_aps_cmd_partner, tvb, offset, sizeof(guint64), partner);
            }
            offset += sizeof(guint64);

            /* get and display the initiator flag. */
            initiator = tvb_get_guint8(tvb, offset);
            if (tree) {
                proto_tree_add_boolean(tree, hf_zbee_aps_cmd_initiator_flag, tvb, offset, sizeof(guint8), initiator);
            }
            offset += sizeof(guint8);

            break;
        }
        default:
            break;
    } /* switch */

    /* Done */
    return offset;
} /* dissect_zbee_aps_transport_key */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_update_device
 *  DESCRIPTION
 *      Helper dissector for the Update Device command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_update_device(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint64 device;
    guint16 short_addr;
    guint8  status;

    /* Get and display the device address. */
    device = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_device, tvb, offset, sizeof(guint64), device);
    }
    offset += sizeof(guint64);

    /* Get and display the short address. Only on ZigBee 2006 and later. */
    if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
        short_addr = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(tree, hf_zbee_aps_cmd_short_addr, tvb, offset, sizeof(guint16), short_addr);
        }
        offset += sizeof(guint16);
    }

    /* Get and display the status. */
    status = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_device_status, tvb, offset, sizeof(guint8), status);
    }
    offset += sizeof(guint8);

    /* Done */
    return offset;
} /* dissect_zbee_aps_update_device */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_remove_device
 *  DESCRIPTION
 *      Helper dissector for the Remove Device command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_remove_device(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint64 device;

    /* Get and display the device address. */
    device = tvb_get_letoh64(tvb, offset);
    if(tree){
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_device, tvb, offset, sizeof(guint64), device);
    }
    offset += sizeof(guint64);

    /* Done */
    return offset;
} /* dissect_zbee_aps_remove_device */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_request_key
 *  DESCRIPTION
 *      Helper dissector for the Request Key command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_request_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  key_type;
    guint64 partner;

    /* Get and display the key type. */
    key_type = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_key_type, tvb, offset, sizeof(guint8), key_type);
    }
    offset += sizeof(guint8);

    /* Get and display the partner address. Only present on application master key. */
    if (key_type == ZBEE_APS_CMD_KEY_APP_MASTER) {
        partner = tvb_get_letoh64(tvb, offset);
        if (tree) {
            proto_tree_add_eui64(tree, hf_zbee_aps_cmd_partner, tvb, offset, sizeof(guint64), partner);
        }
        offset += sizeof(guint64);
    }

    /* Done */
    return offset;
} /* dissect_zbee_aps_request_key */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_switch_key
 *  DESCRIPTION
 *      Helper dissector for the Switch Key command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_switch_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  seqno;

    /* Get and display the sequence number. */
    seqno = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_seqno, tvb, offset, sizeof(guint8), seqno);
    }
    offset += sizeof(guint8);

    /* Done */
    return offset;
} /* dissect_zbee_aps_switch_key */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_auth_challenge
 *  DESCRIPTION
 *      Helper dissector for the Entity-Authentication Initiator
 *      or Responder challenge commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_auth_challenge(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  key_type;
    guint8  key_seqno;
    guint64 initiator;
    guint64 responder;

    /* Get and display the key type. */
    key_type = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_ea_key_type, tvb, offset, sizeof(guint8), key_type);
    }
    offset += sizeof(guint8);

    /* If using the network key, display the key sequence number. */
    if (key_type == ZBEE_APS_CMD_EA_KEY_NWK) {
        key_seqno = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(tree, hf_zbee_aps_cmd_seqno, tvb, offset, sizeof(guint8), key_seqno);
        }
        offset += sizeof(guint8);
    }

    /* Get and display the initiator address. */
    initiator = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_initiator, tvb, offset, sizeof(guint64), initiator);
    }
    offset += sizeof(guint64);

    /* Get and display the responder address. */
    responder = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_responder, tvb, offset, sizeof(guint64), responder);
    }
    offset += sizeof(guint64);

    /* Get and display the challenge. */
    tvb_ensure_bytes_exist(tvb, offset, ZBEE_APS_CMD_EA_CHALLENGE_LENGTH);
    if (tree) {
        proto_tree_add_bytes(tree, hf_zbee_aps_cmd_challenge, tvb, offset, ZBEE_APS_CMD_EA_CHALLENGE_LENGTH, ep_tvb_memdup(tvb, offset, ZBEE_APS_CMD_EA_CHALLENGE_LENGTH));
    }
    offset += ZBEE_APS_CMD_EA_CHALLENGE_LENGTH;

    /* Done*/
    return offset;
} /* dissect_zbee_aps_auth_challenge */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_auth_data
 *  DESCRIPTION
 *      Helper dissector for the Entity-Authentication Initiator
 *      or Responder data commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_auth_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  data_type;

    /* Get and display the MAC. */
    tvb_ensure_bytes_exist(tvb, offset, ZBEE_APS_CMD_EA_MAC_LENGTH);
    if (tree) {
        proto_tree_add_bytes(tree, hf_zbee_aps_cmd_mac, tvb, offset, ZBEE_APS_CMD_EA_MAC_LENGTH, ep_tvb_memdup(tvb, offset, ZBEE_APS_CMD_EA_MAC_LENGTH));
    }
    offset += ZBEE_APS_CMD_EA_MAC_LENGTH;

    /* Get and display the data type. */
    data_type = tvb_get_guint8(tvb, offset);
    if (tree) {
        /* Note! We're interpreting the DataType field to be the same as
         * KeyType field in the challenge frames. So far, this seems
         * consistent, although ZigBee appears to have left some holes
         * in the definition of the DataType and Data fields (ie: what
         * happens when KeyType == Link Key?)
         */
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_ea_key_type, tvb, offset, sizeof(guint8), data_type);
    }
    offset += sizeof(guint8);

    /* Get and display the data field. */
    tvb_ensure_bytes_exist(tvb, offset, ZBEE_APS_CMD_EA_DATA_LENGTH);
    if (tree) {
        proto_tree_add_bytes(tree, hf_zbee_aps_cmd_ea_data, tvb, offset, ZBEE_APS_CMD_EA_DATA_LENGTH, ep_tvb_memdup(tvb, offset, ZBEE_APS_CMD_EA_DATA_LENGTH));
    }
    offset += ZBEE_APS_CMD_EA_DATA_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_auth_data */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_aps_auth_data
 *  DESCRIPTION
 *      Helper dissector for the Tunnel command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
guint
dissect_zbee_aps_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint64     dst;
    proto_tree  *root = NULL;
    tvbuff_t    *tunnel_tvb;

    /* Get and display the destination address. */
    dst = tvb_get_letoh64(tvb, offset);
    if (tree) {
        proto_tree_add_eui64(tree, hf_zbee_aps_cmd_dst, tvb, offset, sizeof(guint64), dst);
    }
    offset += sizeof(guint64);

    /* The remainder is a tunneled APS frame. */
    tunnel_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
    if (tree) root = proto_tree_get_root(tree);
    call_dissector(zbee_aps_handle, tunnel_tvb, pinfo, root);
    offset = tvb_length(tvb);

    /* Done */
    return offset;
} /* dissect_zbee_aps_tunnel */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_apf
 *  DESCRIPTION
 *      ZigBee Application Framework dissector for Wireshark. Note
 *      that the Application Framework is deprecated as of ZigBee
 *      2006.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void dissect_zbee_apf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *apf_tree = NULL;
    proto_item  *proto_root;

    guint8      count;
    guint8      type;
    guint       offset = 0;
    guint       i;

    tvbuff_t    *app_tvb;

    dissector_handle_t  app_dissector = (pinfo->private_data);

    /* Create the tree for the application framework. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_zbee_apf, tvb, 0, tvb_length(tvb), "ZigBee Application Framework");
        apf_tree = proto_item_add_subtree(proto_root, ett_zbee_apf);
    }

    /* Get the count and type. */
    count   = get_bit_field(tvb_get_guint8(tvb, offset), ZBEE_APP_COUNT);
    type    = get_bit_field(tvb_get_guint8(tvb, offset), ZBEE_APP_TYPE);
    if (tree) {
        proto_tree_add_uint(apf_tree, hf_zbee_apf_count, tvb, offset, sizeof(guint8), count);
        proto_tree_add_uint(apf_tree, hf_zbee_apf_type, tvb, offset, sizeof(guint8), type);
    }
    offset += sizeof(guint8);

    /* Ensure the application dissector exists. */
    if (app_dissector == NULL) {
        /* No dissector for this profile. */
        goto dissect_app_end;
    }

    /* Handle the transactions. */
    for (i=0; i<count; i++) {
        guint       length;

        /* Create a tvb for this transaction. */
        length = zbee_apf_transaction_len(tvb, offset, type);
        app_tvb = tvb_new_subset(tvb, offset, length, length);

        /* Call the application dissector. */
        call_dissector(app_dissector, app_tvb, pinfo, tree);

        /* Adjust the offset. */
        offset += length;
    }

dissect_app_end:
    if (offset < tvb_length(tvb)) {
        /* There are bytes remaining! */
        app_tvb = tvb_new_subset(tvb, offset, -1, -1);
        call_dissector(data_handle, app_tvb, pinfo, tree);
    }
} /* dissect_zbee_apf */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_apf_transaction_len
 *  DESCRIPTION
 *      Peeks into the application framework, and determines the
 *      length of the transaction. Used only with the kludge that is
 *      the ZigBee 2004 & earlier application framework.
 *  PARAMETERS
 *      tvbuff_t *tvb       - packet buffer.
 *      guint    offset     - offset into the buffer.
 *      guint    type       - message type: KVP or MSG.
 *  RETURNS
 *      guint
 *---------------------------------------------------------------
 */
guint
zbee_apf_transaction_len(tvbuff_t *tvb, guint offset, guint8 type)
{
    if (type == ZBEE_APP_TYPE_KVP) {
        /* KVP Type. */
        /* | 1 Byte |    1 Byte     |  2 Bytes  | 0/1 Bytes  | Variable |
         * | SeqNo  | Cmd/Data Type | Attribute | Error Code |   Data   |
         */
        guint8  kvp_cmd     = get_bit_field(tvb_get_guint8(tvb, offset+1), ZBEE_APP_KVP_CMD);
        guint8  kvp_type    = get_bit_field(tvb_get_guint8(tvb, offset+1), ZBEE_APP_KVP_TYPE);
        guint   kvp_len     = ZBEE_APP_KVP_OVERHEAD;

        /* Add the length of the error code, if present. */
        switch (kvp_cmd) {
            case ZBEE_APP_KVP_SET_RESP:
            case ZBEE_APP_KVP_EVENT_RESP:
                /* Error Code Present. */
                kvp_len += sizeof(guint8);
                /* Data Not Present. */
                return kvp_len;
            case ZBEE_APP_KVP_GET_RESP:
                /* Error Code Present. */
                kvp_len += sizeof(guint8);
                /* Data Present. */
                break;
            case ZBEE_APP_KVP_SET:
            case ZBEE_APP_KVP_SET_ACK:
            case ZBEE_APP_KVP_EVENT:
            case ZBEE_APP_KVP_EVENT_ACK:
                /* No Error Code Present. */
                /* Data Present. */
                break;
            case ZBEE_APP_KVP_GET_ACK:
            default:
                /* No Error Code Present. */
                /* No Data Present. */
                return kvp_len;
        } /* switch */

        /* Add the length of the data. */
        switch (kvp_type) {
            case ZBEE_APP_KVP_ABS_TIME:
            case ZBEE_APP_KVP_REL_TIME:
                kvp_len += sizeof(guint32);
                break;
            case ZBEE_APP_KVP_UINT16:
            case ZBEE_APP_KVP_INT16:
            case ZBEE_APP_KVP_FLOAT16:
                kvp_len += sizeof(guint16);
                break;
            case ZBEE_APP_KVP_UINT8:
            case ZBEE_APP_KVP_INT8:
                kvp_len += sizeof(guint8);
                break;
            case ZBEE_APP_KVP_CHAR_STRING:
            case ZBEE_APP_KVP_OCT_STRING:
                /* Variable Length Types, first byte is the length-1 */
                kvp_len += tvb_get_guint8(tvb, offset+kvp_len)+1;
                break;
            case ZBEE_APP_KVP_NO_DATA:
            default:
                break;
        } /* switch */

        return kvp_len;
    }
    else {
        /* Message Type. */
        /* | 1 Byte | 1 Byte | Length Bytes |
         * | SeqNo  | Length |   Message    |
         */
        return (tvb_get_guint8(tvb, offset+1) + 2);
    }
} /* zbee_apf_transaction_len */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_aps
 *  DESCRIPTION
 *      ZigBee APS protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zbee_aps(void)
{
    static hf_register_info hf[] = {
            { &hf_zbee_aps_fcf_frame_type,
            { "Frame Type",             "zbee.aps.type", FT_UINT8, BASE_HEX, VALS(zbee_aps_frame_types), ZBEE_APS_FCF_FRAME_TYPE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_delivery,
            { "Delivery Mode",          "zbee.aps.delivery", FT_UINT8, BASE_HEX, VALS(zbee_aps_delivery_modes), ZBEE_APS_FCF_DELIVERY_MODE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_indirect_mode,
            { "Indirect Address Mode",  "zbee.aps.indirect_mode", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_INDIRECT_MODE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_ack_mode,
            { "Acknowledgement Mode",  "zbee.aps.ack_mode", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_ACK_MODE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_security,
            { "Security",               "zbee.aps.security", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_SECURITY,
                "Whether security operations are performed on the APS payload.", HFILL }},

            { &hf_zbee_aps_fcf_ack_req,
            { "Acknowledgement Request","zbee.aps.ack_req", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_ACK_REQ,
                "Flag requesting an acknowledgement frame for this packet.", HFILL }},

            { &hf_zbee_aps_fcf_ext_header,
            { "Extended Header",        "zbee.aps.ext_header", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_EXT_HEADER,
                NULL, HFILL }},

            { &hf_zbee_aps_dst,
            { "Destination Endpoint",   "zbee.aps.dst", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_group,
            { "Group",                  "zbee.aps.group", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cluster,
            { "Cluster",                "zbee.aps.cluster", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_profile,
            { "Profile",                "zbee.aps.profile", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_src,
            { "Source Endpoint",        "zbee.aps.src", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_counter,
            { "Counter",                "zbee.aps.counter", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragmentation,
            { "Fragmentation",          "zbee.aps.fragmentation", FT_UINT8, BASE_HEX, VALS(zbee_aps_fragmentation_modes), ZBEE_APS_EXT_FCF_FRAGMENT,
                NULL, HFILL }},

            { &hf_zbee_aps_block_number,
            { "Block Number",           "zbee.aps.block", FT_UINT8, BASE_DEC, NULL, 0x0,
                "A block identifier within a fragmented transmission, or the number of expected blocks if the first block.", HFILL }},

            { &hf_zbee_aps_cmd_id,
            { "Command Identifier",     "zbee.aps.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_aps_cmd_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_initiator,
            { "Initiator Address",      "zbee.aps.cmd.initiator", FT_UINT64, BASE_HEX, NULL, 0x0,
                "The extended address of the device to initiate the SKKE procedure", HFILL }},

            { &hf_zbee_aps_cmd_responder,
            { "Responder Address",      "zbee.aps.cmd.responder", FT_UINT64, BASE_HEX, NULL, 0x0,
                "The extended address of the device responding to the SKKE procedure", HFILL }},

            { &hf_zbee_aps_cmd_partner,
            { "Partner Address",        "zbee.aps.cmd.partner", FT_UINT64, BASE_HEX, NULL, 0x0,
                "The partner to use this key with for link-level security.", HFILL }},

            { &hf_zbee_aps_cmd_initiator_flag,
            { "Initiator",              "zbee.aps.cmd.init_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Inidicates the destination of the transport-key command requested this key.", HFILL }},

            { &hf_zbee_aps_cmd_device,
            { "Device Address",         "zbee.aps.cmd.device", FT_UINT64, BASE_HEX, NULL, 0x0,
                "The device whose status is being updated.", HFILL }},

            { &hf_zbee_aps_cmd_challenge,
            { "Challenge",              "zbee.aps.cmd.challenge", FT_BYTES, BASE_HEX, NULL, 0x0,
                "Random challenge value used during SKKE and authentication.", HFILL }},

            { &hf_zbee_aps_cmd_mac,
            { "Message Authentication Code",    "zbee.aps.cmd.mac", FT_BYTES, BASE_HEX, NULL, 0x0,
                "Message authentication values used during SKKE and authentication.", HFILL }},

            { &hf_zbee_aps_cmd_key,
            { "Key",                    "zbee.aps.cmd.key", FT_BYTES, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_key_type,
            { "Key Type",               "zbee.aps.cmd.key_type", FT_UINT8, BASE_HEX, VALS(zbee_aps_key_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_dst,
            { "Destination Address",    "zbee.aps.cmd.dst", FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_src,
            { "Source Address",         "zbee.aps.cmd.src", FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_seqno,
            { "Sequence Number",        "zbee.aps.cmd.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The key sequence number associated with the network key.", HFILL }},

            { &hf_zbee_aps_cmd_short_addr,
            { "Device Address",         "zbee.aps.cmd.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
                "The device whose status is being updated.", HFILL }},

            { &hf_zbee_aps_cmd_device_status,
            { "Device Status",          "zbee.aps.cmd.status", FT_UINT8, BASE_HEX, VALS(zbee_aps_update_status_names), 0x0,
                "Update device status.", HFILL }},

            { &hf_zbee_aps_cmd_ea_key_type,
            { "Key Type",               "zbee.aps.cmd.ea.key_type", FT_UINT8, BASE_HEX, VALS(zbee_aps_ea_key_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_ea_data,
            { "Data",                   "zbee.aps.cmd.ea.data", FT_BYTES, BASE_HEX, NULL, 0x0,
                "Additional data used in entity authentication. Typically this will be the outgoing frame counter associated with the key used for entity authentication.", HFILL }},

            { &hf_zbee_aps_fragments,
            { "Message fragments",      "zbee.aps.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment,
            { "Message fragment",       "zbee.aps.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_overlap,
            { "Message fragment overlap",       "zbee.aps.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "zbee.aps.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_multiple_tails,
            { "Message has multiple tail fragments", "zbee.aps.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_too_long_fragment,
            { "Message fragment too long",      "zbee.aps.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_error,
            { "Message defragmentation error",  "zbee.aps.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_reassembled_in,
            { "Reassembled in",         "zbee.aps.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }}
    };

    static hf_register_info hf_apf[] = {
            { &hf_zbee_apf_count,
            { "Count",                  "zbee.app.count", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_apf_type,
            { "Type",                   "zbee.app.type", FT_UINT8, BASE_HEX, VALS(zbee_apf_type_names), 0x0,
                NULL, HFILL }}
    };

    /*  APS subtrees */
    static gint *ett[] = {
        &ett_zbee_aps,
        &ett_zbee_aps_fcf,
        &ett_zbee_aps_ext,
        &ett_zbee_aps_cmd,
        &ett_zbee_aps_fragment,
        &ett_zbee_aps_fragments
    };

    static gint *ett_apf[] = {
        &ett_zbee_apf
    };

    /* Register ZigBee APS protocol with Wireshark. */
    proto_zbee_aps = proto_register_protocol("ZigBee Application Support Layer", "ZigBee APS", "zbee.aps");
    proto_register_field_array(proto_zbee_aps, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the APS dissector and subdissector list. */
    zbee_aps_dissector_table = register_dissector_table("zbee.profile", "ZigBee Profile ID", FT_UINT16, BASE_HEX);
    register_dissector("zbee.aps", dissect_zbee_aps, proto_zbee_aps);

    /* Register the init routine. */
    register_init_routine(proto_init_zbee_aps);

    /* Register the ZigBee Application Framework protocol with Wireshark. */
    proto_zbee_apf = proto_register_protocol("ZigBee Application Framework", "ZigBee APF", "zbee.apf");
    proto_register_field_array(proto_zbee_apf, hf_apf, array_length(hf_apf));
    proto_register_subtree_array(ett_apf, array_length(ett_apf));

    /* Register the App dissector. */
    register_dissector("zbee.apf", dissect_zbee_apf, proto_zbee_apf);
} /* proto_register_zbee_aps */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_aps
 *  DESCRIPTION
 *      Registers the zigbee APS dissector with Wireshark.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_aps(void)
{
    /* Find the other dissectors we need. */
    data_handle     = find_dissector("data");
    zbee_aps_handle = find_dissector("zbee.aps");
    zbee_apf_handle = find_dissector("zbee.apf");
} /* proto_reg_handoff_zbee_aps */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_init_zbee_aps
 *  DESCRIPTION
 *      Initializes the APS dissectors prior to beginning protocol
 *      dissection.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_init_zbee_aps(void)
{
    fragment_table_init(&zbee_aps_fragment_table);
    reassembled_table_init(&zbee_aps_reassembled_table);
} /* proto_init_zbee_aps */
