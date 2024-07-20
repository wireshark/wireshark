/* packet-zbee-aps.c
 * Dissector routines for the ZigBee Application Support Sub-layer (APS)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>    /* req'd for packet-zbee-security.h */
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/proto_data.h>

#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-security.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zdp.h"
#include "packet-zbee-tlv.h"

/*************************
 * Function Declarations *
 *************************
 */
/* Dissector Routines */
static void    dissect_zbee_aps_cmd        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version, void *data);

/* Command Dissector Helpers */
static unsigned   dissect_zbee_aps_skke_challenge (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_skke_data      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_transport_key  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_update_device  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint8_t version);
static unsigned   dissect_zbee_aps_remove_device  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_request_key    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_switch_key     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_auth_challenge (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_auth_data      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_tunnel         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, void *data);
static unsigned   dissect_zbee_aps_verify_key     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_aps_confirm_key    (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned   dissect_zbee_t2                 (tvbuff_t *tvb, proto_tree *tree, uint16_t cluster_id);

/* Helper routine. */
static unsigned   zbee_apf_transaction_len    (tvbuff_t *tvb, unsigned offset, uint8_t type);

void dissect_zbee_aps_status_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
void proto_register_zbee_aps(void);

/********************
 * Global Variables *
 ********************
 */
/* Field indices. */
static int proto_zbee_aps;
static int hf_zbee_aps_fcf_frame_type;
static int hf_zbee_aps_fcf_delivery;
static int hf_zbee_aps_fcf_indirect_mode;  /* ZigBee 2004 and earlier. */
static int hf_zbee_aps_fcf_ack_format;       /* ZigBee 2007 and later. */
static int hf_zbee_aps_fcf_security;
static int hf_zbee_aps_fcf_ack_req;
static int hf_zbee_aps_fcf_ext_header;
static int hf_zbee_aps_dst;
static int hf_zbee_aps_group;
static int hf_zbee_aps_cluster;
static int hf_zbee_aps_profile;
static int hf_zbee_aps_src;
static int hf_zbee_aps_counter;
static int hf_zbee_aps_fragmentation;
static int hf_zbee_aps_block_number;
static int hf_zbee_aps_block_ack;
static int hf_zbee_aps_block_ack1;
static int hf_zbee_aps_block_ack2;
static int hf_zbee_aps_block_ack3;
static int hf_zbee_aps_block_ack4;
static int hf_zbee_aps_block_ack5;
static int hf_zbee_aps_block_ack6;
static int hf_zbee_aps_block_ack7;
static int hf_zbee_aps_block_ack8;

static int hf_zbee_aps_cmd_id;
static int hf_zbee_aps_cmd_initiator;
static int hf_zbee_aps_cmd_responder;
static int hf_zbee_aps_cmd_partner;
static int hf_zbee_aps_cmd_initiator_flag;
static int hf_zbee_aps_cmd_device;
static int hf_zbee_aps_cmd_challenge;
static int hf_zbee_aps_cmd_mac;
static int hf_zbee_aps_cmd_key;
static int hf_zbee_aps_cmd_key_hash;
static int hf_zbee_aps_cmd_key_type;
static int hf_zbee_aps_cmd_dst;
static int hf_zbee_aps_cmd_src;
static int hf_zbee_aps_cmd_seqno;
static int hf_zbee_aps_cmd_short_addr;
static int hf_zbee_aps_cmd_device_status;
static int hf_zbee_aps_cmd_status;
static int hf_zbee_aps_cmd_ea_key_type;
static int hf_zbee_aps_cmd_ea_data;

/* Field indices for ZigBee 2003 & earlier Application Framework. */
static int proto_zbee_apf;
static int hf_zbee_apf_count;
static int hf_zbee_apf_type;

/* Subtree indices. */
static int ett_zbee_aps;
static int ett_zbee_aps_fcf;
static int ett_zbee_aps_ext;
static int ett_zbee_aps_cmd;

/* Fragmentation indices. */
static int hf_zbee_aps_fragments;
static int hf_zbee_aps_fragment;
static int hf_zbee_aps_fragment_overlap;
static int hf_zbee_aps_fragment_overlap_conflicts;
static int hf_zbee_aps_fragment_multiple_tails;
static int hf_zbee_aps_fragment_too_long_fragment;
static int hf_zbee_aps_fragment_error;
static int hf_zbee_aps_fragment_count;
static int hf_zbee_aps_reassembled_in;
static int hf_zbee_aps_reassembled_length;
static int ett_zbee_aps_fragment;
static int ett_zbee_aps_fragments;

/* Test Profile #2 indices. */
static int hf_zbee_aps_t2_cluster;
static int hf_zbee_aps_t2_btres_octet_sequence;
static int hf_zbee_aps_t2_btres_octet_sequence_length_requested;
static int hf_zbee_aps_t2_btres_status;
static int hf_zbee_aps_t2_btreq_octet_sequence_length;

/* ZDP indices. */
static int hf_zbee_aps_zdp_cluster;

/* Subtree indices for the ZigBee 2004 & earlier Application Framework. */
static int ett_zbee_apf;
static int ett_zbee_aps_frag_ack;

/* Subtree indices for the ZigBee Test Profile #2. */
static int ett_zbee_aps_t2;

static expert_field ei_zbee_aps_invalid_delivery_mode;
static expert_field ei_zbee_aps_missing_payload;

/* Dissector Handles. */
static dissector_handle_t   zbee_aps_handle;
static dissector_handle_t   zbee_apf_handle;

/* Dissector List. */
static dissector_table_t    zbee_aps_dissector_table;

/* Reassembly table. */
static reassembly_table     zbee_aps_reassembly_table;

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
    &hf_zbee_aps_fragment_count,
    /* Reassembled in field */
    &hf_zbee_aps_reassembled_in,
    /* Reassembled length field */
    &hf_zbee_aps_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "APS Message fragments"
};

static GHashTable *zbee_table_aps_extended_counters;

/********************/
/* Field Names      */
/********************/
/* Frame Type Names */
static const value_string zbee_aps_frame_types[] = {
    { ZBEE_APS_FCF_DATA,            "Data" },
    { ZBEE_APS_FCF_CMD,             "Command" },
    { ZBEE_APS_FCF_ACK,             "Ack" },
    { ZBEE_APS_FCF_INTERPAN,        "Interpan" },
    { 0, NULL }
};

/* Delivery Mode Names */
static const value_string zbee_aps_delivery_modes[] = {
    { ZBEE_APS_FCF_UNICAST,         "Unicast" },
    { ZBEE_APS_FCF_INDIRECT,        "Indirect" },
    { ZBEE_APS_FCF_BCAST,           "Broadcast" },
    { ZBEE_APS_FCF_GROUP,           "Group" },
    { 0, NULL }
};

/* Fragmentation Mode Names */
static const value_string zbee_aps_fragmentation_modes[] = {
    { ZBEE_APS_EXT_FCF_FRAGMENT_NONE,   "None" },
    { ZBEE_APS_EXT_FCF_FRAGMENT_FIRST,  "First Block" },
    { ZBEE_APS_EXT_FCF_FRAGMENT_MIDDLE, "Middle Block" },
    { 0, NULL }
};

/* APS Command Names */
static const value_string zbee_aps_cmd_names[] = {
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
    { ZBEE_APS_CMD_VERIFY_KEY,      "Verify Key" },
    { ZBEE_APS_CMD_CONFIRM_KEY,     "Confirm Key" },
    { ZBEE_APS_CMD_RELAY_MSG_DOWNSTREAM, "Relay Message Downstream" },
    { ZBEE_APS_CMD_RELAY_MSG_UPSTREAM,   "Relay Message Upstream" },
    { 0, NULL }
};

/* APS Key Names */
static const value_string zbee_aps_key_names[] = {
    { ZBEE_APS_CMD_KEY_TC_MASTER,       "Trust Center Master Key" },
    { ZBEE_APS_CMD_KEY_STANDARD_NWK,    "Standard Network Key" },
    { ZBEE_APS_CMD_KEY_APP_MASTER,      "Application Master Key" },
    { ZBEE_APS_CMD_KEY_APP_LINK,        "Application Link Key" },
    { ZBEE_APS_CMD_KEY_TC_LINK,         "Trust Center Link Key" },
    { ZBEE_APS_CMD_KEY_HIGH_SEC_NWK,    "High-Security Network Key" },
    { 0, NULL }
};

/* APS Key Names (Entity-Authentication). */
static const value_string zbee_aps_ea_key_names[] = {
    { ZBEE_APS_CMD_EA_KEY_NWK,          "Network Key" },
    { ZBEE_APS_CMD_EA_KEY_LINK,         "Link Key" },
    { 0, NULL }
};

/* Update Device Status Names */
static const value_string zbee_aps_update_status_names[] = {
    { ZBEE_APS_CMD_UPDATE_STANDARD_SEC_REJOIN,  "Standard security, secured rejoin" },
    { ZBEE_APS_CMD_UPDATE_STANDARD_UNSEC_JOIN,  "Standard security, unsecured join" },
    { ZBEE_APS_CMD_UPDATE_LEAVE,                "Device left" },
    { ZBEE_APS_CMD_UPDATE_STANDARD_UNSEC_REJOIN,"Standard security, unsecured rejoin" },
    { ZBEE_APS_CMD_UPDATE_HIGH_SEC_REJOIN,      "High security, secured rejoin" },
    { ZBEE_APS_CMD_UPDATE_HIGH_UNSEC_JOIN,      "High security, unsecured join" },
    { ZBEE_APS_CMD_UPDATE_HIGH_UNSEC_REJOIN,    "High security, unsecured rejoin" },
    { 0, NULL }
};


/* Update Device Status Names */
static const value_string zbee_aps_status_names[] = {
    { ZBEE_APP_STATUS_SUCCESS,               "SUCCESS" },
    { ZBEE_APP_STATUS_ASDU_TOO_LONG,         "ASDU_TOO_LONG" },
    { ZBEE_APP_STATUS_DEFRAG_DEFERRED,       "DEFRAG_DEFERRED" },
    { ZBEE_APP_STATUS_DEFRAG_UNSUPPORTED,    "DEFRAG_UNSUPPORTED" },
    { ZBEE_APP_STATUS_ILLEGAL_REQUEST,       "ILLEGAL_REQUEST" },
    { ZBEE_APP_STATUS_INVALID_BINDING,       "INVALID_BINDING" },
    { ZBEE_APP_STATUS_INVALID_GROUP,         "INVALID_GROUP" },
    { ZBEE_APP_STATUS_INVALID_PARAMETER,     "INVALID_PARAMETER" },
    { ZBEE_APP_STATUS_NO_ACK,                "NO_ACK" },
    { ZBEE_APP_STATUS_NO_BOUND_DEVICE,       "NO_BOUND_DEVICE" },
    { ZBEE_APP_STATUS_NO_SHORT_ADDRESS,      "NO_SHORT_ADDRESS" },
    { ZBEE_APP_STATUS_NOT_SUPPORTED,         "NOT_SUPPORTED" },
    { ZBEE_APP_STATUS_SECURED_LINK_KEY,      "SECURED_LINK_KEY" },
    { ZBEE_APP_STATUS_SECURED_NWK_KEY,       "SECURED_NWK_KEY" },
    { ZBEE_APP_STATUS_SECURITY_FAIL,         "SECURITY_FAIL" },
    { ZBEE_APP_STATUS_TABLE_FULL,            "TABLE_FULL" },
    { ZBEE_APP_STATUS_UNSECURED,             "UNSECURED" },
    { ZBEE_APP_STATUS_UNSUPPORTED_ATTRIBUTE, "UNSUPPORTED_ATTRIBUTE" },
    { 0, NULL }
};


/* Outdated ZigBee 2004 Value Strings. */
static const value_string zbee_apf_type_names[] = {
    { ZBEE_APP_TYPE_KVP,    "Key-Value Pair" },
    { ZBEE_APP_TYPE_MSG,    "Message" },
    { 0, NULL }
};

#if 0
static const value_string zbee_apf_kvp_command_names[] = {
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
#endif

#if 0
static const value_string zbee_apf_kvp_type_names[] = {
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
#endif

/* ZigBee Application Profile ID Names */
const range_string zbee_aps_apid_names[] = {
    { ZBEE_DEVICE_PROFILE,  ZBEE_DEVICE_PROFILE,            "ZigBee Device Profile" },

    { ZBEE_PROFILE_IPM,     ZBEE_PROFILE_IPM,               "Industrial Plant Monitoring" },

    { ZBEE_PROFILE_T1,      ZBEE_PROFILE_T1,                "Test Profile #1" },
    { ZBEE_PROFILE_HA,      ZBEE_PROFILE_HA,                "Home Automation" },
    { ZBEE_PROFILE_CBA,     ZBEE_PROFILE_CBA,               "Commercial Building Automation" },
    { ZBEE_PROFILE_WSN,     ZBEE_PROFILE_WSN,               "Wireless Sensor Network" },
    { ZBEE_PROFILE_TA,      ZBEE_PROFILE_TA,                "Telecom Automation" },
    { ZBEE_PROFILE_HC,      ZBEE_PROFILE_HC,                "Health Care" },
    { ZBEE_PROFILE_SE,      ZBEE_PROFILE_SE,                "Smart Energy" },
    { ZBEE_PROFILE_RS,      ZBEE_PROFILE_RS,                "Retail Services" },
    { ZBEE_PROFILE_STD_MIN, ZBEE_PROFILE_STD_MAX,           "Unknown ZigBee Standard" },

    { ZBEE_PROFILE_T2,      ZBEE_PROFILE_T2,                "Test Profile #2" },
    { ZBEE_PROFILE_GP,      ZBEE_PROFILE_GP,                "Green Power" },
    { ZBEE_PROFILE_RSVD0_MIN,   ZBEE_PROFILE_RSVD0_MAX,     "Unknown ZigBee Reserved" },
    { ZBEE_PROFILE_RSVD1_MIN,   ZBEE_PROFILE_RSVD1_MAX,     "Unknown ZigBee Reserved" },

    { ZBEE_PROFILE_IEEE_1451_5, ZBEE_PROFILE_IEEE_1451_5,   "IEEE_1451_5" },

    { ZBEE_PROFILE_MFR_SPEC_ORG_MIN,    ZBEE_PROFILE_MFR_SPEC_ORG_MAX,
            "Unallocated Manufacturer-Specific" },

    /* Manufacturer Allocations */
    { ZBEE_PROFILE_CIRRONET_0_MIN,  ZBEE_PROFILE_CIRRONET_0_MAX,    ZBEE_MFG_CIRRONET },
    { ZBEE_PROFILE_CHIPCON_MIN,     ZBEE_PROFILE_CHIPCON_MAX,       ZBEE_MFG_CHIPCON },
    { ZBEE_PROFILE_EMBER_MIN,       ZBEE_PROFILE_EMBER_MAX,         ZBEE_MFG_EMBER },
    { ZBEE_PROFILE_NTS_MIN,         ZBEE_PROFILE_NTS_MAX,           ZBEE_MFG_CHIPCON },
    { ZBEE_PROFILE_FREESCALE_MIN,   ZBEE_PROFILE_FREESCALE_MAX,     ZBEE_MFG_FREESCALE },
    { ZBEE_PROFILE_IPCOM_MIN,       ZBEE_PROFILE_IPCOM_MAX,         ZBEE_MFG_IPCOM },
    { ZBEE_PROFILE_SAN_JUAN_MIN,    ZBEE_PROFILE_SAN_JUAN_MAX,      ZBEE_MFG_SAN_JUAN },
    { ZBEE_PROFILE_TUV_MIN,         ZBEE_PROFILE_TUV_MAX,           ZBEE_MFG_TUV },
    { ZBEE_PROFILE_COMPXS_MIN,      ZBEE_PROFILE_COMPXS_MAX,        ZBEE_MFG_COMPXS },
    { ZBEE_PROFILE_BM_MIN,          ZBEE_PROFILE_BM_MAX,            ZBEE_MFG_BM },
    { ZBEE_PROFILE_AWAREPOINT_MIN,  ZBEE_PROFILE_AWAREPOINT_MAX,    ZBEE_MFG_AWAREPOINT },
    { ZBEE_PROFILE_SAN_JUAN_1_MIN,  ZBEE_PROFILE_SAN_JUAN_1_MAX,    ZBEE_MFG_SAN_JUAN },
    { ZBEE_PROFILE_ZLL,             ZBEE_PROFILE_ZLL,               "ZLL" },
    { ZBEE_PROFILE_PHILIPS_MIN,     ZBEE_PROFILE_PHILIPS_MAX,       ZBEE_MFG_PHILIPS },
    { ZBEE_PROFILE_LUXOFT_MIN,      ZBEE_PROFILE_LUXOFT_MAX,        ZBEE_MFG_LUXOFT },
    { ZBEE_PROFILE_KORWIN_MIN,      ZBEE_PROFILE_KORWIN_MAX,        ZBEE_MFG_KORWIN },
    { ZBEE_PROFILE_1_RF_MIN,        ZBEE_PROFILE_1_RF_MAX,          ZBEE_MFG_1_RF },
    { ZBEE_PROFILE_STG_MIN,         ZBEE_PROFILE_STG_MAX,           ZBEE_MFG_STG },
    { ZBEE_PROFILE_TELEGESIS_MIN,   ZBEE_PROFILE_TELEGESIS_MAX,     ZBEE_MFG_TELEGESIS },
    { ZBEE_PROFILE_CIRRONET_1_MIN,  ZBEE_PROFILE_CIRRONET_1_MAX,    ZBEE_MFG_CIRRONET },
    { ZBEE_PROFILE_VISIONIC_MIN,    ZBEE_PROFILE_VISIONIC_MAX,      ZBEE_MFG_VISIONIC },
    { ZBEE_PROFILE_INSTA_MIN,       ZBEE_PROFILE_INSTA_MAX,         ZBEE_MFG_INSTA },
    { ZBEE_PROFILE_ATALUM_MIN,      ZBEE_PROFILE_ATALUM_MAX,        ZBEE_MFG_ATALUM },
    { ZBEE_PROFILE_ATMEL_MIN,       ZBEE_PROFILE_ATMEL_MAX,         ZBEE_MFG_ATMEL },
    { ZBEE_PROFILE_DEVELCO_MIN,     ZBEE_PROFILE_DEVELCO_MAX,       ZBEE_MFG_DEVELCO },
    { ZBEE_PROFILE_HONEYWELL_MIN,   ZBEE_PROFILE_HONEYWELL_MAX,     ZBEE_MFG_HONEYWELL },
    { ZBEE_PROFILE_NEC_MIN,         ZBEE_PROFILE_NEC_MAX,           ZBEE_MFG_NEC },
    { ZBEE_PROFILE_YAMATAKE_MIN,    ZBEE_PROFILE_YAMATAKE_MAX,      ZBEE_MFG_YAMATAKE },
    { ZBEE_PROFILE_TENDRIL_MIN,     ZBEE_PROFILE_TENDRIL_MAX,       ZBEE_MFG_TENDRIL },
    { ZBEE_PROFILE_ASSA_MIN,        ZBEE_PROFILE_ASSA_MAX,          ZBEE_MFG_ASSA },
    { ZBEE_PROFILE_MAXSTREAM_MIN,   ZBEE_PROFILE_MAXSTREAM_MAX,     ZBEE_MFG_MAXSTREAM },
    { ZBEE_PROFILE_XANADU_MIN,      ZBEE_PROFILE_XANADU_MAX,        ZBEE_MFG_XANADU },
    { ZBEE_PROFILE_NEUROCOM_MIN,    ZBEE_PROFILE_NEUROCOM_MAX,      ZBEE_MFG_NEUROCOM },
    { ZBEE_PROFILE_III_MIN,         ZBEE_PROFILE_III_MAX,           ZBEE_MFG_III },
    { ZBEE_PROFILE_VANTAGE_MIN,     ZBEE_PROFILE_VANTAGE_MAX,       ZBEE_MFG_VANTAGE },
    { ZBEE_PROFILE_ICONTROL_MIN,    ZBEE_PROFILE_ICONTROL_MAX,      ZBEE_MFG_ICONTROL },
    { ZBEE_PROFILE_RAYMARINE_MIN,   ZBEE_PROFILE_RAYMARINE_MAX,     ZBEE_MFG_RAYMARINE },
    { ZBEE_PROFILE_RENESAS_MIN,     ZBEE_PROFILE_RENESAS_MAX,       ZBEE_MFG_RENESAS },
    { ZBEE_PROFILE_LSR_MIN,         ZBEE_PROFILE_LSR_MAX,           ZBEE_MFG_LSR },
    { ZBEE_PROFILE_ONITY_MIN,       ZBEE_PROFILE_ONITY_MAX,         ZBEE_MFG_ONITY },
    { ZBEE_PROFILE_MONO_MIN,        ZBEE_PROFILE_MONO_MAX,          ZBEE_MFG_MONO },
    { ZBEE_PROFILE_RFT_MIN,         ZBEE_PROFILE_RFT_MAX,           ZBEE_MFG_RFT },
    { ZBEE_PROFILE_ITRON_MIN,       ZBEE_PROFILE_ITRON_MAX,         ZBEE_MFG_ITRON },
    { ZBEE_PROFILE_TRITECH_MIN,     ZBEE_PROFILE_TRITECH_MAX,       ZBEE_MFG_TRITECH },
    { ZBEE_PROFILE_EMBEDIT_MIN,     ZBEE_PROFILE_EMBEDIT_MAX,       ZBEE_MFG_EMBEDIT },
    { ZBEE_PROFILE_S3C_MIN,         ZBEE_PROFILE_S3C_MAX,           ZBEE_MFG_S3C },
    { ZBEE_PROFILE_SIEMENS_MIN,     ZBEE_PROFILE_SIEMENS_MAX,       ZBEE_MFG_SIEMENS },
    { ZBEE_PROFILE_MINDTECH_MIN,    ZBEE_PROFILE_MINDTECH_MAX,      ZBEE_MFG_MINDTECH },
    { ZBEE_PROFILE_LGE_MIN,         ZBEE_PROFILE_LGE_MAX,           ZBEE_MFG_LGE },
    { ZBEE_PROFILE_MITSUBISHI_MIN,  ZBEE_PROFILE_MITSUBISHI_MAX,    ZBEE_MFG_MITSUBISHI },
    { ZBEE_PROFILE_JOHNSON_MIN,     ZBEE_PROFILE_JOHNSON_MAX,       ZBEE_MFG_JOHNSON },
    { ZBEE_PROFILE_PRI_MIN,         ZBEE_PROFILE_PRI_MAX,           ZBEE_MFG_PRI },
    { ZBEE_PROFILE_KNICK_MIN,       ZBEE_PROFILE_KNICK_MAX,         ZBEE_MFG_KNICK },
    { ZBEE_PROFILE_VICONICS_MIN,    ZBEE_PROFILE_VICONICS_MAX,      ZBEE_MFG_VICONICS },
    { ZBEE_PROFILE_FLEXIPANEL_MIN,  ZBEE_PROFILE_FLEXIPANEL_MAX,    ZBEE_MFG_FLEXIPANEL },
    { ZBEE_PROFILE_TRANE_MIN,       ZBEE_PROFILE_TRANE_MAX,         ZBEE_MFG_TRANE },
    { ZBEE_PROFILE_JENNIC_MIN,      ZBEE_PROFILE_JENNIC_MAX,        ZBEE_MFG_JENNIC },
    { ZBEE_PROFILE_LIG_MIN,         ZBEE_PROFILE_LIG_MAX,           ZBEE_MFG_LIG },
    { ZBEE_PROFILE_ALERTME_MIN,     ZBEE_PROFILE_ALERTME_MAX,       ZBEE_MFG_ALERTME },
    { ZBEE_PROFILE_DAINTREE_MIN,    ZBEE_PROFILE_DAINTREE_MAX,      ZBEE_MFG_DAINTREE },
    { ZBEE_PROFILE_AIJI_MIN,        ZBEE_PROFILE_AIJI_MAX,          ZBEE_MFG_AIJI },
    { ZBEE_PROFILE_TEL_ITALIA_MIN,  ZBEE_PROFILE_TEL_ITALIA_MAX,    ZBEE_MFG_TEL_ITALIA },
    { ZBEE_PROFILE_MIKROKRETS_MIN,  ZBEE_PROFILE_MIKROKRETS_MAX,    ZBEE_MFG_MIKROKRETS },
    { ZBEE_PROFILE_OKI_MIN,         ZBEE_PROFILE_OKI_MAX,           ZBEE_MFG_OKI },
    { ZBEE_PROFILE_NEWPORT_MIN,     ZBEE_PROFILE_NEWPORT_MAX,       ZBEE_MFG_NEWPORT },

    { ZBEE_PROFILE_C4_CL,           ZBEE_PROFILE_C4_CL,             ZBEE_MFG_C4 " Cluster Library"},
    { ZBEE_PROFILE_C4_MIN,          ZBEE_PROFILE_C4_MAX,            ZBEE_MFG_C4 },

    { ZBEE_PROFILE_STM_MIN,         ZBEE_PROFILE_STM_MAX,           ZBEE_MFG_STM },
    { ZBEE_PROFILE_ASN_0_MIN,       ZBEE_PROFILE_ASN_0_MAX,         ZBEE_MFG_ASN },
    { ZBEE_PROFILE_DCSI_MIN,        ZBEE_PROFILE_DCSI_MAX,          ZBEE_MFG_DCSI },
    { ZBEE_PROFILE_FRANCE_TEL_MIN,  ZBEE_PROFILE_FRANCE_TEL_MAX,    ZBEE_MFG_FRANCE_TEL },
    { ZBEE_PROFILE_MUNET_MIN,       ZBEE_PROFILE_MUNET_MAX,         ZBEE_MFG_MUNET },
    { ZBEE_PROFILE_AUTANI_MIN,      ZBEE_PROFILE_AUTANI_MAX,        ZBEE_MFG_AUTANI },
    { ZBEE_PROFILE_COL_VNET_MIN,    ZBEE_PROFILE_COL_VNET_MAX,      ZBEE_MFG_COL_VNET },
    { ZBEE_PROFILE_AEROCOMM_MIN,    ZBEE_PROFILE_AEROCOMM_MAX,      ZBEE_MFG_AEROCOMM },
    { ZBEE_PROFILE_SI_LABS_MIN,     ZBEE_PROFILE_SI_LABS_MAX,       ZBEE_MFG_SI_LABS },
    { ZBEE_PROFILE_INNCOM_MIN,      ZBEE_PROFILE_INNCOM_MAX,        ZBEE_MFG_INNCOM },
    { ZBEE_PROFILE_CANNON_MIN,      ZBEE_PROFILE_CANNON_MAX,        ZBEE_MFG_CANNON },
    { ZBEE_PROFILE_SYNAPSE_MIN,     ZBEE_PROFILE_SYNAPSE_MAX,       ZBEE_MFG_SYNAPSE },
    { ZBEE_PROFILE_FPS_MIN,         ZBEE_PROFILE_FPS_MAX,           ZBEE_MFG_FPS },
    { ZBEE_PROFILE_CLS_MIN,         ZBEE_PROFILE_CLS_MAX,           ZBEE_MFG_CLS },
    { ZBEE_PROFILE_CRANE_MIN,       ZBEE_PROFILE_CRANE_MAX,         ZBEE_MFG_CRANE },
    { ZBEE_PROFILE_ASN_1_MIN,       ZBEE_PROFILE_ASN_1_MAX,         ZBEE_MFG_ASN },
    { ZBEE_PROFILE_MOBILARM_MIN,    ZBEE_PROFILE_MOBILARM_MAX,      ZBEE_MFG_MOBILARM },
    { ZBEE_PROFILE_IMONITOR_MIN,    ZBEE_PROFILE_IMONITOR_MAX,      ZBEE_MFG_IMONITOR },
    { ZBEE_PROFILE_BARTECH_MIN,     ZBEE_PROFILE_BARTECH_MAX,       ZBEE_MFG_BARTECH },
    { ZBEE_PROFILE_MESHNETICS_MIN,  ZBEE_PROFILE_MESHNETICS_MAX,    ZBEE_MFG_MESHNETICS },
    { ZBEE_PROFILE_LS_IND_MIN,      ZBEE_PROFILE_LS_IND_MAX,        ZBEE_MFG_LS_IND },
    { ZBEE_PROFILE_CASON_MIN,       ZBEE_PROFILE_CASON_MAX,         ZBEE_MFG_CASON },
    { ZBEE_PROFILE_WLESS_GLUE_MIN,  ZBEE_PROFILE_WLESS_GLUE_MAX,    ZBEE_MFG_WLESS_GLUE },
    { ZBEE_PROFILE_ELSTER_MIN,      ZBEE_PROFILE_ELSTER_MAX,        ZBEE_MFG_ELSTER },
    { ZBEE_PROFILE_ONSET_MIN,       ZBEE_PROFILE_ONSET_MAX,         ZBEE_MFG_ONSET },
    { ZBEE_PROFILE_RIGA_MIN,        ZBEE_PROFILE_RIGA_MAX,          ZBEE_MFG_RIGA },
    { ZBEE_PROFILE_ENERGATE_MIN,    ZBEE_PROFILE_ENERGATE_MAX,      ZBEE_MFG_ENERGATE },
    { ZBEE_PROFILE_VANTAGE_1_MIN,   ZBEE_PROFILE_VANTAGE_1_MAX,     ZBEE_MFG_VANTAGE },
    { ZBEE_PROFILE_CONMED_MIN,      ZBEE_PROFILE_CONMED_MAX,        ZBEE_MFG_CONMED },
    { ZBEE_PROFILE_SMS_TEC_MIN,     ZBEE_PROFILE_SMS_TEC_MAX,       ZBEE_MFG_SMS_TEC },
    { ZBEE_PROFILE_POWERMAND_MIN,   ZBEE_PROFILE_POWERMAND_MAX,     ZBEE_MFG_POWERMAND },
    { ZBEE_PROFILE_SCHNEIDER_MIN,   ZBEE_PROFILE_SCHNEIDER_MAX,     ZBEE_MFG_SCHNEIDER },
    { ZBEE_PROFILE_EATON_MIN,       ZBEE_PROFILE_EATON_MAX,         ZBEE_MFG_EATON },
    { ZBEE_PROFILE_TELULAR_MIN,     ZBEE_PROFILE_TELULAR_MAX,       ZBEE_MFG_TELULAR },
    { ZBEE_PROFILE_DELPHI_MIN,      ZBEE_PROFILE_DELPHI_MAX,        ZBEE_MFG_DELPHI },
    { ZBEE_PROFILE_EPISENSOR_MIN,   ZBEE_PROFILE_EPISENSOR_MAX,     ZBEE_MFG_EPISENSOR },
    { ZBEE_PROFILE_LANDIS_GYR_MIN,  ZBEE_PROFILE_LANDIS_GYR_MAX,    ZBEE_MFG_LANDIS_GYR },
    { ZBEE_PROFILE_SHURE_MIN,       ZBEE_PROFILE_SHURE_MAX,         ZBEE_MFG_SHURE },
    { ZBEE_PROFILE_COMVERGE_MIN,    ZBEE_PROFILE_COMVERGE_MAX,      ZBEE_MFG_COMVERGE },
    { ZBEE_PROFILE_KABA_MIN,        ZBEE_PROFILE_KABA_MAX,          ZBEE_MFG_KABA },
    { ZBEE_PROFILE_HIDALGO_MIN,     ZBEE_PROFILE_HIDALGO_MAX,       ZBEE_MFG_HIDALGO },
    { ZBEE_PROFILE_AIR2APP_MIN,     ZBEE_PROFILE_AIR2APP_MAX,       ZBEE_MFG_AIR2APP },
    { ZBEE_PROFILE_AMX_MIN,         ZBEE_PROFILE_AMX_MAX,           ZBEE_MFG_AMX },
    { ZBEE_PROFILE_EDMI_MIN,        ZBEE_PROFILE_EDMI_MAX,          ZBEE_MFG_EDMI },
    { ZBEE_PROFILE_CYAN_MIN,        ZBEE_PROFILE_CYAN_MAX,          ZBEE_MFG_CYAN },
    { ZBEE_PROFILE_SYS_SPA_MIN,     ZBEE_PROFILE_SYS_SPA_MAX,       ZBEE_MFG_SYS_SPA },
    { ZBEE_PROFILE_TELIT_MIN,       ZBEE_PROFILE_TELIT_MAX,         ZBEE_MFG_TELIT },
    { ZBEE_PROFILE_KAGA_MIN,        ZBEE_PROFILE_KAGA_MAX,          ZBEE_MFG_KAGA },
    { ZBEE_PROFILE_4_NOKS_MIN,      ZBEE_PROFILE_4_NOKS_MAX,        ZBEE_MFG_4_NOKS },
    { ZBEE_PROFILE_PROFILE_SYS_MIN, ZBEE_PROFILE_PROFILE_SYS_MAX,   ZBEE_MFG_PROFILE_SYS },
    { ZBEE_PROFILE_FREESTYLE_MIN,   ZBEE_PROFILE_FREESTYLE_MAX,     ZBEE_MFG_FREESTYLE },
    { ZBEE_PROFILE_REMOTE_MIN,      ZBEE_PROFILE_REMOTE_MAX,        ZBEE_MFG_REMOTE_TECH },
    { ZBEE_PROFILE_WAVECOM_MIN,     ZBEE_PROFILE_WAVECOM_MAX,       ZBEE_MFG_WAVECOM },
    { ZBEE_PROFILE_ENERGY_OPT_MIN,  ZBEE_PROFILE_ENERGY_OPT_MAX,    ZBEE_MFG_GREEN_ENERGY },
    { ZBEE_PROFILE_GE_MIN,          ZBEE_PROFILE_GE_MAX,            ZBEE_MFG_GE },
    { ZBEE_PROFILE_MESHWORKS_MIN,   ZBEE_PROFILE_MESHWORKS_MAX,     ZBEE_MFG_MESHWORKS },
    { ZBEE_PROFILE_ELLIPS_MIN,      ZBEE_PROFILE_ELLIPS_MAX,        ZBEE_MFG_ELLIPS },
    { ZBEE_PROFILE_CEDO_MIN,        ZBEE_PROFILE_CEDO_MAX,          ZBEE_MFG_CEDO },
    { ZBEE_PROFILE_A_D_MIN,         ZBEE_PROFILE_A_D_MAX,           ZBEE_MFG_A_AND_D },
    { ZBEE_PROFILE_CARRIER_MIN,     ZBEE_PROFILE_CARRIER_MAX,       ZBEE_MFG_CARRIER },
    { ZBEE_PROFILE_PASSIVESYS_MIN,  ZBEE_PROFILE_PASSIVESYS_MAX,    ZBEE_MFG_PASSIVE },
    { ZBEE_PROFILE_SUNRISE_MIN,     ZBEE_PROFILE_SUNRISE_MAX,       ZBEE_MFG_SUNRISE },
    { ZBEE_PROFILE_MEMTEC_MIN,      ZBEE_PROFILE_MEMTEC_MAX,        ZBEE_MFG_MEMTECH },
    { ZBEE_PROFILE_BRITISH_GAS_MIN, ZBEE_PROFILE_BRITISH_GAS_MAX,   ZBEE_MFG_BRITISH_GAS },
    { ZBEE_PROFILE_SENTEC_MIN,      ZBEE_PROFILE_SENTEC_MAX,        ZBEE_MFG_SENTEC },
    { ZBEE_PROFILE_NAVETAS_MIN,     ZBEE_PROFILE_NAVETAS_MAX,       ZBEE_MFG_NAVETAS },
    { ZBEE_PROFILE_ENERNOC_MIN,     ZBEE_PROFILE_ENERNOC_MAX,       ZBEE_MFG_ENERNOC },
    { ZBEE_PROFILE_ELTAV_MIN,       ZBEE_PROFILE_ELTAV_MAX,         ZBEE_MFG_ELTAV },
    { ZBEE_PROFILE_XSTREAMHD_MIN,   ZBEE_PROFILE_XSTREAMHD_MAX,     ZBEE_MFG_XSTREAMHD },
    { ZBEE_PROFILE_OMRON_MIN,       ZBEE_PROFILE_OMRON_MAX,         ZBEE_MFG_OMRON },
    { ZBEE_PROFILE_NEC_TOKIN_MIN,   ZBEE_PROFILE_NEC_TOKIN_MAX,     ZBEE_MFG_NEC_TOKIN },
    { ZBEE_PROFILE_PEEL_MIN,        ZBEE_PROFILE_PEEL_MAX,          ZBEE_MFG_PEEL },
    { ZBEE_PROFILE_ELECTROLUX_MIN,  ZBEE_PROFILE_ELECTROLUX_MAX,    ZBEE_MFG_ELECTROLUX },
    { ZBEE_PROFILE_SAMSUNG_MIN,     ZBEE_PROFILE_SAMSUNG_MAX,       ZBEE_MFG_SAMSUNG },
    { ZBEE_PROFILE_MAINSTREAM_MIN,  ZBEE_PROFILE_MAINSTREAM_MAX,    ZBEE_MFG_MAINSTREAM },
    { ZBEE_PROFILE_DIGI_MIN,        ZBEE_PROFILE_DIGI_MAX,          ZBEE_MFG_DIGI },
    { ZBEE_PROFILE_RADIOCRAFTS_MIN, ZBEE_PROFILE_RADIOCRAFTS_MAX,   ZBEE_MFG_RADIOCRAFTS },
    { ZBEE_PROFILE_SCHNEIDER2_MIN,  ZBEE_PROFILE_SCHNEIDER2_MAX,    ZBEE_MFG_SCHNEIDER },
    { ZBEE_PROFILE_HUAWEI_MIN,      ZBEE_PROFILE_HUAWEI_MAX,        ZBEE_MFG_HUAWEI },
    { ZBEE_PROFILE_BGLOBAL_MIN,     ZBEE_PROFILE_BGLOBAL_MAX,       ZBEE_MFG_BGLOBAL },
    { ZBEE_PROFILE_ABB_MIN,         ZBEE_PROFILE_ABB_MAX,           ZBEE_MFG_ABB },
    { ZBEE_PROFILE_GENUS_MIN,       ZBEE_PROFILE_GENUS_MAX,         ZBEE_MFG_GENUS },
    { ZBEE_PROFILE_UBISYS_MIN,      ZBEE_PROFILE_UBISYS_MAX,        ZBEE_MFG_UBISYS },
    { ZBEE_PROFILE_CRESTRON_MIN,    ZBEE_PROFILE_CRESTRON_MAX,      ZBEE_MFG_CRESTRON },
    { ZBEE_PROFILE_AAC_TECH_MIN,    ZBEE_PROFILE_AAC_TECH_MAX,      ZBEE_MFG_AAC_TECH },
    { ZBEE_PROFILE_STEELCASE_MIN,   ZBEE_PROFILE_STEELCASE_MAX,     ZBEE_MFG_STEELCASE },
    { 0, 0, NULL }
};

/* ZigBee Application Profile ID Abbreviations */
static const range_string zbee_aps_apid_abbrs[] = {
    { ZBEE_DEVICE_PROFILE,  ZBEE_DEVICE_PROFILE,    "ZDP" },
    { ZBEE_PROFILE_IPM,     ZBEE_PROFILE_IPM,       "IPM" },
    { ZBEE_PROFILE_T1,      ZBEE_PROFILE_T1,        "T1" },
    { ZBEE_PROFILE_HA,      ZBEE_PROFILE_HA,        "HA" },
    { ZBEE_PROFILE_CBA,     ZBEE_PROFILE_CBA,       "CBA" },
    { ZBEE_PROFILE_WSN,     ZBEE_PROFILE_WSN,       "WSN" },
    { ZBEE_PROFILE_TA,      ZBEE_PROFILE_TA,        "TA" },
    { ZBEE_PROFILE_HC,      ZBEE_PROFILE_HC,        "HC" },
    { ZBEE_PROFILE_SE,      ZBEE_PROFILE_SE,        "SE" },
    { ZBEE_PROFILE_RS,      ZBEE_PROFILE_RS,        "RS" },
    { ZBEE_PROFILE_T2,      ZBEE_PROFILE_T2,        "T2" },
    { ZBEE_PROFILE_GP,      ZBEE_PROFILE_GP,        "GP" },
    /* Manufacturer Allocations */
    { ZBEE_PROFILE_C4_MIN,  ZBEE_PROFILE_C4_MAX,    "C4" },

    { 0, 0, NULL }
};

/* ZCL Cluster Names */
/* BUGBUG: big enough to hash? */
const range_string zbee_aps_cid_names[] = {

    /* General */
    { ZBEE_ZCL_CID_BASIC,                           ZBEE_ZCL_CID_BASIC,                           "Basic"},
    { ZBEE_ZCL_CID_POWER_CONFIG,                    ZBEE_ZCL_CID_POWER_CONFIG,                    "Power Configuration"},
    { ZBEE_ZCL_CID_DEVICE_TEMP_CONFIG,              ZBEE_ZCL_CID_DEVICE_TEMP_CONFIG,              "Device Temperature Configuration"},
    { ZBEE_ZCL_CID_IDENTIFY,                        ZBEE_ZCL_CID_IDENTIFY,                        "Identify"},
    { ZBEE_ZCL_CID_GROUPS,                          ZBEE_ZCL_CID_GROUPS,                          "Groups"},
    { ZBEE_ZCL_CID_SCENES,                          ZBEE_ZCL_CID_SCENES,                          "Scenes"},
    { ZBEE_ZCL_CID_ON_OFF,                          ZBEE_ZCL_CID_ON_OFF,                          "On/Off"},
    { ZBEE_ZCL_CID_ON_OFF_SWITCH_CONFIG,            ZBEE_ZCL_CID_ON_OFF_SWITCH_CONFIG,            "On/Off Switch Configuration"},
    { ZBEE_ZCL_CID_LEVEL_CONTROL,                   ZBEE_ZCL_CID_LEVEL_CONTROL,                   "Level Control"},
    { ZBEE_ZCL_CID_ALARMS,                          ZBEE_ZCL_CID_ALARMS,                          "Alarms"},
    { ZBEE_ZCL_CID_TIME,                            ZBEE_ZCL_CID_TIME,                            "Time"},
    { ZBEE_ZCL_CID_RSSI_LOCATION,                   ZBEE_ZCL_CID_RSSI_LOCATION,                   "RSSI Location"},
    { ZBEE_ZCL_CID_ANALOG_INPUT_BASIC,              ZBEE_ZCL_CID_ANALOG_INPUT_BASIC,              "Analog Input (Basic)"},
    { ZBEE_ZCL_CID_ANALOG_OUTPUT_BASIC,             ZBEE_ZCL_CID_ANALOG_OUTPUT_BASIC,             "Analog Output (Basic)"},
    { ZBEE_ZCL_CID_ANALOG_VALUE_BASIC,              ZBEE_ZCL_CID_ANALOG_VALUE_BASIC,              "Analog Value (Basic)"},
    { ZBEE_ZCL_CID_BINARY_INPUT_BASIC,              ZBEE_ZCL_CID_BINARY_INPUT_BASIC,              "Binary Input (Basic)"},
    { ZBEE_ZCL_CID_BINARY_OUTPUT_BASIC,             ZBEE_ZCL_CID_BINARY_OUTPUT_BASIC,             "Binary Output (Basic)"},
    { ZBEE_ZCL_CID_BINARY_VALUE_BASIC,              ZBEE_ZCL_CID_BINARY_VALUE_BASIC,              "Binary Value (Basic)"},
    { ZBEE_ZCL_CID_MULTISTATE_INPUT_BASIC,          ZBEE_ZCL_CID_MULTISTATE_INPUT_BASIC,          "Multistate Input (Basic)"},
    { ZBEE_ZCL_CID_MULTISTATE_OUTPUT_BASIC,         ZBEE_ZCL_CID_MULTISTATE_OUTPUT_BASIC,         "Multistate Output (Basic)"},
    { ZBEE_ZCL_CID_MULTISTATE_VALUE_BASIC,          ZBEE_ZCL_CID_MULTISTATE_VALUE_BASIC,          "Multistate Value (Basic)"},
    { ZBEE_ZCL_CID_COMMISSIONING,                   ZBEE_ZCL_CID_COMMISSIONING,                   "Commissioning"},
    { ZBEE_ZCL_CID_PARTITION,                       ZBEE_ZCL_CID_PARTITION,                       "Partition"},
    { ZBEE_ZCL_CID_OTA_UPGRADE,                     ZBEE_ZCL_CID_OTA_UPGRADE,                     "OTA Upgrade"},
    { ZBEE_ZCL_CID_POLL_CONTROL,                    ZBEE_ZCL_CID_POLL_CONTROL,                    "Poll Control"},
    { ZBEE_ZCL_CID_GP,                              ZBEE_ZCL_CID_GP,                              "Green Power"},
    /* */
    { ZBEE_ZCL_CID_POWER_PROFILE,                    ZBEE_ZCL_CID_POWER_PROFILE,                    "Power Profile"},
    { ZBEE_ZCL_CID_APPLIANCE_CONTROL,                ZBEE_ZCL_CID_APPLIANCE_CONTROL,                "Appliance Control"},

/* Closures */
    { ZBEE_ZCL_CID_SHADE_CONFIG,                    ZBEE_ZCL_CID_SHADE_CONFIG,                    "Shade Configuration"},
    { ZBEE_ZCL_CID_DOOR_LOCK,                       ZBEE_ZCL_CID_DOOR_LOCK,                       "Door Lock"},
    { ZBEE_ZCL_CID_WINDOW_COVERING,                 ZBEE_ZCL_CID_WINDOW_COVERING,                 "Window Covering"},

/* HVAC */
    { ZBEE_ZCL_CID_PUMP_CONFIG_CONTROL,             ZBEE_ZCL_CID_PUMP_CONFIG_CONTROL,             "Pump Configuration Control"},
    { ZBEE_ZCL_CID_THERMOSTAT,                      ZBEE_ZCL_CID_THERMOSTAT,                      "Thermostat"},
    { ZBEE_ZCL_CID_FAN_CONTROL,                     ZBEE_ZCL_CID_FAN_CONTROL,                     "Fan Control"},
    { ZBEE_ZCL_CID_DEHUMIDIFICATION_CONTROL,        ZBEE_ZCL_CID_DEHUMIDIFICATION_CONTROL,        "Dehumidification Control"},
    { ZBEE_ZCL_CID_THERMOSTAT_UI_CONFIG,            ZBEE_ZCL_CID_THERMOSTAT_UI_CONFIG,            "Thermostat User Interface Configuration"},

/* Lighting */
    { ZBEE_ZCL_CID_COLOR_CONTROL,                   ZBEE_ZCL_CID_COLOR_CONTROL,                   "Color Control"},
    { ZBEE_ZCL_CID_BALLAST_CONFIG,                  ZBEE_ZCL_CID_BALLAST_CONFIG,                  "Ballast Configuration"},

/* Measurement and Sensing */
    { ZBEE_ZCL_CID_ILLUMINANCE_MEASUREMENT,         ZBEE_ZCL_CID_ILLUMINANCE_MEASUREMENT,         "Illuminance Measurement"},
    { ZBEE_ZCL_CID_ILLUMINANCE_LEVEL_SENSING,       ZBEE_ZCL_CID_ILLUMINANCE_LEVEL_SENSING,       "Illuminance Level Sensing"},
    { ZBEE_ZCL_CID_TEMPERATURE_MEASUREMENT,         ZBEE_ZCL_CID_TEMPERATURE_MEASUREMENT,         "Temperature Measurement"},
    { ZBEE_ZCL_CID_PRESSURE_MEASUREMENT,            ZBEE_ZCL_CID_PRESSURE_MEASUREMENT,            "Pressure Measurement"},
    { ZBEE_ZCL_CID_FLOW_MEASUREMENT,                ZBEE_ZCL_CID_FLOW_MEASUREMENT,                "Flow Measurement"},
    { ZBEE_ZCL_CID_REL_HUMIDITY_MEASUREMENT,        ZBEE_ZCL_CID_REL_HUMIDITY_MEASUREMENT,        "Relative Humidity Measurement"},
    { ZBEE_ZCL_CID_OCCUPANCY_SENSING,               ZBEE_ZCL_CID_OCCUPANCY_SENSING,               "Occupancy Sensing"},
    { ZBEE_ZCL_CID_ELECTRICAL_MEASUREMENT,          ZBEE_ZCL_CID_ELECTRICAL_MEASUREMENT,          "Electrical Measurement"},

/* Security and Safety */
    { ZBEE_ZCL_CID_IAS_ZONE,                        ZBEE_ZCL_CID_IAS_ZONE,                        "Intruder Alarm System Zone"},
    { ZBEE_ZCL_CID_IAS_ACE,                         ZBEE_ZCL_CID_IAS_ACE,                         "Intruder Alarm System ACE"},
    { ZBEE_ZCL_CID_IAS_WD,                          ZBEE_ZCL_CID_IAS_WD,                          "Intruder Alarm System WD"},

/* Protocol Interfaces */
    { ZBEE_ZCL_CID_GENERIC_TUNNEL,                  ZBEE_ZCL_CID_GENERIC_TUNNEL,                  "BACnet Generic Tunnel"},
    { ZBEE_ZCL_CID_BACNET_PROTOCOL_TUNNEL,          ZBEE_ZCL_CID_BACNET_PROTOCOL_TUNNEL,          "BACnet Protocol Tunnel"},
    { ZBEE_ZCL_CID_BACNET_ANALOG_INPUT_REG,         ZBEE_ZCL_CID_BACNET_ANALOG_INPUT_REG,         "BACnet Analog Input (Regular)"},
    { ZBEE_ZCL_CID_BACNET_ANALOG_INPUT_EXT,         ZBEE_ZCL_CID_BACNET_ANALOG_INPUT_EXT,         "BACnet Analog Input (Extended)"},
    { ZBEE_ZCL_CID_BACNET_ANALOG_OUTPUT_REG,        ZBEE_ZCL_CID_BACNET_ANALOG_OUTPUT_REG,        "BACnet Analog Output (Regular)"},
    { ZBEE_ZCL_CID_BACNET_ANALOG_OUTPUT_EXT,        ZBEE_ZCL_CID_BACNET_ANALOG_OUTPUT_EXT,        "BACnet Analog Output (Extended)"},
    { ZBEE_ZCL_CID_BACNET_ANALOG_VALUE_REG,         ZBEE_ZCL_CID_BACNET_ANALOG_VALUE_REG,         "BACnet Analog Value (Regular)"},
    { ZBEE_ZCL_CID_BACNET_ANALOG_VALUE_EXT,         ZBEE_ZCL_CID_BACNET_ANALOG_VALUE_EXT,         "BACnet Analog Value (Extended)"},
    { ZBEE_ZCL_CID_BACNET_BINARY_INPUT_REG,         ZBEE_ZCL_CID_BACNET_BINARY_INPUT_REG,         "BACnet Binary Input (Regular)"},
    { ZBEE_ZCL_CID_BACNET_BINARY_INPUT_EXT,         ZBEE_ZCL_CID_BACNET_BINARY_INPUT_EXT,         "BACnet Binary Input (Extended)"},
    { ZBEE_ZCL_CID_BACNET_BINARY_OUTPUT_REG,        ZBEE_ZCL_CID_BACNET_BINARY_OUTPUT_REG,        "BACnet Binary Output (Regular)"},
    { ZBEE_ZCL_CID_BACNET_BINARY_OUTPUT_EXT,        ZBEE_ZCL_CID_BACNET_BINARY_OUTPUT_EXT,        "BACnet Binary Output (Extended)"},
    { ZBEE_ZCL_CID_BACNET_BINARY_VALUE_REG,         ZBEE_ZCL_CID_BACNET_BINARY_VALUE_REG,         "BACnet Binary Value (Regular)"},
    { ZBEE_ZCL_CID_BACNET_BINARY_VALUE_EXT,         ZBEE_ZCL_CID_BACNET_BINARY_VALUE_EXT,         "BACnet Binary Value (Extended)"},
    { ZBEE_ZCL_CID_BACNET_MULTISTATE_INPUT_REG,     ZBEE_ZCL_CID_BACNET_MULTISTATE_INPUT_REG,     "BACnet Multistage Input (Regular)"},
    { ZBEE_ZCL_CID_BACNET_MULTISTATE_INPUT_EXT,     ZBEE_ZCL_CID_BACNET_MULTISTATE_INPUT_EXT,     "BACnet Multistage Input (Extended)"},
    { ZBEE_ZCL_CID_BACNET_MULTISTATE_OUTPUT_REG,    ZBEE_ZCL_CID_BACNET_MULTISTATE_OUTPUT_REG,    "BACnet Multistage Output (Regular)"},
    { ZBEE_ZCL_CID_BACNET_MULTISTATE_OUTPUT_EXT,    ZBEE_ZCL_CID_BACNET_MULTISTATE_OUTPUT_EXT,    "BACnet Multistage Output (Extended)"},
    { ZBEE_ZCL_CID_BACNET_MULTISTATE_VALUE_REG,     ZBEE_ZCL_CID_BACNET_MULTISTATE_VALUE_REG,     "BACnet Multistage Value (Regular)"},
    { ZBEE_ZCL_CID_BACNET_MULTISTATE_VALUE_EXT,     ZBEE_ZCL_CID_BACNET_MULTISTATE_VALUE_EXT,     "BACnet Multistage Value (Extended)"},

/* ZCL Cluster IDs - Smart Energy */
    { ZBEE_ZCL_CID_KEEP_ALIVE,                      ZBEE_ZCL_CID_KEEP_ALIVE,                      "Keep-Alive"},
    { ZBEE_ZCL_CID_PRICE,                           ZBEE_ZCL_CID_PRICE,                           "Price"},
    { ZBEE_ZCL_CID_DEMAND_RESPONSE_LOAD_CONTROL,    ZBEE_ZCL_CID_DEMAND_RESPONSE_LOAD_CONTROL,    "Demand Response and Load Control"},
    { ZBEE_ZCL_CID_SIMPLE_METERING,                 ZBEE_ZCL_CID_SIMPLE_METERING,                 "Simple Metering"},
    { ZBEE_ZCL_CID_MESSAGE,                         ZBEE_ZCL_CID_MESSAGE,                         "Message"},
    { ZBEE_ZCL_CID_TUNNELING,                       ZBEE_ZCL_CID_TUNNELING,                       "Tunneling"},
    { ZBEE_ZCL_CID_PRE_PAYMENT,                     ZBEE_ZCL_CID_PRE_PAYMENT,                     "Pre-Payment"},
    { ZBEE_ZCL_CID_ENERGY_MANAGEMENT,               ZBEE_ZCL_CID_ENERGY_MANAGEMENT,               "Energy Management"},
    { ZBEE_ZCL_CID_CALENDAR,                        ZBEE_ZCL_CID_CALENDAR,                        "Calendar"},
    { ZBEE_ZCL_CID_DEVICE_MANAGEMENT,               ZBEE_ZCL_CID_DEVICE_MANAGEMENT,               "Device Management"},
    { ZBEE_ZCL_CID_EVENTS,                          ZBEE_ZCL_CID_EVENTS,                          "Events"},
    { ZBEE_ZCL_CID_MDU_PAIRING,                     ZBEE_ZCL_CID_MDU_PAIRING,                     "MDU Pairing"},
    { ZBEE_ZCL_CID_SUB_GHZ,                         ZBEE_ZCL_CID_SUB_GHZ,                         "Sub-Ghz"},
    { ZBEE_ZCL_CID_DAILY_SCHEDULE,                  ZBEE_ZCL_CID_DAILY_SCHEDULE,                  "Daily Schedule"},

/* ZCL Cluster IDs - Key Establishment */
    { ZBEE_ZCL_CID_KE,                              ZBEE_ZCL_CID_KE,                              "Key Establishment"},

/* ZCL Cluster IDs - Home Automation */
    {ZBEE_ZCL_CID_APPLIANCE_IDENTIFICATION,         ZBEE_ZCL_CID_APPLIANCE_IDENTIFICATION,         "Appliance Identification"},
    {ZBEE_ZCL_CID_METER_IDENTIFICATION,             ZBEE_ZCL_CID_METER_IDENTIFICATION,             "Meter Identification"},
    {ZBEE_ZCL_CID_APPLIANCE_EVENTS_AND_ALERT,       ZBEE_ZCL_CID_APPLIANCE_EVENTS_AND_ALERT,       "Appliance Events And Alerts"},
    {ZBEE_ZCL_CID_APPLIANCE_STATISTICS,             ZBEE_ZCL_CID_APPLIANCE_STATISTICS,             "Appliance Statistics"},

    {ZBEE_ZCL_CID_ZLL,                              ZBEE_ZCL_CID_ZLL,                              "ZLL Commissioning"},

/* ZCL Cluster IDs - Manufacturer Specific */
    {ZBEE_ZCL_CID_MANUFACTURER_SPECIFIC_MIN,        ZBEE_ZCL_CID_MANUFACTURER_SPECIFIC_MAX,        "Manufacturer Specific"},
    { 0, 0, NULL }
};

/* APS Test Profile #2 Cluster Names */
static const value_string zbee_aps_t2_cid_names[] = {
    { ZBEE_APS_T2_CID_BR,         "Broadcast Request"},
    { ZBEE_APS_T2_CID_BTADR,      "Broadcast to All Devices Response"},
    { ZBEE_APS_T2_CID_BTARACR,    "Broadcast to All Routers and Coordinator Response"},
    { ZBEE_APS_T2_CID_BTARXOWIDR, "Broadcast to All RXOnWhenIdle Devices Response"},
    { ZBEE_APS_T2_CID_BTGREQ,     "Buffer Test Group Request"},
    { ZBEE_APS_T2_CID_BTGRES,     "Buffer Test Group Response"},
    { ZBEE_APS_T2_CID_BTREQ,      "Buffer Test Request"},
    { ZBEE_APS_T2_CID_BTRES,      "Buffer Test Response"},
    { ZBEE_APS_T2_CID_FNDR,       "Freeform No Data Response"},
    { ZBEE_APS_T2_CID_FREQ,       "Freeform Request"},
    { ZBEE_APS_T2_CID_FRES,       "Freeform Response"},
    { ZBEE_APS_T2_CID_PCR,        "Packet Count Response"},
    { ZBEE_APS_T2_CID_RDREQ,      "Route Discovery Request"},
    { ZBEE_APS_T2_CID_RDRES,      "Route Discovery Response"},
    { ZBEE_APS_T2_CID_RESPC,      "Reset Packet Count"},
    { ZBEE_APS_T2_CID_RETPC,      "Retrieve Packet Count"},
    { ZBEE_APS_T2_CID_TCP,        "Transmit Counted Packets"},

    { 0, NULL }
};

/* APS Test Profile #2 Buffer Test Response Status Names */
static const value_string zbee_aps_t2_btres_status_names[] = {
    { ZBEE_APS_T2_CID_BTRES_S_SBT,   "Successful Buffer Test"},
    { ZBEE_APS_T2_CID_BTRES_S_TFOFA, "Transmission Failure on First Attempt"},

    { 0, NULL }
};

/* APS Fragmented Block Acknowledgements */
#define ZBEE_APS_FRAG_BLOCK1_ACK    0x01
#define ZBEE_APS_FRAG_BLOCK2_ACK    0x02
#define ZBEE_APS_FRAG_BLOCK3_ACK    0x04
#define ZBEE_APS_FRAG_BLOCK4_ACK    0x08
#define ZBEE_APS_FRAG_BLOCK5_ACK    0x10
#define ZBEE_APS_FRAG_BLOCK6_ACK    0x20
#define ZBEE_APS_FRAG_BLOCK7_ACK    0x40
#define ZBEE_APS_FRAG_BLOCK8_ACK    0x80

/* calculate the extended counter - top 24 bits of the previous counter,
 * plus our own; then correct for wrapping */
static uint32_t
zbee_aps_calculate_extended_counter(uint32_t previous_counter, uint8_t raw_counter)
{
    uint32_t counter = (previous_counter & 0xffffff00) | raw_counter;
    if ((counter + 0x40) < previous_counter) {
        counter += 0x100;
    } else if ((previous_counter + 0x40) < counter) {
        /* we got an out-of-order packet which happened to go backwards over the
         * wrap boundary */
        counter -= 0x100;
    }
    return counter;
}

static struct zbee_aps_node_packet_info*
zbee_aps_node_packet_info(packet_info *pinfo,
                          const zbee_nwk_packet *nwk, const zbee_nwk_hints_t *nwk_hints, const zbee_aps_packet *packet)
{
    struct zbee_aps_node_packet_info *node_data_packet;

    node_data_packet = (struct zbee_aps_node_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_zbee_aps, ZBEE_APS_NODE_PROTO_DATA);
    if (node_data_packet == NULL) {
        ieee802154_short_addr addr16;
        struct zbee_aps_node_info *node_data;
        uint32_t counter;

        if (nwk_hints) {
            addr16.pan = nwk_hints->src_pan;
        }
        else {
            addr16.pan = 0x0000;
        }
        if (packet->type != ZBEE_APS_FCF_ACK) {
            addr16.addr = nwk->src;
        }
        else {
            addr16.addr = nwk->dst;
        }
        node_data = (struct zbee_aps_node_info*) g_hash_table_lookup(zbee_table_aps_extended_counters, &addr16);
        if (node_data == NULL) {
            node_data = wmem_new0(wmem_file_scope(), struct zbee_aps_node_info);
            node_data->extended_counter = 0x100;
            g_hash_table_insert(zbee_table_aps_extended_counters, wmem_memdup(wmem_file_scope(), &addr16, sizeof(addr16)), node_data);
        }

        node_data_packet = wmem_new(wmem_file_scope(), struct zbee_aps_node_packet_info);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_zbee_aps, ZBEE_APS_NODE_PROTO_DATA, node_data_packet);

        counter = zbee_aps_calculate_extended_counter(node_data->extended_counter, packet->counter);
        node_data->extended_counter = counter;
        node_data_packet->extended_counter = counter;
    }

    return node_data_packet;
}

/**
 *ZigBee Application Support Sublayer dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_aps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tvbuff_t                                    *payload_tvb = NULL;
    dissector_handle_t                          profile_handle = NULL;
    dissector_handle_t                          zcl_handle = NULL;

    proto_tree                                  *aps_tree;
    proto_tree                                  *field_tree;
    proto_item                                  *proto_root;

    zbee_aps_packet                             packet;
    zbee_nwk_packet                             *nwk;
    zbee_nwk_hints_t                            *nwk_hints;

    struct zbee_aps_node_packet_info            *node_data_packet;

    uint8_t                                     fcf;
    uint8_t                                     offset = 0;

    static int * const frag_ack_flags[] = {
        &hf_zbee_aps_block_ack1,
        &hf_zbee_aps_block_ack2,
        &hf_zbee_aps_block_ack3,
        &hf_zbee_aps_block_ack4,
        &hf_zbee_aps_block_ack5,
        &hf_zbee_aps_block_ack6,
        &hf_zbee_aps_block_ack7,
        &hf_zbee_aps_block_ack8,
        NULL
    };

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    nwk = (zbee_nwk_packet *)data;

    /* Init. */
    memset(&packet, 0, sizeof(zbee_aps_packet));

    nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
        proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK), 0);

    /*  Create the protocol tree */
    proto_root = proto_tree_add_protocol_format(tree, proto_zbee_aps, tvb, offset, tvb_captured_length(tvb), "ZigBee Application Support Layer");
    aps_tree = proto_item_add_subtree(proto_root, ett_zbee_aps);

    /* Set the protocol column, if the NWK layer hasn't already done so. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee");

    /*  Get the FCF */
    fcf = tvb_get_uint8(tvb, offset);
    packet.type          = zbee_get_bit_field(fcf, ZBEE_APS_FCF_FRAME_TYPE);
    packet.delivery      = zbee_get_bit_field(fcf, ZBEE_APS_FCF_DELIVERY_MODE);
    packet.indirect_mode = zbee_get_bit_field(fcf, ZBEE_APS_FCF_INDIRECT_MODE);
    packet.ack_format    = zbee_get_bit_field(fcf, ZBEE_APS_FCF_ACK_FORMAT);
    packet.security      = zbee_get_bit_field(fcf, ZBEE_APS_FCF_SECURITY);
    packet.ack_req       = zbee_get_bit_field(fcf, ZBEE_APS_FCF_ACK_REQ);
    packet.ext_header    = zbee_get_bit_field(fcf, ZBEE_APS_FCF_EXT_HEADER);

    /* Display the frame type to the proto root and info column. */
    proto_item_append_text(proto_root, " %s", val_to_str_const(packet.type, zbee_aps_frame_types, "Unknown Type"));

    col_set_str(pinfo->cinfo, COL_INFO, "APS: ");
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet.type, zbee_aps_frame_types, "Unknown Frame Type"));

    /*  Display the FCF */

    /* Create the subtree */
    field_tree = proto_tree_add_subtree_format(aps_tree, tvb, offset, 1, ett_zbee_aps_fcf, NULL, "Frame Control Field: %s (0x%02x)",
            val_to_str_const(packet.type, zbee_aps_frame_types, "Unknown"), fcf);

    /* Add the frame type and delivery mode. */
    proto_tree_add_uint(field_tree, hf_zbee_aps_fcf_frame_type, tvb, offset, 1, fcf & ZBEE_APS_FCF_FRAME_TYPE);
    proto_tree_add_uint(field_tree, hf_zbee_aps_fcf_delivery, tvb, offset, 1, fcf & ZBEE_APS_FCF_DELIVERY_MODE);

    if (nwk->version >= ZBEE_VERSION_2007) {
        /* ZigBee 2007 and later uses an ack mode flag. */
        if (packet.type == ZBEE_APS_FCF_ACK) {
            proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_ack_format, tvb, offset, 1,
                    fcf & ZBEE_APS_FCF_ACK_FORMAT);
        }
    }
    else {
        /* ZigBee 2004, uses indirect mode. */
        if (packet.delivery == ZBEE_APS_FCF_INDIRECT) {
            proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_indirect_mode, tvb, offset, 1,
                    fcf & ZBEE_APS_FCF_INDIRECT_MODE);
        }
    }

    /*  Add the rest of the flags */
    proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_security, tvb, offset, 1, fcf & ZBEE_APS_FCF_SECURITY);
    proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_ack_req, tvb, offset, 1, fcf & ZBEE_APS_FCF_ACK_REQ);
    proto_tree_add_boolean(field_tree, hf_zbee_aps_fcf_ext_header, tvb, offset, 1, fcf & ZBEE_APS_FCF_EXT_HEADER);

    offset += 1;

    /* Check if the endpoint addressing fields are present. */
    switch (packet.type) {
        case ZBEE_APS_FCF_DATA:
            /* Endpoint addressing must exist to some extent on data frames. */
            break;

        case ZBEE_APS_FCF_ACK:
            if ((nwk->version >= ZBEE_VERSION_2007) && (packet.ack_format)) {
                /* Command Ack: endpoint addressing does not exist. */
                goto dissect_zbee_aps_no_endpt;
            }
            break;

        case ZBEE_APS_FCF_INTERPAN:
            packet.dst_present = false;
            packet.src_present = false;
            break;

        default:
        case ZBEE_APS_FCF_CMD:
            /* Endpoint addressing does not exist for these frames. */
            goto dissect_zbee_aps_no_endpt;
    } /* switch */

    if (packet.type != ZBEE_APS_FCF_INTERPAN) {
        /* Determine whether the source and/or destination endpoints are present.
         * We should only get here for endpoint-addressed data or ack frames.
         */
        if ((packet.delivery == ZBEE_APS_FCF_UNICAST) || (packet.delivery == ZBEE_APS_FCF_BCAST)) {
            /* Source and destination endpoints exist. (Although, I strongly
             * disagree with the presence of the endpoint in broadcast delivery
             * mode).
             */
            packet.dst_present = true;
            packet.src_present = true;
        }
        else if ((packet.delivery == ZBEE_APS_FCF_INDIRECT) && (nwk->version <= ZBEE_VERSION_2004)) {
            /* Indirect addressing was removed in ZigBee 2006, basically because it
             * was a useless, broken feature which only complicated things. Treat
             * this mode as invalid for ZigBee 2006 and later. When using indirect
             * addressing, only one of the source and destination endpoints exist,
             * and is controlled by the setting of indirect_mode.
             */
            packet.dst_present = (!packet.indirect_mode);
            packet.src_present = (packet.indirect_mode);
        }
        else if ((packet.delivery == ZBEE_APS_FCF_GROUP) && (nwk->version >= ZBEE_VERSION_2007)) {
            /* Group addressing was added in ZigBee 2006, and contains only the
             * source endpoint. (IMO, Broacast deliveries should do the same).
             */
            packet.dst_present = false;
            packet.src_present = true;
        }
        else {
            /* Illegal Delivery Mode. */
            expert_add_info(pinfo, proto_root, &ei_zbee_aps_invalid_delivery_mode);
            return tvb_captured_length(tvb);

        }

        /* If the destination endpoint is present, get and display it. */
        if (packet.dst_present) {
            packet.dst = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(aps_tree, hf_zbee_aps_dst, tvb, offset, 1, packet.dst);
            proto_item_append_text(proto_root, ", Dst Endpt: %d", packet.dst);
            offset += 1;

            /* Update the info column. */
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst Endpt: %d", packet.dst);
        }
    } /* if !interpan */

    /* If the group address is present, display it. */
    if (packet.delivery == ZBEE_APS_FCF_GROUP) {
        packet.group = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint(aps_tree, hf_zbee_aps_group, tvb, offset,2, packet.group);
        proto_item_append_text(proto_root, ", Group: 0x%04x", packet.group);
        offset +=2;

        /* Update the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Group: 0x%04x", packet.group);
    }

    /* Get and display the cluster ID. */
    if (nwk->version >= ZBEE_VERSION_2007) {
        /* Cluster ID is 16-bits long in ZigBee 2007 and later. */
        nwk->cluster_id = tvb_get_letohs(tvb, offset);
        switch (tvb_get_letohs(tvb, offset + 2)) {
            case ZBEE_DEVICE_PROFILE:
                proto_tree_add_uint_format(aps_tree, hf_zbee_aps_zdp_cluster, tvb, offset, 2, nwk->cluster_id,
                    "%s (Cluster ID: 0x%04x)",
                    val_to_str_const(nwk->cluster_id, zbee_zdp_cluster_names, "Unknown Device Profile Cluster"),
                    nwk->cluster_id);
                break;
            case ZBEE_PROFILE_T2:
                proto_tree_add_item(aps_tree, hf_zbee_aps_t2_cluster, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                if (packet.type == ZBEE_APS_FCF_DATA)
                {
                    col_set_str(pinfo->cinfo, COL_INFO,
                                val_to_str_const(nwk->cluster_id, zbee_aps_t2_cid_names, "Unknown T2 cluster"));
                }
                break;
            default:
                proto_tree_add_item(aps_tree, hf_zbee_aps_cluster, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                break;
        }
        offset += 2;
    }
    else {
        /* Cluster ID is 8-bits long in ZigBee 2004 and earlier. */
        nwk->cluster_id = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format_value(aps_tree, hf_zbee_aps_cluster, tvb, offset,
                1, nwk->cluster_id, "0x%02x", nwk->cluster_id);
        offset += 1;
    }

    /* Get and display the profile ID. */
    packet.profile = tvb_get_letohs(tvb, offset);
    profile_handle = dissector_get_uint_handle(zbee_aps_dissector_table, packet.profile);
    proto_tree_add_uint(aps_tree, hf_zbee_aps_profile, tvb, offset,2,
            packet.profile);
    /* Update the protocol root and info column later, after the source endpoint
     * so that the source and destination will be back-to-back in the text.
     */
    offset +=2;

    /* The source endpoint is present for all cases except indirect /w indirect_mode == false */
    if (packet.type != ZBEE_APS_FCF_INTERPAN &&
        ((packet.delivery != ZBEE_APS_FCF_INDIRECT) || (!packet.indirect_mode))) {
        packet.src = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(aps_tree, hf_zbee_aps_src, tvb, offset, 1, packet.src);
        proto_item_append_text(proto_root, ", Src Endpt: %d", packet.src);
        offset += 1;

        /* Update the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Src Endpt: %d", packet.src);
    }

    /* Display the profile ID now that the source endpoint was listed. */
    if (packet.type == ZBEE_APS_FCF_DATA) {
        col_append_fstr(pinfo->cinfo, COL_PROTOCOL, " %s",
                rval_to_str_const(packet.profile, zbee_aps_apid_abbrs, ""));
    }

    /* Jump here if there is no endpoint addressing in this frame. */
dissect_zbee_aps_no_endpt:

    /* Get and display the APS counter. Only present on ZigBee 2007 and later. */
    if (nwk->version >= ZBEE_VERSION_2007 && packet.type != ZBEE_APS_FCF_INTERPAN) {
        packet.counter = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(aps_tree, hf_zbee_aps_counter, tvb, offset, 1, packet.counter);
        offset += 1;
    }

    node_data_packet = zbee_aps_node_packet_info(pinfo, nwk, nwk_hints, &packet);

    /* Get and display the extended header, if present. */
    if (packet.ext_header) {
        fcf = tvb_get_uint8(tvb, offset);
        packet.fragmentation = fcf & ZBEE_APS_EXT_FCF_FRAGMENT;
        /* Create a subtree */
        field_tree = proto_tree_add_subtree_format(aps_tree, tvb, offset, 1, ett_zbee_aps_fcf, NULL, "Extended Frame Control Field (0x%02x)", fcf);

        /* Display the fragmentation sub-field. */
        proto_tree_add_uint(field_tree, hf_zbee_aps_fragmentation, tvb, offset, 1, packet.fragmentation);
        offset += 1;

        /* If fragmentation is enabled, get and display the block number. */
        if (packet.fragmentation != ZBEE_APS_EXT_FCF_FRAGMENT_NONE) {
            packet.block_number = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(field_tree, hf_zbee_aps_block_number, tvb, offset, 1, packet.block_number);
            offset += 1;
        }

        /* If fragmentation is enabled, and this is an acknowledgement, get and display the ack bitfield. */
        if ((packet.fragmentation != ZBEE_APS_EXT_FCF_FRAGMENT_NONE) && (packet.type == ZBEE_APS_FCF_ACK)) {
            proto_tree_add_bitmask(field_tree, tvb, offset, hf_zbee_aps_block_ack, ett_zbee_aps_frag_ack, frag_ack_flags, ENC_NA);
            offset += 1;
        }
    }
    else {
        /* Ensure the fragmentation mode is set off, so that the reassembly handler
         * doesn't get called.
         */
        packet.fragmentation = ZBEE_APS_EXT_FCF_FRAGMENT_NONE;
    }

    /* If a payload is present, and security is enabled, decrypt the payload. */
    if ((offset < tvb_captured_length(tvb)) && packet.security) {
        payload_tvb = dissect_zbee_secure(tvb, pinfo, aps_tree, offset);
        if (payload_tvb == NULL) {
            /* If Payload_tvb is NULL, then the security dissector cleaned up. */
            return tvb_captured_length(tvb);
        }
    }
    /* If the payload exists, create a tvb subset. */
    else if (offset < tvb_captured_length(tvb)) {
        payload_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    /* If the payload exists, and the packet is fragmented, attempt reassembly. */
    if ((payload_tvb) && (packet.fragmentation != ZBEE_APS_EXT_FCF_FRAGMENT_NONE)) {
        uint32_t        msg_id;
        uint32_t        block_num;
        uint32_t        num_blocks;
        fragment_head   *frag_msg = NULL;
        tvbuff_t        *new_tvb;

        /* Set the fragmented flag. */
        pinfo->fragmented = true;

        /* The source address (short address and PAN ID) and APS Counter pair form a unique identifier
         * for each message (fragmented or not). Hash these together to
         * create the message id for the fragmentation handler.
         */
        msg_id = ((nwk->src)<<16) + (node_data_packet->extended_counter & 0xffff);
        if (nwk_hints) {
            msg_id ^= (nwk_hints->src_pan)<<16;
        }

        /* If this is the first block of a fragmented message, than the block
         * number field is the maximum number of blocks in the message. Otherwise
         * the block number is the block being sent.
         */
        if (packet.fragmentation == ZBEE_APS_EXT_FCF_FRAGMENT_FIRST) {
            num_blocks = packet.block_number - 1;
            block_num = 0;  /* first packet. */
        }
        else {
            block_num = packet.block_number;
            num_blocks = 0;
        }

        /* Add this fragment to the reassembly handler. */
        frag_msg = fragment_add_seq_check(&zbee_aps_reassembly_table,
                payload_tvb, 0, pinfo, msg_id, NULL,
                block_num, tvb_captured_length(payload_tvb), true);

        if (num_blocks > 0) {
            fragment_set_tot_len(&zbee_aps_reassembly_table, pinfo, msg_id, NULL, num_blocks);
        }

        new_tvb = process_reassembled_data(payload_tvb, 0, pinfo, "Reassembled ZigBee APS" ,
                frag_msg, &zbee_aps_frag_items, NULL, aps_tree);

        if (new_tvb) {
            /* The reassembly handler defragmented the message, and created a new tvbuff. */
            payload_tvb = new_tvb;
        }
        else {
            /* The reassembly handler could not defragment the message. */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (fragment %d)", block_num);
            call_data_dissector(payload_tvb, pinfo, tree);
            return tvb_captured_length(tvb);
        }
    }

    /* Handle the packet type. */
    switch (packet.type) {
        case ZBEE_APS_FCF_DATA:
        case ZBEE_APS_FCF_INTERPAN:
            if (!payload_tvb) {
                break;
            }
            if (nwk->version <= ZBEE_VERSION_2004) {
                /*
                 * In ZigBee 2004, an "application framework" sits between the
                 * APS and application. Call a subdissector to handle it.
                 */
                nwk->private_data = profile_handle;
                profile_handle = zbee_apf_handle;
            }
            else if (profile_handle == NULL) {
                if (payload_tvb && (packet.profile == ZBEE_PROFILE_T2)) {
                    /* Move T2 dissect here: don't want to show T2 contents as
                     * ZCL mess, broken packets etc */
                    payload_tvb = tvb_new_subset_remaining(payload_tvb, dissect_zbee_t2(payload_tvb, aps_tree, nwk->cluster_id));
                }
                else {
                    /* Could not locate a profile dissector, but there may
                       be profile-wide commands so try to dissect them */
                    zcl_handle = find_dissector(ZBEE_PROTOABBREV_ZCL);
                }
                if (zcl_handle) {
                    call_dissector_with_data(zcl_handle, payload_tvb, pinfo, tree, nwk);
                }
                break;
            }
            call_dissector_with_data(profile_handle, payload_tvb, pinfo, tree, nwk);
            return tvb_captured_length(tvb);

        case ZBEE_APS_FCF_CMD:
            if (!payload_tvb) {
                /* Command packets MUST contain a payload. */
                expert_add_info(pinfo, proto_root, &ei_zbee_aps_missing_payload);
                return tvb_captured_length(tvb);
            }
            dissect_zbee_aps_cmd(payload_tvb, pinfo, aps_tree, nwk->version, data);
            return tvb_captured_length(tvb);

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
        call_data_dissector(payload_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_aps */

/**
 *ZigBee APS sub-dissector for APS Command frames
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param version version of APS
 *@param data raw packet private data.
*/
static void dissect_zbee_aps_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version, void *data)
{
    proto_item  *cmd_root;
    proto_tree  *cmd_tree;

    unsigned    offset = 0;
    uint8_t     cmd_id = tvb_get_uint8(tvb, offset);

    /*  Create a subtree for the APS Command frame, and add the command ID to it. */
    cmd_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_zbee_aps_cmd, &cmd_root,
            "Command Frame: %s", val_to_str_const(cmd_id, zbee_aps_cmd_names, "Unknown"));

    /* Add the command ID. */
    proto_tree_add_uint(cmd_tree, hf_zbee_aps_cmd_id, tvb, offset, 1, cmd_id);
    offset += 1;

    /* Add the command name to the info column. */
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, zbee_aps_cmd_names, "Unknown Command"));

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
            offset = dissect_zbee_aps_update_device(tvb, pinfo, cmd_tree, offset, version);
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
            offset = dissect_zbee_aps_tunnel(tvb, pinfo, cmd_tree, offset, data);
            break;

        case ZBEE_APS_CMD_VERIFY_KEY:
            /* Verify Key Command. */
            offset = dissect_zbee_aps_verify_key(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_CONFIRM_KEY:
            /* Confirm Key  Command. */
            offset = dissect_zbee_aps_confirm_key(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_APS_CMD_RELAY_MSG_DOWNSTREAM:
        case ZBEE_APS_CMD_RELAY_MSG_UPSTREAM:
            break;

        default:
            break;
    } /* switch */

    /* Dissect any TLVs */
    offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data, ZBEE_TLV_SRC_TYPE_ZBEE_APS, cmd_id);

    /* Check for any excess bytes. */
    if (offset < tvb_captured_length(tvb)) {
        /* There are leftover bytes! */
        proto_tree  *root;
        tvbuff_t    *leftover_tvb   = tvb_new_subset_remaining(tvb, offset);

        /* Get the APS Root. */
        root = proto_tree_get_root(tree);

        /* Correct the length of the command tree. */
        proto_item_set_len(cmd_root, offset);

        /* Dump the leftover to the data dissector. */
        call_data_dissector(leftover_tvb, pinfo, root);
    }
} /* dissect_zbee_aps_cmd */

/**
 *Helper dissector for the SKKE Challenge commands (SKKE1 and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_skke_challenge(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    /* Get and display the initiator address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_initiator, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the responder address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_responder, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the SKKE data. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_challenge, tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_SKKE_DATA_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_skke_challenge */

/**
 *Helper dissector for the SKKE Data commands (SKKE3 and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_skke_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    /* Get and display the initiator address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_initiator, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the responder address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_responder, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the SKKE data. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_mac, tvb, offset, ZBEE_APS_CMD_SKKE_DATA_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_SKKE_DATA_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_skke_data */

/**
 *Helper dissector for the Transport Key command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_transport_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t             key_type;
    uint8_t             key[ZBEE_APS_CMD_KEY_LENGTH];
    unsigned            i;

    /* Get and display the key type. */
    key_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_aps_cmd_key_type, tvb, offset, 1, key_type);
    offset += 1;

    /* Coincidentally, all the key descriptors start with the key. So
     * get and display it.
     */
    for (i=0; i<ZBEE_APS_CMD_KEY_LENGTH ; i++) {
        key[i] = tvb_get_uint8(tvb, offset+i);
    } /* for */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_key, tvb, offset, ZBEE_APS_CMD_KEY_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_KEY_LENGTH;

    /* Update the key ring for this pan */
    zbee_sec_add_key_to_keyring(pinfo, key);

    /* Parse the rest of the key descriptor. */
    switch (key_type) {
        case ZBEE_APS_CMD_KEY_STANDARD_NWK:
        case ZBEE_APS_CMD_KEY_HIGH_SEC_NWK:
            {
                /* Network Key */
                uint8_t seqno;

                /* Get and display the sequence number. */
                seqno = tvb_get_uint8(tvb, offset);
                proto_tree_add_uint(tree, hf_zbee_aps_cmd_seqno, tvb, offset, 1, seqno);
                offset += 1;

                /* Get and display the destination address. */
                proto_tree_add_item(tree, hf_zbee_aps_cmd_dst, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                /* Get and display the source address. */
                proto_tree_add_item(tree, hf_zbee_aps_cmd_src, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                break;
            }
        case ZBEE_APS_CMD_KEY_TC_MASTER:
        case ZBEE_APS_CMD_KEY_TC_LINK:
            {
                /* Trust Center master key. */

                /* Get and display the destination address. */
                proto_tree_add_item(tree, hf_zbee_aps_cmd_dst, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                /* Get and display the source address. */
                proto_tree_add_item(tree, hf_zbee_aps_cmd_src, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                break;
            }
        case ZBEE_APS_CMD_KEY_APP_MASTER:
        case ZBEE_APS_CMD_KEY_APP_LINK:
            {
                /* Application master or link key, both have the same format. */
                uint8_t initiator;

                /* get and display the partner address.  */
                proto_tree_add_item(tree, hf_zbee_aps_cmd_partner, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                /* get and display the initiator flag. */
                initiator = tvb_get_uint8(tvb, offset);
                proto_tree_add_boolean(tree, hf_zbee_aps_cmd_initiator_flag, tvb, offset, 1, initiator);
                offset += 1;

                break;
            }
        default:
            break;
    } /* switch */

    /* Done */
    return offset;
} /* dissect_zbee_aps_transport_key */


/**
 *Helper dissector for the Verify Key Command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_verify_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    /* display the key type. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_key_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the source address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_src, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* This value is the outcome of executing the specialized keyed hash
     * function specified in section B.1.4 using a key with the 1-octet string
     * 03 as the input string.
     */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_key_hash, tvb, offset, ZBEE_APS_CMD_KEY_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_KEY_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_verify_key */


/**
 *Helper dissector for the Confirm Key command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_confirm_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    /* display status. */
    unsigned status = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_aps_cmd_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* display the key type. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_key_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_aps_cmd_dst, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_item_append_text(tree, ", %s", val_to_str_const(status, zbee_aps_status_names, "Unknown Status"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(status, zbee_aps_status_names, "Unknown Status"));
    /* Done */
    return offset;
} /* dissect_zbee_aps_confirm_key */

/**
 *Helper dissector for the Update Device command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_update_device(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t version)
{
    /* Get and display the device address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_device, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the short address. Only on ZigBee 2006 and later. */
    if (version >= ZBEE_VERSION_2007) {
        proto_tree_add_item(tree, hf_zbee_aps_cmd_short_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset +=2;
    }

    /* Get and display the status. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_device_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Done */
    return offset;
} /* dissect_zbee_aps_update_device */

/**
 *Helper dissector for the Remove Device command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_remove_device(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    /* Get and display the device address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_device, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Done */
    return offset;
} /* dissect_zbee_aps_remove_device */

/**
 *Helper dissector for the Request Key command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_request_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t key_type;

    /* Get and display the key type. */
    key_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_aps_cmd_key_type, tvb, offset, 1, key_type);
    offset += 1;

    /* Get and display the partner address. Only present on application master key. */
    if (key_type == ZBEE_APS_CMD_KEY_APP_MASTER) {
        proto_tree_add_item(tree, hf_zbee_aps_cmd_partner, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    /* Done */
    return offset;
} /* dissect_zbee_aps_request_key */

/**
 *Helper dissector for the Switch Key command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_switch_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t seqno;

    /* Get and display the sequence number. */
    seqno = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_aps_cmd_seqno, tvb, offset, 1, seqno);
    offset += 1;

    /* Done */
    return offset;
} /* dissect_zbee_aps_switch_key */

/**
 *Helper dissector for the Entity-Authentication Initiator
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_auth_challenge(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t key_type;
    uint8_t key_seqno;

    /* Get and display the key type. */
    key_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_aps_cmd_ea_key_type, tvb, offset, 1, key_type);
    offset += 1;

    /* If using the network key, display the key sequence number. */
    if (key_type == ZBEE_APS_CMD_EA_KEY_NWK) {
        key_seqno = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(tree, hf_zbee_aps_cmd_seqno, tvb, offset, 1, key_seqno);
        offset += 1;
    }

    /* Get and display the initiator address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_initiator, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the responder address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_responder, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the challenge. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_challenge, tvb, offset, ZBEE_APS_CMD_EA_CHALLENGE_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_EA_CHALLENGE_LENGTH;

    /* Done*/
    return offset;
} /* dissect_zbee_aps_auth_challenge */

/**
 *Helper dissector for the Entity-Authentication Initiator
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_auth_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t data_type;

    /* Display the MAC. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_mac, tvb, offset, ZBEE_APS_CMD_EA_MAC_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_EA_MAC_LENGTH;

    /* Get and display the data type. */
    data_type = tvb_get_uint8(tvb, offset);
    /* Note! We're interpreting the DataType field to be the same as
     * KeyType field in the challenge frames. So far, this seems
     * consistent, although ZigBee appears to have left some holes
     * in the definition of the DataType and Data fields (ie: what
     * happens when KeyType == Link Key?)
     */
    proto_tree_add_uint(tree, hf_zbee_aps_cmd_ea_key_type, tvb, offset, 1, data_type);
    offset += 1;

    /* Display the data field. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_ea_data, tvb, offset, ZBEE_APS_CMD_EA_DATA_LENGTH, ENC_NA);
    offset += ZBEE_APS_CMD_EA_DATA_LENGTH;

    /* Done */
    return offset;
} /* dissect_zbee_aps_auth_data */

/**
 *Helper dissector for the Tunnel command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param offset into the tvb to begin dissection.
 *@param data raw packet private data.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbee_aps_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, void *data)
{
    proto_tree  *root;
    tvbuff_t    *tunnel_tvb;

    /* Get and display the destination address. */
    proto_tree_add_item(tree, hf_zbee_aps_cmd_dst, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* The remainder is a tunneled APS frame. */
    tunnel_tvb = tvb_new_subset_remaining(tvb, offset);
    root = proto_tree_get_root(tree);
    call_dissector_with_data(zbee_aps_handle, tunnel_tvb, pinfo, root, data);
    offset = tvb_captured_length(tvb);

    /* Done */
    return offset;
} /* dissect_zbee_aps_tunnel */


/**
 *ZigBee Application Framework dissector for Wireshark. Note
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree.
*/
static int dissect_zbee_apf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree  *apf_tree;
    proto_item  *proto_root;

    uint8_t     count;
    uint8_t     type;
    unsigned    offset = 0;
    unsigned    i;

    tvbuff_t    *app_tvb;
    dissector_handle_t  app_dissector = NULL;
    zbee_nwk_packet *nwk = (zbee_nwk_packet *)data;

    if (nwk != NULL)
        app_dissector = (dissector_handle_t)(nwk->private_data);

    /* Create the tree for the application framework. */
    proto_root = proto_tree_add_protocol_format(tree, proto_zbee_apf, tvb, 0,
            tvb_captured_length(tvb), "ZigBee Application Framework");
    apf_tree = proto_item_add_subtree(proto_root, ett_zbee_apf);

    /* Get the count and type. */
    count   = zbee_get_bit_field(tvb_get_uint8(tvb, offset), ZBEE_APP_COUNT);
    type    = zbee_get_bit_field(tvb_get_uint8(tvb, offset), ZBEE_APP_TYPE);
    proto_tree_add_uint(apf_tree, hf_zbee_apf_count, tvb, offset, 1, count);
    proto_tree_add_uint(apf_tree, hf_zbee_apf_type, tvb, offset, 1, type);
    offset += 1;

    /* Ensure the application dissector exists. */
    if (app_dissector == NULL) {
        /* No dissector for this profile. */
        goto dissect_app_end;
    }

    /* Handle the transactions. */
    for (i=0; i<count; i++) {
        unsigned    length;

        /* Create a tvb for this transaction. */
        length = zbee_apf_transaction_len(tvb, offset, type);
        app_tvb = tvb_new_subset_length(tvb, offset, length);

        /* Call the application dissector. */
        call_dissector_with_data(app_dissector, app_tvb, pinfo, tree, data);

        /* Adjust the offset. */
        offset += length;
    }

dissect_app_end:
    if (offset < tvb_captured_length(tvb)) {
        /* There are bytes remaining! */
        app_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(app_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_apf */

/**
 *ZigBee Test Profile #2 dissector for Wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to the command subtree.
 *@param cluster_id ZigBee Test Profile #2 cluster ID.
*/
static unsigned
dissect_zbee_t2(tvbuff_t *tvb, proto_tree *tree, uint16_t cluster_id)
{
    unsigned offset = 0;
    uint8_t payload_length;
    proto_tree *t2_tree;

    t2_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_zbee_aps_t2, NULL, "ZigBee Test Profile #2");

    switch (cluster_id) {
        case ZBEE_APS_T2_CID_BTRES:
            payload_length = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(t2_tree, hf_zbee_aps_t2_btres_octet_sequence_length_requested, tvb, offset, 1,
                payload_length);
            offset += 1;
            proto_tree_add_item(t2_tree, hf_zbee_aps_t2_btres_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(t2_tree, hf_zbee_aps_t2_btres_octet_sequence, tvb, offset, payload_length, ENC_NA);
            offset += payload_length;
            break;
        case ZBEE_APS_T2_CID_BTREQ:
            payload_length = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(t2_tree, hf_zbee_aps_t2_btreq_octet_sequence_length, tvb, offset, 1, payload_length);
            offset += 1;
            break;
    }
    return offset;
} /* dissect_zbee_t2 */

/**
 *Peeks into the application framework, and determines the
 *
 *@param tvb packet buffer.
 *@param offset offset into the buffer.
 *@param type message type: KVP or MSG.
*/
static unsigned
zbee_apf_transaction_len(tvbuff_t *tvb, unsigned offset, uint8_t type)
{
    if (type == ZBEE_APP_TYPE_KVP) {
        /* KVP Type. */
        /* | 1 Byte |    1 Byte     |  2 Bytes  | 0/1 Bytes  | Variable |
         * | SeqNo  | Cmd/Data Type | Attribute | Error Code |   Data   |
         */
        uint8_t kvp_cmd     = zbee_get_bit_field(tvb_get_uint8(tvb, offset+1), ZBEE_APP_KVP_CMD);
        uint8_t kvp_type    = zbee_get_bit_field(tvb_get_uint8(tvb, offset+1), ZBEE_APP_KVP_TYPE);
        unsigned   kvp_len     = ZBEE_APP_KVP_OVERHEAD;

        /* Add the length of the error code, if present. */
        switch (kvp_cmd) {
            case ZBEE_APP_KVP_SET_RESP:
            case ZBEE_APP_KVP_EVENT_RESP:
                /* Error Code Present. */
                kvp_len += 1;
                /* Data Not Present. */
                return kvp_len;
            case ZBEE_APP_KVP_GET_RESP:
                /* Error Code Present. */
                kvp_len += 1;
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
                kvp_len += 4;
                break;
            case ZBEE_APP_KVP_UINT16:
            case ZBEE_APP_KVP_INT16:
            case ZBEE_APP_KVP_FLOAT16:
                kvp_len += 2;
                break;
            case ZBEE_APP_KVP_UINT8:
            case ZBEE_APP_KVP_INT8:
                kvp_len += 1;
                break;
            case ZBEE_APP_KVP_CHAR_STRING:
            case ZBEE_APP_KVP_OCT_STRING:
                /* Variable Length Types, first byte is the length-1 */
                kvp_len += tvb_get_uint8(tvb, offset+kvp_len)+1;
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
        return (tvb_get_uint8(tvb, offset+1) + 2);
    }
} /* zbee_apf_transaction_len */

static void
proto_init_zbee_aps(void)
{
    zbee_table_aps_extended_counters  = g_hash_table_new(ieee802154_short_addr_hash, ieee802154_short_addr_equal);
}

static void
proto_cleanup_zbee_aps(void)
{
    g_hash_table_destroy(zbee_table_aps_extended_counters);
}

/* The ZigBee Smart Energy version in enum_val_t for the ZigBee Smart Energy version preferences. */
static const enum_val_t zbee_zcl_protocol_version_enums[] = {
    { "se1.1b",     "SE 1.1b",     ZBEE_SE_VERSION_1_1B },
    { "se1.2",      "SE 1.2",      ZBEE_SE_VERSION_1_2 },
    { "se1.2a",     "SE 1.2a",     ZBEE_SE_VERSION_1_2A },
    { "se1.2b",     "SE 1.2b",     ZBEE_SE_VERSION_1_2B },
    { "se1.4",      "SE 1.4",      ZBEE_SE_VERSION_1_4 },
    { NULL, NULL, 0 }
};

int gPREF_zbee_se_protocol_version = ZBEE_SE_VERSION_1_4;

void
dissect_zbee_aps_status_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned status = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_aps_cmd_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(status, zbee_aps_status_names, "Unknown Status"));
}

/**
 *ZigBee APS protocol registration routine.
 *
*/
void proto_register_zbee_aps(void)
{
    static hf_register_info hf[] = {
            { &hf_zbee_aps_fcf_frame_type,
            { "Frame Type",             "zbee_aps.type", FT_UINT8, BASE_HEX, VALS(zbee_aps_frame_types), ZBEE_APS_FCF_FRAME_TYPE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_delivery,
            { "Delivery Mode",          "zbee_aps.delivery", FT_UINT8, BASE_HEX, VALS(zbee_aps_delivery_modes), ZBEE_APS_FCF_DELIVERY_MODE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_indirect_mode,
            { "Indirect Address Mode",  "zbee_aps.indirect_mode", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_INDIRECT_MODE,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_ack_format,
            { "Acknowledgement Format", "zbee_aps.ack_format", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_ACK_FORMAT,
                NULL, HFILL }},

            { &hf_zbee_aps_fcf_security,
            { "Security",               "zbee_aps.security", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_SECURITY,
                "Whether security operations are performed on the APS payload.", HFILL }},

            { &hf_zbee_aps_fcf_ack_req,
            { "Acknowledgement Request","zbee_aps.ack_req", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_ACK_REQ,
                "Flag requesting an acknowledgement frame for this packet.", HFILL }},

            { &hf_zbee_aps_fcf_ext_header,
            { "Extended Header",        "zbee_aps.ext_header", FT_BOOLEAN, 8, NULL, ZBEE_APS_FCF_EXT_HEADER,
                NULL, HFILL }},

            { &hf_zbee_aps_dst,
            { "Destination Endpoint",   "zbee_aps.dst", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_group,
            { "Group",                  "zbee_aps.group", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cluster,
            { "Cluster",                "zbee_aps.cluster", FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
                    RVALS(zbee_aps_cid_names), 0x0, NULL, HFILL }},

            { &hf_zbee_aps_profile,
            { "Profile",                "zbee_aps.profile", FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
                    RVALS(zbee_aps_apid_names), 0x0, NULL, HFILL }},

            { &hf_zbee_aps_src,
            { "Source Endpoint",        "zbee_aps.src", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_counter,
            { "Counter",                "zbee_aps.counter", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragmentation,
            { "Fragmentation",          "zbee_aps.fragmentation", FT_UINT8, BASE_HEX, VALS(zbee_aps_fragmentation_modes), ZBEE_APS_EXT_FCF_FRAGMENT,
                NULL, HFILL }},

            { &hf_zbee_aps_block_number,
            { "Block Number",           "zbee_aps.block", FT_UINT8, BASE_DEC, NULL, 0x0,
                "A block identifier within a fragmented transmission, or the number of expected blocks if the first block.", HFILL }},

            { &hf_zbee_aps_block_ack,
            { "Block Acknowledgements", "zbee_aps.block_acks", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

            { &hf_zbee_aps_block_ack1,
            { "Block 1", "zbee_aps.block1_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK1_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack2,
            { "Block 2", "zbee_aps.block2_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK2_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack3,
            { "Block 3", "zbee_aps.block3_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK3_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack4,
            { "Block 4", "zbee_aps.block4_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK4_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack5,
            { "Block 5", "zbee_aps.block5_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK5_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack6,
            { "Block 6", "zbee_aps.block6_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK6_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack7,
            { "Block 7", "zbee_aps.block7_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK7_ACK, NULL, HFILL }},

            { &hf_zbee_aps_block_ack8,
            { "Block 8", "zbee_aps.block8_ack", FT_BOOLEAN, 8, TFS(&tfs_acknowledged_not_acknowledged),
                ZBEE_APS_FRAG_BLOCK8_ACK, NULL, HFILL }},

            { &hf_zbee_aps_cmd_id,
            { "Command Identifier",     "zbee_aps.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_aps_cmd_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_initiator,
            { "Initiator Address",      "zbee_aps.cmd.initiator", FT_EUI64, BASE_NONE, NULL, 0x0,
                "The extended address of the device to initiate the SKKE procedure", HFILL }},

            { &hf_zbee_aps_cmd_responder,
            { "Responder Address",      "zbee_aps.cmd.responder", FT_EUI64, BASE_NONE, NULL, 0x0,
                "The extended address of the device responding to the SKKE procedure", HFILL }},

            { &hf_zbee_aps_cmd_partner,
            { "Partner Address",        "zbee_aps.cmd.partner", FT_EUI64, BASE_NONE, NULL, 0x0,
                "The partner to use this key with for link-level security.", HFILL }},

            { &hf_zbee_aps_cmd_initiator_flag,
            { "Initiator",              "zbee_aps.cmd.init_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Indicates the destination of the transport-key command requested this key.", HFILL }},

            { &hf_zbee_aps_cmd_device,
            { "Device Address",         "zbee_aps.cmd.device", FT_EUI64, BASE_NONE, NULL, 0x0,
                "The device whose status is being updated.", HFILL }},

            { &hf_zbee_aps_cmd_challenge,
            { "Challenge",              "zbee_aps.cmd.challenge", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Random challenge value used during SKKE and authentication.", HFILL }},

            { &hf_zbee_aps_cmd_mac,
            { "Message Authentication Code",    "zbee_aps.cmd.mac", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Message authentication values used during SKKE and authentication.", HFILL }},

            { &hf_zbee_aps_cmd_key,
            { "Key",                    "zbee_aps.cmd.key", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_key_hash,
            { "Key Hash",               "zbee_aps.cmd.key_hash", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_key_type,
            { "Key Type",               "zbee_aps.cmd.key_type", FT_UINT8, BASE_HEX,
                    VALS(zbee_aps_key_names), 0x0, NULL, HFILL }},

            { &hf_zbee_aps_cmd_dst,
            { "Extended Destination",   "zbee_aps.cmd.dst", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_src,
            { "Extended Source",        "zbee_aps.cmd.src", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_seqno,
            { "Sequence Number",        "zbee_aps.cmd.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The key sequence number associated with the network key.", HFILL }},

            { &hf_zbee_aps_cmd_short_addr,
            { "Device Address",         "zbee_aps.cmd.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
                "The device whose status is being updated.", HFILL }},

            { &hf_zbee_aps_cmd_device_status,
            { "Device Status",          "zbee_aps.cmd.update_status", FT_UINT8, BASE_HEX,
                    VALS(zbee_aps_update_status_names), 0x0,
                "Update device status.", HFILL }},

            { &hf_zbee_aps_cmd_status,
            { "Status",                 "zbee_aps.cmd.status", FT_UINT8, BASE_HEX,
                    VALS(zbee_aps_status_names), 0x0,
                "APS status.", HFILL }},

            { &hf_zbee_aps_cmd_ea_key_type,
            { "Key Type",               "zbee_aps.cmd.ea.key_type", FT_UINT8, BASE_HEX,
                    VALS(zbee_aps_ea_key_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_cmd_ea_data,
            { "Data",                   "zbee_aps.cmd.ea.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Additional data used in entity authentication. Typically this will be the outgoing frame counter associated with the key used for entity authentication.", HFILL }},

            { &hf_zbee_aps_fragments,
            { "Message fragments",      "zbee_aps.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment,
            { "Message fragment",       "zbee_aps.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_overlap,
            { "Message fragment overlap",       "zbee_aps.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "zbee_aps.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_multiple_tails,
            { "Message has multiple tail fragments", "zbee_aps.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_too_long_fragment,
            { "Message fragment too long",      "zbee_aps.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_error,
            { "Message defragmentation error",  "zbee_aps.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_fragment_count,
            { "Message fragment count",         "zbee_aps.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_reassembled_in,
            { "Reassembled in",         "zbee_aps.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_reassembled_length,
            { "Reassembled ZigBee APS length",         "zbee_aps.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_aps_t2_cluster,
                { "Cluster", "zbee_aps.t2.cluster", FT_UINT16, BASE_HEX, VALS(zbee_aps_t2_cid_names), 0x0, NULL,
                    HFILL }},

            { &hf_zbee_aps_t2_btres_octet_sequence,
                { "Octet Sequence", "zbee_aps.t2.btres.octet_sequence", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

            { &hf_zbee_aps_t2_btres_octet_sequence_length_requested,
                { "Octet Sequence Length Requested", "zbee_aps.t2.btres.octet_sequence_length_requested", FT_UINT8,
                    BASE_DEC, NULL, 0x0, NULL, HFILL }},

            { &hf_zbee_aps_t2_btres_status,
                { "Status", "zbee_aps.t2.btres.status", FT_UINT8, BASE_HEX, VALS(zbee_aps_t2_btres_status_names), 0x0,
                    NULL, HFILL }},

            { &hf_zbee_aps_t2_btreq_octet_sequence_length,
                { "Octet Sequence Length", "zbee_aps.t2.btreq.octet_sequence_length", FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

            { &hf_zbee_aps_zdp_cluster,
                { "Cluster", "zbee_aps.zdp_cluster", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }}
    };

    static hf_register_info hf_apf[] = {
            { &hf_zbee_apf_count,
            { "Count",                  "zbee_apf.count", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_apf_type,
            { "Type",                   "zbee_apf.type", FT_UINT8, BASE_HEX,
                    VALS(zbee_apf_type_names), 0x0, NULL, HFILL }}
    };

    /*  APS subtrees */
    static int *ett[] = {
        &ett_zbee_aps,
        &ett_zbee_aps_fcf,
        &ett_zbee_aps_ext,
        &ett_zbee_aps_cmd,
        &ett_zbee_aps_fragment,
        &ett_zbee_aps_fragments,
        &ett_zbee_aps_t2,
        &ett_zbee_aps_frag_ack
    };

    static int *ett_apf[] = {
        &ett_zbee_apf
    };

    static ei_register_info ei[] = {
        { &ei_zbee_aps_invalid_delivery_mode, { "zbee_aps.invalid_delivery_mode", PI_PROTOCOL, PI_WARN, "Invalid Delivery Mode", EXPFILL }},
        { &ei_zbee_aps_missing_payload, { "zbee_aps.missing_payload", PI_MALFORMED, PI_ERROR, "Missing Payload", EXPFILL }},
    };

    register_init_routine(proto_init_zbee_aps);
    register_cleanup_routine(proto_cleanup_zbee_aps);

    expert_module_t* expert_zbee_aps;

    /* Register ZigBee APS protocol with Wireshark. */
    proto_zbee_aps = proto_register_protocol("ZigBee Application Support Layer", "ZigBee APS", ZBEE_PROTOABBREV_APS);
    proto_register_field_array(proto_zbee_aps, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_zbee_aps = expert_register_protocol(proto_zbee_aps);
    expert_register_field_array(expert_zbee_aps, ei, array_length(ei));

    /* Register the APS dissector and subdissector list. */
    zbee_aps_dissector_table = register_dissector_table("zbee.profile", "ZigBee Profile ID", proto_zbee_aps, FT_UINT16, BASE_HEX);
    zbee_aps_handle = register_dissector(ZBEE_PROTOABBREV_APS, dissect_zbee_aps, proto_zbee_aps);

    /* Register preferences */
    module_t* zbee_se_prefs = prefs_register_protocol(proto_zbee_aps, NULL);

    prefs_register_enum_preference(zbee_se_prefs, "zbeeseversion", "ZigBee Smart Energy Version",
            "Specifies the ZigBee Smart Energy version used when dissecting "
            "ZigBee APS messages within the Smart Energy Profile",
            &gPREF_zbee_se_protocol_version, zbee_zcl_protocol_version_enums, false);

    /* Register reassembly table. */
    reassembly_table_register(&zbee_aps_reassembly_table,
                          &addresses_reassembly_table_functions);

    /* Register the ZigBee Application Framework protocol with Wireshark. */
    proto_zbee_apf = proto_register_protocol("ZigBee Application Framework", "ZigBee APF", "zbee_apf");
    proto_register_field_array(proto_zbee_apf, hf_apf, array_length(hf_apf));
    proto_register_subtree_array(ett_apf, array_length(ett_apf));

    /* Register the App dissector. */
    zbee_apf_handle = register_dissector("zbee_apf", dissect_zbee_apf, proto_zbee_apf);
} /* proto_register_zbee_aps */

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
