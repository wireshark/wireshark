/* packet-btlmp.c
 * Routines for the Bluetooth Link Manager Protocol
 *
 * Copyright 2020, Thomas Sailer <t.sailer@alumni.ethz.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>


#include "packet-bluetooth.h"
#include "packet-btbredr_rf.h"

static int proto_btlmp;

static int hf_opcode[3];
static int hf_escopcode[4];
static int hf_accept_opcode;
static int hf_accept_escopcode[4];
static int hf_errorcode;
static int hf_param_feature_page0_byte0[9];
static int hf_param_feature_page0_byte1[9];
static int hf_param_feature_page0_byte2[7];
static int hf_param_feature_page0_byte3[9];
static int hf_param_feature_page0_byte4[9];
static int hf_param_feature_page0_byte5[9];
static int hf_param_feature_page0_byte6[9];
static int hf_param_feature_page0_byte7[6];
static int hf_param_feature_page1_byte0[6];
static int hf_param_feature_page2_byte0[9];
static int hf_param_feature_page2_byte1[6];
static int hf_param_features_page;
static int hf_param_max_supported_page;
static int hf_param_versnr;
static int hf_param_compid;
static int hf_param_subversnr;
static int hf_param_namelength;
static int hf_param_nameoffset;
static int hf_param_namefragment;
static int hf_param_afh_mode;
static int hf_param_afh_instant;
static int hf_param_afh_channelmap[10];
static int hf_param_afh_reportingmode;
static int hf_param_afh_mininterval;
static int hf_param_afh_maxinterval;
static int hf_param_afh_channelclass[10][4];
static int hf_param_rand;
static int hf_param_key;
static int hf_param_clockoffset;
static int hf_param_authresp;
static int hf_param_encryptionmode;
static int hf_param_encryptionkeysize;
static int hf_param_switchinstant;
static int hf_param_holdtime;
static int hf_param_holdinstant;
static int hf_param_dsniff;
static int hf_param_tsniff;
static int hf_param_sniffattempt;
static int hf_param_snifftimeout;
static int hf_param_timingcontrolflags[5];
static int hf_param_futureuse1;
static int hf_param_datarate[6];
static int hf_param_pollinterval;
static int hf_param_nbc;
static int hf_param_scohandle;
static int hf_param_dsco;
static int hf_param_tsco;
static int hf_param_scopacket;
static int hf_param_airmode;
static int hf_param_slots;
static int hf_param_tmgacc_drift;
static int hf_param_tmgacc_jitter;
static int hf_param_slotoffset;
static int hf_param_bdaddr;
static int hf_param_pagingscheme;
static int hf_param_pagingschemesettings;
static int hf_param_supervisiontimeout;
static int hf_param_testscenario;
static int hf_param_testhoppingmode;
static int hf_param_testtxfrequency;
static int hf_param_testrxfrequency;
static int hf_param_testpowercontrolmode;
static int hf_param_testpollperiod;
static int hf_param_testpackettype;
static int hf_param_testdatalength;
static int hf_param_keysizemask;
static int hf_param_encapsulatedmajor;
static int hf_param_encapsulatedminor;
static int hf_param_encapsulatedlength;
static int hf_param_encapsulateddata;
static int hf_param_simplepaircommit;
static int hf_param_simplepairnonce;
static int hf_param_dhkeyconfirm;
static int hf_param_clkadjid;
static int hf_param_clkadjinstant;
static int hf_param_clkadjus;
static int hf_param_clkadjslots;
static int hf_param_clkadjmode;
static int hf_param_clkadjclk;
static int hf_param_clkadjperiod;
static int hf_param_packettypetable;
static int hf_param_escohandle;
static int hf_param_escoltaddr;
static int hf_param_escod;
static int hf_param_escot;
static int hf_param_escow;
static int hf_param_escopackettypems;
static int hf_param_escopackettypesm;
static int hf_param_escopacketlengthms;
static int hf_param_escopacketlengthsm;
static int hf_param_negostate;
static int hf_param_maxsniffsubrate;
static int hf_param_minsniffmodetimeout;
static int hf_param_sniffsubratinginstant;
static int hf_param_iocapcap;
static int hf_param_iocapoobauthdata;
static int hf_param_iocapauthreq;
static int hf_param_keypressnotificationtype;
static int hf_param_poweradjreq;
static int hf_param_poweradjresp[5];
static int hf_param_samindex;
static int hf_param_samtsm;
static int hf_param_samnsm;
static int hf_param_samsubmaps;
static int hf_param_samupdatemode;
static int hf_param_samtype0submap;
static int hf_param_samd;
static int hf_param_saminstant;
static int hf_params;

static int ett_btlmp;

static dissector_handle_t btlmp_handle;

static const value_string opcode_vals[] = {
    {   1, "LMP_name_req" },
    {   2, "LMP_name_res" },
    {   3, "LMP_accepted" },
    {   4, "LMP_not_accepted" },
    {   5, "LMP_clkoffset_req" },
    {   6, "LMP_clkoffset_res" },
    {   7, "LMP_detach" },
    {   8, "LMP_in_rand" },
    {   9, "LMP_comb_key" },
    {  10, "LMP_unit_key" },
    {  11, "LMP_au_rand" },
    {  12, "LMP_sres" },
    {  13, "LMP_temp_rand" },
    {  14, "LMP_temp_key" },
    {  15, "LMP_encryption_mode_req" },
    {  16, "LMP_encryption_key_size_req" },
    {  17, "LMP_start_encryption_req" },
    {  18, "LMP_stop_encryption_req" },
    {  19, "LMP_switch_req" },
    {  20, "LMP_hold" },
    {  21, "LMP_hold_req" },
    {  23, "LMP_sniff_req" },
    {  24, "LMP_unsniff_req" },
    {  31, "LMP_incr_power_req" },
    {  32, "LMP_decr_power_req" },
    {  33, "LMP_max_power" },
    {  34, "LMP_min_power" },
    {  35, "LMP_auto_rate" },
    {  36, "LMP_preferred_rate" },
    {  37, "LMP_version_req" },
    {  38, "LMP_version_res" },
    {  39, "LMP_features_req" },
    {  40, "LMP_features_res" },
    {  41, "LMP_quality_of_service" },
    {  42, "LMP_quality_of_service_req" },
    {  43, "LMP_SCO_link_req" },
    {  44, "LMP_remove_SCO_link_req" },
    {  45, "LMP_max_slot" },
    {  46, "LMP_max_slot_req" },
    {  47, "LMP_timing_accuracy_req" },
    {  48, "LMP_timing_accuracy_res" },
    {  49, "LMP_setup_complete" },
    {  50, "LMP_use_semi_permanent_key" },
    {  51, "LMP_host_connection_req" },
    {  52, "LMP_slot_offset" },
    {  53, "LMP_page_mode_req" },
    {  54, "LMP_page_scan_mode_req" },
    {  55, "LMP_supervision_timeout" },
    {  56, "LMP_test_activate" },
    {  57, "LMP_test_control" },
    {  58, "LMP_encryption_key_size_mask_req" },
    {  59, "LMP_encryption_key_size_mask_res" },
    {  60, "LMP_set_AFH" },
    {  61, "LMP_encapsulated_header" },
    {  62, "LMP_encapsulated_payload" },
    {  63, "LMP_Simple_Pairing_Confirm" },
    {  64, "LMP_Simple_Pairing_Number" },
    {  65, "LMP_DHkey_Check" },
    {  66, "LMP_pause_encryption_aes_req" },
    { 124, "Escape 1" },
    { 125, "Escape 2" },
    { 126, "Escape 3" },
    { 127, "Escape 4" },
    {   0, NULL }
};

static const value_string escape1_opcode_vals[] = {
    { 0x00, "Mandatory Scan Mode" },
    { 0,    NULL }
};

static const value_string escape2_opcode_vals[] = {
    { 0x00, "Mandatory Scan Mode" },
    { 0,    NULL }
};

static const value_string escape3_opcode_vals[] = {
    { 0x00, "Mandatory Scan Mode" },
    { 0,    NULL }
};

static const value_string escape4_opcode_vals[] = {
    {   1, "LMP_accepted_ext" },
    {   2, "LMP_not_accepted_ext" },
    {   3, "LMP_features_req_ext" },
    {   4, "LMP_features_res_ext" },
    {   5, "LMP_clk_adj" },
    {   6, "LMP_clk_adj_ack" },
    {   7, "LMP_clk_adj_req" },
    {  11, "LMP_packet_type_table_req" },
    {  12, "LMP_eSCO_link_req" },
    {  13, "LMP_remove_eSCO_link_req" },
    {  16, "LMP_channel_classification_req" },
    {  17, "LMP_channel_classification" },
    {  21, "LMP_sniff_subrating_req" },
    {  22, "LMP_sniff_subrating_res" },
    {  23, "LMP_pause_encryption_req" },
    {  24, "LMP_resume_encryption_req" },
    {  25, "LMP_IO_Capability_req" },
    {  26, "LMP_IO_Capability_res" },
    {  27, "LMP_numeric_comparison_failed" },
    {  28, "LMP_passkey_failed" },
    {  29, "LMP_oob_failed" },
    {  30, "LMP_keypress_notification" },
    {  31, "LMP_power_control_req" },
    {  32, "LMP_power_control_res" },
    {  33, "LMP_ping_req" },
    {  34, "LMP_ping_res" },
    {  35, "LMP_SAM_set_type0" },
    {  36, "LMP_SAM_define_map" },
    {  37, "LMP_SAM_switch" },
    {   0, NULL }
};

static const value_string errorcode_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Unknown HCI Command" },
    { 0x02, "Unknown Connection Identifier" },
    { 0x03, "Hardware Failure" },
    { 0x04, "Page Timeout" },
    { 0x05, "Authentication Failure" },
    { 0x06, "PIN or Key Missing" },
    { 0x07, "Memory Capacity Exceeded" },
    { 0x08, "Connection Timeout" },
    { 0x09, "Connection Limit Exceeded" },
    { 0x0A, "Synchronous Connection Limit To A Device Exceeded" },
    { 0x0B, "Connection Already Exists" },
    { 0x0C, "Command Disallowed" },
    { 0x0D, "Connection Rejected due to Limited Resources" },
    { 0x0E, "Connection Rejected Due To Security Reasons" },
    { 0x0F, "Connection Rejected due to Unacceptable BD_ADDR" },
    { 0x10, "Connection Accept Timeout Exceeded" },
    { 0x11, "Unsupported Feature or Parameter Value" },
    { 0x12, "Invalid HCI Command Parameters" },
    { 0x13, "Remote User Terminated Connection" },
    { 0x14, "Remote Device Terminated Connection due to Low Resources" },
    { 0x15, "Remote Device Terminated Connection due to Power Off" },
    { 0x16, "Connection Terminated By Local Host" },
    { 0x17, "Repeated Attempts" },
    { 0x18, "Pairing Not Allowed" },
    { 0x19, "Unknown LMP PDU" },
    { 0x1A, "Unsupported Remote Feature / Unsupported LMP Feature" },
    { 0x1B, "SCO Offset Rejected" },
    { 0x1C, "SCO Interval Rejected" },
    { 0x1D, "SCO Air Mode Rejected" },
    { 0x1E, "Invalid LMP Parameters / Invalid LL Parameters" },
    { 0x1F, "Unspecified Error" },
    { 0x20, "Unsupported LMP Parameter Value / Unsupported LL Parameter Value" },
    { 0x21, "Role Change Not Allowed" },
    { 0x22, "LMP Response Timeout / LL Response Timeout" },
    { 0x23, "LMP Error Transaction Collision / LL Procedure Collision" },
    { 0x24, "LMP PDU Not Allowed" },
    { 0x25, "Encryption Mode Not Acceptable" },
    { 0x26, "Link Key cannot be Changed" },
    { 0x27, "Requested QoS Not Supported" },
    { 0x28, "Instant Passed" },
    { 0x29, "Pairing With Unit Key Not Supported" },
    { 0x2A, "Different Transaction Collision" },
    { 0x2B, "Reserved for future use" },
    { 0x2C, "QoS Unacceptable Parameter" },
    { 0x2D, "QoS Rejected" },
    { 0x2E, "Channel Classification Not Supported" },
    { 0x2F, "Insufficient Security" },
    { 0x30, "Parameter Out Of Mandatory Range" },
    { 0x31, "Reserved for future use" },
    { 0x32, "Role Switch Pending" },
    { 0x33, "Reserved for future use" },
    { 0x34, "Reserved Slot Violation" },
    { 0x35, "Role Switch Failed" },
    { 0x36, "Extended Inquiry Response Too Large" },
    { 0x37, "Secure Simple Pairing Not Supported By Host" },
    { 0x38, "Host Busy - Pairing" },
    { 0x39, "Connection Rejected due to No Suitable Channel Found" },
    { 0x3A, "Controller Busy" },
    { 0x3B, "Unacceptable Connection Parameters" },
    { 0x3C, "Advertising Timeout" },
    { 0x3D, "Connection Terminated due to MIC Failure" },
    { 0x3E, "Connection Failed to be Established / Synchronization Timeout" },
    { 0x3F, "MAC Connection Failed" },
    { 0x40, "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock" },
    { 0x41, "Type0 Submap Not Defined" },
    { 0x42, "Unknown Advertising Identifier" },
    { 0x43, "Limit Reached" },
    { 0x44, "Operation Cancelled by Host" },
    { 0x45, "Packet Too Long" },
    { 0x00, NULL }
};

static const value_string afh_mode_vals[] = {
    { 0x00, "AFH disabled" },
    { 0x01, "AFH enabled" },
    { 0x00, NULL }
};

static const value_string afh_reportingmode_vals[] = {
    { 0x00, "AFH reporting disabled" },
    { 0x01, "AFH reporting enabled" },
    { 0x00, NULL }
};

static const value_string afh_channelclass_vals[] = {
    { 0x00, "unknown" },
    { 0x01, "good" },
    { 0x02, "reserved" },
    { 0x03, "bad" },
    { 0x00, NULL }
};

static const value_string encryptionmode_vals[] = {
    { 0x00, "no encryption" },
    { 0x01, "encryption" },
    { 0x02, "encryption" },
    { 0x00, NULL }
};

static const value_string timingcontrol_timingchange_vals[] = {
    { 0x00, "no timing change" },
    { 0x01, "timing change" },
    { 0x00, NULL }
};

static const value_string timingcontrol_useinit2[] = {
    { 0x00, "use initialization 1" },
    { 0x01, "use initialization 2" },
    { 0x00, NULL }
};

static const value_string timingcontrol_noaccesswindow[] = {
    { 0x00, "access window" },
    { 0x01, "no access window" },
    { 0x00, NULL }
};

static const value_string dataratenofec_vals[] = {
    { 0x00, "use FEC" },
    { 0x01, "do not use FEC" },
    { 0x00, NULL }
};

static const value_string dataratepacketsizepreference_vals[] = {
    { 0x00, "no packet size preference" },
    { 0x01, "use 1-slot packets" },
    { 0x02, "use 3-slot packets" },
    { 0x03, "use 5-slot packets" },
    { 0x00, NULL }
};

static const value_string dataratedrpreference_vals[] = {
    { 0x00, "use DM1 packets" },
    { 0x01, "use 2Mb/s packets" },
    { 0x02, "use 3Mb/s packets" },
    { 0x00, NULL }
};

static const value_string scopacket_vals[] = {
    { 0x00, "HV1" },
    { 0x01, "HV2" },
    { 0x02, "HV3" },
    { 0x00, NULL }
};

static const value_string airmode_vals[] = {
    { 0x00, "ulaw log" },
    { 0x01, "Alaw log" },
    { 0x02, "CVSD" },
    { 0x03, "transparent data" },
    { 0x00, NULL }
};

static const value_string pagingscheme_vals[] = {
    { 0x00, "mandatory scheme" },
    { 0x00, NULL }
};

static const value_string pagingschemesettings_vals[] = {
    { 0x00, "R0" },
    { 0x01, "R1" },
    { 0x02, "R2" },
    { 0x00, NULL }
};

static const value_string encapsulatedmajor_vals[] = {
    { 0x01, "public key" },
    { 0x00, NULL }
};

static const value_string encapsulatedminor_vals[] = {
    { 0x01, "P-192 public key" },
    { 0x02, "P-256 public key" },
    { 0x00, NULL }
};

static const value_string clkadjmode_vals[] = {
    { 0x00, "before instant" },
    { 0x01, "after instant" },
    { 0x00, NULL }
};

static const value_string packettypetable_vals[] = {
    { 0x00, "1Mb/s only" },
    { 0x01, "2/3Mb/s" },
    { 0x00, NULL }
};

static const value_string escopackettypems_vals[] = {
    { 0x00, "POLL" },
    { 0x07, "EV3" },
    { 0x0c, "EV4" },
    { 0x0d, "EV5" },
    { 0x26, "2-EV3" },
    { 0x2c, "2-EV5" },
    { 0x37, "3-EV3" },
    { 0x3d, "3-EV5" },
    { 0x00, NULL }
};

static const value_string escopackettypesm_vals[] = {
    { 0x00, "NULL" },
    { 0x07, "EV3" },
    { 0x0c, "EV4" },
    { 0x0d, "EV5" },
    { 0x26, "2-EV3" },
    { 0x2c, "2-EV5" },
    { 0x37, "3-EV3" },
    { 0x3d, "3-EV5" },
    { 0x00, NULL }
};

static const value_string negostate_vals[] = {
    { 0, "initiate negotiation" },
    { 1, "the latest received set of negotiable parameters were possible but these parameters are preferred" },
    { 2, "the latest received set of negotiable parameters would cause a reserved slot violation" },
    { 3, "the latest received set of negotiable parameters would cause a latency violation" },
    { 4, "the latest received set of negotiable parameters are not supported" },
    { 0, NULL }
};

static const value_string iocapcap_vals[] = {
    { 0x00, "Display Only" },
    { 0x01, "Display Yes/No" },
    { 0x02, "Keyboard Only" },
    { 0x03, "No Input No Output" },
    { 0x00, NULL }
};

static const value_string iocapoobauthdata_vals[] = {
    { 0x00, "No OOB Authentication Data received" },
    { 0x01, "OOB Authentication Data received" },
    { 0x00, NULL }
};

static const value_string iocapauthreq_vals[] = {
    { 0x00, "MITM Protection Not Required - No Bonding" },
    { 0x01, "MITM Protection Required - No Bonding" },
    { 0x02, "MITM Protection Not Required - Dedicated Bonding" },
    { 0x03, "MITM Protection Required - Dedicated Bonding" },
    { 0x04, "MITM Protection Not Required - General Bonding" },
    { 0x05, "MITM Protection Required - General Bonding" },
    { 0x00, NULL }
};

static const value_string keypressnotificationtype_vals[] = {
    { 0x00, "passkey entry started" },
    { 0x01, "passkey digit entered" },
    { 0x02, "passkey digit erased" },
    { 0x03, "passkey cleared" },
    { 0x04, "passkey entry completed" },
    { 0x00, NULL }
};

static const value_string poweradjreq_vals[] = {
    { 0x00, "decrement power one step" },
    { 0x01, "increment power one step" },
    { 0x02, "increase to maximum power" },
    { 0x00, NULL }
};

static const value_string poweradjresp_vals[] = {
    { 0x00, "not supported" },
    { 0x01, "changed one step" },
    { 0x02, "max power" },
    { 0x03, "min power" },
    { 0x00, NULL }
};

static const value_string samupdatemode_vals[] = {
    { 0, "Existing SAM slot maps containing any type 0 submaps are invalidated" },
    { 1, "The defined type 0 submap takes effect immediately" },
    { 2, "The defined type 0 submap takes effect at the start of the next sub-interval" },
    { 0, NULL }
};

static const unit_name_string units_ppm = { " ppm", NULL };

static const unit_name_string units_slots = { " slot", " slots" };

static const unit_name_string units_slotpairs = { " slot pair", " slot pairs" };




static void decode_uint8_binary(char *s, uint8_t value)
{
    for (unsigned i = 0; i < 8 && i + 1 < ITEM_LABEL_LENGTH; ++i, value <<= 1)
        *s++ = '0' + ((value >> 7) & 1);
    *s = 0;
}

void proto_register_btlmp(void);
void proto_reg_handoff_btlmp(void);

static int
dissect_btlmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item                *btlmp_item;
    proto_tree                *btlmp_tree;
    int                        offset = 0;
    uint16_t                   opcode;
    connection_info_t *connection_info = (connection_info_t *)data;

    btlmp_item = proto_tree_add_item(tree, proto_btlmp, tvb, offset, -1, ENC_NA);
    btlmp_tree = proto_item_add_subtree(btlmp_item, ett_btlmp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT LMP");

    for (unsigned i = 0; i < array_length(hf_opcode); ++i)
        proto_tree_add_item(btlmp_tree, hf_opcode[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
    opcode = tvb_get_uint8(tvb, offset) >> 1;
    offset += 1;
    if (opcode >= 0x7c) {
        opcode &= 3;
        proto_tree_add_item(btlmp_tree, hf_escopcode[opcode], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++opcode;
        opcode <<= 8;
        opcode |= tvb_get_uint8(tvb, offset);
        offset += 1;
    }
    switch (opcode) {
    case 0x001: // LMP_name_req
        break;

    case 0x002: // LMP_name_res
        proto_tree_add_item(btlmp_tree, hf_param_nameoffset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_namelength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        if (tvb_captured_length_remaining(tvb, offset) <= 0)
            break;
        proto_tree_add_item(btlmp_tree, hf_param_namefragment, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        offset = tvb_reported_length(tvb);
        break;

    case 0x003: // LMP_accepted
        proto_tree_add_item(btlmp_tree, hf_accept_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x004: // LMP_not_accepted
        proto_tree_add_item(btlmp_tree, hf_accept_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_errorcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x005: // LMP_clkoffset_req
        break;

    case 0x006: // LMP_clkoffset_res
        proto_tree_add_item(btlmp_tree, hf_param_clockoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x007: // LMP_detach
        proto_tree_add_item(btlmp_tree, hf_errorcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x008: // LMP_in_rand
    case 0x009: // LMP_comb_key
    case 0x00b: // LMP_au_rand
    case 0x00d: // LMP_temp_rand
    case 0x011: // LMP_start_encryption_req
    case 0x042: // LMP_pause_encryption_aes_req
        proto_tree_add_item(btlmp_tree, hf_param_rand, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x00a: // LMP_unit_key
    case 0x00e: // LMP_temp_key
        proto_tree_add_item(btlmp_tree, hf_param_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x00c: // LMP_sres
        proto_tree_add_item(btlmp_tree, hf_param_authresp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case 0x00f: // LMP_encryption_mode_req
        proto_tree_add_item(btlmp_tree, hf_param_encryptionmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x010: // LMP_encryption_key_size_req
        proto_tree_add_item(btlmp_tree, hf_param_encryptionkeysize, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x012: // LMP_stop_encryption_req
        break;

    case 0x013: // LMP_switch_req
        proto_tree_add_item(btlmp_tree, hf_param_switchinstant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case 0x014: // LMP_hold
    case 0x015: // LMP_hold_req
        proto_tree_add_item(btlmp_tree, hf_param_holdtime, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_holdinstant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case 0x017: // LMP_sniff_req
        for (unsigned i = 0; i < array_length(hf_param_timingcontrolflags); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_timingcontrolflags[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_dsniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_tsniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_sniffattempt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_snifftimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x018: // LMP_unsniff_req
        break;

    case 0x01f: // LMP_incr_power_req
    case 0x020: // LMP_decr_power_req
        proto_tree_add_item(btlmp_tree, hf_param_futureuse1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x021: // LMP_max_power
    case 0x022: // LMP_min_power
    case 0x023: // LMP_auto_rate
       break;

    case 0x024: // LMP_preferred_rate
        for (unsigned i = 0; i < array_length(hf_param_datarate); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_datarate[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;

    case 0x025: // LMP_version_req
    case 0x026: // LMP_version_res
        proto_tree_add_item(btlmp_tree, hf_param_versnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_compid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_subversnr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x027: // LMP_features_req
    case 0x028: // LMP_features_res
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte0); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte0[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte1); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte1[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte2); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte2[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte3); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte3[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte4); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte4[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte5); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte5[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte6); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte6[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte7); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte7[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x029: // LMP_quality_of_service
    case 0x02a: // LMP_quality_of_service_req
        proto_tree_add_item(btlmp_tree, hf_param_pollinterval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_nbc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x02b: // LMP_SCO_link_req
        proto_tree_add_item(btlmp_tree, hf_param_scohandle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_timingcontrolflags); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_timingcontrolflags[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_dsco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_tsco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_scopacket, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_airmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x02c: // LMP_remove_SCO_link_req
        proto_tree_add_item(btlmp_tree, hf_param_scohandle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_errorcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x02d: // LMP_max_slot
    case 0x02e: // LMP_max_slot_req
        proto_tree_add_item(btlmp_tree, hf_param_slots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x02f: // LMP_timing_accuracy_req
        break;

    case 0x030: // LMP_timing_accuracy_res
        proto_tree_add_item(btlmp_tree, hf_param_tmgacc_drift, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_tmgacc_jitter, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x031: // LMP_setup_complete
    case 0x032: // LMP_use_semi_permanent_key
    case 0x033: // LMP_host_connection_req
       break;

    case 0x034: // LMP_slot_offset
        proto_tree_add_item(btlmp_tree, hf_param_slotoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_bdaddr, tvb, offset, 6, ENC_NA);
        offset += 6;
        break;

    case 0x035: // LMP_page_mode_req
    case 0x036: // LMP_page_scan_mode_req
        proto_tree_add_item(btlmp_tree, hf_param_pagingscheme, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_pagingschemesettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x037: // LMP_supervision_timeout
        proto_tree_add_item(btlmp_tree, hf_param_supervisiontimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x038: // LMP_test_activate
        break;

    case 0x039: // LMP_test_control
        proto_tree_add_item(btlmp_tree, hf_param_testscenario, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testhoppingmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testtxfrequency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testrxfrequency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testpowercontrolmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testpollperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testpackettype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_testdatalength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x03a: // LMP_encryption_key_size_mask_req
        break;

    case 0x03b: // LMP_encryption_key_size_mask_res
        proto_tree_add_item(btlmp_tree, hf_param_keysizemask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x03c: // LMP_set_AFH
        proto_tree_add_item(btlmp_tree, hf_param_afh_instant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(btlmp_tree, hf_param_afh_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_afh_channelmap); ++i, ++offset)
            proto_tree_add_item(btlmp_tree, hf_param_afh_channelmap[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;

    case 0x03d: // LMP_encapsulated_header
        proto_tree_add_item(btlmp_tree, hf_param_encapsulatedmajor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_encapsulatedminor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_encapsulatedlength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x03e: // LMP_encapsulated_payload
        proto_tree_add_item(btlmp_tree, hf_param_encapsulateddata, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x03f: // LMP_Simple_Pairing_Confirm
        proto_tree_add_item(btlmp_tree, hf_param_simplepaircommit, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x040: // LMP_Simple_Pairing_Number
        proto_tree_add_item(btlmp_tree, hf_param_simplepairnonce, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x041: // LMP_DHkey_Check
        proto_tree_add_item(btlmp_tree, hf_param_dhkeyconfirm, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x401: // LMP_accepted_ext
        proto_tree_add_item(btlmp_tree, hf_accept_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_accept_escopcode[tvb_get_uint8(tvb, offset - 1) & 3], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x402: // LMP_not_accepted_ext
        proto_tree_add_item(btlmp_tree, hf_accept_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_accept_escopcode[tvb_get_uint8(tvb, offset - 1) & 3], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_errorcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x403: // LMP_features_req_ext
    case 0x404: // LMP_features_res_ext
        proto_tree_add_item(btlmp_tree, hf_param_features_page, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_max_supported_page, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        switch (tvb_get_uint8(tvb, offset - 2)) {
        case 0:
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte0); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte0[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte1); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte1[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte2); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte2[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte3); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte3[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte4); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte4[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte5); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte5[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte6); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte6[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page0_byte7); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page0_byte7[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            break;

        case 1:
            for (unsigned i = 0; i < array_length(hf_param_feature_page1_byte0); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page1_byte0[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            break;

        case 2:
            for (unsigned i = 0; i < array_length(hf_param_feature_page2_byte0); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page2_byte0[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            for (unsigned i = 0; i < array_length(hf_param_feature_page2_byte1); ++i)
                proto_tree_add_item(btlmp_tree, hf_param_feature_page2_byte1[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            break;

        default:
            break;
        }
        break;

    case 0x405: // LMP_clk_adj
        proto_tree_add_item(btlmp_tree, hf_param_clkadjid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjinstant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjus, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjclk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case 0x406: // LMP_clk_adj_ack
        proto_tree_add_item(btlmp_tree, hf_param_clkadjid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x407: // LMP_clk_adj_req
        proto_tree_add_item(btlmp_tree, hf_param_clkadjus, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_clkadjperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x40b: // LMP_packet_type_table_req
        proto_tree_add_item(btlmp_tree, hf_param_packettypetable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x40c: // LMP_eSCO_link_req
        btbredr_rf_add_esco_link(connection_info, pinfo, tvb_get_uint8(tvb, offset), tvb_get_uint8(tvb, offset + 1),
                                 tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN), tvb_get_uint16(tvb, offset + 10, ENC_LITTLE_ENDIAN));
        proto_tree_add_item(btlmp_tree, hf_param_escohandle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escoltaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_timingcontrolflags); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_timingcontrolflags[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escot, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escow, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escopackettypems, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escopackettypesm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_escopacketlengthms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_escopacketlengthsm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_airmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_negostate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x40d: // LMP_remove_eSCO_link_req
        btbredr_rf_remove_esco_link(connection_info, pinfo, tvb_get_uint8(tvb, offset));
        proto_tree_add_item(btlmp_tree, hf_param_escohandle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_errorcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x410: // LMP_channel_classification_req
        proto_tree_add_item(btlmp_tree, hf_param_afh_reportingmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_afh_mininterval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_afh_maxinterval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x411: // LMP_channel_classification
        for (unsigned i = 0; i < array_length(hf_param_afh_channelclass); ++i)
            for (unsigned j = 0; j < array_length(hf_param_afh_channelclass[0]); ++j)
                proto_tree_add_item(btlmp_tree, hf_param_afh_channelclass[i][j], tvb, offset + i, 1, ENC_LITTLE_ENDIAN);
        offset += array_length(hf_param_afh_channelclass);
        break;

    case 0x415: // LMP_sniff_subrating_req
    case 0x416: // LMP_sniff_subrating_res
        proto_tree_add_item(btlmp_tree, hf_param_maxsniffsubrate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_minsniffmodetimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(btlmp_tree, hf_param_sniffsubratinginstant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case 0x417: // LMP_pause_encryption_req
    case 0x418: // LMP_resume_encryption_req
        break;

    case 0x419: // LMP_IO_Capability_req
    case 0x41a: // LMP_IO_Capability_res
        proto_tree_add_item(btlmp_tree, hf_param_iocapcap, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_iocapoobauthdata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_iocapauthreq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x41b: // LMP_numeric_comparison_failed
    case 0x41c: // LMP_passkey_failed
    case 0x41d: // LMP_oob_failed
        break;

    case 0x41e: // LMP_keypress_notification
        proto_tree_add_item(btlmp_tree, hf_param_keypressnotificationtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x41f: // LMP_power_control_req
         proto_tree_add_item(btlmp_tree, hf_param_poweradjreq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
       break;

    case 0x420: // LMP_power_control_res
        for (unsigned i = 0; i < array_length(hf_param_poweradjresp); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_poweradjresp[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        break;

    case 0x421: // LMP_ping_req
    case 0x422: // LMP_ping_res
        break;

    case 0x423: // LMP_SAM_set_type0
        proto_tree_add_item(btlmp_tree, hf_param_samupdatemode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_samtype0submap, tvb, offset, 14, ENC_NA);
        offset += 14;
        break;

    case 0x424: // LMP_SAM_define_map
        proto_tree_add_item(btlmp_tree, hf_param_samindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_samtsm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_samnsm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_samsubmaps, tvb, offset, 12, ENC_NA);
        offset += 12;
        break;

    case 0x425: // LMP_SAM_switch
        proto_tree_add_item(btlmp_tree, hf_param_samindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        for (unsigned i = 0; i < array_length(hf_param_timingcontrolflags); ++i)
            proto_tree_add_item(btlmp_tree, hf_param_timingcontrolflags[i], tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_samd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ++offset;
        proto_tree_add_item(btlmp_tree, hf_param_saminstant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    default:
        break;
    }
    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(btlmp_tree, hf_params, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        offset = tvb_reported_length(tvb);
    }
    return offset;
}

void
proto_register_btlmp(void)
{
    static hf_register_info hf[] = {
        {  &hf_opcode[0],
            { "Opcode",                                         "btlmp.opcode.byte0",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_opcode[1],
            { "TID",                                            "btlmp.opcode.tid",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_opcode[2],
            { "Opcode",                                         "btlmp.opcode.opcode",
            FT_UINT8, BASE_DEC_HEX, VALS(opcode_vals), 0xfe,
            NULL, HFILL }
        },
        {  &hf_escopcode[0],
            { "Escape 1 Opcode",                                "btlmp.opcode.escaped",
            FT_UINT16, BASE_DEC_HEX, VALS(escape1_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_escopcode[1],
            { "Escape 2 Opcode",                                "btlmp.opcode.escaped",
            FT_UINT16, BASE_DEC_HEX, VALS(escape2_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_escopcode[2],
            { "Escape 3 Opcode",                                "btlmp.opcode.escaped",
            FT_UINT16, BASE_DEC_HEX, VALS(escape3_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_escopcode[3],
            { "Escape 4 Opcode",                                "btlmp.opcode.escaped",
            FT_UINT16, BASE_DEC_HEX, VALS(escape4_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_accept_opcode,
            { "Opcode",                                         "btlmp.accept_opcode",
            FT_UINT8, BASE_DEC_HEX, VALS(opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_accept_escopcode[0],
            { "Escape 1 Opcode",                                "btlmp.accept_opcode1",
            FT_UINT16, BASE_DEC_HEX, VALS(escape1_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_accept_escopcode[1],
            { "Escape 2 Opcode",                                "btlmp.accept_opcode2",
            FT_UINT16, BASE_DEC_HEX, VALS(escape2_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_accept_escopcode[2],
            { "Escape 3 Opcode",                                "btlmp.accept_opcode3",
            FT_UINT16, BASE_DEC_HEX, VALS(escape3_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_accept_escopcode[3],
            { "Escape 4 Opcode",                                "btlmp.accept_opcode4",
            FT_UINT16, BASE_DEC_HEX, VALS(escape4_opcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_errorcode,
            { "Error Code",                                     "btlmp.errorcode",
            FT_UINT8, BASE_DEC_HEX, VALS(errorcode_vals), 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[0],
            { "Feature Page 0 Byte 0",                          "btlmp.feature.page0.byte0",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[1],
            { "3 slot packets",                                 "btlmp.feature.page0.3slotpackets",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[2],
            { "5 slot packets",                                 "btlmp.feature.page0.5slotpackets",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[3],
            { "Encryption",                                     "btlmp.feature.page0.encryption",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[4],
            { "Slot offset",                                    "btlmp.feature.page0.slotoffset",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[5],
            { "Timing accuracy",                                "btlmp.feature.page0.timingaccuracy",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[6],
            { "Role switch",                                    "btlmp.feature.page0.roleswitch",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[7],
            { "Hold mode",                                      "btlmp.feature.page0.holdmode",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte0[8],
            { "Sniff mode",                                     "btlmp.feature.page0.sniffmode",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[0],
            { "Feature Page 0 Byte 1",                          "btlmp.feature.page0.byte1",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[1],
            { "Reserved",                                       "btlmp.feature.page0.reserved1",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[2],
            { "Power control requests",                         "btlmp.feature.page0.powercontrolrequests",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[3],
            { "Channel quality driven data rate (CQDDR)",       "btlmp.feature.page0.cqddr",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[4],
            { "SCO link",                                       "btlmp.feature.page0.scolink",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[5],
            { "HV2 packets",                                    "btlmp.feature.page0.hv2packets",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[6],
            { "HV3 packets",                                    "btlmp.feature.page0.hv3packets",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[7],
            { "u-law log synchronous data",                     "btlmp.feature.page0.ulaw",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte1[8],
            { "A-law log synchronous data",                     "btlmp.feature.page0.alaw",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[0],
            { "Feature Page 0 Byte 2",                          "btlmp.feature.page0.byte2",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[1],
            { "CVSD synchronous data",                          "btlmp.feature.page0.cvsd",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[2],
            { "Paging parameter negotiation",                   "btlmp.feature.page0.pagingparameter",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[3],
            { "Power control",                                  "btlmp.feature.page0.powercontrol",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[4],
            { "Transparent synchronous data",                   "btlmp.feature.page0.transparentsynchronous",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[5],
            { "Flow control lag (least significant bit)",       "btlmp.feature.page0.flowcontrollag",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte2[6],
            { "Broadcast Encryption",                           "btlmp.feature.page0.broadcastencryption",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[0],
            { "Feature Page 0 Byte 3",                          "btlmp.feature.page0.byte3",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[1],
            { "Reserved",                                       "btlmp.feature.page0.reserved2",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[2],
            { "Enhanced Data Rate ACL 2 Mb/s mode",             "btlmp.feature.page0.edracl2",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[3],
            { "Enhanced Data Rate ACL 3 Mb/s mode",             "btlmp.feature.page0.edracl3",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[4],
            { "Enhanced inquiry scan",                          "btlmp.feature.page0.enhinqscan",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[5],
            { "Interlaced inquiry scan",                        "btlmp.feature.page0.interlacedinqscan",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[6],
            { "Interlaced page scan",                           "btlmp.feature.page0.interlacedpgscan",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[7],
            { "RSSI with inquiry results",                      "btlmp.feature.page0.inqrssi",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte3[8],
            { "Extended SCO link (EV3 packets)",                "btlmp.feature.page0.escolink",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[0],
            { "Feature Page 0 Byte 4",                          "btlmp.feature.page0.byte4",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[1],
            { "EV4 packets",                                    "btlmp.feature.page0.ev4",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[2],
            { "EV5 packets",                                    "btlmp.feature.page0.ev5",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[3],
            { "Reserved",                                       "btlmp.feature.page0.reserved3",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[4],
            { "AFH capable peripheral",                              "btlmp.feature.page0.afhcapableperipheral",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[5],
            { "AFH classification peripheral",                       "btlmp.feature.page0.afhclassificationperipheral",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[6],
            { "BR/EDR Not Supported",                           "btlmp.feature.page0.bredrnotsupp",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[7],
            { "LE Supported (Controller)",                      "btlmp.feature.page0.lesuppcontroller",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte4[8],
            { "3-slot Enhanced Data Rate ACL packets",          "btlmp.feature.page0.3slotedracl",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[0],
            { "Feature Page 0 Byte 5",                          "btlmp.feature.page0.byte5",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[1],
            { "5-slot Enhanced Data Rate ACL packets",          "btlmp.feature.page0.5slotedracl",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[2],
            { "Sniff subrating",                                "btlmp.feature.page0.sniffsubrating",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[3],
            { "Pause encryption",                               "btlmp.feature.page0.pauseencrypt",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[4],
            { "AFH capable central",                             "btlmp.feature.page0.afhcapablecentral",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[5],
            { "AFH classification central",                      "btlmp.feature.page0.afhclassificationcentral",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[6],
            { "Enhanced Data Rate eSCO 2 Mb/s mode",            "btlmp.feature.page0.edresco2",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[7],
            { "Enhanced Data Rate eSCO 3 Mb/s mode",            "btlmp.feature.page0.edresco3",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte5[8],
            { "3-slot Enhanced Data Rate eSCO packets",         "btlmp.feature.page0.3slotedresco",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[0],
            { "Feature Page 0 Byte 6",                          "btlmp.feature.page0.byte6",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[1],
            { "Extended Inquiry Response",                      "btlmp.feature.page0.extinqresp",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[2],
            { "Simultaneous LE and BR/EDR to Same Device Capable (Controller)", "btlmp.feature.page0.simullebredrcontroller",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[3],
            { "Reserved",                                       "btlmp.feature.page0.reserved4",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[4],
            { "Secure Simple Pairing (Controller Support)",     "btlmp.feature.page0.securesimplepaircontroller",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[5],
            { "Encapsulated PDU",                               "btlmp.feature.page0.encpdu",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[6],
            { "Erroneous Data Reporting",                       "btlmp.feature.page0.errdatareport",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[7],
            { "Non-flushable Packet Boundary Flag",             "btlmp.feature.page0.nonflushboundary",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte6[8],
            { "Reserved",                                       "btlmp.feature.page0.reserved5",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte7[0],
            { "Feature Page 0 Byte 1",                          "btlmp.feature.page0.byte7",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte7[1],
            { "HCI Link Supervision Timeout Changed event",     "btlmp.feature.page0.hcilinksupervisiontimeoutchgevt",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte7[2],
            { "Variable Inquiry TX Power Level",                "btlmp.feature.page0.varinqtxpwr",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte7[3],
            { "Enhanced Power Control",                         "btlmp.feature.page0.enhpowercontrol",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte7[4],
            { "Reserved",                                       "btlmp.feature.page0.reserved6",
            FT_UINT8, BASE_DEC, NULL, 0x78,
            NULL, HFILL }
        },
        {  &hf_param_feature_page0_byte7[5],
            { "Extended features",                              "btlmp.feature.page0.extftr",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page1_byte0[0],
            { "Feature Page 1 Byte 0",                          "btlmp.feature.page1.byte0",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page1_byte0[1],
            { "Secure Simple Pairing (Host Support)",           "btlmp.feature.page1.securesimplepairhost",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page1_byte0[2],
            { "LE Supported (Host)",                            "btlmp.feature.page1.lesupphost",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page1_byte0[3],
            { "Simultaneous LE and BR/EDR to Same Device Capable (Host)", "btlmp.feature.page1.simullebredrhost",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page1_byte0[4],
            { "Secure Connections (Host Support)",              "btlmp.feature.page1.secureconnhost",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page1_byte0[5],
            { "Reserved",                                       "btlmp.feature.page1.reserved1",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[0],
            { "Feature Page 2 Byte 0",                          "btlmp.feature.page2.byte0",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[1],
            { "Connectionless Peripheral Broadcast - Central",        "btlmp.feature.page2.cpbcentral",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[2],
            { "Connectionless Peripheral Broadcast - Peripheral",         "btlmp.feature.page2.cpbperipheral",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[3],
            { "Synchronization Train",                          "btlmp.feature.page2.synctrain",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[4],
            { "Synchronization Scan",                           "btlmp.feature.page2.syncscan",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[5],
            { "HCI_Inquiry_Response_Notification event",        "btlmp.feature.page2.hciinqrespnotifevt",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[6],
            { "Generalized interlaced scan",                    "btlmp.feature.page2.generalinterlacedscan",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[7],
            { "Coarse Clock Adjustment",                        "btlmp.feature.page2.coarseclockadj",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte0[8],
            { "Reserved",                                       "btlmp.feature.page2.reserved1",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte1[0],
            { "Feature Page 2 Byte 1",                          "btlmp.feature.page2.byte1",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte1[1],
            { "Secure Connections (Controller Support)",        "btlmp.feature.page2.secureconncontroller",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte1[2],
            { "Ping",                                           "btlmp.feature.page2.ping",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte1[3],
            { "Slot Availability Mask",                         "btlmp.feature.page2.slotavailabilitymask",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte1[4],
            { "Train nudging",                                  "btlmp.feature.page2.trainnudging",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        {  &hf_param_feature_page2_byte1[5],
            { "Reserved",                                       "btlmp.feature.page2.reserved2",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        {  &hf_param_features_page,
            { "Feature Page",                                   "btlmp.feature.features_page",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_max_supported_page,
            { "Max Supported Page",                             "btlmp.feature.max_supported_page",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_versnr,
            { "VersNr",                                         "btlmp.version.versnr",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_compid,
            { "CompId",                                         "btlmp.version.CompId",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_subversnr,
            { "SubVersNr",                                      "btlmp.version.SubVersNr",
              FT_UINT16, BASE_HEX, NULL, 0x00,
              NULL, HFILL }
        },
        {  &hf_param_namelength,
           { "Name Length",                                     "btlmp.name.length",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_nameoffset,
           { "Name Offset",                                     "btlmp.name.offset",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_namefragment,
           { "Name Fragment",                                   "btlmp.name.fragment",
             FT_STRINGZPAD, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_param_afh_mode,
           { "AFH Mode",                                        "btlmp.afh.mode",
             FT_UINT8, BASE_HEX, VALS(afh_mode_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_instant,
           { "AFH Instant",                                     "btlmp.afh.instant",
             FT_UINT32, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[0],
           { "AFH Channel Map 0",                               "btlmp.afh.channelmap0",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[1],
           { "AFH Channel Map 1",                               "btlmp.afh.channelmap1",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[2],
           { "AFH Channel Map 2",                               "btlmp.afh.channelmap2",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[3],
           { "AFH Channel Map 3",                               "btlmp.afh.channelmap3",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[4],
           { "AFH Channel Map 4",                               "btlmp.afh.channelmap4",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[5],
           { "AFH Channel Map 5",                               "btlmp.afh.channelmap5",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[6],
           { "AFH Channel Map 6",                               "btlmp.afh.channelmap6",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[7],
           { "AFH Channel Map 7",                               "btlmp.afh.channelmap7",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[8],
           { "AFH Channel Map 8",                               "btlmp.afh.channelmap8",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelmap[9],
           { "AFH Channel Map 9",                               "btlmp.afh.channelmap9",
             FT_UINT32, BASE_CUSTOM, CF_FUNC(decode_uint8_binary), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_reportingmode,
           { "AFH Reporting Mode",                              "btlmp.afh.reportingmode",
             FT_UINT8, BASE_HEX, VALS(afh_reportingmode_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_mininterval,
           { "AFH Min Interval",                                "btlmp.afh.mininterval",
             FT_UINT16, BASE_HEX_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_maxinterval,
           { "AFH Max Interval",                                "btlmp.afh.maxinterval",
             FT_UINT16, BASE_HEX_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[0][0],
           { "AFH Channel 0-1 Classification",                  "btlmp.afh.channelclass0",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[0][1],
           { "AFH Channel 2-3 Classification",                  "btlmp.afh.channelclass2",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[0][2],
           { "AFH Channel 4-5 Classification",                  "btlmp.afh.channelclass4",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[0][3],
           { "AFH Channel 6-7 Classification",                  "btlmp.afh.channelclass6",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[1][0],
           { "AFH Channel 8-9 Classification",                  "btlmp.afh.channelclass8",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[1][1],
           { "AFH Channel 10-11 Classification",                "btlmp.afh.channelclass10",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[1][2],
           { "AFH Channel 12-13 Classification",                "btlmp.afh.channelclass12",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[1][3],
           { "AFH Channel 14-15 Classification",                "btlmp.afh.channelclass14",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[2][0],
           { "AFH Channel 16-17 Classification",                "btlmp.afh.channelclass16",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[2][1],
           { "AFH Channel 18-19 Classification",                "btlmp.afh.channelclass18",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[2][2],
           { "AFH Channel 20-21 Classification",                "btlmp.afh.channelclass20",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[2][3],
           { "AFH Channel 22-23 Classification",                "btlmp.afh.channelclass22",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[3][0],
           { "AFH Channel 24-25 Classification",                "btlmp.afh.channelclass24",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[3][1],
           { "AFH Channel 26-27 Classification",                "btlmp.afh.channelclass26",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[3][2],
           { "AFH Channel 28-29 Classification",                "btlmp.afh.channelclass28",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[3][3],
           { "AFH Channel 30-31 Classification",                "btlmp.afh.channelclass30",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[4][0],
           { "AFH Channel 32-33 Classification",                "btlmp.afh.channelclass32",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[4][1],
           { "AFH Channel 34-35 Classification",                "btlmp.afh.channelclass34",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[4][2],
           { "AFH Channel 36-37 Classification",                "btlmp.afh.channelclass36",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[4][3],
           { "AFH Channel 38-39 Classification",                "btlmp.afh.channelclass38",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[5][0],
           { "AFH Channel 40-41 Classification",                "btlmp.afh.channelclass40",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[5][1],
           { "AFH Channel 42-43 Classification",                "btlmp.afh.channelclass42",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[5][2],
           { "AFH Channel 44-45 Classification",                "btlmp.afh.channelclass44",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[5][3],
           { "AFH Channel 46-47 Classification",                "btlmp.afh.channelclass46",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[6][0],
           { "AFH Channel 48-49 Classification",                "btlmp.afh.channelclass48",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[6][1],
           { "AFH Channel 50-51 Classification",                "btlmp.afh.channelclass50",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[6][2],
           { "AFH Channel 52-53 Classification",                "btlmp.afh.channelclass52",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[6][3],
           { "AFH Channel 54-55 Classification",                "btlmp.afh.channelclass54",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[7][0],
           { "AFH Channel 56-57 Classification",                "btlmp.afh.channelclass56",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[7][1],
           { "AFH Channel 58-59 Classification",                "btlmp.afh.channelclass58",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[7][2],
           { "AFH Channel 60-61 Classification",                "btlmp.afh.channelclass60",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[7][3],
           { "AFH Channel 62-63 Classification",                "btlmp.afh.channelclass62",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[8][0],
           { "AFH Channel 64-65 Classification",                "btlmp.afh.channelclass64",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[8][1],
           { "AFH Channel 66-67 Classification",                "btlmp.afh.channelclass66",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[8][2],
           { "AFH Channel 68-69 Classification",                "btlmp.afh.channelclass68",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[8][3],
           { "AFH Channel 70-71 Classification",                "btlmp.afh.channelclass70",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[9][0],
           { "AFH Channel 72-73 Classification",                "btlmp.afh.channelclass72",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[9][1],
           { "AFH Channel 74-75 Classification",                "btlmp.afh.channelclass74",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[9][2],
           { "AFH Channel 76-77 Classification",                "btlmp.afh.channelclass76",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_afh_channelclass[9][3],
           { "AFH Channel 78 Classification",                   "btlmp.afh.channelclass78",
             FT_UINT8, BASE_HEX, VALS(afh_channelclass_vals), 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_rand,
           { "Random Number",                                   "btlmp.randomnumber",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_key,
           { "Key",                                             "btlmp.key",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clockoffset,
           { "Clock Offset",                                    "btlmp.clockoffset",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slotpairs, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_authresp,
           { "Authentication Response",                         "btlmp.authenticationresponse",
             FT_UINT32, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_encryptionmode,
           { "Encryption Mode",                                 "btlmp.encryptionmode",
             FT_UINT8, BASE_HEX, VALS(encryptionmode_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_encryptionkeysize,
           { "Encryption Key Size",                             "btlmp.encryptionkeysize",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_switchinstant,
           { "Switch Instant",                                  "btlmp.switchinstant",
             FT_UINT32, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_holdtime,
           { "Hold Time",                                       "btlmp.holdtime",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_holdinstant,
           { "Hold Instant",                                    "btlmp.holdinstant",
             FT_UINT32, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_dsniff,
           { "Dsniff",                                          "btlmp.sniff.d",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_tsniff,
           { "Tsniff",                                          "btlmp.sniff.t",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_sniffattempt,
           { "Sniff Attempt",                                   "btlmp.sniff.attempt",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_snifftimeout,
           { "Sniff Timeout",                                   "btlmp.sniff.timeout",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_timingcontrolflags[0],
           { "Timing Control Flags",                            "btlmp.timingcontrol.flags",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_timingcontrolflags[1],
           { "Timing Change",                                   "btlmp.timingcontrol.timingchange",
             FT_UINT8, BASE_DEC, VALS(timingcontrol_timingchange_vals), 0x01,
             NULL, HFILL }
        },
        {  &hf_param_timingcontrolflags[2],
           { "Use Initialization 2",                            "btlmp.timingcontrol.useinit2",
             FT_UINT8, BASE_DEC, VALS(timingcontrol_useinit2), 0x02,
             NULL, HFILL }
        },
        {  &hf_param_timingcontrolflags[3],
           { "No Access Window",                                "btlmp.timingcontrol.noaccesswindow",
             FT_UINT8, BASE_DEC, VALS(timingcontrol_noaccesswindow), 0x04,
             NULL, HFILL }
        },
        {  &hf_param_timingcontrolflags[4],
           { "Reserved",                                        "btlmp.timingcontrol.reserved",
             FT_UINT8, BASE_HEX, NULL, 0xf8,
             NULL, HFILL }
        },
        {  &hf_param_futureuse1,
           { "Future Use",                                      "btlmp.futureuse1",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_datarate[0],
           { "Datarate",                                        "btlmp.datarate.flags",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_datarate[1],
           { "Do not use FEC",                                  "btlmp.datarate.nofec",
             FT_UINT8, BASE_DEC, VALS(dataratenofec_vals), 0x01,
             NULL, HFILL }
        },
        {  &hf_param_datarate[2],
           { "Basic Rate Packet Size Preference",               "btlmp.datarate.brpacketsizepreference",
             FT_UINT8, BASE_DEC, VALS(dataratepacketsizepreference_vals), 0x06,
             NULL, HFILL }
        },
        {  &hf_param_datarate[3],
           { "Enhanced Data Rate Datarate Preference",          "btlmp.datarate.edrdataratepreference",
             FT_UINT8, BASE_DEC, VALS(dataratedrpreference_vals), 0x18,
             NULL, HFILL }
        },
        {  &hf_param_datarate[4],
           { "Enhanced Data Rate Packet Size Preference",       "btlmp.datarate.edrpacketsizepreference",
             FT_UINT8, BASE_DEC, VALS(dataratepacketsizepreference_vals), 0x60,
             NULL, HFILL }
        },
        {  &hf_param_datarate[5],
           { "Reserved",                                        "btlmp.datarate.reserved",
             FT_UINT8, BASE_DEC, NULL, 0x80,
             NULL, HFILL }
        },
        {  &hf_param_pollinterval,
           { "Poll Interval",                                   "btlmp.qos.pollinterval",
             FT_UINT16, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_nbc,
           { "NBC",                                             "btlmp.qos.nbc",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_scohandle,
           { "SCO Handle",                                      "btlmp.sco.handle",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_dsco,
           { "Dsco",                                            "btlmp.sco.d",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_tsco,
           { "Tsco",                                            "btlmp.sco.t",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_scopacket,
           { "SCO packet",                                      "btlmp.sco.packet",
             FT_UINT8, BASE_HEX, VALS(scopacket_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_airmode,
           { "Air Mode",                                        "btlmp.sco.airmode",
             FT_UINT8, BASE_HEX, VALS(airmode_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_slots,
           { "Slots",                                           "btlmp.slots",
             FT_UINT8, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_tmgacc_drift,
           { "Drift",                                           "btlmp.timingaccuracy.drift",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_ppm, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_tmgacc_jitter,
           { "Jitter",                                          "btlmp.timingaccuracy.jitter",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_microsecond_microseconds, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_slotoffset,
           { "Slot Offset",                                     "btlmp.slotoffset",
             FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_microsecond_microseconds, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_bdaddr,
           { "Address",                                         "btlmp.bd_addr",
             FT_ETHER, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_pagingscheme,
           { "Paging Scheme",                                   "btlmp.paging.scheme",
             FT_UINT8, BASE_HEX, VALS(pagingscheme_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_pagingschemesettings,
           { "Paging Scheme Settings",                          "btlmp.paging.schemesettings",
             FT_UINT8, BASE_HEX, VALS(pagingschemesettings_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_supervisiontimeout,
           { "Supervision Timeout",                             "btlmp.supervisiontimeout",
             FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testscenario,
           { "Scenario",                                        "btlmp.test.scenario",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testhoppingmode,
           { "Hopping Mode",                                    "btlmp.test.hoppingmode",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testtxfrequency,
           { "TX frequency",                                    "btlmp.test.txfrequency",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testrxfrequency,
           { "RX frequency",                                    "btlmp.test.rxfrequency",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testpowercontrolmode,
           { "Power Control Mode",                              "btlmp.test.powercontrolmode",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testpollperiod,
           { "Poll Period",                                     "btlmp.test.pollperiod",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testpackettype,
           { "Packet Type",                                     "btlmp.test.packettype",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_testdatalength,
           { "Length of Test Data",                             "btlmp.test.datalength",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_keysizemask,
           { "Key Size Mask",                                   "btlmp.keysizemask",
             FT_UINT16, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_encapsulatedmajor,
           { "Encapsulated Major Type",                         "btlmp.encapsulated.major",
             FT_UINT8, BASE_HEX, VALS(encapsulatedmajor_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_encapsulatedminor,
           { "Encapsulated Minor Type",                         "btlmp.encapsulated.minor",
             FT_UINT8, BASE_HEX, VALS(encapsulatedminor_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_encapsulatedlength,
           { "Encapsulated Payload Length",                     "btlmp.encapsulated.payloadlength",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_encapsulateddata,
           { "Encapsulated Data",                               "btlmp.encapsulated.data",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_simplepaircommit,
           { "Commitment Value",                                "btlmp.simplepair.commit",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_simplepairnonce,
           { "Nonce Value",                                     "btlmp.simplepair.nonce",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_dhkeyconfirm,
           { "Confirmation Value",                              "btlmp.dhkey.confirm",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjid,
           { "Clock Adjust ID",                                 "btlmp.clkadj.id",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjinstant,
           { "Clock Adjust Instant",                            "btlmp.clkadj.instant",
             FT_UINT32, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjus,
           { "Clock Adjust Microseconds",                       "btlmp.clkadj.us",
             FT_INT16, BASE_DEC | BASE_UNIT_STRING, &units_microsecond_microseconds, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjslots,
           { "Clock Adjust Slots",                              "btlmp.clkadj.slots",
             FT_UINT8, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjmode,
           { "Clock Adjust Mode",                               "btlmp.clkadj.mode",
             FT_UINT8, BASE_HEX, VALS(clkadjmode_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjclk,
           { "Clock Adjust Clock",                              "btlmp.clkadj.clk",
             FT_UINT32, BASE_HEX | BASE_UNIT_STRING, &units_slotpairs, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_clkadjperiod,
           { "Clock Adjust Period",                             "btlmp.clkadj.period",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_packettypetable,
           { "Packet Type Table",                               "btlmp.packettypetable",
             FT_UINT8, BASE_HEX, VALS(packettypetable_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escohandle,
           { "eSCO Handle",                                     "btlmp.esco.handle",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escoltaddr,
           { "eSCO LT_ADDR",                                    "btlmp.esco.ltaddr",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escod,
           { "Desco",                                           "btlmp.esco.d",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escot,
           { "Tesco",                                           "btlmp.esco.t",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escow,
           { "Wesco",                                           "btlmp.esco.w",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escopackettypems,
           { "eSCO Packet Type M->S",                           "btlmp.esco.packettypems",
             FT_UINT8, BASE_HEX, VALS(escopackettypems_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escopackettypesm,
           { "eSCO Packet Type S->M",                           "btlmp.esco.packettypesm",
             FT_UINT8, BASE_HEX, VALS(escopackettypesm_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escopacketlengthms,
           { "eSCO Packet Length M->S",                         "btlmp.esco.packetlengthms",
             FT_UINT16, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_escopacketlengthsm,
           { "eSCO Packet Length S->M",                         "btlmp.esco.packetlengthsm",
             FT_UINT16, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_negostate,
           { "Negotiation State",                               "btlmp.negotiationstate",
             FT_UINT8, BASE_HEX, VALS(negostate_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_maxsniffsubrate,
           { "Max Sniff Subrate",                               "btlmp.sniffsubrate.max",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_minsniffmodetimeout,
           { "Min Sniff Mode Timeout",                          "btlmp.sniffsubrate.minmodetimeout",
             FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_sniffsubratinginstant,
           { "Sniff Subrating Instant",                         "btlmp.sniffsubrate.instant",
             FT_UINT32, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_iocapcap,
           { "IO Capabilities",                                 "btlmp.iocap.cap",
             FT_UINT8, BASE_HEX, VALS(iocapcap_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_iocapoobauthdata,
           { "OOB Authentication Data",                         "btlmp.iocap.oobauthdata",
             FT_UINT8, BASE_HEX, VALS(iocapoobauthdata_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_iocapauthreq,
           { "Authentication Requirement",                      "btlmp.iocap.authreq",
             FT_UINT8, BASE_HEX, VALS(iocapauthreq_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_keypressnotificationtype,
           { "Notification Type",                               "btlmp.keypress.notificationtype",
             FT_UINT8, BASE_HEX, VALS(keypressnotificationtype_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_poweradjreq,
           { "Power Adjustment Request",                        "btlmp.poweradj.request",
             FT_UINT8, BASE_HEX, VALS(poweradjreq_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_poweradjresp[0],
           { "Power Adjustment Response",                       "btlmp.poweradj.response",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_poweradjresp[1],
           { "GFSK",                                            "btlmp.poweradj.gfsk",
             FT_UINT8, BASE_HEX, VALS(poweradjresp_vals), 0x03,
             NULL, HFILL }
        },
        {  &hf_param_poweradjresp[2],
           { "Pi/4-DQPSK",                                      "btlmp.poweradj.pi4dqsk",
             FT_UINT8, BASE_HEX, VALS(poweradjresp_vals), 0x0C,
             NULL, HFILL }
        },
        {  &hf_param_poweradjresp[3],
           { "8DPSK",                                           "btlmp.poweradj.8dpsk",
             FT_UINT8, BASE_HEX, VALS(poweradjresp_vals), 0x30,
             NULL, HFILL }
        },
        {  &hf_param_poweradjresp[4],
           { "Reserved",                                        "btlmp.poweradj.reserved",
             FT_UINT8, BASE_HEX, NULL, 0xC0,
             NULL, HFILL }
        },
        {  &hf_param_samindex,
           { "SAM Index",                                       "btlmp.sam.index",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_samtsm,
           { "Tsam-sm",                                         "btlmp.sam.tsm",
             FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_samnsm,
           { "Nsam-sm",                                         "btlmp.sam.nsm",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_samsubmaps,
           { "SAM Submaps",                                     "btlmp.sam.submaps",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_samupdatemode,
           { "Update Mode",                                     "btlmp.sam.updatemode",
             FT_UINT8, BASE_HEX, VALS(samupdatemode_vals), 0x00,
             NULL, HFILL }
        },
        {  &hf_param_samtype0submap,
           { "SAM Type 0 Submap",                               "btlmp.sam.type0submap",
             FT_BYTES, BASE_NONE, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_samd,
           { "Dsam",                                            "btlmp.sam.d",
             FT_UINT8, BASE_HEX, NULL, 0x00,
             NULL, HFILL }
        },
        {  &hf_param_saminstant,
           { "SAM Instant",                                     "btlmp.sam.instant",
             FT_UINT32, BASE_HEX | BASE_UNIT_STRING, &units_slots, 0x00,
             NULL, HFILL }
        },
        {  &hf_params,
            { "Parameters",                                     "btlmp.parameters",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_btlmp
    };

    proto_btlmp = proto_register_protocol("Bluetooth Link Manager Protocol", "BT LMP", "btlmp");
    proto_register_field_array(proto_btlmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btlmp_handle = register_dissector("btlmp", dissect_btlmp, proto_btlmp);
}

void
proto_reg_handoff_btlmp(void)
{
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
