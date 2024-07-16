/* packet-gsm_r_uus1.c
 * Routines for GSM-R UUS1 dissection
 *
 * Copyright 2018, Michail Koreshkov <michail.koreshkov [at] bk.ru
 *
 * Reference [1]
 * Railways Telecommunications (RT);
 * Global System for Mobile communications (GSM);
 * Usage of the User-to-User Information Element
 * for GSM Operation on Railways
 * (ETSI TS 102 610 V1.2.0 (2012-08))
 *
 * Reference [2]
 * EIRENE SRS: "UIC Project EIRENE System Requirements Specification".
 *
 * Reference [3]
 * MORANE F 10 T 6003 4: "FFFS for Presentation of Functional Numbers
 * to Called and Calling Parties".
 *
 * Reference [4]
 * eLDA IRS (V5.0): "Interface Requirements Specification
 * enhanced Location Dependent Addressing".
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

/* forward reference */
void proto_register_gsm_r_uus1(void);
void proto_reg_handoff_gsm_r_uus1(void);


/* Initialize the protocol and registered fields */
static int proto_gsm_r_uus1;

static int hf_gsm_r_uus1_elem_tag;
static int hf_gsm_r_uus1_elem_len;
static int hf_gsm_r_uus1_pfn;
static int hf_gsm_r_uus1_pfn_digits;

/* 5.2 and 5.3 */
static int hf_gsm_r_uus1_chpc;
static int hf_gsm_r_uus1_chpc_t_dur;
static int hf_gsm_r_uus1_chpc_t_rel;
static int hf_gsm_r_uus1_chpc_pl_call;
static int hf_gsm_r_uus1_chpc_cause;
static int hf_gsm_r_uus1_chpc_cause_power;
static int hf_gsm_r_uus1_chpc_cause_radio;
static int hf_gsm_r_uus1_chpc_cause_reserved3;
static int hf_gsm_r_uus1_chpc_cause_reserved4;
static int hf_gsm_r_uus1_chpc_cause_user_command;
static int hf_gsm_r_uus1_chpc_cause_reserved6;
static int hf_gsm_r_uus1_chpc_cause_reserved7;
static int hf_gsm_r_uus1_chpc_cause_reserved8;
static int hf_gsm_r_uus1_chpc_gref;
static int hf_gsm_r_uus1_chpc_ack_cause;

/* 5.4 */
static int hf_gsm_r_uus1_epfn;

/* 5.5 */
static int hf_gsm_r_uus1_present_text_str;

/* 5.6 */
static int hf_gsm_r_uus1_elda;
static int hf_gsm_r_uus1_elda_lat;
static int hf_gsm_r_uus1_elda_lat_deg;
static int hf_gsm_r_uus1_elda_lat_min;
static int hf_gsm_r_uus1_elda_lat_sec;
static int hf_gsm_r_uus1_elda_lat_hem;
static int hf_gsm_r_uus1_elda_long;
static int hf_gsm_r_uus1_elda_long_deg;
static int hf_gsm_r_uus1_elda_long_min;
static int hf_gsm_r_uus1_elda_long_sec;
static int hf_gsm_r_uus1_elda_long_hem;
static int hf_gsm_r_uus1_elda_height;
static int hf_gsm_r_uus1_elda_speed;
static int hf_gsm_r_uus1_elda_heading;
static int hf_gsm_r_uus1_elda_e_time;
static int hf_gsm_r_uus1_elda_distance;
static int hf_gsm_r_uus1_elda_scale;
static int hf_gsm_r_uus1_elda_spare;

/* 5.7 */
static int hf_gsm_r_uus1_present_dsd_alarm;
static int hf_gsm_r_uus1_present_dsd_alarm_loco_number;

/* 5.8 */
static int hf_gsm_r_uus1_alert_controller;
static int hf_gsm_r_uus1_alert_controller_gref;

/* Initialize the subtree pointers */
static int ett_gsm_r_uus1;
static int ett_gsm_r_uus1_pfn;
static int ett_gsm_r_uus1_chpc;
static int ett_gsm_r_uus1_chpc_cause;
static int ett_gsm_r_uus1_epfn;
static int ett_gsm_r_uus1_present_text_str;
static int ett_gsm_r_uus1_elda;
static int ett_gsm_r_uus1_elda_lat;
static int ett_gsm_r_uus1_elda_long;
static int ett_gsm_r_uus1_present_dsd_alarm;
static int ett_gsm_r_uus1_alert_controller;


/* Preferences */
static bool q931_u2u;
static bool gsm_a_u2u = true;


static expert_field ei_gsm_r_uus1_not_implemented_yet;

static const value_string gsm_r_uus1_tags[] = {
    { 2,  "Acknowledgement by Receiver of a HPC and response from device accepting the acknowledgement" },
    { 3,  "Acknowledgement by Initiator of a HPC" },
    { 5,  "Presentation of Functional Number" },
    { 6,  "enhanced Location Dependent Addressing" },
    { 7,  "enhanced Location Dependent Addressing (Reserved for future use)" },
    { 8,  "enhanced Location Dependent Addressing (Reserved for future use)" },
    { 9,  "ePFN Information" },
    { 10, "User specific plain text according to alphabet indicator" },
    { 11, "DSD Alarm Notification" },
    { 12, "Alerting of a Controller Notification and Response" },
    { 0, NULL }
};


/*
 * 5.1 Presentation of functional number
 *
 */
static uint16_t
de_gsm_r_uus1_pfn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset)
{
    uint32_t	curr_offset;
    uint32_t	len;
    const char *fn_str;
    proto_item *item;
    proto_tree *sub_tree;

    curr_offset = offset;

    len = tvb_get_guint8(tvb, offset+1);

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_pfn, tvb, curr_offset, len+2, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_pfn);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    if(len == 0) {
        proto_item_append_text(item, ": No FN Available");
    }else {
        fn_str = tvb_bcd_dig_to_str(pinfo->pool, tvb, offset+2, len, NULL, false);
        proto_tree_add_string(sub_tree, hf_gsm_r_uus1_pfn_digits, tvb, curr_offset, len, fn_str);
        proto_item_append_text(item, ": %s", fn_str);

        curr_offset += len;
    }

    return (curr_offset - offset);
}


/*
 * 5.2 Confirmation of High Priority Calls
 *
 */
static const range_string gsm_r_uus1_chpc_priority_vals[] = {
    { 0x00, 0x00, "no priority specified in call"},
    { 0x01, 0x01, "eMLPP priority of 4 (Railway Information)"},
    { 0x02, 0x02, "eMLPP priority of 3 (Railway Operation)"},
    { 0x03, 0x03, "eMLPP priority of 2 (Public Emergency/Group Calls)"},
    { 0x04, 0x04, "eMLPP priority of 1 (Command and Control)"},
    { 0x05, 0x05, "eMLPP priority of 0 (Railway Emergency)"},
    { 0x06, 0x07, "unknown" },
    { 0, 0, NULL }
};

static uint16_t
de_gsm_r_uus1_chpc_forward(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    uint32_t	curr_offset;
    uint32_t	len;
    uint32_t t_dur;
    uint32_t t_rel;
    proto_item *item;
    proto_tree *sub_tree;

    curr_offset = offset;

    len = tvb_get_guint8(tvb, offset+1);

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_chpc, tvb, curr_offset, len+2, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_chpc);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    t_dur = tvb_get_guint24(tvb, curr_offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint_format_value(sub_tree, hf_gsm_r_uus1_chpc_t_dur, tvb, curr_offset, 3, t_dur, "%d ms", t_dur*100);
    curr_offset += 3;

    t_rel = tvb_get_guint32(tvb, curr_offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint_format_value(sub_tree, hf_gsm_r_uus1_chpc_t_rel, tvb, curr_offset, 4, t_rel, "%d ms", t_rel*100);
    curr_offset += 4;

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_chpc_pl_call, tvb, curr_offset, 1, ENC_NA);
    curr_offset += 1;

    static int * const cause_flags[] = {
        &hf_gsm_r_uus1_chpc_cause_power,
        &hf_gsm_r_uus1_chpc_cause_radio,
        &hf_gsm_r_uus1_chpc_cause_reserved3,
        &hf_gsm_r_uus1_chpc_cause_reserved4,
        &hf_gsm_r_uus1_chpc_cause_user_command,
        &hf_gsm_r_uus1_chpc_cause_reserved6,
        &hf_gsm_r_uus1_chpc_cause_reserved7,
        &hf_gsm_r_uus1_chpc_cause_reserved8,
        NULL
    };

    proto_tree_add_bitmask(sub_tree, tvb, curr_offset, hf_gsm_r_uus1_chpc_cause, ett_gsm_r_uus1_chpc_cause, cause_flags, ENC_NA);
    curr_offset += 1;

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_chpc_gref, tvb, curr_offset, 4, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
    curr_offset += 4;

    return (curr_offset - offset);
}

/*
 * 5.3 CHPC tag definition for collecting network device
 *
 * The tag is included in a RELEASE_COMPLETE message
 * which shall have the release cause value of "Normal Call Clearing".
 *
 * gsm_a.dtap.msg_cc_type == 0x2a
 */
static const range_string gsm_r_uus1_chpc_ack_cause_vals[] = {
    { 0x00, 0x00, "ACK (no error)" },
    { 0x01, 0x01, "NACK-1 (error, repetition should take place)" },
    { 0x02, 0x7f, "Reserved for internal use" },
    { 0x80, 0x80, "NACK-2 (fatal error, NO repetition to take place)" },
    { 0x81, 0xff, "Reserved" },
    { 0, 0, NULL }
};

static uint16_t
de_gsm_r_uus1_chpc_collect(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    proto_item *item;
    proto_tree *sub_tree;

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_chpc, tvb, offset, 2, ENC_NA);
    proto_item_set_text(item, "CHPC for collecting network device");
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_chpc);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_chpc_ack_cause, tvb, offset+1, 1, ENC_NA);

    return 2;
}

/*
 * Type of field depends on BSSAP message type. SETUP or RELEASE_COMPLETE
 * But I don't know how to verify message type.
 * That is why use length variable to find type of field
 */
static uint16_t
de_gsm_r_uus1_chpc(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    uint8_t field_length;
    field_length = tvb_get_guint8(tvb, offset+1);
    if(field_length == 13)
        return de_gsm_r_uus1_chpc_forward(tvb, tree, offset);
    else
        return de_gsm_r_uus1_chpc_collect(tvb, tree, offset);
}

/*
 * 5.4 Enhanced presentation of functional number
 * (not implemented now)
 */
static uint16_t
de_gsm_r_uus1_epfn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset)
{
    uint32_t	curr_offset;
    uint32_t	len;
    proto_item *item;
    proto_tree *sub_tree;

    curr_offset = offset;

    len = tvb_get_guint8(tvb, offset+1);

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_epfn, tvb, curr_offset, len+2, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_epfn);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    proto_tree_add_expert(sub_tree, pinfo, &ei_gsm_r_uus1_not_implemented_yet, tvb, curr_offset, len);
    curr_offset += len;

    return (curr_offset - offset);
}

/*
 * 5.5 Presentation of text strings
 * (not implemented now)
 */
static uint16_t
de_gsm_r_uus1_text_str(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset)
{
    uint32_t	curr_offset;
    uint32_t	len;
    proto_item *item;
    proto_tree *sub_tree;

    curr_offset = offset;

    len = tvb_get_guint8(tvb, offset+1);

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_present_text_str, tvb, curr_offset, len+2, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_present_text_str);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    proto_tree_add_expert(sub_tree, pinfo, &ei_gsm_r_uus1_not_implemented_yet, tvb, curr_offset, len);
    curr_offset += len;

    return (curr_offset - offset);
}

/*
 * 5.6 Transfer of train position (eLDA)
 *
 */
static const true_false_string gsm_r_uus1_elda_lat_hem = {
    "North",
    "South"
};

static const true_false_string gsm_r_uus1_elda_long_hem = {
    "West",
    "East"
};

static const value_string gsm_r_uus1_elda_scale_vals[] = {
    { 0,  "10 cm resolution" },
    { 1,  "1 metre resolution" },
    { 2,  "10 metre resolution" },
    { 3,  "Odometry information not valid" },
    { 0, NULL }
};


static uint16_t
de_gsm_r_uus1_elda(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset)
{
    uint32_t	curr_offset;
    unsigned   bit_offset;

    uint32_t val;
    uint32_t lat_deg_val;
    uint32_t lat_min_val;
    uint32_t lat_sec_val;
    uint32_t lat_hem_val;

    uint32_t long_deg_val;
    uint32_t long_min_val;
    uint32_t long_sec_val;
    uint32_t long_hem_val;

    uint32_t t_val;

    proto_item *item;
    proto_tree *sub_tree;

    proto_item *lat_item;
    proto_item *long_item;
    proto_tree *lat_tree;
    proto_tree *long_tree;

    curr_offset = offset;

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_elda, tvb, curr_offset, 16, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_elda);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    bit_offset = curr_offset * 8;

    /* Latitude */
    lat_item = proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elda_lat, tvb, curr_offset, 4, ENC_NA);
    lat_tree = proto_item_add_subtree(lat_item, ett_gsm_r_uus1_elda_lat);

    val = tvb_get_guint32(tvb, curr_offset, ENC_NA);
    lat_deg_val = tvb_get_bits(tvb, bit_offset, 7, ENC_NA);
    bit_offset += 7;
    lat_min_val = tvb_get_bits(tvb, bit_offset, 6, ENC_NA);
    bit_offset += 6;
    lat_sec_val = tvb_get_bits(tvb, bit_offset, 13, ENC_NA);
    bit_offset += 13;
    lat_hem_val = tvb_get_bits(tvb, bit_offset, 1, ENC_NA);
    bit_offset += 1;

    proto_tree_add_uint(lat_tree, hf_gsm_r_uus1_elda_lat_deg, tvb, curr_offset, 4, val);
    proto_tree_add_uint(lat_tree, hf_gsm_r_uus1_elda_lat_min, tvb, curr_offset, 4, val);
    proto_tree_add_uint_format_value(lat_tree, hf_gsm_r_uus1_elda_lat_sec, tvb, curr_offset, 4, val, "%.2f", (float)(lat_sec_val)/100);
    proto_tree_add_boolean(lat_tree, hf_gsm_r_uus1_elda_lat_hem, tvb, curr_offset, 4, val);

    proto_item_set_text(lat_item, "Latitude: %d %d\'%.2f\"%s", lat_deg_val, lat_min_val, (float)(lat_sec_val)/100,
        lat_hem_val ? "N" : "S");

    curr_offset += 3;

    /* Longitude */
    long_item = proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elda_long, tvb, curr_offset, 4, ENC_NA);
    long_tree = proto_item_add_subtree(long_item, ett_gsm_r_uus1_elda_long);

    val = tvb_get_guint32(tvb, curr_offset, ENC_NA);
    long_deg_val = tvb_get_bits(tvb, bit_offset, 8, ENC_NA);
    bit_offset += 8;
    long_min_val = tvb_get_bits(tvb, bit_offset, 6, ENC_NA);
    bit_offset += 6;
    long_sec_val = tvb_get_bits(tvb, bit_offset, 13, ENC_NA);
    bit_offset += 13;
    long_hem_val = tvb_get_bits(tvb, bit_offset, 1, ENC_NA);
    bit_offset += 1;

    proto_tree_add_uint(long_tree, hf_gsm_r_uus1_elda_long_deg, tvb, curr_offset, 4, val);
    proto_tree_add_uint(long_tree, hf_gsm_r_uus1_elda_long_min, tvb, curr_offset, 4, val);
    proto_tree_add_uint_format_value(long_tree, hf_gsm_r_uus1_elda_long_sec, tvb, curr_offset, 4, val, "%.2f", (float)(long_sec_val)/100);
    proto_tree_add_boolean(long_tree, hf_gsm_r_uus1_elda_long_hem, tvb, curr_offset, 4, val);

    proto_item_set_text(long_item, "Longitude: %d %d\'%.2f\"%s", long_deg_val, long_min_val, (float)(long_sec_val)/100,
        long_hem_val ? "W" : "E");

    curr_offset += 3;

    /* Height, Speed, Heading */

    // height step 1m. Range: -100m...+4500m
    t_val = tvb_get_bits(tvb, bit_offset, 13, ENC_NA) - 100;
    proto_tree_add_int(sub_tree, hf_gsm_r_uus1_elda_height, tvb, curr_offset, 4, t_val);
    bit_offset += 13;

    // speed step 10 km/h
    t_val = tvb_get_bits(tvb, bit_offset, 6, ENC_NA) * 10;
    proto_tree_add_uint(sub_tree, hf_gsm_r_uus1_elda_speed, tvb, curr_offset, 4, t_val);
    bit_offset += 6;

    // heading step 10 deg
    t_val = tvb_get_bits(tvb, bit_offset, 6, ENC_NA) * 10;
    proto_tree_add_uint(sub_tree, hf_gsm_r_uus1_elda_heading, tvb, curr_offset, 4, t_val);
    bit_offset += 6;

    curr_offset += 4;

    /* Elapsed Time, Distance, Scale, Spare */

    // time step 1 second. Range: 0...2047
    t_val = tvb_get_bits(tvb, bit_offset, 11, ENC_NA);
    proto_tree_add_uint(sub_tree, hf_gsm_r_uus1_elda_e_time, tvb, curr_offset, 4, t_val);
    bit_offset += 11;

    // distance step = 10 cm, 1 m or 10 m depending on the parameter Scale
    t_val = tvb_get_bits(tvb, bit_offset, 14, ENC_NA);
    proto_tree_add_uint(sub_tree, hf_gsm_r_uus1_elda_distance, tvb, curr_offset, 4, t_val);
    bit_offset += 14;

    // scale
    t_val = tvb_get_bits(tvb, bit_offset, 2, ENC_NA);
    proto_tree_add_uint(sub_tree, hf_gsm_r_uus1_elda_scale, tvb, curr_offset, 4, t_val);
    bit_offset += 2;

    // spare
    t_val = tvb_get_bits(tvb, bit_offset, 5, ENC_NA);
    proto_tree_add_uint(sub_tree, hf_gsm_r_uus1_elda_spare, tvb, curr_offset, 4, t_val);

    return 16;
}

/*
 * 5.7 Notification DSD alarm condition
 *
 */
static uint16_t
de_gsm_r_uus1_dsd_alarm(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset)
{
    uint32_t	curr_offset;
    uint32_t	len;
    const char *loco_engine_number;
    proto_item *item;
    proto_tree *sub_tree;

    curr_offset = offset;

    len = tvb_get_guint8(tvb, offset+1);

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_present_dsd_alarm, tvb, curr_offset, len+2, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_present_dsd_alarm);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    loco_engine_number = tvb_bcd_dig_to_str(pinfo->pool, tvb, offset+2, len, NULL, false);
    proto_tree_add_string(sub_tree, hf_gsm_r_uus1_present_dsd_alarm_loco_number, tvb, curr_offset, len, loco_engine_number);
    proto_item_append_text(item, ": %s", loco_engine_number);
    curr_offset += len;

    return (curr_offset - offset);
}


/*
 * 5.8 Notification of a request to alert a controller
 *
 */
static uint16_t
de_gsm_r_uus1_alert_controller(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset)
{
    uint32_t	curr_offset;
    uint32_t	len;
    proto_item *item;
    proto_tree *sub_tree;
    char       *gref_str;

    curr_offset = offset;

    len = tvb_get_guint8(tvb, offset+1);

    item = proto_tree_add_item(tree, hf_gsm_r_uus1_alert_controller, tvb, curr_offset+2, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_gsm_r_uus1_alert_controller);

    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_tag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_gsm_r_uus1_elem_len, tvb, curr_offset+1, 1, ENC_NA);
    curr_offset += 2;

    proto_tree_add_item_ret_display_string(sub_tree, hf_gsm_r_uus1_alert_controller_gref, tvb, curr_offset, 4, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN, pinfo->pool, &gref_str);
    proto_item_append_text(item, ": %s", gref_str);
    curr_offset += 4;

    return (curr_offset - offset);
}


static int
dissect_gsm_r_uus1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint8_t elem_tag;
    uint32_t	offset;
    uint32_t	len;
    proto_item   *gsm_r_uus1_item   = NULL;
    proto_tree   *gsm_r_uus1_tree   = NULL;

    offset = 0;
    len = tvb_captured_length(tvb);

    gsm_r_uus1_item =
        proto_tree_add_protocol_format(tree, proto_gsm_r_uus1, tvb, 0, len, "GSM-R User-to-User Signaling");

    gsm_r_uus1_tree = proto_item_add_subtree(gsm_r_uus1_item, ett_gsm_r_uus1);

    while (offset < len){
        elem_tag = tvb_get_guint8(tvb, offset);
        switch (elem_tag) {
        case 2:
        case 3:
            offset += de_gsm_r_uus1_chpc(tvb, gsm_r_uus1_tree, offset);
            break;
        case 5:
            offset += de_gsm_r_uus1_pfn(tvb, pinfo, gsm_r_uus1_tree, offset);
            break;
        case 6:
        case 7:
        case 8:
            offset += de_gsm_r_uus1_elda(tvb, gsm_r_uus1_tree, pinfo, offset);
            break;
        case 9:
            offset += de_gsm_r_uus1_epfn(tvb, gsm_r_uus1_tree, pinfo, offset);
            break;
        case 10:
            offset += de_gsm_r_uus1_text_str(tvb, gsm_r_uus1_tree, pinfo, offset);
            break;
        case 11:
             offset += de_gsm_r_uus1_dsd_alarm(tvb, gsm_r_uus1_tree, pinfo, offset);
            break;
        case 12:
            offset += de_gsm_r_uus1_alert_controller(tvb, gsm_r_uus1_tree, pinfo, offset);
            break;
        default:
            return offset;
        }
    }

    return offset;
}

/* heuristic dissector */
static bool
dissect_gsm_r_uus1_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (dissect_gsm_r_uus1(tvb, pinfo, tree, data) > 0)
        return false;

    return true;
}


/* Register the protocol with Wireshark */
void
proto_register_gsm_r_uus1(void)
{
    /* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_gsm_r_uus1_elem_tag,
          { "Element tag", "gsm-r-uus1.elem_tag",
            FT_UINT8, BASE_DEC, VALS(gsm_r_uus1_tags), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elem_len,
          { "Length", "gsm-r-uus1.elem_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_pfn,
          { "Presentation of Functional Number (PFN)", "gsm-r-uus1.pfn",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_pfn_digits,
          { "Digits", "gsm-r-uus1.pfn.digits",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc,
          { "Confirmation of High Priority Calls (CHPC)", "gsm-r-uus1.chpc",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_t_dur,
          { "Duration of the call", "gsm-r-uus1.chpc.t_dur",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_t_rel,
          { "Interval between the end of the call and the transmission of the confirmation message", "gsm-r-uus1.chpc.t_rel",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_pl_call,
          { "Priority level of the call", "gsm-r-uus1.chpc.pl_call",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_r_uus1_chpc_priority_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause,
          { "Reason for termination of the call", "gsm-r-uus1.chpc.cause",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_power,
          { "Mobile was powered off when receiving (power fail)", "gsm-r-uus1.chpc.cause.power",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_radio,
          { "Call was interrupted due to radio link error", "gsm-r-uus1.chpc.cause.radio",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_reserved3,
          { "Reserved", "gsm-r-uus1.chpc.cause.reserved3",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_reserved4,
          { "Reserved", "gsm-r-uus1.chpc.cause.reserved4",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_user_command,
          { "Call was left on user command", "gsm-r-uus1.chpc.cause.user_command",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_reserved6,
          { "Reserved", "gsm-r-uus1.chpc.cause.reserved6",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_reserved7,
          { "Reserved", "gsm-r-uus1.chpc.cause.reserved7",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_cause_reserved8,
          { "Reserved", "gsm-r-uus1.chpc.cause.reserved8",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_gref,
          { "Group call reference", "gsm-r-uus1.chpc.gref",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_chpc_ack_cause,
          { "ACK/CAUSE", "gsm-r-uus1.chpc.ack_cause",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_r_uus1_chpc_ack_cause_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_epfn,
          { "Enhanced presentation of functional number (ePFN)", "gsm-r-uus1.epfn",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_present_text_str,
          { "Presentation of text strings", "gsm-r-uus1.present_text_str",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda,
          { "Train position (eLDA)", "gsm-r-uus1.elda",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_lat,
          { "Latitude", "gsm-r-uus1.elda.lat",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_lat_deg,
          { "Degrees", "gsm-r-uus1.elda.lat.deg",
            FT_UINT32, BASE_DEC, NULL, 0xFE000000,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_lat_min,
          { "Minutes", "gsm-r-uus1.elda.lat.min",
            FT_UINT32, BASE_DEC, NULL, 0x01F80000,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_lat_sec,
          { "Seconds", "gsm-r-uus1.elda.lat.sec",
            FT_UINT32, BASE_DEC, NULL, 0x0007FFC0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_lat_hem,
          { "Hemisphere", "gsm-r-uus1.elda.lat.hem",
            FT_BOOLEAN, 32, TFS(&gsm_r_uus1_elda_lat_hem), 0x00000020,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_long,
          { "Latitude", "gsm-r-uus1.elda.long",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_long_deg,
          { "Degrees", "gsm-r-uus1.elda.long.deg",
            FT_UINT32, BASE_DEC, NULL, 0x1FE00000,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_long_min,
          { "Minutes", "gsm-r-uus1.elda.long.min",
            FT_UINT32, BASE_DEC, NULL, 0x001F8000,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_long_sec,
          { "Seconds", "gsm-r-uus1.elda_long.sec",
            FT_UINT32, BASE_DEC, NULL, 0x00007FFC,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_long_hem,
          { "Hemisphere", "gsm-r-uus1.elda_long.hem",
            FT_BOOLEAN, 32, TFS(&gsm_r_uus1_elda_long_hem), 0x00000002,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_height,
          { "Height (m)", "gsm-r-uus1.elda.height",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_speed,
          { "Speed (km/h)", "gsm-r-uus1.elda.speed",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_heading,
          { "Heading (deg)", "gsm-r-uus1.elda.heading",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_e_time,
          { "Elapsed Time (sec)", "gsm-r-uus1.elda.e_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_distance,
          { "Distance", "gsm-r-uus1.elda.distance",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_scale,
          { "Scale", "gsm-r-uus1.elda.scale",
            FT_UINT32, BASE_DEC, VALS(gsm_r_uus1_elda_scale_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_elda_spare,
          { "Spare", "gsm-r-uus1.elda.spare",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_present_dsd_alarm,
          { "Notification DSD alarm condition", "gsm-r-uus1.present_dsd_alarm",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_present_dsd_alarm_loco_number,
          { "Locomotive engine number", "gsm-r-uus1.present_dsd_alarm.loco_number",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_alert_controller,
          { "Notification of a request to alert a controller", "gsm-r-uus1.alert_controller",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_r_uus1_alert_controller_gref,
          { "Group call reference", "gsm-r-uus1.alert_controller.gref",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_gsm_r_uus1_not_implemented_yet, { "gsm-r-uus1.not_implemented_yet", PI_UNDECODED, PI_NOTE, "Not implemented yet", EXPFILL }},
    };

    expert_module_t* expert_gsm_r_uus1;

    static int *ett[] = {
        &ett_gsm_r_uus1,
        &ett_gsm_r_uus1_pfn,
        &ett_gsm_r_uus1_chpc,
        &ett_gsm_r_uus1_chpc_cause,
        &ett_gsm_r_uus1_epfn,
        &ett_gsm_r_uus1_present_text_str,
        &ett_gsm_r_uus1_elda,
        &ett_gsm_r_uus1_elda_lat,
        &ett_gsm_r_uus1_elda_long,
        &ett_gsm_r_uus1_present_dsd_alarm,
        &ett_gsm_r_uus1_alert_controller
    };

    module_t *gsm_r_uus1_module;

    /* Register the protocol name and description */
    proto_gsm_r_uus1 =
        proto_register_protocol("GSM-R User-to-User Signaling", "GSM-R", "gsm-r-uus1");

    proto_register_field_array(proto_gsm_r_uus1, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    expert_gsm_r_uus1 = expert_register_protocol(proto_gsm_r_uus1);
    expert_register_field_array(expert_gsm_r_uus1, ei, array_length(ei));

    /* subdissector code */
    register_dissector("gsm-r-uus1", dissect_gsm_r_uus1, proto_gsm_r_uus1);

    gsm_r_uus1_module = prefs_register_protocol(proto_gsm_r_uus1, proto_reg_handoff_gsm_r_uus1);
    prefs_register_bool_preference(gsm_r_uus1_module, "dissect_q931_u2u",
        "Dissect Q.931 User-To-User information",
        "Dissect Q.931 User-To-User information",
        &q931_u2u);
    prefs_register_bool_preference(gsm_r_uus1_module, "dissect_gsm_a_u2u",
        "Dissect GSM-A User-To-User information",
        "Dissect GSM-A User-To-User information",
        &gsm_a_u2u);
}

void
proto_reg_handoff_gsm_r_uus1(void)
{
    dissector_handle_t gsm_r_uus1_handle;

    gsm_r_uus1_handle = find_dissector("gsm-r-uus1");

    if(q931_u2u){
        heur_dissector_add("q931_user", dissect_gsm_r_uus1_heur, "GSM-R over UUS1", "gsm_r_uus1", proto_gsm_r_uus1, HEURISTIC_ENABLE);
    } else {
        heur_dissector_delete("q931_user", dissect_gsm_r_uus1_heur, proto_gsm_r_uus1);
    }


    if(gsm_a_u2u){
        dissector_add_uint("gsm_a.dtap.u2u_prot_discr", 0, gsm_r_uus1_handle);
    } else {
        dissector_delete_uint("gsm_a.dtap.u2u_prot_discr", 0, gsm_r_uus1_handle);
    }
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
