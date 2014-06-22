/* packet-ansi_637.c
 * Routines for ANSI IS-637-A/D (SMS) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 * Copyright 2013, Michael Lum <michael.lum [AT] starsolutions.com>
 * In association with Star Solutions, Inc. (Updated for some of IS-637-D and CMAS)
 *
 * Title                3GPP2                   Other
 *
 *   Short Message Service
 *                      3GPP2 C.S0015-0         TIA/EIA-637-A
 *                      3GPP2 C.S0015-C v1.0    TIA/EIA-637-D
 *                      3GPP2 C.R1001-H v1.0    TSB-58-I (or J?)
 *
 * For CMAS See:
 *   TIA-1149.1 or
 *   (520-10030206__Editor_TIA-1149-0-1_CMASoverCDMA_Publication.pdf)
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

#include "config.h"

#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/tfs.h>

#include "packet-gsm_sms.h"
#include "packet-ansi_a.h"

void proto_register_ansi_637(void);
void proto_reg_handoff_ansi_637(void);

static const char *ansi_proto_name_tele = "ANSI IS-637-A (SMS) Teleservice Layer";
static const char *ansi_proto_name_trans = "ANSI IS-637-A (SMS) Transport Layer";
static const char *ansi_proto_name_short = "IS-637-A";

/*
 * Masks the number of bits given by len starting at the given offset
 * MBoffset should be from 0 to 7 and MBlen 1 to 8
 * MASK_B(0, 1) = 0x80
 * MASK_B(0, 8) = 0xff
 * MASK_B(4, 3) = 0x0e
 * MASK_B(7, 1) = 0x01
 */
#define MASK_B(MBoffset, MBlen) \
    ((0xff >> (MBoffset)) & (0xff << (8 - ((MBoffset) + (MBlen)))))

static const value_string ansi_tele_msg_type_strings[] = {
    { 1,        "Deliver (mobile-terminated only)" },
    { 2,        "Submit (mobile-originated only)" },
    { 3,        "Cancellation (mobile-originated only)" },
    { 4,        "Delivery Acknowledgement (mobile-terminated only)" },
    { 5,        "User Acknowledgement (either direction)" },
    { 6,        "Read Acknowledgement (either direction)" },
    { 7,        "Deliver Report (mobile-originated only)" },
    { 8,        "Submit Report (mobile-terminated only)" },
    { 0, NULL }
};

static const value_string ansi_tele_msg_header_ind_strings[] = {
    { 0,        "The User Data field contains only the short message" },
    { 1,        "The User Data field contains a Header in addition to the short message" },
    { 0, NULL }
};

static const value_string ansi_tele_msg_status_strings[] = {
    { 0x00,     "Message accepted" },
    { 0x01,     "Message deposited to Internet" },
    { 0x02,     "Message delivered" },
    { 0x03,     "Message cancelled" },
    { 0x84,     "Network congestion" },
    { 0x85,     "Network error" },
    { 0x9f,     "Unknown error" },
    { 0xc4,     "Network congestion" },
    { 0xc5,     "Network error" },
    { 0xc6,     "Cancel failed" },
    { 0xc7,     "Blocked destination" },
    { 0xc8,     "Text too long" },
    { 0xc9,     "Duplicate message" },
    { 0xca,     "Invalid destination" },
    { 0xcd,     "Message expired" },
    { 0xdf,     "Unknown error" },
    { 0, NULL }
};
static value_string_ext ansi_tele_msg_status_strings_ext = VALUE_STRING_EXT_INIT(ansi_tele_msg_status_strings);

static const value_string ansi_tele_id_strings[] = {
    { 1,        "Reserved for maintenance" },
    { 4096,     "AMPS Extended Protocol Enhanced Services" },
    { 4097,     "CDMA Cellular Paging Teleservice" },
    { 4098,     "CDMA Cellular Messaging Teleservice" },
    { 4099,     "CDMA Voice Mail Notification" },
    { 4100,     "CDMA Wireless Application Protocol (WAP)" },
    { 4101,     "CDMA Wireless Enhanced Messaging Teleservice (WEMT)" },
    { 0, NULL }
};
#define INTERNAL_BROADCAST_TELE_ID      65535

static const value_string ansi_tele_param_strings[] = {
    { 0x00,     "Message Identifier" },
    { 0x01,     "User Data" },
    { 0x02,     "User Response Code" },
    { 0x03,     "Message Center Time Stamp" },
    { 0x04,     "Validity Period - Absolute" },
    { 0x05,     "Validity Period - Relative" },
    { 0x06,     "Deferred Delivery Time - Absolute" },
    { 0x07,     "Deferred Delivery Time - Relative" },
    { 0x08,     "Priority Indicator" },
    { 0x09,     "Privacy Indicator" },
    { 0x0a,     "Reply Option" },
    { 0x0b,     "Number of Messages" },
    { 0x0c,     "Alert on Message Delivery" },
    { 0x0d,     "Language Indicator" },
    { 0x0e,     "Call-Back Number" },
    { 0x0f,     "Message Display Mode" },
    { 0x10,     "Multiple Encoding User Data" },
    { 0x11,     "Message Deposit Index" },
    { 0x12,     "Service Category Program Data" },
    { 0x13,     "Service Category Program Results" },
    { 0x14,     "Message status" },
    { 0x15,     "TP-Failure cause" },
    { 0x16,     "Enhanced VMN" },
    { 0x17,     "Enhanced VMN Ack" },
    { 0, NULL }
};
static value_string_ext ansi_tele_param_strings_ext = VALUE_STRING_EXT_INIT(ansi_tele_param_strings);

#define ANSI_TRANS_MSG_TYPE_BROADCAST   1

static const value_string ansi_trans_msg_type_strings[] = {
    { 0,        "Point-to-Point" },
    { 1,        "Broadcast" },
    { 2,        "Acknowledge" },
    { 0, NULL }
};

static const value_string ansi_trans_param_strings[] = {
    { 0x00,     "Teleservice Identifier" },
    { 0x01,     "Service Category" },
    { 0x02,     "Originating Address" },
    { 0x03,     "Originating Subaddress" },
    { 0x04,     "Destination Address" },
    { 0x05,     "Destination Subaddress" },
    { 0x06,     "Bearer Reply Option" },
    { 0x07,     "Cause Codes" },
    { 0x08,     "Bearer Data" },
    { 0, NULL }
};

static const value_string ansi_tele_month_strings[] = {
    { 0,        "January" },
    { 1,        "February" },
    { 2,        "March" },
    { 3,        "April" },
    { 4,        "May" },
    { 5,        "June" },
    { 6,        "July" },
    { 7,        "August" },
    { 8,        "September" },
    { 9,        "October" },
    { 10,       "November" },
    { 11,       "December" },
    { 0, NULL }
};

static const value_string ansi_trans_subaddr_odd_even_ind_strings[] = {
    { 0x00,     "Even" },
    { 0x01,     "Odd" },
    { 0, NULL }
};

static const true_false_string tfs_digit_mode_8bit_4bit = {
    "8-bit ASCII",
    "4-bit DTMF"
};

static const true_false_string tfs_number_mode_data_ansi_t1 = {
    "Data Network Address",
    "ANSI T1.607"
};

/*
 * from Table 2.7.1.3.2.4-4. Representation of DTMF Digits
 * 3GPP2 C.S0005-C (IS-2000 aka cdma2000)
 */
static const unsigned char air_digits[] = {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '?','1','2','3','4','5','6','7','8','9','0','*','#','?','?'
};

/* Initialize the protocol and registered fields */
static int proto_ansi_637_tele = -1;
static int proto_ansi_637_trans = -1;

static int hf_ansi_637_trans_param_id = -1;
static int hf_ansi_637_trans_length = -1;
static int hf_ansi_637_trans_bin_addr = -1;
static int hf_ansi_637_trans_tele_id = -1;
static int hf_ansi_637_trans_srvc_cat = -1;
static int hf_ansi_637_trans_addr_param_digit_mode = -1;
static int hf_ansi_637_trans_addr_param_number_mode = -1;
static int hf_ansi_637_trans_addr_param_ton = -1;
static int hf_ansi_637_trans_addr_param_plan = -1;
static int hf_ansi_637_trans_addr_param_num_fields = -1;
static int hf_ansi_637_trans_addr_param_number = -1;
static int hf_ansi_637_trans_subaddr_type = -1;
static int hf_ansi_637_trans_subaddr_odd_even_ind = -1;
static int hf_ansi_637_trans_subaddr_num_fields = -1;
static int hf_ansi_637_trans_bearer_reply_seq_num = -1;
static int hf_ansi_637_trans_cause_codes_seq_num = -1;
static int hf_ansi_637_trans_cause_codes_error_class = -1;
static int hf_ansi_637_trans_cause_codes_code = -1;

static int hf_ansi_637_tele_msg_type = -1;
static int hf_ansi_637_tele_msg_id = -1;
static int hf_ansi_637_tele_length = -1;
static int hf_ansi_637_tele_msg_status = -1;
static int hf_ansi_637_tele_msg_header_ind = -1;
static int hf_ansi_637_tele_msg_rsvd = -1;
static int hf_ansi_637_tele_subparam_id = -1;
static int hf_ansi_637_tele_user_data_text = -1;
static int hf_ansi_637_tele_user_data_encoding = -1;
static int hf_ansi_637_tele_user_data_message_type = -1;
static int hf_ansi_637_tele_user_data_num_fields = -1;
static int hf_ansi_637_tele_response_code = -1;
static int hf_ansi_637_tele_message_center_ts_year = -1;
static int hf_ansi_637_tele_message_center_ts_month = -1;
static int hf_ansi_637_tele_message_center_ts_day = -1;
static int hf_ansi_637_tele_message_center_ts_hours = -1;
static int hf_ansi_637_tele_message_center_ts_minutes = -1;
static int hf_ansi_637_tele_message_center_ts_seconds = -1;
static int hf_ansi_637_tele_validity_period_ts_year = -1;
static int hf_ansi_637_tele_validity_period_ts_month = -1;
static int hf_ansi_637_tele_validity_period_ts_day = -1;
static int hf_ansi_637_tele_validity_period_ts_hours = -1;
static int hf_ansi_637_tele_validity_period_ts_minutes = -1;
static int hf_ansi_637_tele_validity_period_ts_seconds = -1;
static int hf_ansi_637_tele_validity_period_relative_validity = -1;
static int hf_ansi_637_tele_deferred_del_ts_year = -1;
static int hf_ansi_637_tele_deferred_del_ts_month = -1;
static int hf_ansi_637_tele_deferred_del_ts_day = -1;
static int hf_ansi_637_tele_deferred_del_ts_hours = -1;
static int hf_ansi_637_tele_deferred_del_ts_minutes = -1;
static int hf_ansi_637_tele_deferred_del_ts_seconds = -1;
static int hf_ansi_637_tele_deferred_del_relative = -1;
static int hf_ansi_637_tele_priority_indicator = -1;
static int hf_ansi_637_tele_privacy_indicator = -1;
static int hf_ansi_637_tele_reply_option_user_ack_req = -1;
static int hf_ansi_637_tele_reply_option_dak_req = -1;
static int hf_ansi_637_tele_reply_option_read_ack_req = -1;
static int hf_ansi_637_tele_reply_option_report_req = -1;
static int hf_ansi_637_tele_num_messages = -1;
static int hf_ansi_637_tele_alert_msg_delivery_priority = -1;
static int hf_ansi_637_tele_language = -1;
static int hf_ansi_637_tele_cb_num_digit_mode = -1;
static int hf_ansi_637_tele_cb_num_ton = -1;
static int hf_ansi_637_tele_cb_num_plan = -1;
static int hf_ansi_637_tele_cb_num_num_fields = -1;
static int hf_ansi_637_tele_cb_num_number = -1;
static int hf_ansi_637_tele_msg_display_mode = -1;
static int hf_ansi_637_tele_msg_deposit_idx = -1;
static int hf_ansi_637_tele_srvc_cat_prog_results_srvc_cat = -1;
static int hf_ansi_637_tele_srvc_cat_prog_results_result = -1;
static int hf_ansi_637_tele_msg_status_error_class = -1;
static int hf_ansi_637_tele_msg_status_code = -1;
static int hf_ansi_637_tele_tp_failure_cause_value = -1;
static int hf_ansi_637_reserved_bits_8_generic = -1;
static int hf_ansi_637_reserved_bits_8_03 = -1;
static int hf_ansi_637_reserved_bits_8_07 = -1;
static int hf_ansi_637_reserved_bits_8_0f = -1;
static int hf_ansi_637_reserved_bits_8_3f = -1;
static int hf_ansi_637_reserved_bits_8_7f = -1;
static int hf_ansi_637_tele_cmas_encoding = -1;
static int hf_ansi_637_tele_cmas_num_fields = -1;
static int hf_ansi_637_tele_cmas_protocol_version = -1;
static int hf_ansi_637_tele_cmas_record_type = -1;
static int hf_ansi_637_tele_cmas_record_len = -1;
static int hf_ansi_637_tele_cmas_char_set = -1;
static int hf_ansi_637_tele_cmas_category = -1;
static int hf_ansi_637_tele_cmas_response_type = -1;
static int hf_ansi_637_tele_cmas_severity = -1;
static int hf_ansi_637_tele_cmas_urgency = -1;
static int hf_ansi_637_tele_cmas_certainty = -1;
static int hf_ansi_637_tele_cmas_identifier = -1;
static int hf_ansi_637_tele_cmas_alert_handling = -1;
static int hf_ansi_637_tele_cmas_expires_year = -1;
static int hf_ansi_637_tele_cmas_expires_month = -1;
static int hf_ansi_637_tele_cmas_expires_day = -1;
static int hf_ansi_637_tele_cmas_expires_hours = -1;
static int hf_ansi_637_tele_cmas_expires_minutes = -1;
static int hf_ansi_637_tele_cmas_expires_seconds = -1;
static int hf_ansi_637_tele_cmas_language = -1;

/* Initialize the subtree pointers */
static gint ett_ansi_637_tele = -1;
static gint ett_ansi_637_trans = -1;
static gint ett_ansi_637_header_ind = -1;
static gint ett_params = -1;

static expert_field ei_ansi_637_extraneous_data = EI_INIT;
static expert_field ei_ansi_637_short_data = EI_INIT;
static expert_field ei_ansi_637_unexpected_length = EI_INIT;
static expert_field ei_ansi_637_unknown_encoding = EI_INIT;
static expert_field ei_ansi_637_failed_conversion = EI_INIT;
static expert_field ei_ansi_637_unknown_cmas_record_type = EI_INIT;
static expert_field ei_ansi_637_unknown_trans_parameter = EI_INIT;
static expert_field ei_ansi_637_no_trans_parameter_dissector = EI_INIT;
static expert_field ei_ansi_637_unknown_tele_parameter = EI_INIT;
static expert_field ei_ansi_637_no_tele_parameter_dissector = EI_INIT;

static dissector_handle_t ansi_637_tele_handle;
static dissector_handle_t ansi_637_trans_handle;

static guint32 ansi_637_trans_tele_id;
static char ansi_637_bigbuf[1024];
static dissector_table_t tele_dissector_table;
static proto_tree *g_tree;

/* PARAM FUNCTIONS */

#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_637_extraneous_data, \
            tvb, offset, (edc_len) - (edc_max_len)); \
    }

#define SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_637_short_data, \
            tvb, offset, (sdc_len)); \
        return; \
    }

#define EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_637_unexpected_length, \
            tvb, offset, (edc_len)); \
        return; \
    }

/*
 * text decoding helper
 *
 * there are 'unused_bits' bits remaining in the octet at 'offset'
 */
static void
text_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint8 encoding, guint8 num_fields, guint16 num_bits, guint8 unused_bits, guint8 fill_bits)
{
    guint8      bit;
    guint32     required_octs;
    tvbuff_t    *tvb_out = NULL;

    GIConv      cd;
    GError      *l_conv_error = NULL;
    gchar       *ustr = NULL;

    /*
     * has to be big enough to hold all of the 'shifted' bits
     */
    required_octs = (num_bits + fill_bits + 7) / 8;

    /*
     * shift the bits to octet alignment in 'buf'
     */
    tvb_out =
        tvb_new_octet_aligned(tvb, (offset * 8) + (8 - unused_bits), (required_octs * 8));
    add_new_data_source(pinfo, tvb_out, "Characters");

    switch (encoding)
    {
    default:
        proto_tree_add_expert(tree, pinfo, &ei_ansi_637_unknown_encoding, tvb, offset, required_octs);
        return;

    case 0x02: /* 7-bit ASCII */

        offset = 0;
        bit = 0;

        proto_tree_add_ascii_7bits_item(tree, hf_ansi_637_tele_user_data_text, tvb_out, (offset << 3) + bit, num_fields);
        break;

    case 0x03: /* IA5 */

        offset = 0;
        bit = 0;

        ustr = tvb_get_ascii_7bits_string(wmem_packet_scope(), tvb, (offset << 3) + bit, num_fields);
        IA5_7BIT_decode(ansi_637_bigbuf, ustr, num_fields);

        proto_tree_add_string(tree, hf_ansi_637_tele_user_data_text, tvb_out, 0,
            offset, ansi_637_bigbuf);
        break;

    case 0x04: /* UNICODE */

        offset = 0;

        proto_tree_add_item(tree, hf_ansi_637_tele_user_data_text, tvb_out, offset, num_fields*2, ENC_UCS_2|ENC_BIG_ENDIAN);
        break;

    case 0x07: /* Latin/Hebrew */

        offset = 0;

        proto_tree_add_item(tree, hf_ansi_637_tele_user_data_text, tvb_out, offset, num_fields, ENC_ISO_8859_8|ENC_NA);
        break;

    case 0x08: /* Latin */

        offset = 0;

        proto_tree_add_item(tree, hf_ansi_637_tele_user_data_text, tvb_out, offset, num_fields, ENC_ISO_8859_1|ENC_NA);
        break;

    case 0x09: /* GSM 7-bit default alphabet */

        offset = 0;
        bit = fill_bits;

        proto_tree_add_ts_23_038_7bits_item(tree, hf_ansi_637_tele_user_data_text, tvb_out, (offset << 3) + bit, num_fields);
        break;

    case 0x10: /* KSC5601 (Korean) */

        offset = 0;

        if ((cd = g_iconv_open("UTF-8", "EUC-KR")) != (GIConv) -1)
        {
            ustr = g_convert_with_iconv(tvb_get_ptr(tvb_out, offset, required_octs), required_octs , cd , NULL , NULL , &l_conv_error);
            if (!l_conv_error)
            {
                proto_tree_add_string(tree, hf_ansi_637_tele_user_data_text, tvb_out, offset,
                    required_octs, ustr);
            }
            else
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_ansi_637_failed_conversion, tvb_out, offset, required_octs,
                    "Failed iconv conversion on EUC-KR - (report to wireshark.org)");
            }
            if (ustr)
            {
                g_free(ustr);
            }
            g_iconv_close(cd);
        }
        break;
    }
}

static void
tele_param_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, int hf_year, int hf_month, int hf_day, int hf_hours, int hf_minutes, int hf_seconds)
{
    guint8      oct;
    guint16     temp;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 6);

    oct = tvb_get_guint8(tvb, offset);

    temp = (((oct & 0xf0) >> 4) * 10) + (oct & 0x0f);
    temp += ((temp < 96) ? 2000 : 1900);

    proto_tree_add_uint_format_value(tree, hf_year, tvb, offset, 1,
        oct,
        "%u (%02x)",
        temp, oct);

    offset += 1;

    oct = tvb_get_guint8(tvb, offset);

    temp = (((oct & 0xf0) >> 4) * 10) + (oct & 0x0f) - 1;

    str = val_to_str_const(temp, ansi_tele_month_strings, "Invalid");
    proto_tree_add_uint_format_value(tree, hf_month, tvb, offset, 1,
        oct,
        "%s (%02x)",
        str, oct);

    offset += 1;

    oct = tvb_get_guint8(tvb, offset);

    temp = (((oct & 0xf0) >> 4) * 10) + (oct & 0x0f);

    proto_tree_add_uint_format_value(tree, hf_day, tvb, offset, 1,
        oct,
        "%u",
        temp);

    offset += 1;

    oct = tvb_get_guint8(tvb, offset);

    temp = (((oct & 0xf0) >> 4) * 10) + (oct & 0x0f);

    proto_tree_add_uint_format_value(tree, hf_hours, tvb, offset, 1,
        oct,
        "%u",
        temp);

    offset += 1;

    oct = tvb_get_guint8(tvb, offset);

    temp = (((oct & 0xf0) >> 4) * 10) + (oct & 0x0f);

    proto_tree_add_uint_format_value(tree, hf_minutes, tvb, offset, 1, oct,
        "%u",
        temp);

    offset += 1;

    oct = tvb_get_guint8(tvb, offset);

    temp = (((oct & 0xf0) >> 4) * 10) + (oct & 0x0f);

    proto_tree_add_uint_format_value(tree, hf_seconds, tvb, offset, 1,
        oct,
        "%u",
        temp);
}

static void
tele_param_msg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p)
{
    EXACT_DATA_CHECK(len, 3);

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_type, tvb, offset, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_id, tvb, offset, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_header_ind, tvb, offset, 3, ENC_BIG_ENDIAN);
    if ((tvb_get_guint8(tvb, offset + 2) & 0x08) == 0x08)
    {
        *has_private_data_p = TRUE;
    }

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_rsvd, tvb, offset, 3, ENC_BIG_ENDIAN);
}

/*
 * for record types 0, 1, 2 and 3 for unknowns
 */
#define NUM_CMAS_PARAM 4
static gint ett_tia_1149_cmas_param[NUM_CMAS_PARAM];

/*
 * Special dissection for CMAS Message as defined in TIA-1149
 */
static const value_string cmas_category_strings[] = {
    { 0x00,     "Geo (Geophysical including landslide)" },
    { 0x01,     "Met (Meteorological including flood)" },
    { 0x02,     "Safety (General emergency and public safety)" },
    { 0x03,     "Security (Law enforcement, military, homeland and local/private security)" },
    { 0x04,     "Rescue (Rescue and recovery)" },
    { 0x05,     "Fire (Fire suppression and rescue)" },
    { 0x06,     "Health (Medical and public health)" },
    { 0x07,     "Env (Pollution and other environmental)" },
    { 0x08,     "Transport (Public and private transportation)" },
    { 0x09,     "Infra (Utility, telecommunication, other nontransport infrastructure)" },
    { 0x0a,     "CBRNE (Chemical, Biological, Radiological, Nuclear or High-Yield Explosive threat or attack)" },
    { 0x0b,     "Other (Other events)" },
    { 0, NULL }
};

static const value_string cmas_response_type_strings[] = {
    { 0x00,     "Shelter (Take shelter in place)" },
    { 0x01,     "Evacuate (Relocate)" },
    { 0x02,     "Prepare (Make preparations)" },
    { 0x03,     "Execute (Execute a pre-planned activity)" },
    { 0x04,     "Monitor (Attend to information sources)" },
    { 0x05,     "Avoid (Avoid hazard)" },
    { 0x06,     "Assess (Evaluate the information in this message. This value SHOULD NOT be used in public warning applications.)" },
    { 0x07,     "None (No action recommended)" },
    { 0, NULL }
};

static const value_string cmas_severity_strings[] = {
    { 0x00,     "Extreme (Extraordinary threat to life or property)" },
    { 0x01,     "Severe (Significant threat to life or property)" },
    { 0, NULL }
};

static const value_string cmas_urgency_strings[] = {
    { 0x00,     "Immediate (Responsive action should be taken immediately)" },
    { 0x01,     "Expected (Responsive action should be taken soon - within the next hour)" },
    { 0, NULL }
};

static const value_string cmas_certainty_strings[] = {
    { 0x00,     "Observed (Determined to have occurred or to be ongoing)" },
    { 0x01,     "Likely (Likely. Probability > ~50%)" },
    { 0, NULL }
};

static void
tele_param_user_data_cmas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    proto_tree  *subtree;
    guint8      bit_mask_8;
    guint8      oct, oct2;
    guint8      encoding;
    guint8      num_fields;
    guint8      reserved_bits;
    guint8      unused_bits;
    guint8      record_type;
    guint8      record_len;
    guint8      subtree_idx;
    guint16     num_bits;
    guint32     value;
    guint32     temp_offset;
    guint32     required_octs;
    tvbuff_t    *tvb_out = NULL;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    value = tvb_get_ntohs(tvb, offset);

    /*
     * must be encoded as 'Octet, unspecified'
     */
    if ((value & 0xf800) != 0)
    {
        proto_tree_add_expert(tree, pinfo, &ei_ansi_637_unknown_encoding, tvb, offset, len);
        return;
    }

    proto_tree_add_uint_format_value(tree, hf_ansi_637_tele_cmas_encoding, tvb, offset, 2,
        value,
        "%s (%u)",
        val_to_str_const((value & 0xf800) >> 11, ansi_tsb58_encoding_vals, "Error"),
        (value & 0xf800) >> 11);

    proto_tree_add_item(tree, hf_ansi_637_tele_cmas_num_fields, tvb, offset, 2, ENC_BIG_ENDIAN);

    num_fields = (value & 0x07f8) >> 3;

    offset += 2;

    /* NOTE: there are now 3 bits remaining in 'value' */

    unused_bits = 3;

    required_octs = num_fields;

    tvb_out =
        tvb_new_octet_aligned(tvb, ((offset - 1) * 8) + (8 - unused_bits), (required_octs * 8));
    add_new_data_source(pinfo, tvb_out, "CMAS Message");

    temp_offset = offset;
    offset = 0;

    proto_tree_add_item(tree, hf_ansi_637_tele_cmas_protocol_version, tvb_out, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    while ((required_octs - offset) > 2)
    {
        record_type = tvb_get_guint8(tvb_out, offset);
        subtree_idx = record_type;

        switch (record_type)
        {
        default: str = "Reserved"; subtree_idx = 3; break;
        case 0x00: str = "Type 0 Elements (Alert Text)"; break;
        case 0x01: str = "Type 1 Elements"; break;
        case 0x02: str = "Type 2 Elements"; break;
        }

        record_len = tvb_get_guint8(tvb_out, offset + 1);

        subtree =
            proto_tree_add_subtree(tree, tvb_out, offset, record_len + 2,
                ett_tia_1149_cmas_param[subtree_idx], NULL,  str);

        proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_record_type, tvb_out, offset, 1,
            record_type,
            "%s",
            str);

        offset += 1;

        proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_record_len, tvb_out, offset, 1,
            record_len,
            "%u",
            record_len);

        offset += 1;

        switch (record_type)
        {
        default:
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_637_unknown_cmas_record_type, tvb_out, offset, record_len);

            offset += record_len;
            break;

        case 0x00:
            encoding = (tvb_get_guint8(tvb_out, offset) & 0xf8) >> 3;

            str = val_to_str_const(encoding, ansi_tsb58_encoding_vals, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_char_set, tvb_out, offset, 1,
                encoding,
                "%s (%u)",
                str, encoding);

            num_bits = (record_len * 8) - 5;

            switch (encoding)
            {
            case 0x04: /* UNICODE */
                /* 16-bit encodings */
                num_fields = num_bits / 16;
                reserved_bits = 3;
                break;

            case 0x00: /* Octet, unspecified */
            case 0x10: /* KSC5601 (Korean) */
            case 0x07: /* Latin/Hebrew */
            case 0x08: /* Latin */
                /* 8-bit encodings */
                num_fields = num_bits / 8;
                reserved_bits = 3;
                break;

            default:
                /* 7-bit encodings */
                num_fields = num_bits / 7;

                if ((num_bits % 7) == 0)
                {
                    oct2 = tvb_get_guint8(tvb_out, offset + record_len - 1);
                    if ((oct2 & 0x7f) == 0)
                    {
                        /*
                         * the entire last 7 bits are reserved
                         */
                        num_fields--;
                    }
                }

                reserved_bits = num_bits - (num_fields * 7);
                break;
            }

            temp_offset = offset;
            text_decoder(tvb_out, pinfo, subtree, temp_offset, encoding, num_fields,
                num_bits, 3 /* (5 bits used from 'temp_offset' octet for encoding */, 0);

            offset += (record_len - 1);

            if (reserved_bits > 0)
            {
                oct = tvb_get_guint8(tvb_out, offset);

                bit_mask_8 = MASK_B(8 - reserved_bits, reserved_bits);

                other_decode_bitfield_value(ansi_637_bigbuf, oct, bit_mask_8, 8);
                proto_tree_add_uint_format(subtree, hf_ansi_637_reserved_bits_8_generic, tvb_out, offset, 1,
                    oct & bit_mask_8,
                    "%s = Reserved bit(s)",
                    ansi_637_bigbuf);
            }

            offset += 1;
            break;

        case 0x01:
            oct = tvb_get_guint8(tvb_out, offset);

            str = val_to_str_const(oct, cmas_category_strings, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_category, tvb_out, offset, 1,
                oct,
                "%s (%u)",
                str, oct);

            offset += 1;

            oct = tvb_get_guint8(tvb_out, offset);

            str = val_to_str_const(oct, cmas_response_type_strings, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_response_type, tvb_out, offset, 1,
                oct,
                "%s (%u)",
                str, oct);

            offset += 1;

            oct = tvb_get_guint8(tvb_out, offset);

            str = val_to_str_const((oct & 0xf0) >> 4, cmas_severity_strings, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_severity, tvb_out, offset, 1,
                oct,
                "%s (%u)",
                str, (oct & 0xf0) >> 4);

            str = val_to_str_const(oct & 0x0f, cmas_urgency_strings, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_urgency, tvb_out, offset, 1,
                oct,
                "%s (%u)",
                str, oct & 0x0f);

            offset += 1;

            oct = tvb_get_guint8(tvb_out, offset);

            str = val_to_str_const((oct & 0xf0) >> 4, cmas_certainty_strings, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_certainty, tvb_out, offset, 1,
                oct,
                "%s (%u)",
                str, (oct & 0xf0) >> 4);

            proto_tree_add_item(subtree, hf_ansi_637_reserved_bits_8_0f, tvb_out, offset, 1, ENC_BIG_ENDIAN);

            offset += 1;
            break;

        case 0x02:
            proto_tree_add_item(subtree, hf_ansi_637_tele_cmas_identifier, tvb_out, offset, 2, ENC_BIG_ENDIAN);

            offset += 2;

            proto_tree_add_item(subtree, hf_ansi_637_tele_cmas_alert_handling, tvb_out, offset, 1, ENC_BIG_ENDIAN);

            offset += 1;

            oct = tvb_get_guint8(tvb_out, offset);

            /*
             * TIA-1149 does not say whether this should be encoded in the same way as IS-637
             * I.e. year = oct + ((oct < 96) ? 2000 : 1900);
             */
            value = oct + ((oct < 96) ? 2000 : 1900);

            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_expires_year, tvb_out, offset, 1,
                oct,
                "%u (%02x)",
                value, oct);

            offset += 1;

            oct = tvb_get_guint8(tvb_out, offset);

            str = val_to_str_const(oct - 1, ansi_tele_month_strings, "Invalid");

            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_expires_month, tvb_out, offset, 1,
                oct,
                "%s (%02x)",
                str, oct);

            offset += 1;

            proto_tree_add_item(subtree, hf_ansi_637_tele_cmas_expires_day, tvb_out, offset, 1, ENC_BIG_ENDIAN);

            offset += 1;

            proto_tree_add_item(subtree, hf_ansi_637_tele_cmas_expires_hours, tvb_out, offset, 1, ENC_BIG_ENDIAN);

            offset += 1;

            proto_tree_add_item(subtree, hf_ansi_637_tele_cmas_expires_minutes, tvb_out, offset, 1, ENC_BIG_ENDIAN);

            offset += 1;

            proto_tree_add_item(subtree, hf_ansi_637_tele_cmas_expires_seconds, tvb_out, offset, 1, ENC_BIG_ENDIAN);

            offset += 1;

            oct = tvb_get_guint8(tvb_out, offset);

            str = val_to_str_ext_const(oct, &ansi_tsb58_language_ind_vals_ext, "Reserved");
            proto_tree_add_uint_format_value(subtree, hf_ansi_637_tele_cmas_language, tvb_out, offset, 1,
                oct,
                "%s (%u)",
                str, oct);

            offset += 1;
            break;
        }
    }

    EXTRANEOUS_DATA_CHECK(required_octs, offset);

    offset += temp_offset;      /* move 'offset' back to the correct spot in 'tvb' */

    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_07, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
tele_param_user_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p)
{
    guint8              oct;
    guint8              bit_mask_8;
    guint8              encoding;
    guint8              encoding_bit_len;
    guint8              num_fields;
    guint8              unused_bits;
    guint8              fill_bits;
    guint16             reserved_bits;
    guint32             value;
    guint32             orig_offset;
    guint32             saved_offset;
    guint32             required_octs;
    const gchar         *str = NULL;
    tvbuff_t            *tvb_out = NULL;
    enum character_set  cset;

    SHORT_DATA_CHECK(len, 2);

    orig_offset = offset;
    reserved_bits = len * 8;

    value = tvb_get_ntohs(tvb, offset);

    encoding_bit_len = 7;
    cset = ASCII_7BITS;

    encoding = (guint8) ((value & 0xf800) >> 11);
    switch (encoding)
    {
    case 0x00:
        str = "Octet, unspecified";
        encoding_bit_len = 8;
        cset = OTHER;
        break;

    case 0x01:
        str = "Extended Protocol Message";
        break;

    case 0x02:
        str = "7-bit ASCII";
        break;

    case 0x03:
        str = "IA5";
        break;

    case 0x04:
        str = "UNICODE";
        encoding_bit_len = 16;
        cset = OTHER;
        break;

    case 0x05:
        str = "Shift-JIS";
        break;

    case 0x06:
        str = "Korean";
        cset = OTHER;
        break;

    case 0x07:
        str = "Latin/Hebrew";
        encoding_bit_len = 8;
        cset = OTHER;
        break;

    case 0x08:
        str = "Latin";
        encoding_bit_len = 8;
        cset = OTHER;
        break;

    case 0x09:
        str = "GSM 7-bit default alphabet";
        cset = GSM_7BITS;
        break;

    case 0x10:
        str = "KSC5601 (Korean)";
        encoding_bit_len = 8;
        cset = OTHER;
        break;

    default:
        str = "Reserved";
        break;
    }

    proto_tree_add_uint_format_value(tree, hf_ansi_637_tele_user_data_encoding, tvb, offset, 2,
        value,
        "%s (%u)",
        str,
        encoding);

    reserved_bits -= 5;

    if (encoding == 0x01)
    {
        proto_tree_add_item(tree, hf_ansi_637_tele_user_data_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 1;
        value = tvb_get_ntohs(tvb, offset);

        reserved_bits -= 8;
    }

    proto_tree_add_item(tree, hf_ansi_637_tele_user_data_num_fields, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 1;

    num_fields = (value & 0x07f8) >> 3;

    reserved_bits -= 8 + (num_fields * encoding_bit_len);

    /* NOTE: there are now 3 bits remaining in 'value' */

    unused_bits = 3;
    fill_bits = 0;

    /*
     * ALL of this is for header support !
     */
    if (*has_private_data_p == TRUE)
    {
        gsm_sms_udh_fields_t    udh_fields;
        gint32                  num_udh_bits;

        memset(&udh_fields, 0, sizeof(udh_fields));

        value = tvb_get_ntohs(tvb, offset);

        /*
         * 'length' split across two octets +1 for the length octet itself
         * (dis_field_udh() will start at the length offset)
         */
        required_octs = ((value & 0x07f8) >> 3) + 1;

        /*
         * need fill bits
         */
        if (encoding_bit_len == 7)
        {
            /*
             * not the same formula as dis_field_udh() because we are including
             * the length octet in the calculation but the result is the same
             */
            fill_bits = 7 - ((required_octs * 8) % 7);
        }

        num_udh_bits = (required_octs * 8) + fill_bits;

        tvb_out =
            tvb_new_octet_aligned(tvb, (offset * 8) + (8 - unused_bits), num_udh_bits);
        add_new_data_source(pinfo, tvb_out, "Header");

        saved_offset = offset + required_octs;

        offset = 0;
        fill_bits = 0;
        dis_field_udh(tvb_out, tree, &offset, &required_octs, &num_fields, cset, &fill_bits, &udh_fields);

        offset = saved_offset;

        if (encoding_bit_len == 7)
        {
            switch (cset)
            {
            case GSM_7BITS:
            case OTHER:
                break;

            case ASCII_7BITS:
                if (fill_bits > unused_bits)
                {
                    /* this branch was NOT tested */

                    offset += 1;
                    unused_bits = 8 - (fill_bits - unused_bits);
                }
                else if (fill_bits > 0)
                {
                    /* this branch was tested */
                    unused_bits = unused_bits - fill_bits;
                }

                if (unused_bits == 0)
                {
                    /* this branch was NOT tested */

                    offset += 1;
                    unused_bits = 8;
                }
                break;
            }
        }

        if (udh_fields.frags > 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Short Message fragment %u of %u)", udh_fields.frag, udh_fields.frags);
        }
    }

    text_decoder(tvb, pinfo, tree, offset, encoding, num_fields,
        num_fields * encoding_bit_len, unused_bits, fill_bits);

    if (reserved_bits > 0)
    {
        /*
         * unlike for CMAS, the bits that can be reserved will always be
         * at the end of an octet so we don't have to worry about them
         * spanning two octets
         */

        switch (cset)
        {
        case GSM_7BITS:
            bit_mask_8 = MASK_B(0, reserved_bits);                      /* MSBs */
            break;

        default:
            bit_mask_8 = MASK_B(8 - reserved_bits, reserved_bits);      /* LSBs */
            break;
        }

        oct = tvb_get_guint8(tvb, orig_offset + len - 1);

        other_decode_bitfield_value(ansi_637_bigbuf, oct, bit_mask_8, 8);
        proto_tree_add_uint_format(tree, hf_ansi_637_reserved_bits_8_generic, tvb, orig_offset + len - 1, 1,
            oct & bit_mask_8,
            "%s = Reserved bit(s)",
            ansi_637_bigbuf);
    }
}

static void
tele_param_rsp_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
tele_param_message_center_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 6);

    tele_param_timestamp(tvb, pinfo, tree, len, offset,
        hf_ansi_637_tele_message_center_ts_year,
        hf_ansi_637_tele_message_center_ts_month,
        hf_ansi_637_tele_message_center_ts_day,
        hf_ansi_637_tele_message_center_ts_hours,
        hf_ansi_637_tele_message_center_ts_minutes,
        hf_ansi_637_tele_message_center_ts_seconds);
}

static void
tele_param_validity_period_abs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 6);

    tele_param_timestamp(tvb, pinfo, tree, len, offset,
        hf_ansi_637_tele_validity_period_ts_year,
        hf_ansi_637_tele_validity_period_ts_month,
        hf_ansi_637_tele_validity_period_ts_day,
        hf_ansi_637_tele_validity_period_ts_hours,
        hf_ansi_637_tele_validity_period_ts_minutes,
        hf_ansi_637_tele_validity_period_ts_seconds);
}

static void
tele_param_timestamp_rel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len _U_, guint32 offset, int hf)
{
    guint8      oct;
    guint32     value = 0;
    const gchar *str = NULL;
    const gchar *str2 = NULL;

    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case 245: str = "Indefinite"; break;
    case 246: str = "Immediate"; break;
    case 247: str = "Valid until mobile becomes inactive/Deliver when mobile next becomes active"; break;
    case 248: str = "Valid until registration area changes, discard if not registered" ; break;
    default:
        if (oct <= 143) { value = (oct + 1) * 5; str2 = "Minutes"; break; }
        else if ((oct >= 144) && (oct <= 167)) { value = (oct - 143) * 30; str2 = "Minutes + 12 Hours"; break; }
        else if ((oct >= 168) && (oct <= 196)) { value = oct - 166; str2 = "Days"; break; }
        else if ((oct >= 197) && (oct <= 244)) { value = oct - 192; str2 = "Weeks"; break; }
        else { str = "Reserved"; break; }
    }

    if (str != NULL)
    {
        proto_tree_add_uint_format_value(tree, hf, tvb, offset, 1,
            oct,
            "%s",
            str);
    }
    else
    {
        proto_tree_add_uint_format_value(tree, hf, tvb, offset, 1,
            oct,
            "%u %s",
            value, str2);
    }
}

static void
tele_param_validity_period_rel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    tele_param_timestamp_rel(tvb, pinfo, tree, len, offset, hf_ansi_637_tele_validity_period_relative_validity);
}

static void
tele_param_deferred_del_abs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 6);

    tele_param_timestamp(tvb, pinfo, tree, len, offset,
        hf_ansi_637_tele_deferred_del_ts_year,
        hf_ansi_637_tele_deferred_del_ts_month,
        hf_ansi_637_tele_deferred_del_ts_day,
        hf_ansi_637_tele_deferred_del_ts_hours,
        hf_ansi_637_tele_deferred_del_ts_minutes,
        hf_ansi_637_tele_deferred_del_ts_seconds);
}

static void
tele_param_deferred_del_rel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    tele_param_timestamp_rel(tvb, pinfo, tree, len, offset, hf_ansi_637_tele_deferred_del_relative);
}

static const value_string tele_param_priority_ind_strings[] = {
    { 0,        "Normal" },
    { 1,        "Interactive" },
    { 2,        "Urgent" },
    { 3,        "Emergency" },
    { 0, NULL }
};

static void
tele_param_pri_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_priority_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_3f, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static const value_string tele_param_privacy_ind_strings[] = {
    { 0,        "Not restricted (privacy level 0)" },
    { 1,        "Restricted (privacy level 1)" },
    { 2,        "Confidential (privacy level 2)" },
    { 3,        "Secret (privacy level 3)" },
    { 0, NULL }
};

static void
tele_param_priv_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_privacy_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_3f, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
tele_param_reply_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_reply_option_user_ack_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_tele_reply_option_dak_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_tele_reply_option_read_ack_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_tele_reply_option_report_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_0f, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
tele_param_num_messages(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    guint8      oct;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint_format_value(tree, hf_ansi_637_tele_num_messages, tvb, offset, 1,
        ((oct & 0xf0) >> 4) * 10 + (oct & 0x0f),
        "%u%u",
        (oct & 0xf0) >> 4, oct & 0x0f);
}

static const value_string tele_param_alert_priority_strings[] = {
    { 0,        "Use Mobile default alert" },
    { 1,        "Use Low-priority alert" },
    { 2,        "Use Medium-priority alert" },
    { 3,        "Use High-priority alert" },
    { 0, NULL }
};

static void
tele_param_alert(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_alert_msg_delivery_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_3f, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
tele_param_lang_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    guint8      oct;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    str = val_to_str_ext_const(oct, &ansi_tsb58_language_ind_vals_ext, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_637_tele_language, tvb, offset, 1,
        oct,
        "%s (%u)",
        str, oct);
}

static void
tele_param_cb_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    guint8      oct, oct2, num_fields, odd;
    guint8      *poctets;
    guint32     saved_offset;
    guint32     required_octs;
    guint32     i;

    SHORT_DATA_CHECK(len, 2);

    proto_tree_add_item(tree, hf_ansi_637_tele_cb_num_digit_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
        proto_tree_add_item(tree, hf_ansi_637_tele_cb_num_ton, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_637_tele_cb_num_plan, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset += 1;

        proto_tree_add_item(tree, hf_ansi_637_tele_cb_num_num_fields, tvb, offset, 1, ENC_BIG_ENDIAN);

        num_fields = tvb_get_guint8(tvb, offset);

        if (num_fields == 0) return;

        SHORT_DATA_CHECK(len - 2, num_fields);

        offset += 1;

        poctets = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, num_fields, ENC_ASCII|ENC_NA);

        proto_tree_add_string_format(tree, hf_ansi_637_tele_cb_num_number, tvb, offset, num_fields,
            (gchar *) poctets,
            "Number: %s",
            (gchar *) format_text(poctets, num_fields));
    }
    else
    {
        offset += 1;

        oct2 = tvb_get_guint8(tvb, offset);
        num_fields = ((oct & 0x7f) << 1) | ((oct2 & 0x80) >> 7);

        /*
         * not combined into a 16-bit field because hf_ansi_637_tele_cb_num_num_fields is used above
         * and uses a different bitmask
         */
        other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x7f, 8);
        proto_tree_add_uint_format(tree, hf_ansi_637_tele_cb_num_num_fields, tvb, offset, 1,
            num_fields,
            "%s = Number of fields (MSB): %u",
            ansi_637_bigbuf,
            num_fields);

        other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x80, 8);
        proto_tree_add_text(tree, tvb, offset, 1,
            "%s = Number of fields (LSB)",
            ansi_637_bigbuf);

        oct = oct2;
        odd = FALSE;

        if (num_fields > 0)
        {
            i = (num_fields - 1) * 4;
            required_octs = (i / 8) + ((i % 8) ? 1 : 0);

            SHORT_DATA_CHECK(len - 2, required_octs);

            odd = num_fields & 0x01;
            memset((void *) ansi_637_bigbuf, 0, sizeof(ansi_637_bigbuf));
            saved_offset = offset;
            offset += 1;

            i = 0;
            while (i < num_fields)
            {
                ansi_637_bigbuf[i] = air_digits[(oct & 0x78) >> 3];

                i += 1;
                if (i >= num_fields) break;

                oct2 = tvb_get_guint8(tvb, offset);
                offset += 1;

                ansi_637_bigbuf[i] = air_digits[((oct & 0x07) << 1) | ((oct2 & 0x80) >> 7)];

                oct = oct2;
                i += 1;
            }

            proto_tree_add_string_format(tree, hf_ansi_637_tele_cb_num_number, tvb, saved_offset, offset - saved_offset,
                ansi_637_bigbuf,
                "Number: %s",
                ansi_637_bigbuf);
        }

        proto_tree_add_item(tree,
            odd ? hf_ansi_637_reserved_bits_8_07 : hf_ansi_637_reserved_bits_8_7f,
            tvb, offset - 1, 1, ENC_BIG_ENDIAN);
    }
}

static const value_string tele_param_msg_display_mode_strings[] = {
    { 0,        "Immediate Display: The mobile station is to display the received message as soon as possible." },
    { 1,        "Mobile default setting: The mobile station is to display the received message based on a pre-defined mode in the mobile station." },
    { 2,        "User Invoke: The mobile station is to display the received message based on the mode selected by the user." },
    { 3,        "Reserved" },
    { 0, NULL }
};

static void
tele_param_disp_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_display_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_3f, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
tele_param_msg_deposit_idx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 2);

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_deposit_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static const value_string tele_param_srvc_cat_prog_results_result_strings[] = {
    { 0x00,     "Programming successful" },
    { 0x01,     "Service Category memory limit exceeded" },
    { 0x02,     "Service Category limit exceeded" },
    { 0x03,     "Category already programmed" },
    { 0x04,     "Category not previously programmed" },
    { 0x05,     "Invalid MAX_MESSAGES" },
    { 0x06,     "Invalid ALERT_OPTION" },
    { 0x07,     "Invalid Service Category name" },
    { 0x08,     "Unspecified programming failure" },
    { 0x09,     "Reserved" },
    { 0x0a,     "Reserved" },
    { 0x0b,     "Reserved" },
    { 0x0c,     "Reserved" },
    { 0x0d,     "Reserved" },
    { 0x0e,     "Reserved" },
    { 0x0f,     "Reserved" },
    { 0, NULL }
};

static void
tele_param_srvc_cat_prog_results(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    guint32     curr_offset;
    guint32     value;
    const gchar *str = NULL;

    curr_offset = offset;

    while ((len - (curr_offset - offset)) >= 3)
    {
        value = tvb_get_ntohs(tvb, curr_offset);

        str = val_to_str_const(value, ansi_tsb58_srvc_cat_vals, "Reserved");
        proto_tree_add_uint_format_value(tree, hf_ansi_637_tele_srvc_cat_prog_results_srvc_cat, tvb, curr_offset, 2,
            value,
            "%s (%u)",
            str, value);

        curr_offset += 2;

        proto_tree_add_item(tree, hf_ansi_637_tele_srvc_cat_prog_results_result, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_0f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset += 1;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/* Adamek Jan - IS637C Message status decoding procedure */
static const value_string tele_param_msg_status_error_class_strings[] = {
    { 0x00,     "No Error" },
    { 0x01,     "Reserved" },
    { 0x02,     "Temporary Condition" },
    { 0x03,     "Permanent Condition" },
    { 0, NULL }
};

static void
tele_param_msg_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    guint8      oct;
    guint8      msg_status_code;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_msg_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_tele_msg_status_error_class, tvb, offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, offset);

    msg_status_code = (oct & 0x3f);

    switch ((oct & 0xc0) >> 6)
    {
    case 0x00:
        switch (msg_status_code)
        {
        case 0x00: str = "Message accepted"; break;
        case 0x01: str = "Message deposited to Internet"; break;
        case 0x02: str = "Message delivered"; break;
        case 0x03: str = "Message cancelled"; break;
        default: str = "Reserved"; break;
        }
        break;

    case 0x02:
        switch (msg_status_code)
        {
        case 0x04: str = "Network congestion"; break;
        case 0x05: str = "Network error"; break;
        case 0x1f: str = "Unknown error"; break;
        default: str = "Reserved"; break;
        }
        break;

    case 0x03:
        switch (msg_status_code)
        {
        case 0x04: str = "Network congestion"; break;
        case 0x05: str = "Network error"; break;
        case 0x06: str = "Cancel failed"; break;
        case 0x07: str = "Blocked destination"; break;
        case 0x08: str = "Text too long"; break;
        case 0x09: str = "Duplicate message"; break;
        case 0x0a: str = "Invalid destination"; break;
        case 0x0d: str = "Message expired"; break;
        case 0x1f: str = "Unknown error"; break;
        default: str = "Reserved"; break;
        }
        break;

    default:
        str = "Reserved";
        break;
    }

    proto_tree_add_uint_format_value(tree, hf_ansi_637_tele_msg_status_code, tvb, offset, 1,
        oct,
        "%s (%u)",
        str, msg_status_code);
}

static void
tele_param_tp_failure_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p _U_)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_637_tele_tp_failure_cause_value, tvb, offset, 1, ENC_BIG_ENDIAN);
}

#define NUM_TELE_PARAM (sizeof(ansi_tele_param_strings)/sizeof(value_string))
static gint ett_ansi_637_tele_param[NUM_TELE_PARAM];
static void (*ansi_637_tele_param_fcn[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gboolean *has_private_data_p) = {
    tele_param_msg_id,                  /* Message Identifier */
    tele_param_user_data,               /* User Data */
    tele_param_rsp_code,                /* User Response Code */
    tele_param_message_center_timestamp,/* Message Center Time Stamp */
    tele_param_validity_period_abs,     /* Validity Period - Absolute */
    tele_param_validity_period_rel,     /* Validity Period - Relative */
    tele_param_deferred_del_abs,        /* Deferred Delivery Time - Absolute */
    tele_param_deferred_del_rel,        /* Deferred Delivery Time - Relative */
    tele_param_pri_ind,                 /* Priority Indicator */
    tele_param_priv_ind,                /* Privacy Indicator */
    tele_param_reply_opt,               /* Reply Option */
    tele_param_num_messages,            /* Number of Messages */
    tele_param_alert,                   /* Alert on Message Delivery */
    tele_param_lang_ind,                /* Language Indicator */
    tele_param_cb_num,                  /* Call-Back Number */
    tele_param_disp_mode,               /* Message Display Mode */
    NULL,                               /* Multiple Encoding User Data */
    tele_param_msg_deposit_idx,         /* Message Deposit Index */
    NULL,                               /* Service Category Program Data */
    tele_param_srvc_cat_prog_results,   /* Service Category Program Results */
    tele_param_msg_status,              /* Message status */
    tele_param_tp_failure_cause,        /* TP-Failure cause */
    NULL,                               /* Enhanced VMN */
    NULL                                /* Enhanced VMN Ack */
};

static void
trans_param_tele_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint32     value;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 2);

    value = tvb_get_ntohs(tvb, offset);

    ansi_637_trans_tele_id = value;

    str = try_val_to_str(value, ansi_tele_id_strings);

    if (NULL == str)
    {
        switch (value)
        {
        case 1:
            str = "Reserved for maintenance";
            break;
        case 4102:
            str = "CDMA Service Category Programming Teleservice (SCPT)";
            break;
        case 4103:
            str = "CDMA Card Application Toolkit Protocol Teleservice (CATPT)";
            break;
        case 32513:
            str = "TDMA Cellular Messaging Teleservice";
            break;
        case 32514:
            str = "TDMA Cellular Paging Teleservice (CPT-136)";
            break;
        case 32515:
            str = "TDMA Over-the-Air Activation Teleservice (OATS)";
            break;
        case 32520:
            str = "TDMA System Assisted Mobile Positioning through Satellite (SAMPS)";
            break;
        case 32584:
            str = "TDMA Segmented System Assisted Mobile Positioning Service";
            break;
        default:
            if ((value >= 2) && (value <= 4095))
            {
                str = "Reserved for assignment by TIA-41";
            }
            else if ((value >= 4104) && (value <= 4113))
            {
                str = "Reserved for GSM1x Teleservice (CDMA)";
            }
            else if ((value >= 4114) && (value <= 32512))
            {
                str = "Reserved for assignment by TIA-41";
            }
            else if ((value >= 32521) && (value <= 32575))
            {
                str = "Reserved for assignment by this Standard for TDMA MS-based SMEs";
            }
            else if ((value >= 49152) && (value <= 65535))
            {
                str = "Reserved for carrier specific teleservices";
            }
            else
            {
                str = "Unrecognized Teleservice ID";
            }
            break;
        }
    }

    /*
     * NOT format_value because I don't need the text from the hf_
     */
    proto_tree_add_uint_format(tree, hf_ansi_637_trans_tele_id, tvb, offset, 2,
        value,
        "%s (%u)",
        str, value);

    g_snprintf(add_string, string_len, " - %s (%u)", str, value);
}

static void
trans_param_srvc_cat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint32     value;
    const gchar *str;

    EXACT_DATA_CHECK(len, 2);

    value = tvb_get_ntohs(tvb, offset);

    str = val_to_str_const(value, ansi_tsb58_srvc_cat_vals, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_637_trans_srvc_cat, tvb, offset, 2,
        value,
        "%s (%u)",
        str, value);

    g_snprintf(add_string, string_len, " - %s (%u)", str, value);

    if ((value >= ANSI_TSB58_SRVC_CAT_CMAS_MIN) && (value <= ANSI_TSB58_SRVC_CAT_CMAS_MAX))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " - CMAS (%s)", str);
    }
}

static const value_string trans_param_addr_data_net_ton_strings[] = {
    { 0x00,     "Unknown" },
    { 0x01,     "Internet Protocol (RFC 791)" },
    { 0x02,     "Internet Email Address (RFC 822)" },
    { 0, NULL }
};

static void
trans_param_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct, oct2, num_fields, odd;
    gboolean    email_addr;
    guint32     saved_offset;
    guint32     required_octs;
    guint32     i;

    SHORT_DATA_CHECK(len, 2);

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_637_trans_addr_param_digit_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_trans_addr_param_number_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (oct & 0x80)
    {
        if (oct & 0x40)
        {
            email_addr = (((oct & 0x38) >> 3) == 0x02) ? TRUE : FALSE;

            /*
             * do not change to ...add_item() with VALS in hf defintion because this parameter is
             * used below in the 'else' with a different string array
             */
            proto_tree_add_uint_format_value(tree, hf_ansi_637_trans_addr_param_ton, tvb, offset, 1,
                oct,
                "%s (%u)",
                val_to_str_const((oct & 0x38) >> 3, trans_param_addr_data_net_ton_strings, "Reserved"), (oct & 0x38) >> 3);

            offset += 1;

            oct2 = tvb_get_guint8(tvb, offset);
            num_fields = ((oct & 0x07) << 5) | ((oct2 & 0xf8) >> 3);

            /*
             * not combined into a 16-bit field because hf_ansi_637_trans_addr_param_num_fields is used below
             * and uses a different bitmask
             */
            other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
            proto_tree_add_uint_format(tree, hf_ansi_637_trans_addr_param_num_fields, tvb, offset - 1, 1,
                num_fields,
                "%s = Number of fields (MSB): %u",
                ansi_637_bigbuf, num_fields);

            other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xf8, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Number of fields (LSB)",
                ansi_637_bigbuf);

            if (num_fields == 0) return;

            SHORT_DATA_CHECK(len - 2, num_fields);

            other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x07, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Most significant bits of first field",
                ansi_637_bigbuf);

            offset += 1;
            oct = oct2;

            i = 0;
            while (i < num_fields)
            {
                ansi_637_bigbuf[i] = (oct & 0x07) << 5;
                ansi_637_bigbuf[i] |= ((oct = tvb_get_guint8(tvb, offset + i)) & 0xf8) >> 3;
                i += 1;
            }
            ansi_637_bigbuf[i] = '\0';

            if (email_addr)
            {
                proto_tree_add_string_format(tree, hf_ansi_637_trans_addr_param_number, tvb, offset, num_fields - 1,
                    ansi_637_bigbuf,
                    "Number: %s",
                    ansi_637_bigbuf);
            }
            else
            {
                proto_tree_add_bytes(tree, hf_ansi_637_trans_bin_addr, tvb, offset, num_fields - 1,
                    (guint8 *) ansi_637_bigbuf);
            }

            offset += (num_fields - 1);

            other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xf8, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Least significant bits of last field",
                ansi_637_bigbuf);

            proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_07, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else
        {
            /*
             * do not change to ...add_item() with VALS in hf definition because this parameter
             * is used above in the 'if' with a different string array
             */
            proto_tree_add_uint_format_value(tree, hf_ansi_637_trans_addr_param_ton, tvb, offset, 1,
                oct,
                "%s (%u)",
                val_to_str_const((oct & 0x38) >> 3, ansi_a_ms_info_rec_num_type_vals, "Reserved"), (oct & 0x38) >> 3);

            oct2 = tvb_get_guint8(tvb, offset + 1);

            other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
            proto_tree_add_uint_format(tree, hf_ansi_637_trans_addr_param_plan, tvb, offset, 1,
                ((oct & 0x07) << 1) | ((oct2 & 0x80) >> 7),
                "%s = Numbering Plan (MSB): %s (%u)",
                ansi_637_bigbuf,
                val_to_str_const(((oct & 0x07) << 1) | ((oct2 & 0x80) >> 7), ansi_a_ms_info_rec_num_plan_vals, "Reserved"),
                ((oct & 0x07) << 1) | ((oct2 & 0x80) >> 7));

            offset += 1;
            oct = oct2;

            other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Numbering Plan (LSB)",
                ansi_637_bigbuf);

            offset += 1;

            oct2 = tvb_get_guint8(tvb, offset);
            num_fields = ((oct & 0x7f) << 1) | ((oct2 & 0x80) >> 7);

            other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x7f, 8);
            proto_tree_add_uint_format(tree, hf_ansi_637_trans_addr_param_num_fields, tvb, offset - 1, 1,
                num_fields,
                "%s = Number of fields (MSB): %u",
                ansi_637_bigbuf,
                num_fields);

            other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x80, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Number of fields (LSB)",
                ansi_637_bigbuf);

            if (num_fields == 0) return;

            SHORT_DATA_CHECK(len - 3, num_fields);

            other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x7f, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Most significant bits of first field",
                ansi_637_bigbuf);

            offset += 1;
            oct = oct2;

            i = 0;
            while (i < num_fields)
            {
                ansi_637_bigbuf[i] = (oct & 0x7f) << 1;
                ansi_637_bigbuf[i] |= ((oct = tvb_get_guint8(tvb, offset + i)) & 0x80) >> 7;
                i += 1;
            }
            ansi_637_bigbuf[i] = '\0';

            proto_tree_add_string_format(tree, hf_ansi_637_trans_addr_param_number, tvb, offset, num_fields - 1,
                ansi_637_bigbuf,
                "Number: %s",
                ansi_637_bigbuf);

            offset += (num_fields - 1);

            other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
            proto_tree_add_text(tree, tvb, offset, 1,
                "%s = Least significant bit of last field",
                ansi_637_bigbuf);

            proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_7f, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
    }
    else
    {
        offset += 1;

        oct2 = tvb_get_guint8(tvb, offset);
        num_fields = ((oct & 0x3f) << 2) | ((oct2 & 0xc0) >> 6);

        other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
        proto_tree_add_uint_format(tree, hf_ansi_637_trans_addr_param_num_fields, tvb, offset - 1, 1,
            num_fields,
            "%s = Number of fields (MSB): %u",
            ansi_637_bigbuf,
            num_fields);

        other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xc0, 8);
        proto_tree_add_text(tree, tvb, offset, 1,
            "%s = Number of fields (LSB)",
            ansi_637_bigbuf);

        oct = oct2;
        odd = FALSE;

        if (num_fields > 0)
        {
            i = (num_fields - 1) * 4;
            required_octs = (i / 8) + ((i % 8) ? 1 : 0);

            SHORT_DATA_CHECK(len - 2, required_octs);

            odd = num_fields & 0x01;
            memset((void *) ansi_637_bigbuf, 0, sizeof(ansi_637_bigbuf));
            saved_offset = offset;
            offset += 1;

            i = 0;
            while (i < num_fields)
            {
                ansi_637_bigbuf[i] =
                    air_digits[(oct & 0x3c) >> 2];

                i += 1;
                if (i >= num_fields) break;

                oct2 = tvb_get_guint8(tvb, offset);
                offset += 1;

                ansi_637_bigbuf[i] =
                    air_digits[((oct & 0x03) << 2) | ((oct2 & 0xc0) >> 6)];

                oct = oct2;

                i += 1;
            }

            proto_tree_add_string_format(tree, hf_ansi_637_trans_addr_param_number, tvb, saved_offset, offset - saved_offset,
                ansi_637_bigbuf,
                "Number: %s",
                ansi_637_bigbuf);
        }

        proto_tree_add_item(tree,
            odd ? hf_ansi_637_reserved_bits_8_03 : hf_ansi_637_reserved_bits_8_3f,
            tvb, offset - 1, 1, ENC_BIG_ENDIAN);
    }
}

static const value_string trans_param_subaddr_type_strings[] = {
    { 0x0,      "NSAP (CCITT Recommendation X.213 or ISO 8348 AD2)" },
    { 0x1,      "User-specified" },
    { 0, NULL }
};

static void
trans_param_subaddress(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct, num_fields;
    guint32     value;
    guint32     i;

    SHORT_DATA_CHECK(len, 2);

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_uint_format_value(tree, hf_ansi_637_trans_subaddr_type, tvb, offset, 2,
        value,
        "%s (%u)",
        val_to_str_const((value & 0xe000) >> 13, trans_param_subaddr_type_strings, "Reserved"), (value & 0xe000) >> 13);

    proto_tree_add_item(tree, hf_ansi_637_trans_subaddr_odd_even_ind, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_trans_subaddr_num_fields, tvb, offset, 2, ENC_BIG_ENDIAN);

    num_fields = (value & 0x0ff0) >> 4;

    if (num_fields == 0) return;

    SHORT_DATA_CHECK(len - 2, num_fields);

    other_decode_bitfield_value(ansi_637_bigbuf, value, 0x000f, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
        "%s = Most significant bits of first field",
        ansi_637_bigbuf);

    offset += 2;

    oct = value & 0x000f;
    i = 0;
    while (i < num_fields)
    {
        ansi_637_bigbuf[i] = (oct & 0x0f) << 4;
        ansi_637_bigbuf[i] |= ((oct = tvb_get_guint8(tvb, offset + i)) & 0xf0) >> 4;
        i += 1;
    }
    ansi_637_bigbuf[i] = '\0';

    proto_tree_add_bytes(tree, hf_ansi_637_trans_bin_addr, tvb, offset, num_fields - 1,
        (guint8 *) ansi_637_bigbuf);

    offset += (num_fields - 1);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
        "%s = Least significant bits of last field",
        ansi_637_bigbuf);

    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_0f, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
trans_param_bearer_reply_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len _U_, guint32 offset, gchar *add_string, int string_len)
{
    proto_tree_add_item(tree, hf_ansi_637_trans_bearer_reply_seq_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_reserved_bits_8_03, tvb, offset, 1, ENC_BIG_ENDIAN);

    g_snprintf(add_string, string_len, " - Reply Sequence Number (%u)",
        (tvb_get_guint8(tvb, offset) & 0xfc) >> 2);
}

static const value_string trans_param_cause_codes_error_class_strings[] = {
    { 0x00,     "No Error" },
    { 0x01,     "Reserved" },
    { 0x02,     "Temporary Condition" },
    { 0x03,     "Permanent Condition" },
    { 0, NULL }
};

static void
trans_param_cause_codes(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint8      oct;
    const gchar *str;

    proto_tree_add_item(tree, hf_ansi_637_trans_cause_codes_seq_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_637_trans_cause_codes_error_class, tvb, offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, offset);

    g_snprintf(add_string, string_len, " - Reply Sequence Number (%u)", (oct & 0xfc) >> 2);

    if (!(oct & 0x03)) return;

    if (len == 1) return;

    offset += 1;

    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case   0: str = "Address vacant"; break;
    case   1: str = "Address translation failure"; break;
    case   2: str = "Network resource shortage"; break;
    case   3: str = "Network failure"; break;
    case   4: str = "Invalid Teleservice ID"; break;
    case   5: str = "Other network problem"; break;
    case   6: str = "Unsupported network interface"; break;
    case  32: str = "No page response"; break;
    case  33: str = "Destination busy"; break;
    case  34: str = "No acknowledgement"; break;
    case  35: str = "Destination resource shortage"; break;
    case  36: str = "SMS delivery postponed"; break;
    case  37: str = "Destination out of service"; break;
    case  38: str = "Destination no longer at this address"; break;
    case  39: str = "Other terminal problem"; break;
    case  64: str = "Radio interface resource shortage"; break;
    case  65: str = "Radio interface incompatibility"; break;
    case  66: str = "Other radio interface problem"; break;
    case  67: str = "Unsupported Base Station Capability"; break;
    case  96: str = "Encoding problem"; break;
    case  97: str = "Service origination denied"; break;
    case  98: str = "Service termination denied"; break;
    case  99: str = "Supplementary service not supported"; break;
    case 100: str = "Service not supported"; break;
    case 101: str = "Reserved"; break;
    case 102: str = "Missing expected parameter"; break;
    case 103: str = "Missing mandatory parameter"; break;
    case 104: str = "Unrecognized parameter value"; break;
    case 105: str = "Unexpected parameter value"; break;
    case 106: str = "User Data size error"; break;
    case 107: str = "Other general problems"; break;
    case 108: str = "Session not active"; break;
    default:
        if ((oct >= 7) && (oct <= 31)) { str = "Reserved, treat as Other network problem"; }
        else if ((oct >= 40) && (oct <= 47)) { str = "Reserved, treat as Other terminal problem"; }
        else if ((oct >= 48) && (oct <= 63)) { str = "Reserved, treat as SMS delivery postponed"; }
        else if ((oct >= 68) && (oct <= 95)) { str = "Reserved, treat as Other radio interface problem"; }
        else if ((oct >= 109) && (oct <= 223)) { str = "Reserved, treat as Other general problems"; }
        else { str = "Reserved for protocol extension, treat as Other general problems"; }
        break;
    }

    proto_tree_add_uint_format_value(tree, hf_ansi_637_trans_cause_codes_code, tvb, offset, 1,
        oct,
        "%s (%u)",
        str, oct);
}

static void
trans_param_bearer_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, guint len, guint32 offset, gchar *add_string _U_, int string_len _U_)
{
    tvbuff_t    *tele_tvb;

    /*
     * dissect the embedded teleservice data
     */
    tele_tvb = tvb_new_subset_length(tvb, offset, len);

    dissector_try_uint(tele_dissector_table, ansi_637_trans_tele_id, tele_tvb, pinfo, g_tree);
}

#define NUM_TRANS_PARAM (sizeof(ansi_trans_param_strings)/sizeof(value_string))
static gint ett_ansi_637_trans_param[NUM_TRANS_PARAM];
static void (*ansi_637_trans_param_fcn[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len) = {
    trans_param_tele_id,                /* Teleservice Identifier */
    trans_param_srvc_cat,               /* Service Category */
    trans_param_address,                /* Originating Address */
    trans_param_subaddress,             /* Originating Subaddress */
    trans_param_address,                /* Destination Address */
    trans_param_subaddress,             /* Destination Subaddress */
    trans_param_bearer_reply_opt,       /* Bearer Reply Option */
    trans_param_cause_codes,            /* Cause Codes */
    trans_param_bearer_data,            /* Bearer Data */
    NULL,                               /* NONE */
};

#define NUM_TRANS_MSG_TYPE (sizeof(ansi_trans_msg_type_strings)/sizeof(value_string))
static gint ett_ansi_637_trans_msg[NUM_TRANS_MSG_TYPE];

/* GENERIC IS-637 DISSECTOR FUNCTIONS */

static gboolean
dissect_ansi_637_tele_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset, gboolean *has_private_data_p)
{
    void        (*param_fcn)(tvbuff_t *, packet_info *, proto_tree *, guint, guint32, gboolean *) = NULL;
    guint8      oct;
    guint8      len;
    guint32     curr_offset;
    gint        ett_param_idx, idx;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str = NULL;


    curr_offset = *offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    str = try_val_to_str_idx_ext((guint32) oct, &ansi_tele_param_strings_ext, &idx);

    if (NULL == str)
    {
        return(FALSE);
    }

    ett_param_idx = ett_ansi_637_tele_param[idx];
    param_fcn = ansi_637_tele_param_fcn[idx];

    subtree =
        proto_tree_add_subtree(tree, tvb, curr_offset, -1,
            ett_param_idx, &item, str);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_subparam_id, tvb, curr_offset, 1, oct);

    curr_offset += 1;

    len = tvb_get_guint8(tvb, curr_offset);

    proto_item_set_len(item, (curr_offset - *offset) + len + 1);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_length, tvb, curr_offset, 1, len);

    curr_offset += 1;

    if (len > 0)
    {
        if (param_fcn == NULL)
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_637_no_tele_parameter_dissector, tvb, curr_offset, len);
        }
        else
        {
            /*
             * internal working (aka hack) for CMAS
             *
             * the 'User Data' subparameter is encoded in a special way for CMAS
             * (as per TIA-1149)
             *
             * if (Broadcast SMS && 'User Data') then call CMAS dissector
             */
            if ((ansi_637_trans_tele_id == INTERNAL_BROADCAST_TELE_ID) &&
                (oct == 0x01))
            {
                param_fcn = tele_param_user_data_cmas;
            }

            (*param_fcn)(tvb, pinfo, subtree, len, curr_offset, has_private_data_p);
        }

        curr_offset += len;
    }

    *offset = curr_offset;

    return(TRUE);
}

static void
dissect_ansi_637_tele_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ansi_637_tree, gboolean *has_private_data_p)
{
    guint8      len;
    guint32     curr_offset;

    curr_offset = 0;
    len = tvb_length(tvb);

    while ((len - curr_offset) > 0)
    {
        if (!dissect_ansi_637_tele_param(tvb, pinfo, ansi_637_tree, &curr_offset, has_private_data_p))
        {
            proto_tree_add_expert(ansi_637_tree, pinfo, &ei_ansi_637_unknown_tele_parameter, tvb, curr_offset, len - curr_offset);
            break;
        }
    }
}

static void
dissect_ansi_637_tele(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ansi_637_item;
    proto_tree  *ansi_637_tree = NULL;
    const gchar *str = NULL;
    guint32     value;
    gboolean    has_private_data = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
        g_tree = tree;

        value = pinfo->match_uint;

        /*
         * create the ansi_637 protocol tree
         */
        str = try_val_to_str(value, ansi_tele_id_strings);

        if (NULL == str)
        {
            switch (value)
            {
            case 1:
                str = "Reserved for maintenance";
                break;
            case 4102:
                str = "CDMA Service Category Programming Teleservice (SCPT)";
                break;
            case 4103:
                str = "CDMA Card Application Toolkit Protocol Teleservice (CATPT)";
                break;
            case 32513:
                str = "TDMA Cellular Messaging Teleservice";
                break;
            case 32514:
                str = "TDMA Cellular Paging Teleservice (CPT-136)";
                break;
            case 32515:
                str = "TDMA Over-the-Air Activation Teleservice (OATS)";
                break;
            case 32520:
                str = "TDMA System Assisted Mobile Positioning through Satellite (SAMPS)";
                break;
            case 32584:
                str = "TDMA Segmented System Assisted Mobile Positioning Service";
                break;
            default:
                if ((value >= 2) && (value <= 4095))
                {
                    str = "Reserved for assignment by TIA-41";
                }
                else if ((value >= 4104) && (value <= 4113))
                {
                    str = "Reserved for GSM1x Teleservice (CDMA)";
                }
                else if ((value >= 4114) && (value <= 32512))
                {
                    str = "Reserved for assignment by TIA-41";
                }
                else if ((value >= 32521) && (value <= 32575))
                {
                    str = "Reserved for assignment by this Standard for TDMA MS-based SMEs";
                }
                else if ((value >= 49152) && (value <= 65535))
                {
                    str = "Reserved for carrier specific teleservices";
                }
                else
                {
                    str = "Unrecognized Teleservice ID";
                }
                break;
            }
        }

        if (value == INTERNAL_BROADCAST_TELE_ID)
        {
            /*
             * supposed to be "Reserved for carrier specific teleservices"
             * but we are using it to key SMS Broadcast dissection where
             * there is no teleservice ID
             */
            ansi_637_item =
                proto_tree_add_protocol_format(tree, proto_ansi_637_tele, tvb, 0, -1,
                    "%s",
                    ansi_proto_name_tele);
        }
        else
        {
            ansi_637_item =
                proto_tree_add_protocol_format(tree, proto_ansi_637_tele, tvb, 0, -1,
                    "%s - %s (%u)",
                    ansi_proto_name_tele, str, pinfo->match_uint);
        }

        ansi_637_tree = proto_item_add_subtree(ansi_637_item, ett_ansi_637_tele);

        dissect_ansi_637_tele_message(tvb, pinfo, ansi_637_tree, &has_private_data);
    }
}

static gboolean
dissect_ansi_637_trans_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset)
{
    void        (*param_fcn)(tvbuff_t *, packet_info *, proto_tree *, guint, guint32, gchar *, int) = NULL;
    guint8      oct;
    guint8      len;
    guint32     curr_offset;
    gint        ett_param_idx, idx;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str;

    curr_offset = *offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    str = try_val_to_str_idx((guint32) oct, ansi_trans_param_strings, &idx);

    if (NULL == str)
    {
        return(FALSE);
    }

    ett_param_idx = ett_ansi_637_trans_param[idx];
    param_fcn = ansi_637_trans_param_fcn[idx];

    subtree = proto_tree_add_subtree(tree, tvb, curr_offset, -1, ett_param_idx, &item, str);

    proto_tree_add_uint(subtree, hf_ansi_637_trans_param_id, tvb, curr_offset, 1, oct);

    curr_offset += 1;

    len = tvb_get_guint8(tvb, curr_offset);

    proto_item_set_len(item, (curr_offset - *offset) + len + 1);

    proto_tree_add_uint(subtree, hf_ansi_637_trans_length, tvb, curr_offset, 1, len);

    curr_offset += 1;

    if (len > 0)
    {
        if (param_fcn == NULL)
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_637_no_trans_parameter_dissector, tvb, curr_offset, len);
        }
        else
        {
            gchar       *ansi_637_add_string;

            ansi_637_add_string = (gchar *) wmem_alloc(wmem_packet_scope(), 1024);
            ansi_637_add_string[0] = '\0';
            (*param_fcn)(tvb, pinfo, subtree, len, curr_offset, ansi_637_add_string, 1024);

            if (ansi_637_add_string[0] != '\0')
            {
                proto_item_append_text(item, "%s", ansi_637_add_string);
            }
        }

        curr_offset += len;
    }

    *offset = curr_offset;

    return(TRUE);
}


static void
dissect_ansi_637_trans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ansi_637_item;
    proto_tree  *ansi_637_tree = NULL;
    guint32     curr_offset;
    gint        idx;
    const gchar *str = NULL;
    guint8      oct;
    guint8      len;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
        g_tree = tree;

        /*
         * reset the teleservice ID for each dissection
         */
        ansi_637_trans_tele_id = 0;

        /*
         * create the ansi_637 protocol tree
         */
        oct = tvb_get_guint8(tvb, 0);

        str = try_val_to_str_idx(oct, ansi_trans_msg_type_strings, &idx);

        if (NULL == str)
        {
            ansi_637_item =
                proto_tree_add_protocol_format(tree, proto_ansi_637_trans, tvb, 0, -1,
                    "%s - Unrecognized Transport Layer Message Type (%u)",
                    ansi_proto_name_trans, oct);

            ansi_637_tree = proto_item_add_subtree(ansi_637_item, ett_ansi_637_trans);
        }
        else
        {
            ansi_637_item =
                proto_tree_add_protocol_format(tree, proto_ansi_637_trans, tvb, 0, -1,
                    "%s - %s",
                    ansi_proto_name_trans, str);

            ansi_637_tree = proto_item_add_subtree(ansi_637_item, ett_ansi_637_trans_msg[idx]);

            if (oct == ANSI_TRANS_MSG_TYPE_BROADCAST)
            {
                /*
                 * there is no teleservice ID for Broadcast but we want the
                 * bearer data to be dissected
                 *
                 * using a reserved value to key dissector port
                 */
                ansi_637_trans_tele_id = INTERNAL_BROADCAST_TELE_ID;

                col_append_str(pinfo->cinfo, COL_INFO, "(BROADCAST)");
            }
        }

        curr_offset = 1;

        len = tvb_length(tvb);

        while ((len - curr_offset) > 0)
        {
            if (!dissect_ansi_637_trans_param(tvb, pinfo, ansi_637_tree, &curr_offset))
            {
                proto_tree_add_expert(ansi_637_tree, pinfo, &ei_ansi_637_unknown_trans_parameter, tvb, curr_offset, len - curr_offset);
                break;
            }
        }
    }
}


/* Dissect SMS embedded in SIP */
static void
dissect_ansi_637_trans_app(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "/");
    col_set_fence(pinfo->cinfo, COL_INFO);
    dissect_ansi_637_trans(tvb, pinfo, tree);
}


/* Register the protocol with Wireshark */
void
proto_register_ansi_637(void)
{
    guint               i;

    /* Setup list of header fields */
    static hf_register_info hf_trans[] = {
        { &hf_ansi_637_trans_param_id,
            { "Transport Param ID", "ansi_637_trans.param_id",
            FT_UINT8, BASE_DEC, VALS(ansi_trans_param_strings), 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_length,
            { "Length", "ansi_637_trans.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_bin_addr,
            { "Binary Address", "ansi_637_trans.bin_addr",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_tele_id,
            { "Teleservice ID", "ansi_637_trans.tele_id",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_srvc_cat,
            { "Service Category", "ansi_637_trans.srvc_cat",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_addr_param_digit_mode,
            { "Digit Mode", "ansi_637_trans.addr_param.digit_mode",
            FT_BOOLEAN, 8, TFS(&tfs_digit_mode_8bit_4bit), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_addr_param_number_mode,
            { "Number Mode", "ansi_637_trans.addr_param.number_mode",
            FT_BOOLEAN, 8, TFS(&tfs_number_mode_data_ansi_t1), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_addr_param_ton,
            { "Type of Number", "ansi_637_trans.addr_param.ton",
            FT_UINT8, BASE_DEC, NULL, 0x38,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_addr_param_plan,
            { "Numbering Plan", "ansi_637_trans.addr_param.plan",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_addr_param_num_fields,
            { "Number of fields", "ansi_637_trans.addr_param.num_fields",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_addr_param_number,
            { "Number", "ansi_637_trans.addr_param.number",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_subaddr_type,
            { "Type", "ansi_637_trans.subaddr.type",
            FT_UINT16, BASE_DEC, NULL, 0xe000,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_subaddr_odd_even_ind,
            { "Odd/Even Indicator", "ansi_637_trans.subaddr.odd_even_ind",
            FT_UINT16, BASE_DEC, VALS(ansi_trans_subaddr_odd_even_ind_strings), 0x1000,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_subaddr_num_fields,
            { "Number of fields", "ansi_637_trans.subaddr.num_fields",
            FT_UINT16, BASE_DEC, NULL, 0x0ff0,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_bearer_reply_seq_num,
            { "Reply Sequence Number", "ansi_637_trans.bearer_reply.seq_num",
            FT_UINT8, BASE_DEC, NULL, 0xfc,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_cause_codes_seq_num,
            { "Reply Sequence Number", "ansi_637_trans.cause_codes.seq_num",
            FT_UINT8, BASE_DEC, NULL, 0xfc,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_cause_codes_error_class,
            { "Error Class", "ansi_637_trans.cause_codes.error_class",
            FT_UINT8, BASE_DEC, VALS(trans_param_cause_codes_error_class_strings), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_637_trans_cause_codes_code,
            { "Cause Code", "ansi_637_trans.cause_codes.code",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        }
    };

    static hf_register_info hf_tele[] = {
        { &hf_ansi_637_tele_msg_type,
            { "Message Type",
            "ansi_637_tele.msg_type",
            FT_UINT24, BASE_DEC, VALS(ansi_tele_msg_type_strings), 0xf00000,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_id,
            { "Message ID",
            "ansi_637_tele.msg_id",
            FT_UINT24, BASE_DEC, NULL, 0x0ffff0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_length,
            { "Length", "ansi_637_tele.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_status,
            { "Message Status",
            "ansi_637_tele.msg_status",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ansi_tele_msg_status_strings_ext, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_header_ind,
            { "Header Indicator",
            "ansi_637_tele.msg_header_ind",
            FT_UINT24, BASE_DEC, VALS(ansi_tele_msg_header_ind_strings), 0x000008,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_rsvd,
            { "Reserved",
            "ansi_637_tele.msg_rsvd",
            FT_UINT24, BASE_DEC, NULL, 0x000007,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_subparam_id,
            { "Teleservice Subparam ID", "ansi_637_tele.subparam_id",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ansi_tele_param_strings_ext, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_user_data_text,
            { "Encoded user data", "ansi_637_tele.user_data.text",
            FT_STRING, STR_UNICODE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_user_data_encoding,
            { "Encoding", "ansi_637_tele.user_data.encoding",
            FT_UINT16, BASE_DEC, NULL, 0xf800,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_user_data_message_type,
            { "Message Type (see TIA/EIA/IS-91)", "ansi_637_tele.user_data.message_type",
            FT_UINT16, BASE_DEC, NULL, 0x07f8,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_user_data_num_fields,
            { "Number of fields", "ansi_637_tele.user_data.num_fields",
            FT_UINT16, BASE_DEC, NULL, 0x07f8,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_response_code,
            { "Response Code", "ansi_637_tele.response_code",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_message_center_ts_year,
            { "Timestamp (Year)", "ansi_637_tele.message_center_ts.year",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_message_center_ts_month,
            { "Timestamp (Month)", "ansi_637_tele.message_center_ts.month",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_message_center_ts_day,
            { "Timestamp (Day)", "ansi_637_tele.message_center_ts.day",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_message_center_ts_hours,
            { "Timestamp (Hours)", "ansi_637_tele.message_center_ts.hours",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_message_center_ts_minutes,
            { "Timestamp (Minutes)", "ansi_637_tele.message_center_ts.minutes",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_message_center_ts_seconds,
            { "Timestamp (Seconds)", "ansi_637_tele.message_center_ts.seconds",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_ts_year,
            { "Timestamp (Year)", "ansi_637_tele.validity_period_ts.year",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_ts_month,
            { "Timestamp (Month)", "ansi_637_tele.validity_period_ts.month",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_ts_day,
            { "Timestamp (Day)", "ansi_637_tele.validity_period_ts.day",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_ts_hours,
            { "Timestamp (Hours)", "ansi_637_tele.validity_period_ts.hours",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_ts_minutes,
            { "Timestamp (Minutes)", "ansi_637_tele.validity_period_ts.minutes",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_ts_seconds,
            { "Timestamp (Seconds)", "ansi_637_tele.validity_period_ts.seconds",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_validity_period_relative_validity,
            { "Validity", "ansi_637_tele.validity_period_relative.validity",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_ts_year,
            { "Timestamp (Year)", "ansi_637_tele.deferred_del_ts.year",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_ts_month,
            { "Timestamp (Month)", "ansi_637_tele.deferred_del_ts.month",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_ts_day,
            { "Timestamp (Day)", "ansi_637_tele.deferred_del_ts.day",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_ts_hours,
            { "Timestamp (Hours)", "ansi_637_tele.deferred_del_ts.hours",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_ts_minutes,
            { "Timestamp (Minutes)", "ansi_637_tele.deferred_del_ts.minutes",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_ts_seconds,
            { "Timestamp (Seconds)", "ansi_637_tele.deferred_del_ts.seconds",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_deferred_del_relative,
            { "Delivery Time", "ansi_637_tele.deferred_del.relative",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_priority_indicator,
            { "Priority", "ansi_637_tele.priority_indicator",
            FT_UINT8, BASE_DEC, VALS(tele_param_priority_ind_strings), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_privacy_indicator,
            { "Privacy", "ansi_637_tele.privacy_indicator",
            FT_UINT8, BASE_DEC, VALS(tele_param_privacy_ind_strings), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_reply_option_user_ack_req,
            { "User Acknowledgement Requested", "ansi_637_tele.reply_option.user_ack_req",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_reply_option_dak_req,
            { "Delivery Acknowledgement Requested", "ansi_637_tele.reply_option.dak_req",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_reply_option_read_ack_req,
            { "Read Acknowledgement Requested", "ansi_637_tele.reply_option.read_ack_req",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_reply_option_report_req,
            { "Delivery/Submit Report Requested", "ansi_637_tele.reply_option.report_req",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_num_messages,
            { "Number of voice mail messages", "ansi_637_tele.num_messages.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_alert_msg_delivery_priority,
            { "Privacy", "ansi_637_tele.alert_msg_delivery.priority",
            FT_UINT8, BASE_DEC, VALS(tele_param_alert_priority_strings), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_language,
            { "Language", "ansi_637_tele.language",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cb_num_digit_mode,
            { "Digit Mode", "ansi_637_tele.cb_num.digit_mode",
            FT_BOOLEAN, 8, TFS(&tfs_digit_mode_8bit_4bit), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cb_num_ton,
            { "Type of Number", "ansi_637_tele.cb_num.ton",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_num_type_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cb_num_plan,
            { "Numbering Plan", "ansi_637_tele.cb_num.plan",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_num_plan_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cb_num_num_fields,
            { "Number of fields", "ansi_637_tele.cb_num.num_fields",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cb_num_number,
            { "Call-Back Number", "ansi_637_tele.cb_num.number",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_display_mode,
            { "Message Display Mode", "ansi_637_tele.msg_display_mode",
            FT_UINT8, BASE_DEC, VALS(tele_param_msg_display_mode_strings), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_deposit_idx,
            { "Message Deposit Index", "ansi_637_tele.msg_deposit_idx",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_srvc_cat_prog_results_srvc_cat,
            { "Service Category", "ansi_637_tele.srvc_cat_prog_results.srvc_cat",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_srvc_cat_prog_results_result,
            { "Programming Result", "ansi_637_tele.srvc_cat_prog_results.result",
            FT_UINT8, BASE_DEC, VALS(tele_param_srvc_cat_prog_results_result_strings), 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_status_error_class,
            { "Error Class", "ansi_637_tele.msg_status.error_class",
            FT_UINT8, BASE_DEC, VALS(tele_param_msg_status_error_class_strings), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_msg_status_code,
            { "Message Status Code", "ansi_637_tele.msg_status.code",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_tp_failure_cause_value,
            { "GSM SMS TP-Failure Cause", "ansi_637_tele.tp_failure_cause.value",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_reserved_bits_8_generic,
            { "Reserved bit(s)", "ansi_637_tele.reserved",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_reserved_bits_8_03,
            { "Reserved bit(s)", "ansi_637_tele.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_637_reserved_bits_8_07,
            { "Reserved bit(s)", "ansi_637_tele.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_637_reserved_bits_8_0f,
            { "Reserved bit(s)", "ansi_637_tele.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_637_reserved_bits_8_3f,
            { "Reserved bit(s)", "ansi_637_tele.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_637_reserved_bits_8_7f,
            { "Reserved bit(s)", "ansi_637_tele.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_encoding,
            { "Encoding", "ansi_637_tele.cmas.encoding",
            FT_UINT16, BASE_DEC, NULL, 0xf800,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_num_fields,
            { "Number of fields", "ansi_637_tele.cmas.num_fields",
            FT_UINT16, BASE_DEC, NULL, 0x07f8,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_protocol_version,
            { "CMAE_protocol_version", "ansi_637_tele.cmas.protocol_version",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_record_type,
            { "E_RECORD_TYPE", "ansi_637_tele.cmas.record_type",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_record_len,
            { "E_RECORD_LENGTH", "ansi_637_tele.cmas.record_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_char_set,
            { "CMAE_char_set", "ansi_637_tele.cmas.char_set",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_category,
            { "CMAE_category", "ansi_637_tele.cmas.category",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_response_type,
            { "CMAE_response_type", "ansi_637_tele.cmas.response_type",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_severity,
            { "CMAE_severity", "ansi_637_tele.cmas.severity",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_urgency,
            { "CMAE_urgency", "ansi_637_tele.cmas.urgency",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_certainty,
            { "CMAE_certainty", "ansi_637_tele.cmas.certainty",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_identifier,
            { "CMAE_identifier", "ansi_637_tele.cmas.identifier",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_alert_handling,
            { "CMAE_alert_handling", "ansi_637_tele.cmas.alert_handling",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_expires_year,
            { "CMAE_expires (Year)", "ansi_637_tele.cmas.expires.year",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_expires_month,
            { "CMAE_expires (Month)", "ansi_637_tele.cmas.expires.month",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_expires_day,
            { "CMAE_expires (Day)", "ansi_637_tele.cmas.expires.day",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_expires_hours,
            { "CMAE_expires (Hours)", "ansi_637_tele.cmas.expires.hours",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_expires_minutes,
            { "CMAE_expires (Minutes)", "ansi_637_tele.cmas.expires.minutes",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_expires_seconds,
            { "CMAE_expires (Seconds)", "ansi_637_tele.cmas.expires.seconds",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_637_tele_cmas_language,
            { "CMAE_language", "ansi_637_tele.cmas.language",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_ansi_637_extraneous_data,
            { "ansi_637.extraneous_data", PI_PROTOCOL, PI_NOTE,
            "Extraneous Data - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_short_data,
            { "ansi_637.short_data", PI_PROTOCOL, PI_NOTE,
            "Short Data (?) - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_unexpected_length,
            { "ansi_637.unexpected_length", PI_PROTOCOL, PI_WARN,
            "Unexpected Data Length - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_unknown_encoding,
            { "ansi_637.unknown_format", PI_PROTOCOL, PI_NOTE,
            "Encoding Unknown/Unsupported - (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_failed_conversion,
            { "ansi_637.failed_conversion", PI_PROTOCOL, PI_WARN,
            "Failed iconv conversion - (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_unknown_cmas_record_type,
            { "ansi_637.unknown_cmas_record_type", PI_PROTOCOL, PI_WARN,
            "Unknown CMAS record type - (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_unknown_trans_parameter,
            { "ansi_637.unknown_trans_parameter", PI_PROTOCOL, PI_WARN,
            "Unknown transport layer parameter - (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_no_trans_parameter_dissector,
            { "ansi_637.no_trans_parameter_dissector", PI_PROTOCOL, PI_WARN,
            "No transport layer parameter dissector - (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_unknown_tele_parameter,
            { "ansi_637.unknown_tele_parameter", PI_PROTOCOL, PI_WARN,
            "Unknown teleservice layer parameter - (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_637_no_tele_parameter_dissector,
            { "ansi_637.no_tele_parameter_dissector", PI_PROTOCOL, PI_WARN,
            "No teleservice layer parameter dissector - (report to wireshark.org)",
            EXPFILL }
        }
    };

    expert_module_t     *expert_ansi_637;

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_PARAMS   4
    gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+NUM_TRANS_MSG_TYPE+NUM_TRANS_PARAM+NUM_CMAS_PARAM];

    memset((void *) ett, 0, sizeof(ett));

    ett[0] = &ett_ansi_637_tele;
    ett[1] = &ett_ansi_637_trans;
    ett[2] = &ett_ansi_637_header_ind;
    ett[3] = &ett_params;

    for (i=0; i < NUM_TELE_PARAM; i++)
    {
        ett_ansi_637_tele_param[i] = -1;
        ett[NUM_INDIVIDUAL_PARAMS+i] = &ett_ansi_637_tele_param[i];
    }

    for (i=0; i < NUM_TRANS_MSG_TYPE; i++)
    {
        ett_ansi_637_trans_msg[i] = -1;
        ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+i] = &ett_ansi_637_trans_msg[i];
    }

    for (i=0; i < NUM_TRANS_PARAM; i++)
    {
        ett_ansi_637_trans_param[i] = -1;
        ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+NUM_TRANS_MSG_TYPE+i] = &ett_ansi_637_trans_param[i];
    }

    for (i=0; i < NUM_CMAS_PARAM; i++)
    {
        ett_tia_1149_cmas_param[i] = -1;
        ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+NUM_TRANS_MSG_TYPE+NUM_TRANS_PARAM+i] = &ett_tia_1149_cmas_param[i];
    }

    /* Register the protocol name and description */
    proto_ansi_637_tele =
        proto_register_protocol(ansi_proto_name_tele, "ANSI IS-637-A Teleservice", "ansi_637_tele");

    proto_ansi_637_trans =
        proto_register_protocol(ansi_proto_name_trans, "ANSI IS-637-A Transport", "ansi_637_trans");

    ansi_637_tele_handle = register_dissector("ansi_637_tele", dissect_ansi_637_tele, proto_ansi_637_tele);
    ansi_637_trans_handle = register_dissector("ansi_637_trans", dissect_ansi_637_trans, proto_ansi_637_trans);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_637_tele, hf_tele, array_length(hf_tele));
    proto_register_field_array(proto_ansi_637_trans, hf_trans, array_length(hf_trans));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ansi_637 =
        expert_register_protocol(proto_ansi_637_trans);
    expert_register_field_array(expert_ansi_637, ei, array_length(ei));

    tele_dissector_table =
        register_dissector_table("ansi_637.tele_id",
            "ANSI IS-637-A Teleservice ID", FT_UINT8, BASE_DEC);
}


void
proto_reg_handoff_ansi_637(void)
{
    dissector_handle_t  ansi_637_trans_app_handle;
    guint               i;

    ansi_637_trans_app_handle = create_dissector_handle(dissect_ansi_637_trans_app, proto_ansi_637_trans);

    /* Dissect messages embedded in SIP */
    dissector_add_string("media_type", "application/vnd.3gpp2.sms", ansi_637_trans_app_handle);

    /*
     * register for all known teleservices
     * '-1' is to stop before trailing '0' entry
     *
     * to add teleservices, modify 'ansi_tele_id_strings'
     */
    for (i=0; i < ((sizeof(ansi_tele_id_strings)/sizeof(value_string))-1); i++)
    {
        /*
         * ANSI MAP dissector will push out teleservice ids
         */
        dissector_add_uint("ansi_map.tele_id", ansi_tele_id_strings[i].value, ansi_637_tele_handle);

        /*
         * we will push out teleservice ids after Transport layer decode
         */
        dissector_add_uint("ansi_637.tele_id", ansi_tele_id_strings[i].value, ansi_637_tele_handle);
    }

    /*
     * internal implementation add this pseudo teleservice ID for handling broadcast SMS
     * (which don't have teleservice IDs)
     */
    dissector_add_uint("ansi_map.tele_id", INTERNAL_BROADCAST_TELE_ID, ansi_637_tele_handle);
    dissector_add_uint("ansi_637.tele_id", INTERNAL_BROADCAST_TELE_ID, ansi_637_tele_handle);

    /*
     * ANSI A-interface will push out transport layer data
     */
    dissector_add_uint("ansi_a.sms", 0, ansi_637_trans_handle);
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
