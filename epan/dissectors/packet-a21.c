/* packet-a21.c
 *
 * Routines for A21/s102 Message dissection
 * Copyright 2012, Joseph Chai <chaienzhao@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP2 A.S0008-C v4.0
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-e212.h"
#include "packet-a21.h"

void proto_register_a21(void);
void proto_reg_handoff_a21(void);

#define A21_PORT 23272
static dissector_handle_t a21_handle;
static dissector_handle_t gcsna_handle;

static int proto_a21;

static int hf_a21_message_type;
static int hf_a21_element_identifier;
static int hf_a21_element_length;
static int hf_a21_corr_id_corr_value;
static int hf_a21_mn_id_msid_value;
static int hf_a21_mn_id_odd_even_indicator;
static int hf_a21_mn_id_type_of_identity;
static int hf_a21_mn_id_esn;
static int hf_a21_mn_id_identity_digit_1;
static int hf_a21_gcsna_pdu_length;
static int hf_a21_gcsna_content;
static int hf_a21_reference_cell_id_cell;
static int hf_a21_reference_cell_id_sector;
static int hf_a21_mob_sub_info_record_id;
static int hf_a21_mob_sub_info_record_length;
static int hf_a21_mob_sub_info_record_content;
static int hf_a21_mob_sub_info_re_con_all_band_inc;
static int hf_a21_mob_sub_info_re_con_curr_band_sub;
static int hf_a21_mob_sub_info_re_band_class;
static int hf_a21_mob_sub_info_re_con_all_sub_band_inc;
static int hf_a21_mob_sub_info_re_sub_cls_len;
/*
static int hf_a21_mob_sub_info_re_con_band_class;
*/
static int hf_a21_auth_chall_para_rand_num_type;
static int hf_a21_auth_chall_para_rand_value;
static int hf_a21_service_option;
static int hf_a21_gcsna_status_reserved;
static int hf_a21_gcsna_status_priority_incl;
static int hf_a21_gcsna_status_gec;
static int hf_a21_gcsna_status_status_incl;
static int hf_a21_gcsna_status;
static int hf_a21_gcsna_status_call_priority;
static int hf_a21_3G1X_parameters;
static int hf_a21_reserved;
static int hf_a21_msg_tran_ctrl_paging_msg;
static int hf_a21_msg_tran_ctrl_simul_xmit_with_next;
static int hf_a21_msg_tran_ctrl_ackrequired;
static int hf_a21_msg_tran_ctrl_3GXLogicalChannel;
static int hf_a21_msg_tran_ctrl_protocol_revision;
static int hf_a21_1x_lac_en_pdu;
static int hf_a21_pilot_list_num_of_pilots;
static int hf_a21_cause_value;
static int hf_a21_mscid_market_id;
static int hf_a21_mscid_switch_number;
static int hf_a21_event;
static int hf_a21_additional_event_info;
static int hf_a21_allowed_forward_link_message;
static int hf_a21_channel_record_length;
static int hf_a21_ch_rec_sys_type;
static int hf_a21_ch_rec_band_class;
static int hf_a21_ch_rec_ch_num;

static int hf_a21_cell_id_info;
static int hf_a21_msc_id;
static int hf_a21_cell_id;
static int hf_a21_sector;
static int hf_a21_hrpd_sector_id_len;
static int hf_a21_ch_hrpd_sector_id;
static int hf_a21_ch_reference_pilot;
static int hf_a21_ch_pilot_pn;
static int hf_a21_ch_pilot_pn_phase;
static int hf_a21_ch_pilot_strength;
static int hf_a21_ch_pilot_ow_delay_flag;
static int hf_a21_ch_pilot_ow_delay;
static int hf_a21_sc0;
static int hf_a21_sc1;
static int hf_a21_sc2;
static int hf_a21_sc3;
static int hf_a21_sc4;
static int hf_a21_sc5;
static int hf_a21_sc6;
static int hf_a21_sc7;

static int ett_a21;
static int ett_a21_ie;
static int ett_a21_corr_id;
static int ett_a21_record_content;
static int ett_a21_pilot_list;
static int ett_a21_cr;
static int ett_a21_band_class;

static expert_field ei_a21_ie_data_not_dissected_yet;

static const value_string a21_message_type_vals[] = {
	{0x01, "A21-1x Air Interface Signalling"},	/* 01H */
	{0x02, "A21-Ack"},				/* 02H */
	{0x03, "A21-1x Parameters"},			/* 03H */
	{0x04, "A21-Event Notification"},		/* 04H */
	{0x05, "A21-1x Parameters Request"},		/* 05H */
	{0x06, "A21-Service Request"},			/* 06H */
	{0x07, "A21-Service Response"},			/* 07H */
	{0x08, "A21-Radio Update Request"},		/* 08H */
	{0x09, "A21-Radio Update Response"},		/* 09H */
	{0,    NULL}
};

#define A21_IEI_1X_LAC_ENCAPSULATED_PDU			0x01	/* 01H */
#define A21_IEI_A21_1X_PARAMETERS			0x02	/* 02H */
#define A21_IEI_PILOT_LIST				0x03	/* 03H */
#define A21_IEI_CORRELATION_ID				0x04	/* 04H */
#define A21_IEI_MOBILE_IDENTITY				0x05	/* 05H */
#define A21_IEI_AUTHENTICATION_CHALLENGE_PARAMETER	0x06	/* 06H */
#define A21_IEI_A21_1X_MESSAGE_TRANSMISSION_CONTROL	0x07	/* 07H */
#define A21_IEI_A21_CAUSE				0x08	/* 08H */
#define A21_IEI_A21_EVENT				0x09	/* 09H */
#define A21_IEI_SERVICE_OPTION				0x0A	/* 0AH */
#define A21_IEI_A21_MOBILE_SUBSCRIPTION_INFORMATION	0x0B	/* 0BH */
#define A21_IEI_GCSNA_STATUS				0x0C	/* 0CH */
#define A21_IEI_GCSNA_PDU				0xC0	/* C0H */
#define A21_IEI_REFERENCE_CELL_ID			0x0D	/* 0DH */
/*(Reserved range of IEIs for S102)				30H-3FH */



static void
dissect_a21_correlation_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;
	proto_item *tc;
	proto_tree *corr_tree;
	uint32_t corr_id;

	corr_tree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_a21_corr_id, &tc, "A21 Correlation ID");

	proto_tree_add_item(corr_tree, hf_a21_element_identifier, tvb, offset,  1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(corr_tree, hf_a21_element_length, tvb, offset,  1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item_ret_uint(corr_tree, hf_a21_corr_id_corr_value, tvb, offset,  4, ENC_BIG_ENDIAN, &corr_id);
	proto_item_append_text(tc, " %u", corr_id);
	/* offset += 4; */

}

static const value_string a21_mn_id_type_of_identity_vals[] = {
	{ 0,  "No Identity Code" },
	{ 1,  "MEID" },
	{ 5,  "ESN" },
	{ 6,  "IMSI" },
	{ 0,  NULL }
};

/* 5.2.4.8 Mobile Identity (MN ID) */
static void
dissect_a21_mobile_identity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_)
{
	int offset = 0;
	unsigned identity_type;
	const char *imsi_str;

	if (tree == NULL)
		return;

	identity_type = tvb_get_uint8(tvb, offset) & 0x07;
	proto_tree_add_item(tree, hf_a21_mn_id_type_of_identity, tvb, offset, 1, ENC_BIG_ENDIAN);

	switch (identity_type) {
	case 0:
		/* No Identity Code */
		proto_tree_add_item(tree, hf_a21_mn_id_msid_value, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* offset++; */
		break;
	case 1:
		/* MEID */
		proto_tree_add_item(tree, hf_a21_mn_id_odd_even_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* offset++; */
		break;
	case 5:
		/* ESN */
		proto_tree_add_item(tree, hf_a21_mn_id_odd_even_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_a21_mn_id_identity_digit_1, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_a21_mn_id_esn, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* offset++; */
		break;
	case 6:
		/* IMSI */
		proto_tree_add_item(tree, hf_a21_mn_id_odd_even_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);

		imsi_str = dissect_e212_imsi(tvb, pinfo, tree,  offset, length, true);
		proto_item_append_text(item, "%s", imsi_str);

		break;
	}


}

static void
dissect_a21_1x_message_transmission_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;
	if (tree == NULL)
		return;
	proto_tree_add_item(tree, hf_a21_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_msg_tran_ctrl_paging_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_msg_tran_ctrl_simul_xmit_with_next, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_msg_tran_ctrl_ackrequired, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_msg_tran_ctrl_3GXLogicalChannel, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_a21_msg_tran_ctrl_protocol_revision, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* offset++; */
}

static void
dissect_a21_1x_lac_encapsulated_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;
	proto_tree_add_item(tree, hf_a21_1x_lac_en_pdu, tvb, offset, 3, ENC_BIG_ENDIAN);
	/* offset += 3; */

}

/* 5.2.4.5 A21 1x Parameters */
static void
dissect_a21_1x_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_)
{
	proto_tree_add_item(tree, hf_a21_3G1X_parameters, tvb, 0,length, ENC_NA);
}

/*
 * 6.4.1.12 Pilot List
 * This IE contains the 1xRTT Pilot List passed to the MME from the eNodeB.
 * It is included by the MME whenever the MME receives the 1xRTT Pilot List from the eNodeB.
 * Details of format and contents of this IE are specified in 3GPP2 A.S0008-D and 3GPP2 A.S0009-D .
 */

 /* a21/S102 Channel Record Cell ID Info */
static const value_string a21_ch_cellid_info_values[] = {
    { 0x00,    "Cell Identifier field is not included - pilot: actual 1x pilot" },
    { 0x01,    "1x Cell Identifier field is included - pilot: actual 1x pilot" },
    { 0x02,    "1x Cell Identifier field is included - pilot: estimated 1x pilot" },
    { 0x03,    "1x Cell Identifier field is included - pilot: actual HRPD pilot" },
    { 0x04,    "HRPD Sector Identifier field is included - pilot: actual HRPD pilot" },
    { 0x05,    "Only an HRPD Sector Identifier field is included" },
    { 0x06,    "Only an actual HRPD pilot is included" },
    { 0x07,    "Only a 1x Cell Identifier is included" },
    { 0, NULL }
};

/* Pilot One Way Delay flag */
/* A.S0008-C p. 428 */
static const value_string a21_ch_pilot_ow_delay_values[] = {
    {0x00, "Not Included"},
    {0x01, "Included"},
    {0x00, NULL}
};

/* Pilot List System Type */
/* C.S0024-B p. 1493 */
static const value_string s102_ch_pilot_system_type_values[] = {
    {0x00, "ChannelNumber field specifies forward CDMA channel and Reverse CDMA channel that are FDD- paired."},
    {0x01, "System compliant to 3GPP2 C.S0002 Physical Layer Standard for cdma2000 Spread Spectrum Systems"},
    {0x02, "ChannelNumber field specifies only the forward CDMA channel."},
    {0x00, NULL}
};

/* S102 Current Band Class */
static const value_string a21_band_class_values[] = {
    { 0x00,    "800 MHz" },
    { 0x01,    "1900 MHz" },
    { 0x02,    "TACS" },
    { 0x03,    "JTACS" },
    { 0x04,    "Korean PCS" },
    { 0x05,    "450 MHz" },
    { 0x06,    "2 GHz" },
    { 0x07,    "Upper 700 MHz" },
    { 0x08,    "1800 MHz" },
    { 0x09,    "900 MHz" },
    { 0x0a,    "Secondary 800" },
    { 0x0b,    "400 MHz European PAMR" },
    { 0x0c,    "800 MHz PAMR" },
    { 0x0d,    "2.5 GHz IMT-2000 Extension" },
    { 0x0e,    "US PCS 1.9GHz" },
    { 0x0f,    "AWS" },
    { 0x10,    "US 2.5GHz" },
    { 0x11,    "US 2.5GHz Forward Link Only" },
    { 0x12,    "700 MHz Public Safety" },
    { 0x13,    "Lower 700 MHz" },
    { 0x14,    "L-Band" },
    { 0, NULL }
};

#if 0
static value_string_ext a21_band_class_values_ext = VALUE_STRING_EXT_INIT(a21_band_class_values);
#endif

static void
dissect_a21_pilot_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	proto_tree *sub_tree, *cr_tree;
	proto_item* ti;
	int offset = 0,start_offset;
	uint32_t num, ch_rec_len, i, cell_id_info, hrpd_len, reference_pilot, pilot_ow_delay_flag;

	proto_tree_add_item_ret_uint(tree, hf_a21_pilot_list_num_of_pilots, tvb, offset, 1, ENC_BIG_ENDIAN, &num);
	offset++;
	for (i = 0; i < num; i++){
		start_offset = offset;
		sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_a21_pilot_list, &ti, "Pilot %u", i+1);
		proto_tree_add_item_ret_uint(sub_tree, hf_a21_channel_record_length, tvb, offset, 1, ENC_BIG_ENDIAN, &ch_rec_len);
		offset++;
		/* Channel Record
		 * This field contains a channel record as defined in 3GPP2: C.S0024-B v1.0. The
		 * information contained in a channel record include the system
		 * type, band class, and channel number
		*/
		cr_tree = proto_tree_add_subtree(sub_tree, tvb, offset, ch_rec_len, ett_a21_cr, &ti, "Channel Record");

		/* SystemType len = 8 bit */
		proto_tree_add_item(cr_tree, hf_a21_ch_rec_sys_type, tvb, offset, 1, ENC_BIG_ENDIAN);

		/* BandClass len = 5 bit */
		proto_tree_add_item(cr_tree, hf_a21_ch_rec_band_class, tvb, offset+1, 1, ENC_BIG_ENDIAN);

		/* ChannelNumber len = 11 bit */
		proto_tree_add_item(cr_tree, hf_a21_ch_rec_ch_num, tvb, offset+1, 2, ENC_BIG_ENDIAN);


		offset += ch_rec_len;
		/* Cell ID Info */
		proto_tree_add_item_ret_uint(sub_tree, hf_a21_cell_id_info, tvb, offset, 1, ENC_BIG_ENDIAN, &cell_id_info);
		offset++;
		switch (cell_id_info)
		{
		case 1:
		case 2:
		case 3:
		case 7:
			/* Next Info: MSCID - 1x Cell - Sector*/
			proto_tree_add_item(sub_tree, hf_a21_msc_id, tvb, offset, 3, ENC_BIG_ENDIAN);
			offset += 3;

			proto_tree_add_item(sub_tree, hf_a21_cell_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(sub_tree, hf_a21_sector, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case 4:
		case 5:
		case 6:
			/* Next Info: HRPD Sector Identifier */
			proto_tree_add_item_ret_uint(sub_tree, hf_a21_hrpd_sector_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &hrpd_len);
			offset += 1;
			proto_tree_add_item(sub_tree, hf_a21_ch_hrpd_sector_id, tvb, offset, hrpd_len, ENC_NA);

			offset += hrpd_len;
			break;
		default:
			break;
		}
		/* reference pilot flag */
		proto_tree_add_item_ret_uint(sub_tree, hf_a21_ch_reference_pilot, tvb, offset, 1, ENC_BIG_ENDIAN, &reference_pilot);

		if (reference_pilot)
		{
			/* Reference Pilot PN */
			proto_tree_add_item(sub_tree, hf_a21_ch_pilot_pn, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
		else
		{
			/* Reference Pilot PN Phase*/
			proto_tree_add_item(sub_tree, hf_a21_ch_pilot_pn_phase, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
		offset += 2;

		/* Pilot one way delay flag */
		proto_tree_add_item_ret_uint(sub_tree, hf_a21_ch_pilot_ow_delay_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &pilot_ow_delay_flag);

		/* Pilot Strength */
		proto_tree_add_item(sub_tree, hf_a21_ch_pilot_strength, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		/* Pilot one way delay */
		if (pilot_ow_delay_flag)
		{
			proto_tree_add_item(sub_tree, hf_a21_ch_pilot_ow_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}

		proto_item_set_len(ti, offset - start_offset);

	}
}

static const range_string a21_random_number_type_rvals[] = {
	{0x00, 0x00, "Reserved"},
	{0x01, 0x01, "RAND"},
	{0x02, 0x0F, "Reserved"},
	{0, 0,   NULL}
};

static void
dissect_a21_authentication_challenge_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;
	unsigned type;

	if (tree == NULL)
		return;
	type = tvb_get_uint8(tvb, offset) & 0x0f;
	proto_tree_add_item(tree, hf_a21_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_auth_chall_para_rand_num_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	switch (type) {
	case 1:
		proto_tree_add_item(tree, hf_a21_auth_chall_para_rand_value, tvb, offset, 4, ENC_BIG_ENDIAN);
		/*offset += 4;*/
		break;
	}

}

/* A.S0008-C_v1.0_070801 5.2.4.14 A21 Mobile Subscription Information */

static const value_string a21_record_identifier_vals[] = {
	{0x00, "Band Class/Band Subclass Record"},
	/* All other values are reserved */
	{0,    NULL}
};


static void
dissect_a21_mobile_subscription_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_)
{
	int offset = 0, start_offset, rec_end_offset;
	int i = 0, j = 0;
	uint8_t record_id, band_class;
	uint16_t record_len = 0;
	proto_tree *record_tree, *band_tree;
	proto_item* ti;
	uint32_t rec_len, sub_cls_len;

	static int * const flags[] = {
	    &hf_a21_sc7,
	    &hf_a21_sc6,
	    &hf_a21_sc5,
	    &hf_a21_sc4,
	    &hf_a21_sc3,
	    &hf_a21_sc2,
	    &hf_a21_sc1,
	    &hf_a21_sc0,
	    NULL
	};

	if (tree == NULL)
		return;
	while (offset<length) {
		record_id  = tvb_get_uint8(tvb, offset);
		record_len = tvb_get_uint8(tvb, offset+1);

		record_tree = proto_tree_add_subtree_format(tree, tvb, offset+2, record_len,
								ett_a21_record_content, NULL, "Record %u",i+1);

		proto_tree_add_item(record_tree, hf_a21_mob_sub_info_record_id, tvb, offset,  1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item_ret_uint(record_tree, hf_a21_mob_sub_info_record_length, tvb, offset,  1, ENC_BIG_ENDIAN, &rec_len);
		offset++;
		rec_end_offset = offset + rec_len;

		if (record_id == 0) {
			/* All Band Classes Included*/
			proto_tree_add_item(record_tree, hf_a21_mob_sub_info_re_con_all_band_inc, tvb, offset,  1, ENC_BIG_ENDIAN);
			/* Current Band Subclass */
			proto_tree_add_item(record_tree, hf_a21_mob_sub_info_re_con_curr_band_sub, tvb, offset,  1, ENC_BIG_ENDIAN);
			offset++;
			while (offset < rec_end_offset) {
				j++;
				start_offset = offset;
				band_class = tvb_get_uint8(tvb, offset);
				band_tree = proto_tree_add_subtree_format(record_tree, tvb, offset, -1,
					ett_a21_band_class, &ti, "Band Class %u - %s(%u)",
					j,
					val_to_str_const(band_class, a21_band_class_values, "Unknown"),
					band_class
				);

				/* Band Class */
				proto_tree_add_item(band_tree, hf_a21_mob_sub_info_re_band_class, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				/* All Band Subclasses Included | Reserved |Band Class 1 Subclass Length Octet 7 */
				proto_tree_add_item(band_tree, hf_a21_mob_sub_info_re_con_all_sub_band_inc, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item_ret_uint(band_tree, hf_a21_mob_sub_info_re_sub_cls_len, tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cls_len);
				offset++;
				if (sub_cls_len > 0) {
					proto_tree_add_bitmask_list(band_tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
				}
				offset += sub_cls_len;
				proto_item_set_len(ti, offset - start_offset);
			}
		} else {
			proto_tree_add_item(record_tree, hf_a21_mob_sub_info_record_content, tvb, offset,  record_len, ENC_NA);
			offset += record_len;
		}
	}
}

static const value_string a21_gcsna_status_vals[] = {
	{0x01, "Handoff successful"},
	{0x02, "Handoff failure"},
	/* All other values are reserved */
	{0,    NULL}
};


static void
dissect_a21_gcsna_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;
	uint8_t priority_incl, status_incl;

	if (tree == NULL)
		return;
	status_incl = tvb_get_uint8(tvb, offset) & 0x01;
	priority_incl = tvb_get_uint8(tvb, offset) & 0x04;

	proto_tree_add_item(tree, hf_a21_gcsna_status_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_gcsna_status_priority_incl, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_gcsna_status_gec, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_a21_gcsna_status_status_incl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (status_incl == 1) {
		proto_tree_add_item(tree, hf_a21_gcsna_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (priority_incl == 1) {
		proto_tree_add_item(tree, hf_a21_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_a21_gcsna_status_call_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}

/* 5.2.4.16 GCSNA PDU */
static void
dissect_a21_gcsna_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_a21_gcsna_content, tvb, offset, length, ENC_NA);
	if (gcsna_handle) {
		tvbuff_t *new_tvb;
		new_tvb	= tvb_new_subset_length(tvb, offset, length);
		/* call the dissector with the parent (top)tree */
		call_dissector(gcsna_handle, new_tvb, pinfo, top_tree);
	}

}

/* 5.2.4.17 Reference Cell ID */
static void
dissect_a21_reference_cell_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;

	if (tree == NULL)
		return;
	proto_tree_add_item(tree, hf_a21_mscid_market_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_a21_mscid_switch_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_a21_reference_cell_id_cell, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_a21_reference_cell_id_sector, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* offset++; */

}

static const value_string a21_cause_vals[] = {
	{0x00, "Unknown mobile"},
	{0x01, "Unknown cell identifier(s)"},
	{0x02, "Tunneling of 1x messages not available"},
	{0x03, "Resources not available"},
	{0x04, "A21 context for this MS/AT may be released"},
	{0x05, "Airlink lost"},
	{0x06, "Abort Handoff from HRPD to 1x"},
	{0x07, "Unspecified"},
	{0x08, "Rejection"},
	{0x09, "Already Paging"},
	{0x0A, "Abort handoff from LTE to 1x"},
	{0x0B, "Version not supported"},
	/* All other values are reserved */
	{0,    NULL}
};


static void
dissect_a21_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_a21_cause_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* offset++; */
}

static const value_string a21_event_vals[] = {
	{0x00, "MS/AT present in 1x"},
	{0x01, "MS/AT present in HRPD/Cancel Handoff"},
	{0x02, "1x Power Down"},
	{0x03, "HRPD Power Down/Connection Closed"},
	{0x04, "Handoff Rejected"},
	{0x05, "1x Registration"},
	{0x06, "Transmission of All 1x LAC Encapsulated PDUs Disabled"},
	{0x07, "Transmission of 1x LAC Encapsulated PDU(s) Enabled"},
	{0x08, "MS/AT no longer present in this AN/PCF"},
	{0x09, "MS/AT no longer present in this 1x BS"},
	{0x0A, "MS/AT Not Acquired"},
	{0x0B, "Redirection"},
	/* All other values are reserved */
	{0,    NULL}
};

static const value_string a21_additional_event_info_vals[] = {
	{0x00, "This field shall not be included"},
	{0x01, "This field shall not be included"},
	{0x02, "This field shall not be included"},
	{0x03, "This field shall not be included"},
	{0x04, "This field shall not be included"},
	{0x05, "This field shall not be included"},
	{0x06, "This field shall not be included"},
	{0x07, "This field shall contain the variable length AllowedForwardLinkMessages negotiated by the HRPD AN and the AT"},
	/* All other values, This field shall not be included */
	{0,    NULL}
};


static void
dissect_a21_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_)
{
	int offset = 0;
	uint8_t event_id;

	if (tree == NULL)
		return;
	event_id = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_a21_event, tvb, offset,  1, ENC_BIG_ENDIAN);
	proto_item_append_text(item, "%s", val_to_str_const(event_id, a21_event_vals, "Unknown"));
	offset++;
	if (length>1) {
		if (event_id == 7) {
			proto_tree_add_item(tree, hf_a21_allowed_forward_link_message, tvb, offset, 2, ENC_BIG_ENDIAN);
			/*offset += 2;*/
		}
		else {
			proto_tree_add_item(tree, hf_a21_additional_event_info, tvb, offset, 2, ENC_BIG_ENDIAN);
			/*offset += 2;*/
		}
	}


}

static const value_string a21_service_option_vals[] = {
	{0x003B, "HRPD Packet Data"},
	/*{0x59xx, "HRPD Packet Data with ReservationLabel where xx = [00-FFH] and contains the ReservationLabel"},*/
	{0,    NULL}
};


/* 5.2.4.13 Service Option */
static void
dissect_a21_service_option(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_a21_service_option, tvb, offset, 2, ENC_BIG_ENDIAN);
	/* offset += 2; */

}

static void
dissect_a21_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_a21_ie_data_not_dissected_yet, tvb, 0, length);
}

static const value_string a21_element_type_vals[] = {
	{0x01, "1x LAC Encapsulated PDU"},
	{0x02, "A21 1x Parameters"},
	{0x03, "Pilot List"},
	{0x04, "Correlation ID"},
	{0x05, "Mobile Identity (MN ID)"},
	{0x06, "Authentication Challenge Parameter (RAND)"},
	{0x07, "A21 1x Message Transmission Control"},
	{0x08, "A21 Cause"},
	{0x09, "A21 Event"},
	{0x0A, "Service Option"},
	{0x0B, "A21 Mobile Subscription Information"},
	{0x0C, "GCSNA Status"},
	{0x0D, "Reference Cell ID"},
	{0xC0, "GCSNA PDU"},
	{0,    NULL}
};


void
dissect_a21_ie_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree, proto_tree *tree, int offset, uint8_t message_type)
{
	uint8_t ie_type, length_len;
	uint16_t length = 0;
	tvbuff_t *ie_tvb;
	proto_tree *ie_tree;
	proto_item *ti;

	while (offset < (int)tvb_reported_length(tvb)) {
		ie_type = tvb_get_uint8(tvb, offset);
		if (ie_type == A21_IEI_GCSNA_PDU) {
			/* length of GCSNA PDU is 2 octets long */
			length_len = 2;
			length = tvb_get_ntohs(tvb, offset+1);
		} else {
			/* Octet 2-length */
			length_len = 1;
			length = tvb_get_uint8(tvb, offset+1);
		}

		ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1 + length_len + length, ett_a21_ie, &ti,
									"%s : ", val_to_str_const(ie_type, a21_element_type_vals, "Unknown"));

		/* Octet 1-element identifier */
		proto_tree_add_item(ie_tree, hf_a21_element_identifier, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(ie_tree, hf_a21_gcsna_pdu_length, tvb, offset, length_len, ENC_BIG_ENDIAN);
		offset = offset+length_len;

		ie_tvb = tvb_new_subset_remaining(tvb, offset);

		switch (ie_type) {
		case A21_IEI_1X_LAC_ENCAPSULATED_PDU:
			/* 5.2.4.4 1x LAC Encapsulated PDU */
			dissect_a21_1x_lac_encapsulated_pdu(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_A21_1X_PARAMETERS:
			/* 5.2.4.5 A21 1x Parameters */
			dissect_a21_1x_parameters(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_PILOT_LIST:
			/* 5.2.4.6 Pilot List */
			dissect_a21_pilot_list(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_CORRELATION_ID:
			/* 5.2.4.7 Correlation ID */
			dissect_a21_correlation_id(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_MOBILE_IDENTITY:
			/* 5.2.4.8 Mobile Identity (MN ID) */
			dissect_a21_mobile_identity(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_AUTHENTICATION_CHALLENGE_PARAMETER:
			/* 5.2.4.9 Authentication Challenge Parameter (RAND) */
			dissect_a21_authentication_challenge_parameter(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_A21_1X_MESSAGE_TRANSMISSION_CONTROL:
			/* 5.2.4.10 A21 1x Message Transmission Control */
			dissect_a21_1x_message_transmission_control(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_A21_CAUSE:
			/* 5.2.4.11 A21 Cause */
			dissect_a21_cause(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_A21_EVENT:
			/* 5.2.4.12 A21 Event */
			dissect_a21_event(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_SERVICE_OPTION:
			/* 5.2.4.13 Service Option */
			dissect_a21_service_option(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_A21_MOBILE_SUBSCRIPTION_INFORMATION:
			/* 5.2.4.14 A21 Mobile Subscription Information */
			dissect_a21_mobile_subscription_information(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_GCSNA_STATUS:
			/* 5.2.4.15 GCSNA Status */
			dissect_a21_gcsna_status(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_GCSNA_PDU:
			/* 5.2.4.16 GCSNA PDU */
			dissect_a21_gcsna_pdu(ie_tvb,pinfo, top_tree, ie_tree, ti, length, message_type);
			break;
		case A21_IEI_REFERENCE_CELL_ID:
			/* 5.2.4.17 Reference Cell ID */
			dissect_a21_reference_cell_id(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		default:
			dissect_a21_unknown(ie_tvb,pinfo, ie_tree, ti, length, message_type);
			break;
		}
		offset = offset + length;
	}
}


static int
dissect_a21(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint8_t message_type;
	int offset = 0;
	proto_item *ti, *tc;
	proto_tree *a21_tree, *corr_tree;
	uint32_t corr_id;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "A21");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Message header is 7 octet long
	 * Octet 1 consists of message type
	 * Octets 2-7 contain the Correlation Identifier.
	*/

	message_type = tvb_get_uint8(tvb, offset);
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_type, a21_message_type_vals, "Unknown"));

	ti = proto_tree_add_protocol_format(tree, proto_a21, tvb, 0, -1,
				      "A21 Protocol: %s",
				      val_to_str_const(message_type, a21_message_type_vals, "Unknown"));
	a21_tree = proto_item_add_subtree(ti, ett_a21);

	/* message type in Octet 1 */
	proto_tree_add_item(a21_tree, hf_a21_message_type, tvb, offset,  1, ENC_BIG_ENDIAN);
	offset++;
	/* Correlation Identifier in Octets 2-7 */
	corr_tree = proto_tree_add_subtree(a21_tree, tvb, offset, 6, ett_a21_corr_id, &tc, "A21 Correlation ID");

	proto_tree_add_item(corr_tree, hf_a21_element_identifier, tvb, offset,  1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(corr_tree, hf_a21_element_length, tvb, offset,  1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item_ret_uint(corr_tree, hf_a21_corr_id_corr_value, tvb, offset, 4, ENC_BIG_ENDIAN, &corr_id);
	proto_item_append_text(tc, " %u", corr_id);
	offset += 4;

	dissect_a21_ie_common(tvb, pinfo, tree, a21_tree, offset,  message_type);

	return tvb_captured_length(tvb);
}

void proto_register_a21(void)
{
	static hf_register_info hf_a21[] = {
		  { &hf_a21_message_type,
			 {"Message Type", "a21.message_type",
			  FT_UINT8, BASE_DEC, VALS(a21_message_type_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_element_identifier,
			 {"A21 Element Identifier", "a21.element_identifier",
			  FT_UINT8, BASE_DEC, VALS(a21_element_type_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_element_length,
			 {"Length", "a21.length",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_corr_id_corr_value,
			 {"Correlation Value", "a21.corr_id_corr_value",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mn_id_msid_value,
			 {"MSID Value", "a21.mn_id_msid_value",
			  FT_UINT8, BASE_DEC, NULL, 0xf8,
			  NULL, HFILL }
		  },
		  { &hf_a21_mn_id_identity_digit_1,
			 {"Identity Digit 1", "a21.mn_id_identity_digit_1",
			  FT_UINT8, BASE_DEC, NULL, 0x08,
			  NULL, HFILL }
		  },
		  { &hf_a21_mn_id_odd_even_indicator,
			 {"Odd/Even Indicator", "a21.mn_id_odd_even_indicator",
			  FT_UINT8, BASE_DEC, NULL, 0x08,
			  NULL, HFILL }
		  },
		  { &hf_a21_mn_id_type_of_identity,
			 {"Type of Identity", "a21.mn_id_type_of_identity",
			  FT_UINT8, BASE_DEC, VALS(a21_mn_id_type_of_identity_vals), 0x07,
			  NULL, HFILL }
		  },
		  { &hf_a21_mn_id_esn,
			 {"ESN", "a21.mn_id_esn",
			  FT_UINT8, BASE_DEC, NULL, 0x7f,
			  NULL, HFILL }
		  },
		  { &hf_a21_reserved,
			 {"Reserved", "a21.reserved",
			  FT_UINT8, BASE_DEC, NULL, 0xf0,
			  NULL, HFILL }
		  },
		  { &hf_a21_msg_tran_ctrl_paging_msg,
			 {"Paging Message", "a21.msg_tran_ctrl_paging_msg",
			  FT_UINT8, BASE_DEC, NULL, 0x08,
			  NULL, HFILL }
		  },
		  { &hf_a21_msg_tran_ctrl_simul_xmit_with_next,
			 {"Simul Xmit with Next", "a21.msg_tran_ctrl_simul_xmit_with_next",
			  FT_UINT8, BASE_DEC, NULL, 0x04,
			  NULL, HFILL }
		  },
		  { &hf_a21_msg_tran_ctrl_ackrequired,
			 {"AckRequired", "a21.msg_tran_ctrl_ackrequired",
			  FT_UINT8, BASE_DEC, NULL, 0x02,
			  NULL, HFILL }
		  },
		  { &hf_a21_msg_tran_ctrl_3GXLogicalChannel,
			 {"3GXLogicalChannel", "a21.msg_tran_ctrl_3GXLogicalChannel",
			  FT_UINT8, BASE_DEC, NULL, 0x01,
			  NULL, HFILL }
		  },
		  { &hf_a21_msg_tran_ctrl_protocol_revision,
			 {"ProtocolRevision", "a21.msg_tran_ctrl_protocol_revision",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_1x_lac_en_pdu,
			 {"1x LAC Encapsulated PDU", "a21.1x_lac_en_pdu",
			  FT_UINT24, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_pilot_list_num_of_pilots,
			 {"Number of Pilots", "a21.pilot_list_num_of_pilots",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_cause_value,
			 {"A21 Cause Value", "a21.cause_value",
			  FT_UINT8, BASE_DEC, VALS(a21_cause_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mscid_market_id,
			 {"Market ID", "a21.mscid_market_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mscid_switch_number,
			 {"Switch Number", "a21.mscid_switch_number",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_event,
			 {"Event", "a21.event",
			  FT_UINT8, BASE_DEC, VALS(a21_event_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_additional_event_info,
			 {"Additional Event Info", "a21.additional_event_info",
			  FT_UINT16, BASE_DEC, VALS(a21_additional_event_info_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_allowed_forward_link_message,
			 {"Allowed Forward Link Messages", "a21.allowed_forward_link_message",
			  FT_UINT16, BASE_DEC, VALS(a21_additional_event_info_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_pdu_length,
			 {"Length", "a21.gcsna_pdu_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_content,
			 {"GCSNA Content", "a21.gcsna_content",
			  FT_NONE, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_reference_cell_id_cell,
			 {"Cell", "a21.reference_cell_id_cell",
			  FT_UINT16, BASE_DEC, NULL, 0xfff0,
			  NULL, HFILL }
		  },
		  { &hf_a21_reference_cell_id_sector,
			 {"Sector", "a21.reference_cell_id_sector",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_record_id,
			 {"Record Identifier", "a21.mob_sub_info_record_id",
			  FT_UINT8, BASE_DEC, VALS(a21_record_identifier_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_record_length,
			 {"Record Length", "a21.mob_sub_info_record_length",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_record_content,
			 {"Record Content", "a21.mob_sub_info_record_content",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_re_con_all_band_inc,
			 {"All Band Classes Included", "a21.mob_sub_info_re_con_all_band_inc",
			  FT_UINT8, BASE_DEC, NULL, 0x80,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_re_con_curr_band_sub,
			 {"Current Band Subclass", "a21.mob_sub_info_re_con_curr_band_sub",
			  FT_UINT8, BASE_DEC, NULL, 0x7f,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_re_band_class,
			 {"Band Class", "a21.mob_sub_info_re_band_class",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_re_con_all_sub_band_inc,
			 {"All Band Subclasses Included", "a21.mob_sub_info_re_con_all_sub_band_inc",
			  FT_UINT8, BASE_DEC, NULL, 0x80,
			  NULL, HFILL }
		  },
		  { &hf_a21_mob_sub_info_re_sub_cls_len,
			 {"Subclass Length", "a21.mob_sub_info_re_sub_cls_len",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		  },
#if 0
		  { &hf_a21_mob_sub_info_re_con_band_class,
			 {"Band Class", "a21.mob_sub_info_re_con_band_class",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
#endif
		  { &hf_a21_auth_chall_para_rand_num_type,
			 {"Random Number Type", "a21.auth_chall_para_rand_num_type",
			  FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(a21_random_number_type_rvals), 0x0f,
			  NULL, HFILL }
		  },
		  { &hf_a21_auth_chall_para_rand_value,
			 {"RAND Value", "a21.auth_chall_para_rand_value",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_service_option,
			 {"Service Option", "a21.service_option",
			  FT_UINT16, BASE_DEC, VALS(a21_service_option_vals), 0x7f,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_status_reserved,
			 {"Reserved", "a21.gcsna_status_reserved",
			  FT_UINT8, BASE_DEC, NULL, 0xf8,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_status_priority_incl,
			 {"Priority Incl", "a21.gcsna_status_priority_incl",
			  FT_UINT8, BASE_DEC, NULL, 0x04,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_status_gec,
			 {"GEC", "a21.gcsna_status_gec",
			  FT_UINT8, BASE_DEC, NULL, 0x02,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_status_status_incl,
			 {"Status Incl", "a21.gcsna_status_status_incl",
			  FT_UINT8, BASE_DEC, NULL, 0x01,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_status,
			 {"Status", "a21.gcsna_status",
			  FT_UINT8, BASE_DEC, VALS(a21_gcsna_status_vals), 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_gcsna_status_call_priority,
			 {"Call Priority", "a21.gcsna_status_call_priority",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		  },
		  { &hf_a21_3G1X_parameters,
			 {"3G1X Parameters", "a21.3G1X_parameters",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_channel_record_length,
			 {"Channel Record Length", "a21.channel_record_length",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_ch_rec_sys_type,
		  { "System Type", "a21.ch_system_type",
		  FT_UINT8, BASE_HEX, VALS(s102_ch_pilot_system_type_values), 0x0,
		  NULL, HFILL }
		  },
		  { &hf_a21_ch_rec_band_class,
		      { "Band Class", "a21.ch_band_class",
		      FT_UINT8, BASE_DEC, VALS(a21_band_class_values), 0xf8,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_rec_ch_num,
		      { "Channel Number", "a21.ch_channel_number",
		      FT_UINT16, BASE_DEC, NULL, 0x07ff,
		      NULL, HFILL }
		  },

		  { &hf_a21_cell_id_info,
			 {"Cell ID Info", "a21.cell_id_info",
			  FT_UINT8, BASE_DEC, VALS(a21_ch_cellid_info_values), 0x07,
			  NULL, HFILL }
		  },
		  { &hf_a21_msc_id,
		      { "MSC ID", "a21.msc_id",
		      FT_UINT24, BASE_DEC, NULL, 0x0,
		      NULL, HFILL }
		  },
		  { &hf_a21_cell_id,
		      { "Cell ID", "a21.cell_id",
		      FT_UINT16, BASE_DEC, NULL, 0xfff0,
		      NULL, HFILL }
		  },
		  { &hf_a21_sector,
		      { "Sector", "a21.sector",
		      FT_UINT8, BASE_DEC, NULL, 0x0f,
		      NULL, HFILL }
		  },
		  { &hf_a21_hrpd_sector_id_len,
			 {"HRPD Sector id Length", "a21.hrpd_sector_id_len",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		  },
		  { &hf_a21_ch_hrpd_sector_id,
		      { "HRPD Sector id", "a21.hrpd_sector_id",
		      FT_UINT8, BASE_HEX, NULL, 0x0,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_reference_pilot,
		      { "Reference Pilot", "a21.ch_reference_pilot",
		      FT_UINT8, BASE_DEC, NULL, 0x80,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_pilot_pn,
		      { "Pilot PN", "a21.ch_pilot_pn",
		      FT_UINT16, BASE_DEC, NULL, 0x01ff,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_pilot_pn_phase,
		      { "Pilot PN Phase", "a21.ch_pilot_pn_phase",
		      FT_UINT16, BASE_DEC, NULL, 0x7fff,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_pilot_strength,
		      { "Pilot Strength", "a21.ch_pilot_strength",
		      FT_UINT8, BASE_DEC, NULL, 0x3f,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_pilot_ow_delay_flag,
		      { "Pilot OneWay Delay", "a21.ch_pilot_onew_delay",
		      FT_UINT8, BASE_DEC, VALS(a21_ch_pilot_ow_delay_values), 0x40,
		      NULL, HFILL }
		  },
		  { &hf_a21_ch_pilot_ow_delay,
		      { "Pilot OneWay Delay (units of 100ns)", "a21.ch_pilot_onew_delay_value",
		      FT_UINT16, BASE_DEC, NULL, 0x0,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc0,
		  { "SC0",   "a21.sc0",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc1,
		  { "SC1",   "a21.sc1",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc2,
		  { "SC2",   "a21.sc2",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc3,
		  { "SC3",   "a21.sc3",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc4,
		  { "SC4",   "a21.sc4",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc5,
		  { "SC5",   "a21.sc5",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc6,
		  { "SC6",   "a21.sc6",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
		      NULL, HFILL }
		  },
		  { &hf_a21_sc7,
		  { "SC7",   "a21.sc7",
		      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
		      NULL, HFILL }
		  },

	};
	/* Setup protocol subtree array */
	static int *ett_a21_array[] = {
		&ett_a21,
		&ett_a21_corr_id,
		&ett_a21_ie,
		&ett_a21_record_content,
		&ett_a21_pilot_list,
		&ett_a21_cr,
		&ett_a21_band_class
	};

	expert_module_t *expert_a21;

	static ei_register_info ei[] = {
		{ &ei_a21_ie_data_not_dissected_yet,
		  { "a21.ie_data_not_dissected_yet",
		    PI_PROTOCOL, PI_NOTE, "IE data not dissected yet", EXPFILL }},
	};

	proto_a21 = proto_register_protocol("A21 Protocol", "A21", "a21");
	proto_register_field_array(proto_a21, hf_a21, array_length(hf_a21));
	proto_register_subtree_array(ett_a21_array, array_length(ett_a21_array));
	expert_a21 = expert_register_protocol(proto_a21);
	expert_register_field_array(expert_a21, ei, array_length(ei));

	a21_handle = register_dissector("a21", dissect_a21, proto_a21);
}

void proto_reg_handoff_a21(void)
{
	gcsna_handle = find_dissector_add_dependency("gcsna", proto_a21);
	dissector_add_uint_with_preference("udp.port", A21_PORT, a21_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
