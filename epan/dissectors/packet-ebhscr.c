/* packet-ebhscr.c
 * Routines for EBHSCR dissection
 * Copyright 2019, Ana Pantar <ana.pantar@gmail.com> for Elektrobit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * For more information on this protocol see:
 * https://www.elektrobit.com/ebhscr
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>

void proto_reg_handoff_ebhscr(void);
void proto_register_ebhscr(void);

static int proto_ebhscr = -1;

static int hf_ebhscr_packet_header = -1;
static int hf_ebhscr_major_number = -1;
static int hf_ebhscr_slot = -1;
static int hf_ebhscr_channel = -1;
static int hf_ebhscr_status = -1;
static int hf_ebhscr_status_unused = -1;

static int hf_can_proto_type = -1;
static int hf_can_status_available = -1;
static int hf_can_LEC = -1;
static int hf_can_ERRP = -1;
static int hf_can_ERRW = -1;
static int hf_can_BOFF = -1;
static int hf_can_DLEC = -1;
static int hf_can_TEC = -1;
static int hf_can_REC = -1;
static int hf_can_CEL = -1;
static int hf_can_reserved_bytes = -1;

static int hf_eth_reserved_bytes = -1;
static int hf_eth_tx_trunc = -1;
static int hf_eth_trans_undrun = -1;
static int hf_eth_retrans_limit = -1;
static int hf_eth_late_collision = -1;
static int hf_eth_link_up_down = -1;
static int hf_eth_master_slave = -1;
static int hf_eth_fcs_unavailable = -1;
static int hf_eth_rsvd_bit = -1;
static int hf_eth_speed = -1;

static int hf_eth_crc_error = -1;
static int hf_eth_mii_foe = -1;
static int hf_eth_payload_foe = -1;
static int hf_eth_hdr_foe = -1;
static int hf_eth_rcv_dec_err = -1;
static int hf_eth_sym_error = -1;
static int hf_eth_jabber_event = -1;
static int hf_eth_pol_ch_event = -1;
static int hf_eth_fls_carrier_event = -1;
static int hf_eth_rx_trunc = -1;

static int hf_ts_time_offset_valid = -1;
static int hf_ts_last_offset_change_valid = -1;
static int hf_ts_nano_seconds_last_jump_valid = -1;
static int hf_ts_UTC_leap_seconds_valid = -1;
static int hf_ts_sync_state_valid = -1;
static int hf_ts_time_source = -1;

static int hf_ts_time_offset_ns = -1;
static int hf_ts_last_offset_ns = -1;
static int hf_ts_last_jump_ns = -1;
static int hf_ts_utc_leap_sec = -1;
static int hf_ts_sync_state = -1;

static int hf_dio_overflow_mon_unit = -1;
static int hf_dio_jump_occured = -1;
static int hf_dio_value_type = -1;
static int hf_dio_reserved_bytes = -1;

static int hf_ebhscr_version = -1;
static int hf_ebhscr_length = -1;
static int hf_ebhscr_start_timestamp = -1;
static int hf_ebhscr_stop_timestamp = -1;
static int hf_ebhscr_mjr_hdr = -1;
static int hf_ebhscr_mjr_hdr_unused = -1;

static gint ett_ebhscr = -1;
static gint ett_ebhscr_packet_header = -1;
static gint ett_ebhscr_status = -1;
static gint ett_ebhscr_mjr_hdr = -1;

static int * const can_status_bits[] = {
	&hf_can_proto_type,
	&hf_can_status_available,
	NULL
};

static int * const can_mjr_hdr_bits[] = {
	& hf_can_reserved_bytes,
	& hf_can_LEC,
	& hf_can_ERRP,
	& hf_can_ERRW,
	& hf_can_BOFF,
	& hf_can_DLEC,
	& hf_can_TEC,
	& hf_can_REC,
	& hf_can_CEL,
	NULL
};

static const value_string can_proto_type_strings[] = {
	{ 0,	"Classical CAN" },
	{ 1,	"CAN FD data frame" },
	{ 0, NULL },
};

static const value_string can_status_available_strings[] = {
	{ 0,	"CAN protocol status not available" },
	{ 1,	"CAN protocol status available" },
	{ 0, NULL },
};

static const val64_string can_last_err_code_strings[] = {
	{ 0,	"No Error" },
	{ 1,	"Stuff Error" },
	{ 2,	"Form Error" },
	{ 3,	"Ack Error" },
	{ 4,	"Bit1 Error" },
	{ 5,	"Bit0 Error" },
	{ 6,	"CRC Error" },
	{ 7,	"Reserved" },
	{ 0, NULL },
};

static const val64_string can_ERRP_strings[] = {
	{ 0,	"Error counters are below the error passive limit (128)" },
	{ 1,	"One of the error counters has reached the error passive limit (128)" },
	{ 0, NULL },
};

static const val64_string can_ERRW_strings[] = {
	{ 0,	"Error counters are below the error warning limit (96)" },
	{ 1,	"One of the error counters has reached the error warning limit (96)" },
	{ 0, NULL },
};
static const val64_string can_BOFF_strings[] = {
	{ 0,	"Not in Bus Off state" },
	{ 1,	"In Bus Off state." },
	{ 0, NULL },
};


static int * const  eth_rx_error_bits[] = {
	&hf_eth_crc_error,
	&hf_eth_mii_foe,
	&hf_eth_payload_foe,
	&hf_eth_hdr_foe,
	&hf_eth_rcv_dec_err,
	&hf_eth_sym_error,
	&hf_eth_jabber_event,
	&hf_eth_pol_ch_event,
	&hf_eth_fls_carrier_event,
	&hf_eth_rx_trunc,
	NULL
};

static int * const eth_mjr_hdr_bits[] = {
	&hf_eth_reserved_bytes,
	&hf_eth_tx_trunc,
	&hf_eth_trans_undrun,
	&hf_eth_retrans_limit,
	&hf_eth_late_collision,
	&hf_eth_link_up_down,
	&hf_eth_master_slave,
	&hf_eth_fcs_unavailable,
	&hf_eth_rsvd_bit,
	&hf_eth_speed,
	NULL
};

static const val64_string eth_link_strings[] = {
	{ 0,	"Link Down" },
	{ 1,	"Link Up" },
	{ 0, NULL },
};

static const val64_string eth_master_strings[] = {
	{ 0,	"Slave" },
	{ 1,	"Master" },
	{ 0, NULL },
};

static const val64_string eth_fcs_strings[] = {
	{ 0,	"FCS appended to payload" },
	{ 1,	"FCS not appended to payload." },
	{ 0, NULL },
};

static const val64_string eth_speed_strings[] = {
	{ 0,	"Speed 10M" },
	{ 1,	"Speed 100M" },
	{ 2,	"Speed 1000M" },
	{ 3,	"Speed 2.5G" },
	{ 4,	"Speed 5G" },
	{ 5,	"Speed 10G" },
	{ 6,	"Speed 25G" },
	{ 7,	"Speed 40G" },
	{ 8,	"Speed 100G" },
	{ 9,	"Reserved" },
	{ 10,	"Reserved" },
	{ 11,	"Reserved" },
	{ 12,	"Reserved" },
	{ 13,	"Reserved" },
	{ 14,	"Reserved" },
	{ 15,	"Speed unknown. This value can be used when the speed could not be detected." },
	{ 0, NULL },
};

static int * const ts_status_bits[] = {
	&hf_ts_time_offset_valid,
	&hf_ts_last_offset_change_valid,
	&hf_ts_nano_seconds_last_jump_valid,
	&hf_ts_UTC_leap_seconds_valid,
	&hf_ts_sync_state_valid,
	NULL
};

static const val64_string ts_time_source_strings[] = {
	{ 0x00,	"TimeSourceNone" },
	{ 0x01,	"TimeSourceEBTimesyncHard" },
	{ 0x02,	"TimeSourceXTSS" },
	{ 0x03,	"TimeSourcePTPHW" },
	{ 0x10,	"TimeSourcePTPSW" },
	{ 0x20,	"TimeSourceGPS" },
	{ 0x30,	"TimeSourceEBTimesyncSoft" },
	{ 0x40,	"TimeSourceCAN" },
	{ 0x50,	"TimeSourceEBVirt" },
	{ 0, NULL },
};
static const value_string ts_sync_state_strings[] = {
	{ 0,	"Free running" },
	{ 1,	"Locked to master" },
	{ 0, NULL },
};

static int * const dio_status_bits[] = {
	&hf_dio_overflow_mon_unit,
	&hf_dio_jump_occured,
	NULL
};

static int * const dio_mjr_hdr_bits[] = {
	&hf_dio_value_type,
	&hf_dio_reserved_bytes,
	NULL
};

static const val64_string dio_val_type_strings[] = {
	{ 0,	"Event triggered falling edge" },
	{ 1,	"Event triggered rising edge" },
	{ 0, NULL },
};

static expert_field ei_ebhscr_frame_header = EI_INIT;
static expert_field ei_ebhscr_err_status_flag = EI_INIT;
static expert_field ei_ebhscr_info_status_flag = EI_INIT;

static dissector_handle_t can_handle;
static dissector_handle_t can_fd_handle;
static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t ebhscr_user_handle;

static dissector_table_t subdissector_table;

#define EBHSCR_USER_FIRST 0X43
#define EBHSCR_USER_LAST 0X4F

#define ETHERNET_FRAME 0x50
#define NMEA_FRAME 0x51
#define TIME_STATE_FRAME 0x52
#define CAN_FRAME 0x53
#define DIO_FRAME 0x56
#define EBHSCR_HEADER_LENGTH 32

static int dissect_ebhscr_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, guint16 ebhscr_status,
								guint32 ebhscr_frame_length)
{
	guint16 can_proto_status, can_type;
	guint32 ebhscr_current_payload_length;
	tvbuff_t* next_tvb;
	proto_item *ti;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status, ett_ebhscr_status,
								can_status_bits, ENC_BIG_ENDIAN);

	can_proto_status = (ebhscr_status & 0x0002);
	if (can_proto_status) {
		proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
								can_mjr_hdr_bits, ENC_BIG_ENDIAN);
		expert_add_info(pinfo, ti, &ei_ebhscr_info_status_flag);
	}
	else {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	}

	/* received hdr only and no data */
	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;
	/* payload is CAN or CAN FD frame */
	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);

	can_type = (ebhscr_status & 0x0001);

	if (can_type) {
		call_dissector(can_fd_handle, next_tvb, pinfo, tree);
	}
	else {
		call_dissector(can_handle, next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, guint16 ebhscr_status,
								guint32 ebhscr_frame_length)
{
	tvbuff_t* next_tvb;
	proto_item *ti;
	guint64 major_hrd, fsc_not_present;
	guint32 ebhscr_current_payload_length;
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status,
								ett_ebhscr_status, eth_rx_error_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}

	major_hrd = tvb_get_guint64(tvb, 24, ENC_BIG_ENDIAN);

	proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
							eth_mjr_hdr_bits, ENC_BIG_ENDIAN);

	fsc_not_present = (major_hrd & 0x0000000400000000);

	/* received hdr only and no data */
	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}
	/* payload is 802.3 Ethernet frame */
	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	if (fsc_not_present) {
		call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
	}
	else {
		call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_nmea(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, guint32 ebhscr_frame_length,
								guint32 ebhscr_length)
{
	tvbuff_t* next_tvb;
	guint8 *nmea_str;
	guint32 ebhscr_current_payload_length;

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status_unused, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr_unused, tvb, 24, 8, ENC_BIG_ENDIAN);

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);
	nmea_str = tvb_get_string_enc(wmem_packet_scope(), tvb, 32, ebhscr_length, ENC_UTF_8);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", "NMEA:", nmea_str);
	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, guint16 ebhscr_status,
								guint32 ebhscr_frame_length)
{
	tvbuff_t* next_tvb;
	guint32 ebhscr_current_payload_length;
	guint64 time_source = 0;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "TimeState ");
	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status, ett_ebhscr_status,
								ts_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_info_status_flag);
	}
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint64(ebhscr_packet_header_tree, hf_ts_time_source, tvb, 24, 8, ENC_BIG_ENDIAN, &time_source);
	col_append_str(pinfo->cinfo, COL_INFO, val64_to_str_const(time_source, ts_time_source_strings, "Unknown Time Source"));

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;
	if (ebhscr_current_payload_length < 28) {
		return tvb_captured_length(tvb);
	}

	/* display params only if the appropriate valid bit is set */
	if ((ebhscr_status & 0x001) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_time_offset_ns, tvb, 32, 8, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x002) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_last_offset_ns, tvb, 40, 8, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x004) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_last_jump_ns, tvb, 48, 8, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x008) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_utc_leap_sec, tvb, 56, 2, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x010) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_sync_state, tvb, 58, 2, ENC_BIG_ENDIAN);
	}

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int
dissect_ebhscr_dio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
					proto_tree *ebhscr_packet_header_tree, guint16 ebhscr_status, guint32 ebhscr_frame_length)
{
	tvbuff_t* next_tvb;
	proto_item *ti;
	guint32 ebhscr_current_payload_length;

	col_set_str(pinfo->cinfo, COL_INFO, "DIO");
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status,
								ett_ebhscr_status, dio_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}
	proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
							dio_mjr_hdr_bits, ENC_BIG_ENDIAN);

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int
dissect_ebhscr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *ebhscr_packet_header_tree;
	proto_tree *ebhscr_tree;
	tvbuff_t* next_tvb;
	guint32 ebhscr_frame_length, ebhscr_length;
	gint ebhscr_current_payload_length;
	guint8 ebhscr_major_num;
	guint16 ebhscr_status = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EBHSCR");
	col_clear(pinfo->cinfo, COL_INFO);

	ebhscr_frame_length = tvb_captured_length(tvb);

	ti = proto_tree_add_item(tree, proto_ebhscr, tvb, 0, -1, ENC_NA);
	ebhscr_tree = proto_item_add_subtree(ti, ett_ebhscr);

	if (ebhscr_frame_length < EBHSCR_HEADER_LENGTH) {
		expert_add_info(pinfo, ebhscr_tree, &ei_ebhscr_frame_header);
		return tvb_captured_length(tvb);
	}

	ebhscr_major_num = tvb_get_guint8(tvb, 0);
	ebhscr_status = tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN) & 0x0FFF;

	ti = proto_tree_add_item(ebhscr_tree, hf_ebhscr_packet_header, tvb, 0, 4, ENC_BIG_ENDIAN);
	ebhscr_packet_header_tree = proto_item_add_subtree(ti, ett_ebhscr_packet_header);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_major_number, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_slot, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_channel, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_version, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(ebhscr_packet_header_tree, hf_ebhscr_length, tvb, 4, 4, ENC_BIG_ENDIAN, &ebhscr_length);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_start_timestamp, tvb, 8, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_stop_timestamp, tvb, 16, 8, ENC_BIG_ENDIAN);

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	if ((ebhscr_major_num >= EBHSCR_USER_FIRST) && (ebhscr_major_num <= EBHSCR_USER_LAST)) {
		if (ebhscr_user_handle != NULL) {
			next_tvb = tvb_new_subset_length(tvb, 0, ebhscr_frame_length);
			call_dissector(ebhscr_user_handle, next_tvb, pinfo, ebhscr_tree);
		}
		else {
			proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
			next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
			call_data_dissector(next_tvb, pinfo, tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, 32,
							ebhscr_current_payload_length, ' '));
		}
		return tvb_captured_length(tvb);
	}

	/* each dissect function handles Status and Major number specific header bits */
	if (ebhscr_major_num == CAN_FRAME) {
		dissect_ebhscr_can(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == ETHERNET_FRAME) {
		dissect_ebhscr_eth(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == NMEA_FRAME)
	{
		dissect_ebhscr_nmea(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_frame_length, ebhscr_length);
	}

	else if (ebhscr_major_num == TIME_STATE_FRAME) {
		dissect_ebhscr_ts(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}
	else if (ebhscr_major_num == DIO_FRAME) {
		dissect_ebhscr_dio(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
		next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_ebhscr(void)
{
	expert_module_t *expert_ebhscr;

	static hf_register_info hf[] = {
		{ &hf_ebhscr_packet_header,
			{ "Packet header", "ebhscr.hdr",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
			},
		{ &hf_ebhscr_major_number,
			{ "Major number", "ebhscr.mjr",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_slot,
			{ "Slot", "ebhscr.slot",
			FT_UINT8, BASE_HEX,
			NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_channel,
			{ "Channel", "ebhscr.channel",
			FT_UINT8, BASE_HEX,
			NULL, 0x3f,
			NULL, HFILL }
		},
		{ &hf_ebhscr_status,
			{ "Status", "ebhscr.sts",
			FT_UINT16, BASE_HEX,
			NULL, 0x0FFF,
			NULL, HFILL }
		},
		{ &hf_ebhscr_status_unused,{
			"Status [Unused]", "ebhscr.sts.unused",
			FT_UINT32,	BASE_HEX,
			NULL, 0x0FFF,
			NULL, HFILL }
		},
		{ &hf_ebhscr_version,
			{ "Version", "ebhscr.ver",
			FT_UINT16, BASE_HEX,
			NULL, 0xF000,
			NULL, HFILL }
		},
		{ &hf_ebhscr_length,
			{ "Length", "ebhscr.len",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_start_timestamp,
			{ "Start timestamp", "ebhscr.strt",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_stop_timestamp,
			{ "Stop timestamp", "ebhscr.stpt",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_mjr_hdr,
			{ "Major number specific header", "ebhscr.mjrhdr",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_mjr_hdr_unused,
			{ "Major number specific header [Unused]", "ebhscr.mjrhdr.unused",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_can_proto_type,
			{ "CAN FD flag", "ebhscr.can.type",
			FT_UINT16, BASE_HEX,
			VALS(can_proto_type_strings), 0x0001,
			NULL, HFILL }
		},
		{ &hf_can_status_available,
			{ "CAN protocol status availability", "ebhscr.can.asts",
			FT_UINT16, BASE_HEX,
			VALS(can_status_available_strings), 0x0002,
			NULL, HFILL }
		},
		{ &hf_can_LEC,
			{ "CAN Last error code", "ebhscr.can.LEC",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_last_err_code_strings), 0x0000000700000000,
			NULL, HFILL }
		},
		{ &hf_can_ERRP,
			{ "CAN Counters reached Error passive limit", "ebhscr.can.errp",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_ERRP_strings), 0x0000002000000000,
			NULL, HFILL }
		},
		{ &hf_can_ERRW,
			{ "CAN Counters reached Error warning limit", "ebhscr.can.errw",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_ERRW_strings), 0x0000004000000000,
			NULL, HFILL }
		},
		{ &hf_can_BOFF,
		{ "CAN Bus Off state", "ebhscr.can.boff",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_BOFF_strings), 0x0000008000000000,
			NULL, HFILL }
		},
		{ &hf_can_DLEC,
		{ "CAN Data phase of CAN FD frame (with BRS flag set) last error code.", "ebhscr.can.dlec",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(can_last_err_code_strings), 0x0000070000000000,
			NULL, HFILL }
		},
		{ &hf_can_TEC,
			{ "CAN Transmit Error Counter", "ebhscr.can.tec",
			FT_UINT64, BASE_HEX,
			NULL, 0x00FF000000000000,
			NULL, HFILL }
		},
		{ &hf_can_REC,
			{ "CAN Receive Error Counter", "ebhscr.can.rec",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			NULL, 0x7F00000000000000,
			NULL, HFILL }
		},
		{ &hf_can_CEL,
			{ "Can Error Logging Counter", "ebhscr.can.cel",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			NULL, 0x00000000000000FF,
			NULL, HFILL }
		},
		{ &hf_can_reserved_bytes,
			{ "Reserved Flags", "ebhscr.can.rsv",
			FT_BOOLEAN, 64, NULL,
			0x00000000FFFFFF00,
			NULL, HFILL }
		},
		{ &hf_eth_reserved_bytes,
			{ "Reserved Flags", "ebhscr.eth.rsv",
			FT_BOOLEAN, 64, NULL,
			0xFFF0FF00FFFFFFFF,
			NULL, HFILL }
		},
		{ &hf_eth_link_up_down,
			{ "Link Up or Down", "ebhscr.eth.lud",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_link_strings), 0x0000000100000000,
			NULL, HFILL }
		},
		{ &hf_eth_master_slave,
			{ "Master or Slave (if supported)", "ebhscr.eth.ms",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_master_strings), 0x0000000200000000,
			NULL, HFILL }
		},
		{ &hf_eth_fcs_unavailable,
		{ "FCS unavailable", "ebhscr.eth.fcsua",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_fcs_strings), 0x0000000400000000,
			NULL, HFILL }
		},
		{ &hf_eth_rsvd_bit,
		{ "Reserved", "ebhscr.eth.rsvd",
			FT_BOOLEAN, 64, NULL,
			0x0000000800000000,
			NULL, HFILL }
		},
		{ &hf_eth_speed,
			{ "Ethernet speed", "ebhscr.eth.spd",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_speed_strings), 0x000000F000000000,
			NULL, HFILL }
		},
		{ &hf_eth_crc_error,
			{ "Ethernet CRC Error", "ebhscr.eth.crc",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			NULL, HFILL }
		},
		{ &hf_eth_mii_foe,
			{ "Media-independent interface FIFO Overflow Error", "ebhscr.eth.miifoe",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_eth_payload_foe,
			{ "Payload FIFO Overflow Error", "ebhscr.eth.pfoe",
			FT_BOOLEAN, 16,
			NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_eth_hdr_foe,
			{ "Header FIFO Overflow Error", "ebhscr.eth.hfoe",
			FT_BOOLEAN, 16,
			NULL, 0x0008,
			NULL, HFILL }
		},
		{ &hf_eth_rcv_dec_err,
			{ "Receiver Decoder Error", "ebhscr.eth.rde",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			NULL, HFILL }
		},
		{ &hf_eth_sym_error,
			{ "Symbol Error", "ebhscr.eth.se",
			FT_BOOLEAN, 16,
			NULL, 0x0020,
			NULL, HFILL }
		},
		{ &hf_eth_jabber_event,
			{ "Jabber", "ebhscr.eth.jbr",
			FT_BOOLEAN, 16,
			NULL, 0x0040,
			NULL, HFILL }
		},
		{ &hf_eth_pol_ch_event,
			{ "Polarity Change", "ebhscr.eth.pche",
			FT_BOOLEAN, 16,
			NULL, 0x0080,
			NULL, HFILL }
		},
		{ &hf_eth_fls_carrier_event,
			{ "False Carrier", "ebhscr.eth.flsc",
			FT_BOOLEAN, 16,
			NULL, 0x0100,
			NULL, HFILL }
		},
		{ &hf_eth_rx_trunc,
			{ "Truncation", "ebhscr.eth.rxtrc",
			FT_BOOLEAN, 16,
			NULL, 0x0200,
			NULL, HFILL }
		},
		{ &hf_eth_tx_trunc,
			{ "If value 1 then a Truncation occurred. The frame is sent truncated.", "ebhscr.eth.trc",
			FT_BOOLEAN, 64, NULL,
			0x0001000000000000,
			NULL, HFILL }
		},
		{ &hf_eth_trans_undrun,
			{ "If value 1 then a Transmitter Underrun occurred.", "ebhscr.eth.trudr",
			FT_BOOLEAN, 64, NULL,
			0x0002000000000000,
			NULL, HFILL }
		},
		{ &hf_eth_retrans_limit,
			{ "If value 1 then the Retransmission Limit was reached", "ebhscr.eth.rtrlmt",
			FT_BOOLEAN, 64, NULL,
			0x0004000000000000,
			NULL, HFILL }
		},
		{ &hf_eth_late_collision,
			{ "If value 1 then a Late collision was detected.", "ebhscr.eth.ltcls",
			FT_BOOLEAN, 64, NULL,
			0x0008000000000000,
			NULL, HFILL }
		},
		{ &hf_ts_time_offset_valid,
			{ "Time offset in ns valid (byte 0-7)", "ebhscr.ts.tov",
			FT_BOOLEAN, 16,	NULL,
			0x0001,
			NULL, HFILL }
		},
		{ &hf_ts_last_offset_change_valid,
		{ "Last offset change in ns valid (byte 8-15)", "ebhscr.ts.locv",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_ts_nano_seconds_last_jump_valid,
			{ "Nano seconds last jump valid (byte 16-23)", "ebhscr.ts.nsljv",
			FT_BOOLEAN, 16,
			NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_ts_UTC_leap_seconds_valid,
		{ "UTC leap seconds valid (byte 24-25)", "ebhscr.ts.utclsv",
			FT_BOOLEAN, 16,
			NULL, 0x0008,
			NULL, HFILL }
		},
		{ &hf_ts_sync_state_valid,
		{ "Sync state valid (byte 26-27)", "ebhscr.ts.ssv",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			NULL, HFILL }
		},
		{ &hf_ts_time_source,
		{ "Time source", "ebhscr.ts.tsrc",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(ts_time_source_strings), 0x0,
			NULL, HFILL }
		},
		{ &hf_ts_time_offset_ns,
		{ "Time offset in nanoseconds", "ebhscr.ts.off", FT_UINT64, BASE_HEX,
			NULL, 0, "The offset is the difference of the zero-based capture counter to TAI", HFILL }
		},
		{ &hf_ts_last_offset_ns,
			{ "Last offset change in nano seconds", "ebhscr.ts.lstoff", FT_UINT64, BASE_HEX,
			NULL, 0, "Point in time of last change of time offset.", HFILL }
		},
		{ &hf_ts_last_jump_ns,
			{ "Nano seconds last jump", "ebhscr.ts.lstjmp", FT_UINT64, BASE_HEX,
			NULL, 0, "Point in time of last hard change/jump of time count after the jump.", HFILL }
		},
		{ &hf_ts_utc_leap_sec,
			{ "UTC leap-seconds", "ebhscr.ts.leap", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ts_sync_state,
			{ "Sync state", "ebhscr.ts.syn", FT_UINT16, BASE_HEX,
			VALS(ts_sync_state_strings), 0, NULL, HFILL }
		},
		{ &hf_dio_overflow_mon_unit,
			{ "Overflow in the monitoring unit", "ebhscr.dio.ofw_mon",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			"Set to 1 in case of an overflow in the monitoring unit. In this case all remaining fields are invalid.", HFILL }
		},
		{ &hf_dio_jump_occured,
			{ "Time jump occured", "ebhscr.dio.jump_occ",
			FT_BOOLEAN, 16,
			NULL, 0x0400,
			"Set to 1 if a time jump occured near the edge and thus the timestamp was estimated.", HFILL }
		},
		{ &hf_dio_value_type,
			{ "Digital IO value type", "ebhscr.dio.valtype",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(dio_val_type_strings), 0x0100000000000000,
			NULL, HFILL }
		},
		{ &hf_dio_reserved_bytes,
			{ "Reserved Flags", "ebhscr.dio.rsv",
			FT_BOOLEAN, 64, NULL,
			0x00FFFFFFFFFFFFFF,
			NULL, HFILL }
		},

	};

	static gint *ett[] = {
		&ett_ebhscr,
		&ett_ebhscr_packet_header,
		&ett_ebhscr_status,
		&ett_ebhscr_mjr_hdr,
	};

	static ei_register_info ei[] = {
		{ &ei_ebhscr_frame_header,
			{ "ebhscr.frame_header", PI_MALFORMED, PI_ERROR,
			"Frame Header is malformed", EXPFILL }
		},
		{ &ei_ebhscr_err_status_flag,
			{ "ebhscr.sts.err.status", PI_PROTOCOL, PI_WARN,
			"Status Flag is set", EXPFILL }
		},
		{ &ei_ebhscr_info_status_flag,
			{ "ebhscr.sts.info.status", PI_PROTOCOL, PI_CHAT,
			"Status Flag is set", EXPFILL }
		},
	};

	proto_ebhscr = proto_register_protocol(
		"EBHSCR Protocol",
		"EBHSCR",
		"ebhscr"
		);

	proto_register_field_array(proto_ebhscr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_ebhscr = expert_register_protocol(proto_ebhscr);
	expert_register_field_array(expert_ebhscr, ei, array_length(ei));

	register_dissector("ebhscr", dissect_ebhscr, proto_ebhscr);
	subdissector_table = register_decode_as_next_proto(proto_ebhscr, "ebhscr.subdissector",
														"ebhscr next level dissector", NULL);
}

void
proto_reg_handoff_ebhscr(void)
{
	static dissector_handle_t ebhscr_handle;

	can_handle = find_dissector_add_dependency("can-hostendian", proto_ebhscr);
	can_fd_handle = find_dissector_add_dependency("canfd", proto_ebhscr);

	eth_withfcs_handle = find_dissector_add_dependency("eth_withfcs", proto_ebhscr);
	eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_ebhscr);
	ebhscr_user_handle = find_dissector_add_dependency("ebhscr_user", proto_ebhscr);

	ebhscr_handle = create_dissector_handle( dissect_ebhscr, proto_ebhscr);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_EBHSCR, ebhscr_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
