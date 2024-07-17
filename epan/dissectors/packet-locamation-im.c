/* packet-locamation-im.c
 * Routines for Locamation Interface Modules packet disassembly.
 *
 * Copyright (c) 2022 Locamation BV.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Locamation Interface Modules
 *
 * The modules send SNAP packets.
 *
 * Several types of IMs are supported:
 * - Current Interface Module (CIM), version 1
 * - Current Interface Module (CIM), version 2, revision 0
 * - Voltage Interface Module (VIM), version 1
 * - Voltage Interface Module (VIM), version 2, revision 0
 */

/* clang-format off */
#include "config.h"
#include <epan/packet.h>
/* clang-format on */

#include <epan/expert.h>
#include <string.h>

#include "packet-llc.h"

#ifndef ETH_FRAME_LEN
#define ETH_FRAME_LEN 1514 /* Max. octets in frame sans FCS */
#endif

/*
 * ########################################################################
 * #
 * # Forward Declarations
 * #
 * ########################################################################
 */

void proto_register_locamation_im(void);
void proto_reg_handoff_locamation_im(void);

/*
 * ########################################################################
 * #
 * # Defines
 * #
 * ########################################################################
 */

#define COMPANY_NAME "Locamation"
#define COMPANY_OUI 0x0040d6

#define COMPANY_IM_TEXT "Interface Module"

#define COMPANY_PID_CALIBRATION 0x0000
#define COMPANY_PID_IDENT 0xffff
#define COMPANY_PID_SAMPLES_IM1 0x0002
#define COMPANY_PID_SAMPLES_IM2R0 0x000e

#define PROTOCOL_NAME_IM_CALIBRATION "CALIBRATION"
#define PROTOCOL_NAME_IM_IDENT "IDENT"
#define PROTOCOL_NAME_IM_SAMPLES_IM1 "SAMPLES - IM1"
#define PROTOCOL_NAME_IM_SAMPLES_IM2R0 "SAMPLES - IM2R0"

#define PROTOCOL_NAME_CALIBRATION (COMPANY_NAME " " COMPANY_IM_TEXT " " PROTOCOL_NAME_IM_CALIBRATION)
#define PROTOCOL_NAME_IDENT (COMPANY_NAME " " COMPANY_IM_TEXT " " PROTOCOL_NAME_IM_IDENT)
#define PROTOCOL_NAME_SAMPLES_IM1 (COMPANY_NAME " " COMPANY_IM_TEXT " " PROTOCOL_NAME_IM_SAMPLES_IM1)
#define PROTOCOL_NAME_SAMPLES_IM2R0 (COMPANY_NAME " " COMPANY_IM_TEXT " " PROTOCOL_NAME_IM_SAMPLES_IM2R0)

#define PROTOCOL_SHORTNAME_CALIBRATION PROTOCOL_NAME_IM_CALIBRATION
#define PROTOCOL_SHORTNAME_IDENT PROTOCOL_NAME_IM_IDENT
#define PROTOCOL_SHORTNAME_SAMPLES_IM1 PROTOCOL_NAME_IM_SAMPLES_IM1
#define PROTOCOL_SHORTNAME_SAMPLES_IM2R0 PROTOCOL_NAME_IM_SAMPLES_IM2R0

#define MASK_SAMPLES_CONTROL_TYPE 0x80
#define MASK_SAMPLES_CONTROL_SIMULATED 0x40
#define MASK_SAMPLES_CONTROL_VERSION 0x30
#define MASK_SAMPLES_CONTROL_SEQUENCE_NUMBER 0x0f

#define MASK_RANGES_SAMPLE_8 0xc000
#define MASK_RANGES_SAMPLE_7 0x3000
#define MASK_RANGES_SAMPLE_6 0x0c00
#define MASK_RANGES_SAMPLE_5 0x0300
#define MASK_RANGES_SAMPLE_4 0x00c0
#define MASK_RANGES_SAMPLE_3 0x0030
#define MASK_RANGES_SAMPLE_2 0x000c
#define MASK_RANGES_SAMPLE_1 0x0003

#define MASK_TIMESTAMP_ADDITIONAL_STATUS_HOLDOVER_STATE 0x01
#define MASK_TIMESTAMP_ADDITIONAL_STATUS_MASTER_CLOCK_SWITCH 0x02

/*
 * ########################################################################
 * #
 * # PID Table
 * #
 * ########################################################################
 */

static const value_string company_pid_vals[] = {
    {COMPANY_PID_CALIBRATION, PROTOCOL_NAME_IM_CALIBRATION},
    {COMPANY_PID_IDENT, PROTOCOL_NAME_IM_IDENT},
    {COMPANY_PID_SAMPLES_IM1, PROTOCOL_NAME_IM_SAMPLES_IM1},
    {COMPANY_PID_SAMPLES_IM2R0, PROTOCOL_NAME_IM_SAMPLES_IM2R0},
    {0, NULL}};

/*
 * ########################################################################
 * #
 * # Types
 * #
 * ########################################################################
 */

/*
 * struct _sample_set_t {
 * 	uint16_t ranges;
 * 	int32_t sample_1;
 * 	int32_t sample_2;
 * 	int32_t sample_3;
 * 	int32_t sample_4;
 * 	int32_t sample_5;
 * 	int32_t sample_6;
 * 	int32_t sample_7;
 * 	int32_t sample_8;
 * };
 */
#define SAMPLE_SET_SIZE 34

/*
 * struct _timestamp_t {
 * 	uint8_t sync_status;
 * 	uint8_t additional_status;
 * 	uint32_t sec;
 * 	uint32_t nsec;
 * };
 */
#define TIMESTAMP_SIZE 10

/*
 * struct _timestamps_t {
 * 	uint8_t version;
 * 	guint24 reserved;
 * 	struct _timestamp_t timestamps[8];
 * };
 */
#define TIMESTAMPS_SIZE 84

/*
 * ########################################################################
 * #
 * # Helpers
 * #
 * ########################################################################
 */

static void add_split_lines(packet_info *pinfo, tvbuff_t *tvb, int tvb_offset, proto_tree *tree, int hf) {
	int offset = tvb_offset;
	int next_offset;
	while (tvb_offset_exists(tvb, offset)) {
		int len = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
		if (len == -1) {
			break;
		}

		char *line = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_UTF_8);
		proto_tree_add_string_format_value(tree, hf, tvb, offset, (next_offset - offset), line, "%s", line);
		offset = next_offset;
	}
}

/*
 * ########################################################################
 * #
 * # CALIBRATION
 * #
 * ########################################################################
 *
 * Calibration Packets
 *
 * Calibration Packets are sent by IM1 sensors.
 *
 * The calibration packets are sent in a burst, with a header packet
 * followed by a number of chunk packets. Both packet types start with a
 * Sequence Number.
 *
 * The calibration file can be reconstructed by appending all chunk packets
 * in the Sequence Number order.
 *
 * Sequence Number: 2 bytes, unsigned
 *   == 0: Header Packet
 *   != 0: Chunk Packet
 *
 * Header Packet
 * =============
 * Sequence Number      : 2 bytes, unsigned (fixed value 0)
 * First Sequence Number: 2 bytes, unsigned (fixed value 1)
 * Last Sequence Number : 2 bytes, unsigned (N)
 * Name                 : string
 *
 * Chunk Packet
 * ============
 * Sequence Number  : 2 bytes, unsigned (1 <= Sequence Number <= N)
 * Calibration Chunk: string
 */

static int hf_calibration_sequence_number;
static int hf_calibration_first_sequence_number;
static int hf_calibration_last_sequence_number;
static int hf_calibration_name;
static int hf_calibration_name_line;
static int hf_calibration_chunk;
static int hf_calibration_chunk_line;

static hf_register_info protocol_registration_calibration[] = {
    {&hf_calibration_sequence_number, {"Sequence Number", "locamation-im.calibration.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_first_sequence_number, {"First Sequence Number", "locamation-im.calibration.first_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_last_sequence_number, {"Last Sequence Number", "locamation-im.calibration.last_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_name, {"Name", "locamation-im.calibration.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_name_line, {"Name Line", "locamation-im.calibration.name.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_chunk, {"Chunk", "locamation-im.calibration.chunk", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_chunk_line, {"Chunk Line", "locamation-im.calibration.chunk.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}}};

static expert_field ei_calibration_header;

static ei_register_info ei_calibration[] = {
    {&ei_calibration_header, {"locamation-im.calibration.header", PI_SEQUENCE, PI_NOTE, "Header Packet", EXPFILL}}};

static int h_protocol_calibration = -1;

static int ett_protocol_calibration;
static int ett_calibration_lines;

static int dissect_calibration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTOCOL_SHORTNAME_CALIBRATION);
	col_set_str(pinfo->cinfo, COL_INFO, PROTOCOL_NAME_CALIBRATION);

	proto_item *calibration_item = proto_tree_add_item(tree, h_protocol_calibration, tvb, 0, -1, ENC_NA);
	proto_tree *calibration_item_subtree = proto_item_add_subtree(calibration_item, ett_protocol_calibration);

	int tvb_offset = 0;

	/* Sequence Number */
	int item_size = 2;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	uint16_t sequence_number = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN);
	if (sequence_number == 0) {
		expert_add_info(pinfo, calibration_item, &ei_calibration_header);
	}
	proto_tree_add_item(calibration_item_subtree, hf_calibration_sequence_number, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	if (sequence_number == 0) {
		/* Header Packet */

		/* First Sequence Number */
		item_size = 2;
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_tree_add_item(calibration_item_subtree, hf_calibration_first_sequence_number, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
		tvb_offset += item_size;

		/* Last Sequence Number */
		item_size = 2;
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_tree_add_item(calibration_item_subtree, hf_calibration_last_sequence_number, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
		tvb_offset += item_size;

		/* Name */
		int name_length = tvb_reported_length_remaining(tvb, tvb_offset);
		proto_item *name_item = proto_tree_add_item(calibration_item_subtree, hf_calibration_name, tvb, tvb_offset, name_length, ENC_UTF_8);

		/* Name - Lines */
		proto_tree *name_item_subtree = proto_item_add_subtree(name_item, ett_calibration_lines);
		add_split_lines(pinfo, tvb, tvb_offset, name_item_subtree, hf_calibration_name_line);
	} else {
		/* Chunk Packet */

		/* Chunk */
		int chunk_length = tvb_reported_length_remaining(tvb, tvb_offset);
		proto_item *chunk_item = proto_tree_add_item(calibration_item_subtree, hf_calibration_chunk, tvb, tvb_offset, chunk_length, ENC_UTF_8);

		/* Chunk - Lines */
		proto_tree *chunk_item_subtree = proto_item_add_subtree(chunk_item, ett_calibration_lines);
		add_split_lines(pinfo, tvb, tvb_offset, chunk_item_subtree, hf_calibration_chunk_line);
	}

	return tvb_captured_length(tvb);
}

/*
 * ########################################################################
 * #
 * # IDENT
 * #
 * ########################################################################
 *
 * Ident Packets
 *
 * Ident Packets are sent by IM1 and IM2R0 sensors.
 *
 * Ident Packet
 * ============
 * Content: string
 */

static int hf_ident_contents;
static int hf_ident_contents_line;

static hf_register_info protocol_registration_ident[] = {
    {&hf_ident_contents, {"Contents", "locamation-im.ident.contents", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ident_contents_line, {"Contents Line", "locamation-im.ident.contents.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}}};

static int h_protocol_ident = -1;

static int ett_protocol_ident;
static int ett_ident_lines;

static int dissect_ident(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTOCOL_SHORTNAME_IDENT);
	col_set_str(pinfo->cinfo, COL_INFO, PROTOCOL_NAME_IDENT);

	proto_item *ident_item = proto_tree_add_item(tree, h_protocol_ident, tvb, 0, -1, ENC_NA);
	proto_tree *ident_item_subtree = proto_item_add_subtree(ident_item, ett_protocol_ident);

	/* Contents */
	int contents_length = tvb_reported_length_remaining(tvb, 0);
	proto_item *contents_item = proto_tree_add_item(ident_item_subtree, hf_ident_contents, tvb, 0, contents_length, ENC_UTF_8);

	/* Contents - Lines */
	proto_tree *contents_item_subtree = proto_item_add_subtree(contents_item, ett_ident_lines);
	add_split_lines(pinfo, tvb, 0, contents_item_subtree, hf_ident_contents_line);

	return tvb_captured_length(tvb);
}

/*
 * ########################################################################
 * #
 * # SAMPLES - Common
 * #
 * ########################################################################
 */

static expert_field ei_samples_ranges_sample_1_invalid;
static expert_field ei_samples_ranges_sample_2_invalid;
static expert_field ei_samples_ranges_sample_3_invalid;
static expert_field ei_samples_ranges_sample_4_invalid;
static expert_field ei_samples_ranges_sample_5_invalid;
static expert_field ei_samples_ranges_sample_6_invalid;
static expert_field ei_samples_ranges_sample_7_invalid;
static expert_field ei_samples_ranges_sample_8_invalid;

static void check_ranges(tvbuff_t *tvb, packet_info *pinfo, int tvb_offset, proto_item *item) {
	uint16_t ranges = tvb_get_uint16(tvb, tvb_offset, ENC_BIG_ENDIAN);

	if ((ranges & MASK_RANGES_SAMPLE_8) == MASK_RANGES_SAMPLE_8) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_8_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_7) == MASK_RANGES_SAMPLE_7) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_7_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_6) == MASK_RANGES_SAMPLE_6) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_6_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_5) == MASK_RANGES_SAMPLE_5) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_5_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_4) == MASK_RANGES_SAMPLE_4) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_4_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_3) == MASK_RANGES_SAMPLE_3) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_3_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_2) == MASK_RANGES_SAMPLE_2) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_2_invalid);
	}
	if ((ranges & MASK_RANGES_SAMPLE_1) == MASK_RANGES_SAMPLE_1) {
		expert_add_info(pinfo, item, &ei_samples_ranges_sample_1_invalid);
	}
}

static int ett_samples_sample_set_ranges;

static int hf_samples_sample_set_ranges;

static int hf_samples_sample_set_ranges_sample_1;
static int hf_samples_sample_set_ranges_sample_2;
static int hf_samples_sample_set_ranges_sample_3;
static int hf_samples_sample_set_ranges_sample_4;
static int hf_samples_sample_set_ranges_sample_5;
static int hf_samples_sample_set_ranges_sample_6;
static int hf_samples_sample_set_ranges_sample_7;
static int hf_samples_sample_set_ranges_sample_8;

static int *const rangesBits[] = {
    &hf_samples_sample_set_ranges_sample_8,
    &hf_samples_sample_set_ranges_sample_7,
    &hf_samples_sample_set_ranges_sample_6,
    &hf_samples_sample_set_ranges_sample_5,
    &hf_samples_sample_set_ranges_sample_4,
    &hf_samples_sample_set_ranges_sample_3,
    &hf_samples_sample_set_ranges_sample_2,
    &hf_samples_sample_set_ranges_sample_1,
    NULL};

static int hf_samples_sample_set_sample_1;
static int hf_samples_sample_set_sample_2;
static int hf_samples_sample_set_sample_3;
static int hf_samples_sample_set_sample_4;
static int hf_samples_sample_set_sample_5;
static int hf_samples_sample_set_sample_6;
static int hf_samples_sample_set_sample_7;
static int hf_samples_sample_set_sample_8;

static void add_sample_set(tvbuff_t *tvb, packet_info *pinfo, int *tvb_offset, int hf, proto_tree *tree) {
	int item_size = SAMPLE_SET_SIZE;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_item *sample_set_item = proto_tree_add_item(tree, hf, tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);

	proto_tree *sample_set_item_subtree = proto_item_add_subtree(sample_set_item, ett_samples_sample_set_ranges);

	/* Ranges */
	item_size = 2;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_item *ranges_item = proto_tree_add_bitmask(sample_set_item_subtree, tvb, *tvb_offset, hf_samples_sample_set_ranges, ett_samples_sample_set_ranges, rangesBits, ENC_BIG_ENDIAN);
	check_ranges(tvb, pinfo, *tvb_offset, ranges_item);
	*tvb_offset += item_size;

	/* Samples */
	int const hfs[] = {
	    hf_samples_sample_set_sample_1,
	    hf_samples_sample_set_sample_2,
	    hf_samples_sample_set_sample_3,
	    hf_samples_sample_set_sample_4,
	    hf_samples_sample_set_sample_5,
	    hf_samples_sample_set_sample_6,
	    hf_samples_sample_set_sample_7,
	    hf_samples_sample_set_sample_8};

	item_size = 4;
	for (unsigned index_sample = 0; index_sample < array_length(hfs); index_sample++) {
		tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
		proto_tree_add_item(sample_set_item_subtree, hfs[index_sample], tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
		*tvb_offset += item_size;
	}
}

static void add_sample_sets(tvbuff_t *tvb, packet_info *pinfo, int *tvb_offset, int *hfs, unsigned hfs_size, proto_tree *tree) {
	for (unsigned index_sample_set = 0; index_sample_set < hfs_size; index_sample_set++) {
		add_sample_set(tvb, pinfo, tvb_offset, hfs[index_sample_set], tree);
	}
}

static void add_rms_values(tvbuff_t *tvb, int *tvb_offset, int *hfs, unsigned hfs_size, proto_tree *tree) {
	int item_size = 4;
	for (unsigned index_rms_value = 0; index_rms_value < hfs_size; index_rms_value++) {
		tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
		proto_tree_add_item(tree, hfs[index_rms_value], tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
		*tvb_offset += item_size;
	}
}

static int ett_samples_timestamps_sample;
static int ett_samples_timestamps_sample_reserved;
static int ett_samples_timestamps_sample_timestamp;

static int hf_samples_timestamps_sample_sync_status;
static int hf_samples_timestamps_sample_additional_status;
static int hf_samples_timestamps_sample_additional_status_holdover_state;
static int hf_samples_timestamps_sample_additional_status_master_clock_switch;
static int hf_samples_timestamps_sample_timestamp;
static int hf_samples_timestamps_sample_timestamp_seconds;
static int hf_samples_timestamps_sample_timestamp_nanoseconds;

static const value_string samples_timestamps_sample_sync_status[] = {
    {0, "None"},
    {1, "Local"},
    {2, "Global"},
    {0, NULL}};

static int *const timestamp_additional_status_bits[] = {
    &hf_samples_timestamps_sample_additional_status_holdover_state,
    &hf_samples_timestamps_sample_additional_status_master_clock_switch,
    NULL};

static expert_field ei_samples_timestamp_sync_status_invalid;

static void add_timestamp_sample(tvbuff_t *tvb, packet_info *pinfo, int *tvb_offset_previous, int *tvb_offset, int hf, proto_tree *tree) {
	int item_size = TIMESTAMP_SIZE;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);

	/* Get the timestamp components */
	uint8_t sync_status = tvb_get_uint8(tvb, *tvb_offset);
	uint32_t seconds = tvb_get_uint32(tvb, *tvb_offset + 2, ENC_BIG_ENDIAN);
	uint32_t nanoseconds = tvb_get_uint32(tvb, *tvb_offset + 6, ENC_BIG_ENDIAN);

	/* Convert the timestamp seconds to a split time type */
	time_t sample_time = (time_t)seconds;
	struct tm *sample_time_split = gmtime(&sample_time);

	/* Construct the readable sync status */
	const char *sync_status_buf = val_to_str(sync_status, samples_timestamps_sample_sync_status, "Unknown (%u)");

	/* Construct the readable timestamp */
	char timestamp_buf[ITEM_LABEL_LENGTH];
	size_t timestamp_length = 0;
	if (sample_time_split != NULL) {
		timestamp_length += strftime(&timestamp_buf[timestamp_length], ITEM_LABEL_LENGTH - timestamp_length, "%Y-%m-%d %H:%M:%S.", sample_time_split);
	} else {
		timestamp_length += snprintf(&timestamp_buf[timestamp_length], ITEM_LABEL_LENGTH - timestamp_length, "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?.");
	}
	snprintf(&timestamp_buf[timestamp_length], ITEM_LABEL_LENGTH - timestamp_length, "%09u TAI", nanoseconds);

	/* Construct the readable sample text */
	char title_buf[ITEM_LABEL_LENGTH];
	size_t title_length = 0;
	title_length += snprintf(&title_buf[title_length], ITEM_LABEL_LENGTH - title_length, "%s (Sync: %s", timestamp_buf, sync_status_buf);
	if (tvb_offset_previous != NULL) {
		/* Get the previous timestamp components and calculate the time difference */
		uint32_t seconds_previous = tvb_get_uint32(tvb, *tvb_offset_previous + 2, ENC_BIG_ENDIAN);
		uint32_t nanoseconds_previous = tvb_get_uint32(tvb, *tvb_offset_previous + 6, ENC_BIG_ENDIAN);
		uint64_t time_previous = ((uint64_t)seconds_previous * 1000000000) + nanoseconds_previous;
		uint64_t time_now = ((uint64_t)seconds * 1000000000) + nanoseconds;
		uint64_t time_diff = 0;
		char time_difference_sign[2] = {'\0', '\0'};
		if (time_now > time_previous) {
			time_diff = time_now - time_previous;
			time_difference_sign[0] = '\0';
		} else if (time_now < time_previous) {
			time_diff = time_previous - time_now;
			time_difference_sign[0] = '-';
		}
		double frequency = 0.0;
		if (time_diff != 0) {
			frequency = 1.0 / ((double)time_diff * 1.0E-09);
		}
		title_length += snprintf(&title_buf[title_length], ITEM_LABEL_LENGTH - title_length, ", Time Difference: %s%" G_GINT64_MODIFIER "u nsec", time_difference_sign, time_diff);
		if (frequency != 0.0) {
			title_length += snprintf(&title_buf[title_length], ITEM_LABEL_LENGTH - title_length, " = %f Hz", frequency);
		}
	}
	snprintf(&title_buf[title_length], ITEM_LABEL_LENGTH - title_length, ")");

	proto_item *sample_timestamp_item = proto_tree_add_string(tree, hf, tvb, *tvb_offset, item_size, title_buf);

	proto_tree *sample_timestamp_item_subtree = proto_item_add_subtree(sample_timestamp_item, ett_samples_timestamps_sample);

	/* Sync Status */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_item *sync_status_item = proto_tree_add_item(sample_timestamp_item_subtree, hf_samples_timestamps_sample_sync_status, tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
	*tvb_offset += item_size;

	if (sync_status > 2) {
		expert_add_info(pinfo, sync_status_item, &ei_samples_timestamp_sync_status_invalid);
	}

	/* Additional Status */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_tree_add_bitmask(sample_timestamp_item_subtree, tvb, *tvb_offset, hf_samples_timestamps_sample_additional_status, ett_samples_timestamps_sample_reserved, timestamp_additional_status_bits, ENC_BIG_ENDIAN);
	*tvb_offset += item_size;

	/* Timestamp */
	item_size = 8;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_item *sample_timestamp_timestamp_item = proto_tree_add_string(sample_timestamp_item_subtree, hf_samples_timestamps_sample_timestamp, tvb, *tvb_offset, item_size, timestamp_buf);

	proto_tree *sample_timestamp_timestamp_item_subtree = proto_item_add_subtree(sample_timestamp_timestamp_item, ett_samples_timestamps_sample_timestamp);

	/* Seconds */
	item_size = 4;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_tree_add_item(sample_timestamp_timestamp_item_subtree, hf_samples_timestamps_sample_timestamp_seconds, tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
	*tvb_offset += item_size;

	/* Nanoseconds */
	item_size = 4;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_tree_add_item(sample_timestamp_timestamp_item_subtree, hf_samples_timestamps_sample_timestamp_nanoseconds, tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
	*tvb_offset += item_size;
}

static void add_timestamps_set(tvbuff_t *tvb, packet_info *pinfo, int *tvb_offset, int *hfs, unsigned hfs_size, proto_tree *tree) {
	int tvb_offset_previous = 0;
	for (unsigned index_timestamp = 0; index_timestamp < hfs_size; index_timestamp++) {
		int tvb_offset_saved = *tvb_offset;
		add_timestamp_sample(tvb, pinfo, (index_timestamp == 0) ? NULL : &tvb_offset_previous, tvb_offset, hfs[index_timestamp], tree);
		tvb_offset_previous = tvb_offset_saved;
	}
}

/*
 * Samples Packets
 *
 * Samples Packets are sent by IM1 and IM2R0 sensors.
 * However, details of the packets differ between the sensors.
 *
 * Samples Packet
 * ==============
 * Transport Delay: 2 bytes, unsigned (resolution = 10ns)
 * Hop Count: 1 byte, unsigned
 * Control data: 1 byte, bitmap
 *   bit  [7]   : type     : 0 = CIM, 1 = VIM
 *   bit  [6]   : simulated: 0 = Real Samples, 1 = Simulated Samples
 *   bits [5..4]: version  : 00 = IM1, 11 = IM2R0
 *   bits [3..0]: seqnr    : Sequence Number, in the range [0,15], monotonically
 *                           increasing and wrapping
 * Temperature: 2 bytes, signed (resolution = 0.25C)
 * Padding: 1 byte
 * ADC Status: 1 byte, unsigned
 * Sample Data
 *   * Sample data is stored in sample data sets.
 *     Each sample data set contains ranges and the data of 8 samples, and
 *     samples are equi-distant in time.
 *
 *     Sample Data Set
 *     ===============
 *       Range: 2 bytes, bitmap
 *              - bits [15,14]: Range of sample 8 (newest sample)
 *              - bits [13,12]: Range of sample 7
 *              - bits [11,10]: Range of sample 6
 *              - bits [ 9, 8]: Range of sample 5
 *              - bits [ 7, 6]: Range of sample 4
 *              - bits [ 5, 4]: Range of sample 3
 *              - bits [ 3, 2]: Range of sample 2
 *              - bits [ 1, 0]: Range of sample 1 (oldest sample)
 *              Range values:
 *                00 = measurement ADC channel
 *                01 = protection ADC channel, range low
 *                10 = protection ADC channel, range high
 *                11 = unused
 *       Sample 1: 4 bytes, signed (oldest sample)
 *       Sample 2: 4 bytes, signed
 *       Sample 3: 4 bytes, signed
 *       Sample 4: 4 bytes, signed
 *       Sample 5: 4 bytes, signed
 *       Sample 6: 4 bytes, signed
 *       Sample 7: 4 bytes, signed
 *       Sample 8: 4 bytes, signed (newest sample)
 *
 *   * IM1
 *     6 sample data sets, one set per ADC channel:
 *
 *     Sample Data
 *     ===========
 *              CIM                             VIM
 *     set 1    channel 1, measurement          channel 1
 *     set 2    channel 2, measurement          channel 2
 *     set 3    channel 3, measurement          channel 3
 *     set 4    channel 1, protection           0
 *     set 5    channel 2, protection           0
 *     set 6    channel 3, protection           0
 *
 *   * IM2R0
 *     8 sample data sets, one set per ADC channel:
 *
 *     Sample Data
 *     ===========
 *              CIM                             VIM
 *     set 1    channel 1, measurement          channel 1
 *     set 2    channel 2, measurement          channel 2
 *     set 3    channel 3, measurement          channel 3
 *     set 4    channel 1, protection           neutral channel
 *     set 5    channel 2, protection           0
 *     set 6    channel 3, protection           0
 *     set 7    neutral channel, measurement    0
 *     set 8    neutral channel, protection     0
 * RMS values
 *   * RMS values are stored as 4 byte signed values.
 *
 *   * IM1
 *     6 values, one per ADC-channel:
 *
 *     RMS values
 *     ==========
 *              CIM                             VIM
 *     value 1  channel 1, measurement          channel 1
 *     value 2  channel 2, measurement          channel 2
 *     value 3  channel 3, measurement          channel 3
 *     value 4  channel 1, protection           0
 *     value 5  channel 2, protection           0
 *     value 6  channel 3, protection           0
 *
 *   * IM2R0
 *     8 values, one per ADC-channel:
 *
 *     RMS values
 *     ==========
 *              CIM                             VIM
 *     value 1  0                               0
 *     value 2  0                               0
 *     value 3  0                               0
 *     value 4  0                               0
 *     value 5  0                               0
 *     value 6  0                               0
 *     value 7  0                               0
 *     value 8  0                               0
 * Timestamps
 *   * Timestamps are PTP driven and are stored in a versioned block.
 *     Each timestamp also has status information.
 *
 *   * IM1
 *     Timestamps are not applicable for IM1.
 *
 *   * IM2R0
 *     Timestamps are optional.
 *
 *     Timestamps Block
 *     ================
 *     Version   1 byte, unsigned
 *     Reserved  3 bytes, unsigned
 *     Sample 1  Timestamp (oldest sample)
 *     Sample 2  Timestamp
 *     Sample 3  Timestamp
 *     Sample 4  Timestamp
 *     Sample 5  Timestamp
 *     Sample 6  Timestamp
 *     Sample 7  Timestamp
 *     Sample 8  Timestamp (newest sample)
 *
 *     Timestamp
 *     =========
 *     Sync Status  1 byte, unsigned
 *       0     = Not synchronized (during start-up or synchronization lost)
 *       1     = Synchronized but not to a Grand Master Clock
 *       2     = Synchronized to a Grand Master Clock
 *       3-255 = Invalid
 *     Additional Status  1 byte, bitmap
 *       bits [7, 2]: Reserved
 *       bits [1]   : Master clock switch
 *         1 = The device switched to a different master clock or
 *             became synchronized to a master clock for the first time.
 *         0 = The device did not switch to a different master clock nor
 *             became synchronized to a master clock for the first time.
 *       bits [0]   : Holdover state
 *         1 = The device is in its holdover state.
 *         0 = The device is not in its holdover state.
 *     Seconds      4 bytes, unsigned
 *     Nanoseconds  4 bytes, unsigned
 */

static int ett_protocol_samples;
static int ett_samples_control;
static int ett_samples_sets;
static int ett_samples_sets_set;
static int ett_samples_rms;
static int ett_samples_rms_values;
static int ett_samples_timestamps;
static int ett_samples_timestamps_set;

static expert_field ei_samples_im_version_invalid;

static int hf_samples_transport_delay;
static int hf_samples_hop_count;
static int hf_samples_control;
static int hf_samples_control_type;
static int hf_samples_control_simulated;
static int hf_samples_control_version;
static int hf_samples_control_sequence_number;
static int hf_samples_temperature;
static int hf_samples_padding;
static int hf_samples_adc_status;
static int hf_samples_sample_set;
static int hf_samples_rms_values;
static int hf_samples_timestamps;

static int *const controlBits[] = {
    &hf_samples_control_type,
    &hf_samples_control_simulated,
    &hf_samples_control_version,
    &hf_samples_control_sequence_number,
    NULL};

static int hf_samples_sample_set_measurement_channel_1;
static int hf_samples_sample_set_measurement_channel_2;
static int hf_samples_sample_set_measurement_channel_3;
static int hf_samples_sample_set_measurement_channel_n;
static int hf_samples_sample_set_protection_channel_1;
static int hf_samples_sample_set_protection_channel_2;
static int hf_samples_sample_set_protection_channel_3;
static int hf_samples_sample_set_protection_channel_n;
static int hf_samples_sample_set_channel_unused;

static int hf_samples_rms_values_measurement_channel_1;
static int hf_samples_rms_values_measurement_channel_2;
static int hf_samples_rms_values_measurement_channel_3;
static int hf_samples_rms_values_protection_channel_1;
static int hf_samples_rms_values_protection_channel_2;
static int hf_samples_rms_values_protection_channel_3;
static int hf_samples_rms_values_channel_unused;

static int hf_samples_timestamps_version;
static int hf_samples_timestamps_reserved;
static int hf_samples_timestamps_sample_1;
static int hf_samples_timestamps_sample_2;
static int hf_samples_timestamps_sample_3;
static int hf_samples_timestamps_sample_4;
static int hf_samples_timestamps_sample_5;
static int hf_samples_timestamps_sample_6;
static int hf_samples_timestamps_sample_7;
static int hf_samples_timestamps_sample_8;

static int dissect_samples_im(bool im1, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, int h_protocol_samples) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, im1 ? PROTOCOL_SHORTNAME_SAMPLES_IM1 : PROTOCOL_SHORTNAME_SAMPLES_IM2R0);
	col_set_str(pinfo->cinfo, COL_INFO, im1 ? PROTOCOL_NAME_SAMPLES_IM1 : PROTOCOL_NAME_SAMPLES_IM2R0);

	proto_item *samples_item = proto_tree_add_item(tree, h_protocol_samples, tvb, 0, -1, ENC_NA);
	proto_tree *samples_item_subtree = proto_item_add_subtree(samples_item, ett_protocol_samples);

	int tvb_offset = 0;

	/* Transport Delay */
	int item_size = 2;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_transport_delay, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* Hop Count */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_hop_count, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* Get Control */
	uint8_t control = tvb_get_uint8(tvb, tvb_offset);
	bool isIM1 = ((control & MASK_SAMPLES_CONTROL_VERSION) == 0);
	bool isIM2R0 = ((control & MASK_SAMPLES_CONTROL_VERSION) == MASK_SAMPLES_CONTROL_VERSION);
	bool isCIM = ((control & MASK_SAMPLES_CONTROL_TYPE) == 0);

	/* Control */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_item *control_item = proto_tree_add_bitmask(samples_item_subtree, tvb, tvb_offset, hf_samples_control, ett_samples_control, controlBits, ENC_BIG_ENDIAN);
	tvb_offset += item_size;
	if (!isIM1 && !isIM2R0) {
		expert_add_info(pinfo, control_item, &ei_samples_im_version_invalid);
	}

	/* Temperature */
	item_size = 2;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_temperature, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* Padding */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_padding, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* ADC status */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_adc_status, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* Sample Sets */
	{
		proto_tree *sample_sets_subtree = proto_item_add_subtree(samples_item, ett_samples_sets);

		if (im1) {
			item_size = SAMPLE_SET_SIZE * 6;
		} else {
			item_size = SAMPLE_SET_SIZE * 8;
		}
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_item *sample_sets_subtree_item = proto_tree_add_item(sample_sets_subtree, hf_samples_sample_set, tvb, tvb_offset, item_size, ENC_NA);

		proto_tree *sample_sets_subtree_item_subtree = proto_item_add_subtree(sample_sets_subtree_item, ett_samples_sets_set);

		if (isIM1) {
			if (isCIM) {
				/* IM1 CIM */

				int hfs[] = {
				    hf_samples_sample_set_measurement_channel_1,
				    hf_samples_sample_set_measurement_channel_2,
				    hf_samples_sample_set_measurement_channel_3,
				    hf_samples_sample_set_protection_channel_1,
				    hf_samples_sample_set_protection_channel_2,
				    hf_samples_sample_set_protection_channel_3};

				add_sample_sets(tvb, pinfo, &tvb_offset, hfs, array_length(hfs), sample_sets_subtree_item_subtree);
			} else {
				/* IM1 VIM */

				int hfs[] = {
				    hf_samples_sample_set_measurement_channel_1,
				    hf_samples_sample_set_measurement_channel_2,
				    hf_samples_sample_set_measurement_channel_3,
				    hf_samples_sample_set_channel_unused,
				    hf_samples_sample_set_channel_unused,
				    hf_samples_sample_set_channel_unused};

				add_sample_sets(tvb, pinfo, &tvb_offset, hfs, array_length(hfs), sample_sets_subtree_item_subtree);
			}
		} else if (isIM2R0) {
			if (isCIM) {
				/* IM2R0 CIM */

				int hfs[] = {
				    hf_samples_sample_set_measurement_channel_1,
				    hf_samples_sample_set_measurement_channel_2,
				    hf_samples_sample_set_measurement_channel_3,
				    hf_samples_sample_set_protection_channel_1,
				    hf_samples_sample_set_protection_channel_2,
				    hf_samples_sample_set_protection_channel_3,
				    hf_samples_sample_set_measurement_channel_n,
				    hf_samples_sample_set_protection_channel_n};

				add_sample_sets(tvb, pinfo, &tvb_offset, hfs, array_length(hfs), sample_sets_subtree_item_subtree);
			} else {
				/* IM2R0 VIM */

				int hfs[] = {
				    hf_samples_sample_set_measurement_channel_1,
				    hf_samples_sample_set_measurement_channel_2,
				    hf_samples_sample_set_measurement_channel_3,
				    hf_samples_sample_set_measurement_channel_n,
				    hf_samples_sample_set_channel_unused,
				    hf_samples_sample_set_channel_unused,
				    hf_samples_sample_set_channel_unused,
				    hf_samples_sample_set_channel_unused};

				add_sample_sets(tvb, pinfo, &tvb_offset, hfs, array_length(hfs), sample_sets_subtree_item_subtree);
			}
		}
	}

	/* RMS Values */
	{
		proto_tree *rms_values_subtree = proto_item_add_subtree(samples_item, ett_samples_rms);

		if (im1) {
			item_size = 4 * 6;
		} else {
			item_size = 4 * 8;
		}
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_item *rms_values_item = proto_tree_add_item(rms_values_subtree, hf_samples_rms_values, tvb, tvb_offset, item_size, ENC_NA);

		proto_tree *rms_values_item_subtree = proto_item_add_subtree(rms_values_item, ett_samples_rms_values);

		if (isIM1) {
			if (isCIM) {
				/* IM1 CIM */

				int hfs[] = {
				    hf_samples_rms_values_measurement_channel_1,
				    hf_samples_rms_values_measurement_channel_2,
				    hf_samples_rms_values_measurement_channel_3,
				    hf_samples_rms_values_protection_channel_1,
				    hf_samples_rms_values_protection_channel_2,
				    hf_samples_rms_values_protection_channel_3};

				add_rms_values(tvb, &tvb_offset, hfs, array_length(hfs), rms_values_item_subtree);
			} else {
				/* IM1 VIM */

				int hfs[] = {
				    hf_samples_rms_values_measurement_channel_1,
				    hf_samples_rms_values_measurement_channel_2,
				    hf_samples_rms_values_measurement_channel_3,
				    hf_samples_rms_values_channel_unused,
				    hf_samples_rms_values_channel_unused,
				    hf_samples_rms_values_channel_unused};

				add_rms_values(tvb, &tvb_offset, hfs, array_length(hfs), rms_values_item_subtree);
			}
		} else if (isIM2R0) {
			int hfs[] = {
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused,
			    hf_samples_rms_values_channel_unused};

			add_rms_values(tvb, &tvb_offset, hfs, array_length(hfs), rms_values_item_subtree);
		}
	}

	/* Timestamps */
	if (isIM2R0 && tvb_bytes_exist(tvb, tvb_offset, TIMESTAMPS_SIZE)) {
		proto_tree *samples_timestamps_subtree = proto_item_add_subtree(samples_item, ett_samples_timestamps);

		item_size = TIMESTAMPS_SIZE;
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_item *samples_timestamps_subtree_item = proto_tree_add_item(samples_timestamps_subtree, hf_samples_timestamps, tvb, tvb_offset, item_size, ENC_NA);

		proto_tree *samples_timestamps_subtree_item_subtree = proto_item_add_subtree(samples_timestamps_subtree_item, ett_samples_timestamps_set);

		/* Version */
		item_size = 1;
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_tree_add_item(samples_timestamps_subtree_item_subtree, hf_samples_timestamps_version, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
		tvb_offset += item_size;

		/* Reserved */
		item_size = 3;
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_tree_add_item(samples_timestamps_subtree_item_subtree, hf_samples_timestamps_reserved, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
		tvb_offset += item_size;

		/* Sample Timestamps */

		int hfs[] = {
		    hf_samples_timestamps_sample_1,
		    hf_samples_timestamps_sample_2,
		    hf_samples_timestamps_sample_3,
		    hf_samples_timestamps_sample_4,
		    hf_samples_timestamps_sample_5,
		    hf_samples_timestamps_sample_6,
		    hf_samples_timestamps_sample_7,
		    hf_samples_timestamps_sample_8};

		add_timestamps_set(tvb, pinfo, &tvb_offset, hfs, array_length(hfs), samples_timestamps_subtree_item_subtree);
	}

	return tvb_captured_length(tvb);
}

/*
 * ########################################################################
 * #
 * # Samples - IM1
 * #
 * ########################################################################
 */

static void samples_transport_delay(char *result, uint16_t transport_delay) {
	snprintf(result, ITEM_LABEL_LENGTH, "%u ns", transport_delay * 10);
}

static const value_string samples_control_type_vals[] = {
    {0, "Current Interface Module"},
    {1, "Voltage Interface Module"},
    {0, NULL}};

static const value_string samples_control_simulated_vals[] = {
    {0, "Sampled"},
    {1, "Simulated"},
    {0, NULL}};

static const value_string samples_control_version_vals[] = {
    {0, "IM1"},
    {1, "Unused"},
    {2, "Unused"},
    {3, "IM2R0"},
    {0, NULL}};

static void samples_sequence_number(char *result, uint8_t sequence_number) {
	snprintf(result, ITEM_LABEL_LENGTH, "%u", sequence_number);
}

static void samples_temperature(char *result, int16_t temperature) {
	snprintf(result, ITEM_LABEL_LENGTH, "%.2f C", (0.25f * temperature));
}

static const value_string ranges_vals[] = {
    {0, "Measurement ADC Channel"},
    {1, "Protection ADC Channel, Range Low"},
    {2, "Protection ADC Channel, Range High"},
    {3, "Unused"},
    {0, NULL}};

static hf_register_info protocol_registration_samples[] = {
    {&hf_samples_transport_delay, {"Transport Delay", "locamation-im.samples.transport_delay", FT_UINT16, BASE_CUSTOM, CF_FUNC(samples_transport_delay), 0x0, NULL, HFILL}},
    {&hf_samples_hop_count, {"Hop Count", "locamation-im.samples.hop_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_control, {"Control", "locamation-im.samples.control", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_control_type, {"Type", "locamation-im.samples.control.type", FT_UINT8, BASE_DEC, VALS(samples_control_type_vals), MASK_SAMPLES_CONTROL_TYPE, NULL, HFILL}},
    {&hf_samples_control_simulated, {"Simulated", "locamation-im.samples.control.simulated", FT_UINT8, BASE_DEC, VALS(samples_control_simulated_vals), MASK_SAMPLES_CONTROL_SIMULATED, NULL, HFILL}},
    {&hf_samples_control_version, {"Version", "locamation-im.samples.control.version", FT_UINT8, BASE_DEC, VALS(samples_control_version_vals), MASK_SAMPLES_CONTROL_VERSION, NULL, HFILL}},
    {&hf_samples_control_sequence_number, {"Sequence Number", "locamation-im.samples.control.sequence_number", FT_UINT8, BASE_CUSTOM, CF_FUNC(samples_sequence_number), MASK_SAMPLES_CONTROL_SEQUENCE_NUMBER, NULL, HFILL}},
    {&hf_samples_temperature, {"Temperature", "locamation-im.samples.temperature", FT_INT16, BASE_CUSTOM, CF_FUNC(samples_temperature), 0x0, NULL, HFILL}},
    {&hf_samples_padding, {"Padding", "locamation-im.samples.padding", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_adc_status, {"ADC Status", "locamation-im.samples.adc_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set, {"Sample Sets", "locamation-im.samples.sets", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values, {"RMS Values", "locamation-im.samples.rms_values", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_measurement_channel_1, {"Measurement Channel 1", "locamation-im.samples.sets.measurement.channel.1", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_measurement_channel_2, {"Measurement Channel 2", "locamation-im.samples.sets.measurement.channel.2", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_measurement_channel_3, {"Measurement Channel 3", "locamation-im.samples.sets.measurement.channel.3", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_measurement_channel_n, {"Measurement Channel N", "locamation-im.samples.sets.measurement.channel.n", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_protection_channel_1, {"Protection Channel 1", "locamation-im.samples.sets.protection.channel.1", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_protection_channel_2, {"Protection Channel 2", "locamation-im.samples.sets.protection.channel.2", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_protection_channel_3, {"Protection Channel 3", "locamation-im.samples.sets.protection.channel.3", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_protection_channel_n, {"Protection Channel N", "locamation-im.samples.sets.protection.channel.n", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_channel_unused, {"Unused Channel", "locamation-im.samples.sets.channel.unused", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_ranges, {"Ranges", "locamation-im.samples.sets.measurement.ranges", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_1, {"Sample 1", "locamation-im.samples.sets.measurement.ranges.sample.1", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_1, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_2, {"Sample 2", "locamation-im.samples.sets.measurement.ranges.sample.2", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_2, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_3, {"Sample 3", "locamation-im.samples.sets.measurement.ranges.sample.3", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_3, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_4, {"Sample 4", "locamation-im.samples.sets.measurement.ranges.sample.4", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_4, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_5, {"Sample 5", "locamation-im.samples.sets.measurement.ranges.sample.5", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_5, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_6, {"Sample 6", "locamation-im.samples.sets.measurement.ranges.sample.6", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_6, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_7, {"Sample 7", "locamation-im.samples.sets.measurement.ranges.sample.7", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_7, NULL, HFILL}},
    {&hf_samples_sample_set_ranges_sample_8, {"Sample 8", "locamation-im.samples.sets.measurement.ranges.sample.8", FT_UINT16, BASE_DEC, VALS(ranges_vals), MASK_RANGES_SAMPLE_8, NULL, HFILL}},
    {&hf_samples_sample_set_sample_1, {"Sample 1", "locamation-im.samples.sets.sample.1", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_2, {"Sample 2", "locamation-im.samples.sets.sample.2", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_3, {"Sample 3", "locamation-im.samples.sets.sample.3", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_4, {"Sample 4", "locamation-im.samples.sets.sample.4", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_5, {"Sample 5", "locamation-im.samples.sets.sample.5", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_6, {"Sample 6", "locamation-im.samples.sets.sample.6", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_7, {"Sample 7", "locamation-im.samples.sets.sample.7", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_sample_set_sample_8, {"Sample 8", "locamation-im.samples.sets.sample.8", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_measurement_channel_1, {"Measurement Channel 1", "locamation-im.samples.rms.measurement.channel.1", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_measurement_channel_2, {"Measurement Channel 2", "locamation-im.samples.rms.measurement.channel.2", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_measurement_channel_3, {"Measurement Channel 3", "locamation-im.samples.rms.measurement.channel.3", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_protection_channel_1, {"Protection Channel 1", "locamation-im.samples.rms.protection.channel.1", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_protection_channel_2, {"Protection Channel 2", "locamation-im.samples.rms.protection.channel.2", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_protection_channel_3, {"Protection Channel 3", "locamation-im.samples.rms.protection.channel.3", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_rms_values_channel_unused, {"Unused Channel", "locamation-im.samples.rms.channel.unused", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}}};

static ei_register_info ei_samples_im1[] = {
    {&ei_samples_ranges_sample_1_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.1.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 1", EXPFILL}},
    {&ei_samples_ranges_sample_2_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.2.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 2", EXPFILL}},
    {&ei_samples_ranges_sample_3_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.3.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 3", EXPFILL}},
    {&ei_samples_ranges_sample_4_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.4.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 4", EXPFILL}},
    {&ei_samples_ranges_sample_5_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.5.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 5", EXPFILL}},
    {&ei_samples_ranges_sample_6_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.6.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 6", EXPFILL}},
    {&ei_samples_ranges_sample_7_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.7.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 7", EXPFILL}},
    {&ei_samples_ranges_sample_8_invalid, {"locamation-im.samples.sets.measurement.ranges.sample.8.invalid", PI_MALFORMED, PI_ERROR, "Invalid Range for sample 8", EXPFILL}}};

static int h_protocol_samples_im1 = -1;

static int dissect_samples_im1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	return dissect_samples_im(true, tvb, pinfo, tree, data, h_protocol_samples_im1);
}

/*
 * ########################################################################
 * #
 * # Samples - IM2R0
 * #
 * ########################################################################
 */

static hf_register_info protocol_registration_samples_im2[] = {
    {&hf_samples_timestamps, {"Timestamps", "locamation-im.samples.timestamps", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_version, {"Version", "locamation-im.samples.timestamps.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_reserved, {"Reserved", "locamation-im.samples.timestamps.reserved", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_1, {"Sample 1", "locamation-im.samples.timestamps.sample.1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_2, {"Sample 2", "locamation-im.samples.timestamps.sample.2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_3, {"Sample 3", "locamation-im.samples.timestamps.sample.3", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_4, {"Sample 4", "locamation-im.samples.timestamps.sample.4", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_5, {"Sample 5", "locamation-im.samples.timestamps.sample.5", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_6, {"Sample 6", "locamation-im.samples.timestamps.sample.6", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_7, {"Sample 7", "locamation-im.samples.timestamps.sample.7", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_8, {"Sample 8", "locamation-im.samples.timestamps.sample.8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_sync_status, {"Sync Status", "locamation-im.samples.timestamps.sample.sync.status", FT_UINT8, BASE_DEC, VALS(samples_timestamps_sample_sync_status), 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_additional_status, {"Additional Status", "locamation-im.samples.timestamps.sample.additional.status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_additional_status_holdover_state, {"Holdover", "locamation-im.samples.timestamps.sample.additional.status.holdover.state", FT_BOOLEAN, 8, TFS(&tfs_active_inactive), MASK_TIMESTAMP_ADDITIONAL_STATUS_HOLDOVER_STATE, NULL, HFILL}},
    {&hf_samples_timestamps_sample_additional_status_master_clock_switch, {"Master Clock Switch", "locamation-im.samples.timestamps.sample.additional.status.master.clock.switch", FT_BOOLEAN, 8, TFS(&tfs_yes_no), MASK_TIMESTAMP_ADDITIONAL_STATUS_MASTER_CLOCK_SWITCH, NULL, HFILL}},
    {&hf_samples_timestamps_sample_timestamp, {"Timestamp", "locamation-im.samples.timestamps.sample.timestamp", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_timestamp_seconds, {"Seconds", "locamation-im.samples.timestamps.sample.timestamp.seconds", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_samples_timestamps_sample_timestamp_nanoseconds, {"Nanoseconds", "locamation-im.samples.timestamps.sample.timestamp.nanoseconds", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}}};

static ei_register_info ei_samples_im2r0[] = {
    {&ei_samples_im_version_invalid, {"locamation-im.samples.control.version.invalid", PI_MALFORMED, PI_ERROR, "Invalid Version", EXPFILL}},
    {&ei_samples_timestamp_sync_status_invalid, {"locamation-im.samples.timestamps.sample.sync.status.invalid", PI_MALFORMED, PI_ERROR, "Invalid Status", EXPFILL}}};

static int h_protocol_samples_im2r0 = -1;

static int dissect_samples_im2r0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	return dissect_samples_im(false, tvb, pinfo, tree, data, h_protocol_samples_im2r0);
}

/*
 * ########################################################################
 * #
 * # LLC
 * #
 * ########################################################################
 */

static int hf_llc_company_pid;

static hf_register_info llc_registration[] = {
    {&hf_llc_company_pid, {"PID", "locamation-im.llc.pid", FT_UINT16, BASE_HEX, VALS(company_pid_vals), 0x0, "Protocol ID", HFILL}}};

/*
 * ########################################################################
 * #
 * # Registration
 * #
 * ########################################################################
 */

static int *protocol_subtree[] = {
    &ett_protocol_calibration,
    &ett_calibration_lines,

    &ett_protocol_ident,
    &ett_ident_lines,

    &ett_samples_sample_set_ranges,
    &ett_protocol_samples,
    &ett_samples_control,
    &ett_samples_sets,
    &ett_samples_sets_set,
    &ett_samples_rms,
    &ett_samples_rms_values,
    &ett_samples_timestamps,
    &ett_samples_timestamps_set,
    &ett_samples_timestamps_sample,
    &ett_samples_timestamps_sample_timestamp,
    &ett_samples_timestamps_sample_reserved};

static dissector_handle_t h_calibration;
static dissector_handle_t h_ident;
static dissector_handle_t h_samples_im1;
static dissector_handle_t h_samples_im2r0;

void proto_register_locamation_im(void) {
	/* Setup subtrees */
	proto_register_subtree_array(protocol_subtree, array_length(protocol_subtree));

	/* Register Protocols */

	/* Calibration */
	h_protocol_calibration = proto_register_protocol(PROTOCOL_NAME_CALIBRATION, PROTOCOL_SHORTNAME_CALIBRATION, "locamation-im.calibration");
	proto_register_field_array(h_protocol_calibration, protocol_registration_calibration, array_length(protocol_registration_calibration));
	expert_module_t *expert_calibration = expert_register_protocol(h_protocol_calibration);
	expert_register_field_array(expert_calibration, ei_calibration, array_length(ei_calibration));

	/* Ident */
	h_protocol_ident = proto_register_protocol(PROTOCOL_NAME_IDENT, PROTOCOL_SHORTNAME_IDENT, "locamation-im.ident");
	proto_register_field_array(h_protocol_ident, protocol_registration_ident, array_length(protocol_registration_ident));

	/* Samples - IM1 */
	h_protocol_samples_im1 = proto_register_protocol(PROTOCOL_NAME_SAMPLES_IM1, PROTOCOL_SHORTNAME_SAMPLES_IM1, "locamation-im.samples.im1");
	proto_register_field_array(h_protocol_samples_im1, protocol_registration_samples, array_length(protocol_registration_samples));
	expert_module_t *expert_samples_im1 = expert_register_protocol(h_protocol_samples_im1);
	expert_register_field_array(expert_samples_im1, ei_samples_im1, array_length(ei_samples_im1));

	/* Samples - IM2R0 */
	h_protocol_samples_im2r0 = proto_register_protocol(PROTOCOL_NAME_SAMPLES_IM2R0, PROTOCOL_SHORTNAME_SAMPLES_IM2R0, "locamation-im.samples.im2r0");
	proto_register_field_array(h_protocol_samples_im2r0, protocol_registration_samples_im2, array_length(protocol_registration_samples_im2));
	expert_module_t *expert_samples_im2r0 = expert_register_protocol(h_protocol_samples_im2r0);
	expert_register_field_array(expert_samples_im2r0, ei_samples_im2r0, array_length(ei_samples_im2r0));

	/* LLC Handler Registration */
	llc_add_oui(COMPANY_OUI, "locamation-im.llc.pid", "LLC " COMPANY_NAME " OUI PID", llc_registration, -1);
}

void proto_reg_handoff_locamation_im(void) {
	/* Calibration */
	h_calibration = create_dissector_handle(dissect_calibration, h_protocol_calibration);
	dissector_add_uint("locamation-im.llc.pid", COMPANY_PID_CALIBRATION, h_calibration);

	/* Ident */
	h_ident = create_dissector_handle(dissect_ident, h_protocol_ident);
	dissector_add_uint("locamation-im.llc.pid", COMPANY_PID_IDENT, h_ident);

	/* Samples - IM1 */
	h_samples_im1 = create_dissector_handle(dissect_samples_im1, h_protocol_samples_im1);
	dissector_add_uint("locamation-im.llc.pid", COMPANY_PID_SAMPLES_IM1, h_samples_im1);

	/* Samples - IM2R0 */
	h_samples_im2r0 = create_dissector_handle(dissect_samples_im2r0, h_protocol_samples_im2r0);
	dissector_add_uint("locamation-im.llc.pid", COMPANY_PID_SAMPLES_IM2R0, h_samples_im2r0);
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
