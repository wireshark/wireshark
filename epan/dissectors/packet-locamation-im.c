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

#include <epan/dissectors/packet-llc.h>
#include <epan/expert.h>
#include <string.h>

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
 * 	guint16 ranges;
 * 	gint32 sample_1;
 * 	gint32 sample_2;
 * 	gint32 sample_3;
 * 	gint32 sample_4;
 * 	gint32 sample_5;
 * 	gint32 sample_6;
 * 	gint32 sample_7;
 * 	gint32 sample_8;
 * };
 */
#define SAMPLE_SET_SIZE 34

/*
 * ########################################################################
 * #
 * # Helpers
 * #
 * ########################################################################
 */

static void add_split_lines(tvbuff_t *tvb, int tvb_offset, proto_tree *tree, int hf, char *src_buf, int src_buf_size, gboolean line_numbers) {
	char line_buf[ETH_FRAME_LEN + 1];

	char *line_start = src_buf;
	char *line_end = src_buf;
	int line_start_index = 0;
	int line_nr = 1;
	while ((line_start_index <= (src_buf_size - 1)) && (line_end <= &src_buf[src_buf_size - 1]) && (line_start != NULL)) {
		line_end = strchr(line_start, '\n');
		gboolean found_line_end = (line_end != NULL);
		int line_end_index = found_line_end ? (int)(line_end - src_buf) : src_buf_size;
		int line_length = line_end_index - line_start_index;

		int line_number_length = 0;
		if (line_numbers) {
			line_number_length = snprintf(line_buf, sizeof(line_buf), " %2d:", line_nr++);
		}

		int total_line_length = tvb_get_raw_bytes_as_string(tvb, tvb_offset + line_start_index, &line_buf[line_number_length], line_length + 1);
		if (found_line_end) {
			total_line_length++;
		}
		proto_tree_add_string(tree, hf, tvb, tvb_offset + line_start_index, total_line_length, line_buf);

		line_start = line_end + 1;
		line_start_index = line_end_index + 1;
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

static int hf_calibration_sequence_number = -1;
static int hf_calibration_first_sequence_number = -1;
static int hf_calibration_last_sequence_number = -1;
static int hf_calibration_name = -1;
static int hf_calibration_name_line = -1;
static int hf_calibration_chunk = -1;
static int hf_calibration_chunk_line = -1;

static hf_register_info protocol_registration_calibration[] = {
    {&hf_calibration_sequence_number, {"Sequence Number", "locamation-im.calibration.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_first_sequence_number, {"First Sequence Number", "locamation-im.calibration.first_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_last_sequence_number, {"Last Sequence Number", "locamation-im.calibration.last_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_name, {"Name", "locamation-im.calibration.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_name_line, {"Name Line", "locamation-im.calibration.name.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_chunk, {"Chunk", "locamation-im.calibration.chunk", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_calibration_chunk_line, {"Chunk Line", "locamation-im.calibration.chunk.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}}};

static expert_field ei_calibration_header = EI_INIT;

static ei_register_info ei_calibration[] = {
    {&ei_calibration_header, {"locamation-im.calibration.header", PI_SEQUENCE, PI_NOTE, "Header Packet", EXPFILL}}};

static int h_protocol_calibration = -1;

static gint hst_protocol_calibration = -1;
static gint hst_calibration_lines = -1;

static int dissect_calibration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTOCOL_SHORTNAME_CALIBRATION);
	col_set_str(pinfo->cinfo, COL_INFO, PROTOCOL_NAME_CALIBRATION);

	proto_item *calibration_item = proto_tree_add_item(tree, h_protocol_calibration, tvb, 0, -1, ENC_NA);
	proto_tree *calibration_item_subtree = proto_item_add_subtree(calibration_item, hst_protocol_calibration);

	gint tvb_offset = 0;

	/* Sequence Number */
	gint item_size = 2;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	guint16 sequence_number = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);
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
		char name_buf[ETH_FRAME_LEN + 1];
		int name_length = tvb_get_raw_bytes_as_string(tvb, tvb_offset, name_buf, sizeof(name_buf));
		proto_item *name_item = proto_tree_add_string(calibration_item_subtree, hf_calibration_name, tvb, tvb_offset, name_length, name_buf);

		/* Name - Lines */
		proto_tree *name_item_subtree = proto_item_add_subtree(name_item, hst_calibration_lines);
		add_split_lines(tvb, tvb_offset, name_item_subtree, hf_calibration_name_line, name_buf, name_length, FALSE);
	} else {
		/* Chunk Packet */

		/* Chunk */
		char chunk_buf[ETH_FRAME_LEN + 1];
		int chunk_length = tvb_get_raw_bytes_as_string(tvb, tvb_offset, chunk_buf, sizeof(chunk_buf));
		proto_item *chunk_item = proto_tree_add_string(calibration_item_subtree, hf_calibration_chunk, tvb, tvb_offset, chunk_length, chunk_buf);

		/* Chunk - Lines */
		proto_tree *chunk_item_subtree = proto_item_add_subtree(chunk_item, hst_calibration_lines);
		add_split_lines(tvb, tvb_offset, chunk_item_subtree, hf_calibration_chunk_line, chunk_buf, chunk_length, FALSE);
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

static int hf_ident_contents = -1;
static int hf_ident_contents_line = -1;

static hf_register_info protocol_registration_ident[] = {
    {&hf_ident_contents, {"Contents", "locamation-im.ident.contents", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ident_contents_line, {"Contents Line", "locamation-im.ident.contents.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}}};

static int h_protocol_ident = -1;

static gint hst_protocol_ident = -1;
static gint hst_ident_lines = -1;

static int dissect_ident(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTOCOL_SHORTNAME_IDENT);
	col_set_str(pinfo->cinfo, COL_INFO, PROTOCOL_NAME_IDENT);

	proto_item *ident_item = proto_tree_add_item(tree, h_protocol_ident, tvb, 0, -1, ENC_NA);
	proto_tree *ident_item_subtree = proto_item_add_subtree(ident_item, hst_protocol_ident);

	/* Contents */
	char contents_buf[ETH_FRAME_LEN + 1];
	int contents_length = tvb_get_raw_bytes_as_string(tvb, 0, contents_buf, sizeof(contents_buf));
	proto_item *contents_item = proto_tree_add_string(ident_item_subtree, hf_ident_contents, tvb, 0, contents_length, contents_buf);

	/* Contents - Lines */
	proto_tree *contents_item_subtree = proto_item_add_subtree(contents_item, hst_ident_lines);
	add_split_lines(tvb, 0, contents_item_subtree, hf_ident_contents_line, contents_buf, contents_length, FALSE);

	return tvb_captured_length(tvb);
}

/*
 * ########################################################################
 * #
 * # SAMPLES - Common
 * #
 * ########################################################################
 */

static expert_field ei_samples_ranges_sample_1_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_2_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_3_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_4_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_5_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_6_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_7_invalid = EI_INIT;
static expert_field ei_samples_ranges_sample_8_invalid = EI_INIT;

static void check_ranges(tvbuff_t *tvb, packet_info *pinfo, gint tvb_offset, proto_item *item) {
	guint16 ranges = tvb_get_guint16(tvb, tvb_offset, ENC_BIG_ENDIAN);

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

static gint hst_samples_sample_set_ranges = -1;

static int hf_samples_sample_set_ranges = -1;

static int hf_samples_sample_set_ranges_sample_1 = -1;
static int hf_samples_sample_set_ranges_sample_2 = -1;
static int hf_samples_sample_set_ranges_sample_3 = -1;
static int hf_samples_sample_set_ranges_sample_4 = -1;
static int hf_samples_sample_set_ranges_sample_5 = -1;
static int hf_samples_sample_set_ranges_sample_6 = -1;
static int hf_samples_sample_set_ranges_sample_7 = -1;
static int hf_samples_sample_set_ranges_sample_8 = -1;

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

static int hf_samples_sample_set_sample_1 = -1;
static int hf_samples_sample_set_sample_2 = -1;
static int hf_samples_sample_set_sample_3 = -1;
static int hf_samples_sample_set_sample_4 = -1;
static int hf_samples_sample_set_sample_5 = -1;
static int hf_samples_sample_set_sample_6 = -1;
static int hf_samples_sample_set_sample_7 = -1;
static int hf_samples_sample_set_sample_8 = -1;

static void add_sample_set(tvbuff_t *tvb, packet_info *pinfo, gint *tvb_offset, int hf, proto_tree *tree) {
	gint item_size = SAMPLE_SET_SIZE;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_item *sample_set_item = proto_tree_add_item(tree, hf, tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);

	proto_tree *sample_set_item_subtree = proto_item_add_subtree(sample_set_item, hst_samples_sample_set_ranges);

	/* Ranges */
	item_size = 2;
	tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
	proto_item *ranges_item = proto_tree_add_bitmask(sample_set_item_subtree, tvb, *tvb_offset, hf_samples_sample_set_ranges, hst_samples_sample_set_ranges, rangesBits, ENC_BIG_ENDIAN);
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
	for (guint index_sample = 0; index_sample < array_length(hfs); index_sample++) {
		tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
		proto_tree_add_item(sample_set_item_subtree, hfs[index_sample], tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
		*tvb_offset += item_size;
	}
}

static void add_sample_sets(tvbuff_t *tvb, packet_info *pinfo, gint *tvb_offset, int *hfs, guint hfs_size, proto_tree *tree) {
	for (guint index_sample_set = 0; index_sample_set < hfs_size; index_sample_set++) {
		add_sample_set(tvb, pinfo, tvb_offset, hfs[index_sample_set], tree);
	}
}

static void add_rms_values(tvbuff_t *tvb, gint *tvb_offset, int *hfs, guint hfs_size, proto_tree *tree) {
	gint item_size = 4;
	for (guint index_rms_value = 0; index_rms_value < hfs_size; index_rms_value++) {
		tvb_ensure_bytes_exist(tvb, *tvb_offset, item_size);
		proto_tree_add_item(tree, hfs[index_rms_value], tvb, *tvb_offset, item_size, ENC_BIG_ENDIAN);
		*tvb_offset += item_size;
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
 */

static gint hst_protocol_samples = -1;
static gint hst_samples_control = -1;
static gint hst_samples_sets = -1;
static gint hst_samples_sets_set = -1;
static gint hst_samples_rms = -1;
static gint hst_samples_rms_values = -1;

static expert_field ei_samples_im_version_invalid = EI_INIT;

static int hf_samples_transport_delay = -1;
static int hf_samples_hop_count = -1;
static int hf_samples_control = -1;
static int hf_samples_control_type = -1;
static int hf_samples_control_simulated = -1;
static int hf_samples_control_version = -1;
static int hf_samples_control_sequence_number = -1;
static int hf_samples_temperature = -1;
static int hf_samples_padding = -1;
static int hf_samples_adc_status = -1;
static int hf_samples_sample_set = -1;
static int hf_samples_rms_values = -1;

static int *const controlBits[] = {
    &hf_samples_control_type,
    &hf_samples_control_simulated,
    &hf_samples_control_version,
    &hf_samples_control_sequence_number,
    NULL};

static int hf_samples_sample_set_measurement_channel_1 = -1;
static int hf_samples_sample_set_measurement_channel_2 = -1;
static int hf_samples_sample_set_measurement_channel_3 = -1;
static int hf_samples_sample_set_measurement_channel_n = -1;
static int hf_samples_sample_set_protection_channel_1 = -1;
static int hf_samples_sample_set_protection_channel_2 = -1;
static int hf_samples_sample_set_protection_channel_3 = -1;
static int hf_samples_sample_set_protection_channel_n = -1;
static int hf_samples_sample_set_channel_unused = -1;

static int hf_samples_rms_values_measurement_channel_1 = -1;
static int hf_samples_rms_values_measurement_channel_2 = -1;
static int hf_samples_rms_values_measurement_channel_3 = -1;
static int hf_samples_rms_values_protection_channel_1 = -1;
static int hf_samples_rms_values_protection_channel_2 = -1;
static int hf_samples_rms_values_protection_channel_3 = -1;
static int hf_samples_rms_values_channel_unused = -1;

static int dissect_samples_im(gboolean im1, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, int h_protocol_samples) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, im1 ? PROTOCOL_SHORTNAME_SAMPLES_IM1 : PROTOCOL_SHORTNAME_SAMPLES_IM2R0);
	col_set_str(pinfo->cinfo, COL_INFO, im1 ? PROTOCOL_NAME_SAMPLES_IM1 : PROTOCOL_NAME_SAMPLES_IM2R0);

	proto_item *samples_item = proto_tree_add_item(tree, h_protocol_samples, tvb, 0, -1, ENC_NA);
	proto_tree *samples_item_subtree = proto_item_add_subtree(samples_item, hst_protocol_samples);

	gint tvb_offset = 0;

	/* Transport Delay */
	gint item_size = 2;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_transport_delay, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* Hop Count */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_tree_add_item(samples_item_subtree, hf_samples_hop_count, tvb, tvb_offset, item_size, ENC_BIG_ENDIAN);
	tvb_offset += item_size;

	/* Get Control */
	guint8 control = tvb_get_guint8(tvb, tvb_offset);
	gboolean isIM1 = ((control & MASK_SAMPLES_CONTROL_VERSION) == 0);
	gboolean isIM2R0 = ((control & MASK_SAMPLES_CONTROL_VERSION) == MASK_SAMPLES_CONTROL_VERSION);
	gboolean isCIM = ((control & MASK_SAMPLES_CONTROL_TYPE) == 0);

	/* Control */
	item_size = 1;
	tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
	proto_item *control_item = proto_tree_add_bitmask(samples_item_subtree, tvb, tvb_offset, hf_samples_control, hst_samples_control, controlBits, ENC_BIG_ENDIAN);
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
		proto_tree *sample_sets_subtree = proto_item_add_subtree(samples_item, hst_samples_sets);

		if (im1) {
			item_size = SAMPLE_SET_SIZE * 6;
		} else {
			item_size = SAMPLE_SET_SIZE * 8;
		}
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_item *sample_sets_subtree_item = proto_tree_add_item(sample_sets_subtree, hf_samples_sample_set, tvb, tvb_offset, item_size, ENC_NA);

		proto_tree *sample_sets_subtree_item_subtree = proto_item_add_subtree(sample_sets_subtree_item, hst_samples_sets_set);

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
		proto_tree *rms_values_subtree = proto_item_add_subtree(samples_item, hst_samples_rms);

		if (im1) {
			item_size = 4 * 6;
		} else {
			item_size = 4 * 8;
		}
		tvb_ensure_bytes_exist(tvb, tvb_offset, item_size);
		proto_item *rms_values_item = proto_tree_add_item(rms_values_subtree, hf_samples_rms_values, tvb, tvb_offset, item_size, ENC_NA);

		proto_tree *rms_values_item_subtree = proto_item_add_subtree(rms_values_item, hst_samples_rms_values);

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

	return tvb_captured_length(tvb);
}

/*
 * ########################################################################
 * #
 * # Samples - IM1
 * #
 * ########################################################################
 */

static void samples_transport_delay(gchar *result, guint16 transport_delay) {
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

static void samples_sequence_number(gchar *result, guint8 sequence_number) {
	snprintf(result, ITEM_LABEL_LENGTH, "%u", sequence_number);
}

static void samples_temperature(gchar *result, gint16 temperature) {
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
    {&hf_samples_control_simulated, {"Status", "locamation-im.samples.control.simulated", FT_UINT8, BASE_DEC, VALS(samples_control_simulated_vals), MASK_SAMPLES_CONTROL_SIMULATED, NULL, HFILL}},
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
	return dissect_samples_im(TRUE, tvb, pinfo, tree, data, h_protocol_samples_im1);
}

/*
 * ########################################################################
 * #
 * # Samples - IM2R0
 * #
 * ########################################################################
 */

static ei_register_info ei_samples_im2r0[] = {
    {&ei_samples_im_version_invalid, {"locamation-im.samples.control.version.invalid", PI_MALFORMED, PI_ERROR, "Invalid Version", EXPFILL}}};

static int h_protocol_samples_im2r0 = -1;

static int dissect_samples_im2r0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	return dissect_samples_im(FALSE, tvb, pinfo, tree, data, h_protocol_samples_im2r0);
}

/*
 * ########################################################################
 * #
 * # LLC
 * #
 * ########################################################################
 */

static int hf_llc_company_pid = -1;

static hf_register_info llc_registration[] = {
    {&hf_llc_company_pid, {"PID", "locamation-im.llc.pid", FT_UINT16, BASE_HEX, VALS(company_pid_vals), 0x0, "Protocol ID", HFILL}}};

/*
 * ########################################################################
 * #
 * # Registration
 * #
 * ########################################################################
 */

static gint *protocol_subtree[] = {
    &hst_protocol_calibration,
    &hst_calibration_lines,

    &hst_protocol_ident,
    &hst_ident_lines,

    &hst_samples_sample_set_ranges,
    &hst_protocol_samples,
    &hst_samples_control,
    &hst_samples_sets,
    &hst_samples_sets_set,
    &hst_samples_rms,
    &hst_samples_rms_values};

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
	proto_register_field_array(h_protocol_samples_im2r0, NULL, 0);
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
