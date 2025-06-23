/* packet-idn.c
 * Routines for IDN dissection
 * By Maxim Kropp <maxim.kropp@hotmail.de>
 * Copyright 2017 Maxim Kropp
 *
 * Supervised by Matthias Frank <matthew@cs.uni-bonn.de>
 * Copyright 2017 Matthias Frank, Institute of Computer Science 4, University of Bonn
 *
 * Stream Specification: https://www.ilda.com/resources/StandardsDocs/ILDA_IDN-Stream_rev001.pdf
 * This specification only defines IDN messages, the other packet commands
 * are part of the hello specification which is not released yet.
 * All ILDA Technical Standards can be found at https://www.ilda.com/technical.htm
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include <wsutil/array.h>

#define IDN_PORT 7255

#define MAX_CHANNELS	512
#define MAX_BUFFER		2048

/* Packet Commands */
#define IDNCMD_VOID							0x00
#define IDNCMD_PING_REQUEST					0x08
#define IDNCMD_PING_RESPONSE				0x09
#define IDNCMD_SCAN_REQUEST					0x10
#define IDNCMD_SCAN_RESPONSE				0x11
#define IDNCMD_SERVICEMAP_REQUEST			0x12
#define IDNCMD_SERVICEMAP_RESPONSE			0x13
#define IDNCMD_MESSAGE						0x40
#define IDNCMD_MESSAGE_ACKREQ				0x41
#define IDNCMD_MESSAGE_CLOSE				0x44
#define IDNCMD_MESSAGE_ACKREQ_CLOSE			0x45
#define IDNCMD_MESSAGE_ACK					0x47

/* Chunk Types */
#define IDNCT_VOID				0x00
#define IDNCT_LP_WAVE_SAMPLE	0x01
#define IDNCT_LP_FRAME_CHUNK	0x02
#define IDNCT_LP_FRAME_FF		0x03
#define IDNCT_LP_FRAME_SF		0xC0
#define IDNCT_OCTET_SEGMENT		0x10
#define IDNCT_OCTET_STRING		0x11
#define IDNCT_DIMMER_LEVELS		0x18
#define IDNCT_AUDIO_WAVE_SAMPLE		0x20

/* Service Modes (CONT = continuous stream, DISC = discrete stream) */
#define IDNSM_VOID				0x00
#define IDNSM_LP_GRAPHIC_CONT	0x01
#define IDNSM_LP_GRAPHIC_DISC	0x02
#define IDNSM_LP_EFFECTS_CONT	0x03
#define IDNSM_LP_EFFECTS_DISC	0x04
#define IDNSM_DMX512_CONT		0x05
#define IDNSM_DMX512_DISC		0x06
#define IDNSM_AUDIO_WAVE_SEGMENTS	0x0C

/* Dictionary Tags */
#define IDNTAG_PRECISION			0x4010
#define IDNTAG_WAVELENGTH_PREFIX	0x5C00
#define IDNTAG_INTENSITY			0x5C10
#define IDNTAG_BEAM_BRUSH			0x5C20
#define IDNTAG_BREAK_START			0x1000
#define IDNTAG_BREAK_END			0x100F
#define IDNTAG_SPACE_MOD_START		0x1100
#define IDNTAG_SPACE_MOD_END		0x11FF
#define IDNTAG_NOP					0x4000
#define IDNTAG_HINT0				0x4100
#define IDNTAG_HINT1				0x4101
#define IDNTAG_COLOR_START			0x5000
#define IDNTAG_COLOR_END			0x53FF
#define IDNTAG_COLOR_RED			0x527E
#define IDNTAG_COLOR_GREEN			0x5214
#define IDNTAG_COLOR_BLUE			0x51CC
#define IDNTAG_OPTIONAL_U1			0x51BD
#define IDNTAG_OPTIONAL_U2			0x5241
#define IDNTAG_OPTIONAL_U3			0x51E8
#define IDNTAG_OPTIONAL_U4			0x4201
#define IDNTAG_COORD_X				0x4200
#define IDNTAG_COORD_X_END			0x420F
#define IDNTAG_COORD_Y				0x4210
#define IDNTAG_COORD_Y_END			0x421F
#define IDNTAG_COORD_Z				0x4220
#define IDNTAG_COORD_Z_END			0x422F
#define IDNTAG_DIMMER_START			0x0040
#define IDNTAG_DIMMER_END			0x004F

/* Other */
#define IDNO_VOID_AREA	0xF

typedef struct {
	bool has_config_header;
	bool is_dmx;
	uint16_t total_size;
	uint8_t channel_id;
	uint8_t chunk_type;
	gboolean is_audio;
} message_info;

typedef struct {
	uint8_t word_count;
	uint8_t sdm;
	char *dic_precision;
	wmem_strbuf_t *sample_column_string;
	int sample_size;
	int *count;
	int *base;
	guint8 audio_format;
	guint8 audio_channels;
} configuration_info;

void proto_register_idn(void);
void proto_reg_handoff_idn(void);

static dissector_handle_t idn_handle;

static int proto_idn;

static int ett_idn;
static int ett_idn_header_tree;
static int ett_idn_scanreply_header_tree;
static int ett_idn_channel_message_header_tree;
static int ett_protocol_version;
static int ett_unit_id;
static int ett_status;
static int ett_idn_cnl;
static int ett_configuration_header;
static int ett_chunk_header_tree;
static int ett_chunk_header_flags;
static int ett_cfl;
static int ett_dic;
static int ett_dic_tree;
static int ett_data;
static int ett_subdata;
static int ett_dmx_subtree;
static int ett_audio_header;
static int ett_audio_samples;

static expert_field ei_idn_no_config;
static expert_field ei_idn_scwc_unknown;
static expert_field ei_idn_channels_over;
static expert_field ei_idn_scm_mismatch;

/* IDN-Header */
static int hf_idn_command;
static int hf_idn_flags;
static int hf_idn_sequence;
static int hf_idn_total_size;

/* Scanreply Header */
static int hf_idn_struct_size;
static int hf_idn_protocol_version;
static int hf_idn_protocol_version_major;
static int hf_idn_protocol_version_minor;
static int hf_idn_status;
static int hf_idn_malfn;
static int hf_idn_offline;
static int hf_idn_xcld;
static int hf_idn_ocpd;
static int hf_idn_rt;
static int hf_idn_reserved8;
static int hf_idn_unit_id;
static int hf_idn_uid_length;
static int hf_idn_uid_category;
static int hf_idn_uid;
static int hf_idn_name;

/* Service Map Response */
static int hf_idn_entry_size;
static int hf_idn_relay_count;
static int hf_idn_service_count;
static int hf_idn_relay_number;

/* Channel Message Header */
static int hf_idn_cnl;
static int hf_idn_most_significant_bit_cnl;
static int hf_idn_cclf;
static int hf_idn_channel_id;
static int hf_idn_chunk_type;
static int hf_idn_timestamp;

/* Configuration Header */
static int hf_idn_scwc;
static int hf_idn_cfl;
static int hf_idn_sdm;
static int hf_idn_close;
static int hf_idn_routing;
static int hf_idn_service_id;
static int hf_idn_service_mode;

/* Chunk Header */
static int hf_idn_chunk_header_flags;
static int hf_idn_two_bits_reserved_1;
static int hf_idn_two_bits_reserved_2;
static int hf_idn_three_bits_reserved;
static int hf_idn_four_bits_reserved;
static int hf_idn_scm;
static int hf_idn_once;
static int hf_idn_duration;
static int hf_idn_chunk_data_sequence;
static int hf_idn_offset;
static int hf_idn_dlim;
static int hf_idn_reserved;

/* Audio Dictionary Tags */
static int hf_idn_audio_dictionary_tag;
static int hf_idn_category;
static int hf_idn_format;
static int hf_idn_subcategory;
static int hf_idn_parameter;
static int hf_idn_suffix_length;
static int hf_idn_layout;
static int hf_idn_4bit_channels;
static int hf_idn_8bit_channels;

/* Audio Header */
static int hf_idn_audio_flags;
static int hf_idn_audio_duration;
static int hf_idn_audio_flags_two_bits_reserved;
static int hf_idn_audio_flags_four_bits_reserved;
static int hf_idn_audio_flags_scm;

/* Audio Samples */
static int hf_idn_audio_sample_format_zero;
static int hf_idn_audio_sample_format_one;
static int hf_idn_audio_sample_format_two;
/* Tags */
static int hf_idn_gts;
static int hf_idn_gts_void;
static int hf_idn_boundary;
static int hf_idn_gts_word;
static int hf_idn_gts_break;
static int hf_idn_gts_space_modifier;
static int hf_idn_gts_hint;
static int hf_idn_gts_category;
static int hf_idn_gts_subcategory;
static int hf_idn_gts_identifier;
static int hf_idn_gts_parameter;
static int hf_idn_gts_glin;
static int hf_idn_gts_clin;
static int hf_idn_gts_cbal;
static int hf_idn_gts_ctim;
static int hf_idn_gts_nop;
static int hf_idn_gts_precision;
static int hf_idn_gts_cscl;
static int hf_idn_gts_iscl;
static int hf_idn_gts_sht;
static int hf_idn_gts_u4;
static int hf_idn_gts_x;
static int hf_idn_gts_y;
static int hf_idn_gts_z;
static int hf_idn_gts_color;
static int hf_idn_gts_wavelength_prefix;
static int hf_idn_gts_intensity;
static int hf_idn_gts_beam_brush;
static int hf_idn_gts_sample;
static int hf_idn_dmx_octet;
static int hf_idn_dmx_identifier;
static int hf_idn_dmx_parameter;
static int hf_idn_dmx_void;
static int hf_idn_octet;
static int hf_idn_dmx_base;
static int hf_idn_dmx_count;
static int hf_idn_dmx_dls;
static int hf_idn_dmx_unknown;

/* Acknowledgement */
static int hf_idn_result_code;
static int hf_idn_event_flags;

/* Long Bitmasks that need defining */


static const value_string command_code[] = {
	{ IDNCMD_VOID, "VOID" },
	{ IDNCMD_PING_REQUEST, "PING_REQUEST" },
	{ IDNCMD_PING_RESPONSE, "PING_RESPONSE" },
	{ IDNCMD_SCAN_REQUEST, "SCAN_REQUEST" },
	{ IDNCMD_SCAN_RESPONSE, "SCAN_RESPONSE" },
	{ IDNCMD_SERVICEMAP_REQUEST, "SERVICEMAP_REQUEST" },
	{ IDNCMD_SERVICEMAP_RESPONSE, "SERVICEMAP_RESPONSE" },
	{ IDNCMD_MESSAGE, "MESSAGE" },
	{ IDNCMD_MESSAGE_ACKREQ, "MESSAGE_ACKREQ" },
	{ IDNCMD_MESSAGE_CLOSE, "MESSAGE_CLOSE" },
	{ IDNCMD_MESSAGE_ACKREQ_CLOSE, "MESSAGE_ACKREQ_CLOSE" },
	{ IDNCMD_MESSAGE_ACK, "MESSAGE_ACK" },
	{ 0, NULL}
};
static const value_string chunk_type[] = {
	{ IDNCT_VOID, "VOID" },
	{ IDNCT_LP_WAVE_SAMPLE, "Laser Projector Wave Samples" },
	{ IDNCT_LP_FRAME_CHUNK, "Laser Projector Frame Samples (entire chunk)" },
	{ IDNCT_LP_FRAME_FF, "Laser Projector Frame Samples (first fragment)" },
	{ IDNCT_OCTET_SEGMENT, "Octet Segment" },
	{ IDNCT_OCTET_STRING, "Octet String" },
	{ IDNCT_DIMMER_LEVELS, "Dimmer Levels" },
	{ IDNCT_LP_FRAME_SF, "Laser Projector Frame Samples (sequel fragment)" },
	{ IDNCT_AUDIO_WAVE_SAMPLE, "Audio Wave Samples"},
	{ 0, NULL}
};
static const value_string chunk_type_header[] = {
	{ IDNCT_LP_WAVE_SAMPLE, "Wave Sample" },
	{ IDNCT_LP_FRAME_CHUNK, "Frame Sample" },
	{ IDNCT_LP_FRAME_FF, "Frame Sample" },
	{ IDNCT_OCTET_SEGMENT, "Octet Segment" },
	{ IDNCT_OCTET_STRING, "Octet String" },
	{ IDNCT_DIMMER_LEVELS, "Dimmer Levels" },
	{ 0, NULL}
};
static const value_string cfl_string[] = {
	{ 0x30, "DATA_MATCH" },
	{ 0x01, "ROUTING" },
	{ 0x02, "CLOSE" },
	{ 0, NULL}
};
static const value_string service_mode_string[] = {
	{ IDNSM_VOID, "VOID" },
	{ IDNSM_LP_GRAPHIC_CONT, "Laser Projector Graphic (Continuous)" },
	{ IDNSM_LP_GRAPHIC_DISC, "Laser Projector Graphic (Discrete)" },
	{ IDNSM_LP_EFFECTS_CONT, "Laser Projector Effects (Continuous)" },
	{ IDNSM_LP_EFFECTS_DISC, "Laser Projector Effects (Discrete)" },
	{ IDNSM_DMX512_CONT, "DMX512 (Continuous)" },
	{ IDNSM_DMX512_DISC, "DMX512 (Discrete)" },
	{ IDNSM_AUDIO_WAVE_SEGMENTS, "Audio: Stream of waveform segments"},
	{ 0, NULL}
};
static const value_string gts_glin[] = {
	{ 0, "Projector specific" },
	{ 1, "Geometrically corrected and linear, aspect ratio 1:1" },
	{ 2, "Reserved" },
	{ 3, "No transformation" },
	{ 0, NULL}
};
static const value_string gts_clin[] = {
	{ 0, "Projector specific" },
	{ 1, "Power linear (half value SHALL be half power)" },
	{ 2, "Visually linear (half value SHALL be half brightness)" },
	{ 3, "No transformation" },
	{ 0, NULL}
};
static const value_string gts_cbal[] = {
	{ 0, "Projector specific" },
	{ 1, "White balanced" },
	{ 2, "Reserved" },
	{ 3, "No transformation" },
	{ 0, NULL}
};
static const value_string gts_ctim[] = {
	{ 0, "Projector specific" },
	{ 1, "Coordinates and colors correlated in time" },
	{ 2, "Reserved" },
	{ 3, "No transformation" },
	{ 0, NULL}
};
static const value_string idn_color[] = {
	{ 638, "Red" },
	{ 532, "Green" },
	{ 460, "Blue" },
	{ 445, "Optional(U1), used as deep blue" },
	{ 577, "Optional(U2), used as yellow" },
	{ 488, "Optional(U3), used as cyan" },
	{ 0, NULL}
};
static const value_string idn_cat_color[] = {
	{ IDNTAG_OPTIONAL_U1, "U1" },
	{ IDNTAG_COLOR_BLUE, "B" },
	{ IDNTAG_OPTIONAL_U3, "U3" },
	{ IDNTAG_COLOR_GREEN, "G" },
	{ IDNTAG_OPTIONAL_U2, "U2" },
	{ IDNTAG_COLOR_RED, "R" },
	{ 0, NULL}
};
static const value_string result_code[] = {
	{ 0x00, "Message successfully received and passed to the IDN session" },
	{ 0xEB, "Empty (no message) close command without established connection" },
	{ 0xEC, "All sessions are occupied by clients (new connection refused)" },
	{ 0xED, "The client group is excluded from streaming" },
	{ 0xEE, "Invalid payload" },
	{ 0xEF, "Any other processing error" },
	{ 0, NULL}
};

static const value_string category[] _U_= {
	{ 0x0, "Decoder modifiers with suffix" },
	{ 0x1, "Decoder modifiers with parameter" },
	{ 0x4, "Sample word descriptors" },
	{ 0x6, "Common channel layout descriptors" },
	{ 0x8, "Multichannel layout descriptors" },
	{ 0, NULL }
};

static const value_string format[] _U_={
	{ 0x0, "8 Bit signed integer (one octet)" },
	{ 0x1, "16 Bit signed integer (two octets)" },
	{ 0x2, "24 Bit signed integer (three octets)" },
	{ 0, NULL }
};

static int get_service_match(uint8_t flags) {
	return flags >> 4;
}

static void determine_message_type(packet_info *pinfo, message_info *minfo) {
	minfo->is_dmx = 0;
	minfo->is_audio = 0;
	switch(minfo->chunk_type) {
		case IDNCT_VOID:
			col_append_str(pinfo->cinfo, COL_INFO, "-VOID");
			break;
		case IDNCT_LP_WAVE_SAMPLE:
			col_append_str(pinfo->cinfo, COL_INFO, "-WAVE");
			break;
		case IDNCT_LP_FRAME_CHUNK:
			col_append_str(pinfo->cinfo, COL_INFO, "-FRAME");
			break;
		case IDNCT_LP_FRAME_FF:
			col_append_str(pinfo->cinfo, COL_INFO, "-FIRST");
			break;
		case IDNCT_DIMMER_LEVELS:
			col_append_str(pinfo->cinfo, COL_INFO, "-DMX");
			minfo->is_dmx = 1;
			break;
		case IDNCT_OCTET_STRING:
			col_append_str(pinfo->cinfo, COL_INFO, "-DMX");
			minfo->is_dmx = 1;
			break;
		case IDNCT_OCTET_SEGMENT:
			col_append_str(pinfo->cinfo, COL_INFO, "-DMX");
			minfo->is_dmx = 1;
			break;
		case IDNCT_LP_FRAME_SF:
			if(minfo->has_config_header) {
				col_append_str(pinfo->cinfo, COL_INFO, "-LAST");
			}else {
				col_append_str(pinfo->cinfo, COL_INFO, "-SEQ");
			}
			break;
		case IDNCT_AUDIO_WAVE_SAMPLE:
			col_append_str(pinfo->cinfo, COL_INFO, "-AUDIO");
			minfo->is_audio = 1;
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, "-UNKNOWN");
	}
}

static int dissect_idn_message_acknowledgement(tvbuff_t *tvb, int offset, proto_tree *idn_tree) {
	proto_tree *idn_message_acknowledgement_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 4, ett_idn_header_tree, NULL, "Message Acknowledgement");
	proto_tree_add_item(idn_message_acknowledgement_tree, hf_idn_struct_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_message_acknowledgement_tree, hf_idn_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_message_acknowledgement_tree, hf_idn_event_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

static configuration_info *get_configuration_info(packet_info *pinfo, int channel_id) {
	configuration_info *config = NULL;

	conversation_element_t *conv_key = wmem_alloc_array(pinfo->pool, conversation_element_t, 6);
	conv_key[0].type = CE_ADDRESS;
	conv_key[0].addr_val = pinfo->src;
	conv_key[1].type = CE_PORT;
	conv_key[1].port_val = pinfo->srcport;
	conv_key[2].type = CE_ADDRESS;
	conv_key[2].addr_val = pinfo->dst;
	conv_key[3].type = CE_PORT;
	conv_key[3].port_val = pinfo->destport;
	conv_key[4].type = CE_UINT;
	conv_key[4].uint_val = channel_id;
	conv_key[5].type = CE_CONVERSATION_TYPE;
	conv_key[5].conversation_type_val = CONVERSATION_IDN;

	conversation_t *conv = find_conversation_full(pinfo->num, conv_key);
	if(conv) {
		wmem_tree_t *config_tree = (wmem_tree_t*)conversation_get_proto_data(conv, proto_idn);
		if (config_tree) {
			config = (configuration_info *)wmem_tree_lookup32_le(config_tree, pinfo->num);
		}
	}

	return config;
}

static int dissect_idn_dmx_sample_values(tvbuff_t *tvb, packet_info* pinfo, int offset, proto_tree *idn_dmx_subtree, uint16_t data_size, int base) {
	int i, j;
	short int rest;
	wmem_strbuf_t* values;

	for(i=0; i+16<=data_size; i+=16) {
		values = wmem_strbuf_new(pinfo->pool, "");
		for(j=1; j<16; j++){
			wmem_strbuf_append_printf(values, " %3d", tvb_get_uint8(tvb, offset+j));
		}
		proto_tree_add_bytes_format(idn_dmx_subtree, hf_idn_gts_sample, tvb, offset, 16, NULL, "%3d: %s", base+i, wmem_strbuf_get_str(values));
		offset += 16;
	}
	rest = data_size - i;
	if(rest > 0) {
		values = wmem_strbuf_new(pinfo->pool, "");
		for(j=0; j<rest; j++){
			wmem_strbuf_append_printf(values, " %3d", tvb_get_uint8(tvb, offset+j));
		}
		proto_tree_add_bytes_format(idn_dmx_subtree, hf_idn_gts_sample, tvb, offset, rest, NULL, "%3d: %s", base+i, wmem_strbuf_get_str(values));
		offset += rest;
	}
	return offset;
}

static void set_laser_sample_values_string(tvbuff_t *tvb, int offset, configuration_info *config, wmem_strbuf_t* values) {
	int i;
	if((config->dic_precision)[2] == 1)
		wmem_strbuf_append_printf(values, "%5d", tvb_get_uint16(tvb, offset, 2));
	else
		wmem_strbuf_append_printf(values, "%5d", tvb_get_uint8(tvb, offset));

	for(i=1; i<config->sample_size; i++){
		if((config->dic_precision)[i+1] == 1) {
			//do nothing
		}else if((config->dic_precision)[i+2] == 1) {
			wmem_strbuf_append_printf(values, " %5d", tvb_get_uint16(tvb, offset+i, 2));
			i++;
		}else {
			wmem_strbuf_append_printf(values, " %5d", tvb_get_uint8(tvb, offset+i));
		}
	}
}

static int dissect_idn_octet_segment(tvbuff_t *tvb, packet_info* pinfo, int offset, proto_tree *idn_tree) {
	int i, j;
	short int rest;
	wmem_strbuf_t* values;
	int data_size = tvb_reported_length_remaining(tvb, offset);
	proto_tree *idn_samples_tree = proto_tree_add_subtree(idn_tree, tvb, offset, data_size, ett_data, NULL, "Octets");

	for(i=0; i+16<=data_size; i+=16) {
		values = wmem_strbuf_new(pinfo->pool, "");
		for(j=0; j<16; j++){
			wmem_strbuf_append_printf(values, " %3d", tvb_get_int8(tvb, offset+j));
		}
		proto_tree_add_bytes_format(idn_samples_tree, hf_idn_gts_sample, tvb, offset, 16, NULL, "%s", wmem_strbuf_get_str(values));
		offset += 16;
	}
	rest = data_size - i;
	if(rest > 0) {
		values = wmem_strbuf_new(pinfo->pool, "");
		for(j=0; j<rest; j++){
			wmem_strbuf_append_printf(values, " %3d", tvb_get_int8(tvb, offset+j));
		}
		proto_tree_add_bytes_format(idn_samples_tree, hf_idn_gts_sample, tvb, offset, rest, NULL, "%s", wmem_strbuf_get_str(values));
		offset += rest;
	}
	return offset;
}

static int dissect_idn_dmx_data(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *idn_tree, configuration_info *config) {
	int i;
	int *count = config->count;
	int *base = config->base;
	int base_value;
	int data_size = tvb_reported_length_remaining(tvb, offset);
	proto_tree *idn_samples_tree = proto_tree_add_subtree(idn_tree, tvb, offset, data_size, ett_data, NULL, "Channels");
	proto_tree *idn_dmx_subtree;

	for(i=0; i<config->word_count; i++) {
		base_value = base[i]-1;
		if(base_value == -1)
			break;
		if(count[i] != -1) {
			data_size = count[i];
			if(data_size + base_value > MAX_CHANNELS) {
				expert_add_info_format(pinfo, idn_samples_tree, &ei_idn_channels_over, "Over %5d Channels", MAX_CHANNELS);
				return offset;
			}
			idn_dmx_subtree = proto_tree_add_subtree_format(idn_samples_tree, tvb, offset, data_size, ett_dmx_subtree, NULL, "Range: %3d - %3d", base[i], base_value+data_size);
		}else {
			int	base_size = MAX_CHANNELS - base_value;
			data_size = tvb_reported_length_remaining(tvb, offset);
			if(data_size > base_size) {
				data_size = base_size;
			}
			if(data_size + base_value > MAX_CHANNELS) {
				data_size = MAX_CHANNELS - base_value;
			}
			idn_dmx_subtree = proto_tree_add_subtree_format(idn_samples_tree, tvb, offset, data_size, ett_dmx_subtree, NULL, "Range: %3d - %3d", base[i], base_value+data_size);
		}
		offset = dissect_idn_dmx_sample_values(tvb, pinfo, offset, idn_dmx_subtree, data_size, base_value);
	}
	return offset;
}

static int dissect_idn_laser_data(tvbuff_t *tvb, packet_info* pinfo, int offset, proto_tree *idn_tree, configuration_info *config) {
	int i;
	int laser_data_size = tvb_reported_length_remaining(tvb, offset);
	wmem_strbuf_t* values;

	if (config->sample_size == 0) {
		/* TODO: log expert info error? */
		return 0;
	}

	int sample_size = laser_data_size/config->sample_size;
	proto_tree *idn_samples_tree = proto_tree_add_subtree_format(idn_tree, tvb, offset, laser_data_size, ett_data, NULL, "Samples %s", wmem_strbuf_get_str(config->sample_column_string));
	proto_tree *idn_samples_subtree = NULL;

	for(i=1; i<=sample_size; i++) {
		if((i-1)%10 == 0 && i+10 > sample_size) {
			idn_samples_subtree = proto_tree_add_subtree_format(idn_samples_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_subdata, NULL, "Samples %3d - %3d", i, sample_size);
		}else if((i-1)%10 == 0) {
			idn_samples_subtree = proto_tree_add_subtree_format(idn_samples_tree, tvb, offset, config->sample_size*10, ett_subdata, NULL, "Samples %3d - %3d", i, i+9);
		}
		values = wmem_strbuf_new(pinfo->pool, "");
		set_laser_sample_values_string(tvb, offset, config, values);
		proto_tree_add_bytes_format(idn_samples_subtree, hf_idn_gts_sample, tvb, offset, config->sample_size, NULL,  "Sample %3d: %s", i, wmem_strbuf_get_str(values));
		offset += config->sample_size;
	}
	return offset;
}

static int dissect_idn_dimmer_levels_chunk_header(tvbuff_t *tvb, int offset, proto_tree* chunk_header_tree, proto_tree* flag_tree) {

	proto_tree_add_item(flag_tree, hf_idn_four_bits_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(chunk_header_tree, hf_idn_reserved, tvb, offset, 3, ENC_NA);
	offset += 3;
	return offset;
}

static int dissect_idn_octet_string_chunk_header(tvbuff_t *tvb, int offset, proto_tree* chunk_header_tree, proto_tree* flag_tree) {

	proto_tree_add_item(flag_tree, hf_idn_four_bits_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(chunk_header_tree, hf_idn_reserved, tvb, offset, 3, ENC_NA);
	offset += 3;
	return offset;
}

static int dissect_idn_octet_segment_chunk_header(tvbuff_t *tvb, int offset, proto_tree* chunk_header_tree, proto_tree* flag_tree) {

	proto_tree_add_item(flag_tree, hf_idn_three_bits_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flag_tree, hf_idn_dlim, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(chunk_header_tree, hf_idn_chunk_data_sequence, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(chunk_header_tree, hf_idn_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

static int dissect_idn_frame_chunk_header(tvbuff_t *tvb, int offset, proto_tree* chunk_header_tree, proto_tree* flag_tree) {

	proto_tree_add_item(flag_tree, hf_idn_three_bits_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flag_tree, hf_idn_once, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(chunk_header_tree, hf_idn_duration, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	return offset;
}

static int dissect_idn_wave_chunk_header(tvbuff_t *tvb, int offset, proto_tree* chunk_header_tree, proto_tree* flag_tree) {

	proto_tree_add_item(flag_tree, hf_idn_four_bits_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(chunk_header_tree, hf_idn_duration, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	return offset;
}

static int dissect_idn_chunk_header(tvbuff_t* tvb, packet_info* pinfo, int offset, proto_tree* idn_tree, message_info* minfo, configuration_info* config) {

	proto_tree *chunk_header_tree, *flag_tree;
	proto_item *flag_item, *scm_item;
	uint32_t scm;

	switch (minfo->chunk_type) {
		case IDNCT_LP_WAVE_SAMPLE:
		case IDNCT_LP_FRAME_CHUNK:
		case IDNCT_LP_FRAME_FF:
		case IDNCT_OCTET_SEGMENT:
		case IDNCT_OCTET_STRING:
		case IDNCT_DIMMER_LEVELS:
			chunk_header_tree = proto_tree_add_subtree_format(idn_tree, tvb, offset, 4, ett_chunk_header_tree, NULL, "%s Chunk Header", val_to_str_const(minfo->chunk_type, chunk_type_header, "Unknown"));
			flag_item = proto_tree_add_item(chunk_header_tree, hf_idn_chunk_header_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
			flag_tree = proto_item_add_subtree(flag_item, ett_chunk_header_flags);
			proto_tree_add_item(flag_tree, hf_idn_two_bits_reserved_1, tvb, offset, 1, ENC_BIG_ENDIAN);
			scm_item = proto_tree_add_item_ret_uint(flag_tree, hf_idn_scm, tvb, offset, 1, ENC_BIG_ENDIAN, &scm);
			if (config->sdm != scm) {
				expert_add_info(pinfo, scm_item, &ei_idn_scm_mismatch);
				return offset;
			}

			switch (minfo->chunk_type) {
			case IDNCT_LP_WAVE_SAMPLE:
				offset = dissect_idn_wave_chunk_header(tvb, offset, chunk_header_tree, flag_tree);
				break;
			case IDNCT_LP_FRAME_CHUNK:
			case IDNCT_LP_FRAME_FF:
				offset = dissect_idn_frame_chunk_header(tvb, offset, chunk_header_tree, flag_tree);
				break;
			case IDNCT_OCTET_SEGMENT:
				offset = dissect_idn_octet_segment_chunk_header(tvb, offset, chunk_header_tree, flag_tree);
				break;
			case IDNCT_OCTET_STRING:
				offset = dissect_idn_octet_string_chunk_header(tvb, offset, chunk_header_tree, flag_tree);
				break;
			case IDNCT_DIMMER_LEVELS:
				offset = dissect_idn_dimmer_levels_chunk_header(tvb, offset, chunk_header_tree, flag_tree);
				break;
			}
			break;
		default:
			return offset;
	}
	return offset;
}

static int dissect_idn_dmx_gts(tvbuff_t *tvb, int offset, proto_tree *gts_tree, const int hf_hdr, int *dictionary_size) {
	static int * const gts[] = {
		&hf_idn_dmx_identifier,
		&hf_idn_dmx_parameter,
		NULL
	};
	proto_tree_add_bitmask(gts_tree, tvb, offset, hf_hdr, ett_dic, gts, ENC_BIG_ENDIAN);
	offset++;
	if(dictionary_size)
		(*dictionary_size)++;

	return offset;
}

static int dissect_idn_dimmer_level_subset(tvbuff_t *tvb, int offset, proto_tree *gts_tree, configuration_info *config, int i, int *dictionary_size) {
	uint8_t dls = tvb_get_uint8(tvb, offset);
	offset = dissect_idn_dmx_gts(tvb, offset, gts_tree, hf_idn_dmx_dls, dictionary_size);

	if(dls & 2) {
		proto_tree_add_item(gts_tree, hf_idn_dmx_base, tvb, offset, 2, ENC_BIG_ENDIAN);
		config->base[i-1] = tvb_get_uint16(tvb, offset, 2);
		offset += 2;
		(*dictionary_size) += 2;
		if(dls & 1) {
			proto_tree_add_item(gts_tree, hf_idn_dmx_count, tvb, offset, 1, ENC_BIG_ENDIAN);
			config->count[i-1] = tvb_get_uint8(tvb, offset);
			offset++;
			(*dictionary_size)++;
		}else {
			config->count[i-1] = -1;
		}
	}

	return offset;
}

static int dissect_idn_dmx_dictionary(tvbuff_t *tvb, int offset, proto_tree *idn_tree, configuration_info *config) {
	int i, j, curr_size;
	bool words_found = 0;
	int dictionary_size = 0;
	uint8_t idepar; /* idetifier + parameter */
	proto_tree *gts_tree = proto_tree_add_subtree(idn_tree, tvb, offset, -1, ett_dic_tree, NULL, "Dictionary");

	for(i=1; i<=config->word_count; i++) {
		idepar = tvb_get_uint8(tvb, offset);

		if(idepar <= IDNO_VOID_AREA) {
			if(idepar == 0) {
				proto_tree_add_item(gts_tree, hf_idn_dmx_void, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				dictionary_size += 1;
				if(!words_found)
					i -= 1;
			}else {
				offset = dissect_idn_dmx_gts(tvb, offset, gts_tree, hf_idn_dmx_unknown, NULL);
				for(j=1; j<=idepar; j++) {
					proto_tree_add_item(gts_tree, hf_idn_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					dictionary_size += 1;
					if(words_found)
						i += 1;
				}
				if(!words_found)
					i -= 1;
			}
		}else if(idepar >= IDNTAG_DIMMER_START && idepar <= IDNTAG_DIMMER_END) {
			offset = dissect_idn_dimmer_level_subset(tvb, offset, gts_tree, config, i, &dictionary_size);
		}else {
			offset = dissect_idn_dmx_gts(tvb, offset, gts_tree, hf_idn_dmx_unknown, &dictionary_size);
		}

		if(i == config->word_count && !words_found) {
			curr_size = dictionary_size;
			while(curr_size%4 != 0 && i > 0) {
				i -= 1;
				curr_size += 1;
			}
			words_found = 1;
		}
	}
	proto_item_set_len(gts_tree, dictionary_size);

	return offset;
}

static int dissect_idn_laser_gts(tvbuff_t *tvb, int offset, proto_tree *gts_tree, const int hf_hdr, int *dictionary_size, configuration_info *config, bool is_sample) {
	static int * const gts[] = {
		&hf_idn_gts_category,
		&hf_idn_gts_subcategory,
		&hf_idn_gts_identifier,
		&hf_idn_gts_parameter,
		NULL
	};

	proto_tree_add_bitmask(gts_tree, tvb, offset, hf_hdr, ett_dic, gts, ENC_BIG_ENDIAN);

	if(dictionary_size)
		*dictionary_size += 2;
	if(config && is_sample)
		config->sample_size++;

	return offset + 2;
}

static int dissect_idn_x_area(tvbuff_t *tvb, int offset, proto_tree *gts_tree, uint16_t catsub, int *dictionary_size, configuration_info *config) {

	if(catsub == IDNTAG_OPTIONAL_U4) {
		offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_u4, dictionary_size, config, 1);
	}else {
		offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_x, dictionary_size, config, 1);
	}

	return offset;
}

static int dissect_idn_laser_dictionary(tvbuff_t *tvb, int offset, proto_tree *idn_tree, configuration_info *config) {
	int i, j;
	int dictionary_size = 0;
	uint16_t catsub; /* category + subcategory */
	proto_tree *gts_tree = proto_tree_add_subtree(idn_tree, tvb, offset, -1, ett_dic_tree, NULL, "Dictionary");

	/* Reset the sample column data */
	config->sample_column_string = wmem_strbuf_new_len(wmem_file_scope(), "", 0);
	wmem_strbuf_append(config->sample_column_string, "(");
	for(i=1; i<=config->word_count*2; i++) {
		catsub = tvb_get_uint16(tvb, offset, 2);

		if(catsub <= IDNO_VOID_AREA) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_void, &dictionary_size, config, 0);
			if(catsub > 0) {
				for(j=0; j<catsub; j++) {
					offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_void, &dictionary_size, config, 0);
				}
			}
		}else if(catsub == IDNTAG_PRECISION) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_precision, &dictionary_size, config, 1);
			(config->dic_precision)[i] = 1;
		}else if(catsub >= IDNTAG_BREAK_START && catsub <= IDNTAG_BREAK_END) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_break, &dictionary_size, config, 0);
		}else if(catsub >= IDNTAG_SPACE_MOD_START && catsub <= IDNTAG_SPACE_MOD_END) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_space_modifier, &dictionary_size, config, 0);
		}else if(catsub == IDNTAG_NOP) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_nop, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " NOP");
		}else if(catsub >= IDNTAG_HINT0 && catsub <= IDNTAG_HINT1) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_hint, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " H");
		}else if(catsub >= IDNTAG_COORD_X && catsub <= IDNTAG_COORD_X_END) {
			offset = dissect_idn_x_area(tvb, offset, gts_tree, catsub, &dictionary_size, config);
			wmem_strbuf_append(config->sample_column_string, (catsub == IDNTAG_OPTIONAL_U4) ? " U4" : " X");
		}else if(catsub >= IDNTAG_COORD_Y && catsub <= IDNTAG_COORD_Y_END) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_y, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " Y");
		}else if(catsub >= IDNTAG_COORD_Z && catsub <= IDNTAG_COORD_Z_END) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_z, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " Z");
		}else if(catsub >= IDNTAG_COLOR_START && catsub <= IDNTAG_COLOR_END) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_color, &dictionary_size, config, 1);
			wmem_strbuf_append_printf(config->sample_column_string, " %s", val_to_str_const(catsub, idn_cat_color, "C"));
		}else if(catsub == IDNTAG_WAVELENGTH_PREFIX) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_wavelength_prefix, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " WP");
		}else if(catsub == IDNTAG_INTENSITY) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_intensity, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " I");
		}else if(catsub == IDNTAG_BEAM_BRUSH) {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts_beam_brush, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " BB");
		}else {
			offset = dissect_idn_laser_gts(tvb, offset, gts_tree, hf_idn_gts, &dictionary_size, config, 1);
			wmem_strbuf_append(config->sample_column_string, " U/R");
		}
	}
	proto_item_set_len(gts_tree, dictionary_size);
	wmem_strbuf_append(config->sample_column_string, " )");

	return offset;
}

static int dissect_idn_channel_configuration_header(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *idn_tree, int channel_id, configuration_info **config_p) {
	conversation_t *conv;
	uint8_t word_count;
	uint8_t sdm;
	static int * const channel_and_service_configuration_flags[] = {
		&hf_idn_two_bits_reserved_1,
		&hf_idn_sdm,
		&hf_idn_two_bits_reserved_2,
		&hf_idn_close,
		&hf_idn_routing,
		NULL
	};

	col_append_str(pinfo->cinfo, COL_INFO, " (Configuration Header)");
	proto_tree *configuration_header_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 4, ett_configuration_header, NULL, "Channel Configuration Header");
	proto_tree_add_item(configuration_header_tree, hf_idn_scwc, tvb, offset, 1, ENC_BIG_ENDIAN);
	word_count = tvb_get_uint8(tvb, offset);
	offset += 1;
	proto_tree_add_bitmask(configuration_header_tree, tvb, offset, hf_idn_cfl, ett_cfl, channel_and_service_configuration_flags, ENC_BIG_ENDIAN);
	sdm = get_service_match(tvb_get_uint8(tvb, offset));
	offset += 1;
	proto_tree_add_item(configuration_header_tree, hf_idn_service_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(configuration_header_tree, hf_idn_service_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;


	conversation_element_t *conv_key = wmem_alloc_array(pinfo->pool, conversation_element_t, 6);
	conv_key[0].type = CE_ADDRESS;
	conv_key[0].addr_val = pinfo->src;
	conv_key[1].type = CE_PORT;
	conv_key[1].port_val = pinfo->srcport;
	conv_key[2].type = CE_ADDRESS;
	conv_key[2].addr_val = pinfo->dst;
	conv_key[3].type = CE_PORT;
	conv_key[3].port_val = pinfo->destport;
	conv_key[4].type = CE_UINT;
	conv_key[4].uint_val = channel_id;
	conv_key[5].type = CE_CONVERSATION_TYPE;
	conv_key[5].conversation_type_val = CONVERSATION_IDN;

	configuration_info *config;
	conv = find_conversation_full(pinfo->num, conv_key);
	if (!(conv && conv->setup_frame == pinfo->num)) {
		conv = conversation_new_full(pinfo->num, conv_key);
	}
	wmem_tree_t *config_tree = (wmem_tree_t*)conversation_get_proto_data(conv, proto_idn);
	if (!config_tree) {
		config_tree = wmem_tree_new(wmem_file_scope());
		conversation_add_proto_data(conv, proto_idn, config_tree);
	}
	/* XXX: It wastes some memory to allocate a new configuration if it
	 * hasn't changed since the last time it was sent, so we could use
	 * lookup32_le and see if it's the same as the previous, but that
	 * requires doing so after parsing the rest of the configuration.
	 */
	config = (configuration_info *)wmem_tree_lookup32(config_tree, pinfo->num);
	if (config) {
		/* sample size increments as we parse the dictionary, so reset.
		* The other values shouldn't change, though we'll waste time
		* overwriting the array with the same values.
		*/
		config->sample_size = 0;
	} else {
		config = wmem_new0(wmem_file_scope(), configuration_info);
		config->word_count = word_count;
		config->sdm = sdm;
		config->sample_size = 0;
		config->dic_precision = wmem_alloc0_array(wmem_file_scope(), char, (255*2)+1);
		config->sample_column_string = wmem_strbuf_new(wmem_file_scope(), "");
		config->count = wmem_alloc0_array(wmem_file_scope(), int, word_count+1);
		config->base = wmem_alloc0_array(wmem_file_scope(), int, word_count+1);
		wmem_tree_insert32(config_tree, pinfo->num, config);
	}

	*config_p = config;

	return offset;
}

static int dissect_idn_channel_configuration(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *idn_tree, message_info *minfo, configuration_info **config_p) {
	offset = dissect_idn_channel_configuration_header(tvb, pinfo, offset, idn_tree, minfo->channel_id, config_p);

	configuration_info *config = *config_p;
	if(config->word_count > 0) {
		if(minfo->chunk_type == IDNCT_OCTET_SEGMENT || minfo->chunk_type == IDNCT_AUDIO_WAVE_SAMPLE) {
			return offset;
		}else if(minfo->is_dmx) {
			offset = dissect_idn_dmx_dictionary(tvb, offset, idn_tree, config);
		}else {
			offset = dissect_idn_laser_dictionary(tvb, offset, idn_tree, config);
		}
	}

	return offset;
}

static int dissect_idn_message_header(tvbuff_t *tvb, int offset, proto_tree *idn_tree, message_info *minfo) {
	uint8_t cnl;
	static int * const cnl_data[] = {
			&hf_idn_most_significant_bit_cnl,
			&hf_idn_cclf,
			&hf_idn_channel_id,
			NULL
	};

	proto_tree *idn_channel_message_header_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 8, ett_idn_channel_message_header_tree, NULL, "Channel Message Header");
	proto_tree_add_item(idn_channel_message_header_tree, hf_idn_total_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	minfo->total_size = tvb_get_uint16(tvb, offset, 2);
	offset += 2;
	proto_tree_add_bitmask(idn_channel_message_header_tree, tvb, offset, hf_idn_cnl, ett_idn_cnl, cnl_data, ENC_BIG_ENDIAN);

	cnl = tvb_get_uint8(tvb, offset);
	minfo->has_config_header = cnl & 0x40;
	minfo->channel_id = cnl & 0x3f;

	offset += 1;
	proto_tree_add_item(idn_channel_message_header_tree, hf_idn_chunk_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	minfo->chunk_type = tvb_get_uint8(tvb, offset);
	offset += 1;
	proto_tree_add_item(idn_channel_message_header_tree, hf_idn_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

// static int dissect_idn_audio_category_0(tvbuff_t *tvb _U_, packet_info *pinfo _U_, int offset _U_, proto_tree *idn_tree _U_){
// 	static int * const audio_cat_0[] = {
// 		&hf_idn_category,
// 		&hf_idn_subcategory,
// 		&hf_idn_parameter,
// 		&hf_idn_suffix_length,
// 		NULL
// 	};
// 	proto_tree_add_bitmask(idn_tree, tvb, offset, hf_idn_audio_dictionary_tag, ett_audio_header, audio_cat_0, ENC_BIG_ENDIAN);
// 	return offset;
// }

static int dissect_idn_audio_category_8(tvbuff_t *tvb, int offset, proto_tree *idn_tree, configuration_info *cinfo){

	static int * const audio_cat_8[] = {
		&hf_idn_category,
		&hf_idn_format,
		&hf_idn_8bit_channels,
		NULL
	};
	guint8 channels = tvb_get_int8(tvb, offset);
	cinfo->audio_format = channels & 0x0F;
	channels &= 0x00FF;
	cinfo->audio_channels = channels;

	proto_tree_add_bitmask(idn_tree, tvb, offset, hf_idn_audio_dictionary_tag, ett_audio_header, audio_cat_8, ENC_BIG_ENDIAN);

	return offset;
}

static int dissect_idn_audio_category_6(tvbuff_t *tvb, int offset, proto_tree *idn_tree, configuration_info *cinfo){
	//proto_tree_add_item(idn_tree, hf_idn_category, tvb, offset, 1, ENC_BIG_ENDIAN);
	//offset += 1;
	static int * const audio_cat_6[] = {
		&hf_idn_category,
		&hf_idn_format,
		&hf_idn_layout,
		&hf_idn_4bit_channels,
		NULL
	};
	guint8 channels = tvb_get_int8(tvb, offset);
	guint8 audio_format = channels;
	audio_format = audio_format & 0x0F;
	cinfo->audio_format = audio_format;
	channels &= 0x0F;
	cinfo->audio_channels = channels;

	proto_tree_add_bitmask(idn_tree, tvb, offset, hf_idn_audio_dictionary_tag, ett_audio_header, audio_cat_6, ENC_BIG_ENDIAN);
	return offset;
}

static int dissect_idn_audio_dictionary(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *idn_tree, configuration_info *config){
	gint8 det_category;
	gint16 current_tag;
	int tag_count = config->word_count;
	tag_count *= 2;
	proto_item *dictionary_tree = proto_tree_add_subtree(idn_tree, tvb, offset, tag_count, ett_dic_tree, NULL, "Dictionary");

	for(int i = 0; i < tag_count; i++){
		current_tag = tvb_get_uint16(tvb, offset, 2);
		switch (current_tag) {
			case 0x0000:
				//add void tag
				proto_tree_add_item(dictionary_tree, hf_idn_gts_void, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				break;
			default:
				//determing category
				det_category = tvb_get_int8(tvb, offset);
				det_category = det_category >> 4;
				//dissect depending on category
				switch (det_category) {
					case 0x6:
						dissect_idn_audio_category_6(tvb, offset, dictionary_tree, config);
						break;
					case 0x8:
						dissect_idn_audio_category_8(tvb, offset, dictionary_tree, config);
						break;
				}
				offset += 2;
				break;
		}
	}
	return offset;
}

static int dissect_idn_audio_header(tvbuff_t *tvb, int offset, proto_tree *idn_tree){

	static int * const audio_flags[] = {
		&hf_idn_audio_flags_two_bits_reserved,
		&hf_idn_audio_flags_scm,
		&hf_idn_audio_flags_four_bits_reserved,
		NULL
	};

	proto_item *audio_header_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 4, ett_audio_header, NULL, "Audio Header");

	proto_tree_add_bitmask(audio_header_tree, tvb, offset, hf_idn_audio_flags, ett_audio_header, audio_flags, ENC_BIG_ENDIAN);
	offset +=1;

	proto_tree_add_item(audio_header_tree, hf_idn_audio_duration, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+= 3;

	return offset;
}

static int dissect_idn_audio_samples_format_0(tvbuff_t *tvb, int offset, proto_tree *idn_tree){
	int max_samples = tvb_reported_length_remaining(tvb, offset);
	for(int i = 0; i < max_samples; i++){
		proto_tree_add_item(idn_tree, hf_idn_audio_sample_format_zero, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}
	return offset;
}

static int dissect_idn_audio_samples_format_1(tvbuff_t *tvb, int offset, proto_tree *idn_tree){
	int max_samples = tvb_reported_length_remaining(tvb, offset);
	max_samples /= 2;
	for(int i = 0; i < max_samples; i++){
		proto_tree_add_item(idn_tree, hf_idn_audio_sample_format_one, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	return offset;
}

static int dissect_idn_audio_samples_format_2(tvbuff_t *tvb, int offset, proto_tree *idn_tree){
	int max_samples = tvb_reported_length_remaining(tvb, offset);
	max_samples /= 3;
	for(int i = 0; i < max_samples; i++){
		proto_tree_add_item( idn_tree, hf_idn_audio_sample_format_two, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;
	}
	return offset;
}

static int dissect_idn_audio_samples(tvbuff_t *tvb, int offset, proto_tree *idn_tree, configuration_info  * config){
	proto_item *audio_samples_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 4, ett_audio_samples, NULL, "Audio Samples");
	switch (config->audio_format) {
		case 0x00:
			dissect_idn_audio_samples_format_0(tvb, offset, audio_samples_tree);
			break;
		case 0x01:
			dissect_idn_audio_samples_format_1(tvb, offset, audio_samples_tree);
			break;
		case 0x02:
			dissect_idn_audio_samples_format_2(tvb, offset, audio_samples_tree);
			break;
	}
	return offset;
}

static int dissect_idn_audio(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *idn_tree, configuration_info  * config){

	offset = dissect_idn_audio_dictionary(tvb, pinfo, offset, idn_tree, config);
	offset = dissect_idn_audio_header(tvb, offset, idn_tree);
	offset = dissect_idn_audio_samples(tvb, offset, idn_tree, config);
	return offset;
}

static int dissect_idn_message(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *idn_tree) {

	configuration_info *config = NULL;
	message_info minfo;

	offset = dissect_idn_message_header(tvb, offset, idn_tree, &minfo);
	determine_message_type(pinfo, &minfo);
	if(minfo.total_size == 8)
		return offset;

	if(minfo.has_config_header && minfo.chunk_type != IDNCT_LP_FRAME_SF) {
		offset = dissect_idn_channel_configuration(tvb, pinfo, offset, idn_tree, &minfo, &config);
	}else if(minfo.chunk_type != IDNCT_VOID) {
		config = get_configuration_info(pinfo, minfo.channel_id);
	}

	if (config == NULL) {
		expert_add_info(pinfo, idn_tree, &ei_idn_no_config);
		return offset;
	}

	if (config->word_count == 0 && minfo.chunk_type != IDNCT_OCTET_SEGMENT) {
		expert_add_info(pinfo, idn_tree, &ei_idn_scwc_unknown);
		return offset;
	}

	if(minfo.chunk_type != IDNCT_VOID && minfo.chunk_type != IDNCT_LP_FRAME_SF && minfo.chunk_type != IDNCT_AUDIO_WAVE_SAMPLE) {
		offset = dissect_idn_chunk_header(tvb, pinfo, offset, idn_tree, &minfo, config);
	}else if(minfo.chunk_type == IDNCT_VOID) {
		return offset;
	}

	if(minfo.chunk_type == IDNCT_OCTET_SEGMENT) {
		offset = dissect_idn_octet_segment(tvb, pinfo, offset, idn_tree);
	}else if(minfo.is_dmx) {
		offset = dissect_idn_dmx_data(tvb, pinfo, offset, idn_tree, config);
	}else if(minfo.is_audio){
		offset = dissect_idn_audio(tvb, pinfo, offset, idn_tree, config);
	}else {
		offset = dissect_idn_laser_data(tvb, pinfo, offset, idn_tree, config);
	}

	return offset;
}

static int dissect_idn_servicemap_entry(tvbuff_t *tvb, packet_info* pinfo, int offset, proto_tree *idn_tree) {
	uint8_t service_id = tvb_get_uint8(tvb, offset);
	proto_tree *idn_servicemap_entry_tree = NULL;
	proto_item *entry_item;
	const uint8_t* name;

	if(service_id == 0) {
		idn_servicemap_entry_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 24, ett_idn_header_tree, &entry_item, "Relay Entry");
	}else {
		idn_servicemap_entry_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 24, ett_idn_header_tree, &entry_item, "Service Entry");
	}

	proto_tree_add_item(idn_servicemap_entry_tree, hf_idn_service_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_servicemap_entry_tree, hf_idn_service_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_servicemap_entry_tree, hf_idn_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_servicemap_entry_tree, hf_idn_relay_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_string(idn_servicemap_entry_tree, hf_idn_name, tvb, offset, 20, ENC_ASCII, pinfo->pool, &name);
	proto_item_append_text(entry_item, " - %s", name);
	offset += 20;
	return offset;
}

static int dissect_idn_servicemap_response_header(tvbuff_t *tvb, int offset, proto_tree *idn_tree, uint8_t *relay_count, uint8_t *service_count) {
	proto_tree *idn_servicemap_response_header_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 4, ett_idn_header_tree, NULL, "Service Map Response Header");
	proto_tree_add_item(idn_servicemap_response_header_tree, hf_idn_struct_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_servicemap_response_header_tree, hf_idn_entry_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	*relay_count = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(idn_servicemap_response_header_tree, hf_idn_relay_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	*service_count = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(idn_servicemap_response_header_tree, hf_idn_service_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	return offset;
}

static int dissect_idn_servicemap_response(tvbuff_t *tvb, packet_info* pinfo, int offset, proto_tree *idn_tree) {
	uint8_t relay_count, service_count;
	uint16_t map_entries_size;

	offset = dissect_idn_servicemap_response_header(tvb, offset, idn_tree, &relay_count, &service_count);
	map_entries_size = relay_count + service_count;
	proto_tree *idn_servicemap_entries_tree = proto_tree_add_subtree(idn_tree, tvb, offset, map_entries_size*24, ett_idn_header_tree, NULL, "Service Map Entries");
	for(int i=0; i<map_entries_size; i++)
		offset = dissect_idn_servicemap_entry(tvb, pinfo, offset, idn_servicemap_entries_tree);

	return offset;
}

static int dissect_idn_scan_response(tvbuff_t *tvb, int offset, proto_tree *idn_tree) {
	static int * const protocol_version[] = {
			&hf_idn_protocol_version_major,
			&hf_idn_protocol_version_minor,
			NULL
	};
	static int * const status[] = {
			&hf_idn_malfn,
			&hf_idn_offline,
			&hf_idn_xcld,
			&hf_idn_ocpd,
			&hf_idn_three_bits_reserved,
			&hf_idn_rt,
			NULL
	};


	proto_tree *idn_scanreply_header_tree = proto_tree_add_subtree(idn_tree, tvb, offset, 40, ett_idn_header_tree, NULL, "Scan Response");
	proto_tree_add_item(idn_scanreply_header_tree, hf_idn_struct_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_bitmask(idn_scanreply_header_tree, tvb, offset, hf_idn_protocol_version, ett_protocol_version, protocol_version, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_bitmask(idn_scanreply_header_tree, tvb, offset, hf_idn_status, ett_status, status, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_scanreply_header_tree, hf_idn_reserved8, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree *uid_tree = proto_tree_add_subtree(idn_scanreply_header_tree, tvb, offset, 16, ett_unit_id, NULL, "Unit ID");
	proto_tree_add_item(uid_tree, hf_idn_uid_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(uid_tree, hf_idn_uid_category, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(uid_tree, hf_idn_unit_id, tvb, offset, 14, ENC_NA);
	offset += 14;

	proto_tree_add_item(idn_scanreply_header_tree, hf_idn_name, tvb, offset, 20, ENC_ASCII);
	offset += 20;
	return offset;
}

static int dissect_idn_header(tvbuff_t *tvb, int offset, proto_tree *idn_tree, uint8_t packet_type) {
	int header_len = (packet_type == IDNCMD_VOID || packet_type == IDNCMD_PING_RESPONSE) ? 1 : 4;
	proto_tree *idn_header_tree = proto_tree_add_subtree(idn_tree, tvb, offset, header_len, ett_idn_header_tree, NULL, "IDN Header");
	proto_tree_add_item(idn_header_tree, hf_idn_command, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	if (packet_type == IDNCMD_VOID || packet_type == IDNCMD_PING_RESPONSE) {
		return offset;
	}
	proto_tree_add_item(idn_header_tree, hf_idn_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(idn_header_tree, hf_idn_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

static int dissect_idn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	int offset = 0;
	proto_item *ti = proto_tree_add_item(tree, proto_idn, tvb, 0, -1, ENC_NA);
	proto_tree *idn_tree = proto_item_add_subtree(ti, ett_idn);
	uint8_t packet_type = tvb_get_uint8(tvb, 0);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDN");
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type, command_code, "Unknown (0x%02x)"));

	offset = dissect_idn_header(tvb, offset, idn_tree, packet_type);

	switch (packet_type) {
		case IDNCMD_SCAN_RESPONSE:
			dissect_idn_scan_response(tvb, offset, idn_tree);
			break;
		case IDNCMD_SERVICEMAP_RESPONSE:
			offset = dissect_idn_servicemap_response(tvb, pinfo, offset, idn_tree);
			break;
		case IDNCMD_MESSAGE:
		case IDNCMD_MESSAGE_ACKREQ:
		case IDNCMD_MESSAGE_CLOSE:
		case IDNCMD_MESSAGE_ACKREQ_CLOSE:
			offset = dissect_idn_message(tvb, pinfo, offset, idn_tree);
			break;
		case IDNCMD_MESSAGE_ACK:
			offset = dissect_idn_message_acknowledgement(tvb, offset, idn_tree);
			break;
		default:
			break;
	}

	return offset;
}

void proto_register_idn(void) {
	static hf_register_info hf[] = {
		{ &hf_idn_command,
			{ "Command code", "idn.command",
			FT_UINT8, BASE_HEX,
			VALS(command_code), 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_flags,
			{ "Flags", "idn.flags",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_sequence,
			{ "Sequence counter", "idn.sequence",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_total_size,
			{ "Total Size", "idn.total_size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_struct_size,
			{ "Struct Size", "idn.struct_size",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_protocol_version,
			{ "Protocol Version", "idn.protocol_version",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_protocol_version_major,
			{ "Major", "idn.protocol_version_major",
			FT_UINT8, BASE_DEC,
			NULL, 0xF0,
			NULL, HFILL }
		},
		{ &hf_idn_protocol_version_minor,
			{ "Minor", "idn.protocol_version_minor",
			FT_UINT8, BASE_DEC,
			NULL, 0x0F,
			NULL, HFILL }
		},
		{ &hf_idn_status,
			{ "Status", "idn.status",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_malfn,
			{ "Malfunction", "idn.status_malfn",
			FT_UINT8, BASE_DEC,
			NULL, 0x80,
			NULL, HFILL }
		},
		{ &hf_idn_offline,
			{ "Offline", "idn.offline",
			FT_UINT8, BASE_DEC,
			NULL, 0x40,
			NULL, HFILL }
		},
		{ &hf_idn_xcld,
			{ "Excluded", "idn.xcld",
			FT_UINT8, BASE_DEC,
			NULL, 0x20,
			NULL, HFILL }
		},
		{ &hf_idn_ocpd,
			{ "Occupied", "idn.ocpd",
			FT_UINT8, BASE_DEC,
			NULL, 0x10,
			NULL, HFILL }
		},
		{ &hf_idn_rt,
			{ "Realtime", "idn.rt",
			FT_UINT8, BASE_DEC,
			NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_idn_reserved8,
			{ "Reserved", "idn.reserved8",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_unit_id,
			{ "Unit ID", "idn.unit_id",
			FT_BYTES, SEP_SPACE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_uid_length,
			{ "Length", "idn.unit_id_length",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_uid_category,
			{ "Caregory", "idn.unit_id_category",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_uid,
			{ "Unit ID", "idn.unit_id_number",
			FT_BYTES, SEP_SPACE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_name,
			{ "Name", "idn.name",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_entry_size,
			{ "Entry Size", "idn.entry_size",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_relay_count,
			{ "Relay Count", "idn.relay_count",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_service_count,
			{ "Service Count", "idn.service_count",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_cnl,
			{ "Channel configuration and routing information (CNL)", "idn.cnl",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_most_significant_bit_cnl,
			{ "Most significant bit (always 1)", "idn.most_significant_bit_cnl",
			FT_UINT8, BASE_DEC,
			NULL, 0x80,
			NULL, HFILL }
		},
		{ &hf_idn_cclf,
			{ "Channel Configuration and Last Fragment bit (CCLF)", "idn.cclf",
			FT_UINT8, BASE_DEC,
			NULL, 0x40,
			NULL, HFILL }
		},
		{ &hf_idn_channel_id,
			{ "Channel ID (opened Channels)", "idn.channel_id",
			FT_UINT8, BASE_DEC,
			NULL, 0x3F,
			NULL, HFILL }
		},
		{ &hf_idn_chunk_type,
			{ "Chunk Type", "idn.chunk_type",
			FT_UINT8, BASE_HEX,
			VALS(chunk_type), 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_timestamp,
			{ "Timestamp", "idn.timestamp",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_scwc,
			{ "Service Configuration Word Count (SCWC)", "idn.scwc",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_cfl,
			{ "Channel and service configuration Flags (CFL)", "idn.cfl",
			FT_UINT8, BASE_HEX,
			VALS(cfl_string), 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_sdm,
			{ "Service Data Match (SDM)", "idn.sdm",
			FT_UINT8, BASE_DEC,
			NULL, 0x30,
			NULL, HFILL }
		},
		{ &hf_idn_close,
			{ "Close", "idn.close",
			FT_UINT8, BASE_DEC,
			NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_idn_routing,
			{ "Routing", "idn.routing",
			FT_UINT8, BASE_DEC,
			NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_idn_service_id,
			{ "Service ID", "idn.service_id",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_relay_number,
			{ "Relay Number", "idn.relay_number",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_service_mode,
			{ "Service Mode", "idn.service_mode",
			FT_UINT8, BASE_HEX,
			VALS(service_mode_string), 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_chunk_header_flags,
			{ "Chunk Header Flags", "idn.chunk_header_flags",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_two_bits_reserved_1,
			{ "Reserved", "idn.zero_zero",
			FT_UINT8, BASE_DEC,
			NULL, 0xC0,
			NULL, HFILL }
		},
		{ &hf_idn_two_bits_reserved_2,
			{ "Reserved", "idn.zero_zero",
			FT_UINT8, BASE_DEC,
			NULL, 0xC,
			NULL, HFILL }
		},
		{ &hf_idn_scm,
			{ "Service configuration match (SCM)", "idn.scm",
			FT_UINT8, BASE_DEC,
			NULL, 0x30,
			NULL, HFILL }
		},
		{ &hf_idn_three_bits_reserved,
			{ "Reserved", "idn.three_bit_reserved",
			FT_UINT8, BASE_DEC,
			NULL, 0xE,
			NULL, HFILL }
		},
		{ &hf_idn_four_bits_reserved,
			{ "Reserved", "idn.three_bit_reserved",
			FT_UINT8, BASE_DEC,
			NULL, 0xF,
			NULL, HFILL }
		},
		{ &hf_idn_once,
			{ "Once", "idn.once",
			FT_UINT8, BASE_DEC,
			NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_idn_dlim,
			{ "Delimiter (DLIM)", "idn.dlim",
			FT_UINT8, BASE_DEC,
			NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_idn_duration,
			{ "Duration", "idn.frame_sample_duration",
			FT_UINT24, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_chunk_data_sequence,
			{ "Sequence", "idn.octet_segment_sequence",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_offset,
			{ "Offset", "idn.offset",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_reserved,
			{ "Reserved", "idn.reserved",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts,
			{ "Unknown", "idn.unknown",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_void,
			{ "Void", "idn.gts_void",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_boundary,
			{ "Void (32-bit boundary)", "idn.gts_boundary",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_word,
			{ "16-bit word", "idn.gts_word",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_break,
			{ "Break", "idn.gts_break",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_space_modifier,
			{ "Space Modifier", "idn.gts_space_modifier",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_hint,
			{ "Hint", "idn.gts_hint",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_category,
			{ "Category", "idn.gts_category",
			FT_UINT16, BASE_DEC,
			NULL, 0xF000,
			NULL, HFILL }
		},
		{ &hf_idn_gts_subcategory,
			{ "Subcategory", "idn.gts_subcategory",
			FT_UINT16, BASE_DEC,
			NULL, 0x0F00,
			NULL, HFILL }
		},
		{ &hf_idn_gts_identifier,
			{ "Identifier", "idn.gts_identifier",
			FT_UINT16, BASE_DEC,
			NULL, 0x00F0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_parameter,
			{ "Parameter", "idn.gts_parameter",
			FT_UINT16, BASE_DEC,
			NULL, 0x000F,
			NULL, HFILL }
		},
		{ &hf_idn_gts_glin,
			{ "Graphic Space Linearity (GLIN)", "idn.gts_glin",
			FT_UINT16, BASE_DEC,
			VALS(gts_glin), 0x00C0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_clin,
			{ "Color Space Linearity (CLIN)", "idn.gts_clin",
			FT_UINT16, BASE_DEC,
			VALS(gts_clin), 0x0030,
			NULL, HFILL }
		},
		{ &hf_idn_gts_cbal,
			{ "Color Balance (CBAL)", "idn.gts_cbal",
			FT_UINT16, BASE_DEC,
			VALS(gts_cbal), 0x000C,
			NULL, HFILL }
		},
		{ &hf_idn_gts_ctim,
			{ "Color Timing (CTIM)", "idn.gts_ctim",
			FT_UINT16, BASE_DEC,
			VALS(gts_ctim), 0x0003,
			NULL, HFILL }
		},
		{ &hf_idn_gts_nop,
			{ "No Operation (NOP)", "idn.gts_nop",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_precision,
			{ "Precision", "idn.gts_precision",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_cscl,
			{ "Color scale (CSCL)", "idn.gts_cscl",
			FT_UINT16, BASE_DEC,
			NULL, 0x00C0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_iscl,
			{ "Intensity scale (ISCL)", "idn.gts_iscl",
			FT_UINT16, BASE_DEC,
			NULL, 0x0030,
			NULL, HFILL }
		},
		{ &hf_idn_gts_sht,
			{ "Shutter (SHT)", "idn.gts_sht",
			FT_UINT16, BASE_DEC,
			NULL, 0x000F,
			NULL, HFILL }
		},
		{ &hf_idn_gts_u4,
			{ "Optional(U4), used as X-prime", "idn.gts_u4",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_x,
			{ "X", "idn.gts_x",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_y,
			{ "Y", "idn.gts_y",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_z,
			{ "Z", "idn.gts_z",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_color,
			{ "Color", "idn.gts_color",
			FT_UINT16, BASE_DEC,
			VALS(idn_color), 0x03FF,
			NULL, HFILL }
		},
		{ &hf_idn_gts_wavelength_prefix,
			{ "Wavelength Prefix", "idn.gts_wavelength_prefix",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_intensity,
			{ "Intensity/blanking", "idn.gts_intensity",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_beam_brush,
			{ "Beam-Brush", "idn.gts_beam_brush",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_gts_sample,
			{ "Sample", "idn.gts_sample",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_octet,
			{ "Octet", "idn.gts_octet",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_identifier,
			{ "Identifier", "idn.gts_dmx_identifier",
			FT_UINT8, BASE_DEC,
			NULL, 0xF0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_parameter,
			{ "Parameter", "idn.gts_dmx_parameter",
			FT_UINT8, BASE_DEC,
			NULL, 0x0F,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_void,
			{ "Void", "idn.gts_dmx_void",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_octet,
			{ "Octet", "idn.gts_dmx_octet",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_dls,
			{ "Dimmer Level Subset", "idn.dmx_dls",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_base,
			{ "Base", "idn.dmx_base",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_count,
			{ "Count", "idn.dmx_count",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_dmx_unknown,
			{ "Unknown", "idn.dmx_unknown",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_result_code,
			{ "Result Code", "idn.result_code",
			FT_UINT8, BASE_DEC,
			VALS(result_code), 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_event_flags,
			{ "Event Flags", "idn.event_flags",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_idn_audio_dictionary_tag,
			{ "Audio Dictionary Tag", "idn.audioheader",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
			}
		},
		{ &hf_idn_category,
			{ "Category", "idn.category",
			FT_UINT16, BASE_HEX,
			VALS(category), 0xF000,
			NULL, HFILL
			}
		},
		{ &hf_idn_format,
			{ "Format", "idn.format",
			FT_UINT16, BASE_DEC,
			VALS(format), 0x0F00,
			NULL, HFILL
			}
		},
		{ &hf_idn_layout,
			{ "Layout", "idn.layout",
			FT_UINT16, BASE_DEC,
			NULL, 0x00F0,
			NULL, HFILL
			}
		},
		{ &hf_idn_4bit_channels,
			{ "Channels", "idn.category6channels",
			FT_UINT16, BASE_DEC,
			NULL, 0x000F,
			NULL, HFILL
			}
		},
		{ &hf_idn_subcategory,
			{ "Subcategory", "idn.subcategory",
			FT_UINT16, BASE_DEC,
			NULL, 0x0F00,
			NULL, HFILL
			}
		},
		{ &hf_idn_parameter,
			{ "Format", "idn.format",
			FT_UINT16, BASE_DEC,
			NULL, 0x00F0,
			NULL, HFILL
			}
		},
		{ &hf_idn_suffix_length,
			{ "Suffix length", "idn.suffix_length",
			FT_UINT16, BASE_DEC,
			NULL, 0x000F,
			NULL, HFILL
			}
		},
		{ &hf_idn_8bit_channels,
			{ "Channels", "idn.channel",
			FT_UINT16, BASE_DEC,
			NULL, 0x00FF,
			NULL, HFILL
			}
		},
		{ &hf_idn_audio_flags,
			{ "Flags", "idn.audio_flags",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_idn_audio_duration,
			{ "Duration in microseconds", "idn.audio_duration",
			FT_UINT24, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_idn_audio_flags_two_bits_reserved,
			{ "Reserved", "idn.audio_2",
			FT_UINT8, BASE_HEX,
			NULL, 0xC0,
			NULL, HFILL}
		},
		{ &hf_idn_audio_flags_four_bits_reserved,
			{ "Reserved", "idn.audio_4",
			FT_UINT8, BASE_HEX,
			NULL, 0x0F,
			NULL, HFILL}
		},
		{ &hf_idn_audio_flags_scm,
			{ "Service configuration match", "idn.audio_scm",
			FT_UINT8, BASE_HEX,
			NULL, 0x30,
			NULL, HFILL}
		},
		{ &hf_idn_audio_sample_format_zero,
			{ "Audio Sample (format 0)", "idn.audio_sample_0",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_idn_audio_sample_format_one,
			{ "Audio Sample (format 1)", "idn.audio_sample_1",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_idn_audio_sample_format_two,
			{ "Audio Sample (format 2)", "idn.audio_sample_2",
			FT_UINT24, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		}
	};

	static int *ett[] = {
		&ett_idn,
		&ett_idn_header_tree,
		&ett_idn_scanreply_header_tree,
		&ett_idn_channel_message_header_tree,
		&ett_protocol_version,
		&ett_unit_id,
		&ett_status,
		&ett_idn_cnl,
		&ett_cfl,
		&ett_configuration_header,
		&ett_chunk_header_tree,
		&ett_chunk_header_flags,
		&ett_dic,
		&ett_dic_tree,
		&ett_data,
		&ett_subdata,
		&ett_dmx_subtree,
		&ett_audio_header,
		&ett_audio_samples
	};

	expert_module_t* expert_idn;
	static ei_register_info ei[] = {
		{ &ei_idn_no_config, { "idn.no_config", PI_UNDECODED, PI_NOTE,
			"No configuration is associated with this message", EXPFILL } },
		{ &ei_idn_scwc_unknown, { "idn.scwc.unknown", PI_SEQUENCE, PI_WARN,
			"SCWC is zero/unknown", EXPFILL } },
		{ &ei_idn_channels_over, { "idn.channel.over", PI_PROTOCOL, PI_ERROR,
			"Over number of channels", EXPFILL } },
		{ &ei_idn_scm_mismatch, { "idn.scm.mismatch", PI_PROTOCOL, PI_ERROR,
			"SCM doesn't match configured SDM", EXPFILL } },
	};

	proto_idn = proto_register_protocol (
		"Ilda Digital Network Protocol",
		"IDN",
		"idn"
	);

	proto_register_field_array(proto_idn, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_idn = expert_register_protocol(proto_idn);
	expert_register_field_array(expert_idn, ei, array_length(ei));

	idn_handle = register_dissector("idn", dissect_idn, proto_idn);
}

void proto_reg_handoff_idn(void) {
	dissector_add_uint("udp.port", IDN_PORT, idn_handle);
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
