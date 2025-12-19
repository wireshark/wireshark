/* packet-citp.c
 * Routines for CITP packet disassembly
 *
 * Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * Specification:
 * https://bitbucket.org/lars_wernlund/citp/src/master/
 * https://www.capture.se/Portals/0/Downloads/CITP%20CAEX%20Specification%20F.pdf?ver=2020-07-03-093027-283
 * http://www.techref.info/web/prod/cap/data/citp.pdf
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Include files */
#include "config.h"
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include "packet-tcp.h"


#define MAKE_TYPE_VAL(a, b, c, d)   ((a)<<24 | (b)<<16 | (c)<<8 | (d))

#define CITP_PORTS "4809-4810" /* Not IANA registered */

/* constants */
#define CITP_COOKIE ((const uint8_t*)"CITP")
#define CITP_COOKIE_LEN 4


#define CITP_PINF MAKE_TYPE_VAL('P', 'I', 'N', 'F')
#define CITP_SDMX MAKE_TYPE_VAL('S', 'D', 'M', 'X')
#define CITP_FPTC MAKE_TYPE_VAL('F', 'P', 'T', 'C')
#define CITP_FSEL MAKE_TYPE_VAL('F', 'S', 'E', 'L')
#define CITP_FINF MAKE_TYPE_VAL('F', 'I', 'N', 'F')
#define CITP_CAEX MAKE_TYPE_VAL('C', 'A', 'E', 'X')
#define CITP_MSEX MAKE_TYPE_VAL('M', 'S', 'E', 'X')


#define CITP_PINF_PNAM MAKE_TYPE_VAL('P', 'N', 'a', 'm')
#define CITP_PINF_PLOC MAKE_TYPE_VAL('P', 'L', 'o', 'c')

#define CITP_SDMX_CAPA MAKE_TYPE_VAL('C', 'a', 'p', 'a')
#define CITP_SDMX_UNAM MAKE_TYPE_VAL('U', 'N', 'a', 'm')
#define CITP_SDMX_ENID MAKE_TYPE_VAL('E', 'n', 'I', 'd')
#define CITP_SDMX_CHBK MAKE_TYPE_VAL('C', 'h', 'B', 'k')
#define CITP_SDMX_CHLS MAKE_TYPE_VAL('C', 'h', 'L', 's')
#define CITP_SDMX_SXSR MAKE_TYPE_VAL('S', 'X', 'S', 'r')
#define CITP_SDMX_SXUS MAKE_TYPE_VAL('S', 'X', 'U', 'S')

#define CITP_FPTC_PTCH MAKE_TYPE_VAL('P', 't', 'c', 'h')
#define CITP_FPTC_UPTC MAKE_TYPE_VAL('U', 'P', 't', 'c')
#define CITP_FPTC_SPTC MAKE_TYPE_VAL('S', 'P', 't', 'c')

#define CITP_FSEL_SELE MAKE_TYPE_VAL('S', 'e', 'l', 'e')
#define CITP_FSEL_DESE MAKE_TYPE_VAL('D', 'e', 'S', 'e')

#define CITP_FINF_SFRA MAKE_TYPE_VAL('S', 'F', 'r', 'a')
#define CITP_FINF_FRAM MAKE_TYPE_VAL('F', 'r', 'a', 'm')

#define CITP_MSEX_CINF MAKE_TYPE_VAL('C', 'I', 'n', 'f')
#define CITP_MSEX_SINF MAKE_TYPE_VAL('S', 'I', 'n', 'f')
#define CITP_MSEX_NACK MAKE_TYPE_VAL('N', 'a', 'c', 'k')
#define CITP_MSEX_LSTA MAKE_TYPE_VAL('L', 'S', 't', 'a')
#define CITP_MSEX_GELI MAKE_TYPE_VAL('G', 'E', 'L', 'I')
#define CITP_MSEX_ELIN MAKE_TYPE_VAL('E', 'L', 'I', 'n')
#define CITP_MSEX_ELUP MAKE_TYPE_VAL('E', 'L', 'U', 'p')
#define CITP_MSEX_GEIN MAKE_TYPE_VAL('G', 'E', 'I', 'n')
#define CITP_MSEX_MEIN MAKE_TYPE_VAL('M', 'E', 'I', 'n')
#define CITP_MSEX_EEIN MAKE_TYPE_VAL('E', 'E', 'I', 'n')
#define CITP_MSEX_GLEI MAKE_TYPE_VAL('G', 'L', 'I', 'n')
#define CITP_MSEX_GELT MAKE_TYPE_VAL('G', 'E', 'L', 'T')
#define CITP_MSEX_ELTH MAKE_TYPE_VAL('E', 'L', 'T', 'h')
#define CITP_MSEX_GETH MAKE_TYPE_VAL('G', 'E', 'T', 'h')
#define CITP_MSEX_ETHN MAKE_TYPE_VAL('E', 'T', 'h', 'n')
#define CITP_MSEX_GVSR MAKE_TYPE_VAL('G', 'V', 'S', 'r')
#define CITP_MSEX_VSRC MAKE_TYPE_VAL('V', 'S', 'r', 'c')
#define CITP_MSEX_RQST MAKE_TYPE_VAL('R', 'q', 'S', 't')
#define CITP_MSEX_STFR MAKE_TYPE_VAL('S', 't', 'F', 'r')


#define CITP_CAEX_NACK 0xFFFFFFFF
#define CITP_CAEX_LIVE_VIEW_GET_IMAGE  0x00000100
#define CITP_CAEX_LIVE_VIEW_IMAGE      0x00000101
#define CITP_CAEX_LIVE_VIEW_GET_STATUS 0x00000200
#define CITP_CAEX_LIVE_VIEW_STATUS     0x00000201
#define CITP_CAEX_CUE_RECORD_CAPA      0x00010100
#define CITP_CAEX_CUE_RECORD           0x00010200
#define CITP_CAEX_CUE_CLEAR_CAPA       0x00010300
#define CITP_CAEX_CUE_CLEAR            0x00010400
#define CITP_CAEX_SHOW_ENTER           0x00020100
#define CITP_CAEX_SHOW_LEAVE           0x00020101
#define CITP_CAEX_SET_TRANS_SPACE      0x00020150
#define CITP_CAEX_FIXTURE_LIST_REQ     0x00020200
#define CITP_CAEX_FIXTURE_LIST         0x00020201
#define CITP_CAEX_FIXTURE_MODIFY       0x00020202
#define CITP_CAEX_FIXTURE_REMOVE       0x00020203
#define CITP_CAEX_FIXTURE_ID           0x00020204
#define CITP_CAEX_FIXTURE_SELECT       0x00020300
#define CITP_CAEX_FIXTURE_STATUS       0x00020400
#define CITP_CAEX_LASER_GET_LIST       0x00030100
#define CITP_CAEX_LASER_LIST           0x00030101
#define CITP_CAEX_LASER_CONTROL        0x00030102
#define CITP_CAEX_LASER_FRAME          0x00030200


#define CITP_SDMX_CAPABILITY_CHLS   1
#define CITP_SDMX_CAPABILITY_SXSR   2
#define CITP_SDMX_CAPABILITY_SXUS   3
#define CITP_SDMX_CAPABILITY_ARTNET 101
#define CITP_SDMX_CAPABILITY_E131   102
#define CITP_SDMX_CAPABILITY_NET2   103
#define CITP_SDMX_CAPABILITY_MANET  104
#define CITP_SDMX_CAPABILITY_COMPVC 105

#define CITP_CAEX_IDENTIFIER_RDM_MANF         5
#define CITP_CAEX_IDENTIFIER_RDM_MODEL        0
#define CITP_CAEX_IDENTIFIER_RDM_PERSON       1
#define CITP_CAEX_IDENTIFIER_ALTA_FIXT        2
#define CITP_CAEX_IDENTIFIER_ALTA_MODEL       3
#define CITP_CAEX_IDENTIFIER_CAPTURE_INSTANCE 4

#define CITP_MSEX_V10 0x0100
#define CITP_MSEX_V11 0x0101
#define CITP_MSEX_V12 0x0102

#define CITP_MSEX_FORMAT_RGB8 MAKE_TYPE_VAL('R', 'G', 'B', '8')
#define CITP_MSEX_FORMAT_JPEG MAKE_TYPE_VAL('J', 'P', 'E', 'G')
#define CITP_MSEX_FORMAT_PNG  MAKE_TYPE_VAL('P', 'N', 'G', ' ')
#define CITP_MSEX_FORMAT_FJPG MAKE_TYPE_VAL('f', 'J', 'P', 'G')
#define CITP_MSEX_FORMAT_FPNG MAKE_TYPE_VAL('f', 'P', 'N', 'G')

static int proto_citp;
static int proto_citp_pinf;
static int proto_citp_sdmx;
static int proto_citp_fptc;
static int proto_citp_fsel;
static int proto_citp_finf;
static int proto_citp_caex;
static int proto_citp_msex;

static dissector_handle_t citp_handle;
static dissector_handle_t citp_tcp_handle;

static dissector_table_t content_type_table;
static dissector_table_t encryption_id_table;


static dissector_handle_t dmx_chan_handle;
static dissector_handle_t jpeg_handle;
static dissector_handle_t png_handle;

/*  Open/Close trees */
static int ett_citp;
static int ett_citp_pinf;
static int ett_citp_sdmx;
static int ett_citp_fptc;
static int ett_citp_fsel;
static int ett_citp_finf;
static int ett_citp_caex;
static int ett_citp_msex;

static int ett_citp_sdmx_capabilities;
static int ett_citp_fptc_fixture_identifiers;
static int ett_citp_fptc_content_hint;
static int ett_citp_fsel_fixture_identifiers;
static int ett_citp_finf_fixture_identifiers;
static int ett_citp_caex_view_pos;
static int ett_citp_caex_view_focus;
static int ett_citp_caex_cue_option;
static int ett_citp_caex_laser_point;
static int ett_citp_caex_laser_point_colour;
static int ett_citp_caex_show_fixtures;
static int ett_citp_caex_show_fixture;
static int ett_citp_caex_show_fixture_identifier;
static int ett_citp_caex_show_fixture_pos;
static int ett_citp_caex_show_fixture_angles;
static int ett_citp_caex_show_fixture_changed_fields;

static int ett_citp_msex_supported_versions;
static int ett_citp_msex_supported_version;
static int ett_citp_msex_supported_library_types;
static int ett_citp_msex_libraries;
static int ett_citp_msex_library;
static int ett_citp_msex_elements;
static int ett_citp_msex_element;
static int ett_citp_msex_element_parameter_names;
static int ett_citp_msex_sources;
static int ett_citp_msex_source;
static int ett_citp_msex_layers;
static int ett_citp_msex_layer;
static int ett_citp_msex_layer_status_flags;
static int ett_citp_msex_thumbnail_formats;
static int ett_citp_msex_stream_formats;
static int ett_citp_msex_library_update_flags;
static int ett_citp_msex_thumbnail_flags;
static int ett_citp_msex_source_flags;
static int ett_citp_msex_library_id;
static int ett_citp_msex_library_parent_id;
static int ett_citp_msex_frame_fragment;
static int ett_citp_msex_library_affected_elements;
static int ett_citp_msex_library_affected_subs;

/* Expert Info */
static expert_field ei_citp_content_type;
static expert_field ei_citp_message_size;

static expert_field ei_citp_pinf_content_type;
static expert_field ei_citp_sdmx_content_type;
static expert_field ei_citp_fptc_content_type;
static expert_field ei_citp_fsel_content_type;
static expert_field ei_citp_finf_content_type;

static expert_field ei_citp_caex_content_code;
static expert_field ei_citp_caex_fixture_ident;
static expert_field ei_citp_caex_view_format;
static expert_field ei_citp_msex_content_type;
static expert_field ei_citp_msex_version;
static expert_field ei_citp_msex_thumb_format;
static expert_field ei_citp_msex_stream_format;

/*  Register fields */
static int hf_citp_cookie;
static int hf_citp_version_major;
static int hf_citp_version_minor;
static int hf_citp_message_index;
static int hf_citp_message_size;
static int hf_citp_message_part_count;
static int hf_citp_message_part_index;
static int hf_citp_content_type;

static int hf_citp_pinf_content_type;
static int hf_citp_pinf_listening_port;
static int hf_citp_pinf_name;
static int hf_citp_pinf_type;
static int hf_citp_pinf_state;

static int hf_citp_sdmx_content_type;
static int hf_citp_sdmx_capability_count;
static int hf_citp_sdmx_capabilities;
static int hf_citp_sdmx_capability;
static int hf_citp_sdmx_universe_index;
static int hf_citp_sdmx_universe_name;
static int hf_citp_sdmx_encryption_identifier;
static int hf_citp_sdmx_blind;
static int hf_citp_sdmx_first_channel;
static int hf_citp_sdmx_channel_count;
static int hf_citp_sdmx_channel_levels;
static int hf_citp_sdmx_encrypted_channel_data;
static int hf_citp_sdmx_channel_level_block;
static int hf_citp_sdmx_channel;
static int hf_citp_sdmx_channel_level;
static int hf_citp_sdmx_connection_string;

static int hf_citp_fptc_content_type;
static int hf_citp_fptc_content_hint;
static int hf_citp_fptc_content_hint_in_sequence;
static int hf_citp_fptc_content_hint_end_sequence;
static int hf_citp_fptc_fixture_identifier;
static int hf_citp_fptc_universe;
static int hf_citp_fptc_channel;
static int hf_citp_fptc_channel_count;
static int hf_citp_fptc_fixture_make;
static int hf_citp_fptc_fixture_name;
static int hf_citp_fptc_fixture_count;
static int hf_citp_fptc_fixture_identifiers;

static int hf_citp_fsel_content_type;
static int hf_citp_fsel_complete;
static int hf_citp_fsel_fixture_count;
static int hf_citp_fsel_fixture_identifiers;
static int hf_citp_fsel_fixture_identifier;

static int hf_citp_finf_content_type;
static int hf_citp_finf_fixture_count;
static int hf_citp_finf_fixture_identifiers;
static int hf_citp_finf_fixture_identifier;
static int hf_citp_finf_frame_filter_count;
static int hf_citp_finf_frame_gobo_count;
static int hf_citp_finf_frame_names;
static int hf_citp_finf_filter_name;
static int hf_citp_finf_gobo_name;



static int hf_citp_caex_content_code;
static int hf_citp_caex_nack_reason;
static int hf_citp_caex_view_availability;
static int hf_citp_caex_view_size;
static int hf_citp_caex_view_width;
static int hf_citp_caex_view_height;
static int hf_citp_caex_view_position;
static int hf_citp_caex_view_position_x;
static int hf_citp_caex_view_position_y;
static int hf_citp_caex_view_position_z;
static int hf_citp_caex_view_focus;
static int hf_citp_caex_view_focus_x;
static int hf_citp_caex_view_focus_y;
static int hf_citp_caex_view_focus_z;
static int hf_citp_caex_view_format;
static int hf_citp_caex_view_data_size;
static int hf_citp_caex_view_data;

static int hf_citp_caex_cue_availability;
static int hf_citp_caex_cue_option_count;
static int hf_citp_caex_cue_option;
static int hf_citp_caex_cue_option_name;
static int hf_citp_caex_cue_option_value;
static int hf_citp_caex_cue_option_choices;
static int hf_citp_caex_cue_option_help;
static int hf_citp_caex_cue_clear_availability;

static int hf_citp_caex_show_name;
static int hf_citp_caex_show_transformation_space;
static int hf_citp_caex_show_fixture_list_type;
static int hf_citp_caex_show_fixture_count;
static int hf_citp_caex_show_fixtures;
static int hf_citp_caex_show_fixture;
static int hf_citp_caex_show_fixture_console_identifier;
static int hf_citp_caex_show_fixture_manufacturer_name;
static int hf_citp_caex_show_fixture_model_name;
static int hf_citp_caex_show_fixture_mode_name;
static int hf_citp_caex_show_fixture_channel_count;
static int hf_citp_caex_show_fixture_is_dimmer;
static int hf_citp_caex_show_fixture_identifier_count;
static int hf_citp_caex_show_fixture_identifier;
static int hf_citp_caex_show_fixture_identifier_type;
static int hf_citp_caex_show_fixture_identifier_data_size;
static int hf_citp_caex_show_fixture_identifier_data;
static int hf_citp_caex_show_fixture_identifier_rdm_manufacturer_id;
static int hf_citp_caex_show_fixture_identifier_rdm_device_model_id;
static int hf_citp_caex_show_fixture_identifier_rdm_personality_id;
static int hf_citp_caex_show_fixture_identifier_altabase_fixture_id;
static int hf_citp_caex_show_fixture_identifier_altabase_mode_id;
static int hf_citp_caex_show_fixture_identifier_capture_instance_id;
static int hf_citp_caex_show_fixture_patched;
static int hf_citp_caex_show_fixture_universe;
static int hf_citp_caex_show_fixture_universe_channel;
static int hf_citp_caex_show_fixture_unit;
static int hf_citp_caex_show_fixture_channel;
static int hf_citp_caex_show_fixture_circuit;
static int hf_citp_caex_show_fixture_note;
static int hf_citp_caex_show_fixture_position;
static int hf_citp_caex_show_fixture_position_x;
static int hf_citp_caex_show_fixture_position_y;
static int hf_citp_caex_show_fixture_position_z;
static int hf_citp_caex_show_fixture_angles;
static int hf_citp_caex_show_fixture_angles_x;
static int hf_citp_caex_show_fixture_angles_y;
static int hf_citp_caex_show_fixture_angles_z;
static int hf_citp_caex_show_fixture_locked;
static int hf_citp_caex_show_fixture_clearable;
static int hf_citp_caex_show_fixture_changed_fields;
static int hf_citp_caex_show_fixture_changed_fields_patch;
static int hf_citp_caex_show_fixture_changed_fields_unit;
static int hf_citp_caex_show_fixture_changed_fields_channel;
static int hf_citp_caex_show_fixture_changed_fields_circuit;
static int hf_citp_caex_show_fixture_changed_fields_note;
static int hf_citp_caex_show_fixture_changed_fields_position;

static int hf_citp_caex_laser_source_key;
static int hf_citp_caex_laser_feed_count;
static int hf_citp_caex_laser_feed_name;
static int hf_citp_caex_laser_feed_index;
static int hf_citp_caex_laser_frame_rate;
static int hf_citp_caex_laser_frame_sequence_number;
static int hf_citp_caex_laser_point_count;
static int hf_citp_caex_laser_points;
static int hf_citp_caex_laser_point;
static int hf_citp_caex_laser_point_x_low;
static int hf_citp_caex_laser_point_y_low;
static int hf_citp_caex_laser_point_xy_high;
static int hf_citp_caex_laser_point_x;
static int hf_citp_caex_laser_point_y;
static int hf_citp_caex_laser_point_colour;
static int hf_citp_caex_laser_point_colour_r;
static int hf_citp_caex_laser_point_colour_g;
static int hf_citp_caex_laser_point_colour_b;



static int hf_citp_msex_version_major;
static int hf_citp_msex_version_minor;
static int hf_citp_msex_content_type;
static int hf_citp_msex_supported_version_count;
static int hf_citp_msex_supported_versions;
static int hf_citp_msex_supported_version;
static int hf_citp_msex_uuid;
static int hf_citp_msex_product_name;
static int hf_citp_msex_product_version_major;
static int hf_citp_msex_product_version_minor;
static int hf_citp_msex_product_version_bugfix;
static int hf_citp_msex_supported_library_types;
static int hf_citp_msex_supported_library_types_media;
static int hf_citp_msex_supported_library_types_effects;
static int hf_citp_msex_supported_library_types_cues;
static int hf_citp_msex_supported_library_types_crossfades;
static int hf_citp_msex_supported_library_types_masks;
static int hf_citp_msex_supported_library_types_blend_presets;
static int hf_citp_msex_supported_library_types_effect_presets;
static int hf_citp_msex_supported_library_types_image_presets;
static int hf_citp_msex_supported_library_types_3d_meshes;
static int hf_citp_msex_received_content_type;

static int hf_citp_msex_layer_count;
static int hf_citp_msex_layers;
static int hf_citp_msex_layer;
static int hf_citp_msex_layer_dmx_source;
static int hf_citp_msex_layer_number;
static int hf_citp_msex_layer_physical_output;
static int hf_citp_msex_layer_status_flags;
static int hf_citp_msex_layer_status_flags_playing;
static int hf_citp_msex_layer_status_flags_reverse;
static int hf_citp_msex_layer_status_flags_looping;
static int hf_citp_msex_layer_status_flags_bouncing;
static int hf_citp_msex_layer_status_flags_random;
static int hf_citp_msex_layer_status_flags_paused;

static int hf_citp_msex_library_count;
static int hf_citp_msex_libraries;
static int hf_citp_msex_library;
static int hf_citp_msex_library_type;
static int hf_citp_msex_library_number;
static int hf_citp_msex_library_id;
static int hf_citp_msex_library_id_level;
static int hf_citp_msex_library_id_level_1;
static int hf_citp_msex_library_id_level_2;
static int hf_citp_msex_library_id_level_3;
static int hf_citp_msex_library_parent_id;
static int hf_citp_msex_library_serial_number;
static int hf_citp_msex_library_dmx_min;
static int hf_citp_msex_library_dmx_max;
static int hf_citp_msex_library_name;
static int hf_citp_msex_library_sub_count;
static int hf_citp_msex_library_element_count;
static int hf_citp_msex_library_update_flags;
static int hf_citp_msex_library_update_flags_elements_updated;
static int hf_citp_msex_library_update_flags_elements_added_removed;
static int hf_citp_msex_library_update_flags_subs_updated;
static int hf_citp_msex_library_update_flags_subs_added_removed;
static int hf_citp_msex_library_update_flags_all_elements;
static int hf_citp_msex_library_update_flags_all_subs;
static int hf_citp_msex_library_affected_elements;
static int hf_citp_msex_library_affected_subs;
static int hf_citp_msex_library_affected_element;
static int hf_citp_msex_library_affected_sub;

static int hf_citp_msex_element_count;
static int hf_citp_msex_elements;
static int hf_citp_msex_element;
static int hf_citp_msex_element_number;
static int hf_citp_msex_element_serial_number;
static int hf_citp_msex_element_dmx_min;
static int hf_citp_msex_element_dmx_max;
static int hf_citp_msex_element_name;
static int hf_citp_msex_element_version_timestamp;
static int hf_citp_msex_element_position;
static int hf_citp_msex_element_width;
static int hf_citp_msex_element_height;
static int hf_citp_msex_element_length;
static int hf_citp_msex_element_fps;
static int hf_citp_msex_element_parameter_count;
static int hf_citp_msex_element_parameter_names;
static int hf_citp_msex_element_parameter_name;

static int hf_citp_msex_thumbnail_format_count;
static int hf_citp_msex_thumbnail_formats;
static int hf_citp_msex_thumbnail_format;
static int hf_citp_msex_thumbnail_width;
static int hf_citp_msex_thumbnail_height;
static int hf_citp_msex_thumbnail_flags;
static int hf_citp_msex_thumbnail_flags_preserve_aspect;
static int hf_citp_msex_thumbnail_buffer_size;
static int hf_citp_msex_thumbnail_buffer;

static int hf_citp_msex_source_count;
static int hf_citp_msex_sources;
static int hf_citp_msex_source;
static int hf_citp_msex_source_server_uuid;
static int hf_citp_msex_source_id;
static int hf_citp_msex_source_name;
static int hf_citp_msex_source_physical_output;
static int hf_citp_msex_source_layer_number;
static int hf_citp_msex_source_flags;
static int hf_citp_msex_source_flags_without_effects;
static int hf_citp_msex_source_width;
static int hf_citp_msex_source_height;

static int hf_citp_msex_stream_format_count;
static int hf_citp_msex_stream_formats;
static int hf_citp_msex_stream_format;
static int hf_citp_msex_stream_width;
static int hf_citp_msex_stream_height;
static int hf_citp_msex_stream_fps;
static int hf_citp_msex_stream_timeout;

static int hf_citp_msex_frame_buffer_size;
static int hf_citp_msex_frame_buffer;
static int hf_citp_msex_frame_index;
static int hf_citp_msex_frame_fragment;
static int hf_citp_msex_frame_fragment_count;
static int hf_citp_msex_frame_fragment_index;
static int hf_citp_msex_frame_fragment_byte_offset;

static const true_false_string tfs_live_blind = {
    "Blind",
    "Live",
};

static const value_string citp_content_type_names[] = {
    { CITP_PINF, "PINF : Peer INFormation" },
    { CITP_SDMX, "SDMX : Send DMX" },
    { CITP_FPTC, "FPTC : Fixture PATch" },
    { CITP_FSEL, "FSEL : Fixture SELection" },
    { CITP_FINF, "FINF : Fixture INFormation" },
    { CITP_CAEX, "CAEX : CApture EXtensions" },
    { CITP_MSEX, "MSEX : Media Server EXtensions" },
    { 0,         NULL },
};
static const value_string citp_pinf_content_type_names[] = {
    { CITP_PINF_PNAM, "PNam : Peer Name" },
    { CITP_PINF_PLOC, "PLoc : Peer Location" },
    { 0,              NULL },
};
static const value_string citp_sdmx_content_type_names[] = {
    { CITP_SDMX_CAPA, "Capa : Capabilities" },
    { CITP_SDMX_UNAM, "UNam : Universe Name" },
    { CITP_SDMX_ENID, "EnId : Encryption Identifier" },
    { CITP_SDMX_CHBK, "ChBk : Channel Block" },
    { CITP_SDMX_CHLS, "ChLs : Channel List" },
    { CITP_SDMX_SXSR, "SXSr : Set External Source" },
    { CITP_SDMX_SXUS, "SXUS : Set External Universe Source" },
    { 0,              NULL },
};
static const value_string citp_fptc_content_type_names[] = {
    { CITP_FPTC_PTCH, "Ptch : Patch" },
    { CITP_FPTC_UPTC, "UPtc : UnPatch" },
    { CITP_FPTC_SPTC, "SPtc : Send Patch" },
    { 0,              NULL },
};
static const value_string citp_fsel_content_type_names[] = {
    { CITP_FSEL_SELE, "Sele : Select" },
    { CITP_FSEL_DESE, "DeSe : Deselect" },
    { 0,              NULL },
};
static const value_string citp_finf_content_type_names[] = {
    { CITP_FINF_SFRA, "SFra : Send Frames" },
    { CITP_FINF_FRAM, "Fram : Frames" },
    { 0,              NULL },
};
static const value_string citp_msex_content_type_names[] = {
    { CITP_MSEX_CINF, "CInf : Client Information" },
    { CITP_MSEX_SINF, "SInf : Server Information" },
    { CITP_MSEX_NACK, "Nack : Negative Acknowledgement" },
    { CITP_MSEX_LSTA, "LSta : Layer Status" },
    { CITP_MSEX_GELI, "GELI : Get Element Library Information" },
    { CITP_MSEX_ELIN, "ELIn : Element Library Information" },
    { CITP_MSEX_ELUP, "ELUp : Element Library Updated" },
    { CITP_MSEX_GEIN, "GEIn : Get Element Information" },
    { CITP_MSEX_MEIN, "MEIn : Media Element Information" },
    { CITP_MSEX_EEIN, "EEIn : Effect Element Information" },
    { CITP_MSEX_GLEI, "GLIn : Generic Element Information" },
    { CITP_MSEX_GELT, "GELT : Get Element Library Thumbnail" },
    { CITP_MSEX_ELTH, "ELTh : Element Library Thumbnail" },
    { CITP_MSEX_GETH, "GETh : Get Element Thumbnail" },
    { CITP_MSEX_ETHN, "EThn : Element Thumbnail" },
    { CITP_MSEX_GVSR, "GVSr : Get Video Sources" },
    { CITP_MSEX_VSRC, "VSrc : Video Sources" },
    { CITP_MSEX_RQST, "RqSt : Request Stream" },
    { CITP_MSEX_STFR, "StFr : Stream Frame" },
    { 0,              NULL },
};
static const value_string citp_msex_content_type_short_names[] = {
    { CITP_MSEX_CINF, "CInf" },
    { CITP_MSEX_SINF, "SInf" },
    { CITP_MSEX_NACK, "Nack" },
    { CITP_MSEX_LSTA, "LSta" },
    { CITP_MSEX_GELI, "GELI" },
    { CITP_MSEX_ELIN, "ELIn" },
    { CITP_MSEX_ELUP, "ELUp" },
    { CITP_MSEX_GEIN, "GEIn" },
    { CITP_MSEX_MEIN, "MEIn" },
    { CITP_MSEX_EEIN, "EEIn" },
    { CITP_MSEX_GLEI, "GLIn" },
    { CITP_MSEX_GELT, "GELT" },
    { CITP_MSEX_ELTH, "ELTh" },
    { CITP_MSEX_GETH, "GETh" },
    { CITP_MSEX_ETHN, "EThn" },
    { CITP_MSEX_GVSR, "GVSr" },
    { CITP_MSEX_VSRC, "VSrc" },
    { CITP_MSEX_RQST, "RqSt" },
    { CITP_MSEX_STFR, "StFr" },
    { 0,              NULL },
};

/* Use these with BASE_SPECIAL_VALS */
static const value_string citp_all_fixtures_val_str[] = {
    { 0, "All Fixtures" },
    { 0, NULL}
};
static const value_string citp_all_libraries_val_str[] = {
    { 0, "All Libraries" },
    { 0, NULL}
};
static const value_string citp_all_elements_val_str[] = {
    { 0, "All Elements" },
    { 0, NULL}
};

static const value_string citp_sdmx_capability_names[] = {
    { CITP_SDMX_CAPABILITY_CHLS,   "ChLs channel list" },
    { CITP_SDMX_CAPABILITY_SXSR,   "SXSr external source" },
    { CITP_SDMX_CAPABILITY_SXUS,   "SXUS per-universe external sources" },
    { CITP_SDMX_CAPABILITY_ARTNET, "Art-Net external sources" },
    { CITP_SDMX_CAPABILITY_E131,   "BSR E1.31 external sources" },
    { CITP_SDMX_CAPABILITY_NET2,   "ETC Net2 external sources" },
    { CITP_SDMX_CAPABILITY_MANET,  "MA-Net external sources" },
    { CITP_SDMX_CAPABILITY_COMPVC, "Compulite VC external sources" },
    { 0,                           NULL },
};

static const value_string citp_caex_content_code_names[] = {
    { CITP_CAEX_LIVE_VIEW_GET_IMAGE,  "Get Live View Image" },
    { CITP_CAEX_LIVE_VIEW_IMAGE,      "Live View Image" },
    { CITP_CAEX_LIVE_VIEW_GET_STATUS, "Get Live View Status" },
    { CITP_CAEX_LIVE_VIEW_STATUS,     "Live View Status" },
    { CITP_CAEX_CUE_RECORD_CAPA,      "Set Cue Recording Capabilities" },
    { CITP_CAEX_CUE_RECORD,           "Record Cue" },
    { CITP_CAEX_CUE_CLEAR_CAPA,       "Set Recorder Clearing Capabilities" },
    { CITP_CAEX_CUE_CLEAR,            "Clear Recorder" },
    { CITP_CAEX_SHOW_ENTER,           "Enter Show" },
    { CITP_CAEX_SHOW_LEAVE,           "Leave Show" },
    { CITP_CAEX_SET_TRANS_SPACE,      "Set Fixture Transformation Space" },
    { CITP_CAEX_FIXTURE_LIST_REQ,     "Fixture List Request" },
    { CITP_CAEX_FIXTURE_LIST,         "Fixture List" },
    { CITP_CAEX_FIXTURE_MODIFY,       "Fixture Modify" },
    { CITP_CAEX_FIXTURE_REMOVE,       "Fixture Remove" },
    { CITP_CAEX_FIXTURE_ID,           "Fixture Identify" },
    { CITP_CAEX_FIXTURE_SELECT,       "Fixture Selection" },
    { CITP_CAEX_FIXTURE_STATUS,       "Fixture Console Status" },
    { CITP_CAEX_LASER_GET_LIST,       "Get Laser Feed List" },
    { CITP_CAEX_LASER_LIST,           "Laser Feed List" },
    { CITP_CAEX_LASER_CONTROL,        "Laser Feed Control" },
    { CITP_CAEX_LASER_FRAME,          "Laser Feed Frame" },
    { CITP_CAEX_NACK,                 "NAck" },
    { 0,                              NULL },
};

static const value_string citp_caex_nack_reason[] = {
    { 0, "Unknown Request" },
    { 1, "Incorrect or Malformed Request" },
    { 2, "Internal Error" },
    { 3, "Request Refused" },
    { 0, NULL },
};
static const value_string citp_caex_view_availability[] = {
    { 0, "Not available" },
    { 1, "Alpha view available" },
    { 2, "Beta view available" },
    { 3, "Gamma view available" },
    { 0, NULL },
};
static const value_string citp_caex_cue_record_availability[] = {
    { 0, "Not available" },
    { 1, "Available" },
    { 0, NULL },
};
static const value_string citp_caex_cue_clear_availability[] = {
    { 0, "Unsupported" },
    { 1, "Currently unavailable" },
    { 2, "Available" },
    { 0, NULL },
};
static const value_string citp_caex_show_transformation_spaces[] = {
    { 0, "Native" },
    { 1, "PanHome" },
    { 0, NULL },
};
static const value_string citp_caex_show_fixture_list_types[] = {
    { 0, "Existing patch list" },
    { 1, "New fixture(s)" },
    { 2, "Exchanged fixture(s)" },
    { 0, NULL },
};
static const value_string citp_caex_show_identifier_types[] = {
    { CITP_CAEX_IDENTIFIER_RDM_MODEL,        "RDM Model Id" },
    { CITP_CAEX_IDENTIFIER_RDM_PERSON,       "RDM Personality Id" },
    { CITP_CAEX_IDENTIFIER_ALTA_FIXT,        "AltaBase Fixture Id" },
    { CITP_CAEX_IDENTIFIER_ALTA_MODEL,       "AltaBase Model Id" },
    { CITP_CAEX_IDENTIFIER_CAPTURE_INSTANCE, "Capture Instance Id" },
    { CITP_CAEX_IDENTIFIER_RDM_MANF,         "RDM Manufacturer Id" },
    { 0,                                     NULL },
};
static const value_string citp_msex_library_types[] = {
    { 1, "Media" },
    { 2, "Effects" },
    { 3, "Cues" },
    { 4, "Crossfades" },
    { 5, "Masks" },
    { 6, "Blend Presets" },
    { 7, "Effect Presets" },
    { 8, "Image Presets" },
    { 9, "3D Meshes" },
    { 0, NULL },
};


static int * const citp_fptc_content_hint[] = {
    &hf_citp_fptc_content_hint_in_sequence,
    &hf_citp_fptc_content_hint_end_sequence,
    NULL
};

static int * const citp_caex_laser_point_colour_fields[] = {
    &hf_citp_caex_laser_point_colour_r,
    &hf_citp_caex_laser_point_colour_g,
    &hf_citp_caex_laser_point_colour_b,
    NULL
};

static int * const citp_caex_show_fixture_changed_fields[] = {
    &hf_citp_caex_show_fixture_changed_fields_patch,
    &hf_citp_caex_show_fixture_changed_fields_unit,
    &hf_citp_caex_show_fixture_changed_fields_channel,
    &hf_citp_caex_show_fixture_changed_fields_circuit,
    &hf_citp_caex_show_fixture_changed_fields_note,
    &hf_citp_caex_show_fixture_changed_fields_position,
    NULL
};

static int * const citp_msex_supported_library_types[] = {
    &hf_citp_msex_supported_library_types_media,
    &hf_citp_msex_supported_library_types_effects,
    &hf_citp_msex_supported_library_types_cues,
    &hf_citp_msex_supported_library_types_crossfades,
    &hf_citp_msex_supported_library_types_masks,
    &hf_citp_msex_supported_library_types_blend_presets,
    &hf_citp_msex_supported_library_types_effect_presets,
    &hf_citp_msex_supported_library_types_image_presets,
    &hf_citp_msex_supported_library_types_3d_meshes,
    NULL
};

static int * const citp_msex_layer_status_flags[] = {
    &hf_citp_msex_layer_status_flags_playing,
    &hf_citp_msex_layer_status_flags_reverse,
    &hf_citp_msex_layer_status_flags_looping,
    &hf_citp_msex_layer_status_flags_bouncing,
    &hf_citp_msex_layer_status_flags_random,
    &hf_citp_msex_layer_status_flags_paused,
    NULL
};

static int * const citp_msex_library_update_flags[] = {
    &hf_citp_msex_library_update_flags_elements_updated,
    &hf_citp_msex_library_update_flags_elements_added_removed,
    &hf_citp_msex_library_update_flags_subs_updated,
    &hf_citp_msex_library_update_flags_subs_added_removed,
    &hf_citp_msex_library_update_flags_all_elements,
    &hf_citp_msex_library_update_flags_all_subs,
    NULL
};

static int * const citp_msex_thumbnail_flags[] = {
    &hf_citp_msex_thumbnail_flags_preserve_aspect,
    NULL
};

static int * const citp_msex_source_flags[] = {
    &hf_citp_msex_source_flags_without_effects,
    NULL
};


/******************************************************************************/
/* Dissect protocol                                                           */

typedef struct sdmx_enc_info {
    char *id;
} sdmx_enc_info;

/** enid should have been allocated with wmem_file_scope() */
void set_conversation_encryption(packet_info *pinfo, char* enid) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    sdmx_enc_info * info = conversation_get_proto_data(conv, proto_citp_sdmx);
    if (info == NULL) {
        info = wmem_alloc0(wmem_file_scope(), sizeof(sdmx_enc_info));
        info->id = enid;
        conversation_add_proto_data(conv, proto_citp_sdmx, (void*)info);
    } else {
        if (strcmp(info->id, enid) == 0) {
            /* free unused enid */
            wmem_free(wmem_file_scope(), enid);
        } else {
            /* free old enid, is copied wherever it's used in proto tree, so no use-after-free */
            wmem_free(wmem_file_scope(), info->id);
            info->id = enid;
        }
    }
}

char* get_conversation_encryption(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    sdmx_enc_info * info = conversation_get_proto_data(conv, proto_citp_sdmx);
    if (info == NULL) return NULL;
    return info->id;
}

static int
dissect_u16_list(tvbuff_t *tvb, proto_tree *tree, int offset, uint32_t count, int hf_list, int ett_list, int hf_list_element) {
    if (count != 0) {
        proto_item *ti = proto_tree_add_item(tree, hf_list, tvb, offset, count * 2, ENC_NA);
        proto_tree *list_tree = proto_item_add_subtree(ti, ett_list);
        for (unsigned int i = 0; i < count; i++) {
            proto_tree_add_item(list_tree, hf_list_element, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
    }
    return offset;
}

static int
dissect_pinf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int str_len;
    const uint8_t *name;
    int offset = 0;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/PINF");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_pinf, tvb, offset, -1, ENC_NA);
    proto_tree *pinf_tree = proto_item_add_subtree(ti, ett_citp_pinf);

    uint32_t content_type;
    proto_tree_add_item_ret_uint(pinf_tree, hf_citp_pinf_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;

    switch (content_type) {
        case CITP_PINF_PNAM:
            proto_tree_add_item_ret_string_and_length(pinf_tree, hf_citp_pinf_name, tvb, offset, -1, ENC_UTF_8, pinfo->pool, &name, &str_len);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "PNam, %s", name);
            break;
        case CITP_PINF_PLOC: {
            uint32_t port;
            proto_tree_add_item_ret_uint(pinf_tree, hf_citp_pinf_listening_port, tvb, offset, 2, ENC_LITTLE_ENDIAN, &port);
            offset += 2;
            proto_tree_add_item_ret_length(pinf_tree, hf_citp_pinf_type, tvb, offset, -1, ENC_UTF_8, &str_len);
            offset += str_len;
            proto_tree_add_item_ret_string_and_length(pinf_tree, hf_citp_pinf_name, tvb, offset, -1, ENC_UTF_8, pinfo->pool, &name, &str_len);
            offset += str_len;
            proto_tree_add_item_ret_length(pinf_tree, hf_citp_pinf_state, tvb, offset, -1, ENC_UTF_8, &str_len);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "PLoc, Port %d, %s", port, name);
            break;
        }
        default:
            expert_add_info(pinfo, tree, &ei_citp_pinf_content_type);
            break;
    }
    return offset;
}

static int
dissect_sdmx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int str_len;
    uint32_t count;
    uint32_t univ_num; const uint8_t *name;
    int offset = 0;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/SDMX");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_sdmx, tvb, offset, -1, ENC_NA);
    proto_tree *sdmx_tree = proto_item_add_subtree(ti, ett_citp_sdmx);

    uint32_t content_type;
    proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;

    switch (content_type) {
        case CITP_SDMX_CAPA:
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_capability_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
            offset += 2;
            offset = dissect_u16_list(tvb, sdmx_tree, offset, count, hf_citp_sdmx_capabilities, ett_citp_sdmx_capabilities, hf_citp_sdmx_capability);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Capa, Count %d", count);
            break;
        case CITP_SDMX_UNAM:
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_universe_index, tvb, offset, 1, ENC_LITTLE_ENDIAN, &univ_num);
            offset += 1;
            proto_tree_add_item_ret_string_and_length(sdmx_tree, hf_citp_sdmx_universe_name, tvb, offset, -1, ENC_UTF_8, pinfo->pool, &name, &str_len);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "UNam, Universe %d: %s", univ_num, name);
            break;
        case CITP_SDMX_ENID: {
            str_len = tvb_strsize(tvb, offset);
            char* enid = (char*)tvb_get_string_enc(wmem_file_scope(), tvb, offset, str_len, ENC_UTF_8);
            proto_tree_add_item(sdmx_tree, hf_citp_sdmx_encryption_identifier, tvb, offset, str_len, ENC_UTF_8);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "EnId, %s", enid);

            /* add encryption info to conversation */
            set_conversation_encryption(pinfo, enid);
            break;
        }
        case CITP_SDMX_CHBK: {
            bool blind;
            proto_tree_add_item_ret_boolean(sdmx_tree, hf_citp_sdmx_blind, tvb, offset, 1, ENC_LITTLE_ENDIAN, &blind);
            offset += 1;
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_universe_index, tvb, offset, 1, ENC_LITTLE_ENDIAN, &univ_num);
            offset += 1;
            uint32_t start_chan;
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_first_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN, &start_chan);
            offset += 2;
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_channel_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
            offset += 2;

            col_add_fstr(pinfo->cinfo, COL_INFO, "ChBk, %s, Universe %d, Channels %d-%d", tfs_get_string(blind, &tfs_live_blind), univ_num, start_chan+1, start_chan+count);

            char* enc_info = get_conversation_encryption(pinfo);
            if (enc_info != NULL) {
                proto_tree_add_item(sdmx_tree, hf_citp_sdmx_encrypted_channel_data, tvb, offset, count, ENC_NA);
                proto_item_set_generated(
                    proto_tree_add_string(sdmx_tree, hf_citp_sdmx_encryption_identifier, tvb, offset, 0, enc_info));

                /* call into encryption sub-dissector */
                col_set_fence(pinfo->cinfo, COL_INFO);
                dissector_try_string_with_data(encryption_id_table, enc_info, tvb_new_subset_length(tvb, offset, count), pinfo, tree, true, NULL);
                col_clear_fence(pinfo->cinfo, COL_INFO);
                offset += count;
            } else {
                tvbuff_t* dmx_tvb = tvb_new_subset_length(tvb, offset, count);
                proto_tree_add_item(sdmx_tree, hf_citp_sdmx_channel_levels, tvb, offset, count, ENC_NA);
                offset += count;

                /* Set info writable,
                 * otherwise dmx-chan will clear the column then not add anything, this keeps some useful info
                 */
                bool saved_write = col_get_writable(pinfo->cinfo, COL_INFO);
                col_set_writable(pinfo->cinfo, COL_INFO, false);
                call_dissector(dmx_chan_handle, dmx_tvb, pinfo, tree);
                col_set_writable(pinfo->cinfo, COL_INFO, saved_write);
            }
            break;
        }
        case CITP_SDMX_CHLS:
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_channel_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
            offset += 2;
            col_add_fstr(pinfo->cinfo, COL_INFO, "ChLs, %d channels", count);

            for (unsigned int i = 0; i < count; i++) {
                proto_item* chan = proto_tree_add_item(sdmx_tree, hf_citp_sdmx_channel_level_block, tvb, offset, 4, ENC_NA);
                proto_tree* chan_tree = proto_item_add_subtree(chan, hf_citp_sdmx_channel_level_block);

                proto_tree_add_item(chan_tree, hf_citp_sdmx_universe_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
                uint32_t chan_idx, chan_level;
                proto_tree_add_item_ret_uint(chan_tree, hf_citp_sdmx_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN, &chan_idx);
                offset+=2;
                proto_tree_add_item_ret_uint(chan_tree, hf_citp_sdmx_channel_level, tvb, offset, 1, ENC_LITTLE_ENDIAN, &chan_level);
                offset+=1;
                proto_item_append_text(chan, ", %u @ %u", chan_idx, chan_level);
            }
            break;
        case CITP_SDMX_SXSR:
            proto_tree_add_item_ret_string_and_length(sdmx_tree, hf_citp_sdmx_connection_string, tvb, offset, -1, ENC_UTF_8, pinfo->pool, &name, &str_len);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "SXSr, %s", name);
            break;
        case CITP_SDMX_SXUS:
            proto_tree_add_item_ret_uint(sdmx_tree, hf_citp_sdmx_universe_index, tvb, offset, 1, ENC_LITTLE_ENDIAN, &univ_num);
            offset += 1;
            proto_tree_add_item_ret_string_and_length(sdmx_tree, hf_citp_sdmx_connection_string, tvb, offset, -1, ENC_UTF_8, pinfo->pool, &name, &str_len);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "SXUS, Universe %d, %s", univ_num, name);
            break;
        default:
            expert_add_info(pinfo, tree, &ei_citp_sdmx_content_type);
            break;
    }

    proto_item_set_len(ti, offset);
    return offset;
}

static int
dissect_fptc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int str_len;
    int offset = 0;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/FPTC");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_fptc, tvb, offset, -1, ENC_NA);
    proto_tree *fptc_tree = proto_item_add_subtree(ti, ett_citp_fptc);

    uint32_t content_type;
    proto_tree_add_item_ret_uint(fptc_tree, hf_citp_fptc_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;
    proto_tree_add_bitmask(fptc_tree, tvb, offset, hf_citp_fptc_content_hint, ett_citp_fptc_content_hint, citp_fptc_content_hint, ENC_LITTLE_ENDIAN);
    offset += 4;

    switch (content_type) {
        case CITP_FPTC_PTCH: {
            uint32_t fixt_id, univ_num, chan_s, chan_cnt;
            proto_tree_add_item_ret_uint(fptc_tree, hf_citp_fptc_fixture_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN, &fixt_id);
            offset += 2;
            proto_tree_add_item_ret_uint(fptc_tree, hf_citp_fptc_universe, tvb, offset, 1, ENC_LITTLE_ENDIAN, &univ_num);
            offset += 1;
            offset += 1; /* RESERVED */
            proto_tree_add_item_ret_uint(fptc_tree, hf_citp_fptc_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN, &chan_s);
            offset += 2;
            proto_tree_add_item_ret_uint(fptc_tree, hf_citp_fptc_channel_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &chan_cnt);
            offset += 2;
            proto_tree_add_item_ret_length(fptc_tree, hf_citp_fptc_fixture_make, tvb, offset, -1, ENC_UTF_8, &str_len);
            offset += str_len;
            proto_tree_add_item_ret_length(fptc_tree, hf_citp_fptc_fixture_name, tvb, offset, -1, ENC_UTF_8, &str_len);
            offset += str_len;
            col_add_fstr(pinfo->cinfo, COL_INFO, "Ptch, ID %d, Universe %d, Channels %d-%d", fixt_id, univ_num, chan_s+1, chan_s+chan_cnt);
            break;
        }
        case CITP_FPTC_SPTC:
        case CITP_FPTC_UPTC: {
            uint32_t count;
            proto_tree_add_item_ret_uint(fptc_tree, hf_citp_fptc_fixture_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
            offset += 2;
            offset = dissect_u16_list(tvb, fptc_tree, offset, count, hf_citp_fptc_fixture_identifiers, ett_citp_fptc_fixture_identifiers, hf_citp_fptc_fixture_identifier);
            col_add_fstr(pinfo->cinfo, COL_INFO, content_type == CITP_FPTC_SPTC ? "SPtc, %s" : "UPtc, %s",
                val_to_str(pinfo->pool, count, citp_all_fixtures_val_str, "%d fixtures"));
            break;
        }
        default:
            expert_add_info(pinfo, tree, &ei_citp_fptc_content_type);
            break;
    }

    return offset;
}

static int
dissect_fsel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/FSEL");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_fsel, tvb, offset, -1, ENC_NA);
    proto_tree *fsel_tree = proto_item_add_subtree(ti, ett_citp_fsel);

    uint32_t content_type;
    proto_tree_add_item_ret_uint(fsel_tree, hf_citp_fsel_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;

    if (content_type != CITP_FSEL_SELE && content_type != CITP_FSEL_DESE) {
        expert_add_info(pinfo, tree, &ei_citp_fsel_content_type);
        return offset;
    }

    if (content_type == CITP_FSEL_SELE) {
        bool complete;
        proto_tree_add_item_ret_boolean(fsel_tree, hf_citp_fsel_complete, tvb, offset, 1, ENC_LITTLE_ENDIAN, &complete);
        offset += 1;
        offset += 1; /* RESERVED */
        col_add_str(pinfo->cinfo, COL_INFO, complete ? "Sele, complete" : "Sele, ");
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "DeSe, ");
    }
    uint32_t count;
    proto_tree_add_item_ret_uint(fsel_tree, hf_citp_fsel_fixture_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
    offset += 2;

    offset = dissect_u16_list(tvb, fsel_tree, offset, count, hf_citp_fsel_fixture_identifiers, ett_citp_fsel_fixture_identifiers, hf_citp_fsel_fixture_identifier);
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(pinfo->pool, count, citp_all_fixtures_val_str, "%d fixtures"));

    return offset;
}

static int
dissect_finf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/FINF");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_finf, tvb, offset, -1, ENC_NA);
    proto_tree *finf_tree = proto_item_add_subtree(ti, ett_citp_finf);

    uint32_t content_type;
    proto_tree_add_item_ret_uint(finf_tree, hf_citp_finf_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;

    switch (content_type) {
        case CITP_FINF_SFRA: {
            uint32_t count;
            proto_tree_add_item_ret_uint(finf_tree, hf_citp_finf_fixture_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
            offset += 2;
            offset = dissect_u16_list(tvb, finf_tree, offset, count, hf_citp_finf_fixture_identifiers, ett_citp_finf_fixture_identifiers, hf_citp_finf_fixture_identifier);
            col_add_fstr(pinfo->cinfo, COL_INFO, "SFra, %s", val_to_str(pinfo->pool, count, citp_all_fixtures_val_str, "%d fixtures"));
            break;
        }
        case CITP_FINF_FRAM: {
            uint32_t fixt_id, filter_count, gobo_count;
            proto_tree_add_item_ret_uint(finf_tree, hf_citp_finf_fixture_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN, &fixt_id);
            offset += 2;
            proto_tree_add_item_ret_uint(finf_tree, hf_citp_finf_frame_filter_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &filter_count);
            offset += 1;
            proto_tree_add_item_ret_uint(finf_tree, hf_citp_finf_frame_gobo_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &gobo_count);
            offset += 1;
            col_add_fstr(pinfo->cinfo, COL_INFO, "Fram, Fixture %d, %d filters, %d gobos", fixt_id, filter_count, gobo_count);

            int str_len;
            proto_tree_add_item_ret_length(finf_tree, hf_citp_finf_frame_names, tvb, offset, -1, ENC_UTF_8, &str_len);
            uint8_t* start = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len, ENC_UTF_8);
            /* based on SrvLoc attribute list parser */
            unsigned int filt_idx = 0;
            uint32_t x = 0;
            uint8_t c = start[x];
            while (c) {
                if  (c == '\n') {
                    if (filt_idx<filter_count)
                        proto_tree_add_item(finf_tree, hf_citp_finf_filter_name, tvb, offset, x, ENC_UTF_8);
                    else
                        proto_tree_add_item(finf_tree, hf_citp_finf_gobo_name, tvb, offset, x, ENC_UTF_8);
                    offset += x+1;
                    start += x+1;
                    filt_idx++;
                    /* reset string length */
                    x = 0;
                    c = start[x];
                } else {
                    /* increment and get next */
                    x++;
                    c = start[x];
                }
            }
            /* add final filter name */
            if (x > 0) {
                if (filt_idx<filter_count)
                    proto_tree_add_item(finf_tree, hf_citp_finf_filter_name, tvb, offset, x, ENC_UTF_8);
                else
                    proto_tree_add_item(finf_tree, hf_citp_finf_gobo_name, tvb, offset, x, ENC_UTF_8);
                offset += x+1;
            }
            break;
        }
        default:
            expert_add_info(pinfo, tree, &ei_citp_finf_content_type);
            break;
    }

    return offset;
}


static int
dissect_caex_view_inner(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {
    proto_tree_add_item(tree, hf_citp_caex_view_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_citp_caex_view_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    proto_item *pos = proto_tree_add_item(tree, hf_citp_caex_view_position, tvb, offset, 12, ENC_NA);
    proto_tree *pos_tree = proto_item_add_subtree(pos, ett_citp_caex_view_pos);
    proto_tree_add_item(pos_tree, hf_citp_caex_view_position_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(pos_tree, hf_citp_caex_view_position_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(pos_tree, hf_citp_caex_view_position_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    proto_item *focus = proto_tree_add_item(tree, hf_citp_caex_view_focus, tvb, offset, 12, ENC_NA);
    proto_tree *focus_tree = proto_item_add_subtree(focus, ett_citp_caex_view_focus);
    proto_tree_add_item(focus_tree, hf_citp_caex_view_focus_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(focus_tree, hf_citp_caex_view_focus_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(focus_tree, hf_citp_caex_view_focus_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    return offset;
}

static int
dissect_caex_cue_inner(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t content_code) {
    uint32_t option_count;
    int str_len, prev_offset;
    proto_tree_add_item_ret_uint(tree, hf_citp_caex_cue_option_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &option_count);
    offset+=1;
    for (unsigned int i = 0; i < option_count; i++) {
        prev_offset = offset;
        proto_item *option = proto_tree_add_item(tree, hf_citp_caex_cue_option, tvb, offset, -1, ENC_NA);
        proto_tree *option_tree = proto_item_add_subtree(option, ett_citp_caex_cue_option);

        const uint8_t* option_name;
        proto_tree_add_item_ret_string_and_length(option_tree, hf_citp_caex_cue_option_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &option_name, &str_len);
        offset+=str_len;
        if (content_code == CITP_CAEX_CUE_RECORD_CAPA) {
            proto_tree_add_item_ret_length(option_tree, hf_citp_caex_cue_option_choices, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
            offset+=str_len;
            proto_tree_add_item_ret_length(option_tree, hf_citp_caex_cue_option_help, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
            offset+=str_len;
        } else if (content_code == CITP_CAEX_CUE_RECORD) {
            proto_tree_add_item_ret_length(option_tree, hf_citp_caex_cue_option_value, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
            offset+=str_len;
        }

        proto_item_append_text(option, ": %s", option_name);
        proto_item_set_len(option, offset-prev_offset);
    }
    return offset;
}

static int
dissect_caex_fixture(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t content_code) {
    const uint8_t* str;
    int str_len;
    uint32_t fixture_id;
    if (content_code == CITP_CAEX_FIXTURE_LIST) {
        proto_tree_add_item(tree, hf_citp_caex_show_fixture_list_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
    }

    uint32_t fixture_count;
    proto_tree_add_item_ret_uint(tree, hf_citp_caex_show_fixture_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &fixture_count);
    offset+=2;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %d fixtures", fixture_count);
    if (fixture_count == 0)
        return offset;

    proto_item *list_item = proto_tree_add_item(tree, hf_citp_caex_show_fixtures, tvb, offset, -1, ENC_NA);
    proto_tree *list_tree = proto_item_add_subtree(list_item, ett_citp_caex_show_fixtures);

    if (content_code == CITP_CAEX_FIXTURE_REMOVE || content_code == CITP_CAEX_FIXTURE_SELECT) {
        for (unsigned int i = 0; i < fixture_count; i++) {
            proto_tree_add_item(list_tree, hf_citp_caex_show_fixture_console_identifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        }
    }
    else if (content_code == CITP_CAEX_FIXTURE_STATUS || content_code == CITP_CAEX_FIXTURE_ID) {
        for (unsigned int i = 0; i < fixture_count; i++) {
            proto_item *fixture = proto_tree_add_item(list_tree, hf_citp_caex_show_fixture, tvb, offset, -1, ENC_NA);
            proto_tree *fixt_tree = proto_item_add_subtree(fixture, ett_citp_caex_show_fixture);

            if (content_code == CITP_CAEX_FIXTURE_ID) {
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_identifier_capture_instance_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
                offset+=16;
                proto_item_set_len(fixture, 20);
            }

            proto_tree_add_item_ret_uint(fixt_tree, hf_citp_caex_show_fixture_console_identifier, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fixture_id);
            offset+=4;
            proto_item_append_text(fixture, ", ID: %u", fixture_id);

            if (content_code == CITP_CAEX_FIXTURE_STATUS) {
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_locked, tvb, offset, 1, ENC_NA);
                offset+=1;
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_clearable, tvb, offset, 1, ENC_NA);
                offset+=1;
                proto_item_set_len(fixture, 6);
            }
        }
    }
    else if (content_code == CITP_CAEX_FIXTURE_LIST || content_code == CITP_CAEX_FIXTURE_MODIFY) {
        for (unsigned int i = 0; i < fixture_count; i++) {
            proto_item *fixture = proto_tree_add_item(list_tree, hf_citp_caex_show_fixture, tvb, offset, -1, ENC_NA);
            proto_tree *fixt_tree = proto_item_add_subtree(fixture, ett_citp_caex_show_fixture);
            int s_offset = offset;
            proto_tree_add_item_ret_uint(fixt_tree, hf_citp_caex_show_fixture_console_identifier, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fixture_id);
            offset+=4;
            proto_item_append_text(fixture, ", ID: %u", fixture_id);

            uint32_t changed_fields = 0xFF;
            if (content_code == CITP_CAEX_FIXTURE_LIST) {
                proto_tree_add_item_ret_string_and_length(fixt_tree, hf_citp_caex_show_fixture_manufacturer_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &str, &str_len);
                proto_item_append_text(fixture, ", %s", str);
                offset+=str_len;
                proto_tree_add_item_ret_string_and_length(fixt_tree, hf_citp_caex_show_fixture_model_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &str, &str_len);
                proto_item_append_text(fixture, ", %s", str);
                offset+=str_len;
                proto_tree_add_item_ret_length(fixt_tree, hf_citp_caex_show_fixture_mode_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
                offset+=str_len;
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_channel_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_is_dimmer, tvb, offset, 1, ENC_NA);
                offset+=1;

                uint32_t identifier_count;
                proto_tree_add_item_ret_uint(fixt_tree, hf_citp_caex_show_fixture_identifier_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &identifier_count);
                offset+=1;
                for (unsigned int j = 0; j < identifier_count; j++) {
                    proto_item *ident = proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_identifier, tvb, offset, -1, ENC_NA);
                    proto_tree *ident_tree = proto_item_add_subtree(ident, ett_citp_caex_show_fixture_identifier);

                    uint32_t ident_type, ident_data_size;
                    proto_tree_add_item_ret_uint(ident_tree, hf_citp_caex_show_fixture_identifier_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ident_type);
                    offset+=1;
                    proto_tree_add_item_ret_uint(ident_tree, hf_citp_caex_show_fixture_identifier_data_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ident_data_size);
                    proto_item_set_len(ident, 3+ident_data_size);
                    offset+=2;
                    proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_data, tvb, offset, ident_data_size, ENC_NA);

                    switch (ident_type) {
                        case CITP_CAEX_IDENTIFIER_RDM_MANF:
                            proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_rdm_manufacturer_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            break;
                        case CITP_CAEX_IDENTIFIER_RDM_MODEL:
                            proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_rdm_device_model_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            break;
                        case CITP_CAEX_IDENTIFIER_RDM_PERSON:
                            proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_rdm_personality_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                            break;
                        case CITP_CAEX_IDENTIFIER_ALTA_FIXT:
                            proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_altabase_fixture_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
                            break;
                        case CITP_CAEX_IDENTIFIER_ALTA_MODEL:
                            proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_altabase_mode_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
                            break;
                        case CITP_CAEX_IDENTIFIER_CAPTURE_INSTANCE:
                            proto_tree_add_item(ident_tree, hf_citp_caex_show_fixture_identifier_capture_instance_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
                            break;
                        default:
                            expert_add_info(pinfo, tree, &ei_citp_caex_fixture_ident);
                            break;
                    }

                    offset+=ident_data_size;
                }
            }
            else if (content_code == CITP_CAEX_FIXTURE_MODIFY) {
                changed_fields = tvb_get_uint8(tvb, offset);
                proto_tree_add_bitmask(fixt_tree, tvb, offset, hf_citp_caex_show_fixture_changed_fields, ett_citp_caex_show_fixture_changed_fields, citp_caex_show_fixture_changed_fields, ENC_LITTLE_ENDIAN);
                offset+=1;
            }

            if (changed_fields & 0x01) {
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_patched, tvb, offset, 1, ENC_NA);
                offset+=1;
                uint32_t univ, chan;
                proto_tree_add_item_ret_uint(fixt_tree, hf_citp_caex_show_fixture_universe, tvb, offset, 1, ENC_LITTLE_ENDIAN, &univ);
                offset+=1;
                proto_tree_add_item_ret_uint(fixt_tree, hf_citp_caex_show_fixture_universe_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN, &chan);
                offset+=2;
                proto_item_append_text(fixture, ", Universe: %u, Channel: %u", univ, chan);
            }
            if (changed_fields & 0x02) {
                proto_tree_add_item_ret_length(fixt_tree, hf_citp_caex_show_fixture_unit, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
                offset+=str_len;
            }
            if (changed_fields & 0x04) {
                proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
            }
            if (changed_fields & 0x08) {
                proto_tree_add_item_ret_length(fixt_tree, hf_citp_caex_show_fixture_circuit, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
                offset+=str_len;
            }
            if (changed_fields & 0x10) {
                proto_tree_add_item_ret_length(fixt_tree, hf_citp_caex_show_fixture_note, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
                offset+=str_len;
            }
            if (changed_fields & 0x20) {
                proto_item *pos = proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_position, tvb, offset, 12, ENC_NA);
                proto_tree *pos_tree = proto_item_add_subtree(pos, ett_citp_caex_show_fixture_pos);
                proto_tree_add_item(pos_tree, hf_citp_caex_show_fixture_position_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset+=4;
                proto_tree_add_item(pos_tree, hf_citp_caex_show_fixture_position_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset+=4;
                proto_tree_add_item(pos_tree, hf_citp_caex_show_fixture_position_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset+=4;

                proto_item *focus = proto_tree_add_item(fixt_tree, hf_citp_caex_show_fixture_angles, tvb, offset, 12, ENC_NA);
                proto_tree *focus_tree = proto_item_add_subtree(focus, ett_citp_caex_show_fixture_angles);
                proto_tree_add_item(focus_tree, hf_citp_caex_show_fixture_angles_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset+=4;
                proto_tree_add_item(focus_tree, hf_citp_caex_show_fixture_angles_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset+=4;
                proto_tree_add_item(focus_tree, hf_citp_caex_show_fixture_angles_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset+=4;
            }

            proto_item_set_len(fixture, offset - s_offset);
        }
    }


    return offset;
}

static int
dissect_caex_laser_frame(tvbuff_t *tvb, int offset, packet_info *pinfo  _U_, proto_tree *tree) {
    proto_tree_add_item(tree, hf_citp_caex_laser_source_key, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(tree, hf_citp_caex_laser_feed_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    proto_tree_add_item(tree, hf_citp_caex_laser_frame_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    uint32_t point_count;
    proto_tree_add_item_ret_uint(tree, hf_citp_caex_laser_point_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &point_count);
    offset+=2;
    for (unsigned int i = 0; i < point_count; i++) {
        proto_item *point = proto_tree_add_item(tree, hf_citp_caex_laser_point, tvb, offset, 5, ENC_NA);
        proto_tree *point_tree = proto_item_add_subtree(point, ett_citp_caex_laser_point);

        uint32_t x, y, xy;
        proto_tree_add_item_ret_uint(point_tree, hf_citp_caex_laser_point_x_low, tvb, offset, 1, ENC_LITTLE_ENDIAN, &x);
        offset+=1;
        proto_tree_add_item_ret_uint(point_tree, hf_citp_caex_laser_point_y_low, tvb, offset, 1, ENC_LITTLE_ENDIAN, &y);
        offset+=1;
        proto_tree_add_item_ret_uint(point_tree, hf_citp_caex_laser_point_xy_high, tvb, offset, 1, ENC_LITTLE_ENDIAN, &xy);
        offset+=1;

        proto_item_set_generated(
            proto_tree_add_uint(point_tree, hf_citp_caex_laser_point_x, tvb, offset, 0, x + ((xy&0x0F)<<8)));
        proto_item_set_generated(
            proto_tree_add_uint(point_tree, hf_citp_caex_laser_point_y, tvb, offset, 0, y + ((xy&0xF0)<<4)));

        proto_tree_add_bitmask(point_tree, tvb, offset, hf_citp_caex_laser_point_colour, ett_citp_caex_laser_point_colour, citp_caex_laser_point_colour_fields, ENC_LITTLE_ENDIAN);
        offset+=2;
    }

    return offset;
}

static int
dissect_caex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    const uint8_t *str;
    int str_len;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/CAEX");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_caex, tvb, offset, -1, ENC_NA);
    proto_tree *caex_tree = proto_item_add_subtree(ti, ett_citp_caex);

    uint32_t content_code;
    proto_tree_add_item_ret_uint(caex_tree, hf_citp_caex_content_code, tvb, offset, 4, ENC_LITTLE_ENDIAN, &content_code);
    offset += 4;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(content_code, citp_caex_content_code_names, "Unknown Message Type"));

    switch (content_code) {
        case CITP_CAEX_NACK:
            proto_tree_add_item(caex_tree, hf_citp_caex_nack_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            break;

        case CITP_CAEX_LIVE_VIEW_GET_STATUS: break;
        case CITP_CAEX_LIVE_VIEW_STATUS:
            proto_tree_add_item(caex_tree, hf_citp_caex_view_availability, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            offset = dissect_caex_view_inner(tvb, offset, pinfo, caex_tree);
            break;
        case CITP_CAEX_LIVE_VIEW_GET_IMAGE: {
            uint32_t format;
            proto_tree_add_item_ret_uint(caex_tree, hf_citp_caex_view_format, tvb, offset, 1, ENC_LITTLE_ENDIAN, &format);
            if (format != 1)
                expert_add_info(pinfo, tree, &ei_citp_caex_view_format);
            offset+=1;
            offset = dissect_caex_view_inner(tvb, offset, pinfo, caex_tree);
            break;
        }
        case CITP_CAEX_LIVE_VIEW_IMAGE: {
            uint32_t format, data_size;
            proto_tree_add_item_ret_uint(caex_tree, hf_citp_caex_view_format, tvb, offset, 1, ENC_LITTLE_ENDIAN, &format);
            offset+=1;
            proto_tree_add_item_ret_uint(caex_tree, hf_citp_caex_view_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &data_size);
            offset+=4;
            if (format == 1) {
                /* call out to JPEG dissector */
                tvbuff_t* jpeg_tvb = tvb_new_subset_length(tvb, offset, data_size);
                call_dissector(jpeg_handle, jpeg_tvb, pinfo, tree);
            } else {
                /* No other formats currently defined */
                expert_add_info(pinfo, tree, &ei_citp_caex_view_format);
                proto_tree_add_item(tree, hf_citp_caex_view_data, tvb, offset, data_size, ENC_NA);
                offset+=data_size;
            }
            break;
        }

        case CITP_CAEX_CUE_RECORD_CAPA:
            proto_tree_add_item(caex_tree, hf_citp_caex_cue_availability, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            offset = dissect_caex_cue_inner(tvb, offset, pinfo, caex_tree, content_code);
            break;
        case CITP_CAEX_CUE_RECORD:
            offset = dissect_caex_cue_inner(tvb, offset, pinfo, caex_tree, content_code);
            break;
        case CITP_CAEX_CUE_CLEAR_CAPA:
            proto_tree_add_item(caex_tree, hf_citp_caex_cue_clear_availability, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            break;
        case CITP_CAEX_CUE_CLEAR: break;

        case CITP_CAEX_SHOW_ENTER:
            proto_tree_add_item_ret_string_and_length(caex_tree, hf_citp_caex_show_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &str, &str_len);
            offset+=str_len;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", str);
            break;
        case CITP_CAEX_SHOW_LEAVE: break;
        case CITP_CAEX_SET_TRANS_SPACE:
            proto_tree_add_item(caex_tree, hf_citp_caex_show_transformation_space, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            break;
        case CITP_CAEX_FIXTURE_LIST_REQ: break;
        case CITP_CAEX_FIXTURE_LIST:
        case CITP_CAEX_FIXTURE_ID:
        case CITP_CAEX_FIXTURE_MODIFY:
        case CITP_CAEX_FIXTURE_REMOVE:
        case CITP_CAEX_FIXTURE_SELECT:
        case CITP_CAEX_FIXTURE_STATUS:
            offset = dissect_caex_fixture(tvb, offset, pinfo, caex_tree, content_code);
            break;

        case CITP_CAEX_LASER_GET_LIST: break;
        case CITP_CAEX_LASER_LIST: {
            proto_tree_add_item(caex_tree, hf_citp_caex_laser_source_key, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            uint32_t feed_count;
            proto_tree_add_item_ret_uint(caex_tree, hf_citp_caex_laser_feed_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &feed_count);
            offset+=1;
            for (unsigned int i = 0; i < feed_count; i++) {
                proto_tree_add_item_ret_length(caex_tree, hf_citp_caex_laser_feed_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
                offset+=str_len;
            }
            break;
        }
        case CITP_CAEX_LASER_CONTROL:
            proto_tree_add_item(caex_tree, hf_citp_caex_laser_feed_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(caex_tree, hf_citp_caex_laser_frame_rate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            break;
        case CITP_CAEX_LASER_FRAME:
            offset = dissect_caex_laser_frame(tvb, offset, pinfo, caex_tree);
            break;
        default:
            expert_add_info(pinfo, tree, &ei_citp_caex_content_code);
            break;
    }

    return offset;
}



static uint32_t
dissect_msex_count(tvbuff_t *tvb, proto_tree *tree, int *offset, uint16_t version, int hf) {
    uint32_t ret;
    if (version >= CITP_MSEX_V12) {
        proto_tree_add_item_ret_uint(tree, hf, tvb, *offset, 2, ENC_LITTLE_ENDIAN, &ret);
        *offset += 2;
    } else {
        proto_tree_add_item_ret_uint(tree, hf, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &ret);
        *offset += 1;
    }
    return ret;
}

static int
dissect_msex_library_num_or_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool do_id, const char **str_out) {
    if (do_id) {
        proto_item* id = proto_tree_add_item(tree, hf_citp_msex_library_id, tvb, offset, 4, ENC_NA);
        proto_tree* id_tree = proto_item_add_subtree(id, ett_citp_msex_library_id);

        uint32_t l, l1, l2, l3;
        proto_tree_add_item_ret_uint(id_tree, hf_citp_msex_library_id_level, tvb, offset, 1, ENC_LITTLE_ENDIAN, &l);
        offset+=1;
        proto_tree_add_item_ret_uint(id_tree, hf_citp_msex_library_id_level_1, tvb, offset, 1, ENC_LITTLE_ENDIAN, &l1);
        offset+=1;
        proto_tree_add_item_ret_uint(id_tree, hf_citp_msex_library_id_level_2, tvb, offset, 1, ENC_LITTLE_ENDIAN, &l2);
        offset+=1;
        proto_tree_add_item_ret_uint(id_tree, hf_citp_msex_library_id_level_3, tvb, offset, 1, ENC_LITTLE_ENDIAN, &l3);
        offset+=1;

        if (l == 0) {
            proto_item_append_text(id, ": Root");
        } else if (l == 1) {
            proto_item_append_text(id, ": %u", l1);
        } else if (l == 2) {
            proto_item_append_text(id, ": %u.%u", l1, l2);
        } else {
            proto_item_append_text(id, ": %u.%u.%u", l1, l2, l3);
        }
        if (str_out != NULL) {
            wmem_strbuf_t *strbuf = wmem_strbuf_new(pinfo->pool, "");
            if (l == 0) {
                wmem_strbuf_append_printf(strbuf, "root");
            } else if (l == 1) {
                wmem_strbuf_append_printf(strbuf, "%u", l1);
            } else if (l == 2) {
                wmem_strbuf_append_printf(strbuf, "%u.%u", l1, l2);
            } else {
                wmem_strbuf_append_printf(strbuf, "%u.%u.%u", l1, l2, l3);
            }
            *str_out = wmem_strbuf_get_str(strbuf);
        }
    } else {
        uint32_t library_number;
        proto_tree_add_item_ret_uint(tree, hf_citp_msex_library_number, tvb, offset, 1, ENC_LITTLE_ENDIAN, &library_number);
        offset+=1;
        if (str_out != NULL) {
            wmem_strbuf_t *strbuf = wmem_strbuf_new(pinfo->pool, "");
            wmem_strbuf_append_printf(strbuf, "%d", library_number);
            *str_out = wmem_strbuf_get_str(strbuf);
        }
    }
    return offset;
}

static int
dissect_msex_supported_versions(tvbuff_t *tvb, proto_tree *tree, int offset) {
    uint32_t count;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_supported_version_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
    offset+=1;
    if (count > 0) {
        proto_item *supv = proto_tree_add_item(tree, hf_citp_msex_supported_versions, tvb, offset, count*2, ENC_NA);
        proto_tree *supv_tree = proto_item_add_subtree(supv, ett_citp_msex_supported_versions);

        for (unsigned int i = 0; i < count; i++) {
            proto_item *ver = proto_tree_add_item(supv_tree, hf_citp_msex_supported_version, tvb, offset, 2, ENC_NA);
            proto_tree *ver_tree = proto_item_add_subtree(ver, ett_citp_msex_supported_version);

            uint32_t major, minor;
            proto_tree_add_item_ret_uint(ver_tree, hf_citp_msex_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN, &major);
            offset+=1;
            proto_tree_add_item_ret_uint(ver_tree, hf_citp_msex_version_minor, tvb, offset, 1, ENC_LITTLE_ENDIAN, &minor);
            offset+=1;

            proto_item_append_text(ver, ": v%u.%u", major, minor);
            proto_item_append_text(supv, i == 0 ? ": v%u.%u" : ", v%u.%u", major, minor);
        }
    }
    return offset;
}

static int
dissect_msex_affected_array(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_all, int ett_all, int hf_single) {
    proto_item* ti = proto_tree_add_item(tree, hf_all, tvb, offset, 32, ENC_NA);
    proto_tree* aff = proto_item_add_subtree(ti, ett_all);
    bool first = true;

    for (int i = 0; i < 32; i++) {
        uint8_t dat = tvb_get_uint8(tvb, offset);
        for (int j = 0; j < 8; j++) {
            if ((1<<j) & dat) {
                proto_item_set_generated(proto_tree_add_uint(aff, hf_single, tvb, offset, 1, i*8 + j));

                proto_item_append_text(ti, first ? ": %u" : ", %u", i*8 + j);
                first = false;
            }
        }
        offset+=1;
    }
    return offset;
}


/**SInf
 * - Server Information
 */
static int
dissect_msex_sinf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, uint16_t version) {
    int str_len;
    uint32_t count;

    if (version >= CITP_MSEX_V12) {
        proto_tree_add_item_ret_length(tree, hf_citp_msex_uuid, tvb, offset, -1, ENC_UTF_8, &str_len);
        offset+=str_len;
    }
    proto_tree_add_item_ret_length(tree, hf_citp_msex_product_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
    offset+=str_len;
    proto_tree_add_item(tree, hf_citp_msex_product_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    proto_tree_add_item(tree, hf_citp_msex_product_version_minor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    if (version >= CITP_MSEX_V12) {
        proto_tree_add_item(tree, hf_citp_msex_product_version_bugfix, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        offset = dissect_msex_supported_versions(tvb, tree, offset);
        proto_tree_add_bitmask(tree, tvb, offset, hf_citp_msex_supported_library_types, ett_citp_msex_supported_library_types, citp_msex_supported_library_types, ENC_LITTLE_ENDIAN);
        offset+=2;

        proto_tree_add_item_ret_uint(tree, hf_citp_msex_thumbnail_format_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
        offset+=1;
        proto_item *thumb = proto_tree_add_item(tree, hf_citp_msex_thumbnail_formats, tvb, offset, count*4, ENC_NA);
        proto_tree *thumb_tree = proto_item_add_subtree(thumb, ett_citp_msex_thumbnail_formats);
        for (unsigned int i = 0; i < count; i++) {
            proto_tree_add_item(thumb_tree, hf_citp_msex_thumbnail_format, tvb, offset, 4, ENC_ASCII);
            offset+=4;
        }

        proto_tree_add_item_ret_uint(tree, hf_citp_msex_stream_format_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
        offset+=1;
        proto_item *stream = proto_tree_add_item(tree, hf_citp_msex_stream_formats, tvb, offset, count*4, ENC_NA);
        proto_tree *stream_tree = proto_item_add_subtree(stream, ett_citp_msex_stream_formats);
        for (unsigned int i = 0; i < count; i++) {
            proto_tree_add_item(stream_tree, hf_citp_msex_stream_format, tvb, offset, 4, ENC_ASCII);
            offset+=4;
        }
    }

    proto_tree_add_item_ret_uint(tree, hf_citp_msex_layer_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
    offset+=1;
    proto_item* layer = proto_tree_add_item(tree, hf_citp_msex_layers, tvb, offset, -1, ENC_NA);
    proto_tree* layer_tree = proto_item_add_subtree(layer, ett_citp_msex_layers);
    int s_offset = offset;
    for (unsigned int i = 0; i < count; i++) {
        proto_tree_add_item_ret_length(layer_tree, hf_citp_msex_layer_dmx_source, tvb, offset, -1, ENC_UTF_8, &str_len);
        offset+=str_len;
    }
    proto_item_set_len(layer, offset-s_offset);

    return offset;
}

/**LSta
 * - Layer Status
 */
static int
dissect_msex_lsta(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version) {
    int str_len;
    uint32_t count;

    proto_tree_add_item_ret_uint(tree, hf_citp_msex_layer_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
    offset+=1;

    proto_item *layers = proto_tree_add_item(tree, hf_citp_msex_layers, tvb, offset, -1, ENC_NA);
    proto_tree *layers_tree = proto_item_add_subtree(layers, ett_citp_msex_layers);
    int list_offset = offset;
    for (unsigned int i = 0; i < count; i++) {
        proto_item* layer = proto_tree_add_item(layers_tree, hf_citp_msex_layer, tvb, offset, -1, ENC_NA);
        proto_tree* layer_tree = proto_item_add_subtree(layer, ett_citp_msex_layer);
        int layer_offset = offset;

        proto_tree_add_item(layer_tree, hf_citp_msex_layer_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(layer_tree, hf_citp_msex_layer_physical_output, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        if (version >= CITP_MSEX_V12) {
            proto_tree_add_item(layer_tree, hf_citp_msex_library_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
        }
        offset = dissect_msex_library_num_or_id(tvb, pinfo, layer_tree, offset, version >= CITP_MSEX_V12, NULL);
        proto_tree_add_item(layer_tree, hf_citp_msex_element_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item_ret_length(layer_tree, hf_citp_msex_element_name, tvb, offset, -1, ENC_LITTLE_ENDIAN, &str_len);
        offset+=str_len;
        proto_tree_add_item(layer_tree, hf_citp_msex_element_position, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(layer_tree, hf_citp_msex_element_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(layer_tree, hf_citp_msex_element_fps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_bitmask(layer_tree, tvb, offset, hf_citp_msex_layer_status_flags, ett_citp_msex_layer_status_flags, citp_msex_layer_status_flags, ENC_LITTLE_ENDIAN);
        offset+=4;

        proto_item_set_len(layer, offset-layer_offset);
    }
    proto_item_set_len(layers, offset-list_offset);

    return offset;
}

/**GELI, ELIn
 * - Get Element Library Information
 * - Element Library Information
 */
static int
dissect_msex_library(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version, uint32_t content_type) {
    uint32_t library_type;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_library_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &library_type);
    offset+=1;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Type: %s", val_to_str_const(library_type, citp_msex_library_types, "Unknown"));

    if (version >= CITP_MSEX_V11 && content_type == CITP_MSEX_GELI) {
        const char* parent_s;
        offset = dissect_msex_library_num_or_id(tvb, pinfo, tree, offset, true, &parent_s);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Parent: %s", parent_s);
    }

    uint32_t library_count = dissect_msex_count(tvb, tree, &offset, version, hf_citp_msex_library_count);
    if (library_count == 0) {
        if (content_type == CITP_MSEX_GELI) {
            col_append_str(pinfo->cinfo, COL_INFO, ", All libraries");
        }
        return offset;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %d libraries", library_count);

    proto_item *libs = proto_tree_add_item(tree, hf_citp_msex_libraries, tvb, offset, -1, ENC_NA);
    proto_tree *libs_tree = proto_item_add_subtree(libs, ett_citp_msex_libraries);

    if (content_type == CITP_MSEX_GELI) {
        proto_item_set_len(libs, library_count);
        for (unsigned int i = 0; i < library_count; i++) {
            proto_tree_add_item(libs_tree, hf_citp_msex_library_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
        }
        return offset;
    }

    int s_offset = offset;
    for (unsigned int i = 0; i < library_count; i++) {
        proto_item *lib = proto_tree_add_item(libs_tree, hf_citp_msex_library, tvb, offset, -1, ENC_NA);
        proto_tree *lib_tree = proto_item_add_subtree(lib, ett_citp_msex_library);
        int l_offset = offset;

        const char* lib_num;
        const uint8_t* lib_name;
        int lib_name_len;
        uint32_t elem_count;
        offset = dissect_msex_library_num_or_id(tvb, pinfo, lib_tree, offset, version >= CITP_MSEX_V11, &lib_num);
        if (version >= CITP_MSEX_V12) {
            proto_tree_add_item(lib_tree, hf_citp_msex_library_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        }
        proto_tree_add_item(lib_tree, hf_citp_msex_library_dmx_min, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(lib_tree, hf_citp_msex_library_dmx_max, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item_ret_string_and_length(lib_tree, hf_citp_msex_library_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &lib_name, &lib_name_len);
        offset+=lib_name_len;
        /* These fields can be either 8 or 16 bits */
        if (version >= CITP_MSEX_V11) {
            dissect_msex_count(tvb, lib_tree, &offset, version, hf_citp_msex_library_sub_count);
        }
        elem_count = dissect_msex_count(tvb, lib_tree, &offset, version, hf_citp_msex_library_element_count);

        proto_item_set_len(lib, offset-l_offset);
        if (lib_name_len > 2) { /* UCS_2, so 2 bytes for null terminator */
            proto_item_append_text(lib, ", %s: %s, %d elements", lib_num, lib_name, elem_count);
        } else {
            proto_item_append_text(lib, ", %s, %d elements", lib_num, elem_count);
        }
    }
    proto_item_set_len(libs, offset-s_offset);

    return offset;
}

/** GEIn, MEIn, EEIn, GLIn
 * - Get Element Information
 * - Media Element Information
 * - Effect Element Information
 * - Generic Element Information
 */
static int
dissect_msex_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version, uint32_t content_type) {
    int str_len;

    uint32_t library_type;
    if (content_type == CITP_MSEX_GEIN || (content_type == CITP_MSEX_GLEI && version >= CITP_MSEX_V12)) {
        proto_tree_add_item_ret_uint(tree, hf_citp_msex_library_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &library_type);
        offset+=1;
    } else if (content_type == CITP_MSEX_MEIN) {
        library_type = 1;
    } else { /* EEIn */
        library_type = 2;
    }
    const char* lib_str;
    offset = dissect_msex_library_num_or_id(tvb, pinfo, tree, offset, version >= CITP_MSEX_V11, &lib_str);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Library: %s (%s)", lib_str,
        val_to_str_const(library_type, citp_msex_library_types, "Unknown"));

    uint32_t element_count = dissect_msex_count(tvb, tree, &offset, version, hf_citp_msex_element_count);
    if (element_count == 0) {
        if (content_type == CITP_MSEX_GEIN) {
            col_append_str(pinfo->cinfo, COL_INFO, ", All elements");
        }
        return offset;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %d elements", element_count);

    proto_item *elems = proto_tree_add_item(tree, hf_citp_msex_elements, tvb, offset, -1, ENC_NA);
    proto_tree *elems_tree = proto_item_add_subtree(elems, ett_citp_msex_elements);

    if (content_type == CITP_MSEX_GEIN) {
        proto_item_set_len(elems, element_count);
        for (unsigned int i = 0; i < element_count; i++) {
            proto_tree_add_item(tree, hf_citp_msex_element_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
        }
        return offset;
    }

    int s_offset = offset;
    for (unsigned int i = 0; i < element_count; i++) {
        proto_item *elem = proto_tree_add_item(elems_tree, hf_citp_msex_element, tvb, offset, -1, ENC_NA);
        proto_tree *elem_tree = proto_item_add_subtree(elem, ett_citp_msex_element);
        int e_offset = offset;

        uint32_t elem_num;
        proto_tree_add_item_ret_uint(elem_tree, hf_citp_msex_element_number, tvb, offset, 1, ENC_LITTLE_ENDIAN, &elem_num);
        offset+=1;
        if (version >= CITP_MSEX_V12) {
            proto_tree_add_item(elem_tree, hf_citp_msex_element_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        }
        proto_tree_add_item(elem_tree, hf_citp_msex_element_dmx_min, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(elem_tree, hf_citp_msex_element_dmx_max, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        const uint8_t* elem_name;
        proto_tree_add_item_ret_string_and_length(elem_tree, hf_citp_msex_element_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &elem_name, &str_len);
        offset+=str_len;

        proto_item_append_text(elem, ", %u: %s", elem_num, elem_name);

        if (content_type == CITP_MSEX_MEIN || content_type == CITP_MSEX_GLEI) {
            proto_tree_add_item(elem_tree, hf_citp_msex_element_version_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+=8;
        }

        if (content_type == CITP_MSEX_MEIN) {
            proto_tree_add_item(elem_tree, hf_citp_msex_element_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(elem_tree, hf_citp_msex_element_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(elem_tree, hf_citp_msex_element_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(elem_tree, hf_citp_msex_element_fps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
        } else if (content_type == CITP_MSEX_EEIN) {
            uint32_t param_count;
            proto_tree_add_item_ret_uint(elem_tree, hf_citp_msex_element_parameter_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_count);
            offset+=1;
            if (param_count > 0) {
                proto_item *params = proto_tree_add_item(elems_tree, hf_citp_msex_element_parameter_names, tvb, offset, -1, ENC_NA);
                proto_tree *params_tree = proto_item_add_subtree(elem, ett_citp_msex_element_parameter_names);
                int p_offset = offset;

                for (unsigned int j = 0; j < param_count; j++) {
                    proto_tree_add_item_ret_length(params_tree, hf_citp_msex_element_parameter_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, &str_len);
                    offset+=str_len;
                }
                proto_item_set_len(params, offset-p_offset);
            }
        }

        proto_item_set_len(elem, offset-e_offset);
    }
    proto_item_set_len(elems, offset-s_offset);

    return offset;
}

/** GELT, GETh
 * - Get Element Library Thumbnail
 * - Get Element Thumbnail
*/
static int
dissect_msex_thumbnail_get(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version, uint32_t content_type) {
    const uint8_t* thumb_format_str;
    uint32_t thumbnail_format = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_string(tree, hf_citp_msex_thumbnail_format, tvb, offset, 4, ENC_ASCII, pinfo->pool, &thumb_format_str);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Format: %s", thumb_format_str);
    offset+=4;
    if (thumbnail_format != CITP_MSEX_FORMAT_RGB8 && thumbnail_format != CITP_MSEX_FORMAT_JPEG && thumbnail_format != CITP_MSEX_FORMAT_PNG) {
        expert_add_info(pinfo, tree, &ei_citp_msex_thumb_format);
    }

    proto_tree_add_item(tree, hf_citp_msex_thumbnail_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_citp_msex_thumbnail_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_citp_msex_thumbnail_flags, ett_citp_msex_thumbnail_flags, citp_msex_thumbnail_flags, ENC_LITTLE_ENDIAN);
    offset+=1;
    uint32_t library_type;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_library_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &library_type);
    offset+=1;

    uint32_t count;
    if (content_type == CITP_MSEX_GELT) { /* Library thumbnails */
        count = dissect_msex_count(tvb, tree, &offset, version, hf_citp_msex_library_count);
        if (count == 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ", All libraries");
            return offset;
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d libraries", count);

        proto_item *libs = proto_tree_add_item(tree, hf_citp_msex_libraries, tvb, offset, -1, ENC_NA);
        proto_tree *libs_tree = proto_item_add_subtree(libs, ett_citp_msex_libraries);

        if (version >= CITP_MSEX_V11) {
            proto_item_set_len(libs, count);
        } else {
            proto_item_set_len(libs, count*4);
        }
        for (unsigned int i = 0; i < count; i++) {
            offset = dissect_msex_library_num_or_id(tvb, pinfo, libs_tree, offset, version >= CITP_MSEX_V11, NULL);
        }
    } else { /* Element thumbnails CITP_MSEX_GETH */
        const char *lib_str;
        offset = dissect_msex_library_num_or_id(tvb, pinfo, tree, offset, version >= CITP_MSEX_V11, &lib_str);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Library: %s (%s)", lib_str,
            val_to_str_const(library_type, citp_msex_library_types, "Unknown"));

        count = dissect_msex_count(tvb, tree, &offset, version, hf_citp_msex_element_count);
        if (count == 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ", All elements");
            return offset;
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d elements", count);

        proto_item *elems = proto_tree_add_item(tree, hf_citp_msex_elements, tvb, offset, -1, ENC_NA);
        proto_tree *elems_tree = proto_item_add_subtree(elems, ett_citp_msex_elements);
        for (unsigned int i = 0; i < count; i++) {
            proto_tree_add_item(elems_tree, hf_citp_msex_element_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
        }
    }
    return offset;
}

/** ELTh, EThn
 * - Element Library Thumbnail
 * - Element Thumbnail
*/
static int
dissect_msex_thumbnail(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version, uint32_t content_type, proto_tree* root_tree) {
    uint32_t library_type;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_library_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &library_type);
    offset+=1;

    const char* library_num;
    offset = dissect_msex_library_num_or_id(tvb, pinfo, tree, offset, version >= CITP_MSEX_V11, &library_num);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Library: %s (%s)", library_num,
        val_to_str_const(library_type, citp_msex_library_types, "Unknown"));

    if (content_type == CITP_MSEX_ETHN) {
        uint32_t element_number;
        proto_tree_add_item_ret_uint(tree, hf_citp_msex_element_number, tvb, offset, 1, ENC_LITTLE_ENDIAN, &element_number);
        offset+=1;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Element: %d", element_number);
    }

    const uint8_t* thumb_format_str;
    uint32_t thumbnail_format = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_string(tree, hf_citp_msex_thumbnail_format, tvb, offset, 4, ENC_ASCII, pinfo->pool, &thumb_format_str);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Format: %s", thumb_format_str);
    offset+=4;
    if (thumbnail_format != CITP_MSEX_FORMAT_RGB8 && thumbnail_format != CITP_MSEX_FORMAT_JPEG && thumbnail_format != CITP_MSEX_FORMAT_PNG) {
        expert_add_info(pinfo, tree, &ei_citp_msex_thumb_format);
    }

    proto_tree_add_item(tree, hf_citp_msex_thumbnail_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_citp_msex_thumbnail_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    uint32_t buff_size;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_thumbnail_buffer_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &buff_size);
    offset+=2;
    proto_tree_add_item(tree, hf_citp_msex_thumbnail_buffer, tvb, offset, buff_size, ENC_NA);
    tvbuff_t* thumbnail_tvb = tvb_new_subset_length(tvb, offset, buff_size);
    offset+=buff_size;

    if (thumbnail_format == CITP_MSEX_FORMAT_RGB8) {
        /* nothing to do, don't bother dissecting this */
    } else if (thumbnail_format == CITP_MSEX_FORMAT_JPEG) {
        call_dissector(jpeg_handle, thumbnail_tvb, pinfo, root_tree);
    } else if (thumbnail_format == CITP_MSEX_FORMAT_PNG) {
        call_dissector(png_handle, thumbnail_tvb, pinfo, root_tree);
    }

    return offset;
}

/**VSrc
 * - Video Sources
 */
static int
dissect_msex_vsrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version _U_) {
    uint32_t count;
    const uint8_t* str;
    int str_len;

    proto_tree_add_item_ret_uint(tree, hf_citp_msex_source_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
    offset+=2;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %d sources", count);

    proto_item *sources = proto_tree_add_item(tree, hf_citp_msex_sources, tvb, offset, -1, ENC_NA);
    proto_tree *sources_tree = proto_item_add_subtree(sources, ett_citp_msex_sources);
    int list_offset = offset;
    for (unsigned int i = 0; i < count; i++) {
        proto_item *source = proto_tree_add_item(sources_tree, hf_citp_msex_source, tvb, offset, -1, ENC_NA);
        proto_tree *source_tree = proto_item_add_subtree(source, ett_citp_msex_source);
        int src_offset = offset;

        uint32_t src_id;
        proto_tree_add_item_ret_uint(source_tree, hf_citp_msex_source_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &src_id);
        offset+=2;
        proto_tree_add_item_ret_string_and_length(source_tree, hf_citp_msex_source_name, tvb, offset, -1, ENC_UCS_2|ENC_LITTLE_ENDIAN, pinfo->pool, &str, &str_len);
        offset+=str_len;
        proto_tree_add_item(source_tree, hf_citp_msex_source_physical_output, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(source_tree, hf_citp_msex_source_layer_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_bitmask(source_tree, tvb, offset, hf_citp_msex_source_flags, ett_citp_msex_source_flags, citp_msex_source_flags, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(source_tree, hf_citp_msex_source_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(source_tree, hf_citp_msex_source_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;

        proto_item_set_len(source, offset-src_offset);
        proto_item_append_text(source, ", %u: %s", src_id, str);
    }
    proto_item_set_len(sources, offset-list_offset);

    return offset;
}

/**StFr
 * - Stream Frame
 */
static int
dissect_msex_stfr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint16_t version, proto_tree* root_tree) {
    if (version >= CITP_MSEX_V12) {
        proto_tree_add_item(tree, hf_citp_msex_source_server_uuid, tvb, offset, 36, ENC_UTF_8);
        offset+=36;
    }
    uint32_t source_id;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_source_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &source_id);
    offset+=2;

    const uint8_t* frame_format_str;
    uint32_t frame_format = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_string(tree, hf_citp_msex_stream_format, tvb, offset, 4, ENC_ASCII, pinfo->pool, &frame_format_str);
    offset+=4;
    if (frame_format != CITP_MSEX_FORMAT_RGB8 && frame_format != CITP_MSEX_FORMAT_JPEG &&
        frame_format != CITP_MSEX_FORMAT_PNG &&
        frame_format != CITP_MSEX_FORMAT_FJPG && frame_format != CITP_MSEX_FORMAT_FPNG) {
        expert_add_info(pinfo, tree, &ei_citp_msex_stream_format);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Source: %d, Format: %s", source_id, frame_format_str);

    proto_tree_add_item(tree, hf_citp_msex_stream_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_citp_msex_stream_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    uint32_t buff_size;
    proto_tree_add_item_ret_uint(tree, hf_citp_msex_frame_buffer_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &buff_size);
    offset+=2;
    tvbuff_t* frame_tvb = tvb_new_subset_length(tvb, offset, buff_size);
    proto_tree_add_item(tree, hf_citp_msex_frame_buffer, tvb, offset, buff_size, ENC_NA);
    offset+=buff_size;

    if (frame_format == CITP_MSEX_FORMAT_RGB8) {
        /* nothing to do, don't bother dissecting this */
    } else if (frame_format == CITP_MSEX_FORMAT_JPEG) {
        call_dissector(jpeg_handle, frame_tvb, pinfo, root_tree);
    } else if (frame_format == CITP_MSEX_FORMAT_PNG) {
        call_dissector(png_handle, frame_tvb, pinfo, root_tree);
    } else if (frame_format == CITP_MSEX_FORMAT_FJPG || frame_format == CITP_MSEX_FORMAT_FPNG) {
        int frame_offset = 0;
        proto_item* frag = proto_tree_add_item(tree, hf_citp_msex_frame_fragment, frame_tvb, frame_offset, 12, ENC_NA);
        proto_tree* frag_tree = proto_item_add_subtree(frag, ett_citp_msex_frame_fragment);

        proto_tree_add_item(frag_tree, hf_citp_msex_frame_index, tvb, frame_offset, 4, ENC_LITTLE_ENDIAN);
        frame_offset+=4;
        proto_tree_add_item(frag_tree, hf_citp_msex_frame_fragment_count, tvb, frame_offset, 2, ENC_LITTLE_ENDIAN);
        frame_offset+=2;
        proto_tree_add_item(frag_tree, hf_citp_msex_frame_fragment_index, tvb, frame_offset, 2, ENC_LITTLE_ENDIAN);
        frame_offset+=2;
        proto_tree_add_item(frag_tree, hf_citp_msex_frame_fragment_byte_offset, tvb, frame_offset, 4, ENC_LITTLE_ENDIAN);
        frame_offset+=4;

        tvbuff_t* frag_tvb = tvb_new_subset_remaining(tvb, frame_offset);
        if (frame_format == CITP_MSEX_FORMAT_FJPG) {
            call_dissector(jpeg_handle, frag_tvb, pinfo, root_tree);
        } else if (frame_format == CITP_MSEX_FORMAT_FPNG) {
            call_dissector(png_handle, frag_tvb, pinfo, root_tree);
        }
    }

    return offset;
}

static int
dissect_msex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/MSEX");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp_msex, tvb, offset, -1, ENC_NA);
    proto_tree *msex_tree = proto_item_add_subtree(ti, ett_citp_msex);

    uint16_t version = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(msex_tree, hf_citp_msex_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    proto_tree_add_item(msex_tree, hf_citp_msex_version_minor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    if (version < CITP_MSEX_V10 || version > CITP_MSEX_V12) {
        expert_add_info(pinfo, msex_tree, &ei_citp_msex_version);
    }

    uint32_t content_type;
    proto_tree_add_item_ret_uint(msex_tree, hf_citp_msex_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(content_type, citp_msex_content_type_short_names, "Unknown Message Type"));

    switch (content_type) {
        case CITP_MSEX_CINF:
            offset = dissect_msex_supported_versions(tvb, msex_tree, offset);
            break;
        case CITP_MSEX_SINF:
            offset = dissect_msex_sinf(tvb, pinfo, msex_tree, offset, version);
            break;
        case CITP_MSEX_NACK:
            proto_tree_add_item(msex_tree, hf_citp_msex_received_content_type, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case CITP_MSEX_LSTA:
            offset = dissect_msex_lsta(tvb, pinfo, msex_tree, offset, version);
            break;
        case CITP_MSEX_GELI:
        case CITP_MSEX_ELIN:
            offset = dissect_msex_library(tvb, pinfo, msex_tree, offset, version, content_type);
            break;
        case CITP_MSEX_ELUP:
            proto_tree_add_item(msex_tree, hf_citp_msex_library_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            offset = dissect_msex_library_num_or_id(tvb, pinfo, msex_tree, offset, version >= CITP_MSEX_V11, NULL);
            proto_tree_add_bitmask(msex_tree, tvb, offset, hf_citp_msex_library_update_flags, ett_citp_msex_library_update_flags, citp_msex_library_update_flags, ENC_LITTLE_ENDIAN);
            offset+=1;
            if (version >= CITP_MSEX_V12) {
                offset = dissect_msex_affected_array(tvb, msex_tree, offset, hf_citp_msex_library_affected_elements, ett_citp_msex_library_affected_elements, hf_citp_msex_library_affected_element);
                offset = dissect_msex_affected_array(tvb, msex_tree, offset, hf_citp_msex_library_affected_subs, ett_citp_msex_library_affected_subs, hf_citp_msex_library_affected_sub);
            }
            break;
        case CITP_MSEX_GEIN:
        case CITP_MSEX_MEIN:
        case CITP_MSEX_EEIN:
        case CITP_MSEX_GLEI:
            offset = dissect_msex_element(tvb, pinfo, msex_tree, offset, version, content_type);
            break;
        case CITP_MSEX_GELT:
        case CITP_MSEX_GETH:
            offset = dissect_msex_thumbnail_get(tvb, pinfo, msex_tree, offset, version, content_type);
            break;
        case CITP_MSEX_ELTH:
        case CITP_MSEX_ETHN:
            offset = dissect_msex_thumbnail(tvb, pinfo, msex_tree, offset, version, content_type, tree);
            break;
        case CITP_MSEX_GVSR: break;
        case CITP_MSEX_VSRC:
            offset = dissect_msex_vsrc(tvb, pinfo, msex_tree, offset, version);
            break;
        case CITP_MSEX_RQST: {
            uint32_t source_id;
            proto_tree_add_item_ret_uint(msex_tree, hf_citp_msex_source_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &source_id);
            offset+=2;

            const uint8_t* format;
            uint32_t frame_format = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_string(msex_tree, hf_citp_msex_stream_format, tvb, offset, 4, ENC_ASCII, pinfo->pool, &format);
            offset+=4;
            if (frame_format != CITP_MSEX_FORMAT_RGB8 && frame_format != CITP_MSEX_FORMAT_JPEG &&
                frame_format != CITP_MSEX_FORMAT_PNG &&
                frame_format != CITP_MSEX_FORMAT_FJPG && frame_format != CITP_MSEX_FORMAT_FPNG) {
                expert_add_info(pinfo, tree, &ei_citp_msex_stream_format);
            }

            proto_tree_add_item(msex_tree, hf_citp_msex_stream_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(msex_tree, hf_citp_msex_stream_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(msex_tree, hf_citp_msex_stream_fps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(msex_tree, hf_citp_msex_stream_timeout, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Source: %d, Format: %s", source_id, format);
            break;
        }
        case CITP_MSEX_STFR:
            offset = dissect_msex_stfr(tvb, pinfo, msex_tree, offset, version, tree);
            break;
        default:
            expert_add_info(pinfo, tree, &ei_citp_msex_content_type);
            break;
    }

    return offset;
}



static int
dissect_citp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_reported_length(tvb) < CITP_COOKIE_LEN) {
        return 0;
    }

    if (tvb_memeql(tvb, 0, CITP_COOKIE, CITP_COOKIE_LEN) != 0) {
        return 0;
    }

    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CITP");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_citp, tvb, offset, -1, ENC_NA);
    proto_tree *citp_tree = proto_item_add_subtree(ti, ett_citp);

    proto_tree_add_item(citp_tree, hf_citp_cookie, tvb, offset, 4, ENC_ASCII);
    offset += 4;

    proto_tree_add_item(citp_tree, hf_citp_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(citp_tree, hf_citp_version_minor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(citp_tree, hf_citp_message_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    uint32_t message_size;
    proto_tree_add_item_ret_uint(citp_tree, hf_citp_message_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &message_size);
    proto_item_set_len(ti, message_size);
    offset += 4;

    proto_tree_add_item(citp_tree, hf_citp_message_part_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(citp_tree, hf_citp_message_part_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    uint32_t content_type;
    proto_tree_add_item_ret_uint(citp_tree, hf_citp_content_type, tvb, offset, 4, ENC_BIG_ENDIAN, &content_type);
    offset += 4;

    /* Message doesn't include any data, no dissection */
    if (message_size <= 20) {
        return offset;
    }

    unsigned int consumed = dissector_try_uint_with_data(content_type_table, content_type, tvb_new_subset_length(tvb, offset, message_size-20), pinfo, tree, true, NULL);
    if (consumed != 0) {
        if (consumed + 20 != message_size) {
            expert_add_info(pinfo, citp_tree, &ei_citp_message_size);
        }
    } else {
        /* We also do a manual check here in case the protocols have been disabled */
        if (content_type != CITP_PINF && content_type != CITP_SDMX &&
            content_type != CITP_FPTC && content_type != CITP_FSEL &&
            content_type != CITP_FINF && content_type != CITP_CAEX &&
            content_type != CITP_MSEX) {
            expert_add_info(pinfo, citp_tree, &ei_citp_content_type);
        }
    }
    return offset;
}


static bool
test_citp(tvbuff_t *tvb)
{
    /* Check we have enough bytes */
    if (tvb_captured_length(tvb) < 20)
        return false;

    /* Make sure we have the COOKIE */
    if (tvb_memeql(tvb, 0, CITP_COOKIE, CITP_COOKIE_LEN) == -1)
        return false;

    return true;
}

static unsigned
get_citp_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* Return 1 here so we keep making progress in the event of a malformed packet */
    if (tvb_memeql(tvb, offset, CITP_COOKIE, CITP_COOKIE_LEN) == -1) {
        return 1;
    }

    return (unsigned)tvb_get_uint32(tvb, offset+8, ENC_LITTLE_ENDIAN);
}

static int
dissect_citp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 11, get_citp_len, dissect_citp, data);
    return tvb_reported_length(tvb);
}

static bool
dissect_citp_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_citp(tvb))
        return false;

    /* specify that dissect_citp is to be called directly from now on for
     * packets for this "connection" ... but only do this if your heuristic sits directly
     * on top of (was called by) a dissector which established a conversation for the
     * protocol "port type". In other words: only directly over TCP, UDP, DCCP, ...
     * otherwise you'll be overriding the dissector that called your heuristic dissector.
     */
    conversation_t* conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, citp_tcp_handle);

    /* and do the dissection */
    dissect_citp_tcp(tvb, pinfo, tree, data);

    return true;
}


/******************************************************************************/
/* Register protocol                                                          */
void
proto_register_citp(void) {
    static hf_register_info hf[] = {
        { &hf_citp_cookie,
            { "Cookie", "citp.cookie",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_version_major,
            { "Major Version", "citp.version_major",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_version_minor,
            { "Minor Version", "citp.version_minor",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_message_index,
            { "Message Index", "citp.index",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_message_size,
            { "Message Size", "citp.message_size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_message_part_count,
            { "Message Part Count", "citp.message_part_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_message_part_index,
            { "Message Part Index", "citp.message_part",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_content_type,
            { "Content Type", "citp.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_content_type_names), 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_pinf[] = {
        { &hf_citp_pinf_content_type,
            { "Content Type", "citp.pinf.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_pinf_content_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_pinf_name,
            { "Name", "citp.pinf.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_pinf_listening_port,
            { "Listening TCP Port", "citp.pinf.listening_port",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_pinf_type,
            { "Type", "citp.pinf.type",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_pinf_state,
            { "State", "citp.pinf.state",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_sdmx[] = {
        { &hf_citp_sdmx_content_type,
            { "Content Type", "citp.sdmx.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_sdmx_content_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_capability_count,
            { "Capability Count", "citp.sdmx.capability_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_capabilities,
            { "Capabilities", "citp.sdmx.capabilities",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_capability,
            { "Capability", "citp.sdmx.capability",
            FT_UINT16, BASE_DEC,
            VALS(citp_sdmx_capability_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_universe_index,
            { "Universe Index", "citp.sdmx.universe_index",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_universe_name,
            { "Universe Name", "citp.sdmx.universe_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_encryption_identifier,
            { "Encryption scheme identifier", "citp.sdmx.encryption_identifier",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_blind,
            { "Blind", "citp.sdmx.blind",
            FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_live_blind), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_first_channel,
            { "First Channel", "citp.sdmx.first_channel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_channel_count,
            { "Channel Count", "citp.sdmx.channel_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_channel_levels,
            { "Channel Levels", "citp.sdmx.channel_levels",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_encrypted_channel_data,
            { "Encrypted Channel Data", "citp.sdmx.encrypted_channel_data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_channel_level_block,
            { "Channel Level Block", "citp.sdmx.channel_level_block",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_channel,
            { "Channel", "citp.sdmx.channel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_channel_level,
            { "Channel Level", "citp.sdmx.channel_level",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_sdmx_connection_string,
            { "Connection String", "citp.sdmx.connection_string",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_fptc[] = {
        { &hf_citp_fptc_content_type,
            { "Content Type", "citp.fptc.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_fptc_content_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_content_hint,
            { "Content Hint", "citp.fptc.content_hint",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_content_hint_in_sequence,
            { "In Sequence", "citp.fptc.content_hint.in_sequence",
            FT_UINT32, BASE_HEX,
            NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_citp_fptc_content_hint_end_sequence,
            { "End Of Sequence", "citp.fptc.content_hint.end_sequence",
            FT_UINT32, BASE_HEX,
            NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_citp_fptc_fixture_identifier,
            { "Fixture Identifier", "citp.fptc.fixture_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_universe,
            { "Universe", "citp.fptc.universe",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_channel,
            { "Channel", "citp.fptc.channel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_channel_count,
            { "Channel Count", "citp.fptc.channel_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_fixture_make,
            { "Fixture Make", "citp.fptc.fixture_make",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_fixture_name,
            { "Fixture Name", "citp.fptc.fixture_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_fixture_count,
            { "Fixture Count", "citp.fptc.fixture_count",
            FT_UINT16, BASE_DEC | BASE_SPECIAL_VALS,
            VALS(citp_all_fixtures_val_str), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fptc_fixture_identifiers,
            { "Fixture Identifiers", "citp.fptc.fixture_identifiers",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_fsel[] = {
        { &hf_citp_fsel_content_type,
            { "Content Type", "citp.fsel.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_fsel_content_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fsel_complete,
            { "Complete", "citp.fsel.complete",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fsel_fixture_count,
            { "Fixture Count", "citp.fsel.fixture_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fsel_fixture_identifiers,
            { "Fixture Identifiers", "citp.fsel.fixture_identifiers",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_fsel_fixture_identifier,
            { "Fixture Identifier", "citp.fsel.fixture_identifier",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_finf[] = {
        { &hf_citp_finf_content_type,
            { "Content Type", "citp.finf.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_finf_content_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_fixture_count,
            { "Fixture Count", "citp.finf.fixture_count",
            FT_UINT16, BASE_DEC | BASE_SPECIAL_VALS,
            VALS(citp_all_fixtures_val_str), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_fixture_identifiers,
            { "Fixture Identifiers", "citp.finf.fixture_identifiers",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_fixture_identifier,
            { "Fixture Identifier", "citp.finf.fixture_identifier",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_frame_filter_count,
            { "Frame Filter Count", "citp.finf.frame_filter_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_frame_gobo_count,
            { "Frame Gobo Count", "citp.finf.frame_gobo_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_frame_names,
            { "Frame Names", "citp.finf.frame_names",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_filter_name,
            { "Filter Name", "citp.finf.filter_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_finf_gobo_name,
            { "Gobo Name", "citp.finf.gobo_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_caex[] = {
        { &hf_citp_caex_content_code,
            { "Content Code", "citp.caex.content_code",
            FT_UINT32, BASE_HEX,
            VALS(citp_caex_content_code_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_nack_reason,
            { "NAck Reason", "citp.caex.nack_reason",
            FT_UINT8, BASE_HEX,
            VALS(citp_caex_nack_reason), 0x0,
            NULL, HFILL }
        },

        { &hf_citp_caex_view_availability,
            { "Availability", "citp.caex.live_view.availability",
            FT_UINT8, BASE_HEX,
            VALS(citp_caex_view_availability), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_size,
            { "View Size", "citp.caex.live_view.size",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_width,
            { "Width", "citp.caex.live_view.size.width",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_height,
            { "Height", "citp.caex.live_view.size.height",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_position,
            { "Camera Position", "citp.caex.live_view.position",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_position_x,
            { "X", "citp.caex.live_view.position.x",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_position_y,
            { "Y", "citp.caex.live_view.position.y",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_position_z,
            { "Z", "citp.caex.live_view.position.z",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_focus,
            { "Camera Focus", "citp.caex.live_view.focus",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_focus_x,
            { "X", "citp.caex.live_view.focus.x",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_focus_y,
            { "Y", "citp.caex.live_view.focus.y",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_focus_z,
            { "Z", "citp.caex.live_view.focus.z",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_format,
            { "Format", "citp.caex.live_view.format",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_data_size,
            { "Data Size", "citp.caex.live_view.data_size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_view_data,
            { "Data", "citp.caex.live_view.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_citp_caex_cue_availability,
            { "Availability", "citp.caex.cue_record.availability",
            FT_UINT8, BASE_HEX,
            VALS(citp_caex_cue_record_availability), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_option_count,
            { "Option Count", "citp.caex.cue_record.option_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_option,
            { "Option", "citp.caex.cue_record.option",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_option_name,
            { "Name", "citp.caex.cue_record.option.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_option_value,
            { "Value", "citp.caex.cue_record.option.value",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_option_choices,
            { "Choices", "citp.caex.cue_record.option.choices",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_option_help,
            { "Help", "citp.caex.cue_record.option.help",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_cue_clear_availability,
            { "Availability", "citp.caex.cue_record.clear_availability",
            FT_UINT8, BASE_HEX,
            VALS(citp_caex_cue_clear_availability), 0x0,
            NULL, HFILL }
        },

        { &hf_citp_caex_show_name,
            { "Name", "citp.caex.show.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_transformation_space,
            { "Transformation Space", "citp.caex.show.transformation_space",
            FT_UINT8, BASE_HEX,
            VALS(citp_caex_show_transformation_spaces), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_list_type,
            { "List Type", "citp.caex.show.fixture_list_type",
            FT_UINT8, BASE_HEX,
            VALS(citp_caex_show_fixture_list_types), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_count,
            { "Fixture Count", "citp.caex.show.fixture_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixtures,
            { "Fixtures", "citp.caex.show.fixtures",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture,
            { "Fixture", "citp.caex.show.fixture",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_console_identifier,
            { "Console Identifier", "citp.caex.show.fixture.console_identifier",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_manufacturer_name,
            { "Manufacturer Name", "citp.caex.show.fixture.manufacturer_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_model_name,
            { "Model Name", "citp.caex.show.fixture.model_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_mode_name,
            { "DMX Mode Name", "citp.caex.show.fixture.mode_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_channel_count,
            { "Channel Count", "citp.caex.show.fixture.channel_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_is_dimmer,
            { "Is Dimmer", "citp.caex.show.fixture.is_dimmer",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_count,
            { "Identifier Count", "citp.caex.show.fixture.identifier_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier,
            { "Identifier", "citp.caex.show.fixture.identifier",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_type,
            { "Type", "citp.caex.show.fixture.identifier.type",
            FT_UINT8, BASE_NONE,
            VALS(citp_caex_show_identifier_types), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_data_size,
            { "Data Size", "citp.caex.show.fixture.identifier.data_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_data,
            { "Data", "citp.caex.show.fixture.identifier.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_rdm_manufacturer_id,
            { "RDM Manufacturer Id", "citp.caex.show.fixture.identifier.rdm_manf_id",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_rdm_device_model_id,
            { "RDM Device Model Id", "citp.caex.show.fixture.identifier.rdm_model_id",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_rdm_personality_id,
            { "RDM Personality Id", "citp.caex.show.fixture.identifier.rdm_personality_id",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_altabase_fixture_id,
            { "AltaBase Fixture Id", "citp.caex.show.fixture.identifier.altabase_fixture_id",
            FT_GUID, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_altabase_mode_id,
            { "AltaBase Mode Id", "citp.caex.show.fixture.identifier.altabase_mode_id",
            FT_GUID, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_identifier_capture_instance_id,
            { "Capture Instance Id", "citp.caex.show.fixture.identifier.capture_instance_id",
            FT_GUID, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_patched,
            { "Patched", "citp.caex.show.fixture.patched",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_universe,
            { "Universe", "citp.caex.show.fixture.universe",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_universe_channel,
            { "Universe Channel", "citp.caex.show.fixture.universe_channel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_unit,
            { "Unit", "citp.caex.show.fixture.unit",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_channel,
            { "Channel", "citp.caex.show.fixture.channel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_circuit,
            { "Circuit", "citp.caex.show.fixture.circuit",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_note,
            { "Note", "citp.caex.show.fixture.note",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_position,
            { "Position", "citp.caex.show.fixture.position",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_position_x,
            { "X", "citp.caex.show.fixture.position.x",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_position_y,
            { "Y", "citp.caex.show.fixture.position.y",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_position_z,
            { "Z", "citp.caex.show.fixture.position.z",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_angles,
            { "Angles", "citp.caex.show.fixture.angles",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_angles_x,
            { "X", "citp.caex.show.fixture.angles.x",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_angles_y,
            { "Y", "citp.caex.show.fixture.angles.y",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_angles_z,
            { "Z", "citp.caex.show.fixture.angles.z",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_locked,
            { "Locked", "citp.caex.show.fixture.locked",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_clearable,
            { "Clearable", "citp.caex.show.fixture.clearable",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields,
            { "Changed Fields", "citp.caex.show.fixture.changed_fields",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields_patch,
            { "Patch", "citp.caex.show.fixture.changed_fields.patch",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields_unit,
            { "Unit", "citp.caex.show.fixture.changed_fields.unit",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields_channel,
            { "Channel", "citp.caex.show.fixture.changed_fields.channel",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields_circuit,
            { "Circuit", "citp.caex.show.fixture.changed_fields.circuit",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields_note,
            { "Note", "citp.caex.show.fixture.changed_fields.note",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_citp_caex_show_fixture_changed_fields_position,
            { "Position", "citp.caex.show.fixture.changed_fields.position",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },

        { &hf_citp_caex_laser_source_key,
            { "Source Key", "citp.caex.laser.source_key",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_feed_count,
            { "Feed Count", "citp.caex.laser.feed_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_feed_name,
            { "Feed Name", "citp.caex.laser.feed_name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_feed_index,
            { "Feed Index", "citp.caex.laser.feed_index",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_frame_rate,
            { "Frame Rate", "citp.caex.laser.frame_rate",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_frame_sequence_number,
            { "Sequence Number", "citp.caex.laser.frame_sequence",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_count,
            { "Point Count", "citp.caex.laser.point_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_points,
            { "Points", "citp.caex.laser.points",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point,
            { "Point", "citp.caex.laser.point",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_x_low,
            { "X Low Byte", "citp.caex.laser.point.x_low",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_y_low,
            { "Y Low Byte", "citp.caex.laser.point.y_low",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_xy_high,
            { "XY High Nibbles", "citp.caex.laser.point.xy_high",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_x,
            { "X [0, 4093]", "citp.caex.laser.point.x",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_y,
            { "Y [0, 4093]", "citp.caex.laser.point.y",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_colour,
            { "Colour", "citp.caex.laser.point.colour",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_colour_r,
            { "R [0, 31]", "citp.caex.laser.point.colour.r",
            FT_UINT16, BASE_DEC,
            NULL, 0b1111100000000000,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_colour_g,
            { "G [0, 63]", "citp.caex.laser.point.colour.g",
            FT_UINT16, BASE_DEC,
            NULL, 0b0000011111100000,
            NULL, HFILL }
        },
        { &hf_citp_caex_laser_point_colour_b,
            { "B [0, 31]", "citp.caex.laser.point.colour.b",
            FT_UINT16, BASE_DEC,
            NULL, 0b0000000000011111,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_msex[] = {
        { &hf_citp_msex_version_major,
            { "Major Version", "citp.msex.version_major",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_version_minor,
            { "Minor Version", "citp.msex.version_minor",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_content_type,
            { "Content Type", "citp.msex.content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_msex_content_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_version_count,
            { "Supported Version Count", "citp.msex.supported_version_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_versions,
            { "Supported Versions", "citp.msex.supported_versions",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_version,
            { "Supported Version", "citp.msex.supported_version",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_uuid,
            { "UUID", "citp.msex.uuid",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_product_name,
            { "Product Name", "citp.msex.product.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_product_version_major,
            { "Product Major Version", "citp.msex.product.version_major",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_product_version_minor,
            { "Product Minor Version", "citp.msex.product.version_minor",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_product_version_bugfix,
            { "Product Bugfix Version", "citp.msex.product.version_bugfix",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types,
            { "Supported Library Types", "citp.msex.supported_library_types",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_media,
            { "Media", "citp.msex.supported_library_types.media",
            FT_BOOLEAN, 16,
            NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_effects,
            { "Effects", "citp.msex.supported_library_types.effects",
            FT_BOOLEAN, 16,
            NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_cues,
            { "Cues", "citp.msex.supported_library_types.cues",
            FT_BOOLEAN, 16,
            NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_crossfades,
            { "Crossfades", "citp.msex.supported_library_types.crossfades",
            FT_BOOLEAN, 16,
            NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_masks,
            { "Masks", "citp.msex.supported_library_types.masks",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_blend_presets,
            { "Blend Presets", "citp.msex.supported_library_types.blend_presets",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_effect_presets,
            { "Effect Presets", "citp.msex.supported_library_types.effect_presets",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_image_presets,
            { "Image Presets", "citp.msex.supported_library_types.image_presets",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_citp_msex_supported_library_types_3d_meshes,
            { "3D Meshes", "citp.msex.supported_library_types.3d_meshes",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_citp_msex_received_content_type,
            { "Received Content Type", "citp.msex.received_content_type",
            FT_UINT32, BASE_HEX,
            VALS(citp_msex_content_type_names), 0x0,
            NULL, HFILL }
        },

        { &hf_citp_msex_layer_count,
            { "Layer Count", "citp.msex.layer_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_layers,
            { "Layers", "citp.msex.layers",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_dmx_source,
            { "Dmx Source", "citp.msex.layer.dmx_source",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_number,
            { "Number", "citp.msex.layer.number",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_physical_output,
            { "Physical Output", "citp.msex.layer.physical_output",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags,
            { "Status Flags", "citp.msex.layer.status",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags_playing,
            { "Playing", "citp.msex.layer.status.playing",
            FT_BOOLEAN, 32,
            NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags_reverse,
            { "Playber Reverse", "citp.msex.layer.status.reverse",
            FT_BOOLEAN, 32,
            NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags_looping,
            { "Playback Looping", "citp.msex.layer.status.looping",
            FT_BOOLEAN, 32,
            NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags_bouncing,
            { "Playback Bouncing", "citp.msex.layer.status.bouncing",
            FT_BOOLEAN, 32,
            NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags_random,
            { "Playback Random", "citp.msex.layer.status.random",
            FT_BOOLEAN, 32,
            NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_citp_msex_layer_status_flags_paused,
            { "Paused", "citp.msex.layer.status.paused",
            FT_BOOLEAN, 32,
            NULL, 0x00000020,
            NULL, HFILL }
        },

        { &hf_citp_msex_library_count,
            { "Library Count", "citp.msex.library_count",
            FT_UINT8, BASE_DEC | BASE_SPECIAL_VALS,
            VALS(citp_all_libraries_val_str), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_libraries,
            { "Libraries", "citp.msex.libraries",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library,
            { "Library", "citp.msex.library",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_type,
            { "Library Type", "citp.msex.library.type",
            FT_UINT8, BASE_DEC,
            VALS(citp_msex_library_types), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_number,
            { "Library Number", "citp.msex.library.number",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_id,
            { "Library Id", "citp.msex.library.id",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_id_level,
            { "Level", "citp.msex.library.id.level",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_id_level_1,
            { "Level 1 Index", "citp.msex.library.id.level_1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_id_level_2,
            { "Level 2 Index", "citp.msex.library.id.level_2",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_id_level_3,
            { "Level 3 Index", "citp.msex.library.id.level_3",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_parent_id,
            { "Parent Library Id", "citp.msex.library.parent_id",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_serial_number,
            { "Serial Number", "citp.msex.library.serial_number",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_dmx_min,
            { "DMX Rage Min", "citp.msex.library.dmx_min",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_dmx_max,
            { "DMX Rage Max", "citp.msex.library.dmx_max",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_name,
            { "Name", "citp.msex.library.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_sub_count,
            { "Sub-Library Count", "citp.msex.library.sub_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_element_count,
            { "Element Count", "citp.msex.library.element_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags,
            { "Updates", "citp.msex.library.update_flags",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags_elements_updated,
            { "Elements Updated", "citp.msex.library.update_flags.elements_updated",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags_elements_added_removed,
            { "Elements Added/Removed", "citp.msex.library.update_flags.elements_added_removed",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags_subs_updated,
            { "Sub-Libraries Updated", "citp.msex.library.update_flags.subs_updated",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags_subs_added_removed,
            { "Sub-Libraries Added/Removed", "citp.msex.library.update_flags.subs_removed",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags_all_elements,
            { "All Elements Affected", "citp.msex.library.update_flags.all_elements",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_update_flags_all_subs,
            { "All Sub-Libraries Affected", "citp.msex.library.update_flags.all_subs",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_affected_elements,
            { "Affected Elements", "citp.msex.library.affected_elements",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_affected_subs,
            { "Affected Sub-Libraries", "citp.msex.library.affected_subs",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_affected_element,
            { "Element", "citp.msex.library.affected_elements.element",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_library_affected_sub,
            { "Sub-Library", "citp.msex.library.affected_subs.sub",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_citp_msex_element_count,
            { "Element Count", "citp.msex.element_count",
            FT_UINT8, BASE_DEC | BASE_SPECIAL_VALS,
            VALS(citp_all_elements_val_str), 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_elements,
            { "Elements", "citp.msex.elements",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element,
            { "Element", "citp.msex.element",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_number,
            { "Element Number", "citp.msex.element.number",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_serial_number,
            { "Serial Number", "citp.msex.element.serial_number",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_dmx_min,
            { "DMX Rage Min", "citp.msex.element.dmx_min",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_dmx_max,
            { "DMX Rage Max", "citp.msex.element.dmx_max",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_name,
            { "Name", "citp.msex.element.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_version_timestamp,
            { "Version Timestamp", "citp.msex.element.version_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_position,
            { "Position", "citp.msex.element.position",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_width,
            { "Width", "citp.msex.element.width",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_height,
            { "Height", "citp.msex.element.height",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_length,
            { "Length", "citp.msex.element.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_fps,
            { "FPS", "citp.msex.element.fps",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_parameter_count,
            { "Parameter Count", "citp.msex.element.parameter_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_parameter_names,
            { "Parameter Names", "citp.msex.element.parameter_names",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_element_parameter_name,
            { "Parameter", "citp.msex.element.parameter",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_citp_msex_thumbnail_format_count,
            { "Thumbnail Format Count", "citp.msex.thumbnail_format_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_formats,
            { "Thumbnail Formats", "citp.msex.thumbnail_formats",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_format,
            { "Thumbnail Format", "citp.msex.thumbnail.format",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_width,
            { "Thumbnail Width", "citp.msex.thumbnail.width",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_height,
            { "Thumbnail Height", "citp.msex.thumbnail.height",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_flags,
            { "Thumbnail Flags", "citp.msex.thumbnail.flags",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_flags_preserve_aspect,
            { "Preserve Aspect Ratio", "citp.msex.thumbnail.flags.preserve_aspect",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_buffer_size,
            { "Thumbnail Buffer Size", "citp.msex.thumbnail.buffer_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_thumbnail_buffer,
            { "Thumbnail Buffer", "citp.msex.thumbnail.buffer",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_citp_msex_source_count,
            { "Source Count", "citp.msex.source_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_sources,
            { "Sources", "citp.msex.sources",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source,
            { "Source", "citp.msex.source",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_server_uuid,
            { "Media Server UUID", "citp.msex.source.uuid",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_id,
            { "Source Id", "citp.msex.source.id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_name,
            { "Source Name", "citp.msex.source.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_physical_output,
            { "Physical Output", "citp.msex.source.physical_output",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_layer_number,
            { "Layer Number", "citp.msex.source.layer_number",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_flags,
            { "Flags", "citp.msex.source.flags",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_flags_without_effects,
            { "Without Effects", "citp.msex.source.flags.without_effects",
            FT_BOOLEAN, 16,
            NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_width,
            { "Width", "citp.msex.source.width",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_source_height,
            { "Height", "citp.msex.source.height",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_citp_msex_stream_format_count,
            { "Stream Format Count", "citp.msex.stream_format_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_stream_formats,
            { "Stream Formats", "citp.msex.stream_formats",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_stream_format,
            { "Stream Format", "citp.msex.stream.format",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_stream_width,
            { "Width", "citp.msex.stream.width",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_stream_height,
            { "Height", "citp.msex.stream.height",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_stream_fps,
            { "FPS", "citp.msex.stream.fps",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_stream_timeout,
            { "Timeout", "citp.msex.stream.timeout",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_citp_msex_frame_buffer_size,
            { "Frame Buffer Size", "citp.msex.frame.buffer_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_frame_buffer,
            { "Frame Buffer", "citp.msex.frame.buffer",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_frame_index,
            { "Frame Index", "citp.msex.frame.index",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_frame_fragment,
            { "Frame Fragment Preamble", "citp.msex.frame.fragment",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_frame_fragment_count,
            { "Fragment Count", "citp.msex.frame.fragment.count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_frame_fragment_index,
            { "Fragment Index", "citp.msex.frame.fragment.index",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_citp_msex_frame_fragment_byte_offset,
            { "Fragment Byte Offset", "citp.msex.frame.fragment.byte_offset",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_citp,

        &ett_citp_pinf,

        &ett_citp_sdmx,
        &ett_citp_sdmx_capabilities,

        &ett_citp_fptc,
        &ett_citp_fptc_fixture_identifiers,
        &ett_citp_fptc_content_hint,

        &ett_citp_fsel,
        &ett_citp_fsel_fixture_identifiers,

        &ett_citp_finf,
        &ett_citp_finf_fixture_identifiers,

        &ett_citp_caex,
        &ett_citp_caex_view_pos,
        &ett_citp_caex_view_focus,
        &ett_citp_caex_cue_option,
        &ett_citp_caex_laser_point,
        &ett_citp_caex_laser_point_colour,
        &ett_citp_caex_show_fixtures,
        &ett_citp_caex_show_fixture,
        &ett_citp_caex_show_fixture_identifier,
        &ett_citp_caex_show_fixture_pos,
        &ett_citp_caex_show_fixture_angles,
        &ett_citp_caex_show_fixture_changed_fields,

        &ett_citp_msex,
        &ett_citp_msex_supported_versions,
        &ett_citp_msex_supported_version,
        &ett_citp_msex_supported_library_types,
        &ett_citp_msex_libraries,
        &ett_citp_msex_library,
        &ett_citp_msex_elements,
        &ett_citp_msex_element,
        &ett_citp_msex_element_parameter_names,
        &ett_citp_msex_sources,
        &ett_citp_msex_source,
        &ett_citp_msex_layers,
        &ett_citp_msex_layer,
        &ett_citp_msex_layer_status_flags,
        &ett_citp_msex_thumbnail_formats,
        &ett_citp_msex_stream_formats,
        &ett_citp_msex_library_update_flags,
        &ett_citp_msex_thumbnail_flags,
        &ett_citp_msex_source_flags,
        &ett_citp_msex_library_id,
        &ett_citp_msex_library_parent_id,
        &ett_citp_msex_frame_fragment,
        &ett_citp_msex_library_affected_elements,
        &ett_citp_msex_library_affected_subs,
    };

    static ei_register_info ei[] = {
        { &ei_citp_content_type, { "citp.content_type.unknown", PI_PROTOCOL, PI_ERROR, "Unknown CITP content type", EXPFILL }},
        { &ei_citp_message_size, { "citp.message_size.mismatch", PI_PROTOCOL, PI_WARN, "Mismatch between reported message size and consumed data", EXPFILL }},
    };

    static ei_register_info ei_pinf[] = {
        { &ei_citp_pinf_content_type,  { "citp.pinf.content_type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid PINF content type", EXPFILL }},
    };
    static ei_register_info ei_sdmx[] = {
        { &ei_citp_sdmx_content_type,  { "citp.sdmx.content_type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid SDMX content type", EXPFILL }},
    };
    static ei_register_info ei_fptc[] = {
        { &ei_citp_fptc_content_type,  { "citp.fptc.content_type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid FPTC content type", EXPFILL }},
    };
    static ei_register_info ei_fsel[] = {
        { &ei_citp_fsel_content_type,  { "citp.fsel.content_type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid FSEL content type", EXPFILL }},
    };
    static ei_register_info ei_finf[] = {
        { &ei_citp_finf_content_type,  { "citp.finf.content_type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid FINF content type", EXPFILL }},
    };
    static ei_register_info ei_caex[] = {
        { &ei_citp_caex_content_code,  { "citp.caex.content_code.invalid", PI_PROTOCOL, PI_ERROR, "Invalid CAEX content code", EXPFILL }},
        { &ei_citp_caex_fixture_ident, { "citp.caex.show.fixture.identifier.type.unknown", PI_PROTOCOL, PI_ERROR, "Unknown fixture identifier type", EXPFILL }},
        { &ei_citp_caex_view_format,   { "citp.caex.live_view.format.invalid", PI_PROTOCOL, PI_ERROR, "Invalid live-view image format. Must be JPEG", EXPFILL }},
    };
    static ei_register_info ei_msex[] = {
        { &ei_citp_msex_content_type,  { "citp.msex.content_type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid MSEX content type", EXPFILL }},
        { &ei_citp_msex_version,       { "citp.msex.version.unknown", PI_PROTOCOL, PI_WARN, "Unrecognised MSEX version", EXPFILL }},
        { &ei_citp_msex_thumb_format,  { "citp.msex.thumbnail.format.invalid", PI_PROTOCOL, PI_ERROR, "Invalid thumbnail format. Must be RGB8, JPEG or PNG", EXPFILL }},
        { &ei_citp_msex_stream_format, { "citp.msex.stream.format.invalid", PI_PROTOCOL, PI_ERROR, "Invalid stream format. Must be RGB8, JPEG, PNG, fJPG or fPNG", EXPFILL }},
    };

    proto_citp = proto_register_protocol("Controller Interface Transport Protocol", "CITP", "citp");

    proto_register_field_array(proto_citp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_register_field_array(expert_register_protocol(proto_citp), ei, array_length(ei));

    citp_handle = register_dissector_with_description (
        "citp",          /* dissector name           */
        "Controller Interface Transport Protocol", /* dissector description    */
        dissect_citp,    /* dissector function       */
        proto_citp       /* protocol being dissected */
    );
    citp_tcp_handle = create_dissector_handle(dissect_citp_tcp, proto_citp);

    content_type_table = register_dissector_table("citp.content_type", "CITP Content Type", proto_citp, FT_UINT32, BASE_HEX);
    encryption_id_table = register_dissector_table("citp.sdmx.encryption_identifier", "SDMX Encryption Id", proto_citp, FT_STRING, STRING_CASE_INSENSITIVE);

    proto_citp_pinf = proto_register_protocol("CITP Peer Information",        "CITP/PINF", "citp.pinf");
    proto_citp_sdmx = proto_register_protocol("CITP Send DMX",                "CITP/SDMX", "citp.sdmx");
    proto_citp_fptc = proto_register_protocol("CITP Fixture Patch",           "CITP/FPTC", "citp.fptc");
    proto_citp_fsel = proto_register_protocol("CITP Fixture Selection",       "CITP/FSEL", "citp.fsel");
    proto_citp_finf = proto_register_protocol("CITP Fixture Information",     "CITP/FINF", "citp.finf");
    proto_citp_caex = proto_register_protocol("CITP Capture Extensions",      "CITP/CAEX", "citp.caex");
    proto_citp_msex = proto_register_protocol("CITP Media Server Extensions", "CITP/MSEX", "citp.msex");

    proto_register_field_array(proto_citp_pinf, hf_pinf, array_length(hf_pinf));
    proto_register_field_array(proto_citp_sdmx, hf_sdmx, array_length(hf_sdmx));
    proto_register_field_array(proto_citp_fptc, hf_fptc, array_length(hf_fptc));
    proto_register_field_array(proto_citp_fsel, hf_fsel, array_length(hf_fsel));
    proto_register_field_array(proto_citp_finf, hf_finf, array_length(hf_finf));
    proto_register_field_array(proto_citp_caex, hf_caex, array_length(hf_caex));
    proto_register_field_array(proto_citp_msex, hf_msex, array_length(hf_msex));

    expert_register_field_array(expert_register_protocol(proto_citp_pinf), ei_pinf, array_length(ei_pinf));
    expert_register_field_array(expert_register_protocol(proto_citp_sdmx), ei_sdmx, array_length(ei_sdmx));
    expert_register_field_array(expert_register_protocol(proto_citp_fptc), ei_fptc, array_length(ei_fptc));
    expert_register_field_array(expert_register_protocol(proto_citp_fsel), ei_fsel, array_length(ei_fsel));
    expert_register_field_array(expert_register_protocol(proto_citp_finf), ei_finf, array_length(ei_finf));
    expert_register_field_array(expert_register_protocol(proto_citp_caex), ei_caex, array_length(ei_caex));
    expert_register_field_array(expert_register_protocol(proto_citp_msex), ei_msex, array_length(ei_msex));
}

/******************************************************************************/
/* Register handoff                                                           */
void
proto_reg_handoff_citp(void)
{
    dissector_add_uint_range_with_preference("udp.port", CITP_PORTS, citp_handle);

    heur_dissector_add("tcp", dissect_citp_heur_tcp, "CITP over TCP", "citp_tcp", proto_citp, HEURISTIC_ENABLE);

    dissector_add_uint("citp.content_type", CITP_PINF, create_dissector_handle(dissect_pinf, proto_citp_pinf));
    dissector_add_uint("citp.content_type", CITP_SDMX, create_dissector_handle(dissect_sdmx, proto_citp_sdmx));
    dissector_add_uint("citp.content_type", CITP_FPTC, create_dissector_handle(dissect_fptc, proto_citp_fptc));
    dissector_add_uint("citp.content_type", CITP_FSEL, create_dissector_handle(dissect_fsel, proto_citp_fsel));
    dissector_add_uint("citp.content_type", CITP_FINF, create_dissector_handle(dissect_finf, proto_citp_finf));
    dissector_add_uint("citp.content_type", CITP_CAEX, create_dissector_handle(dissect_caex, proto_citp_caex));
    dissector_add_uint("citp.content_type", CITP_MSEX, create_dissector_handle(dissect_msex, proto_citp_msex));

    dmx_chan_handle = find_dissector_add_dependency("dmx-chan", proto_citp);
    jpeg_handle = find_dissector_add_dependency("image-jfif", proto_citp);
    png_handle = find_dissector_add_dependency("png", proto_citp);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
