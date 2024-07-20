/* packet-vrt.c
 * Routines for VRT (VITA 49) packet disassembly
 * Copyright 2012 Ettus Research LLC - Nick Foster <nick@ettus.com>: original dissector
 * Copyright 2013 Alexander Chemeris <alexander.chemeris@gmail.com>: dissector improvement
 * Copyright 2013 Dario Lombardo (lomato@gmail.com): Official Wireshark port
 * Copyright 2022 Amazon.com, Inc. or its affiliates - Cody Planteen <codplant@amazon.com>: context packet decoding
 *
 * Original dissector repository: https://github.com/bistromath/vrt-dissector
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <math.h>

void proto_register_vrt(void);
void proto_reg_handoff_vrt(void);

static dissector_handle_t vrt_handle;

#define VITA_49_PORT    4991

typedef int (*complex_dissector_t)(proto_tree *tree, tvbuff_t *tvb, int offset);

typedef struct {
    int tsi; /* 2-bit timestamp type */
    int tsf; /* 2-bit fractional timestamp type */
    int oui; /* 24-bit GPS/INS manufacturer OUI */
    int ts_int; /* 32-bit integer timestamp (opt.) */
    int ts_picosecond; /* 64-bit fractional timestamp (mutually exclusive with below) */
    int ts_frac_sample; /* 64-bit fractional timestamp (mutually exclusive with above) */
    int pos_x; /* 32-bit position X */
    int pos_y; /* 32-bit position Y */
    int pos_z; /* 32-bit position Z */
    int att_alpha; /* 32-bit attitude alpha */
    int att_beta; /* 32-bit attitude beta */
    int att_phi; /* 32-bit attitude phi */
    int vel_dx; /* 32-bit velocity dX */
    int vel_dy; /* 32-bit velocity dY */
    int vel_dz; /* 32-bit velocity dZ */
} ephemeris_fields;

typedef struct {
    int tsi; /* 2-bit timestamp type */
    int tsf; /* 2-bit fractional timestamp type */
    int oui; /* 24-bit GPS/INS manufacturer OUI */
    int ts_int; /* 32-bit integer timestamp (opt.) */
    int ts_picosecond; /* 64-bit fractional timestamp (mutually exclusive with below) */
    int ts_frac_sample; /* 64-bit fractional timestamp (mutually exclusive with above) */
    int lat; /* 32-bit latitude */
    int lon; /* 32-bit longitude */
    int alt; /* 32-bit altitude */
    int speed; /* 32-bit speed over ground */
    int heading; /* 32-bit heading angle */
    int track; /* 32-bit track angle */
    int mag_var; /* 32-bit magnetic variation */
} formatted_gps_ins_fields;

typedef int (*complex_dissector_t)(proto_tree *tree, tvbuff_t *tvb, int offset);

static bool vrt_use_ettus_uhd_header_format;

static int proto_vrt;

/* fields */
static int hf_vrt_header; /* 32-bit header */
static int hf_vrt_type; /* 4-bit pkt type */
static int hf_vrt_cidflag; /* 1-bit class ID flag */
static int hf_vrt_tflag; /* 1-bit trailer flag */
static int hf_vrt_tsmflag; /* 1-bit timestamp mode */
static int hf_vrt_tsi; /* 2-bit timestamp type */
static int hf_vrt_tsf; /* 2-bit fractional timestamp type */
static int hf_vrt_seq; /* 4-bit sequence number */
static int hf_vrt_len; /* 16-bit length */
static int hf_vrt_sid; /* 32-bit stream ID (opt.) */
static int hf_vrt_cid; /* 64-bit class ID (opt.) */
static int hf_vrt_cid_oui; /* 24-bit class ID OUI */
static int hf_vrt_cid_icc; /* 16-bit class ID ICC */
static int hf_vrt_cid_pcc; /* 16-bit class ID PCC */
static int hf_vrt_cif[8]; /* 32-bit CIF0-CIF7 (opt.) */
static int hf_vrt_cif0_change_flag; /* 1-bit context field change indicator */
static int hf_vrt_cif0_ref_pt_id; /* 1-bit reference point identifier */
static int hf_vrt_cif0_bandwidth; /* 1-bit bandwidth */
static int hf_vrt_cif0_if_freq; /* 1-bit IF reference frequency */
static int hf_vrt_cif0_rf_freq; /* 1-bit RF reference frequency */
static int hf_vrt_cif0_rf_freq_offset; /* 1-bit RF reference frequency offset */
static int hf_vrt_cif0_if_band_offset; /* 1-bit IF band offset */
static int hf_vrt_cif0_ref_level; /* 1-bit reference level */
static int hf_vrt_cif0_gain; /* 1-bit gain */
static int hf_vrt_cif0_over_range_count; /* 1-bit over-range count */
static int hf_vrt_cif0_sample_rate; /* 1-bit sample rate */
static int hf_vrt_cif0_timestamp_adjust; /* 1-bit timestamp adjustment */
static int hf_vrt_cif0_timestamp_cal; /* 1-bit timestamp calibration time */
static int hf_vrt_cif0_temperature; /* 1-bit temperature */
static int hf_vrt_cif0_device_id; /* 1-bit device identifier */
static int hf_vrt_cif0_state_event; /* 1-bit state/event indicators */
static int hf_vrt_cif0_signal_data_format; /* 1-bit signal data packet payload format */
static int hf_vrt_cif0_gps; /* 1-bit formatted GPS */
static int hf_vrt_cif0_ins; /* 1-bit formatted INS */
static int hf_vrt_cif0_ecef_ephemeris; /* 1-bit ECEF ephemeris */
static int hf_vrt_cif0_rel_ephemeris; /* 1-bit relative ephemeris */
static int hf_vrt_cif0_ephemeris_ref_id; /* 1-bit ephemeris ref ID */
static int hf_vrt_cif0_gps_ascii; /* 1-bit GPS ASCII */
static int hf_vrt_cif0_context_assoc_lists; /* 1-bit context association lists */
static int hf_vrt_cif0_cif7; /* 1-bit CIF7 */
static int hf_vrt_cif0_cif6; /* 1-bit CIF6 */
static int hf_vrt_cif0_cif5; /* 1-bit CIF5 */
static int hf_vrt_cif0_cif4; /* 1-bit CIF4 */
static int hf_vrt_cif0_cif3; /* 1-bit CIF3 */
static int hf_vrt_cif0_cif2; /* 1-bit CIF2 */
static int hf_vrt_cif0_cif1; /* 1-bit CIF1 */
/* TODO: complete CIF1 support (have partial CIF1 support) */
static int hf_vrt_cif1_phase_offset; /* 1-bit phase offset */
static int hf_vrt_cif1_polarization; /* 1-bit polarization */
static int hf_vrt_cif1_range; /* 1-bit range (distance) */
static int hf_vrt_cif1_aux_freq; /* 1-bit aux frequency */
static int hf_vrt_cif1_aux_bandwidth; /* 1-bit aux bandwidth */
static int hf_vrt_cif1_io32; /* 1-bit discrete I/O (32-bit) */
static int hf_vrt_cif1_io64; /* 1-bit discrete I/O (64-bit) */
static int hf_vrt_cif1_v49_spec; /* 1-bit V49 spec compliance */
static int hf_vrt_cif1_ver; /* 1-bit version and build code */
static int hf_vrt_context_ref_pt_id; /* 32-bit reference point identifier */
static int hf_vrt_context_bandwidth; /* 64-bit bandwidth */
static int hf_vrt_context_if_freq; /* 64-bit IF reference frequency */
static int hf_vrt_context_rf_freq; /* 64-bit RF reference frequency */
static int hf_vrt_context_rf_freq_offset; /* 64-bit RF frequency offset */
static int hf_vrt_context_if_band_offset; /* 64-bit IF band offset */
static int hf_vrt_context_ref_level; /* 16-bit reference level */
static int hf_vrt_context_gain_stage2; /* 16-bit gain stage 2 */
static int hf_vrt_context_gain_stage1; /* 16-bit gain stage 1 */
static int hf_vrt_context_over_range_count; /* 32-bit over-range count */
static int hf_vrt_context_sample_rate; /* 64-bit sample rate */
static int hf_vrt_context_timestamp_adjust; /* 64-bit timestamp adjustment */
static int hf_vrt_context_timestamp_cal; /* 32-bit timestamp calibration */
static int hf_vrt_context_temperature; /* 16-bit device temperature */
static int hf_vrt_context_device_id_oui; /* 24-bit device ID OUI */
static int hf_vrt_context_device_id_code; /* 16-bit device ID code */
static int hf_vrt_context_state_event_en_cal_time; /* 1-bit enable calibrated time */
static int hf_vrt_context_state_event_en_valid_data; /* 1-bit enable valid data */
static int hf_vrt_context_state_event_en_ref_lock; /* 1-bit enable reference lock */
static int hf_vrt_context_state_event_en_agc; /* 1-bit enable AGC/MGC */
static int hf_vrt_context_state_event_en_detected_sig; /* 1-bit enable detected signal */
static int hf_vrt_context_state_event_en_spectral_inv; /* 1-bit enable spectral inversion */
static int hf_vrt_context_state_event_en_over_range; /* 1-bit enable over-range */
static int hf_vrt_context_state_event_en_sample_loss; /* 1-bit enable sample loss */
static int hf_vrt_context_state_event_cal_time; /* 1-bit enable calibrated time */
static int hf_vrt_context_state_event_valid_data; /* 1-bit enable valid data */
static int hf_vrt_context_state_event_ref_lock; /* 1-bit enable reference lock */
static int hf_vrt_context_state_event_agc; /* 1-bit enable AGC/MGC */
static int hf_vrt_context_state_event_detected_sig; /* 1-bit enable detected signal */
static int hf_vrt_context_state_event_spectral_inv; /* 1-bit enable spectral inversion */
static int hf_vrt_context_state_event_over_range; /* 1-bit enable over-range */
static int hf_vrt_context_state_event_sample_loss; /* 1-bit enable sample loss */
static int hf_vrt_context_state_event_user; /* 8-bit user-defined */
static int hf_vrt_context_signal_data_format_packing; /* 1-bit signal data format packing */
static int hf_vrt_context_signal_data_format_type; /* 2-bit real/complex type */
static int hf_vrt_context_signal_data_format_item; /* 5-bit data item format */
static int hf_vrt_context_signal_data_format_repeat; /* 1-bit sample-component repeat indicator */
static int hf_vrt_context_signal_data_format_event_size; /* 3-bit event-tag size */
static int hf_vrt_context_signal_data_format_channel_size; /* 4-bit channel-tag size */
static int hf_vrt_context_signal_data_format_fraction_size; /* 4-bit data item fraction size */
static int hf_vrt_context_signal_data_format_packing_size; /* 6-bit item packing field size */
static int hf_vrt_context_signal_data_format_item_size; /* 6-bit data item size */
static int hf_vrt_context_signal_data_format_repeat_count; /* 16-bit repeat count */
static int hf_vrt_context_signal_data_format_vector_size; /* 16-bit vector size */
static formatted_gps_ins_fields hf_vrt_context_gps; /* struct for formatted GPS */
static formatted_gps_ins_fields hf_vrt_context_ins; /* struct for formatted INS */
static ephemeris_fields hf_vrt_context_ecef_ephemeris; /* struct for ECEF ephemeris */
static ephemeris_fields hf_vrt_context_rel_ephemeris; /* struct for relative ephemeris */
static int hf_vrt_context_ephemeris_ref_id; /* 32-bit ephemeris reference identifier */
static int hf_vrt_context_gps_ascii_oui; /* 24-bit GPS/INS manufacturer OUI */
static int hf_vrt_context_gps_ascii_size; /* 32-bit number of words */
static int hf_vrt_context_gps_ascii_data; /* Variable GPS ASCII data */
static int hf_vrt_context_assoc_lists_src_size; /* 32-bit source list size */
static int hf_vrt_context_assoc_lists_sys_size; /* 32-bit system list size */
static int hf_vrt_context_assoc_lists_vec_size; /* 32-bit vector-component list size */
static int hf_vrt_context_assoc_lists_a; /* 1-bit "A" bit (asynchronous-channel tag list present) */
static int hf_vrt_context_assoc_lists_asy_size; /* 32-bit asynchronous-channel list size */
static int hf_vrt_context_assoc_lists_src_data; /* Variable source context association list */
static int hf_vrt_context_assoc_lists_sys_data; /* Variable system context association list */
static int hf_vrt_context_assoc_lists_vec_data; /* Variable vector-component context association list */
static int hf_vrt_context_assoc_lists_asy_data; /* Variable asynchronous-channel context association list */
static int hf_vrt_context_assoc_lists_asy_tag_data; /* Variable asynchronous-channel tag list */
static int hf_vrt_context_phase_offset; /* 16-bit phase offset */
static int hf_vrt_context_pol_tilt; /* 16-bit polarization tilt angle */
static int hf_vrt_context_pol_ellipticity; /* 16-bit polarization ellipticity angle */
static int hf_vrt_context_range; /* 32-bit range (distance) */
static int hf_vrt_context_aux_freq; /* 64-bit aux frequency */
static int hf_vrt_context_aux_bandwidth; /* 64-bit aux bandwidth */
static int hf_vrt_context_io32; /* 32-bit discrete I/O */
static int hf_vrt_context_io64; /* 64-bit discrete I/O */
static int hf_vrt_context_v49_spec; /* 32-bit V49 spec compliance */
static int hf_vrt_context_ver_year; /* 7-bit year */
static int hf_vrt_context_ver_day; /* 9-bit day */
static int hf_vrt_context_ver_rev; /* 6-bit revision */
static int hf_vrt_context_ver_user; /* 10-bit user defined */
static int hf_vrt_ts_int; /* 32-bit integer timestamp (opt.) */
static int hf_vrt_ts_frac_picosecond; /* 64-bit fractional timestamp (opt.) */
static int hf_vrt_ts_frac_sample; /* 64-bit fractional timestamp (opt.) */
static int hf_vrt_data; /* data */
static int hf_vrt_trailer; /* 32-bit trailer (opt.) */
static int hf_vrt_trailer_enables; /* trailer indicator enables */
static int hf_vrt_trailer_ind; /* trailer indicators */
static int hf_vrt_trailer_e; /* ass con pac cnt enable */
static int hf_vrt_trailer_acpc; /* associated context packet count */
static int hf_vrt_trailer_en_caltime; /* calibrated time indicator */
static int hf_vrt_trailer_en_valid; /* valid data ind */
static int hf_vrt_trailer_en_reflock; /* reference locked ind */
static int hf_vrt_trailer_en_agc; /* AGC/MGC enabled ind */
static int hf_vrt_trailer_en_sig; /* signal detected ind */
static int hf_vrt_trailer_en_inv; /* spectral inversion ind */
static int hf_vrt_trailer_en_overrng; /* overrange indicator */
static int hf_vrt_trailer_en_sampleloss; /* sample loss indicator */
static int hf_vrt_trailer_en_user0; /* User indicator 0 */
static int hf_vrt_trailer_en_user1; /* User indicator 1 */
static int hf_vrt_trailer_en_user2; /* User indicator 2 */
static int hf_vrt_trailer_en_user3; /* User indicator 3 */
static int hf_vrt_trailer_ind_caltime; /* calibrated time indicator */
static int hf_vrt_trailer_ind_valid; /* valid data ind */
static int hf_vrt_trailer_ind_reflock; /* reference locked ind */
static int hf_vrt_trailer_ind_agc; /* AGC/MGC enabled ind */
static int hf_vrt_trailer_ind_sig; /* signal detected ind */
static int hf_vrt_trailer_ind_inv; /* spectral inversion ind */
static int hf_vrt_trailer_ind_overrng; /* overrange indicator */
static int hf_vrt_trailer_ind_sampleloss; /* sample loss indicator */
static int hf_vrt_trailer_ind_user0; /* User indicator 0 */
static int hf_vrt_trailer_ind_user1; /* User indicator 1 */
static int hf_vrt_trailer_ind_user2; /* User indicator 2 */
static int hf_vrt_trailer_ind_user3; /* User indicator 3 */

/* fixed sizes (in bytes) of context packet CIF field bits */
static int context_size_cif0[32] = { 0, 4, 4, 4, 4, 4, 4, 4, 8, 8, 4, 52, 52, 44, 44, 8,
    4, 8, 4, 4, 8, 8, 4, 4, 4, 8, 8, 8, 8, 8, 4, 0 };
static int context_size_cif1[32] = { 0, 8, 4, 4, 4, 8, 4, 0, 0, 0, 52, 0, 0, 8, 4, 8,
    4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 0, 4, 4, 4 };

/* subtree state variables */
static int ett_vrt;
static int ett_header;
static int ett_trailer;
static int ett_indicators;
static int ett_ind_enables;
static int ett_cid;
static int ett_cif0;
static int ett_cif1;
static int ett_gain;
static int ett_device_id;
static int ett_state_event;
static int ett_signal_data_format;
static int ett_gps;
static int ett_ins;
static int ett_ecef_ephem;
static int ett_rel_ephem;
static int ett_gps_ascii;
static int ett_assoc_lists;
static int ett_pol;
static int ett_ver;

/* constants (unit conversion) */
static const double FEMTOSEC_PER_SEC = 1e-15;
static const double RADIX_CELSIUS = 1.0/64.0;
static const double RADIX_DECIBEL = 1.0/128.0;
static const double RADIX_DECIBEL_MILLIWATT = 1.0/128.0;
static const double RADIX_DEGREES = 1.0/4194304.0;
static const double RADIX_HERTZ = 1.0/1048576.0;
static const double RADIX_METER = 1.0/32.0;
static const double RADIX_METER_UNSIGNED = 1.0/64.0;
static const double RADIX_METERS_PER_SECOND = 1.0/65536.0;
static const double RADIX_RADIAN_PHASE = 1.0/128.0;
static const double RADIX_RADIAN_POL = 1.0/8192.0;

/* constants (tree index) */
static const int ETT_IDX_GAIN = 8;
static const int ETT_IDX_DEVICE_ID = 9;
static const int ETT_IDX_STATE_EVENT = 10;
static const int ETT_IDX_SIGNAL_DATA_FORMAT = 11;
static const int ETT_IDX_GPS = 12;
static const int ETT_IDX_INS = 13;
static const int ETT_IDX_ECEF_EPHEM = 14;
static const int ETT_IDX_REL_EPHEM = 15;
static const int ETT_IDX_GPS_ASCII = 16;
static const int ETT_IDX_ASSOC_LISTS = 17;
static const int ETT_IDX_POL = 18;
static const int ETT_IDX_VER = 19;

static const value_string packet_types[] = {
    {0x00, "IF data packet without stream ID"},
    {0x01, "IF data packet with stream ID"},
    {0x02, "Extension data packet without stream ID"},
    {0x03, "Extension data packet with stream ID"},
    {0x04, "IF context packet"},
    {0x05, "Extension context packet"},
    {0, NULL}
};

static const value_string tsi_types[] = {
    {0x00, "No integer-seconds timestamp field included"},
    {0x01, "Coordinated Universal Time (UTC)"},
    {0x02, "GPS time"},
    {0x03, "Other"},
    {0, NULL}
};

static const value_string tsf_types[] = {
    {0x00, "No fractional-seconds timestamp field included"},
    {0x01, "Sample count timestamp"},
    {0x02, "Real time (picoseconds) timestamp"},
    {0x03, "Free running count timestamp"},
    {0, NULL}
};

static const value_string tsm_types[] = {
    {0x00, "Precise timestamp resolution"},
    {0x01, "General timestamp resolution"},
    {0, NULL}
};

static const value_string packing_method[] = {
    {0x00, "Processing efficient"},
    {0x01, "Link efficient"},
    {0, NULL}
};

static const value_string data_sample_type[] = {
    {0x00, "Real"},
    {0x01, "Complex, Cartesian"},
    {0x02, "Complex, polar"},
    {0, NULL}
};

static const value_string data_item_format[] = {
    {0x00, "Signed fixed-point"},
    {0x01, "Signed VRT, 1-bit exponent"},
    {0x02, "Signed VRT, 2-bit exponent"},
    {0x03, "Signed VRT, 3-bit exponent"},
    {0x04, "Signed VRT, 4-bit exponent"},
    {0x05, "Signed VRT, 5-bit exponent"},
    {0x06, "Signed VRT, 6-bit exponent"},
    {0x07, "Signed fixed-point non-normalized"},
    {0x0D, "IEEE-754 half-precision floating-point"},
    {0x0E, "IEEE-754 single-precision floating-point"},
    {0x0F, "IEEE-754 double-precision floating-point"},
    {0x10, "Unsigned fixed-point"},
    {0x11, "Unsigned VRT, 1-bit exponent"},
    {0x12, "Unsigned VRT, 2-bit exponent"},
    {0x13, "Unsigned VRT, 3-bit exponent"},
    {0x14, "Unsigned VRT, 4-bit exponent"},
    {0x15, "Unsigned VRT, 5-bit exponent"},
    {0x16, "Unsigned VRT, 6-bit exponent"},
    {0x17, "Unsigned fixed-point non-normalized"},
    {0, NULL}
};

static const value_string standard_version_codes[] = {
    {0x01, "Implements V49.0"},
    {0x02, "Implements V49.1"},
    {0x03, "Implements V49A"},
    {0x04, "Implements V49.2"},
    {0, NULL}
};

static int * const enable_hfs[] = {
    &hf_vrt_trailer_en_user3,
    &hf_vrt_trailer_en_user2,
    &hf_vrt_trailer_en_user1,
    &hf_vrt_trailer_en_user0,
    &hf_vrt_trailer_en_sampleloss,
    &hf_vrt_trailer_en_overrng,
    &hf_vrt_trailer_en_inv,
    &hf_vrt_trailer_en_sig,
    &hf_vrt_trailer_en_agc,
    &hf_vrt_trailer_en_reflock,
    &hf_vrt_trailer_en_valid,
    &hf_vrt_trailer_en_caltime
};

static int * const ind_hfs[] = {
    &hf_vrt_trailer_ind_user3,
    &hf_vrt_trailer_ind_user2,
    &hf_vrt_trailer_ind_user1,
    &hf_vrt_trailer_ind_user0,
    &hf_vrt_trailer_ind_sampleloss,
    &hf_vrt_trailer_ind_overrng,
    &hf_vrt_trailer_ind_inv,
    &hf_vrt_trailer_ind_sig,
    &hf_vrt_trailer_ind_agc,
    &hf_vrt_trailer_ind_reflock,
    &hf_vrt_trailer_ind_valid,
    &hf_vrt_trailer_ind_caltime
};

static void dissect_header(tvbuff_t *tvb, proto_tree *tree, int type, int offset);
static void dissect_trailer(tvbuff_t *tvb, proto_tree *tree, int offset);
static void dissect_cid(tvbuff_t *tvb, proto_tree *tree, int offset);
static int dissect_context(tvbuff_t *tvb, proto_tree *tree, int offset);
static int dissect_context_as_cif(tvbuff_t *tvb, proto_tree *tree, int offset, uint32_t cif, complex_dissector_t
    *complex_fptr, int **item_ptr, const int *size_ptr, int stop);
static int dissect_context_array_of_records(proto_tree *tree _U_, tvbuff_t *tvb, int offset);
static int dissect_context_assoc_lists(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_cif0(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_cif1(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_device_id(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_ecef_ephemeris(proto_tree *tree, tvbuff_t *tvb, int offset);
static void dissect_context_ephemeris(const ephemeris_fields *s, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_gain(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_gps(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_gps_ascii(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_ins(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_phase_offset(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_polarization(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_ref_level(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_rel_ephemeris(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_signal_data_format(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_state_event(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_temperature(proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_context_ver(proto_tree *tree, tvbuff_t *tvb, int offset);
static const char* get_engr_prefix(double *val);

/* context simple field dissector function pointer array (mutually exclusive with complex below) */
static int* hf_vrt_context_cif0[32] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, &hf_vrt_context_ephemeris_ref_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    &hf_vrt_context_timestamp_cal, &hf_vrt_context_timestamp_adjust, &hf_vrt_context_sample_rate,
    &hf_vrt_context_over_range_count, NULL, NULL, &hf_vrt_context_if_band_offset,
    &hf_vrt_context_rf_freq_offset, &hf_vrt_context_rf_freq, &hf_vrt_context_if_freq,
    &hf_vrt_context_bandwidth, &hf_vrt_context_ref_pt_id, NULL };

static int* hf_vrt_context_cif1[32] = { NULL, NULL, NULL, &hf_vrt_context_v49_spec, NULL,
    &hf_vrt_context_io64, &hf_vrt_context_io32, NULL, NULL, NULL, NULL, NULL, NULL,
    &hf_vrt_context_aux_bandwidth, NULL, &hf_vrt_context_aux_freq, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, &hf_vrt_context_range, NULL, NULL, NULL, NULL, NULL, NULL, NULL };


/* context complex field dissector function pointer array */
static complex_dissector_t complex_dissector_cif0[32] = {
    NULL, dissect_context_cif1, NULL, NULL, NULL, NULL, NULL, NULL, dissect_context_assoc_lists,
    dissect_context_gps_ascii, NULL, dissect_context_rel_ephemeris, dissect_context_ecef_ephemeris,
    dissect_context_ins, dissect_context_gps, dissect_context_signal_data_format,
    dissect_context_state_event, dissect_context_device_id, dissect_context_temperature, NULL,
    NULL, NULL, NULL, dissect_context_gain, dissect_context_ref_level, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL };

/* partial CIF1 support */
static complex_dissector_t complex_dissector_cif1[32] = {
    NULL, NULL, dissect_context_ver, NULL, NULL, NULL, NULL, dissect_context_array_of_records,
    NULL, dissect_context_array_of_records, NULL, dissect_context_array_of_records, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    dissect_context_array_of_records, NULL,
    dissect_context_polarization, dissect_context_phase_offset };


static int dissect_vrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int     offset = 0;
    uint8_t type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49");
    col_clear(pinfo->cinfo,COL_INFO);

    /* HACK to support UHD's weird header offset on data packets. */
    if (vrt_use_ettus_uhd_header_format && tvb_get_uint8(tvb, 0) == 0)
        offset += 4;

    /* get packet type */
    type = tvb_get_uint8(tvb, offset) >> 4;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, packet_types, "Reserved packet type (0x%02x)"));

    if (tree) { /* we're being asked for details */
        uint8_t sidflag;
        uint8_t cidflag;
        uint8_t tflag;
        uint8_t tsitype;
        uint8_t tsftype;
        uint16_t len;
        uint16_t nsamps;

        proto_tree *vrt_tree;
        proto_item *ti;

        /* get SID, CID, T flags and TSI, TSF types */
        sidflag = (((type & 0x01) != 0) || (type == 4)) ? 1 : 0;
        cidflag = (tvb_get_uint8(tvb, offset) >> 3) & 0x01;
        /* tflag is in data packets but not context packets */
        tflag =   (tvb_get_uint8(tvb, offset) >> 2) & 0x01;
        if (type == 4)
            tflag = 0; /* this should be unnecessary but we do it just in case */
        /* tsmflag is in context packets but not data packets
           tsmflag = (tvb_get_uint8(tvb, offset) >> 0) & 0x01; */
        tsitype = (tvb_get_uint8(tvb, offset+1) >> 6) & 0x03;
        tsftype = (tvb_get_uint8(tvb, offset+1) >> 4) & 0x03;
        len     = tvb_get_ntohs(tvb, offset+2);

        nsamps  = len - 1;  /* (Before adjusting word count for optional fields) */

        ti = proto_tree_add_item(tree, proto_vrt, tvb, offset, -1, ENC_NA);
        vrt_tree = proto_item_add_subtree(ti, ett_vrt);

        dissect_header(tvb, vrt_tree, type, offset);
        offset += 4;

        /* header's done! if SID (last bit of type), put the stream ID here */
        if (sidflag) {
            proto_tree_add_item(vrt_tree, hf_vrt_sid, tvb, offset, 4, ENC_BIG_ENDIAN);
            nsamps -= 1;
            offset += 4;

        }

        /* if there's a class ID (cidflag), put the class ID here */
        if (cidflag) {
            dissect_cid(tvb, vrt_tree, offset);
            nsamps -= 2;
            offset += 8;
        }

        /* if TSI and/or TSF, populate those here */
        if (tsitype != 0) {
            proto_tree_add_item(vrt_tree, hf_vrt_ts_int, tvb, offset, 4, ENC_BIG_ENDIAN);
            nsamps -= 1;
            offset += 4;
        }
        if (tsftype != 0) {
            if (tsftype == 1 || tsftype == 3) {
                proto_tree_add_item(vrt_tree, hf_vrt_ts_frac_sample, tvb, offset, 8, ENC_BIG_ENDIAN);
            } else if (tsftype == 2) {
                proto_tree_add_item(vrt_tree, hf_vrt_ts_frac_picosecond, tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            nsamps -= 2;
            offset += 8;
        }

        if (tflag) {
            nsamps -= 1;
        }

        /* now we've got either a context packet or a data packet */
        if (type == 4) {
            /* parse context packet */
            int num_v49_words = dissect_context(tvb, vrt_tree, offset);
            nsamps -= num_v49_words;
            offset += 4*num_v49_words;
        }

        /* we're into the data */
        if (nsamps != 0) {
            proto_tree_add_item(vrt_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
        }

        offset += nsamps*4;

        if (tflag) {
            dissect_trailer(tvb, vrt_tree, offset);
        }
    }
    return tvb_captured_length(tvb);
}

static void dissect_header(tvbuff_t *tvb, proto_tree *tree, int type, int offset)
{
    proto_item *hdr_item;
    proto_tree *hdr_tree;

    hdr_item = proto_tree_add_item(tree, hf_vrt_header, tvb, offset, 4, ENC_BIG_ENDIAN);

    hdr_tree = proto_item_add_subtree(hdr_item, ett_header);
    proto_tree_add_item(hdr_tree, hf_vrt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_cidflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (type == 4) {
        proto_tree_add_item(hdr_tree, hf_vrt_tsmflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(hdr_tree, hf_vrt_tflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;
    proto_tree_add_item(hdr_tree, hf_vrt_tsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_tsf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hdr_tree, hf_vrt_len, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void dissect_trailer(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *enable_item, *ind_item, *trailer_item;
    proto_tree *enable_tree;
    proto_tree *ind_tree;
    proto_tree *trailer_tree;
    uint16_t    en_bits;
    int16_t     i;

    trailer_item = proto_tree_add_item(tree, hf_vrt_trailer, tvb, offset, 4, ENC_BIG_ENDIAN);
    trailer_tree = proto_item_add_subtree(trailer_item, ett_trailer);

    /* grab the indicator enables and the indicators;
       only display enables, indicators which are enabled */
    enable_item = proto_tree_add_item(trailer_tree, hf_vrt_trailer_enables, tvb, offset, 2, ENC_BIG_ENDIAN);
    ind_item = proto_tree_add_item(trailer_tree, hf_vrt_trailer_ind, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    /* grab enable bits */
    en_bits = (tvb_get_ntohs(tvb, offset) & 0xFFF0) >> 4;

    /* if there's any enables, start trees for enable bits and for indicators
       only enables and indicators which are enabled get printed. */
    if (en_bits) {
        enable_tree = proto_item_add_subtree(enable_item, ett_ind_enables);
        ind_tree = proto_item_add_subtree(ind_item, ett_indicators);
        for (i = 11; i >= 0; i--) {
            if (en_bits & (1<<i)) {
                /* XXX: Display needs to be improved ... */
                proto_tree_add_item(enable_tree, *enable_hfs[i], tvb, offset,   2, ENC_BIG_ENDIAN);
                proto_tree_add_item(ind_tree, *ind_hfs[i],       tvb, offset+1, 2, ENC_BIG_ENDIAN);
            }
        }
    }
    offset += 3;
    proto_tree_add_item(trailer_tree, hf_vrt_trailer_e,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(trailer_tree, hf_vrt_trailer_acpc, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void dissect_cid(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *cid_item;
    proto_tree *cid_tree;

    cid_item = proto_tree_add_item(tree, hf_vrt_cid, tvb, offset, 8, ENC_BIG_ENDIAN);
    cid_tree = proto_item_add_subtree(cid_item, ett_cid);

    offset += 1;
    proto_tree_add_item(cid_tree, hf_vrt_cid_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(cid_tree, hf_vrt_cid_icc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(cid_tree, hf_vrt_cid_pcc, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static int dissect_context(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint32_t cif[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    int offset_start = offset;

    cif[0] = tvb_get_ntohl(tvb, offset);
    dissect_context_cif0(tree, tvb, offset);
    offset += 4;
    // CIF1-CIF7 bit fields come next with CIF1 first
    for (int i = 1; i < 8; i++) {
        if (cif[0] & (1 << i)) {
            if (complex_dissector_cif0[i] != NULL) {
                (*complex_dissector_cif0[i])(tree, tvb, offset);
            } else {
                proto_tree_add_item(tree, hf_vrt_cif[i], tvb, offset, 4, ENC_BIG_ENDIAN);
            }
            cif[i] = tvb_get_ntohl(tvb, offset);
            offset += 4;
        }
    }

    // decode CIF0 fields
    offset = dissect_context_as_cif(tvb, tree, offset, cif[0], complex_dissector_cif0, hf_vrt_context_cif0,
                                    context_size_cif0, 7);
    // finally other CIFs (only CIF1 for now)
    if (cif[0] & (1 << 1)) {
        offset = dissect_context_as_cif(tvb, tree, offset, cif[1], complex_dissector_cif1, hf_vrt_context_cif1,
                                        context_size_cif1, 0);
    }

    // return how many VITA-49 words were processed
    return (offset - offset_start)/4;
}

static int dissect_context_as_cif(tvbuff_t *tvb, proto_tree *tree, int offset, uint32_t cif,
                                  complex_dissector_t *complex_fptr, int **item_ptr, const int *size_ptr, int stop) {
    for (int i = 31; i > stop; i--) {
        if (cif & (1u << i)) {
            if (complex_fptr[i] != NULL) {
                // a complex dissector returns the variable part of field length (in bytes)
                offset += (*complex_fptr[i])(tree, tvb, offset);
            } else if (item_ptr[i] != NULL) {
                proto_tree_add_item(tree, *item_ptr[i], tvb, offset, size_ptr[i], ENC_BIG_ENDIAN);
            }
            // add fixed part of field length (in bytes)
            offset += size_ptr[i];
        }
    }

    return offset;
}

static int dissect_context_array_of_records(proto_tree *tree _U_, tvbuff_t *tvb, int offset) {
    // This is a placeholder that does not populate a proto tree, but computes & returns the
    // variable field length so subsequent field indexing is correct.
    return tvb_get_ntohl(tvb, offset)*4;
}

static int dissect_context_assoc_lists(proto_tree *tree, tvbuff_t *tvb, int offset) {
    // compute number of variable words in field
    uint32_t word1 = tvb_get_ntohl(tvb, offset);
    uint32_t src_size = (word1 >> 16) & 0x01FF;
    uint32_t sys_size = word1 & 0x01FF;
    uint32_t word2 = tvb_get_ntohl(tvb, offset + 4);
    uint32_t vec_size = word2 >> 16;
    bool a_bit = (word2 & 0x8000) != 0;
    uint32_t asy_size = word2 & 0x7FFF;
    uint32_t num_words = src_size + sys_size + vec_size + asy_size + a_bit*asy_size;

    proto_tree *assoc_tree = proto_tree_add_subtree(tree, tvb, offset, 8 + num_words*4, ETT_IDX_ASSOC_LISTS, NULL,
                                                    "Context association lists");
    proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_src_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_sys_size, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_vec_size, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_a, tvb, offset + 6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_asy_size, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
    offset += 8;

    if (src_size > 0) {
        proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_src_data, tvb, offset, src_size*4, ENC_NA);
        offset += src_size*4;
    }

    if (sys_size > 0) {
        proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_sys_data, tvb, offset, sys_size*4, ENC_NA);
        offset += sys_size*4;
    }

    if (vec_size > 0) {
        proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_vec_data, tvb, offset, vec_size*4, ENC_NA);
        offset += vec_size*4;
    }

    if (asy_size > 0) {
        proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_asy_data, tvb, offset, asy_size*4, ENC_NA);
        offset += asy_size*4;
        if (a_bit) {
            proto_tree_add_item(assoc_tree, hf_vrt_context_assoc_lists_asy_tag_data, tvb, offset, asy_size*4, ENC_NA);
        }
    }

    return num_words*4;
}

static int dissect_context_cif0(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_item *cif0_item;
    proto_tree *cif0_tree;

    cif0_item = proto_tree_add_item(tree, hf_vrt_cif[0], tvb, offset, 4, ENC_BIG_ENDIAN);
    cif0_tree = proto_item_add_subtree(cif0_item, ett_cif0);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_change_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_ref_pt_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_bandwidth, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_if_freq, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_rf_freq, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_rf_freq_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_if_band_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_ref_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_gain, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_over_range_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_sample_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_timestamp_adjust, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_timestamp_cal, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_temperature, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_device_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_state_event, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_signal_data_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_gps, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_ins, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_ecef_ephemeris, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_rel_ephemeris, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_ephemeris_ref_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_gps_ascii, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_context_assoc_lists, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif7, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif0_tree, hf_vrt_cif0_cif1, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_cif1(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_item *cif1_item = proto_tree_add_item(tree, hf_vrt_cif[1], tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree *cif1_tree = proto_item_add_subtree(cif1_item, ett_cif1);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_phase_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_polarization, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_range, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_aux_freq, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_aux_bandwidth, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_io32, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_io64, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_v49_spec, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cif1_tree, hf_vrt_cif1_ver, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_device_id(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *id_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ETT_IDX_DEVICE_ID, NULL, "Device identifier");
    proto_tree_add_item(id_tree, hf_vrt_context_device_id_oui, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(id_tree, hf_vrt_context_device_id_code, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_ecef_ephemeris(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *ecef_tree = proto_tree_add_subtree(tree, tvb, offset, 52, ETT_IDX_ECEF_EPHEM, NULL, "ECEF ephemeris");
    dissect_context_ephemeris(&hf_vrt_context_ecef_ephemeris, ecef_tree, tvb, offset);
    return 0;
}

static void dissect_context_ephemeris(const ephemeris_fields *s, proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(tree, s->tsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->tsf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->oui, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->ts_int, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    uint8_t tsftype = tvb_get_uint8(tvb, offset) & 0x03;
    if (tsftype == 1 || tsftype == 3) {
        proto_tree_add_item(tree, s->ts_frac_sample, tvb, offset + 8, 8, ENC_BIG_ENDIAN);
    } else if (tsftype == 2) {
        proto_tree_add_item(tree, s->ts_picosecond, tvb, offset + 8, 8, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(tree, s->pos_x, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->pos_y, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->pos_z, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->att_alpha, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->att_beta, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->att_phi, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->vel_dx, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->vel_dy, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->vel_dz, tvb, offset + 48, 4, ENC_BIG_ENDIAN);
}

static void dissect_context_formatted_gps_ins(const formatted_gps_ins_fields *s, proto_tree *tree, tvbuff_t *tvb,
                                              int offset) {
    proto_tree_add_item(tree, s->tsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->tsf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->oui, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->ts_int, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    uint8_t tsftype = tvb_get_uint8(tvb, offset) & 0x03;
    if (tsftype == 1 || tsftype == 3) {
        proto_tree_add_item(tree, s->ts_frac_sample, tvb, offset + 8, 8, ENC_BIG_ENDIAN);
    } else if (tsftype == 2) {
        proto_tree_add_item(tree, s->ts_picosecond, tvb, offset + 8, 8, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(tree, s->lat, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->lon, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->alt, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->speed, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->heading, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->track, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, s->mag_var, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
}

static int dissect_context_gain(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *gain_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ETT_IDX_GAIN, NULL, "Gain");
    proto_tree_add_item(gain_tree, hf_vrt_context_gain_stage2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gain_tree, hf_vrt_context_gain_stage1, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_gps(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *gps_tree = proto_tree_add_subtree(tree, tvb, offset, 44, ETT_IDX_GPS, NULL, "Formatted GPS");
    dissect_context_formatted_gps_ins(&hf_vrt_context_gps, gps_tree, tvb, offset);
    return 0;
}

static int dissect_context_gps_ascii(proto_tree *tree, tvbuff_t *tvb, int offset) {
    uint32_t nword = tvb_get_ntohl(tvb, offset + 4);
    proto_tree *gps_tree = proto_tree_add_subtree(tree, tvb, offset, 8 + nword*4, ETT_IDX_GPS_ASCII, NULL, "GPS ASCII");
    proto_tree_add_item(gps_tree, hf_vrt_context_gps_ascii_oui, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(gps_tree, hf_vrt_context_gps_ascii_size, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    if (nword > 0) {
        proto_tree_add_item(gps_tree, hf_vrt_context_gps_ascii_data, tvb, offset + 8, nword*4, ENC_NA);
    }

    return nword*4;
}

static int dissect_context_ins(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *ins_tree = proto_tree_add_subtree(tree, tvb, offset, 44, ETT_IDX_INS, NULL, "Formatted INS");
    dissect_context_formatted_gps_ins(&hf_vrt_context_ins, ins_tree, tvb, offset);
    return 0;
}

static int dissect_context_phase_offset(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(tree, hf_vrt_context_phase_offset, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_polarization(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *pol_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ETT_IDX_POL, NULL, "Polarization");
    proto_tree_add_item(pol_tree, hf_vrt_context_pol_tilt, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pol_tree, hf_vrt_context_pol_ellipticity, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_ref_level(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(tree, hf_vrt_context_ref_level, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_rel_ephemeris(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *rel_tree = proto_tree_add_subtree(tree, tvb, offset, 52, ETT_IDX_REL_EPHEM, NULL, "Relative ephemeris");
    dissect_context_ephemeris(&hf_vrt_context_rel_ephemeris, rel_tree, tvb, offset);
    return 0;
}

static int dissect_context_signal_data_format(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *format_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ETT_IDX_SIGNAL_DATA_FORMAT, NULL,
                                                     "Signal data packet payload format");
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_packing, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_item, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_repeat, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_event_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_channel_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_fraction_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_packing_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_item_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_repeat_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(format_tree, hf_vrt_context_signal_data_format_vector_size, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 0;
}

static int dissect_context_state_event(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *state_event_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ETT_IDX_STATE_EVENT, NULL,
                                                          "State and event indicators");
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_cal_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_valid_data, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_ref_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_agc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_detected_sig, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_spectral_inv, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_over_range, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_en_sample_loss, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_cal_time, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_valid_data, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_ref_lock, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_agc, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_detected_sig, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_spectral_inv, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_over_range, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_sample_loss, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(state_event_tree, hf_vrt_context_state_event_user, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_temperature(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(tree, hf_vrt_context_temperature, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    return 0;
}

static int dissect_context_ver(proto_tree *tree, tvbuff_t *tvb, int offset) {
    proto_tree *ver_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ETT_IDX_VER, NULL,
                                                  "Version and build code");
    proto_tree_add_item(ver_tree, hf_vrt_context_ver_year, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ver_tree, hf_vrt_context_ver_day, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ver_tree, hf_vrt_context_ver_rev, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ver_tree, hf_vrt_context_ver_user, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    return 0;
}

static void format_celsius(char *str, int16_t val) {
    snprintf(str, ITEM_LABEL_LENGTH, "%f °C", (double)val*RADIX_CELSIUS);
}

static void format_decibel(char *str, int16_t val) {
    snprintf(str, ITEM_LABEL_LENGTH, "%f dB", (double)val*RADIX_DECIBEL);
}

static void format_decibel_milliwatt(char *str, int16_t val) {
    snprintf(str, ITEM_LABEL_LENGTH, "%f dBm", (double)val*RADIX_DECIBEL_MILLIWATT);
}

static void format_degrees(char *str, int32_t val) {
    snprintf(str, ITEM_LABEL_LENGTH, "%f degrees", (double)val*RADIX_DEGREES);
}

static void format_hertz(char *str, int64_t val) {
    double val_f64 = (double)val*RADIX_HERTZ;
    const char *prefix = get_engr_prefix(&val_f64);
    snprintf(str, ITEM_LABEL_LENGTH, "%f %sHz", val_f64, prefix);
}

static void format_meter(char *str, int32_t val) {
    double val_f64 = (double)val*RADIX_METER;
    const char *prefix = get_engr_prefix(&val_f64);
    snprintf(str, ITEM_LABEL_LENGTH, "%f %sm", val_f64, prefix);
}

static void format_meter_unsigned(char *str, uint32_t val) {
    double val_f64 = (double)val*RADIX_METER_UNSIGNED;
    const char *prefix = get_engr_prefix(&val_f64);
    snprintf(str, ITEM_LABEL_LENGTH, "%f %sm", val_f64, prefix);
}

static void format_meters_per_second(char *str, int32_t val) {
    double val_f64 = (double)val*RADIX_METERS_PER_SECOND;
    const char *prefix = get_engr_prefix(&val_f64);
    snprintf(str, ITEM_LABEL_LENGTH, "%f %sm/s", val_f64, prefix);
}

static void format_radian_phase(char *str, int16_t val) {
    snprintf(str, ITEM_LABEL_LENGTH, "%f rad", (double)val*RADIX_RADIAN_PHASE);
}

static void format_radian_pol(char *str, int16_t val) {
    snprintf(str, ITEM_LABEL_LENGTH, "%f rad", (double)val*RADIX_RADIAN_POL);
}

static void format_second(char *str, int64_t val) {
    double val_f64 = (double)val*FEMTOSEC_PER_SEC;
    const char *prefix = get_engr_prefix(&val_f64);
    snprintf(str, ITEM_LABEL_LENGTH, "%f %ss", val_f64, prefix);
}

static const char* get_engr_prefix(double *val) {
    const char* prefix_str = "";
    int32_t exp = (int32_t)floor(log10(fabs(*val))/(double)3.0)*3;

    switch (exp) {
        case -15:
            prefix_str = "f";
            *val *= 1e15;
            break;
        case -12:
            prefix_str = "p";
            *val *= 1e12;
            break;
        case -9:
            prefix_str = "n";
            *val *= 1e9;
            break;
        case -6:
            prefix_str = "µ";
            *val *= 1e6;
            break;
        case -3:
            prefix_str = "m";
            *val *= 1e3;
            break;
        case 3:
            prefix_str = "k";
            *val *= 1e-3;
            break;
        case 6:
            prefix_str = "M";
            *val *= 1e-6;
            break;
        case 9:
            prefix_str = "G";
            *val *= 1e-9;
            break;
        case 12:
            prefix_str = "T";
            *val *= 1e-12;
            break;
    }

    return prefix_str;
}

void
proto_register_vrt(void)
{
    module_t *vrt_module;

    static hf_register_info hf[] = {
        { &hf_vrt_header,
            { "VRT header", "vrt.hdr",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_type,
            { "Packet type", "vrt.type",
            FT_UINT8, BASE_DEC,
            VALS(packet_types), 0xF0,
            NULL, HFILL }
        },
        { &hf_vrt_cidflag,
            { "Class ID included", "vrt.cidflag",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_tflag,
            { "Trailer included", "vrt.tflag",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_tsmflag,
            { "Timestamp mode", "vrt.tsmflag",
            FT_UINT8, BASE_DEC,
            VALS(tsm_types), 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_tsi,
            { "Integer timestamp type", "vrt.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0xC0,
            NULL, HFILL }
        },
        { &hf_vrt_tsf,
            { "Fractional timestamp type", "vrt.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x30,
            NULL, HFILL }
        },
        { &hf_vrt_seq,
            { "Sequence number", "vrt.seq",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_vrt_len,
            { "Length", "vrt.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_int,
            { "Integer timestamp", "vrt.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_sid,
            { "Stream ID", "vrt.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid,
            { "Class ID", "vrt.cid",
            FT_UINT64, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[0],
            { "CIF0", "vrt.cif0",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_change_flag,
            { "Context field change indicator", "vrt.cif0.change",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_ref_pt_id,
            { "Reference point identifier", "vrt.cif0.refptid",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_bandwidth,
            { "Bandwidth", "vrt.cif0.bw",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_if_freq,
            { "IF reference frequency", "vrt.cif0.iffreq",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_rf_freq,
            { "RF reference frequency", "vrt.cif0.rffreq",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_rf_freq_offset,
            { "RF reference frequency offset", "vrt.cif0.rffreqoffset",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_if_band_offset,
            { "IF band offset", "vrt.cif0.ifbandoffset",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_ref_level,
            { "Reference level", "vrt.cif0.reflevel",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_gain,
            { "Gain", "vrt.cif0.gain",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_over_range_count,
            { "Over-range count", "vrt.cif0.overrangecount",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_sample_rate,
            { "Sample rate", "vrt.cif0.samplerate",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_timestamp_adjust,
            { "Timestamp adjustment", "vrt.cif0.timestampadjust",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_timestamp_cal,
            { "Timestamp calibration time", "vrt.cif0.timestampcal",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_temperature,
            { "Temperature", "vrt.cif0.temperature",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_device_id,
            { "Device identifier", "vrt.cif0.deviceid",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_state_event,
            { "State/event indicators", "vrt.cif0.stateevent",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_signal_data_format,
            { "Signal data format", "vrt.cif0.signaldataformat",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_gps,
            { "Formatted GPS", "vrt.cif0.gps",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_ins,
            { "Formatted INS", "vrt.cif0.ins",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_ecef_ephemeris,
            { "ECEF ephemeris", "vrt.cif0.ecefephem",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_rel_ephemeris,
            { "Relative ephemeris", "vrt.cif0.relephem",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_ephemeris_ref_id,
            { "Ephemeris ref ID", "vrt.cif0.ephemrefid",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_gps_ascii,
            { "GPS ASCII", "vrt.cif0.gpsascii",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_context_assoc_lists,
            { "Context association lists", "vrt.cif0.assoclists",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif7,
            { "CIF7", "vrt.cif0.cif7",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif6,
            { "CIF6", "vrt.cif0.cif6",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif5,
            { "CIF5", "vrt.cif0.cif5",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif4,
            { "CIF4", "vrt.cif0.cif4",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif3,
            { "CIF3", "vrt.cif0.cif3",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif2,
            { "CIF2", "vrt.cif0.cif2",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_cif0_cif1,
            { "CIF1", "vrt.cif0.cif1",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_phase_offset,
            { "Phase offset", "vrt.cif1.phaseoffset",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_polarization,
            { "Polarization", "vrt.cif1.polarization",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_range,
            { "Range (distance)", "vrt.cif1.range",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_aux_freq,
            { "Aux frequency", "vrt.cif1.auxfreq",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_aux_bandwidth,
            { "Aux bandwidth", "vrt.cif1.auxbw",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_io32,
            { "Discrete I/O (32-bit)", "vrt.cif1.io32",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_io64,
            { "Discrete I/O (64-bit)", "vrt.cif1.io64",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_v49_spec,
            { "V49 spec compliance", "vrt.cif1.v49spec",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_cif1_ver,
            { "Version and build code", "vrt.cif1.ver",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_cif[1],
            { "CIF1", "vrt.cif1",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[2],
            { "CIF2", "vrt.cif2",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[3],
            { "CIF3", "vrt.cif3",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[4],
            { "CIF4", "vrt.cif4",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[5],
            { "CIF5", "vrt.cif5",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[6],
            { "CIF6", "vrt.cif6",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cif[7],
            { "CIF7", "vrt.cif7",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ref_pt_id,
            { "Reference point identifier", "vrt.context.refptid",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_bandwidth,
            { "Bandwidth", "vrt.context.bw",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_if_freq,
            { "IF reference frequency", "vrt.context.iffreq",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rf_freq,
            { "RF reference frequency", "vrt.context.rffreq",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rf_freq_offset,
            { "RF reference frequency offset", "vrt.context.rffreqoffset",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_if_band_offset,
            { "IF band offset", "vrt.context.ifbandoffset",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ref_level,
            { "Reference level", "vrt.context.reflevel",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_decibel_milliwatt), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gain_stage2,
            { "Stage 2", "vrt.context.gain.stage2",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_decibel), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gain_stage1,
            { "Stage 1", "vrt.context.gain.stage1",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_decibel), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_over_range_count,
            { "Over-range count", "vrt.context.overrangecount",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_sample_rate,
            { "Sample rate", "vrt.context.samplerate",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_timestamp_adjust,
            { "Timestamp adjustment", "vrt.context.timestampadjust",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_timestamp_cal,
            { "Timestamp calibration", "vrt.context.timestampcal",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_temperature,
            { "Device temperature", "vrt.context.temperature",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_celsius), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_device_id_oui,
            { "Manufacturer OUI", "vrt.context.deviceid.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_device_id_code,
            { "Device code", "vrt.context.deviceid.code",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_cal_time,
            { "Calibrated time enable", "vrt.context.stateevent.caltime.en",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_valid_data,
            { "Valid data enable", "vrt.context.stateevent.validdata.en",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_ref_lock,
            { "Reference lock enable", "vrt.context.stateevent.reflock.en",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_agc,
            { "AGC/MGC enable", "vrt.context.stateevent.agc.en",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_detected_sig,
            { "Detected signal enable", "vrt.context.stateevent.detectedsignal.en",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_spectral_inv,
            { "Spectral inversion enable", "vrt.context.stateevent.spectralinv.en",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_over_range,
            { "Over-range enable", "vrt.context.stateevent.overrange.en",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_en_sample_loss,
            { "Sample loss enable", "vrt.cif0.context.sampleloss.en",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_cal_time,
            { "Calibrated time indicator", "vrt.context.stateevent.caltime.val",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_valid_data,
            { "Valid data indicator", "vrt.context.stateevent.validdata.val",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_ref_lock,
            { "Reference lock indicator", "vrt.context.stateevent.reflock.val",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_agc,
            { "AGC/MGC indicator", "vrt.context.stateevent.agc.val",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_detected_sig,
            { "Detected signal indicator", "vrt.context.stateevent.detectedsignal.val",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_spectral_inv,
            { "Spectral inversion indicator", "vrt.context.stateevent.spectralinv.val",
            FT_BOOLEAN, 8,
            NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_over_range,
            { "Over-range indicator", "vrt.context.stateevent.overrange.val",
            FT_BOOLEAN, 8,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_sample_loss,
            { "Sample loss indicator", "vrt.context.stateevent.sampleloss.val",
            FT_BOOLEAN, 8,
            NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_vrt_context_state_event_user,
            { "User-defined", "vrt.context.stateevent.user",
            FT_UINT8, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_packing,
            { "Packing method", "vrt.context.signaldataformat.packing",
            FT_UINT8, BASE_DEC,
            VALS(packing_method), 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_type,
            { "Real/complex type", "vrt.context.signaldataformat.realcomplex",
            FT_UINT8, BASE_DEC,
            VALS(data_sample_type), 0x60,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_item,
            { "Data item format", "vrt.context.signaldataformat.format",
            FT_UINT8, BASE_DEC,
            VALS(data_item_format), 0x1F,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_repeat,
            { "Sample-component repeat indicator", "vrt.context.signaldataformat.repeat",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_event_size,
            { "Event-tag size", "vrt.context.signaldataformat.eventsize",
            FT_UINT8, BASE_DEC,
            NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_channel_size,
            { "Channel-tag size", "vrt.context.signaldataformat.channelsize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_fraction_size,
            { "Data item fraction size", "vrt.context.signaldataformat.fractionsize",
            FT_UINT16, BASE_DEC,
            NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_packing_size,
            { "Item packing field size", "vrt.context.signaldataformat.packingsize",
            FT_UINT16, BASE_DEC,
            NULL, 0x0FC0,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_item_size,
            { "Data item size", "vrt.context.signaldataformat.itemsize",
            FT_UINT16, BASE_DEC,
            NULL, 0x003F,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_repeat_count,
            { "Repeat count", "vrt.context.signaldataformat.repeatcount",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vrt_context_signal_data_format_vector_size,
            { "Vector size", "vrt.context.signaldataformat.vectorsize",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.tsi,
            { "Integer timestamp type", "vrt.context.gps.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0x0C,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.tsf,
            { "Fractional timestamp type", "vrt.context.gps.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x03,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.oui,
            { "Manufacturer OUI", "vrt.context.gps.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.ts_int,
            { "Integer timestamp of position fix", "vrt.context.gps.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.context.gps.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.ts_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.context.gps.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.lat,
            { "Latitude", "vrt.context.gps.lat",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.lon,
            { "Longitude", "vrt.context.gps.lon",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.alt,
            { "Altitude", "vrt.context.gps.alt",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.speed,
            { "Speed over ground", "vrt.context.gps.speed",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.heading,
            { "Heading angle", "vrt.context.gps.heading",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.track,
            { "Track angle", "vrt.context.gps.track",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps.mag_var,
            { "Magnetic variation", "vrt.context.gps.mag_var",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.tsi,
            { "Integer timestamp type", "vrt.context.ins.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0x0C,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.tsf,
            { "Fractional timestamp type", "vrt.context.ins.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x03,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.oui,
            { "Manufacturer OUI", "vrt.context.ins.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.ts_int,
            { "Integer timestamp of position fix", "vrt.context.ins.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.context.ins.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.ts_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.context.ins.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.lat,
            { "Latitude", "vrt.context.ins.lat",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.lon,
            { "Longitude", "vrt.context.ins.lon",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.alt,
            { "Altitude", "vrt.context.ins.alt",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.speed,
            { "Speed over ground", "vrt.context.ins.speed",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.heading,
            { "Heading angle", "vrt.context.ins.heading",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.track,
            { "Track angle", "vrt.context.ins.track",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ins.mag_var,
            { "Magnetic variation", "vrt.context.ins.mag_var",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.tsi,
            { "Integer timestamp type", "vrt.context.ecefephem.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0x0C,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.tsf,
            { "Fractional timestamp type", "vrt.context.ecefephem.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x03,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.oui,
            { "Manufacturer OUI", "vrt.context.ecefephem.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.ts_int,
            { "Integer timestamp of position fix", "vrt.context.ecefephem.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.context.ecefephem.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.ts_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.context.ecefephem.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.pos_x,
            { "Position X", "vrt.context.ecefephem.posx",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.pos_y,
            { "Position Y", "vrt.context.ecefephem.posy",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.pos_z,
            { "Position Z", "vrt.context.ecefephem.posz",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.att_alpha,
            { "Attitude alpha (α)", "vrt.context.ecefephem.attalpha",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.att_beta,
            { "Attitude beta (β)", "vrt.context.ecefephem.attbeta",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.att_phi,
            { "Attitude phi (φ)", "vrt.context.ecefephem.attphi",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.vel_dx,
            { "Velocity dX", "vrt.context.ecefephem.veldx",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.vel_dy,
            { "Velocity dY", "vrt.context.ecefephem.veldy",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ecef_ephemeris.vel_dz,
            { "Velocity dZ", "vrt.context.ecefephem.veldz",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.tsi,
            { "Integer timestamp type", "vrt.context.relephem.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0x0C,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.tsf,
            { "Fractional timestamp type", "vrt.context.relephem.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x03,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.oui,
            { "Manufacturer OUI", "vrt.context.relephem.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.ts_int,
            { "Integer timestamp of position fix", "vrt.context.relephem.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.context.relephem.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.ts_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.context.relephem.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.pos_x,
            { "Position X", "vrt.context.relephem.posx",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.pos_y,
            { "Position Y", "vrt.context.relephem.posy",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.pos_z,
            { "Position Z", "vrt.context.relephem.posz",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meter), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.att_alpha,
            { "Attitude alpha (α)", "vrt.context.relephem.attalpha",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.att_beta,
            { "Attitude beta (β)", "vrt.context.relephem.attbeta",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.att_phi,
            { "Attitude phi (φ)", "vrt.context.relephem.attphi",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_degrees), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.vel_dx,
            { "Velocity dX", "vrt.context.relephem.veldx",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.vel_dy,
            { "Velocity dY", "vrt.context.relephem.veldy",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_rel_ephemeris.vel_dz,
            { "Velocity dZ", "vrt.context.relephem.veldz",
            FT_INT32, BASE_CUSTOM,
            CF_FUNC(format_meters_per_second), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ephemeris_ref_id,
            { "Ephemeris reference identifier", "vrt.context.ephemrefid",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps_ascii_oui,
            { "Manufacturer OUI", "vrt.context.gpsascii.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps_ascii_size,
            { "Number of words", "vrt.context.gpsascii.size",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_gps_ascii_data,
            { "Data", "vrt.context.gpsascii.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_src_size,
            { "Source list size", "vrt.context.assoclists.src.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x01FF,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_sys_size,
            { "System list size", "vrt.context.assoclists.sys.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x01FF,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_vec_size,
            { "Vector-component list size", "vrt.context.assoclists.vec.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_a,
            { "A bit (asynchronous-channel tag list present)", "vrt.context.assoclists.a",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_asy_size,
            { "Asynchronous-channel list size", "vrt.context.assoclists.asy.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_src_data,
            { "Source context association list", "vrt.context.assoclists.src.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_sys_data,
            { "System context association list", "vrt.context.assoclists.sys.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_vec_data,
            { "Vector-component context association list", "vrt.context.assoclists.vec.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_asy_data,
            { "Asynchronous-channel context association list", "vrt.context.assoclists.asy.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_assoc_lists_asy_tag_data,
            { "Asynchronous-channel tag list", "vrt.context.assoclists.asy.tagdata",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_phase_offset,
            { "Phase offset", "vrt.context.phaseoffset",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_radian_phase), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_pol_tilt,
            { "Tilt angle (θ)", "vrt.context.polarization.tilt",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_radian_pol), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_pol_ellipticity,
            { "Ellipticity angle (χ)", "vrt.context.polarization.ellipticity",
            FT_INT16, BASE_CUSTOM,
            CF_FUNC(format_radian_pol), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_range,
            { "Range (distance)", "vrt.context.range",
            FT_UINT32, BASE_CUSTOM,
            CF_FUNC(format_meter_unsigned), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_aux_freq,
            { "Aux frequency", "vrt.context.auxfreq",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_aux_bandwidth,
            { "Aux bandwidth", "vrt.context.auxbw",
            FT_INT64, BASE_CUSTOM,
            CF_FUNC(format_hertz), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_io32,
            { "Discrete I/O (32-bit)", "vrt.context.io32",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_io64,
            { "Discrete I/O (64-bit)", "vrt.context.io64",
            FT_UINT64, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_v49_spec,
            { "V49 spec compliance", "vrt.context.v49spec",
            FT_UINT32, BASE_HEX,
            VALS(standard_version_codes), 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ver_year,
            { "Year", "vrt.context.ver.year",
            FT_UINT16, BASE_DEC,
            NULL, 0xFE00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ver_day,
            { "Day", "vrt.context.ver.day",
            FT_UINT16, BASE_DEC,
            NULL, 0x01FF,
            NULL, HFILL }
        },
        { &hf_vrt_context_ver_rev,
            { "Revision", "vrt.context.ver.rev",
            FT_UINT16, BASE_DEC,
            NULL, 0xFC00,
            NULL, HFILL }
        },
        { &hf_vrt_context_ver_user,
            { "User defined", "vrt.context.ver.user",
            FT_UINT16, BASE_DEC,
            NULL, 0x03FF,
            NULL, HFILL }
        },
        { &hf_vrt_data,
            { "Data", "vrt.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer,
            { "Trailer", "vrt.trailer",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_enables,
            { "Indicator enable bits", "vrt.enables",
            FT_UINT16, BASE_HEX,
            NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind,
            { "Indicator bits", "vrt.indicators",
            FT_UINT16, BASE_HEX,
            NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_e,
            { "Associated context packet count enabled", "vrt.e",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_acpc,
            { "Associated context packet count", "vrt.acpc",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_caltime,
            { "Calibrated time indicator", "vrt.caltime",
            FT_BOOLEAN, 16,
            NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_valid,
            { "Valid signal indicator", "vrt.valid",
            FT_BOOLEAN, 16,
            NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_reflock,
            { "Reference lock indicator", "vrt.reflock",
            FT_BOOLEAN, 16,
            NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_agc,
            { "AGC/MGC indicator", "vrt.agc",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_sig,
            { "Signal detected indicator", "vrt.sig",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_inv,
            { "Spectral inversion indicator", "vrt.inv",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_overrng,
            { "Overrange indicator", "vrt.overrng",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_sampleloss,
            { "Lost sample indicator", "vrt.sampleloss",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user0,
            { "User indicator 0", "vrt.user0",
            FT_BOOLEAN, 16,
            NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user1,
            { "User indicator 1", "vrt.user1",
            FT_BOOLEAN, 16,
            NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user2,
            { "User indicator 2", "vrt.user2",
            FT_BOOLEAN, 16,
            NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user3,
            { "User indicator 3", "vrt.user3",
            FT_BOOLEAN, 16,
            NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_caltime,
            { "Calibrated time indicator enable", "vrt.caltime_en",
            FT_BOOLEAN, 16,
            NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_valid,
            { "Valid signal indicator enable", "vrt.valid_en",
            FT_BOOLEAN, 16,
            NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_reflock,
            { "Reference lock indicator enable", "vrt.reflock_en",
            FT_BOOLEAN, 16,
            NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_agc,
            { "AGC/MGC indicator enable", "vrt.agc_en",
            FT_BOOLEAN, 16,
            NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_sig,
            { "Signal detected indicator enable", "vrt.sig_en",
            FT_BOOLEAN, 16,
            NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_inv,
            { "Spectral inversion indicator enable", "vrt.inv_en",
            FT_BOOLEAN, 16,
            NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_overrng,
            { "Overrange indicator enable", "vrt.overrng_en",
            FT_BOOLEAN, 16,
            NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_sampleloss,
            { "Lost sample indicator enable", "vrt.sampleloss_en",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user0,
            { "User indicator 0 enable", "vrt.user0_en",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user1,
            { "User indicator 1 enable", "vrt.user1_en",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user2,
            { "User indicator 2 enable", "vrt.user2_en",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user3,
            { "User indicator 3 enable", "vrt.user3_en",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_vrt_cid_oui,
            { "Class ID Organizationally Unique ID", "vrt.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid_icc,
            { "Class ID Information Class Code", "vrt.icc",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid_pcc,
            { "Class ID Packet Class Code", "vrt.pcc",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    // update ETT_IDX_* as new items added to track indices
    static int *ett[] = {
        &ett_vrt,
        &ett_header,
        &ett_trailer,
        &ett_indicators,
        &ett_ind_enables,
        &ett_cid,
        &ett_cif0,
        &ett_cif1,
        &ett_gain, // ETT_IDX_GAIN
        &ett_device_id,  // ETT_IDX_DEVICE_ID
        &ett_state_event, // ETT_IDX_STATE_EVENT
        &ett_signal_data_format, // ETT_IDX_SIGNAL_DATA_FORMAT
        &ett_gps, // ETT_IDX_GPS
        &ett_ins, // ETT_IDX_INS
        &ett_ecef_ephem, // ETT_IDX_ECEF_EPHEM
        &ett_rel_ephem, // ETT_IDX_REL_EPHEM
        &ett_gps_ascii, // ETT_IDX_GPS_ASCII
        &ett_assoc_lists, // ETT_IDX_ASSOC_LISTS
        &ett_pol, // ETT_IDX_POL
        &ett_ver, // ETT_IDX_VER
     };

    proto_vrt = proto_register_protocol ("VITA 49 radio transport protocol", "VITA 49", "vrt");

    proto_register_field_array(proto_vrt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vrt_handle = register_dissector("vrt", dissect_vrt, proto_vrt);

    vrt_module = prefs_register_protocol(proto_vrt, NULL);
    prefs_register_bool_preference(vrt_module, "ettus_uhd_header_format",
        "Use Ettus UHD header format",
        "Activate workaround for weird Ettus UHD header offset on data packets",
        &vrt_use_ettus_uhd_header_format);
}

void
proto_reg_handoff_vrt(void)
{
    dissector_add_uint_with_preference("udp.port", VITA_49_PORT, vrt_handle);

    dissector_add_string("rtp_dyn_payload_type","VITA 49", vrt_handle);
    dissector_add_uint_range_with_preference("rtp.pt", "", vrt_handle);
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
