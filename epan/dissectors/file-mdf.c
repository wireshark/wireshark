/* file-mdf.c
 * ASAM MDF File Format.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2022-2026 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This dissector allows to parse MDF (MF4) files.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#define MDF_LEN_IDBLOCK 64
#define MDF_BLOCK_HDR_LEN 24

#define MDF_LEN_MAGIC 8
static const uint8_t mdf_magic_fin[MDF_LEN_MAGIC] = { 'M', 'D', 'F', ' ', ' ', ' ', ' ', ' ' };
static const uint8_t mdf_magic_unf[MDF_LEN_MAGIC] = { 'U', 'n', 'F', 'i', 'n', 'M', 'F', ' ' };

#define MDF_BLOCK_ID_AT_ATTACHMENT          0x23234154
#define MDF_BLOCK_ID_CA_CHANNEL_ARRAY       0x23234341
#define MDF_BLOCK_ID_CC_CONVERSION          0x23234343
#define MDF_BLOCK_ID_CG_CHANNEL_GROUP       0x23234347
#define MDF_BLOCK_ID_CH_CHANNEL_HIERARCHY   0x23234348
#define MDF_BLOCK_ID_CL_CHANNEL_LIST        0x2323434c
#define MDF_BLOCK_ID_CN_CHANNEL             0x2323434e
#define MDF_BLOCK_ID_CU_CHANNEL_UNION       0x23234355
#define MDF_BLOCK_ID_CV_CHANNEL_VARIANT     0x23234356
#define MDF_BLOCK_ID_DG_DATA_GROUP          0x23234447
#define MDF_BLOCK_ID_DI_DATA_INVALIDATION   0x23234449
#define MDF_BLOCK_ID_DL_DATA_LIST           0x2323444c
#define MDF_BLOCK_ID_DS_DATA_STREAM         0x23234453
#define MDF_BLOCK_ID_DT_DATA                0x23234454
#define MDF_BLOCK_ID_DV_DATA_VALUES         0x23234456
#define MDF_BLOCK_ID_DZ_DATA_ZIPPED         0x2323445A
#define MDF_BLOCK_ID_EV_EVENT               0x23234556
#define MDF_BLOCK_ID_FH_FILE_HEADER         0x23234648
#define MDF_BLOCK_ID_GD_GUARD               0x23234744
#define MDF_BLOCK_ID_HD_HEADER              0x23234844
#define MDF_BLOCK_ID_HL_HEADER_LIST         0x2323484c
#define MDF_BLOCK_ID_LD_LIST_DATA           0x23234c44
#define MDF_BLOCK_ID_MD_META_DATA           0x23234d44
#define MDF_BLOCK_ID_RD_REDUCTION_DATA      0x23235244
#define MDF_BLOCK_ID_RI_REDUCTION_INVAL     0x23235249
#define MDF_BLOCK_ID_RV_REDUCTION_VALUES    0x23235256
#define MDF_BLOCK_ID_SD_SIGNAL_DATA         0x23235344
#define MDF_BLOCK_ID_SI_SOURCE_INFO         0x23235349
#define MDF_BLOCK_ID_SR_SAMPLE_REDUCTION    0x23235352
#define MDF_BLOCK_ID_VD_VLSC_DATA           0x23235644
#define MDF_BLOCK_ID_TX_TEXT                0x23235458

#define MDF_AT_FLAGS_EMBEDDED               0x0001
#define MDF_AT_FLAGS_COMPRESSED             0x0002
#define MDF_AT_FLAGS_GENERAL_ZIP            0x0008
#define MDF_AT_FLAGS_ZIP_FILENAME           0x0010
#define MDF_AT_FLAGS_ZIP_MIMETYPE           0x0020
#define MDF_CG_FLAGS_REMOTE_MASTER          0x0008
#define MDF_CN_TYPE_VLSC                    7

#define MDF_DZ_ZIP_DEFLATE                  0
#define MDF_DZ_ZIP_TRANSPOSITION_DEFLATE    1

#define MDF_CC_FIXED_LINKS                  4
#define MDF_CC_FIXED_DATA_LEN               24

/* Upper bound for the size of a decompressed DZ block we are willing to create. */
#define MDF_DZ_MAX_UNCOMPRESSED_LEN         (256U * 1024U * 1024U)

#define MDF_CN_DATA_OFFSET_FLAGS            12
#define MDF_CN_DATA_OFFSET_ATTACHMENT_COUNT 22
#define MDF_CN_FLAGS_DEFAULT_X              0x00001000

static int proto_mdf;

static expert_field ei_mdf_block_malformed;
static expert_field ei_mdf_too_few_links;
static expert_field ei_mdf_link_invalid;
static expert_field ei_mdf_cc_val_count;
static expert_field ei_mdf_list_count;
static dissector_table_t media_type_table;

static expert_field ei_mdf_dz_decompress_failed;
static expert_field ei_mdf_dz_length_mismatch;
static expert_field ei_mdf_dz_unsupported;

static int hf_mdf_id;
static int hf_mdf_id_file;
static int hf_mdf_id_vers;
static int hf_mdf_id_prog;
static int hf_mdf_id_res1;
static int hf_mdf_id_ver;
static int hf_mdf_id_res2;
static int hf_mdf_id_unfin_flg;
static int hf_mdf_id_cstom_flg;

static int hf_mdf_block_header;
static int hf_mdf_block_id;
static int hf_mdf_block_res;
static int hf_mdf_block_length;
static int hf_mdf_block_link_cnt;
static int hf_mdf_block_links;
static int hf_mdf_block_link;
static int hf_mdf_block_data;


static int hf_mdf_at;
static int hf_mdf_at_next;
static int hf_mdf_at_tx_filename;
static int hf_mdf_at_tx_mimetype;
static int hf_mdf_at_tx_comment;
static int hf_mdf_at_flags;
static int hf_mdf_at_creator_index;
static int hf_mdf_at_tx_filename_zip;
static int hf_mdf_at_tx_mimetype_zip;
static int hf_mdf_at_zip_type;
static int hf_mdf_at_path_syntax;
static int hf_mdf_at_reserved;
static int hf_mdf_at_md5_checksum;
static int hf_mdf_at_original_size;
static int hf_mdf_at_embedded_size;
static int hf_mdf_at_embedded_data;
static int hf_mdf_at_uncompressed;

static int hf_mdf_cn;
static int hf_mdf_cn_next;
static int hf_mdf_cn_composition;
static int hf_mdf_cn_tx_name;
static int hf_mdf_cn_si_source;
static int hf_mdf_cn_cc_conversion;
static int hf_mdf_cn_data;
static int hf_mdf_cn_md_unit;
static int hf_mdf_cn_md_comment;
static int hf_mdf_cn_at_reference;
static int hf_mdf_cn_default_x;
static int hf_mdf_cn_type;
static int hf_mdf_cn_sync_type;
static int hf_mdf_cn_data_type;
static int hf_mdf_cn_bit_offset;
static int hf_mdf_cn_byte_offset;
static int hf_mdf_cn_bit_count;
static int hf_mdf_cn_flags;
static int hf_mdf_cn_inval_bit_pos;
static int hf_mdf_cn_precision;
static int hf_mdf_cn_cn_size;
static int hf_mdf_cn_alignment;
static int hf_mdf_cn_attachment_count;
static int hf_mdf_cn_val_range_min;
static int hf_mdf_cn_val_range_max;
static int hf_mdf_cn_limit_min;
static int hf_mdf_cn_limit_max;
static int hf_mdf_cn_limit_ext_min;
static int hf_mdf_cn_limit_ext_max;

static int hf_mdf_cg;
static int hf_mdf_cg_next;
static int hf_mdf_cg_cn_first;
static int hf_mdf_cg_tx_acq_name;
static int hf_mdf_cg_si_acq_source;
static int hf_mdf_cg_sr_first;
static int hf_mdf_cg_md_comment;
static int hf_mdf_cg_cg_master;
static int hf_mdf_cg_record_id;
static int hf_mdf_cg_cycle_count;
static int hf_mdf_cg_flags;
static int hf_mdf_cg_path_separator;
static int hf_mdf_cg_reserved;
static int hf_mdf_cg_data_bytes;
static int hf_mdf_cg_inval_bytes;

static int hf_mdf_cc;
static int hf_mdf_cc_tx_name;
static int hf_mdf_cc_md_unit;
static int hf_mdf_cc_md_comment;
static int hf_mdf_cc_cc_inverse;
static int hf_mdf_cc_cc_ref;
static int hf_mdf_cc_type;
static int hf_mdf_cc_precision;
static int hf_mdf_cc_flags;
static int hf_mdf_cc_ref_count;
static int hf_mdf_cc_val_count;
static int hf_mdf_cc_phy_range_min;
static int hf_mdf_cc_phy_range_max;
static int hf_mdf_cc_val;

static int hf_mdf_dg;
static int hf_mdf_dg_next;
static int hf_mdf_dg_cg_first;
static int hf_mdf_dg_data;
static int hf_mdf_dg_md_comment;
static int hf_mdf_dg_rec_id_size;
static int hf_mdf_dg_reserved;

static int hf_mdf_dl;
static int hf_mdf_dl_next;
static int hf_mdf_dl_data_link;
static int hf_mdf_dl_flags;
static int hf_mdf_dl_reserved;
static int hf_mdf_dl_count;
static int hf_mdf_dl_equal_length;
static int hf_mdf_dl_offset;
static int hf_mdf_dl_time_value;
static int hf_mdf_dl_angle_value;
static int hf_mdf_dl_distance_value;

static int hf_mdf_hl;
static int hf_mdf_hl_dl_first;
static int hf_mdf_hl_flags;
static int hf_mdf_hl_zip_type;
static int hf_mdf_hl_reserved;

static int hf_mdf_ld;
static int hf_mdf_ld_next;
static int hf_mdf_ld_data_link;
static int hf_mdf_ld_inval_link;
static int hf_mdf_ld_flags;
static int hf_mdf_ld_count;
static int hf_mdf_ld_equal_sample_count;
static int hf_mdf_ld_sample_offset;
static int hf_mdf_ld_time_value;
static int hf_mdf_ld_angle_value;
static int hf_mdf_ld_distance_value;

static int hf_mdf_sd;
static int hf_mdf_sd_data;

static int hf_mdf_rd;
static int hf_mdf_rd_data;

static int hf_mdf_ca;
static int hf_mdf_ca_composition;
static int hf_mdf_ca_data;
static int hf_mdf_ca_dynamic_size;
static int hf_mdf_ca_input_quantity;
static int hf_mdf_ca_output_quantity;
static int hf_mdf_ca_comparison_quantity;
static int hf_mdf_ca_cc_axis_conversion;
static int hf_mdf_ca_axis_link;
static int hf_mdf_ca_type;
static int hf_mdf_ca_storage;
static int hf_mdf_ca_ndim;
static int hf_mdf_ca_flags;
static int hf_mdf_ca_byte_offset_base;
static int hf_mdf_ca_inval_bit_pos_base;
static int hf_mdf_ca_dim_size;
static int hf_mdf_ca_axis_value;
static int hf_mdf_ca_cycle_count;
static int hf_mdf_ca_flags_dynamic_size;
static int hf_mdf_ca_flags_input_quantity;
static int hf_mdf_ca_flags_output_quantity;
static int hf_mdf_ca_flags_comparison_quantity;
static int hf_mdf_ca_flags_axis;
static int hf_mdf_ca_flags_fixed_axis;
static int hf_mdf_ca_flags_inverse_layout;
static int hf_mdf_ca_flags_left_open;
static int hf_mdf_ch;
static int hf_mdf_ch_next;
static int hf_mdf_ch_first;
static int hf_mdf_ch_tx_name;
static int hf_mdf_ch_md_comment;
static int hf_mdf_ch_dg;
static int hf_mdf_ch_cg;
static int hf_mdf_ch_cn;
static int hf_mdf_ch_element_count;
static int hf_mdf_ch_type;
static int hf_mdf_ch_reserved;
static int hf_mdf_ev;
static int hf_mdf_ev_next;
static int hf_mdf_ev_parent;
static int hf_mdf_ev_range;
static int hf_mdf_ev_tx_name;
static int hf_mdf_ev_md_comment;
static int hf_mdf_ev_scope;
static int hf_mdf_ev_at_reference;
static int hf_mdf_ev_type;
static int hf_mdf_ev_sync_type;
static int hf_mdf_ev_range_type;
static int hf_mdf_ev_cause;
static int hf_mdf_ev_flags;
static int hf_mdf_ev_flags_post_processing;
static int hf_mdf_ev_reserved;
static int hf_mdf_ev_scope_count;
static int hf_mdf_ev_attachment_count;
static int hf_mdf_ev_creator_index;
static int hf_mdf_ev_sync_base_value;
static int hf_mdf_ev_sync_factor;
static int hf_mdf_sr;
static int hf_mdf_sr_next;
static int hf_mdf_sr_data;
static int hf_mdf_sr_cycle_count;
static int hf_mdf_sr_interval;
static int hf_mdf_sr_sync_type;
static int hf_mdf_sr_flags;
static int hf_mdf_sr_flags_inval_bytes;
static int hf_mdf_sr_flags_dominant_inval;
static int hf_mdf_sr_reserved;

static int hf_mdf_di;
static int hf_mdf_di_data;

static int hf_mdf_dv;
static int hf_mdf_dv_data;

static int hf_mdf_cl;
static int hf_mdf_cl_composition;
static int hf_mdf_cl_cn_size;
static int hf_mdf_cl_flags;
static int hf_mdf_cl_flags_size_is_count;
static int hf_mdf_cl_flags_alignment_reset;
static int hf_mdf_cl_alignment;
static int hf_mdf_cl_bit_offset;
static int hf_mdf_cl_byte_offset;
static int hf_mdf_cu;
static int hf_mdf_cu_cn_member;
static int hf_mdf_cu_member_count;
static int hf_mdf_cu_reserved;
static int hf_mdf_cv;
static int hf_mdf_cv_cn_discriminator;
static int hf_mdf_cv_cn_option;
static int hf_mdf_cv_option_count;
static int hf_mdf_cv_reserved;
static int hf_mdf_cv_option_val;
static int hf_mdf_ds;
static int hf_mdf_ds_cn_composition;
static int hf_mdf_ds_cn_alignment_start;
static int hf_mdf_ds_version;
static int hf_mdf_ds_mode;
static int hf_mdf_ds_reserved;
static int hf_mdf_gd;
static int hf_mdf_gd_link;
static int hf_mdf_gd_version;
static int hf_mdf_gd_reserved;
static int hf_mdf_ri;
static int hf_mdf_ri_data;
static int hf_mdf_rv;
static int hf_mdf_rv_data;
static int hf_mdf_vd;
static int hf_mdf_vd_data;
static int hf_mdf_ld_zip_info;
static int hf_mdf_ld_zip_info_inval;
static int hf_mdf_ld_flags_ext;
static int hf_mdf_ld_flags_zip_info_valid;
static int hf_mdf_ld_flags_ext_inval_data;
static int hf_mdf_ev_tx_group_name;
static int hf_mdf_ev_flags_group_name;

static int hf_mdf_dt;
static int hf_mdf_dt_data;

static int hf_mdf_dz;
static int hf_mdf_dz_org_block_type;
static int hf_mdf_dz_zip_type;
static int hf_mdf_dz_reserved;
static int hf_mdf_dz_zip_parameter;
static int hf_mdf_dz_org_data_length;
static int hf_mdf_dz_data_length;
static int hf_mdf_dz_data;
static int hf_mdf_dz_uncompressed;

static int hf_mdf_fh;
static int hf_mdf_fh_next;
static int hf_mdf_fh_comment;
static int hf_mdf_fh_time_ns;
static int hf_mdf_fh_tz_offset_min;
static int hf_mdf_fh_dst_offset_min;
static int hf_mdf_fh_time_flags;
static int hf_mdf_fh_reserved;

static int hf_mdf_hd;
static int hf_mdf_hd_dg_first;
static int hf_mdf_hd_fh_first;
static int hf_mdf_hd_ch_first;
static int hf_mdf_hd_at_first;
static int hf_mdf_hd_ev_first;
static int hf_mdf_hd_md_comment;
static int hf_mdf_hd_start_time_ns;
static int hf_mdf_hd_tz_offset_min;
static int hf_mdf_hd_dst_offset_min;
static int hf_mdf_hd_time_flags;
static int hf_mdf_hd_time_class;
static int hf_mdf_hd_flags;
static int hf_mdf_hd_reserved;
static int hf_mdf_hd_start_angle_rad;
static int hf_mdf_hd_start_distance_m;

static int hf_mdf_md;
static int hf_mdf_md_data;

static int hf_mdf_si;
static int hf_mdf_si_tx_name;
static int hf_mdf_si_tx_path;
static int hf_mdf_si_md_comment;
static int hf_mdf_si_type;
static int hf_mdf_si_bus_type;
static int hf_mdf_si_flags;
static int hf_mdf_si_reserved;

static int hf_mdf_tx;
static int hf_mdf_tx_data;

static int hf_mdf_unknown_block;

static int hf_mdf_at_flags_embedded;
static int hf_mdf_at_flags_compressed;
static int hf_mdf_at_flags_md5_valid;
static int hf_mdf_at_flags_general_zip;
static int hf_mdf_at_flags_zip_filename;
static int hf_mdf_at_flags_zip_mimetype;
static int hf_mdf_cc_flags_precision_valid;
static int hf_mdf_cc_flags_range_valid;
static int hf_mdf_cc_flags_status_string;
static int hf_mdf_dl_flags_equal_length;
static int hf_mdf_dl_flags_time_values;
static int hf_mdf_dl_flags_angle_values;
static int hf_mdf_dl_flags_distance_values;
static int hf_mdf_hl_flags_equal_length;
static int hf_mdf_hl_flags_time_values;
static int hf_mdf_hl_flags_angle_values;
static int hf_mdf_hl_flags_distance_values;
static int hf_mdf_ld_flags_equal_length;
static int hf_mdf_ld_flags_time_values;
static int hf_mdf_ld_flags_angle_values;
static int hf_mdf_ld_flags_distance_values;
static int hf_mdf_cg_flags_vlsd;
static int hf_mdf_cg_flags_bus_event;
static int hf_mdf_cg_flags_plain_bus_event;
static int hf_mdf_cg_flags_remote_master;
static int hf_mdf_cg_flags_event_signal;
static int hf_mdf_cg_flags_vlsc;
static int hf_mdf_cg_flags_raw_sensor_event;
static int hf_mdf_cg_flags_protocol_event;
static int hf_mdf_cn_flags_all_inval;
static int hf_mdf_cn_flags_inval_bit_valid;
static int hf_mdf_cn_flags_precision_valid;
static int hf_mdf_cn_flags_val_range_valid;
static int hf_mdf_cn_flags_limit_valid;
static int hf_mdf_cn_flags_limit_ext_valid;
static int hf_mdf_cn_flags_discrete;
static int hf_mdf_cn_flags_calibration;
static int hf_mdf_cn_flags_calculated;
static int hf_mdf_cn_flags_virtual;
static int hf_mdf_cn_flags_bus_event;
static int hf_mdf_cn_flags_monotonous;
static int hf_mdf_cn_flags_default_x;
static int hf_mdf_cn_flags_event_signal;
static int hf_mdf_cn_flags_vlsd_stream;
static int hf_mdf_cn_flags_raw_sensor_event;
static int hf_mdf_cn_flags_auxiliary;
static int hf_mdf_cn_flags_data_stream_mode;
static int hf_mdf_cn_flags_alignment_reset;
static int hf_mdf_cn_flags_protocol_event;
static int hf_mdf_cn_flags_data_description_mode;
static int hf_mdf_fh_time_flags_local_time;
static int hf_mdf_fh_time_flags_offsets_valid;
static int hf_mdf_hd_time_flags_local_time;
static int hf_mdf_hd_time_flags_offsets_valid;
static int hf_mdf_hd_flags_angle_valid;
static int hf_mdf_hd_flags_distance_valid;
static int hf_mdf_si_flags_simulated;

static int ett_mdf;
static int ett_mdf_block_header;
static int ett_mdf_block_links;
static int ett_mdf_block_data;
static int ett_mdf_block_id;
static int ett_mdf_block_at;
static int ett_mdf_block_cc;
static int ett_mdf_block_cg;
static int ett_mdf_block_cn;
static int ett_mdf_block_dg;
static int ett_mdf_block_dl;
static int ett_mdf_block_hl;
static int ett_mdf_block_ld;
static int ett_mdf_block_sd;
static int ett_mdf_block_rd;
static int ett_mdf_block_ca;
static int ett_mdf_block_ch;
static int ett_mdf_block_ev;
static int ett_mdf_block_sr;
static int ett_mdf_block_di;
static int ett_mdf_block_dv;
static int ett_mdf_block_cl;
static int ett_mdf_block_cu;
static int ett_mdf_block_cv;
static int ett_mdf_block_ds;
static int ett_mdf_block_gd;
static int ett_mdf_block_ri;
static int ett_mdf_block_rv;
static int ett_mdf_block_vd;
static int ett_mdf_cl_flags;
static int ett_mdf_ld_flags_ext;
static int ett_mdf_block_dt;
static int ett_mdf_block_dz;
static int ett_mdf_block_fh;
static int ett_mdf_block_hd;
static int ett_mdf_block_md;
static int ett_mdf_block_si;
static int ett_mdf_block_tx;
static int ett_mdf_unknownblock;
static int ett_mdf_at_flags;
static int ett_mdf_cc_flags;
static int ett_mdf_ca_flags;
static int ett_mdf_ev_flags;
static int ett_mdf_sr_flags;
static int ett_mdf_dl_flags;
static int ett_mdf_hl_flags;
static int ett_mdf_ld_flags;
static int ett_mdf_cg_flags;
static int ett_mdf_cn_flags;
static int ett_mdf_fh_time_flags;
static int ett_mdf_hd_time_flags;
static int ett_mdf_hd_flags;
static int ett_mdf_si_flags;


void proto_register_file_mdf(void);
void proto_reg_handoff_file_mdf(void);


static const value_string mdf_block_cn_type[] = {
    {0, "Fixed Length Data Channel"},
    {1, "Variable Length Data Channel or VLSD"},
    {2, "Master Channel for all Signals of this Group"},
    {3, "Virtual Master Channel"},
    {4, "Synchronization Channel"},
    {5, "Maximum Length Data Channel"},
    {6, "Virtual Data Channel"},
    {7, "Variable Length Data Channel with Size Channel (VLSC)"},
    {0, NULL}
};

static const value_string mdf_block_cc_type[] = {
    {0, "1:1 Conversion (Identity)"},
    {1, "Linear Conversion"},
    {2, "Rational Conversion"},
    {3, "Algebraic Conversion"},
    {4, "Value to Value with Interpolation"},
    {5, "Value to Value without Interpolation"},
    {6, "Value Range to Value"},
    {7, "Value to Text/Scale Conversion"},
    {8, "Value Range to Text/Scale Conversion"},
    {9, "Text to Value"},
    {10, "Text to Text"},
    {11, "Bitfield Text Table"},
    {0, NULL}
};

static const value_string mdf_block_ld_zip_info[] = {
    {0, "Deflate"},
    {1, "Transposition + Deflate"},
    {2, "ZStd"},
    {3, "Transposition + ZStd"},
    {255, "No compression"},
    {0, NULL}
};

static const value_string mdf_block_ds_mode[] = {
    {0, "Data Stream Mode"},
    {1, "Data Description Mode"},
    {0, NULL}
};

static const value_string mdf_block_ca_type[] = {
    {0, "Array"},
    {1, "Scaling Axis"},
    {2, "Look-Up"},
    {3, "Interval Axis"},
    {4, "Classification Result"},
    {0, NULL}
};

static const value_string mdf_block_ca_storage[] = {
    {0, "CN Template"},
    {1, "CG Template"},
    {2, "DG Template"},
    {0, NULL}
};

static const value_string mdf_block_ch_type[] = {
    {0, "Group"},
    {1, "Function"},
    {2, "Structure"},
    {3, "Map List"},
    {4, "Input Variables of Function"},
    {5, "Output Variables of Function"},
    {6, "Local Variables of Function"},
    {7, "Calibration Objects Defined in Function"},
    {8, "Calibration Objects Referenced in Function"},
    {0, NULL}
};

static const value_string mdf_block_ev_type[] = {
    {0, "Recording"},
    {1, "Recording Interrupt"},
    {2, "Acquisition Interrupt"},
    {3, "Start Recording Trigger"},
    {4, "Stop Recording Trigger"},
    {5, "Trigger"},
    {6, "Marker"},
    {0, NULL}
};

static const value_string mdf_block_sync_type[] = {
    {1, "Time (s)"},
    {2, "Angle (rad)"},
    {3, "Distance (m)"},
    {4, "Index"},
    {0, NULL}
};

static const value_string mdf_block_ev_range_type[] = {
    {0, "Point"},
    {1, "Range"},
    {2, "Range Start"},
    {3, "Range End"},
    {0, NULL}
};

static const value_string mdf_block_ev_cause[] = {
    {0, "Other"},
    {1, "Error"},
    {2, "Tool"},
    {3, "Script"},
    {4, "User"},
    {0, NULL}
};

static const value_string mdf_block_dz_zip_type[] = {
    {0, "Deflate"},
    {1, "Transposition + Deflate"},
    {2, "ZStd"},
    {3, "Transposition + ZStd"},
    {0, NULL}
};

static const value_string mdf_block_at_zip_type[] = {
    {0, "Deflate"},
    {2, "ZStd"},
    {4, "LZ4"},
    {254, "Custom compression"},
    {0, NULL}
};

static const value_string mdf_block_at_path_syntax[] = {
    {0, "Unspecified"},
    {1, "Windows"},
    {2, "Unix"},
    {3, "URI"},
    {0, NULL}
};

static const value_string mdf_block_si_type[] = {
    {0, "OTHER"},
    {1, "ECU"},
    {2, "BUS"},
    {3, "I/O"},
    {4, "TOOL"},
    {5, "USER"},
    {6, "VIDEO"},
    {7, "RADAR"},
    {8, "LIDAR"},
    {9, "PROTOCOL"},
    {0, NULL}
};

static const value_string mdf_block_si_bus_type[] = {
    {0, "NONE"},
    {1, "OTHER"},
    {2, "CAN"},
    {3, "LIN"},
    {4, "MOST"},
    {5, "FLEXRAY"},
    {6, "K_LINE"},
    {7, "ETHERNET"},
    {8, "USB"},
    {0, NULL}
};


static int * const mdf_at_flags[] = {
    &hf_mdf_at_flags_embedded,
    &hf_mdf_at_flags_compressed,
    &hf_mdf_at_flags_md5_valid,
    &hf_mdf_at_flags_general_zip,
    &hf_mdf_at_flags_zip_filename,
    &hf_mdf_at_flags_zip_mimetype,
    NULL
};

static int * const mdf_cc_flags[] = {
    &hf_mdf_cc_flags_precision_valid,
    &hf_mdf_cc_flags_range_valid,
    &hf_mdf_cc_flags_status_string,
    NULL
};

static int * const mdf_dl_flags[] = {
    &hf_mdf_dl_flags_equal_length,
    &hf_mdf_dl_flags_time_values,
    &hf_mdf_dl_flags_angle_values,
    &hf_mdf_dl_flags_distance_values,
    NULL
};

static int * const mdf_hl_flags[] = {
    &hf_mdf_hl_flags_equal_length,
    &hf_mdf_hl_flags_time_values,
    &hf_mdf_hl_flags_angle_values,
    &hf_mdf_hl_flags_distance_values,
    NULL
};

static int * const mdf_ld_flags[] = {
    &hf_mdf_ld_flags_equal_length,
    &hf_mdf_ld_flags_time_values,
    &hf_mdf_ld_flags_angle_values,
    &hf_mdf_ld_flags_distance_values,
    &hf_mdf_ld_flags_zip_info_valid,
    NULL
};

static int * const mdf_ld_flags_ext[] = {
    &hf_mdf_ld_flags_ext_inval_data,
    NULL
};

static int * const mdf_cl_flags[] = {
    &hf_mdf_cl_flags_size_is_count,
    &hf_mdf_cl_flags_alignment_reset,
    NULL
};

static int * const mdf_ca_flags[] = {
    &hf_mdf_ca_flags_dynamic_size,
    &hf_mdf_ca_flags_input_quantity,
    &hf_mdf_ca_flags_output_quantity,
    &hf_mdf_ca_flags_comparison_quantity,
    &hf_mdf_ca_flags_axis,
    &hf_mdf_ca_flags_fixed_axis,
    &hf_mdf_ca_flags_inverse_layout,
    &hf_mdf_ca_flags_left_open,
    NULL
};

static int * const mdf_ev_flags[] = {
    &hf_mdf_ev_flags_post_processing,
    &hf_mdf_ev_flags_group_name,
    NULL
};

static int * const mdf_sr_flags[] = {
    &hf_mdf_sr_flags_inval_bytes,
    &hf_mdf_sr_flags_dominant_inval,
    NULL
};

static int * const mdf_cg_flags[] = {
    &hf_mdf_cg_flags_vlsd,
    &hf_mdf_cg_flags_bus_event,
    &hf_mdf_cg_flags_plain_bus_event,
    &hf_mdf_cg_flags_remote_master,
    &hf_mdf_cg_flags_event_signal,
    &hf_mdf_cg_flags_vlsc,
    &hf_mdf_cg_flags_raw_sensor_event,
    &hf_mdf_cg_flags_protocol_event,
    NULL
};

static int * const mdf_cn_flags[] = {
    &hf_mdf_cn_flags_all_inval,
    &hf_mdf_cn_flags_inval_bit_valid,
    &hf_mdf_cn_flags_precision_valid,
    &hf_mdf_cn_flags_val_range_valid,
    &hf_mdf_cn_flags_limit_valid,
    &hf_mdf_cn_flags_limit_ext_valid,
    &hf_mdf_cn_flags_discrete,
    &hf_mdf_cn_flags_calibration,
    &hf_mdf_cn_flags_calculated,
    &hf_mdf_cn_flags_virtual,
    &hf_mdf_cn_flags_bus_event,
    &hf_mdf_cn_flags_monotonous,
    &hf_mdf_cn_flags_default_x,
    &hf_mdf_cn_flags_event_signal,
    &hf_mdf_cn_flags_vlsd_stream,
    &hf_mdf_cn_flags_raw_sensor_event,
    &hf_mdf_cn_flags_auxiliary,
    &hf_mdf_cn_flags_data_stream_mode,
    &hf_mdf_cn_flags_alignment_reset,
    &hf_mdf_cn_flags_protocol_event,
    &hf_mdf_cn_flags_data_description_mode,
    NULL
};

static int * const mdf_fh_time_flags[] = {
    &hf_mdf_fh_time_flags_local_time,
    &hf_mdf_fh_time_flags_offsets_valid,
    NULL
};

static int * const mdf_hd_time_flags[] = {
    &hf_mdf_hd_time_flags_local_time,
    &hf_mdf_hd_time_flags_offsets_valid,
    NULL
};

static int * const mdf_hd_flags[] = {
    &hf_mdf_hd_flags_angle_valid,
    &hf_mdf_hd_flags_distance_valid,
    NULL
};

static int * const mdf_si_flags[] = {
    &hf_mdf_si_flags_simulated,
    NULL
};

/* Only valid after mdf_block_sane() succeeded. */
static int
mdf_data_length(uint64_t length, uint64_t link_count) {
    return (int)length - MDF_BLOCK_HDR_LEN - 8 * (int)link_count;
}

/* Checks that the length and link count of a block header fit together, fit
 * into the remaining data and leave room for min_data bytes of block data. */
static bool
mdf_block_sane(tvbuff_t *tvb, int offset, uint64_t length, uint64_t link_count, int min_data) {
    uint64_t remaining = (uint64_t)tvb_captured_length_remaining(tvb, offset);

    if (length < MDF_BLOCK_HDR_LEN || length > remaining) {
        return false;
    }
    if (link_count > (length - MDF_BLOCK_HDR_LEN) / 8) {
        return false;
    }
    return (length - MDF_BLOCK_HDR_LEN - 8 * link_count) >= (uint64_t)min_data;
}

#define MDF_TEXT_MAX_SHOWN 64

/* Is target the file offset of the start of a block that fits into the file? */
static bool
mdf_valid_block_offset(tvbuff_t *tvb, uint64_t target) {
    uint64_t remaining = (uint64_t)tvb_captured_length_remaining(tvb, 0);

    return (target & 7) == 0 && target >= MDF_LEN_IDBLOCK &&
           target <= remaining - MIN(remaining, MDF_BLOCK_HDR_LEN) &&
           (tvb_get_ntohl(tvb, (int)target) & 0xffff0000) == 0x23230000;
}

/* Returns a short single line text for a TX block (its text) or an MD block
 * (the content of its first <TX> element) at the file offset target, or NULL. */
static const char *
mdf_block_text(tvbuff_t *tvb, packet_info *pinfo, uint64_t target) {
    uint64_t  remaining = (uint64_t)tvb_captured_length_remaining(tvb, 0);
    uint32_t  block_id;
    uint64_t  length, links, data_off, data_len;
    char     *text;
    char     *end;
    size_t    len;
    size_t    i;
    bool      truncated = false;

    if (!mdf_valid_block_offset(tvb, target)) {
        return NULL;
    }
    block_id = tvb_get_ntohl(tvb, (int)target);
    if (block_id != MDF_BLOCK_ID_TX_TEXT && block_id != MDF_BLOCK_ID_MD_META_DATA) {
        return NULL;
    }

    length = tvb_get_uint64(tvb, (int)target + 8, ENC_LITTLE_ENDIAN);
    links = tvb_get_uint64(tvb, (int)target + 16, ENC_LITTLE_ENDIAN);
    if (length < MDF_BLOCK_HDR_LEN || length > remaining - target || links > (length - MDF_BLOCK_HDR_LEN) / 8) {
        return NULL;
    }
    data_off = target + MDF_BLOCK_HDR_LEN + 8 * links;
    data_len = length - MDF_BLOCK_HDR_LEN - 8 * links;
    if (data_len == 0) {
        return NULL;
    }

    /* XML needs more room than we want to show */
    text = (char *)tvb_get_string_enc(pinfo->pool, tvb, (int)data_off,
                                      (int)MIN(data_len, block_id == MDF_BLOCK_ID_MD_META_DATA ? 4096 : MDF_TEXT_MAX_SHOWN * 4),
                                      ENC_UTF_8);
    if (block_id == MDF_BLOCK_ID_MD_META_DATA) {
        text = strstr(text, "<TX>");
        if (text == NULL) {
            return NULL;
        }
        text += 4;
        end = strstr(text, "</TX>");
        if (end != NULL) {
            *end = '\0';
        }
    }

    len = strlen(text);
    if (len > MDF_TEXT_MAX_SHOWN) {
        len = MDF_TEXT_MAX_SHOWN;
        /* do not cut a UTF-8 sequence in half */
        while (len > 0 && ((uint8_t)text[len] & 0xc0) == 0x80) {
            len--;
        }
        truncated = true;
    }
    text[len] = '\0';
    for (i = 0; i < len; i++) {
        if ((uint8_t)text[i] < 0x20) {
            text[i] = ' ';
        }
    }
    if (text[0] == '\0') {
        return NULL;
    }
    return truncated ? wmem_strdup_printf(pinfo->pool, "%s...", text) : text;
}

/* Adds a link (the file offset of another block, 0 = no link) and annotates it
 * with the type of the block it points to. The whole file is available in the
 * tvb, so the target can be looked at directly. For text and meta data blocks
 * the start of the text is shown as well. */
static proto_item *
mdf_add_link(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, packet_info *pinfo) {
    proto_item *ti;
    uint64_t    target;
    const char *text;

    ti = proto_tree_add_item_ret_uint64(tree, hf, tvb, offset, 8, ENC_LITTLE_ENDIAN, &target);

    if (target == 0) {
        proto_item_append_text(ti, " (no link)");
        return ti;
    }

    if (!mdf_valid_block_offset(tvb, target)) {
        proto_item_append_text(ti, " (invalid)");
        expert_add_info(pinfo, ti, &ei_mdf_link_invalid);
        return ti;
    }

    proto_item_append_text(ti, " -> %s", tvb_get_string_enc(pinfo->pool, tvb, (int)target, 4, ENC_ASCII));

    text = mdf_block_text(tvb, pinfo, target);
    if (text != NULL) {
        proto_item_append_text(ti, " \"%s\"", text);
    }
    return ti;
}

/* The value of link number idx of the block at offset, or 0 if there is none. */
static uint64_t
mdf_get_link(tvbuff_t *tvb, int offset, uint64_t idx) {
    uint64_t link_count = tvb_get_uint64(tvb, offset + 16, ENC_LITTLE_ENDIAN);
    uint64_t remaining = (uint64_t)tvb_captured_length_remaining(tvb, offset);

    if (idx >= link_count || MDF_BLOCK_HDR_LEN + 8 * (idx + 1) > remaining) {
        return 0;
    }
    return tvb_get_uint64(tvb, offset + MDF_BLOCK_HDR_LEN + 8 * (int)idx, ENC_LITTLE_ENDIAN);
}

#define MDF_NO_LINK UINT64_MAX

/* Appends the name, unit and comment of a block (found via its links, or the
 * text of a TX/MD block itself) to its summary line: "Name" (unit) - comment */
static void
mdf_append_summary(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo, int offset, uint32_t block_id) {
    uint64_t    name_idx = MDF_NO_LINK, unit_idx = MDF_NO_LINK, comment_idx = MDF_NO_LINK;
    const char *name = NULL, *unit = NULL, *comment = NULL;

    switch (block_id) {
    case MDF_BLOCK_ID_AT_ATTACHMENT:      name_idx = 1; comment_idx = 3; break;
    case MDF_BLOCK_ID_CH_CHANNEL_HIERARCHY: name_idx = 2; comment_idx = 3; break;
    case MDF_BLOCK_ID_EV_EVENT:           name_idx = 3; comment_idx = 4; break;
    case MDF_BLOCK_ID_CC_CONVERSION:      name_idx = 0; unit_idx = 1; comment_idx = 2; break;
    case MDF_BLOCK_ID_CG_CHANNEL_GROUP:   name_idx = 2; comment_idx = 5; break;
    case MDF_BLOCK_ID_CN_CHANNEL:         name_idx = 2; unit_idx = 6; comment_idx = 7; break;
    case MDF_BLOCK_ID_DG_DATA_GROUP:      comment_idx = 3; break;
    case MDF_BLOCK_ID_FH_FILE_HEADER:     comment_idx = 1; break;
    case MDF_BLOCK_ID_HD_HEADER:          comment_idx = 5; break;
    case MDF_BLOCK_ID_SI_SOURCE_INFO:     name_idx = 0; comment_idx = 2; break;
    case MDF_BLOCK_ID_MD_META_DATA:
    case MDF_BLOCK_ID_TX_TEXT:
        name = mdf_block_text(tvb, pinfo, (uint64_t)offset);
        break;
    default:
        return;
    }

    if (name_idx != MDF_NO_LINK) {
        name = mdf_block_text(tvb, pinfo, mdf_get_link(tvb, offset, name_idx));
    }
    if (unit_idx != MDF_NO_LINK) {
        unit = mdf_block_text(tvb, pinfo, mdf_get_link(tvb, offset, unit_idx));
    }
    if (comment_idx != MDF_NO_LINK) {
        comment = mdf_block_text(tvb, pinfo, mdf_get_link(tvb, offset, comment_idx));
    }

    if (name == NULL && unit == NULL && comment == NULL) {
        return;
    }
    proto_item_append_text(ti, ":");
    if (name != NULL) {
        proto_item_append_text(ti, " \"%s\"", name);
    }
    if (unit != NULL) {
        proto_item_append_text(ti, " (%s)", unit);
    }
    if (comment != NULL) {
        proto_item_append_text(ti, "%s %s", (name != NULL || unit != NULL) ? " -" : "", comment);
    }
}

/* Inflates a zlib stream of an AT or DZ block. Returns the data as a tvb that
 * belongs to tvb, or NULL (with an expert info) if that is not possible. A
 * deviation from the original length stated in the block is reported, too. */
static tvbuff_t *
mdf_zlib_uncompress(tvbuff_t *tvb, int offset, unsigned data_length, uint64_t org_data_length,
                    packet_info *pinfo, proto_tree *tree) {
    tvbuff_t *out_tvb;

    if (org_data_length > MDF_DZ_MAX_UNCOMPRESSED_LEN) {
        expert_add_info(pinfo, tree, &ei_mdf_dz_unsupported);
        return NULL;
    }

    out_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, data_length);
    if (out_tvb == NULL) {
        expert_add_info(pinfo, tree, &ei_mdf_dz_decompress_failed);
        return NULL;
    }

    if (tvb_captured_length(out_tvb) != org_data_length) {
        expert_add_info(pinfo, tree, &ei_mdf_dz_length_mismatch);
    }
    return out_tvb;
}

#define MDF_TAB_WIDTH 4

/* Returns a tvb in which tabs are replaced by spaces, or tvb itself if it has none. */
static tvbuff_t *
mdf_expand_tabs(tvbuff_t *tvb, packet_info *pinfo) {
    unsigned len = tvb_captured_length(tvb);
    unsigned tabs = 0, i, n = 0;
    const uint8_t *in;
    uint8_t *out;

    in = tvb_get_ptr(tvb, 0, len);
    for (i = 0; i < len; i++) {
        if (in[i] == '\t') {
            tabs++;
        }
    }
    if (tabs == 0) {
        return tvb;
    }
    out = (uint8_t *)wmem_alloc(pinfo->pool, len + tabs * (MDF_TAB_WIDTH - 1));
    for (i = 0; i < len; i++) {
        if (in[i] == '\t') {
            memset(out + n, ' ', MDF_TAB_WIDTH);
            n += MDF_TAB_WIDTH;
        } else {
            out[n++] = in[i];
        }
    }
    return tvb_new_child_real_data(tvb, out, n, n);
}

/* Shows (decompressed) attachment data as an own data source and hands it to
 * the dissector registered for its MIME type. Without such a dissector the
 * data is shown as bytes. */
static void
mdf_add_attachment_data(tvbuff_t *data_tvb, const char *mime, packet_info *pinfo, proto_tree *tree, int hf, const char *name) {
    if (data_tvb == NULL) {
        return;
    }
    add_new_data_source(pinfo, data_tvb, name);
    if (mime != NULL && g_ascii_strcasecmp(mime, "application/x-dbc") == 0) {
        /* shown as text, where a tab would be displayed as \t */
        data_tvb = mdf_expand_tabs(data_tvb, pinfo);
    }
    if (mime != NULL && dissector_try_string_with_data(media_type_table, mime, data_tvb, pinfo, tree, true, NULL) > 0) {
        return;
    }
    proto_tree_add_item(tree, hf, data_tvb, 0, -1, ENC_NA);
}

/* Shows decompressed data (if there is any) as an own data source and as an item of the block. */
static void
mdf_add_uncompressed(tvbuff_t *uncompressed_tvb, packet_info *pinfo, proto_tree *tree, int hf, const char *name) {
    mdf_add_attachment_data(uncompressed_tvb, NULL, pinfo, tree, hf, name);
}

/* The ID BLOCK is special by not following the block format! */
static int
dissect_mdf_id_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo _U_, proto_tree *root_tree, void *data _U_) {
    int         offset = offset_orig;
    proto_tree     *subtree;
    proto_item     *ti;

    ti = proto_tree_add_item(root_tree, hf_mdf_id, tvb, offset_orig, MDF_LEN_IDBLOCK, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_mdf_block_id);

    proto_tree_add_item(subtree, hf_mdf_id_file, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    proto_tree_add_item(subtree, hf_mdf_id_vers, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    proto_tree_add_item(subtree, hf_mdf_id_prog, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    proto_tree_add_item(subtree, hf_mdf_id_res1, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(subtree, hf_mdf_id_ver, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_mdf_id_res2, tvb, offset, 30, ENC_NA);
    offset += 30;

    proto_tree_add_item(subtree, hf_mdf_id_unfin_flg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_mdf_id_cstom_flg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset - offset_orig;
}

static int
dissect_mdf_block_header(tvbuff_t *tvb, int offset_orig, packet_info *pinfo _U_, proto_tree *tree, uint64_t *length, uint64_t *link_count) {
    proto_item     *ti;
    proto_tree     *header_tree;
    int         offset = offset_orig;

    ti = proto_tree_add_item(tree, hf_mdf_block_header, tvb, offset_orig, MDF_BLOCK_HDR_LEN, ENC_NA);
    header_tree = proto_item_add_subtree(ti, ett_mdf_block_header);

    proto_tree_add_item(header_tree, hf_mdf_block_id, tvb, offset, 4, ENC_ASCII);
    offset += 4;

    proto_tree_add_item(header_tree, hf_mdf_block_res, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item_ret_uint64(header_tree, hf_mdf_block_length, tvb, offset, 8, ENC_LITTLE_ENDIAN, length);
    offset += 8;

    proto_tree_add_item_ret_uint64(header_tree, hf_mdf_block_link_cnt, tvb, offset, 8, ENC_LITTLE_ENDIAN, link_count);
    offset += 8;

    return offset - offset_orig;
}

/* A run of links of the same kind inside a block. */
typedef struct {
    int      hf;
    uint64_t count;
} mdf_link_run;

static uint64_t
mdf_sat_mul(uint64_t a, uint64_t b) {
    if (a != 0 && b > UINT64_MAX / a) {
        return UINT64_MAX;
    }
    return a * b;
}

static uint64_t
mdf_sat_add(uint64_t a, uint64_t b) {
    return (b > UINT64_MAX - a) ? UINT64_MAX : a + b;
}

/* Adds the link_count links starting at offset, labelled by the given runs.
 * Links beyond the runs are shown as plain links. Returns the end offset. */
static int
mdf_add_link_runs(proto_tree *tree, tvbuff_t *tvb, int offset, uint64_t link_count, const mdf_link_run *runs, unsigned run_count, packet_info *pinfo) {
    unsigned r;
    uint64_t k;

    for (r = 0; r < run_count; r++) {
        for (k = 0; k < runs[r].count && link_count > 0; k++, link_count--) {
            mdf_add_link(tree, runs[r].hf, tvb, offset, pinfo);
            offset += 8;
        }
    }
    for (; link_count > 0; link_count--) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }
    return offset;
}

static int
dissect_mdf_at_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        data_length;
    uint64_t        org_data_length;
    uint64_t        link_count;
    uint32_t        flags;
    uint32_t        zip_type;
    uint64_t        flags64;
    int             data_off;
    mdf_link_run    runs[2];

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_at, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_at);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 40)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 4 */
    if (link_count < 4) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    mdf_add_link(tree, hf_mdf_at_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_at_tx_filename, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_at_tx_mimetype, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_at_tx_comment, tvb, offset, pinfo);
    offset += 8;

    /* the flags tell which of the optional links are present; they are the first data field */
    data_off = offset + 8 * (int)(link_count - 4);
    flags = tvb_get_letohs(tvb, data_off);
    runs[0].hf = hf_mdf_at_tx_filename_zip;
    runs[0].count = (flags & MDF_AT_FLAGS_ZIP_FILENAME) ? 1 : 0;
    runs[1].hf = hf_mdf_at_tx_mimetype_zip;
    runs[1].count = (flags & MDF_AT_FLAGS_ZIP_MIMETYPE) ? 1 : 0;
    offset = mdf_add_link_runs(tree, tvb, offset, link_count - 4, runs, 2, pinfo);

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_mdf_at_flags, ett_mdf_at_flags, mdf_at_flags, ENC_LITTLE_ENDIAN, &flags64);
    flags = (uint32_t)flags64;
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_at_creator_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_mdf_at_zip_type, tvb, offset, 1, ENC_NA, &zip_type);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_at_path_syntax, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_at_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_at_md5_checksum, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item_ret_uint64(tree, hf_mdf_at_original_size, tvb, offset, 8, ENC_LITTLE_ENDIAN, &org_data_length);
    offset += 8;
    proto_tree_add_item_ret_uint64(tree, hf_mdf_at_embedded_size, tvb, offset, 8, ENC_LITTLE_ENDIAN, &data_length);
    offset += 8;
    if (data_length > (length - (offset - offset_orig))) {
        expert_add_info(pinfo, tree, &ei_mdf_block_malformed);
        data_length = length - (offset - offset_orig);
    }
    proto_tree_add_item(tree, hf_mdf_at_embedded_data, tvb, offset, (int)data_length, ENC_NA);

    if ((flags & MDF_AT_FLAGS_EMBEDDED) && data_length > 0) {
        const char *mime = mdf_block_text(tvb, pinfo, mdf_get_link(tvb, offset_orig, 2));
        tvbuff_t *att_tvb;
        bool      compressed = (flags & MDF_AT_FLAGS_COMPRESSED) || (flags & MDF_AT_FLAGS_GENERAL_ZIP);

        if ((flags & MDF_AT_FLAGS_COMPRESSED) || ((flags & MDF_AT_FLAGS_GENERAL_ZIP) && zip_type == 0)) {
            att_tvb = mdf_zlib_uncompress(tvb, offset, (unsigned)data_length, org_data_length, pinfo, tree);
        } else if (flags & MDF_AT_FLAGS_GENERAL_ZIP) {
            /* ZStd, LZ4 or a custom algorithm */
            expert_add_info(pinfo, tree, &ei_mdf_dz_unsupported);
            att_tvb = NULL;
        } else {
            att_tvb = tvb_new_subset_length(tvb, offset, (int)data_length);
        }
        mdf_add_attachment_data(att_tvb, mime, pinfo, tree, hf_mdf_at_uncompressed,
                                compressed ? "Uncompressed Attachment" : "Attachment");
    }
    offset += (int)data_length;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_cc_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int             offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint32_t        ref_count;
    uint32_t        val_count;
    uint32_t        j;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_cc, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_cc);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, MDF_CC_FIXED_DATA_LEN)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    if (link_count < MDF_CC_FIXED_LINKS) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 4 + cc_ref_count */
    mdf_add_link(tree, hf_mdf_cc_tx_name, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cc_md_unit, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cc_md_comment, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cc_cc_inverse, tvb, offset, pinfo);
    offset += 8;

    /* The reference count is part of the data section, which follows the links. */
    ref_count = tvb_get_uint16(tvb, offset + 8 * (int)(link_count - MDF_CC_FIXED_LINKS) + 4, ENC_LITTLE_ENDIAN);
    for (i = MDF_CC_FIXED_LINKS; i < link_count; i++) {
        mdf_add_link(tree, (i - MDF_CC_FIXED_LINKS) < ref_count ? hf_mdf_cc_cc_ref : hf_mdf_block_link,
                     tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_cc_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cc_precision, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_cc_flags, ett_mdf_cc_flags, mdf_cc_flags, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_cc_ref_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_mdf_cc_val_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &val_count);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_cc_phy_range_min, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cc_phy_range_max, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    if ((uint64_t)val_count * 8 > (uint64_t)(mdf_data_length(length, link_count) - MDF_CC_FIXED_DATA_LEN)) {
        expert_add_info(pinfo, tree, &ei_mdf_cc_val_count);
        val_count = (uint32_t)((mdf_data_length(length, link_count) - MDF_CC_FIXED_DATA_LEN) / 8);
    }
    for (j = 0; j < val_count; j++) {
        proto_tree_add_item(tree, hf_mdf_cc_val, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_cg_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_cg, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_cg);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 32)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 6 - 7 */
    if (link_count < 6) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    mdf_add_link(tree, hf_mdf_cg_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cg_cn_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cg_tx_acq_name, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cg_si_acq_source, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cg_sr_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cg_md_comment, tvb, offset, pinfo);
    offset += 8;

    /* cg_cg_master is only present if the remote master flag is set (cg_flags follows record ID and cycle count) */
    i = 6;
    if (link_count > 6 && (tvb_get_letohs(tvb, offset + 8 * (int)(link_count - 6) + 16) & MDF_CG_FLAGS_REMOTE_MASTER)) {
        mdf_add_link(tree, hf_mdf_cg_cg_master, tvb, offset, pinfo);
        offset += 8;
        i++;
    }
    for (; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_cg_record_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cg_cycle_count, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_cg_flags, ett_mdf_cg_flags, mdf_cg_flags, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_cg_path_separator, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_cg_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_cg_data_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_cg_inval_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_cn_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint16_t        attachment_count;
    uint32_t         flags;
    uint8_t         cn_type;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_cn, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_cn);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 72)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    attachment_count = tvb_get_uint16(tvb, offset + (8 * (int)link_count) + MDF_CN_DATA_OFFSET_ATTACHMENT_COUNT, ENC_LITTLE_ENDIAN);
    flags = tvb_get_uint32(tvb, offset + (8 * (int)link_count) + MDF_CN_DATA_OFFSET_FLAGS, ENC_LITTLE_ENDIAN);
    cn_type = tvb_get_uint8(tvb, offset + (8 * (int)link_count));

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 8 + n attachments + 0|3 default */
    if (link_count < 8) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    mdf_add_link(tree, hf_mdf_cn_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_composition, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_tx_name, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_si_source, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_cc_conversion, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_data, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_md_unit, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cn_md_comment, tvb, offset, pinfo);
    offset += 8;

    uint64_t links_counted = 8;

    uint16_t j;
    for (j = 0; j < attachment_count && links_counted < link_count; j++) {
        mdf_add_link(tree, hf_mdf_cn_at_reference, tvb, offset, pinfo);
        offset += 8;
        links_counted++;
    }

    if ((flags & MDF_CN_FLAGS_DEFAULT_X) && links_counted + 3 <= link_count) {
        mdf_add_link(tree, hf_mdf_cn_default_x, tvb, offset, pinfo);
        offset += 8;
        mdf_add_link(tree, hf_mdf_cn_default_x, tvb, offset, pinfo);
        offset += 8;
        mdf_add_link(tree, hf_mdf_cn_default_x, tvb, offset, pinfo);
        offset += 8;
        links_counted += 3;
    }

    if (cn_type == MDF_CN_TYPE_VLSC && links_counted < link_count) {
        mdf_add_link(tree, hf_mdf_cn_cn_size, tvb, offset, pinfo);
        offset += 8;
        links_counted++;
    }

    uint64_t i;
    for (i = links_counted; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_cn_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cn_sync_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cn_data_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cn_bit_offset, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cn_byte_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_cn_bit_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_cn_flags, ett_mdf_cn_flags, mdf_cn_flags, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_cn_inval_bit_pos, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_cn_precision, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cn_alignment, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cn_attachment_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_cn_val_range_min, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cn_val_range_max, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cn_limit_min, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cn_limit_max, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cn_limit_ext_min, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_cn_limit_ext_max, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_dg_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_dg, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_dg);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 4 */

    if (link_count < 4) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_dg_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_dg_cg_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_dg_data, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_dg_md_comment, tvb, offset, pinfo);
    offset += 8;

    for (i = 4; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_dg_rec_id_size, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_dg_reserved, tvb, offset, 7, ENC_NA);
    offset += 7;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_dt_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_dt, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_dt);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 0)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 0 */
    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    /* DATA */
    proto_tree_add_item(blocktree, hf_mdf_dt_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

/* Adds count 64 bit values (offsets, time, angle or distance values) of a list
 * block, as far as they fit into the remaining bytes of the block. Returns the
 * number of bytes used. */
static int
mdf_add_u64_array(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, uint64_t count, int remaining) {
    int used = 0;

    while (count > 0 && remaining - used >= 8) {
        proto_tree_add_item(tree, hf, tvb, offset + used, 8, ENC_LITTLE_ENDIAN);
        used += 8;
        count--;
    }
    return used;
}

static int
dissect_mdf_dl_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint64_t        flags;
    uint32_t        count;
    int             remaining;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_dl, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_dl);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: next list block and one link per data block */
    if (link_count < 1) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_dl_next, tvb, offset, pinfo);
    offset += 8;
    for (i = 1; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_dl_data_link, tvb, offset, pinfo);
        offset += 8;
    }

    remaining = mdf_data_length(length, link_count);
    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, remaining, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_mdf_dl_flags, ett_mdf_dl_flags, mdf_dl_flags, ENC_LITTLE_ENDIAN, &flags);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_dl_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;
    ti = proto_tree_add_item_ret_uint(tree, hf_mdf_dl_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    remaining -= 8;
    if (count != link_count - 1) {
        expert_add_info(pinfo, ti, &ei_mdf_list_count);
    }

    if (flags & 0x01) {
        if (remaining >= 8) {
            proto_tree_add_item(tree, hf_mdf_dl_equal_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            remaining -= 8;
        }
    } else {
        i = mdf_add_u64_array(tree, hf_mdf_dl_offset, tvb, offset, count, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (flags & 0x02) {
        i = mdf_add_u64_array(tree, hf_mdf_dl_time_value, tvb, offset, count, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (flags & 0x04) {
        i = mdf_add_u64_array(tree, hf_mdf_dl_angle_value, tvb, offset, count, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (flags & 0x08) {
        i = mdf_add_u64_array(tree, hf_mdf_dl_distance_value, tvb, offset, count, remaining);
        offset += (int)i;
    }

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_hl_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_hl, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_hl);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 1 */
    if (link_count < 1) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_hl_dl_first, tvb, offset, pinfo);
    offset += 8;

    for (i = 1; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_hl_flags, ett_mdf_hl_flags, mdf_hl_flags, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_hl_zip_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_hl_reserved, tvb, offset, 5, ENC_NA);
    offset += 5;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_ld_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        flags;
    uint64_t        flags_ext;
    uint64_t        expected_links;
    uint64_t        i;
    uint32_t        count;
    int             data_off;
    int             remaining;
    mdf_link_run    runs[2];

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_ld, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_ld);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: next list block, one link per data block and, if flagged, one per invalidation data block */
    if (link_count < 1) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    /* the extended flags and the count are needed to tell the data links from the invalidation links */
    data_off = offset + 8 * (int)link_count;
    flags = tvb_get_uint8(tvb, data_off);
    flags_ext = tvb_get_uint8(tvb, data_off + 3);
    count = tvb_get_letohl(tvb, data_off + 4);

    mdf_add_link(tree, hf_mdf_ld_next, tvb, offset, pinfo);
    offset += 8;
    runs[0].hf = hf_mdf_ld_data_link;
    runs[0].count = count;
    runs[1].hf = hf_mdf_ld_inval_link;
    runs[1].count = (flags_ext & 0x80) ? count : 0;
    offset = mdf_add_link_runs(tree, tvb, offset, link_count - 1, runs, 2, pinfo);

    remaining = mdf_data_length(length, link_count);
    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, remaining, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_ld_flags, ett_mdf_ld_flags, mdf_ld_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ld_zip_info, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ld_zip_info_inval, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_ld_flags_ext, ett_mdf_ld_flags_ext, mdf_ld_flags_ext, ENC_LITTLE_ENDIAN);
    offset += 1;
    ti = proto_tree_add_item(tree, hf_mdf_ld_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    remaining -= 8;

    expected_links = 1 + (uint64_t)count * ((flags_ext & 0x80) ? 2 : 1);
    if (link_count != expected_links) {
        expert_add_info(pinfo, ti, &ei_mdf_list_count);
    }

    if (flags & 0x01) {
        if (remaining >= 8) {
            proto_tree_add_item(tree, hf_mdf_ld_equal_sample_count, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            remaining -= 8;
        }
    } else {
        i = mdf_add_u64_array(tree, hf_mdf_ld_sample_offset, tvb, offset, count, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (flags & 0x02) {
        i = mdf_add_u64_array(tree, hf_mdf_ld_time_value, tvb, offset, count, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (flags & 0x04) {
        i = mdf_add_u64_array(tree, hf_mdf_ld_angle_value, tvb, offset, count, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (flags & 0x08) {
        i = mdf_add_u64_array(tree, hf_mdf_ld_distance_value, tvb, offset, count, remaining);
        offset += (int)i;
    }

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

/* SD and RD blocks: no links, the data is not interpreted. */
static int
dissect_mdf_raw_data_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, proto_item **ti_ret,
                           int hf_block, int ett_block, int hf_data) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_block, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_block);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 0)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 0 */
    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    /* DATA */
    proto_tree_add_item(blocktree, hf_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_sd_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_sd, ett_mdf_block_sd, hf_mdf_sd_data);
}

static int
dissect_mdf_dv_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_dv, ett_mdf_block_dv, hf_mdf_dv_data);
}

static int
dissect_mdf_di_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_di, ett_mdf_block_di, hf_mdf_di_data);
}

static int
dissect_mdf_rv_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_rv, ett_mdf_block_rv, hf_mdf_rv_data);
}

static int
dissect_mdf_ri_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_ri, ett_mdf_block_ri, hf_mdf_ri_data);
}

static int
dissect_mdf_vd_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_vd, ett_mdf_block_vd, hf_mdf_vd_data);
}

static int
dissect_mdf_rd_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    return dissect_mdf_raw_data_block(tvb, offset_orig, pinfo, root_tree, ti_ret, hf_mdf_rd, ett_mdf_block_rd, hf_mdf_rd_data);
}

static int
dissect_mdf_ch_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint32_t        count;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_ch, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_ch);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: 4 plus 3 per element */
    if (link_count < 4) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_ch_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ch_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ch_tx_name, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ch_md_comment, tvb, offset, pinfo);
    offset += 8;
    for (i = 4; i < link_count; i++) {
        mdf_add_link(tree, ((i - 4) % 3 == 0) ? hf_mdf_ch_dg : ((i - 4) % 3 == 1) ? hf_mdf_ch_cg : hf_mdf_ch_cn, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    ti = proto_tree_add_item_ret_uint(tree, hf_mdf_ch_element_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    if (link_count != 4 + 3 * (uint64_t)count) {
        expert_add_info(pinfo, ti, &ei_mdf_list_count);
    }
    proto_tree_add_item(tree, hf_mdf_ch_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ch_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_ev_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint32_t        scope_count;
    uint32_t        attachment_count;
    int             data_off;
    mdf_link_run    runs[3];
    uint32_t        group_name;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_ev, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_ev);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 32)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: 5 plus one per scope and one per attachment */
    if (link_count < 5) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    /* the counts are needed to tell the scope links from the attachment links */
    data_off = offset + 8 * (int)link_count;
    scope_count = tvb_get_letohl(tvb, data_off + 8);
    attachment_count = tvb_get_letohs(tvb, data_off + 12);
    group_name = (tvb_get_uint8(tvb, data_off + 4) & 0x02) ? 1 : 0;

    mdf_add_link(tree, hf_mdf_ev_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ev_parent, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ev_range, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ev_tx_name, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ev_md_comment, tvb, offset, pinfo);
    offset += 8;
    runs[0].hf = hf_mdf_ev_scope;
    runs[0].count = scope_count;
    runs[1].hf = hf_mdf_ev_at_reference;
    runs[1].count = attachment_count;
    runs[2].hf = hf_mdf_ev_tx_group_name;
    runs[2].count = group_name;
    offset = mdf_add_link_runs(tree, tvb, offset, link_count - 5, runs, 3, pinfo);

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_ev_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ev_sync_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ev_range_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ev_cause, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_ev_flags, ett_mdf_ev_flags, mdf_ev_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ev_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;
    ti = proto_tree_add_item(tree, hf_mdf_ev_scope_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (link_count != 5 + (uint64_t)scope_count + attachment_count + group_name) {
        expert_add_info(pinfo, ti, &ei_mdf_list_count);
    }
    proto_tree_add_item(tree, hf_mdf_ev_attachment_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_ev_creator_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_ev_sync_base_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_ev_sync_factor, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_sr_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_sr, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_sr);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 24)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 2 */
    if (link_count < 2) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_sr_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_sr_data, tvb, offset, pinfo);
    offset += 8;
    for (i = 2; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_sr_cycle_count, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_sr_interval, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_sr_sync_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_sr_flags, ett_mdf_sr_flags, mdf_sr_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_sr_reserved, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

#define MDF_CA_FIXED_DATA_LEN               16
#define MDF_CA_STORAGE_CG_TEMPLATE          1
#define MDF_CA_STORAGE_DG_TEMPLATE          2
#define MDF_CA_FLAGS_DYNAMIC_SIZE           0x01
#define MDF_CA_FLAGS_INPUT_QUANTITY         0x02
#define MDF_CA_FLAGS_OUTPUT_QUANTITY        0x04
#define MDF_CA_FLAGS_COMPARISON_QUANTITY    0x08
#define MDF_CA_FLAGS_AXIS                   0x10
#define MDF_CA_FLAGS_FIXED_AXIS             0x20

static int
dissect_mdf_ca_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint64_t        dims;
    uint64_t        dim_product = 0;
    uint64_t        dim_sum = 0;
    uint64_t        expected_links;
    uint32_t        ndim_item;
    uint32_t        storage;
    uint32_t        flags;
    int             data_off;
    int             data_len;
    int             remaining;
    unsigned        run_count = 0;
    mdf_link_run    runs[7];

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_ca, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_ca);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, MDF_CA_FIXED_DATA_LEN)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: the composition and, depending on the storage type and flags, lists of
     * links whose sizes depend on the dimensions. All of that is in the data. */
    if (link_count < 1) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    data_off = offset + 8 * (int)link_count;
    data_len = mdf_data_length(length, link_count);
    storage = tvb_get_uint8(tvb, data_off + 1);
    ndim_item = tvb_get_letohs(tvb, data_off + 2);
    flags = tvb_get_letohl(tvb, data_off + 4);

    /* only as many dimensions as fit into the block */
    dims = MIN((uint64_t)ndim_item, (uint64_t)(data_len - MDF_CA_FIXED_DATA_LEN) / 8);
    if (dims > 0) {
        dim_product = 1;
        for (i = 0; i < dims; i++) {
            uint64_t dim_size = tvb_get_letoh64(tvb, data_off + MDF_CA_FIXED_DATA_LEN + 8 * (int)i);
            dim_product = mdf_sat_mul(dim_product, dim_size);
            dim_sum = mdf_sat_add(dim_sum, dim_size);
        }
    }

    runs[run_count].hf = hf_mdf_ca_composition;
    runs[run_count++].count = 1;
    expected_links = 1;
    if (storage == MDF_CA_STORAGE_DG_TEMPLATE) {
        runs[run_count].hf = hf_mdf_ca_data;
        runs[run_count++].count = dim_product;
        expected_links = mdf_sat_add(expected_links, dim_product);
    }
    if (flags & MDF_CA_FLAGS_DYNAMIC_SIZE) {
        runs[run_count].hf = hf_mdf_ca_dynamic_size;
        runs[run_count++].count = 3 * dims;
        expected_links = mdf_sat_add(expected_links, 3 * dims);
    }
    if (flags & MDF_CA_FLAGS_INPUT_QUANTITY) {
        runs[run_count].hf = hf_mdf_ca_input_quantity;
        runs[run_count++].count = 3 * dims;
        expected_links = mdf_sat_add(expected_links, 3 * dims);
    }
    if (flags & MDF_CA_FLAGS_OUTPUT_QUANTITY) {
        runs[run_count].hf = hf_mdf_ca_output_quantity;
        runs[run_count++].count = 3;
        expected_links = mdf_sat_add(expected_links, 3);
    }
    if (flags & MDF_CA_FLAGS_COMPARISON_QUANTITY) {
        runs[run_count].hf = hf_mdf_ca_comparison_quantity;
        runs[run_count++].count = 3;
        expected_links = mdf_sat_add(expected_links, 3);
    }
    if (flags & MDF_CA_FLAGS_AXIS) {
        runs[run_count].hf = hf_mdf_ca_cc_axis_conversion;
        runs[run_count++].count = dims;
        runs[run_count].hf = hf_mdf_ca_axis_link;
        runs[run_count++].count = 3 * dims;
        expected_links = mdf_sat_add(expected_links, 4 * dims);
    }
    if (expected_links != link_count) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_list_count);
    }
    offset = mdf_add_link_runs(tree, tvb, offset, link_count, runs, run_count, pinfo);

    remaining = data_len;
    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, remaining, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_ca_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ca_storage, tvb, offset, 1, ENC_NA);
    offset += 1;
    ti = proto_tree_add_item(tree, hf_mdf_ca_ndim, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (dims < ndim_item) {
        expert_add_info(pinfo, ti, &ei_mdf_block_malformed);
    }
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_ca_flags, ett_mdf_ca_flags, mdf_ca_flags, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_ca_byte_offset_base, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mdf_ca_inval_bit_pos_base, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    remaining -= MDF_CA_FIXED_DATA_LEN;

    i = mdf_add_u64_array(tree, hf_mdf_ca_dim_size, tvb, offset, dims, remaining);
    offset += (int)i;
    remaining -= (int)i;
    if ((flags & MDF_CA_FLAGS_AXIS) && (flags & MDF_CA_FLAGS_FIXED_AXIS)) {
        i = mdf_add_u64_array(tree, hf_mdf_ca_axis_value, tvb, offset, dim_sum, remaining);
        offset += (int)i;
        remaining -= (int)i;
    }
    if (storage == MDF_CA_STORAGE_CG_TEMPLATE) {
        i = mdf_add_u64_array(tree, hf_mdf_ca_cycle_count, tvb, offset, dim_product, remaining);
        offset += (int)i;
    }

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_cv_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint32_t        count;
    int             remaining;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_cv, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_cv);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: the discriminator channel and one channel per option */
    if (link_count < 1) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_cv_cn_discriminator, tvb, offset, pinfo);
    offset += 8;
    for (i = 1; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_cv_cn_option, tvb, offset, pinfo);
        offset += 8;
    }

    remaining = mdf_data_length(length, link_count);
    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, remaining, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    ti = proto_tree_add_item_ret_uint(tree, hf_mdf_cv_option_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    if (link_count != 1 + (uint64_t)count) {
        expert_add_info(pinfo, ti, &ei_mdf_list_count);
    }
    proto_tree_add_item(tree, hf_mdf_cv_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;
    remaining -= 8;
    offset += mdf_add_u64_array(tree, hf_mdf_cv_option_val, tvb, offset, count, remaining);

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_cu_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint32_t        count;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_cu, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_cu);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: one channel per member */
    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_cu_cn_member, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    ti = proto_tree_add_item_ret_uint(tree, hf_mdf_cu_member_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    if (link_count != count) {
        expert_add_info(pinfo, ti, &ei_mdf_list_count);
    }
    proto_tree_add_item(tree, hf_mdf_cu_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_cl_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_cl, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_cl);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 2 */
    if (link_count < 2) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_cl_composition, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_cl_cn_size, tvb, offset, pinfo);
    offset += 8;
    for (i = 2; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_cl_flags, ett_mdf_cl_flags, mdf_cl_flags, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_cl_alignment, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cl_bit_offset, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_cl_byte_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_ds_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_ds, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_ds);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 2 */
    if (link_count < 2) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_ds_cn_composition, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_ds_cn_alignment_start, tvb, offset, pinfo);
    offset += 8;
    for (i = 2; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_ds_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_ds_mode, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_ds_reserved, tvb, offset, 5, ENC_NA);
    offset += 5;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_gd_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_gd, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_gd);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 1 */
    if (link_count < 1) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_gd_link, tvb, offset, pinfo);
    offset += 8;
    for (i = 1; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_gd_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_gd_reserved, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

/* Undoes the transposition of "Transposition + Deflate": the stored data holds
 * the first byte of every record, then the second byte of every record, and so
 * on. Trailing bytes that do not fill a complete record are stored as they are. */
static uint8_t *
mdf_dz_transpose_back(wmem_allocator_t *scope, const uint8_t *in, uint32_t len, uint32_t columns) {
    uint8_t  *out = (uint8_t *)wmem_alloc(scope, len);
    uint32_t  rows = len / columns;
    uint32_t  r, c;

    for (c = 0; c < columns; c++) {
        for (r = 0; r < rows; r++) {
            out[(uint64_t)r * columns + c] = in[(uint64_t)c * rows + r];
        }
    }
    memcpy(out + (uint64_t)rows * columns, in + (uint64_t)rows * columns, len - rows * columns);
    return out;
}

/* Returns the uncompressed data of a DZ block as a new tvb or NULL (with an
 * expert info) if it cannot be uncompressed. */
static tvbuff_t *
mdf_dz_uncompress(tvbuff_t *tvb, int offset, unsigned data_length, uint32_t zip_type, uint32_t zip_parameter,
                  uint64_t org_data_length, packet_info *pinfo, proto_tree *tree) {
    tvbuff_t *tmp_tvb;
    uint8_t  *buf;
    unsigned  len;

    if ((zip_type != MDF_DZ_ZIP_DEFLATE && zip_type != MDF_DZ_ZIP_TRANSPOSITION_DEFLATE) ||
        (zip_type == MDF_DZ_ZIP_TRANSPOSITION_DEFLATE && zip_parameter == 0)) {
        expert_add_info(pinfo, tree, &ei_mdf_dz_unsupported);
        return NULL;
    }

    tmp_tvb = mdf_zlib_uncompress(tvb, offset, data_length, org_data_length, pinfo, tree);
    if (tmp_tvb == NULL) {
        return NULL;
    }
    len = tvb_captured_length(tmp_tvb);

    if (zip_type == MDF_DZ_ZIP_DEFLATE) {
        return tmp_tvb;
    }

    buf = mdf_dz_transpose_back(pinfo->pool, tvb_get_ptr(tmp_tvb, 0, len), len, zip_parameter);
    return tvb_new_child_real_data(tmp_tvb, buf, len, len);
}

static int
dissect_mdf_dz_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        data_length;
    uint64_t        org_data_length;
    uint32_t        zip_type;
    uint32_t        zip_parameter;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_dz, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_dz);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 24)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 0*/
    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_dz_org_block_type, tvb, offset, 2, ENC_ASCII);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_mdf_dz_zip_type, tvb, offset, 1, ENC_NA, &zip_type);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_dz_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_mdf_dz_zip_parameter, tvb, offset, 4, ENC_LITTLE_ENDIAN, &zip_parameter);
    offset += 4;
    proto_tree_add_item_ret_uint64(tree, hf_mdf_dz_org_data_length, tvb, offset, 8, ENC_LITTLE_ENDIAN, &org_data_length);
    offset += 8;
    proto_tree_add_item_ret_uint64(tree, hf_mdf_dz_data_length, tvb, offset, 8, ENC_LITTLE_ENDIAN, &data_length);
    offset += 8;

    if (data_length > (length - (offset - offset_orig))) {
        expert_add_info(pinfo, tree, &ei_mdf_block_malformed);
        data_length = length - (offset - offset_orig);
    }
    /* This only works up until 2GB block size */
    proto_tree_add_item(tree, hf_mdf_dz_data, tvb, offset, (int)data_length, ENC_NA);

    mdf_add_uncompressed(mdf_dz_uncompress(tvb, offset, (unsigned)data_length, zip_type, zip_parameter, org_data_length, pinfo, tree),
                         pinfo, tree, hf_mdf_dz_uncompressed, "Uncompressed MDF Data");
    offset += (int)data_length;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_fh_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_fh, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_fh);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 16)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 2 */
    if (link_count < 2) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_fh_next, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_fh_comment, tvb, offset, pinfo);
    offset += 8;

    for (i = 2; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_fh_time_ns, tvb, offset, 8, ENC_TIME_NSECS | ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_fh_tz_offset_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_fh_dst_offset_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_fh_time_flags, ett_mdf_fh_time_flags, mdf_fh_time_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_fh_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_hd_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_hd, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_hd);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 32)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS: 6 for HD Blocks */
    if (link_count < 6) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }
    mdf_add_link(tree, hf_mdf_hd_dg_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_hd_fh_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_hd_ch_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_hd_at_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_hd_ev_first, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_hd_md_comment, tvb, offset, pinfo);
    offset += 8;

    for (i = 6; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_hd_start_time_ns, tvb, offset, 8, ENC_TIME_NSECS | ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_hd_tz_offset_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdf_hd_dst_offset_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_hd_time_flags, ett_mdf_hd_time_flags, mdf_hd_time_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_hd_time_class, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_hd_flags, ett_mdf_hd_flags, mdf_hd_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_hd_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_hd_start_angle_rad, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mdf_hd_start_distance_m, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_md_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_md, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_md);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 0)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 0 */
    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    /* DATA */
    proto_tree_add_item(blocktree, hf_mdf_md_data, tvb, offset, mdf_data_length(length, link_count), ENC_UTF_8);

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_si_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_si, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_si);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 8)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 3 */
    if (link_count < 3) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_too_few_links);
        proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
        return (int)length;
    }

    mdf_add_link(tree, hf_mdf_si_tx_name, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_si_tx_path, tvb, offset, pinfo);
    offset += 8;
    mdf_add_link(tree, hf_mdf_si_md_comment, tvb, offset, pinfo);
    offset += 8;

    for (i = 3; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_data);

    /* DATA */
    proto_tree_add_item(tree, hf_mdf_si_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_si_bus_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mdf_si_flags, ett_mdf_si_flags, mdf_si_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdf_si_reserved, tvb, offset, 5, ENC_NA);
    offset += 5;

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_tx_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_tx, tvb, offset_orig, -1, ENC_NA);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_block_tx);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 0)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    /* LINKS, should be 0 */
    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    /* DATA */
    proto_tree_add_item(blocktree, hf_mdf_tx_data, tvb, offset, mdf_data_length(length, link_count), ENC_UTF_8);

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_unknown_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data _U_, proto_item **ti_ret) {
    proto_item     *ti;
    proto_tree     *blocktree;
    proto_tree     *tree;
    int         offset = offset_orig;

    uint64_t        length;
    uint64_t        link_count;
    uint64_t        i;
    uint8_t        *id_string;

    *ti_ret = proto_tree_add_item(root_tree, hf_mdf_unknown_block, tvb, offset_orig, -1, ENC_NA);
    id_string = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
    proto_item_append_text(*ti_ret, " %s", id_string);
    blocktree = proto_item_add_subtree(*ti_ret, ett_mdf_unknownblock);
    offset += dissect_mdf_block_header(tvb, offset, pinfo, blocktree, &length, &link_count);
    if (!mdf_block_sane(tvb, offset_orig, length, link_count, 0)) {
        expert_add_info(pinfo, *ti_ret, &ei_mdf_block_malformed);
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    ti = proto_tree_add_item(blocktree, hf_mdf_block_links, tvb, offset, 8 * (int)link_count, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mdf_block_links);

    for (i = 0; i < link_count; i++) {
        mdf_add_link(tree, hf_mdf_block_link, tvb, offset, pinfo);
        offset += 8;
    }

    proto_tree_add_item(blocktree, hf_mdf_block_data, tvb, offset, mdf_data_length(length, link_count), ENC_NA);
    offset += mdf_data_length(length, link_count);

    proto_item_set_end(*ti_ret, tvb, offset_orig + (int)length);
    return MAX(offset - offset_orig, (int)length);
}

static int
dissect_mdf_block(tvbuff_t *tvb, int offset_orig, packet_info *pinfo, proto_tree *root_tree, void *data) {
    proto_item *ti = NULL;

    uint32_t    block_id;
    int         length = 0;

    if (tvb_captured_length_remaining(tvb, offset_orig) < MDF_BLOCK_HDR_LEN) {
        /* we reached the end and just claim the last space to be taken */
        return tvb_captured_length_remaining(tvb, offset_orig);
    }

    /* this is the big endian representation of the 4 letter string */
    block_id = tvb_get_ntohl(tvb, offset_orig);

    /* does it start with '##' ? */
    if ((block_id & 0xffff0000) != 0x23230000) {
        /* this is not a start of a block! we advance 8 bytes (blocks are 8-byte aligned) to recover */
        return 8;
    }

    switch (block_id) {
    case MDF_BLOCK_ID_AT_ATTACHMENT:
        length = dissect_mdf_at_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CA_CHANNEL_ARRAY:
        length = dissect_mdf_ca_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CH_CHANNEL_HIERARCHY:
        length = dissect_mdf_ch_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_EV_EVENT:
        length = dissect_mdf_ev_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_SR_SAMPLE_REDUCTION:
        length = dissect_mdf_sr_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CL_CHANNEL_LIST:
        length = dissect_mdf_cl_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CU_CHANNEL_UNION:
        length = dissect_mdf_cu_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CV_CHANNEL_VARIANT:
        length = dissect_mdf_cv_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DS_DATA_STREAM:
        length = dissect_mdf_ds_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_GD_GUARD:
        length = dissect_mdf_gd_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_RI_REDUCTION_INVAL:
        length = dissect_mdf_ri_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_RV_REDUCTION_VALUES:
        length = dissect_mdf_rv_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_VD_VLSC_DATA:
        length = dissect_mdf_vd_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CC_CONVERSION:
        length = dissect_mdf_cc_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CG_CHANNEL_GROUP:
        length = dissect_mdf_cg_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_CN_CHANNEL:
        length = dissect_mdf_cn_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DG_DATA_GROUP:
        length = dissect_mdf_dg_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DI_DATA_INVALIDATION:
        length = dissect_mdf_di_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DV_DATA_VALUES:
        length = dissect_mdf_dv_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DL_DATA_LIST:
        length = dissect_mdf_dl_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DT_DATA:
        length = dissect_mdf_dt_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_DZ_DATA_ZIPPED:
        length = dissect_mdf_dz_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_FH_FILE_HEADER:
        length = dissect_mdf_fh_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_HD_HEADER:
        length = dissect_mdf_hd_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_HL_HEADER_LIST:
        length = dissect_mdf_hl_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_LD_LIST_DATA:
        length = dissect_mdf_ld_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_MD_META_DATA:
        length = dissect_mdf_md_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_RD_REDUCTION_DATA:
        length = dissect_mdf_rd_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_SD_SIGNAL_DATA:
        length = dissect_mdf_sd_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_SI_SOURCE_INFO:
        length = dissect_mdf_si_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    case MDF_BLOCK_ID_TX_TEXT:
        length = dissect_mdf_tx_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
        break;
    default:
        length = dissect_mdf_unknown_block(tvb, offset_orig, pinfo, root_tree, data, &ti);
    }

    if (length != 0 && ti != NULL) {
        proto_item_append_text(ti, " [%d - %d]", offset_orig, offset_orig + length);
        mdf_append_summary(ti, tvb, pinfo, offset_orig, block_id);
    }

    return length;
}

static int
dissect_mdf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    int         offset = 0;
    int         bytes_parsed;
    proto_tree *mdf_tree;
    proto_item *ti;

    /* at least a complete IDBLOCK is expected */
    if (tvb_captured_length(tvb) < MDF_LEN_IDBLOCK) {
        return 0;
    }

    if (tvb_memeql(tvb, 0, mdf_magic_fin, MDF_LEN_MAGIC) != 0 && tvb_memeql(tvb, 0, mdf_magic_unf, MDF_LEN_MAGIC) != 0) {
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_mdf, tvb, offset, -1, ENC_NA);
    mdf_tree = proto_item_add_subtree(ti, ett_mdf);

    dissect_mdf_id_block(tvb, offset, pinfo, mdf_tree, data);
    offset = MDF_LEN_IDBLOCK;

    /* Blocks are always 8-byte aligned. */
    while (tvb_captured_length_remaining(tvb, offset) > 0) {
        bytes_parsed = dissect_mdf_block(tvb, offset, pinfo, mdf_tree, data);
        if (bytes_parsed <= 0) {
            break;
        }
        offset += bytes_parsed;
        offset = (offset + 7) & ~7;
    }

    return MIN(offset, (int)tvb_captured_length(tvb));
}

static bool
dissect_mdf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_mdf(tvb, pinfo, tree, NULL) > 0;
}

void
proto_register_file_mdf(void) {
    static hf_register_info hf[] = {
        { &hf_mdf_id,                             { "File ID Block",                     "mdf.id_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_file,                        { "File identifier",                   "mdf.id_block.id_file",                     FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_vers,                        { "Format identifier",                 "mdf.id_block.id_vers",                     FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_prog,                        { "Program identifier",                "mdf.id_block.id_prog",                     FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_res1,                        { "Reserved 1",                        "mdf.id_block.id_res1",                     FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_ver,                         { "Version Number",                    "mdf.id_block.id_ver",                      FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_res2,                        { "Reserved 2",                        "mdf.id_block.id_res2",                     FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_unfin_flg,                   { "Unfinished Flags",                  "mdf.id_block.std_unfin_flags",             FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_id_cstom_flg,                   { "Custom Unfin. Flags",               "mdf.id_block.cst_unfin_flags",             FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_block_header,                   { "Header",                            "mdf.block.header",                         FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_id,                       { "Block Type ID",                     "mdf.block.id",                             FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_res,                      { "Reserved",                          "mdf.block.reserved",                       FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_length,                   { "Length",                            "mdf.block.length",                         FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_link_cnt,                 { "Link Count",                        "mdf.block.link_count",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_links,                    { "Links",                             "mdf.block.links",                          FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_link,                     { "Link",                              "mdf.block.link",                           FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_block_data,                     { "Data",                              "mdf.block.data",                           FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_at,                             { "Attachment Block",                  "mdf.at_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_next,                        { "Next Attachment (AT)",              "mdf.at_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_tx_filename,                 { "File Name (TX)",                    "mdf.at_block.tx_filename",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_tx_mimetype,                 { "MIME Type (TX)",                    "mdf.at_block.tx_mimetype",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_tx_comment,                  { "Comment (TX/MD)",                   "mdf.at_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_flags,                       { "Flags",                             "mdf.at_block.flags",                       FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_creator_index,               { "Creator Index",                     "mdf.at_block.creator_index",               FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_tx_filename_zip,             { "File Name Zip (TX)",                "mdf.at_block.tx_filename_zip",             FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_tx_mimetype_zip,             { "MIME Type Zip (TX)",                "mdf.at_block.tx_mimetype_zip",             FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_zip_type,                    { "Zip Type",                          "mdf.at_block.zip_type",                    FT_UINT8,         BASE_DEC,          VALS(mdf_block_at_zip_type),    0x00,       NULL, HFILL }},
        { &hf_mdf_at_path_syntax,                 { "Path Syntax",                       "mdf.at_block.path_syntax",                 FT_UINT8,         BASE_DEC,          VALS(mdf_block_at_path_syntax), 0x00,       NULL, HFILL }},
        { &hf_mdf_at_reserved,                    { "Reserved",                          "mdf.at_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_md5_checksum,                { "MD5 Checksum",                      "mdf.at_block.md5_checksum",                FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_original_size,               { "Original Size",                     "mdf.at_block.original_size",               FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_embedded_size,               { "Embedded Size",                     "mdf.at_block.embedded_size",               FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_uncompressed,                { "Uncompressed Data",                 "mdf.at_block.uncompressed",                FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_at_embedded_data,               { "Embedded Data",                     "mdf.at_block.embedded_data",               FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_cc,                             { "Conversion Block",                  "mdf.cc_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_tx_name,                     { "Name (TX)",                         "mdf.cc_block.tx_name",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_md_unit,                     { "Unit (TX/MD)",                      "mdf.cc_block.md_unit",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_md_comment,                  { "Comment (TX/MD)",                   "mdf.cc_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_cc_inverse,                  { "Inverse Conversion (CC)",           "mdf.cc_block.cc_inverse",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_cc_ref,                      { "Reference (TX/CC)",                 "mdf.cc_block.cc_ref",                      FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_type,                        { "Conversion Type",                   "mdf.cc_block.type",                        FT_UINT8,         BASE_DEC,          VALS(mdf_block_cc_type),        0x00,       NULL, HFILL }},
        { &hf_mdf_cc_precision,                   { "Precision",                         "mdf.cc_block.precision",                   FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_flags,                       { "Flags",                             "mdf.cc_block.flags",                       FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_ref_count,                   { "Reference Count",                   "mdf.cc_block.ref_count",                   FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_val_count,                   { "Value Count",                       "mdf.cc_block.val_count",                   FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_phy_range_min,               { "Physical Range Min",                "mdf.cc_block.phy_range_min",               FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_phy_range_max,               { "Physical Range Max",                "mdf.cc_block.phy_range_max",               FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cc_val,                         { "Value",                             "mdf.cc_block.val",                         FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_cg,                             { "Channel Group Block",               "mdf.cg_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_next,                        { "Next Channel Group (CG)",           "mdf.cg_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_cn_first,                    { "First Channel (CN)",                "mdf.cg_block.cn_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_tx_acq_name,                 { "Acquisition Name (TX)",             "mdf.cg_block.acq_name",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_si_acq_source,               { "Acquisition Source (SI)",           "mdf.cg_block.acq_source",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_sr_first,                    { "First Sample Reduction (SR)",       "mdf.cg_block.sr_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_md_comment,                  { "Comment (TX/MD)",                   "mdf.cg_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_cg_master,                   { "Master Channel Group (CG)",         "mdf.cg_block.cg_master",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_record_id,                   { "Record ID",                         "mdf.cg_block.record_id",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_cycle_count,                 { "Cycle Count",                       "mdf.cg_block.cycle_count",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_flags,                       { "Flags",                             "mdf.cg_block.flags",                       FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_path_separator,              { "Path Separator",                    "mdf.cg_block.path_separator",              FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_reserved,                    { "Reserved",                          "mdf.cg_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_data_bytes,                  { "Data Bytes",                        "mdf.cg_block.data_bytes",                  FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cg_inval_bytes,                 { "Invalidation Bytes",                "mdf.cg_block.inval_bytes",                 FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_cn,                             { "Channel Block",                     "mdf.cn_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_next,                        { "Next Channel (CN)",                 "mdf.cn_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_composition,                 { "Composition (CN/CA)",               "mdf.cn_block.composition",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_tx_name,                     { "Name (TX)",                         "mdf.cn_block.tx_name",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_si_source,                   { "Source (SI)",                       "mdf.cn_block.si_source",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_cc_conversion,               { "Conversion (CC)",                   "mdf.cn_block.cc_conversion",               FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_data,                        { "Signal Data (SD/CG/DL/DZ)",         "mdf.cn_block.data",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_md_unit,                     { "Unit (TX/MD)",                      "mdf.cn_block.md_unit",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_md_comment,                  { "Comment (TX/MD)",                   "mdf.cn_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_at_reference,                { "Attachment (AT)",                   "mdf.cn_block.at_reference",                FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_default_x,                   { "Default X Axis (DG/CG/CN)",         "mdf.cn_block.default_x",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_type,                        { "Type",                              "mdf.cn_block.type",                        FT_UINT8,         BASE_HEX,          VALS(mdf_block_cn_type),        0x00,       NULL, HFILL }},
        { &hf_mdf_cn_sync_type,                   { "Sync Type",                         "mdf.cn_block.sync_type",                   FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_data_type,                   { "Data Type",                         "mdf.cn_block.data_type",                   FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_bit_offset,                  { "Bit Offset",                        "mdf.cn_block.bit_offset",                  FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_byte_offset,                 { "Byte Offset",                       "mdf.cn_block.byte_offset",                 FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_bit_count,                   { "Bit Count",                         "mdf.cn_block.bit_count",                   FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_flags,                       { "Flags",                             "mdf.cn_block.flags",                       FT_UINT32,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_inval_bit_pos,               { "Invalidation Bit Position",         "mdf.cn_block.inval_bit_pos",               FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_precision,                   { "Precision",                         "mdf.cn_block.precision",                   FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_cn_size,                     { "Size Channel (CN)",                 "mdf.cn_block.cn_size",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_alignment,                   { "Alignment",                         "mdf.cn_block.alignment",                   FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_attachment_count,            { "Attachment Count",                  "mdf.cn_block.attachment_count",            FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_val_range_min,               { "Minimal Signal Value",              "mdf.cn_block.val_range_min",               FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_val_range_max,               { "Maximal Signal Value",              "mdf.cn_block.val_range_max",               FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_limit_min,                   { "Lower Limit",                       "mdf.cn_block.limit_min",                   FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_limit_max,                   { "Upper Limit",                       "mdf.cn_block.limit_max",                   FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_limit_ext_min,               { "Lower Extended Limit",              "mdf.cn_block.limit_ext_min",               FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cn_limit_ext_max,               { "Upper Extended Limit",              "mdf.cn_block.limit_ext_max",               FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_dg,                             { "Data Group Block",                  "mdf.dg_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dg_next,                        { "Next Data Group (DG)",              "mdf.dg_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dg_cg_first,                    { "First Channel Group (CG)",          "mdf.dg_block.cg_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dg_data,                        { "Data (DT/DZ/DL/HL/GD)",             "mdf.dg_block.data",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dg_md_comment,                  { "Comment (TX/MD)",                   "mdf.dg_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dg_rec_id_size,                 { "Record ID Size",                    "mdf.dg_block.rec_id_size",                 FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dg_reserved,                    { "Reserved",                          "mdf.dg_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_dl,                             { "Data List Block",                   "mdf.dl_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_next,                        { "Next Data List (DL)",               "mdf.dl_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_data_link,                   { "Data (DT/SD/VD/RD/DZ)",             "mdf.dl_block.data_link",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_flags,                       { "Flags",                             "mdf.dl_block.flags",                       FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_reserved,                    { "Reserved",                          "mdf.dl_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_count,                       { "Data Block Count",                  "mdf.dl_block.count",                       FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_equal_length,                { "Equal Data Length",                 "mdf.dl_block.equal_length",                FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_offset,                      { "Data Offset",                       "mdf.dl_block.offset",                      FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_time_value,                  { "First Time Value",                  "mdf.dl_block.time_value",                  FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_angle_value,                 { "First Angle Value",                 "mdf.dl_block.angle_value",                 FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dl_distance_value,              { "First Distance Value",              "mdf.dl_block.distance_value",              FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_hl,                             { "Header List Block",                 "mdf.hl_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hl_dl_first,                    { "First Data List (DL)",              "mdf.hl_block.dl_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hl_flags,                       { "Flags",                             "mdf.hl_block.flags",                       FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hl_zip_type,                    { "Zip algorithm used",                "mdf.hl_block.zip_type",                    FT_UINT8,         BASE_DEC,          VALS(mdf_block_dz_zip_type),    0x00,       NULL, HFILL }},
        { &hf_mdf_hl_reserved,                    { "Reserved",                          "mdf.hl_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_ld,                             { "List Data Block",                   "mdf.ld_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_next,                        { "Next List Data (LD)",               "mdf.ld_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_data_link,                   { "Data (DV/RV/DZ)",                   "mdf.ld_block.data_link",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_inval_link,                  { "Invalidation Data (DI/RI/DZ)",      "mdf.ld_block.inval_link",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_flags,                       { "Flags",                             "mdf.ld_block.flags",                       FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_count,                       { "Data Block Count",                  "mdf.ld_block.count",                       FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_equal_sample_count,          { "Equal Sample Count",                "mdf.ld_block.equal_sample_count",          FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_sample_offset,               { "Sample Offset",                     "mdf.ld_block.sample_offset",               FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_time_value,                  { "First Time Value",                  "mdf.ld_block.time_value",                  FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_angle_value,                 { "First Angle Value",                 "mdf.ld_block.angle_value",                 FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_distance_value,              { "First Distance Value",              "mdf.ld_block.distance_value",              FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_sd,                             { "Signal Data Block",                 "mdf.sd_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sd_data,                        { "Data",                              "mdf.sd_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_rd,                             { "Reduction Data Block",              "mdf.rd_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_rd_data,                        { "Data",                              "mdf.rd_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_ca,                             { "Channel Array Block",               "mdf.ca_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_composition,                 { "Composition (CN/CA)",               "mdf.ca_block.composition",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_data,                        { "Data (DG/CG/CN)",                   "mdf.ca_block.data",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_dynamic_size,                { "Dynamic Size (CN)",                 "mdf.ca_block.dynamic_size",                FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_input_quantity,              { "Input Quantity (CN)",               "mdf.ca_block.input_quantity",              FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_output_quantity,             { "Output Quantity (CN)",              "mdf.ca_block.output_quantity",             FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_comparison_quantity,         { "Comparison Quantity (CN)",          "mdf.ca_block.comparison_quantity",         FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_cc_axis_conversion,          { "Axis Conversion (CC)",              "mdf.ca_block.cc_axis_conversion",          FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_axis_link,                   { "Axis (DG/CG/CN)",                   "mdf.ca_block.axis_link",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_type,                        { "Type",                              "mdf.ca_block.type",                        FT_UINT8,         BASE_DEC,          VALS(mdf_block_ca_type),        0x00,       NULL, HFILL }},
        { &hf_mdf_ca_storage,                     { "Storage",                           "mdf.ca_block.storage",                     FT_UINT8,         BASE_DEC,          VALS(mdf_block_ca_storage),     0x00,       NULL, HFILL }},
        { &hf_mdf_ca_ndim,                        { "Number of Dimensions",              "mdf.ca_block.ndim",                        FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_flags,                       { "Flags",                             "mdf.ca_block.flags",                       FT_UINT32,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_byte_offset_base,            { "Byte Offset Base",                  "mdf.ca_block.byte_offset_base",            FT_INT32,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_inval_bit_pos_base,          { "Invalidation Bit Position Base",    "mdf.ca_block.inval_bit_pos_base",          FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_dim_size,                    { "Dimension Size",                    "mdf.ca_block.dim_size",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_axis_value,                  { "Axis Value",                        "mdf.ca_block.axis_value",                  FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ca_cycle_count,                 { "Cycle Count",                       "mdf.ca_block.cycle_count",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch,                             { "Channel Hierarchy Block",           "mdf.ch_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_next,                        { "Next Sibling (CH)",                 "mdf.ch_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_first,                       { "First Child (CH)",                  "mdf.ch_block.first",                       FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_tx_name,                     { "Name (TX)",                         "mdf.ch_block.tx_name",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_md_comment,                  { "Comment (TX/MD)",                   "mdf.ch_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_dg,                          { "Element Data Group (DG)",           "mdf.ch_block.dg",                          FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_cg,                          { "Element Channel Group (CG)",        "mdf.ch_block.cg",                          FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_cn,                          { "Element Channel (CN)",              "mdf.ch_block.cn",                          FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_element_count,               { "Element Count",                     "mdf.ch_block.element_count",               FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ch_type,                        { "Hierarchy Type",                    "mdf.ch_block.type",                        FT_UINT8,         BASE_DEC,          VALS(mdf_block_ch_type),        0x00,       NULL, HFILL }},
        { &hf_mdf_ch_reserved,                    { "Reserved",                          "mdf.ch_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev,                             { "Event Block",                       "mdf.ev_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_next,                        { "Next Event (EV)",                   "mdf.ev_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_parent,                      { "Parent Event (EV)",                 "mdf.ev_block.parent",                      FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_range,                       { "Range Begin Event (EV)",            "mdf.ev_block.range",                       FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_tx_name,                     { "Name (TX)",                         "mdf.ev_block.tx_name",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_md_comment,                  { "Comment (TX/MD)",                   "mdf.ev_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_scope,                       { "Scope (CG/CN)",                     "mdf.ev_block.scope",                       FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_at_reference,                { "Attachment (AT)",                   "mdf.ev_block.at_reference",                FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_type,                        { "Type",                              "mdf.ev_block.type",                        FT_UINT8,         BASE_DEC,          VALS(mdf_block_ev_type),        0x00,       NULL, HFILL }},
        { &hf_mdf_ev_sync_type,                   { "Sync Type",                         "mdf.ev_block.sync_type",                   FT_UINT8,         BASE_DEC,          VALS(mdf_block_sync_type),      0x00,       NULL, HFILL }},
        { &hf_mdf_ev_range_type,                  { "Range Type",                        "mdf.ev_block.range_type",                  FT_UINT8,         BASE_DEC,          VALS(mdf_block_ev_range_type),  0x00,       NULL, HFILL }},
        { &hf_mdf_ev_cause,                       { "Cause",                             "mdf.ev_block.cause",                       FT_UINT8,         BASE_DEC,          VALS(mdf_block_ev_cause),       0x00,       NULL, HFILL }},
        { &hf_mdf_ev_flags,                       { "Flags",                             "mdf.ev_block.flags",                       FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_reserved,                    { "Reserved",                          "mdf.ev_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_scope_count,                 { "Scope Count",                       "mdf.ev_block.scope_count",                 FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_attachment_count,            { "Attachment Count",                  "mdf.ev_block.attachment_count",            FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_creator_index,               { "Creator Index",                     "mdf.ev_block.creator_index",               FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_sync_base_value,             { "Sync Base Value",                   "mdf.ev_block.sync_base_value",             FT_INT64,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_sync_factor,                 { "Sync Factor",                       "mdf.ev_block.sync_factor",                 FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr,                             { "Sample Reduction Block",            "mdf.sr_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr_next,                        { "Next Sample Reduction (SR)",        "mdf.sr_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr_data,                        { "Data (RD/DZ/DL/HL)",                "mdf.sr_block.data",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr_cycle_count,                 { "Cycle Count",                       "mdf.sr_block.cycle_count",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr_interval,                    { "Interval",                          "mdf.sr_block.interval",                    FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr_sync_type,                   { "Sync Type",                         "mdf.sr_block.sync_type",                   FT_UINT8,         BASE_DEC,          VALS(mdf_block_sync_type),      0x00,       NULL, HFILL }},
        { &hf_mdf_sr_flags,                       { "Flags",                             "mdf.sr_block.flags",                       FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_sr_reserved,                    { "Reserved",                          "mdf.sr_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_di,                             { "Data Invalidation Block",           "mdf.di_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_di_data,                        { "Invalidation Data",                 "mdf.di_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dv,                             { "Data Values Block",                 "mdf.dv_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dv_data,                        { "Data",                              "mdf.dv_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_cl,                             { "Channel List Block",                "mdf.cl_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cl_composition,                 { "Composition (CN/CL/CV/CU/DS)",      "mdf.cl_block.composition",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cl_cn_size,                     { "Size Channel (CN)",                 "mdf.cl_block.cn_size",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cl_flags,                       { "Flags",                             "mdf.cl_block.flags",                       FT_UINT16,        BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cl_alignment,                   { "Alignment",                         "mdf.cl_block.alignment",                   FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cl_bit_offset,                  { "Bit Offset",                        "mdf.cl_block.bit_offset",                  FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cl_byte_offset,                 { "Byte Offset",                       "mdf.cl_block.byte_offset",                 FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cu,                             { "Channel Union Block",               "mdf.cu_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cu_cn_member,                   { "Member Channel (CN)",               "mdf.cu_block.cn_member",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cu_member_count,                { "Member Count",                      "mdf.cu_block.member_count",                FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cu_reserved,                    { "Reserved",                          "mdf.cu_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cv,                             { "Channel Variant Block",             "mdf.cv_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cv_cn_discriminator,            { "Discriminator Channel (CN)",        "mdf.cv_block.cn_discriminator",            FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cv_cn_option,                   { "Option Channel (CN)",               "mdf.cv_block.cn_option",                   FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cv_option_count,                { "Option Count",                      "mdf.cv_block.option_count",                FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cv_reserved,                    { "Reserved",                          "mdf.cv_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_cv_option_val,                  { "Option Value",                      "mdf.cv_block.option_val",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ds,                             { "Data Stream Block",                 "mdf.ds_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ds_cn_composition,              { "Composition (CN)",                  "mdf.ds_block.cn_composition",              FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ds_cn_alignment_start,          { "Alignment Start Channel (CN)",      "mdf.ds_block.cn_alignment_start",          FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ds_version,                     { "Minimum MDF Version",               "mdf.ds_block.version",                     FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ds_mode,                        { "Mode",                              "mdf.ds_block.mode",                        FT_UINT8,         BASE_DEC,          VALS(mdf_block_ds_mode),        0x00,       NULL, HFILL }},
        { &hf_mdf_ds_reserved,                    { "Reserved",                          "mdf.ds_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_gd,                             { "Guard Block",                       "mdf.gd_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_gd_link,                        { "Guarded Block",                     "mdf.gd_block.link",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_gd_version,                     { "Minimum MDF Version",               "mdf.gd_block.version",                     FT_UINT16,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_gd_reserved,                    { "Reserved",                          "mdf.gd_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ri,                             { "Reduction Invalidation Data Block", "mdf.ri_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ri_data,                        { "Invalidation Data",                 "mdf.ri_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_rv,                             { "Reduction Values Block",            "mdf.rv_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_rv_data,                        { "Data",                              "mdf.rv_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_vd,                             { "VLSC Data Block",                   "mdf.vd_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_vd_data,                        { "Data",                              "mdf.vd_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ld_zip_info,                    { "Zip Info Data",                     "mdf.ld_block.zip_info",                    FT_UINT8,         BASE_DEC,          VALS(mdf_block_ld_zip_info),    0x00,       NULL, HFILL }},
        { &hf_mdf_ld_zip_info_inval,              { "Zip Info Invalidation Data",        "mdf.ld_block.zip_info_inval",              FT_UINT8,         BASE_DEC,          VALS(mdf_block_ld_zip_info),    0x00,       NULL, HFILL }},
        { &hf_mdf_ld_flags_ext,                   { "Extended Flags",                    "mdf.ld_block.flags_ext",                   FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_ev_tx_group_name,               { "Group Name (TX)",                   "mdf.ev_block.tx_group_name",               FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_dt,                             { "Data Block",                        "mdf.dt_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dt_data,                        { "Data",                              "mdf.dt_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_dz,                             { "Data Zipped Block",                 "mdf.dz_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_org_block_type,              { "Block Type Original Data",          "mdf.dz_block.org_block_type",              FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_zip_type,                    { "Zip algorithm used",                "mdf.dz_block.zip_type",                    FT_UINT8,         BASE_DEC,          VALS(mdf_block_dz_zip_type),    0x00,       NULL, HFILL }},
        { &hf_mdf_dz_reserved,                    { "Reserved",                          "mdf.dz_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_zip_parameter,               { "Zip Parameter",                     "mdf.dz_block.zip_parameter",               FT_UINT32,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_org_data_length,             { "Length uncompressed",               "mdf.dz_block.org_data_length",             FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_data_length,                 { "Length",                            "mdf.dz_block.data_length",                 FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_data,                        { "Compressed Data",                   "mdf.dz_block.data",                        FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_dz_uncompressed,                { "Uncompressed Data",                 "mdf.dz_block.uncompressed",                FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_fh,                             { "File History Block",                "mdf.fh_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_next,                        { "Next File History (FH)",            "mdf.fh_block.next",                        FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_comment,                     { "Comment (MD)",                      "mdf.fh_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_time_ns,                     { "Time",                              "mdf.fh_block.time",                        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_tz_offset_min,               { "Time Zone Offset (mins)",           "mdf.fh_block.tz_offset_min",               FT_INT16,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_dst_offset_min,              { "Daylight Saving Time off.",         "mdf.fh_block.dst_offset_min",              FT_INT16,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_time_flags,                  { "Time Flags",                        "mdf.fh_block.time_flags",                  FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_fh_reserved,                    { "Reserved",                          "mdf.fh_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_hd,                             { "File Header Block",                 "mdf.hd_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_dg_first,                    { "First Data Group (DG)",             "mdf.hd_block.dg_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_fh_first,                    { "First File History (FH)",           "mdf.hd_block.fh_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_ch_first,                    { "First Channel Hierarchy (CH)",      "mdf.hd_block.ch_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_at_first,                    { "First Attachment (AT)",             "mdf.hd_block.at_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_ev_first,                    { "First Event (EV)",                  "mdf.hd_block.ev_first",                    FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_md_comment,                  { "Comment (MD)",                      "mdf.hd_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_start_time_ns,               { "Start Time",                        "mdf.hd_block.start_time",                  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_tz_offset_min,               { "Time Zone Offset (mins)",           "mdf.hd_block.tz_offset_min",               FT_INT16,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_dst_offset_min,              { "Daylight Saving Time off.",         "mdf.hd_block.dst_offset_min",              FT_INT16,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_time_flags,                  { "Time Flags",                        "mdf.hd_block.time_flags",                  FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_time_class,                  { "Time Class",                        "mdf.hd_block.time_class",                  FT_UINT8,         BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_flags,                       { "Flags",                             "mdf.hd_block.flags",                       FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_reserved,                    { "Reserved",                          "mdf.hd_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_start_angle_rad,             { "Start Angle (rad)",                 "mdf.hd_block.start_angle_rad",             FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_hd_start_distance_m,            { "Start Distance (m)",                "mdf.hd_block.start_distance_m",            FT_DOUBLE,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_md,                             { "Meta Data Block",                   "mdf.md_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_md_data,                        { "Meta Data",                         "mdf.md_block.data",                        FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_si,                             { "Source Information",                "mdf.si_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_si_tx_name,                     { "Name (TX)",                         "mdf.si_block.tx_name",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_si_tx_path,                     { "Path (TX)",                         "mdf.si_block.tx_path",                     FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_si_md_comment,                  { "Comment (TX/MD)",                   "mdf.si_block.md_comment",                  FT_UINT64,        BASE_DEC,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_si_type,                        { "Type",                              "mdf.si_block.type",                        FT_UINT8,         BASE_DEC,          VALS(mdf_block_si_type),        0x00,       NULL, HFILL }},
        { &hf_mdf_si_bus_type,                    { "Bus Type",                          "mdf.si_block.bus_type",                    FT_UINT8,         BASE_DEC,          VALS(mdf_block_si_bus_type),    0x00,       NULL, HFILL }},
        { &hf_mdf_si_flags,                       { "Flags",                             "mdf.si_block.flags",                       FT_UINT8,         BASE_HEX,          NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_si_reserved,                    { "Reserved",                          "mdf.si_block.reserved",                    FT_BYTES,         BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_tx,                             { "Text Block",                        "mdf.tx_block",                             FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},
        { &hf_mdf_tx_data,                        { "Text Data",                         "mdf.tx_block.data",                        FT_STRING,        BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

        { &hf_mdf_at_flags_embedded,              { "Embedded Data",                     "mdf.at_block.flags.embedded",              FT_BOOLEAN,       16,                NULL,                           0x0001,     NULL, HFILL }},
        { &hf_mdf_at_flags_compressed,            { "Compressed Embedded Data",          "mdf.at_block.flags.compressed",            FT_BOOLEAN,       16,                NULL,                           0x0002,     NULL, HFILL }},
        { &hf_mdf_at_flags_md5_valid,             { "MD5 Checksum Valid",                "mdf.at_block.flags.md5_valid",             FT_BOOLEAN,       16,                NULL,                           0x0004,     NULL, HFILL }},
        { &hf_mdf_cc_flags_precision_valid,       { "Precision Valid",                   "mdf.cc_block.flags.precision_valid",       FT_BOOLEAN,       16,                NULL,                           0x0001,     NULL, HFILL }},
        { &hf_mdf_cc_flags_range_valid,           { "Physical Range Valid",              "mdf.cc_block.flags.range_valid",           FT_BOOLEAN,       16,                NULL,                           0x0002,     NULL, HFILL }},
        { &hf_mdf_cc_flags_status_string,         { "Status String",                     "mdf.cc_block.flags.status_string",         FT_BOOLEAN,       16,                NULL,                           0x0004,     NULL, HFILL }},
        { &hf_mdf_dl_flags_equal_length,          { "Equal Length Data Blocks",          "mdf.dl_block.flags.equal_length",          FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_dl_flags_time_values,           { "Time Values Present",               "mdf.dl_block.flags.time_values",           FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_dl_flags_angle_values,          { "Angle Values Present",              "mdf.dl_block.flags.angle_values",          FT_BOOLEAN,       8,                 NULL,                           0x04,       NULL, HFILL }},
        { &hf_mdf_dl_flags_distance_values,       { "Distance Values Present",           "mdf.dl_block.flags.distance_values",       FT_BOOLEAN,       8,                 NULL,                           0x08,       NULL, HFILL }},
        { &hf_mdf_hl_flags_equal_length,          { "Equal Length Data Blocks",          "mdf.hl_block.flags.equal_length",          FT_BOOLEAN,       16,                NULL,                           0x0001,     NULL, HFILL }},
        { &hf_mdf_hl_flags_time_values,           { "Time Values Present",               "mdf.hl_block.flags.time_values",           FT_BOOLEAN,       16,                NULL,                           0x0002,     NULL, HFILL }},
        { &hf_mdf_hl_flags_angle_values,          { "Angle Values Present",              "mdf.hl_block.flags.angle_values",          FT_BOOLEAN,       16,                NULL,                           0x0004,     NULL, HFILL }},
        { &hf_mdf_hl_flags_distance_values,       { "Distance Values Present",           "mdf.hl_block.flags.distance_values",       FT_BOOLEAN,       16,                NULL,                           0x0008,     NULL, HFILL }},
        { &hf_mdf_ld_flags_equal_length,          { "Equal Sample Count",                "mdf.ld_block.flags.equal_length",          FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_ld_flags_time_values,           { "Time Values Present",               "mdf.ld_block.flags.time_values",           FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_ld_flags_angle_values,          { "Angle Values Present",              "mdf.ld_block.flags.angle_values",          FT_BOOLEAN,       8,                 NULL,                           0x04,       NULL, HFILL }},
        { &hf_mdf_ld_flags_distance_values,       { "Distance Values Present",           "mdf.ld_block.flags.distance_values",       FT_BOOLEAN,       8,                 NULL,                           0x08,       NULL, HFILL }},
        { &hf_mdf_ca_flags_dynamic_size,          { "Dynamic Size",                      "mdf.ca_block.flags.dynamic_size",          FT_BOOLEAN,       32,                NULL,                           0x00000001, NULL, HFILL }},
        { &hf_mdf_ca_flags_input_quantity,        { "Input Quantity",                    "mdf.ca_block.flags.input_quantity",        FT_BOOLEAN,       32,                NULL,                           0x00000002, NULL, HFILL }},
        { &hf_mdf_ca_flags_output_quantity,       { "Output Quantity",                   "mdf.ca_block.flags.output_quantity",       FT_BOOLEAN,       32,                NULL,                           0x00000004, NULL, HFILL }},
        { &hf_mdf_ca_flags_comparison_quantity,   { "Comparison Quantity",               "mdf.ca_block.flags.comparison_quantity",   FT_BOOLEAN,       32,                NULL,                           0x00000008, NULL, HFILL }},
        { &hf_mdf_ca_flags_axis,                  { "Axis",                              "mdf.ca_block.flags.axis",                  FT_BOOLEAN,       32,                NULL,                           0x00000010, NULL, HFILL }},
        { &hf_mdf_ca_flags_fixed_axis,            { "Fixed Axis",                        "mdf.ca_block.flags.fixed_axis",            FT_BOOLEAN,       32,                NULL,                           0x00000020, NULL, HFILL }},
        { &hf_mdf_ca_flags_inverse_layout,        { "Inverse Layout",                    "mdf.ca_block.flags.inverse_layout",        FT_BOOLEAN,       32,                NULL,                           0x00000040, NULL, HFILL }},
        { &hf_mdf_ca_flags_left_open,             { "Left-Open Intervals",               "mdf.ca_block.flags.left_open",             FT_BOOLEAN,       32,                NULL,                           0x00000080, NULL, HFILL }},
        { &hf_mdf_ev_flags_post_processing,       { "Post Processing",                   "mdf.ev_block.flags.post_processing",       FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_sr_flags_inval_bytes,           { "Invalidation Bytes Present",        "mdf.sr_block.flags.inval_bytes",           FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_sr_flags_dominant_inval,        { "Dominant Invalidation Bit",         "mdf.sr_block.flags.dominant_inval",        FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_cl_flags_size_is_count,         { "Size Represents Number of Items",   "mdf.cl_block.flags.size_is_count",         FT_BOOLEAN,       16,                NULL,                           0x0001,     NULL, HFILL }},
        { &hf_mdf_cl_flags_alignment_reset,       { "Alignment Reset",                   "mdf.cl_block.flags.alignment_reset",       FT_BOOLEAN,       16,                NULL,                           0x0002,     NULL, HFILL }},
        { &hf_mdf_ld_flags_zip_info_valid,        { "Zip Info Valid",                    "mdf.ld_block.flags.zip_info_valid",        FT_BOOLEAN,       8,                 NULL,                           0x80,       NULL, HFILL }},
        { &hf_mdf_ld_flags_ext_inval_data,        { "Invalidation Data Present",         "mdf.ld_block.flags_ext.inval_data",        FT_BOOLEAN,       8,                 NULL,                           0x80,       NULL, HFILL }},
        { &hf_mdf_ev_flags_group_name,            { "Group Name Present",                "mdf.ev_block.flags.group_name",            FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_at_flags_general_zip,           { "General Compressed Embedded Data",  "mdf.at_block.flags.general_zip",           FT_BOOLEAN,       16,                NULL,                           0x0008,     NULL, HFILL }},
        { &hf_mdf_at_flags_zip_filename,          { "Zip File Name Valid",               "mdf.at_block.flags.zip_filename",          FT_BOOLEAN,       16,                NULL,                           0x0010,     NULL, HFILL }},
        { &hf_mdf_at_flags_zip_mimetype,          { "Zip MIME Type Valid",               "mdf.at_block.flags.zip_mimetype",          FT_BOOLEAN,       16,                NULL,                           0x0020,     NULL, HFILL }},
        { &hf_mdf_cg_flags_vlsc,                  { "VLSC Channel Group",                "mdf.cg_block.flags.vlsc",                  FT_BOOLEAN,       16,                NULL,                           0x0020,     NULL, HFILL }},
        { &hf_mdf_cg_flags_raw_sensor_event,      { "Raw Sensor Event Channel Group",    "mdf.cg_block.flags.raw_sensor_event",      FT_BOOLEAN,       16,                NULL,                           0x0040,     NULL, HFILL }},
        { &hf_mdf_cg_flags_protocol_event,        { "Protocol Event Channel Group",      "mdf.cg_block.flags.protocol_event",        FT_BOOLEAN,       16,                NULL,                           0x0080,     NULL, HFILL }},
        { &hf_mdf_cn_flags_raw_sensor_event,      { "Raw Sensor Event",                  "mdf.cn_block.flags.raw_sensor_event",      FT_BOOLEAN,       32,                NULL,                           0x00008000, NULL, HFILL }},
        { &hf_mdf_cn_flags_auxiliary,             { "Auxiliary Channel",                 "mdf.cn_block.flags.auxiliary",             FT_BOOLEAN,       32,                NULL,                           0x00010000, NULL, HFILL }},
        { &hf_mdf_cn_flags_data_stream_mode,      { "Data Stream Mode",                  "mdf.cn_block.flags.data_stream_mode",      FT_BOOLEAN,       32,                NULL,                           0x00020000, NULL, HFILL }},
        { &hf_mdf_cn_flags_alignment_reset,       { "Alignment Reset",                   "mdf.cn_block.flags.alignment_reset",       FT_BOOLEAN,       32,                NULL,                           0x00040000, NULL, HFILL }},
        { &hf_mdf_cn_flags_protocol_event,        { "Protocol Event",                    "mdf.cn_block.flags.protocol_event",        FT_BOOLEAN,       32,                NULL,                           0x00080000, NULL, HFILL }},
        { &hf_mdf_cn_flags_data_description_mode, { "Data Description Mode",             "mdf.cn_block.flags.data_description_mode", FT_BOOLEAN,       32,                NULL,                           0x00100000, NULL, HFILL }},
        { &hf_mdf_cg_flags_vlsd,                  { "VLSD Channel Group",                "mdf.cg_block.flags.vlsd",                  FT_BOOLEAN,       16,                NULL,                           0x0001,     NULL, HFILL }},
        { &hf_mdf_cg_flags_bus_event,             { "Bus Event Channel Group",           "mdf.cg_block.flags.bus_event",             FT_BOOLEAN,       16,                NULL,                           0x0002,     NULL, HFILL }},
        { &hf_mdf_cg_flags_plain_bus_event,       { "Plain Bus Event Channel Group",     "mdf.cg_block.flags.plain_bus_event",       FT_BOOLEAN,       16,                NULL,                           0x0004,     NULL, HFILL }},
        { &hf_mdf_cg_flags_remote_master,         { "Remote Master",                     "mdf.cg_block.flags.remote_master",         FT_BOOLEAN,       16,                NULL,                           0x0008,     NULL, HFILL }},
        { &hf_mdf_cg_flags_event_signal,          { "Event Signal Group",                "mdf.cg_block.flags.event_signal",          FT_BOOLEAN,       16,                NULL,                           0x0010,     NULL, HFILL }},
        { &hf_mdf_cn_flags_all_inval,             { "All Values Invalid",                "mdf.cn_block.flags.all_inval",             FT_BOOLEAN,       32,                NULL,                           0x00000001, NULL, HFILL }},
        { &hf_mdf_cn_flags_inval_bit_valid,       { "Invalidation Bit Valid",            "mdf.cn_block.flags.inval_bit_valid",       FT_BOOLEAN,       32,                NULL,                           0x00000002, NULL, HFILL }},
        { &hf_mdf_cn_flags_precision_valid,       { "Precision Valid",                   "mdf.cn_block.flags.precision_valid",       FT_BOOLEAN,       32,                NULL,                           0x00000004, NULL, HFILL }},
        { &hf_mdf_cn_flags_val_range_valid,       { "Value Range Valid",                 "mdf.cn_block.flags.val_range_valid",       FT_BOOLEAN,       32,                NULL,                           0x00000008, NULL, HFILL }},
        { &hf_mdf_cn_flags_limit_valid,           { "Limit Range Valid",                 "mdf.cn_block.flags.limit_valid",           FT_BOOLEAN,       32,                NULL,                           0x00000010, NULL, HFILL }},
        { &hf_mdf_cn_flags_limit_ext_valid,       { "Extended Limit Range Valid",        "mdf.cn_block.flags.limit_ext_valid",       FT_BOOLEAN,       32,                NULL,                           0x00000020, NULL, HFILL }},
        { &hf_mdf_cn_flags_discrete,              { "Discrete Value Range",              "mdf.cn_block.flags.discrete",              FT_BOOLEAN,       32,                NULL,                           0x00000040, NULL, HFILL }},
        { &hf_mdf_cn_flags_calibration,           { "Calibration",                       "mdf.cn_block.flags.calibration",           FT_BOOLEAN,       32,                NULL,                           0x00000080, NULL, HFILL }},
        { &hf_mdf_cn_flags_calculated,            { "Calculated",                        "mdf.cn_block.flags.calculated",            FT_BOOLEAN,       32,                NULL,                           0x00000100, NULL, HFILL }},
        { &hf_mdf_cn_flags_virtual,               { "Virtual",                           "mdf.cn_block.flags.virtual",               FT_BOOLEAN,       32,                NULL,                           0x00000200, NULL, HFILL }},
        { &hf_mdf_cn_flags_bus_event,             { "Bus Event",                         "mdf.cn_block.flags.bus_event",             FT_BOOLEAN,       32,                NULL,                           0x00000400, NULL, HFILL }},
        { &hf_mdf_cn_flags_monotonous,            { "Strictly Monotonous",               "mdf.cn_block.flags.monotonous",            FT_BOOLEAN,       32,                NULL,                           0x00000800, NULL, HFILL }},
        { &hf_mdf_cn_flags_default_x,             { "Default X Axis",                    "mdf.cn_block.flags.default_x",             FT_BOOLEAN,       32,                NULL,                           0x00001000, NULL, HFILL }},
        { &hf_mdf_cn_flags_event_signal,          { "Event Signal",                      "mdf.cn_block.flags.event_signal",          FT_BOOLEAN,       32,                NULL,                           0x00002000, NULL, HFILL }},
        { &hf_mdf_cn_flags_vlsd_stream,           { "VLSD Data Stream",                  "mdf.cn_block.flags.vlsd_stream",           FT_BOOLEAN,       32,                NULL,                           0x00004000, NULL, HFILL }},
        { &hf_mdf_fh_time_flags_local_time,       { "Local Time",                        "mdf.fh_block.time_flags.local_time",       FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_fh_time_flags_offsets_valid,    { "Time Offsets Valid",                "mdf.fh_block.time_flags.offsets_valid",    FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_hd_time_flags_local_time,       { "Local Time",                        "mdf.hd_block.time_flags.local_time",       FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_hd_time_flags_offsets_valid,    { "Time Offsets Valid",                "mdf.hd_block.time_flags.offsets_valid",    FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_hd_flags_angle_valid,           { "Start Angle Valid",                 "mdf.hd_block.flags.angle_valid",           FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},
        { &hf_mdf_hd_flags_distance_valid,        { "Start Distance Valid",              "mdf.hd_block.flags.distance_valid",        FT_BOOLEAN,       8,                 NULL,                           0x02,       NULL, HFILL }},
        { &hf_mdf_si_flags_simulated,             { "Simulated Source",                  "mdf.si_block.flags.simulated",             FT_BOOLEAN,       8,                 NULL,                           0x01,       NULL, HFILL }},

        { &hf_mdf_unknown_block,                  { "--- Unknown Block",                 "mdf.unknown_block",                        FT_NONE,          BASE_NONE,         NULL,                           0x00,       NULL, HFILL }},

    };

    static int *ett[] = {
        &ett_mdf,
        &ett_mdf_block_header,
        &ett_mdf_block_links,
        &ett_mdf_block_data,
        &ett_mdf_block_id,
        &ett_mdf_block_at,
        &ett_mdf_block_cc,
        &ett_mdf_block_cg,
        &ett_mdf_block_cn,
        &ett_mdf_block_dg,
        &ett_mdf_block_dl,
        &ett_mdf_block_hl,
        &ett_mdf_block_ld,
        &ett_mdf_block_sd,
        &ett_mdf_block_rd,
        &ett_mdf_block_ca,
        &ett_mdf_block_ch,
        &ett_mdf_block_ev,
        &ett_mdf_block_sr,
        &ett_mdf_block_di,
        &ett_mdf_block_dv,
        &ett_mdf_block_cl,
        &ett_mdf_block_cu,
        &ett_mdf_block_cv,
        &ett_mdf_block_ds,
        &ett_mdf_block_gd,
        &ett_mdf_block_ri,
        &ett_mdf_block_rv,
        &ett_mdf_block_vd,
        &ett_mdf_cl_flags,
        &ett_mdf_ld_flags_ext,
        &ett_mdf_block_dt,
        &ett_mdf_block_dz,
        &ett_mdf_block_fh,
        &ett_mdf_block_hd,
        &ett_mdf_block_md,
        &ett_mdf_block_si,
        &ett_mdf_block_tx,
        &ett_mdf_unknownblock,
        &ett_mdf_at_flags,
        &ett_mdf_cc_flags,
        &ett_mdf_ca_flags,
        &ett_mdf_ev_flags,
        &ett_mdf_sr_flags,
        &ett_mdf_dl_flags,
        &ett_mdf_hl_flags,
        &ett_mdf_ld_flags,
        &ett_mdf_cg_flags,
        &ett_mdf_cn_flags,
        &ett_mdf_fh_time_flags,
        &ett_mdf_hd_time_flags,
        &ett_mdf_hd_flags,
        &ett_mdf_si_flags,
    };

    static ei_register_info ei[] = {
        { &ei_mdf_block_malformed, { "mdf.block.malformed", PI_MALFORMED, PI_ERROR,
            "Block length or link count is inconsistent with the available data", EXPFILL }},
        { &ei_mdf_too_few_links, { "mdf.block.too_few_links", PI_MALFORMED, PI_ERROR,
            "Block has fewer links than its type requires", EXPFILL }},
        { &ei_mdf_link_invalid, { "mdf.block.link_invalid", PI_MALFORMED, PI_WARN,
            "Link does not point to the start of a block in this file", EXPFILL }},
        { &ei_mdf_cc_val_count, { "mdf.cc_block.val_count_invalid", PI_MALFORMED, PI_ERROR,
            "Value count exceeds the data of the block", EXPFILL }},
        { &ei_mdf_list_count, { "mdf.block.list_count_mismatch", PI_MALFORMED, PI_WARN,
            "Count in the block does not match its link count", EXPFILL }},
        { &ei_mdf_dz_decompress_failed, { "mdf.dz_block.decompress_failed", PI_UNDECODED, PI_WARN,
            "Could not decompress the data (corrupt data or zlib not available)", EXPFILL }},
        { &ei_mdf_dz_length_mismatch, { "mdf.dz_block.length_mismatch", PI_MALFORMED, PI_WARN,
            "Uncompressed length differs from the length stated in the block", EXPFILL }},
        { &ei_mdf_dz_unsupported, { "mdf.dz_block.unsupported", PI_UNDECODED, PI_NOTE,
            "Unsupported zip type or parameter, or uncompressed length too large", EXPFILL }},
    };

    expert_module_t *expert_mdf;

    proto_mdf = proto_register_protocol("MDF File Format", "File-MDF", "file-mdf");
    proto_register_field_array(proto_mdf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mdf = expert_register_protocol(proto_mdf);
    expert_register_field_array(expert_mdf, ei, array_length(ei));

    register_dissector("file-mdf", dissect_mdf, proto_mdf);
}

void
proto_reg_handoff_file_mdf(void) {
    media_type_table = find_dissector_table("media_type");
    heur_dissector_add("wtap_file", dissect_mdf_heur, "MDF File", "mdf_wtap", proto_mdf, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
