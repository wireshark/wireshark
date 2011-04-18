/* packet-h264.c
 * Routines for H.264 dissection
 * Copyright 2007 - 2009, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References:
 * http://www.ietf.org/rfc/rfc3984.txt?number=3984
 * http://www.itu.int/rec/T-REC-H.264/en
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/asn1.h>
#include <epan/strutil.h>

#include <epan/prefs.h>


/* Initialize the protocol and registered fields */
static int proto_h264								= -1;
static int hf_h264_type								= -1;
static int hf_h264_nal_f_bit						= -1;
static int hf_h264_nal_nri							= -1;
static int hf_h264_start_bit						= -1;
static int hf_h264_forbidden_bit					= -1;
static int hf_h264_end_bit							= -1;
static int hf_h264_profile							= -1;
static int hf_h264_profile_idc						= -1;
static int hf_h264_rbsp_stop_bit					= -1;
static int hf_h264_rbsp_trailing_bits				= -1;
static int hf_h264_constraint_set0_flag				= -1;
static int hf_h264_constraint_set1_flag				= -1;
static int hf_h264_constraint_set2_flag				= -1;
static int hf_h264_constraint_set3_flag				= -1;
static int hf_h264_reserved_zero_4bits				= -1;
static int hf_h264_level_idc						= -1;
static int hf_h264_nal_unit							= -1;
static int hf_h264_forbidden_zero_bit				= -1;
static int hf_h264_nal_ref_idc						= -1;
static int hf_h264_nal_unit_type					= -1;
static int hf_h264_seq_parameter_set_id				= -1;
static int hf_h264_chroma_format_idc				= -1;
static int hf_h264_residual_colour_transform_flag	= -1;
static int hf_h264_bit_depth_luma_minus8			= -1;
static int hf_h264_bit_depth_chroma_minus8			= -1;
static int hf_h264_qpprime_y_zero_transform_bypass_flag = -1;
static int hf_h264_seq_scaling_matrix_present_flag	= -1;
static int hf_h264_log2_max_frame_num_minus4		= -1;
static int hf_h264_pic_order_cnt_type				= -1;
static int hf_h264_log2_max_pic_order_cnt_lsb_minus4 = -1;
static int hf_h264_delta_pic_order_always_zero_flag = -1;
static int hf_h264_offset_for_non_ref_pic			= -1;
static int hf_h264_offset_for_top_to_bottom_field	= -1;
static int hf_h264_num_ref_frames_in_pic_order_cnt_cycle = -1;
static int hf_h264_offset_for_ref_frame				= -1;
static int hf_h264_num_ref_frames					= -1;
static int hf_h264_gaps_in_frame_num_value_allowed_flag = -1;
static int hf_h264_pic_width_in_mbs_minus1			= -1;
static int hf_h264_pic_height_in_map_units_minus1	= -1;
static int hf_h264_frame_mbs_only_flag				= -1;
static int hf_h264_mb_adaptive_frame_field_flag		= -1;
static int hf_h264_direct_8x8_inference_flag		= -1;
static int hf_h264_frame_cropping_flag				= -1;
static int hf_h264_frame_crop_left_offset			= -1;
static int hf_h264_frame_crop_right_offset			= -1;
static int hf_h264_frame_crop_top_offset			= -1;
static int hf_h264_frame_crop_bottom_offset			= -1;
static int hf_h264_vui_parameters_present_flag		= -1;
static int hf_h264_pic_parameter_set_id				= -1;
static int hf_h264_entropy_coding_mode_flag			= -1;
static int hf_h264_pic_order_present_flag			= -1;
static int hf_h264_num_slice_groups_minus1			= -1;
static int hf_h264_slice_group_map_type				= -1;
static int hf_h264_num_ref_idx_l0_active_minus1		= -1;
static int hf_h264_num_ref_idx_l1_active_minus1		= -1;
static int hf_h264_weighted_pred_flag				= -1;
static int hf_h264_weighted_bipred_idc				= -1;
static int hf_h264_pic_init_qp_minus26				= -1;
static int hf_h264_pic_init_qs_minus26				= -1;
static int hf_h264_chroma_qp_index_offset			= -1;
static int hf_h264_deblocking_filter_control_present_flag = -1;
static int hf_h264_constrained_intra_pred_flag		= -1;
static int hf_h264_redundant_pic_cnt_present_flag	= -1;
static int hf_h264_transform_8x8_mode_flag			= -1;
static int hf_h264_pic_scaling_matrix_present_flag	= -1;
static int hf_h264_second_chroma_qp_index_offset	= -1;
static int hf_h264_par_profile						= -1;
static int hf_h264_par_profile_b					= -1;
static int hf_h264_par_profile_m					= -1;
static int hf_h264_par_profile_e					= -1;
static int hf_h264_par_profile_h					= -1;
static int hf_h264_par_profile_h10					= -1;
static int hf_h264_par_profile_h4_2_2				= -1;
static int hf_h264_par_profile_h4_4_4				= -1;
static int hf_h264_par_add_mode_sup					= -1;
static int hf_h264_par_AdditionalModesSupported		= -1;
static int hf_h264_par_add_mode_sup_rcdo			= -1;
static int hf_h264_par_ProfileIOP					= -1;
static int hf_h264_par_constraint_set0_flag			= -1;
static int hf_h264_par_constraint_set1_flag			= -1;
static int hf_h264_par_constraint_set2_flag			= -1;

/* VUI parameters */
static int hf_h264_aspect_ratio_info_present_flag	= -1;
static int hf_h264_aspect_ratio_idc					= -1;
static int hf_h264_sar_width						= -1;
static int hf_h264_sar_height						= -1;
static int hf_h264_overscan_info_present_flag		= -1;
static int hf_h264_overscan_appropriate_flag		= -1;
static int hf_h264_video_signal_type_present_flag	= -1;
static int hf_h264_video_format						= -1;
static int hf_h264_video_full_range_flag			= -1;
static int hf_h264_colour_description_present_flag	= -1;
static int hf_h264_colour_primaries					= -1;
static int hf_h264_transfer_characteristics			= -1;
static int hf_h264_matrix_coefficients				= -1;
static int hf_h264_chroma_loc_info_present_flag		= -1;
static int hf_h264_chroma_sample_loc_type_top_field = -1;
static int hf_h264_chroma_sample_loc_type_bottom_field = -1;
static int hf_h264_timing_info_present_flag			= -1;
static int hf_h264_num_units_in_tick				= -1;
static int hf_h264_time_scale						= -1;
static int hf_h264_fixed_frame_rate_flag			= -1;
static int hf_h264_nal_hrd_parameters_present_flag	= -1;
static int hf_h264_vcl_hrd_parameters_present_flag	= -1;
static int hf_h264_low_delay_hrd_flag				= -1;
static int hf_h264_pic_struct_present_flag			= -1;
static int hf_h264_bitstream_restriction_flag		= -1;
static int hf_h264_motion_vectors_over_pic_boundaries_flag = -1;
static int hf_h264_max_bytes_per_pic_denom			= -1;
static int hf_h264_max_bits_per_mb_denom			= -1;
static int hf_h264_log2_max_mv_length_horizontal	= -1;
static int hf_h264_log2_max_mv_length_vertical		= -1;
static int hf_h264_num_reorder_frames				= -1;
static int hf_h264_max_dec_frame_buffering			= -1;
static int hf_h264_cpb_cnt_minus1					= -1;
static int hf_h264_bit_rate_scale					= -1;
static int hf_h264_cpb_size_scale					= -1;
static int hf_h264_bit_rate_value_minus1			= -1;
static int hf_h264_cpb_size_value_minus1			= -1;
static int hf_h264_cbr_flag							= -1;
static int hf_h264_initial_cpb_removal_delay_length_minus1 = -1;
static int hf_h264_cpb_removal_delay_length_minus1	= -1;
static int hf_h264_dpb_output_delay_length_minus11	= -1;
static int hf_h264_time_offset_length				= -1;

static int hf_h264_first_mb_in_slice				= -1;
static int hf_h264_slice_type						= -1;
static int hf_h264_slice_id							= -1;
static int hf_h264_payloadsize						= -1;
static int hf_h264_payloadtype							= -1;
static int hf_h264_frame_num						= -1;

/* Initialize the subtree pointers */
static int ett_h264 = -1;
static int ett_h264_profile = -1;
static int ett_h264_nal = -1;
static int ett_h264_fua = -1;
static int ett_h264_stream = -1;
static int ett_h264_nal_unit = -1;
static int ett_h264_par_profile = -1;
static int ett_h264_par_AdditionalModesSupported = -1;
static int ett_h264_par_ProfileIOP				 = -1;

/* The dynamic payload type range which will be dissected as H.264 */

#define RTP_PT_DEFAULT_RANGE "0"
static range_t *temp_dynamic_payload_type_range = NULL;

static dissector_handle_t h264_handle;

/* syntax tables in subclause 7.3 is equal to
 * ue(v), me(v), se(v), or te(v).
 */
typedef enum {
    H264_UE_V = 0,
    H264_ME_V = 1,
    H264_SE_V = 2,
    H264_TE_V = 3
} h264_golomb_descriptors;


static const true_false_string h264_f_bit_vals = {
  "Bit errors or other syntax violations",
  "No bit errors or other syntax violations"
};
static const true_false_string h264_start_bit_vals = {
  "the first packet of FU-A picture",
  "Not the first packet of FU-A picture"
};
static const true_false_string h264_end_bit_vals = {
  "the last packet of FU-A picture",
  "Not the last packet of FU-A picture"
};
static const true_false_string h264_forbidden_bit_vals = {
  "Forbidden Bit of FU-A",
  "Not Forbidden Bit of FU-A"
};

#define H264_SEQ_PAR_SET		7
#define H264_PIC_PAR_SET		8

static const value_string h264_type_values[] = {
	{ 0,	"Undefined" },
	{ 1,	"NAL unit - Coded slice of a non-IDR picture" },	/* Single NAL unit packet per H.264 */
	{ 2,	"NAL unit - Coded slice data partition A" },
	{ 3,	"NAL unit - Coded slice data partition B" },
	{ 4,	"NAL unit - Coded slice data partition C" },
	{ 5,	"NAL unit - Coded slice of an IDR picture" },
	{ 6,	"NAL unit - Supplemental enhancement information (SEI)" },
	{ H264_SEQ_PAR_SET,	"NAL unit - Sequence parameter set" },				/* 7 */
	{ H264_PIC_PAR_SET,	"NAL unit - Picture parameter set" },				/* 8 */
	{ 9,	"NAL unit - Access unit delimiter" },
	{ 10,	"NAL unit - End of sequence" },
	{ 11,	"NAL unit - End of stream" },
	{ 12,	"NAL unit - Filler data" },
	{ 13,	"NAL unit - Sequence parameter set extension" },
	{ 14,	"NAL unit - Reserved" },
	{ 15,	"NAL unit - Reserved" },
	{ 16,	"NAL unit - Reserved" },
	{ 17,	"NAL unit - Reserved" },
	{ 18,	"NAL unit - Reserved" },
	{ 19,	"NAL unit - Coded slice of an auxiliary coded picture without partitioning" },
	{ 20,	"NAL unit - Reserved" },
	{ 21,	"NAL unit - Reserved" },
	{ 22,	"NAL unit - Reserved" },
	{ 23,	"NAL unit - Reserved" },
	{ 24,	"STAP-A" },		/* Single-time aggregation packet */
	{ 25,	"STAP-B" },		/* Single-time aggregation packet */
	{ 26,	"MTAP16" },		/* Multi-time aggregation packet */
	{ 27,	"MTAP24" },		/* Multi-time aggregation packet */
	{ 28,	"FU-A" },		/* Fragmentation unit */
	{ 29,	"FU-B" },		/* Fragmentation unit */
	{ 30,	"undefined" },
	{ 31,	"undefined" },
	{ 0,	NULL }
};


static const value_string h264_profile_idc_values[] = {
	{ 66,	"Baseline profile" },
	{ 77,	"Main profile" },
	{ 88,	"Extended profile" },
	{ 100,	"High profile" },
	{ 110,	"High 10 profile" },
	{ 122,	"High 4:2:2 profile" },
	{ 144,	"High 4:4:4 profile" },
	{ 0,	NULL }
};

static const value_string h264_level_bitrate_values[] = {
	{ 10,	"64kb/s" },
	{ 11,	"192kb/s" },
	{ 12,	"384kb/s" },
	{ 13,	"2 Mb/s" },
	{ 20,	"2 Mb/s" },
	{ 21,	"4 Mb/s" },
	{ 22,	"4 Mb/s" },
	{ 30,	"10 Mb/s" },
	{ 31,	"14 Mb/s" },
	{ 32,	"20 Mb/s" },
	{ 40,	"20 Mb/s" },
	{ 41,	"50 Mb/s" },
	{ 42,	"50 Mb/s" },
	{ 50,	"135 Mb/s" },
	{ 51,	"240 Mb/s" },
	{ 0,	NULL }
};

static const value_string h264_nal_unit_type_vals[] = {
	{ 0,	"Unspecified" },
	{ 1,	"Coded slice of a non-IDR picture" },
	{ 2,	"Coded slice data partition A" },
	{ 3,	"Coded slice data partition B" },
	{ 4,	"Coded slice data partition C" },
	{ 5,	"Coded slice of an IDR picture" },
	{ 6,	"Supplemental enhancement information (SEI)" },
	{ 7,	"Sequence parameter set" },
	{ 8,	"Picture parameter set" },
	{ 9,	"Access unit delimiter" },
	{ 10,	"End of sequence" },
	{ 11,	"End of stream" },
	{ 12,	"Filler data" },
	{ 13,	"Sequence parameter set extension" },
	{ 14,	"Reserved" },
	{ 15,	"Reserved" },
	{ 16,	"Reserved" },
	{ 17,	"Reserved" },
	{ 18,	"Reserved" },
	{ 19,	"Coded slice of an auxiliary coded picture without partitioning" },
	{ 20,	"Reserved" },
	{ 21,	"Reserved" },
	{ 22,	"Reserved" },
	{ 23,	"Reserved" },
	{ 24,	"Unspecified" },
	{ 25,	"Unspecified" },
	{ 26,	"Unspecified" },
	{ 27,	"Unspecified" },
	{ 28,	"FU-A" },
	{ 29,	"Unspecified" },
	{ 30,	"Unspecified" },
	{ 31,	"Unspecified" },
	{ 0,	NULL }
};

static const value_string h264_slice_group_map_type_vals[] = {
	{ 0,	"Interleaved slice groups" },
	{ 1,	"Dispersed slice group mapping" },
	{ 2,	"One or more foreground slice groups and a leftover slice group" },
	{ 3,	"Changing slice groups" },
	{ 4,	"Changing slice groups" },
	{ 5,	"Changing slice groups" },
	{ 6,	"Explicit assignment of a slice group to each slice group map unit" },
	{ 0,	NULL }
};

/* Table 7-6 Name association to slice_type */
static const value_string h264_slice_type_vals[] = {
	{ 0,	"P (P slice)" },
	{ 1,	"B (B slice)" },
	{ 2,	"I (I slice)" },
	{ 3,	"SP (SP slice)" },
	{ 4,	"SI (SI slice)" },
	{ 5,	"P (P slice)" },
	{ 6,	"B (B slice)" },
	{ 7,	"I (I slice)" },
	{ 8,	"SP (SP slice)" },
	{ 9,	"SI (SI slice)" },
	{ 0,	NULL }
};
/* byte_aligned( ) is specified as follows.
 * - If the current position in the bitstream is on a byte boundary, i.e.,
 *	 the next bit in the bitstream is the first bit in a byte,
 *	 the return value of byte_aligned( ) is equal to TRUE.
 * - Otherwise, the return value of byte_aligned( ) is equal to FALSE.
 */
static gboolean
h264_byte_aligned(int bit_offset)
{
	if(bit_offset&0x3)
		return FALSE;

	return TRUE;
}
/* Expect a tvb and a bit offset into the tvb
 * returns the valu and bit_offset
 */
#define cVALS(x) (const value_string*)(x)

guint32
dissect_h264_exp_golomb_code(proto_tree *tree, int hf_index, tvbuff_t *tvb, gint *start_bit_offset, h264_golomb_descriptors descriptor)
/*(tvbuff_t *tvb, gint *start_bit_offset) */
{
	gint		leading_zero_bits, bit_offset, start_offset;
	guint32		codenum, mask, value, tmp;
	gint32		se_value=0;
	gint		b;
	char *str;
	int bit;
	int i;
	header_field_info *hf_field = NULL;

	start_offset = *start_bit_offset>>3;

	if(hf_index > -1)
		hf_field = proto_registrar_get_nth(hf_index);

	bit_offset = *start_bit_offset;

	/* prepare the string */
	str=ep_alloc(256);
	str[0]='\0';
	for(bit=0;bit<((int)(bit_offset&0x07));bit++){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		g_strlcat(str,".", 256);
	}


	leading_zero_bits = -1;
	for( b = 0; !b; leading_zero_bits++ ){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		if(bit&&(!(bit%8))){
			g_strlcat(str, " ", 256);
		}
		b = tvb_get_bits8(tvb, bit_offset, 1);
		if(b != 0){
			g_strlcat(str, "1", 256);
		} else {
			g_strlcat(str, "0", 256);
		}
		bit++;
		bit_offset++;
	}

	if(leading_zero_bits==0){
		codenum = 0;
		*start_bit_offset = bit_offset;
		for(;bit%8;bit++){
			if(bit&&(!(bit%4))){
				g_strlcat(str, " ", 256);
			}
		g_strlcat(str,".", 256);
		}
		if(hf_field){
			g_strlcat(str," = ", 256);
			g_strlcat(str,hf_field->name, 256);
			switch (descriptor){
			case H264_SE_V:
				/* if the syntax element is coded as se(v),
				 * the value of the syntax element is derived by invoking the
				 * mapping process for signed Exp-Golomb codes as specified in
				 * subclause 9.1.1 with codeNum as the input.
				 */
				if(hf_field->type==FT_INT32){
					if (hf_field->strings) {
						proto_tree_add_int_format(tree, hf_index, tvb, start_offset, 1, codenum,
							  "%s: %s (%d)",
							  str,
							  val_to_str(codenum, cVALS(hf_field->strings), "Unknown "),
							  codenum);
					}else{
						switch(hf_field->display){
							case BASE_DEC:
								proto_tree_add_int_format(tree, hf_index, tvb, start_offset, 1, codenum,
							         "%s: %d",
									  str,
									  codenum);
								break;
							default:
								DISSECTOR_ASSERT_NOT_REACHED();
								break;
						}
					}
				}
				return codenum;
			default:
				break;
			}
			if(hf_field->type==FT_UINT32){
				if (hf_field->strings) {
					proto_tree_add_uint_format(tree, hf_index, tvb, start_offset, 1, codenum,
						  "%s: %s (%u)",
						  str,
						  val_to_str(codenum, cVALS(hf_field->strings), "Unknown "),
						  codenum);
				}else{
					switch(hf_field->display){
						case BASE_DEC:
							proto_tree_add_uint_format(tree, hf_index, tvb, start_offset, 1, codenum,
						         "%s: %u",
								  str,
								  codenum);
							break;
						case BASE_HEX:
							proto_tree_add_uint_format(tree, hf_index, tvb, start_offset, 1, codenum,
					             "%s: 0x%x",
								  str,
								  codenum);
							break;
						default:
							DISSECTOR_ASSERT_NOT_REACHED();
							break;
					}
				}
			}else{
				/* Only allow guint32 */
				DISSECTOR_ASSERT_NOT_REACHED();
			}
		}
		return codenum;
	}

	/*
	Syntax elements coded as ue(v), me(v), or se(v) are Exp-Golomb-coded. Syntax elements coded as te(v) are truncated
	Exp-Golomb-coded. The parsing process for these syntax elements begins with reading the bits starting at the current
	location in the bitstream up to and including the first non-zero bit, and counting the number of leading bits that are
	equal to 0. This process is specified as follows:
	leadingZeroBits = -1;
	for( b = 0; !b; leadingZeroBits++ )
	b = read_bits( 1 )
	The variable codeNum is then assigned as follows:
	codeNum = 2leadingZeroBits - 1 + read_bits( leadingZeroBits )
	where the value returned from read_bits( leadingZeroBits ) is interpreted as a binary representation of an unsigned
	integer with most significant bit written first.
	*/
	codenum = 1;
	codenum = codenum << leading_zero_bits;
	mask = codenum>>1;
	if (leading_zero_bits > 32)
		DISSECTOR_ASSERT_NOT_REACHED();
	else if (leading_zero_bits > 16)
		value = tvb_get_bits32(tvb, bit_offset,leading_zero_bits, FALSE);
	else if (leading_zero_bits > 8)
		value = tvb_get_bits16(tvb, bit_offset,leading_zero_bits, FALSE);
	else
		value = tvb_get_bits8(tvb, bit_offset,leading_zero_bits );
	codenum = (codenum-1) + value;
	bit_offset = bit_offset + leading_zero_bits;

	/* read the bits for the int */
	for(i=0;i<leading_zero_bits;i++){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		if(bit&&(!(bit%8))){
			g_strlcat(str, " ", 256);
		}
		bit++;
		tmp = value & mask;
		if(tmp != 0){
			g_strlcat(str, "1", 256);
		} else {
			g_strlcat(str, "0", 256);
		}
		mask = mask>>1;
	}
	for(;bit%8;bit++){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		g_strlcat(str,".", 256);
	}

	switch (descriptor){
	case H264_SE_V:
		/* if the syntax element is coded as se(v),
		 * the value of the syntax element is derived by invoking the
		 * mapping process for signed Exp-Golomb codes as specified in
		 * subclause 9.1.1 with codeNum as the input.
		 *		k+1
		 * (-1)    Ceil( k/2 )
		 */
		se_value = (codenum + 1) >> 1;
		if (!(se_value & 1)){
			se_value =  - se_value;
		}
		break;
	default:
		break;
	}

	if(hf_field){
		g_strlcat(str," = ", 256);
		g_strlcat(str,hf_field->name, 256);
		switch (descriptor){
		case H264_SE_V:
			g_strlcat(str,"(se(v))", 256);
			/* if the syntax element is coded as se(v),
			 * the value of the syntax element is derived by invoking the
			 * mapping process for signed Exp-Golomb codes as specified in
			 * subclause 9.1.1 with codeNum as the input.
			 */
			break;
		default:
		break;
		}
		if((hf_field->type==FT_UINT32)&&(descriptor==H264_UE_V)){
			if (hf_field->strings) {
				proto_tree_add_uint_format(tree, hf_index, tvb, start_offset, 1, codenum,
						  "%s: %s (%u)",
						  str,
						  val_to_str(codenum, cVALS(hf_field->strings), "Unknown "),
						  codenum);
			}else{
				switch(hf_field->display){
					case BASE_DEC:
						proto_tree_add_uint_format(tree, hf_index, tvb, start_offset, 1, codenum,
					         "%s: %u",
							  str,
							  codenum);
						break;
					case BASE_HEX:
						proto_tree_add_uint_format(tree, hf_index, tvb, start_offset, 1, codenum,
				             "%s: 0x%x",
							  str,
							  codenum);
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						break;
				}
			}
		}else if((hf_field->type==FT_INT32)&&(descriptor==H264_SE_V)){
			if (hf_field->strings) {
				proto_tree_add_int_format(tree, hf_index, tvb, start_offset, 1, codenum,
						  "%s: %s (%d)",
						  str,
						  val_to_str(codenum, cVALS(hf_field->strings), "Unknown "),
						  se_value);
			}else{
				switch(hf_field->display){
					case BASE_DEC:
						proto_tree_add_int_format(tree, hf_index, tvb, start_offset, 1, codenum,
					         "%s: %d",
							  str,
							  se_value);
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						break;
				}
			}
			*start_bit_offset = bit_offset;
			return se_value;

		}else{
			/* Only allow guint32 */
			DISSECTOR_ASSERT_NOT_REACHED();
		}
	}

	*start_bit_offset = bit_offset;
	return codenum;

}

/* This function is adapted to parsing NAL units from SDP data where the
 * base64 coding may add extra padding
 */

static gboolean
more_rbsp_data(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_, gint bit_offset)
{

	int offset;
	int remaining_length;
	int last_one_bit;
	guint8 b = 0;

	/* XXX might not be the best way of doing things but:
	 * Serch from the end of the tvb for the first '1' bit
	 * assuming that its's the RTBSP stop bit
	 */

	/* Set offset to the byte we are treating */
	offset = bit_offset>>3;
	remaining_length = tvb_length_remaining(tvb,offset);
	/* If there is more then 2 bytes left there *should* be more data */
	if(remaining_length>2){
		return TRUE;
	}
	/* Start from last bit */
	last_one_bit = (tvb_length(tvb) << 3);

	for( b = 0; !b; ){
		last_one_bit--;
		b = tvb_get_bits8(tvb, last_one_bit, 1);
	}

	if( last_one_bit == bit_offset){
		return FALSE;
	}

	return TRUE;
}

static int
dissect_h264_rbsp_trailing_bits(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint bit_offset)
{
	gint remaining_bits=0;

	proto_tree_add_bits_item(tree, hf_h264_rbsp_stop_bit, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if((bit_offset&0x7)!=0){
		remaining_bits = 8 - (bit_offset&0x7);
		proto_tree_add_bits_item(tree, hf_h264_rbsp_trailing_bits, tvb, bit_offset, remaining_bits, FALSE);
	}

	return bit_offset+remaining_bits;
}

/*
 * 7.3.3 Slice header syntax
 * slice_header( )
 * XXX Just parse a few bytes
 */
static int
dissect_h264_slice_header(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint bit_offset)
{
	/* first_mb_in_slice 2 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_first_mb_in_slice, tvb, &bit_offset, H264_UE_V);

	/* slice_type 2 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_slice_type, tvb, &bit_offset, H264_UE_V);

	/* pic_parameter_set_id 2 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_pic_parameter_set_id, tvb, &bit_offset, H264_UE_V);

	/* frame_num 2 u(v) */
	/*
	 * represented by log2_max_frame_num_minus4 + 4 bits in
	 * the bitstream
	 * proto_tree_add_bits_item(tree, hf_h264_frame_num, tvb, bit_offset, 4, FALSE);
	 */


	return bit_offset;
}


/* 7.3.2.1.1 Scaling list syntax
 *
 * scaling_list( scalingList, sizeOfScalingList, useDefaultScalingMatrixFlag )
 */
/*
static int
dissect_h264_scaling_list(proto_tree *tree, tvbuff_t *tvb, gint bit_offset, int hf_index_scalinglist,
						  guint8 sizeOfScalingList, int hf_index_usedefaultscalingmatrixflag)
{

	guint8 lastScale = 8;
	guint8 nextScale = 8:
	guint8 delta_scale;

	for( j = 0; j < sizeOfScalingList; j++ ) {
	  if( nextScale != 0 ) {
		  / delta_scale 0 | 1 se(v) /
		  delta_scale = dissect_h264_exp_golomb_code(tree, hf_h264_delta_scale, tvb, &bit_offset);
		  nextScale = ( lastScale + delta_scale + 256 ) % 256;
		  useDefaultScalingMatrixFlag = ( j == 0 && nextScale == 0 );
	}
	scalingList[ j ] = ( nextScale == 0 ) ? lastScale : nextScale
	lastScale = scalingList[ j ]
	}
}
*/
/* E.1.2 HRD parameters syntax */
static int
dissect_h264_hrd_parameters(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint bit_offset)
{
	guint8 cpb_cnt_minus1;
	int SchedSelIdx;


	/* cpb_cnt_minus1 0 ue(v) */
	cpb_cnt_minus1 = dissect_h264_exp_golomb_code(tree, hf_h264_cpb_cnt_minus1, tvb, &bit_offset, H264_UE_V);

	/* bit_rate_scale 0 u(4) */
	proto_tree_add_bits_item(tree, hf_h264_bit_rate_scale, tvb, bit_offset, 4, FALSE);
	bit_offset = bit_offset + 4;

	/* cpb_size_scale 0 u(4) */
	proto_tree_add_bits_item(tree, hf_h264_cpb_size_scale, tvb, bit_offset, 4, FALSE);
	bit_offset = bit_offset + 4;
	/* for( SchedSelIdx = 0; SchedSelIdx <= cpb_cnt_minus1; SchedSelIdx++ ) { */
	for( SchedSelIdx = 0; SchedSelIdx <= cpb_cnt_minus1; SchedSelIdx++ ) {

		/* bit_rate_value_minus1[ SchedSelIdx ] 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_bit_rate_value_minus1, tvb, &bit_offset, H264_UE_V);

		/* cpb_size_value_minus1[ SchedSelIdx ] 0 ue(v)*/
		dissect_h264_exp_golomb_code(tree, hf_h264_cpb_size_value_minus1, tvb, &bit_offset, H264_UE_V);

		/* cbr_flag[ SchedSelIdx ] 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_cbr_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;
	}
	/* initial_cpb_removal_delay_length_minus1 0 u(5) */
	proto_tree_add_bits_item(tree, hf_h264_initial_cpb_removal_delay_length_minus1, tvb, bit_offset, 5, FALSE);
	bit_offset = bit_offset + 5;

	/* cpb_removal_delay_length_minus1 0 u(5) */
	proto_tree_add_bits_item(tree, hf_h264_cpb_removal_delay_length_minus1, tvb, bit_offset, 5, FALSE);
	bit_offset = bit_offset + 5;

	/* dpb_output_delay_length_minus1 0 u(5) */
	proto_tree_add_bits_item(tree, hf_h264_dpb_output_delay_length_minus11, tvb, bit_offset, 5, FALSE);
	bit_offset = bit_offset + 5;

	/* time_offset_length 0 u(5) */
	proto_tree_add_bits_item(tree, hf_h264_time_offset_length, tvb, bit_offset, 5, FALSE);
	bit_offset = bit_offset + 5;

	return bit_offset;
}

#define EXTENDED_SAR 255

/* E.1.1 VUI parameters syntax */

/* Table E-2 - Meaning of video_format */
static const value_string h264_video_format_vals[] = {
	{ 22,	"reserved_sei_message)" },
	{ 0,	"Component" },
	{ 1,	"PAL" },
	{ 2,	"NTSC" },
	{ 3,	"SECAM" },
	{ 4,	"MAC" },
	{ 5,	"Unspecified video format" },
	{ 6,	"Reserved" },
	{ 7,	"Reserved" },
	{ 0,	NULL }
};
static int
dissect_h264_vui_parameters(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint bit_offset)
{

	guint8 aspect_ratio_info_present_flag, aspect_ratio_idc, overscan_info_present_flag;
	guint8 video_signal_type_present_flag, colour_description_present_flag, chroma_loc_info_present_flag;
	guint8 timing_info_present_flag, nal_hrd_parameters_present_flag, vcl_hrd_parameters_present_flag;
	guint8 bitstream_restriction_flag;

	/* vui_parameters( ) {
	 * aspect_ratio_info_present_flag 0 u(1)
	 */
	aspect_ratio_info_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_aspect_ratio_info_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( aspect_ratio_info_present_flag ) {
		/* aspect_ratio_idc 0 u(8) */
		aspect_ratio_idc = tvb_get_bits8(tvb, bit_offset, 8);
		proto_tree_add_bits_item(tree, hf_h264_aspect_ratio_idc, tvb, bit_offset, 8, FALSE);
		bit_offset = bit_offset + 8;

		if( aspect_ratio_idc == EXTENDED_SAR ) {
			/* sar_width 0 u(16) */
			proto_tree_add_bits_item(tree, hf_h264_sar_width, tvb, bit_offset, 16, FALSE);
			bit_offset = bit_offset + 16;

			/* sar_height 0 u(16) */
			proto_tree_add_bits_item(tree, hf_h264_sar_height, tvb, bit_offset, 16, FALSE);
			bit_offset = bit_offset + 16;
		}
	}
	/* overscan_info_present_flag 0 u(1) */
	overscan_info_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_overscan_info_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( overscan_info_present_flag ){
		/* overscan_appropriate_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_overscan_appropriate_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;
	}

	/* video_signal_type_present_flag 0 u(1) */
	video_signal_type_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_video_signal_type_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( video_signal_type_present_flag ) {
		/* video_format 0 u(3) > */
		proto_tree_add_bits_item(tree, hf_h264_video_format, tvb, bit_offset, 3, FALSE);
		bit_offset = bit_offset + 3;

		/* video_full_range_flag 0 u(1)*/
		proto_tree_add_bits_item(tree, hf_h264_video_full_range_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		/* colour_description_present_flag 0 u(1) */
		colour_description_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
		proto_tree_add_bits_item(tree, hf_h264_colour_description_present_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		if( colour_description_present_flag ) {
			/* colour_primaries 0 u(8) */
			proto_tree_add_bits_item(tree, hf_h264_colour_primaries, tvb, bit_offset, 8, FALSE);
			bit_offset = bit_offset + 8;

			/* transfer_characteristics 0 u(8) */
			proto_tree_add_bits_item(tree, hf_h264_transfer_characteristics, tvb, bit_offset, 8, FALSE);
			bit_offset = bit_offset + 8;

			/* matrix_coefficients 0 u(8)*/
			proto_tree_add_bits_item(tree, hf_h264_matrix_coefficients, tvb, bit_offset, 8, FALSE);
			bit_offset = bit_offset + 8;
		}
	}

	/* chroma_loc_info_present_flag 0 u(1) */
	chroma_loc_info_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_chroma_loc_info_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( chroma_loc_info_present_flag ) {
		/* chroma_sample_loc_type_top_field 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_chroma_sample_loc_type_top_field, tvb, &bit_offset, H264_UE_V);

		/* chroma_sample_loc_type_bottom_field 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_chroma_sample_loc_type_bottom_field, tvb, &bit_offset, H264_UE_V);
	}

	/* timing_info_present_flag 0 u(1) */
	timing_info_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_timing_info_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( timing_info_present_flag ) {
		/* num_units_in_tick 0 u(32) */
		proto_tree_add_bits_item(tree, hf_h264_num_units_in_tick, tvb, bit_offset, 32, FALSE);
		bit_offset = bit_offset + 32;

		/* time_scale 0 u(32) */
		proto_tree_add_bits_item(tree, hf_h264_time_scale, tvb, bit_offset, 32, FALSE);
		bit_offset = bit_offset + 32;

		/* fixed_frame_rate_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_fixed_frame_rate_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;
	}
	/* nal_hrd_parameters_present_flag 0 u(1) */
	nal_hrd_parameters_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_nal_hrd_parameters_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( nal_hrd_parameters_present_flag ){
		/* hrd_parameters( ) */
		bit_offset = dissect_h264_hrd_parameters(tree, tvb, pinfo, bit_offset);
	}

	/* vcl_hrd_parameters_present_flag 0 u(1) */
	vcl_hrd_parameters_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_vcl_hrd_parameters_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( vcl_hrd_parameters_present_flag ){
		/* hrd_parameters( ) */
		bit_offset = dissect_h264_hrd_parameters(tree, tvb, pinfo, bit_offset);
	}
	if( nal_hrd_parameters_present_flag || vcl_hrd_parameters_present_flag ){
		/* low_delay_hrd_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_low_delay_hrd_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;
	}
	/* pic_struct_present_flag 0 u(1) */
	proto_tree_add_bits_item(tree, hf_h264_pic_struct_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* bitstream_restriction_flag 0 u(1) */
	bitstream_restriction_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_bitstream_restriction_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( bitstream_restriction_flag ) {
		/* motion_vectors_over_pic_boundaries_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_motion_vectors_over_pic_boundaries_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		/* max_bytes_per_pic_denom 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_max_bytes_per_pic_denom, tvb, &bit_offset, H264_UE_V);

		/* max_bits_per_mb_denom 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_max_bits_per_mb_denom, tvb, &bit_offset, H264_UE_V);

		/* log2_max_mv_length_horizontal 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_log2_max_mv_length_horizontal, tvb, &bit_offset, H264_UE_V);

		/* log2_max_mv_length_vertical 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_log2_max_mv_length_vertical, tvb, &bit_offset, H264_UE_V);

		/* num_reorder_frames 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_num_reorder_frames, tvb, &bit_offset, H264_UE_V);

		/* max_dec_frame_buffering 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_max_dec_frame_buffering, tvb, &bit_offset, H264_UE_V);
	}

	return bit_offset;
}


/* Used To dissect SDP parameter (H.264)profile */
void
dissect_h264_profile(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item, *level_item;
	proto_tree *h264_profile_tree;
	gint	offset = 0;
	guint8	constraint_set3_flag;
	guint32	level_idc;

	item = proto_tree_add_item(tree, hf_h264_profile, tvb, offset, -1, FALSE);
	h264_profile_tree = proto_item_add_subtree(item, ett_h264_profile);

	proto_tree_add_item(h264_profile_tree, hf_h264_profile_idc, tvb, offset, 1, FALSE);
	offset++;

	constraint_set3_flag = (tvb_get_guint8(tvb,offset)&0x10)>>4;
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set0_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set1_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set2_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set3_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_reserved_zero_4bits, tvb, offset, 1, FALSE);
	offset++;

	/* A level to which the bitstream conforms shall be indicated by the syntax element level_idc as follows.
	 *	- If level_idc is equal to 11 and constraint_set3_flag is equal to 1, the indicated level is level 1b.
	 *	- Otherwise (level_idc is not equal to 11 or constraint_set3_flag is not equal to 1), level_idc shall
	 *    be set equal to a value of ten times the level number specified in Table A-1 and constraint_set3_flag
	 *    shall be set equal to 0.
	 */

	level_idc = tvb_get_guint8(tvb,offset);
	level_item = proto_tree_add_item(h264_profile_tree, hf_h264_level_idc, tvb, offset, 1, FALSE);
	if((level_idc==11)&&(constraint_set3_flag==1)){
		proto_item_append_text(level_item," [Level 1b (128kb/s)]");
	}else{
		proto_item_append_text(level_item," [Level %.1f %s]",((double)level_idc/10),val_to_str(level_idc, h264_level_bitrate_values, "Unknown "));
	}

}

/*
 * 7.3.2.8 Slice layer without partitioning RBSP syntax
 * slice_layer_without_partitioning_rbsp( )
 */

static void
dissect_h264_slice_layer_without_partitioning_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	gint bit_offset;

	bit_offset = offset <<3;

	/* slice_header( ) 2 */
	bit_offset = dissect_h264_slice_header(tree, tvb, pinfo, bit_offset);
	proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "[Not decoded yet]");
	return;
	/* slice_data( ) * all categories of slice_data( ) syntax * 2 | 3 | 4 */
	/* rbsp_slice_trailing_bits( ) */

}

/*
 * 7.3.2.9.1 Slice data partition A RBSP syntax
 * slice_data_partition_a_layer_rbsp( )
 */
static void
dissect_h264_slice_data_partition_a_layer_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	gint bit_offset;

	bit_offset = offset <<3;

	/* slice_header( ) 2 */
	bit_offset = dissect_h264_slice_header(tree, tvb, pinfo, bit_offset);

	/* slice_id All ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_slice_id, tvb, &bit_offset, H264_UE_V);
	proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "[Not decoded yet]");
	return;
	/* slice_data( ) * only category 2 parts of slice_data( ) syntax * 2*/
	/* rbsp_slice_trailing_bits( )*/

}

/*
 * 7.3.2.9.2 Slice data partition B RBSP syntax
 * slice_data_partition_b_layer_rbsp(
 */
static void
dissect_h264_slice_data_partition_b_layer_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	gint bit_offset;

	bit_offset = offset <<3;

	/* slice_id All ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_slice_id, tvb, &bit_offset, H264_UE_V);
	/* if( redundant_pic_cnt_present_flag )	*/
	/* redundant_pic_cnt All ue(v) */
	/* slice_data( ) * only category 3 parts of slice_data( ) syntax * 3 */
	/* rbsp_slice_trailing_bits( ) 3 */
	proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "[Not decoded yet]");

}

/*
 * 7.3.2.9.3 Slice data partition C RBSP syntax
 * slice_data_partition_c_layer_rbsp( )
 */
static void
dissect_h264_slice_data_partition_c_layer_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	gint bit_offset;

	bit_offset = offset <<3;

	/* slice_id All ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_slice_id, tvb, &bit_offset, H264_UE_V);
	/* if( redundant_pic_cnt_present_flag ) */
	/* redundant_pic_cnt All ue(v) */
	/* slice_data( ) * only category 4 parts of slice_data( ) syntax * 4 */
	/* rbsp_slice_trailing_bits( ) 4 */
	proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "[Not decoded yet]");

}
/* D.1.6 User data unregistered SEI message syntax */

static int
h264_user_data_unregistered(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint bit_offset, guint32 payloadSize)
{
	/* user_data_unregistered( payloadSize ) { C Descriptor */
	/* uuid_iso_iec_11578 5 u(128)
	 * uuid_iso_iec_11578 shall have a value specified as a UUID
	 * according to the procedures of ISO/IEC 11578:1996 Annex A.
	 */
	proto_tree_add_text(tree, tvb, bit_offset>>3, 16, "uuid_iso_iec_1157");
	bit_offset+=128;
	/* 	for( i = 16; i < payloadSize; i++ )
	 *	user_data_payload_byte 5 b(8)
	 */
	proto_tree_add_text(tree, tvb, bit_offset>>3, payloadSize-16, "user_data_payload");
	bit_offset+=(payloadSize-16)<<3;

		return bit_offset;
}
/* D.1 SEI payload syntax */
static const value_string h264_sei_payload_vals[] = {
	{ 0,	"buffering_period" },
	{ 1,	"pic_timing" },
	{ 2,	"pan_scan_rect" },
	{ 3,	"filler_payload" },
	{ 4,	"user_data_registered_itu_t_t35" },
	{ 5,	"user_data_unregistered" },
	{ 6,	"recovery_point" },
	{ 7,	"dec_ref_pic_marking_repetition" },
	{ 8,	"spare_pic" },
	{ 9,	"scene_inf)" },
	{ 10,	"sub_seq_info)" },
	{ 11,	"sub_seq_layer_characteristics" },
	{ 12,	"sub_seq_characteristics" },
	{ 13,	"full_frame_freeze_release" },
	{ 14,	"full_frame_freeze_release" },
	{ 15,	"full_frame_snapshot" },
	{ 16,	"progressive_refinement_segment_start" },
	{ 17,	"progressive_refinement_segment_end" },
	{ 18,	"motion_constrained_slice_group_set" },
	{ 19,	"film_grain_characteristics)" },
	{ 20,	"deblocking_filter_display_preference)" },
	{ 21,	"stereo_video_info)" },
	{ 22,	"reserved_sei_message)" },
	{ 0,	NULL }
};

static int
h264_sei_payload(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint bit_offset, guint32 payloadType, guint32 payloadSize)
{
	/* sei_payload( payloadType, payloadSize ) { C Descriptor */
	if( payloadType == 0 ){
		/* buffering_period( payloadSize ) 5 */
		bit_offset = bit_offset +(payloadSize<<3);
#if 0
	}else if( payloadType == 1 ){
		/* pic_timing( payloadSize ) 5 */
	}else if( payloadType == 2 ){
		/* pan_scan_rect( payloadSize ) 5 */
	}else if( payloadType == 3 ){
		/* filler_payload( payloadSize ) 5 */
	}else if( payloadType == 4 ){
		/* user_data_registered_itu_t_t35( payloadSize ) 5 */
#endif
	}else if( payloadType == 5 ){
		/* user_data_unregistered( payloadSize ) 5 */
		bit_offset = h264_user_data_unregistered( tree, tvb, pinfo, bit_offset, payloadSize);
	}else if( payloadType == 6 ){
		/* recovery_point( payloadSize ) 5 */
		bit_offset = bit_offset +(payloadSize<<3);
	}else if( payloadType == 7 ){
		/* dec_ref_pic_marking_repetition( payloadSize ) 5 */
		bit_offset = bit_offset +(payloadSize<<3);
	}
#if 0
else if( payloadType == 8 )
spare_pic( payloadSize ) 5
else if( payloadType == 9 )
scene_info( payloadSize ) 5
else if( payloadType == 10 )
sub_seq_info( payloadSize ) 5
else if( payloadType == 11 )
sub_seq_layer_characteristics( payloadSize ) 5
else if( payloadType == 12 )
sub_seq_characteristics( payloadSize ) 5
else if( payloadType == 13 )
full_frame_freeze( payloadSize ) 5
else if( payloadType == 14 )
full_frame_freeze_release( payloadSize ) 5
else if( payloadType == 15 )
full_frame_snapshot( payloadSize ) 5
else if( payloadType == 16 )
progressive_refinement_segment_start( payloadSize ) 5
else if( payloadType == 17 )
progressive_refinement_segment_end( payloadSize ) 5
else if( payloadType == 18 )
motion_constrained_slice_group_set( payloadSize ) 5
else if( payloadType == 19 )
film_grain_characteristics( payloadSize ) 5
else if( payloadType == 20 )
deblocking_filter_display_preference( payloadSize ) 5
else if( payloadType == 21 )
stereo_video_info( payloadSize ) 5
else
reserved_sei_message( payloadSize ) 5
	return bit_offset;
#endif
	if( !h264_byte_aligned(bit_offset)){
		/* bit_equal_to_one / * equal to 1 * / 5 f(1) */
		/* TODO:Display the filler and, error if not 1 ?? */
		bit_offset++;
		while( !h264_byte_aligned(bit_offset)){
			/* bit_equal_to_zero / * equal to 0 * / 5 f(1) */
			/* TODO:Display the filler and, error if not 0 ?? */
			bit_offset++;
		}
	}
	return bit_offset;
}

/*
 * 7.3.2.3.1 Supplemental enhancement information message syntax
 */
static gint
dissect_h264_sei_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint bit_offset)
{
	/* sei_message( ) { C Descriptor */
	guint32 payloadType = 0, payloadSize;
	gint start_bit_offset, length;

	start_bit_offset = bit_offset;

	/* while( next_bits( 8 ) == 0xFF ) { */
	while( tvb_get_bits8(tvb, bit_offset, 8) == 0xFF ) {
		/* ff_byte / * equal to 0xFF * / 5 f(8) */
		payloadType += 255;
		bit_offset+=8;
	}
	/* last_payload_type_byte 5 u(8) */
	payloadType += tvb_get_bits8(tvb, bit_offset, 8);
	bit_offset+=8;
	length = (bit_offset - start_bit_offset)>>3;

	proto_tree_add_uint(tree, hf_h264_payloadtype, tvb, start_bit_offset>>3, length, payloadType);

	payloadSize = 0;
	start_bit_offset = bit_offset;
	/* while( next_bits( 8 ) == 0xFF ) { */
	while( tvb_get_bits8(tvb, bit_offset, 8) == 0xFF ) {
		/* ff_byte / * equal to 0xFF * / 5 f(8) */
		payloadSize += 255;
		bit_offset+=8;
	}
	/* last_payload_size_byte 5 u(8) */
	/* payloadSize += last_payload_size_byte */
	payloadSize += tvb_get_bits8(tvb, bit_offset, 8);
	bit_offset+=8;
	length = (bit_offset - start_bit_offset)>>3;
	proto_tree_add_uint(tree, hf_h264_payloadsize, tvb, start_bit_offset>>3, length, payloadSize);

	/*sei_payload( payloadType, payloadSize ) 5 */
	bit_offset = h264_sei_payload( tree, tvb, pinfo, bit_offset, payloadType, payloadSize);
	return bit_offset;
}
/*
 * 7.3.2.3 Supplemental enhancement information RBSP syntax
 * sei_rbsp( )
 */
static int
dissect_h264_sei_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	gint bit_offset;

	bit_offset = offset <<3;
	/* do */
	/* sei_message( ) 5*/
	bit_offset = dissect_h264_sei_message( tree, tvb, pinfo, bit_offset);

	/* while( more_rbsp_data( ) )
	 * If there is more data in an RBSP before rbsp_trailing_bits( ),
	 * the return value of more_rbsp_data( ) is equal to TRUE.
	 */
	/* rbsp_trailing_bits( ) 5 */
	bit_offset = dissect_h264_rbsp_trailing_bits(tree, tvb, pinfo, bit_offset);

	return bit_offset;
}

/* Ref 7.3.2.1 Sequence parameter set RBSP syntax */
static int
dissect_h264_seq_parameter_set_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_item *level_item;
	gint bit_offset;
	guint8	constraint_set3_flag;
	guint32	level_idc;

	gint i;
	guint8 profile_idc, chroma_format_idc, frame_mbs_only_flag, frame_cropping_flag;
	guint8 pic_order_cnt_type, vui_parameters_present_flag, num_ref_frames_in_pic_order_cnt_cycle;
	guint8 seq_scaling_matrix_present_flag; /* seq_scaling_list_present_flag */

	/* profile_idc 0 u(8) */
	profile_idc = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(tree, hf_h264_profile_idc, tvb, offset, 1, FALSE);
	offset++;

	constraint_set3_flag = (tvb_get_guint8(tvb,offset)&0x10)>>4;
	/* constraint_set0_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set0_flag, tvb, offset, 1, FALSE);

	/* constraint_set1_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set1_flag, tvb, offset, 1, FALSE);

	/* constraint_set2_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set2_flag, tvb, offset, 1, FALSE);

	/* constraint_set3_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set3_flag, tvb, offset, 1, FALSE);

	/* reserved_zero_4bits  equal to 0  0 u(4)*/
	proto_tree_add_item(tree, hf_h264_reserved_zero_4bits, tvb, offset, 1, FALSE);
	offset++;

	/* level_idc 0 u(8) */
	level_idc = tvb_get_guint8(tvb,offset);
	level_item = proto_tree_add_item(tree, hf_h264_level_idc, tvb, offset, 1, FALSE);
	if((level_idc==11)&&(constraint_set3_flag==1)){
		proto_item_append_text(level_item,"[Level 1b]");
	}else{
		proto_item_append_text(level_item," [Level %.1f %s]",((double)level_idc/10),val_to_str(level_idc, h264_level_bitrate_values, "Unknown "));
	}
	offset++;
	/* seq_parameter_set_id 0 ue(v)
	 * ue(v): unsigned integer Exp-Golomb-coded syntax element with the left bit first.
	 * The parsing process for this descriptor is specified in subclause 9.1.
	 */
	bit_offset = offset<<3;
	dissect_h264_exp_golomb_code(tree, hf_h264_seq_parameter_set_id, tvb, &bit_offset, H264_UE_V);


	if( profile_idc == 100 || profile_idc == 110 ||
		profile_idc == 122 || profile_idc == 144 ) {

		/* chroma_format_idc 0 ue(v) */
		chroma_format_idc = dissect_h264_exp_golomb_code(tree, hf_h264_chroma_format_idc, tvb, &bit_offset, H264_UE_V);
		if( chroma_format_idc == 3 ){
			/* residual_colour_transform_flag 0 u(1) */
			proto_tree_add_bits_item(tree, hf_h264_residual_colour_transform_flag, tvb, bit_offset, 1, FALSE);
			bit_offset++;
		}

		/* bit_depth_luma_minus8 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_bit_depth_luma_minus8, tvb, &bit_offset, H264_UE_V);

		/* bit_depth_chroma_minus8 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_bit_depth_chroma_minus8, tvb, &bit_offset, H264_UE_V);

		/* qpprime_y_zero_transform_bypass_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_qpprime_y_zero_transform_bypass_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		/* seq_scaling_matrix_present_flag 0 u(1) */
		seq_scaling_matrix_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
		proto_tree_add_bits_item(tree, hf_h264_seq_scaling_matrix_present_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		if( seq_scaling_matrix_present_flag ){
			/*
			for( i = 0; i < 8; i++ ) {
				/ seq_scaling_list_present_flag[ i ] 0 u(1) /
				seq_scaling_list_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
				bit_offset++;
				if( seq_scaling_list_present_flag){
					if( i < 6 )
						scaling_list( ScalingList4x4[ i ], 16,UseDefaultScalingMatrix4x4Flag[ i ])0
						dissect_h264_scaling_list()
					else
						scaling_list( ScalingList8x8[ i - 6 ], 64,UseDefaultScalingMatrix8x8Flag[ i - 6 ] )0
				}
			}
			*/
			proto_tree_add_text(tree, tvb, offset, -1, "[Not decoded yet]");
			return -1;
		}

	}

	/* log2_max_frame_num_minus4 0 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_log2_max_frame_num_minus4, tvb, &bit_offset, H264_UE_V);

	/* pic_order_cnt_type 0 ue(v) */
	pic_order_cnt_type = dissect_h264_exp_golomb_code(tree,hf_h264_pic_order_cnt_type, tvb, &bit_offset, H264_UE_V);

	if(pic_order_cnt_type == 0){
		/* log2_max_pic_order_cnt_lsb_minus4 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_log2_max_pic_order_cnt_lsb_minus4, tvb, &bit_offset, H264_UE_V);
	}else if(pic_order_cnt_type == 1) {
		/* delta_pic_order_always_zero_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_delta_pic_order_always_zero_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		/* offset_for_non_ref_pic 0 se(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_offset_for_non_ref_pic, tvb, &bit_offset, H264_SE_V);

		/* offset_for_top_to_bottom_field 0 se(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_offset_for_top_to_bottom_field, tvb, &bit_offset, H264_SE_V);

		/* num_ref_frames_in_pic_order_cnt_cycle 0 ue(v) */
		num_ref_frames_in_pic_order_cnt_cycle = dissect_h264_exp_golomb_code(tree, hf_h264_num_ref_frames_in_pic_order_cnt_cycle, tvb, &bit_offset, H264_UE_V);
		for( i = 0; i < num_ref_frames_in_pic_order_cnt_cycle; i++ ){
			/*offset_for_ref_frame[ i ] 0 se(v)*/
			dissect_h264_exp_golomb_code(tree, hf_h264_offset_for_ref_frame, tvb, &bit_offset, H264_SE_V);
		}
	}
	/* num_ref_frames 0 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_num_ref_frames, tvb, &bit_offset, H264_UE_V);

	/* 	gaps_in_frame_num_value_allowed_flag 0 u(1) */
	proto_tree_add_bits_item(tree, hf_h264_gaps_in_frame_num_value_allowed_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* 	pic_width_in_mbs_minus1 0 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_pic_width_in_mbs_minus1, tvb, &bit_offset, H264_UE_V);

	/* pic_height_in_map_units_minus1 0 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_pic_height_in_map_units_minus1, tvb, &bit_offset, H264_UE_V);

	/* frame_mbs_only_flag 0 u(1) */
	frame_mbs_only_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_frame_mbs_only_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	if( !frame_mbs_only_flag ){
		/* mb_adaptive_frame_field_flag 0 u(1) */
		proto_tree_add_bits_item(tree, hf_h264_mb_adaptive_frame_field_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;
	}

	/* direct_8x8_inference_flag 0 u(1) */
	proto_tree_add_bits_item(tree, hf_h264_direct_8x8_inference_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* frame_cropping_flag 0 u(1) */
	frame_cropping_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_frame_cropping_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if(frame_cropping_flag) {
		/* frame_crop_left_offset 0 ue(v) */
		dissect_h264_exp_golomb_code(tree, hf_h264_frame_crop_left_offset, tvb, &bit_offset, H264_UE_V);
		dissect_h264_exp_golomb_code(tree,hf_h264_frame_crop_right_offset, tvb, &bit_offset, H264_UE_V);
		dissect_h264_exp_golomb_code(tree, hf_h264_frame_crop_top_offset, tvb, &bit_offset, H264_UE_V);
		dissect_h264_exp_golomb_code(tree, hf_h264_frame_crop_bottom_offset, tvb, &bit_offset, H264_UE_V);

	}

	/* 	vui_parameters_present_flag 0 u(1) */
	vui_parameters_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
	proto_tree_add_bits_item(tree, hf_h264_vui_parameters_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	if(vui_parameters_present_flag){
		bit_offset = dissect_h264_vui_parameters(tree, tvb, pinfo, bit_offset);
	}

	/* 	rbsp_trailing_bits( ) 0 */
	bit_offset = dissect_h264_rbsp_trailing_bits(tree, tvb, pinfo, bit_offset);

	offset = bit_offset>>3;

	return offset;
}

/* 7.3.2.2 Picture parameter set RBSP syntax */

static void
dissect_h264_pic_parameter_set_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{

	gint bit_offset;
	guint32 num_slice_groups_minus1, pic_scaling_matrix_present_flag;

	bit_offset = offset<<3;

	/* pic_parameter_set_id 1 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_pic_parameter_set_id, tvb, &bit_offset, H264_UE_V);

	/* seq_parameter_set_id 1 ue(v) */
	dissect_h264_exp_golomb_code(tree, hf_h264_seq_parameter_set_id, tvb, &bit_offset, H264_UE_V);

	/* entropy_coding_mode_flag 1 u(1) */
	proto_tree_add_bits_item(tree, hf_h264_entropy_coding_mode_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* pic_order_present_flag 1 u(1)*/
	proto_tree_add_bits_item(tree, hf_h264_pic_order_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* num_slice_groups_minus1 1 ue(v)*/
	num_slice_groups_minus1 = dissect_h264_exp_golomb_code(tree, hf_h264_num_slice_groups_minus1, tvb, &bit_offset, H264_UE_V);
	if( num_slice_groups_minus1 > 0 ) {
		/* slice_group_map_type 1 ue(v)*/
		dissect_h264_exp_golomb_code(tree, hf_h264_slice_group_map_type, tvb, &bit_offset, H264_UE_V);
	/*	slice_group_map_type = dissect_h264_exp_golomb_code(tree, hf_h264_slice_group_map_type, tvb, &bit_offset, H264_UE_V);*/
	/* if( slice_group_map_type == 0 )*/
	/* for( iGroup = 0; iGroup <= num_slice_groups_minus1; iGroup++ )*/
	/* run_length_minus1[ iGroup ] 1 ue(v)*/
	/* else if( slice_group_map_type == 2 )*/
	/* for( iGroup = 0; iGroup < num_slice_groups_minus1; iGroup++ ) {*/
	/* top_left[ iGroup ] 1 ue(v)*/
	/* bottom_right[ iGroup ] 1 ue(v)*/
	/* }*/
	/* else if( slice_group_map_type == 3 ||*/
	/* slice_group_map_type == 4 ||*/
	/* slice_group_map_type == 5 ) {*/
	/* slice_group_change_direction_flag 1 u(1)*/
	/* slice_group_change_rate_minus1 1 ue(v)*/
	/* } else if( slice_group_map_type == 6 ) {*/
	/* pic_size_in_map_units_minus1 1 ue(v)*/
	/* for( i = 0; i <= pic_size_in_map_units_minus1; i++ )*/
	/* slice_group_id[ i ] 1 u(v)*/
	/* }*/
	/* }*/
		proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "[Not decoded yet]");
		return;
	}
	/* num_ref_idx_l0_active_minus1 1 ue(v)*/
	dissect_h264_exp_golomb_code(tree, hf_h264_num_ref_idx_l0_active_minus1, tvb, &bit_offset, H264_UE_V);

	/* num_ref_idx_l1_active_minus1 1 ue(v)*/
	dissect_h264_exp_golomb_code(tree, hf_h264_num_ref_idx_l1_active_minus1, tvb, &bit_offset, H264_UE_V);

	/* weighted_pred_flag 1 u(1)*/
	proto_tree_add_bits_item(tree, hf_h264_weighted_pred_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* weighted_bipred_idc 1 u(2)*/
	proto_tree_add_bits_item(tree, hf_h264_weighted_bipred_idc, tvb, bit_offset, 2, FALSE);
	bit_offset= bit_offset+2;

	/* pic_init_qp_minus26  * relative to 26 * 1 se(v)*/
	dissect_h264_exp_golomb_code(tree, hf_h264_pic_init_qp_minus26, tvb, &bit_offset, H264_SE_V);

	/* pic_init_qs_minus26  * relative to 26 *  1 se(v)*/
	dissect_h264_exp_golomb_code(tree, hf_h264_pic_init_qs_minus26, tvb, &bit_offset, H264_SE_V);

	/* chroma_qp_index_offset 1 se(v)*/
	dissect_h264_exp_golomb_code(tree, hf_h264_chroma_qp_index_offset, tvb, &bit_offset, H264_SE_V);

	/* deblocking_filter_control_present_flag 1 u(1)*/
	proto_tree_add_bits_item(tree, hf_h264_deblocking_filter_control_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* constrained_intra_pred_flag 1 u(1)*/
	proto_tree_add_bits_item(tree, hf_h264_constrained_intra_pred_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	/* redundant_pic_cnt_present_flag 1 u(1)*/
	proto_tree_add_bits_item(tree, hf_h264_redundant_pic_cnt_present_flag, tvb, bit_offset, 1, FALSE);
	bit_offset++;

	if( more_rbsp_data(tree, tvb, pinfo, bit_offset)){
		/* transform_8x8_mode_flag 1 u(1)*/
		proto_tree_add_bits_item(tree, hf_h264_transform_8x8_mode_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		/* pic_scaling_matrix_present_flag 1 u(1)*/
		pic_scaling_matrix_present_flag = tvb_get_bits8(tvb, bit_offset, 1);
		proto_tree_add_bits_item(tree, hf_h264_pic_scaling_matrix_present_flag, tvb, bit_offset, 1, FALSE);
		bit_offset++;

		if( pic_scaling_matrix_present_flag ){
			proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "[Not decoded yet]");
			return;
			/* for( i = 0; i < 6 + 2* transform_8x8_mode_flag; i++ ) {*/
				/* pic_scaling_list_present_flag[ i ] 1 u(1)*/
				/* if( pic_scaling_list_present_flag[ i ] )*/
				/* if( i < 6 )*/
					/* scaling_list( ScalingList4x4[ i ], 16, UseDefaultScalingMatrix4x4Flag[ i ] )*/
				/* else*/
					/* scaling_list( ScalingList8x8[ i - 6 ], 64, UseDefaultScalingMatrix8x8Flag[ i - 6 ] )*/
			/* }*/
			}

		/* second_chroma_qp_index_offset 1 se(v)*/
		dissect_h264_exp_golomb_code(tree, hf_h264_second_chroma_qp_index_offset, tvb, &bit_offset, H264_SE_V);
	}
	bit_offset = dissect_h264_rbsp_trailing_bits(tree, tvb, pinfo, bit_offset);

}

/*
 * 7.3.2.4 Access unit delimiter RBSP syntax
 * access_unit_delimiter_rbsp( )
 */
static void
dissect_h264_access_unit_delimiter_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	/* primary_pic_type 6 u(3) */
	/* rbsp_trailing_bits( ) 6 */
	proto_tree_add_text(tree, tvb, offset, -1, "[Not decoded yet]");

}

/*
 * 7.3.2.5 End of sequence RBSP syntax
 * end_of_seq_rbsp( ) {}
 */
static void
dissect_h264_end_of_seq_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "[Not decoded yet]");

}

/*
 * 7.3.2.6 End of stream RBSP syntax
 * end_of_stream_rbsp( ) {}
 */
static void
dissect_h264_end_of_stream_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "[Not decoded yet]");

}

/*
 * 7.3.2.7 Filler data RBSP syntax
 * filler_data_rbsp( )
 */
static void
dissect_h264_filler_data_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	/* while( next_bits( 8 ) == 0xFF ) */
	/* ff_byte * equal to 0xFF * 9 f(8) */
	/* rbsp_trailing_bits( ) 9 */
	proto_tree_add_text(tree, tvb, offset, -1, "[Not decoded yet]");

}

/*
 * 7.3.2.1.2 Sequence parameter set extension RBSP syntax
 * seq_parameter_set_extension_rbsp( )
 */
static void
dissect_h264_seq_parameter_set_extension_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	/* seq_parameter_set_id 10 ue(v) */
	/* aux_format_idc 10 ue(v) */
	/* if( aux_format_idc != 0 ) { */
	/* bit_depth_aux_minus8 10 ue(v) */
	/* alpha_incr_flag 10 u(1) */
	/* alpha_opaque_value 10 u(v) */
	/* alpha_transparent_value 10 u(v) */
	/* } */
	/* additional_extension_flag 10 u(1) */
	/* rbsp_trailing_bits() 10 */
	proto_tree_add_text(tree, tvb, offset, -1, "[Not decoded yet]");

}


/*
 * Dissect NAL unit as recived in sprop-parameter-sets of SDP
 * or "DecoderConfiguration parameter in H.245
 */
void
dissect_h264_nal_unit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *h264_nal_tree;
	gint	offset = 0;
	guint8 nal_unit_type;
	guint32 dword;
	item = proto_tree_add_item(tree, hf_h264_nal_unit, tvb, offset, -1, FALSE);
	h264_nal_tree = proto_item_add_subtree(item, ett_h264_nal_unit);

startover:
	/* In decoder configuration start code may be pressent
	 * B.1.1 Byte stream NAL unit syntax
	 */
	dword = tvb_get_bits32(tvb, offset<<3, 32, FALSE);
	if(dword==1){
		/* zero_byte + start_code_prefix_one_3bytes */
		offset+=4;
	}else if((dword >> 8)== 1){
		/* start_code_prefix_one_3bytes */
		offset+= 3;
	}
	/* Ref: 7.3.1 NAL unit syntax */
	nal_unit_type = tvb_get_guint8(tvb,offset) & 0x1f;

	/* forbidden_zero_bit All f(1) */
	proto_tree_add_item(h264_nal_tree, hf_h264_forbidden_zero_bit, tvb, offset, 1, FALSE);
	/* nal_ref_idc All u(2) */
	proto_tree_add_item(h264_nal_tree, hf_h264_nal_ref_idc, tvb, offset, 1, FALSE);
	/* nal_unit_type All u(5) */
	proto_tree_add_item(h264_nal_tree, hf_h264_nal_unit_type, tvb, offset, 1, FALSE);
	offset++;

	switch(nal_unit_type){
	case 0: /* Unspecified */
		proto_tree_add_text(h264_nal_tree, tvb, offset, -1, "Unspecified NAL unit type");
		break;
	case 1:	/* Coded slice of a non-IDR picture */
		dissect_h264_slice_layer_without_partitioning_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 2:	/* Coded slice data partition A */
		dissect_h264_slice_data_partition_a_layer_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 3:	/* Coded slice data partition B */
		dissect_h264_slice_data_partition_b_layer_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 4:	/* Coded slice data partition C */
		dissect_h264_slice_data_partition_c_layer_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 5:	/* Coded slice of an IDR picture */
		dissect_h264_slice_layer_without_partitioning_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 6:	/* Supplemental enhancement information (SEI) */
		dissect_h264_sei_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case H264_SEQ_PAR_SET:	/* 7 Sequence parameter set*/
		offset = dissect_h264_seq_parameter_set_rbsp(h264_nal_tree, tvb, pinfo, offset);
		/* A bit ugly */
		if(tvb_length_remaining(tvb,offset) > 0){
			/* In this case length = offset as we start from zero */
			proto_item_set_len(item, offset/*Length */);
			item = proto_tree_add_item(tree, hf_h264_nal_unit, tvb, offset, -1, FALSE);
			h264_nal_tree = proto_item_add_subtree(item, ett_h264_nal_unit);
			goto startover;
		}
		break;
	case H264_PIC_PAR_SET:	/* 8 Picture parameter set */
		dissect_h264_pic_parameter_set_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 9:	/* Access unit delimiter */
		dissect_h264_access_unit_delimiter_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 10:	/* End of sequence */
		dissect_h264_end_of_seq_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 11:	/* End of stream */
		dissect_h264_end_of_stream_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 12:	/* Filler data */
		dissect_h264_filler_data_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 13:	/* Sequence parameter set extension */
		dissect_h264_seq_parameter_set_extension_rbsp(h264_nal_tree, tvb, pinfo, offset);
		break;
	case 14:	/* Reserved */
	case 15:	/* Reserved */
	case 16:	/* Reserved */
	case 17:	/* Reserved */
	case 18:	/* Reserved */
		proto_tree_add_text(h264_nal_tree, tvb, offset, -1, "Reserved NAL unit type");
		break;
	case 19:	/* Coded slice of an auxiliary coded picture without partitioning */
		dissect_h264_slice_layer_without_partitioning_rbsp(tree, tvb, pinfo, offset);
		break;
	case 28:
		dissect_h264_slice_layer_without_partitioning_rbsp(tree, tvb, pinfo, offset);
		break;
	default:
		/* 24..31 Unspecified */
		proto_tree_add_text(h264_nal_tree, tvb, offset, -1, "Unspecified NAL unit type");
		break;
	}

}
/* Code to actually dissect the packets */
static void
dissect_h264(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *item, *ti, *stream_item, *fua_item;
	proto_tree *h264_tree, *h264_nal_tree, *stream_tree, *fua_tree;
	guint8 type;


/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "H264");
	if (tree) {

		item = proto_tree_add_item(tree, proto_h264, tvb, 0, -1, FALSE);
		h264_tree = proto_item_add_subtree(item, ett_h264);

		type = tvb_get_guint8(tvb,offset)&0x1f;
/* if the type is 28, it would be draw another title */
		if(type == 28)
			ti = proto_tree_add_text(h264_tree, tvb, offset, 1, "FU identifier");
		else
			ti = proto_tree_add_text(h264_tree, tvb, offset, 1, "NAL unit header or first byte of the payload");
		h264_nal_tree = proto_item_add_subtree(ti, ett_h264_nal);

		/* +---------------+
		 * |0|1|2|3|4|5|6|7|
		 * +-+-+-+-+-+-+-+-+
		 * |F|NRI|  Type   |
		 * +---------------+
		 */

		/* F: 1 bit
		 * forbidden_zero_bit.  A value of 0 indicates that the NAL unit type
		 * octet and payload should not contain bit errors or other syntax
		 * violations.  A value of 1 indicates that the NAL unit type octet
		 * and payload may contain bit errors or other syntax violations.
		 */
		proto_tree_add_item(h264_nal_tree, hf_h264_nal_f_bit, tvb, offset, 1, FALSE);
		proto_tree_add_item(h264_nal_tree, hf_h264_nal_nri, tvb, offset, 1, FALSE);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
				val_to_str(type, h264_type_values, "Unknown Type (%u)"));
		}

		proto_tree_add_item(h264_nal_tree, hf_h264_type, tvb, offset, 1, FALSE);
		offset++;
		if (type == 28){
			fua_item = proto_tree_add_text(h264_tree, tvb, offset, 1, "FU Header");
			fua_tree = proto_item_add_subtree(fua_item, ett_h264_fua);
			proto_tree_add_item(fua_tree, hf_h264_start_bit, tvb, offset, 1, FALSE);
			proto_tree_add_item(fua_tree, hf_h264_end_bit, tvb, offset, 1, FALSE);
			proto_tree_add_item(fua_tree, hf_h264_forbidden_bit, tvb, offset, 1, FALSE);
			proto_tree_add_item(fua_tree, hf_h264_nal_unit_type, tvb, offset, 1, FALSE);
			if ( (tvb_get_guint8(tvb,offset)&0x80) == 0x80 ){
				type = tvb_get_guint8(tvb,offset)&0x1f;
				offset++;
			}
			else
				return;
		}
		stream_item =proto_tree_add_text(h264_tree, tvb, offset, -1, "H264 bitstream");
		stream_tree = proto_item_add_subtree(stream_item, ett_h264_stream);
		switch(type){
		case 1:				/* 1 Coded slice of a non-IDR picture */
			dissect_h264_slice_layer_without_partitioning_rbsp(stream_tree, tvb, pinfo, offset);
			break;
		case 3:	/* Coded slice data partition B */
			dissect_h264_slice_data_partition_b_layer_rbsp(h264_nal_tree, tvb, pinfo, offset);
			break;
		case 4:	/* Coded slice data partition C */
			dissect_h264_slice_data_partition_c_layer_rbsp(h264_nal_tree, tvb, pinfo, offset);
			break;
		case 5:	/* Coded slice of an IDR picture */
			dissect_h264_slice_layer_without_partitioning_rbsp(stream_tree, tvb, pinfo, offset);
			break;
		case 6:	/* Supplemental enhancement information (SEI) */
			dissect_h264_sei_rbsp(stream_tree, tvb, pinfo, offset);
			break;
		case H264_SEQ_PAR_SET:	/* 7 Sequence parameter set*/
			dissect_h264_seq_parameter_set_rbsp(stream_tree, tvb, pinfo, offset);
			break;
		case H264_PIC_PAR_SET:	/* 8 Picture parameter set */
			dissect_h264_pic_parameter_set_rbsp(stream_tree, tvb, pinfo, offset);
			break;
		case 19:	/* Coded slice of an auxiliary coded picture without partitioning */
			dissect_h264_slice_layer_without_partitioning_rbsp(stream_tree, tvb, pinfo, offset);
			break;
		default:
			break;
		}
	}/* if tree */

}


/* Capability */

static const int *profile_fields[] = {
  &hf_h264_par_profile_b,
  &hf_h264_par_profile_m,
  &hf_h264_par_profile_e,
  &hf_h264_par_profile_h,
  &hf_h264_par_profile_h10,
  &hf_h264_par_profile_h4_2_2,
  &hf_h264_par_profile_h4_4_4,
  NULL
};

static int
dissect_h264_par_profile(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  int offset = 0;

  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_h264_par_profile, ett_h264_par_profile,
                         profile_fields, FALSE);
  offset += 1;
  return offset;
}

static const int *AdditionalModesSupported_fields[] = {
  &hf_h264_par_add_mode_sup_rcdo,
  NULL
};
static int
dissect_h264_par_AdditionalModesSupported(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  int offset = 0;

  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_h264_par_AdditionalModesSupported, ett_h264_par_AdditionalModesSupported,
                         AdditionalModesSupported_fields, FALSE);
  offset += 1;
  return offset;
}


static const int *ProfileIOP_fields[] = {
  &hf_h264_par_constraint_set0_flag,
  &hf_h264_par_constraint_set1_flag,
  &hf_h264_par_constraint_set2_flag,
  NULL
};


static int
dissect_h264_ProfileIOP(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  int offset = 0;

  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_h264_par_ProfileIOP, ett_h264_par_ProfileIOP,
                         ProfileIOP_fields, FALSE);
  offset += 1;
  return offset;
}

static const value_string h264_par_level_values[] = {
  { 15,		"1" },
  { 19,		"1b" },
  { 22,		"1.1" },
  { 29,		"1.2" },
  { 36,		"1.3" },
  { 43,		"2" },
  { 50,		"2.1" },
  { 57,		"2.2" },
  { 64,		"3" },
  { 71,		"3.1" },
  { 78,		"3.2" },
  { 85,		"4" },
  { 92,		"4.1" },
  { 99,		"4.2" },
  { 106,	"5" },
  { 113 ,	"5.1" },
  { 0,	NULL }
};

static int
dissect_h264_par_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_)
{
  int offset = 0;
  guint16 lvl;
  const gchar *p = NULL;
  asn1_ctx_t *actx;

  actx = get_asn1_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(actx);

  lvl = tvb_get_ntohs(tvb, offset);
  p = match_strval(lvl, VALS(h264_par_level_values));
  if (p) {
    proto_item_append_text(actx->created_item, " - Level %s", p);
  }
  offset += 2;
  return offset;
}
static int
dissect_h264_par_DecoderConfigurationInformation(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_)
{
  asn1_ctx_t *actx;

  actx = get_asn1_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(actx);

  dissect_h264_nal_unit(tvb, pinfo, tree);

  return tvb_length(tvb);
}

typedef struct _h264_capability_t {
  const gchar *id;
  const gchar *name;
  new_dissector_t content_pdu;
} h264_capability_t;

static h264_capability_t h264_capability_tab[] = {
  /* ITU-T H.241 (05/2006), 8.3 H.264 capabilities */
  { "GenericCapability/0.0.8.241.0.0.1", "ITU-T Rec. H.241 H.264 Video Capabilities", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/41", "Profile", dissect_h264_par_profile },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/42", "Level", dissect_h264_par_level },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/3" , "CustomMaxMBPS", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/4" , "CustomMaxFS", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/5" , "CustomMaxDPB", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/6" , "CustomMaxBRandCPB", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/7" , "MaxStaticMBPS", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/8" , "max-rcmd-nal-unit-size", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/9" , "max-nal-unit-size", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/10", "SampleAspectRatiosSupported", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/11", "AdditionalModesSupported", dissect_h264_par_AdditionalModesSupported },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/12", "AdditionalDisplayCapabilities", NULL },
  /* TS 26.111  H.264 */
  { "GenericCapability/0.0.8.241.0.0.1/nonCollapsing/43" , "DecoderConfigurationInformation", dissect_h264_par_DecoderConfigurationInformation },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/44" , "AcceptRedundantSlices", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/45" , "NalAlignedMode", NULL },
  { "GenericCapability/0.0.8.241.0.0.1/collapsing/46" , "ProfileIOP", dissect_h264_ProfileIOP },
  { NULL, NULL, NULL },
};

static h264_capability_t *find_cap(const gchar *id) {
  h264_capability_t *ftr = NULL;
  h264_capability_t *f;

  for (f=h264_capability_tab; f->id; f++) {
    if (!strcmp(id, f->id)) { ftr = f; break; }
  }
  return ftr;
}

static void
dissect_h264_name(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree)
{
  asn1_ctx_t *actx;
  h264_capability_t *ftr = NULL;

  actx = get_asn1_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(actx);
  if (tree) {
    ftr = find_cap(pinfo->match_string);
    if (ftr) {
      proto_item_append_text(actx->created_item, " - %s", ftr->name);
      proto_item_append_text(proto_item_get_parent(proto_tree_get_parent(tree)), ": %s", ftr->name);
    } else {
      proto_item_append_text(actx->created_item, " - unknown(%s)", pinfo->match_string);
    }
  }
}


static void range_delete_h264_rtp_pt_callback(guint32 rtp_pt) {
  if (rtp_pt >= 96 && rtp_pt <= 127)
     dissector_delete_uint("rtp.pt", rtp_pt, h264_handle);
}

static void range_add_h264_rtp_pt_callback(guint32 rtp_pt) {
  if (rtp_pt >= 96 && rtp_pt <= 127)
     dissector_add_uint("rtp.pt", rtp_pt, h264_handle);
}



/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_h264(void)
{

	static range_t *dynamic_payload_type_range = NULL;
	static gboolean h264_prefs_initialized = FALSE;

	if (!h264_prefs_initialized) {
		dissector_handle_t h264_name_handle;
		h264_capability_t *ftr;

		h264_handle = find_dissector("h264");
		dissector_add_string("rtp_dyn_payload_type","H264", h264_handle);

		h264_name_handle = create_dissector_handle(dissect_h264_name, proto_h264);
		for (ftr=h264_capability_tab; ftr->id; ftr++) {
		    if (ftr->name)
				dissector_add_string("h245.gef.name", ftr->id, h264_name_handle);
			if (ftr->content_pdu)
				dissector_add_string("h245.gef.content", ftr->id, new_create_dissector_handle(ftr->content_pdu, proto_h264));
		}
		h264_prefs_initialized = TRUE;
	} else {
		range_foreach(dynamic_payload_type_range, range_delete_h264_rtp_pt_callback);
		g_free(dynamic_payload_type_range);
	}

	dynamic_payload_type_range = range_copy(temp_dynamic_payload_type_range);
	range_foreach(dynamic_payload_type_range, range_add_h264_rtp_pt_callback);
}

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_h264(void)
{

	module_t *h264_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_h264_nal_f_bit,
			{ "F bit",           "h264.f",
			FT_BOOLEAN, 8, TFS(&h264_f_bit_vals), 0x80,
			NULL, HFILL }
		},
		{ &hf_h264_nal_nri,
			{ "Nal_ref_idc (NRI)",           "h264.nal_nri",
			FT_UINT8, BASE_DEC, NULL, 0x60,
			NULL, HFILL }
		},
		{ &hf_h264_type,
			{ "Type",           "h264.nal_unit_hdr",
			FT_UINT8, BASE_DEC, VALS(h264_type_values), 0x1f,
			NULL, HFILL }
		},
		{ &hf_h264_start_bit,
			{ "Start bit", "h264.start.bit",
			FT_BOOLEAN, 8, TFS(&h264_start_bit_vals), 0x80,
			NULL, HFILL }
		},
		{ &hf_h264_end_bit,
			{ "End bit", "h264.end.bit",
			FT_BOOLEAN, 8, TFS(&h264_end_bit_vals), 0x40,
			NULL, HFILL }
		},
		{ &hf_h264_forbidden_bit,
			{ "Forbidden bit", "h264.forbidden.bit",
			FT_UINT8, BASE_DEC, NULL, 0x20,
			NULL, HFILL }
		},
		{ &hf_h264_profile,
			{ "Profile",           "h264.profile",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_profile_idc,
			{ "Profile_idc",           "h264.profile_idc",
			FT_UINT8, BASE_DEC, VALS(h264_profile_idc_values), 0xff,
			NULL, HFILL }
		},
		{ &hf_h264_rbsp_stop_bit,
			{ "rbsp_stop_bit",           "h264.rbsp_stop_bit",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_rbsp_trailing_bits,
			{ "rbsp_trailing_bits",           "h264.rbsp_trailing_bits",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_constraint_set0_flag,
			{ "Constraint_set0_flag",           "h264.constraint_set0_flag",
			FT_UINT8, BASE_DEC, NULL, 0x80,
			NULL, HFILL }
		},
		{ &hf_h264_constraint_set1_flag,
			{ "Constraint_set1_flag",           "h264.constraint_set1_flag",
			FT_UINT8, BASE_DEC, NULL, 0x40,
			NULL, HFILL }
		},
		{ &hf_h264_constraint_set2_flag,
			{ "Constraint_set2_flag",           "h264.constraint_set2_flag",
			FT_UINT8, BASE_DEC, NULL, 0x20,
			NULL, HFILL }
		},
		{ &hf_h264_constraint_set3_flag,
			{ "Constraint_set3_flag",           "h264.constraint_set3_flag",
			FT_UINT8, BASE_DEC, NULL, 0x10,
			NULL, HFILL }
		},
		{ &hf_h264_reserved_zero_4bits,
			{ "Reserved_zero_4bits",           "h264.reserved_zero_4bits",
			FT_UINT8, BASE_DEC, NULL, 0x0f,
			NULL, HFILL }
		},
		{ &hf_h264_level_idc,
			{ "Level_id",           "h264.level_id",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
		{ &hf_h264_nal_unit,
			{ "NAL unit",           "h264.nal_unit",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_forbidden_zero_bit,
			{ "Forbidden_zero_bit",           "h264.forbidden_zero_bit",
			FT_UINT8, BASE_DEC, NULL, 0x80,
			NULL, HFILL }
		},
		{ &hf_h264_nal_ref_idc,
			{ "Nal_ref_idc",           "h264.nal_ref_idc",
			FT_UINT8, BASE_DEC, NULL, 0x60,
			NULL, HFILL }
		},
		{&hf_h264_nal_unit_type,
			{ "Nal_unit_type",           "h264.nal_unit_type",
			FT_UINT8, BASE_DEC, VALS(h264_nal_unit_type_vals), 0x1f,
			NULL, HFILL }
		},
		{ &hf_h264_seq_parameter_set_id,
			{ "seq_parameter_set_id",           "h264.seq_parameter_set_id",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_chroma_format_idc,
			{ "chroma_format_id",           "h264.chroma_format_id",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_residual_colour_transform_flag,
			{ "residual_colour_transform_flag",           "h264.residual_colour_transform_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_bit_depth_luma_minus8,
			{ "bit_depth_luma_minus8",           "h264.bit_depth_luma_minus8",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_bit_depth_chroma_minus8,
			{ "bit_depth_chroma_minus8",           "h264.bit_depth_chroma_minus8",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_qpprime_y_zero_transform_bypass_flag,
			{ "qpprime_y_zero_transform_bypass_flag",           "h264.qpprime_y_zero_transform_bypass_flag",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_seq_scaling_matrix_present_flag,
			{ "seq_scaling_matrix_present_flag",           "h264.seq_scaling_matrix_present_flag",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_log2_max_frame_num_minus4,
			{ "log2_max_frame_num_minus4",           "h264.log2_max_frame_num_minus4",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_order_cnt_type,
			{ "pic_order_cnt_type",           "h264.pic_order_cnt_type",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_log2_max_pic_order_cnt_lsb_minus4,
			{ "log2_max_pic_order_cnt_lsb_minus4",           "h264.log2_max_pic_order_cnt_lsb_minus4",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_delta_pic_order_always_zero_flag,
			{ "delta_pic_order_always_zero_flag",           "h264.delta_pic_order_always_zero_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_offset_for_non_ref_pic,
			{ "offset_for_non_ref_pic",           "h264.offset_for_non_ref_pic",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_offset_for_top_to_bottom_field,
			{ "offset_for_top_to_bottom_field",           "h264.offset_for_top_to_bottom_field",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_ref_frames_in_pic_order_cnt_cycle,
			{ "num_ref_frames_in_pic_order_cnt_cycle",           "h264.num_ref_frames_in_pic_order_cnt_cycle",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_offset_for_ref_frame,
			{ "offset_for_ref_frame",           "h264.offset_for_ref_frame",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_ref_frames,
			{ "num_ref_frames",           "h264.num_ref_frames",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_gaps_in_frame_num_value_allowed_flag,
			{ "gaps_in_frame_num_value_allowed_flag",           "h264.gaps_in_frame_num_value_allowed_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_width_in_mbs_minus1,
			{ "pic_width_in_mbs_minus1",           "h264.pic_width_in_mbs_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_height_in_map_units_minus1,
			{ "pic_height_in_map_units_minus1",           "h264.pic_height_in_map_units_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_mbs_only_flag,
			{ "frame_mbs_only_flag",           "h264.frame_mbs_only_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_mb_adaptive_frame_field_flag,
			{ "mb_adaptive_frame_field_flag",           "h264.mb_adaptive_frame_field_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_direct_8x8_inference_flag,
			{ "direct_8x8_inference_flag",           "h264.direct_8x8_inference_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_cropping_flag,
			{ "frame_cropping_flag",           "h264.frame_cropping_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_crop_left_offset,
			{ "frame_crop_left_offset",           "h264.frame_crop_left_offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_crop_right_offset,
			{ "frame_crop_left_offset",           "h264.frame_crop_right_offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_crop_top_offset,
			{ "frame_crop_top_offset",           "h264.frame_crop_top_offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_crop_bottom_offset,
			{ "frame_crop_bottom_offset",           "h264.frame_crop_bottom_offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_vui_parameters_present_flag,
			{ "vui_parameters_present_flag",           "h264.vui_parameters_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_parameter_set_id,
			{ "pic_parameter_set_id",           "h264.pic_parameter_set_id",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_entropy_coding_mode_flag,
			{ "entropy_coding_mode_flag",           "h264.entropy_coding_mode_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_order_present_flag,
			{ "pic_order_present_flag",           "h264.pic_order_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_slice_groups_minus1,
			{ "num_slice_groups_minus1",           "h264.num_slice_groups_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_slice_group_map_type,
			{ "slice_group_map_type",           "h264.slice_group_map_type",
			FT_UINT32, BASE_DEC, VALS(h264_slice_group_map_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_ref_idx_l0_active_minus1,
			{ "num_ref_idx_l0_active_minus1",           "h264.num_ref_idx_l0_active_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_ref_idx_l1_active_minus1,
			{ "num_ref_idx_l1_active_minus1",           "h264.num_ref_idx_l1_active_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_weighted_pred_flag,
			{ "weighted_pred_flag",           "h264.weighted_pred_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_weighted_bipred_idc,
			{ "weighted_bipred_idc",           "h264.weighted_bipred_idc",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_init_qp_minus26,
			{ "pic_init_qp_minus26",           "h264.pic_init_qp_minus26",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_init_qs_minus26,
			{ "pic_init_qs_minus26",           "h264.pic_init_qs_minus26",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_chroma_qp_index_offset,
			{ "chroma_qp_index_offset",           "h264.chroma_qp_index_offset",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_deblocking_filter_control_present_flag,
			{ "deblocking_filter_control_present_flag",           "h264.deblocking_filter_control_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_constrained_intra_pred_flag,
			{ "constrained_intra_pred_flag",           "h264.constrained_intra_pred_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_redundant_pic_cnt_present_flag,
			{ "redundant_pic_cnt_present_flag",           "h264.redundant_pic_cnt_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_transform_8x8_mode_flag,
			{ "transform_8x8_mode_flag",           "h264.transform_8x8_mode_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_scaling_matrix_present_flag,
			{ "pic_scaling_matrix_present_flag",           "h264.pic_scaling_matrix_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_second_chroma_qp_index_offset,
			{ "second_chroma_qp_index_offset",           "h264.second_chroma_qp_index_offset",
			FT_INT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_h264_aspect_ratio_info_present_flag,
			{ "aspect_ratio_info_present_flag",           "h264.aspect_ratio_info_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_aspect_ratio_idc,
			{ "aspect_ratio_idc",           "h264.aspect_ratio_idc",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_sar_width,
			{ "sar_width",           "h264.sar_width",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_sar_height,
			{ "sar_height",           "h264.sar_height",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_overscan_info_present_flag,
			{ "overscan_info_present_flag",           "h264.overscan_info_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_overscan_appropriate_flag,
			{ "overscan_appropriate_flag",           "h264.overscan_appropriate_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_video_signal_type_present_flag,
			{ "video_signal_type_present_flag",           "h264.video_signal_type_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_video_format,
			{ "video_format",           "h264.video_format",
			FT_UINT8, BASE_DEC, VALS(h264_video_format_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_video_full_range_flag,
			{ "video_full_range_flag",           "h264.video_full_range_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_colour_description_present_flag,
			{ "colour_description_present_flag",           "h264.colour_description_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_colour_primaries,
			{ "colour_primaries",           "h264.colour_primaries",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_transfer_characteristics,
			{ "transfer_characteristics",           "h264.transfer_characteristics",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_matrix_coefficients,
			{ "matrix_coefficients",           "h264.matrix_coefficients",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_chroma_loc_info_present_flag,
			{ "chroma_loc_info_present_flag",           "h264.chroma_loc_info_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_chroma_sample_loc_type_top_field,
			{ "chroma_sample_loc_type_top_field",           "h264.chroma_sample_loc_type_top_field",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_chroma_sample_loc_type_bottom_field,
			{ "chroma_sample_loc_type_bottom_field",           "h264.chroma_sample_loc_type_bottom_field",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_timing_info_present_flag,
			{ "timing_info_present_flag",           "h264.timing_info_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_units_in_tick,
			{ "num_units_in_tick",           "h264.num_units_in_tick",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_time_scale,
			{ "time_scale",           "h264.time_scale",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_fixed_frame_rate_flag,
			{ "fixed_frame_rate_flag",           "h264.fixed_frame_rate_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_nal_hrd_parameters_present_flag,
			{ "nal_hrd_parameters_present_flag",           "h264.nal_hrd_parameters_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_vcl_hrd_parameters_present_flag,
			{ "vcl_hrd_parameters_present_flag",           "h264.vcl_hrd_parameters_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_low_delay_hrd_flag,
			{ "low_delay_hrd_flag",           "h264.low_delay_hrd_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_pic_struct_present_flag,
			{ "pic_struct_present_flag",           "h264.pic_struct_present_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_bitstream_restriction_flag,
			{ "bitstream_restriction_flag",           "h264.bitstream_restriction_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_motion_vectors_over_pic_boundaries_flag,
			{ "motion_vectors_over_pic_boundaries_flag",           "h264.motion_vectors_over_pic_boundaries_flag",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_max_bytes_per_pic_denom,
			{ "max_bytes_per_pic_denom",           "h264.max_bytes_per_pic_denom",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_max_bits_per_mb_denom,
			{ "max_bits_per_mb_denom",           "h264.max_bits_per_mb_denom",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_log2_max_mv_length_horizontal,
			{ "max_mv_length_horizontal",           "h264.max_mv_length_horizontal",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_log2_max_mv_length_vertical,
			{ "log2_max_mv_length_vertical",           "h264.log2_max_mv_length_vertical",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_num_reorder_frames,
			{ "num_reorder_frames",           "h264.num_reorder_frames",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_max_dec_frame_buffering,
			{ "max_dec_frame_buffering",           "h264.max_dec_frame_buffering",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_cpb_cnt_minus1,
			{ "cpb_cnt_minus1",           "h264.cpb_cnt_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_bit_rate_scale,
			{ "bit_rate_scale",           "h264.bit_rate_scale",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_cpb_size_scale,
			{ "cpb_size_scale",           "h264.cpb_size_scale",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_bit_rate_value_minus1,
			{ "bit_rate_value_minus1",           "h264.bit_rate_value_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_cpb_size_value_minus1,
			{ "cpb_size_value_minus1",           "h264.cpb_size_value_minus1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_cbr_flag,
			{ "cbr_flag",           "h264.cbr_flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_initial_cpb_removal_delay_length_minus1,
			{ "initial_cpb_removal_delay_length_minus1",           "h264.initial_cpb_removal_delay_length_minus1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_cpb_removal_delay_length_minus1,
			{ "cpb_removal_delay_length_minus1",           "h264.cpb_removal_delay_length_minus1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_dpb_output_delay_length_minus11,
			{ "dpb_output_delay_length_minus11",           "h264.dpb_output_delay_length_minus11",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_time_offset_length,
			{ "time_offset_length",           "h264.time_offset_length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_first_mb_in_slice,
			{ "first_mb_in_slice",           "h264.first_mb_in_slice",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_slice_type,
			{ "slice_type",           "h264.slice_type",
			FT_UINT32, BASE_DEC, VALS(h264_slice_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_slice_id,
			{ "slice_id",           "h264.slice_id",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_payloadsize,
			{ "PayloadSize",           "h264.payloadsize",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_payloadtype,
			{ "payloadType",           "h264.payloadtype",
			FT_UINT32, BASE_DEC, VALS(h264_sei_payload_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_frame_num,
			{ "frame_num",           "h264.frame_num",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h264_par_profile,
		        { "Profile", "h264.profile",
		        FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL}},
		{ &hf_h264_par_profile_b,
		        { "Baseline Profile", "h264.profile.base",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL}},
		{ &hf_h264_par_profile_m,
		        { "Main Profile", "h264.profile.main",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL}},
		{ &hf_h264_par_profile_e,
		        { "Extended Profile.", "h264.profile.ext",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL, HFILL}},
		{ &hf_h264_par_profile_h,
		        { "High Profile", "h264.profile.high",
			FT_BOOLEAN, 8, NULL, 0x08,
			NULL, HFILL}},
		{ &hf_h264_par_profile_h10,
		        { "High 10 Profile", "h264.profile.high10",
			FT_BOOLEAN, 8, NULL, 0x04,
			NULL, HFILL}},
		{ &hf_h264_par_profile_h4_2_2,
		        { "High 4:2:2 Profile", "h264.profile.high4_2_2",
			FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL}},
		{ &hf_h264_par_profile_h4_4_4,
		        { "High 4:4:4 Profile", "h264.profile.high4_4_4",
			FT_BOOLEAN, 8, NULL, 0x01,
			NULL, HFILL}},
		{ &hf_h264_par_AdditionalModesSupported,
		        { "AdditionalModesSupported", "h264.AdditionalModesSupported",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL}},
		{ &hf_h264_par_add_mode_sup,
		        { "Additional Modes Supported", "h264.add_mode_sup",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL}},
		{ &hf_h264_par_add_mode_sup_rcdo,
		        { "Reduced Complexity Decoding Operation (RCDO) support", "h264.add_mode_sup.rcdo",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL}},
		{ &hf_h264_par_ProfileIOP,
		        { "ProfileIOP", "h264.ProfileIOP",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL}},
		{ &hf_h264_par_constraint_set0_flag,
		        { "constraint_set0_flag", "h264.par.constraint_set0_flag",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL}},
		{ &hf_h264_par_constraint_set1_flag,
		        { "constraint_set1_flag", "h264.par.constraint_set1_flag",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL}},
		{ &hf_h264_par_constraint_set2_flag,
		        { "constraint_set2_flag", "h264.par.constraint_set2_flag",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL, HFILL}},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_h264,
		&ett_h264_profile,
		&ett_h264_nal,
		&ett_h264_fua,
		&ett_h264_stream,
		&ett_h264_nal_unit,
		&ett_h264_par_profile,
		&ett_h264_par_AdditionalModesSupported,
		&ett_h264_par_ProfileIOP,
	};

/* Register the protocol name and description */
	proto_h264 = proto_register_protocol("H.264","H264", "h264");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_h264, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	/* Register a configuration option for port */


	h264_module = prefs_register_protocol(proto_h264, proto_reg_handoff_h264);


	prefs_register_range_preference(h264_module, "dynamic.payload.type",
						    "H264 dynamic payload types",
						    "Dynamic payload types which will be interpreted as H264"
						    "; Values must be in the range 96 - 127",
						    &temp_dynamic_payload_type_range, 127);

	register_dissector("h264", dissect_h264, proto_h264);
}


