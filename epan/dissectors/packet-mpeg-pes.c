/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mpeg-pes.c                                                          */
/* asn2wrs.py -q -L -p mpeg-pes -c ./mpeg-pes.cnf -s ./packet-mpeg-pes-template -D . -O ../.. mpeg-pes.asn */

/* MPEG Packetized Elementary Stream (PES) packet decoder.
 * Written by Shaun Jackman <sjackman@gmail.com>.
 * Copyright 2007 Shaun Jackman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wiretap/wtap.h>

#include "packet-per.h"

static int hf_mpeg_pes_prefix;                    /* OCTET_STRING_SIZE_3 */
static int hf_mpeg_pes_stream;                    /* T_stream */
static int hf_mpeg_pes_length;                    /* INTEGER_0_65535 */
static int hf_mpeg_pes_must_be_one;               /* BOOLEAN */
static int hf_mpeg_pes_stream_must_be_zero;       /* BOOLEAN */
static int hf_mpeg_pes_scrambling_control;        /* T_scrambling_control */
static int hf_mpeg_pes_priority;                  /* BOOLEAN */
static int hf_mpeg_pes_data_alignment;            /* BOOLEAN */
static int hf_mpeg_pes_copyright;                 /* BOOLEAN */
static int hf_mpeg_pes_original;                  /* BOOLEAN */
static int hf_mpeg_pes_pts_flag;                  /* BOOLEAN */
static int hf_mpeg_pes_dts_flag;                  /* BOOLEAN */
static int hf_mpeg_pes_escr_flag;                 /* BOOLEAN */
static int hf_mpeg_pes_es_rate_flag;              /* BOOLEAN */
static int hf_mpeg_pes_dsm_trick_mode_flag;       /* BOOLEAN */
static int hf_mpeg_pes_additional_copy_info_flag;  /* BOOLEAN */
static int hf_mpeg_pes_crc_flag;                  /* BOOLEAN */
static int hf_mpeg_pes_extension_flag;            /* BOOLEAN */
static int hf_mpeg_pes_header_data_length;        /* INTEGER_0_255 */
static int hf_mpeg_pes_horizontal_size;           /* BIT_STRING_SIZE_12 */
static int hf_mpeg_pes_vertical_size;             /* BIT_STRING_SIZE_12 */
static int hf_mpeg_pes_aspect_ratio;              /* T_aspect_ratio */
static int hf_mpeg_pes_frame_rate;                /* T_frame_rate */
static int hf_mpeg_pes_bit_rate;                  /* BIT_STRING_SIZE_18 */
static int hf_mpeg_pes_vbv_buffer_size;           /* BIT_STRING_SIZE_10 */
static int hf_mpeg_pes_constrained_parameters_flag;  /* BOOLEAN */
static int hf_mpeg_pes_load_intra_quantiser_matrix;  /* BOOLEAN */
static int hf_mpeg_pes_load_non_intra_quantiser_matrix;  /* BOOLEAN */
static int hf_mpeg_pes_must_be_0001;              /* BIT_STRING_SIZE_4 */
static int hf_mpeg_pes_profile_and_level;         /* INTEGER_0_255 */
static int hf_mpeg_pes_progressive_sequence;      /* BOOLEAN */
static int hf_mpeg_pes_chroma_format;             /* INTEGER_0_3 */
static int hf_mpeg_pes_horizontal_size_extension;  /* INTEGER_0_3 */
static int hf_mpeg_pes_vertical_size_extension;   /* INTEGER_0_3 */
static int hf_mpeg_pes_bit_rate_extension;        /* BIT_STRING_SIZE_12 */
static int hf_mpeg_pes_vbv_buffer_size_extension;  /* INTEGER_0_255 */
static int hf_mpeg_pes_low_delay;                 /* BOOLEAN */
static int hf_mpeg_pes_frame_rate_extension_n;    /* INTEGER_0_3 */
static int hf_mpeg_pes_frame_rate_extension_d;    /* INTEGER_0_3 */
static int hf_mpeg_pes_drop_frame_flag;           /* BOOLEAN */
static int hf_mpeg_pes_hour;                      /* INTEGER_0_32 */
static int hf_mpeg_pes_minute;                    /* INTEGER_0_64 */
static int hf_mpeg_pes_second;                    /* INTEGER_0_64 */
static int hf_mpeg_pes_frame;                     /* INTEGER_0_64 */
static int hf_mpeg_pes_closed_gop;                /* BOOLEAN */
static int hf_mpeg_pes_broken_gop;                /* BOOLEAN */
static int hf_mpeg_pes_must_be_zero;              /* BIT_STRING_SIZE_5 */
static int hf_mpeg_pes_temporal_sequence_number;  /* BIT_STRING_SIZE_10 */
static int hf_mpeg_pes_frame_type;                /* T_frame_type */
static int hf_mpeg_pes_vbv_delay;                 /* BIT_STRING_SIZE_16 */
static int ett_mpeg_pes_PES;
static int ett_mpeg_pes_Stream;
static int ett_mpeg_pes_Sequence_header;
static int ett_mpeg_pes_Sequence_extension;
static int ett_mpeg_pes_Group_of_pictures;
static int ett_mpeg_pes_Picture;


static int
dissect_mpeg_pes_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const value_string mpeg_pes_T_stream_vals[] = {
  {   0, "picture" },
  { 179, "sequence-header" },
  { 181, "sequence-header-extension" },
  { 184, "group-of-pictures" },
  { 185, "program-end" },
  { 186, "pack-header" },
  { 187, "system-header" },
  { 188, "program-stream-map" },
  { 189, "private-stream-1" },
  { 190, "padding-stream" },
  { 191, "private-stream-2" },
  { 192, "audio-stream" },
  { 224, "video-stream" },
  { 0, NULL }
};


static int
dissect_mpeg_pes_T_stream(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t PES_sequence[] = {
  { &hf_mpeg_pes_prefix     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_OCTET_STRING_SIZE_3 },
  { &hf_mpeg_pes_stream     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_T_stream },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_pes_PES(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_pes_PES, PES_sequence);

  return offset;
}



static int
dissect_mpeg_pes_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_mpeg_pes_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string mpeg_pes_T_scrambling_control_vals[] = {
  {   0, "not-scrambled" },
  { 0, NULL }
};


static int
dissect_mpeg_pes_T_scrambling_control(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}



static int
dissect_mpeg_pes_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t Stream_sequence[] = {
  { &hf_mpeg_pes_length     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_65535 },
  { &hf_mpeg_pes_must_be_one, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_stream_must_be_zero, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_scrambling_control, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_T_scrambling_control },
  { &hf_mpeg_pes_priority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_data_alignment, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_copyright  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_original   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_pts_flag   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_dts_flag   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_escr_flag  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_es_rate_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_dsm_trick_mode_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_additional_copy_info_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_crc_flag   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_extension_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_header_data_length, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_pes_Stream(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_pes_Stream, Stream_sequence);

  return offset;
}



static int
dissect_mpeg_pes_BIT_STRING_SIZE_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 12, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string mpeg_pes_T_aspect_ratio_vals[] = {
  {   1, "aspect-1to1" },
  {   2, "aspect-4to3" },
  {   3, "aspect-16to9" },
  {   4, "aspect-2-21to1" },
  { 0, NULL }
};


static int
dissect_mpeg_pes_T_aspect_ratio(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string mpeg_pes_T_frame_rate_vals[] = {
  {   0, "reserved" },
  { 23976, "fr" },
  { 24000, "fr" },
  { 25000, "fr" },
  { 29970, "fr" },
  { 30000, "fr" },
  { 50000, "fr" },
  { 59940, "fr" },
  { 60000, "fr" },
  { 0, NULL }
};

static uint32_t T_frame_rate_value_map[9+0] = {0, 23976, 24000, 25000, 29970, 30000, 50000, 59940, 60000};

static int
dissect_mpeg_pes_T_frame_rate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, false, 0, T_frame_rate_value_map);

  return offset;
}



static int
dissect_mpeg_pes_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_mpeg_pes_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Sequence_header_sequence[] = {
  { &hf_mpeg_pes_horizontal_size, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_12 },
  { &hf_mpeg_pes_vertical_size, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_12 },
  { &hf_mpeg_pes_aspect_ratio, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_T_aspect_ratio },
  { &hf_mpeg_pes_frame_rate , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_T_frame_rate },
  { &hf_mpeg_pes_bit_rate   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_18 },
  { &hf_mpeg_pes_must_be_one, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_vbv_buffer_size, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_10 },
  { &hf_mpeg_pes_constrained_parameters_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_load_intra_quantiser_matrix, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_load_non_intra_quantiser_matrix, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_pes_Sequence_header(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_pes_Sequence_header, Sequence_header_sequence);

  return offset;
}



static int
dissect_mpeg_pes_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_mpeg_pes_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}


static const per_sequence_t Sequence_extension_sequence[] = {
  { &hf_mpeg_pes_must_be_0001, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_4 },
  { &hf_mpeg_pes_profile_and_level, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_255 },
  { &hf_mpeg_pes_progressive_sequence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_chroma_format, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_3 },
  { &hf_mpeg_pes_horizontal_size_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_3 },
  { &hf_mpeg_pes_vertical_size_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_3 },
  { &hf_mpeg_pes_bit_rate_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_12 },
  { &hf_mpeg_pes_must_be_one, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_vbv_buffer_size_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_255 },
  { &hf_mpeg_pes_low_delay  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_frame_rate_extension_n, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_3 },
  { &hf_mpeg_pes_frame_rate_extension_d, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_pes_Sequence_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_pes_Sequence_extension, Sequence_extension_sequence);

  return offset;
}



static int
dissect_mpeg_pes_INTEGER_0_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32U, NULL, false);

  return offset;
}



static int
dissect_mpeg_pes_INTEGER_0_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 64U, NULL, false);

  return offset;
}



static int
dissect_mpeg_pes_BIT_STRING_SIZE_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Group_of_pictures_sequence[] = {
  { &hf_mpeg_pes_drop_frame_flag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_hour       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_32 },
  { &hf_mpeg_pes_minute     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_64 },
  { &hf_mpeg_pes_must_be_one, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_second     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_64 },
  { &hf_mpeg_pes_frame      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_INTEGER_0_64 },
  { &hf_mpeg_pes_closed_gop , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_broken_gop , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BOOLEAN },
  { &hf_mpeg_pes_must_be_zero, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_5 },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_pes_Group_of_pictures(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_pes_Group_of_pictures, Group_of_pictures_sequence);

  return offset;
}


static const value_string mpeg_pes_T_frame_type_vals[] = {
  {   1, "i-frame" },
  {   2, "p-frame" },
  {   3, "b-frame" },
  {   4, "d-frame" },
  { 0, NULL }
};


static int
dissect_mpeg_pes_T_frame_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_mpeg_pes_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Picture_sequence[] = {
  { &hf_mpeg_pes_temporal_sequence_number, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_10 },
  { &hf_mpeg_pes_frame_type , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_T_frame_type },
  { &hf_mpeg_pes_vbv_delay  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_pes_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_pes_Picture(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_pes_Picture, Picture_sequence);

  return offset;
}


void proto_register_mpeg_pes(void);
void proto_reg_handoff_mpeg_pes(void);

static int proto_mpeg;
static int proto_mpeg_pes;

static int ett_mpeg_pes_pack_header;
static int ett_mpeg_pes_header_data;
static int ett_mpeg_pes_trick_mode;

static int hf_mpeg_pes_pack_header;
static int hf_mpeg_pes_scr;
static int hf_mpeg_pes_program_mux_rate;
static int hf_mpeg_pes_stuffing_length;
static int hf_mpeg_pes_stuffing;
static int hf_mpeg_pes_extension;
static int hf_mpeg_pes_header_data;
static int hf_mpeg_pes_pts;
static int hf_mpeg_pes_dts;
static int hf_mpeg_pes_escr;
static int hf_mpeg_pes_es_rate;
static int hf_mpeg_pes_dsm_trick_mode;
static int hf_mpeg_pes_dsm_trick_mode_control;
static int hf_mpeg_pes_dsm_trick_mode_field_id;
static int hf_mpeg_pes_dsm_trick_mode_intra_slice_refresh;
static int hf_mpeg_pes_dsm_trick_mode_frequency_truncation;
static int hf_mpeg_pes_dsm_trick_mode_rep_cntrl;
static int hf_mpeg_pes_copy_info;
static int hf_mpeg_pes_crc;
static int hf_mpeg_pes_extension_flags;
static int hf_mpeg_pes_private_data;
static int hf_mpeg_pes_pack_length;
static int hf_mpeg_pes_sequence;
static int hf_mpeg_pes_pstd_buffer;
static int hf_mpeg_pes_extension2;
static int hf_mpeg_pes_padding;
static int hf_mpeg_pes_data;

static int hf_mpeg_video_sequence_header;
static int hf_mpeg_video_sequence_extension;
static int hf_mpeg_video_group_of_pictures;
static int hf_mpeg_video_picture;
static int hf_mpeg_video_quantization_matrix;
static int hf_mpeg_video_data;

static dissector_handle_t mpeg_handle;

static dissector_table_t stream_type_table;

enum { PES_PREFIX = 1 };

/*
 * MPEG uses 32-bit start codes that all begin with the three byte sequence
 * 00 00 01 (the start code prefix) for bit and byte alignment, among other
 * purposes.
 *
 * The values from 0xb9 through 0xff are "system start codes" and described in
 * ISO/IEC 13818-1:2019 / ITU-T H.222.0. The bulk of them, 0xbc through 0xff,
 * are stream_id values and documented in Table 2-22 "Stream_id assignments".
 * The remaining three are used by Program Streams and found as follows:
 * 0xb9, the MPEG_program_end_code, in 2.5.3.2 "Semantic definition of fields
 * in program stream"
 * 0xba, the pack_start_code, in 2.5.3.4 "Semantic definition of fields in
 * program stream pack"
 * 0xbb, the system_header_start_code, in 2.5.3.6 "Semantic definition of fields
 * in system header"
 *
 * The remaining 185 values from 0x00 to 0xb8 are used by MPEG-2 video
 * (backwards compatible with MPEG-1 video) and documented in ISO/IEC 13818-2 /
 * ITU-T H.262 (2000), in Table 6-1 "Start code values". These are not stream
 * id values and do not mark PES packets, but rather demarcate elements in the
 * coded MPEG-1/2 video bitstream, at a different hierarchical level than the
 * PES packets. The sets of values used for video start codes and for stream
 * ids are disjoint to avoid any ambiguity when resynchronizing. Note the
 * dissector currently conflates MPEG video with MPEG PES.
 *
 * Care is taken to ensure that the start code prefix 0x000001 does not occur
 * elsewhere in the structure (avoiding "emulation of start codes").
 *
 * The video can have other formats, given by the stream type, carried on
 * TS in the PMT and in PS from the similar Program Stream Map. AVC/H.264 and
 * HEVC/H.265 carried in PES also use the start code prefix, before each NAL,
 * and escape the raw byte sequence with bytes that prevent internal start code
 * prefixes. The byte following the prefix (the first byte of the NAL header)
 * has high bit zero, so the values of the NAL header are in the range used by
 * the MPEG-2 video bitstream, not the range used by stream ids, allowing for
 * synchronization in the same way. See Annex B "Byte Stream Format" of H.264
 * and H.265.
 */
enum {
	STREAM_PICTURE = 0x00,
	STREAM_SEQUENCE = 0xb3,
	STREAM_SEQUENCE_EXTENSION = 0xb5,
	STREAM_GOP = 0xb8,
	STREAM_END = 0xb9,
	STREAM_PACK = 0xba,
	STREAM_SYSTEM = 0xbb,
	STREAM_PROGRAM = 0xbc,
	STREAM_PRIVATE1 = 0xbd,
	STREAM_PADDING = 0xbe,
	STREAM_PRIVATE2 = 0xbf,
	STREAM_AUDIO = 0xc0,
	STREAM_VIDEO = 0xe0
};

enum {
	PTS_FLAG = 0x80,
	DTS_FLAG = 0x40,
	ESCR_FLAG = 0x20,
	ES_RATE_FLAG = 0x10,
	DSM_TRICK_MODE_FLAG = 0x08,
	COPY_INFO_FLAG = 0x04,
	CRC_FLAG = 0x02,
	EXTENSION_FLAG = 0x01
};

enum {
	PRIVATE_DATA_FLAG = 0x80,
	PACK_LENGTH_FLAG = 0x40,
	SEQUENCE_FLAG = 0x20,
	PSTD_BUFFER_FLAG = 0x10,
	MUST_BE_ONES = 0x07,
	EXTENSION_FLAG2 = 0x01
};

enum {
	FAST_FORWARD_CONTROL = 0x00,
	SLOW_MOTION_CONTROL = 0x01,
	FREEZE_FRAME_CONTROL = 0x02,
	FAST_REVERSE_CONTROL = 0x03,
	SLOW_REVERSE_CONTROL = 0x04
};

static const value_string mpeg_pes_TrickModeControl_vals[] = {
  { FAST_FORWARD_CONTROL, "fast-forward" },
  { SLOW_MOTION_CONTROL,  "slow-motion" },
  { FREEZE_FRAME_CONTROL, "freeze-frame" },
  { FAST_REVERSE_CONTROL, "fast-reverse" },
  { SLOW_REVERSE_CONTROL, "slow-reverse" },
  {   5, "reserved" },
  {   6, "reserved" },
  {   7, "reserved" },
  {   0, NULL }
};

static const value_string mpeg_pes_TrickModeFieldId_vals[] = {
  {   0, "display-from-top-field-only" },
  {   1, "display-from-bottom-field-only" },
  {   2, "display-complete-frame" },
  {   3, "reserved" },
  {   0, NULL }
};

static const value_string mpeg_pes_TrickModeIntraSliceRefresh_vals[] = {
  {   0, "macroblocks-may-not-be-missing" },
  {   1, "macroblocks-may-be-missing" },
  {   0, NULL }
};

static const value_string mpeg_pes_TrickModeFrequencyTruncation_vals[] = {
  {   0, "only-DC-coefficients-are-non-zero" },
  {   1, "only-the-first-three-coefficients-are-non-zero" },
  {   2, "only-the-first-six-coefficients-are-non-zero" },
  {   3, "all-coefficients-may-be-non-zero" },
  {   0, NULL }
};

#define TSHZ 90000

static uint64_t decode_time_stamp(tvbuff_t *tvb, int offset, nstime_t *nst)
{
	uint64_t bytes = tvb_get_ntoh40(tvb, offset);
	uint64_t ts =
		(bytes >> 33 & 0x0007) << 30 |
		(bytes >> 17 & 0x7fff) << 15 |
		(bytes >>  1 & 0x7fff) << 0;
	unsigned int rem = (unsigned int)(ts % TSHZ);
	nst->secs = (time_t)(ts / TSHZ);
	nst->nsecs = (int)(INT64_C(1000000000) * rem / TSHZ);
	return ts;
}

#define SCRHZ 27000000

static uint64_t decode_clock_reference(tvbuff_t *tvb, int offset,
		nstime_t *nst)
{
	uint64_t bytes = tvb_get_ntoh48(tvb, offset);
	uint64_t ts =
		(bytes >> 43 & 0x0007) << 30 |
		(bytes >> 27 & 0x7fff) << 15 |
		(bytes >> 11 & 0x7fff) << 0;
	unsigned int ext = (unsigned int)((bytes >> 1) & 0x1ff);
	uint64_t cr = 300 * ts + ext;
	unsigned int rem = (unsigned int)(cr % SCRHZ);
	nst->secs = (time_t)(cr / SCRHZ);
	nst->nsecs = (int)(INT64_C(1000000000) * rem / SCRHZ);
	return cr;
}

static int
dissect_mpeg_pes_header_data(tvbuff_t *tvb, packet_info *pinfo _U_,
		proto_tree *root, unsigned int flags)
{
	proto_item *item = proto_tree_add_item(root, hf_mpeg_pes_header_data, tvb,
			0, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_mpeg_pes_header_data);

	int offset = 0;
	if (flags & PTS_FLAG) {
		nstime_t nst;
		decode_time_stamp(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_pts, tvb,
				offset, 5, &nst);
		offset += 5;
	}
	if (flags & DTS_FLAG) {
		nstime_t nst;
		decode_time_stamp(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_dts, tvb,
				offset, 5, &nst);
		offset += 5;
	}
	if (flags & ESCR_FLAG) {
		nstime_t nst;
		decode_clock_reference(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_escr, tvb,
				offset, 6, &nst);
		offset += 6;
	}
	if (flags & ES_RATE_FLAG) {
		unsigned int es_rate = (tvb_get_ntohs(tvb, offset) >> 1 & 0x3fff) * 50;
		proto_tree_add_uint(tree, hf_mpeg_pes_es_rate, tvb,
				offset, 3, es_rate);
		offset += 3;
	}
	if (flags & DSM_TRICK_MODE_FLAG)
	{
		uint8_t value = tvb_get_uint8(tvb, offset);
		uint8_t control;
		proto_tree *trick_tree;
		proto_item *trick_item;

		trick_item = proto_tree_add_item(item,
			hf_mpeg_pes_dsm_trick_mode, tvb,
				offset, 1, ENC_NA);

		trick_tree = proto_item_add_subtree(trick_item,
			ett_mpeg_pes_trick_mode);

		control = (value >> 5);
		proto_tree_add_uint(trick_tree,
			hf_mpeg_pes_dsm_trick_mode_control, tvb,
			offset, 1,
			control);

		if (control == FAST_FORWARD_CONTROL
			|| control == FAST_REVERSE_CONTROL)
		{
			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_field_id, tvb,
				offset, 1,
				(value & 0x18) >> 3);

			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_intra_slice_refresh, tvb,
				offset, 1,
				(value & 0x04) >> 2);

			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_frequency_truncation, tvb,
				offset, 1,
				(value & 0x03));
		}
		else if (control == SLOW_MOTION_CONTROL
			|| control == SLOW_REVERSE_CONTROL)
		{
			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_rep_cntrl, tvb,
				offset, 1,
				(value & 0x1F));
		}
		else if (control == FREEZE_FRAME_CONTROL)
		{
			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_field_id, tvb,
				offset, 1,
				(value & 0x18) >> 3);
		}

		offset += 1;
	}
	if (flags & COPY_INFO_FLAG) {
		proto_tree_add_item(tree, hf_mpeg_pes_copy_info, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}
	if (flags & CRC_FLAG) {
		proto_tree_add_item(tree, hf_mpeg_pes_crc, tvb,
				offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (flags & EXTENSION_FLAG) {
		int flags2 = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_mpeg_pes_extension_flags, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;

		if (flags2 & PRIVATE_DATA_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_private_data, tvb,
					offset, 16, ENC_NA);
			offset += 16;
		}
		if (flags2 & PACK_LENGTH_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_pack_length, tvb,
					offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}
		if (flags2 & SEQUENCE_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_sequence, tvb,
					offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		if (flags2 & PSTD_BUFFER_FLAG) {
			unsigned int pstd = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(tree, hf_mpeg_pes_pstd_buffer, tvb,
					offset, 2, (pstd & 0x2000 ? 1024 : 128) * (pstd & 0x1ff));
			offset += 2;
		}
		if (flags2 & EXTENSION_FLAG2) {
			proto_tree_add_item(tree, hf_mpeg_pes_extension2, tvb,
					offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	return offset;
}

static int
dissect_mpeg_pes_pack_header(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *root)
{
	unsigned int program_mux_rate, stuffing_length;

	proto_item *item = proto_tree_add_item(root, hf_mpeg_pes_pack_header, tvb,
			offset / 8, 10, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_mpeg_pes_pack_header);

	nstime_t nst;
	decode_clock_reference(tvb, offset / 8, &nst);
	proto_tree_add_time(tree, hf_mpeg_pes_scr, tvb, offset / 8, 6, &nst);
	offset += 6 * 8;

	program_mux_rate = (tvb_get_ntoh24(tvb, offset / 8) >> 2) * 50;
	proto_tree_add_uint(tree, hf_mpeg_pes_program_mux_rate, tvb, offset / 8, 3,
			program_mux_rate);
	offset += 3 * 8;

	stuffing_length = tvb_get_uint8(tvb, offset / 8) & 0x07;
	proto_tree_add_item(tree, hf_mpeg_pes_stuffing_length, tvb,
			offset / 8, 1, ENC_BIG_ENDIAN);
	offset += 1 * 8;

	if (stuffing_length > 0) {
		proto_tree_add_item(tree, hf_mpeg_pes_stuffing, tvb,
				offset / 8, stuffing_length, ENC_NA);
		offset += stuffing_length * 8;
	}

	return offset;
}

static int
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_mpeg_pes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int prefix;
	int stream;
	asn1_ctx_t asn1_ctx;
	int offset = 0;
	uint8_t stream_type;

	if (!tvb_bytes_exist(tvb, 0, 3))
		return 0;	/* not enough bytes for a PES prefix */

	prefix = tvb_get_ntoh24(tvb, 0);
	if (prefix != PES_PREFIX)
		return 0;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG PES");
	col_clear(pinfo->cinfo, COL_INFO);

	stream = tvb_get_uint8(tvb, 3);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(stream, mpeg_pes_T_stream_vals, "Unknown stream: %d"));

	/* Were we called from MP2T providing a stream type from a PMT? */
	stream_type = GPOINTER_TO_UINT(data);
	/* Luckily, stream_type 0 is reserved, so a null value is fine.
	 * XXX: Implement Program Stream Map for Program Stream (similar
	 * to PMT but maps stream_ids to stream_types instead of PIDs.)
	 */

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
	offset = dissect_mpeg_pes_PES(tvb, offset, &asn1_ctx,
			tree, proto_mpeg_pes);

	increment_dissection_depth(pinfo);
	if (stream == STREAM_PICTURE) {
		int frame_type;

		frame_type = tvb_get_uint8(tvb, 5) >> 3 & 0x07;
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(frame_type, mpeg_pes_T_frame_type_vals, "Unknown frame type: %d"));

		offset = dissect_mpeg_pes_Picture(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_picture);
		proto_tree_add_item(tree, hf_mpeg_video_data, tvb,
				offset / 8, -1, ENC_NA);
	} else if (stream == STREAM_SEQUENCE) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Sequence_header(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_sequence_header);

		proto_tree_add_item(tree, hf_mpeg_video_quantization_matrix, tvb,
				offset / 8, 64, ENC_NA);
		offset += 64 * 8;

		es = tvb_new_subset_remaining(tvb, offset / 8);
		dissect_mpeg_pes(es, pinfo, tree, NULL);
	} else if (stream == STREAM_SEQUENCE_EXTENSION) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Sequence_extension(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_sequence_extension);

		es = tvb_new_subset_remaining(tvb, offset / 8);
		dissect_mpeg_pes(es, pinfo, tree, NULL);
	} else if (stream == STREAM_GOP) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Group_of_pictures(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_group_of_pictures);

		es = tvb_new_subset_remaining(tvb, offset / 8);
		dissect_mpeg_pes(es, pinfo, tree, NULL);
	} else if (stream == STREAM_PACK) {
		if (tvb_get_uint8(tvb, offset / 8) >> 6 == 1) {
			dissect_mpeg_pes_pack_header(tvb, offset, pinfo, tree);
		} else {
			proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
					offset / 8, 8, ENC_NA);
		}
	} else if (stream == STREAM_SYSTEM || stream == STREAM_PRIVATE2) {
		unsigned int data_length = tvb_get_ntohs(tvb, offset / 8);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, ENC_BIG_ENDIAN);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, data_length, ENC_NA);
	} else if (stream == STREAM_PADDING) {
		unsigned int padding_length = tvb_get_ntohs(tvb, offset / 8);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, ENC_BIG_ENDIAN);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_padding, tvb,
				offset / 8, padding_length, ENC_NA);
	} else if (stream == STREAM_PRIVATE1
			|| stream >= STREAM_AUDIO) {
		int length = tvb_get_ntohs(tvb, 4);

		if ((tvb_get_uint8(tvb, 6) & 0xc0) == 0x80) {
			int header_length;
			tvbuff_t *es;
			int save_offset = offset;

			offset = dissect_mpeg_pes_Stream(tvb, offset, &asn1_ctx,
					tree, hf_mpeg_pes_extension);
			/* https://gitlab.com/wireshark/wireshark/-/issues/2229
			 * A value of 0 indicates that the PES packet length
			 * is neither specified nor bounded and is allowed
			 * only in PES packets whose payload is a video
			 * elementary stream contained in Transport Stream
			 * packets.
			 *
			 * See ISO/IEC 13818-1:2007, section 2.4.3.7
			 * "Semantic definition of fields in PES packet",
			 * which says of the PES_packet_length that "A value
			 * of 0 indicates that the PES packet length is
			 * neither specified nor bounded and is allowed only
			 * in PES packets whose payload consists of bytes
			 * from a video elementary stream contained in
			 * Transport Stream packets."
			 */
			if(length !=0 && stream != STREAM_VIDEO){
				/*
				 * XXX - note that ISO/IEC 13818-1:2007
				 * says that the length field is *not*
				 * part of the above extension.
				 *
				 * This means that the length of the length
				 * field itself should *not* be subtracted
				 * from the length field; ISO/IEC 13818-1:2007
				 * says that the PES_packet_length field is
				 * "A 16-bit field specifying the number of
				 * bytes in the PES packet following the
				 * last byte of the field."
				 *
				 * So we calculate the size of the extension,
				 * in bytes, by subtracting the saved bit
				 * offset value from the current bit offset
				 * value, divide by 8 to convert to a size
				 * in bytes, and then subtract 2 to remove
				 * the length field's length from the total
				 * length.
				 *
				 * (In addition, ISO/IEC 13818-1:2007
				 * suggests that the length field is
				 * always present, but this code, when
				 * processing some stream ID types, doesn't
				 * treat it as being present.  Where are
				 * the formats of those payloads specified?)
				 */
				length -= ((offset - save_offset) / 8) - 2;
			}

			header_length = tvb_get_uint8(tvb, 8);
			if (header_length > 0) {
				int flags = tvb_get_uint8(tvb, 7);
				tvbuff_t *header_data = tvb_new_subset_length(tvb, offset / 8,
						header_length);
				dissect_mpeg_pes_header_data(header_data, pinfo, tree, flags);
				offset += header_length * 8;
				 /* length may be zero for Video stream */
				if(length !=0 && stream != STREAM_VIDEO){
					length -= header_length;
				}
			}

			/* length may be zero for Video stream */
			if(length==0){
				es = tvb_new_subset_remaining(tvb, offset / 8);
			} else {
				es = tvb_new_subset_length_caplen(tvb, offset / 8, -1, length);
			}
			if (!dissector_try_uint_new(stream_type_table, stream_type, es, pinfo, tree, true, NULL)) {
				/* If we didn't get a stream type, then assume
				 * MPEG-1/2 Audio or Video.
				 */
				if (tvb_get_ntoh24(es, 0) == PES_PREFIX)
					dissect_mpeg_pes(es, pinfo, tree, NULL);
				else if (tvb_get_uint8(es, 0) == 0xff)
					dissect_mpeg(es, pinfo, tree, NULL);
				else
					proto_tree_add_item(tree, hf_mpeg_pes_data, es,
							0, -1, ENC_NA);
			}
		} else {
			unsigned int data_length = tvb_get_ntohs(tvb, offset / 8);
			proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
					offset / 8, 2, ENC_BIG_ENDIAN);
			offset += 2 * 8;

			proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
					offset / 8, data_length, ENC_NA);
		}
	} else if (stream != STREAM_END) {
		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, -1, ENC_NA);
	}
	decrement_dissection_depth(pinfo);
	return tvb_reported_length(tvb);
}

static heur_dissector_list_t heur_subdissector_list;

static int
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    heur_dtbl_entry_t *hdtbl_entry;

    if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL)) {
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG");
	    col_clear(pinfo->cinfo, COL_INFO);

	    proto_tree_add_item(tree, proto_mpeg, tvb, 0, -1, ENC_NA);
    }
	return tvb_captured_length(tvb);
}

static bool
dissect_mpeg_pes_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  return dissect_mpeg_pes(tvb, pinfo, tree, data) > 0;
}

void
proto_register_mpeg_pes(void)
{
	static hf_register_info hf[] = {
    { &hf_mpeg_pes_prefix,
      { "prefix", "mpeg-pes.prefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_mpeg_pes_stream,
      { "stream", "mpeg-pes.stream",
        FT_UINT8, BASE_HEX, VALS(mpeg_pes_T_stream_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_pes_length,
      { "length", "mpeg-pes.length",
        FT_UINT16, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_mpeg_pes_must_be_one,
      { "must-be-one", "mpeg-pes.must_be_one",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_stream_must_be_zero,
      { "must-be-zero", "mpeg-pes.stream.must-be-zero",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_scrambling_control,
      { "scrambling-control", "mpeg-pes.scrambling_control",
        FT_UINT8, BASE_DEC, VALS(mpeg_pes_T_scrambling_control_vals), 0x30,
        NULL, HFILL }},
    { &hf_mpeg_pes_priority,
      { "priority", "mpeg-pes.priority",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_data_alignment,
      { "data-alignment", "mpeg-pes.data_alignment",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_copyright,
      { "copyright", "mpeg-pes.copyright",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_original,
      { "original", "mpeg-pes.original",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_pts_flag,
      { "pts-flag", "mpeg-pes.pts_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_dts_flag,
      { "dts-flag", "mpeg-pes.dts_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_escr_flag,
      { "escr-flag", "mpeg-pes.escr_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_es_rate_flag,
      { "es-rate-flag", "mpeg-pes.es_rate_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_dsm_trick_mode_flag,
      { "dsm-trick-mode-flag", "mpeg-pes.dsm_trick_mode_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_additional_copy_info_flag,
      { "additional-copy-info-flag", "mpeg-pes.additional_copy_info_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_crc_flag,
      { "crc-flag", "mpeg-pes.crc_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_extension_flag,
      { "extension-flag", "mpeg-pes.extension_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_header_data_length,
      { "header-data-length", "mpeg-pes.header_data_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_mpeg_pes_horizontal_size,
      { "horizontal-size", "mpeg-pes.horizontal_size",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_12", HFILL }},
    { &hf_mpeg_pes_vertical_size,
      { "vertical-size", "mpeg-pes.vertical_size",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_12", HFILL }},
    { &hf_mpeg_pes_aspect_ratio,
      { "aspect-ratio", "mpeg-pes.aspect_ratio",
        FT_UINT32, BASE_DEC, VALS(mpeg_pes_T_aspect_ratio_vals), 0,
        "T_aspect_ratio", HFILL }},
    { &hf_mpeg_pes_frame_rate,
      { "frame-rate", "mpeg-pes.frame_rate",
        FT_UINT32, BASE_DEC, VALS(mpeg_pes_T_frame_rate_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_pes_bit_rate,
      { "bit-rate", "mpeg-pes.bit_rate",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_mpeg_pes_vbv_buffer_size,
      { "vbv-buffer-size", "mpeg-pes.vbv_buffer_size",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_mpeg_pes_constrained_parameters_flag,
      { "constrained-parameters-flag", "mpeg-pes.constrained_parameters_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_load_intra_quantiser_matrix,
      { "load-intra-quantiser-matrix", "mpeg-pes.load_intra_quantiser_matrix",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_load_non_intra_quantiser_matrix,
      { "load-non-intra-quantiser-matrix", "mpeg-pes.load_non_intra_quantiser_matrix",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_must_be_0001,
      { "must-be-0001", "mpeg-pes.must_be_0001",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_mpeg_pes_profile_and_level,
      { "profile-and-level", "mpeg-pes.profile_and_level",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_mpeg_pes_progressive_sequence,
      { "progressive-sequence", "mpeg-pes.progressive_sequence",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_chroma_format,
      { "chroma-format", "mpeg-pes.chroma_format",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_pes_horizontal_size_extension,
      { "horizontal-size-extension", "mpeg-pes.horizontal_size_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_pes_vertical_size_extension,
      { "vertical-size-extension", "mpeg-pes.vertical_size_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_pes_bit_rate_extension,
      { "bit-rate-extension", "mpeg-pes.bit_rate_extension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_12", HFILL }},
    { &hf_mpeg_pes_vbv_buffer_size_extension,
      { "vbv-buffer-size-extension", "mpeg-pes.vbv_buffer_size_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_mpeg_pes_low_delay,
      { "low-delay", "mpeg-pes.low_delay",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_frame_rate_extension_n,
      { "frame-rate-extension-n", "mpeg-pes.frame_rate_extension_n",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_pes_frame_rate_extension_d,
      { "frame-rate-extension-d", "mpeg-pes.frame_rate_extension_d",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_pes_drop_frame_flag,
      { "drop-frame-flag", "mpeg-pes.drop_frame_flag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_hour,
      { "hour", "mpeg-pes.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32", HFILL }},
    { &hf_mpeg_pes_minute,
      { "minute", "mpeg-pes.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_64", HFILL }},
    { &hf_mpeg_pes_second,
      { "second", "mpeg-pes.second",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_64", HFILL }},
    { &hf_mpeg_pes_frame,
      { "frame", "mpeg-pes.frame",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_64", HFILL }},
    { &hf_mpeg_pes_closed_gop,
      { "closed-gop", "mpeg-pes.closed_gop",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_broken_gop,
      { "broken-gop", "mpeg-pes.broken_gop",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_pes_must_be_zero,
      { "must-be-zero", "mpeg-pes.must_be_zero",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_mpeg_pes_temporal_sequence_number,
      { "temporal-sequence-number", "mpeg-pes.temporal_sequence_number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_mpeg_pes_frame_type,
      { "frame-type", "mpeg-pes.frame_type",
        FT_UINT32, BASE_DEC, VALS(mpeg_pes_T_frame_type_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_pes_vbv_delay,
      { "vbv-delay", "mpeg-pes.vbv_delay",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
		{ &hf_mpeg_pes_pack_header,
			{ "Pack header", "mpeg-pes.pack",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_scr,
			{ "system clock reference (SCR)", "mpeg-pes.scr",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_program_mux_rate,
			{ "PES program mux rate", "mpeg-pes.program-mux-rate",
				FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_stuffing_length,
			{ "PES stuffing length", "mpeg-pes.stuffing-length",
				FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }},
		{ &hf_mpeg_pes_stuffing,
			{ "PES stuffing bytes", "mpeg-pes.stuffing",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension,
			{ "PES extension", "mpeg-pes.extension",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_header_data,
			{ "PES header data", "mpeg-pes.header-data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_pts,
			{ "presentation time stamp (PTS)", "mpeg-pes.pts",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_dts,
			{ "decode time stamp (DTS)", "mpeg-pes.dts",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_escr,
			{ "elementary stream clock reference (ESCR)", "mpeg-pes.escr",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_es_rate,
			{ "elementary stream rate", "mpeg-pes.es-rate",
				FT_UINT24, BASE_DEC, NULL, 0x7ffe, NULL, HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode,
			{ "Trick mode", "mpeg-pes.trick-mode",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_control,
			{ "control", "mpeg-pes.trick-mode-control",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeControl_vals), 0,
				"mpeg_pes trick mode control", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_field_id,
			{ "field id", "mpeg-pes.trick-mode-field-id",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeFieldId_vals), 0,
				"mpeg_pes trick mode field id", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_intra_slice_refresh,
			{ "intra slice refresh", "mpeg-pes.trick-mode-intra-slice-refresh",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeIntraSliceRefresh_vals), 0,
				"mpeg_pes trick mode intra slice refresh", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_frequency_truncation,
			{ "frequency truncation", "mpeg-pes.trick-mode-frequency-truncation",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeFrequencyTruncation_vals), 0,
				"mpeg_pes trick mode frequency truncation", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_rep_cntrl,
			{ "rep cntrl", "mpeg-pes.trick-mode-rep-cntrl",
				FT_UINT8, BASE_HEX, NULL, 0, "mpeg_pes trick mode rep cntrl", HFILL }},
		{ &hf_mpeg_pes_copy_info,
			{ "copy info", "mpeg-pes.copy-info",
				FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_mpeg_pes_crc,
			{ "CRC", "mpeg-pes.crc",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension_flags,
			{ "extension flags", "mpeg-pes.extension-flags",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_private_data,
			{ "private data", "mpeg-pes.private-data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_pack_length,
			{ "pack length", "mpeg-pes.pack-length",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_sequence,
			{ "sequence", "mpeg-pes.sequence",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_pstd_buffer,
			{ "P-STD buffer size", "mpeg-pes.pstd-buffer",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension2,
			{ "extension2", "mpeg-pes.extension2",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_padding,
			{ "PES padding", "mpeg-pes.padding",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_data,
			{ "PES data", "mpeg-pes.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_sequence_header,
			{ "MPEG sequence header", "mpeg-video.sequence",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_sequence_extension,
			{ "MPEG sequence extension", "mpeg-video.sequence-ext",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_group_of_pictures,
			{ "MPEG group of pictures", "mpeg-video.gop",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_picture,
			{ "MPEG picture", "mpeg-video.picture",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_quantization_matrix,
			{ "MPEG quantization matrix", "mpeg-video.quant",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_data,
			{ "MPEG picture data", "mpeg-video.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static int *ett[] = {
    &ett_mpeg_pes_PES,
    &ett_mpeg_pes_Stream,
    &ett_mpeg_pes_Sequence_header,
    &ett_mpeg_pes_Sequence_extension,
    &ett_mpeg_pes_Group_of_pictures,
    &ett_mpeg_pes_Picture,
		&ett_mpeg_pes_pack_header,
		&ett_mpeg_pes_header_data,
		&ett_mpeg_pes_trick_mode
	};

	proto_mpeg = proto_register_protocol("Moving Picture Experts Group", "MPEG", "mpeg");
	mpeg_handle = register_dissector("mpeg", dissect_mpeg, proto_mpeg);
	heur_subdissector_list = register_heur_dissector_list_with_description("mpeg", "MPEG payload", proto_mpeg);

	proto_mpeg_pes = proto_register_protocol("Packetized Elementary Stream", "MPEG PES", "mpeg-pes");
	proto_register_field_array(proto_mpeg_pes, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("mpeg-pes", dissect_mpeg_pes, proto_mpeg_pes);

	stream_type_table = register_dissector_table("mpeg-pes.stream", "MPEG PES stream type", proto_mpeg_pes, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_mpeg_pes(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MPEG, mpeg_handle);
	heur_dissector_add("mpeg", dissect_mpeg_pes_heur, "MPEG PES", "mpeg_pes", proto_mpeg_pes, HEURISTIC_ENABLE);

	dissector_add_uint("mpeg-pes.stream", 0x1B, find_dissector_add_dependency("h264_bytestream", proto_mpeg_pes));
	dissector_add_uint("mpeg-pes.stream", 0x24, find_dissector_add_dependency("h265_bytestream", proto_mpeg_pes));
}
