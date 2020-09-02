/* packet-xra.c
 * Routines for Excentis DOCSIS31 XRA31 sniffer dissection
 * Copyright 2017, Bruno Verstuyft <bruno.verstuyft[AT]excentis.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>

void proto_register_xra(void);
void proto_reg_handoff_xra(void);

/* Initialize the protocol and registered fields */
static dissector_handle_t docsis_handle;
static dissector_handle_t xra_handle;


static int proto_xra = -1;

static int proto_plc = -1;
static int proto_ncp = -1;
static int proto_segment = -1;
static int proto_init_ranging = -1;


static gint ett_xra = -1;
static gint ett_xra_tlv = -1;
static gint ett_xra_tlv_cw_info = -1;
static gint ett_xra_tlv_ms_info = -1;
static gint ett_xra_tlv_burst_info = -1;
static gint ett_plc = -1;
static gint ett_plc_mb = -1;
static gint ett_plc_timestamp = -1;
static gint ett_ncp = -1;
static gint ett_ncp_mb = -1;
static gint ett_init_ranging = -1;

static gint hf_xra_version = -1;
static gint hf_xra_direction = -1;
static gint hf_xra_packettype = -1;
static gint hf_xra_tlvlength = -1;
static gint hf_xra_tlv = -1;
/*
 * XRA TLV
 */
static gint hf_xra_tlv_ds_channel_id = -1;
static gint hf_xra_tlv_ds_channel_frequency = -1;
static gint hf_xra_tlv_modulation = -1;
static gint hf_xra_tlv_annex = -1;
static gint hf_xra_tlv_us_channel_id = -1;
static gint hf_xra_tlv_profile_id = -1;
static gint hf_xra_tlv_sid = -1;
static gint hf_xra_tlv_iuc = -1;
static gint hf_xra_tlv_burstid = -1;
static gint hf_xra_tlv_ms_info = -1;
static gint hf_xra_tlv_burst_info = -1;
static gint hf_xra_tlv_ucd_ccc_parity = -1;
static gint hf_xra_tlv_grant_size = -1;
static gint hf_xra_tlv_segment_header_present = -1;
static gint hf_xra_tlv_ncp_trunc = -1;
static gint hf_xra_tlv_ncp_symbolid = -1;

/*
 * Minislot Info
 */
static gint hf_xra_tlv_start_minislot_id_abs = -1;
static gint hf_xra_tlv_start_minislot_id_rel = -1;
static gint hf_xra_tlv_stop_minislot_id_rel = -1;

/*
 *Ranging TLV
*/
static gint hf_xra_tlv_ranging_number_ofdma_frames = -1;
static gint hf_xra_tlv_ranging_timing_adjust = -1;

static gint hf_xra_tlv_power_level = -1;
static gint hf_xra_tlv_mer = -1;
static gint hf_xra_tlv_subslot_id =-1;
static gint hf_xra_tlv_control_word = -1;

static gint hf_xra_unknown = -1;

/*
 * Codeword Info TLV
 */
static gint hf_xra_tlv_cw_info = -1;
static gint hf_xra_tlv_cw_info_nr_of_info_bytes = -1;
static gint hf_xra_tlv_cw_info_bch_decoding_successful = -1;
static gint hf_xra_tlv_cw_info_profile_parity = -1;
static gint hf_xra_tlv_cw_info_bch_number_of_corrected_bits = -1;
static gint hf_xra_tlv_cw_info_ldpc_nr_of_code_bits = -1;
static gint hf_xra_tlv_cw_info_ldpc_decoding_successful = -1;
static gint hf_xra_tlv_cw_info_ldpc_number_of_corrected_bits = -1;
static gint hf_xra_tlv_cw_info_ldpc_number_of_iterations = -1;
static gint hf_xra_tlv_cw_info_rs_decoding_successful = -1;
static gint hf_xra_tlv_cw_info_rs_number_of_corrected_symbols = -1;

/*
 * Burst Info TLV
 */
static gint hf_xra_tlv_burst_info_burst_id_reference = -1;

/*
 * PLC specific
 */
static gint hf_plc_mb = -1;

/*
 * NCP specific
 */
static gint hf_ncp_mb = -1;
static gint hf_ncp_mb_profileid = -1;
static gint hf_ncp_mb_z = -1;
static gint hf_ncp_mb_c = -1;
static gint hf_ncp_mb_n = -1;
static gint hf_ncp_mb_l = -1;
static gint hf_ncp_mb_t = -1;
static gint hf_ncp_mb_u = -1;
static gint hf_ncp_mb_r = -1;
static gint hf_ncp_mb_subcarrier_start_pointer = -1;
static gint hf_ncp_crc = -1;

/*
 * Init Ranging Specific
 */
static gint hf_xra_init_ranging_mac = -1;
static gint hf_xra_init_ranging_ds_channel_id = -1;
static gint hf_xra_init_ranging_crc = -1;

/*
 *PLC MB
 */
static gint hf_plc_em_mb = -1;
static gint hf_plc_trigger_mb = -1;

/*
 * PLC Timestamp MB specific
 */
static gint hf_plc_mb_ts_reserved = -1;
static gint hf_plc_mb_ts_timestamp = -1;
static gint hf_plc_mb_ts_timestamp_epoch = -1;
static gint hf_plc_mb_ts_timestamp_d30timestamp = -1;
static gint hf_plc_mb_ts_timestamp_extra_204_8 = -1;
static gint hf_plc_mb_ts_timestamp_extra_204_8_X_16 = -1;
static gint hf_plc_mb_ts_timestamp_formatted = -1;
static gint hf_plc_mb_ts_crc24d = -1;

/*
 * PLC Message Channel MB specific
 */
static gint hf_plc_mb_mc_reserved = -1;
static gint hf_plc_mb_mc_pspf_present = -1;
static gint hf_plc_mb_mc_psp = -1;

/*
 * OFDMA SEGMENT
 */
static gint hf_docsis_segment_pfi = -1;
static gint hf_docsis_segment_reserved = -1;
static gint hf_docsis_segment_pointerfield = -1;
static gint hf_docsis_segment_sequencenumber = -1;
static gint hf_docsis_segment_sidclusterid = -1;
static gint hf_docsis_segment_request = -1;
static gint hf_docsis_segment_hcs = -1;
static gint hf_docsis_segment_hcs_status = -1;
static gint hf_docsis_segment_data = -1;

static expert_field ei_docsis_segment_hcs_bad = EI_INIT;

static int dissect_xra(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_);
static int dissect_xra_tlv(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_, guint16 tlvLength, guint* segmentHeaderPresent);
static int dissect_plc(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_);
static int dissect_ncp(tvbuff_t * tvb, proto_tree * tree, void* data _U_);
static int dissect_init_ranging(tvbuff_t * tvb, proto_tree * tree, void* data _U_);
static int dissect_ofdma_segment(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, void* data _U_);



#define XRA_DIRECTION_DOWNSTREAM 0
#define XRA_DIRECTION_UPSTREAM 1

#define XRA_PACKETTYPE_DS_SCQAM_DOCSIS_MACFRAME 1
#define XRA_PACKETTYPE_OFDM_DOCSIS 8
#define XRA_PACKETTYPE_OFDM_NCP 9
#define XRA_PACKETTYPE_OFDM_PLC 10
#define XRA_PACKETTYPE_OFDM_PLC_MMM 11

#define XRA_PACKETTYPE_TDMA_BURST 65
#define XRA_PACKETTYPE_OFDMA_DATA_BURST 72
#define XRA_PACKETTTYPE_OFDMA_INITIAL_RANGING 73
#define XRA_PACKETTTYPE_OFDMA_FINE_RANGING 74
#define XRA_PACKETTYPE_OFDMA_REQ 75
#define XRA_PACKETTYPE_OFDMA_PROBING_SEQUENCE 76
#define XRA_PACKETTYPE_US_DOCSIS_MACFRAME 80

/*TLVs*/
#define XRA_DS_CHANNEL_ID 1
#define XRA_DS_FREQUENCY 2
#define XRA_MODULATION 3
#define XRA_ANNEX 4
#define XRA_PROFILE_ID 5
#define XRA_CODEWORD_INFO 6
#define XRA_NCP_TRUNC 7
#define XRA_NCP_SYMBOLID 8
#define XRA_MER 9
#define XRA_US_CHANNEL_ID 10
#define XRA_SID 11
#define XRA_IUC 12
#define XRA_BURST_ID 13
#define XRA_BURST_INFO 14
#define XRA_MINISLOT_INFO 15
#define XRA_UCD_CCC_PARITY 16
#define XRA_GRANT_SIZE 17
#define XRA_SEGMENT_HEADER_PRESENT 18
#define XRA_NUMBER_OFDMA_FRAMES 19
#define XRA_ESTIMATED_TIMING_ADJUST 20
#define XRA_ESTIMATED_POWER_LEVEL 21
#define XRA_SUBSLOT_ID 22
#define XRA_CONTROL_WORD 23

#define XRA_CONFIGURATION_INFO 254
#define XRA_EXTENSION_TYPE 255


/*Codeword Info Sub-Tlvs*/
#define XRA_TLV_CW_INFO_PROFILE_PARITY 1
#define XRA_TLV_CW_INFO_NR_OF_INFO_BYTES 2
#define XRA_TLV_CW_INFO_BCH_DECODING_SUCCESFUL 3
#define XRA_TLV_CW_INFO_BCH_NUMBER_OF_CORRECTED_BITS 4
#define XRA_TLV_CW_INFO_LDPC_NUMBER_OF_CODE_BITS 5
#define XRA_TLV_CW_INFO_LDPC_DECODING_SUCCESSFUL 6
#define XRA_TLV_CW_INFO_LDPC_NUMBER_OF_CORRECTED_BITS 7
#define XRA_TLV_CW_INFO_LDPC_NUMBER_OF_ITERATIONS 8
#define XRA_TLV_CW_INFO_RS_DECODING_SUCCESFUL 9
#define XRA_TLV_CW_INFO_RS_NUMBER_OF_CORRECTED_SYMBOLS 10

/*Burst Info Sub-Tlv*/
#define XRA_BURST_INFO_BURST_ID_REFERENCE 1

/*Minislot Info Sub-TLVs*/
#define XRA_TLV_MINISLOT_INFO_START_MINISLOT_ID 1
#define XRA_TLV_MINISLOT_INFO_REL_START_MINISLOT 2
#define XRA_TLV_MINISLOT_INFO_REL_STOP_MINISLOT 3



/*PLC Message Block Types*/
#define PLC_TIMESTAMP_MB 1
#define PLC_ENERGY_MANAGEMENT_MB 2
#define PLC_MESSAGE_CHANNEL_MB 3
#define PLC_TRIGGER_MB 4




static const value_string direction_vals[] = {
  {XRA_DIRECTION_DOWNSTREAM, "Downstream"},
  {XRA_DIRECTION_UPSTREAM, "Upstream"},
  {0, NULL}
};

static const value_string packettype[] = {
  {XRA_PACKETTYPE_DS_SCQAM_DOCSIS_MACFRAME, "SC-QAM DOCSIS Macframe"},
  {XRA_PACKETTYPE_OFDM_DOCSIS, "OFDM DOCSIS"},
  {XRA_PACKETTYPE_OFDM_NCP, "OFDM NCP"},
  {XRA_PACKETTYPE_OFDM_PLC, "OFDM PLC"},
  {XRA_PACKETTYPE_OFDM_PLC_MMM, "OFDM PLC MMM"},
  {XRA_PACKETTYPE_TDMA_BURST, "TDMA Burst"},
  {XRA_PACKETTYPE_OFDMA_DATA_BURST, "OFDMA Data Burst"},
  {XRA_PACKETTTYPE_OFDMA_INITIAL_RANGING, "OFDMA Initial Ranging"},
  {XRA_PACKETTTYPE_OFDMA_FINE_RANGING, "OFDMA Fine Ranging"},
  {XRA_PACKETTYPE_OFDMA_REQ, "OFDMA REQ"},
  {XRA_PACKETTYPE_OFDMA_PROBING_SEQUENCE, "OFDMA Probing Sequence"},
  {XRA_PACKETTYPE_US_DOCSIS_MACFRAME, "US DOCSIS Macframe"},
  {0, NULL}
};

static const value_string annex_vals[] = {
  {0, "Annex A"},
  {1, "Annex B"},
  {0, NULL}
};

static const value_string modulation_vals[] = {
  {0, "64-QAM"},
  {1, "256-QAM"},
  {0, NULL}
};


static const value_string profile_id[] = {
  {0, "Profile A"},
  {1, "Profile B"},
  {2, "Profile C"},
  {3, "Profile D"},
  {4, "Profile E"},
  {5, "Profile F"},
  {6, "Profile G"},
  {7, "Profile H"},
  {8, "Profile I"},
  {9, "Profile J"},
  {10, "Profile K"},
  {11, "Profile L"},
  {12, "Profile M"},
  {13, "Profile N"},
  {14, "Profile O"},
  {15, "Profile P"},
  {0, NULL}
};

static const value_string message_block_type[] = {
  {PLC_TIMESTAMP_MB, "Timestamp Message Block"},
  {PLC_ENERGY_MANAGEMENT_MB, "Energy Management Message Block"},
  {PLC_MESSAGE_CHANNEL_MB, "Message Channel Message Block"},
  {PLC_TRIGGER_MB, "Trigger Message Block"},
  {0, NULL}
};

static const value_string packet_start_pointer_field[] = {
  {0, "Not Present"},
  {1, "Present"},
  {0, NULL}
};

static const true_false_string zero_bit_loading = {
  "subcarriers are all zero-bit-loaded",
  "subcarriers follow profile"
};

static const true_false_string data_profile_update = {
  "use odd profile",
  "use even profile"
};

static const true_false_string ncp_profile_select = {
  "use odd profile",
  "use even profile"
};

static const true_false_string last_ncp_block = {
  "this is the last NCP in the chain and is followed by an NCP CRC message block",
  "this NCP is followed by another NCP"
};

static const true_false_string codeword_tagging = {
  "this codeword is included in the codeword counts reported by the CM in the OPT-RSP message",
  "this codeword is not included in the codeword counts reported by the CM in the OPT-RSP message"
};

static const value_string local_proto_checksum_vals[] = {
  { PROTO_CHECKSUM_E_BAD, "Bad"},
  { PROTO_CHECKSUM_E_GOOD, "Good"},
  { 0, NULL}
};

static const value_string control_word_vals[] = {
  { 0, "I=128, J=1"},
  { 1, "I=128, J=1"},
  { 2, "I=128, J=2"},
  { 3, "I=64, J=2"},
  { 4, "I=128, J=3"},
  { 5, "I=32, J=4"},
  { 6, "I=128, J=4"},
  { 7, "I=16, J=8"},
  { 8, "I=128, J=5"},
  { 9, "I=8, J=16"},
  { 10, "I=128, J=6"},
  { 11, "Reserved"},
  { 12, "I=128, J=7"},
  { 13, "Reserved"},
  { 14, "I=128, J=8"},
  { 15, "Reserved"},
  { 0, NULL}
};

static int
dissect_xra(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_) {
  proto_item *it;
  proto_tree *xra_tree;

  it = proto_tree_add_protocol_format (tree, proto_xra, tvb, 0, -1,"XRA");

  xra_tree = proto_item_add_subtree (it, ett_xra);

  tvbuff_t *docsis_tvb;
  tvbuff_t *plc_tvb;
  tvbuff_t *ncp_tvb;
  tvbuff_t *xra_tlv_tvb;
  tvbuff_t *segment_tvb;
  tvbuff_t *init_ranging_tvb;

  guint direction, packet_type, tlv_length;

  proto_tree_add_item (xra_tree, hf_xra_version, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (xra_tree, hf_xra_direction, tvb, 1, 1, ENC_BIG_ENDIAN, &direction);
  proto_tree_add_item_ret_uint (xra_tree, hf_xra_packettype, tvb, 1, 1, ENC_BIG_ENDIAN, &packet_type);
  proto_tree_add_item_ret_uint (xra_tree, hf_xra_tlvlength, tvb, 2, 2, ENC_BIG_ENDIAN, &tlv_length);

  guint16 xra_length = 4 + tlv_length;
  proto_item_append_text(it, " (Excentis XRA header: %d bytes). DOCSIS frame is %d bytes.", xra_length, tvb_reported_length_remaining(tvb, xra_length));
  proto_item_set_len(it, xra_length);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(packet_type, packettype, "Unknown XRA packet type: %u"));

  /*Dissecting TLVs*/
  guint segment_header_present = 0;
  xra_tlv_tvb = tvb_new_subset_length(tvb, 4, tlv_length);
  dissect_xra_tlv(xra_tlv_tvb, pinfo, xra_tree, data, tlv_length, &segment_header_present);

  if(tvb_reported_length_remaining(tvb, xra_length) == 0) {
    return xra_length;
  }
  /*Dissecting contents*/
  switch(packet_type) {
    case XRA_PACKETTYPE_DS_SCQAM_DOCSIS_MACFRAME:
    case XRA_PACKETTYPE_OFDM_DOCSIS:
    case XRA_PACKETTYPE_OFDM_PLC_MMM:
      /*Calling docsis dissector*/
      docsis_tvb = tvb_new_subset_remaining(tvb, xra_length);
      if (docsis_handle) {
        call_dissector (docsis_handle, docsis_tvb, pinfo, tree);
      }
      break;
    case XRA_PACKETTYPE_OFDM_PLC:
      plc_tvb = tvb_new_subset_remaining(tvb, xra_length);
      return dissect_plc(plc_tvb , pinfo, tree, data);
    case XRA_PACKETTYPE_OFDM_NCP:
      ncp_tvb = tvb_new_subset_remaining(tvb, xra_length);
      return dissect_ncp(ncp_tvb, tree, data);
    case XRA_PACKETTYPE_TDMA_BURST:
    case XRA_PACKETTYPE_OFDMA_DATA_BURST:
      if(segment_header_present) {
        col_append_str(pinfo->cinfo, COL_INFO, ": Segment");
        segment_tvb = tvb_new_subset_remaining(tvb, xra_length);
        return dissect_ofdma_segment(segment_tvb, pinfo, tree, data);
      }
      break;
    case XRA_PACKETTYPE_OFDMA_REQ:
    case XRA_PACKETTYPE_US_DOCSIS_MACFRAME:
      /*Calling docsis dissector*/
      docsis_tvb = tvb_new_subset_remaining(tvb, xra_length);
      if (docsis_handle) {
        call_dissector (docsis_handle, docsis_tvb, pinfo, tree);
      }
      break;
    case XRA_PACKETTTYPE_OFDMA_FINE_RANGING:
      /*Calling docsis dissector*/
      docsis_tvb = tvb_new_subset_remaining(tvb, xra_length);
      if (docsis_handle) {
        call_dissector (docsis_handle, docsis_tvb, pinfo, tree);
      }
      break;
    case XRA_PACKETTTYPE_OFDMA_INITIAL_RANGING:
      init_ranging_tvb = tvb_new_subset_remaining(tvb, xra_length);
      return dissect_init_ranging(init_ranging_tvb, tree, data);
    default:
      proto_tree_add_item (xra_tree, hf_xra_unknown, tvb, 1, 1, ENC_NA);
      break;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_xra_tlv_cw_info(tvbuff_t * tvb, proto_tree * tree, void* data _U_, guint16 tlv_length) {
  proto_item *it;
  proto_tree *xra_tlv_cw_info_tree;

  it = proto_tree_add_item (tree, hf_xra_tlv_cw_info, tvb, 0, tlv_length, ENC_NA);
  xra_tlv_cw_info_tree = proto_item_add_subtree (it, ett_xra_tlv_cw_info);

  guint32 tlv_index =0;
  while (tlv_index < tlv_length) {
    guint8 type = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    guint8 length = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    switch (type) {
      case XRA_TLV_CW_INFO_NR_OF_INFO_BYTES:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_nr_of_info_bytes, tvb, tlv_index, length, ENC_NA);
        break;
      case XRA_TLV_CW_INFO_BCH_DECODING_SUCCESFUL:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_bch_decoding_successful, tvb, tlv_index, length, ENC_NA);
        break;
      case XRA_TLV_CW_INFO_PROFILE_PARITY:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_profile_parity, tvb, tlv_index, length, ENC_NA);
        break;
      case XRA_TLV_CW_INFO_BCH_NUMBER_OF_CORRECTED_BITS:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_bch_number_of_corrected_bits, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_CW_INFO_LDPC_NUMBER_OF_CODE_BITS:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_ldpc_nr_of_code_bits, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_CW_INFO_LDPC_DECODING_SUCCESSFUL:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_ldpc_decoding_successful, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_CW_INFO_LDPC_NUMBER_OF_CORRECTED_BITS:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_ldpc_number_of_corrected_bits, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_CW_INFO_LDPC_NUMBER_OF_ITERATIONS:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_ldpc_number_of_iterations, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_CW_INFO_RS_DECODING_SUCCESFUL:
        proto_tree_add_item(xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_rs_decoding_successful, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_CW_INFO_RS_NUMBER_OF_CORRECTED_SYMBOLS:
        proto_tree_add_item(xra_tlv_cw_info_tree, hf_xra_tlv_cw_info_rs_number_of_corrected_symbols, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      default:
        proto_tree_add_item (xra_tlv_cw_info_tree, hf_xra_unknown, tvb, tlv_index, length, ENC_NA);
        break;
    }
    tlv_index+=length;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_xra_tlv_ms_info(tvbuff_t * tvb, proto_tree * tree, void* data _U_, guint16 tlv_length) {
  proto_item *it;
  proto_tree *xra_tlv_ms_info_tree;

  it = proto_tree_add_item (tree, hf_xra_tlv_ms_info, tvb, 0, tlv_length, ENC_NA);
  xra_tlv_ms_info_tree = proto_item_add_subtree (it, ett_xra_tlv_ms_info);

  guint32 tlv_index =0;
  while (tlv_index < tlv_length) {
    guint8 type = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    guint8 length = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    switch (type) {
      case XRA_TLV_MINISLOT_INFO_START_MINISLOT_ID:
        proto_tree_add_item (xra_tlv_ms_info_tree, hf_xra_tlv_start_minislot_id_abs, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_MINISLOT_INFO_REL_START_MINISLOT:
        proto_tree_add_item (xra_tlv_ms_info_tree, hf_xra_tlv_start_minislot_id_rel, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_TLV_MINISLOT_INFO_REL_STOP_MINISLOT:
        proto_tree_add_item (xra_tlv_ms_info_tree, hf_xra_tlv_stop_minislot_id_rel, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      default:
        proto_tree_add_item (xra_tlv_ms_info_tree, hf_xra_unknown, tvb, tlv_index, length, ENC_NA);
        break;
    }
    tlv_index+=length;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_xra_tlv_burst_info(tvbuff_t * tvb, proto_tree * tree, void* data _U_, guint16 tlv_length) {
  proto_item *it;
  proto_tree *xra_tlv_burst_info_tree;

  it = proto_tree_add_item (tree, hf_xra_tlv_burst_info, tvb, 0, tlv_length, ENC_NA);
  xra_tlv_burst_info_tree = proto_item_add_subtree (it, ett_xra_tlv_burst_info);

  guint32 tlv_index =0;
  while (tlv_index < tlv_length) {
    guint8 type = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    guint8 length = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    switch (type) {
      case XRA_BURST_INFO_BURST_ID_REFERENCE:
        proto_tree_add_item (xra_tlv_burst_info_tree, hf_xra_tlv_burst_info_burst_id_reference, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_US_CHANNEL_ID:
        proto_tree_add_item (xra_tlv_burst_info_tree, hf_xra_tlv_us_channel_id, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_SID:
        proto_tree_add_item (xra_tlv_burst_info_tree, hf_xra_tlv_sid, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_IUC:
        proto_tree_add_item (xra_tlv_burst_info_tree, hf_xra_tlv_iuc, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;

      default:
        proto_tree_add_item (xra_tlv_burst_info_tree, hf_xra_unknown, tvb, tlv_index, length, ENC_NA);
        break;
    }
    tlv_index+=length;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_xra_tlv(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_, guint16 tlv_length, guint* segment_header_present) {
  proto_item *it;
  proto_tree *xra_tlv_tree;
  guint symbol_id;
  double mer, power_level;

  it = proto_tree_add_item (tree, hf_xra_tlv, tvb, 0, tlv_length, ENC_NA);
  xra_tlv_tree = proto_item_add_subtree (it, ett_xra_tlv);

  guint32 tlv_index =0;
  tvbuff_t *xra_tlv_cw_info_tvb, *xra_tlv_ms_info_tvb, *xra_tlv_burst_info_tvb;

  while (tlv_index < tlv_length) {
    guint8 type = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    guint8 length = tvb_get_guint8 (tvb, tlv_index);
    ++tlv_index;
    switch (type) {
      case XRA_DS_CHANNEL_ID:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_ds_channel_id, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_DS_FREQUENCY:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_ds_channel_frequency, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_MODULATION:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_modulation, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_ANNEX:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_annex, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_PROFILE_ID:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_profile_id, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_CODEWORD_INFO:
        xra_tlv_cw_info_tvb = tvb_new_subset_length(tvb, tlv_index, length);
        dissect_xra_tlv_cw_info(xra_tlv_cw_info_tvb, xra_tlv_tree, data, length);
        break;
      case XRA_NCP_TRUNC:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_ncp_trunc, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_NCP_SYMBOLID:
        proto_tree_add_item_ret_uint (xra_tlv_tree, hf_xra_tlv_ncp_symbolid, tvb, tlv_index, length, FALSE, &symbol_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": (SymbolId: %u):", symbol_id);
        break;
      case XRA_MER:
        mer = tvb_get_guint8(tvb, tlv_index)/4.0;
        proto_tree_add_double_format_value(xra_tlv_tree, hf_xra_tlv_mer, tvb, tlv_index, length, mer, "%.2f dB", mer);
        break;
      case XRA_US_CHANNEL_ID:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_us_channel_id, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_SID:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_sid, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_IUC:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_iuc, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_BURST_ID:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_burstid, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_BURST_INFO:
        xra_tlv_burst_info_tvb = tvb_new_subset_length(tvb, tlv_index, length);
        dissect_xra_tlv_burst_info(xra_tlv_burst_info_tvb, xra_tlv_tree, data, length);
        break;
      case XRA_MINISLOT_INFO:
        xra_tlv_ms_info_tvb = tvb_new_subset_length(tvb, tlv_index, length);
        dissect_xra_tlv_ms_info(xra_tlv_ms_info_tvb, xra_tlv_tree, data, length);
        break;
      case XRA_UCD_CCC_PARITY:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_ucd_ccc_parity, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_GRANT_SIZE:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_grant_size, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_SEGMENT_HEADER_PRESENT:
        proto_tree_add_item_ret_uint (xra_tlv_tree, hf_xra_tlv_segment_header_present, tvb, tlv_index, length, FALSE, segment_header_present);
        break;
      case XRA_NUMBER_OFDMA_FRAMES:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_ranging_number_ofdma_frames, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_ESTIMATED_TIMING_ADJUST:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_ranging_timing_adjust, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_ESTIMATED_POWER_LEVEL:
        power_level = ((gint16) (256*tvb_get_guint8(tvb, tlv_index) + tvb_get_guint8(tvb, tlv_index+1)) )/10.0;
        proto_tree_add_double_format_value(xra_tlv_tree, hf_xra_tlv_power_level, tvb, tlv_index, length, power_level, "%.1f dBmV", power_level);
        break;
      case XRA_SUBSLOT_ID:
        proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_subslot_id, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      case XRA_CONTROL_WORD:
         proto_tree_add_item (xra_tlv_tree, hf_xra_tlv_control_word, tvb, tlv_index, length, ENC_BIG_ENDIAN);
        break;
      default:
        proto_tree_add_item (xra_tlv_tree, hf_xra_unknown, tvb, tlv_index, length, ENC_NA);
        break;
    }
    tlv_index+=length;
  }

  return tvb_captured_length(tvb);
}

static void
dissect_timestamp_mb(tvbuff_t * tvb, proto_tree* tree) {
  nstime_t ts;
  guint64 plc_timestamp, plc_timestamp_ns;
  proto_item* timestamp_it;
  proto_tree* timestamp_tree;

  static int * const timestamp_parts[] = {
    &hf_plc_mb_ts_timestamp_epoch,
    &hf_plc_mb_ts_timestamp_d30timestamp,
    &hf_plc_mb_ts_timestamp_extra_204_8,
    &hf_plc_mb_ts_timestamp_extra_204_8_X_16,
    NULL
  };

  proto_tree_add_item (tree, hf_plc_mb_ts_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);

  timestamp_it = proto_tree_add_item_ret_uint64 (tree, hf_plc_mb_ts_timestamp, tvb, 1, 8, ENC_BIG_ENDIAN, &plc_timestamp);
  timestamp_tree = proto_item_add_subtree (timestamp_it, ett_plc_timestamp);

  /*See figure 104  CM-SP-MULPIv3.1-115-180509*/
  proto_tree_add_bitmask_list(timestamp_tree, tvb, 1, 8, timestamp_parts, ENC_BIG_ENDIAN);

  /*Timestamp calculation in ns. Beware of overflow of guint64. Splitting off timestamp in composing contributions
   * Epoch (bits 63-41): 10.24 MHz/2^32 clock: *100000*2^22 ns
   * D3.0 timestamp (bits 40-9): 204.8MHz/20 clock: 10.24MHz clock
   * Bits 8-4: 204.8MHz clock
   * Lowest 4 bits (bits 3-0): 16*204.8MHz clock
   */
  plc_timestamp_ns = ((plc_timestamp>>41)&0x7FFFFF)*100000*4194304 +  ((plc_timestamp >>9)&0xFFFFFFFF)*100000/1024 + ((plc_timestamp>>4)&0x1F)*10000/2048 + (plc_timestamp&0x0F)*10000/2048/16;

  ts.secs= (time_t)(plc_timestamp_ns/1000000000);
  ts.nsecs=plc_timestamp_ns%1000000000;
  proto_tree_add_time(timestamp_tree, hf_plc_mb_ts_timestamp_formatted, tvb, 1, 8,  &ts);

  proto_tree_add_item (tree, hf_plc_mb_ts_crc24d, tvb, 9, 3, ENC_NA);
}

static void
dissect_message_channel_mb(tvbuff_t * tvb, packet_info * pinfo, proto_tree* tree, guint16 remaining_length) {
  proto_tree_add_item (tree, hf_plc_mb_mc_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);

  guint packet_start_pointer_field_present, packet_start_pointer;

  proto_tree_add_item_ret_uint (tree, hf_plc_mb_mc_pspf_present, tvb, 0, 1, FALSE, &packet_start_pointer_field_present);

  /*If not present, this contains stuff from other packet. We can't do much in this case*/
  if(packet_start_pointer_field_present) {
    proto_tree_add_item_ret_uint (tree, hf_plc_mb_mc_psp, tvb, 1, 2, FALSE, &packet_start_pointer);

    guint16 docsis_start = 3 + packet_start_pointer;
    while (docsis_start + 6 < remaining_length) {
      /*DOCSIS header in packet*/
      guint8 fc = tvb_get_guint8(tvb,docsis_start + 0);
      if (fc == 0xFF) {
        //skip fill bytes
        docsis_start += 1;
        continue;
      }
      guint16 docsis_length = 256*tvb_get_guint8(tvb,docsis_start + 2) + tvb_get_guint8(tvb,docsis_start + 3);
      if (docsis_start + 6 + docsis_length <= remaining_length) {
        /*DOCSIS packet included in packet*/
        tvbuff_t *docsis_tvb;

        docsis_tvb = tvb_new_subset_length(tvb, docsis_start, docsis_length + 6);
        if (docsis_handle) {
          call_dissector (docsis_handle, docsis_tvb, pinfo, tree);
          col_append_str(pinfo->cinfo, COL_INFO, "; ");
          col_set_fence(pinfo->cinfo,COL_INFO);
        }
      }
      docsis_start += 6 + docsis_length;
    }
  }
}

static int
dissect_message_block(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint8 mb_type, guint16 mb_length) {
  proto_tree * mb_tree;
  proto_item *mb_item;

  mb_item = proto_tree_add_item (tree, hf_plc_mb, tvb, 0, 1, ENC_BIG_ENDIAN);

  mb_tree = proto_item_add_subtree (mb_item, ett_plc_mb);

  switch (mb_type) {
    case PLC_TIMESTAMP_MB:
      dissect_timestamp_mb(tvb, mb_tree);
      break;
    case PLC_ENERGY_MANAGEMENT_MB:
      proto_tree_add_item (mb_tree, hf_plc_em_mb, tvb, 0, mb_length, ENC_NA);
      break;
    case PLC_MESSAGE_CHANNEL_MB:
      dissect_message_channel_mb(tvb, pinfo, mb_tree, mb_length);
      break;
    case PLC_TRIGGER_MB:
      proto_tree_add_item (mb_tree, hf_plc_trigger_mb, tvb, 0, mb_length, ENC_NA);
      break;
    /*Future Use Message Block*/
    default:
      break;
  }
  return tvb_captured_length(tvb);
}

static int
dissect_ncp_message_block(tvbuff_t * tvb, proto_tree * tree) {
  proto_tree * mb_tree;
  proto_item *mb_item;

  mb_item = proto_tree_add_item (tree, hf_ncp_mb, tvb, 0, 3, ENC_NA);
  mb_tree = proto_item_add_subtree (mb_item, ett_ncp_mb);

  proto_tree_add_item (mb_tree, hf_ncp_mb_profileid, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_z, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_c, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_n, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_l, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_t, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_u, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_r, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mb_tree, hf_ncp_mb_subcarrier_start_pointer, tvb, 1, 2, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static int
dissect_plc(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_) {

  guint16 offset = 0;
  proto_tree *plc_tree;
  proto_item *plc_item;
  tvbuff_t *mb_tvb;

  plc_item = proto_tree_add_protocol_format (tree, proto_plc, tvb, 0, -1,"DOCSIS PLC");
  plc_tree = proto_item_add_subtree (plc_item, ett_plc);


  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    guint8 mb_type = tvb_get_guint8 (tvb, offset) >>4;
    guint8 mb_nibble2 = tvb_get_guint8 (tvb, offset) & 0x0F;
    guint8 mb_byte2 = tvb_get_guint8 (tvb, offset+1);
    guint8 last_mb = 0;

    /*Do not initialize with 0, otherwise an infinite loop results in case mbLength is not initialized.*/
    guint16 mb_length = 1000;

    if(mb_type == 0xFF) {
      break;
    }
    switch (mb_type) {
      case PLC_TIMESTAMP_MB:
        mb_length =12;
        col_append_str(pinfo->cinfo, COL_INFO, ": TS-MB, ");
        break;
      case PLC_ENERGY_MANAGEMENT_MB:
        mb_length = 4 + mb_nibble2*6;
        col_append_str(pinfo->cinfo, COL_INFO, "EM-MB, ");
        break;
      case PLC_MESSAGE_CHANNEL_MB:
        last_mb = 1;
        mb_length = tvb_reported_length_remaining(tvb, offset);
        col_append_str(pinfo->cinfo, COL_INFO, "MC-MB");
        break;
      case PLC_TRIGGER_MB:
        mb_length = 9;
        col_append_str(pinfo->cinfo, COL_INFO, "TRG-MB, ");
        break;
      /*Future Use Message Block*/
      default:
        mb_length = 5 + 256*(mb_nibble2 &0x01) + mb_byte2;
        col_append_str(pinfo->cinfo, COL_INFO, "FUT-MB, ");
        break;
    }
    mb_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_message_block(mb_tvb,pinfo, plc_tree, mb_type, mb_length);

    if (last_mb) {
      break;
    }

    offset+= mb_length;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_ncp(tvbuff_t * tvb, proto_tree * tree, void* data _U_) {
  guint16 offset = 0;
  proto_tree *ncp_tree;
  proto_item *ncp_item;
  tvbuff_t *ncp_mb_tvb;

  ncp_item = proto_tree_add_protocol_format (tree, proto_ncp, tvb, 0, -1,"DOCSIS NCP");
  ncp_tree = proto_item_add_subtree (ncp_item, ett_ncp);


  while (tvb_captured_length_remaining(tvb, offset) > 3) {
    ncp_mb_tvb = tvb_new_subset_length(tvb, offset, 3);
    dissect_ncp_message_block(ncp_mb_tvb, ncp_tree);

    offset+= 3;
  }
  proto_tree_add_item (ncp_tree, hf_ncp_crc, tvb, offset, 3, ENC_NA);

  return tvb_captured_length(tvb);
}

static int
dissect_init_ranging(tvbuff_t * tvb, proto_tree * tree, void* data _U_) {

  proto_tree *init_ranging_tree;
  proto_item *init_ranging_item;

  init_ranging_item = proto_tree_add_protocol_format (tree, proto_init_ranging, tvb, 0, -1,"OFDMA Initial Ranging Request");
  init_ranging_tree = proto_item_add_subtree (init_ranging_item, ett_init_ranging);

  proto_tree_add_item (init_ranging_tree, hf_xra_init_ranging_mac, tvb, 0, 6, ENC_NA);
  proto_tree_add_item (init_ranging_tree, hf_xra_init_ranging_ds_channel_id, tvb, 6, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (init_ranging_tree, hf_xra_init_ranging_crc, tvb, 7, 3, ENC_NA);

  return tvb_captured_length(tvb);
}

static int
dissect_ofdma_segment(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, void* data _U_) {
  proto_tree *segment_tree;
  proto_item *segment_item;


  segment_item = proto_tree_add_protocol_format (tree, proto_segment, tvb, 0, -1,"DOCSIS Segment");
  segment_tree = proto_item_add_subtree (segment_item, ett_plc);

  proto_tree_add_item (segment_tree, hf_docsis_segment_pfi, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (segment_tree, hf_docsis_segment_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (segment_tree, hf_docsis_segment_pointerfield, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (segment_tree, hf_docsis_segment_sequencenumber, tvb, 2, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (segment_tree, hf_docsis_segment_sidclusterid, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (segment_tree, hf_docsis_segment_request, tvb, 4, 2, ENC_BIG_ENDIAN);

  /* dissect the header check sequence */
  /* CRC-CCITT(16+12+5+1) */
  guint16 fcs = g_ntohs(crc16_ccitt_tvb(tvb, 6));
  proto_tree_add_checksum(segment_tree, tvb, 6, hf_docsis_segment_hcs, hf_docsis_segment_hcs_status, &ei_docsis_segment_hcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

  proto_tree_add_item (segment_tree, hf_docsis_segment_data, tvb, 8, tvb_reported_length_remaining(tvb, 8), ENC_NA);

  return tvb_captured_length(tvb);
}

void
proto_register_xra (void)
{
  static hf_register_info hf[] = {
    {&hf_xra_version,
      {"Version", "xra.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Xra Version", HFILL}
    },
    {&hf_xra_direction,
      {"Direction", "xra.direction",
        FT_UINT8, BASE_DEC, VALS(direction_vals), 0xC0,
        NULL, HFILL}
    },
    {&hf_xra_packettype,
      {"Packet Type", "xra.packettype",
        FT_UINT8, BASE_DEC, VALS(packettype), 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlvlength,
      {"TLV length", "xra.tlvlength",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv,
      {"XRA TLV", "xra.tlv",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    /*XRA TLV*/
    {&hf_xra_tlv_ds_channel_id,
      {"DS Channel ID", "xra.tlv.ds_channel_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_ds_channel_frequency,
      {"DS Channel Frequency", "xra.tlv.ds_channel_frequency",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_modulation,
      {"Modulation", "xra.tlv.modulation",
        FT_UINT8, BASE_DEC, VALS(modulation_vals), 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_annex,
      {"Annex", "xra.tlv.annex",
        FT_UINT8, BASE_DEC, VALS(annex_vals), 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_us_channel_id,
      {"US Channel ID", "xra.tlv.us_channel_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_profile_id,
      {"Profile", "xra.tlv.profile_id",
        FT_UINT8, BASE_DEC, VALS(profile_id), 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_sid,
      {"SID", "xra.tlv.sid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_iuc,
      {"IUC", "xra.tlv.iuc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_burstid,
      {"Burst ID", "xra.tlv.burstid",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_ms_info,
      {"Minislot Info", "xra.tlv.ms_info",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_ucd_ccc_parity,
      {"UCD CCC Parity", "xra.tlv.ucd_ccc_parity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_grant_size,
      {"Grant Size (bits)", "xra.tlv.grant_size",
        FT_UINT32, BASE_DEC, NULL, 0x00FFFFFF,
        NULL, HFILL}
    },
    {&hf_xra_tlv_segment_header_present,
      {"Segment Header Present", "xra.tlv.segment_header_present",
        FT_UINT8, BASE_DEC, NULL,0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_ncp_trunc,
      {"Truncated due to uncorrectables", "xra.tlv.ncp.trunc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_ncp_symbolid,
      {"SymbolId", "xra.tlv.ncp.symbolid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_start_minislot_id_abs,
      {"Start Minislot ID (absolute)", "xra.tlv.ms_info.start_minislot_id_abs",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_start_minislot_id_rel,
      {"Start Minislot ID (relative)", "xra.tlv.ms_info.start_minislot_id_rel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_stop_minislot_id_rel,
      {"Stop Minislot ID (relative)", "xra.tlv.ms_info.stop_minislot_id_rel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    /*Ranging*/
    {&hf_xra_tlv_ranging_number_ofdma_frames,
      {"Number of OFDMA frames", "xra.tlv.ranging.number_ofdma_frames",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_ranging_timing_adjust,
      {"Timing Adjust (in 1/204.8 MHz units)", "xra.tlv.ranging.timing_adjust",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_power_level,
      {"Estimated Power Level", "xra.tlv.power_level",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_mer,
      {"MER", "xra.tlv.mer",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_subslot_id,
      {"Subslot ID", "xra.tlv.subslot_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_control_word,
      {"Control Word", "xra.tlv.control_word",
        FT_UINT8, BASE_DEC, VALS(control_word_vals), 0x0,
        NULL, HFILL}
    },

    /*Codeword Info DS*/
    {&hf_xra_tlv_cw_info,
      {"Codeword Info", "xra.tlv.cw_info",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_nr_of_info_bytes,
      {"Number of info bytes", "xra.tlv.cw_info.nr_of_info_bytes",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_bch_decoding_successful,
      {"BCH decoding successful", "xra.tlv.cw_info.bch_decoding_successful",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_profile_parity,
      {"Codeword parity", "xra.tlv.cw_info.profile_parity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_bch_number_of_corrected_bits,
      {"BCH Number of corrected bits", "xra.tlv.cw_info.bch_number_of_corrected_bits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_ldpc_nr_of_code_bits,
      {"Number of code bits", "xra.tlv.cw_info.ldpc_nr_of_code_bits",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_ldpc_decoding_successful,
      {"LDPC decoding successful", "xra.tlv.cw_info.ldpc_decoding_successful",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_ldpc_number_of_iterations,
      {"LDPC Number of iterations", "xra.tlv.cw_info.ldpc_number_of_iterations",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_ldpc_number_of_corrected_bits,
      {"LDPC Number of corrected info bits", "xra.tlv.cw_info.ldpc_number_of_corrected_bits",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_rs_decoding_successful,
      {"Reed-Solomon Decoding Successful", "xra.tlv.cw_info.rs_decoding_successful",
        FT_BOOLEAN, 8, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_cw_info_rs_number_of_corrected_symbols,
      {"Reed-Solomon Number of Corrected Symbols", "xra.tlv.cw_info.rs_number_of_corrected_symbols",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_unknown,
      {"Unknown", "xra.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    /*Burst Info */
    {&hf_xra_tlv_burst_info,
      {"Burst Info", "xra.tlv.burst_info",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_xra_tlv_burst_info_burst_id_reference,
      {"Burst ID reference", "xra.tlv.burst_info.burst_id_reference",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    /*PLC specific*/
    {&hf_plc_mb,
      {"PLC Message Block", "docsis_plc.mb_type",
        FT_UINT8, BASE_DEC,VALS(message_block_type) , 0xF0,
        NULL, HFILL}
    },
    /*NCP specfific*/
    {&hf_ncp_mb,
      {"NCP Message Block", "docsis_ncp.mb",
        FT_BYTES, BASE_NONE,NULL , 0x0,
        NULL, HFILL}
    },
    {&hf_ncp_mb_profileid,
      {"NCP MB Profile ID", "docsis_ncp.mb.profileid",
        FT_UINT8, BASE_DEC,NULL , 0xF0,
        NULL, HFILL}
    },
    {&hf_ncp_mb_z,
      {"NCP MB Zero Bit Loading", "docsis_ncp.mb.z",
        FT_BOOLEAN, 8, TFS(&zero_bit_loading) , 0x08,
        NULL, HFILL}
    },
    {&hf_ncp_mb_c,
      {"NCP MB Data Profile Update", "docsis_ncp.mb.z",
        FT_BOOLEAN, 8, TFS(&data_profile_update) , 0x04,
        NULL, HFILL}
    },
    {&hf_ncp_mb_n,
      {"NCP MB NCP Profile Selected", "docsis_ncp.mb.n",
        FT_BOOLEAN, 8, TFS(&ncp_profile_select) , 0x02,
        NULL, HFILL}
    },
    {&hf_ncp_mb_l,
      {"NCP MB Last NCP Block", "docsis_ncp.mb.l",
        FT_BOOLEAN, 8, TFS(&last_ncp_block) , 0x01,
        NULL, HFILL}
    },
    {&hf_ncp_mb_t,
      {"NCP MB Codeword Tagging", "docsis_ncp.mb.t",
        FT_BOOLEAN, 8, TFS(&codeword_tagging) , 0x80,
        NULL, HFILL}
    },
    {&hf_ncp_mb_u,
      {"NCP MB NCP Profile Update Indicator", "docsis_ncp.mb.u",
        FT_BOOLEAN, 8, NULL , 0x40,
        NULL, HFILL}
    },
    {&hf_ncp_mb_r,
      {"NCP MB Reserved", "docsis_ncp.mb.r",
        FT_BOOLEAN, 8, NULL , 0x20,
        NULL, HFILL}
    },
    {&hf_ncp_mb_subcarrier_start_pointer,
      {"NCP MB Subcarrier Start Pointer", "docsis_ncp.mb.subcarrier_start_pointer",
        FT_UINT16, BASE_DEC, NULL , 0x1FFF,
        NULL, HFILL}
    },
    {&hf_ncp_crc,
      {"NCP CRC", "docsis_ncp.crc",
        FT_BYTES, BASE_NONE, NULL , 0x0,
        NULL, HFILL}
    },
    /*Init Ranging Specific*/
    {&hf_xra_init_ranging_mac,
      {"MAC Address", "xra.init_ranging.mac",
        FT_ETHER, BASE_NONE, NULL , 0x0,
        NULL, HFILL}
    },
    {&hf_xra_init_ranging_ds_channel_id,
      {"DS Channel ID", "xra.init_ranging.ds_channel_id",
        FT_UINT8, BASE_DEC, NULL , 0x0,
        NULL, HFILL}
    },
    {&hf_xra_init_ranging_crc,
      {"CRC", "xra.init_ranging.crc",
        FT_BYTES, BASE_NONE, NULL , 0x0,
        NULL, HFILL}
    },
    /*PLC MB*/
    {&hf_plc_em_mb,
      {"PLC EM MB", "docsis_plc.em_mb",
        FT_BYTES, BASE_NONE, NULL , 0x0,
        NULL, HFILL}
    },
    {&hf_plc_trigger_mb,
      {"PLC Trigger MB", "docsis_plc.trigger_mb",
        FT_BYTES, BASE_NONE, NULL , 0x0,
        NULL, HFILL}
    },
    /*Timestamp MB*/
    {&hf_plc_mb_ts_reserved,
      {"Reserved", "docsis_plc.mb_ts_reserved",
        FT_UINT8, BASE_DEC,0 , 0x0F,
        NULL, HFILL}
    },
    {&hf_plc_mb_ts_timestamp,
      {"Timestamp", "docsis_plc.mb_ts_timestamp",
        FT_UINT64, BASE_DEC,0 , 0x0,
        NULL, HFILL}
    },
    {&hf_plc_mb_ts_timestamp_epoch,
      {"Timestamp Epoch", "docsis_plc.mb_ts_timestamp_epoch",
        FT_UINT64, BASE_HEX,0 , 0xFFFFFE0000000000,
        NULL, HFILL}
    },
    {&hf_plc_mb_ts_timestamp_d30timestamp,
      {"D3.0 Timestamp", "docsis_plc.mb_ts_timestamp_d30timestamp",
        FT_UINT64, BASE_HEX,0 , 0x000001FFFFFFFE00,
        NULL, HFILL}
    },
    {&hf_plc_mb_ts_timestamp_extra_204_8,
      {"Timestamp: extra 204.8MHz samples", "docsis_plc.mb_ts_timestamp_extra_204_8",
        FT_UINT64, BASE_DEC,0 , 0x00000000000001F0,
        NULL, HFILL}
    },
    {&hf_plc_mb_ts_timestamp_extra_204_8_X_16,
      {"Timestamp: extra 16 x 204.8MHz samples", "docsis_plc.mb_ts_timestamp_extra_204_8_X_16",
        FT_UINT64, BASE_DEC, 0 , 0x000000000000000F,
        NULL, HFILL}
    },
    {&hf_plc_mb_ts_timestamp_formatted,
      {"Formatted PLC timestamp", "docsis_plc.mb_ts_timestamp_formatted",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }
    },
    {&hf_plc_mb_ts_crc24d,
      {"CRC-24-D", "docsis_plc.mb_ts_crc24d",
        FT_BYTES, BASE_NONE, 0 , 0x0,
        NULL, HFILL}
    },
    /*Message Channel MB*/
    {&hf_plc_mb_mc_reserved,
      {"Reserved", "docsis_plc.mb_mc_reserved",
        FT_UINT8, BASE_DEC,0 , 0x0E,
        NULL, HFILL}
    },
    {&hf_plc_mb_mc_pspf_present,
      {"Packet Start Pointer Field", "docsis_plc.mb_mc_pspf_present",
        FT_UINT8, BASE_DEC, VALS(packet_start_pointer_field) , 0x01,
        NULL, HFILL}
    },
    {&hf_plc_mb_mc_psp,
      {"Packet Start Pointer", "docsis_plc.mb_mc_psp",
        FT_UINT16, BASE_DEC, 0 , 0x0,
        NULL, HFILL}
    },
    //DOCSIS SEGMENT
    {&hf_docsis_segment_pfi,
      {"Pointer Field Indicator", "docsis_segment.pfi",
        FT_UINT8, BASE_DEC, NULL, 0x80,
        NULL, HFILL}
    },
    {&hf_docsis_segment_reserved,
      {"Reserved", "docsis_segment.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x40,
        NULL, HFILL}
    },
    {&hf_docsis_segment_pointerfield,
      {"Pointer Field", "docsis_segment.pointerfield",
        FT_UINT16, BASE_DEC, NULL, 0x3FFF,
        NULL, HFILL}
    },
    {&hf_docsis_segment_sequencenumber,
      {"Sequence Number", "docsis_segment.sequencenumber",
        FT_UINT16, BASE_DEC, NULL, 0xFFF8,
        NULL, HFILL}
    },
    {&hf_docsis_segment_sidclusterid,
      {"SID Cluster ID", "docsis_segment.sidclusterid",
        FT_UINT8, BASE_DEC, NULL, 0x07,
        NULL, HFILL}
    },
    {&hf_docsis_segment_request,
      {"Request (N bytes)", "docsis_segment.request",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_docsis_segment_hcs,
      {"HCS", "docsis_segment.hcs",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_docsis_segment_hcs_status,
     { "Segment HCS Status", "docsis_segment.hcs.status",
       FT_UINT8, BASE_NONE, VALS(local_proto_checksum_vals), 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_segment_data,
      {"Data", "docsis_segment.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
  };

  static ei_register_info ei[] = {
      { &ei_docsis_segment_hcs_bad, { "docsis_segment.hcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_xra,
    &ett_xra_tlv,
    &ett_xra_tlv_cw_info,
    &ett_xra_tlv_ms_info,
    &ett_xra_tlv_burst_info,
    &ett_plc,
    &ett_plc_mb,
    &ett_plc_timestamp,
    &ett_ncp,
    &ett_ncp_mb,
    &ett_init_ranging
  };

  expert_module_t* expert_xra;

  /* Register the protocol name and description */
  proto_xra = proto_register_protocol ("Excentis XRA header", "XRA", "xra");
  proto_segment = proto_register_protocol("DOCSIS Segment", "DOCSIS Segment", "docsis_segment");
  proto_plc = proto_register_protocol("DOCSIS PHY Link Channel", "DOCSIS PLC", "docsis_plc");
  proto_ncp = proto_register_protocol("DOCSIS_NCP", "DOCSIS_NCP", "docsis_ncp");
  proto_init_ranging = proto_register_protocol("DOCSIS_INIT_RANGING", "DOCSIS_INIT_RANGING", "docsis_init_ranging");

  /* register expert notifications */
  expert_xra = expert_register_protocol(proto_xra);
  expert_register_field_array(expert_xra, ei, array_length(ei));

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_xra, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("xra", dissect_xra, proto_xra);

}

void
proto_reg_handoff_xra(void)
{
  docsis_handle = find_dissector ("docsis");

  xra_handle = create_dissector_handle(dissect_xra, proto_xra);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_DOCSIS31_XRA31, xra_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
