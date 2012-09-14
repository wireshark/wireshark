/* packet-gsm_rlcmac.c
 * Routines for GSM RLC MAC control plane message dissection in wireshark.
 * TS 44.060 and 24.008
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
 * Copyright (c) 2011 ST-Ericsson
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

 /* Notes on the use of this dissector:-
  * 
  * These dissectors should be called with pinfo->private_data pointing to a
  * populated RlcMacPrivateData_t structure, this is needed to pass the Physical 
  * Layer Coding scheme and other parameters required for correct Data Block decoding.
  * For backward compatibility, a NULL pointer causes the dissector to assume GPRS CS1.
  *
  * To dissect EGPRS blocks, the gsm_rlcmac_ul or gsm_rlcmac_dl dissector should be
  * called 1, 2 or 3 times, for the header block and then each available data block, 
  * with the flags in pinfo->private_data indicating which block is to be dissected.
  *
  *   - The EGPRS Header Block occupies 4, 5 or 6 octets, the last octet is right-aligned
  *     (as viewed in wireshark) with any null bits at the high bits of the last octet.
  *   - Each EGPRS Data Block has 6 padding bits at the front, so there are then 2 data bits 
  *     followed by the rest of the data block (which is implicitly octet aligned).
  *   - Either or both of the possible EGPRS Data Blocks may have been received
  *     with bad CRC and this should be marked in the flags field to allow
  *     upper layer decoding to ignore bad data blocks
  * 
  * see packet-gsmtap.c for an example of the use of this dissector.
  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-csn1.h"
#include "packet-gsm_rlcmac.h"

/* private typedefs */
typedef struct
{
   guint8 offset;
   guint8 li;
}length_indicator_t;

/* local constant tables */
const guint8 gsm_rlcmac_gprs_cs_to_block_length[] = {
   23, /* CS1 */
   33, /* CS2 */
   39, /* CS3 */
   53  /* CS4 */
};

const guint8 gsm_rlcmac_egprs_header_type_to_dl_header_block_length[] = {
   5, /* RLCMAC_HDR_TYPE_1 */
   4, /* RLCMAC_HDR_TYPE_2 */
   4  /* RLCMAC_HDR_TYPE_3 */
};

const guint8 gsm_rlcmac_egprs_header_type_to_ul_header_block_length[] = {
   6, /* RLCMAC_HDR_TYPE_1 */
   5, /* RLCMAC_HDR_TYPE_2 */
   4  /* RLCMAC_HDR_TYPE_3 */
};

const guint8 gsm_rlcmac_egprs_mcs_to_data_block_length[] = {
   0,/* MCS0 */
   23,
   29,
   38,
   45,
   57,
   75,
   57,
   69,
   75 /* MCS9 */
};

/* Initialize the protocol and registered fields
*/
static int proto_gsm_rlcmac = -1;
static int ett_gsm_rlcmac  = -1;
static int ett_gsm_rlcmac_data  = -1;
static int ett_data_segments  = -1;

/* common MAC header IEs */
static int hf_usf = -1;
static int hf_ul_payload_type = -1;
static int hf_dl_payload_type = -1;
static int hf_ul_retry_bit = -1;
static int hf_rrbp = -1;
static int hf_s_p = -1;
static int hf_es_p = -1;
static int hf_fbi = -1;

/* common RLC IEs*/
static int hf_prach8_message_type_3 = -1;
static int hf_prach8_message_type_6 = -1;
static int hf_prach11_message_type_6 = -1;
static int hf_prach11_message_type_9 = -1;
static int hf_tlli = -1;
static int hf_uplink_tfi = -1;
static int hf_downlink_tfi = -1;
static int hf_page_mode = -1;
static int hf_bsn = -1;
static int hf_bsn2 = -1;
static int hf_e = -1;
static int hf_li= -1;
static int hf_pi= -1;
static int hf_ti= -1;
static int hf_rsb= -1;
static int hf_spb= -1;
static int hf_cps1= -1;
static int hf_cps2= -1;
static int hf_cps3= -1;
static int hf_me = -1;


static int hf_countdown_value = -1;
static int hf_ul_data_si = -1;


static int hf_ul_data_spare = -1;
static int hf_tlli_indicator = -1;
static int hf_pfi = -1;

/* RLC/MAC Downlink control block header */
static int hf_dl_ctrl_rbsn = -1;
static int hf_dl_ctrl_rti = -1;
static int hf_dl_ctrl_fs = -1;
static int hf_dl_ctrl_ac = -1;
static int hf_dl_ctrl_pr = -1;
static int hf_dl_ctrl_d = -1;

static int hf_dl_ctrl_rbsn_e = -1;
static int hf_dl_ctrl_fs_e = -1;
static int hf_dl_ctrl_spare = -1;
static int hf_startingtime_n32;
static int hf_startingtime_n51;
static int hf_startingtime_n26;

/* common uplink ies */
static int hf_ul_message_type;
static int hf_ul_mac_header_spare;
static int hf_ul_retry;

/*< Global TFI IE >*/

/*< Starting Frame Number Description IE >*/
static int hf_starting_frame_number_k;

/*< Ack/Nack Description IE >*/
static int hf_ack_nack_description_final_ack_indication;
static int hf_ack_nack_description_starting_sequence_number;

/*< Packet Timing Advance IE >*/
static int hf_timing_advance_value;
static int hf_timing_advance_index;
static int hf_timing_advance_timeslot_number;

/*< Power Control Parameters IE >*/
static int hf_alpha;
static int hf_gamma;
static int hf_t_avg_w;
static int hf_t_avg_t;
static int hf_pc_meas_chan;
static int hf_n_avg_i;

/*< Global Power Control Parameters IE >*/
static int hf_global_power_control_parameters_pb;
static int hf_global_power_control_parameters_int_meas_channel_list_avail;

/*< Global Packet Timing Advance IE >*/

/*< Channel Quality Report struct >*/
static int hf_channel_quality_report_c_value;
static int hf_channel_quality_report_rxqual;
static int hf_channel_quality_report_sign_var;
static int hf_channel_quality_report_slot0_i_level_tn;
static int hf_channel_quality_report_slot1_i_level_tn;
static int hf_channel_quality_report_slot2_i_level_tn;
static int hf_channel_quality_report_slot3_i_level_tn;
static int hf_channel_quality_report_slot4_i_level_tn;
static int hf_channel_quality_report_slot5_i_level_tn;
static int hf_channel_quality_report_slot6_i_level_tn;
static int hf_channel_quality_report_slot7_i_level_tn;

/*< EGPRS Ack/Nack Description >*/
static int hf_egprs_acknack_final_ack_indication;
static int hf_egprs_acknack_beginning_of_window;
static int hf_egprs_acknack_end_of_window;
static int hf_egprs_acknack_starting_sequence_number;
static int hf_egprs_acknack_crbb_length;
static int hf_egprs_acknack_crbb_starting_color_code;

/*<P1 Rest Octets>*/

/*<P2 Rest Octets>*/
static int hf_mobileallocationie_length;
static int hf_single_rf_channel_spare;
static int hf_arfcn;
static int hf_maio;
static int hf_hsn;
static int hf_channel_description_channel_type_and_tdma_offset;
static int hf_channel_description_tn;
static int hf_group_call_reference_value;
static int hf_group_call_reference_sf;
static int hf_group_call_reference_af;
static int hf_group_call_reference_call_priority;
static int hf_group_call_reference_ciphering_information;
static int hf_nln_pch;
static int hf_nln_status;
static int hf_priority;
static int hf_p1_rest_octets_packet_page_indication_1;
static int hf_p1_rest_octets_packet_page_indication_2;
static int hf_p2_rest_octets_cn3;
static int hf_nln;
static int hf_p2_rest_octets_packet_page_indication_3;

/* <IA Rest Octets> */
static int hf_usf_granularity;
static int hf_p0;
static int hf_pr_mode;
static int hf_nr_of_radio_blocks_allocated;
static int hf_bts_pwr_ctrl_mode;
static int hf_polling;
static int hf_egprs_channel_coding_command;
static int hf_tlli_block_channel_coding;
static int hf_bep_period2;
static int hf_resegment;
static int hf_egprs_windowsize;
static int hf_extendedra;
static int hf_ia_egprs_uniontype ;
static int hf_ia_freqparamsbeforetime_length;
static int hf_gprs_channel_coding_command;
static int hf_link_quality_measurement_mode;
static int hf_rlc_mode;
static int hf_ta_valid;
static int hf_tqi;

/* <Packet Polling Request> */
static int hf_dl_message_type;

/*< SI 13 Rest Octets >*/
static int hf_gprs_cell_options_nmo;
static int hf_gprs_cell_options_t3168;
static int hf_gprs_cell_options_t3192;
static int hf_gprs_cell_options_drx_timer_max;
static int hf_gprs_cell_options_access_burst_type;
static int hf_ack_type;
static int hf_gprs_cell_options_bs_cv_max;
static int hf_gprs_cell_options_pan_dec;
static int hf_gprs_cell_options_pan_inc;
static int hf_gprs_cell_options_pan_max;
static int hf_rac;
static int hf_pbcch_not_present_spgc_ccch_sup;
static int hf_pbcch_not_present_priority_access_thr;
static int hf_pbcch_not_present_network_control_order;
static int hf_pbcch_description_pb;
static int hf_pbcch_description_tn;
static int hf_pbcch_present_psi1_repeat_period;
static int hf_bcch_change_mark;
static int hf_si_change_field;
static int hf_si13_change_mark;
static int hf_sgsnr;
static int hf_si_status_ind;

/*< Packet TBF Release message content >*/
static int hf_packetbf_release_uplink_release;
static int hf_packetbf_release_downlink_release;
static int hf_packetbf_release_tbf_release_cause;

/*< Packet Control Acknowledgement message content >*/
static int hf_packet_control_acknowledgement_additionsr6_ctrl_ack_extension;
static int hf_packet_control_acknowledgement_additionsr5_tn_rrbp;
static int hf_packet_control_acknowledgement_additionsr5_g_rnti_extension;
static int hf_packet_control_acknowledgement_ctrl_ack;

/*< Packet Downlink Dummy Control Block message content >*/

/*< Packet Uplink Dummy Control Block message content >*/
static int hf_receive_n_pdu_number_nsapi;
static int hf_receive_n_pdu_number_value;

/*< MS Radio Access capability IE >*/
static int hf_dtm_egprs_dtm_egprs_multislot_class;
static int hf_dtm_egprs_highmultislotclass_dtm_egprs_highmultislotclass;
static int hf_multislot_capability_hscsd_multislot_class;
static int hf_multislot_capability_gprs_multislot_class;
static int hf_multislot_capability_gprs_extended_dynamic_allocation_capability;
static int hf_multislot_capability_sms_value;
static int hf_multislot_capability_sm_value;
static int hf_multislot_capability_ecsd_multislot_class;
static int hf_multislot_capability_egprs_multislot_class;
static int hf_multislot_capability_egprs_extended_dynamic_allocation_capability;
static int hf_multislot_capability_dtm_gprs_multislot_class;
static int hf_multislot_capability_single_slot_dtm;
static int hf_content_rf_power_capability;
static int hf_content_a5_bits;
static int hf_content_es_ind;
static int hf_content_ps;
static int hf_content_vgcs;
static int hf_content_vbs;
static int hf_content_eight_psk_power_capability;
static int hf_content_compact_interference_measurement_capability;
static int hf_content_revision_level_indicator;
static int hf_content_umts_fdd_radio_access_technology_capability;
static int hf_content_umts_384_tdd_radio_access_technology_capability;
static int hf_content_cdma2000_radio_access_technology_capability;
static int hf_content_umts_128_tdd_radio_access_technology_capability;
static int hf_content_geran_feature_package_1;
static int hf_content_extended_dtm_gprs_multislot_class;
static int hf_content_extended_dtm_egprs_multislot_class;
static int hf_content_modulation_based_multislot_class_support;
static int hf_content_highmultislotcapability;
static int hf_content_geran_lu_modecapability;
static int hf_content_gmsk_multislotpowerprofile;
static int hf_content_eightpsk_multislotprofile;
static int hf_content_multipletbf_capability;
static int hf_content_downlinkadvancedreceiverperformance;
static int hf_content_extendedrlc_mac_controlmessagesegmentionscapability;
static int hf_content_dtm_enhancementscapability;
static int hf_content_dtm_gprs_highmultislotclass;
static int hf_content_ps_handovercapability;
static int hf_additional_accessechnologies_struct_t_access_technology_type;
static int hf_additional_accessechnologies_struct_t_gmsk_power_class;
static int hf_additional_accessechnologies_struct_t_eight_psk_power_class;
/*static int hf_ms_radio_access_capability_iei;*/
/*static int hf_ms_radio_access_capability_length;*/

/*< MS Classmark 3 IE >*/
static int hf_arc_a5_bits;
static int hf_multiband_a5_bits;
static int hf_arc_arc2_spare;
static int hf_arc_arc1;
static int hf_edge_rf_pwr_edge_rf_pwrcap1;
static int hf_edge_rf_pwr_edge_rf_pwrcap2;
static int hf_ms_class3_unpacked_spare1;
static int hf_ms_class3_unpacked_r_gsm_arc;
static int hf_ms_class3_unpacked_multislotclass;
static int hf_ms_class3_unpacked_ucs2;
static int hf_ms_class3_unpacked_extendedmeasurementcapability;
static int hf_ms_class3_unpacked_sms_value;
static int hf_ms_class3_unpacked_sm_value;
static int hf_ms_class3_unpacked_ms_positioningmethod;
static int hf_ms_class3_unpacked_edge_multislotclass;
static int hf_ms_class3_unpacked_modulationcapability;
static int hf_ms_class3_unpacked_gsm400_bands;
static int hf_ms_class3_unpacked_gsm400_arc;
static int hf_ms_class3_unpacked_gsm850_arc;
static int hf_ms_class3_unpacked_pcs1900_arc;
static int hf_ms_class3_unpacked_umts_fdd_radio_access_technology_capability;
static int hf_ms_class3_unpacked_umts_384_tdd_radio_access_technology_capability;
static int hf_ms_class3_unpacked_cdma2000_radio_access_technology_capability;
static int hf_ms_class3_unpacked_dtm_gprs_multislot_class;
static int hf_ms_class3_unpacked_single_slot_dtm;
static int hf_ms_class3_unpacked_gsm_band;
static int hf_ms_class3_unpacked_gsm_700_associated_radio_capability;
static int hf_ms_class3_unpacked_umts_128_tdd_radio_access_technology_capability;
static int hf_ms_class3_unpacked_geran_feature_package_1;
static int hf_ms_class3_unpacked_extended_dtm_gprs_multislot_class;
static int hf_ms_class3_unpacked_extended_dtm_egprs_multislot_class;
static int hf_ms_class3_unpacked_highmultislotcapability;
static int hf_ms_class3_unpacked_geran_lu_modecapability;
static int hf_ms_class3_unpacked_geran_featurepackage_2;
static int hf_ms_class3_unpacked_gmsk_multislotpowerprofile;
static int hf_ms_class3_unpacked_eightpsk_multislotprofile;
static int hf_ms_class3_unpacked_tgsm_400_bandssupported;
static int hf_ms_class3_unpacked_tgsm_400_associatedradiocapability;
static int hf_ms_class3_unpacked_tgsm_900_associatedradiocapability;
static int hf_ms_class3_unpacked_downlinkadvancedreceiverperformance;
static int hf_ms_class3_unpacked_dtm_enhancementscapability;
static int hf_ms_class3_unpacked_dtm_gprs_highmultislotclass;
static int hf_ms_class3_unpacked_offsetrequired;
static int hf_ms_class3_unpacked_repeatedsacch_capability;
static int hf_ms_class3_unpacked_spare2;
static int hf_channel_request_description_peak_throughput_class;
static int hf_channel_request_description_radio_priority;
static int hf_channel_request_description_llc_pdu_type;
static int hf_channel_request_description_rlc_octet_count;

/* < Packet Resource Request message content > */
static int hf_bep_measurementreport_mean_bep_gmsk;
static int hf_bep_measurementreport_mean_bep_8psk;
static int hf_interferencemeasurementreport_i_level;
static int hf_egprs_bep_linkqualitymeasurements_mean_bep_gmsk;
static int hf_egprs_bep_linkqualitymeasurements_cv_bep_gmsk;
static int hf_egprs_bep_linkqualitymeasurements_mean_bep_8psk;
static int hf_egprs_bep_linkqualitymeasurements_cv_bep_8psk;
static int hf_prr_additionsr99_ms_rac_additionalinformationavailable;
static int hf_prr_additionsr99_retransmissionofprr;
static int hf_packet_resource_request_access_type;
static int hf_packet_resource_request_change_mark;
static int hf_packet_resource_request_c_value;
static int hf_packet_resource_request_sign_var;

/*< Packet Mobile TBF Status message content > */
static int hf_packet_mobile_tbf_status_tbf_cause;

/*< Packet PSI Status message content > */
static int hf_psi_message_psix_change_mark;
static int hf_additional_msg_type;
static int hf_packet_psi_status_pbcch_change_mark;

/* < Packet SI Status message content > */
static int hf_si_message_mess_rec;

/* < Packet Downlink Ack/Nack message content > */

/*< EGPRS Packet Downlink Ack/Nack message content > */
static int hf_egprs_channelqualityreport_c_value;
static int hf_egprs_pd_acknack_ms_out_of_memory;
static int hf_fddarget_cell_t_fdd_arfcn;
static int hf_fddarget_cell_t_diversity;
static int hf_fddarget_cell_t_bandwith_fdd;
static int hf_fddarget_cell_t_scrambling_code;
static int hf_tddarget_cell_t_tdd_arfcn;
static int hf_tddarget_cell_t_diversity;
static int hf_tddarget_cell_t_bandwith_tdd;
static int hf_tddarget_cell_t_cell_parameter;
static int hf_tddarget_cell_t_sync_case_tstd;


/*< Packet Cell Change Failure message content > */
static int hf_packet_cell_change_failure_bsic;
static int hf_packet_cell_change_failure_cause;
static int hf_utran_csg_target_cell_ci;
static int hf_eutran_csg_target_cell_ci;
static int hf_eutran_csg_target_cell_tac;


/*< Packet Uplink Ack/Nack message content > */
static int hf_pu_acknack_gprs_additionsr99_tbf_est;
static int hf_pu_acknack_gprs_fixedallocationdummy;
static int hf_pu_acknack_egprs_00_pre_emptive_transmission;
static int hf_pu_acknack_egprs_00_prr_retransmission_request;
static int hf_pu_acknack_egprs_00_arac_retransmission_request;
static int hf_pu_acknack_egprs_00_tbf_est;
static int hf_packet_extended_timing_advance;

/*< Packet Uplink Assignment message content > */
static int hf_change_mark_change_mark_1;
static int hf_change_mark_change_mark_2;
static int hf_indirect_encoding_ma_number;
static int hf_packet_request_reference_random_access_information;
static int hf_timeslot_allocation_usf_tn;
static int hf_extended_dynamic_allocation;
static int hf_rlc_data_blocks_granted;
static int hf_single_block_allocation_timeslot_number;
static int hf_dtm_single_block_allocation_timeslot_number;
static int hf_compact_reducedma_bitmaplength;
static int hf_multiblock_allocation_timeslot_number;
static int hf_pua_egprs_00_arac_retransmission_request;

/*< Packet Downlink Assignment message content > */
static int hf_measurement_mapping_struct_measurement_interval;
static int hf_measurement_mapping_struct_measurement_bitmap;
static int hf_mac_mode;
static int hf_control_ack;
static int hf_dl_timeslot_allocation;
static int hf_dtm_channel_request_description_dtm_pkt_est_cause;

/*< Packet Paging Request message content > */
static int hf_mobile_identity_length_of_mobile_identity_contents;
static int hf_page_request_for_rr_conn_channel_needed;
static int hf_page_request_for_rr_conn_emlpp_priority;
static int hf_packet_pdch_release_timeslots_available;

/*< Packet Power Control/Timing Advance message content >*/

/*< Packet Queueing Notification message content > */

/*< Packet Timeslot Reconfigure message content > */

/*< Packet PRACH Parameters message content > */
static int hf_prach_control_s;
static int hf_prach_control_tx_int;
static int hf_hcs_priority_class;
static int hf_hcs_hcs_thr;
static int hf_location_repeat_pbcch_location;
static int hf_location_repeat_psi1_repeat_period;
static int hf_si13_pbcch_location_si13_location;
static int hf_cell_selection_bsic;
static int hf_cell_bar_access_2;
static int hf_cell_selection_same_ra_as_serving_cell;
static int hf_cell_selection_gprs_rxlev_access_min;
static int hf_cell_selection_gprs_ms_txpwr_max_cch;
static int hf_cell_selection_gprs_temporary_offset;
static int hf_cell_selection_gprs_penalty_time;
static int hf_cell_selection_gprs_reselect_offset;
static int hf_neighbourcellparameters_start_frequency;
static int hf_neighbourcellparameters_nr_of_remaining_cells;
static int hf_cell_selection_2_same_ra_as_serving_cell;
static int hf_cell_selection_2_gprs_rxlev_access_min;
static int hf_cell_selection_2_gprs_ms_txpwr_max_cch;
static int hf_cell_selection_2_gprs_temporary_offset;
static int hf_cell_selection_2_gprs_penalty_time;
static int hf_cell_selection_2_gprs_reselect_offset;

/* < Packet Access Reject message content > */
static int hf_reject_wait_indication;
static int hf_reject_wait_indication_size;

/* < Packet Cell Change Order message content > */
static int hf_h_freqbsiccell_bsic;
static int hf_cellselectionparamswithfreqdiff_bsic;
static int hf_add_frequency_list_start_frequency;
static int hf_add_frequency_list_bsic;
static int hf_add_frequency_list_nr_of_frequencies;
static int hf_removed_freq_index_removed_freq_index;
static int hf_nc_measurement_parameters_network_control_order;
static int hf_nc_measurement_parameters_nc_non_drx_period;
static int hf_nc_measurement_parameters_nc_reporting_period_i;
static int hf_nc_measurement_parameters_nc_reporting_period_t;
static int hf_nc_measurement_parameters_with_frequency_list_network_control_order;
static int hf_nc_measurement_parameters_with_frequency_list_nc_non_drx_period;
static int hf_nc_measurement_parameters_with_frequency_list_nc_reporting_period_i;
static int hf_nc_measurement_parameters_with_frequency_list_nc_reporting_period_t;

/*< Packet Cell Change Order message contents >*/
static int hf_ba_ind_ba_ind;
static int hf_ba_ind_ba_ind_3g;
static int hf_gprsreportpriority_number_cells;
static int hf_offsetthreshold_reporting_offset;
static int hf_offsetthreshold_reporting_threshold;
static int hf_gprsmeasurementparams_pmo_pcco_multi_band_reporting;
static int hf_gprsmeasurementparams_pmo_pcco_serving_band_reporting;
static int hf_gprsmeasurementparams_pmo_pcco_scale_ord;
static int hf_gprsmeasurementparams3g_qsearch_p;
static int hf_gprsmeasurementparams3g_searchprio3g;
static int hf_gprsmeasurementparams3g_repquantfdd;
static int hf_gprsmeasurementparams3g_multiratreportingfdd;
static int hf_gprsmeasurementparams3g_reportingoffsetfdd;
static int hf_gprsmeasurementparams3g_reportingthresholdfdd;
static int hf_gprsmeasurementparams3g_multiratreportingtdd;
static int hf_gprsmeasurementparams3g_reportingoffsettdd;
static int hf_gprsmeasurementparams3g_reportingthresholdtdd;
static int hf_multiratparams3g_multiratreporting;
static int hf_enh_gprsmeasurementparams3g_pmo_qsearch_p;
static int hf_enh_gprsmeasurementparams3g_pmo_searchprio3g;
static int hf_enh_gprsmeasurementparams3g_pmo_repquantfdd;
static int hf_enh_gprsmeasurementparams3g_pmo_multiratreportingfdd;
static int hf_enh_gprsmeasurementparams3g_pcco_qsearch_p;
static int hf_enh_gprsmeasurementparams3g_pcco_searchprio3g;
static int hf_enh_gprsmeasurementparams3g_pcco_repquantfdd;
static int hf_enh_gprsmeasurementparams3g_pcco_multiratreportingfdd;
static int hf_n2_removed_3gcell_index;
static int hf_n2_cell_diff_length_3g;
static int hf_cdma2000_description_complete_this;
static int hf_utran_fdd_neighbourcells_zero;
static int hf_utran_fdd_neighbourcells_uarfcn;
static int hf_utran_fdd_neighbourcells_indic0;
static int hf_utran_fdd_neighbourcells_nrofcells;
static int hf_utran_fdd_description_bandwidth;
static int hf_utran_tdd_neighbourcells_zero;
static int hf_utran_tdd_neighbourcells_uarfcn;
static int hf_utran_tdd_neighbourcells_indic0;
static int hf_utran_tdd_neighbourcells_nrofcells;
static int hf_utran_tdd_description_bandwidth;
static int hf_index_start_3g;
static int hf_absolute_index_start_emr;
static int hf_psi3_change_mark;
static int hf_enh_measurement_parameters_pmo_pmo_ind;
static int hf_enh_measurement_parameters_pmo_report_type;
static int hf_enh_measurement_parameters_pmo_reporting_rate;
static int hf_enh_measurement_parameters_pmo_invalid_bsic_reporting;
static int hf_enh_measurement_parameters_pcco_pmo_ind;
static int hf_enh_measurement_parameters_pcco_report_type;
static int hf_enh_measurement_parameters_pcco_reporting_rate;
static int hf_enh_measurement_parameters_pcco_invalid_bsic_reporting;
static int hf_ccn_support_description_number_cells;
static int hf_lu_modecellselectionparameters_cell_bar_qualify_3;
static int hf_lu_modeneighbourcellparams_nr_of_frequencies;
static int hf_lu_modeonlycellselection_cell_bar_qualify_3;
static int hf_lu_modeonlycellselection_same_ra_as_serving_cell;
static int hf_lu_modeonlycellselection_gprs_rxlev_access_min;
static int hf_lu_modeonlycellselection_gprs_ms_txpwr_max_cch;
static int hf_lu_modeonlycellselection_gprs_temporary_offset;
static int hf_lu_modeonlycellselection_gprs_penalty_time;
static int hf_lu_modeonlycellselection_gprs_reselect_offset;
static int hf_lu_modeonlycellselectionparamswithfreqdiff_bsic;
static int hf_add_lu_modeonlyfrequencylist_start_frequency;
static int hf_add_lu_modeonlyfrequencylist_bsic;
static int hf_add_lu_modeonlyfrequencylist_nr_of_frequencies;
static int hf_add_lu_modeonlyfrequencylist_freq_diff_length;
static int hf_gprs_additionalmeasurementparams3g_fdd_reporting_threshold_2;
static int hf_servingcellpriorityparametersdescription_geran_priority;
static int hf_servingcellpriorityparametersdescription_thresh_priority_search;
static int hf_servingcellpriorityparametersdescription_thresh_gsm_low;
static int hf_servingcellpriorityparametersdescription_h_prio;
static int hf_servingcellpriorityparametersdescription_t_reselection;
static int hf_repeatedutran_priorityparameters_utran_priority;
static int hf_repeatedutran_priorityparameters_thresh_utran_high;
static int hf_repeatedutran_priorityparameters_thresh_utran_low;
static int hf_repeatedutran_priorityparameters_utran_qrxlevmin;
static int hf_priorityparametersdescription3g_pmo_default_utran_priority;
static int hf_priorityparametersdescription3g_pmo_default_thresh_utran;
static int hf_priorityparametersdescription3g_pmo_default_utran_qrxlevmin;
static int hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_threshold;
static int hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_threshold_2;
static int hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_offset;
static int hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_threshold;
static int hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_threshold_2;
static int hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_offset;
static int hf_gprs_eutran_measurementparametersdescription_qsearch_p_eutran;
static int hf_gprs_eutran_measurementparametersdescription_eutran_rep_quant;
static int hf_gprs_eutran_measurementparametersdescription_eutran_multirat_reporting;
static int hf_repeatedeutran_cells_earfcn;
static int hf_repeatedeutran_cells_measurementbandwidth;
static int hf_repeatedeutran_neighbourcells_eutran_priority;
static int hf_repeatedeutran_neighbourcells_thresh_eutran_high;
static int hf_repeatedeutran_neighbourcells_thresh_eutran_low;
static int hf_repeatedeutran_neighbourcells_eutran_qrxlevmin;
static int hf_pcid_pattern_pcid_pattern_length;
static int hf_pcid_pattern_pcid_pattern_sense;
static int hf_pcid_group_ie_pcid_bitmap_group;
static int hf_eutran_frequency_index_eutran_frequency_index;
static int hf_eutran_parametersdescription_pmo_eutran_ccn_active;
static int hf_psc_pattern_sense;
static int hf_psc_pattern_length;
static int hf_meas_ctrl_param_meas_ctrl_eutran;
static int hf_meas_ctrl_param_eutran_freq_idx;
static int hf_meas_ctrl_param_meas_ctrl_utran;
static int hf_meas_ctrl_param_utran_freq_idx;
static int hf_rept_eutran_enh_cell_resel_param_eutran_qmin;
static int hf_rept_eutran_enh_cell_resel_param_thresh_eutran_high_q;
static int hf_rept_eutran_enh_cell_resel_param_thresh_eutran_low_q;
static int hf_rept_eutran_enh_cell_resel_param_thresh_eutran_qqualmin;
static int hf_rept_eutran_enh_cell_resel_param_thresh_eutran_rsrpmin;

static int hf_utran_csg_fdd_reporting_threshold;
static int hf_utran_csg_fdd_reporting_threshold2;
static int hf_utran_csg_tdd_reporting_threshold;
static int hf_eutran_csg_fdd_reporting_threshold;
static int hf_eutran_csg_fdd_reporting_threshold2;
static int hf_eutran_csg_tdd_reporting_threshold;
static int hf_eutran_csg_tdd_reporting_threshold2;


static int hf_pmo_additionsr8_ba_ind_3g;
static int hf_pmo_additionsr8_pmo_ind;
static int hf_pmo_additionsr7_reporting_offset_700;
static int hf_pmo_additionsr7_reporting_threshold_700;
static int hf_pmo_additionsr7_reporting_offset_810;
static int hf_pmo_additionsr7_reporting_threshold_810;
static int hf_pmo_additionsr6_ccn_active_3g;
static int hf_pcco_additionsr6_ccn_active_3g;
static int hf_pmo_additionsr5_grnti;
static int hf_pcco_additionsr5_grnti;
static int hf_pmo_additionsr4_ccn_active;
static int hf_pcco_additionsr4_ccn_active;
static int hf_pcco_additionsr4_container_id;
static int hf_lsa_id_info_element_lsa_id;
static int hf_lsa_id_info_element_shortlsa_id;
static int hf_lsa_parameters_nr_of_freq_or_cells;
static int hf_target_cell_gsm_immediate_rel;
static int hf_target_cell_gsm_bsic;
static int hf_target_cell_3g_immediate_rel;
static int hf_target_cell_eutran_earfcn;
static int hf_target_cell_eutran_measurement_bandwidth;
static int hf_target_cell_eutran_pl_cell_id;
static int hf_idvd_default_utran_priority;
static int hf_idvd_utran_priority;
static int hf_idvd_default_eutran_priority;
static int hf_idvd_eutran_priority;
static int hf_idvd_prio_geran_priority;
static int hf_idvd_prio_t3230_timeout_value;
static int hf_target_cell_g_rnti_ext;



/*< Packet (Enhanced) Measurement Report message contents > */
static int hf_ba_used_ba_used;
static int hf_ba_used_ba_used_3g;
static int hf_serving_cell_data_rxlev_serving_cell;
static int hf_nc_measurements_frequency_n;
static int hf_nc_measurements_bsic_n;
static int hf_nc_measurements_rxlev_n;
static int hf_repeatedinvalid_bsic_info_bcch_freq_n;
static int hf_repeatedinvalid_bsic_info_bsic_n;
static int hf_repeatedinvalid_bsic_info_rxlev_n;
static int hf_reporting_quantity_instance_reporting_quantity;
static int hf_nc_measurement_report_nc_mode;
static int hf_nc_measurement_report_number_of_nc_measurements;
static int hf_enh_nc_measurement_report_nc_mode;
static int hf_enh_nc_measurement_report_pmo_used;
static int hf_enh_nc_measurement_report_bsic_seen;
static int hf_enh_nc_measurement_report_scale;
static int hf_ext_measurement_report_ext_reporting_type;
static int hf_ext_measurement_report_slot0_i_level;
static int hf_ext_measurement_report_slot1_i_level;
static int hf_ext_measurement_report_slot2_i_level;
static int hf_ext_measurement_report_slot3_i_level;
static int hf_ext_measurement_report_slot4_i_level;
static int hf_ext_measurement_report_slot5_i_level;
static int hf_ext_measurement_report_slot6_i_level;
static int hf_ext_measurement_report_slot7_i_level;
static int hf_ext_measurement_report_number_of_ext_measurements;
static int hf_measurements_3g_cell_list_index_3g;
static int hf_measurements_3g_reporting_quantity;
static int hf_pmr_additionsr99_pmo_used;
static int hf_pmr_eutran_meas_rpt_freq_idx;
static int hf_pmr_eutran_meas_rpt_cell_id;
static int hf_pmr_eutran_meas_rpt_quantity;
static int hf_emr_servingcell_dtx_used;
static int hf_emr_servingcell_rxlev_val;
static int hf_emr_servingcell_rx_qual_full;
static int hf_emr_servingcell_mean_bep;
static int hf_emr_servingcell_cv_bep;
static int hf_emr_servingcell_nbr_rcvd_blocks;
static int hf_enhancedmeasurementreport_rr_short_pd;
static int hf_enhancedmeasurementreport_message_type;
static int hf_enhancedmeasurementreport_shortlayer2_header;
static int hf_enhancedmeasurementreport_bsic_seen;
static int hf_enhancedmeasurementreport_scale;
static int hf_packet_measurement_report_psi5_change_mark;

/*< Packet Measurement Order message contents >*/
static int hf_ext_frequency_list_start_frequency;
static int hf_ext_frequency_list_nr_of_frequencies;
static int hf_ext_frequency_list_freq_diff_length;
static int hf_packet_measurement_order_pmo_index;
static int hf_packet_measurement_order_pmo_count;
static int hf_ccn_measurement_report_rxlev_serving_cell;
static int hf_ccn_measurement_report_number_of_nc_measurements;
static int hf_target_cell_gsm_notif_bsic;
static int hf_fdd_target_cell_notif_fdd_arfcn;
static int hf_fdd_target_cell_notif_bandwith_fdd;
static int hf_fdd_target_cell_notif_scrambling_code;
static int hf_target_cell_3g_notif_reporting_quantity;
static int hf_pccn_additionsr6_ba_used_3g;

/*< Packet Cell Change Notification message contents > */
static int hf_packet_cell_change_notification_ba_ind;
static int hf_packet_cell_change_notification_pmo_used;
static int hf_packet_cell_change_notification_pccn_sending;
static int hf_packet_cell_change_notification_lte_reporting_quantity;
static int hf_eutran_ccn_meas_rpt_3g_ba_used;
static int hf_eutran_ccn_meas_rpt_freq_idx;
static int hf_eutran_ccn_meas_cell_id;
static int hf_eutran_ccn_meas_rpt_quantity;
static int hf_utran_csg_meas_rpt_cgi;
static int hf_utran_csg_meas_rpt_csg_id;
static int hf_utran_csg_meas_rpt_access_mode;
static int hf_utran_csg_meas_rpt_quantity;
static int hf_eutran_csg_meas_rpt_cgi;
static int hf_eutran_csg_meas_rpt_ta;
static int hf_eutran_csg_meas_rpt_csg_id;
static int hf_eutran_csg_meas_rpt_access_mode;
static int hf_eutran_csg_meas_rpt_quantity;



/*< Packet Cell Change Continue message contents > */
static int hf_packet_cell_change_continue_arfcn;
static int hf_packet_cell_change_continue_bsic;
static int hf_packet_cell_change_continue_container_id;

/*< Packet Neighbour Cell Data message contents > */
static int hf_pncd_container_with_id_bsic;
static int hf_packet_neighbour_cell_data_container_id;
static int hf_packet_neighbour_cell_data_spare;
static int hf_packet_neighbour_cell_data_container_index;

/*< Packet Serving Cell Data message contents > */
static int hf_packet_serving_cell_data_spare;
static int hf_packet_serving_cell_data_container_index;
static int hf_servingcelldata_rxlev_serving_cell;
static int hf_repeated_invalid_bsic_info_bcch_freq_ncell;
static int hf_repeated_invalid_bsic_info_bsic;
static int hf_repeated_invalid_bsic_info_rxlev_ncell;
static int hf_reporting_quantity_reporting_quantity;
static int hf_nc_measurementreport_nc_mode;
static int hf_nc_measurementreport_pmo_used;
static int hf_nc_measurementreport_scale;

/*< Packet Handover Command message content > */
static int hf_globaltimeslotdescription_ms_timeslotallocation;
static int hf_pho_usf_1_7_usf;
static int hf_usf_allocationarray_usf_0;
static int hf_egprs_description_linkqualitymeasurementmode;
static int hf_nas_container_nas_containerlength;
static int hf_ps_handoverto_utran_payload_rrc_containerlength;
static int hf_pho_radioresources_handoverreference;
static int hf_pho_radioresources_si;
static int hf_pho_radioresources_nci;
static int hf_pho_radioresources_bsic;
static int hf_pho_radioresources_ccn_active;
static int hf_pho_radioresources_ccn_active_3g;
static int hf_pho_radioresources_networkcontrolorder;
static int hf_pho_radioresources_rlc_reset;
static int hf_pho_radioresources_uplinkcontroltimeslot;
static int hf_packet_handover_command_containerid;

/*< End Packet Handover Command >*/

/*< Packet Physical Information message content > */

/*< End Packet Physical Information > */

/* < Additinal MS Radio Access Capability */
/* < End Additinal MS Radio Access Capability */


/* < Packet Pause > */
/* < End Packet Pause > */

/* < Packet System Information Type 1 > */
static int hf_packet_system_info_type1_pbcch_change_mark;
static int hf_packet_system_info_type1_psi_change_field;
static int hf_packet_system_info_type1_psi1_repeat_period;
static int hf_packet_system_info_type1_psi_count_lr;
static int hf_packet_system_info_type1_psi_count_hr;
static int hf_packet_system_info_type1_measurement_order;
static int hf_packet_system_info_type1_psi_status_ind;
static int hf_packet_system_info_type1_mscr;
static int hf_packet_system_info_type1_band_indicator;
static int hf_packet_system_info_type1_lb_ms_txpwr_max_ccch;
static int hf_pccch_org_bs_pcc_rel;
static int hf_pccch_org_pbcch_blks;
static int hf_pccch_org_pag_blks_res;
static int hf_pccch_org_prach_blks;
/* <End Packet System Information Type 1> */

/* <Packet System Information Type 2> */
static int hf_packet_system_info_type2_change_mark;
static int hf_packet_system_info_type2_index;
static int hf_packet_system_info_type2_count;
static int hf_packet_system_info_type2_ref_freq_num;
static int hf_packet_system_info_type2_ma_number;
static int hf_tsc;
static int hf_packet_system_info_type2_non_hopping_timeslot;
static int hf_packet_system_info_type2_hopping_ma_num;
static int hf_packet_system_info_type2_hopping_timeslot;

static int hf_packet_cell_id_cell_identity;
static int hf_packet_lai_lac;
static int hf_packet_plmn_mcc1;
static int hf_packet_plmn_mcc2;
static int hf_packet_plmn_mcc3;
static int hf_packet_plmn_mnc1;
static int hf_packet_plmn_mnc2;
static int hf_packet_plmn_mnc3;
static int hf_packet_non_gprs_cell_opt_att;
static int hf_packet_non_gprs_cell_opt_t3212;
static int hf_packet_non_gprs_cell_opt_neci;
static int hf_packet_non_gprs_cell_opt_pwrc;
static int hf_packet_non_gprs_cell_opt_dtx;
static int hf_packet_non_gprs_cell_opt_radio_link_timeout;
static int hf_packet_non_gprs_cell_opt_bs_ag_blks_res;
static int hf_packet_non_gprs_cell_opt_ccch_conf;
static int hf_packet_non_gprs_cell_opt_bs_pa_mfrms;
static int hf_packet_non_gprs_cell_opt_max_retrans;
static int hf_packet_non_gprs_cell_opt_tx_int;
static int hf_packet_non_gprs_cell_opt_ec;
static int hf_packet_non_gprs_cell_opt_ms_txpwr_max_ccch;
static int hf_packet_non_gprs_cell_opt_ext_len;
/* <End Packet System Information Type 2> */


/* <Packet System Information Type 3> */
static int hf_packet_system_info_type3_change_mark;
static int hf_packet_system_info_type3_bis_count;

static int hf_exc_acc;
static int hf_packet_scell_param_gprs_rxlev_access_min;
static int hf_packet_scell_param_gprs_ms_txpwr_max_cch;
static int hf_packet_scell_param_multiband_reporting;

static int hf_packet_gen_cell_sel_gprs_cell_resl_hyst;
static int hf_packet_gen_cell_sel_c31_hyst;
static int hf_packet_gen_cell_sel_c32_qual;
static int hf_packet_gen_cell_sel_t_resel;
static int hf_packet_gen_cell_sel_ra_resel_hyst;

static int hf_packet_compact_cell_sel_bsic;
static int hf_packet_compact_cell_sel_same_as_scell;
static int hf_packet_compact_cell_sel_gprs_rxlev_access_min;
static int hf_packet_compact_cell_sel_gprs_ms_txpwr_max_cch;
static int hf_packet_compact_cell_sel_gprs_temp_offset;
static int hf_packet_compact_cell_sel_gprs_penalty_time;
static int hf_packet_compact_cell_sel_gprs_resel_offset;
static int hf_packet_compact_cell_sel_time_group;
static int hf_packet_compact_cell_sel_guar_const_pwr_blks;
static int hf_packet_compact_ncell_param_start_freq;
static int hf_packet_compact_ncell_param_nr_of_remaining_cells;
/* <End Packet System Information Type 3> */

/* <Packet System Information Type 5> */
static int hf_gprsmeasurementparams3g_psi5_repquantfdd;
static int hf_gprsmeasurementparams3g_psi5_multiratreportingfdd;
static int hf_gprsmeasurementparams3g_psi5_reportingoffsetfdd;
static int hf_gprsmeasurementparams3g_psi5_reportingthresholdfdd;
static int hf_gprsmeasurementparams3g_psi5_multiratreportingtdd;
static int hf_gprsmeasurementparams3g_psi5_reportingoffsettdd;
static int hf_gprsmeasurementparams3g_psi5_reportingthresholdtdd;
static int hf_enh_reporting_parameters_report_type;
static int hf_enh_reporting_parameters_reporting_rate;
static int hf_enh_reporting_parameters_invalid_bsic_reporting;
static int hf_enh_reporting_parameters_ncc_permitted;
static int hf_packet_system_info_type5_change_mark;
static int hf_packet_system_info_type5_index;
static int hf_packet_system_info_type5_count;
/* <End Packet System Information Type 5> */


/* <Packet System Information Type 13> */
static int hf_packet_system_info_type13_lb_ms_mxpwr_max_cch;
static int hf_packet_system_info_type13_si2n_support;
/* <End Packet System Information Type 13> */




static int hf_si1_restoctet_nch_position;
static int hf_si1_restoctet_bandindicator;
static int hf_selection_parameters_cbq;
static int hf_selection_parameters_cell_reselect_offset;
static int hf_selection_parameters_temporary_offset;
static int hf_selection_parameters_penalty_time;
static int hf_si3_rest_octet_power_offset;
static int hf_si3_rest_octet_system_information_2ter_indicator;
static int hf_si3_rest_octet_early_classmark_sending_control;
static int hf_si3_rest_octet_where;
static int hf_si3_rest_octet_ra_colour;
static int hf_si13_position;
static int hf_si3_rest_octet_ecs_restriction3g;
static int hf_si3_rest_octet_si2quaterindicator;
static int hf_si4_rest_octet_power_offset;
static int hf_si4_rest_octet_ra_colour;
static int hf_pch_and_nch_info_pagingchannelrestructuring;
static int hf_pch_and_nch_info_nln_sacch;
static int hf_pch_and_nch_info_callpriority;
static int hf_si6_restoctet_vbs_vgcs_options;
static int hf_si6_restoctet_max_lapdm;
static int hf_si6_restoctet_bandindicator;

static dissector_handle_t data_handle;

/* Payload type as defined in TS 44.060 / 10.4.7 */
#define PAYLOAD_TYPE_DATA              0
#define PAYLOAD_TYPE_CTRL_NO_OPT_OCTET 1
#define PAYLOAD_TYPE_CTRL_OPT_OCTET    2
#define PAYLOAD_TYPE_RESERVED          3


#define GPRS_CS_OFFSET(cS) ((cS)- RLCMAC_CS1)
#define EGPRS_HEADER_TYPE_OFFSET(hT) ((hT)- RLCMAC_HDR_TYPE_1)

static const guint8 egprs_Header_type1_coding_puncturing_scheme_to_mcs[] = {
   9 /* 0x00, "(MCS-9/P1 ; MCS-9/P1)" */,            
   9 /* 0x01, "(MCS-9/P1 ; MCS-9/P2)" */,
   9 /* 0x02, "(MCS-9/P1 ; MCS-9/P3)" */,            
   9 /* 0x03, "reserved" */,            
   9 /* 0x04, "(MCS-9/P2 ; MCS-9/P1)" */,
   9 /* 0x05, "(MCS-9/P2 ; MCS-9/P2)" */,            
   9 /* 0x06, "(MCS-9/P2 ; MCS-9/P3)" */,
   9 /* 0x07, "reserved" */,            
   9 /* 0x08, "(MCS-9/P3 ; MCS-9/P1)" */,            
   9 /* 0x09, "(MCS-9/P3 ; MCS-9/P2)" */,
   9 /* 0x0A, "(MCS-9/P3 ; MCS-9/P3)" */,            
   8 /* 0x0B, "(MCS-8/P1 ; MCS-8/P1)" */,            
   8 /* 0x0C, "(MCS-8/P1 ; MCS-8/P2)" */,            
   8 /* 0x0D, "(MCS-8/P1 ; MCS-8/P3)" */,            
   8 /* 0x0E, "(MCS-8/P2 ; MCS-8/P1)" */,            
   8 /* 0x0F, "(MCS-8/P2 ; MCS-8/P2)" */,            
   8 /* 0x10, "(MCS-8/P2 ; MCS-8/P3)" */,            
   8 /* 0x11, "(MCS-8/P3 ; MCS-8/P1)" */,            
   8 /* 0x12, "(MCS-8/P3 ; MCS-8/P2)" */,            
   8 /* 0x13, "(MCS-8/P3 ; MCS-8/P3)" */,            
   7 /* 0x14, "(MCS-7/P1 ; MCS-7/P1)" */,            
   7 /* 0x15, "(MCS-7/P1 ; MCS-7/P2)" */,            
   7 /* 0x16, "(MCS-7/P1 ; MCS-7/P3)" */,            
   7 /* 0x17, "(MCS-7/P2 ; MCS-7/P1)" */,            
   7 /* 0x18, "(MCS-7/P2 ; MCS-7/P2)" */,            
   7 /* 0x19, "(MCS-7/P2 ; MCS-7/P3)" */,            
   7 /* 0x1A, "(MCS-7/P3 ; MCS-7/P1)" */,            
   7 /* 0x1B, "(MCS-7/P3 ; MCS-7/P2)" */,            
   7 /* 0x1C, "(MCS-7/P3 ; MCS-7/P3)" */,            
};

static const guint8 egprs_Header_type2_coding_puncturing_scheme_to_mcs[] = {
   6 /* {0x00, "MCS-6/P1"} */,            
   6 /* {0x01, "MCS-6/P2"} */,
   6 /* {0x02, "MCS-6/P1 with 6 octet padding"} */,            
   6 /* {0x03, "MCS-6/P2 with 6 octet padding "} */,
   5 /* {0x04, "MCS-5/P1"} */,            
   5 /* {0x05, "MCS-5/P2"} */,
   5 /* {0x06, "MCS-6/P1 with 10 octet padding "} */,            
   5 /* {0x07, "MCS-6/P2 with 10 octet padding "} */,
};

static const guint8 egprs_Header_type3_coding_puncturing_scheme_to_mcs[] = {
   4 /* {0x00, "MCS-4/P1"} */,            
   4 /* {0x01, "MCS-4/P2"} */,
   4 /* {0x02, "MCS-4/P3"} */,            
   3 /* {0x03, "MCS-3/P1"} */,            
   3 /* {0x04, "MCS-3/P2"} */,
   3 /* {0x05, "MCS-3/P3"} */,            
   3 /* {0x06, "MCS-3/P1 with padding"} */,            
   3 /* {0x07, "MCS-3/P2 with padding"} */,
   3 /* {0x08, "MCS-3/P3 with padding"} */,            
   2 /* {0x09, "MCS-2/P1"} */,
   2 /* {0x0A, "MCS-2/P2"} */,
   1 /* {0x0B, "MCS-1/P1"} */,
   1 /* {0x0C, "MCS-1/P2"} */,
   2 /* {0x0D, "MCS-2/P1 with padding"} */,            
   2 /* {0x0E, "MCS-2/P2 with padding"} */,
   0 /* {0x0F, "MCS-0"} */,            
};

static crumb_spec_t bits_spec_ul_bsn1[] = {
    {10, 6},
    {0,  5},
    {0,  0}
};
static crumb_spec_t bits_spec_ul_bsn2[] = {
    {8,  8},
    {0,  2},
    {0,  0}
};

static crumb_spec_t bits_spec_ul_tfi[] = {
    {13, 3},
    {0,  2},
    {0,  0}
};

static crumb_spec_t bits_spec_ul_type2_cps[] = {
    {15, 1},
    {0,  2},
    {0,  0}
};
static crumb_spec_t bits_spec_ul_type3_cps[] = {
    {14, 2},
    {0,  2},
    {0,  0}
};

static crumb_spec_t bits_spec_dl_type1_bsn1[] = {
    {23, 1},
    {8,  8},
    {0,  2},
    {0,  0}
};
static crumb_spec_t bits_spec_dl_type1_bsn2[] = {
    {13, 3},
    {0,  7},
    {0,  0}
};

static crumb_spec_t bits_spec_dl_type2_bsn[] = {
    {23, 1},
    {8,  8},
    {0,  2},
    {0,  0}
};

static crumb_spec_t bits_spec_dl_type3_bsn[] = {
    {23, 1},
    {8,  8},
    {0,  2},
    {0,  0}
};

static crumb_spec_t bits_spec_dl_tfi[] = {
    {12, 4},
    {0,  1},
    {0,  0}
};

/* CSN1 structures */
/*(not all parts of CSN_DESCR structure are always initialized.)*/
static const
CSN_DESCR_BEGIN(PLMN_t)
  M_UINT       (PLMN_t,  MCC2,  4, &hf_packet_plmn_mcc2),
  M_UINT       (PLMN_t,  MCC1,  4, &hf_packet_plmn_mcc1),
  M_UINT       (PLMN_t,  MNC3,  4, &hf_packet_plmn_mnc3),
  M_UINT       (PLMN_t,  MCC3,  4, &hf_packet_plmn_mcc3),
  M_UINT       (PLMN_t,  MNC2,  4, &hf_packet_plmn_mnc2),
  M_UINT       (PLMN_t,  MNC1,  4, &hf_packet_plmn_mnc1),
CSN_DESCR_END  (PLMN_t)

static const
CSN_DESCR_BEGIN(StartingTime_t)
  M_UINT       (StartingTime_t,  N32,  5, &hf_startingtime_n32),
  M_UINT       (StartingTime_t,  N51,  6, &hf_startingtime_n51),
  M_UINT       (StartingTime_t,  N26,  5, &hf_startingtime_n26),
CSN_DESCR_END  (StartingTime_t)

/*< Global TFI IE >*/
static const
CSN_DESCR_BEGIN(Global_TFI_t)
  M_UNION      (Global_TFI_t, 2),
  M_UINT       (Global_TFI_t,  u.UPLINK_TFI,  5, &hf_uplink_tfi),
  M_UINT       (Global_TFI_t,  u.DOWNLINK_TFI,  5, &hf_downlink_tfi),
CSN_DESCR_END  (Global_TFI_t)

/*< Starting Frame Number Description IE >*/
static const
CSN_DESCR_BEGIN(Starting_Frame_Number_t)
  M_UNION      (Starting_Frame_Number_t, 2),
  M_TYPE       (Starting_Frame_Number_t, u.StartingTime, StartingTime_t),
  M_UINT       (Starting_Frame_Number_t,  u.k,  13, &hf_starting_frame_number_k),
CSN_DESCR_END(Starting_Frame_Number_t)

/*< Ack/Nack Description IE >*/
static const
CSN_DESCR_BEGIN(Ack_Nack_Description_t)
  M_UINT       (Ack_Nack_Description_t,  FINAL_ACK_INDICATION, 1, &hf_ack_nack_description_final_ack_indication),
  M_UINT       (Ack_Nack_Description_t,  STARTING_SEQUENCE_NUMBER,  7, &hf_ack_nack_description_starting_sequence_number),
  M_BITMAP     (Ack_Nack_Description_t, RECEIVED_BLOCK_BITMAP, 64),
CSN_DESCR_END  (Ack_Nack_Description_t)

/*< Packet Timing Advance IE >*/
static const
CSN_DESCR_BEGIN(Packet_Timing_Advance_t)
  M_NEXT_EXIST (Packet_Timing_Advance_t, Exist_TIMING_ADVANCE_VALUE, 1),
  M_UINT       (Packet_Timing_Advance_t,  TIMING_ADVANCE_VALUE, 6, &hf_timing_advance_value),

  M_NEXT_EXIST (Packet_Timing_Advance_t, Exist_IndexAndtimeSlot, 2),
  M_UINT       (Packet_Timing_Advance_t, TIMING_ADVANCE_INDEX, 4, &hf_timing_advance_index),
  M_UINT       (Packet_Timing_Advance_t, TIMING_ADVANCE_TIMESLOT_NUMBER, 3, &hf_timing_advance_timeslot_number),
CSN_DESCR_END  (Packet_Timing_Advance_t)

/*< Power Control Parameters IE >*/
static const
CSN_DESCR_BEGIN(GPRS_Power_Control_Parameters_t)
  M_UINT       (GPRS_Power_Control_Parameters_t, ALPHA, 4, &hf_alpha),
  M_UINT       (GPRS_Power_Control_Parameters_t, T_AVG_W, 5, &hf_t_avg_w),
  M_UINT       (GPRS_Power_Control_Parameters_t, T_AVG_T, 5, &hf_t_avg_t),
  M_UINT       (GPRS_Power_Control_Parameters_t, PC_MEAS_CHAN, 1, &hf_pc_meas_chan),
  M_UINT       (GPRS_Power_Control_Parameters_t, N_AVG_I, 4, &hf_n_avg_i),
CSN_DESCR_END  (GPRS_Power_Control_Parameters_t)

/*< Global Power Control Parameters IE >*/
static const
CSN_DESCR_BEGIN(Global_Power_Control_Parameters_t)
  M_UINT       (Global_Power_Control_Parameters_t, ALPHA, 4, &hf_alpha),
  M_UINT       (Global_Power_Control_Parameters_t, T_AVG_W, 5, &hf_t_avg_w),
  M_UINT       (Global_Power_Control_Parameters_t, T_AVG_T, 5, &hf_t_avg_t),
  M_UINT       (Global_Power_Control_Parameters_t, Pb, 4, &hf_global_power_control_parameters_pb),
  M_UINT       (Global_Power_Control_Parameters_t, PC_MEAS_CHAN, 1, &hf_pc_meas_chan),
  M_UINT       (Global_Power_Control_Parameters_t, INT_MEAS_CHANNEL_LIST_AVAIL, 1, &hf_global_power_control_parameters_int_meas_channel_list_avail),
  M_UINT       (Global_Power_Control_Parameters_t, N_AVG_I, 4, &hf_n_avg_i),
CSN_DESCR_END  (Global_Power_Control_Parameters_t)

/*< Global Packet Timing Advance IE >*/
static const
CSN_DESCR_BEGIN(Global_Packet_Timing_Advance_t)
  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_TIMING_ADVANCE_VALUE, 1),
  M_UINT       (Global_Packet_Timing_Advance_t,  TIMING_ADVANCE_VALUE,  6, &hf_timing_advance_value),

  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_UPLINK_TIMING_ADVANCE, 2),
  M_UINT       (Global_Packet_Timing_Advance_t,  UPLINK_TIMING_ADVANCE_INDEX,  4, &hf_timing_advance_index),
  M_UINT       (Global_Packet_Timing_Advance_t,  UPLINK_TIMING_ADVANCE_TIMESLOT_NUMBER,  3, &hf_timing_advance_timeslot_number),

  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_DOWNLINK_TIMING_ADVANCE, 2),
  M_UINT       (Global_Packet_Timing_Advance_t,  DOWNLINK_TIMING_ADVANCE_INDEX,  4, &hf_timing_advance_index),
  M_UINT       (Global_Packet_Timing_Advance_t,  DOWNLINK_TIMING_ADVANCE_TIMESLOT_NUMBER,  3, &hf_timing_advance_timeslot_number),
CSN_DESCR_END  (Global_Packet_Timing_Advance_t)

/*< Channel Quality Report struct >*/
static const
CSN_DESCR_BEGIN(Channel_Quality_Report_t)
  M_UINT       (Channel_Quality_Report_t,  C_VALUE,  6, &hf_channel_quality_report_c_value),
  M_UINT       (Channel_Quality_Report_t,  RXQUAL,  3, &hf_channel_quality_report_rxqual),
  M_UINT       (Channel_Quality_Report_t,  SIGN_VAR,  6, &hf_channel_quality_report_sign_var),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[0].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[0].I_LEVEL_TN,  4, &hf_channel_quality_report_slot0_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[1].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[1].I_LEVEL_TN,  4, &hf_channel_quality_report_slot1_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[2].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[2].I_LEVEL_TN,  4, &hf_channel_quality_report_slot2_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[3].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[3].I_LEVEL_TN,  4, &hf_channel_quality_report_slot3_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[4].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[4].I_LEVEL_TN,  4, &hf_channel_quality_report_slot4_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[5].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[5].I_LEVEL_TN,  4, &hf_channel_quality_report_slot5_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[6].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[6].I_LEVEL_TN,  4, &hf_channel_quality_report_slot6_i_level_tn),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[7].Exist, 1),
  M_UINT       (Channel_Quality_Report_t,  Slot[7].I_LEVEL_TN,  4, &hf_channel_quality_report_slot7_i_level_tn),
CSN_DESCR_END  (Channel_Quality_Report_t)

/*< EGPRS Ack/Nack Description struct >*/
static const
CSN_DESCR_BEGIN   (EGPRS_AckNack_Desc_t)
  M_UINT          (EGPRS_AckNack_Desc_t,  FINAL_ACK_INDICATION,  1, &hf_egprs_acknack_final_ack_indication),
  M_UINT          (EGPRS_AckNack_Desc_t,  BEGINNING_OF_WINDOW,  1, &hf_egprs_acknack_beginning_of_window),
  M_UINT          (EGPRS_AckNack_Desc_t,  END_OF_WINDOW,  1, &hf_egprs_acknack_end_of_window),
  M_UINT          (EGPRS_AckNack_Desc_t,  STARTING_SEQUENCE_NUMBER,  11, &hf_egprs_acknack_starting_sequence_number),

  M_NEXT_EXIST    (EGPRS_AckNack_Desc_t,  Exist_CRBB, 3),
  M_UINT          (EGPRS_AckNack_Desc_t,  CRBB_LENGTH,  7, &hf_egprs_acknack_crbb_length),
  M_UINT          (EGPRS_AckNack_Desc_t,  CRBB_STARTING_COLOR_CODE,  1, &hf_egprs_acknack_crbb_starting_color_code),
  M_LEFT_VAR_BMP  (EGPRS_AckNack_Desc_t,  CRBB, CRBB_LENGTH, 0),

  M_LEFT_VAR_BMP_1(EGPRS_AckNack_Desc_t,  URBB, URBB_LENGTH, 0),
CSN_DESCR_END     (EGPRS_AckNack_Desc_t)

/*< EGPRS Ack/Nack Description IE >*/
gint16 Egprs_Ack_Nack_Desc_w_len_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(EGPRS_AckNack_Desc_t), tvb, data, ett_gsm_rlcmac);
}

/* this intermediate structure is only required because M_SERIALIZE cannot be used as a member of M_UNION */
static const
CSN_DESCR_BEGIN(EGPRS_AckNack_w_len_t)
  M_SERIALIZE  (EGPRS_AckNack_w_len_t, Desc, 8, Egprs_Ack_Nack_Desc_w_len_Dissector),
CSN_DESCR_END  (EGPRS_AckNack_w_len_t)

static const
CSN_DESCR_BEGIN(EGPRS_AckNack_t)
  M_UNION      (EGPRS_AckNack_t,  2),
  M_TYPE       (EGPRS_AckNack_t, Desc, EGPRS_AckNack_Desc_t),
  M_TYPE       (EGPRS_AckNack_t, Desc, EGPRS_AckNack_w_len_t),
CSN_DESCR_END  (EGPRS_AckNack_t)

/*<P1 Rest Octets>*/
/*<P2 Rest Octets>*/
static const
CSN_DESCR_BEGIN(MobileAllocationIE_t)
  M_UINT       (MobileAllocationIE_t,  Length,  8, &hf_mobileallocationie_length),
  M_VAR_ARRAY  (MobileAllocationIE_t, MA, Length, 0),
CSN_DESCR_END  (MobileAllocationIE_t)

static const
CSN_DESCR_BEGIN(SingleRFChannel_t)
  M_UINT       (SingleRFChannel_t,  spare,  2, &hf_single_rf_channel_spare),
  M_UINT       (SingleRFChannel_t,  ARFCN,  10, &hf_arfcn),
CSN_DESCR_END  (SingleRFChannel_t)

static const
CSN_DESCR_BEGIN(RFHoppingChannel_t)
  M_UINT       (RFHoppingChannel_t,  MAIO,  6, &hf_maio),
  M_UINT       (RFHoppingChannel_t,  HSN,  6, &hf_hsn),
CSN_DESCR_END  (RFHoppingChannel_t)

static const
CSN_DESCR_BEGIN(MobileAllocation_or_Frequency_Short_List_t)
  M_UNION      (MobileAllocation_or_Frequency_Short_List_t, 2),
  M_BITMAP     (MobileAllocation_or_Frequency_Short_List_t, u.Frequency_Short_List, 64),
  M_TYPE       (MobileAllocation_or_Frequency_Short_List_t, u.MA, MobileAllocationIE_t),
CSN_DESCR_END  (MobileAllocation_or_Frequency_Short_List_t)

static const
CSN_DESCR_BEGIN(Channel_Description_t)
  M_UINT       (Channel_Description_t,  Channel_type_and_TDMA_offset,  5, &hf_channel_description_channel_type_and_tdma_offset),
  M_UINT       (Channel_Description_t,  TN,  3, &hf_channel_description_tn),
  M_UINT       (Channel_Description_t,  TSC,  3, &hf_tsc),

  M_UNION      (Channel_Description_t, 2),
  M_TYPE       (Channel_Description_t, u.SingleRFChannel, SingleRFChannel_t),
  M_TYPE       (Channel_Description_t, u.RFHoppingChannel, RFHoppingChannel_t),
CSN_DESCR_END(Channel_Description_t)

static const
CSN_DESCR_BEGIN(Group_Channel_Description_t)
  M_TYPE       (Group_Channel_Description_t, Channel_Description, Channel_Description_t),

  M_NEXT_EXIST (Group_Channel_Description_t, Exist_Hopping, 1),
  M_TYPE       (Group_Channel_Description_t, MA_or_Frequency_Short_List, MobileAllocation_or_Frequency_Short_List_t),
CSN_DESCR_END  (Group_Channel_Description_t)

static const
CSN_DESCR_BEGIN(Group_Call_Reference_t)
  M_UINT       (Group_Call_Reference_t,  value,  27, &hf_group_call_reference_value),
  M_UINT       (Group_Call_Reference_t,  SF, 1,&hf_group_call_reference_sf),
  M_UINT       (Group_Call_Reference_t,  AF, 1, &hf_group_call_reference_af),
  M_UINT       (Group_Call_Reference_t,  call_priority,  3, &hf_group_call_reference_call_priority),
  M_UINT       (Group_Call_Reference_t,  Ciphering_information,  4, &hf_group_call_reference_ciphering_information),
CSN_DESCR_END  (Group_Call_Reference_t)

static const
CSN_DESCR_BEGIN(Group_Call_information_t)
  M_TYPE       (Group_Call_information_t, Group_Call_Reference, Group_Call_Reference_t),

  M_NEXT_EXIST (Group_Call_information_t, Exist_Group_Channel_Description, 1),
  M_TYPE       (Group_Call_information_t, Group_Channel_Description, Group_Channel_Description_t),
CSN_DESCR_END (Group_Call_information_t)

static const
CSN_DESCR_BEGIN  (P1_Rest_Octets_t)
  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_NLN_PCH_and_NLN_status, 2),
  M_UINT         (P1_Rest_Octets_t,  NLN_PCH,  2, &hf_nln_pch),
  M_UINT         (P1_Rest_Octets_t,  NLN_status,  1, &hf_nln_status),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P1_Rest_Octets_t,  Priority1,  3, &hf_priority),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P1_Rest_Octets_t,  Priority2,  3, &hf_priority),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Group_Call_information, 1),
  M_TYPE         (P1_Rest_Octets_t, Group_Call_information, Group_Call_information_t),

  M_UINT_LH      (P1_Rest_Octets_t,  Packet_Page_Indication_1,  1, &hf_p1_rest_octets_packet_page_indication_1),
  M_UINT_LH      (P1_Rest_Octets_t,  Packet_Page_Indication_2,  1, &hf_p1_rest_octets_packet_page_indication_2),
CSN_DESCR_END    (P1_Rest_Octets_t)

static const
CSN_DESCR_BEGIN  (P2_Rest_Octets_t)
  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_CN3, 1),
  M_UINT         (P2_Rest_Octets_t,  CN3,  2, &hf_p2_rest_octets_cn3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_NLN_and_status, 2),
  M_UINT         (P2_Rest_Octets_t,  NLN,  2, &hf_nln),
  M_UINT         (P2_Rest_Octets_t,  NLN_status,  1, &hf_nln_status),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority1,  3, &hf_priority),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority2,  3, &hf_priority),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority3, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority3,  3, &hf_priority),

  M_UINT_LH      (P2_Rest_Octets_t,  Packet_Page_Indication_3,  1, &hf_p2_rest_octets_packet_page_indication_3),
CSN_DESCR_END    (P2_Rest_Octets_t)


/* <IA Rest Octets>
 * Note!!
 * - first two bits skipped and frequencyparameters skipped
 * - additions for R99 and EGPRS added
 */
static const
CSN_DESCR_BEGIN(DynamicAllocation_t)
  M_UINT       (DynamicAllocation_t,  USF,  3, &hf_usf),
  M_UINT       (DynamicAllocation_t,  USF_GRANULARITY,  1, &hf_usf_granularity),

  M_NEXT_EXIST (DynamicAllocation_t, Exist_P0_PR_MODE, 2),
  M_UINT       (DynamicAllocation_t,  P0,  4, &hf_p0),
  M_UINT       (DynamicAllocation_t,  PR_MODE,  1, &hf_pr_mode),
CSN_DESCR_END  (DynamicAllocation_t)

static const
CSN_DESCR_BEGIN(EGPRS_TwoPhaseAccess_t)
  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_ALPHA, 1),
  M_UINT       (EGPRS_TwoPhaseAccess_t, ALPHA, 4, &hf_alpha),

  M_UINT       (EGPRS_TwoPhaseAccess_t, GAMMA, 5, &hf_gamma),
  M_TYPE       (EGPRS_TwoPhaseAccess_t, TBF_STARTING_TIME, StartingTime_t),
  M_UINT       (EGPRS_TwoPhaseAccess_t, NR_OF_RADIO_BLOCKS_ALLOCATED, 2, &hf_nr_of_radio_blocks_allocated),

  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (EGPRS_TwoPhaseAccess_t, P0, 4, &hf_p0),
  M_UINT       (EGPRS_TwoPhaseAccess_t, BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT       (EGPRS_TwoPhaseAccess_t, PR_MODE,  1, &hf_pr_mode),
CSN_DESCR_END  (EGPRS_TwoPhaseAccess_t)

static const
CSN_DESCR_BEGIN(EGPRS_OnePhaseAccess_t)
  M_UINT       (EGPRS_OnePhaseAccess_t,  TFI_ASSIGNMENT,  5, &hf_uplink_tfi),
  M_UINT       (EGPRS_OnePhaseAccess_t,  POLLING,  1, &hf_polling),

  M_UNION      (EGPRS_OnePhaseAccess_t, 2),
  M_TYPE       (EGPRS_OnePhaseAccess_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR    (EGPRS_OnePhaseAccess_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT       (EGPRS_OnePhaseAccess_t,  EGPRS_CHANNEL_CODING_COMMAND,  4, &hf_egprs_channel_coding_command),
  M_UINT       (EGPRS_OnePhaseAccess_t,  TLLI_BLOCK_CHANNEL_CODING,  1, &hf_tlli_block_channel_coding),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  BEP_PERIOD2, 4, &hf_bep_period2),

  M_UINT       (EGPRS_OnePhaseAccess_t,  RESEGMENT, 1, &hf_resegment),
  M_UINT       (EGPRS_OnePhaseAccess_t,  EGPRS_WindowSize,  5, &hf_egprs_windowsize),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_ALPHA, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  ALPHA, 4, &hf_alpha),

  M_UINT       (EGPRS_OnePhaseAccess_t,  GAMMA, 5, &hf_gamma),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  TIMING_ADVANCE_INDEX,  4, &hf_timing_advance_index),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE       (EGPRS_OnePhaseAccess_t, TBF_STARTING_TIME, StartingTime_t),
CSN_DESCR_END  (EGPRS_OnePhaseAccess_t)

static const
CSN_DESCR_BEGIN(IA_EGPRS_00_t)
  M_UINT       (IA_EGPRS_00_t,  ExtendedRA,  5, &hf_extendedra),

  M_REC_ARRAY  (IA_EGPRS_00_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UNION      (IA_EGPRS_00_t, 2),
  M_TYPE       (IA_EGPRS_00_t, Access.TwoPhaseAccess, EGPRS_TwoPhaseAccess_t),
  M_TYPE       (IA_EGPRS_00_t, Access.OnePhaseAccess, EGPRS_OnePhaseAccess_t),
CSN_DESCR_END  (IA_EGPRS_00_t)

static const
CSN_ChoiceElement_t IA_EGPRS_Choice[] =
{
  {2, 0x00, 0, M_TYPE   (IA_EGPRS_t, u.IA_EGPRS_PUA, IA_EGPRS_00_t)},
  {2, 0x01, 0, CSN_ERROR(IA_EGPRS_t, "01 <IA_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED)},
  {1, 0x01, 0, CSN_ERROR(IA_EGPRS_t, "1 <IA_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED)}
};

/* Please observe the double usage of UnionType element.
 * First, it is used to store the second bit of LL/LH identification of EGPRS contents.
 * Thereafter, UnionType will be used to store the index to detected choice.
 */
static const
CSN_DESCR_BEGIN(IA_EGPRS_t)
  M_UINT       (IA_EGPRS_t,  UnionType ,  1, &hf_ia_egprs_uniontype ),
  M_CHOICE     (IA_EGPRS_t, UnionType, IA_EGPRS_Choice, ElementsOf(IA_EGPRS_Choice)),
CSN_DESCR_END  (IA_EGPRS_t)

static const
CSN_DESCR_BEGIN(IA_FreqParamsBeforeTime_t)
  M_UINT       (IA_FreqParamsBeforeTime_t,  Length,  6, &hf_ia_freqparamsbeforetime_length),
  M_UINT       (IA_FreqParamsBeforeTime_t,  MAIO,  6, &hf_maio),
  M_VAR_ARRAY  (IA_FreqParamsBeforeTime_t, MobileAllocation, Length, 8),
CSN_DESCR_END  (IA_FreqParamsBeforeTime_t)

static const
CSN_DESCR_BEGIN  (GPRS_SingleBlockAllocation_t)
  M_NEXT_EXIST   (GPRS_SingleBlockAllocation_t, Exist_ALPHA, 1),
  M_UINT         (GPRS_SingleBlockAllocation_t,  ALPHA, 4, &hf_alpha),

  M_UINT         (GPRS_SingleBlockAllocation_t, GAMMA, 5, &hf_gamma),
  M_FIXED        (GPRS_SingleBlockAllocation_t, 2, 0x01),
  M_TYPE         (GPRS_SingleBlockAllocation_t, TBF_STARTING_TIME, StartingTime_t), /*bit(16)*/

  M_NEXT_EXIST_LH(GPRS_SingleBlockAllocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT         (GPRS_SingleBlockAllocation_t,  P0, 4, &hf_p0),
  M_UINT         (GPRS_SingleBlockAllocation_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT         (GPRS_SingleBlockAllocation_t,  PR_MODE, 1, &hf_pr_mode),
CSN_DESCR_END    (GPRS_SingleBlockAllocation_t)

static const
CSN_DESCR_BEGIN  (GPRS_DynamicOrFixedAllocation_t)
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TFI_ASSIGNMENT,  5, &hf_uplink_tfi),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  POLLING,  1, &hf_polling),

  M_UNION        (GPRS_DynamicOrFixedAllocation_t, 2),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR      (GPRS_DynamicOrFixedAllocation_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  CHANNEL_CODING_COMMAND, 2, &hf_gprs_channel_coding_command),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TLLI_BLOCK_CHANNEL_CODING, 1, &hf_tlli_block_channel_coding),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_ALPHA, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  ALPHA, 4, &hf_alpha),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t, GAMMA, 5, &hf_gamma),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TIMING_ADVANCE_INDEX,  4, &hf_timing_advance_index),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, TBF_STARTING_TIME, StartingTime_t),
CSN_DESCR_END    (GPRS_DynamicOrFixedAllocation_t)

static const
CSN_DESCR_BEGIN(PU_IA_AdditionsR99_t)
  M_NEXT_EXIST (PU_IA_AdditionsR99_t, Exist_ExtendedRA, 1),
  M_UINT       (PU_IA_AdditionsR99_t,  ExtendedRA, 5, &hf_extendedra),
CSN_DESCR_END  (PU_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN          (Packet_Uplink_ImmAssignment_t)
  M_UNION                (Packet_Uplink_ImmAssignment_t, 2),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.SingleBlockAllocation, GPRS_SingleBlockAllocation_t),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.DynamicOrFixedAllocation, GPRS_DynamicOrFixedAllocation_t),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Uplink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, AdditionsR99, PU_IA_AdditionsR99_t),
CSN_DESCR_END            (Packet_Uplink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN(PD_IA_AdditionsR99_t)
  M_UINT       (PD_IA_AdditionsR99_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),
  M_UINT       (PD_IA_AdditionsR99_t,  LINK_QUALITY_MEASUREMENT_MODE, 2, &hf_link_quality_measurement_mode),

  M_NEXT_EXIST (PD_IA_AdditionsR99_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (PD_IA_AdditionsR99_t,  BEP_PERIOD2, 4, &hf_bep_period2),
CSN_DESCR_END  (PD_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(Packet_Downlink_ImmAssignment_t)
  M_UINT       (Packet_Downlink_ImmAssignment_t, TLLI, 32, &hf_tlli),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TFI_to_TA_VALID, 6 + 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TFI_ASSIGNMENT, 5, &hf_downlink_tfi),

  M_UINT       (Packet_Downlink_ImmAssignment_t, RLC_MODE, 1, &hf_rlc_mode),
  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_ALPHA, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  ALPHA, 4, &hf_alpha),

  M_UINT       (Packet_Downlink_ImmAssignment_t, GAMMA, 5, &hf_gamma),
  M_UINT       (Packet_Downlink_ImmAssignment_t, POLLING, 1, &hf_polling),
  M_UINT       (Packet_Downlink_ImmAssignment_t, TA_VALID, 1, &hf_ta_valid),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TIMING_ADVANCE_INDEX, 4, &hf_timing_advance_index),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, TBF_STARTING_TIME, StartingTime_t),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_P0_PR_MODE, 3),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  P0, 4, &hf_p0),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  PR_MODE, 1, &hf_pr_mode),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Downlink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, AdditionsR99, PD_IA_AdditionsR99_t),
CSN_DESCR_END  (Packet_Downlink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN          (Second_Part_Packet_Assignment_t)
  M_NEXT_EXIST_OR_NULL_LH(Second_Part_Packet_Assignment_t, Exist_SecondPart, 2),
  M_NEXT_EXIST           (Second_Part_Packet_Assignment_t, Exist_ExtendedRA, 1),
  M_UINT                 (Second_Part_Packet_Assignment_t,  ExtendedRA, 5, &hf_extendedra),
CSN_DESCR_END            (Second_Part_Packet_Assignment_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_UL_DL_t)
  M_UNION      (IA_PacketAssignment_UL_DL_t, 2),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Uplink_ImmAssignment, Packet_Uplink_ImmAssignment_t),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Downlink_ImmAssignment, Packet_Downlink_ImmAssignment_t),
CSN_DESCR_END  (IA_PacketAssignment_UL_DL_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_t)
  M_UNION      (IA_PacketAssignment_t, 2),
  M_TYPE       (IA_PacketAssignment_t, u.UplinkDownlinkAssignment, IA_PacketAssignment_UL_DL_t),
  M_TYPE       (IA_PacketAssignment_t, u.UplinkDownlinkAssignment, Second_Part_Packet_Assignment_t),
CSN_DESCR_END  (IA_PacketAssignment_t)

/* <Packet Polling Request> */
static const
CSN_ChoiceElement_t PacketPollingID[] =
{
  {1, 0,    0, M_TYPE(PacketPollingID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketPollingID_t, u.TLLI, 32, &hf_tlli)},
  {3, 0x06, 0, M_UINT(PacketPollingID_t, u.TQI, 16, &hf_tqi)},
/*{3, 0x07 , 0, M_TYPE(PacketUplinkID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},*/
};

static const
CSN_DESCR_BEGIN(PacketPollingID_t)
  M_CHOICE     (PacketPollingID_t, UnionType, PacketPollingID, ElementsOf(PacketPollingID)),
CSN_DESCR_END  (PacketPollingID_t)

static const
CSN_DESCR_BEGIN(Packet_Polling_Request_t)
  M_UINT       (Packet_Polling_Request_t,  MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Polling_Request_t,  PAGE_MODE, 2, &hf_page_mode),
  M_TYPE       (Packet_Polling_Request_t, ID, PacketPollingID_t),
  M_UINT       (Packet_Polling_Request_t,  TYPE_OF_ACK, 1, &hf_ack_type),
  M_PADDING_BITS(Packet_Polling_Request_t),
CSN_DESCR_END  (Packet_Polling_Request_t)

static const
CSN_DESCR_BEGIN(MobileAllocation_t)
  M_UINT_OFFSET(MobileAllocation_t, MA_BitLength, 6, 1),
  M_VAR_BITMAP (MobileAllocation_t, MA_BITMAP, MA_BitLength, 0),
CSN_DESCR_END  (MobileAllocation_t)

static const
CSN_DESCR_BEGIN(ARFCN_index_list_t)
  M_REC_ARRAY  (ARFCN_index_list_t, ARFCN_INDEX, ElementsOf_ARFCN_INDEX, 6),
CSN_DESCR_END  (ARFCN_index_list_t)

static const
CSN_DESCR_BEGIN(GPRS_Mobile_Allocation_t)
  M_UINT       (GPRS_Mobile_Allocation_t, HSN, 6, &hf_hsn),
  M_REC_ARRAY  (GPRS_Mobile_Allocation_t, RFL_NUMBER, ElementsOf_RFL_NUMBER, 4),
  M_UNION      (GPRS_Mobile_Allocation_t, 2),
  M_TYPE       (GPRS_Mobile_Allocation_t, u.MA, MobileAllocation_t),
  M_TYPE       (GPRS_Mobile_Allocation_t, u.ARFCN_index_list, ARFCN_index_list_t),
CSN_DESCR_END  (GPRS_Mobile_Allocation_t)

/*< SI 13 Rest Octets >*/
static const
CSN_DESCR_BEGIN (Extension_Bits_t)
  M_UINT_OFFSET (Extension_Bits_t, extension_length, 6, 1),
  M_LEFT_VAR_BMP(Extension_Bits_t, Extension_Info, extension_length, 0),
CSN_DESCR_END   (Extension_Bits_t)

static const
CSN_DESCR_BEGIN(GPRS_Cell_Options_t)
  M_UINT       (GPRS_Cell_Options_t,  NMO,  2, &hf_gprs_cell_options_nmo),
  M_UINT       (GPRS_Cell_Options_t, T3168, 3, &hf_gprs_cell_options_t3168),
  M_UINT       (GPRS_Cell_Options_t, T3192, 3, &hf_gprs_cell_options_t3192),
  M_UINT       (GPRS_Cell_Options_t,  DRX_TIMER_MAX,  3, &hf_gprs_cell_options_drx_timer_max),
  M_UINT       (GPRS_Cell_Options_t,  ACCESS_BURST_TYPE, 1, &hf_gprs_cell_options_access_burst_type),
  M_UINT       (GPRS_Cell_Options_t,  CONTROL_ACK_TYPE, 1, &hf_ack_type),
  M_UINT       (GPRS_Cell_Options_t,  BS_CV_MAX,  4, &hf_gprs_cell_options_bs_cv_max),

  M_NEXT_EXIST (GPRS_Cell_Options_t, Exist_PAN, 3),
  M_UINT       (GPRS_Cell_Options_t,  PAN_DEC,  3, &hf_gprs_cell_options_pan_dec),
  M_UINT       (GPRS_Cell_Options_t,  PAN_INC,  3, &hf_gprs_cell_options_pan_inc),
  M_UINT       (GPRS_Cell_Options_t,  PAN_MAX,  3, &hf_gprs_cell_options_pan_max),

  M_NEXT_EXIST (GPRS_Cell_Options_t, Exist_Extension_Bits, 1),
  M_TYPE       (GPRS_Cell_Options_t, Extension_Bits, Extension_Bits_t),
CSN_DESCR_END  (GPRS_Cell_Options_t)

static const
CSN_DESCR_BEGIN(PBCCH_Not_present_t)
  M_UINT       (PBCCH_Not_present_t,  RAC, 8, &hf_rac),
  M_UINT       (PBCCH_Not_present_t,  SPGC_CCCH_SUP, 1, &hf_pbcch_not_present_spgc_ccch_sup),
  M_UINT       (PBCCH_Not_present_t,  PRIORITY_ACCESS_THR,  3, &hf_pbcch_not_present_priority_access_thr),
  M_UINT       (PBCCH_Not_present_t,  NETWORK_CONTROL_ORDER,  2, &hf_pbcch_not_present_network_control_order),
  M_TYPE       (PBCCH_Not_present_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE       (PBCCH_Not_present_t, GPRS_Power_Control_Parameters, GPRS_Power_Control_Parameters_t),
CSN_DESCR_END  (PBCCH_Not_present_t)

static const
CSN_ChoiceElement_t SI13_PBCCH_Description_Channel[] =
{/* this one is used in SI13*/
  {2, 0x00, 0, M_NULL(PBCCH_Description_t, u.dummy, 0)},/*Default to BCCH carrier*/
  {2, 0x01, 0, M_UINT(PBCCH_Description_t, u.ARFCN, 10, &hf_arfcn)},
  {1, 0x01, 0, M_UINT(PBCCH_Description_t, u.MAIO, 6, &hf_maio)},
};

static const
CSN_DESCR_BEGIN(PBCCH_Description_t)/*SI13*/
  M_UINT       (PBCCH_Description_t,  Pb,  4, &hf_pbcch_description_pb),
  M_UINT       (PBCCH_Description_t,  TSC, 3, &hf_tsc),
  M_UINT       (PBCCH_Description_t,  TN,  3, &hf_pbcch_description_tn),

  M_CHOICE     (PBCCH_Description_t, UnionType, SI13_PBCCH_Description_Channel, ElementsOf(SI13_PBCCH_Description_Channel)),
CSN_DESCR_END  (PBCCH_Description_t)

static const
CSN_DESCR_BEGIN(PBCCH_present_t)
  M_UINT       (PBCCH_present_t,  PSI1_REPEAT_PERIOD,  4, &hf_pbcch_present_psi1_repeat_period),
  M_TYPE       (PBCCH_present_t, PBCCH_Description, PBCCH_Description_t),
CSN_DESCR_END  (PBCCH_present_t)

static const
CSN_DESCR_BEGIN(SI13_AdditionsR6)
  M_NEXT_EXIST (SI13_AdditionsR6, Exist_LB_MS_TXPWR_MAX_CCH, 1),
  M_UINT       (SI13_AdditionsR6,  LB_MS_TXPWR_MAX_CCH,  5, &hf_packet_system_info_type13_lb_ms_mxpwr_max_cch),
  M_UINT       (SI13_AdditionsR6,  SI2n_SUPPORT,  2, &hf_packet_system_info_type13_si2n_support),
CSN_DESCR_END  (SI13_AdditionsR6)

static const
CSN_DESCR_BEGIN(SI13_AdditionsR4)
  M_UINT       (SI13_AdditionsR4,  SI_STATUS_IND, 1, &hf_si_status_ind),
  M_NEXT_EXIST_OR_NULL_LH (SI13_AdditionsR4, Exist_AdditionsR6, 1),
  M_TYPE       (SI13_AdditionsR4,  AdditionsR6, SI13_AdditionsR6),
CSN_DESCR_END  (SI13_AdditionsR4)

static const
CSN_DESCR_BEGIN(SI13_AdditionR99)
  M_UINT       (SI13_AdditionR99,  SGSNR, 1, &hf_sgsnr),
  M_NEXT_EXIST_OR_NULL_LH (SI13_AdditionR99, Exist_AdditionsR4, 1),
  M_TYPE       (SI13_AdditionR99,  AdditionsR4, SI13_AdditionsR4),
CSN_DESCR_END  (SI13_AdditionR99)

static const
CSN_DESCR_BEGIN          (SI_13_t)
  M_THIS_EXIST_LH        (SI_13_t),

  M_UINT                 (SI_13_t,  BCCH_CHANGE_MARK, 3, &hf_bcch_change_mark),
  M_UINT                 (SI_13_t,  SI_CHANGE_FIELD, 4, &hf_si_change_field),

  M_NEXT_EXIST           (SI_13_t, Exist_MA, 2),
  M_UINT                 (SI_13_t,  SI13_CHANGE_MARK, 2, &hf_si13_change_mark),
  M_TYPE                 (SI_13_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),

  M_UNION                (SI_13_t, 2),
  M_TYPE                 (SI_13_t, u.PBCCH_Not_present, PBCCH_Not_present_t),
  M_TYPE                 (SI_13_t, u.PBCCH_present, PBCCH_present_t),

  M_NEXT_EXIST_OR_NULL_LH(SI_13_t, Exist_AdditionsR99, 1),
  M_TYPE                 (SI_13_t, AdditionsR99, SI13_AdditionR99),
CSN_DESCR_END            (SI_13_t)

/************************************************************/
/*                         TS 44.060 messages               */
/************************************************************/

/*< Packet TBF Release message content >*/
static const
CSN_DESCR_BEGIN(Packet_TBF_Release_t)
  M_UINT       (Packet_TBF_Release_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_TBF_Release_t, PAGE_MODE, 2, &hf_page_mode),
  M_FIXED      (Packet_TBF_Release_t, 1, 0x00),
  M_TYPE       (Packet_TBF_Release_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_TBF_Release_t, UPLINK_RELEASE, 1, &hf_packetbf_release_uplink_release),
  M_UINT       (Packet_TBF_Release_t, DOWNLINK_RELEASE, 1, &hf_packetbf_release_downlink_release),
  M_UINT       (Packet_TBF_Release_t, TBF_RELEASE_CAUSE, 4, &hf_packetbf_release_tbf_release_cause),
  M_PADDING_BITS(Packet_TBF_Release_t ),
CSN_DESCR_END  (Packet_TBF_Release_t)

/*< Packet Control Acknowledgement message content >*/

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_AdditionsR6_t)
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR6_t, Exist_CTRL_ACK_Extension, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR6_t,  CTRL_ACK_Extension,  9, &hf_packet_control_acknowledgement_additionsr6_ctrl_ack_extension),
CSN_DESCR_END          (Packet_Control_Acknowledgement_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_AdditionsR5_t)
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_TN_RRBP, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR5_t,  TN_RRBP,  3, &hf_packet_control_acknowledgement_additionsr5_tn_rrbp),
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_G_RNTI_Extension, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR5_t,  G_RNTI_Extension,  4, &hf_packet_control_acknowledgement_additionsr5_g_rnti_extension),

  M_NEXT_EXIST_OR_NULL (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_AdditionsR6, 1),
  M_TYPE               (Packet_Control_Acknowledgement_AdditionsR5_t, AdditionsR6, Packet_Control_Acknowledgement_AdditionsR6_t),
CSN_DESCR_END          (Packet_Control_Acknowledgement_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_t)
  M_UINT               (Packet_Control_Acknowledgement_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT               (Packet_Control_Acknowledgement_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT               (Packet_Control_Acknowledgement_t,  R, 1, &hf_ul_retry),

  M_UINT               (Packet_Control_Acknowledgement_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  M_UINT               (Packet_Control_Acknowledgement_t,  TLLI, 32, &hf_tlli),
  M_UINT               (Packet_Control_Acknowledgement_t,  CTRL_ACK,  2, &hf_packet_control_acknowledgement_ctrl_ack),
  M_NEXT_EXIST_OR_NULL (Packet_Control_Acknowledgement_t, Exist_AdditionsR5, 1),
  M_TYPE               (Packet_Control_Acknowledgement_t, AdditionsR5, Packet_Control_Acknowledgement_AdditionsR5_t),

  M_PADDING_BITS       (Packet_Control_Acknowledgement_t),
CSN_DESCR_END  (Packet_Control_Acknowledgement_t)

/*< Packet Downlink Dummy Control Block message content >*/
static const
CSN_DESCR_BEGIN(Packet_Downlink_Dummy_Control_Block_t)
  M_UINT       (Packet_Downlink_Dummy_Control_Block_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Downlink_Dummy_Control_Block_t, PAGE_MODE, 2, &hf_page_mode),

  M_NEXT_EXIST (Packet_Downlink_Dummy_Control_Block_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (Packet_Downlink_Dummy_Control_Block_t, PERSISTENCE_LEVEL, 4, 4),

  M_PADDING_BITS(Packet_Downlink_Dummy_Control_Block_t ),
CSN_DESCR_END  (Packet_Downlink_Dummy_Control_Block_t)

/*< Packet Uplink Dummy Control Block message content >*/
static const
CSN_DESCR_BEGIN(Packet_Uplink_Dummy_Control_Block_t)
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, PayloadType, 2, &hf_ul_payload_type),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, spare, 5, &hf_ul_mac_header_spare),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, R, 1, &hf_ul_retry),

  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, MESSAGE_TYPE, 6, &hf_ul_message_type),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t,  TLLI,  32, &hf_tlli),
/*M_FIXED      (Packet_Uplink_Dummy_Control_Block_t, 1, 0),*/
  M_PADDING_BITS(Packet_Uplink_Dummy_Control_Block_t),
CSN_DESCR_END  (Packet_Uplink_Dummy_Control_Block_t)

static const
CSN_DESCR_BEGIN(Receive_N_PDU_Number_t)
  M_UINT       (Receive_N_PDU_Number_t,  nsapi,  4, &hf_receive_n_pdu_number_nsapi),
  M_UINT       (Receive_N_PDU_Number_t,  value,  8, &hf_receive_n_pdu_number_value),
CSN_DESCR_END  (Receive_N_PDU_Number_t)

gint16 Receive_N_PDU_Number_list_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(Receive_N_PDU_Number_t), tvb, data, ett_gsm_rlcmac);
}

static const
CSN_DESCR_BEGIN(Receive_N_PDU_Number_list_t)
  M_SERIALIZE  (Receive_N_PDU_Number_list_t, IEI, 7, Receive_N_PDU_Number_list_Dissector),
  M_VAR_TARRAY (Receive_N_PDU_Number_list_t, Receive_N_PDU_Number, Receive_N_PDU_Number_t, Count_Receive_N_PDU_Number),
CSN_DESCR_END  (Receive_N_PDU_Number_list_t)

/*< MS Radio Access capability IE >*/
static const
CSN_DESCR_BEGIN       (DTM_EGPRS_t)
  M_NEXT_EXIST        (DTM_EGPRS_t, Exist_DTM_EGPRS_multislot_class, 1),
  M_UINT              (DTM_EGPRS_t,  DTM_EGPRS_multislot_class,  2, &hf_dtm_egprs_dtm_egprs_multislot_class),
CSN_DESCR_END         (DTM_EGPRS_t)

static const
CSN_DESCR_BEGIN       (DTM_EGPRS_HighMultislotClass_t)
  M_NEXT_EXIST        (DTM_EGPRS_HighMultislotClass_t, Exist_DTM_EGPRS_HighMultislotClass, 1),
  M_UINT              (DTM_EGPRS_HighMultislotClass_t,  DTM_EGPRS_HighMultislotClass,  3, &hf_dtm_egprs_highmultislotclass_dtm_egprs_highmultislotclass),
CSN_DESCR_END         (DTM_EGPRS_HighMultislotClass_t)

static const
CSN_DESCR_BEGIN       (Multislot_capability_t)
  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_HSCSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t,  HSCSD_multislot_class,  5, &hf_multislot_capability_hscsd_multislot_class),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_GPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t,  GPRS_multislot_class,  5, &hf_multislot_capability_gprs_multislot_class),
  M_UINT              (Multislot_capability_t,  GPRS_Extended_Dynamic_Allocation_Capability,  1, &hf_multislot_capability_gprs_extended_dynamic_allocation_capability),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_SM, 2),
  M_UINT              (Multislot_capability_t,  SMS_VALUE,  4, &hf_multislot_capability_sms_value),
  M_UINT              (Multislot_capability_t,  SM_VALUE,  4, &hf_multislot_capability_sm_value),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_ECSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t,  ECSD_multislot_class,  5, &hf_multislot_capability_ecsd_multislot_class),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_EGPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t,  EGPRS_multislot_class,  5, &hf_multislot_capability_egprs_multislot_class),
  M_UINT              (Multislot_capability_t,  EGPRS_Extended_Dynamic_Allocation_Capability,  1, &hf_multislot_capability_egprs_extended_dynamic_allocation_capability),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT              (Multislot_capability_t,  DTM_GPRS_multislot_class,  2, &hf_multislot_capability_dtm_gprs_multislot_class),
  M_UINT              (Multislot_capability_t,  Single_Slot_DTM,  1, &hf_multislot_capability_single_slot_dtm),
  M_TYPE              (Multislot_capability_t, DTM_EGPRS_Params, DTM_EGPRS_t),
CSN_DESCR_END         (Multislot_capability_t)

static const
CSN_DESCR_BEGIN       (Content_t)
  M_UINT              (Content_t,  RF_Power_Capability,  3, &hf_content_rf_power_capability),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_A5_bits, 1),
  M_UINT_OR_NULL      (Content_t,  A5_bits,  7, &hf_content_a5_bits),

  M_UINT_OR_NULL      (Content_t,  ES_IND,  1, &hf_content_es_ind),
  M_UINT_OR_NULL      (Content_t,  PS,  1, &hf_content_ps),
  M_UINT_OR_NULL      (Content_t,  VGCS,  1, &hf_content_vgcs),
  M_UINT_OR_NULL      (Content_t,  VBS,  1, &hf_content_vbs),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_Multislot_capability, 1),
  M_TYPE              (Content_t, Multislot_capability, Multislot_capability_t),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_Eight_PSK_Power_Capability, 1),
  M_UINT              (Content_t,  Eight_PSK_Power_Capability,  2, &hf_content_eight_psk_power_capability),

  M_UINT_OR_NULL      (Content_t,  COMPACT_Interference_Measurement_Capability,  1, &hf_content_compact_interference_measurement_capability),
  M_UINT_OR_NULL      (Content_t,  Revision_Level_Indicator,  1, &hf_content_revision_level_indicator),
  M_UINT_OR_NULL      (Content_t,  UMTS_FDD_Radio_Access_Technology_Capability,  1, &hf_content_umts_fdd_radio_access_technology_capability),
  M_UINT_OR_NULL      (Content_t,  UMTS_384_TDD_Radio_Access_Technology_Capability,  1, &hf_content_umts_384_tdd_radio_access_technology_capability),
  M_UINT_OR_NULL      (Content_t,  CDMA2000_Radio_Access_Technology_Capability,  1, &hf_content_cdma2000_radio_access_technology_capability),

  M_UINT_OR_NULL      (Content_t,  UMTS_128_TDD_Radio_Access_Technology_Capability,  1, &hf_content_umts_128_tdd_radio_access_technology_capability),
  M_UINT_OR_NULL      (Content_t,  GERAN_Feature_Package_1,  1, &hf_content_geran_feature_package_1),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_Extended_DTM_multislot_class, 2),
  M_UINT              (Content_t,  Extended_DTM_GPRS_multislot_class,  2, &hf_content_extended_dtm_gprs_multislot_class),
  M_UINT              (Content_t,  Extended_DTM_EGPRS_multislot_class,  2, &hf_content_extended_dtm_egprs_multislot_class),

  M_UINT_OR_NULL      (Content_t,  Modulation_based_multislot_class_support,  1, &hf_content_modulation_based_multislot_class_support),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_HighMultislotCapability, 1),
  M_UINT              (Content_t,  HighMultislotCapability,  2, &hf_content_highmultislotcapability),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_GERAN_lu_ModeCapability, 1),
  M_UINT              (Content_t,  GERAN_lu_ModeCapability,  4, &hf_content_geran_lu_modecapability),

  M_UINT_OR_NULL      (Content_t,  GMSK_MultislotPowerProfile,  2, &hf_content_gmsk_multislotpowerprofile),
  M_UINT_OR_NULL      (Content_t,  EightPSK_MultislotProfile,  2, &hf_content_eightpsk_multislotprofile),

  M_UINT_OR_NULL      (Content_t,  MultipleTBF_Capability,  1, &hf_content_multipletbf_capability),
  M_UINT_OR_NULL      (Content_t,  DownlinkAdvancedReceiverPerformance,  2, &hf_content_downlinkadvancedreceiverperformance),
  M_UINT_OR_NULL      (Content_t,  ExtendedRLC_MAC_ControlMessageSegmentionsCapability,  1, &hf_content_extendedrlc_mac_controlmessagesegmentionscapability),
  M_UINT_OR_NULL      (Content_t,  DTM_EnhancementsCapability,  1, &hf_content_dtm_enhancementscapability),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_DTM_GPRS_HighMultislotClass, 2),
  M_UINT              (Content_t,  DTM_GPRS_HighMultislotClass,  3, &hf_content_dtm_gprs_highmultislotclass),
  M_TYPE              (Content_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT_OR_NULL      (Content_t,  PS_HandoverCapability,  1, &hf_content_ps_handovercapability),
CSN_DESCR_END         (Content_t)

gint16 Content_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(Content_t), tvb, data, ett_gsm_rlcmac);
}

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_struct_t)
  M_UINT              (Additional_access_technologies_struct_t,  Access_Technology_Type,  4, &hf_additional_accessechnologies_struct_t_access_technology_type),
  M_UINT              (Additional_access_technologies_struct_t,  GMSK_Power_class,  3, &hf_additional_accessechnologies_struct_t_gmsk_power_class),
  M_UINT              (Additional_access_technologies_struct_t,  Eight_PSK_Power_class,  2, &hf_additional_accessechnologies_struct_t_eight_psk_power_class),
CSN_DESCR_END         (Additional_access_technologies_struct_t)

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_t)
  M_REC_TARRAY        (Additional_access_technologies_t, Additional_access_technologies[0], Additional_access_technologies_struct_t, Count_additional_access_technologies),
CSN_DESCR_END         (Additional_access_technologies_t)

gint16 Additional_access_technologies_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(Additional_access_technologies_t), tvb, data, ett_gsm_rlcmac);
}

static const
CSN_ChoiceElement_t MS_RA_capability_value_Choice[] =
{
  {4, AccTech_GSMP,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSME,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1800,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1900,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM850,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMOther, 0, M_SERIALIZE (MS_RA_capability_value_t, u.Additional_access_technologies, 7, Additional_access_technologies_Dissector)}, /* Short Form */
};

static const
CSN_DESCR_BEGIN(MS_RA_capability_value_t)
  M_CHOICE     (MS_RA_capability_value_t, IndexOfAccTech, MS_RA_capability_value_Choice, ElementsOf(MS_RA_capability_value_Choice)),
CSN_DESCR_END  (MS_RA_capability_value_t)

static const
CSN_DESCR_BEGIN (MS_Radio_Access_capability_t)
/*Will be done in the main routines:*/
/*M_UINT        (MS_Radio_Access_capability_t,  IEI,  8, &hf_ms_radio_access_capability_iei),*/
/*M_UINT        (MS_Radio_Access_capability_t,  Length,  8, &hf_ms_radio_access_capability_length),*/

  M_REC_TARRAY_1(MS_Radio_Access_capability_t, MS_RA_capability_value, MS_RA_capability_value_t, Count_MS_RA_capability_value),
CSN_DESCR_END   (MS_Radio_Access_capability_t)

/*< MS Classmark 3 IE >*/
static const
CSN_DESCR_BEGIN(ARC_t)
  M_UINT       (ARC_t,  A5_Bits,  4, &hf_arc_a5_bits),
  M_UINT       (ARC_t,  Arc2_Spare,  4, &hf_arc_arc2_spare),
  M_UINT       (ARC_t,  Arc1,  4, &hf_arc_arc1),
CSN_DESCR_END  (ARC_t)

static const
CSN_ChoiceElement_t MultibandChoice[] =
{
  {3, 0x00, 0, M_UINT(Multiband_t, u.A5_Bits, 4, &hf_multiband_a5_bits)},
  {3, 0x05, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x06, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x01, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x02, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x04, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
};

static const
CSN_DESCR_BEGIN(Multiband_t)
  M_CHOICE     (Multiband_t, Multiband, MultibandChoice, ElementsOf(MultibandChoice)),
CSN_DESCR_END  (Multiband_t)

static const
CSN_DESCR_BEGIN(EDGE_RF_Pwr_t)
  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap1, 1),
  M_UINT       (EDGE_RF_Pwr_t,  EDGE_RF_PwrCap1,  2, &hf_edge_rf_pwr_edge_rf_pwrcap1),

  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap2, 1),
  M_UINT       (EDGE_RF_Pwr_t,  EDGE_RF_PwrCap2,  2, &hf_edge_rf_pwr_edge_rf_pwrcap2),
CSN_DESCR_END  (EDGE_RF_Pwr_t)

static const
CSN_DESCR_BEGIN(MS_Class3_Unpacked_t)
  M_UINT       (MS_Class3_Unpacked_t,  Spare1,  1, &hf_ms_class3_unpacked_spare1),
  M_TYPE       (MS_Class3_Unpacked_t, Multiband, Multiband_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_R_Support, 1),
  M_UINT       (MS_Class3_Unpacked_t,  R_GSM_Arc,  3, &hf_ms_class3_unpacked_r_gsm_arc),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  MultiSlotClass,  5, &hf_ms_class3_unpacked_multislotclass),

  M_UINT       (MS_Class3_Unpacked_t,  UCS2,  1, &hf_ms_class3_unpacked_ucs2),
  M_UINT       (MS_Class3_Unpacked_t,  ExtendedMeasurementCapability,  1, &hf_ms_class3_unpacked_extendedmeasurementcapability),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_MeasurementCapability, 2),
  M_UINT       (MS_Class3_Unpacked_t,  SMS_VALUE,  4, &hf_ms_class3_unpacked_sms_value),
  M_UINT       (MS_Class3_Unpacked_t,  SM_VALUE,  4, &hf_ms_class3_unpacked_sm_value),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_PositioningMethodCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  MS_PositioningMethod,  5, &hf_ms_class3_unpacked_ms_positioningmethod),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  EDGE_MultiSlotClass,  5, &hf_ms_class3_unpacked_edge_multislotclass),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_Struct, 2),
  M_UINT       (MS_Class3_Unpacked_t,  ModulationCapability,  1, &hf_ms_class3_unpacked_modulationcapability),
  M_TYPE       (MS_Class3_Unpacked_t, EDGE_RF_PwrCaps, EDGE_RF_Pwr_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM400_Info, 2),
  M_UINT       (MS_Class3_Unpacked_t,  GSM400_Bands,  2, &hf_ms_class3_unpacked_gsm400_bands),
  M_UINT       (MS_Class3_Unpacked_t,  GSM400_Arc,  4, &hf_ms_class3_unpacked_gsm400_arc),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM850_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM850_Arc,  4, &hf_ms_class3_unpacked_gsm850_arc),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_PCS1900_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t,  PCS1900_Arc,  4, &hf_ms_class3_unpacked_pcs1900_arc),

  M_UINT       (MS_Class3_Unpacked_t,  UMTS_FDD_Radio_Access_Technology_Capability,  1, &hf_ms_class3_unpacked_umts_fdd_radio_access_technology_capability),
  M_UINT       (MS_Class3_Unpacked_t,  UMTS_384_TDD_Radio_Access_Technology_Capability,  1, &hf_ms_class3_unpacked_umts_384_tdd_radio_access_technology_capability),
  M_UINT       (MS_Class3_Unpacked_t,  CDMA2000_Radio_Access_Technology_Capability,  1, &hf_ms_class3_unpacked_cdma2000_radio_access_technology_capability),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_GPRS_multislot_class,  2, &hf_ms_class3_unpacked_dtm_gprs_multislot_class),
  M_UINT       (MS_Class3_Unpacked_t,  Single_Slot_DTM,  1, &hf_ms_class3_unpacked_single_slot_dtm),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_Params, DTM_EGPRS_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_SingleBandSupport, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM_Band,  4, &hf_ms_class3_unpacked_gsm_band),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM_700_Associated_Radio_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM_700_Associated_Radio_Capability,  4, &hf_ms_class3_unpacked_gsm_700_associated_radio_capability),

  M_UINT       (MS_Class3_Unpacked_t,  UMTS_128_TDD_Radio_Access_Technology_Capability,  1, &hf_ms_class3_unpacked_umts_128_tdd_radio_access_technology_capability),
  M_UINT       (MS_Class3_Unpacked_t,  GERAN_Feature_Package_1,  1, &hf_ms_class3_unpacked_geran_feature_package_1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_Extended_DTM_multislot_class, 2),
  M_UINT       (MS_Class3_Unpacked_t,  Extended_DTM_GPRS_multislot_class,  2, &hf_ms_class3_unpacked_extended_dtm_gprs_multislot_class),
  M_UINT       (MS_Class3_Unpacked_t,  Extended_DTM_EGPRS_multislot_class,  2, &hf_ms_class3_unpacked_extended_dtm_egprs_multislot_class),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_HighMultislotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  HighMultislotCapability,  2, &hf_ms_class3_unpacked_highmultislotcapability),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GERAN_lu_ModeCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GERAN_lu_ModeCapability,  4, &hf_ms_class3_unpacked_geran_lu_modecapability),

  M_UINT       (MS_Class3_Unpacked_t,  GERAN_FeaturePackage_2,  1, &hf_ms_class3_unpacked_geran_featurepackage_2),

  M_UINT       (MS_Class3_Unpacked_t,  GMSK_MultislotPowerProfile,  2, &hf_ms_class3_unpacked_gmsk_multislotpowerprofile),
  M_UINT       (MS_Class3_Unpacked_t,  EightPSK_MultislotProfile,  2, &hf_ms_class3_unpacked_eightpsk_multislotprofile),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_400_Bands, 2),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_400_BandsSupported,  2, &hf_ms_class3_unpacked_tgsm_400_bandssupported),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_400_AssociatedRadioCapability,  4, &hf_ms_class3_unpacked_tgsm_400_associatedradiocapability),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_900_AssociatedRadioCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_900_AssociatedRadioCapability,  4, &hf_ms_class3_unpacked_tgsm_900_associatedradiocapability),

  M_UINT       (MS_Class3_Unpacked_t,  DownlinkAdvancedReceiverPerformance,  2, &hf_ms_class3_unpacked_downlinkadvancedreceiverperformance),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_EnhancementsCapability,  1, &hf_ms_class3_unpacked_dtm_enhancementscapability),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_HighMultislotClass, 3),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_GPRS_HighMultislotClass,  3, &hf_ms_class3_unpacked_dtm_gprs_highmultislotclass),
  M_UINT       (MS_Class3_Unpacked_t,  OffsetRequired,  1, &hf_ms_class3_unpacked_offsetrequired),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT       (MS_Class3_Unpacked_t,  RepeatedSACCH_Capability,  1, &hf_ms_class3_unpacked_repeatedsacch_capability),
  M_UINT       (MS_Class3_Unpacked_t,  Spare2,  1, &hf_ms_class3_unpacked_spare2),
CSN_DESCR_END  (MS_Class3_Unpacked_t)

static const
CSN_DESCR_BEGIN(Channel_Request_Description_t)
  M_UINT       (Channel_Request_Description_t,  PEAK_THROUGHPUT_CLASS,  4, &hf_channel_request_description_peak_throughput_class),
  M_UINT       (Channel_Request_Description_t,  RADIO_PRIORITY,  2, &hf_channel_request_description_radio_priority),
  M_UINT       (Channel_Request_Description_t,  RLC_MODE, 1, &hf_rlc_mode),
  M_UINT       (Channel_Request_Description_t,  LLC_PDU_TYPE, 1, &hf_channel_request_description_llc_pdu_type),
  M_UINT       (Channel_Request_Description_t,  RLC_OCTET_COUNT,  16, &hf_channel_request_description_rlc_octet_count),
CSN_DESCR_END  (Channel_Request_Description_t)

/* < Packet Resource Request message content > */
static const
CSN_ChoiceElement_t PacketResourceRequestID[] =
{
  {1, 0,    0, M_TYPE(PacketResourceRequestID_t, u.Global_TFI, Global_TFI_t)},
  {1, 0x01, 0, M_UINT(PacketResourceRequestID_t, u.TLLI, 32, &hf_tlli)},
};

static const
CSN_DESCR_BEGIN(PacketResourceRequestID_t)
  M_CHOICE     (PacketResourceRequestID_t, UnionType, PacketResourceRequestID, ElementsOf(PacketResourceRequestID)),
CSN_DESCR_END  (PacketResourceRequestID_t)

static const
CSN_DESCR_BEGIN(BEP_MeasurementReport_t)
  M_NEXT_EXIST (BEP_MeasurementReport_t, Exist, 3),
  M_UNION      (BEP_MeasurementReport_t, 2),
  M_UINT       (BEP_MeasurementReport_t,  u.MEAN_BEP_GMSK,  4, &hf_bep_measurementreport_mean_bep_gmsk),
  M_UINT       (BEP_MeasurementReport_t,  u.MEAN_BEP_8PSK,  4, &hf_bep_measurementreport_mean_bep_8psk),
CSN_DESCR_END  (BEP_MeasurementReport_t)

static const
CSN_DESCR_BEGIN(InterferenceMeasurementReport_t)
  M_NEXT_EXIST (InterferenceMeasurementReport_t, Exist, 1),
  M_UINT       (InterferenceMeasurementReport_t,  I_LEVEL,  4, &hf_interferencemeasurementreport_i_level),
CSN_DESCR_END  (InterferenceMeasurementReport_t)

static const
CSN_DESCR_BEGIN(EGPRS_TimeslotLinkQualityMeasurements_t)
  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_t, Exist_BEP_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_t, BEP_MEASUREMENTS, BEP_MeasurementReport_t, 8),

  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_t, Exist_INTERFERENCE_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_t, INTERFERENCE_MEASUREMENTS, InterferenceMeasurementReport_t, 8),
CSN_DESCR_END  (EGPRS_TimeslotLinkQualityMeasurements_t)

static const
CSN_DESCR_BEGIN(EGPRS_BEP_LinkQualityMeasurements_t)
  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_t, Exist_MEAN_CV_BEP_GMSK, 2),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  MEAN_BEP_GMSK,  5, &hf_egprs_bep_linkqualitymeasurements_mean_bep_gmsk),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  CV_BEP_GMSK,  3, &hf_egprs_bep_linkqualitymeasurements_cv_bep_gmsk),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_t, Exist_MEAN_CV_BEP_8PSK, 2),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  MEAN_BEP_8PSK,  5, &hf_egprs_bep_linkqualitymeasurements_mean_bep_8psk),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t,  CV_BEP_8PSK,  3, &hf_egprs_bep_linkqualitymeasurements_cv_bep_8psk),
CSN_DESCR_END  (EGPRS_BEP_LinkQualityMeasurements_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR99_t)
  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_EGPRS_BEP_LinkQualityMeasurements, 1),
  M_TYPE       (PRR_AdditionsR99_t, EGPRS_BEP_LinkQualityMeasurements, EGPRS_BEP_LinkQualityMeasurements_t),

  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_EGPRS_TimeslotLinkQualityMeasurements, 1),
  M_TYPE       (PRR_AdditionsR99_t, EGPRS_TimeslotLinkQualityMeasurements, EGPRS_TimeslotLinkQualityMeasurements_t),

  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_PFI, 1),
  M_UINT       (PRR_AdditionsR99_t,  PFI, 7, &hf_pfi),

  M_UINT       (PRR_AdditionsR99_t,  MS_RAC_AdditionalInformationAvailable,  1, &hf_prr_additionsr99_ms_rac_additionalinformationavailable),
  M_UINT       (PRR_AdditionsR99_t,  RetransmissionOfPRR,  1, &hf_prr_additionsr99_retransmissionofprr),
CSN_DESCR_END  (PRR_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Resource_Request_t)
  /* Mac header */
  M_UINT              (Packet_Resource_Request_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT              (Packet_Resource_Request_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT              (Packet_Resource_Request_t,  R, 1, &hf_ul_retry),
  M_UINT              (Packet_Resource_Request_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_ACCESS_TYPE, 1),
  M_UINT              (Packet_Resource_Request_t,  ACCESS_TYPE,  2, &hf_packet_resource_request_access_type),

  M_TYPE              (Packet_Resource_Request_t, ID, PacketResourceRequestID_t),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_MS_Radio_Access_capability, 1),
  M_TYPE              (Packet_Resource_Request_t, MS_Radio_Access_capability, MS_Radio_Access_capability_t),

  M_TYPE              (Packet_Resource_Request_t, Channel_Request_Description, Channel_Request_Description_t),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_CHANGE_MARK, 1),
  M_UINT              (Packet_Resource_Request_t,  CHANGE_MARK,  2, &hf_packet_resource_request_change_mark),

  M_UINT              (Packet_Resource_Request_t,  C_VALUE,  6, &hf_packet_resource_request_c_value),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_SIGN_VAR, 1),
  M_UINT              (Packet_Resource_Request_t,  SIGN_VAR,  6, &hf_packet_resource_request_sign_var),

  M_TYPE_ARRAY        (Packet_Resource_Request_t, Slot, InterferenceMeasurementReport_t, 8),

  M_NEXT_EXIST_OR_NULL(Packet_Resource_Request_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Resource_Request_t, AdditionsR99, PRR_AdditionsR99_t),

   M_PADDING_BITS     (Packet_Resource_Request_t),
CSN_DESCR_END         (Packet_Resource_Request_t)

/*< Packet Mobile TBF Status message content > */
static const
CSN_DESCR_BEGIN(Packet_Mobile_TBF_Status_t)
  /* Mac header */
  M_UINT       (Packet_Mobile_TBF_Status_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT       (Packet_Mobile_TBF_Status_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT       (Packet_Mobile_TBF_Status_t,  R, 1, &hf_ul_retry),
  M_UINT       (Packet_Mobile_TBF_Status_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_TYPE       (Packet_Mobile_TBF_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_Mobile_TBF_Status_t,  TBF_CAUSE,  3, &hf_packet_mobile_tbf_status_tbf_cause),

  M_NEXT_EXIST (Packet_Mobile_TBF_Status_t, Exist_STATUS_MESSAGE_TYPE, 1),
  M_UINT       (Packet_Mobile_TBF_Status_t,  STATUS_MESSAGE_TYPE, 6, &hf_dl_message_type),

  M_PADDING_BITS(Packet_Mobile_TBF_Status_t),
CSN_DESCR_END  (Packet_Mobile_TBF_Status_t)

/*< Packet PSI Status message content > */
static const
CSN_DESCR_BEGIN(PSI_Message_t)
  M_UINT       (PSI_Message_t, PSI_MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (PSI_Message_t,  PSIX_CHANGE_MARK,  2, &hf_psi_message_psix_change_mark),
  M_NEXT_EXIST (PSI_Message_t, Exist_PSIX_COUNT_and_Instance_Bitmap, 2),
  M_FIXED      (PSI_Message_t, 4, 0),   /* Placeholder for PSIX_COUNT (4 bits) */
  M_FIXED      (PSI_Message_t, 1, 0),   /* Placeholder for Instance bitmap (1 bit) */
CSN_DESCR_END  (PSI_Message_t)

static const
CSN_DESCR_BEGIN(PSI_Message_List_t)
  M_REC_TARRAY (PSI_Message_List_t, PSI_Message[0], PSI_Message_t, Count_PSI_Message),
  M_FIXED      (PSI_Message_List_t, 1, 0x00),
  M_UINT       (PSI_Message_List_t, ADDITIONAL_MSG_TYPE, 1, &hf_additional_msg_type),
CSN_DESCR_END  (PSI_Message_List_t)

static const
CSN_DESCR_BEGIN(Unknown_PSI_Message_List_t)
  M_FIXED      (Unknown_PSI_Message_List_t, 1, 0x00),
  M_UINT       (Unknown_PSI_Message_List_t,  ADDITIONAL_MSG_TYPE, 1, &hf_dl_message_type),
CSN_DESCR_END  (Unknown_PSI_Message_List_t)

static const
CSN_DESCR_BEGIN(Packet_PSI_Status_t)
  /* Mac header */
  M_UINT       (Packet_PSI_Status_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT       (Packet_PSI_Status_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT       (Packet_PSI_Status_t,  R, 1, &hf_ul_retry),
  M_UINT       (Packet_PSI_Status_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_TYPE       (Packet_PSI_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_PSI_Status_t,  PBCCH_CHANGE_MARK,  3, &hf_packet_psi_status_pbcch_change_mark),
  M_TYPE       (Packet_PSI_Status_t, PSI_Message_List, PSI_Message_List_t),
  M_TYPE       (Packet_PSI_Status_t, Unknown_PSI_Message_List, Unknown_PSI_Message_List_t),
  M_PADDING_BITS(Packet_PSI_Status_t),
CSN_DESCR_END  (Packet_PSI_Status_t)

/* < Packet SI Status message content > */

static const
CSN_DESCR_BEGIN(SI_Message_t)
  M_UINT       (SI_Message_t,  SI_MESSAGE_TYPE, 8, &hf_dl_message_type),
  M_UINT       (SI_Message_t,  MESS_REC,  2, &hf_si_message_mess_rec),
CSN_DESCR_END  (SI_Message_t)

static const
CSN_DESCR_BEGIN(SI_Message_List_t)
  M_REC_TARRAY (SI_Message_List_t, SI_Message[0], SI_Message_t, Count_SI_Message),
  M_FIXED      (SI_Message_List_t, 1, 0x00),
  M_UINT       (SI_Message_List_t, ADDITIONAL_MSG_TYPE, 1, &hf_additional_msg_type),
CSN_DESCR_END  (SI_Message_List_t)

static const
CSN_DESCR_BEGIN(Unknown_SI_Message_List_t)
  M_FIXED      (Unknown_SI_Message_List_t, 1, 0x00),
  M_UINT       (Unknown_SI_Message_List_t, ADDITIONAL_MSG_TYPE, 1, &hf_additional_msg_type),
CSN_DESCR_END  (Unknown_SI_Message_List_t)

static const
CSN_DESCR_BEGIN(Packet_SI_Status_t)
  /* Mac header */
  M_UINT       (Packet_SI_Status_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT       (Packet_SI_Status_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT       (Packet_SI_Status_t,  R, 1, &hf_ul_retry),
  M_UINT       (Packet_SI_Status_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_TYPE       (Packet_SI_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_SI_Status_t, BCCH_CHANGE_MARK,  3, &hf_bcch_change_mark),
  M_TYPE       (Packet_SI_Status_t, SI_Message_List, SI_Message_List_t),
  M_TYPE       (Packet_SI_Status_t, Unknown_SI_Message_List, Unknown_SI_Message_List_t),
  M_PADDING_BITS(Packet_SI_Status_t),
CSN_DESCR_END  (Packet_SI_Status_t)

/* < Packet Downlink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(PD_AckNack_AdditionsR99_t)
  M_NEXT_EXIST (PD_AckNack_AdditionsR99_t, Exist_PFI, 1),
  M_UINT       (PD_AckNack_AdditionsR99_t,  PFI, 7, &hf_pfi),
CSN_DESCR_END  (PD_AckNack_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Downlink_Ack_Nack_t)
  M_UINT              (Packet_Downlink_Ack_Nack_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  R, 1, &hf_ul_retry),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  MESSAGE_TYPE,  6, &hf_ul_message_type),
  M_UINT              (Packet_Downlink_Ack_Nack_t,  DOWNLINK_TFI,  5, &hf_downlink_tfi),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, Ack_Nack_Description, Ack_Nack_Description_t),

  M_NEXT_EXIST        (Packet_Downlink_Ack_Nack_t, Exist_Channel_Request_Description, 1),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, Channel_Request_Description, Channel_Request_Description_t),

  M_TYPE              (Packet_Downlink_Ack_Nack_t, Channel_Quality_Report, Channel_Quality_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Downlink_Ack_Nack_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, AdditionsR99, PD_AckNack_AdditionsR99_t),

  M_PADDING_BITS      (Packet_Downlink_Ack_Nack_t),
CSN_DESCR_END         (Packet_Downlink_Ack_Nack_t)


/*< EGPRS Packet Downlink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(EGPRS_ChannelQualityReport_t)
  M_TYPE       (EGPRS_ChannelQualityReport_t, EGPRS_BEP_LinkQualityMeasurements, EGPRS_BEP_LinkQualityMeasurements_t),
  M_UINT       (EGPRS_ChannelQualityReport_t,  C_VALUE,  6, &hf_egprs_channelqualityreport_c_value),
  M_TYPE       (EGPRS_ChannelQualityReport_t, EGPRS_TimeslotLinkQualityMeasurements, EGPRS_TimeslotLinkQualityMeasurements_t),
CSN_DESCR_END  (EGPRS_ChannelQualityReport_t)

static const
CSN_DESCR_BEGIN(EGPRS_PD_AckNack_t)
/*  M_CALLBACK   (EGPRS_PD_AckNack_t, (void*)21, IsSupported, IsSupported), */
  M_UINT       (EGPRS_PD_AckNack_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT       (EGPRS_PD_AckNack_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT       (EGPRS_PD_AckNack_t,  R, 1, &hf_ul_retry),

  M_UINT       (EGPRS_PD_AckNack_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  M_UINT       (EGPRS_PD_AckNack_t,  DOWNLINK_TFI, 5, &hf_downlink_tfi),
  M_UINT       (EGPRS_PD_AckNack_t,  MS_OUT_OF_MEMORY,  1, &hf_egprs_pd_acknack_ms_out_of_memory),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_EGPRS_ChannelQualityReport, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, EGPRS_ChannelQualityReport, EGPRS_ChannelQualityReport_t),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_ChannelRequestDescription, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, ChannelRequestDescription, Channel_Request_Description_t),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_PFI, 1),
  M_UINT       (EGPRS_PD_AckNack_t,  PFI, 7, &hf_pfi),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_ExtensionBits, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, ExtensionBits, Extension_Bits_t),

  M_TYPE       (EGPRS_PD_AckNack_t, EGPRS_AckNack, EGPRS_AckNack_t),
/*  M_CALLBACK   (EGPRS_PD_AckNack_t, (void*)24, EGPRS_AckNack, EGPRS_AckNack),  */
  M_PADDING_BITS(EGPRS_PD_AckNack_t),
CSN_DESCR_END  (EGPRS_PD_AckNack_t)

static const
CSN_DESCR_BEGIN(FDD_Target_Cell_t)
  M_UINT       (FDD_Target_Cell_t,  FDD_ARFCN,  14, &hf_fddarget_cell_t_fdd_arfcn),
  M_UINT       (FDD_Target_Cell_t,  DIVERSITY,  1, &hf_fddarget_cell_t_diversity),
  M_NEXT_EXIST (FDD_Target_Cell_t, Exist_Bandwith_FDD, 1),
  M_UINT       (FDD_Target_Cell_t,  BANDWITH_FDD,  3, &hf_fddarget_cell_t_bandwith_fdd),
  M_UINT       (FDD_Target_Cell_t,  SCRAMBLING_CODE,  9, &hf_fddarget_cell_t_scrambling_code),
CSN_DESCR_END  (FDD_Target_Cell_t)

static const
CSN_DESCR_BEGIN(TDD_Target_Cell_t)
  M_UINT       (TDD_Target_Cell_t,  TDD_ARFCN,  14, &hf_tddarget_cell_t_tdd_arfcn),
  M_UINT       (TDD_Target_Cell_t,  DIVERSITY_TDD,  1, &hf_tddarget_cell_t_diversity),
  M_NEXT_EXIST (TDD_Target_Cell_t, Exist_Bandwith_TDD, 1),
  M_UINT       (TDD_Target_Cell_t,  BANDWITH_TDD,  3, &hf_tddarget_cell_t_bandwith_tdd),
  M_UINT       (TDD_Target_Cell_t,  CELL_PARAMETER,  7, &hf_tddarget_cell_t_cell_parameter),
  M_UINT       (TDD_Target_Cell_t,  Sync_Case_TSTD,  1, &hf_tddarget_cell_t_sync_case_tstd),
CSN_DESCR_END  (TDD_Target_Cell_t)

static const
CSN_DESCR_BEGIN(EUTRAN_Target_Cell_t)
  M_UINT       (EUTRAN_Target_Cell_t,  EARFCN,  16, &hf_target_cell_eutran_earfcn),
  M_NEXT_EXIST (EUTRAN_Target_Cell_t, Exist_Measurement_Bandwidth, 1),
  M_UINT       (EUTRAN_Target_Cell_t,  Measurement_Bandwidth,  3, &hf_target_cell_eutran_measurement_bandwidth),
  M_UINT       (EUTRAN_Target_Cell_t,  Physical_Layer_Cell_Identity,  9, &hf_target_cell_eutran_pl_cell_id),
CSN_DESCR_END  (EUTRAN_Target_Cell_t)

static const
CSN_DESCR_BEGIN(UTRAN_CSG_Target_Cell_t)
  M_UINT       (UTRAN_CSG_Target_Cell_t, UTRAN_CI,  28, &hf_utran_csg_target_cell_ci),
  M_NEXT_EXIST (UTRAN_CSG_Target_Cell_t, Exist_PLMN_ID, 1),
  M_TYPE       (UTRAN_CSG_Target_Cell_t, PLMN_ID, PLMN_t),
CSN_DESCR_END  (UTRAN_CSG_Target_Cell_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Target_Cell_t)
  M_UINT       (EUTRAN_CSG_Target_Cell_t, EUTRAN_CI,  28, &hf_eutran_csg_target_cell_ci),
  M_UINT       (EUTRAN_CSG_Target_Cell_t, Tracking_Area_Code,  16, &hf_eutran_csg_target_cell_tac),
  M_NEXT_EXIST (EUTRAN_CSG_Target_Cell_t, Exist_PLMN_ID, 1),
  M_TYPE       (EUTRAN_CSG_Target_Cell_t, PLMN_ID, PLMN_t),
CSN_DESCR_END  (EUTRAN_CSG_Target_Cell_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR9_t)
  M_NEXT_EXIST (PCCF_AdditionsR9_t, Exist_UTRAN_CSG_Target_Cell, 1),
  M_TYPE       (PCCF_AdditionsR9_t, UTRAN_CSG_Target_Cell, UTRAN_CSG_Target_Cell_t),
  M_NEXT_EXIST (PCCF_AdditionsR9_t, Exist_EUTRAN_CSG_Target_Cell, 1),
  M_TYPE       (PCCF_AdditionsR9_t, EUTRAN_CSG_Target_Cell, EUTRAN_CSG_Target_Cell_t),
CSN_DESCR_END  (PCCF_AdditionsR9_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR8_t)
  M_NEXT_EXIST (PCCF_AdditionsR8_t, Exist_EUTRAN_Target_Cell, 1),
  M_TYPE       (PCCF_AdditionsR8_t, EUTRAN_Target_Cell, EUTRAN_Target_Cell_t),
  M_NEXT_EXIST_OR_NULL(PCCF_AdditionsR8_t, Exist_AdditionsR9, 1),
  M_TYPE       (PCCF_AdditionsR8_t, AdditionsR9, PCCF_AdditionsR9_t),
CSN_DESCR_END  (PCCF_AdditionsR8_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR5_t)
  M_NEXT_EXIST (PCCF_AdditionsR5_t, Exist_G_RNTI_extention, 1),
  M_UINT       (PCCF_AdditionsR5_t,  G_RNTI_extention,  4, &hf_pmo_additionsr5_grnti),
  M_NEXT_EXIST_OR_NULL(PCCF_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE       (PCCF_AdditionsR5_t, AdditionsR8, PCCF_AdditionsR8_t),
CSN_DESCR_END  (PCCF_AdditionsR5_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR99_t)
  M_NEXT_EXIST (PCCF_AdditionsR99_t, Exist_FDD_Description, 1),
  M_TYPE       (PCCF_AdditionsR99_t, FDD_Target_Cell, FDD_Target_Cell_t),
  M_NEXT_EXIST (PCCF_AdditionsR99_t, Exist_TDD_Description, 1),
  M_TYPE       (PCCF_AdditionsR99_t, TDD_Target_Cell, TDD_Target_Cell_t),
  M_NEXT_EXIST_OR_NULL(PCCF_AdditionsR99_t, Exist_AdditionsR5, 1),
  M_TYPE       (PCCF_AdditionsR99_t, AdditionsR5, PCCF_AdditionsR5_t),
CSN_DESCR_END  (PCCF_AdditionsR99_t)

/*< Packet Cell Change Failure message content > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Failure_t)
  /* Mac header */
  M_UINT               (Packet_Cell_Change_Failure_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT               (Packet_Cell_Change_Failure_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT               (Packet_Cell_Change_Failure_t,  R, 1, &hf_ul_retry),
  M_UINT               (Packet_Cell_Change_Failure_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_UINT               (Packet_Cell_Change_Failure_t,  TLLI, 32, &hf_tlli),
  M_UINT               (Packet_Cell_Change_Failure_t,  ARFCN, 10, &hf_arfcn),
  M_UINT               (Packet_Cell_Change_Failure_t,  BSIC,  6, &hf_packet_cell_change_failure_bsic),
  M_UINT               (Packet_Cell_Change_Failure_t,  CAUSE,  4, &hf_packet_cell_change_failure_cause),

  M_NEXT_EXIST_OR_NULL (Packet_Cell_Change_Failure_t, Exist_AdditionsR99, 1),
  M_TYPE               (Packet_Cell_Change_Failure_t, AdditionsR99, PCCF_AdditionsR99_t),

  M_PADDING_BITS       (Packet_Cell_Change_Failure_t),
CSN_DESCR_END          (Packet_Cell_Change_Failure_t)

/*< Packet Uplink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(Power_Control_Parameters_t)
  M_UINT       (Power_Control_Parameters_t, ALPHA, 4, &hf_alpha),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[0].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[0].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[1].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[1].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[2].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[2].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[3].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[3].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[4].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[4].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[5].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[5].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[6].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[6].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[7].Exist, 1),
  M_UINT       (Power_Control_Parameters_t,  Slot[7].GAMMA_TN, 5, &hf_gamma),
CSN_DESCR_END  (Power_Control_Parameters_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PU_AckNack_GPRS_AdditionsR99_t, Exist_PacketExtendedTimingAdvance, 1),
  M_UINT       (PU_AckNack_GPRS_AdditionsR99_t,  PacketExtendedTimingAdvance, 2, &hf_packet_extended_timing_advance),

  M_UINT       (PU_AckNack_GPRS_AdditionsR99_t,  TBF_EST,  1, &hf_pu_acknack_gprs_additionsr99_tbf_est),
CSN_DESCR_END  (PU_AckNack_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PU_AckNack_GPRS_t)
  M_UINT              (PU_AckNack_GPRS_t,  CHANNEL_CODING_COMMAND, 2, &hf_gprs_channel_coding_command),
  M_TYPE              (PU_AckNack_GPRS_t, Ack_Nack_Description, Ack_Nack_Description_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI, 1),
  M_UINT              (PU_AckNack_GPRS_t,  Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI, 32, &hf_tlli),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Extension_Bits, Extension_Bits_t),

  M_UNION             (PU_AckNack_GPRS_t, 2), /* Fixed Allocation was removed */
  M_UINT              (PU_AckNack_GPRS_t,  u.FixedAllocationDummy,  1, &hf_pu_acknack_gprs_fixedallocationdummy),
  CSN_ERROR           (PU_AckNack_GPRS_t, "01 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PU_AckNack_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PU_AckNack_GPRS_t, AdditionsR99, PU_AckNack_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PU_AckNack_GPRS_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_EGPRS_00_t)
  M_UINT       (PU_AckNack_EGPRS_00_t,  EGPRS_ChannelCodingCommand, 4, &hf_egprs_channel_coding_command),
  M_UINT       (PU_AckNack_EGPRS_00_t,  RESEGMENT, 1, &hf_resegment),
  M_UINT       (PU_AckNack_EGPRS_00_t,  PRE_EMPTIVE_TRANSMISSION,  1, &hf_pu_acknack_egprs_00_pre_emptive_transmission),
  M_UINT       (PU_AckNack_EGPRS_00_t,  PRR_RETRANSMISSION_REQUEST,  1, &hf_pu_acknack_egprs_00_prr_retransmission_request),
  M_UINT       (PU_AckNack_EGPRS_00_t,  ARAC_RETRANSMISSION_REQUEST,  1, &hf_pu_acknack_egprs_00_arac_retransmission_request),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI, 32, &hf_tlli),

  M_UINT       (PU_AckNack_EGPRS_00_t,  TBF_EST,  1, &hf_pu_acknack_egprs_00_tbf_est),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Extension_Bits, Extension_Bits_t),

  M_TYPE       (PU_AckNack_EGPRS_00_t, EGPRS_AckNack, EGPRS_AckNack_t),
/*  M_CALLBACK   (PU_AckNack_EGPRS_00_t, (void*)24, EGPRS_AckNack, EGPRS_AckNack),  */
CSN_DESCR_END  (PU_AckNack_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_EGPRS_t)
/*  M_CALLBACK   (PU_AckNack_EGPRS_t, (void*)21, IsSupported, IsSupported), */
  M_UNION      (PU_AckNack_EGPRS_t, 4),
  M_TYPE       (PU_AckNack_EGPRS_t, u.PU_AckNack_EGPRS_00, PU_AckNack_EGPRS_00_t),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "01 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "10 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "11 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PU_AckNack_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Uplink_Ack_Nack_t)
  M_UINT       (Packet_Uplink_Ack_Nack_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Uplink_Ack_Nack_t, PAGE_MODE, 2, &hf_page_mode),
  M_FIXED      (Packet_Uplink_Ack_Nack_t, 2, 0x00),
  M_UINT       (Packet_Uplink_Ack_Nack_t, UPLINK_TFI, 5, &hf_uplink_tfi),

  M_UNION      (Packet_Uplink_Ack_Nack_t, 2),
  M_TYPE       (Packet_Uplink_Ack_Nack_t, u.PU_AckNack_GPRS_Struct, PU_AckNack_GPRS_t),
  M_TYPE       (Packet_Uplink_Ack_Nack_t, u.PU_AckNack_EGPRS_Struct, PU_AckNack_EGPRS_t),

  M_PADDING_BITS(Packet_Uplink_Ack_Nack_t ),
CSN_DESCR_END  (Packet_Uplink_Ack_Nack_t)

/*< Packet Uplink Assignment message content > */
static const
CSN_DESCR_BEGIN(CHANGE_MARK_t)
  M_UINT       (CHANGE_MARK_t,  CHANGE_MARK_1,  2, &hf_change_mark_change_mark_1),

  M_NEXT_EXIST (CHANGE_MARK_t, Exist_CHANGE_MARK_2, 1),
  M_UINT       (CHANGE_MARK_t,  CHANGE_MARK_2,  2, &hf_change_mark_change_mark_2),
CSN_DESCR_END  (CHANGE_MARK_t)

static const
CSN_DESCR_BEGIN(Indirect_encoding_t)
  M_UINT       (Indirect_encoding_t,  MAIO, 6, &hf_maio),
  M_UINT       (Indirect_encoding_t,  MA_NUMBER,  4, &hf_indirect_encoding_ma_number),

  M_NEXT_EXIST (Indirect_encoding_t, Exist_CHANGE_MARK, 1),
  M_TYPE       (Indirect_encoding_t, CHANGE_MARK, CHANGE_MARK_t),
CSN_DESCR_END  (Indirect_encoding_t)

static const
CSN_DESCR_BEGIN(Direct_encoding_1_t)
  M_UINT       (Direct_encoding_1_t,  MAIO, 6, &hf_maio),
  M_TYPE       (Direct_encoding_1_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),
CSN_DESCR_END  (Direct_encoding_1_t)

static const
CSN_DESCR_BEGIN(Direct_encoding_2_t)
  M_UINT       (Direct_encoding_2_t,  MAIO, 6, &hf_maio),
  M_UINT       (Direct_encoding_2_t,  HSN, 6, &hf_hsn),
  M_UINT_OFFSET(Direct_encoding_2_t, Length_of_MA_Frequency_List, 4, 3),
  M_VAR_ARRAY  (Direct_encoding_2_t, MA_Frequency_List, Length_of_MA_Frequency_List, 0),
CSN_DESCR_END  (Direct_encoding_2_t)

static const
CSN_DESCR_BEGIN(Frequency_Parameters_t)
  M_UINT       (Frequency_Parameters_t, TSC, 3, &hf_tsc),

  M_UNION      (Frequency_Parameters_t, 4),
  M_UINT       (Frequency_Parameters_t, u.ARFCN, 10, &hf_arfcn),
  M_TYPE       (Frequency_Parameters_t, u.Indirect_encoding, Indirect_encoding_t),
  M_TYPE       (Frequency_Parameters_t, u.Direct_encoding_1, Direct_encoding_1_t),
  M_TYPE       (Frequency_Parameters_t, u.Direct_encoding_2, Direct_encoding_2_t),
CSN_DESCR_END  (Frequency_Parameters_t)

static const
CSN_DESCR_BEGIN(Packet_Request_Reference_t)
  M_UINT       (Packet_Request_Reference_t,  RANDOM_ACCESS_INFORMATION,  11, &hf_packet_request_reference_random_access_information),
  M_UINT_ARRAY (Packet_Request_Reference_t, FRAME_NUMBER, 8, 2),
CSN_DESCR_END  (Packet_Request_Reference_t)

static const
CSN_DESCR_BEGIN(Timeslot_Allocation_t)
  M_NEXT_EXIST (Timeslot_Allocation_t, Exist, 1),
  M_UINT       (Timeslot_Allocation_t,  USF_TN,  3, &hf_timeslot_allocation_usf_tn),
CSN_DESCR_END  (Timeslot_Allocation_t)

static const
CSN_DESCR_BEGIN(Timeslot_Allocation_Power_Ctrl_Param_t)
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, ALPHA, 4, &hf_alpha),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[0].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[0].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[0].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[1].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[1].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[1].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[2].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[2].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[2].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[3].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[3].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[3].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[4].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[4].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[4].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[5].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[5].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[5].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[6].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[6].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[6].GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[7].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[7].USF_TN, 3, &hf_usf),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t,  Slot[7].GAMMA_TN, 5, &hf_gamma),
CSN_DESCR_END  (Timeslot_Allocation_Power_Ctrl_Param_t)

/* USED in <Packet Uplink Assignment message content> */
static const
CSN_DESCR_BEGIN(Dynamic_Allocation_t)
  M_UINT       (Dynamic_Allocation_t,  Extended_Dynamic_Allocation,  1, &hf_extended_dynamic_allocation),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (Dynamic_Allocation_t,  P0, 4, &hf_p0),
  M_UINT       (Dynamic_Allocation_t,  PR_MODE, 1, &hf_pr_mode),

  M_UINT       (Dynamic_Allocation_t, USF_GRANULARITY, 1, &hf_usf_granularity),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (Dynamic_Allocation_t,  UPLINK_TFI_ASSIGNMENT, 5, &hf_uplink_tfi),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED, 1),
  M_UINT       (Dynamic_Allocation_t,  RLC_DATA_BLOCKS_GRANTED,  8, &hf_rlc_data_blocks_granted),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_TBF_Starting_Time, 1),
  M_TYPE       (Dynamic_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_UNION      (Dynamic_Allocation_t, 2),
  M_TYPE_ARRAY (Dynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (Dynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (Dynamic_Allocation_t)

static const
CSN_DESCR_BEGIN(Single_Block_Allocation_t)
  M_UINT       (Single_Block_Allocation_t,  TIMESLOT_NUMBER,  3, &hf_single_block_allocation_timeslot_number),

  M_NEXT_EXIST (Single_Block_Allocation_t, Exist_ALPHA_and_GAMMA_TN, 2),
  M_UINT       (Single_Block_Allocation_t,  ALPHA, 4, &hf_alpha),
  M_UINT       (Single_Block_Allocation_t,  GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (Single_Block_Allocation_t, Exist_P0, 3),
  M_UINT       (Single_Block_Allocation_t,  P0, 4, &hf_p0),
  M_UINT       (Single_Block_Allocation_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT       (Single_Block_Allocation_t,  PR_MODE, 1, &hf_pr_mode),

  M_TYPE       (Single_Block_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),
CSN_DESCR_END  (Single_Block_Allocation_t)

static const
CSN_DESCR_BEGIN(DTM_Dynamic_Allocation_t)
  M_UINT       (DTM_Dynamic_Allocation_t,  Extended_Dynamic_Allocation,  1, &hf_extended_dynamic_allocation),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (DTM_Dynamic_Allocation_t,  P0, 4, &hf_p0),
  M_UINT       (DTM_Dynamic_Allocation_t,  PR_MODE, 1, &hf_pr_mode),

  M_UINT       (DTM_Dynamic_Allocation_t,  USF_GRANULARITY, 1, &hf_usf_granularity),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (DTM_Dynamic_Allocation_t,  UPLINK_TFI_ASSIGNMENT, 5, &hf_uplink_tfi),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED, 1),
  M_UINT       (DTM_Dynamic_Allocation_t,  RLC_DATA_BLOCKS_GRANTED, 8, &hf_rlc_data_blocks_granted),

  M_UNION      (DTM_Dynamic_Allocation_t, 2),
  M_TYPE_ARRAY (DTM_Dynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (DTM_Dynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (DTM_Dynamic_Allocation_t)

static const
CSN_DESCR_BEGIN(DTM_Single_Block_Allocation_t)
  M_UINT       (DTM_Single_Block_Allocation_t, TIMESLOT_NUMBER, 3, &hf_dtm_single_block_allocation_timeslot_number),

  M_NEXT_EXIST (DTM_Single_Block_Allocation_t, Exist_ALPHA_and_GAMMA_TN, 2),
  M_UINT       (DTM_Single_Block_Allocation_t,  ALPHA, 4, &hf_alpha),
  M_UINT       (DTM_Single_Block_Allocation_t,  GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (DTM_Single_Block_Allocation_t, Exist_P0, 3),
  M_UINT       (DTM_Single_Block_Allocation_t,  P0, 4, &hf_p0),
  M_UINT       (DTM_Single_Block_Allocation_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT       (DTM_Single_Block_Allocation_t,  PR_MODE, 1, &hf_pr_mode),
CSN_DESCR_END  (DTM_Single_Block_Allocation_t)


/* Help structures */
typedef struct
{
  Global_TFI_t Global_TFI;  /* 0  < Global TFI : < Global TFI IE > > */
} h0_Global_TFI_t;

static const
CSN_DESCR_BEGIN(h0_Global_TFI_t)
  M_FIXED      (h0_Global_TFI_t, 1, 0x00),
  M_TYPE       (h0_Global_TFI_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (h0_Global_TFI_t)

typedef struct
{
  guint32 TLLI;/* | 10  < TLLI : bit (32) >*/
} h10_TLLI_t;

static const
CSN_DESCR_BEGIN(h10_TLLI_t)
  M_FIXED      (h10_TLLI_t, 2, 0x02),
  M_UINT       (h10_TLLI_t, TLLI, 32, &hf_tlli),
CSN_DESCR_END (h10_TLLI_t)

typedef struct
{
  guint16 TQI;/*| 110  < TQI : bit (16) > */
} h110_TQI_t;

static const
CSN_DESCR_BEGIN(h110_TQI_t)
  M_FIXED      (h110_TQI_t, 3, 0x06),
  M_UINT       (h110_TQI_t, TQI, 16, &hf_tqi),
CSN_DESCR_END  (h110_TQI_t)

typedef struct
{
  Packet_Request_Reference_t Packet_Request_Reference;/*| 111  < Packet Request Reference : < Packet Request Reference IE > > }*/
} h111_Packet_Request_Reference_t;

static const
CSN_DESCR_BEGIN(h111_Packet_Request_Reference_t)
  M_FIXED      (h111_Packet_Request_Reference_t, 3, 0x07),
  M_TYPE       (h111_Packet_Request_Reference_t, Packet_Request_Reference, Packet_Request_Reference_t),
CSN_DESCR_END  (h111_Packet_Request_Reference_t)

static const
CSN_ChoiceElement_t PacketUplinkID[] =
{
  {1, 0,    0, M_TYPE(PacketUplinkID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketUplinkID_t, u.TLLI, 32, &hf_tlli)},
  {3, 0x06, 0, M_UINT(PacketUplinkID_t, u.TQI, 16, &hf_tqi)},
  {3, 0x07, 0, M_TYPE(PacketUplinkID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
};

static const
CSN_DESCR_BEGIN(PacketUplinkID_t)
  M_CHOICE     (PacketUplinkID_t, UnionType, PacketUplinkID, ElementsOf(PacketUplinkID)),
CSN_DESCR_END  (PacketUplinkID_t)

static const
CSN_DESCR_BEGIN(PUA_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PUA_GPRS_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PUA_GPRS_AdditionsR99_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),
CSN_DESCR_END  (PUA_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PUA_GPRS_t)
  M_UINT              (PUA_GPRS_t, CHANNEL_CODING_COMMAND,  2, &hf_gprs_channel_coding_command),
  M_UINT              (PUA_GPRS_t, TLLI_BLOCK_CHANNEL_CODING, 1, &hf_tlli_block_channel_coding),
  M_TYPE              (PUA_GPRS_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (PUA_GPRS_t, Exist_Frequency_Parameters, 1),
  M_TYPE              (PUA_GPRS_t, Frequency_Parameters, Frequency_Parameters_t),

  M_UNION             (PUA_GPRS_t, 4),
  CSN_ERROR           (PUA_GPRS_t, "00 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE              (PUA_GPRS_t, u.Dynamic_Allocation, Dynamic_Allocation_t),
  M_TYPE              (PUA_GPRS_t, u.Single_Block_Allocation, Single_Block_Allocation_t),
  CSN_ERROR           (PUA_GPRS_t, "11 <Fixed Allocation> not supported", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PUA_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PUA_GPRS_t, AdditionsR99, PUA_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PUA_GPRS_t)

static const
CSN_DESCR_BEGIN(COMPACT_ReducedMA_t)
  M_UINT       (COMPACT_ReducedMA_t,  BitmapLength,  7, &hf_compact_reducedma_bitmaplength),
  M_VAR_BITMAP (COMPACT_ReducedMA_t, ReducedMA_Bitmap, BitmapLength, 0),

  M_NEXT_EXIST (COMPACT_ReducedMA_t, Exist_MAIO_2, 1),
  M_UINT       (COMPACT_ReducedMA_t,  MAIO_2, 6, &hf_maio),
CSN_DESCR_END  (COMPACT_TeducedMA_t)

static const
CSN_DESCR_BEGIN(MultiBlock_Allocation_t)
  M_UINT       (MultiBlock_Allocation_t, TIMESLOT_NUMBER, 3, &hf_multiblock_allocation_timeslot_number),

  M_NEXT_EXIST (MultiBlock_Allocation_t, Exist_ALPHA_GAMMA_TN, 2),
  M_UINT       (MultiBlock_Allocation_t,  ALPHA, 4, &hf_alpha),
  M_UINT       (MultiBlock_Allocation_t,  GAMMA_TN, 5, &hf_gamma),

  M_NEXT_EXIST (MultiBlock_Allocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (MultiBlock_Allocation_t,  P0, 4, &hf_p0),
  M_UINT       (MultiBlock_Allocation_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT       (MultiBlock_Allocation_t,  PR_MODE, 1, &hf_pr_mode),

  M_TYPE       (MultiBlock_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),
  M_UINT       (MultiBlock_Allocation_t,  NUMBER_OF_RADIO_BLOCKS_ALLOCATED, 2, &hf_nr_of_radio_blocks_allocated),
CSN_DESCR_END  (MultiBlock_Allocation_t)

static const
CSN_DESCR_BEGIN (PUA_EGPRS_00_t)
  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_CONTENTION_RESOLUTION_TLLI, 1),
  M_UINT        (PUA_EGPRS_00_t,  CONTENTION_RESOLUTION_TLLI,  32, &hf_tlli),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE        (PUA_EGPRS_00_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),

  M_UINT        (PUA_EGPRS_00_t,  EGPRS_CHANNEL_CODING_COMMAND, 4, &hf_egprs_channel_coding_command),
  M_UINT        (PUA_EGPRS_00_t,  RESEGMENT, 1, &hf_resegment),
  M_UINT        (PUA_EGPRS_00_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),

  M_REC_ARRAY   (PUA_EGPRS_00_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UINT        (PUA_EGPRS_00_t,  ARAC_RETRANSMISSION_REQUEST,  1, &hf_pua_egprs_00_arac_retransmission_request),
  M_UINT        (PUA_EGPRS_00_t,  TLLI_BLOCK_CHANNEL_CODING, 1, &hf_tlli_block_channel_coding),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_BEP_PERIOD2, 1),
  M_UINT        (PUA_EGPRS_00_t,  BEP_PERIOD2, 4, &hf_bep_period2),

  M_TYPE        (PUA_EGPRS_00_t, PacketTimingAdvance, Packet_Timing_Advance_t),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT        (PUA_EGPRS_00_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_Frequency_Parameters, 1),
  M_TYPE        (PUA_EGPRS_00_t, Frequency_Parameters, Frequency_Parameters_t),

  M_UNION       (PUA_EGPRS_00_t, 4),
  CSN_ERROR     (PUA_EGPRS_00_t, "00 <extension>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE        (PUA_EGPRS_00_t, u.Dynamic_Allocation, Dynamic_Allocation_t),
  M_TYPE        (PUA_EGPRS_00_t, u.MultiBlock_Allocation, MultiBlock_Allocation_t),
  CSN_ERROR     (PUA_EGPRS_00_t, "11 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END   (PUA_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PUA_EGPRS_t)
  M_UNION      (PUA_EGPRS_t, 4),
  M_TYPE       (PUA_EGPRS_t, u.PUA_EGPRS_00, PUA_EGPRS_00_t),
  CSN_ERROR    (PUA_EGPRS_t, "01 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PUA_EGPRS_t, "10 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PUA_EGPRS_t, "11 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PUA_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Uplink_Assignment_t)
  M_UINT       (Packet_Uplink_Assignment_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Uplink_Assignment_t, PAGE_MODE, 2, &hf_page_mode),

  M_NEXT_EXIST (Packet_Uplink_Assignment_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (Packet_Uplink_Assignment_t, PERSISTENCE_LEVEL, 4, 4),

  M_TYPE       (Packet_Uplink_Assignment_t, ID, PacketUplinkID_t),

  M_UNION      (Packet_Uplink_Assignment_t, 2),
  M_TYPE       (Packet_Uplink_Assignment_t, u.PUA_GPRS_Struct, PUA_GPRS_t),
  M_TYPE       (Packet_Uplink_Assignment_t, u.PUA_EGPRS_Struct, PUA_EGPRS_t),

  M_PADDING_BITS(Packet_Uplink_Assignment_t ),
CSN_DESCR_END  (Packet_Uplink_Assignment_t)

/*< Packet Downlink Assignment message content > */
static const
CSN_DESCR_BEGIN(Measurement_Mapping_struct_t)
  M_TYPE       (Measurement_Mapping_struct_t, Measurement_Starting_Time, Starting_Frame_Number_t),
  M_UINT       (Measurement_Mapping_struct_t,  MEASUREMENT_INTERVAL,  5, &hf_measurement_mapping_struct_measurement_interval),
  M_UINT       (Measurement_Mapping_struct_t,  MEASUREMENT_BITMAP,  8, &hf_measurement_mapping_struct_measurement_bitmap),
CSN_DESCR_END  (Measurement_Mapping_struct_t)

static const
CSN_ChoiceElement_t PacketDownlinkID[] =
{
  {1,    0, 0, M_TYPE(PacketDownlinkID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketDownlinkID_t, u.TLLI, 32, &hf_tlli)},
};

static const
CSN_DESCR_BEGIN(PacketDownlinkID_t)
  M_CHOICE     (PacketDownlinkID_t, UnionType, PacketDownlinkID, ElementsOf(PacketDownlinkID)),
CSN_DESCR_END  (PacketDownlinkID_t)

static const
CSN_DESCR_BEGIN(PDA_AdditionsR99_t)
  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_EGPRS_Params, 4), /*if Exist_EGPRS_Params == FALSE then none of the following 4 vars exist */
  M_UINT       (PDA_AdditionsR99_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),
  M_UINT       (PDA_AdditionsR99_t,  LINK_QUALITY_MEASUREMENT_MODE, 2, &hf_link_quality_measurement_mode),
  M_NEXT_EXIST (PDA_AdditionsR99_t,  Exist_BEP_PERIOD2, 1),
  M_UINT       (PDA_AdditionsR99_t,   BEP_PERIOD2, 4, &hf_bep_period2),

  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PDA_AdditionsR99_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),

  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE       (PDA_AdditionsR99_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),
CSN_DESCR_END  (PDA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Downlink_Assignment_t)
  M_UINT              (Packet_Downlink_Assignment_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT              (Packet_Downlink_Assignment_t, PAGE_MODE, 2, &hf_page_mode),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY        (Packet_Downlink_Assignment_t, PERSISTENCE_LEVEL, 4, 4),

  M_TYPE              (Packet_Downlink_Assignment_t, ID, PacketDownlinkID_t),

  M_FIXED             (Packet_Downlink_Assignment_t, 1, 0x00),/*-- Message escape */

  M_UINT              (Packet_Downlink_Assignment_t, MAC_MODE, 2, &hf_mac_mode),
  M_UINT              (Packet_Downlink_Assignment_t, RLC_MODE, 1, &hf_rlc_mode),
  M_UINT              (Packet_Downlink_Assignment_t, CONTROL_ACK, 1, &hf_control_ack),
  M_UINT              (Packet_Downlink_Assignment_t, TIMESLOT_ALLOCATION, 8, &hf_dl_timeslot_allocation),
  M_TYPE              (Packet_Downlink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_P0_and_BTS_PWR_CTRL_MODE, 3),
  M_UINT              (Packet_Downlink_Assignment_t,  P0, 4, &hf_p0),
  M_UINT              (Packet_Downlink_Assignment_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT              (Packet_Downlink_Assignment_t,  PR_MODE, 1, &hf_pr_mode),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Frequency_Parameters, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Frequency_Parameters, Frequency_Parameters_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT              (Packet_Downlink_Assignment_t,  DOWNLINK_TFI_ASSIGNMENT, 5, &hf_downlink_tfi),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Power_Control_Parameters, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_TBF_Starting_Time, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Measurement_Mapping, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Measurement_Mapping, Measurement_Mapping_struct_t),

  M_NEXT_EXIST_OR_NULL(Packet_Downlink_Assignment_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, AdditionsR99, PDA_AdditionsR99_t),

  M_PADDING_BITS    (Packet_Downlink_Assignment_t),
CSN_DESCR_END         (Packet_Downlink_Assignment_t)

typedef Packet_Downlink_Assignment_t pdlaCheck_t;

static const
CSN_DESCR_BEGIN(pdlaCheck_t)
  M_UINT       (pdlaCheck_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (pdlaCheck_t, PAGE_MODE, 2, &hf_page_mode),

  M_NEXT_EXIST (pdlaCheck_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (pdlaCheck_t, PERSISTENCE_LEVEL, 4, 4),

  M_TYPE       (pdlaCheck_t, ID, PacketDownlinkID_t),
CSN_DESCR_END  (pdlaCheck_t)

/* DTM Packet UL Assignment */
static const
CSN_DESCR_BEGIN(DTM_Packet_Uplink_Assignment_t)
  M_UINT       (DTM_Packet_Uplink_Assignment_t, CHANNEL_CODING_COMMAND, 2, &hf_gprs_channel_coding_command),
  M_UINT       (DTM_Packet_Uplink_Assignment_t, TLLI_BLOCK_CHANNEL_CODING, 1, &hf_tlli_block_channel_coding),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_UNION      (DTM_Packet_Uplink_Assignment_t, 3),
  CSN_ERROR    (DTM_Packet_Uplink_Assignment_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, u.DTM_Dynamic_Allocation, DTM_Dynamic_Allocation_t),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, u.DTM_Single_Block_Allocation, DTM_Single_Block_Allocation_t),
  M_NEXT_EXIST_OR_NULL  (DTM_Packet_Uplink_Assignment_t, Exist_EGPRS_Parameters, 3),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  EGPRS_CHANNEL_CODING_COMMAND, 4, &hf_egprs_channel_coding_command),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  RESEGMENT, 1, &hf_resegment),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),
  M_NEXT_EXIST (DTM_Packet_Uplink_Assignment_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (DTM_Packet_Uplink_Assignment_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),
CSN_DESCR_END(DTM_Packet_Uplink_Assignment_t)

static const
CSN_DESCR_BEGIN(DTM_UL_t)
  M_TYPE       (DTM_UL_t, DTM_Packet_Uplink_Assignment, DTM_Packet_Uplink_Assignment_t),
CSN_DESCR_END(DTM_UL_t)

/* DTM Packet DL Assignment */
static const
CSN_DESCR_BEGIN(DTM_Packet_Downlink_Assignment_t)
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  MAC_MODE, 2, &hf_mac_mode),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  RLC_MODE, 1, &hf_rlc_mode),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  TIMESLOT_ALLOCATION, 8, &hf_dl_timeslot_allocation),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_P0_and_BTS_PWR_CTRL_MODE, 3),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  P0, 4, &hf_p0),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  BTS_PWR_CTRL_MODE, 1, &hf_bts_pwr_ctrl_mode),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  PR_MODE, 1, &hf_pr_mode),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Power_Control_Parameters, 1),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  DOWNLINK_TFI_ASSIGNMENT, 5, &hf_downlink_tfi),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Measurement_Mapping, 1),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Measurement_Mapping, Measurement_Mapping_struct_t),
  M_NEXT_EXIST_OR_NULL  (DTM_Packet_Downlink_Assignment_t, EGPRS_Mode, 2),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  LINK_QUALITY_MEASUREMENT_MODE, 2, &hf_link_quality_measurement_mode),
  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),
CSN_DESCR_END(DTM_Packet_Downlink_Assignment_t)

static const
CSN_DESCR_BEGIN(DTM_DL_t)
  M_TYPE       (DTM_DL_t, DTM_Packet_Downlink_Assignment, DTM_Packet_Downlink_Assignment_t),
CSN_DESCR_END(DTM_DL_t)

/* GPRS Broadcast Information */
static const
CSN_DESCR_BEGIN(DTM_GPRS_Broadcast_Information_t)
  M_TYPE       (DTM_GPRS_Broadcast_Information_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE       (DTM_GPRS_Broadcast_Information_t, GPRS_Power_Control_Parameters, GPRS_Power_Control_Parameters_t),
CSN_DESCR_END(DTM_GPRS_Broadcast_Information_t)

static const
CSN_DESCR_BEGIN(DTM_GPRS_B_t)
  M_TYPE       (DTM_GPRS_B_t, DTM_GPRS_Broadcast_Information, DTM_GPRS_Broadcast_Information_t),
CSN_DESCR_END(DTM_GPRS_B_t)

static const
CSN_DESCR_BEGIN(DTM_Channel_Request_Description_t)
  M_UINT       (DTM_Channel_Request_Description_t,  DTM_Pkt_Est_Cause,  2, &hf_dtm_channel_request_description_dtm_pkt_est_cause),
  M_TYPE       (DTM_Channel_Request_Description_t, Channel_Request_Description, Channel_Request_Description_t),
  M_NEXT_EXIST (DTM_Channel_Request_Description_t, Exist_PFI, 1),
  M_UINT       (DTM_Channel_Request_Description_t,  PFI, 7, &hf_pfi),
CSN_DESCR_END(DTM_Channel_Request_Description_t)
/* DTM  */

/*< Packet Paging Request message content > */
typedef struct
{
  guint8 Length_of_Mobile_Identity_contents;/* bit (4) */
  guint8 Mobile_Identity[8];/* octet (val (Length of Mobile Identity contents)) */
} Mobile_Identity_t; /* helper */

static const
CSN_DESCR_BEGIN(Mobile_Identity_t)
  M_UINT       (Mobile_Identity_t,  Length_of_Mobile_Identity_contents,  4, &hf_mobile_identity_length_of_mobile_identity_contents),
  M_VAR_ARRAY  (Mobile_Identity_t, Mobile_Identity, Length_of_Mobile_Identity_contents, 0),
CSN_DESCR_END  (Mobile_Identity_t)

static const
CSN_DESCR_BEGIN(Page_request_for_TBF_establishment_t)
  M_UNION      (Page_request_for_TBF_establishment_t, 2),
  M_UINT_ARRAY (Page_request_for_TBF_establishment_t, u.PTMSI, 8, 4),/* bit (32) == 8*4 */
  M_TYPE       (Page_request_for_TBF_establishment_t, u.Mobile_Identity, Mobile_Identity_t),
CSN_DESCR_END  (Page_request_for_TBF_establishment_t)

static const
CSN_DESCR_BEGIN(Page_request_for_RR_conn_t)
  M_UNION      (Page_request_for_RR_conn_t, 2),
  M_UINT_ARRAY (Page_request_for_RR_conn_t, u.TMSI, 8, 4),/* bit (32) == 8*4 */
  M_TYPE       (Page_request_for_RR_conn_t, u.Mobile_Identity, Mobile_Identity_t),

  M_UINT       (Page_request_for_RR_conn_t,  CHANNEL_NEEDED,  2, &hf_page_request_for_rr_conn_channel_needed),

  M_NEXT_EXIST (Page_request_for_RR_conn_t, Exist_eMLPP_PRIORITY, 1),
  M_UINT       (Page_request_for_RR_conn_t,  eMLPP_PRIORITY,  3, &hf_page_request_for_rr_conn_emlpp_priority),
CSN_DESCR_END  (Page_request_for_RR_conn_t)

static const
CSN_DESCR_BEGIN(Repeated_Page_info_t)
  M_UNION      (Repeated_Page_info_t, 2),
  M_TYPE       (Repeated_Page_info_t, u.Page_req_TBF, Page_request_for_TBF_establishment_t),
  M_TYPE       (Repeated_Page_info_t, u.Page_req_RR, Page_request_for_RR_conn_t),
CSN_DESCR_END  (Repeated_Page_info_t)

static const
CSN_DESCR_BEGIN(Packet_Paging_Request_t)
  M_UINT       (Packet_Paging_Request_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Paging_Request_t, PAGE_MODE, 2, &hf_page_mode),

  M_NEXT_EXIST (Packet_Paging_Request_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (Packet_Paging_Request_t, PERSISTENCE_LEVEL, 4, 4), /* 4bit*4 */

  M_NEXT_EXIST (Packet_Paging_Request_t, Exist_NLN, 1),
  M_UINT       (Packet_Paging_Request_t,  NLN, 2, &hf_nln),

  M_REC_TARRAY (Packet_Paging_Request_t, Repeated_Page_info, Repeated_Page_info_t, Count_Repeated_Page_info),
  M_PADDING_BITS(Packet_Paging_Request_t),
CSN_DESCR_END  (Packet_Paging_Request_t)

static const
CSN_DESCR_BEGIN(Packet_PDCH_Release_t)
  M_UINT       (Packet_PDCH_Release_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_PDCH_Release_t, PAGE_MODE, 2, &hf_page_mode),

  M_FIXED      (Packet_PDCH_Release_t, 1, 0x01),
  M_UINT       (Packet_PDCH_Release_t, TIMESLOTS_AVAILABLE, 8, &hf_packet_pdch_release_timeslots_available),
  M_PADDING_BITS(Packet_PDCH_Release_t),
CSN_DESCR_END  (Packet_PDCH_Release_t)

/*< Packet Power Control/Timing Advance message content >*/
static const
CSN_DESCR_BEGIN(GlobalTimingAndPower_t)
  M_TYPE       (GlobalTimingAndPower_t, Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_TYPE       (GlobalTimingAndPower_t, Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END  (GlobalTimingAndPower_t)

static const
CSN_DESCR_BEGIN(GlobalTimingOrPower_t)
  M_UNION      (GlobalTimingOrPower_t, 2),
  M_TYPE       (GlobalTimingOrPower_t, u.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_TYPE       (GlobalTimingOrPower_t, u.Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END  (GlobalTimingOrPower_t)

static const
CSN_ChoiceElement_t PacketPowerControlTimingAdvanceID[] =
{
  {1, 0,    0, M_TYPE(PacketPowerControlTimingAdvanceID_t, u.Global_TFI, Global_TFI_t)},
  {3, 0x06, 0, M_UINT(PacketPowerControlTimingAdvanceID_t, u.TQI, 16, &hf_tqi)},
  {3, 0x07, 0, M_TYPE(PacketPowerControlTimingAdvanceID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
};

static const
CSN_DESCR_BEGIN(PacketPowerControlTimingAdvanceID_t)
  M_CHOICE     (PacketPowerControlTimingAdvanceID_t, UnionType, PacketPowerControlTimingAdvanceID, ElementsOf(PacketPowerControlTimingAdvanceID)),
CSN_DESCR_END  (PacketPowerControlTimingAdvanceID_t)

static const
CSN_DESCR_BEGIN(Packet_Power_Control_Timing_Advance_t)
  M_UINT       (Packet_Power_Control_Timing_Advance_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Power_Control_Timing_Advance_t, PAGE_MODE, 2, &hf_page_mode),

  M_TYPE       (Packet_Power_Control_Timing_Advance_t, ID, PacketPowerControlTimingAdvanceID_t),

  /*-- Message escape*/
  M_FIXED      (Packet_Power_Control_Timing_Advance_t, 1, 0x00),

  M_NEXT_EXIST (Packet_Power_Control_Timing_Advance_t, Exist_Global_Power_Control_Parameters, 1),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, Global_Power_Control_Parameters, Global_Power_Control_Parameters_t),

  M_UNION      (Packet_Power_Control_Timing_Advance_t, 2),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, u.GlobalTimingAndPower, GlobalTimingAndPower_t),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, u.GlobalTimingOrPower, GlobalTimingOrPower_t),

  M_PADDING_BITS(Packet_Power_Control_Timing_Advance_t),
CSN_DESCR_END  (Packet_Power_Control_Timing_Advance_t)

/*< Packet Queueing Notification message content > */
static const
CSN_DESCR_BEGIN(Packet_Queueing_Notification_t)
  M_UINT       (Packet_Queueing_Notification_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Queueing_Notification_t, PAGE_MODE, 2, &hf_page_mode),

  M_FIXED      (Packet_Queueing_Notification_t, 3, 0x07),/* 111 Fixed */
  M_TYPE       (Packet_Queueing_Notification_t, Packet_Request_Reference, Packet_Request_Reference_t),

  M_UINT       (Packet_Queueing_Notification_t, TQI, 16, &hf_tqi),
  M_PADDING_BITS(Packet_Queueing_Notification_t),
CSN_DESCR_END  (Packet_Queueing_Notification_t)

/* USED in Packet Timeslot Reconfigure message content
 * This is almost the same structure as used in
 * <Packet Uplink Assignment message content> but UPLINK_TFI_ASSIGNMENT is removed.
 */
static const
CSN_DESCR_BEGIN(TRDynamic_Allocation_t)
  M_UINT       (TRDynamic_Allocation_t,  Extended_Dynamic_Allocation,  1, &hf_extended_dynamic_allocation),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (TRDynamic_Allocation_t,  P0, 4, &hf_p0),
  M_UINT       (TRDynamic_Allocation_t,  PR_MODE, 1, &hf_pr_mode),

  M_UINT       (TRDynamic_Allocation_t,  USF_GRANULARITY, 1, &hf_usf_granularity),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED, 1),
  M_UINT       (TRDynamic_Allocation_t,  RLC_DATA_BLOCKS_GRANTED,  8, &hf_rlc_data_blocks_granted),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_TBF_Starting_Time, 1),
  M_TYPE       (TRDynamic_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_UNION      (TRDynamic_Allocation_t, 2),
  M_TYPE_ARRAY (TRDynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (TRDynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (TRDynamic_Allocation_t)

/*< Packet Timeslot Reconfigure message content > */
static const
CSN_DESCR_BEGIN(PTR_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PTR_GPRS_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PTR_GPRS_AdditionsR99_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),
CSN_DESCR_END  (PTR_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PTR_GPRS_t)
  M_UINT              (PTR_GPRS_t,  CHANNEL_CODING_COMMAND,  2, &hf_gprs_channel_coding_command),
  M_TYPE              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_RLC_MODE, 1, &hf_rlc_mode),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.CONTROL_ACK,  1, &hf_control_ack),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TFI_ASSIGNMENT, 5, &hf_downlink_tfi),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.UPLINK_TFI_ASSIGNMENT, 5, &hf_uplink_tfi),

  M_UINT              (PTR_GPRS_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TIMESLOT_ALLOCATION, 8, &hf_dl_timeslot_allocation),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_Frequency_Parameters, 1),
  M_TYPE              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Frequency_Parameters, Frequency_Parameters_t),

  M_UNION             (PTR_GPRS_t, 2),
  M_TYPE              (PTR_GPRS_t, u.Dynamic_Allocation, TRDynamic_Allocation_t),
  CSN_ERROR           (PTR_GPRS_t, "1 - Fixed Allocation was removed", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PTR_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PTR_GPRS_t, AdditionsR99, PTR_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PTR_GPRS_t)

static const
CSN_DESCR_BEGIN(PTR_EGPRS_00_t)
  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE       (PTR_EGPRS_00_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),

  M_UINT       (PTR_EGPRS_00_t,  EGPRS_ChannelCodingCommand, 4, &hf_egprs_channel_coding_command),
  M_UINT       (PTR_EGPRS_00_t,  RESEGMENT,  1, &hf_resegment),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_DOWNLINK_EGPRS_WindowSize, 1),
  M_UINT       (PTR_EGPRS_00_t,  DOWNLINK_EGPRS_WindowSize, 5, &hf_egprs_windowsize),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_UPLINK_EGPRS_WindowSize, 1),
  M_UINT       (PTR_EGPRS_00_t,  UPLINK_EGPRS_WindowSize, 5, &hf_egprs_windowsize),

  M_UINT       (PTR_EGPRS_00_t,  LINK_QUALITY_MEASUREMENT_MODE, 2, &hf_link_quality_measurement_mode),

  M_TYPE       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PTR_EGPRS_00_t,  Packet_Extended_Timing_Advance, 2, &hf_packet_extended_timing_advance),

  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_RLC_MODE, 1, &hf_rlc_mode),
  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.CONTROL_ACK,  1, &hf_control_ack),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_DOWNLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TFI_ASSIGNMENT, 5, &hf_downlink_tfi),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_UPLINK_TFI_ASSIGNMENT, 1),
  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.UPLINK_TFI_ASSIGNMENT, 5, &hf_uplink_tfi),

  M_UINT       (PTR_EGPRS_00_t,  Common_Timeslot_Reconfigure_Data.DOWNLINK_TIMESLOT_ALLOCATION, 8, &hf_dl_timeslot_allocation),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_Frequency_Parameters, 1),
  M_TYPE       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Frequency_Parameters, Frequency_Parameters_t),

  M_UNION      (PTR_EGPRS_00_t, 2),
  M_TYPE       (PTR_EGPRS_00_t, u.Dynamic_Allocation, TRDynamic_Allocation_t),
  CSN_ERROR    (PTR_EGPRS_00_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PTR_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PTR_EGPRS_t)
  M_UNION      (PTR_EGPRS_t, 4),
  M_TYPE       (PTR_EGPRS_t, u.PTR_EGPRS_00, PTR_EGPRS_00_t),
  CSN_ERROR    (PTR_EGPRS_t, "01 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PTR_EGPRS_t, "10 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PTR_EGPRS_t, "11 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PTR_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Timeslot_Reconfigure_t)
  M_UINT       (Packet_Timeslot_Reconfigure_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Timeslot_Reconfigure_t, PAGE_MODE, 2, &hf_page_mode),

  M_FIXED      (Packet_Timeslot_Reconfigure_t, 1, 0x00),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, Global_TFI, Global_TFI_t),

  M_UNION      (Packet_Timeslot_Reconfigure_t, 2),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, u.PTR_GPRS_Struct, PTR_GPRS_t),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, u.PTR_EGPRS_Struct, PTR_EGPRS_t),

  M_PADDING_BITS(Packet_Timeslot_Reconfigure_t),
CSN_DESCR_END  (Packet_Timeslot_Reconfigure_t)

typedef Packet_Timeslot_Reconfigure_t PTRCheck_t;

static const
CSN_DESCR_BEGIN(PTRCheck_t)
  M_UINT       (PTRCheck_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (PTRCheck_t, PAGE_MODE, 2, &hf_page_mode),
  M_FIXED      (PTRCheck_t, 1, 0x00),/* 0 fixed */
  M_TYPE       (PTRCheck_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (PTRCheck_t)

/*< Packet PRACH Parameters message content > */
static const
CSN_DESCR_BEGIN(PRACH_Control_t)
  M_UINT_ARRAY (PRACH_Control_t, ACC_CONTR_CLASS, 8, 2), /* bit (16) == 8bit*2 */
  M_UINT_ARRAY (PRACH_Control_t, MAX_RETRANS, 2, 4), /* bit (2) * 4 */
  M_UINT       (PRACH_Control_t,  S,  4, &hf_prach_control_s),
  M_UINT       (PRACH_Control_t,  TX_INT,  4, &hf_prach_control_tx_int),
  M_NEXT_EXIST (PRACH_Control_t, Exist_PERSISTENCE_LEVEL, 1),
  M_UINT_ARRAY (PRACH_Control_t, PERSISTENCE_LEVEL, 4, 4),
CSN_DESCR_END  (PRACH_Control_t)

static const
CSN_DESCR_BEGIN(Cell_Allocation_t)
  M_REC_ARRAY  (Cell_Allocation_t, RFL_Number, NoOfRFLs, 4),
CSN_DESCR_END  (Cell_Allocation_t)

static const
CSN_DESCR_BEGIN(HCS_t)
  M_UINT       (HCS_t,  PRIORITY_CLASS,  3, &hf_hcs_priority_class),
  M_UINT       (HCS_t,  HCS_THR,  5, &hf_hcs_hcs_thr),
CSN_DESCR_END  (HCS_t)

static const
CSN_DESCR_BEGIN(Location_Repeat_t)
  M_UINT       (Location_Repeat_t,  PBCCH_LOCATION,  2, &hf_location_repeat_pbcch_location),
  M_UINT       (Location_Repeat_t,  PSI1_REPEAT_PERIOD,  4, &hf_location_repeat_psi1_repeat_period),
CSN_DESCR_END  (Location_Repeat_t)

static const
CSN_DESCR_BEGIN(SI13_PBCCH_Location_t)
  M_UNION      (SI13_PBCCH_Location_t, 2),
  M_UINT       (SI13_PBCCH_Location_t,  u.SI13_LOCATION,  1, &hf_si13_pbcch_location_si13_location),
  M_TYPE       (SI13_PBCCH_Location_t, u.lr, Location_Repeat_t),
CSN_DESCR_END  (SI13_PBCCH_Location_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_t)
  M_UINT       (Cell_Selection_t,  BSIC,  6, &hf_cell_selection_bsic),
  M_UINT       (Cell_Selection_t,  CELL_BAR_ACCESS_2,  1, &hf_cell_bar_access_2),
  M_UINT       (Cell_Selection_t,  EXC_ACC,  1, &hf_exc_acc),
  M_UINT       (Cell_Selection_t,  SAME_RA_AS_SERVING_CELL,  1, &hf_cell_selection_same_ra_as_serving_cell),
  M_NEXT_EXIST (Cell_Selection_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (Cell_Selection_t,  GPRS_RXLEV_ACCESS_MIN,  6, &hf_cell_selection_gprs_rxlev_access_min),
  M_UINT       (Cell_Selection_t,  GPRS_MS_TXPWR_MAX_CCH,  5, &hf_cell_selection_gprs_ms_txpwr_max_cch),
  M_NEXT_EXIST (Cell_Selection_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (Cell_Selection_t,  GPRS_TEMPORARY_OFFSET,  3, &hf_cell_selection_gprs_temporary_offset),
  M_UINT       (Cell_Selection_t,  GPRS_PENALTY_TIME,  5, &hf_cell_selection_gprs_penalty_time),
  M_NEXT_EXIST (Cell_Selection_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (Cell_Selection_t,  GPRS_RESELECT_OFFSET,  5, &hf_cell_selection_gprs_reselect_offset),
  M_NEXT_EXIST (Cell_Selection_t, Exist_HCS, 1),
  M_TYPE       (Cell_Selection_t, HCS, HCS_t),
  M_NEXT_EXIST (Cell_Selection_t, Exist_SI13_PBCCH_Location, 1),
  M_TYPE       (Cell_Selection_t, SI13_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (Cell_Selection_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_Params_With_FreqDiff_t)
  M_VAR_BITMAP (Cell_Selection_Params_With_FreqDiff_t, FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_TYPE       (Cell_Selection_Params_With_FreqDiff_t, Cell_SelectionParams, Cell_Selection_t),
CSN_DESCR_END  (Cell_Selection_Params_With_FreqDiff_t)

CSN_CallBackStatus_t callback_init_Cell_Selection_Params_FREQUENCY_DIFF(proto_tree *tree _U_, tvbuff_t *tvb _U_, void* param1, void* param2, int bit_offset _U_, int ett_csn1 _U_)
{
    guint  i;
    guint8 freq_diff_len = *(guint8*)param1;
    Cell_Selection_Params_With_FreqDiff_t *pCell_Sel_Param = (Cell_Selection_Params_With_FreqDiff_t*)param2;

    for( i=0; i<16; i++, pCell_Sel_Param++ )
    {
        pCell_Sel_Param->FREQ_DIFF_LENGTH = freq_diff_len;
    }

    return 0;
}

static const
CSN_DESCR_BEGIN(NeighbourCellParameters_t)
  M_UINT       (NeighbourCellParameters_t,  START_FREQUENCY,  10, &hf_neighbourcellparameters_start_frequency),
  M_TYPE       (NeighbourCellParameters_t, Cell_Selection, Cell_Selection_t),
  M_UINT       (NeighbourCellParameters_t,  NR_OF_REMAINING_CELLS,  4, &hf_neighbourcellparameters_nr_of_remaining_cells),
  M_UINT_OFFSET(NeighbourCellParameters_t, FREQ_DIFF_LENGTH, 3, 1),/* offset 1 */
  M_CALLBACK   (NeighbourCellParameters_t, callback_init_Cell_Selection_Params_FREQUENCY_DIFF, FREQ_DIFF_LENGTH, Cell_Selection_Params_With_FreqDiff),
  M_VAR_TARRAY (NeighbourCellParameters_t, Cell_Selection_Params_With_FreqDiff, Cell_Selection_Params_With_FreqDiff_t, NR_OF_REMAINING_CELLS),
CSN_DESCR_END  (NeighbourCellParameters_t)

static const
CSN_DESCR_BEGIN(NeighbourCellList_t)
  M_REC_TARRAY (NeighbourCellList_t, Parameters, NeighbourCellParameters_t, Count),
CSN_DESCR_END  (NeighbourCellList_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_2_t)
  M_UINT       (Cell_Selection_2_t,  CELL_BAR_ACCESS_2,  1, &hf_cell_bar_access_2),
  M_UINT       (Cell_Selection_2_t,  EXC_ACC,  1, &hf_exc_acc),
  M_UINT       (Cell_Selection_2_t,  SAME_RA_AS_SERVING_CELL,  1, &hf_cell_selection_2_same_ra_as_serving_cell),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (Cell_Selection_2_t,  GPRS_RXLEV_ACCESS_MIN,  6, &hf_cell_selection_2_gprs_rxlev_access_min),
  M_UINT       (Cell_Selection_2_t,  GPRS_MS_TXPWR_MAX_CCH,  5, &hf_cell_selection_2_gprs_ms_txpwr_max_cch),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (Cell_Selection_2_t,  GPRS_TEMPORARY_OFFSET,  3, &hf_cell_selection_2_gprs_temporary_offset),
  M_UINT       (Cell_Selection_2_t,  GPRS_PENALTY_TIME,  5, &hf_cell_selection_2_gprs_penalty_time),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (Cell_Selection_2_t,  GPRS_RESELECT_OFFSET,  5, &hf_cell_selection_2_gprs_reselect_offset),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_HCS, 1),
  M_TYPE       (Cell_Selection_2_t, HCS, HCS_t),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_SI13_PBCCH_Location, 1),
  M_TYPE       (Cell_Selection_2_t, SI13_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (Cell_Selection_2_t)

static const
CSN_DESCR_BEGIN(Packet_PRACH_Parameters_t)
  M_UINT       (Packet_PRACH_Parameters_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_PRACH_Parameters_t, PAGE_MODE, 2, &hf_page_mode),

  M_TYPE       (Packet_PRACH_Parameters_t, PRACH_Control, PRACH_Control_t),
  M_PADDING_BITS(Packet_PRACH_Parameters_t),
CSN_DESCR_END  (Packet_PRACH_Parameters_t)

/* < Packet Access Reject message content > */
static const
CSN_ChoiceElement_t RejectID[] =
{
  {1, 0x00, 0, M_UINT(RejectID_t, u.TLLI, 32, &hf_tlli)},
  {2, 0x02, 0, M_TYPE(RejectID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
  {2, 0x03, 0, M_TYPE(RejectID_t, u.Global_TFI, Global_TFI_t)},
};

static const
CSN_DESCR_BEGIN(RejectID_t)
  M_CHOICE     (RejectID_t, UnionType, RejectID, ElementsOf(RejectID)),
CSN_DESCR_END  (RejectID_t)

static const
CSN_DESCR_BEGIN(Reject_t)
  M_TYPE       (Reject_t, ID, RejectID_t),

  M_NEXT_EXIST (Reject_t, Exist_Wait, 2),
  M_UINT       (Reject_t,  WAIT_INDICATION,  8, &hf_reject_wait_indication),
  M_UINT       (Reject_t,  WAIT_INDICATION_SIZE,  1, &hf_reject_wait_indication_size),
CSN_DESCR_END  (Reject_t)

static const
CSN_DESCR_BEGIN(Packet_Access_Reject_t)
  M_UINT       (Packet_Access_Reject_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Access_Reject_t, PAGE_MODE, 2, &hf_page_mode),

  M_TYPE       (Packet_Access_Reject_t, Reject, Reject_t),
  M_REC_TARRAY (Packet_Access_Reject_t, Reject[1], Reject_t, Count_Reject),
  M_PADDING_BITS(Packet_Access_Reject_t),
CSN_DESCR_END  (Packet_Access_Reject_t)

/* < Packet Cell Change Order message content > */
static const
CSN_ChoiceElement_t PacketCellChangeOrderID[] =
{
  {1, 0,    0, M_TYPE(PacketCellChangeOrderID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, 0, M_UINT(PacketCellChangeOrderID_t, u.TLLI, 32, &hf_tlli)},
};
/* PacketCellChangeOrderID_t; */

static const
CSN_DESCR_BEGIN(PacketCellChangeOrderID_t)
  M_CHOICE     (PacketCellChangeOrderID_t, UnionType, PacketCellChangeOrderID, ElementsOf(PacketCellChangeOrderID)),
CSN_DESCR_END  (PacketCellChangeOrderID_t)

static const
CSN_DESCR_BEGIN(h_FreqBsicCell_t)
  M_UINT       (h_FreqBsicCell_t,  BSIC,  6, &hf_h_freqbsiccell_bsic),
  M_TYPE       (h_FreqBsicCell_t, Cell_Selection, Cell_Selection_t),
CSN_DESCR_END  (h_FreqBsicCell_t)

static const CSN_DESCR_BEGIN(CellSelectionParamsWithFreqDiff_t)
  /*FREQUENCY_DIFF is really an integer but the number of bits to decode it are stored in FREQ_DIFF_LENGTH*/
  M_VAR_BITMAP (CellSelectionParamsWithFreqDiff_t, FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_UINT       (CellSelectionParamsWithFreqDiff_t,  BSIC,  6, &hf_cellselectionparamswithfreqdiff_bsic),
  M_NEXT_EXIST (CellSelectionParamsWithFreqDiff_t, Exist_CellSelectionParams, 1),
  M_TYPE       (CellSelectionParamsWithFreqDiff_t, CellSelectionParams, Cell_Selection_2_t),
CSN_DESCR_END  (CellSelectionParamsWithFreqDiff_t)


CSN_CallBackStatus_t callback_init_Cell_Sel_Param_2_FREQUENCY_DIFF(proto_tree *tree _U_, tvbuff_t *tvb _U_, void* param1, void* param2, int bit_offset _U_, int ett_csn1 _U_)
{
    guint  i;
    guint8 freq_diff_len = *(guint8*)param1;
    CellSelectionParamsWithFreqDiff_t *pCell_Sel_Param = (CellSelectionParamsWithFreqDiff_t*)param2;

    for( i=0; i<16; i++, pCell_Sel_Param++ )
    {
        pCell_Sel_Param->FREQ_DIFF_LENGTH = freq_diff_len;
    }

    return 0;
}


static const
CSN_DESCR_BEGIN(Add_Frequency_list_t)
  M_UINT       (Add_Frequency_list_t,  START_FREQUENCY,  10, &hf_add_frequency_list_start_frequency),
  M_UINT       (Add_Frequency_list_t,  BSIC,  6, &hf_add_frequency_list_bsic),

  M_NEXT_EXIST (Add_Frequency_list_t, Exist_Cell_Selection, 1),
  M_TYPE       (Add_Frequency_list_t, Cell_Selection, Cell_Selection_2_t),

  M_UINT       (Add_Frequency_list_t,  NR_OF_FREQUENCIES,  5, &hf_add_frequency_list_nr_of_frequencies),
  M_UINT_OFFSET(Add_Frequency_list_t, FREQ_DIFF_LENGTH, 3, 1),/*offset 1*/

  M_CALLBACK   (Add_Frequency_list_t, callback_init_Cell_Sel_Param_2_FREQUENCY_DIFF, FREQ_DIFF_LENGTH, CellSelectionParamsWithFreqDiff),

  M_VAR_TARRAY (Add_Frequency_list_t, CellSelectionParamsWithFreqDiff, CellSelectionParamsWithFreqDiff_t, NR_OF_FREQUENCIES),
CSN_DESCR_END  (Add_Frequency_list_t)

static const CSN_DESCR_BEGIN(Removed_Freq_Index_t)
  M_UINT(Removed_Freq_Index_t, REMOVED_FREQ_INDEX, 6, &hf_removed_freq_index_removed_freq_index),
CSN_DESCR_END(Removed_Freq_Index_t)

static const
CSN_DESCR_BEGIN(NC_Frequency_list_t)
  M_NEXT_EXIST (NC_Frequency_list_t, Exist_REMOVED_FREQ, 2),
  M_UINT_OFFSET(NC_Frequency_list_t, NR_OF_REMOVED_FREQ, 5, 1),/*offset 1*/
  M_VAR_TARRAY (NC_Frequency_list_t, Removed_Freq_Index, Removed_Freq_Index_t, NR_OF_REMOVED_FREQ),
  M_REC_TARRAY (NC_Frequency_list_t, Add_Frequency, Add_Frequency_list_t, Count_Add_Frequency),
CSN_DESCR_END  (NC_Frequency_list_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Parameters_t)
  M_UINT       (NC_Measurement_Parameters_t,  NETWORK_CONTROL_ORDER,  2, &hf_nc_measurement_parameters_network_control_order),

  M_NEXT_EXIST (NC_Measurement_Parameters_t, Exist_NC, 3),
  M_UINT       (NC_Measurement_Parameters_t,  NC_NON_DRX_PERIOD,  3, &hf_nc_measurement_parameters_nc_non_drx_period),
  M_UINT       (NC_Measurement_Parameters_t,  NC_REPORTING_PERIOD_I,  3, &hf_nc_measurement_parameters_nc_reporting_period_i),
  M_UINT       (NC_Measurement_Parameters_t,  NC_REPORTING_PERIOD_T,  3, &hf_nc_measurement_parameters_nc_reporting_period_t),
CSN_DESCR_END  (NC_Measurement_Parameters_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Parameters_with_Frequency_List_t)
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NETWORK_CONTROL_ORDER,  2, &hf_nc_measurement_parameters_with_frequency_list_network_control_order),

  M_NEXT_EXIST (NC_Measurement_Parameters_with_Frequency_List_t, Exist_NC, 3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NC_NON_DRX_PERIOD,  3, &hf_nc_measurement_parameters_with_frequency_list_nc_non_drx_period),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NC_REPORTING_PERIOD_I,  3, &hf_nc_measurement_parameters_with_frequency_list_nc_reporting_period_i),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t,  NC_REPORTING_PERIOD_T,  3, &hf_nc_measurement_parameters_with_frequency_list_nc_reporting_period_t),

  M_NEXT_EXIST (NC_Measurement_Parameters_with_Frequency_List_t, Exist_NC_FREQUENCY_LIST, 1),
  M_TYPE       (NC_Measurement_Parameters_with_Frequency_List_t, NC_Frequency_list, NC_Frequency_list_t),
CSN_DESCR_END  (NC_Measurement_Parameters_with_Frequency_List_t)

/*< Packet Cell Change Order message contents >*/
static const
CSN_DESCR_BEGIN(BA_IND_t)
  M_UINT       (BA_IND_t,  BA_IND,  1, &hf_ba_ind_ba_ind),
  M_UINT       (BA_IND_t,  BA_IND_3G,  1, &hf_ba_ind_ba_ind_3g),
CSN_DESCR_END  (BA_IND_t)

static const
CSN_DESCR_BEGIN(GPRSReportPriority_t)
  M_UINT       (GPRSReportPriority_t,  NUMBER_CELLS,  7, &hf_gprsreportpriority_number_cells),
  M_VAR_BITMAP (GPRSReportPriority_t, REPORT_PRIORITY, NUMBER_CELLS, 0),
CSN_DESCR_END  (GPRSReportPriority_t)

static const
CSN_DESCR_BEGIN(OffsetThreshold_t)
  M_UINT       (OffsetThreshold_t,  REPORTING_OFFSET,  3, &hf_offsetthreshold_reporting_offset),
  M_UINT       (OffsetThreshold_t,  REPORTING_THRESHOLD,  3, &hf_offsetthreshold_reporting_threshold),
CSN_DESCR_END  (OffsetThreshold_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams_PMO_PCCO_t)
  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_MULTI_BAND_REPORTING, 1),
  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t,  MULTI_BAND_REPORTING,  2, &hf_gprsmeasurementparams_pmo_pcco_multi_band_reporting),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_SERVING_BAND_REPORTING, 1),
  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t,  SERVING_BAND_REPORTING,  2, &hf_gprsmeasurementparams_pmo_pcco_serving_band_reporting),

  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t,  SCALE_ORD,  2, &hf_gprsmeasurementparams_pmo_pcco_scale_ord),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold900, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold900, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold1800, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold1800, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold400, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold400, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold1900, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold1900, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold850, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold850, OffsetThreshold_t),
CSN_DESCR_END  (GPRSMeasurementParams_PMO_PCCO_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams3G_t)
  M_UINT       (GPRSMeasurementParams3G_t,  Qsearch_p,  4, &hf_gprsmeasurementparams3g_qsearch_p),
  M_UINT       (GPRSMeasurementParams3G_t,  SearchPrio3G,  1, &hf_gprsmeasurementparams3g_searchprio3g),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existRepParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t,  RepQuantFDD,  1, &hf_gprsmeasurementparams3g_repquantfdd),
  M_UINT       (GPRSMeasurementParams3G_t,  MultiratReportingFDD,  2, &hf_gprsmeasurementparams3g_multiratreportingfdd),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existReportingParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingOffsetFDD,  3, &hf_gprsmeasurementparams3g_reportingoffsetfdd),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingThresholdFDD,  3, &hf_gprsmeasurementparams3g_reportingthresholdfdd),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existMultiratReportingTDD, 1),
  M_UINT       (GPRSMeasurementParams3G_t,  MultiratReportingTDD,  2, &hf_gprsmeasurementparams3g_multiratreportingtdd),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existOffsetThresholdTDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingOffsetTDD,  3, &hf_gprsmeasurementparams3g_reportingoffsettdd),
  M_UINT       (GPRSMeasurementParams3G_t,  ReportingThresholdTDD,  3, &hf_gprsmeasurementparams3g_reportingthresholdtdd),
CSN_DESCR_END  (GPRSMeasurementParams3G_t)

static const
CSN_DESCR_BEGIN(MultiratParams3G_t)
  M_NEXT_EXIST (MultiratParams3G_t, existMultiratReporting, 1),
  M_UINT       (MultiratParams3G_t,  MultiratReporting,  2, &hf_multiratparams3g_multiratreporting),

  M_NEXT_EXIST (MultiratParams3G_t, existOffsetThreshold, 1),
  M_TYPE       (MultiratParams3G_t, OffsetThreshold, OffsetThreshold_t),
CSN_DESCR_END  (MultiratParams3G_t)

static const
CSN_DESCR_BEGIN(ENH_GPRSMeasurementParams3G_PMO_t)
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  Qsearch_P,  4, &hf_enh_gprsmeasurementparams3g_pmo_qsearch_p),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  SearchPrio3G,  1, &hf_enh_gprsmeasurementparams3g_pmo_searchprio3g),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PMO_t, existRepParamsFDD, 2),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  RepQuantFDD,  1, &hf_enh_gprsmeasurementparams3g_pmo_repquantfdd),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t,  MultiratReportingFDD,  2, &hf_enh_gprsmeasurementparams3g_pmo_multiratreportingfdd),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PMO_t, existOffsetThreshold, 1),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, OffsetThreshold, OffsetThreshold_t),

  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, ParamsTDD, MultiratParams3G_t),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, ParamsCDMA2000, MultiratParams3G_t),
CSN_DESCR_END  (ENH_GPRSMeasurementParams3G_PMO_t)

static const
CSN_DESCR_BEGIN(ENH_GPRSMeasurementParams3G_PCCO_t)
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  Qsearch_P,  4, &hf_enh_gprsmeasurementparams3g_pcco_qsearch_p),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  SearchPrio3G,  1, &hf_enh_gprsmeasurementparams3g_pcco_searchprio3g),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PCCO_t, existRepParamsFDD, 2),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  RepQuantFDD,  1, &hf_enh_gprsmeasurementparams3g_pcco_repquantfdd),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t,  MultiratReportingFDD,  2, &hf_enh_gprsmeasurementparams3g_pcco_multiratreportingfdd),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PCCO_t, existOffsetThreshold, 1),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PCCO_t, OffsetThreshold, OffsetThreshold_t),

  M_TYPE       (ENH_GPRSMeasurementParams3G_PCCO_t, ParamsTDD, MultiratParams3G_t),
CSN_DESCR_END  (ENH_GPRSMeasurementParams3G_PCCO_t)

static const
CSN_DESCR_BEGIN(N2_t)
  M_UINT       (N2_t,  REMOVED_3GCELL_INDEX,  7, &hf_n2_removed_3gcell_index),
  M_UINT       (N2_t,  CELL_DIFF_LENGTH_3G,  3, &hf_n2_cell_diff_length_3g),
  M_VAR_BITMAP (N2_t, CELL_DIFF_3G, CELL_DIFF_LENGTH_3G, 0),
CSN_DESCR_END  (N2_t)

static const
CSN_DESCR_BEGIN (N1_t)
  M_UINT_OFFSET (N1_t, N2_Count, 5, 1), /*offset 1*/
  M_VAR_TARRAY  (N1_t, N2s, N2_t, N2_Count),
CSN_DESCR_END   (N1_t)

static const
CSN_DESCR_BEGIN (Removed3GCellDescription_t)
  M_UINT_OFFSET (Removed3GCellDescription_t, N1_Count, 2, 1),  /* offset 1 */
  M_VAR_TARRAY  (Removed3GCellDescription_t, N1s, N1_t, N1_Count),
CSN_DESCR_END   (Removed3GCellDescription_t)

static const
CSN_DESCR_BEGIN(CDMA2000_Description_t)
  M_UINT       (CDMA2000_Description_t,  Complete_This,  1, &hf_cdma2000_description_complete_this),
  CSN_ERROR    (CDMA2000_Description_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (CDMA2000_Description_t)

static const guint8 NR_OF_FDD_CELLS_map[32] = {0, 10, 19, 28, 36, 44, 52, 60, 67, 74, 81, 88, 95, 102, 109, 116, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
CSN_CallBackStatus_t callback_UTRAN_FDD_map_NrOfFrequencies(proto_tree *tree _U_, tvbuff_t *tvb _U_, void* param1, void* param2, int bit_offset _U_, int ett_csn1 _U_)
{   /* TS 44.060 Table 11.2.9b.2.a */
    guint8 * pNrOfCells = (guint8*)param1;
    guint8 * pBitsInCellInfo = (guint8*)param2;

    if( *pNrOfCells < 32 )
    {
        *pBitsInCellInfo = NR_OF_FDD_CELLS_map[*pNrOfCells];
    }
    else
    {
        *pBitsInCellInfo = 0;
    }

    return 0;
}

CSN_CallBackStatus_t callback_UTRAN_FDD_compute_FDD_CELL_INFORMATION(proto_tree *tree, tvbuff_t *tvb, void* param1, void* param2 _U_, int bit_offset, int ett_csn1)
{
    proto_item   *ti;
    proto_tree   *subtree;
    UTRAN_FDD_NeighbourCells_t * pUtranFddNcell = (UTRAN_FDD_NeighbourCells_t*)param1;
    gint xdd_cell_info, wsize, nwi, jwi, w[64], i, iused;
    gint curr_bit_offset, idx;

    curr_bit_offset = bit_offset;
    idx = pUtranFddNcell->BitsInCellInfo;

    if( idx > 0 )
    {
        ti = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1,  "FDD_CELL_INFORMATION: ");
        subtree = proto_item_add_subtree(ti, ett_csn1);
        
        if (pUtranFddNcell->Indic0)
        {
            proto_tree_add_text(tree,tvb, curr_bit_offset>>3, 0, "Scrambling Code: %d", 0);
            proto_tree_add_text(tree,tvb, curr_bit_offset>>3, 0, "Diversity: %d", 0);
        }

        if (idx)
        {
            wsize = 10;
            nwi = 1;
            jwi = 0;
            i = 1;

            while (idx > 0)
            {
                w[i] = tvb_get_bits(tvb, curr_bit_offset, wsize, ENC_BIG_ENDIAN);
                curr_bit_offset += wsize;
                idx -= wsize;
                if (w[i] == 0)
                {
                    idx = 0;
                    break;
                }
                if (++jwi==nwi)
                {
                    jwi = 0;
                    nwi <<= 1;
                    wsize--;
                }
                i++;
            }
            if (idx < 0)
            {
                curr_bit_offset += idx;
            }
            iused = i-1;

            for (i=1; i <= iused; i++)
            {
                xdd_cell_info = f_k(i, w, 1024);
                proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 0, "Scrambling Code: %d", xdd_cell_info & 0x01FF);
                proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 0, "Diversity: %d", (xdd_cell_info >> 9) & 0x01);
            }
        }
    }

    return curr_bit_offset - bit_offset;
}



static const
CSN_DESCR_BEGIN(UTRAN_FDD_NeighbourCells_t)
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  ZERO,      1, &hf_utran_fdd_neighbourcells_zero),
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  UARFCN,   14, &hf_utran_fdd_neighbourcells_uarfcn),
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  Indic0,      1, &hf_utran_fdd_neighbourcells_indic0),
  M_UINT       (UTRAN_FDD_NeighbourCells_t,  NrOfCells,   5, &hf_utran_fdd_neighbourcells_nrofcells),
  M_VAR_BITMAP (UTRAN_FDD_NeighbourCells_t, CellInfo,  BitsInCellInfo, 0),
CSN_DESCR_END  (UTRAN_FDD_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(UTRAN_FDD_Description_t)
  M_NEXT_EXIST (UTRAN_FDD_Description_t, existBandwidth, 1),
  M_UINT       (UTRAN_FDD_Description_t,  Bandwidth,       3, &hf_utran_fdd_description_bandwidth),
  M_REC_TARRAY (UTRAN_FDD_Description_t, CellParams, UTRAN_FDD_NeighbourCells_t, NrOfFrequencies),
CSN_DESCR_END  (UTRAN_FDD_Description_t)


static const guint8 NR_OF_TDD_CELLS_map[32] = {0, 9, 17, 25, 32, 39, 46, 53, 59, 65, 71, 77, 83, 89, 95, 101, 106, 111, 116, 121, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
CSN_CallBackStatus_t callback_UTRAN_TDD_map_NrOfFrequencies(proto_tree *tree _U_, tvbuff_t *tvb _U_, void* param1, void* param2, int bit_offset _U_, int ett_csn1 _U_)
{  /* TS 44.060 Table 11.2.9b.2.b */
    guint8 * pNrOfCells = (guint8*)param1;
    guint8 * pBitsInCellInfo = (guint8*)param2;

    if( *pNrOfCells < 32 )
    {
        *pBitsInCellInfo = NR_OF_TDD_CELLS_map[*pNrOfCells];
    }
    else
    {
        *pBitsInCellInfo = 0;
    }

    return 0;
}

CSN_CallBackStatus_t callback_UTRAN_TDD_compute_TDD_CELL_INFORMATION(proto_tree *tree, tvbuff_t *tvb, void* param1, void* param2 _U_, int bit_offset, int ett_csn1)
{
    proto_item   *ti;
    proto_tree   *subtree;
    UTRAN_TDD_NeighbourCells_t * pUtranTddNcell = (UTRAN_TDD_NeighbourCells_t*)param1;
    gint xdd_cell_info, wsize, nwi, jwi, w[64], i, iused;
    gint curr_bit_offset, idx;

    curr_bit_offset = bit_offset;
    idx = pUtranTddNcell->BitsInCellInfo;

    if( idx > 0 )
    {
        ti = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1,  "TDD_CELL_INFORMATION: ");
        subtree = proto_item_add_subtree(ti, ett_csn1);
        
        if (pUtranTddNcell->Indic0)
        {
            proto_tree_add_text(tree,tvb, curr_bit_offset>>3, 0, "Cell Parameter: %d", 0);
            proto_tree_add_text(tree,tvb, curr_bit_offset>>3, 0, "Sync Case TSTD: %d", 0);
            proto_tree_add_text(tree,tvb, curr_bit_offset>>3, 0, "Diversity TDD: %d", 0);
        }

        if (idx)
        {
            wsize = 10;
            nwi = 1;
            jwi = 0;
            i = 1;

            while (idx > 0)
            {
                w[i] = tvb_get_bits(tvb, curr_bit_offset, wsize, ENC_BIG_ENDIAN);
                curr_bit_offset += wsize;
                idx -= wsize;
                if (w[i] == 0)
                {
                    idx = 0;
                    break;
                }
                if (++jwi==nwi)
                {
                    jwi = 0;
                    nwi <<= 1;
                    wsize--;
                }
                i++;
            }
            if (idx < 0)
            {
                curr_bit_offset += idx;
            }
            iused = i-1;

            for (i=1; i <= iused; i++)
            {
                xdd_cell_info = f_k(i, w, 1024);
                proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 0, "Cell Parameter: %d", xdd_cell_info & 0x007F);
                proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 0, "Sync Case TSTD: %d", (xdd_cell_info >> 7) & 0x01);
                proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 0, "Diversity TDD: %d", (xdd_cell_info >> 8) & 0x01);
            }
        }
    }

    return curr_bit_offset - bit_offset;
}


static const
CSN_DESCR_BEGIN(UTRAN_TDD_NeighbourCells_t)
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  ZERO,      1, &hf_utran_tdd_neighbourcells_zero),
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  UARFCN,   14, &hf_utran_tdd_neighbourcells_uarfcn),
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  Indic0,      1, &hf_utran_tdd_neighbourcells_indic0),
  M_UINT       (UTRAN_TDD_NeighbourCells_t,  NrOfCells,   5, &hf_utran_tdd_neighbourcells_nrofcells),
  M_CALLBACK   (UTRAN_TDD_NeighbourCells_t,  callback_UTRAN_TDD_map_NrOfFrequencies, NrOfCells, BitsInCellInfo),
  M_CALLBACK   (UTRAN_TDD_NeighbourCells_t,  callback_UTRAN_TDD_compute_TDD_CELL_INFORMATION, ZERO, CellInfo),
CSN_DESCR_END  (UTRAN_TDD_NeighbourCells_t)


static const
CSN_DESCR_BEGIN(UTRAN_TDD_Description_t)
  M_NEXT_EXIST (UTRAN_TDD_Description_t, existBandwidth, 1),
  M_UINT       (UTRAN_TDD_Description_t,  Bandwidth,       3, &hf_utran_tdd_description_bandwidth),
  M_REC_TARRAY (UTRAN_TDD_Description_t, CellParams, UTRAN_TDD_NeighbourCells_t, NrOfFrequencies),
CSN_DESCR_END  (UTRAN_TDD_Description_t)

static const
CSN_DESCR_BEGIN(NeighbourCellDescription3G_PMO_t)
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Index_Start_3G, 1),
  M_UINT       (NeighbourCellDescription3G_PMO_t,  Index_Start_3G, 7, &hf_index_start_3g),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Absolute_Index_Start_EMR, 1),
  M_UINT       (NeighbourCellDescription3G_PMO_t,  Absolute_Index_Start_EMR, 7, &hf_absolute_index_start_emr),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_UTRAN_FDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, UTRAN_FDD_Description, UTRAN_FDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_UTRAN_TDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, UTRAN_TDD_Description, UTRAN_TDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_CDMA2000_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, CDMA2000_Description, CDMA2000_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Removed3GCellDescription, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, Removed3GCellDescription, Removed3GCellDescription_t),
CSN_DESCR_END  (NeighbourCellDescription3G_PMO_t)

static const
CSN_DESCR_BEGIN(NeighbourCellDescription3G_PCCO_t)
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Index_Start_3G, 1),
  M_UINT       (NeighbourCellDescription3G_PCCO_t,  Index_Start_3G, 7, &hf_index_start_3g),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Absolute_Index_Start_EMR, 1),
  M_UINT       (NeighbourCellDescription3G_PCCO_t,  Absolute_Index_Start_EMR, 7, &hf_absolute_index_start_emr),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_UTRAN_FDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, UTRAN_FDD_Description, UTRAN_FDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_UTRAN_TDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, UTRAN_TDD_Description, UTRAN_TDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Removed3GCellDescription, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, Removed3GCellDescription, Removed3GCellDescription_t),
CSN_DESCR_END  (NeighbourCellDescription3G_PCCO_t)

static const
CSN_DESCR_BEGIN(ENH_Measurement_Parameters_PMO_t)
  M_UNION      (ENH_Measurement_Parameters_PMO_t, 2),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, u.BA_IND, BA_IND_t),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  u.PSI3_CHANGE_MARK, 2, &hf_psi3_change_mark),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  PMO_IND,  1, &hf_enh_measurement_parameters_pmo_pmo_ind),

  M_UINT       (ENH_Measurement_Parameters_PMO_t,  REPORT_TYPE,  1, &hf_enh_measurement_parameters_pmo_report_type),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  REPORTING_RATE,  1, &hf_enh_measurement_parameters_pmo_reporting_rate),
  M_UINT       (ENH_Measurement_Parameters_PMO_t,  INVALID_BSIC_REPORTING,  1, &hf_enh_measurement_parameters_pmo_invalid_bsic_reporting),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_NeighbourCellDescription3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, NeighbourCellDescription3G, NeighbourCellDescription3G_PMO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSReportPriority, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSReportPriority, GPRSReportPriority_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSMeasurementParams, GPRSMeasurementParams_PMO_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSMeasurementParams3G, ENH_GPRSMeasurementParams3G_PMO_t),
CSN_DESCR_END  (ENH_Measurement_Parameters_PMO_t)

static const
CSN_DESCR_BEGIN(ENH_Measurement_Parameters_PCCO_t)
  M_UNION      (ENH_Measurement_Parameters_PCCO_t, 2),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, u.BA_IND, BA_IND_t),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  u.PSI3_CHANGE_MARK, 2, &hf_psi3_change_mark),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  PMO_IND,  1, &hf_enh_measurement_parameters_pcco_pmo_ind),

  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  REPORT_TYPE,  1, &hf_enh_measurement_parameters_pcco_report_type),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  REPORTING_RATE,  1, &hf_enh_measurement_parameters_pcco_reporting_rate),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t,  INVALID_BSIC_REPORTING,  1, &hf_enh_measurement_parameters_pcco_invalid_bsic_reporting),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_NeighbourCellDescription3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, NeighbourCellDescription3G, NeighbourCellDescription3G_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSReportPriority, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSReportPriority, GPRSReportPriority_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSMeasurementParams, GPRSMeasurementParams_PMO_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSMeasurementParams3G, ENH_GPRSMeasurementParams3G_PCCO_t),
CSN_DESCR_END  (ENH_Measurement_Parameters_PCCO_t)

static const
CSN_DESCR_BEGIN(CCN_Support_Description_t)
  M_UINT       (CCN_Support_Description_t,  NUMBER_CELLS,  7, &hf_ccn_support_description_number_cells),
  M_VAR_BITMAP (CCN_Support_Description_t, CCN_SUPPORTED, NUMBER_CELLS, 0),
CSN_DESCR_END  (CCN_Support_Description_t)

static const
CSN_DESCR_BEGIN(lu_ModeCellSelectionParameters_t)
  M_UINT       (lu_ModeCellSelectionParameters_t,  CELL_BAR_QUALIFY_3,  2, &hf_lu_modecellselectionparameters_cell_bar_qualify_3),
  M_NEXT_EXIST (lu_ModeCellSelectionParameters_t, Exist_SI13_Alt_PBCCH_Location, 1),
  M_TYPE       (lu_ModeCellSelectionParameters_t, SI13_Alt_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (lu_ModeCellSelectionParameters_t)

static const
CSN_DESCR_BEGIN(lu_ModeCellSelectionParams_t)
  M_NEXT_EXIST (lu_ModeCellSelectionParams_t, Exist_lu_ModeCellSelectionParams, 1),
  M_TYPE       (lu_ModeCellSelectionParams_t, lu_ModeCellSelectionParameters, lu_ModeCellSelectionParameters_t),
CSN_DESCR_END  (lu_ModeCellSelectionParams_t)

static const
CSN_DESCR_BEGIN(lu_ModeNeighbourCellParams_t)
  M_TYPE       (lu_ModeNeighbourCellParams_t, lu_ModeCellSelectionParameters, lu_ModeCellSelectionParams_t),
  M_UINT       (lu_ModeNeighbourCellParams_t,  NR_OF_FREQUENCIES,  5, &hf_lu_modeneighbourcellparams_nr_of_frequencies),
  M_VAR_TARRAY (lu_ModeNeighbourCellParams_t, lu_ModeCellSelectionParams, lu_ModeCellSelectionParams_t, NR_OF_FREQUENCIES),
CSN_DESCR_END  (lu_ModeNeighbourCellParams_t)

static const
CSN_DESCR_BEGIN(lu_ModeOnlyCellSelection_t)
  M_UINT       (lu_ModeOnlyCellSelection_t,  CELL_BAR_QUALIFY_3,  2, &hf_lu_modeonlycellselection_cell_bar_qualify_3),
  M_UINT       (lu_ModeOnlyCellSelection_t,  SAME_RA_AS_SERVING_CELL,  1, &hf_lu_modeonlycellselection_same_ra_as_serving_cell),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_RXLEV_ACCESS_MIN,  6, &hf_lu_modeonlycellselection_gprs_rxlev_access_min),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_MS_TXPWR_MAX_CCH,  5, &hf_lu_modeonlycellselection_gprs_ms_txpwr_max_cch),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_TEMPORARY_OFFSET,  3, &hf_lu_modeonlycellselection_gprs_temporary_offset),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_PENALTY_TIME,  5, &hf_lu_modeonlycellselection_gprs_penalty_time),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (lu_ModeOnlyCellSelection_t,  GPRS_RESELECT_OFFSET,  5, &hf_lu_modeonlycellselection_gprs_reselect_offset),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_HCS, 1),
  M_TYPE       (lu_ModeOnlyCellSelection_t, HCS, HCS_t),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_SI13_Alt_PBCCH_Location, 1),
  M_TYPE       (lu_ModeOnlyCellSelection_t, SI13_Alt_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (lu_ModeOnlyCellSelection_t)

static const
CSN_DESCR_BEGIN(lu_ModeOnlyCellSelectionParamsWithFreqDiff_t)
  /*FREQUENCY_DIFF is really an integer but the number of bits to decode it are stored in FREQ_DIFF_LENGTH*/
  M_VAR_BITMAP (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_UINT       (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t,  BSIC,  6, &hf_lu_modeonlycellselectionparamswithfreqdiff_bsic),
  M_NEXT_EXIST (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, Exist_lu_ModeOnlyCellSelectionParams, 1),
  M_TYPE       (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, lu_ModeOnlyCellSelectionParams, lu_ModeOnlyCellSelection_t),
CSN_DESCR_END  (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t)

CSN_CallBackStatus_t callback_init_luMode_Cell_Sel_Param_FREQUENCY_DIFF(proto_tree *tree _U_, tvbuff_t *tvb _U_, void* param1, void* param2, int bit_offset _U_, int ett_csn1 _U_)
{
    guint  i;
    guint8 freq_diff_len = *(guint8*)param1;
    lu_ModeOnlyCellSelectionParamsWithFreqDiff_t *pArray = (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t*)param2;

    for( i=0; i<16; i++, pArray++ )
    {
        pArray->FREQ_DIFF_LENGTH = freq_diff_len;
    }

    return 0;
}

static const
CSN_DESCR_BEGIN(Add_lu_ModeOnlyFrequencyList_t)
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  START_FREQUENCY,  10, &hf_add_lu_modeonlyfrequencylist_start_frequency),
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  BSIC,  6, &hf_add_lu_modeonlyfrequencylist_bsic),

  M_NEXT_EXIST (Add_lu_ModeOnlyFrequencyList_t, Exist_lu_ModeCellSelection, 1),
  M_TYPE       (Add_lu_ModeOnlyFrequencyList_t, lu_ModeOnlyCellSelection, lu_ModeOnlyCellSelection_t),

  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  NR_OF_FREQUENCIES,  5, &hf_add_lu_modeonlyfrequencylist_nr_of_frequencies),
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t,  FREQ_DIFF_LENGTH,  3, &hf_add_lu_modeonlyfrequencylist_freq_diff_length),

  M_CALLBACK   (Add_lu_ModeOnlyFrequencyList_t, callback_init_luMode_Cell_Sel_Param_FREQUENCY_DIFF, FREQ_DIFF_LENGTH, lu_ModeOnlyCellSelectionParamsWithFreqDiff),

  M_VAR_TARRAY (Add_lu_ModeOnlyFrequencyList_t, lu_ModeOnlyCellSelectionParamsWithFreqDiff, lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, NR_OF_FREQUENCIES),
CSN_DESCR_END  (Add_lu_ModeOnlyFrequencyList_t)

static const
CSN_DESCR_BEGIN(NC_lu_ModeOnlyCapableCellList_t)
  M_REC_TARRAY (NC_lu_ModeOnlyCapableCellList_t, Add_lu_ModeOnlyFrequencyList, Add_lu_ModeOnlyFrequencyList_t, Count_Add_lu_ModeOnlyFrequencyList),
CSN_DESCR_END  (NC_lu_ModeOnlyCapableCellList_t)

static const
CSN_DESCR_BEGIN(GPRS_AdditionalMeasurementParams3G_t)
  M_NEXT_EXIST (GPRS_AdditionalMeasurementParams3G_t, Exist_FDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (GPRS_AdditionalMeasurementParams3G_t,  FDD_REPORTING_THRESHOLD_2,  6, &hf_gprs_additionalmeasurementparams3g_fdd_reporting_threshold_2),
CSN_DESCR_END  (GPRS_AdditionalMeasurementParams3G_t)

static const
CSN_DESCR_BEGIN(ServingCellPriorityParametersDescription_t)
  M_UINT       (ServingCellPriorityParametersDescription_t,  GERAN_PRIORITY,  3, &hf_servingcellpriorityparametersdescription_geran_priority),
  M_UINT       (ServingCellPriorityParametersDescription_t,  THRESH_Priority_Search,  4, &hf_servingcellpriorityparametersdescription_thresh_priority_search),
  M_UINT       (ServingCellPriorityParametersDescription_t,  THRESH_GSM_low,  4, &hf_servingcellpriorityparametersdescription_thresh_gsm_low),
  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2, &hf_servingcellpriorityparametersdescription_h_prio),
  M_UINT       (ServingCellPriorityParametersDescription_t,  T_Reselection,  2, &hf_servingcellpriorityparametersdescription_t_reselection),
CSN_DESCR_END  (ServingCellPriorityParametersDescription_t)

static const
CSN_DESCR_BEGIN(RepeatedUTRAN_PriorityParameters_t)
  M_REC_ARRAY  (RepeatedUTRAN_PriorityParameters_t, UTRAN_FREQUENCY_INDEX_a, NumberOfFrequencyIndexes, 5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existUTRAN_PRIORITY, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  UTRAN_PRIORITY,  3, &hf_repeatedutran_priorityparameters_utran_priority),

  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  THRESH_UTRAN_high,  5, &hf_repeatedutran_priorityparameters_thresh_utran_high),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existTHRESH_UTRAN_low, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  THRESH_UTRAN_low,  5, &hf_repeatedutran_priorityparameters_thresh_utran_low),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existUTRAN_QRXLEVMIN, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t,  UTRAN_QRXLEVMIN,  5, &hf_repeatedutran_priorityparameters_utran_qrxlevmin),
CSN_DESCR_END  (RepeatedUTRAN_PriorityParameters_t)

static const
CSN_DESCR_BEGIN(PriorityParametersDescription3G_PMO_t)

  M_NEXT_EXIST (PriorityParametersDescription3G_PMO_t, existDEFAULT_UTRAN_Parameters, 3),
  M_UINT       (PriorityParametersDescription3G_PMO_t,  DEFAULT_UTRAN_PRIORITY,  3, &hf_priorityparametersdescription3g_pmo_default_utran_priority),
  M_UINT       (PriorityParametersDescription3G_PMO_t,  DEFAULT_THRESH_UTRAN,  5, &hf_priorityparametersdescription3g_pmo_default_thresh_utran),
  M_UINT       (PriorityParametersDescription3G_PMO_t,  DEFAULT_UTRAN_QRXLEVMIN,  5, &hf_priorityparametersdescription3g_pmo_default_utran_qrxlevmin),

  M_REC_TARRAY (PriorityParametersDescription3G_PMO_t, RepeatedUTRAN_PriorityParameters_a, RepeatedUTRAN_PriorityParameters_t, NumberOfPriorityParameters),
CSN_DESCR_END  (PriorityParametersDescription3G_PMO_t)

static const
CSN_DESCR_BEGIN(EUTRAN_REPORTING_THRESHOLD_OFFSET_t)
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_THRESHOLD_OFFSET, 5),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_FDD_REPORTING_THRESHOLD,  3, &hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_threshold),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_FDD_REPORTING_THRESHOLD_2,  6, &hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_threshold_2),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_OFFSET, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_FDD_REPORTING_OFFSET,  3, &hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_offset),

  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_THRESHOLD_OFFSET, 5),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_TDD_REPORTING_THRESHOLD,  3, &hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_threshold),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_TDD_REPORTING_THRESHOLD_2,  6, &hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_threshold_2),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_OFFSET, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t,  EUTRAN_TDD_REPORTING_OFFSET,  3, &hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_offset),
CSN_DESCR_END  (EUTRAN_REPORTING_THRESHOLD_OFFSET_t)

static const
CSN_DESCR_BEGIN(GPRS_EUTRAN_MeasurementParametersDescription_t)
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t,  Qsearch_P_EUTRAN,  4, &hf_gprs_eutran_measurementparametersdescription_qsearch_p_eutran),
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t,  EUTRAN_REP_QUANT, 1, &hf_gprs_eutran_measurementparametersdescription_eutran_rep_quant),
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t,  EUTRAN_MULTIRAT_REPORTING,  2, &hf_gprs_eutran_measurementparametersdescription_eutran_multirat_reporting),
  M_TYPE       (GPRS_EUTRAN_MeasurementParametersDescription_t, EUTRAN_REPORTING_THRESHOLD_OFFSET, EUTRAN_REPORTING_THRESHOLD_OFFSET_t),
CSN_DESCR_END  (GPRS_EUTRAN_MeasurementParametersDescription_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_Cells_t)
  M_UINT       (RepeatedEUTRAN_Cells_t,  EARFCN,  16, &hf_repeatedeutran_cells_earfcn),
  M_NEXT_EXIST (RepeatedEUTRAN_Cells_t, existMeasurementBandwidth, 1),
  M_UINT       (RepeatedEUTRAN_Cells_t,  MeasurementBandwidth,  3, &hf_repeatedeutran_cells_measurementbandwidth),
CSN_DESCR_END  (RepeatedEUTRAN_Cells_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_NeighbourCells_t)
  M_REC_TARRAY (RepeatedEUTRAN_NeighbourCells_t, EUTRAN_Cells_a, RepeatedEUTRAN_Cells_t, nbrOfEUTRAN_Cells),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existEUTRAN_PRIORITY, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  EUTRAN_PRIORITY,  3, &hf_repeatedeutran_neighbourcells_eutran_priority),

  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  THRESH_EUTRAN_high,  5, &hf_repeatedeutran_neighbourcells_thresh_eutran_high),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existTHRESH_EUTRAN_low, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  THRESH_EUTRAN_low,  5, &hf_repeatedeutran_neighbourcells_thresh_eutran_low),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existEUTRAN_QRXLEVMIN, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t,  EUTRAN_QRXLEVMIN,  5, &hf_repeatedeutran_neighbourcells_eutran_qrxlevmin),
CSN_DESCR_END  (RepeatedEUTRAN_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(PCID_Pattern_t)
  M_UINT       (PCID_Pattern_t,  PCID_Pattern_length,  3, &hf_pcid_pattern_pcid_pattern_length),
  M_VAR_BITMAP (PCID_Pattern_t, PCID_Pattern, PCID_Pattern_length, 1), /* offset 1, 44.060 12.57 */
  M_UINT       (PCID_Pattern_t,  PCID_Pattern_sense,  1, &hf_pcid_pattern_pcid_pattern_sense),
CSN_DESCR_END  (PCID_Pattern_t)

static const
CSN_DESCR_BEGIN(PCID_Group_IE_t)

  M_REC_ARRAY  (PCID_Group_IE_t, PCID_a, NumberOfPCIDs, 9),

  M_NEXT_EXIST (PCID_Group_IE_t, existPCID_BITMAP_GROUP, 1),
  M_UINT       (PCID_Group_IE_t,  PCID_BITMAP_GROUP,  6, &hf_pcid_group_ie_pcid_bitmap_group),

  M_REC_TARRAY (PCID_Group_IE_t, PCID_Pattern_a, PCID_Pattern_t, NumberOfPCID_Patterns),
CSN_DESCR_END  (PCID_Group_IE_t)

static const
CSN_DESCR_BEGIN(EUTRAN_FREQUENCY_INDEX_t)
  M_UINT       (EUTRAN_FREQUENCY_INDEX_t,  EUTRAN_FREQUENCY_INDEX,  3, &hf_eutran_frequency_index_eutran_frequency_index),
CSN_DESCR_END  (EUTRAN_FREQUENCY_INDEX_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_NotAllowedCells_t)
  M_TYPE       (RepeatedEUTRAN_NotAllowedCells_t, NotAllowedCells, PCID_Group_IE_t),

  M_REC_TARRAY (RepeatedEUTRAN_NotAllowedCells_t, EUTRAN_FREQUENCY_INDEX_a, EUTRAN_FREQUENCY_INDEX_t, NumberOfFrequencyIndexes),
CSN_DESCR_END  (RepeatedEUTRAN_NotAllowedCells_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_PCID_to_TA_mapping_t)
  M_REC_TARRAY (RepeatedEUTRAN_PCID_to_TA_mapping_t, PCID_ToTA_Mapping_a, PCID_Group_IE_t, NumberOfMappings),
  M_REC_TARRAY (RepeatedEUTRAN_PCID_to_TA_mapping_t, EUTRAN_FREQUENCY_INDEX_a, EUTRAN_FREQUENCY_INDEX_t, NumberOfFrequencyIndexes),
CSN_DESCR_END  (RepeatedEUTRAN_PCID_to_TA_mapping_t)

static const
CSN_DESCR_BEGIN(EUTRAN_ParametersDescription_PMO_t)
  M_UINT       (EUTRAN_ParametersDescription_PMO_t,  EUTRAN_CCN_ACTIVE, 1, &hf_eutran_parametersdescription_pmo_eutran_ccn_active),

  M_NEXT_EXIST (EUTRAN_ParametersDescription_PMO_t, existGPRS_EUTRAN_MeasurementParametersDescription, 1),
  M_TYPE       (EUTRAN_ParametersDescription_PMO_t, GPRS_EUTRAN_MeasurementParametersDescription, GPRS_EUTRAN_MeasurementParametersDescription_t),

  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_NeighbourCells_a, RepeatedEUTRAN_NeighbourCells_t, nbrOfRepeatedEUTRAN_NeighbourCellsStructs),
  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_NotAllowedCells_a, RepeatedEUTRAN_NotAllowedCells_t, NumberOfNotAllowedCells),
  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_PCID_to_TA_mapping_a, RepeatedEUTRAN_PCID_to_TA_mapping_t, NumberOfMappings),
CSN_DESCR_END  (EUTRAN_ParametersDescription_PMO_t)

static const
CSN_DESCR_BEGIN(PSC_Pattern_t)
  M_UINT       (PSC_Pattern_t,  PSC_Pattern_length,  3, &hf_psc_pattern_length),
  M_VAR_BITMAP (PSC_Pattern_t,  PSC_Pattern, PSC_Pattern_length, 1),
  M_UINT       (PSC_Pattern_t,  PSC_Pattern_sense, 1, &hf_psc_pattern_sense),
CSN_DESCR_END  (PSC_Pattern_t)

static const
CSN_DESCR_BEGIN(PSC_Group_t)
  M_REC_ARRAY  (PSC_Group_t, PSC, PSC_Count, 9),
  M_REC_TARRAY (PSC_Group_t, PSC_Pattern, PSC_Pattern_t, PSC_Pattern_Count),
CSN_DESCR_END  (PSC_Group_t)

static const
CSN_DESCR_BEGIN(ThreeG_CSG_Description_Body_t)
  M_TYPE       (ThreeG_CSG_Description_Body_t, CSG_PSC_SPLIT, PSC_Group_t),
  M_REC_ARRAY  (ThreeG_CSG_Description_Body_t, UTRAN_FREQUENCY_INDEX, Count, 5),
CSN_DESCR_END  (ThreeG_CSG_Description_Body_t)

static const
CSN_DESCR_BEGIN(ThreeG_CSG_Description_t)
  M_REC_TARRAY (ThreeG_CSG_Description_t, ThreeG_CSG_Description_Body, ThreeG_CSG_Description_Body_t, Count),
CSN_DESCR_END  (ThreeG_CSG_Description_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Description_Body_t)
  M_TYPE       (EUTRAN_CSG_Description_Body_t, CSG_PCI_SPLIT, PSC_Group_t),
  M_REC_ARRAY  (EUTRAN_CSG_Description_Body_t, EUTRAN_FREQUENCY_INDEX, Count, 3),
CSN_DESCR_END  (EUTRAN_CSG_Description_Body_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Description_t)
  M_REC_TARRAY (EUTRAN_CSG_Description_t, EUTRAN_CSG_Description_Body, EUTRAN_CSG_Description_Body_t, Count),
CSN_DESCR_END  (EUTRAN_CSG_Description_t)

static const
CSN_DESCR_BEGIN(Meas_Ctrl_Param_Desp_t)
  M_NEXT_EXIST (Meas_Ctrl_Param_Desp_t, existMeasurement_Control_EUTRAN, 3),
  M_UINT       (Meas_Ctrl_Param_Desp_t,  Measurement_Control_EUTRAN, 1, &hf_meas_ctrl_param_meas_ctrl_eutran),
  M_UINT       (Meas_Ctrl_Param_Desp_t,  EUTRAN_FREQUENCY_INDEX_top, 3, &hf_meas_ctrl_param_eutran_freq_idx),
  M_REC_ARRAY  (Meas_Ctrl_Param_Desp_t,  EUTRAN_FREQUENCY_INDEX, Count_EUTRAN_FREQUENCY_INDEX, 3),
  M_NEXT_EXIST (Meas_Ctrl_Param_Desp_t, existMeasurement_Control_UTRAN, 1),
  M_UINT       (Meas_Ctrl_Param_Desp_t,  Measurement_Control_UTRAN, 1, &hf_meas_ctrl_param_meas_ctrl_utran),
  M_UINT       (Meas_Ctrl_Param_Desp_t, UTRAN_FREQUENCY_INDEX_top, 5, &hf_meas_ctrl_param_utran_freq_idx),
  M_REC_ARRAY  (Meas_Ctrl_Param_Desp_t, UTRAN_FREQUENCY_INDEX, Count_UTRAN_FREQUENCY_INDEX, 5),
CSN_DESCR_END  (Meas_Ctrl_Param_Desp_t)

static const
CSN_DESCR_BEGIN(Reselection_Based_On_RSRQ_t)
  M_UINT       (Reselection_Based_On_RSRQ_t,  THRESH_EUTRAN_high_Q,  5, &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_high_q),
  M_NEXT_EXIST (Reselection_Based_On_RSRQ_t, existTHRESH_EUTRAN_low_Q, 1),
  M_UINT       (Reselection_Based_On_RSRQ_t,  THRESH_EUTRAN_low_Q,  5, &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_low_q),
  M_NEXT_EXIST (Reselection_Based_On_RSRQ_t, existEUTRAN_QQUALMIN, 1),
  M_UINT       (Reselection_Based_On_RSRQ_t,  EUTRAN_QQUALMIN,  4, &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_qqualmin),
  M_NEXT_EXIST (Reselection_Based_On_RSRQ_t, existEUTRAN_RSRPmin, 1),
  M_UINT       (Reselection_Based_On_RSRQ_t,  EUTRAN_RSRPmin,  5, &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_rsrpmin),
CSN_DESCR_END  (Reselection_Based_On_RSRQ_t)

static const
CSN_DESCR_BEGIN(Rept_EUTRAN_Enh_Cell_Resel_Param_t)
  M_REC_ARRAY  (Rept_EUTRAN_Enh_Cell_Resel_Param_t,  EUTRAN_FREQUENCY_INDEX, Count_EUTRAN_FREQUENCY_INDEX, 3),
  M_UNION      (Rept_EUTRAN_Enh_Cell_Resel_Param_t, 2),
  M_UINT       (Rept_EUTRAN_Enh_Cell_Resel_Param_t,  u.EUTRAN_Qmin,  4, &hf_rept_eutran_enh_cell_resel_param_eutran_qmin),
  M_TYPE       (Rept_EUTRAN_Enh_Cell_Resel_Param_t,  u.Reselection_Based_On_RSRQ, Reselection_Based_On_RSRQ_t),
CSN_DESCR_END  (Rept_EUTRAN_Enh_Cell_Resel_Param_t)

static const
CSN_DESCR_BEGIN(Enh_Cell_Reselect_Param_Desp_t)
  M_REC_TARRAY (Enh_Cell_Reselect_Param_Desp_t, Repeated_EUTRAN_Enhanced_Cell_Reselection_Parameters, Rept_EUTRAN_Enh_Cell_Resel_Param_t, Count),
CSN_DESCR_END  (Enh_Cell_Reselect_Param_Desp_t)

static const
CSN_DESCR_BEGIN(UTRAN_CSG_Cells_Reporting_Desp_t)
  M_NEXT_EXIST (UTRAN_CSG_Cells_Reporting_Desp_t, existUTRAN_CSG_FDD_REPORTING_THRESHOLD, 2),
  M_UINT       (UTRAN_CSG_Cells_Reporting_Desp_t, UTRAN_CSG_FDD_REPORTING_THRESHOLD, 3, &hf_utran_csg_fdd_reporting_threshold),
  M_UINT       (UTRAN_CSG_Cells_Reporting_Desp_t, UTRAN_CSG_FDD_REPORTING_THRESHOLD_2, 6, &hf_utran_csg_fdd_reporting_threshold2),
  M_NEXT_EXIST (UTRAN_CSG_Cells_Reporting_Desp_t, existUTRAN_CSG_TDD_REPORTING_THRESHOLD, 1),
  M_UINT       (UTRAN_CSG_Cells_Reporting_Desp_t, UTRAN_CSG_TDD_REPORTING_THRESHOLD, 3, &hf_utran_csg_tdd_reporting_threshold),
CSN_DESCR_END  (UTRAN_CSG_Cells_Reporting_Desp_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Cells_Reporting_Desp_t)
  M_NEXT_EXIST (EUTRAN_CSG_Cells_Reporting_Desp_t, existEUTRAN_CSG_FDD_REPORTING_THRESHOLD, 2),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_FDD_REPORTING_THRESHOLD, 3, &hf_eutran_csg_fdd_reporting_threshold),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_FDD_REPORTING_THRESHOLD_2, 6, &hf_eutran_csg_fdd_reporting_threshold2),
  M_NEXT_EXIST (EUTRAN_CSG_Cells_Reporting_Desp_t, existEUTRAN_CSG_TDD_REPORTING_THRESHOLD, 2),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_TDD_REPORTING_THRESHOLD, 3, &hf_eutran_csg_tdd_reporting_threshold),
  M_UINT       (EUTRAN_CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_TDD_REPORTING_THRESHOLD_2, 6, &hf_eutran_csg_tdd_reporting_threshold2),
CSN_DESCR_END  (EUTRAN_CSG_Cells_Reporting_Desp_t)


static const
CSN_DESCR_BEGIN(CSG_Cells_Reporting_Desp_t)
  M_NEXT_EXIST (CSG_Cells_Reporting_Desp_t, existUTRAN_CSG_Cells_Reporting_Description, 1),
  M_TYPE       (CSG_Cells_Reporting_Desp_t, UTRAN_CSG_Cells_Reporting_Description, UTRAN_CSG_Cells_Reporting_Desp_t),
  M_NEXT_EXIST (CSG_Cells_Reporting_Desp_t, existEUTRAN_CSG_Cells_Reporting_Description, 1),
  M_TYPE       (CSG_Cells_Reporting_Desp_t, EUTRAN_CSG_Cells_Reporting_Description, EUTRAN_CSG_Cells_Reporting_Desp_t),
CSN_DESCR_END  (CSG_Cells_Reporting_Desp_t)

static const
CSN_DESCR_BEGIN        (PriorityAndEUTRAN_ParametersDescription_PMO_t)
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existServingCellPriorityParametersDescription, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, ServingCellPriorityParametersDescription, ServingCellPriorityParametersDescription_t),
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existPriorityParametersDescription3G_PMO, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, PriorityParametersDescription3G_PMO, PriorityParametersDescription3G_PMO_t),
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existEUTRAN_ParametersDescription_PMO, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, EUTRAN_ParametersDescription_PMO, EUTRAN_ParametersDescription_PMO_t),
CSN_DESCR_END          (PriorityAndEUTRAN_ParametersDescription_PMO_t)


static const
CSN_DESCR_BEGIN        (Delete_All_Stored_Individual_Priorities_t)
  M_NULL               (Delete_All_Stored_Individual_Priorities_t, dummy, 0),
CSN_DESCR_END          (Delete_All_Stored_Individual_Priorities_t)

static const
CSN_DESCR_BEGIN        (Individual_UTRAN_Priority_FDD_t)
  M_REC_ARRAY          (Individual_UTRAN_Priority_FDD_t, FDD_ARFCN, Count, 14),
CSN_DESCR_END          (Individual_UTRAN_Priority_FDD_t)

static const
CSN_DESCR_BEGIN        (Individual_UTRAN_Priority_TDD_t)
  M_REC_ARRAY          (Individual_UTRAN_Priority_TDD_t, TDD_ARFCN, Count, 14),
CSN_DESCR_END          (Individual_UTRAN_Priority_TDD_t)

static const
CSN_DESCR_BEGIN        (Repeated_Individual_UTRAN_Priority_Parameters_t)
  M_UNION              (Repeated_Individual_UTRAN_Priority_Parameters_t, 2),
  M_TYPE               (Repeated_Individual_UTRAN_Priority_Parameters_t, u.Individual_UTRAN_Priority_FDD, Individual_UTRAN_Priority_FDD_t),
  M_TYPE               (Repeated_Individual_UTRAN_Priority_Parameters_t, u.Individual_UTRAN_Priority_TDD, Individual_UTRAN_Priority_TDD_t),
  M_UINT               (Repeated_Individual_UTRAN_Priority_Parameters_t,  UTRAN_PRIORITY,  3, &hf_idvd_utran_priority),
CSN_DESCR_END          (Repeated_Individual_UTRAN_Priority_Parameters_t)

static const
CSN_DESCR_BEGIN        (ThreeG_Individual_Priority_Parameters_Description_t)
  M_NEXT_EXIST         (ThreeG_Individual_Priority_Parameters_Description_t, Exist_DEFAULT_UTRAN_PRIORITY, 1),
  M_UINT               (ThreeG_Individual_Priority_Parameters_Description_t,  DEFAULT_UTRAN_PRIORITY,  3, &hf_idvd_default_utran_priority),
  M_REC_TARRAY         (ThreeG_Individual_Priority_Parameters_Description_t, Repeated_Individual_UTRAN_Priority_Parameters, Repeated_Individual_UTRAN_Priority_Parameters_t, Repeated_Individual_UTRAN_Priority_Parameters_Count),
CSN_DESCR_END          (ThreeG_Individual_Priority_Parameters_Description_t)

static const
CSN_DESCR_BEGIN        (Repeated_Individual_EUTRAN_Priority_Parameters_t)
  M_REC_ARRAY          (Repeated_Individual_EUTRAN_Priority_Parameters_t, EARFCN, Count, 16),
  M_UINT               (Repeated_Individual_EUTRAN_Priority_Parameters_t,  EUTRAN_PRIORITY,  3, &hf_idvd_eutran_priority),
CSN_DESCR_END          (Repeated_Individual_EUTRAN_Priority_Parameters_t)

static const
CSN_DESCR_BEGIN        (EUTRAN_Individual_Priority_Parameters_Description_t)
  M_NEXT_EXIST         (EUTRAN_Individual_Priority_Parameters_Description_t, Exist_DEFAULT_EUTRAN_PRIORITY, 1),
  M_UINT               (EUTRAN_Individual_Priority_Parameters_Description_t,  DEFAULT_EUTRAN_PRIORITY,  3, &hf_idvd_default_eutran_priority),
  M_REC_TARRAY         (EUTRAN_Individual_Priority_Parameters_Description_t, Repeated_Individual_EUTRAN_Priority_Parameters, Repeated_Individual_EUTRAN_Priority_Parameters_t, Count),
CSN_DESCR_END          (EUTRAN_Individual_Priority_Parameters_Description_t)

static const
CSN_DESCR_BEGIN        (Provide_Individual_Priorities_t)
  M_UINT               (Provide_Individual_Priorities_t,  GERAN_PRIORITY,  3, &hf_idvd_prio_geran_priority),
  M_NEXT_EXIST         (Provide_Individual_Priorities_t, Exist_3G_Individual_Priority_Parameters_Description, 1),
  M_TYPE               (Provide_Individual_Priorities_t, ThreeG_Individual_Priority_Parameters_Description, ThreeG_Individual_Priority_Parameters_Description_t),
  M_NEXT_EXIST         (Provide_Individual_Priorities_t, Exist_EUTRAN_Individual_Priority_Parameters_Description, 1),
  M_TYPE               (Provide_Individual_Priorities_t, EUTRAN_Individual_Priority_Parameters_Description, EUTRAN_Individual_Priority_Parameters_Description_t),
  M_NEXT_EXIST         (Provide_Individual_Priorities_t, Exist_T3230_timeout_value, 1),
  M_UINT               (Provide_Individual_Priorities_t,  T3230_timeout_value,  3, &hf_idvd_prio_t3230_timeout_value),
CSN_DESCR_END          (Provide_Individual_Priorities_t)

static const
CSN_DESCR_BEGIN        (Individual_Priorities_t)
  M_UNION              (Individual_Priorities_t, 2),
  M_TYPE               (Individual_Priorities_t, u.Delete_All_Stored_Individual_Priorities, Delete_All_Stored_Individual_Priorities_t),
  M_TYPE               (Individual_Priorities_t, u.Provide_Individual_Priorities, Provide_Individual_Priorities_t),
CSN_DESCR_END          (Individual_Priorities_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR9_t)
  M_NEXT_EXIST         (PMO_AdditionsR9_t, existEnhanced_Cell_Reselection_Parameters_Description, 1),
  M_TYPE               (PMO_AdditionsR9_t, Enhanced_Cell_Reselection_Parameters_Description, Enh_Cell_Reselect_Param_Desp_t),
  M_NEXT_EXIST         (PMO_AdditionsR9_t, existCSG_Cells_Reporting_Description, 1),
  M_TYPE               (PMO_AdditionsR9_t, CSG_Cells_Reporting_Description, CSG_Cells_Reporting_Desp_t),
CSN_DESCR_END          (PMO_AdditionsR9_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR8_t)
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existBA_IND_3G_PMO_IND, 2),
  M_UINT               (PMO_AdditionsR8_t,  BA_IND_3G, 1, &hf_pmo_additionsr8_ba_ind_3g),
  M_UINT               (PMO_AdditionsR8_t,  PMO_IND, 1, &hf_pmo_additionsr8_pmo_ind),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existPriorityAndEUTRAN_ParametersDescription_PMO, 1),
  M_TYPE               (PMO_AdditionsR8_t, PriorityAndEUTRAN_ParametersDescription_PMO, PriorityAndEUTRAN_ParametersDescription_PMO_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existIndividualPriorities_PMO, 1),
  M_TYPE               (PMO_AdditionsR8_t, IndividualPriorities_PMO, Individual_Priorities_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existThreeG_CSG_Description, 1),
  M_TYPE               (PMO_AdditionsR8_t, ThreeG_CSG_Description_PMO, ThreeG_CSG_Description_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existEUTRAN_CSG_Description, 1),
  M_TYPE               (PMO_AdditionsR8_t, EUTRAN_CSG_Description_PMO, EUTRAN_CSG_Description_t),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existMeasurement_Control_Parameters_Description, 1),
  M_TYPE               (PMO_AdditionsR8_t, Measurement_Control_Parameters_Description_PMO, Meas_Ctrl_Param_Desp_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR8_t, existAdditionsR9, 1),
  M_TYPE               (PMO_AdditionsR8_t, AdditionsR9, PMO_AdditionsR9_t),
CSN_DESCR_END          (PMO_AdditionsR8_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR7_t)
  M_NEXT_EXIST         (PMO_AdditionsR7_t, existREPORTING_OFFSET_THRESHOLD_700, 2),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_OFFSET_700,  3, &hf_pmo_additionsr7_reporting_offset_700),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_THRESHOLD_700,  3, &hf_pmo_additionsr7_reporting_threshold_700),

  M_NEXT_EXIST         (PMO_AdditionsR7_t, existREPORTING_OFFSET_THRESHOLD_810, 2),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_OFFSET_810,  3, &hf_pmo_additionsr7_reporting_offset_810),
  M_UINT               (PMO_AdditionsR7_t,  REPORTING_THRESHOLD_810,  3, &hf_pmo_additionsr7_reporting_threshold_810),

  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR7_t, existAdditionsR8, 1),
  M_TYPE               (PMO_AdditionsR7_t, additionsR8, PMO_AdditionsR8_t),
CSN_DESCR_END          (PMO_AdditionsR7_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR6_t)
  M_UINT               (PMO_AdditionsR6_t,  CCN_ACTIVE_3G,  1, &hf_pmo_additionsr6_ccn_active_3g),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR6_t, existAdditionsR7, 1),
  M_TYPE               (PMO_AdditionsR6_t, additionsR7, PMO_AdditionsR7_t),
CSN_DESCR_END          (PMO_AdditionsR6_t)

static const
CSN_DESCR_BEGIN(PCCO_AdditionsR6_t)
  M_UINT       (PCCO_AdditionsR6_t,  CCN_ACTIVE_3G,  1, &hf_pcco_additionsr6_ccn_active_3g),
CSN_DESCR_END  (PCCO_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR5_t)
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existGRNTI_Extension, 1),
  M_UINT               (PMO_AdditionsR5_t,  GRNTI,  4, &hf_pmo_additionsr5_grnti),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, exist_lu_ModeNeighbourCellParams, 1),
  M_REC_TARRAY         (PMO_AdditionsR5_t, lu_ModeNeighbourCellParams, lu_ModeNeighbourCellParams_t, count_lu_ModeNeighbourCellParams),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existNC_lu_ModeOnlyCapableCellList, 1),
  M_TYPE               (PMO_AdditionsR5_t, NC_lu_ModeOnlyCapableCellList, NC_lu_ModeOnlyCapableCellList_t),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existGPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE               (PMO_AdditionsR5_t, GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR5_t, existAdditionsR6, 1),
  M_TYPE               (PMO_AdditionsR5_t, additionsR6, PMO_AdditionsR6_t),
CSN_DESCR_END  (PMO_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR5_t)
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existGRNTI_Extension, 1),
  M_UINT               (PCCO_AdditionsR5_t,  GRNTI,  4, &hf_pcco_additionsr5_grnti),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, exist_lu_ModeNeighbourCellParams, 1),
  M_REC_TARRAY         (PCCO_AdditionsR5_t, lu_ModeNeighbourCellParams, lu_ModeNeighbourCellParams_t, count_lu_ModeNeighbourCellParams),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existNC_lu_ModeOnlyCapableCellList, 1),
  M_TYPE               (PCCO_AdditionsR5_t, NC_lu_ModeOnlyCapableCellList, NC_lu_ModeOnlyCapableCellList_t),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existGPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE               (PCCO_AdditionsR5_t, GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR5_t, existAdditionsR6, 1),
  M_TYPE               (PCCO_AdditionsR5_t, additionsR6, PCCO_AdditionsR6_t),
CSN_DESCR_END  (PCCO_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR4_t)
  M_UINT               (PMO_AdditionsR4_t,  CCN_ACTIVE,  1, &hf_pmo_additionsr4_ccn_active),
  M_NEXT_EXIST         (PMO_AdditionsR4_t, Exist_CCN_Support_Description_ID, 1),
  M_TYPE               (PMO_AdditionsR4_t, CCN_Support_Description, CCN_Support_Description_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR4_t, Exist_AdditionsR5, 1),
  M_TYPE               (PMO_AdditionsR4_t, AdditionsR5, PMO_AdditionsR5_t),
CSN_DESCR_END          (PMO_AdditionsR4_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR99_t)
  M_NEXT_EXIST         (PMO_AdditionsR99_t, Exist_ENH_Measurement_Parameters, 1),
  M_TYPE               (PMO_AdditionsR99_t, ENH_Measurement_Parameters, ENH_Measurement_Parameters_PMO_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR99_t, Exist_AdditionsR4, 1),
  M_TYPE               (PMO_AdditionsR99_t, AdditionsR4, PMO_AdditionsR4_t),
CSN_DESCR_END          (PMO_AdditionsR99_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR4_t)
  M_UINT               (PCCO_AdditionsR4_t,  CCN_ACTIVE,  1, &hf_pcco_additionsr4_ccn_active),
  M_NEXT_EXIST         (PCCO_AdditionsR4_t, Exist_Container_ID, 1),
  M_UINT               (PCCO_AdditionsR4_t,  CONTAINER_ID,  2, &hf_pcco_additionsr4_container_id),
  M_NEXT_EXIST         (PCCO_AdditionsR4_t, Exist_CCN_Support_Description_ID, 1),
  M_TYPE               (PCCO_AdditionsR4_t, CCN_Support_Description, CCN_Support_Description_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR4_t, Exist_AdditionsR5, 1),
  M_TYPE               (PCCO_AdditionsR4_t, AdditionsR5, PCCO_AdditionsR5_t),
CSN_DESCR_END  (PCCO_AdditionsR4_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR99_t)
  M_TYPE               (PCCO_AdditionsR99_t, ENH_Measurement_Parameters, ENH_Measurement_Parameters_PCCO_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR99_t, Exist_AdditionsR4, 1),
  M_TYPE               (PCCO_AdditionsR99_t, AdditionsR4, PCCO_AdditionsR4_t),
CSN_DESCR_END          (PCCO_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(LSA_ID_Info_Element_t)
  M_UNION      (LSA_ID_Info_Element_t, 2),
  M_UINT       (LSA_ID_Info_Element_t,  u.LSA_ID,  24, &hf_lsa_id_info_element_lsa_id),
  M_UINT       (LSA_ID_Info_Element_t,  u.ShortLSA_ID,  10, &hf_lsa_id_info_element_shortlsa_id),
CSN_DESCR_END  (LSA_ID_Info_Element_t)

static const
CSN_DESCR_BEGIN(LSA_ID_Info_t)
  M_REC_TARRAY (LSA_ID_Info_t, LSA_ID_Info_Elements, LSA_ID_Info_Element_t, Count_LSA_ID_Info_Element),
CSN_DESCR_END  (LSA_ID_Info_t)

static const
CSN_DESCR_BEGIN(LSA_Parameters_t)
  M_UINT       (LSA_Parameters_t,  NR_OF_FREQ_OR_CELLS,  5, &hf_lsa_parameters_nr_of_freq_or_cells),
  M_VAR_TARRAY (LSA_Parameters_t, LSA_ID_Info, LSA_ID_Info_t, NR_OF_FREQ_OR_CELLS),
CSN_DESCR_END  (LSA_Parameters_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR98_t)
  M_NEXT_EXIST         (PMO_AdditionsR98_t, Exist_LSA_Parameters, 1),
  M_TYPE               (PMO_AdditionsR98_t, LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR98_t, Exist_AdditionsR99, 1),
  M_TYPE               (PMO_AdditionsR98_t, AdditionsR99, PMO_AdditionsR99_t),
CSN_DESCR_END          (PMO_AdditionsR98_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR98_t)
  M_NEXT_EXIST         (PCCO_AdditionsR98_t, Exist_LSA_Parameters, 1),
  M_TYPE               (PCCO_AdditionsR98_t, LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR98_t, Exist_AdditionsR99, 1),
  M_TYPE               (PCCO_AdditionsR98_t, AdditionsR99, PCCO_AdditionsR99_t),
CSN_DESCR_END          (PCCO_AdditionsR98_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_GSM_t)
  M_UINT               (Target_Cell_GSM_t,  IMMEDIATE_REL,  1, &hf_target_cell_gsm_immediate_rel),
  M_UINT               (Target_Cell_GSM_t,  ARFCN, 10, &hf_arfcn),
  M_UINT               (Target_Cell_GSM_t,  BSIC,  6, &hf_target_cell_gsm_bsic),
  M_TYPE               (Target_Cell_GSM_t, NC_Measurement_Parameters, NC_Measurement_Parameters_with_Frequency_List_t),
  M_NEXT_EXIST_OR_NULL (Target_Cell_GSM_t, Exist_AdditionsR98, 1),
  M_TYPE               (Target_Cell_GSM_t, AdditionsR98, PCCO_AdditionsR98_t),
CSN_DESCR_END          (Target_Cell_GSM_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_3G_AdditionsR8_t)
  M_NEXT_EXIST         (Target_Cell_3G_AdditionsR8_t, Exist_EUTRAN_Target_Cell, 1),
  M_TYPE               (Target_Cell_3G_AdditionsR8_t, EUTRAN_Target_Cell, EUTRAN_Target_Cell_t),
  M_NEXT_EXIST         (Target_Cell_3G_AdditionsR8_t, Exist_Individual_Priorities, 1),
  M_TYPE               (Target_Cell_3G_AdditionsR8_t, Individual_Priorities, Individual_Priorities_t),
CSN_DESCR_END          (Target_Cell_3G_AdditionsR8_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_3G_AdditionsR5_t)
  M_NEXT_EXIST         (Target_Cell_3G_AdditionsR5_t, Exist_G_RNTI_Extention, 1),
  M_UINT               (Target_Cell_3G_AdditionsR5_t,  G_RNTI_Extention,  4, &hf_target_cell_g_rnti_ext),
  M_NEXT_EXIST_OR_NULL (Target_Cell_3G_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE               (Target_Cell_3G_AdditionsR5_t, AdditionsR8, Target_Cell_3G_AdditionsR8_t),
CSN_DESCR_END          (Target_Cell_3G_AdditionsR5_t)

static const
CSN_DESCR_BEGIN(Target_Cell_3G_t)
  /* 00 -- Message escape */
  M_FIXED      (Target_Cell_3G_t, 2, 0x00),
  M_UINT       (Target_Cell_3G_t,  IMMEDIATE_REL,  1, &hf_target_cell_3g_immediate_rel),
  M_NEXT_EXIST (Target_Cell_3G_t, Exist_FDD_Description, 1),
  M_TYPE       (Target_Cell_3G_t, FDD_Target_Cell, FDD_Target_Cell_t),
  M_NEXT_EXIST (Target_Cell_3G_t, Exist_TDD_Description, 1),
  M_TYPE       (Target_Cell_3G_t, TDD_Target_Cell, TDD_Target_Cell_t),
  M_NEXT_EXIST_OR_NULL (Target_Cell_3G_t, Exist_AdditionsR5, 1),
  M_TYPE       (Target_Cell_3G_t, AdditionsR5, Target_Cell_3G_AdditionsR5_t),
CSN_DESCR_END  (Target_Cell_3G_t)

static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Order_t)
  M_UINT       (Packet_Cell_Change_Order_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Cell_Change_Order_t, PAGE_MODE, 2, &hf_page_mode),

  M_TYPE       (Packet_Cell_Change_Order_t, ID, PacketCellChangeOrderID_t),

  M_UNION      (Packet_Cell_Change_Order_t, 2),
  M_TYPE       (Packet_Cell_Change_Order_t, u.Target_Cell_GSM, Target_Cell_GSM_t),
  M_TYPE       (Packet_Cell_Change_Order_t, u.Target_Cell_3G, Target_Cell_3G_t),

  M_PADDING_BITS(Packet_Cell_Change_Order_t),
CSN_DESCR_END  (Packet_Cell_Change_Order_t)

/*< Packet (Enhanced) Measurement Report message contents > */
static const
CSN_DESCR_BEGIN(BA_USED_t)
  M_UINT       (BA_USED_t,  BA_USED,  1, &hf_ba_used_ba_used),
  M_UINT       (BA_USED_t,  BA_USED_3G,  1, &hf_ba_used_ba_used_3g),
CSN_DESCR_END  (BA_USED_t)

static const
CSN_DESCR_BEGIN(Serving_Cell_Data_t)
  M_UINT       (Serving_Cell_Data_t,  RXLEV_SERVING_CELL,  6, &hf_serving_cell_data_rxlev_serving_cell),
  M_FIXED      (Serving_Cell_Data_t, 1, 0),
CSN_DESCR_END  (Serving_Cell_Data_t)

static const
CSN_DESCR_BEGIN(NC_Measurements_t)
  M_UINT       (NC_Measurements_t,  FREQUENCY_N,  6, &hf_nc_measurements_frequency_n),

  M_NEXT_EXIST (NC_Measurements_t, Exist_BSIC_N, 1),
  M_UINT       (NC_Measurements_t,  BSIC_N,  6, &hf_nc_measurements_bsic_n),
  M_UINT       (NC_Measurements_t,  RXLEV_N,  6, &hf_nc_measurements_rxlev_n),
CSN_DESCR_END  (NC_Measurements_t)

static const
CSN_DESCR_BEGIN(RepeatedInvalid_BSIC_Info_t)
  M_UINT       (RepeatedInvalid_BSIC_Info_t,  BCCH_FREQ_N,  5, &hf_repeatedinvalid_bsic_info_bcch_freq_n),
  M_UINT       (RepeatedInvalid_BSIC_Info_t,  BSIC_N,  6, &hf_repeatedinvalid_bsic_info_bsic_n),
  M_UINT       (RepeatedInvalid_BSIC_Info_t,  RXLEV_N,  6, &hf_repeatedinvalid_bsic_info_rxlev_n),
CSN_DESCR_END  (RepeatedInvalid_BSIC_Info_t)

static const
CSN_DESCR_BEGIN(REPORTING_QUANTITY_Instance_t)
  M_NEXT_EXIST (REPORTING_QUANTITY_Instance_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT       (REPORTING_QUANTITY_Instance_t,  REPORTING_QUANTITY,  6, &hf_reporting_quantity_instance_reporting_quantity),
CSN_DESCR_END  (REPORTING_QUANTITY_Instance_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Report_t)
  M_UINT       (NC_Measurement_Report_t,  NC_MODE,  1, &hf_nc_measurement_report_nc_mode),
  M_TYPE       (NC_Measurement_Report_t, Serving_Cell_Data, Serving_Cell_Data_t),
  M_UINT       (NC_Measurement_Report_t,  NUMBER_OF_NC_MEASUREMENTS,  3, &hf_nc_measurement_report_number_of_nc_measurements),
  M_VAR_TARRAY (NC_Measurement_Report_t, NC_Measurements, NC_Measurements_t, NUMBER_OF_NC_MEASUREMENTS),
CSN_DESCR_END  (NC_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(ENH_NC_Measurement_Report_t)
  M_UINT       (ENH_NC_Measurement_Report_t,  NC_MODE,  1, &hf_enh_nc_measurement_report_nc_mode),
  M_UNION      (ENH_NC_Measurement_Report_t, 2),
  M_TYPE       (ENH_NC_Measurement_Report_t, u.BA_USED, BA_USED_t),
  M_UINT       (ENH_NC_Measurement_Report_t,  u.PSI3_CHANGE_MARK, 2, &hf_psi3_change_mark),
  M_UINT       (ENH_NC_Measurement_Report_t,  PMO_USED,  1, &hf_enh_nc_measurement_report_pmo_used),
  M_UINT       (ENH_NC_Measurement_Report_t,  BSIC_Seen,  1, &hf_enh_nc_measurement_report_bsic_seen),
  M_UINT       (ENH_NC_Measurement_Report_t,  SCALE,  1, &hf_enh_nc_measurement_report_scale),
  M_NEXT_EXIST (ENH_NC_Measurement_Report_t, Exist_Serving_Cell_Data, 1),
  M_TYPE       (ENH_NC_Measurement_Report_t, Serving_Cell_Data, Serving_Cell_Data_t),
  M_REC_TARRAY (ENH_NC_Measurement_Report_t, RepeatedInvalid_BSIC_Info[0], RepeatedInvalid_BSIC_Info_t, Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST (ENH_NC_Measurement_Report_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY (ENH_NC_Measurement_Report_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END  (ENH_NC_Measurement_Report_t)


static const
CSN_DESCR_BEGIN(EXT_Measurement_Report_t)
  M_UINT       (EXT_Measurement_Report_t,  EXT_REPORTING_TYPE,  2, &hf_ext_measurement_report_ext_reporting_type),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Exist_I_LEVEL, 1),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[0].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[0].I_LEVEL,  6, &hf_ext_measurement_report_slot0_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[1].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[1].I_LEVEL,  6, &hf_ext_measurement_report_slot1_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[2].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[2].I_LEVEL,  6, &hf_ext_measurement_report_slot2_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[3].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[3].I_LEVEL,  6, &hf_ext_measurement_report_slot3_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[4].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[4].I_LEVEL,  6, &hf_ext_measurement_report_slot4_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[5].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[5].I_LEVEL,  6, &hf_ext_measurement_report_slot5_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[6].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[6].I_LEVEL,  6, &hf_ext_measurement_report_slot6_i_level),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[7].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t,  Slot[7].I_LEVEL,  6, &hf_ext_measurement_report_slot7_i_level),

  M_UINT       (EXT_Measurement_Report_t,  NUMBER_OF_EXT_MEASUREMENTS,  5, &hf_ext_measurement_report_number_of_ext_measurements),
  M_VAR_TARRAY (EXT_Measurement_Report_t, EXT_Measurements, NC_Measurements_t, NUMBER_OF_EXT_MEASUREMENTS),
CSN_DESCR_END  (EXT_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (Measurements_3G_t)
  M_UINT          (Measurements_3G_t,  CELL_LIST_INDEX_3G,  7, &hf_measurements_3g_cell_list_index_3g),
  M_UINT          (Measurements_3G_t,  REPORTING_QUANTITY,  6, &hf_measurements_3g_reporting_quantity),
CSN_DESCR_END   (Measurements_3G_t)

static const
CSN_DESCR_BEGIN (EUTRAN_Measurement_Report_Body_t)
  M_UINT        (EUTRAN_Measurement_Report_Body_t,  EUTRAN_FREQUENCY_INDEX,  3, &hf_pmr_eutran_meas_rpt_freq_idx),
  M_UINT        (EUTRAN_Measurement_Report_Body_t,  CELL_IDENTITY,  9, &hf_pmr_eutran_meas_rpt_cell_id),
  M_UINT        (EUTRAN_Measurement_Report_Body_t,  REPORTING_QUANTITY,  6, &hf_pmr_eutran_meas_rpt_quantity),
CSN_DESCR_END   (EUTRAN_Measurement_Report_Body_t)

static const
CSN_DESCR_BEGIN (EUTRAN_Measurement_Report_t)
  M_UINT_OFFSET (EUTRAN_Measurement_Report_t, N_EUTRAN,  2, 1),
  M_VAR_TARRAY  (EUTRAN_Measurement_Report_t, Report, EUTRAN_Measurement_Report_Body_t, N_EUTRAN),
CSN_DESCR_END   (EUTRAN_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(UTRAN_CSG_Measurement_Report_t)
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  UTRAN_CGI,  28, &hf_utran_csg_meas_rpt_cgi),
  M_NEXT_EXIST (UTRAN_CSG_Measurement_Report_t, Exist_PLMN_ID, 1),
  M_TYPE       (UTRAN_CSG_Measurement_Report_t,  Plmn_ID, PLMN_t),
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  CSG_ID,  27, &hf_utran_csg_meas_rpt_csg_id),
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  Access_Mode, 1, &hf_utran_csg_meas_rpt_access_mode),
  M_UINT       (UTRAN_CSG_Measurement_Report_t,  REPORTING_QUANTITY,  6, &hf_utran_csg_meas_rpt_quantity),
CSN_DESCR_END  (UTRAN_CSG_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(EUTRAN_CSG_Measurement_Report_t)
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, EUTRAN_CGI, 28, &hf_eutran_csg_meas_rpt_cgi),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, Tracking_Area_Code, 16, &hf_eutran_csg_meas_rpt_ta),
  M_NEXT_EXIST (EUTRAN_CSG_Measurement_Report_t, Exist_PLMN_ID, 1),
  M_TYPE       (EUTRAN_CSG_Measurement_Report_t,  Plmn_ID, PLMN_t),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, CSG_ID, 27, &hf_eutran_csg_meas_rpt_csg_id),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, Access_Mode, 1, &hf_eutran_csg_meas_rpt_access_mode),
  M_UINT       (EUTRAN_CSG_Measurement_Report_t, REPORTING_QUANTITY, 6, &hf_eutran_csg_meas_rpt_quantity),
CSN_DESCR_END  (EUTRAN_CSG_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR9_t)
  M_NEXT_EXIST  (PMR_AdditionsR9_t, Exist_UTRAN_CSG_Meas_Rpt, 1),
  M_TYPE        (PMR_AdditionsR9_t, UTRAN_CSG_Meas_Rpt, UTRAN_CSG_Measurement_Report_t),
  M_NEXT_EXIST  (PMR_AdditionsR9_t, Exist_EUTRAN_CSG_Meas_Rpt, 1),
  M_TYPE        (PMR_AdditionsR9_t, EUTRAN_CSG_Meas_Rpt, EUTRAN_CSG_Measurement_Report_t),
CSN_DESCR_END   (PMR_AdditionsR9_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR8_t)
  M_NEXT_EXIST  (PMR_AdditionsR8_t, Exist_EUTRAN_Meas_Rpt, 1),
  M_TYPE        (PMR_AdditionsR8_t, EUTRAN_Meas_Rpt, EUTRAN_Measurement_Report_t),
  M_NEXT_EXIST_OR_NULL(PMR_AdditionsR8_t, Exist_AdditionsR9, 1),
  M_TYPE        (PMR_AdditionsR8_t, AdditionsR9, PMR_AdditionsR9_t),
CSN_DESCR_END   (PMR_AdditionsR8_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR5_t)
  M_NEXT_EXIST  (PMR_AdditionsR5_t, Exist_GRNTI, 4),
  M_UINT        (PMR_AdditionsR5_t,  GRNTI,  4, &hf_pmo_additionsr5_grnti),
  M_NEXT_EXIST_OR_NULL (PMR_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE        (PMR_AdditionsR5_t, AdditionsR8, PMR_AdditionsR8_t),
CSN_DESCR_END   (PMR_AdditionsR5_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR99_t)
  M_NEXT_EXIST  (PMR_AdditionsR99_t, Exist_Info3G, 4),
  M_UNION       (PMR_AdditionsR99_t, 2),
  M_TYPE        (PMR_AdditionsR99_t, u.BA_USED, BA_USED_t),
  M_UINT        (PMR_AdditionsR99_t,  u.PSI3_CHANGE_MARK,  2, &hf_psi3_change_mark),
  M_UINT        (PMR_AdditionsR99_t,  PMO_USED,  1, &hf_pmr_additionsr99_pmo_used),

  M_NEXT_EXIST  (PMR_AdditionsR99_t, Exist_MeasurementReport3G, 2),
  M_UINT_OFFSET (PMR_AdditionsR99_t, N_3G, 3, 1),   /* offset 1 */
  M_VAR_TARRAY_OFFSET  (PMR_AdditionsR99_t, Measurements_3G, Measurements_3G_t, N_3G),

  M_NEXT_EXIST_OR_NULL (PMR_AdditionsR99_t, Exist_AdditionsR5, 1),
  M_TYPE        (PMR_AdditionsR99_t, AdditionsR5, PMR_AdditionsR5_t),
CSN_DESCR_END   (PMR_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(EMR_ServingCell_t)
  /*CSN_MEMBER_BIT (EMR_ServingCell_t, DTX_USED),*/
  M_UINT         (EMR_ServingCell_t,  DTX_USED,         1, &hf_emr_servingcell_dtx_used),
  M_UINT         (EMR_ServingCell_t,  RXLEV_VAL,        6, &hf_emr_servingcell_rxlev_val),
  M_UINT         (EMR_ServingCell_t,  RX_QUAL_FULL,     3, &hf_emr_servingcell_rx_qual_full),
  M_UINT         (EMR_ServingCell_t,  MEAN_BEP,         5, &hf_emr_servingcell_mean_bep),
  M_UINT         (EMR_ServingCell_t,  CV_BEP,           3, &hf_emr_servingcell_cv_bep),
  M_UINT         (EMR_ServingCell_t,  NBR_RCVD_BLOCKS,  5, &hf_emr_servingcell_nbr_rcvd_blocks),
CSN_DESCR_END(EMR_ServingCell_t)

static const
CSN_DESCR_BEGIN   (EnhancedMeasurementReport_t)
  M_UINT          (EnhancedMeasurementReport_t,  RR_Short_PD,  1, &hf_enhancedmeasurementreport_rr_short_pd),
  M_UINT          (EnhancedMeasurementReport_t,  MESSAGE_TYPE,  5, &hf_enhancedmeasurementreport_message_type),
  M_UINT          (EnhancedMeasurementReport_t,  ShortLayer2_Header,  2, &hf_enhancedmeasurementreport_shortlayer2_header),
  M_TYPE          (EnhancedMeasurementReport_t, BA_USED, BA_USED_t),
  M_UINT          (EnhancedMeasurementReport_t,  BSIC_Seen,  1, &hf_enhancedmeasurementreport_bsic_seen),
  M_UINT          (EnhancedMeasurementReport_t,  SCALE,  1, &hf_enhancedmeasurementreport_scale),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE          (EnhancedMeasurementReport_t, ServingCellData, EMR_ServingCell_t),
  M_REC_TARRAY    (EnhancedMeasurementReport_t, RepeatedInvalid_BSIC_Info[0], RepeatedInvalid_BSIC_Info_t,
                    Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY    (EnhancedMeasurementReport_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END     (EnhancedMeasurementReport_t)

static const
CSN_DESCR_BEGIN       (Packet_Measurement_Report_t)
  /* Mac header */
  M_UINT              (Packet_Measurement_Report_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT              (Packet_Measurement_Report_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT              (Packet_Measurement_Report_t,  R, 1, &hf_ul_retry),
  M_UINT              (Packet_Measurement_Report_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_UINT              (Packet_Measurement_Report_t,  TLLI, 32, &hf_tlli),

  M_NEXT_EXIST        (Packet_Measurement_Report_t, Exist_PSI5_CHANGE_MARK, 1),
  M_UINT              (Packet_Measurement_Report_t,  PSI5_CHANGE_MARK,  2, &hf_packet_measurement_report_psi5_change_mark),

  M_UNION             (Packet_Measurement_Report_t, 2),
  M_TYPE              (Packet_Measurement_Report_t, u.NC_Measurement_Report, NC_Measurement_Report_t),
  M_TYPE              (Packet_Measurement_Report_t, u.EXT_Measurement_Report, EXT_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Measurement_Report_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Measurement_Report_t, AdditionsR99, PMR_AdditionsR99_t),

  M_PADDING_BITS      (Packet_Measurement_Report_t),
CSN_DESCR_END         (Packet_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (PEMR_AdditionsR9_t)
  M_NEXT_EXIST  (PEMR_AdditionsR9_t, Exist_UTRAN_CSG_Target_Cell, 1),
  M_TYPE        (PEMR_AdditionsR9_t, UTRAN_CSG_Target_Cell, UTRAN_CSG_Target_Cell_t),
  M_NEXT_EXIST  (PEMR_AdditionsR9_t, Exist_EUTRAN_CSG_Target_Cell, 1),
  M_TYPE        (PEMR_AdditionsR9_t, EUTRAN_CSG_Target_Cell, EUTRAN_CSG_Target_Cell_t),
CSN_DESCR_END   (PEMR_AdditionsR9_t)

static const
CSN_DESCR_BEGIN (Bitmap_Report_Quantity_t)
  M_NEXT_EXIST  (Bitmap_Report_Quantity_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT        (Bitmap_Report_Quantity_t,  REPORTING_QUANTITY,  6, &hf_reporting_quantity_instance_reporting_quantity),
CSN_DESCR_END   (Bitmap_Report_Quantity_t)

static const
CSN_DESCR_BEGIN (PEMR_AdditionsR8_t)
  M_UINT_OFFSET (PEMR_AdditionsR8_t, BITMAP_LENGTH,  7, 1),
  M_VAR_TARRAY  (PEMR_AdditionsR8_t, Bitmap_Report_Quantity, Bitmap_Report_Quantity_t, BITMAP_LENGTH),
  M_NEXT_EXIST  (PEMR_AdditionsR8_t, Exist_EUTRAN_Meas_Rpt, 1),
  M_TYPE        (PEMR_AdditionsR8_t, EUTRAN_Meas_Rpt, EUTRAN_Measurement_Report_t),
  M_NEXT_EXIST_OR_NULL(PEMR_AdditionsR8_t, Exist_AdditionsR9, 1),
  M_TYPE        (PEMR_AdditionsR8_t, AdditionsR9, PEMR_AdditionsR9_t),
CSN_DESCR_END   (PEMR_AdditionsR8_t)

static const
CSN_DESCR_BEGIN (PEMR_AdditionsR5_t)
  M_NEXT_EXIST  (PEMR_AdditionsR5_t, Exist_GRNTI_Ext, 1),
  M_UINT        (PEMR_AdditionsR5_t,  GRNTI_Ext,  4, &hf_pmo_additionsr5_grnti),
  M_NEXT_EXIST_OR_NULL(PEMR_AdditionsR5_t, Exist_AdditionsR8, 1),
  M_TYPE        (PEMR_AdditionsR5_t, AdditionsR8, PEMR_AdditionsR8_t),
CSN_DESCR_END   (PEMR_AdditionsR5_t)


static const
CSN_DESCR_BEGIN       (Packet_Enh_Measurement_Report_t)
  /* Mac header */
  M_UINT              (Packet_Enh_Measurement_Report_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT              (Packet_Enh_Measurement_Report_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT              (Packet_Enh_Measurement_Report_t,  R, 1, &hf_ul_retry),
  M_UINT              (Packet_Enh_Measurement_Report_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_UINT              (Packet_Enh_Measurement_Report_t,  TLLI, 32, &hf_tlli),

  M_TYPE              (Packet_Enh_Measurement_Report_t, Measurements, ENH_NC_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Enh_Measurement_Report_t, Exist_AdditionsR5, 1),
  M_TYPE              (Packet_Enh_Measurement_Report_t, AdditionsR5, PEMR_AdditionsR5_t),

  M_PADDING_BITS(Packet_Enh_Measurement_Report_t),
CSN_DESCR_END         (Packet_Enh_Measurement_Report_t)

/*< Packet Measurement Order message contents >*/
static const
CSN_DESCR_BEGIN(EXT_Frequency_List_t)
  M_UINT       (EXT_Frequency_List_t,  START_FREQUENCY,  10, &hf_ext_frequency_list_start_frequency),
  M_UINT       (EXT_Frequency_List_t,  NR_OF_FREQUENCIES,  5, &hf_ext_frequency_list_nr_of_frequencies),
  M_UINT       (EXT_Frequency_List_t,  FREQ_DIFF_LENGTH,  3, &hf_ext_frequency_list_freq_diff_length),

/* TBD: Count_FREQUENCY_DIFF
 * guint8 FREQUENCY_DIFF[31];
 * bit (FREQ_DIFF_LENGTH) * NR_OF_FREQUENCIES --> MAX is bit(7) * 31
 */
CSN_DESCR_END  (EXT_Frequency_List_t)

static const
CSN_DESCR_BEGIN        (Packet_Measurement_Order_t)
  M_UINT               (Packet_Measurement_Order_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT               (Packet_Measurement_Order_t, PAGE_MODE, 2, &hf_page_mode),

  M_TYPE               (Packet_Measurement_Order_t, ID, PacketDownlinkID_t), /* reuse the PDA ID type */

  M_UINT               (Packet_Measurement_Order_t, PMO_INDEX, 3, &hf_packet_measurement_order_pmo_index),
  M_UINT               (Packet_Measurement_Order_t, PMO_COUNT, 3, &hf_packet_measurement_order_pmo_count),

  M_NEXT_EXIST         (Packet_Measurement_Order_t, Exist_NC_Measurement_Parameters, 1),
  M_TYPE               (Packet_Measurement_Order_t, NC_Measurement_Parameters, NC_Measurement_Parameters_with_Frequency_List_t),

  M_NEXT_EXIST         (Packet_Measurement_Order_t, Exist_EXT_Measurement_Parameters, 1),
  M_FIXED              (Packet_Measurement_Order_t, 2, 0x0),    /* EXT_Measurement_Parameters not handled */

  M_NEXT_EXIST_OR_NULL (Packet_Measurement_Order_t, Exist_AdditionsR98, 1),
  M_TYPE               (Packet_Measurement_Order_t, AdditionsR98, PMO_AdditionsR98_t),

  M_PADDING_BITS       (Packet_Measurement_Order_t),
CSN_DESCR_END          (Packet_Measurement_Order_t)

static const
CSN_DESCR_BEGIN(CCN_Measurement_Report_t)
  M_UINT       (CCN_Measurement_Report_t,  RXLEV_SERVING_CELL,  6, &hf_ccn_measurement_report_rxlev_serving_cell),
  M_FIXED      (CCN_Measurement_Report_t, 1, 0),
  M_UINT       (CCN_Measurement_Report_t,  NUMBER_OF_NC_MEASUREMENTS,  3, &hf_ccn_measurement_report_number_of_nc_measurements),
  M_VAR_TARRAY (CCN_Measurement_Report_t, NC_Measurements, NC_Measurements_t, NUMBER_OF_NC_MEASUREMENTS),
CSN_DESCR_END  (CCN_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(Target_Cell_GSM_Notif_t)
  M_UINT       (Target_Cell_GSM_Notif_t, ARFCN, 10, &hf_arfcn),
  M_UINT       (Target_Cell_GSM_Notif_t, BSIC, 6, &hf_target_cell_gsm_notif_bsic),
CSN_DESCR_END  (Target_Cell_GSM_Notif_t)

static const
CSN_DESCR_BEGIN(FDD_Target_Cell_Notif_t)
  M_UINT       (FDD_Target_Cell_Notif_t,  FDD_ARFCN,  14, &hf_fdd_target_cell_notif_fdd_arfcn),
  M_NEXT_EXIST (FDD_Target_Cell_Notif_t, Exist_Bandwith_FDD, 1),
  M_UINT       (FDD_Target_Cell_Notif_t,  BANDWITH_FDD,  3, &hf_fdd_target_cell_notif_bandwith_fdd),
  M_UINT       (FDD_Target_Cell_Notif_t,  SCRAMBLING_CODE,  9, &hf_fdd_target_cell_notif_scrambling_code),
CSN_DESCR_END  (FDD_Target_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(TDD_Target_Cell_Notif_t)
  M_UINT       (TDD_Target_Cell_Notif_t,  TDD_ARFCN,  14, &hf_tddarget_cell_t_tdd_arfcn),
  M_NEXT_EXIST (TDD_Target_Cell_Notif_t, Exist_Bandwith_TDD, 1),
  M_UINT       (TDD_Target_Cell_Notif_t,  BANDWITH_TDD,  3, &hf_tddarget_cell_t_bandwith_tdd),
  M_UINT       (TDD_Target_Cell_Notif_t,  CELL_PARAMETER,  7, &hf_tddarget_cell_t_cell_parameter),
  M_UINT       (TDD_Target_Cell_Notif_t,  Sync_Case_TSTD,  1, &hf_tddarget_cell_t_sync_case_tstd),
CSN_DESCR_END  (TDD_Target_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_3G_Notif_t)
  M_NEXT_EXIST (Target_Cell_3G_Notif_t, Exist_FDD_Description, 1),
  M_TYPE       (Target_Cell_3G_Notif_t, FDD_Target_Cell_Notif, FDD_Target_Cell_Notif_t),
  M_NEXT_EXIST (Target_Cell_3G_Notif_t, Exist_TDD_Description, 1),
  M_TYPE       (Target_Cell_3G_Notif_t, TDD_Target_Cell, TDD_Target_Cell_Notif_t),
  M_UINT       (Target_Cell_3G_Notif_t,  REPORTING_QUANTITY,  6, &hf_target_cell_3g_notif_reporting_quantity),
CSN_DESCR_END  (Target_Cell_3G_Notif_t)

static const
CSN_DESCR_BEGIN(Target_EUTRAN_Cell_Notif_t)
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  EARFCN,  16, &hf_target_cell_eutran_earfcn),
  M_NEXT_EXIST (Target_EUTRAN_Cell_Notif_t, Exist_Measurement_Bandwidth, 1),
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  Measurement_Bandwidth,  3, &hf_target_cell_eutran_measurement_bandwidth),
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  Physical_Layer_Cell_Identity,  9, &hf_target_cell_eutran_pl_cell_id),
  M_UINT       (Target_EUTRAN_Cell_Notif_t,  Reporting_Quantity,  6, &hf_packet_cell_change_notification_lte_reporting_quantity),
CSN_DESCR_END  (Target_EUTRAN_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(Eutran_Ccn_Measurement_Report_Cell_t)
  M_UINT       (Eutran_Ccn_Measurement_Report_Cell_t,  EUTRAN_FREQUENCY_INDEX,  3, &hf_eutran_ccn_meas_rpt_freq_idx),
  M_UINT       (Eutran_Ccn_Measurement_Report_Cell_t,  CELL_IDENTITY,  9, &hf_eutran_ccn_meas_cell_id),
  M_UINT       (Eutran_Ccn_Measurement_Report_Cell_t,  REPORTING_QUANTITY,  6, &hf_eutran_ccn_meas_rpt_quantity),
CSN_DESCR_END  (Eutran_Ccn_Measurement_Report_Cell_t)


static const
CSN_DESCR_BEGIN(Eutran_Ccn_Measurement_Report_t)
  M_UINT       (Eutran_Ccn_Measurement_Report_t,  ThreeG_BA_USED, 1, &hf_eutran_ccn_meas_rpt_3g_ba_used),
  M_UINT_OFFSET(Eutran_Ccn_Measurement_Report_t,  N_EUTRAN,  2, 1),
  M_VAR_TARRAY (Eutran_Ccn_Measurement_Report_t,  Eutran_Ccn_Measurement_Report_Cell, Eutran_Ccn_Measurement_Report_Cell_t, N_EUTRAN),
CSN_DESCR_END  (Eutran_Ccn_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(Target_Cell_4G_Notif_t)
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_Arfcn, 2),
  M_UINT       (Target_Cell_4G_Notif_t,  Arfcn, 10, &hf_arfcn),
  M_UINT       (Target_Cell_4G_Notif_t,  bsic, 6, &hf_target_cell_gsm_bsic),
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_3G_Target_Cell, 1),
  M_TYPE       (Target_Cell_4G_Notif_t,  Target_Cell_3G_Notif, Target_Cell_3G_Notif_t),
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_Eutran_Target_Cell, 1),
  M_TYPE       (Target_Cell_4G_Notif_t,  Target_EUTRAN_Cell, Target_EUTRAN_Cell_Notif_t),
  M_NEXT_EXIST (Target_Cell_4G_Notif_t, Exist_Eutran_Ccn_Measurement_Report, 1),
  M_TYPE       (Target_Cell_4G_Notif_t,  Eutran_Ccn_Measurement_Report, Eutran_Ccn_Measurement_Report_t),
CSN_DESCR_END  (Target_Cell_4G_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_CSG_Notif_t)
  M_FIXED      (Target_Cell_CSG_Notif_t, 1, 0x00),
  M_UNION      (Target_Cell_CSG_Notif_t, 2),
  M_TYPE       (Target_Cell_CSG_Notif_t, u.UTRAN_CSG_Measurement_Report, UTRAN_CSG_Measurement_Report_t),
  M_TYPE       (Target_Cell_CSG_Notif_t, u.EUTRAN_CSG_Measurement_Report, EUTRAN_CSG_Measurement_Report_t),
  M_NEXT_EXIST (Target_Cell_CSG_Notif_t, Exist_Eutran_Ccn_Measurement_Report, 1),
  M_TYPE       (Target_Cell_CSG_Notif_t,  Eutran_Ccn_Measurement_Report, Eutran_Ccn_Measurement_Report_t),
CSN_DESCR_END  (Target_Cell_CSG_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Other_RAT_2_Notif_t)
  /* 110 vs 1110 */
  M_UNION      (Target_Other_RAT_2_Notif_t, 2),
  M_TYPE       (Target_Other_RAT_2_Notif_t, u.Target_Cell_4G_Notif, Target_Cell_4G_Notif_t),
  M_TYPE       (Target_Other_RAT_2_Notif_t, u.Target_Cell_CSG_Notif, Target_Cell_CSG_Notif_t),
CSN_DESCR_END  (Target_Other_RAT_2_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Other_RAT_Notif_t)
  /* 10 vs 110 */
  M_UNION      (Target_Other_RAT_Notif_t, 2),
  M_TYPE       (Target_Other_RAT_Notif_t, u.Target_Cell_3G_Notif, Target_Cell_3G_Notif_t),
  M_TYPE       (Target_Other_RAT_Notif_t, u.Target_Other_RAT_2_Notif, Target_Other_RAT_2_Notif_t),
CSN_DESCR_END  (Target_Other_RAT_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_t)
  /* 0 vs 10 */
  M_UNION      (Target_Cell_t, 2),
  M_TYPE       (Target_Cell_t, u.Target_Cell_GSM_Notif, Target_Cell_GSM_Notif_t),
  M_TYPE       (Target_Cell_t, u.Target_Other_RAT_Notif, Target_Other_RAT_Notif_t),
CSN_DESCR_END  (Target_Cell_t)

static const
CSN_DESCR_BEGIN (PCCN_AdditionsR6_t)
  M_NEXT_EXIST  (PCCN_AdditionsR6_t, Exist_BA_USED_3G, 1),
  M_UINT        (PCCN_AdditionsR6_t,  BA_USED_3G,  1, &hf_pccn_additionsr6_ba_used_3g),

  M_UINT_OFFSET (PCCN_AdditionsR6_t, N_3G, 3, 1),   /* offset 1 */
  M_VAR_TARRAY_OFFSET (PCCN_AdditionsR6_t, Measurements_3G, Measurements_3G_t, N_3G),
CSN_DESCR_END   (PCCN_AdditionsR6_t)

/*< Packet Cell Change Notification message contents > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Notification_t)
  /* Mac header */
  M_UINT              (Packet_Cell_Change_Notification_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT              (Packet_Cell_Change_Notification_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT              (Packet_Cell_Change_Notification_t,  R, 1, &hf_ul_retry),
  M_UINT              (Packet_Cell_Change_Notification_t,  MESSAGE_TYPE, 6, &hf_ul_message_type),
  /* Mac header */

  M_TYPE              (Packet_Cell_Change_Notification_t, Global_TFI, Global_TFI_t),
  M_TYPE              (Packet_Cell_Change_Notification_t, Target_Cell, Target_Cell_t),

  M_UNION             (Packet_Cell_Change_Notification_t, 2),
  M_UINT              (Packet_Cell_Change_Notification_t,  u.BA_IND,  1, &hf_packet_cell_change_notification_ba_ind),
  M_UINT              (Packet_Cell_Change_Notification_t,  u.PSI3_CHANGE_MARK, 2, &hf_psi3_change_mark),

  M_UINT              (Packet_Cell_Change_Notification_t,  PMO_USED,  1, &hf_packet_cell_change_notification_pmo_used),
  M_UINT              (Packet_Cell_Change_Notification_t,  PCCN_SENDING,  1, &hf_packet_cell_change_notification_pccn_sending),
  M_TYPE              (Packet_Cell_Change_Notification_t, CCN_Measurement_Report, CCN_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Cell_Change_Notification_t, Exist_AdditionsR6, 1),
  M_TYPE              (Packet_Cell_Change_Notification_t, AdditionsR6, PCCN_AdditionsR6_t),

  M_PADDING_BITS(Packet_Cell_Change_Notification_t),
CSN_DESCR_END  (Packet_Cell_Change_Notification_t)

/*< Packet Cell Change Continue message contents > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Continue_t)
  M_UINT       (Packet_Cell_Change_Continue_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Cell_Change_Continue_t, PAGE_MODE, 2, &hf_page_mode),
  M_FIXED      (Packet_Cell_Change_Continue_t, 1, 0x00),
  M_TYPE       (Packet_Cell_Change_Continue_t, Global_TFI, Global_TFI_t),

  M_NEXT_EXIST (Packet_Cell_Change_Continue_t, Exist_ID, 3),
  M_UINT       (Packet_Cell_Change_Continue_t, ARFCN, 10, &hf_packet_cell_change_continue_arfcn),
  M_UINT       (Packet_Cell_Change_Continue_t, BSIC,  6, &hf_packet_cell_change_continue_bsic),
  M_UINT       (Packet_Cell_Change_Continue_t, CONTAINER_ID,  2, &hf_packet_cell_change_continue_container_id),

  M_PADDING_BITS(Packet_Cell_Change_Continue_t),
CSN_DESCR_END  (Packet_Cell_Change_Continue_t)

/*< Packet Neighbour Cell Data message contents > */
static const
CSN_DESCR_BEGIN(PNCD_Container_With_ID_t)
  M_UINT       (PNCD_Container_With_ID_t,  ARFCN, 10, &hf_arfcn),
  M_UINT       (PNCD_Container_With_ID_t,  BSIC,  6, &hf_pncd_container_with_id_bsic),
  M_UINT_ARRAY (PNCD_Container_With_ID_t, CONTAINER, 8, 17),/* 8*17 bits */
CSN_DESCR_END  (PNCD_Container_With_ID_t)

static const
CSN_DESCR_BEGIN(PNCD_Container_Without_ID_t)
  M_UINT_ARRAY (PNCD_Container_Without_ID_t, CONTAINER, 8, 19),/* 8*19 bits */
CSN_DESCR_END  (PNCD_Container_Without_ID_t)

static const
CSN_ChoiceElement_t PNCDContainer[] =
{
  {1, 0x0, 0, M_TYPE(PNCDContainer_t, u.PNCD_Container_Without_ID, PNCD_Container_Without_ID_t)},
  {1, 0x1, 0, M_TYPE(PNCDContainer_t, u.PNCD_Container_With_ID, PNCD_Container_With_ID_t)},
};

static const
CSN_DESCR_BEGIN(PNCDContainer_t)
  M_CHOICE     (PNCDContainer_t, UnionType, PNCDContainer, ElementsOf(PNCDContainer)),
CSN_DESCR_END  (PNCDContainer_t)

static const
CSN_DESCR_BEGIN(Packet_Neighbour_Cell_Data_t)
  M_UINT       (Packet_Neighbour_Cell_Data_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Neighbour_Cell_Data_t, PAGE_MODE, 2, &hf_page_mode),
  M_FIXED      (Packet_Neighbour_Cell_Data_t, 1, 0x00),
  M_TYPE       (Packet_Neighbour_Cell_Data_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Neighbour_Cell_Data_t, CONTAINER_ID,  2, &hf_packet_neighbour_cell_data_container_id),
  M_UINT       (Packet_Neighbour_Cell_Data_t, spare,  1, &hf_packet_neighbour_cell_data_spare),
  M_UINT       (Packet_Neighbour_Cell_Data_t, CONTAINER_INDEX,  5, &hf_packet_neighbour_cell_data_container_index),

  M_TYPE       (Packet_Neighbour_Cell_Data_t, Container, PNCDContainer_t),
  M_PADDING_BITS(Packet_Neighbour_Cell_Data_t),
CSN_DESCR_END  (Packet_Neighbour_Cell_Data_t)

/*< Packet Serving Cell Data message contents > */
static const
CSN_DESCR_BEGIN(Packet_Serving_Cell_Data_t)
  M_UINT       (Packet_Serving_Cell_Data_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (Packet_Serving_Cell_Data_t, PAGE_MODE, 2, &hf_page_mode),
  M_FIXED      (Packet_Serving_Cell_Data_t, 1, 0x00),
  M_TYPE       (Packet_Serving_Cell_Data_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Serving_Cell_Data_t, spare,  4, &hf_packet_serving_cell_data_spare),
  M_UINT       (Packet_Serving_Cell_Data_t, CONTAINER_INDEX,  5, &hf_packet_serving_cell_data_container_index),
  M_UINT_ARRAY (Packet_Serving_Cell_Data_t, CONTAINER, 8, 19),/* 8*19 bits */
  M_PADDING_BITS(Packet_Serving_Cell_Data_t),
CSN_DESCR_END  (Packet_Serving_Cell_Data_t)


/* Enhanced Measurement Report */
static const
CSN_DESCR_BEGIN (ServingCellData_t)
  M_UINT        (ServingCellData_t,  RXLEV_SERVING_CELL,  6, &hf_servingcelldata_rxlev_serving_cell),
  M_FIXED       (ServingCellData_t, 1, 0),
CSN_DESCR_END   (ServingCellData_t)

static const
CSN_DESCR_BEGIN (Repeated_Invalid_BSIC_Info_t)
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  BCCH_FREQ_NCELL,  5, &hf_repeated_invalid_bsic_info_bcch_freq_ncell),
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  BSIC,  6, &hf_repeated_invalid_bsic_info_bsic),
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  RXLEV_NCELL,  5, &hf_repeated_invalid_bsic_info_rxlev_ncell),
CSN_DESCR_END   (Repeated_Invalid_BSIC_Info_t)

static const
CSN_DESCR_BEGIN (REPORTING_QUANTITY_t)
  M_NEXT_EXIST  (REPORTING_QUANTITY_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT        (REPORTING_QUANTITY_t,  REPORTING_QUANTITY,  6, &hf_reporting_quantity_reporting_quantity),
CSN_DESCR_END   (REPORTING_QUANTITY_t)


static const
CSN_DESCR_BEGIN (NC_MeasurementReport_t)
  M_UINT        (NC_MeasurementReport_t, NC_MODE, 1, &hf_nc_measurementreport_nc_mode),
  M_UNION       (NC_MeasurementReport_t, 2),
  M_TYPE        (NC_MeasurementReport_t,  u.BA_USED, BA_USED_t),
  M_UINT        (NC_MeasurementReport_t,  u.PSI3_CHANGE_MARK, 2, &hf_psi3_change_mark),
  M_UINT        (NC_MeasurementReport_t, PMO_USED, 1, &hf_nc_measurementreport_pmo_used),
  M_UINT        (NC_MeasurementReport_t, SCALE, 1, &hf_nc_measurementreport_scale),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE        (NC_MeasurementReport_t, ServingCellData, ServingCellData_t),

  M_REC_TARRAY  (NC_MeasurementReport_t, Repeated_Invalid_BSIC_Info, Repeated_Invalid_BSIC_Info_t, Count_Repeated_Invalid_BSIC_Info),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_Repeated_REPORTING_QUANTITY, 1),
  M_VAR_TARRAY  (NC_MeasurementReport_t, Repeated_REPORTING_QUANTITY, REPORTING_QUANTITY_t, Count_Repeated_Reporting_Quantity),
CSN_DESCR_END   (NC_MeasurementReport_t)



/*< Packet Handover Command message content > */
static const
CSN_DESCR_BEGIN (GlobalTimeslotDescription_t)
  M_UNION       (GlobalTimeslotDescription_t, 2),
  M_UINT        (GlobalTimeslotDescription_t,  u.MS_TimeslotAllocation,  8, &hf_globaltimeslotdescription_ms_timeslotallocation),
  M_TYPE        (GlobalTimeslotDescription_t, u.Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END   (GlobalTimeslotDescription_t)

static const
CSN_DESCR_BEGIN (PHO_DownlinkAssignment_t)
  M_UINT        (PHO_DownlinkAssignment_t,  TimeslotAllocation,  8, &hf_dl_timeslot_allocation),
  M_UINT        (PHO_DownlinkAssignment_t,  PFI, 7, &hf_pfi),
  M_UINT        (PHO_DownlinkAssignment_t,  RLC_Mode, 1, &hf_rlc_mode),
  M_UINT        (PHO_DownlinkAssignment_t,  TFI_Assignment, 5, &hf_downlink_tfi),
  M_UINT        (PHO_DownlinkAssignment_t,  ControlACK, 1, &hf_control_ack),

  M_NEXT_EXIST  (PHO_DownlinkAssignment_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (PHO_DownlinkAssignment_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),
CSN_DESCR_END   (PHO_DownlinkAssignment_t)

static const
CSN_DESCR_BEGIN (PHO_USF_1_7_t)
  M_NEXT_EXIST  (PHO_USF_1_7_t, Exist_USF, 1),
  M_UINT        (PHO_USF_1_7_t,  USF,  3, &hf_pho_usf_1_7_usf),
CSN_DESCR_END   (PHO_USF_1_7_t)

static const
CSN_DESCR_BEGIN       (USF_AllocationArray_t)
  M_UINT              (USF_AllocationArray_t,  USF_0,  3, &hf_usf_allocationarray_usf_0),
  M_VAR_TARRAY_OFFSET (USF_AllocationArray_t, USF_1_7, PHO_USF_1_7_t, NBR_OfAllocatedTimeslots),
CSN_DESCR_END         (USF_AllocationArray_t)

static const
CSN_DESCR_BEGIN  (PHO_UplinkAssignment_t)
  M_UINT         (PHO_UplinkAssignment_t, PFI, 7, &hf_pfi),
  M_UINT         (PHO_UplinkAssignment_t, RLC_Mode, 1, &hf_rlc_mode),
  M_UINT         (PHO_UplinkAssignment_t, TFI_Assignment, 5, &hf_downlink_tfi),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_ChannelCodingCommand, 1),
  M_UINT         (PHO_UplinkAssignment_t,  ChannelCodingCommand, 2, &hf_gprs_channel_coding_command),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_EGPRS_ChannelCodingCommand, 1),
  M_UINT         (PHO_UplinkAssignment_t,  EGPRS_ChannelCodingCommand, 4, &hf_egprs_channel_coding_command),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_EGPRS_WindowSize, 1),
  M_UINT         (PHO_UplinkAssignment_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),

  M_UINT         (PHO_UplinkAssignment_t, USF_Granularity, 1, &hf_usf_granularity),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_TBF_TimeslotAllocation, 1),
  M_LEFT_VAR_BMP (PHO_UplinkAssignment_t,  TBF_TimeslotAllocation, u.USF_AllocationArray.NBR_OfAllocatedTimeslots, 0),

  M_UNION        (PHO_UplinkAssignment_t, 2),
  M_UINT         (PHO_UplinkAssignment_t,  u.USF_SingleAllocation, 3, &hf_usf),
  M_TYPE         (PHO_UplinkAssignment_t,  u.USF_AllocationArray, USF_AllocationArray_t),
CSN_DESCR_END    (PHO_UplinkAssignment_t)

static const
CSN_DESCR_BEGIN (GlobalTimeslotDescription_UA_t)
  M_TYPE        (GlobalTimeslotDescription_UA_t, GlobalTimeslotDescription, GlobalTimeslotDescription_t),
  M_NEXT_EXIST  (GlobalTimeslotDescription_UA_t, Exist_PHO_UA, 3),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */

  M_TYPE        (GlobalTimeslotDescription_UA_t, PHO_UA, PHO_UplinkAssignment_t),
  M_FIXED       (GlobalTimeslotDescription_UA_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (GlobalTimeslotDescription_UA_t)

static const
CSN_DESCR_BEGIN (PHO_GPRS_t)
  M_NEXT_EXIST  (PHO_GPRS_t, Exist_ChannelCodingCommand, 1),
  M_UINT        (PHO_GPRS_t,  ChannelCodingCommand, 2, &hf_gprs_channel_coding_command),

  M_NEXT_EXIST  (PHO_GPRS_t, Exist_GlobalTimeslotDescription_UA, 1),
  M_TYPE        (PHO_GPRS_t, GTD_UA, GlobalTimeslotDescription_UA_t),

  M_NEXT_EXIST  (PHO_GPRS_t, Exist_DownlinkAssignment, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */
  M_TYPE        (PHO_GPRS_t, DownlinkAssignment, PHO_DownlinkAssignment_t),
  M_FIXED       (PHO_GPRS_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (PHO_GPRS_t)

static const
CSN_DESCR_BEGIN (EGPRS_Description_t)
  M_NEXT_EXIST  (EGPRS_Description_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (EGPRS_Description_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),

  M_UINT        (EGPRS_Description_t,  LinkQualityMeasurementMode,  2, &hf_egprs_description_linkqualitymeasurementmode),
  M_NEXT_EXIST  (EGPRS_Description_t, Exist_BEP_Period2, 1),
  M_UINT        (EGPRS_Description_t,  BEP_Period2,  4, &hf_bep_period2),
CSN_DESCR_END   (EGPRS_Description_t)

static const
CSN_DESCR_BEGIN (DownlinkTBF_t)
  M_NEXT_EXIST  (DownlinkTBF_t, Exist_EGPRS_Description, 1),
  M_TYPE        (DownlinkTBF_t, EGPRS_Description, EGPRS_Description_t),

  M_NEXT_EXIST  (DownlinkTBF_t, Exist_DownlinkAssignment, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */
  M_TYPE        (DownlinkTBF_t, DownlinkAssignment, PHO_DownlinkAssignment_t),
  M_FIXED       (DownlinkTBF_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (DownlinkTBF_t)

static const
CSN_DESCR_BEGIN (PHO_EGPRS_t)
  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (PHO_EGPRS_t,  EGPRS_WindowSize, 5, &hf_egprs_windowsize),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_EGPRS_ChannelCodingCommand, 1),
  M_UINT        (PHO_EGPRS_t,  EGPRS_ChannelCodingCommand, 4, &hf_egprs_channel_coding_command),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_BEP_Period2, 1),
  M_UINT        (PHO_EGPRS_t,  BEP_Period2, 4, &hf_bep_period2),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_GlobalTimeslotDescription_UA, 1),
  M_TYPE        (PHO_EGPRS_t, GTD_UA, GlobalTimeslotDescription_UA_t),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_DownlinkTBF, 2),
  M_TYPE        (PHO_EGPRS_t, DownlinkTBF, DownlinkTBF_t),
CSN_DESCR_END   (PHO_EGPRS_t)

static const
CSN_DESCR_BEGIN(PHO_TimingAdvance_t)
  M_TYPE       (PHO_TimingAdvance_t, GlobalPacketTimingAdvance, Global_Packet_Timing_Advance_t),
  M_NEXT_EXIST (PHO_TimingAdvance_t, Exist_PacketExtendedTimingAdvance, 1),
  M_UINT       (PHO_TimingAdvance_t,  PacketExtendedTimingAdvance, 2, &hf_packet_extended_timing_advance),
CSN_DESCR_END  (PHO_TimingAdvance_t)

static const
CSN_DESCR_BEGIN(NAS_Container_t)
  M_UINT       (NAS_Container_t,  NAS_ContainerLength,  7, &hf_nas_container_nas_containerlength),
  M_VAR_ARRAY  (NAS_Container_t, NAS_Container, NAS_ContainerLength, 0),
CSN_DESCR_END  (NAS_Container_t)

static const
CSN_DESCR_BEGIN(PS_HandoverTo_UTRAN_Payload_t)
  M_UINT       (PS_HandoverTo_UTRAN_Payload_t,  RRC_ContainerLength,  8, &hf_ps_handoverto_utran_payload_rrc_containerlength),
  M_VAR_ARRAY  (PS_HandoverTo_UTRAN_Payload_t, RRC_Container, RRC_ContainerLength, 0),
CSN_DESCR_END  (PS_HandoverTo_UTRAN_Payload_t)


static const
CSN_DESCR_BEGIN(PHO_RadioResources_t)
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_HandoverReference, 1),
  M_UINT       (PHO_RadioResources_t,  HandoverReference,  8, &hf_pho_radioresources_handoverreference),

  M_UINT       (PHO_RadioResources_t, ARFCN, 10, &hf_arfcn),
  M_UINT       (PHO_RadioResources_t,  SI,  2, &hf_pho_radioresources_si),
  M_UINT       (PHO_RadioResources_t,  NCI, 1, &hf_pho_radioresources_nci),
  M_UINT       (PHO_RadioResources_t,  BSIC,  6, &hf_pho_radioresources_bsic),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Active, 1),
  M_UINT       (PHO_RadioResources_t,  CCN_Active, 1, &hf_pho_radioresources_ccn_active),

  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Active_3G, 1),
  M_UINT       (PHO_RadioResources_t,  CCN_Active_3G, 1, &hf_pho_radioresources_ccn_active_3g),

  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Support_Description, 1),
  M_TYPE       (PHO_RadioResources_t, CCN_Support_Description, CCN_Support_Description_t),

  M_TYPE       (PHO_RadioResources_t, Frequency_Parameters, Frequency_Parameters_t),
  M_UINT       (PHO_RadioResources_t,  NetworkControlOrder,  2, &hf_pho_radioresources_networkcontrolorder),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_PHO_TimingAdvance, 1),
  M_TYPE       (PHO_RadioResources_t, PHO_TimingAdvance, PHO_TimingAdvance_t),

  M_UINT       (PHO_RadioResources_t,  Extended_Dynamic_Allocation, 1, &hf_extended_dynamic_allocation),
  M_UINT       (PHO_RadioResources_t,  RLC_Reset, 1, &hf_pho_radioresources_rlc_reset),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_PO_PR, 2),
  M_UINT       (PHO_RadioResources_t,  PO, 4, &hf_p0),
  M_UINT       (PHO_RadioResources_t,  PR_Mode, 1, &hf_pr_mode),


  M_NEXT_EXIST (PHO_RadioResources_t, Exist_UplinkControlTimeslot, 1),
  M_UINT       (PHO_RadioResources_t,  UplinkControlTimeslot,  3, &hf_pho_radioresources_uplinkcontroltimeslot),

  M_UNION      (PHO_RadioResources_t, 2),
  M_TYPE       (PHO_RadioResources_t, u.PHO_GPRS_Mode, PHO_GPRS_t),
  M_TYPE       (PHO_RadioResources_t, u.PHO_EGPRS_Mode, PHO_EGPRS_t),
CSN_DESCR_END  (PHO_RadioResources_t)

static const
CSN_DESCR_BEGIN(PS_HandoverTo_A_GB_ModePayload_t)
  M_FIXED      (PS_HandoverTo_A_GB_ModePayload_t, 2, 0x00), /* For future extension to enum. */
  M_TYPE       (PS_HandoverTo_A_GB_ModePayload_t, PHO_RadioResources, PHO_RadioResources_t),

  M_NEXT_EXIST (PS_HandoverTo_A_GB_ModePayload_t, Exist_NAS_Container, 1),
  M_TYPE       (PS_HandoverTo_A_GB_ModePayload_t, NAS_Container, NAS_Container_t),
CSN_DESCR_END  (PS_HandoverTo_A_GB_ModePayload_t)

static const
CSN_DESCR_BEGIN(Packet_Handover_Command_t)
  M_UINT       (Packet_Handover_Command_t, MessageType,6, &hf_dl_message_type),
  M_UINT       (Packet_Handover_Command_t, PageMode, 2, &hf_page_mode),

  M_FIXED      (Packet_Handover_Command_t, 1, 0x00), /* 0 fixed */
  M_TYPE       (Packet_Handover_Command_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Handover_Command_t,  ContainerID,  2, &hf_packet_handover_command_containerid),

  M_UNION      (Packet_Handover_Command_t, 4),
  M_TYPE       (Packet_Handover_Command_t, u.PS_HandoverTo_A_GB_ModePayload, PS_HandoverTo_A_GB_ModePayload_t),
  M_TYPE       (Packet_Handover_Command_t, u.PS_HandoverTo_UTRAN_Payload, PS_HandoverTo_UTRAN_Payload_t),
  CSN_ERROR    (Packet_Handover_Command_t, "10 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (Packet_Handover_Command_t, "11 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_PADDING_BITS(Packet_Handover_Command_t),
CSN_DESCR_END  (Packet_Handover_Command_t)

/*< End Packet Handover Command >*/

/*< Packet Physical Information message content > */

static const
CSN_DESCR_BEGIN(Packet_PhysicalInformation_t)
  M_UINT       (Packet_PhysicalInformation_t,  MessageType, 6, &hf_dl_message_type),
  M_UINT       (Packet_PhysicalInformation_t,  PageMode, 2, &hf_page_mode),

  M_TYPE       (Packet_PhysicalInformation_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_PhysicalInformation_t,  TimingAdvance, 8, &hf_timing_advance_value),
  M_PADDING_BITS(Packet_PhysicalInformation_t),
CSN_DESCR_END  (Packet_PhysicalInformation_t)

/*< End Packet Physical Information > */


/*< ADDITIONAL MS RADIO ACCESS CAPABILITIES content > */
static const
CSN_ChoiceElement_t AdditionalMsRadAccessCapID[] =
{
  {1, 0,    0, M_TYPE(AdditionalMsRadAccessCapID_t, u.Global_TFI, Global_TFI_t)},
  {1, 0x01, 0, M_UINT(AdditionalMsRadAccessCapID_t, u.TLLI, 32, &hf_tlli)},
};

static const
CSN_DESCR_BEGIN(AdditionalMsRadAccessCapID_t)
  M_CHOICE     (AdditionalMsRadAccessCapID_t, UnionType, AdditionalMsRadAccessCapID, ElementsOf(AdditionalMsRadAccessCapID)),
CSN_DESCR_END  (AdditionalMsRadAccessCapID_t)


static const
CSN_DESCR_BEGIN       (Additional_MS_Rad_Access_Cap_t)
  /* Mac header */
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  PayloadType, 2, &hf_ul_payload_type),
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  spare, 5, &hf_ul_mac_header_spare),
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  R, 1, &hf_ul_retry),
  M_UINT              (Additional_MS_Rad_Access_Cap_t,  MESSAGE_TYPE,  6, &hf_ul_message_type),
  /* Mac header */

  M_TYPE              (Additional_MS_Rad_Access_Cap_t,  ID, AdditionalMsRadAccessCapID_t),
  M_TYPE              (Additional_MS_Rad_Access_Cap_t,  MS_Radio_Access_capability, MS_Radio_Access_capability_t),
  M_PADDING_BITS      (Additional_MS_Rad_Access_Cap_t),
CSN_DESCR_END         (Additional_MS_Rad_Access_Cap_t)


/*< End  ADDITIONAL MS RADIO ACCESS CAPABILITIES > */


/*< Packet Pause content > */

static const
CSN_DESCR_BEGIN       (Packet_Pause_t)
  M_UINT              (Packet_Pause_t,  MESSAGE_TYPE, 2, &hf_dl_message_type),
  M_UINT              (Packet_Pause_t,  TLLI, 32, &hf_tlli),
  M_BITMAP            (Packet_Pause_t,  RAI, 48),
  M_PADDING_BITS      (Packet_Pause_t),
CSN_DESCR_END         (Packet_Pause_t)


/*< End Packet Pause > */


/*< Packet System Information Type 1 message content >*/
static const
CSN_DESCR_BEGIN(PSI1_AdditionsR6_t)
  M_UINT       (PSI1_AdditionsR6_t, LB_MS_TXPWR_MAX_CCH, 5, &hf_packet_system_info_type1_lb_ms_txpwr_max_ccch),
CSN_DESCR_END  (PSI1_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (PSI1_AdditionsR99_t)
  M_UINT               (PSI1_AdditionsR99_t, MSCR,  1, &hf_packet_system_info_type1_mscr),
  M_UINT               (PSI1_AdditionsR99_t, SGSNR,  1, &hf_sgsnr),
  M_UINT               (PSI1_AdditionsR99_t, BandIndicator,  1, &hf_packet_system_info_type1_band_indicator),
  M_NEXT_EXIST_OR_NULL (PSI1_AdditionsR99_t, Exist_AdditionsR6, 1),
  M_TYPE               (PSI1_AdditionsR99_t, AdditionsR6, PSI1_AdditionsR6_t),
CSN_DESCR_END          (PSI1_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(PCCCH_Organization_t)
  M_UINT       (PCCCH_Organization_t,  BS_PCC_REL,  1, &hf_pccch_org_bs_pcc_rel),
  M_UINT       (PCCCH_Organization_t,  BS_PBCCH_BLKS, 2, &hf_pccch_org_pbcch_blks),
  M_UINT       (PCCCH_Organization_t,  BS_PAG_BLKS_RES, 4, &hf_pccch_org_pag_blks_res),
  M_UINT       (PCCCH_Organization_t,  BS_PRACH_BLKS, 4, &hf_pccch_org_prach_blks),
CSN_DESCR_END  (PCCCH_Organization_t)


static const
CSN_DESCR_BEGIN(PSI1_t)
  M_UINT               (PSI1_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT               (PSI1_t, PAGE_MODE, 2, &hf_page_mode),

  M_UINT               (PSI1_t, PBCCH_CHANGE_MARK,  3, &hf_packet_system_info_type1_pbcch_change_mark),
  M_UINT               (PSI1_t, PSI_CHANGE_FIELD,  4, &hf_packet_system_info_type1_psi_change_field),
  M_UINT               (PSI1_t, PSI1_REPEAT_PERIOD,  4, &hf_packet_system_info_type1_psi1_repeat_period),
  M_UINT               (PSI1_t, PSI_COUNT_LR,  6, &hf_packet_system_info_type1_psi_count_lr),

  M_NEXT_EXIST         (PSI1_t, Exist_PSI_COUNT_HR, 1),
  M_UINT               (PSI1_t, PSI_COUNT_HR,  4, &hf_packet_system_info_type1_psi_count_hr),

  M_UINT               (PSI1_t, MEASUREMENT_ORDER,  1, &hf_packet_system_info_type1_measurement_order),
  M_TYPE               (PSI1_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE               (PSI1_t, PRACH_Control, PRACH_Control_t),
  M_TYPE               (PSI1_t, PCCCH_Organization, PCCCH_Organization_t),
  M_TYPE               (PSI1_t, Global_Power_Control_Parameters, Global_Power_Control_Parameters_t),
  M_UINT               (PSI1_t, PSI_STATUS_IND,  1, &hf_packet_system_info_type1_psi_status_ind),

  M_NEXT_EXIST_OR_NULL (PSI1_t, Exist_AdditionsR99, 1),
  M_TYPE               (PSI1_t, AdditionsR99, PSI1_AdditionsR99_t),

  M_PADDING_BITS(PSI1_t),
CSN_DESCR_END  (PSI1_t)
/*< End Packet System Information Type 1 message content >*/


/*< Packet System Information Type 2 message content >*/

static const
CSN_DESCR_BEGIN(LAI_t)
  M_TYPE       (LAI_t,  PLMN, PLMN_t),
  M_UINT       (LAI_t,  LAC,  16, &hf_packet_lai_lac),
CSN_DESCR_END  (LAI_t)

static const
CSN_DESCR_BEGIN(Cell_Identification_t)
  M_TYPE       (Cell_Identification_t,  LAI, LAI_t),
  M_UINT       (Cell_Identification_t,  RAC, 8, &hf_rac),
  M_UINT       (Cell_Identification_t,  Cell_Identity,  16, &hf_packet_cell_id_cell_identity),
CSN_DESCR_END  (Cell_Identification_t)

static const
CSN_DESCR_BEGIN(Non_GPRS_Cell_Options_t)
  M_UINT       (Non_GPRS_Cell_Options_t,  ATT, 1, &hf_packet_non_gprs_cell_opt_att),
  
  M_NEXT_EXIST (Non_GPRS_Cell_Options_t, Exist_T3212, 1),
  M_UINT       (Non_GPRS_Cell_Options_t,  T3212, 8, &hf_packet_non_gprs_cell_opt_t3212),
  
  M_UINT       (Non_GPRS_Cell_Options_t,  NECI, 1, &hf_packet_non_gprs_cell_opt_neci),
  M_UINT       (Non_GPRS_Cell_Options_t,  PWRC, 1, &hf_packet_non_gprs_cell_opt_pwrc),
  M_UINT       (Non_GPRS_Cell_Options_t,  DTX, 2, &hf_packet_non_gprs_cell_opt_dtx),
  M_UINT       (Non_GPRS_Cell_Options_t,  RADIO_LINK_TIMEOUT, 4, &hf_packet_non_gprs_cell_opt_radio_link_timeout),
  M_UINT       (Non_GPRS_Cell_Options_t,  BS_AG_BLKS_RES, 3, &hf_packet_non_gprs_cell_opt_bs_ag_blks_res),
  M_UINT       (Non_GPRS_Cell_Options_t,  CCCH_CONF, 3, &hf_packet_non_gprs_cell_opt_ccch_conf),
  M_UINT       (Non_GPRS_Cell_Options_t,  BS_PA_MFRMS, 3, &hf_packet_non_gprs_cell_opt_bs_pa_mfrms),
  M_UINT       (Non_GPRS_Cell_Options_t,  MAX_RETRANS, 2, &hf_packet_non_gprs_cell_opt_max_retrans),
  M_UINT       (Non_GPRS_Cell_Options_t,  TX_INTEGER, 4, &hf_packet_non_gprs_cell_opt_tx_int),
  M_UINT       (Non_GPRS_Cell_Options_t,  EC, 1, &hf_packet_non_gprs_cell_opt_ec),
  M_UINT       (Non_GPRS_Cell_Options_t,  MS_TXPWR_MAX_CCCH, 5, &hf_packet_non_gprs_cell_opt_ms_txpwr_max_ccch),

  M_NEXT_EXIST (Non_GPRS_Cell_Options_t, Exist_Extension_Bits, 1),
  M_TYPE       (Non_GPRS_Cell_Options_t,  Extension_Bits, Extension_Bits_t),
CSN_DESCR_END  (Non_GPRS_Cell_Options_t)

static const
CSN_DESCR_BEGIN(Reference_Frequency_t)
  M_UINT(Reference_Frequency_t, NUMBER, 4, &hf_packet_system_info_type2_ref_freq_num),
  M_UINT_OFFSET(Reference_Frequency_t, Length, 4, 3),
  M_VAR_ARRAY  (Reference_Frequency_t, Contents[0], Length, 0),
CSN_DESCR_END  (Reference_Frequency_t)

static const
CSN_DESCR_BEGIN(PSI2_MA_t)
  M_UINT(PSI2_MA_t, NUMBER, 4, &hf_packet_system_info_type2_ma_number),
  M_TYPE(PSI2_MA_t, Mobile_Allocation, GPRS_Mobile_Allocation_t),
CSN_DESCR_END  (PSI2_MA_t)

static const
CSN_DESCR_BEGIN(Non_Hopping_PCCCH_Carriers_t)
  M_UINT(Non_Hopping_PCCCH_Carriers_t, ARFCN, 10, &hf_arfcn),
  M_UINT(Non_Hopping_PCCCH_Carriers_t, TIMESLOT_ALLOCATION, 8, &hf_packet_system_info_type2_non_hopping_timeslot),
CSN_DESCR_END  (Non_Hopping_PCCCH_Carriers_t)

static const
CSN_DESCR_BEGIN(NonHoppingPCCCH_t)
  M_REC_TARRAY (NonHoppingPCCCH_t, Carriers[0], Non_Hopping_PCCCH_Carriers_t, Count_Carriers),
CSN_DESCR_END  (NonHoppingPCCCH_t)

static const
CSN_DESCR_BEGIN(Hopping_PCCCH_Carriers_t)
  M_UINT(Hopping_PCCCH_Carriers_t, MAIO, 6, &hf_maio),
  M_UINT(Hopping_PCCCH_Carriers_t, TIMESLOT_ALLOCATION, 8, &hf_packet_system_info_type2_hopping_timeslot),
CSN_DESCR_END  (Hopping_PCCCH_Carriers_t)

static const
CSN_DESCR_BEGIN(HoppingPCCCH_t)
  M_UINT(HoppingPCCCH_t, MA_NUMBER, 4, &hf_packet_system_info_type2_hopping_ma_num),
  M_REC_TARRAY (HoppingPCCCH_t, Carriers[0], Hopping_PCCCH_Carriers_t, Count_Carriers),
CSN_DESCR_END  (HoppingPCCCH_t)

static const
CSN_DESCR_BEGIN(PCCCH_Description_t)
  M_UINT(PCCCH_Description_t, TSC, 3, &hf_tsc),
  M_UNION     (PCCCH_Description_t, 2),
  M_TYPE      (PCCCH_Description_t, u.NonHopping, NonHoppingPCCCH_t),
  M_TYPE      (PCCCH_Description_t, u.Hopping, HoppingPCCCH_t),
CSN_DESCR_END  (PCCCH_Description_t)

static const
CSN_DESCR_BEGIN(PSI2_t)
  M_UINT       (PSI2_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (PSI2_t, PAGE_MODE, 2, &hf_page_mode),

  M_UINT       (PSI2_t, CHANGE_MARK, 2, &hf_packet_system_info_type2_change_mark),
  M_UINT       (PSI2_t, INDEX, 3, &hf_packet_system_info_type2_index),
  M_UINT       (PSI2_t, COUNT, 3, &hf_packet_system_info_type2_count),

  M_NEXT_EXIST (PSI2_t, Exist_Cell_Identification, 1),
  M_TYPE       (PSI2_t, Cell_Identification, Cell_Identification_t),

  M_NEXT_EXIST (PSI2_t, Exist_Non_GPRS_Cell_Options, 1),
  M_TYPE       (PSI2_t, Non_GPRS_Cell_Options, Non_GPRS_Cell_Options_t),

  M_REC_TARRAY (PSI2_t, Reference_Frequency[0], Reference_Frequency_t, Count_Reference_Frequency),
  M_TYPE       (PSI2_t, Cell_Allocation, Cell_Allocation_t),
  M_REC_TARRAY (PSI2_t, GPRS_MA[0], PSI2_MA_t, Count_GPRS_MA),
  M_REC_TARRAY (PSI2_t, PCCCH_Description[0], PCCCH_Description_t, Count_PCCCH_Description),
  M_PADDING_BITS(PSI2_t),
CSN_DESCR_END  (PSI2_t)
/*< End Packet System Information Type 2 message content >*/



/*< Packet System Information Type 3 message content >*/
static const
CSN_DESCR_BEGIN(Serving_Cell_params_t)
  M_UINT       (Serving_Cell_params_t,  CELL_BAR_ACCESS_2, 1, &hf_cell_bar_access_2),
  M_UINT       (Serving_Cell_params_t,  EXC_ACC, 1, &hf_exc_acc),
  M_UINT       (Serving_Cell_params_t,  GPRS_RXLEV_ACCESS_MIN, 6, &hf_packet_scell_param_gprs_rxlev_access_min),
  M_UINT       (Serving_Cell_params_t,  GPRS_MS_TXPWR_MAX_CCH, 5, &hf_packet_scell_param_gprs_ms_txpwr_max_cch),
  M_NEXT_EXIST (Serving_Cell_params_t, Exist_HCS, 1),
  M_TYPE       (Serving_Cell_params_t,  HCS, HCS_t),
  M_UINT       (Serving_Cell_params_t,  MULTIBAND_REPORTING, 2, &hf_packet_scell_param_multiband_reporting),
CSN_DESCR_END  (Serving_Cell_params_t)


static const
CSN_DESCR_BEGIN(Gen_Cell_Sel_t)
  M_UINT       (Gen_Cell_Sel_t,  GPRS_CELL_RESELECT_HYSTERESIS, 3, &hf_packet_gen_cell_sel_gprs_cell_resl_hyst),
  M_UINT       (Gen_Cell_Sel_t,  C31_HYST, 1, &hf_packet_gen_cell_sel_c31_hyst),
  M_UINT       (Gen_Cell_Sel_t,  C32_QUAL, 1, &hf_packet_gen_cell_sel_c32_qual),
  M_FIXED      (Gen_Cell_Sel_t, 1, 0x01),
    
  M_NEXT_EXIST (Gen_Cell_Sel_t, Exist_T_RESEL, 1),
  M_UINT       (Gen_Cell_Sel_t,  T_RESEL, 3, &hf_packet_gen_cell_sel_t_resel),

  M_NEXT_EXIST (Gen_Cell_Sel_t, Exist_RA_RESELECT_HYSTERESIS, 1),
  M_UINT       (Gen_Cell_Sel_t,  RA_RESELECT_HYSTERESIS, 3, &hf_packet_gen_cell_sel_ra_resel_hyst),
CSN_DESCR_END  (Gen_Cell_Sel_t)


static const
CSN_DESCR_BEGIN(COMPACT_Cell_Sel_t)
  M_UINT       (COMPACT_Cell_Sel_t,  bsic, 6, &hf_packet_compact_cell_sel_bsic),
  M_UINT       (COMPACT_Cell_Sel_t,  CELL_BAR_ACCESS_2, 1, &hf_cell_bar_access_2),
  M_UINT       (COMPACT_Cell_Sel_t,  EXC_ACC, 1, &hf_exc_acc),
  M_UINT       (COMPACT_Cell_Sel_t,  SAME_RA_AS_SERVING_CELL, 1, &hf_packet_compact_cell_sel_same_as_scell),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GPRS_RXLEV_ACCESS_MIN, 2),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_RXLEV_ACCESS_MIN, 6, &hf_packet_compact_cell_sel_gprs_rxlev_access_min),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_MS_TXPWR_MAX_CCH, 5, &hf_packet_compact_cell_sel_gprs_ms_txpwr_max_cch),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GPRS_TEMPORARY_OFFSET, 2),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_TEMPORARY_OFFSET, 3, &hf_packet_compact_cell_sel_gprs_temp_offset),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_PENALTY_TIME, 5, &hf_packet_compact_cell_sel_gprs_penalty_time),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GPRS_RESELECT_OFFSET, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  GPRS_RESELECT_OFFSET, 5, &hf_packet_compact_cell_sel_gprs_resel_offset),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_Hcs_Parm, 1),
  M_TYPE       (COMPACT_Cell_Sel_t,  HCS_Param, HCS_t),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_TIME_GROUP, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  TIME_GROUP, 2, &hf_packet_compact_cell_sel_time_group),
  M_NEXT_EXIST (COMPACT_Cell_Sel_t, Exist_GUAR_CONSTANT_PWR_BLKS, 1),
  M_UINT       (COMPACT_Cell_Sel_t,  GUAR_CONSTANT_PWR_BLKS, 2, &hf_packet_compact_cell_sel_guar_const_pwr_blks),
CSN_DESCR_END  (COMPACT_Cell_Sel_t)

static const
CSN_DESCR_BEGIN(COMPACT_Neighbour_Cell_Param_Remaining_t)
  M_VAR_BITMAP (COMPACT_Neighbour_Cell_Param_Remaining_t,  FREQUENCY_DIFF, FREQ_DIFF_LENGTH, 0),
  M_TYPE       (COMPACT_Neighbour_Cell_Param_Remaining_t,  COMPACT_Cell_Sel_Remain_Cells, COMPACT_Cell_Sel_t),
CSN_DESCR_END  (COMPACT_Neighbour_Cell_Param_Remaining_t)

CSN_CallBackStatus_t callback_init_COMP_Ncell_Param_FREQUENCY_DIFF(proto_tree *tree _U_, tvbuff_t *tvb _U_, void* param1, void* param2, int bit_offset _U_, int ett_csn1 _U_)
{
    guint  i;
    guint8 freq_diff_len = *(guint8*)param1;
    COMPACT_Neighbour_Cell_Param_Remaining_t *pCom_NCell_Param_rem = (COMPACT_Neighbour_Cell_Param_Remaining_t*)param2;

    for( i=0; i<16; i++, pCom_NCell_Param_rem++ )
    {
        pCom_NCell_Param_rem->FREQ_DIFF_LENGTH = freq_diff_len;
    }

    return 0;
}

static const
CSN_DESCR_BEGIN(COMPACT_Neighbour_Cell_Param_t)
  M_UINT       (COMPACT_Neighbour_Cell_Param_t,  START_FREQUENCY, 10, &hf_packet_compact_ncell_param_start_freq),
  M_TYPE       (COMPACT_Neighbour_Cell_Param_t,  COMPACT_Cell_Sel, COMPACT_Cell_Sel_t),
  M_UINT       (COMPACT_Neighbour_Cell_Param_t,  NR_OF_REMAINING_CELLS, 4, &hf_packet_compact_ncell_param_nr_of_remaining_cells),
  M_UINT_OFFSET(COMPACT_Neighbour_Cell_Param_t,  FREQ_DIFF_LENGTH, 3, 1),
  M_CALLBACK   (COMPACT_Neighbour_Cell_Param_t,  callback_init_COMP_Ncell_Param_FREQUENCY_DIFF, FREQ_DIFF_LENGTH, COMPACT_Neighbour_Cell_Param_Remaining),
  M_VAR_TARRAY (COMPACT_Neighbour_Cell_Param_t,  COMPACT_Neighbour_Cell_Param_Remaining, COMPACT_Neighbour_Cell_Param_Remaining_t, NR_OF_REMAINING_CELLS),
CSN_DESCR_END  (COMPACT_Neighbour_Cell_Param_t)


static const
CSN_DESCR_BEGIN(COMPACT_Info_t)
  M_TYPE       (COMPACT_Info_t,  Cell_Identification, Cell_Identification_t),
  M_REC_TARRAY (COMPACT_Info_t,  COMPACT_Neighbour_Cell_Param, COMPACT_Neighbour_Cell_Param_t, COMPACT_Neighbour_Cell_Param_Count),
CSN_DESCR_END  (COMPACT_Info_t)


static const
CSN_DESCR_BEGIN(PSI3_AdditionR4_t)
  M_NEXT_EXIST (PSI3_AdditionR4_t, Exist_CCN_Support_Desc, 1),
  M_TYPE       (PSI3_AdditionR4_t,  CCN_Support_Desc, CCN_Support_Description_t),
CSN_DESCR_END  (PSI3_AdditionR4_t)


static const
CSN_DESCR_BEGIN(PSI3_AdditionR99_t)
  M_FIXED      (PSI3_AdditionR99_t, 2, 0x00),
  M_NEXT_EXIST (PSI3_AdditionR99_t, Exist_COMPACT_Info, 1),
  M_TYPE       (PSI3_AdditionR99_t,  COMPACT_Info, COMPACT_Info_t),
  M_FIXED      (PSI3_AdditionR99_t, 1, 0x00),
  M_NEXT_EXIST (PSI3_AdditionR99_t, Exist_AdditionR4, 1),
  M_TYPE       (PSI3_AdditionR99_t,  AdditionR4, PSI3_AdditionR4_t),
CSN_DESCR_END  (PSI3_AdditionR99_t)


static const
CSN_DESCR_BEGIN(PSI3_AdditionR98_t)
  M_TYPE       (PSI3_AdditionR98_t,  Scell_LSA_ID_Info, LSA_ID_Info_t),

  M_NEXT_EXIST (PSI3_AdditionR98_t, Exist_LSA_Parameters, 1),
  M_TYPE       (PSI3_AdditionR98_t,  LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST (PSI3_AdditionR98_t, Exist_AdditionR99, 1),
  M_TYPE       (PSI3_AdditionR98_t,  AdditionR99, PSI3_AdditionR99_t),
CSN_DESCR_END  (PSI3_AdditionR98_t)


static const
CSN_DESCR_BEGIN(PSI3_t)
  M_UINT       (PSI3_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (PSI3_t, PAGE_MODE, 2, &hf_page_mode),
  M_UINT       (PSI3_t, CHANGE_MARK, 2, &hf_packet_system_info_type3_change_mark),
  M_UINT       (PSI3_t, BIS_COUNT, 4, &hf_packet_system_info_type3_bis_count),
  M_TYPE       (PSI3_t, Serving_Cell_params, Serving_Cell_params_t),
  M_TYPE       (PSI3_t, General_Cell_Selection, Gen_Cell_Sel_t),
  M_TYPE       (PSI3_t, NeighbourCellList, NeighbourCellList_t),
  
  M_NEXT_EXIST (PSI3_t, Exist_AdditionR98, 1),
  M_TYPE       (PSI3_t, AdditionR98, PSI3_AdditionR98_t),

  M_PADDING_BITS(PSI3_t),
CSN_DESCR_END  (PSI3_t)
/*< End Packet System Information Type 3 message content >*/


/*< Packet System Information Type 5 message content >*/
static const
CSN_DESCR_BEGIN(MeasurementParams_t)
  M_NEXT_EXIST (MeasurementParams_t, Exist_MULTI_BAND_REPORTING, 1),
  M_UINT       (MeasurementParams_t,  MULTI_BAND_REPORTING,  2, &hf_gprsmeasurementparams_pmo_pcco_multi_band_reporting),

  M_NEXT_EXIST (MeasurementParams_t, Exist_SERVING_BAND_REPORTING, 1),
  M_UINT       (MeasurementParams_t,  SERVING_BAND_REPORTING,  2, &hf_gprsmeasurementparams_pmo_pcco_serving_band_reporting),

  M_NEXT_EXIST (MeasurementParams_t, Exist_SCALE_ORD, 1),
  M_UINT       (MeasurementParams_t,  SCALE_ORD,  2, &hf_gprsmeasurementparams_pmo_pcco_scale_ord),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold900, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold900, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold1800, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold1800, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold400, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold400, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold1900, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold1900, OffsetThreshold_t),

  M_NEXT_EXIST (MeasurementParams_t, Exist_OffsetThreshold850, 1),
  M_TYPE       (MeasurementParams_t, OffsetThreshold850, OffsetThreshold_t),
CSN_DESCR_END  (MeasurementParams_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams3G_PSI5_t)
  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existRepParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  RepQuantFDD,  1, &hf_gprsmeasurementparams3g_psi5_repquantfdd),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  MultiratReportingFDD,  2, &hf_gprsmeasurementparams3g_psi5_multiratreportingfdd),
    
  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existReportingParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingOffsetFDD,  3, &hf_gprsmeasurementparams3g_psi5_reportingoffsetfdd),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingThresholdFDD,  3, &hf_gprsmeasurementparams3g_psi5_reportingthresholdfdd),
    
  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existMultiratReportingTDD, 1),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  MultiratReportingTDD,  2, &hf_gprsmeasurementparams3g_psi5_multiratreportingtdd),
    
  M_NEXT_EXIST (GPRSMeasurementParams3G_PSI5_t, existOffsetThresholdTDD, 2),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingOffsetTDD,  3, &hf_gprsmeasurementparams3g_psi5_reportingoffsettdd),
  M_UINT       (GPRSMeasurementParams3G_PSI5_t,  ReportingThresholdTDD,  3, &hf_gprsmeasurementparams3g_psi5_reportingthresholdtdd),
CSN_DESCR_END  (GPRSMeasurementParams3G_PSI5_t)

static const
CSN_DESCR_BEGIN(ENH_Reporting_Parameters_t)
  M_UINT       (ENH_Reporting_Parameters_t,  REPORT_TYPE,  1, &hf_enh_reporting_parameters_report_type),
  M_UINT       (ENH_Reporting_Parameters_t,  REPORTING_RATE,  1, &hf_enh_reporting_parameters_reporting_rate),
  M_UINT       (ENH_Reporting_Parameters_t,  INVALID_BSIC_REPORTING,  1, &hf_enh_reporting_parameters_invalid_bsic_reporting),

  M_NEXT_EXIST (ENH_Reporting_Parameters_t, Exist_NCC_PERMITTED, 1),
  M_UINT       (ENH_Reporting_Parameters_t,  NCC_PERMITTED,  8, &hf_enh_reporting_parameters_ncc_permitted),
    
  M_NEXT_EXIST (ENH_Reporting_Parameters_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Reporting_Parameters_t, GPRSMeasurementParams, MeasurementParams_t),
    
  M_NEXT_EXIST (ENH_Reporting_Parameters_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Reporting_Parameters_t, GPRSMeasurementParams3G, GPRSMeasurementParams3G_PSI5_t),
CSN_DESCR_END  (ENH_Reporting_Parameters_t)

static const
CSN_DESCR_BEGIN(PSI5_AdditionsR7)
  M_NEXT_EXIST (PSI5_AdditionsR7, Exist_OffsetThreshold_700, 1),
  M_TYPE       (PSI5_AdditionsR7,  OffsetThreshold_700, OffsetThreshold_t),

  M_NEXT_EXIST (PSI5_AdditionsR7, Exist_OffsetThreshold_810, 1),
  M_TYPE       (PSI5_AdditionsR7,  OffsetThreshold_810, OffsetThreshold_t),
CSN_DESCR_END  (PSI5_AdditionsR7)

static const
CSN_DESCR_BEGIN(PSI5_AdditionsR5)
  M_NEXT_EXIST (PSI5_AdditionsR5, Exist_GPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE       (PSI5_AdditionsR5,  GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  
  M_NEXT_EXIST (PSI5_AdditionsR5, Exist_AdditionsR7, 1),
  M_TYPE       (PSI5_AdditionsR5,  AdditionsR7, PSI5_AdditionsR7),
CSN_DESCR_END  (PSI5_AdditionsR5)

static const
CSN_DESCR_BEGIN(PSI5_AdditionsR99)
  M_NEXT_EXIST (PSI5_AdditionsR99, Exist_ENH_Reporting_Param, 1),
  M_TYPE       (PSI5_AdditionsR99,  ENH_Reporting_Param, ENH_Reporting_Parameters_t),

  M_NEXT_EXIST (PSI5_AdditionsR99, Exist_AdditionsR5, 1),
  M_TYPE       (PSI5_AdditionsR99,  AdditionisR5, PSI5_AdditionsR5),
CSN_DESCR_END  (PSI5_AdditionsR99)

static const
CSN_DESCR_BEGIN(PSI5_t)
  M_UINT       (PSI5_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (PSI5_t, PAGE_MODE, 2, &hf_page_mode),
  M_UINT       (PSI5_t, CHANGE_MARK, 2, &hf_packet_system_info_type5_change_mark),
  M_UINT       (PSI5_t, INDEX, 3, &hf_packet_system_info_type5_index),
  M_UINT       (PSI5_t, COUNT, 3, &hf_packet_system_info_type5_count),

  M_NEXT_EXIST (PSI5_t, Eixst_NC_Meas_Param, 1),
  M_TYPE       (PSI5_t, NC_Meas_Param, NC_Measurement_Parameters_t),

  M_FIXED      (PSI5_t, 1, 0x00),

  M_NEXT_EXIST (PSI5_t, Exist_AdditionsR99, 1),
  M_TYPE       (PSI5_t,  AdditionsR99, PSI5_AdditionsR99),

  M_PADDING_BITS(PSI5_t),
CSN_DESCR_END  (PSI5_t)
/*< End Packet System Information Type 5 message content >*/


/*< Packet System Information Type 13 message content >*/
static const
CSN_DESCR_BEGIN(PSI13_AdditionsR6)
  M_NEXT_EXIST (PSI13_AdditionsR6, Exist_LB_MS_TXPWR_MAX_CCH, 1),
  M_UINT       (PSI13_AdditionsR6,  LB_MS_TXPWR_MAX_CCH,  5, &hf_packet_system_info_type13_lb_ms_mxpwr_max_cch),
  M_UINT       (PSI13_AdditionsR6,  SI2n_SUPPORT,  2, &hf_packet_system_info_type13_si2n_support),
CSN_DESCR_END  (PSI13_AdditionsR6)

static const
CSN_DESCR_BEGIN(PSI13_AdditionsR4)
  M_UINT       (PSI13_AdditionsR4, SI_STATUS_IND, 1, &hf_si_status_ind),
  M_NEXT_EXIST (PSI13_AdditionsR4, Exist_AdditionsR6, 1),
  M_TYPE       (PSI13_AdditionsR4,  AdditionsR6, PSI13_AdditionsR6),
CSN_DESCR_END  (PSI13_AdditionsR4)

static const
CSN_DESCR_BEGIN(PSI13_AdditionR99)
  M_UINT       (PSI13_AdditionR99, SGSNR, 1, &hf_sgsnr),
  M_NEXT_EXIST (PSI13_AdditionR99, Exist_AdditionsR4, 1),
  M_TYPE       (PSI13_AdditionR99,  AdditionsR4, PSI13_AdditionsR4),
CSN_DESCR_END  (PSI13_AdditionR99)

static const
CSN_DESCR_BEGIN(PSI13_t)
  M_UINT       (PSI13_t, MESSAGE_TYPE, 6, &hf_dl_message_type),
  M_UINT       (PSI13_t, PAGE_MODE, 2, &hf_page_mode),
  M_UINT       (PSI13_t, BCCH_CHANGE_MARK, 3, &hf_bcch_change_mark),
  M_UINT       (PSI13_t, SI_CHANGE_FIELD, 4, &hf_si_change_field),
  
  M_NEXT_EXIST (PSI13_t, Exist_MA, 2),
  M_UINT       (PSI13_t,  SI13_CHANGE_MARK, 2, &hf_si13_change_mark),
  M_TYPE       (PSI13_t,  GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),

  M_UNION      (PSI13_t, 2),
  M_TYPE       (PSI13_t, u.PBCCH_Not_present, PBCCH_Not_present_t),
  M_TYPE       (PSI13_t, u.PBCCH_present, PBCCH_present_t),

  M_NEXT_EXIST (PSI13_t, Exist_AdditionsR99, 1),
  M_TYPE       (PSI13_t, AdditionsR99, PSI13_AdditionR99),

  M_PADDING_BITS(PSI13_t),
CSN_DESCR_END  (PSI13_t)
/*< End Packet System Information Type 13 message content >*/


#if 0 /* Not used ??? */

typedef const char* MT_Strings_t;

static const MT_Strings_t szMT_Downlink[] = {
  "Invalid Message Type",                /* 0x00 */
  "PACKET_CELL_CHANGE_ORDER",            /* 0x01 */
  "PACKET_DOWNLINK_ASSIGNMENT",          /* 0x02 */
  "PACKET_MEASUREMENT_ORDER",            /* 0x03 */
  "PACKET_POLLING_REQUEST",              /* 0x04 */
  "PACKET_POWER_CONTROL_TIMING_ADVANCE", /* 0x05 */
  "PACKET_QUEUEING_NOTIFICATION",        /* 0x06 */
  "PACKET_TIMESLOT_RECONFIGURE",         /* 0x07 */
  "PACKET_TBF_RELEASE",                  /* 0x08 */
  "PACKET_UPLINK_ACK_NACK",              /* 0x09 */
  "PACKET_UPLINK_ASSIGNMENT",            /* 0x0A */
  "PACKET_CELL_CHANGE_CONTINUE",         /* 0x0B */
  "PACKET_NEIGHBOUR_CELL_DATA",          /* 0x0C */
  "PACKET_SERVING_CELL_DATA",            /* 0x0D */
  "Invalid Message Type",                /* 0x0E */
  "Invalid Message Type",                /* 0x0F */
  "Invalid Message Type",                /* 0x10 */
  "Invalid Message Type",                /* 0x11 */
  "Invalid Message Type",                /* 0x12 */
  "Invalid Message Type",                /* 0x13 */
  "Invalid Message Type",                /* 0x14 */
  "PACKET_HANDOVER_COMMAND",             /* 0x15 */
  "PACKET_PHYSICAL_INFORMATION",         /* 0x16 */
  "Invalid Message Type",                /* 0x17 */
  "Invalid Message Type",                /* 0x18 */
  "Invalid Message Type",                /* 0x19 */
  "Invalid Message Type",                /* 0x1A */
  "Invalid Message Type",                /* 0x1B */
  "Invalid Message Type",                /* 0x1C */
  "Invalid Message Type",                /* 0x1D */
  "Invalid Message Type",                /* 0x1E */
  "Invalid Message Type",                /* 0x1F */
  "Invalid Message Type",                /* 0x20 */
  "PACKET_ACCESS_REJECT",                /* 0x21 */
  "PACKET_PAGING_REQUEST",               /* 0x22 */
  "PACKET_PDCH_RELEASE",                 /* 0x23 */
  "PACKET_PRACH_PARAMETERS",             /* 0x24 */
  "PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK", /* 0x25 */
  "Invalid Message Type",                /* 0x26 */
  "Invalid Message Type",                /* 0x27 */
  "Invalid Message Type",                /* 0x28 */
  "Invalid Message Type",                /* 0x29 */
  "Invalid Message Type",                /* 0x2A */
  "Invalid Message Type",                /* 0x2B */
  "Invalid Message Type",                /* 0x2C */
  "Invalid Message Type",                /* 0x2D */
  "Invalid Message Type",                /* 0x2E */
  "Invalid Message Type",                /* 0x2F */
  "PACKET_SYSTEM_INFO_6",                /* 0x30 */
  "PACKET_SYSTEM_INFO_1",                /* 0x31 */
  "PACKET_SYSTEM_INFO_2",                /* 0x32 */
  "PACKET_SYSTEM_INFO_3",                /* 0x33 */
  "PACKET_SYSTEM_INFO_3_BIS",            /* 0x34 */
  "PACKET_SYSTEM_INFO_4",                /* 0x35 */
  "PACKET_SYSTEM_INFO_5",                /* 0x36 */
  "PACKET_SYSTEM_INFO_13",               /* 0x37 */
  "PACKET_SYSTEM_INFO_7",                /* 0x38 */
  "PACKET_SYSTEM_INFO_8",                /* 0x39 */
  "PACKET_SYSTEM_INFO_14",               /* 0x3A */
  "Invalid Message Type",                /* 0x3B */
  "PACKET_SYSTEM_INFO_3_TER",            /* 0x3C */
  "PACKET_SYSTEM_INFO_3_QUATER",         /* 0x3D */
  "PACKET_SYSTEM_INFO_15"                /* 0x3E */
};

static const MT_Strings_t szMT_Uplink[] = {
  "PACKET_CELL_CHANGE_FAILURE",          /* 0x00 */
  "PACKET_CONTROL_ACKNOWLEDGEMENT",      /* 0x01 */
  "PACKET_DOWNLINK_ACK_NACK",            /* 0x02 */
  "PACKET_UPLINK_DUMMY_CONTROL_BLOCK",   /* 0x03 */
  "PACKET_MEASUREMENT_REPORT",           /* 0x04 */
  "PACKET_RESOURCE_REQUEST",             /* 0x05 */
  "PACKET_MOBILE_TBF_STATUS",            /* 0x06 */
  "PACKET_PSI_STATUS",                   /* 0x07 */
  "EGPRS_PACKET_DOWNLINK_ACK_NACK",      /* 0x08 */
  "PACKET_PAUSE",                        /* 0x09 */
  "PACKET_ENHANCED_MEASUREMENT_REPORT",  /* 0x0A */
  "ADDITIONAL_MS_RAC",                   /* 0x0B */
  "PACKET_CELL_CHANGE_NOTIFICATION",     /* 0x0C */
  "PACKET_SI_STATUS",                    /* 0x0D */
};

static const char*
MT_DL_TextGet(guint8 mt)
{
  if (mt < ElementsOf(szMT_Downlink))
  {
    return(szMT_Downlink[mt]);
  }
  else
  {
    return("Unknown message type");
  }
}

static const char*
MT_UL_TextGet(guint8 mt)
{
  if (mt < ElementsOf(szMT_Uplink))
  {
    return(szMT_Uplink[mt]);
  }
  else
  {
    return("Unknown message type");
  }
}

#endif

/* SI1_RestOctet_t */

static const
CSN_DESCR_BEGIN  (SI1_RestOctet_t)
  M_NEXT_EXIST_LH(SI1_RestOctet_t, Exist_NCH_Position, 1),
  M_UINT         (SI1_RestOctet_t,  NCH_Position,  5, &hf_si1_restoctet_nch_position),

  M_UINT_LH      (SI1_RestOctet_t,  BandIndicator,  1, &hf_si1_restoctet_bandindicator),
CSN_DESCR_END    (SI1_RestOctet_t)

/* SI3_Rest_Octet_t */
static const
CSN_DESCR_BEGIN(Selection_Parameters_t)
  M_UINT       (Selection_Parameters_t,  CBQ,  1, &hf_selection_parameters_cbq),
  M_UINT       (Selection_Parameters_t,  CELL_RESELECT_OFFSET,  6, &hf_selection_parameters_cell_reselect_offset),
  M_UINT       (Selection_Parameters_t,  TEMPORARY_OFFSET,  3, &hf_selection_parameters_temporary_offset),
  M_UINT       (Selection_Parameters_t,  PENALTY_TIME,  5, &hf_selection_parameters_penalty_time),
CSN_DESCR_END  (Selection_Parameters_t)

static const
CSN_DESCR_BEGIN  (SI3_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI3_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI3_Rest_Octet_t,  Power_Offset,  2, &hf_si3_rest_octet_power_offset),

  M_UINT_LH      (SI3_Rest_Octet_t,  System_Information_2ter_Indicator,  1, &hf_si3_rest_octet_system_information_2ter_indicator),
  M_UINT_LH      (SI3_Rest_Octet_t,  Early_Classmark_Sending_Control,  1, &hf_si3_rest_octet_early_classmark_sending_control),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_WHERE, 1),
  M_UINT         (SI3_Rest_Octet_t,  WHERE,  3, &hf_si3_rest_octet_where),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI3_Rest_Octet_t,  RA_COLOUR,  3, &hf_si3_rest_octet_ra_colour),
  M_UINT         (SI3_Rest_Octet_t,  SI13_POSITION, 1, &hf_si13_position),

  M_UINT_LH      (SI3_Rest_Octet_t,  ECS_Restriction3G,  1, &hf_si3_rest_octet_ecs_restriction3g),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, ExistSI2quaterIndicator, 1),
  M_UINT         (SI3_Rest_Octet_t,  SI2quaterIndicator,  1, &hf_si3_rest_octet_si2quaterindicator),
CSN_DESCR_END    (SI3_Rest_Octet_t)

static const
CSN_DESCR_BEGIN  (SI4_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI4_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI4_Rest_Octet_t,  Power_Offset,  2, &hf_si4_rest_octet_power_offset),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI4_Rest_Octet_t,  RA_COLOUR,  3, &hf_si4_rest_octet_ra_colour),
  M_UINT         (SI4_Rest_Octet_t,  SI13_POSITION, 1, &hf_si13_position),
CSN_DESCR_END    (SI4_Rest_Octet_t)

/* SI6_RestOctet_t */

static const
CSN_DESCR_BEGIN(PCH_and_NCH_Info_t)
  M_UINT       (PCH_and_NCH_Info_t,  PagingChannelRestructuring,  1, &hf_pch_and_nch_info_pagingchannelrestructuring),
  M_UINT       (PCH_and_NCH_Info_t,  NLN_SACCH,  2, &hf_pch_and_nch_info_nln_sacch),

  M_NEXT_EXIST (PCH_and_NCH_Info_t, Exist_CallPriority, 1),
  M_UINT       (PCH_and_NCH_Info_t,  CallPriority,  3, &hf_pch_and_nch_info_callpriority),

  M_UINT       (PCH_and_NCH_Info_t, NLN_Status, 1, &hf_nln_status),
CSN_DESCR_END  (PCH_and_NCH_Info_t)

static const
CSN_DESCR_BEGIN  (SI6_RestOctet_t)
  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_PCH_and_NCH_Info, 1),
  M_TYPE         (SI6_RestOctet_t, PCH_and_NCH_Info, PCH_and_NCH_Info_t),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_VBS_VGCS_Options, 1),
  M_UINT         (SI6_RestOctet_t,  VBS_VGCS_Options,  2, &hf_si6_restoctet_vbs_vgcs_options),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_DTM_Support, 2),
  M_UINT         (SI6_RestOctet_t,  RAC, 8, &hf_rac),
  M_UINT         (SI6_RestOctet_t,  MAX_LAPDm, 3, &hf_si6_restoctet_max_lapdm),

  M_UINT_LH      (SI6_RestOctet_t,  BandIndicator, 1, &hf_si6_restoctet_bandindicator),
CSN_DESCR_END    (SI6_RestOctet_t)

CSN_DESCR_BEGIN  (UL_Data_Mac_Header_t)
  M_UINT         (UL_Data_Mac_Header_t,  Payload_Type, 2, &hf_ul_payload_type),
  M_UINT         (UL_Data_Mac_Header_t,  Countdown_Value, 4, &hf_countdown_value),
  M_UINT         (UL_Data_Mac_Header_t,  SI, 1, &hf_ul_data_si),
  M_UINT         (UL_Data_Mac_Header_t,  R, 1, &hf_ul_retry_bit),
CSN_DESCR_END    (UL_Data_Mac_Header_t)

CSN_DESCR_BEGIN  (UL_Data_Block_GPRS_t)
  M_TYPE         (UL_Data_Block_GPRS_t, UL_Data_Mac_Header, UL_Data_Mac_Header_t),
  M_UINT         (UL_Data_Block_GPRS_t, Spare, 1, &hf_ul_data_spare),
  M_UINT         (UL_Data_Block_GPRS_t, PI, 1, &hf_pi),
  M_UINT         (UL_Data_Block_GPRS_t, TFI, 5, &hf_uplink_tfi),
  M_UINT         (UL_Data_Block_GPRS_t, TI, 1, &hf_tlli_indicator),
  M_UINT         (UL_Data_Block_GPRS_t, BSN, 7, &hf_bsn),
  M_UINT         (UL_Data_Block_GPRS_t, E, 1, &hf_e),
CSN_DESCR_END    (UL_Data_Block_GPRS_t)

CSN_DESCR_BEGIN  (UL_Data_Block_EGPRS_Header_Type1_t)
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type1_t, TFI, bits_spec_ul_tfi, 5, &hf_uplink_tfi),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type1_t, TFI, bits_spec_ul_tfi, 1, &hf_uplink_tfi),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, Countdown_Value, 4, &hf_countdown_value),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, SI, 1, &hf_ul_data_si),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, R, 1, &hf_ul_retry_bit),
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_ul_bsn1, 11, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_ul_bsn1, 1, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type1_t, TFI, bits_spec_ul_tfi, 0, &hf_uplink_tfi),
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type1_t, BSN2, bits_spec_ul_bsn2, 10, &hf_bsn2),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type1_t, BSN2, bits_spec_ul_bsn2, 1, &hf_bsn2),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_ul_bsn1, 0, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type1_t, BSN2, bits_spec_ul_bsn2, 0, &hf_bsn2),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, SPARE1, 1, &hf_ul_data_spare),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, PI, 1, &hf_pi),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, RSB, 1, &hf_rsb),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, CPS, 5, &hf_cps1),
  M_NULL         (UL_Data_Block_EGPRS_Header_Type1_t, dummy, 2),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type1_t, SPARE2, 6, &hf_ul_data_spare),
CSN_DESCR_END    (UL_Data_Block_EGPRS_Header_Type1_t)

CSN_DESCR_BEGIN  (UL_Data_Block_EGPRS_Header_Type2_t)
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type2_t, TFI, bits_spec_ul_tfi, 5, &hf_uplink_tfi),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type2_t, TFI, bits_spec_ul_tfi, 1, &hf_uplink_tfi),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, Countdown_Value, 4, &hf_countdown_value),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, SI, 1, &hf_ul_data_si),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, R, 1, &hf_ul_retry_bit),
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_ul_bsn1, 11, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_ul_bsn1, 1, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type2_t, TFI, bits_spec_ul_tfi, 0, &hf_uplink_tfi),
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type2_t, CPS, bits_spec_ul_type2_cps, 5, &hf_cps2),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type2_t, CPS, bits_spec_ul_type2_cps, 1, &hf_cps2),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_ul_bsn1, 0, &hf_bsn),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, SPARE1, 5, &hf_ul_data_spare),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, PI, 1, &hf_pi),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, RSB, 1, &hf_rsb),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type2_t, CPS, bits_spec_ul_type2_cps, 0, &hf_cps2),
  M_NULL         (UL_Data_Block_EGPRS_Header_Type1_t, dummy, 3),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type2_t, SPARE2, 5, &hf_ul_data_spare),
CSN_DESCR_END    (UL_Data_Block_EGPRS_Header_Type2_t)

CSN_DESCR_BEGIN  (UL_Data_Block_EGPRS_Header_Type3_t)
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type3_t, TFI, bits_spec_ul_tfi, 5, &hf_uplink_tfi),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type3_t, TFI, bits_spec_ul_tfi, 1, &hf_uplink_tfi),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, Countdown_Value, 4, &hf_countdown_value),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, SI, 1, &hf_ul_data_si),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, R, 1, &hf_ul_retry_bit),
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_ul_bsn1, 11, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_ul_bsn1, 1, &hf_bsn),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type3_t, TFI, bits_spec_ul_tfi, 0, &hf_uplink_tfi),
  M_SPLIT_BITS   (UL_Data_Block_EGPRS_Header_Type3_t, CPS, bits_spec_ul_type3_cps, 4, &hf_cps3),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type3_t, CPS, bits_spec_ul_type3_cps, 1, &hf_cps3),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_ul_bsn1, 0, &hf_bsn),
  M_NULL         (UL_Data_Block_EGPRS_Header_Type1_t, dummy, 1),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, SPARE1, 1, &hf_ul_data_spare),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, PI, 1, &hf_pi),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, RSB, 1, &hf_rsb),
  M_UINT         (UL_Data_Block_EGPRS_Header_Type3_t, SPB, 2, &hf_spb),
  M_BITS_CRUMB   (UL_Data_Block_EGPRS_Header_Type3_t, CPS, bits_spec_ul_type3_cps, 0, &hf_cps3),
CSN_DESCR_END    (UL_Data_Block_EGPRS_Header_Type3_t)

CSN_DESCR_BEGIN  (UL_Packet_Control_Ack_11_t)
  M_UINT         (UL_Packet_Control_Ack_11_t,  MESSAGE_TYPE, 9, &hf_prach11_message_type_9),
  M_UINT         (UL_Packet_Control_Ack_11_t,  CTRL_ACK, 2, &hf_packet_control_acknowledgement_ctrl_ack),
CSN_DESCR_END    (UL_Packet_Control_Ack_11_t)

CSN_DESCR_BEGIN  (UL_Packet_Control_Ack_TN_RRBP_11_t)
  M_UINT         (UL_Packet_Control_Ack_TN_RRBP_11_t,  MESSAGE_TYPE, 6, &hf_prach11_message_type_6),
  M_UINT         (UL_Packet_Control_Ack_TN_RRBP_11_t,  TN_RRBP, 3, &hf_packet_control_acknowledgement_additionsr5_tn_rrbp),
  M_UINT         (UL_Packet_Control_Ack_TN_RRBP_11_t,  CTRL_ACK, 2, &hf_packet_control_acknowledgement_ctrl_ack),
CSN_DESCR_END    (UL_Packet_Control_Ack_TN_RRBP_11_t)

CSN_DESCR_BEGIN  (UL_Packet_Control_Ack_8_t)
  M_UINT         (UL_Packet_Control_Ack_8_t,  MESSAGE_TYPE, 6, &hf_prach8_message_type_6),
  M_UINT         (UL_Packet_Control_Ack_8_t,  CTRL_ACK, 2, &hf_packet_control_acknowledgement_ctrl_ack),
CSN_DESCR_END    (UL_Packet_Control_Ack_8_t)

CSN_DESCR_BEGIN  (UL_Packet_Control_Ack_TN_RRBP_8_t)
  M_UINT         (UL_Packet_Control_Ack_TN_RRBP_8_t,  MESSAGE_TYPE, 3, &hf_prach8_message_type_3),
  M_UINT         (UL_Packet_Control_Ack_TN_RRBP_8_t,  TN_RRBP, 3, &hf_packet_control_acknowledgement_additionsr5_tn_rrbp),
  M_UINT         (UL_Packet_Control_Ack_TN_RRBP_8_t,  CTRL_ACK, 2, &hf_packet_control_acknowledgement_ctrl_ack),
CSN_DESCR_END    (UL_Packet_Control_Ack_TN_RRBP_8_t)

CSN_DESCR_BEGIN  (DL_Data_Mac_Header_t)
  M_UINT         (DL_Data_Mac_Header_t, Payload_Type, 2, &hf_dl_payload_type),
  M_UINT         (DL_Data_Mac_Header_t,  RRBP,  2, &hf_rrbp),
  M_UINT         (DL_Data_Mac_Header_t,  S_P,  1, &hf_s_p),
  M_UINT         (DL_Data_Mac_Header_t,  USF,  3, &hf_usf),
CSN_DESCR_END    (DL_Data_Mac_Header_t)


CSN_DESCR_BEGIN  (DL_Data_Block_GPRS_t)
  M_TYPE         (DL_Data_Block_GPRS_t, DL_Data_Mac_Header, DL_Data_Mac_Header_t),
  M_UINT         (DL_Data_Block_GPRS_t, Power_Reduction, 2, &hf_dl_ctrl_pr),
  M_UINT         (DL_Data_Block_GPRS_t, TFI, 5, &hf_downlink_tfi),
  M_UINT         (DL_Data_Block_GPRS_t, FBI, 1, &hf_fbi),
  M_UINT         (DL_Data_Block_GPRS_t, BSN, 7, &hf_bsn),
  M_UINT         (DL_Data_Block_GPRS_t, E, 1, &hf_e),
CSN_DESCR_END    (DL_Data_Block_GPRS_t)

CSN_DESCR_BEGIN  (DL_Data_Block_EGPRS_Header_Type1_t)
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type1_t, TFI, bits_spec_dl_tfi, 5, &hf_downlink_tfi),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, TFI, bits_spec_dl_tfi, 1, &hf_downlink_tfi),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type1_t, RRBP, 2, &hf_rrbp),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type1_t, ES_P, 2, &hf_es_p),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type1_t, USF, 3, &hf_usf),
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_dl_type1_bsn1, 11, &hf_bsn),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_dl_type1_bsn1, 2, &hf_bsn),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type1_t, Power_Reduction, 2, &hf_dl_ctrl_pr),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, TFI, bits_spec_dl_tfi, 0, &hf_downlink_tfi),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_dl_type1_bsn1, 1, &hf_bsn),
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type1_t, BSN2, bits_spec_dl_type1_bsn2, 11, &hf_bsn2),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, BSN2, bits_spec_dl_type1_bsn2, 1, &hf_bsn2),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, BSN1, bits_spec_dl_type1_bsn1, 0, &hf_bsn),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type1_t, CPS, 5, &hf_cps1),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type1_t, BSN2, bits_spec_dl_type1_bsn2, 0, &hf_bsn2),
CSN_DESCR_END    (DL_Data_Block_EGPRS_Header_Type1_t)

CSN_DESCR_BEGIN  (DL_Data_Block_EGPRS_Header_Type2_t)
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type2_t, TFI, bits_spec_dl_tfi, 5, &hf_downlink_tfi),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type2_t, TFI, bits_spec_dl_tfi, 1, &hf_downlink_tfi),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type2_t, RRBP, 2, &hf_rrbp),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type2_t, ES_P, 2, &hf_es_p),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type2_t, USF, 3, &hf_usf),
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_dl_type2_bsn, 11, &hf_bsn),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_dl_type2_bsn, 2, &hf_bsn),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type2_t, Power_Reduction, 2, &hf_dl_ctrl_pr),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type2_t, TFI, bits_spec_dl_tfi, 0, &hf_downlink_tfi),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_dl_type2_bsn, 1, &hf_bsn),
  M_NULL         (UL_Data_Block_EGPRS_Header_Type1_t, dummy, 4),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type2_t, CPS, 3, &hf_cps2),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type2_t, BSN1, bits_spec_dl_type2_bsn, 0, &hf_bsn),
CSN_DESCR_END    (DL_Data_Block_EGPRS_Header_Type2_t)

CSN_DESCR_BEGIN  (DL_Data_Block_EGPRS_Header_Type3_t)
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type3_t, TFI, bits_spec_dl_tfi, 5, &hf_downlink_tfi),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type3_t, TFI, bits_spec_dl_tfi, 1, &hf_downlink_tfi),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type3_t, RRBP, 2, &hf_rrbp),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type3_t, ES_P, 2, &hf_es_p),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type3_t, USF, 3, &hf_usf),
  M_SPLIT_BITS   (DL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_dl_type3_bsn, 11, &hf_bsn),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_dl_type3_bsn, 2, &hf_bsn),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type3_t, Power_Reduction, 2, &hf_dl_ctrl_pr),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type3_t, TFI, bits_spec_dl_tfi, 0, &hf_downlink_tfi),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_dl_type3_bsn, 1, &hf_bsn),
  M_NULL         (UL_Data_Block_EGPRS_Header_Type1_t, dummy, 1),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type3_t, SPB, 2, &hf_spb),
  M_UINT         (DL_Data_Block_EGPRS_Header_Type3_t, CPS, 4, &hf_cps3),
  M_BITS_CRUMB   (DL_Data_Block_EGPRS_Header_Type3_t, BSN1, bits_spec_dl_type3_bsn, 0, &hf_bsn),
CSN_DESCR_END    (DL_Data_Block_EGPRS_Header_Type3_t)


static const value_string dl_rlc_message_type_vals[] = {
  /* {0x00,  "Invalid Message Type"},                  */            
    {0x01, "PACKET_CELL_CHANGE_ORDER"},
    {0x02, "PACKET_DOWNLINK_ASSIGNMENT"},
    {0x03, "PACKET_MEASUREMENT_ORDER"},
    {0x04, "PACKET_POLLING_REQUEST"},
    {0x05, "PACKET_POWER_CONTROL_TIMING_ADVANCE"},
    {0x06, "PACKET_QUEUEING_NOTIFICATION"},
    {0x07, "PACKET_TIMESLOT_RECONFIGURE"},
    {0x08, "PACKET_TBF_RELEASE"},
    {0x09, "PACKET_UPLINK_ACK_NACK"},
    {0x0A, "PACKET_UPLINK_ASSIGNMENT"},
    {0x0B, "PACKET_CELL_CHANGE_CONTINUE"},
    {0x0C, "PACKET_NEIGHBOUR_CELL_DATA"},
    {0x0D, "PACKET_SERVING_CELL_DATA"},
    /* {0x0E, "Invalid Message Type"},                 */     
    /* {0x0F, "Invalid Message Type"},                 */
    /* {0x10, "Invalid Message Type"},                 */
    /* {0x11, "Invalid Message Type"},                 */
    /* {0x12, "Invalid Message Type"},                 */
    /* {0x13, "Invalid Message Type"},                 */
    /* {0x14, "Invalid Message Type"},                 */
    {0x15, "PACKET_HANDOVER_COMMAND"},
    {0x16, "PACKET_PHYSICAL_INFORMATION"},
    /* {0x17, "Invalid Message Type"},                 */
    /* {0x18, "Invalid Message Type"},                 */
    /* {0x19, "Invalid Message Type"},                 */
    /* {0x1A, "Invalid Message Type"},                 */
    /* {0x1B, "Invalid Message Type"},                 */
    /* {0x1C, "Invalid Message Type"},                 */
    /* {0x1D, "Invalid Message Type"},                 */
    /* {0x1E, "Invalid Message Type"},                 */
    /* {0x1F, "Invalid Message Type"},                 */
    /* {0x20, "Invalid Message Type"},                 */
    {0x21, "PACKET_ACCESS_REJECT"},
    {0x22, "PACKET_PAGING_REQUEST"},
    {0x23, "PACKET_PDCH_RELEASE"},
    {0x24, "PACKET_PRACH_PARAMETERS"},
    {0x25, "PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK"},
    /* {0x26, "Invalid Message Type"},                 */
    /* {0x27, "Invalid Message Type"},                 */
    /* {0x28, "Invalid Message Type"},                 */
    /* {0x29, "Invalid Message Type"},                 */
    /* {0x2A, "Invalid Message Type"},                 */
    /* {0x2B, "Invalid Message Type"},                 */
    /* {0x2C, "Invalid Message Type"},                 */
    /* {0x2D, "Invalid Message Type"},                 */
    /* {0x2E, "Invalid Message Type"},                 */
    /* {0x2F, "Invalid Message Type"},                 */
    {0x30, "PACKET_SYSTEM_INFO_6"},
    {0x31, "PACKET_SYSTEM_INFO_1"},
    {0x32, "PACKET_SYSTEM_INFO_2"},
    {0x33, "PACKET_SYSTEM_INFO_3"},
    {0x34, "PACKET_SYSTEM_INFO_3_BIS"},
    {0x35, "PACKET_SYSTEM_INFO_4"},
    {0x36, "PACKET_SYSTEM_INFO_5"},
    {0x37, "PACKET_SYSTEM_INFO_13"},
    {0x38, "PACKET_SYSTEM_INFO_7"},
    {0x39, "PACKET_SYSTEM_INFO_8"},
    {0x3A, "PACKET_SYSTEM_INFO_14"},
    /* {0x3B, "Invalid Message Type"},                 */
    {0x3C, "PACKET_SYSTEM_INFO_3_TER"},
    {0x3D, "PACKET_SYSTEM_INFO_3_QUATER"},
    {0x3E, "PACKET_SYSTEM_INFO_15"},
    { 0, NULL }
};

static value_string_ext dl_rlc_message_type_vals_ext = VALUE_STRING_EXT_INIT(dl_rlc_message_type_vals);

static const value_string ul_rlc_message_type_vals[] = {
    {0x00, "PACKET_CELL_CHANGE_FAILURE"},            
    {0x01, "PACKET_CONTROL_ACKNOWLEDGEMENT"},
    {0x02, "PACKET_DOWNLINK_ACK_NACK"},
    {0x03, "PACKET_UPLINK_DUMMY_CONTROL_BLOCK"},
    {0x04, "PACKET_MEASUREMENT_REPORT"},
    {0x05, "PACKET_RESOURCE_REQUEST"},
    {0x06, "PACKET_MOBILE_TBF_STATUS"},
    {0x07, "PACKET_PSI_STATUS"},
    {0x08, "EGPRS_PACKET_DOWNLINK_ACK_NACK"},
    {0x09, "PACKET_PAUSE"},
    {0x0A, "PACKET_ENHANCED_MEASUREMENT_REPORT"},
    {0x0B, "ADDITIONAL_MS_RAC"},
    {0x0C, "PACKET_CELL_CHANGE_NOTIFICATION"},
    {0x0D, "PACKET_SI_STATUS"},
    /* {0x0E, "Invalid Message Type"},                 */     
    /* {0x0F, "Invalid Message Type"},                 */
    /* {0x10, "Invalid Message Type"},                 */
    /* {0x11, "Invalid Message Type"},                 */
    /* {0x12, "Invalid Message Type"},                 */
    /* {0x13, "Invalid Message Type"},                 */
    /* {0x14, "Invalid Message Type"},                 */
    {0, NULL }
};


static const value_string ul_prach8_message_type3_vals[] = {
    {0x00, "PACKET_CONTROL_ACKNOWLEDGEMENT"},
    {0, NULL }
};

static const value_string ul_prach8_message_type6_vals[] = {
    {0x1F, "PACKET_CONTROL_ACKNOWLEDGEMENT"},
    {0, NULL }
};

static const value_string ul_prach11_message_type6_vals[] = {
    {0x37, "PACKET_CONTROL_ACKNOWLEDGEMENT"},
    {0, NULL }
};

static const value_string ul_prach11_message_type9_vals[] = {
    {0x1F9, "PACKET_CONTROL_ACKNOWLEDGEMENT"},
    {0, NULL }
};

static value_string_ext ul_rlc_message_type_vals_ext = VALUE_STRING_EXT_INIT(ul_rlc_message_type_vals);

static const true_false_string retry_vals = {
    "MS sent channel request message twice or more",
    "MS sent channel request message once"
};

static const value_string ctrl_ack_vals[] = {
    {0x00, "In case the message is sent in access burst format, the MS received two RLC/MAC blocks with the same RTI value, one with RBSN = 0 and the other with RBSN = 1 and the mobile station is requesting new TBF. Otherwise the bit value '00' is reserved and shall not be sent. If received it shall be intepreted as the MS received an RLC/MAC control block addressed to itself and with RBSN = 1, and did not receive an RLC/MAC control block with the same RTI value and RBSN = 0"},            
    {0x01, "The MS received an RLC/MAC control block addressed to itself and with RBSN = 1, and did not receive an	RLC/MAC control block with the same RTI value and RBSN = 0"},
    {0x02, "The MS received an RLC/MAC control block addressed to itself and with RBSN = 0, and did not receive an	RLC/MAC control block with the same RTI value and RBSN = 1. This value is sent irrespective of the value of the FS bit"},            
    {0x03, "The MS received two RLC/MAC blocks with the same RTI value, one with RBSN = 0 and the other with RBSN = 1"},
    {0, NULL }
};

static const value_string ul_payload_type_vals[] = {
    {0x00, "RLC/MAC block contains an RLC data block"},            
    {0x01, "RLC/MAC block contains an RLC/MAC control block that does not include the optional octets of the RLC/MAC control header"},
    {0x02, "Reserved"},            
    {0x03, "Reserved"},
    {0, NULL }
};

static const value_string dl_payload_type_vals[] = {
    {0x00, "RLC/MAC block contains an RLC data block"},            
    {0x01, "RLC/MAC block contains an RLC/MAC control block that does not include the optional octets of the RLC/MAC control header"},
    {0x02, "RLC/MAC block contains an RLC/MAC control block that includes the optional first octet of the RLC/MAC control header"},            
    {0x03, "Reserved. The mobile station shall ignore all fields of the RLC/MAC block except for the USF field"},
    {0, NULL }
};


static const value_string rrbp_vals[] = {
    {0x00, "Reserved Block: (N+13) mod 2715648"},            
    {0x01, "Reserved Block: (N+17 or N+18) mod 2715648"},
    {0x02, "Reserved Block: (N+21 or N+22) mod 2715648"},            
    {0x03, "Reserved Block: (N+26) mod 2715648"},            
    {0, NULL }
};

static const true_false_string s_p_vals = {
    "RRBP field is valid",
    "RRBP field is not valid"
};

static const true_false_string fbi_vals = {
    "Current Block is last RLC data block in TBF",
    "Current Block is not last RLC data block in TBF"
};

static const value_string page_mode_vals[] = {
    {0x00, "Normal Paging"},            
    {0x01, "Extended Paging"},
    {0x02, "Paging Reorganization"},            
    {0x03, "Same as before"},            
    {0, NULL }
};

static const value_string e_vals[] = {
    {0x00, "Extension octet follows immediately"},            
    {0x01, "No extension Octet Follows"},
    {0, NULL }
};

static const value_string me_vals[] = {
    {0x00, "The mobile station shall ignore all fields of the RLC/MAC block except for the fields of the MAC header"},            
    {0x01, "no more LLC segments in this RLC block after the current segment, no more extension octets"},
    {0x02, "a new LLC PDU starts after the current LLC PDU and there is another extension octet, which delimits the new LLC PDU"},            
    {0x03, "a new LLC PDU starts after the current LLC PDU and continues until the end of the RLC information field, no more extension octets"},            
    {0, NULL }
};

static const true_false_string ack_type_vals = {
    "PACKET CONTROL ACKNOWLEDGEMENT message format shall be an RLC/MAC control block",
    "CONTROL ACKNOWLEDGEMENT message format shall be sent as four access bursts"
};

static const true_false_string fs_vals = {
    "Current block contains the final segment of an RLC/MAC control message",
    "Current block does not contain the final segment of an RLC/MAC control message"
};

static const true_false_string ac_vals = {
    "TFI/D octet is present",
    "TFI/D octet is not present"
};

static const value_string power_reduction_vals[] = {
    {0x00, "0 dB (included) to 3 dB (excluded) less than BCCH level - P0"},            
    {0x01, "3 dB (included) to 7 dB (excluded) less than BCCH level - P0"},
    {0x02, "7 dB (included) to 10 dB (included) less than BCCH level - P0"},            
    {0x03, "Not usable"},
    {0, NULL }
};

static const true_false_string ctrl_d_vals = {
    "TFI field identifies a downlink TBF",
    "TFI field identifies an uplink TBF"
};

static const value_string rbsn_e_vals[] = {
    {0x00, "2nd RLC/MAC control block"},            
    {0x01, "3rd / last RLC/MAC control block"},
    {0x02, "4th / last RLC/MAC control block"},            
    {0x03, "5th / last RLC/MAC control block"},
    {0x04, "6th / last RLC/MAC control block"},            
    {0x05, "7th / last RLC/MAC control block"},
    {0x06, "8th / last RLC/MAC control block"},            
    {0x07, "9th and last RLC/MAC control block"},
    {0, NULL }
};

static const value_string alpha_vals[] = {
    {0x00, "Alpha* = 0.0"},            
    {0x01, "Alpha* = 0.1"},
    {0x02, "Alpha* = 0.2"},            
    {0x03, "Alpha* = 0.3"},
    {0x04, "Alpha* = 0.4"},            
    {0x05, "Alpha* = 0.5"},
    {0x06, "Alpha* = 0.6"},            
    {0x07, "Alpha* = 0.7"},
    {0x08, "Alpha* = 0.8"},            
    {0x09, "Alpha* = 0.9"},
    {0x0A, "Alpha* = 1.0"},            
    {0x0B, "Alpha* = 1.0"},            
    {0x0C, "Alpha* = 1.0"},            
    {0x0D, "Alpha* = 1.0"},            
    {0x0E, "Alpha* = 1.0"},            
    {0x0F, "Alpha* = 1.0"},            
    {0, NULL }
};

static const true_false_string rlc_mode_vals = {
    "RLC unacknowledged mode",
    "RLC acknowledged mode"
};

static const true_false_string pc_meas_chan_vals = {
    "downlink measurements for power control shall be made on PDCH",
    "downlink measurements for power control shall be made on BCCH"
};

static const value_string mac_mode_vals[] = {
    {0x00, "Dynamic Allocation"},            
    {0x01, "Extended Dynamic Allocation"},
    {0x02, "Reserved -- The value '10' was allocated in an earlier version of the protocol and shall not be used"},            
    {0x03, "Reserved -- The value '11' was allocated in an earlier version of the protocol and shall not be used"},
    {0, NULL }
};

static const true_false_string control_ack_vals = {
    "A new downlink TBF for the mobile station whose timer T3192 is running",
    "Not a new downlink TBF for the mobile station whose timer T3192 is running"
};

static const value_string cell_change_failure_cause_vals[] = {
    {0x00, "Frequency not implemented"},            
    {0x01, "No response on target cell"},
    {0x02, "Immediate Assign Reject or Packet Access Reject on target cell"},            
    {0x03, "On-going CS connection"},
    {0x04, "PS Handover failure - other"},            
    {0x05, "MS in GMM Standby state"},
    {0x06, "Forced to the Standby state"},            
    {0x07, "Reserved for Future Use"},
    {0x08, "Reserved for Future Use"},            
    {0x09, "Reserved for Future Use"},
    {0x0A, "Reserved for Future Use"},            
    {0x0B, "Reserved for Future Use"},            
    {0x0C, "Reserved for Future Use"},            
    {0x0D, "Reserved for Future Use"},            
    {0x0E, "Reserved for Future Use"},            
    {0x0F, "Reserved for Future Use"},            
    {0, NULL }
};

static const value_string egprs_modulation_channel_coding_scheme_vals[] = {
    {0x00, "MCS-1"},            
    {0x01, "MCS-2"},
    {0x02, "MCS-3"},            
    {0x03, "MCS-4"},
    {0x04, "MCS-5"},            
    {0x05, "MCS-6"},
    {0x06, "MCS-7"},            
    {0x07, "MCS-8"},
    {0x08, "MCS-9"},            
    {0x09, "MCS-5-7"},
    {0x0A, "MCS-6-9"},            
    {0x0B, "reserved"},            
    {0x0C, "reserved"},            
    {0x0D, "reserved"},            
    {0x0E, "reserved"},            
    {0x0F, "reserved"},            
    {0, NULL }
};

static const value_string egprs_Header_type1_coding_puncturing_scheme_vals[] = {
    {0x00, "(MCS-9/P1 ; MCS-9/P1)"},            
    {0x01, "(MCS-9/P1 ; MCS-9/P2)"},
    {0x02, "(MCS-9/P1 ; MCS-9/P3)"},            
    {0x04, "(MCS-9/P2 ; MCS-9/P1)"},
    {0x05, "(MCS-9/P2 ; MCS-9/P2)"},            
    {0x06, "(MCS-9/P2 ; MCS-9/P3)"},
    {0x08, "(MCS-9/P3 ; MCS-9/P1)"},            
    {0x09, "(MCS-9/P3 ; MCS-9/P2)"},
    {0x0A, "(MCS-9/P3 ; MCS-9/P3)"},            
    {0x0B, "(MCS-8/P1 ; MCS-8/P1)"},            
    {0x0C, "(MCS-8/P1 ; MCS-8/P2)"},            
    {0x0D, "(MCS-8/P1 ; MCS-8/P3)"},            
    {0x0E, "(MCS-8/P2 ; MCS-8/P1)"},            
    {0x0F, "(MCS-8/P2 ; MCS-8/P2)"},            
    {0x10, "(MCS-8/P2 ; MCS-8/P3)"},            
    {0x11, "(MCS-8/P3 ; MCS-8/P1)"},            
    {0x12, "(MCS-8/P3 ; MCS-8/P2)"},            
    {0x13, "(MCS-8/P3 ; MCS-8/P3)"},            
    {0x14, "(MCS-7/P1 ; MCS-7/P1"},            
    {0x15, "(MCS-7/P1 ; MCS-7/P2)"},            
    {0x16, "(MCS-7/P1 ; MCS-7/P3)"},            
    {0x17, "(MCS-7/P2 ; MCS-7/P1)"},            
    {0x18, "(MCS-7/P2 ; MCS-7/P2)"},            
    {0x19, "(MCS-7/P2 ; MCS-7/P3)"},            
    {0x1A, "(MCS-7/P3 ; MCS-7/P1)"},            
    {0x1B, "(MCS-7/P3 ; MCS-7/P2)"},            
    {0x1C, "(MCS-7/P3 ; MCS-7/P3)"},            
    {0, NULL }
};
static value_string_ext egprs_Header_type1_coding_puncturing_scheme_vals_ext = VALUE_STRING_EXT_INIT(egprs_Header_type1_coding_puncturing_scheme_vals);

static const value_string egprs_Header_type2_coding_puncturing_scheme_vals[] = {
    {0x00, "MCS-6/P1"},            
    {0x01, "MCS-6/P2"},
    {0x02, "MCS-6/P1 with 6 octet padding"},            
    {0x03, "MCS-6/P2 with 6 octet padding "},
    {0x04, "MCS-5/P1"},            
    {0x05, "MCS-5/P2"},
    {0x06, "MCS-6/P1 with 10 octet padding "},            
    {0x07, "MCS-6/P2 with 10 octet padding "},
    {0, NULL }
};
static value_string_ext egprs_Header_type2_coding_puncturing_scheme_vals_ext = VALUE_STRING_EXT_INIT(egprs_Header_type2_coding_puncturing_scheme_vals);

static const value_string egprs_Header_type3_coding_puncturing_scheme_vals[] = {
    {0x00, "MCS-4/P1"},            
    {0x01, "MCS-4/P2"},
    {0x02, "MCS-4/P3"},            
    {0x03, "MCS-3/P1"},            
    {0x04, "MCS-3/P2"},
    {0x05, "MCS-3/P3"},            
    {0x06, "MCS-3/P1 with padding"},            
    {0x07, "MCS-3/P2 with padding"},
    {0x08, "MCS-3/P3 with padding"},            
    {0x09, "MCS-2/P1"},
    {0x0A, "MCS-2/P2"},
    {0x0B, "MCS-1/P1"},
    {0x0C, "MCS-1/P2"},
    {0x0D, "MCS-2/P1 with padding"},            
    {0x0E, "MCS-2/P2 with padding"},
    {0x0F, "MCS-0"},            
    {0, NULL }
};
static value_string_ext egprs_Header_type3_coding_puncturing_scheme_vals_ext = VALUE_STRING_EXT_INIT(egprs_Header_type3_coding_puncturing_scheme_vals);

static const value_string gsm_rlcmac_psi_change_field_vals[] = {
  { 0, "Update of unspecified PSI message(s)"},
  { 1, "Unknown"},
  { 2, "PSI2 updated"},
  { 3, "PSI3/PSI3bis/PSI3ter/PSI3quater updated"},
  { 4, "Unknown"},
  { 5, "PSI5 updated"},
  { 6, "PSI6 updated"},
  { 7, "PSI7 updated"},
  { 8, "PSI8 updated"},
  { 9, "Update of unknown SI message type"},
  {10, "Update of unknown SI message type"},
  {11, "Update of unknown SI message type"},
  {12, "Update of unknown SI message type"},
  {13, "Update of unknown SI message type"},
  {14, "Update of unknown SI message type"},
  {15, "Update of unknown SI message type"},
  { 0, NULL}
};

static const value_string gsm_rlcmac_val_plus_1_vals[] = {
  { 0, "1"},
  { 1, "2"},
  { 2, "3"},
  { 3, "4"},
  { 4, "5"},
  { 5, "6"},
  { 6, "7"},
  { 7, "8"},
  { 8, "9"},
  { 9, "10"},
  {10, "11"},
  {11, "12"},
  {12, "13"},
  {13, "14"},
  {14, "15"},
  {15, "16"},
  { 0, NULL}
};

static const true_false_string gsm_rlcmac_psi1_measurement_order_value = {
  "MS shall send measurement reports for cell re-selection",
  "MS performs cell re-selection in both packet idle and transfert mode and shall not send any measurement reports to the network"
};

static const value_string gsm_rlcmac_nmo_vals[] = {
  { 0, "Network Mode of Operation I"},
  { 1, "Network Mode of Operation II"},
  { 2, "Network Mode of Operation III"},
  { 3, "Reserved"},
  { 0, NULL}
};

static const value_string gsm_rlcmac_t3168_vals[] = {
  { 0, "500 ms"},
  { 1, "1000 ms"},
  { 2, "1500 ms"},
  { 3, "2000 ms"},
  { 4, "2500 ms"},
  { 5, "3000 ms"},
  { 6, "3500 ms"},
  { 7, "4000 ms"},
  { 0, NULL}
};

static const value_string gsm_rlcmac_t3192_vals[] = {
  { 0, "500 ms"},
  { 1, "1000 ms"},
  { 2, "1500 ms"},
  { 3, "0 ms"},
  { 4, "80 ms"},
  { 5, "120 ms"},
  { 6, "160 ms"},
  { 7, "200 ms"},
  { 0, NULL}
};

static guint8 construct_gprs_data_segment_li_array(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 initial_offset, guint8 *li_count, length_indicator_t *li_array, guint64 *e)
{
    guint8 offset = initial_offset, li_array_size = *li_count;
	proto_item 	*item;

    *li_count = 0;
    while((*e == 0))
    {
       item = proto_tree_add_bits_item(tree, hf_li, tvb, offset * 8, 6, ENC_BIG_ENDIAN);
        if(*li_count < li_array_size)
        {
           li_array[*li_count].li = tvb_get_guint8(tvb, offset);
           li_array[*li_count].offset = offset;
           (*li_count)++;
        }
        else
        {
           expert_add_info_format(pinfo, item, PI_UNDECODED, PI_ERROR, "Too many LIs, corresponding blocks will not be decoded");
        }
        proto_tree_add_bits_item(tree, hf_me, tvb, (offset * 8) + 6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bits_ret_val(tree, hf_e, tvb, (offset * 8) + 7, 1, e, ENC_BIG_ENDIAN);
        offset++;
    }
    return (offset - initial_offset);
}

static guint8 construct_egprs_data_segment_li_array(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 initial_offset, guint8 *li_count, length_indicator_t *li_array, guint64 *e)
{
    guint8 offset = initial_offset, li_array_size = *li_count;
	proto_item 	*item;

    *li_count = 0;
    while(*e == 0)
    {
        DISSECTOR_ASSERT(*li_count < li_array_size);
        item = proto_tree_add_bits_item(tree, hf_li, tvb, offset * 8, 7, ENC_BIG_ENDIAN);
        proto_tree_add_bits_ret_val(tree, hf_e, tvb, (offset * 8) + 7, 1, e, ENC_BIG_ENDIAN);
        if(*li_count < li_array_size)
        {
           /* store the LI and offset for use later when dissecting the rlc segments */
           li_array[*li_count].offset = offset;
           li_array[*li_count].li = tvb_get_guint8(tvb, offset);
           (*li_count)++;
        }
        else
        {
           expert_add_info_format(pinfo, item, PI_UNDECODED, PI_ERROR, "Too many LIs, corresponding blocks will not be decoded");
        }
        offset++;
    }
    return (offset - initial_offset);
}

static guint8 dissect_gprs_data_segments(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 initial_offset, 
                                   guint8 octet_length, guint8 li_count, length_indicator_t *li_array)
{
    guint8 octet_offset = initial_offset;
    guint8 i;
    tvbuff_t* data_tvb = NULL;
    gboolean more = TRUE, first_li = TRUE;
    proto_tree *subtree = NULL;
    proto_item *ti = NULL;

    /* decode the LIs and any associated LLC Frames */
    for(i = 0; (i < li_count) && more; i++)
    {
		guint8 li = li_array[i].li >> 2;

        /* if more bit is false, there are no more data segments in this block after the current one */
        more = (li_array[i].li & 2) == 2;

        switch(li)
        {
            case 0:
                ti = proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                    "LI[%d]=%d indicates: The previous segment of LLC Frame precisely filled the previous RLC Block",
                                    i, li);
                break;

            case 63:
                if(first_li)
                {
                    ti = proto_tree_add_text(tree, tvb, octet_offset, li, 
                                        "data segment: LI[%d]=%d indicates: The RLC data block contains only filler bits",
                                        i, li);
                }
                else
                {
                    ti = proto_tree_add_text(tree, tvb, octet_offset, li, 
                                        "data segment: LI[%d]=%d indicates: The remainder of the RLC data block contains filler bits",
                                        i, li);
                }
                subtree = proto_item_add_subtree(ti, ett_data_segments);
                data_tvb = tvb_new_subset(tvb, octet_offset, octet_length - octet_offset, octet_length - octet_offset);
                call_dissector(data_handle, data_tvb, pinfo, subtree);
                octet_offset = octet_length;
                break;

            default:
                ti = proto_tree_add_text(tree, tvb, octet_offset, li, 
                                    "data segment: LI[%d]=%d indicates: (Last segment of) LLC frame (%d octets)",
                                    i, li, li);
                subtree = proto_item_add_subtree(ti, ett_data_segments);
                data_tvb = tvb_new_subset(tvb, octet_offset, li, li);
                call_dissector(data_handle, data_tvb, pinfo, subtree);
                octet_offset += li;
                break;
        }
        first_li = FALSE;
    }        
    if(octet_offset < octet_length)
    {				 
       /* if there is space left in the RLC Block, then it is a segment of LLC Frame without LI*/
        if(more)
        {
            ti = proto_tree_add_text(tree, tvb, octet_offset, octet_length - octet_offset, 
                                "data segment: LI not present: \n The Upper Layer PDU in the current RLC data block either fills the current RLC data block precisely \nor continues in the following in-sequence RLC data block");
        }
        else
        {
            ti = proto_tree_add_text(tree, tvb, octet_offset, octet_length - octet_offset, "Padding Octets");
        }
        subtree = proto_item_add_subtree(ti, ett_data_segments);
        data_tvb = tvb_new_subset(tvb, octet_offset, octet_length - octet_offset, octet_length - octet_offset);
        call_dissector(data_handle, data_tvb, pinfo, subtree);
        octet_offset = octet_length;
    }
    return (octet_offset - initial_offset);
}

static guint16 dissect_egprs_data_segments(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint initial_offset, guint8 octet_length, guint8 li_count, length_indicator_t *li_array)
{
    guint octet_offset = initial_offset;
    guint8 i;
    tvbuff_t* data_tvb = NULL;
    gboolean first_li = TRUE;
    proto_tree *subtree = NULL;
    proto_item *ti = NULL;

    /* decode the LIs and any associated LLC Frames */
    for(i = 0; i < li_count; i++)
    {
		guint8 li = li_array[i].li >> 1;

        /* if more bit is false, there are no more data segments in this block after the current one */
        switch(li)
        {
            case 0:
               if(first_li)
               {
                   if(li_array[i].li & 1)
                   {
                       proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                           "LI[%d]=%d indicates: The previous RLC data block contains a Upper Layer PDU, or a part of it, \nthat fills precisely the previous data block and for which there is no length indicator in that RLC data block. \nThe current RLC data block contains a Upper Layer PDU that either fills the current RLC data block precisely or \ncontinues in the next RLC data block.",
                                           i, li);
                   }
                   else
                   {
                       proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                           "LI[%d]=%d indicates: The last Upper Layer PDU of the previous in sequence RLC data block ends \nat the boundary of that RLC data block and it has no LI in the header of that RLC data block. \nThus the current RLC data block contains the first segment of all included Upper Layer PDUs.",
                                           i, li);
                   }
               }
               else
               {
                  proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                      "LI[%d]=%d indicates: Unexpected occurrence of LI=0.",
                                      i, li);
               }
                break;

           case 126:
               if(first_li)
               {
                   if(li_array[i].li & 1)
                   {
                       proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                           "LI[%d]=%d indicates: The current RLC data block contains the first segment of an Upper Layer PDU \nthat either fills the current RLC data block precisely or continues in the next RLC data block.",
                                           i, li);
                   }
                   else
                   {
                       proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                           "LI[%d]=%d indicates: The current RLC data block contains the first segment of all included Upper Layer PDUs.",
                                           i, li);
                   }
               }
               else
               {
                  proto_tree_add_text(tree, tvb, li_array[i].offset, 1, 
                                      "LI[%d]=%d indicates: Unexpected occurrence of LI=126.",
                                      i, li);
               }
                break;

            case 127:
                if(first_li)
                {
                    ti = proto_tree_add_text(tree, tvb, octet_offset, octet_length - octet_offset, 
                                        "data segment: LI[%d]=%d indicates: The RLC data block contains only filler bits",
                                        i, li);
                }
                else
                {
                    ti = proto_tree_add_text(tree, tvb, octet_offset, octet_length - octet_offset, 
                                        "data segment: LI[%d]=%d indicates: The remainder of the RLC data block contains filler bits",
                                        i, li);
                }
                subtree = proto_item_add_subtree(ti, ett_data_segments);
                data_tvb = tvb_new_subset(tvb, octet_offset, octet_length - octet_offset, octet_length - octet_offset);
                call_dissector(data_handle, data_tvb, pinfo, subtree);
                octet_offset = octet_length;
                break;

           default:
              ti = proto_tree_add_text(tree, tvb, octet_offset, li, 
                                  "data segment: LI[%d]=%d indicates: (Last segment of) LLC frame (%d octets)", 
                                  i, li, li);
              subtree = proto_item_add_subtree(ti, ett_data_segments);
              data_tvb = tvb_new_subset(tvb, octet_offset, li, li);
              call_dissector(data_handle, data_tvb, pinfo, subtree);
              octet_offset += li;
                break;
        }
        first_li = FALSE;
    }        
    /* if there is space left in the RLC Block, then it is a segment of LLC Frame without LI*/
    if(octet_offset < octet_length)
    {				 
        ti = proto_tree_add_text(tree, tvb, octet_offset, octet_length - octet_offset, 
                            "data segment: LI not present: \n The Upper Layer PDU in the current RLC data block either fills the current RLC data block precisely \nor continues in the following in-sequence RLC data block");
        subtree = proto_item_add_subtree(ti, ett_data_segments);
        data_tvb = tvb_new_subset(tvb, octet_offset, octet_length - octet_offset, octet_length - octet_offset);
        call_dissector(data_handle, data_tvb, pinfo, subtree);
        octet_offset = octet_length;
    }
    return (octet_offset - initial_offset);
}

static void
dissect_ul_rlc_control_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacUplink_t *data, guint16 bit_length)
{
  csnStream_t      ar;
  proto_item   *ti;
  proto_tree *rlcmac_tree;
  guint bit_offset = 0;

  csnStreamInit(&ar, 0, bit_length);
  data->u.MESSAGE_TYPE = tvb_get_bits8(tvb, 8, 6);

  ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, 
                                      "GSM RLC/MAC: %s (%d) (Uplink)", 
                                      val_to_str_ext(data->u.MESSAGE_TYPE, &ul_rlc_message_type_vals_ext, "Unknown Messsage Type"), 
                                      data->u.MESSAGE_TYPE);
  rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

  col_append_sep_str(pinfo->cinfo, COL_INFO, ":", val_to_str_ext(data->u.MESSAGE_TYPE, &ul_rlc_message_type_vals_ext, "Unknown Messsage Type"));

  switch (data->u.MESSAGE_TYPE)
  {
    case MT_PACKET_CELL_CHANGE_FAILURE:
    {
      /*
       * data is the pointer to the unpack struct that hold the unpack value
       * CSNDESCR is an array that holds the different element types
       * ar is the csn context holding the bitcount, offset and output
       */
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Failure_t), tvb, &data->u.Packet_Cell_Change_Failure, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CONTROL_ACK:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Control_Acknowledgement_t), tvb, &data->u.Packet_Control_Acknowledgement, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_DOWNLINK_ACK_NACK:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Ack_Nack_t), tvb, &data->u.Packet_Downlink_Ack_Nack, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Uplink_Dummy_Control_Block_t), tvb, &data->u.Packet_Uplink_Dummy_Control_Block, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_MEASUREMENT_REPORT:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Measurement_Report_t), tvb, &data->u.Packet_Measurement_Report, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_RESOURCE_REQUEST:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Resource_Request_t), tvb, &data->u.Packet_Resource_Request, ett_gsm_rlcmac);
      break;
    }

    case MT_PACKET_MOBILE_TBF_STATUS:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Mobile_TBF_Status_t), tvb, &data->u.Packet_Mobile_TBF_Status, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PSI_STATUS:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PSI_Status_t), tvb, &data->u.Packet_PSI_Status, ett_gsm_rlcmac);
      break;
    }
    case MT_EGPRS_PACKET_DOWNLINK_ACK_NACK:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(EGPRS_PD_AckNack_t), tvb, &data->u.Egprs_Packet_Downlink_Ack_Nack, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PAUSE:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Pause_t), tvb, &data->u.Packet_Pause, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_ENHANCED_MEASUREMENT_REPORT:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Enh_Measurement_Report_t), tvb, &data->u.Packet_Enh_Measurement_Report, ett_gsm_rlcmac);
      break;
    }
    case MT_ADDITIONAL_MS_RAC:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Additional_MS_Rad_Access_Cap_t), tvb, &data->u.Additional_MS_Rad_Access_Cap, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CELL_CHANGE_NOTIFICATION:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Notification_t), tvb, &data->u.Packet_Cell_Change_Notification, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SI_STATUS:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_SI_Status_t), tvb, &data->u.Packet_SI_Status, ett_gsm_rlcmac);
      break;
    }
    default:
      /*ret = -1;*/
      break;
  }
}

static void 
dissect_dl_rlc_control_message(tvbuff_t *tvb, proto_tree *tree, RlcMacDownlink_t *data, guint16 initial_bit_offset, guint16 bit_length)
{
  csnStream_t  ar;
  proto_item   *ti = NULL;
  proto_tree   *rlcmac_tree = NULL;
  guint16 bit_offset = initial_bit_offset;

   ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, 
                                       "%s (%d) (downlink)", 
                                       val_to_str_ext(data->u.MESSAGE_TYPE, &dl_rlc_message_type_vals_ext, "Unknown Messsage Type"), 
                                       data->u.MESSAGE_TYPE);
   rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);
  /* Initialize the contexts */
   csnStreamInit(&ar, bit_offset, bit_length - bit_offset);

  switch (data->u.MESSAGE_TYPE)
  {
    case MT_PACKET_ACCESS_REJECT:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Access_Reject_t), tvb, &data->u.Packet_Access_Reject, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CELL_CHANGE_ORDER:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Order_t), tvb, &data->u.Packet_Cell_Change_Order, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CELL_CHANGE_CONTINUE:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Continue_t), tvb, &data->u.Packet_Cell_Change_Continue, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_DOWNLINK_ASSIGNMENT:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Assignment_t), tvb, &data->u.Packet_Downlink_Assignment, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_MEASUREMENT_ORDER:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Measurement_Order_t), tvb, &data->u.Packet_Measurement_Order, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_NEIGHBOUR_CELL_DATA:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Neighbour_Cell_Data_t), tvb, &data->u.Packet_Neighbour_Cell_Data, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SERVING_CELL_DATA:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Serving_Cell_Data_t), tvb, &data->u.Packet_Serving_Cell_Data, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PAGING_REQUEST:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Paging_Request_t), tvb, &data->u.Packet_Paging_Request, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PDCH_RELEASE:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PDCH_Release_t), tvb, &data->u.Packet_PDCH_Release, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_POLLING_REQ:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Polling_Request_t), tvb, &data->u.Packet_Polling_Request, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_POWER_CONTROL_TIMING_ADVANCE:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Power_Control_Timing_Advance_t), tvb, &data->u.Packet_Power_Control_Timing_Advance, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PRACH_PARAMETERS:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PRACH_Parameters_t), tvb, &data->u.Packet_PRACH_Parameters, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_QUEUEING_NOTIFICATION:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Queueing_Notification_t), tvb, &data->u.Packet_Queueing_Notification, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_TIMESLOT_RECONFIGURE:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Timeslot_Reconfigure_t), tvb, &data->u.Packet_Timeslot_Reconfigure, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_TBF_RELEASE:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_TBF_Release_t), tvb, &data->u.Packet_TBF_Release, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_UPLINK_ACK_NACK:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Uplink_Ack_Nack_t), tvb, &data->u.Packet_Uplink_Ack_Nack, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_UPLINK_ASSIGNMENT:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Uplink_Assignment_t), tvb, &data->u.Packet_Uplink_Assignment, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_HANDOVER_COMMAND:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Handover_Command_t), tvb, &data->u.Packet_Handover_Command, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PHYSICAL_INFORMATION:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PhysicalInformation_t), tvb, &data->u.Packet_Handover_Command, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Dummy_Control_Block_t), tvb, &data->u.Packet_Downlink_Dummy_Control_Block, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_1:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(PSI1_t), tvb, &data->u.PSI1, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_2:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(PSI2_t), tvb, &data->u.PSI2, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_3:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(PSI3_t), tvb, &data->u.PSI3, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_5:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(PSI5_t), tvb, &data->u.PSI5, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SYSTEM_INFO_13:
    {
      /*ret =*/ csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(PSI13_t), tvb, &data->u.PSI13, ett_gsm_rlcmac);
      break;
    }
    default:
      /*ret = -1;*/
      break;
  }
}

static void 
dissect_dl_gprs_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacDownlink_t * data)
{
   /* See RLC/MAC downlink control block structure in TS 44.060 / 10.3.1 */
   proto_item      *ti = NULL;
   proto_tree      *rlcmac_tree = NULL;
   csnStream_t      ar;
   gint bit_offset = 0;
   guint16 bit_length = tvb_length(tvb) * 8;
   length_indicator_t li_array[7];
   guint8 li_count = array_length(li_array);

   guint8 payload_type = tvb_get_bits8(tvb, 0, 2);
   guint8 rbsn = tvb_get_bits8(tvb, 8, 1);
   guint8 fs   = tvb_get_bits8(tvb, 14, 1);
   guint8 ac   = tvb_get_bits8(tvb, 15, 1);

   col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "GPRS DL");
   if(payload_type == PAYLOAD_TYPE_DATA)
   {
       guint64 e;

       col_add_str(pinfo->cinfo, COL_PROTOCOL, "GSM RLC/MAC");
       ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, 
                                           "GPRS DL DATA (CS%d)",
                                            data->block_format & 0x0F);
       rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

       csnStreamInit(&ar, 0, bit_length);

       /* dissect the RLC header */
       csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(DL_Data_Block_GPRS_t), tvb, &data->u.DL_Data_Block_GPRS, ett_gsm_rlcmac);
       bit_offset = ar.bit_offset;

       /* build the array of data segment descriptors */
       e = data->u.DL_Data_Block_GPRS.E;
       bit_offset += 8 * construct_gprs_data_segment_li_array(tvb, rlcmac_tree, pinfo,
                                                              bit_offset / 8, 
                                                              &li_count, 
                                                              li_array, 
                                                              &e);
       if (e)
       {
          /* dissect the data segments */
          bit_offset += (8 * dissect_gprs_data_segments(tvb, pinfo, rlcmac_tree, bit_offset / 8, bit_length / 8, 
                                                   li_count, 
                                                   li_array));
       }
       else
       {
          proto_tree_add_text(tree, tvb, bit_offset >> 3, 1,  "Unexpected header extension, dissection abandoned");
       }

       return;
   }
   else if(payload_type == PAYLOAD_TYPE_RESERVED)
   {
      col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "GSM RLC/MAC RESERVED MESSAGE TYPE");
       /* Dissect the MAC header */
       ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, "Payload Type: RESERVED (0), not implemented");
       rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);
       proto_tree_add_bits_item(rlcmac_tree, hf_dl_payload_type, tvb, 0, 2, ENC_BIG_ENDIAN);
       proto_tree_add_bits_item(rlcmac_tree, hf_rrbp, tvb, 2, 2, ENC_BIG_ENDIAN);
       proto_tree_add_bits_item(rlcmac_tree, hf_s_p, tvb, 4, 1, ENC_BIG_ENDIAN);
       proto_tree_add_bits_item(rlcmac_tree, hf_usf, tvb, 5, 3, ENC_BIG_ENDIAN);
       return;
   }
   /* We can decode the message */
   else if (data->block_format == RLCMAC_CS1)
   {
       /* First print the message type and create a tree item */
       guint8 message_type_offset = 8;
       if(payload_type == PAYLOAD_TYPE_CTRL_OPT_OCTET)
       {
           message_type_offset += 8;
           if(ac == 1)
           {
               message_type_offset += 8;
           }
           if((rbsn == 1) && (fs == 0))
           {
               message_type_offset += 8;
           }
       }
       data->u.MESSAGE_TYPE = tvb_get_bits8(tvb, message_type_offset, 6);
       col_add_str(pinfo->cinfo, COL_PROTOCOL, "GSM RLC/MAC");
       col_append_sep_fstr(pinfo->cinfo, COL_INFO, ":", "GPRS DL:%s", val_to_str_ext(data->u.MESSAGE_TYPE, &dl_rlc_message_type_vals_ext, "Unknown Messsage Type"));
       ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, message_type_offset >> 3, -1, 
                                           "GSM RLC/MAC: %s (%d) (Downlink)", 
                                           val_to_str_ext(data->u.MESSAGE_TYPE, &dl_rlc_message_type_vals_ext, "Unknown Messsage Type"), 
                                           data->u.MESSAGE_TYPE);
       rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

       /* Dissect the MAC header */
       proto_tree_add_bits_item(rlcmac_tree, hf_dl_payload_type, tvb, 0, 2, ENC_BIG_ENDIAN);
       proto_tree_add_bits_item(rlcmac_tree, hf_rrbp, tvb, 2, 2, ENC_BIG_ENDIAN);
       proto_tree_add_bits_item(rlcmac_tree, hf_s_p, tvb, 4, 1, ENC_BIG_ENDIAN);
       proto_tree_add_bits_item(rlcmac_tree, hf_usf, tvb, 5, 3, ENC_BIG_ENDIAN);
       bit_offset += 8;


       if(payload_type == PAYLOAD_TYPE_CTRL_OPT_OCTET)
       {
           proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rbsn, tvb, 8, 1, ENC_BIG_ENDIAN);
           proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rti, tvb, 9, 5, ENC_BIG_ENDIAN);
           proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_fs, tvb, 14, 1, ENC_BIG_ENDIAN);
           proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_ac, tvb, 15, 1, ENC_BIG_ENDIAN);
           bit_offset += 8;

           if(ac == 1) /* Indicates presence of TFI optional octet*/
           {
               guint8 ctrl_d = tvb_get_bits8(tvb, 23, 1);

               proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_pr, tvb, 16, 2, ENC_BIG_ENDIAN);
               proto_tree_add_bits_item(rlcmac_tree, (ctrl_d?hf_downlink_tfi:hf_uplink_tfi), tvb, 18, 5, ENC_BIG_ENDIAN);
               proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_d, tvb, 23, 1, ENC_BIG_ENDIAN);
               bit_offset += 8;
           }
           if((rbsn == 1) && (fs == 0)) /* Indicates the presence of optional octet 2/3 */
           {
               proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rbsn_e, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
               bit_offset += 3;
               proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_fs_e, tvb, bit_offset++, 1, ENC_BIG_ENDIAN);
               proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_spare, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
               bit_offset += 4;
           }
       }
       dissect_dl_rlc_control_message(tvb, rlcmac_tree, data, bit_offset, bit_length);
   }
   else
   {
      proto_tree_add_text(rlcmac_tree,tvb, bit_offset >> 3, -1, "GPRS block with invalid coding scheme (%d) for RLC Control",
                          data->block_format);
   }
}

static void 
dissect_egprs_dl_header_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacDownlink_t *data)
{
   if (data->flags & GSM_RLC_MAC_EGPRS_FANR_FLAG)
   {
      proto_tree_add_text(tree, tvb, 0, -1, "GPRS FANR Header dissection not supported (yet)");
   }
   else
   {
      proto_item   *ti = NULL;
      proto_tree *rlcmac_tree = NULL;
      csnStream_t      ar;

      guint16 bit_length = tvb_length(tvb) * 8;

      col_add_str(pinfo->cinfo, COL_PROTOCOL, "GSM RLC/MAC");
      col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "EGPRS DL:HEADER");
      /* Dissect the MAC header */
      ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, 0, -1, 
                                          "GSM RLC/MAC: EGPRS DL HEADER");
      rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

      ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = 0;
   
      csnStreamInit(&ar, 0, bit_length);
      switch(data->block_format)
      {
         case RLCMAC_HDR_TYPE_3:
            csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(DL_Data_Block_EGPRS_Header_Type3_t), tvb, &data->u.DL_Data_Block_EGPRS_Header, ett_gsm_rlcmac);
            if (data->u.DL_Data_Block_EGPRS_Header.CPS < array_length(egprs_Header_type3_coding_puncturing_scheme_vals))
            {
               ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = egprs_Header_type3_coding_puncturing_scheme_to_mcs[data->u.DL_Data_Block_EGPRS_Header.CPS];
            }
            break;
   
         case RLCMAC_HDR_TYPE_2:
            csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(DL_Data_Block_EGPRS_Header_Type2_t), tvb, &data->u.DL_Data_Block_EGPRS_Header, ett_gsm_rlcmac);
            if (data->u.DL_Data_Block_EGPRS_Header.CPS < array_length(egprs_Header_type2_coding_puncturing_scheme_vals))
            {
              ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = egprs_Header_type2_coding_puncturing_scheme_to_mcs[data->u.DL_Data_Block_EGPRS_Header.CPS];
            }
             break;
   
         case RLCMAC_HDR_TYPE_1:
            csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(DL_Data_Block_EGPRS_Header_Type1_t), tvb, &data->u.DL_Data_Block_EGPRS_Header, ett_gsm_rlcmac);
            if (data->u.DL_Data_Block_EGPRS_Header.CPS < array_length(egprs_Header_type1_coding_puncturing_scheme_vals))
            {
                ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = egprs_Header_type1_coding_puncturing_scheme_to_mcs[data->u.DL_Data_Block_EGPRS_Header.CPS];
            }
            break;
   
         default:
               proto_tree_add_text(tree, tvb, 0, -1, "EGPRS Header Type not handled (yet)");
            break;
      }
      ((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_dl_header_info.bsn1 = data->u.DL_Data_Block_EGPRS_Header.BSN1;
      ((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_dl_header_info.bsn2 = data->u.DL_Data_Block_EGPRS_Header.BSN2;
   }
}

static void 
dissect_ul_pacch_access_burst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacUplink_t * data)
{
   proto_item   *ti = NULL;
   proto_tree *rlcmac_tree = NULL;
   csnStream_t      ar;
   guint16 bit_length = tvb_length(tvb) * 8;

   col_add_str(pinfo->cinfo, COL_PROTOCOL, "GSM RLC/MAC");
   col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "PACCH ACCESS BURST");
   ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, 0, -1, 
                                       "GPRS UL PACCH ACCESS BURST");
   rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

   if ((bit_length > 8) && (tvb_get_bits16(tvb, 0, 9, ENC_BIG_ENDIAN) == 0x1F9))
   {
      csnStreamInit(&ar, 0, bit_length);
      csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Packet_Control_Ack_11_t), tvb, &data->u.UL_Packet_Control_Ack_11, ett_gsm_rlcmac);
   }
   else if ((bit_length > 8) && (tvb_get_bits8(tvb, 0, 6) == 0x37))
   {
      csnStreamInit(&ar, 0, bit_length);
      csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Packet_Control_Ack_TN_RRBP_11_t), tvb, &data->u.UL_Packet_Control_Ack_TN_RRBP_11, ett_gsm_rlcmac);
   }
   else if (tvb_get_bits8(tvb, 0, 6) == 0x1F)
   {
      csnStreamInit(&ar, 0, bit_length);
      csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Packet_Control_Ack_8_t), tvb, &data->u.UL_Packet_Control_Ack_8, ett_gsm_rlcmac);
   }
   else if (tvb_get_bits8(tvb, 0, 3) == 0x0)
   {
      csnStreamInit(&ar, 0, bit_length);
      csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Packet_Control_Ack_TN_RRBP_8_t), tvb, &data->u.UL_Packet_Control_Ack_TN_RRBP_8, ett_gsm_rlcmac);
   }
   else
   {
      proto_tree_add_text(tree, tvb, 0, -1, 
                          "Unknown PACCH access burst");
      call_dissector(data_handle, tvb, pinfo, tree);
   }
}

static void 
dissect_ul_gprs_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacUplink_t * data)
{
   proto_item   *ti = NULL;
   proto_tree *rlcmac_tree = NULL;
   csnStream_t      ar;
   guint8 payload_type = tvb_get_bits8(tvb, 0, 2);
   guint16 bit_length = tvb_length(tvb) * 8;
   guint16 bit_offset = 0;
   length_indicator_t li_array[10];
   guint8 li_count = array_length(li_array);

   col_add_str(pinfo->cinfo, COL_PROTOCOL, "GSM RLC/MAC");
   col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "GPRS UL");
   if(payload_type == PAYLOAD_TYPE_DATA)
   {
      guint64 e;

      ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, 
                                          "GPRS UL DATA (CS%d)", 
                                          data->block_format & 0x0F);
      rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);
      data->u.UL_Data_Block_GPRS.TI = 0;
      data->u.UL_Data_Block_GPRS.PI = 0;

      csnStreamInit(&ar, 0, bit_length);

      /* dissect the RLC header */
      csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Data_Block_GPRS_t), tvb, &data->u.UL_Data_Block_GPRS, ett_gsm_rlcmac);
      bit_offset = ar.bit_offset;

      /* build the array of data segment descriptors */
      e = data->u.UL_Data_Block_GPRS.E;
      bit_offset += 8 * construct_gprs_data_segment_li_array(tvb, rlcmac_tree, pinfo, 
                                                             bit_offset / 8, 
                                                             &li_count, 
                                                             li_array, 
                                                             &e);

      /* the next fields are present according to earlier flags */
      if(data->u.UL_Data_Block_GPRS.TI)
      {
           proto_tree_add_bits_item(rlcmac_tree, hf_tlli, tvb, bit_offset, 32, ENC_BIG_ENDIAN);
           bit_offset += 32;
      }
      if(data->u.UL_Data_Block_GPRS.PI)
      {
           proto_tree_add_bits_item(rlcmac_tree, hf_pfi, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
           bit_offset += 7;
           proto_tree_add_bits_ret_val(rlcmac_tree, hf_e, tvb, bit_offset, 1, &e, ENC_BIG_ENDIAN);
           bit_offset ++;
      }

      if (e)
      {
         /* dissect the data segments */
         bit_offset += (8 * dissect_gprs_data_segments(tvb, pinfo, rlcmac_tree, bit_offset / 8, bit_length / 8, 
                                              li_count, 
                                              li_array));
      }
      else
      {
         proto_tree_add_text(tree, tvb, bit_offset >> 3, 1,  "Unexpected header extension, dissection abandoned");
      }
   }
   else if(payload_type == PAYLOAD_TYPE_RESERVED)
   {
       proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, "Payload Type: RESERVED (3)");
       col_append_sep_str(pinfo->cinfo, COL_INFO, ":",  "GSM RLC/MAC RESERVED MESSAGE TYPE");
   }
   else if (data->block_format == RLCMAC_CS1)
   {
      dissect_ul_rlc_control_message(tvb, pinfo, tree, data, bit_length);
   }
   else
   {
      proto_tree_add_text(rlcmac_tree,tvb, bit_offset >> 3, -1, "GPRS UL block with Coding Scheme CS%d and incompatible payload type", 
                          data->block_format &0x0F);
   }
}
static void 
dissect_egprs_ul_header_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacUplink_t *data)
{
   if (data->flags & GSM_RLC_MAC_EGPRS_FANR_FLAG)
   {
      proto_tree_add_text(tree, tvb, 0, -1, "GPRS FANR Header dissection not supported (yet)");
   }
   else
   {
      proto_item   *ti = NULL;
      proto_tree *rlcmac_tree = NULL;
      csnStream_t      ar;
      guint16 bit_offset = 0;
      guint16 bit_length = tvb_length(tvb) * 8;
   
      col_add_str(pinfo->cinfo, COL_PROTOCOL,  "GSM RLC/MAC");
      col_append_sep_str(pinfo->cinfo, COL_INFO, ":",  "EGPRS UL:HEADER");
       ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, bit_offset >> 3, -1, 
                                           "GSM RLC/MAC: EGPRS UL HEADER");
       rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);
       data->u.UL_Data_Block_EGPRS_Header.PI = 0;
       ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = 0;
       csnStreamInit(&ar, 0, bit_length);
       switch(data->block_format)
       {
          case RLCMAC_HDR_TYPE_3:
             csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Data_Block_EGPRS_Header_Type3_t), tvb, &data->u.UL_Data_Block_EGPRS_Header, ett_gsm_rlcmac);
             if (data->u.UL_Data_Block_EGPRS_Header.CPS < array_length(egprs_Header_type3_coding_puncturing_scheme_vals))
             {
                ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = egprs_Header_type3_coding_puncturing_scheme_to_mcs[data->u.UL_Data_Block_EGPRS_Header.CPS];
             }
             break;
   
          case RLCMAC_HDR_TYPE_2:
             csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Data_Block_EGPRS_Header_Type2_t), tvb, &data->u.UL_Data_Block_EGPRS_Header, ett_gsm_rlcmac);
             if (data->u.UL_Data_Block_EGPRS_Header.CPS < array_length(egprs_Header_type2_coding_puncturing_scheme_vals))
             {
                ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = egprs_Header_type2_coding_puncturing_scheme_to_mcs[data->u.UL_Data_Block_EGPRS_Header.CPS];
             }
             break;
   
          case RLCMAC_HDR_TYPE_1:
             csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(UL_Data_Block_EGPRS_Header_Type1_t), tvb, &data->u.UL_Data_Block_EGPRS_Header, ett_gsm_rlcmac);
             if (data->u.UL_Data_Block_EGPRS_Header.CPS < array_length(egprs_Header_type1_coding_puncturing_scheme_vals))
             {
                ((RlcMacPrivateData_t *)(pinfo->private_data))->mcs = egprs_Header_type1_coding_puncturing_scheme_to_mcs[data->u.UL_Data_Block_EGPRS_Header.CPS];
             }
             break;
   
          default:
             proto_tree_add_text(tree, tvb, 0, -1, "EGPRS Header Type not handled (yet)");
             break;
       }
       bit_offset = ar.bit_offset;

       ((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_ul_header_info.pi = data->u.UL_Data_Block_EGPRS_Header.PI;
       ((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_ul_header_info.bsn1 = data->u.UL_Data_Block_EGPRS_Header.BSN1;
       ((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_ul_header_info.bsn2 = data->u.UL_Data_Block_EGPRS_Header.BSN2;
   }
}

static void 
dissect_egprs_ul_data_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacUplink_t *data, egprs_ul_header_info_t *egprs_ul_header_info)
{
   proto_item   *ti = NULL;
   proto_tree *data_tree = NULL;
   guint8 offset = 0;
   length_indicator_t li_array[20];
   guint8 li_count = array_length(li_array);
   guint64 e, tlli_i;
   guint16 block_number;

   block_number = (data->flags & GSM_RLC_MAC_EGPRS_BLOCK2)?(egprs_ul_header_info->bsn1 + egprs_ul_header_info->bsn2) % 1024:egprs_ul_header_info->bsn1;

   col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "DATA BLOCK");
   ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, offset, -1, 
                                       "GSM RLC/MAC: EGPRS UL DATA BLOCK %d (BSN %d)",
                                       (data->flags & GSM_RLC_MAC_EGPRS_BLOCK2)?2:1,
                                       block_number);
   data_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac_data);

    /* we assume that the body of the data block is octet aligned, 
       but there are 6 unused bits in the first octet to
       achieve alignment of the following octets */

   /* the data block starts with 2 bit header */
   proto_tree_add_bits_ret_val(data_tree, hf_ti, tvb, 6, 1, &tlli_i, ENC_BIG_ENDIAN);
   proto_tree_add_bits_ret_val(data_tree, hf_e, tvb, 7, 1, &e, ENC_BIG_ENDIAN);
   offset ++;

   /* build the array of Length Indicators */
   offset += construct_egprs_data_segment_li_array(tvb, data_tree, pinfo, offset, 
                                                 &li_count, 
                                                 li_array, 
                                                 &e);

   /* the next fields are present according to earlier flags */
   if(tlli_i)
   {
       proto_tree_add_bits_item(data_tree, hf_tlli, tvb, offset * 8, 32, ENC_BIG_ENDIAN);
       offset += 4;
   }
   if(egprs_ul_header_info->pi)
   {
       proto_tree_add_bits_item(data_tree, hf_pfi, tvb, offset * 8, 7, ENC_BIG_ENDIAN);
       proto_tree_add_bits_ret_val(data_tree, hf_e, tvb, (offset * 8) + 7, 1, &e, ENC_BIG_ENDIAN);
       offset ++;
   }
   if (e)
   {
      /* dissect the data segments */
      dissect_egprs_data_segments(tvb, pinfo, data_tree, offset, 
                                  tvb_length(tvb), li_count, li_array);
   }
   else
   {
      proto_tree_add_text(tree, tvb, offset, 1,  "Unexpected header extension, dissection abandoned");
   }
}


static void 
dissect_egprs_dl_data_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, RlcMacDownlink_t *data, egprs_dl_header_info_t *egprs_dl_header_info)
{
    proto_item      *ti = NULL;
    proto_tree      *data_tree = NULL;
    guint16 offset = 0, block_number;
    length_indicator_t li_array[20];
    guint8 li_count = array_length(li_array);
    guint64 fbi, e;

    block_number = egprs_dl_header_info->bsn1;
    if (data->flags & GSM_RLC_MAC_EGPRS_BLOCK2)
    {
       block_number = (block_number + egprs_dl_header_info->bsn2) % 1024;
    }

    col_append_sep_str(pinfo->cinfo, COL_INFO, ":", "DATA BLOCK");
    ti = proto_tree_add_protocol_format(tree, proto_gsm_rlcmac, tvb, offset, -1, 
                                        "GSM RLC/MAC: EGPRS DL DATA BLOCK %d (BSN %d)",
                                        (data->flags & GSM_RLC_MAC_EGPRS_BLOCK2)?2:1, 
                                        block_number);
    data_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac_data);

    /* we assume that there are 6 null bits in the first octet of each data block, 
       to give octet alignment of the main body of the block.  
       This alignment should be guaranteed by the transport-protocol dissector that called this one */

    /* the data block starts with 2 bit header */
    proto_tree_add_bits_ret_val(data_tree, hf_fbi, tvb, 6, 1, &fbi, ENC_BIG_ENDIAN);
    proto_tree_add_bits_ret_val(data_tree, hf_e, tvb, 7, 1, &e, ENC_BIG_ENDIAN);
    offset ++;

    /* build the array of data segment descriptors */
    offset += construct_egprs_data_segment_li_array(tvb, data_tree, pinfo, 1, 
                                                  &li_count, 
                                                  li_array, 
                                                  &e);
    if (e)
    {
       /* dissect the data segments */
       dissect_egprs_data_segments(tvb, pinfo, data_tree, offset, 
                                   tvb_length(tvb), li_count, li_array);
    }
    else
    {
       proto_tree_add_text(tree, tvb, offset, 1,  "Unexpected header extension, dissection abandoned");
    }
}

static void
dissect_gsm_rlcmac_downlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    RlcMacDownlink_t * data;

    /* allocate a data structure and guess the coding scheme */
    data = ep_alloc(sizeof(RlcMacDownlink_t));

    if ((pinfo->private_data != NULL) && (((RlcMacPrivateData_t *)(pinfo->private_data))->magic == GSM_RLC_MAC_MAGIC_NUMBER))
    {
       /* the transport protocol dissector has provided a data structure that contains (at least) the Coding Scheme */
	   data->block_format = ((RlcMacPrivateData_t *)pinfo->private_data)->block_format;
       data->flags = ((RlcMacPrivateData_t *)(pinfo->private_data))->flags;
    }
    else
    {
       data->block_format = RLCMAC_CS1;
       data->flags = 0;
    }

    switch(data->block_format)
    {
       case RLCMAC_CS1:
       case RLCMAC_CS2:
       case RLCMAC_CS3:
       case RLCMAC_CS4:
         dissect_dl_gprs_block(tvb, pinfo, tree, data);
         break;

       case RLCMAC_HDR_TYPE_1:
       case RLCMAC_HDR_TYPE_2:
       case RLCMAC_HDR_TYPE_3:
          if (data->flags & (GSM_RLC_MAC_EGPRS_BLOCK1 | GSM_RLC_MAC_EGPRS_BLOCK2))
          {
             dissect_egprs_dl_data_block(tvb, pinfo, tree, data, &((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_dl_header_info);            
          }
          else
          {
             dissect_egprs_dl_header_block(tvb, pinfo, tree, data);
          }
          break;

       default:
          proto_tree_add_text(tree, tvb, 0, -1, "GSM RLCMAC unknown coding scheme (%d)", data->block_format);
          break;
    }
}



static void
dissect_gsm_rlcmac_uplink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    RlcMacUplink_t *data;

    /* allocate a data structure and set the coding scheme */
   data = ep_alloc(sizeof(RlcMacUplink_t));

    if ((pinfo->private_data != NULL) && (((RlcMacPrivateData_t *)(pinfo->private_data))->magic == GSM_RLC_MAC_MAGIC_NUMBER))
    {
       /* the transport protocol dissector has provided a data structure that contains (at least) the Coding Scheme */
       data->block_format = ((RlcMacPrivateData_t *)pinfo->private_data)->block_format;
       data->flags = ((RlcMacPrivateData_t *)(pinfo->private_data))->flags;
    }
	else if (tvb_length(tvb) < 3)
	{
       /* assume that little packets are PACCH */
       data->block_format = RLCMAC_PRACH;
       data->flags = 0;
	}
    else
    {
       data->block_format = RLCMAC_CS1;
       data->flags = 0;
    }
    
    switch(data->block_format)
    {
       case RLCMAC_PRACH:
          dissect_ul_pacch_access_burst(tvb, pinfo, tree, data);
          break;

        case RLCMAC_CS1:
        case RLCMAC_CS2:
        case RLCMAC_CS3:
        case RLCMAC_CS4:
          dissect_ul_gprs_block(tvb, pinfo, tree, data);
          break;

       case RLCMAC_HDR_TYPE_1:
       case RLCMAC_HDR_TYPE_2:
       case RLCMAC_HDR_TYPE_3:
           if (data->flags & (GSM_RLC_MAC_EGPRS_BLOCK1 | GSM_RLC_MAC_EGPRS_BLOCK2))
           {
              dissect_egprs_ul_data_block(tvb, pinfo, tree, data, &((RlcMacPrivateData_t *)(pinfo->private_data))->u.egprs_ul_header_info);            
           }
           else
           {
              dissect_egprs_ul_header_block(tvb, pinfo, tree, data);
           }
            break;

       default:
          proto_tree_add_text(tree, tvb, 0, -1, "GSM RLCMAC unknown coding scheme (%d)", data->block_format);
          break;
    }
}

void
proto_register_gsm_rlcmac(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_gsm_rlcmac,
    &ett_gsm_rlcmac_data,
    &ett_data_segments
  };
  static hf_register_info hf[] = {
     { &hf_page_mode,
       { "PAGE_MODE",        "gsm_rlcmac.page_mode",
         FT_UINT8, BASE_DEC, VALS(page_mode_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_bsn,
       { "Block Sequence Number",        "gsm_rlcmac.bsn",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_bsn2,
       { "Block Sequence Number 2 offset", "gsm_rlcmac.bsn2",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_e,
       { "Extension",        "gsm_rlcmac.e",
         FT_UINT8, BASE_DEC, VALS(e_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_li,
       { "Length Indicator",        "gsm_rlcmac.li",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_pi,
       { "PFI Indicator",        "gsm_rlcmac.pi",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_ti,
       { "TLLI Indicator",        "gsm_rlcmac.ti",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_rsb,
       { "Resent Block Bit",        "gsm_rlcmac.rsb",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_spb,
       { "Split Block indicator",        "gsm_rlcmac.spb",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_cps1,
       { "Coding and Puncturing scheme",        "gsm_rlcmac.cps",
         FT_UINT8, BASE_HEX|BASE_EXT_STRING, &egprs_Header_type1_coding_puncturing_scheme_vals_ext, 0x0,
         NULL, HFILL
       }
     },
     { &hf_cps2,
       { "Coding and Puncturing scheme",        "gsm_rlcmac.cps",
         FT_UINT8, BASE_HEX|BASE_EXT_STRING, &egprs_Header_type2_coding_puncturing_scheme_vals_ext, 0x0,
         NULL, HFILL
       }
     },
     { &hf_cps3,
       { "Coding and Puncturing scheme",        "gsm_rlcmac.cps",
         FT_UINT8, BASE_HEX|BASE_EXT_STRING, &egprs_Header_type3_coding_puncturing_scheme_vals_ext, 0x0,
         NULL, HFILL
       }
     },
     { &hf_me,
       { "More/Extension",        "gsm_rlcmac.me",
         FT_UINT8, BASE_DEC, VALS(me_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_tlli_indicator,
       { "TI",
         "gsm_rlcmac.ul.ti",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_countdown_value,
       { "CV",
         "gsm_rlcmac.ul.cv",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_ul_data_si,
       { "SI",
         "gsm_rlcmac.ul.data_si",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_ul_retry_bit,
       { "R",
         "gsm_rlcmac.ul.retry",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_rrbp,
       { "RRBP",
         "gsm_rlcmac.rrbp",
         FT_UINT8, BASE_DEC, VALS(rrbp_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_s_p,
       { "S/P",
         "gsm_rlcmac.s_p",
         FT_BOOLEAN, BASE_NONE, TFS(&s_p_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_es_p,
       { "ES/P",
         "gsm_rlcmac.es_p",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_fbi,
       { "FBI",
         "gsm_rlcmac.fbi",
         FT_BOOLEAN, BASE_NONE, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_uplink_tfi,
       { "UPLINK TFI",
         "gsm_rlcmac.ul.tfi",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_downlink_tfi,
       { "DOWNLINK TFI",
         "gsm_rlcmac.dl.tfi",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_ul_data_spare,
       { "UL SPARE",
         "gsm_rlcmac.ul.data_spare",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_pfi,
       { "PFI",
         "gsm_rlcmac.pfi",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_usf,
       { "USF",
         "gsm_rlcmac.usf",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
     { &hf_dl_payload_type,
       { "Payload Type (DL)",
         "gsm_rlcmac.dl_payload_type",
         FT_UINT8, BASE_DEC, VALS(dl_payload_type_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_ul_payload_type,
       { "Payload Type (UL)",
         "gsm_rlcmac.ul_payload_type",
         FT_UINT8, BASE_DEC, VALS(ul_payload_type_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_prach8_message_type_3,
       { "Message Type (3 bit)",
         "gsm_rlcmac.message_type_3",
         FT_UINT8, BASE_DEC, VALS(ul_prach8_message_type3_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_prach8_message_type_6,
       { "Message Type (6 bit)",
         "gsm_rlcmac.message_type_6",
         FT_UINT8, BASE_DEC, VALS(ul_prach8_message_type6_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_prach11_message_type_6,
       { "Message Type (6 bit)",
         "gsm_rlcmac.message_type_6",
         FT_UINT8, BASE_DEC, VALS(ul_prach11_message_type6_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_prach11_message_type_9,
       { "Message Type (9 bit)",
         "gsm_rlcmac.message_type_9",
         FT_UINT8, BASE_DEC, VALS(ul_prach11_message_type9_vals), 0x0,
         NULL, HFILL
       }
     },
     { &hf_tlli,
       { "TLLI",
         "gsm_rlcmac.tlli",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL
       }
     },
    { &hf_dl_ctrl_rbsn,
      { "RBSN",
        "gsm_rlcmac.dl.rbsn",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_rti,
      { "RTI",
        "gsm_rlcmac.dl.rti",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_fs,
      { "FS",
        "gsm_rlcmac.dl.fs",
        FT_BOOLEAN, BASE_NONE, TFS(&fs_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_ac,
      { "AC",
        "gsm_rlcmac.dl.ac",
        FT_BOOLEAN, BASE_NONE, TFS(&ac_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_pr,
      { "PR",
        "gsm_rlcmac.dl.pr",
        FT_UINT8, BASE_DEC, VALS(power_reduction_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_d,
      { "D",
        "gsm_rlcmac.dl.d",
        FT_BOOLEAN,BASE_NONE, TFS(&ctrl_d_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_rbsn_e,
      { "RBSNe",
        "gsm_rlcmac.dl.rbsn_e",
        FT_UINT8, BASE_DEC, VALS(rbsn_e_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_fs_e,
      { "FSe",
        "gsm_rlcmac.dl.fs_e",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_spare,
      { "DL CTRL SPARE",
        "gsm_rlcmac.dl.ctrl_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_startingtime_n32,
      { "N32",        "gsm_rlcmac.dl.n32",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_startingtime_n51,
      { "N51",        "gsm_rlcmac.dl.n51",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_startingtime_n26,
      { "N26",        "gsm_rlcmac.dl.n26",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Global TFI IE >*/

/*< Starting Frame Number Description IE >*/
    { &hf_starting_frame_number_k,
      { "k",        "gsm_rlcmac.dl.k",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Ack/Nack Description IE >*/
    { &hf_ack_nack_description_final_ack_indication,
      { "FINAL_ACK_INDICATION",        "gsm_rlcmac.dl.final_ack_indication",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ack_nack_description_starting_sequence_number,
      { "STARTING_SEQUENCE_NUMBER",        "gsm_rlcmac.dl.starting_sequence_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Timing Advance IE >*/
    { &hf_timing_advance_value,
      { "TIMING_ADVANCE_VALUE",        "gsm_rlcmac.dl.timing_advance_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_timing_advance_index,
      { "TIMING_ADVANCE_INDEX",        "gsm_rlcmac.dl.timing_advance_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_timing_advance_timeslot_number,
      { "TIMING_ADVANCE_TIMESLOT_NUMBER",        "gsm_rlcmac.dl.timing_advance_timeslot_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Power Control Parameters IE >*/
    { &hf_alpha,
      { "ALPHA",        "gsm_rlcmac.dl.alpha",
        FT_UINT8, BASE_DEC, VALS(alpha_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_t_avg_w,
      { "T_AVG_W",        "gsm_rlcmac.dl.t_avg_w",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_t_avg_t,
      { "T_AVG_T",        "gsm_rlcmac.dl.t_avg_t",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pc_meas_chan,
      { "PC_MEAS_CHAN",        "gsm_rlcmac.dl.pc_meas_chan",
        FT_BOOLEAN, BASE_NONE, TFS(&pc_meas_chan_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_n_avg_i,
      { "N_AVG_I",        "gsm_rlcmac.dl.n_avg_i",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Global Power Control Parameters IE >*/
    { &hf_global_power_control_parameters_pb,
      { "Pb",        "gsm_rlcmac.dl.pb",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_global_power_control_parameters_int_meas_channel_list_avail,
      { "INT_MEAS_CHANNEL_LIST_AVAIL",        "gsm_rlcmac.dl.int_meas_channel_list_avail",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Global Packet Timing Advance IE >*/

/*< Channel Quality Report struct >*/
    { &hf_channel_quality_report_c_value,
      { "C_VALUE",        "gsm_rlcmac.dl.c_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_rxqual,
      { "RXQUAL",        "gsm_rlcmac.dl.rxqual",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_sign_var,
      { "SIGN_VAR",        "gsm_rlcmac.dl.sign_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot0_i_level_tn,
      { "Slot[0].I_LEVEL_TN",        "gsm_rlcmac.dl.slot0_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot1_i_level_tn,
      { "Slot[1].I_LEVEL_TN",        "gsm_rlcmac.dl.slot1_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot2_i_level_tn,
      { "Slot[2].I_LEVEL_TN",        "gsm_rlcmac.dl.slot2_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot3_i_level_tn,
      { "Slot[3].I_LEVEL_TN",        "gsm_rlcmac.dl.slot3_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot4_i_level_tn,
      { "Slot[4].I_LEVEL_TN",        "gsm_rlcmac.dl.slot4_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot5_i_level_tn,
      { "Slot[5].I_LEVEL_TN",        "gsm_rlcmac.dl.slot5_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot6_i_level_tn,
      { "Slot[6].I_LEVEL_TN",        "gsm_rlcmac.dl.slot6_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_quality_report_slot7_i_level_tn,
      { "Slot[7].I_LEVEL_TN",        "gsm_rlcmac.dl.slot7_i_level_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< EGPRS Ack/Nack Description >*/
    { &hf_egprs_acknack_final_ack_indication,
      { "FINAL_ACK_INDICATION",        "gsm_rlcmac.dl.final_ack_indication",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_acknack_beginning_of_window,
      { "BEGINNING_OF_WINDOW",        "gsm_rlcmac.dl.beginning_of_window",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_acknack_end_of_window,
      { "END_OF_WINDOW",        "gsm_rlcmac.dl.end_of_window",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_acknack_starting_sequence_number,
      { "STARTING_SEQUENCE_NUMBER",        "gsm_rlcmac.dl.starting_sequence_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_acknack_crbb_length,
      { "CRBB_LENGTH",        "gsm_rlcmac.dl.crbb_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_acknack_crbb_starting_color_code,
      { "CRBB_STARTING_COLOR_CODE",        "gsm_rlcmac.dl.crbb_starting_color_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*<P1 Rest Octets>*/

/*<P2 Rest Octets>*/
    { &hf_mobileallocationie_length,
      { "Length",        "gsm_rlcmac.dl.mobileallocationie_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_single_rf_channel_spare,
      { "spare",        "gsm_rlcmac.dl.single_rf_channel_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_arfcn,
      { "ARFCN",        "gsm_rlcmac.dl.arfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_maio,
      { "MAIO",        "gsm_rlcmac.dl.maio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_hsn,
      { "HSN",        "gsm_rlcmac.dl.hsn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_description_channel_type_and_tdma_offset,
      { "Channel_type_and_TDMA_offset",        "gsm_rlcmac.dl.channel_description_channel_type_and_tdma_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_description_tn,
      { "TN",        "gsm_rlcmac.dl.channel_description_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tsc,
      { "TSC",        "gsm_rlcmac.dl.tsc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_group_call_reference_value,
      { "value",        "gsm_rlcmac.dl.group_call_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_group_call_reference_sf,
      { "SF",        "gsm_rlcmac.dl.group_call_sf",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_group_call_reference_af,
      { "AF",        "gsm_rlcmac.dl.group_call_af",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_group_call_reference_call_priority,
      { "call_priority",        "gsm_rlcmac.dl.group_call_reference_call_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_group_call_reference_ciphering_information,
      { "Ciphering_information",        "gsm_rlcmac.dl.group_call_reference_call_ciphering_information",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nln_pch,
      { "NLN_PCH",        "gsm_rlcmac.dl.nln_pch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nln_status,
      { "NLN_status",        "gsm_rlcmac.dl.nln_status",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_priority,
      { "Priority",        "gsm_rlcmac.dl.priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_p1_rest_octets_packet_page_indication_1,
      { "Packet_Page_Indication_1",        "gsm_rlcmac.dl.p1_rest_octets_packet_page_indication_1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_p1_rest_octets_packet_page_indication_2,
      { "Packet_Page_Indication_2",        "gsm_rlcmac.dl.p1_rest_octets_packet_page_indication_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_p2_rest_octets_cn3,
      { "CN3",        "gsm_rlcmac.dl.p2_rest_octets_cn3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nln,
      { "NLN",        "gsm_rlcmac.dl.nln",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_p2_rest_octets_packet_page_indication_3,
      { "Packet_Page_Indication_3",        "gsm_rlcmac.dl.p2_rest_octets_packet_page_indication_3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/* <IA Rest Octets> */
    { &hf_usf_granularity,
      { "USF_GRANULARITY",        "gsm_rlcmac.dl.usf_granularity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_p0,
      { "P0",        "gsm_rlcmac.dl.p0",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pr_mode,
      { "PR_MODE",        "gsm_rlcmac.dl.pr_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gamma,
      { "GAMMA",        "gsm_rlcmac.dl.gamma",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nr_of_radio_blocks_allocated,
      { "NR_OF_RADIO_BLOCKS_ALLOCATED",        "gsm_rlcmac.dl.nr_of_radio_blocks_allocated",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_bts_pwr_ctrl_mode,
      { "BTS_PWR_CTRL_MODE",        "gsm_rlcmac.dl.bts_pwr_ctrl_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_polling,
      { "POLLING",        "gsm_rlcmac.dl.polling",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_channel_coding_command,
      { "EGPRS_CHANNEL_CODING_COMMAND",        "gsm_rlcmac.dl.egprs_channel_coding_command",
        FT_UINT8, BASE_DEC, VALS(egprs_modulation_channel_coding_scheme_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_tlli_block_channel_coding,
      { "TLLI_BLOCK_CHANNEL_CODING",        "gsm_rlcmac.dl.tlli_block_channel_coding",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_bep_period2,
      { "BEP_PERIOD2",        "gsm_rlcmac.dl.bep_period2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_resegment,
      { "RESEGMENT",        "gsm_rlcmac.dl.resegment",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_windowsize,
      { "EGPRS_WindowSize",        "gsm_rlcmac.dl.egprs_windowsize",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_extendedra,
      { "ExtendedRA",        "gsm_rlcmac.dl.extendedra",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ia_egprs_uniontype ,
      { "UnionType",        "gsm_rlcmac.dl.ia_egprs_00_uniontype",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ia_freqparamsbeforetime_length,
      { "Length",        "gsm_rlcmac.dl.ia_freqparamsbeforetime_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_channel_coding_command,
      { "CHANNEL_CODING_COMMAND",        "gsm_rlcmac.dl.gprs_channel_coding_command",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_link_quality_measurement_mode,
      { "LINK_QUALITY_MEASUREMENT_MODE",        "gsm_rlcmac.dl.link_quality_measurement_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rlc_mode,
      { "RLC_MODE",        "gsm_rlcmac.dl.rlc_mode",
        FT_BOOLEAN, BASE_NONE, TFS(&rlc_mode_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_ta_valid,
      { "TA_VALID",        "gsm_rlcmac.dl.packet_downlink_immassignment_ta_valid",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tqi,
      { "TQI",        "gsm_rlcmac.dl.tqi",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/* <Packet Polling Request> */
    { &hf_dl_message_type,
      { "MESSAGE_TYPE (DL)",        "gsm_rlcmac.dl.message_type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dl_rlc_message_type_vals_ext, 0x0,
        NULL, HFILL
      }
    },

/*< SI 13 Rest Octets >*/
    { &hf_gprs_cell_options_nmo,
      { "NMO",        "gsm_rlcmac.dl.gprs_cell_options_nmo",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_nmo_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_t3168,
      { "T3168", "gsm_rlcmac.dl.gprs_cell_options_t3168",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_t3168_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_t3192,
      { "T3192", "gsm_rlcmac.dl.gprs_cell_options_t3192",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_t3192_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_drx_timer_max,
      { "DRX_TIMER_MAX",        "gsm_rlcmac.dl.gprs_cell_options_drx_timer_max",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_access_burst_type,
      { "ACCESS_BURST_TYPE",        "gsm_rlcmac.dl.gprs_cell_options_access_burst_type",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ack_type,
      { "CONTROL_ACK_TYPE",        "gsm_rlcmac.dl.ack_type",
        FT_BOOLEAN, BASE_NONE, TFS(&ack_type_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_bs_cv_max,
      { "BS_CV_MAX",        "gsm_rlcmac.dl.gprs_cell_options_bs_cv_max",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_pan_dec,
      { "PAN_DEC",        "gsm_rlcmac.dl.gprs_cell_options_pan_dec",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_pan_inc,
      { "PAN_INC",        "gsm_rlcmac.dl.gprs_cell_options_pan_inc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_cell_options_pan_max,
      { "PAN_MAX",        "gsm_rlcmac.dl.gprs_cell_options_pan_max",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rac,
      { "RAC",        "gsm_rlcmac.dl.rac",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pbcch_not_present_spgc_ccch_sup,
      { "SPGC_CCCH_SUP",        "gsm_rlcmac.dl.pbcch_not_present_spgc_ccch_sup",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pbcch_not_present_priority_access_thr,
      { "PRIORITY_ACCESS_THR",        "gsm_rlcmac.dl.pbcch_not_present_priority_access_thr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pbcch_not_present_network_control_order,
      { "NETWORK_CONTROL_ORDER",        "gsm_rlcmac.dl.pbcch_not_present_network_control_order",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pbcch_description_pb,
      { "Pb",        "gsm_rlcmac.dl.pbcch_description_pb",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pbcch_description_tn,
      { "TN",        "gsm_rlcmac.dl.pbcch_description_tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pbcch_present_psi1_repeat_period,
      { "PSI1_REPEAT_PERIOD",        "gsm_rlcmac.dl.pbcch_present_psi1_repeat_period",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_val_plus_1_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_bcch_change_mark,
      { "BCCH_CHANGE_MARK",        "gsm_rlcmac.dl.bcch_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si_change_field,
      { "SI_CHANGE_FIELD",        "gsm_rlcmac.dl.si_change_field",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si13_change_mark,
      { "SI13_CHANGE_MARK",        "gsm_rlcmac.dl.si13_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_sgsnr,
      { "SGSNR",        "gsm_rlcmac.dl.sgsnr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si_status_ind,
      { "SI_STATUS_IND",        "gsm_rlcmac.dl.si_status_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet TBF Release message content >*/
    { &hf_packetbf_release_uplink_release,
      { "UPLINK_RELEASE",        "gsm_rlcmac.dl.packetbf_release_uplink_release",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packetbf_release_downlink_release,
      { "DOWNLINK_RELEASE",        "gsm_rlcmac.dl.packetbf_release_downlink_release",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packetbf_release_tbf_release_cause,
      { "TBF_RELEASE_CAUSE",        "gsm_rlcmac.dl.packetbf_release_tbf_release_cause",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Control Acknowledgement message content >*/
    { &hf_packet_control_acknowledgement_additionsr6_ctrl_ack_extension,
      { "CTRL_ACK_Extension",        "gsm_rlcmac.ul.packet_control_ack_additionsr6_ctrl_ack_extension",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_control_acknowledgement_additionsr5_tn_rrbp,
      { "TN_RRBP",        "gsm_rlcmac.ul.packet_control_ack_additionsr5_tn_rrbp",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_control_acknowledgement_additionsr5_g_rnti_extension,
      { "G_RNTI_Extension",        "gsm_rlcmac.ul.packet_control_ack_additionsr5_g_rnti_extension",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ul_retry,
      { "R",        "gsm_rlcmac.ul.retry",
        FT_BOOLEAN, BASE_NONE, TFS(&retry_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_ul_message_type,
      { "MESSAGE_TYPE (UL)",        "gsm_rlcmac.ul.message_type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ul_rlc_message_type_vals_ext, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_control_acknowledgement_ctrl_ack,
      { "CTRL_ACK",        "gsm_rlcmac.ul.packet_control_ack_ctrl_ack",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Downlink Dummy Control Block message content >*/

/*< Packet Uplink Dummy Control Block message content >*/
    { &hf_receive_n_pdu_number_nsapi,
      { "nsapi",        "gsm_rlcmac.dl.receive_n_pdu_number_nsapi",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_receive_n_pdu_number_value,
      { "value",        "gsm_rlcmac.dl.receive_n_pdu_number_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< MS Radio Access capability IE >*/
    { &hf_dtm_egprs_dtm_egprs_multislot_class,
      { "DTM_EGPRS_multislot_class",        "gsm_rlcmac.ul.dtm_egprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dtm_egprs_highmultislotclass_dtm_egprs_highmultislotclass,
      { "DTM_EGPRS_HighMultislotClass",        "gsm_rlcmac.ul.dtm_egprs_highmultislotclass",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_hscsd_multislot_class,
      { "HSCSD_multislot_class",        "gsm_rlcmac.ul.hscsd_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_gprs_multislot_class,
      { "GPRS_multislot_class",        "gsm_rlcmac.ul.gprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_gprs_extended_dynamic_allocation_capability,
      { "GPRS_Extended_Dynamic_Allocation_Capability",        "gsm_rlcmac.ul.gprs_extended_dynamic_allocation_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_sms_value,
      { "SMS_VALUE",        "gsm_rlcmac.ul.sms_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_sm_value,
      { "SM_VALUE",        "gsm_rlcmac.ul.sm_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_ecsd_multislot_class,
      { "ECSD_multislot_class",        "gsm_rlcmac.ul.ecsd_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_egprs_multislot_class,
      { "EGPRS_multislot_class",        "gsm_rlcmac.ul.egprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_egprs_extended_dynamic_allocation_capability,
      { "EGPRS_Extended_Dynamic_Allocation_Capability",        "gsm_rlcmac.ul.egprs_extended_dynamic_allocation_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_dtm_gprs_multislot_class,
      { "DTM_GPRS_multislot_class",        "gsm_rlcmac.ul.dtm_gprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multislot_capability_single_slot_dtm,
      { "Single_Slot_DTM",        "gsm_rlcmac.ul.single_slot_dtm",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_rf_power_capability,
      { "RF_Power_Capability",        "gsm_rlcmac.ul.rf_power_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_a5_bits,
      { "A5_bits",        "gsm_rlcmac.ul.a5_bits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_es_ind,
      { "ES_IND",        "gsm_rlcmac.ul.es_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_ps,
      { "PS",        "gsm_rlcmac.ul.ps",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_vgcs,
      { "VGCS",        "gsm_rlcmac.ul.vgcs",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_vbs,
      { "VBS",        "gsm_rlcmac.ul.vbs",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_eight_psk_power_capability,
      { "Eight_PSK_Power_Capability",        "gsm_rlcmac.ul.eight_psk_power_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_compact_interference_measurement_capability,
      { "COMPACT_Interference_Measurement_Capability",        "gsm_rlcmac.ul.compact_interference_measurement_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_revision_level_indicator,
      { "Revision_Level_Indicator",        "gsm_rlcmac.ul.revision_level_indicator",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_umts_fdd_radio_access_technology_capability,
      { "UMTS_FDD_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.umts_fdd_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_umts_384_tdd_radio_access_technology_capability,
      { "UMTS_384_TDD_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.umts_384_tdd_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_cdma2000_radio_access_technology_capability,
      { "CDMA2000_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.cdma2000_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_umts_128_tdd_radio_access_technology_capability,
      { "UMTS_128_TDD_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.umts_128_tdd_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_geran_feature_package_1,
      { "GERAN_Feature_Package_1",        "gsm_rlcmac.ul.geran_feature_package_1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_extended_dtm_gprs_multislot_class,
      { "Extended_DTM_GPRS_multislot_class",        "gsm_rlcmac.ul.extended_dtm_gprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_extended_dtm_egprs_multislot_class,
      { "Extended_DTM_EGPRS_multislot_class",        "gsm_rlcmac.ul.extended_dtm_egprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_modulation_based_multislot_class_support,
      { "Modulation_based_multislot_class_support",        "gsm_rlcmac.ul.modulation_based_multislot_class_support",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_highmultislotcapability,
      { "HighMultislotCapability",        "gsm_rlcmac.ul.highmultislotcapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_geran_lu_modecapability,
      { "GERAN_lu_ModeCapability",        "gsm_rlcmac.ul.geran_lu_modecapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_gmsk_multislotpowerprofile,
      { "GMSK_MultislotPowerProfile",        "gsm_rlcmac.ul.gmsk_multislotpowerprofile",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_eightpsk_multislotprofile,
      { "EightPSK_MultislotProfile",        "gsm_rlcmac.ul.eightpsk_multislotprofile",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_multipletbf_capability,
      { "MultipleTBF_Capability",        "gsm_rlcmac.ul.multipletbf_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_downlinkadvancedreceiverperformance,
      { "DownlinkAdvancedReceiverPerformance",        "gsm_rlcmac.ul.downlinkadvancedreceiverperformance",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_extendedrlc_mac_controlmessagesegmentionscapability,
      { "ExtendedRLC_MAC_ControlMessageSegmentionsCapability",        "gsm_rlcmac.ul.extendedrlc_mac_controlmessagesegmentionscapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_dtm_enhancementscapability,
      { "DTM_EnhancementsCapability",        "gsm_rlcmac.ul.dtm_enhancementscapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_dtm_gprs_highmultislotclass,
      { "DTM_GPRS_HighMultislotClass",        "gsm_rlcmac.ul.dtm_gprs_highmultislotclass",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_content_ps_handovercapability,
      { "PS_HandoverCapability",        "gsm_rlcmac.ul.ps_handovercapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_additional_accessechnologies_struct_t_access_technology_type,
      { "Access_Technology_Type",        "gsm_rlcmac.ul.access_technology_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_additional_accessechnologies_struct_t_gmsk_power_class,
      { "GMSK_Power_class",        "gsm_rlcmac.ul.gmsk_power_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_additional_accessechnologies_struct_t_eight_psk_power_class,
      { "Eight_PSK_Power_class",        "gsm_rlcmac.ul.eight_psk_power_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
#if 0
    { &hf_ms_radio_access_capability_iei,
      { "IEI",        "gsm_rlcmac.ul.iei",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_radio_access_capability_length,
      { "Length",        "gsm_rlcmac.ul.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
#endif
/*< MS Classmark 3 IE >*/
    { &hf_arc_a5_bits,
      { "A5_Bits",        "gsm_rlcmac.ul.a5_bits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_arc_arc2_spare,
      { "Arc2_Spare",        "gsm_rlcmac.ul.arc2_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_arc_arc1,
      { "Arc1",        "gsm_rlcmac.ul.arc1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multiband_a5_bits,
      { "A5 Bits",        "gsm_rlcmac.ul.multiband_a5_bits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_edge_rf_pwr_edge_rf_pwrcap1,
      { "EDGE_RF_PwrCap1",        "gsm_rlcmac.ul.edge_rf_pwrcap1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_edge_rf_pwr_edge_rf_pwrcap2,
      { "EDGE_RF_PwrCap2",        "gsm_rlcmac.ul.edge_rf_pwrcap2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_spare1,
      { "Spare1",        "gsm_rlcmac.ul.ms_class3_unpacked_spare1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_r_gsm_arc,
      { "R_GSM_Arc",        "gsm_rlcmac.ul.ms_class3_unpacked_r_gsm_arc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_multislotclass,
      { "MultiSlotClass",        "gsm_rlcmac.ul.ms_class3_unpacked_multislotclass",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_ucs2,
      { "UCS2",        "gsm_rlcmac.ul.ms_class3_unpacked_ucs2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_extendedmeasurementcapability,
      { "ExtendedMeasurementCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_extendedmeasurementcapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_sms_value,
      { "SMS_VALUE",        "gsm_rlcmac.ul.ms_class3_unpacked_sms_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_sm_value,
      { "SM_VALUE",        "gsm_rlcmac.ul.ms_class3_unpacked_sm_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_ms_positioningmethod,
      { "MS_PositioningMethod",        "gsm_rlcmac.ul.ms_class3_unpacked_ms_positioningmethod",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_edge_multislotclass,
      { "EDGE_MultiSlotClass",        "gsm_rlcmac.ul.ms_class3_unpacked_edge_multislotclass",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_modulationcapability,
      { "ModulationCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_modulationcapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_gsm400_bands,
      { "GSM400_Bands",        "gsm_rlcmac.ul.ms_class3_unpacked_gsm400_bands",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_gsm400_arc,
      { "GSM400_Arc",        "gsm_rlcmac.ul.ms_class3_unpacked_gsm400_arc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_gsm850_arc,
      { "GSM850_Arc",        "gsm_rlcmac.ul.ms_class3_unpacked_gsm850_arc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_pcs1900_arc,
      { "PCS1900_Arc",        "gsm_rlcmac.ul.ms_class3_unpacked_pcs1900_arc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_umts_fdd_radio_access_technology_capability,
      { "UMTS_FDD_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.ms_class3_unpacked_umts_fdd_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_umts_384_tdd_radio_access_technology_capability,
      { "UMTS_384_TDD_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.ms_class3_unpacked_umts_384_tdd_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_cdma2000_radio_access_technology_capability,
      { "CDMA2000_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.ms_class3_unpacked_cdma2000_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_dtm_gprs_multislot_class,
      { "DTM_GPRS_multislot_class",        "gsm_rlcmac.ul.ms_class3_unpacked_dtm_gprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_single_slot_dtm,
      { "Single_Slot_DTM",        "gsm_rlcmac.ul.ms_class3_unpacked_single_slot_dtm",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_gsm_band,
      { "GSM_Band",        "gsm_rlcmac.ul.ms_class3_unpacked_gsm_band",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_gsm_700_associated_radio_capability,
      { "GSM_700_Associated_Radio_Capability",        "gsm_rlcmac.ul.ms_class3_unpacked_gsm_700_associated_radio_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_umts_128_tdd_radio_access_technology_capability,
      { "UMTS_128_TDD_Radio_Access_Technology_Capability",        "gsm_rlcmac.ul.ms_class3_unpacked_umts_128_tdd_radio_access_technology_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_geran_feature_package_1,
      { "GERAN_Feature_Package_1",        "gsm_rlcmac.ul.ms_class3_unpacked_geran_feature_package_1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_extended_dtm_gprs_multislot_class,
      { "Extended_DTM_GPRS_multislot_class",        "gsm_rlcmac.ul.ms_class3_unpacked_extended_dtm_gprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_extended_dtm_egprs_multislot_class,
      { "Extended_DTM_EGPRS_multislot_class",        "gsm_rlcmac.ul.ms_class3_unpacked_extended_dtm_egprs_multislot_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_highmultislotcapability,
      { "HighMultislotCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_highmultislotcapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_geran_lu_modecapability,
      { "GERAN_lu_ModeCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_geran_lu_modecapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_geran_featurepackage_2,
      { "GERAN_FeaturePackage_2",        "gsm_rlcmac.ul.ms_class3_unpacked_geran_featurepackage_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_gmsk_multislotpowerprofile,
      { "GMSK_MultislotPowerProfile",        "gsm_rlcmac.ul.ms_class3_unpacked_gmsk_multislotpowerprofile",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_eightpsk_multislotprofile,
      { "EightPSK_MultislotProfile",        "gsm_rlcmac.ul.ms_class3_unpacked_eightpsk_multislotprofile",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_tgsm_400_bandssupported,
      { "TGSM_400_BandsSupported",        "gsm_rlcmac.ul.ms_class3_unpacked_tgsm_400_bandssupported",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_tgsm_400_associatedradiocapability,
      { "TGSM_400_AssociatedRadioCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_tgsm_400_associatedradiocapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_tgsm_900_associatedradiocapability,
      { "TGSM_900_AssociatedRadioCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_tgsm_900_associatedradiocapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_downlinkadvancedreceiverperformance,
      { "DownlinkAdvancedReceiverPerformance",        "gsm_rlcmac.ul.ms_class3_unpacked_downlinkadvancedreceiverperformance",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_dtm_enhancementscapability,
      { "DTM_EnhancementsCapability",        "gsm_rlcmac.ul.ms_class3_unpacked_dtm_enhancementscapability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_dtm_gprs_highmultislotclass,
      { "DTM_GPRS_HighMultislotClass",        "gsm_rlcmac.ul.ms_class3_unpacked_dtm_gprs_highmultislotclass",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_offsetrequired,
      { "OffsetRequired",        "gsm_rlcmac.ul.ms_class3_unpacked_offsetrequired",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_repeatedsacch_capability,
      { "RepeatedSACCH_Capability",        "gsm_rlcmac.ul.ms_class3_unpacked_repeatedsacch_capability",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ms_class3_unpacked_spare2,
      { "Spare2",        "gsm_rlcmac.ul.ms_class3_unpacked_spare2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_request_description_peak_throughput_class,
      { "PEAK_THROUGHPUT_CLASS",        "gsm_rlcmac.ul.channel_request_description_peak_throughput_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_request_description_radio_priority,
      { "RADIO_PRIORITY",        "gsm_rlcmac.ul.channel_request_description_radio_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_request_description_llc_pdu_type,
      { "LLC_PDU_TYPE",        "gsm_rlcmac.ul.channel_request_description_llc_pdu_type",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_channel_request_description_rlc_octet_count,
      { "RLC_OCTET_COUNT",        "gsm_rlcmac.ul.channel_request_description_rlc_octet_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/* < Packet Resource Request message content > */
    { &hf_bep_measurementreport_mean_bep_gmsk,
      { "MEAN_BEP_GMSK",        "gsm_rlcmac.ul.prr_mean_bep_gmsk",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_bep_measurementreport_mean_bep_8psk,
      { "MEAN_BEP_8PSK",        "gsm_rlcmac.ul.prr_mean_bep_8psk",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_interferencemeasurementreport_i_level,
      { "I_LEVEL",        "gsm_rlcmac.ul.prr_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_bep_linkqualitymeasurements_mean_bep_gmsk,
      { "MEAN_BEP_GMSK",        "gsm_rlcmac.ul.prr_mean_bep_gmsk",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_bep_linkqualitymeasurements_cv_bep_gmsk,
      { "CV_BEP_GMSK",        "gsm_rlcmac.ul.prr_cv_bep_gmsk",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_bep_linkqualitymeasurements_mean_bep_8psk,
      { "MEAN_BEP_8PSK",        "gsm_rlcmac.ul.prr_mean_bep_8psk",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_bep_linkqualitymeasurements_cv_bep_8psk,
      { "CV_BEP_8PSK",        "gsm_rlcmac.ul.prr_cv_bep_8psk",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_prr_additionsr99_ms_rac_additionalinformationavailable,
      { "MS_RAC_AdditionalInformationAvailable",        "gsm_rlcmac.ul.prr_ms_rac_additionalinformationavailable",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_prr_additionsr99_retransmissionofprr,
      { "RetransmissionOfPRR",        "gsm_rlcmac.ul.prr_retransmissionofprr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ul_mac_header_spare,
      { "spare",        "gsm_rlcmac.ul.mac_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_resource_request_access_type,
      { "ACCESS_TYPE",        "gsm_rlcmac.ul.prr_access_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_resource_request_change_mark,
      { "CHANGE_MARK",        "gsm_rlcmac.ul.prr_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_resource_request_c_value,
      { "C_VALUE",        "gsm_rlcmac.ul.prr_c_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_resource_request_sign_var,
      { "SIGN_VAR",        "gsm_rlcmac.ul.prr_sign_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Mobile TBF Status message content > */
    { &hf_packet_mobile_tbf_status_tbf_cause,
      { "TBF_CAUSE",        "gsm_rlcmac.ul.pmts_tbf_cause",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/*< Packet PSI Status message content > */
    { &hf_psi_message_psix_change_mark,
      { "PSIX_CHANGE_MARK",        "gsm_rlcmac.ul.pps_psix_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_additional_msg_type,
      { "ADDITIONAL_MSG_TYPE",        "gsm_rlcmac.ul.additional_msg_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_psi_status_pbcch_change_mark,
      { "PBCCH_CHANGE_MARK",        "gsm_rlcmac.ul.pps_pbcch_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/* < Packet SI Status message content > */
    { &hf_si_message_mess_rec,
      { "MESS_REC",        "gsm_rlcmac.ul.si_message_mess_rec",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/* < Packet Downlink Ack/Nack message content > */

/*< EGPRS Packet Downlink Ack/Nack message content > */
    { &hf_egprs_channelqualityreport_c_value,
      { "C_VALUE",        "gsm_rlcmac.ul.epdan_c_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_pd_acknack_ms_out_of_memory,
      { "MS_OUT_OF_MEMORY",        "gsm_rlcmac.ul.epdan_ms_out_of_memory",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fddarget_cell_t_fdd_arfcn,
      { "FDD_ARFCN",        "gsm_rlcmac.ul.epdan_fdd_arfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fddarget_cell_t_diversity,
      { "DIVERSITY",        "gsm_rlcmac.ul.epdan_diversity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fddarget_cell_t_bandwith_fdd,
      { "BANDWITH_FDD",        "gsm_rlcmac.ul.epdan_bandwith_fdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fddarget_cell_t_scrambling_code,
      { "SCRAMBLING_CODE",        "gsm_rlcmac.ul.epdan_scrambling_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tddarget_cell_t_tdd_arfcn,
      { "TDD-ARFCN",        "gsm_rlcmac.ul.epdan_tdd_arfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tddarget_cell_t_diversity,
      { "Diversity TDD",        "gsm_rlcmac.ul.epdan_diversity_tdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tddarget_cell_t_bandwith_tdd,
      { "Bandwidth_TDD",        "gsm_rlcmac.ul.epdan_bandwidth_tdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tddarget_cell_t_cell_parameter,
      { "Cell Parameter",        "gsm_rlcmac.ul.epdan_cell_param",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_tddarget_cell_t_sync_case_tstd,
      { "Sync Case TSTD",        "gsm_rlcmac.ul.epdan_sync_case_tstd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Cell Change Failure message content > */
    { &hf_packet_cell_change_failure_bsic,
      { "BSIC",        "gsm_rlcmac.ul.pccf_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_change_failure_cause,
      { "CAUSE",        "gsm_rlcmac.ul.pccf_cause",
        FT_UINT8, BASE_DEC, VALS(cell_change_failure_cause_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_target_cell_ci,
      { "UTRAN_CI",        "gsm_rlcmac.ul.utran_csg_target_cell_ci",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_target_cell_ci,
      { "EUTRAN_CI",        "gsm_rlcmac.ul.eutran_csg_target_cell_ci",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_target_cell_tac,
      { "Tracking Area Code",        "gsm_rlcmac.ul.eutran_csg_target_cell_tac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Uplink Ack/Nack message content > */
    { &hf_pu_acknack_gprs_additionsr99_tbf_est,
      { "TBF_EST",        "gsm_rlcmac.ul.puan_tbf_est",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pu_acknack_gprs_fixedallocationdummy,
      { "FixedAllocationDummy",        "gsm_rlcmac.ul.puan_fixedallocationdummy",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pu_acknack_egprs_00_pre_emptive_transmission,
      { "PRE_EMPTIVE_TRANSMISSION",        "gsm_rlcmac.ul.puan_pre_emptive_transmission",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pu_acknack_egprs_00_prr_retransmission_request,
      { "PRR_RETRANSMISSION_REQUEST",        "gsm_rlcmac.ul.puan_prr_retransmission_request",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pu_acknack_egprs_00_arac_retransmission_request,
      { "ARAC_RETRANSMISSION_REQUEST",        "gsm_rlcmac.ul.puan_arac_retransmission_request",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pu_acknack_egprs_00_tbf_est,
      { "TBF_EST",        "gsm_rlcmac.ul.puan_tbf_est",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_extended_timing_advance,
      { "Packet_Extended_Timing_Advance",        "gsm_rlcmac.ul.packet_extended_timing_advance",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Uplink Assignment message content > */
    { &hf_change_mark_change_mark_1,
      { "CHANGE_MARK_1",        "gsm_rlcmac.dl.pua_change_mark_1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_change_mark_change_mark_2,
      { "CHANGE_MARK_2",        "gsm_rlcmac.dl.pua_change_mark_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_indirect_encoding_ma_number,
      { "MA_NUMBER",        "gsm_rlcmac.dl.pua_ma_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_request_reference_random_access_information,
      { "RANDOM_ACCESS_INFORMATION",        "gsm_rlcmac.dl.pua_random_access_information",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_extended_dynamic_allocation,
      { "Extended_Dynamic_Allocation",        "gsm_rlcmac.dl.extended_dynamic_allocation",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

    { &hf_rlc_data_blocks_granted,
      { "RLC_DATA_BLOCKS_GRANTED",        "gsm_rlcmac.dl.rlc_data_blocks_granted",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_single_block_allocation_timeslot_number,
      { "TIMESLOT_NUMBER",        "gsm_rlcmac.dl.pua_timeslot_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dtm_single_block_allocation_timeslot_number,
      { "TIMESLOT_NUMBER",        "gsm_rlcmac.dl.pua_dtm_timeslot_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_compact_reducedma_bitmaplength,
      { "BitmapLength",        "gsm_rlcmac.dl.pua_bitmaplength",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multiblock_allocation_timeslot_number,
      { "TIMESLOT_NUMBER",        "gsm_rlcmac.dl.pua_multiblock_timeslot_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pua_egprs_00_arac_retransmission_request,
      { "ARAC_RETRANSMISSION_REQUEST",        "gsm_rlcmac.dl.pua_egprs_00_arac_retransmission_request",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Downlink Assignment message content > */
    { &hf_measurement_mapping_struct_measurement_interval,
      { "MEASUREMENT_INTERVAL",        "gsm_rlcmac.dl.pda_measurement_interval",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_measurement_mapping_struct_measurement_bitmap,
      { "MEASUREMENT_BITMAP",        "gsm_rlcmac.dl.pda_measurement_bitmap",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_mac_mode,
      { "MAC_MODE",        "gsm_rlcmac.dl.mac_mode",
        FT_UINT8, BASE_DEC, VALS(mac_mode_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_control_ack,
      { "CONTROL_ACK",        "gsm_rlcmac.dl.control_ack",
        FT_BOOLEAN, BASE_NONE, TFS(&control_ack_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_timeslot_allocation,
      { "TIMESLOT_ALLOCATION",        "gsm_rlcmac.dl.timeslot_allocation",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dtm_channel_request_description_dtm_pkt_est_cause,
      { "DTM_Pkt_Est_Cause",        "gsm_rlcmac.dl.pda_dtm_pkt_est_cause",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Paging Request message content > */
    { &hf_mobile_identity_length_of_mobile_identity_contents,
      { "Length_of_Mobile_Identity_contents",        "gsm_rlcmac.dl.ppr_length_of_mobile_identity_contents",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_page_request_for_rr_conn_channel_needed,
      { "CHANNEL_NEEDED",        "gsm_rlcmac.dl.ppr_channel_needed",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_page_request_for_rr_conn_emlpp_priority,
      { "eMLPP_PRIORITY",        "gsm_rlcmac.dl.ppr_emlpp_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_pdch_release_timeslots_available,
      { "TIMESLOTS_AVAILABLE",        "gsm_rlcmac.dl.ppr_timeslots_available",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/*< Packet Power Control/Timing Advance message content >*/

/*< Packet Queueing Notification message content > */

/*< Packet Timeslot Reconfigure message content > */

/*< Packet PRACH Parameters message content > */
    { &hf_prach_control_s,
      { "S",        "gsm_rlcmac.dl.prach_s",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_prach_control_tx_int,
      { "TX_INT",        "gsm_rlcmac.dl.prach_tx_int",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_hcs_priority_class,
      { "PRIORITY_CLASS",        "gsm_rlcmac.dl.hcs_priority_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_hcs_hcs_thr,
      { "HCS_THR",        "gsm_rlcmac.dl.hcs_thr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_location_repeat_pbcch_location,
      { "PBCCH_LOCATION",        "gsm_rlcmac.dl.pbcch_location",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_location_repeat_psi1_repeat_period,
      { "PSI1_REPEAT_PERIOD",        "gsm_rlcmac.dl.psi1_repeat_period",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_val_plus_1_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_si13_pbcch_location_si13_location,
      { "SI13_LOCATION",        "gsm_rlcmac.dl.si13_location",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_bsic,
      { "BSIC",        "gsm_rlcmac.dl.cell_selection_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_bar_access_2,
      { "CELL_BAR_ACCESS_2",        "gsm_rlcmac.dl.cell_selection_cell_bar_access_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_exc_acc,
      { "EXC_ACC",        "gsm_rlcmac.dl.exc_acc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_same_ra_as_serving_cell,
      { "SAME_RA_AS_SERVING_CELL",        "gsm_rlcmac.dl.cell_selection_same_ra_as_serving_cell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_gprs_rxlev_access_min,
      { "GPRS_RXLEV_ACCESS_MIN",        "gsm_rlcmac.dl.cell_selection_gprs_rxlev_access_min",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_gprs_ms_txpwr_max_cch,
      { "GPRS_MS_TXPWR_MAX_CCH",        "gsm_rlcmac.dl.cell_selection_gprs_ms_txpwr_max_cch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_gprs_temporary_offset,
      { "GPRS_TEMPORARY_OFFSET",        "gsm_rlcmac.dl.cell_selection_gprs_temporary_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_gprs_penalty_time,
      { "GPRS_PENALTY_TIME",        "gsm_rlcmac.dl.cell_selection_gprs_penalty_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_gprs_reselect_offset,
      { "GPRS_RESELECT_OFFSET",        "gsm_rlcmac.dl.cell_selection_gprs_reselect_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_neighbourcellparameters_start_frequency,
      { "START_FREQUENCY",        "gsm_rlcmac.dl.cell_selection_start_frequency",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_neighbourcellparameters_nr_of_remaining_cells,
      { "NR_OF_REMAINING_CELLS",        "gsm_rlcmac.dl.cell_selection_nr_of_remaining_cells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_2_same_ra_as_serving_cell,
      { "SAME_RA_AS_SERVING_CELL",        "gsm_rlcmac.dl.cell_selection2_same_ra_as_serving_cell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_2_gprs_rxlev_access_min,
      { "GPRS_RXLEV_ACCESS_MIN",        "gsm_rlcmac.dl.cell_selection2_gprs_rxlev_access_min",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_2_gprs_ms_txpwr_max_cch,
      { "GPRS_MS_TXPWR_MAX_CCH",        "gsm_rlcmac.dl.cell_selection2_gprs_ms_txpwr_max_cch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_2_gprs_temporary_offset,
      { "GPRS_TEMPORARY_OFFSET",        "gsm_rlcmac.dl.cell_selection2_gprs_temporary_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_2_gprs_penalty_time,
      { "GPRS_PENALTY_TIME",        "gsm_rlcmac.dl.cell_selection2_gprs_penalty_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cell_selection_2_gprs_reselect_offset,
      { "GPRS_RESELECT_OFFSET",        "gsm_rlcmac.dl.cell_selection2_gprs_reselect_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/* < Packet Access Reject message content > */
    { &hf_reject_wait_indication,
      { "WAIT_INDICATION",        "gsm_rlcmac.dl.par_wait_indication",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_reject_wait_indication_size,
      { "WAIT_INDICATION_SIZE",        "gsm_rlcmac.dl.par_wait_indication_size",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/* < Packet Cell Change Order message content > */
    { &hf_h_freqbsiccell_bsic,
      { "BSIC",        "gsm_rlcmac.dl.pcco_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cellselectionparamswithfreqdiff_bsic,
      { "BSIC",        "gsm_rlcmac.dl.pcco_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_frequency_list_start_frequency,
      { "START_FREQUENCY",        "gsm_rlcmac.dl.add_frequency_list_start_frequency",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_frequency_list_bsic,
      { "BSIC",        "gsm_rlcmac.dl.add_frequency_list_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_frequency_list_nr_of_frequencies,
      { "NR_OF_FREQUENCIES",        "gsm_rlcmac.dl.add_frequency_list_nr_of_frequencies",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_removed_freq_index_removed_freq_index,
      { "REMOVED FREQUENCIES",        "gsm_rlcmac.dl.removed_freq_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_network_control_order,
      { "NETWORK_CONTROL_ORDER",        "gsm_rlcmac.dl.nc_measurement_parameters_network_control_order",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_nc_non_drx_period,
      { "NC_NON_DRX_PERIOD",        "gsm_rlcmac.dl.nc_measurement_parameters_nc_non_drx_period",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_nc_reporting_period_i,
      { "NC_REPORTING_PERIOD_I",        "gsm_rlcmac.dl.nc_measurement_parameters_nc_reporting_period_i",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_nc_reporting_period_t,
      { "NC_REPORTING_PERIOD_T",        "gsm_rlcmac.dl.nc_measurement_parameters_nc_reporting_period_t",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_with_frequency_list_network_control_order,
      { "NETWORK_CONTROL_ORDER",        "gsm_rlcmac.dl.nc_measurement_parameters_network_control_order",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_with_frequency_list_nc_non_drx_period,
      { "NC_NON_DRX_PERIOD",        "gsm_rlcmac.dl.nc_measurement_parameters_nc_non_drx_period",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_with_frequency_list_nc_reporting_period_i,
      { "NC_REPORTING_PERIOD_I",        "gsm_rlcmac.dl.nc_measurement_parameters_nc_reporting_period_i",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_parameters_with_frequency_list_nc_reporting_period_t,
      { "NC_REPORTING_PERIOD_T",        "gsm_rlcmac.dl.nc_measurement_parameters_nc_reporting_period_t",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Cell Change Order message contents >*/
    { &hf_ba_ind_ba_ind,
      { "BA_IND",        "gsm_rlcmac.dl.pcco_ba_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ba_ind_ba_ind_3g,
      { "BA_IND_3G",        "gsm_rlcmac.dl.pcco_ba_ind_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsreportpriority_number_cells,
      { "NUMBER_CELLS",        "gsm_rlcmac.dl.gprsreportpriority_number_cells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_offsetthreshold_reporting_offset,
      { "REPORTING_OFFSET",        "gsm_rlcmac.dl.offsetthreshold_reporting_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_offsetthreshold_reporting_threshold,
      { "REPORTING_THRESHOLD",        "gsm_rlcmac.dl.offsetthreshold_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams_pmo_pcco_multi_band_reporting,
      { "MULTI_BAND_REPORTING",        "gsm_rlcmac.dl.gprsmeasurementparams_pmo_pcco_multi_band_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams_pmo_pcco_serving_band_reporting,
      { "SERVING_BAND_REPORTING",        "gsm_rlcmac.dl.gprsmeasurementparams_pmo_pcco_serving_band_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams_pmo_pcco_scale_ord,
      { "SCALE_ORD",        "gsm_rlcmac.dl.gprsmeasurementparams_pmo_pcco_scale_ord",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_qsearch_p,
      { "Qsearch_p",        "gsm_rlcmac.dl.gprsmeasurementparams3g_qsearch_p",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_searchprio3g,
      { "SearchPrio3G",        "gsm_rlcmac.dl.gprsmeasurementparams3g_searchprio3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_repquantfdd,
      { "RepQuantFDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_repquantfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_multiratreportingfdd,
      { "MultiratReportingFDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_multiratreportingfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_reportingoffsetfdd,
      { "ReportingOffsetFDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_reportingoffsetfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_reportingthresholdfdd,
      { "ReportingThresholdFDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_reportingthresholdfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_multiratreportingtdd,
      { "MultiratReportingTDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_multiratreportingtdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_reportingoffsettdd,
      { "ReportingOffsetTDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_reportingoffsettdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_reportingthresholdtdd,
      { "ReportingThresholdTDD",        "gsm_rlcmac.dl.gprsmeasurementparams3g_reportingthresholdtdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_multiratparams3g_multiratreporting,
      { "MultiratReporting",        "gsm_rlcmac.dl.multiratparams3g_multiratreporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pmo_qsearch_p,
      { "Qsearch_P",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pmo_qsearch_p",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pmo_searchprio3g,
      { "SearchPrio3G",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pmo_searchprio3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pmo_repquantfdd,
      { "RepQuantFDD",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pmo_repquantfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pmo_multiratreportingfdd,
      { "MultiratReportingFDD",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pmo_multiratreportingfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pcco_qsearch_p,
      { "Qsearch_P",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pcco_qsearch_p",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pcco_searchprio3g,
      { "SearchPrio3G",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pcco_searchprio3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pcco_repquantfdd,
      { "RepQuantFDD",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pcco_repquantfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_gprsmeasurementparams3g_pcco_multiratreportingfdd,
      { "MultiratReportingFDD",        "gsm_rlcmac.dl.enh_gprsmeasurementparams3g_pcco_multiratreportingfdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_n2_removed_3gcell_index,
      { "REMOVED_3GCELL_INDEX",        "gsm_rlcmac.dl.removed_3gcell_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_n2_cell_diff_length_3g,
      { "CELL_DIFF_LENGTH_3G",        "gsm_rlcmac.dl.cell_diff_length_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_cdma2000_description_complete_this,
      { "Complete_This",        "gsm_rlcmac.dl.complete_this",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_fdd_neighbourcells_zero,
      { "ZERO",        "gsm_rlcmac.dl.utran_fdd_neighbourcells_zero",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_fdd_neighbourcells_uarfcn,
      { "UARFCN",        "gsm_rlcmac.dl.utran_fdd_neighbourcells_uarfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_fdd_neighbourcells_indic0,
      { "Indic0",        "gsm_rlcmac.dl.utran_fdd_neighbourcells_indic0",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_fdd_neighbourcells_nrofcells,
      { "NrOfCells",        "gsm_rlcmac.dl.utran_fdd_neighbourcells_nrofcells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_fdd_description_bandwidth,
      { "Bandwidth",        "gsm_rlcmac.dl.utran_fdd_neighbourcells_bandwidth",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_tdd_neighbourcells_zero,
      { "ZERO",        "gsm_rlcmac.dl.utran_tdd_neighbourcells_zero",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_tdd_neighbourcells_uarfcn,
      { "UARFCN",        "gsm_rlcmac.dl.utran_tdd_neighbourcells_uarfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_tdd_neighbourcells_indic0,
      { "Indic0",        "gsm_rlcmac.dl.utran_tdd_neighbourcells_indic0",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_tdd_neighbourcells_nrofcells,
      { "NrOfCells",        "gsm_rlcmac.dl.utran_tdd_neighbourcells_nrofcells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_tdd_description_bandwidth,
      { "Bandwidth",        "gsm_rlcmac.dl.utran_tdd_description_bandwidth",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_index_start_3g,
      { "Index_Start_3G",        "gsm_rlcmac.dl.index_start_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_absolute_index_start_emr,
      { "Absolute_Index_Start_EMR",        "gsm_rlcmac.dl.absolute_index_start_emr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_psi3_change_mark,
      { "PSI3_CHANGE_MARK",        "gsm_rlcmac.dl.psi3_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pmo_pmo_ind,
      { "PMO_IND",        "gsm_rlcmac.dl.enh_measurement_parameters_pmo_pmo_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pmo_report_type,
      { "REPORT_TYPE",        "gsm_rlcmac.dl.enh_measurement_parameters_pmo_report_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pmo_reporting_rate,
      { "REPORTING_RATE",        "gsm_rlcmac.dl.enh_measurement_parameters_pmo_reporting_rate",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pmo_invalid_bsic_reporting,
      { "INVALID_BSIC_REPORTING",        "gsm_rlcmac.dl.enh_measurement_parameters_pmo_invalid_bsic_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pcco_pmo_ind,
      { "PMO_IND",        "gsm_rlcmac.dl.enh_measurement_parameters_pcco_pmo_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pcco_report_type,
      { "REPORT_TYPE",        "gsm_rlcmac.dl.enh_measurement_parameters_pcco_report_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pcco_reporting_rate,
      { "REPORTING_RATE",        "gsm_rlcmac.dl.enh_measurement_parameters_pcco_reporting_rate",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_measurement_parameters_pcco_invalid_bsic_reporting,
      { "INVALID_BSIC_REPORTING",        "gsm_rlcmac.dl.enh_measurement_parameters_pcco_invalid_bsic_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ccn_support_description_number_cells,
      { "NUMBER_CELLS",        "gsm_rlcmac.dl.ccn_support_description_number_cells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modecellselectionparameters_cell_bar_qualify_3,
      { "CELL_BAR_QUALIFY_3",        "gsm_rlcmac.dl.lu_modecellselectionparameters_cell_bar_qualify_3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeneighbourcellparams_nr_of_frequencies,
      { "NR_OF_FREQUENCIES",        "gsm_rlcmac.dl.lu_modecellselectionparameters_nr_of_frequencies",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_cell_bar_qualify_3,
      { "CELL_BAR_QUALIFY_3",        "gsm_rlcmac.dl.lu_modeonlycellselection_cell_bar_qualify_3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_same_ra_as_serving_cell,
      { "SAME_RA_AS_SERVING_CELL",        "gsm_rlcmac.dl.lu_modeonlycellselection_same_ra_as_serving_cell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_gprs_rxlev_access_min,
      { "GPRS_RXLEV_ACCESS_MIN",        "gsm_rlcmac.dl.lu_modeonlycellselection_gprs_rxlev_access_min",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_gprs_ms_txpwr_max_cch,
      { "GPRS_MS_TXPWR_MAX_CCH",        "gsm_rlcmac.dl.lu_modeonlycellselection_gprs_ms_txpwr_max_cch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_gprs_temporary_offset,
      { "GPRS_TEMPORARY_OFFSET",        "gsm_rlcmac.dl.lu_modeonlycellselection_gprs_temporary_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_gprs_penalty_time,
      { "GPRS_PENALTY_TIME",        "gsm_rlcmac.dl.lu_modeonlycellselection_gprs_penalty_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselection_gprs_reselect_offset,
      { "GPRS_RESELECT_OFFSET",        "gsm_rlcmac.dl.lu_modeonlycellselection_gprs_reselect_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lu_modeonlycellselectionparamswithfreqdiff_bsic,
      { "BSIC",        "gsm_rlcmac.dl.lu_modeonlycellselectionparamswithfreqdiff_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_lu_modeonlyfrequencylist_start_frequency,
      { "START_FREQUENCY",        "gsm_rlcmac.dl.dd_lu_modeonlyfrequencylist_start_frequency",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_lu_modeonlyfrequencylist_bsic,
      { "BSIC",        "gsm_rlcmac.dl.dd_lu_modeonlyfrequencylist_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_lu_modeonlyfrequencylist_nr_of_frequencies,
      { "NR_OF_FREQUENCIES",        "gsm_rlcmac.dl.dd_lu_modeonlyfrequencylist_nr_of_frequencies",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_add_lu_modeonlyfrequencylist_freq_diff_length,
      { "FREQ_DIFF_LENGTH",        "gsm_rlcmac.dl.dd_lu_modeonlyfrequencylist_freq_diff_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_additionalmeasurementparams3g_fdd_reporting_threshold_2,
      { "FDD_REPORTING_THRESHOLD_2",        "gsm_rlcmac.dl.gprs_additionalmeasurementparams3g_fdd_reporting_threshold_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_servingcellpriorityparametersdescription_geran_priority,
      { "GERAN_PRIORITY",        "gsm_rlcmac.dl.servingcellpriorityparametersdescription_geran_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_servingcellpriorityparametersdescription_thresh_priority_search,
      { "THRESH_Priority_Search",        "gsm_rlcmac.dl.servingcellpriorityparametersdescription_thresh_priority_search",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_servingcellpriorityparametersdescription_thresh_gsm_low,
      { "THRESH_GSM_low",        "gsm_rlcmac.dl.servingcellpriorityparametersdescription_thresh_gsm_low",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_servingcellpriorityparametersdescription_h_prio,
      { "H_PRIO",        "gsm_rlcmac.dl.servingcellpriorityparametersdescription_h_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_servingcellpriorityparametersdescription_t_reselection,
      { "T_Reselection",        "gsm_rlcmac.dl.servingcellpriorityparametersdescription_t_reselection",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedutran_priorityparameters_utran_priority,
      { "UTRAN_PRIORITY",        "gsm_rlcmac.dl.repeatedutran_priorityparameters_utran_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedutran_priorityparameters_thresh_utran_high,
      { "THRESH_UTRAN_high",        "gsm_rlcmac.dl.repeatedutran_priorityparameters_thresh_utran_high",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedutran_priorityparameters_thresh_utran_low,
      { "THRESH_UTRAN_low",        "gsm_rlcmac.dl.repeatedutran_priorityparameters_thresh_utran_low",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedutran_priorityparameters_utran_qrxlevmin,
      { "UTRAN_QRXLEVMIN",        "gsm_rlcmac.dl.repeatedutran_priorityparameters_utran_qrxlevmin",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_priorityparametersdescription3g_pmo_default_utran_priority,
      { "DEFAULT_UTRAN_PRIORITY",        "gsm_rlcmac.dl.priorityparametersdescription3g_pmo_default_utran_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_priorityparametersdescription3g_pmo_default_thresh_utran,
      { "DEFAULT_THRESH_UTRAN",        "gsm_rlcmac.dl.priorityparametersdescription3g_pmo_default_thresh_utran",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_priorityparametersdescription3g_pmo_default_utran_qrxlevmin,
      { "DEFAULT_UTRAN_QRXLEVMIN",        "gsm_rlcmac.dl.priorityparametersdescription3g_pmo_default_utran_qrxlevmin",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_threshold,
      { "EUTRAN_FDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.eutran_fdd_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_threshold_2,
      { "EUTRAN_FDD_REPORTING_THRESHOLD_2",        "gsm_rlcmac.dl.eutran_fdd_reporting_threshold_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_reportinghreshold_offset_t_eutran_fdd_reporting_offset,
      { "EUTRAN_FDD_REPORTING_OFFSET",        "gsm_rlcmac.dl.eutran_fdd_reporting_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_threshold,
      { "EUTRAN_TDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.eutran_tdd_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_threshold_2,
      { "EUTRAN_TDD_REPORTING_THRESHOLD_2",        "gsm_rlcmac.dl.eutran_tdd_reporting_threshold_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_reportinghreshold_offset_t_eutran_tdd_reporting_offset,
      { "EUTRAN_TDD_REPORTING_OFFSET",        "gsm_rlcmac.dl.eutran_tdd_reporting_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_eutran_measurementparametersdescription_qsearch_p_eutran,
      { "Qsearch_P_EUTRAN",        "gsm_rlcmac.dl.qsearch_p_eutran",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_eutran_measurementparametersdescription_eutran_rep_quant,
      { "EUTRAN_REP_QUANT",        "gsm_rlcmac.dl.eutran_rep_quant",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprs_eutran_measurementparametersdescription_eutran_multirat_reporting,
      { "EUTRAN_MULTIRAT_REPORTING",        "gsm_rlcmac.dl.eutran_multirat_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedeutran_cells_earfcn,
      { "EARFCN",        "gsm_rlcmac.dl.repeatedeutran_cells_earfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedeutran_cells_measurementbandwidth,
      { "MeasurementBandwidth",        "gsm_rlcmac.dl.repeatedeutran_cells_measurementbandwidth",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedeutran_neighbourcells_eutran_priority,
      { "EUTRAN_PRIORITY",        "gsm_rlcmac.dl.repeatedeutran_neighbourcells_eutran_priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedeutran_neighbourcells_thresh_eutran_high,
      { "THRESH_EUTRAN_high",        "gsm_rlcmac.dl.repeatedeutran_neighbourcells_thresh_eutran_high",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedeutran_neighbourcells_thresh_eutran_low,
      { "THRESH_EUTRAN_low",        "gsm_rlcmac.dl.repeatedeutran_neighbourcells_thresh_eutran_low",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedeutran_neighbourcells_eutran_qrxlevmin,
      { "EUTRAN_QRXLEVMIN",        "gsm_rlcmac.dl.repeatedeutran_neighbourcells_eutran_qrxlevmin",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcid_pattern_pcid_pattern_length,
      { "PCID_Pattern_length",        "gsm_rlcmac.dl.pcid_pattern_pcid_pattern_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcid_pattern_pcid_pattern_sense,
      { "PCID_Pattern_sense",        "gsm_rlcmac.dl.pcid_pattern_pcid_pattern_sense",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcid_group_ie_pcid_bitmap_group,
      { "PCID_BITMAP_GROUP",        "gsm_rlcmac.dl.pcid_group_ie_pcid_bitmap_group",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_frequency_index_eutran_frequency_index,
      { "EUTRAN_FREQUENCY_INDEX",        "gsm_rlcmac.dl.eutran_frequency_index_eutran_frequency_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_psc_pattern_length,
      { "PSC_pattern_length",        "gsm_rlcmac.dl.psc_pattern_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_psc_pattern_sense,
      { "PSC_pattern_sense",        "gsm_rlcmac.dl.psc_pattern_sense",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_meas_ctrl_param_meas_ctrl_eutran,
      { "Measurement_Control_E-UTRAN",        "gsm_rlcmac.dl.meas_ctrl_param_eutran",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_meas_ctrl_param_eutran_freq_idx,
      { "EUTRAN_FREQUENCY_INDEX",        "gsm_rlcmac.dl.meas_ctrl_param_eutran_freq_idx",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_meas_ctrl_param_meas_ctrl_utran,
      { "Measurement_Control_UTRAN",        "gsm_rlcmac.dl.meas_ctrl_param_utran",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_meas_ctrl_param_utran_freq_idx,
      { "UTRAN_FREQUENCY_INDEX",        "gsm_rlcmac.dl.meas_ctrl_param_utran_freq_idx",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rept_eutran_enh_cell_resel_param_eutran_qmin,
      { "E-UTRAN_Qmin",        "gsm_rlcmac.dl.enh_cell_resel_param_eutran_qmin",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_high_q,
      { "THRESH_E-UTRAN_high_Q",        "gsm_rlcmac.dl.enh_cell_resel_param_eutran_high_q",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_low_q,
      { "THRESH_E-UTRAN_low_Q",        "gsm_rlcmac.dl.enh_cell_resel_param_eutran_low_q",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_qqualmin,
      { "E-UTRAN_QQUALMIN",        "gsm_rlcmac.dl.enh_cell_resel_param_eutran_qqualmin",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_rept_eutran_enh_cell_resel_param_thresh_eutran_rsrpmin,
      { "E-UTRAN_RSRPmin",        "gsm_rlcmac.dl.enh_cell_resel_param_eutran_rsrpmin",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_fdd_reporting_threshold,
      { "UTRAN_CSG_FDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.utran_csg_fdd_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_fdd_reporting_threshold2,
      { "UTRAN_CSG_FDD_REPORTING_THRESHOLD_2",        "gsm_rlcmac.dl.utran_csg_fdd_reporting_threshold2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_tdd_reporting_threshold,
      { "UTRAN_CSG_TDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.utran_csg_tdd_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_fdd_reporting_threshold,
      { "E-UTRAN_CSG_FDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.eutran_csg_fdd_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_fdd_reporting_threshold2,
      { "E-UTRAN_CSG_FDD_REPORTING_THRESHOLD_2",        "gsm_rlcmac.dl.eutran_csg_fdd_reporting_threshold2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_tdd_reporting_threshold,
      { "E-UTRAN_CSG_TDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.eutran_csg_tdd_reporting_threshold",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_tdd_reporting_threshold2,
      { "E-UTRAN_CSG_TDD_REPORTING_THRESHOLD_2",        "gsm_rlcmac.dl.eutran_csg_tdd_reporting_threshold2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },    
    { &hf_eutran_parametersdescription_pmo_eutran_ccn_active,
      { "EUTRAN_CCN_ACTIVE",        "gsm_rlcmac.dl.eutran_parametersdescription_pmo_eutran_ccn_active",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr8_ba_ind_3g,
      { "BA_IND_3G",        "gsm_rlcmac.dl.pmo_additionsr8_ba_ind_3g",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr8_pmo_ind,
      { "PMO_IND",        "gsm_rlcmac.dl.pmo_additionsr8_pmo_ind",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr7_reporting_offset_700,
      { "REPORTING_OFFSET_700",        "gsm_rlcmac.dl.pmo_additionsr7_reporting_offset_700",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr7_reporting_threshold_700,
      { "REPORTING_THRESHOLD_700",        "gsm_rlcmac.dl.pmo_additionsr7_reporting_threshold_700",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr7_reporting_offset_810,
      { "REPORTING_OFFSET_810",        "gsm_rlcmac.dl.pmo_additionsr7_reporting_offset_810",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr7_reporting_threshold_810,
      { "REPORTING_THRESHOLD_810",        "gsm_rlcmac.dl.pmo_additionsr7_reporting_threshold_810",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr6_ccn_active_3g,
      { "CCN_ACTIVE_3G",        "gsm_rlcmac.dl.pmo_additionsr6_ccn_active_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcco_additionsr6_ccn_active_3g,
      { "CCN_ACTIVE_3G",        "gsm_rlcmac.dl.pcco_additionsr6_ccn_active_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr5_grnti,
      { "GRNTI",        "gsm_rlcmac.dl.pmo_additionsr5_grnti",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcco_additionsr5_grnti,
      { "GRNTI",        "gsm_rlcmac.dl.pcco_additionsr5_grnti",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmo_additionsr4_ccn_active,
      { "CCN_ACTIVE",        "gsm_rlcmac.dl.pmo_additionsr4_ccn_active",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcco_additionsr4_ccn_active,
      { "CCN_ACTIVE",        "gsm_rlcmac.dl.pcco_additionsr4_ccn_active",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pcco_additionsr4_container_id,
      { "CONTAINER_ID",        "gsm_rlcmac.dl.pcco_additionsr4_container_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lsa_id_info_element_lsa_id,
      { "LSA_ID",        "gsm_rlcmac.dl.lsa_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lsa_id_info_element_shortlsa_id,
      { "ShortLSA_ID",        "gsm_rlcmac.dl.lsa_shortlsa_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_lsa_parameters_nr_of_freq_or_cells,
      { "NR_OF_FREQ_OR_CELLS",        "gsm_rlcmac.dl.lsa_nr_of_freq_or_cells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_gsm_immediate_rel,
      { "IMMEDIATE_REL",        "gsm_rlcmac.dl.taget_cell_immediate_rel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_gsm_bsic,
      { "BSIC",        "gsm_rlcmac.dl.taget_cell_gsm_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_3g_immediate_rel,
      { "IMMEDIATE_REL",        "gsm_rlcmac.dl.immediate_rel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_eutran_earfcn,
      { "EARFCN",        "gsm_rlcmac.dl.pcco_target_cell_eutran_earfcn",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_eutran_measurement_bandwidth,
      { "Measurement Bandwidth",        "gsm_rlcmac.dl.pcco_target_cell_eutran_meas_bw",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_eutran_pl_cell_id,
      { "Physical Layer Cell Identity",        "gsm_rlcmac.dl.pcco_target_cell_eutran_cell_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_idvd_default_utran_priority,
      { "DEFAULT_UTRAN_PRIORITY",        "gsm_rlcmac.dl.idvl_prio_dlft_geran_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_idvd_utran_priority,
      { "UTRAN_PRIORITY",        "gsm_rlcmac.dl.idvl_prio_geran_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_idvd_default_eutran_priority,
      { "DEFAULT_E-UTRAN_PRIORITY",        "gsm_rlcmac.dl.idvl_prio_dlft_eutran_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_idvd_eutran_priority,
      { "E-UTRAN_PRIORITY",        "gsm_rlcmac.dl.idvl_prio_eutran_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_idvd_prio_geran_priority,
      { "GERAN_PRIORITY",        "gsm_rlcmac.dl.idvl_prio_dlft_geran_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_idvd_prio_t3230_timeout_value,
      { "T3230 timeout value",        "gsm_rlcmac.dl.idvl_prio_t3230",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_g_rnti_ext,
      { "G-RNTI extension",        "gsm_rlcmac.dl.pcco_g_rnti_ext",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet (Enhanced) Measurement Report message contents > */
    { &hf_ba_used_ba_used,
      { "BA_USED",        "gsm_rlcmac.ul.ba_used",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ba_used_ba_used_3g,
      { "BA_USED_3G",        "gsm_rlcmac.ul.ba_used_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_serving_cell_data_rxlev_serving_cell,
      { "RXLEV_SERVING_CELL",        "gsm_rlcmac.ul.rxlev_serving_cell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurements_frequency_n,
      { "FREQUENCY_N",        "gsm_rlcmac.ul.frequency_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurements_bsic_n,
      { "BSIC_N",        "gsm_rlcmac.ul.bsic_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurements_rxlev_n,
      { "RXLEV_N",        "gsm_rlcmac.ul.rxlev_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedinvalid_bsic_info_bcch_freq_n,
      { "BCCH_FREQ_N",        "gsm_rlcmac.ul.bcch_freq_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedinvalid_bsic_info_bsic_n,
      { "BSIC_N",        "gsm_rlcmac.ul.bsic_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeatedinvalid_bsic_info_rxlev_n,
      { "RXLEV_N",        "gsm_rlcmac.ul.rxlev_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_reporting_quantity_instance_reporting_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.reporting_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_report_nc_mode,
      { "NC_MODE",        "gsm_rlcmac.ul.nc_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurement_report_number_of_nc_measurements,
      { "NUMBER_OF_NC_MEASUREMENTS",        "gsm_rlcmac.ul.number_of_nc_measurements",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_nc_measurement_report_nc_mode,
      { "NC_MODE",        "gsm_rlcmac.ul.nc_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_nc_measurement_report_pmo_used,
      { "PMO_USED",        "gsm_rlcmac.ul.pmo_used",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_nc_measurement_report_bsic_seen,
      { "BSIC_Seen",        "gsm_rlcmac.ul.bsic_seen",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_nc_measurement_report_scale,
      { "SCALE",        "gsm_rlcmac.ul.scale",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_ext_reporting_type,
      { "EXT_REPORTING_TYPE",        "gsm_rlcmac.ul.ext_reporting_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot0_i_level,
      { "Slot[0].I_LEVEL",        "gsm_rlcmac.ul.slot0_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot1_i_level,
      { "Slot[1].I_LEVEL",        "gsm_rlcmac.ul.slot1_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot2_i_level,
      { "Slot[2].I_LEVEL",        "gsm_rlcmac.ul.slot2_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot3_i_level,
      { "Slot[3].I_LEVEL",        "gsm_rlcmac.ul.slot3_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot4_i_level,
      { "Slot[4].I_LEVEL",        "gsm_rlcmac.ul.slot4_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot5_i_level,
      { "Slot[5].I_LEVEL",        "gsm_rlcmac.ul.slot5_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot6_i_level,
      { "Slot[6].I_LEVEL",        "gsm_rlcmac.ul.slot6_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_slot7_i_level,
      { "Slot[7].I_LEVEL",        "gsm_rlcmac.ul.slot7_i_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_measurement_report_number_of_ext_measurements,
      { "NUMBER_OF_EXT_MEASUREMENTS",        "gsm_rlcmac.ul.number_of_ext_measurements",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_measurements_3g_cell_list_index_3g,
      { "CELL_LIST_INDEX_3G",        "gsm_rlcmac.ul.measurements_3g_cell_list_index_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_measurements_3g_reporting_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.measurements_3g_reporting_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmr_additionsr99_pmo_used,
      { "PMO_USED",        "gsm_rlcmac.ul.pmr_additionsr99_pmo_used",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmr_eutran_meas_rpt_freq_idx,
      { "E-UTRAN_FREQUENCY_INDEX",        "gsm_rlcmac.ul.pmr_eutran_meas_rpt_freq_idx",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmr_eutran_meas_rpt_cell_id,
      { "CELL IDENTITY",        "gsm_rlcmac.ul.pmr_eutran_meas_rpt_cell_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pmr_eutran_meas_rpt_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.pmr_eutran_meas_rpt_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_emr_servingcell_dtx_used,
      { "DTX_USED",        "gsm_rlcmac.ul.emr_servingcell_dtx_used",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_emr_servingcell_rxlev_val,
      { "RXLEV_VAL",        "gsm_rlcmac.ul.emr_servingcell_rxlev_val",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_emr_servingcell_rx_qual_full,
      { "RX_QUAL_FULL",        "gsm_rlcmac.ul.emr_servingcell_rx_qual_full",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_emr_servingcell_mean_bep,
      { "MEAN_BEP",        "gsm_rlcmac.ul.emr_mean_bep",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_emr_servingcell_cv_bep,
      { "CV_BEP",        "gsm_rlcmac.ul.emr_cv_bep",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_emr_servingcell_nbr_rcvd_blocks,
      { "NBR_RCVD_BLOCKS",        "gsm_rlcmac.ul.emr_nbr_rcvd_blocks",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enhancedmeasurementreport_rr_short_pd,
      { "RR_Short_PD",        "gsm_rlcmac.ul.emr_rr_short_pd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enhancedmeasurementreport_message_type,
      { "MESSAGE_TYPE",        "gsm_rlcmac.ul.emr_message_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enhancedmeasurementreport_shortlayer2_header,
      { "ShortLayer2_Header",        "gsm_rlcmac.ul.emr_shortlayer2_header",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enhancedmeasurementreport_bsic_seen,
      { "BSIC_Seen",        "gsm_rlcmac.ul.emr_bsic_seen",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enhancedmeasurementreport_scale,
      { "SCALE",        "gsm_rlcmac.ul.emr_scale",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_measurement_report_psi5_change_mark,
      { "PSI5_CHANGE_MARK",        "gsm_rlcmac.ul.pmr_psi5_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Measurement Order message contents >*/
    { &hf_ext_frequency_list_start_frequency,
      { "START_FREQUENCY",        "gsm_rlcmac.dl.ext_frequency_list_start_frequency",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_frequency_list_nr_of_frequencies,
      { "NR_OF_FREQUENCIES",        "gsm_rlcmac.dl.ext_frequency_list_nr_of_frequencies",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ext_frequency_list_freq_diff_length,
      { "FREQ_DIFF_LENGTH",        "gsm_rlcmac.dl.ext_frequency_list_freq_diff_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_measurement_order_pmo_index,
      { "PMO_INDEX",        "gsm_rlcmac.dl.pmo_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_measurement_order_pmo_count,
      { "PMO_COUNT",        "gsm_rlcmac.dl.pmo_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ccn_measurement_report_rxlev_serving_cell,
      { "RXLEV_SERVING_CELL",        "gsm_rlcmac.dl.rxlev_serving_cell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ccn_measurement_report_number_of_nc_measurements,
      { "NUMBER_OF_NC_MEASUREMENTS",        "gsm_rlcmac.dl.number_of_nc_measurements",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_gsm_notif_bsic,
      { "BSIC",        "gsm_rlcmac.dl.target_cell_gsm_notif_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fdd_target_cell_notif_fdd_arfcn,
      { "FDD_ARFCN",        "gsm_rlcmac.dl.fdd_target_cell_notif_fdd_arfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fdd_target_cell_notif_bandwith_fdd,
      { "BANDWITH_FDD",        "gsm_rlcmac.dl.fdd_target_cell_notif_bandwith_fdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_fdd_target_cell_notif_scrambling_code,
      { "SCRAMBLING_CODE",        "gsm_rlcmac.dl.fdd_target_cell_notif_scrambling_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_target_cell_3g_notif_reporting_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.dl.target_cell_3g_notif_reporting_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pccn_additionsr6_ba_used_3g,
      { "BA_USED_3G",        "gsm_rlcmac.dl.pccn_additionsr6_ba_used_3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Cell Change Notification message contents > */
    { &hf_packet_cell_change_notification_ba_ind,
      { "BA_IND",        "gsm_rlcmac.ul.pccn_ba_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_change_notification_pmo_used,
      { "PMO_USED",        "gsm_rlcmac.ul.pccn_pmo_used",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_change_notification_pccn_sending,
      { "PCCN_SENDING",        "gsm_rlcmac.ul.pccn_pccn_sending",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_change_notification_lte_reporting_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.pccn_lte_reporting_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_ccn_meas_rpt_3g_ba_used,
      { "3G_BA_USED",        "gsm_rlcmac.ul.pccn_eutran_ccn_meas_rpt_3g_ba_used",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_ccn_meas_rpt_freq_idx,
      { "E-UTRAN_FREQUENCY_INDEX",        "gsm_rlcmac.ul.pccn_eutran_ccn_meas_rpt_freq_idx",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_ccn_meas_cell_id,
      { "CELL IDENTITY",        "gsm_rlcmac.ul.pccn_eutran_ccn_meas_rpt_cell_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_ccn_meas_rpt_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.pccn_eutran_ccn_meas_rpt_rpt_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_meas_rpt_cgi,
      { "UTRAN_CGI",        "gsm_rlcmac.ul.utran_csg_meas_rpt_cgi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_meas_rpt_csg_id,
      { "CSG_ID",        "gsm_rlcmac.ul.utran_csg_meas_rpt_csg_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_meas_rpt_access_mode,
      { "Access Mode",        "gsm_rlcmac.ul.utran_csg_meas_rpt_access_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_utran_csg_meas_rpt_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.utran_csg_meas_rpt_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_meas_rpt_cgi,
      { "EUTRAN_CGI",        "gsm_rlcmac.ul.eutran_csg_meas_rpt_cgi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_meas_rpt_ta,
      { "Tracking Area Code",        "gsm_rlcmac.ul.eutran_csg_meas_rpt_ta",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_meas_rpt_csg_id,
      { "CSG_ID",        "gsm_rlcmac.ul.eutran_csg_meas_rpt_csg_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_meas_rpt_access_mode,
      { "Access Mode",        "gsm_rlcmac.ul.eutran_csg_meas_rpt_access_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_eutran_csg_meas_rpt_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.ul.eutran_csg_meas_rpt_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Cell Change Continue message contents > */
    { &hf_packet_cell_change_continue_arfcn,
      { "ARFCN",        "gsm_rlcmac.dl.pccc_arfcn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_change_continue_bsic,
      { "BSIC",        "gsm_rlcmac.dl.pccc_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_change_continue_container_id,
      { "CONTAINER_ID",        "gsm_rlcmac.dl.pccc_container_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Neighbour Cell Data message contents > */
    { &hf_pncd_container_with_id_bsic,
      { "BSIC",        "gsm_rlcmac.dl.pncd_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_neighbour_cell_data_container_id,
      { "CONTAINER_ID",        "gsm_rlcmac.dl.pncd_container_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_neighbour_cell_data_spare,
      { "spare",        "gsm_rlcmac.dl.pncd_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_neighbour_cell_data_container_index,
      { "CONTAINER_INDEX",        "gsm_rlcmac.dl.pncd_container_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Serving Cell Data message contents > */
    { &hf_packet_serving_cell_data_spare,
      { "spare",        "gsm_rlcmac.dl.pscd_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_serving_cell_data_container_index,
      { "CONTAINER_INDEX",        "gsm_rlcmac.dl.pscd_container_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_servingcelldata_rxlev_serving_cell,
      { "RXLEV_SERVING_CELL",        "gsm_rlcmac.dl.servingcelldata_rxlev_serving_cell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeated_invalid_bsic_info_bcch_freq_ncell,
      { "BCCH_FREQ_NCELL",        "gsm_rlcmac.dl.repeated_invalid_bsic_info_bcch_freq_ncell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeated_invalid_bsic_info_bsic,
      { "BSIC",        "gsm_rlcmac.dl.repeated_invalid_bsic_info_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_repeated_invalid_bsic_info_rxlev_ncell,
      { "RXLEV_NCELL",        "gsm_rlcmac.dl.repeated_invalid_bsic_info_rxlev_ncell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_reporting_quantity_reporting_quantity,
      { "REPORTING_QUANTITY",        "gsm_rlcmac.dl.repeated_invalid_bsic_info_reporting_quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurementreport_nc_mode,
      { "NC_MODE",        "gsm_rlcmac.dl.nc_measurementreport_nc_mode",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurementreport_pmo_used,
      { "PMO_USED",        "gsm_rlcmac.dl.nc_measurementreport_pmo_used",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nc_measurementreport_scale,
      { "SCALE",        "gsm_rlcmac.dl.nc_measurementreport_scale",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },

/*< Packet Handover Command message content > */
    { &hf_globaltimeslotdescription_ms_timeslotallocation,
      { "MS_TimeslotAllocation",        "gsm_rlcmac.dl.pho_ms_timeslotallocation",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_usf_1_7_usf,
      { "USF",        "gsm_rlcmac.dl.pho_usf",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_usf_allocationarray_usf_0,
      { "USF_0",        "gsm_rlcmac.dl.pho_usf_0",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_egprs_description_linkqualitymeasurementmode,
      { "LinkQualityMeasurementMode",        "gsm_rlcmac.dl.linkqualitymeasurementmode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_nas_container_nas_containerlength,
      { "NAS_ContainerLength",        "gsm_rlcmac.dl.nas_containerlength",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ps_handoverto_utran_payload_rrc_containerlength,
      { "RRC_ContainerLength",        "gsm_rlcmac.dl.ps_handoverto_utran_payload_rrc_containerlength",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_handoverreference,
      { "HandoverReference",        "gsm_rlcmac.dl.pho_radioresources_handoverreference",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_si,
      { "SI",        "gsm_rlcmac.dl.pho_radioresources_si",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_nci,
      { "NCI",        "gsm_rlcmac.dl.pho_radioresources_nci",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_bsic,
      { "BSIC",        "gsm_rlcmac.dl.pho_radioresources_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_ccn_active,
      { "CCN_Active",        "gsm_rlcmac.dl.pho_radioresources_ccn_active",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_ccn_active_3g,
      { "CCN_Active_3G",        "gsm_rlcmac.dl.pho_radioresources_ccn_active_3g",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_networkcontrolorder,
      { "NetworkControlOrder",        "gsm_rlcmac.dl.pho_radioresources_networkcontrolorder",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_rlc_reset,
      { "RLC_Reset",        "gsm_rlcmac.dl.pho_radioresources_rlc_reset",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pho_radioresources_uplinkcontroltimeslot,
      { "UplinkControlTimeslot",        "gsm_rlcmac.dl.pho_radioresources_uplinkcontroltimeslot",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_handover_command_containerid,
      { "ContainerID",        "gsm_rlcmac.dl.pho_containerid",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/*< End Packet Handover Command >*/

/*< Packet Physical Information message content > */

/*< End Packet Physical Information > */
    { &hf_si1_restoctet_nch_position,
      { "NCH_Position",        "gsm_rlcmac.dl.i1_restoctet_nch_position",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si1_restoctet_bandindicator,
      { "BandIndicator",        "gsm_rlcmac.dl.i1_restoctet_bandindicator",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_selection_parameters_cbq,
      { "CBQ",        "gsm_rlcmac.dl.selection_parameters_cbq",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_selection_parameters_cell_reselect_offset,
      { "CELL_RESELECT_OFFSET",        "gsm_rlcmac.dl.cell_reselect_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_selection_parameters_temporary_offset,
      { "TEMPORARY_OFFSET",        "gsm_rlcmac.dl.selection_parameters_temporary_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_selection_parameters_penalty_time,
      { "PENALTY_TIME",        "gsm_rlcmac.dl.selection_parameters_penalty_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_power_offset,
      { "Power_Offset",        "gsm_rlcmac.dl.si3_rest_octet_power_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_system_information_2ter_indicator,
      { "System_Information_2ter_Indicator",        "gsm_rlcmac.dl.si3_rest_octet_system_information_2ter_indicator",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_early_classmark_sending_control,
      { "Early_Classmark_Sending_Control",        "gsm_rlcmac.dl.si3_rest_octet_early_classmark_sending_control",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_where,
      { "WHERE",        "gsm_rlcmac.dl.si3_rest_octet_where",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_ra_colour,
      { "RA_COLOUR",        "gsm_rlcmac.dl.si3_rest_octet_ra_colour",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si13_position,
      { "SI13_POSITION",        "gsm_rlcmac.dl.si13_position",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_ecs_restriction3g,
      { "ECS_Restriction3G",        "gsm_rlcmac.dl.si3_rest_octet_ecs_restriction3g",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si3_rest_octet_si2quaterindicator,
      { "SI2quaterIndicator",        "gsm_rlcmac.dl.si3_rest_octet_si2quaterindicator",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si4_rest_octet_power_offset,
      { "Power_Offset",        "gsm_rlcmac.dl.si4_rest_octet_power_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si4_rest_octet_ra_colour,
      { "RA_COLOUR",        "gsm_rlcmac.dl.si4_rest_octet_ra_colour",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pch_and_nch_info_pagingchannelrestructuring,
      { "PagingChannelRestructuring",        "gsm_rlcmac.dl.pch_and_nch_info_pagingchannelrestructuring",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pch_and_nch_info_nln_sacch,
      { "NLN_SACCH",        "gsm_rlcmac.dl.pch_and_nch_info_nln_sacch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pch_and_nch_info_callpriority,
      { "CallPriority",        "gsm_rlcmac.dl.pch_and_nch_info_callpriority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si6_restoctet_vbs_vgcs_options,
      { "VBS_VGCS_Options",        "gsm_rlcmac.dl.si6_restoctet_vbs_vgcs_options",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si6_restoctet_max_lapdm,
      { "MAX_LAPDm",        "gsm_rlcmac.dl.si6_restoctet_max_lapdm",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_si6_restoctet_bandindicator,
      { "BandIndicator",        "gsm_rlcmac.dl.si6_restoctet_bandindicator",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/*< Additional MS Radio Access Capability message content > */
/*< End Additional MS Radio Access Capability> */

/*< Packet Pause message content > */
/*< End Packet Pause> */

/* < Packet System Information Type 1 message content > */    
    { &hf_packet_system_info_type1_pbcch_change_mark,
      { "PBCCH_CHANGE_MARK",        "gsm_rlcmac.dl.psi1_pbcch_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_psi_change_field,
      { "PSI_CHANGE_FIELD",        "gsm_rlcmac.dl.psi1_psi_change_field",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_psi_change_field_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_psi1_repeat_period,
      { "PSI1_REPEAT_PERIOD",        "gsm_rlcmac.dl.psi1_psi1_repeat_period",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_val_plus_1_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_psi_count_lr,
      { "PSI_COUNT_LR",        "gsm_rlcmac.dl.psi1_psi_count_lr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_psi_count_hr,
      { "PSI_COUNT_HR",        "gsm_rlcmac.dl.psi1_psi_count_hr",
        FT_UINT8, BASE_DEC, VALS(gsm_rlcmac_val_plus_1_vals), 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_measurement_order,
      { "MEASUREMENT_ORDER",        "gsm_rlcmac.dl.psi1_measurement_order",
        FT_BOOLEAN, BASE_NONE, TFS(&gsm_rlcmac_psi1_measurement_order_value), 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_psi_status_ind,
      { "PSI_STATUS_IND",        "gsm_rlcmac.dl.psi1_psi_status_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_mscr,
      { "MSCR",        "gsm_rlcmac.dl.psi1_mscr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_band_indicator,
      { "BAND_INDICATOR",        "gsm_rlcmac.dl.psi1_band_indicator",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type1_lb_ms_txpwr_max_ccch,
      { "LB_MS_TXPWR_MAX_CCCH", "gsm_rlcmac.dl.psi1_lb_ms_txpwr_max_ccch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pccch_org_bs_pcc_rel,
      { "BS_PCC_REL",        "gsm_rlcmac.dl.pccch_org_bs_pcc_rel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pccch_org_pbcch_blks,
      { "PBCCH_BLKS",        "gsm_rlcmac.dl.pccch_org_pbcch_blks",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pccch_org_pag_blks_res,
      { "PAG_BLKS_RES",        "gsm_rlcmac.dl.pccch_org_pag_blks_res",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_pccch_org_prach_blks,
      { "PRACH_BLKS",        "gsm_rlcmac.dl.pccch_org_prach_blks",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/* < End Packet System Information Type 1 message content > */

/* < Packet System Information Type 2 message content > */    
    { &hf_packet_system_info_type2_change_mark,
      { "PSI2_CHANGE_MARK",        "gsm_rlcmac.dl.psi2_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_index,
      { "PSI2_INDEX",        "gsm_rlcmac.dl.psi2_INDEX",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_count,
      { "PSI2_COUNT",        "gsm_rlcmac.dl.psi2_COUNT",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_cell_id_cell_identity,
      { "CELL_IDENTITY",        "gsm_rlcmac.dl.cell_id_cell_identity",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_lai_lac,
      { "LAC",        "gsm_rlcmac.dl.lai_lac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_plmn_mcc1,
      { "MCC1",        "gsm_rlcmac.dl.plmn_mcc1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_plmn_mcc2,
      { "MCC2",        "gsm_rlcmac.dl.plmn_mcc2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_plmn_mcc3,
      { "MCC3",        "gsm_rlcmac.dl.plmn_mcc3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_plmn_mnc1,
      { "MNC1",        "gsm_rlcmac.dl.plmn_mnc1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_plmn_mnc2,
      { "MNC2",        "gsm_rlcmac.dl.plmn_mnc2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_plmn_mnc3,
      { "MNC3",        "gsm_rlcmac.dl.plmn_mnc3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_att,
      { "ATT",        "gsm_rlcmac.dl.non_gprs_cell_opt_att",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_t3212,
      { "T3212",        "gsm_rlcmac.dl.non_gprs_cell_opt_t3212",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_neci,
      { "NECI",        "gsm_rlcmac.dl.non_gprs_cell_opt_neci",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_pwrc,
      { "PWRC",        "gsm_rlcmac.dl.non_gprs_cell_opt_pwrc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_dtx,
      { "DTX",        "gsm_rlcmac.dl.non_gprs_cell_opt_dtx",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_radio_link_timeout,
      { "RADIO_LINK_TIMEOUT",        "gsm_rlcmac.dl.non_gprs_cell_opt_radio_link_timeout",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_bs_ag_blks_res,
      { "BS_AG_BLKS_RES",        "gsm_rlcmac.dl.non_gprs_cell_opt_bs_ag_blks_res",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_ccch_conf,
      { "CCCH_CONF",        "gsm_rlcmac.dl.non_gprs_cell_opt_ccch_conf",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_bs_pa_mfrms,
      { "BS_PA_MFRMS",        "gsm_rlcmac.dl.non_gprs_cell_opt_bs_pa_mfrms",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_max_retrans,
      { "MAX_RETRANS",        "gsm_rlcmac.dl.non_gprs_cell_opt_max_retrans",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_tx_int,
      { "TX_INTEGER",        "gsm_rlcmac.dl.non_gprs_cell_opt_tx_integer",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_ec,
      { "EC",        "gsm_rlcmac.dl.non_gprs_cell_opt_ec",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_ms_txpwr_max_ccch,
      { "MS_TXPWR_MAX_CCCH",        "gsm_rlcmac.dl.non_gprs_cell_opt_ms_txpwr_max_ccch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_non_gprs_cell_opt_ext_len,
      { "Extention_Length",        "gsm_rlcmac.dl.non_gprs_cell_opt_extention_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_ref_freq_num,
      { "RFL_NUMBER",        "gsm_rlcmac.dl.psi2_ref_freq_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_ma_number,
      { "MA_NUMBER",        "gsm_rlcmac.dl.psi2_ma_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_non_hopping_timeslot,
      { "TIMESLOT",        "gsm_rlcmac.dl.psi2_pccch_desc_non_hopping_timeslot",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_hopping_ma_num,
      { "MA_NUMBER",        "gsm_rlcmac.dl.psi2_pccch_desc_hopping_ma_num",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type2_hopping_timeslot,
      { "TIMESLOT",        "gsm_rlcmac.dl.psi2_pccch_desc_hopping_timeslot",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL
      }
    },
/* < End Packet System Information Type 2 message content > */


/* < Packet System Information Type 3 message content > */
    { &hf_packet_system_info_type3_change_mark,
      { "PSI3_CHANGE_MARK",        "gsm_rlcmac.dl.psi3_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type3_bis_count,
      { "PSI3_BIS_COUNT",        "gsm_rlcmac.dl.psi3_bis_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_scell_param_gprs_rxlev_access_min,
      { "RXLEV_ACCESS_MIN",        "gsm_rlcmac.dl.psi3_scell_param_gprs_rxlev_access_min",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_scell_param_gprs_ms_txpwr_max_cch,
      { "MS_TXPWR_MAX_CCH",        "gsm_rlcmac.dl.psi3_scell_param_ms_txpwr_max_cch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_scell_param_multiband_reporting,
      { "MULTIBAND_REPORTING",        "gsm_rlcmac.dl.psi3_scell_param_multiband_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_gen_cell_sel_gprs_cell_resl_hyst,
      { "GPRS_CELL_RESELECT_HYSTERESIS",        "gsm_rlcmac.dl.psi3_gen_cell_sel_resel_hyst",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_gen_cell_sel_c31_hyst,
      { "C31_HYST",        "gsm_rlcmac.dl.psi3_gen_cell_sel_c31_hyst",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_gen_cell_sel_c32_qual,
      { "C32_QUAL",        "gsm_rlcmac.dl.psi3_gen_cell_sel_c32_qual",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_gen_cell_sel_t_resel,
      { "T_RESEL",        "gsm_rlcmac.dl.psi3_gen_cell_sel_t_resel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_gen_cell_sel_ra_resel_hyst,
      { "RA_RESELECT_HYSTERESIS",        "gsm_rlcmac.dl.psi3_gen_cell_sel_ra_resel_hyst",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_bsic,
      { "BSIC",        "gsm_rlcmac.dl.psi3_compact_cell_sel_bsic",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_same_as_scell,
      { "SAME_AS_SERVING_CELL",        "gsm_rlcmac.dl.psi3_compact_cell_sel_same_as_scell",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_gprs_rxlev_access_min,
      { "GPRS_RXLEV_ACCESS_MIN",        "gsm_rlcmac.dl.psi3_compact_cell_sel_gprs_rxlev_access_min",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_gprs_ms_txpwr_max_cch,
      { "GPRS_MS_TXPWR_MAX_CCH",        "gsm_rlcmac.dl.psi3_compact_cell_sel_gprs_ms_txpwr_cch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_gprs_temp_offset,
      { "GPRS_TEMP_OFFSET",        "gsm_rlcmac.dl.psi3_compact_cell_sel_gprs_temp_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_gprs_penalty_time,
      { "GPRS_PENALTY_TIME",        "gsm_rlcmac.dl.psi3_compact_cell_sel_gprs_panelty_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_gprs_resel_offset,
      { "GPRS_RESEL_OFFSET",        "gsm_rlcmac.dl.psi3_compact_cell_sel_gprs_resel_offset",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_time_group,
      { "TIME_GROUP",        "gsm_rlcmac.dl.psi3_compact_cell_sel_time_group",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_cell_sel_guar_const_pwr_blks,
      { "GUAR_CONSTANT_PWR_BLKS",        "gsm_rlcmac.dl.psi3_compact_cell_sel_guar_const_pwr_blks",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_ncell_param_start_freq,
      { "START_FREQUENCY",        "gsm_rlcmac.dl.psi3_compact_ncell_start_freq",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_compact_ncell_param_nr_of_remaining_cells,
      { "NR_OF_REMAINING_CELLS",        "gsm_rlcmac.dl.psi3_compact_ncell_nr_of_remaining_cells",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/* < End Packet System Information Type 3 message content > */

/* < Packet System Information Type 5 message content > */
    { &hf_gprsmeasurementparams3g_psi5_repquantfdd,
      { "FDD_REP_QUANT",        "gsm_rlcmac.dl.psi5_rep_quant_fdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_psi5_multiratreportingfdd,
      { "FDD_MULTIRAT_REPORTING",        "gsm_rlcmac.dl.psi5_multirat_reporting_fdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_psi5_reportingoffsetfdd,
      { "FDD_REPORTING_OFFSET",        "gsm_rlcmac.dl.psi5_reporting_offset_fdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_psi5_reportingthresholdfdd,
      { "FDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.psi5_reporting_threshold_fdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_psi5_multiratreportingtdd,
      { "TDD_MULTIRAT_REPORTING",        "gsm_rlcmac.dl.psi5_multirat_reporting_tdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_psi5_reportingoffsettdd,
      { "TDD_REPORTING_OFFSET",        "gsm_rlcmac.dl.psi5_reporting_offset_tdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_gprsmeasurementparams3g_psi5_reportingthresholdtdd,
      { "TDD_REPORTING_THRESHOLD",        "gsm_rlcmac.dl.psi5_reporting_threshold_tdd",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_reporting_parameters_report_type,
      { "Report_Type",        "gsm_rlcmac.dl.psi5_enh_reporting_param_report_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_reporting_parameters_reporting_rate,
      { "REPORTING_RATE",        "gsm_rlcmac.dl.psi5_enh_reporting_param_reporting_rate",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_reporting_parameters_invalid_bsic_reporting,
      { "INVALID_BSIC_REPORTING",        "gsm_rlcmac.dl.psi5_enh_reporting_param_invalid_bsic_reporting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_enh_reporting_parameters_ncc_permitted,
      { "NCC_PERMITTED",        "gsm_rlcmac.dl.psi5_enh_reporting_param_ncc_permitted",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type5_change_mark,
      { "PSI5_CHANGE_MARK",        "gsm_rlcmac.dl.psi5_change_mark",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type5_index,
      { "PSI5_INDEX",        "gsm_rlcmac.dl.psi5_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type5_count,
      { "PSI5_COUNT",        "gsm_rlcmac.dl.psi5_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/* < End Packet System Information Type 5 message content > */

/* < Packet System Information Type 13 message content > */
    { &hf_packet_system_info_type13_lb_ms_mxpwr_max_cch,
      { "LB_MS_TXPWR_MAX_CCH",        "gsm_rlcmac.dl.psi13_lb_ms_txpwr_max_cch",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_packet_system_info_type13_si2n_support,
      { "SI2n_SUPPORT",        "gsm_rlcmac.dl.psi13_si2n_support",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
/* < End Packet System Information Type 13 message content > */

  };


  /* Register the protocol name and description */
  proto_gsm_rlcmac = proto_register_protocol("Radio Link Control, Medium Access Control, 3GPP TS44.060",
                                             "GSM RLC MAC", "gsm_rlcmac");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_gsm_rlcmac, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("gsm_rlcmac_ul", dissect_gsm_rlcmac_uplink, proto_gsm_rlcmac);
  register_dissector("gsm_rlcmac_dl", dissect_gsm_rlcmac_downlink, proto_gsm_rlcmac);
}

void
proto_reg_handoff_gsm_rlcmac(void)
{
    data_handle = find_dissector("data");
}

